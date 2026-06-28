# 链下证明开发文档（Hypernova / Groth16 / IPA + checkpoint 协议）

> SubTask 37.3：poker_l1 OffChain 执行模型 + ZK 证明结算开发文档
>
> 实现来源：`poker_l1/src/offline/`（`mod.rs` / `state.rs` / `ccs.rs` / `hypernova.rs` / `groth16.rs` / `ipa.rs` / `zk_verifier.rs` / `ack_chain.rs`）、`poker_l1/src/vm/contracts/`（`checkpoint_anchor.rs` / `force_checkin.rs` / `challenge_delta.rs` / `checkpoint_skip.rs`）
>
> 规范依据：`spec.md`（FROZEN 2026-06-27）L493–525 / L527–553 / L655–669 / L697–723 / L853–857

---

## 1. 概述

poker_l1 OffChain 执行模型采用「链下计算 + ZK 证明结算」范式：参与者将 Game 状态从链上 checkout 到链下执行环境，链下完成多手牌计算后通过 checkin tx 提交 ZK proof π、状态增量 Δ、新承诺 `new_commitment` 与 `ack_chain` 进行结算。链上 verifier 验证 π 通过后，应用 Δ 更新 Game 对象并解锁 checkout 锁定。

### 执行模式

`OfflineState.execution_mode` 决定 Game 是否走链下通道（`poker_l1/src/offline/state.rs:52-58`）：

| ExecutionMode | 行为 | checkout | checkin |
|---------------|------|----------|---------|
| `OnChain` | 所有步骤直接走链上 GameTurn 通道 | 跳过（SubTask 21.4） | 不触发 |
| `OffChain` | 开局后触发 checkout，结算时触发 checkin | 触发（SubTask 21.2） | 触发（SubTask 21.3） |

### NEW-C1 mainnet gate

`VerifierStatus`（`poker_l1/src/offline/zk_verifier.rs:31-50`）以 per-`chain_id` 粒度控制 OffChain 是否可用：

- `Stub`：MVP 阶段，仅校验 proof 格式；**主网拒绝 OffChain checkout**
- `Production`：完整 ZK 验证；升级须经治理 90% quorum + `parameter_delay_blocks` timelock

```rust
pub fn allows_offchain(self, chain_id: ChainId, is_mainnet: bool) -> bool {
    if self == Self::Stub && is_mainnet { return false; }
    let _ = chain_id;
    true
}
```

`check_offchain_allowed()`（`state.rs:412-422`）在 checkout 前调用此 gate，`Stub + mainnet` 返回 `OffChainDisabledOnMainnet`。

### 模块依赖

```text
ack_chain ──┐
            ├──► state ──┐
zk_verifier ┘            │
     ▲                    │
     ├── hypernova ──┐    │
     ├── groth16    ├──► ccs
     └── ipa        │
                      └──► （chain 模块后续 Phase 5b/5c 使用）
```

全部模块 `deny(unsafe_code)`；MVP 阶段 verifier 均为 `Stub`。

---

## 2. OffChain 生命周期

完整生命周期由四个阶段构成（`poker_l1/src/offline/state.rs` + `vm/contracts/checkpoint_anchor.rs`）：

### 2.1 checkout（OnChain → OffChain）

`CheckoutTx { game_id, state: OfflineState }`（`state.rs:96-101`）。`execute_checkout()` 仅当 `should_checkout()` 返回 true（即 `execution_mode == OffChain`）时计算 commitment = `blake2b_256(game_id || version || state_root || participants || nonce || execution_mode)` 并存入链上，owner 标记为 `ChannelOwner`。

### 2.2 checkpoint_anchor（链下 checkpoint 提交）

链下执行期间操作方每 `checkpoint_interval_blocks` 提交 `CheckpointAnchorTx`（详见 §3）。该 tx 走 `CheckpointAnchor` 通道，路由到 assigned_validator，与 GameTurn 同路由但独立 lane（不参与 turn ordering），**免 gas**，通过 gossipsub 广播防栽赃。

### 2.3 offline 执行（CCS 电路 + Hypernova fold）

每步链下执行生成一个 CCS 电路实例，多步折叠为单个最终证明 π（详见 §4）。skip 段不参与 ack_chain（R5-M5）。

### 2.4 checkin（OffChain → OnChain 结算）

`CheckinTx`（`state.rs:110-125`）字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `game_id` | `ObjectID` | Game 对象 ID |
| `proof` | `Vec<u8>` | ZK proof π |
| `state_delta` | `Vec<u8>` | 状态增量 Δ |
| `new_commitment` | `Hash` | 结算后状态承诺 |
| `ack_chain` | `Vec<AckEntry>` | 正常 checkpoint ack 聚合 |
| `scheme_id` | `u32` | Hypernova(1) / Groth16(2) / IPA(3) |
| `has_partial_checkin` | `bool` | 是否衔接 partial_checkin（SEC2-M8） |

签名域（R5-M6）：`hash(chain_id || game_id || π_hash || state_delta_hash || new_commitment || ack_chain_hash)`。

`execute_checkin()`（`state.rs:273-334`）流程：
1. SEC2-M4：`ack_chain.len() <= max_ack_chain_length`（默认 1000）
2. 构造 `ZkPublicIo`（initial_commitment 由 `last_partial_fold` 决定）
3. SEC2-M8：`has_partial_checkin` 与 `last_partial_fold` 一致性校验（NEW-M6：`ack_chain_partial_hash` 比对）
4. 调用 `registry.zk_verify(chain_id, scheme_id, proof, public_io, max_skip, max_ack)`

### 2.5 partial_checkin（中间结算）

`PartialCheckinTx`（`state.rs:181-194`）用于折叠中断恢复（SEC-H1）：

```rust
pub struct PartialCheckinTx {
    pub game_id: ObjectID,
    pub proof_partial: Vec<u8>,
    pub folded_step_count: u32,
    pub intermediate_commitment: Hash,
    pub ack_chain_partial: Vec<AckEntry>,
    pub scheme_id: u32,
}
```

`execute_partial_checkin()`（`state.rs:344-407`）校验：
- **SEC-H1**：`partial_checkin_count < max_partial_checkin_count`（默认 3，MIN=1，MAX=10）
- **SEC-H1 进度校验**：`tx.folded_step_count > prev.folded_step_count`（否则 `NoProgressPartialCheckin`）
- 链上 verifier 验证 π_partial（Stub 状态下仅校验格式）
- 返回更新后的 `LastPartialFold { intermediate_commitment, folded_step_count, proof_partial_hash, ack_chain_partial_hash }`

---

## 3. Checkpoint 协议

### 3.1 提交间隔

`DEFAULT_CHECKPOINT_INTERVAL_BLOCKS = 5`，`MIN_CHECKPOINT_INTERVAL_BLOCKS = 3`（SEC2-M4，`checkpoint_anchor.rs:40-42`）。操作方每 `checkpoint_interval_blocks` 个 block 提交一次 `CheckpointAnchorTx`，更新 `game.last_action_height`。

### 3.2 CheckpointAnchorTx 结构

定义于 `checkpoint_anchor.rs:79-92`：

| 字段 | 类型 | 说明 |
|------|------|------|
| `game_id` | `ObjectID` | Game 对象 ID |
| `checkpoint_seq` | `u64` | checkpoint 序号（单调递增，去重依据） |
| `current_turn` | `Address` | 当前轮次玩家地址（绑定 ACK 到具体状态） |
| `state_hash` | `Hash` | 链下状态哈希（此 checkpoint 时刻的状态承诺） |
| `ack_signatures` | `Vec<AckSignature>` | 所有活跃参与者的 ACK 签名 |
| `opt_out_ack_proof` | `Option<Vec<OptOutAckProof>>` | ack_deadline 逾期默认 ACK 证明 |

去重：相同 `(game_id, checkpoint_seq)` 仅首次生效；非 `game.checkpoint_seq + 1` 的序号返回 `DuplicateCheckpoint`。

### 3.3 ACK 协议

`AckEntry`（`ack_chain.rs:43-60`）记录单个参与者的 ACK：

```rust
pub struct AckEntry {
    pub chain_id: ChainId,          // R4-H3：防跨链重放
    pub epoch: u64,                 // SEC-C3：防跨 epoch 重放
    pub game_id: ObjectID,
    pub current_turn: Address,
    pub state_hash: Hash,
    pub checkpoint_seq: u64,
    pub participant: TaggedPubkey,
    pub participant_signature: Vec<u8>,
}
```

ACK 签名对象（`ack_chain.rs:89-110` + `checkpoint_anchor.rs:106-124`）：

```text
msg_hash = blake2b_256(
    chain_id || epoch || game_id || current_turn || state_hash ||
    checkpoint_seq || ACK_DOMAIN_TAG(0x02)
)
```

域分离常量（`mod.rs:42-50`）：

| 常量 | 值 | 用途 |
|------|----|------|
| `ACK_DOMAIN_TAG` | `0x02` | ACK 签名 |
| `REFUSE_ACK_DOMAIN_TAG` | `0x03` | refuse_ack 签名 |
| `OPERATOR_ACK_DOMAIN_TAG` | `0x04` | operator_ack 签名 |

`ack_i`（用于 Merkle 树叶子）额外包含 `participant_tagged_pubkey || participant_signature`（R4-M5），与签名消息区分。

### 3.4 ACK 签名覆盖与 opt_out

`verify_checkpoint_anchor()`（`checkpoint_anchor.rs:143-205`）校验：
1. 每个 `ack_signature.participant` 须在 `active_participants` 中（否则 `AckSignerNotParticipant`）
2. 同一 participant 多个 ack 仅首个有效
3. `ack_signatures` + `opt_out_ack_proof` 须覆盖全部 `active_participants`（缺少返回 `MissingAck`）
4. `active_participants` = 当前进度未 fold 且未 sit-out 的在座玩家

`ack_deadline_blocks = 3`。`opt_out_ack_proof`（`checkpoint_anchor.rs:62-69`）字段：`{ participant, request_ack_block_height, ack_deadline }`。`is_opt_out_ack_valid()` 要求 `current_block_height > ack_deadline`（严格大于）。ack_deadline 逾期且无 ACK 无 refuse_ack → 视为默认 ACK，操作方提交带 `opt_out_ack_proof` 的 checkpoint_anchor。refuse_ack dispute 走 `REFUSE_ACK_DOMAIN_TAG` 域分离签名。

### 3.5 ack_chain_hash（RFC 6962 Merkle 树）

`ack_chain_hash = MerkleRoot(ack_1 || ack_2 || ... || ack_n)`（`ack_chain.rs:143-161`）。

域分离（`mod.rs:42-44`）：
- `ACK_MERKLE_LEAF_PREFIX = 0x00`
- `ACK_MERKLE_INTERNAL_PREFIX = 0x01`

构造规则：
- 叶子节点哈希 = `H(0x00 || ack_i)` — 防与内部节点混淆
- 内部节点哈希 = `H(0x01 || left || right)` — 防二次原像攻击
- `EMPTY_LEAF_VALUE = b""`（SEC-L5 空树根 = `H(0x00 || b"")`）
- 单叶子 → `H(0x00 || ack_1)`
- 不平衡树 → RFC 6962 filled subtree 用 `H(0x00 || b"")` 补齐到 2 的幂

```rust
fn merkle_root_from_leaves(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() { return empty_root(); }
    let wrapped: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
    if wrapped.len() == 1 { return wrapped[0]; }
    // 补齐到 2 的幂，用 empty_root() 填充，自底向上合并
    // ...
}
```

`max_ack_chain_length`：DEFAULT=1000，MIN=100，MAX=10000（`mod.rs:55-59`）。Merkle 包含证明 `AckMerkleProof { leaf_index, siblings }` 大小为 `ceil(log2(n))`，1000 个 ack → 10 个 sibling。

### 3.6 SEC-H2 无进度检测

`apply_checkpoint_anchor()`（`checkpoint_anchor.rs:240-275`）：
- `tx.state_hash == game.last_checkpoint_state_hash` → `no_progress_count += 1`
- 否则 → `no_progress_count = 0` + 更新 `last_checkpoint_state_hash` + 重置 `designated_operator_check_exemptions`
- 连续 `DEFAULT_NO_PROGRESS_THRESHOLD = 2` 次相同 state_hash → 触发 `force_revert`

---

## 4. CCS 电路 + Hypernova Fold

### 4.1 CcsInstance 结构

每步链下执行生成一个 CCS 实例（`ccs.rs:33-44`）：

```rust
pub struct CcsInstance {
    pub mat_commitments: Vec<Hash>,    // 约束矩阵 commitments
    pub public_input_hash: Hash,        // 公共输入哈希
    pub witness_commitment: Hash,       // witness commitment（witness 不上链）
    pub state_delta_hash: Hash,         // Δ_i 哈希（聚合到 public_io.state_delta_hash）
    pub ack_step_hash: Hash,            // 该步对应的 ack 集合哈希
}
```

### 4.2 CcsCircuit trait

`CcsCircuit`（`ccs.rs:50-68`）提供电路抽象：

```rust
pub trait CcsCircuit: Send + Sync {
    fn name(&self) -> &str;
    fn num_matrices(&self) -> usize;
    fn to_instance(&self, witness: &[u8], public_inputs: &[u8],
                   state_delta: &[u8], ack_step_hash: Hash)
        -> Result<CcsInstance, PokerL1Error>;
}
```

`ZkShuffleCcsCircuit`（`ccs.rs:240-308`）：`num_mats = 3`（CCS 标准要求 q=2 → 3 个矩阵 A/B/C）。MVP 阶段 `to_instance()` 用 blake2b 对输入做哈希作为 commitments；Production 阶段须接入 `poker_protocol::zk_shuffle` 完整电路转换。

### 4.3 fold_step（单步折叠）

`fold_step(prev, instance, chain_id, game_id) -> FoldStepResult`（`ccs.rs:91-158`）：
- `fold_step_count = prev.fold_step_count + 1`（首次为 1）
- **O15 上限校验**：`fold_step_count > MAX_FOLD_STEP_COUNT(1000)` → `FoldStepCountExceeded`
- 累计 `state_delta_hash`：`blake2b(prev_cumulative || instance.state_delta_hash)`
- 累计 `ack_chain_hash`：`blake2b(prev_cumulative || instance.ack_step_hash)`

`FoldStepResult`（`ccs.rs:72-85`）含 `folded_instance`、`witness_commitment`、`sumcheck`、`cumulative_state_delta_hash`、`cumulative_ack_chain_hash`、`fold_step_count`。

### 4.4 fold_loop（多步折叠）

`fold_loop(instances, initial_commitment, final_commitment, ack_chain_hash, skip_count, segment_continuity_proof) -> FoldLoopResult`（`ccs.rs:185-234`）：

| 参数 | 说明 |
|------|------|
| `instances` | CCS 实例列表（按折叠顺序），`len() <= 1000` |
| `initial_commitment` | 折叠起点状态承诺 |
| `final_commitment` | 折叠终点状态承诺 |
| `ack_chain_hash` | 所有 checkpoint ack 的聚合哈希（由 ack_chain 模块计算） |
| `skip_count` | 被跳过的 checkpoint 段数 |
| `segment_continuity_proof` | 段间连续性证明（R5-H6） |

校验：`instances` 非空 + `len() <= MAX_FOLD_STEP_COUNT`。返回 `FoldLoopResult { proof: HypernovaProof, public_io: ZkPublicIo, fold_step_count }`。

### 4.5 MVP 实现

当前 MVP 采用 **blake2b 哈希链累计**，不实际执行 Hypernova 折叠算法（`ccs.rs:109-148`）。Production 阶段须实现：
1. 完整 CCS 约束矩阵折叠
2. Sumcheck protocol
3. Cross-language claim 验证
4. Fiat-Shamir challenge 重新生成与验证

`MAX_FOLD_STEP_COUNT = 1000`（`mod.rs:53`，O15 修复）防 DoS。

---

## 5. ZK 证明方案

三种 scheme 通过 `SchemeId`（`u32`）标识（`zk_verifier.rs:16-23`）：

### 5.1 Scheme 对比

| Scheme | scheme_id | proof 最小字节 | gas | 用途 |
|--------|-----------|----------------|-----|------|
| Hypernova | `SCHEME_HYPERNOVA = 1` | `HYPERNOVA_PROOF_MIN_SIZE = 64` | 50000 | 多步折叠主方案 |
| Groth16 | `SCHEME_GROTH16 = 2` | `GROTH16_PROOF_SIZE = 192` | 20000 | 单步快速验证 |
| IPA | `SCHEME_IPA = 3` | `IPA_PROOF_MIN_SIZE = 32` | 15000 | 简洁承诺验证 |

### 5.2 Hypernova

`HypernovaProof`（`hypernova.rs:64-99`）：

```rust
pub struct HypernovaProof {
    pub folded_instance: FoldedInstance,    // instance_commitment + fold_step_count
    pub witness_commitment: WitnessCommitment,
    pub final_sumcheck: FinalSumcheck,      // evaluations: Vec<Hash> + final_sum
}
```

- `FoldedInstance.fold_step_count == public_io.fold_step_count`
- `proof_hash() = blake2b_256(to_bytes())`
- Fiat-Shamir challenge（`hypernova.rs:104-113`）：

```rust
pub fn fiat_shamir_challenge(public_io: &ZkPublicIo) -> Hash {
    // challenge = blake2b_256("hypernova_fs" || public_io.to_bytes())
}
```

Stub verifier 仅校验 proof 非空 + `len() >= 64`；Production 须验证 final sumcheck 等式 + folded instance cross-language claim。

### 5.3 Groth16

`Groth16Vk`（`groth16.rs:36-47`）— BLS12-381 compressed：

| 字段 | 长度 | 说明 |
|------|------|------|
| `alpha_g1` | 48B | αG1（G1 compressed） |
| `beta_g2` | 96B | βG2（G2 compressed） |
| `gamma_g2` | 96B | γG2 |
| `delta_g2` | 96B | δG2 |
| `ic` | `Vec<[u8;48]>` | IC = `[γ^{-1}(β·u_i(τ)+α·v_i(τ)+w_i(τ))/γ]_1` |

`Groth16Proof`（`groth16.rs:85-92`）：`a_g1[48] + b_g2[96] + c_g1[48]` = **192 字节**（`GROTH16_PROOF_SIZE`）。

**SEC-M10 CRS fingerprint**（`groth16.rs:51-65`）：

```rust
crs_fingerprint = blake2b_256(alpha_g1 || beta_g2 || gamma_g2 || delta_g2 || ic)
```

- `vk_id = blake2b_256(vk.to_bytes())`
- 注册时同时存储 `crs_fingerprint`，注册后不可更改
- `verify_crs_fingerprint(vk_id)` 校验 `blake2b_256(stored_vk) == crs_fingerprint`，不匹配返回 `CrsFingerprintMismatch`
- 防 **key substitution attack**（攻击者用 weak vk 替换合法 vk）
- 更新 vk 须治理 90% quorum 通过注册新 `vk_id`

**Production 验证等式**（`groth16.rs:188-191`）：

```text
e(A, B) == e(αG1, βG2) * e(L, γG2) * e(C, δG2)
```

其中 `L = Σ IC[i] * public_input[i]`（含 `IC[0] = αG1`）。MVP 未实现 pairing 验证。

### 5.4 IPA

`IpaProof`（`ipa.rs:38-47`）：

```rust
pub struct IpaProof {
    pub l_vec: Vec<[u8; 48]>,    // 折叠轮次 L 向量（G1 点）
    pub r_vec: Vec<[u8; 48]>,    // 折叠轮次 R 向量（G1 点）
    pub a_final: [u8; 32],       // 最终标量 a
    pub b_final: [u8; 32],       // 最终标量 b
}
```

算法（`ipa.rs:8-17`）：
1. prover 提交 commitment `C = <a, G> + <b, H> + <a, b> * U`
2. 每轮 prover 发送 `L_i, R_i`（cross commitments）
3. verifier 发送 challenge `x_i = Fiat-Shamir(transcript)`
4. 折叠：`a' = a_L + x_i^{-1} * a_R`，`b' = b_R + x_i^{-1} * b_L`
5. 最终轮：`a, b` 缩为标量，验证 `C == a * G_final + b * H_final + (a*b) * U`

Stub verifier 校验 proof 非空 + `len() >= 32`；Production 须实现完整内积论证验证（Pedersen 承诺 + 折叠递归 + Fiat-Shamir）。

---

## 6. ZkPublicIo 边界（O15 修复）

所有 ZK scheme 的最终 π 都须包含统一的 `ZkPublicIo` 边界（`zk_verifier.rs:55-71`）— O15 修复防止 fold_step_count 失控。

### 6.1 字段集

| 字段 | 类型 | 约束 |
|------|------|------|
| `initial_commitment` | `Hash` (32B) | 折叠起点状态承诺 |
| `final_commitment` | `Hash` (32B) | 折叠终点状态承诺（== checkin tx 的 `new_commitment`） |
| `state_delta_hash` | `Hash` (32B) | 状态增量哈希（NEW-H4：不可逆，用于 challenge_delta 比对） |
| `ack_chain_hash` | `Hash` (32B) | 所有 checkpoint ack 聚合哈希（仅正常 checkpoint） |
| `fold_step_count` | `u32` (4B) | ≤ 1000（O15） |
| `skip_count` | `u32` (4B) | ≤ `max_skip_segments`（默认 3） |
| `segment_continuity_proof` | `Vec<u8>` (变长) | R5-H6：verify_segment_chain 校验 |

### 6.2 to_bytes() 布局

`MIN_BYTES = 136`（`zk_verifier.rs:129`）。

| 偏移 | 长度 | 字段 |
|------|------|------|
| 0 | 32 | `initial_commitment` |
| 32 | 32 | `final_commitment` |
| 64 | 32 | `state_delta_hash` |
| 96 | 32 | `ack_chain_hash` |
| 128 | 4 | `fold_step_count` (BE u32) |
| 132 | 4 | `skip_count` (BE u32) |
| 136 | 变长 | `segment_continuity_proof` |

### 6.3 validate()

`validate(max_skip_segments, max_ack_chain_length)`（`zk_verifier.rs:79-100`）：
- `fold_step_count <= MAX_FOLD_STEP_COUNT(1000)` — 否则 `FoldStepCountExceeded`
- `skip_count <= max_skip_segments` — 否则 `SkipCountExceeded`
- `ack_chain_length` 由 ack_chain 模块自行校验

边界判定采用 `<=`（SEC2-L6），即 `fold_step_count == 1000` 通过，`1001` 失败。

---

## 7. ZK Verifier 注册表

### 7.1 热插拔机制

`ZkVerifierRegistry`（`zk_verifier.rs:211-216`）以 `BTreeMap<SchemeId, Arc<dyn ZkVerifier>>` 存储 verifier 实例。节点升级新增 verifier 时只需实现 `ZkVerifier` trait 并调用 `register()`，**无需重新编译已部署合约**（spec.md L515-519）。

```rust
pub fn register(&mut self, verifier: Arc<dyn ZkVerifier>) {
    let scheme_id = verifier.scheme_id();
    self.verifiers.insert(scheme_id, verifier);
}
pub fn unregister(&mut self, scheme_id: SchemeId) -> Option<Arc<dyn ZkVerifier>> {
    self.verifiers.remove(&scheme_id)
}
```

### 7.2 per-chain_id verifier_status

`statuses: BTreeMap<ChainId, VerifierStatus>`（`zk_verifier.rs:215`）。未设置时默认 `Stub`。`set_verifier_status()` 升级为 `Production` 须治理 90% quorum + `parameter_delay_blocks` timelock（NEW-C1）。

### 7.3 zk_verify 通用入口

`zk_verify(chain_id, scheme_id, proof, public_io, max_skip, max_ack) -> ZkVerifyResult`（`zk_verifier.rs:278-308`）流程：
1. 查找 verifier（未注册返回 `ZkVerifierNotRegistered`）
2. 查询 `verifier_status(chain_id)`（per-chain_id）
3. 校验 `public_io.validate(max_skip, max_ack)`（O15 + SubTask 27.11）
4. 校验 proof 格式（无论 Stub/Production 都校验）
5. 调用 `verifier.verify(proof, public_io, status)`

### 7.4 ZkVerifier trait

```rust
pub trait ZkVerifier: Send + Sync {
    fn scheme_id(&self) -> SchemeId;
    fn verify(&self, proof: &[u8], public_io: &ZkPublicIo,
              status: VerifierStatus) -> Result<bool, PokerL1Error>;
    fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error>;
}
```

`ZkVerifyResult { verified, verifier_status, scheme_id }` 返回验证结果与所用 verifier 状态，便于 caller 审计。

### 7.5 Stub vs Production

| 状态 | 行为 |
|------|------|
| `Stub` | 仅校验 proof 格式（长度/非空），返回 `verified = true` |
| `Production` | 完整 ZK 验证（MVP 未实现，返回 `Other` 错误） |

便捷注册函数：`register_hypernova_verifier()` / `register_groth16_verifier()` / `register_ipa_verifier()`（各 verifier 模块提供）。

---

## 8. 故障恢复协议

### 8.1 三阶段恢复（RecoveryStage）

`RecoveryStage`（`force_checkin.rs:142-166`）— 纯 timer 驱动，**不要求故障证据**（任何证据可伪造，时间窗口不可伪造）：

| 阶段 | 时间窗口 | 允许操作 | forfeit |
|------|----------|----------|---------|
| Stage1 | `elapsed <= turn_timeout_blocks` | `force_advance`（SEC2-L6：`<=` 边界） | 无 |
| Stage2 | `elapsed <= turn_timeout + da_window + recovery_window` | `request_da` + 参与者重折叠 `force_checkin` | 无 |
| Stage3 | 窗口过期 | `forfeit` + `force_revert` | 是 |

`DEFAULT_RECOVERY_WINDOW_BLOCKS = 100`（`force_checkin.rs:49`）。`elapsed = current_block_height - game.last_action_height`（saturating_sub 防下溢）。

```rust
pub const fn allows_force_advance(&self) -> bool { matches!(self, Self::Stage1 { .. }) }
pub const fn allows_force_checkin(&self) -> bool { matches!(self, Self::Stage2 { .. }) }
pub const fn requires_forfeit_and_revert(&self) -> bool { matches!(self, Self::Stage3 { .. }) }
```

### 8.2 H4 forfeit 边界判定

`ForfeitDecision::compute()`（`force_checkin.rs:94-128`）基于 `last_checkpoint_age = current_block_height - game.last_action_height`：

| 条件 | ForfeitReason | should_forfeit |
|------|---------------|----------------|
| `last_checkpoint_age <= boundary` | `MaliciousWithholding` | true（操作方有能力提交但拒绝） |
| `last_checkpoint_age > boundary` | `MachineFailure` | false（操作方无法提交，可重折叠） |

`boundary = turn_timeout_blocks`（普通操作方）；**designated operator 场景加倍为 `turn_timeout_blocks * 2`**（NEW-M4，`force_checkin.rs:107-111`）。

### 8.3 force_checkin 场景判定

`determine_force_checkin_scenario()`（`force_checkin.rs:344-367`）：

| 条件 | ForceCheckinScenario |
|------|----------------------|
| `last_checkpoint_state_hash == None`（无 checkpoint 广播） | `NotFeasibleRequiresRevert`（纯扣留走 request_revert） |
| 有 checkpoint + H4 判定 MaliciousWithholding | `MaliciousWithholding` |
| 有 checkpoint + H4 判定 MachineFailure | `MachineFailure` |

`apply_force_checkin()`（`force_checkin.rs:470-529`）流程：
1. 判定场景（BEFORE mutation）
2. `NotFeasible` → 拒绝（caller 须改走 `request_revert`）
3. 计算 `ForfeitDecision`
4. 应用 Δ'：标记 `hand.phase = Settled`
5. 更新 `game.last_action_height = current_block_height`
6. 清除 `last_commitment`（checkin 完成 checkout cycle）
7. 清除 `last_checkpoint_state_hash`（已消费）
8. 递增 `version`

### 8.4 designated operator check 豁免

NEW-M4 / R3-M1 / R3-M7（`force_checkin.rs:262-301`）：
- `force_advance` 时**无条件豁免当前轮次玩家**（若为 designated operator）— 改为 check 而非 fold
- Game 维护 `designated_operator_check_exemptions` 计数器
- `DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT = 2`，达上限后恢复 fold 语义
- 防恶意 designated operator 循环停发无限拖延
- state_hash 变化时（`apply_checkpoint_anchor`）重置豁免计数

### 8.5 checkpoint_skip

`checkpoint_skip` tx（`checkpoint_skip.rs`，SubTask 27.10-27.13a）：
- `(game_id, skip_segment_start, skip_segment_end, last_known_state_hash, continuity_proof)`
- 仅更新 `last_action_height` 与 `skip_count += 1`，**不推进 ack_chain_hash**
- `max_skip_segments` 默认 3（SubTask 27.11）；超出则操作方必须提交 `request_revert`
- π 的 public_io 边界包含 `skip_count` + `segment_continuity_proof`
- `continuity_proof` 格式 = `(start_state_proof, end_state_proof)`；`start_state_proof` 须 ≥2/3 参与者 ACK 签名聚合
- R5-H6：`verify_segment_chain()` 逐段校验段间状态连续性

---

## 9. challenge_delta 语义

`challenge_delta` tx（`challenge_delta.rs`，SubTask 28.5）防止操作方在 checkin 时篡改 Δ。

### 9.1 比对逻辑

从 π 的 `public_io.state_delta_hash` 重新派生 Δ'，对比操作方提交的 Δ：

```rust
// 链上无法从 state_delta_hash 逆推正确 Δ'（NEW-H4：哈希不可逆）
// 因此挑战方须自行计算 Δ' 并提交
let claimed_delta_hash = hash_state_delta(&tx.claimed_state_delta);
// 比对 claimed_delta_hash 与 π.public_io.state_delta_hash
```

`hash_state_delta()`（`challenge_delta.rs:113-120`）= `blake2b_256(state_delta)`，与 `CheckinTx::state_delta_hash()` 算法一致。

### 9.2 挑战结果

| 比对结果 | succeeded | 后果 |
|----------|-----------|------|
| `claimed_delta_hash != π.state_delta_hash` | true（挑战成立） | 操作方 forfeit 保证金 + 触发 `request_revert` 回退到最后 ACKed checkpoint |
| `claimed_delta_hash == π.state_delta_hash` | false（挑战失败） | 挑战方 forfeit 保证金（恶意挑战惩罚） |

### 9.3 R4-L7 保证金机制

SEC-C4 修复（`challenge_delta.rs:39-62`）：
- `challenger_deposit = buy_in_amount * challenge_deposit_ratio / 100`
- `DEFAULT_CHALLENGE_DEPOSIT_RATIO = 50`（SEC-C4：由 10 提升，可治理 ∈ [1, 100]）
- `DEFAULT_CHALLENGE_REWARD_RATIO = 100`（SEC-C4：由 50 提升，可治理 ∈ [10, 100]）
- 挑战成立 → 保证金退还 + 从操作方 forfeit 保证金分得 `challenge_reward_ratio %`，剩余按 buy_in 比例分配给其他受害者玩家
- 挑战失败 → 保证金没收分配给操作方

---

## 10. 开发示例

### 10.1 注册全部 verifier 并执行 checkin

```rust
use poker_l1::offline::{
    groth16::register_groth16_verifier, hypernova::register_hypernova_verifier,
    ipa::register_ipa_verifier, state::{CheckinTx, execute_checkin},
    zk_verifier::{ZkVerifierRegistry, VerifierStatus, SCHEME_HYPERNOVA},
    DEFAULT_MAX_ACK_CHAIN_LENGTH,
};
use poker_l1::object_model::ObjectID;

// 1. 注册全部 verifier（热插拔，无需重编译已部署合约）
let mut registry = ZkVerifierRegistry::new();
register_hypernova_verifier(&mut registry);
register_groth16_verifier(&mut registry);
register_ipa_verifier(&mut registry);
// 主网升级到 Production 须治理 90% quorum + timelock：
// registry.set_verifier_status(chain_id, VerifierStatus::Production);

// 2. 构造 checkin tx（Stub + testnet 允许；Stub + mainnet 拒绝）
let tx = CheckinTx {
    game_id: ObjectID::new([0x01; 20], 1),
    proof: vec![0xAA; 64],            // Hypernova proof（Stub: 仅校验长度）
    state_delta: vec![0xBB; 32],       // Δ
    new_commitment: [0xCC; 32],        // 结算后状态承诺
    ack_chain: vec![/* AckEntry ... */],
    scheme_id: SCHEME_HYPERNOVA,
    has_partial_checkin: false,
};

let result = execute_checkin(&tx, &registry, poker_l1::DEFAULT_CHAIN_ID,
    None, 3, DEFAULT_MAX_ACK_CHAIN_LENGTH).expect("checkin 应成功");
assert!(result.verified);
assert_eq!(result.verifier_status, VerifierStatus::Stub);
```

### 10.2 链下 fold_loop 生成 proof

```rust
use poker_l1::offline::ccs::{fold_loop, ZkShuffleCcsCircuit, CcsCircuit};

// 1. 链下执行生成 CCS 实例（每步一个）
let circuit = ZkShuffleCcsCircuit::new();  // num_mats = 3 (A/B/C)
let instances: Vec<_> = (0..5).map(|step| circuit.to_instance(
    &witness[step], &public_inputs[step], &state_delta[step], ack_step_hashes[step])
).collect::<Result<_, _>>()?;

// 2. 多步折叠为单个 proof（O15: instances.len() <= 1000）
let result = fold_loop(&instances, initial_commitment, final_commitment,
    ack_chain_hash, 0, segment_continuity_proof)?;

// 3. 提交 checkin：proof + Δ + new_commitment + ack_chain
let tx = CheckinTx {
    proof: result.proof.to_bytes(),
    state_delta: aggregated_delta,
    new_commitment: result.public_io.final_commitment,
    ack_chain, scheme_id: SCHEME_HYPERNOVA, has_partial_checkin: false, game_id,
};
```

### 10.3 ack_chain_hash 计算

```rust
use poker_l1::offline::ack_chain::{AckEntry, compute_ack_chain_hash, prove_ack_inclusion};

// 构造 AckEntry 列表（每个 checkpoint 一个），计算 RFC 6962 Merkle root
let entries: Vec<AckEntry> = checkpoints.iter().map(|cp| AckEntry {
    chain_id, epoch, game_id: cp.game_id, current_turn: cp.current_turn,
    state_hash: cp.state_hash, checkpoint_seq: cp.seq,
    participant: cp.participant.clone(), participant_signature: cp.signature.clone(),
}).collect();
let root = compute_ack_chain_hash(&entries);

// 生成包含证明（O(log n) 大小）：1000 entries → 10 个 sibling
let proof = prove_ack_inclusion(&entries, 0).expect("proof 应生成");
assert_eq!(proof.siblings.len(), 10);
```

### 10.4 故障恢复 force_checkin

```rust
use poker_l1::vm::contracts::force_checkin::{ForceCheckinInput, apply_force_checkin, RecoveryStage};

let stage = RecoveryStage::compute(&game, current_block_height,
    turn_timeout_blocks, da_window_blocks, recovery_window_blocks);
match stage {
    RecoveryStage::Stage1 { .. } => { /* force_advance 可触发，无 forfeit */ }
    RecoveryStage::Stage2 { .. } => {
        // request_da + 参与者重折叠 force_checkin
        let input = ForceCheckinInput::new(current_block_height,
            is_designated_operator, turn_timeout_blocks,
            new_commitment, state_delta_prime);  // 参与者自行计算
        let outcome = apply_force_checkin(&mut game, &input)?;
        // outcome.should_forfeit: H4 边界判定（age <= boundary → forfeit）
    }
    RecoveryStage::Stage3 { .. } => { /* forfeit + force_revert */ }
}
```

---

## 附录 A：常量速查

| 常量 | 值 | 来源 | 说明 |
|------|----|------|------|
| `MAX_FOLD_STEP_COUNT` | 1000 | `mod.rs:53` | O15 fold_step_count 上限 |
| `DEFAULT/MIN/MAX_MAX_ACK_CHAIN_LENGTH` | 1000 / 100 / 10000 | `mod.rs:55-59` | ack_chain 长度边界（SEC2-M4） |
| `DEFAULT/MIN/MAX_MAX_PARTIAL_CHECKIN_COUNT` | 3 / 1 / 10 | `mod.rs:61-65` | SEC-H1 partial_checkin 次数边界 |
| `DEFAULT/MIN_CHECKPOINT_INTERVAL_BLOCKS` | 5 / 3 | `checkpoint_anchor.rs:40-42` | checkpoint 间隔（SEC2-M4） |
| `DEFAULT_NO_PROGRESS_THRESHOLD` | 2 | `checkpoint_anchor.rs:44` | SEC-H2 无进度阈值 |
| `DEFAULT_RECOVERY_WINDOW_BLOCKS` | 100 | `force_checkin.rs:49` | Stage2 恢复窗口 |
| `DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT` | 2 | `force_checkin.rs:51` | NEW-M4 豁免上限 |
| `DEFAULT_MAX_SKIP_SEGMENTS` | 3 | `checkpoint_skip.rs:38` | skip_count 上限（SubTask 27.11） |
| `ACK_DOMAIN_TAG` / `REFUSE_ACK_DOMAIN_TAG` / `OPERATOR_ACK_DOMAIN_TAG` | 0x02 / 0x03 / 0x04 | `mod.rs:46-50` | 签名域分离 |
| `ACK_MERKLE_LEAF_PREFIX` / `ACK_MERKLE_INTERNAL_PREFIX` | 0x00 / 0x01 | `mod.rs:42-44` | RFC 6962 域分离 |
| `EMPTY_LEAF_VALUE` | `b""` | `ack_chain.rs:36` | SEC-L5 空树根 |
| `HYPERNOVA_PROOF_MIN_SIZE` / `GROTH16_PROOF_SIZE` / `IPA_PROOF_MIN_SIZE` | 64 / 192 / 32 | 各 verifier 模块 | proof 字节下限 |
| `SCHEME_HYPERNOVA` / `SCHEME_GROTH16` / `SCHEME_IPA` | 1 / 2 / 3 | `zk_verifier.rs:19-23` | scheme_id |
| `ZkPublicIo::MIN_BYTES` | 136 | `zk_verifier.rs:129` | public_io 最小字节 |

## 附录 B：源文件索引

| 模块 | 路径 |
|------|------|
| offline 模块入口 + 公共常量 | `poker_l1/src/offline/mod.rs` |
| OfflineState / CheckoutTx / CheckinTx / PartialCheckinTx | `poker_l1/src/offline/state.rs` |
| CCS 电路 / fold_step / fold_loop / ZkShuffleCcsCircuit | `poker_l1/src/offline/ccs.rs` |
| Hypernova Proof / Fiat-Shamir / Verifier | `poker_l1/src/offline/hypernova.rs` |
| Groth16 Vk / Proof / CRS fingerprint / Verifier | `poker_l1/src/offline/groth16.rs` |
| IPA Proof / Verifier | `poker_l1/src/offline/ipa.rs` |
| ZkVerifier trait / ZkVerifierRegistry / ZkPublicIo | `poker_l1/src/offline/zk_verifier.rs` |
| AckEntry / RFC 6962 Merkle 树 / 包含证明 | `poker_l1/src/offline/ack_chain.rs` |
| CheckpointAnchorTx / ACK 验证 / SEC-H2 | `poker_l1/src/vm/contracts/checkpoint_anchor.rs` |
| force_checkin / RecoveryStage / ForfeitDecision | `poker_l1/src/vm/contracts/force_checkin.rs` |
| challenge_delta / 保证金机制 | `poker_l1/src/vm/contracts/challenge_delta.rs` |
| checkpoint_skip / StateProof / segment_continuity | `poker_l1/src/vm/contracts/checkpoint_skip.rs` |

---

**文档版本**：SubTask 37.3 — 链下证明开发文档 | 规范依据：`spec.md`（FROZEN 2026-06-27）| MVP（verifier 均为 Stub）；Production 升级须治理 90% quorum + `parameter_delay_blocks` timelock
