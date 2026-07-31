# H-source 接线：共识来源 inclusion-proof 闭合

## 背景与已确认事实

经核验，当前 `ExpectedChainAnchor` 在生产中**无处构造**——唯一构造点都在测试里，且都从「正在被证明的 task」自推（正是文档警告的反模式）。`proving_service` 的 `TexasPokerPlugin::verify_chain` 只做未锚定的相邻连续性检查。

**关键约束（决定方案形状）**：共识层 `DagCommitCertificate` 只签名
- `state_root`（全局对象 SMT root，blake2b，depth 256，key=`blake2b(ObjectID)`，value=BCS(Object)）
- `public_tx_root` / `gameturn_tx_root`（**order-independent** SMT，leaf=tx_hash）

它**不**签名「某 table+hand 的有序调用序列」。因此「完整 inclusion-proof」只能逐 tx 认证其属于该块，顺序由 `hand_id`/`call_seq` 重建（依赖 Bullshark projection，文档化）。

**已确认可复用原语**：
- `SparseMerkleTree::verify(root, key, value: Option<&[u8]>, path) -> bool`（`object_model/smt.rs:243`）
- `DagCommitCertificate::signing_hash(chain_id)` / `validate_commit_certificate_fields` / `validate_commit_certificate_quorum`（`consensus/mod.rs:240`、`bullshark.rs:375/350`）
- `signature::unified::verify_signature(tagged_pubkey, sig, msg_hash)`（`signature/unified.rs:22`）
- `verify_light_client_header`（`network/mod.rs:754`）——签名验证的模板（去重 + 2/3 + 逐签名）
- `dispatch_call_digest(context, selector, raw_args)`（`poker_texas_air/prove_task.rs:40`）——从 `{tx.contract_call, BlockHeader}` 可完整重算
- `compute_state_root(&table)`（`state_root.rs:144`）→ `StateRoot`，与 `ExpectedChainAnchor.pre/post_state_root` 同型
- 表对象固定 ObjectID = `reserved::texas_poker_contract_id()`，存于全局 SMT（`store.rs:27/110`）

**缺失原语**：`DagCommitCertificate` 的 secp256k1 quorum **签名验证函数不存在**（只有 bit-count）。这是本次主要新增代码。

---

## 实施方案（4 个文件改动 + 测试）

### 1. 新增 cert 签名验证 — `poker_l1/src/consensus/cert_verification.rs`（新文件）

镜像 `verify_light_client_header`（去重 → 2/3 quorum → 逐签名 verify_fn），适配 `DagCommitCertificate` 的 bitmap+签名列表布局。

```rust
/// 校验 DagCommitCertificate 的 secp256k1 quorum 签名。
/// - 先调 validate_commit_certificate_quorum（bit-count ≥ 2/3）
/// - 按 signer_bitmap 升序 set-bit 与 signature_list **紧凑对应**，逐签名
///   用 verify_fn(pubkey, sig, signing_hash) 验证
/// - 去重防同一 validator 多签刷 quorum
pub fn verify_commit_certificate_signatures(
    cert: &DagCommitCertificate,
    chain_id: ChainId,
    validators: &[ValidatorEntry],          // signer_bitmap bit i → validators[i]
    verify_fn: impl Fn(&TaggedPubkey, &[u8], &[u8; 32]) -> PokerL1Result<()>,
) -> PokerL1Result<()>
```
逻辑：计算 `msg = cert.signing_hash(chain_id)`；遍历 `signer_bitmap` 的 set-bit（升序），与 `signature_list` 逐元素配对（set-bit 数必须 == `signature_list.len()`，否则 `SignatureBitmapMismatch`）；对每个 `(validator_pubkey, sig, msg)` 调 `verify_fn`；用 BTreeSet 去重 validator index。`validate_commit_certificate_quorum(cert, validators.len())` 复用现有 2/3 计数。`validators` 为 `&[ValidatorEntry]` 以避免强依赖 `ValidatorSet` 全结构（`ValidatorSet.validators: Vec<ValidatorEntry>`，`validator_set.rs:302`）。

在 `consensus/mod.rs` 注册 `pub mod cert_verification;`。新增错误变体 `PokerL1Error::SignatureBitmapMismatch`（若不存在）。

### 2. 新增 anchor 共识来源 — `poker_texas_air/src/consensus_anchor.rs`（新文件）

提供把「已认证 Block + DagCommitCertificate + 每调用 SMT 包含证明」转换成 `ExpectedChainAnchor` 的工厂。**不改 `ExpectedChainAnchor` 结构**（其字段与构造器已 sound，见核验）。

核心类型与函数：

```rust
/// 一个已认证的 dispatch 调用及其在块内的包含证明。
pub struct ConsensusDispatchCall {
    pub tx: Transaction,                 // 来自 Block.public_txs/gameturn_txs
    pub lane: TxLane,                    // 选择用 public_tx_root 还是 gameturn_tx_root
    pub inclusion_path: MerklePath,      // SparseMerkleTree::prove 的结果
}

/// 从共识材料构造 ExpectedChainAnchor，每步都做密码学校验。
pub fn build_anchor_from_consensus(
    block_header: &BlockHeader,
    cert: &DagCommitCertificate,
    chain_id: ChainId,
    validators: &[ValidatorEntry],
    table_object_id: ObjectID,
    pre_table: &TexasPokerTable,
    post_table: &TexasPokerTable,
    pre_table_inclusion: &MerklePath,    // 单桌 snapshot ∈ 全局 state_root
    calls: &[ConsensusDispatchCall],     // 已按 call_seq 排序
) -> TexasAirResult<ExpectedChainAnchor>
```

校验步骤（任一失败返回 `ConsensusAnchorError`）：
1. **块认证**：`validate_commit_certificate_fields(cert, expected…, header.state_root, header.public_tx_root, header.gameturn_tx_root)` + `verify_commit_certificate_signatures(cert, chain_id, validators, signature::unified::verify_signature)`。
2. **单桌 snapshot ∈ 全局 root**：`SparseMerkleTree::verify(&header.state_root, &table_object_id.merkle_key(), Some(&borsh(pre_table)), pre_table_inclusion)` ——锚定端点 `pre_state_root = compute_state_root(pre_table)`。对 `post_table` 同理（post snapshot 与其包含证明由调用方提供，见「端点 root 处理」）。
3. **逐调用包含**：对每个 `call`，用 `block_header` 字段重建 `DispatchContext`（caller=`derive_address(tx.tagged_pubkey)`、caller_pubkey=`tx.tagged_pubkey`、chain_id=`tx.chain_id`、block_height=`header.height`、block_timestamp=`header.timestamp_ms`），取 selector=`tx.contract_call.method_selector`、raw_args=`tx.contract_call.args`，重算 `dispatch_call_digest(&ctx, &sel, &args)`，并用 `SparseMerkleTree::verify(&对应 tx_root, &blake2b(tx.tx_hash()), Some(&tx.tx_hash()), &call.inclusion_path)` 认证该 tx ∈ 块。
4. 从 `pre_table`/`post_table` 读 `table_id`/`hand_id`/`first_call_seq`/`pre_version`/`post_version`，配 `dispatch_call_digests`（步骤 3 重算的有序列表），调 `ExpectedChainAnchor::new(...)`。

**端点 root 处理（按用户选择「锚定单桌 table snapshot」）**：`pre/post_state_root = compute_state_root(table)`（Poseidon252，与 receipt 同型），其真实性由「该 table 对象 ∈ 全局 block state_root 的 SMT 包含证明」保证（步骤 2）。这复用 `SparseMerkleTree::verify`，**不改 `ExpectedChainAnchor` 结构**。post snapshot 的 SMT 包含证明针对下一块的 state_root（同一 table object 的新版本）——在调用参数中显式提供并文档化。

文档化边界（写入模块 doc）：调用顺序由 `call_seq` 重建，信任根仍是 quorum 签名过的 tx 集合（order-independent SMT）；线性顺序依赖 Bullshark projection 一致性。

在 `poker_texas_air/src/lib.rs` 注册 `pub mod consensus_anchor;`。`poker_texas_air/Cargo.toml` 已依赖 `poker_l1`。

### 3. 接入 proving_service — `proving_service/src/contracts/texas_poker.rs`

新增 plugin 方法（trait 之外的具体方法，保持 trait 稳定）：
```rust
pub fn verify_chain_against_consensus(
    &self,
    anchor: &ExpectedChainAnchor,
) -> PluginResult<()>
```
内部调 `self.orchestrator.proven()` 已有的 receipt chain，用 `Orchestrator` 现有 `verify_against_anchor` 路径（即 `VerifiedChain::verify_against_anchor`）。**删除/改写 `verify_chain` 里那条「服务尚未接入共识来源」TODO 注释**，指向新方法。`runner.rs` 的 demo 路径保持未锚定（它是 lifecycle 覆盖 demo，非生产），但新增一条注释说明生产应走 `verify_chain_against_consensus`。

不在 HTTP server 新增端点（避免扩大面）；anchor 构造的入口是 `build_anchor_from_consensus`，由未来 L1 submit 层调用。

### 4. 更新文档 — `poker_texas_air/docs/PO5_PO6_DESIGN_NOTES.md`

把 P05-H-source 从 🟡 改为 ✅（附新文件路径 + 「cert 签名验证、SMT 包含证明、单桌 snapshot 锚定」说明），总结对照表同步。明确剩余边界（顺序依赖 Bullshark projection；post snapshot 跨块）。

---

## 测试（新增，均在各自 crate 的 `#[cfg(test)]`）

1. **`poker_l1` — `cert_verification` 单测**：
   - 真 quorum：用 `assemble_commit_certificate` + 真实 secp256k1 对 `signing_hash` 签名（≥2/3 validator）→ 验证通过。
   - 不足 quorum / 错误 msg / 重复 signer / bitmap 与 signature_list 数量不匹配 → 各自 fail。
2. **`poker_l1` — 集成**：复用 `bullshark.rs:762` 的 `project_block_from_commit` 模式产出真块（tx 在 `gameturn_txs`），用 `SparseMerkleTree::prove` 取包含路径，验证 `verify` 通过。
3. **`poker_texas_air` — `consensus_anchor` 单测**：
   - 正路：构造真块 + 真 cert + 真 SMT 包含证明 → `build_anchor_from_consensus` 成功，且产出的 anchor 与手动 `ExpectedChainAnchor::new(...)` 字段一致。
   - 篡改回归：篡改 tx args（digest 变）、篡改 pre_table（snapshot 包含证明失败）、用错误 validator 集（cert 签名失败）、用不匹配的 tx_root → 全部 fail。
   - 端到端：`build_anchor_from_consensus` 产出 anchor → `Orchestrator::prove_and_verify_chain_against(tasks, &anchor)` 对真 task 序列通过。

---

## 风险与取舍

- **主要新代码 = cert 签名验证**。镜像已有 `verify_light_client_header`，低风险；bitmap/sig 紧凑对应约定需在测试里固化。
- **不改任何 sound 类型结构**（`ExpectedChainAnchor`/`VerificationReceipt` 字段私有、构造器不变），只新增「如何安全填字段」的工厂。现有 fail-closed gate 全部保留。
- **顺序不在签名内**是固有约束，文档化为信任 Bullshark projection；不尝试伪造「签名过的有序序列」（那需改共识 schema，超出 H-source 范围）。
- post snapshot 跨块：pre 来自本块 state_root，post 来自下一块——在参数中显式提供，不在本次自动跨块拼接。

工作量估：cert 验证 ~0.5 天、anchor 工厂 ~1 天、测试 ~1 天、文档+接线 ~0.5 天。无密码学新设计（全部复用已审计原语）。