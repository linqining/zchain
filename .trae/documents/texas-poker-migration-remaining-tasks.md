# Texas Poker 迁移剩余任务执行计划

> **状态**：待用户批准
> **前置**：B.1（poker_protocol borsh feature）、A.1-A.3（ObjectBackend + Snapshot + executor 泛型化）已完成并验证
> **范围**：完成 3-part 目标的剩余 4 个任务（A.4 / A.5 / B.2 / B.3 / B.4）+ 端到端验证

---

## 1. Summary（任务总览）

本计划承接上一会话已完成的基础设施工作，完成用户 3-part 目标的剩余部分：

1. **Task 3 接线**（A.4-A.5）：将 `executor::execute_block` 接入主链 `build_block_from_vertex`，让 block 中的 tx 真正执行并产生新 `state_root`。
2. **Task 1 替换**（B.2-B.3）：删除 `texas_poker/crypto/` 13 文件，`types.rs` 字段从 `Vec<u8>` 改为 typed `poker_protocol` 类型；`state_machine.rs` 改 `use poker_protocol::*`，新建 `utils.rs` 适配缺失函数。
3. **Task 2 迁移**（B.4）：全量 `bcs → borsh` 迁移（合约层 + Object 持久化层，破坏 on-disk 格式）。
4. **端到端验证**：`cargo build --workspace` + `cargo test --workspace` + `cargo clippy --workspace`。

---

## 2. Current State Analysis（当前状态分析 — 已验证）

### 2.1 已完成工作（无需重做）

| 文件 | 状态 | 验证方式 |
|------|------|----------|
| `/Users/mac/projects/zchain/Cargo.toml` | ✅ 已含 `poker_protocol = { path = "../zgame/poker_protocol", features = ["borsh"] }` + `borsh = "1.5"` workspace 依赖 | `rg poker_protocol` 确认 |
| `/Users/mac/projects/zchain/poker_l1/Cargo.toml` | ✅ 已含 `poker_protocol = { workspace = true }` + `borsh = { workspace = true }` | `rg poker_protocol` 确认 |
| `/Users/mac/projects/zgame/poker_protocol/src/borsh_impls.rs` | ✅ 已创建（10 类型 BorshSerialize/Deserialize） | 上一会话 180 tests pass |
| `/Users/mac/projects/zchain/poker_l1/src/storage/object_backend.rs` | ✅ 已创建（ObjectBackend trait + ObjectDb impl） | 文件存在，133 行 |
| `/Users/mac/projects/zchain/poker_l1/src/storage/object_db_snapshot.rs` | ✅ 已创建（ObjectDbSnapshot + 6 tests） | 文件存在，292 行 |
| `/Users/mac/projects/zchain/poker_l1/src/storage/object_db.rs` | ✅ 已加 `create_snapshot()` 方法 | A.2 完成 |
| `/Users/mac/projects/zchain/poker_l1/src/object_model/{store,smt}.rs` | ✅ 已加 `#[derive(Clone)]` | A.2 完成 |
| `/Users/mac/projects/zchain/poker_l1/src/executor.rs` | ✅ `execute_tx`/`execute_block` 已泛型化 `<B: ObjectBackend>` | line 171, 488 确认 |
| `/Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs` | ✅ `Precompile::call` + `PrecompileRegistry::execute` 已改 `&mut dyn ObjectBackend` | A.3 完成 |
| `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/{game,texas_poker}_precompile.rs` | ✅ `call` 签名已改 `&mut dyn ObjectBackend` | A.3 完成 |
| `/Users/mac/projects/zchain/poker_l1/src/node/mod.rs` | ✅ line 714 已改 `&mut *object_db`（MutexGuard deref） | A.3 完成 |

### 2.2 build_block_from_vertex 当前状态（A.4 目标）

- **位置**：`/Users/mac/projects/zchain/src/main.rs:1021-1091`
- **当前签名**：`fn build_block_from_vertex(vertex, chain_id, commit_round, prev_commit_hash, prev_block_hash, height, state_root: Hash, secret_key) -> Result<Block, String>`
- **当前行为**（line 1018-1020 注释）："当前未接入 tx 执行引擎，caller 应传入上一 block 后的 state_root"
- **caller**：`run_validator_loop`（line 1214）调用时传 `node.state_root()`（旧值，未执行 tx）
- **state_root 使用点**：line 1057（cert.state_root）+ line 1084（header.state_root）

### 2.3 Node 当前状态

- **位置**：`/Users/mac/projects/zchain/poker_l1/src/node/mod.rs:300-331`
- **关键字段**：
  - `object_db: std::sync::Mutex<ObjectDb>`（line 306）
  - `account_store: std::sync::Mutex<AccountStore>`（line 310）
  - `precompile_registry: Arc<PrecompileRegistry>`（line 330）
- **`state_root()` 方法**（line 720-731）：`&self` → `Hash`，委托 `object_db.state_root()`
- **已有方法**：`put_block`、`put_vertex`、`block_store()`、`submit_tx` 等
- **缺口**：无 `execute_block_on_state` 封装方法（A.4 需新增）

### 2.4 texas_poker/crypto/ 当前状态（B.2 目标）

- **位置**：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/crypto/`
- **13 文件**：`mod.rs` + `bls_elgamal.rs` + `bls_scalar.rs` + `chaum_pedersen.rs` + `leave_proof.rs` + `reconstruct_proof.rs` + `remask_proof.rs` + `reveal_token_proof.rs` + `schnorr_proof.rs` + `serialization.rs` + `shuffle_proof.rs` + `transcript.rs` + `zk_verifier.rs`
- **完全重复**：与 `poker_protocol` 的 `crypto/` + `zk_shuffle/` 模块功能重叠

### 2.5 state_machine.rs 当前状态（B.3 目标）

- **位置**：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/state_machine.rs`（2814 行）
- **crypto 引用点**（grep 确认）：
  - line 32-38：`use super::crypto::{bls_elgamal as elgamal, bls_scalar::{...}, serialization as ser, zk_verifier}`
  - line 1147：`super::crypto::remask_proof::verify(...)`
  - line 1155：`super::crypto::shuffle_proof::verify(...)`
  - line 1245：`super::crypto::shuffle_proof::verify(...)`
  - line 1346：`super::crypto::reveal_token_proof::verify(...)`
  - line 1562：`super::crypto::leave_proof::verify(...)`
  - 另有 `verify_pk_ownership` / `verify_reconstruct` 通过 `zk_verifier` 间接调用
- **工具函数**（line 53-68）：`bytes_ct_to_g1` / `g1_ct_to_bytes` / `pk_to_g1`（bytes↔G1 转换，typed 化后可大幅简化）

### 2.6 poker_protocol 可用 API

- **位置**：`/Users/mac/projects/zgame/poker_protocol/src/`
- **模块结构**：
  - `crypto/`：`curve.rs`（ElGamalCiphertext/G1Projective/Scalar 等核心类型）、`elgamal.rs`、`types.rs`
  - `zk_shuffle/`：`shuffle_proof.rs`（ZKShuffleProof）、`dleq_proof.rs`（DLEqProof + RemaskKind/LeaveKind）、`remask_proof.rs`、`reveal_token_proof.rs`、`reconstruction/`、`generalized_schnorr_proof.rs`、`leave_proof.rs`、`transcript_ext.rs`（CryptoTranscript trait + MerlinTranscript）
  - `z_poker/`：上层游戏逻辑
- **`DefaultCurve = Bls12381Curve`**（基于 blstrs）
- **borsh feature**：已启用，10 类型已 impl BorshSerialize/Deserialize

### 2.7 bcs 调用点分布（B.4 目标）

`rg "bcs::" --type rust` 确认 **35 个文件** 含 bcs 调用：

| 区域 | 主要文件 | 迁移策略 |
|------|----------|----------|
| Object 持久化 | `storage/object_db.rs`, `object_model/{id,object,ownership,store}.rs` | derive Borsh + `borsh::to_vec`/`from_slice` |
| Block/Vertex 持久化 | `storage/{block_store,dag_vertex_store}.rs`, `block/mod.rs` | 同上 |
| Account | `account/mod.rs` | 同上 |
| 合约 dispatch | `vm/contracts/dispatch.rs`（19 处）, `vm/contracts/{game,texas_poker}_precompile.rs` | 同上 |
| Texas poker 内部 | `vm/contracts/texas_poker/{dispatch,events,side_pot,types}.rs` | 同上 |
| 共识 | `consensus/*` | 同上 |
| 交易/签名 | `transaction/mod.rs`, `signature/tagged_pubkey.rs` | 同上 |
| VM syscalls | `vm/syscalls.rs` | 同上 |
| 同步/main | `sync/mod.rs`, `src/main.rs` | 同上 |

---

## 3. Proposed Changes（变更方案）

### Track A：Tx 执行引擎接线（A.4-A.5）

#### A.4 — build_block_from_vertex 接线 + Node 封装

**决策**：采用**直接执行**（非 snapshot），理由：
1. `execute_block` 已设计为"失败 tx 返回失败回执，不阻断 block"，仅 RocksDB 写失败等底层错误才传播
2. account_store 无法 snapshot（A.1-A.2 只覆盖 object_db），混用 snapshot + direct 会导致状态不一致
3. snapshot 基础设施（A.1-A.2）保留供未来 RPC preview / reorg 场景使用
4. 与已批准计划一致（最简路径）

**文件 1**：`/Users/mac/projects/zchain/poker_l1/src/node/mod.rs`

新增方法（封装锁获取 + execute_block 调用）：

```rust
/// 在当前链状态上执行 txs，返回执行结果（含新 state_root）。
///
/// 供 `build_block_from_vertex` 在产块时调用：执行 vertex 中的 txs，
/// 取 `outcome.state_root` 作为新 block 的 state_root。
///
/// 内部加锁 `object_db` + `account_store`，调用 `executor::execute_block`。
/// 失败（如锁中毒）返回 `PokerL1Error`。
pub fn execute_block_on_state(
    &self,
    env: &ExecutionEnvironment,
    txs: &[Transaction],
) -> PokerL1Result<BlockExecutionOutcome> {
    let mut object_db = self.object_db.lock().map_err(|e| {
        PokerL1Error::Other(format!("object_db mutex poisoned: {e}"))
    })?;
    let mut account_store = self.account_store.lock().map_err(|e| {
        PokerL1Error::Other(format!("account_store mutex poisoned: {e}"))
    })?;
    Ok(execute_block(env, txs, &mut *object_db, &mut *account_store))
}
```

**文件 2**：`/Users/mac/projects/zchain/src/main.rs`（修改 `build_block_from_vertex` line 1021-1091）

签名变更：
```rust
fn build_block_from_vertex(
    vertex: &DagVertex,
    chain_id: poker_l1::ChainId,
    commit_round: u64,
    prev_commit_hash: Hash,
    prev_block_hash: Hash,
    height: u64,
    node: &Node,           // ← 替换 state_root: Hash
    prev_state_root: Hash, // ← 供 fallback / 日志对比
    secret_key: &secp256k1::SecretKey,
) -> Result<Block, String>
```

流程改造（在 step 3 "计算 roots" 之后，step 4 "构造 commit cert" 之前插入）：
```rust
// 3.5 执行 txs，得到新 state_root
let env = ExecutionEnvironment::new(chain_id, height, timestamp_ms)
    .with_precompile_registry_arc(node.precompile_registry());  // 需新增 Node::precompile_registry() 访问器
let outcome = node.execute_block_on_state(&env, &sorted_txs)
    .map_err(|e| format!("execute_block failed: {e}"))?;
let state_root = outcome.state_root;
// 注：execute_block 已处理失败 tx（返回失败回执，不阻断 block），
// 故此处仅在底层错误（锁中毒 / RocksDB 写失败）时返回 Err
```

**关键调整**：
- `timestamp_ms` 提前到 step 3.5 之前计算（原 step 7 才算）
- 移除 line 1018-1020 "未接入" 注释
- `cert.state_root`（line 1057）+ `header.state_root`（line 1084）改用 `outcome.state_root`

**文件 3**：`/Users/mac/projects/zchain/src/main.rs`（修改 `run_validator_loop` line 1214）

调用点改造：
```rust
match build_block_from_vertex(
    prev_vertex,
    chain_id,
    commit_round,
    prev_commit_hash,
    prev_block_hash,
    node.block_store().get_tip_height().ok().flatten().map(|h| h + 1).unwrap_or(1),
    &node,                      // ← 替换 node.state_root()
    node.state_root(),          // ← prev_state_root（fallback / 日志）
    &secret_key,
) {
```

**文件 4**：`/Users/mac/projects/zchain/poker_l1/src/node/mod.rs`

新增 `precompile_registry()` 访问器（供 main.rs 构造 ExecutionEnvironment）：
```rust
/// 获取预编译合约注册表引用（共享 Arc）。
#[must_use]
pub fn precompile_registry(&self) -> Arc<PrecompileRegistry> {
    Arc::clone(&self.precompile_registry)
}
```

#### A.5 — Track A 验证

```bash
cd /Users/mac/projects/zchain
cargo build -p poker_l1 2>&1 | tail -30
cargo build 2>&1 | tail -30          # 编译 src/main.rs
cargo test -p poker_l1 --lib executor 2>&1 | tail -30
cargo test -p poker_l1 --lib storage 2>&1 | tail -30
cargo test -p poker_l1 --lib node 2>&1 | tail -30
```

---

### Track B：poker_protocol 替换 + Borsh 迁移（B.2-B.4）

#### B.2 — 删除 texas_poker/crypto/ + types.rs typed 化

**步骤 1**：删除 13 文件

```
poker_l1/src/vm/contracts/texas_poker/crypto/
├── mod.rs
├── bls_elgamal.rs
├── bls_scalar.rs
├── chaum_pedersen.rs
├── leave_proof.rs
├── reconstruct_proof.rs
├── remask_proof.rs
├── reveal_token_proof.rs
├── schnorr_proof.rs
├── serialization.rs
├── shuffle_proof.rs
├── transcript.rs
└── zk_verifier.rs
```

**步骤 2**：修改 `poker_l1/src/vm/contracts/texas_poker/mod.rs`

- 移除 `pub mod crypto;`
- 新增 `pub mod utils;`（B.3 创建）

**步骤 3**：修改 `poker_l1/src/vm/contracts/texas_poker/types.rs`

字段类型替换映射（Vec<u8> → typed poker_protocol 类型）：

| 当前字段 | 新类型 | 说明 |
|----------|--------|------|
| `ElGamalCiphertext { c1: Vec<u8>, c2: Vec<u8> }` | 直接删除该本地类型，改 `use poker_protocol::crypto::curve::ElGamalCiphertext as PpElGamalCiphertext` | poker_protocol 已有同名类型 |
| `Seat.pk: Vec<u8>` | `G1Projective`（`poker_protocol::crypto::curve::G1Projective`） | 公钥点 |
| `RevealTokenData.token: Vec<u8>` | `G1Projective` | token 点 |
| `ReconstructState.coefficient: Vec<u8>` | `BlsScalar`（`poker_protocol::crypto::curve::Scalar`） | 重构系数 |
| `DecryptedCard.ciphertext_bytes: Vec<u8>` | `Option<PpElGamalCiphertext>`（None = 已完全解密） | 部分解密密文 |
| `DecryptedCard.plaintext_bytes: Vec<u8>` | `Option<G1Projective>`（None = 仅部分解密） | 明文牌点 |
| `DeckState.aggregated_pk: Vec<u8>` | `G1Projective` | 聚合公钥 |
| `DeckState.plaintext: Vec<Vec<u8>>` | `Vec<G1Projective>` | 明文牌组 |

**保留为 Vec<u8> 的字段**（无对应 typed 类型或不需要 typed）：
- `Seat.hand: Vec<Card>` — Card 是本地类型（不是密码学点）
- `ReconstructPlayerDeck.output_cts: Vec<ElGamalCiphertext>` — 改为 `Vec<PpElGamalCiphertext>`

**derive 调整**：
- 所有结构体添加 `#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]`（依赖 B.1）
- 保留 `Serialize, Deserialize`（serde 仍用于 RPC / 调试场景）

**ElGamalCiphertext 本地类型处理决策**：
- **删除本地 `ElGamalCiphertext`**，全局改用 `poker_protocol::crypto::curve::ElGamalCiphertext`
- 影响 `types.rs` + `state_machine.rs`（line 46 `use super::types::ElGamalCiphertext as BytesCiphertext`）+ `dispatch.rs`
- 别名 `pub type ElGamalCiphertext = poker_protocol::crypto::curve::ElGamalCiphertext;` 在 `types.rs` 顶部（过渡期兼容）

#### B.3 — state_machine.rs 改 use poker_protocol::* + utils.rs

**步骤 1**：替换 import（line 27-48）

删除：
```rust
use super::crypto::bls_elgamal as elgamal;
use super::crypto::bls_scalar::{self, g1_add, g1_equal, ...};
use super::crypto::serialization as ser;
use super::crypto::zk_verifier;
```

新增：
```rust
use poker_protocol::crypto::curve::{
    G1Projective, Scalar as BlsScalar, ElGamalCiphertext,
    g1_add, g1_equal, g1_generator, g1_is_identity, g1_sub,
    generate_plaintext_cards, hash_to_scalar, serialize_g1,
};
use poker_protocol::zk_shuffle::{
    shuffle_proof::ZKShuffleProof,
    dleq_proof::{DLEqProof, RemaskKind, LeaveKind},
    reveal_token_proof::RevealTokenProof,
    reconstruction::ReconstructProof,
    transcript_ext::{CryptoTranscript, MerlinTranscript},
};
use super::utils;  // 适配层
```

**步骤 2**：6 个 ZK 验证集成点改造

| 集成点 | 当前调用 | 新调用 |
|--------|----------|--------|
| line 1147 | `super::crypto::remask_proof::verify(&remask_proof, &input_cts, &mask_cts, &pk_pt, &mut t)` | `DLEqProof::<_, RemaskKind>::verify(&remask_proof, &input_cts, &mask_cts, &pk_pt, &mut t)` |
| line 1155 | `super::crypto::shuffle_proof::verify(...)` | `ZKShuffleProof::verify(...)` |
| line 1245 | `super::crypto::shuffle_proof::verify(...)` | `ZKShuffleProof::verify(...)` |
| line 1346 | `super::crypto::reveal_token_proof::verify(...)` | `RevealTokenProof::verify(...)` |
| line 1562 | `super::crypto::leave_proof::verify(...)` | `DLEqProof::<_, LeaveKind>::verify(...)` |
| `verify_pk_ownership` | `zk_verifier::verify_or_skip(skip, crypto::schnorr_proof::verify_pk_ownership(...))` | `utils::verify_pk_ownership(skip, ...)` |
| `verify_reconstruct` | `zk_verifier::verify_or_skip(skip, crypto::reconstruct_proof::verify(...))` | `utils::verify_reconstruct(skip, ...)` |

**步骤 3**：新建 `poker_l1/src/vm/contracts/texas_poker/utils.rs`

适配 `poker_protocol` 不直接提供但 `crypto/` 中存在的"包装函数"：

```rust
//! poker_protocol 适配层 — 吸收 crypto/ 与 poker_protocol 的 API 差异。
//!
//! 提供的函数：
//! - `verify_pk_ownership`：包装 GeneralizedSchnorrProof::verify + transcript 构造
//! - `verify_reconstruct`：包装 ReconstructProof::verify + transcript 构造
//! - `verify_or_skip`：dev chain skip 回退（保留原 zk_verifier 语义）
//! - bytes↔G1 转换工具（如 `parse_g1`、`parse_scalar`，若 poker_protocol 未导出）

use poker_protocol::crypto::curve::{G1Projective, Scalar};
use poker_protocol::zk_shuffle::{
    generalized_schnorr_proof::GeneralizedSchnorrProof,
    reconstruction::ReconstructProof,
    transcript_ext::{CryptoTranscript, MerlinTranscript},
};
use poker_protocol::crypto::DefaultCurve;

/// 验证 pk ownership（Schnorr 证明）。
///
/// `skip = true` 时直接返回 true（dev chain 回退）。
pub fn verify_pk_ownership(
    skip: bool,
    pk: &G1Projective,
    proof: &GeneralizedSchnorrProof<DefaultCurve>,
) -> bool {
    if skip { return true; }
    let mut transcript = MerlinTranscript::new(b"pk_ownership");
    proof.verify(pk, &mut transcript).is_ok()
}

/// 验证 reconstruct proof。
pub fn verify_reconstruct(
    skip: bool,
    proof: &ReconstructProof<DefaultCurve>,
    /* 其他参数按 poker_protocol API 调整 */
) -> bool {
    if skip { return true; }
    let mut transcript = MerlinTranscript::new(b"reconstruct");
    proof.verify(&mut transcript).is_ok()
}
```

**步骤 4**：bytes↔G1 转换工具简化

`state_machine.rs` line 53-68 的 `bytes_ct_to_g1` / `g1_ct_to_bytes` / `pk_to_g1` 在 typed 化后大部分不再需要（字段已是 G1Projective）。保留少量转换函数（如 RPC 边界）在 `utils.rs`。

**步骤 5**：transcript 适配

- `crypto::transcript` 是 Merlin transcript 封装
- `poker_protocol::zk_shuffle::transcript_ext::CryptoTranscript` trait + `MerlinTranscript` 实现
- 所有 prove/verify 调用需传入 `&mut impl CryptoTranscript`（或 `&mut MerlinTranscript`）

#### B.4 — 全量 borsh 迁移

**子任务 B.4.1**：核心类型 derive 添加

为以下类型添加 `#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]`：

| 文件 | 类型 |
|------|------|
| `object_model/id.rs` | `ObjectID` |
| `object_model/object.rs` | `Object` |
| `object_model/ownership.rs` | `Ownership` |
| `account/mod.rs` | `Account` |
| `block/mod.rs` | `Block`, `BlockHeader` |
| `transaction/mod.rs` | `Transaction`, `TxRequest`, `Gas`, `ContractCall`, `RouteHint`, `TxLane` |
| `signature/tagged_pubkey.rs` | `TaggedPubkey` |
| `consensus/*` | `DagVertex`, `DagCommitCertificate`, `ValidatorEntry`, `ValidatorSet` 等 |
| `vm/contracts/texas_poker/types.rs` | 所有结构体（B.2 已涉及） |
| `vm/contracts/dispatch.rs` | `GameContract` |
| `vm/syscalls.rs` | `MerklePath` 等 |

**orphan rule 处理**：
- 本地 newtype（`Address = [u8; 20]`, `Hash = [u8; 32]`）直接 derive
- 外部类型（如 `G1Projective`, `BlsScalar`）已在 `poker_protocol::borsh_impls` 中 impl（B.1 完成）

**子任务 B.4.2**：bcs → borsh 调用替换（35 文件）

全局替换：
- `bcs::to_bytes(&x)` → `borsh::to_vec(&x)`
- `bcs::from_bytes::<T>(b)` → `borsh::from_slice::<T>(b)`
- `bcs::from_bytes(b)` (省略类型) → `borsh::from_slice(b)`

**错误类型适配**：
- `bcs::Error` → `borsh::io::Error`
- 所有 `.map_err(|e| PokerL1Error::Serialization(format!("...: {e}")))` 处保持不变（format! 兼容任何 Display）

**子任务 B.4.3**：测试更新

所有测试中 `bcs::to_bytes(&x).unwrap()` → `borsh::to_vec(&x).unwrap()`，`bcs::from_bytes(&b).unwrap()` → `borsh::from_slice(&b).unwrap()`。

**子任务 B.4.4**：依赖清理（可选，本期保留 bcs 兼容）

- `/Users/mac/projects/zchain/Cargo.toml`：保留 `bcs` 依赖（避免破坏尚未迁移的第三方代码路径）
- 最终移除 `bcs` 留待下一期

---

## 4. Assumptions & Decisions（假设与决策）

### 决策

1. **A.4 执行策略**：**直接执行**（非 snapshot）。理由：execute_block 已处理失败 tx；account_store 无法 snapshot；snapshot 保留供未来 RPC preview / reorg 使用。
2. **B.2 ElGamalCiphertext 处理**：**删除本地类型，全局改用 poker_protocol 同名类型**。过渡期在 `types.rs` 顶部加 `pub type ElGamalCiphertext = poker_protocol::crypto::curve::ElGamalCiphertext;` 别名。
3. **B.3 适配层**：**新建 utils.rs** 吸收 `verify_pk_ownership` / `verify_reconstruct` 等 poker_protocol 未直接提供的包装函数 + `verify_or_skip` dev chain 回退。
4. **B.4 bcs 依赖**：**保留 bcs 依赖**（兼容期），新代码一律用 borsh。最终移除留待下一期。
5. **on-disk 格式破坏**：用户已确认全量迁移，部署时需清空 `~/.zchain/data` 等数据目录。

### 假设

1. **poker_protocol verify API 签名兼容** —— B.3 改造时若发现签名差异（如 transcript 参数类型），在 utils.rs 中适配。
2. **borsh 1.5 API**：`borsh::to_vec(&T) -> Result<Vec<u8>>` + `borsh::from_slice(&[u8]) -> Result<T>`，derive 宏 `BorshSerialize, BorshDeserialize`。
3. **Node::precompile_registry 可暴露 Arc** —— 新增 `pub fn precompile_registry(&self) -> Arc<PrecompileRegistry>` 访问器无障碍。
4. **timestamp_ms 计算提前** —— A.4 需在 execute_block 之前计算 timestamp（原 step 7 提前到 step 3.5）。

---

## 5. Verification Steps（验证步骤）

### 阶段验证

| 阶段 | 命令 | 期望 |
|------|------|------|
| A.4-A.5 完成 | `cargo build -p poker_l1 && cargo build && cargo test -p poker_l1 --lib {executor,storage,node}` | 0 error，executor/storage/node 测试全过 |
| B.2-B.3 完成 | `cargo build -p poker_l1 && cargo test -p poker_l1 --lib vm::contracts::texas_poker` | 0 error，texas_poker 测试全过 |
| B.4 完成 | `cargo build --workspace && cargo test --workspace` | 0 error，全部测试通过 |
| 最终 | `cargo clippy --workspace -- -D warnings` | 0 warning |

### 端到端验证

```bash
# 1. 清空旧数据目录（on-disk 格式破坏）
rm -rf ~/.zchain/data  # 路径按实际 node 配置调整

# 2. 全量构建
cd /Users/mac/projects/zchain
cargo build --workspace 2>&1 | tee /tmp/build.log
# 期望：Compiling ... Finished

# 3. 全量测试
cargo test --workspace 2>&1 | tee /tmp/test.log
# 期望：test result: ok. N passed; 0 failed

# 4. Clippy
cargo clippy --workspace -- -D warnings 2>&1 | tee /tmp/clippy.log
# 期望：Finished

# 5. 启动节点冒烟测试（可选）
cargo run --bin zchain -- --dev 2>&1 | head -50
# 期望：节点启动、产块、state_root 变化
```

### 关键回归点

- **executor 单元测试**：`poker_l1/src/executor.rs:526+` 的 28 个测试必须全过
- **ObjectDbSnapshot 测试**：`object_db_snapshot.rs` 的 6 个测试全过
- **poker_protocol roundtrip**：`borsh_impls.rs` 的 10 类型 roundtrip 测试全过
- **texas_poker 集成测试**：`poker_l1/src/vm/contracts/texas_poker/tests/` 全过
- **build_block_from_vertex**：产块后 state_root 应反映 tx 执行结果（非 prev_state_root）

---

## 6. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| poker_protocol verify API 签名不兼容 | B.3 阻塞 | utils.rs 适配层吸收差异；逐个集成点改造 + 单测 |
| borsh derive 对外部类型失败 | B.4 阻塞 | orphan rule 限制；G1Projective/Scalar 已在 B.1 impl；本地 newtype 直接 derive |
| typed 字段破坏现有序列化测试 | B.2 测试失败 | 逐个测试更新；保留 serde 兼容 |
| execute_block 在产块时失败导致停摆 | 主链阻塞 | execute_block 已设计为失败 tx 不阻断；仅底层错误传播，返回 Err 由 caller 跳过本轮 |
| on-disk 格式破坏导致旧数据无法读取 | 部署阻塞 | 文档明确要求清空数据目录 |
| state_machine.rs 2814 行改造量大 | B.3 回归风险 | 逐个集成点改造 + 每步编译验证；保留 `verify_or_skip` 回退 |
| bcs → borsh 全局替换遗漏 | B.4 编译失败 | `rg "bcs::" --type rust` 二次扫描确认零残留 |

---

## 7. 执行顺序

```
A.4（Node::execute_block_on_state + build_block_from_vertex 接线）
  │
  ▼
A.5（Track A 验证：cargo build + test）
  │
  ▼
B.2（删除 crypto/ 13 文件 + types.rs typed 化）
  │
  ▼
B.3（state_machine.rs 改 use poker_protocol::* + utils.rs）
  │
  ▼
B.4（全量 borsh 迁移：35 文件 bcs → borsh）
  │
  ▼
端到端验证（cargo build --workspace + cargo test --workspace + clippy）
```

**串行执行理由**：
- B.3 依赖 B.2（state_machine 引用 types.rs 的 typed 字段）
- B.4 依赖 B.2（texas_poker types 需先 typed 化才能 derive Borsh）
- A.4-A.5 与 B.2-B.4 无依赖，但串行执行便于隔离问题

---

## 8. 文件变更清单

### 新建文件（1）
1. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs` — poker_protocol 适配层

### 删除文件（13）
- `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/crypto/` 整个目录
  - mod.rs, bls_elgamal.rs, bls_scalar.rs, chaum_pedersen.rs, leave_proof.rs, reconstruct_proof.rs, remask_proof.rs, reveal_token_proof.rs, schnorr_proof.rs, serialization.rs, shuffle_proof.rs, transcript.rs, zk_verifier.rs

### 修改文件（关键）
1. `/Users/mac/projects/zchain/poker_l1/src/node/mod.rs` — 新增 `execute_block_on_state` + `precompile_registry` 访问器
2. `/Users/mac/projects/zchain/src/main.rs` — `build_block_from_vertex` 接线 + `run_validator_loop` 调用点 + bcs → borsh
3. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/mod.rs` — 移除 `pub mod crypto;`，新增 `pub mod utils;`
4. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs` — Vec<u8> → typed + derive Borsh
5. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/state_machine.rs` — use poker_protocol::*，6 集成点改造
6. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/{dispatch,events,side_pot}.rs` — bcs → borsh + typed 适配
7. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/dispatch.rs` — bcs → borsh（19 处）
8. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/{game,texas_poker}_precompile.rs` — bcs → borsh
9. `/Users/mac/projects/zchain/poker_l1/src/object_model/{id,object,ownership,store}.rs` — derive Borsh + bcs → borsh
10. `/Users/mac/projects/zchain/poker_l1/src/storage/{object_db,block_store,dag_vertex_store}.rs` — bcs → borsh
11. `/Users/mac/projects/zchain/poker_l1/src/{block,account,consensus,sync,signature,transaction}/*` — derive Borsh + bcs → borsh
12. `/Users/mac/projects/zchain/poker_l1/src/vm/syscalls.rs` — bcs → borsh（MerklePath）
13. `/Users/mac/projects/zchain/poker_l1/src/error.rs` — bcs::Error → borsh::io::