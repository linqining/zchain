# Texas Poker Protocol 迁移 + Borsh 序列化 + Tx 执行引擎接线

> **状态**：待用户批准
> **范围**：3 个并行 Track（A: 执行引擎接线，B: poker_protocol 替换 + borsh 迁移）
> **破坏性变更**：on-disk Object 格式（BCS → Borsh），需清空旧数据目录

---

## 1. Summary（任务总览）

用户 3-part 目标：

1. **替换算法**：`poker_l1/src/vm/contracts/texas_poker` 中的 crypto/ 13 文件改用 `../zgame/poker_protocol` 替换；不支持的函数列出并改造。
2. **改用 borsh**：合约调用序列化方式改成 borsh（**全量迁移**：合约层 + Object 持久化层，破坏 on-disk 格式）。
3. **接入执行引擎**：zchain 主链 `build_block_from_vertex` 接入 `executor::execute_block`，让 block 中的 tx 真正执行并产生新 state_root。

三条任务并行展开：
- **Track A**（Task 3）：Fork/Snapshot 机制 → executor 泛型化 → 主链接线
- **Track B**（Task 1+2）：poker_protocol borsh feature → 删除 crypto/ + types.rs typed 化 → state_machine.rs 改 use poker_protocol::* → 全量 borsh 迁移

---

## 2. Current State Analysis（当前状态分析）

### 2.1 已完成工作（继承自上一会话）

| 文件 | 状态 | 说明 |
|------|------|------|
| `/Users/mac/projects/zgame/poker_protocol/Cargo.toml` | ✅ 已修改 | 添加 `borsh = ["dep:borsh"]` feature + `borsh = { version = "1.5", optional = true }` 依赖 |
| `/Users/mac/projects/zgame/poker_protocol/src/lib.rs` | ✅ 已修改 | 注册 `#[cfg(feature = "borsh")] pub mod borsh_impls;` |
| `/Users/mac/projects/zgame/poker_protocol/src/borsh_impls.rs` | ✅ 已创建（479 行） | 10 个类型的 BorshSerialize/Deserialize 实现，含 roundtrip 测试 |
| `/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/dleq_proof.rs` | ✅ 已修改 | 添加 `pub(crate) fn from_parts(...)` 绕过私有 `_kind` 字段 |

**B.1 待验证**：需 `cargo build --features borsh` 确认编译通过，`cargo test --features borsh` 确认 roundtrip 测试通过。

### 2.2 executor.rs 当前状态

- **位置**：`/Users/mac/projects/zchain/poker_l1/src/executor.rs`（不在 `vm/` 子目录）
- **`execute_tx` 签名**（line 171-181）：
  ```rust
  pub fn execute_tx(
      env: &ExecutionEnvironment,
      tx: &Transaction,
      object_db: &mut ObjectDb,
      account_store: &mut AccountStore,
  ) -> TxReceipt
  ```
- **`execute_block` 签名**（line 488-523）：接收 `&mut ObjectDb` + `&mut AccountStore`，返回 `BlockExecutionOutcome { receipts, state_root, total_gas_used }`
- **已实现**：tx limits/chain_id/signature 重校验、gas-free lane 一致性、precompile 路由、block-level gas 累计
- **缺口**：`execute_block` 直接接收 `&mut ObjectDb`，无法在 fork 上"试执行"再决定是否提交

### 2.3 ObjectDb 当前状态

- **位置**：`/Users/mac/projects/zchain/poker_l1/src/storage/object_db.rs`
- **结构**（line 31-36）：
  ```rust
  pub struct ObjectDb {
      db: Arc<DB>,        // RocksDB
      store: ObjectStore, // 内存 SMT
  }
  ```
- **非 Clone**：`Arc<DB>` 可 Clone，但 `ObjectStore` 需确认
- **`state_root()`**（line 90-92）：`const fn`，返回 `self.store.state_root()`
- **`&mut self` 方法**：`create` / `update` / `transfer` / `delete`（均双写 RocksDB + 内存 SMT）
- **无 snapshot/fork 机制**：需要新增

### 2.4 build_block_from_vertex 当前状态

- **位置**：`/Users/mac/projects/zchain/src/main.rs:1021-1091`
- **签名**：接收 `state_root: Hash` 参数（caller 提供）
- **当前行为**：不执行任何 tx，直接用 caller 传入的 state_root 构造 block header
- **注释**（line 1018-1020）："当前未接入 tx 执行引擎，caller 应传入上一 block 后的 state_root"
- **caller**：`run_validator_loop`（line 1214）调用时传入 `node.state_root()`（旧值）

### 2.5 Node 结构

- **位置**：`/Users/mac/projects/zchain/poker_l1/src/node/mod.rs:300-331`
- **关键字段**：
  ```rust
  object_db: std::sync::Mutex<ObjectDb>,        // line 306
  account_store: std::sync::Mutex<AccountStore>, // line 310
  precompile_registry: Arc<PrecompileRegistry>,  // line 330
  ```
- **`state_root()`**（line 720-731）：`&self` → `Hash`，委托给 `object_db.state_root()`

### 2.6 texas_poker/crypto/ 当前状态

- **位置**：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/crypto/`
- **13 个子模块**（mod.rs line 27-38）：
  bls_elgamal, bls_scalar, chaum_pedersen, leave_proof, reconstruct_proof, remask_proof, reveal_token_proof, schnorr_proof, serialization, shuffle_proof, transcript, zk_verifier
- **完全重复**：与 `poker_protocol` 的 crypto/zk_shuffle 模块功能重叠

### 2.7 bcs 调用点分布（50+ 处）

| 区域 | 文件 | 调用数 | 迁移策略 |
|------|------|--------|----------|
| Object 持久化 | `storage/object_db.rs` | 5 | **Borsh**（on-disk 格式破坏） |
| Object 模型 | `object_model/{id,object,ownership,store}.rs` | ~11 | **Borsh**（derive + SMT 序列化） |
| Block 持久化 | `storage/block_store.rs`, `block/mod.rs` | 4 | **Borsh** |
| Vertex 持久化 | `storage/dag_vertex_store.rs` | 8 | **Borsh** |
| Account | `account/mod.rs` | 2 | **Borsh** |
| 合约 dispatch | `vm/contracts/dispatch.rs` | 19 | **Borsh**（合约调用入口） |
| 合约 precompile | `vm/contracts/{game,texas_poker}_precompile.rs` | 6 | **Borsh** |
| Texas poker 内部 | `vm/contracts/texas_poker/{dispatch,events,side_pot}.rs` | ~23 | **Borsh** |
| 共识 | `consensus/*` | ~38 | **Borsh** |
| 同步/P2P | `sync/mod.rs`, `src/main.rs` | 7 | **Borsh**（破坏 P2P 协议兼容性） |
| 签名 | `signature/tagged_pubkey.rs` | 2 | **Borsh** |
| 交易 | `transaction/mod.rs` | 4 | **Borsh** |
| VM syscalls | `vm/syscalls.rs` | 3 | **Borsh**（MerklePath） |

### 2.8 poker_protocol 依赖状态

- ✅ **已是 workspace 依赖**：`/Users/mac/projects/zchain/Cargo.toml:26` → `poker_protocol = { path = "../zgame/poker_protocol" }`
- ✅ **poker_l1 已声明使用**：`poker_l1/Cargo.toml:18` → `poker_protocol = { workspace = true }`
- ❌ **未启用 borsh feature**：需改为 `poker_protocol = { workspace = true, features = ["borsh"] }`
- ❌ **workspace 未声明 borsh**：需在 root `Cargo.toml` 添加 `borsh = "1.5"`

---

## 3. Proposed Changes（变更方案）

### Track A：Tx 执行引擎接线（Task 3）

#### A.1 — 引入 ObjectBackend trait

**文件**：`/Users/mac/projects/zchain/poker_l1/src/storage/object_backend.rs`（新建）

```rust
/// Object 读写后端抽象，使 executor 可在 ObjectDb 或 ObjectDbSnapshot 上泛型工作。
pub trait ObjectBackend {
    fn create(&mut self, object: Object) -> PokerL1Result<()>;
    fn read(&self, id: &ObjectID) -> PokerL1Result<Object>;
    fn update(&mut self, id: &ObjectID, caller: &Address, new_data: Vec<u8>) -> PokerL1Result<()>;
    fn transfer(&mut self, id: &ObjectID, caller: &Address, new_owner: Address) -> PokerL1Result<()>;
    fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object>;
    fn state_root(&self) -> Hash;
}

impl ObjectBackend for ObjectDb { /* 委托现有方法 */ }
```

#### A.2 — ObjectDbSnapshot 实现

**文件**：`/Users/mac/projects/zchain/poker_l1/src/storage/object_db_snapshot.rs`（新建）

- 从 `ObjectDb` 创建快照：复制 `ObjectStore`（内存 SMT），不复制 RocksDB
- 所有写操作记录到 `mutation_log: Vec<Mutation>`，不直接落 RocksDB
- `state_root()` 返回快照 SMT 的 root（用于"试执行"后预览新状态根）
- `apply_to(&mut self, db: &mut ObjectDb)`：将 mutation_log 回放到主 ObjectDb（commit）
- `discard(self)`：丢弃（rollback）

**ObjectStore Clone 验证**：A.1 开始时先验证 `ObjectStore` 是否 `Clone`；若否，需先为 `ObjectStore` 添加 `Clone` derive 或实现 `fn clone_for_snapshot(&self) -> Self`。

#### A.3 — executor 泛型化

**文件**：`/Users/mac/projects/zchain/poker_l1/src/executor.rs`（修改）

将 `execute_tx` / `execute_block` / `execute_tx_inner` 的 `object_db: &mut ObjectDb` 改为 `object_db: &mut impl ObjectBackend`。`account_store` 保持不变（AccountStore 已可直接 &mut）。

影响范围：
- 函数签名泛型化（3 处）
- 内部 `object_db.create/update/read/transfer/delete` 调用不变（trait 已包含同名方法）
- `object_db.state_root()` 调用不变（trait 已包含）

#### A.4 — 主链接线

**文件 1**：`/Users/mac/projects/zchain/src/main.rs`（修改 `build_block_from_vertex` line 1021-1091）

- 新增参数：`node: &Node`（替代 `state_root: Hash`，因为需要访问 object_db/account_store 执行 txs）
- 流程改造：
  1. 从 vertex 提取 tx_list → S9 排序 → 拆分 public/gameturn
  2. 锁 `node.object_db` + `node.account_store`
  3. 调用 `execute_block(&env, &sorted_txs, &mut object_db, &mut account_store)`
  4. 取 `outcome.state_root` 作为 block header 的 state_root
  5. 构造 commit cert + 签名 + block header（用新 state_root）

**文件 2**：`/Users/mac/projects/zchain/src/main.rs`（修改 `run_validator_loop` line 1100-1283）

- line 1214 的调用：传 `&node` 而非 `node.state_root()`
- 移除 line 1018-1020 的"未接入"注释

**文件 3**：`/Users/mac/projects/zchain/poker_l1/src/node/mod.rs`

- 新增 `pub fn execute_block_on_state(&self, env: &ExecutionEnvironment, txs: &[Transaction]) -> PokerL1Result<BlockExecutionOutcome>` 封装锁获取 + execute_block 调用，供 main.rs 使用（避免 main.rs 直接操作 Mutex）
- 或：新增 `pub fn with_object_db<R>(&self, f: impl FnOnce(&mut ObjectDb) -> R) -> R` 通用锁包装

**决策**：采用 `execute_block_on_state` 封装（语义清晰，避免 main.rs 直接处理锁）。

#### A.5 — Track A 验证

```bash
cd /Users/mac/projects/zchain
cargo build -p poker_l1 2>&1 | tail -30
cargo build 2>&1 | tail -30
cargo test -p poker_l1 --lib executor 2>&1 | tail -30
cargo test -p poker_l1 --lib storage 2>&1 | tail -30
```

---

### Track B：poker_protocol 替换 + Borsh 迁移（Task 1+2）

#### B.1 — poker_protocol borsh feature（已基本完成，待验证）

**文件**（已修改）：
- `/Users/mac/projects/zgame/poker_protocol/Cargo.toml`
- `/Users/mac/projects/zgame/poker_protocol/src/lib.rs`
- `/Users/mac/projects/zgame/poker_protocol/src/borsh_impls.rs`（479 行，10 类型）
- `/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/dleq_proof.rs`（添加 from_parts）

**待执行验证**：
```bash
cd /Users/mac/projects/zgame/poker_protocol
cargo build --features borsh 2>&1 | tail -30
cargo test --features borsh 2>&1 | tail -30
```

**workspace 接入**：修改 `/Users/mac/projects/zchain/Cargo.toml`：
- `[workspace.dependencies]` 添加 `borsh = "1.5"`
- `poker_protocol = { path = "../zgame/poker_protocol", features = ["borsh"] }`

修改 `/Users/mac/projects/zchain/poker_l1/Cargo.toml`：
- 添加 `borsh = { workspace = true }`

#### B.2 — 删除 texas_poker/crypto/ + types.rs typed 化

**删除文件**：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/crypto/` 整个目录（13 文件）

**修改文件**：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/mod.rs`
- 移除 `pub mod crypto;` 声明
- 添加 `use poker_protocol::*;`（或按需导入子模块）

**修改文件**：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs`

字段类型替换映射（Vec<u8> → typed poker_protocol 类型）：

| 当前字段（Vec<u8>） | 新类型（poker_protocol） | 说明 |
|---------------------|--------------------------|------|
| `ElGamalCiphertext.c1/c2: Vec<u8>` | `poker_protocol::crypto::curve::ElGamalCiphertext`（即 `ElGamalCiphertextGeneric<Bls12381Curve>`） | 直接使用 typed 类型 |
| `Seat.pk: Vec<u8>` | `G1Projective`（即 `Bls12381Curve::Point`） | 公钥点 |
| `ShuffleState.{pending,completed}_proofs: Vec<u8>` | `ZKShuffleProof<Bls12381Curve>` | shuffle 证明 |
| `RevealTokenState.assignments.proof: Vec<u8>` | `RevealTokenProof<Bls12381Curve>` | reveal token 证明 |
| `ReconstructState.coefficient: Vec<u8>` | `BlsScalar`（即 `Bls12381Curve::Scalar`） | 重构系数 |
| `ReconstructPlayerDeck.deck: Vec<u8>` | `Vec<ElGamalCiphertext>` | 玩家牌组 |
| `DecryptedCard.plaintext_bytes: Vec<u8>` | `G1Projective` | 明文牌点 |
| `DeckState.plaintext: Vec<Vec<u8>>` | `Vec<G1Projective>` | 明文牌组 |
| `DeckState.ciphertext_bytes: Vec<u8>` | `Vec<ElGamalCiphertext>` | 密文牌组 |

**注意**：所有 typed 字段同时需要 `#[derive(BorshSerialize, BorshDeserialize)]`（依赖 B.1 的 impl）。

#### B.3 — state_machine.rs 改 use poker_protocol::*

**修改文件**：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/state_machine.rs`

**步骤 1**：替换 import（line 27-50）
- 删除所有 `use super::crypto::{...}` 
- 改为 `use poker_protocol::{crypto::curve::*, zk_shuffle::*, ...};`

**步骤 2**：6 个 ZK 验证集成点改造（按 agent 报告的 line 号）：

| 集成点 | 当前调用（crypto::） | 新调用（poker_protocol::） |
|--------|----------------------|-----------------------------|
| line 1109-1115 | `verify_pk_ownership` | `poker_protocol::zk_shuffle::schnorr_proof::GeneralizedSchnorrProof::verify` |
| line 1145-1148 | `verify_remask` | `poker_protocol::zk_shuffle::dleq_proof::DLEqProof::<_, RemaskKind>::verify` |
| line 1153-1162 | `verify_shuffle` | `poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof::verify` |
| line 1343-1355 | `verify_reveal_token` | `poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof::verify` |
| line 1490-1499 | `verify_reconstruct` | `poker_protocol::zk_shuffle::reconstruction::ReconstructProof::verify` |
| line 1560-1563 | `verify_leave` | `poker_protocol::zk_shuffle::dleq_proof::DLEqProof::<_, LeaveKind>::verify` |

**步骤 3**：新建 `utils.rs` 适配缺失函数

**文件**：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs`（新建）

poker_protocol 不直接提供但 crypto/ 中存在的"包装函数"（如 `verify_pk_ownership` 内部构造 transcript + 调用 Schnorr verify）需在此适配。列出每个缺失函数 + 适配实现：

```rust
// utils.rs 示例
use poker_protocol::crypto::curve::*;
use poker_protocol::zk_shuffle::transcript_ext::MerlinTranscript;

/// 适配 crypto::schnorr_proof::verify_pk_ownership
pub fn verify_pk_ownership(pk: &G1Projective, proof: &GeneralizedSchnorrProof<Bls12381Curve>) -> bool {
    let mut transcript = MerlinTranscript::new(b"pk_ownership");
    // 调用 poker_protocol 的 verify...
}
```

**步骤 4**：transcript 适配
- crypto::transcript 是 Merlin transcript 封装
- poker_protocol::zk_shuffle::transcript_ext::CryptoTranscript trait + MerlinTranscript 实现
- 所有 prove/verify 调用需传入 `&mut impl CryptoTranscript`

#### B.4 — 全量 borsh 迁移

**子任务 B.4.1**：核心模型 derive 添加

为以下类型添加 `#[derive(BorshSerialize, BorshDeserialize)]`：
- `/Users/mac/projects/zchain/poker_l1/src/object_model/id.rs` — `ObjectID { creator_address: Address ([u8;20]), creation_nonce: u64 }`
- `/Users/mac/projects/zchain/poker_l1/src/object_model/object.rs` — `Object`
- `/Users/mac/projects/zchain/poker_l1/src/object_model/ownership.rs` — `Ownership`
- `/Users/mac/projects/zchain/poker_l1/src/object_model/store.rs` — `ObjectStore` 内部类型（如 `Entry`）
- `/Users/mac/projects/zchain/poker_l1/src/account/mod.rs` — `Account`
- `/Users/mac/projects/zchain/poker_l1/src/block/mod.rs` — `Block`, `BlockHeader`
- `/Users/mac/projects/zchain/poker_l1/src/transaction/mod.rs` — `Transaction`, `TxRequest`, `Gas`, `ContractCall`
- `/Users/mac/projects/zchain/poker_l1/src/signature/tagged_pubkey.rs` — `TaggedPubkey`
- `/Users/mac/projects/zchain/poker_l1/src/consensus/*` — `DagVertex`, `DagCommitCertificate`, `TxLane` 等
- `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs` — 所有结构体（B.2 已涉及）

**子任务 B.4.2**：bcs → borsh 调用替换

全局替换所有 `bcs::to_bytes(x)` → `borsh::to_vec(x)`，`bcs::from_bytes(b)` → `borsh::from_slice(b)`。

**注意**：错误类型变化——`bcs::Error` → `borsh::io::Error`，所有 `.map_err(|e| PokerL1Error::Serialization(format!("...: {e}")))` 处需调整错误转换。

**子任务 B.4.3**：依赖清理

- `/Users/mac/projects/zchain/Cargo.toml`：保留 `bcs` 一段时间（兼容期），但新代码用 borsh
- 最终：移除 `bcs` 依赖（破坏性，需清空旧数据目录）

**子任务 B.4.4**：测试更新

所有 `bcs::to_bytes(&x).unwrap()` 测试调用替换为 `borsh::to_vec(&x).unwrap()`。

#### B.5 — Track B 验证

```bash
cd /Users/mac/projects/zchain
cargo build --workspace 2>&1 | tail -50
cargo test --workspace 2>&1 | tail -50
cargo clippy --workspace -- -D warnings 2>&1 | tail -50
```

---

## 4. Assumptions & Decisions（假设与决策）

### 用户已确认决策（来自上一会话 AskUserQuestion）

1. **Task 1 替换策略**：**直接删除式替换** —— 删除 crypto/ 13 文件，types.rs 字段从 `Vec<u8>` 改为 typed poker_protocol 类型。
2. **Task 2 borsh 范围**：**全量 borsh 迁移** —— 合约层 + Object 持久化层，破坏 on-disk 格式（需清空旧数据目录）。
3. **Task 3 状态策略**：**Fork/Snapshot 机制** —— 新增 `ObjectBackend` trait + `ObjectDbSnapshot`，executor 泛型化。

### 关键技术假设

1. **ObjectStore 可 Clone 或可实现 clone_for_snapshot** —— A.2 起始时验证；若 ObjectStore 内部含 `Rc<RefCell<...>>` 等不可 Clone 类型，需先重构。
2. **poker_protocol 的 verify API 签名兼容** —— B.3 改造时若发现签名差异（如 transcript 参数），在 utils.rs 中适配。
3. **borsh 1.5 API**：`borsh::to_vec(&T) -> Result<Vec<u8>>` + `borsh::from_slice(&[u8]) -> Result<T>`，derive 宏 `BorshSerialize, BorshDeserialize`。
4. **on-disk 格式破坏可接受** —— 用户已确认；部署时需清空 `~/.zchain/data` 等数据目录。
5. **P2P 协议兼容性破坏可接受** —— sync/mod.rs 的 bcs 改 borsh 会破坏与旧节点互通；用户已确认全量迁移。

### 未选方案（记录）

- **Task 3 替代方案**：直接在 `&mut ObjectDb` 上执行 + rollback（无 snapshot）。未选：rollback 复杂、易遗漏状态泄漏。
- **Task 1 替代方案**：保留 crypto/ 作为 poker_protocol 的薄包装层。未选：双重维护、类型不透明（Vec<u8>）。
- **Task 2 替代方案**：仅合约层 borsh，Object 持久化保留 bcs。未选：双序列化方案混乱、跨层类型 derive 不一致。

---

## 5. Verification Steps（验证步骤）

### 阶段验证

| 阶段 | 命令 | 期望 |
|------|------|------|
| B.1 完成 | `cd /Users/mac/projects/zgame/poker_protocol && cargo build --features borsh && cargo test --features borsh` | 0 error，roundtrip 测试全过 |
| A.5 完成 | `cargo build -p poker_l1 && cargo test -p poker_l1 --lib executor && cargo test -p poker_l1 --lib storage` | 0 error，executor/storage 测试全过 |
| B.5 完成 | `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings` | 0 error，0 warning，全部测试通过 |

### 端到端验证（最终）

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

# 5. 启动节点冒烟测试
cargo run --bin zchain -- --dev 2>&1 | head -50
# 期望：节点启动、产块、state_root 变化
```

### 关键回归点

- **executor 单元测试**：`poker_l1/src/executor.rs:526+` 的 `#[cfg(test)] mod tests` 必须全过
- **poker_protocol roundtrip**：`borsh_impls.rs` 内的 10 类型 roundtrip 测试
- **texas_poker 集成测试**：`poker_l1/src/vm/contracts/texas_poker/tests/` 全过
- **ObjectDb 持久化测试**：`storage/object_db.rs` 内的 create/read/update/delete 往返测试

---

## 6. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| ObjectStore 不可 Clone | A.2 阻塞 | 先验证；若不可 Clone，为 ObjectStore 实现 `clone_for_snapshot()`（深拷贝 SMT 内部 HashMap） |
| poker_protocol verify API 签名不兼容 | B.3 阻塞 | utils.rs 适配层吸收差异；逐个集成点改造 + 单测 |
| borsh derive 对外部类型失败 | B.4 阻塞 | orphan rule 限制；对 Address([u8;20])、Hash([u8;32]) 等本地 newtype 直接 derive |
| on-disk 格式破坏导致旧数据无法读取 | 部署阻塞 | 文档明确要求清空数据目录；提供迁移脚本（可选，本期不做） |
| P2P 协议不兼容旧节点 | 网络隔离 | 用户已确认全量迁移；部署需全网络同步升级 |
| tx 执行失败导致产块失败 | 主链停摆 | execute_block 已设计为"失败 tx 返回失败回执，不阻断 block"；仅底层错误（如 RocksDB 写失败）才传播 |

---

## 7. 执行顺序（推荐）

```
B.1（验证 + workspace 接入）─┐
                            ├─► B.2（删除 crypto + types typed）
                            │   │
                            │   ▼
                            │   B.3（state_machine 改 use poker_protocol::*）
                            │   │
A.1-A.5（Track A 全程）─┐    │   ▼
                       │    │   B.4（全量 borsh 迁移）
                       │    │   │
                       └────┴───┴─► 端到端验证
```

- **B.1 与 Track A 可完全并行**（无依赖）
- **B.2 依赖 B.1**（typed 字段需 borsh derive）
- **B.3 依赖 B.2**（state_machine 引用 types.rs 的 typed 字段）
- **B.4 依赖 B.1**（poker_protocol 类型需 borsh impl）+ B.2（texas_poker types 需 typed）
- **端到端验证依赖所有阶段完成**

---

## 8. 文件变更清单

### 新建文件（5）
1. `/Users/mac/projects/zchain/poker_l1/src/storage/object_backend.rs` — ObjectBackend trait
2. `/Users/mac/projects/zchain/poker_l1/src/storage/object_db_snapshot.rs` — ObjectDbSnapshot
3. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs` — poker_protocol 适配层
4. `/Users/mac/projects/zgame/poker_protocol/src/borsh_impls.rs` — ✅ 已创建
5. （无其他新建）

### 删除文件（13）
- `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/crypto/` 整个目录
  - bls_elgamal.rs, bls_scalar.rs, chaum_pedersen.rs, leave_proof.rs, reconstruct_proof.rs, remask_proof.rs, reveal_token_proof.rs, schnorr_proof.rs, serialization.rs, shuffle_proof.rs, transcript.rs, zk_verifier.rs, mod.rs

### 修改文件（关键，非穷举）
1. `/Users/mac/projects/zchain/Cargo.toml` — 添加 borsh workspace 依赖，poker_protocol 启用 borsh feature
2. `/Users/mac/projects/zchain/poker_l1/Cargo.toml` — 添加 borsh 依赖
3. `/Users/mac/projects/zchain/poker_l1/src/storage/mod.rs` — 注册 object_backend + object_db_snapshot 模块
4. `/Users/mac/projects/zchain/poker_l1/src/executor.rs` — 泛型化 execute_tx/execute_block
5. `/Users/mac/projects/zchain/src/main.rs` — build_block_from_vertex + run_validator_loop 接线
6. `/Users/mac/projects/zchain/poker_l1/src/node/mod.rs` — 新增 execute_block_on_state 封装
7. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/mod.rs` — 移除 crypto 声明，添加 utils
8. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs` — Vec<u8> → typed
9. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/state_machine.rs` — use poker_protocol::*，6 集成点改造
10. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/dispatch.rs` — bcs → borsh
11. `/Users/mac/projects/zchain/poker_l1/src/object_model/{id,object,ownership,store}.rs` — derive Borsh
12. `/Users/mac/projects/zchain/poker_l1/src/storage/{object_db,block_store,dag_vertex_store}.rs` — bcs → borsh
13. `/Users/mac/projects/zchain/poker_l1/src/{block,account,consensus,sync,signature,transaction}/*` — bcs → borsh
14. `/Users/mac/projects/zchain/poker_l1/src/vm/{syscalls,contracts/dispatch,contracts/*_precompile}.rs` — bcs → borsh
15. `/Users/mac/projects/zchain/src/main.rs` — bcs → borsh（P2P 消息）
