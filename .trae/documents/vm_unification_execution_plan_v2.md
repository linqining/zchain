# VM 统一架构执行计划（v2 — 续作）

## 背景与状态

本计划是 `/Users/mac/projects/zchain/.trae/documents/vm_unification_plan.md`（v1，已审批通过）的执行细化版，用于接续上次会话丢失上下文后的工作。

### 已确认的当前状态

| 项目 | 状态 | 证据 |
|---|---|---|
| v1 方案文件 | ✅ 完整存在 | `.trae/documents/vm_unification_plan.md`（27959 字节，500 行）|
| 方案审批 | ✅ 用户已批准 | 上次会话通过 NotifyUser 审批 |
| 用户决策 | ✅ 已固化 | 方案 B（抽象共用层）+ 单向 adapter 桥接 + BLS 双库共存 + 完整 5 阶段 |
| Phase 0 测试基线 | ✅ 完成 | 上次会话已跑通 poker_l1 vm 451 测试 + poker_zkvm 1069 测试 |
| workspace 编译 | ✅ 通过 | `cargo check --workspace` 仅有 warning，无 error |
| vm-common 目录 | ⚠️ 半成品 | `vm-common/src/` 和 `vm-common/tests/` 已建空目录，但 Cargo.toml/lib.rs 尚未创建 |
| workspace Cargo.toml | ❌ 未注册 | `members = ["poker_l1", "poker_zkvm"]` 尚未加 `"vm-common"` |
| Phase 1-5 实施 | ❌ 未开始 | 除目录骨架外无任何代码 |

### 关键代码事实（探索确认）

- **`poker_l1/src/vm/precompile.rs`**：定义 `Precompile` trait（id/version/call/supports_selector/is_gas_free），按 `ObjectID` 路由，已含 `PrecompileRegistry` + 治理 timelock（7200 blocks）
- **`poker_zkvm/src/precompiles/mod.rs`**：定义 `PrecompileCircuit` trait（name/num_variables/build_ccs/assign_witness/gas_cost），按 `String` 名称路由，有独立 `PrecompileRegistry`
- **桥接关键差异**：`Precompile::id() → ObjectID` vs `PrecompileCircuit::name() → &str`，adapter 需建立 `name → ObjectID` 映射
- **`poker_l1/src/vm/gas_table.rs:117-120`**：已 re-export 5 个 zkvm gas 常量（`GAS_ZKVM_ECDSA_VERIFY` 等），证明跨 crate 引用可行
- **`poker_zkvm/src/syscalls/gas.rs`**：1091 行，含 15 个 syscall 级常量 + 8 个 RV32I 指令级常量 + `SyscallGasArgs` + `syscall_gas()` + `instruction_gas()`
- **`poker_zkvm/src/syscalls/mod.rs`**：定义 `SyscallId` 枚举（15 个，0x01-0x0F），`SyscallContext`、`Syscall` trait、`SyscallRegistry`
- **`poker_l1/src/vm/contracts/`**：17 个文件（含 `dispatch.rs`、`mod.rs`、`types.rs`、`examples.rs`、`game_precompile.rs` + 12 个业务合约）
- **`poker_zkvm/src/precompiles/`**：24 个文件（含 `mod.rs`、`ccs_builder.rs` + 22 个电路文件，实际 `PrecompileCircuit` 实现数需在 Phase 2 进一步统计）

---

## 执行原则

1. **不重复 v1 已确定的设计决策**：本计划聚焦"如何执行"，架构层面引用 v1
2. **每个阶段独立可回退**：阶段失败时 `git reset` 到阶段起点即可
3. **每阶段完成立即跑测试**：不积累多阶段再测
4. **零修改承诺**：业务合约（`poker_l1/src/vm/contracts/*.rs`，除 `mod.rs`/`types.rs`/`dispatch.rs`/`game_precompile.rs`）+ 约束系统（`poker_zkvm/src/constraints/`）+ Hypernova/fold/prover/recursion 全程不动
5. **遵循项目硬约束**：GameTurn/CheckpointAnchor gas-free、`#![deny(unsafe_code)]` 不破坏、IMPL-SEC-4 安全基线不动

---

## Phase 0：测试基线（已完成）

**状态**：✅ 完成（上次会话已建立）

**已验证**：
- `cargo test -p poker_l1` vm 模块 451 测试全绿
- `cargo test -p poker_zkvm` 1069 测试全绿
- `cargo check --workspace` 通过

**未完成的可选 snapshot 测试**：v1 计划提到的 `tests/syscall_abi_snapshot.rs`。考虑到现有测试已覆盖 ABI，且 snapshot 测试需引入 `insta` 依赖增加复杂度，**决定推迟到 Phase 5 或不做**（用现有测试作为回归基线即可）。这是对 v1 的微调，避免 over-engineering。

---

## Phase 1：vm-common crate 骨架 + gas/syscall_id 迁移

**目标**：建立 `vm-common` crate，迁移共享 gas 常量与统一 `SyscallId` 枚举，建立单一事实源。

**预计工作量**：2-3 天（非周，实际编码时间）

### Step 1.1：创建 vm-common/Cargo.toml

**文件**：`/Users/mac/projects/zchain/vm-common/Cargo.toml`

```toml
[package]
name = "vm-common"
version = "0.1.0"
edition = "2024"
description = "Shared cross-cutting concerns for poker_l1 vm and poker_zkvm (gas/syscall_id/precompile/crypto/gas_strategy)"

[dependencies]
# 严格限制：vm-common 不依赖 solana_rbpf 也不依赖 arkworks
# 仅依赖基础工具库
serde = { workspace = true, optional = true }
thiserror = { workspace = true }

[features]
default = []
# 启用 serde 序列化（PrecompileRegistry 状态持久化用）
serde = ["dep:serde"]
```

**验证**：`cargo tree -p vm-common` 应只有 `thiserror`、`serde` 等基础库

### Step 1.2：注册到 workspace

**修改文件**：`/Users/mac/projects/zchain/Cargo.toml`

```toml
[workspace]
resolver = "2"
members = ["poker_l1", "poker_zkvm", "vm-common"]
```

### Step 1.3：创建 vm-common/src/lib.rs

**文件**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`

```rust
//! vm-common — poker_l1 vm 与 poker_zkvm 的共享横切关注点。
//!
//! 严格不含 ISA 语义（BPF / RV32I），不依赖 solana_rbpf 或 arkworks。
//! 仅含五大横切关注点：
//! - `gas` — gas 常量单一事实源
//! - `syscall_id` — 统一 SyscallId 枚举
//! - `precompile` — Precompile trait + Registry（Phase 2 迁入）
//! - `crypto` — CryptoProvider trait（Phase 3 迁入）
//! - `gas_strategy` — GasStrategy trait（Phase 4 迁入）
//!
//! # 安全保证
//!
//! 本 crate 严格 `#![deny(unsafe_code)]`，不引入任何 unsafe 代码。

#![deny(unsafe_code)]
#![forbid(unsafe_code)]

pub mod gas;
pub mod syscall_id;
```

### Step 1.4：创建 vm-common/src/gas.rs（核心迁移）

**文件**：`/Users/mac/projects/zchain/vm-common/src/gas.rs`

**迁移策略**（基于已读 `poker_l1/src/vm/gas_table.rs` 与 `poker_zkvm/src/syscalls/gas.rs`）：

**迁入 vm-common 的常量**（非 ISA 专有）：
- 来自 `poker_l1/src/vm/gas_table.rs` 的 syscall 级常量：
  - `GAS_OBJECT_READ_BASE=10`, `GAS_OBJECT_READ_PER_BYTE=1`
  - `GAS_OBJECT_WRITE_BASE=20`, `GAS_OBJECT_WRITE_PER_BYTE=1`
  - `GAS_OBJECT_CREATE_BASE=20`, `GAS_OBJECT_CREATE_PER_BYTE=1`
  - `GAS_EMIT_EVENT_BASE=10`, `GAS_EMIT_EVENT_PER_BYTE=1`
  - `GAS_LOG=10`, `GAS_PANIC=10`
  - `GAS_GET_BLOCK_HEIGHT=1`, `GAS_GET_TIMESTAMP=1`
  - `GAS_SECP256K1_VERIFY=500`
  - `GAS_BLS_G1_MUL=500`, `GAS_BLS_G1_ADD=500`, `GAS_BLS_G1_NEG=500`
  - `GAS_BLS_G2_MUL=500`, `GAS_BLS_G2_ADD=500`, `GAS_BLS_G2_NEG=500`
  - `GAS_BLS_PAIRING=5000`, `GAS_BLS_MILLER_LOOP=2000`, `GAS_BLS_FINAL_EXP=1000`
  - `GAS_BLS_HASH_TO_G1_BASE=1000`, `GAS_BLS_HASH_TO_G1_PER_BYTE=10`
  - `GAS_BLS_HASH_TO_G2_BASE=1000`, `GAS_BLS_HASH_TO_G2_PER_BYTE=10`
  - `GAS_HYPERNOVA_VERIFY=300_000`, `GAS_GROTH16_VERIFY=20000`, `GAS_IPA_VERIFY=15000`
  - `GAS_ZK_VERIFY=300_000`, `GAS_VERIFY_FAILURE_PROOF=80000`
- 来自 `poker_zkvm/src/syscalls/gas.rs` 的 syscall 级常量：
  - `GAS_ZKVM_READ_INPUT_BASE=10`, `GAS_ZKVM_COMMIT_OUTPUT_BASE=10`
  - `GAS_ZKVM_POSEIDON_BASE=100`, `GAS_ZKVM_POSEIDON_PER_BLOCK=50`
  - `GAS_ZKVM_SHA256_PER_BYTE=1`, `GAS_ZKVM_ECDSA_VERIFY=100_000`
  - `GAS_ZKVM_EMIT_EVENT_BASE=10`, `GAS_ZKVM_EMIT_EVENT_PER_BYTE=1`
  - `GAS_ZKVM_LOG_BASE=10`, `GAS_ZKVM_LOG_PER_BYTE=1`
  - `GAS_ZKVM_PANIC=10`, `GAS_ZKVM_GET_RANDOMNESS=100`
  - `GAS_ZKVM_READ_STATE_PER_SLOT=50`
  - `GAS_ZKVM_KECCAK256_PER_BYTE=2`, `GAS_ZKVM_KECCAK256_PER_ROUND=10_000`
  - `GAS_ZKVM_MODEXP_BASE=50_000`, `GAS_ZKVM_MODEXP_PER_BIT=600`
  - `GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL=100`
  - `GAS_ZKVM_ED25519_BASE=50_000`, `GAS_ZKVM_ED25519_PER_BIT=8_000`
  - `GAS_ZKVM_BN254_PAIRING_MVP=30_000`, `GAS_ZKVM_BN254_PAIRING_FULL=80_000`
- 共享 size limits：`MAX_OBJECT_SIZE=64KB`, `MAX_EVENT_PAYLOAD_SIZE=16KB`, `MAX_HEAP_SIZE=1MB`, `MAX_STACK_SIZE=64KB`, `MAX_INPUT_SIZE=64KB`, `MAX_BLS_HASH_MSG_SIZE=65536`
- 共享 gas limits：`BLOCK_GAS_LIMIT=50M`, `TX_GAS_LIMIT=10M`
- 纯函数：`object_read_gas`, `object_write_gas`, `object_create_gas`, `emit_event_gas`, `memory_gas`, `bls_hash_to_g1_gas`, `bls_hash_to_g2_gas`, `zk_verify_gas`

**保留在 poker_l1 本地**（BPF 专有）：
- `GAS_ARITHMETIC=1`, `GAS_MEMORY_BASE=3`, `GAS_MEMORY_PER_BYTE=2`, `GAS_BRANCH=2`
- `check_bls_hash_msg_len`（依赖 `PokerL1Error`，保留本地）

**保留在 poker_zkvm 本地**（RV32I 专有）：
- `GAS_INSN_ARITHMETIC=1`, `GAS_INSN_MEMORY_BASE=3`, `GAS_INSN_MEMORY_PER_BYTE=2`, `GAS_INSN_BRANCH=2`, `GAS_INSN_SHIFT=2`, `GAS_INSN_MUL=20`, `GAS_INSN_DIV=20`, `GAS_INSN_UPPER_IMM=1`, `GAS_INSN_SYSTEM=2`
- `SyscallGasArgs`, `syscall_gas()`, `instruction_gas()`, `total_step_gas()`（依赖 `Instruction`，保留本地）

**修改 `poker_l1/src/vm/gas_table.rs`**：
- 删除迁出的常量定义
- 顶部加 `pub use vm_common::gas::*;`（保留外部 API 兼容）
- 保留 BPF 专有常量与 `check_bls_hash_msg_len`
- 原 `pub use poker_zkvm::syscalls::gas::{...};` 改为不需要（vm-common 已含这些常量）

**修改 `poker_zkvm/src/syscalls/gas.rs`**：
- 删除迁出的 syscall 级常量定义
- 顶部加 `pub use vm_common::gas::*;`
- 保留 RV32I 指令级常量与 `SyscallGasArgs`/`syscall_gas`/`instruction_gas`/`total_step_gas`

### Step 1.5：创建 vm-common/src/syscall_id.rs

**文件**：`/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`

**统一枚举设计**（分段 ID 空间，向后兼容）：

```rust
//! 统一 SyscallId 枚举 — 跨 VM 的 syscall ID 单一事实源。
//!
//! ID 空间分段：
//! - 0x01-0x0F：原有 zkvm 15 个 syscall（保持现有值不变，向后兼容）
//! - 0x10-0x3F：链上链下共用扩展（新增共用 syscall 用此段）
//! - 0x40-0x7F：poker_l1 专属（object_*/get_block_height/verify_signature 等）
//! - 0x80-0xFF：BLS12-381 系列（poker_l1 现有 12 个 bls12_381_*）

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SyscallId {
    // ===== 0x01-0x0F：原有 zkvm 15 个（值不变，向后兼容） =====
    ReadInput = 0x01,
    CommitOutput = 0x02,
    Poseidon = 0x03,
    Sha256 = 0x04,
    EcdsaVerify = 0x05,
    EmitEvent = 0x06,
    Log = 0x07,
    Panic = 0x08,
    GetRandomness = 0x09,
    ReadState = 0x0A,
    Keccak256 = 0x0B,
    Modexp = 0x0C,
    MerkleVerify = 0x0D,
    Ed25519Verify = 0x0E,
    Bn254Pairing = 0x0F,

    // ===== 0x40-0x5F：poker_l1 专属 =====
    ObjectRead = 0x40,
    ObjectWrite = 0x41,
    ObjectCreate = 0x42,
    GetBlockHeight = 0x43,
    GetTimestamp = 0x44,
    VerifySignature = 0x45,
    VerifyFailureProof = 0x46,
    ZkVerify = 0x47,

    // ===== 0x80-0x8F：BLS12-381 系列（poker_l1） =====
    Bls12_381G1Add = 0x80,
    Bls12_381G1Mul = 0x81,
    Bls12_381G1Neg = 0x82,
    Bls12_381G2Add = 0x83,
    Bls12_381G2Mul = 0x84,
    Bls12_381G2Neg = 0x85,
    Bls12_381PairingCheck = 0x86,
    Bls12_381MillerLoop = 0x87,
    Bls12_381FinalExp = 0x88,
    Bls12_381HashToG1 = 0x89,
    Bls12_381HashToG2 = 0x8A,
    Bls12_381Aggregate = 0x8B,
}

impl SyscallId {
    pub fn from_u32(id: u32) -> Option<Self> { /* match */ }
    pub fn as_u32(&self) -> u32 { *self as u32 }
    pub fn is_zkvm(&self) -> bool { /* 0x01-0x0F */ }
    pub fn is_poker_l1(&self) -> bool { /* 0x40-0xFF */ }
    pub fn is_shared(&self) -> bool { /* 0x10-0x3F（当前空） */ }
}
```

**重要：不强制改现有注册机制**。poker_zkvm 的 `SyscallId`（0x01-0x0F）保留原样使用，poker_l1 的 syscall 通过 `declare_builtin_function!` 宏注册（不依赖枚举）。vm-common 的 `SyscallId` 仅供**新加 syscall** 与 ABI 文档使用，**不破坏现有路由**。

### Step 1.6：依赖接入

**修改 `/Users/mac/projects/zchain/poker_l1/Cargo.toml`**：
```toml
[dependencies]
vm-common = { path = "../vm-common" }
# ... 其余不变
```

**修改 `/Users/mac/projects/zchain/poker_zkvm/Cargo.toml`**：
```toml
[dependencies]
vm-common = { path = "../vm-common" }
# ... 其余不变
```

### Step 1.7：vm-common 单元测试

**文件**：`/Users/mac/projects/zchain/vm-common/src/gas.rs`（底部 `#[cfg(test)] mod tests`）：
- 常量值断言（确保迁移后值不变）
- 纯函数测试（`object_read_gas(100) == 110` 等）

**文件**：`/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`（底部测试）：
- `from_u32` / `as_u32` 往返测试
- `is_zkvm` / `is_poker_l1` 分段测试

### Step 1.8：回归测试

```bash
cargo build --workspace                    # 编译通过
cargo test -p vm-common                    # vm-common 单元测试全绿
cargo test -p poker_l1                     # poker_l1 全绿（验证 re-export 兼容）
cargo test -p poker_zkvm                   # poker_zkvm 全绿（验证 re-export 兼容）
cargo tree -p vm-common                    # 验证无 solana_rbpf / arkworks 依赖
rg "GAS_ZKVM_ECDSA_VERIFY" --type rust     # 应只在 vm-common/src/gas.rs 定义
```

### Phase 1 验收

- [ ] `cargo build --workspace` 通过
- [ ] `cargo test --workspace` 全绿
- [ ] `cargo tree -p vm-common` 无 solana_rbpf/arkworks
- [ ] gas 常量在 vm-common 中单一事实源（rg 验证）
- [ ] `poker_l1/src/vm/gas_table.rs` 与 `poker_zkvm/src/syscalls/gas.rs` 中无重复常量定义
- [ ] 现有测试零退化

---

## Phase 2：Precompile trait 上移 + 单向 adapter 桥接

**目标**：将 `Precompile` trait 从 poker_l1 迁到 vm-common，为 zkvm `PrecompileCircuit` 实现 adapter，让 zkvm 电路可作为链上 precompile 调用。

**预计工作量**：3-5 天

### Step 2.1：迁移 Precompile trait 到 vm-common

**新建**：`/Users/mac/projects/zchain/vm-common/src/precompile.rs`

从 `poker_l1/src/vm/precompile.rs` 迁入：
- `Precompile` trait
- `PrecompileRegistry`（含热插拔注册、版本管理、治理 timelock=7200 blocks）
- `DispatchResult`、`ExecutionEnvironment`、`PrecompileStatus`、`PrecompileVersion`
- `0xFF` 前缀的 reserved ObjectID namespace 常量

**关键挑战**：`Precompile::call()` 签名依赖 `ObjectID`、`Address`、`TaggedPubkey`、`ObjectDb`、`PokerL1Error` 等 poker_l1 类型。需要：

**方案 2.1A（推荐，trait + 关联类型抽象）**：
- 在 vm-common 中定义 `Precompile` trait 时，使用泛型或关联类型抽象 `ObjectID`、`ObjectDb` 等
- 在 poker_l1 中为具体类型实现 `Precompile` 的具体版本
- 优点：vm-common 保持纯净；缺点：trait 签名稍复杂

**方案 2.1B（备选，vm-common 依赖 poker_l1 的子集）**：
- 把 `ObjectID`、`Address` 等基础类型也迁到 vm-common
- 缺点：vm-common 变重，破坏"不含 ISA 语义"原则

**决策**：采用方案 2.1A。具体做法：
- vm-common 定义 `Precompile<Db, Err>` 泛型 trait（或用关联类型 `type Db; type Err;`）
- poker_l1 中 `pub use vm_common::precompile::Precompile as PrecompileBase;` + 类型别名 `type Precompile = PrecompileBase<ObjectDb, PokerL1Error>;`
- 业务合约代码零修改（通过 `use crate::vm::precompile::Precompile` 引入，类型别名透明）

**修改**：`/Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs`
- 内容改为 `pub use vm_common::precompile::*;` + 类型别名
- 保留 `poker_l1` 特有的辅助函数（若有）

**修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`
- 加 `pub mod precompile;`

### Step 2.2：zkvm PrecompileCircuitAdapter

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/adapter.rs`

```rust
use vm_common::precompile::{Precompile, DispatchResult, ExecutionEnvironment};
use crate::precompiles::PrecompileCircuit;
use crate::ccs::{Ccs, CcsInstance, Fr};

/// 将 zkvm PrecompileCircuit 适配为 vm_common Precompile trait。
///
/// 单向桥接：zkvm 电路 → 链上 Precompile 接口。
/// 不强制链上业务合约实现 CCS 接口。
pub struct PrecompileCircuitAdapter<T: PrecompileCircuit> {
    circuit: T,
    /// 电路名称 → 保留 ObjectID 的映射（0xFF 前缀命名空间）
    object_id: ObjectID,
}

impl<T: PrecompileCircuit> Precompile for PrecompileCircuitAdapter<T> {
    fn id(&self) -> ObjectID { self.object_id }
    fn version(&self) -> u32 { 1 }
    fn call(&self, caller, pubkey, selector, args, env, object_db) -> Result<DispatchResult> {
        // 1. 解码 args → Fr 输入
        // 2. 调用 self.circuit.assign_witness(inputs) 得到 witness
        // 3. 调用 self.circuit.build_ccs() 得到 Ccs
        // 4. 验证 ccs.satisfied_by(&witness)
        // 5. 返回 DispatchResult { return_data, ccs_instance: Some((ccs, witness)), ... }
    }
    fn supports_selector(&self, s: &[u8; 32]) -> bool { /* 转发或默认 */ }
    fn is_gas_free(&self) -> bool { false }
}
```

### Step 2.3：共享 PrecompileRegistry 测试

**新建**：`/Users/mac/projects/zchain/vm-common/tests/precompile_adapter.rs`
- 测试 `PrecompileCircuitAdapter::new(poseidon_circuit).call(...)` 返回正确结果
- 测试生成的 CCS 实例可被 `satisfied_by` 验证

**新建**：`/Users/mac/projects/zchain/vm-common/tests/registry_unified.rs`
- 测试同一 registry 可同时容纳链上业务合约与 zkvm 电路

### Step 2.4：回归测试

```bash
cargo test --workspace
git diff poker_l1/src/vm/contracts/  # 除 mod.rs/types.rs/dispatch.rs/game_precompile.rs 外应为空
cargo test -p vm-common --test precompile_adapter
cargo test -p vm-common --test registry_unified
```

### Phase 2 验收

- [ ] 17 个业务合约零修改（git diff 验证）
- [ ] zkvm 9 个电路（poseidon/sha256/ecdsa/keccak256/merkle_verify/modexp/ed25519/bn254_pairing/zk_shuffle）通过 adapter 可作为 `Precompile` 调用
- [ ] `cargo test --workspace` 全绿

---

## Phase 3：CryptoProvider trait 抽象 + 双实现

**目标**：统一密码学原语接口，业务 BLS 用 bls12-381（blstrs），zkvm 电路约束用 ark-bn254（arkworks）。

**预计工作量**：3-5 天

### Step 3.1：定义 CryptoProvider trait

**新建**：`/Users/mac/projects/zchain/vm-common/src/crypto.rs`

定义 trait，包含：
- 哈希：`sha256`, `keccak256`, `blake2b_256`, `poseidon`
- 签名验证：`ecdsa_verify_secp256k1`, `ed25519_verify`
- BLS12-381：`bls12_381_g1_add/mul/neg`, `bls12_381_g2_add/mul/neg`, `bls12_381_pairing_check`, `bls12_381_hash_to_g1/g2`
- BN254：`bn254_pairing_check`

使用关联类型 `type G1; type G2; type Scalar;` 抽象曲线点。

### Step 3.2：双实现

**新建**：`/Users/mac/projects/zchain/poker_l1/src/vm/crypto_blstrs.rs`
- `BlstrsCryptoProvider` 实现 `CryptoProvider`
- G1 = `blstrs::G1Projective`, Scalar = `blstrs::Scalar`

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/crypto_arkworks.rs`
- `ArkworksCryptoProvider` 实现 `CryptoProvider`
- G1 = `ark_bn254::G1Projective`, Scalar = `ark_bn254::Fr`

### Step 3.3：改造调用点

**修改**：`poker_l1/src/vm/syscalls.rs`
- 12 个 `bls12_381_*` syscall 改走 `BlstrsCryptoProvider`（替换直接 `blstrs::` 调用）

**修改**：`poker_zkvm/src/syscalls/host.rs`
- `sha256`/`poseidon`/`ecdsa_verify` 改走 `ArkworksCryptoProvider`

### Step 3.4：一致性测试

**新建**：`/Users/mac/projects/zchain/vm-common/tests/crypto_consistency.rs`
- 对同一输入跑 `BlstrsCryptoProvider::sha256` 与 `ArkworksCryptoProvider::sha256`，断言一致
- BLS12-381 与 BN254 不做等价断言（不同曲线）

### Phase 3 验收

- [ ] `rg "blstrs::" poker_l1/src/vm/syscalls.rs` 无匹配
- [ ] `rg "ark_bn254::" poker_zkvm/src/syscalls/host.rs` 无匹配
- [ ] `cargo test --workspace` 全绿

---

## Phase 4：GasStrategy trait + 双实现

**目标**：gas 计费策略差异化，zkvm 指令级 gas 返回 0，链上保持完整计费。

**预计工作量**：2-3 天

### Step 4.1：定义 GasStrategy trait

**新建**：`/Users/mac/projects/zchain/vm-common/src/gas_strategy.rs`

```rust
pub trait GasStrategy: Send + Sync {
    fn instruction_gas(&self, insn_category: InsnCategory) -> u64;
    fn syscall_gas(&self, id: SyscallId, args_len: usize) -> u64;
    fn instruction_meter_enabled(&self) -> bool;
    fn default_tx_gas_limit(&self) -> u64;
    fn default_block_gas_limit(&self) -> u64;
}

pub enum InsnCategory {
    Arithmetic, Memory, ControlFlow, Syscall, Other,
}
```

### Step 4.2：双实现

**新建**：`/Users/mac/projects/zchain/poker_l1/src/vm/gas_strategy.rs`
- `BpfGasStrategy`：instruction_gas 返回 1，meter_enabled = true，tx_limit = 10M

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas_strategy.rs`
- `ZkvmGasStrategy`：instruction_gas 返回 0，meter_enabled = false，tx_limit = 0

### Step 4.3：接入（GameTurn gas-free 不变）

**修改**：`poker_l1/src/vm/context.rs` - `PokerL1Context::new` 接收 `&dyn GasStrategy`
**修改**：`poker_zkvm/src/isa/executor.rs` - `execute_elf_with_limits_and_config` 接收 `&dyn GasStrategy`

**关键约束**：`poker_l1/src/executor.rs:186-302` 的 GameTurn/CheckpointAnchor lane 逻辑零修改。`GasStrategy` 仅作用于走 rBPF 执行的合约。

### Step 4.4：测试

- `cargo test -p poker_l1 test_execute_out_of_gas`（链上 gas 仍生效）
- `cargo test -p poker_l1 test_gameturn_gas_free`（GameTurn 仍 gas-free）
- 新增 `vm-common/tests/gas_strategy.rs`：`ZkvmGasStrategy::instruction_gas(any) == 0`

### Phase 4 验收

- [ ] zkvm 指令级 gas = 0
- [ ] 链上 GameTurn gas-free 路径未变
- [ ] `cargo test --workspace` 全绿

---

## Phase 5：ABI 文档与治理收尾

**目标**：固化统一 ABI 文档，更新 spec.md 非 FROZEN 部分。

**预计工作量**：1-2 天

### Step 5.1：ABI 文档
- 为 `vm-common/src/syscall_id.rs` 每个 `SyscallId` 变体添加 doc-comment
- 运行 `cargo doc -p vm-common --no-deps` 生成文档

### Step 5.2：更新文档
- 更新 `/Users/mac/projects/zchain/poker_zkvm/docs/38-3-zkvm-syscall-reference.md`：引用 `vm-common::syscall_id`
- 新建 `/Users/mac/projects/zchain/vm-common/ARCHITECTURE.md`：架构图与设计决策

### Step 5.3：更新 spec.md（非 FROZEN 部分）
- 记录 vm-common 架构
- 记录阶段实施摘要
- 记录未来演进路径

### Step 5.4：更新 project_memory.md
- 增加 vm-common 相关工程约定
- 记录"业务 BLS 用 blstrs，zkvm 电路用 ark-bn254"决策
- 记录"PrecompileCircuitAdapter 单向桥接"决策

### Phase 5 验收

- [ ] ABI 文档完整生成
- [ ] spec.md 非 FROZEN 部分更新
- [ ] project_memory.md 增加新约定

---

## 总验收（端到端）

```bash
cargo build --workspace
cargo test --workspace
cargo tree -p vm-common  # 应无 solana_rbpf / arkworks
cargo bench -p poker_l1 --bench task36_zk_verifier  # 性能无显著退化（< 5%）
cargo bench -p poker_zkvm --bench phase12_benchmarks
```

---

## 风险与缓解

| 风险 | 等级 | 缓解 |
|---|---|---|
| vm-common 抽象边界设计不当成为 god-crate | 中 | Phase 1 严格限制依赖，`cargo tree` 验证 |
| PrecompileCircuitAdapter 桥接语义不一致 | 中 | Phase 2 cross-impl 测试，对比 host_execute 与 build_ccs+assign_witness |
| CryptoProvider 双实现行为差异 | 中 | Phase 3 cross-impl 一致性测试（纯哈希必须一致） |
| GasStrategy 接入导致 gas 测试退化 | 低 | Phase 4 完整回归 test_execute_out_of_gas |
| 业务合约 ABI 被意外破坏 | 低 | git diff poker_l1/src/vm/contracts/ 必须为空（mod.rs/types.rs/dispatch.rs/game_precompile.rs 除外） |
| `poker_zkvm::#![deny(unsafe_code)]` 被破坏 | 低 | vm-common 不引入 unsafe；adapter 在 zkvm 内部实现 |
| Phase 2 trait 迁移导致类型签名复杂化 | 中 | 采用方案 2.1A（关联类型），保持业务合约零修改 |

---

## 关键文件清单

### 新建（共 13 个）
- `vm-common/Cargo.toml`
- `vm-common/src/lib.rs`
- `vm-common/src/gas.rs`
- `vm-common/src/syscall_id.rs`
- `vm-common/src/precompile.rs`（Phase 2）
- `vm-common/src/crypto.rs`（Phase 3）
- `vm-common/src/gas_strategy.rs`（Phase 4）
- `vm-common/ARCHITECTURE.md`（Phase 5）
- `poker_l1/src/vm/crypto_blstrs.rs`（Phase 3）
- `poker_l1/src/vm/gas_strategy.rs`（Phase 4）
- `poker_zkvm/src/crypto_arkworks.rs`（Phase 3）
- `poker_zkvm/src/syscalls/gas_strategy.rs`（Phase 4）
- `poker_zkvm/src/precompiles/adapter.rs`（Phase 2）

### 修改（共 9 个）
- `Cargo.toml`（workspace members 加 vm-common）
- `poker_l1/Cargo.toml`（加 vm-common 依赖）
- `poker_zkvm/Cargo.toml`（加 vm-common 依赖）
- `poker_l1/src/vm/gas_table.rs`（常量迁出，加 re-export）
- `poker_l1/src/vm/precompile.rs`（trait 迁出，加 re-export + 类型别名）
- `poker_l1/src/vm/syscalls.rs`（BLS 调用改走 BlstrsCryptoProvider）
- `poker_l1/src/vm/context.rs`（new 接收 &dyn GasStrategy）
- `poker_zkvm/src/syscalls/gas.rs`（常量迁出，加 re-export）
- `poker_zkvm/src/syscalls/host.rs`（密码学调用改走 ArkworksCryptoProvider）
- `poker_zkvm/src/precompiles/mod.rs`（新增 adapter 模块声明）
- `poker_zkvm/src/isa/executor.rs`（接收 &dyn GasStrategy）

### 零修改（共 40+ 个）
- `poker_l1/src/vm/contracts/*.rs`（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs）
- `poker_l1/src/vm/loader.rs`
- `poker_l1/src/vm/upgrade.rs`
- `poker_l1/src/executor.rs`（GameTurn gas-free lane）
- `poker_zkvm/src/constraints/*`
- `poker_zkvm/src/hypernova/*`
- `poker_zkvm/src/fold/*`
- `poker_zkvm/src/prover/*`
- `poker_zkvm/src/recursion/*`
- `poker_zkvm/src/isa/*`（RV32I 引擎）
- `poker_zkvm/src/precompiles/*.rs`（9 个电路实现，仅加 adapter wrapper）

---

## 与 v1 方案的差异

本执行计划对 v1 方案的微调：

1. **Phase 0 snapshot 测试推迟**：v1 计划用 `insta` 做 syscall ABI snapshot，本计划认为现有测试已覆盖，推迟到 Phase 5 或不做，避免 over-engineering
2. **Phase 2 Precompile trait 迁移采用关联类型方案（2.1A）**：v1 未明确如何处理 `ObjectID`/`ObjectDb` 依赖，本计划明确采用关联类型抽象，保持 vm-common 纯净
3. **统一 SyscallId 枚举 ID 段调整**：v1 提到 0x60-0x7F 为 zkvm 专属，但 zkvm 现有 syscall 已占 0x01-0x0F。本计划保持 zkvm 现有 ID 不变（向后兼容），新增共用 syscall 用 0x10-0x3F 段
4. **时间估算更现实**：v1 用"周"为单位（2-3 周/阶段），本计划用"天"为单位（2-5 天/阶段），更贴合实际编码时间

---

## 总结

本执行计划是 v1 架构方案的落地细化，Phase 0 已完成，Phase 1 半成品（仅空目录），需从 Step 1.1 开始执行。每阶段独立可回退，每阶段完成立即跑测试。业务合约与约束系统全程零修改，符合项目所有硬