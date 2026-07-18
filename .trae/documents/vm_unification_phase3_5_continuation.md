# VM 统一架构 — Phase 3-5 续作执行计划（接续版）

## 背景与状态评估

本计划接续上一个会话的工作。上一个会话已完成 Phase 3.3-3.5（修复 BlstrsCryptoProvider 编译错误、创建 ArkworksCryptoProvider、注册模块），并开始 Phase 3.6（创建跨 VM 一致性测试文件）。

### 当前状态盘点（基于实际文件系统检查）

| 阶段 | 状态 | 证据 |
|---|---|---|
| Phase 3.3 | ✅ 完成 | `poker_l1/src/vm/crypto_blstrs.rs`（10042B），10 测试通过 |
| Phase 3.4 | ✅ 完成 | `poker_zkvm/src/crypto_arkworks.rs`（11061B），11 测试通过 |
| Phase 3.5 | ✅ 完成 | `poker_zkvm/src/lib.rs` L57-58 已注册 `pub mod crypto_arkworks;` |
| Phase 3.6 | ⚠️ **文件截断** | `poker_l1/tests/crypto_consistency.rs` 仅 152 行，最后一行 `assert!(!ark` 被截断；**测试未运行** |
| Phase 3.7 | ⏳ 未开始 | — |
| Phase 4 | ⏳ 未开始 | `vm-common/src/gas_strategy.rs` 不存在；`poker_l1/src/vm/gas_strategy.rs` 不存在；`poker_zkvm/src/syscalls/gas_strategy.rs` 不存在 |
| Phase 5 | ⏳ 未开始 | `vm-common/src/catalog.rs` 不存在；ARCHITECTURE.md 不存在；CONTRACT_DEV_GUIDE.md 不存在 |

### 关键发现（修订原计划）

**原计划错误**：Phase 4.3 的 BpfGasStrategy 代码引用了 `gas::GAS_MEMORY_BASE` 和 `gas::GAS_BRANCH`，但实际验证 `vm-common/src/gas.rs` 后发现这两个常量是 **BPF 专有**，保留在 `poker_l1/src/vm/gas_table.rs` 中（gas.rs L11-12 明确注释）。

**修订方案**：BpfGasStrategy 直接引用 `crate::vm::gas_table::{GAS_MEMORY_BASE, GAS_BRANCH}` 等 BPF 专有常量，而非 `vm_common::gas::`。这符合 gas.rs 的设计意图（"ISA 专有常量保留在各 crate 本地"）。

---

## 执行原则（沿用）

1. 每阶段独立可回退，每阶段完成立即跑测试
2. 业务合约（17 个）零修改
3. Hypernova/CCS/constraints/prover/recursion 零修改
4. GameTurn/CheckpointAnchor gas-free lane 零修改
5. `poker_zkvm::#![deny(unsafe_code)]` 与 `#![deny(missing_docs)]` 不破坏
6. vm-common 严格 `#![deny(unsafe_code)]`，不依赖 solana_rbpf/arkworks
7. **非侵入式**：Phase 3-4 不改造现有 syscall/executor 调用路径

---

## Phase 3.6+3.7：修复截断 + 一致性测试 + 回归

### Step 3.6.1：修复 `crypto_consistency.rs` 截断

**文件**：`/Users/mac/projects/zchain/poker_l1/tests/crypto_consistency.rs`

**问题**：文件在 L152 `assert!(!ark` 处被截断，`test_bls12_381_vs_bn254_no_comparison` 函数不完整，导致编译失败。

**修复**：补全 L152 之后的内容，使函数完整闭合：

```rust
    // arkworks 对 BN254 可能返回 true 或 false（取决于输入），但不 panic
    assert!(!arkworks.bn254_pairing_check(&[([0u8; 32], [0u8; 64])]));
    assert!(!arkworks.bn254_pairing_check(&[]));
}
```

### Step 3.6.2：验证 Phase 3.6 测试

```bash
cargo test -p poker_l1 --test crypto_consistency
```

**预期**：10 个测试全绿。若失败：
- 若为 hex decode 错误 → 检查 known vector 常量
- 若为 BLS12-381/BN254 边界 → 检查 BlstrsCryptoProvider 的 `bn254_pairing_check` 是否对空 pairs 返回 false（应返回 false）

### Step 3.7：Phase 3 回归测试

```bash
cargo test -p vm-common                          # crypto trait 测试（4 个）
cargo test -p poker_l1 vm::crypto_blstrs         # BlstrsCryptoProvider（10 个）
cargo test -p poker_zkvm --features test-helpers crypto_arkworks  # ArkworksCryptoProvider（11 个）
cargo test -p poker_l1 --test crypto_consistency # 一致性（10 个）
cargo test --workspace --no-fail-fast            # 全回归（基线 1365 测试）
```

### Phase 3 验收

- [ ] `crypto_consistency.rs` 截断已修复，10 测试全绿
- [ ] 现有 syscall 调用路径零退化
- [ ] `cargo test --workspace` 全绿

---

## Phase 4：GasStrategy trait + 双实现

**目标**：形式化 gas 计费策略接口，明确 zkvm 指令级 gas = 0、链上 = 1 的差异。**非侵入式形式化层**，不接入 executor。

### Step 4.1：定义 GasStrategy trait

**新建**：`/Users/mac/projects/zchain/vm-common/src/gas_strategy.rs`（约 120 行）

```rust
//! GasStrategy — 跨 VM gas 计费策略形式化接口（Phase 4）。
//!
//! # 设计
//!
//! - `BpfGasStrategy`（poker_l1）：指令级 1 gas/条 + syscall 级按 gas_table 计费
//! - `ZkvmGasStrategy`（poker_zkvm）：指令级 gas = 0（无 gas 费），仅 step_limit
//!
//! # 范围说明
//!
//! Phase 4 仅建立 trait + 双实现 + 跨实现测试，**不改造现有 executor 签名**。
//! 让 PokerL1Context::new / execute_elf_with_limits_and_config 改用 GasStrategy
//! 是未来增量工作，避免破坏 GameTurn gas-free 硬约束。

use crate::syscall_id::SyscallId;

/// 指令分类（用于 gas 计费抽象）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnCategory {
    /// 算术指令
    Arithmetic,
    /// 内存指令
    Memory,
    /// 控制流指令
    ControlFlow,
    /// 移位指令
    Shift,
    /// 乘法指令
    Mul,
    /// 除法指令
    Div,
    /// 上立即数加载
    UpperImm,
    /// 系统指令
    System,
    /// 其他
    Other,
}

/// Gas 计费策略 trait。
pub trait GasStrategy: Send + Sync {
    /// 指令级 gas（每条指令按类别）。
    fn instruction_gas(&self, category: InsnCategory) -> u64;
    /// syscall 级 gas（按 SyscallId + 参数长度）。
    fn syscall_gas(&self, id: SyscallId, args_len: u32) -> u64;
    /// 是否启用指令级 gas 计量。
    fn instruction_meter_enabled(&self) -> bool;
    /// 默认 tx gas 上限。
    fn default_tx_gas_limit(&self) -> u64;
    /// 默认 block gas 上限。
    fn default_block_gas_limit(&self) -> u64;
    /// 策略名称（"bpf" / "zkvm"）。
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyStrategy;
    impl GasStrategy for DummyStrategy {
        fn instruction_gas(&self, _: InsnCategory) -> u64 { 0 }
        fn syscall_gas(&self, _: SyscallId, _: u32) -> u64 { 0 }
        fn instruction_meter_enabled(&self) -> bool { false }
        fn default_tx_gas_limit(&self) -> u64 { 0 }
        fn default_block_gas_limit(&self) -> u64 { 0 }
        fn name(&self) -> &'static str { "dummy" }
    }

    #[test]
    fn test_gas_strategy_trait_object() {
        let s: Box<dyn GasStrategy> = Box::new(DummyStrategy);
        assert_eq!(s.name(), "dummy");
        assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), 0);
    }

    #[test]
    fn test_insn_category_copy() {
        let c = InsnCategory::Arithmetic;
        let c2 = c;
        assert_eq!(c, c2);
    }
}
```

### Step 4.2：注册 gas_strategy 模块

**修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`

当前 L20-23：
```rust
pub mod crypto;
pub mod gas;
pub mod precompile;
pub mod syscall_id;
```

改为（按字母序插入 `gas_strategy` 在 `gas` 之后）：
```rust
pub mod crypto;
pub mod gas;
pub mod gas_strategy;
pub mod precompile;
pub mod syscall_id;
```

同步更新 L9 注释（`gas_strategy` 已存在，无需改）。

### Step 4.3：BpfGasStrategy 实现（**修订版** — 修正原计划常量引用错误）

**新建**：`/Users/mac/projects/zchain/poker_l1/src/vm/gas_strategy.rs`（约 110 行）

**关键修订**：原计划引用 `gas::GAS_MEMORY_BASE` / `gas::GAS_BRANCH`，但这两个是 BPF 专有常量，位于 `poker_l1/src/vm/gas_table.rs`，不在 `vm_common::gas`。修订后从 `crate::vm::gas_table` 引用。

```rust
//! BpfGasStrategy — poker_l1 链上 BPF gas 策略（Phase 4）。
//!
//! 完整计费：指令级 1 gas/条 + syscall 级按 vm_common::gas 计费。
//!
//! # 范围说明
//!
//! Phase 4 仅形式化 gas 策略接口，**不接入 executor**。
//! 现有 PokerL1Context / syscalls.rs 的 gas 计费路径保持原状。

use vm_common::gas;
use vm_common::gas_strategy::{GasStrategy, InsnCategory};
use vm_common::syscall_id::SyscallId;

// BPF 指令级常量保留在 gas_table.rs（ISA 专有），此处复用
use crate::vm::gas_table::{GAS_ARITHMETIC, GAS_BRANCH, GAS_MEMORY_BASE};

/// poker_l1 链上 BPF gas 策略。
pub struct BpfGasStrategy;

impl BpfGasStrategy {
    #[must_use]
    pub const fn new() -> Self { Self }
}

impl Default for BpfGasStrategy {
    fn default() -> Self { Self::new() }
}

impl GasStrategy for BpfGasStrategy {
    fn instruction_gas(&self, category: InsnCategory) -> u64 {
        match category {
            InsnCategory::Arithmetic | InsnCategory::UpperImm | InsnCategory::Other => {
                GAS_ARITHMETIC
            }
            InsnCategory::Memory => GAS_MEMORY_BASE,
            InsnCategory::ControlFlow | InsnCategory::System => GAS_BRANCH,
            InsnCategory::Shift => 2,
            InsnCategory::Mul => 20,
            InsnCategory::Div => 20,
        }
    }

    fn syscall_gas(&self, id: SyscallId, args_len: u32) -> u64 {
        match id {
            SyscallId::ObjectRead => gas::object_read_gas(args_len as u64),
            SyscallId::ObjectWrite => gas::object_write_gas(args_len as u64),
            SyscallId::ObjectCreate => gas::object_create_gas(args_len as u64),
            SyscallId::EmitEvent => gas::emit_event_gas(args_len as u64),
            SyscallId::VerifySignature => gas::GAS_SECP256K1_VERIFY,
            SyscallId::ZkVerify => gas::zk_verify_gas(0),
            _ => 0,
        }
    }

    fn instruction_meter_enabled(&self) -> bool { true }
    fn default_tx_gas_limit(&self) -> u64 { gas::TX_GAS_LIMIT }
    fn default_block_gas_limit(&self) -> u64 { gas::BLOCK_GAS_LIMIT }
    fn name(&self) -> &'static str { "bpf" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_strategy_name() {
        assert_eq!(BpfGasStrategy::new().name(), "bpf");
    }

    #[test]
    fn test_bpf_instruction_gas() {
        let s = BpfGasStrategy::new();
        assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), GAS_ARITHMETIC);
        assert_eq!(s.instruction_gas(InsnCategory::Memory), GAS_MEMORY_BASE);
        assert_eq!(s.instruction_gas(InsnCategory::ControlFlow), GAS_BRANCH);
        assert_eq!(s.instruction_gas(InsnCategory::Mul), 20);
        assert_eq!(s.instruction_gas(InsnCategory::Div), 20);
    }

    #[test]
    fn test_bpf_meter_enabled() {
        assert!(BpfGasStrategy::new().instruction_meter_enabled());
    }

    #[test]
    fn test_bpf_gas_limits() {
        let s = BpfGasStrategy::new();
        assert_eq!(s.default_tx_gas_limit(), 10_000_000);
        assert!(s.default_block_gas_limit() > s.default_tx_gas_limit());
    }
}
```

**实施前验证步骤**：
1. Read `/Users/mac/projects/zchain/poker_l1/src/vm/gas_table.rs` 确认 `GAS_ARITHMETIC`、`GAS_MEMORY_BASE`、`GAS_BRANCH` 实际导出名（spec 注释 L17-19 提到算术=1、内存=3、分支=2，但常量名可能不同）。
2. 若常量名不同，调整 use 语句。
3. 若 `SyscallId` 中没有 `ObjectRead` 等变体名（可能是 `ObjectRead = 0x40`），需匹配实际变体名。

### Step 4.4：ZkvmGasStrategy 实现

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas_strategy.rs`（约 80 行）

```rust
//! ZkvmGasStrategy — poker_zkvm 链下 ZK VM gas 策略（Phase 4）。
//!
//! **无 gas 费**：所有 instruction_gas 返回 0，instruction_meter_enabled = false。
//! 仅 step_limit（执行步数上限）约束执行。
//!
//! # 范围说明
//!
//! Phase 4 仅形式化，不接入 zkvm executor。现有 `instruction_gas()` / `syscall_gas()`
//! 在 `poker_zkvm/src/syscalls/gas.rs` 保持原状（被约束系统使用）。

use vm_common::gas_strategy::{GasStrategy, InsnCategory};
use vm_common::syscall_id::SyscallId;

/// poker_zkvm 链下 ZK VM gas 策略（全 0）。
pub struct ZkvmGasStrategy;

impl ZkvmGasStrategy {
    #[must_use]
    pub const fn new() -> Self { Self }
}

impl Default for ZkvmGasStrategy {
    fn default() -> Self { Self::new() }
}

impl GasStrategy for ZkvmGasStrategy {
    fn instruction_gas(&self, _category: InsnCategory) -> u64 { 0 }
    fn syscall_gas(&self, _id: SyscallId, _args_len: u32) -> u64 { 0 }
    fn instruction_meter_enabled(&self) -> bool { false }
    fn default_tx_gas_limit(&self) -> u64 { 0 }
    fn default_block_gas_limit(&self) -> u64 { 0 }
    fn name(&self) -> &'static str { "zkvm" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkvm_strategy_name() {
        assert_eq!(ZkvmGasStrategy::new().name(), "zkvm");
    }

    #[test]
    fn test_zkvm_no_gas() {
        let s = ZkvmGasStrategy::new();
        assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), 0);
        assert_eq!(s.instruction_gas(InsnCategory::Mul), 0);
        assert_eq!(s.instruction_gas(InsnCategory::Div), 0);
        assert_eq!(s.instruction_gas(InsnCategory::Memory), 0);
    }

    #[test]
    fn test_zkvm_meter_disabled() {
        assert!(!ZkvmGasStrategy::new().instruction_meter_enabled());
    }

    #[test]
    fn test_zkvm_zero_limits() {
        let s = ZkvmGasStrategy::new();
        assert_eq!(s.default_tx_gas_limit(), 0);
        assert_eq!(s.default_block_gas_limit(), 0);
    }
}
```

### Step 4.5：注册 gas_strategy 模块

**修改 1**：`/Users/mac/projects/zchain/poker_l1/src/vm/mod.rs`

当前 L17-25：
```rust
pub mod context;
pub mod contract;
pub mod contracts;
pub mod crypto_blstrs;
pub mod gas_table;
pub mod loader;
pub mod precompile;
pub mod syscalls;
pub mod upgrade;
```

插入 `pub mod gas_strategy;`（字母序，在 `gas_table` 之后）：
```rust
pub mod context;
pub mod contract;
pub mod contracts;
pub mod crypto_blstrs;
pub mod gas_strategy;
pub mod gas_table;
pub mod loader;
pub mod precompile;
pub mod syscalls;
pub mod upgrade;
```

**修改 2**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs`

需先 Read 确认现有模块声明顺序，然后按字母序插入 `pub mod gas_strategy;`。

**注意 poker_zkvm 的 `#![deny(missing_docs)]`**：模块声明需带 doc-comment：
```rust
/// Phase 4 — GasStrategy trait 的 zkvm 实现（无 gas 费）。
pub mod gas_strategy;
```

### Step 4.6：跨实现一致性测试

**新建**：`/Users/mac/projects/zchain/poker_l1/tests/gas_strategy_consistency.rs`（约 90 行）

```rust
//! Phase 4.6 — 跨 VM GasStrategy 一致性测试。
//!
//! 验证 BpfGasStrategy（poker_l1）与 ZkvmGasStrategy（poker_zkvm）的核心差异：
//! - BPF 有 gas，zkvm 无 gas
//! - 两者可作为 trait object 共存

use poker_l1::vm::gas_strategy::BpfGasStrategy;
use poker_zkvm::syscalls::gas_strategy::ZkvmGasStrategy;
use vm_common::gas_strategy::{GasStrategy, InsnCategory};

#[test]
fn test_bpf_vs_zkvm_gas_difference() {
    let bpf = BpfGasStrategy::new();
    let zkvm = ZkvmGasStrategy::new();

    assert!(bpf.instruction_meter_enabled());
    assert!(!zkvm.instruction_meter_enabled());

    for cat in [
        InsnCategory::Arithmetic, InsnCategory::Memory, InsnCategory::ControlFlow,
        InsnCategory::Shift, InsnCategory::Mul, InsnCategory::Div,
        InsnCategory::UpperImm, InsnCategory::System, InsnCategory::Other,
    ] {
        assert_eq!(zkvm.instruction_gas(cat), 0, "zkvm {:?} should be 0", cat);
    }
}

#[test]
fn test_strategy_names() {
    assert_eq!(BpfGasStrategy::new().name(), "bpf");
    assert_eq!(ZkvmGasStrategy::new().name(), "zkvm");
    assert_ne!(BpfGasStrategy::new().name(), ZkvmGasStrategy::new().name());
}

#[test]
fn test_bpf_limits_positive() {
    let bpf = BpfGasStrategy::new();
    assert_eq!(bpf.default_tx_gas_limit(), 10_000_000);
    assert_eq!(bpf.default_block_gas_limit(), 50_000_000);
}

#[test]
fn test_zkvm_limits_zero() {
    let zkvm = ZkvmGasStrategy::new();
    assert_eq!(zkvm.default_tx_gas_limit(), 0);
    assert_eq!(zkvm.default_block_gas_limit(), 0);
}

#[test]
fn test_trait_object_collection() {
    let strategies: Vec<Box<dyn GasStrategy>> = vec![
        Box::new(BpfGasStrategy::new()),
        Box::new(ZkvmGasStrategy::new()),
    ];
    assert_eq!(strategies.len(), 2);
    assert_eq!(strategies[0].name(), "bpf");
    assert_eq!(strategies[1].name(), "zkvm");
}
```

### Step 4.7：Phase 4 回归测试

```bash
cargo test -p vm-common gas_strategy                # GasStrategy trait 测试
cargo test -p poker_l1 vm::gas_strategy             # BpfGasStrategy 测试
cargo test -p poker_zkvm --features test-helpers syscalls::gas_strategy  # ZkvmGasStrategy 测试
cargo test -p poker_l1 --test gas_strategy_consistency  # 跨实现一致性
cargo test --workspace --no-fail-fast               # 全回归
```

### Phase 4 验收

- [ ] `vm-common/src/gas_strategy.rs` 定义 trait + InsnCategory（2 测试）
- [ ] `poker_l1/src/vm/gas_strategy.rs` 实现 BpfGasStrategy（4 测试）
- [ ] `poker_zkvm/src/syscalls/gas_strategy.rs` 实现 ZkvmGasStrategy（4 测试，全 0）
- [ ] zkvm 指令级 gas = 0（验证所有 InsnCategory）
- [ ] poker_l1 GameTurn gas-free lane 路径零修改
- [ ] poker_zkvm `#![deny(missing_docs)]` 不破坏（模块带 doc-comment）
- [ ] `cargo test --workspace` 全绿

---

## Phase 5：ABI 文档 + 架构文档 + 合约开发者指南

**目标**：固化统一 ABI 文档，建立合约开发者单一入口指南，更新 project_memory.md。

### Step 5.1：完善 SyscallId doc-comments

**修改**：`/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`

需先 Read 确认现有 35 个变体的实际名称与 ID 值，然后为每个变体添加 doc-comment：
- zkvm 段（0x01-0x0F）：注明"仅 zkvm 使用"
- poker_l1 段（0x40-0x7F）：注明"仅 poker_l1 使用"
- BLS12-381 段（0x80-0xFF）：注明"跨 VM 共享"

**验证**：`cargo doc -p vm-common --no-deps` 无警告

### Step 5.2：创建 ARCHITECTURE.md

**新建**：`/Users/mac/projects/zchain/vm-common/ARCHITECTURE.md`

**内容大纲**：
1. vm-common 架构图（6 大模块：gas / syscall_id / precompile / crypto / gas_strategy / catalog）
2. 依赖边界图（vm-common 不依赖 solana_rbpf / arkworks / blstrs）
3. Phase 1-5 实施摘要
4. 与 poker_l1 / poker_zkvm 的关系图
5. 关键设计决策：
   - PrecompileMetadata 单向桥接（字节级 ID）
   - CryptoProvider 字节级接口（`[u8; 48]` G1 / `[u8; 96]` G2）
   - GasStrategy 形式化层（非侵入式，不接入 executor）
   - PrecompileCatalog 跨 VM 可用性矩阵
6. 演进路径（未来如何让 syscalls/executors 改用新 trait）

### Step 5.3：创建 PrecompileCatalog

**新建**：`/Users/mac/projects/zchain/vm-common/src/catalog.rs`（约 200 行）

**目标**：建立跨 VM precompile 可用性矩阵，让合约开发者清楚哪些预编译在哪个 VM 可用。

**实施前验证**：
1. Read `/Users/mac/projects/zchain/vm-common/src/precompile.rs` 确认 `precompile_id_from_name` 函数签名（原计划假设存在，需验证）
2. 若函数不存在或签名不同，调整 catalog 实现方式（可改为内联 `blake2b_256(name)` + 0xFF 前缀）
3. Read `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/` 目录列表，确认 17 个业务合约名称

**核心结构**：

```rust
//! PrecompileCatalog — 跨 VM 预编译可用性目录（Phase 5）。
//!
//! 合约开发者单一入口：通过此目录查询某个预编译在 L1 / zkvm 的可用性、
//! gas 策略、ID 与调用方式，无需阅读两个 VM 的源码。

/// 预编译可用性条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub name: &'static str,
    pub category: PrecompileCategory,
    pub l1_available: bool,
    pub zkvm_available: bool,
    pub is_gas_free: bool,
    pub id_bytes: [u8; 32],
    pub description: &'static str,
}

/// 预编译类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecompileCategory {
    Hash, Signature, Pairing, Business, ZkProof, Other,
}

/// 跨 VM 预编译目录。
#[derive(Debug, Default)]
pub struct PrecompileCatalog {
    entries: Vec<CatalogEntry>,
}

impl PrecompileCatalog {
    pub fn default_catalog() -> Self { /* 填充所有已知预编译 */ }
    pub fn find(&self, name: &str) -> Option<&CatalogEntry> { /* ... */ }
    pub fn cross_vm_available(&self) -> impl Iterator<Item = &CatalogEntry> { /* ... */ }
    pub fn gas_free(&self) -> impl Iterator<Item = &CatalogEntry> { /* ... */ }
    pub fn by_category(&self, cat: PrecompileCategory) -> impl Iterator<Item = &CatalogEntry> { /* ... */ }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}
```

**条目清单**（约 25 个）：
- 哈希（4）：sha256, keccak256, blake2b_256, poseidon
- 签名（3）：ecdsa_secp256k1, ed25519, ecdsa_verify
- 配对（3）：bls12_381_pairing, bn254_pairing, bn254_ops
- 业务（17）：gameturn, checkpoint_anchor, force_advance, force_settle, force_checkin, settle, revert, hand_started, ack_protocol, forfeit, censor_detection, delegated_escape, force_checkpoint, challenge_delta, checkpoint_skip, request_da, checkin（需对照实际 contracts/ 目录确认）
- ZK（1）：zk_verify

**测试**（7 个）：
- `test_catalog_default_not_empty` — len > 20
- `test_find_sha256` — 跨 VM 可用
- `test_find_gameturn_gas_free` — L1 only, gas-free
- `test_cross_vm_available_includes_hashes`
- `test_gas_free_lane` — gameturn + checkpoint_anchor
- `test_by_category_business` — ≥16 个业务合约
- `test_id_bytes_stable` — sha256 的 id_bytes[0] == 0xFF

### Step 5.4：注册 catalog 模块

**修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`

最终状态：
```rust
pub mod catalog;
pub mod crypto;
pub mod gas;
pub mod gas_strategy;
pub mod precompile;
pub mod syscall_id;
```

同步更新 L1-9 模块说明注释。

### Step 5.5：创建合约开发者指南

**新建**：`/Users/mac/projects/zchain/vm-common/CONTRACT_DEV_GUIDE.md`

**内容大纲**：
1. 概述（两个 VM 执行环境的差异）
2. 预编译可用性矩阵表
3. Syscall ID 空间（0x01-0x0F zkvm / 0x40-0x7F poker_l1 / 0x80-0xFF 跨 VM）
4. Gas 策略（poker_l1 有 gas / zkvm 无 gas / gas-free lane）
5. 如何写跨 VM 兼容合约（优先用跨 VM 可用预编译）
6. 示例代码片段

### Step 5.6：更新 project_memory.md

**修改**：`/Users/mac/.trae-cn/memory/projects/-Users-mac-projects-zchain/project_memory.md`

在 `Engineering Conventions` 节末尾追加（使用 Edit 工具，不重写）：

```markdown
- vm-common crate 是跨 VM 共享横切关注点的单一事实源（gas/syscall_id/precompile/crypto/gas_strategy/catalog）
- vm-common 严格 #![deny(unsafe_code)]，不依赖 solana_rbpf 或 arkworks
- PrecompileMetadata 是跨 VM 预编译元数据接口（字节级 ID），完整 call() 统一推迟
- CryptoProvider trait 使用字节级接口（[u8; 48] G1 / [u8; 96] G2）避免关联类型
- 业务 BLS 用 blstrs（poker_l1），zkvm 电路用 ark-bn254（poker_zkvm），双库共存
- GasStrategy trait 形式化跨 VM gas 差异；zkvm 指令级 gas = 0（非侵入式，未接入 executor）
- PrecompileCatalog 是合约开发者单一入口，查询预编译跨 VM 可用性矩阵
- 业务合约（17 个）+ Hypernova/CCS/constraints/prover 全程零修改
```

### Step 5.7：最终端到端验证

```bash
cargo build --workspace                    # 编译通过
cargo test --workspace --no-fail-fast      # 全绿
cargo doc -p vm-common --no-deps           # 文档无警告
cargo tree -p vm-common                    # 应只有基础工具库，无 solana_rbpf/arkworks
```

### Phase 5 验收

- [ ] `vm-common/src/syscall_id.rs` 每个 SyscallId 变体有 doc-comment
- [ ] `vm-common/ARCHITECTURE.md` 创建
- [ ] `vm-common/src/catalog.rs` 创建，7 测试全绿
- [ ] `vm-common/CONTRACT_DEV_GUIDE.md` 创建
- [ ] `project_memory.md` 追加 8 条新工程约定
- [ ] 端到端 `cargo test --workspace` 全绿
- [ ] `cargo doc -p vm-common --no-deps` 无警告

---

## 关键文件清单

### Phase 3.6 修复（1 个修改）
- **修改**：`/Users/mac/projects/zchain/poker_l1/tests/crypto_consistency.rs`（补全截断）

### Phase 4 新建与修改（3 新建 + 1 测试 + 3 注册修改）
- **新建**：`/Users/mac/projects/zchain/vm-common/src/gas_strategy.rs`
- **新建**：`/Users/mac/projects/zchain/poker_l1/src/vm/gas_strategy.rs`
- **新建**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas_strategy.rs`
- **新建**：`/Users/mac/projects/zchain/poker_l1/tests/gas_strategy_consistency.rs`
- **修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`（加 `pub mod gas_strategy;`）
- **修改**：`/Users/mac/projects/zchain/poker_l1/src/vm/mod.rs`（加 `pub mod gas_strategy;`）
- **修改**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs`（加 `pub mod gas_strategy;`）

### Phase 5 新建与修改（3 新建 + 3 修改）
- **新建**：`/Users/mac/projects/zchain/vm-common/src/catalog.rs`
- **新建**：`/Users/mac/projects/zchain/vm-common/ARCHITECTURE.md`
- **新建**：`/Users/mac/projects/zchain/vm-common/CONTRACT_DEV_GUIDE.md`
- **修改**：`/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`（doc-comment）
- **修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`（加 `pub mod catalog;`）
- **修改**：`/Users/mac/.trae-cn/memory/projects/-Users-mac-projects-zchain/project_memory.md`（追加约定）

### 零修改区域（硬约束）
- `poker_l1/src/vm/contracts/*.rs`（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs）
- `poker_l1/src/vm/precompile.rs`、`syscalls.rs`、`context.rs`、`executor.rs`
- `poker_zkvm/src/constraints/*`、`hypernova/*`、`fold/*`、`prover/*`、`recursion/*`、`isa/*`
- `poker_zkvm/src/precompiles/*.rs`（仅 mod.rs 已有 adapter）
- `poker_zkvm/src/syscalls/host.rs`

---

## 风险与缓解

| 风险 | 等级 | 缓解 |
|---|---|---|
| `crypto_consistency.rs` 截断修复后仍有编译错误 | 低 | 修复后立即 `cargo test -p poker_l1 --test crypto_consistency` |
| `gas_table.rs` 实际常量名与 BpfGasStrategy 引用不符 | 中 | Step 4.3 前先 Read gas_table.rs 确认实际导出名 |
| `SyscallId` 变体名与 BpfGasStrategy match 不符 | 中 | Step 4.3 前先 Read syscall_id.rs 确认变体名 |
| `precompile_id_from_name` 函数不存在 | 中 | Step 5.3 前先 Read precompile.rs；若不存在则内联实现 |
| 业务合约名称与 catalog 条目不符 | 低 | Step 5.3 前用 `ls poker_l1/src/vm/contracts/` 交叉验证 |
| poker_zkvm `#![deny(missing_docs)]` 被破坏 | 低 | gas_strategy 模块声明带 doc-comment |
| Phase 5 project_memory.md 修改覆盖既有内容 | 低 | 使用 Edit 工具追加，不重写整个文件 |

---

## 实施顺序与依赖

```
Phase 3.6.1 (修复截断) → 3.6.2 (测试) → 3.7 (回归)
    ↓
Phase 4.1 (trait) → 4.2 (注册) → 4.3 (BpfGasStrategy) → 4.4 (ZkvmGasStrategy)
    → 4.5 (注册) → 4.6 (测试) → 4.7 (回归)
    ↓
Phase 5.1 (syscall_id doc) → 5.3 (catalog) → 5.4 (注册)
    → 5.2 (ARCHITECTURE.md) → 5.5 (DEV_GUIDE) → 5.6 (memory) → 5.7 (端到端)
```

**预计总工作量**：1.5-2 天
- Phase 3.6-3.7：0.5 天
- Phase 4：0.5 天
- Phase 5：0.5-1 天

---

## 总结

本接续计划完成 Phase 3.6 截断修复 + Phase 3.7 回归 + Phase 4（GasStrategy）+ Phase 5（catalog + 文档）。

**核心修订**：原计划 Phase 4.3 的 BpfGasStrategy 错误引用了 `gas::GAS_MEMORY_BASE` / `gas::GAS_BRANCH`（这两个常量实际在 `poker_l1/src/vm/gas_table.rs`，是 BPF 专有）。本计划修订为从 `crate::vm::gas_table` 引用，符合 vm-common 的设计意图（"ISA 专有常量保留在各 crate 本地"）。

业务合约、约束系统、Hypernova/prover/recursion、GameTurn gas-free lane 全程零修改。每阶段独立可回退，每阶段完成立即跑测试。
