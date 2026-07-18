# VM 统一架构 — Phase 3-5 续作执行计划

## 背景与决策

### 用户决策（本次会话）

| 决策项 | 选择 | 理由 |
|---|---|---|
| 统一范围 | **非侵入式抽象层（继续 Option B）** | RV32I-CCS 耦合 236KB，完整引擎统一需 3-6 个月且风险高 |
| 主要动机 | **减少代码重复 + 合约开发者单一入口** | 通过 vm-common 横切关注点统一 + 跨 VM precompile 目录与开发者指南 |

### 当前状态评估

| 阶段 | 状态 | 证据 |
|---|---|---|
| Phase 0 测试基线 | ✅ 完成 | poker_l1 vm 测试 + poker_zkvm 1069 测试全绿 |
| Phase 1（vm-common 骨架 + gas/syscall_id） | ✅ 完成 | `vm-common/src/{gas.rs, syscall_id.rs}` 已存在，`cargo check -p vm-common` 通过 |
| Phase 2（PrecompileMetadata + zkvm adapter） | ✅ 完成 | `vm-common/src/precompile.rs`（8386B）+ `poker_zkvm/src/precompiles/adapter.rs`（6955B）已存在，6 测试通过 |
| Phase 3.1-3.2（CryptoProvider trait + 注册） | ✅ 完成 | `vm-common/src/crypto.rs`（330 行，4 测试）已定义完整 trait，`lib.rs` 已注册 `pub mod crypto;` |
| Phase 3.3（BlstrsCryptoProvider） | ❌ **3 个编译错误** | `poker_l1/src/vm/crypto_blstrs.rs` 已创建（317 行）但编译失败 |
| Phase 3.4-3.7 | ⏳ 未开始 | ArkworksCryptoProvider + 一致性测试未创建 |
| Phase 4（GasStrategy） | ⏳ 未开始 | `vm-common/src/gas_strategy.rs` 不存在（探索 agent 误报） |
| Phase 5（ABI 文档） | ⏳ 未开始 | — |

### Phase 3.3 编译错误详情（3 处）

**文件**：`/Users/mac/projects/zchain/poker_l1/src/vm/crypto_blstrs.rs`

1. **L57 `Blake2b256::new()`**：import 已改为 `Blake2bVar`（L16-17），但方法体仍用 `Blake2b256::new()`
   - 修复：改用 `Blake2bVar::new(32).expect("32 <= 64")` + `finalize_variable`
2. **L78 `secp256k1::Message::from_digest_ref(msg_hash).ok()`**：secp256k1 0.29 无 `from_digest_ref`，有 `from_digest`
   - 修复：`secp256k1::Message::from_digest(*msg_hash)`（直接返回 `Message`，非 Result）
3. **L88 `let Ok(sig) = ed25519_dalek::Signature::from_bytes(signature)`**：ed25519-dalek 2.1.1 的 `Signature::from_bytes(&[u8; 64]) -> Signature` 是不可失败API（固定长度输入），返回 `Signature` 非 `Result`
   - 修复：`let sig = ed25519_dalek::Signature::from_bytes(signature);`（移除 `let Ok()` 模式匹配）

---

## 执行原则（沿用）

1. 每阶段独立可回退，每阶段完成立即跑测试
2. 业务合约（17 个）零修改（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs）
3. Hypernova/CCS/constraints/prover/recursion 零修改
4. GameTurn/CheckpointAnchor gas-free lane 零修改
5. `poker_zkvm::#![deny(unsafe_code)]` 不破坏
6. vm-common 严格 `#![deny(unsafe_code)]`，不依赖 solana_rbpf/arkworks
7. **非侵入式**：Phase 3-4 不改造现有 syscall/executor 调用路径

---

## Phase 3：CryptoProvider 抽象 — 修复与完成

**目标**：修复 BlstrsCryptoProvider 编译错误，创建 ArkworksCryptoProvider，建立一致性测试。

### Step 3.3：修复 BlstrsCryptoProvider 编译错误

**文件**：`/Users/mac/projects/zchain/poker_l1/src/vm/crypto_blstrs.rs`

**修复 1** — `blake2b_256` 方法（L56-60）：

```rust
fn blake2b_256(&self, input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(input);
    let mut result = [0u8; 32];
    hasher.finalize_variable(&mut result).expect("32 bytes output");
    result
}
```

**修复 2** — `ecdsa_verify_secp256k1` 方法（L77-81）：

```rust
// 验签（secp256k1 0.29: from_digest 直接返回 Message，非 Result）
let msg = secp256k1::Message::from_digest(*msg_hash);
secp256k1::Secp256k1::verification_only()
    .verify_ecdsa(&msg, &sig_obj, &pubkey_obj)
    .is_ok()
```

**修复 3** — `ed25519_verify` 方法（L87-90）：

```rust
fn ed25519_verify(&self, msg: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
    // ed25519-dalek 2.1.1: Signature::from_bytes 不可失败（固定 64B 输入）
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    pk.verify_strict(msg, &sig).is_ok()
}
```

**验证**：`cargo test -p poker_l1 vm::crypto_blstrs` — 10 个单元测试全绿

### Step 3.4：创建 ArkworksCryptoProvider

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/crypto_arkworks.rs`（约 280 行）

**实现要点**：
- `ArkworksCryptoProvider` 结构体（无字段，`#[derive(Debug, Default, Clone, Copy)]`）
- 哈希函数：`sha2::Sha256` / `sha3::Keccak256` / `blake2::Blake2bVar`（与 BlstrsCryptoProvider 使用相同 crate，结果必然一致）
- ECDSA：`secp256k1` crate（与 poker_l1 一致）
- Ed25519：`ed25519_dalek`（与 poker_l1 一致）
- **BLS12-381**：全部返回 `None`/`false`（zkvm 不用 BLS12-381）
- **BN254**：调用 `ark_bn254::Bn254::pairing`（zkvm 用 BN254）

**BN254 pairing 实现关键**：
```rust
fn bn254_pairing_check(
    &self,
    pairs: &[([u8; BN254_G1_COMPRESSED_SIZE], [u8; BN254_G2_COMPRESSED_SIZE])],
) -> bool {
    use ark_bn254::{Bn254, G1Projective, G2Projective};
    use ark_ec::pairing::Pairing;
    use ark_serialize::CanonicalDeserialize;

    let mut g1_points = Vec::new();
    let mut g2_points = Vec::new();
    for (g1_bytes, g2_bytes) in pairs {
        let g1 = match G1Projective::deserialize_compressed_unchecked(g1_bytes.as_slice()) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let g2 = match G2Projective::deserialize_compressed_unchecked(g2_bytes.as_slice()) {
            Ok(p) => p,
            Err(_) => return false,
        };
        g1_points.push(g1);
        g2_points.push(g2);
    }
    // Bn254::multi_pairing 返回 GT，检查是否 == one
    let gt = Bn254::multi_pairing(&g1_points, &g2_points);
    gt == ark_bn254::Bn254::target_field::one()
}
```

**单元测试**（约 10 个）：
- `test_arkworks_provider_name` — 返回 `"arkworks"`
- `test_arkworks_sha256` — 与 BlstrsCryptoProvider 相同向量
- `test_arkworks_keccak256` — 空输入已知哈希
- `test_arkworks_blake2b_256` — 非全零验证
- `test_arkworks_ecdsa_invalid_input` — 非法输入返回 false
- `test_arkworks_ed25519_invalid_input` — 非法输入返回 false
- `test_arkworks_bls12_381_unsupported` — 所有 BLS12-381 方法返回 None/false
- `test_arkworks_bn254_invalid_input` — 非法输入返回 false
- `test_arkworks_aggregate_empty` — 空集合返回 None
- `test_arkworks_trait_object` — `Box<dyn CryptoProvider>` 可用

### Step 3.5：注册 crypto_arkworks 模块

**修改**：`/Users/mac/projects/zchain/poker_zkvm/src/lib.rs`

在 Layer 5 区块（L52-55 附近）添加：
```rust
pub mod crypto_arkworks;  // Phase 3 — CryptoProvider 实现（ark-bn254 后端）
```

**注意**：放置在 `pub mod precompiles;` 之前或之后均可，但需在 `#![deny(unsafe_code)]` 之后（保持 crate 级 deny）

### Step 3.6：跨实现一致性测试

**新建**：`/Users/mac/projects/zchain/poker_l1/tests/crypto_consistency.rs`（约 150 行）

**为什么放在 poker_l1**：poker_l1 同时依赖 `poker_zkvm`（workspace 依赖）和自身的 `BlstrsCryptoProvider`，可访问两个 provider。

**测试用例**：
```rust
use poker_l1::vm::crypto_blstrs::BlstrsCryptoProvider;
use poker_zkvm::crypto_arkworks::ArkworksCryptoProvider;
use vm_common::crypto::CryptoProvider;

#[test]
fn test_sha256_consistency() {
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    let inputs: &[&[u8]] = &[b"", b"hello", b"test message", &[0u8; 64]];
    for input in inputs {
        assert_eq!(blstrs.sha256(input), arkworks.sha256(input),
            "sha256 mismatch for input len {}", input.len());
    }
}

#[test]
fn test_keccak256_consistency() { /* 同上 */ }

#[test]
fn test_blake2b_256_consistency() { /* 同上 */ }

#[test]
fn test_ecdsa_invalid_input_consistency() {
    // 两个 provider 对非法输入都应返回 false
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    assert_eq!(
        blstrs.ecdsa_verify_secp256k1(&[0u8; 32], &[0u8; 65], &[0u8; 33]),
        arkworks.ecdsa_verify_secp256k1(&[0u8; 32], &[0u8; 65], &[0u8; 33])
    );
}

#[test]
fn test_ed25519_invalid_input_consistency() { /* 同上 */ }

#[test]
fn test_provider_names_distinct() {
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    assert_eq!(blstrs.name(), "blstrs");
    assert_eq!(arkworks.name(), "arkworks");
    assert_ne!(blstrs.name(), arkworks.name());
}

#[test]
fn test_trait_object_collection() {
    let providers: Vec<Box<dyn CryptoProvider>> = vec![
        Box::new(BlstrsCryptoProvider::new()),
        Box::new(ArkworksCryptoProvider::new()),
    ];
    assert_eq!(providers.len(), 2);
    assert_eq!(providers[0].name(), "blstrs");
    assert_eq!(providers[1].name(), "arkworks");
}
```

**注意**：不测试 BLS12-381 vs BN254 等价（不同曲线，结果不可比）

### Step 3.7：回归测试

```bash
cargo test -p vm-common                         # crypto trait 测试（4 个）
cargo test -p poker_l1 vm::crypto_blstrs        # BlstrsCryptoProvider 测试（10 个）
cargo test -p poker_zkvm --features test-helpers crypto_arkworks  # ArkworksCryptoProvider 测试
cargo test -p poker_l1 --test crypto_consistency # 跨实现一致性（7 个）
cargo test --workspace                           # 全回归
```

### Phase 3 验收

- [ ] `crypto_blstrs.rs` 3 个编译错误已修复，10 测试全绿
- [ ] `poker_zkvm/src/crypto_arkworks.rs` 创建，10 测试全绿
- [ ] `poker_zkvm/src/lib.rs` 注册 `pub mod crypto_arkworks;`
- [ ] `poker_l1/tests/crypto_consistency.rs` 7 测试全绿
- [ ] 现有 syscall 调用路径零退化（poker_l1 BLS syscall 仍走 `crypto_precompiles/bls.rs`）
- [ ] `cargo test --workspace` 全绿

---

## Phase 4：GasStrategy trait + 双实现

**目标**：形式化 gas 计费策略接口，明确 zkvm 指令级 gas = 0、链上 = 1 的差异。非侵入式形式化层。

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
    Arithmetic,
    Memory,
    ControlFlow,
    Shift,
    Mul,
    Div,
    UpperImm,
    System,
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

    /// 测试用 GasStrategy 实现（全 0，仅验证 trait object）。
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

```rust
pub mod crypto;
pub mod gas;
pub mod gas_strategy;   // ← 新增
pub mod precompile;
pub mod syscall_id;
```

### Step 4.3：BpfGasStrategy 实现

**新建**：`/Users/mac/projects/zchain/poker_l1/src/vm/gas_strategy.rs`（约 100 行）

```rust
//! BpfGasStrategy — poker_l1 链上 BPF gas 策略（Phase 4）。

use vm_common::gas;
use vm_common::gas_strategy::{GasStrategy, InsnCategory};
use vm_common::syscall_id::SyscallId;

/// poker_l1 链上 BPF gas 策略。
///
/// 完整计费：指令级 1 gas/条 + syscall 级按 vm_common::gas 计费。
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
            InsnCategory::Arithmetic | InsnCategory::UpperImm | InsnCategory::Other => 1,
            InsnCategory::Memory => gas::GAS_MEMORY_BASE,
            InsnCategory::ControlFlow | InsnCategory::System => gas::GAS_BRANCH,
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
        assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), 1);
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

**注意**：需先确认 `vm_common::gas` 中导出了 `GAS_MEMORY_BASE`、`GAS_BRANCH`、`GAS_SECP256K1_VERIFY`、`TX_GAS_LIMIT`、`BLOCK_GAS_LIMIT` 常量与 `object_read_gas`/`object_write_gas`/`object_create_gas`/`emit_event_gas`/`zk_verify_gas` 函数。若常量名不符，需调整 match 分支（读取 `vm-common/src/gas.rs` 确认实际导出名）。

### Step 4.4：ZkvmGasStrategy 实现

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas_strategy.rs`（约 80 行）

```rust
//! ZkvmGasStrategy — poker_zkvm 链下 ZK VM gas 策略（Phase 4）。
//!
//! **无 gas 费**：所有 instruction_gas 返回 0，instruction_meter_enabled = false。
//! 仅 step_limit（执行步数上限）约束执行。

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

**修改**：`/Users/mac/projects/zchain/poker_l1/src/vm/mod.rs` — 添加 `pub mod gas_strategy;`

**修改**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs` — 添加 `pub mod gas_strategy;`

### Step 4.6：跨实现一致性测试

**新建**：`/Users/mac/projects/zchain/poker_l1/tests/gas_strategy_consistency.rs`（约 80 行）

```rust
use poker_l1::vm::gas_strategy::BpfGasStrategy;
use poker_zkvm::syscalls::gas_strategy::ZkvmGasStrategy;
use vm_common::gas_strategy::{GasStrategy, InsnCategory};

#[test]
fn test_bpf_vs_zkvm_gas_difference() {
    let bpf = BpfGasStrategy::new();
    let zkvm = ZkvmGasStrategy::new();

    // BPF 有 gas，zkvm 无 gas
    assert!(bpf.instruction_meter_enabled());
    assert!(!zkvm.instruction_meter_enabled());

    // 所有指令类别 zkvm 都是 0
    for cat in [
        InsnCategory::Arithmetic, InsnCategory::Memory, InsnCategory::ControlFlow,
        InsnCategory::Shift, InsnCategory::Mul, InsnCategory::Div,
        InsnCategory::UpperImm, InsnCategory::System, InsnCategory::Other,
    ] {
        assert_eq!(zkvm.instruction_gas(cat), 0, "zkvm {:?} should be 0", cat);
        assert!(bpf.instruction_gas(cat) > 0 || cat == InsnCategory::Other,
            "bpf {:?} should be > 0", cat);
    }
}

#[test]
fn test_strategy_names() {
    assert_eq!(BpfGasStrategy::new().name(), "bpf");
    assert_eq!(ZkvmGasStrategy::new().name(), "zkvm");
}

#[test]
fn test_trait_object_collection() {
    let strategies: Vec<Box<dyn GasStrategy>> = vec![
        Box::new(BpfGasStrategy::new()),
        Box::new(ZkvmGasStrategy::new()),
    ];
    assert_eq!(strategies.len(), 2);
}
```

### Step 4.7：回归测试

```bash
cargo test -p vm-common                         # GasStrategy trait 测试
cargo test -p poker_l1 vm::gas_strategy         # BpfGasStrategy 测试
cargo test -p poker_zkvm --features test-helpers syscalls::gas_strategy  # ZkvmGasStrategy 测试
cargo test -p poker_l1 --test gas_strategy_consistency  # 跨实现一致性
cargo test --workspace                           # 全回归
```

### Phase 4 验收

- [ ] `vm-common/src/gas_strategy.rs` 定义 trait + InsnCategory（2 测试）
- [ ] `poker_l1/src/vm/gas_strategy.rs` 实现 BpfGasStrategy（4 测试）
- [ ] `poker_zkvm/src/syscalls/gas_strategy.rs` 实现 ZkvmGasStrategy（4 测试，全 0）
- [ ] zkvm 指令级 gas = 0（验证所有 InsnCategory）
- [ ] poker_l1 GameTurn gas-free lane 路径零修改
- [ ] `cargo test --workspace` 全绿

---

## Phase 5：ABI 文档 + 架构文档 + 合约开发者指南

**目标**：固化统一 ABI 文档，建立合约开发者单一入口指南，更新 project_memory.md。

### Step 5.1：完善 SyscallId doc-comments

**修改**：`/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`

为每个 `SyscallId` 变体添加 doc-comment（含 ID 值、用途、所属 VM 段）：

```rust
pub enum SyscallId {
    // ===== zkvm 段（0x01-0x0F）=====
    /// zkvm: 读取 host 状态（0x01）。
    /// 仅 poker_zkvm 使用，poker_l1 返回错误。
    ReadState = 0x01,
    /// zkvm: 获取 randomness（0x02）。
    GetRandomness = 0x02,
    // ... 其余 zkvm syscall

    // ===== poker_l1 段（0x40-0x7F）=====
    /// poker_l1: 读取对象（0x40）。
    /// 仅 poker_l1 使用，zkvm 无对象模型。
    ObjectRead = 0x40,
    // ... 其余 poker_l1 syscall

    // ===== BLS12-381 段（0x80-0xFF）=====
    /// 跨 VM: BLS12-381 G1 点加法（0x80）。
    /// 两个 VM 均可用（poker_l1 blstrs 实现，zkvm 通过 host syscall）。
    BlsG1Add = 0x80,
    // ... 其余 BLS syscall
}
```

**验证**：`cargo doc -p vm-common --no-deps` 生成文档无警告

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

### Step 5.3：创建 PrecompileCatalog（合约开发者单一入口）

**新建**：`/Users/mac/projects/zchain/vm-common/src/catalog.rs`（约 200 行）

**目标**：建立跨 VM precompile 可用性矩阵，让合约开发者清楚哪些预编译在哪个 VM 可用。

```rust
//! PrecompileCatalog — 跨 VM 预编译可用性目录（Phase 5）。
//!
//! 合约开发者单一入口：通过此目录查询某个预编译在 L1 / zkvm 的可用性、
//! gas 策略、ID 与调用方式，无需阅读两个 VM 的源码。
//!
//! # 用法
//!
//! ```ignore
//! use vm_common::catalog::PrecompileCatalog;
//! let catalog = PrecompileCatalog::default();
//! let entry = catalog.find("sha256").expect("sha256 应存在");
//! assert!(entry.l1_available);
//! assert!(entry.zkvm_available);
//! ```

/// 预编译可用性条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// 预编译名称（如 "sha256", "poseidon", "gameturn"）
    pub name: &'static str,
    /// 类别
    pub category: PrecompileCategory,
    /// poker_l1 是否可用
    pub l1_available: bool,
    /// poker_zkvm 是否可用
    pub zkvm_available: bool,
    /// 是否 gas-free（GameTurn/CheckpointAnchor lane）
    pub is_gas_free: bool,
    /// 稳定 ID（[u8; 32]，0xFF 前缀）
    pub id_bytes: [u8; 32],
    /// 简短描述
    pub description: &'static str,
}

/// 预编译类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecompileCategory {
    /// 哈希函数
    Hash,
    /// 签名验证
    Signature,
    /// 配对 / 椭圆曲线
    Pairing,
    /// 业务合约（游戏逻辑）
    Business,
    /// ZK 证明
    ZkProof,
    /// 其他
    Other,
}

/// 跨 VM 预编译目录。
#[derive(Debug, Default)]
pub struct PrecompileCatalog {
    entries: Vec<CatalogEntry>,
}

impl PrecompileCatalog {
    /// 创建包含所有已知预编译的目录。
    pub fn default_catalog() -> Self {
        use crate::precompile::precompile_id_from_name;
        let mut entries = Vec::new();

        // ===== 哈希函数（跨 VM 共享）=====
        for &(name, desc) in &[
            ("sha256", "SHA-256 哈希"),
            ("keccak256", "Keccak-256 哈希（Ethereum 风格）"),
            ("blake2b_256", "Blake2b-256 哈希"),
            ("poseidon", "Poseidon 哈希（ZK 友好）"),
        ] {
            entries.push(CatalogEntry {
                name,
                category: PrecompileCategory::Hash,
                l1_available: true,
                zkvm_available: true,
                is_gas_free: false,
                id_bytes: precompile_id_from_name(name),
                description: desc,
            });
        }

        // ===== 签名验证（跨 VM 共享）=====
        for &(name, desc) in &[
            ("ecdsa_secp256k1", "ECDSA secp256k1 签名验证"),
            ("ed25519", "Ed25519 签名验证"),
            ("ecdsa_verify", "ECDSA 验签电路（zkvm 专用）"),
        ] {
            entries.push(CatalogEntry {
                name,
                category: PrecompileCategory::Signature,
                l1_available: name != "ecdsa_verify",
                zkvm_available: true,
                is_gas_free: false,
                id_bytes: precompile_id_from_name(name),
                description: desc,
            });
        }

        // ===== 配对 / 椭圆曲线 =====
        for &(name, l1, zk, desc) in &[
            ("bls12_381_pairing", true, false, "BLS12-381 配对检查"),
            ("bn254_pairing", false, true, "BN254 配对检查"),
            ("bn254_ops", false, true, "BN254 椭圆曲线运算"),
        ] {
            entries.push(CatalogEntry {
                name,
                category: PrecompileCategory::Pairing,
                l1_available: l1,
                zkvm_available: zk,
                is_gas_free: false,
                id_bytes: precompile_id_from_name(name),
                description: desc,
            });
        }

        // ===== 业务合约（仅 L1）=====
        for &(name, gas_free, desc) in &[
            ("gameturn", true, "游戏回合（gas-free lane）"),
            ("checkpoint_anchor", true, "检查点锚定（gas-free lane）"),
            ("force_advance", false, "强制推进"),
            ("force_settle", false, "强制结算"),
            ("force_checkin", false, "强制签到"),
            ("settle", false, "结算"),
            ("revert", false, "回退"),
            ("hand_started", false, "手牌开始"),
            ("ack_protocol", false, "确认协议"),
            ("forfeit", false, "弃牌"),
            ("censor_detection", false, "审查检测"),
            ("delegated_escape", false, "委托逃生"),
            ("force_checkpoint", false, "强制检查点"),
            ("challenge_delta", false, "挑战增量"),
            ("checkpoint_skip", false, "检查点跳过"),
            ("request_da", false, "请求 DA"),
        ] {
            entries.push(CatalogEntry {
                name,
                category: PrecompileCategory::Business,
                l1_available: true,
                zkvm_available: false,
                is_gas_free: gas_free,
                id_bytes: precompile_id_from_name(name),
                description: desc,
            });
        }

        // ===== ZK 证明（跨 VM）=====
        entries.push(CatalogEntry {
            name: "zk_verify",
            category: PrecompileCategory::ZkProof,
            l1_available: true,
            zkvm_available: true,
            is_gas_free: false,
            id_bytes: precompile_id_from_name("zk_verify"),
            description: "ZK 证明验证（Hypernova/Groth16）",
        });

        Self { entries }
    }

    /// 按名称查找。
    pub fn find(&self, name: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// 列出所有在两个 VM 都可用的预编译。
    pub fn cross_vm_available(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries.iter().filter(|e| e.l1_available && e.zkvm_available)
    }

    /// 列出所有 gas-free 预编译。
    pub fn gas_free(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries.iter().filter(|e| e.is_gas_free)
    }

    /// 按类别筛选。
    pub fn by_category(&self, cat: PrecompileCategory) -> impl Iterator<Item = &CatalogEntry> {
        self.entries.iter().filter(move |e| e.category == cat)
    }

    /// 条目总数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_default_not_empty() {
        let c = PrecompileCatalog::default_catalog();
        assert!(c.len() > 20);
    }

    #[test]
    fn test_find_sha256() {
        let c = PrecompileCatalog::default_catalog();
        let e = c.find("sha256").expect("sha256 应存在");
        assert!(e.l1_available && e.zkvm_available);
        assert!(!e.is_gas_free);
    }

    #[test]
    fn test_find_gameturn_gas_free() {
        let c = PrecompileCatalog::default_catalog();
        let e = c.find("gameturn").expect("gameturn 应存在");
        assert!(e.l1_available);
        assert!(!e.zkvm_available);
        assert!(e.is_gas_free);
    }

    #[test]
    fn test_cross_vm_available_includes_hashes() {
        let c = PrecompileCatalog::default_catalog();
        let names: Vec<_> = c.cross_vm_available().map(|e| e.name).collect();
        assert!(names.contains(&"sha256"));
        assert!(names.contains(&"keccak256"));
    }

    #[test]
    fn test_gas_free_lane() {
        let c = PrecompileCatalog::default_catalog();
        let gas_free: Vec<_> = c.gas_free().map(|e| e.name).collect();
        assert!(gas_free.contains(&"gameturn"));
        assert!(gas_free.contains(&"checkpoint_anchor"));
    }

    #[test]
    fn test_by_category_business() {
        let c = PrecompileCatalog::default_catalog();
        let business: Vec<_> = c.by_category(PrecompileCategory::Business).collect();
        assert!(business.len() >= 16); // 16 个业务合约
    }

    #[test]
    fn test_id_bytes_stable() {
        let c = PrecompileCatalog::default_catalog();
        let e = c.find("sha256").unwrap();
        assert_eq!(e.id_bytes[0], 0xFF);
    }
}
```

### Step 5.4：注册 catalog 模块

**修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`

```rust
pub mod catalog;        // ← 新增
pub mod crypto;
pub mod gas;
pub mod gas_strategy;
pub mod precompile;
pub mod syscall_id;
```

### Step 5.5：创建合约开发者指南

**新建**：`/Users/mac/projects/zchain/vm-common/CONTRACT_DEV_GUIDE.md`

**内容大纲**：

```markdown
# zchain 合约开发者指南

## 概述

zchain 有两个 VM 执行环境：
- **poker_l1（链上）**：使用 solana_rbpf 引擎，有 gas 计费
- **poker_zkvm（链下 ZK）**：使用 RV32I 引擎，无 gas 费

合约开发者通过本指南了解哪些预编译在哪个 VM 可用。

## 预编译可用性矩阵

| 预编译 | 类别 | L1 | zkvm | gas-free | 说明 |
|---|---|---|---|---|---|
| sha256 | 哈希 | ✅ | ✅ | ❌ | SHA-256 |
| keccak256 | 哈希 | ✅ | ✅ | ❌ | Keccak-256 |
| blake2b_256 | 哈希 | ✅ | ✅ | ❌ | Blake2b-256 |
| poseidon | 哈希 | ❌ | ✅ | ❌ | ZK 友好哈希 |
| ecdsa_secp256k1 | 签名 | ✅ | ❌ | ❌ | ECDSA 验签 |
| ed25519 | 签名 | ✅ | ✅ | ❌ | Ed25519 验签 |
| ecdsa_verify | 签名 | ❌ | ✅ | ❌ | ECDSA 电路 |
| bls12_381_pairing | 配对 | ✅ | ❌ | ❌ | BLS12-381 |
| bn254_pairing | 配对 | ❌ | ✅ | ❌ | BN254 |
| gameturn | 业务 | ✅ | ❌ | ✅ | 游戏回合 |
| checkpoint_anchor | 业务 | ✅ | ❌ | ✅ | 检查点锚定 |
| ... | ... | ... | ... | ... | ... |
| zk_verify | ZK | ✅ | ✅ | ❌ | ZK 证明验证 |

## Syscall ID 空间

- 0x01-0x0F：zkvm 专用（read_state, get_randomness 等）
- 0x40-0x7F：poker_l1 专用（object_read, object_write 等）
- 0x80-0xFF：跨 VM 共享（BLS12-381 操作）

## Gas 策略

- **poker_l1**：指令级 1 gas/条 + syscall 级按表计费
- **poker_zkvm**：无 gas 费，仅 step_limit（≤ 1,048,576 步）
- **gas-free lane**：GameTurn / CheckpointAnchor 交易在 L1 免 gas

## 如何写跨 VM 兼容合约

1. 优先使用跨 VM 可用的预编译（sha256/keccak256/ed25519/zk_verify）
2. 避免在 ZK 上下文调用 L1 专用 syscall（object_read 等）
3. 使用 `vm_common::catalog::PrecompileCatalog` 查询可用性
```

### Step 5.6：更新 project_memory.md

**修改**：`/Users/mac/.trae-cn/memory/projects/-Users-mac-projects-zchain/project_memory.md`

在 `Engineering Conventions` 节追加：

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
cargo test --workspace                     # 全绿
cargo doc -p vm-common --no-deps           # 文档无警告
cargo tree -p vm-common                    # 应只有 thiserror，无 solana_rbpf/arkworks
git diff poker_l1/src/vm/contracts/        # 应为空（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs）
git diff poker_zkvm/src/constraints/       # 应为空
git diff poker_zkvm/src/hypernova/         # 应为空
```

### Phase 5 验收

- [ ] `vm-common/src/syscall_id.rs` 每个 SyscallId 变体有 doc-comment
- [ ] `vm-common/ARCHITECTURE.md` 创建
- [ ] `vm-common/src/catalog.rs` 创建，7 测试全绿
- [ ] `vm-common/CONTRACT_DEV_GUIDE.md` 创建
- [ ] `project_memory.md` 追加 8 条新工程约定
- [ ] 端到端 `cargo test --workspace` 全绿
- [ ] git diff 验证零修改区域确实未动

---

## 关键文件清单

### Phase 3 修复与新建（4 个）
- **修改**：`/Users/mac/projects/zchain/poker_l1/src/vm/crypto_blstrs.rs`（修复 3 个编译错误）
- **新建**：`/Users/mac/projects/zchain/poker_zkvm/src/crypto_arkworks.rs`（ArkworksCryptoProvider，~280 行）
- **修改**：`/Users/mac/projects/zchain/poker_zkvm/src/lib.rs`（注册 `pub mod crypto_arkworks;`）
- **新建**：`/Users/mac/projects/zchain/poker_l1/tests/crypto_consistency.rs`（一致性测试，~150 行）

### Phase 4 新建（3 个 + 1 个测试 + 2 个注册）
- **新建**：`/Users/mac/projects/zchain/vm-common/src/gas_strategy.rs`（GasStrategy trait，~120 行）
- **新建**：`/Users/mac/projects/zchain/poker_l1/src/vm/gas_strategy.rs`（BpfGasStrategy，~100 行）
- **新建**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas_strategy.rs`（ZkvmGasStrategy，~80 行）
- **新建**：`/Users/mac/projects/zchain/poker_l1/tests/gas_strategy_consistency.rs`（跨实现测试，~80 行）
- **修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`（加 `pub mod gas_strategy;`）
- **修改**：`/Users/mac/projects/zchain/poker_l1/src/vm/mod.rs`（加 `pub mod gas_strategy;`）
- **修改**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs`（加 `pub mod gas_strategy;`）

### Phase 5 文档与 catalog（3 个新建 + 2 个修改）
- **新建**：`/Users/mac/projects/zchain/vm-common/src/catalog.rs`（PrecompileCatalog，~200 行）
- **新建**：`/Users/mac/projects/zchain/vm-common/ARCHITECTURE.md`
- **新建**：`/Users/mac/projects/zchain/vm-common/CONTRACT_DEV_GUIDE.md`
- **修改**：`/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`（doc-comment 完善）
- **修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`（加 `pub mod catalog;`）
- **修改**：`/Users/mac/.trae-cn/memory/projects/-Users-mac-projects-zchain/project_memory.md`（追加约定）

### 零修改区域（硬约束）
- `poker_l1/src/vm/contracts/*.rs`（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs）
- `poker_l1/src/vm/precompile.rs`（完整 Precompile trait 保持原状）
- `poker_l1/src/vm/syscalls.rs`（BLS syscall 调用路径不改）
- `poker_l1/src/vm/context.rs`（PokerL1Context 签名不改）
- `poker_l1/src/executor.rs`（GameTurn gas-free lane）
- `poker_zkvm/src/constraints/*`
- `poker_zkvm/src/hypernova/*`
- `poker_zkvm/src/fold/*`
- `poker_zkvm/src/prover/*`
- `poker_zkvm/src/recursion/*`
- `poker_zkvm/src/isa/*`（RV32I 引擎）
- `poker_zkvm/src/precompiles/*.rs`（23 个电路实现，仅 mod.rs 已加 adapter）
- `poker_zkvm/src/syscalls/host.rs`（host syscall 实现不改）

---

## 风险与缓解

| 风险 | 等级 | 缓解 |
|---|---|---|
| crypto_blstrs.rs 3 个编译错误修复后仍有其他错误 | 低 | 修复后立即 `cargo test -p poker_l1 vm::crypto_blstrs` 验证 |
| ArkworksCryptoProvider BN254 pairing API 不匹配 | 中 | 先 `cargo doc -p ark-bn254` 确认 `Bn254::multi_pairing` 签名，再实现 |
| vm-common::gas 常量名与 BpfGasStrategy 引用不符 | 中 | Step 4.3 前先 Read `vm-common/src/gas.rs` 确认实际导出名 |
| PrecompileCatalog 条目与实际合约数不符 | 低 | 实现后用 `git ls-files poker_l1/src/vm/contracts/` 交叉验证 |
| Phase 5 project_memory.md 修改覆盖既有内容 | 低 | 使用 Edit 工具追加，不重写整个文件 |
| poker_zkvm deny(unsafe_code) 被破坏 | 低 | crypto_arkworks.rs 与 gas_strategy.rs 不使用 unsafe |

---

## 实施顺序与依赖

```
Phase 3.3 (修复 BlstrsCryptoProvider) 
    ↓
Phase 3.4 (ArkworksCryptoProvider) 
    ↓
Phase 3.5 (注册模块) + Phase 3.6 (一致性测试) 
    ↓ 
Phase 3.7 (回归) 
    ↓
Phase 4.1 (GasStrategy trait) → 4.2 (注册) → 4.3 (BpfGasStrategy) → 4.4 (ZkvmGasStrategy) → 4.5 (注册) → 4.6 (测试) → 4.7 (回归)
    ↓
Phase 5.1 (syscall_id doc) → 5.3 (catalog.rs) → 5.4 (注册) → 5.2 (ARCHITECTURE.md) → 5.5 (DEV_GUIDE) → 5.6 (memory) → 5.7 (端到端)
```

**预计总工作量**：3-4 天
- Phase 3：1-1.5 天（修复 + ArkworksCryptoProvider + 一致性测试）
- Phase 4：0.5-1 天（GasStrategy trait + 双实现）
- Phase 5：1-1.5 天（catalog + 文档 + memory）

---

## 总结

本计划从 Phase 3.3 编译错误修复接续，完成 Phase 3-5 共 3 个阶段。核心策略是**非侵入式形式化层**：

1. **Phase 3**（1-1.5 天）：修复 BlstrsCryptoProvider 3 个编译错误，创建 ArkworksCryptoProvider，建立一致性测试
2. **Phase 4**（0.5-1 天）：建立 GasStrategy trait + 双实现（zkvm 全 0），**不改 executor 签名**
3. **Phase 5**（1-1.5 天）：PrecompileCatalog 合约开发者单一入口 + ABI 文档 + ARCHITECTURE.md + project_memory 更新

业务合约、约束系统、Hypernova/prover/recursion、GameTurn gas-free lane 全程零修改。每阶段独立可回退，