# Phase I Batch 1 完成计划

## Summary

完成 Phase I Batch 1 的最后一步（I-4 注册集成），将 3 个新预编译电路（keccak256 / modexp / merkle_verify）注册到 SyscallId 枚举、gas 计费表和 PrecompileRegistry 测试中，并全量验证。

## Current State Analysis

### 已完成
- **I-1 merkle_verify**: `precompiles/merkle_verify.rs` 完整，MVP + Full 模式，`new()` / `new_full_with_depth(n)` 构造函数就绪
- **I-2 modexp**: `precompiles/modexp.rs` 完整，MVP + Full 模式，`new()` / `new_full_with_bits(n)` 构造函数就绪
- **I-3 keccak256**: `precompiles/keccak256.rs` 完整，bit_not 约束已修复（L229: `bit + not_bit - 1 = 0`），host 实现已验证与 FIPS 202 规范一致
- 3 个模块均已在 `precompiles/mod.rs` L20-30 声明为 `pub mod`
- 3 个电路均实现 `PrecompileCircuit` + `CcsCircuit` 双 trait

### 未完成
- **I-4 注册集成**:
  - `syscalls/mod.rs`: SyscallId 仍为 10 个变体（0x01-0x0A），未新增 Keccak256/Modexp/MerkleVerify
  - `syscalls/gas.rs`: 仅有原始 13 个 gas 常量，未新增 5 个预编译 gas 常量
  - `precompiles/mod.rs` 测试: `test_phase10_registry_full` 等仅注册 4 个预编译（poseidon/sha256/ecdsa/zk_shuffle）
- **keccak256("abc") 测试状态未知**: bit_not 已修复，host 实现静态分析正确，但未运行测试确认

### 不在本次范围
- host syscall 实现（`host.rs` 中的 `Keccak256Syscall` 等）— Phase I 聚焦预编译电路（CCS），host 执行是独立关注点
- ed25519 / bn254 pairing / bls12-381 — 属于 Phase I Batch 2，本次不做

## Proposed Changes

### Step 1: 验证 keccak256("abc") 测试

先运行测试确认 bit_not 修复后 keccak256 实现正确：

```bash
cargo test -p poker_zkvm --lib precompiles::keccak256::tests::test_host_keccak256_abc -- --nocapture
cargo test -p poker_zkvm --lib precompiles::keccak256::tests::test_host_keccak256_empty -- --nocapture
cargo test -p poker_zkvm --lib precompiles::keccak256::tests::test_keccak_mvp_single_round -- --nocapture
cargo test -p poker_zkvm --lib precompiles::keccak256::tests::test_keccak_gas_cost -- --nocapture
cargo test -p poker_zkvm --lib precompiles::keccak256::tests::test_keccak_wrong_input_length -- --nocapture
```

**预期结果**: 全部通过（host 实现已验证正确，bit_not 约束已修复）。
**如果失败**: 用 Python pycryptodome 验证正确值，添加调试测试打印中间状态，定位并修复 bug。

### Step 2: 修改 `syscalls/mod.rs`

**文件**: `poker_zkvm/src/syscalls/mod.rs`

#### 2.1 SyscallId 枚举新增 3 个变体 (L62-83)

在 `ReadState = 0x0A` 后新增：

```rust
    /// `zkvm_keccak256(ptr, len, out_ptr)` — Keccak-256 哈希。
    Keccak256 = 0x0B,
    /// `zkvm_modexp(base_ptr, exp_ptr, mod_ptr, result_ptr, num_bits)` — 大数模幂。
    Modexp = 0x0C,
    /// `zkvm_merkle_verify(leaf, path, indices, root, depth)` — Merkle 路径验证。
    MerkleVerify = 0x0D,
```

#### 2.2 `from_u32()` 新增 3 个分支 (L90-103)

在 `0x0A => Ok(Self::ReadState)` 后新增：

```rust
            0x0B => Ok(Self::Keccak256),
            0x0C => Ok(Self::Modexp),
            0x0D => Ok(Self::MerkleVerify),
```

#### 2.3 `all()` 返回 `[Self; 13]` (L106-121)

```rust
    /// 返回全部 13 个 syscall ID（按枚举顺序）。
    #[must_use]
    pub fn all() -> [Self; 13] {
        [
            Self::ReadInput,
            Self::CommitOutput,
            Self::Poseidon,
            Self::Sha256,
            Self::EcdsaVerify,
            Self::EmitEvent,
            Self::Log,
            Self::Panic,
            Self::GetRandomness,
            Self::ReadState,
            Self::Keccak256,
            Self::Modexp,
            Self::MerkleVerify,
        ]
    }
```

#### 2.4 SyscallRegistry 数组 10 → 13 (L289)

```rust
pub struct SyscallRegistry {
    /// 13 个 syscall 实现，index = SyscallId as usize - 1。
    syscalls: [Option<Box<dyn Syscall>>; 13],
}
```

#### 2.5 Debug impl 新增 11/12/13 分支 (L298-310)

在 `10 => "ReadState"` 后新增：

```rust
                11 => "Keccak256",
                12 => "Modexp",
                13 => "MerkleVerify",
```

#### 2.6 测试更新

- `test_from_u32_all_valid_ids` (L406-423): 新增 `(0x0B, SyscallId::Keccak256)`, `(0x0C, SyscallId::Modexp)`, `(0x0D, SyscallId::MerkleVerify)`
- `test_from_u32_invalid_ids` (L428-441): `invalid_ids` 改为 `[0x00u32, 0x0E, 0xFF, 0x100, u32::MAX]`（0x0B/0x0C/0x0D 不再非法）
- `test_syscall_id_as_u32` (L446+): 新增 `assert_eq!(SyscallId::Keccak256 as u32, 0x0B)` 等 3 行
- `test_all_returns_ten_syscalls`: 重命名为 `test_all_returns_thirteen_syscalls`，断言 `len() == 13`
- `test_syscall_registry_dispatch_invalid_id` (L530+): 将测试 0x0B 返回错误的用例改为 0x0E
- 注释 L5 "10 个 syscall ID 枚举" → "13 个 syscall ID 枚举"
- 注释 L34 "10 个 ZKVM Syscall" → "13 个 ZKVM Syscall"
- 注释 L106 "10 个 syscall" → "13 个 syscall"
- 注释 L286 "10 个 syscall" → "13 个 syscall"
- 注释 L327 "10 个 syscall" → "13 个 syscall"

### Step 3: 修改 `syscalls/gas.rs`

**文件**: `poker_zkvm/src/syscalls/gas.rs`

#### 3.1 新增 5 个 gas 常量 (在 L53 `GAS_ZKVM_READ_STATE_PER_SLOT` 后)

```rust
/// `keccak256` 每字节 gas（absorb 阶段）。
pub const GAS_ZKVM_KECCAK256_PER_BYTE: u64 = 2;

/// `keccak256` 每轮 gas（Keccak-f[1600] 置换，24 轮）。
pub const GAS_ZKVM_KECCAK256_PER_ROUND: u64 = 10_000;

/// `modexp` 基础 gas。
pub const GAS_ZKVM_MODEXP_BASE: u64 = 50_000;

/// `modexp` 每指数位 gas。
pub const GAS_ZKVM_MODEXP_PER_BIT: u64 = 600;

/// `merkle_verify` 每层路径 gas。
pub const GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL: u64 = 100;
```

#### 3.2 SyscallGasArgs 新增字段 (L62-67)

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct SyscallGasArgs {
    /// 输入长度（字节）— 用于 PER_BYTE / PER_BLOCK 计算。
    pub input_len: u32,
    /// slot 数量 — 用于 `read_state` 的 PER_SLOT 计算。
    pub num_slots: u32,
    /// 指数位数 — 用于 `modexp` 的 PER_BIT 计算。
    pub num_bits: u32,
    /// Merkle 树深度 — 用于 `merkle_verify` 的 PER_LEVEL 计算。
    pub depth: u32,
}
```

#### 3.3 syscall_gas 新增 3 个分支 (L86-104)

在 `SyscallId::ReadState => ...` 后新增：

```rust
        SyscallId::Keccak256 => {
            GAS_ZKVM_KECCAK256_PER_ROUND * 24 + GAS_ZKVM_KECCAK256_PER_BYTE * args.input_len as u64
        }
        SyscallId::Modexp => {
            GAS_ZKVM_MODEXP_BASE + GAS_ZKVM_MODEXP_PER_BIT * args.num_bits as u64
        }
        SyscallId::MerkleVerify => {
            GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL * args.depth as u64
        }
```

#### 3.4 测试更新

- `test_gas_constants_values` (L113-127): 新增 5 个常量断言
- `test_fixed_gas_syscalls` (L132-139): 不变（3 个新 syscall 不是固定 gas）
- 新增 `test_keccak256_gas_calculation`: 验证 `PER_ROUND * 24 + PER_BYTE * input_len`
- 新增 `test_modexp_gas_calculation`: 验证 `BASE + PER_BIT * num_bits`
- 新增 `test_merkle_verify_gas_calculation`: 验证 `PER_LEVEL * depth`
- `test_all_syscalls_have_gas` (L224-230): 已自动覆盖（`SyscallId::all()` 返回 13 个），需确认 `args` 包含 `num_bits` 和 `depth`

### Step 4: 修改 `precompiles/mod.rs` 测试

**文件**: `poker_zkvm/src/precompiles/mod.rs`

#### 4.1 `test_phase10_registry_full` (L341-369)

注册 3 个新预编译，总数 4 → 7：

```rust
    fn test_phase10_registry_full() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(poseidon::PoseidonCircuit::new()));
        registry.register(Box::new(sha256::Sha256Circuit::new()));
        registry.register(Box::new(ecdsa::EcdsaVerifyCircuit::new()));
        registry.register(Box::new(zk_shuffle::ZkShuffleCcsCircuit::new()));
        registry.register(Box::new(keccak256::Keccak256Circuit::new()));
        registry.register(Box::new(modexp::ModexpCircuit::new()));
        registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));

        assert_eq!(registry.len(), 7, "应有 7 个预编译电路");

        // ... 保留现有 4 个断言 ...

        // Keccak256 (MVP)
        let keccak = registry.get("keccak256").expect("应找到 keccak256");
        assert_eq!(keccak.gas_cost(), 10_000);

        // Modexp (MVP)
        let modexp = registry.get("modexp").expect("应找到 modexp");
        assert_eq!(modexp.gas_cost(), 50_000);

        // MerkleVerify (MVP)
        let merkle = registry.get("merkle_verify").expect("应找到 merkle_verify");
        assert_eq!(merkle.gas_cost(), 100);
    }
```

#### 4.2 `test_phase10_all_implement_both_traits` (L373-393)

新增 3 个 trait 检查：

```rust
        // Keccak256
        let keccak = keccak256::Keccak256Circuit::new();
        let _: &dyn PrecompileCircuit = &keccak;
        let _: &dyn CcsCircuit = &keccak;

        // Modexp
        let modexp = modexp::ModexpCircuit::new();
        let _: &dyn PrecompileCircuit = &modexp;
        let _: &dyn CcsCircuit = &modexp;

        // MerkleVerify
        let merkle = merkle_verify::MerkleVerifyCircuit::new();
        let _: &dyn PrecompileCircuit = &merkle;
        let _: &dyn CcsCircuit = &merkle;
```

#### 4.3 `test_phase10_gas_costs_reasonable` (L397-419)

`cases` 数组新增 3 项，注册表新增 3 个：

```rust
        let cases = [
            ("poseidon", 200u64, 1_000u64),
            ("sha256", 25_000, 100_000),
            ("ecdsa_verify", 100_000, 200_000),
            ("zk_shuffle", 0, 1),
            ("keccak256", 5_000, 15_000),       // MVP = 10_000
            ("modexp", 10_000, 100_000),        // MVP = 50_000
            ("merkle_verify", 1, 1_000),        // MVP = 100
        ];

        let mut registry = PrecompileRegistry::new();
        // ... 4 个现有注册 ...
        registry.register(Box::new(keccak256::Keccak256Circuit::new()));
        registry.register(Box::new(modexp::ModexpCircuit::new()));
        registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));
```

### Step 5: 全量验证

按以下顺序执行验证：

1. **keccak256 单元测试**:
   ```bash
   cargo test -p poker_zkvm --lib precompiles::keccak256 -- --nocapture
   ```

2. **modexp 单元测试**:
   ```bash
   cargo test -p poker_zkvm --lib precompiles::modexp -- --nocapture
   ```

3. **merkle_verify 单元测试**:
   ```bash
   cargo test -p poker_zkvm --lib precompiles::merkle_verify -- --nocapture
   ```

4. **预编译注册表测试**:
   ```bash
   cargo test -p poker_zkvm --lib precompiles::tests::test_phase10 -- --nocapture
   ```

5. **syscall gas + mod 测试**:
   ```bash
   cargo test -p poker_zkvm --lib syscalls::gas -- --nocapture
   cargo test -p poker_zkvm --lib syscalls::tests -- --nocapture
   ```

6. **clippy 检查**:
   ```bash
   cargo clippy -p poker_zkvm --all-features -- -D warnings
   ```

7. **全量回归**:
   ```bash
   cargo test -p poker_zkvm --lib
   ```

8. **ignored 测试（release 模式）**:
   ```bash
   cargo test -p poker_zkvm --lib --release -- --ignored precompiles::keccak256 --nocapture
   ```

## Assumptions & Decisions

### 假设
1. "推进下一阶段" 指完成 Phase I Batch 1（I-4 注册集成），而非开始 Phase J/K
2. keccak256("abc") 测试在 bit_not 修复后应通过（host 实现静态分析正确）
3. host syscall 实现不在本次范围（Phase I 聚焦预编译电路 CCS，host 执行是独立关注点）

### 决策
1. **gas 公式**: Keccak256 = `PER_ROUND * 24 + PER_BYTE * input_len`（24 轮置换 + absorb 字节成本）
2. **SyscallGasArgs 扩展**: 新增 `num_bits` 和 `depth` 字段（u32，Default = 0），向后兼容
3. **数组大小 10 → 13**: SyscallRegistry.syscalls 数组扩展为 13，新增 3 个槽位为 None（无 host 实现）
4. **不修改 host.rs**: `create_full_registry()` 仍注册 10 个 host syscall，新增 3 个 ID 的 dispatch 返回 "not registered"（正确行为）
5. **测试重命名**: `test_all_returns_ten_syscalls` → `test_all_returns_thirteen_syscalls`

### 未选择方案
- **方案 A（未选）**: 同时实现 host syscall（Keccak256Syscall/ModexpSyscall/MerkleVerifySyscall）— 工作量大，且 Phase I 聚焦预编译电路
- **方案 B（未选）**: 将 ed25519/bn254/bls12-381 也纳入本次 — 属于 Batch 2，本次不做
