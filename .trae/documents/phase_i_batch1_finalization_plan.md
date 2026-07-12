# Phase I Batch 1 — Finalization Plan（bit_not 修复 + I-4 注册集成 + 全量验证）

## Summary

完成 Phase I Batch 1 的剩余工作：(1) 修复 keccak256.rs 中 `bit_not` 函数的约束错误（导致所有 keccak 测试失败）；(2) 实现 I-4 注册集成（SyscallId 0x0B-0x0D + 5 个 gas 常量 + SyscallGasArgs 扩展 + PrecompileRegistry 测试注册）；(3) 全量验证（cargo test + clippy）。

**依据**：`phase_i_batch1_completion_plan.md`（用户已批准）。I-2 modexp 和 I-1 merkle_verify 已完成，I-3 keccak256 文件已写但有 1 个关键 bug，I-4 未开始。

## Current State Analysis

### 实际代码状态

| 子任务 | 文件 | 状态 |
|--------|------|------|
| I-1 merkle_verify | `precompiles/merkle_verify.rs` | ✅ 完成，11 测试通过 |
| I-2 modexp | `precompiles/modexp.rs` | ✅ 完成，9 测试通过 |
| I-3 keccak256 | `precompiles/keccak256.rs` | ⚠️ 文件完整（~900行），但 `bit_not` 约束错误，测试未验证 |
| I-4 注册 | `syscalls/mod.rs` / `gas.rs` / `precompiles/mod.rs` | ❌ 未开始 |

### keccak256.rs `bit_not` Bug 详情

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/keccak256.rs`
**位置**：Line 229

**当前（错误）代码**：
```rust
fn bit_not(&mut self, a: &[usize]) -> Vec<usize> {
    let one = Fr::one();
    let mut result = Vec::with_capacity(a.len());
    for &bit in a {
        let not_val = one.sub(&self.get_val(bit));
        let not_bit = self.alloc(not_val);
        let row = self.ccs.alloc_row();
        self.ccs.add_linear(row, &[(bit, Fr::one()), (not_bit, Fr::one().neg())]);
        // ↑ 约束 bit - not_bit = 0，即 bit = not_bit（错误！）
        result.push(not_bit);
    }
    result
}
```

**问题分析**：
- 约束 `(bit, +1) + (not_bit, -1) = 0` 即 `bit - not_bit = 0`，即 `bit = not_bit`
- 但 witness 设为 `not_bit = 1 - bit`
- 两者仅当 `bit = 0.5` 时同时成立（非合法 bit 值）
- 结果：所有使用 `bit_not` 的 Chi 步约束永远不满足，keccak 测试全部失败

**修复**：约束应改为 `bit + not_bit - 1 = 0`（即 `not_bit = 1 - bit`），利用 var 0 = 常数 1：
```rust
self.ccs.add_linear(row, &[(bit, Fr::one()), (not_bit, Fr::one()), (0, Fr::one().neg())]);
```

### 已验证的基础设施

- `CcsBuilder::add_linear(row, terms)` 每个 term 生成 1 个矩阵 + 1 个 subset
- Var 0 = 常数 1（`CcsBuilder::new()` 保留，witness[0] = `Fr::one()`）
- `bit_decompose_64` 已含 `bit_check`，所有 lane bit 均被约束为合法 bit
- `bit_xor` 约束 `a + b - 2*a*b - out = 0`（正确）
- `bit_and` 约束 `a * b = ab`（正确）
- `bit_rotr` 纯 witness 重排（`result[i] = a[(i+offset)%n]` = ROTR by offset），0 约束（正确）
- `SyscallId` 枚举当前 10 个变体（0x01-0x0A），`#[repr(u32)]`
- `SyscallRegistry.syscalls: [Option<...>; 10]`，`register` 用 `id as usize - 1` 索引
- `SyscallGasArgs` 当前 2 字段（`input_len`, `num_slots`）
- `test_phase10_registry_full` 当前注册 4 个预编译

## Proposed Changes

### Step 1: 修复 keccak256.rs `bit_not` 约束（I-3 完成）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/keccak256.rs`
**位置**：Line 229

**修改**：

将：
```rust
self.ccs.add_linear(row, &[(bit, Fr::one()), (not_bit, Fr::one().neg())]);
```

改为：
```rust
self.ccs.add_linear(row, &[(bit, Fr::one()), (not_bit, Fr::one()), (0, Fr::one().neg())]);
```

**同时清理注释**：删除 Line 230-240 的调试注释（"Wait, this constrains..." 等），保留简洁的文档注释。

**约束语义验证**：
- 3 个 term：`(bit, +1)`, `(not_bit, +1)`, `(0, -1)`
- 生成 3 个矩阵 M_bit, M_not_bit, M_var0（各含 row 行单元素）
- 3 个 subset：`{M_bit}` coeff=+1, `{M_not_bit}` coeff=+1, `{M_var0}` coeff=-1
- CCS 求值：`+1*z[bit] + 1*z[not_bit] + (-1)*z[0] = bit + not_bit - 1 = 0` ✓

**验证**：
```bash
cargo test -p poker_zkvm --lib precompiles::keccak256
```
预期：6 个非 ignore 测试通过，2 个 `#[ignore]` Full 模式测试需 release 手动运行。

### Step 2: 修改 `syscalls/mod.rs`（I-4a — SyscallId 扩展）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs`

#### 2.1 文档注释表格更新（L9-20）

在表格末尾新增 3 行：
```
//! | 0x0B | `keccak256` | (ptr, len, out_ptr) | Keccak-256 哈希 |
//! | 0x0C | `modexp` | (base_ptr, exp_ptr, mod_ptr, out_ptr, num_bits) | 大数模幂 |
//! | 0x0D | `merkle_verify` | (leaf_ptr, root_ptr, path_ptr, depth) | Merkle 路径验证 |
```

#### 2.2 SyscallId 枚举新增 3 个变体（L82 后）

```rust
    /// `zkvm_keccak256(ptr, len, out_ptr)` — Keccak-256 哈希。
    Keccak256 = 0x0B,
    /// `zkvm_modexp(base_ptr, exp_ptr, mod_ptr, out_ptr, num_bits)` — 大数模幂。
    Modexp = 0x0C,
    /// `zkvm_merkle_verify(leaf_ptr, root_ptr, path_ptr, depth)` — Merkle 路径验证。
    MerkleVerify = 0x0D,
```

#### 2.3 `from_u32()` 新增 3 个分支（L101 后）

```rust
            0x0B => Ok(Self::Keccak256),
            0x0C => Ok(Self::Modexp),
            0x0D => Ok(Self::MerkleVerify),
```

#### 2.4 `all()` 改为 `[Self; 13]`（L108-121）

```rust
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

#### 2.5 `SyscallRegistry.syscalls` 数组扩展（L289）

```rust
pub struct SyscallRegistry {
    syscalls: [Option<Box<dyn Syscall>>; 13],
}
```

#### 2.6 `Debug` 实现 match 扩展（L298-310）

在 `10 => "ReadState"` 后新增：
```rust
                11 => "Keccak256",
                12 => "Modexp",
                13 => "MerkleVerify",
```

将 `_ => "Unknown"` 保持不变。

#### 2.7 测试更新

**`test_from_u32_invalid_ids`**（L428-441）：
- 将 `invalid_ids` 从 `[0x00, 0x0B, 0x0C, 0xFF, 0x100, u32::MAX]` 改为 `[0x00, 0x0E, 0x0F, 0xFF, 0x100, u32::MAX]`

**`test_syscall_id_as_u32`**（L446-457）：
- 新增 3 个断言：
```rust
    assert_eq!(SyscallId::Keccak256 as u32, 0x0B);
    assert_eq!(SyscallId::Modexp as u32, 0x0C);
    assert_eq!(SyscallId::MerkleVerify as u32, 0x0D);
```

**`test_all_returns_ten_syscalls`** → 重命名为 `test_all_returns_thirteen_syscalls`（L462-469）：
- `assert_eq!(all.len(), 13, "应有 13 个 syscall")`

**`test_syscall_registry_default`**（L640-645）：
- 注意：`registry.len()` 返回已注册数量。`host::create_full_registry()` 仍只注册 10 个 host syscall（新 3 个无 host 实现），所以 `len()` 仍为 10。
- 保持 `assert_eq!(registry.len(), 10)` 不变。
- 如果需要，新增测试验证 0x0B-0x0D 在 default registry 中为 "not registered"。

**`test_syscall_registry_dispatch_invalid_id`**（L544-553）：
- 将 `0x0B` 替换为 `0x0E`（真正非法的 ID）

**新增 `test_from_u32_new_syscalls`**：
```rust
#[test]
fn test_from_u32_new_syscalls() {
    assert_eq!(SyscallId::from_u32(0x0B).unwrap(), SyscallId::Keccak256);
    assert_eq!(SyscallId::from_u32(0x0C).unwrap(), SyscallId::Modexp);
    assert_eq!(SyscallId::from_u32(0x0D).unwrap(), SyscallId::MerkleVerify);
}
```

### Step 3: 修改 `syscalls/gas.rs`（I-4b — Gas 常量扩展）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas.rs`

#### 3.1 新增 5 个 gas 常量（L53 后）

```rust
/// `keccak256` 每字节 gas。
pub const GAS_ZKVM_KECCAK256_PER_BYTE: u64 = 2;
/// `keccak256` 每轮 gas（MVP 单轮）。
pub const GAS_ZKVM_KECCAK256_PER_ROUND: u64 = 10_000;
/// `modexp` 基础 gas。
pub const GAS_ZKVM_MODEXP_BASE: u64 = 50_000;
/// `modexp` 每位指数 gas。
pub const GAS_ZKVM_MODEXP_PER_BIT: u64 = 600;
/// `merkle_verify` 每层 gas。
pub const GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL: u64 = 100;
```

#### 3.2 `SyscallGasArgs` 新增字段（L62-67）

```rust
pub struct SyscallGasArgs {
    pub input_len: u32,
    pub num_slots: u32,
    /// modexp 指数位数。
    pub num_bits: u32,
    /// merkle_verify 路径深度。
    pub depth: u32,
}
```

#### 3.3 `syscall_gas()` 新增 3 个分支（L102 前）

```rust
        SyscallId::Keccak256 => GAS_ZKVM_KECCAK256_PER_BYTE * args.input_len as u64,
        SyscallId::Modexp => GAS_ZKVM_MODEXP_BASE + GAS_ZKVM_MODEXP_PER_BIT * args.num_bits as u64,
        SyscallId::MerkleVerify => GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL * args.depth as u64,
```

#### 3.4 文档注释公式表更新（L73-84）

新增 3 行：
```
/// | `Keccak256` | `PER_BYTE * input_len` |
/// | `Modexp` | `BASE + PER_BIT * num_bits` |
/// | `MerkleVerify` | `PER_LEVEL * depth` |
```

#### 3.5 测试更新

**`test_gas_constants_values`**（L113-127）：
- 新增 5 个常量断言：
```rust
    assert_eq!(GAS_ZKVM_KECCAK256_PER_BYTE, 2);
    assert_eq!(GAS_ZKVM_KECCAK256_PER_ROUND, 10_000);
    assert_eq!(GAS_ZKVM_MODEXP_BASE, 50_000);
    assert_eq!(GAS_ZKVM_MODEXP_PER_BIT, 600);
    assert_eq!(GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL, 100);
```

**`test_all_syscalls_have_gas`**（L224-230）：
- 更新 args 初始化：
```rust
    let args = SyscallGasArgs { input_len: 32, num_slots: 1, num_bits: 8, depth: 3 };
```

**新增 `test_new_syscall_gas_calculations`**：
```rust
#[test]
fn test_new_syscall_gas_calculations() {
    // Keccak256: PER_BYTE * input_len
    let args = SyscallGasArgs { input_len: 100, ..Default::default() };
    assert_eq!(syscall_gas(SyscallId::Keccak256, &args), 200);

    // Modexp: BASE + PER_BIT * num_bits
    let args = SyscallGasArgs { num_bits: 8, ..Default::default() };
    assert_eq!(syscall_gas(SyscallId::Modexp, &args), 50_000 + 600 * 8);

    // MerkleVerify: PER_LEVEL * depth
    let args = SyscallGasArgs { depth: 10, ..Default::default() };
    assert_eq!(syscall_gas(SyscallId::MerkleVerify, &args), 1000);
}
```

### Step 4: 修改 `precompiles/mod.rs`（I-4c — 注册新预编译到测试）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs`

#### 4.1 `test_phase10_registry_full`（L341-369）

在现有 4 个注册后新增 3 个：
```rust
        registry.register(Box::new(keccak256::Keccak256Circuit::new()));
        registry.register(Box::new(modexp::ModexpCircuit::new()));
        registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));
```

更新断言：
```rust
        assert_eq!(registry.len(), 7, "应有 7 个预编译电路");
```

新增 3 个电路的断言：
```rust
        // Keccak256 (MVP)
        let keccak = registry.get("keccak256").expect("应找到 keccak256");
        assert_eq!(keccak.gas_cost(), 10_000);

        // Modexp (MVP)
        let modexp = registry.get("modexp").expect("应找到 modexp");
        assert_eq!(modexp.gas_cost(), 50_000);

        // MerkleVerify (MVP)
        let merkle = registry.get("merkle_verify").expect("应找到 merkle_verify");
        assert_eq!(merkle.gas_cost(), 100);
```

#### 4.2 `test_phase10_all_implement_both_traits`（L373-393）

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

#### 4.3 `test_phase10_gas_costs_reasonable`（L397-419）

新增 3 个注册 + 3 个 case：
```rust
        registry.register(Box::new(keccak256::Keccak256Circuit::new()));
        registry.register(Box::new(modexp::ModexpCircuit::new()));
        registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));
```

cases 数组新增：
```rust
        ("keccak256", 5_000, 50_000),
        ("modexp", 10_000, 100_000),
        ("merkle_verify", 50, 1_000),
```

### Step 5: 全量验证

```bash
# 1. keccak256 单元测试（含 bit_not 修复验证）
cargo test -p poker_zkvm --lib precompiles::keccak256

# 2. 全部预编译测试
cargo test -p poker_zkvm --lib precompiles

# 3. syscall gas + mod 测试
cargo test -p poker_zkvm --lib syscalls::gas
cargo test -p poker_zkvm --lib syscalls::mod

# 4. clippy（无警告）
cargo clippy -p poker_zkvm --lib -- -D warnings

# 5. 全量回归（不含 ignored）
cargo test -p poker_zkvm --lib

# 6. （可选）release 模式运行 keccak Full 测试
cargo test -p poker_zkvm --lib --release -- --ignored precompiles::keccak256
```

## Assumptions & Decisions

| 决策点 | 选择 | 理由 |
|--------|------|------|
| bit_not 修复方式 | 添加 `(0, Fr::one().neg())` term | 利用 var 0 = 常数 1，约束 `bit + not_bit - 1 = 0` |
| SyscallRegistry 数组大小 | 10 → 13 | 新增 3 个 SyscallId 变体 |
| host::create_full_registry 不变 | 仍只注册 10 个 | 新 3 个无 host 实现，仅电路层完成 |
| SyscallGasArgs 扩展 | 新增 `num_bits` + `depth` | modexp/merkle 需要参数化 gas |
| keccak256 Full 测试 | 保持 `#[ignore]` | 192K 约束需 release 模式 |
| RC bits 缺少 bit_check | 暂不修复 | 诚实 witness 下测试可通过；soundness hardening 留待后续 |
| 预编译 gas_cost 检查 | 仅检查 MVP 模式 gas | Full 模式 gas 取决于参数（num_bits/depth/rounds） |

## Implementation Order

1. **Step 1**: 修复 keccak256.rs `bit_not` 约束（1 行修改 + 注释清理）
2. **Step 1 验证**: `cargo test -p poker_zkvm --lib precompiles::keccak256` 全绿
3. **Step 2**: 修改 `syscalls/mod.rs`（SyscallId 0x0B-0x0D + from_u32 + all + 数组扩展 + Debug + 测试更新）
4. **Step 2 验证**: `cargo test -p poker_zkvm --lib syscalls::mod` 全绿
5. **Step 3**: 修改 `syscalls/gas.rs`（5 个常量 + SyscallGasArgs 扩展 + syscall_gas 分支 + 测试更新）
6. **Step 3 验证**: `cargo test -p poker_zkvm --lib syscalls::gas` 全绿
7. **Step 4**: 修改 `precompiles/mod.rs`（注册 3 个新预编译到 3 个测试）
8. **Step 4 验证**: `cargo test -p poker_zkvm --lib precompiles` 全绿
9. **Step 5**: 全量验证（clippy + cargo test --lib）

## Out of Scope

- keccak256 RC bits 添加 bit_check（soundness hardening，留待后续）
- keccak256 Full 模式多块吸收（当前仅支持单块 ≤ 136 bytes）
- 新 SyscallId 的 host 实现（host::create_full_registry 不变）
- bn254 pairing / ed25519 / bls12-381（Phase I Batch 2+）
- 现有 4 个预编译（poseidon/sha256/ecdsa/zk_shuffle）修改
- 既有 10 个 SyscallId 修改（仅新增）
