# Phase I Batch 1 — 实现计划（merkle_verify + modexp + keccak256）

## Summary

将 poker_zkvm 预编译覆盖率从 3/8 提升到 6/8，新增 3 个低风险预编译：`merkle_verify`、`modexp`、`keccak256`。每个预编译实现 MVP + Full 双模式 + 完整测试闭环。同时扩展 SyscallId（0x0B-0x0D）和 gas 常量。

**依据**：已有的 `phase_i_batch1_execution_plan.md`（用户已批准）。本文件是基于代码库探索验证后的细化实现计划。

## Current State Analysis

### 已验证的基础设施

| 组件 | 位置 | 状态 |
|------|------|------|
| `PrecompileCircuit` trait | `precompiles/mod.rs:L47-65` | `name/num_variables/build_ccs/assign_witness/gas_cost` |
| `CcsCircuit` trait | `precompiles/mod.rs:L131-151` | `name/num_matrices/to_ccs_instance` |
| `CcsBuilder` | `precompiles/ccs_builder.rs` | `alloc_var/alloc_row/add_linear/add_multiplication/add_bit_check/build` |
| `bit_ops` | `precompiles/bit_ops.rs` | 全部 `pub`：`bit_decompose(64-bit)/bit_xor/bit_and/bit_or/bit_not/bit_rotr/bit_recompose` |
| `NonNativeBuilder` | `precompiles/non_native.rs:L274` | `pub ccs: CcsBuilder` + `pub witness: Vec<Fr>`，`mul_mod/add_mod/sub_mod/from_u256/element_to_u256/assert_lt` |
| `NonNativeElement` | `precompiles/non_native.rs:L264` | `pub limbs: [usize; 4]`（crate 内可访问） |
| `host_mul_mod` | `precompiles/non_native.rs:L179` | `pub(crate)` — 可直接复用 |
| `host_pow_mod` | `precompiles/ecdsa.rs:L464` | **私有**（测试模块内）— 需提取到 `non_native.rs` |
| `Ccs::new` | `ccs/mod.rs:L234` | `(num_vars, matrices, subsets, coeffs)` |
| `SyscallId` | `syscalls/mod.rs:L62-83` | 10 个变体 0x01-0x0A，`#[repr(u32)]` |
| `syscall_gas` | `syscalls/gas.rs:L86` | match SyscallId → u64 |

### 现有预编译模式（sha256.rs 为模板）

```
struct XxxCircuit { full_mode: bool, ... }
impl XxxCircuit {
    fn new() -> Self  // MVP
    fn new_full() -> Self  // Full
    fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>, Output), ZkvmError>
}
impl PrecompileCircuit for XxxCircuit { ... }  // build_ccs + assign_witness
impl CcsCircuit for XxxCircuit { ... }  // to_ccs_instance
```

### 依赖状况（Cargo.toml）

- **可用**：ark-bn254, sha2, secp256k1, blake2, ark-crypto-primitives
- **不可用**：sha3, curve25519-dalek, ark-bls12-381
- **决策**：keccak256 自实现，不加 sha3 依赖

## Proposed Changes

### I-1: 新增 `precompiles/merkle_verify.rs`（最低复杂度）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/merkle_verify.rs`

**结构体**：
```rust
#[derive(Debug, Clone)]
pub struct MerkleVerifyCircuit {
    depth: usize,      // Merkle 树深度
    full_mode: bool,
}
```

**MVP 模式**（单层验证，depth=1）：
- 哈希函数：`H(left, right) = left * 2 + right`（1 个 multiplication-free linear 约束）
  - 选择 `*2` 而非 `+` 区分左右子节点：`parent - left*2 - right = 0`
- witness：`[1, left, right, parent]`（4 变量）
- 输入：`[left, right, parent]`（3 个 Fr）
- CCS 结构：3 矩阵（M_parent[col=3,coeff=1], M_left[col=1,coeff=2], M_right[col=2,coeff=-1]），1 subset `[0,1,2]`，1 coeff `Fr::one()`
- gas：`GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL * 1 = 100`

**Full 模式**（深度可配置，`new_full_with_depth(n)`）：
- 每层逻辑：
  1. `direction_bit`（1 bit_check 约束，0=左/1=右）
  2. conditional select：
     - `H_left = current * 2 + sibling`（direction=0 时）
     - `H_right = sibling * 2 + current`（direction=1 时）
     - `parent = (1-direction) * H_left + direction * H_right`
  3. 每层约束：2 multiplication（direction*H_right, (1-direction)*H_left）+ 2 linear（H_left, H_right）+ 1 linear（parent 合并）
- 输入：`[leaf, root, sibling_0..sibling_{d-1}, direction_bits]`（2 + d + d 个 Fr）
- gas：`GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL * depth`

**实现要点**：
- MVP 用直接 `CcsBuilder` 构建（参考 mod.rs 的 MockMulCircuit）
- Full 用 `CcsBuilder` + 手动 witness 跟踪（类似 sha256 的 FullBuilder 但更简单，因为无需 bit_decompose 整个值，只需 1-bit direction）

**测试**（5 个）：
1. `test_merkle_mvp_satisfied` — `H(3, 4) = 10`，验证通过
2. `test_merkle_mvp_tampered_parent` — parent=11 时不满足
3. `test_merkle_full_depth3_satisfied` — 3 层路径验证通过
4. `test_merkle_full_tampered_leaf` — 篡改 leaf 后不满足
5. `test_merkle_full_tampered_sibling` — 篡改 sibling 后不满足

### I-2: 新增 `precompiles/modexp.rs`（中等复杂度）

**前置修改**：`precompiles/non_native.rs`

提取 `host_pow_mod` 从 `ecdsa.rs:L464` 到 `non_native.rs`：
```rust
/// 模幂：base^exp mod modulus（square-and-multiply，256-bit）
pub(crate) fn host_pow_mod(base: &[u64; 4], exp: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    // 从 ecdsa.rs 原样迁移
}
```

同时更新 `ecdsa.rs`：删除私有 `host_pow_mod`，改为 `use crate::precompiles::non_native::host_pow_mod;`

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/modexp.rs`

**结构体**：
```rust
#[derive(Debug, Clone)]
pub struct ModexpCircuit {
    num_bits: usize,   // 指数位数
    full_mode: bool,
}
```

**MVP 模式**（单次模乘，验证 `base * exp = result mod modulus`）：
- 使用 `NonNativeBuilder::mul_mod(base, exp, modulus)` 生成约束
- 输入：`[base(4 limbs), exp(4 limbs), modulus(4 limbs), result(4 limbs)]`（16 Fr）
- 实际上 MVP 只验证 `base * exp ≡ result (mod modulus)`，不真正做幂运算
- gas：`GAS_ZKVM_MODEXP_BASE = 50_000`

**Full 模式**（square-and-multiply，`new_full_with_bits(n)`）：
- Bit-decompose exponent（n bits，复用 `bit_ops::bit_decompose`）
- 循环 i = n-1 down to 0：
  1. `acc = acc² mod modulus`（`mul_mod(acc, acc, modulus)`）
  2. `bit_i = exponent_bits[i]`
  3. `temp = acc * base mod modulus`（`mul_mod(acc, base, modulus)`）
  4. `acc = bit_i ? temp : acc`（conditional select：`acc = bit_i * temp + (1-bit_i) * acc`）
- 最终 `assert_equal(acc, result)`
- 约束数：n × (2 mul_mod + 1 select) ≈ n × 2800
- 输入：`[base(4), exponent(4), modulus(4), result(4)]`（16 Fr）
- gas：`GAS_ZKVM_MODEXP_PER_BIT * num_bits + GAS_ZKVM_MODEXP_BASE`

**Conditional select 实现**（电路内）：
```
// bit ∈ {0, 1}, 已 bit_check
// temp = mul_mod(acc, base, modulus)
// result = bit * temp + (1 - bit) * acc
// 需要 2 multiplication 约束（bit*temp, (1-bit)*acc）+ 1 linear
```

**测试**（5 个）：
1. `test_modexp_mvp_satisfied` — `2 * 3 = 6 mod 7`
2. `test_modexp_mvp_tampered_result` — result=5 时不满足
3. `test_modexp_full_8bit_satisfied` — `2^10 = 1024 mod 1000000007`（8-bit exponent）
4. `test_modexp_full_tampered_base` — 篡改 base 后不满足
5. `test_host_pow_mod` — host 端 `host_pow_mod(2, 10, 1000000007) == 1024`

### I-3: 新增 `precompiles/keccak256.rs`（最高复杂度）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/keccak256.rs`

**结构体**：
```rust
#[derive(Debug, Clone)]
pub struct Keccak256Circuit {
    full_mode: bool,
}
```

**Keccak-f[1600] 算法**：
- 状态：25 个 64-bit lanes（5×5 矩阵）
- 24 轮，每轮：theta + rho + pi + chi + iota

**MVP 模式**（单轮置换）：
- 状态：25 个 Fr 变量（每个 64-bit 值）
- 单轮 5 步：
  1. **theta**：`C[x] = A[x,0] XOR A[x,1] XOR ... XOR A[x,4]`；`D[x] = C[x-1] XOR rot(C[x+1], 1)`；`A[x,y] ^= D[x]`
     - 约束：5 × (4 xor + 1 rotr + 1 xor) = 5 × 5 bit-ops × 64 bits
  2. **rho**：`A[x,y] = rot(A[x,y], r[x,y])`（旋转常量表，0 约束）
  3. **pi**：`A[y, 2x+3y] = A[x,y]`（置换，0 约束）
  4. **chi**：`A'[x,y] = A[x,y] XOR (NOT A[x+1,y]) AND A[x+2,y]`
     - 约束：25 × (1 not + 1 and + 1 xor) × 64 bits
  5. **iota**：`A'[0,0] = A[0,0] XOR RC[round]`（1 xor × 64 bits）
- 使用 `bit_ops::bit_decompose(builder, val_col, 64)` 分解每个 lane
- gas：`GAS_ZKVM_KECCAK256_PER_ROUND = 10_000`

**Full 模式**（24 轮 + padding）：
- `Keccak256Circuit::new_full()` — 24 轮完整 Keccak-f[1600]
- 输入吸收 + 24 轮置换 + 挤出 32 字节
- 约束数：~24 × 8000 ≈ 192,000（与 SHA-256 Full 同量级）
- gas：`GAS_ZKVM_KECCAK256_PER_BYTE * input_len`（默认 input_len=32 时 64 gas）

**Keccak 常量表**：
- **rho 旋转常量** `RHO_OFFSETS[5][5]`（24 个非零值，A[0][0]=0）
- **iota 轮常量** `RC[24]`（64-bit，每轮一个）

**Host 端实现**（测试模块内）：
- `host_keccak_f1600(state: &mut [[u64; 5]; 5])` — 24 轮置换（使用 u64 原生运算）
- `host_keccak256(input: &[u8]) -> [u8; 32]` — 完整哈希（padding + absorb + squeeze）
- 用于生成测试向量

**测试**（4 个）：
1. `test_keccak_mvp_single_round` — 单轮置换正确性（对比 host_keccak_f1600 单轮）
2. `test_keccak_full_empty_input` — `keccak256("")` = `0xc5d246...`（已知值）
3. `test_keccak_full_abc` — `keccak256("abc")` = `0x4e0365...`（已知值）
4. `test_keccak_full_tampered_input` — 篡改输入后哈希不匹配

**MVP 实现策略**：
- 使用 `CcsBuilder` + 手动 witness 跟踪（类似 sha256 的 FullBuilder）
- 每个 lane 分解为 64 bit 变量后，theta/rho/pi/chi/iota 全在 bit 域操作
- 最后 `bit_recompose` 回 64-bit lane 变量

### I-4: 注册 + Syscall 集成

**修改 `precompiles/mod.rs`**：
```rust
// L20-27 后添加
pub mod keccak256;
pub mod merkle_verify;
pub mod modexp;
```

在 `test_phase10_registry_full` 测试中注册 3 个新预编译（7 个总数）。

**修改 `syscalls/mod.rs`**：
```rust
pub enum SyscallId {
    // ... 既有 0x01-0x0A ...
    Keccak256 = 0x0B,
    Modexp = 0x0C,
    MerkleVerify = 0x0D,
}
```
- `from_u32()`：添加 0x0B/0x0C/0x0D 分支
- `all()`：返回 `[Self; 13]`（原 10 + 3 新）
- 文档注释表格更新

**修改 `syscalls/gas.rs`**：
```rust
pub const GAS_ZKVM_KECCAK256_PER_BYTE: u64 = 2;
pub const GAS_ZKVM_KECCAK256_PER_ROUND: u64 = 10_000;
pub const GAS_ZKVM_MODEXP_BASE: u64 = 50_000;
pub const GAS_ZKVM_MODEXP_PER_BIT: u64 = 600;
pub const GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL: u64 = 100;
```
- `syscall_gas()` 添加 3 个新分支
- `SyscallGasArgs` 新增 `num_bits: u32` 字段（modexp 用）和 `depth: u32` 字段（merkle 用）
- 更新 `test_all_syscalls_have_gas` 测试
- 更新 `test_gas_constants_values` 测试

## Assumptions & Decisions

| 决策点 | 选择 | 理由 |
|--------|------|------|
| merkle_verify 哈希函数 | `H(l,r) = l*2 + r` | 低风险；Poseidon permutation 未暴露为 pub，复用需重构 poseidon.rs |
| modexp host 函数 | 提取 `host_pow_mod` 到 `non_native.rs` 作为 `pub(crate)` | 避免代码重复；ecdsa.rs 改为 import |
| keccak256 依赖 | 自实现，不加 sha3 crate | 保持依赖最小化；host 端在测试模块实现 |
| SyscallId 扩展 | 新增 0x0B-0x0D | Stage 4 计划明确要求 |
| keccak256 MVP | 单轮置换 | 验证约束结构，Full 模式 24 轮 |
| SyscallGasArgs 扩展 | 新增 `num_bits` + `depth` 字段 | modexp/merkle 需要参数化 gas |
| Full 模式测试 | 256-bit modexp 标记 `#[ignore]` | 避免 CI 超时；手动 release 运行 |

## Verification Steps

```bash
# 1. 单个预编译测试（秒级）
cargo test -p poker_zkvm --lib precompiles::merkle_verify
cargo test -p poker_zkvm --lib precompiles::modexp
cargo test -p poker_zkvm --lib precompiles::keccak256

# 2. 全部预编译测试（秒级）
cargo test -p poker_zkvm --lib precompiles

# 3. syscall gas 测试
cargo test -p poker_zkvm --lib syscalls::gas
cargo test -p poker_zkvm --lib syscalls::mod

# 4. clippy
cargo clippy -p poker_zkvm --lib -- -D warnings

# 5. 全量回归（不含 ignored）
cargo test -p poker_zkvm --lib

# 6. ignored 测试（release 模式，手动）
cargo test -p poker_zkvm --lib --release -- --ignored precompiles::modexp
```

## Implementation Order

1. **I-1**: `merkle_verify.rs`（MVP + Full + 5 测试）
2. **I-2**: `modexp.rs`（提取 `host_pow_mod` + MVP + Full + 5 测试）
3. **I-3**: `keccak256.rs`（host Keccak + MVP 单轮 + Full 24 轮 + 4 测试）
4. **I-4**: 注册 + SyscallId + gas 常量 + 集成测试
5. 验证步骤 1-4（定向测试 + clippy）
6. 验证步骤 5（全量回归）

## Out of Scope

- bn254 pairing（hint-based）— 留待后续批次
- ed25519 — 留待后续批次（需 curve25519-dalek 依赖）
- bls12-381 pairing — 留待后续批次
- 现有 4 个预编译（poseidon/sha256/ecdsa/zk_shuffle）— 不修改
- 既有 10 个 SyscallId — 仅新增，不修改既有
- 既有 gas 常量 — 仅新增，不修改既有
