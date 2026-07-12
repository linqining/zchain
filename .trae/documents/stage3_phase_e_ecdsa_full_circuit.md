# Stage 3 — Phase E：ECDSA 完整验证电路

> **背景**：Phase B（SHA-256 完整电路）已完成，包括 `Ccs::satisfied_by` 行隔离快速路径优化。
> Phase E 是 Stage 3 的最后一个 Phase，实现 secp256k1 上的完整 ECDSA 验签电路。
>
> **参考规格**：`/Users/mac/projects/zchain/.trae/documents/stage3_execution_plan.md` L272-288

## Summary

Phase E 将 ECDSA 电路从 MVP（double-and-add 单步约束，6 变量/7 矩阵/3 行）扩展到完整 secp256k1 验签：验证 `s·R' = z·G + r·P`，其中 `R' = (r, ry)` 且 `ry` 为 prover hint（避免在电路中计算 `s⁻¹`）。

核心挑战：secp256k1 的基域 `p_curve ≈ 2^256` 和标量域 `n ≈ 2^256` 均超过 BN254 Fr（`p ≈ 2^254`），需要非原生域算术（multi-limb 表示 + hint-based 乘法）。

分 4 步执行：
- **E1**：`src/precompiles/non_native.rs` — 非原生域算术（k=4 limbs × 64 bits + hint-based mul_mod）
- **E2**：`src/precompiles/secp256k1_ops.rs` — secp256k1 点运算（Jacobian 坐标点加/倍乘 + 256-bit double-and-add 标量乘）
- **E3**：`src/precompiles/ecdsa.rs` — 扩展为双模式（MVP + 完整 ECDSA verify）
- **E4**：`src/precompiles/mod.rs` — 添加模块声明

## Current State Analysis

### ECDSA MVP 现状（[ecdsa.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/ecdsa.rs)）

- `EcdsaVerifyCircuit { curve: &'static str }`，`new()` 构造
- 6 变量 witness `[1, bit, R, P, bit_P, R_new]`
- 7 行隔离矩阵，3 约束行（bit range check + 条件乘 + 条件加）
- `gas_cost()` = 100,000
- 12 个测试全部通过

### 可用模式（来自 Phase A/B）

1. **CcsBuilder API**（[ccs_builder.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/ccs_builder.rs)）：
   - `alloc_var()` → 从 1 开始（0 = 常数 1）
   - `alloc_row()` → 从 0 开始
   - `add_multiplication(row, a, b, result)` — 3 矩阵 + 2 subsets
   - `add_linear(row, &[(col, coeff)])` — N 矩阵 + N subsets
   - `add_bit_check(row, col)` — 1 矩阵 + 2 subsets
   - `build()` → `Ccs`

2. **FullBuilder 模式**（[sha256.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/sha256.rs) L381+）：
   - 组合 `CcsBuilder` + `witness: Vec<Fr>` 跟踪器
   - `alloc(val)` — 分配变量并设置 witness 值
   - `get_val(idx)` — 获取变量 witness 值
   - 每个操作方法镜像 bit_ops 约束结构，同时计算 witness

3. **双模式模式**（[sha256.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/sha256.rs) L64-108）：
   - `full_mode: bool` 标志
   - `new()` (MVP) + `new_full()` (完整)
   - trait 方法根据 `full_mode` 分派

4. **Ccs::satisfied_by 快速路径**（[ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs) L304-324）：
   - 行隔离矩阵（≤1 entry）→ O(matrices + subsets + num_rows) 快速路径
   - CcsBuilder 生成的矩阵自动满足行隔离条件

### 可用依赖

- `secp256k1 = "0.29"` — 测试中生成有效签名
- `ark-ff`, `ark-ec` — 域元素和曲线运算
- `ark-bn254` — BN254 Fr（电路域）

### ZkvmField trait 可用方法（[field.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/field.rs) L27-80）

`from_u32_with_wrap(v)`, `from_u64(v)`, `to_u32()`, `add`, `sub`, `mul`, `neg`, `inverse`, `zero`, `one`, `is_zero`, `square`, `double`, `to_canonical_bytes`, `from_canonical_bytes`

## Proposed Changes

### E1：创建 `src/precompiles/non_native.rs`

**目标**：在 BN254 Fr 域上模拟 secp256k1 的 256-bit 非原生域算术。

**核心设计**：
- **Limb 表示**：k=4, b=64 bits。每个 256-bit 值表示为 4 个 Fr limb `[l0, l1, l2, l3]`（little-endian，`l0` = 最低 64 bits）
- **Hint-based 乘法**：prover 提供 quotient `q`（4 limbs）和 remainder `r`（4 limbs），电路验证 `a*b = q*modulus + r`（schoolbook 大整数乘法）+ `r < modulus`（范围检查）
- **NonNativeBuilder**（`pub(crate)`）：组合 `CcsBuilder` + `witness: Vec<Fr>`，供 `secp256k1_ops.rs` 和 `ecdsa.rs` 共用

**数据结构**：

```rust
/// secp256k1 常量（[u64; 4] little-endian）
pub const SECP256K1_P_CURVE: [u64; 4];  // 基域模数 p
pub const SECP256K1_N: [u64; 4];         // 标量域模数 n（阶）
pub const SECP256K1_GX: [u64; 4];        // 生成元 G 的 x 坐标
pub const SECP256K1_GY: [u64; 4];        // 生成元 G 的 y 坐标

/// 非原生域元素（4 limbs × 64 bits）
#[derive(Clone)]
pub(crate) struct NonNativeElement {
    /// 4 个 limb 变量索引（little-endian）
    pub limbs: [usize; 4],
}

/// 非原生域构建器（组合 CCS + witness 跟踪）
pub(crate) struct NonNativeBuilder {
    pub ccs: CcsBuilder,
    pub witness: Vec<Fr>,
}
```

**NonNativeBuilder 方法**：

| 方法 | 功能 | 约束数（行数） |
|------|------|----------------|
| `new()` | 初始化（witness[0] = Fr::one()） | 0 |
| `alloc(val: Fr)` | 分配变量 + 设置 witness | 0 |
| `get_val(idx)` | 获取 witness 值 | 0 |
| `alloc_element(limbs: [Fr; 4])` | 分配 4-limb 元素 | 0 |
| `from_u256(val: [u64; 4])` | 从 host 值创建元素 | 0 |
| `add_mod(a, b, modulus)` | 模加（hint: carry） | ~20 |
| `sub_mod(a, b, modulus)` | 模减（hint: borrow） | ~20 |
| `mul_mod(a, b, modulus)` | 模乘（hint: q, r） | ~300 |
| `assert_lt(val, bound)` | 范围检查 val < bound | ~260 |
| `assert_equal(a, b)` | 相等检查 | ~4 |
| `is_zero(a, modulus)` | 判零（hint: inverse） | ~310 |

**mul_mod 算法**（hint-based，约 300 约束）：

```text
输入: a = [a0, a1, a2, a3], b = [b0, b1, b2, b3], modulus = [m0, m1, m2, m3]
Prover hint: q = [q0, q1, q2, q3] (quotient), r = [r0, r1, r2, r3] (remainder)

1. 计算 a*b 的 8-limb 乘积 product[0..7]（schoolbook）:
   product[k] = sum(a_i * b_j for i+j == k) + carries
   - 16 个乘法约束 (a_i * b_j)
   - 8 个 carry 链加法约束

2. 计算 q*modulus 的 8-limb 乘积 qm[0..7]（同样 schoolbook）:
   - 16 个乘法约束 (q_i * m_j)
   - 8 个 carry 链加法约束

3. 验证 product - qm = r（低 4 limb = r，高 4 limb = 0）:
   - 8 个减法/相等约束

4. 范围检查 r < modulus:
   - bit_decompose 每个 r limb (4 × 64 = 256 bits)
   - 逐 bit 比较

总计: ~300 约束
```

**Host-side 辅助函数**（纯 Rust，`[u64; 4]` 算术）：

```rust
/// 256-bit 加法 mod modulus
fn host_add_mod(a: [u64; 4], b: [u64; 4], modulus: [u64; 4]) -> [u64; 4];

/// 256-bit 减法 mod modulus
fn host_sub_mod(a: [u64; 4], b: [u64; 4], modulus: [u64; 4]) -> [u64; 4];

/// 256-bit 乘法 mod modulus（schoolbook + Barrett or Fermat）
fn host_mul_mod(a: [u64; 4], b: [u64; 4], modulus: [u64; 4]) -> [u64; 4];

/// 256-bit 比较 a < b
fn host_lt(a: [u64; 4], b: [u64; 4]) -> bool;

/// 256-bit 模逆（Fermat: a^(modulus-2) mod modulus，快速幂）
fn host_inv_mod(a: [u64; 4], modulus: [u64; 4]) -> [u64; 4];

/// [u64; 4] → [Fr; 4]
fn u256_to_limbs(val: [u64; 4]) -> [Fr; 4];

/// [Fr; 4] → [u64; 4]（仅用于 host-side 测试验证）
fn limbs_to_u256(limbs: &[Fr; 4]) -> [u64; 4];
```

**测试**（≥8 个）：
- `test_host_add_mod` — 基域 + 标量域模加
- `test_host_mul_mod` — 模乘（含 G·k 验证）
- `test_host_inv_mod` — 模逆（a * a⁻¹ = 1）
- `test_nonnative_add_mod` — 电路模加 satisfied_by
- `test_nonnative_sub_mod` — 电路模减 satisfied_by
- `test_nonnative_mul_mod` — 电路模乘 satisfied_by
- `test_nonnative_assert_lt` — 范围检查（合法/篡改）
- `test_nonnative_assert_equal` — 相等检查
- `test_nonnative_soundness` — 篡改 witness 导致约束失败

---

### E2：创建 `src/precompiles/secp256k1_ops.rs`

**目标**：在非原生域上实现 secp256k1 的 Jacobian 坐标点运算。

**核心设计**：
- **Jacobian 坐标**：点 `(X, Y, Z)` 表示仿射点 `(X/Z², Y/Z³)`，避免模逆
- **point_double**：~9 mul_mod（Jacobian 倍点公式）
- **point_add**：~16 mul_mod（Jacobian 点加公式，处理不同点）
- **scalar_mul**：256-bit double-and-add（256 轮 × (1 double + conditional 1 add)）
- **assert_on_curve**：验证 `Y² = X³ + 7`（在 Jacobian 坐标下 `Y² = X³ + 7·Z⁶`）

**数据结构**：

```rust
/// secp256k1 Jacobian 坐标点
#[derive(Clone)]
pub(crate) struct Point {
    pub x: NonNativeElement,  // 4 limbs
    pub y: NonNativeElement,  // 4 limbs
    pub z: NonNativeElement,  // 4 limbs
}
```

**方法**：

| 方法 | 功能 | 约束数（行数） |
|------|------|----------------|
| `point_double(builder, p)` | Jacobian 倍点 | ~2,700 (9 mul_mod × ~300) |
| `point_add(builder, a, b)` | Jacobian 点加（不同点） | ~4,800 (16 mul_mod × ~300) |
| `scalar_mul(builder, scalar, point, modulus)` | 256-bit double-and-add | ~1,920,000 (256 × (2700 + 4800)) |
| `assert_on_curve(builder, p)` | 验证 Y²=X³+7·Z⁶ | ~1,500 (5 mul_mod) |
| `assert_point_equal(builder, a, b)` | 验证两点相等 | ~900 (3 mul_mod) |

**point_double 公式**（Jacobian，secp256k1 a=0）：

```text
A = X²                  // 1 mul_mod
B = Y²                  // 1 mul_mod
C = B²                  // 1 mul_mod
D = 2*((X+B)² - A - C)  // 2 mul_mod (X+B squared, 2×)
E = 3*A                 // 0 mul_mod (常数 3)
F = E²                  // 1 mul_mod
X3 = F - 2*D            // 0 mul_mod (线性)
Y3 = E*(D - X3) - 8*C   // 1 mul_mod
Z3 = 2*Y*Z              // 1 mul_mod
总计: ~7-9 mul_mod
```

**point_add 公式**（Jacobian，不同点）：

```text
U1 = X1 * Z2²           // 2 mul_mod
S1 = Y1 * Z2³           // 2 mul_mod (Z2² * Z2)
U2 = X2 * Z1²           // 2 mul_mod
S2 = Y2 * Z1³           // 2 mul_mod
H = U2 - U1             // 0 mul_mod
R = S2 - S1             // 0 mul_mod
X3 = R² - H³ - 2*U1*H²  // ~4 mul_mod
Y3 = R*(U1*H² - X3) - S1*H³  // ~4 mul_mod
Z3 = Z1 * Z2 * H         // ~2 mul_mod
总计: ~16 mul_mod
```

**scalar_mul 算法**（double-and-add，256-bit）：

```text
结果 = identity (Z=0)
for bit in scalar_bits (MSB → LSB):
    结果 = point_double(结果)
    if bit == 1:
        结果 = point_add(结果, point)
```

**测试**（≥6 个）：
- `test_point_double` — 2·G 坐标与 `secp256k1` crate 一致
- `test_point_add` — G + 2·G = 3·G 与 crate 一致
- `test_scalar_mul_generator` — k·G 与 `secp256k1` crate 一致（小 k）
- `test_scalar_mul_pubkey` — k·P 与 crate 一致
- `test_assert_on_curve` — 合法点通过 / 非法点失败
- `test_assert_point_equal` — 相等点通过 / 不同点失败

---

### E3：扩展 `src/precompiles/ecdsa.rs` 到完整验证

**目标**：添加双模式支持，完整模式验证 `s·R' = z·G + r·P`。

**核心设计**：
- 保留现有 MVP（`new()`），新增 `new_full()`
- 完整模式输入：24 个 Fr（6 值 × 4 limbs）：`r, s, z, px, py, ry`
- 验证等式：`s·R' = z·G + r·P`，其中 `R' = (r, ry)`（ry 为 prover hint）
- 避免在电路中计算 `s⁻¹`（改用等式两边乘以 s）

**修改 `EcdsaVerifyCircuit` 结构**：

```rust
#[derive(Debug, Clone)]
pub struct EcdsaVerifyCircuit {
    curve: &'static str,
    full_mode: bool,  // 新增
}

impl EcdsaVerifyCircuit {
    pub fn new() -> Self { Self { curve: "secp256k1", full_mode: false } }
    pub fn new_full() -> Self { Self { curve: "secp256k1", full_mode: true } }
    pub fn is_full_mode(&self) -> bool { self.full_mode }

    /// 完整 ECDSA 验证，同时构建 CCS + witness
    fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError>;
}
```

**`run_full` 算法**：

```text
输入: 24 Fr = [r0..r3, s0..s3, z0..z3, px0..px3, py0..py3, ry0..ry3]

1. 创建 NonNativeBuilder
2. 解析输入为 6 个 NonNativeElement (r, s, z, px, py, ry) — 使用标量域 n
3. 构造点:
   - G = (GX, GY, 1) — 生成元（基域 p_curve）
   - P = (px, py, 1) — 公钥（基域 p_curve）
   - R' = (r, ry, 1) — 签名点（基域 p_curve）
4. 验证 R' 在曲线上: assert_on_curve(R')
5. 计算左侧: sR' = scalar_mul(s, R', n)  [标量域 n, 点在基域 p_curve]
6. 计算右侧: zG = scalar_mul(z, G, n)
7. 计算右侧: rP = scalar_mul(r, P, n)
8. 计算右侧: zG_plus_rP = point_add(zG, rP)
9. 验证等式: assert_point_equal(sR', zG_plus_rP)
10. 返回 (ccs, witness)
```

**PrecompileCircuit trait 分派**：

```rust
fn num_variables(&self) -> usize {
    if self.full_mode { /* run_full 中的变量数 */ } else { 6 }
}
fn build_ccs(&self) -> Ccs {
    if self.full_mode { self.run_full(&[]).0 } else { /* 现有 MVP */ }
}
fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
    if self.full_mode { Ok(self.run_full(inputs)?.1) } else { /* 现有 MVP */ }
}
fn gas_cost(&self) -> u64 {
    if self.full_mode { 3_000_000 } else { 100_000 }
}
```

**CcsCircuit trait 分派**：

```rust
fn num_matrices(&self) -> usize {
    if self.full_mode { self.build_ccs().num_matrices() } else { 7 }
}
```

**测试**（≥8 个）：
- `test_ecdsa_full_build_ccs` — 矩阵/变量/行数 > 0
- `test_ecdsa_full_valid_signature` — 有效签名通过 satisfied_by（使用 `secp256k1` crate 生成）
- `test_ecdsa_full_tampered_r` — 篡改 r → 失败
- `test_ecdsa_full_tampered_s` — 篡改 s → 失败
- `test_ecdsa_full_tampered_z` — 篡改 z → 失败
- `test_ecdsa_full_tampered_pubkey` — 篡改公钥 → 失败
- `test_ecdsa_full_wrong_ry` — 错误 ry → 失败
- `test_ecdsa_full_mvp_backward_compatible` — `new()` 仍为 MVP，12 个既有测试通过

---

### E4：修改 `src/precompiles/mod.rs`

添加模块声明（按字母序）：

```rust
pub mod bit_ops;
pub mod ccs_builder;
pub mod ecdsa;
pub mod non_native;       // 新增
pub mod poseidon;
pub mod secp256k1_ops;    // 新增
pub mod sha256;
pub mod zk_shuffle;
```

**修改文件清单**：
- 新建 `src/precompiles/non_native.rs`
- 新建 `src/precompiles/secp256k1_ops.rs`
- 修改 `src/precompiles/ecdsa.rs`（添加完整模式）
- 修改 `src/precompiles/mod.rs`（添加 2 个模块声明）

## Assumptions & Decisions

1. **k=4, b=64 limb 表示**（vs spec 的 k=4, b=80）：4×64=256 bits 覆盖 secp256k1 的 256-bit 域；limb 乘积 64×64=128 bits 远小于 BN254 Fr（254 bits），无需拆分；host 端用 `[u64; 4]` 自然表示。

2. **Hint-based 乘法**（vs Barrett reduction）：prover 提供 q（商）和 r（余数），电路验证 `a*b = q*modulus + r` + `r < modulus`。避免在电路中实现 Barrett 参数预计算，约束数约 300/mul_mod。

3. **NonNativeBuilder 为 `pub(crate)`**：仅 `secp256k1_ops.rs` 和 `ecdsa.rs` 需要访问，不暴露到 crate 外部。

4. **Jacobian 坐标**（vs 仿射坐标）：避免模逆（模逆约需 ~256 次 mul_mod via Fermat），Jacobian 倍点 ~9 mul_mod，点加 ~16 mul_mod。

5. **ECDSA verify: `s·R' = z·G + r·P`**（vs `R' = s⁻¹·(z·G + r·P)`）：避免在电路中计算 `s⁻¹`。R' = (r, ry)，ry 为 prover hint（2 个可能的 y 值之一）。

6. **约束数估算**：完整模式约 5.8M 约束（3 次 scalar_mul × ~1.92M + 点加/曲线检查开销）。vs spec 估算 ~315K（需窗口法标量乘 + 批量范围检查等优化）。**本 Phase 先实现正确版本，优化留待后续迭代**。

7. **MVP 向后兼容**：保留 `new()` 及 12 个既有测试不变。`new_full()` 为独立路径。

8. **host_inv_mod 使用 Fermat 小定理**：`a⁻¹ = a^(modulus-2) mod modulus`，快速幂实现。避免引入 `num-bigint` 依赖。

9. **gas_cost 完整模式 = 3,000,000**：高于 MVP 的 100,000，反映完整验证的计算成本（参考以太坊 ECDSA precompile 3,000 gas，但 zk 电路成本更高）。

## 约束数与性能说明

| 组件 | 约束数（行数） | 说明 |
|------|----------------|------|
| 1× mul_mod | ~300 | 16 乘法 + 16 乘法 + carry + 范围检查 |
| point_double | ~2,700 | 9 mul_mod |
| point_add | ~4,800 | 16 mul_mod |
| scalar_mul (256-bit) | ~1,920,000 | 256 × (2700 + 4800) |
| ECDSA verify (3× scalar_mul) | ~5,760,000 | 3 × 1.92M + 点加 + 曲线检查 |
| 总计 | ~5.8M | vs spec ~315K |

**优化路线图（本 Phase 不实现，记录供后续迭代）**：
- 窗口法标量乘（width-4）：将 256 轮降至 64 轮，约束数 ÷ 4 → ~1.45M
- 批量范围检查：多 limb 共享 bit_decompose 开销
- 预计算表：G 的 2^k 倍点作为常量嵌入
- 基域优化：secp256k1 的 a=0, b=7 特殊形式简化倍点公式

## Verification Steps

### E1 完成后
```bash
cargo test -p poker_zkvm --lib non_native    # 非原生域测试通过
cargo clippy -p poker_zkvm --all-targets     # 零警告
```

### E2 完成后
```bash
cargo test -p poker_zkvm --lib secp256k1_ops  # 点运算测试通过
cargo clippy -p poker_zkvm --all-targets      # 零警告
```

### E3+E4 完成后（完整验证）
```bash
cargo build -p poker_zkvm                          # 编译通过
cargo test -p poker_zkvm --lib                     # 所有库测试通过（含既有 808+ 新增）
cargo test -p poker_zkvm --lib ecdsa               # ECDSA 测试通过（MVP + 完整）
cargo clippy -p poker_zkvm --all-targets           # 零警告
cargo bench -p poker_zkvm --no-run                 # 基准编译通过
cargo test -p poker_l1 --lib                       # 确保无回归
```

### 额外验证
- `test_ecdsa_full_valid_signature`：使用 `secp256k1` crate 生成有效签名，电路 `satisfied_by` 返回 `true`
- `test_ecdsa_full_tampered_*`：篡改任一输入导致 `satisfied_by` 返回 `false`
- `test_ecdsa_full_mvp_backward_compatible`：12 个 MVP 既有测试全部通过

## 执行策略

按 E1 → E2 → E3 → E4 顺序执行，每步完成后运行局部测试确认。E1 是基础（非原生域算术），E2 依赖 E1（点运算用 mul_mod），E3 依赖 E2（ECDSA verify 用 scalar_mul），E4 仅添加模块声明。

**风险**：极高（spec L288）。非原生域算术是最复杂的密码学电路。关键风险点：
1. mul_mod 的 carry 链正确性 — 需严格测试边界值
2. scalar_mul 的 double-and-add 逻辑 — 需与 `secp256k1` crate 对比验证
3. 约束数 ~5.8M 可能导致编译/测试时间过长 — 如遇 OOM，先减小测试用例的 scalar bits（如 8-bit 标量）
