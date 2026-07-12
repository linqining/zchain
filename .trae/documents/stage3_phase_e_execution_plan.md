# Stage 3 — Phase E 执行计划（ECDSA 完整验证电路）

> **设计文档**：`/Users/mac/projects/zchain/.trae/documents/stage3_phase_e_ecdsa_full_circuit.md`（已批准）
>
> **当前状态**：E1 的 `non_native.rs` 已写入 1055 行但存在编译错误和死代码；E2/E3/E4 未开始。

## Summary

Phase E 将 ECDSA 电路从 MVP 扩展到完整 secp256k1 验签。`non_native.rs` 已存在但需修复编译错误。然后创建 `secp256k1_ops.rs`（点运算），扩展 `ecdsa.rs`（双模式），更新 `mod.rs`。

**关键发现（探索阶段）**：实际 mul_mod 约束数 ~1400（非设计文档估算的 ~300），因为 8 个 product limb 各需 65 约束的范围检查。完整 256-bit ECDSA 约 27M 约束，无法在测试中运行 `satisfied_by`。测试策略调整为：组件级测试用小标量（8-bit），ECDSA 完整模式仅测 CCS 构建 + witness 赋值。

## Current State Analysis

### non_native.rs 已有代码（1055 行）— 存在 4 个问题

1. **编译错误（`host_div_mod`）**：第 152 行 `let msb = remainder[3] >> 63;` 在 for 循环内声明，第 170 行 `let _ = msb;` 在循环外引用 → `cannot find value 'msb'`。`msb` 实际从未使用（移位操作从高索引到低索引处理，不需要 MSB）。

2. **死代码（`range_check_64`）**：第 332 行 `bit_val` 用 `to_u32()` 计算（只取低 32 位），第 337 行立即被 `to_canonical_bytes()` 覆盖。第 327 行 `val` 和第 334 行 `full_val` 也是冗余。

3. **冗余计算（`mul_mod`）**：第 674-685 行在 if/else 块内计算 `carry_out_val` 但从未使用，第 689-693 行重新计算。

4. **潜在借用冲突**：`add_mod`（第 517 行）和 `sub_mod`（第 602 行）中 `self.ccs.add_multiplication(r_mult, reduced_var, self.bound_var(m_v), rm_var)` — `self.bound_var()` 需 `&mut self`，`self.ccs.add_multiplication` 需 `&mut self.ccs`。可能触发 borrow checker 错误（Rust 两阶段借用可能允许，需编译验证）。

### ecdsa.rs MVP（368 行，12 测试）— 完整可用

- `EcdsaVerifyCircuit { curve: &'static str }`，`new()` 构造
- 6 变量 witness，7 行隔离矩阵，3 约束行
- `gas_cost()` = 100,000，12 个测试全部通过

### 可用模式

- **CcsBuilder API**：`alloc_var()`（从 1 开始）、`alloc_row()`（从 0 开始）、`add_multiplication(row, a, b, result)`（3 矩阵 + 2 subsets）、`add_linear(row, &[(col, coeff)])`（N 矩阵 + N subsets）、`add_bit_check(row, col)`（1 矩阵 + 2 subsets）、`build() → Result<Ccs, ZkvmError>`
- **FullBuilder 模式**（sha256.rs）：组合 `CcsBuilder` + `witness: Vec<Fr>`，每个操作方法同时添加约束和计算 witness
- **双模式模式**（sha256.rs）：`full_mode: bool`，`new()` (MVP) + `new_full()` (完整)，trait 方法分派
- **`Ccs::satisfied_by` 快速路径**：行隔离矩阵 → O(matrices + subsets + num_rows)

### 可用依赖

- `secp256k1 = { workspace = true }` — 正式依赖（非 dev），可在测试中使用
- `ark-ec`, `ark-ff` — 曲线和域运算
- `ark-bn254` — BN254 Fr（电路域）
- `Fr` = `Bn254ScalarField`（`ark_bn254::Fr` 的 newtype），定义在 `src/ccs/mod.rs:25`

## Proposed Changes

### E1：修复 non_native.rs + 添加到 mod.rs

**文件**：`src/precompiles/non_native.rs`（修复）+ `src/precompiles/mod.rs`（添加声明）

**修复 1 — `host_div_mod` 编译错误**：
- 删除第 152 行 `let msb = remainder[3] >> 63;`
- 删除第 170 行 `let _ = msb; // suppress warning`
- 修复第 153 行缩进（`for k in (1..4).rev() {` 应与循环体对齐）

**修复 2 — `range_check_64` 死代码**：
- 删除第 327 行 `let val = self.get_val(var);`（仅被死代码使用）
- 删除第 332 行 `let bit_val = Fr::from_u64(((val.to_u32() as u64) >> i) & 1);`
- 删除第 333 行注释 `// 注意: to_u32 只返回低 32 位...`
- 删除第 334 行 `let full_val = self.get_val(var);`（冗余，值同 `val`）
- 保留第 335-337 行的正确计算（使用 `to_canonical_bytes()`）

**修复 3 — `mul_mod` 冗余计算**：
- 在 if/else 块中（第 674-685 行），删除 `carry_out_val` 的计算，只保留 `(expected_val, expected_var)` 的返回
- 简化为：
```rust
let (expected_val, expected_var) = if k < 4 {
    (self.get_val(r_elem.limbs[k]), r_elem.limbs[k])
} else {
    (Fr::zero(), 0)
};
```

**修复 4（条件）— 借用冲突**：
- 如果编译报错 `cannot borrow self as mutable because it is also borrowed as immutable`：
- 在 `add_mod` 和 `sub_mod` 中，将 `self.bound_var(m_v)` 提取为独立变量：
```rust
let m_var = self.bound_var(m_v);
let r_mult = self.ccs.alloc_row();
self.ccs.add_multiplication(r_mult, reduced_var, m_var, rm_var);
```

**修复 5 — 添加模块声明**：
- 在 `src/precompiles/mod.rs` 中添加 `pub mod non_native;`（按字母序，在 `ecdsa` 之后、`poseidon` 之前）

**验证**：
```bash
cargo test -p poker_zkvm --lib non_native    # 9 个测试通过
cargo clippy -p poker_zkvm --all-targets     # 零警告
```

---

### E2：创建 src/precompiles/secp256k1_ops.rs

**文件**：新建 `src/precompiles/secp256k1_ops.rs`

**目标**：在非原生域上实现 secp256k1 的 Jacobian 坐标点运算，支持可配置标量位宽。

**核心设计**：
- Jacobian 坐标 `(X, Y, Z)` 表示仿射点 `(X/Z², Y/Z³)`，避免模逆
- `scalar_mul` 接受 `num_bits` 参数，允许小位宽测试（8-bit）
- 所有点运算通过 `NonNativeBuilder` 添加约束 + 计算 witness

**数据结构**：

```rust
use crate::precompiles::non_native::{
    NonNativeBuilder, NonNativeElement,
    SECP256K1_P_CURVE, SECP256K1_N, SECP256K1_GX, SECP256K1_GY,
};

/// secp256k1 Jacobian 坐标点
#[derive(Clone)]
pub(crate) struct Point {
    pub x: NonNativeElement,  // 4 limbs, 基域 p_curve
    pub y: NonNativeElement,  // 4 limbs, 基域 p_curve
    pub z: NonNativeElement,  // 4 limbs, 基域 p_curve
}
```

**方法清单**：

| 方法 | 功能 | 约束数（~1400/mul_mod） |
|------|------|------------------------|
| `point_double(builder, p) -> Point` | Jacobian 倍点（a=0 公式） | ~12,600 (9 mul_mod) |
| `point_add(builder, a, b) -> Point` | Jacobian 点加（不同点） | ~22,400 (16 mul_mod) |
| `scalar_mul(builder, scalar, point, num_bits) -> Point` | double-and-add（可配置位宽） | num_bits × ~35,000 |
| `assert_on_curve(builder, p)` | 验证 Y²=X³+7·Z⁶ | ~7,000 (5 mul_mod) |
| `assert_point_equal(builder, a, b)` | 验证两点相等（X1·Z2²=X2·Z1² 且 Y1·Z2³=Y2·Z1³） | ~8,400 (6 mul_mod) |
| `identity_point(builder) -> Point` | 无穷远点 (Z=0) | 0 |

**point_double 公式**（Jacobian，secp256k1 a=0）：

```text
A = X²                    // 1 mul_mod
B = Y²                    // 1 mul_mod
C = B²                    // 1 mul_mod
D = 2*((X+B)² - A - C)   // 2 mul_mod ((X+B)² 展开)
E = 3*A                   // 0 mul_mod (常数 3)
F = E²                    // 1 mul_mod
X3 = F - 2*D             // 0 mul_mod (线性)
Y3 = E*(D - X3) - 8*C    // 1 mul_mod
Z3 = 2*Y*Z               // 1 mul_mod (Y*Z 然后 ×2)
总计: ~8 mul_mod
```

**point_add 公式**（Jacobian，不同点，a=0）：

```text
Z1Z1 = Z1²               // 1 mul_mod
Z2Z2 = Z2²               // 1 mul_mod
U1 = X1 * Z2Z2           // 1 mul_mod
U2 = X2 * Z1Z1           // 1 mul_mod
S1 = Y1 * Z2 * Z2Z2      // 2 mul_mod
S2 = Y2 * Z1 * Z1Z1      // 2 mul_mod
H = U2 - U1              // 0 mul_mod
R = S2 - S1              // 0 mul_mod
HH = H²                  // 1 mul_mod
HHH = H * HH             // 1 mul_mod
U1HH = U1 * HH           // 1 mul_mod
X3 = R² - HHH - 2*U1HH  // 1 mul_mod (R²)
Y3 = R*(U1HH - X3) - S1*HHH  // 2 mul_mod
Z3 = Z1 * Z2 * H         // 2 mul_mod
总计: ~16 mul_mod
```

**scalar_mul 算法**（double-and-add，MSB → LSB）：

```text
result = identity_point (Z=0)
for bit in (0..num_bits).rev():
    result = point_double(result)
    if (scalar >> bit) & 1 == 1:
        result = point_add(result, point)
```

**测试**（≥6 个，使用 `num_bits=8` 小标量 + `secp256k1` crate 交叉验证）：

1. `test_point_double` — 2·G 与 secp256k1 crate 一致
   - 用 `secp256k1::Secp256k1` 计算 `SecretKey::from_slice(&[2; 32])` 的公钥
   - 电路计算 `point_double(G)`，验证 X/Z² 和 Y/Z³ 与 crate 结果一致
2. `test_point_add` — G + 2·G = 3·G 与 crate 一致
3. `test_scalar_mul_small` — 3·G（num_bits=8）与 crate 一致
   - 构建电路 → build → `satisfied_by` 返回 true
   - 验证结果点坐标与 `SecretKey::from_slice(&[3; 32])` 的公钥一致
4. `test_scalar_mul_pubkey` — 5·P（P 为某公钥）与 crate 一致
5. `test_assert_on_curve` — G 通过 / 随机非曲线点失败
6. `test_assert_point_equal` — 相等点通过 / 不同点失败

**关键实现细节**：
- `Point` 方法接收 `&mut NonNativeBuilder`，返回新 `Point`
- 每个中间值通过 `builder.alloc(val)` 分配变量 + 设置 witness
- 常数（如 2、3、7）通过 `builder.from_u256(&[val, 0, 0, 0])` 创建
- `point_double` 的 `2*Y*Z` 用 `mul_mod` 计算 `Y*Z`，然后用 `add_mod` 加自身（×2）
- `scalar_mul` 的条件加法用 double-and-add（非条件约束），bit 值在 witness 中确定

**验证**：
```bash
cargo test -p poker_zkvm --lib secp256k1_ops  # 6 个测试通过
cargo clippy -p poker_zkvm --all-targets       # 零警告
```

---

### E3：扩展 src/precompiles/ecdsa.rs 到完整验证

**文件**：修改 `src/precompiles/ecdsa.rs`

**目标**：添加双模式支持，完整模式验证 `s·R' = z·G + r·P`（可配置标量位宽）。

**修改 `EcdsaVerifyCircuit` 结构**：

```rust
#[derive(Debug, Clone)]
pub struct EcdsaVerifyCircuit {
    curve: &'static str,
    full_mode: bool,       // 新增
    scalar_num_bits: usize, // 新增：完整模式标量位宽（默认 256，测试用 8）
}

impl EcdsaVerifyCircuit {
    pub fn new() -> Self { Self { curve: "secp256k1", full_mode: false, scalar_num_bits: 256 } }
    pub fn new_full() -> Self { Self { curve: "secp256k1", full_mode: true, scalar_num_bits: 256 } }
    pub fn new_full_with_bits(num_bits: usize) -> Self { Self { curve: "secp256k1", full_mode: true, scalar_num_bits: num_bits } }
    pub fn is_full_mode(&self) -> bool { self.full_mode }
    pub fn scalar_num_bits(&self) -> usize { self.scalar_num_bits }
}
```

**`run_full` 算法**：

```text
输入: 24 Fr = [r0..r3, s0..s3, z0..z3, px0..px3, py0..py3, ry0..ry3]

1. 创建 NonNativeBuilder
2. 解析输入为 6 个 NonNativeElement:
   - r, s, z: 标量域 n (4 limbs each)
   - px, py, ry: 基域 p_curve (4 limbs each)
3. 构造点（基域 p_curve）:
   - G = (GX, GY, 1) — 生成元
   - P = (px, py, 1) — 公钥
   - R' = (r, ry, 1) — 签名点（ry 为 prover hint）
4. 验证 R' 在曲线上: assert_on_curve(R')  [基域 p_curve]
5. 计算左侧: sR' = scalar_mul(s, R', n, self.scalar_num_bits)  [标量域 n]
6. 计算右侧: zG = scalar_mul(z, G, n, self.scalar_num_bits)
7. 计算右侧: rP = scalar_mul(r, P, n, self.scalar_num_bits)
8. 计算右侧: zG_plus_rP = point_add(zG, rP)  [基域 p_curve]
9. 验证等式: assert_point_equal(sR', zG_plus_rP)
10. 返回 (ccs, witness)
```

**注意**：标量域 n 和基域 p_curve 是不同的模数。`scalar_mul` 用标量域 n 做标量算术（mul_mod 的 modulus = SECP256K1_N），但点坐标在基域 p_curve 上（mul_mod 的 modulus = SECP256K1_P_CURVE）。需要确保 `NonNativeBuilder` 的 `mul_mod` 接收 modulus 参数（已有设计支持）。

**PrecompileCircuit trait 分派**：

```rust
fn num_variables(&self) -> usize {
    if self.full_mode {
        let dummy = vec![Fr::zero(); 24];
        self.run_full(&dummy).unwrap().0.num_vars
    } else { 6 }
}
fn build_ccs(&self) -> Ccs {
    if self.full_mode {
        let dummy = vec![Fr::zero(); 24];
        self.run_full(&dummy).unwrap().0
    } else { self.build_mvp_ccs() }
}
fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
    if self.full_mode {
        if inputs.len() != 24 { return Err(...); }
        Ok(self.run_full(inputs)?.1)
    } else { self.assign_mvp_witness(inputs) }
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

1. `test_ecdsa_full_build_ccs_small` — `new_full_with_bits(4)` 构建 CCS，矩阵/变量/行数 > 0
2. `test_ecdsa_full_assign_witness_small` — `new_full_with_bits(4)` 赋值 witness，长度 = num_vars
3. `test_ecdsa_full_satisfied_small` — `new_full_with_bits(4)` + 小标量测试用例，`satisfied_by` 返回 true
   - **构造方法**：用小标量 r=7, s=3, z=5（均 < 16），R' = G（ry = GY），计算 P = r⁻¹·(s·R' - z·G) mod n
   - r=7 作为标量使用，同时作为 R' 的 x 坐标 → 需要 x=7 在曲线上有有效 y
   - **备选方案**：如果 x=7 不在曲线上，用 G 作为 R'，r = Gx（256-bit），但 `scalar_num_bits=256` 太大
   - **最终方案**：不强制 r = R'.x。电路验证 `s·R' = z·G + r·P`，其中 R' = (r, ry) 由输入提供。用 r=7, ry=<valid y for x=7>。如果 x=7 不在曲线上，搜索最小的有效 x 值。如果找不到小 x，用 `scalar_num_bits=256` + k=1（R=G, r=Gx），仅测试 build + assign（不运行 `satisfied_by`）
4. `test_ecdsa_full_mvp_backward_compatible` — `new()` 仍为 MVP，12 个既有测试通过
5. `test_ecdsa_full_tampered_r` — 篡改 r → `satisfied_by` 返回 false（小位宽）
6. `test_ecdsa_full_tampered_s` — 篡改 s → false
7. `test_ecdsa_full_tampered_z` — 篡改 z → false
8. `test_ecdsa_full_wrong_ry` — 错误 ry → false（曲线检查失败）

**测试可行性说明**：
- `scalar_num_bits=4` 的 ECDSA 电路约 3 × (4 × 35,000) ≈ 420K 约束
- `satisfied_by` 快速路径对 420K 行隔离矩阵可行（~秒级）
- 但需要构造有效的测试用例（小标量 + 曲线上有效点）

**验证**：
```bash
cargo test -p poker_zkvm --lib ecdsa          # MVP + 完整模式测试
cargo clippy -p poker_zkvm --all-targets       # 零警告
```

---

### E4：更新 mod.rs + 完整验证

**文件**：`src/precompiles/mod.rs`

**修改**：添加模块声明（按字母序）：

```rust
pub mod bit_ops;
pub mod ccs_builder;
pub mod ecdsa;
pub mod non_native;        // 新增
pub mod poseidon;
pub mod secp256k1_ops;     // 新增
pub mod sha256;
pub mod zk_shuffle;
```

**完整验证**：

```bash
cargo build -p poker_zkvm                          # 编译通过
cargo test -p poker_zkvm --lib                     # 所有库测试通过
cargo test -p poker_zkvm --lib ecdsa               # ECDSA 测试（MVP + 完整）
cargo test -p poker_zkvm --lib non_native          # 非原生域测试
cargo test -p poker_zkvm --lib secp256k1_ops       # 点运算测试
cargo clippy -p poker_zkvm --all-targets           # 零警告
cargo bench -p poker_zkvm --no-run                 # 基准编译通过
cargo test -p poker_l1 --lib                       # 确保无回归
```

## Assumptions & Decisions

1. **约束数现实**：mul_mod ~1400 约束（非设计文档的 ~300），主因是 8 个 product limb 各需 65 约束的范围检查。完整 256-bit ECDSA ≈ 27M 约束，测试中无法运行 `satisfied_by`。

2. **测试策略**：
   - `secp256k1_ops.rs`：用 `num_bits=8` 小标量，运行 `satisfied_by` 验证正确性
   - `ecdsa.rs` 完整模式：用 `scalar_num_bits=4`，如果能构造有效小测试用例则运行 `satisfied_by`；否则仅测 CCS 构建 + witness 赋值
   - MVP 向后兼容：12 个既有测试全部通过

3. **`scalar_mul` 可配置位宽**：`scalar_mul(builder, scalar, point, num_bits)` 接受 `num_bits` 参数，允许 4/8/256 位测试。`EcdsaVerifyCircuit::new_full_with_bits(num_bits)` 提供构造接口。

4. **标量域 vs 基域**：secp256k1 有两个域 — 标量域 n（阶）和基域 p_curve。标量算术（r, s, z 的 mul_mod）用 n，点坐标算术（X, Y, Z 的 mul_mod）用 p_curve。`NonNativeBuilder::mul_mod` 已接收 modulus 参数，支持两个域。

5. **借用冲突修复**：如果 `self.ccs.add_multiplication(..., self.bound_var(m_v), ...)` 触发 borrow checker 错误，将 `self.bound_var(m_v)` 提取为独立变量。

6. **`bound_var` 优化**：当值为 `Fr::one()` 时返回变量 0（常数 1），避免分配新变量。

7. **优化路线图（本 Phase 不实现）**：窗口法标量乘（约束数 ÷ 4）、批量范围检查、预计算表、secp256k1 a=0 特殊形式简化。

## Verification Steps

### E1 完成后
```bash
cargo test -p poker_zkvm --lib non_native    # 9 个测试通过
cargo clippy -p poker_zkvm --all-targets     # 零警告
```

### E2 完成后
```bash
cargo test -p poker_zkvm --lib secp256k1_ops  # 6 个测试通过
cargo clippy -p poker_zkvm --all-targets      # 零警告
```

### E3 完成后
```bash
cargo test -p poker_zkvm --lib ecdsa          # MVP 12 + 完整 ≥8 测试通过
cargo clippy -p poker_zkvm --all-targets      # 零警告
```

### E4 完成后（完整验证）
```bash
cargo build -p poker_zkvm                     # 编译通过
cargo test -p poker_zkvm --lib                # 所有库测试通过
cargo bench -p poker_zkvm --no-run            # 基准编译通过
cargo test -p poker_l1 --lib                  # 无回归
```

## 执行顺序

E1（修复 non_native.rs）→ E2（secp256k1_ops.rs）→ E3（ecdsa.rs 扩展）→ E4（mod.rs + 完整验证）

每步完成后运行局部测试确认通过，再进入下一步。
