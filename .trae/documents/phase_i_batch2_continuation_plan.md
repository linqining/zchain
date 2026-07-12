# Phase I Batch 2 — 续执行计划（从当前状态恢复）

## Summary

继续执行被中断的 Phase I Batch 2 工作。Part 1 已完成 ~90%（`test_phase10_gas_costs_reasonable` 更新 + `GAS_PER_BYTE` 删除），但发现 keccak256.rs 有新的 dead_code 警告（`RATE_BITS`/`RATE_LANES` 在 `#[cfg(test)]` 内使用，非测试构建报 unused）。Part 2-5 完全未开始。

本计划聚焦：**修复 Part 1 遗留警告 → 执行 Part 2 (ed25519) → Part 3 (bn254_pairing) → Part 4 (syscalls/gas) → Part 5 全量验证**。

详细设计参考 [`phase_i_batch2_ed25519_bn254.md`](./phase_i_batch2_ed25519_bn254.md)（已批准，本计划是其续执行版本）。

## Current State Analysis

### 已完成
- ✅ `test_phase10_gas_costs_reasonable` 已扩展到 7 个 case（precompiles/mod.rs）
- ✅ `GAS_PER_BYTE` 常量已从 keccak256.rs 删除
- ✅ 4 个 test_phase10 测试通过、modexp 9 passed、merkle_verify 11 passed

### 遗留问题（Part 1 收尾）
- ⚠️ keccak256.rs L70-71：`RATE_BITS` / `RATE_LANES` 触发 dead_code 警告
  - 原因：仅被 L654/666/859 引用，而这些行位于 L591 `#[cfg(test)]` 块内
  - 修复方案：给两个常量加 `#[cfg(test)]` 门控（与使用点一致），或加 `#[allow(dead_code)]`
  - 选择：加 `#[cfg(test)]`（更精确，非测试构建不编译）

### 未开始
- ⬜ Part 2：`poker_zkvm/src/precompiles/ed25519.rs`（文件不存在）
- ⬜ Part 3：`poker_zkvm/src/precompiles/bn254_pairing.rs`（文件不存在）
- ⬜ Part 4：`syscalls/mod.rs` 仍为 13 变体（0x01-0x0D），`gas.rs` 未加 4 个新常量
- ⬜ Part 5：全量验证

### 关键参考模式（已确认）
- `NonNativeElement { limbs: [usize; 4] }` — 4 limb 变量（non_native.rs:L291）
- `NonNativeBuilder::alloc_element([Fr; 4])` / `from_u256(&[u64; 4])` / `element_to_u256(&elem)`
- `mul_mod(&elem, &elem, modulus: &[u64; 4])` / `add_mod` / `sub_mod` / `assert_lt` / `assert_equal`
- `scalar_mul(builder, &Point, &NonNativeElement, num_bits)` 模式（secp256k1_ops.rs:L260-381）：bit 分解 + recompose + double-and-add with started flag + select_point
- `EcdsaVerifyCircuit { curve, full_mode, scalar_num_bits }` + `new()`/`new_full()`/`new_full_with_bits(n)` + `run_full()` + 双 trait impl（ecdsa.rs）

---

## Proposed Changes

### Part 1 收尾：修复 dead_code 警告

**文件**：`poker_zkvm/src/precompiles/keccak256.rs` L70-71

```rust
#[cfg(test)]
const RATE_BITS: usize = 1088;
#[cfg(test)]
const RATE_LANES: usize = RATE_BITS / 64; // 17
```

**验证**：`cargo clippy -p poker_zkvm --all-features -- -D warnings` 无 warning。

---

### Part 2: ed25519.rs — Curve25519 Edwards 预编译

**新建文件**：`poker_zkvm/src/precompiles/ed25519.rs`

#### 2.1 常量（`[u64; 4]` LE）

```rust
// p = 2^255 - 19
const ED25519_P: [u64; 4] = [
    0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
];
// d = -121665/121666 mod p
const ED25519_D: [u64; 4] = [
    0x6623ECEE14A786D5, 0xD4118F7B7BDBA0D1,
    0x8C7AB6D1C5634A6F, 0x52036CEE2B6FFE73,
];
// 2*d mod p（预计算，用于加法公式）
const ED25519_TWO_D: [u64; 4] = [
    0x2C47D9DC294F0DAA, 0xA8231EF6F7B741A3,
    0x18F56DA38AC69C5D, 0x2406D9DC56DFFCE6,
];
// L = 2^252 + 27742317777372353535851937790883648493（基点阶）
const ED25519_L: [u64; 4] = [
    0x00000000FFFFFFED, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFE, 0x3FFFFFFFFFFFFFFF,
];
// 基点 B = (Bx, By)，By = 4/5 mod p
const ED25519_BX: [u64; 4] = [
    0x8D7F91D55C6D2661, 0x7F9C8E5AD3F8B7C1,
    0x2A3C61B4C26D7B7D, 0x216936A3CD6E5228,
];
const ED25519_BY: [u64; 4] = [
    0x6666666666666666, 0xCCCCCCCCCCCCCCCC,
    0x3333333333333333, 0x6666666666666666,
];
```

（注：常量值在实现时需用 host 端脚本验证 `By = 4/5 mod p` 和 `Bx² = (By²-1)/(d·By²+1) mod p`）

#### 2.2 EdwardsPoint + 点运算

```rust
#[derive(Clone)]
pub(crate) struct EdwardsPoint {
    pub x: NonNativeElement,
    pub y: NonNativeElement,
    pub t: NonNativeElement,
    pub z: NonNativeElement,
}

pub(crate) fn identity_point(b: &mut NonNativeBuilder) -> EdwardsPoint {
    // (0, 1, 0, 1)
    let zero = b.from_u256(&[0, 0, 0, 0]);
    let one = b.from_u256(&[1, 0, 0, 0]);
    EdwardsPoint {
        x: zero.clone(), y: one.clone(),
        t: zero, z: one,
    }
}

pub(crate) fn from_affine(b: &mut NonNativeBuilder, x: &[u64; 4], y: &[u64; 4]) -> EdwardsPoint {
    let xv = b.from_u256(x);
    let yv = b.from_u256(y);
    // T = X*Y mod p
    let tv = b.mul_mod(&xv, &yv, &ED25519_P);
    let zv = b.from_u256(&[1, 0, 0, 0]);
    EdwardsPoint { x: xv, y: yv, t: tv, z: zv }
}

// 统一加法（a=-1, extended coords）：9 mul_mod
pub(crate) fn point_add(b: &mut NonNativeBuilder, p: &EdwardsPoint, q: &EdwardsPoint) -> EdwardsPoint {
    let m = &ED25519_P;
    let a = b.mul_mod(&{ /* Y1-X1 */ }, &{ /* Y2-X2 */ }, m);  // 实现时展开 sub_mod
    // ... 9 mul_mod + 4 add/sub_mod
}

// 优化倍点：7 mul_mod
pub(crate) fn point_double(b: &mut NonNativeBuilder, p: &EdwardsPoint) -> EdwardsPoint { ... }

// double-and-add with started flag（复用 secp256k1_ops.rs:L260-381 模式）
pub(crate) fn scalar_mul(b: &mut NonNativeBuilder, p: &EdwardsPoint, k: &NonNativeElement, num_bits: usize) -> EdwardsPoint { ... }

pub(crate) fn assert_on_curve(b: &mut NonNativeBuilder, p: &EdwardsPoint) {
    // -x² + y² = 1 + d·x²·y² → y² - x² - d·x²·y² - 1 = 0
}

pub(crate) fn assert_point_equal(b: &mut NonNativeBuilder, p: &EdwardsPoint, q: &EdwardsPoint) {
    // X1*Z2 == X2*Z1 且 Y1*Z2 == Y2*Z1
}
```

**select_point / select_fr**：复用 secp256k1_ops.rs 模式（`result = if_zero + bit * (if_one - if_zero)`）。

#### 2.3 Ed25519VerifyCircuit

```rust
#[derive(Debug, Clone)]
pub struct Ed25519VerifyCircuit {
    full_mode: bool,
    scalar_num_bits: usize,
}

impl Ed25519VerifyCircuit {
    pub fn new() -> Self { Self { full_mode: false, scalar_num_bits: 0 } }
    pub fn new_full() -> Self { Self { full_mode: true, scalar_num_bits: 252 } }
    pub fn new_full_with_bits(n: usize) -> Self { Self { full_mode: true, scalar_num_bits: n } }

    // MVP: 输入 24 Fr = [P1_x(4), P1_y(4), P2_x(4), P2_y(4), P3_x(4), P3_y(4)]
    // 验证 P1 + P2 = P3
    pub fn run_mvp(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> { ... }

    // Full: 输入 20 Fr = [P_x(4), P_y(4), scalar(4), result_x(4), result_y(4)]
    // 验证 scalar · P = result
    pub fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> { ... }
}

impl PrecompileCircuit for Ed25519VerifyCircuit {
    fn name(&self) -> &str { "ed25519" }
    fn num_variables(&self) -> usize { if self.full_mode { 0 } else { 6 } }
    fn build_ccs(&self) -> Ccs { /* MVP: 7 矩阵模式（同 ecdsa MVP）*/ }
    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> { ... }
    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            GAS_ED25519_BASE + GAS_ED25519_PER_BIT * self.scalar_num_bits as u64
        } else { GAS_ED25519_BASE }
    }
}

impl CcsCircuit for Ed25519VerifyCircuit { /* 同 ecdsa 模式 */ }
```

**gas 常量**（inline 在 ed25519.rs，与 syscalls/gas.rs 对齐）：
```rust
const GAS_ED25519_BASE: u64 = 50_000;
const GAS_ED25519_PER_BIT: u64 = 8_000;
```

#### 2.4 测试

- `test_edwards_point_add_basic`：B + B = 2B（host 参考计算）
- `test_edwards_point_double`：2·B = 2B
- `test_edwards_scalar_mul_small`：3·B = 3B（num_bits=4）
- `test_ed25519_mvp_single_add`：P1 + P2 = P3 闭环
- `test_ed25519_full_scalar_mul_8bit`：k·P = result（num_bits=8）
- `test_ed25519_gas_cost`：MVP=50_000, Full(8)=114_000
- `test_ed25519_wrong_input_length`：错误处理
- `#[ignore] test_ed25519_full_252bit`：release 模式 252-bit

**host 参考计算**：使用 `non_native.rs` 的 `host_mul_mod`/`host_add_mod`/`host_sub_mod` 手算 Edwards 公式，不引入 curve25519-dalek。

#### 2.5 注册到 precompiles/mod.rs

在 `pub mod merkle_verify;` 后新增 `pub mod ed25519;`。

---

### Part 3: bn254_pairing.rs — hint-based 配对预编译

**新建文件**：`poker_zkvm/src/precompiles/bn254_pairing.rs`

#### 3.1 常量

```rust
// BN254 基域 p（254 bit）
const BN254_P: [u64; 4] = [
    0x3C208C16D87CFD47, 0x97816A916871CA8D,
    0xB85045B68181585D, 0x30644E72E131A029,
];
const BN254_B: [u64; 4] = [3, 0, 0, 0];  // y² = x³ + 3
```

#### 3.2 G1 曲线检查

```rust
// y² = x³ + 3 mod p
pub(crate) fn assert_g1_on_curve(b: &mut NonNativeBuilder, x: &NonNativeElement, y: &NonNativeElement) {
    let m = &BN254_P;
    let y_sq = b.mul_mod(y, y, m);
    let x_sq = b.mul_mod(x, x, m);
    let x_cu = b.mul_mod(&x_sq, x, m);
    let three_b = b.from_u256(&BN254_B);
    let x_cu_plus_3 = b.add_mod(&x_cu, &three_b, m);
    b.assert_equal(&y_sq, &x_cu_plus_3);
}
```

#### 3.3 Bn254PairingCircuit

```rust
#[derive(Debug, Clone)]
pub struct Bn254PairingCircuit {
    full_mode: bool,
}

impl Bn254PairingCircuit {
    pub fn new() -> Self { Self { full_mode: false } }
    pub fn new_full() -> Self { Self { full_mode: true } }

    // MVP: 输入 8 Fr = [x(4), y(4)]
    // 验证 y² = x³ + 3
    pub fn run_mvp(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> { ... }

    // Full: 输入 17 Fr = [A_x(4), A_y(4), C_x(4), C_y(4), hint(1)]
    // 验证 A,C 在 G1 上 + hint flag = 1
    pub fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> { ... }
}

impl PrecompileCircuit for Bn254PairingCircuit {
    fn name(&self) -> &str { "bn254_pairing" }
    fn gas_cost(&self) -> u64 {
        if self.full_mode { GAS_BN254_PAIRING_FULL } else { GAS_BN254_PAIRING_MVP }
    }
    // ... 其他方法
}

const GAS_BN254_PAIRING_MVP: u64 = 30_000;
const GAS_BN254_PAIRING_FULL: u64 = 80_000;
```

#### 3.4 测试

- `test_bn254_g1_on_curve`：(1, 2) 在曲线上（`4 = 1+3`）
- `test_bn254_g1_not_on_curve`：(1, 3) 不在曲线上（`9 ≠ 4`）
- `test_bn254_pairing_mvp`：MVP 闭环
- `test_bn254_pairing_full`：Full 闭环（双 G1 + hint=1）
- `test_bn254_pairing_gas_cost`：MVP=30_000, Full=80_000
- `test_bn254_pairing_wrong_input_length`：错误处理

**host 参考**：BN254 G1 生成元 (1, 2) 满足 `2² = 1³ + 3` → `4 = 4` ✓。可选使用 `ark-bn254::G1Affine` 验证更多测试点。

#### 3.5 注册到 precompiles/mod.rs

新增 `pub mod bn254_pairing;`。

---

### Part 4: Syscall + gas 注册

#### 4.1 `syscalls/mod.rs` — 13 → 15 变体

在 `MerkleVerify = 0x0D` 后新增：
```rust
Ed25519Verify = 0x0E,
Bn254Pairing = 0x0F,
```

同步更新：
- 模块文档注释（L4-5, L8-23）：`13 个 syscall` → `15 个`，新增 0x0E/0x0F 行
- `from_u32`（L99-116）：新增 `0x0E => Ed25519Verify`, `0x0F => Bn254Pairing`，错误消息范围 `0x01-0x0F`
- `all()`（L118-120）：`[Self; 13]` → `[Self; 15]`
- `SyscallRegistry.syscalls`：`[Option<...>; 13]` → `[Option<...>; 15]`
- `Debug impl`：新增 `14 => "Ed25519Verify"`, `15 => "Bn254Pairing"`
- 测试：
  - `test_from_u32_all_valid_ids`：+2 case
  - `test_from_u32_invalid_ids`：边界 `0x10`（原 `0x0E`）
  - `test_all_returns_thirteen_syscalls` → `test_all_returns_fifteen_syscalls`
  - `test_syscall_registry_dispatch_invalid_id`：边界 `0x10`

#### 4.2 `syscalls/gas.rs` — 4 个新常量 + 2 分支

```rust
pub const GAS_ZKVM_ED25519_BASE: u64 = 50_000;
pub const GAS_ZKVM_ED25519_PER_BIT: u64 = 8_000;
pub const GAS_ZKVM_BN254_PAIRING_MVP: u64 = 30_000;
pub const GAS_ZKVM_BN254_PAIRING_FULL: u64 = 80_000;
```

`syscall_gas` 新增：
```rust
SyscallId::Ed25519Verify => {
    GAS_ZKVM_ED25519_BASE + GAS_ZKVM_ED25519_PER_BIT * args.num_bits as u64
}
SyscallId::Bn254Pairing => GAS_ZKVM_BN254_PAIRING_FULL,
```

新增测试：`test_ed25519_gas_calculation`、`test_bn254_pairing_gas_calculation`。

#### 4.3 `precompiles/mod.rs` — 测试更新

- `test_phase10_registry_full`：7 → 9 预编译，新增 ed25519 + bn254_pairing 的 gas_cost 断言
- `test_phase10_all_implement_both_traits`：新增 2 个 trait 检查
- `test_phase10_gas_costs_reasonable`：新增 2 case：
  ```rust
  ("ed25519", 5_000, 100_000),        // MVP = 50_000
  ("bn254_pairing", 1_000, 100_000),  // MVP = 30_000
  ```
  以及 2 个 register 调用

---

### Part 5: 全量验证

按顺序执行：

1. **ed25519 单元测试**：
   ```bash
   cargo test -p poker_zkvm --lib precompiles::ed25519 -- --nocapture
   ```
2. **bn254_pairing 单元测试**：
   ```bash
   cargo test -p poker_zkvm --lib precompiles::bn254_pairing -- --nocapture
   ```
3. **预编译注册表测试**：
   ```bash
   cargo test -p poker_zkvm --lib precompiles::tests::test_phase10 -- --nocapture
   ```
4. **syscall gas + mod 测试**：
   ```bash
   cargo test -p poker_zkvm --lib syscalls -- --nocapture
   ```
5. **clippy 检查**：
   ```bash
   cargo clippy -p poker_zkvm --all-features -- -D warnings
   ```
6. **全量 lib 回归**：
   ```bash
   cargo test -p poker_zkvm --lib
   ```
7. **ignored 测试（release 模式）**：
   ```bash
   cargo test -p poker_zkvm --lib --release -- --ignored precompiles::ed25519 --nocapture
   ```

---

## Assumptions & Decisions

### 假设
1. NonNativeBuilder 支持任意 `[u64; 4]` 模数（已验证：`mul_mod`/`add_mod`/`sub_mod` 接受 `modulus: &[u64; 4]` 参数）
2. Curve25519 p = 2^255-19 的 top limb 仅 63 bit，`range_check_64` 和 `assert_lt` 仍正确工作（limb < 2^64 不要求 limb < p）
3. Ed25519 Full 模式的 h（SHA-512 哈希）由 host 计算，作为 public input 传入（不在电路内做 SHA-512）
4. BN254 G2 曲线验证需要 Fp2 运算（8 limb），Full 模式仅验证 G1 + hint，不验证 G2
5. `ark-bn254` workspace 依赖可用于 host 侧测试参考计算（dev-dependency 已有）

### 决策
1. **Ed25519 坐标系**：Extended twisted Edwards (X:Y:T:Z)，避免电路内模逆，统一加法公式
2. **Ed25519 MVP**：单点加法验证（P1 + P2 = P3），~18200 约束
3. **Ed25519 Full**：标量乘法（k · P = result），参数化 num_bits，252-bit ~5.6M 约束
4. **BN254 MVP**：单 G1 曲线检查（y² = x³ + 3），~4300 约束
5. **BN254 Full**：双 G1 检查 + pairing hint flag，~8600 约束
6. **Ed25519 ops inline**：不单独建 `ed25519_ops.rs`，ops 代码 inline 在 ed25519.rs（与 modexp.rs 一致）
7. **不引入 curve25519-dalek**：host 参考计算用 NonNativeBuilder 的 host 函数 + 手算 Edwards 公式
8. **RATE_BITS/RATE_LANES 修复**：加 `#[cfg(test)]` 门控（精确匹配使用点）
9. **SyscallId 扩展 13→15**：0x0E = Ed25519Verify，0x0F = Bn254Pairing
10. **gas 公式**：Ed25519 = `BASE + PER_BIT * num_bits`（与 modexp 一致），BN254 = 固定值

### 未选择方案
- 引入 curve25519-dalek 依赖（用户选择 NonNativeBuilder 自实现）
- 完整 BN254 pairing 电路（~100M+ 约束不实际，stage4 计划推荐 hint-based）
- ed25519_ops.rs 独立文件（ops 仅被 ed25519.rs 使用，inline 避免过度抽象）
- Ed25519 Full 完整验签（含 SHA-512）（SHA-512 电路是独立大工程，本次 Full 仅做标量乘）

---

## 约束数与 gas 汇总

| 预编译 | 模式 | mul_mod 数 | 约束数 | gas |
|--------|------|-----------|--------|-----|
| ed25519 | MVP（单点加） | ~13 | ~18200 | 50_000 |
| ed25519 | Full(252-bit) | ~4032 | ~5.6M | 2_066_000 |
| ed25519 | Full(8-bit, 测试) | ~128 | ~179K | 114_000 |
| bn254_pairing | MVP（G1 检查） | ~3 | ~4300 | 30_000 |
| bn254_pairing | Full（双 G1 + hint） | ~6 | ~8600 | 80_000 |

---

## 执行顺序

1. **Part 1 收尾**（~3 分钟）：修复 `RATE_BITS`/`RATE_LANES` dead_code + clippy 验证
2. **Part 2**（核心）：创建 ed25519.rs — 常量 + EdwardsPoint + 点运算 + 电路 + 测试 + 注册
3. **Part 3**：创建 bn254_pairing.rs — 常量 + G1 检查 + 电路 + 测试 + 注册
4. **Part 4**：syscalls/mod.rs (13→15) + gas.rs (4 常量) + precompiles/mod.rs 测试 (7→9)
5. **Part 5**：全量验证（7 步）

## Verification Steps

- 每完成一个 Part，立即运行该 Part 的单元测试
- Part 5 执行 7 步全量验证，所有测试通过且 clippy 无 warning 才视为完成
- ignored 测试（252-bit ed25519）在 release 模式下手动验证
