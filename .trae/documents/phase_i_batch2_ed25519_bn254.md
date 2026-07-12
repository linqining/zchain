# Phase I Batch 2 — ed25519 + bn254 pairing 预编译

## Summary

完成 Phase I Batch 1 收尾（1 个测试更新 + 验证），然后实现 Phase I Batch 2 的两个新预编译电路：
- **ed25519**：基于 NonNativeBuilder 自实现 Curve25519 Edwards 曲线点运算 + 验签电路（MVP 单点加 + Full 标量乘）
- **bn254_pairing**：hint-based 配对验证电路（MVP G1 曲线检查 + Full 配对等式 hint 验证）

达到 8/8 预编译覆盖（poseidon/sha256/ecdsa/keccak256/modexp/merkle_verify/ed25519/bn254_pairing）。

## Current State Analysis

### Phase I Batch 1 状态（~95% 完成）
- ✅ Step 1-3：keccak256 测试修复、syscalls/mod.rs（13 变体）、syscalls/gas.rs（5 常量）
- 🔄 Step 4：`test_phase10_registry_full` + `test_phase10_all_implement_both_traits` 已更新；`test_phase10_gas_costs_reasonable`（precompiles/mod.rs:L427-449）仍只有 4 个 case，需新增 3 个 + 3 个 register
- ⬜ Step 5：全量验证未运行

### 可复用模式
- **NonNativeBuilder**（`non_native.rs`）：支持任意 `[u64; 4]` 模数，提供 `mul_mod`/`add_mod`/`sub_mod`/`assert_lt`/`assert_equal`，每个 `mul_mod` ~1400 约束
- **secp256k1_ops.rs 模式**：`Point{x,y,z}` + `point_double`/`point_add`/`scalar_mul`/`assert_on_curve`/`assert_point_equal`，`pub(crate)` 可见性
- **EcdsaVerifyCircuit 模式**（`ecdsa.rs`）：`{full_mode, scalar_num_bits}` + `new()`/`new_full()`/`new_full_with_bits(n)` + `run_mvp()`/`run_full()` + 双 trait 实现
- **ModexpCircuit 模式**（`modexp.rs`）：MVP 单操作 + Full 参数化，辅助函数 inline

### 关键数学参数

**Curve25519 / Ed25519**（twisted Edwards, a = -1）：
- 曲线方程：`-x² + y² = 1 + d·x²·y²`
- `p = 2^255 - 19`，`[u64;4] LE = [0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF]`
- `d = -121665/121666 mod p = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3`
- `L = 2^252 + 27742317777372353535851937790883648493`（基点阶）
- 基点 B：`By = 4/5 mod p`，`Bx` 从曲线方程恢复
- Extended 坐标 (X:Y:T:Z)，`x = X/Z`，`y = Y/Z`，`T = XY/Z`

**BN254**：
- `p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`（254 bit）
- `[u64;4] LE = [0x3C208C16D87CFD47, 0x97816A916871CA8D, 0xB85045B68181585D, 0x30644E72E131A029]`
- G1 曲线：`y² = x³ + 3 (mod p)`
- G2 曲线：`y'² = x'³ + 3/(9+u) (mod p²)` — Fp2 运算复杂，Full 模式仅 hint 验证

### 不在本次范围
- host syscall 实现（`Keccak256Syscall`/`Ed25519Syscall` 等）— 独立关注点
- SHA-512 电路（Ed25519 Full 的 h 哈希由 host 计算，作为 public input 传入）
- 完整 BN254 pairing 约束（~100M+ 约束不实际，用 hint-based）
- ed25519_ops 独立文件 — ops 代码 inline 在 ed25519.rs（与 modexp.rs 一致，避免过度抽象）

---

## Proposed Changes

### Part 1: Phase I Batch 1 收尾

#### 1.1 更新 `test_phase10_gas_costs_reasonable`

**文件**：`poker_zkvm/src/precompiles/mod.rs`（L427-449）

`cases` 数组新增 3 项，`registry` 新增 3 个 register：

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
registry.register(Box::new(poseidon::PoseidonCircuit::new()));
registry.register(Box::new(sha256::Sha256Circuit::new()));
registry.register(Box::new(ecdsa::EcdsaVerifyCircuit::new()));
registry.register(Box::new(zk_shuffle::ZkShuffleCcsCircuit::new()));
registry.register(Box::new(keccak256::Keccak256Circuit::new()));
registry.register(Box::new(modexp::ModexpCircuit::new()));
registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));
```

#### 1.2 运行 Step 5 全量验证

按 `phase_i_batch1_completion.md` Step 5 的 8 步顺序执行：
1. keccak256 单元测试（已通过）
2. modexp 单元测试
3. merkle_verify 单元测试
4. precompiles::tests::test_phase10
5. syscalls::gas + syscalls::tests（已通过）
6. clippy 检查
7. 全量 lib 回归
8. ignored 测试（release 模式）

---

### Part 2: ed25519 预编译

#### 2.1 新建 `poker_zkvm/src/precompiles/ed25519.rs`

**结构**（参照 ecdsa.rs + secp256k1_ops.rs 模式）：

```
ed25519.rs
├── 常量（ED25519_P, ED25519_D, ED25519_L, ED25519_BX, ED25519_BY）
├── EdwardsPoint { x, y, t, z: NonNativeElement }  // extended coords
├── 辅助函数
│   ├── identity_point() → EdwardsPoint  // (0, 1, 0, 1)
│   ├── from_affine(x, y) → EdwardsPoint  // (x, y, x*y, 1)
│   ├── point_add(p, q) → EdwardsPoint   // 统一加法（含倍点）
│   ├── point_double(p) → EdwardsPoint   // 优化倍点（7 mul_mod）
│   ├── scalar_mul(p, k, num_bits) → EdwardsPoint  // double-and-add
│   ├── assert_on_curve(p)               // -x²+y² = 1+d·x²·y²
│   └── assert_point_equal(p, q)
├── Ed25519VerifyCircuit { full_mode, scalar_num_bits }
│   ├── new() → MVP（单点加法验证）
│   ├── new_full() → 252-bit 标量乘
│   ├── new_full_with_bits(n) → 自定义位数
│   ├── run_mvp(inputs) → (Ccs, witness)
│   ├── run_full(inputs) → (Ccs, witness)
│   └── PrecompileCircuit + CcsCircuit impl
└── tests
```

**Edwards 加法公式**（a = -1, extended coords, 统一公式）：

```
A = (Y1-X1) * (Y2-X2)       // 1 mul_mod
B = (Y1+X1) * (Y2+X2)       // 1 mul_mod
C = T1 * T2                 // 1 mul_mod
D = Z1 * Z2                 // 1 mul_mod
kC = (2*d) * C              // 1 mul_mod（2d 预计算常量）
E = B - A                   // sub_mod
F = D - kC                  // sub_mod
G = D + kC                  // add_mod
H = B + A                   // add_mod
X3 = E * F                  // 1 mul_mod
Y3 = G * H                  // 1 mul_mod
T3 = E * H                  // 1 mul_mod
Z3 = F * G                  // 1 mul_mod
// 共 9 mul_mod ≈ 12600 约束
```

**Edwards 倍点公式**（a = -1, 优化版）：

```
A = X1²                     // 1 mul_mod
B = Y1²                     // 1 mul_mod
C = 2 * Z1²                 // 1 mul_mod
D = -A  (a=-1, 仅取反)      // 0 mul_mod
E = (X1+Y1)² - A - B       // 1 mul_mod
G = D + B                   // add_mod
F = G - C                   // sub_mod
H = D - B                   // sub_mod
X3 = E * F                  // 1 mul_mod
Y3 = G * H                  // 1 mul_mod
T3 = E * H                  // 1 mul_mod
Z3 = F * G                  // 1 mul_mod
// 共 7 mul_mod ≈ 9800 约束
```

**标量乘法**（double-and-add with started flag，复用 secp256k1_ops.rs:L260-381 模式）：
- 每个 bit：1 point_double (7 mul_mod) + 1 point_add (9 mul_mod) + select 约束
- n-bit 标量乘：~n × 16 mul_mod ≈ n × 22400 约束
- 252-bit Full：~5.6M 约束

**MVP 模式**（`run_mvp`）：
- 输入 20 Fr：`[P1_x(4), P1_y(4), P2_x(4), P2_y(4), P3_x(4)]` — 不，需要 P3_y 也
- 实际输入 24 Fr：`[P1_x(4), P1_y(4), P2_x(4), P2_y(4), P3_x(4), P3_y(4)]`
- 验证：`P1 + P2 = P3`（Edwards 统一加法）
- 约束数：~12600 + assert_point_equal (~5600) ≈ 18200

**Full 模式**（`run_full`）：
- 输入 16 Fr：`[P_x(4), P_y(4), scalar(4), result_x(4)]` — 需要 result_y
- 实际输入 20 Fr：`[P_x(4), P_y(4), scalar(4), result_x(4), result_y(4)]`
- 验证：`scalar · P = result`
- 标量模数用 `ED25519_L`（但 bit 分解只取低 num_bits 位，不需要标量模运算）
- 约束数：~num_bits × 22400

**gas_cost**：
```rust
const GAS_ED25519_BASE: u64 = 50_000;
const GAS_ED25519_PER_BIT: u64 = 8_000;

fn gas_cost(&self) -> u64 {
    if self.full_mode {
        GAS_ED25519_BASE + GAS_ED25519_PER_BIT * self.scalar_num_bits as u64
    } else {
        GAS_ED25519_BASE
    }
}
```

**测试**：
- `test_edwards_point_add_basic`：B + B = 2B（与 host 计算对比）
- `test_edwards_point_double`：2·B = 2B
- `test_edwards_scalar_mul_small`：3·B = 3B（num_bits=4）
- `test_ed25519_mvp_single_add`：P1 + P2 = P3 闭环
- `test_ed25519_full_scalar_mul`：k·P = result 闭环
- `test_ed25519_gas_cost`：MVP = 50_000，Full(8) = 114_000
- `test_ed25519_wrong_input_length`：错误处理
- `#[ignore] test_ed25519_full_252bit`：release 模式 252-bit

**host 参考计算**：
- 使用 `NonNativeBuilder::element_to_u256` + `non_native.rs` 的 `host_mul_mod`/`host_add_mod`/`host_sub_mod` 进行 host 侧 Edwards 运算
- 不引入外部 curve25519-dalek 依赖

#### 2.2 在 `precompiles/mod.rs` 注册

```rust
pub mod ed25519;  // L20 区域新增
```

---

### Part 3: bn254_pairing 预编译（hint-based）

#### 3.1 新建 `poker_zkvm/src/precompiles/bn254_pairing.rs`

**设计**：hint-based — 电路验证 G1 点在曲线上，配对结果由 host 计算并作为 hint 传入。

**结构**：

```
bn254_pairing.rs
├── 常量（BN254_P, BN254_B = 3）
├── assert_g1_on_curve(builder, x, y)  // y² = x³ + 3 mod p
├── Bn254PairingCircuit { full_mode }
│   ├── new() → MVP（单 G1 曲线检查）
│   ├── new_full() → Full（双 G1 检查 + 配对等式 hint）
│   ├── run_mvp(inputs) → (Ccs, witness)
│   ├── run_full(inputs) → (Ccs, witness)
│   └── PrecompileCircuit + CcsCircuit impl
└── tests
```

**MVP 模式**（`run_mvp`）：
- 输入 8 Fr：`[x(4), y(4)]`
- 验证：`y² = x³ + 3 (mod BN254_P)`
- 约束：2 mul_mod (y², x²) + 1 mul_mod (x³) + 1 mul_mod (3·Z⁶ if Jacobian, 但 affine 直接 y²=x³+3)
- 实际 affine：`y² - x³ - 3 = 0`，用 `assert_equal(y², x³ + 3)`
- 约 3 mul_mod + add/sub ≈ 4300 约束

**Full 模式**（`run_full`）：
- 输入 18 Fr：`[A_x(4), A_y(4), C_x(4), C_y(4), pairing_valid(1), ...]`
  - 实际：`[A_x(4), A_y(4), C_x(4), C_y(4)]` = 16 Fr + 1 hint = 17 Fr
  - 简化为 16 Fr + 1 hint flag
- 验证：
  1. A 在 G1 曲线上：`A_y² = A_x³ + 3`
  2. C 在 G1 曲线上：`C_y² = C_x³ + 3`
  3. hint flag = 1（host 保证 `e(A,B) = e(C,D)`，B/D 为 G2 点由 host 处理）
- 约束：2 × G1 曲线检查 + bit_check ≈ 8600 + 1 约束

**gas_cost**：
```rust
const GAS_BN254_PAIRING_MVP: u64 = 30_000;
const GAS_BN254_PAIRING_FULL: u64 = 80_000;

fn gas_cost(&self) -> u64 {
    if self.full_mode { GAS_BN254_PAIRING_FULL } else { GAS_BN254_PAIRING_MVP }
}
```

**测试**：
- `test_bn254_g1_on_curve`：BN254 生成元 (1, 2) 在曲线上
- `test_bn254_g1_not_on_curve`：(1, 3) 不在曲线上
- `test_bn254_pairing_mvp`：MVP 闭环
- `test_bn254_pairing_full`：Full 闭环（双 G1 + hint）
- `test_bn254_pairing_gas_cost`：MVP = 30_000，Full = 80_000
- `test_bn254_pairing_wrong_input_length`：错误处理

**host 参考计算**：
- BN254 G1 生成元：`(1, 2)` 满足 `2² = 1³ + 3` → `4 = 4` ✓
- 使用 `ark_bn254::G1Affine` 验证测试点（dev-dependency 已有 `ark-bn254`）

#### 3.2 在 `precompiles/mod.rs` 注册

```rust
pub mod bn254_pairing;  // L20 区域新增
```

---

### Part 4: Syscall + gas 注册

#### 4.1 `syscalls/mod.rs` — SyscallId 13 → 15 变体

在 `MerkleVerify = 0x0D` 后新增：

```rust
    /// `zkvm_ed25519_verify(msg_ptr, msg_len, sig_ptr, pubkey_ptr) -> bool` — Ed25519 验签。
    Ed25519Verify = 0x0E,
    /// `zkvm_bn254_pairing(a_ptr, b_ptr, c_ptr, d_ptr) -> bool` — BN254 配对等式验证。
    Bn254Pairing = 0x0F,
```

同步更新：
- `from_u32`：新增 `0x0E => Ed25519Verify`, `0x0F => Bn254Pairing`
- `all()`：`[Self; 13]` → `[Self; 15]`
- `SyscallRegistry.syscalls`：`[Option<...>; 13]` → `[Option<...>; 15]`
- `Debug impl`：新增 `14 => "Ed25519Verify"`, `15 => "Bn254Pairing"`
- 模块文档注释：新增 0x0E/0x0F 行
- 测试：`test_from_u32_all_valid_ids` +2 case，`test_from_u32_invalid_ids`（0x0E→0x10），`test_all_returns_thirteen_syscalls` → `test_all_returns_fifteen_syscalls`，`test_syscall_registry_dispatch_invalid_id`（0x0E→0x10）

#### 4.2 `syscalls/gas.rs` — 4 个新常量

```rust
/// `ed25519_verify` 基础 gas。
pub const GAS_ZKVM_ED25519_BASE: u64 = 50_000;
/// `ed25519_verify` 每标量位 gas。
pub const GAS_ZKVM_ED25519_PER_BIT: u64 = 8_000;
/// `bn254_pairing` MVP gas（单 G1 检查）。
pub const GAS_ZKVM_BN254_PAIRING_MVP: u64 = 30_000;
/// `bn254_pairing` Full gas（双 G1 + hint）。
pub const GAS_ZKVM_BN254_PAIRING_FULL: u64 = 80_000;
```

`syscall_gas` 新增 2 分支：

```rust
SyscallId::Ed25519Verify => {
    GAS_ZKVM_ED25519_BASE + GAS_ZKVM_ED25519_PER_BIT * args.num_bits as u64
}
SyscallId::Bn254Pairing => GAS_ZKVM_BN254_PAIRING_FULL,
```

新增测试：`test_ed25519_gas_calculation`、`test_bn254_pairing_gas_calculation`。

#### 4.3 `precompiles/mod.rs` — 测试更新

`test_phase10_registry_full`：7 → 9 预编译，新增 ed25519 + bn254_pairing 的 gas_cost 断言。

`test_phase10_all_implement_both_traits`：新增 2 个 trait 检查。

`test_phase10_gas_costs_reasonable`：新增 2 case：
```rust
("ed25519", 5_000, 100_000),        // MVP = 50_000
("bn254_pairing", 1_000, 100_000),  // MVP = 30_000
```

---

### Part 5: 全量验证

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
1. NonNativeBuilder 支持任意 `[u64; 4]` 模数（已验证：`mul_mod`/`add_mod`/`sub_mod` 國参数 modulus）
2. Curve25519 p = 2^255-19 的 top limb 仅 63 bit，`range_check_64` 和 `assert_lt` 仍正确工作
3. Ed25519 Full 模式的 h（SHA-512 哈希）由 host 计算，作为 public input 传入电路（不在电路内做 SHA-512）
4. BN254 G2 曲线验证需要 Fp2 运算（8 limb），Full 模式仅验证 G1 + hint，不验证 G2
5. `ark-bn254` workspace 依赖可用于 host 侧测试参考计算

### 决策
1. **Ed25519 坐标系**：Extended twisted Edwards (X:Y:T:Z)，避免电路内模逆，统一加法公式
2. **Ed25519 MVP**：单点加法验证（P1 + P2 = P3），~18200 约束
3. **Ed25519 Full**：标量乘法（k · P = result），参数化 num_bits，252-bit ~5.6M 约束
4. **BN254 MVP**：单 G1 曲线检查（y² = x³ + 3），~4300 约束
5. **BN254 Full**：双 G1 检查 + pairing hint flag，~8600 约束
6. **Ed25519 ops inline**：不单独建 `ed25519_ops.rs` 文件，ops 代码 inline 在 ed25519.rs（与 modexp.rs 一致）
7. **不引入 curve25519-dalek**：host 参考计算用 NonNativeBuilder 的 host 函数 + 手算 Edwards 公式
8. **SyscallId 扩展 13→15**：0x0E = Ed25519Verify，0x0F = Bn254Pairing
9. **gas 公式**：Ed25519 = `BASE + PER_BIT * num_bits`（与 modexp 一致），BN254 = 固定值

### 未选择方案
- **方案 A（未选）**：引入 curve25519-dalek 依赖 — 用户选择 NonNativeBuilder 自实现
- **方案 B（未选）**：完整 BN254 pairing 电路 — ~100M+ 约束不实际，stage4 计划推荐 hint-based
- **方案 C（未选）**：ed25519_ops.rs 独立文件 — ops 仅被 ed25519.rs 使用，inline 避免过度抽象
- **方案 D（未选）**：Ed25519 Full 完整验签（含 SHA-512）— SHA-512 电路是独立大工程，本次 Full 仅做标量乘

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

1. **Part 1**（~10 分钟）：Batch 1 收尾 — 更新 `test_phase10_gas_costs_reasonable` + Step 5 验证
2. **Part 2**（核心）：ed25519.rs — 常量 + EdwardsPoint + 点运算 + 电路 + 测试
3. **Part 3**：bn254_pairing.rs — 常量 + G1 检查 + 电路 + 测试
4. **Part 4**：syscalls/mod.rs + gas.rs + precompiles/mod.rs 注册
5. **Part 5**：全量验证
