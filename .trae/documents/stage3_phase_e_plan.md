# Stage 3 — Phase E: ECDSA Full Circuit 实施计划

## Summary

Phase E 将 MVP ECDSA 电路（仅 double-and-add 单步约束）扩展为完整 ECDSA 验签电路，
实现 `s·R' = z·G + r·P` 验证等式。分 4 步执行：E1 验证非原生域算术修复 →
E2 创建 secp256k1 点运算电路 → E3 扩展 ECDSA 电路为双模式 → E4 模块注册与全量验证。

## Current State Analysis

### 已完成
- [non_native.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/non_native.rs) — 非原生域算术（E1 修复中）
  - `NonNativeBuilder`: add_mod, sub_mod, mul_mod, assert_lt, assert_equal, range_check_64
  - `host_div_mod` overflow 修复已应用（track MSB before shift），**测试尚未重新运行**
  - 9 个测试（3 个之前失败：test_host_mul_mod, test_host_inv_mod, test_nonnative_mul_mod_large）
- [ecdsa.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/ecdsa.rs) — MVP ECDSA 电路（368 行，12 测试通过）
  - 仅约束 double-and-add 单步（bit, R, P, bit_P, R_new）
  - 不含完整标量乘、曲线运算、验证等式
- [sha256.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/sha256.rs) — FullBuilder 模式参考（Phase B 完成）
  - 双模式：`new()` (MVP) + `new_full()` (完整 64-round)
  - `FullBuilder { ccs: CcsBuilder, witness: Vec<Fr> }` 组合模式
- [ccs_builder.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/ccs_builder.rs) — CcsBuilder API
  - `add_multiplication(row, a, b, result)`, `add_linear(row, &[(col, coeff)])`, `add_bit_check(row, col)`
  - 变量 0 = 常数 1, alloc_var 从 1 开始
- [mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs) — 已声明 `pub mod non_native;`，未声明 `secp256k1_ops`

### 关键约束
- BN254 Fr ≈ 2^254，secp256k1 p_curve ≈ 2^256 和 n ≈ 2^256 均超出 Fr → 需 4-limb 非原生表示
- 每个 mul_mod ≈ 1400 约束（8 limb 范围检查 × 65 + carry 链 + r < modulus 范围检查）
- 完整 256-bit ECDSA ≈ 3 × 256 × 16 mul_mod ≈ 17M+ 约束 → 测试用小 scalar_num_bits
- `Ccs::satisfied_by` 有 row-isolated 快速路径（所有矩阵 ≤1 entry 时触发），CcsBuilder 保证此性质

### host_div_mod 修复正确性分析

修复后的逻辑（track overflow before shift）：
```rust
let overflow = remainder[3] >> 63;  // shift 前 MSB
// shift left...
if overflow > 0 || !host_lt(&remainder, divisor) { subtract... }
```

**正确性证明**：当 overflow > 0 时，`shifted = true_shifted - 2^256`。
由不变式 `old_remainder < divisor`，可得 `shifted < divisor`（因 `old_remainder * 2 < 2*divisor`，
`shifted = old_remainder*2 + bit - 2^256 < 2*divisor - 2^256 < divisor` 当 `divisor < 2^256`）。
因此 `host_sub(&shifted, divisor)` 必产生 borrow，返回 `shifted - divisor + 2^256 = true_remainder`。✓

## Proposed Changes

### E1: 验证 non_native.rs 修复（预计 5 分钟）

**目标**: 确认 host_div_mod overflow 修复解决 3 个失败测试。

**步骤**:
1. 运行 `cargo test -p poker_zkvm --lib non_native` — 验证全部 9 个测试通过
2. 若有失败，根据错误信息修复
3. 运行 `cargo clippy -p poker_zkvm --all-targets` — 零警告

**注意**: diagnostics 显示 `host_mul_mod`, `host_mul_big`, `host_inv_mod` 等 "never used" 警告。
这些是 `pub(crate)` 函数，仅在 `#[cfg(test)]` 中使用。若 clippy 报 dead_code，需加
`#[allow(dead_code)]` 或在测试中通过 `#[allow(dead_code)]` 作用域抑制。但实际上这些函数
被 NonNativeBuilder 的方法（mul_mod 等）间接调用，不应触发 dead_code。若触发，检查是否
NonNativeBuilder 本身被标记为 never used（因目前无外部消费者），需加 `#[allow(dead_code)]`
到 NonNativeBuilder 和 NonNativeElement 上，待 E2/E3 消费后移除。

### E2: 创建 secp256k1_ops.rs（预计 60 分钟）

**目标**: 实现 secp256k1 点运算电路，为 E3 提供基础。

**文件**: `poker_zkvm/src/precompiles/secp256k1_ops.rs`（新建）

**设计**:

#### Point 结构（Jacobian 坐标）
```rust
#[derive(Clone)]
pub(crate) struct Point {
    x: NonNativeElement,  // mod p_curve
    y: NonNativeElement,  // mod p_curve
    z: NonNativeElement,  // mod p_curve (Z=0 表示无穷远点)
}
```

#### 方法清单

1. **`identity_point(builder) -> Point`**
   - 返回 (1, 1, 0) — Jacobian 无穷远点

2. **`from_affine(builder, x: &[u64;4], y: &[u64;4]) -> Point`**
   - 创建仿射点 (x, y, 1)

3. **`point_double(builder, P: &Point) -> Point`**
   - secp256k1 的 a=0，Jacobian 倍点公式：
     - A = X² (1 mul_mod)
     - B = Y² (1 mul_mod)
     - C = B² (1 mul_mod, 即 Y⁴)
     - D = 2*((X+B)² - A - C) (1 mul_mod for (X+B)², rest add/sub)
     - E = 3*A (add only)
     - F = E² (1 mul_mod)
     - X3 = F - 2*D (sub only)
     - Y3 = E*(D - X3) - 8*C (1 mul_mod)
     - Z3 = 2*Y*Z (1 mul_mod)
   - 总计 ~6 mul_mod + ~10 add_mod/sub_mod
   - **正确性**: Z=0 时，所有含 Z 的项为 0，X3=F-2D, Y3=E*(D-X3)-8C, 但 B=Y²=0, C=0, D=2*((X+0)²-A-0)=0, F=E²=9A², X3=9A², Y3=3A*(0-9A²)=-27A³, Z3=0 → 仍为无穷远点 ✓

4. **`point_add(builder, P: &Point, Q: &Point) -> Point`**
   - 标准非统一 Jacobian 加法（假设 P ≠ ±Q，两者均非无穷远点）：
     - U1 = X1*Z2², S1 = Y1*Z2³ (2 mul_mod)
     - U2 = X2*Z1², S2 = Y2*Z1³ (2 mul_mod)
     - H = U1 - U2 (sub_mod)
     - H2 = H², H3 = H*H2 (2 mul_mod)
     - r = S1 - S2 (sub_mod)
     - V = U1*H2 (1 mul_mod)
     - X3 = r² - H3 - 2*V (1 mul_mod for r²)
     - Y3 = r*(V - X3) - S1*H3 (2 mul_mod)
     - Z3 = Z1*Z2*H (2 mul_mod: Z1*Z2 first, then *H)
   - 总计 ~12 mul_mod + ~6 add_mod/sub_mod
   - **不处理** P=±Q 和无穷远点（由 scalar_mul 的 "started" flag 避免）

5. **`scalar_mul(builder, P: &Point, scalar: &[u64;4], num_bits: usize) -> Point`**
   - Double-and-add with "started" flag:
     ```
     R = identity, started = 0
     for i in (0..num_bits).rev():
         if started: R = point_double(R)
         bit = (scalar[i/64] >> (i%64)) & 1
         if bit:
             if started: R = point_add(R, P)
             else: R = P, started = 1
     ```
   - 电路实现：
     - `started` 是一个 bit 变量（bit_check 约束）
     - `bit_i` 是标量的第 i 位（bit_check 约束）
     - 条件选择：
       - `should_double = started`（如果 started=0，跳过 doubling）
       - `should_add = started AND bit_i`（如果未 started，直接赋值 P）
       - 使用 conditional_select(pattern) 选择结果
   - **简化**: 为避免复杂的条件分支，采用 "always compute, then select" 策略：
     - 始终计算 double_result = point_double(R) 和 add_result = point_add(double_result, P)
     - 但 point_double(identity) = identity（已验证），point_add(identity, P) 不可用
     - 替代：当 started=0 时，double_result = identity（正确），需要 conditional_set(R, P) when bit=1
   - **最终方案**: 使用 4-way 条件选择：
     - case 0: started=0, bit=0 → R = identity
     - case 1: started=0, bit=1 → R = P, started_next=1
     - case 2: started=1, bit=0 → R = point_double(R)
     - case 3: started=1, bit=1 → R = point_add(point_double(R), P)
     - 使用 bit_check + multiplication 实现 selector

6. **`assert_on_curve(builder, P: &Point)`**
   - Jacobian 曲线方程: Y² = X³ + 7 (a=0)
   - 齐次形式: Y²*Z⁶ = X³*Z⁶ + 7*Z⁶? 不对。
   - 正确的齐次形式: y² = x³ + 7 其中 (x,y) = (X/Z², Y/Z³)
   - → Y²/Z⁶ = X³/Z⁶ + 7 → Y² = X³ + 7*Z⁶
   - 约束: Y² - X³ - 7*Z⁶ = 0 (mod p_curve)
   - 计算: lhs = y² (1 mul_mod), x³ = x²*x (2 mul_mod), z⁶ = z²*z⁴ (2 mul_mod), 7*z⁶ (1 mul_mod)
   - 总计 ~6 mul_mod + ~3 add_mod/sub_mod

7. **`assert_point_equal(builder, P: &Point, Q: &Point)`**
   - Jacobian 相等: X1*Z2² = X2*Z1² 且 Y1*Z2³ = Y2*Z1³
   - 计算 4 个 mul_mod + 2 assert_equal

#### 测试（≥6 个）
- `test_identity_double` — doubling identity = identity
- `test_point_double_basic` — 2*G 的坐标与 secp256k1 crate 一致
- `test_point_add_basic` — G + G 应等于 2*G（但用 point_add 而非 point_double，用 2G 和 G 验证 3G）
- `test_scalar_mul_small` — 3*G = G + G + G，用 num_bits=4
- `test_assert_on_curve` — G 在曲线上
- `test_assert_point_equal` — 2*G == point_double(G)
- `test_scalar_mul_consistency` — k*G 与 secp256k1 crate 一致（k=5, num_bits=4）

测试使用 `num_bits=8` 小标量，通过 `ccs.satisfied_by(&witness)` 验证约束满足。
每个 mul_mod ≈ 1400 约束，8-bit scalar_mul ≈ 8*(6+12)*1400 ≈ 200K 约束，可接受。

### E3: 扩展 ecdsa.rs 为双模式（预计 45 分钟）

**目标**: 在 ecdsa.rs 中添加完整 ECDSA 验签模式。

**文件**: `poker_zkvm/src/precompiles/ecdsa.rs`（修改）

**设计**:

#### 结构扩展
```rust
#[derive(Debug, Clone)]
pub struct EcdsaVerifyCircuit {
    curve: &'static str,
    full_mode: bool,
    scalar_num_bits: usize,  // 仅 full_mode 使用
}
```

#### 新增方法
- `new_full() -> Self` — 完整模式，默认 scalar_num_bits=256
- `new_full_with_bits(num_bits: usize) -> Self` — 完整模式，可配置位数（用于测试）
- `is_full_mode(&self) -> bool`
- `scalar_num_bits(&self) -> usize`

#### PrecompileCircuit trait 扩展
- `num_variables()`: full_mode 时返回动态值（取决于 scalar_num_bits），MVP 时返回 6
- `build_ccs()`: full_mode 时调用 `run_full()` 构建 CCS，MVP 时用现有逻辑
- `assign_witness()`: full_mode 时接受 [s, r, z, px, py, ry]（6 个 [u64;4] 展开为 24 Fr），MVP 时接受 [bit, R, P]
- `gas_cost()`: full_mode 返回 3_000_000（完整 ECDSA 验签），MVP 返回 100_000

#### run_full() 实现
ECDSA 验证等式: `s·R' = z·G + r·P`

1. **输入解析**:
   - s, r, z: 标量域元素 [u64;4]（mod n）
   - P = (px, py): 公钥仿射坐标 [u64;4]×2（mod p_curve）
   - ry: R' 的 y 坐标 hint [u64;4]（mod p_curve）
   - r 同时作为 R' 的 x 坐标

2. **构建步骤**:
   a. 创建 NonNativeBuilder
   b. 分配 s, r, z, px, py, ry 为 NonNativeElement
   c. 范围检查所有输入 < 各自模数（s,r,z < n; px,py,ry < p_curve）
   d. 构造 R' = (r, ry, 1)（Jacobian），assert_on_curve(R')
   e. 构造 P = (px, py, 1)，assert_on_curve(P)
   f. 构造 G = (GX, GY, 1)
   g. sR = scalar_mul(R', s, scalar_num_bits) — 注意标量是 s（mod n），但点坐标是 mod p_curve
   h. zG = scalar_mul(G, z, scalar_num_bits)
   i. rP = scalar_mul(P, r, scalar_num_bits)
   j. rhs = point_add(zG, rP)
   k. assert_point_equal(sR, rhs)

3. **标量处理**: s, r, z 是 [u64;4] 值，scalar_mul 需要其 bit 分解。
   - 直接 bit_decompose 每个 limb（4 × 64 = 256 bits）
   - 使用低 scalar_num_bits 位

4. **MVP 向后兼容**: `new()` 保持现有行为不变

#### 测试（≥8 个）
- `test_ecdsa_full_build_ccs` — 构建 CCS 不 panic
- `test_ecdsa_full_satisfied_valid` — 有效签名满足约束（scalar_num_bits=4，使用 secp256k1 crate 生成真实签名）
- `test_ecdsa_full_satisfied_invalid` — 无效签名不满足约束
- `test_ecdsa_full_tampered_s` — 篡改 s → 失败
- `test_ecdsa_full_tampered_r` — 篡改 r → 失败
- `test_ecdsa_full_tampered_z` — 篡改 z → 失败
- `test_ecdsa_full_tampered_pubkey` — 篡改公钥 → 失败
- `test_ecdsa_full_wrong_ry` — 错误 ry hint → assert_on_curve 失败
- `test_ecdsa_full_mvp_backward_compat` — new() 仍为 MVP 模式
- `test_ecdsa_full_gas_cost` — full_mode gas = 3_000_000

**测试策略**: 使用 `scalar_num_bits=4` 生成真实 ECDSA 签名（取低 4 位标量），
验证 `ccs.satisfied_by(&witness)`。预计 ~3*4*16*1400 ≈ 270K 约束，可接受。

**关键注意**: 测试中生成签名时，需确保 s, r, z 的低 4 位非零（否则 scalar_mul 退化为 identity）。
使用 secp256k1 crate 签名后取 mod 2^4。

### E4: 模块注册与全量验证（预计 15 分钟）

**步骤**:
1. 在 [mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs) 添加 `pub mod secp256k1_ops;`
2. 运行 `cargo build -p poker_zkvm` — 编译通过
3. 运行 `cargo test -p poker_zkvm --lib` — 所有 lib 测试通过
4. 运行 `cargo clippy -p poker_zkvm --all-targets` — 零警告
5. 运行 `cargo test -p poker_zkvm --test '*'` — 集成测试通过
6. 运行 `cargo bench -p poker_zkvm --no-run` — benchmark 编译通过
7. 运行 `cargo test -p poker_l1 --lib` — poker_l1 回归测试通过（1276 测试）

## Assumptions & Decisions

1. **k=4 b=64 limbs**: 64×64=128 < 254 (BN254 Fr)，在 Fr 中精确计算。已实现于 non_native.rs。
2. **Jacobian 坐标**: 避免标量乘中的模逆。无穷远点 Z=0。
3. **s·R' = z·G + r·P**: 避免 in-circuit 计算 s⁻¹ mod n。R' = (r, ry)，ry 为 hint，通过 assert_on_curve 验证。
4. **scalar_num_bits 可配置**: 完整模式默认 256 位，测试用 4-8 位。约束数 ~3 * num_bits * 16 * 1400。
5. **"started" flag**: scalar_mul 中跟踪是否已遇到第一个 1 bit，避免 point_add 处理无穷远点。
6. **MVP 向后兼容**: `new()` 保持现有行为，`new_full()` 启用完整模式。
7. **gas_cost**: full_mode = 3_000_000（高于 MVP 的 100_000，反映完整验证开销）。
8. **标量 bit 分解**: 标量 s/r/z 是 [u64;4]，直接 bit_decompose（64 bit_check per limb + recompose），取低 scalar_num_bits 位。
9. **NonNativeBuilder dead_code**: E1 阶段可能需 `#[allow(dead_code)]`，E2/E3 消费后移除。
10. **不实现 constant-time**: ZK 电路中不需要恒定时间操作，条件选择通过 bit_check + multiplication 实现。

## Verification Steps

### E1 验证
```bash
cargo test -p poker_zkvm --lib non_native    # 全部 9 测试通过
cargo clippy -p poker_zkvm --all-targets     # 零警告
```

### E2 验证
```bash
cargo test -p poker_zkvm --lib secp256k1_ops # 全部 ≥6 测试通过
cargo clippy -p poker_zkvm --all-targets     # 零警告
```

### E3 验证
```bash
cargo test -p poker_zkvm --lib ecdsa         # MVP 12 + full ≥8 = ≥20 测试通过
cargo clippy -p poker_zkvm --all-targets     # 零警告
```

### E4 验证（全量）
```bash
cargo build -p poker_zkvm                    # 编译通过
cargo test -p poker_zkvm --lib               # 所有 lib 测试通过
cargo test -p poker_zkvm --test '*'          # 集成测试通过
cargo clippy -p poker_zkvm --all-targets     # 零警告
cargo bench -p poker_zkvm --no-run           # benchmark 编译通过
cargo test -p poker_l1 --lib                 # poker_l1 回归（1276 测试）
```

## Execution Order

按 E1 → E2 → E3 → E4 顺序执行，每步完成后运行局部测试确认通过再进入下一步。
