# Phase H: ECDSA Full 256-bit 标量支持 — 执行计划

## 摘要

将 ECDSA Full 模式默认 `scalar_num_bits` 从 8 升级到 256，使 `new_full()` 生产默认支持完整 256-bit ECDSA 验签。采用 Approach A（保守直接升级）— 仅改默认值、gas 公式和测试输入，不引入新算法。`scalar_mul`（`secp256k1_ops.rs:L260`）已支持任意 `num_bits`，无需修改算法层。

**仅修改一个文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/ecdsa.rs`

## 当前状态分析（已验证）

通过阅读 `ecdsa.rs` 当前内容确认：

| 项 | 当前值 | 行号 | 目标值 |
|---|---|---|---|
| `new_full()` 默认 `scalar_num_bits` | `8` | L68 | `256` |
| `gas_cost()` Full 模式 | 固定 `3_000_000` | L277 | `75_600 × num_bits + 22_400` |
| `host_scalar_mul` 函数 | 不存在 | — | 新增（测试模块内） |
| `make_full_mode_test_inputs()` | 小标量 s=3,z=2,r=1 | L480 | 重命名为 `_small` + 新增 256-bit 版本 |
| `test_ecdsa_full_mode_constructors` 断言 | `scalar_num_bits() == 8` | L700 | `== 256` |
| `test_ecdsa_full_mode_gas_cost` 断言 | `== 3_000_000` | L726 | 新公式两个断言 |

**生产安全确认**（grep 验证）：
- `EcdsaVerifyCircuit::new_full()` 仅在 `ecdsa.rs` 测试模块内使用（L698, L711, L725, L734, L740, L748, L761, L774, L787）
- 生产注册使用 `EcdsaVerifyCircuit::new()`（MVP 模式）— `mod.rs` L342, L382, L405, L442
- 修改 `new_full()` 默认值不影响生产路径

**算法层确认**（已阅读 `secp256k1_ops.rs`）：
- `scalar_mul(builder, p, scalar, num_bits)`（L260-381）通过 bit 分解 + double-and-add 支持任意 `num_bits`
- recompose 约束（L282-320）对 `num_bits/64` 个完整 limb + `num_bits%64` 个剩余 bit 添加线性约束
- 256-bit 时：4 个完整 limb + 0 个剩余 bit，约束逻辑正确

**Host 辅助函数确认**（已阅读 `non_native.rs`）：
- `host_add_mod`, `host_sub_mod`, `host_mul_mod`, `host_inv_mod`, `host_lt`, `host_sub` 均已存在
- `SECP256K1_N`（标量域模数）在 L46 定义
- `SECP256K1_GX`, `SECP256K1_GY`（生成元）在 L54, L62 定义

## 实现步骤

### H-1: 修改 `new_full()` 默认值 (L62-69)

**修改**：
```rust
// L62-69
pub fn new_full() -> Self {
    Self {
        curve: "secp256k1",
        full_mode: true,
        scalar_num_bits: 256,  // 8 → 256
    }
}
```

**更新模块文档注释**（L25）：
```
//! 测试使用 `scalar_num_bits=8`（截断标量到低 8 位）以控制约束规模。
```
改为：
```
//! 生产默认 256-bit 完整标量；快速测试使用 `new_full_with_bits(8)` 截断到低 8 位。
```

### H-2: 修改 `gas_cost()` 公式 (L272-283)

**修改** Full 模式分支：
```rust
fn gas_cost(&self) -> u64 {
    if self.full_mode {
        // 3 次 scalar_mul(num_bits) + 1 次 point_add + assert_point_equal
        // per_bit: 3 × 25200 = 75600；fixed: 16800 + 5600 = 22400
        let per_bit_gas: u64 = 75_600;
        let fixed_gas: u64 = 22_400;
        per_bit_gas * self.scalar_num_bits as u64 + fixed_gas
    } else {
        100_000
    }
}
```

| num_bits | gas_cost |
|----------|----------|
| 8 | 627,200 |
| 256 | 19,376,000 |

### H-3: 添加 `host_scalar_mul` 函数（测试模块内，L434 `host_to_affine` 之后）

Host 端 double-and-add 标量乘法，匹配电路 `scalar_mul` 逻辑（含 "started" 标志避免无穷远点问题）。

```rust
/// Host 端标量乘法：scalar · P（double-and-add，匹配电路 scalar_mul 逻辑）。
///
/// 从高位到低位迭代 256 位，使用 "started" 标志避免对无穷远点调用 point_add。
fn host_scalar_mul(scalar: &[u64; 4], p: &HostPoint) -> HostPoint {
    let mut result = ([1u64, 0, 0, 0], [1u64, 0, 0, 0], [0u64, 0, 0, 0]); // 无穷远点
    let mut started = false;

    for bit_idx in (0..256).rev() {
        if started {
            result = host_point_double(&result);
        }
        let limb_idx = bit_idx / 64;
        let bit_in_limb = bit_idx % 64;
        let bit = (scalar[limb_idx] >> bit_in_limb) & 1;
        if bit == 1 {
            if started {
                result = host_point_add(&result, p);
            } else {
                result = *p;
                started = true;
            }
        }
    }
    result
}
```

### H-4: 重命名 + 新增测试输入函数

**1. 重命名** `make_full_mode_test_inputs()`（L480）→ `make_full_mode_test_inputs_small()`

保留小标量 s=3, z=2, r=1 给 8-bit 快速测试。更新函数文档注释说明用途。

**2. 新增** `make_full_mode_test_inputs()` — 真实 256-bit ECDSA 签名：

测试向量（d=1, z=1, k=2）：
- 私钥 `d = 1`，消息哈希 `z = 1`，nonce `k = 2`
- 公钥 `P = d·G = G`（生成元）
- nonce 点 `R = k·G = 2·G`
- `r = R.x mod n`（256-bit 签名分量）
- `s = k⁻¹·(z + r·d) mod n`（256-bit 签名分量）
- 验证等式：`s·R' = z·G + r·P` ⟺ `(1+r)·G = (1+r)·G` ✓

```rust
fn make_full_mode_test_inputs() -> Vec<Fr> {
    let n = &SECP256K1_N;
    let g = host_from_affine(&SECP256K1_GX, &SECP256K1_GY);

    // d = 1, z = 1, k = 2
    let d: [u64; 4] = [1, 0, 0, 0];
    let z: [u64; 4] = [1, 0, 0, 0];
    let k: [u64; 4] = [2, 0, 0, 0];

    // P = d·G = G
    let p_point = host_scalar_mul(&d, &g);
    let (px, py) = host_to_affine(&p_point);

    // R = k·G = 2·G
    let r_point = host_scalar_mul(&k, &g);
    let (r_x, _r_y) = host_to_affine(&r_point);

    // r = R.x mod n
    let r = if host_lt(&r_x, n) { r_x } else { host_sub(&r_x, n).0 };
    debug_assert!(host_lt(&r, n), "r < n");

    // ry = R.y（hint，用于构造 R' = (r, ry)）
    let ry = _r_y;

    // s = k⁻¹ · (z + r·d) mod n = k⁻¹ · (1 + r) mod n
    let k_inv = host_inv_mod(&k, n);
    let z_plus_rd = host_add_mod(&z, &r, n); // z + r·d = 1 + r (d=1)
    let s = host_mul_mod(&k_inv, &z_plus_rd, n);

    let mut inputs: Vec<Fr> = Vec::with_capacity(24);
    inputs.extend(u256_to_fr_vec(&s));       // s (4 limbs)
    inputs.extend(u256_to_fr_vec(&r));       // r (4 limbs)
    inputs.extend(u256_to_fr_vec(&ry));      // ry (4 limbs)
    inputs.extend(u256_to_fr_vec(&z));       // z (4 limbs)
    inputs.extend(u256_to_fr_vec(&px));      // px (4 limbs)
    inputs.extend(u256_to_fr_vec(&py));      // py (4 limbs)
    inputs
}
```

**3. 更新 import**（L319-321）：添加 `host_lt`, `host_sub`, `SECP256K1_N`

```rust
use crate::precompiles::non_native::{
    host_add_mod, host_sub_mod, host_mul_mod, host_inv_mod, host_lt, host_sub,
    SECP256K1_P_CURVE, SECP256K1_N,
};
```

### H-5: 更新现有测试

**需要更新的测试**（6 个）：

| 测试 | 行号 | 修改内容 |
|------|------|----------|
| `test_ecdsa_full_mode_constructors` | L693 | 断言 `scalar_num_bits() == 8` → `== 256`（L700） |
| `test_ecdsa_full_mode_basic_satisfied` | L708 | `new_full()` → `new_full_with_bits(8)`，`make_full_mode_test_inputs()` → `make_full_mode_test_inputs_small()` |
| `test_ecdsa_full_mode_gas_cost` | L721 | 断言改为：256-bit `gas_cost() == 19_376_000` + 8-bit `new_full_with_bits(8).gas_cost() == 627_200` |
| `test_ecdsa_full_mode_tampered_s` | L747 | `new_full()` → `new_full_with_bits(8)` + `make_full_mode_test_inputs_small()` |
| `test_ecdsa_full_mode_tampered_r` | L760 | 同上 |
| `test_ecdsa_full_mode_tampered_px` | L773 | 同上 |

**不需要修改的测试**（4 个使用 `new_full()` 但逻辑不变）：
- `test_ecdsa_full_mode_num_variables`（L730）— 仅检查 `num_variables() == 0`
- `test_ecdsa_full_mode_invalid_input_length`（L739）— 仅检查输入长度错误（`run_full` 先检查长度再执行 scalar_mul）
- `test_ecdsa_full_mode_assign_witness_error`（L786）— 仅检查 full_mode 返回错误
- `test_ecdsa_full_mode_mvp_backward_compatible`（L793）— 使用 `new()` MVP 模式

### H-6: 添加 4 个新测试

在测试模块末尾（L810 `}` 之前）添加：

**1. `test_host_scalar_mul_2g`（无 ignore，秒级）**：
```rust
#[test]
fn test_host_scalar_mul_2g() {
    let g = host_from_affine(&SECP256K1_GX, &SECP256K1_GY);
    let two_g = host_scalar_mul(&[2, 0, 0, 0], &g);
    let expected = host_point_double(&g);
    let (x, _) = host_to_affine(&two_g);
    let (ex, _) = host_to_affine(&expected);
    assert_eq!(x, ex, "2·G 应等于 double(G)");
}
```

**2. `test_host_scalar_mul_3g`（无 ignore，秒级）**：
```rust
#[test]
fn test_host_scalar_mul_3g() {
    let g = host_from_affine(&SECP256K1_GX, &SECP256K1_GY);
    let three_g = host_scalar_mul(&[3, 0, 0, 0], &g);
    let two_g = host_point_double(&g);
    let expected = host_point_add(&two_g, &g);
    let (x, _) = host_to_affine(&three_g);
    let (ex, _) = host_to_affine(&expected);
    assert_eq!(x, ex, "3·G 应等于 double(G) + G");
}
```

**3. `test_ecdsa_full_mode_256bit_satisfied`（`#[ignore]`，~19.4M 约束）**：
```rust
#[test]
#[ignore = "256-bit ECDSA 需 ~19.4M 约束，用 --release --ignored 运行"]
fn test_ecdsa_full_mode_256bit_satisfied() {
    let circuit = EcdsaVerifyCircuit::new_full(); // 默认 256-bit
    let inputs = make_full_mode_test_inputs();
    let (ccs, witness) = circuit.run_full(&inputs).expect("run_full 应成功");
    assert!(
        ccs.satisfied_by(&witness).expect("satisfied_by"),
        "256-bit ECDSA 真实验签等式应满足"
    );
}
```

**4. `test_ecdsa_full_mode_256bit_tampered_s`（`#[ignore]`）**：
```rust
#[test]
#[ignore = "256-bit ECDSA 需 ~19.4M 约束，用 --release --ignored 运行"]
fn test_ecdsa_full_mode_256bit_tampered_s() {
    let circuit = EcdsaVerifyCircuit::new_full();
    let mut inputs = make_full_mode_test_inputs();
    // 篡改 s[0]：+1 → 等式不成立
    inputs[0] = inputs[0].add(&Fr::one());
    let (ccs, witness) = circuit.run_full(&inputs).expect("run_full 应成功");
    assert!(
        !ccs.satisfied_by(&witness).expect("satisfied_by"),
        "篡改 s 后 256-bit 等式应不满足"
    );
}
```

## 假设与决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 算法方案 | Approach A（直接升级默认值） | `scalar_mul` 已支持任意 num_bits；不引入新算法风险 |
| 256-bit 测试执行 | `#[ignore]` 标记 | debug 模式 10-30 分钟，避免阻塞 CI |
| 测试向量选择 | d=1, z=1, k=2 | 最小真实 ECDSA 签名，验证等式 `(1+r)·G = (1+r)·G` |
| gas 公式 | `75_600 × num_bits + 22_400` | 匹配约束计数：3×25200×n + 16800 + 5600 |
| 未选 Approach B | windowed scalar mul | 算法复杂、风险高，用户偏好保守重构 |

## 风险与缓解

| 风险 | 级别 | 缓解 |
|------|------|------|
| 256-bit 测试执行时间（debug 10-30 分钟） | 高 | `#[ignore]` 标记，文档注明用 `--release --ignored` |
| 内存使用（~5GB 峰值） | 中 | `#[ignore]` 避免意外触发 |
| r = R.x mod n 边界（R.x ≥ n） | 极低 | `debug_assert!(host_lt(&r, n))`，概率 ~2^(-128) |

## 验证步骤

```bash
# 1. host_scalar_mul 单元测试（秒级）
cargo test -p poker_zkvm --lib precompiles::ecdsa::tests::test_host_scalar_mul

# 2. 8-bit 快速回归测试（秒级）
cargo test -p poker_zkvm --lib precompiles::ecdsa

# 3. clippy
cargo clippy -p poker_zkvm --lib

# 4. 256-bit 测试（release 模式，30-120 秒）
cargo test --release -p poker_zkvm --lib precompiles::ecdsa::tests::test_ecdsa_full_mode_256bit -- --ignored

# 5. 全量回归（不含 ignored）
cargo test -p poker_zkvm --lib
```

## 不受影响

- `secp256k1_ops.rs` — `scalar_mul` 已支持任意 num_bits，无需修改
- `non_native.rs` — host 辅助函数已存在
- `mod.rs` — 生产注册使用 `new()`（MVP 模式），不受影响
- 12 个 MVP 模式测试 — 不使用 `new_full()`

## 实现顺序

1. **H-1**: 修改 `new_full()` 默认值 + 模块文档注释
2. **H-2**: 修改 `gas_cost()` 公式
3. **H-3**: 添加 `host_scalar_mul` 函数
4. **H-4**: 重命名 + 新增测试输入函数 + 更新 import
5. **H-5**: 更新 6 个现有测试
6. **H-6**: 添加 4 个新测试
7. 运行验证步骤 1-3（快速回归）
8. 运行验证步骤 4（256-bit ignored 测试，可选）
