# Phase H: ECDSA Full 256-bit 标量支持 — 执行计划

## Context

当前 ECDSA Full 模式默认 `scalar_num_bits: 8`，测试使用小标量（s=3, z=2, r=1），无法验证真实 256-bit ECDSA 签名。`scalar_mul` 函数（`secp256k1_ops.rs:L260`）已支持任意 `num_bits`，无需修改算法。本阶段将默认值升级到 256-bit，使用真实 ECDSA 签名测试向量。

**方案选择**：Approach A（保守直接升级）— 不引入新算法，仅改默认值和测试输入。未选 Approach B（windowed scalar mul）因为算法复杂、风险高，且用户偏好保守重构。

**仅修改一个文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/ecdsa.rs`

## 实现步骤

### H-1: 修改 `new_full()` 默认值 (L64-69)

`scalar_num_bits: 8` → `scalar_num_bits: 256`

更新模块文档注释（L25）说明生产默认 256-bit。

### H-2: 修改 `gas_cost()` 公式 (L272-283)

固定 3,000,000 → 按 `num_bits` 缩放：
```rust
let per_bit_gas: u64 = 75_600;   // 3 × 25200
let fixed_gas: u64 = 22_400;      // 16800 + 5600
per_bit_gas * self.scalar_num_bits as u64 + fixed_gas
```

| num_bits | gas_cost |
|----------|----------|
| 8 | 627,200 |
| 256 | 19,376,000 |

### H-3: 添加 `host_scalar_mul` 函数 (测试模块内，L434 之后)

Host 端 double-and-add 标量乘法，匹配电路 `scalar_mul` 逻辑（含 "started" 标志避免无穷远点问题）。

```rust
fn host_scalar_mul(scalar: &[u64; 4], p: &HostPoint) -> HostPoint
```

处理 256 位标量，使用现有 `host_point_double` + `host_point_add`。

### H-4: 重命名 + 新增测试输入函数

1. **重命名** `make_full_mode_test_inputs()` → `make_full_mode_test_inputs_small()`（保留 s=3, z=2, r=1 给 8-bit 快速测试）

2. **新增** `make_full_mode_test_inputs()` — 真实 256-bit ECDSA 签名：
   - 私钥 d=1，消息哈希 z=1，nonce k=2
   - P = d·G = G（公钥）
   - R = k·G = 2·G（nonce 点）
   - r = R.x mod n（256-bit 签名分量）
   - s = k⁻¹·(z + r·d) mod n（256-bit 签名分量）
   - 验证等式：s·R' = z·G + r·P ⟺ (1+r)·G = (1+r)·G ✓

3. **更新 import**：添加 `host_lt`, `host_sub`, `SECP256K1_N`

### H-5: 更新现有 6 个测试

| 测试 | 修改 |
|------|------|
| `test_ecdsa_full_mode_constructors` | `scalar_num_bits == 8` → `== 256` |
| `test_ecdsa_full_mode_basic_satisfied` | `new_full()` → `new_full_with_bits(8)`, `make_full_mode_test_inputs()` → `make_full_mode_test_inputs_small()` |
| `test_ecdsa_full_mode_gas_cost` | 断言 256-bit gas=19,376,000 + 8-bit gas=627,200 |
| `test_ecdsa_full_mode_tampered_s` | `new_full()` → `new_full_with_bits(8)` + `make_full_mode_test_inputs_small()` |
| `test_ecdsa_full_mode_tampered_r` | 同上 |
| `test_ecdsa_full_mode_tampered_px` | 同上 |

### H-6: 添加 4 个新测试

1. `test_host_scalar_mul_2g` — `host_scalar_mul(2, G) == host_point_double(G)`（无 ignore）
2. `test_host_scalar_mul_3g` — `host_scalar_mul(3, G) == host_point_add(double(G), G)`（无 ignore）
3. `test_ecdsa_full_mode_256bit_satisfied` — 256-bit 真实验签（`#[ignore]`，~19.4M 约束）
4. `test_ecdsa_full_mode_256bit_tampered_s` — 256-bit 篡改 s 后不满足（`#[ignore]`）

## 风险与缓解

| 风险 | 级别 | 缓解 |
|------|------|------|
| 256-bit 测试执行时间（debug 模式 10-30 分钟） | 高 | 标记 `#[ignore]`，文档注明用 `--release --ignored` |
| 内存使用（~5GB 峰值） | 中 | `#[ignore]` 避免意外触发，文档建议 8GB+ 内存 |
| r = R.x mod n 边界（R.x ≥ n） | 极低 | `debug_assert!(host_lt(&r, n))`，概率 ~2^(-128) |

## 验证策略

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
