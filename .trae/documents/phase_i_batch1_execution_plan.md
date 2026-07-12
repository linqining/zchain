# Phase I Batch 1: 预编译补齐（3 个低风险）— 执行计划

## Context

当前预编译覆盖率 3/8（poseidon + sha256 + ecdsa，zk\_shuffle 为 stub）。Phase I 目标是补齐市场标准预编译。用户决策：分批实现，本批次先做 3 个低风险预编译（modexp + keccak256 + merkle\_verify），bn254 pairing（hint-based）/ ed25519 / bls12-381 留待后续批次。

**修改/新增文件**：

* 新增：`poker_zkvm/src/precompiles/modexp.rs`

* 新增：`poker_zkvm/src/precompiles/keccak256.rs`

* 新增：`poker_zkvm/src/precompiles/merkle_verify.rs`

* 修改：`poker_zkvm/src/precompiles/mod.rs`（注册 + 模块声明）

* 修改：`poker_zkvm/src/precompiles/non_native.rs`（导出 `host_pow_mod`）

* 修改：`poker_zkvm/src/syscalls/mod.rs`（新增 SyscallId 变体）

* 修改：`poker_zkvm/src/syscalls/gas.rs`（新增 gas 常量）

## 当前架构（已验证）

**PrecompileCircuit trait**（`mod.rs:L47-65`）：

* `name()`, `num_variables()`, `build_ccs()`, `assign_witness()`, `gas_cost()`

**CcsCircuit trait**（`mod.rs:L131-151`）：

* `name()`, `num_matrices()`, `to_ccs_instance(witness, public_inputs)`

**CcsBuilder API**（`ccs_builder.rs:L43-141`）：

* `alloc_var()`, `alloc_row()`, `add_linear(row, terms)`, `add_multiplication(row, a, b, c)`, `add_bit_check(row, var)`, `build()`

**bit\_ops API**（`bit_ops.rs`，全部 `pub`）：

* `bit_decompose(builder, val_col, num_bits)` — 支持 64-bit

* `bit_xor`, `bit_and`, `bit_or`, `bit_not` — 操作 `&[usize]` bit 数组

* `bit_rotr(bits, n, num_bits)` — 纯重排，0 约束

* `bit_recompose(builder, bits)` — 1 linear 约束

**NonNativeBuilder**（`non_native.rs`）：

* `mul_mod(a, b, modulus)` — hint-based 模乘约束（L630-722）

* `add_mod(a, b, modulus)` — 模加约束（L451-539）

* `from_u256(val)`, `element_to_u256(elem)`, `range_check_element(elem)`

**现有依赖**（Cargo.toml）：ark-bn254, sha2, secp256k1, blake2。无 sha3/keccak 依赖。

## 实现步骤

### I-1: merkle\_verify（最低复杂度，先实现）

**新增文件**：`precompiles/merkle_verify.rs`

**MVP 模式**（单层验证）：

* 约束：`parent = left * 2 + right`（1 linear，系数 2 区分左右子节点）

* witness：`[1, left, right, parent]`（4 变量）

* 输入：`[left, right, parent]`（3 个 Fr）

* gas：`GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL = 100`

**Full 模式**（深度可配置的路径验证）：

* `MerkleVerifyCircuit::new_full_with_depth(n)` — n 层路径

* 每层：`current = direction ? H(sibling, current) : H(current, sibling)`

* `H(left, right) = left * 2 + right`（1 linear 约束/层）

* bit-decompose direction\_bits（每层 1 bit\_check）

* 输入：`[leaf, root, sibling[depth], direction_bits]`

* gas：`GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL * depth`

**约束结构**（MVP，行隔离矩阵模式）：

```
row 0: parent - left*2 - right = 0
```

1 个矩阵 M\_parent（row 0, col 3, coeff=1）+ 1 个矩阵 M\_left（row 0, col 1, coeff=2）+ 1 个矩阵 M\_right（row 0, col 2, coeff=-1）

**测试**：

* `test_merkle_mvp_satisfied` — 单层验证通过

* `test_merkle_mvp_tampered_parent` — 篡改 parent 后不满足

* `test_merkle_full_depth3_satisfied` — 3 层路径验证通过

* `test_merkle_full_tampered_leaf` — 篡改 leaf 后不满足

* `test_merkle_full_tampered_sibling` — 篡改 sibling 后不满足

### I-2: modexp（中等复杂度，复用 NonNativeBuilder）

**新增文件**：`precompiles/modexp.rs`

**前置修改**：将 ecdsa.rs 测试模块中的 `host_pow_mod` 逻辑提取到 `non_native.rs` 作为 `pub(crate) fn host_pow_mod(base, exp, modulus)`。

**MVP 模式**（单次模乘）：

* 约束：`base * exponent = result mod modulus`（使用 `NonNativeBuilder::mul_mod`）

* 输入：`[base(4 limbs), modulus(4 limbs), result(4 limbs)]` + exponent 作为 witness hint

* gas：`GAS_ZKVM_MODEXP_BASE = 50_000`

**Full 模式**（square-and-multiply）：

* `ModexpCircuit::new_full_with_bits(n)` — n 位指数

* Bit-decompose exponent（n bits）

* 循环：accumulator = accumulator² ; if bit: accumulator \*= base

* 每次 mul\_mod ≈ 1400 约束，n 次 → n × 2800 约束（square + conditional mul）

* 输入：`[base(4), exponent(4), modulus(4), result(4)]`（16 Fr）

* gas：`GAS_ZKVM_MODEXP_PER_BIT * num_bits + GAS_ZKVM_MODEXP_BASE`

**测试**：

* `test_modexp_mvp_satisfied` — `2 * 3 = 6 mod 7`

* `test_modexp_mvp_tampered_result` — 篡改 result 后不满足

* `test_modexp_full_8bit_satisfied` — `2^10 = 1024 mod 1000000007`（8-bit exponent）

* `test_modexp_full_tampered_base` — 篡改 base 后不满足

* `test_host_pow_mod` — host 端模幂正确性

### I-3: keccak256（最高复杂度，自实现 Keccak-f\[1600]）

**新增文件**：`precompiles/keccak256.rs`

**MVP 模式**（单轮 Keccak-f\[1600]）：

* 状态：25 个 Fr 变量（5×5 lanes，每个 64-bit）

* 单轮：theta + rho + pi + chi + iota

* 使用 `bit_ops::bit_decompose(64)`, `bit_xor`, `bit_and`, `bit_not`, `bit_rotr`

* gas：`GAS_ZKVM_KECCAK256_PER_ROUND = 10_000`

**Full 模式**（24 轮 + padding）：

* `Keccak256Circuit::new_full()` — 24 轮完整 Keccak-f\[1600]

* 输入：消息吸收 + 24 轮置换 + 挤出 32 字节哈希

* 约束数：\~24 × 8000 ≈ 192,000（与 SHA-256 Full 同量级）

* gas：`GAS_ZKVM_KECCAK256_PER_BYTE * input_len`

**Keccak-f\[1600] 单轮约束构建**：

```
theta: C[x] = A[x,0] XOR A[x,1] XOR ... XOR A[x,4]
       D[x] = C[x-1] XOR rot(C[x+1], 1)
       A[x,y] = A[x,y] XOR D[x]
rho:   A[x,y] = rot(A[x,y], r[x,y])  (旋转常量表)
pi:    A[y, 2x+3y] = A[x,y]  (置换，0 约束)
chi:   A'[x,y] = A[x,y] XOR (NOT A[x+1,y]) AND A[x+2,y]
iota:  A'[0,0] = A[0,0] XOR RC[round]
```

**Host 端实现**（测试模块内）：

* 实现 `host_keccak_f1600(state: &mut [[u64; 5]; 5])` — 24 轮置换

* 实现 `host_keccak256(input: &[u8]) -> [u8; 32]` — 完整哈希

* 用于生成测试向量

**测试**：

* `test_keccak_mvp_single_round` — 单轮置换正确性

* `test_keccak_full_empty_input` — 空输入哈希 = keccak256("")

* `test_keccak_full_abc` — "abc" 哈希正确

* `test_keccak_full_tampered_input` — 篡改输入后哈希不匹配

### I-4: 注册 + Syscall 集成

**precompiles/mod.rs 修改**：

```rust
pub mod modexp;
pub mod keccak256;
pub mod merkle_verify;
```

在 `test_phase10_registry_full` 测试中注册 3 个新预编译。

**syscalls/mod.rs 修改**：

```rust
pub enum SyscallId {
    // ... 既有 0x01-0x0A ...
    Keccak256 = 0x0B,
    Modexp = 0x0C,
    MerkleVerify = 0x0D,
}
```

更新 `from_u32()` 和 `all()` 方法。

**syscalls/gas.rs 修改**：

```rust
pub const GAS_ZKVM_KECCAK256_PER_BYTE: u64 = 2;
pub const GAS_ZKVM_MODEXP_BASE: u64 = 50_000;
pub const GAS_ZKVM_MODEXP_PER_BIT: u64 = 600;
pub const GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL: u64 = 100;
```

更新 `syscall_gas()` 函数添加 3 个新分支。

## 假设与决策

| 决策点                 | 选择                                            | 理由                                  |
| ------------------- | --------------------------------------------- | ----------------------------------- |
| merkle\_verify 哈希函数 | 简单线性 `H(l,r) = l*2 + r`                       | 低风险；Poseidon 复用需重构 poseidon.rs，留待后续 |
| modexp host 函数      | 从 ecdsa.rs 提取 host\_pow\_mod 到 non\_native.rs | 避免代码重复                              |
| keccak256 依赖        | 自实现，不加 sha3 crate                             | 保持依赖最小化；host 端在测试模块实现               |
| SyscallId 扩展        | 新增 0x0B-0x0D                                  | Stage 4 计划明确要求                      |
| keccak256 MVP       | 单轮置换                                          | 验证约束结构，Full 模式 24 轮                 |

## 风险与缓解

| 风险                          | 级别 | 缓解                                      |
| --------------------------- | -- | --------------------------------------- |
| keccak256 Full 约束数大（\~192K） | 中  | 与 SHA-256 Full 同量级，已验证可行                |
| keccak256 旋转常量表复杂           | 低  | 预计算常量数组，rho 步骤用 bit\_rotr（0 约束）         |
| modexp 256-bit 测试慢          | 中  | MVP 用 8-bit，Full 256-bit 标记 `#[ignore]` |
| SyscallId 扩展影响 spec         | 低  | Stage 4 计划已批准扩展                         |

## 验证步骤

```bash
# 1. 单个预编译测试（秒级）
cargo test -p poker_zkvm --lib precompiles::merkle_verify
cargo test -p poker_zkvm --lib precompiles::modexp
cargo test -p poker_zkvm --lib precompiles::keccak256

# 2. 全部预编译测试（秒级）
cargo test -p poker_zkvm --lib precompiles

# 3. syscall gas 测试
cargo test -p poker_zkvm --lib syscalls::gas

# 4. clippy
cargo clippy -p poker_zkvm --lib

# 5. 全量回归（不含 ignored）
cargo test -p poker_zkvm --lib
```

## 实现顺序

1. **I-1**: merkle\_verify.rs（MVP + Full + 测试）
2. **I-2**: modexp.rs（提取 host\_pow\_mod + MVP + Full + 测试）
3. **I-3**: keccak256.rs（host Keccak + MVP 单轮 + Full 24 轮 + 测试）
4. **I-4**: 注册 + SyscallId + gas 常量 + 集成测试
5. 运行验证步骤 1-4
6. 运行验证步骤 5（全量回归）

## 不受影响

* 现有 4 个预编译（poseidon/sha256/ecdsa/zk\_shuffle）— 不修改

* 既有 10 个 SyscallId — 仅新增，不修改既有

* 既有 gas 常量 — 仅新增，不修改既有

