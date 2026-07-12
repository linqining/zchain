# Stage 3 实施计划：预编译电路完善 + CycleFold 真实压缩

## Context

Stage 3 是 poker_zkvm 审计修复的最后一个 Stage，包含两个核心任务：
1. **预编译电路完善**：将 Poseidon/SHA-256/ECDSA 从 MVP 扩展到完整密码学实现
2. **CycleFold 真实压缩**：实现 Groth16 SNARK 压缩系统，将 proof 从 ~245KB 压缩到 ~200 字节

当前状态：所有预编译均为 MVP（单操作约束），CycleFold 仅有原生验证模拟（无真实压缩）。

## 关键发现

- `ark-groth16` 已在 workspace 依赖中（v0.6），但 poker_zkvm 未引用
- `ark-r1cs-std` / `ark-relations` 不在依赖中（需新增）
- Poseidon 配置（MDS 矩阵 + 轮常数）已在 `syscalls/poseidon.rs` 中完整实现
- `recursion/mod.rs:267` 的 `aggregated_proof = left.proof().clone()` 是压缩占位符
- `prover/groth16_compress.rs` 是 stub（返回 "Phase 12 pending"）
- CCS 框架使用自定义 SparseMatrix，非 arkworks R1CS

## Phase A：CCS Builder + Poseidon 完整电路

**目标**：构建程序化 CCS 约束生成器，实现完整 64 轮 Poseidon permutation。

### Step A1：创建 CcsBuilder 工具

新文件：`src/precompiles/ccs_builder.rs`

提供高级 API 声明约束，内部遵循 row isolation 模式：
- `alloc_var()` — 分配新变量，返回索引
- `add_multiplication(row, a, b, result)` — 约束 `z[a] * z[b] - z[result] = 0`
- `add_linear(row, terms: &[(col, Fr)])` — 约束 `sum(coeff * z[col]) = 0`
- `add_bit_check(row, col)` — 约束 `z[col] * (1 - z[col]) = 0`
- `build()` — 生成 `Ccs` 结构

### Step A2：扩展 Poseidon 到完整 permutation

修改文件：`src/precompiles/poseidon.rs`

参数（来自 `syscalls/poseidon.rs`）：
- alpha=5, state_size=3 (rate=2, capacity=1)
- 8 full rounds + 56 partial rounds = 64 轮
- MDS 矩阵 + 轮常数已生成

每轮约束结构：
- Full round：3 个 S-box（每个 3 约束：x²=x*x, x⁴=x²*x², x⁵=x⁴*x）+ 3 个线性层（MDS×state + constants）= 12 约束
- Partial round：1 个 S-box + 3 个线性层 = 6 约束

总计：8×12 + 56×6 = 456 约束，~800 矩阵，~390 变量

`assign_witness` 运行完整 Poseidon permutation，记录所有中间值。

### Step A3：测试

- `build_ccs` 产生正确的矩阵/subset/系数数量
- `assign_witness` 产生满足 `ccs.satisfied_by(witness)` 的 witness
- 电路输出与 `syscalls/poseidon.rs` 的 `poseidon_hash()` 一致
- 篡改任何中间变量导致约束失败

**修改文件**：
- 新建 `src/precompiles/ccs_builder.rs`
- 修改 `src/precompiles/poseidon.rs`
- 修改 `src/precompiles/mod.rs`（添加 `pub mod ccs_builder`）

**风险**：低。Poseidon 仅涉及 BN254 Fr 域运算，无 bit decomposition 或非原生算术。

## Phase B：SHA-256 完整电路

**目标**：实现完整 64 轮 SHA-256 压缩函数。

### Step B1：创建 bit 操作工具

新文件：`src/precompiles/bit_ops.rs`

- `bit_decompose(builder, val_col, num_bits=32)` — 分解为 32 个 bit 变量 + 32 个 range check
- `bit_xor(builder, a_bits, b_bits)` — 逐位 XOR（`a + b - 2*a*b`，每 bit 1 个乘法约束）
- `bit_and(builder, a_bits, b_bits)` — 逐位 AND（`a * b`，每 bit 1 个乘法约束）
- `bit_rotr(builder, bits, n)` — 纯 witness 重排，无约束
- `add_mod_2_32(builder, a, b)` — 32 位 ripple-carry 加法器（~224 约束）

### Step B2：扩展 SHA-256 到完整 compression

修改文件：`src/precompiles/sha256.rs`

每轮（64 轮）：
- 8 个状态字 (a-h) 的 bit 分解 + range check
- Sigma0/Sigma1（3 个 ROTR + 2 个 XOR）+ recomposition
- Ch/Maj 函数 + recomposition
- T1 = h + Sigma1 + Ch + K[t] + W[t]（4 次 mod 2³² 加法）
- T2 = Sigma0 + Maj（1 次加法）
- new_a = T1 + T2, new_e = d + T1

每轮 ~1920 约束，64 轮 ~123,000 约束，~32,000 变量

### Step B3：测试

- bit decomposition + recomposition roundtrip
- 32 位加法匹配 `wrapping_add`
- 单轮 SHA-256 匹配参考实现
- 完整 64 轮压缩 "abc" 匹配 NIST 测试向量 `ba7816bf...`

**修改文件**：
- 新建 `src/precompiles/bit_ops.rs`
- 修改 `src/precompiles/sha256.rs`
- 修改 `src/precompiles/mod.rs`

**风险**：中。mod 2³² 算术需要 bit decomposition，但概念清晰。约束数大（~123K），先用 4 轮测试再扩展。

## Phase C：Groth16 基础设施

**目标**：添加 R1CS 依赖，构建 BN254 EC 操作 gadget 库，创建 Groth16 setup/prove/verify 包装。

### Step C1：添加依赖

修改 `Cargo.toml`（workspace + poker_zkvm）：
```toml
ark-r1cs-std = "0.6"
ark-relations = "0.6"
ark-groth16 = { workspace = true }
ark-snark = "0.6"
```

### Step C2：R1CS Gadget 库

新文件：`src/recursion/r1cs_gadgets.rs`

使用 `ark-r1cs-std` 的 `FpVar`/`CurveVar`/`GroupVar`：
- BN254 G1 点加法 + 标量乘法（复用 arkworks 原生实现）
- MSM（多标量乘法，用于 IPA G_final 计算）
- Blake2b/Poseidon 哈希 gadget（用于 transcript）

### Step C3：Groth16 包装器

修改文件：`src/prover/groth16_compress.rs`

替换 stub：
```rust
pub struct Groth16Proof { a: G1Affine, b: G2Affine, c: G1Affine }

fn groth16_setup(circuit) -> (ProvingKey, VerifyingKey)
fn groth16_prove(pk, circuit) -> Groth16Proof
fn groth16_verify(vk, public_inputs, proof) -> bool
```

### Step C4：测试

- 简单 R1CS 电路（x*y=z）Groth16 setup/prove/verify
- EC 点加法 gadget 匹配原生计算
- Groth16 proof 序列化/反序列化

**修改文件**：
- 新建 `src/recursion/r1cs_gadgets.rs`
- 修改 `src/prover/groth16_compress.rs`
- 修改 `src/recursion/mod.rs`（添加 `pub mod r1cs_gadgets`）
- 修改 `poker_zkvm/Cargo.toml` + workspace `Cargo.toml`

**风险**：低-中。arkworks 提供大部分原语，主要挑战是 API 兼容性。

## Phase D：Hypernova Verifier R1CS 电路 + CycleFold 压缩

**目标**：构建验证 Hypernova proof 的 R1CS 电路，用 Groth16 压缩 proof。

### Step D1：Hypernova Verifier R1CS 电路

新文件：`src/recursion/hypernova_verifier_circuit.rs`

实现 `ConstraintSynthesizer`，编码：
1. 每个 fold step：
   - fold commitment 等式 `C' = C_L + r·C_C`（1 EC add + 1 scalar mul）
   - fold instance 等式 `x' = x_L + r·x_C`（域加法）
   - sumcheck final check（域算术）
2. 最终 IPA opening 验证：
   - 重算 challenges x_k
   - 计算 G_final MSM（N=512 点，~1.3M 约束）
   - 验证 IPA 等式

**关键优化**：transcript challenges 由外部原生计算后作为 witness 提供，电路仅验证数学关系。challenges 是 proof 数据的确定性函数，soundness 不受损。

### Step D2：集成到 CycleFold 框架

修改文件：`src/recursion/mod.rs`

替换 `aggregated_proof = left.proof().clone()`：
```rust
let circuit = HypernovaVerifierCircuit::new(left.proof(), right.proof());
let groth16_proof = groth16_prove(&pk, circuit)?;
let aggregated_proof = CompressedProof::Groth16(groth16_proof);
```

### Step D3：扩展 proof 格式

引入 `CompressedProof` 枚举：
```rust
enum CompressedProof {
    Hypernova(HypernovaProof),  // 未压缩
    Groth16(Groth16Proof),      // 压缩后（~200 字节）
}
```

修改 `verifier.rs` 添加 Groth16 proof 验证路径。

### Step D4：测试

- R1CS 电路生成正确约束
- 2-batch Hypernova proof 压缩后 Groth16 proof 验证通过
- 篡改 Hypernova proof 导致 Groth16 proof 生成失败
- 压缩后 proof < 200 字节
- E2E：`prove` → 压缩 → 链上验证

**修改文件**：
- 新建 `src/recursion/hypernova_verifier_circuit.rs`
- 修改 `src/recursion/mod.rs`
- 修改 `src/prover/groth16_compress.rs`
- 修改 `src/cyclegfold.rs`
- 修改 `src/verifier.rs`

**风险**：高。IPA MSM 约束数 ~1.3M（N=512），Groth16 setup 需数分钟。先从 N=16 测试用例开始。

## Phase E：ECDSA 完整电路

**目标**：实现完整 secp256k1 ECDSA 验证。

### Step E1：非原生域算术

新文件：`src/precompiles/non_native.rs`

secp256k1 标量域 ≠ BN254 Fr，需多 limb 表示：
- k=4 limbs, b=80 bits（总 320 bits > 256 bits）
- limb 加法 + carry 传播
- limb 乘法（schoolbook, k²=16 次）+ Barrett reduction

### Step E2：secp256k1 EC 操作

新文件：`src/precompiles/secp256k1_ops.rs`

- 仿射坐标点加法/倍乘
- 使用 projective 坐标避免逆元（~12 乘法/步）
- 窗口法标量乘（width-4, 64 轮）

### Step E3：完整 ECDSA 验证

修改文件：`src/precompiles/ecdsa.rs`

验证 `s·R = z·G + r·P`（2 次标量乘 + 点加法 + range check）
- 使用窗口法：~154K 约束/次 × 2 = ~308K 约束
- range check + verify equation：~7K 约束
- 总计 ~315K 约束

### Step E4：测试

- 非原生加法/乘法匹配 secp256k1 域运算
- EC 点操作匹配 `secp256k1` crate
- 验证真实 ECDSA 签名
- RFC 6979 测试向量

**修改文件**：
- 新建 `src/precompiles/non_native.rs`
- 新建 `src/precompiles/secp256k1_ops.rs`
- 修改 `src/precompiles/ecdsa.rs`

**风险**：极高。非原生域算术是最复杂的密码学电路，limb reduction 易错。

## 实施顺序

推荐顺序：**A → C → D → B → E**

1. Phase A（Poseidon）— 验证 CCS 框架可扩展到大规模电路
2. Phase C（Groth16 基础设施）— 为 Phase D 铺路，独立可测
3. Phase D（CycleFold 压缩）— 最高价值，解决 proof 大小问题
4. Phase B（SHA-256）— 引入 bit 操作模式
5. Phase E（ECDSA）— 最复杂，利用前述所有模式

## 验证方法

每个 Phase 完成后：
```bash
cd /Users/mac/projects/zchain/poker_zkvm
cargo build                          # 编译通过
cargo test --lib                     # 所有库测试通过
cargo clippy --all-targets           # 零警告
cargo bench --no-run                 # 基准编译通过
```

Phase D 完成后额外验证：
```bash
cargo test --features test-helpers --test e2e_fibonacci  # 压缩后 E2E 通过
cargo test --features test-helpers --test soundness_tests
```

## 不在范围内

- Phase 11 Task 11.1（poker_l1 BREAKING 迁移）— 独立于 Stage 3
- Phase 11.5（治理参数调整）— 独立于 Stage 3
- Phase 2d/2e（RV32I 剩余指令）— Stage 2 范围
- 生产环境 Groth16 trusted setup ceremony — 使用测试 RNG 生成参数
