# Stage 3 执行计划：预编译电路完善 + CycleFold 真实压缩

> **背景**：基于已批准的 `/Users/mac/projects/zchain/.trae/documents/stage3_implementation_plan.md` 设计文档。
> 本文件是执行级别的细化计划，聚焦 Phase A 的可执行细节，并锁定 Phase B-E 的关键决策。

## Summary

Stage 3 是 poker_zkvm 审计修复的最后阶段，包含两大任务：
1. **预编译电路完善**：将 Poseidon / SHA-256 / ECDSA 从 MVP（单操作约束）扩展到完整密码学实现
2. **CycleFold 真实压缩**：用 Groth16 SNARK 替换 `recursion/mod.rs:267` 的 stub（`left.proof().clone()`），将 proof 从 ~245KB 压缩到 ~200 字节

执行顺序：**A → C → D → B → E**（A 验证 CCS 框架可扩展；C 为 D 铺路；D 解决 proof 大小问题；B 引入 bit 操作模式；E 最复杂，利用前述所有模式）。

## Current State Analysis

### 预编译 MVP 现状

| 电路 | 文件 | 变量数 | 矩阵数 | 行数 | subsets | 实现深度 |
|------|------|--------|--------|------|---------|----------|
| Poseidon | `src/precompiles/poseidon.rs` | 5 | 7 | 3 | 6 | S-box x^5 单 round |
| SHA-256 | `src/precompiles/sha256.rs` | 6 | 7 | 2 | 6 | Ch 函数单 op |
| ECDSA | `src/precompiles/ecdsa.rs` | 6 | 7 | 3 | 7 | double-and-add 单步 |
| ZkShuffle | `src/precompiles/zk_shuffle.rs` | 0 | 0 | 0 | 0 | stub（返回 "Phase 11 pending"） |

### CycleFold 压缩现状

- `src/recursion/mod.rs:267`：`let aggregated_proof = left.proof().clone();` — 无真实压缩
- `src/prover/groth16_compress.rs`：stub，返回 `Err("Phase 12 pending")`
- `src/cyclegfold.rs`：仅 doc comment 占位
- `RecursiveVerifierCircuit` trait 已定义（`verify_native` 委托到 `verify_hypernova`）

### 依赖现状

- workspace `Cargo.toml` L47：`ark-groth16 = { version = "0.6", default-features = false }` ✅
- `poker_zkvm/Cargo.toml`：未引用 `ark-groth16` / `ark-r1cs-std` / `ark-relations` / `ark-snark` ❌
- workspace 也未声明 `ark-r1cs-std` / `ark-relations` / `ark-snark` ❌

### CCS 框架现状

- `Ccs::new(num_vars, matrices: Vec<SparseMatrix>, subsets: Vec<Vec<usize>>, coeffs: Vec<Fr>)` — 手动构造
- `SparseMatrix::new(num_rows, num_cols)` + `add_entry(row, col, val)`
- 无程序化 builder — 每个预编译电路手动构建矩阵（如 Poseidon 的 7 个矩阵各只含单一非零项）
- `fold/ccs.rs` 扩展方法：`to_lcccs` / `to_cccs` / `compute_v_at` / `ccs_commitment`

### Poseidon 配置（已可用于 Phase A）

`src/syscalls/poseidon.rs` 已通过 `find_poseidon_ark_and_mds` 生成完整配置：
- `alpha = 5`，`rate = 2`，`capacity = 1`（state size = 3）
- `full_rounds = 8`，`partial_rounds = 56`（共 64 轮）
- `ark`（轮常数向量，长度 = 64 × 3 = 192）+ `mds`（3×3 MDS 矩阵）
- 通过 `poseidon_config()` 获取 `&'static PoseidonConfig<Fr>`

## Proposed Changes

### Phase A：CCS Builder + Poseidon 完整电路（立即执行）

#### Step A1：创建 `src/precompiles/ccs_builder.rs`

**目标**：提供程序化 CCS 约束声明 API，替代手动矩阵构建。

**公共 API**：
```rust
pub struct CcsBuilder {
    num_vars: usize,
    num_rows: usize,
    // 内部存储：(row, col, coeff) 三元组，按 constraint 分组
    constraints: Vec<Constraint>,
    next_var: usize,
    next_row: usize,
}

enum Constraint {
    // z[a] * z[b] - z[result] = 0  →  两个 subset: {M_a, M_b} (c=+1), {M_result} (c=-1)
    Multiplication { a: usize, b: usize, result: usize, row: usize },
    // sum(coeff * z[col]) = 0  →  每个 (col, coeff) 一个矩阵，subset = all cols, c 系数
    Linear { terms: Vec<(usize, Fr)>, row: usize },
    // z[col] * (1 - z[col]) = 0  →  z[col]^2 - z[col] = 0
    BitCheck { col: usize, row: usize },
}

impl CcsBuilder {
    pub fn new() -> Self;
    /// 分配新变量，返回索引（从 1 开始，0 保留给常数 1）
    pub fn alloc_var(&mut self) -> usize;
    /// 约束 z[a] * z[b] = z[result]（在指定 row）
    pub fn add_multiplication(&mut self, row: usize, a: usize, b: usize, result: usize);
    /// 约束 sum(coeff * z[col]) = 0（在指定 row）
    pub fn add_linear(&mut self, row: usize, terms: &[(usize, Fr)]);
    /// 约束 z[col] * (1 - z[col]) = 0（在指定 row）
    pub fn add_bit_check(&mut self, row: usize, col: usize);
    /// 分配新 row 并返回索引
    pub fn alloc_row(&mut self) -> usize;
    /// 生成 Ccs 结构（行隔离矩阵 + subsets + coeffs）
    pub fn build(self) -> Result<Ccs, ZkvmError>;
}
```

**`build()` 实现要点**：
- 每个 `Constraint` 转换为行隔离矩阵组（参考现有 Poseidon MVP 模式：每个矩阵仅单一行有非零项）
- `Multiplication{a, b, result, row}` → 3 个矩阵（M_a@row, M_b@row, M_result@row）+ 2 个 subsets（{M_a, M_b} c=+1, {M_result} c=-1）
- `Linear{terms, row}` → 每个 term 一个矩阵 + 1 个 subset（所有矩阵，coeff 为 term 系数）
- `BitCheck{col, row}` → 2 个矩阵（M_col@row ×2）+ 2 个 subsets（{M_col, M_col} c=+1, {M_col} c=-1）
- `num_vars` = builder 追踪的 `next_var`；`num_rows` = 追踪的 `next_row`

**测试**：
- `test_ccs_builder_multiplication` — 单个乘法约束 build + satisfied_by
- `test_ccs_builder_linear` — 线性约束 build + satisfied_by
- `test_ccs_builder_bit_check` — bit 约束 build + satisfied_by
- `test_ccs_builder_chained` — 链式约束（x² → x⁴ → x⁵）匹配现有 Poseidon MVP 输出
- `test_ccs_builder_row_isolation` — 验证无关 subset 在其他行求值为 0

#### Step A2：扩展 `src/precompiles/poseidon.rs` 到完整 64 轮 permutation

**目标**：替换 MVP 单 S-box 为完整 Poseidon permutation。

**参数来源**：复用 `crate::syscalls::poseidon::poseidon_config()` 获取 `&'static PoseidonConfig<Fr>`（含 `ark` 轮常数 + `mds` 矩阵）。

**电路结构**：
- 输入：3 个 Fr（state = [s0, s1, s2]）
- 64 轮 permutation：
  - **Full round**（8 轮）：3 个 S-box（每个 S-box = 3 约束：x²=x*x, x⁴=x²*x², x⁵=x⁴*x）+ 1 个线性层（MDS × state + ark[round]）= 12 约束
  - **Partial round**（56 轮）：1 个 S-box（capacity 元素）+ 1 个线性层 = 6 约束
- 总约束：8×12 + 56×6 = 456 约束
- 预计矩阵数：~800（行隔离模式，每约束 2-3 矩阵）
- 预计变量数：~390（每轮引入 ~6 新中间变量）

**实现方式**：
```rust
impl PoseidonCircuit {
    pub fn new_full() -> Self;  // 完整 permutation 模式
    fn build_full_ccs(&self) -> Ccs;  // 用 CcsBuilder 构建 456 约束
    fn assign_full_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError>;
}
```

**`assign_witness` 逻辑**：
1. 获取 `poseidon_config()` 的 `ark` + `mds`
2. 运行完整 64 轮 permutation，记录所有中间值（S-box 输入/输出、线性层结果）
3. 返回完整 witness 向量

**向后兼容**：
- 保留 `PoseidonCircuit::new()`（MVP 模式）用于既有测试
- 新增 `PoseidonCircuit::new_full()`（完整模式）
- `PrecompileCircuit` trait 方法根据模式分派
- 更新 `gas_cost()`：完整模式 = 64 × 200 = 12800 gas

**测试**：
- `test_poseidon_full_build_ccs` — 矩阵/subset/row 数量正确（~800/~456×2/456）
- `test_poseidon_full_satisfied_by` — witness 满足所有约束
- `test_poseidon_full_matches_host` — 电路输出 == `poseidon_hash(&[s0, s1])`（注意：sponge 模式下 capacity=0）
- `test_poseidon_full_soundness_tampered_round` — 篡改任一中间变量导致约束失败
- `test_poseidon_full_known_vector` — 已知输入→输出对（从 `poseidon_hash` 预计算）

#### Step A3：修改 `src/precompiles/mod.rs`

添加 `pub mod ccs_builder;`（L20 区域，按字母序插入）。

**修改文件清单**：
- 新建 `src/precompiles/ccs_builder.rs`
- 修改 `src/precompiles/poseidon.rs`（添加完整模式）
- 修改 `src/precompiles/mod.rs`（添加模块声明）

**风险**：低。Poseidon 仅涉及 BN254 Fr 域运算，无 bit decomposition。CcsBuilder 是纯增量工具。

---

### Phase C：Groth16 基础设施（Phase A 完成后执行）

#### Step C1：添加依赖

修改 `/Users/mac/projects/zchain/Cargo.toml`（workspace `[workspace.dependencies]`）：
```toml
ark-r1cs-std = "0.6"
ark-relations = "0.6"
ark-snark = "0.6"
```
（`ark-groth16` 已存在 L47，需确认 `default-features = false` 是否需调整为包含 `std`）

修改 `/Users/mac/projects/zchain/poker_zkvm/Cargo.toml` `[dependencies]`：
```toml
ark-groth16 = { workspace = true }
ark-r1cs-std = { workspace = true }
ark-relations = { workspace = true }
ark-snark = { workspace = true }
```

#### Step C2：创建 `src/recursion/r1cs_gadgets.rs`

使用 `ark-r1cs-std` 的 `FpVar` / `CurveVar` / `GroupVar`：
- BN254 G1 点加法 + 标量乘法（复用 arkworks 原生 `PairingVar`）
- MSM gadget（用于 IPA `G_final` 计算）
- Blake2b/Poseidon 哈希 gadget（用于 transcript challenge 重算）

#### Step C3：替换 `src/prover/groth16_compress.rs` stub

```rust
pub struct Groth16Proof {
    pub a: ark_bn254::G1Affine,
    pub b: ark_bn254::G2Affine,
    pub c: ark_bn254::G1Affine,
}

pub fn groth16_setup<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<(ProvingKey, VerifyingKey)>;
pub fn groth16_prove(pk: &ProvingKey, circuit: impl ConstraintSynthesizer<Fr>) -> Result<Groth16Proof>;
pub fn groth16_verify(vk: &VerifyingKey, public_inputs: &[Fr], proof: &Groth16Proof) -> Result<bool>;
```

测试用 RNG 生成参数（非生产 ceremony）。

**修改文件**：
- 新建 `src/recursion/r1cs_gadgets.rs`
- 修改 `src/prover/groth16_compress.rs`（替换 stub）
- 修改 `src/recursion/mod.rs`（添加 `pub mod r1cs_gadgets`）
- 修改 `poker_zkvm/Cargo.toml` + workspace `Cargo.toml`

---

### Phase D：Hypernova Verifier R1CS 电路 + CycleFold 压缩（Phase C 完成后执行）

#### Step D1：创建 `src/recursion/hypernova_verifier_circuit.rs`

实现 `ark_relations::r1cs::ConstraintSynthesizer`，编码 Hypernova verifier 步骤：
1. 每个 fold step：fold commitment 等式 `C' = C_L + r·C_C`（1 EC add + 1 scalar mul）
2. sumcheck final check（域算术）
3. IPA opening 验证：重算 challenges + `G_final` MSM（N=512 点，~1.3M 约束）

**关键优化**：transcript challenges 由外部原生计算后作为 witness 提供，电路仅验证数学关系（soundness 不受损，因 challenges 是 proof 数据的确定性函数）。

#### Step D2：集成到 CycleFold 框架

修改 `src/recursion/mod.rs:267`：
```rust
// 替换: let aggregated_proof = left.proof().clone();
let circuit = HypernovaVerifierCircuit::new(left.proof(), right.proof())?;
let groth16_proof = groth16_prove(&pk, circuit)?;
let aggregated_proof = HypernovaProof::Compressed(groth16_proof);
```

#### Step D3：扩展 proof 格式

引入 `CompressedProof` 枚举（Hypernova 未压缩 / Groth16 压缩），修改 `verifier.rs` 添加 Groth16 验证路径。

**修改文件**：
- 新建 `src/recursion/hypernova_verifier_circuit.rs`
- 修改 `src/recursion/mod.rs`
- 修改 `src/prover/groth16_compress.rs`
- 修改 `src/cyclegfold.rs`
- 修改 `src/verifier.rs`

**风险**：高。IPA MSM 约束数 ~1.3M。先从 N=16 测试用例开始，验证后再扩展到 N=512。

---

### Phase B：SHA-256 完整电路（Phase D 完成后执行）

#### Step B1：创建 `src/precompiles/bit_ops.rs`

- `bit_decompose(builder, val_col, num_bits=32)` — 32 个 bit 变量 + 32 个 range check
- `bit_xor(builder, a_bits, b_bits)` — 逐位 `a + b - 2*a*b`
- `bit_and(builder, a_bits, b_bits)` — 逐位 `a * b`
- `bit_rotr(builder, bits, n)` — 纯 witness 重排
- `add_mod_2_32(builder, a, b)` — 32 位 ripple-carry 加法器（~224 约束）

#### Step B2：扩展 `src/precompiles/sha256.rs` 到完整 64 轮 compression

每轮 ~1920 约束，64 轮 ~123,000 约束，~32,000 变量。

**修改文件**：新建 `src/precompiles/bit_ops.rs`，修改 `src/precompiles/sha256.rs` + `mod.rs`

---

### Phase E：ECDSA 完整电路（Phase B 完成后执行）

#### Step E1：创建 `src/precompiles/non_native.rs`

secp256k1 标量域 ≠ BN254 Fr，需多 limb 表示（k=4, b=80 bits）+ Barrett reduction。

#### Step E2：创建 `src/precompiles/secp256k1_ops.rs`

projective 坐标点加法/倍乘 + 窗口法标量乘（width-4, 64 轮）。

#### Step E3：扩展 `src/precompiles/ecdsa.rs` 到完整验证

验证 `s·R = z·G + r·P`，总计 ~315,000 约束。

**修改文件**：新建 `non_native.rs` + `secp256k1_ops.rs`，修改 `ecdsa.rs`

**风险**：极高。非原生域算术是最复杂的密码学电路。

## Assumptions & Decisions

1. **Phase A 向后兼容**：保留 MVP `PoseidonCircuit::new()`，新增 `new_full()`。既有测试不受影响。
2. **CcsBuilder 行隔离模式**：每个矩阵仅单一行有非零项，与现有 Poseidon MVP 模式一致，确保 subset 不污染其他行。
3. **Poseidon 参数复用**：完整模式直接调用 `syscalls::poseidon::poseidon_config()` 获取 `ark` + `mds`，不重新生成。
4. **Groth16 测试参数**：使用 RNG 生成 proving/verifying key（非生产 ceremony），足够开发与测试。
5. **Phase D 渐进策略**：先 N=16（小规模 IPA）验证 R1CS 电路正确性，再扩展到 N=512（生产规模）。
6. **CompressedProof 枚举**：引入后需修改 `verifier.rs` 分派路径，但保持既有 Hypernova proof 验证不变（向后兼容）。
7. **不在范围内**：Phase 11 Task 11.1（poker_l1 BREAKING 迁移）、Phase 11.5（治理参数）、Phase 2d/2e（RV32I 剩余指令）、生产 Groth16 trusted setup ceremony。

## Verification Steps

### 每个 Phase 完成后
```bash
cd /Users/mac/projects/zchain
cargo build -p poker_zkvm                          # 编译通过
cargo test -p poker_zkvm --lib                     # 所有库测试通过
cargo clippy -p poker_zkvm --all-targets           # 零警告
cargo bench -p poker_zkvm --no-run                 # 基准编译通过
cargo test -p poker_l1 --lib                       # 确保无回归
```

### Phase A 完成后额外验证
- `test_poseidon_full_matches_host`：电路输出 == `poseidon_hash()` 输出
- `test_ccs_builder_chained`：CcsBuilder 输出 == 现有 MVP 手动构建的 CCS

### Phase D 完成后额外验证
```bash
cargo test -p poker_zkvm --features test-helpers --test e2e_fibonacci  # 压缩后 E2E 通过
cargo test -p poker_zkvm --features test-helpers --test soundness_tests
```
- 压缩后 proof < 200 字节
- E2E：`prove` → 压缩 → 链上验证 闭环

## 执行策略

本计划按 **A → C → D → B → E** 顺序执行。每个 Phase 完成后运行验证步骤，确认无回归再进入下一 Phase。Phase A 是立即执行的起点，聚焦 CcsBuilder 工具 + Poseidon 完整电路。
