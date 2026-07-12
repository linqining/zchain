# Stage 3 续作计划：从 Phase A2 起步

> **背景**：基于已批准的 `stage3_execution_plan.md`（A → C → D → B → E 顺序）。
> Phase A1（CcsBuilder）已完成并通过全部测试。本计划聚焦 Phase A2 的可执行细节，
> 并锁定 Phase C-E 的关键决策点。

## Summary

Stage 3 续作从 Phase A2 起步，按已批准顺序推进：
1. **Phase A2（立即执行）**：将 `poseidon.rs` 从 MVP 单 S-box 扩展到完整 64 轮 permutation
2. **Phase C**：Groth16 基础设施（依赖 + r1cs_gadgets + 替换 stub）
3. **Phase D**：Hypernova Verifier R1CS 电路 + CycleFold 真实压缩
4. **Phase B**：SHA-256 完整 64 轮 compression 电路
5. **Phase E**：ECDSA 完整验证电路（非原生域算术）

## Current State Analysis

### 已完成（Phase A1）

- [x] `src/precompiles/ccs_builder.rs` — CcsBuilder 工具，支持 `Multiplication`/`Linear`/`BitCheck` 三种约束
- [x] 10 个单元测试全部通过（含 row isolation、chained、mixed constraints）
- [x] `src/precompiles/mod.rs:20` 已声明 `pub mod ccs_builder;`
- [x] `cargo build -p poker_zkvm` 编译通过（1.92s）

### 待完成

| Phase | 文件 | 当前状态 | 目标状态 |
|-------|------|----------|----------|
| A2 | `src/precompiles/poseidon.rs` | MVP 单 S-box（5 vars, 7 matrices, 3 rows） | 完整 64 轮 permutation（~435 约束） |
| C | `src/prover/groth16_compress.rs` + 依赖 | stub 返回 `Phase 12 pending` | 真实 Groth16 setup/prove/verify |
| C | `src/recursion/r1cs_gadgets.rs` | 不存在 | BN254 G1 点运算 + MSM gadget |
| D | `src/recursion/mod.rs:267` | `left.proof().clone()` | Groth16 压缩后 proof |
| D | `src/recursion/hypernova_verifier_circuit.rs` | 不存在 | Hypernova verifier 的 R1CS 电路 |
| B | `src/precompiles/bit_ops.rs` + `sha256.rs` | MVP 单 Ch 函数 | 完整 64 轮 SHA-256 compression |
| E | `src/precompiles/non_native.rs` + `ecdsa.rs` | MVP 单步 double-and-add | 完整 ECDSA 验证 |

### 依赖现状

- workspace `Cargo.toml` L47：`ark-groth16 = { version = "0.6", default-features = false }` ✅
- workspace 缺失：`ark-r1cs-std`、`ark-relations`、`ark-snark` ❌
- `poker_zkvm/Cargo.toml`：未引用任何 Groth16 相关依赖 ❌

### Poseidon 配置（Phase A2 可直接复用）

`src/syscalls/poseidon.rs` 已提供完整配置：
- `poseidon_config() -> &'static PoseidonConfig<Fr>`（ark_bn254::Fr）
- 参数：alpha=5, rate=2, capacity=1, full_rounds=8, partial_rounds=56
- `ark`：64 × 3 轮常数向量
- `mds`：3×3 MDS 矩阵
- `poseidon_hash(&[Fr]) -> Fr`：sponge 接口，用于测试对照

---

## Proposed Changes

### Phase A2：Poseidon 完整 64 轮 permutation 电路（立即执行）

#### 目标

替换 `poseidon.rs` 中的 MVP 单 S-box 实现，用 CcsBuilder 构建完整 64 轮 Poseidon permutation 的 CCS 约束。

#### Permutation 结构（来自 ark-crypto-primitives 0.6.0 源码）

```
permute(state):
  // 前 4 轮 full round
  for r in 0..4:
    state = ark[r] + state        // 3 元素全加
    state = sbox_full(state)      // 3 元素全做 x^5
    state = mds * state           // 3×3 矩阵乘
  
  // 56 轮 partial round
  for r in 4..60:
    state = ark[r] + state
    state = sbox_partial(state)   // 仅 state[0] 做 x^5
    state = mds * state
  
  // 后 4 轮 full round
  for r in 60..64:
    state = ark[r] + state
    state = sbox_full(state)
    state = mds * state
```

#### 约束优化：合并 MDS[r] + ARK[r+1]

将 round r 的 MDS 线性层与 round r+1 的 ARK 合并为单一仿射线性约束：
```
new_s_i = Σ_j(mds[i][j] * x5_j) + ark[r+1][i]
```
这把每轮的 3 个 MDS 约束 + 3 个 ARK 约束合并为 3 个线性约束，节省一半线性约束。

#### 约束计数

| 轮次 | S-box 约束 | 线性层约束 | 小计 |
|------|-----------|-----------|------|
| Round 0（full, 首轮） | 3×3=9（3 元素各 x²,x⁴,x⁵） | 3（ARK[0] 初始化）+ 3（MDS+ARK[1]）= 6 | 15 |
| Round 1-3（full） | 9 each | 3（MDS+ARK[r+1]）each | 12 each → 36 |
| Round 4-59（partial） | 3 each（仅 state[0]） | 3 each | 6 each → 336 |
| Round 60-62（full） | 9 each | 3 each | 12 each → 36 |
| Round 63（full, 末轮） | 9 | 3（仅 MDS，无下一轮 ARK） | 12 |
| **总计** | | | **435** |

#### 变量计数

- z[0] = Fr::one()（常数 1）
- z[1..4] = 初始 state [s0, s1, s2]
- 每轮新增变量：
  - Full round（非首轮）：3（x²）+ 3（x⁴）+ 3（x⁵）+ 3（MDS+ARK 输出）= 12
  - Partial round：3（x²）+ 3（x⁴）+ 3（x⁵ for elem 0）+ 3（MDS+ARK 输出）= 12
  - 首轮额外：3（ARK[0] 输出）
  - 末轮：3（MDS 输出，无下一轮 ARK 合并）

估算：4 + 3 + 63×12 + 3 = 4 + 3 + 756 + 3 = 766 变量（保守上界，实际可能更少因部分轮只对 elem 0 做 S-box）

实际变量数需在实现时精确计算，但 CcsBuilder 会自动追踪。

#### 实现方案

**文件**：`src/precompiles/poseidon.rs`（修改）

**结构改动**：
```rust
#[derive(Debug, Clone)]
pub struct PoseidonCircuit {
    alpha: u64,
    full_mode: bool,  // false = MVP 单 S-box, true = 完整 64 轮
}

impl PoseidonCircuit {
    /// MVP 模式（向后兼容）。
    pub fn new() -> Self {
        Self { alpha: 5, full_mode: false }
    }
    
    /// 完整 64 轮 permutation 模式。
    pub fn new_full() -> Self {
        Self { alpha: 5, full_mode: true }
    }
    
    /// 用 CcsBuilder 构建完整 permutation CCS。
    fn build_full_ccs(&self) -> Ccs {
        let config = poseidon_config();
        let mut builder = CcsBuilder::new();
        
        // 分配初始 state 变量
        let s0 = builder.alloc_var();  // 1
        let s1 = builder.alloc_var();  // 2
        let s2 = builder.alloc_var();  // 3
        
        // Round 0: ARK[0] + S-box + MDS+ARK[1]
        // ... (用 builder.add_linear / add_multiplication 逐约束添加)
        
        // Round 1-63: S-box + MDS+ARK[r+1] (或仅 MDS for 末轮)
        
        builder.build().expect("Poseidon full CCS 构造应成功")
    }
    
    /// 运行完整 permutation 并记录所有中间值。
    fn assign_full_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        // inputs = [s0, s1, s2]（sponge 的初始 state，capacity=0）
        // 运行 64 轮 permutation，按 build_full_ccs 的变量分配顺序填充 witness
    }
}
```

**PrecompileCircuit trait 分派**：
```rust
impl PrecompileCircuit for PoseidonCircuit {
    fn num_variables(&self) -> usize {
        if self.full_mode { /* 完整模式变量数 */ } else { 5 }
    }
    
    fn build_ccs(&self) -> Ccs {
        if self.full_mode { self.build_full_ccs() } else { /* 现有 MVP 逻辑 */ }
    }
    
    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode { self.assign_full_witness(inputs) } else { /* 现有 MVP 逻辑 */ }
    }
    
    fn gas_cost(&self) -> u64 {
        if self.full_mode { 64 * 200 } else { 200 }  // 完整模式 12800 gas
    }
}
```

**assign_full_witness 实现要点**：
1. 获取 `poseidon_config()` 的 `ark` + `mds`（类型为 `&Vec<Vec<ark_bn254::Fr>>`）
2. 将 `ark_bn254::Fr` 转为 `Bn254ScalarField`：`Bn254ScalarField::from_fr(ark[r][i])`
3. 逐步运行 permutation，记录每个中间值到 witness 向量
4. witness 顺序必须与 `build_full_ccs` 中 `alloc_var` 的顺序一致

**测试**：
- `test_poseidon_full_build_ccs` — 矩阵/subset/row 数量正确（~435 约束，矩阵数 = 约束数 × 2-3）
- `test_poseidon_full_satisfied_by` — 正确 witness 满足所有约束
- `test_poseidon_full_matches_host` — 电路输出 == `poseidon_hash(&[s0, s1])` 的 permutation 结果
  - 注意：`poseidon_hash` 是 sponge 接口，内部会先 absorb 再 squeeze，涉及一次 permutation
  - 需提取 sponge 内部 permutation 的 state 作为对照（或直接调用 `PoseidonSponge` 的 permute）
- `test_poseidon_full_soundness_tampered_round` — 篡改任一中间变量导致约束失败
- `test_poseidon_full_known_vector` — 已知输入→输出对（从 `poseidon_hash` 预计算）
- `test_poseidon_full_gas_cost` — 完整模式 gas = 12800

**向后兼容**：
- 保留 `PoseidonCircuit::new()`（MVP 模式）及所有现有测试不变
- `PrecompileRegistry` 注册时默认用 `new()`（MVP），测试可显式注册 `new_full()`
- `mod.rs:337` 的 `test_phase10_registry_full` 不受影响（用 `new()`）

#### 风险

- **低**：Poseidon 仅涉及 BN254 Fr 域运算，无 bit decomposition
- **低**：CcsBuilder 已验证可处理链式约束（`test_ccs_builder_chained` 匹配 MVP S-box 语义）
- **中**：变量顺序一致性需仔细维护（`build_full_ccs` 与 `assign_full_witness` 必须用相同 alloc 顺序）
- **中**：`poseidon_hash` 是 sponge 接口，需确认完整 permutation 输出与 sponge 内部 state 的对应关系

---

### Phase C：Groth16 基础设施（Phase A2 完成后执行）

#### Step C1：添加依赖

**修改 `/Users/mac/projects/zchain/Cargo.toml`** `[workspace.dependencies]`：
```toml
ark-r1cs-std = { version = "0.6", default-features = false, features = ["std"] }
ark-relations = { version = "0.6", default-features = false, features = ["std"] }
ark-snark = { version = "0.6", default-features = false }
```
（`ark-groth16` 已存在 L47，需确认 `default-features = false` 是否需调整为含 `std`）

**修改 `/Users/mac/projects/zchain/poker_zkvm/Cargo.toml`** `[dependencies]`：
```toml
ark-groth16 = { workspace = true }
ark-r1cs-std = { workspace = true }
ark-relations = { workspace = true }
ark-snark = { workspace = true }
```

#### Step C2：创建 `src/recursion/r1cs_gadgets.rs`

使用 `ark-r1cs-std` 的 `FpVar` / `CurveVar`：
- BN254 G1 点加法 + 标量乘法（复用 arkworks 原生 `PairingVar`）
- MSM gadget（用于 IPA `G_final` 计算）
- Poseidon 哈希 gadget（用于 transcript challenge 重算）

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

**关键优化**：transcript challenges 由外部原生计算后作为 witness 提供，电路仅验证数学关系。

#### Step D2：集成到 CycleFold 框架

修改 `src/recursion/mod.rs:267`：
```rust
// 替换: let aggregated_proof = left.proof().clone();
let circuit = HypernovaVerifierCircuit::new(left.proof(), right.proof())?;
let groth16_proof = groth16_prove(&pk, circuit)?;
let aggregated_proof = HypernovaProof::Compressed(groth16_proof);
```

#### Step D3：扩展 proof 格式

引入 `CompressedProof` 枚举，修改 `verifier.rs` 添加 Groth16 验证路径。

**修改文件**：
- 新建 `src/recursion/hypernova_verifier_circuit.rs`
- 修改 `src/recursion/mod.rs`
- 修改 `src/prover/groth16_compress.rs`
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

---

## Assumptions & Decisions

1. **Phase A2 向后兼容**：保留 MVP `PoseidonCircuit::new()`，新增 `new_full()`。既有测试和 `PrecompileRegistry` 注册不受影响。
2. **CcsBuilder 行隔离模式**：复用 Phase A1 已验证的 CcsBuilder，所有约束自动遵循行隔离。
3. **Poseidon 参数复用**：完整模式直接调用 `syscalls::poseidon::poseidon_config()` 获取 `ark` + `mds`，不重新生成。
4. **MDS+ARK 合并优化**：将 round r 的 MDS 与 round r+1 的 ARK 合并为单一线性约束，节省约一半线性约束。
5. **变量顺序一致性**：`build_full_ccs` 和 `assign_full_witness` 必须用相同的 `alloc_var` 顺序分配变量。建议在实现时先写一个共享的 `allocate_variables()` 函数。
6. **Groth16 测试参数**：使用 RNG 生成 proving/verifying key（非生产 ceremony），足够开发与测试。
7. **Phase D 渐进策略**：先 N=16（小规模 IPA）验证 R1CS 电路正确性，再扩展到 N=512（生产规模）。
8. **不在范围内**：生产 Groth16 trusted setup ceremony、poker_l1 on-chain verifier 迁移（H-3）。

## Verification Steps

### Phase A2 完成后
```bash
cd /Users/mac/projects/zchain
cargo build -p poker_zkvm                          # 编译通过
cargo test -p poker_zkvm --lib poseidon            # Poseidon 全部测试通过
cargo test -p poker_zkvm --lib ccs_builder         # CcsBuilder 测试无回归
cargo test -p poker_zkvm --lib precompiles         # 预编译全部测试通过
cargo clippy -p poker_zkvm --all-targets           # 零警告
cargo bench -p poker_zkvm --no-run                 # 基准编译通过
cargo test -p poker_l1 --lib                       # 确保无回归
```

额外验证：
- `test_poseidon_full_matches_host`：电路输出 == `poseidon_hash()` 内部 permutation 结果
- `test_poseidon_full_satisfied_by`：正确 witness 满足所有 ~435 约束
- `test_poseidon_full_soundness_tampered_round`：篡改任一中间变量导致约束失败

### Phase C 完成后
- `cargo test -p poker_zkvm --lib groth16` — Groth16 setup/prove/verify 闭环
- `cargo test -p poker_zkvm --lib r1cs_gadgets` — G1 点运算 + MSM gadget 正确

### Phase D 完成后
```bash
cargo test -p poker_zkvm --features test-helpers --test e2e_fibonacci  # 压缩后 E2E 通过
cargo test -p poker_zkvm --features test-helpers --test soundness_tests
```
- 压缩后 proof < 200 字节
- E2E：`prove` → 压缩 → 链上验证 闭环

## 执行策略

立即从 Phase A2 开始实现。完成后运行验证步骤，确认无回归再进入 Phase C。
