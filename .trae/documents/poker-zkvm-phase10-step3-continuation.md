# poker_zkvm Phase 10 → Phase 5 续接计划（Step 3 起）

> **change-id**：`build-hypernova-zkvm`
> **spec 版本**：v1.4 FROZEN
> **前置状态**：Phase 0-4 完成（319 测试）；Step 1（CCS，17 测试）+ Step 2（precompiles mod，6 测试）已完成
> **当前问题**：`precompiles/mod.rs` 第 20 行声明 `pub mod poseidon;` 但 `precompiles/poseidon.rs` 不存在 → **编译失败**
> **批准的详细设计**：`/Users/mac/projects/zchain/.trae/documents/poker-zkvm-phase5-10-execution-plan.md`（14 步）
> **批准的详细设计文档**：`/Users/mac/projects/zchain/.trae/documents/poker-zkvm-phase10-then-phase5-plan.md`（583 行）

---

## 一、当前状态确认（Phase 1 探索结果）

### 1.1 已完成

| 步骤 | 文件 | 状态 | 测试 |
|------|------|------|------|
| Step 1 | [ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs) | ✅ 完成 | 17 测试（SparseMatrix / Ccs / CcsInstance） |
| Step 2 | [precompiles/mod.rs](file:////Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs) | ✅ 完成 | 6 测试（PrecompileRegistry / MockMulCircuit / MockCcsCircuit） |
| Step 2 | [lib.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/lib.rs) L48 | ✅ 完成 | `pub mod precompiles;` 已声明 |
| Step 3 准备 | [syscalls/poseidon.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/syscalls/poseidon.rs) L53 | ✅ 完成 | `poseidon_config()` 已改为 `pub fn` |

### 1.2 当前阻塞点

[precompiles/mod.rs:20](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L20) 声明 `pub mod poseidon;`，但 `precompiles/poseidon.rs` 文件不存在 → `cargo build` 失败。

### 1.3 关键类型与 API（已就绪）

**CCS 数据结构**（[ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs)）：
- `pub type Fr = Bn254ScalarField;`（L25）
- `SparseMatrix { num_rows, num_cols, entries: Vec<SparseEntry> }` — `new()` / `add_entry(row, col, value)` / `get(row, col)` / `evaluate(z: &[Fr]) -> Result<Vec<Fr>, ZkvmError>`
- `Ccs { num_vars, matrices, subsets, coeffs }` — `new(...)` / `satisfied_by(z: &[Fr]) -> Result<bool, ZkvmError>` / `num_matrices()` / `num_constraints()` / `num_rows()`
- `CcsInstance { ccs, witness, public_inputs }` — `new(...)` / `is_satisfied()`

**域元素转换**（[field.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/field.rs)）：
- `Bn254ScalarField::from_fr(fr: ark_bn254::Fr) -> Self`（L91，const fn）
- `Bn254ScalarField::into_fr(self) -> ark_bn254::Fr`（L101）
- `Bn254ScalarField::as_fr(&self) -> &ark_bn254::Fr`（L96，const fn）
- `ZkvmField` trait：`from_u32_with_wrap` / `from_u64` / `zero` / `one` / `add` / `sub` / `mul` / `square` / `inverse`

**Poseidon host**（[syscalls/poseidon.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/syscalls/poseidon.rs)）：
- `pub fn poseidon_config() -> &'static PoseidonConfig<ark_bn254::Fr>`（L53）— alpha=5, rate=2, capacity=1, 8 full + 56 partial rounds
- `pub fn poseidon_hash(inputs: &[ark_bn254::Fr]) -> ark_bn254::Fr`（L82）
- `pub fn poseidon_hash_bytes(input: &[u8]) -> ark_bn254::Fr`（L101）
- `pub fn poseidon_compress(left: &ark_bn254::Fr, right: &ark_bn254::Fr) -> ark_bn254::Fr`（L115）

**预编译 trait**（[precompiles/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs)）：
- `PrecompileCircuit` trait（L40-58）：`name()` / `num_variables()` / `build_ccs() -> Ccs` / `assign_witness(&[Fr]) -> Result<Vec<Fr>, ZkvmError>` / `gas_cost() -> u64`
- `PrecompileRegistry`（L71-112）：`new()` / `register(Box<dyn PrecompileCircuit>)` / `get(&str) -> Option<&dyn PrecompileCircuit>` / `len()` / `is_empty()`
- `CcsCircuit` trait（L124-144）：`name()` / `num_matrices()` / `to_ccs_instance(&[Fr], &[Fr]) -> Result<CcsInstance, ZkvmError>`

---

## 二、续接执行计划（Step 3-14）

严格遵循已批准的 `poker-zkvm-phase5-10-execution-plan.md` 14 步计划。本计划聚焦 Step 3（当前阻塞点），Step 4-14 按已批准计划执行。

### Step 3：Poseidon 预编译电路（Task 10.2）— **立即执行**

**文件**：新建 [poker_zkvm/src/precompiles/poseidon.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/poseidon.rs)

**目标**：修复编译错误 + 实现 Poseidon 哈希 CCS 约束电路，与 host `poseidon_hash_bytes` 输出一致。

**实现内容**：

1. **`PoseidonCircuit` struct**：
   ```rust
   /// Poseidon 哈希预编译电路（Phase 10 — Task 10.2）。
   ///
   /// 复用 syscalls/poseidon.rs 配置（alpha=5, rate=2, capacity=1, 8 full + 56 partial rounds）。
   /// MVP 阶段实现单 round S-box 约束结构，多 round 用重复结构生成。
   #[derive(Debug, Clone)]
   pub struct PoseidonCircuit {
       /// 是否为完整 permutation 模式（false = 仅 S-box 单 round 验证）。
       full_mode: bool,
   }
   ```

2. **MVP 策略（S-box 单 round 验证）**：
   - S-box（x^5）用 3 个约束表达：
     - `x2 = x * x`（乘法约束）
     - `x4 = x2 * x2`（乘法约束）
     - `x5 = x4 * x`（乘法约束）
   - witness 向量 `z = [1, x, x2, x4, x5]`（5 变量）
   - 矩阵（行隔离，参考 Step 1 `test_ccs_multiple_matrices` 模式）：
     - `M_0`：提取 `x`（z[1]）
     - `M_1`：提取 `x2`（z[2]）
     - `M_2`：提取 `x4`（z[3]）
     - `M_3`：提取 `x5`（z[4]）
   - 约束：
     - `S_0={0,0}, c_0=1` → `x * x`（注意：CCS subset 是矩阵索引集合，同一索引可重复 → `Π_{j∈{0,0}} M_j·z = (M_0·z)^2`）

   **修正**：CCS subset 是矩阵索引的多重集，`S={0,0}` 表示 `M_0·z` 的平方。但 Step 1 的 `test_ccs_multiple_matrices` 用了不同矩阵隔离行。更清晰的做法：
   - `M_x`：提取 `x`（z[1]）
   - `M_x2`：提取 `x2`（z[2]）
   - `M_x4`：提取 `x4`（z[3]）
   - `M_x5`：提取 `x5`（z[4]）
   - 约束 1：`x * x - x2 = 0` → `S_0={M_x, M_x}, c_0=1` + `S_1={M_x2}, c_1=-1`
   - 约束 2：`x2 * x2 - x4 = 0` → `S_2={M_x2, M_x2}, c_2=1` + `S_3={M_x4}, c_3=-1`
   - 约束 3：`x4 * x - x5 = 0` → `S_4={M_x4, M_x}, c_4=1` + `S_5={M_x5}, c_5=-1`
   - 每个约束占 1 行（行隔离），共 3 行

3. **`PrecompileCircuit` trait 实现**：
   - `name()` → `"poseidon"`
   - `num_variables()` → 5（z = [1, x, x2, x4, x5]）
   - `build_ccs()` → 构造上述 3 行 × 4 矩阵的 CCS
   - `assign_witness(inputs: &[Fr])` → `inputs[0]` 作为 `x`，计算 `x2/x4/x5`，返回 `[1, x, x2, x4, x5]`
   - `gas_cost()` → 对齐 spec L637（~200 gas/round，MVP 单 round 返回 200）

4. **`CcsCircuit` trait 实现**（可选，供 Phase 11 集成）：
   - `name()` → `"poseidon"`
   - `num_matrices()` → 4
   - `to_ccs_instance(witness, public_inputs)` → 构造 CcsInstance

5. **host 一致性**：
   - `assign_witness` 计算的 `x5`（即 `x^5`）应与 host `poseidon_hash_bytes` 无直接可比性（host 是完整 64-round permutation）
   - MVP 一致性测试：`x5 == x.mul(&x).mul(&x).mul(&x).mul(&x)`（域内 x^5），并验证 `x5` 与 `ark_bn254::Fr` 的 `x^5` 一致（通过 `into_fr` 转换）

**测试**（10）：
1. `test_poseidon_circuit_build_ccs` — CCS 结构合理（7 矩阵 / 6 subset / 3 行）
2. `test_poseidon_circuit_satisfied_by` — 合法 witness（x=3）通过 satisfied_by
3. `test_poseidon_circuit_soundness_tampered_x5` — 篡改 x5 后 satisfied_by 失败
4. `test_poseidon_circuit_soundness_tampered_x2` — 篡改 x2 后 satisfied_by 失败
5. `test_poseidon_circuit_consistency_with_host` — `x5` 与 `ark_bn254::Fr` 的 `x^5` 一致
6. `test_poseidon_circuit_empty_input` — 空输入返回错误
7. `test_poseidon_circuit_wrong_input_length` — 输入长度 != 1 返回错误
8. `test_poseidon_circuit_registry_integration` — 注册到 PrecompileRegistry 并查找
9. `test_poseidon_circuit_gas_cost` — gas_cost 返回合理值
10. `test_poseidon_circuit_ccs_circuit_trait` — CcsCircuit trait object dispatch

**未选择方案**（写入 alternatives.md Step 3 章节）：
- 完整 Poseidon 电路（64 round × 15 约束 = 960 约束）— 实现量大，MVP 阶段先实现 S-box 单 round 结构
- lookup 优化 Poseidon（部分 S-box 通过查表）— 依赖 LogUp（Step 13），本步骤先用纯约束

### Step 4-14（按已批准计划执行，此处仅摘要）

| 步骤 | 文件 | 目标 | 测试数 |
|------|------|------|--------|
| Step 4 | `precompiles/sha256.rs`（新建） | SHA-256 电路，与 `sha2` crate 一致 | 6-8 |
| Step 5 | `precompiles/ecdsa.rs`（新建） | ECDSA 验签电路骨架（~110k 约束 MVP） | 6-8 |
| Step 6 | `precompiles/zk_shuffle.rs`（新建）+ `poker_l1/src/offline/ccs.rs`（修改） | ZkShuffleCcsCircuit 迁移，保持 stub | 3-4 |
| Step 7 | `precompiles/mod.rs`（修改）+ `docs/alternatives.md`（修改） | Phase 10 集成测试 + 文档 | 3-5 |
| Step 8 | `constraints/mod.rs`（重写） | compile_trace_to_ccs + batching | 4-6 |
| Step 9 | `constraints/algebra.rs`（新建） | 算术指令子电路（ADD/SUB/SHIFT/DIV） | 15-20 |
| Step 10 | `constraints/memory.rs`（重写） | byte-level permutation 内存一致性 | 10-15 |
| Step 11 | `constraints/control_flow.rs`（新建） | JAL/JALR/BEQ/.../LUI/AUIPC | 8-12 |
| Step 12 | `constraints/syscall_circuit.rs`（新建） | ECALL 分派到 PrecompileRegistry | 9-12 |
| Step 13 | `lookup/mod.rs`（重写） | LogUp lookup 协议 | 8-10 |
| Step 14 | `constraints/mod.rs`（修改）+ `docs/alternatives.md`（修改） | Phase 5 集成测试 + 文档 | 2-4 |

详细实现见 `/Users/mac/projects/zchain/.trae/documents/poker-zkvm-phase5-10-execution-plan.md` 第 99-187 行。

---

## 三、Step 3 详细实现方案

### 3.1 CCS 约束设计（关键 — 行隔离原则）

**核心约束**（S-box x^5，3 个等式）：
- `x2 = x * x`
- `x4 = x2 * x2`
- `x5 = x4 * x`

**witness 向量**：`z = [1, x, x2, x4, x5]`（5 变量）

**关键教训（来自 Step 1 `test_ccs_multiple_matrices`）**：CCS 中 ALL subsets 贡献到 ALL rows。
若矩阵 M_j 在 row 0 和 row 1 都有非零项，则 `(M_j·z)[0]` 和 `(M_j·z)[1]` 都非零，
导致包含 M_j 的 subset 在两行都产生非零乘积，污染其他行的约束。

**解决方案**：行隔离 — 每个矩阵只在**单一行**有非零项。
同一变量在不同行使用时，需要不同的矩阵。

**矩阵设计**（7 个矩阵，每个 3 行 × 5 列，仅在对应行有 1 个非零项）：

| 矩阵索引 | 名称 | 非零位置 | 提取变量 |
|----------|------|----------|----------|
| 0 | M_x_r0 | (0, 1) | row 0 提取 x (z[1]) |
| 1 | M_x2_r0 | (0, 2) | row 0 提取 x2 (z[2]) |
| 2 | M_x2_r1 | (1, 2) | row 1 提取 x2 (z[2]) |
| 3 | M_x4_r1 | (1, 3) | row 1 提取 x4 (z[3]) |
| 4 | M_x4_r2 | (2, 3) | row 2 提取 x4 (z[3]) |
| 5 | M_x_r2 | (2, 1) | row 2 提取 x (z[1]) |
| 6 | M_x5_r2 | (2, 4) | row 2 提取 x5 (z[4]) |

**子集与系数**（6 个 subset）：

| subset | 矩阵索引 | 系数 | row 0 贡献 | row 1 贡献 | row 2 贡献 |
|--------|----------|------|------------|------------|------------|
| S_0 | {0, 0} | +1 | x*x | 0*0=0 | 0*0=0 |
| S_1 | {1} | -1 | -x2 | 0 | 0 |
| S_2 | {2, 2} | +1 | 0 | x2*x2 | 0 |
| S_3 | {3} | -1 | 0 | -x4 | 0 |
| S_4 | {4, 5} | +1 | 0 | 0 | x4*x |
| S_5 | {6} | -1 | 0 | 0 | -x5 |

**逐行校验**：
- row 0: `x*x - x2 + 0 + 0 + 0 + 0 = x^2 - x2 = 0` ✓（因 x2 = x*x）
- row 1: `0 + 0 + x2*x2 - x4 + 0 + 0 = x2^2 - x4 = 0` ✓（因 x4 = x2*x2）
- row 2: `0 + 0 + 0 + 0 + x4*x - x5 = x4*x - x5 = 0` ✓（因 x5 = x4*x）

### 3.2 文件结构

```rust
//! Poseidon 哈希预编译电路（Phase 10 — Task 10.2）。
//!
//! 复用 syscalls/poseidon.rs 配置（alpha=5, rate=2, capacity=1, 8+56 rounds）。
//! MVP 阶段实现 S-box（x^5）单 round 约束结构，多 round 用重复结构生成。
//!
//! # 约束结构（S-box x^5）
//!
//! witness z = [1, x, x2, x4, x5]
//! - x2 = x * x
//! - x4 = x2 * x2
//! - x5 = x4 * x
//!
//! 使用 7 个行隔离矩阵（每个矩阵仅单一行有非零项），确保 subset 不污染其他行。
//! 详见 build_ccs() 文档。

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// Poseidon 哈希预编译电路。
///
/// MVP 实现仅约束 S-box（x^5）单 round 结构。
/// 完整 64-round Poseidon permutation 留待后续迭代。
#[derive(Debug, Clone)]
pub struct PoseidonCircuit {
    /// S-box 指数（固定 5，与 syscalls/poseidon.rs POSEIDON_ALPHA 一致）。
    alpha: u64,
}

impl PoseidonCircuit {
    /// 创建 Poseidon 电路（alpha=5）。
    #[must_use]
    pub fn new() -> Self {
        Self { alpha: 5 }
    }

    /// 返回 alpha 值。
    #[must_use]
    pub fn alpha(&self) -> u64 {
        self.alpha
    }
}

impl Default for PoseidonCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for PoseidonCircuit {
    fn name(&self) -> &str {
        "poseidon"
    }

    fn num_variables(&self) -> usize {
        // z = [1, x, x2, x4, x5]
        5
    }

    fn build_ccs(&self) -> Ccs {
        // 7 个行隔离矩阵，每个 3 行 × 5 列
        // 矩阵索引: 0=M_x_r0, 1=M_x2_r0, 2=M_x2_r1, 3=M_x4_r1, 4=M_x4_r2, 5=M_x_r2, 6=M_x5_r2

        let mut m_x_r0 = SparseMatrix::new(3, 5);
        m_x_r0.add_entry(0, 1, Fr::one()).expect("M_x_r0");

        let mut m_x2_r0 = SparseMatrix::new(3, 5);
        m_x2_r0.add_entry(0, 2, Fr::one()).expect("M_x2_r0");

        let mut m_x2_r1 = SparseMatrix::new(3, 5);
        m_x2_r1.add_entry(1, 2, Fr::one()).expect("M_x2_r1");

        let mut m_x4_r1 = SparseMatrix::new(3, 5);
        m_x4_r1.add_entry(1, 3, Fr::one()).expect("M_x4_r1");

        let mut m_x4_r2 = SparseMatrix::new(3, 5);
        m_x4_r2.add_entry(2, 3, Fr::one()).expect("M_x4_r2");

        let mut m_x_r2 = SparseMatrix::new(3, 5);
        m_x_r2.add_entry(2, 1, Fr::one()).expect("M_x_r2");

        let mut m_x5_r2 = SparseMatrix::new(3, 5);
        m_x5_r2.add_entry(2, 4, Fr::one()).expect("M_x5_r2");

        let neg_one = Fr::zero().sub(&Fr::one());

        Ccs::new(
            5,
            vec![m_x_r0, m_x2_r0, m_x2_r1, m_x4_r1, m_x4_r2, m_x_r2, m_x5_r2],
            vec![
                vec![0, 0], // S_0: (M_x_r0·z)^2 → row 0: x*x
                vec![1],     // S_1: M_x2_r0·z   → row 0: x2
                vec![2, 2], // S_2: (M_x2_r1·z)^2 → row 1: x2*x2
                vec![3],     // S_3: M_x4_r1·z   → row 1: x4
                vec![4, 5], // S_4: (M_x4_r2·z)*(M_x_r2·z) → row 2: x4*x
                vec![6],     // S_5: M_x5_r2·z   → row 2: x5
            ],
            vec![
                Fr::one(),  // c_0: +x*x
                neg_one,    // c_1: -x2
                Fr::one(),  // c_2: +x2*x2
                neg_one,    // c_3: -x4
                Fr::one(),  // c_4: +x4*x
                neg_one,    // c_5: -x5
            ],
        )
        .expect("PoseidonCircuit CCS 构造应成功")
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if inputs.len() != 1 {
            return Err(ZkvmError::Other(format!(
                "PoseidonCircuit::assign_witness: inputs.len() {} != 1（MVP 单 S-box 输入）",
                inputs.len()
            )));
        }
        let x = inputs[0];
        let x2 = x.square();
        let x4 = x2.square();
        let x5 = x4.mul(&x);
        Ok(vec![Fr::one(), x, x2, x4, x5])
    }

    fn gas_cost(&self) -> u64 {
        // spec L637: Poseidon ~200 gas/round；MVP 单 S-box round
        200
    }
}

impl CcsCircuit for PoseidonCircuit {
    fn name(&self) -> &str {
        "poseidon"
    }

    fn num_matrices(&self) -> usize {
        7
    }

    fn to_ccs_instance(
        &self,
        witness: &[Fr],
        public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError> {
        let ccs = self.build_ccs();
        CcsInstance::new(ccs, witness.to_vec(), public_inputs.to_vec())
    }
}
```

### 3.3 测试模块

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::PrecompileRegistry;

    #[test]
    fn test_poseidon_circuit_build_ccs() {
        let circuit = PoseidonCircuit::new();
        let ccs = circuit.build_ccs();
        assert_eq!(ccs.num_matrices(), 7); // 7 个行隔离矩阵
        assert_eq!(ccs.num_constraints(), 6); // 6 subsets
        assert_eq!(ccs.num_rows(), 3);
        assert_eq!(ccs.num_vars, 5);
    }

    #[test]
    fn test_poseidon_circuit_satisfied_by() {
        let circuit = PoseidonCircuit::new();
        let ccs = circuit.build_ccs();
        // x = 3 → x2=9, x4=81, x5=243
        let x = Fr::from_u32_with_wrap(3);
        let witness = circuit.assign_witness(&[x]).expect("assign_witness");
        assert_eq!(witness.len(), 5);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    #[test]
    fn test_poseidon_circuit_soundness_tampered_x5() {
        let circuit = PoseidonCircuit::new();
        let ccs = circuit.build_ccs();
        let x = Fr::from_u32_with_wrap(3);
        let mut witness = circuit.assign_witness(&[x]).expect("assign_witness");
        // 篡改 x5（z[4]）→ 243 改为 244
        witness[4] = Fr::from_u32_with_wrap(244);
        assert!(!ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    #[test]
    fn test_poseidon_circuit_soundness_tampered_x2() {
        let circuit = PoseidonCircuit::new();
        let ccs = circuit.build_ccs();
        let x = Fr::from_u32_with_wrap(3);
        let mut witness = circuit.assign_witness(&[x]).expect("assign_witness");
        // 篡改 x2（z[2]）→ 9 改为 10
        witness[2] = Fr::from_u32_with_wrap(10);
        assert!(!ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    #[test]
    fn test_poseidon_circuit_consistency_with_host() {
        // x5 应与 ark_bn254::Fr 的 x^5 一致
        let circuit = PoseidonCircuit::new();
        let x_bn = Fr::from_u32_with_wrap(7);
        let witness = circuit.assign_witness(&[x_bn]).expect("assign_witness");
        let x5 = witness[4];

        // 通过 ark_bn254::Fr 验证
        let x_fr = x_bn.into_fr();
        let expected = x_fr * x_fr * x_fr * x_fr * x_fr;
        assert_eq!(x5.into_fr(), expected);
    }

    #[test]
    fn test_poseidon_circuit_empty_input() {
        let circuit = PoseidonCircuit::new();
        let result = circuit.assign_witness(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_poseidon_circuit_wrong_input_length() {
        let circuit = PoseidonCircuit::new();
        let result = circuit.assign_witness(&[Fr::one(), Fr::one()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_poseidon_circuit_registry_integration() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(PoseidonCircuit::new()));
        assert_eq!(registry.len(), 1);
        let circuit = registry.get("poseidon").expect("应找到 poseidon");
        assert_eq!(circuit.name(), "poseidon");
        assert_eq!(circuit.num_variables(), 5);
        assert_eq!(circuit.gas_cost(), 200);
    }

    #[test]
    fn test_poseidon_circuit_gas_cost() {
        let circuit = PoseidonCircuit::new();
        assert_eq!(circuit.gas_cost(), 200);
    }

    #[test]
    fn test_poseidon_circuit_ccs_circuit_trait() {
        let circuit = PoseidonCircuit::new();
        let x = Fr::from_u32_with_wrap(5);
        let witness = circuit.assign_witness(&[x]).expect("assign_witness");
        let public_inputs = vec![Fr::one()];

        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "poseidon");
        assert_eq!(ccs_circuit.num_matrices(), 7);

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance");
        assert!(instance.is_satisfied().expect("is_satisfied"));
    }
}
```

---

## 四、验证步骤

### Step 3 完成后

1. **`cargo build -p poker_zkvm`** — 编译成功（修复 `pub mod poseidon;` 缺失文件错误）
2. **`cargo test -p poker_zkvm --lib precompiles::poseidon`** — 10 个新测试全部通过
3. **`cargo test -p poker_zkvm`** — 全部测试通过（既有 312 + 新增 10 = 322）
4. **`cargo clippy -p poker_zkvm --all-targets -- -D warnings`** — 零警告
5. **`#![deny(unsafe_code)]` + `#![deny(missing_docs)]`** — 所有 public item 有 `///` 文档

### Step 4-14 每个 Step 完成后

同上验证流程，累计测试数逐步增长。

### 最终验证（Step 14 完成后）

- **总测试数** ≈ 319（既有）+ 90-130（新增）= 409-449
- **clippy 零警告**
- **alternatives.md** 含 Phase 10 + Phase 5 章节
- **tasks.md** Phase 5 + Phase 10 全部 `[x]` 勾选
- **checklist.md** Phase 5 + Phase 10 全部勾选

---

## 五、假设与约束

1. **spec v1.4 FROZEN** — 严格遵循 spec.md L268-312 + L637-669
2. **TDD 严格模式** — 每个 Step 按 RED → GREEN → REFACTOR，测试通过后才进入下一步
3. **不修改 Phase 0-4 既有代码** — 除已完成的 `syscalls/poseidon.rs::poseidon_config()` 改 public 外
4. **poker_l1 修改最小化** — 仅 Step 6 添加 re-export + deprecated 标记
5. **Phase 6+ 不在本计划范围** — Hypernova 折叠留待后续 Phase
6. **CCS 数据结构为 Phase 6 预留** — `to_lcccs()` / `to_cccs()` 方法签名定义但返回 `Err(Other("Phase 6 pending"))`
7. **多个方案时选择推荐的，未选择方案放 alternatives.md** — 遵循用户既定工作流
8. **Step 3 MVP 范围** — 仅实现 S-box（x^5）单 round 约束结构；完整 64-round Poseidon 留待后续迭代

---

## 六、执行顺序

```
Step 3: Poseidon 预编译电路  ← 立即执行（修复编译）
Step 4: SHA-256 预编译电路
Step 5: ECDSA 预编译电路
Step 6: ZkShuffleCcsCircuit 迁移
Step 7: Phase 10 集成测试 + 文档
─── Phase 10 完成 ───
Step 8: compile_trace_to_ccs + batching
Step 9: 算术指令子电路
Step 10: 内存访问子电路
Step 11: 控制流子电路
Step 12: Syscall 子电路
Step 13: LogUp lookup 协议
Step 14: Phase 5 集成测试 + 文档
─── Phase 5 完成 ───
```
