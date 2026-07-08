//! Poseidon 哈希预编译电路（Phase 10 — Task 10.2）。
//!
//! 复用 [`crate::syscalls::poseidon`] 配置（alpha=5, rate=2, capacity=1, 8+56 rounds）。
//! MVP 阶段实现 S-box（x^5）单 round 约束结构，多 round 用重复结构生成。
//!
//! # 约束结构（S-box x^5）
//!
//! witness `z = [1, x, x2, x4, x5]`，约束：
//! - `x2 = x * x`
//! - `x4 = x2 * x2`
//! - `x5 = x4 * x`
//!
//! 使用 7 个行隔离矩阵（每个矩阵仅单一行有非零项），确保 subset 不污染其他行。
//! 这是 CCS 语义的关键要求：ALL subsets 贡献到 ALL rows，因此必须用行隔离
//! 使无关 subset 在对应行求值为 0。

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
    /// S-box 指数（固定 5，与 `syscalls/poseidon.rs` `POSEIDON_ALPHA` 一致）。
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
        //
        // 行隔离原则：每个矩阵只在单一行有非零项，确保包含该矩阵的 subset
        // 在其他行求值得 0（因 (M_j·z)[other_row] = 0，乘积为 0）。
        //
        // 约束（3 行）：
        // - row 0: x*x - x2 = 0  → S_0={0,0} c_0=+1, S_1={1} c_1=-1
        // - row 1: x2*x2 - x4 = 0 → S_2={2,2} c_2=+1, S_3={3} c_3=-1
        // - row 2: x4*x - x5 = 0  → S_4={4,5} c_4=+1, S_5={6} c_5=-1

        let mut m_x_r0 = SparseMatrix::new(3, 5);
        m_x_r0.add_entry(0, 1, Fr::one()).expect("M_x_r0: row 0 col 1");

        let mut m_x2_r0 = SparseMatrix::new(3, 5);
        m_x2_r0
            .add_entry(0, 2, Fr::one())
            .expect("M_x2_r0: row 0 col 2");

        let mut m_x2_r1 = SparseMatrix::new(3, 5);
        m_x2_r1
            .add_entry(1, 2, Fr::one())
            .expect("M_x2_r1: row 1 col 2");

        let mut m_x4_r1 = SparseMatrix::new(3, 5);
        m_x4_r1
            .add_entry(1, 3, Fr::one())
            .expect("M_x4_r1: row 1 col 3");

        let mut m_x4_r2 = SparseMatrix::new(3, 5);
        m_x4_r2
            .add_entry(2, 3, Fr::one())
            .expect("M_x4_r2: row 2 col 3");

        let mut m_x_r2 = SparseMatrix::new(3, 5);
        m_x_r2
            .add_entry(2, 1, Fr::one())
            .expect("M_x_r2: row 2 col 1");

        let mut m_x5_r2 = SparseMatrix::new(3, 5);
        m_x5_r2
            .add_entry(2, 4, Fr::one())
            .expect("M_x5_r2: row 2 col 4");

        let neg_one = Fr::zero().sub(&Fr::one());

        Ccs::new(
            5,
            vec![
                m_x_r0, m_x2_r0, m_x2_r1, m_x4_r1, m_x4_r2, m_x_r2, m_x5_r2,
            ],
            vec![
                vec![0, 0], // S_0: (M_x_r0·z)^2 → row 0: x*x
                vec![1], // S_1: M_x2_r0·z → row 0: x2
                vec![2, 2], // S_2: (M_x2_r1·z)^2 → row 1: x2*x2
                vec![3], // S_3: M_x4_r1·z → row 1: x4
                vec![4, 5], // S_4: (M_x4_r2·z)*(M_x_r2·z) → row 2: x4*x
                vec![6], // S_5: M_x5_r2·z → row 2: x5
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::PrecompileRegistry;

    #[test]
    fn test_poseidon_circuit_build_ccs() {
        let circuit = PoseidonCircuit::new();
        let ccs = circuit.build_ccs();
        assert_eq!(ccs.num_matrices(), 7, "应有 7 个行隔离矩阵");
        assert_eq!(ccs.num_constraints(), 6, "应有 6 个 subsets");
        assert_eq!(ccs.num_rows(), 3, "应有 3 行约束");
        assert_eq!(ccs.num_vars, 5, "witness 应为 5 变量");
    }

    #[test]
    fn test_poseidon_circuit_satisfied_by() {
        let circuit = PoseidonCircuit::new();
        let ccs = circuit.build_ccs();
        // x = 3 → x2=9, x4=81, x5=243
        let x = Fr::from_u32_with_wrap(3);
        let witness = circuit.assign_witness(&[x]).expect("assign_witness 应成功");
        assert_eq!(witness.len(), 5);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_poseidon_circuit_soundness_tampered_x5() {
        let circuit = PoseidonCircuit::new();
        let ccs = circuit.build_ccs();
        let x = Fr::from_u32_with_wrap(3);
        let mut witness = circuit.assign_witness(&[x]).expect("assign_witness 应成功");
        // 篡改 x5（z[4]）→ 243 改为 244
        witness[4] = Fr::from_u32_with_wrap(244);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 x5 后应不满足约束"
        );
    }

    #[test]
    fn test_poseidon_circuit_soundness_tampered_x2() {
        let circuit = PoseidonCircuit::new();
        let ccs = circuit.build_ccs();
        let x = Fr::from_u32_with_wrap(3);
        let mut witness = circuit.assign_witness(&[x]).expect("assign_witness 应成功");
        // 篡改 x2（z[2]）→ 9 改为 10
        witness[2] = Fr::from_u32_with_wrap(10);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 x2 后应不满足约束"
        );
    }

    #[test]
    fn test_poseidon_circuit_consistency_with_host() {
        // x5 应与 ark_bn254::Fr 的 x^5 一致
        let circuit = PoseidonCircuit::new();
        let x_bn = Fr::from_u32_with_wrap(7);
        let witness = circuit.assign_witness(&[x_bn]).expect("assign_witness 应成功");
        let x5 = witness[4];

        // 通过 ark_bn254::Fr 直接计算 x^5 验证
        let x_fr = x_bn.into_fr();
        let expected = x_fr * x_fr * x_fr * x_fr * x_fr;
        assert_eq!(x5.into_fr(), expected, "x5 应与 ark_bn254::Fr 的 x^5 一致");
    }

    #[test]
    fn test_poseidon_circuit_empty_input() {
        let circuit = PoseidonCircuit::new();
        let result = circuit.assign_witness(&[]);
        assert!(result.is_err(), "空输入应返回错误");
    }

    #[test]
    fn test_poseidon_circuit_wrong_input_length() {
        let circuit = PoseidonCircuit::new();
        let result = circuit.assign_witness(&[Fr::one(), Fr::one()]);
        assert!(result.is_err(), "输入长度 != 1 应返回错误");
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
        assert_eq!(circuit.gas_cost(), 200, "gas_cost 应为 200");
    }

    #[test]
    fn test_poseidon_circuit_ccs_circuit_trait() {
        let circuit = PoseidonCircuit::new();
        let x = Fr::from_u32_with_wrap(5);
        let witness = circuit.assign_witness(&[x]).expect("assign_witness 应成功");
        let public_inputs = vec![Fr::one()];

        // 通过 CcsCircuit trait object 调用
        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "poseidon");
        assert_eq!(ccs_circuit.num_matrices(), 7);

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance 应成功");
        assert!(instance.is_satisfied().expect("is_satisfied 应成功"));
    }
}
