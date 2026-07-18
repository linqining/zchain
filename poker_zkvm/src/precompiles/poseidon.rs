//! Poseidon 哈希预编译电路（Phase 10 — Task 10.2 / Stage 3 — Phase A2）。
//!
//! 复用 [`crate::syscalls::poseidon`] 配置（alpha=5, rate=2, capacity=1, 8+56 rounds）。
//!
//! # 两种模式
//!
//! - **MVP 模式**（`new()`）：S-box（x^5）单 round 约束结构，5 变量，7 矩阵。
//! - **完整模式**（`new_full()`）：64 轮 Poseidon permutation，~435 约束，~439 变量。
//!
//! # MVP 约束结构（S-box x^5）
//!
//! witness `z = [1, x, x2, x4, x5]`，约束：
//! - `x2 = x * x`
//! - `x4 = x2 * x2`
//! - `x5 = x4 * x`
//!
//! # 完整模式约束结构（64 轮 permutation）
//!
//! Permutation: 4 full → 56 partial → 4 full = 64 轮。
//! 每轮：ARK → S-box(x^5) → MDS。
//! 优化：将 round r 的 MDS 与 round r+1 的 ARK 合并为单一仿射线性约束。
//!
//! 使用 [`CcsBuilder`] 程序化构建，自动遵循行隔离模式。

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::{Bn254ScalarField, ZkvmField};
use crate::precompiles::ccs_builder::CcsBuilder;
use crate::precompiles::{CcsCircuit, PrecompileCircuit};
use crate::syscalls::poseidon::poseidon_config;

/// Poseidon permutation 总轮数。
const POSEIDON_TOTAL_ROUNDS: u64 = 64;

/// Full round 数（前 4 轮 + 后 4 轮）。
const POSEIDON_FULL_ROUNDS_HALF: u64 = 4;

/// 完整模式变量数（z[0]=1 + 初始 state 3 + 64 轮中间变量）。
/// Round 0: 15 vars (3 ARK + 9 S-box + 3 MDS+ARK)
/// Rounds 1-3 (full): 12 each = 36
/// Rounds 4-59 (partial): 6 each = 336
/// Rounds 60-62 (full): 12 each = 36
/// Round 63 (full, last): 12 (9 S-box + 3 MDS)
/// Total: 1 + 3 + 15 + 36 + 336 + 36 + 12 = 439
const FULL_MODE_NUM_VARS: usize = 439;

/// 完整模式 gas 成本（64 轮 × 200 gas/round）。
const FULL_MODE_GAS_COST: u64 = 12_800;

/// Poseidon 哈希预编译电路。
///
/// 支持两种模式：
/// - MVP 模式（`new()`）：单 S-box 约束，用于快速测试
/// - 完整模式（`new_full()`）：64 轮 Poseidon permutation
#[derive(Debug, Clone)]
pub struct PoseidonCircuit {
    /// S-box 指数（固定 5，与 `syscalls/poseidon.rs` `POSEIDON_ALPHA` 一致）。
    alpha: u64,
    /// 是否使用完整 64 轮 permutation 模式。
    full_mode: bool,
}

impl PoseidonCircuit {
    /// 创建 Poseidon 电路（完整 64 轮 permutation 模式，alpha=5）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            alpha: 5,
            full_mode: true,
        }
    }

    /// 创建 Poseidon 电路（MVP 模式，单 S-box 约束，用于快速测试）。
    #[must_use]
    pub fn new_mvp() -> Self {
        Self {
            alpha: 5,
            full_mode: false,
        }
    }

    /// 创建 Poseidon 电路（完整 64 轮 permutation 模式）。
    #[must_use]
    pub fn new_full() -> Self {
        Self {
            alpha: 5,
            full_mode: true,
        }
    }

    /// 返回 alpha 值。
    #[must_use]
    pub fn alpha(&self) -> u64 {
        self.alpha
    }

    /// 是否为完整模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    /// 用 CcsBuilder 构建完整 64 轮 permutation CCS。
    ///
    /// 变量分配顺序（与 `assign_full_witness` 严格一致）：
    /// - z[0] = 1（常数，CcsBuilder 自动保留）
    /// - z[1..4] = 初始 state [s0, s1, s2]
    /// - 每轮按 ARK(仅 round 0) → S-box → MDS(+ARK) 顺序分配
    fn build_full_ccs(&self) -> Ccs {
        let config = poseidon_config();
        let mut builder = CcsBuilder::new();

        // z[1..4] = 初始 state
        let s0 = builder.alloc_var();
        let s1 = builder.alloc_var();
        let s2 = builder.alloc_var();

        let mut current = [s0, s1, s2];

        for round in 0..POSEIDON_TOTAL_ROUNDS {
            let is_full = !(POSEIDON_FULL_ROUNDS_HALF..60).contains(&round);
            let is_first = round == 0;
            let is_last = round == POSEIDON_TOTAL_ROUNDS - 1;

            // Step 1: ARK（仅 round 0；后续轮的 ARK 已合并到上一轮的 MDS）
            let sbox_in = if is_first {
                let a0 = builder.alloc_var();
                let a1 = builder.alloc_var();
                let a2 = builder.alloc_var();

                // 约束: a_i - current_i - ark[round][i] = 0
                for i in 0..3 {
                    let row = builder.alloc_row();
                    let ark_val = Bn254ScalarField::from_fr(config.ark[round as usize][i]);
                    builder.add_linear(
                        row,
                        &[
                            ([a0, a1, a2][i], Fr::one()),
                            (current[i], Fr::one().neg()),
                            (0, ark_val.neg()),
                        ],
                    );
                }

                [a0, a1, a2]
            } else {
                current
            };

            // Step 2: S-box (x^5 = x² → x⁴ → x⁵)
            // Full round: 3 个元素都做 S-box
            // Partial round: 仅 state[0] 做 S-box
            let sbox_out = if is_full {
                let mut outs = [0usize; 3];
                for i in 0..3 {
                    let sq = builder.alloc_var();
                    let quad = builder.alloc_var();
                    let quint = builder.alloc_var();

                    let r1 = builder.alloc_row();
                    builder.add_multiplication(r1, sbox_in[i], sbox_in[i], sq);
                    let r2 = builder.alloc_row();
                    builder.add_multiplication(r2, sq, sq, quad);
                    let r3 = builder.alloc_row();
                    builder.add_multiplication(r3, quad, sbox_in[i], quint);

                    outs[i] = quint;
                }
                outs
            } else {
                // Partial: 仅 elem 0
                let sq = builder.alloc_var();
                let quad = builder.alloc_var();
                let quint = builder.alloc_var();

                let r1 = builder.alloc_row();
                builder.add_multiplication(r1, sbox_in[0], sbox_in[0], sq);
                let r2 = builder.alloc_row();
                builder.add_multiplication(r2, sq, sq, quad);
                let r3 = builder.alloc_row();
                builder.add_multiplication(r3, quad, sbox_in[0], quint);

                [quint, sbox_in[1], sbox_in[2]]
            };

            // Step 3: MDS（+ ARK[round+1] 如果非末轮）
            // 约束: ns_i - sum_j(mds[i][j] * sbox_out_j) - ark_next_i = 0
            let ns0 = builder.alloc_var();
            let ns1 = builder.alloc_var();
            let ns2 = builder.alloc_var();
            let new_state = [ns0, ns1, ns2];

            for (i, &ns_i) in new_state.iter().enumerate() {
                let row = builder.alloc_row();
                let mut terms = Vec::with_capacity(5);
                terms.push((ns_i, Fr::one()));
                for (j, &sbox_out_j) in sbox_out.iter().enumerate() {
                    let mds_val = Bn254ScalarField::from_fr(config.mds[i][j]);
                    terms.push((sbox_out_j, mds_val.neg()));
                }
                if !is_last {
                    let ark_next = Bn254ScalarField::from_fr(config.ark[(round + 1) as usize][i]);
                    terms.push((0, ark_next.neg()));
                }
                builder.add_linear(row, &terms);
            }

            current = new_state;
        }

        builder.build().expect("Poseidon full CCS 构造应成功")
    }

    /// 运行完整 64 轮 permutation 并记录所有中间值。
    ///
    /// witness 分配顺序与 `build_full_ccs` 严格一致。
    fn assign_full_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if inputs.len() != 3 {
            return Err(ZkvmError::Other(format!(
                "PoseidonCircuit::assign_full_witness: inputs.len() {} != 3（完整模式需要 3 个 state 元素）",
                inputs.len()
            )));
        }

        let config = poseidon_config();
        let mut witness = Vec::with_capacity(FULL_MODE_NUM_VARS);

        // z[0] = 1（常数）
        witness.push(Fr::one());

        // z[1..4] = 初始 state
        let mut state = [inputs[0], inputs[1], inputs[2]];
        witness.extend_from_slice(&state);

        for round in 0..POSEIDON_TOTAL_ROUNDS {
            let is_full = !(POSEIDON_FULL_ROUNDS_HALF..60).contains(&round);
            let is_first = round == 0;
            let is_last = round == POSEIDON_TOTAL_ROUNDS - 1;

            // Step 1: ARK（仅 round 0）
            let sbox_in = if is_first {
                let a = [
                    state[0].add(&Bn254ScalarField::from_fr(config.ark[round as usize][0])),
                    state[1].add(&Bn254ScalarField::from_fr(config.ark[round as usize][1])),
                    state[2].add(&Bn254ScalarField::from_fr(config.ark[round as usize][2])),
                ];
                witness.extend_from_slice(&a);
                a
            } else {
                state
            };

            // Step 2: S-box
            let sbox_out = if is_full {
                let mut outs = [Fr::zero(); 3];
                for i in 0..3 {
                    let sq = sbox_in[i].square();
                    let quad = sq.square();
                    let quint = quad.mul(&sbox_in[i]);
                    witness.push(sq);
                    witness.push(quad);
                    witness.push(quint);
                    outs[i] = quint;
                }
                outs
            } else {
                let sq = sbox_in[0].square();
                let quad = sq.square();
                let quint = quad.mul(&sbox_in[0]);
                witness.push(sq);
                witness.push(quad);
                witness.push(quint);
                [quint, sbox_in[1], sbox_in[2]]
            };

            // Step 3: MDS (+ ARK[round+1] if not last)
            let mut new_state = [Fr::zero(); 3];
            for (i, new_state_i) in new_state.iter_mut().enumerate() {
                let mut sum = Fr::zero();
                for (j, &sbox_out_j) in sbox_out.iter().enumerate() {
                    let mds_val = Bn254ScalarField::from_fr(config.mds[i][j]);
                    sum = sum.add(&mds_val.mul(&sbox_out_j));
                }
                if !is_last {
                    let ark_next = Bn254ScalarField::from_fr(config.ark[(round + 1) as usize][i]);
                    sum = sum.add(&ark_next);
                }
                *new_state_i = sum;
            }
            witness.extend_from_slice(&new_state);
            state = new_state;
        }

        Ok(witness)
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
        if self.full_mode {
            FULL_MODE_NUM_VARS
        } else {
            // MVP: z = [1, x, x2, x4, x5]
            5
        }
    }

    fn build_ccs(&self) -> Result<Ccs, ZkvmError> {
        if self.full_mode {
            Ok(self.build_full_ccs())
        } else {
            Ok(self.build_mvp_ccs())
        }
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            self.assign_full_witness(inputs)
        } else {
            self.assign_mvp_witness(inputs)
        }
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            FULL_MODE_GAS_COST
        } else {
            // spec L637: Poseidon ~200 gas/round；MVP 单 S-box round
            200
        }
    }
}

impl PoseidonCircuit {
    /// MVP 模式 CCS 构建（原有逻辑，提取为独立方法）。
    fn build_mvp_ccs(&self) -> Ccs {
        // 7 个行隔离矩阵，每个 3 行 × 5 列
        let mut m_x_r0 = SparseMatrix::new(3, 5);
        m_x_r0
            .add_entry(0, 1, Fr::one())
            .expect("M_x_r0: row 0 col 1");

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
            vec![m_x_r0, m_x2_r0, m_x2_r1, m_x4_r1, m_x4_r2, m_x_r2, m_x5_r2],
            vec![
                vec![0, 0], // S_0: (M_x_r0·z)^2 → row 0: x*x
                vec![1],    // S_1: M_x2_r0·z → row 0: x2
                vec![2, 2], // S_2: (M_x2_r1·z)^2 → row 1: x2*x2
                vec![3],    // S_3: M_x4_r1·z → row 1: x4
                vec![4, 5], // S_4: (M_x4_r2·z)*(M_x_r2·z) → row 2: x4*x
                vec![6],    // S_5: M_x5_r2·z → row 2: x5
            ],
            vec![
                Fr::one(), // c_0: +x*x
                neg_one,   // c_1: -x2
                Fr::one(), // c_2: +x2*x2
                neg_one,   // c_3: -x4
                Fr::one(), // c_4: +x4*x
                neg_one,   // c_5: -x5
            ],
        )
        .expect("PoseidonCircuit MVP CCS 构造应成功")
    }

    /// MVP 模式 witness 赋值（原有逻辑）。
    fn assign_mvp_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if inputs.len() != 1 {
            return Err(ZkvmError::Other(format!(
                "PoseidonCircuit::assign_mvp_witness: inputs.len() {} != 1（MVP 单 S-box 输入）",
                inputs.len()
            )));
        }
        let x = inputs[0];
        let x2 = x.square();
        let x4 = x2.square();
        let x5 = x4.mul(&x);
        Ok(vec![Fr::one(), x, x2, x4, x5])
    }
}

impl CcsCircuit for PoseidonCircuit {
    fn name(&self) -> &str {
        "poseidon"
    }

    fn num_matrices(&self) -> usize {
        if self.full_mode {
            self.build_full_ccs().num_matrices()
        } else {
            7
        }
    }

    fn to_ccs_instance(
        &self,
        witness: &[Fr],
        public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError> {
        let ccs = self.build_ccs()?;
        CcsInstance::new(ccs, witness.to_vec(), public_inputs.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::PrecompileRegistry;
    use crate::syscalls::poseidon::poseidon_hash;

    // ===== MVP 模式测试（原有，保持不变）=====

    #[test]
    fn test_poseidon_circuit_build_ccs() {
        let circuit = PoseidonCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        assert_eq!(ccs.num_matrices(), 7, "应有 7 个行隔离矩阵");
        assert_eq!(ccs.num_constraints(), 6, "应有 6 个 subsets");
        assert_eq!(ccs.num_rows(), 3, "应有 3 行约束");
        assert_eq!(ccs.num_vars, 5, "witness 应为 5 变量");
    }

    #[test]
    fn test_poseidon_circuit_satisfied_by() {
        let circuit = PoseidonCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let x = Fr::from_u32_with_wrap(3);
        let witness = circuit.assign_witness(&[x]).expect("assign_witness 应成功");
        assert_eq!(witness.len(), 5);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_poseidon_circuit_soundness_tampered_x5() {
        let circuit = PoseidonCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let x = Fr::from_u32_with_wrap(3);
        let mut witness = circuit.assign_witness(&[x]).expect("assign_witness 应成功");
        witness[4] = Fr::from_u32_with_wrap(244);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 x5 后应不满足约束"
        );
    }

    #[test]
    fn test_poseidon_circuit_soundness_tampered_x2() {
        let circuit = PoseidonCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let x = Fr::from_u32_with_wrap(3);
        let mut witness = circuit.assign_witness(&[x]).expect("assign_witness 应成功");
        witness[2] = Fr::from_u32_with_wrap(10);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 x2 后应不满足约束"
        );
    }

    #[test]
    fn test_poseidon_circuit_consistency_with_host() {
        let circuit = PoseidonCircuit::new_mvp();
        let x_bn = Fr::from_u32_with_wrap(7);
        let witness = circuit
            .assign_witness(&[x_bn])
            .expect("assign_witness 应成功");
        let x5 = witness[4];

        let x_fr = x_bn.into_fr();
        let expected = x_fr * x_fr * x_fr * x_fr * x_fr;
        assert_eq!(x5.into_fr(), expected, "x5 应与 ark_bn254::Fr 的 x^5 一致");
    }

    #[test]
    fn test_poseidon_circuit_empty_input() {
        let circuit = PoseidonCircuit::new_mvp();
        let result = circuit.assign_witness(&[]);
        assert!(result.is_err(), "空输入应返回错误");
    }

    #[test]
    fn test_poseidon_circuit_wrong_input_length() {
        let circuit = PoseidonCircuit::new_mvp();
        let result = circuit.assign_witness(&[Fr::one(), Fr::one()]);
        assert!(result.is_err(), "输入长度 != 1 应返回错误");
    }

    #[test]
    fn test_poseidon_circuit_registry_integration() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(PoseidonCircuit::new_mvp()));
        assert_eq!(registry.len(), 1);
        let circuit = registry.get("poseidon").expect("应找到 poseidon");
        assert_eq!(circuit.name(), "poseidon");
        assert_eq!(circuit.num_variables(), 5);
        assert_eq!(circuit.gas_cost(), 200);
    }

    #[test]
    fn test_poseidon_circuit_gas_cost() {
        let circuit = PoseidonCircuit::new_mvp();
        assert_eq!(circuit.gas_cost(), 200, "MVP gas_cost 应为 200");
    }

    #[test]
    fn test_poseidon_circuit_ccs_circuit_trait() {
        let circuit = PoseidonCircuit::new_mvp();
        let x = Fr::from_u32_with_wrap(5);
        let witness = circuit.assign_witness(&[x]).expect("assign_witness 应成功");
        let public_inputs = vec![Fr::one()];

        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "poseidon");
        assert_eq!(ccs_circuit.num_matrices(), 7);

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance 应成功");
        assert!(instance.is_satisfied().expect("is_satisfied 应成功"));
    }

    // ===== 完整模式测试（Stage 3 — Phase A2）=====

    #[test]
    fn test_poseidon_full_build_ccs() {
        let circuit = PoseidonCircuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");

        // 变量数应为 439
        assert_eq!(
            ccs.num_vars, FULL_MODE_NUM_VARS,
            "完整模式应有 {FULL_MODE_NUM_VARS} 个变量，实际 {}",
            ccs.num_vars
        );

        // 约束数（subsets 数）应 > 0
        let num_constraints = ccs.num_constraints();
        assert!(
            num_constraints > 400,
            "完整模式约束数应 > 400，实际 {num_constraints}"
        );

        // 行数应 > 0
        let num_rows = ccs.num_rows();
        assert!(num_rows > 400, "完整模式行数应 > 400，实际 {num_rows}");

        // 矩阵数应 > 0
        let num_matrices = ccs.num_matrices();
        assert!(
            num_matrices > 100,
            "完整模式矩阵数应 > 100，实际 {num_matrices}"
        );
    }

    #[test]
    fn test_poseidon_full_satisfied_by() {
        let circuit = PoseidonCircuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");

        // 输入: [0, 1, 2]（sponge 初始 state: capacity=0, rate=[1, 2]）
        let inputs = [
            Fr::zero(),
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(2),
        ];
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_full_witness 应成功");

        assert_eq!(
            witness.len(),
            FULL_MODE_NUM_VARS,
            "witness 长度应为 {FULL_MODE_NUM_VARS}，实际 {}",
            witness.len()
        );

        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "完整模式 witness 应满足所有约束"
        );
    }

    #[test]
    fn test_poseidon_full_matches_host() {
        // 电路输出应与 poseidon_hash 的内部 permutation 一致
        // poseidon_hash([s0, s1]) 内部:
        //   1. sponge state = [0, 0, 0]
        //   2. absorb [s0, s1] → state = [0, s0, s1]
        //   3. permute → state = permuted([0, s0, s1])
        //   4. return state[1]

        let s0_ark = ark_bn254::Fr::from(1u64);
        let s1_ark = ark_bn254::Fr::from(2u64);
        let expected_hash = poseidon_hash(&[s0_ark, s1_ark]);

        let circuit = PoseidonCircuit::new_full();
        let inputs = [
            Fr::zero(), // capacity = 0
            Bn254ScalarField::from_fr(s0_ark),
            Bn254ScalarField::from_fr(s1_ark),
        ];
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_full_witness 应成功");

        // 最终 state 是 witness 的最后 3 个变量 [state[0], state[1], state[2]]
        let n = witness.len();
        let final_state_1 = witness[n - 2]; // state[1]

        assert_eq!(
            final_state_1.into_fr(),
            expected_hash,
            "电路输出的 state[1] 应与 poseidon_hash 一致"
        );
    }

    #[test]
    fn test_poseidon_full_soundness_tampered_round() {
        let circuit = PoseidonCircuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");

        let inputs = [
            Fr::zero(),
            Fr::from_u32_with_wrap(3),
            Fr::from_u32_with_wrap(5),
        ];
        let mut witness = circuit
            .assign_witness(&inputs)
            .expect("assign_full_witness 应成功");

        // 篡改中间变量（round 5 的 S-box elem 0 输出）
        // 变量索引计算: z[0]=1, z[1..4]=initial, z[4..19]=round 0 (15 vars),
        // z[20..32]=round 1 (12 vars), z[32..44]=round 2, z[44..56]=round 3,
        // z[56..62]=round 4 (6 vars, partial), z[62..68]=round 5 (partial)
        // round 5 S-box elem 0: sq=z[62], quad=z[63], quint=z[64]
        // 篡改 quint (z[64])
        assert!(witness.len() > 65, "witness 应足够长以包含 round 5 的变量");
        witness[64] = witness[64].add(&Fr::one()); // 篡改: +1

        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 round 5 S-box 输出后应不满足约束"
        );
    }

    #[test]
    fn test_poseidon_full_soundness_tampered_final_state() {
        let circuit = PoseidonCircuit::new_full();
        let ccs = circuit.build_ccs().expect("build_ccs");

        let inputs = [
            Fr::zero(),
            Fr::from_u32_with_wrap(7),
            Fr::from_u32_with_wrap(11),
        ];
        let mut witness = circuit
            .assign_witness(&inputs)
            .expect("assign_full_witness 应成功");

        // 篡改最终 state 的最后一个变量
        let n = witness.len();
        witness[n - 1] = witness[n - 1].add(&Fr::one());

        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改最终 state 后应不满足约束"
        );
    }

    #[test]
    fn test_poseidon_full_known_vector() {
        // 多个已知输入→输出对，验证电路输出与 poseidon_hash 一致
        let test_cases = [
            (ark_bn254::Fr::from(0u64), ark_bn254::Fr::from(0u64)),
            (ark_bn254::Fr::from(1u64), ark_bn254::Fr::from(2u64)),
            (ark_bn254::Fr::from(3u64), ark_bn254::Fr::from(5u64)),
            (ark_bn254::Fr::from(7u64), ark_bn254::Fr::from(11u64)),
            (ark_bn254::Fr::from(42u64), ark_bn254::Fr::from(100u64)),
        ];

        let circuit = PoseidonCircuit::new_full();

        for (s0_ark, s1_ark) in test_cases {
            let expected_hash = poseidon_hash(&[s0_ark, s1_ark]);

            let inputs = [
                Fr::zero(),
                Bn254ScalarField::from_fr(s0_ark),
                Bn254ScalarField::from_fr(s1_ark),
            ];
            let witness = circuit
                .assign_witness(&inputs)
                .expect("assign_full_witness 应成功");

            let n = witness.len();
            let actual_hash = witness[n - 2]; // state[1]

            assert_eq!(
                actual_hash.into_fr(),
                expected_hash,
                "输入 ({s0_ark:?}, {s1_ark:?}) 的电路输出与 poseidon_hash 不一致"
            );
        }
    }

    #[test]
    fn test_poseidon_full_gas_cost() {
        let circuit = PoseidonCircuit::new_full();
        assert_eq!(
            circuit.gas_cost(),
            FULL_MODE_GAS_COST,
            "完整模式 gas_cost 应为 {FULL_MODE_GAS_COST}"
        );
    }

    #[test]
    fn test_poseidon_full_wrong_input_length() {
        let circuit = PoseidonCircuit::new_full();
        // 输入长度 != 3 应返回错误
        assert!(circuit.assign_witness(&[]).is_err(), "空输入应返回错误");
        assert!(
            circuit.assign_witness(&[Fr::one()]).is_err(),
            "输入长度 1 应返回错误"
        );
        assert!(
            circuit.assign_witness(&[Fr::one(), Fr::one()]).is_err(),
            "输入长度 2 应返回错误"
        );
        assert!(
            circuit
                .assign_witness(&[Fr::one(), Fr::one(), Fr::one(), Fr::one()])
                .is_err(),
            "输入长度 4 应返回错误"
        );
    }

    #[test]
    fn test_poseidon_full_ccs_circuit_trait() {
        let circuit = PoseidonCircuit::new_full();
        let inputs = [
            Fr::zero(),
            Fr::from_u32_with_wrap(3),
            Fr::from_u32_with_wrap(5),
        ];
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_full_witness 应成功");
        let public_inputs = vec![Fr::one()];

        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "poseidon");

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance 应成功");
        assert!(
            instance.is_satisfied().expect("is_satisfied 应成功"),
            "完整模式 CcsInstance 应满足"
        );
    }

    #[test]
    fn test_poseidon_full_consistency_with_mvp_sbox() {
        // 验证完整模式的 S-box 语义与 MVP 一致（x^5 = x² → x⁴ → x⁵）
        // 在完整模式中，round 0 的 S-box 输入是 a_i = state[i] + ark[0][i]
        // state = [inputs[0], inputs[1], inputs[2]]，其 x^5 应与直接计算一致
        let circuit = PoseidonCircuit::new_full();
        let config = poseidon_config();

        let inputs = [
            Fr::from_u32_with_wrap(7),
            Fr::from_u32_with_wrap(3),
            Fr::from_u32_with_wrap(2),
        ];
        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_full_witness 应成功");

        // round 0 ARK[0] output: z[4..7] = state[i] + ark[0][i]
        let a0 = witness[4];
        let a1 = witness[5];
        let a2 = witness[6];
        // round 0 S-box elem 0: z[7]=a0², z[8]=a0⁴, z[9]=a0⁵
        let a0_sq = witness[7];
        let a0_quad = witness[8];
        let a0_quint = witness[9];

        // 验证 S-box 语义
        assert_eq!(a0_sq, a0.square(), "a0² 应与直接计算一致");
        assert_eq!(a0_quad, a0_sq.square(), "a0⁴ 应与 a0²² 一致");
        assert_eq!(a0_quint, a0_quad.mul(&a0), "a0⁵ 应与 a0⁴·a0 一致");

        // 验证 ARK[0] 正确：a_i = inputs[i] + ark[0][i]
        let expected_a0 = inputs[0].add(&Bn254ScalarField::from_fr(config.ark[0][0]));
        assert_eq!(
            a0, expected_a0,
            "ARK[0] 输出应与 inputs[0] + ark[0][0] 一致"
        );
        let expected_a1 = inputs[1].add(&Bn254ScalarField::from_fr(config.ark[0][1]));
        assert_eq!(
            a1, expected_a1,
            "ARK[0] 输出应与 inputs[1] + ark[0][1] 一致"
        );
        let expected_a2 = inputs[2].add(&Bn254ScalarField::from_fr(config.ark[0][2]));
        assert_eq!(
            a2, expected_a2,
            "ARK[0] 输出应与 inputs[2] + ark[0][2] 一致"
        );
    }

    #[test]
    fn test_poseidon_full_backward_compatibility() {
        // MVP 模式不受完整模式影响
        let mvp = PoseidonCircuit::new_mvp();
        assert!(!mvp.is_full_mode());
        assert_eq!(mvp.num_variables(), 5);
        assert_eq!(mvp.gas_cost(), 200);

        let full = PoseidonCircuit::new_full();
        assert!(full.is_full_mode());
        assert_eq!(full.num_variables(), FULL_MODE_NUM_VARS);
        assert_eq!(full.gas_cost(), FULL_MODE_GAS_COST);

        // 两种模式可以共存于注册表（同名覆盖，但可分别测试）
        let mvp_ccs = mvp.build_ccs().expect("build_ccs");
        let full_ccs = full.build_ccs().expect("build_ccs");
        assert_eq!(mvp_ccs.num_vars, 5);
        assert_eq!(full_ccs.num_vars, FULL_MODE_NUM_VARS);
    }
}
