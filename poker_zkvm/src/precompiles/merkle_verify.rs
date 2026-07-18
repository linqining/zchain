//! Merkle 路径验证预编译电路（Phase I — Batch 1）。
//!
//! # 两种模式
//!
//! - **MVP 模式**（`new()`）：单层验证 `H(left, right) = left*2 + right`，4 变量。
//! - **完整模式**（`new_full_with_depth(n)`）：n 层路径验证，含 conditional select。
//!
//! # 哈希函数
//!
//! 使用简单线性哈希 `H(left, right) = left * 2 + right`。
//! 选择 `*2` 区分左右子节点（`H(l,r) ≠ H(r,l)` 当 `l ≠ r`）。
//! Poseidon 哈希复用留待后续（需重构 poseidon.rs 暴露 permutation 函数）。
//!
//! # Full 模式约束结构（每层 5 约束）
//!
//! 每层 i：
//! 1. `bit_check(direction_i)` — direction ∈ {0, 1}
//! 2. `linear`: `H_left - 2*current - sibling = 0`
//! 3. `linear`: `H_right - 2*sibling - current = 0`
//! 4. `linear`: `diff - H_right + H_left = 0`
//! 5. `multiplication`: `bit_diff = direction * diff`
//! 6. `linear`: `parent - H_left - bit_diff = 0`
//!
//! 最终：`linear`: `root - last_parent = 0`

use crate::ccs::{Ccs, CcsInstance, Fr};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::ccs_builder::CcsBuilder;
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// Merkle 验证 gas 常量（与 syscalls/gas.rs 对齐）。
const GAS_PER_LEVEL: u64 = 100;

/// Merkle 路径验证预编译电路。
#[derive(Debug, Clone)]
pub struct MerkleVerifyCircuit {
    depth: usize,
    full_mode: bool,
}

impl MerkleVerifyCircuit {
    /// 创建 Full 模式电路（depth=1 路径验证，含 conditional select）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            depth: 1,
            full_mode: true,
        }
    }

    /// 创建 MVP 模式电路（单层验证，用于快速测试）。
    #[must_use]
    pub fn new_mvp() -> Self {
        Self {
            depth: 1,
            full_mode: false,
        }
    }

    /// 创建 Full 模式电路（指定深度的路径验证）。
    #[must_use]
    pub fn new_full_with_depth(depth: usize) -> Self {
        assert!(depth > 0, "depth must be > 0");
        Self {
            depth,
            full_mode: true,
        }
    }

    /// 返回深度。
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// 是否为 Full 模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    // ===== MVP 模式 =====

    /// 构建 MVP CCS（单层 `parent = left*2 + right`）。
    fn build_mvp_ccs(&self) -> Ccs {
        let mut builder = CcsBuilder::new();
        let left = builder.alloc_var(); // 1
        let right = builder.alloc_var(); // 2
        let parent = builder.alloc_var(); // 3
        let row = builder.alloc_row();
        // parent - 2*left - right = 0
        builder.add_linear(
            row,
            &[
                (parent, Fr::one()),
                (left, Fr::from_u64(2).neg()),
                (right, Fr::one().neg()),
            ],
        );
        builder.build().expect("MVP CCS build should succeed")
    }

    /// MVP witness 赋值：`[left, right, parent]` → `[1, left, right, parent]`。
    fn assign_mvp_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if inputs.len() != 3 {
            return Err(ZkvmError::Other(format!(
                "MerkleVerifyCircuit (MVP): inputs.len() {} != 3 (left, right, parent)",
                inputs.len()
            )));
        }
        Ok(vec![Fr::one(), inputs[0], inputs[1], inputs[2]])
    }

    // ===== Full 模式 =====

    /// 运行 Full 模式，同时构建 CCS + witness。
    ///
    /// # 输入
    /// - `inputs[0]` — leaf
    /// - `inputs[1]` — root
    /// - `inputs[2..2+depth]` — sibling[0..depth]
    /// - `inputs[2+depth..2+2*depth]` — direction_bits[0..depth]（0=左/1=右）
    ///
    /// # 返回
    /// `(Ccs, witness)`
    fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        let d = self.depth;
        let expected_len = 2 + 2 * d;
        if inputs.len() != expected_len {
            return Err(ZkvmError::Other(format!(
                "MerkleVerifyCircuit (Full): inputs.len() {} != {} (leaf + root + {} siblings + {} direction_bits)",
                inputs.len(),
                expected_len,
                d,
                d
            )));
        }

        let mut builder = CcsBuilder::new();
        let mut witness = vec![Fr::one()];

        // 公共输入变量
        let leaf_var = builder.alloc_var();
        witness.push(inputs[0]);
        let root_var = builder.alloc_var();
        witness.push(inputs[1]);

        // sibling 变量
        let mut sibling_vars = Vec::with_capacity(d);
        for i in 0..d {
            let sv = builder.alloc_var();
            witness.push(inputs[2 + i]);
            sibling_vars.push(sv);
        }

        // direction_bit 变量
        let mut dir_vars = Vec::with_capacity(d);
        for i in 0..d {
            let dv = builder.alloc_var();
            witness.push(inputs[2 + d + i]);
            dir_vars.push(dv);
        }

        let two = Fr::from_u64(2);

        // 逐层构建约束 + 计算 witness
        let mut current_var = leaf_var;
        let mut current_val = inputs[0];

        for i in 0..d {
            let sibling_val = inputs[2 + i];
            let dir_val = inputs[2 + d + i];

            // bit_check on direction
            let row_bc = builder.alloc_row();
            builder.add_bit_check(row_bc, dir_vars[i]);

            // H_left = current * 2 + sibling
            let h_left_var = builder.alloc_var();
            let h_left_val = current_val.mul(&two).add(&sibling_val);
            witness.push(h_left_val);
            let row_hl = builder.alloc_row();
            builder.add_linear(
                row_hl,
                &[
                    (h_left_var, Fr::one()),
                    (current_var, two.neg()),
                    (sibling_vars[i], Fr::one().neg()),
                ],
            );

            // H_right = sibling * 2 + current
            let h_right_var = builder.alloc_var();
            let h_right_val = sibling_val.mul(&two).add(&current_val);
            witness.push(h_right_val);
            let row_hr = builder.alloc_row();
            builder.add_linear(
                row_hr,
                &[
                    (h_right_var, Fr::one()),
                    (sibling_vars[i], two.neg()),
                    (current_var, Fr::one().neg()),
                ],
            );

            // diff = H_right - H_left
            let diff_var = builder.alloc_var();
            let diff_val = h_right_val.sub(&h_left_val);
            witness.push(diff_val);
            let row_diff = builder.alloc_row();
            builder.add_linear(
                row_diff,
                &[
                    (diff_var, Fr::one()),
                    (h_right_var, Fr::one().neg()),
                    (h_left_var, Fr::one()),
                ],
            );

            // bit_diff = direction * diff
            let bit_diff_var = builder.alloc_var();
            let bit_diff_val = dir_val.mul(&diff_val);
            witness.push(bit_diff_val);
            let row_bd = builder.alloc_row();
            builder.add_multiplication(row_bd, dir_vars[i], diff_var, bit_diff_var);

            // parent = H_left + bit_diff
            let parent_var = builder.alloc_var();
            let parent_val = h_left_val.add(&bit_diff_val);
            witness.push(parent_val);
            let row_parent = builder.alloc_row();
            builder.add_linear(
                row_parent,
                &[
                    (parent_var, Fr::one()),
                    (h_left_var, Fr::one().neg()),
                    (bit_diff_var, Fr::one().neg()),
                ],
            );

            current_var = parent_var;
            current_val = parent_val;
        }

        // 最终约束：root - last_parent = 0
        let row_final = builder.alloc_row();
        builder.add_linear(
            row_final,
            &[(root_var, Fr::one()), (current_var, Fr::one().neg())],
        );

        let ccs = builder.build()?;
        Ok((ccs, witness))
    }
}

impl Default for MerkleVerifyCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for MerkleVerifyCircuit {
    fn name(&self) -> &str {
        "merkle_verify"
    }

    fn num_variables(&self) -> usize {
        if self.full_mode {
            // 1 (const) + 2 (leaf, root) + d (siblings) + d (directions) + 5*d (per-layer)
            3 + 7 * self.depth
        } else {
            4 // [1, left, right, parent]
        }
    }

    fn build_ccs(&self) -> Result<Ccs, ZkvmError> {
        if self.full_mode {
            let d = self.depth;
            let dummy = vec![Fr::zero(); 2 + 2 * d];
            Ok(self.run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0)
        } else {
            Ok(self.build_mvp_ccs())
        }
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            Ok(self.run_full(inputs)?.1)
        } else {
            self.assign_mvp_witness(inputs)
        }
    }

    fn gas_cost(&self) -> u64 {
        GAS_PER_LEVEL * self.depth as u64
    }
}

impl CcsCircuit for MerkleVerifyCircuit {
    fn name(&self) -> &str {
        "merkle_verify"
    }

    fn num_matrices(&self) -> usize {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 2 + 2 * self.depth];
            self.run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0
                .num_matrices()
        } else {
            3
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
    use crate::field::ZkvmField;

    /// host 端 Merkle 哈希：H(left, right) = left*2 + right
    fn host_hash(left: Fr, right: Fr) -> Fr {
        left.mul(&Fr::from_u64(2)).add(&right)
    }

    /// host 端计算 Merkle root（给定 leaf + siblings + directions）。
    fn host_merkle_root(leaf: Fr, siblings: &[Fr], directions: &[Fr]) -> Fr {
        let mut current = leaf;
        for (i, sib) in siblings.iter().enumerate() {
            let dir = directions[i];
            if dir == Fr::zero() {
                current = host_hash(current, *sib);
            } else {
                current = host_hash(*sib, current);
            }
        }
        current
    }

    // ===== MVP 测试 =====

    #[test]
    fn test_merkle_mvp_satisfied() {
        let circuit = MerkleVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let left = Fr::from_u64(3);
        let right = Fr::from_u64(4);
        let parent = host_hash(left, right); // 3*2 + 4 = 10
        assert_eq!(parent, Fr::from_u64(10));

        let witness = circuit
            .assign_witness(&[left, right, parent])
            .expect("assign_witness should succeed");
        assert_eq!(witness.len(), 4);
        assert!(
            ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed")
        );
    }

    #[test]
    fn test_merkle_mvp_tampered_parent() {
        let circuit = MerkleVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let left = Fr::from_u64(3);
        let right = Fr::from_u64(4);
        let parent = Fr::from_u64(11); // 篡改：应为 10

        let witness = circuit
            .assign_witness(&[left, right, parent])
            .expect("assign_witness should succeed");
        assert!(
            !ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "篡改 parent 后应不满足约束"
        );
    }

    #[test]
    fn test_merkle_mvp_tampered_left() {
        let circuit = MerkleVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let left = Fr::from_u64(3);
        let right = Fr::from_u64(4);
        let parent = host_hash(left, right); // 10

        // 篡改 witness 中的 left
        let mut witness = circuit
            .assign_witness(&[left, right, parent])
            .expect("assign_witness should succeed");
        witness[1] = Fr::from_u64(5); // left 3 → 5
        assert!(
            !ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "篡改 left 后应不满足约束"
        );
    }

    // ===== Full 模式测试 =====

    #[test]
    fn test_merkle_full_depth3_satisfied() {
        let depth = 3;
        let circuit = MerkleVerifyCircuit::new_full_with_depth(depth);
        let ccs = circuit.build_ccs().expect("build_ccs");

        // 构造有效 Merkle 路径
        let leaf = Fr::from_u64(42);
        let siblings = vec![Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(3)];
        // direction = 0: current is left child → H(current, sibling)
        // direction = 1: current is right child → H(sibling, current)
        let directions = vec![Fr::zero(), Fr::one(), Fr::zero()];

        let root = host_merkle_root(leaf, &siblings, &directions);

        // 构造输入：[leaf, root, sibling_0, sibling_1, sibling_2, dir_0, dir_1, dir_2]
        let mut inputs = vec![leaf, root];
        inputs.extend_from_slice(&siblings);
        inputs.extend_from_slice(&directions);

        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");
        assert_eq!(witness.len(), circuit.num_variables());
        assert!(
            ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "3 层 Merkle 路径验证应通过"
        );
    }

    #[test]
    fn test_merkle_full_tampered_leaf() {
        let depth = 3;
        let circuit = MerkleVerifyCircuit::new_full_with_depth(depth);
        let ccs = circuit.build_ccs().expect("build_ccs");

        let leaf = Fr::from_u64(42);
        let siblings = vec![Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(3)];
        let directions = vec![Fr::zero(), Fr::one(), Fr::zero()];
        let root = host_merkle_root(leaf, &siblings, &directions);

        let mut inputs = vec![leaf, root];
        inputs.extend_from_slice(&siblings);
        inputs.extend_from_slice(&directions);

        let mut witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");

        // 篡改 leaf
        witness[1] = Fr::from_u64(99);
        assert!(
            !ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "篡改 leaf 后应不满足约束"
        );
    }

    #[test]
    fn test_merkle_full_tampered_sibling() {
        let depth = 3;
        let circuit = MerkleVerifyCircuit::new_full_with_depth(depth);
        let ccs = circuit.build_ccs().expect("build_ccs");

        let leaf = Fr::from_u64(42);
        let siblings = vec![Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(3)];
        let directions = vec![Fr::zero(), Fr::one(), Fr::zero()];
        let root = host_merkle_root(leaf, &siblings, &directions);

        let mut inputs = vec![leaf, root];
        inputs.extend_from_slice(&siblings);
        inputs.extend_from_slice(&directions);

        let mut witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");

        // 篡改 sibling[0]（var index = 3）
        witness[3] = Fr::from_u64(99);
        assert!(
            !ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "篡改 sibling 后应不满足约束"
        );
    }

    #[test]
    fn test_merkle_full_depth1_satisfied() {
        let depth = 1;
        let circuit = MerkleVerifyCircuit::new_full_with_depth(depth);
        let ccs = circuit.build_ccs().expect("build_ccs");

        let leaf = Fr::from_u64(5);
        let siblings = vec![Fr::from_u64(7)];
        let directions = vec![Fr::zero()]; // leaf is left child
        let root = host_merkle_root(leaf, &siblings, &directions); // 5*2 + 7 = 17

        let mut inputs = vec![leaf, root];
        inputs.extend_from_slice(&siblings);
        inputs.extend_from_slice(&directions);

        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");
        assert!(
            ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "1 层 Merkle 路径验证应通过"
        );
    }

    #[test]
    fn test_merkle_full_direction_right() {
        let depth = 2;
        let circuit = MerkleVerifyCircuit::new_full_with_depth(depth);
        let ccs = circuit.build_ccs().expect("build_ccs");

        let leaf = Fr::from_u64(5);
        let siblings = vec![Fr::from_u64(7), Fr::from_u64(11)];
        // direction = 1: current is right child → H(sibling, current)
        let directions = vec![Fr::one(), Fr::one()];
        let root = host_merkle_root(leaf, &siblings, &directions);

        let mut inputs = vec![leaf, root];
        inputs.extend_from_slice(&siblings);
        inputs.extend_from_slice(&directions);

        let witness = circuit
            .assign_witness(&inputs)
            .expect("assign_witness should succeed");
        assert!(
            ccs.satisfied_by(&witness)
                .expect("satisfied_by should succeed"),
            "direction=1 (右子节点) 路径验证应通过"
        );
    }

    #[test]
    fn test_merkle_gas_cost() {
        let mvp = MerkleVerifyCircuit::new_mvp();
        assert_eq!(mvp.gas_cost(), 100);

        let full3 = MerkleVerifyCircuit::new_full_with_depth(3);
        assert_eq!(full3.gas_cost(), 300);

        let full10 = MerkleVerifyCircuit::new_full_with_depth(10);
        assert_eq!(full10.gas_cost(), 1000);
    }

    #[test]
    fn test_merkle_wrong_input_length() {
        let circuit = MerkleVerifyCircuit::new_mvp();
        let result = circuit.assign_witness(&[Fr::one()]);
        assert!(result.is_err());

        let full = MerkleVerifyCircuit::new_full_with_depth(3);
        let result = full.assign_witness(&[Fr::one()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_ccs_circuit_trait() {
        let circuit = MerkleVerifyCircuit::new_mvp();
        let _ccs = circuit.build_ccs().expect("build_ccs");
        let witness = circuit
            .assign_witness(&[Fr::from_u64(3), Fr::from_u64(4), Fr::from_u64(10)])
            .expect("assign_witness");
        let public_inputs = vec![Fr::from_u64(10)];

        let instance = circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance should succeed");
        assert!(
            instance
                .is_satisfied()
                .expect("is_satisfied should succeed")
        );
    }
}
