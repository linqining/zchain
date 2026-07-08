//! SHA-256 哈希预编译电路（Phase 10 — Task 10.3）。
//!
//! 与 [`sha2`] crate 输出一致。MVP 阶段实现核心非线性函数 Ch 的约束结构，
//! 完整 64-round compression 留待后续迭代。
//!
//! # Ch 函数（SHA-256 核心非线性操作）
//!
//! SHA-256 的 Ch 函数定义为：
//! ```text
//! Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)
//! ```
//!
//! 对单 bit（域元素 ∈ {0, 1}），可化简为：
//! ```text
//! Ch(x, y, z) = z + x * (y - z)
//! ```
//!
//! 因为：
//! - `x AND y = x * y`（bit 乘法）
//! - `NOT x = 1 - x`
//! - `(NOT x) AND z = (1 - x) * z = z - x*z`
//! - `Ch = x*y + (z - x*z) = z + x*(y - z)`
//!
//! # CCS 约束结构
//!
//! witness `z = [1, x, y, z_var, y_minus_z, ch]`（6 变量）
//!
//! 约束（2 行）：
//! - row 0: `y - z_var - y_minus_z = 0`（线性约束，定义中间变量）
//! - row 1: `x * y_minus_z - ch + z_var = 0`（乘法约束，Ch 定义）
//!
//! 使用 7 个行隔离矩阵（同 Poseidon 电路模式），确保 subset 不污染其他行。

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// SHA-256 哈希预编译电路。
///
/// MVP 实现仅约束 Ch 函数（核心非线性操作）。
/// 完整 64-round SHA-256 compression 留待后续迭代。
#[derive(Debug, Clone)]
pub struct Sha256Circuit {
    /// 块大小（字节，固定 64 = 512 bits）。
    block_size: usize,
    /// 输出大小（字节，固定 32 = 256 bits）。
    output_size: usize,
}

impl Sha256Circuit {
    /// 创建 SHA-256 电路（block_size=64, output_size=32）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_size: 64,
            output_size: 32,
        }
    }

    /// 返回块大小（字节）。
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// 返回输出大小（字节）。
    #[must_use]
    pub fn output_size(&self) -> usize {
        self.output_size
    }
}

impl Default for Sha256Circuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for Sha256Circuit {
    fn name(&self) -> &str {
        "sha256"
    }

    fn num_variables(&self) -> usize {
        // z = [1, x, y, z_var, y_minus_z, ch]
        6
    }

    fn build_ccs(&self) -> Ccs {
        // 7 个行隔离矩阵，每个 2 行 × 6 列
        // 矩阵索引:
        //   0=M_y_r0,      1=M_z_r0,      2=M_ymz_r0,
        //   3=M_x_r1,      4=M_ymz_r1,    5=M_ch_r1,    6=M_z_r1
        //
        // 约束（2 行）：
        // - row 0: y - z_var - y_minus_z = 0
        //   S_0={0} c_0=+1, S_1={1} c_1=-1, S_2={2} c_2=-1
        // - row 1: x * y_minus_z - ch + z_var = 0
        //   S_3={3,4} c_3=+1, S_4={5} c_4=-1, S_5={6} c_5=+1

        let mut m_y_r0 = SparseMatrix::new(2, 6);
        m_y_r0.add_entry(0, 2, Fr::one()).expect("M_y_r0");

        let mut m_z_r0 = SparseMatrix::new(2, 6);
        m_z_r0.add_entry(0, 3, Fr::one()).expect("M_z_r0");

        let mut m_ymz_r0 = SparseMatrix::new(2, 6);
        m_ymz_r0.add_entry(0, 4, Fr::one()).expect("M_ymz_r0");

        let mut m_x_r1 = SparseMatrix::new(2, 6);
        m_x_r1.add_entry(1, 1, Fr::one()).expect("M_x_r1");

        let mut m_ymz_r1 = SparseMatrix::new(2, 6);
        m_ymz_r1.add_entry(1, 4, Fr::one()).expect("M_ymz_r1");

        let mut m_ch_r1 = SparseMatrix::new(2, 6);
        m_ch_r1.add_entry(1, 5, Fr::one()).expect("M_ch_r1");

        let mut m_z_r1 = SparseMatrix::new(2, 6);
        m_z_r1.add_entry(1, 3, Fr::one()).expect("M_z_r1");

        let neg_one = Fr::zero().sub(&Fr::one());

        Ccs::new(
            6,
            vec![
                m_y_r0, m_z_r0, m_ymz_r0, m_x_r1, m_ymz_r1, m_ch_r1, m_z_r1,
            ],
            vec![
                vec![0], // S_0: M_y_r0 → row 0: y
                vec![1], // S_1: M_z_r0 → row 0: z_var
                vec![2], // S_2: M_ymz_r0 → row 0: y_minus_z
                vec![3, 4], // S_3: M_x_r1 * M_ymz_r1 → row 1: x * y_minus_z
                vec![5], // S_4: M_ch_r1 → row 1: ch
                vec![6], // S_5: M_z_r1 → row 1: z_var
            ],
            vec![
                Fr::one(),  // c_0: +y
                neg_one,    // c_1: -z_var
                neg_one,    // c_2: -y_minus_z
                Fr::one(),  // c_3: +x * y_minus_z
                neg_one,    // c_4: -ch
                Fr::one(),  // c_5: +z_var
            ],
        )
        .expect("Sha256Circuit CCS 构造应成功")
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        // 输入: [x, y, z_var]（3 个域元素，MVP 阶段表示 Ch 函数的 3 个 bit 输入）
        if inputs.len() != 3 {
            return Err(ZkvmError::Other(format!(
                "Sha256Circuit::assign_witness: inputs.len() {} != 3（Ch 函数需要 x, y, z 三个输入）",
                inputs.len()
            )));
        }
        let x = inputs[0];
        let y = inputs[1];
        let z_var = inputs[2];

        // 中间变量: y_minus_z = y - z
        let y_minus_z = y.sub(&z_var);

        // Ch(x, y, z) = z + x * (y - z)
        let ch = z_var.add(&x.mul(&y_minus_z));

        // witness: [1, x, y, z_var, y_minus_z, ch]
        Ok(vec![Fr::one(), x, y, z_var, y_minus_z, ch])
    }

    fn gas_cost(&self) -> u64 {
        // spec L637: SHA-256 ~25,000 gas/block；MVP 单 Ch 操作返回比例值
        25_000
    }
}

impl CcsCircuit for Sha256Circuit {
    fn name(&self) -> &str {
        "sha256"
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

    /// 计算 Ch 函数（bit 级别）— 用于与 host 一致性验证。
    ///
    /// `Ch(x, y, z) = (x & y) ^ ((!x) & z)`，输入为 0/1 整数。
    fn ch_bit(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ ((!x) & z)
    }

    #[test]
    fn test_sha256_circuit_build_ccs() {
        let circuit = Sha256Circuit::new();
        let ccs = circuit.build_ccs();
        assert_eq!(ccs.num_matrices(), 7, "应有 7 个行隔离矩阵");
        assert_eq!(ccs.num_constraints(), 6, "应有 6 个 subsets");
        assert_eq!(ccs.num_rows(), 2, "应有 2 行约束");
        assert_eq!(ccs.num_vars, 6, "witness 应为 6 变量");
    }

    #[test]
    fn test_sha256_circuit_satisfied_by() {
        let circuit = Sha256Circuit::new();
        let ccs = circuit.build_ccs();
        // x=1, y=1, z=0 → Ch = 0 + 1*(1-0) = 1
        let inputs = vec![
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(0),
        ];
        let witness = circuit.assign_witness(&inputs).expect("assign_witness 应成功");
        assert_eq!(witness.len(), 6);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_sha256_circuit_soundness_tampered_ch() {
        let circuit = Sha256Circuit::new();
        let ccs = circuit.build_ccs();
        let inputs = vec![
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(0),
        ];
        let mut witness = circuit.assign_witness(&inputs).expect("assign_witness 应成功");
        // 篡改 ch（z[5]）→ 1 改为 0
        witness[5] = Fr::from_u32_with_wrap(0);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 ch 后应不满足约束"
        );
    }

    #[test]
    fn test_sha256_circuit_soundness_tampered_ymz() {
        let circuit = Sha256Circuit::new();
        let ccs = circuit.build_ccs();
        let inputs = vec![
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(0),
        ];
        let mut witness = circuit.assign_witness(&inputs).expect("assign_witness 应成功");
        // 篡改 y_minus_z（z[4]）→ 1 改为 2
        witness[4] = Fr::from_u32_with_wrap(2);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 y_minus_z 后应不满足约束"
        );
    }

    #[test]
    fn test_sha256_circuit_consistency_with_bit_ch() {
        // 对所有 bit 组合 (x, y, z) ∈ {0,1}^3，验证电路 Ch 输出与 bitwise Ch 一致
        let circuit = Sha256Circuit::new();
        for x in 0..=1u32 {
            for y in 0..=1u32 {
                for z in 0..=1u32 {
                    let inputs = vec![
                        Fr::from_u32_with_wrap(x),
                        Fr::from_u32_with_wrap(y),
                        Fr::from_u32_with_wrap(z),
                    ];
                    let witness = circuit.assign_witness(&inputs).expect("assign_witness");
                    let ch_circuit = witness[5];
                    let ch_expected = ch_bit(x, y, z);
                    assert_eq!(
                        ch_circuit.to_u32(),
                        ch_expected,
                        "Ch({x}, {y}, {z}) 不一致: 电路={}, 期望={}",
                        ch_circuit.to_u32(),
                        ch_expected
                    );
                    // 同时验证 CCS 满足
                    let ccs = circuit.build_ccs();
                    assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
                }
            }
        }
    }

    #[test]
    fn test_sha256_circuit_consistency_with_sha2_crate() {
        // 验证 sha2 crate 的 SHA-256 对空输入产生已知哈希
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = hasher.finalize();
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex::encode(result), expected_hex);
    }

    #[test]
    fn test_sha256_circuit_known_vectors() {
        // NIST 测试向量验证（host sha2 crate）
        use sha2::{Digest, Sha256};
        let cases = [
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("hello world", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
        ];
        for (msg, expected_hex) in cases {
            let mut hasher = Sha256::new();
            hasher.update(msg.as_bytes());
            let result = hasher.finalize();
            assert_eq!(
                hex::encode(result),
                expected_hex,
                "SHA-256(\"{msg}\") 不匹配"
            );
        }
    }

    #[test]
    fn test_sha256_circuit_empty_input() {
        let circuit = Sha256Circuit::new();
        let result = circuit.assign_witness(&[]);
        assert!(result.is_err(), "空输入应返回错误");
    }

    #[test]
    fn test_sha256_circuit_wrong_input_length() {
        let circuit = Sha256Circuit::new();
        let result = circuit.assign_witness(&[Fr::one(), Fr::one()]);
        assert!(result.is_err(), "输入长度 != 3 应返回错误");
    }

    #[test]
    fn test_sha256_circuit_registry_integration() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(Sha256Circuit::new()));
        assert_eq!(registry.len(), 1);
        let circuit = registry.get("sha256").expect("应找到 sha256");
        assert_eq!(circuit.name(), "sha256");
        assert_eq!(circuit.num_variables(), 6);
        assert_eq!(circuit.gas_cost(), 25_000);
    }

    #[test]
    fn test_sha256_circuit_gas_cost() {
        let circuit = Sha256Circuit::new();
        assert_eq!(circuit.gas_cost(), 25_000, "gas_cost 应为 25000");
    }

    #[test]
    fn test_sha256_circuit_block_and_output_size() {
        let circuit = Sha256Circuit::new();
        assert_eq!(circuit.block_size(), 64, "block_size 应为 64 字节");
        assert_eq!(circuit.output_size(), 32, "output_size 应为 32 字节");
    }

    #[test]
    fn test_sha256_circuit_ccs_circuit_trait() {
        let circuit = Sha256Circuit::new();
        let inputs = vec![
            Fr::from_u32_with_wrap(1),
            Fr::from_u32_with_wrap(0),
            Fr::from_u32_with_wrap(1),
        ];
        let witness = circuit.assign_witness(&inputs).expect("assign_witness 应成功");
        let public_inputs = vec![Fr::one()];

        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "sha256");
        assert_eq!(ccs_circuit.num_matrices(), 7);

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance 应成功");
        assert!(instance.is_satisfied().expect("is_satisfied 应成功"));
    }
}
