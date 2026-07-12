//! BN254 配对预编译电路（Phase I — Batch 2）。
//!
//! 双模式实现：
//! - **MVP 模式**（`new()`）：单 G1 点曲线检查（y² = x³ + 3）。
//! - **Full 模式**（`new_full()`）：双 G1 点曲线检查 + 配对等式 hint 验证。
//!
//! # 曲线参数（BN254 / alt_bn128）
//!
//! G1 曲线方程：`y² = x³ + 3 (mod p)`
//!
//! `p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`
//!
//! # 设计说明
//!
//! 采用 hint-based 方案：电路验证 G1 点在曲线上，配对结果由 host 计算并作为 hint flag 传入。
//! G2 曲线验证需要 Fp2 运算（8 limb），Full 模式仅验证 G1 + hint，不验证 G2。
//!
//! # 约束计数
//!
//! | 操作 | mul_mod 数 | 约束数 |
//! |------|-----------|--------|
//! | G1 曲线检查（affine） | 3 | ~4300 |
//! | Full（双 G1 + hint） | 6 | ~8600 |

#![allow(dead_code)]

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::non_native::{
    host_add_mod, host_mul_mod, NonNativeBuilder, NonNativeElement,
};
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

// ===== BN254 常量（[u64; 4] little-endian）=====

/// BN254 基域 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583。
const BN254_P: [u64; 4] = [
    0x3C20_8C16_D87C_FD47,
    0x9781_6A91_6871_CA8D,
    0xB850_45B6_8181_585D,
    0x3064_4E72_E131_A029,
];

/// G1 曲线参数 b = 3。
const BN254_B: [u64; 4] = [3, 0, 0, 0];

/// BN254 G1 生成元 x = 1。
const BN254_G1_X: [u64; 4] = [1, 0, 0, 0];

/// BN254 G1 生成元 y = 2。
const BN254_G1_Y: [u64; 4] = [2, 0, 0, 0];

/// BN254 pairing MVP gas。
const GAS_BN254_PAIRING_MVP: u64 = 30_000;

/// BN254 pairing Full gas。
const GAS_BN254_PAIRING_FULL: u64 = 80_000;

// ===== G1 曲线检查 =====

/// 验证 G1 点在曲线上：`y² = x³ + b (mod p)`。
///
/// affine 坐标直接验证，约 3 mul_mod ≈ 4300 约束。
pub(crate) fn assert_g1_on_curve(
    builder: &mut NonNativeBuilder,
    x: &NonNativeElement,
    y: &NonNativeElement,
) {
    let m = &BN254_P;

    // y²
    let y_sq = builder.mul_mod(y, y, m);

    // x²
    let x_sq = builder.mul_mod(x, x, m);
    // x³ = x² * x
    let x_cubed = builder.mul_mod(&x_sq, x, m);

    // x³ + b
    let b_elem = builder.from_u256(&BN254_B);
    let rhs = builder.add_mod(&x_cubed, &b_elem, m);

    // y² == x³ + b
    builder.assert_equal(&y_sq, &rhs);
}

// ===== Bn254PairingCircuit =====

/// BN254 配对预编译电路。
///
/// 双模式：
/// - MVP（`new()`）：单 G1 点曲线检查
/// - Full（`new_full()`）：双 G1 点曲线检查 + 配对等式 hint
#[derive(Debug, Clone)]
pub struct Bn254PairingCircuit {
    /// 是否为完整模式。
    full_mode: bool,
}

impl Bn254PairingCircuit {
    /// 创建 MVP 模式电路（单 G1 曲线检查）。
    #[must_use]
    pub fn new() -> Self {
        Self { full_mode: false }
    }

    /// 创建 Full 模式电路（双 G1 检查 + 配对 hint）。
    #[must_use]
    pub fn new_full() -> Self {
        Self { full_mode: true }
    }

    /// 是否为 Full 模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    /// 运行 MVP 模式：验证 G1 点在曲线上。
    ///
    /// 输入 8 个 Fr：`[x(4), y(4)]`
    pub fn run_mvp(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 8 {
            return Err(ZkvmError::Other(format!(
                "Bn254PairingCircuit::run_mvp: inputs.len() {} != 8（需要 x/y 各 4 limbs）",
                inputs.len()
            )));
        }

        let mut builder = NonNativeBuilder::new();

        let x_limbs = [inputs[0], inputs[1], inputs[2], inputs[3]];
        let y_limbs = [inputs[4], inputs[5], inputs[6], inputs[7]];

        let x = builder.alloc_element(x_limbs);
        let y = builder.alloc_element(y_limbs);

        assert_g1_on_curve(&mut builder, &x, &y);

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }

    /// 运行 Full 模式：验证双 G1 点 + 配对等式 hint。
    ///
    /// 输入 17 个 Fr：`[A_x(4), A_y(4), C_x(4), C_y(4), pairing_valid(1)]`
    pub fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 17 {
            return Err(ZkvmError::Other(format!(
                "Bn254PairingCircuit::run_full: inputs.len() {} != 17（需要 A/C 各 8 + hint 1）",
                inputs.len()
            )));
        }

        let mut builder = NonNativeBuilder::new();

        let a_x = [inputs[0], inputs[1], inputs[2], inputs[3]];
        let a_y = [inputs[4], inputs[5], inputs[6], inputs[7]];
        let c_x = [inputs[8], inputs[9], inputs[10], inputs[11]];
        let c_y = [inputs[12], inputs[13], inputs[14], inputs[15]];
        let pairing_valid = inputs[16];

        let a_x_elem = builder.alloc_element(a_x);
        let a_y_elem = builder.alloc_element(a_y);
        let c_x_elem = builder.alloc_element(c_x);
        let c_y_elem = builder.alloc_element(c_y);

        // A 在 G1 曲线上
        assert_g1_on_curve(&mut builder, &a_x_elem, &a_y_elem);

        // C 在 G1 曲线上
        assert_g1_on_curve(&mut builder, &c_x_elem, &c_y_elem);

        // pairing_valid 必须为 1（host 保证 e(A,B) = e(C,D)）
        let hint_var = builder.alloc(pairing_valid);
        let row = builder.ccs.alloc_row();
        builder.ccs.add_bit_check(row, hint_var);

        // assert hint == 1
        let one_var = builder.alloc(Fr::one());
        let row = builder.ccs.alloc_row();
        builder.ccs.add_linear(
            row,
            &[
                (hint_var, Fr::one()),
                (one_var, Fr::one().neg()),
            ],
        );

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }
}

impl Default for Bn254PairingCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for Bn254PairingCircuit {
    fn name(&self) -> &str {
        "bn254_pairing"
    }

    fn num_variables(&self) -> usize {
        if self.full_mode {
            0
        } else {
            4
        }
    }

    fn build_ccs(&self) -> Ccs {
        if self.full_mode {
            return Ccs::new(1, vec![], vec![], vec![]).expect("minimal CCS for full mode");
        }

        // MVP: 简化版 4 变量（bit-check 风格，与 ed25519/ecdsa MVP 一致）
        // z = [1, x, x_sq, y_sq]
        // 约束：
        // - row 0: x*x - x_sq = 0
        // - row 1: y*y - y_sq = 0
        // （注：MVP build_ccs 是简化 stub，真实约束在 run_mvp 中）
        let mut m0 = SparseMatrix::new(2, 4);
        m0.add_entry(0, 1, Fr::one()).expect("M0");
        let mut m1 = SparseMatrix::new(2, 4);
        m1.add_entry(0, 1, Fr::one()).expect("M1");
        let mut m2 = SparseMatrix::new(2, 4);
        m2.add_entry(0, 2, Fr::one()).expect("M2");
        m2.add_entry(1, 3, Fr::one()).expect("M2 y");

        let neg_one = Fr::zero().sub(&Fr::one());

        Ccs::new(
            4,
            vec![m0, m1, m2],
            vec![
                vec![0, 1], // S_0: x*x
                vec![2],    // S_1: -x_sq
                vec![3],    // S_2: -y_sq
            ],
            vec![Fr::one(), neg_one, neg_one],
        )
        .expect("Bn254PairingCircuit CCS 构造应成功")
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            return Err(ZkvmError::Other(
                "Bn254PairingCircuit: full mode 请使用 run_full() 方法".to_string(),
            ));
        }

        if inputs.len() != 2 {
            return Err(ZkvmError::Other(format!(
                "Bn254PairingCircuit::assign_witness: inputs.len() {} != 2（需要 x, y）",
                inputs.len()
            )));
        }
        let x = inputs[0];
        let y = inputs[1];

        let x_sq = x.mul(&x);
        let y_sq = y.mul(&y);

        Ok(vec![Fr::one(), x, x_sq, y_sq])
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            GAS_BN254_PAIRING_FULL
        } else {
            GAS_BN254_PAIRING_MVP
        }
    }
}

impl CcsCircuit for Bn254PairingCircuit {
    fn name(&self) -> &str {
        "bn254_pairing"
    }

    fn num_matrices(&self) -> usize {
        if self.full_mode {
            0
        } else {
            3
        }
    }

    fn to_ccs_instance(
        &self,
        witness: &[Fr],
        public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError> {
        if self.full_mode {
            return Err(ZkvmError::Other(
                "Bn254PairingCircuit: full mode 请使用 run_full() 方法".to_string(),
            ));
        }

        let ccs = self.build_ccs();
        CcsInstance::new(ccs, witness.to_vec(), public_inputs.to_vec())
    }
}

// ===== 辅助函数 =====

fn fr_limbs_to_u256(limbs: &[Fr; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for i in 0..4 {
        let bytes = limbs[i].to_canonical_bytes();
        result[i] = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
    }
    result
}

fn u256_to_fr_vec(val: &[u64; 4]) -> Vec<Fr> {
    vec![
        Fr::from_u64(val[0]),
        Fr::from_u64(val[1]),
        Fr::from_u64(val[2]),
        Fr::from_u64(val[3]),
    ]
}

// ===== host 侧参考计算 =====

fn host_g1_on_curve(x: &[u64; 4], y: &[u64; 4]) -> bool {
    let m = &BN254_P;
    let y_sq = host_mul_mod(y, y, m);
    let x_sq = host_mul_mod(x, x, m);
    let x_cubed = host_mul_mod(&x_sq, x, m);
    let rhs = host_add_mod(&x_cubed, &BN254_B, m);
    y_sq == rhs
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::PrecompileRegistry;

    #[test]
    fn test_bn254_g1_on_curve_generator() {
        // G1 生成元 (1, 2) 应在曲线上：2² = 1³ + 3 → 4 = 4
        assert!(host_g1_on_curve(&BN254_G1_X, &BN254_G1_Y));
    }

    #[test]
    fn test_bn254_g1_not_on_curve() {
        // (1, 3) 不在曲线上：9 ≠ 1 + 3
        assert!(!host_g1_on_curve(&[1, 0, 0, 0], &[3, 0, 0, 0]));
    }

    #[test]
    fn test_bn254_pairing_mvp() {
        let mut inputs = Vec::new();
        inputs.extend(u256_to_fr_vec(&BN254_G1_X));
        inputs.extend(u256_to_fr_vec(&BN254_G1_Y));

        let circuit = Bn254PairingCircuit::new();
        let (ccs, witness) = circuit.run_mvp(&inputs).expect("run_mvp ok");
        assert!(ccs.num_rows() > 1000);
        let instance = CcsInstance::new(ccs, witness, vec![]).expect("instance");
        assert!(instance.is_satisfied().expect("is_satisfied"));
    }

    #[test]
    fn test_bn254_pairing_mvp_wrong_point() {
        // (1, 3) 不在曲线上
        let mut inputs = Vec::new();
        inputs.extend(u256_to_fr_vec(&[1, 0, 0, 0]));
        inputs.extend(u256_to_fr_vec(&[3, 0, 0, 0]));

        let circuit = Bn254PairingCircuit::new();
        let (ccs, witness) = circuit.run_mvp(&inputs).expect("run_mvp ok");
        let instance = CcsInstance::new(ccs, witness, vec![]).expect("instance");
        assert!(!instance.is_satisfied().expect("is_satisfied"), "不在曲线上的点应不满足约束");
    }

    #[test]
    fn test_bn254_pairing_full() {
        // 两个生成元 A=C=(1,2)，e(G1, G2) = e(G1, G2) 成立
        let mut inputs = Vec::new();
        inputs.extend(u256_to_fr_vec(&BN254_G1_X)); // A_x
        inputs.extend(u256_to_fr_vec(&BN254_G1_Y)); // A_y
        inputs.extend(u256_to_fr_vec(&BN254_G1_X)); // C_x
        inputs.extend(u256_to_fr_vec(&BN254_G1_Y)); // C_y
        inputs.push(Fr::one()); // pairing_valid = 1

        let circuit = Bn254PairingCircuit::new_full();
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full ok");
        assert!(ccs.num_rows() > 2000);
        let instance = CcsInstance::new(ccs, witness, vec![]).expect("instance");
        assert!(instance.is_satisfied().expect("is_satisfied"));
    }

    #[test]
    fn test_bn254_pairing_full_hint_zero() {
        // hint = 0 应不满足
        let mut inputs = Vec::new();
        inputs.extend(u256_to_fr_vec(&BN254_G1_X));
        inputs.extend(u256_to_fr_vec(&BN254_G1_Y));
        inputs.extend(u256_to_fr_vec(&BN254_G1_X));
        inputs.extend(u256_to_fr_vec(&BN254_G1_Y));
        inputs.push(Fr::zero()); // pairing_valid = 0

        let circuit = Bn254PairingCircuit::new_full();
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full ok");
        let instance = CcsInstance::new(ccs, witness, vec![]).expect("instance");
        assert!(!instance.is_satisfied().expect("is_satisfied"), "hint=0 应不满足");
    }

    #[test]
    fn test_bn254_pairing_gas_cost() {
        let mvp = Bn254PairingCircuit::new();
        assert_eq!(mvp.gas_cost(), 30_000);

        let full = Bn254PairingCircuit::new_full();
        assert_eq!(full.gas_cost(), 80_000);
    }

    #[test]
    fn test_bn254_pairing_wrong_input_length() {
        let circuit = Bn254PairingCircuit::new();
        assert!(circuit.run_mvp(&[Fr::zero(); 7]).is_err());
        assert!(circuit.run_mvp(&[Fr::zero(); 9]).is_err());

        let full = Bn254PairingCircuit::new_full();
        assert!(full.run_full(&[Fr::zero(); 16]).is_err());
        assert!(full.run_full(&[Fr::zero(); 18]).is_err());
    }

    #[test]
    fn test_bn254_pairing_registers_in_precompile_registry() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(Bn254PairingCircuit::new()));
        let found = registry.get("bn254_pairing");
        assert!(found.is_some());
        assert_eq!(found.unwrap().gas_cost(), 30_000);
    }
}
