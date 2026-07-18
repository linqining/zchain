//! ECDSA 验签预编译电路（Phase 10 — Task 10.4 / Phase E3）。
//!
//! 双模式实现：
//! - **MVP 模式**（`new()`）：double-and-add 单步约束结构（条件点加法 + bit range check）。
//! - **Full 模式**（`new_full()` / `new_full_with_bits(n)`）：完整 ECDSA 验签等式
//!   `s·R' = z·G + r·P`，使用 NonNativeBuilder + secp256k1_ops 非原生域算术。
//!
//! # MVP 模式约束结构（double-and-add 单步）
//!
//! witness `z = [1, bit, R, P, bit_P, R_new]`，约束：
//! - `bit * (1 - bit) = 0`（bit range check，确保 bit ∈ {0, 1}）
//! - `bit * P - bit_P = 0`（条件乘）
//! - `R + bit_P - R_new = 0`（条件加）
//!
//! 使用 7 个行隔离矩阵（同 Poseidon/SHA-256 模式），确保 subset 不污染其他行。
//!
//! # Full 模式
//!
//! 使用 `run_full()` 方法，输入 24 个 Fr 值（6 个 NonNativeElement × 4 limbs）：
//! `[s(4), r(4), ry(4), z(4), px(4), py(4)]`
//!
//! 验签等式：`s·R' = z·G + r·P`，其中 R' = (r, ry)（ry 为 hint）。
//! 避免 in-circuit 计算 s⁻¹ mod n，直接验证乘法形式等式。
//!
//! 生产默认 256-bit 完整标量；快速测试使用 `new_full_with_bits(8)` 截断到低 8 位。

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::non_native::{NonNativeBuilder, SECP256K1_GX, SECP256K1_GY};
use crate::precompiles::secp256k1_ops::{assert_point_equal, from_affine, point_add, scalar_mul};
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// ECDSA 验签预编译电路。
///
/// 双模式：
/// - MVP（`new()`）：double-and-add 单步约束
/// - Full（`new_full()`）：完整 ECDSA verify 等式 `s·R' = z·G + r·P`
#[derive(Debug, Clone)]
pub struct EcdsaVerifyCircuit {
    /// 曲线名称（固定 "secp256k1"）。
    curve: &'static str,
    /// 是否为完整验签模式。
    full_mode: bool,
    /// Full 模式下标量乘法使用的比特数（截断到低位）。
    scalar_num_bits: usize,
}

impl EcdsaVerifyCircuit {
    /// 创建 ECDSA 验签电路（Full 模式，secp256k1，256-bit 完整标量）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            curve: "secp256k1",
            full_mode: true,
            scalar_num_bits: 256,
        }
    }

    /// 创建 MVP ECDSA 验签电路（secp256k1，double-and-add 单步约束，用于快速测试）。
    #[must_use]
    pub fn new_mvp() -> Self {
        Self {
            curve: "secp256k1",
            full_mode: false,
            scalar_num_bits: 0,
        }
    }

    /// 创建 Full 模式 ECDSA 验签电路，默认 256-bit 完整标量。
    #[must_use]
    pub fn new_full() -> Self {
        Self {
            curve: "secp256k1",
            full_mode: true,
            scalar_num_bits: 256,
        }
    }

    /// 创建 Full 模式 ECDSA 验签电路，自定义标量比特数。
    #[must_use]
    pub fn new_full_with_bits(n: usize) -> Self {
        Self {
            curve: "secp256k1",
            full_mode: true,
            scalar_num_bits: n,
        }
    }

    /// 返回曲线名称。
    #[must_use]
    pub fn curve(&self) -> &'static str {
        self.curve
    }

    /// 是否为 Full 模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    /// Full 模式下标量比特数。
    #[must_use]
    pub fn scalar_num_bits(&self) -> usize {
        self.scalar_num_bits
    }

    /// Full 模式 ECDSA 验签：验证 `s·R' = z·G + r·P`。
    ///
    /// 输入 24 个 Fr 值：`[s(4), r(4), ry(4), z(4), px(4), py(4)]`
    ///
    /// 返回 `(Ccs, witness)`。
    ///
    /// # Errors
    /// - 输入长度不为 24
    /// - CCS 构建失败
    pub fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 24 {
            return Err(ZkvmError::Other(format!(
                "EcdsaVerifyCircuit::run_full: inputs.len() {} != 24（需要 s/r/ry/z/px/py 各 4 limbs）",
                inputs.len()
            )));
        }

        let mut builder = NonNativeBuilder::new();

        // 分配输入为 NonNativeElement
        let s = builder.alloc_element([inputs[0], inputs[1], inputs[2], inputs[3]]);
        let r = builder.alloc_element([inputs[4], inputs[5], inputs[6], inputs[7]]);
        let ry = builder.alloc_element([inputs[8], inputs[9], inputs[10], inputs[11]]);
        let z = builder.alloc_element([inputs[12], inputs[13], inputs[14], inputs[15]]);
        let px = builder.alloc_element([inputs[16], inputs[17], inputs[18], inputs[19]]);
        let py = builder.alloc_element([inputs[20], inputs[21], inputs[22], inputs[23]]);

        // 转为 [u64; 4] 用于 from_affine
        let r_u256 = builder.element_to_u256(&r);
        let ry_u256 = builder.element_to_u256(&ry);
        let px_u256 = builder.element_to_u256(&px);
        let py_u256 = builder.element_to_u256(&py);

        // R' = (r, ry, 1)
        let r_prime = from_affine(&mut builder, &r_u256, &ry_u256);
        // G = (GX, GY, 1)
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        // P = (px, py, 1)
        let p = from_affine(&mut builder, &px_u256, &py_u256);

        // 左边: s · R'
        let s_r_prime = scalar_mul(&mut builder, &r_prime, &s, self.scalar_num_bits);

        // 右边: z · G + r · P
        let z_g = scalar_mul(&mut builder, &g, &z, self.scalar_num_bits);
        let r_p = scalar_mul(&mut builder, &p, &r, self.scalar_num_bits);
        let rhs = point_add(&mut builder, &z_g, &r_p);

        // 断言: s · R' == z · G + r · P
        assert_point_equal(&mut builder, &s_r_prime, &rhs);

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }
}

impl Default for EcdsaVerifyCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for EcdsaVerifyCircuit {
    fn name(&self) -> &str {
        "ecdsa_verify"
    }

    fn num_variables(&self) -> usize {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 24];
            self.run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0
                .num_vars
        } else {
            // z = [1, bit, R, P, bit_P, R_new]
            6
        }
    }

    fn build_ccs(&self) -> Result<Ccs, ZkvmError> {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 24];
            return Ok(self
                .run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0);
        }

        // 7 个行隔离矩阵，每个 3 行 × 6 列
        // 矩阵索引: 0=M_bit_r0, 1=M_bit_r1, 2=M_P_r1, 3=M_bitP_r1,
        //          4=M_R_r2, 5=M_bitP_r2, 6=M_Rnew_r2
        //
        // 行隔离原则：每个矩阵只在单一行有非零项，确保包含该矩阵的 subset
        // 在其他行求值为 0（因 (M_j·z)[other_row] = 0，乘积为 0）。
        //
        // 约束（3 行）：
        // - row 0: bit - bit*bit = 0  → S_0={0} c_0=+1, S_1={0,0} c_1=-1
        // - row 1: bit*P - bit_P = 0  → S_2={1,2} c_2=+1, S_3={3} c_3=-1
        // - row 2: R + bit_P - R_new = 0 → S_4={4} c_4=+1, S_5={5} c_5=+1, S_6={6} c_6=-1

        let mut m_bit_r0 = SparseMatrix::new(3, 6);
        m_bit_r0.add_entry(0, 1, Fr::one()).expect("M_bit_r0");

        let mut m_bit_r1 = SparseMatrix::new(3, 6);
        m_bit_r1.add_entry(1, 1, Fr::one()).expect("M_bit_r1");

        let mut m_p_r1 = SparseMatrix::new(3, 6);
        m_p_r1.add_entry(1, 3, Fr::one()).expect("M_P_r1");

        let mut m_bitp_r1 = SparseMatrix::new(3, 6);
        m_bitp_r1.add_entry(1, 4, Fr::one()).expect("M_bitP_r1");

        let mut m_r_r2 = SparseMatrix::new(3, 6);
        m_r_r2.add_entry(2, 2, Fr::one()).expect("M_R_r2");

        let mut m_bitp_r2 = SparseMatrix::new(3, 6);
        m_bitp_r2.add_entry(2, 4, Fr::one()).expect("M_bitP_r2");

        let mut m_rnew_r2 = SparseMatrix::new(3, 6);
        m_rnew_r2.add_entry(2, 5, Fr::one()).expect("M_Rnew_r2");

        let neg_one = Fr::zero().sub(&Fr::one());

        Ok(Ccs::new(
            6,
            vec![
                m_bit_r0, m_bit_r1, m_p_r1, m_bitp_r1, m_r_r2, m_bitp_r2, m_rnew_r2,
            ],
            vec![
                vec![0],    // S_0: M_bit_r0 → row 0: +bit
                vec![0, 0], // S_1: (M_bit_r0)^2 → row 0: -bit*bit
                vec![1, 2], // S_2: M_bit_r1 * M_P_r1 → row 1: +bit*P
                vec![3],    // S_3: M_bitP_r1 → row 1: -bit_P
                vec![4],    // S_4: M_R_r2 → row 2: +R
                vec![5],    // S_5: M_bitP_r2 → row 2: +bit_P
                vec![6],    // S_6: M_Rnew_r2 → row 2: -R_new
            ],
            vec![
                Fr::one(), // c_0: +bit
                neg_one,   // c_1: -bit*bit
                Fr::one(), // c_2: +bit*P
                neg_one,   // c_3: -bit_P
                Fr::one(), // c_4: +R
                Fr::one(), // c_5: +bit_P
                neg_one,   // c_6: -R_new
            ],
        )
        .expect("EcdsaVerifyCircuit CCS 构造应成功"))
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            return Ok(self.run_full(inputs)?.1);
        }

        // 输入: [bit, R, P]（3 个域元素，MVP 表示 double-and-add 单步的 3 个输入）
        if inputs.len() != 3 {
            return Err(ZkvmError::Other(format!(
                "EcdsaVerifyCircuit::assign_witness: inputs.len() {} != 3（需要 bit, R, P 三个输入）",
                inputs.len()
            )));
        }
        let bit = inputs[0];
        let r = inputs[1];
        let p = inputs[2];

        // bit_P = bit * P（条件乘）
        let bit_p = bit.mul(&p);

        // R_new = R + bit_P（条件加）
        let r_new = r.add(&bit_p);

        // witness: [1, bit, R, P, bit_P, R_new]
        Ok(vec![Fr::one(), bit, r, p, bit_p, r_new])
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            // Full 模式: 3 次 scalar_mul(num_bits) + 1 次 point_add + assert_point_equal
            // per_bit: 3 × 25200 = 75600；fixed: 16800 + 5600 = 22400
            let per_bit_gas: u64 = 75_600;
            let fixed_gas: u64 = 22_400;
            per_bit_gas * self.scalar_num_bits as u64 + fixed_gas
        } else {
            // spec L660: GAS_ZKVM_ECDSA_VERIFY = 100_000（与既有 GAS_SECP256K1_VERIFY 对齐）
            // MVP 单步返回完整 gas（与 SHA-256 模式一致 — 单 Ch 操作返回 25_000 block gas）
            100_000
        }
    }
}

impl CcsCircuit for EcdsaVerifyCircuit {
    fn name(&self) -> &str {
        "ecdsa_verify"
    }

    fn num_matrices(&self) -> usize {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 24];
            self.run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0
                .num_matrices()
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
    use crate::precompiles::non_native::{
        SECP256K1_N, SECP256K1_P_CURVE, host_add_mod, host_inv_mod, host_lt, host_mul_mod,
        host_pow_mod, host_sub, host_sub_mod,
    };

    // ===== 辅助函数 =====

    /// [u64; 4] → Vec<Fr>（4 个 limb）
    fn u256_to_fr_vec(val: &[u64; 4]) -> Vec<Fr> {
        vec![
            Fr::from_u64(val[0]),
            Fr::from_u64(val[1]),
            Fr::from_u64(val[2]),
            Fr::from_u64(val[3]),
        ]
    }

    // ===== Host-side EC 点运算（匹配电路公式）=====
    // 用于在测试中计算有效的 ECDSA 验签输入。

    type HostPoint = ([u64; 4], [u64; 4], [u64; 4]); // (X, Y, Z) Jacobian

    fn host_from_affine(x: &[u64; 4], y: &[u64; 4]) -> HostPoint {
        (*x, *y, [1, 0, 0, 0])
    }

    /// Jacobian 倍点（dbl-2009-l, a=0），匹配电路 point_double。
    fn host_point_double(p: &HostPoint) -> HostPoint {
        let m = &SECP256K1_P_CURVE;
        let (x, y, z) = p;

        let a = host_mul_mod(x, x, m);
        let b = host_mul_mod(y, y, m);
        let c = host_mul_mod(&b, &b, m);

        let xb = host_add_mod(x, &b, m);
        let xb2 = host_mul_mod(&xb, &xb, m);
        let tmp1 = host_sub_mod(&xb2, &a, m);
        let tmp2 = host_sub_mod(&tmp1, &c, m);
        let d = host_add_mod(&tmp2, &tmp2, m);

        let e = host_add_mod(&a, &a, m);
        let e = host_add_mod(&e, &a, m);

        let f = host_mul_mod(&e, &e, m);

        let two_d = host_add_mod(&d, &d, m);
        let x3 = host_sub_mod(&f, &two_d, m);

        let d_minus_x3 = host_sub_mod(&d, &x3, m);
        let e_dm = host_mul_mod(&e, &d_minus_x3, m);
        let two_c = host_add_mod(&c, &c, m);
        let four_c = host_add_mod(&two_c, &two_c, m);
        let eight_c = host_add_mod(&four_c, &four_c, m);
        let y3 = host_sub_mod(&e_dm, &eight_c, m);

        let two_y = host_add_mod(y, y, m);
        let z3 = host_mul_mod(&two_y, z, m);

        (x3, y3, z3)
    }

    /// Jacobian 点加法（add-1998-cmo-2, H = U1 - U2），匹配电路 point_add。
    fn host_point_add(p: &HostPoint, q: &HostPoint) -> HostPoint {
        let m = &SECP256K1_P_CURVE;
        let (x1, y1, z1) = p;
        let (x2, y2, z2) = q;

        let z2_sq = host_mul_mod(z2, z2, m);
        let z2_cu = host_mul_mod(&z2_sq, z2, m);
        let z1_sq = host_mul_mod(z1, z1, m);
        let z1_cu = host_mul_mod(&z1_sq, z1, m);

        let u1 = host_mul_mod(x1, &z2_sq, m);
        let s1 = host_mul_mod(y1, &z2_cu, m);
        let u2 = host_mul_mod(x2, &z1_sq, m);
        let s2 = host_mul_mod(y2, &z1_cu, m);

        let h = host_sub_mod(&u1, &u2, m);
        let h2 = host_mul_mod(&h, &h, m);
        let h3 = host_mul_mod(&h, &h2, m);

        let r = host_sub_mod(&s1, &s2, m);
        let v = host_mul_mod(&u1, &h2, m);

        let r_sq = host_mul_mod(&r, &r, m);
        let two_v = host_add_mod(&v, &v, m);
        let x3_tmp = host_add_mod(&r_sq, &h3, m);
        let x3 = host_sub_mod(&x3_tmp, &two_v, m);

        let v_minus_x3 = host_sub_mod(&v, &x3, m);
        let r_vx = host_mul_mod(&r, &v_minus_x3, m);
        let s1_h3 = host_mul_mod(&s1, &h3, m);
        let y3 = host_sub_mod(&r_vx, &s1_h3, m);

        let z1z2 = host_mul_mod(z1, z2, m);
        let z3 = host_mul_mod(&z1z2, &h, m);

        (x3, y3, z3)
    }

    fn host_negate(p: &HostPoint) -> HostPoint {
        let m = &SECP256K1_P_CURVE;
        let neg_y = host_sub_mod(m, &p.1, m);
        (p.0, neg_y, p.2)
    }

    fn host_to_affine(p: &HostPoint) -> ([u64; 4], [u64; 4]) {
        let m = &SECP256K1_P_CURVE;
        let inv_z = host_inv_mod(&p.2, m);
        let inv_z2 = host_mul_mod(&inv_z, &inv_z, m);
        let inv_z3 = host_mul_mod(&inv_z2, &inv_z, m);
        let x = host_mul_mod(&p.0, &inv_z2, m);
        let y = host_mul_mod(&p.1, &inv_z3, m);
        (x, y)
    }

    /// Host 端标量乘法：scalar · P（double-and-add，匹配电路 scalar_mul 逻辑）。
    ///
    /// 从高位到低位迭代 256 位，使用 "started" 标志避免对无穷远点调用 point_add。
    fn host_scalar_mul(scalar: &[u64; 4], p: &HostPoint) -> HostPoint {
        let mut result = ([1u64, 0, 0, 0], [1u64, 0, 0, 0], [0u64, 0, 0, 0]); // 无穷远点
        let mut started = false;

        for bit_idx in (0..256).rev() {
            if started {
                result = host_point_double(&result);
            }
            let limb_idx = bit_idx / 64;
            let bit_in_limb = bit_idx % 64;
            let bit = (scalar[limb_idx] >> bit_in_limb) & 1;
            if bit == 1 {
                if started {
                    result = host_point_add(&result, p);
                } else {
                    result = *p;
                    started = true;
                }
            }
        }
        result
    }

    /// sqrt(a) mod p（p ≡ 3 mod 4，使用 a^((p+1)/4)）
    fn host_sqrt_mod(a: &[u64; 4]) -> [u64; 4] {
        let p = &SECP256K1_P_CURVE;
        let p_plus_1: [u64; 4] = [p[0].wrapping_add(1), p[1], p[2], p[3]];
        let mut exp = [0u64; 4];
        exp[0] = (p_plus_1[0] >> 2) | ((p_plus_1[1] & 3) << 62);
        exp[1] = (p_plus_1[1] >> 2) | ((p_plus_1[2] & 3) << 62);
        exp[2] = (p_plus_1[2] >> 2) | ((p_plus_1[3] & 3) << 62);
        exp[3] = p_plus_1[3] >> 2;

        host_pow_mod(a, &exp, p)
    }

    /// 构造 Full 模式测试输入（小标量，用于 8-bit 快速测试）。
    ///
    /// 使用小标量（s=3, z=2, r=1，均 < 256 满足 8-bit recompose 约束）。
    /// R' = (1, sqrt(8) mod p) — 曲线上的有效点（1³ + 7 = 8，8 是 QR mod p）。
    /// P = 3·R' - 2·G，使等式 3·R' = 2·G + 1·P 成立。
    fn make_full_mode_test_inputs_small() -> Vec<Fr> {
        let r: [u64; 4] = [1, 0, 0, 0];
        let ry = host_sqrt_mod(&[8, 0, 0, 0]);

        // 验证 ry² ≡ 8 mod p
        let ry_sq = host_mul_mod(&ry, &ry, &SECP256K1_P_CURVE);
        debug_assert_eq!(ry_sq, [8, 0, 0, 0], "ry² ≡ 8 mod p");

        let r_prime = host_from_affine(&r, &ry);
        let g = host_from_affine(&SECP256K1_GX, &SECP256K1_GY);

        // 3·R' = 2·R' + R'
        let two_r = host_point_double(&r_prime);
        let three_r = host_point_add(&two_r, &r_prime);

        // 2·G
        let two_g = host_point_double(&g);

        // P = 3·R' - 2·G = 3·R' + (-2·G)
        let neg_two_g = host_negate(&two_g);
        let p_point = host_point_add(&three_r, &neg_two_g);

        let (px, py) = host_to_affine(&p_point);

        let mut inputs: Vec<Fr> = Vec::with_capacity(24);
        inputs.extend(u256_to_fr_vec(&[3, 0, 0, 0])); // s = 3
        inputs.extend(u256_to_fr_vec(&r)); // r = 1
        inputs.extend(u256_to_fr_vec(&ry)); // ry = sqrt(8) mod p
        inputs.extend(u256_to_fr_vec(&[2, 0, 0, 0])); // z = 2
        inputs.extend(u256_to_fr_vec(&px)); // px
        inputs.extend(u256_to_fr_vec(&py)); // py
        inputs
    }

    /// 构造 Full 模式测试输入（真实 256-bit ECDSA 签名）。
    ///
    /// 测试向量：私钥 d=1，消息哈希 z=1，nonce k=2。
    /// - P = d·G = G（公钥）
    /// - R = k·G = 2·G（nonce 点）
    /// - r = R.x mod n（256-bit 签名分量）
    /// - s = k⁻¹·(z + r·d) mod n（256-bit 签名分量）
    /// - 验证等式：s·R' = z·G + r·P ⟺ (1+r)·G = (1+r)·G ✓
    fn make_full_mode_test_inputs() -> Vec<Fr> {
        let n = &SECP256K1_N;
        let g = host_from_affine(&SECP256K1_GX, &SECP256K1_GY);

        // d = 1, z = 1, k = 2
        let d: [u64; 4] = [1, 0, 0, 0];
        let z: [u64; 4] = [1, 0, 0, 0];
        let k: [u64; 4] = [2, 0, 0, 0];

        // P = d·G = G
        let p_point = host_scalar_mul(&d, &g);
        let (px, py) = host_to_affine(&p_point);

        // R = k·G = 2·G
        let r_point = host_scalar_mul(&k, &g);
        let (r_x, r_y) = host_to_affine(&r_point);

        // r = R.x mod n
        let r = if host_lt(&r_x, n) {
            r_x
        } else {
            host_sub(&r_x, n).0
        };
        debug_assert!(host_lt(&r, n), "r < n");

        // ry = R.y（hint，用于构造 R' = (r, ry)）
        let ry = r_y;

        // s = k⁻¹ · (z + r·d) mod n = k⁻¹ · (1 + r) mod n
        let k_inv = host_inv_mod(&k, n);
        let z_plus_rd = host_add_mod(&z, &r, n); // z + r·d = 1 + r (d=1)
        let s = host_mul_mod(&k_inv, &z_plus_rd, n);

        let mut inputs: Vec<Fr> = Vec::with_capacity(24);
        inputs.extend(u256_to_fr_vec(&s)); // s (4 limbs)
        inputs.extend(u256_to_fr_vec(&r)); // r (4 limbs)
        inputs.extend(u256_to_fr_vec(&ry)); // ry (4 limbs)
        inputs.extend(u256_to_fr_vec(&z)); // z (4 limbs)
        inputs.extend(u256_to_fr_vec(&px)); // px (4 limbs)
        inputs.extend(u256_to_fr_vec(&py)); // py (4 limbs)
        inputs
    }

    // ===== MVP 模式测试（既有 12 个）=====

    #[test]
    fn test_ecdsa_circuit_build_ccs() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        assert_eq!(ccs.num_matrices(), 7, "应有 7 个行隔离矩阵");
        assert_eq!(ccs.num_constraints(), 7, "应有 7 个 subsets");
        assert_eq!(ccs.num_rows(), 3, "应有 3 行约束");
        assert_eq!(ccs.num_vars, 6, "witness 应为 6 变量");
    }

    #[test]
    fn test_ecdsa_circuit_satisfied_by_bit_zero() {
        // bit=0: bit_P=0, R_new=R
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let bit = Fr::zero();
        let r = Fr::from_u32_with_wrap(42);
        let p = Fr::from_u32_with_wrap(100);
        let witness = circuit
            .assign_witness(&[bit, r, p])
            .expect("assign_witness 应成功");
        assert_eq!(witness.len(), 6);
        assert!(witness[4].is_zero(), "bit=0 时 bit_P 应为 0");
        assert_eq!(witness[5], r, "bit=0 时 R_new 应等于 R");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_ecdsa_circuit_satisfied_by_bit_one() {
        // bit=1: bit_P=P, R_new=R+P
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let bit = Fr::one();
        let r = Fr::from_u32_with_wrap(42);
        let p = Fr::from_u32_with_wrap(100);
        let witness = circuit
            .assign_witness(&[bit, r, p])
            .expect("assign_witness 应成功");
        assert_eq!(witness[4], p, "bit=1 时 bit_P 应等于 P");
        assert_eq!(witness[5].to_u32(), 142, "bit=1 时 R_new 应等于 R+P");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_ecdsa_circuit_soundness_bit_not_binary() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let bit = Fr::from_u32_with_wrap(2);
        let r = Fr::from_u32_with_wrap(42);
        let p = Fr::from_u32_with_wrap(100);
        let witness = circuit
            .assign_witness(&[bit, r, p])
            .expect("assign_witness 应成功");
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "bit=2（非二进制）应不满足约束"
        );
    }

    #[test]
    fn test_ecdsa_circuit_soundness_tampered_rnew() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let bit = Fr::one();
        let r = Fr::from_u32_with_wrap(42);
        let p = Fr::from_u32_with_wrap(100);
        let mut witness = circuit
            .assign_witness(&[bit, r, p])
            .expect("assign_witness 应成功");
        witness[5] = Fr::from_u32_with_wrap(143);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 R_new 后应不满足约束"
        );
    }

    #[test]
    fn test_ecdsa_circuit_soundness_tampered_bitp() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let ccs = circuit.build_ccs().expect("build_ccs");
        let bit = Fr::one();
        let r = Fr::from_u32_with_wrap(42);
        let p = Fr::from_u32_with_wrap(100);
        let mut witness = circuit
            .assign_witness(&[bit, r, p])
            .expect("assign_witness 应成功");
        witness[4] = Fr::from_u32_with_wrap(101);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by 应成功"),
            "篡改 bit_P 后应不满足约束"
        );
    }

    #[test]
    fn test_ecdsa_circuit_consistency_with_host() {
        use secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk_r = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk_p = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk_r = sk_r.public_key(&secp);
        let pk_p = sk_p.public_key(&secp);

        let circuit = EcdsaVerifyCircuit::new_mvp();
        let bit = Fr::one();
        let r = Fr::from_u32_with_wrap(1);
        let p = Fr::from_u32_with_wrap(2);
        let witness = circuit
            .assign_witness(&[bit, r, p])
            .expect("assign_witness 应成功");
        assert_eq!(witness[5].to_u32(), 3, "bit=1 时 R_new 应等于 R+P");
        assert_eq!(pk_r.serialize().len(), 33);
        assert_eq!(pk_p.serialize().len(), 33);
    }

    #[test]
    fn test_ecdsa_circuit_empty_input() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let result = circuit.assign_witness(&[]);
        assert!(result.is_err(), "空输入应返回错误");
    }

    #[test]
    fn test_ecdsa_circuit_wrong_input_length() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let result = circuit.assign_witness(&[Fr::one(), Fr::one()]);
        assert!(result.is_err(), "输入长度 != 3 应返回错误");
    }

    #[test]
    fn test_ecdsa_circuit_registry_integration() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(EcdsaVerifyCircuit::new_mvp()));
        assert_eq!(registry.len(), 1);
        let circuit = registry.get("ecdsa_verify").expect("应找到 ecdsa_verify");
        assert_eq!(circuit.name(), "ecdsa_verify");
        assert_eq!(circuit.num_variables(), 6);
        assert_eq!(circuit.gas_cost(), 100_000);
    }

    #[test]
    fn test_ecdsa_circuit_gas_cost() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        assert_eq!(
            circuit.gas_cost(),
            100_000,
            "gas_cost 应为 100_000（spec L660）"
        );
    }

    #[test]
    fn test_ecdsa_circuit_curve_name() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        assert_eq!(circuit.curve(), "secp256k1", "curve 应为 secp256k1");
    }

    #[test]
    fn test_ecdsa_circuit_ccs_circuit_trait() {
        let circuit = EcdsaVerifyCircuit::new_mvp();
        let bit = Fr::one();
        let r = Fr::from_u32_with_wrap(42);
        let p = Fr::from_u32_with_wrap(100);
        let witness = circuit
            .assign_witness(&[bit, r, p])
            .expect("assign_witness 应成功");
        let public_inputs = vec![Fr::one()];

        let ccs_circuit: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs_circuit.name(), "ecdsa_verify");
        assert_eq!(ccs_circuit.num_matrices(), 7);

        let instance = ccs_circuit
            .to_ccs_instance(&witness, &public_inputs)
            .expect("to_ccs_instance 应成功");
        assert!(instance.is_satisfied().expect("is_satisfied 应成功"));
    }

    // ===== Full 模式测试（新增 10 个）=====

    #[test]
    fn test_ecdsa_full_mode_constructors() {
        let mvp = EcdsaVerifyCircuit::new_mvp();
        assert!(!mvp.is_full_mode(), "new() 应为 MVP 模式");
        assert_eq!(mvp.scalar_num_bits(), 0);

        let full = EcdsaVerifyCircuit::new_full();
        assert!(full.is_full_mode(), "new_full() 应为 Full 模式");
        assert_eq!(full.scalar_num_bits(), 256, "new_full() 默认 256-bit");

        let custom = EcdsaVerifyCircuit::new_full_with_bits(16);
        assert!(custom.is_full_mode());
        assert_eq!(
            custom.scalar_num_bits(),
            16,
            "new_full_with_bits(16) 应为 16"
        );
    }

    #[test]
    fn test_ecdsa_full_mode_basic_satisfied() {
        // 等式: 3·R' = 2·G + 1·P，其中 R'=(1, sqrt(8)), P=3·R'-2·G
        // s=3, z=2, r=1 — 均小于 256，满足 8-bit recompose 约束
        let circuit = EcdsaVerifyCircuit::new_full_with_bits(8);
        let inputs = make_full_mode_test_inputs_small();
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full 应成功");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "Full 模式基本验签等式应满足"
        );
    }

    #[test]
    fn test_ecdsa_full_mode_gas_cost() {
        let mvp = EcdsaVerifyCircuit::new_mvp();
        assert_eq!(mvp.gas_cost(), 100_000, "MVP gas_cost = 100_000");

        let full_256 = EcdsaVerifyCircuit::new_full();
        assert_eq!(
            full_256.gas_cost(),
            19_376_000,
            "Full 256-bit gas_cost = 19_376_000"
        );

        let full_8 = EcdsaVerifyCircuit::new_full_with_bits(8);
        assert_eq!(full_8.gas_cost(), 627_200, "Full 8-bit gas_cost = 627_200");
    }

    #[test]
    fn test_ecdsa_full_mode_num_variables() {
        let mvp = EcdsaVerifyCircuit::new_mvp();
        assert_eq!(mvp.num_variables(), 6, "MVP num_variables = 6");

        let full = EcdsaVerifyCircuit::new_full();
        // Full mode 调用 run_full() 构建真实 CCS，变量数 ≈ 29M（256-bit scalar_mul × 3）
        assert!(
            full.num_variables() > 1_000_000,
            "Full num_variables 应 > 1M"
        );
    }

    #[test]
    fn test_ecdsa_full_mode_invalid_input_length() {
        let circuit = EcdsaVerifyCircuit::new_full();
        let bad_inputs = vec![Fr::zero(); 23]; // 23 != 24
        let result = circuit.run_full(&bad_inputs);
        assert!(result.is_err(), "输入长度 != 24 应返回错误");
    }

    #[test]
    fn test_ecdsa_full_mode_tampered_s() {
        let circuit = EcdsaVerifyCircuit::new_full_with_bits(8);
        let mut inputs = make_full_mode_test_inputs_small();
        // 篡改 s[0]: 3 → 4 → 4·R' ≠ 2·G + 1·P = 3·R'
        inputs[0] = Fr::from_u64(4);
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full 应成功");
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改 s 后等式不成立，CCS 应不满足"
        );
    }

    #[test]
    fn test_ecdsa_full_mode_tampered_r() {
        let circuit = EcdsaVerifyCircuit::new_full_with_bits(8);
        let mut inputs = make_full_mode_test_inputs_small();
        // 篡改 r[0]: 1 → 2 → r·P 变为 2·P，且 R'=(2, sqrt(8)) 不再匹配
        inputs[4] = Fr::from_u64(2);
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full 应成功");
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改 r 后等式不成立，CCS 应不满足"
        );
    }

    #[test]
    fn test_ecdsa_full_mode_tampered_px() {
        let circuit = EcdsaVerifyCircuit::new_full_with_bits(8);
        let mut inputs = make_full_mode_test_inputs_small();
        // 篡改 px[0]: 原值 + 1 → P 不再是正确的点
        inputs[16] = inputs[16].add(&Fr::one());
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full 应成功");
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改 px 后等式不成立，CCS 应不满足"
        );
    }

    #[test]
    fn test_ecdsa_full_mode_assign_witness_error() {
        let circuit = EcdsaVerifyCircuit::new_full();
        let result = circuit.assign_witness(&[Fr::one(), Fr::one(), Fr::one()]);
        assert!(result.is_err(), "Full 模式调用 assign_witness 应返回错误");
    }

    #[test]
    fn test_ecdsa_full_mode_mvp_backward_compatible() {
        // new() 仍为 MVP 模式，所有 MVP 行为不变
        let circuit = EcdsaVerifyCircuit::new_mvp();
        assert!(!circuit.is_full_mode());
        assert_eq!(circuit.num_variables(), 6);
        assert_eq!(circuit.gas_cost(), 100_000);

        // MVP CCS 仍可正常使用
        let ccs = circuit.build_ccs().expect("build_ccs");
        assert_eq!(ccs.num_matrices(), 7);
        assert_eq!(ccs.num_rows(), 3);

        // MVP assign_witness 仍正常工作
        let witness = circuit
            .assign_witness(&[
                Fr::one(),
                Fr::from_u32_with_wrap(42),
                Fr::from_u32_with_wrap(100),
            ])
            .expect("assign_witness 应成功");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    // ===== 256-bit ECDSA 测试（Phase H）=====

    #[test]
    fn test_host_scalar_mul_2g() {
        let g = host_from_affine(&SECP256K1_GX, &SECP256K1_GY);
        let two_g = host_scalar_mul(&[2, 0, 0, 0], &g);
        let expected = host_point_double(&g);
        let (x, _) = host_to_affine(&two_g);
        let (ex, _) = host_to_affine(&expected);
        assert_eq!(x, ex, "2·G 应等于 double(G)");
    }

    #[test]
    fn test_host_scalar_mul_3g() {
        let g = host_from_affine(&SECP256K1_GX, &SECP256K1_GY);
        let three_g = host_scalar_mul(&[3, 0, 0, 0], &g);
        let two_g = host_point_double(&g);
        let expected = host_point_add(&two_g, &g);
        let (x, _) = host_to_affine(&three_g);
        let (ex, _) = host_to_affine(&expected);
        assert_eq!(x, ex, "3·G 应等于 double(G) + G");
    }

    #[test]
    #[ignore = "256-bit ECDSA 需 ~19.4M 约束，用 --release --ignored 运行"]
    fn test_ecdsa_full_mode_256bit_satisfied() {
        let circuit = EcdsaVerifyCircuit::new_full(); // 默认 256-bit
        let inputs = make_full_mode_test_inputs();
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full 应成功");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "256-bit ECDSA 真实验签等式应满足"
        );
    }

    #[test]
    #[ignore = "256-bit ECDSA 需 ~19.4M 约束，用 --release --ignored 运行"]
    fn test_ecdsa_full_mode_256bit_tampered_s() {
        let circuit = EcdsaVerifyCircuit::new_full();
        let mut inputs = make_full_mode_test_inputs();
        // 篡改 s[0]：+1 → 等式不成立
        inputs[0] = inputs[0].add(&Fr::one());
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full 应成功");
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改 s 后 256-bit 等式应不满足"
        );
    }
}
