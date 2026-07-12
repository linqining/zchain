//! Fr-based R1CS gadget 库（Phase F — 真实 Groth16 压缩）。
//!
//! 提供 BN254 G1 点运算 gadget，在 `ConstraintSystem<Fr>` 中工作。
//! 用于 [`HypernovaVerifierCircuitBN254`]，使其可实现 `ConstraintSynthesizer<Fr>`，
//! 从而接入 `Groth16::<Bn254>` 生成真实 SNARK proof。
//!
//! ## 设计原理
//!
//! BN254 G1 点坐标 ∈ Fq（base field）。在 `ConstraintSystem<Fr>` 中工作時，
//! Fq 元素需用 `EmulatedFpVar<Fq, Fr>` 非原生模拟。
//!
//! `ProjectiveVar<BN254_G1_Config, EmulatedFpVar<Fq, Fr>>` 因 trait 约束不兼容
//! （`BasePrimeField<BN254_G1_Config> = Fq`，但 `EmulatedFpVar<Fq, Fr>` 提供
//! `FieldVar<Fq, Fr>` 而非 `FieldVar<Fq, Fq>`），故手动实现 G1 点运算。
//!
//! ## 坐标系
//!
//! ark-ec 0.6.0 的 `SWProjective`（即 `G1Projective`）内部使用 **Jacobian 坐标**
//! （仿射 = X/Z² : Y/Z³），非标准投影坐标（X/Z : Y/Z）。所有公式必须匹配
//! Jacobian 版本：
//! - `add-2007-bl`（Jacobian）— Z3 = 2·Z1·Z2·H
//! - `dbl-2009-l`（Jacobian, a=0）— Z3 = 2·Y1·Z1
//!
//! ## 实现范围
//!
//! - Jacobian 坐标 (X, Y, Z)，无穷远点 = (1, 1, 0)（Z=0）
//! - 不完全加法公式（不处理 P1=P2 的情况，对随机 fold commitment 概率可忽略）
//! - 安全加法 `safe_add`（处理无穷远点）
//! - 倍点 `point_double`（正确处理无穷远点：Z=0 → Z'=0）
//! - 标量乘法 `scalar_mul`（MSB-first double-and-add，使用安全加法）
//!
//! ## 约束数估算
//!
//! 非原生点运算开销大（每个 EmulatedFpVar 乘法 ~100 约束）：
//! - `point_double`：~7 次 Fq 乘法 ≈ ~700 约束
//! - `add_incomplete`：~13 次 Fq 乘法 ≈ ~1300 约束
//! - `safe_add`：~13 次 Fq 乘法 + 2 次 is_eq + 6 次 cond_select ≈ ~1900 约束
//! - `scalar_mul`（254-bit）：~254 × (double + safe_add + cond_select) ≈ ~700k 约束
//! - `fold_commitment_check_bn254`：~700k + ~1900 + ~400(enforce_equal_projective) ≈ ~702k 约束/步

use ark_bn254::{Fq, Fr, G1Projective};
use ark_ff::{One, Zero};
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;

/// Fq 的模拟变量类型别名（在 Fr-based CS 中表示 Fq 元素）。
pub type FqVarEmulated = EmulatedFpVar<Fq, Fr>;

/// Fr 变量类型别名（标量域原生）。
pub type FrVar = FpVar<Fr>;

/// BN254 G1 点的 Fr-based R1CS 表示（Jacobian 坐标）。
///
/// 在 `ConstraintSystem<Fr>` 中工作，BN254 G1 点坐标（Fq）用 `EmulatedFpVar` 非原生模拟。
/// 使用 Jacobian 坐标（仿射 = X/Z² : Y/Z³），匹配 ark-ec 0.6.0 的 `G1Projective`。
/// 无穷远点表示为 Z=0（X、Y 值任意）。
#[derive(Debug, Clone)]
pub struct G1VarBN254 {
    /// 投影 X 坐标
    pub x: FqVarEmulated,
    /// 投影 Y 坐标
    pub y: FqVarEmulated,
    /// 投影 Z 坐标（Z=0 表示无穷远点）
    pub z: FqVarEmulated,
}

impl G1VarBN254 {
    /// 无穷远点 (0, 1, 0)
    pub fn zero() -> Self {
        Self {
            x: FqVarEmulated::Constant(Fq::zero()),
            y: FqVarEmulated::Constant(Fq::one()),
            z: FqVarEmulated::Constant(Fq::zero()),
        }
    }

    /// 分配 G1 点作为公共输入。
    pub fn new_input<T: Borrow<G1Projective>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let point = *f()?.borrow();
        Ok(Self {
            x: FqVarEmulated::new_input(ark_relations::ns!(cs, "x"), || Ok(point.x))?,
            y: FqVarEmulated::new_input(ark_relations::ns!(cs, "y"), || Ok(point.y))?,
            z: FqVarEmulated::new_input(ark_relations::ns!(cs, "z"), || Ok(point.z))?,
        })
    }

    /// 分配 G1 点作为 witness。
    pub fn new_witness<T: Borrow<G1Projective>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let point = *f()?.borrow();
        Ok(Self {
            x: FqVarEmulated::new_witness(ark_relations::ns!(cs, "x"), || Ok(point.x))?,
            y: FqVarEmulated::new_witness(ark_relations::ns!(cs, "y"), || Ok(point.y))?,
            z: FqVarEmulated::new_witness(ark_relations::ns!(cs, "z"), || Ok(point.z))?,
        })
    }

    /// 强制等式约束：self == other（逐坐标比较）。
    pub fn enforce_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        self.x.enforce_equal(&other.x)?;
        self.y.enforce_equal(&other.y)?;
        self.z.enforce_equal(&other.z)?;
        Ok(())
    }

    /// Jacobian 坐标等式约束：self ~ other（交叉乘法，允许不同 Z）。
    ///
    /// ark-ec 的 `G1Projective` 使用 Jacobian 坐标（仿射 = X/Z² : Y/Z³），
    /// 故比较两个 Jacobian 点是否表示同一仿射点需验证：
    /// - X1·Z2² == X2·Z1²
    /// - Y1·Z2³ == Y2·Z1³
    ///
    /// 额外约束：~4 次 Fq 乘法 + 2 次 enforce_equal。
    pub fn enforce_equal_projective(&self, other: &Self) -> Result<(), SynthesisError> {
        let z1_sq = &self.z * &self.z;
        let z2_sq = &other.z * &other.z;
        let x1_z2_sq = &self.x * &z2_sq;
        let x2_z1_sq = &other.x * &z1_sq;
        x1_z2_sq.enforce_equal(&x2_z1_sq)?;
        let z1_cu = &z1_sq * &self.z;
        let z2_cu = &z2_sq * &other.z;
        let y1_z2_cu = &self.y * &z2_cu;
        let y2_z1_cu = &other.y * &z1_cu;
        y1_z2_cu.enforce_equal(&y2_z1_cu)?;
        Ok(())
    }

    /// 条件选择：cond ? true_value : false_value（逐坐标选择）。
    pub fn conditionally_select(
        cond: &Boolean<Fr>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            x: FqVarEmulated::conditionally_select(cond, &true_value.x, &false_value.x)?,
            y: FqVarEmulated::conditionally_select(cond, &true_value.y, &false_value.y)?,
            z: FqVarEmulated::conditionally_select(cond, &true_value.z, &false_value.z)?,
        })
    }
}

/// 倍点：2 * P（BN254 G1, a=0）。
///
/// 使用标准投影坐标倍点公式。正确处理无穷远点（Z=0 → Z'=0）。
fn point_double(p: &G1VarBN254) -> G1VarBN254 {
    // A = X^2
    let a = &p.x * &p.x;
    // B = Y^2
    let b = &p.y * &p.y;
    // C = B^2
    let c = &b * &b;
    // D = 2 * ((X + B)^2 - A - C)
    let x_plus_b = &p.x + &b;
    let x_plus_b_sq = &x_plus_b * &x_plus_b;
    let inner = &(&x_plus_b_sq - &a) - &c;
    let d = &inner + &inner;
    // E = 3 * A (a=0 for BN254)
    let two_a = &a + &a;
    let e = &two_a + &a;
    // F = E^2
    let f = &e * &e;
    // X3 = F - 2*D
    let two_d = &d + &d;
    let x3 = &f - &two_d;
    // Y3 = E * (D - X3) - 8*C
    let d_minus_x3 = &d - &x3;
    let two_c = &c + &c;
    let four_c = &two_c + &two_c;
    let eight_c = &four_c + &four_c;
    let y3 = &(&e * &d_minus_x3) - &eight_c;
    // Z3 = 2 * Y * Z
    let yz = &p.y * &p.z;
    let z3 = &yz + &yz;

    G1VarBN254 { x: x3, y: y3, z: z3 }
}

/// 不完全加法：P1 + P2（假设 P1 ≠ ±P2，均非无穷远点）。
///
/// 使用 EFD `add-2007-bl` Jacobian 坐标加法公式（a=0），匹配 ark-ec 0.6.0
/// 的 `SWProjective` 实现（内部使用 Jacobian 坐标，仿射 = X/Z² : Y/Z³）。
///
/// ark-ec 的 J = -H·I（负号），本实现用 J = H·I（正号），X3/Y3 公式中的
/// ±J 抵消，故 X3、Y3 结果与 ark-ec 一致。Z3 必须使用 Jacobian 公式
/// `2·Z1·Z2·H`（非标准投影的 `(Z1+Z2)² - Z1Z1 - Z2Z2`）。
///
/// 不处理 P1=P2（需倍点）或 P1=-P2（结果为无穷远点）。
/// 对随机 fold commitment，这些边界情况概率可忽略（2^-254）。
fn add_incomplete(a: &G1VarBN254, b: &G1VarBN254) -> G1VarBN254 {
    // Z1Z1 = Z1^2, Z2Z2 = Z2^2
    let z1z1 = &a.z * &a.z;
    let z2z2 = &b.z * &b.z;
    // U1 = X1*Z2Z2, U2 = X2*Z1Z1
    let u1 = &a.x * &z2z2;
    let u2 = &b.x * &z1z1;
    // S1 = Y1*Z2^3, S2 = Y2*Z1^3
    let z2_cu = &z2z2 * &b.z;
    let s1 = &a.y * &z2_cu;
    let z1_cu = &z1z1 * &a.z;
    let s2 = &b.y * &z1_cu;
    // H = U2-U1, HH = H^2, I = 4*HH, J = H*I
    let h = &u2 - &u1;
    let hh = &h * &h;
    let i = &hh + &hh + &hh + &hh;
    let j = &h * &i;
    // r = 2*(S2-S1), V = U1*I
    let s2_minus_s1 = &s2 - &s1;
    let r = &s2_minus_s1 + &s2_minus_s1;
    let v = &u1 * &i;
    // X3 = r^2 - J - 2*V
    let r_sq = &r * &r;
    let two_v = &v + &v;
    let x3 = &r_sq - &j - &two_v;
    // Y3 = r*(V-X3) - 2*S1*J
    let v_minus_x3 = &v - &x3;
    let r_v_minus_x3 = &r * &v_minus_x3;
    let s1_j = &s1 * &j;
    let two_s1_j = &s1_j + &s1_j;
    let y3 = &r_v_minus_x3 - &two_s1_j;
    // Z3 = 2 * Z1 * Z2 * H (Jacobian add-2007-bl)
    let z1_z2 = &a.z * &b.z;
    let two_z1_z2 = &z1_z2 + &z1_z2;
    let z3 = &two_z1_z2 * &h;

    G1VarBN254 { x: x3, y: y3, z: z3 }
}

/// 安全加法：P1 + P2（处理无穷远点）。
///
/// 若 P1 为无穷远点，返回 P2；若 P2 为无穷远点，返回 P1；否则返回不完全加法结果。
/// 不处理 P1=P2 的情况（概率可忽略）。
fn safe_add(a: &G1VarBN254, b: &G1VarBN254) -> Result<G1VarBN254, SynthesisError> {
    let added = add_incomplete(a, b);
    let zero_fq = FqVarEmulated::Constant(Fq::zero());
    let a_is_inf = a.z.is_eq(&zero_fq)?;
    let b_is_inf = b.z.is_eq(&zero_fq)?;
    // 若 a 为无穷远点，选择 b；否则选择 added
    let step1 = G1VarBN254::conditionally_select(&a_is_inf, b, &added)?;
    // 若 b 为无穷远点，选择 a；否则选择 step1
    let result = G1VarBN254::conditionally_select(&b_is_inf, a, &step1)?;
    Ok(result)
}

/// 安全倍点：2 * P（处理无穷远点）。
///
/// 若 P 为无穷远点（Z=0），返回标准无穷远点 (0, 1, 0)；
/// 否则返回 `point_double` 结果。
fn safe_double(p: &G1VarBN254) -> Result<G1VarBN254, SynthesisError> {
    let doubled = point_double(p);
    let zero = G1VarBN254::zero();
    let zero_fq = FqVarEmulated::Constant(Fq::zero());
    let p_is_inf = p.z.is_eq(&zero_fq)?;
    G1VarBN254::conditionally_select(&p_is_inf, &zero, &doubled)
}

/// 标量乘法：scalar * point（MSB-first double-and-add）。
///
/// 将标量分解为比特，从 MSB 到 LSB 逐步倍点和条件加法。
/// 使用 `safe_add` 处理累加器为无穷远点的情况。
pub fn scalar_mul_gadget_bn254(
    point: &G1VarBN254,
    scalar: &FrVar,
) -> Result<G1VarBN254, SynthesisError> {
    let bits = scalar.to_bits_le()?;
    if bits.is_empty() {
        return Ok(G1VarBN254::zero());
    }
    let zero_point = G1VarBN254::zero();
    // 初始化：MSB（LE 序列最后一个 bit）为 1 时从 point 开始，否则从 zero 开始
    let mut result = G1VarBN254::conditionally_select(
        bits.last().unwrap(),
        point,
        &zero_point,
    )?;
    // 处理剩余比特（MSB-1 到 LSB）
    for bit in bits.iter().rev().skip(1) {
        let doubled = safe_double(&result)?;
        let added = safe_add(&doubled, point)?;
        result = G1VarBN254::conditionally_select(bit, &added, &doubled)?;
    }
    Ok(result)
}

/// 点加法 gadget：result = a + b（安全加法，处理无穷远点）。
pub fn point_add_gadget_bn254(
    a: &G1VarBN254,
    b: &G1VarBN254,
) -> Result<G1VarBN254, SynthesisError> {
    safe_add(a, b)
}

/// fold commitment 等式验证 gadget：`C' == C_L + r * C_C`。
///
/// 计算 `C_L + r * C_C`，通过 `enforce_equal` 约束强制与 `C'` 相等。
/// 若等式不满足，约束系统 `is_satisfied()` 返回 false。
pub fn fold_commitment_check_bn254(
    c_prime: &G1VarBN254,
    c_l: &G1VarBN254,
    c_c: &G1VarBN254,
    r: &FrVar,
) -> Result<(), SynthesisError> {
    let r_c_c = scalar_mul_gadget_bn254(c_c, r)?;
    let expected = point_add_gadget_bn254(c_l, &r_c_c)?;
    c_prime.enforce_equal_projective(&expected)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AdditiveGroup, PrimeGroup};
    use ark_ff::One;
    use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::{test_rng, UniformRand};

    /// 辅助：在 CS<Fr> 中分配 G1 witness
    fn alloc_g1(cs: ConstraintSystemRef<Fr>, point: G1Projective) -> G1VarBN254 {
        G1VarBN254::new_witness(ark_relations::ns!(cs, "g1"), || Ok(point)).unwrap()
    }

    /// 辅助：在 CS<Fr> 中分配 Fr witness
    fn alloc_fr(cs: ConstraintSystemRef<Fr>, val: Fr) -> FrVar {
        FrVar::new_witness(ark_relations::ns!(cs, "scalar"), || Ok(val)).unwrap()
    }

    #[test]
    fn test_g1_scalar_mul_identity_bn254() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();
        let p = G1Projective::rand(&mut rng);
        let p_var = alloc_g1(cs.clone(), p);
        let zero_scalar = alloc_fr(cs.clone(), Fr::zero());
        let result = scalar_mul_gadget_bn254(&p_var, &zero_scalar).unwrap();
        let zero_point = G1VarBN254::zero();
        result.enforce_equal_projective(&zero_point).unwrap();
        assert!(cs.is_satisfied().unwrap(), "0 * P 应等于无穷远点");
    }

    #[test]
    fn test_g1_scalar_mul_generator_bn254() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = G1Projective::generator();
        let g_var = alloc_g1(cs.clone(), g);
        let one_scalar = alloc_fr(cs.clone(), Fr::one());
        let result = scalar_mul_gadget_bn254(&g_var, &one_scalar).unwrap();
        result.enforce_equal_projective(&g_var).unwrap();
        assert!(cs.is_satisfied().unwrap(), "1 * G 应等于 G");
    }

    #[test]
    fn test_g1_scalar_mul_small_bn254() {
        // 2 * G == G.double()
        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = G1Projective::generator();
        let g_var = alloc_g1(cs.clone(), g);
        let two_scalar = alloc_fr(cs.clone(), Fr::from(2u64));
        let result = scalar_mul_gadget_bn254(&g_var, &two_scalar).unwrap();
        let expected = g.double();
        let expected_var = alloc_g1(cs.clone(), expected);
        result.enforce_equal_projective(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap(), "2 * G 应等于 G.double()");
    }

    #[test]
    fn test_g1_point_add_bn254() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();
        let a = G1Projective::rand(&mut rng);
        let b = G1Projective::rand(&mut rng);
        let a_var = alloc_g1(cs.clone(), a);
        let b_var = alloc_g1(cs.clone(), b);

        let result = point_add_gadget_bn254(&a_var, &b_var).unwrap();
        let expected = a + b;

        let expected_var = alloc_g1(cs.clone(), expected);
        result.enforce_equal_projective(&expected_var).unwrap();
        if !cs.is_satisfied().unwrap() {
            let unsat = cs.which_is_unsatisfied().unwrap();
            panic!("a + b 约束不满足: {unsat:?}");
        }
    }

    #[test]
    fn test_fold_commitment_check_valid_bn254() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();
        let c_l = G1Projective::rand(&mut rng);
        let c_c = G1Projective::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let c_prime = c_l + c_c * r;
        let c_prime_var = alloc_g1(cs.clone(), c_prime);
        let c_l_var = alloc_g1(cs.clone(), c_l);
        let c_c_var = alloc_g1(cs.clone(), c_c);
        let r_var = alloc_fr(cs.clone(), r);
        fold_commitment_check_bn254(&c_prime_var, &c_l_var, &c_c_var, &r_var).unwrap();
        assert!(cs.is_satisfied().unwrap(), "合法 fold commitment 应满足约束");
    }

    #[test]
    fn test_fold_commitment_check_invalid_bn254() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();
        let c_l = G1Projective::rand(&mut rng);
        let c_c = G1Projective::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let wrong_c_prime = G1Projective::rand(&mut rng);
        let c_prime_var = alloc_g1(cs.clone(), wrong_c_prime);
        let c_l_var = alloc_g1(cs.clone(), c_l);
        let c_c_var = alloc_g1(cs.clone(), c_c);
        let r_var = alloc_fr(cs.clone(), r);
        fold_commitment_check_bn254(&c_prime_var, &c_l_var, &c_c_var, &r_var).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "错误 C' 应导致 CS 不满足"
        );
    }
}
