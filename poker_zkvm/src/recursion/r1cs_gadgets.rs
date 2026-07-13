//! R1CS gadget 库（Phase C — Step C2）。
//!
//! 提供 BN254 G1 点运算 gadget，供 Phase D HypernovaVerifierCircuit 使用。
//! 基于 `ark-r1cs-std` 的 `CurveVar` / `ProjectiveVar` 抽象。
//!
//! ## 字段说明
//!
//! BN254 G1 点坐标 ∈ Fq（base field）。
//! 本模块的 gadget 在 `ConstraintSystem<Fq>` 中工作。
//!
//! 标量乘法使用 `EmulatedFpVar<Fr, Fq>` — 在 Fq-based CS 中模拟 Fr 标量。
//! 这是 cycle-of-curves 的必然结果：
//! - BN254 G1 坐标 ∈ Fq → gadget 需 Fq-based CS
//! - BN254 标量 ∈ Fr → 需 `EmulatedFpVar` 在 Fq CS 中表示 Fr 元素
//!
//! Phase D 的 Grumpkin Groth16 电路（scalar field = Fq）将使用这些 gadget
//! 原生验证 BN254 G1 commitment 等式。

use ark_bn254::{Fq, Fr, constraints::GVar as Bn254G1Var};
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::SynthesisError;

/// BN254 G1 的 R1CS gadget 类型别名。
///
/// `GVar = ProjectiveVar<Config, FpVar<Fq>>`，在 `ConstraintSystem<Fq>` 中工作。
pub type G1Var = Bn254G1Var;

/// Fq 变量类型别名（base field variable）。
pub type FqVar = FpVar<Fq>;

/// Fr 的模拟变量类型别名（在 Fq-based CS 中表示 Fr 标量）。
///
/// 用于标量乘法：`G1Var * ScalarVar`。
/// 非原生域算术，比 Fq 原生运算开销大，但保证了 BN254 标量域的正确性。
pub type ScalarVar = EmulatedFpVar<Fr, Fq>;

/// 点加法 gadget：`result = a + b`
///
/// 使用 `ProjectiveVar` 的 `+` 运算符（ark-r1cs-std 实现的完整加法公式）。
pub fn point_add_gadget(a: &G1Var, b: &G1Var) -> Result<G1Var, SynthesisError> {
    Ok(a + b)
}

/// 标量乘法 gadget：`result = scalar * point`
///
/// 使用 `CurveVar` 的 `Mul<EmulatedFpVar<Fr, Fq>>` 实现。
/// 用于 fold commitment `C' = C_L + r·C_C` 中的 `r·C_C`。
///
/// 标量类型为 `ScalarVar`（= `EmulatedFpVar<Fr, Fq>`），
/// 在 Fq-based CS 中模拟 Fr 标量。
pub fn scalar_mul_gadget(point: &G1Var, scalar: &ScalarVar) -> Result<G1Var, SynthesisError> {
    Ok(point.clone() * scalar)
}

/// MSM gadget：`result = sum_i(scalars[i] * points[i])`
///
/// 用于 IPA `G_final` 计算（Phase D）。
/// 循环调用标量乘法 + 点加法。
///
/// # 约束数估算
/// 每点标量乘法 ~2500 约束（EmulatedFpVar 开销），
/// N=512 点时约 1.3M 约束。
pub fn msm_gadget(points: &[G1Var], scalars: &[ScalarVar]) -> Result<G1Var, SynthesisError> {
    assert_eq!(
        points.len(),
        scalars.len(),
        "MSM: points 和 scalars 长度不匹配"
    );
    let mut acc = G1Var::zero();
    for (p, s) in points.iter().zip(scalars.iter()) {
        let term = scalar_mul_gadget(p, s)?;
        acc = point_add_gadget(&acc, &term)?;
    }
    Ok(acc)
}

/// fold commitment 等式验证 gadget：`C' == C_L + r * C_C`
///
/// 通过 `enforce_equal` 约束强制等式成立。
/// 若等式不满足，约束系统 `is_satisfied()` 返回 false。
///
/// # 参数
/// - `c_prime` — fold 后的 commitment（C'）
/// - `c_l` — LCCCS 的 commitment（C_L）
/// - `c_c` — CCCCS 的 commitment（C_C）
/// - `r` — fold challenge（标量，Fr 值在 Fq CS 中模拟）
pub fn fold_commitment_check(
    c_prime: &G1Var,
    c_l: &G1Var,
    c_c: &G1Var,
    r: &ScalarVar,
) -> Result<(), SynthesisError> {
    let r_c_c = scalar_mul_gadget(c_c, r)?;
    let expected = point_add_gadget(c_l, &r_c_c)?;
    c_prime.enforce_equal(&expected)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective;
    use ark_ec::PrimeGroup;
    use ark_ff::{One, Zero};
    use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_std::{UniformRand, test_rng};

    /// 辅助：在 CS<Fq> 中分配 G1 witness
    fn alloc_g1(cs: ConstraintSystemRef<Fq>, point: G1Projective) -> G1Var {
        G1Var::new_witness(ark_relations::ns!(cs, "g1"), || Ok(point)).unwrap()
    }

    /// 辅助：在 CS<Fq> 中分配 Scalar (Fr) witness 作为 EmulatedFpVar
    fn alloc_scalar(cs: ConstraintSystemRef<Fq>, val: Fr) -> ScalarVar {
        ScalarVar::new_witness(ark_relations::ns!(cs, "scalar"), || Ok(val)).unwrap()
    }

    #[test]
    fn test_g1_scalar_mul_identity() {
        // 0 * P = O（无穷远点）
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let p = G1Projective::rand(&mut rng);
        let p_var = alloc_g1(cs.clone(), p);
        let zero_scalar = alloc_scalar(cs.clone(), Fr::zero());
        let result = scalar_mul_gadget(&p_var, &zero_scalar).unwrap();
        let zero_point = G1Var::zero();
        result.enforce_equal(&zero_point).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_g1_scalar_mul_generator() {
        // 1 * G = G
        let cs = ConstraintSystem::<Fq>::new_ref();
        let g = G1Projective::generator();
        let g_var = alloc_g1(cs.clone(), g);
        let one_scalar = alloc_scalar(cs.clone(), Fr::one());
        let result = scalar_mul_gadget(&g_var, &one_scalar).unwrap();
        result.enforce_equal(&g_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_g1_point_add_commutative() {
        // P + Q == Q + P
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let p = G1Projective::rand(&mut rng);
        let q = G1Projective::rand(&mut rng);
        let p_var = alloc_g1(cs.clone(), p);
        let q_var = alloc_g1(cs.clone(), q);
        let pq = point_add_gadget(&p_var, &q_var).unwrap();
        let qp = point_add_gadget(&q_var, &p_var).unwrap();
        pq.enforce_equal(&qp).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_msm_two_elements() {
        // a*P + b*Q 与原生计算一致
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let p = G1Projective::rand(&mut rng);
        let q = G1Projective::rand(&mut rng);
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        // 原生计算：G1Projective * Fr（标量乘法）
        let expected = p * a + q * b;
        let p_var = alloc_g1(cs.clone(), p);
        let q_var = alloc_g1(cs.clone(), q);
        let a_var = alloc_scalar(cs.clone(), a);
        let b_var = alloc_scalar(cs.clone(), b);
        let msm_result = msm_gadget(&[p_var, q_var], &[a_var, b_var]).unwrap();
        let expected_var = alloc_g1(cs.clone(), expected);
        msm_result.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_fold_commitment_check_valid() {
        // 正确 C' = C_L + r * C_C → CS satisfied
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let c_l = G1Projective::rand(&mut rng);
        let c_c = G1Projective::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let c_prime = c_l + c_c * r;
        let c_prime_var = alloc_g1(cs.clone(), c_prime);
        let c_l_var = alloc_g1(cs.clone(), c_l);
        let c_c_var = alloc_g1(cs.clone(), c_c);
        let r_var = alloc_scalar(cs.clone(), r);
        fold_commitment_check(&c_prime_var, &c_l_var, &c_c_var, &r_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_fold_commitment_check_invalid() {
        // 错误 C' → CS not satisfied
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let c_l = G1Projective::rand(&mut rng);
        let c_c = G1Projective::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let wrong_c_prime = G1Projective::rand(&mut rng);
        let c_prime_var = alloc_g1(cs.clone(), wrong_c_prime);
        let c_l_var = alloc_g1(cs.clone(), c_l);
        let c_c_var = alloc_g1(cs.clone(), c_c);
        let r_var = alloc_scalar(cs.clone(), r);
        fold_commitment_check(&c_prime_var, &c_l_var, &c_c_var, &r_var).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "错误 C' 应导致 CS 不满足");
    }
}
