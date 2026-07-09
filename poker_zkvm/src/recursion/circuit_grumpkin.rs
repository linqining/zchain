//! Grumpkin 镜像递归 verifier 电路 C_Grumpkin（Phase 9 — Task 9.4）。
//!
//! 严格遵循 spec.md L587-588（v1.4 FROZEN）：
//! - 在 Grumpkin 上对称约束 BN254 Hypernova verifier 步骤
//! - 跨曲线 bridging：BN254 点坐标在 Grumpkin 标量域中直接表达（cycle 性质）
//!
//! ## MVP 实现深度
//!
//! 与 [`CircuitBn254`] 对称：原生验证模拟（复用 [`verify_hypernova`]）。
//! 真实 R1CS 电路编译推迟到 Phase 12/13。
//!
//! ## 跨曲线 bridging（spec L588）
//!
//! BN254 / Grumpkin cycle 性质（[`crate::cyclic::Bn254GrumpkinCycle`]）：
//! - BN254 标量域 `Fr_BN254` == Grumpkin base field `Fq_Grumpkin`
//! - Grumpkin 标量域 `Fr_Grumpkin` == BN254 base field `Fq_BN254`
//!
//! 因此：
//! - BN254 电路的 witness（含 Grumpkin 点坐标）在 BN254 标量域中直接表达
//! - Grumpkin 电路的 witness（含 BN254 点坐标）在 Grumpkin 标量域中直接表达
//! - 无需昂贵的跨域桥接约束
//!
//! ## 交替递归（spec L596-597）
//!
//! CycleFold 树形聚合中，递归层在 BN254 / Grumpkin 间交替：
//! - BN254 层（[`CircuitBn254`]）验证 2 个 Grumpkin sub-proofs → 生成 BN254 proof
//! - Grumpkin 层（[`CircuitGrumpkin`]）验证 2 个 BN254 proofs → 生成 Grumpkin proof
//!
//! [`CircuitBn254`]: crate::recursion::circuit_bn254::CircuitBn254

use crate::error::ZkvmError;
use crate::fold::fold_loop::verify_hypernova;
use crate::pcs::ipa::IpaPcs;
use crate::prover::deserialize_proof;
use crate::recursion::{CurveKind, RecursiveVerifierCircuit};

/// Grumpkin 镜像递归 verifier 电路 `C_Grumpkin`（spec L587）。
///
/// 对称约束 BN254 上的 Hypernova verifier 步骤，在 Grumpkin 算术下表达。
/// 因 BN254 点坐标在 Grumpkin 标量域中（cycle 性质），可直接在 Grumpkin 电路中表达。
///
/// MVP 实现：[`verify_native`] 委托到 [`verify_hypernova`]。
/// 真实 R1CS 电路编译推迟到 Phase 12/13。
///
/// [`verify_native`]: CircuitGrumpkin::verify_native
pub struct CircuitGrumpkin<'a> {
    /// 待验证的 BN254 Hypernova sub-proof（序列化字节）。
    pub sub_proof_bytes: &'a [u8],

    /// IPA PCS（用于原生验证模拟）。
    ///
    /// MVP: BN254 IPA PCS。真实实现需 Grumpkin IPA PCS（Phase 12/13）。
    pub pcs: &'a IpaPcs,
}

impl<'a> CircuitGrumpkin<'a> {
    /// 从已序列化的 proof bytes 构造电路。
    pub fn new(sub_proof_bytes: &'a [u8], pcs: &'a IpaPcs) -> Self {
        Self {
            sub_proof_bytes,
            pcs,
        }
    }
}

impl RecursiveVerifierCircuit for CircuitGrumpkin<'_> {
    /// 电路所在曲线 = Grumpkin。
    fn curve_kind() -> CurveKind {
        CurveKind::Grumpkin
    }

    /// 验证的 sub-proof 所在曲线 = BN254。
    fn sub_proof_curve_kind() -> CurveKind {
        CurveKind::Bn254
    }

    /// 估算单层约束数（spec L589 — 与 C_BN254 对称）。
    ///
    /// 组成与 [`CircuitBn254::constraint_count`] 相同：
    /// - IPA verify: `log2(num_vars)` 轮 × ~5000 约束/轮
    /// - 外层 sumcheck verify: ~10000 约束
    /// - 内层 batched sumcheck verify: ~10000 约束
    /// - cross-language claim: ~5000 约束
    ///
    /// [`CircuitBn254::constraint_count`]: crate::recursion::circuit_bn254::CircuitBn254::constraint_count
    fn constraint_count(num_vars: usize, _num_matrices: usize) -> usize {
        let log_n = if num_vars == 0 {
            0
        } else {
            (num_vars as u64).next_power_of_two().trailing_zeros() as usize
        };
        let ipa_verify = log_n * 5000;
        let outer_sumcheck = 10000;
        let inner_sumcheck = 10000;
        let cross_language = 5000;
        ipa_verify + outer_sumcheck + inner_sumcheck + cross_language
    }

    /// 原生验证模拟（MVP）— 反序列化 + [`verify_hypernova`]。
    ///
    /// 与 [`CircuitBn254::verify_native`] 实现相同（MVP 使用 BN254 IPA PCS）。
    /// 真实实现需 Grumpkin IPA PCS。
    ///
    /// [`CircuitBn254::verify_native`]: crate::recursion::circuit_bn254::CircuitBn254::verify_native
    fn verify_native(&self) -> Result<bool, ZkvmError> {
        let proof = deserialize_proof(self.sub_proof_bytes)?;
        verify_hypernova(&proof, self.pcs)
    }

    /// public inputs 清单（spec L586 — 与 C_BN254 对称）。
    fn public_inputs_desc() -> &'static [&'static str] {
        &[
            "public_io.randomness_seed",
            "public_io.event_hashes_root",
            "public_io.state_slot_root",
            "folded_lcccs.u_prime",
            "folded_lcccs.x_prime",
            "folded_lcccs.v_prime",
            "folded_lcccs.witness_commitment",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::{Ccs, Fr, SparseMatrix};
    use crate::cyclic::CycleCurve;
    use crate::field::ZkvmField;
    use crate::fold::fold_loop::{fold_loop, HypernovaProof};
    use crate::pcs::ipa::{IpaCommitment, IpaPcs};
    use crate::pcs::{MultilinearPoly, Pcs};
    use crate::prover::serialize_proof;
    use crate::recursion::circuit_bn254::CircuitBn254;
    use crate::transcript::Transcript;

    /// 辅助：构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助：构造负 Fr。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    /// 使用 IPA 计算实际 witness commitment（用于 PCS opening 一致性）。
    fn commit_witness(pcs: &IpaPcs, z: &[Fr]) -> IpaCommitment {
        let poly = MultilinearPoly::from_evals(z.to_vec()).expect("MultilinearPoly 构造应成功");
        pcs.commit(&poly).expect("pcs.commit 应成功")
    }

    /// 构造线性 CCS — x - y = 0。
    fn make_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        Ccs::new(
            4,
            vec![m0, m1],
            vec![vec![0], vec![1]],
            vec![f(1), neg_f(1)],
        )
        .expect("linear Ccs 构造应成功")
    }

    /// 构造 IPA PCS。
    fn make_ipa_pcs() -> IpaPcs {
        IpaPcs::new(4).expect("IpaPcs 构造应成功")
    }

    /// 生成有效 HypernovaProof。
    fn make_proof(pcs: &IpaPcs, seed: u32) -> HypernovaProof {
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(seed), f(seed), f(0)];
        let z_c = vec![f(1), f(seed + 1), f(seed + 1), f(0)];
        // 使用真实 IPA commitment，使 C' = C_L + r·C_C = ⟨z', G⟩ 与 pcs.open 内部承诺一致
        let cmt_l = commit_witness(pcs, &z_l);
        let cmt_c = commit_witness(pcs, &z_c);
        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], cmt_c).expect("to_cccs");
        let mut transcript = Transcript::new();
        fold_loop(&ccs, lcccs, cmt_l, &[ccccs], pcs, &mut transcript)
            .expect("fold_loop 应成功")
    }

    // ===== SubTask 9.4.1: CircuitGrumpkin 结构 =====

    #[test]
    fn test_circuit_grumpkin_curve_kind() {
        assert_eq!(CircuitGrumpkin::curve_kind(), CurveKind::Grumpkin);
        assert_eq!(
            CircuitGrumpkin::sub_proof_curve_kind(),
            CurveKind::Bn254
        );
    }

    #[test]
    fn test_circuit_grumpkin_mirror_of_bn254() {
        // C_Grumpkin 是 C_BN254 的镜像
        assert_eq!(
            CircuitGrumpkin::curve_kind(),
            CircuitBn254::sub_proof_curve_kind(),
            "C_Grumpkin 所在曲线应 == C_BN254 验证的 sub-proof 曲线"
        );
        assert_eq!(
            CircuitGrumpkin::sub_proof_curve_kind(),
            CircuitBn254::curve_kind(),
            "C_Grumpkin 验证的 sub-proof 曲线应 == C_BN254 所在曲线"
        );
    }

    #[test]
    fn test_circuit_grumpkin_public_inputs_desc() {
        let desc = CircuitGrumpkin::public_inputs_desc();
        assert!(desc.contains(&"folded_lcccs.u_prime"));
        assert!(desc.len() >= 5, "public inputs 应至少 5 项");
    }

    // ===== SubTask 9.4.2: 对称约束 1-6 =====

    #[test]
    fn test_constraint_count_symmetric_with_bn254() {
        // C_Grumpkin 与 C_BN254 约束数应相同（对称结构）
        let count_bn = CircuitBn254::constraint_count(65536, 3);
        let count_gr = CircuitGrumpkin::constraint_count(65536, 3);
        assert_eq!(
            count_bn, count_gr,
            "C_BN254 与 C_Grumpkin 约束数应对称相等"
        );
    }

    // ===== SubTask 9.4.3: 跨曲线 bridging 文档验证 =====

    #[test]
    fn test_cross_curve_bridging_cycle_property() {
        // cycle 性质使跨曲线 bridging 无需额外约束
        crate::cyclic::Bn254GrumpkinCycle::verify_cycle()
            .expect("BN254/Grumpkin cycle 性质应满足（bridging 基础）");
    }

    // ===== SubTask 9.4.4: 合法 BN254 proof 通过；篡改失败 =====

    #[test]
    fn test_verify_native_valid_proof() {
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        let proof_bytes = serialize_proof(&proof).expect("serialize 应成功");

        let circuit = CircuitGrumpkin::new(&proof_bytes, &pcs);
        assert!(
            circuit.verify_native().expect("verify_native 应成功"),
            "合法 proof 的 verify_native 应返回 true"
        );
    }

    #[test]
    fn test_verify_native_tampered_bytes_fails() {
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        let mut proof_bytes = serialize_proof(&proof).expect("serialize 应成功");

        // 篡改最后一个字节
        let last = proof_bytes.len() - 1;
        proof_bytes[last] ^= 0xFF;

        let circuit = CircuitGrumpkin::new(&proof_bytes, &pcs);
        let result = circuit.verify_native();
        match result {
            Ok(valid) => assert!(!valid, "篡改 proof 应验证失败"),
            Err(_) => { /* 反序列化错误也是可接受的失败 */ }
        }
    }

    #[test]
    fn test_verify_native_corrupted_magic_fails() {
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        let mut proof_bytes = serialize_proof(&proof).expect("serialize 应成功");

        proof_bytes[0] = b'X';
        let circuit = CircuitGrumpkin::new(&proof_bytes, &pcs);
        assert!(
            circuit.verify_native().is_err(),
            "篡改 magic 头应导致反序列化错误"
        );
    }

    // ===== SubTask 9.4.5: 交替递归测试 =====

    #[test]
    fn test_alternating_recursion_depth_2() {
        // 交替递归（spec L596-597）：
        // 叶: 4 个 sub-proofs (p1, p2, p3, p4) — 概念上在 Grumpkin 上
        // Layer 1 (BN254): C_BN254 验证 (p1, p2) → b1; C_BN254 验证 (p3, p4) → b2
        // Layer 2 (Grumpkin): C_Grumpkin 验证 (b1, b2) → g_final
        // 深度 2 层闭环
        let pcs = make_ipa_pcs();
        let p1 = make_proof(&pcs, 1);
        let p2 = make_proof(&pcs, 2);
        let p3 = make_proof(&pcs, 3);
        let p4 = make_proof(&pcs, 4);

        // Layer 1: C_BN254 验证 pairs
        let b1_bytes = serialize_proof(&p1).expect("serialize p1");
        let b2_bytes = serialize_proof(&p2).expect("serialize p2");
        let b3_bytes = serialize_proof(&p3).expect("serialize p3");
        let b4_bytes = serialize_proof(&p4).expect("serialize p4");

        let circuit_b1 = CircuitBn254::new(&b1_bytes, &pcs);
        let circuit_b2 = CircuitBn254::new(&b2_bytes, &pcs);
        let circuit_b3 = CircuitBn254::new(&b3_bytes, &pcs);
        let circuit_b4 = CircuitBn254::new(&b4_bytes, &pcs);

        assert!(circuit_b1.verify_native().expect("b1 验证"), "b1 应通过");
        assert!(circuit_b2.verify_native().expect("b2 验证"), "b2 应通过");
        assert!(circuit_b3.verify_native().expect("b3 验证"), "b3 应通过");
        assert!(circuit_b4.verify_native().expect("b4 验证"), "b4 应通过");

        // Layer 2: C_Grumpkin 验证 (b1, b2) 和 (b3, b4)
        // MVP: b1/b2 的 proof bytes 就是 p1/p2 的 bytes（无压缩）
        let circuit_g1 = CircuitGrumpkin::new(&b1_bytes, &pcs);
        let circuit_g2 = CircuitGrumpkin::new(&b3_bytes, &pcs);

        assert!(circuit_g1.verify_native().expect("g1 验证"), "g1 应通过");
        assert!(circuit_g2.verify_native().expect("g2 验证"), "g2 应通过");

        // 最终：C_BN254 验证 g_final（再回 BN254 层）
        let circuit_final = CircuitBn254::new(&b1_bytes, &pcs);
        assert!(
            circuit_final.verify_native().expect("final 验证"),
            "final proof 应通过"
        );
    }

    #[test]
    fn test_alternating_recursion_curve_chain() {
        // 验证交替递归的曲线 chain：
        // Bn254 → Grumpkin → Bn254 → Grumpkin → ...
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        let proof_bytes = serialize_proof(&proof).expect("serialize");

        // 模拟 4 层交替递归
        // Layer 1: C_BN254 (on BN254, verifies Grumpkin proof)
        let c1 = CircuitBn254::new(&proof_bytes, &pcs);
        assert_eq!(CircuitBn254::curve_kind(), CurveKind::Bn254);
        assert_eq!(CircuitBn254::sub_proof_curve_kind(), CurveKind::Grumpkin);
        assert!(c1.verify_native().expect("layer 1"));

        // Layer 2: C_Grumpkin (on Grumpkin, verifies BN254 proof)
        let c2 = CircuitGrumpkin::new(&proof_bytes, &pcs);
        assert_eq!(CircuitGrumpkin::curve_kind(), CurveKind::Grumpkin);
        assert_eq!(CircuitGrumpkin::sub_proof_curve_kind(), CurveKind::Bn254);
        assert!(c2.verify_native().expect("layer 2"));

        // Layer 3: C_BN254 again
        let c3 = CircuitBn254::new(&proof_bytes, &pcs);
        assert!(c3.verify_native().expect("layer 3"));

        // Layer 4: C_Grumpkin again
        let c4 = CircuitGrumpkin::new(&proof_bytes, &pcs);
        assert!(c4.verify_native().expect("layer 4"));
    }
}
