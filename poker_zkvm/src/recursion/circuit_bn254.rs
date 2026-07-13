//! BN254 递归 verifier 电路 C_BN254（Phase 9 — Task 9.3）。
//!
//! 严格遵循 spec.md L575-590（v1.4 FROZEN）：
//! - 在 BN254 上约束 Grumpkin Hypernova proof `π_G` 的 verifier 步骤
//! - 6 条约束覆盖反序列化 / PCS verify / 外层 sumcheck / 内层 batched sumcheck /
//!   cross-language claim / transcript 一致性
//!
//! ## MVP 实现深度
//!
//! spec L590 明确将"递归电路本身的 SNARK 证明"推迟到 Phase 12/13。
//! Phase 9 采用原生验证模拟（复用 [`verify_hypernova`]）：
//! - 电路结构 + trait + 6 条约束文档化
//! - `verify_native` 委托到 [`verify_hypernova`]
//! - 约束数估算 100k-200k（spec L589）
//!
//! ## 6 条约束（spec L580-585）
//!
//! | # | 约束                          | spec  | MVP 原生验证对应                              |
//! |---|-------------------------------|-------|-----------------------------------------------|
//! | 1 | 反序列化 `π_G`                | L580  | [`deserialize_proof`] + magic/version 校验    |
//! | 2 | PCS verify (IPA on Grumpkin) | L581  | `pcs.verify(commitment, r_y, z, opening)`     |
//! | 3 | 外层 sumcheck (claimed = u')  | L582  | `sumcheck::verify(..., u_l, ...)`             |
//! | 4 | 内层 batched sumcheck (单 r_y)| L583  | `sumcheck::verify` 内部含内层 batched         |
//! | 5 | cross-language claim (r_y)    | L584  | PCS opening + z_at_point 一致性               |
//! | 6 | transcript 一致性             | L585  | fresh transcript 重算 challenge               |

use crate::error::ZkvmError;
#[allow(deprecated)]
use crate::fold::fold_loop::verify_hypernova;
use crate::pcs::ipa::IpaPcs;
use crate::prover::deserialize_proof;
use crate::recursion::{CurveKind, RecursiveVerifierCircuit};

/// BN254 递归 verifier 电路 `C_BN254`（spec L575-590）。
///
/// 约束一个 Grumpkin 上的 Hypernova proof `π_G` 的 verifier 步骤，
/// 在 BN254 算术下表达。因 Grumpkin 点坐标在 BN254 标量域中
/// （cycle 性质 — [`crate::cyclic::Bn254GrumpkinCycle`]），可直接在 BN254 电路中表达。
///
/// MVP 实现：[`verify_native`] 委托到 [`verify_hypernova`]。
/// 真实 R1CS 电路编译推迟到 Phase 12/13。
///
/// [`verify_native`]: CircuitBn254::verify_native
pub struct CircuitBn254<'a> {
    /// 待验证的 Grumpkin Hypernova sub-proof（序列化字节）。
    pub sub_proof_bytes: &'a [u8],

    /// IPA PCS（用于原生验证模拟）。
    ///
    /// MVP: BN254 IPA PCS。真实实现需 Grumpkin IPA PCS（Phase 12/13）。
    pub pcs: &'a IpaPcs,
}

impl<'a> CircuitBn254<'a> {
    /// 从已序列化的 proof bytes 构造电路。
    pub fn new(sub_proof_bytes: &'a [u8], pcs: &'a IpaPcs) -> Self {
        Self {
            sub_proof_bytes,
            pcs,
        }
    }
}

impl RecursiveVerifierCircuit for CircuitBn254<'_> {
    /// 电路所在曲线 = BN254。
    fn curve_kind() -> CurveKind {
        CurveKind::Bn254
    }

    /// 验证的 sub-proof 所在曲线 = Grumpkin。
    fn sub_proof_curve_kind() -> CurveKind {
        CurveKind::Grumpkin
    }

    /// 估算单层约束数（spec L589）。
    ///
    /// 组成：
    /// - IPA verify: `log2(num_vars)` 轮 × ~5000 约束/轮
    /// - 外层 sumcheck verify: ~10000 约束
    /// - 内层 batched sumcheck verify: ~10000 约束
    /// - cross-language claim: ~5000 约束
    ///
    /// 典型值：num_vars = 2^16 → log_n = 16 → 80000 + 25000 = 105000
    /// 范围：100,000-200,000 约束/单递归层
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
    /// 对应 6 条约束的原生验证：
    ///
    /// - 约束 1: `deserialize_proof` — 反序列化 + magic/version/field_id 校验
    /// - 约束 2-6: `verify_hypernova` — PCS verify + 外层 sumcheck + 内层 batched
    ///   + cross-language claim + transcript 一致性
    fn verify_native(&self) -> Result<bool, ZkvmError> {
        let proof = deserialize_proof(self.sub_proof_bytes)?;
        #[allow(deprecated)]
        verify_hypernova(&proof, self.pcs)
    }

    /// public inputs 清单（spec L586）。
    ///
    /// `π_G` 的 public_io + folded LCCCS 的 u'/x'/v' + witness_commitment'。
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
    use crate::field::ZkvmField;
    use crate::fold::fold_loop::{HypernovaProof, fold_loop};
    use crate::pcs::ipa::{IpaCommitment, IpaPcs};
    use crate::pcs::{MultilinearPoly, Pcs};
    use crate::prover::serialize_proof;
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
        fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &[ccccs],
            pcs,
            &mut transcript,
            ccs.ccs_commitment(),
            [0u8; 32],
            vec![vec![]],
        )
        .expect("fold_loop 应成功")
    }

    // ===== SubTask 9.3.1: CircuitBn254 结构 + public inputs =====

    #[test]
    fn test_circuit_bn254_curve_kind() {
        assert_eq!(CircuitBn254::curve_kind(), CurveKind::Bn254);
        assert_eq!(CircuitBn254::sub_proof_curve_kind(), CurveKind::Grumpkin);
    }

    #[test]
    fn test_circuit_bn254_public_inputs_desc() {
        let desc = CircuitBn254::public_inputs_desc();
        assert!(desc.contains(&"folded_lcccs.u_prime"));
        assert!(desc.contains(&"folded_lcccs.witness_commitment"));
        assert!(desc.len() >= 5, "public inputs 应至少 5 项");
    }

    // ===== SubTask 9.3.8: 约束数估算 =====

    #[test]
    fn test_constraint_count_in_range() {
        // num_vars = 2^4 = 16 → log_n = 4 → 20000 + 25000 = 45000
        let count = CircuitBn254::constraint_count(16, 2);
        assert!(count >= 40000, "约束数应 ≥ 40000，实际 {count}");

        // num_vars = 2^16 = 65536 → log_n = 16 → 80000 + 25000 = 105000
        let count_large = CircuitBn254::constraint_count(65536, 3);
        assert!(
            (100000..=200000).contains(&count_large),
            "约束数应在 100k-200k 范围，实际 {count_large}"
        );
    }

    #[test]
    fn test_constraint_count_grows_with_log() {
        let small = CircuitBn254::constraint_count(16, 2);
        let large = CircuitBn254::constraint_count(1024, 2);
        assert!(
            large > small,
            "更大 num_vars 应有更多约束：{large} > {small}"
        );
    }

    // ===== SubTask 9.3.9: 合法 proof 通过；篡改失败 =====

    #[test]
    fn test_verify_native_valid_proof() {
        let pcs = make_ipa_pcs();
        let proof = make_proof(&pcs, 1);
        let proof_bytes = serialize_proof(&proof).expect("serialize 应成功");

        let circuit = CircuitBn254::new(&proof_bytes, &pcs);
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

        // 篡改最后一个字节（z_at_point 的一部分）
        let last = proof_bytes.len() - 1;
        proof_bytes[last] ^= 0xFF;

        let circuit = CircuitBn254::new(&proof_bytes, &pcs);
        let result = circuit.verify_native();
        // 篡改应导致验证失败（反序列化错误或 verify_hypernova 返回 false）
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

        // 篡改 magic 头
        proof_bytes[0] = b'X';

        let circuit = CircuitBn254::new(&proof_bytes, &pcs);
        assert!(
            circuit.verify_native().is_err(),
            "篡改 magic 头应导致反序列化错误"
        );
    }

    #[test]
    fn test_verify_native_empty_bytes_fails() {
        let pcs = make_ipa_pcs();
        let circuit = CircuitBn254::new(&[], &pcs);
        assert!(circuit.verify_native().is_err(), "空 bytes 应返回错误");
    }

    #[test]
    fn test_verify_native_multiple_valid_proofs() {
        let pcs = make_ipa_pcs();
        for seed in 1..=4 {
            let proof = make_proof(&pcs, seed);
            let proof_bytes = serialize_proof(&proof).expect("serialize 应成功");
            let circuit = CircuitBn254::new(&proof_bytes, &pcs);
            assert!(
                circuit.verify_native().expect("verify_native 应成功"),
                "proof seed={seed} 应验证通过"
            );
        }
    }
}
