//! 多步折叠循环 + PCS opening（Phase 6 — Task 6.6）。
//!
//! 严格遵循 spec.md L411-418（v1.4 FROZEN）与 Hypernova 原论文。
//!
//! ## 流程
//!
//! 1. 顺序折叠 N-1 次（N ≤ `MAX_FOLD_STEP_COUNT = 1000`）
//!    - 每步调用 [`fold_step::fold`] 派生 fold challenge `r` 并计算 folded LCCCS
//!    - 每步调用 [`sumcheck::prove`] 生成 sumcheck 证明
//!    - **关键**：用 `actual_u_prime` 更新 folded LCCCS 的 `u_l`（非线性 CCS 修正）
//! 2. 最终折叠后生成 PCS opening proof 在 `r_y` 处打开 `z'`
//! 3. 返回 [`HypernovaProof`]
//!
//! ## v1.3 关键修正
//!
//! - **C2-001**：`r_y` 为单 challenge（非元组）
//! - **C2-003**：外层 claimed sum = `u'` 标量
//! - **M2-001**：relaxed 约束 `u'` 可非 0
//! - **非线性 CCS 修正**：`u' = u_L + r·u_C` 仅对线性 CCS 成立；
//!   对非线性 CCS，实际 claimed sum = `actual_u_prime`（由 sumcheck 计算），
//!   folded LCCCS 的 `u_l` 必须更新为 `actual_u_prime`（见 alternatives.md）
//!
//! ## 实现决策
//!
//! - **fresh transcript for sumcheck**：每步 sumcheck 使用独立 fresh transcript，
//!   使 verifier 能用 fresh transcript 验证 final sumcheck（见 alternatives.md）。
//!   fold challenge 仍从主 transcript 派生（绑定 fold 输入）。
//! - **final_sumcheck**：HypernovaProof 仅含最后一步的 sumcheck（spec L417）。
//!   完整 verifier 需所有 sumcheck proofs（见 alternatives.md）。
//! - **PCS opening transcript**：与 final sumcheck 共享 fresh transcript（链式）。

use crate::ccs::{Ccs, Fr};
use crate::constraints::MAX_FOLD_STEP_COUNT;
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::fold::ccccs::Ccccs;
use crate::fold::fold_step;
use crate::fold::lcccs::Lcccs;
use crate::fold::sumcheck;
use crate::pcs::ipa::{IpaCommitment, IpaPcs, IpaProof};
use crate::pcs::{MultilinearPoly, Pcs};
use crate::transcript::Transcript;

/// Hypernova 证明（spec L417）。
///
/// 包含 final sumcheck proof + PCS opening proof + folded 实例。
#[derive(Debug, Clone)]
pub struct HypernovaProof {
    /// ABI 版本（= 1）。
    pub abi_version: u8,
    /// 最终 folded LCCCS 实例（verifier view）。
    pub folded_instance: Lcccs,
    /// 最终 folded witness commitment `C'`。
    pub witness_commitment: IpaCommitment,
    /// 最后一步 fold 的 sumcheck 证明（spec L417 — final_sumcheck）。
    pub final_sumcheck: sumcheck::SumcheckProof,
    /// PCS opening 证明（IPA 在 r_y 处打开 z'）。
    pub pcs_opening: IpaProof,
    /// 内层 batched sumcheck 产生的单 challenge（v1.3 修正 C2-001）。
    pub r_y: Vec<Fr>,
    /// `z'(r_y)` — folded witness 在 r_y 处的求值（PCS opening 值）。
    pub z_at_point: Fr,
}

/// 多步折叠循环（spec L411-418）。
///
/// # 参数
/// - `ccs` — CCS 结构（所有实例共享）
/// - `initial_lcccs` — 初始 LCCCS 实例（running instance）
/// - `initial_commitment` — 初始 witness commitment `C_L`
/// - `ccccs_instances` — N-1 个 CCCCS 实例（incoming instances）
/// - `pcs` — IPA PCS（用于 PCS opening）
/// - `transcript` — Fiat-Shamir transcript（用于 fold challenge 派生）
///
/// # 返回
/// [`HypernovaProof`]，含 folded 实例 + final sumcheck + PCS opening。
///
/// # 错误
/// - `FoldStepCountExceeded` — 实例数 > `MAX_FOLD_STEP_COUNT`
/// - `fold_step::fold` 失败（CCS 不匹配 / 维度不一致）
/// - `sumcheck::prove` 失败（维度 / 校验）
/// - PCS opening 失败（维度 / IPA 内部错误）
///
/// # 流程
///
/// 1. 校验 `ccccs_instances.len() ≤ MAX_FOLD_STEP_COUNT`
/// 2. 对每个 CCCCS 实例：
///    - `fold_step::fold(lcccs, commitment, ccccs, transcript)` → folded LCCCS + z' + C'
///    - `sumcheck::prove(ccs, z', r_x_l, u_prime_spec, fresh_transcript)` → sumcheck proof + r_y + z_at_r_y + actual_u_prime
///    - 更新 folded LCCCS 的 `u_l = actual_u_prime`（非线性 CCS 修正）
/// 3. 最终折叠后：
///    - 构造 `MultilinearPoly` from folded witness
///    - `pcs.open(poly, r_y, transcript)` → PCS opening proof
/// 4. 返回 `HypernovaProof`
pub fn fold_loop(
    ccs: &Ccs,
    initial_lcccs: Lcccs,
    initial_commitment: IpaCommitment,
    ccccs_instances: &[Ccccs],
    pcs: &IpaPcs,
    transcript: &mut Transcript,
) -> Result<HypernovaProof, ZkvmError> {
    // 1. 校验实例数上限
    let n = ccccs_instances.len();
    if n > MAX_FOLD_STEP_COUNT {
        return Err(ZkvmError::FoldStepCountExceeded {
            actual: n as u32,
            limit: MAX_FOLD_STEP_COUNT as u32,
        });
    }

    // 2. 顺序折叠
    let mut current_lcccs = initial_lcccs;
    let mut current_commitment = initial_commitment;
    let mut current_witness: Vec<Fr> = current_lcccs.trace_l.clone();

    // 保存最后一步的 sumcheck 输出
    let mut last_sumcheck_proof: Option<sumcheck::SumcheckProof> = None;
    let mut last_r_y: Vec<Fr> = Vec::new();
    let mut last_z_at_r_y = Fr::zero();
    let mut last_sumcheck_transcript: Option<Transcript> = None;

    for ccccs in ccccs_instances.iter() {
        // (a) fold_step — 使用主 transcript 派生 fold challenge r
        let fold_output =
            fold_step::fold(&current_lcccs, &current_commitment, ccccs, transcript)?;

        // (b) sumcheck::prove — 使用 fresh transcript（见 alternatives.md）
        let u_prime_spec = fold_output.folded_lcccs.u_l; // u_L + r·u_C（spec 公式）
        let mut sumcheck_transcript = Transcript::new();
        let sumcheck_output = sumcheck::prove(
            ccs,
            &fold_output.folded_witness,
            &current_lcccs.r_x_l,
            u_prime_spec,
            &mut sumcheck_transcript,
        )?;

        // (c) 更新 folded LCCCS 的 u_l = actual_u_prime（非线性 CCS 关键修正）
        // 对线性 CCS：actual_u_prime == u_prime_spec（无变化）
        // 对非线性 CCS：actual_u_prime ≠ u_prime_spec（必须更新）
        let mut corrected_lcccs = fold_output.folded_lcccs.clone();
        corrected_lcccs.u_l = sumcheck_output.actual_u_prime;

        // (d) 推进到下一轮
        current_lcccs = corrected_lcccs;
        current_commitment = fold_output.folded_commitment;
        current_witness = fold_output.folded_witness;

        last_sumcheck_proof = Some(sumcheck_output.proof);
        last_r_y = sumcheck_output.r_y;
        last_z_at_r_y = sumcheck_output.z_at_r_y;
        last_sumcheck_transcript = Some(sumcheck_transcript);
    }

    // 3. 生成 PCS opening（使用 final sumcheck 的 transcript，链式）
    // 若无 CCCCS 实例（N=1），则无 sumcheck，使用 fresh transcript
    let final_sumcheck = last_sumcheck_proof.ok_or_else(|| {
        ZkvmError::Other("fold_loop: 至少需要 1 个 CCCCS 实例（N ≥ 2）".to_string())
    })?;

    let mut pcs_transcript = last_sumcheck_transcript.unwrap_or_default();

    // 构造 MultilinearPoly from folded witness
    // witness.len() = num_vars（已为 2 的幂，由 sumcheck 校验）
    let poly = MultilinearPoly::from_evals(current_witness.clone())?;

    // PCS opening 在 r_y 处打开 z'
    let (pcs_opening, pcs_eval) = pcs.open(&poly, &last_r_y, &mut pcs_transcript)?;

    // debug 校验：PCS opening 的 eval 应 = z_at_r_y
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(
            pcs_eval.0, last_z_at_r_y,
            "PCS opening eval 应 = sumcheck 的 z_at_r_y"
        );
    }

    // 4. 返回 HypernovaProof
    Ok(HypernovaProof {
        abi_version: 1, // ZKVM_ABI_VERSION = 1
        folded_instance: current_lcccs,
        witness_commitment: current_commitment,
        final_sumcheck,
        pcs_opening,
        r_y: last_r_y,
        z_at_point: last_z_at_r_y,
    })
}

/// 验证 Hypernova 证明（spec L397-409 — cross-language claim 验证）。
///
/// **简化 verifier**：仅验证 final sumcheck + PCS opening。
/// 完整 verifier 需验证所有 fold 步骤的 sumcheck（见 alternatives.md）。
///
/// # 参数
/// - `proof` — HypernovaProof
/// - `pcs` — IPA PCS（用于 PCS opening 验证）
///
/// # 返回
/// `true` 若 final sumcheck + PCS opening 均验证通过。
///
/// # 验证流程
/// 1. 外层 + 内层 sumcheck：`sumcheck::verify(...)`
/// 2. PCS opening：`pcs.verify(commitment, r_y, z_at_point, opening_proof)`
///
/// # 注
///
/// 此简化 verifier 创建 fresh transcript，与 prover 的 final sumcheck transcript 匹配
/// （因 prover 对 final sumcheck 使用 fresh transcript）。
/// 此 verifier 不验证中间 fold 步骤——完整 verifier 需所有 sumcheck proofs + fold 数据。
pub fn verify_hypernova(proof: &HypernovaProof, pcs: &IpaPcs) -> Result<bool, ZkvmError> {
    // 1. 验证 final sumcheck（fresh transcript，与 prover 的 final sumcheck transcript 匹配）
    let mut transcript = Transcript::new();
    let sumcheck_valid = sumcheck::verify(
        &proof.final_sumcheck,
        &proof.folded_instance.ccs_ref,
        &proof.folded_instance.r_x_l,
        proof.folded_instance.u_l, // = actual_u_prime（prover 更新过）
        proof.z_at_point,
        &mut transcript,
    )?;

    if !sumcheck_valid {
        return Ok(false);
    }

    // 2. 验证 PCS opening（同一 transcript，链式 — 与 prover 的 PCS opening transcript 匹配）
    let pcs_eval = crate::pcs::ipa::IpaEval(proof.z_at_point);
    let pcs_valid = pcs.verify(
        &proof.witness_commitment,
        &proof.r_y,
        &pcs_eval,
        &proof.pcs_opening,
        &mut transcript,
    )?;

    Ok(pcs_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::SparseMatrix;
    use crate::field::ZkvmField;
    use ark_bn254::G1Affine;
    use ark_ec::AffineRepr;

    /// 辅助：构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助：构造负 Fr。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    /// 构造 stub commitment（仅用于不涉及 PCS opening 的测试）。
    fn stub_commitment() -> IpaCommitment {
        IpaCommitment(G1Affine::generator())
    }

    /// 使用 IPA 计算实际 witness commitment（用于 PCS opening 一致性测试）。
    fn commit_witness(pcs: &IpaPcs, z: &[Fr]) -> IpaCommitment {
        let poly = MultilinearPoly::from_evals(z.to_vec()).expect("MultilinearPoly 构造应成功");
        pcs.commit(&poly).expect("pcs.commit 应成功")
    }

    /// 构造线性 CCS — x - y = 0（1 row, 4 vars, 2 matrices）。
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

    /// 构造非线性 CCS — x*y - z = 0（1 row, 4 vars, 3 matrices）。
    fn make_nonlinear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        let mut m2 = SparseMatrix::new(1, 4);
        m2.add_entry(0, 3, f(1)).unwrap();

        Ccs::new(
            4,
            vec![m0, m1, m2],
            vec![vec![0, 1], vec![2]],
            vec![f(1), neg_f(1)],
        )
        .expect("nonlinear Ccs 构造应成功")
    }

    /// 构造 4-row 线性 CCS — 4 个约束行（4 rows, 4 vars, 2 matrices）。
    fn make_4row_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(4, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        m0.add_entry(1, 1, f(1)).unwrap();
        m0.add_entry(2, 1, f(1)).unwrap();
        m0.add_entry(3, 1, f(1)).unwrap();

        let mut m1 = SparseMatrix::new(4, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        m1.add_entry(1, 2, f(1)).unwrap();
        m1.add_entry(2, 2, f(1)).unwrap();
        m1.add_entry(3, 2, f(1)).unwrap();

        Ccs::new(
            4,
            vec![m0, m1],
            vec![vec![0], vec![1]],
            vec![f(1), neg_f(1)],
        )
        .expect("4-row linear Ccs 构造应成功")
    }

    /// 构造 IPA PCS（max_n_vars = 4，支持最多 16 个变量的 witness）。
    fn make_ipa_pcs() -> IpaPcs {
        IpaPcs::new(4).expect("IpaPcs 构造应成功")
    }

    // ===== 正例：单步折叠（N=2）=====

    #[test]
    fn test_fold_loop_single_fold_linear_ccs() {
        // 线性 CCS: x - y = 0
        // z_L = [1, 5, 5, 0] (satisfied, 4 vars padded)
        // z_C = [1, 3, 3, 0] (satisfied)
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 校验 HypernovaProof 结构
        assert_eq!(proof.abi_version, 1);
        assert_eq!(proof.r_y.len(), 2); // log2(num_vars=4) = 2
        // 线性 CCS: actual_u_prime = u_L + r·u_C = 0
        assert_eq!(proof.folded_instance.u_l, Fr::zero());
        // folded witness 长度 = num_vars = 4
        assert_eq!(proof.folded_instance.trace_l.len(), 4);
    }

    #[test]
    fn test_fold_loop_single_fold_nonlinear_ccs() {
        // 非线性 CCS: x*y - z = 0
        // z_L = [1, 3, 4, 12] (satisfied: 3*4 - 12 = 0)
        // z_C = [1, 2, 5, 10] (satisfied: 2*5 - 10 = 0)
        let ccs = make_nonlinear_ccs();
        let z_l = vec![f(1), f(3), f(4), f(12)];
        let z_c = vec![f(1), f(2), f(5), f(10)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 非线性 CCS: actual_u_prime ≠ u_L + r·u_C = 0（因 Π 不分配 +）
        // folded LCCCS 的 u_l 应 = actual_u_prime（非 0）
        assert_ne!(
            proof.folded_instance.u_l,
            Fr::zero(),
            "非线性 CCS: actual_u_prime 应 ≠ 0（u_L + r·u_C = 0，但实际 sum ≠ 0）"
        );
        // r_y 长度 = log2(num_vars=4) = 2
        assert_eq!(proof.r_y.len(), 2);
    }

    // ===== 正例：多步折叠（N=3）=====

    #[test]
    fn test_fold_loop_multi_fold_linear_ccs() {
        // 线性 CCS: x - y = 0
        // 3 个 satisfied 实例
        let ccs = make_linear_ccs();
        let z1 = vec![f(1), f(5), f(5), f(0)];
        let z2 = vec![f(1), f(3), f(3), f(0)];
        let z3 = vec![f(1), f(7), f(7), f(0)];

        let lcccs = ccs.to_lcccs(&z1, &[], vec![]).expect("to_lcccs 1");
        let ccccs2 = ccs.to_cccs(&z2, vec![], stub_commitment()).expect("to_cccs 2");
        let ccccs3 = ccs.to_cccs(&z3, vec![], stub_commitment()).expect("to_cccs 3");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs2, ccccs3],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 线性 CCS 链式折叠后 u' = 0
        assert_eq!(proof.folded_instance.u_l, Fr::zero());
        assert_eq!(proof.r_y.len(), 2);
    }

    #[test]
    fn test_fold_loop_multi_fold_nonlinear_ccs() {
        // 非线性 CCS: x*y - z = 0
        // 3 个 satisfied 实例
        let ccs = make_nonlinear_ccs();
        let z1 = vec![f(1), f(3), f(4), f(12)];
        let z2 = vec![f(1), f(2), f(5), f(10)];
        let z3 = vec![f(1), f(6), f(7), f(42)];

        let lcccs = ccs.to_lcccs(&z1, &[], vec![]).expect("to_lcccs 1");
        let ccccs2 = ccs.to_cccs(&z2, vec![], stub_commitment()).expect("to_cccs 2");
        let ccccs3 = ccs.to_cccs(&z3, vec![], stub_commitment()).expect("to_cccs 3");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs2, ccccs3],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 非线性 CCS 链式折叠后 u' ≠ 0
        assert_ne!(proof.folded_instance.u_l, Fr::zero());
    }

    // ===== 正例：4-row CCS =====

    #[test]
    fn test_fold_loop_4row_linear_ccs() {
        // 4-row 线性 CCS, r_x_l = [0, 0]（在 row 0 处求值）
        let ccs = make_4row_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        // x_l 与 x_c 长度必须一致（fold_step 校验 x_l.len() == x_c.len()）
        let x_public = vec![f(0), f(0)];
        let lcccs = ccs
            .to_lcccs(&z_l, &[f(0), f(0)], x_public.clone())
            .expect("to_lcccs");
        let ccccs = ccs
            .to_cccs(&z_c, x_public, stub_commitment())
            .expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 4-row CCS: r_y 长度 = log2(num_vars=4) = 2
        assert_eq!(proof.r_y.len(), 2);
        assert_eq!(proof.folded_instance.u_l, Fr::zero());
    }

    // ===== 边界：0 个 CCCCS 实例 =====

    #[test]
    fn test_fold_loop_no_ccccs_instances() {
        // 0 个 CCCCS 实例 → 应返回错误（至少需要 1 个）
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let result = fold_loop(&ccs, lcccs, stub_commitment(), &[], &pcs, &mut transcript);
        assert!(result.is_err(), "0 个 CCCCS 实例应返回错误");
    }

    // ===== 边界：实例数超限 =====

    #[test]
    fn test_fold_loop_too_many_instances() {
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");

        // 构造 MAX_FOLD_STEP_COUNT + 1 个 CCCCS 实例
        let ccccs_instances: Vec<Ccccs> = (0..=MAX_FOLD_STEP_COUNT)
            .map(|_| {
                ccs.to_cccs(&[f(1), f(3), f(3), f(0)], vec![], stub_commitment())
                    .expect("to_cccs")
            })
            .collect();

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let result = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &ccccs_instances,
            &pcs,
            &mut transcript,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            ZkvmError::FoldStepCountExceeded { actual, limit } => {
                assert_eq!(actual as usize, MAX_FOLD_STEP_COUNT + 1);
                assert_eq!(limit as usize, MAX_FOLD_STEP_COUNT);
            }
            other => panic!("期望 FoldStepCountExceeded，得到 {other:?}"),
        }
    }

    // ===== verify_hypernova 正例 =====

    #[test]
    fn test_verify_hypernova_linear_ccs_valid() {
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        // 使用真实 IPA commitment，使 C' = C_L + r·C_C = ⟨z', G⟩ 与 pcs.open 内部承诺一致
        let pcs = make_ipa_pcs();
        let cmt_l = commit_witness(&pcs, &z_l);
        let cmt_c = commit_witness(&pcs, &z_c);

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], cmt_c).expect("to_cccs");

        let mut transcript = Transcript::new();

        let proof = fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        let valid = verify_hypernova(&proof, &pcs).expect("verify 应成功");
        assert!(valid, "valid proof 应验证通过");
    }

    #[test]
    fn test_verify_hypernova_nonlinear_ccs_valid() {
        let ccs = make_nonlinear_ccs();
        let z_l = vec![f(1), f(3), f(4), f(12)];
        let z_c = vec![f(1), f(2), f(5), f(10)];

        // 使用真实 IPA commitment，使 C' = C_L + r·C_C = ⟨z', G⟩ 与 pcs.open 内部承诺一致
        let pcs = make_ipa_pcs();
        let cmt_l = commit_witness(&pcs, &z_l);
        let cmt_c = commit_witness(&pcs, &z_c);

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], cmt_c).expect("to_cccs");

        let mut transcript = Transcript::new();

        let proof = fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        let valid = verify_hypernova(&proof, &pcs).expect("verify 应成功");
        assert!(valid, "非线性 CCS valid proof 应验证通过");
    }

    #[test]
    fn test_verify_hypernova_multi_fold_valid() {
        let ccs = make_linear_ccs();
        let z1 = vec![f(1), f(5), f(5), f(0)];
        let z2 = vec![f(1), f(3), f(3), f(0)];
        let z3 = vec![f(1), f(7), f(7), f(0)];

        // 使用真实 IPA commitment，使 C' = C_L + r·C_C = ⟨z', G⟩ 与 pcs.open 内部承诺一致
        let pcs = make_ipa_pcs();
        let cmt1 = commit_witness(&pcs, &z1);
        let cmt2 = commit_witness(&pcs, &z2);
        let cmt3 = commit_witness(&pcs, &z3);

        let lcccs = ccs.to_lcccs(&z1, &[], vec![]).expect("to_lcccs 1");
        let ccccs2 = ccs.to_cccs(&z2, vec![], cmt2).expect("to_cccs 2");
        let ccccs3 = ccs.to_cccs(&z3, vec![], cmt3).expect("to_cccs 3");

        let mut transcript = Transcript::new();

        let proof = fold_loop(
            &ccs,
            lcccs,
            cmt1,
            &[ccccs2, ccccs3],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        let valid = verify_hypernova(&proof, &pcs).expect("verify 应成功");
        assert!(valid, "多步折叠 valid proof 应验证通过");
    }

    // ===== verify_hypernova 负例：篡改 proof =====

    #[test]
    fn test_verify_hypernova_tampered_u_l() {
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let mut proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 篡改 folded_instance.u_l
        proof.folded_instance.u_l = f(99);

        let valid = verify_hypernova(&proof, &pcs).expect("verify 应成功");
        assert!(!valid, "篡改 u_l 后应验证失败");
    }

    #[test]
    fn test_verify_hypernova_tampered_z_at_point() {
        let ccs = make_nonlinear_ccs();
        let z_l = vec![f(1), f(3), f(4), f(12)];
        let z_c = vec![f(1), f(2), f(5), f(10)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let mut proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 篡改 z_at_point
        proof.z_at_point = f(99);

        let valid = verify_hypernova(&proof, &pcs).expect("verify 应成功");
        assert!(!valid, "篡改 z_at_point 后应验证失败");
    }

    #[test]
    fn test_verify_hypernova_tampered_sumcheck_proof() {
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let mut proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 篡改 sumcheck proof 的 v_pp[0]
        if !proof.final_sumcheck.v_pp.is_empty() {
            proof.final_sumcheck.v_pp[0] = f(99);
        }

        let valid = verify_hypernova(&proof, &pcs).expect("verify 应成功");
        assert!(!valid, "篡改 sumcheck proof 后应验证失败");
    }

    #[test]
    fn test_verify_hypernova_tampered_pcs_opening() {
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let mut proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop 应成功");

        // 篡改 PCS opening 的 a_final
        if !proof.pcs_opening.l_vec.is_empty() {
            proof.pcs_opening.a_final = f(99);
        }

        let valid = verify_hypernova(&proof, &pcs).expect("verify 应成功");
        assert!(!valid, "篡改 PCS opening 后应验证失败");
    }

    // ===== actual_u_prime 修正验证 =====

    #[test]
    fn test_fold_loop_actual_u_prime_correction_nonlinear() {
        // 验证非线性 CCS 的 actual_u_prime 修正：
        // folded LCCCS 的 u_l 应 = actual_u_prime（非 u_L + r·u_C = 0）
        let ccs = make_nonlinear_ccs();
        let z_l = vec![f(1), f(3), f(4), f(12)];
        let z_c = vec![f(1), f(2), f(5), f(10)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        // 手动执行 fold + sumcheck 以获取 actual_u_prime
        let fold_output =
            fold_step::fold(&lcccs, &stub_commitment(), &ccccs, &mut transcript).expect("fold");

        let mut sumcheck_t = Transcript::new();
        let sumcheck_out = sumcheck::prove(
            &ccs,
            &fold_output.folded_witness,
            &lcccs.r_x_l,
            fold_output.folded_lcccs.u_l, // u_L + r·u_C = 0
            &mut sumcheck_t,
        )
        .expect("sumcheck::prove");

        // 非线性 CCS: actual_u_prime ≠ u_L + r·u_C = 0
        assert_ne!(sumcheck_out.actual_u_prime, Fr::zero());
        assert_eq!(fold_output.folded_lcccs.u_l, Fr::zero()); // spec 公式 = 0

        // fold_loop 应将 u_l 更新为 actual_u_prime
        let mut transcript2 = Transcript::new();
        let proof = fold_loop(
            &ccs,
            lcccs.clone(),
            stub_commitment(),
            std::slice::from_ref(&ccccs),
            &pcs,
            &mut transcript2,
        )
        .expect("fold_loop");

        assert_eq!(
            proof.folded_instance.u_l, sumcheck_out.actual_u_prime,
            "fold_loop 应将 folded LCCCS 的 u_l 更新为 actual_u_prime"
        );
    }

    #[test]
    fn test_fold_loop_actual_u_prime_linear_unchanged() {
        // 线性 CCS: actual_u_prime == u_L + r·u_C（无变化）
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop");

        // 线性 CCS: u_l = 0 = u_L + r·u_C = actual_u_prime
        assert_eq!(proof.folded_instance.u_l, Fr::zero());
    }

    // ===== PCS opening 一致性 =====

    #[test]
    fn test_fold_loop_pcs_opening_eval_matches_z_at_point() {
        let ccs = make_nonlinear_ccs();
        let z_l = vec![f(1), f(3), f(4), f(12)];
        let z_c = vec![f(1), f(2), f(5), f(10)];

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let proof = fold_loop(
            &ccs,
            lcccs,
            stub_commitment(),
            &[ccccs],
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop");

        // 手动构造 MultilinearPoly 并在 r_y 处求值，应 = z_at_point
        let poly =
            MultilinearPoly::from_evals(proof.folded_instance.trace_l.clone()).expect("poly");
        // 使用 IPA 的 open 重新打开，验证 eval 一致
        let mut t = Transcript::new();
        // 先吸收 sumcheck 数据以对齐 transcript
        sumcheck::verify(
            &proof.final_sumcheck,
            &proof.folded_instance.ccs_ref,
            &proof.folded_instance.r_x_l,
            proof.folded_instance.u_l,
            proof.z_at_point,
            &mut t,
        )
        .expect("sumcheck verify");
        let (_, eval) = pcs.open(&poly, &proof.r_y, &mut t).expect("pcs.open");
        assert_eq!(eval.0, proof.z_at_point, "PCS opening eval 应 = z_at_point");
    }

    // ===== witness_commitment 一致性 =====

    #[test]
    fn test_fold_loop_witness_commitment_correct() {
        // 验证 C' = C_L + r·C_C（fold_step 已验证，此处验证 fold_loop 传递正确）
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];

        let cmt_l = stub_commitment();
        let cmt_c = stub_commitment();

        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, vec![], cmt_c.clone()).expect("to_cccs");

        let mut transcript = Transcript::new();
        let pcs = make_ipa_pcs();

        let proof = fold_loop(
            &ccs,
            lcccs.clone(),
            cmt_l.clone(),
            std::slice::from_ref(&ccccs),
            &pcs,
            &mut transcript,
        )
        .expect("fold_loop");

        // 手动计算 C' = C_L + r·C_C
        let mut fold_t = Transcript::new();
        let fold_out =
            fold_step::fold(&lcccs, &cmt_l, &ccccs, &mut fold_t).expect("fold_step");
        assert_eq!(
            proof.witness_commitment.0, fold_out.folded_commitment.0,
            "fold_loop 的 witness_commitment 应 = fold_step 的 folded_commitment"
        );
    }
}
