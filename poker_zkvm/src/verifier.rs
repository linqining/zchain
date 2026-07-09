//! 端到端 verifier（Phase 8 — Task 8.1 实现 + 安全修复完整 verifier）。
//!
//! 严格遵循 spec.md L397-409（v1.4 FROZEN）与 soundness 链：
//! - [`verify_production`] — 完整 Production verifier：
//!   CCS 白名单 → public_io 绑定 → fold challenge 重派生 → fold 等式验证 →
//!   所有中间 sumcheck → batch 连续性 → 最终 PCS opening
//!
//! ## Soundness 链
//!
//! verifier 验证以下链式保证，使恶意 prover 无法伪造 proof：
//! 1. **CCS 白名单**：拒绝未注册的 CCS 结构
//! 2. **public_io 绑定**：proof 与 public_io 哈希绑定，防重放
//! 3. **fold challenge 重派生**：重放主 transcript，验证每步 r 来自正确 FS
//! 4. **fold commitment 等式**：每步 `C' = C_L + r · C_C`（不需 witness）
//! 5. **fold 实例等式**：每步 `x' = x_L + r · x_C`、`r_x' = r_x_L`、`u' = actual_u_prime`
//! 6. **所有中间 sumcheck**：每步验证 `G(r_x_L) == actual_u_prime` + 内层 cross-language claim
//! 7. **batch 连续性**：所有 batch 的 step_index 连续递增
//! 8. **最终 PCS opening**：验证 `z'(r_y)` 的正确性

use crate::ccs::Fr as ZkvmFr;
use crate::constraints::verify_batch_continuity;
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::fold::sumcheck;
use crate::pcs::ipa::{IpaCommitment, IpaEval, IpaPcs};
use crate::pcs::Pcs;
use crate::prover::{deserialize_proof, hash_public_io, ZkPublicIo};
use crate::transcript::{Transcript, HYPERNOVA_FOLD_DOMAIN_TAG};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;

/// 将 G1Affine 压缩序列化为字节（匹配 fold_step.rs 的 point_to_bytes）。
fn point_to_bytes(p: &ark_bn254::G1Affine) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes)
        .expect("G1Affine serialize_compressed 不应失败");
    bytes
}

/// 端到端 Production verifier（完整 soundness 链）。
///
/// 验证 Hypernova proof 字节序列的完整性，包含：
/// 1. 反序列化 proof（含 magic / version / 字段长度校验）
/// 2. CCS 白名单校验（防 CCS 结构注入）
/// 3. public_io 绑定校验（防重放攻击）
/// 4. 重放主 transcript，派生 r_x_l 并校验一致性
/// 5. 逐步验证 fold_steps（fold challenge 重派生 + fold 等式 + 中间 sumcheck）
/// 6. batch 连续性校验
/// 7. 最终 PCS opening 验证
///
/// # 参数
/// - `proof_bytes` — 序列化的 HypernovaProof 字节
/// - `public_io` — 公共输入输出（与 proof 绑定校验）
/// - `ccs_whitelist` — 允许的 CCS commitment 列表（白名单）
///
/// # 返回
/// - `Ok(true)` — proof 验证通过
/// - `Err(...)` — 验证失败（含具体错误原因）
///
/// # 安全性
///
/// 完整 verifier 恢复 soundness 保证：恶意 prover 无法通过篡改 CCS 结构、
/// 替换 public_io、伪造 fold challenge、篡改中间 sumcheck 或 fold commitment
/// 来生成通过验证的 proof。
pub fn verify_production(
    proof_bytes: &[u8],
    public_io: &ZkPublicIo,
    ccs_whitelist: &[[u8; 32]],
) -> Result<bool, ZkvmError> {
    // 1. 反序列化 proof
    let proof = deserialize_proof(proof_bytes)?;

    // 2. CCS 白名单校验
    if !ccs_whitelist.contains(&proof.ccs_commitment) {
        return Err(ZkvmError::Other(format!(
            "CCS 不在白名单: commitment {:?}..",
            &proof.ccs_commitment[..8]
        )));
    }

    // 3. public_io 绑定校验
    let expected_pio = hash_public_io(public_io);
    if expected_pio != proof.public_io_commitment {
        return Err(ZkvmError::Other(
            "public_io 不匹配: hash_public_io(public_io) != proof.public_io_commitment".to_string(),
        ));
    }

    // 4. 重建 IpaPcs（基于 initial_lcccs.ccs_ref.num_vars）
    let ccs = &proof.initial_lcccs.ccs_ref;
    let num_vars = ccs.num_vars;
    if !num_vars.is_power_of_two() {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "ccs_ref.num_vars {num_vars} 非 2 的幂"
        )));
    }
    let pcs_n_vars = num_vars.trailing_zeros() as usize;
    let pcs = IpaPcs::new(pcs_n_vars)?;

    // 4.5 ccs_commitment 一致性校验（Finding C — 防御深度）
    let initial_ccs_commit = ccs.ccs_commitment();
    if proof.ccs_commitment != initial_ccs_commit {
        return Err(ZkvmError::Other(
            "ccs_commitment 不匹配：proof.ccs_commitment != initial_lcccs.ccs_ref.ccs_commitment()".to_string(),
        ));
    }

    // 5. 重放主 transcript（匹配 prover/mod.rs 的 absorb 顺序）
    let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
    // (a) absorb public_io_commitment（在 ccs_commitment 之前 — 匹配 prover 顺序）
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.public_io_commitment);
    // (b) absorb ccs_commitment
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.ccs_commitment);
    // (c) absorb 所有 batch_public_inputs（每组逐 Fr absorb_field — 匹配 prover 顺序）
    for group in &proof.batch_public_inputs {
        for pi in group {
            transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
        }
    }
    // (d) 派生 r_x_l（长度 = log2(num_rows)）
    let num_rows = ccs.num_rows();
    if num_rows == 0 || !num_rows.is_power_of_two() {
        return Err(ZkvmError::Other(format!(
            "verify_production: num_rows = {num_rows} 非 2 的幂"
        )));
    }
    let r_x_l_len = num_rows.trailing_zeros() as usize;
    let derived_r_x_l: Vec<ZkvmFr> = (0..r_x_l_len)
        .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
        .collect();
    // (e) 校验 derived_r_x_l == proof.initial_lcccs.r_x_l
    if derived_r_x_l != proof.initial_lcccs.r_x_l {
        return Err(ZkvmError::Other(
            "r_x_l 不匹配: 派生值 != proof.initial_lcccs.r_x_l".to_string(),
        ));
    }

    // 6. 逐步验证 fold_steps
    let mut current_lcccs = proof.initial_lcccs.clone();
    let mut current_witness_commitment = proof.initial_witness_commitment.clone();
    let mut last_sumcheck_transcript: Option<Transcript> = None;

    for step in &proof.fold_steps {
        // (a) 重放 fold absorb（匹配 fold_step.rs:133-157 顺序）
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.ccs_commitment);
        transcript.absorb(
            HYPERNOVA_FOLD_DOMAIN_TAG,
            &point_to_bytes(&current_witness_commitment.0),
        );
        transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.u_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.x_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.r_x_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.v_l);
        transcript.absorb(
            HYPERNOVA_FOLD_DOMAIN_TAG,
            &point_to_bytes(&step.ccccs_witness_commitment.0),
        );
        transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &step.ccccs_u_c);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &step.ccccs_x_c);

        // (b) 派生 fold challenge r
        let r = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);

        // (c) 计算 v_C[j](r_x_L) = ccs.compute_v_at(&step.ccccs_trace_c, &current.r_x_l)
        let v_c_at_r_x_l = ccs.compute_v_at(&step.ccccs_trace_c, &current_lcccs.r_x_l)?;

        // (d) 验证 fold 实例等式（与 step.folded_lcccs 比对）
        // folded_x = current.x_l + r·step.ccccs_x_c
        let expected_folded_x: Vec<ZkvmFr> = current_lcccs
            .x_l
            .iter()
            .zip(&step.ccccs_x_c)
            .map(|(xl, xc)| xl.add(&r.mul(xc)))
            .collect();
        if expected_folded_x != step.folded_lcccs.x_l {
            return Err(ZkvmError::Other(
                "fold 实例等式失败: folded_x 不匹配".to_string(),
            ));
        }

        // folded_trace = current.trace_l + r·step.ccccs_trace_c
        let expected_folded_trace: Vec<ZkvmFr> = current_lcccs
            .trace_l
            .iter()
            .zip(&step.ccccs_trace_c)
            .map(|(tl, tc)| tl.add(&r.mul(tc)))
            .collect();
        if expected_folded_trace != step.folded_lcccs.trace_l {
            return Err(ZkvmError::Other(
                "fold 实例等式失败: folded_trace 不匹配".to_string(),
            ));
        }

        // folded_r_x = current.r_x_l
        if current_lcccs.r_x_l != step.folded_lcccs.r_x_l {
            return Err(ZkvmError::Other(
                "fold 实例等式失败: folded_r_x_l 不匹配".to_string(),
            ));
        }

        // folded_v[j] = current.v_l[j] + r·v_C[j]
        if current_lcccs.v_l.len() != v_c_at_r_x_l.len() {
            return Err(ZkvmError::Other(format!(
                "fold 实例等式失败: v_l.len() {} != v_c_at_r_x_l.len() {}",
                current_lcccs.v_l.len(),
                v_c_at_r_x_l.len()
            )));
        }
        let expected_folded_v: Vec<ZkvmFr> = current_lcccs
            .v_l
            .iter()
            .zip(&v_c_at_r_x_l)
            .map(|(vl, vc)| vl.add(&r.mul(vc)))
            .collect();
        if expected_folded_v != step.folded_lcccs.v_l {
            return Err(ZkvmError::Other(
                "fold 实例等式失败: folded_v 不匹配".to_string(),
            ));
        }

        // step.folded_lcccs.u_l == step.actual_u_prime（u_l 修正校验）
        if step.folded_lcccs.u_l != step.actual_u_prime {
            return Err(ZkvmError::Other(
                "u_l 修正校验失败: folded_lcccs.u_l != actual_u_prime".to_string(),
            ));
        }

        // (e) 验证 fold commitment 等式: C' = C_L + r·C_C
        let c_l_group = current_witness_commitment.0.into_group();
        let c_c_group = step.ccccs_witness_commitment.0.into_group();
        let r_ark = r.into_fr();
        let expected_folded_commitment_group = c_l_group + c_c_group * r_ark;
        let expected_folded_commitment =
            IpaCommitment(expected_folded_commitment_group.into_affine());
        if expected_folded_commitment.0 != step.folded_witness_commitment.0 {
            return Err(ZkvmError::Other(
                "fold commitment 等式失败: C' != C_L + r·C_C".to_string(),
            ));
        }

        // (f) 验证 sumcheck（fresh transcript — 匹配 prover 的 fresh transcript 策略）
        let mut fresh_t = Transcript::new();
        let sumcheck_valid = sumcheck::verify(
            &step.sumcheck_proof,
            ccs,
            &current_lcccs.r_x_l,
            step.actual_u_prime,
            step.z_at_r_y,
            &mut fresh_t,
        )?;
        if !sumcheck_valid {
            return Err(ZkvmError::SumcheckVerificationFailed);
        }

        // (g) 推进
        current_lcccs = step.folded_lcccs.clone();
        current_witness_commitment = step.folded_witness_commitment.clone();
        last_sumcheck_transcript = Some(fresh_t);
    }

    // 7. batch 连续性校验
    if !verify_batch_continuity(&proof.batch_public_inputs) {
        return Err(ZkvmError::Other(
            "batch 不连续: batch_public_inputs 连续性校验失败".to_string(),
        ));
    }

    // 7.5 PCS-sumcheck 绑定校验（Finding A + B）
    let last_step = proof.fold_steps.last().ok_or_else(|| {
        ZkvmError::InvalidZkProofFormat("fold_steps 为空：无法链接 PCS opening".to_string())
    })?;
    if proof.r_y != last_step.r_y {
        return Err(ZkvmError::Other(
            "PCS opening 解耦：proof.r_y != fold_steps.last().r_y".to_string(),
        ));
    }
    if proof.z_at_point != last_step.z_at_r_y {
        return Err(ZkvmError::Other(
            "PCS opening 解耦：proof.z_at_point != fold_steps.last().z_at_r_y".to_string(),
        ));
    }

    // 8. 最终 PCS opening 验证（使用最后一步的 fresh transcript，链式）
    let mut pcs_transcript = last_sumcheck_transcript.unwrap_or_default();
    let pcs_eval = IpaEval(proof.z_at_point);
    let pcs_valid = pcs.verify(
        &current_witness_commitment,
        &proof.r_y,
        &pcs_eval,
        &proof.pcs_opening,
        &mut pcs_transcript,
    )?;
    if !pcs_valid {
        return Err(ZkvmError::PcsVerificationFailed);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::serialize_proof;

    /// 辅助：生成合法 proof bytes + public_io。
    fn make_valid_proof_and_public_io() -> (Vec<u8>, ZkPublicIo) {
        crate::prover::generate_test_proof()
    }

    /// 辅助：从 proof bytes 提取 ccs_commitment 作为白名单。
    fn extract_ccs_whitelist(proof_bytes: &[u8]) -> Vec<[u8; 32]> {
        let proof = deserialize_proof(proof_bytes).expect("deserialize 应成功");
        vec![proof.ccs_commitment]
    }

    #[test]
    fn test_verify_production_valid_proof_passes() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let result = verify_production(&proof_bytes, &public_io, &ccs_whitelist);
        assert!(result.is_ok(), "合法 proof 应通过验证，got: {:?}", result);
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_production_tampered_magic_fails() {
        let (mut proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        proof_bytes[0] = b'X'; // 篡改 magic
        let result = verify_production(&proof_bytes, &public_io, &ccs_whitelist);
        assert!(
            matches!(result, Err(ZkvmError::InvalidZkProofFormat(ref m)) if m.contains("magic")),
            "expected InvalidZkProofFormat with magic error, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_tampered_abi_version_fails() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        // 反序列化 → 篡改 abi_version → 重新序列化
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        proof.abi_version = proof.abi_version.wrapping_add(1);
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        // abi_version 篡改不应导致验证失败（advisory 字段）
        assert!(
            result.is_ok(),
            "abi_version 篡改不应影响验证（advisory 字段），got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_tampered_folded_lcccs_u_l_fails() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 篡改最后一步的 folded_lcccs.u_l
        let last_step = proof
            .fold_steps
            .last_mut()
            .expect("fold_steps 非空");
        last_step.folded_lcccs.u_l = last_step
            .folded_lcccs
            .u_l
            .add(&ZkvmFr::from_u32_with_wrap(1));
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(
                result,
                Err(ZkvmError::SumcheckVerificationFailed)
                    | Err(ZkvmError::PcsVerificationFailed)
                    | Err(ZkvmError::Other(_))
            ),
            "篡改 u_l 应导致验证失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_tampered_witness_commitment_fails() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 替换最后一步的 folded_witness_commitment 为一个不同的点
        use ark_bn254::G1Affine;
        use ark_ec::AffineRepr;
        let last_step = proof
            .fold_steps
            .last_mut()
            .expect("fold_steps 非空");
        last_step.folded_witness_commitment = IpaCommitment(G1Affine::generator());
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(
                result,
                Err(ZkvmError::PcsVerificationFailed) | Err(ZkvmError::Other(_))
            ),
            "篡改 witness_commitment 应导致验证失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_tampered_sumcheck_fails() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 篡改最后一步的 sumcheck_proof
        let last_step = proof
            .fold_steps
            .last_mut()
            .expect("fold_steps 非空");
        if !last_step.sumcheck_proof.outer_round_polys.is_empty()
            && !last_step.sumcheck_proof.outer_round_polys[0].is_empty()
        {
            let val = last_step.sumcheck_proof.outer_round_polys[0][0];
            last_step.sumcheck_proof.outer_round_polys[0][0] =
                val.add(&ZkvmFr::from_u32_with_wrap(1));
        }
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(
                result,
                Err(ZkvmError::SumcheckVerificationFailed) | Err(ZkvmError::Other(_))
            ),
            "篡改 sumcheck 应导致验证失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_tampered_pcs_opening_fails() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        proof.pcs_opening.a_final = proof
            .pcs_opening
            .a_final
            .add(&ZkvmFr::from_u32_with_wrap(1));
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(
                result,
                Err(ZkvmError::PcsVerificationFailed) | Err(ZkvmError::Other(_))
            ),
            "篡改 pcs_opening 应导致 PCS 验证失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_tampered_r_y_fails() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        if !proof.r_y.is_empty() {
            let val = proof.r_y[0];
            proof.r_y[0] = val.add(&ZkvmFr::from_u32_with_wrap(1));
        }
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(
                result,
                Err(ZkvmError::PcsVerificationFailed)
                    | Err(ZkvmError::SumcheckVerificationFailed)
                    | Err(ZkvmError::Other(_))
            ),
            "篡改 r_y 应导致验证失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_tampered_z_at_point_fails() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        proof.z_at_point = proof.z_at_point.add(&ZkvmFr::from_u32_with_wrap(1));
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(
                result,
                Err(ZkvmError::SumcheckVerificationFailed)
                    | Err(ZkvmError::PcsVerificationFailed)
                    | Err(ZkvmError::Other(_))
            ),
            "篡改 z_at_point 应导致验证失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_oversized_proof_fails() {
        let oversized = vec![0u8; crate::prover::MAX_PROOF_TOTAL_SIZE + 1];
        let public_io = ZkPublicIo {
            input: Vec::new(),
            output: Vec::new(),
            randomness_seed: ZkvmFr::zero(),
            initial_commitment: ZkvmFr::zero(),
            final_commitment: ZkvmFr::zero(),
            event_hashes: Vec::new(),
        };
        let result = verify_production(&oversized, &public_io, &[]);
        assert!(
            matches!(result, Err(ZkvmError::InvalidZkProofFormat(ref m)) if m.contains("MAX_PROOF_TOTAL_SIZE")),
            "expected InvalidZkProofFormat with size error, got: {result:?}"
        );
    }

    // ===== 新增安全测试（Step 7.2）=====

    #[test]
    fn test_verify_production_rejects_unregistered_ccs() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        // 使用空白名单（不含 proof.ccs_commitment）
        let empty_whitelist: Vec<[u8; 32]> = vec![];
        let result = verify_production(&proof_bytes, &public_io, &empty_whitelist);
        assert!(
            matches!(result, Err(ZkvmError::Other(ref m)) if m.contains("CCS 不在白名单")),
            "CCS 不在白名单应被拒绝，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_rejects_mismatched_public_io() {
        let (proof_bytes, _public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        // 构造不同的 public_io（修改 output）
        let tampered_public_io = ZkPublicIo {
            input: vec![0xFF],
            output: vec![0xAA],
            randomness_seed: ZkvmFr::zero(),
            initial_commitment: ZkvmFr::zero(),
            final_commitment: ZkvmFr::zero(),
            event_hashes: Vec::new(),
        };
        let result = verify_production(&proof_bytes, &tampered_public_io, &ccs_whitelist);
        assert!(
            matches!(result, Err(ZkvmError::Other(ref m)) if m.contains("public_io 不匹配")),
            "public_io 不匹配应被拒绝，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_rejects_tampered_fold_challenge() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 篡改第一步的 ccccs_u_c（fold challenge 重派生将不匹配）
        if !proof.fold_steps.is_empty() {
            let val = proof.fold_steps[0].ccccs_u_c;
            proof.fold_steps[0].ccccs_u_c = val.add(&ZkvmFr::from_u32_with_wrap(1));
        }
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            result.is_err(),
            "篡改 ccccs_u_c 应导致 fold challenge 重派生失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_rejects_tampered_intermediate_sumcheck() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 篡改第一步（非最后一步）的 sumcheck_proof
        // generate_test_proof 产生 2 个 CCS 实例 → 1 个 fold_step，故只有 1 步
        // 此测试验证：篡改任意 sumcheck_proof 应被检测
        if !proof.fold_steps.is_empty() {
            let step = &mut proof.fold_steps[0];
            if !step.sumcheck_proof.outer_round_polys.is_empty()
                && !step.sumcheck_proof.outer_round_polys[0].is_empty()
            {
                let val = step.sumcheck_proof.outer_round_polys[0][0];
                step.sumcheck_proof.outer_round_polys[0][0] =
                    val.add(&ZkvmFr::from_u32_with_wrap(1));
            }
        }
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(
                result,
                Err(ZkvmError::SumcheckVerificationFailed) | Err(ZkvmError::Other(_))
            ),
            "篡改中间 sumcheck 应导致验证失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_rejects_non_continuous_batch() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 篡改 batch_public_inputs 使不连续（修改第二组的 first_idx）
        if proof.batch_public_inputs.len() >= 2 {
            let val = proof.batch_public_inputs[1][1]; // first_idx
            proof.batch_public_inputs[1][1] = val.add(&ZkvmFr::from_u32_with_wrap(100));
        }
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(result, Err(ZkvmError::Other(ref m)) if m.contains("batch 不连续")
                || m.contains("r_x_l 不匹配")
                || m.contains("fold 实例等式")),
            "batch 不连续应被拒绝，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_rejects_tampered_fold_commitment() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 篡改第一步的 folded_witness_commitment（fold commitment 等式将失败）
        use ark_bn254::G1Affine;
        use ark_ec::AffineRepr;
        if !proof.fold_steps.is_empty() {
            proof.fold_steps[0].folded_witness_commitment =
                IpaCommitment(G1Affine::generator());
        }
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(result, Err(ZkvmError::Other(ref m)) if m.contains("fold commitment 等式失败")
                || m.contains("PCS")),
            "篡改 fold commitment 应导致验证失败，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_rejects_pcs_sumcheck_decoupling() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 篡改 proof.r_y（使其 != fold_steps.last().r_y）
        if !proof.r_y.is_empty() {
            let val = proof.r_y[0];
            proof.r_y[0] = val.add(&ZkvmFr::from_u32_with_wrap(1));
        }
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(result, Err(ZkvmError::Other(ref m)) if m.contains("PCS opening 解耦")),
            "PCS-sumcheck 解耦应被拒绝，got: {result:?}"
        );
    }

    #[test]
    fn test_verify_production_rejects_empty_fold_steps() {
        let (proof_bytes, public_io) = make_valid_proof_and_public_io();
        let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
        let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
        // 清空 fold_steps
        proof.fold_steps.clear();
        let tampered = serialize_proof(&proof).expect("serialize 应成功");
        let result = verify_production(&tampered, &public_io, &ccs_whitelist);
        assert!(
            matches!(result, Err(ZkvmError::InvalidZkProofFormat(ref m)) if m.contains("fold_steps 为空")),
            "空 fold_steps 应被拒绝，got: {result:?}"
        );
    }
}
