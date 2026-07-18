//! 统一 ZK 验证入口（移植自 `texas_poker_move/sources/zk_verifier.move`）。
//!
//! # 功能
//!
//! - Transcript 工厂：为每种 proof 创建带正确协议名的 transcript
//! - `verify_*`：统一入口，封装 transcript 创建 + proof module verify
//! - `verify_pk_ownership`：PK 所有权证明（80 字节 Schnorr）
//! - `verify_or_skip`：dev chain 友好的 ZK skip 回退
//!
//! # ZK 跳过策略
//!
//! `TableConfig.zk_skip_enabled = true` 时，`verify_or_skip` 直接返回 true，
//! 便于 dev chain 首版跑通流程。mainnet 强制 false。

use blstrs::{G1Projective, Scalar};

use super::bls_elgamal::ElGamalCiphertext;
use super::bls_scalar::{
    g1_is_identity, g1_generator, hash_to_scalar, parse_g1, parse_scalar, serialize_g1, verify_dleq,
};
use super::leave_proof::LeaveProof;
use super::reconstruct_proof::ReconstructProof;
use super::remask_proof::RemaskProof;
use super::reveal_token_proof::RevealTokenProof;
use super::shuffle_proof::ShuffleProof;
use super::transcript::Transcript;
use crate::error::PokerL1Result;

// ========== Transcript 工厂 ==========

/// 创建洗牌证明的 Transcript。
#[must_use]
pub fn new_shuffle_transcript() -> Transcript {
    Transcript::new(b"zk_shuffle_proof_v1")
}

/// 创建重掩码证明的 Transcript。
#[must_use]
pub fn new_remask_transcript() -> Transcript {
    Transcript::new(b"zk_remask_proof_v1")
}

/// 创建离场证明的 Transcript。
#[must_use]
pub fn new_leave_transcript() -> Transcript {
    Transcript::new(b"zk_leave_proof_v1")
}

/// 创建重建证明的 Transcript。
#[must_use]
pub fn new_reconstruct_transcript() -> Transcript {
    Transcript::new(b"zk_reconstruct_proof_v1")
}

/// 创建 remask + shuffle 共享 Transcript（用于 join_and_shuffle 场景）。
#[must_use]
pub fn new_mask_shuffle_transcript() -> Transcript {
    Transcript::new(b"zk_mask_shuffle_proof_v1")
}

// ========== 验证入口 ==========

/// 验证洗牌证明。
pub fn verify_shuffle(
    input_cts: &[ElGamalCiphertext],
    output_cts: &[ElGamalCiphertext],
    pk: &G1Projective,
    proof: &ShuffleProof,
) -> PokerL1Result<bool> {
    let mut t = new_shuffle_transcript();
    super::shuffle_proof::verify(proof, input_cts, output_cts, pk, &mut t)
}

/// 验证洗牌证明（使用外部 Transcript，用于 remask+shuffle 共享 transcript 场景）。
pub fn verify_shuffle_with_transcript(
    input_cts: &[ElGamalCiphertext],
    output_cts: &[ElGamalCiphertext],
    pk: &G1Projective,
    proof: &ShuffleProof,
    t: &mut Transcript,
) -> PokerL1Result<bool> {
    super::shuffle_proof::verify(proof, input_cts, output_cts, pk, t)
}

/// 验证重掩码证明。
pub fn verify_remask(
    input_cts: &[ElGamalCiphertext],
    output_cts: &[ElGamalCiphertext],
    player_pk: &G1Projective,
    proof: &RemaskProof,
) -> PokerL1Result<bool> {
    let mut t = new_remask_transcript();
    super::remask_proof::verify(proof, input_cts, output_cts, player_pk, &mut t)
}

/// 验证重掩码证明（使用外部 Transcript）。
pub fn verify_remask_with_transcript(
    input_cts: &[ElGamalCiphertext],
    output_cts: &[ElGamalCiphertext],
    player_pk: &G1Projective,
    proof: &RemaskProof,
    t: &mut Transcript,
) -> PokerL1Result<bool> {
    super::remask_proof::verify(proof, input_cts, output_cts, player_pk, t)
}

/// 验证离场证明。
pub fn verify_leave(
    input_cts: &[ElGamalCiphertext],
    output_cts: &[ElGamalCiphertext],
    player_pk: &G1Projective,
    proof: &LeaveProof,
) -> PokerL1Result<bool> {
    let mut t = new_leave_transcript();
    super::leave_proof::verify(proof, input_cts, output_cts, player_pk, &mut t)
}

/// 验证揭牌令牌证明。
///
/// 注意：此证明使用独立 transcript（`reveal_token_proof_v3`），不接收外部 transcript。
pub fn verify_reveal_token(
    encrypted_card: &ElGamalCiphertext,
    reveal_token: &G1Projective,
    expected_pk: &G1Projective,
    proof: &RevealTokenProof,
) -> PokerL1Result<bool> {
    super::reveal_token_proof::verify(proof, encrypted_card, reveal_token, expected_pk)
}

/// 验证重建证明。
pub fn verify_reconstruct(
    cards: &[G1Projective],
    output_cards: &[ElGamalCiphertext],
    swap_out_cards: &[ElGamalCiphertext],
    user_readable_cards: &[ElGamalCiphertext],
    user_pk: &G1Projective,
    proof: &ReconstructProof,
) -> PokerL1Result<bool> {
    let mut t = new_reconstruct_transcript();
    super::reconstruct_proof::verify(
        proof,
        cards,
        output_cards,
        swap_out_cards,
        user_readable_cards,
        user_pk,
        &mut t,
    )
}

// ========== PK 所有权证明 ==========

/// 验证 PK 所有权证明（Schnorr proof of knowledge of sk where pk = G · sk）。
///
/// `proof_bytes` 格式：commitment (48 bytes G1) + response (32 bytes scalar) = 80 bytes
///
/// 挑战派生：`challenge = hash_to_scalar(G_bytes || pk_bytes || commitment_bytes)`
/// （M-D12 修复：使用 `hash_to_scalar` 替代原始 SHA2-256，清除高位确保 < 曲线阶）
///
/// 验证等式：`G · response == commitment + pk · challenge`
pub fn verify_pk_ownership(pk: &G1Projective, proof_bytes: &[u8]) -> bool {
    // M-D11 修复：拒绝恒等元公钥
    if g1_is_identity(pk) {
        return false;
    }
    // 检查长度: 48 (commitment) + 32 (response) = 80
    if proof_bytes.len() != 80 {
        return false;
    }

    let g = g1_generator();
    let pk_bytes = serialize_g1(pk);
    let g_bytes = serialize_g1(&g);

    // 反序列化 commitment 和 response
    let commitment_bytes = &proof_bytes[0..48];
    let response_bytes = &proof_bytes[48..80];

    let commitment = match parse_g1(commitment_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let response = match parse_scalar(response_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 拒绝恒等元 commitment
    if g1_is_identity(&commitment) {
        return false;
    }

    // M-D12 修复：使用 hash_to_scalar 派生挑战
    // challenge = hash_to_scalar(G_bytes || pk_bytes || commitment_bytes)
    let mut hash_input = Vec::with_capacity(g_bytes.len() + pk_bytes.len() + commitment_bytes.len());
    hash_input.extend_from_slice(&g_bytes);
    hash_input.extend_from_slice(&pk_bytes);
    hash_input.extend_from_slice(commitment_bytes);
    let challenge = match hash_to_scalar(&hash_input) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 验证: G * response == commitment + pk * challenge
    verify_dleq(&g, pk, &commitment, &response, &challenge)
}

// ========== ZK skip 回退 ==========

/// dev chain 友好的 ZK skip 回退。
///
/// 若 `should_skip` 为 true，直接返回 true（跳过 ZK 验证）；
/// 否则调用 `verify_fn` 执行实际验证。
///
/// # 参数
///
/// - `should_skip`：是否跳过 ZK 验证（通常来自 `TableConfig::skip_*()`）
/// - `verify_fn`：实际验证函数（返回 `PokerL1Result<bool>`）
pub fn verify_or_skip<F>(should_skip: bool, verify_fn: F) -> PokerL1Result<bool>
where
    F: FnOnce() -> PokerL1Result<bool>,
{
    if should_skip {
        return Ok(true);
    }
    verify_fn()
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{g1_generator, g1_identity, hash_to_g1, scalar_from_u64};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_transcript_factories_produce_distinct_states() {
        let t1 = new_shuffle_transcript();
        let t2 = new_remask_transcript();
        let t3 = new_leave_transcript();
        let t4 = new_reconstruct_transcript();
        let t5 = new_mask_shuffle_transcript();
        // 所有 transcript 初始状态应互不相同
        let s1 = t1.state();
        let s2 = t2.state();
        let s3 = t3.state();
        let s4 = t4.state();
        let s5 = t5.state();
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s1, s4);
        assert_ne!(s1, s5);
        assert_ne!(s2, s3);
    }

    #[test]
    fn test_verify_or_skip_skip_mode() {
        let result = verify_or_skip(true, || Ok(false)).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_or_skip_no_skip_mode() {
        let result = verify_or_skip(false, || Ok(true)).unwrap();
        assert!(result);
        let result = verify_or_skip(false, || Ok(false)).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_pk_ownership_valid() {
        // 构造合法的 PK 所有权证明
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let g = g1_generator();

        // 链下构造 proof: commitment = G · omega, response = omega + challenge · sk
        use ff::Field;
        let omega = blstrs::Scalar::random(&mut rng);
        let commitment = g * omega;

        // challenge = hash_to_scalar(G || pk || commitment)
        let g_bytes = serialize_g1(&g);
        let pk_bytes = serialize_g1(&pk);
        let comm_bytes = serialize_g1(&commitment);
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&g_bytes);
        hash_input.extend_from_slice(&pk_bytes);
        hash_input.extend_from_slice(&comm_bytes);
        let challenge = hash_to_scalar(&hash_input).unwrap();

        let response = omega + challenge * sk;

        let mut proof_bytes = Vec::with_capacity(80);
        proof_bytes.extend_from_slice(&comm_bytes);
        proof_bytes.extend_from_slice(&super::super::bls_scalar::serialize_scalar(&response));

        assert!(verify_pk_ownership(&pk, &proof_bytes));
    }

    #[test]
    fn test_verify_pk_ownership_wrong_length_rejected() {
        let pk = g1_generator() * scalar_from_u64(123);
        let short_proof = vec![0u8; 79];
        assert!(!verify_pk_ownership(&pk, &short_proof));
    }

    #[test]
    fn test_verify_pk_ownership_identity_pk_rejected() {
        let identity = g1_identity();
        let proof = vec![0u8; 80];
        assert!(!verify_pk_ownership(&identity, &proof));
    }

    #[test]
    fn test_verify_pk_ownership_tampered_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let g = g1_generator();

        use ff::Field;
        let omega = blstrs::Scalar::random(&mut rng);
        let commitment = g * omega;

        let g_bytes = serialize_g1(&g);
        let pk_bytes = serialize_g1(&pk);
        let comm_bytes = serialize_g1(&commitment);
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&g_bytes);
        hash_input.extend_from_slice(&pk_bytes);
        hash_input.extend_from_slice(&comm_bytes);
        let challenge = hash_to_scalar(&hash_input).unwrap();

        let response = omega + challenge * sk;

        let mut proof_bytes = Vec::with_capacity(80);
        proof_bytes.extend_from_slice(&comm_bytes);
        proof_bytes.extend_from_slice(&super::super::bls_scalar::serialize_scalar(&response));

        // 篡改 response
        proof_bytes[48] ^= 0xFF;
        assert!(!verify_pk_ownership(&pk, &proof_bytes));
    }

    #[test]
    fn test_verify_reveal_token_via_zk_verifier() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let pt = hash_to_g1(b"card_0");
        let ct = super::super::bls_elgamal::encrypt(&pt, &pk, &scalar_from_u64(7));

        let (proof, reveal_token) =
            super::super::reveal_token_proof::prove(&ct, &sk, &pk, &mut rng).unwrap();
        let ok = verify_reveal_token(&ct, &reveal_token, &pk, &proof).unwrap();
        assert!(ok);
    }
}