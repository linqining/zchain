//! Reconstruct Proof（移植自 `texas_poker_move/sources/reconstruct_proof.move`）。
//!
//! 重建证明：验证玩家从加密牌组中正确重建了可读牌。
//!
//! # 结构
//!
//! - `SwapOutCardProof`：单张 swap-out 操作的 Chaum-Pedersen DLEq 证明
//! - `ReconstructionDLEQProof`：盲化 DLEQ 证明（points_out[i] = points_in[i] · blind）
//! - `ReconstructProof`：完整重建证明（含 swap_out_proofs + 盲化 DLEQ + 总 DLEQ + 3 层 Schnorr）
//!
//! # 验证流程（6 步）
//!
//! 1. 验证每个 swap_out_proof（Chaum-Pedersen DLEq）
//! 2. 生成 ρ_i 挑战，计算加权求和
//! 3. 验证 blind_dleq_proof（盲化 DLEQ）
//! 4. 验证 swap_combined_schnorr_proof（base = swap_out c1+c2，R = swap_sum_c1 + swap_sum_c2）
//! 5. 验证 sum_swap_out_c1_schnorr_proof 和 sum_swap_out_c2_schnorr_proof
//! 6. 验证 total_dleq_proof（log_G(user_pk) == log_{c1_total}(c2_total)）

use blstrs::{G1Projective, Scalar};

use super::bls_elgamal::ElGamalCiphertext;
use super::bls_scalar::{
    g1_add, g1_is_identity, g1_mul, g1_sub, g1_msm, g1_generator, parse_g1, parse_scalar,
    serialize_g1,
};
use super::chaum_pedersen::{self, ChaumPedersenProof};
use super::schnorr_proof::{self, GeneralizedSchnorrProof};
use super::transcript::Transcript;
use crate::error::PokerL1Result;

/// SwapOutCardProof：单张 swap-out 操作的证明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapOutCardProof {
    /// 序列化的 user_readable_card（96 字节：c1+c2）。
    pub user_readable_card: Vec<u8>,
    /// 序列化的 swap_out_card（96 字节：c1+c2）。
    pub swap_out_card: Vec<u8>,
    /// Chaum-Pedersen DLEq 证明。
    pub chaum_pedersen_proof: ChaumPedersenProof,
}

impl SwapOutCardProof {
    /// 构造 SwapOutCardProof。
    pub fn new(
        user_readable_card: Vec<u8>,
        swap_out_card: Vec<u8>,
        chaum_pedersen_proof: ChaumPedersenProof,
    ) -> Self {
        Self {
            user_readable_card,
            swap_out_card,
            chaum_pedersen_proof,
        }
    }
}

/// ReconstructionDLEQProof：盲化 DLEQ 证明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructionDLEQProof {
    /// `A = sum_point_total · w`（48 字节 G1 compressed）。
    pub commitment: Vec<u8>,
    /// `s = w + a · c`（32 字节 Scalar）。
    pub response: Vec<u8>,
    /// anti-replay nonce（32 字节 Scalar）。
    pub nonce: Vec<u8>,
}

impl ReconstructionDLEQProof {
    /// 构造 ReconstructionDLEQProof。
    pub fn new(commitment: Vec<u8>, response: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self {
            commitment,
            response,
            nonce,
        }
    }
}

/// ReconstructProof：完整重建证明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructProof {
    /// 每个 swap-out 的证明。
    pub swap_out_proofs: Vec<SwapOutCardProof>,
    /// 盲化后的 output c1 加权和（48 字节 G1 compressed）。
    pub sum_c1_r_commit: Vec<u8>,
    /// 盲化后的 (output c2 - card) 加权和（48 字节 G1 compressed）。
    pub sum_c2_r_commit: Vec<u8>,
    /// swap_out c1 加权和（48 字节 G1 compressed）。
    pub swap_sum_c1_commit: Vec<u8>,
    /// swap_out c2 加权和（48 字节 G1 compressed）。
    pub swap_sum_c2_commit: Vec<u8>,
    /// anti-replay nonce（32 字节 Scalar）。
    pub nonce: Vec<u8>,
    /// 盲化 DLEQ 证明。
    pub blind_dleq_proof: ReconstructionDLEQProof,
    /// 总 DLEQ 证明（Chaum-Pedersen）。
    pub total_dleq_proof: ChaumPedersenProof,
    /// swap 组合 Schnorr 证明。
    pub swap_combined_schnorr_proof: GeneralizedSchnorrProof,
    /// swap c1 Schnorr 证明。
    pub sum_swap_out_c1_schnorr_proof: GeneralizedSchnorrProof,
    /// swap c2 Schnorr 证明。
    pub sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProof,
}

impl ReconstructProof {
    /// 构造 ReconstructProof。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        swap_out_proofs: Vec<SwapOutCardProof>,
        sum_c1_r_commit: Vec<u8>,
        sum_c2_r_commit: Vec<u8>,
        swap_sum_c1_commit: Vec<u8>,
        swap_sum_c2_commit: Vec<u8>,
        nonce: Vec<u8>,
        blind_dleq_proof: ReconstructionDLEQProof,
        total_dleq_proof: ChaumPedersenProof,
        swap_combined_schnorr_proof: GeneralizedSchnorrProof,
        sum_swap_out_c1_schnorr_proof: GeneralizedSchnorrProof,
        sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProof,
    ) -> Self {
        Self {
            swap_out_proofs,
            sum_c1_r_commit,
            sum_c2_r_commit,
            swap_sum_c1_commit,
            swap_sum_c2_commit,
            nonce,
            blind_dleq_proof,
            total_dleq_proof,
            swap_combined_schnorr_proof,
            sum_swap_out_c1_schnorr_proof,
            sum_swap_out_c2_schnorr_proof,
        }
    }
}

/// 验证 ReconstructProof。
///
/// # 参数
///
/// - `proof`：证明结构
/// - `cards`：明文牌点
/// - `output_cards`：重建后的输出密文
/// - `swap_out_cards`：swap-out 牌密文
/// - `user_readable_cards`：用户可读牌密文
/// - `user_pk`：用户公钥
/// - `t`：Fiat-Shamir transcript
#[allow(clippy::too_many_arguments)]
pub fn verify(
    proof: &ReconstructProof,
    cards: &[G1Projective],
    output_cards: &[ElGamalCiphertext],
    swap_out_cards: &[ElGamalCiphertext],
    user_readable_cards: &[ElGamalCiphertext],
    user_pk: &G1Projective,
    t: &mut Transcript,
) -> PokerL1Result<bool> {
    let n = proof.swap_out_proofs.len();
    let g = g1_generator();

    // M1: 校验 cards 与 output_cards 长度一致
    if cards.len() != output_cards.len() {
        return Ok(false);
    }

    // ===== Step 1: 验证 swap_out_proofs =====
    if n != user_readable_cards.len() {
        return Ok(false);
    }
    if swap_out_cards.len() != n {
        return Ok(false);
    }

    for i in 0..n {
        let sop = &proof.swap_out_proofs[i];
        // M2: 校验字节长度
        if sop.user_readable_card.len() != 96 {
            return Ok(false);
        }
        if sop.swap_out_card.len() != 96 {
            return Ok(false);
        }
        // 反序列化
        let deser_readable = match ElGamalCiphertext::from_bytes(&sop.user_readable_card) {
            Ok(ct) => ct,
            Err(_) => return Ok(false),
        };
        let deser_swap_out = match ElGamalCiphertext::from_bytes(&sop.swap_out_card) {
            Ok(ct) => ct,
            Err(_) => return Ok(false),
        };

        // 验证反序列化的 user_readable_card == user_readable_cards[i]
        if deser_readable.c1 != user_readable_cards[i].c1
            || deser_readable.c2 != user_readable_cards[i].c2
        {
            return Ok(false);
        }
        // 验证反序列化的 swap_out_card == swap_out_cards[i]
        if deser_swap_out.c1 != swap_out_cards[i].c1
            || deser_swap_out.c2 != swap_out_cards[i].c2
        {
            return Ok(false);
        }

        // delta_c1 = swap_out.c1 - user_readable.c1
        let delta_c1 = g1_sub(&deser_swap_out.c1, &deser_readable.c1);
        // delta_c2 = swap_out.c2 - user_readable.c2
        let delta_c2 = g1_sub(&deser_swap_out.c2, &deser_readable.c2);

        // 验证 Chaum-Pedersen: log_{delta_c1}(delta_c2) == log_G(user_pk)
        if !chaum_pedersen::verify(
            &sop.chaum_pedersen_proof,
            &delta_c1,
            &g,
            &delta_c2,
            user_pk,
            t,
        )? {
            return Ok(false);
        }
    }

    // ===== Step 2: 生成 rho_i 挑战 =====
    t.append_points(b"reconstruct_card", cards);
    for ct in output_cards {
        t.append_point(b"reconstruct_output_c1", &ct.c1);
    }
    for ct in output_cards {
        t.append_point(b"reconstruct_output_c2", &ct.c2);
    }
    let rho = t.challenge_vec(b"reconstruct_rho", output_cards.len())?;

    // ===== Step 3: 计算加权求和 =====
    let output_c1s: Vec<G1Projective> = output_cards.iter().map(|ct| ct.c1).collect();
    let sum_output_c1 = g1_msm(&rho, &output_c1s)?;

    let c2_minus_cards: Vec<G1Projective> = (0..output_cards.len())
        .map(|i| g1_sub(&output_cards[i].c2, &cards[i]))
        .collect();
    let sum_output_c2_minus_cards = g1_msm(&rho, &c2_minus_cards)?;

    // ===== Step 4: 验证 blind_dleq_proof =====
    let points_in_0 = sum_output_c1;
    let points_in_1 = sum_output_c2_minus_cards;
    let points_out_0 = match parse_g1(&proof.sum_c1_r_commit) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let points_out_1 = match parse_g1(&proof.sum_c2_r_commit) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    // 4.1 追加 nonce
    let blind_nonce = match parse_scalar(&proof.blind_dleq_proof.nonce) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    t.append_scalar(b"reconstruct_blind_nonce", &blind_nonce);

    // 4.2 追加 points_in 和 points_out
    t.append_point(b"reconstruct_blind_in_0", &points_in_0);
    t.append_point(b"reconstruct_blind_in_1", &points_in_1);
    t.append_point(b"reconstruct_blind_out_0", &points_out_0);
    t.append_point(b"reconstruct_blind_out_1", &points_out_1);

    // 4.3 提取 base_coefficient
    let base_coeff = t.challenge(b"reconstruct_base_coeff")?;

    // 4.4 sum_point_in_total = points_in[0] + points_in[1] * base_coeff
    let points_in_1_scaled = g1_mul(&base_coeff, &points_in_1);
    let sum_point_in_total = g1_add(&points_in_0, &points_in_1_scaled);

    // 4.5 sum_point_out_total = points_out[0] + points_out[1] * base_coeff
    let points_out_1_scaled = g1_mul(&base_coeff, &points_out_1);
    let sum_point_out_total = g1_add(&points_out_0, &points_out_1_scaled);

    // 4.6 追加 commitment
    let blind_commitment = match parse_g1(&proof.blind_dleq_proof.commitment) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    if g1_is_identity(&blind_commitment) {
        return Ok(false);
    }
    t.append_point(b"reconstruct_blind_commitment", &blind_commitment);

    // 4.7 提取挑战 c
    let blind_c = t.challenge(b"reconstruct_blind_challenge")?;

    // 4.8 验证: sum_point_in_total * response == commitment + sum_point_out_total * c
    let blind_s = match parse_scalar(&proof.blind_dleq_proof.response) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    if !super::bls_scalar::verify_dleq(
        &sum_point_in_total,
        &sum_point_out_total,
        &blind_commitment,
        &blind_s,
        &blind_c,
    ) {
        return Ok(false);
    }

    // ===== Step 5: 验证 swap Schnorr proofs（3 层）=====

    // 5.1 swap combined: base_points = [swap_out[0].c1, swap_out[0].c2, ..., swap_out[n-1].c1, swap_out[n-1].c2]
    // （交错布局，与 Move 端一致；witnesses 也对应交错）
    // R = swap_sum_c1 + swap_sum_c2
    let mut combined_base_points = Vec::with_capacity(2 * n);
    for ct in swap_out_cards {
        combined_base_points.push(ct.c1);
        combined_base_points.push(ct.c2);
    }
    let swap_sum_c1_commit_pt = match parse_g1(&proof.swap_sum_c1_commit) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let swap_sum_c2_commit_pt = match parse_g1(&proof.swap_sum_c2_commit) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    if g1_is_identity(&swap_sum_c1_commit_pt) || g1_is_identity(&swap_sum_c2_commit_pt) {
        return Ok(false);
    }
    let combined_r = g1_add(&swap_sum_c1_commit_pt, &swap_sum_c2_commit_pt);

    if !schnorr_proof::verify(
        &proof.swap_combined_schnorr_proof,
        &combined_base_points,
        &combined_r,
        t,
    )? {
        return Ok(false);
    }

    // 5.2 c1 Schnorr: base_points = [swap_out[0].c1, ..., swap_out[n-1].c1]
    let c1_base_points: Vec<G1Projective> = swap_out_cards.iter().map(|ct| ct.c1).collect();
    if !schnorr_proof::verify(
        &proof.sum_swap_out_c1_schnorr_proof,
        &c1_base_points,
        &swap_sum_c1_commit_pt,
        t,
    )? {
        return Ok(false);
    }

    // 5.3 c2 Schnorr: base_points = [swap_out[0].c2, ..., swap_out[n-1].c2]
    let c2_base_points: Vec<G1Projective> = swap_out_cards.iter().map(|ct| ct.c2).collect();
    if !schnorr_proof::verify(
        &proof.sum_swap_out_c2_schnorr_proof,
        &c2_base_points,
        &swap_sum_c2_commit_pt,
        t,
    )? {
        return Ok(false);
    }

    // ===== Step 6: 验证 total_dleq_proof =====
    let c1_total = g1_add(&points_out_0, &swap_sum_c1_commit_pt);
    let c2_total = g1_add(&points_out_1, &swap_sum_c2_commit_pt);

    if !chaum_pedersen::verify(
        &proof.total_dleq_proof,
        &g,
        &c1_total,
        user_pk,
        &c2_total,
        t,
    )? {
        return Ok(false);
    }

    Ok(true)
}

// ===== 链下 prove =====

#[cfg(any(test, feature = "client"))]
mod prove {
    use super::*;
    use super::super::bls_scalar::serialize_scalar;
    use ff::Field;
    use rand::Rng;

    /// 链下生成 ReconstructProof。
    ///
    /// # 参数
    ///
    /// - `cards`：明文牌点
    /// - `output_cards`：重建后的输出密文（玩家计算得到）
    /// - `user_readable_cards`：用户可读牌密文（玩家持有一部分私钥后能解密的牌）
    /// - `swap_r`：每张 swap-out 牌的随机掩码 `r_i`
    /// - `user_sk`：用户私钥
    /// - `user_pk`：用户公钥 `G · user_sk`
    /// - `t`：Fiat-Shamir transcript
    ///
    /// # Returns
    ///
    /// `(proof, swap_out_cards)` — 证明和 swap-out 牌密文。
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        cards: &[G1Projective],
        output_cards: &[ElGamalCiphertext],
        user_readable_cards: &[ElGamalCiphertext],
        swap_r: &[Scalar],
        user_sk: &Scalar,
        user_pk: &G1Projective,
        t: &mut Transcript,
        rng: &mut impl Rng,
    ) -> PokerL1Result<(ReconstructProof, Vec<ElGamalCiphertext>)> {
        let n = user_readable_cards.len();
        assert_eq!(cards.len(), output_cards.len(), "cards 与 output_cards 长度必须相同");
        assert_eq!(swap_r.len(), n, "swap_r 长度必须等于 user_readable_cards");

        let g = g1_generator();

        // 1. 计算 swap_out_cards[i] = re_encrypt(user_readable_cards[i], user_pk, swap_r[i])
        let swap_out_cards: Vec<ElGamalCiphertext> = (0..n)
            .map(|i| {
                let ur = &user_readable_cards[i];
                let g_r = g1_mul(&swap_r[i], &g);
                let pk_r = g1_mul(&swap_r[i], user_pk);
                ElGamalCiphertext::new(g1_add(&ur.c1, &g_r), g1_add(&ur.c2, &pk_r))
            })
            .collect();

        // 2. 为每张牌生成 Chaum-Pedersen 证明
        // delta_c1 = swap_out.c1 - user_readable.c1 = swap_r · G
        // delta_c2 = swap_out.c2 - user_readable.c2 = swap_r · user_pk
        // 证明 log_{delta_c1}(delta_c2) == log_G(user_pk) == user_sk
        // 即 x = user_sk 使得 p1 = x · delta_c1 = delta_c2, p2 = x · G = user_pk
        let mut swap_out_proofs = Vec::with_capacity(n);
        for i in 0..n {
            let ur = &user_readable_cards[i];
            let soc = &swap_out_cards[i];
            let delta_c1 = g1_sub(&soc.c1, &ur.c1);
            // delta_c2 不需要参与 prove（prove 自动计算 p1 = x · g1）
            let cp_proof = chaum_pedersen::prove(&delta_c1, &g, user_sk, t, rng)?;
            let readable_bytes = ur.to_bytes().to_vec();
            let swap_bytes = soc.to_bytes().to_vec();
            swap_out_proofs.push(SwapOutCardProof::new(readable_bytes, swap_bytes, cp_proof));
        }

        // 3. Step 2 transcript：追加 cards + output_cards c1/c2 + 生成 rho
        t.append_points(b"reconstruct_card", cards);
        for ct in output_cards {
            t.append_point(b"reconstruct_output_c1", &ct.c1);
        }
        for ct in output_cards {
            t.append_point(b"reconstruct_output_c2", &ct.c2);
        }
        let rho = t.challenge_vec(b"reconstruct_rho", output_cards.len())?;

        // 4. 计算加权求和
        let output_c1s: Vec<G1Projective> = output_cards.iter().map(|ct| ct.c1).collect();
        let sum_output_c1 = g1_msm(&rho, &output_c1s)?;
        let c2_minus_cards: Vec<G1Projective> = (0..output_cards.len())
            .map(|i| g1_sub(&output_cards[i].c2, &cards[i]))
            .collect();
        let sum_output_c2_minus_cards = g1_msm(&rho, &c2_minus_cards)?;

        // 5. Step 4: 盲化 DLEQ proof
        // 生成盲化因子 blind，points_out[i] = points_in[i] · blind
        let blind = Scalar::random(&mut *rng);
        let points_out_0 = g1_mul(&blind, &sum_output_c1);
        let points_out_1 = g1_mul(&blind, &sum_output_c2_minus_cards);

        let blind_nonce = Scalar::random(&mut *rng);
        t.append_scalar(b"reconstruct_blind_nonce", &blind_nonce);
        t.append_point(b"reconstruct_blind_in_0", &sum_output_c1);
        t.append_point(b"reconstruct_blind_in_1", &sum_output_c2_minus_cards);
        t.append_point(b"reconstruct_blind_out_0", &points_out_0);
        t.append_point(b"reconstruct_blind_out_1", &points_out_1);
        let base_coeff = t.challenge(b"reconstruct_base_coeff")?;
        let points_in_1_scaled = g1_mul(&base_coeff, &sum_output_c2_minus_cards);
        let sum_point_in_total = g1_add(&sum_output_c1, &points_in_1_scaled);
        let points_out_1_scaled = g1_mul(&base_coeff, &points_out_1);
        let sum_point_out_total = g1_add(&points_out_0, &points_out_1_scaled);

        // 盲化承诺 w，commitment = w · sum_point_in_total
        let w = Scalar::random(&mut *rng);
        let blind_commitment = g1_mul(&w, &sum_point_in_total);
        t.append_point(b"reconstruct_blind_commitment", &blind_commitment);
        let blind_c = t.challenge(b"reconstruct_blind_challenge")?;
        // response = w + blind · c
        let blind_s = w + blind_c * blind;
        let blind_dleq_proof = ReconstructionDLEQProof::new(
            serialize_g1(&blind_commitment).to_vec(),
            serialize_scalar(&blind_s).to_vec(),
            serialize_scalar(&blind_nonce).to_vec(),
        );

        // 6. Step 5: swap Schnorr proofs
        // 6.1 swap combined: base_points 交错 [c1_0, c2_0, c1_1, c2_1, ...]
        // witnesses 交错 [ρ_0, ρ_0, ρ_1, ρ_1, ...]（使 R = Σ ρ_i · (c1_i + c2_i)）
        let mut combined_base_points = Vec::with_capacity(2 * n);
        let mut combined_witnesses = Vec::with_capacity(2 * n);
        for i in 0..n {
            combined_base_points.push(swap_out_cards[i].c1);
            combined_base_points.push(swap_out_cards[i].c2);
            combined_witnesses.push(rho[i]);
            combined_witnesses.push(rho[i]);
        }
        // swap_sum_c1 = Σ ρ_i · swap_out[i].c1, swap_sum_c2 = Σ ρ_i · swap_out[i].c2
        let swap_c1s: Vec<G1Projective> = swap_out_cards.iter().map(|ct| ct.c1).collect();
        let swap_c2s: Vec<G1Projective> = swap_out_cards.iter().map(|ct| ct.c2).collect();
        let swap_sum_c1 = g1_msm(&rho, &swap_c1s)?;
        let swap_sum_c2 = g1_msm(&rho, &swap_c2s)?;
        let combined_r = g1_add(&swap_sum_c1, &swap_sum_c2);

        let (swap_combined_schnorr_proof, _schnorr_r_combined) =
            schnorr_proof::prove(&combined_base_points, &combined_witnesses, t, rng)?;

        // 6.2 c1-only Schnorr: base = [c1_0, ..., c1_{n-1}], witnesses = [ρ_0, ..., ρ_{n-1}]
        let c1_base_points: Vec<G1Projective> = swap_out_cards.iter().map(|ct| ct.c1).collect();
        let (sum_swap_out_c1_schnorr_proof, _) =
            schnorr_proof::prove(&c1_base_points, &rho, t, rng)?;

        // 6.3 c2-only Schnorr: base = [c2_0, ..., c2_{n-1}], witnesses = [ρ_0, ..., ρ_{n-1}]
        let c2_base_points: Vec<G1Projective> = swap_out_cards.iter().map(|ct| ct.c2).collect();
        let (sum_swap_out_c2_schnorr_proof, _) =
            schnorr_proof::prove(&c2_base_points, &rho, t, rng)?;

        // 7. Step 6: total DLEQ proof
        // c1_total = sum_c1_r + swap_sum_c1 = blind · sum_output_c1 + swap_sum_c1
        // c2_total = sum_c2_r + swap_sum_c2 = blind · sum_output_c2_minus_cards + swap_sum_c2
        // 证明 log_G(user_pk) == log_{c1_total}(c2_total) == user_sk
        // 这要求 c2_total = user_sk · c1_total
        // 但实际上：sum_output_c2_minus_cards = Σ ρ_i · (output_c2_i - card_i) = Σ ρ_i · (output_c2_i - M_i)
        //   其中 M_i 是明文，output_c2_i = M_i + r_i · aggregate_pk
        //   所以 output_c2_i - M_i = r_i · aggregate_pk
        //   sum_output_c2_minus_cards = Σ ρ_i · r_i · aggregate_pk
        // sum_output_c1 = Σ ρ_i · output_c1_i = Σ ρ_i · r_i · G
        // 所以 sum_output_c2_minus_cards = aggregate_sk · sum_output_c1
        // 但 blind · sum_output_c2_minus_cards = blind · aggregate_sk · sum_output_c1
        //   = aggregate_sk · (blind · sum_output_c1) = aggregate_sk · points_out_0
        // 类似 swap_sum_c2 与 swap_sum_c1 的关系：swap_out_card = re_encrypt(user_readable, user_pk, swap_r)
        //   swap_out.c1 = ur.c1 + swap_r · G, swap_out.c2 = ur.c2 + swap_r · user_pk
        //   swap_sum_c1 = Σ ρ_i · (ur.c1_i + swap_r_i · G) = Σ ρ_i · ur.c1_i + (Σ ρ_i · swap_r_i) · G
        //   swap_sum_c2 = Σ ρ_i · (ur.c2_i + swap_r_i · user_pk) = Σ ρ_i · ur.c2_i + (Σ ρ_i · swap_r_i) · user_pk
        //   若 user_readable_cards 与 output_cards 同源（同样 r_i），则 ur.c2_i = ur.c1_i · aggregate_sk
        //   → swap_sum_c2 = aggregate_sk · Σ ρ_i · ur.c1_i + (Σ ρ_i · swap_r_i) · user_pk
        //   而 swap_sum_c1 · user_sk = user_sk · Σ ρ_i · ur.c1_i + (Σ ρ_i · swap_r_i) · user_pk
        //   所以 swap_sum_c2 = swap_sum_c1 · user_sk 当且仅当 aggregate_sk = user_sk
        // 但这里 aggregate_sk != user_sk 通常（aggregate 是所有玩家 sk 之和）
        // 所以 total_dleq 实际证明的是 c2_total / c1_total = user_sk，这要求 blind · sum_output_c2_minus_cards + swap_sum_c2 = user_sk · (points_out_0 + swap_sum_c1)
        // 这需要特殊构造 output_cards 和 user_readable_cards
        // 此处 prove 是 player-side 的，假设 player 持有正确的关系
        let c1_total = g1_add(&points_out_0, &swap_sum_c1);
        let c2_total = g1_add(&points_out_1, &swap_sum_c2);
        // 用 user_sk 作为 x，g1=g, g2=c1_total → p1=g·user_sk=user_pk, p2=c1_total·user_sk=c2_total
        let total_dleq_proof = chaum_pedersen::prove(&g, &c1_total, user_sk, t, rng)?;

        let nonce_scalar = Scalar::random(&mut *rng);
        let proof = ReconstructProof::new(
            swap_out_proofs,
            serialize_g1(&points_out_0).to_vec(),
            serialize_g1(&points_out_1).to_vec(),
            serialize_g1(&swap_sum_c1).to_vec(),
            serialize_g1(&swap_sum_c2).to_vec(),
            serialize_scalar(&nonce_scalar).to_vec(),
            blind_dleq_proof,
            total_dleq_proof,
            swap_combined_schnorr_proof,
            sum_swap_out_c1_schnorr_proof,
            sum_swap_out_c2_schnorr_proof,
        );
        Ok((proof, swap_out_cards))
    }
}

#[cfg(any(test, feature = "client"))]
pub use prove::prove;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{g1_generator, hash_to_g1, scalar_from_u64};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_transcript() -> Transcript {
        Transcript::new(b"test_reconstruct_protocol")
    }

    /// 构造测试场景：1 张牌，1 个玩家，user_sk == aggregate_sk（最简单情形）。
    /// 关键关系：
    /// - output_cards[i].c2 = cards[i] + user_sk · output_cards[i].c1（用 user_pk 加密的明文）
    /// - user_readable_cards[i].c2 = user_sk · user_readable_cards[i].c1（加密零）
    /// - swap_out_cards[i] = re_encrypt(user_readable_cards[i], user_pk, swap_r[i])
    #[test]
    fn test_prove_verify_roundtrip_single_card() {
        let mut rng = StdRng::seed_from_u64(42);
        let user_sk = scalar_from_u64(123_456);
        let user_pk = g1_generator() * user_sk;
        let g = g1_generator();

        // 单张牌
        let plaintext = hash_to_g1(b"card_0");
        let cards = vec![plaintext];

        // output_cards: 用 user_pk 加密明文（c2 = plaintext + r · user_pk = cards + user_sk · c1）
        let r_out = scalar_from_u64(7);
        let output_ct = super::super::bls_elgamal::encrypt(&plaintext, &user_pk, &r_out);
        let output_cards = vec![output_ct];

        // user_readable_cards: 加密零（c2 = r' · user_pk = user_sk · c1）
        let r_ur = scalar_from_u64(11);
        let ur_ct = ElGamalCiphertext::new(g1_mul(&r_ur, &g), g1_mul(&r_ur, &user_pk));
        let user_readable_cards = vec![ur_ct];

        // swap_r: 单张牌的 swap-out 随机数
        let swap_r = vec![scalar_from_u64(99)];

        let mut t_prove = make_transcript();
        let (proof, _swap_out_cards) = prove(
            &cards,
            &output_cards,
            &user_readable_cards,
            &swap_r,
            &user_sk,
            &user_pk,
            &mut t_prove,
            &mut rng,
        )
        .unwrap();

        let mut t_verify = make_transcript();
        // 重新计算 swap_out_cards（prove 内部已生成）
        let swap_out_cards: Vec<ElGamalCiphertext> = (0..user_readable_cards.len())
            .map(|i| {
                let ur = &user_readable_cards[i];
                let g_r = g1_mul(&swap_r[i], &g);
                let pk_r = g1_mul(&swap_r[i], &user_pk);
                ElGamalCiphertext::new(g1_add(&ur.c1, &g_r), g1_add(&ur.c2, &pk_r))
            })
            .collect();

        let ok = verify(
            &proof,
            &cards,
            &output_cards,
            &swap_out_cards,
            &user_readable_cards,
            &user_pk,
            &mut t_verify,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn test_verify_length_mismatch_cards_output_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let user_sk = scalar_from_u64(123_456);
        let user_pk = g1_generator() * user_sk;

        let plaintext = hash_to_g1(b"card_0");
        let r = scalar_from_u64(7);
        let output_ct = super::super::bls_elgamal::encrypt(&plaintext, &user_pk, &r);

        // cards 与 output_cards 长度不一致
        let cards = vec![plaintext, hash_to_g1(b"extra")];
        let output_cards = vec![output_ct];
        let user_readable_cards = vec![output_ct];
        let swap_r = vec![scalar_from_u64(99)];

        let mut t_prove = make_transcript();
        // prove 会 panic 因长度不一致，所以直接构造空 proof 测 verify
        let _ = (cards.len(), output_cards.len(), &mut rng, &swap_r, &user_sk, &user_pk, &mut t_prove);

        // 直接构造 dummy proof 测试 verify
        let dummy_cp = ChaumPedersenProof::new(vec![0u8; 48], vec![0u8; 48], vec![0u8; 32]);
        let dummy_schnorr = GeneralizedSchnorrProof::new(vec![0u8; 48], vec![vec![0u8; 32]]);
        let dummy_blind = ReconstructionDLEQProof::new(vec![0u8; 48], vec![0u8; 32], vec![0u8; 32]);
        let empty_proof = ReconstructProof::new(
            vec![],
            vec![0u8; 48],
            vec![0u8; 48],
            vec![0u8; 48],
            vec![0u8; 48],
            vec![0u8; 32],
            dummy_blind,
            dummy_cp.clone(),
            dummy_schnorr.clone(),
            dummy_schnorr.clone(),
            dummy_schnorr,
        );

        let mut t_verify = make_transcript();
        let ok = verify(
            &empty_proof,
            &cards,
            &output_cards,
            &[],
            &[],
            &user_pk,
            &mut t_verify,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_swap_out_length_mismatch_rejected() {
        let user_sk = scalar_from_u64(123_456);
        let user_pk = g1_generator() * user_sk;
        let plaintext = hash_to_g1(b"card_0");
        let r = scalar_from_u64(7);
        let output_ct = super::super::bls_elgamal::encrypt(&plaintext, &user_pk, &r);

        let cards = vec![plaintext];
        let output_cards = vec![output_ct];
        let user_readable_cards = vec![output_ct];
        // swap_out_cards 长度与 swap_out_proofs 不一致
        let swap_out_cards = vec![output_ct, output_ct];

        let dummy_cp = ChaumPedersenProof::new(vec![0u8; 48], vec![0u8; 48], vec![0u8; 32]);
        let dummy_schnorr = GeneralizedSchnorrProof::new(vec![0u8; 48], vec![vec![0u8; 32]]);
        let dummy_blind = ReconstructionDLEQProof::new(vec![0u8; 48], vec![0u8; 32], vec![0u8; 32]);
        // 1 个 swap_out_proof 但 2 个 swap_out_cards
        let swap_out_proof = SwapOutCardProof::new(
            output_ct.to_bytes().to_vec(),
            output_ct.to_bytes().to_vec(),
            dummy_cp.clone(),
        );
        let proof = ReconstructProof::new(
            vec![swap_out_proof],
            vec![0u8; 48],
            vec![0u8; 48],
            vec![0u8; 48],
            vec![0u8; 48],
            vec![0u8; 32],
            dummy_blind,
            dummy_cp,
            dummy_schnorr.clone(),
            dummy_schnorr.clone(),
            dummy_schnorr,
        );

        let mut t_verify = make_transcript();
        let ok = verify(
            &proof,
            &cards,
            &output_cards,
            &swap_out_cards,
            &user_readable_cards,
            &user_pk,
            &mut t_verify,
        )
        .unwrap();
        assert!(!ok);
    }
}
