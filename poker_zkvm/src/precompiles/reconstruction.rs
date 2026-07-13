//! Reconstruction proof（Phase M — M-6）。
//!
//! 完整移植 poker_protocol `reconstruction/mod.rs` + `swap_out.rs`。
//!
//! # 三个结构体
//!
//! - [`ReconstructionDLEQProof`] — blind DLEq，证明 points_in 和 points_out 共享同一 blind
//! - [`SwapOutCardProof`] — 证明 swap_out_card 由 user_readable_card 替换而出（委托 ChaumPedersen）
//! - [`ReconstructProof`] — 组合证明，包含 11 个字段，10+ 顺序 transcript 步骤
//!
//! # transcript 标签（完全匹配 poker_protocol）
//!
//! `reconstruct_card` / `reconstruct_output_c1` / `reconstruct_output_c2` / `reconstruct_rho`
//! / `reconstruct_blind_nonce` / `reconstruct_blind_in_{i}` / `reconstruct_blind_out_{i}`
//! / `reconstruct_base_coeff` / `reconstruct_blind_commitment` / `reconstruct_blind_challenge`
//!
//! 兼容 Move 合约：nonce 不参与 transcript，仅作为结构体字段（防重放）。

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_std::rand::Rng;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use crate::precompiles::chaum_pedersen::ChaumPedersenDLEQProof;
use crate::precompiles::elgamal::{ElGamalCiphertext, ElGamalPublicKey};
use crate::precompiles::generalized_schnorr::GeneralizedSchnorrProof;
use crate::precompiles::poker_transcript::{
    PokerTranscript, compress_g1, decompress_g1, fr_from_32bytes, fr_to_32bytes,
};

// ===== 辅助函数 =====

/// 幂迭代：x^0, x^1, x^2, ...
pub fn exp_iter(x: Fr) -> impl Iterator<Item = Fr> {
    std::iter::successors(Some(Fr::one()), move |acc| Some(*acc * x))
}

/// 从 output_cards 和 user_sk 派生 coefficient（Blake2b256 → Fr）。
pub fn derive_from_output_cards(output_cards: &[ElGamalCiphertext], user_sk: &Fr) -> Fr {
    let mut sum_c1 = G1Projective::zero();
    let mut sum_c2 = G1Projective::zero();
    for ct in output_cards {
        sum_c1 += G1Projective::from(ct.c);
        sum_c2 += G1Projective::from(ct.d);
    }
    let sum_c1_sk = sum_c1 * user_sk;
    let sum_c2_sk = sum_c2 * user_sk;

    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"derive_from_output_cards_v1:");
    buffer.extend_from_slice(&compress_g1(&sum_c1_sk.into_affine()));
    buffer.extend_from_slice(&compress_g1(&sum_c2_sk.into_affine()));

    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
    hasher.update(&buffer);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("finalize");
    let bigint = ark_ff::BigInt::<4>::new([
        u64::from_le_bytes(out[0..8].try_into().unwrap()),
        u64::from_le_bytes(out[8..16].try_into().unwrap()),
        u64::from_le_bytes(out[16..24].try_into().unwrap()),
        u64::from_le_bytes(out[24..32].try_into().unwrap()),
    ]);
    Fr::from_bigint(bigint).unwrap_or_else(Fr::zero)
}

/// 重建牌组：从 cards + user_readable_cards 生成 output_cards 和 swap_out_cards。
///
/// 返回 (s_vec, output_cards, swap_out_cards)。
#[allow(clippy::type_complexity)]
pub fn reconstruct_deck(
    cards: &[G1Affine],
    user_readable_cards: &[ElGamalCiphertext],
    user_sk: &Fr,
    user_pk: &G1Affine,
    coefficient: &Fr,
) -> Option<(
    Vec<Fr>,
    Vec<ElGamalCiphertext>,
    Vec<(usize, ElGamalCiphertext)>,
)> {
    if user_readable_cards.is_empty() {
        return None;
    }
    if coefficient.is_zero() || coefficient == &Fr::one() {
        return None;
    }

    let pk = ElGamalPublicKey { pk: *user_pk };

    // 解密 user_readable_cards 获取明文
    let mut user_plain_card = Vec::new();
    for user_readable_card in user_readable_cards {
        let plaintext = crate::precompiles::elgamal::decrypt(
            &crate::precompiles::elgamal::ElGamalSecretKey { sk: *user_sk },
            user_readable_card,
        );
        if !cards.contains(&plaintext) {
            return None;
        }
        user_plain_card.push(plaintext);
    }

    // 构造 s_vec = [1, coeff, coeff^2, ..., coeff^(n+k-1)]
    let s_vec: Vec<Fr> = exp_iter(*coefficient)
        .take(cards.len() + user_readable_cards.len())
        .collect();

    // 生成 output_cards
    let output_cards: Vec<ElGamalCiphertext> = cards
        .iter()
        .enumerate()
        .map(|(i, card)| {
            let mut enc_card = crate::precompiles::elgamal::encrypt(&pk, card, &s_vec[i]);
            if user_plain_card.contains(card) {
                // 用户可读卡：从 d 中减去明文，使用户解密得到 0
                enc_card.d =
                    (G1Projective::from(enc_card.d) - G1Projective::from(*card)).into_affine();
            }
            enc_card
        })
        .collect();

    // 构建 plain_card_idx_map
    let mut plain_card_idx_map = std::collections::HashMap::new();
    for (i, card) in cards.iter().enumerate() {
        if user_plain_card.contains(card) {
            let key = compress_g1(card).to_vec();
            plain_card_idx_map.insert(key, i);
        }
    }

    // 生成 swap_out_cards
    let mut swap_out_cards = Vec::new();
    for (i, user_plain_card) in user_plain_card.iter().enumerate() {
        let key = compress_g1(user_plain_card).to_vec();
        let idx = *plain_card_idx_map.get(&key)?;
        let enc_card =
            crate::precompiles::elgamal::encrypt(&pk, user_plain_card, &s_vec[cards.len() + i]);
        swap_out_cards.push((idx, enc_card));
    }

    Some((s_vec, output_cards, swap_out_cards))
}

// ===== ReconstructionDLEQProof =====

/// Blind DLEq proof，证明 points_in 和 points_out 共享同一 blind 系数。
///
/// 点的线性组合使用 base_coeff 的幂作为系数（从 base^0=1 开始）。
#[derive(Debug, Clone, Copy)]
pub struct ReconstructionDLEQProof {
    /// 承诺点 commitment = sum_point_total · w
    pub commitment: G1Affine,
    /// Response = w + blind · c
    pub response: Fr,
    /// Nonce（防重放，参与 transcript）
    pub nonce: Fr,
}

impl ReconstructionDLEQProof {
    /// 生成 blind DLEq proof。
    pub fn prove(
        points_in: &[G1Affine],
        points_out: &[G1Affine],
        blind: Fr,
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        if blind.is_zero() {
            return None;
        }
        if points_in.len() != points_out.len() || points_in.is_empty() {
            return None;
        }

        let nonce = Fr::rand(rng);
        transcript.append_scalar(b"reconstruct_blind_nonce", &nonce);
        for (i, point) in points_in.iter().enumerate() {
            let label = format!("reconstruct_blind_in_{i}");
            transcript.append_point(label.as_bytes(), point);
        }
        for (i, point) in points_out.iter().enumerate() {
            let label = format!("reconstruct_blind_out_{i}");
            transcript.append_point(label.as_bytes(), point);
        }
        let base_coeff = transcript.challenge(b"reconstruct_base_coeff");

        // sum_point_total = Σ points_in[i] · base_coeff^i (从 base^0=1 开始)
        let mut sum_point_total = G1Projective::zero();
        let mut coeff = Fr::one();
        for point in points_in {
            sum_point_total += G1Projective::from(*point) * coeff;
            coeff *= base_coeff;
        }
        if sum_point_total.is_zero() {
            return None;
        }

        let w = Fr::rand(rng);
        let commitment = (sum_point_total * w).into_affine();
        if commitment.is_zero() {
            return None;
        }
        transcript.append_point(b"reconstruct_blind_commitment", &commitment);
        let c = transcript.challenge(b"reconstruct_blind_challenge");
        let response = w + blind * c;

        Some(Self {
            commitment,
            response,
            nonce,
        })
    }

    /// 验证 blind DLEq proof。
    pub fn verify(
        &self,
        points_in: &[G1Affine],
        points_out: &[G1Affine],
        transcript: &mut PokerTranscript,
    ) -> bool {
        if self.commitment.is_zero() {
            return false;
        }
        if points_in.len() != points_out.len() || points_in.is_empty() {
            return false;
        }

        transcript.append_scalar(b"reconstruct_blind_nonce", &self.nonce);
        for (i, point) in points_in.iter().enumerate() {
            let label = format!("reconstruct_blind_in_{i}");
            transcript.append_point(label.as_bytes(), point);
        }
        for (i, point) in points_out.iter().enumerate() {
            let label = format!("reconstruct_blind_out_{i}");
            transcript.append_point(label.as_bytes(), point);
        }
        let base_coeff = transcript.challenge(b"reconstruct_base_coeff");

        let mut sum_point_in_total = G1Projective::zero();
        let mut sum_point_out_total = G1Projective::zero();
        let mut coeff = Fr::one();
        for (pin, pout) in points_in.iter().zip(points_out.iter()) {
            sum_point_in_total += G1Projective::from(*pin) * coeff;
            sum_point_out_total += G1Projective::from(*pout) * coeff;
            coeff *= base_coeff;
        }
        transcript.append_point(b"reconstruct_blind_commitment", &self.commitment);
        let c = transcript.challenge(b"reconstruct_blind_challenge");

        let lhs = sum_point_in_total * self.response;
        let rhs = G1Projective::from(self.commitment) + sum_point_out_total * c;
        lhs == rhs
    }

    /// 序列化为 97 字节（33 + 32 + 32）。
    pub fn to_bytes(&self) -> [u8; 97] {
        let mut out = [0u8; 97];
        let c = compress_g1(&self.commitment);
        out[0..33].copy_from_slice(&c);
        out[33..65].copy_from_slice(&fr_to_32bytes(&self.response));
        out[65..97].copy_from_slice(&fr_to_32bytes(&self.nonce));
        out
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 97 {
            return None;
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes[0..33]);
        let commitment = decompress_g1(&arr)?;
        let response = fr_from_32bytes(&bytes[33..65])?;
        let nonce = fr_from_32bytes(&bytes[65..97])?;
        Some(Self {
            commitment,
            response,
            nonce,
        })
    }
}

// ===== SwapOutCardProof =====

/// 证明 swap_out_card 由 user_readable_card 替换而出。
///
/// 委托 ChaumPedersenDLEQProof 证明 delta_c1 和 G 共享离散对数 user_sk。
#[derive(Debug, Clone)]
pub struct SwapOutCardProof {
    /// 用户可读牌密文。
    pub user_readable_card: ElGamalCiphertext,
    /// 换出的牌密文。
    pub swap_out_card: ElGamalCiphertext,
    /// Chaum-Pedersen DLEQ proof。
    pub chaum_pedersen_proof: ChaumPedersenDLEQProof,
}

impl SwapOutCardProof {
    /// 生成 SwapOutCardProof。
    pub fn prove(
        user_readable_card: ElGamalCiphertext,
        swap_out_card: ElGamalCiphertext,
        user_sk: &Fr,
        user_pk: &G1Affine,
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        let delta_c1 = (G1Projective::from(swap_out_card.c)
            - G1Projective::from(user_readable_card.c))
        .into_affine();
        let delta_c2 = (G1Projective::from(swap_out_card.d)
            - G1Projective::from(user_readable_card.d))
        .into_affine();
        let g = G1Projective::generator().into_affine();
        let chaum_pedersen_proof = ChaumPedersenDLEQProof::prove(
            &delta_c1, &g, user_sk, &delta_c2, user_pk, transcript, rng,
        )?;

        Some(Self {
            user_readable_card,
            swap_out_card,
            chaum_pedersen_proof,
        })
    }

    /// 验证 SwapOutCardProof。
    pub fn verify(
        &self,
        user_readable_card: &ElGamalCiphertext,
        swap_out_card: &ElGamalCiphertext,
        user_pk: &G1Affine,
        transcript: &mut PokerTranscript,
    ) -> bool {
        if self.user_readable_card.c != user_readable_card.c
            || self.user_readable_card.d != user_readable_card.d
        {
            return false;
        }
        if self.swap_out_card.c != swap_out_card.c || self.swap_out_card.d != swap_out_card.d {
            return false;
        }
        let delta_c1 = (G1Projective::from(swap_out_card.c)
            - G1Projective::from(user_readable_card.c))
        .into_affine();
        let delta_c2 = (G1Projective::from(swap_out_card.d)
            - G1Projective::from(user_readable_card.d))
        .into_affine();
        let g = G1Projective::generator().into_affine();
        self.chaum_pedersen_proof
            .verify(&delta_c1, &g, &delta_c2, user_pk, transcript)
    }

    /// 序列化为 230 字节（66 + 66 + 98）。
    pub fn to_bytes(&self) -> [u8; 230] {
        let mut out = [0u8; 230];
        let urc_c = compress_g1(&self.user_readable_card.c);
        let urc_d = compress_g1(&self.user_readable_card.d);
        let soc_c = compress_g1(&self.swap_out_card.c);
        let soc_d = compress_g1(&self.swap_out_card.d);
        out[0..33].copy_from_slice(&urc_c);
        out[33..66].copy_from_slice(&urc_d);
        out[66..99].copy_from_slice(&soc_c);
        out[99..132].copy_from_slice(&soc_d);
        let cp_bytes = self.chaum_pedersen_proof.to_bytes();
        out[132..230].copy_from_slice(&cp_bytes);
        out
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 230 {
            return None;
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes[0..33]);
        let urc_c = decompress_g1(&arr)?;
        arr.copy_from_slice(&bytes[33..66]);
        let urc_d = decompress_g1(&arr)?;
        arr.copy_from_slice(&bytes[66..99]);
        let soc_c = decompress_g1(&arr)?;
        arr.copy_from_slice(&bytes[99..132]);
        let soc_d = decompress_g1(&arr)?;
        let chaum_pedersen_proof = ChaumPedersenDLEQProof::from_bytes(&bytes[132..230])?;
        Some(Self {
            user_readable_card: ElGamalCiphertext { c: urc_c, d: urc_d },
            swap_out_card: ElGamalCiphertext { c: soc_c, d: soc_d },
            chaum_pedersen_proof,
        })
    }
}

// ===== ReconstructProof =====

/// ReconstructProof 组合证明（11 字段）。
#[derive(Debug, Clone)]
pub struct ReconstructProof {
    /// 每个 swap_out_card 的替换证明。
    pub swap_out_cards_proofs: Vec<SwapOutCardProof>,
    /// sum_output_c1 · blind 承诺。
    pub sum_c1_r_commit: G1Affine,
    /// sum_output_c2 · blind 承诺。
    pub sum_c2_r_commit: G1Affine,
    /// swap_out_cards c1 的加权承诺。
    pub swap_sum_c1_commit: G1Affine,
    /// swap_out_cards c2 的加权承诺。
    pub swap_sum_c2_commit: G1Affine,
    /// 防重放 nonce（不参与 transcript）。
    pub nonce: Fr,
    /// Blind DLEq proof。
    pub blind_dleq_proof: ReconstructionDLEQProof,
    /// Total Chaum-Pedersen DLEq proof。
    pub total_dleq_proof: ChaumPedersenDLEQProof,
    /// 合并 Schnorr proof（c1/c2 使用相同 secret_vec）。
    pub swap_combined_schnorr_proof: GeneralizedSchnorrProof,
    /// 独立 c1 Schnorr proof（防止 c1/c2 信息转移攻击）。
    pub sum_swap_out_c1_schnorr_proof: GeneralizedSchnorrProof,
    /// 独立 c2 Schnorr proof。
    pub sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProof,
}

impl ReconstructProof {
    /// 生成 ReconstructProof。
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        cards: &[G1Affine],
        user_readable_cards: &[ElGamalCiphertext],
        output_cards: &[ElGamalCiphertext],
        swap_out_cards: &[(usize, ElGamalCiphertext)],
        user_sk: &Fr,
        user_pk: &G1Affine,
        s_vec: &[Fr],
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        // nonce 不追加到 transcript（Move 兼容）
        let nonce = Fr::rand(rng);

        // 步骤一：为每个 user_readable_card 创建 SwapOutCardProof
        let mut swap_out_cards_proofs: Vec<SwapOutCardProof> = Vec::new();
        for (i, user_readable_card) in user_readable_cards.iter().enumerate() {
            let swap_out_card = &swap_out_cards[i];
            let proof = SwapOutCardProof::prove(
                *user_readable_card,
                swap_out_card.1,
                user_sk,
                user_pk,
                transcript,
                rng,
            )?;
            swap_out_cards_proofs.push(proof);
        }

        // 追加 cards
        for card in cards {
            transcript.append_point(b"reconstruct_card", card);
        }
        // 追加 output_cards c1/c2
        for output_card in output_cards {
            transcript.append_point(b"reconstruct_output_c1", &output_card.c);
        }
        for output_card in output_cards {
            transcript.append_point(b"reconstruct_output_c2", &output_card.d);
        }

        // 步骤二：生成 rho_i
        let scalars: Vec<Fr> = transcript.challenge_vec(b"reconstruct_rho", output_cards.len());

        // 计算 sum_output_c1, sum_output_c2
        let points_c1: Vec<G1Affine> = output_cards.iter().map(|oc| oc.c).collect();
        let points_c2: Vec<G1Affine> = output_cards
            .iter()
            .zip(cards.iter())
            .map(|(oc, card)| (G1Projective::from(oc.d) - G1Projective::from(*card)).into_affine())
            .collect();

        let sum_output_c1: G1Projective =
            VariableBaseMSM::msm(&points_c1, &scalars).unwrap_or(G1Projective::zero());
        let sum_output_c2: G1Projective =
            VariableBaseMSM::msm(&points_c2, &scalars).unwrap_or(G1Projective::zero());

        // 步骤三：blind
        let blind = Fr::rand(rng);
        let sum_c1_r_commit = (sum_output_c1 * blind).into_affine();
        let sum_c2_r_commit = (sum_output_c2 * blind).into_affine();

        let points_in = [sum_output_c1.into_affine(), sum_output_c2.into_affine()];
        let points_out = [sum_c1_r_commit, sum_c2_r_commit];
        let blind_dleq_proof =
            ReconstructionDLEQProof::prove(&points_in, &points_out, blind, transcript, rng)?;

        // 步骤四：secret_vec
        let secret_vec: Vec<Fr> = swap_out_cards
            .iter()
            .map(|(idx, _)| scalars[*idx] * blind)
            .collect();

        let swap_c1_points: Vec<G1Affine> = swap_out_cards.iter().map(|(_, oc)| oc.c).collect();
        let swap_c2_points: Vec<G1Affine> = swap_out_cards.iter().map(|(_, oc)| oc.d).collect();

        let swap_sum_c1_commit: G1Projective =
            VariableBaseMSM::msm(&swap_c1_points, &secret_vec).unwrap_or(G1Projective::zero());
        let swap_sum_c2_commit: G1Projective =
            VariableBaseMSM::msm(&swap_c2_points, &secret_vec).unwrap_or(G1Projective::zero());
        let swap_sum_c1_commit = swap_sum_c1_commit.into_affine();
        let swap_sum_c2_commit = swap_sum_c2_commit.into_affine();

        // combined Schnorr
        let mut combined_base_points: Vec<G1Affine> = Vec::with_capacity(2 * swap_out_cards.len());
        let mut combined_secret_vec: Vec<Fr> = Vec::with_capacity(2 * swap_out_cards.len());
        for (i, (_, oc)) in swap_out_cards.iter().enumerate() {
            combined_base_points.push(oc.c);
            combined_base_points.push(oc.d);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }
        let swap_combined_commit = (G1Projective::from(swap_sum_c1_commit)
            + G1Projective::from(swap_sum_c2_commit))
        .into_affine();
        let swap_combined_schnorr_proof = GeneralizedSchnorrProof::prove(
            &combined_base_points,
            &combined_secret_vec,
            &swap_combined_commit,
            transcript,
            rng,
        )?;

        // c1/c2 独立 Schnorr
        let sum_swap_out_c1_schnorr_proof = GeneralizedSchnorrProof::prove(
            &swap_c1_points,
            &secret_vec,
            &swap_sum_c1_commit,
            transcript,
            rng,
        )?;
        let sum_swap_out_c2_schnorr_proof = GeneralizedSchnorrProof::prove(
            &swap_c2_points,
            &secret_vec,
            &swap_sum_c2_commit,
            transcript,
            rng,
        )?;

        // total DLEq
        let c1_total = (G1Projective::from(sum_c1_r_commit)
            + G1Projective::from(swap_sum_c1_commit))
        .into_affine();
        let c2_total = (G1Projective::from(sum_c2_r_commit)
            + G1Projective::from(swap_sum_c2_commit))
        .into_affine();

        // s = (Σ s_vec[i] * scalars[i]) + (Σ s_vec[n+i] * scalars[swap_idx_i])
        let mut s = Fr::zero();
        for i in 0..cards.len() {
            s += s_vec[i] * scalars[i];
        }
        for (i, (swap_index, _)) in swap_out_cards.iter().enumerate() {
            s += s_vec[i + cards.len()] * scalars[*swap_index];
        }
        let s = s * blind;

        let g = G1Projective::generator().into_affine();
        let total_dleq_proof =
            ChaumPedersenDLEQProof::prove(&g, user_pk, &s, &c1_total, &c2_total, transcript, rng)?;

        Some(Self {
            swap_out_cards_proofs,
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
        })
    }

    /// 验证 ReconstructProof。
    pub fn verify(
        &self,
        cards: &[G1Affine],
        output_cards: &[ElGamalCiphertext],
        swap_out_cards: &[ElGamalCiphertext],
        user_readable_cards: &[ElGamalCiphertext],
        user_pk: &G1Affine,
        transcript: &mut PokerTranscript,
    ) -> bool {
        // 步骤一：验证 swap_out_cards_proofs
        if self.swap_out_cards_proofs.len() != user_readable_cards.len() {
            return false;
        }
        if swap_out_cards.len() != self.swap_out_cards_proofs.len() {
            return false;
        }
        for (i, proof) in self.swap_out_cards_proofs.iter().enumerate() {
            if !proof.verify(
                &user_readable_cards[i],
                &swap_out_cards[i],
                user_pk,
                transcript,
            ) {
                return false;
            }
        }

        // 追加 cards
        for card in cards {
            transcript.append_point(b"reconstruct_card", card);
        }
        // 追加 output_cards c1/c2
        for output_card in output_cards {
            transcript.append_point(b"reconstruct_output_c1", &output_card.c);
        }
        for output_card in output_cards {
            transcript.append_point(b"reconstruct_output_c2", &output_card.d);
        }

        // 步骤二：重新生成 rho_i
        let scalars: Vec<Fr> = transcript.challenge_vec(b"reconstruct_rho", output_cards.len());

        let points_c1: Vec<G1Affine> = output_cards.iter().map(|oc| oc.c).collect();
        let points_c2: Vec<G1Affine> = output_cards
            .iter()
            .zip(cards.iter())
            .map(|(oc, card)| (G1Projective::from(oc.d) - G1Projective::from(*card)).into_affine())
            .collect();

        let sum_output_c1: G1Projective =
            VariableBaseMSM::msm(&points_c1, &scalars).unwrap_or(G1Projective::zero());
        let sum_output_c2: G1Projective =
            VariableBaseMSM::msm(&points_c2, &scalars).unwrap_or(G1Projective::zero());

        // 步骤三：验证 blind_dleq_proof
        let points_in = [sum_output_c1.into_affine(), sum_output_c2.into_affine()];
        let points_out = [self.sum_c1_r_commit, self.sum_c2_r_commit];
        if !self
            .blind_dleq_proof
            .verify(&points_in, &points_out, transcript)
        {
            return false;
        }

        // 检查 swap_sum_c1_commit, swap_sum_c2_commit 非 identity
        if self.swap_sum_c1_commit.is_zero() || self.swap_sum_c2_commit.is_zero() {
            return false;
        }

        // 验证 swap_combined_schnorr_proof
        let mut combined_base_points: Vec<G1Affine> = Vec::with_capacity(2 * swap_out_cards.len());
        for oc in swap_out_cards {
            combined_base_points.push(oc.c);
            combined_base_points.push(oc.d);
        }
        let combined_commit = (G1Projective::from(self.swap_sum_c1_commit)
            + G1Projective::from(self.swap_sum_c2_commit))
        .into_affine();
        if !self.swap_combined_schnorr_proof.verify(
            &combined_base_points,
            &combined_commit,
            transcript,
        ) {
            return false;
        }

        // 验证 c1/c2 独立 Schnorr
        let base_points_c1: Vec<G1Affine> = swap_out_cards.iter().map(|oc| oc.c).collect();
        let base_points_c2: Vec<G1Affine> = swap_out_cards.iter().map(|oc| oc.d).collect();
        if !self.sum_swap_out_c1_schnorr_proof.verify(
            &base_points_c1,
            &self.swap_sum_c1_commit,
            transcript,
        ) {
            return false;
        }
        if !self.sum_swap_out_c2_schnorr_proof.verify(
            &base_points_c2,
            &self.swap_sum_c2_commit,
            transcript,
        ) {
            return false;
        }

        // 验证 total_dleq_proof
        let c1_total = (G1Projective::from(self.sum_c1_r_commit)
            + G1Projective::from(self.swap_sum_c1_commit))
        .into_affine();
        let c2_total = (G1Projective::from(self.sum_c2_r_commit)
            + G1Projective::from(self.swap_sum_c2_commit))
        .into_affine();
        let g = G1Projective::generator().into_affine();
        if !self
            .total_dleq_proof
            .verify(&g, user_pk, &c1_total, &c2_total, transcript)
        {
            return false;
        }

        true
    }

    /// 序列化为变长字节。
    pub fn to_bytes(&self) -> Vec<u8> {
        let swap_count = self.swap_out_cards_proofs.len() as u16;
        let mut out = Vec::new();
        out.extend_from_slice(&swap_count.to_le_bytes());
        for proof in &self.swap_out_cards_proofs {
            out.extend_from_slice(&proof.to_bytes());
        }
        out.extend_from_slice(&compress_g1(&self.sum_c1_r_commit));
        out.extend_from_slice(&compress_g1(&self.sum_c2_r_commit));
        out.extend_from_slice(&compress_g1(&self.swap_sum_c1_commit));
        out.extend_from_slice(&compress_g1(&self.swap_sum_c2_commit));
        out.extend_from_slice(&fr_to_32bytes(&self.nonce));
        out.extend_from_slice(&self.blind_dleq_proof.to_bytes());
        out.extend_from_slice(&self.total_dleq_proof.to_bytes());
        out.extend_from_slice(&self.swap_combined_schnorr_proof.to_bytes());
        out.extend_from_slice(&self.sum_swap_out_c1_schnorr_proof.to_bytes());
        out.extend_from_slice(&self.sum_swap_out_c2_schnorr_proof.to_bytes());
        out
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let swap_count = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let mut offset = 2;

        let mut swap_out_cards_proofs = Vec::with_capacity(swap_count);
        for _ in 0..swap_count {
            if offset + 230 > bytes.len() {
                return None;
            }
            let proof = SwapOutCardProof::from_bytes(&bytes[offset..offset + 230])?;
            swap_out_cards_proofs.push(proof);
            offset += 230;
        }

        let needed = offset + 4 * 33 + 32 + 97 + 98;
        if bytes.len() < needed {
            return None;
        }

        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes[offset..offset + 33]);
        let sum_c1_r_commit = decompress_g1(&arr)?;
        offset += 33;
        arr.copy_from_slice(&bytes[offset..offset + 33]);
        let sum_c2_r_commit = decompress_g1(&arr)?;
        offset += 33;
        arr.copy_from_slice(&bytes[offset..offset + 33]);
        let swap_sum_c1_commit = decompress_g1(&arr)?;
        offset += 33;
        arr.copy_from_slice(&bytes[offset..offset + 33]);
        let swap_sum_c2_commit = decompress_g1(&arr)?;
        offset += 33;

        let nonce = fr_from_32bytes(&bytes[offset..offset + 32])?;
        offset += 32;

        let blind_dleq_proof = ReconstructionDLEQProof::from_bytes(&bytes[offset..offset + 97])?;
        offset += 97;
        let total_dleq_proof = ChaumPedersenDLEQProof::from_bytes(&bytes[offset..offset + 98])?;
        offset += 98;

        // 变长 GeneralizedSchnorrProof：需要知道长度
        // 每个 Schnorr proof = 33 + 2 + n*32
        if offset + 35 > bytes.len() {
            return None;
        }
        let schnorr_count_1 = u16::from_le_bytes([bytes[offset + 33], bytes[offset + 34]]) as usize;
        let schnorr_1_len = 35 + schnorr_count_1 * 32;
        if offset + schnorr_1_len > bytes.len() {
            return None;
        }
        let swap_combined_schnorr_proof =
            GeneralizedSchnorrProof::from_bytes(&bytes[offset..offset + schnorr_1_len])?;
        offset += schnorr_1_len;

        if offset + 35 > bytes.len() {
            return None;
        }
        let schnorr_count_2 = u16::from_le_bytes([bytes[offset + 33], bytes[offset + 34]]) as usize;
        let schnorr_2_len = 35 + schnorr_count_2 * 32;
        if offset + schnorr_2_len > bytes.len() {
            return None;
        }
        let sum_swap_out_c1_schnorr_proof =
            GeneralizedSchnorrProof::from_bytes(&bytes[offset..offset + schnorr_2_len])?;
        offset += schnorr_2_len;

        if offset + 35 > bytes.len() {
            return None;
        }
        let schnorr_count_3 = u16::from_le_bytes([bytes[offset + 33], bytes[offset + 34]]) as usize;
        let schnorr_3_len = 35 + schnorr_count_3 * 32;
        if offset + schnorr_3_len > bytes.len() {
            return None;
        }
        let sum_swap_out_c2_schnorr_proof =
            GeneralizedSchnorrProof::from_bytes(&bytes[offset..offset + schnorr_3_len])?;
        offset += schnorr_3_len;

        if offset != bytes.len() {
            return None;
        }

        Some(Self {
            swap_out_cards_proofs,
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
        })
    }
}

/// 字节导向的 ReconstructProof 验证。
#[must_use]
pub fn reconstruct_verify_bytes(
    cards_bytes: &[u8],
    output_cards_bytes: &[u8],
    swap_out_cards_bytes: &[u8],
    user_readable_cards_bytes: &[u8],
    user_pk_bytes: &[u8],
    proof_bytes: &[u8],
    transcript: &mut PokerTranscript,
) -> bool {
    use crate::precompiles::poker_transcript::{g1_to_64bytes, parse_g1_from_64bytes};

    // cards: n × 64 bytes
    if !cards_bytes.len().is_multiple_of(64) {
        return false;
    }
    let cards: Vec<G1Affine> = (0..cards_bytes.len() / 64)
        .map(|i| parse_g1_from_64bytes(&cards_bytes[i * 64..(i + 1) * 64]))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if cards.len() != cards_bytes.len() / 64 {
        return false;
    }

    // output_cards: n × 128 bytes (c[64] || d[64])
    if !output_cards_bytes.len().is_multiple_of(128) {
        return false;
    }
    let parse_ct = |bytes: &[u8], i: usize| -> Option<ElGamalCiphertext> {
        let start = i * 128;
        let c = parse_g1_from_64bytes(&bytes[start..start + 64])?;
        let d = parse_g1_from_64bytes(&bytes[start + 64..start + 128])?;
        Some(ElGamalCiphertext { c, d })
    };
    let n_output = output_cards_bytes.len() / 128;
    let output_cards: Vec<ElGamalCiphertext> = (0..n_output)
        .map(|i| parse_ct(output_cards_bytes, i))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if output_cards.len() != n_output {
        return false;
    }

    // swap_out_cards: k × 128 bytes
    if !swap_out_cards_bytes.len().is_multiple_of(128) {
        return false;
    }
    let n_swap = swap_out_cards_bytes.len() / 128;
    let swap_out_cards: Vec<ElGamalCiphertext> = (0..n_swap)
        .map(|i| parse_ct(swap_out_cards_bytes, i))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if swap_out_cards.len() != n_swap {
        return false;
    }

    // user_readable_cards: k × 128 bytes
    if !user_readable_cards_bytes.len().is_multiple_of(128) {
        return false;
    }
    let n_urc = user_readable_cards_bytes.len() / 128;
    let user_readable_cards: Vec<ElGamalCiphertext> = (0..n_urc)
        .map(|i| parse_ct(user_readable_cards_bytes, i))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if user_readable_cards.len() != n_urc {
        return false;
    }

    let user_pk = match parse_g1_from_64bytes(user_pk_bytes) {
        Some(p) => p,
        None => return false,
    };
    let proof = match ReconstructProof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => return false,
    };

    // 验证 _g1_to_64bytes 可用（避免 unused 警告）
    let _ = g1_to_64bytes;

    proof.verify(
        &cards,
        &output_cards,
        &swap_out_cards,
        &user_readable_cards,
        &user_pk,
        transcript,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::elgamal::{card_to_point, encrypt, keygen_from_secret};
    use ark_std::test_rng;

    /// 测试辅助：构造 cards 和 user_readable_cards
    fn setup_reconstruct(
        n_cards: usize,
        n_user_readable: usize,
        rng: &mut impl Rng,
    ) -> (Fr, G1Affine, Vec<G1Affine>, Vec<ElGamalCiphertext>, Fr) {
        let user_sk = Fr::rand(rng);
        let user_pk = keygen_from_secret(&user_sk).pk;

        // 生成 n_cards 张牌的明文点
        let cards: Vec<G1Affine> = (0..n_cards).map(|i| card_to_point((i as u8) + 1)).collect();

        // 选 n_user_readable 张牌作为用户可读牌
        let user_readable_cards: Vec<ElGamalCiphertext> = (0..n_user_readable)
            .map(|i| {
                let card = cards[i];
                let r = Fr::rand(rng);
                encrypt(&keygen_from_secret(&user_sk), &card, &r)
            })
            .collect();

        // coefficient（非 0、非 1）
        let coefficient = Fr::from(7u64);

        (user_sk, user_pk, cards, user_readable_cards, coefficient)
    }

    #[test]
    fn test_reconstruction_dleq_roundtrip() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let p1 = (G1Projective::generator() * Fr::from(3u64)).into_affine();
        let blind = Fr::from(7u64);
        // points_out[i] = points_in[i] * blind
        let points_in = vec![g, p1];
        let points_out = vec![
            (G1Projective::from(g) * blind).into_affine(),
            (G1Projective::from(p1) * blind).into_affine(),
        ];

        let mut ts = PokerTranscript::new(b"test_rdleq");
        let proof =
            ReconstructionDLEQProof::prove(&points_in, &points_out, blind, &mut ts, &mut rng)
                .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_rdleq");
        assert!(proof.verify(&points_in, &points_out, &mut ts2));
    }

    #[test]
    fn test_reconstruction_dleq_wrong_blind() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let p1 = (G1Projective::generator() * Fr::from(3u64)).into_affine();
        let blind = Fr::from(7u64);
        let points_in = vec![g, p1];
        let points_out = vec![
            (G1Projective::from(g) * blind).into_affine(),
            (G1Projective::from(p1) * blind).into_affine(),
        ];

        let mut ts = PokerTranscript::new(b"test_rdleq_w");
        let proof =
            ReconstructionDLEQProof::prove(&points_in, &points_out, blind, &mut ts, &mut rng)
                .expect("prove should succeed");

        // 用不同 points_out 验证应失败
        let wrong_out = vec![
            (G1Projective::from(g) * Fr::from(11u64)).into_affine(),
            (G1Projective::from(p1) * Fr::from(11u64)).into_affine(),
        ];
        let mut ts2 = PokerTranscript::new(b"test_rdleq_w");
        assert!(!proof.verify(&points_in, &wrong_out, &mut ts2));
    }

    #[test]
    fn test_swap_out_card_proof_roundtrip() {
        let mut rng = test_rng();
        let user_sk = Fr::rand(&mut rng);
        let user_pk = keygen_from_secret(&user_sk).pk;
        let card = card_to_point(42);

        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);
        let user_readable = encrypt(&keygen_from_secret(&user_sk), &card, &r1);
        let swap_out = encrypt(&keygen_from_secret(&user_sk), &card, &r2);

        let mut ts = PokerTranscript::new(b"test_swap");
        let proof = SwapOutCardProof::prove(
            user_readable,
            swap_out,
            &user_sk,
            &user_pk,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_swap");
        assert!(proof.verify(&user_readable, &swap_out, &user_pk, &mut ts2));
    }

    #[test]
    fn test_swap_out_card_proof_wrong_card() {
        let mut rng = test_rng();
        let user_sk = Fr::rand(&mut rng);
        let user_pk = keygen_from_secret(&user_sk).pk;
        let card = card_to_point(42);

        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);
        let user_readable = encrypt(&keygen_from_secret(&user_sk), &card, &r1);
        let swap_out = encrypt(&keygen_from_secret(&user_sk), &card, &r2);
        let wrong_swap = encrypt(&keygen_from_secret(&user_sk), &card_to_point(43), &r2);

        let mut ts = PokerTranscript::new(b"test_swap_w");
        let proof = SwapOutCardProof::prove(
            user_readable,
            swap_out,
            &user_sk,
            &user_pk,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_swap_w");
        assert!(!proof.verify(&user_readable, &wrong_swap, &user_pk, &mut ts2));
    }

    #[test]
    fn test_reconstruct_proof_single_card() {
        let mut rng = test_rng();
        let (user_sk, user_pk, cards, user_readable_cards, coefficient) =
            setup_reconstruct(3, 1, &mut rng);

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        )
        .expect("reconstruct_deck should succeed");

        let mut ts = PokerTranscript::new(b"test_recon_1");
        let proof = ReconstructProof::prove(
            &cards,
            &user_readable_cards,
            &output_cards,
            &swap_out_cards,
            &user_sk,
            &user_pk,
            &s_vec,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let swap_out_only: Vec<ElGamalCiphertext> =
            swap_out_cards.iter().map(|(_, ct)| *ct).collect();
        let mut ts2 = PokerTranscript::new(b"test_recon_1");
        assert!(proof.verify(
            &cards,
            &output_cards,
            &swap_out_only,
            &user_readable_cards,
            &user_pk,
            &mut ts2
        ));
    }

    #[test]
    fn test_reconstruct_proof_multi_cards() {
        let mut rng = test_rng();
        let (user_sk, user_pk, cards, user_readable_cards, coefficient) =
            setup_reconstruct(5, 2, &mut rng);

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        )
        .expect("reconstruct_deck should succeed");

        let mut ts = PokerTranscript::new(b"test_recon_m");
        let proof = ReconstructProof::prove(
            &cards,
            &user_readable_cards,
            &output_cards,
            &swap_out_cards,
            &user_sk,
            &user_pk,
            &s_vec,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let swap_out_only: Vec<ElGamalCiphertext> =
            swap_out_cards.iter().map(|(_, ct)| *ct).collect();
        let mut ts2 = PokerTranscript::new(b"test_recon_m");
        assert!(proof.verify(
            &cards,
            &output_cards,
            &swap_out_only,
            &user_readable_cards,
            &user_pk,
            &mut ts2
        ));
    }

    #[test]
    fn test_reconstruct_proof_serialization() {
        let mut rng = test_rng();
        let (user_sk, user_pk, cards, user_readable_cards, coefficient) =
            setup_reconstruct(4, 2, &mut rng);

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        )
        .expect("reconstruct_deck should succeed");

        let mut ts = PokerTranscript::new(b"test_recon_ser");
        let proof = ReconstructProof::prove(
            &cards,
            &user_readable_cards,
            &output_cards,
            &swap_out_cards,
            &user_sk,
            &user_pk,
            &s_vec,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let bytes = proof.to_bytes();
        let recovered = ReconstructProof::from_bytes(&bytes).expect("from_bytes should succeed");

        let swap_out_only: Vec<ElGamalCiphertext> =
            swap_out_cards.iter().map(|(_, ct)| *ct).collect();
        let mut ts2 = PokerTranscript::new(b"test_recon_ser");
        assert!(recovered.verify(
            &cards,
            &output_cards,
            &swap_out_only,
            &user_readable_cards,
            &user_pk,
            &mut ts2
        ));
    }

    #[test]
    fn test_reconstruct_proof_byte_verify() {
        use crate::precompiles::poker_transcript::g1_to_64bytes;

        let mut rng = test_rng();
        let (user_sk, user_pk, cards, user_readable_cards, coefficient) =
            setup_reconstruct(3, 1, &mut rng);

        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &coefficient,
        )
        .expect("reconstruct_deck should succeed");

        let mut ts = PokerTranscript::new(b"test_recon_bv");
        let proof = ReconstructProof::prove(
            &cards,
            &user_readable_cards,
            &output_cards,
            &swap_out_cards,
            &user_sk,
            &user_pk,
            &s_vec,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");
        let proof_bytes = proof.to_bytes();

        // 构造字节级输入
        let cards_bytes: Vec<u8> = cards.iter().flat_map(g1_to_64bytes).collect();
        let output_cards_bytes: Vec<u8> = output_cards
            .iter()
            .flat_map(|ct| {
                let mut v = g1_to_64bytes(&ct.c).to_vec();
                v.extend_from_slice(&g1_to_64bytes(&ct.d));
                v
            })
            .collect();
        let swap_out_only: Vec<ElGamalCiphertext> =
            swap_out_cards.iter().map(|(_, ct)| *ct).collect();
        let swap_out_bytes: Vec<u8> = swap_out_only
            .iter()
            .flat_map(|ct| {
                let mut v = g1_to_64bytes(&ct.c).to_vec();
                v.extend_from_slice(&g1_to_64bytes(&ct.d));
                v
            })
            .collect();
        let user_readable_bytes: Vec<u8> = user_readable_cards
            .iter()
            .flat_map(|ct| {
                let mut v = g1_to_64bytes(&ct.c).to_vec();
                v.extend_from_slice(&g1_to_64bytes(&ct.d));
                v
            })
            .collect();
        let pk_bytes = g1_to_64bytes(&user_pk);

        let mut ts2 = PokerTranscript::new(b"test_recon_bv");
        assert!(reconstruct_verify_bytes(
            &cards_bytes,
            &output_cards_bytes,
            &swap_out_bytes,
            &user_readable_bytes,
            &pk_bytes,
            &proof_bytes,
            &mut ts2,
        ));
    }
}
