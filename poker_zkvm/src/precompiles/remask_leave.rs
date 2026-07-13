//! Per-card DLEq proof — RemaskProof / LeaveProof（Phase M — M-5）。
//!
//! 证明同一 sk 被用于所有卡的 remask/leave 操作。
//!
//! # Remask vs Leave
//!
//! - Remask: d2 = output.d - input.d（添加加密层），校验输入+输出密文有效性
//! - Leave:  d2 = input.d - output.d（移除加密层），仅校验输入密文有效性
//!
//! # 协议
//!
//! 1. Prover 选随机 ω，计算 per-card 承诺 A_i = input.c_i · ω 和 pk 承诺 B = G · ω
//! 2. Challenge c = H(pk, input_c1, input_c2, output_c1, output_c2, A_i, B, d2_i, nonce)
//! 3. Response s = ω + c · sk
//! 4. Verifier 校验：
//!    - G · s == B + pk · c（pk DLEq）
//!    - input.c_i · s == A_i + d2_i · c（per-card DLEq）
//!    - input.c_i == output.c_i（c1 不变性）
//!    - 密文有效性（is_valid()）
//!
//! # 序列化（变长）
//!
//! | 字段 | 长度 | 说明 |
//! |------|------|------|
//! | direction | 1 | 0=Remask, 1=Leave |
//! | count | 2 | u16 LE，per_card_commitments 数量 |
//! | per_card_commitments | count × 33 | G1 压缩格式 |
//! | commitment_pk | 33 | G1 压缩格式 |
//! | response | 32 | Fr LE |
//! | nonce | 32 | Fr LE |
//!
//! 兼容 poker_protocol `DLEqProof<C, RemaskKind/LeaveKind>`，transcript 标签完全一致。

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::rand::Rng;

use crate::precompiles::elgamal::ElGamalCiphertext;
use crate::precompiles::poker_transcript::{
    PokerTranscript, compress_g1, decompress_g1, fr_from_32bytes, fr_to_32bytes,
};

/// DLEq 方向：Remask（添加加密层）或 Leave（移除加密层）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DleqDirection {
    /// d2 = output.d - input.d，校验输入+输出密文有效性
    Remask,
    /// d2 = input.d - output.d，仅校验输入密文有效性
    Leave,
}

impl DleqDirection {
    /// 序列化为 1 字节。
    pub fn to_byte(self) -> u8 {
        match self {
            DleqDirection::Remask => 0,
            DleqDirection::Leave => 1,
        }
    }

    /// 从 1 字节反序列化。
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(DleqDirection::Remask),
            1 => Some(DleqDirection::Leave),
            _ => None,
        }
    }

    /// 标签前缀：remask_ 或 leave_
    fn prefix(self) -> &'static str {
        match self {
            DleqDirection::Remask => "remask_",
            DleqDirection::Leave => "leave_",
        }
    }

    /// 计算 d2 = direction(output.d, input.d)
    fn compute_d2(self, input_d: &G1Affine, output_d: &G1Affine) -> G1Affine {
        let in_proj = G1Projective::from(*input_d);
        let out_proj = G1Projective::from(*output_d);
        match self {
            DleqDirection::Remask => (out_proj - in_proj).into_affine(),
            DleqDirection::Leave => (in_proj - out_proj).into_affine(),
        }
    }

    /// 是否校验输出密文有效性。
    fn validates_output(self) -> bool {
        matches!(self, DleqDirection::Remask)
    }
}

/// Per-card DLEq proof（RemaskProof 或 LeaveProof）。
#[derive(Debug, Clone)]
pub struct PerCardDleqProof {
    /// Per-card 承诺 A_i = input.c_i · ω
    pub per_card_commitments: Vec<G1Affine>,
    /// pk DLEq 承诺 B = G · ω
    pub commitment_pk: G1Affine,
    /// Response s = ω + c · sk
    pub response: Fr,
    /// Nonce（防重放，参与 transcript）
    pub nonce: Fr,
    /// 方向（Remask 或 Leave）
    pub direction: DleqDirection,
}

/// 类型别名：RemaskProof = PerCardDleqProof
pub type RemaskProof = PerCardDleqProof;
/// 类型别名：LeaveProof = PerCardDleqProof
pub type LeaveProof = PerCardDleqProof;

/// 追加 DLEq context 到 transcript 并返回 challenge。
///
/// 保证 prove/verify 两端追加完全相同的字节序列（关键 soundness 保证）。
#[allow(clippy::too_many_arguments)]
fn append_dleq_context(
    transcript: &mut PokerTranscript,
    input_cts: &[ElGamalCiphertext],
    output_cts: &[ElGamalCiphertext],
    player_pk: &G1Affine,
    per_card_commitments: &[G1Affine],
    commitment_pk: &G1Affine,
    d2_values: &[G1Affine],
    nonce: &Fr,
    direction: DleqDirection,
) -> Fr {
    let prefix = direction.prefix();

    let pk_label = format!("{prefix}pk");
    let input_c1_label = format!("{prefix}input_c1");
    let input_c2_label = format!("{prefix}input_c2");
    let output_c1_label = format!("{prefix}output_c1");
    let output_c2_label = format!("{prefix}output_c2");
    let per_card_label = format!("{prefix}per_card_commitment");
    let commit_pk_label = format!("{prefix}commitment_pk");
    let d2_label = format!("{prefix}d2");
    let nonce_label = format!("{prefix}nonce");
    let challenge_label = format!("{prefix}challenge");

    transcript.append_point(pk_label.as_bytes(), player_pk);
    for ct in input_cts {
        transcript.append_point(input_c1_label.as_bytes(), &ct.c);
        transcript.append_point(input_c2_label.as_bytes(), &ct.d);
    }
    for ct in output_cts {
        transcript.append_point(output_c1_label.as_bytes(), &ct.c);
        transcript.append_point(output_c2_label.as_bytes(), &ct.d);
    }
    for a_i in per_card_commitments {
        transcript.append_point(per_card_label.as_bytes(), a_i);
    }
    transcript.append_point(commit_pk_label.as_bytes(), commitment_pk);
    for d2 in d2_values {
        transcript.append_point(d2_label.as_bytes(), d2);
    }
    transcript.append_scalar(nonce_label.as_bytes(), nonce);
    transcript.challenge(challenge_label.as_bytes())
}

impl PerCardDleqProof {
    /// 生成 DLEq proof，证明同一 sk 被用于所有卡。
    pub fn prove(
        input_cts: &[ElGamalCiphertext],
        output_cts: &[ElGamalCiphertext],
        player_sk: &Fr,
        player_pk: &G1Affine,
        direction: DleqDirection,
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        let n = input_cts.len().min(output_cts.len());
        if n == 0 {
            return None;
        }
        if player_pk.is_zero() {
            return None;
        }

        let g = G1Projective::generator().into_affine();
        let omega = Fr::rand(rng);
        let nonce = Fr::rand(rng);

        let per_card_commitments: Vec<G1Affine> = input_cts[..n]
            .iter()
            .map(|ct| (G1Projective::from(ct.c) * omega).into_affine())
            .collect();
        let commitment_pk = (G1Projective::from(g) * omega).into_affine();

        let d2_values: Vec<G1Affine> = (0..n)
            .map(|i| direction.compute_d2(&input_cts[i].d, &output_cts[i].d))
            .collect();

        let c = append_dleq_context(
            transcript,
            &input_cts[..n],
            &output_cts[..n],
            player_pk,
            &per_card_commitments,
            &commitment_pk,
            &d2_values,
            &nonce,
            direction,
        );

        let response = omega + c * player_sk;

        Some(Self {
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
            direction,
        })
    }

    /// 验证 DLEq proof。
    pub fn verify(
        &self,
        input_cts: &[ElGamalCiphertext],
        output_cts: &[ElGamalCiphertext],
        player_pk: &G1Affine,
        transcript: &mut PokerTranscript,
    ) -> bool {
        let n = self.per_card_commitments.len();
        if n == 0 {
            return false;
        }
        if n != input_cts.len() || n != output_cts.len() {
            return false;
        }
        if player_pk.is_zero() {
            return false;
        }
        if self.commitment_pk.is_zero() {
            return false;
        }

        let g = G1Projective::generator().into_affine();

        let mut d2_values: Vec<G1Affine> = Vec::with_capacity(n);
        for i in 0..n {
            if !input_cts[i].is_valid() {
                return false;
            }
            if self.direction.validates_output() && !output_cts[i].is_valid() {
                return false;
            }
            if input_cts[i].c != output_cts[i].c {
                return false;
            }
            d2_values.push(self.direction.compute_d2(&input_cts[i].d, &output_cts[i].d));
        }

        let c = append_dleq_context(
            transcript,
            &input_cts[..n],
            &output_cts[..n],
            player_pk,
            &self.per_card_commitments,
            &self.commitment_pk,
            &d2_values,
            &self.nonce,
            self.direction,
        );

        let neg_c = -c;
        let lhs_pk: G1Projective = VariableBaseMSM::msm(&[g, *player_pk], &[self.response, neg_c])
            .unwrap_or(G1Affine::identity().into());
        if lhs_pk.into_affine() != self.commitment_pk {
            return false;
        }

        for i in 0..n {
            let lhs: G1Projective =
                VariableBaseMSM::msm(&[input_cts[i].c, d2_values[i]], &[self.response, neg_c])
                    .unwrap_or(G1Affine::identity().into());
            if lhs.into_affine() != self.per_card_commitments[i] {
                return false;
            }
        }

        true
    }

    /// 序列化为变长字节。
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.per_card_commitments.len();
        let mut out = Vec::with_capacity(1 + 2 + n * 33 + 33 + 32 + 32);
        out.push(self.direction.to_byte());
        out.extend_from_slice(&(n as u16).to_le_bytes());
        for a in &self.per_card_commitments {
            out.extend_from_slice(&compress_g1(a));
        }
        out.extend_from_slice(&compress_g1(&self.commitment_pk));
        out.extend_from_slice(&fr_to_32bytes(&self.response));
        out.extend_from_slice(&fr_to_32bytes(&self.nonce));
        out
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        let direction = DleqDirection::from_byte(bytes[0])?;
        let n = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
        let expected_len = 3 + n * 33 + 33 + 32 + 32;
        if bytes.len() != expected_len {
            return None;
        }

        let mut per_card_commitments = Vec::with_capacity(n);
        let mut offset = 3;
        for _ in 0..n {
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&bytes[offset..offset + 33]);
            per_card_commitments.push(decompress_g1(&arr)?);
            offset += 33;
        }

        let mut pk_arr = [0u8; 33];
        pk_arr.copy_from_slice(&bytes[offset..offset + 33]);
        let commitment_pk = decompress_g1(&pk_arr)?;
        offset += 33;

        let response = fr_from_32bytes(&bytes[offset..offset + 32])?;
        offset += 32;
        let nonce = fr_from_32bytes(&bytes[offset..offset + 32])?;

        Some(Self {
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
            direction,
        })
    }
}

/// 字节导向的 PerCardDleqProof 验证。
///
/// # 参数格式
/// - `input_cts_bytes`: n × 128 字节 (c[64] || d[64])
/// - `output_cts_bytes`: n × 128 字节
/// - `player_pk_bytes`: 64 字节
/// - `proof_bytes`: 变长 PerCardDleqProof 序列化
#[must_use]
pub fn per_card_dleq_verify_bytes(
    input_cts_bytes: &[u8],
    output_cts_bytes: &[u8],
    player_pk_bytes: &[u8],
    proof_bytes: &[u8],
    transcript: &mut PokerTranscript,
) -> bool {
    use crate::precompiles::poker_transcript::parse_g1_from_64bytes;

    if !input_cts_bytes.len().is_multiple_of(128) || !output_cts_bytes.len().is_multiple_of(128) {
        return false;
    }
    let n = input_cts_bytes.len() / 128;
    if output_cts_bytes.len() / 128 != n {
        return false;
    }

    let parse_ct = |bytes: &[u8], i: usize| -> Option<ElGamalCiphertext> {
        let start = i * 128;
        let c = parse_g1_from_64bytes(&bytes[start..start + 64])?;
        let d = parse_g1_from_64bytes(&bytes[start + 64..start + 128])?;
        Some(ElGamalCiphertext { c, d })
    };

    let input_cts: Vec<ElGamalCiphertext> = (0..n)
        .map(|i| parse_ct(input_cts_bytes, i))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if input_cts.len() != n {
        return false;
    }

    let output_cts: Vec<ElGamalCiphertext> = (0..n)
        .map(|i| parse_ct(output_cts_bytes, i))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if output_cts.len() != n {
        return false;
    }

    let player_pk = match parse_g1_from_64bytes(player_pk_bytes) {
        Some(p) => p,
        None => return false,
    };
    let proof = match PerCardDleqProof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    proof.verify(&input_cts, &output_cts, &player_pk, transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::elgamal::{encrypt, keygen_from_secret};
    use ark_std::test_rng;

    fn make_ciphertexts(n: usize, rng: &mut impl Rng) -> (Fr, G1Affine, Vec<ElGamalCiphertext>) {
        let sk = Fr::rand(rng);
        let pk = keygen_from_secret(&sk);
        let cts: Vec<ElGamalCiphertext> = (0..n)
            .map(|i| {
                let card = crate::precompiles::elgamal::card_to_point((i as u8) + 1);
                let r = Fr::rand(rng);
                encrypt(&pk, &card, &r)
            })
            .collect();
        (sk, pk.pk, cts)
    }

    /// Remask: output.c = input.c (unchanged), output.d = input.d + input.c * sk
    /// This is the DLEq-compatible remask where d2 = output.d - input.d = input.c * sk
    fn remask_cts(cts: &[ElGamalCiphertext], sk: &Fr) -> (G1Affine, Vec<ElGamalCiphertext>) {
        let pk = keygen_from_secret(sk);
        let remasked: Vec<ElGamalCiphertext> = cts
            .iter()
            .map(|ct| {
                let mask = G1Projective::from(ct.c) * sk;
                ElGamalCiphertext {
                    c: ct.c,
                    d: (G1Projective::from(ct.d) + mask).into_affine(),
                }
            })
            .collect();
        (pk.pk, remasked)
    }

    #[test]
    fn test_remask_52_cards_roundtrip() {
        let mut rng = test_rng();
        let (sk, pk, input_cts) = make_ciphertexts(52, &mut rng);
        let (_pk2, output_cts) = remask_cts(&input_cts, &sk);

        let mut ts = PokerTranscript::new(b"test_remask");
        let proof = PerCardDleqProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            DleqDirection::Remask,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_remask");
        assert!(proof.verify(&input_cts, &output_cts, &pk, &mut ts2));
    }

    #[test]
    fn test_leave_52_cards_roundtrip() {
        let mut rng = test_rng();
        let (sk, pk, original_cts) = make_ciphertexts(52, &mut rng);
        let (_pk2, remasked_cts) = remask_cts(&original_cts, &sk);

        // Leave: remasked → original (remove encryption layer)
        let mut ts = PokerTranscript::new(b"test_leave");
        let proof = PerCardDleqProof::prove(
            &remasked_cts,
            &original_cts,
            &sk,
            &pk,
            DleqDirection::Leave,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_leave");
        assert!(proof.verify(&remasked_cts, &original_cts, &pk, &mut ts2));
    }

    #[test]
    fn test_remask_wrong_pk() {
        let mut rng = test_rng();
        let (sk, _pk, input_cts) = make_ciphertexts(5, &mut rng);
        let (pk2, output_cts) = remask_cts(&input_cts, &sk);
        let wrong_pk = keygen_from_secret(&Fr::rand(&mut rng));

        let mut ts = PokerTranscript::new(b"test_remask");
        let proof = PerCardDleqProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk2,
            DleqDirection::Remask,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_remask");
        assert!(
            !proof.verify(&input_cts, &output_cts, &wrong_pk.pk, &mut ts2),
            "应验证失败"
        );
    }

    #[test]
    fn test_remask_tampered_output() {
        let mut rng = test_rng();
        let (sk, pk, input_cts) = make_ciphertexts(3, &mut rng);
        let (_pk2, output_cts) = remask_cts(&input_cts, &sk);

        // Prove with original output
        let mut ts = PokerTranscript::new(b"test_remask");
        let proof = PerCardDleqProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            DleqDirection::Remask,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        // Tamper: change output card 0's d component
        let mut tampered_output = output_cts.clone();
        tampered_output[0].d = (G1Projective::generator() * Fr::from(999u64)).into_affine();

        // Verify with tampered output should fail
        let mut ts2 = PokerTranscript::new(b"test_remask");
        assert!(
            !proof.verify(&input_cts, &tampered_output, &pk, &mut ts2),
            "应验证失败"
        );
    }

    #[test]
    fn test_remask_single_card() {
        let mut rng = test_rng();
        let (sk, pk, input_cts) = make_ciphertexts(1, &mut rng);
        let (_pk2, output_cts) = remask_cts(&input_cts, &sk);

        let mut ts = PokerTranscript::new(b"test_remask");
        let proof = PerCardDleqProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            DleqDirection::Remask,
            &mut ts,
            &mut rng,
        )
        .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_remask");
        assert!(proof.verify(&input_cts, &output_cts, &pk, &mut ts2));
    }

    #[test]
    fn test_remask_then_leave_restores() {
        let mut rng = test_rng();
        let (sk, pk, original_cts) = make_ciphertexts(10, &mut rng);

        // Remask: original → remasked
        let (_pk2, remasked_cts) = remask_cts(&original_cts, &sk);
        let mut ts1 = PokerTranscript::new(b"test_rl");
        let remask_proof = PerCardDleqProof::prove(
            &original_cts,
            &remasked_cts,
            &sk,
            &pk,
            DleqDirection::Remask,
            &mut ts1,
            &mut rng,
        )
        .expect("remask prove");
        let mut ts1v = PokerTranscript::new(b"test_rl");
        assert!(remask_proof.verify(&original_cts, &remasked_cts, &pk, &mut ts1v));

        // Leave: remasked → restored (should equal original since same pk)
        let mut ts2 = PokerTranscript::new(b"test_rl");
        let leave_proof = PerCardDleqProof::prove(
            &remasked_cts,
            &original_cts,
            &sk,
            &pk,
            DleqDirection::Leave,
            &mut ts2,
            &mut rng,
        )
        .expect("leave prove");
        let mut ts2v = PokerTranscript::new(b"test_rl");
        assert!(leave_proof.verify(&remasked_cts, &original_cts, &pk, &mut ts2v));
    }

    #[test]
    fn test_serialization_n1() {
        let mut rng = test_rng();
        let (sk, pk, input_cts) = make_ciphertexts(1, &mut rng);
        let (_pk2, output_cts) = remask_cts(&input_cts, &sk);

        let mut ts = PokerTranscript::new(b"test_ser");
        let proof = PerCardDleqProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            DleqDirection::Remask,
            &mut ts,
            &mut rng,
        )
        .expect("prove");

        let bytes = proof.to_bytes();
        let expected = 1 + 2 + 33 + 33 + 32 + 32;
        assert_eq!(bytes.len(), expected);
        let recovered = PerCardDleqProof::from_bytes(&bytes).expect("from_bytes");

        let mut ts2 = PokerTranscript::new(b"test_ser");
        assert!(recovered.verify(&input_cts, &output_cts, &pk, &mut ts2));
    }

    #[test]
    fn test_serialization_n5() {
        let mut rng = test_rng();
        let (sk, pk, input_cts) = make_ciphertexts(5, &mut rng);
        let (_pk2, output_cts) = remask_cts(&input_cts, &sk);

        let mut ts = PokerTranscript::new(b"test_ser");
        let proof = PerCardDleqProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            DleqDirection::Remask,
            &mut ts,
            &mut rng,
        )
        .expect("prove");

        let bytes = proof.to_bytes();
        let expected = 1 + 2 + 5 * 33 + 33 + 32 + 32;
        assert_eq!(bytes.len(), expected);
        let recovered = PerCardDleqProof::from_bytes(&bytes).expect("from_bytes");

        let mut ts2 = PokerTranscript::new(b"test_ser");
        assert!(recovered.verify(&input_cts, &output_cts, &pk, &mut ts2));
    }

    #[test]
    fn test_serialization_n52() {
        let mut rng = test_rng();
        let (sk, pk, input_cts) = make_ciphertexts(52, &mut rng);
        let (_pk2, output_cts) = remask_cts(&input_cts, &sk);

        let mut ts = PokerTranscript::new(b"test_ser");
        let proof = PerCardDleqProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            DleqDirection::Remask,
            &mut ts,
            &mut rng,
        )
        .expect("prove");

        let bytes = proof.to_bytes();
        let expected = 1 + 2 + 52 * 33 + 33 + 32 + 32;
        assert_eq!(bytes.len(), expected);
        let recovered = PerCardDleqProof::from_bytes(&bytes).expect("from_bytes");

        let mut ts2 = PokerTranscript::new(b"test_ser");
        assert!(recovered.verify(&input_cts, &output_cts, &pk, &mut ts2));
    }

    #[test]
    fn test_byte_verify() {
        let mut rng = test_rng();
        let (sk, pk, input_cts) = make_ciphertexts(3, &mut rng);
        let (_pk2, output_cts) = remask_cts(&input_cts, &sk);

        let mut ts = PokerTranscript::new(b"test_bv");
        let proof = PerCardDleqProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            DleqDirection::Remask,
            &mut ts,
            &mut rng,
        )
        .expect("prove");
        let proof_bytes = proof.to_bytes();

        use crate::precompiles::poker_transcript::g1_to_64bytes;
        let mut in_bytes = Vec::new();
        for ct in &input_cts {
            in_bytes.extend_from_slice(&g1_to_64bytes(&ct.c));
            in_bytes.extend_from_slice(&g1_to_64bytes(&ct.d));
        }
        let mut out_bytes = Vec::new();
        for ct in &output_cts {
            out_bytes.extend_from_slice(&g1_to_64bytes(&ct.c));
            out_bytes.extend_from_slice(&g1_to_64bytes(&ct.d));
        }
        let pk_bytes = g1_to_64bytes(&pk);

        let mut ts2 = PokerTranscript::new(b"test_bv");
        assert!(per_card_dleq_verify_bytes(
            &in_bytes,
            &out_bytes,
            &pk_bytes,
            &proof_bytes,
            &mut ts2
        ));
    }
}
