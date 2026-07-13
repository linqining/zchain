//! ZKShuffleProof — shuffle 排列一致性 Sigma 协议证明（Phase M — M-11）。
//!
//! 完整移植 poker_protocol `shuffle_proof.rs`，transcript 标签与协议完全一致。
//!
//! # 协议
//!
//! 证明 `output_cts` 是 `input_cts` 的合法 shuffle（排列 + 重加密）。
//!
//! 核心思路：
//! 1. 生成批量系数 `ρ_0..ρ_{n-1}`（Fiat-Shamir challenge）
//! 2. 计算加权和 `R_c1 = Σ ρ_i · input[i].c1`，`R_c2 = Σ ρ_i · input[i].c2`
//! 3. 证明 `R_c1` 和 `R_c2` 可由 `output` 的线性组合表示（秘密为排列 + 重加密随机数）
//! 4. 使用 3 个 GeneralizedSchnorrProof 防止 c1/c2 信息转移攻击：
//!    - combined（c1+c2 使用相同排列）
//!    - sum_c1（c1 独立）
//!    - sum_c2（c2 独立）
//!
//! # 序列化（变长）
//!
//! | 字段 | 长度 | 说明 |
//! |------|------|------|
//! | sum_c1_commit | 33 | G1 压缩格式 |
//! | sum_c2_commit | 33 | G1 压缩格式 |
//! | nonce | 32 | Fr little-endian |
//! | combined_schnorr_len | 2 | u16 LE |
//! | combined_schnorr_proof | 变长 | GeneralizedSchnorrProof 序列化 |
//! | sum_c1_schnorr_len | 2 | u16 LE |
//! | sum_c1_schnorr_proof | 变长 | GeneralizedSchnorrProof 序列化 |
//! | sum_c2_schnorr_len | 2 | u16 LE |
//! | sum_c2_schnorr_proof | 变长 | GeneralizedSchnorrProof 序列化 |
//!
//! # Transcript 标签（完全匹配 poker_protocol）
//!
//! `shuffle_pk` / `shuffle_nonce` / `input c1` / `input c2` / `output c1` / `output c2`
//! / `rho_challenge`（challenge_vec with n challenges）

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use ark_std::rand::Rng;

use crate::precompiles::elgamal::ElGamalCiphertext;
use crate::precompiles::generalized_schnorr::GeneralizedSchnorrProof;
use crate::precompiles::poker_transcript::{
    PokerTranscript, compress_g1, decompress_g1, fr_from_32bytes, fr_to_32bytes,
};

/// Fiat-Shamir transcript domain tag。
pub const SHUFFLE_PROOF_LABEL: &[u8] = b"zk_shuffle_proof_v3";

/// ZKShuffleProof — 证明 output_cts 是 input_cts 的合法 shuffle。
#[derive(Debug, Clone)]
pub struct ZKShuffleProof {
    /// `Σ ρ_i · input[i].c1`
    pub sum_c1_commit: G1Affine,
    /// `Σ ρ_i · input[i].c2`
    pub sum_c2_commit: G1Affine,
    /// 合并 Schnorr 证明（c1+c2 使用相同排列，防止 c1/c2 swap 攻击）。
    pub combined_schnorr_proof: GeneralizedSchnorrProof,
    /// c1 独立 Schnorr 证明。
    pub sum_c1_schnorr_proof: GeneralizedSchnorrProof,
    /// c2 独立 Schnorr 证明。
    pub sum_c2_schnorr_proof: GeneralizedSchnorrProof,
    /// 防重放 nonce。
    pub nonce: Fr,
}

impl ZKShuffleProof {
    /// 派生批量系数 `ρ_0..ρ_{n-1}`。
    ///
    /// 将 input/output 密文加入 transcript，然后生成 n 个 challenge。
    fn derive_batch_coefficients(
        input_cts: &[ElGamalCiphertext],
        output_cts: &[ElGamalCiphertext],
        transcript: &mut PokerTranscript,
    ) -> Vec<Fr> {
        let n = input_cts.len();
        for ct in input_cts.iter().take(n) {
            transcript.append_point(b"input c1", &ct.c);
            transcript.append_point(b"input c2", &ct.d);
        }
        for ct in output_cts.iter().take(n) {
            transcript.append_point(b"output c1", &ct.c);
            transcript.append_point(b"output c2", &ct.d);
        }
        transcript.challenge_vec(b"rho_challenge", n)
    }

    /// 生成 ZKShuffleProof。
    ///
    /// # 参数
    /// - `input_cts` — 输入密文数组
    /// - `output_cts` — 输出密文数组（shuffle 后）
    /// - `permute` — 排列：`output[j] = reencrypt(input[permute[j]], r_values[j])`
    /// - `r_values` — 重加密随机数
    /// - `pk` — 玩家公钥
    /// - `transcript` — Fiat-Shamir transcript
    /// - `rng` — 随机数生成器
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        input_cts: &[ElGamalCiphertext],
        output_cts: &[ElGamalCiphertext],
        permute: &[usize],
        r_values: &[Fr],
        pk: &G1Affine,
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        let n = input_cts.len();
        if output_cts.len() != n || permute.len() != n || r_values.len() != n {
            return None;
        }
        if n == 0 {
            return None;
        }

        // 安全检查：拒绝 identity 基点
        for ct in input_cts.iter() {
            if ct.c.is_zero() || ct.d.is_zero() {
                return None;
            }
        }
        for ct in output_cts.iter() {
            if ct.c.is_zero() || ct.d.is_zero() {
                return None;
            }
        }
        if pk.is_zero() {
            return None;
        }

        // 将 pk 加入 transcript（绑定证明到玩家公钥）
        transcript.append_point(b"shuffle_pk", pk);

        let nonce = Fr::rand(rng);
        transcript.append_scalar(b"shuffle_nonce", &nonce);

        let rho = Self::derive_batch_coefficients(input_cts, output_cts, transcript);

        let input_c1s: Vec<G1Affine> = input_cts.iter().map(|ct| ct.c).collect();
        let input_c2s: Vec<G1Affine> = input_cts.iter().map(|ct| ct.d).collect();

        let sum_input_c1_commit: G1Projective =
            VariableBaseMSM::msm(&input_c1s, &rho).unwrap_or(G1Affine::identity().into());
        let sum_input_c2_commit: G1Projective =
            VariableBaseMSM::msm(&input_c2s, &rho).unwrap_or(G1Affine::identity().into());
        let sum_input_c1_commit = sum_input_c1_commit.into_affine();
        let sum_input_c2_commit = sum_input_c2_commit.into_affine();

        // 构造 secret_vec = [k_0, ..., k_{n-1}, pk_delta]
        // 其中 k_{position} = rho[j]，position = permute.index(j)
        let mut secret_vec = vec![Fr::zero(); n];
        let mut pk_delta = Fr::zero();
        for (j, &rho_j) in rho.iter().enumerate().take(n) {
            let position = permute.iter().position(|&x| x == j)?;
            secret_vec[position] = rho_j;
            let r_val = r_values[position];
            pk_delta -= r_val * rho_j;
        }
        secret_vec.push(pk_delta);

        let g = G1Projective::generator().into_affine();

        // c1 基点: [output[0].c1, ..., output[n-1].c1, G]
        let mut base_points_c1: Vec<G1Affine> = output_cts.iter().map(|ct| ct.c).collect();
        base_points_c1.push(g);

        // c2 基点: [output[0].c2, ..., output[n-1].c2, pk]
        let mut base_points_c2: Vec<G1Affine> = output_cts.iter().map(|ct| ct.d).collect();
        base_points_c2.push(*pk);

        // 合并基点: [output[0].c1, output[0].c2, ..., output[n-1].c1, output[n-1].c2, G, pk]
        let mut combined_base_points: Vec<G1Affine> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Fr> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output_cts[i].c);
            combined_base_points.push(output_cts[i].d);
            combined_secret_vec.push(secret_vec[i]); // k_i for c1
            combined_secret_vec.push(secret_vec[i]); // same k_i for c2
        }
        combined_base_points.push(g);
        combined_base_points.push(*pk);
        combined_secret_vec.push(secret_vec[n]); // pk_delta for G
        combined_secret_vec.push(secret_vec[n]); // same pk_delta for pk

        let combined_commit: G1Projective =
            G1Projective::from(sum_input_c1_commit) + G1Projective::from(sum_input_c2_commit);
        let combined_commit = combined_commit.into_affine();

        let combined_schnorr_proof = GeneralizedSchnorrProof::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            transcript,
            rng,
        )?;

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::prove(
            &base_points_c1,
            &secret_vec,
            &sum_input_c1_commit,
            transcript,
            rng,
        )?;

        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::prove(
            &base_points_c2,
            &secret_vec,
            &sum_input_c2_commit,
            transcript,
            rng,
        )?;

        Some(Self {
            sum_c1_commit: sum_input_c1_commit,
            sum_c2_commit: sum_input_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        })
    }

    /// 验证 ZKShuffleProof。
    ///
    /// # 参数
    /// - `&self` — proof
    /// - `input_cts` — 输入密文数组
    /// - `output_cts` — 输出密文数组
    /// - `pk` — 玩家公钥
    /// - `transcript` — Fiat-Shamir transcript
    pub fn verify(
        &self,
        input_cts: &[ElGamalCiphertext],
        output_cts: &[ElGamalCiphertext],
        pk: &G1Affine,
        transcript: &mut PokerTranscript,
    ) -> bool {
        let n = input_cts.len();
        if output_cts.len() != n {
            return false;
        }
        if n == 0 {
            return false;
        }

        // 安全检查：拒绝 identity 基点
        for ct in input_cts.iter() {
            if ct.c.is_zero() || ct.d.is_zero() {
                return false;
            }
        }
        for ct in output_cts.iter() {
            if ct.c.is_zero() || ct.d.is_zero() {
                return false;
            }
        }
        if pk.is_zero() {
            return false;
        }

        transcript.append_point(b"shuffle_pk", pk);
        transcript.append_scalar(b"shuffle_nonce", &self.nonce);

        let rho = Self::derive_batch_coefficients(input_cts, output_cts, transcript);

        let input_c1s: Vec<G1Affine> = input_cts.iter().map(|ct| ct.c).collect();
        let input_c2s: Vec<G1Affine> = input_cts.iter().map(|ct| ct.d).collect();

        let sum_input_c1_commit: G1Projective =
            VariableBaseMSM::msm(&input_c1s, &rho).unwrap_or(G1Affine::identity().into());
        let sum_input_c2_commit: G1Projective =
            VariableBaseMSM::msm(&input_c2s, &rho).unwrap_or(G1Affine::identity().into());
        let sum_input_c1_commit = sum_input_c1_commit.into_affine();
        let sum_input_c2_commit = sum_input_c2_commit.into_affine();

        // 校验 sum commitments 匹配
        if self.sum_c1_commit != sum_input_c1_commit {
            return false;
        }
        if self.sum_c2_commit != sum_input_c2_commit {
            return false;
        }

        let g = G1Projective::generator().into_affine();

        // 重构 combined base points
        let mut combined_base_points: Vec<G1Affine> = Vec::with_capacity(2 * n + 2);
        for ct in output_cts.iter() {
            combined_base_points.push(ct.c);
            combined_base_points.push(ct.d);
        }
        combined_base_points.push(g);
        combined_base_points.push(*pk);

        // 重构 c1/c2 base points
        let mut base_points_c1: Vec<G1Affine> = output_cts.iter().map(|ct| ct.c).collect();
        base_points_c1.push(g);
        let mut base_points_c2: Vec<G1Affine> = output_cts.iter().map(|ct| ct.d).collect();
        base_points_c2.push(*pk);

        // 验证 3 个 Schnorr proof
        let combined_commit: G1Projective =
            G1Projective::from(self.sum_c1_commit) + G1Projective::from(self.sum_c2_commit);
        let combined_commit = combined_commit.into_affine();

        if !self
            .combined_schnorr_proof
            .verify(&combined_base_points, &combined_commit, transcript)
        {
            return false;
        }
        if !self
            .sum_c1_schnorr_proof
            .verify(&base_points_c1, &self.sum_c1_commit, transcript)
        {
            return false;
        }
        if !self
            .sum_c2_schnorr_proof
            .verify(&base_points_c2, &self.sum_c2_commit, transcript)
        {
            return false;
        }

        true
    }

    /// 序列化为变长字节。
    pub fn to_bytes(&self) -> Vec<u8> {
        let combined_bytes = self.combined_schnorr_proof.to_bytes();
        let c1_bytes = self.sum_c1_schnorr_proof.to_bytes();
        let c2_bytes = self.sum_c2_schnorr_proof.to_bytes();

        let mut out = Vec::with_capacity(
            33 + 33 + 32 + 2 + combined_bytes.len() + 2 + c1_bytes.len() + 2 + c2_bytes.len(),
        );
        out.extend_from_slice(&compress_g1(&self.sum_c1_commit));
        out.extend_from_slice(&compress_g1(&self.sum_c2_commit));
        out.extend_from_slice(&fr_to_32bytes(&self.nonce));
        out.extend_from_slice(&(combined_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&combined_bytes);
        out.extend_from_slice(&(c1_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&c1_bytes);
        out.extend_from_slice(&(c2_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&c2_bytes);
        out
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 33 + 33 + 32 + 6 {
            return None;
        }
        let mut c1_arr = [0u8; 33];
        c1_arr.copy_from_slice(&bytes[0..33]);
        let sum_c1_commit = decompress_g1(&c1_arr)?;

        let mut c2_arr = [0u8; 33];
        c2_arr.copy_from_slice(&bytes[33..66]);
        let sum_c2_commit = decompress_g1(&c2_arr)?;

        let nonce = fr_from_32bytes(&bytes[66..98])?;

        let mut offset = 98;

        let combined_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + combined_len > bytes.len() {
            return None;
        }
        let combined_schnorr_proof =
            GeneralizedSchnorrProof::from_bytes(&bytes[offset..offset + combined_len])?;
        offset += combined_len;

        let c1_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + c1_len > bytes.len() {
            return None;
        }
        let sum_c1_schnorr_proof =
            GeneralizedSchnorrProof::from_bytes(&bytes[offset..offset + c1_len])?;
        offset += c1_len;

        let c2_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        if offset + c2_len > bytes.len() {
            return None;
        }
        let sum_c2_schnorr_proof =
            GeneralizedSchnorrProof::from_bytes(&bytes[offset..offset + c2_len])?;

        Some(Self {
            sum_c1_commit,
            sum_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        })
    }
}

/// 字节导向的 ZKShuffleProof 验证。
///
/// # 参数格式
/// - `input_cts_bytes`: n × 128 字节（每张牌 c1‖c2，各 64B）
/// - `output_cts_bytes`: n × 128 字节
/// - `pk_bytes`: 64 字节
/// - `proof_bytes`: 变长 ZKShuffleProof 序列化
#[must_use]
pub fn shuffle_verify_bytes(
    input_cts_bytes: &[u8],
    output_cts_bytes: &[u8],
    pk_bytes: &[u8],
    proof_bytes: &[u8],
    transcript: &mut PokerTranscript,
) -> bool {
    use crate::precompiles::poker_transcript::parse_g1_from_64bytes;

    if !input_cts_bytes.len().is_multiple_of(128) {
        return false;
    }
    if !output_cts_bytes.len().is_multiple_of(128) {
        return false;
    }
    let n = input_cts_bytes.len() / 128;
    if output_cts_bytes.len() / 128 != n {
        return false;
    }
    if n == 0 {
        return false;
    }

    let parse_cts = |bytes: &[u8]| -> Option<Vec<ElGamalCiphertext>> {
        (0..n)
            .map(|i| {
                let off = i * 128;
                let c = parse_g1_from_64bytes(&bytes[off..off + 64])?;
                let d = parse_g1_from_64bytes(&bytes[off + 64..off + 128])?;
                Some(ElGamalCiphertext { c, d })
            })
            .collect()
    };

    let input_cts = match parse_cts(input_cts_bytes) {
        Some(v) => v,
        None => return false,
    };
    let output_cts = match parse_cts(output_cts_bytes) {
        Some(v) => v,
        None => return false,
    };
    let pk = match parse_g1_from_64bytes(pk_bytes) {
        Some(p) => p,
        None => return false,
    };
    let proof = match ZKShuffleProof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    proof.verify(&input_cts, &output_cts, &pk, transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::elgamal::{ElGamalPublicKey, encrypt, keygen_from_secret, reencrypt};
    use crate::precompiles::poker_transcript::g1_to_64bytes;
    use ark_std::test_rng;

    /// 构造 n 张加密牌。
    fn make_encrypted_cards(n: usize, pk: &G1Affine, rng: &mut impl Rng) -> Vec<ElGamalCiphertext> {
        let pk_obj = ElGamalPublicKey { pk: *pk };
        (0..n)
            .map(|i| {
                let msg = (G1Projective::generator() * Fr::from((i + 1) as u64)).into_affine();
                let r = Fr::rand(rng);
                encrypt(&pk_obj, &msg, &r)
            })
            .collect()
    }

    /// 对 input 执行 shuffle + re_encrypt。
    fn shuffle_and_reencrypt(
        input: &[ElGamalCiphertext],
        permute: &[usize],
        pk: &G1Affine,
        rng: &mut impl Rng,
    ) -> (Vec<Fr>, Vec<ElGamalCiphertext>) {
        let n = input.len();
        let pk_obj = ElGamalPublicKey { pk: *pk };
        let mut r_values = Vec::with_capacity(n);
        let mut output = Vec::with_capacity(n);
        for &p in permute.iter().take(n) {
            let r_j = Fr::rand(rng);
            r_values.push(r_j);
            output.push(reencrypt(&pk_obj, &input[p], &r_j));
        }
        (r_values, output)
    }

    /// 构造随机排列。
    fn random_permute(n: usize, rng: &mut impl Rng) -> Vec<usize> {
        let mut arr: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            let j = rng.gen_range(0..=i);
            arr.swap(i, j);
        }
        arr
    }

    #[test]
    fn test_shuffle_honest_prover() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(5, &pk, &mut rng);
        let permute = random_permute(5, &mut rng);
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            proof.verify(&input, &output, &pk, &mut ts2),
            "honest prover should pass"
        );
    }

    #[test]
    fn test_shuffle_identity_permutation() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(4, &pk, &mut rng);
        let permute: Vec<usize> = (0..4).collect();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            proof.verify(&input, &output, &pk, &mut ts2),
            "identity permutation should pass"
        );
    }

    #[test]
    fn test_shuffle_tampered_output() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(4, &pk, &mut rng);
        let permute = random_permute(4, &mut rng);
        let (r_values, mut output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");

        // 篡改 output[0].c1
        output[0].c = (G1Projective::from(output[0].c) + G1Projective::generator()).into_affine();

        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            !proof.verify(&input, &output, &pk, &mut ts2),
            "tampered output should fail"
        );
    }

    #[test]
    fn test_shuffle_tampered_input() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let mut input = make_encrypted_cards(4, &pk, &mut rng);
        let permute = random_permute(4, &mut rng);
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");

        // 篡改 input[0].c2
        input[0].d = (G1Projective::from(input[0].d) + G1Projective::generator()).into_affine();

        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            !proof.verify(&input, &output, &pk, &mut ts2),
            "tampered input should fail"
        );
    }

    #[test]
    fn test_shuffle_tampered_nonce() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(4, &pk, &mut rng);
        let permute = random_permute(4, &mut rng);
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let mut proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");

        proof.nonce += Fr::from(1u64);

        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            !proof.verify(&input, &output, &pk, &mut ts2),
            "tampered nonce should fail"
        );
    }

    #[test]
    fn test_shuffle_wrong_pk() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(4, &pk, &mut rng);
        let permute = random_permute(4, &mut rng);
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");

        // 错误的 pk
        let wrong_pk = keygen_from_secret(&(sk + Fr::from(1u64))).pk;
        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            !proof.verify(&input, &output, &wrong_pk, &mut ts2),
            "wrong pk should fail"
        );
    }

    #[test]
    fn test_shuffle_tampered_commitment() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(4, &pk, &mut rng);
        let permute = random_permute(4, &mut rng);
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let mut proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");

        // 篡改 sum_c1_commit
        proof.sum_c1_commit =
            (G1Projective::from(proof.sum_c1_commit) + G1Projective::generator()).into_affine();

        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            !proof.verify(&input, &output, &pk, &mut ts2),
            "tampered commitment should fail"
        );
    }

    #[test]
    fn test_shuffle_reject_identity_output() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(3, &pk, &mut rng);
        let permute = random_permute(3, &mut rng);
        let (r_values, mut output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        // 将 output[1].c1 置为 identity
        output[1].c = G1Affine::identity();

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .is_none(),
            "identity output should be rejected by prove"
        );
    }

    #[test]
    fn test_shuffle_serialization_roundtrip() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(4, &pk, &mut rng);
        let permute = random_permute(4, &mut rng);
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");

        let bytes = proof.to_bytes();
        let recovered = ZKShuffleProof::from_bytes(&bytes).expect("from_bytes");

        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            recovered.verify(&input, &output, &pk, &mut ts2),
            "serialized proof should verify"
        );
    }

    #[test]
    fn test_shuffle_byte_verify() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let input = make_encrypted_cards(3, &pk, &mut rng);
        let permute = random_permute(3, &mut rng);
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk, &mut rng);

        let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        let proof =
            ZKShuffleProof::prove(&input, &output, &permute, &r_values, &pk, &mut ts, &mut rng)
                .expect("prove should succeed");
        let proof_bytes = proof.to_bytes();

        // 构造字节级输入
        let mut input_bytes = Vec::new();
        for ct in &input {
            input_bytes.extend_from_slice(&g1_to_64bytes(&ct.c));
            input_bytes.extend_from_slice(&g1_to_64bytes(&ct.d));
        }
        let mut output_bytes = Vec::new();
        for ct in &output {
            output_bytes.extend_from_slice(&g1_to_64bytes(&ct.c));
            output_bytes.extend_from_slice(&g1_to_64bytes(&ct.d));
        }
        let pk_bytes = g1_to_64bytes(&pk);

        let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(shuffle_verify_bytes(
            &input_bytes,
            &output_bytes,
            &pk_bytes,
            &proof_bytes,
            &mut ts2
        ));

        // 篡改检测
        let mut tampered = proof_bytes.clone();
        // 篡改 sum_c1_commit 第一字节（offset 0）
        tampered[0] ^= 0x01;
        let mut ts3 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
        assert!(
            !shuffle_verify_bytes(&input_bytes, &output_bytes, &pk_bytes, &tampered, &mut ts3),
            "tampered proof should fail"
        );
    }
}
