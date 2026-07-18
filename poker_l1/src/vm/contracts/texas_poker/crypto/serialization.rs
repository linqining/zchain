//! Proof 字节流 ↔ struct 反序列化（移植自 `texas_poker_move/sources/table_serialization.move`）。
//!
//! # 字节布局约定
//!
//! - G1 点（compressed）：48 字节
//! - Scalar：32 字节
//! - 密文（c1 + c2）：96 字节
//! - 长度前缀：u16 小端（2 字节）
//!
//! # 链上/链下分离
//!
//! - 链上（节点）：仅使用 `deserialize_*` 函数（从客户端提交的字节流恢复 proof struct）
//! - 链下（CLI 客户端）：使用 `serialize_*` 函数（`#[cfg(feature = "client")]`）生成字节流

use blstrs::G1Projective;

use super::bls_elgamal::ElGamalCiphertext;
use super::bls_scalar::parse_g1;
use super::chaum_pedersen::ChaumPedersenProof;
use super::leave_proof::LeaveProof;
use super::reconstruct_proof::{ReconstructProof, ReconstructionDLEQProof, SwapOutCardProof};
use super::remask_proof::RemaskProof;
use super::reveal_token_proof::RevealTokenProof;
use super::schnorr_proof::GeneralizedSchnorrProof;
use super::shuffle_proof::ShuffleProof;
use crate::error::{PokerL1Error, PokerL1Result};

/// G1 compressed 点字节数。
pub const G1_POINT_SIZE: usize = 48;
/// Scalar 字节数。
pub const SCALAR_SIZE: usize = 32;
/// 密文字节数（c1 + c2，各 48 字节）。
pub const CIPHERTEXT_SIZE: usize = 96;

// ========== 字节读取辅助 ==========

/// 从 `data` 的 `offset` 处读取 `len` 字节。
fn read_bytes(data: &[u8], offset: usize, len: usize) -> PokerL1Result<Vec<u8>> {
    if offset + len > data.len() {
        return Err(PokerL1Error::Serialization(format!(
            "read_bytes out of range: offset={}, len={}, data_len={}",
            offset,
            len,
            data.len()
        )));
    }
    Ok(data[offset..offset + len].to_vec())
}

/// 读取 u16 小端。
fn read_u16(data: &[u8], offset: usize) -> PokerL1Result<u16> {
    if offset + 2 > data.len() {
        return Err(PokerL1Error::Serialization(format!(
            "read_u16 out of range: offset={}, data_len={}",
            offset,
            data.len()
        )));
    }
    let lo = data[offset] as u16;
    let hi = data[offset + 1] as u16;
    Ok(lo + (hi << 8))
}

/// 读取 G1 compressed bytes（48 字节）。
fn read_g1_point(data: &[u8], offset: usize) -> PokerL1Result<Vec<u8>> {
    read_bytes(data, offset, G1_POINT_SIZE)
}

/// 读取 Scalar bytes（32 字节）。
fn read_scalar(data: &[u8], offset: usize) -> PokerL1Result<Vec<u8>> {
    read_bytes(data, offset, SCALAR_SIZE)
}

// ========== Schnorr Proof 反序列化 ==========

/// 反序列化广义 Schnorr 证明。
///
/// 布局：commitment(48) + count(2) + responses(count * 32)
pub fn deserialize_schnorr_proof(data: &[u8], offset: usize) -> PokerL1Result<(GeneralizedSchnorrProof, usize)> {
    let mut off = offset;
    let commitment = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let count = read_u16(data, off)? as usize;
    off += 2;
    let mut responses = Vec::with_capacity(count);
    for _ in 0..count {
        responses.push(read_scalar(data, off)?);
        off += SCALAR_SIZE;
    }
    Ok((GeneralizedSchnorrProof::new(commitment, responses), off))
}

// ========== Shuffle Proof 反序列化 ==========

/// 反序列化 ShuffleProof。
///
/// 布局：sum_c1_commit(48) + sum_c2_commit(48) + nonce(32) + 3 个 schnorr_proof
pub fn deserialize_shuffle_proof(data: &[u8]) -> PokerL1Result<ShuffleProof> {
    let mut off = 0;
    let sum_c1_commit = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let sum_c2_commit = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let nonce = read_scalar(data, off)?;
    off += SCALAR_SIZE;
    let (combined_schnorr_proof, off2) = deserialize_schnorr_proof(data, off)?;
    off = off2;
    let (sum_c1_schnorr_proof, off3) = deserialize_schnorr_proof(data, off)?;
    off = off3;
    let (sum_c2_schnorr_proof, _) = deserialize_schnorr_proof(data, off)?;
    Ok(ShuffleProof::new(
        sum_c1_commit,
        sum_c2_commit,
        combined_schnorr_proof,
        sum_c1_schnorr_proof,
        sum_c2_schnorr_proof,
        nonce,
    ))
}

// ========== Remask Proof 反序列化 ==========

/// 反序列化 RemaskProof。
///
/// 布局：count(2) + per_card_commitments(count * 48) + commitment_pk(48) + response(32) + nonce(32)
pub fn deserialize_remask_proof(data: &[u8]) -> PokerL1Result<RemaskProof> {
    let mut off = 0;
    let count = read_u16(data, off)? as usize;
    off += 2;
    let mut per_card_commitments = Vec::with_capacity(count);
    for _ in 0..count {
        per_card_commitments.push(read_g1_point(data, off)?);
        off += G1_POINT_SIZE;
    }
    let commitment_pk = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let response = read_scalar(data, off)?;
    off += SCALAR_SIZE;
    let nonce = read_scalar(data, off)?;
    Ok(RemaskProof::new(
        per_card_commitments,
        commitment_pk,
        response,
        nonce,
    ))
}

// ========== Leave Proof 反序列化 ==========

/// 反序列化 LeaveProof。
///
/// 布局与 RemaskProof 相同：count(2) + per_card_commitments(count * 48) + commitment_pk(48) + response(32) + nonce(32)
pub fn deserialize_leave_proof(data: &[u8]) -> PokerL1Result<LeaveProof> {
    let mut off = 0;
    let count = read_u16(data, off)? as usize;
    off += 2;
    let mut per_card_commitments = Vec::with_capacity(count);
    for _ in 0..count {
        per_card_commitments.push(read_g1_point(data, off)?);
        off += G1_POINT_SIZE;
    }
    let commitment_pk = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let response = read_scalar(data, off)?;
    off += SCALAR_SIZE;
    let nonce = read_scalar(data, off)?;
    Ok(LeaveProof::new(
        per_card_commitments,
        commitment_pk,
        response,
        nonce,
    ))
}

// ========== Reveal Token Proof 反序列化 ==========

/// 反序列化 RevealTokenProof。
///
/// 布局：user_public_key(48) + commitment_t1(48) + commitment_t2(48) + response_s(32) + nonce(32)
pub fn deserialize_reveal_token_proof(data: &[u8]) -> PokerL1Result<RevealTokenProof> {
    let mut off = 0;
    let user_public_key = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let commitment_t1 = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let commitment_t2 = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let response_s = read_scalar(data, off)?;
    off += SCALAR_SIZE;
    let nonce = read_scalar(data, off)?;
    Ok(RevealTokenProof::new(
        user_public_key,
        commitment_t1,
        commitment_t2,
        response_s,
        nonce,
    ))
}

// ========== Reconstruct Proof 反序列化 ==========

/// 反序列化 ReconstructProof（最复杂）。
///
/// 布局：
/// - swap_out_count(2)
/// - 每个 swap_out_proof：
///   - user_readable_card(96) + swap_out_card(96) + chaum_pedersen(commitment_a(48) + commitment_b(48) + response(32))
/// - sum_c1_r_commit(48) + sum_c2_r_commit(48) + swap_sum_c1_commit(48) + swap_sum_c2_commit(48)
/// - nonce(32)
/// - blind_dleq_proof: commitment(48) + response(32) + nonce(32)
/// - total_dleq_proof: commitment_a(48) + commitment_b(48) + response(32)
/// - 3 个 schnorr_proof
pub fn deserialize_reconstruct_proof(data: &[u8]) -> PokerL1Result<ReconstructProof> {
    let mut off = 0;
    let swap_out_count = read_u16(data, off)? as usize;
    off += 2;
    let mut swap_out_proofs = Vec::with_capacity(swap_out_count);
    for _ in 0..swap_out_count {
        let user_readable_card = read_bytes(data, off, CIPHERTEXT_SIZE)?;
        off += CIPHERTEXT_SIZE;
        let swap_out_card = read_bytes(data, off, CIPHERTEXT_SIZE)?;
        off += CIPHERTEXT_SIZE;
        let cp_commitment_a = read_g1_point(data, off)?;
        off += G1_POINT_SIZE;
        let cp_commitment_b = read_g1_point(data, off)?;
        off += G1_POINT_SIZE;
        let cp_response = read_scalar(data, off)?;
        off += SCALAR_SIZE;
        let cp_proof = ChaumPedersenProof::new(cp_commitment_a, cp_commitment_b, cp_response);
        swap_out_proofs.push(SwapOutCardProof::new(
            user_readable_card,
            swap_out_card,
            cp_proof,
        ));
    }
    let sum_c1_r_commit = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let sum_c2_r_commit = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let swap_sum_c1_commit = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let swap_sum_c2_commit = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let nonce = read_scalar(data, off)?;
    off += SCALAR_SIZE;
    // blind_dleq_proof
    let blind_commitment = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let blind_response = read_scalar(data, off)?;
    off += SCALAR_SIZE;
    let blind_nonce = read_scalar(data, off)?;
    off += SCALAR_SIZE;
    let blind_dleq_proof = ReconstructionDLEQProof::new(blind_commitment, blind_response, blind_nonce);
    // total_dleq_proof
    let total_commitment_a = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let total_commitment_b = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let total_response = read_scalar(data, off)?;
    off += SCALAR_SIZE;
    let total_dleq_proof = ChaumPedersenProof::new(total_commitment_a, total_commitment_b, total_response);
    // 3 个 schnorr proofs
    let (swap_combined_schnorr_proof, off2) = deserialize_schnorr_proof(data, off)?;
    off = off2;
    let (sum_swap_out_c1_schnorr_proof, off3) = deserialize_schnorr_proof(data, off)?;
    off = off3;
    let (sum_swap_out_c2_schnorr_proof, _) = deserialize_schnorr_proof(data, off)?;
    Ok(ReconstructProof::new(
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
    ))
}

// ========== Chaum-Pedersen Proof 反序列化 ==========

/// 反序列化 ChaumPedersenProof。
///
/// 布局：commitment_a(48) + commitment_b(48) + response(32)
pub fn deserialize_chaum_pedersen_proof(data: &[u8]) -> PokerL1Result<ChaumPedersenProof> {
    let mut off = 0;
    let commitment_a = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let commitment_b = read_g1_point(data, off)?;
    off += G1_POINT_SIZE;
    let response = read_scalar(data, off)?;
    Ok(ChaumPedersenProof::new(commitment_a, commitment_b, response))
}

// ========== 密文与 G1 点向量反序列化 ==========

/// 反序列化密文向量。
///
/// 布局：count(2) + count * 96 字节（每个密文 c1(48) + c2(48)）
pub fn deserialize_ciphertexts(data: &[u8]) -> PokerL1Result<Vec<ElGamalCiphertext>> {
    let mut off = 0;
    let count = read_u16(data, off)? as usize;
    off += 2;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let ct_bytes = read_bytes(data, off, CIPHERTEXT_SIZE)?;
        off += CIPHERTEXT_SIZE;
        result.push(ElGamalCiphertext::from_bytes(&ct_bytes)?);
    }
    Ok(result)
}

/// 反序列化 G1 点向量（每个点 48 字节 compressed）。
///
/// 布局：count(2) + count * 48 字节
pub fn deserialize_g1_points(data: &[u8]) -> PokerL1Result<Vec<G1Projective>> {
    let mut off = 0;
    let count = read_u16(data, off)? as usize;
    off += 2;
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let pt_bytes = read_g1_point(data, off)?;
        off += G1_POINT_SIZE;
        result.push(parse_g1(&pt_bytes)?);
    }
    Ok(result)
}

// ========== 链下序列化（client feature） ==========

#[cfg(any(test, feature = "client"))]
mod serialize {
    use super::*;
    use super::super::bls_scalar::{serialize_g1};

    /// 序列化 Schnorr 证明。
    pub fn serialize_schnorr_proof(proof: &GeneralizedSchnorrProof) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&proof.commitment);
        let count = proof.responses.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        for r in &proof.responses {
            out.extend_from_slice(r);
        }
        out
    }

    /// 序列化 ShuffleProof。
    pub fn serialize_shuffle_proof(proof: &ShuffleProof) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&proof.sum_c1_commit);
        out.extend_from_slice(&proof.sum_c2_commit);
        out.extend_from_slice(&proof.nonce);
        out.extend(serialize_schnorr_proof(&proof.combined_schnorr_proof));
        out.extend(serialize_schnorr_proof(&proof.sum_c1_schnorr_proof));
        out.extend(serialize_schnorr_proof(&proof.sum_c2_schnorr_proof));
        out
    }

    /// 序列化 RemaskProof。
    pub fn serialize_remask_proof(proof: &RemaskProof) -> Vec<u8> {
        let mut out = Vec::new();
        let count = proof.per_card_commitments.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        for c in &proof.per_card_commitments {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&proof.commitment_pk);
        out.extend_from_slice(&proof.response);
        out.extend_from_slice(&proof.nonce);
        out
    }

    /// 序列化 LeaveProof。
    pub fn serialize_leave_proof(proof: &LeaveProof) -> Vec<u8> {
        let mut out = Vec::new();
        let count = proof.per_card_commitments.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        for c in &proof.per_card_commitments {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&proof.commitment_pk);
        out.extend_from_slice(&proof.response);
        out.extend_from_slice(&proof.nonce);
        out
    }

    /// 序列化 RevealTokenProof。
    pub fn serialize_reveal_token_proof(proof: &RevealTokenProof) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&proof.user_public_key);
        out.extend_from_slice(&proof.commitment_t1);
        out.extend_from_slice(&proof.commitment_t2);
        out.extend_from_slice(&proof.response_s);
        out.extend_from_slice(&proof.nonce);
        out
    }

    /// 序列化 ChaumPedersenProof。
    pub fn serialize_chaum_pedersen_proof(proof: &ChaumPedersenProof) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&proof.commitment_a);
        out.extend_from_slice(&proof.commitment_b);
        out.extend_from_slice(&proof.response);
        out
    }

    /// 序列化 ReconstructProof。
    pub fn serialize_reconstruct_proof(proof: &ReconstructProof) -> Vec<u8> {
        let mut out = Vec::new();
        let swap_count = proof.swap_out_proofs.len() as u16;
        out.extend_from_slice(&swap_count.to_le_bytes());
        for sop in &proof.swap_out_proofs {
            out.extend_from_slice(&sop.user_readable_card);
            out.extend_from_slice(&sop.swap_out_card);
            out.extend(serialize_chaum_pedersen_proof(&sop.chaum_pedersen_proof));
        }
        out.extend_from_slice(&proof.sum_c1_r_commit);
        out.extend_from_slice(&proof.sum_c2_r_commit);
        out.extend_from_slice(&proof.swap_sum_c1_commit);
        out.extend_from_slice(&proof.swap_sum_c2_commit);
        out.extend_from_slice(&proof.nonce);
        // blind_dleq_proof
        out.extend_from_slice(&proof.blind_dleq_proof.commitment);
        out.extend_from_slice(&proof.blind_dleq_proof.response);
        out.extend_from_slice(&proof.blind_dleq_proof.nonce);
        // total_dleq_proof
        out.extend(serialize_chaum_pedersen_proof(&proof.total_dleq_proof));
        // 3 schnorr proofs
        out.extend(serialize_schnorr_proof(&proof.swap_combined_schnorr_proof));
        out.extend(serialize_schnorr_proof(&proof.sum_swap_out_c1_schnorr_proof));
        out.extend(serialize_schnorr_proof(&proof.sum_swap_out_c2_schnorr_proof));
        out
    }

    /// 序列化密文向量。
    pub fn serialize_ciphertexts(cts: &[ElGamalCiphertext]) -> Vec<u8> {
        let mut out = Vec::new();
        let count = cts.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        for ct in cts {
            out.extend_from_slice(&ct.to_bytes());
        }
        out
    }

    /// 序列化 G1 点向量。
    pub fn serialize_g1_points(points: &[G1Projective]) -> Vec<u8> {
        let mut out = Vec::new();
        let count = points.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        for p in points {
            out.extend_from_slice(&serialize_g1(p));
        }
        out
    }
}

#[cfg(any(test, feature = "client"))]
pub use serialize::*;

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{g1_generator, hash_to_g1, scalar_from_u64};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_transcript(label: &[u8]) -> super::super::transcript::Transcript {
        super::super::transcript::Transcript::new(label)
    }

    #[test]
    fn test_schnorr_proof_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let base_points = vec![g1_generator(), hash_to_g1(b"base2")];
        let witnesses = vec![scalar_from_u64(123), scalar_from_u64(456)];
        let mut t = make_transcript(b"test_ser_schnorr");
        let (proof, _) =
            super::super::schnorr_proof::prove(&base_points, &witnesses, &mut t, &mut rng).unwrap();

        let bytes = serialize_schnorr_proof(&proof);
        let (proof2, off) = deserialize_schnorr_proof(&bytes, 0).unwrap();
        assert_eq!(off, bytes.len());
        assert_eq!(proof, proof2);
    }

    #[test]
    fn test_remask_proof_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts: Vec<ElGamalCiphertext> = (0..3)
            .map(|i| {
                let pt = hash_to_g1(format!("card_{i}").as_bytes());
                super::super::bls_elgamal::encrypt(&pt, &pk, &scalar_from_u64((i + 1) as u64))
            })
            .collect();
        let mut t = make_transcript(b"test_ser_remask");
        let (proof, _) =
            super::super::remask_proof::prove(&input_cts, &sk, &pk, &mut t, &mut rng).unwrap();

        let bytes = serialize_remask_proof(&proof);
        let proof2 = deserialize_remask_proof(&bytes).unwrap();
        assert_eq!(proof, proof2);
    }

    #[test]
    fn test_leave_proof_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts: Vec<ElGamalCiphertext> = (0..3)
            .map(|i| {
                let pt = hash_to_g1(format!("card_{i}").as_bytes());
                super::super::bls_elgamal::encrypt(&pt, &pk, &scalar_from_u64((i + 1) as u64))
            })
            .collect();
        let mut t = make_transcript(b"test_ser_leave");
        let (proof, _) =
            super::super::leave_proof::prove(&input_cts, &sk, &pk, &mut t, &mut rng).unwrap();

        let bytes = serialize_leave_proof(&proof);
        let proof2 = deserialize_leave_proof(&bytes).unwrap();
        assert_eq!(proof, proof2);
    }

    #[test]
    fn test_reveal_token_proof_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let pt = hash_to_g1(b"card_0");
        let ct = super::super::bls_elgamal::encrypt(&pt, &pk, &scalar_from_u64(7));
        let (proof, _) = super::super::reveal_token_proof::prove(&ct, &sk, &pk, &mut rng).unwrap();

        let bytes = serialize_reveal_token_proof(&proof);
        let proof2 = deserialize_reveal_token_proof(&bytes).unwrap();
        assert_eq!(proof, proof2);
    }

    #[test]
    fn test_shuffle_proof_roundtrip() {
        use blstrs::Scalar;
        use ff::Field;
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts: Vec<ElGamalCiphertext> = (0..4)
            .map(|i| {
                let pt = hash_to_g1(format!("card_{i}").as_bytes());
                super::super::bls_elgamal::encrypt(&pt, &pk, &scalar_from_u64((i + 1) as u64))
            })
            .collect();
        let permutation: Vec<usize> = vec![2, 0, 3, 1];
        let masks: Vec<Scalar> = (0..4).map(|_| Scalar::random(&mut rng)).collect();
        let mut t = make_transcript(b"test_ser_shuffle");
        let (proof, _) =
            super::super::shuffle_proof::prove(&input_cts, &permutation, &masks, &pk, &mut t, &mut rng).unwrap();

        let bytes = serialize_shuffle_proof(&proof);
        let proof2 = deserialize_shuffle_proof(&bytes).unwrap();
        assert_eq!(proof, proof2);
    }

    #[test]
    fn test_ciphertexts_roundtrip() {
        let pk = g1_generator() * scalar_from_u64(99);
        let cts: Vec<ElGamalCiphertext> = (0..5)
            .map(|i| {
                let pt = hash_to_g1(format!("c_{i}").as_bytes());
                super::super::bls_elgamal::encrypt(&pt, &pk, &scalar_from_u64((i + 1) as u64))
            })
            .collect();
        let bytes = serialize_ciphertexts(&cts);
        let cts2 = deserialize_ciphertexts(&bytes).unwrap();
        assert_eq!(cts.len(), cts2.len());
        for (a, b) in cts.iter().zip(cts2.iter()) {
            assert_eq!(a.c1, b.c1);
            assert_eq!(a.c2, b.c2);
        }
    }
}
