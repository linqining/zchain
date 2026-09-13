//! Vendored Borsh wire encodings for the reconstruction V3 family, specialized
//! on the zchain default curve (`StarkCurve`, i.e. zgame `DefaultCurve`).
//!
//! Mirrors `poker_texas_air/poker-protocol-{bg,proofs}/src/borsh_impl.rs`
//! (2026-09-12): identical field order, u32 LE length prefixes, the same
//! 1..=1024 / 2..=1024 length discipline and version-byte checks, so the
//! logical wire shape is the upstream one. Point/scalar encodings follow the
//! zgame `poker_protocol` convention (48-byte compressed BLS12-381 G1,
//! 32-byte big-endian scalar), consistent with the existing zgame impls for
//! `ElGamalCiphertextGeneric<StarkCurve>` / `ECPoint`.
//!
//! `ElGamalCiphertextGeneric<StarkCurve>` itself is implemented in zgame
//! (`poker_protocol` crate, `borsh` feature) and is reused here.

use borsh::{BorshDeserialize, BorshSerialize};
use group::GroupEncoding;

use poker_protocol::crypto::curve::CurveScalar;
use poker_protocol::crypto::stark_curve::{StarkCurve, StarkPoint, StarkScalar};

use super::bayer_groth::{BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument};
use super::chaum_pedersen::ChaumPedersenDLEQProof;
use super::cross_key::CrossKeyNegationProof;
use super::ordered_encryption::OrderedEncryptionProof;
use super::slot_or::SlotContributionOrProof;
use super::swap_out::{ReconstructionDLEQProof, SwapOutCardProof};
use super::v3::{ReconstructProofV3, ReconstructionV3Statement, RECONSTRUCTION_V3_PROOF_VERSION};

// ============================================================
// Fixed-width point/scalar helpers (zgame encoding conventions)
// ============================================================

/// Stark 曲线压缩点字节数（32 字节 felt）。
const G1_COMPRESSED_LEN: usize = 32;
/// BLS scalar byte length (big-endian, Move-compatible).
const SCALAR_LEN: usize = 32;

/// Upstream deck-size discipline: reconstruction vectors never exceed 1024.
const MAX_RECONSTRUCTION_DECK_SIZE: usize = 1024;

#[inline]
fn write_point<W: borsh::io::Write>(p: &StarkPoint, w: &mut W) -> borsh::io::Result<()> {
    w.write_all(p.to_compressed().as_ref())
}

#[inline]
fn read_point<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<StarkPoint> {
    let mut bytes = [0u8; G1_COMPRESSED_LEN];
    r.read_exact(&mut bytes)?;
    StarkPoint::from_compressed(&bytes).ok_or_else(|| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid stark compressed point",
        )
    })
}

#[inline]
fn write_scalar<W: borsh::io::Write>(s: &StarkScalar, w: &mut W) -> borsh::io::Result<()> {
    // CurveScalar::as_bytes() -> to_bytes_be() -> 32-byte big-endian (Move-compatible).
    let bytes = <StarkScalar as CurveScalar>::as_bytes(s);
    w.write_all(&bytes)
}

#[inline]
fn read_scalar<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<StarkScalar> {
    let mut bytes = [0u8; SCALAR_LEN];
    r.read_exact(&mut bytes)?;
    // from_bytes_mod_order accepts any 32 bytes and reduces mod q.
    Ok(<StarkScalar as CurveScalar>::from_bytes_mod_order(&bytes))
}

#[inline]
fn write_scalar_vec<W: borsh::io::Write>(v: &[StarkScalar], w: &mut W) -> borsh::io::Result<()> {
    let len = v.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    for s in v {
        write_scalar(s, w)?;
    }
    Ok(())
}

#[inline]
fn read_scalar_vec<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Vec<StarkScalar>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_scalar(r)?);
    }
    Ok(out)
}

fn write_reconstruction_len<W: borsh::io::Write>(
    len: usize,
    min: usize,
    w: &mut W,
) -> borsh::io::Result<()> {
    if !(min..=MAX_RECONSTRUCTION_DECK_SIZE).contains(&len) {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid reconstruction vector length",
        ));
    }
    let len = u32::try_from(len).map_err(|_| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "reconstruction vector too long",
        )
    })?;
    w.write_all(&len.to_le_bytes())
}

fn read_reconstruction_len<R: borsh::io::Read>(r: &mut R, min: usize) -> borsh::io::Result<usize> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if !(min..=MAX_RECONSTRUCTION_DECK_SIZE).contains(&len) {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid reconstruction vector length",
        ));
    }
    Ok(len)
}

// ============================================================
// Legacy V2 helper proofs (parity with upstream borsh_impl)
// ============================================================

impl BorshSerialize for ChaumPedersenDLEQProof<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.commitment_a, w)?;
        write_point(&self.commitment_b, w)?;
        write_scalar(&self.response, w)
    }
}

impl BorshDeserialize for ChaumPedersenDLEQProof<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let commitment_a = read_point(r)?;
        let commitment_b = read_point(r)?;
        let response = read_scalar(r)?;
        Ok(Self {
            commitment_a,
            commitment_b,
            response,
        })
    }
}

impl BorshSerialize for ReconstructionDLEQProof<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.commitment, w)?;
        write_scalar(&self.response, w)?;
        write_scalar(&self.nonce, w)
    }
}

impl BorshDeserialize for ReconstructionDLEQProof<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let commitment = read_point(r)?;
        let response = read_scalar(r)?;
        let nonce = read_scalar(r)?;
        Ok(Self {
            commitment,
            response,
            nonce,
        })
    }
}

impl BorshSerialize for SwapOutCardProof<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.user_readable_card, w)?;
        BorshSerialize::serialize(&self.swap_out_card, w)?;
        BorshSerialize::serialize(&self.chaum_pedersen_proof, w)
    }
}

impl BorshDeserialize for SwapOutCardProof<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let user_readable_card = BorshDeserialize::deserialize_reader(r)?;
        let swap_out_card = BorshDeserialize::deserialize_reader(r)?;
        let chaum_pedersen_proof = BorshDeserialize::deserialize_reader(r)?;
        Ok(Self {
            user_readable_card,
            swap_out_card,
            chaum_pedersen_proof,
        })
    }
}

impl BorshSerialize for OrderedEncryptionProof<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        let n = self.responses.len();
        if self.commitment_g.len() != n || self.commitment_pk.len() != n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "mismatched ordered encryption proof lengths",
            ));
        }
        write_reconstruction_len(n, 2, w)?;
        for point in &self.commitment_g {
            write_point(point, w)?;
        }
        for point in &self.commitment_pk {
            write_point(point, w)?;
        }
        for response in &self.responses {
            write_scalar(response, w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for OrderedEncryptionProof<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let n = read_reconstruction_len(r, 2)?;
        let commitment_g = (0..n).map(|_| read_point(r)).collect::<Result<_, _>>()?;
        let commitment_pk = (0..n).map(|_| read_point(r)).collect::<Result<_, _>>()?;
        let responses = (0..n).map(|_| read_scalar(r)).collect::<Result<_, _>>()?;
        Ok(Self {
            commitment_g,
            commitment_pk,
            responses,
        })
    }
}

// ============================================================
// Bayer--Groth shuffle proof
// ============================================================

impl BorshSerialize for MultiExponentiationArgument<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_point(&self.c_alpha, writer)?;
        write_point(&self.c_beta, writer)?;
        BorshSerialize::serialize(&self.ciphertext_0, writer)?;
        BorshSerialize::serialize(&self.ciphertext_1, writer)?;
        write_scalar_vec(&self.alpha_response, writer)?;
        write_scalar(&self.commitment_response, writer)?;
        write_scalar(&self.beta, writer)?;
        write_scalar(&self.beta_blinding_response, writer)?;
        write_scalar(&self.rerandomization_response, writer)
    }
}

impl BorshDeserialize for MultiExponentiationArgument<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            c_alpha: read_point(reader)?,
            c_beta: read_point(reader)?,
            ciphertext_0: BorshDeserialize::deserialize_reader(reader)?,
            ciphertext_1: BorshDeserialize::deserialize_reader(reader)?,
            alpha_response: read_scalar_vec(reader)?,
            commitment_response: read_scalar(reader)?,
            beta: read_scalar(reader)?,
            beta_blinding_response: read_scalar(reader)?,
            rerandomization_response: read_scalar(reader)?,
        })
    }
}

impl BorshSerialize for ProductArgument<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_point(&self.c_d, writer)?;
        write_point(&self.c_delta, writer)?;
        write_point(&self.c_capital_delta, writer)?;
        write_scalar_vec(&self.a_response, writer)?;
        write_scalar_vec(&self.b_response, writer)?;
        write_scalar(&self.r_response, writer)?;
        write_scalar(&self.s_response, writer)
    }
}

impl BorshDeserialize for ProductArgument<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let c_d = read_point(reader)?;
        let c_delta = read_point(reader)?;
        let c_capital_delta = read_point(reader)?;
        let a_response = read_scalar_vec(reader)?;
        let b_response = read_scalar_vec(reader)?;
        if a_response.len() != b_response.len() {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "mismatched Bayer-Groth product response lengths",
            ));
        }
        Ok(Self {
            c_d,
            c_delta,
            c_capital_delta,
            a_response,
            b_response,
            r_response: read_scalar(reader)?,
            s_response: read_scalar(reader)?,
        })
    }
}

impl BorshSerialize for BayerGrothShuffleProof<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_point(&self.c_permutation, writer)?;
        write_point(&self.c_permuted_powers, writer)?;
        BorshSerialize::serialize(&self.multi_exponentiation, writer)?;
        BorshSerialize::serialize(&self.product, writer)
    }
}

impl BorshDeserialize for BayerGrothShuffleProof<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let c_permutation = read_point(reader)?;
        let c_permuted_powers = read_point(reader)?;
        let multi_exponentiation = MultiExponentiationArgument::deserialize_reader(reader)?;
        let product = ProductArgument::deserialize_reader(reader)?;
        let n = multi_exponentiation.alpha_response.len();
        if product.a_response.len() != n || product.b_response.len() != n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "mismatched Bayer-Groth proof response lengths",
            ));
        }
        Ok(Self {
            c_permutation,
            c_permuted_powers,
            multi_exponentiation,
            product,
        })
    }
}

// ============================================================
// Reconstruction V3 statement and proof package
// ============================================================

impl BorshSerialize for CrossKeyNegationProof<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.commitment_owner_key, w)?;
        write_point(&self.commitment_contribution_c1, w)?;
        write_point(&self.commitment_joint_c2, w)?;
        write_scalar(&self.response_owner_sk, w)?;
        write_scalar(&self.response_contribution_randomness, w)
    }
}

impl BorshDeserialize for CrossKeyNegationProof<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            commitment_owner_key: read_point(r)?,
            commitment_contribution_c1: read_point(r)?,
            commitment_joint_c2: read_point(r)?,
            response_owner_sk: read_scalar(r)?,
            response_contribution_randomness: read_scalar(r)?,
        })
    }
}

impl BorshSerialize for SlotContributionOrProof<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        for point in &self.commitment_g {
            write_point(point, w)?;
        }
        for point in &self.commitment_pk {
            write_point(point, w)?;
        }
        for challenge in &self.challenges {
            write_scalar(challenge, w)?;
        }
        for response in &self.responses {
            write_scalar(response, w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for SlotContributionOrProof<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            commitment_g: [read_point(r)?, read_point(r)?],
            commitment_pk: [read_point(r)?, read_point(r)?],
            challenges: [read_scalar(r)?, read_scalar(r)?],
            responses: [read_scalar(r)?, read_scalar(r)?],
        })
    }
}

impl BorshSerialize for ReconstructionV3Statement<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        if self.version != RECONSTRUCTION_V3_PROOF_VERSION
            || self.cards.len() != self.contributions.len()
            || self.user_readable_cards.len() > self.cards.len()
        {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid reconstruction V3 statement shape",
            ));
        }
        w.write_all(&[self.version])?;
        w.write_all(&self.context_digest)?;
        w.write_all(&self.reconstruction_epoch.to_le_bytes())?;
        w.write_all(&self.prior_state_digest)?;
        write_point(&self.aggregate_pk, w)?;
        write_point(&self.owner_pk, w)?;

        write_reconstruction_len(self.cards.len(), 2, w)?;
        for card in &self.cards {
            write_point(card, w)?;
        }
        write_reconstruction_len(self.user_readable_cards.len(), 1, w)?;
        for ciphertext in &self.user_readable_cards {
            BorshSerialize::serialize(ciphertext, w)?;
        }
        // Contributions have exactly the canonical card count, so no second
        // attacker-controlled length is necessary on the wire.
        for ciphertext in &self.contributions {
            BorshSerialize::serialize(ciphertext, w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for ReconstructionV3Statement<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        if version[0] != RECONSTRUCTION_V3_PROOF_VERSION {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "unsupported reconstruction V3 statement version",
            ));
        }
        let mut context_digest = [0u8; 32];
        r.read_exact(&mut context_digest)?;
        let mut epoch_bytes = [0u8; 8];
        r.read_exact(&mut epoch_bytes)?;
        let reconstruction_epoch = u64::from_le_bytes(epoch_bytes);
        let mut prior_state_digest = [0u8; 32];
        r.read_exact(&mut prior_state_digest)?;
        let aggregate_pk = read_point(r)?;
        let owner_pk = read_point(r)?;

        let n = read_reconstruction_len(r, 2)?;
        let cards = (0..n).map(|_| read_point(r)).collect::<Result<_, _>>()?;
        let k = read_reconstruction_len(r, 1)?;
        if k > n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "more readable cards than reconstruction slots",
            ));
        }
        let user_readable_cards = (0..k)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<poker_protocol::crypto::curve::ElGamalCiphertextGeneric<StarkCurve>>, _>>()?;
        let contributions = (0..n)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<poker_protocol::crypto::curve::ElGamalCiphertextGeneric<StarkCurve>>, _>>()?;
        let statement = Self {
            version: version[0],
            context_digest,
            reconstruction_epoch,
            prior_state_digest,
            aggregate_pk,
            owner_pk,
            cards,
            user_readable_cards,
            contributions,
        };
        statement.validate().map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid reconstruction V3 statement",
            )
        })?;
        Ok(statement)
    }
}

impl BorshSerialize for ReconstructProofV3<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        let k = self.negative_contributions.len();
        let n = self.slot_membership_proofs.len();
        if self.cross_key_proofs.len() != k || k == 0 || k > n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid reconstruction V3 proof shape",
            ));
        }
        w.write_all(&[RECONSTRUCTION_V3_PROOF_VERSION])?;
        write_reconstruction_len(k, 1, w)?;
        for ciphertext in &self.negative_contributions {
            BorshSerialize::serialize(ciphertext, w)?;
        }
        for proof in &self.cross_key_proofs {
            BorshSerialize::serialize(proof, w)?;
        }
        BorshSerialize::serialize(&self.contribution_shuffle_proof, w)?;
        write_reconstruction_len(n, 2, w)?;
        for proof in &self.slot_membership_proofs {
            BorshSerialize::serialize(proof, w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for ReconstructProofV3<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        if version[0] != RECONSTRUCTION_V3_PROOF_VERSION {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "unsupported reconstruction V3 proof version",
            ));
        }
        let k = read_reconstruction_len(r, 1)?;
        let negative_contributions = (0..k)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<poker_protocol::crypto::curve::ElGamalCiphertextGeneric<StarkCurve>>, _>>()?;
        let cross_key_proofs = (0..k)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<CrossKeyNegationProof<StarkCurve>>, _>>()?;
        let contribution_shuffle_proof =
            BayerGrothShuffleProof::<StarkCurve>::deserialize_reader(r)?;
        let n = read_reconstruction_len(r, 2)?;
        if k > n
            || contribution_shuffle_proof
                .multi_exponentiation
                .alpha_response
                .len()
                != n
        {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "reconstruction V3 proof vector lengths disagree",
            ));
        }
        let slot_membership_proofs = (0..n)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<SlotContributionOrProof<StarkCurve>>, _>>()?;
        Ok(Self {
            negative_contributions,
            cross_key_proofs,
            contribution_shuffle_proof,
            slot_membership_proofs,
        })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol::crypto::curve::{Curve, ElGamalCiphertextGeneric};
    use super::super::RECONSTRUCTION_V3_PROOF_LABEL;
    use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
    use rand_core::OsRng;

    #[test]
    fn reconstruction_v3_statement_and_proof_borsh_roundtrip() {
        let cards = (0..8)
            .map(|i| {
                <StarkCurve as Curve>::hash_to_curve(
                    format!("borsh/reconstruction/v3/card/{i}").as_bytes(),
                )
            })
            .collect::<Vec<_>>();
        let owner_sk = <StarkScalar as CurveScalar>::from_u64(73);
        let other_sk = <StarkScalar as CurveScalar>::from_u64(29);
        let aggregate_sk = owner_sk + other_sk;
        let owner_pk = <StarkCurve as Curve>::base_g() * owner_sk;
        let aggregate_pk = <StarkCurve as Curve>::base_g() * aggregate_sk;
        let readable_cards = [1usize, 6]
            .iter()
            .enumerate()
            .map(|(i, index)| {
                ElGamalCiphertextGeneric::<StarkCurve>::encrypt(
                    &cards[*index],
                    &owner_pk,
                    &<StarkScalar as CurveScalar>::from_u64(2000 + i as u64),
                )
            })
            .collect::<Vec<_>>();

        let (statement, proof) = ReconstructProofV3::<StarkCurve>::prove(
            [3u8; 32],
            12,
            [4u8; 32],
            cards,
            readable_cards,
            &owner_sk,
            &owner_pk,
            &aggregate_pk,
            &mut OsRng,
            &mut FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL),
        )
        .unwrap();

        let statement_bytes = borsh::to_vec(&statement).unwrap();
        let proof_bytes = borsh::to_vec(&proof).unwrap();
        assert_eq!(statement_bytes[0], RECONSTRUCTION_V3_PROOF_VERSION);
        assert_eq!(proof_bytes[0], RECONSTRUCTION_V3_PROOF_VERSION);

        let recovered_statement: ReconstructionV3Statement<StarkCurve> =
            borsh::from_slice(&statement_bytes).unwrap();
        let recovered_proof: ReconstructProofV3<StarkCurve> =
            borsh::from_slice(&proof_bytes).unwrap();
        assert_eq!(statement, recovered_statement);
        recovered_proof
            .verify(
                &recovered_statement,
                &mut FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL),
            )
            .unwrap();
    }

    #[test]
    fn reconstruction_v3_borsh_rejects_unknown_version_and_huge_length() {
        assert!(borsh::from_slice::<ReconstructProofV3<StarkCurve>>(&[99]).is_err());

        let mut malicious = vec![RECONSTRUCTION_V3_PROOF_VERSION];
        malicious.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(borsh::from_slice::<ReconstructProofV3<StarkCurve>>(&malicious).is_err());
    }
}
