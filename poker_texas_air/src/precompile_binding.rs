//! Trusted host binding for poker cryptographic precompile calls.
//!
//! A binding is issued only after the native backend verifies the canonical
//! request. Production verification replays that verification and recomputes
//! both digests; a proof-carried `success = true` value is never accepted.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use poker_protocol::precompile::{
    NativeBls12381ReconstructionV3Verifier, NativeBls12381ShuffleVerifier,
};
use poker_protocol::precompile_abi::{
    ReconstructionV3Verifier, ReconstructionV3VerifyRequest, ShuffleVerifier, ShuffleVerifyRequest,
    RECONSTRUCTION_V3_ABI_VERSION, SHUFFLE_ABI_VERSION,
};
use stwo::core::fields::m31::M31;

use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::state_root::StateRoot;

/// Number of M31 columns used for one full 256-bit digest.
pub const DIGEST_LIMBS: usize = 16;

/// Poker proof precompile selected by a call binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PokerPrecompileId {
    /// Bayer--Groth shuffle proof verification.
    Shuffle = 1,
    /// Reconstruction V3 slot-OR verification.
    ReconstructionV3 = 3,
}

/// Native backend identity committed by the receipt digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrecompileBackendId {
    /// Auditable Rust BLS12-381 reference verifier.
    NativeBls12381V1 = 1,
}

/// AIR-visible projection of a verified precompile call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecompileAirBinding {
    /// Precompile selector.
    pub precompile_id: u8,
    /// Canonical request ABI version.
    pub abi_version: u8,
    /// Full request digest represented by sixteen big-endian u16 limbs.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Full verifier-issued receipt digest represented identically.
    pub receipt_digest: [M31; DIGEST_LIMBS],
}

impl PrecompileAirBinding {
    /// Zero binding used only by mechanism tests that exercise the explicitly
    /// untrusted `verify_method` compatibility entry point.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn synthetic_unverified() -> Self {
        Self {
            precompile_id: 0,
            abi_version: 0,
            request_digest: [M31::from(0u32); DIGEST_LIMBS],
            receipt_digest: [M31::from(0u32); DIGEST_LIMBS],
        }
    }
}

/// Verifier-issued binding containing the canonical precompile request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileCallBinding {
    precompile_id: PokerPrecompileId,
    abi_version: u8,
    backend_id: PrecompileBackendId,
    request_bytes: Vec<u8>,
    request_digest: [u8; 32],
    receipt_digest: [u8; 32],
}

impl PrecompileCallBinding {
    /// Verify and bind a canonical shuffle request with the native backend.
    pub fn verify_shuffle(request: &ShuffleVerifyRequest) -> TexasAirResult<Self> {
        let request_bytes = request.encode().map_err(precompile_error)?;
        NativeBls12381ShuffleVerifier
            .verify(request)
            .map_err(precompile_error)?;
        Ok(Self::issue(
            PokerPrecompileId::Shuffle,
            SHUFFLE_ABI_VERSION,
            request_bytes,
        ))
    }

    /// Verify and bind a canonical reconstruction V3 request with the native backend.
    pub fn verify_reconstruction_v3(
        request: &ReconstructionV3VerifyRequest,
    ) -> TexasAirResult<Self> {
        let request_bytes = request.encode().map_err(precompile_error)?;
        NativeBls12381ReconstructionV3Verifier
            .verify(request)
            .map_err(precompile_error)?;
        Ok(Self::issue(
            PokerPrecompileId::ReconstructionV3,
            RECONSTRUCTION_V3_ABI_VERSION,
            request_bytes,
        ))
    }

    fn issue(precompile_id: PokerPrecompileId, abi_version: u8, request_bytes: Vec<u8>) -> Self {
        let backend_id = PrecompileBackendId::NativeBls12381V1;
        let request_digest = hash256(b"zchain.poker.precompile.request.v1", &request_bytes);
        let mut receipt = Vec::with_capacity(4 + 32);
        receipt.extend_from_slice(&[
            precompile_id as u8,
            abi_version,
            backend_id as u8,
            1, // verified-success result code
        ]);
        receipt.extend_from_slice(&request_digest);
        let receipt_digest = hash256(b"zchain.poker.precompile.receipt.v1", &receipt);
        Self {
            precompile_id,
            abi_version,
            backend_id,
            request_bytes,
            request_digest,
            receipt_digest,
        }
    }

    /// Re-run canonical decoding and native verification, then recompute every
    /// committed field. This is the production verifier's fail-closed check.
    pub fn reverify(&self) -> TexasAirResult<()> {
        let rebuilt = match self.precompile_id {
            PokerPrecompileId::Shuffle => {
                let request =
                    ShuffleVerifyRequest::decode(&self.request_bytes).map_err(precompile_error)?;
                Self::verify_shuffle(&request)?
            }
            PokerPrecompileId::ReconstructionV3 => {
                let request = ReconstructionV3VerifyRequest::decode(&self.request_bytes)
                    .map_err(precompile_error)?;
                Self::verify_reconstruction_v3(&request)?
            }
        };
        if &rebuilt != self {
            return Err(TexasAirError::SpecViolation(
                "precompile binding metadata/digest does not match canonical re-verification"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Precompile selector.
    #[must_use]
    pub const fn precompile_id(&self) -> PokerPrecompileId {
        self.precompile_id
    }

    /// Canonical request ABI version.
    #[must_use]
    pub const fn abi_version(&self) -> u8 {
        self.abi_version
    }

    /// Backend identity committed by the receipt.
    #[must_use]
    pub const fn backend_id(&self) -> PrecompileBackendId {
        self.backend_id
    }

    /// Full canonical request digest.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Full verifier-issued receipt digest.
    #[must_use]
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    /// Canonical request bytes retained for independent verifier replay.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    /// Convert the full digests to AIR columns without truncation.
    #[must_use]
    pub fn air_binding(&self) -> PrecompileAirBinding {
        PrecompileAirBinding {
            precompile_id: self.precompile_id as u8,
            abi_version: self.abi_version,
            request_digest: digest_to_m31_limbs(self.request_digest),
            receipt_digest: digest_to_m31_limbs(self.receipt_digest),
        }
    }
}

/// Construct the canonical replay scope included in every proof request.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn precompile_call_context(
    kind: MethodKind,
    seat_index: u8,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
    pre_version: u64,
    post_version: u64,
    pre_state_root: StateRoot,
    post_state_root: StateRoot,
    dispatch_call_digest: [u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(128);
    context.extend_from_slice(b"zchain.texas_poker.precompile_call.v1");
    context.extend_from_slice(&[kind as u8, seat_index]);
    context.extend_from_slice(&table_id.to_le_bytes());
    context.extend_from_slice(&hand_id.to_le_bytes());
    context.extend_from_slice(&call_seq.to_le_bytes());
    context.extend_from_slice(&pre_version.to_le_bytes());
    context.extend_from_slice(&post_version.to_le_bytes());
    context.extend_from_slice(&pre_state_root.field().to_bytes_be());
    context.extend_from_slice(&post_state_root.field().to_bytes_be());
    context.extend_from_slice(&dispatch_call_digest);
    context
}

/// Represent a 256-bit digest by sixteen exact u16 limbs in M31.
#[must_use]
pub fn digest_to_m31_limbs(digest: [u8; 32]) -> [M31; DIGEST_LIMBS] {
    std::array::from_fn(|i| {
        M31::from(u32::from(u16::from_be_bytes([
            digest[2 * i],
            digest[2 * i + 1],
        ])))
    })
}

fn hash256(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(domain);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

fn precompile_error(error: impl std::fmt::Display) -> TexasAirError {
    TexasAirError::SpecViolation(format!("poker precompile verification failed: {error}"))
}
