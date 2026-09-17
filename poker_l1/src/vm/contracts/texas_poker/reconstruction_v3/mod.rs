//! Vendored reconstruction proof family (V3 focus), adapted to the zchain
//! `poker_protocol` (zgame) type world.
//!
//! Vendored from `poker_texas_air/poker-protocol-proofs/src/reconstruction/`
//! (plus its Bayer--Groth backend from `poker-protocol-bg/src/proof.rs`) on
//! **2026-09-12**, because the zgame `poker_protocol` crate's
//! `zk_shuffle::reconstruction` module never carried the V3 API (B8 drift).
//!
//! Adaptations (proof/verification math is byte-for-byte unchanged):
//! - `poker_protocol_core::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric}`
//!   → `poker_protocol::crypto::curve::{...}` (same trait shape, different trait).
//! - `poker_protocol_core::VerificationError` → `poker_protocol::zk_shuffle::error::VerificationError`.
//!   The zgame enum lacks `InvalidPermutation` / `InvalidRerandomizerCount` /
//!   `InvalidCommitmentKey` / `InvalidBayerGrothProof`; those four (used only by
//!   the Bayer--Groth backend) are mapped onto closest existing variants, see
//!   `bayer_groth.rs`.
//! - `crate::transcript_ext::CryptoTranscript` → `poker_protocol::zk_shuffle::transcript_ext::CryptoTranscript`
//!   (identical method surface: `append_message` / `append_point` / `append_scalar` /
//!   `challenge::<C>() -> Challenge<C>`), so no local extension trait is needed.
//! - `poker_protocol_bg::BayerGrothShuffleProof` has **no** zgame counterpart
//!   (zgame never shipped a bayer_groth module), so the backend itself is
//!   vendored here as [`bayer_groth`].
//! - Borsh wire support is vendored in `borsh_impl_stark` and specialized on
//!   [`poker_protocol::crypto::types::DefaultCurve`] (StarkCurve，poker_protocol
//!   v1.0.0 起唯一世界)，mirroring the upstream field order and length discipline
//!   with the 32-byte felt compressed point / 32-byte big-endian scalar encoding.
//!
//! Not vendored (unused by poker_l1, and they pull `rayon`): the V2 proof glue
//! in upstream `mod.rs` (`ReconstructProof`, `reconstruct_deck`,
//! `derive_from_output_cards`, `exp_iter`). The V2 helper proofs this family
//! shares (`swap_out` / `chaum_pedersen` / `ordered_encryption`) are vendored
//! intact, and the legacy V2 transcript label constant is preserved so
//! historical artifact decoding keeps its exact domain.

mod bayer_groth;
mod chaum_pedersen;
mod cross_key;
mod ordered_encryption;
mod slot_or;
mod swap_out;
mod v3;

// poker_l1 declares no `borsh` cargo feature; its `borsh` dependency (and the
// `poker_protocol` `borsh` feature feeding the ElGamal impls used below)
// is always on, so the wire impls are compiled unconditionally.
// 旧 BLS 版 `borsh_impl.rs`（`ReconstructProofV3<Bls12381Curve>` 家族）随
// poker_protocol v1.0.0 删除 BLS 世界一并移除（上游声明"不考虑兼容"）；
// Stark wire impls 见下方 `borsh_impl_stark`。
pub use chaum_pedersen::ChaumPedersenDLEQProof;
pub use cross_key::CrossKeyNegationProof;
pub use ordered_encryption::OrderedEncryptionProof;
pub(crate) use slot_or::ContributionBranch;
pub use slot_or::SlotContributionOrProof;
pub use swap_out::{ReconstructionDLEQProof, SwapOutCardProof};
pub use v3::{
    apply_reconstruction_contributions, canonical_base_deck, ReconstructProofV3,
    ReconstructionV3Statement, RECONSTRUCTION_V3_PROOF_LABEL, RECONSTRUCTION_V3_PROOF_VERSION,
};

pub use bayer_groth::{BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument};

/// zgame [`poker_protocol::zk_shuffle::error::VerificationError`] re-exported
/// for parity with the upstream module surface.
pub use poker_protocol::zk_shuffle::error::VerificationError;

/// Legacy (V2) reconstruction transcript label.
///
/// The V2 proof glue itself is not vendored; this constant survives so
/// `utils::new_reconstruct_transcript` keeps constructing the exact historical
/// domain when decoding or auditing V2 artifacts.
pub const RECONSTRUCTION_PROOF_LABEL: &[u8] = b"zk_reconstruct_proof_v2";

/// Legacy (V2) reconstruction proof version byte.
pub const RECONSTRUCTION_PROOF_VERSION: u8 = 2;

pub mod borsh_impl_stark;
