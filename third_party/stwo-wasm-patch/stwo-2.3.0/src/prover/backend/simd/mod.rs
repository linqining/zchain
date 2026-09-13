// VENDORED PATCH — provenance (zchain stwo-wasm path A):
// - Source: crates.io `stwo` 2.3.0 (sha of origin dir: registry
//   index.crates.io-1949cf8c6b5b557f/stwo-2.3.0), vendored at
//   third_party/stwo-wasm-patch/stwo-2.3.0 (zchain repo).
// - Local change (the ONLY functional change across the vendored tree):
//   the poseidon252 family exclusion gate
//   `#[cfg(not(target_arch = "wasm32"))]` was converted to the explicit
//   feature gate `#[cfg(feature = "wasm-poseidon")]` (default-on; see
//   Cargo.toml [features]) at every site that excluded Poseidon252Channel /
//   Poseidon252MerkleHasher / the simd+cpu backend impls on wasm32.
//   Rationale: starknet-crypto 0.6.2 (this crate's poseidon dependency) is
//   pure Rust and compiles for wasm32-unknown-unknown (measured: zchain
//   stwo-wasm-probe, logs/wasm_check_*.txt EXIT=0), so the original gate is
//   preventive, not a technical constraint. Feature gate instead of removing
//   the gate entirely keeps upstream's ability to build a
//   poseidon-free wasm verifier, while default-on makes wasm behave like
//   native for existing consumers.
// - Upstream issue draft: docs/stwo-wasm-path-a.md (zchain repo) §"Upstream issue draft".
// - All other lines are byte-identical to the registry copy (`diff -r` attested
//   in docs/stwo-wasm-path-a.md).
use serde::{Deserialize, Serialize};

use super::{Backend, BackendForChannel};
use crate::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
#[cfg(feature = "wasm-poseidon")]
use crate::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;

pub mod accumulation;
pub mod bit_reverse;
pub mod blake2s;
pub mod blake2s_lifted;
#[cfg(test)]
pub mod blake2s_ref;
pub mod circle;
pub mod cm31;
pub mod column;
pub mod conversion;
pub mod domain;
pub mod fft;
pub mod fri;
mod grind;
pub mod lookups;
pub mod m31;
#[cfg(feature = "wasm-poseidon")]
pub mod poseidon252;
#[cfg(feature = "wasm-poseidon")]
pub mod poseidon252_lifted;
pub mod prefix_sum;
pub mod qm31;
pub mod quotients;
mod utils;
pub mod very_packed_m31;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct SimdBackend;

impl Backend for SimdBackend {}
impl BackendForChannel<Blake2sMerkleChannel> for SimdBackend {}
impl BackendForChannel<Blake2sM31MerkleChannel> for SimdBackend {}
#[cfg(feature = "wasm-poseidon")]
impl BackendForChannel<Poseidon252MerkleChannel> for SimdBackend {}

// Optimal chunk sizes were determined empirically on an intel 155u machine.
pub(super) const PACKED_M31_BATCH_INVERSE_CHUNK_SIZE: usize = 1 << 9;
pub(super) const PACKED_CM31_BATCH_INVERSE_CHUNK_SIZE: usize = 1 << 10;
pub(super) const PACKED_QM31_BATCH_INVERSE_CHUNK_SIZE: usize = 1 << 11;
