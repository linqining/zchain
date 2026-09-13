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
use core::fmt::Debug;

use std_shims::Vec;

use super::fields::qm31::SecureField;
use crate::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

#[cfg(feature = "wasm-poseidon")]
mod poseidon252;
#[cfg(feature = "wasm-poseidon")]
pub use poseidon252::Poseidon252Channel;

mod blake2s;
pub use blake2s::{Blake2sChannel, Blake2sChannelGeneric, Blake2sM31Channel};

pub const EXTENSION_FELTS_PER_HASH: usize = 2;

pub trait Channel: Default + Clone + Debug {
    const BYTES_PER_HASH: usize;

    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool;

    // Mix functions.
    fn mix_u32s(&mut self, data: &[u32]);
    fn mix_felts(&mut self, felts: &[SecureField]);
    fn mix_u64(&mut self, value: u64);

    // Draw functions.
    fn draw_secure_felt(&mut self) -> SecureField;
    /// Generates a uniform random vector of SecureField elements.
    fn draw_secure_felts(&mut self, n_felts: usize) -> Vec<SecureField>;
    /// Returns a vector of random u32s.
    ///
    /// The length of this vector depends on the channel's hash function.
    /// For blake2s channel, the length of the returned vector is 8
    /// while for poseidon channel, the length is 7.
    fn draw_u32s(&mut self) -> Vec<u32>;
}

pub trait MerkleChannel: Default {
    type C: Channel;
    type H: MerkleHasherLifted;
    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash);
}
