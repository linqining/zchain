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
//! Vector commitment scheme (VCS) module.

pub mod blake2_hash;
pub mod blake2_merkle;
pub mod blake3_hash;
pub mod hash;
mod merkle_hasher;
pub use merkle_hasher::MerkleHasher;
#[cfg(feature = "wasm-poseidon")]
pub mod poseidon252_merkle;
#[cfg(all(test, feature = "prover"))]
pub mod test_utils;
pub mod utils;
pub mod verifier;
