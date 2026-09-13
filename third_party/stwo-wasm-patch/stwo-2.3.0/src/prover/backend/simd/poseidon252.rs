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
use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use starknet_ff::FieldElement as FieldElement252;

use super::SimdBackend;
use crate::core::fields::m31::BaseField;
use crate::core::vcs::poseidon252_merkle::Poseidon252MerkleHasher;
#[cfg(feature = "wasm-poseidon")]
use crate::core::vcs::MerkleHasher;
use crate::parallel_iter;
use crate::prover::backend::{Col, Column, ColumnOps};
use crate::prover::vcs::ops::MerkleOps;

impl ColumnOps<FieldElement252> for SimdBackend {
    type Column = Vec<FieldElement252>;

    fn bit_reverse_column(_column: &mut Self::Column) {
        unimplemented!()
    }
}

impl MerkleOps<Poseidon252MerkleHasher> for SimdBackend {
    // TODO(ShaharS): replace with SIMD implementation.
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<FieldElement252>>,
        columns: &[&Col<Self, BaseField>],
    ) -> Vec<FieldElement252> {
        let iter = parallel_iter!(0..(1 << log_size));
        iter.map(|i| {
            Poseidon252MerkleHasher::hash_node(
                prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                &columns.iter().map(|column| column.at(i)).collect_vec(),
            )
        })
        .collect()
    }
}
