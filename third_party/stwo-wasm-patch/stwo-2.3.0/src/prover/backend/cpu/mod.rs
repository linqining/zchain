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
pub mod accumulation;
mod blake2s;
pub mod circle;
mod fri;
mod grind;
pub mod lookups;
mod merkle_lifted;
#[cfg(feature = "wasm-poseidon")]
mod poseidon252;
pub mod quotients;

use std::fmt::Debug;

pub use fri::{fold_circle_into_line_cpu, fold_line_cpu};
use serde::{Deserialize, Serialize};

use super::{Backend, BackendForChannel, Column, ColumnOps};
use crate::core::utils::bit_reverse;
use crate::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
#[cfg(feature = "wasm-poseidon")]
use crate::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use crate::prover::lookups::mle::Mle;
use crate::prover::poly::circle::{CircleCoefficients, CircleEvaluation};

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct CpuBackend;

impl Backend for CpuBackend {}
impl BackendForChannel<Blake2sMerkleChannel> for CpuBackend {}
impl BackendForChannel<Blake2sM31MerkleChannel> for CpuBackend {}
#[cfg(feature = "wasm-poseidon")]
impl BackendForChannel<Poseidon252MerkleChannel> for CpuBackend {}

impl<T: Debug + Clone + Default + Send + Sync> ColumnOps<T> for CpuBackend {
    type Column = Vec<T>;

    fn bit_reverse_column(column: &mut Self::Column) {
        bit_reverse(column)
    }
}

impl<T: Debug + Clone + Default + Send + Sync> Column<T> for Vec<T> {
    fn zeros(len: usize) -> Self {
        vec![T::default(); len]
    }
    #[allow(clippy::uninit_vec)]
    unsafe fn uninitialized(length: usize) -> Self {
        let mut data = Vec::with_capacity(length);
        data.set_len(length);
        data
    }
    fn to_cpu(&self) -> Vec<T> {
        self.clone()
    }
    fn len(&self) -> usize {
        self.len()
    }
    fn at(&self, index: usize) -> T {
        self[index].clone()
    }
    fn set(&mut self, index: usize, value: T) {
        self[index] = value;
    }
    fn split_at_mid(mut self) -> (Self, Self) {
        let second = self.split_off(self.len() / 2);
        (self, second)
    }
}

pub type CpuCirclePoly = CircleCoefficients<CpuBackend>;
pub type CpuCircleEvaluation<F, EvalOrder> = CircleEvaluation<CpuBackend, F, EvalOrder>;
pub type CpuMle<F> = Mle<CpuBackend, F>;

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rand::prelude::*;
    use rand::rngs::SmallRng;

    use crate::core::fields::qm31::QM31;
    use crate::core::fields::{batch_inverse_in_place, FieldExpOps};
    use crate::prover::backend::cpu::bit_reverse;
    use crate::prover::backend::Column;

    #[test]
    fn bit_reverse_works() {
        let mut data = [0, 1, 2, 3, 4, 5, 6, 7];
        bit_reverse(&mut data);
        assert_eq!(data, [0, 4, 2, 6, 1, 5, 3, 7]);
    }

    #[test]
    #[should_panic]
    fn bit_reverse_non_power_of_two_size_fails() {
        let mut data = [0, 1, 2, 3, 4, 5];
        bit_reverse(&mut data);
    }

    // TODO(Ohad): remove.
    #[test]
    fn batch_inverse_in_place_test() {
        let mut rng = SmallRng::seed_from_u64(0);
        let column = rng.gen::<[QM31; 16]>().to_vec();
        let expected = column.iter().map(|e| e.inverse()).collect_vec();
        let mut dst = Vec::zeros(column.len());

        batch_inverse_in_place(&column, &mut dst);

        assert_eq!(expected, dst);
    }

    #[test]
    fn test_split_at_mid_cpu_column() {
        let values = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let col: Vec<_> = values.into_iter().collect();
        let (lhs, rhs) = col.split_at_mid();
        assert_eq!(lhs, vec![1, 2, 3, 4]);
        assert_eq!(rhs, vec![5, 6, 7, 8]);
    }
}
