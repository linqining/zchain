# Stwo Cairo 1.2.2 compatibility import

This directory contains the published `stwo-cairo-common` and `stwo-cairo-prover` 1.2.2
sources from <https://github.com/starkware-libs/stwo-cairo> (Apache-2.0 package metadata).
They are used only for the generated Poseidon252 witness closure consumed by the recursive
verifier AIR.

The generated AIR itself remains the crates.io `cairo-air = 1.2.2` package. The two imported
witness crates are unchanged except for compiler compatibility fixes required by the current
nightly:

1. `Mask::to_int()` is replaced by `to_array().map(i32::from)`.
2. The removed `array_chunks` feature gate is dropped.
3. Slice `array_chunks` calls are replaced by `chunks_exact` plus checked array conversion.

No AIR constraints, constants, relation identifiers, witness formulas, or component layouts are
changed. When an upstream 1.2.x release contains these fixes, prefer removing this import and
returning to crates.io dependencies.

## Suite boundary

These imported crates' own `cargo test` targets are **not** part of this repository's test
suite (the official suite is per-crate, see `scripts/ci_local.sh`): the published 1.2.2
packaging strips path-type dev-dependencies (`stwo-cairo-dev-utils`, …), so the vendored
prover's test harness cannot compile. An ad-hoc `cargo test --workspace` must use
`--exclude stwo-cairo-prover`. This is an upstream packaging artifact, not a soundness
finding: the imported code here is the witness-closure path only, which is exercised by the
first-party recursive AIR tests in `poker_zkvm/src/stwo_backend/recursive/`.
