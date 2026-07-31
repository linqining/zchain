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
