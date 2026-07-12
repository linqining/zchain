# Stage 3 — Phase E Continuation Plan (E2 Fix + E3 + E4)

## Summary

Continue Phase E (ECDSA Full Circuit). E1 (non_native.rs host_div_mod overflow fix + clippy) is complete. E2 (secp256k1_ops.rs) has 3 compile errors to fix. E3 (extend ecdsa.rs to dual-mode full verification of `s·R' = z·G + r·P`) and E4 (full verification) are not yet started.

## Current State Analysis

### E2 — secp256k1_ops.rs (3 compile errors)

File: `poker_zkvm/src/precompiles/secp256k1_ops.rs` (created, 634 lines)
Module declaration in `poker_zkvm/src/precompiles/mod.rs:26` already done.

**Error 1 (E0603)** — `host_sub` is private in `non_native.rs:114`.
- Test `test_assert_on_curve_fails` (line 544) imports `host_sub` to compute `GY - 1`.
- All 9 host functions (`host_lt`, `host_add`, `host_sub`, etc.) are private `fn` in non_native.rs.

**Error 2 (E0382)** — `test_identity_double` (line 452) calls `builder.element_to_u256(&result.z)` at line 464 AFTER `builder.build()` moved the builder at line 459.

**Error 3 (E0382)** — `test_scalar_mul_consistency` (line 594) calls `builder.build()` at line 619, then uses `builder` again at lines 624-627 (`from_affine`, `assert_point_equal`, `witness.clone()`, second `build()`).

### E3 — ecdsa.rs extension (not started)

File: `poker_zkvm/src/precompiles/ecdsa.rs` (368 lines, MVP only)
- MVP: 6 variables, 7 matrices, 3 rows, double-and-add single step.
- 12 existing tests (all must continue to pass).

**Available infrastructure:**
- `NonNativeBuilder` (non_native.rs): `new()`, `alloc()`, `from_u256()`, `alloc_element()`, `add_mod()`, `sub_mod()`, `mul_mod()`, `assert_equal()`, `assert_lt()`, `build(self)`.
- `secp256k1_ops.rs`: `Point`, `identity_point()`, `from_affine()`, `point_double()`, `point_add()`, `scalar_mul(builder, p, scalar, num_bits)`, `assert_on_curve()`, `assert_point_equal()`.
- `SECP256K1_GX`, `SECP256K1_GY`, `SECP256K1_P_CURVE`, `SECP256K1_N` constants (pub in non_native.rs).

### E4 — full verification (not started)

Run cargo build, test (poker_zkvm + poker_l1), clippy, bench --no-run.

## Proposed Changes

### Step E2-FIX: Fix 3 compile errors in secp256k1_ops.rs

**Fix 1 (E0603)** — Rewrite `test_assert_on_curve_fails` to not use `host_sub`. Replace lines 544-563:

```rust
#[test]
fn test_assert_on_curve_fails() {
    // (Gx, Gy+1) is NOT on the curve
    let bad_y = [
        SECP256K1_GY[0].wrapping_add(1),
        SECP256K1_GY[1],
        SECP256K1_GY[2],
        SECP256K1_GY[3],
    ];
    let mut builder = NonNativeBuilder::new();
    let bad_point = from_affine(&mut builder, &SECP256K1_GX, &bad_y);
    assert_on_curve(&mut builder, &bad_point);

    let witness = builder.witness.clone();
    let ccs = builder.build().expect("build");
    assert!(
        !ccs.satisfied_by(&witness).expect("satisfied_by"),
        "point not on curve should fail assert_on_curve"
    );
}
```

- Remove `host_sub` from the `use` import at line 444 (keep `SECP256K1_GX`, `SECP256K1_GY`).
- `wrapping_add(1)` on `SECP256K1_GY[0]` (0x9C47D08FFB10D4B8) won't overflow; result is a valid u64. The point (Gx, Gy+1) is not on y²=x³+7, so assert_on_curve's `assert_equal` constraint fails.

**Fix 2 (E0382 in test_identity_double)** — Move `element_to_u256` call BEFORE `build()`. Replace lines 451-467:

```rust
#[test]
fn test_identity_double() {
    let mut builder = NonNativeBuilder::new();
    let id = identity_point(&mut builder);
    let result = point_double(&mut builder, &id);

    // Compute Z before build (build consumes builder)
    let z_u256 = builder.element_to_u256(&result.z);

    let witness = builder.witness.clone();
    let ccs = builder.build().expect("build");
    assert_eq!(witness.len(), ccs.num_vars);
    assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    assert_eq!(z_u256, [0, 0, 0, 0], "doubling identity should give identity (Z=0)");
}
```

**Fix 3 (E0382 in test_scalar_mul_consistency)** — Restructure to build only ONCE. Do `assert_point_equal` BEFORE `build()`. Replace lines 593-633:

```rust
#[test]
fn test_scalar_mul_consistency() {
    // k*G should match secp256k1 crate for k=5, num_bits=4
    use secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk5 = SecretKey::from_slice(&{
        let mut b = [0u8; 32];
        b[31] = 5;
        b
    })
    .unwrap();
    let pk5 = sk5.public_key(&secp);
    let serialized = pk5.serialize_uncompressed();
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&serialized[1..33]);
    y_bytes.copy_from_slice(&serialized[33..65]);
    let expected_x = bytes_be_to_u256_le(&x_bytes);
    let expected_y = bytes_be_to_u256_le(&y_bytes);

    let mut builder = NonNativeBuilder::new();
    let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
    let scalar = builder.from_u256(&[5, 0, 0, 0]);
    let result = scalar_mul(&mut builder, &g, &scalar, 4);

    // Assert result == 5*G (known from secp256k1 crate)
    let expected = from_affine(&mut builder, &expected_x, &expected_y);
    assert_point_equal(&mut builder, &result, &expected);

    let witness = builder.witness.clone();
    let ccs = builder.build().expect("build");
    assert!(
        ccs.satisfied_by(&witness).expect("satisfied_by"),
        "scalar_mul(5, G) should equal 5*G from secp256k1 crate"
    );
}
```

Rationale: combining scalar_mul + assert_point_equal in one build checks both (a) scalar_mul constraints are satisfiable and (b) result matches 5*G. If scalar_mul is broken, either the constraints fail or assert_point_equal fails.

**Verification after E2-FIX:**
```bash
cargo test -p poker_zkvm --lib secp256k1_ops
```
Expected: 8 tests pass.

### Step E3: Extend ecdsa.rs to dual-mode full verification

File: `poker_zkvm/src/precompiles/ecdsa.rs`

**Design:** Follow sha256.rs dual-mode pattern. Add `full_mode: bool` and `scalar_num_bits: usize` fields. MVP `new()` stays backward-compatible. Full mode implements `s·R' = z·G + r·P`.

**Struct change:**
```rust
#[derive(Debug, Clone)]
pub struct EcdsaVerifyCircuit {
    curve: &'static str,
    full_mode: bool,
    scalar_num_bits: usize,
}
```

**New constructors:**
- `new()` — MVP mode (full_mode=false, scalar_num_bits=0). Backward compatible.
- `new_full()` — Full mode, 256 bits (production).
- `new_full_with_bits(n)` — Full mode, n bits (for fast testing).

**run_full method:**
```rust
fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError>
```
- Input layout (28 Fr values = 7 NonNativeElements × 4 limbs):
  - inputs[0..4] = z (msg hash scalar, 4 limbs)
  - inputs[4..8] = r (sig r, 4 limbs)
  - inputs[8..12] = s (sig s, 4 limbs)
  - inputs[12..16] = px (pubkey x, 4 limbs)
  - inputs[16..20] = py (pubkey y, 4 limbs)
  - inputs[20..24] = rx (R' x, 4 limbs)
  - inputs[24..28] = ry (R' y, 4 limbs)
- Algorithm:
  1. Create `NonNativeBuilder`
  2. Allocate z, r, s, px, py, rx, ry as NonNativeElements via `alloc_element`
  3. G = `from_affine(&SECP256K1_GX, &SECP256K1_GY)`
  4. P = `from_affine(px, py)` (pubkey point)
  5. R' = `from_affine(rx, ry)` (R point with hinted y)
  6. sR = `scalar_mul(&mut builder, &R', &s, self.scalar_num_bits)`
  7. zG = `scalar_mul(&mut builder, &G, &z, self.scalar_num_bits)`
  8. rP = `scalar_mul(&mut builder, &P, &r, self.scalar_num_bits)`
  9. zG_rP = `point_add(&mut builder, &zG, &rP)`
  10. `assert_point_equal(&mut builder, &sR, &zG_rP)`
  11. `builder.build()` → (Ccs, witness)

**PrecompileCircuit trait methods (full mode branches):**
- `num_variables()` — `run_full(dummy_28).0.num_vars` for full mode, 6 for MVP.
- `build_ccs()` — `run_full(dummy_28).0` for full mode, existing MVP CCS otherwise.
- `assign_witness(inputs)` — validate `inputs.len() == 28` for full mode (3 for MVP), return `run_full(inputs).1`.
- `gas_cost()` — `3_000_000` for full mode (spec-aligned, ~17M constraints), `100_000` for MVP.

**CcsCircuit trait:** `num_matrices()` returns 7 for MVP (unchanged). For full mode, return `run_full(dummy).0.num_matrices()`.

**E3 Tests (≥8 new tests, added to existing 12 MVP tests):**

Testing strategy: Use small `scalar_num_bits` (e.g., 8) with constructed (non-real-ECDSA) test cases where all scalars fit in num_bits. The circuit equation `s·R' = z·G + r·P` is tested directly.

**Key test identity:** With R'=G, P=2·G (host-computed via secp256k1 crate), z=3, r=5:
- s·G = z·G + r·(2·G) = (z + 2r)·G → s = z + 2r = 3 + 10 = 13
- All scalars (3, 5, 13) fit in 8 bits.

Tests:
1. `test_ecdsa_full_new` — `new_full()` sets full_mode=true, scalar_num_bits=256.
2. `test_ecdsa_full_with_bits` — `new_full_with_bits(8)` sets scalar_num_bits=8.
3. `test_ecdsa_full_build_ccs` — `build_ccs()` returns CCS with num_vars > 6, num_matrices > 7.
4. `test_ecdsa_full_valid_equation` — z=3, r=5, s=13, R'=G, P=2·G → CCS satisfied.
5. `test_ecdsa_full_invalid_s` — z=3, r=5, s=14 (wrong) → CCS NOT satisfied.
6. `test_ecdsa_full_invalid_z` — z=4 (wrong), r=5, s=13 → CCS NOT satisfied.
7. `test_ecdsa_full_tampered_witness` — Valid inputs but tamper one witness limb → CCS NOT satisfied.
8. `test_ecdsa_full_gas_cost` — `gas_cost()` == 3_000_000 for full mode.
9. `test_ecdsa_full_backward_compatible` — `new()` still works as MVP (6 vars, 100_000 gas).
10. `test_ecdsa_full_wrong_input_length` — `assign_witness` with wrong length returns error.

Test helper: `fn make_2g() -> ([u64;4], [u64;4])` computes 2·G via secp256k1 crate.

**Imports needed in ecdsa.rs:**
```rust
use crate::precompiles::non_native::{NonNativeBuilder, NonNativeElement, SECP256K1_GX, SECP256K1_GY};
use crate::precompiles::secp256k1_ops::{from_affine, point_add, scalar_mul, assert_point_equal};
```

### Step E4: Full verification

```bash
# 1. Build
cargo build -p poker_zkvm

# 2. All poker_zkvm lib tests (existing + E2 8 tests + E3 new tests)
cargo test -p poker_zkvm --lib

# 3. With test-helpers feature
cargo test -p poker_zkvm --lib --features test-helpers

# 4. Clippy zero warnings
cargo clippy -p poker_zkvm --lib --features test-helpers -- -D warnings

# 5. Bench compiles
cargo bench -p poker_zkvm --no-run

# 6. poker_l1 regression
cargo build -p poker_l1
cargo test -p poker_l1 --lib
```

**Expected results:**
- All poker_zkvm lib tests pass (existing 787+ + 8 E2 + 10 E3 = 805+).
- Zero clippy warnings (non_native.rs has `#![allow(dead_code)]` and `#![allow(clippy::needless_range_loop)]`; secp256k1_ops.rs has `#![allow(clippy::needless_range_loop)]`).
- Bench compiles.
- poker_l1: 1276 tests pass (regression).

**Known pre-existing failures (NOT caused by Phase E):**
- `e2e_fibonacci` / `e2e_sha256`: proof size > 512KB (Stage 1 batch_size=256 issue, requires CycleFold compression — out of scope for Phase E).

## Assumptions & Decisions

1. **E2-FIX approach for E0603**: Rewrite test to not use `host_sub` (direct limb arithmetic) rather than making `host_sub` `pub(crate)`. Rationale: keeps non_native.rs API surface minimal; the test only needs simple `wrapping_add(1)`.

2. **E2-FIX approach for E0382**: Clone witness and compute host-side values BEFORE `build()`. For `test_scalar_mul_consistency`, combine scalar_mul + assert_point_equal into a single build (Option B from analysis). Rationale: simpler than two-builder approach; if scalar_mul is broken, the combined CCS still fails.

3. **E3 testing with small num_bits**: Use `new_full_with_bits(8)` for most tests. Construct test cases where z, r, s all fit in 8 bits. Use the identity `s = z + 2r` with R'=G, P=2·G. Rationale: 256-bit tests would generate ~19M constraints per scalar_mul (×3 = ~58M), too slow for CI. E2 already validates scalar_mul correctness with 4-bit tests.

4. **E3 gas_cost = 3_000_000**: Aligned with ~17M constraint estimate for full 256-bit mode (3× scalar_mul(256) ≈ 19.4M rows + point_add + assert_point_equal). Spec L660 says MVP = 100_000; full mode is higher.

5. **E3 does NOT add assert_on_curve for R' and P**: The ECDSA verify equation `s·R' = z·G + r·P` is sound even without on-curve checks for R' and P, because a malicious prover using off-curve points would not satisfy the equation for valid (z, r, s). On-curve checks can be added in a future hardening phase. This keeps constraint count lower for testing.

6. **MVP backward compatibility**: `new()` preserves existing behavior exactly. All 12 existing MVP tests must pass unchanged.

## Verification Steps

1. After E2-FIX: `cargo test -p poker_zkvm --lib secp256k1_ops` → 8 tests pass.
2. After E3: `cargo test -p poker_zkvm --lib ecdsa` → 22 tests pass (12 MVP + 10 new).
3. After E4: Full suite passes (poker_zkvm lib + poker_l1 lib + clippy + bench).
