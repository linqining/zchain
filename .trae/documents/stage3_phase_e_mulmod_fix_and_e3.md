# Stage 3 Phase E — mul\_mod Fix + ECDSA Full Circuit

## Summary

Fix the critical `mul_mod` bug in `non_native.rs` that causes 6/8 `secp256k1_ops` tests to fail, then extend `ecdsa.rs` to dual-mode (MVP + full) ECDSA verification implementing `s·R' = z·G + r·P`, and run full regression.

## Current State Analysis

### Bug Description

* `test_nonnative_mul_mod_large` PASSES: `(p-1)*(p-1) mod p = 1` (trivial carry chain, q=p-2, r=1)

* `test_nonnative_mul_mod_gx` FAILS: `GX*GX mod p` (complex carry chain with non-trivial q, r)

* `test_nonnative_mul_mod_gx_gy` FAILS: `GX*GY mod p`

* `test_nonnative_mul_mod_mixed` (3 \* GY): NOT YET RUN

### Static Analysis Conclusion (confirmed this session)

All constraint logic is correct **by construction**:

* `mul_big_circuit` carry chain: `carry[k] + Σp[i][j] - product[k] - carry[k+1]*2^64 = 0` — holds because `carry_out = (sum - product) * inv(2^64)` and `inv(2^64) * 2^64 = 1` in Fr

* `mul_mod` carry chain: `ab[k] - qm[k] - carry_in - expected - carry_out*2^64 = 0` — holds by same algebraic identity

* `assert_lt`: `val + d + 1 = bound` with carry chain — correct for honest witness where `val < bound`

* `host_div_mod`: bit-by-bit long division, invariant `remainder < divisor` maintained

* `host_add_mod` / `host_sub_mod`: correct modular arithmetic with carry/borrow handling

* `satisfied_by_row_isolated`: correct for CcsBuilder-generated CCS (all matrices have ≤1 entry)

* `CcsBuilder.add_linear/add_multiplication/add_bit_check`: correct matrix/subset/coeff generation

**Conclusion**: Bug cannot be found by static analysis. Runtime diagnostic is required to identify which CCS rows fail, then root-cause from there.

### Files Involved

* `poker_zkvm/src/precompiles/non_native.rs` — mul\_mod bug location + 3 debug tests (lines 1050-1161)

* `poker_zkvm/src/precompiles/secp256k1_ops.rs` — E2 implementation, 6/8 tests failing

* `poker_zkvm/src/precompiles/ecdsa.rs` — E3 target, current MVP (6 vars, 7 matrices, 3 rows)

* `poker_zkvm/src/precompiles/ccs_builder.rs` — CcsBuilder API (verified correct)

* `poker_zkvm/src/ccs/mod.rs` — satisfied\_by fast path (verified correct)

## Proposed Changes

### Step 1: E2-FIX-1 — Run Diagnostic Tests

Run the existing diagnostic tests to identify which CCS rows fail:

```bash
cargo test -p poker_zkvm --lib test_nonnative_mul_mod_gx -- --nocapture
cargo test -p poker_zkvm --lib test_nonnative_mul_mod_mixed -- --nocapture
cargo test -p poker_zkvm --lib test_nonnative_mul_mod_gx_gy -- --nocapture
```

The diagnostic code (already in non\_native.rs lines 1064-1085) iterates all rows, evaluates each subset at each row, and panics with the first 10 failing row indices and total row count.

**Expected output**: Failed row indices will pinpoint which constraint section is broken:

* Rows 0-15: `mul_big_circuit` multiplication constraints (16 per call, 2 calls = 32)

* Next \~7 rows: `mul_big_circuit` carry chain (7 per call, 2 calls = 14)

* Next \~8 rows: `mul_big_circuit` range\_check\_64 (8 per call, 2 calls = 16, but each range\_check is 64+1 rows)

* Mul\_mod carry chain rows: 8 rows + 1 final carry

* assert\_lt rows: 4 carry + 1 final + 256 range\_check bits

### Step 2: E2-FIX-2 — Host Verification Test

Add `test_host_div_mod_gx_verification` to `non_native.rs` tests to distinguish host bug vs circuit bug:

```rust
#[test]
fn test_host_div_mod_gx_verification() {
    // Verify host_div_mod returns correct q, r for GX*GX
    let product = host_mul_big(&SECP256K1_GX, &SECP256K1_GX);
    let (q, r) = host_div_mod(&product, &SECP256K1_P_CURVE);

    // Verify: q * p + r == product (512-bit)
    let qm = host_mul_big(&q, &SECP256K1_P_CURVE);
    // q*p + r should equal product
    let mut sum = [0u64; 8];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s, c1) = qm[i].overflowing_add(r[i]);
        let (s, c2) = s.overflowing_add(carry);
        sum[i] = s;
        carry = (c1 as u64) + (c2 as u64);
    }
    for i in 4..8 {
        let (s, c1) = qm[i].overflowing_add(carry);
        sum[i] = s;
        carry = c1 as u64;
    }
    assert_eq!(sum, product, "q*p + r must equal product");
    assert!(host_lt(&r, &SECP256K1_P_CURVE), "r < p must hold");
}
```

If this test fails → host\_div\_mod bug (fix host function).
If this test passes → circuit bug (fix witness computation or constraint structure).

### Step 3: E2-FIX-3 — Fix the Bug

Based on diagnostic results, apply the appropriate fix. Possible scenarios:

**Scenario A**: `host_div_mod` returns wrong q/r → Fix the long division algorithm (check bit ordering, overflow handling, or subtraction logic).

**Scenario B**: `mul_big_circuit` witness values incorrect → Fix carry computation (check `sum.to_canonical_bytes()` extraction, `u64::from_le_bytes` correctness, or carry propagation).

**Scenario C**: `mul_mod` carry chain witness incorrect → Fix carry\_out computation for negative intermediate values (check Fr representation of negative carries, division by 2^64 in Fr).

**Scenario D**: `assert_lt` fails → Fix d\_val computation or carry chain (check `host_sub_mod` for the d computation, or carry chain for `val + d + 1 = bound`).

**Scenario E**: `range_check_64` fails → Fix bit decomposition or recompose constraint (check `to_canonical_bytes` for values near 2^64, or `fr_pow2` computation).

**Scenario F**: `satisfied_by_row_isolated` fast path bug → Fix the fast path (check matrix\_vals computation, all\_same\_row logic, or empty subset handling).

**Most likely scenario** (based on static analysis showing logic is correct by construction): Scenario A or B — a subtle host function bug that only manifests with complex 256-bit values (not trivial values like p-1).

### Step 4: E2-FIX-4 — Cleanup and Verify

1. Remove the 3 debug tests (`test_nonnative_mul_mod_gx`, `test_nonnative_mul_mod_mixed`, `test_nonnative_mul_mod_gx_gy`) — replace with clean versions without diagnostic code
2. Run all non\_native tests: `cargo test -p poker_zkvm --lib non_native`
3. Run all secp256k1\_ops tests: `cargo test -p poker_zkvm --lib secp256k1_ops`
4. All 8 secp256k1\_ops tests must pass (currently 2 pass, 6 fail)

### Step 5: E3 — Extend ecdsa.rs to Dual-Mode Full Verification

Extend `EcdsaVerifyCircuit` with full ECDSA verification mode.

#### 5.1: Struct Extension

```rust
#[derive(Debug, Clone)]
pub struct EcdsaVerifyCircuit {
    curve: &'static str,
    full_mode: bool,          // false = MVP, true = full
    scalar_num_bits: usize,   // bit length for scalar_mul (default 8 for testing)
}
```

#### 5.2: New Constructors

```rust
impl EcdsaVerifyCircuit {
    pub fn new() -> Self { /* existing MVP */ }
    
    pub fn new_full() -> Self {
        Self { curve: "secp256k1", full_mode: true, scalar_num_bits: 8 }
    }
    
    pub fn new_full_with_bits(n: usize) -> Self {
        Self { curve: "secp256k1", full_mode: true, scalar_num_bits: n }
    }
}
```

#### 5.3: Full Verification Logic (`run_full`)

Implements `s·R' = z·G + r·P` where R' = (r, ry) with ry as hint:

```rust
fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
    // inputs: [s(4 limbs), r(4 limbs), ry(4 limbs), z(4 limbs), px(4 limbs), py(4 limbs)]
    // = 6 NonNativeElements × 4 limbs = 24 Fr values
    
    let mut builder = NonNativeBuilder::new();
    
    // Allocate inputs as NonNativeElements
    let s = builder.alloc_element(/* from inputs[0..4] */);
    let r = builder.alloc_element(/* from inputs[4..8] */);
    let ry = builder.alloc_element(/* from inputs[8..12] */);
    let z = builder.alloc_element(/* from inputs[12..16] */);
    let px = builder.alloc_element(/* from inputs[16..20] */);
    let py = builder.alloc_element(/* from inputs[20..24] */);
    
    let m_n = &SECP256K1_N; // scalar field modulus
    
    // R' = (r, ry) as affine point → Jacobian (r, ry, 1)
    let r_prime = from_affine(&mut builder, &r_u256, &ry_u256);
    
    // G = (GX, GY) as Jacobian (GX, GY, 1)
    let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
    
    // P = (px, py) as Jacobian (px, py, 1)
    let p = from_affine(&mut builder, &px_u256, &py_u256);
    
    // Left side: s · R'
    let s_r_prime = scalar_mul(&mut builder, &r_prime, &s, self.scalar_num_bits);
    
    // Right side: z · G + r · P
    let z_g = scalar_mul(&mut builder, &g, &z, self.scalar_num_bits);
    let r_p = scalar_mul(&mut builder, &p, &r, self.scalar_num_bits);
    let rhs = point_add(&mut builder, &z_g, &r_p);
    
    // Assert: s · R' == z · G + r · P
    assert_point_equal(&mut builder, &s_r_prime, &rhs);
    
    let witness = builder.witness.clone();
    let ccs = builder.build()?;
    Ok((ccs, witness))
}
```

#### 5.4: Trait Method Updates

* `num_variables()`: return 0 for full mode (dynamic, not fixed)

* `build_ccs()`: return empty CCS for full mode (use `run_full` instead)

* `assign_witness()`: return error for full mode (use `run_full` instead)

* `gas_cost()`: return 3,000,000 for full mode (spec-aligned estimate for 256-bit verify)

#### 5.5: Tests (10 new tests)

1. `test_ecdsa_full_mode_constructors` — new\_full(), new\_full\_with\_bits(n)
2. `test_ecdsa_full_mode_basic_satisfied` — small scalar (8 bits), identity s=z+2r
3. `test_ecdsa_full_mode_gas_cost` — 3,000,000 for full, 100,000 for MVP
4. `test_ecdsa_full_mode_num_variables` — 0 for full, 6 for MVP
5. `test_ecdsa_full_mode_invalid_input_length` — error on wrong input count
6. `test_ecdsa_full_mode_with_real_signature` — use secp256k1 crate to generate sig, verify in circuit (8-bit truncation)
7. `test_ecdsa_full_mode_tampered_s` — modify s → assert\_point\_equal fails
8. `test_ecdsa_full_mode_tampered_r` — modify r → fails
9. `test_ecdsa_full_mode_tampered_px` — modify px → fails
10. `test_ecdsa_full_mode_mvp_backward_compatible` — new() still works as before

### Step 6: E4 — Full Regression Verification

```bash
# poker_zkvm
cargo build -p poker_zkvm
cargo test -p poker_zkvm --lib
cargo clippy -p poker_zkvm -- -D warnings
cargo bench -p poker_zkvm --no-run

# poker_l1 (downstream)
cargo build -p poker_l1
cargo test -p poker_l1 --lib
cargo clippy -p poker_l1 -- -D warnings

# E2E (known pre-existing failures: fibonacci/sha256 proof size > 512KB)
cargo test -p poker_zkvm --test e2e_poker_hand_eval
```

## Assumptions & Decisions

1. **Diagnostic-first approach**: Run tests before fixing, since static analysis exhausted all avenues. The diagnostic code is already in place.
2. **Host verification test**: Added to distinguish host bug from circuit bug — critical for determining fix location.
3. **E3 uses small scalar\_num\_bits (8)**: Full 256-bit scalar\_mul would generate \~20M constraints (too slow for tests). 8-bit truncation is sufficient for structural validation.
4. **E3 gas\_cost = 3,000,000**: Aligned with spec estimate for full ECDSA verify (vs 100,000 for MVP).
5. **E3 backward compatible**: `new()` retains MVP behavior. Full mode is opt-in via `new_full()`.
6. **Pre-existing E2E failures**: fibonacci/sha256 tests fail due to proof size > 512KB (Stage 1 batch\_size=256 issue, requires CycleFold). Not addressed in this phase.

## Verification Steps

1. E2-FIX: All 8 secp256k1\_ops tests pass + all non\_native tests pass
2. E3: All 10 new ecdsa full-mode tests pass + all 12 existing MVP tests pass
3. E4: poker\_zkvm lib tests pass, poker\_l1 lib tests pass, clippy zero warnings, bench compiles
4. No regression in existing tests (soundness, e2e\_poker\_hand\_eval)

