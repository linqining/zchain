# Stage 3 — Phase B: SHA-256 Full Circuit

## Summary

Extend the SHA-256 precompile circuit from MVP (single Ch function, 6 vars) to a complete 64-round compression circuit with dual-mode support (`new()` MVP + `new_full()` complete), following the Poseidon dual-mode pattern. Uses the bit-level utilities from B1 (`bit_ops.rs`) to build the full circuit.

## Current State Analysis

### B1 (COMPLETE — needs test verification only)
- **File**: `poker_zkvm/src/precompiles/bit_ops.rs`
- 9 public functions: `bit_decompose`, `bit_xor`, `bit_and`, `bit_or`, `bit_not`, `bit_rotr`, `bit_shr`, `add_mod_2_32`, `bit_recompose`
- 12 tests covering correctness + soundness
- Compilation fixes applied (type error `Vec<u32>` → `Vec<usize>`, 7 unused variable warnings fixed)
- **NOT YET VERIFIED**: tests not re-run after fixes

### B3 (COMPLETE)
- **File**: `poker_zkvm/src/precompiles/mod.rs` line 20
- `pub mod bit_ops;` added

### B2 (NOT STARTED — main work)
- **File**: `poker_zkvm/src/precompiles/sha256.rs`
- Current state: MVP only — `Sha256Circuit` with `new()`, Ch function, 6 vars, 7 matrices, 25,000 gas
- Needs: `new_full()`, `full_mode` flag, `build_full_ccs()`, `assign_full_witness()`, SHA256_K constants, helper functions

### Reference Pattern (Poseidon)
- **File**: `poker_zkvm/src/precompiles/poseidon.rs`
- Dual-mode: `new()` (MVP, 5 vars) + `new_full()` (complete, 439 vars)
- `full_mode: bool` flag in struct
- `PrecompileCircuit` trait methods dispatch: `build_ccs()` → `build_full_ccs()`/`build_mvp_ccs()`, `assign_witness()` → `assign_full_witness()`/`assign_mvp_witness()`
- `CcsCircuit::num_matrices()` dispatches based on mode

## Proposed Changes

### Step 1: Verify B1 (bit_ops.rs)

Run B1 tests and clippy to confirm all fixes are correct:

```bash
cd /Users/mac/projects/zchain && cargo test -p poker_zkvm --lib precompiles::bit_ops 2>&1
cargo clippy -p poker_zkvm --all-targets 2>&1
```

**Expected**: All 12 bit_ops tests pass, zero clippy warnings.

### Step 2: B2 — Extend sha256.rs with Full Mode

#### 2a: Add SHA-256 Constants

Add `SHA256_K` (64 round constants) and `SHA256_H0` (8 initial hash values) as `const` arrays at the top of `sha256.rs`:

```rust
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const FULL_MODE_GAS_COST: u64 = 25_000;
```

#### 2b: Add `full_mode` Flag to `Sha256Circuit`

Modify the struct to add `full_mode: bool`:

```rust
#[derive(Debug, Clone)]
pub struct Sha256Circuit {
    block_size: usize,
    output_size: usize,
    full_mode: bool,
}
```

Add `new_full()` constructor and `is_full_mode()` accessor (matching Poseidon pattern). Update `new()` to set `full_mode: false`.

#### 2c: Create Internal `FullBuilder` Struct (Combined CCS + Witness)

**Key Design Decision**: Unlike Poseidon (which has separate `build_full_ccs()` and `assign_full_witness()` that must be manually kept in sync), SHA-256's circuit is ~170K variables — too large for manual sync. Instead, use a **combined builder** that constructs CCS constraints and computes witness values simultaneously, guaranteeing they stay in sync.

```rust
/// 32-bit word represented as 32 bit variable indices.
struct Word {
    bits: Vec<usize>,  // 32 variable indices in CcsBuilder
}

/// Combined CCS builder + witness tracker for SHA-256 full mode.
/// Ensures constraint structure and witness values are always in sync.
struct FullBuilder {
    ccs: CcsBuilder,
    witness: Vec<Fr>,
}

impl FullBuilder {
    fn new() -> Self {
        Self {
            ccs: CcsBuilder::new(),
            witness: vec![Fr::one()],  // z[0] = 1
        }
    }

    /// Allocate a variable with a known witness value.
    fn alloc(&mut self, val: Fr) -> usize {
        let idx = self.ccs.alloc_var();
        self.witness.push(val);
        idx
    }

    /// Decompose a u32 value into 32 bit variables.
    /// Adds bit_check + recompose constraints (same as bit_ops::bit_decompose).
    fn decompose(&mut self, val: u32) -> Word { ... }

    /// Bit-level XOR: result[i] = a[i] XOR b[i].
    /// Adds multiplication + linear constraints per bit.
    fn xor(&mut self, a: &Word, b: &Word) -> Word { ... }

    /// Bit-level AND.
    fn and(&mut self, a: &Word, b: &Word) -> Word { ... }

    /// Bit-level NOT: result[i] = 1 - a[i].
    fn not(&mut self, a: &Word) -> Word { ... }

    /// Rotate right by n (pure rearrangement, no constraints).
    fn rotr(&self, w: &Word, n: usize) -> Word { ... }

    /// Shift right by n (zero-fill, n linear constraints for zero bits).
    fn shr(&mut self, w: &Word, n: usize) -> Word { ... }

    /// 32-bit modular addition: result = (a + b) mod 2^32.
    /// Ripple-carry adder (same as bit_ops::add_mod_2_32).
    fn add_mod_2_32(&mut self, a: &Word, b: &Word) -> Word { ... }
}
```

Each method mirrors the corresponding `bit_ops` function's constraint structure but also computes and pushes witness values.

#### 2d: Implement `run_full()` — Core SHA-256 Compression

```rust
impl Sha256Circuit {
    /// Run full SHA-256 compression, building CCS + witness simultaneously.
    /// Returns (Ccs, witness_vec).
    /// CCS structure is input-independent; witness depends on inputs.
    fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        // Input: 24 u32 values as Fr
        //   inputs[0..8]  = initial hash state H0..H7
        //   inputs[8..24] = message words W[0..15]
        if inputs.len() != 24 { return Err(...); }

        let mut fb = FullBuilder::new();

        // 1. Decompose inputs to Words
        let mut h: Vec<Word> = Vec::with_capacity(8);
        for i in 0..8 {
            h.push(fb.decompose(inputs[i].to_u32()));
        }
        let mut w: Vec<Word> = Vec::with_capacity(64);
        for i in 0..16 {
            w.push(fb.decompose(inputs[8 + i].to_u32()));
        }

        // 2. Decompose K constants (precompute all 64)
        let k_words: Vec<Word> = SHA256_K.iter().map(|&k| fb.decompose(k)).collect();

        // 3. Message schedule: W[16..63]
        for t in 16..64 {
            // sigma0(W[t-15]) = ROTR(W[t-15],7) XOR ROTR(W[t-15],18) XOR SHR(W[t-15],3)
            let s0_a = fb.rotr(&w[t-15], 7);
            let s0_b = fb.rotr(&w[t-15], 18);
            let s0_c = fb.shr(&w[t-15], 3);
            let s0_ab = fb.xor(&s0_a, &s0_b);
            let s0 = fb.xor(&s0_ab, &s0_c);

            // sigma1(W[t-2]) = ROTR(W[t-2],17) XOR ROTR(W[t-2],19) XOR SHR(W[t-2],10)
            let s1_a = fb.rotr(&w[t-2], 17);
            let s1_b = fb.rotr(&w[t-2], 19);
            let s1_c = fb.shr(&w[t-2], 10);
            let s1_ab = fb.xor(&s1_a, &s1_b);
            let s1 = fb.xor(&s1_ab, &s1_c);

            // W[t] = W[t-16] + s0 + W[t-7] + s1 (mod 2^32)
            let tmp1 = fb.add_mod_2_32(&w[t-16], &s0);
            let tmp2 = fb.add_mod_2_32(&tmp1, &w[t-7]);
            w.push(fb.add_mod_2_32(&tmp2, &s1));
        }

        // 4. Initialize working variables
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0].clone(), h[1].clone(), h[2].clone(), h[3].clone(),
             h[4].clone(), h[5].clone(), h[6].clone(), h[7].clone());

        // 5. 64 rounds of compression
        for t in 0..64 {
            // S1 = ROTR(e,6) XOR ROTR(e,11) XOR ROTR(e,25)
            let s1_a = fb.rotr(&e, 6);
            let s1_b = fb.rotr(&e, 11);
            let s1_c = fb.rotr(&e, 25);
            let s1_ab = fb.xor(&s1_a, &s1_b);
            let s1 = fb.xor(&s1_ab, &s1_c);

            // ch = (e AND f) XOR ((NOT e) AND g)
            let e_and_f = fb.and(&e, &f);
            let not_e = fb.not(&e);
            let not_e_and_g = fb.and(&not_e, &g);
            let ch = fb.xor(&e_and_f, &not_e_and_g);

            // temp1 = h + S1 + ch + K[t] + W[t] (mod 2^32)
            let t1a = fb.add_mod_2_32(&hh, &s1);
            let t1b = fb.add_mod_2_32(&t1a, &ch);
            let t1c = fb.add_mod_2_32(&t1b, &k_words[t]);
            let temp1 = fb.add_mod_2_32(&t1c, &w[t]);

            // S0 = ROTR(a,2) XOR ROTR(a,13) XOR ROTR(a,22)
            let s0_a = fb.rotr(&a, 2);
            let s0_b = fb.rotr(&a, 13);
            let s0_c = fb.rotr(&a, 22);
            let s0_ab = fb.xor(&s0_a, &s0_b);
            let s0 = fb.xor(&s0_ab, &s0_c);

            // maj = (a AND b) XOR (a AND c) XOR (b AND c)
            let a_and_b = fb.and(&a, &b);
            let a_and_c = fb.and(&a, &c);
            let b_and_c = fb.and(&b, &c);
            let maj_ab = fb.xor(&a_and_b, &a_and_c);
            let maj = fb.xor(&maj_ab, &b_and_c);

            // temp2 = S0 + maj (mod 2^32)
            let temp2 = fb.add_mod_2_32(&s0, &maj);

            // Shift working variables
            hh = g;
            g = f;
            f = e;
            e = fb.add_mod_2_32(&d, &temp1);
            d = c;
            c = b;
            b = a;
            a = fb.add_mod_2_32(&temp1, &temp2);
        }

        // 6. Final state = (a, b, c, d, e, f, g, h)
        // (These are the output Words — witness values are already tracked)

        let ccs = fb.ccs.build()?;
        Ok((ccs, fb.witness))
    }
}
```

#### 2e: Wire into PrecompileCircuit and CcsCircuit

```rust
impl PrecompileCircuit for Sha256Circuit {
    fn num_variables(&self) -> usize {
        if self.full_mode {
            // Use dummy inputs to determine variable count
            let dummy = vec![Fr::zero(); 24];
            self.run_full(&dummy).unwrap().0.num_vars
        } else {
            6
        }
    }

    fn build_ccs(&self) -> Ccs {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 24];
            self.run_full(&dummy).unwrap().0
        } else {
            self.build_mvp_ccs()  // rename existing build_ccs body
        }
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            if inputs.len() != 24 {
                return Err(ZkvmError::Other(format!(
                    "Sha256Circuit::assign_witness (full): inputs.len() {} != 24 (8 hash state + 16 message words)",
                    inputs.len()
                )));
            }
            Ok(self.run_full(inputs)?.1)
        } else {
            self.assign_mvp_witness(inputs)  // rename existing assign_witness body
        }
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode { FULL_MODE_GAS_COST } else { 25_000 }
    }
}
```

Rename existing MVP methods:
- `build_ccs()` body → `build_mvp_ccs()`
- `assign_witness()` body → `assign_mvp_witness()`

Update `CcsCircuit::num_matrices()` to dispatch based on `full_mode`.

#### 2f: Add Full Mode Tests (~10 tests)

```rust
// ===== Full mode tests (Stage 3 — Phase B2) =====

#[test]
fn test_sha256_full_build_ccs() {
    // Verify CCS structure: num_vars > 100,000, num_matrices > 0, etc.
}

#[test]
fn test_sha256_full_satisfied_by() {
    // Use known input (SHA256_H0 + zero message block)
    // Verify witness satisfies CCS
}

#[test]
fn test_sha256_full_matches_reference() {
    // Implement reference sha256_compress(state, block) using u32 arithmetic
    // Compare circuit output with reference for multiple test cases
}

#[test]
fn test_sha256_full_matches_sha2_crate() {
    // Hash a 55-byte message (padded to exactly 64 bytes = 1 block)
    // Verify circuit output matches sha2 crate's internal state
    // by comparing final hash output
}

#[test]
fn test_sha256_full_soundness_tampered_round() {
    // Tamper with an intermediate variable → should fail
}

#[test]
fn test_sha256_full_soundness_tampered_output() {
    // Tamper with final state → should fail
}

#[test]
fn test_sha256_full_gas_cost() {
    // Verify gas_cost() == 25_000
}

#[test]
fn test_sha256_full_wrong_input_length() {
    // Verify input validation (len != 24 returns error)
}

#[test]
fn test_sha256_full_backward_compatibility() {
    // MVP mode still works alongside full mode
}

#[test]
fn test_sha256_full_ccs_circuit_trait() {
    // Verify CcsCircuit trait dispatch works for full mode
}
```

### Step 3: Final Verification

```bash
# B1 + B2 tests
cargo test -p poker_zkvm --lib precompiles::bit_ops 2>&1
cargo test -p poker_zkvm --lib precompiles::sha256 2>&1

# Full library test suite
cargo test -p poker_zkvm --lib 2>&1

# Clippy zero warnings
cargo clippy -p poker_zkvm --all-targets 2>&1

# Bench compilation
cargo bench -p poker_zkvm --no-run 2>&1

# poker_l1 regression
cargo test -p poker_l1 --lib 2>&1
```

**Expected**: All tests pass, zero clippy warnings, bench compiles, poker_l1 unaffected.

## Assumptions & Decisions

1. **Combined builder approach**: Unlike Poseidon's separate `build_full_ccs`/`assign_full_witness`, SHA-256 uses a `FullBuilder` that tracks CCS + witness simultaneously. This is necessary because the circuit is ~170K variables — manual sync is too error-prone. The CCS structure is input-independent, so `build_ccs()` uses dummy inputs and discards the witness.

2. **Input format**: Full mode takes 24 Fr values (8 hash state + 16 message words), each representing a u32 via `from_u32_with_wrap`. MVP mode continues to take 3 Fr values (Ch function inputs).

3. **Gas cost**: Full mode returns 25,000 gas (spec L637: "SHA-256 ~25,000 gas/block"), same as MVP. The MVP returns 25,000 as a "proportional value" per the existing comment.

4. **K constants**: Decomposed into bit variables inside the circuit with bit_check constraints, ensuring soundness (malicious prover cannot use non-bit values).

5. **Output**: The final 8 hash state Words (a-h) are the last variables in the witness. Tests extract them by index to verify correctness.

6. **Performance**: ~170K variables, ~500K subsets, ~1.5M matrices. Build time estimated at 10-60 seconds. Satisfaction check completes in seconds (sparse matrix ops are O(n)). Memory ~100-200MB. Acceptable for testing.

7. **Reference implementation**: Tests use a hand-written `sha256_compress()` function with u32 arithmetic (not the `sha2` crate internals) for direct comparison, plus a `sha2` crate integration test for end-to-end validation.

## Verification Steps

1. `cargo test -p poker_zkvm --lib precompiles::bit_ops` — 12 B1 tests pass
2. `cargo test -p poker_zkvm --lib precompiles::sha256` — all sha256 tests pass (12 MVP + ~10 full)
3. `cargo test -p poker_zkvm --lib` — full library passes (787+ tests)
4. `cargo clippy -p poker_zkvm --all-targets` — zero warnings
5. `cargo bench -p poker_zkvm --no-run` — bench compiles
6. `cargo test -p poker_l1 --lib` — 1276 tests pass (no regression)
