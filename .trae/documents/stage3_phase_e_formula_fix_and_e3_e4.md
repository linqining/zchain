# Stage 3 Phase E — Formula Bug Fix + ECDSA Full Circuit (E3) + Regression (E4)

## Summary

Fix the remaining formula bug in `secp256k1_ops.rs` (`test_scalar_mul_consistency` fails: CCS satisfied but wrong result), clean up diagnostic code in `non_native.rs`, extend `ecdsa.rs` to dual-mode (MVP + full) ECDSA verification implementing `s·R' = z·G + r·P`, and run full regression.

## Current State Analysis

### What's Done
- **mul_mod carry chain fix**: APPLIED and VERIFIED — ADDITION form (`qm + r' = ab`) at `non_native.rs:657-716`. All 17 `non_native` tests pass.
- **secp256k1_ops tests**: 7/8 pass. `test_scalar_mul_consistency` (scalar_mul(5,G,4) + assert_point_equal(result, 5*G)) FAILS — CCS is satisfied for scalar_mul alone, but fails when combined with assert_point_equal against the known 5*G.
- **2 diagnostic tests written but NOT YET RUN**:
  - `test_point_double_matches_secp256k1` (`secp256k1_ops.rs:667-700`) — checks point_double(G) == 2*G via assert_point_equal
  - `test_scalar_mul_3g_consistency` (`secp256k1_ops.rs:631-665`) — checks scalar_mul(3,G,4) == 3*G via assert_point_equal
- **2 diagnostic tests in non_native.rs need cleanup**: `test_nonnative_mul_mod_gx` (lines 1059-1082) and `test_nonnative_mul_mod_mixed` (lines 1108-1131) have `if !sat { ... panic! }` blocks that should be simplified to `assert!(sat)`.
- **ecdsa.rs**: MVP with 6 variables, 7 matrices, 3 rows, 12 tests. Needs E3 extension.

### Bug Diagnosis

**Symptom**: `scalar_mul(5, G, 4)` produces a result where:
1. All internal CCS constraints are satisfied (mul_mod, add_mod, sub_mod, select_point constraints all hold)
2. But `assert_point_equal(result, 5*G_from_secp256k1_crate)` fails — meaning the computed point ≠ 5*G

**Static analysis performed** (could not identify root cause):
- `point_double` formula matches EFD "dbl-2009-l" for a=0 Jacobian ✓
- `point_add` formula matches EFD "add-2007-bl" for Jacobian ✓
- `scalar_mul` double-and-add logic traced manually for scalar=5 (binary 0101) — produces correct 5*G ✓
- `select_fr`/`select_point` formula: `result = if_zero + bit * (if_one - if_zero)` — correct for bit ∈ {0,1} ✓
- `mul_mod` soundness: a*b = q*m + r (carry chain) + r < m (assert_lt) → r = (a*b) mod m ✓
- All 17 non_native tests pass including GX*GX, GX*GY, 3*GY, (p-1)*(p-1) ✓

**Conclusion**: Runtime diagnostic is required. The two existing diagnostic tests will narrow down whether point_double or point_add (or scalar_mul's select logic) produces wrong results for specific intermediate values not covered by existing tests.

### Files Involved

| File | Role | Current State |
|------|------|---------------|
| `poker_zkvm/src/precompiles/non_native.rs` | Non-native field arithmetic | mul_mod FIXED; 2 tests need cleanup |
| `poker_zkvm/src/precompiles/secp256k1_ops.rs` | secp256k1 point operations | 7/8 tests pass; 1 formula bug remaining |
| `poker_zkvm/src/precompiles/ecdsa.rs` | ECDSA verify circuit | MVP only; needs E3 extension |
| `poker_zkvm/src/precompiles/mod.rs` | PrecompileRegistry + traits | Stable; test_phase10 assertions may need update |
| `poker_zkvm/src/precompiles/ccs_builder.rs` | CcsBuilder API | Stable; no changes needed |

## Execution Split (防止上下文溢出)

本计划拆分为 **3 个独立子阶段**，每个可在单次会话内完成。上下文溢出重启后，直接从下一子阶段继续。

| 子阶段 | 内容 | 预计步骤数 | 完成标志 |
|--------|------|-----------|---------|
| **E-FIX** | Steps 1-3: 诊断 + 修复 formula bug + 清理 diagnostic code | ~5 步 | 8/8 secp256k1_ops + 17/17 non_native 测试通过 |
| **E3** | Step 4: 扩展 ecdsa.rs 双模式完整验签 | ~4 步 | 22/22 ecdsa 测试通过 (12 MVP + 10 full) |
| **E4** | Step 5: 全量回归验证 | ~3 步 | poker_zkvm + poker_l1 全测试通过 + clippy 零警告 |

**重启恢复策略**：
- E-FIX 完成后 → 记录到 memory，重启后直接执行 E3
- E3 完成后 → 记录到 memory，重启后直接执行 E4
- 每个子阶段开始时，先 `cargo test` 确认前一阶段成果完好

---

## Proposed Changes

### Step 1: Run Diagnostic Tests (identify formula bug)

Run the two existing diagnostic tests to narrow down the bug:

```bash
cargo test -p poker_zkvm --lib test_point_double_matches_secp256k1 -- --nocapture
cargo test -p poker_zkvm --lib test_scalar_mul_3g_consistency -- --nocapture
```

**Decision tree based on results**:

| test_point_double_matches_secp256k1 | test_scalar_mul_3g_consistency | Conclusion |
|-----|-----|------|
| FAIL | * | point_double produces wrong result → Step 2a |
| PASS | FAIL | point_add produces wrong result → Step 2b |
| PASS | PASS | Bug is specific to scalar=5 or select logic → Step 2c |

### Step 2: Fix the Formula Bug

Based on Step 1 results, apply the appropriate fix:

#### Step 2a: If point_double is wrong

Add a step-by-step diagnostic test `test_point_double_step_by_step` that:
1. Computes each intermediate value of `point_double(G)` in the circuit (A, B, C, D, E, F, X3, Y3, Z3)
2. Computes the same values on the host using `host_mul_mod`/`host_add_mod`/`host_sub_mod`
3. Compares each circuit value with host value via `assert_equal`
4. The first mismatch pinpoints which mul_mod/add_mod/sub_mod call produces a wrong result

Likely root cause: a specific intermediate value (e.g., GY², (GX+GY²)², E²) triggers a bug in mul_mod/add_mod/sub_mod that is NOT covered by existing tests. Fix the underlying arithmetic operation.

#### Step 2b: If point_add is wrong

Add `test_point_add_2g_plus_g_matches_secp256k1` that:
1. Computes `point_double(G)` → 2*G (already verified correct if Step 2a doesn't trigger)
2. Computes `point_add(2*G, G)` → should be 3*G
3. Checks via `assert_point_equal(result, 3*G_from_crate)`
4. If fails, add step-by-step diagnostic similar to Step 2a

#### Step 2c: If both pass but scalar_mul(5,G,4) fails

The bug is in scalar_mul's select/branching logic for specific bit patterns. Add diagnostic tests:
- `test_scalar_mul_2g_consistency` — scalar_mul(2, G, 4) == 2*G
- `test_scalar_mul_4g_consistency` — scalar_mul(4, G, 4) == 4*G
- `test_scalar_mul_6g_consistency` — scalar_mul(6, G, 4) == 6*G

Trace which bit pattern triggers the wrong result. Likely root cause: a select_point or started_flag logic error for specific bit sequences (e.g., 0101 vs 0011).

**Fix approach**: Compare each iteration's R value with host-computed intermediate points. The host can compute k*G for each prefix of the scalar bits and compare.

### Step 3: Cleanup Diagnostic Code

In `non_native.rs`, simplify the two tests with diagnostic blocks:

**`test_nonnative_mul_mod_gx`** (lines 1058-1082): Replace the `if !sat { ... panic! }` block with:
```rust
assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
```

**`test_nonnative_mul_mod_mixed`** (lines 1107-1131): Same simplification.

Keep `test_nonnative_mul_mod_gx_gy` (already clean) and `test_mul_big_circuit_vs_host_gx` (already clean) as-is.

**Note**: The two diagnostic tests in `secp256k1_ops.rs` (`test_point_double_matches_secp256k1` and `test_scalar_mul_3g_consistency`) are permanent regression tests — they verify correctness against the secp256k1 crate. They should NOT be removed.

### Step 4: E3 — Extend ecdsa.rs to Dual-Mode Full Verification

#### 4.1: Struct Extension

```rust
#[derive(Debug, Clone)]
pub struct EcdsaVerifyCircuit {
    curve: &'static str,
    full_mode: bool,
    scalar_num_bits: usize,
}
```

#### 4.2: Constructors

```rust
impl EcdsaVerifyCircuit {
    pub fn new() -> Self {
        Self { curve: "secp256k1", full_mode: false, scalar_num_bits: 0 }
    }

    pub fn new_full() -> Self {
        Self { curve: "secp256k1", full_mode: true, scalar_num_bits: 8 }
    }

    pub fn new_full_with_bits(n: usize) -> Self {
        Self { curve: "secp256k1", full_mode: true, scalar_num_bits: n }
    }

    pub fn is_full_mode(&self) -> bool { self.full_mode }
    pub fn scalar_num_bits(&self) -> usize { self.scalar_num_bits }
}
```

#### 4.3: Full Verification Logic (`run_full`)

Implements `s·R' = z·G + r·P` where R' = (r, ry) with ry provided as hint:

```rust
pub fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
    // inputs: 24 Fr values = 6 NonNativeElements × 4 limbs
    // [s(4), r(4), ry(4), z(4), px(4), py(4)]
    if inputs.len() != 24 {
        return Err(ZkvmError::Other(format!(
            "EcdsaVerifyCircuit::run_full: inputs.len() {} != 24", inputs.len()
        )));
    }

    let mut builder = NonNativeBuilder::new();

    // Allocate inputs as NonNativeElements
    let s = builder.alloc_element([inputs[0], inputs[1], inputs[2], inputs[3]]);
    let r = builder.alloc_element([inputs[4], inputs[5], inputs[6], inputs[7]]);
    let ry = builder.alloc_element([inputs[8], inputs[9], inputs[10], inputs[11]]);
    let z = builder.alloc_element([inputs[12], inputs[13], inputs[14], inputs[15]]);
    let px = builder.alloc_element([inputs[16], inputs[17], inputs[18], inputs[19]]);
    let py = builder.alloc_element([inputs[20], inputs[21], inputs[22], inputs[23]]);

    // Convert to [u64; 4] for from_affine
    let r_u256 = builder.element_to_u256(&r);
    let ry_u256 = builder.element_to_u256(&ry);
    let px_u256 = builder.element_to_u256(&px);
    let py_u256 = builder.element_to_u256(&py);

    // R' = (r, ry, 1) — Jacobian from affine
    let r_prime = from_affine(&mut builder, &r_u256, &ry_u256);
    // G = (GX, GY, 1)
    let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
    // P = (px, py, 1)
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

#### 4.4: Trait Method Updates

For `PrecompileCircuit`:
- `name()`: return `"ecdsa_verify"` (same for both modes)
- `num_variables()`: return 6 for MVP, 0 for full mode (dynamic)
- `build_ccs()`: return MVP CCS for MVP mode, empty CCS for full mode (use `run_full` instead)
- `assign_witness()`: MVP behavior for MVP mode, return `Err("use run_full() for full mode")` for full mode
- `gas_cost()`: return 100_000 for MVP, 3_000_000 for full mode

For `CcsCircuit`:
- `num_matrices()`: return 7 for MVP, 0 for full mode
- `to_ccs_instance()`: MVP behavior for MVP mode, return error for full mode

#### 4.5: Update `mod.rs` test assertions

`test_phase10_registry_full` currently asserts `ecdsa_verify` has `num_variables=6` and `gas_cost=100_000`. Since the registry uses `EcdsaVerifyCircuit::new()` (MVP mode), these assertions remain valid. No change needed.

`test_phase10_gas_costs_reasonable` checks `ecdsa_verify` gas is in [100_000, 200_000). MVP gas=100_000 is in range. No change needed.

#### 4.6: Tests (10 new tests)

1. **`test_ecdsa_full_mode_constructors`** — `new_full()` returns full_mode=true, scalar_num_bits=8; `new_full_with_bits(16)` returns scalar_num_bits=16; `new()` returns full_mode=false
2. **`test_ecdsa_full_mode_basic_satisfied`** — 8-bit test case: R'=G, z=3, s=10, r=Gx, P=(7*inv(r_trunc,n))*G. Verify CCS satisfied.
3. **`test_ecdsa_full_mode_gas_cost`** — full mode gas=3_000_000, MVP gas=100_000
4. **`test_ecdsa_full_mode_num_variables`** — full mode num_variables=0, MVP num_variables=6
5. **`test_ecdsa_full_mode_invalid_input_length`** — run_full with 23 inputs returns error
6. **`test_ecdsa_full_mode_tampered_s`** — modify s limb → assert_point_equal fails → CCS not satisfied
7. **`test_ecdsa_full_mode_tampered_r`** — modify r limb → fails
8. **`test_ecdsa_full_mode_tampered_px`** — modify px limb → fails
9. **`test_ecdsa_full_mode_assign_witness_error`** — calling assign_witness on full mode returns error
10. **`test_ecdsa_full_mode_mvp_backward_compatible`** — `new()` still produces working MVP circuit with all 12 existing tests passing

**Test case construction for test 2** (8-bit truncation):
- R' = G, so r = Gx mod n, ry = Gy
- r_trunc = Gx mod 256 = SECP256K1_GX[0] mod 256 = 0x98 = 152
- z = 3, s = 10
- Equation: 10·G = 3·G + 152·P → P = 7·inv(152, n)·G
- Host: compute `d = 7 * inv(152, n) mod n` using `host_inv_mod`, then `P = d·G` using secp256k1 crate
- Circuit inputs: s=[10,0,0,0], r=SECP256K1_GX, ry=SECP256K1_GY, z=[3,0,0,0], px/py from P

**Test case construction for tampered tests (6-8)**:
- Same valid inputs as test 2
- Modify one limb of s/r/px by adding 1
- CCS should NOT be satisfied (assert_point_equal fails because the equation no longer holds)

### Step 5: E4 — Full Regression Verification

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

**Expected results**:
- All `non_native` tests pass (17 tests, cleaned up)
- All `secp256k1_ops` tests pass (8 tests, including fixed `test_scalar_mul_consistency`)
- All `ecdsa` tests pass (12 existing MVP + 10 new full-mode = 22 tests)
- All `precompiles::mod` tests pass (including `test_phase10_registry_full`)
- All `soundness` tests pass (13 tests)
- All `e2e_poker_hand_eval` tests pass (5 tests)
- All `poker_l1` lib tests pass (1276 tests)
- Zero clippy warnings
- Bench compilation succeeds
- Pre-existing E2E failures (fibonacci/sha256 proof size > 512KB) remain — not addressed in this phase

## Assumptions & Decisions

1. **Diagnostic-first approach**: Run tests before fixing, since static analysis exhausted all avenues. The two diagnostic tests are already in place.
2. **Step 2 is conditional**: The fix depends on Step 1 results. Three branches (2a/2b/2c) cover all scenarios.
3. **E3 uses 8-bit scalar_num_bits for tests**: Full 256-bit scalar_mul would generate ~19M constraints (3 × 256 × 18 × 1400), too slow for unit tests. 8-bit truncation (~600K constraints) is sufficient for structural validation.
4. **E3 gas_cost = 3,000,000 for full mode**: Reflects full 256-bit verification cost with non-native arithmetic (vs 100,000 for MVP). Aligned with spec estimate scaling.
5. **E3 backward compatible**: `new()` retains MVP behavior with 6 variables/7 matrices/100k gas. Full mode is opt-in via `new_full()`/`new_full_with_bits(n)`.
6. **run_full() is separate from trait methods**: PrecompileCircuit trait methods return empty/error for full mode. Users call `run_full()` directly for full mode. This avoids changing the trait interface.
7. **Pre-existing E2E failures**: fibonacci/sha256 tests fail due to proof size > 512KB (Stage 1 batch_size=256 issue, requires CycleFold). Not addressed in this phase.
8. **Formula bug MUST be fixed before E3**: E3 uses scalar_mul, point_add, and assert_point_equal from secp256k1_ops.rs. If the formula bug persists, E3 tests will fail.

## Verification Steps

1. **Step 1-3 (Formula fix)**: All 8 secp256k1_ops tests pass + all 17 non_native tests pass (cleaned up)
2. **Step 4 (E3)**: All 10 new ecdsa full-mode tests pass + all 12 existing MVP tests pass
3. **Step 5 (E4)**: poker_zkvm lib tests pass, poker_l1 lib tests pass, clippy zero warnings, bench compiles
4. No regression in existing tests (soundness, e2e_poker_hand_eval)
