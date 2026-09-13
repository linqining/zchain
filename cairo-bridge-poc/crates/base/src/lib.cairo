// cairo-bridge-poc: minimal Cairo-verifier recursive-bridge probe.
//
// Shared library. All verification primitives used here are the OFFICIAL
// stwo-cairo v1.2.2 `stwo_verifier_core` implementations (vendored under
// ../../vendor/, Apache-2.0), not reimplementations:
//   - M31/CM31/QM31 arithmetic            -> stwo_verifier_core::fields
//   - fri_fold (circle->line + line folds)-> stwo_verifier_core::poly::utils::fri_fold
//   - Poseidon252 Fiat-Shamir channel     -> stwo_verifier_core::channel
//   - Poseidon252 Merkle hasher           -> stwo_verifier_core::vcs::poseidon_hasher
// The vendored crates were patched only to hard-select the poseidon252 /
// naive (non-opcode) code paths, because scarb 2.11.4 does not support the
// upstream v1.2.2 `[features]` forwarding syntax (upstream pins scarb 2.15).
//
// Benches execute N data-dependent iterations of a single primitive so that
// (steps(program) - steps(baseline)) / N yields the per-op Cairo cost.

pub mod benches {
    use core::poseidon::hades_permutation;
    use stwo_verifier_core::fields::m31::m31;
    use stwo_verifier_core::fields::qm31::QM31Trait;
    use stwo_verifier_core::poly::utils::fri_fold;
    use stwo_verifier_core::channel::{Channel, ChannelTrait};
    use stwo_verifier_core::vcs::MerkleHasher;
    use stwo_verifier_core::vcs::poseidon_hasher::PoseidonMerkleHasher;

    pub fn bench_empty(seed: felt252, n: usize) -> felt252 {
        let mut i: usize = 0;
        while i < n {
            i += 1;
        };
        seed + i.into()
    }

    pub fn bench_m31_add(seed: felt252, n: usize) -> felt252 {
        let mut a = m31(0x1234567);
        let mut b = m31(0x2b7e151);
        let mut i: usize = 0;
        while i < n {
            a = a + b;
            b = b + a;
            i += 1;
        };
        seed + a.inner.into()
    }

    pub fn bench_m31_mul(seed: felt252, n: usize) -> felt252 {
        let mut a = m31(0x1234567);
        let mut b = m31(0x2b7e151);
        let mut i: usize = 0;
        while i < n {
            a = a * b;
            b = b + a;
            i += 1;
        };
        seed + a.inner.into()
    }

    pub fn bench_qm31_mul(seed: felt252, n: usize) -> felt252 {
        let mut a = QM31Trait::from_fixed_array([m31(1), m31(2), m31(3), m31(4)]);
        let mut b = QM31Trait::from_fixed_array([m31(5), m31(6), m31(7), m31(8)]);
        let mut i: usize = 0;
        while i < n {
            a = a * b;
            b = b + a;
            i += 1;
        };
        let [c0, _c1, _c2, _c3] = a.to_fixed_array();
        seed + c0.inner.into()
    }

    pub fn bench_fri_fold(seed: felt252, n: usize) -> felt252 {
        let mut v0 = QM31Trait::from_fixed_array([m31(11), m31(22), m31(33), m31(44)]);
        let mut v1 = QM31Trait::from_fixed_array([m31(55), m31(66), m31(77), m31(88)]);
        let itwid = m31(0x1001001);
        let alpha = QM31Trait::from_fixed_array([m31(9), m31(8), m31(7), m31(6)]);
        let mut i: usize = 0;
        while i < n {
            let y = fri_fold(v0, v1, itwid, alpha);
            v1 = v0;
            v0 = y;
            i += 1;
        };
        let [c0, _c1, _c2, _c3] = v0.to_fixed_array();
        seed + c0.inner.into()
    }

    pub fn bench_hades(seed: felt252, n: usize) -> felt252 {
        let mut x = seed;
        let mut i: usize = 0;
        while i < n {
            let (s0, _s1, _s2) = hades_permutation(x, 1, 2);
            x = s0;
            i += 1;
        };
        // Return stays small (adapter requires small public-segment values);
        // the hades chain on x preserves the data dependency.
        seed + i.into()
    }

    /// One canonical channel stage unit: one commitment mix + one secure draw.
    pub fn bench_channel(seed: felt252, n: usize) -> felt252 {
        let mut ch: Channel = Default::default();
        let mut acc: felt252 = seed;
        let mut i: usize = 0;
        while i < n {
            ch.mix_commitment(0x1234abcd00 + i.into());
            let alpha = ch.draw_secure_felt();
            let [l0, _l1, _l2, _l3] = alpha.to_fixed_array();
            acc += l0.inner.into();
            i += 1;
        };
        acc
    }

    /// One Merkle unit: a leaf hash (1 QM31 column) + one internal node hash.
    pub fn bench_merkle(seed: felt252, n: usize) -> felt252 {
        let leaf_limbs = [m31(13), m31(17), m31(19), m31(23)];
        let [lv0, lv1, lv2, lv3] = leaf_limbs;
        let leaf_hash = PoseidonMerkleHasher::hash_node(None, array![lv0, lv1, lv2, lv3].span());
        let sib: felt252 = 0xabcdef12345;
        let mut r = leaf_hash;
        let mut i: usize = 0;
        while i < n {
            r = PoseidonMerkleHasher::hash_node(Some((r, sib)), array![].span());
            i += 1;
        };
        // Return stays small (see bench_hades); r chain preserves dependency.
        seed + i.into()
    }
}

// ---------------------------------------------------------------------------
// verify_min: minimal canonical-shaped STARK verification: exactly one FRI
// structure (8 layers = circle->line + 7 line folds, fold_step = 1,
// log_last_layer_degree_bound = 0), one query, one depth-8 Merkle path, and
// the Poseidon252 channel stage. All pseudo-proof inputs are derived
// deterministically from SEED through the official channel, so the program is
// self-contained. The final FRI value is checked against LAST_LAYER_C and the
// Merkle chain against MERKLE_ROOT - both are independent compile-time
// constants produced by the Rust driver's mirrored arithmetic (cross-check:
// any divergence panics in the VM and fails the run).
// ---------------------------------------------------------------------------
pub mod verify_min {
    use core::panic_with_felt252;
    use stwo_verifier_core::fields::m31::m31;
    use stwo_verifier_core::fields::qm31::QM31Trait;
    use stwo_verifier_core::poly::utils::fri_fold;
    use stwo_verifier_core::channel::{Channel, ChannelTrait};
    use stwo_verifier_core::vcs::MerkleHasher;
    use stwo_verifier_core::vcs::poseidon_hasher::PoseidonMerkleHasher;

    // Canonical single-hand shape: log_size = 8, fold_step = 1,
    // log_last_layer_degree_bound = 0 -> 8 FRI layers, constant last layer.
    const N_LAYERS: usize = 8;

    // Deterministic seed for the embedded pseudo-proof.
    const SEED: felt252 = 0xdeadbeefcafe123;

    // itwid for layer l: inverse of 2^l in M31 (deterministic domain choice).
    // inv(2^l) mod (2^31-1): 2^31 == 1 => inv(2) = (P+1)/2.
    #[inline(never)]
    fn itwid_table() -> Span<u32> {
        let t = array![
            0x40000001, 0x20000001, 0x10000001, 0x08000001, 0x04000001, 0x02000001, 0x01000001,
            0x00800001
        ];
        t.span()
    }

    // Produced by the Rust driver mirror (driver/src/mirror.rs). Placeholders
    // C0..C3 / RROOT are replaced by tools/embed_consts.py before scarb build.
    fn last_layer_c() -> [u32; 4] {
        [0x7c774589, 0x90173dc, 0x51c3e7fc, 0x154b87d2] // EMBED_C (driver mirror)
    }

    fn merkle_root() -> felt252 {
        0x935b73fcee3d262cff17ee0a316f9904c8b23937c7a3a9da12bf429e85f6c // EMBED_ROOT (driver mirror)
    }

    pub fn run() -> felt252 {
        // ---- channel stage: mix 3 commitments (scope/trace/interaction),
        // then draw the 8 FRI folding alphas.
        let mut ch: Channel = Default::default();
        ch.mix_commitment(0x1000 + SEED);
        ch.mix_commitment(0x2000 + SEED);
        ch.mix_commitment(0x3000 + SEED);

        let a0 = ch.draw_secure_felt();
        let a1 = ch.draw_secure_felt();
        let a2 = ch.draw_secure_felt();
        let a3 = ch.draw_secure_felt();
        let a4 = ch.draw_secure_felt();
        let a5 = ch.draw_secure_felt();
        let a6 = ch.draw_secure_felt();
        let a7 = ch.draw_secure_felt();

        // ---- FRI chain: first layer (circle->line), then 7 line folds.
        let y_p = ch.draw_secure_felt();
        let y_m = ch.draw_secure_felt();
        let itw = itwid_table();
        let mut y = fri_fold(y_p, y_m, m31(*itw[0]), a0);
        y = fri_fold(y, ch.draw_secure_felt(), m31(*itw[1]), a1);
        y = fri_fold(y, ch.draw_secure_felt(), m31(*itw[2]), a2);
        y = fri_fold(y, ch.draw_secure_felt(), m31(*itw[3]), a3);
        y = fri_fold(y, ch.draw_secure_felt(), m31(*itw[4]), a4);
        y = fri_fold(y, ch.draw_secure_felt(), m31(*itw[5]), a5);
        y = fri_fold(y, ch.draw_secure_felt(), m31(*itw[6]), a6);
        y = fri_fold(y, ch.draw_secure_felt(), m31(*itw[7]), a7);

        // ---- last layer check: constant polynomial (log_last_layer_degree=0).
        let [cc0, cc1, cc2, cc3] = last_layer_c();
        let c = QM31Trait::from_fixed_array([m31(cc0), m31(cc1), m31(cc2), m31(cc3)]);
        if y != c {
            panic_with_felt252('fri_last_mismatch');
        }

        // ---- Merkle path: 1 QM31 column leaf, depth 8, alternating sides.
        let leaf_qm31 = ch.draw_secure_felt();
        let [lf0, lf1, lf2, lf3] = leaf_qm31.to_fixed_array();
        let mut r = PoseidonMerkleHasher::hash_node(None, array![lf0, lf1, lf2, lf3].span());
        let mut lvl: usize = 0;
        while lvl < 8 {
            // sibling felt = first limb of a channel draw (deterministic).
            let sib_qm31 = ch.draw_secure_felt();
            let [s0, _s1, _s2, _s3] = sib_qm31.to_fixed_array();
            let sib: felt252 = s0.inner.into();
            if lvl % 2 == 0 {
                r = PoseidonMerkleHasher::hash_node(Some((r, sib)), array![].span());
            } else {
                r = PoseidonMerkleHasher::hash_node(Some((sib, r)), array![].span());
            }
            lvl += 1;
        };
        if r != merkle_root() {
            panic_with_felt252('merkle_root_mismatch');
        }

        // ---- checksum (prevents DCE; returned to the output segment).
        // Kept small: the adapter requires public-segment values to fit u128.
        let [y0, _y1, _y2, _y3] = y.to_fixed_array();
        y0.inner.into()
    }
}
