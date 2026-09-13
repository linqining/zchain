//! Bit-faithful Rust mirror of the `verify_min` Cairo program.
//!
//! Every step mirrors stwo-verifier-core v1.2.2 semantics exactly:
//! - `poseidon_permute_comp` (starknet-crypto) == corelib `hades_permutation`
//!   (same Starknet Hades permutation with capacity).
//! - Channel: mix = H(digest, x, cap=2), draw = H(digest, counter, cap=3),
//!   then 8x extract_m31 (low 31 bits, reduced into M31).
//! - FRI fold: `alpha * ((v0 - v1) * itwid) + (v0 + v1)` over QM31
//!   (QM31 = CM31[u] with u^2 = 2 + i, M31 = GF(2^31 - 1)).
//! - Merkle leaf: pack 4 M31 into a felt (base 2^31), add length padding
//!   (n * 2^248), H(padded_word, 1, 0). Internal node: H(x, y, 2).
//!
//! The driver embeds the mirrored FRI last-layer value and Merkle root into
//! the Cairo program; the program recomputes everything through the OFFICIAL
//! verifier_core Cairo code and panics on any divergence (cross-validation).

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use starknet_crypto::poseidon_permute_comp;
use starknet_ff::FieldElement as Felt;

pub const P: u64 = 0x7f_ff_ff_ff;
/// Seed shared with the Cairo program's `SEED` const.
pub const SEED: u64 = 0xdead_beef_cafe_123;

// itwid table: inverse of 2^l mod 2^31-1 (2^31 == 1 => inv(2) = (P+1)/2).
pub const ITWID: [u32; 8] = [
    0x4000_0001, 0x2000_0001, 0x1000_0001, 0x0800_0001, 0x0400_0001, 0x0200_0001, 0x0100_0001,
    0x0080_0001,
];

fn felt_of(v: u64) -> Felt {
    Felt::from(v)
}

/// 2^l as a felt (l <= 250).
pub fn pow2(l: u32) -> Felt {
    let mut acc = Felt::from(1u64);
    let two = Felt::from(2u64);
    for _ in 0..l {
        acc = acc * two;
    }
    acc
}

pub fn hades3(x: Felt, y: Felt, z: Felt) -> (Felt, Felt, Felt) {
    let mut s = [x, y, z];
    poseidon_permute_comp(&mut s);
    (s[0], s[1], s[2])
}

// ---------------- M31 / CM31 / QM31 ----------------

pub fn m31_add(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) % P) as u32
}
pub fn m31_sub(a: u32, b: u32) -> u32 {
    ((a as u64 + P - b as u64) % P) as u32
}
pub fn m31_mul(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % P) as u32
}
pub type CM31 = [u32; 2];
pub type QM31 = [u32; 4]; // (a + b i) + (c + d i) u

pub fn cm_add(x: CM31, y: CM31) -> CM31 {
    [m31_add(x[0], y[0]), m31_add(x[1], y[1])]
}
pub fn cm_sub(x: CM31, y: CM31) -> CM31 {
    [m31_sub(x[0], y[0]), m31_sub(x[1], y[1])]
}
pub fn cm_mul(x: CM31, y: CM31) -> CM31 {
    [
        m31_sub(m31_mul(x[0], y[0]), m31_mul(x[1], y[1])),
        m31_add(m31_mul(x[0], y[1]), m31_mul(x[1], y[0])),
    ]
}
pub fn qm_add(x: QM31, y: QM31) -> QM31 {
    [
        m31_add(x[0], y[0]),
        m31_add(x[1], y[1]),
        m31_add(x[2], y[2]),
        m31_add(x[3], y[3]),
    ]
}
pub fn qm_sub(x: QM31, y: QM31) -> QM31 {
    [
        m31_sub(x[0], y[0]),
        m31_sub(x[1], y[1]),
        m31_sub(x[2], y[2]),
        m31_sub(x[3], y[3]),
    ]
}
pub fn qm_mul_m31(x: QM31, s: u32) -> QM31 {
    [
        m31_mul(x[0], s),
        m31_mul(x[1], s),
        m31_mul(x[2], s),
        m31_mul(x[3], s),
    ]
}
/// (2 + i) * (m, n) = (2m - n, m + 2n)
fn cm_mul_by_2_plus_i(m: u32, n: u32) -> CM31 {
    [m31_sub(m31_mul(2, m), n), m31_add(m, m31_mul(2, n))]
}
pub fn qm_mul(x: QM31, y: QM31) -> QM31 {
    let x0 = [x[0], x[1]];
    let x1 = [x[2], x[3]];
    let y0 = [y[0], y[1]];
    let y1 = [y[2], y[3]];
    let t = cm_mul(x1, y1); // = x1*y1
    let corr = cm_mul_by_2_plus_i(t[0], t[1]); // = (2+i)*x1*y1
    let z0 = cm_add(cm_mul(x0, y0), corr);
    let z1 = cm_add(cm_mul(x0, y1), cm_mul(x1, y0));
    [z0[0], z0[1], z1[0], z1[1]]
}
/// Official `poly::utils::fri_fold`:
/// packed_fused_mul_add((v0 - v1) * itwid, alpha, v0 + v1) = alpha*((v0-v1)*itwid) + (v0+v1)
pub fn fri_fold(v0: QM31, v1: QM31, itwid: u32, alpha: QM31) -> QM31 {
    let f0 = qm_add(v0, v1);
    let f1 = qm_mul_m31(qm_sub(v0, v1), itwid);
    qm_add(qm_mul(alpha, f1), f0)
}

// ---------------- Channel ----------------

pub struct Channel {
    digest: Felt,
    n_draws: u64,
}

impl Channel {
    pub fn new() -> Self {
        Channel {
            digest: Felt::ZERO,
            n_draws: 0,
        }
    }
    pub fn mix_commitment(&mut self, c: Felt) {
        let (s0, _, _) = hades3(self.digest, c, felt_of(2));
        self.digest = s0;
        self.n_draws = 0;
    }
    fn draw_secure_felt252(&mut self) -> Felt {
        let (res, _, _) = hades3(self.digest, felt_of(self.n_draws), felt_of(3));
        self.n_draws += 1;
        res
    }
    /// Official `draw_base_felts`: 8 M31 limbs; `draw_secure_felt` keeps the
    /// first 4 as a QM31.
    pub fn draw_qm31(&mut self) -> QM31 {
        let felt = self.draw_secure_felt252();
        let bytes = felt.to_bytes_be();
        let mut x = BigUint::from_bytes_be(&bytes);
        let mask = BigUint::from((1u128 << 31) - 1);
        let mut limbs = [0u32; 8];
        for limb in limbs.iter_mut() {
            let r: u64 = (&x & &mask).to_u64().unwrap();
            // M31Trait::reduce_u128: div_rem by P (r < 2^31, so only r == P folds)
            *limb = if r == P { 0 } else { r as u32 };
            x >>= 31;
        }
        [limbs[0], limbs[1], limbs[2], limbs[3]]
    }
}

// ---------------- Merkle ----------------

pub fn leaf_hash(limbs: QM31) -> Felt {
    let mut word = felt_of(limbs[0] as u64);
    let shift = pow2(31);
    for l in limbs.iter().skip(1) {
        word = word * shift + felt_of(*l as u64);
    }
    // add_length_padding(word, 4): word + 4 * 2^248
    let padded = word + Felt::from(4u64) * pow2(248);
    let (s0, _, _) = hades3(padded, felt_of(1), Felt::ZERO);
    s0
}

pub fn node_hash(x: Felt, y: Felt) -> Felt {
    let (s0, _, _) = hades3(x, y, felt_of(2));
    s0
}

pub fn felt_from_m31(l: u32) -> Felt {
    felt_of(l as u64)
}

// ---------------- Full mirror of verify_min::run ----------------

pub struct MirrorResult {
    pub last_layer_c: QM31,
    pub merkle_root: Felt,
    pub checksum: Felt,
    pub alphas: [QM31; 8],
}

pub fn run() -> MirrorResult {
    let seed = felt_of(SEED);
    let mut ch = Channel::new();
    ch.mix_commitment(Felt::from(0x1000u64) + seed);
    ch.mix_commitment(Felt::from(0x2000u64) + seed);
    ch.mix_commitment(Felt::from(0x3000u64) + seed);

    let mut alphas = [[0u32; 4]; 8];
    for a in alphas.iter_mut() {
        *a = ch.draw_qm31();
    }

    let y_p = ch.draw_qm31();
    let y_m = ch.draw_qm31();
    let mut y = fri_fold(y_p, y_m, ITWID[0], alphas[0]);
    for l in 1..8 {
        let w = ch.draw_qm31();
        y = fri_fold(y, w, ITWID[l], alphas[l]);
    }
    let last_layer_c = y;

    let leaf = ch.draw_qm31();
    let mut r = leaf_hash(leaf);
    for lvl in 0..8usize {
        let sib = ch.draw_qm31();
        let sib_felt = felt_from_m31(sib[0]);
        if lvl % 2 == 0 {
            r = node_hash(r, sib_felt);
        } else {
            r = node_hash(sib_felt, r);
        }
    }
    let merkle_root = r;

    let checksum = felt_of(last_layer_c[0] as u64) + merkle_root;
    MirrorResult {
        last_layer_c,
        merkle_root,
        checksum,
        alphas,
    }
}
