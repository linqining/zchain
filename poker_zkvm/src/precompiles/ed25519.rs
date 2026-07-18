//! Ed25519 / Curve25519 预编译电路（Phase I — Batch 2）。
//!
//! 双模式实现：
//! - **MVP 模式**（`new()`）：单点加法验证（P1 + P2 = P3）。
//! - **Full 模式**（`new_full()` / `new_full_with_bits(n)`）：标量乘法（scalar · P = result）。
//!
//! # 曲线参数（twisted Edwards, a = -1）
//!
//! 曲线方程：`-x² + y² = 1 + d·x²·y²`
//!
//! 使用 Extended 坐标 (X:Y:T:Z)，仿射坐标：
//! - `x = X / Z`
//! - `y = Y / Z`
//! - `t = T / Z = x·y`
//!
//! # 约束计数
//!
//! | 操作 | mul_mod 数 | 约束数 |
//! |------|-----------|--------|
//! | point_add（统一公式） | 9 | ~12600 |
//! | point_double（优化版） | 7 | ~9800 |
//! | scalar_mul (per bit) | ~16 | ~22400 |
//! | assert_on_curve | 4 | ~5600 |
//! | assert_point_equal | 4 | ~5600 |

#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::non_native::{NonNativeBuilder, NonNativeElement};
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

// ===== Curve25519 / Ed25519 常量（[u64; 4] little-endian）=====

/// Curve25519 基域 p = 2^255 - 19。
const ED25519_P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

/// 曲线参数 d = -121665/121666 mod p。
const ED25519_D: [u64; 4] = [
    0x75EB_4DCA_1359_78A3,
    0x0070_0A4D_4141_D8AB,
    0x8CC7_4079_7779_E898,
    0x5203_6CEE_2B6F_FE73,
];

/// 2*d mod p（预计算，用于统一加法公式）。
const ED25519_TWO_D: [u64; 4] = [
    0xEBD6_9B94_26B2_F159,
    0x00E0_149A_8283_B156,
    0x198E_80F2_EEF3_D130,
    0x2406_D9DC_56DF_FCE7,
];

/// 基点阶 L = 2^252 + 27742317777372353535851937790883648493。
#[allow(dead_code)]
const ED25519_L: [u64; 4] = [
    0x5CF5_D3ED,
    0x5812_631A_5CF5_D3ED,
    0x14DE_F9DE_A2F7_9CD6,
    0x1000_0000_0000_0000,
];

/// 基点 B 的 x 坐标。
const ED25519_BX: [u64; 4] = [
    0x36A9_D29F_70DA_2AD3,
    0x96D3_389F_6ADA_584D,
    0x3F5B_1DCE_0229_23A3,
    0x5E96_C92C_3291_AC01,
];

/// 基点 B 的 y 坐标（= 4/5 mod p）。
const ED25519_BY: [u64; 4] = [
    0x6666_6666_6666_6658,
    0x6666_6666_6666_6666,
    0x6666_6666_6666_6666,
    0x6666_6666_6666_6666,
];

/// Ed25519 基础 gas（与 syscalls/gas.rs 对齐）。
const GAS_ED25519_BASE: u64 = 50_000;

/// Ed25519 每标量位 gas。
const GAS_ED25519_PER_BIT: u64 = 8_000;

// ===== EdwardsPoint + 点运算 =====

/// Extended twisted Edwards 坐标点 (X:Y:T:Z)。
#[derive(Clone)]
pub(crate) struct EdwardsPoint {
    pub x: NonNativeElement,
    pub y: NonNativeElement,
    pub t: NonNativeElement,
    pub z: NonNativeElement,
}

/// 条件选择两个 Fr 值：`result = if_zero + bit * (if_one - if_zero)`。
///
/// 添加 2 linear + 1 multiplication = 3 约束。
fn select_fr(builder: &mut NonNativeBuilder, bit: usize, if_one: usize, if_zero: usize) -> usize {
    let if_one_val = builder.get_val(if_one);
    let if_zero_val = builder.get_val(if_zero);
    let diff_val = if_one_val.sub(&if_zero_val);

    let diff_var = builder.alloc(diff_val);
    let row = builder.ccs.alloc_row();
    builder.ccs.add_linear(
        row,
        &[
            (if_one, Fr::one()),
            (if_zero, Fr::one().neg()),
            (diff_var, Fr::one().neg()),
        ],
    );

    let bit_diff_val = builder.get_val(bit).mul(&diff_val);
    let bit_diff_var = builder.alloc(bit_diff_val);
    let row = builder.ccs.alloc_row();
    builder
        .ccs
        .add_multiplication(row, bit, diff_var, bit_diff_var);

    let result_val = if_zero_val.add(&bit_diff_val);
    let result_var = builder.alloc(result_val);
    let row = builder.ccs.alloc_row();
    builder.ccs.add_linear(
        row,
        &[
            (if_zero, Fr::one()),
            (bit_diff_var, Fr::one()),
            (result_var, Fr::one().neg()),
        ],
    );

    result_var
}

/// 条件选择两个 NonNativeElement：`result = bit ? if_one : if_zero`。
fn select_element(
    builder: &mut NonNativeBuilder,
    bit: usize,
    if_one: &NonNativeElement,
    if_zero: &NonNativeElement,
) -> NonNativeElement {
    let mut limbs = [0usize; 4];
    for k in 0..4 {
        limbs[k] = select_fr(builder, bit, if_one.limbs[k], if_zero.limbs[k]);
    }
    NonNativeElement { limbs }
}

/// 条件选择两个 EdwardsPoint：`result = bit ? if_one : if_zero`。
fn select_point(
    builder: &mut NonNativeBuilder,
    bit: usize,
    if_one: &EdwardsPoint,
    if_zero: &EdwardsPoint,
) -> EdwardsPoint {
    EdwardsPoint {
        x: select_element(builder, bit, &if_one.x, &if_zero.x),
        y: select_element(builder, bit, &if_one.y, &if_zero.y),
        t: select_element(builder, bit, &if_one.t, &if_zero.t),
        z: select_element(builder, bit, &if_one.z, &if_zero.z),
    }
}

/// 单位元（恒等点）= (0, 1, 0, 1)。
pub(crate) fn identity_point(builder: &mut NonNativeBuilder) -> EdwardsPoint {
    let zero = builder.from_u256(&[0, 0, 0, 0]);
    let one = builder.from_u256(&[1, 0, 0, 0]);
    EdwardsPoint {
        x: zero.clone(),
        y: one.clone(),
        t: zero,
        z: one,
    }
}

/// 从仿射坐标 (x, y) 创建 Extended 点。
pub(crate) fn from_affine(
    builder: &mut NonNativeBuilder,
    x: &[u64; 4],
    y: &[u64; 4],
) -> EdwardsPoint {
    let xv = builder.from_u256(x);
    let yv = builder.from_u256(y);
    let tv = builder.mul_mod(&xv, &yv, &ED25519_P);
    let zv = builder.from_u256(&[1, 0, 0, 0]);
    EdwardsPoint {
        x: xv,
        y: yv,
        t: tv,
        z: zv,
    }
}

/// 统一 Edwards 加法（a = -1, extended coords）。
///
/// 公式：
/// - A = (Y1 - X1) * (Y2 - X2)
/// - B = (Y1 + X1) * (Y2 + X2)
/// - C = T1 * 2d * T2
/// - D = Z1 * 2 * Z2
/// - E = B - A
/// - F = D - C
/// - G = D + C
/// - H = B + A
/// - X3 = E * F
/// - Y3 = G * H
/// - T3 = E * H
/// - Z3 = F * G
///
/// 9 mul_mod ≈ 12600 约束。
pub(crate) fn point_add(
    builder: &mut NonNativeBuilder,
    p: &EdwardsPoint,
    q: &EdwardsPoint,
) -> EdwardsPoint {
    let m = &ED25519_P;
    let two_d = &ED25519_TWO_D;

    // Y1 - X1
    let y1_minus_x1 = builder.sub_mod(&p.y, &p.x, m);
    // Y2 - X2
    let y2_minus_x2 = builder.sub_mod(&q.y, &q.x, m);
    // A = (Y1-X1) * (Y2-X2)
    let a = builder.mul_mod(&y1_minus_x1, &y2_minus_x2, m);

    // Y1 + X1
    let y1_plus_x1 = builder.add_mod(&p.y, &p.x, m);
    // Y2 + X2
    let y2_plus_x2 = builder.add_mod(&q.y, &q.x, m);
    // B = (Y1+X1) * (Y2+X2)
    let b = builder.mul_mod(&y1_plus_x1, &y2_plus_x2, m);

    // T1 * T2
    let t1_t2 = builder.mul_mod(&p.t, &q.t, m);
    // C = 2d * T1 * T2
    let two_d_elem = builder.from_u256(two_d);
    let c = builder.mul_mod(&two_d_elem, &t1_t2, m);

    // Z1 * Z2
    let z1_z2 = builder.mul_mod(&p.z, &q.z, m);
    // D = 2 * Z1 * Z2
    let d = builder.add_mod(&z1_z2, &z1_z2, m);

    // E = B - A
    let e = builder.sub_mod(&b, &a, m);
    // F = D - C
    let f = builder.sub_mod(&d, &c, m);
    // G = D + C
    let g = builder.add_mod(&d, &c, m);
    // H = B + A
    let h = builder.add_mod(&b, &a, m);

    // X3 = E * F
    let x3 = builder.mul_mod(&e, &f, m);
    // Y3 = G * H
    let y3 = builder.mul_mod(&g, &h, m);
    // T3 = E * H
    let t3 = builder.mul_mod(&e, &h, m);
    // Z3 = F * G
    let z3 = builder.mul_mod(&f, &g, m);

    EdwardsPoint {
        x: x3,
        y: y3,
        t: t3,
        z: z3,
    }
}

/// Edwards 倍点（a = -1, 优化版）。
///
/// 公式：
/// - A = X1²
/// - B = Y1²
/// - C = 2 * Z1²
/// - D = -A  (即 p - A，因 a = -1)
/// - E = (X1+Y1)² - A - B
/// - G = D + B
/// - F = G - C
/// - H = D - B
/// - X3 = E * F
/// - Y3 = G * H
/// - T3 = E * H
/// - Z3 = F * G
///
/// 7 mul_mod ≈ 9800 约束。
pub(crate) fn point_double(builder: &mut NonNativeBuilder, p: &EdwardsPoint) -> EdwardsPoint {
    let m = &ED25519_P;

    // A = X1²
    let a = builder.mul_mod(&p.x, &p.x, m);
    // B = Y1²
    let b = builder.mul_mod(&p.y, &p.y, m);

    // Z1²
    let z1_sq = builder.mul_mod(&p.z, &p.z, m);
    // C = 2 * Z1²
    let c = builder.add_mod(&z1_sq, &z1_sq, m);

    // D = -A mod p = 0 - A mod p
    let zero = builder.from_u256(&[0, 0, 0, 0]);
    let d = builder.sub_mod(&zero, &a, m);

    // X1 + Y1
    let x1_plus_y1 = builder.add_mod(&p.x, &p.y, m);
    // (X1+Y1)²
    let x1_plus_y1_sq = builder.mul_mod(&x1_plus_y1, &x1_plus_y1, m);
    // E = (X1+Y1)² - A - B
    let tmp_e1 = builder.sub_mod(&x1_plus_y1_sq, &a, m);
    let e = builder.sub_mod(&tmp_e1, &b, m);

    // G = D + B
    let g = builder.add_mod(&d, &b, m);
    // F = G - C
    let f = builder.sub_mod(&g, &c, m);
    // H = D - B
    let h = builder.sub_mod(&d, &b, m);

    // X3 = E * F
    let x3 = builder.mul_mod(&e, &f, m);
    // Y3 = G * H
    let y3 = builder.mul_mod(&g, &h, m);
    // T3 = E * H
    let t3 = builder.mul_mod(&e, &h, m);
    // Z3 = F * G
    let z3 = builder.mul_mod(&f, &g, m);

    EdwardsPoint {
        x: x3,
        y: y3,
        t: t3,
        z: z3,
    }
}

/// 标量乘法：`scalar * P`，使用低 `num_bits` 位。
///
/// Double-and-add with "started" flag，避免 point_add 处理单位元。
pub(crate) fn scalar_mul(
    builder: &mut NonNativeBuilder,
    p: &EdwardsPoint,
    scalar: &NonNativeElement,
    num_bits: usize,
) -> EdwardsPoint {
    let scalar_u256 = builder.element_to_u256(scalar);

    // Bit 分解标量的低 num_bits 位
    let mut bit_vars = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        let bit_val = Fr::from_u64((scalar_u256[limb_idx] >> bit_idx) & 1);
        let bit_var = builder.alloc(bit_val);
        let row = builder.ccs.alloc_row();
        builder.ccs.add_bit_check(row, bit_var);
        bit_vars.push(bit_var);
    }

    // Recompose 约束：验证 bit 分解正确
    let num_full_limbs = num_bits / 64;
    let remaining_bits = num_bits % 64;

    for k in 0..num_full_limbs {
        let row = builder.ccs.alloc_row();
        let mut terms = Vec::with_capacity(65);
        for j in 0..64 {
            let bit_idx = k * 64 + j;
            let mut coeff = Fr::one();
            for _ in 0..j {
                coeff = coeff.double();
            }
            terms.push((bit_vars[bit_idx], coeff));
        }
        terms.push((scalar.limbs[k], Fr::one().neg()));
        builder.ccs.add_linear(row, &terms);
    }
    if remaining_bits > 0 {
        let k = num_full_limbs;
        let row = builder.ccs.alloc_row();
        let mut terms = Vec::with_capacity(remaining_bits + 1);
        for j in 0..remaining_bits {
            let bit_idx = k * 64 + j;
            let mut coeff = Fr::one();
            for _ in 0..j {
                coeff = coeff.double();
            }
            terms.push((bit_vars[bit_idx], coeff));
        }
        terms.push((scalar.limbs[k], Fr::one().neg()));
        builder.ccs.add_linear(row, &terms);
    }

    // Double-and-add
    let identity = identity_point(builder);

    let mut started_var = builder.alloc(Fr::zero());
    {
        let row = builder.ccs.alloc_row();
        builder.ccs.add_bit_check(row, started_var);
    }

    let mut r = identity.clone();

    for i in (0..num_bits).rev() {
        let bit_var = bit_vars[i];

        let double_r = point_double(builder, &r);
        let add_result = point_add(builder, &double_r, p);

        let not_started = select_point(builder, bit_var, p, &identity);
        let started_result = select_point(builder, bit_var, &add_result, &double_r);

        r = select_point(builder, started_var, &started_result, &not_started);

        // started_new = started OR bit = started + bit - started*bit
        let sb_val = builder.get_val(started_var).mul(&builder.get_val(bit_var));
        let sb_var = builder.alloc(sb_val);
        {
            let row = builder.ccs.alloc_row();
            builder
                .ccs
                .add_multiplication(row, started_var, bit_var, sb_var);
        }
        let started_new_val = builder
            .get_val(started_var)
            .add(&builder.get_val(bit_var))
            .sub(&sb_val);
        let started_new = builder.alloc(started_new_val);
        {
            let row = builder.ccs.alloc_row();
            builder.ccs.add_linear(
                row,
                &[
                    (started_var, Fr::one()),
                    (bit_var, Fr::one()),
                    (sb_var, Fr::one().neg()),
                    (started_new, Fr::one().neg()),
                ],
            );
        }
        started_var = started_new;
    }

    r
}

/// 断言点在曲线上：`-x² + y² = 1 + d·x²·y²`。
///
/// Extended 坐标下验证：`-X² + Y² = Z² + d·T²`
/// 即：`Y² + (-X²) - Z² - d·T² = 0`
pub(crate) fn assert_on_curve(builder: &mut NonNativeBuilder, p: &EdwardsPoint) {
    let m = &ED25519_P;

    // X²
    let x_sq = builder.mul_mod(&p.x, &p.x, m);
    // Y²
    let y_sq = builder.mul_mod(&p.y, &p.y, m);
    // Z²
    let z_sq = builder.mul_mod(&p.z, &p.z, m);
    // T²
    let t_sq = builder.mul_mod(&p.t, &p.t, m);

    // d * T²
    let d_elem = builder.from_u256(&ED25519_D);
    let d_t_sq = builder.mul_mod(&d_elem, &t_sq, m);

    // rhs = Z² + d*T²
    let rhs = builder.add_mod(&z_sq, &d_t_sq, m);

    // lhs = -X² + Y² (i.e., Y² - X²)
    let lhs = builder.sub_mod(&y_sq, &x_sq, m);

    // lhs == rhs
    builder.assert_equal(&lhs, &rhs);
}

/// 断言两个点相等：`X1*Z2 == X2*Z1 且 Y1*Z2 == Y2*Z1`。
pub(crate) fn assert_point_equal(
    builder: &mut NonNativeBuilder,
    p: &EdwardsPoint,
    q: &EdwardsPoint,
) {
    let m = &ED25519_P;

    // X1 * Z2
    let x1_z2 = builder.mul_mod(&p.x, &q.z, m);
    // X2 * Z1
    let x2_z1 = builder.mul_mod(&q.x, &p.z, m);
    builder.assert_equal(&x1_z2, &x2_z1);

    // Y1 * Z2
    let y1_z2 = builder.mul_mod(&p.y, &q.z, m);
    // Y2 * Z1
    let y2_z1 = builder.mul_mod(&q.y, &p.z, m);
    builder.assert_equal(&y1_z2, &y2_z1);
}

// ===== Ed25519VerifyCircuit =====

/// Ed25519 / Curve25519 预编译电路。
///
/// 双模式：
/// - MVP（`new()`）：单点加法验证（P1 + P2 = P3）
/// - Full（`new_full()`）：标量乘法（scalar · P = result）
#[derive(Debug, Clone)]
pub struct Ed25519VerifyCircuit {
    /// 是否为完整模式。
    full_mode: bool,
    /// Full 模式下标量乘法使用的比特数（截断到低位）。
    scalar_num_bits: usize,
}

impl Ed25519VerifyCircuit {
    /// 创建 Full 模式电路（252-bit 完整标量乘法）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            full_mode: true,
            scalar_num_bits: 252,
        }
    }

    /// 创建 MVP 模式电路（单点加法验证，用于快速测试）。
    #[must_use]
    pub fn new_mvp() -> Self {
        Self {
            full_mode: false,
            scalar_num_bits: 0,
        }
    }

    /// 创建 Full 模式电路，默认 252-bit 完整标量。
    #[must_use]
    pub fn new_full() -> Self {
        Self {
            full_mode: true,
            scalar_num_bits: 252,
        }
    }

    /// 创建 Full 模式电路，自定义标量比特数。
    #[must_use]
    pub fn new_full_with_bits(n: usize) -> Self {
        Self {
            full_mode: true,
            scalar_num_bits: n,
        }
    }

    /// 是否为 Full 模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    /// Full 模式下标量比特数。
    #[must_use]
    pub fn scalar_num_bits(&self) -> usize {
        self.scalar_num_bits
    }

    /// 运行 MVP 模式：验证 P1 + P2 = P3。
    ///
    /// 输入 24 个 Fr：`[P1_x(4), P1_y(4), P2_x(4), P2_y(4), P3_x(4), P3_y(4)]`
    pub fn run_mvp(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 24 {
            return Err(ZkvmError::Other(format!(
                "Ed25519VerifyCircuit::run_mvp: inputs.len() {} != 24（需要 P1/P2/P3 各 4+4 limbs）",
                inputs.len()
            )));
        }

        let mut builder = NonNativeBuilder::new();

        let p1_x = [inputs[0], inputs[1], inputs[2], inputs[3]];
        let p1_y = [inputs[4], inputs[5], inputs[6], inputs[7]];
        let p2_x = [inputs[8], inputs[9], inputs[10], inputs[11]];
        let p2_y = [inputs[12], inputs[13], inputs[14], inputs[15]];
        let p3_x = [inputs[16], inputs[17], inputs[18], inputs[19]];
        let p3_y = [inputs[20], inputs[21], inputs[22], inputs[23]];

        let p1 = from_affine(
            &mut builder,
            &fr_limbs_to_u256(&p1_x),
            &fr_limbs_to_u256(&p1_y),
        );
        let p2 = from_affine(
            &mut builder,
            &fr_limbs_to_u256(&p2_x),
            &fr_limbs_to_u256(&p2_y),
        );
        let p3 = from_affine(
            &mut builder,
            &fr_limbs_to_u256(&p3_x),
            &fr_limbs_to_u256(&p3_y),
        );

        // P1 + P2
        let sum = point_add(&mut builder, &p1, &p2);

        // assert sum == P3
        assert_point_equal(&mut builder, &sum, &p3);

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }

    /// 运行 Full 模式：验证 scalar · P = result。
    ///
    /// 输入 20 个 Fr：`[P_x(4), P_y(4), scalar(4), result_x(4), result_y(4)]`
    pub fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 20 {
            return Err(ZkvmError::Other(format!(
                "Ed25519VerifyCircuit::run_full: inputs.len() {} != 20（需要 P/scalar/result 共 5×4 limbs）",
                inputs.len()
            )));
        }

        let mut builder = NonNativeBuilder::new();

        let p_x = [inputs[0], inputs[1], inputs[2], inputs[3]];
        let p_y = [inputs[4], inputs[5], inputs[6], inputs[7]];
        let sc = [inputs[8], inputs[9], inputs[10], inputs[11]];
        let r_x = [inputs[12], inputs[13], inputs[14], inputs[15]];
        let r_y = [inputs[16], inputs[17], inputs[18], inputs[19]];

        let p = from_affine(
            &mut builder,
            &fr_limbs_to_u256(&p_x),
            &fr_limbs_to_u256(&p_y),
        );
        let scalar_elem = builder.alloc_element(sc);
        let result = from_affine(
            &mut builder,
            &fr_limbs_to_u256(&r_x),
            &fr_limbs_to_u256(&r_y),
        );

        let computed = scalar_mul(&mut builder, &p, &scalar_elem, self.scalar_num_bits);

        assert_point_equal(&mut builder, &computed, &result);

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }
}

impl Default for Ed25519VerifyCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for Ed25519VerifyCircuit {
    fn name(&self) -> &str {
        "ed25519"
    }

    fn num_variables(&self) -> usize {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 20];
            self.run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0
                .num_vars
        } else {
            6
        }
    }

    fn build_ccs(&self) -> Result<Ccs, ZkvmError> {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 20];
            return Ok(self
                .run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0);
        }

        // MVP: 7 个行隔离矩阵（同 ecdsa MVP 模式）
        // z = [1, bit, P, P2, bit_P, P_new]（每个是抽象的 6 个变量位置）
        // 约束：
        // - row 0: bit - bit*bit = 0
        // - row 1: bit*P - bit_P = 0
        // - row 2: P2 + bit_P - P_new = 0

        let mut m_bit_r0 = SparseMatrix::new(3, 6);
        m_bit_r0.add_entry(0, 1, Fr::one()).expect("M_bit_r0");

        let mut m_bit_r1 = SparseMatrix::new(3, 6);
        m_bit_r1.add_entry(1, 1, Fr::one()).expect("M_bit_r1");

        let mut m_p_r1 = SparseMatrix::new(3, 6);
        m_p_r1.add_entry(1, 2, Fr::one()).expect("M_P_r1");

        let mut m_bitp_r1 = SparseMatrix::new(3, 6);
        m_bitp_r1.add_entry(1, 3, Fr::one()).expect("M_bitP_r1");

        let mut m_p2_r2 = SparseMatrix::new(3, 6);
        m_p2_r2.add_entry(2, 2, Fr::one()).expect("M_P2_r2");

        let mut m_bitp_r2 = SparseMatrix::new(3, 6);
        m_bitp_r2.add_entry(2, 3, Fr::one()).expect("M_bitP_r2");

        let mut m_pnew_r2 = SparseMatrix::new(3, 6);
        m_pnew_r2.add_entry(2, 5, Fr::one()).expect("M_Pnew_r2");

        let neg_one = Fr::zero().sub(&Fr::one());

        Ok(Ccs::new(
            6,
            vec![
                m_bit_r0, m_bit_r1, m_p_r1, m_bitp_r1, m_p2_r2, m_bitp_r2, m_pnew_r2,
            ],
            vec![
                vec![0],    // S_0: +bit
                vec![0, 0], // S_1: -bit*bit
                vec![1, 2], // S_2: +bit*P
                vec![3],    // S_3: -bit_P
                vec![4],    // S_4: +P2
                vec![5],    // S_5: +bit_P
                vec![6],    // S_6: -P_new
            ],
            vec![
                Fr::one(),
                neg_one,
                Fr::one(),
                neg_one,
                Fr::one(),
                Fr::one(),
                neg_one,
            ],
        )
        .expect("Ed25519VerifyCircuit CCS 构造应成功"))
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            return Ok(self.run_full(inputs)?.1);
        }

        if inputs.len() != 3 {
            return Err(ZkvmError::Other(format!(
                "Ed25519VerifyCircuit::assign_witness: inputs.len() {} != 3（需要 bit, P, P2）",
                inputs.len()
            )));
        }
        let bit = inputs[0];
        let p = inputs[1];
        let p2 = inputs[2];

        let bit_p = bit.mul(&p);
        let p_new = p2.add(&bit_p);

        Ok(vec![Fr::one(), bit, p, p2, bit_p, p_new])
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            GAS_ED25519_BASE + GAS_ED25519_PER_BIT * self.scalar_num_bits as u64
        } else {
            GAS_ED25519_BASE
        }
    }
}

impl CcsCircuit for Ed25519VerifyCircuit {
    fn name(&self) -> &str {
        "ed25519"
    }

    fn num_matrices(&self) -> usize {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 20];
            self.run_full(&dummy)
                .expect("dummy run_full should succeed")
                .0
                .num_matrices()
        } else {
            7
        }
    }

    fn to_ccs_instance(
        &self,
        witness: &[Fr],
        public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError> {
        let ccs = self.build_ccs()?;
        CcsInstance::new(ccs, witness.to_vec(), public_inputs.to_vec())
    }
}

// ===== 辅助函数 =====

fn fr_limbs_to_u256(limbs: &[Fr; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for i in 0..4 {
        let bytes = limbs[i].to_canonical_bytes();
        result[i] = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
    }
    result
}

fn u256_to_fr_vec(val: &[u64; 4]) -> Vec<Fr> {
    vec![
        Fr::from_u64(val[0]),
        Fr::from_u64(val[1]),
        Fr::from_u64(val[2]),
        Fr::from_u64(val[3]),
    ]
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::PrecompileRegistry;
    use crate::precompiles::non_native::{host_add_mod, host_inv_mod, host_mul_mod, host_sub_mod};

    type HostPoint = ([u64; 4], [u64; 4], [u64; 4], [u64; 4]); // (X, Y, T, Z) Extended

    fn host_from_affine(x: &[u64; 4], y: &[u64; 4]) -> HostPoint {
        let t = host_mul_mod(x, y, &ED25519_P);
        (*x, *y, t, [1, 0, 0, 0])
    }

    fn host_point_add(p: &HostPoint, q: &HostPoint) -> HostPoint {
        let m = &ED25519_P;

        let y1_minus_x1 = host_sub_mod(&p.1, &p.0, m);
        let y2_minus_x2 = host_sub_mod(&q.1, &q.0, m);
        let a = host_mul_mod(&y1_minus_x1, &y2_minus_x2, m);

        let y1_plus_x1 = host_add_mod(&p.1, &p.0, m);
        let y2_plus_x2 = host_add_mod(&q.1, &q.0, m);
        let b = host_mul_mod(&y1_plus_x1, &y2_plus_x2, m);

        let t1_t2 = host_mul_mod(&p.2, &q.2, m);
        let c = host_mul_mod(&ED25519_TWO_D, &t1_t2, m);

        let z1_z2 = host_mul_mod(&p.3, &q.3, m);
        let d = host_add_mod(&z1_z2, &z1_z2, m);

        let e = host_sub_mod(&b, &a, m);
        let f = host_sub_mod(&d, &c, m);
        let g = host_add_mod(&d, &c, m);
        let h = host_add_mod(&b, &a, m);

        let x3 = host_mul_mod(&e, &f, m);
        let y3 = host_mul_mod(&g, &h, m);
        let t3 = host_mul_mod(&e, &h, m);
        let z3 = host_mul_mod(&f, &g, m);

        (x3, y3, t3, z3)
    }

    fn host_point_double(p: &HostPoint) -> HostPoint {
        let m = &ED25519_P;

        let a = host_mul_mod(&p.0, &p.0, m);
        let b = host_mul_mod(&p.1, &p.1, m);

        let z1_sq = host_mul_mod(&p.3, &p.3, m);
        let c = host_add_mod(&z1_sq, &z1_sq, m);

        let d = host_sub_mod(&ED25519_P, &a, m);

        let x1_plus_y1 = host_add_mod(&p.0, &p.1, m);
        let x1_plus_y1_sq = host_mul_mod(&x1_plus_y1, &x1_plus_y1, m);
        let tmp_e1 = host_sub_mod(&x1_plus_y1_sq, &a, m);
        let e = host_sub_mod(&tmp_e1, &b, m);

        let g = host_add_mod(&d, &b, m);
        let f = host_sub_mod(&g, &c, m);
        let h = host_sub_mod(&d, &b, m);

        let x3 = host_mul_mod(&e, &f, m);
        let y3 = host_mul_mod(&g, &h, m);
        let t3 = host_mul_mod(&e, &h, m);
        let z3 = host_mul_mod(&f, &g, m);

        (x3, y3, t3, z3)
    }

    fn host_scalar_mul(p: &HostPoint, scalar: &[u64; 4], num_bits: usize) -> HostPoint {
        let mut result = ([0, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0], [1, 0, 0, 0]); // identity
        let mut started = false;
        for i in (0..num_bits).rev() {
            let limb = i / 64;
            let bit = i % 64;
            let bit_val = (scalar[limb] >> bit) & 1;
            result = host_point_double(&result);
            if bit_val == 1 {
                if started {
                    result = host_point_add(&result, p);
                } else {
                    result = *p;
                    started = true;
                }
            }
        }
        result
    }

    fn host_to_affine(p: &HostPoint) -> ([u64; 4], [u64; 4]) {
        let m = &ED25519_P;
        let z_inv = host_inv_mod(&p.3, m);
        let x = host_mul_mod(&p.0, &z_inv, m);
        let y = host_mul_mod(&p.1, &z_inv, m);
        (x, y)
    }

    #[test]
    fn test_edwards_point_add_basic() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        let b2_add = host_point_add(&b, &b);
        let (x, y) = host_to_affine(&b2_add);
        // 验证在曲线上：-x² + y² = 1 + d*x²*y²
        let m = &ED25519_P;
        let x2 = host_mul_mod(&x, &x, m);
        let y2 = host_mul_mod(&y, &y, m);
        let lhs = host_sub_mod(&y2, &x2, m);
        let d_x2_y2 = host_mul_mod(&ED25519_D, &host_mul_mod(&x2, &y2, m), m);
        let one = [1, 0, 0, 0];
        let rhs = host_add_mod(&one, &d_x2_y2, m);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_point_double_identity_circuit() {
        let mut builder = NonNativeBuilder::new();
        let identity = identity_point(&mut builder);
        let doubled = point_double(&mut builder, &identity);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "point_double(identity) should be satisfied"
        );

        let x = fr_limbs_to_u256(&[
            witness[doubled.x.limbs[0]],
            witness[doubled.x.limbs[1]],
            witness[doubled.x.limbs[2]],
            witness[doubled.x.limbs[3]],
        ]);
        let y = fr_limbs_to_u256(&[
            witness[doubled.y.limbs[0]],
            witness[doubled.y.limbs[1]],
            witness[doubled.y.limbs[2]],
            witness[doubled.y.limbs[3]],
        ]);
        let z = fr_limbs_to_u256(&[
            witness[doubled.z.limbs[0]],
            witness[doubled.z.limbs[1]],
            witness[doubled.z.limbs[2]],
            witness[doubled.z.limbs[3]],
        ]);

        let z_inv = host_inv_mod(&z, &ED25519_P);
        let x_affine = host_mul_mod(&x, &z_inv, &ED25519_P);
        let y_affine = host_mul_mod(&y, &z_inv, &ED25519_P);

        assert_eq!(x_affine, [0, 0, 0, 0], "identity x should be 0");
        assert_eq!(y_affine, [1, 0, 0, 0], "identity y should be 1");
    }

    #[test]
    fn test_edwards_scalar_mul_circuit_1bit() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        let result_host = host_scalar_mul(&b, &[1, 0, 0, 0], 2);
        let (x_host, y_host) = host_to_affine(&result_host);

        let mut builder = NonNativeBuilder::new();
        let b_circuit = from_affine(&mut builder, &ED25519_BX, &ED25519_BY);
        let scalar = builder.from_u256(&[1, 0, 0, 0]);
        let result_circuit = scalar_mul(&mut builder, &b_circuit, &scalar, 2);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "scalar_mul(1) circuit should be satisfied"
        );

        let x_circuit = fr_limbs_to_u256(&[
            witness[result_circuit.x.limbs[0]],
            witness[result_circuit.x.limbs[1]],
            witness[result_circuit.x.limbs[2]],
            witness[result_circuit.x.limbs[3]],
        ]);
        let y_circuit = fr_limbs_to_u256(&[
            witness[result_circuit.y.limbs[0]],
            witness[result_circuit.y.limbs[1]],
            witness[result_circuit.y.limbs[2]],
            witness[result_circuit.y.limbs[3]],
        ]);
        let z_circuit = fr_limbs_to_u256(&[
            witness[result_circuit.z.limbs[0]],
            witness[result_circuit.z.limbs[1]],
            witness[result_circuit.z.limbs[2]],
            witness[result_circuit.z.limbs[3]],
        ]);

        let z_inv = host_inv_mod(&z_circuit, &ED25519_P);
        let x_affine = host_mul_mod(&x_circuit, &z_inv, &ED25519_P);
        let y_affine = host_mul_mod(&y_circuit, &z_inv, &ED25519_P);

        assert_eq!(x_affine, x_host, "x coordinate mismatch");
        assert_eq!(y_affine, y_host, "y coordinate mismatch");
    }

    #[test]
    fn test_edwards_scalar_mul_circuit_3bit() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        let result_host = host_scalar_mul(&b, &[3, 0, 0, 0], 4);
        let (x_host, y_host) = host_to_affine(&result_host);

        let mut builder = NonNativeBuilder::new();
        let b_circuit = from_affine(&mut builder, &ED25519_BX, &ED25519_BY);
        let scalar = builder.from_u256(&[3, 0, 0, 0]);
        let result_circuit = scalar_mul(&mut builder, &b_circuit, &scalar, 4);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "scalar_mul circuit should be satisfied"
        );

        let x_circuit = fr_limbs_to_u256(&[
            witness[result_circuit.x.limbs[0]],
            witness[result_circuit.x.limbs[1]],
            witness[result_circuit.x.limbs[2]],
            witness[result_circuit.x.limbs[3]],
        ]);
        let y_circuit = fr_limbs_to_u256(&[
            witness[result_circuit.y.limbs[0]],
            witness[result_circuit.y.limbs[1]],
            witness[result_circuit.y.limbs[2]],
            witness[result_circuit.y.limbs[3]],
        ]);
        let z_circuit = fr_limbs_to_u256(&[
            witness[result_circuit.z.limbs[0]],
            witness[result_circuit.z.limbs[1]],
            witness[result_circuit.z.limbs[2]],
            witness[result_circuit.z.limbs[3]],
        ]);

        let z_inv = host_inv_mod(&z_circuit, &ED25519_P);
        let x_affine = host_mul_mod(&x_circuit, &z_inv, &ED25519_P);
        let y_affine = host_mul_mod(&y_circuit, &z_inv, &ED25519_P);

        assert_eq!(x_affine, x_host, "x coordinate mismatch");
        assert_eq!(y_affine, y_host, "y coordinate mismatch");
    }

    #[test]
    fn test_edwards_point_add_circuit() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        let b2_host = host_point_add(&b, &b);
        let (x2_host, y2_host) = host_to_affine(&b2_host);

        let mut builder = NonNativeBuilder::new();
        let b1 = from_affine(&mut builder, &ED25519_BX, &ED25519_BY);
        let b2 = from_affine(&mut builder, &ED25519_BX, &ED25519_BY);
        let result = point_add(&mut builder, &b1, &b2);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "point_add circuit should be satisfied"
        );

        let x_circuit = fr_limbs_to_u256(&[
            witness[result.x.limbs[0]],
            witness[result.x.limbs[1]],
            witness[result.x.limbs[2]],
            witness[result.x.limbs[3]],
        ]);
        let y_circuit = fr_limbs_to_u256(&[
            witness[result.y.limbs[0]],
            witness[result.y.limbs[1]],
            witness[result.y.limbs[2]],
            witness[result.y.limbs[3]],
        ]);
        let z_circuit = fr_limbs_to_u256(&[
            witness[result.z.limbs[0]],
            witness[result.z.limbs[1]],
            witness[result.z.limbs[2]],
            witness[result.z.limbs[3]],
        ]);

        let z_inv = host_inv_mod(&z_circuit, &ED25519_P);
        let x_affine = host_mul_mod(&x_circuit, &z_inv, &ED25519_P);
        let y_affine = host_mul_mod(&y_circuit, &z_inv, &ED25519_P);

        assert_eq!(x_affine, x2_host, "x coordinate mismatch");
        assert_eq!(y_affine, y2_host, "y coordinate mismatch");
    }

    #[test]
    fn test_edwards_point_double_circuit() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        let b2_host = host_point_double(&b);
        let (x2_host, y2_host) = host_to_affine(&b2_host);

        let mut builder = NonNativeBuilder::new();
        let b_circuit = from_affine(&mut builder, &ED25519_BX, &ED25519_BY);
        let b2_circuit = point_double(&mut builder, &b_circuit);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "point_double circuit should be satisfied"
        );

        let x2_circuit = fr_limbs_to_u256(&[
            witness[b2_circuit.x.limbs[0]],
            witness[b2_circuit.x.limbs[1]],
            witness[b2_circuit.x.limbs[2]],
            witness[b2_circuit.x.limbs[3]],
        ]);
        let y2_circuit = fr_limbs_to_u256(&[
            witness[b2_circuit.y.limbs[0]],
            witness[b2_circuit.y.limbs[1]],
            witness[b2_circuit.y.limbs[2]],
            witness[b2_circuit.y.limbs[3]],
        ]);
        let z2_circuit = fr_limbs_to_u256(&[
            witness[b2_circuit.z.limbs[0]],
            witness[b2_circuit.z.limbs[1]],
            witness[b2_circuit.z.limbs[2]],
            witness[b2_circuit.z.limbs[3]],
        ]);

        let z_inv = host_inv_mod(&z2_circuit, &ED25519_P);
        let x_affine = host_mul_mod(&x2_circuit, &z_inv, &ED25519_P);
        let y_affine = host_mul_mod(&y2_circuit, &z_inv, &ED25519_P);

        assert_eq!(x_affine, x2_host, "x coordinate mismatch");
        assert_eq!(y_affine, y2_host, "y coordinate mismatch");
    }

    #[test]
    fn test_edwards_point_double() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        let b2_dbl = host_point_double(&b);
        let b2_add = host_point_add(&b, &b);
        let (x_d, y_d) = host_to_affine(&b2_dbl);
        let (x_a, y_a) = host_to_affine(&b2_add);
        assert_eq!(x_d, x_a);
        assert_eq!(y_d, y_a);
    }

    #[test]
    fn test_edwards_scalar_mul_small() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        // 3*B = B + B + B
        let b2 = host_point_add(&b, &b);
        let b3_manual = host_point_add(&b2, &b);
        let b3_scalar = host_scalar_mul(&b, &[3, 0, 0, 0], 4);
        let (x1, y1) = host_to_affine(&b3_manual);
        let (x2, y2) = host_to_affine(&b3_scalar);
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_ed25519_mvp_single_add() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        let b2 = host_point_add(&b, &b);
        let (x2, y2) = host_to_affine(&b2);

        let mut inputs = Vec::new();
        inputs.extend(u256_to_fr_vec(&ED25519_BX));
        inputs.extend(u256_to_fr_vec(&ED25519_BY));
        inputs.extend(u256_to_fr_vec(&ED25519_BX));
        inputs.extend(u256_to_fr_vec(&ED25519_BY));
        inputs.extend(u256_to_fr_vec(&x2));
        inputs.extend(u256_to_fr_vec(&y2));

        let circuit = Ed25519VerifyCircuit::new_mvp();
        let (ccs, witness) = circuit.run_mvp(&inputs).expect("run_mvp ok");
        assert!(ccs.num_rows() > 1000);
        let instance = CcsInstance::new(ccs, witness, vec![]).expect("instance");
        assert!(instance.is_satisfied().expect("is_satisfied"));
    }

    #[test]
    fn test_ed25519_full_scalar_mul_8bit() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        let k = [42, 0, 0, 0];
        let result = host_scalar_mul(&b, &k, 8);
        let (rx, ry) = host_to_affine(&result);

        let mut inputs = Vec::new();
        inputs.extend(u256_to_fr_vec(&ED25519_BX));
        inputs.extend(u256_to_fr_vec(&ED25519_BY));
        inputs.extend(u256_to_fr_vec(&k));
        inputs.extend(u256_to_fr_vec(&rx));
        inputs.extend(u256_to_fr_vec(&ry));

        let circuit = Ed25519VerifyCircuit::new_full_with_bits(8);
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full ok");
        assert!(ccs.num_rows() > 5000);
        let instance = CcsInstance::new(ccs, witness, vec![]).expect("instance");
        assert!(instance.is_satisfied().expect("is_satisfied"));
    }

    #[test]
    fn test_ed25519_gas_cost() {
        let mvp = Ed25519VerifyCircuit::new_mvp();
        assert_eq!(mvp.gas_cost(), 50_000);

        let full_8 = Ed25519VerifyCircuit::new_full_with_bits(8);
        assert_eq!(full_8.gas_cost(), 50_000 + 8_000 * 8); // 114_000

        let full_252 = Ed25519VerifyCircuit::new_full();
        assert_eq!(full_252.gas_cost(), 50_000 + 8_000 * 252); // 2_066_000
    }

    #[test]
    fn test_ed25519_wrong_input_length() {
        let circuit = Ed25519VerifyCircuit::new_mvp();
        assert!(circuit.run_mvp(&[Fr::zero(); 23]).is_err());
        assert!(circuit.run_mvp(&[Fr::zero(); 25]).is_err());

        let full = Ed25519VerifyCircuit::new_full_with_bits(4);
        assert!(full.run_full(&[Fr::zero(); 19]).is_err());
        assert!(full.run_full(&[Fr::zero(); 21]).is_err());
    }

    #[test]
    #[ignore]
    fn test_ed25519_full_252bit() {
        let b = host_from_affine(&ED25519_BX, &ED25519_BY);
        // k = 2^250 + 1234567
        let k: [u64; 4] = [
            0x0000_0000_0012_D687,
            0x0000_0000_0000_0000,
            0x0000_0000_0000_0000,
            0x0400_0000_0000_0000,
        ];
        let result = host_scalar_mul(&b, &k, 252);
        let (rx, ry) = host_to_affine(&result);

        let mut inputs = Vec::new();
        inputs.extend(u256_to_fr_vec(&ED25519_BX));
        inputs.extend(u256_to_fr_vec(&ED25519_BY));
        inputs.extend(u256_to_fr_vec(&k));
        inputs.extend(u256_to_fr_vec(&rx));
        inputs.extend(u256_to_fr_vec(&ry));

        let circuit = Ed25519VerifyCircuit::new_full();
        let (ccs, witness) = circuit.run_full(&inputs).expect("run_full ok");
        let instance = CcsInstance::new(ccs, witness, vec![]).expect("instance");
        assert!(instance.is_satisfied().expect("is_satisfied"));
    }

    #[test]
    fn test_ed25519_registers_in_precompile_registry() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(Ed25519VerifyCircuit::new_mvp()));
        let found = registry.get("ed25519");
        assert!(found.is_some());
        assert_eq!(found.unwrap().gas_cost(), 50_000);
    }
}
