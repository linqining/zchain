//! BN254 G1 点运算电路（Phase J — J-1）。
//!
//! 在 BN254 Fr 上使用非原生域算术模拟 BN254 G1 的 Jacobian 坐标点运算。
//!
//! # 坐标系
//!
//! 使用 Jacobian 投影坐标 (X:Y:Z)，仿射坐标 (x,y) = (X/Z², Y/Z³)。
//! 无穷远点（单位元）= (1:1:0)。
//!
//! BN254 G1 曲线: y² = x³ + 3 (a=0, b=3)
//!
//! # 约束计数
//!
//! | 操作 | mul_mod 数 | 约束数（行数） |
//! |------|-----------|----------------|
//! | point_double | ~6 | ~8400 |
//! | point_add | ~12 | ~16800 |
//! | scalar_mul (n bits) | ~n*18 | ~n*25200 |
//! | assert_on_curve | ~6 | ~8400 |
//! | assert_point_equal | ~4 | ~5600 |
//! | assert_g1_on_curve (affine) | ~3 | ~4300 |

#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]

use crate::ccs::Fr;
use crate::field::ZkvmField;
use crate::precompiles::non_native::{
    NonNativeBuilder, NonNativeElement, host_add_mod, host_inv_mod, host_mul_mod, host_sub_mod,
};

// ===== BN254 常量（[u64; 4] little-endian）=====

/// BN254 基域 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583。
pub const BN254_P: [u64; 4] = [
    0x3C20_8C16_D87C_FD47,
    0x9781_6A91_6871_CA8D,
    0xB850_45B6_8181_585D,
    0x3064_4E72_E131_A029,
];

/// G1 曲线参数 b = 3。
pub const BN254_B: [u64; 4] = [3, 0, 0, 0];

/// BN254 G1 生成元 x = 1。
pub const BN254_G1_X: [u64; 4] = [1, 0, 0, 0];

/// BN254 G1 生成元 y = 2。
pub const BN254_G1_Y: [u64; 4] = [2, 0, 0, 0];

// ===== Point 结构 =====

/// BN254 G1 Jacobian 投影坐标点。
#[derive(Clone)]
pub(crate) struct Point {
    pub x: NonNativeElement,
    pub y: NonNativeElement,
    pub z: NonNativeElement,
}

// ===== 辅助：条件选择 =====

/// 条件选择两个 Fr 值：result = if_zero + bit * (if_one - if_zero)。
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

/// 条件选择两个 NonNativeElement：result = bit ? if_one : if_zero。
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

/// 条件选择两个 Point：result = bit ? if_one : if_zero。
fn select_point(
    builder: &mut NonNativeBuilder,
    bit: usize,
    if_one: &Point,
    if_zero: &Point,
) -> Point {
    Point {
        x: select_element(builder, bit, &if_one.x, &if_zero.x),
        y: select_element(builder, bit, &if_one.y, &if_zero.y),
        z: select_element(builder, bit, &if_one.z, &if_zero.z),
    }
}

// ===== 点运算 =====

/// 创建无穷远点（单位元）= (1:1:0)。
pub(crate) fn identity_point(builder: &mut NonNativeBuilder) -> Point {
    Point {
        x: builder.from_u256(&[1, 0, 0, 0]),
        y: builder.from_u256(&[1, 0, 0, 0]),
        z: builder.from_u256(&[0, 0, 0, 0]),
    }
}

/// 从仿射坐标 (x, y) 创建点 (x:y:1)。
pub(crate) fn from_affine(builder: &mut NonNativeBuilder, x: &[u64; 4], y: &[u64; 4]) -> Point {
    Point {
        x: builder.from_u256(x),
        y: builder.from_u256(y),
        z: builder.from_u256(&[1, 0, 0, 0]),
    }
}

/// Jacobian 倍点：2P。
///
/// BN254 (a=0) 倍点公式（同 secp256k1，仅 b 不同但倍点不涉及 b）：
/// - A = X², B = Y², C = B² (Y⁴)
/// - D = 2*((X+B)² - A - C)
/// - E = 3*A
/// - F = E²
/// - X3 = F - 2*D
/// - Y3 = E*(D - X3) - 8*C
/// - Z3 = 2*Y*Z
pub(crate) fn point_double(builder: &mut NonNativeBuilder, p: &Point) -> Point {
    let m = &BN254_P;

    let a = builder.mul_mod(&p.x, &p.x, m);
    let b = builder.mul_mod(&p.y, &p.y, m);
    let c = builder.mul_mod(&b, &b, m);

    let xb = builder.add_mod(&p.x, &b, m);
    let xb2 = builder.mul_mod(&xb, &xb, m);
    let tmp1 = builder.sub_mod(&xb2, &a, m);
    let tmp2 = builder.sub_mod(&tmp1, &c, m);
    let d = builder.add_mod(&tmp2, &tmp2, m);

    let e = builder.add_mod(&a, &a, m);
    let e = builder.add_mod(&e, &a, m);

    let f = builder.mul_mod(&e, &e, m);

    let two_d = builder.add_mod(&d, &d, m);
    let x3 = builder.sub_mod(&f, &two_d, m);

    let d_minus_x3 = builder.sub_mod(&d, &x3, m);
    let e_dm = builder.mul_mod(&e, &d_minus_x3, m);
    let two_c = builder.add_mod(&c, &c, m);
    let four_c = builder.add_mod(&two_c, &two_c, m);
    let eight_c = builder.add_mod(&four_c, &four_c, m);
    let y3 = builder.sub_mod(&e_dm, &eight_c, m);

    let two_y = builder.add_mod(&p.y, &p.y, m);
    let z3 = builder.mul_mod(&two_y, &p.z, m);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Jacobian 点加法：P + Q（假设 P ≠ ±Q，两者均非无穷远点）。
///
/// EFD add-1998-cmo-2，H = U1 - U2（符号修正同 secp256k1_ops）：
/// - U1 = X1*Z2², S1 = Y1*Z2³
/// - U2 = X2*Z1², S2 = Y2*Z1³
/// - H = U1 - U2, H2 = H², H3 = H*H2
/// - r = S1 - S2
/// - V = U1*H2
/// - X3 = r² + H3 - 2*V
/// - Y3 = r*(V - X3) - S1*H3
/// - Z3 = Z1*Z2*H
pub(crate) fn point_add(builder: &mut NonNativeBuilder, p: &Point, q: &Point) -> Point {
    let m = &BN254_P;

    let z2_sq = builder.mul_mod(&q.z, &q.z, m);
    let z2_cu = builder.mul_mod(&z2_sq, &q.z, m);

    let z1_sq = builder.mul_mod(&p.z, &p.z, m);
    let z1_cu = builder.mul_mod(&z1_sq, &p.z, m);

    let u1 = builder.mul_mod(&p.x, &z2_sq, m);
    let s1 = builder.mul_mod(&p.y, &z2_cu, m);

    let u2 = builder.mul_mod(&q.x, &z1_sq, m);
    let s2 = builder.mul_mod(&q.y, &z1_cu, m);

    let h = builder.sub_mod(&u1, &u2, m);
    let h2 = builder.mul_mod(&h, &h, m);
    let h3 = builder.mul_mod(&h, &h2, m);

    let r = builder.sub_mod(&s1, &s2, m);

    let v = builder.mul_mod(&u1, &h2, m);

    let r_sq = builder.mul_mod(&r, &r, m);
    let two_v = builder.add_mod(&v, &v, m);
    let x3_tmp = builder.add_mod(&r_sq, &h3, m);
    let x3 = builder.sub_mod(&x3_tmp, &two_v, m);

    let v_minus_x3 = builder.sub_mod(&v, &x3, m);
    let r_vx = builder.mul_mod(&r, &v_minus_x3, m);
    let s1_h3 = builder.mul_mod(&s1, &h3, m);
    let y3 = builder.sub_mod(&r_vx, &s1_h3, m);

    let z1z2 = builder.mul_mod(&p.z, &q.z, m);
    let z3 = builder.mul_mod(&z1z2, &h, m);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// 标量乘法：scalar * P（Double-and-add with "started" flag）。
pub(crate) fn scalar_mul(
    builder: &mut NonNativeBuilder,
    p: &Point,
    scalar: &NonNativeElement,
    num_bits: usize,
) -> Point {
    let scalar_u256 = builder.element_to_u256(scalar);

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

    let num_full_limbs = num_bits / 64;
    let remaining_bits = num_bits % 64;

    for k in 0..num_full_limbs {
        let row = builder.ccs.alloc_row();
        let mut terms = Vec::with_capacity(65);
        for j in 0..64 {
            let bit_idx = k * 64 + j;
            let coeff = {
                let mut v = Fr::one();
                for _ in 0..j {
                    v = v.double();
                }
                v
            };
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
            let coeff = {
                let mut v = Fr::one();
                for _ in 0..j {
                    v = v.double();
                }
                v
            };
            terms.push((bit_vars[bit_idx], coeff));
        }
        terms.push((scalar.limbs[k], Fr::one().neg()));
        builder.ccs.add_linear(row, &terms);
    }

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

/// 断言 Jacobian 点在曲线上：Y² = X³ + 3*Z⁶ (mod p)。
pub(crate) fn assert_on_curve(builder: &mut NonNativeBuilder, p: &Point) {
    let m = &BN254_P;

    let y_sq = builder.mul_mod(&p.y, &p.y, m);

    let x_sq = builder.mul_mod(&p.x, &p.x, m);
    let x_cu = builder.mul_mod(&x_sq, &p.x, m);

    let z_sq = builder.mul_mod(&p.z, &p.z, m);
    let z_four = builder.mul_mod(&z_sq, &z_sq, m);
    let z_six = builder.mul_mod(&z_sq, &z_four, m);

    let b_elem = builder.from_u256(&BN254_B);
    let b_z6 = builder.mul_mod(&b_elem, &z_six, m);

    let rhs = builder.add_mod(&x_cu, &b_z6, m);

    builder.assert_equal(&y_sq, &rhs);
}

/// 断言两个点相等（Jacobian）：X1*Z2² == X2*Z1² 且 Y1*Z2³ == Y2*Z1³。
pub(crate) fn assert_point_equal(builder: &mut NonNativeBuilder, p: &Point, q: &Point) {
    let m = &BN254_P;

    let z1_sq = builder.mul_mod(&p.z, &p.z, m);
    let z2_sq = builder.mul_mod(&q.z, &q.z, m);
    let z1_cu = builder.mul_mod(&z1_sq, &p.z, m);
    let z2_cu = builder.mul_mod(&z2_sq, &q.z, m);

    let lhs_x = builder.mul_mod(&p.x, &z2_sq, m);
    let rhs_x = builder.mul_mod(&q.x, &z1_sq, m);
    builder.assert_equal(&lhs_x, &rhs_x);

    let lhs_y = builder.mul_mod(&p.y, &z2_cu, m);
    let rhs_y = builder.mul_mod(&q.y, &z1_cu, m);
    builder.assert_equal(&lhs_y, &rhs_y);
}

// ===== Affine on-curve 检查 =====

/// 验证仿射 G1 点在曲线上：`y² = x³ + b (mod p)`。
///
/// 约 3 mul_mod ≈ 4300 约束。
pub(crate) fn assert_g1_on_curve(
    builder: &mut NonNativeBuilder,
    x: &NonNativeElement,
    y: &NonNativeElement,
) {
    let m = &BN254_P;

    let y_sq = builder.mul_mod(y, y, m);

    let x_sq = builder.mul_mod(x, x, m);
    let x_cubed = builder.mul_mod(&x_sq, x, m);

    let b_elem = builder.from_u256(&BN254_B);
    let rhs = builder.add_mod(&x_cubed, &b_elem, m);

    builder.assert_equal(&y_sq, &rhs);
}

// ===== Host-side 参考计算 =====

/// Host 侧验证仿射 G1 点在曲线上。
pub fn host_g1_on_curve(x: &[u64; 4], y: &[u64; 4]) -> bool {
    let m = &BN254_P;
    let y_sq = host_mul_mod(y, y, m);
    let x_sq = host_mul_mod(x, x, m);
    let x_cubed = host_mul_mod(&x_sq, x, m);
    let rhs = host_add_mod(&x_cubed, &BN254_B, m);
    y_sq == rhs
}

/// Host 侧验证 Jacobian G1 点在曲线上：Y² = X³ + 3*Z⁶ (mod p)。
pub fn host_jacobian_on_curve(x: &[u64; 4], y: &[u64; 4], z: &[u64; 4]) -> bool {
    let m = &BN254_P;
    let y_sq = host_mul_mod(y, y, m);
    let x_sq = host_mul_mod(x, x, m);
    let x_cu = host_mul_mod(&x_sq, x, m);
    let z_sq = host_mul_mod(z, z, m);
    let z_four = host_mul_mod(&z_sq, &z_sq, m);
    let z_six = host_mul_mod(&z_sq, &z_four, m);
    let b_z6 = host_mul_mod(&BN254_B, &z_six, m);
    let rhs = host_add_mod(&x_cu, &b_z6, m);
    y_sq == rhs
}

/// Host 侧 Jacobian → affine 转换。
pub fn host_jacobian_to_affine(x: &[u64; 4], y: &[u64; 4], z: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    let m = &BN254_P;
    let z_inv = host_inv_mod(z, m);
    let z_inv_sq = host_mul_mod(&z_inv, &z_inv, m);
    let z_inv_cu = host_mul_mod(&z_inv_sq, &z_inv, m);
    let x_aff = host_mul_mod(x, &z_inv_sq, m);
    let y_aff = host_mul_mod(y, &z_inv_cu, m);
    (x_aff, y_aff)
}

/// Host 侧 G1 点加（affine），用于测试参考。
pub fn host_g1_add(
    x1: &[u64; 4],
    y1: &[u64; 4],
    x2: &[u64; 4],
    y2: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    let m = &BN254_P;
    // λ = (y2 - y1) / (x2 - x1)
    let dx = host_sub_mod(x2, x1, m);
    let dy = host_sub_mod(y2, y1, m);
    let dx_inv = host_inv_mod(&dx, m);
    let lambda = host_mul_mod(&dy, &dx_inv, m);
    // x3 = λ² - x1 - x2
    let lambda_sq = host_mul_mod(&lambda, &lambda, m);
    let x3 = host_sub_mod(&host_sub_mod(&lambda_sq, x1, m), x2, m);
    // y3 = λ*(x1 - x3) - y1
    let y3 = host_sub_mod(&host_mul_mod(&lambda, &host_sub_mod(x1, &x3, m), m), y1, m);
    (x3, y3)
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bn254_g1_on_curve_generator() {
        assert!(host_g1_on_curve(&BN254_G1_X, &BN254_G1_Y));
    }

    #[test]
    fn test_bn254_g1_not_on_curve() {
        assert!(!host_g1_on_curve(&[1, 0, 0, 0], &[3, 0, 0, 0]));
    }

    #[test]
    fn test_bn254_identity_double() {
        let mut builder = NonNativeBuilder::new();
        let id = identity_point(&mut builder);
        let result = point_double(&mut builder, &id);

        let z_u256 = builder.element_to_u256(&result.z);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert_eq!(witness.len(), ccs.num_vars);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
        assert_eq!(
            z_u256,
            [0, 0, 0, 0],
            "doubling identity should give identity (Z=0)"
        );
    }

    #[test]
    fn test_bn254_point_double_basic() {
        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &BN254_G1_X, &BN254_G1_Y);
        let result = point_double(&mut builder, &g);

        let x_u256 = builder.element_to_u256(&result.x);
        let y_u256 = builder.element_to_u256(&result.y);
        let z_u256 = builder.element_to_u256(&result.z);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        // Jacobian 结果应在曲线上
        assert!(host_jacobian_on_curve(&x_u256, &y_u256, &z_u256));

        // 归一化后也应在曲线上
        let (x_aff, y_aff) = host_jacobian_to_affine(&x_u256, &y_u256, &z_u256);
        assert!(host_g1_on_curve(&x_aff, &y_aff));
    }

    #[test]
    fn test_bn254_assert_g1_on_curve_valid() {
        let mut builder = NonNativeBuilder::new();
        let x = builder.from_u256(&BN254_G1_X);
        let y = builder.from_u256(&BN254_G1_Y);
        assert_g1_on_curve(&mut builder, &x, &y);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    #[test]
    fn test_bn254_assert_g1_on_curve_invalid() {
        let mut builder = NonNativeBuilder::new();
        let x = builder.from_u256(&[1, 0, 0, 0]);
        let y = builder.from_u256(&[3, 0, 0, 0]); // (1, 3) 不在曲线上
        assert_g1_on_curve(&mut builder, &x, &y);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "(1, 3) 不在曲线上，约束应不满足"
        );
    }

    #[test]
    fn test_bn254_assert_on_curve_jacobian() {
        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &BN254_G1_X, &BN254_G1_Y);
        assert_on_curve(&mut builder, &g);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    #[test]
    fn test_bn254_point_add_basic() {
        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &BN254_G1_X, &BN254_G1_Y);
        let g2 = point_double(&mut builder, &g);
        let g3 = point_add(&mut builder, &g2, &g);

        let x_u256 = builder.element_to_u256(&g3.x);
        let y_u256 = builder.element_to_u256(&g3.y);
        let z_u256 = builder.element_to_u256(&g3.z);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        // Jacobian 结果应在曲线上
        assert!(host_jacobian_on_curve(&x_u256, &y_u256, &z_u256));

        // 归一化后也应在曲线上
        let (x_aff, y_aff) = host_jacobian_to_affine(&x_u256, &y_u256, &z_u256);
        assert!(host_g1_on_curve(&x_aff, &y_aff));
    }

    #[test]
    fn test_bn254_assert_point_equal() {
        let mut builder = NonNativeBuilder::new();
        let g1 = from_affine(&mut builder, &BN254_G1_X, &BN254_G1_Y);
        let g2 = from_affine(&mut builder, &BN254_G1_X, &BN254_G1_Y);
        assert_point_equal(&mut builder, &g1, &g2);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }
}
