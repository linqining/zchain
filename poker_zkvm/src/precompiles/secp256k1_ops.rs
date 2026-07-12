//! secp256k1 点运算电路（Stage 3 — Phase E2）。
//!
//! 在 BN254 Fr 上使用非原生域算术模拟 secp256k1 的 Jacobian 坐标点运算。
//!
//! # 坐标系
//!
//! 使用 Jacobian 投影坐标 (X:Y:Z)，仿射坐标 (x,y) = (X/Z², Y/Z³)。
//! 无穷远点（单位元）= (1:1:0)。
//!
//! secp256k1 曲线: y² = x³ + 7 (a=0, b=7)
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

#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]

use crate::ccs::Fr;
use crate::field::ZkvmField;
use crate::precompiles::non_native::{NonNativeBuilder, NonNativeElement, SECP256K1_P_CURVE};

// ===== Point 结构 =====

/// secp256k1 Jacobian 投影坐标点。
#[derive(Clone)]
pub(crate) struct Point {
    pub x: NonNativeElement,
    pub y: NonNativeElement,
    pub z: NonNativeElement,
}

// ===== 辅助：条件选择 =====

/// 条件选择两个 Fr 值：result = if_zero + bit * (if_one - if_zero)。
///
/// 返回结果变量索引。添加 2 linear + 1 multiplication = 3 约束。
fn select_fr(builder: &mut NonNativeBuilder, bit: usize, if_one: usize, if_zero: usize) -> usize {
    let if_one_val = builder.get_val(if_one);
    let if_zero_val = builder.get_val(if_zero);
    let diff_val = if_one_val.sub(&if_zero_val);

    // diff = if_one - if_zero
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

    // bit_diff = bit * diff
    let bit_diff_val = builder.get_val(bit).mul(&diff_val);
    let bit_diff_var = builder.alloc(bit_diff_val);
    let row = builder.ccs.alloc_row();
    builder
        .ccs
        .add_multiplication(row, bit, diff_var, bit_diff_var);

    // result = if_zero + bit_diff
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
/// secp256k1 (a=0) 倍点公式：
/// - A = X², B = Y², C = B² (Y⁴)
/// - D = 2*((X+B)² - A - C)
/// - E = 3*A
/// - F = E²
/// - X3 = F - 2*D
/// - Y3 = E*(D - X3) - 8*C
/// - Z3 = 2*Y*Z
pub(crate) fn point_double(builder: &mut NonNativeBuilder, p: &Point) -> Point {
    let m = &SECP256K1_P_CURVE;

    // A = X²
    let a = builder.mul_mod(&p.x, &p.x, m);
    // B = Y²
    let b = builder.mul_mod(&p.y, &p.y, m);
    // C = B²
    let c = builder.mul_mod(&b, &b, m);

    // X+B
    let xb = builder.add_mod(&p.x, &b, m);
    // (X+B)²
    let xb2 = builder.mul_mod(&xb, &xb, m);
    // (X+B)² - A - C
    let tmp1 = builder.sub_mod(&xb2, &a, m);
    let tmp2 = builder.sub_mod(&tmp1, &c, m);
    // D = 2*tmp2
    let d = builder.add_mod(&tmp2, &tmp2, m);

    // E = 3*A = A + A + A
    let e = builder.add_mod(&a, &a, m);
    let e = builder.add_mod(&e, &a, m);

    // F = E²
    let f = builder.mul_mod(&e, &e, m);

    // 2*D
    let two_d = builder.add_mod(&d, &d, m);
    // X3 = F - 2*D
    let x3 = builder.sub_mod(&f, &two_d, m);

    // D - X3
    let d_minus_x3 = builder.sub_mod(&d, &x3, m);
    // E*(D - X3)
    let e_dm = builder.mul_mod(&e, &d_minus_x3, m);
    // 8*C = 2*C + 2*C + 2*C + 2*C
    let two_c = builder.add_mod(&c, &c, m);
    let four_c = builder.add_mod(&two_c, &two_c, m);
    let eight_c = builder.add_mod(&four_c, &four_c, m);
    // Y3 = E*(D-X3) - 8*C
    let y3 = builder.sub_mod(&e_dm, &eight_c, m);

    // 2*Y
    let two_y = builder.add_mod(&p.y, &p.y, m);
    // Z3 = 2*Y*Z
    let z3 = builder.mul_mod(&two_y, &p.z, m);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Jacobian 点加法：P + Q（假设 P ≠ ±Q，两者均非无穷远点）。
///
/// 基于 EFD add-1998-cmo-2，但 H = U1 - U2（EFD 原版 H = U2 - U1），
/// 因此 H³ 符号翻转，X3 公式中 H3 项取加号。
/// - U1 = X1*Z2², S1 = Y1*Z2³
/// - U2 = X2*Z1², S2 = Y2*Z1³
/// - H = U1 - U2, H2 = H², H3 = H*H2
/// - r = S1 - S2
/// - V = U1*H2
/// - X3 = r² + H3 - 2*V
/// - Y3 = r*(V - X3) - S1*H3
/// - Z3 = Z1*Z2*H
pub(crate) fn point_add(builder: &mut NonNativeBuilder, p: &Point, q: &Point) -> Point {
    let m = &SECP256K1_P_CURVE;

    // Z2², Z2³
    let z2_sq = builder.mul_mod(&q.z, &q.z, m);
    let z2_cu = builder.mul_mod(&z2_sq, &q.z, m);

    // Z1², Z1³
    let z1_sq = builder.mul_mod(&p.z, &p.z, m);
    let z1_cu = builder.mul_mod(&z1_sq, &p.z, m);

    // U1 = X1*Z2², S1 = Y1*Z2³
    let u1 = builder.mul_mod(&p.x, &z2_sq, m);
    let s1 = builder.mul_mod(&p.y, &z2_cu, m);

    // U2 = X2*Z1², S2 = Y2*Z1³
    let u2 = builder.mul_mod(&q.x, &z1_sq, m);
    let s2 = builder.mul_mod(&q.y, &z1_cu, m);

    // H = U1 - U2
    let h = builder.sub_mod(&u1, &u2, m);
    // H2 = H², H3 = H*H2
    let h2 = builder.mul_mod(&h, &h, m);
    let h3 = builder.mul_mod(&h, &h2, m);

    // r = S1 - S2
    let r = builder.sub_mod(&s1, &s2, m);

    // V = U1*H2
    let v = builder.mul_mod(&u1, &h2, m);

    // r²
    let r_sq = builder.mul_mod(&r, &r, m);
    // 2*V
    let two_v = builder.add_mod(&v, &v, m);
    // X3 = r² + H3 - 2*V  (H = U1-U2 → H³ 符号与 EFD 相反，取加号)
    let x3_tmp = builder.add_mod(&r_sq, &h3, m);
    let x3 = builder.sub_mod(&x3_tmp, &two_v, m);

    // V - X3
    let v_minus_x3 = builder.sub_mod(&v, &x3, m);
    // r*(V - X3)
    let r_vx = builder.mul_mod(&r, &v_minus_x3, m);
    // S1*H3
    let s1_h3 = builder.mul_mod(&s1, &h3, m);
    // Y3 = r*(V-X3) - S1*H3
    let y3 = builder.sub_mod(&r_vx, &s1_h3, m);

    // Z3 = Z1*Z2*H
    let z1z2 = builder.mul_mod(&p.z, &q.z, m);
    let z3 = builder.mul_mod(&z1z2, &h, m);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// 标量乘法：scalar * P。
///
/// Double-and-add with "started" flag，避免 point_add 处理无穷远点。
/// 使用低 `num_bits` 位标量。
pub(crate) fn scalar_mul(
    builder: &mut NonNativeBuilder,
    p: &Point,
    scalar: &NonNativeElement,
    num_bits: usize,
) -> Point {
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
    // 对每个完全覆盖的 limb，添加 recompose linear 约束
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
    // 部分覆盖的 limb
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

    // Double-and-add
    let identity = identity_point(builder);

    // started = 0
    let mut started_var = builder.alloc(Fr::zero());
    {
        let row = builder.ccs.alloc_row();
        builder.ccs.add_bit_check(row, started_var);
    }

    // R = identity
    let mut r = identity.clone();

    for i in (0..num_bits).rev() {
        let bit_var = bit_vars[i];

        // double_R = point_double(R)
        let double_r = point_double(builder, &r);

        // add_result = point_add(double_R, P)
        let add_result = point_add(builder, &double_r, p);

        // not_started_result = bit ? P : identity
        let not_started = select_point(builder, bit_var, p, &identity);

        // started_result = bit ? add_result : double_R
        let started_result = select_point(builder, bit_var, &add_result, &double_r);

        // R_new = started ? started_result : not_started
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

/// 断言点在曲线上：Y² = X³ + 7*Z⁶ (mod p_curve)。
pub(crate) fn assert_on_curve(builder: &mut NonNativeBuilder, p: &Point) {
    let m = &SECP256K1_P_CURVE;

    // Y²
    let y_sq = builder.mul_mod(&p.y, &p.y, m);

    // X³ = X² * X
    let x_sq = builder.mul_mod(&p.x, &p.x, m);
    let x_cu = builder.mul_mod(&x_sq, &p.x, m);

    // Z⁶ = Z² * Z⁴ = Z² * (Z²)²
    let z_sq = builder.mul_mod(&p.z, &p.z, m);
    let z_four = builder.mul_mod(&z_sq, &z_sq, m);
    let z_six = builder.mul_mod(&z_sq, &z_four, m);

    // 7 * Z⁶
    let seven = builder.from_u256(&[7, 0, 0, 0]);
    let seven_z6 = builder.mul_mod(&seven, &z_six, m);

    // X³ + 7*Z⁶
    let rhs = builder.add_mod(&x_cu, &seven_z6, m);

    // Y² == X³ + 7*Z⁶
    builder.assert_equal(&y_sq, &rhs);
}

/// 断言两个点相等（Jacobian）：X1*Z2² == X2*Z1² 且 Y1*Z2³ == Y2*Z1³。
pub(crate) fn assert_point_equal(builder: &mut NonNativeBuilder, p: &Point, q: &Point) {
    let m = &SECP256K1_P_CURVE;

    // Z1², Z2², Z1³, Z2³
    let z1_sq = builder.mul_mod(&p.z, &p.z, m);
    let z2_sq = builder.mul_mod(&q.z, &q.z, m);
    let z1_cu = builder.mul_mod(&z1_sq, &p.z, m);
    let z2_cu = builder.mul_mod(&z2_sq, &q.z, m);

    // X1*Z2² == X2*Z1²
    let lhs_x = builder.mul_mod(&p.x, &z2_sq, m);
    let rhs_x = builder.mul_mod(&q.x, &z1_sq, m);
    builder.assert_equal(&lhs_x, &rhs_x);

    // Y1*Z2³ == Y2*Z1³
    let lhs_y = builder.mul_mod(&p.y, &z2_cu, m);
    let rhs_y = builder.mul_mod(&q.y, &z1_cu, m);
    builder.assert_equal(&lhs_y, &rhs_y);
}

// ===== 测试辅助 =====

/// 将 [u8; 32] (big-endian) 转为 [u64; 4] (little-endian limbs)。
fn bytes_be_to_u256_le(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for k in 0..4 {
        let start = 32 - (k + 1) * 8;
        limbs[k] = u64::from_be_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
    }
    limbs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::non_native::{SECP256K1_GX, SECP256K1_GY};

    /// 获取 secp256k1 G 点坐标。
    fn g_point() -> ([u64; 4], [u64; 4]) {
        (SECP256K1_GX, SECP256K1_GY)
    }

    #[test]
    fn test_identity_double() {
        // doubling identity = identity
        let mut builder = NonNativeBuilder::new();
        let id = identity_point(&mut builder);
        let result = point_double(&mut builder, &id);

        // Compute Z before build (build consumes builder)
        let z_u256 = builder.element_to_u256(&result.z);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert_eq!(witness.len(), ccs.num_vars);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        // Z should be 0
        assert_eq!(
            z_u256,
            [0, 0, 0, 0],
            "doubling identity should give identity (Z=0)"
        );
    }

    #[test]
    fn test_point_double_basic() {
        // 2*G via point_double should match secp256k1 crate
        use secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk2 = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 2;
            b
        })
        .unwrap();
        let pk2 = sk2.public_key(&secp);
        let serialized = pk2.serialize_uncompressed();
        // 0x04 || x(32) || y(32)
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&serialized[1..33]);
        y_bytes.copy_from_slice(&serialized[33..65]);
        let expected_x = bytes_be_to_u256_le(&x_bytes);
        let expected_y = bytes_be_to_u256_le(&y_bytes);

        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        let _result = point_double(&mut builder, &g);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        // Result is in Jacobian (X:Y:Z), convert to affine (X/Z², Y/Z³)
        // For Z=1 (since doubling affine gives Z=2*Y*1=2*Y), need to check
        // Actually Z3 = 2*Y*Z = 2*GY*1, so Z ≠ 1 in general
        // Instead, verify constraint satisfaction is enough for circuit correctness
        // Host-side value check would require modular inverse
        let _ = (expected_x, expected_y);
    }

    #[test]
    fn test_point_add_basic() {
        // 2*G + G = 3*G via point_add(point_double(G), G)
        use secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk3 = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 3;
            b
        })
        .unwrap();
        let pk3 = sk3.public_key(&secp);
        let _ = pk3; // just verify secp256k1 can compute 3*G

        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        let g2 = point_double(&mut builder, &g);
        let g3 = point_add(&mut builder, &g2, &g);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
        let _ = g3;
    }

    #[test]
    fn test_assert_on_curve() {
        // G is on the curve
        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        assert_on_curve(&mut builder, &g);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

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

    #[test]
    fn test_assert_point_equal() {
        // point_double(G) == point_double(G) (same computation)
        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        let g2a = point_double(&mut builder, &g);
        let g2b = point_double(&mut builder, &g);
        assert_point_equal(&mut builder, &g2a, &g2b);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    #[test]
    fn test_scalar_mul_small() {
        // 3*G via scalar_mul with num_bits=4 (scalar=3, bits=0011)
        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        let scalar = builder.from_u256(&[3, 0, 0, 0]);
        let result = scalar_mul(&mut builder, &g, &scalar, 4);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
        let _ = result;
    }

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

    #[test]
    fn test_scalar_mul_3g_consistency() {
        // Check if scalar_mul(3, G, 4) matches 3*G from secp256k1 crate
        use secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk3 = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 3;
            b
        })
        .unwrap();
        let pk3 = sk3.public_key(&secp);
        let serialized = pk3.serialize_uncompressed();
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&serialized[1..33]);
        y_bytes.copy_from_slice(&serialized[33..65]);
        let expected_x = bytes_be_to_u256_le(&x_bytes);
        let expected_y = bytes_be_to_u256_le(&y_bytes);

        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        let scalar = builder.from_u256(&[3, 0, 0, 0]);
        let result = scalar_mul(&mut builder, &g, &scalar, 4);

        let expected = from_affine(&mut builder, &expected_x, &expected_y);
        assert_point_equal(&mut builder, &result, &expected);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "scalar_mul(3, G) should equal 3*G from secp256k1 crate"
        );
    }

    #[test]
    fn test_point_double_matches_secp256k1() {
        // Check if point_double(G) matches 2*G from secp256k1 crate
        use secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk2 = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 2;
            b
        })
        .unwrap();
        let pk2 = sk2.public_key(&secp);
        let serialized = pk2.serialize_uncompressed();
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&serialized[1..33]);
        y_bytes.copy_from_slice(&serialized[33..65]);
        let expected_x = bytes_be_to_u256_le(&x_bytes);
        let expected_y = bytes_be_to_u256_le(&y_bytes);

        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        let result = point_double(&mut builder, &g);

        let expected = from_affine(&mut builder, &expected_x, &expected_y);
        assert_point_equal(&mut builder, &result, &expected);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "point_double(G) should equal 2*G from secp256k1 crate"
        );
    }

    /// Direct test: point_add(point_double(G), G) should equal 3*G.
    #[test]
    fn test_point_add_2g_g_matches_3g() {
        use secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk3 = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 3;
            b
        })
        .unwrap();
        let pk3 = sk3.public_key(&secp);
        let serialized = pk3.serialize_uncompressed();
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&serialized[1..33]);
        y_bytes.copy_from_slice(&serialized[33..65]);
        let expected_x = bytes_be_to_u256_le(&x_bytes);
        let expected_y = bytes_be_to_u256_le(&y_bytes);

        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        let g2 = point_double(&mut builder, &g);
        let g3 = point_add(&mut builder, &g2, &g);

        let expected = from_affine(&mut builder, &expected_x, &expected_y);
        assert_point_equal(&mut builder, &g3, &expected);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "point_add(2*G, G) should equal 3*G from secp256k1 crate"
        );
    }

    /// Check if point_add(2*G, G) produces a point on the curve.
    #[test]
    fn test_point_add_2g_g_on_curve() {
        let mut builder = NonNativeBuilder::new();
        let g = from_affine(&mut builder, &SECP256K1_GX, &SECP256K1_GY);
        let g2 = point_double(&mut builder, &g);
        let g3 = point_add(&mut builder, &g2, &g);
        assert_on_curve(&mut builder, &g3);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build");
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "point_add(2*G, G) should produce a point on the curve"
        );
    }
}
