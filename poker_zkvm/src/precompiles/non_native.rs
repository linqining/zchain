//! 非原生域算术（Stage 3 — Phase E1）。
//!
//! 在 BN254 Fr 域上模拟 secp256k1 的 256-bit 非原生域算术。
//!
//! # Limb 表示
//!
//! 每个 256-bit 值表示为 4 个 64-bit limb（little-endian）：
//! `val = l0 + l1*2^64 + l2*2^128 + l3*2^192`
//!
//! limb 乘积 64×64=128 bits < BN254 Fr (254 bits)，在 Fr 中精确计算。
//!
//! # Hint-based 乘法
//!
//! Prover 提供 quotient `q` 和 remainder `r`，电路验证：
//! 1. `a*b = q*modulus + r`（大整数 schoolbook 乘法 + carry 链）
//! 2. `r < modulus`（范围检查）
//!
//! # 约束计数
//!
//! | 操作 | 约束数（行数） |
//! |------|----------------|
//! | add_mod | ~30 |
//! | sub_mod | ~30 |
//! | mul_mod | ~1400 |
//! | assert_lt | ~270 |
//! | assert_equal | ~4 |

#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]

use crate::ccs::Fr;
use crate::field::ZkvmField;
use crate::precompiles::ccs_builder::CcsBuilder;

// ===== secp256k1 常量（[u64; 4] little-endian）=====

/// secp256k1 基域模数 p = 2^256 - 2^32 - 977
pub const SECP256K1_P_CURVE: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// secp256k1 标量域模数 n（阶）
pub const SECP256K1_N: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// secp256k1 生成元 G 的 x 坐标
pub const SECP256K1_GX: [u64; 4] = [
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
];

/// secp256k1 生成元 G 的 y 坐标
pub const SECP256K1_GY: [u64; 4] = [
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
];

// ===== Fr 辅助函数 =====

/// 2^exp as Fr
fn fr_pow2(exp: u32) -> Fr {
    let mut result = Fr::one();
    for _ in 0..exp {
        result = result.double();
    }
    result
}

/// 获取 2^exp 的逆元
fn fr_inv_pow2(exp: u32) -> Fr {
    fr_pow2(exp).inverse().expect("2^exp 非零，逆元存在")
}

// ===== Host-side [u64; 4] 算术 =====

/// 256-bit 比较 a < b（unsigned）
pub(crate) fn host_lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

/// 256-bit 加法（返回 sum 和 carry）
pub(crate) fn host_add(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (sum, c1) = a[i].overflowing_add(b[i]);
        let (sum, c2) = sum.overflowing_add(carry);
        result[i] = sum;
        carry = (c1 as u64) + (c2 as u64);
    }
    (result, carry)
}

/// 256-bit 减法（返回 diff 和 borrow）
pub(crate) fn host_sub(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut result = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff, b2) = diff.overflowing_sub(borrow as u64);
        result[i] = diff;
        borrow = b1 || b2;
    }
    (result, borrow)
}

/// 256-bit 加法 mod modulus
pub(crate) fn host_add_mod(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let (sum, carry) = host_add(a, b);
    if carry > 0 || !host_lt(&sum, modulus) {
        let (diff, _) = host_sub(&sum, modulus);
        diff
    } else {
        sum
    }
}

/// 256-bit 减法 mod modulus
pub(crate) fn host_sub_mod(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let (diff, borrow) = host_sub(a, b);
    if borrow {
        let (sum, _) = host_add(&diff, modulus);
        sum
    } else {
        diff
    }
}

/// 512-bit / 256-bit 除法，返回 (quotient, remainder)
///
/// 注：商在内部以 512-bit 计算（`[u64; 8]`），但我们的用例中
/// `a, b < modulus` 保证 `q < modulus < 2^256`，因此安全截断为 `[u64; 4]`。
pub(crate) fn host_div_mod(dividend: &[u64; 8], divisor: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    let mut quotient = [0u64; 8];
    let mut remainder = [0u64; 4];

    for bit in (0..512).rev() {
        // Track MSB before shift (overflow when remainder >= 2^255)
        let overflow = remainder[3] >> 63;

        // remainder = remainder << 1
        for k in (1..4).rev() {
            remainder[k] = (remainder[k] << 1) | (remainder[k - 1] >> 63);
        }
        remainder[0] <<= 1;

        // 带入 dividend 的下一位
        let dividend_bit = (dividend[bit / 64] >> (bit % 64)) & 1;
        remainder[0] |= dividend_bit;

        // if overflow (MSB was set) or remainder >= divisor, subtract and set quotient bit
        if overflow > 0 || !host_lt(&remainder, divisor) {
            let (diff, _) = host_sub(&remainder, divisor);
            remainder = diff;
            quotient[bit / 64] |= 1 << (bit % 64);
        }
    }

    // 截断到 [u64; 4]（仅在 q < 2^256 时安全，即 a, b < modulus 的用例）
    let quotient_truncated: [u64; 4] = [quotient[0], quotient[1], quotient[2], quotient[3]];
    (quotient_truncated, remainder)
}

/// 256-bit 乘法 mod modulus
pub(crate) fn host_mul_mod(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    // schoolbook 乘法 → 512-bit product
    let product = host_mul_big(a, b);
    // 除法取模
    let (_, remainder) = host_div_mod(&product, modulus);
    remainder
}

/// 256-bit × 256-bit schoolbook 乘法 → 512-bit 结果
pub(crate) fn host_mul_big(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut product = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let prod = (a[i] as u128) * (b[j] as u128);
            let (sum, c1) = product[i + j].overflowing_add(prod as u64);
            let (sum, c2) = sum.overflowing_add(carry);
            product[i + j] = sum;
            carry = (prod >> 64) as u64 + c1 as u64 + c2 as u64;
        }
        product[i + 4] = product[i + 4].wrapping_add(carry);
    }
    product
}

/// 256-bit 模逆（费马小定理：a^(modulus-2) mod modulus）
pub(crate) fn host_inv_mod(a: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    // exponent = modulus - 2
    let (_, borrow) = host_sub(modulus, &[2, 0, 0, 0]);
    if borrow {
        // modulus < 2, shouldn't happen for secp256k1
        return [0, 0, 0, 0];
    }
    let exponent = {
        let (d, _) = host_sub(modulus, &[2, 0, 0, 0]);
        d
    };

    // 快速幂
    let mut result = [1u64, 0, 0, 0]; // result = 1
    let mut base = *a;
    let mut exp = exponent;

    for _ in 0..256 {
        if exp[0] & 1 == 1 {
            result = host_mul_mod(&result, &base, modulus);
        }
        base = host_mul_mod(&base, &base, modulus);
        // 右移 exp
        for k in 0..3 {
            exp[k] = (exp[k] >> 1) | (exp[k + 1] << 63);
        }
        exp[3] >>= 1;
        // 检查 exp == 0
        if exp == [0u64; 4] {
            break;
        }
    }
    result
}

/// 256-bit 模幂：base^exp mod modulus（square-and-multiply）
pub(crate) fn host_pow_mod(base: &[u64; 4], exp: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let mut result = [1u64, 0, 0, 0];
    let mut b = *base;
    let mut e = *exp;

    for _ in 0..256 {
        if e[0] & 1 == 1 {
            result = host_mul_mod(&result, &b, modulus);
        }
        b = host_mul_mod(&b, &b, modulus);
        for k in 0..3 {
            e[k] = (e[k] >> 1) | (e[k + 1] << 63);
        }
        e[3] >>= 1;
        if e == [0u64; 4] {
            break;
        }
    }
    result
}

/// [u64; 4] → [Fr; 4]
fn u256_to_fr_limbs(val: &[u64; 4]) -> [Fr; 4] {
    [
        Fr::from_u64(val[0]),
        Fr::from_u64(val[1]),
        Fr::from_u64(val[2]),
        Fr::from_u64(val[3]),
    ]
}

/// [Fr; 4] → [u64; 4]（用于 host-side 验证）
fn fr_limbs_to_u256(limbs: &[Fr; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for i in 0..4 {
        let bytes = limbs[i].to_canonical_bytes();
        result[i] = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
    }
    result
}

// ===== 非原生域元素 =====

/// 非原生域元素（4 limbs × 64 bits）
#[derive(Clone)]
pub(crate) struct NonNativeElement {
    /// 4 个 limb 变量索引（little-endian）
    pub limbs: [usize; 4],
}

// ===== 非原生域构建器 =====

/// 组合 CCS 构建器 + witness 跟踪器。
///
/// 每个 operation 方法同时添加约束和计算 witness，确保两者同步。
pub(crate) struct NonNativeBuilder {
    pub ccs: CcsBuilder,
    pub witness: Vec<Fr>,
}

impl NonNativeBuilder {
    /// 创建新构建器（witness[0] = Fr::one()，变量 0 = 常数 1）。
    pub fn new() -> Self {
        Self {
            ccs: CcsBuilder::new(),
            witness: vec![Fr::one()],
        }
    }

    /// 分配变量并设置 witness 值。
    pub fn alloc(&mut self, val: Fr) -> usize {
        let idx = self.ccs.alloc_var();
        self.witness.push(val);
        idx
    }

    /// 获取变量的 witness 值。
    pub fn get_val(&self, idx: usize) -> Fr {
        self.witness[idx]
    }

    /// 分配 4-limb 元素。
    pub fn alloc_element(&mut self, limbs: [Fr; 4]) -> NonNativeElement {
        let l0 = self.alloc(limbs[0]);
        let l1 = self.alloc(limbs[1]);
        let l2 = self.alloc(limbs[2]);
        let l3 = self.alloc(limbs[3]);
        NonNativeElement {
            limbs: [l0, l1, l2, l3],
        }
    }

    /// 从 host [u64; 4] 创建元素。
    #[allow(clippy::wrong_self_convention)]
    pub fn from_u256(&mut self, val: &[u64; 4]) -> NonNativeElement {
        self.alloc_element(u256_to_fr_limbs(val))
    }

    /// 获取元素的 host [u64; 4] 值。
    pub fn element_to_u256(&self, elem: &NonNativeElement) -> [u64; 4] {
        let limbs = [
            self.get_val(elem.limbs[0]),
            self.get_val(elem.limbs[1]),
            self.get_val(elem.limbs[2]),
            self.get_val(elem.limbs[3]),
        ];
        fr_limbs_to_u256(&limbs)
    }

    // ===== 约束方法 =====

    /// 范围检查：变量 < 2^64。
    ///
    /// bit-decompose 成 64 个 bit + recompose。
    fn range_check_64(&mut self, var: usize) {
        let bytes = self.get_val(var).to_canonical_bytes();
        let u64_val = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));

        // 64 个 bit_check
        let mut bits = Vec::with_capacity(64);
        for i in 0..64 {
            let bit_val = Fr::from_u64((u64_val >> i) & 1);
            let bit = self.alloc(bit_val);
            let row = self.ccs.alloc_row();
            self.ccs.add_bit_check(row, bit);
            bits.push(bit);
        }

        // recompose: sum(bit_i * 2^i) = var
        let row = self.ccs.alloc_row();
        let mut terms = Vec::with_capacity(65);
        for (i, &bit) in bits.iter().enumerate() {
            terms.push((bit, fr_pow2(i as u32)));
        }
        terms.push((var, Fr::one().neg()));
        self.ccs.add_linear(row, &terms);
    }

    /// 范围检查：元素所有 4 个 limb < 2^64。
    pub fn range_check_element(&mut self, elem: &NonNativeElement) {
        for &limb in &elem.limbs {
            self.range_check_64(limb);
        }
    }

    /// 相等检查：a == b（逐 limb 线性约束）。
    pub fn assert_equal(&mut self, a: &NonNativeElement, b: &NonNativeElement) {
        for k in 0..4 {
            let row = self.ccs.alloc_row();
            self.ccs.add_linear(
                row,
                &[(a.limbs[k], Fr::one()), (b.limbs[k], Fr::one().neg())],
            );
        }
    }

    /// 断言 val < bound（使用 complement 方法）。
    ///
    /// Prover 提供 d = bound - 1 - val，bit-decompose d（确保 d >= 0），
    /// 验证 val + d + 1 = bound。
    pub fn assert_lt(&mut self, val: &NonNativeElement, bound: &[u64; 4]) {
        let val_u256 = self.element_to_u256(val);

        // d = bound - 1 - val
        let bound_minus_1 = {
            let (d, _) = host_sub(bound, &[1, 0, 0, 0]);
            d
        };
        let d_val = host_sub_mod(&bound_minus_1, &val_u256, bound);

        // 分配 d 并 bit-decompose（256 bits 确保 d >= 0 且 d < 2^256）
        let d_elem = self.from_u256(&d_val);
        for &limb in &d_elem.limbs {
            self.range_check_64(limb);
        }

        // 验证 val + d + 1 = bound（大整数加法 + carry 链）
        let two_64 = fr_pow2(64);
        let mut carry_var = self.alloc(Fr::one()); // carry[0] = 1

        for k in 0..4 {
            let val_v = self.get_val(val.limbs[k]);
            let d_v = self.get_val(d_elem.limbs[k]);
            let carry_v = self.get_val(carry_var);

            // sum = val[k] + d[k] + carry[k]
            let sum = val_v.add(&d_v).add(&carry_v);

            // bound[k] = sum mod 2^64
            let bound_k = Fr::from_u64(bound[k]);

            // next_carry = (sum - bound[k]) / 2^64
            let diff = sum.sub(&bound_k);
            let inv_two_64 = fr_inv_pow2(64);
            let next_carry_val = diff.mul(&inv_two_64);

            let next_carry = self.alloc(next_carry_val);

            // 约束: val[k] + d[k] + carry[k] - bound[k] - next_carry * 2^64 = 0
            let row = self.ccs.alloc_row();
            let neg_two_64 = two_64.neg();
            let bound_k_var = self.bound_var(bound_k);
            self.ccs.add_linear(
                row,
                &[
                    (val.limbs[k], Fr::one()),
                    (d_elem.limbs[k], Fr::one()),
                    (carry_var, Fr::one()),
                    (next_carry, neg_two_64),
                    (bound_k_var, Fr::one().neg()),
                ],
            );

            carry_var = next_carry;
        }

        // 最终 carry 应为 0
        let row = self.ccs.alloc_row();
        self.ccs.add_linear(row, &[(carry_var, Fr::one())]);
    }

    /// 创建一个值为常数的变量（用于线性约束中的常数项）。
    fn bound_var(&mut self, val: Fr) -> usize {
        // 如果值是 one，返回变量 0（常数 1）
        if val == Fr::one() {
            return 0;
        }
        // 否则分配新变量
        self.alloc(val)
    }

    /// 模加：result = (a + b) mod modulus。
    ///
    /// Prover 提供 reduced flag（0 或 1）。
    /// 约束：a + b = result + reduced * modulus（大整数等式）。
    pub fn add_mod(
        &mut self,
        a: &NonNativeElement,
        b: &NonNativeElement,
        modulus: &[u64; 4],
    ) -> NonNativeElement {
        let a_u256 = self.element_to_u256(a);
        let b_u256 = self.element_to_u256(b);

        // host 计算
        let (sum, carry) = host_add(&a_u256, &b_u256);
        let reduced = carry > 0 || !host_lt(&sum, modulus);
        let result_u256 = if reduced {
            let (diff, _) = host_sub(&sum, modulus);
            diff
        } else {
            sum
        };

        // 分配 result 和 reduced flag
        let result_elem = self.from_u256(&result_u256);
        let reduced_val = if reduced { Fr::one() } else { Fr::zero() };
        let reduced_var = self.alloc(reduced_val);

        // bit check: reduced ∈ {0, 1}
        let row = self.ccs.alloc_row();
        self.ccs.add_bit_check(row, reduced_var);

        // 大整数等式: a + b = result + reduced * modulus
        // 逐 limb carry 链: a[k] + b[k] + carry_in[k] = result[k] + reduced*modulus[k] + carry_out[k]*2^64
        let two_64 = fr_pow2(64);
        let mut carry_var = self.alloc(Fr::zero()); // carry_in[0] = 0

        for k in 0..4 {
            let a_v = self.get_val(a.limbs[k]);
            let b_v = self.get_val(b.limbs[k]);
            let r_v = self.get_val(result_elem.limbs[k]);
            let m_v = Fr::from_u64(modulus[k]);
            let carry_v = self.get_val(carry_var);

            // lhs = a[k] + b[k] + carry_in[k]
            let lhs = a_v.add(&b_v).add(&carry_v);
            // rhs = result[k] + reduced * modulus[k] + carry_out[k] * 2^64
            let reduced_modulus = reduced_val.mul(&m_v);
            let rhs_no_carry = r_v.add(&reduced_modulus);
            // carry_out = (lhs - rhs_no_carry) / 2^64
            let diff = lhs.sub(&rhs_no_carry);
            let inv_two_64 = fr_inv_pow2(64);
            let carry_out_val = diff.mul(&inv_two_64);

            let carry_out = self.alloc(carry_out_val);

            // 约束: a[k] + b[k] + carry_in[k] - result[k] - reduced*modulus[k] - carry_out*2^64 = 0
            let row = self.ccs.alloc_row();
            let neg_two_64 = two_64.neg();
            // reduced * modulus[k] 需要一个乘法约束
            let rm_var = self.alloc(reduced_modulus);
            let m_var = self.bound_var(m_v);
            let r_mult = self.ccs.alloc_row();
            self.ccs
                .add_multiplication(r_mult, reduced_var, m_var, rm_var);

            self.ccs.add_linear(
                row,
                &[
                    (a.limbs[k], Fr::one()),
                    (b.limbs[k], Fr::one()),
                    (carry_var, Fr::one()),
                    (result_elem.limbs[k], Fr::one().neg()),
                    (rm_var, Fr::one().neg()),
                    (carry_out, neg_two_64),
                ],
            );

            carry_var = carry_out;
        }

        // 最终 carry 应为 0
        let row = self.ccs.alloc_row();
        self.ccs.add_linear(row, &[(carry_var, Fr::one())]);

        // 范围检查 result < modulus
        self.assert_lt(&result_elem, modulus);

        result_elem
    }

    /// 模减：result = (a - b) mod modulus。
    ///
    /// Prover 提供 borrowed flag（0 或 1）。
    /// 约束：a - b + borrowed * modulus = result（大整数等式）。
    pub fn sub_mod(
        &mut self,
        a: &NonNativeElement,
        b: &NonNativeElement,
        modulus: &[u64; 4],
    ) -> NonNativeElement {
        let a_u256 = self.element_to_u256(a);
        let b_u256 = self.element_to_u256(b);

        // host 计算
        let (diff, borrow) = host_sub(&a_u256, &b_u256);
        let result_u256 = if borrow {
            let (sum, _) = host_add(&diff, modulus);
            sum
        } else {
            diff
        };

        // 分配 result 和 borrowed flag
        let result_elem = self.from_u256(&result_u256);
        let borrowed_val = if borrow { Fr::one() } else { Fr::zero() };
        let borrowed_var = self.alloc(borrowed_val);

        // bit check
        let row = self.ccs.alloc_row();
        self.ccs.add_bit_check(row, borrowed_var);

        // 大整数等式: a - b + borrowed * modulus = result
        // 逐 limb: a[k] - b[k] + borrowed*modulus[k] + borrow_in[k] = result[k] + borrow_out[k]*2^64
        // 注意: borrow 是 "进位" 的反面，borrow_in[k] 表示低位借位
        let two_64 = fr_pow2(64);
        let mut borrow_var = self.alloc(Fr::zero()); // borrow_in[0] = 0

        for k in 0..4 {
            let a_v = self.get_val(a.limbs[k]);
            let b_v = self.get_val(b.limbs[k]);
            let r_v = self.get_val(result_elem.limbs[k]);
            let m_v = Fr::from_u64(modulus[k]);
            let borrow_v = self.get_val(borrow_var);

            // lhs = a[k] - b[k] + borrowed*modulus[k] + borrow_in[k]
            let borrowed_modulus = borrowed_val.mul(&m_v);
            let lhs = a_v.sub(&b_v).add(&borrowed_modulus).add(&borrow_v);
            // rhs = result[k] + borrow_out * 2^64
            // borrow_out = (lhs - result[k]) / 2^64
            let diff = lhs.sub(&r_v);
            let inv_two_64 = fr_inv_pow2(64);
            let borrow_out_val = diff.mul(&inv_two_64);

            let borrow_out = self.alloc(borrow_out_val);

            // borrowed * modulus[k] 需要乘法约束
            let bm_var = self.alloc(borrowed_modulus);
            let m_var = self.bound_var(m_v);
            let r_mult = self.ccs.alloc_row();
            self.ccs
                .add_multiplication(r_mult, borrowed_var, m_var, bm_var);

            // 约束: a[k] - b[k] + borrowed*modulus[k] + borrow_in[k] - result[k] - borrow_out*2^64 = 0
            let row = self.ccs.alloc_row();
            let neg_two_64 = two_64.neg();
            self.ccs.add_linear(
                row,
                &[
                    (a.limbs[k], Fr::one()),
                    (b.limbs[k], Fr::one().neg()),
                    (bm_var, Fr::one()),
                    (borrow_var, Fr::one()),
                    (result_elem.limbs[k], Fr::one().neg()),
                    (borrow_out, neg_two_64),
                ],
            );

            borrow_var = borrow_out;
        }

        // 最终 borrow 应为 0
        let row = self.ccs.alloc_row();
        self.ccs.add_linear(row, &[(borrow_var, Fr::one())]);

        // 范围检查 result < modulus
        self.assert_lt(&result_elem, modulus);

        result_elem
    }

    /// 模乘：result = (a * b) mod modulus。
    ///
    /// Hint-based: prover 提供 q（商）和 r（余数），电路验证 a*b = q*modulus + r。
    pub fn mul_mod(
        &mut self,
        a: &NonNativeElement,
        b: &NonNativeElement,
        modulus: &[u64; 4],
    ) -> NonNativeElement {
        let a_u256 = self.element_to_u256(a);
        let b_u256 = self.element_to_u256(b);

        // host 计算 a*b 和 q, r
        let product_512 = host_mul_big(&a_u256, &b_u256);
        let (q_u256, r_u256) = host_div_mod(&product_512, modulus);

        // 分配 q 和 r（prover hints）
        let q_elem = self.from_u256(&q_u256);
        let r_elem = self.from_u256(&r_u256);

        // 计算 a*b 的 8-limb 大整数（circuit）
        let ab_limbs = self.mul_big_circuit(a, b);

        // 计算 q*modulus 的 8-limb 大整数（circuit）
        let modulus_elem = self.from_u256(modulus);
        let qm_limbs = self.mul_big_circuit(&q_elem, &modulus_elem);

        // 验证: qm + r' = ab（ADDITION form — carry cancels correctly）
        // r' = [r[0], r[1], r[2], r[3], 0, 0, 0, 0]
        // SUBTRACTION form (ab - qm = r') is incorrect because carry_in is
        // subtracted, causing carries from qm+r'=ab to double (2*c_{k-1})
        // instead of canceling, which is not divisible by 2^64.
        let two_64 = fr_pow2(64);
        let inv_two_64 = fr_inv_pow2(64);
        let mut carry_var = self.alloc(Fr::zero()); // carry_in[0] = 0

        for k in 0..8 {
            let qm_v = self.get_val(qm_limbs[k]);
            let ab_v = self.get_val(ab_limbs[k]);
            let carry_v = self.get_val(carry_var);

            // sum = qm[k] + r'[k] + carry_in
            let expected_val = if k < 4 {
                self.get_val(r_elem.limbs[k])
            } else {
                Fr::zero()
            };
            let sum = qm_v.add(&expected_val).add(&carry_v);

            // carry_out = (sum - ab[k]) / 2^64
            let carry_out_val = sum.sub(&ab_v).mul(&inv_two_64);
            let carry_out = self.alloc(carry_out_val);

            // 约束: qm[k] + r'[k] + carry_in - ab[k] - carry_out*2^64 = 0
            let row = self.ccs.alloc_row();
            let neg_two_64 = two_64.neg();

            if k < 4 {
                self.ccs.add_linear(
                    row,
                    &[
                        (qm_limbs[k], Fr::one()),
                        (r_elem.limbs[k], Fr::one()),
                        (carry_var, Fr::one()),
                        (ab_limbs[k], Fr::one().neg()),
                        (carry_out, neg_two_64),
                    ],
                );
            } else {
                // r'[k] = 0, omit r_elem.limbs[k] term
                self.ccs.add_linear(
                    row,
                    &[
                        (qm_limbs[k], Fr::one()),
                        (carry_var, Fr::one()),
                        (ab_limbs[k], Fr::one().neg()),
                        (carry_out, neg_two_64),
                    ],
                );
            }

            carry_var = carry_out;
        }

        // 最终 carry 应为 0
        let row = self.ccs.alloc_row();
        self.ccs.add_linear(row, &[(carry_var, Fr::one())]);

        // 范围检查 r < modulus
        self.assert_lt(&r_elem, modulus);

        r_elem
    }

    /// 大整数乘法（circuit）：a × b → 8-limb product。
    ///
    /// 使用 schoolbook 算法 + carry 链。
    /// 每个 product limb 范围检查 < 2^64。
    fn mul_big_circuit(&mut self, a: &NonNativeElement, b: &NonNativeElement) -> [usize; 8] {
        let a_u256 = self.element_to_u256(a);
        let b_u256 = self.element_to_u256(b);

        // 计算所有 16 个 products 的值
        let mut product_vals = [[Fr::zero(); 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                product_vals[i][j] = Fr::from_u64(a_u256[i]).mul(&Fr::from_u64(b_u256[j]));
            }
        }

        // 分配 product 变量并添加乘法约束
        let mut p_vars = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let p_var = self.alloc(product_vals[i][j]);
                let row = self.ccs.alloc_row();
                self.ccs
                    .add_multiplication(row, a.limbs[i], b.limbs[j], p_var);
                p_vars[i][j] = p_var;
            }
        }

        // Carry 链: product[0..7]
        let two_64 = fr_pow2(64);
        let mut product_vars = [0usize; 8];
        let mut carry_var = self.alloc(Fr::zero()); // carry[0] = 0

        for k in 0..7usize {
            // sum = carry[k] + sum(p[i][j] for i+j==k)
            let mut sum = self.get_val(carry_var);
            for i in 0..4 {
                for j in 0..4 {
                    if i + j == k {
                        sum = sum.add(&product_vals[i][j]);
                    }
                }
            }

            // product[k] = sum mod 2^64
            let sum_bytes = sum.to_canonical_bytes();
            let sum_u64 = u64::from_le_bytes(sum_bytes[0..8].try_into().expect("8 bytes"));
            let product_val = Fr::from_u64(sum_u64);
            let product_var = self.alloc(product_val);

            // carry[k+1] = (sum - product[k]) / 2^64
            let diff = sum.sub(&product_val);
            let inv_two_64 = fr_inv_pow2(64);
            let carry_out_val = diff.mul(&inv_two_64);
            let carry_out = self.alloc(carry_out_val);

            // 约束: sum(p[i][j] for i+j==k) + carry[k] - product[k] - carry[k+1]*2^64 = 0
            let row = self.ccs.alloc_row();
            let neg_two_64 = two_64.neg();
            let mut terms = vec![
                (carry_var, Fr::one()),
                (product_var, Fr::one().neg()),
                (carry_out, neg_two_64),
            ];
            for i in 0..4 {
                for j in 0..4 {
                    if i + j == k {
                        terms.push((p_vars[i][j], Fr::one()));
                    }
                }
            }
            self.ccs.add_linear(row, &terms);

            product_vars[k] = product_var;
            carry_var = carry_out;
        }

        // k=7: product[7] = carry[7] (无 products)
        let product_var = self.alloc(self.get_val(carry_var));
        let row = self.ccs.alloc_row();
        self.ccs.add_linear(
            row,
            &[(carry_var, Fr::one()), (product_var, Fr::one().neg())],
        );
        product_vars[7] = product_var;

        // 范围检查每个 product limb < 2^64
        for &pv in &product_vars {
            self.range_check_64(pv);
        }

        product_vars
    }

    /// 构建 CCS 结构。
    pub fn build(self) -> Result<crate::ccs::Ccs, crate::error::ZkvmError> {
        self.ccs.build()
    }
}

impl Default for NonNativeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_lt() {
        assert!(host_lt(&[1, 0, 0, 0], &[2, 0, 0, 0]));
        assert!(!host_lt(&[2, 0, 0, 0], &[1, 0, 0, 0]));
        assert!(!host_lt(&[1, 0, 0, 0], &[1, 0, 0, 0]));
        assert!(host_lt(&[0, 0, 0, 0], &[0, 1, 0, 0]));
        assert!(host_lt(&[0xFF, 0, 0, 0], &[0, 1, 0, 0]));
    }

    #[test]
    fn test_host_add_mod() {
        // 基域: (p-1 + 2) mod p = 1
        let p_minus_1 = {
            let (d, _) = host_sub(&SECP256K1_P_CURVE, &[1, 0, 0, 0]);
            d
        };
        let result = host_add_mod(&p_minus_1, &[2, 0, 0, 0], &SECP256K1_P_CURVE);
        assert_eq!(result, [1, 0, 0, 0]);

        // 标量域: (n-1 + 2) mod n = 1
        let n_minus_1 = {
            let (d, _) = host_sub(&SECP256K1_N, &[1, 0, 0, 0]);
            d
        };
        let result = host_add_mod(&n_minus_1, &[2, 0, 0, 0], &SECP256K1_N);
        assert_eq!(result, [1, 0, 0, 0]);

        // 简单: 3 + 5 = 8
        let result = host_add_mod(&[3, 0, 0, 0], &[5, 0, 0, 0], &SECP256K1_N);
        assert_eq!(result, [8, 0, 0, 0]);
    }

    #[test]
    fn test_host_sub_mod() {
        // (1 - 2) mod p = p - 1
        let result = host_sub_mod(&[1, 0, 0, 0], &[2, 0, 0, 0], &SECP256K1_P_CURVE);
        let expected = {
            let (d, _) = host_sub(&SECP256K1_P_CURVE, &[1, 0, 0, 0]);
            d
        };
        assert_eq!(result, expected);

        // (5 - 3) mod n = 2
        let result = host_sub_mod(&[5, 0, 0, 0], &[3, 0, 0, 0], &SECP256K1_N);
        assert_eq!(result, [2, 0, 0, 0]);
    }

    #[test]
    fn test_host_mul_mod() {
        // 3 * 5 = 15 mod n
        let result = host_mul_mod(&[3, 0, 0, 0], &[5, 0, 0, 0], &SECP256K1_N);
        assert_eq!(result, [15, 0, 0, 0]);

        // (p-1) * (p-1) mod p = 1 (since (p-1)^2 = p^2 - 2p + 1 ≡ 1 mod p)
        let p_minus_1 = {
            let (d, _) = host_sub(&SECP256K1_P_CURVE, &[1, 0, 0, 0]);
            d
        };
        let result = host_mul_mod(&p_minus_1, &p_minus_1, &SECP256K1_P_CURVE);
        assert_eq!(result, [1, 0, 0, 0]);
    }

    #[test]
    fn test_host_inv_mod() {
        // 3 * 3^(-1) mod n = 1
        let inv = host_inv_mod(&[3, 0, 0, 0], &SECP256K1_N);
        let product = host_mul_mod(&[3, 0, 0, 0], &inv, &SECP256K1_N);
        assert_eq!(product, [1, 0, 0, 0]);

        // p-1 的逆 = p-1 (since (p-1)^2 ≡ 1 mod p)
        let p_minus_1 = {
            let (d, _) = host_sub(&SECP256K1_P_CURVE, &[1, 0, 0, 0]);
            d
        };
        let inv = host_inv_mod(&p_minus_1, &SECP256K1_P_CURVE);
        assert_eq!(inv, p_minus_1);
    }

    #[test]
    fn test_nonnative_add_mod() {
        let mut builder = NonNativeBuilder::new();

        // a = 3, b = 5, modulus = n
        let a = builder.from_u256(&[3, 0, 0, 0]);
        let b = builder.from_u256(&[5, 0, 0, 0]);
        let result = builder.add_mod(&a, &b, &SECP256K1_N);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");

        // 验证 witness
        assert_eq!(witness.len(), ccs.num_vars);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        // 验证 result = 8
        let result_u256 = fr_limbs_to_u256(&[
            witness[result.limbs[0]],
            witness[result.limbs[1]],
            witness[result.limbs[2]],
            witness[result.limbs[3]],
        ]);
        assert_eq!(result_u256, [8, 0, 0, 0]);
    }

    #[test]
    fn test_nonnative_sub_mod() {
        let mut builder = NonNativeBuilder::new();

        // a = 5, b = 3, modulus = n → result = 2
        let a = builder.from_u256(&[5, 0, 0, 0]);
        let b = builder.from_u256(&[3, 0, 0, 0]);
        let result = builder.sub_mod(&a, &b, &SECP256K1_N);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");

        assert_eq!(witness.len(), ccs.num_vars);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        let result_u256 = fr_limbs_to_u256(&[
            witness[result.limbs[0]],
            witness[result.limbs[1]],
            witness[result.limbs[2]],
            witness[result.limbs[3]],
        ]);
        assert_eq!(result_u256, [2, 0, 0, 0]);
    }

    #[test]
    fn test_nonnative_mul_mod() {
        let mut builder = NonNativeBuilder::new();

        // a = 3, b = 5, modulus = n → result = 15
        let a = builder.from_u256(&[3, 0, 0, 0]);
        let b = builder.from_u256(&[5, 0, 0, 0]);
        let result = builder.mul_mod(&a, &b, &SECP256K1_N);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");

        assert_eq!(witness.len(), ccs.num_vars);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        let result_u256 = fr_limbs_to_u256(&[
            witness[result.limbs[0]],
            witness[result.limbs[1]],
            witness[result.limbs[2]],
            witness[result.limbs[3]],
        ]);
        assert_eq!(result_u256, [15, 0, 0, 0]);
    }

    #[test]
    fn test_nonnative_assert_equal() {
        let mut builder = NonNativeBuilder::new();

        let a = builder.from_u256(&[42, 0, 0, 0]);
        let b = builder.from_u256(&[42, 0, 0, 0]);
        builder.assert_equal(&a, &b);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    #[test]
    fn test_nonnative_assert_lt() {
        let mut builder = NonNativeBuilder::new();

        // val = 3, bound = n → 3 < n 应满足
        let val = builder.from_u256(&[3, 0, 0, 0]);
        builder.assert_lt(&val, &SECP256K1_N);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    #[test]
    fn test_nonnative_mul_mod_large() {
        let mut builder = NonNativeBuilder::new();

        // a = p-1, b = p-1, modulus = p → result = 1
        let p_minus_1 = {
            let (d, _) = host_sub(&SECP256K1_P_CURVE, &[1, 0, 0, 0]);
            d
        };
        let a = builder.from_u256(&p_minus_1);
        let b = builder.from_u256(&p_minus_1);
        let result = builder.mul_mod(&a, &b, &SECP256K1_P_CURVE);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");

        assert_eq!(witness.len(), ccs.num_vars);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        let result_u256 = fr_limbs_to_u256(&[
            witness[result.limbs[0]],
            witness[result.limbs[1]],
            witness[result.limbs[2]],
            witness[result.limbs[3]],
        ]);
        assert_eq!(result_u256, [1, 0, 0, 0], "(p-1)*(p-1) mod p = 1");
    }

    #[test]
    fn test_nonnative_mul_mod_gx() {
        // Test mul_mod with actual GX values (used by secp256k1_ops)
        let mut builder = NonNativeBuilder::new();
        let a = builder.from_u256(&SECP256K1_GX);
        let b = builder.from_u256(&SECP256K1_GX);
        let result = builder.mul_mod(&a, &b, &SECP256K1_P_CURVE);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");

        assert_eq!(witness.len(), ccs.num_vars);
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "GX*GX mod p constraints should be satisfied"
        );

        // Verify result matches host computation
        let expected = host_mul_mod(&SECP256K1_GX, &SECP256K1_GX, &SECP256K1_P_CURVE);
        let result_u256 = fr_limbs_to_u256(&[
            witness[result.limbs[0]],
            witness[result.limbs[1]],
            witness[result.limbs[2]],
            witness[result.limbs[3]],
        ]);
        assert_eq!(result_u256, expected, "GX*GX mod p should match host");
    }

    #[test]
    fn test_nonnative_mul_mod_mixed() {
        // Test with mixed-size values: small * large
        let mut builder = NonNativeBuilder::new();
        let a = builder.from_u256(&[3, 0, 0, 0]);
        let b = builder.from_u256(&SECP256K1_GY);
        let result = builder.mul_mod(&a, &b, &SECP256K1_P_CURVE);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");

        assert_eq!(witness.len(), ccs.num_vars);
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "3*GY mod p constraints should be satisfied"
        );

        // Verify result matches host computation
        let expected = host_mul_mod(&[3, 0, 0, 0], &SECP256K1_GY, &SECP256K1_P_CURVE);
        let result_u256 = fr_limbs_to_u256(&[
            witness[result.limbs[0]],
            witness[result.limbs[1]],
            witness[result.limbs[2]],
            witness[result.limbs[3]],
        ]);
        assert_eq!(result_u256, expected, "3*GY mod p should match host");
    }

    #[test]
    fn test_nonnative_mul_mod_gx_gy() {
        // Test mul_mod with GX*GY (different values, not same)
        let mut builder = NonNativeBuilder::new();
        let a = builder.from_u256(&SECP256K1_GX);
        let b = builder.from_u256(&SECP256K1_GY);
        let result = builder.mul_mod(&a, &b, &SECP256K1_P_CURVE);

        let witness = builder.witness.clone();
        let ccs = builder.build().expect("build 应成功");

        assert_eq!(witness.len(), ccs.num_vars);
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        let expected = host_mul_mod(&SECP256K1_GX, &SECP256K1_GY, &SECP256K1_P_CURVE);
        let result_u256 = fr_limbs_to_u256(&[
            witness[result.limbs[0]],
            witness[result.limbs[1]],
            witness[result.limbs[2]],
            witness[result.limbs[3]],
        ]);
        assert_eq!(result_u256, expected, "GX*GY mod p should match host");
    }

    #[test]
    fn test_mul_big_circuit_vs_host_gx() {
        // Compare mul_big_circuit output with host_mul_big for GX*GX
        let mut builder = NonNativeBuilder::new();
        let a = builder.from_u256(&SECP256K1_GX);
        let b = builder.from_u256(&SECP256K1_GX);
        let ab_limbs = builder.mul_big_circuit(&a, &b);

        let witness = builder.witness.clone();

        // Expected from host
        let expected = host_mul_big(&SECP256K1_GX, &SECP256K1_GX);

        for k in 0..8 {
            let circuit_val = witness[ab_limbs[k]];
            let bytes = circuit_val.to_canonical_bytes();
            let circuit_u64 = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
            assert_eq!(
                circuit_u64, expected[k],
                "mul_big_circuit limb {} mismatch: circuit={}, host={}",
                k, circuit_u64, expected[k]
            );
        }
    }

    #[test]
    fn test_host_div_mod_gx_verification() {
        // Verify host_div_mod returns correct q, r for GX*GX
        let product = host_mul_big(&SECP256K1_GX, &SECP256K1_GX);
        let (q, r) = host_div_mod(&product, &SECP256K1_P_CURVE);

        // Verify: q * p + r == product (512-bit)
        let qm = host_mul_big(&q, &SECP256K1_P_CURVE);
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
        assert_eq!(carry, 0, "q*p + r should fit in 512 bits");
        assert_eq!(sum, product, "q*p + r must equal product");
        assert!(host_lt(&r, &SECP256K1_P_CURVE), "r < p must hold");
    }

    #[test]
    fn test_host_div_mod_gx_gy_verification() {
        // Verify host_div_mod returns correct q, r for GX*GY
        let product = host_mul_big(&SECP256K1_GX, &SECP256K1_GY);
        let (q, r) = host_div_mod(&product, &SECP256K1_P_CURVE);

        let qm = host_mul_big(&q, &SECP256K1_P_CURVE);
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
        assert_eq!(carry, 0, "q*p + r should fit in 512 bits");
        assert_eq!(sum, product, "q*p + r must equal product");
        assert!(host_lt(&r, &SECP256K1_P_CURVE), "r < p must hold");
    }
}
