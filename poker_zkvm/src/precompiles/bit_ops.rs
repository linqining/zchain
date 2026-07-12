//! Bit 级操作工具（Stage 3 — Phase B1）。
//!
//! 提供 SHA-256 电路所需的 bit 级 CCS 约束构建工具。所有操作基于 [`CcsBuilder`]，
//! 返回变量索引，供 [`crate::precompiles::sha256`] 完整模式使用。
//!
//! # Bit 表示
//!
//! 每个 32-bit 字表示为 32 个独立 bit 变量（域元素 ∈ {0, 1}）。
//! [`bit_decompose`] 通过 `bit_check` 约束确保每个变量为 bit，并通过 linear 约束
//! 验证 recompose `sum(bit_i * 2^i) = val`。
//!
//! # 约束计数（per 32-bit 操作，按行数计）
//!
//! | 操作 | 行数 | 说明 |
//! |------|------|------|
//! | `bit_decompose` | 33 | 32 bit_check + 1 linear |
//! | `bit_xor` | 64 | 32 × (1 mult + 1 linear) |
//! | `bit_and` | 32 | 32 × 1 mult |
//! | `bit_or` | 64 | 32 × (1 mult + 1 linear) |
//! | `bit_not` | 32 | 32 × 1 linear |
//! | `bit_rotr` | 0 | 纯重排 |
//! | `bit_shr` | n | n 个零填充 linear |
//! | `add_mod_2_32` | 193 | 1 (carry_0=0) + 32 × 6 |
//! | `bit_recompose` | 1 | 1 linear |

use crate::ccs::Fr;
use crate::field::ZkvmField;
use crate::precompiles::ccs_builder::CcsBuilder;

/// 预计算 2^i (i=0..31) 作为域元素，避免重复构造。
fn power_of_2(i: usize) -> Fr {
    Fr::from_u64(1u64 << i)
}

/// 将 `num_bits`-bit 域元素分解为 `num_bits` 个 bit 变量。
///
/// # 约束
/// - `num_bits` 个 `bit_check`（确保每个 bit ∈ {0, 1}）
/// - 1 个 `linear`（验证 recompose: `sum(bit_i * 2^i) - val_col = 0`）
///
/// # 参数
/// - `builder` — CCS 构建器
/// - `val_col` — 待分解的域元素变量索引
/// - `num_bits` — bit 数（通常 32）
///
/// # 返回
/// `num_bits` 个 bit 变量索引（bit_0 = LSB, bit_{n-1} = MSB）
pub fn bit_decompose(builder: &mut CcsBuilder, val_col: usize, num_bits: usize) -> Vec<usize> {
    let mut bits = Vec::with_capacity(num_bits);
    for _ in 0..num_bits {
        let bit = builder.alloc_var();
        let row = builder.alloc_row();
        builder.add_bit_check(row, bit);
        bits.push(bit);
    }

    // linear 约束: sum(bit_i * 2^i) - val_col = 0
    let row = builder.alloc_row();
    let mut terms = Vec::with_capacity(num_bits + 1);
    for (i, &bit) in bits.iter().enumerate() {
        terms.push((bit, power_of_2(i)));
    }
    terms.push((val_col, Fr::one().neg()));
    builder.add_linear(row, &terms);

    bits
}

/// 逐位 XOR：`result[i] = a[i] XOR b[i] = a[i] + b[i] - 2*a[i]*b[i]`。
///
/// # 约束（per bit）
/// - 1 `multiplication`：`a[i] * b[i] = ab`
/// - 1 `linear`：`a[i] + b[i] - 2*ab - result[i] = 0`
pub fn bit_xor(builder: &mut CcsBuilder, a_bits: &[usize], b_bits: &[usize]) -> Vec<usize> {
    assert_eq!(
        a_bits.len(),
        b_bits.len(),
        "bit_xor: a_bits.len() {} != b_bits.len() {}",
        a_bits.len(),
        b_bits.len()
    );
    let two = Fr::from_u64(2);

    let mut result = Vec::with_capacity(a_bits.len());
    for i in 0..a_bits.len() {
        let ab = builder.alloc_var();
        let r_mult = builder.alloc_row();
        builder.add_multiplication(r_mult, a_bits[i], b_bits[i], ab);

        let out = builder.alloc_var();
        let r_lin = builder.alloc_row();
        builder.add_linear(
            r_lin,
            &[
                (a_bits[i], Fr::one()),
                (b_bits[i], Fr::one()),
                (ab, two.neg()),
                (out, Fr::one().neg()),
            ],
        );
        result.push(out);
    }
    result
}

/// 逐位 AND：`result[i] = a[i] * b[i]`。
///
/// # 约束（per bit）
/// - 1 `multiplication`：`a[i] * b[i] = result[i]`
pub fn bit_and(builder: &mut CcsBuilder, a_bits: &[usize], b_bits: &[usize]) -> Vec<usize> {
    assert_eq!(
        a_bits.len(),
        b_bits.len(),
        "bit_and: a_bits.len() {} != b_bits.len() {}",
        a_bits.len(),
        b_bits.len()
    );

    let mut result = Vec::with_capacity(a_bits.len());
    for i in 0..a_bits.len() {
        let out = builder.alloc_var();
        let row = builder.alloc_row();
        builder.add_multiplication(row, a_bits[i], b_bits[i], out);
        result.push(out);
    }
    result
}

/// 逐位 OR：`result[i] = a[i] + b[i] - a[i]*b[i]`。
///
/// # 约束（per bit）
/// - 1 `multiplication`：`a[i] * b[i] = ab`
/// - 1 `linear`：`a[i] + b[i] - ab - result[i] = 0`
pub fn bit_or(builder: &mut CcsBuilder, a_bits: &[usize], b_bits: &[usize]) -> Vec<usize> {
    assert_eq!(
        a_bits.len(),
        b_bits.len(),
        "bit_or: a_bits.len() {} != b_bits.len() {}",
        a_bits.len(),
        b_bits.len()
    );

    let mut result = Vec::with_capacity(a_bits.len());
    for i in 0..a_bits.len() {
        let ab = builder.alloc_var();
        let r_mult = builder.alloc_row();
        builder.add_multiplication(r_mult, a_bits[i], b_bits[i], ab);

        let out = builder.alloc_var();
        let r_lin = builder.alloc_row();
        builder.add_linear(
            r_lin,
            &[
                (a_bits[i], Fr::one()),
                (b_bits[i], Fr::one()),
                (ab, Fr::one().neg()),
                (out, Fr::one().neg()),
            ],
        );
        result.push(out);
    }
    result
}

/// 按位取反：`result[i] = 1 - a[i]`。
///
/// # 约束（per bit）
/// - 1 `linear`：`1 - a[i] - result[i] = 0`（使用常数变量 0 表示 1）
pub fn bit_not(builder: &mut CcsBuilder, a_bits: &[usize]) -> Vec<usize> {
    let mut result = Vec::with_capacity(a_bits.len());
    for &a_bit in a_bits {
        let out = builder.alloc_var();
        let row = builder.alloc_row();
        // 1 - a[i] - result[i] = 0  →  (0, +1) + (a[i], -1) + (result[i], -1)
        builder.add_linear(
            row,
            &[
                (0, Fr::one()),
                (a_bit, Fr::one().neg()),
                (out, Fr::one().neg()),
            ],
        );
        result.push(out);
    }
    result
}

/// 循环右移：`result[i] = bits[(i + n) % num_bits]`。
///
/// 纯 witness 重排，无约束（仅返回重排后的变量索引）。
pub fn bit_rotr(bits: &[usize], n: usize, num_bits: usize) -> Vec<usize> {
    assert_eq!(
        bits.len(),
        num_bits,
        "bit_rotr: bits.len() {} != num_bits {}",
        bits.len(),
        num_bits
    );
    let n = n % num_bits;
    let mut result = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let src = (i + n) % num_bits;
        result.push(bits[src]);
    }
    result
}

/// 逻辑右移：`result[i] = bits[i + n]` if `i + n < num_bits`, else `0`。
///
/// 零填充位：分配新变量 + `linear` 约束 (`bit = 0`)。
pub fn bit_shr(builder: &mut CcsBuilder, bits: &[usize], n: usize, num_bits: usize) -> Vec<usize> {
    assert_eq!(
        bits.len(),
        num_bits,
        "bit_shr: bits.len() {} != num_bits {}",
        bits.len(),
        num_bits
    );

    let mut result = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        if i + n < num_bits {
            // 直接复用原变量（无约束）
            result.push(bits[i + n]);
        } else {
            // 零填充：分配新变量并约束为 0
            let zero_bit = builder.alloc_var();
            let row = builder.alloc_row();
            builder.add_linear(row, &[(zero_bit, Fr::one())]);
            result.push(zero_bit);
        }
    }
    result
}

/// 32-bit ripple-carry 加法器（mod 2^32）：`result = (a + b) mod 2^32`。
///
/// # 算法
/// ```text
/// carry_0 = 0
/// for i in 0..32:
///     p_i = a[i] * b[i]                    // AND (generate)
///     s_i = a[i] + b[i] - 2*p_i            // XOR (propagate)
///     sc_i = s[i] * carry[i]               // AND
///     sum[i] = s[i] + carry[i] - 2*sc_i    // XOR (sum bit)
///     psc = p[i] * sc[i]                   // AND
///     carry[i+1] = p[i] + sc[i] - psc      // OR (carry out)
/// carry_32 丢弃（mod 2^32）
/// ```
///
/// # 约束（per bit）
/// - 3 `multiplication`（p_i, sc_i, psc）
/// - 3 `linear`（s_i, sum_i, carry_{i+1}）
/// - 加上 carry_0 = 0 的 1 `linear`
pub fn add_mod_2_32(builder: &mut CcsBuilder, a_bits: &[usize], b_bits: &[usize]) -> Vec<usize> {
    assert_eq!(
        a_bits.len(),
        32,
        "add_mod_2_32: a_bits.len() {} != 32",
        a_bits.len()
    );
    assert_eq!(
        b_bits.len(),
        32,
        "add_mod_2_32: b_bits.len() {} != 32",
        b_bits.len()
    );

    let two = Fr::from_u64(2);

    // carry_0 = 0
    let mut carry = builder.alloc_var();
    let r_c0 = builder.alloc_row();
    builder.add_linear(r_c0, &[(carry, Fr::one())]);

    let mut sum_bits = Vec::with_capacity(32);
    for i in 0..32 {
        // p_i = a[i] * b[i]
        let p = builder.alloc_var();
        let r_p = builder.alloc_row();
        builder.add_multiplication(r_p, a_bits[i], b_bits[i], p);

        // s_i = a[i] + b[i] - 2*p_i  (XOR)
        let s = builder.alloc_var();
        let r_s = builder.alloc_row();
        builder.add_linear(
            r_s,
            &[
                (a_bits[i], Fr::one()),
                (b_bits[i], Fr::one()),
                (p, two.neg()),
                (s, Fr::one().neg()),
            ],
        );

        // sc_i = s[i] * carry[i]
        let sc = builder.alloc_var();
        let r_sc = builder.alloc_row();
        builder.add_multiplication(r_sc, s, carry, sc);

        // sum[i] = s[i] + carry[i] - 2*sc_i  (XOR)
        let sum = builder.alloc_var();
        let r_sum = builder.alloc_row();
        builder.add_linear(
            r_sum,
            &[
                (s, Fr::one()),
                (carry, Fr::one()),
                (sc, two.neg()),
                (sum, Fr::one().neg()),
            ],
        );
        sum_bits.push(sum);

        // psc = p[i] * sc[i]
        let psc = builder.alloc_var();
        let r_psc = builder.alloc_row();
        builder.add_multiplication(r_psc, p, sc, psc);

        // carry[i+1] = p[i] + sc[i] - psc  (OR)
        let next_carry = builder.alloc_var();
        let r_carry = builder.alloc_row();
        builder.add_linear(
            r_carry,
            &[
                (p, Fr::one()),
                (sc, Fr::one()),
                (psc, Fr::one().neg()),
                (next_carry, Fr::one().neg()),
            ],
        );
        carry = next_carry;
    }
    // carry_32 丢弃（mod 2^32）

    sum_bits
}

/// 将 bit 数组重组为域元素变量。
///
/// # 约束
/// - 1 `linear`：`val - sum(bit_i * 2^i) = 0`
///
/// # 返回
/// 新分配的 val 变量索引
pub fn bit_recompose(builder: &mut CcsBuilder, bits: &[usize]) -> usize {
    let val = builder.alloc_var();
    let row = builder.alloc_row();
    let mut terms = Vec::with_capacity(bits.len() + 1);
    for (i, &bit) in bits.iter().enumerate() {
        terms.push((bit, power_of_2(i)));
    }
    terms.push((val, Fr::one().neg()));
    builder.add_linear(row, &terms);
    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::Fr;
    use crate::field::ZkvmField;

    /// 辅助：将 u32 分解为 bit 数组（LSB first）
    fn u32_to_bits(val: u32, num_bits: usize) -> Vec<Fr> {
        (0..num_bits)
            .map(|i| Fr::from_u32_with_wrap((val >> i) & 1))
            .collect()
    }

    /// 辅助：将 bit 数组（LSB first）重组为 u32
    #[allow(dead_code)]
    fn bits_to_u32(bits: &[Fr]) -> u32 {
        let mut val = 0u32;
        for (i, bit) in bits.iter().enumerate() {
            if bit.to_u32() == 1 {
                val |= 1 << i;
            }
        }
        val
    }

    #[test]
    fn test_bit_decompose_correct() {
        let mut builder = CcsBuilder::new();
        let val = builder.alloc_var();
        let bits = bit_decompose(&mut builder, val, 32);
        assert_eq!(bits.len(), 32);

        let ccs = builder.build().expect("build 应成功");

        // 测试多个值
        for test_val in [0u32, 1, 0xDEADBEEF, 0xFFFFFFFF, 42, 0x80000000] {
            let val_fr = Fr::from_u32_with_wrap(test_val);
            let mut witness = vec![Fr::one(), val_fr];
            let bit_vals = u32_to_bits(test_val, 32);
            witness.extend_from_slice(&bit_vals);
            assert_eq!(witness.len(), ccs.num_vars);
            assert!(
                ccs.satisfied_by(&witness).expect("satisfied_by"),
                "u32={test_val:#x} 应满足约束"
            );
        }
    }

    #[test]
    fn test_bit_decompose_soundness() {
        let mut builder = CcsBuilder::new();
        let val = builder.alloc_var();
        let bits = bit_decompose(&mut builder, val, 32);
        let ccs = builder.build().expect("build 应成功");

        let test_val = 0xDEADBEEFu32;
        let val_fr = Fr::from_u32_with_wrap(test_val);
        let mut witness = vec![Fr::one(), val_fr];
        witness.extend_from_slice(&u32_to_bits(test_val, 32));

        // 篡改一个 bit（bit 0: 1 → 0，但 val 保持不变）
        let bit0_idx = 1 + 1; // z[0]=1, z[1]=val, z[2]=bit_0
        witness[bit0_idx] = Fr::from_u32_with_wrap(0);
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改 bit 后应不满足约束"
        );

        // 篡改 bit 为非 0/1 值
        let mut witness2 = vec![Fr::one(), val_fr];
        witness2.extend_from_slice(&u32_to_bits(test_val, 32));
        witness2[bit0_idx] = Fr::from_u32_with_wrap(2); // 非 bit
        assert!(
            !ccs.satisfied_by(&witness2).expect("satisfied_by"),
            "非 bit 值应不满足约束"
        );

        // 防止 unused warning
        let _ = bits.len();
    }

    #[test]
    fn test_bit_xor_correct() {
        let mut builder = CcsBuilder::new();
        let a_val = builder.alloc_var();
        let b_val = builder.alloc_var();
        let a_bits = bit_decompose(&mut builder, a_val, 32);
        let b_bits = bit_decompose(&mut builder, b_val, 32);
        let result_bits = bit_xor(&mut builder, &a_bits, &b_bits);
        let _result_val = bit_recompose(&mut builder, &result_bits);

        let ccs = builder.build().expect("build 应成功");

        for (a, b) in [
            (0u32, 0u32),
            (0xFFFFFFFF, 0),
            (0xDEADBEEF, 0xCAFEBABE),
            (0x12345678, 0x87654321),
            (0xFFFFFFFF, 0xFFFFFFFF),
        ] {
            let expected = a ^ b;
            let mut witness = vec![Fr::one()];
            witness.push(Fr::from_u32_with_wrap(a));
            witness.push(Fr::from_u32_with_wrap(b));
            witness.extend(u32_to_bits(a, 32));
            witness.extend(u32_to_bits(b, 32));
            // bit_xor allocates ab=a[i]*b[i] then result per bit (interleaved)
            let xor_bits = u32_to_bits(a ^ b, 32);
            for (i, &xor_bit) in xor_bits.iter().enumerate() {
                let ab = (a >> i) & 1 & ((b >> i) & 1);
                witness.push(Fr::from_u32_with_wrap(ab));
                witness.push(xor_bit);
            }
            witness.push(Fr::from_u32_with_wrap(expected));

            assert_eq!(witness.len(), ccs.num_vars);
            assert!(
                ccs.satisfied_by(&witness).expect("satisfied_by"),
                "XOR({a:#x}, {b:#x}) = {expected:#x} 应满足约束"
            );
        }
    }

    #[test]
    fn test_bit_and_correct() {
        let mut builder = CcsBuilder::new();
        let a_val = builder.alloc_var();
        let b_val = builder.alloc_var();
        let a_bits = bit_decompose(&mut builder, a_val, 32);
        let b_bits = bit_decompose(&mut builder, b_val, 32);
        let result_bits = bit_and(&mut builder, &a_bits, &b_bits);
        let _result_val = bit_recompose(&mut builder, &result_bits);

        let ccs = builder.build().expect("build 应成功");

        for (a, b) in [
            (0u32, 0u32),
            (0xFFFFFFFF, 0xFFFFFFFF),
            (0xDEADBEEF, 0xCAFEBABE),
            (0xFF00FF00, 0x00FF00FF),
        ] {
            let expected = a & b;
            let mut witness = vec![Fr::one()];
            witness.push(Fr::from_u32_with_wrap(a));
            witness.push(Fr::from_u32_with_wrap(b));
            witness.extend(u32_to_bits(a, 32));
            witness.extend(u32_to_bits(b, 32));
            witness.extend(u32_to_bits(a & b, 32));
            witness.push(Fr::from_u32_with_wrap(expected));

            assert_eq!(witness.len(), ccs.num_vars);
            assert!(
                ccs.satisfied_by(&witness).expect("satisfied_by"),
                "AND({a:#x}, {b:#x}) = {expected:#x} 应满足约束"
            );
        }
    }

    #[test]
    fn test_bit_or_correct() {
        let mut builder = CcsBuilder::new();
        let a_val = builder.alloc_var();
        let b_val = builder.alloc_var();
        let a_bits = bit_decompose(&mut builder, a_val, 32);
        let b_bits = bit_decompose(&mut builder, b_val, 32);
        let result_bits = bit_or(&mut builder, &a_bits, &b_bits);
        let _result_val = bit_recompose(&mut builder, &result_bits);

        let ccs = builder.build().expect("build 应成功");

        for (a, b) in [
            (0u32, 0u32),
            (0xFFFFFFFF, 0x00000000),
            (0xDEADBEEF, 0xCAFEBABE),
            (0xFF00FF00, 0x00FF00FF),
        ] {
            let expected = a | b;
            let mut witness = vec![Fr::one()];
            witness.push(Fr::from_u32_with_wrap(a));
            witness.push(Fr::from_u32_with_wrap(b));
            witness.extend(u32_to_bits(a, 32));
            witness.extend(u32_to_bits(b, 32));
            // bit_or allocates ab=a[i]*b[i] then result per bit (interleaved)
            let or_bits = u32_to_bits(a | b, 32);
            for (i, &or_bit) in or_bits.iter().enumerate() {
                let ab = (a >> i) & 1 & ((b >> i) & 1);
                witness.push(Fr::from_u32_with_wrap(ab));
                witness.push(or_bit);
            }
            witness.push(Fr::from_u32_with_wrap(expected));

            assert_eq!(witness.len(), ccs.num_vars);
            assert!(
                ccs.satisfied_by(&witness).expect("satisfied_by"),
                "OR({a:#x}, {b:#x}) = {expected:#x} 应满足约束"
            );
        }
    }

    #[test]
    fn test_bit_not_correct() {
        let mut builder = CcsBuilder::new();
        let a_val = builder.alloc_var();
        let a_bits = bit_decompose(&mut builder, a_val, 32);
        let result_bits = bit_not(&mut builder, &a_bits);
        let _result_val = bit_recompose(&mut builder, &result_bits);

        let ccs = builder.build().expect("build 应成功");

        for a in [0u32, 0xFFFFFFFF, 0xDEADBEEF, 0x12345678] {
            let expected = !a;
            let mut witness = vec![Fr::one()];
            witness.push(Fr::from_u32_with_wrap(a));
            witness.extend(u32_to_bits(a, 32));
            // NOT 结果
            let not_bits = u32_to_bits(!a, 32);
            witness.extend(not_bits);
            witness.push(Fr::from_u32_with_wrap(expected));

            assert_eq!(witness.len(), ccs.num_vars);
            assert!(
                ccs.satisfied_by(&witness).expect("satisfied_by"),
                "NOT({a:#x}) = {expected:#x} 应满足约束"
            );
        }
    }

    #[test]
    fn test_bit_rotr_correct() {
        // bit_rotr 是纯重排，不需要 builder
        let bits: Vec<usize> = (0..32).collect();
        let rotated = bit_rotr(&bits, 7, 32);
        assert_eq!(rotated.len(), 32);
        // result[i] = bits[(i + 7) % 32]
        for i in 0..32 {
            assert_eq!(rotated[i], bits[(i + 7) % 32]);
        }

        // n=0 应返回原序
        let rotated0 = bit_rotr(&bits, 0, 32);
        assert_eq!(rotated0, bits);

        // n=32 应等同于 n=0
        let rotated32 = bit_rotr(&bits, 32, 32);
        assert_eq!(rotated32, bits);

        // 验证 ROTR(x, n) 语义
        let test_val = 0xDEADBEEFu32;
        let bit_indices: Vec<usize> = (0..32).map(|i| ((test_val >> i) & 1) as usize).collect();
        let rotated_bits = bit_rotr(&bit_indices, 7, 32);
        let expected = test_val.rotate_right(7);
        let mut result = 0u32;
        for (i, &b) in rotated_bits.iter().enumerate() {
            if b == 1 {
                result |= 1 << i;
            }
        }
        assert_eq!(result, expected, "ROTR({test_val:#x}, 7) = {expected:#x}");
    }

    #[test]
    fn test_bit_shr_correct() {
        let mut builder = CcsBuilder::new();
        let val = builder.alloc_var();
        let bits = bit_decompose(&mut builder, val, 32);
        let shifted = bit_shr(&mut builder, &bits, 4, 32);
        let _result_val = bit_recompose(&mut builder, &shifted);

        let ccs = builder.build().expect("build 应成功");

        for test_val in [0u32, 0xFFFFFFFF, 0xDEADBEEF, 0x80000000] {
            let expected = test_val >> 4;
            let mut witness = vec![Fr::one()];
            witness.push(Fr::from_u32_with_wrap(test_val));
            witness.extend(u32_to_bits(test_val, 32));

            // SHR 填充 4 个零位（高位）
            // bit_shr 分配了 4 个新零变量（bit 28..31）
            // 其余 bit 0..27 直接复用原 bits[4..32]
            // 零变量的值 = 0
            for _ in 0..4 {
                witness.push(Fr::zero());
            }

            // 结果重组
            witness.push(Fr::from_u32_with_wrap(expected));

            // 验证 witness 长度
            assert_eq!(
                witness.len(),
                ccs.num_vars,
                "witness.len() {} != num_vars {}",
                witness.len(),
                ccs.num_vars
            );
            assert!(
                ccs.satisfied_by(&witness).expect("satisfied_by"),
                "SHR({test_val:#x}, 4) = {expected:#x} 应满足约束"
            );
        }
    }

    #[test]
    fn test_add_mod_2_32_no_overflow() {
        let mut builder = CcsBuilder::new();
        let a_val = builder.alloc_var();
        let b_val = builder.alloc_var();
        let a_bits = bit_decompose(&mut builder, a_val, 32);
        let b_bits = bit_decompose(&mut builder, b_val, 32);
        let sum_bits = add_mod_2_32(&mut builder, &a_bits, &b_bits);
        let _result_val = bit_recompose(&mut builder, &sum_bits);

        let ccs = builder.build().expect("build 应成功");

        for (a, b) in [
            (0u32, 0u32),
            (1u32, 2u32),
            (100u32, 200u32),
            (0x7FFFFFFF, 1u32),
            (0x80000000, 0x7FFFFFFF),
        ] {
            let expected = a.wrapping_add(b);
            let mut witness = vec![Fr::one()];
            witness.push(Fr::from_u32_with_wrap(a));
            witness.push(Fr::from_u32_with_wrap(b));
            witness.extend(u32_to_bits(a, 32));
            witness.extend(u32_to_bits(b, 32));

            // 计算 ripple-carry witness
            witness.push(Fr::zero()); // carry_0 = 0
            let mut carry = 0u32;
            for i in 0..32 {
                let a_bit = (a >> i) & 1;
                let b_bit = (b >> i) & 1;
                let p = a_bit & b_bit;
                let s = a_bit ^ b_bit;
                let sc = s & carry;
                let sum_bit = s ^ carry;
                let psc = p & sc;
                let next_carry = p | sc;
                witness.push(Fr::from_u32_with_wrap(p));
                witness.push(Fr::from_u32_with_wrap(s));
                witness.push(Fr::from_u32_with_wrap(sc));
                witness.push(Fr::from_u32_with_wrap(sum_bit));
                witness.push(Fr::from_u32_with_wrap(psc));
                witness.push(Fr::from_u32_with_wrap(next_carry));
                carry = next_carry;
            }
            witness.push(Fr::from_u32_with_wrap(expected));

            assert_eq!(
                witness.len(),
                ccs.num_vars,
                "a={a:#x}, b={b:#x}: witness.len() {} != num_vars {}",
                witness.len(),
                ccs.num_vars
            );
            assert!(
                ccs.satisfied_by(&witness).expect("satisfied_by"),
                "ADD({a:#x}, {b:#x}) = {expected:#x} 应满足约束"
            );
        }
    }

    #[test]
    fn test_add_mod_2_32_overflow() {
        let mut builder = CcsBuilder::new();
        let a_val = builder.alloc_var();
        let b_val = builder.alloc_var();
        let a_bits = bit_decompose(&mut builder, a_val, 32);
        let b_bits = bit_decompose(&mut builder, b_val, 32);
        let sum_bits = add_mod_2_32(&mut builder, &a_bits, &b_bits);
        let _result_val = bit_recompose(&mut builder, &sum_bits);

        let ccs = builder.build().expect("build 应成功");

        // 溢出测试：0xFFFFFFFF + 1 = 0 (mod 2^32)
        let (a, b) = (0xFFFFFFFFu32, 1u32);
        let expected = a.wrapping_add(b); // = 0
        assert_eq!(expected, 0);

        let mut witness = vec![Fr::one()];
        witness.push(Fr::from_u32_with_wrap(a));
        witness.push(Fr::from_u32_with_wrap(b));
        witness.extend(u32_to_bits(a, 32));
        witness.extend(u32_to_bits(b, 32));

        witness.push(Fr::zero()); // carry_0 = 0
        let mut carry = 0u32;
        for i in 0..32 {
            let a_bit = (a >> i) & 1;
            let b_bit = (b >> i) & 1;
            let p = a_bit & b_bit;
            let s = a_bit ^ b_bit;
            let sc = s & carry;
            let sum_bit = s ^ carry;
            let psc = p & sc;
            let next_carry = p | sc;
            witness.push(Fr::from_u32_with_wrap(p));
            witness.push(Fr::from_u32_with_wrap(s));
            witness.push(Fr::from_u32_with_wrap(sc));
            witness.push(Fr::from_u32_with_wrap(sum_bit));
            witness.push(Fr::from_u32_with_wrap(psc));
            witness.push(Fr::from_u32_with_wrap(next_carry));
            carry = next_carry;
        }
        witness.push(Fr::from_u32_with_wrap(expected));

        assert_eq!(witness.len(), ccs.num_vars);
        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by"),
            "ADD({a:#x}, {b:#x}) = {expected:#x} (overflow) 应满足约束"
        );
    }

    #[test]
    fn test_add_mod_2_32_soundness() {
        let mut builder = CcsBuilder::new();
        let a_val = builder.alloc_var();
        let b_val = builder.alloc_var();
        let a_bits = bit_decompose(&mut builder, a_val, 32);
        let b_bits = bit_decompose(&mut builder, b_val, 32);
        let sum_bits = add_mod_2_32(&mut builder, &a_bits, &b_bits);
        let _result_val = bit_recompose(&mut builder, &sum_bits);

        let ccs = builder.build().expect("build 应成功");

        let (a, b) = (100u32, 200u32);
        let expected = a.wrapping_add(b);

        let mut witness = vec![Fr::one()];
        witness.push(Fr::from_u32_with_wrap(a));
        witness.push(Fr::from_u32_with_wrap(b));
        witness.extend(u32_to_bits(a, 32));
        witness.extend(u32_to_bits(b, 32));

        witness.push(Fr::zero()); // carry_0 = 0
        let mut carry = 0u32;
        for i in 0..32 {
            let a_bit = (a >> i) & 1;
            let b_bit = (b >> i) & 1;
            let p = a_bit & b_bit;
            let s = a_bit ^ b_bit;
            let sc = s & carry;
            let sum_bit = s ^ carry;
            let psc = p & sc;
            let next_carry = p | sc;
            witness.push(Fr::from_u32_with_wrap(p));
            witness.push(Fr::from_u32_with_wrap(s));
            witness.push(Fr::from_u32_with_wrap(sc));
            witness.push(Fr::from_u32_with_wrap(sum_bit));
            witness.push(Fr::from_u32_with_wrap(psc));
            witness.push(Fr::from_u32_with_wrap(next_carry));
            carry = next_carry;
        }
        witness.push(Fr::from_u32_with_wrap(expected));

        // 原始 witness 应满足
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        // 篡改 sum bit 0
        // witness 结构: z[0]=1, z[1]=a, z[2]=b, z[3..35]=a_bits, z[35..67]=b_bits,
        // z[67]=carry_0, z[68]=p_0, z[69]=s_0, z[70]=sc_0, z[71]=sum_0
        let sum0_real_idx = 3 + 32 + 32 + 1 + 3; // = 71
        assert_eq!(sum0_real_idx, 71);

        // 篡改 sum[0]
        let original_sum0 = witness[sum0_real_idx];
        witness[sum0_real_idx] = Fr::from_u32_with_wrap(1 - original_sum0.to_u32());
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改 sum bit 后应不满足约束"
        );

        // 恢复
        witness[sum0_real_idx] = original_sum0;
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        // 篡改 result_val
        let result_idx = witness.len() - 1;
        witness[result_idx] = Fr::from_u32_with_wrap(expected.wrapping_add(1));
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改 result 后应不满足约束"
        );

        let _ = sum_bits;
    }

    #[test]
    fn test_bit_recompose_correct() {
        let mut builder = CcsBuilder::new();
        let bits: Vec<usize> = (0..32).map(|_| builder.alloc_var()).collect();
        let _val = bit_recompose(&mut builder, &bits);

        let ccs = builder.build().expect("build 应成功");

        for test_val in [0u32, 1, 0xDEADBEEF, 0xFFFFFFFF, 0x80000000] {
            let mut witness = vec![Fr::one()];
            witness.extend(u32_to_bits(test_val, 32));
            witness.push(Fr::from_u32_with_wrap(test_val));

            assert_eq!(witness.len(), ccs.num_vars);
            assert!(
                ccs.satisfied_by(&witness).expect("satisfied_by"),
                "recompose({test_val:#x}) 应满足约束"
            );
        }

        // 篡改 val 应失败
        let mut witness = vec![Fr::one()];
        witness.extend(u32_to_bits(0xDEADBEEF, 32));
        witness.push(Fr::from_u32_with_wrap(0xCAFEBABE));
        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by"),
            "篡改 val 后应不满足约束"
        );
    }
}
