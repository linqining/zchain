//! Modexp（大数模幂）预编译电路（Phase I — Batch 1）。
//!
//! # 两种模式
//!
//! - **MVP 模式**（`new()`）：验证 `base * exp = result mod modulus`（单次模乘）。
//! - **完整模式**（`new_full_with_bits(n)`）：square-and-multiply，n 位指数。
//!
//! # MVP 约束结构
//!
//! 使用 [`NonNativeBuilder::mul_mod`] 生成 hint-based 模乘约束，
//! 然后 `assert_equal(computed, result)` 验证结果正确性。
//!
//! # Full 模式约束结构（per bit）
//!
//! 1. `squared = mul_mod(acc, acc, modulus)` — 平方
//! 2. `temp = mul_mod(squared, base, modulus)` — 乘 base
//! 3. Conditional select: `acc = bit ? temp : squared`
//!    - `diff = temp - squared`（4 linear，逐 limb）
//!    - `bit_diff = bit * diff`（4 multiplication）
//!    - `new_acc = squared + bit_diff`（4 linear）
//!
//! 最终：`assert_equal(acc, result)`

// conditional_select 需同时索引 true_val/false_val 的 limbs，clippy needless_range_loop 建议不适用。
#![allow(clippy::needless_range_loop)]

use crate::ccs::{Ccs, CcsInstance, Fr};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::non_native::{NonNativeBuilder, NonNativeElement};
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// Modexp gas 常量（与 syscalls/gas.rs 对齐）。
const GAS_BASE: u64 = 50_000;
const GAS_PER_BIT: u64 = 600;

/// Modexp 预编译电路。
#[derive(Debug, Clone)]
pub struct ModexpCircuit {
    num_bits: usize,
    full_mode: bool,
}

impl ModexpCircuit {
    /// 创建 MVP 模式电路（单次模乘验证）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_bits: 0,
            full_mode: false,
        }
    }

    /// 创建 Full 模式电路（square-and-multiply，n 位指数）。
    #[must_use]
    pub fn new_full_with_bits(num_bits: usize) -> Self {
        assert!(num_bits > 0 && num_bits <= 64, "num_bits must be in (0, 64]");
        Self {
            num_bits,
            full_mode: true,
        }
    }

    /// 返回指数位数。
    #[must_use]
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// 是否为 Full 模式。
    #[must_use]
    pub fn is_full_mode(&self) -> bool {
        self.full_mode
    }

    // ===== MVP 模式 =====

    /// 运行 MVP 模式：验证 `base * exp = result mod modulus`。
    fn run_mvp(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 16 {
            return Err(ZkvmError::Other(format!(
                "ModexpCircuit (MVP): inputs.len() {} != 16 (base[4] + exp[4] + modulus[4] + result[4])",
                inputs.len()
            )));
        }

        let mut builder = NonNativeBuilder::new();

        // 分配 base, exp, modulus, result
        let base = builder.alloc_element([inputs[0], inputs[1], inputs[2], inputs[3]]);
        let exp = builder.alloc_element([inputs[4], inputs[5], inputs[6], inputs[7]]);
        let modulus_u256 = fr_slice_to_u256(&inputs[8..12]);
        let _modulus = builder.from_u256(&modulus_u256);
        let result = builder.alloc_element([inputs[12], inputs[13], inputs[14], inputs[15]]);

        // computed = base * exp mod modulus
        let computed = builder.mul_mod(&base, &exp, &modulus_u256);

        // assert_equal(computed, result)
        builder.assert_equal(&computed, &result);

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }

    // ===== Full 模式 =====

    /// 运行 Full 模式：square-and-multiply。
    fn run_full(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        if inputs.len() != 16 {
            return Err(ZkvmError::Other(format!(
                "ModexpCircuit (Full): inputs.len() {} != 16 (base[4] + exponent[4] + modulus[4] + result[4])",
                inputs.len()
            )));
        }

        let mut builder = NonNativeBuilder::new();

        // 分配 base, exponent, modulus, result
        let base = builder.alloc_element([inputs[0], inputs[1], inputs[2], inputs[3]]);
        let exponent = builder.alloc_element([inputs[4], inputs[5], inputs[6], inputs[7]]);
        let modulus_u256 = fr_slice_to_u256(&inputs[8..12]);
        let _modulus = builder.from_u256(&modulus_u256);
        let result = builder.alloc_element([inputs[12], inputs[13], inputs[14], inputs[15]]);

        // Bit-decompose exponent limb[0] into num_bits bits
        let exp_bits = bit_decompose_with_witness(&mut builder, exponent.limbs[0], self.num_bits);

        // acc = 1 (乘法单位元)
        let mut acc = builder.from_u256(&[1u64, 0, 0, 0]);

        // Square-and-multiply: MSB → LSB
        for i in (0..self.num_bits).rev() {
            // squared = acc² mod modulus
            let squared = builder.mul_mod(&acc, &acc, &modulus_u256);

            // temp = squared * base mod modulus
            let temp = builder.mul_mod(&squared, &base, &modulus_u256);

            // Conditional select: acc = bit[i] ? temp : squared
            // = squared + bit[i] * (temp - squared)
            acc = conditional_select(&mut builder, &exp_bits[i], &temp, &squared);
        }

        // assert_equal(acc, result)
        builder.assert_equal(&acc, &result);

        let witness = builder.witness.clone();
        let ccs = builder.build()?;
        Ok((ccs, witness))
    }
}

impl Default for ModexpCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for ModexpCircuit {
    fn name(&self) -> &str {
        "modexp"
    }

    fn num_variables(&self) -> usize {
        if self.full_mode {
            let dummy = vec![Fr::zero(); 16];
            self.run_full(&dummy).expect("dummy run_full should succeed").0.num_vars
        } else {
            let dummy = vec![Fr::zero(); 16];
            self.run_mvp(&dummy).expect("dummy run_mvp should succeed").0.num_vars
        }
    }

    fn build_ccs(&self) -> Ccs {
        let dummy = vec![Fr::zero(); 16];
        if self.full_mode {
            self.run_full(&dummy).expect("dummy run_full should succeed").0
        } else {
            self.run_mvp(&dummy).expect("dummy run_mvp should succeed").0
        }
    }

    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if self.full_mode {
            Ok(self.run_full(inputs)?.1)
        } else {
            Ok(self.run_mvp(inputs)?.1)
        }
    }

    fn gas_cost(&self) -> u64 {
        if self.full_mode {
            GAS_BASE + GAS_PER_BIT * self.num_bits as u64
        } else {
            GAS_BASE
        }
    }
}

impl CcsCircuit for ModexpCircuit {
    fn name(&self) -> &str {
        "modexp"
    }

    fn num_matrices(&self) -> usize {
        let dummy = vec![Fr::zero(); 16];
        if self.full_mode {
            self.run_full(&dummy).expect("dummy run_full should succeed").0.num_matrices()
        } else {
            self.run_mvp(&dummy).expect("dummy run_mvp should succeed").0.num_matrices()
        }
    }

    fn to_ccs_instance(
        &self,
        witness: &[Fr],
        public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError> {
        let ccs = self.build_ccs();
        CcsInstance::new(ccs, witness.to_vec(), public_inputs.to_vec())
    }
}

// ===== 辅助函数 =====

/// 将 4 个 Fr 值转换为 [u64; 4]（用于 host 计算）。
fn fr_slice_to_u256(slice: &[Fr]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for i in 0..4 {
        let bytes = slice[i].to_canonical_bytes();
        result[i] = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
    }
    result
}

/// Bit 分解（带 witness 跟踪）。
///
/// 将 `var` 分解为 `num_bits` 个 bit 变量，同时设置 witness 值。
/// 约束：每个 bit 的 bit_check + recompose linear。
fn bit_decompose_with_witness(
    builder: &mut NonNativeBuilder,
    var: usize,
    num_bits: usize,
) -> Vec<usize> {
    let val = builder.get_val(var);
    let bytes = val.to_canonical_bytes();
    let u64_val = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));

    let mut bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let bit_val = Fr::from_u64((u64_val >> i) & 1);
        let bit = builder.alloc(bit_val);
        let row = builder.ccs.alloc_row();
        builder.ccs.add_bit_check(row, bit);
        bits.push(bit);
    }

    // recompose: sum(bit_i * 2^i) - var = 0
    let row = builder.ccs.alloc_row();
    let mut terms = Vec::with_capacity(num_bits + 1);
    for (i, &bit) in bits.iter().enumerate() {
        terms.push((bit, Fr::from_u64(1u64 << i)));
    }
    terms.push((var, Fr::one().neg()));
    builder.ccs.add_linear(row, &terms);

    bits
}

/// Conditional select: `result = bit ? true_val : false_val`
///
/// = `false_val + bit * (true_val - false_val)`
///
/// 对每个 limb 生成：1 linear（diff）+ 1 multiplication（bit*diff）+ 1 linear（result）
fn conditional_select(
    builder: &mut NonNativeBuilder,
    bit: &usize,
    true_val: &NonNativeElement,
    false_val: &NonNativeElement,
) -> NonNativeElement {
    let mut limbs = [0usize; 4];
    for k in 0..4 {
        let true_v = builder.get_val(true_val.limbs[k]);
        let false_v = builder.get_val(false_val.limbs[k]);

        // diff = true_val - false_val
        let diff_val = true_v.sub(&false_v);
        let diff_var = builder.alloc(diff_val);
        let row_diff = builder.ccs.alloc_row();
        builder.ccs.add_linear(row_diff, &[
            (diff_var, Fr::one()),
            (true_val.limbs[k], Fr::one().neg()),
            (false_val.limbs[k], Fr::one()),
        ]);

        // bit_diff = bit * diff
        let bit_diff_val = builder.get_val(*bit).mul(&diff_val);
        let bit_diff_var = builder.alloc(bit_diff_val);
        let row_bd = builder.ccs.alloc_row();
        builder.ccs.add_multiplication(row_bd, *bit, diff_var, bit_diff_var);

        // result = false_val + bit_diff
        let result_val = false_v.add(&bit_diff_val);
        let result_var = builder.alloc(result_val);
        let row_r = builder.ccs.alloc_row();
        builder.ccs.add_linear(row_r, &[
            (result_var, Fr::one()),
            (false_val.limbs[k], Fr::one().neg()),
            (bit_diff_var, Fr::one().neg()),
        ]);

        limbs[k] = result_var;
    }
    NonNativeElement { limbs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::ZkvmField;
    use crate::precompiles::non_native::host_pow_mod;

    /// 将 [u64; 4] 转为 Vec<Fr>（4 个 limb）
    fn u256_to_fr_vec(val: &[u64; 4]) -> Vec<Fr> {
        vec![
            Fr::from_u64(val[0]),
            Fr::from_u64(val[1]),
            Fr::from_u64(val[2]),
            Fr::from_u64(val[3]),
        ]
    }

    /// 构造 modexp 输入：[base(4), exp(4), modulus(4), result(4)]
    fn make_inputs(base: &[u64; 4], exp: &[u64; 4], modulus: &[u64; 4], result: &[u64; 4]) -> Vec<Fr> {
        let mut inputs = Vec::with_capacity(16);
        inputs.extend_from_slice(&u256_to_fr_vec(base));
        inputs.extend_from_slice(&u256_to_fr_vec(exp));
        inputs.extend_from_slice(&u256_to_fr_vec(modulus));
        inputs.extend_from_slice(&u256_to_fr_vec(result));
        inputs
    }

    // ===== MVP 测试 =====

    #[test]
    fn test_modexp_mvp_satisfied() {
        // 2 * 3 = 6 mod 7
        let base = [2u64, 0, 0, 0];
        let exp = [3u64, 0, 0, 0];
        let modulus = [7u64, 0, 0, 0];
        let result = [6u64, 0, 0, 0];

        let circuit = ModexpCircuit::new();
        let ccs = circuit.build_ccs();
        let witness = circuit
            .assign_witness(&make_inputs(&base, &exp, &modulus, &result))
            .expect("assign_witness should succeed");

        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by should succeed"),
            "2 * 3 = 6 mod 7 应满足约束"
        );
    }

    #[test]
    fn test_modexp_mvp_tampered_result() {
        let base = [2u64, 0, 0, 0];
        let exp = [3u64, 0, 0, 0];
        let modulus = [7u64, 0, 0, 0];
        let result = [5u64, 0, 0, 0]; // 篡改：应为 6

        let circuit = ModexpCircuit::new();
        let ccs = circuit.build_ccs();
        let witness = circuit
            .assign_witness(&make_inputs(&base, &exp, &modulus, &result))
            .expect("assign_witness should succeed");

        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by should succeed"),
            "篡改 result 后应不满足约束"
        );
    }

    // ===== Full 模式测试 =====

    #[test]
    fn test_modexp_full_8bit_satisfied() {
        // 2^10 = 1024 mod 1000000007
        let base = [2u64, 0, 0, 0];
        let exp = [10u64, 0, 0, 0];
        let modulus = [1000000007u64, 0, 0, 0];
        let result = host_pow_mod(&base, &exp, &modulus);
        assert_eq!(result, [1024u64, 0, 0, 0]);

        let circuit = ModexpCircuit::new_full_with_bits(8);
        let ccs = circuit.build_ccs();
        let witness = circuit
            .assign_witness(&make_inputs(&base, &exp, &modulus, &result))
            .expect("assign_witness should succeed");

        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by should succeed"),
            "2^10 = 1024 mod 1000000007 应满足约束"
        );
    }

    #[test]
    fn test_modexp_full_tampered_base() {
        let base = [2u64, 0, 0, 0];
        let exp = [10u64, 0, 0, 0];
        let modulus = [1000000007u64, 0, 0, 0];
        let result = host_pow_mod(&base, &exp, &modulus); // 1024

        // 篡改 base: 2 → 3
        let tampered_base = [3u64, 0, 0, 0];

        let circuit = ModexpCircuit::new_full_with_bits(8);
        let ccs = circuit.build_ccs();
        let witness = circuit
            .assign_witness(&make_inputs(&tampered_base, &exp, &modulus, &result))
            .expect("assign_witness should succeed");

        assert!(
            !ccs.satisfied_by(&witness).expect("satisfied_by should succeed"),
            "篡改 base 后应不满足约束"
        );
    }

    #[test]
    fn test_host_pow_mod() {
        // 2^10 mod 1000000007 = 1024
        let result = host_pow_mod(&[2, 0, 0, 0], &[10, 0, 0, 0], &[1000000007, 0, 0, 0]);
        assert_eq!(result, [1024, 0, 0, 0]);

        // 3^5 mod 7 = 243 mod 7 = 5
        let result = host_pow_mod(&[3, 0, 0, 0], &[5, 0, 0, 0], &[7, 0, 0, 0]);
        assert_eq!(result, [5, 0, 0, 0]);

        // 2^0 mod 7 = 1
        let result = host_pow_mod(&[2, 0, 0, 0], &[0, 0, 0, 0], &[7, 0, 0, 0]);
        assert_eq!(result, [1, 0, 0, 0]);

        // 5^1 mod 7 = 5
        let result = host_pow_mod(&[5, 0, 0, 0], &[1, 0, 0, 0], &[7, 0, 0, 0]);
        assert_eq!(result, [5, 0, 0, 0]);
    }

    #[test]
    fn test_modexp_gas_cost() {
        let mvp = ModexpCircuit::new();
        assert_eq!(mvp.gas_cost(), 50_000);

        let full8 = ModexpCircuit::new_full_with_bits(8);
        assert_eq!(full8.gas_cost(), 50_000 + 600 * 8);

        let full32 = ModexpCircuit::new_full_with_bits(32);
        assert_eq!(full32.gas_cost(), 50_000 + 600 * 32);
    }

    #[test]
    fn test_modexp_wrong_input_length() {
        let circuit = ModexpCircuit::new();
        let result = circuit.assign_witness(&[Fr::one()]);
        assert!(result.is_err());

        let full = ModexpCircuit::new_full_with_bits(8);
        let result = full.assign_witness(&[Fr::one()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_modexp_full_4bit_satisfied() {
        // 3^5 = 243 mod 7 = 5
        let base = [3u64, 0, 0, 0];
        let exp = [5u64, 0, 0, 0];
        let modulus = [7u64, 0, 0, 0];
        let result = host_pow_mod(&base, &exp, &modulus);
        assert_eq!(result, [5u64, 0, 0, 0]);

        let circuit = ModexpCircuit::new_full_with_bits(4);
        let ccs = circuit.build_ccs();
        let witness = circuit
            .assign_witness(&make_inputs(&base, &exp, &modulus, &result))
            .expect("assign_witness should succeed");

        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by should succeed"),
            "3^5 = 5 mod 7 应满足约束"
        );
    }

    #[test]
    fn test_modexp_full_exp_zero() {
        // 2^0 = 1 mod 7
        let base = [2u64, 0, 0, 0];
        let exp = [0u64, 0, 0, 0];
        let modulus = [7u64, 0, 0, 0];
        let result = [1u64, 0, 0, 0];

        let circuit = ModexpCircuit::new_full_with_bits(4);
        let ccs = circuit.build_ccs();
        let witness = circuit
            .assign_witness(&make_inputs(&base, &exp, &modulus, &result))
            .expect("assign_witness should succeed");

        assert!(
            ccs.satisfied_by(&witness).expect("satisfied_by should succeed"),
            "2^0 = 1 mod 7 应满足约束"
        );
    }
}
