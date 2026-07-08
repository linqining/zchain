//! 算术指令子电路（Phase 5 — Task 5.2）。
//!
//! 严格遵循 spec.md L105-139（v1.4 FROZEN）：
//! - ADD/ADDI — u32 加法 + overflow_bit 约束
//! - SUB — u32 减法 + borrow_bit 约束
//! - AND/OR/XOR — 位运算（MVP: 域元素级约束；完整实现需 LogUp 真值表，Step 13）
//! - SLT/SLTU — 比较电路（MVP: 借用 SUB 的 borrow 逻辑）
//! - SLL/SRL/SRA — 移位（MVP: stub，需 bit decomposition，Step 13）
//! - DIV/DIVU/REM/REMU — 除法（MVP: stub，需 RV32M 软件库，Phase 11）
//!
//! ## MVP 策略
//!
//! 每条指令实现核心约束（加/减/位运算语义），range check 留给 Step 13 LogUp。
//! witness 布局统一为 `[1, a, b, result, flag]`（flag = overflow/borrow/carry）。

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;

/// 2^32 作为域元素（u32 overflow 边界）。
fn two_pow_32() -> Fr {
    Fr::from_u64(1u64 << 32)
}

// ===========================================================================
// ADD 子电路（Task 5.2.1）
// ===========================================================================

/// ADD 子电路构建器（a + b = result, 含 overflow_bit）。
///
/// witness: `z = [1, a, b, result, overflow_bit]`（长度 5）
///
/// 约束（2 行）：
/// - Row 0: `a + b - result - 2^32 * overflow_bit = 0`（加法语义）
/// - Row 1: `overflow_bit² - overflow_bit = 0`（bit 范围检查）
///
/// 矩阵（6 个，每个 2×5，行隔离）：
/// - M_a: (0,1)=+1
/// - M_b: (0,2)=+1
/// - M_result: (0,3)=-1
/// - M_ovf: (0,4)=-2^32
/// - M_bit_pos: (1,4)=+1（用于 overflow_bit²）
/// - M_bit_neg: (1,4)=-1（用于 -overflow_bit）
pub struct AddCircuit;

impl AddCircuit {
    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 5;
        let num_rows = 2;

        let mut m_a = SparseMatrix::new(num_rows, num_vars);
        m_a.add_entry(0, 1, Fr::one()).expect("M_a");

        let mut m_b = SparseMatrix::new(num_rows, num_vars);
        m_b.add_entry(0, 2, Fr::one()).expect("M_b");

        let mut m_result = SparseMatrix::new(num_rows, num_vars);
        m_result.add_entry(0, 3, Fr::zero().sub(&Fr::one())).expect("M_result");

        let mut m_ovf = SparseMatrix::new(num_rows, num_vars);
        m_ovf.add_entry(0, 4, Fr::zero().sub(&two_pow_32())).expect("M_ovf");

        let mut m_bit_pos = SparseMatrix::new(num_rows, num_vars);
        m_bit_pos.add_entry(1, 4, Fr::one()).expect("M_bit_pos");

        let mut m_bit_neg = SparseMatrix::new(num_rows, num_vars);
        m_bit_neg.add_entry(1, 4, Fr::zero().sub(&Fr::one())).expect("M_bit_neg");

        Ccs::new(
            num_vars,
            vec![m_a, m_b, m_result, m_ovf, m_bit_pos, m_bit_neg],
            vec![
                vec![0],       // S_0: +a
                vec![1],       // S_1: +b
                vec![2],       // S_2: -result
                vec![3],       // S_3: -2^32 * overflow_bit
                vec![4, 4],    // S_4: +overflow_bit²
                vec![5],       // S_5: -overflow_bit
            ],
            vec![
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
            ],
        )
        .expect("AddCircuit CCS 构造应成功")
    }

    /// 赋值 witness（从 u32 输入计算完整 witness）。
    ///
    /// # 参数
    /// - `a` — 加数
    /// - `b` — 被加数
    ///
    /// # 返回
    /// `z = [1, a_field, b_field, result_field, overflow_bit]`
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let a_field = Fr::from_u32_with_wrap(a);
        let b_field = Fr::from_u32_with_wrap(b);
        let result = a.wrapping_add(b);
        let result_field = Fr::from_u32_with_wrap(result);
        let overflow_bit = if (a as u64) + (b as u64) >= (1u64 << 32) {
            1u32
        } else {
            0u32
        };
        let ovf_field = Fr::from_u32_with_wrap(overflow_bit);

        vec![Fr::one(), a_field, b_field, result_field, ovf_field]
    }

    /// 构建完整 CCS 实例（约束 + witness + 公共输入）。
    ///
    /// # 参数
    /// - `a` — 加数
    /// - `b` — 被加数
    ///
    /// # 错误
    /// witness 长度不匹配返回 `ZkvmError`
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let result = a.wrapping_add(b);
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// SUB 子电路（Task 5.2.2）
// ===========================================================================

/// SUB 子电路构建器（a - b = result, 含 borrow_bit）。
///
/// witness: `z = [1, a, b, result, borrow_bit]`（长度 5）
///
/// 约束（2 行）：
/// - Row 0: `a - b - result + 2^32 * borrow_bit = 0`（减法语义）
///   - 当 a >= b: result = a - b, borrow = 0, 约束: a - b - (a-b) + 0 = 0 ✓
///   - 当 a < b: result = a - b + 2^32, borrow = 1, 约束: a - b - (a-b+2^32) + 2^32 = 0 ✓
/// - Row 1: `borrow_bit² - borrow_bit = 0`（bit 范围检查）
pub struct SubCircuit;

impl SubCircuit {
    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 5;
        let num_rows = 2;

        let mut m_a = SparseMatrix::new(num_rows, num_vars);
        m_a.add_entry(0, 1, Fr::one()).expect("M_a");

        let mut m_b = SparseMatrix::new(num_rows, num_vars);
        m_b.add_entry(0, 2, Fr::zero().sub(&Fr::one())).expect("M_b");

        let mut m_result = SparseMatrix::new(num_rows, num_vars);
        m_result.add_entry(0, 3, Fr::zero().sub(&Fr::one())).expect("M_result");

        let mut m_borrow = SparseMatrix::new(num_rows, num_vars);
        m_borrow.add_entry(0, 4, two_pow_32()).expect("M_borrow");

        let mut m_bit_pos = SparseMatrix::new(num_rows, num_vars);
        m_bit_pos.add_entry(1, 4, Fr::one()).expect("M_bit_pos");

        let mut m_bit_neg = SparseMatrix::new(num_rows, num_vars);
        m_bit_neg.add_entry(1, 4, Fr::zero().sub(&Fr::one())).expect("M_bit_neg");

        Ccs::new(
            num_vars,
            vec![m_a, m_b, m_result, m_borrow, m_bit_pos, m_bit_neg],
            vec![
                vec![0],       // S_0: +a
                vec![1],       // S_1: -b
                vec![2],       // S_2: -result
                vec![3],       // S_3: +2^32 * borrow_bit
                vec![4, 4],    // S_4: +borrow_bit²
                vec![5],       // S_5: -borrow_bit
            ],
            vec![
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
            ],
        )
        .expect("SubCircuit CCS 构造应成功")
    }

    /// 赋值 witness（从 u32 输入计算完整 witness）。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let a_field = Fr::from_u32_with_wrap(a);
        let b_field = Fr::from_u32_with_wrap(b);
        let result = a.wrapping_sub(b);
        let result_field = Fr::from_u32_with_wrap(result);
        let borrow_bit = if a < b { 1u32 } else { 0u32 };
        let borrow_field = Fr::from_u32_with_wrap(borrow_bit);

        vec![Fr::one(), a_field, b_field, result_field, borrow_field]
    }

    /// 构建完整 CCS 实例。
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let result = a.wrapping_sub(b);
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// AND / OR / XOR 子电路（Task 5.2.4 — MVP）
// ===========================================================================

/// AND 子电路（MVP: 域元素级约束）。
///
/// MVP 策略：直接约束 `result = a AND b`（通过 witness 赋值验证）。
/// 完整实现需 bit decomposition + LogUp 真值表（Step 13）。
///
/// witness: `z = [1, a, b, result]`（长度 4）
/// 约束（1 行）：`result - (a AND b) = 0`
/// - 由于 AND 是位运算，无法直接用域算术表达。
/// - MVP: 使用 witness 赋值 + 约束 `result = witness_computed_and`（信任 witness，完整 soundness 需 Step 13）
pub struct AndCircuit;

impl AndCircuit {
    /// 构建 CCS 约束结构（MVP: 单约束 result - computed = 0）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 4;
        let num_rows = 1;

        let mut m_result = SparseMatrix::new(num_rows, num_vars);
        m_result.add_entry(0, 3, Fr::one()).expect("M_result");

        let mut m_computed = SparseMatrix::new(num_rows, num_vars);
        m_computed.add_entry(0, 3, Fr::zero().sub(&Fr::one())).expect("M_computed");

        // MVP: result - result = 0（trivially satisfied，soundness 依赖 witness 赋值）
        // 完整实现需 bit decomposition（Step 13）
        Ccs::new(
            num_vars,
            vec![m_result, m_computed],
            vec![vec![0], vec![1]],
            vec![Fr::one(), Fr::one()],
        )
        .expect("AndCircuit CCS 构造应成功")
    }

    /// 赋值 witness。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let result = a & b;
        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ]
    }

    /// 构建完整 CCS 实例。
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let result = a & b;
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

/// OR 子电路（MVP: 域元素级约束）。
pub struct OrCircuit;

impl OrCircuit {
    /// 构建 CCS 约束结构（MVP）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        AndCircuit::build_ccs()
    }

    /// 赋值 witness。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let result = a | b;
        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ]
    }

    /// 构建完整 CCS 实例。
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let result = a | b;
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

/// XOR 子电路（MVP: 域元素级约束）。
pub struct XorCircuit;

impl XorCircuit {
    /// 构建 CCS 约束结构（MVP）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        AndCircuit::build_ccs()
    }

    /// 赋值 witness。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let result = a ^ b;
        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ]
    }

    /// 构建完整 CCS 实例。
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let result = a ^ b;
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ===== ADD 测试 =====

    #[test]
    fn test_add_build_ccs() {
        let ccs = AddCircuit::build_ccs();
        assert_eq!(ccs.num_vars, 5);
        assert_eq!(ccs.num_matrices(), 6);
        assert_eq!(ccs.num_rows(), 2);
        assert_eq!(ccs.num_constraints(), 6);
    }

    #[test]
    fn test_add_no_overflow() {
        let ccs = AddCircuit::build_ccs();
        let witness = AddCircuit::assign_witness(100, 200);
        assert_eq!(witness.len(), 5);
        assert_eq!(witness[0], Fr::one());
        // overflow_bit = 0
        assert_eq!(witness[4], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_add_with_overflow() {
        let ccs = AddCircuit::build_ccs();
        let witness = AddCircuit::assign_witness(u32::MAX, 1);
        // 0xFFFFFFFF + 1 = 0x100000000, result = 0, overflow = 1
        assert_eq!(witness[3], Fr::zero()); // result = 0
        assert_eq!(witness[4], Fr::one()); // overflow_bit = 1
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_add_large_overflow() {
        let ccs = AddCircuit::build_ccs();
        let a = 0x80000000u32;
        let b = 0x80000000u32;
        let witness = AddCircuit::assign_witness(a, b);
        // 0x80000000 + 0x80000000 = 0x100000000, result = 0, overflow = 1
        assert_eq!(witness[3], Fr::zero());
        assert_eq!(witness[4], Fr::one());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_add_soundness_tampered_overflow_bit() {
        let ccs = AddCircuit::build_ccs();
        let mut witness = AddCircuit::assign_witness(u32::MAX, 1);
        // 篡改 overflow_bit 为 0（应不满足）
        witness[4] = Fr::zero();
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_add_soundness_tampered_result() {
        let ccs = AddCircuit::build_ccs();
        let mut witness = AddCircuit::assign_witness(100, 200);
        // 篡改 result（应不满足）
        witness[3] = Fr::from_u32_with_wrap(999);
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_add_soundness_non_binary_overflow() {
        let ccs = AddCircuit::build_ccs();
        let mut witness = AddCircuit::assign_witness(100, 200);
        // 篡改 overflow_bit 为 2（非 0/1，bit 约束应失败）
        witness[4] = Fr::from_u32_with_wrap(2);
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_add_to_instance() {
        let inst = AddCircuit::to_instance(42, 58).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs.len(), 3);
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(100)); // result
    }

    #[test]
    fn test_add_zero_identity() {
        let ccs = AddCircuit::build_ccs();
        let witness = AddCircuit::assign_witness(0, 42);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(42));
        assert_eq!(witness[4], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    // ===== SUB 测试 =====

    #[test]
    fn test_sub_build_ccs() {
        let ccs = SubCircuit::build_ccs();
        assert_eq!(ccs.num_vars, 5);
        assert_eq!(ccs.num_matrices(), 6);
        assert_eq!(ccs.num_rows(), 2);
    }

    #[test]
    fn test_sub_no_borrow() {
        let ccs = SubCircuit::build_ccs();
        let witness = SubCircuit::assign_witness(200, 100);
        // 200 - 100 = 100, borrow = 0
        assert_eq!(witness[3], Fr::from_u32_with_wrap(100));
        assert_eq!(witness[4], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_sub_with_borrow() {
        let ccs = SubCircuit::build_ccs();
        let witness = SubCircuit::assign_witness(100, 200);
        // 100 - 200 = -100, result = 2^32 - 100 = 4294967196, borrow = 1
        let expected = 100u32.wrapping_sub(200);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(expected));
        assert_eq!(witness[4], Fr::one());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_sub_zero_result() {
        let ccs = SubCircuit::build_ccs();
        let witness = SubCircuit::assign_witness(42, 42);
        assert_eq!(witness[3], Fr::zero());
        assert_eq!(witness[4], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_sub_soundness_tampered_borrow() {
        let ccs = SubCircuit::build_ccs();
        let mut witness = SubCircuit::assign_witness(100, 200);
        witness[4] = Fr::zero(); // 篡改 borrow_bit
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_sub_soundness_tampered_result() {
        let ccs = SubCircuit::build_ccs();
        let mut witness = SubCircuit::assign_witness(200, 100);
        witness[3] = Fr::from_u32_with_wrap(999);
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_sub_to_instance() {
        let inst = SubCircuit::to_instance(100, 30).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(70));
    }

    // ===== AND/OR/XOR 测试 =====

    #[test]
    fn test_and_basic() {
        let ccs = AndCircuit::build_ccs();
        let witness = AndCircuit::assign_witness(0xF0F0, 0xFF00);
        // 0xF0F0 & 0xFF00 = 0xF000
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0xF000));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_and_zero() {
        let ccs = AndCircuit::build_ccs();
        let witness = AndCircuit::assign_witness(0, 0xFFFFFFFF);
        assert_eq!(witness[3], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_and_identity() {
        let ccs = AndCircuit::build_ccs();
        let witness = AndCircuit::assign_witness(0xDEADBEEF, 0xFFFFFFFF);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0xDEADBEEF));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_or_basic() {
        let ccs = OrCircuit::build_ccs();
        let witness = OrCircuit::assign_witness(0xF0F0, 0x0F0F);
        // 0xF0F0 | 0x0F0F = 0xFFFF
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0xFFFF));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_or_zero_identity() {
        let ccs = OrCircuit::build_ccs();
        let witness = OrCircuit::assign_witness(0, 0xABCD);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0xABCD));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_xor_basic() {
        let ccs = XorCircuit::build_ccs();
        let witness = XorCircuit::assign_witness(0xFF00, 0xF0F0);
        // 0xFF00 ^ 0xF0F0 = 0x0FF0
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0x0FF0));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_xor_self_zero() {
        let ccs = XorCircuit::build_ccs();
        let witness = XorCircuit::assign_witness(0xDEADBEEF, 0xDEADBEEF);
        // a ^ a = 0
        assert_eq!(witness[3], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_xor_zero_identity() {
        let ccs = XorCircuit::build_ccs();
        let witness = XorCircuit::assign_witness(0, 0xCAFE);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0xCAFE));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_and_to_instance() {
        let inst = AndCircuit::to_instance(0xFF, 0x0F).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0x0F));
    }

    #[test]
    fn test_or_to_instance() {
        let inst = OrCircuit::to_instance(0xFF, 0x0F).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0xFF));
    }

    #[test]
    fn test_xor_to_instance() {
        let inst = XorCircuit::to_instance(0xFF, 0x0F).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0xF0));
    }

    // ===== 综合测试 =====

    #[test]
    fn test_add_sub_consistency() {
        // ADD(a, b) 的 result = sum; SUB(sum, b) 的 result 应 = a
        let a = 100u32;
        let b = 200u32;
        let sum = a.wrapping_add(b);

        let add_inst = AddCircuit::to_instance(a, b).expect("ADD");
        let sub_inst = SubCircuit::to_instance(sum, b).expect("SUB");

        assert!(add_inst.is_satisfied().expect("ADD 应满足"));
        assert!(sub_inst.is_satisfied().expect("SUB 应满足"));

        // ADD 的 result (sum) == SUB 的 a 输入
        assert_eq!(add_inst.witness[3], sub_inst.witness[1]);
        // SUB 的 result == 原始 a
        assert_eq!(sub_inst.witness[3], Fr::from_u32_with_wrap(a));
    }
}
