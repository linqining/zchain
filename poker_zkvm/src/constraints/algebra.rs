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

/// 2^64 作为域元素（64-bit 乘积分解边界）。
/// 因 `1u64 << 64` 溢出 u64，改用 `(2^32)²` 计算。
fn two_pow_64() -> Fr {
    let t = two_pow_32();
    t.mul(&t)
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
// MUL / MULHU 子电路（Phase K — Task #5）
// ===========================================================================

/// MUL 子电路（a × b 的低 32 位）。
///
/// witness: `z = [1, a, b, product, hi, lo]`（长度 6）
/// - `product = (a as u64) * (b as u64)` — 64-bit 无符号乘积
/// - `hi = product >> 32`，`lo = product & 0xFFFFFFFF`
/// - MUL 结果 = lo
///
/// 约束（2 行）：
/// - Row 0: `a * b - product = 0`（乘法语义）
/// - Row 1: `product - hi * 2^32 - lo = 0`（64-bit 分解）
///
/// MULHU 共用此 CCS，仅 `to_instance` 的 public_inputs 不同（取 hi 而非 lo）。
pub struct MulCircuit;

impl MulCircuit {
    /// 构建 CCS 约束结构（MUL 和 MULHU 共用）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 6;
        let num_rows = 2;

        // Row 0: a * b - product = 0
        let mut m_a = SparseMatrix::new(num_rows, num_vars);
        m_a.add_entry(0, 1, Fr::one()).expect("M_a");

        let mut m_b = SparseMatrix::new(num_rows, num_vars);
        m_b.add_entry(0, 2, Fr::one()).expect("M_b");

        let mut m_prod_neg = SparseMatrix::new(num_rows, num_vars);
        m_prod_neg
            .add_entry(0, 3, Fr::zero().sub(&Fr::one()))
            .expect("M_prod_neg");

        // Row 1: product - hi*2^32 - lo = 0
        let mut m_prod_pos = SparseMatrix::new(num_rows, num_vars);
        m_prod_pos.add_entry(1, 3, Fr::one()).expect("M_prod_pos");

        let mut m_hi = SparseMatrix::new(num_rows, num_vars);
        m_hi.add_entry(1, 4, Fr::zero().sub(&two_pow_32()))
            .expect("M_hi");

        let mut m_lo = SparseMatrix::new(num_rows, num_vars);
        m_lo
            .add_entry(1, 5, Fr::zero().sub(&Fr::one()))
            .expect("M_lo");

        Ccs::new(
            num_vars,
            vec![m_a, m_b, m_prod_neg, m_prod_pos, m_hi, m_lo],
            vec![
                vec![0, 1], // S_0: +a*b (Row 0)
                vec![2],     // S_1: -product (Row 0)
                vec![3],     // S_2: +product (Row 1)
                vec![4],     // S_3: -2^32*hi (Row 1)
                vec![5],     // S_4: -lo (Row 1)
            ],
            vec![
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
            ],
        )
        .expect("MulCircuit CCS 构造应成功")
    }

    /// 赋值 witness（从 u32 输入计算完整 witness）。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let product = (a as u64) * (b as u64);
        let hi = (product >> 32) as u32;
        let lo = (product & 0xFFFFFFFF) as u32;
        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u64(product),
            Fr::from_u32_with_wrap(hi),
            Fr::from_u32_with_wrap(lo),
        ]
    }

    /// 构建完整 CCS 实例（MUL: result = lo）。
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let product = (a as u64) * (b as u64);
        let lo = (product & 0xFFFFFFFF) as u32;
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(lo),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

/// MULHU 子电路（a × b 的高 32 位，无符号×无符号）。
///
/// 共用 MulCircuit 的 `build_ccs()` 和 `assign_witness()`，
/// 仅 `to_instance()` 的 public_inputs 取 hi。
pub struct MulhuCircuit;

impl MulhuCircuit {
    /// 构建 CCS 约束结构（复用 MulCircuit）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        MulCircuit::build_ccs()
    }

    /// 赋值 witness（复用 MulCircuit）。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        MulCircuit::assign_witness(a, b)
    }

    /// 构建完整 CCS 实例（MULHU: result = hi）。
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let product = (a as u64) * (b as u64);
        let hi = (product >> 32) as u32;
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(hi),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// MULH 子电路（Phase K — Task #6：有符号×有符号 → 高 32 位）
// ===========================================================================

/// MULH 子电路（有符号 × 有符号 → 高 32 位）。
///
/// witness: `z = [1, a, b, prod, hi, lo, a_sign, b_sign, neg_sign]`（长度 9）
///
/// 约束（5 行）：
/// - Row 0: `a_sign² - a_sign = 0`（bit 检查）
/// - Row 1: `b_sign² - b_sign = 0`（bit 检查）
/// - Row 2: `neg_sign² - neg_sign = 0`（bit 检查）
/// - Row 3: `(a - 2^32*a_sign)*(b - 2^32*b_sign) - prod + 2^64*neg_sign = 0`
/// - Row 4: `prod - hi*2^32 - lo = 0`
pub struct MulhCircuit;

impl MulhCircuit {
    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 9;
        let num_rows = 5;
        let neg_one = Fr::zero().sub(&Fr::one());

        // Row 0: a_sign² - a_sign = 0
        let mut m_as_pos_r0 = SparseMatrix::new(num_rows, num_vars);
        m_as_pos_r0.add_entry(0, 6, Fr::one()).expect("M_as_pos_r0");
        let mut m_as_neg_r0 = SparseMatrix::new(num_rows, num_vars);
        m_as_neg_r0.add_entry(0, 6, neg_one).expect("M_as_neg_r0");

        // Row 1: b_sign² - b_sign = 0
        let mut m_bs_pos_r1 = SparseMatrix::new(num_rows, num_vars);
        m_bs_pos_r1.add_entry(1, 7, Fr::one()).expect("M_bs_pos_r1");
        let mut m_bs_neg_r1 = SparseMatrix::new(num_rows, num_vars);
        m_bs_neg_r1.add_entry(1, 7, neg_one).expect("M_bs_neg_r1");

        // Row 2: neg_sign² - neg_sign = 0
        let mut m_ns_pos_r2 = SparseMatrix::new(num_rows, num_vars);
        m_ns_pos_r2.add_entry(2, 8, Fr::one()).expect("M_ns_pos_r2");
        let mut m_ns_neg_r2 = SparseMatrix::new(num_rows, num_vars);
        m_ns_neg_r2.add_entry(2, 8, neg_one).expect("M_ns_neg_r2");

        // Row 3: (a - 2^32*a_sign)*(b - 2^32*b_sign) - prod + 2^64*neg_sign = 0
        // 展开: +a*b - 2^32*a*b_sign - 2^32*a_sign*b + 2^64*a_sign*b_sign - prod + 2^64*neg_sign
        let mut m_a_r3 = SparseMatrix::new(num_rows, num_vars);
        m_a_r3.add_entry(3, 1, Fr::one()).expect("M_a_r3");
        let mut m_b_r3 = SparseMatrix::new(num_rows, num_vars);
        m_b_r3.add_entry(3, 2, Fr::one()).expect("M_b_r3");
        let mut m_as_r3 = SparseMatrix::new(num_rows, num_vars);
        m_as_r3.add_entry(3, 6, Fr::one()).expect("M_as_r3");
        let mut m_bs_r3 = SparseMatrix::new(num_rows, num_vars);
        m_bs_r3.add_entry(3, 7, Fr::one()).expect("M_bs_r3");
        let mut m_prod_neg_r3 = SparseMatrix::new(num_rows, num_vars);
        m_prod_neg_r3.add_entry(3, 3, neg_one).expect("M_prod_neg_r3");
        let mut m_ns_r3 = SparseMatrix::new(num_rows, num_vars);
        m_ns_r3.add_entry(3, 8, Fr::one()).expect("M_ns_r3");

        // Row 4: prod - hi*2^32 - lo = 0
        let mut m_prod_pos_r4 = SparseMatrix::new(num_rows, num_vars);
        m_prod_pos_r4.add_entry(4, 3, Fr::one()).expect("M_prod_pos_r4");
        let mut m_hi_r4 = SparseMatrix::new(num_rows, num_vars);
        m_hi_r4
            .add_entry(4, 4, Fr::zero().sub(&two_pow_32()))
            .expect("M_hi_r4");
        let mut m_lo_r4 = SparseMatrix::new(num_rows, num_vars);
        m_lo_r4.add_entry(4, 5, neg_one).expect("M_lo_r4");

        let pow32 = two_pow_32();
        let pow64 = two_pow_64();

        Ccs::new(
            num_vars,
            vec![
                // 0-1: Row 0 a_sign bit
                m_as_pos_r0, m_as_neg_r0,
                // 2-3: Row 1 b_sign bit
                m_bs_pos_r1, m_bs_neg_r1,
                // 4-5: Row 2 neg_sign bit
                m_ns_pos_r2, m_ns_neg_r2,
                // 6-8: Row 3 product (a, b, a_sign, b_sign, prod, neg_sign)
                m_a_r3, m_b_r3, m_as_r3, m_bs_r3, m_prod_neg_r3, m_ns_r3,
                // 12-14: Row 4 decomposition
                m_prod_pos_r4, m_hi_r4, m_lo_r4,
            ],
            vec![
                // Row 0: a_sign² - a_sign
                vec![0, 0], // S_0: +a_sign²
                vec![1],     // S_1: -a_sign
                // Row 1: b_sign² - b_sign
                vec![2, 2], // S_2: +b_sign²
                vec![3],     // S_3: -b_sign
                // Row 2: neg_sign² - neg_sign
                vec![4, 4], // S_4: +neg_sign²
                vec![5],     // S_5: -neg_sign
                // Row 3: expanded product constraint
                vec![6, 7],          // S_6: +a*b
                vec![6, 9],          // S_7: -2^32*a*b_sign → c = -2^32
                vec![8, 7],          // S_8: -2^32*a_sign*b → c = -2^32  (M_as_r3 is idx 8)
                vec![8, 9],          // S_9: +2^64*a_sign*b_sign → c = +2^64 (M_bs_r3 is idx 9)
                vec![10],            // S_10: -prod (M_prod_neg_r3 is idx 10)
                vec![11],            // S_11: +2^64*neg_sign (M_ns_r3 is idx 11)
                // Row 4: prod - hi*2^32 - lo
                vec![12], // S_12: +prod
                vec![13], // S_13: -2^32*hi
                vec![14], // S_14: -lo
            ],
            vec![
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),                   // S_6
                Fr::zero().sub(&pow32),      // S_7: -2^32
                Fr::zero().sub(&pow32),      // S_8: -2^32
                pow64,                       // S_9: +2^64
                Fr::one(),                   // S_10
                pow64,                       // S_11: +2^64
                Fr::one(),
                Fr::one(),
                Fr::one(),
            ],
        )
        .expect("MulhCircuit CCS 构造应成功")
    }

    /// 赋值 witness。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let a_sign = (a >> 31) & 1;
        let b_sign = (b >> 31) & 1;
        let a_signed = a as i32 as i64;
        let b_signed = b as i32 as i64;
        let product_signed = a_signed * b_signed;
        let neg_sign = if product_signed < 0 { 1u32 } else { 0u32 };
        let prod = product_signed as u64;
        let hi = (prod >> 32) as u32;
        let lo = (prod & 0xFFFFFFFF) as u32;
        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u64(prod),
            Fr::from_u32_with_wrap(hi),
            Fr::from_u32_with_wrap(lo),
            Fr::from_u32_with_wrap(a_sign),
            Fr::from_u32_with_wrap(b_sign),
            Fr::from_u32_with_wrap(neg_sign),
        ]
    }

    /// 构建完整 CCS 实例（MULH: result = hi）。
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let a_signed = a as i32 as i64;
        let b_signed = b as i32 as i64;
        let product_signed = a_signed * b_signed;
        let prod = product_signed as u64;
        let hi = (prod >> 32) as u32;
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(hi),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// MULHSU 子电路（Phase K — Task #6：有符号×无符号 → 高 32 位）
// ===========================================================================

/// MULHSU 子电路（有符号 × 无符号 → 高 32 位）。
///
/// witness: `z = [1, a, b, prod, hi, lo, a_sign, neg_sign]`（长度 8）
///
/// 约束（4 行）：
/// - Row 0: `a_sign² - a_sign = 0`
/// - Row 1: `neg_sign² - neg_sign = 0`
/// - Row 2: `(a - 2^32*a_sign)*b - prod + 2^64*neg_sign = 0`
/// - Row 3: `prod - hi*2^32 - lo = 0`
pub struct MulhsuCircuit;

impl MulhsuCircuit {
    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 8;
        let num_rows = 4;
        let neg_one = Fr::zero().sub(&Fr::one());

        // Row 0: a_sign² - a_sign = 0
        let mut m_as_pos_r0 = SparseMatrix::new(num_rows, num_vars);
        m_as_pos_r0.add_entry(0, 6, Fr::one()).expect("M_as_pos_r0");
        let mut m_as_neg_r0 = SparseMatrix::new(num_rows, num_vars);
        m_as_neg_r0.add_entry(0, 6, neg_one).expect("M_as_neg_r0");

        // Row 1: neg_sign² - neg_sign = 0
        let mut m_ns_pos_r1 = SparseMatrix::new(num_rows, num_vars);
        m_ns_pos_r1.add_entry(1, 7, Fr::one()).expect("M_ns_pos_r1");
        let mut m_ns_neg_r1 = SparseMatrix::new(num_rows, num_vars);
        m_ns_neg_r1.add_entry(1, 7, neg_one).expect("M_ns_neg_r1");

        // Row 2: (a - 2^32*a_sign)*b - prod + 2^64*neg_sign = 0
        // 展开: +a*b - 2^32*a_sign*b - prod + 2^64*neg_sign
        let mut m_a_r2 = SparseMatrix::new(num_rows, num_vars);
        m_a_r2.add_entry(2, 1, Fr::one()).expect("M_a_r2");
        let mut m_b_r2 = SparseMatrix::new(num_rows, num_vars);
        m_b_r2.add_entry(2, 2, Fr::one()).expect("M_b_r2");
        let mut m_as_r2 = SparseMatrix::new(num_rows, num_vars);
        m_as_r2.add_entry(2, 6, Fr::one()).expect("M_as_r2");
        let mut m_prod_neg_r2 = SparseMatrix::new(num_rows, num_vars);
        m_prod_neg_r2.add_entry(2, 3, neg_one).expect("M_prod_neg_r2");
        let mut m_ns_r2 = SparseMatrix::new(num_rows, num_vars);
        m_ns_r2.add_entry(2, 7, Fr::one()).expect("M_ns_r2");

        // Row 3: prod - hi*2^32 - lo = 0
        let mut m_prod_pos_r3 = SparseMatrix::new(num_rows, num_vars);
        m_prod_pos_r3.add_entry(3, 3, Fr::one()).expect("M_prod_pos_r3");
        let mut m_hi_r3 = SparseMatrix::new(num_rows, num_vars);
        m_hi_r3
            .add_entry(3, 4, Fr::zero().sub(&two_pow_32()))
            .expect("M_hi_r3");
        let mut m_lo_r3 = SparseMatrix::new(num_rows, num_vars);
        m_lo_r3.add_entry(3, 5, neg_one).expect("M_lo_r3");

        let pow32 = two_pow_32();
        let pow64 = two_pow_64();

        Ccs::new(
            num_vars,
            vec![
                // 0-1: Row 0 a_sign bit
                m_as_pos_r0, m_as_neg_r0,
                // 2-3: Row 1 neg_sign bit
                m_ns_pos_r1, m_ns_neg_r1,
                // 4-8: Row 2 product (a, b, a_sign, prod, neg_sign)
                m_a_r2, m_b_r2, m_as_r2, m_prod_neg_r2, m_ns_r2,
                // 9-11: Row 3 decomposition
                m_prod_pos_r3, m_hi_r3, m_lo_r3,
            ],
            vec![
                // Row 0: a_sign² - a_sign
                vec![0, 0], // S_0: +a_sign²
                vec![1],     // S_1: -a_sign
                // Row 1: neg_sign² - neg_sign
                vec![2, 2], // S_2: +neg_sign²
                vec![3],     // S_3: -neg_sign
                // Row 2: expanded product
                vec![4, 5],          // S_4: +a*b
                vec![6, 5],          // S_5: -2^32*a_sign*b → c = -2^32
                vec![7],             // S_6: -prod
                vec![8],             // S_7: +2^64*neg_sign → c = +2^64
                // Row 3: prod - hi*2^32 - lo
                vec![9],  // S_8: +prod
                vec![10], // S_9: -2^32*hi
                vec![11], // S_10: -lo
            ],
            vec![
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),
                Fr::one(),                  // S_4
                Fr::zero().sub(&pow32),     // S_5: -2^32
                Fr::one(),                  // S_6
                pow64,                      // S_7: +2^64
                Fr::one(),
                Fr::one(),
                Fr::one(),
            ],
        )
        .expect("MulhsuCircuit CCS 构造应成功")
    }

    /// 赋值 witness。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let a_sign = (a >> 31) & 1;
        let a_signed = a as i32 as i64;
        let b_unsigned = b as u64 as i64;
        let product_signed = a_signed * b_unsigned;
        let neg_sign = if product_signed < 0 { 1u32 } else { 0u32 };
        let prod = product_signed as u64;
        let hi = (prod >> 32) as u32;
        let lo = (prod & 0xFFFFFFFF) as u32;
        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u64(prod),
            Fr::from_u32_with_wrap(hi),
            Fr::from_u32_with_wrap(lo),
            Fr::from_u32_with_wrap(a_sign),
            Fr::from_u32_with_wrap(neg_sign),
        ]
    }

    /// 构建完整 CCS 实例（MULHSU: result = hi）。
    pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(a, b);
        let a_signed = a as i32 as i64;
        let b_unsigned = b as u64 as i64;
        let product_signed = a_signed * b_unsigned;
        let prod = product_signed as u64;
        let hi = (prod >> 32) as u32;
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(hi),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// DIV / DIVU / REM / REMU 子电路（Phase K — Task #7：MVP trust witness）
// ===========================================================================

/// DIV 子电路（有符号除法，MVP trust witness）。
///
/// MVP 策略：约束 trivially satisfied（result - result = 0），soundness 依赖 witness 赋值。
/// 完整除法约束（a = q*b + r）和 range check 留给 Step 13 LogUp。
///
/// witness: `z = [1, a, b, result]`（长度 4）
/// RV32M 边界处理：
/// - b=0: result = -1 (0xFFFFFFFF)
/// - 溢出（a=INT_MIN, b=-1）: result = INT_MIN (0x80000000)
/// - 正常: result = (a as i32) / (b as i32)
pub struct DivCircuit;

impl DivCircuit {
    /// 构建 CCS 约束结构（MVP: trivially satisfied）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 4;
        let num_rows = 1;

        let mut m_result_pos = SparseMatrix::new(num_rows, num_vars);
        m_result_pos
            .add_entry(0, 3, Fr::one())
            .expect("M_result_pos");

        let mut m_result_neg = SparseMatrix::new(num_rows, num_vars);
        m_result_neg
            .add_entry(0, 3, Fr::zero().sub(&Fr::one()))
            .expect("M_result_neg");

        Ccs::new(
            num_vars,
            vec![m_result_pos, m_result_neg],
            vec![vec![0], vec![1]],
            vec![Fr::one(), Fr::one()],
        )
        .expect("DivCircuit CCS 构造应成功")
    }

    /// 赋值 witness（RV32M 边界处理）。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let a_signed = a as i32;
        let b_signed = b as i32;
        let result = a_signed
            .checked_div(b_signed)
            .map(|v| v as u32)
            .unwrap_or_else(|| if b_signed == 0 { 0xFFFFFFFF } else { 0x80000000 });
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
        let a_signed = a as i32;
        let b_signed = b as i32;
        let result = a_signed
            .checked_div(b_signed)
            .map(|v| v as u32)
            .unwrap_or_else(|| if b_signed == 0 { 0xFFFFFFFF } else { 0x80000000 });
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

/// DIVU 子电路（无符号除法，MVP trust witness）。
pub struct DivuCircuit;

impl DivuCircuit {
    /// 构建 CCS 约束结构（复用 DivCircuit）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        DivCircuit::build_ccs()
    }

    /// 赋值 witness（RV32M: b=0 时 result = 0xFFFFFFFF）。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let result = a.checked_div(b).unwrap_or(u32::MAX);
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
        let result = a.checked_div(b).unwrap_or(u32::MAX);
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

/// REM 子电路（有符号取余，MVP trust witness）。
pub struct RemCircuit;

impl RemCircuit {
    /// 构建 CCS 约束结构（复用 DivCircuit）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        DivCircuit::build_ccs()
    }

    /// 赋值 witness（RV32M 边界处理）。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let a_signed = a as i32;
        let b_signed = b as i32;
        let result = a_signed
            .checked_rem(b_signed)
            .map(|v| v as u32)
            .unwrap_or_else(|| if b_signed == 0 { a } else { 0 });
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
        let a_signed = a as i32;
        let b_signed = b as i32;
        let result = a_signed
            .checked_rem(b_signed)
            .map(|v| v as u32)
            .unwrap_or_else(|| if b_signed == 0 { a } else { 0 });
        let public_inputs = vec![
            Fr::from_u32_with_wrap(a),
            Fr::from_u32_with_wrap(b),
            Fr::from_u32_with_wrap(result),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

/// REMU 子电路（无符号取余，MVP trust witness）。
pub struct RemuCircuit;

impl RemuCircuit {
    /// 构建 CCS 约束结构（复用 DivCircuit）。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        DivCircuit::build_ccs()
    }

    /// 赋值 witness（RV32M: b=0 时 result = a）。
    #[must_use]
    pub fn assign_witness(a: u32, b: u32) -> Vec<Fr> {
        let result = a.checked_rem(b).unwrap_or(a);
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
        let result = a.checked_rem(b).unwrap_or(a);
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

    // ===== MUL / MULHU 测试 =====

    #[test]
    fn test_mul_basic() {
        let ccs = MulCircuit::build_ccs();
        let witness = MulCircuit::assign_witness(7, 6);
        assert_eq!(witness.len(), 6);
        // 7 * 6 = 42, hi=0, lo=42
        assert_eq!(witness[3], Fr::from_u64(42));
        assert_eq!(witness[4], Fr::zero()); // hi
        assert_eq!(witness[5], Fr::from_u32_with_wrap(42)); // lo
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mul_large() {
        let ccs = MulCircuit::build_ccs();
        let witness = MulCircuit::assign_witness(0xFFFF, 0xFFFF);
        // 0xFFFF * 0xFFFF = 0xFFFE0001
        assert_eq!(witness[3], Fr::from_u64(0xFFFE0001));
        assert_eq!(witness[4], Fr::zero()); // hi
        assert_eq!(witness[5], Fr::from_u32_with_wrap(0xFFFE0001)); // lo
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mul_high_bits() {
        let ccs = MulCircuit::build_ccs();
        let witness = MulCircuit::assign_witness(0x10000, 0x10000);
        // 0x10000 * 0x10000 = 0x100000000, lo=0, hi=1
        assert_eq!(witness[3], Fr::from_u64(0x100000000));
        assert_eq!(witness[4], Fr::one()); // hi
        assert_eq!(witness[5], Fr::zero()); // lo
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mul_zero() {
        let ccs = MulCircuit::build_ccs();
        let witness = MulCircuit::assign_witness(0, 0xDEADBEEF);
        assert_eq!(witness[3], Fr::zero());
        assert_eq!(witness[4], Fr::zero());
        assert_eq!(witness[5], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mul_max() {
        let ccs = MulCircuit::build_ccs();
        // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
        let witness = MulCircuit::assign_witness(u32::MAX, u32::MAX);
        assert_eq!(witness[3], Fr::from_u64(0xFFFFFFFE00000001));
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0xFFFFFFFE)); // hi
        assert_eq!(witness[5], Fr::from_u32_with_wrap(0x00000001)); // lo
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulhu_basic() {
        let ccs = MulhuCircuit::build_ccs();
        let witness = MulhuCircuit::assign_witness(0x10000, 0x10000);
        // hi=1
        assert_eq!(witness[4], Fr::one());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulhu_max() {
        let ccs = MulhuCircuit::build_ccs();
        let witness = MulhuCircuit::assign_witness(u32::MAX, u32::MAX);
        // hi=0xFFFFFFFE
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0xFFFFFFFE));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mul_soundness_tampered_lo() {
        let ccs = MulCircuit::build_ccs();
        let mut witness = MulCircuit::assign_witness(7, 6);
        witness[5] = Fr::from_u32_with_wrap(999); // 篡改 lo
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_mul_soundness_tampered_hi() {
        let ccs = MulCircuit::build_ccs();
        let mut witness = MulCircuit::assign_witness(0x10000, 0x10000);
        witness[4] = Fr::from_u32_with_wrap(999); // 篡改 hi
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_mul_to_instance() {
        let inst = MulCircuit::to_instance(7, 6).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(42)); // lo
    }

    #[test]
    fn test_mulhu_to_instance() {
        let inst = MulhuCircuit::to_instance(u32::MAX, u32::MAX).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0xFFFFFFFE)); // hi
    }

    // ===== MULH / MULHSU 测试 =====

    #[test]
    fn test_mulh_pos_pos() {
        let ccs = MulhCircuit::build_ccs();
        let witness = MulhCircuit::assign_witness(2, 3);
        // 2 * 3 = 6, hi=0
        assert_eq!(witness[4], Fr::zero()); // hi
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulh_neg_neg() {
        let ccs = MulhCircuit::build_ccs();
        // (-1) * (-1) = 1, hi=0
        let witness = MulhCircuit::assign_witness(0xFFFFFFFF, 0xFFFFFFFF);
        assert_eq!(witness[4], Fr::zero()); // hi
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulh_neg_pos() {
        let ccs = MulhCircuit::build_ccs();
        // (-2) * 3 = -6, hi=0xFFFFFFFF (sign extension)
        let witness = MulhCircuit::assign_witness(0xFFFFFFFE, 3);
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0xFFFFFFFF)); // hi
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulh_pos_neg() {
        let ccs = MulhCircuit::build_ccs();
        // 3 * (-2) = -6, hi=0xFFFFFFFF
        let witness = MulhCircuit::assign_witness(3, 0xFFFFFFFE);
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0xFFFFFFFF)); // hi
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulh_min_min() {
        let ccs = MulhCircuit::build_ccs();
        // INT_MIN * INT_MIN = 0x4000000000000000, hi=0x40000000
        let witness = MulhCircuit::assign_witness(0x80000000, 0x80000000);
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0x40000000)); // hi
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulh_overflow_div() {
        let ccs = MulhCircuit::build_ccs();
        // INT_MIN * (-1) = 2^31, hi=0
        let witness = MulhCircuit::assign_witness(0x80000000, 0xFFFFFFFF);
        assert_eq!(witness[4], Fr::zero()); // hi
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulhsu_neg_unsigned() {
        let ccs = MulhsuCircuit::build_ccs();
        // (-1) * 0xFFFFFFFF = -(0xFFFFFFFF), hi=0xFFFFFFFF
        let witness = MulhsuCircuit::assign_witness(0xFFFFFFFF, 0xFFFFFFFF);
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0xFFFFFFFF)); // hi
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulhsu_pos_unsigned() {
        let ccs = MulhsuCircuit::build_ccs();
        // 2 * 3 = 6, hi=0
        let witness = MulhsuCircuit::assign_witness(2, 3);
        assert_eq!(witness[4], Fr::zero()); // hi
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulhsu_min_unsigned() {
        let ccs = MulhsuCircuit::build_ccs();
        // INT_MIN * 0xFFFFFFFF = -0x7FFFFFFF * 0xFFFFFFFF
        let witness = MulhsuCircuit::assign_witness(0x80000000, 0xFFFFFFFF);
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_mulh_soundness_tampered_hi() {
        let ccs = MulhCircuit::build_ccs();
        let mut witness = MulhCircuit::assign_witness(0xFFFFFFFE, 3);
        witness[4] = Fr::zero(); // 篡改 hi（应 = 0xFFFFFFFF）
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_mulh_soundness_tampered_sign() {
        let ccs = MulhCircuit::build_ccs();
        let mut witness = MulhCircuit::assign_witness(0xFFFFFFFE, 3);
        witness[8] = Fr::zero(); // 篡改 neg_sign（应 = 1）
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_mulh_to_instance() {
        let inst = MulhCircuit::to_instance(0xFFFFFFFE, 3).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0xFFFFFFFF)); // hi
    }

    #[test]
    fn test_mulhsu_to_instance() {
        let inst = MulhsuCircuit::to_instance(0xFFFFFFFF, 0xFFFFFFFF).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0xFFFFFFFF)); // hi
    }

    // ===== DIV / DIVU / REM / REMU 测试 =====

    #[test]
    fn test_div_basic() {
        let ccs = DivCircuit::build_ccs();
        let witness = DivCircuit::assign_witness(100, 7);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(14)); // 100/7=14
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_div_by_zero() {
        let ccs = DivCircuit::build_ccs();
        let witness = DivCircuit::assign_witness(100, 0);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0xFFFFFFFF)); // -1
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_div_overflow() {
        let ccs = DivCircuit::build_ccs();
        // INT_MIN / -1 = INT_MIN
        let witness = DivCircuit::assign_witness(0x80000000, 0xFFFFFFFF);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0x80000000));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_div_neg() {
        let ccs = DivCircuit::build_ccs();
        let witness = DivCircuit::assign_witness((-100i32) as u32, 7);
        assert_eq!(witness[3], Fr::from_u32_with_wrap((-14i32) as u32));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_divu_basic() {
        let ccs = DivuCircuit::build_ccs();
        let witness = DivuCircuit::assign_witness(100, 7);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(14));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_divu_by_zero() {
        let ccs = DivuCircuit::build_ccs();
        let witness = DivuCircuit::assign_witness(100, 0);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0xFFFFFFFF));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_rem_basic() {
        let ccs = RemCircuit::build_ccs();
        let witness = RemCircuit::assign_witness(100, 7);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(2)); // 100%7=2
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_rem_by_zero() {
        let ccs = RemCircuit::build_ccs();
        let witness = RemCircuit::assign_witness(100, 0);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(100)); // b=0 → result=a
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_rem_overflow() {
        let ccs = RemCircuit::build_ccs();
        // INT_MIN % -1 = 0
        let witness = RemCircuit::assign_witness(0x80000000, 0xFFFFFFFF);
        assert_eq!(witness[3], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_rem_neg() {
        let ccs = RemCircuit::build_ccs();
        let witness = RemCircuit::assign_witness((-100i32) as u32, 7);
        assert_eq!(witness[3], Fr::from_u32_with_wrap((-2i32) as u32));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_remu_basic() {
        let ccs = RemuCircuit::build_ccs();
        let witness = RemuCircuit::assign_witness(100, 7);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(2));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_remu_by_zero() {
        let ccs = RemuCircuit::build_ccs();
        let witness = RemuCircuit::assign_witness(100, 0);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(100));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_div_to_instance() {
        let inst = DivCircuit::to_instance(100, 7).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(14));
    }

    #[test]
    fn test_divu_to_instance() {
        let inst = DivuCircuit::to_instance(100, 7).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(14));
    }

    #[test]
    fn test_rem_to_instance() {
        let inst = RemCircuit::to_instance(100, 7).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(2));
    }

    #[test]
    fn test_remu_to_instance() {
        let inst = RemuCircuit::to_instance(100, 7).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(2));
    }
}
