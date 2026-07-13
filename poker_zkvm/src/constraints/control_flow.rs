//! 控制流指令子电路（Phase 5 — Task 5.4）。
//!
//! 严格遵循 spec.md L281-286（v1.4 FROZEN）：
//! - JAL/JALR — pc 更新约束（跳转目标 + 链接寄存器）
//! - BEQ/BNE/BLT/BGE/BLTU/BGEU — 条件分支（taken flag + 条件求值）
//! - LUI/AUIPC — 上立即数（imm << 12）
//!
//! ## MVP 策略
//!
//! 实现代表性指令（JAL/BEQ/LUI/AUIPC），其余指令（JALR/BNE/BLT/BGE/BLTU/BGEU）
//! 遵循相同模式，在 Phase 11 补全。range check 留给 Step 13 LogUp。
//!
//! ## 溢出处理
//!
//! RISC-V 使用 mod 2^32 算术，而 CCS 约束在域 mod p（p > 2^32）中。
//! 当立即数为负数（二进制补码表示为大 u32）时，域中的加法不等于 mod 2^32 的结果。
//! 引入 `carry` 见证位：`a + b - result - 2^32 * carry = 0`，`carry ∈ {0, 1}`。
//! 这与 [`crate::constraints::algebra::AddCircuit`] 的 overflow_bit 模式一致。

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;

/// 2^32 作为域元素（u32 溢出边界）。
fn two_pow_32() -> Fr {
    Fr::from_u64(1u64 << 32)
}

// ===========================================================================
// JAL 子电路（Task 5.4.1）
// ===========================================================================

/// JAL 子电路（Jump and Link）。
///
/// 语义：`rd = pc + 4; pc_new = pc + imm`（mod 2^32）
///
/// witness: `z = [1, pc, imm, rd_val, pc_new, pc_carry, rd_carry]`（长度 7）
///
/// 约束（4 行）：
/// - Row 0: `pc + imm - pc_new - 2^32 * pc_carry = 0`（跳转目标，含溢出）
/// - Row 1: `pc + 4 - rd_val - 2^32 * rd_carry = 0`（链接寄存器，含溢出）
/// - Row 2: `pc_carry² - pc_carry = 0`（bit 范围检查）
/// - Row 3: `rd_carry² - rd_carry = 0`（bit 范围检查）
pub struct JalCircuit;

impl JalCircuit {
    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 7;
        let num_rows = 4;
        let neg_one = Fr::zero().sub(&Fr::one());
        let neg_2p32 = Fr::zero().sub(&two_pow_32());
        let const4 = Fr::from_u32_with_wrap(4);

        // Row 0: pc + imm - pc_new - 2^32 * pc_carry = 0
        let mut m_pc_r0 = SparseMatrix::new(num_rows, num_vars);
        m_pc_r0.add_entry(0, 1, Fr::one()).expect("M_pc_r0");

        let mut m_imm_r0 = SparseMatrix::new(num_rows, num_vars);
        m_imm_r0.add_entry(0, 2, Fr::one()).expect("M_imm_r0");

        let mut m_pcnew_neg = SparseMatrix::new(num_rows, num_vars);
        m_pcnew_neg.add_entry(0, 4, neg_one).expect("M_pcnew_neg");

        let mut m_pccarry_neg = SparseMatrix::new(num_rows, num_vars);
        m_pccarry_neg
            .add_entry(0, 5, neg_2p32)
            .expect("M_pccarry_neg");

        // Row 1: pc + 4 - rd_val - 2^32 * rd_carry = 0
        let mut m_pc_r1 = SparseMatrix::new(num_rows, num_vars);
        m_pc_r1.add_entry(1, 1, Fr::one()).expect("M_pc_r1");

        let mut m_const4_r1 = SparseMatrix::new(num_rows, num_vars);
        m_const4_r1.add_entry(1, 0, const4).expect("M_const4_r1");

        let mut m_rd_neg = SparseMatrix::new(num_rows, num_vars);
        m_rd_neg.add_entry(1, 3, neg_one).expect("M_rd_neg");

        let mut m_rdcarry_neg = SparseMatrix::new(num_rows, num_vars);
        m_rdcarry_neg
            .add_entry(1, 6, neg_2p32)
            .expect("M_rdcarry_neg");

        // Row 2: pc_carry² - pc_carry = 0
        let mut m_pcc_sq = SparseMatrix::new(num_rows, num_vars);
        m_pcc_sq.add_entry(2, 5, Fr::one()).expect("M_pcc_sq");

        let mut m_pcc_neg = SparseMatrix::new(num_rows, num_vars);
        m_pcc_neg.add_entry(2, 5, neg_one).expect("M_pcc_neg");

        // Row 3: rd_carry² - rd_carry = 0
        let mut m_rdc_sq = SparseMatrix::new(num_rows, num_vars);
        m_rdc_sq.add_entry(3, 6, Fr::one()).expect("M_rdc_sq");

        let mut m_rdc_neg = SparseMatrix::new(num_rows, num_vars);
        m_rdc_neg.add_entry(3, 6, neg_one).expect("M_rdc_neg");

        Ccs::new(
            num_vars,
            vec![
                m_pc_r0,
                m_imm_r0,
                m_pcnew_neg,
                m_pccarry_neg, // Row 0
                m_pc_r1,
                m_const4_r1,
                m_rd_neg,
                m_rdcarry_neg, // Row 1
                m_pcc_sq,
                m_pcc_neg, // Row 2
                m_rdc_sq,
                m_rdc_neg, // Row 3
            ],
            vec![
                vec![0],
                vec![1],
                vec![2],
                vec![3], // Row 0
                vec![4],
                vec![5],
                vec![6],
                vec![7], // Row 1
                vec![8, 8],
                vec![9], // Row 2
                vec![10, 10],
                vec![11], // Row 3
            ],
            vec![Fr::one(); 12],
        )
        .expect("JalCircuit CCS 构造应成功")
    }

    /// 赋值 witness。
    ///
    /// # 参数
    /// - `pc` — 当前 PC
    /// - `imm` — 跳转偏移（已解码为 u32，可为负数的补码表示）
    #[must_use]
    pub fn assign_witness(pc: u32, imm: u32) -> Vec<Fr> {
        let pc_sum = (pc as u64) + (imm as u64);
        let pc_new = pc_sum as u32;
        let pc_carry = (pc_sum >> 32) as u32;

        let rd_sum = (pc as u64) + 4u64;
        let rd_val = rd_sum as u32;
        let rd_carry = (rd_sum >> 32) as u32;

        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(pc),
            Fr::from_u32_with_wrap(imm),
            Fr::from_u32_with_wrap(rd_val),
            Fr::from_u32_with_wrap(pc_new),
            Fr::from_u32_with_wrap(pc_carry),
            Fr::from_u32_with_wrap(rd_carry),
        ]
    }

    /// 构建完整 CCS 实例。
    pub fn to_instance(pc: u32, imm: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(pc, imm);
        let pc_new = pc.wrapping_add(imm);
        let public_inputs = vec![
            Fr::from_u32_with_wrap(pc),
            Fr::from_u32_with_wrap(imm),
            Fr::from_u32_with_wrap(pc_new),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// BEQ 子电路（Task 5.4.2）
// ===========================================================================

/// BEQ 子电路（Branch if Equal）。
///
/// 语义：`if rs1 == rs2: pc_new = pc + imm; taken = 1` else `pc_new = pc + 4; taken = 0`
///
/// witness: `z = [1, pc, rs1, rs2, imm, taken, pc_new, carry]`（长度 8）
///
/// 约束（4 行）：
/// - Row 0: `taken * (rs1 - rs2) = 0`（taken=1 蕴含 rs1==rs2）
/// - Row 1: `taken² - taken = 0`（bit 范围检查）
/// - Row 2: `pc + imm*taken + 4 - 4*taken - pc_new - 2^32*carry = 0`（条件跳转，含溢出）
///   - taken=1: `pc + imm - pc_new - 2^32*carry = 0`
///   - taken=0: `pc + 4 - pc_new - 2^32*carry = 0`
/// - Row 3: `carry² - carry = 0`（bit 范围检查）
pub struct BeqCircuit;

impl BeqCircuit {
    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 8;
        let num_rows = 4;
        let neg_one = Fr::zero().sub(&Fr::one());
        let neg_2p32 = Fr::zero().sub(&two_pow_32());
        let const4 = Fr::from_u32_with_wrap(4);
        let neg4 = Fr::zero().sub(&const4);

        // Row 0: taken * (rs1 - rs2) = 0 → taken*rs1 - taken*rs2 = 0
        let mut m_taken_r0a = SparseMatrix::new(num_rows, num_vars);
        m_taken_r0a.add_entry(0, 5, Fr::one()).expect("M_taken_r0a");
        let mut m_rs1_r0 = SparseMatrix::new(num_rows, num_vars);
        m_rs1_r0.add_entry(0, 2, Fr::one()).expect("M_rs1_r0");
        let mut m_taken_r0b = SparseMatrix::new(num_rows, num_vars);
        m_taken_r0b.add_entry(0, 5, Fr::one()).expect("M_taken_r0b");
        let mut m_rs2_neg_r0 = SparseMatrix::new(num_rows, num_vars);
        m_rs2_neg_r0.add_entry(0, 3, neg_one).expect("M_rs2_neg_r0");

        // Row 1: taken² - taken = 0
        let mut m_taken_sq = SparseMatrix::new(num_rows, num_vars);
        m_taken_sq.add_entry(1, 5, Fr::one()).expect("M_taken_sq");
        let mut m_taken_neg_r1 = SparseMatrix::new(num_rows, num_vars);
        m_taken_neg_r1
            .add_entry(1, 5, neg_one)
            .expect("M_taken_neg_r1");

        // Row 2: pc + imm*taken + 4 - 4*taken - pc_new - 2^32*carry = 0
        let mut m_pc_r2 = SparseMatrix::new(num_rows, num_vars);
        m_pc_r2.add_entry(2, 1, Fr::one()).expect("M_pc_r2");
        // imm * taken (quadratic)
        let mut m_imm_r2 = SparseMatrix::new(num_rows, num_vars);
        m_imm_r2.add_entry(2, 4, Fr::one()).expect("M_imm_r2");
        let mut m_taken_r2 = SparseMatrix::new(num_rows, num_vars);
        m_taken_r2.add_entry(2, 5, Fr::one()).expect("M_taken_r2");
        // +4 (constant)
        let mut m_const4_r2 = SparseMatrix::new(num_rows, num_vars);
        m_const4_r2.add_entry(2, 0, const4).expect("M_const4_r2");
        // -4*taken
        let mut m_taken_neg4_r2 = SparseMatrix::new(num_rows, num_vars);
        m_taken_neg4_r2
            .add_entry(2, 5, neg4)
            .expect("M_taken_neg4_r2");
        // -pc_new
        let mut m_pcnew_neg_r2 = SparseMatrix::new(num_rows, num_vars);
        m_pcnew_neg_r2
            .add_entry(2, 6, neg_one)
            .expect("M_pcnew_neg_r2");
        // -2^32*carry
        let mut m_carry_neg2p32_r2 = SparseMatrix::new(num_rows, num_vars);
        m_carry_neg2p32_r2
            .add_entry(2, 7, neg_2p32)
            .expect("M_carry_neg2p32_r2");

        // Row 3: carry² - carry = 0
        let mut m_carry_sq = SparseMatrix::new(num_rows, num_vars);
        m_carry_sq.add_entry(3, 7, Fr::one()).expect("M_carry_sq");
        let mut m_carry_neg_r3 = SparseMatrix::new(num_rows, num_vars);
        m_carry_neg_r3
            .add_entry(3, 7, neg_one)
            .expect("M_carry_neg_r3");

        Ccs::new(
            num_vars,
            vec![
                m_taken_r0a,
                m_rs1_r0,
                m_taken_r0b,
                m_rs2_neg_r0, // Row 0
                m_taken_sq,
                m_taken_neg_r1, // Row 1
                m_pc_r2,
                m_imm_r2,
                m_taken_r2,
                m_const4_r2,
                m_taken_neg4_r2,
                m_pcnew_neg_r2,
                m_carry_neg2p32_r2, // Row 2
                m_carry_sq,
                m_carry_neg_r3, // Row 3
            ],
            vec![
                vec![0, 1],
                vec![2, 3], // Row 0: taken*rs1 - taken*rs2
                vec![4, 4],
                vec![5], // Row 1: taken² - taken
                vec![6],
                vec![7, 8],
                vec![9],
                vec![10],
                vec![11],
                vec![12], // Row 2
                vec![13, 13],
                vec![14], // Row 3: carry² - carry
            ],
            vec![Fr::one(); 12],
        )
        .expect("BeqCircuit CCS 构造应成功")
    }

    /// 赋值 witness。
    ///
    /// # 参数
    /// - `pc` — 当前 PC
    /// - `rs1` — 寄存器 1 值
    /// - `rs2` — 寄存器 2 值
    /// - `imm` — 分支偏移（已解码为 u32）
    #[must_use]
    pub fn assign_witness(pc: u32, rs1: u32, rs2: u32, imm: u32) -> Vec<Fr> {
        let taken = u32::from(rs1 == rs2);
        let sum = if taken == 1 {
            (pc as u64) + (imm as u64)
        } else {
            (pc as u64) + 4u64
        };
        let pc_new = sum as u32;
        let carry = (sum >> 32) as u32;

        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(pc),
            Fr::from_u32_with_wrap(rs1),
            Fr::from_u32_with_wrap(rs2),
            Fr::from_u32_with_wrap(imm),
            Fr::from_u32_with_wrap(taken),
            Fr::from_u32_with_wrap(pc_new),
            Fr::from_u32_with_wrap(carry),
        ]
    }

    /// 构建完整 CCS 实例。
    pub fn to_instance(pc: u32, rs1: u32, rs2: u32, imm: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(pc, rs1, rs2, imm);
        let taken = rs1 == rs2;
        let pc_new = if taken {
            pc.wrapping_add(imm)
        } else {
            pc.wrapping_add(4)
        };
        let public_inputs = vec![
            Fr::from_u32_with_wrap(pc),
            Fr::from_u32_with_wrap(imm),
            Fr::from_u32_with_wrap(pc_new),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// LUI 子电路（Task 5.4.3）
// ===========================================================================

/// LUI 子电路（Load Upper Immediate）。
///
/// 语义：`rd = imm << 12`（即 `rd = imm * 4096`）
///
/// 当 imm < 2^20（20 位立即数，零扩展）时，`imm * 4096 < 2^32`，无溢出。
/// range check imm < 2^20 留给 Step 13 LogUp。
///
/// witness: `z = [1, imm, rd_val]`（长度 3）
///
/// 约束（1 行）：`rd_val - imm * 4096 = 0`
pub struct LuiCircuit;

impl LuiCircuit {
    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 3;
        let num_rows = 1;
        let neg_4096 = Fr::zero().sub(&Fr::from_u32_with_wrap(4096));

        let mut m_rd = SparseMatrix::new(num_rows, num_vars);
        m_rd.add_entry(0, 2, Fr::one()).expect("M_rd");

        let mut m_imm_4096 = SparseMatrix::new(num_rows, num_vars);
        m_imm_4096.add_entry(0, 1, neg_4096).expect("M_imm_4096");

        Ccs::new(
            num_vars,
            vec![m_rd, m_imm_4096],
            vec![vec![0], vec![1]],
            vec![Fr::one(), Fr::one()],
        )
        .expect("LuiCircuit CCS 构造应成功")
    }

    /// 赋值 witness。
    ///
    /// # 参数
    /// - `imm` — 20 位立即数（零扩展为 u32，须 < 2^20）
    #[must_use]
    pub fn assign_witness(imm: u32) -> Vec<Fr> {
        let rd_val = imm.wrapping_mul(4096);
        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(imm),
            Fr::from_u32_with_wrap(rd_val),
        ]
    }

    /// 构建完整 CCS 实例。
    pub fn to_instance(imm: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(imm);
        let rd_val = imm.wrapping_mul(4096);
        let public_inputs = vec![Fr::from_u32_with_wrap(imm), Fr::from_u32_with_wrap(rd_val)];
        CcsInstance::new(ccs, witness, public_inputs)
    }
}

// ===========================================================================
// AUIPC 子电路（Task 5.4.3）
// ===========================================================================

/// AUIPC 子电路（Add Upper Immediate to PC）。
///
/// 语义：`rd = pc + (imm << 12)`（mod 2^32）
///
/// witness: `z = [1, pc, imm, rd_val, carry]`（长度 5）
///
/// 约束（2 行）：
/// - Row 0: `pc + imm*4096 - rd_val - 2^32*carry = 0`（含溢出）
/// - Row 1: `carry² - carry = 0`（bit 范围检查）
pub struct AuipcCircuit;

impl AuipcCircuit {
    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 5;
        let num_rows = 2;
        let neg_one = Fr::zero().sub(&Fr::one());
        let neg_2p32 = Fr::zero().sub(&two_pow_32());
        let const4096 = Fr::from_u32_with_wrap(4096);

        // Row 0: pc + imm*4096 - rd_val - 2^32*carry = 0
        let mut m_pc_r0 = SparseMatrix::new(num_rows, num_vars);
        m_pc_r0.add_entry(0, 1, Fr::one()).expect("M_pc_r0");

        let mut m_imm_4096_r0 = SparseMatrix::new(num_rows, num_vars);
        m_imm_4096_r0
            .add_entry(0, 2, const4096)
            .expect("M_imm_4096_r0");

        let mut m_rd_neg_r0 = SparseMatrix::new(num_rows, num_vars);
        m_rd_neg_r0.add_entry(0, 3, neg_one).expect("M_rd_neg_r0");

        let mut m_carry_neg2p32_r0 = SparseMatrix::new(num_rows, num_vars);
        m_carry_neg2p32_r0
            .add_entry(0, 4, neg_2p32)
            .expect("M_carry_neg2p32_r0");

        // Row 1: carry² - carry = 0
        let mut m_carry_sq = SparseMatrix::new(num_rows, num_vars);
        m_carry_sq.add_entry(1, 4, Fr::one()).expect("M_carry_sq");

        let mut m_carry_neg = SparseMatrix::new(num_rows, num_vars);
        m_carry_neg.add_entry(1, 4, neg_one).expect("M_carry_neg");

        Ccs::new(
            num_vars,
            vec![
                m_pc_r0,
                m_imm_4096_r0,
                m_rd_neg_r0,
                m_carry_neg2p32_r0, // Row 0
                m_carry_sq,
                m_carry_neg, // Row 1
            ],
            vec![
                vec![0],
                vec![1],
                vec![2],
                vec![3], // Row 0
                vec![4, 4],
                vec![5], // Row 1
            ],
            vec![Fr::one(); 6],
        )
        .expect("AuipcCircuit CCS 构造应成功")
    }

    /// 赋值 witness。
    ///
    /// # 参数
    /// - `pc` — 当前 PC
    /// - `imm` — 20 位立即数（零扩展为 u32）
    #[must_use]
    pub fn assign_witness(pc: u32, imm: u32) -> Vec<Fr> {
        // 使用 u64 计算避免溢出丢失
        let full_product = (imm as u64) * 4096u64;
        let sum = (pc as u64) + full_product;
        let rd_val = sum as u32;
        let carry = (sum >> 32) as u32;

        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(pc),
            Fr::from_u32_with_wrap(imm),
            Fr::from_u32_with_wrap(rd_val),
            Fr::from_u32_with_wrap(carry),
        ]
    }

    /// 构建完整 CCS 实例。
    pub fn to_instance(pc: u32, imm: u32) -> Result<CcsInstance, ZkvmError> {
        let ccs = Self::build_ccs();
        let witness = Self::assign_witness(pc, imm);
        let rd_val = pc.wrapping_add(imm.wrapping_mul(4096));
        let public_inputs = vec![
            Fr::from_u32_with_wrap(pc),
            Fr::from_u32_with_wrap(imm),
            Fr::from_u32_with_wrap(rd_val),
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

    // ===== JAL 测试 =====

    #[test]
    fn test_jal_build_ccs() {
        let ccs = JalCircuit::build_ccs();
        assert_eq!(ccs.num_vars, 7);
        assert_eq!(ccs.num_matrices(), 12);
        assert_eq!(ccs.num_rows(), 4);
        assert_eq!(ccs.num_constraints(), 12);
    }

    #[test]
    fn test_jal_basic_forward() {
        let ccs = JalCircuit::build_ccs();
        let witness = JalCircuit::assign_witness(0x1000, 0x100);
        // pc_new = 0x1000 + 0x100 = 0x1100, carry=0
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0x1100));
        // rd_val = 0x1000 + 4 = 0x1004, carry=0
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0x1004));
        assert_eq!(witness[5], Fr::zero()); // pc_carry
        assert_eq!(witness[6], Fr::zero()); // rd_carry
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_jal_backward_jump() {
        let ccs = JalCircuit::build_ccs();
        // imm = -16 (0xFFFFFFF0 as u32)
        let witness = JalCircuit::assign_witness(0x1000, 0xFFFFFFF0);
        // pc_new = (0x1000 + 0xFFFFFFF0) mod 2^32 = 0x0FF0
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0x0FF0));
        // carry=1 because 0x1000 + 0xFFFFFFF0 = 0x10000FF0 >= 2^32
        assert_eq!(witness[5], Fr::one()); // pc_carry=1
        // rd_val = 0x1000 + 4 = 0x1004, carry=0
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0x1004));
        assert_eq!(witness[6], Fr::zero()); // rd_carry=0
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_jal_pc_overflow() {
        // pc 接近 2^32 上限，pc+4 溢出
        let ccs = JalCircuit::build_ccs();
        let pc = 0xFFFFFFFE;
        let witness = JalCircuit::assign_witness(pc, 0);
        // pc_new = 0xFFFFFFFE + 0 = 0xFFFFFFFE, carry=0
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0xFFFFFFFE));
        assert_eq!(witness[5], Fr::zero()); // pc_carry=0
        // rd_val = 0xFFFFFFFE + 4 = 0x100000002 mod 2^32 = 0x2, carry=1
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0x2));
        assert_eq!(witness[6], Fr::one()); // rd_carry=1
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_jal_both_overflow() {
        // pc 和 imm 都很大，双溢出
        let ccs = JalCircuit::build_ccs();
        let witness = JalCircuit::assign_witness(0xFFFFFFFF, 0xFFFFFFFF);
        // pc_new = (0xFFFFFFFF + 0xFFFFFFFF) mod 2^32 = 0xFFFFFFFE, carry=1
        assert_eq!(witness[4], Fr::from_u32_with_wrap(0xFFFFFFFE));
        assert_eq!(witness[5], Fr::one()); // pc_carry=1
        // rd_val = 0xFFFFFFFF + 4 = 0x100000003 mod 2^32 = 0x3, carry=1
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0x3));
        assert_eq!(witness[6], Fr::one()); // rd_carry=1
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_jal_soundness_tampered_pc_new() {
        let ccs = JalCircuit::build_ccs();
        let mut witness = JalCircuit::assign_witness(0x1000, 0x100);
        witness[4] = Fr::from_u32_with_wrap(0x9999); // 篡改 pc_new
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_jal_soundness_tampered_rd() {
        let ccs = JalCircuit::build_ccs();
        let mut witness = JalCircuit::assign_witness(0x1000, 0x100);
        witness[3] = Fr::from_u32_with_wrap(0x9999); // 篡改 rd_val
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_jal_soundness_tampered_carry() {
        let ccs = JalCircuit::build_ccs();
        let mut witness = JalCircuit::assign_witness(0x1000, 0xFFFFFFF0);
        // 篡改 pc_carry=0（实际应为 1）
        witness[5] = Fr::zero();
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_jal_soundness_non_binary_carry() {
        let ccs = JalCircuit::build_ccs();
        let mut witness = JalCircuit::assign_witness(0x1000, 0x100);
        witness[5] = Fr::from_u32_with_wrap(2); // pc_carry=2（非 0/1）
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_jal_to_instance() {
        let inst = JalCircuit::to_instance(0x2000, 0x50).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0x2050));
    }

    #[test]
    fn test_jal_link_register_correct() {
        // JAL 后 rd 应指向下一条指令（pc+4）
        let inst = JalCircuit::to_instance(0x1000, 0x200).expect("应成功");
        assert_eq!(inst.witness[3], Fr::from_u32_with_wrap(0x1004));
        assert_eq!(inst.witness[4], Fr::from_u32_with_wrap(0x1200));
    }

    // ===== BEQ 测试 =====

    #[test]
    fn test_beq_build_ccs() {
        let ccs = BeqCircuit::build_ccs();
        assert_eq!(ccs.num_vars, 8);
        assert_eq!(ccs.num_rows(), 4);
    }

    #[test]
    fn test_beq_taken_equal() {
        let ccs = BeqCircuit::build_ccs();
        let witness = BeqCircuit::assign_witness(0x1000, 42, 42, 0x100);
        // rs1 == rs2 → taken=1, pc_new = 0x1000 + 0x100 = 0x1100
        assert_eq!(witness[5], Fr::one()); // taken
        assert_eq!(witness[6], Fr::from_u32_with_wrap(0x1100));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_beq_not_taken_not_equal() {
        let ccs = BeqCircuit::build_ccs();
        let witness = BeqCircuit::assign_witness(0x1000, 42, 99, 0x100);
        // rs1 != rs2 → taken=0, pc_new = 0x1000 + 4 = 0x1004
        assert_eq!(witness[5], Fr::zero()); // taken
        assert_eq!(witness[6], Fr::from_u32_with_wrap(0x1004));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_beq_taken_with_overflow() {
        // taken=1 且 pc+imm 溢出
        let ccs = BeqCircuit::build_ccs();
        let witness = BeqCircuit::assign_witness(0x1000, 10, 10, 0xFFFFF000);
        // pc_new = (0x1000 + 0xFFFFF000) mod 2^32 = 0x0000, carry=1
        assert_eq!(witness[5], Fr::one()); // taken=1
        assert_eq!(witness[6], Fr::zero()); // pc_new=0
        assert_eq!(witness[7], Fr::one()); // carry=1
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_beq_not_taken_with_overflow() {
        // taken=0 且 pc+4 溢出
        let ccs = BeqCircuit::build_ccs();
        let witness = BeqCircuit::assign_witness(0xFFFFFFFE, 1, 2, 0x100);
        // taken=0, pc_new = (0xFFFFFFFE + 4) mod 2^32 = 0x2, carry=1
        assert_eq!(witness[5], Fr::zero()); // taken=0
        assert_eq!(witness[6], Fr::from_u32_with_wrap(0x2));
        assert_eq!(witness[7], Fr::one()); // carry=1
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_beq_soundness_tampered_taken() {
        let ccs = BeqCircuit::build_ccs();
        let mut witness = BeqCircuit::assign_witness(0x1000, 42, 99, 0x100);
        // rs1 != rs2 但篡改 taken=1 → 约束 taken*(rs1-rs2)=0 应失败
        witness[5] = Fr::one();
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_beq_soundness_non_binary_taken() {
        let ccs = BeqCircuit::build_ccs();
        let mut witness = BeqCircuit::assign_witness(0x1000, 42, 42, 0x100);
        witness[5] = Fr::from_u32_with_wrap(2); // taken=2（非 0/1）
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_beq_soundness_tampered_carry() {
        let ccs = BeqCircuit::build_ccs();
        let mut witness = BeqCircuit::assign_witness(0x1000, 10, 10, 0xFFFFF000);
        // 篡改 carry=0（实际应为 1）
        witness[7] = Fr::zero();
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_beq_to_instance_taken() {
        let inst = BeqCircuit::to_instance(0x1000, 10, 10, 0x200).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0x1200));
    }

    #[test]
    fn test_beq_to_instance_not_taken() {
        let inst = BeqCircuit::to_instance(0x1000, 10, 20, 0x200).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0x1004));
    }

    #[test]
    fn test_beq_both_zero_taken() {
        // rs1=0, rs2=0 → 相等 → taken
        let ccs = BeqCircuit::build_ccs();
        let witness = BeqCircuit::assign_witness(0x1000, 0, 0, 0x100);
        assert_eq!(witness[5], Fr::one());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    // ===== LUI 测试 =====

    #[test]
    fn test_lui_build_ccs() {
        let ccs = LuiCircuit::build_ccs();
        assert_eq!(ccs.num_vars, 3);
        assert_eq!(ccs.num_rows(), 1);
    }

    #[test]
    fn test_lui_basic() {
        let ccs = LuiCircuit::build_ccs();
        let witness = LuiCircuit::assign_witness(0x00001);
        // rd = 0x00001 << 12 = 0x1000
        assert_eq!(witness[2], Fr::from_u32_with_wrap(0x1000));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_lui_large_imm() {
        let ccs = LuiCircuit::build_ccs();
        let witness = LuiCircuit::assign_witness(0xFFFFF);
        // rd = 0xFFFFF << 12 = 0xFFFFF000
        assert_eq!(witness[2], Fr::from_u32_with_wrap(0xFFFFF000));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_lui_zero_imm() {
        let ccs = LuiCircuit::build_ccs();
        let witness = LuiCircuit::assign_witness(0);
        assert_eq!(witness[2], Fr::zero());
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_lui_soundness_tampered_rd() {
        let ccs = LuiCircuit::build_ccs();
        let mut witness = LuiCircuit::assign_witness(0x1);
        witness[2] = Fr::from_u32_with_wrap(0x9999);
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_lui_to_instance() {
        let inst = LuiCircuit::to_instance(0xABC).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[1], Fr::from_u32_with_wrap(0xABC000));
    }

    // ===== AUIPC 测试 =====

    #[test]
    fn test_auipc_build_ccs() {
        let ccs = AuipcCircuit::build_ccs();
        assert_eq!(ccs.num_vars, 5);
        assert_eq!(ccs.num_rows(), 2);
    }

    #[test]
    fn test_auipc_basic() {
        let ccs = AuipcCircuit::build_ccs();
        let witness = AuipcCircuit::assign_witness(0x1000, 0x1);
        // rd = 0x1000 + (0x1 << 12) = 0x1000 + 0x1000 = 0x2000
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0x2000));
        assert_eq!(witness[4], Fr::zero()); // carry=0
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_auipc_zero_imm() {
        let ccs = AuipcCircuit::build_ccs();
        let witness = AuipcCircuit::assign_witness(0x2000, 0);
        assert_eq!(witness[3], Fr::from_u32_with_wrap(0x2000));
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_auipc_with_overflow() {
        // pc + imm*4096 溢出
        let ccs = AuipcCircuit::build_ccs();
        let witness = AuipcCircuit::assign_witness(0xFFFFF000, 0x1);
        // imm*4096 = 0x1000, pc + 0x1000 = 0xFFFFF000 + 0x1000 = 0x100000000 mod 2^32 = 0
        // carry=1
        assert_eq!(witness[3], Fr::zero()); // rd_val=0
        assert_eq!(witness[4], Fr::one()); // carry=1
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_auipc_large_imm() {
        // imm = 0xFFFFF (20 位最大值)
        let ccs = AuipcCircuit::build_ccs();
        let witness = AuipcCircuit::assign_witness(0x1000, 0xFFFFF);
        // imm*4096 = 0xFFFFF000, pc + 0xFFFFF000 = 0x1000 + 0xFFFFF000 = 0x100000000 mod 2^32 = 0
        // carry=1
        assert_eq!(witness[3], Fr::zero()); // rd_val=0
        assert_eq!(witness[4], Fr::one()); // carry=1
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_auipc_soundness_tampered_rd() {
        let ccs = AuipcCircuit::build_ccs();
        let mut witness = AuipcCircuit::assign_witness(0x1000, 0x1);
        witness[3] = Fr::from_u32_with_wrap(0x9999);
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_auipc_soundness_tampered_carry() {
        let ccs = AuipcCircuit::build_ccs();
        let mut witness = AuipcCircuit::assign_witness(0xFFFFF000, 0x1);
        // 篡改 carry=0（实际应为 1）
        witness[4] = Fr::zero();
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_auipc_soundness_non_binary_carry() {
        let ccs = AuipcCircuit::build_ccs();
        let mut witness = AuipcCircuit::assign_witness(0x1000, 0x1);
        witness[4] = Fr::from_u32_with_wrap(2); // carry=2（非 0/1）
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_auipc_to_instance() {
        let inst = AuipcCircuit::to_instance(0x1000, 0x5).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        // rd = 0x1000 + 0x5*4096 = 0x1000 + 0x5000 = 0x6000
        assert_eq!(inst.public_inputs[2], Fr::from_u32_with_wrap(0x6000));
    }
}
