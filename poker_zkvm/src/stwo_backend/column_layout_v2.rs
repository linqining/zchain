//! # Stwo Trace 列布局 v3.5 — riscv32im M 扩展算术约束（132 列）
//!
//! 在 v3.4（81 列）基础上追加 M 扩展算术约束 witness 列（+51 列）：
//! - MUL carry chain（21 列）：7 carry × (lo8 + hi0 + hi1)
//! - MUL 低位/高位结果（8 列）+ abs/sign（11 列）
//! - DIV witness（11 列）：quotient / remainder / special / sign
//!
//! ## 列布局（132 列）
//!
//! | 范围 | 列名 | 说明 |
//! |------|------|------|
//! | 0-3 | Pc (4×8-bit limb) | 当前 PC |
//! | 4-7 | PcNext (4×8-bit limb) | 下一 PC |
//! | 8-9 | ArithFlag (2 列) | 算术标志（ADD/ADDI=carry, SUB=borrow） |
//! | 10-13 | ValueAEffective (4×8-bit limb) | 操作数 A 有效值（rd=0 时为 0） |
//! | 14-17 | ValueB (4×8-bit limb) | 操作数 B 值 |
//! | 18-21 | ValueC (4×8-bit limb) | 操作数 C 值 |
//! | 22-64 | Is* indicators (43 列) | 指令 one-hot 标记（RV32I 34 + M 扩展 8 + padding 1） |
//! | 65-68 | HelperA (4×8-bit limb) | 复用：LUI imm / JAL/Branch/AUIPC Pc+imm / Load/Store MemAddr / JALR PcNextAux |
//! | 69-72 | HelperB (4×8-bit limb) | 复用：Load mem_value / Store rs2_value |
//! | 73 | Taken | 分支跳转标记 |
//! | 74-77 | MemAddr (4×8-bit limb) | Load/Store 地址（logup claim 用） |
//! | 78 | SyscallId | ECALL syscall ID（1 列 M31） |
//! | 79-80 | PcCarryFlag (2 列) | PC 进位标志 |
//! | 81-87 | MulCarryLo[0..6] (7 列) | M 扩展 carry 低 8 位（MUL/DIV 共享，one-hot 互斥） |
//! | 88-94 | MulCarryHi0[0..6] (7 列) | M 扩展 carry bit-8（binary 约束） |
//! | 95-101 | MulCarryHi1[0..6] (7 列) | M 扩展 carry bit-9（binary 约束） |
//! | 102-105 | MulHigh[0..3] (4×8-bit limb) | 乘积高 32 位 c₄..c₇ |
//! | 106-109 | AbsA[0..3] (4×8-bit limb) | \|rs1\| 绝对值（MULH/MULHSU） |
//! | 110-113 | AbsB[0..3] (4×8-bit limb) | \|rs2\| 绝对值（MULH） |
//! | 114 | SignA | rs1 符号位（binary） |
//! | 115 | SignB | rs2 符号位（binary） |
//! | 116 | LowNonzero | 乘积低 32 位 ≠ 0（补码借位，binary） |
//! | 117-120 | DivQuot[0..3] (4×8-bit limb) | 商 q |
//! | 121-124 | DivRem[0..3] (4×8-bit limb) | 余数 r |
//! | 125 | DivIsSpecial | 除零/溢出标志（binary） |
//! | 126 | DivSignQ | 商符号（有符号 DIV/REM，binary） |
//! | 127 | DivSignR | 余数符号（有符号 DIV/REM，binary） |
//! | 128-131 | MulLow[0..3] (4×8-bit limb) | 乘积低 32 位 c₀..c₃（MUL/MULH/MULHSU/MULHU/DIV carry chain 统一使用） |

/// 32-bit 值的 limb 数量（4×8-bit）。
pub const WORD_LIMB_COUNT: usize = 4;

/// 字大小（字节），与 `WORD_LIMB_COUNT` 一致。
pub const WORD_SIZE: usize = 4;

// ===========================================================================
// 主 trace 列索引常量（132 列）
// ===========================================================================

// ----- PC 相关（4×8-bit limb each）-----
/// col 0-3：当前 PC（4×8-bit limb）
pub const COL_PC_BASE: usize = 0;
/// col 4-7：下一 PC（4×8-bit limb）
pub const COL_PC_NEXT_BASE: usize = 4;

// ----- 算术标志（2 列，ADD/ADDI=carry, SUB=borrow，互斥使用）-----
/// col 8-9：算术标志（ArithFlag，16-bit 边界）
///
/// - ADD/ADDI 行：carry0, carry1（16-bit 加法进位）
/// - SUB 行：borrow0, borrow1（16-bit 减法借位）
/// - 其他行：0
///
/// 合并理由：ADD/ADDI 与 SUB 的 indicator one-hot 互斥，可复用同一组列。
pub const COL_CARRY_FLAG_BASE: usize = 8;

// ----- 操作数值（4×8-bit limb each，移除 ValueA 死列）-----
/// col 10-13：操作数 A 有效值（4×8-bit limb，rd=0 时为 0）
pub const COL_VALUE_A_EFF_BASE: usize = 10;
/// col 14-17：操作数 B 值（4×8-bit limb）
pub const COL_VALUE_B_BASE: usize = 14;
/// col 18-21：操作数 C 值（4×8-bit limb）
pub const COL_VALUE_C_BASE: usize = 18;

// ----- 指令 indicator（43 列，one-hot）-----
/// indicator 列起始索引（col 22-64，共 43 列）
pub const COL_IS_BASE: usize = 22;

// 指令类别 indicator 偏移（与 `crate::constraints::instruction_category` 对齐）
/// LUI indicator（类别 0）
pub const IS_LUI: usize = 22;
/// AUIPC indicator（类别 1）
pub const IS_AUIPC: usize = 23;
/// JAL indicator（类别 2）
pub const IS_JAL: usize = 24;
/// JALR indicator（类别 3）
pub const IS_JALR: usize = 25;
/// BEQ indicator（类别 4）
pub const IS_BEQ: usize = 26;
/// BNE indicator（类别 5）
pub const IS_BNE: usize = 27;
/// BLT indicator（类别 6）
pub const IS_BLT: usize = 28;
/// BGE indicator（类别 7）
pub const IS_BGE: usize = 29;
/// BLTU indicator（类别 8）
pub const IS_BLTU: usize = 30;
/// BGEU indicator（类别 9）
pub const IS_BGEU: usize = 31;
/// LB/LH/LW/LBU/LHU 共用 indicator（类别 10）
pub const IS_LOAD: usize = 32;
/// SB/SH/SW 共用 indicator（类别 11）
pub const IS_STORE: usize = 33;
/// ADDI indicator（类别 12）
pub const IS_ADDI: usize = 34;
/// SLTI indicator（类别 13）
pub const IS_SLTI: usize = 35;
/// SLTIU indicator（类别 14）
pub const IS_SLTIU: usize = 36;
/// XORI indicator（类别 15）
pub const IS_XORI: usize = 37;
/// ORI indicator（类别 16）
pub const IS_ORI: usize = 38;
/// ANDI indicator（类别 17）
pub const IS_ANDI: usize = 39;
/// SLLI indicator（类别 18）
pub const IS_SLLI: usize = 40;
/// SRLI indicator（类别 19）
pub const IS_SRLI: usize = 41;
/// SRAI indicator（类别 20）
pub const IS_SRAI: usize = 42;
/// ADD indicator（类别 21）
pub const IS_ADD: usize = 43;
/// SUB indicator（类别 22）
pub const IS_SUB: usize = 44;
/// SLL indicator（类别 23）
pub const IS_SLL: usize = 45;
/// SLT indicator（类别 24）
pub const IS_SLT: usize = 46;
/// SLTU indicator（类别 25）
pub const IS_SLTU: usize = 47;
/// XOR indicator（类别 26）
pub const IS_XOR: usize = 48;
/// SRL indicator（类别 27）
pub const IS_SRL: usize = 49;
/// SRA indicator（类别 28）
pub const IS_SRA: usize = 50;
/// OR indicator（类别 29）
pub const IS_OR: usize = 51;
/// AND indicator（类别 30）
pub const IS_AND: usize = 52;
/// FENCE indicator（类别 31）
pub const IS_FENCE: usize = 53;
/// ECALL indicator（类别 32）
pub const IS_ECALL: usize = 54;
/// EBREAK indicator（类别 33）
pub const IS_EBREAK: usize = 55;
// ===== M 扩展 indicators（类别 34-41，riscv32im 支持）=====
/// MUL indicator（类别 34）—— M 扩展：低 32 位乘法
pub const IS_MUL: usize = 56;
/// MULH indicator（类别 35）—— M 扩展：有符号×有符号高 32 位
pub const IS_MULH: usize = 57;
/// MULHSU indicator（类别 36）—— M 扩展：有符号×无符号高 32 位
pub const IS_MULHSU: usize = 58;
/// MULHU indicator（类别 37）—— M 扩展：无符号×无符号高 32 位
pub const IS_MULHU: usize = 59;
/// DIV indicator（类别 38）—— M 扩展：有符号除法
pub const IS_DIV: usize = 60;
/// DIVU indicator（类别 39）—— M 扩展：无符号除法
pub const IS_DIVU: usize = 61;
/// REM indicator（类别 40）—— M 扩展：有符号取余
pub const IS_REM: usize = 62;
/// REMU indicator（类别 41）—— M 扩展：无符号取余
pub const IS_REMU: usize = 63;
/// padding 行 indicator（类别 42）
pub const IS_PADDING: usize = 64;

/// indicator 列数量（43 个指令类别 = RV32I 35 + M 扩展 8）
pub const NUM_INSTRUCTION_CATEGORIES: usize = 43;

// ----- 辅助变量（4×8-bit limb each，2 个 helper）-----
/// col 65-68：辅助变量 A（4×8-bit limb）
///
/// 复用模式（LUI/JAL/Branch/AUIPC/Load/Store/JALR 互斥）：
/// - LUI 行：imm 值（用于 rd_eff = imm 约束）
/// - JAL/Branch taken/AUIPC 行：Pc + imm 预计算值
/// - Load/Store 行：MemAddr 值（rs1 + imm，与 MemAddr 列一致）
/// - JALR 行：PcNextAux 值（JALR 目标地址 = (rs1 + imm) & !1）
/// - 其他行：0（不被约束）
pub const COL_HELPER_A_BASE: usize = 65;
/// col 69-72：辅助变量 B（4×8-bit limb）
///
/// 复用模式（Load/Store 互斥）：
/// - Load 行：mem_value（加载值，用于 rd_eff = mem_value 约束）
/// - Store 行：rs2_value（存储值，用于 rs2 = mem_value 约束）
/// - 其他行：0（不被约束）
pub const COL_HELPER_B_BASE: usize = 69;

// ----- 分支辅助 -----
/// col 73：分支跳转标记（0/1）
pub const COL_TAKEN: usize = 73;

// ----- Phase 3：Load/Store 内存地址（4×8-bit limb）-----
/// col 74-77：Load/Store 指令的内存地址（4×8-bit limb，非 Load/Store 时为 0）
///
/// 注：HelperA 在 Load/Store 行也存 MemAddr 值，但 MemAddr 列单独保留用于 logup claim
/// 和调试输出。
pub const COL_MEM_ADDR_BASE: usize = 74;

// ----- Phase 4：ECALL（仅保留 SyscallId 1 列）-----
/// col 78：SyscallId（1 列 M31，直接表示 syscall_id 0-127）。
///
/// ECALL 行填 syscall_id，非 ECALL 行填 0。
/// v3 移除了 v2 的 24 列 Args/Outputs（texas_poker 不使用）。
pub const COL_SYSCALL_ID: usize = 78;

// ----- Phase 4：PC carry（2 列）-----
/// col 79-80：PC 进位标志（16-bit 边界，仅 IsNonFlow=1 或 Branch not-taken 时使用）。
pub const COL_PC_CARRY_FLAG_BASE: usize = 79;

// ===========================================================================
// M 扩展算术约束 witness 列（col 81-131，共 51 列）
// ===========================================================================
// 参考 RISC Zero / SP1 / OpenVM：8-bit 部分积 + carry chain。
// MUL/DIV 共享 carry 列（81-101），one-hot indicator 互斥保证同一行只使用一组。

/// carry chain 的 carry 数量（7 个：carry0..carry6）。
pub const MUL_CARRY_COUNT: usize = 7;

/// col 81-87：carry 低 8 位（7 列）。
///
/// carryₖ = carry_loₖ + hi0ₖ·256 + hi1ₖ·512
/// carry_loₖ ∈ [0,255]（信任，与 ADD limb 一致）
pub const COL_MUL_CARRY_LO_BASE: usize = 81;

/// col 88-94：carry bit-8（7 列，binary 约束）。
pub const COL_MUL_CARRY_HI0_BASE: usize = 88;

/// col 95-101：carry bit-9（7 列，binary 约束）。
pub const COL_MUL_CARRY_HI1_BASE: usize = 95;

/// col 102-105：乘积高 32 位 c₄..c₇（4×8-bit limb）。
///
/// - MUL：高位丢弃（自由值，仅参与 carry chain 完整性）
/// - MULHU：= rd_eff（高 32 位结果）
/// - MULH/MULHSU：unsigned 乘积高位，经符号调整后 = rd_eff
/// - DIV：必须 = 0（因 q·d ≤ n < 2³²）
pub const COL_MUL_HIGH_BASE: usize = 102;

/// col 106-109：|rs1| 绝对值的 4×8-bit limb（MULH/MULHSU 使用）。
pub const COL_ABS_A_BASE: usize = 106;

/// col 110-113：|rs2| 绝对值的 4×8-bit limb（MULH 使用）。
pub const COL_ABS_B_BASE: usize = 110;

/// col 114：rs1 符号位（1=负数，binary）。
pub const COL_SIGN_A: usize = 114;

/// col 115：rs2 符号位（1=负数，binary）。
pub const COL_SIGN_B: usize = 115;

/// col 116：乘积低 32 位 ≠ 0 标志（补码取反借位用，binary）。
///
/// 用于 MULH/MULHSU 结果符号调整：rd_eff = sign ? (2³²−1−high32−low_nonzero) : high32
pub const COL_LOW_NONZERO: usize = 116;

/// col 117-120：商 q 的 4×8-bit limb（DIV/DIVU/REM/REMU 使用）。
pub const COL_DIV_QUOT_BASE: usize = 117;

/// col 121-124：余数 r 的 4×8-bit limb（DIV/DIVU/REM/REMU 使用）。
pub const COL_DIV_REM_BASE: usize = 121;

/// col 125：除零/溢出特殊标志（1=特殊情况，binary）。
///
/// RISC-V 特殊情况：
/// - d=0：q=0xFFFFFFFF，r=n
/// - DIV INT_MIN/−1：q=INT_MIN，r=0
pub const COL_DIV_IS_SPECIAL: usize = 125;

/// col 126：商符号（有符号 DIV/REM，1=负，binary）。
pub const COL_DIV_SIGN_Q: usize = 126;

/// col 127：余数符号（有符号 DIV/REM，1=负，binary）。
pub const COL_DIV_SIGN_R: usize = 127;

/// col 128-131：乘积低 32 位 c₀..c₃（4×8-bit limb）。
///
/// carry chain 统一使用 COL_MUL_LOW 作为 c₀..c₃，COL_MUL_HIGH 作为 c₄..c₇。
/// - MUL：rd_eff = COL_MUL_LOW（低 32 位 = 结果）
/// - MULHU：rd_eff = COL_MUL_HIGH（高 32 位 = 结果）
/// - MULH/MULHSU：rd_eff = sign_adjust(COL_MUL_HIGH)（符号调整后 = 结果）
/// - DIV：COL_MUL_LOW + COL_DIV_REM = COL_ABS_A（q·d+r=n），COL_MUL_HIGH = 0
pub const COL_MUL_LOW_BASE: usize = 128;

/// v3.5 列布局总列数（132 列）。
///
/// 132 列 = v3.4 基础(81) + M 扩展算术 witness(51)
///   基础 81 = PC(8) + ArithFlag(2) + ValueAEff/B/C(12) + Indicator(43)
///           + HelperA(4) + HelperB(4) + Taken(1) + MemAddr(4) + SyscallId(1) + PcCarry(2)
///   M 扩展 51 = CarryLo(7) + CarryHi0(7) + CarryHi1(7) + MulHigh(4) + MulLow(4)
///             + AbsA(4) + AbsB(4) + SignA(1) + SignB(1) + LowNonzero(1)
///             + DivQuot(4) + DivRem(4) + DivIsSpecial(1) + DivSignQ(1) + DivSignR(1)
pub const NUM_COLUMNS: usize = 132;

/// Phase 4 ECALL dispatch 列数量（v3 仅 1 列 SyscallId）。
pub const ECALL_DISPATCH_NUM_COLUMNS: usize = 1;

/// 将指令类别 ID（0-42）映射为 indicator 列索引。
#[must_use]
pub fn category_to_indicator_col(category: usize) -> usize {
    assert!(
        category < NUM_INSTRUCTION_CATEGORIES,
        "category_to_indicator_col: category {} >= {}",
        category,
        NUM_INSTRUCTION_CATEGORIES
    );
    COL_IS_BASE + category
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_num_columns() {
        assert_eq!(
            NUM_COLUMNS,
            132,
            "v3.5 列布局应为 132 列（v3.4 81 列 + M 扩展算术 witness 51 列）"
        );
    }

    #[test]
    fn test_word_limb_count() {
        assert_eq!(WORD_LIMB_COUNT, 4, "4×8-bit limb 方案，WORD_LIMB_COUNT=4");
        assert_eq!(WORD_SIZE, 4);
    }

    #[test]
    fn test_column_ranges_no_overlap() {
        let ranges: [(usize, usize); 21] = [
            (COL_PC_BASE, 4),                     // 0-3
            (COL_PC_NEXT_BASE, 4),                // 4-7
            (COL_CARRY_FLAG_BASE, 2),             // 8-9（合并 carry/borrow）
            (COL_VALUE_A_EFF_BASE, 4),            // 10-13
            (COL_VALUE_B_BASE, 4),                // 14-17
            (COL_VALUE_C_BASE, 4),                // 18-21
            (COL_HELPER_A_BASE, 4),               // 65-68
            (COL_HELPER_B_BASE, 4),               // 69-72
            (COL_MUL_CARRY_LO_BASE, MUL_CARRY_COUNT),    // 81-87
            (COL_MUL_CARRY_HI0_BASE, MUL_CARRY_COUNT),   // 88-94
            (COL_MUL_CARRY_HI1_BASE, MUL_CARRY_COUNT),   // 95-101
            (COL_MUL_HIGH_BASE, 4),               // 102-105
            (COL_ABS_A_BASE, 4),                   // 106-109
            (COL_ABS_B_BASE, 4),                   // 110-113
            (COL_SIGN_A, 1),                       // 114
            (COL_SIGN_B, 1),                       // 115
            (COL_LOW_NONZERO, 1),                  // 116
            (COL_DIV_QUOT_BASE, 4),                // 117-120
            (COL_DIV_REM_BASE, 4),                 // 121-124
            (COL_DIV_IS_SPECIAL, 3),               // 125-127（IsSpecial + SignQ + SignR）
            (COL_MUL_LOW_BASE, 4),                 // 128-131（MulLow c₀..c₃）
        ];
        let mut all_cols = HashSet::new();
        for (base, count) in &ranges {
            for offset in 0..*count {
                let col = base + offset;
                assert!(all_cols.insert(col), "列 {} 重复分配", col);
            }
        }
    }

    #[test]
    fn test_indicator_columns_range() {
        let indicators = [
            IS_LUI, IS_AUIPC, IS_JAL, IS_JALR, IS_BEQ, IS_BNE, IS_BLT, IS_BGE,
            IS_BLTU, IS_BGEU, IS_LOAD, IS_STORE, IS_ADDI, IS_SLTI, IS_SLTIU,
            IS_XORI, IS_ORI, IS_ANDI, IS_SLLI, IS_SRLI, IS_SRAI, IS_ADD, IS_SUB,
            IS_SLL, IS_SLT, IS_SLTU, IS_XOR, IS_SRL, IS_SRA, IS_OR, IS_AND,
            IS_FENCE, IS_ECALL, IS_EBREAK,
            // M 扩展（8）
            IS_MUL, IS_MULH, IS_MULHSU, IS_MULHU, IS_DIV, IS_DIVU, IS_REM, IS_REMU,
            IS_PADDING,
        ];
        assert_eq!(indicators.len(), NUM_INSTRUCTION_CATEGORIES);
        for &col in &indicators {
            assert!(
                col >= COL_IS_BASE && col < COL_IS_BASE + NUM_INSTRUCTION_CATEGORIES,
                "IS_* 列 {} 不在 indicator 范围 [22, {}]",
                col,
                COL_IS_BASE + NUM_INSTRUCTION_CATEGORIES
            );
        }
    }

    #[test]
    fn test_indicator_columns_distinct() {
        let indicators = [
            IS_LUI, IS_AUIPC, IS_JAL, IS_JALR, IS_BEQ, IS_BNE, IS_BLT, IS_BGE,
            IS_BLTU, IS_BGEU, IS_LOAD, IS_STORE, IS_ADDI, IS_SLTI, IS_SLTIU,
            IS_XORI, IS_ORI, IS_ANDI, IS_SLLI, IS_SRLI, IS_SRAI, IS_ADD, IS_SUB,
            IS_SLL, IS_SLT, IS_SLTU, IS_XOR, IS_SRL, IS_SRA, IS_OR, IS_AND,
            IS_FENCE, IS_ECALL, IS_EBREAK,
            // M 扩展（8）
            IS_MUL, IS_MULH, IS_MULHSU, IS_MULHU, IS_DIV, IS_DIVU, IS_REM, IS_REMU,
            IS_PADDING,
        ];
        let unique: HashSet<_> = indicators.iter().collect();
        assert_eq!(unique.len(), indicators.len(), "IS_* 列有重复");
    }

    #[test]
    fn test_category_to_indicator_col() {
        assert_eq!(category_to_indicator_col(0), IS_LUI);
        assert_eq!(category_to_indicator_col(21), IS_ADD);
        // M 扩展：类别 34-41
        assert_eq!(category_to_indicator_col(34), IS_MUL);
        assert_eq!(category_to_indicator_col(41), IS_REMU);
        assert_eq!(category_to_indicator_col(42), IS_PADDING);
    }

    #[test]
    #[should_panic(expected = "category 43 >= 43")]
    fn test_category_to_indicator_col_out_of_range() {
        let _ = category_to_indicator_col(43);
    }

    #[test]
    fn test_helper_columns() {
        assert_eq!(COL_HELPER_A_BASE, 65);
        assert_eq!(COL_HELPER_B_BASE, 69);
        assert_eq!(COL_HELPER_B_BASE + WORD_LIMB_COUNT, 73);
    }

    #[test]
    fn test_auxiliary_columns() {
        assert_eq!(COL_TAKEN, 73);
        assert_eq!(COL_MEM_ADDR_BASE, 74);
        assert_eq!(COL_SYSCALL_ID, 78);
        assert_eq!(ECALL_DISPATCH_NUM_COLUMNS, 1);
        assert_eq!(COL_PC_CARRY_FLAG_BASE, 79);
    }

    #[test]
    fn test_m_extension_columns() {
        // v3.5：M 扩展算术约束 witness 列布局（col 81-131）
        assert_eq!(MUL_CARRY_COUNT, 7);
        assert_eq!(COL_MUL_CARRY_LO_BASE, 81);
        assert_eq!(COL_MUL_CARRY_HI0_BASE, 88);
        assert_eq!(COL_MUL_CARRY_HI1_BASE, 95);
        assert_eq!(COL_MUL_CARRY_HI1_BASE + MUL_CARRY_COUNT, 102); // 95+7=102
        assert_eq!(COL_MUL_HIGH_BASE, 102);
        assert_eq!(COL_ABS_A_BASE, 106);
        assert_eq!(COL_ABS_B_BASE, 110);
        assert_eq!(COL_SIGN_A, 114);
        assert_eq!(COL_SIGN_B, 115);
        assert_eq!(COL_LOW_NONZERO, 116);
        assert_eq!(COL_DIV_QUOT_BASE, 117);
        assert_eq!(COL_DIV_REM_BASE, 121);
        assert_eq!(COL_DIV_IS_SPECIAL, 125);
        assert_eq!(COL_DIV_SIGN_Q, 126);
        assert_eq!(COL_DIV_SIGN_R, 127);
        assert_eq!(COL_MUL_LOW_BASE, 128);
        // 最后一个 M 扩展列 + 1 = NUM_COLUMNS
        assert_eq!(COL_MUL_LOW_BASE + WORD_LIMB_COUNT, NUM_COLUMNS, "最后一个列应为 131，NUM_COLUMNS=132");
    }
}
