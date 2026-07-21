//! # Stwo Trace 列布局 v3 — 优化方案 D（87 列）
//!
//! 在 v2（128 列）基础上移除 41 列：
//! - 移除 17 列死列（OpA/B/C, ImmC, InstrVal, ValueA, BranchCond, Shamt, SgnA/B/C）
//!   这些列在 AIR 约束和 prover logup 中均未使用
//! - 移除 24 列 ECALL Args/Outputs（仅保留 SyscallId 1 列）
//!   texas_poker 场景不使用 ECALL args/outputs，Tier 2 Poseidon AIR 需要时再恢复
//!
//! ## 列布局（87 列）
//!
//! | 范围 | 列名 | 说明 |
//! |------|------|------|
//! | 0-3 | Pc (4×8-bit limb) | 当前 PC |
//! | 4-7 | PcNext (4×8-bit limb) | 下一 PC |
//! | 8-11 | PcNextAux (4×8-bit limb) | PC 辅助（JALR 等） |
//! | 12-13 | CarryFlag (2 列) | 16-bit 边界进位 |
//! | 14-15 | BorrowFlag (2 列) | 16-bit 边界借位 |
//! | 16-19 | ValueAEffective (4×8-bit limb) | 操作数 A 有效值（rd=0 时为 0） |
//! | 20-23 | ValueB (4×8-bit limb) | 操作数 B 值 |
//! | 24-27 | ValueC (4×8-bit limb) | 操作数 C 值 |
//! | 28-62 | Is* indicators (35 列) | 指令 one-hot 标记 |
//! | 63-66 | Helper1 (4×8-bit limb) | 辅助变量 1 |
//! | 67-70 | Helper2 (4×8-bit limb) | 辅助变量 2 |
//! | 71-74 | Helper3 (4×8-bit limb) | 辅助变量 3 |
//! | 75-78 | Helper4 (4×8-bit limb) | 辅助变量 4（Load/Store mem_value） |
//! | 79 | Taken | 分支跳转标记 |
//! | 80-83 | MemAddr (4×8-bit limb) | Load/Store 地址 |
//! | 84 | SyscallId | ECALL syscall ID（1 列 M31） |
//! | 85-86 | PcCarryFlag (2 列) | PC 进位标志 |

/// 32-bit 值的 limb 数量（4×8-bit）。
pub const WORD_LIMB_COUNT: usize = 4;

/// 字大小（字节），与 `WORD_LIMB_COUNT` 一致。
pub const WORD_SIZE: usize = 4;

// ===========================================================================
// 主 trace 列索引常量（87 列）
// ===========================================================================

// ----- PC 相关（4×8-bit limb each）-----
/// col 0-3：当前 PC（4×8-bit limb）
pub const COL_PC_BASE: usize = 0;
/// col 4-7：下一 PC（4×8-bit limb）
pub const COL_PC_NEXT_BASE: usize = 4;
/// col 8-11：PC 辅助值（4×8-bit limb，JALR 等用）
pub const COL_PC_NEXT_AUX_BASE: usize = 8;

// ----- 进位/借位标志（2 列 each，16-bit 边界）-----
/// col 12-13：进位标志（CarryFlag，16-bit 边界）
pub const COL_CARRY_FLAG_BASE: usize = 12;
/// col 14-15：借位标志（BorrowFlag，16-bit 边界）
pub const COL_BORROW_FLAG_BASE: usize = 14;

// ----- 操作数值（4×8-bit limb each，移除 ValueA 死列）-----
/// col 16-19：操作数 A 有效值（4×8-bit limb，rd=0 时为 0）
pub const COL_VALUE_A_EFF_BASE: usize = 16;
/// col 20-23：操作数 B 值（4×8-bit limb）
pub const COL_VALUE_B_BASE: usize = 20;
/// col 24-27：操作数 C 值（4×8-bit limb）
pub const COL_VALUE_C_BASE: usize = 24;

// ----- 指令 indicator（35 列，one-hot）-----
/// indicator 列起始索引（col 28-62，共 35 列）
pub const COL_IS_BASE: usize = 28;

// 指令类别 indicator 偏移（与 `crate::constraints::instruction_category` 对齐）
/// LUI indicator（类别 0）
pub const IS_LUI: usize = 28;
/// AUIPC indicator（类别 1）
pub const IS_AUIPC: usize = 29;
/// JAL indicator（类别 2）
pub const IS_JAL: usize = 30;
/// JALR indicator（类别 3）
pub const IS_JALR: usize = 31;
/// BEQ indicator（类别 4）
pub const IS_BEQ: usize = 32;
/// BNE indicator（类别 5）
pub const IS_BNE: usize = 33;
/// BLT indicator（类别 6）
pub const IS_BLT: usize = 34;
/// BGE indicator（类别 7）
pub const IS_BGE: usize = 35;
/// BLTU indicator（类别 8）
pub const IS_BLTU: usize = 36;
/// BGEU indicator（类别 9）
pub const IS_BGEU: usize = 37;
/// LB/LH/LW/LBU/LHU 共用 indicator（类别 10）
pub const IS_LOAD: usize = 38;
/// SB/SH/SW 共用 indicator（类别 11）
pub const IS_STORE: usize = 39;
/// ADDI indicator（类别 12）
pub const IS_ADDI: usize = 40;
/// SLTI indicator（类别 13）
pub const IS_SLTI: usize = 41;
/// SLTIU indicator（类别 14）
pub const IS_SLTIU: usize = 42;
/// XORI indicator（类别 15）
pub const IS_XORI: usize = 43;
/// ORI indicator（类别 16）
pub const IS_ORI: usize = 44;
/// ANDI indicator（类别 17）
pub const IS_ANDI: usize = 45;
/// SLLI indicator（类别 18）
pub const IS_SLLI: usize = 46;
/// SRLI indicator（类别 19）
pub const IS_SRLI: usize = 47;
/// SRAI indicator（类别 20）
pub const IS_SRAI: usize = 48;
/// ADD indicator（类别 21）
pub const IS_ADD: usize = 49;
/// SUB indicator（类别 22）
pub const IS_SUB: usize = 50;
/// SLL indicator（类别 23）
pub const IS_SLL: usize = 51;
/// SLT indicator（类别 24）
pub const IS_SLT: usize = 52;
/// SLTU indicator（类别 25）
pub const IS_SLTU: usize = 53;
/// XOR indicator（类别 26）
pub const IS_XOR: usize = 54;
/// SRL indicator（类别 27）
pub const IS_SRL: usize = 55;
/// SRA indicator（类别 28）
pub const IS_SRA: usize = 56;
/// OR indicator（类别 29）
pub const IS_OR: usize = 57;
/// AND indicator（类别 30）
pub const IS_AND: usize = 58;
/// FENCE indicator（类别 31）
pub const IS_FENCE: usize = 59;
/// ECALL indicator（类别 32）
pub const IS_ECALL: usize = 60;
/// EBREAK indicator（类别 33）
pub const IS_EBREAK: usize = 61;
/// padding 行 indicator（类别 34）
pub const IS_PADDING: usize = 62;

/// indicator 列数量（35 个指令类别）
pub const NUM_INSTRUCTION_CATEGORIES: usize = 35;

// ----- 辅助变量（4×8-bit limb each，4 个 helper）-----
/// col 63-66：辅助变量 1（4×8-bit limb）
pub const COL_HELPER1_BASE: usize = 63;
/// col 67-70：辅助变量 2（4×8-bit limb）
pub const COL_HELPER2_BASE: usize = 67;
/// col 71-74：辅助变量 3（4×8-bit limb）
pub const COL_HELPER3_BASE: usize = 71;
/// col 75-78：辅助变量 4（4×8-bit limb，Load/Store mem_value）
pub const COL_HELPER4_BASE: usize = 75;

// ----- 分支辅助 -----
/// col 79：分支跳转标记（0/1）
pub const COL_TAKEN: usize = 79;

// ----- Phase 3：Load/Store 内存地址（4×8-bit limb）-----
/// col 80-83：Load/Store 指令的内存地址（4×8-bit limb，非 Load/Store 时为 0）
pub const COL_MEM_ADDR_BASE: usize = 80;

// ----- Phase 4：ECALL（仅保留 SyscallId 1 列）-----
/// col 84：SyscallId（1 列 M31，直接表示 syscall_id 0-127）。
///
/// ECALL 行填 syscall_id，非 ECALL 行填 0。
/// v3 移除了 v2 的 24 列 Args/Outputs（texas_poker 不使用）。
pub const COL_SYSCALL_ID: usize = 84;

// ----- Phase 4：PC carry（2 列）-----
/// col 85-86：PC 进位标志（16-bit 边界，仅 IsNonFlow=1 或 Branch not-taken 时使用）。
pub const COL_PC_CARRY_FLAG_BASE: usize = 85;

/// v3 列布局总列数（87 列）。
///
/// 87 列 = PC(12) + Carry/Borrow(4) + ValueAEff/B/C(12) + Indicator(35)
///       + Helper(16) + Taken(1) + MemAddr(4) + SyscallId(1) + PcCarry(2)
pub const NUM_COLUMNS: usize = 87;

/// Phase 4 ECALL dispatch 列数量（v3 仅 1 列 SyscallId）。
pub const ECALL_DISPATCH_NUM_COLUMNS: usize = 1;

/// 将指令类别 ID（0-34）映射为 indicator 列索引。
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
            87,
            "v3 列布局应为 87 列（移除 41 列死列和 ECALL Args/Outputs）"
        );
    }

    #[test]
    fn test_word_limb_count() {
        assert_eq!(WORD_LIMB_COUNT, 4, "4×8-bit limb 方案，WORD_LIMB_COUNT=4");
        assert_eq!(WORD_SIZE, 4);
    }

    #[test]
    fn test_column_ranges_no_overlap() {
        let ranges: [(usize, usize); 11] = [
            (COL_PC_BASE, 4),                     // 0-3
            (COL_PC_NEXT_BASE, 4),                // 4-7
            (COL_PC_NEXT_AUX_BASE, 4),            // 8-11
            (COL_CARRY_FLAG_BASE, 2),             // 12-13
            (COL_BORROW_FLAG_BASE, 2),            // 14-15
            (COL_VALUE_A_EFF_BASE, 4),            // 16-19
            (COL_VALUE_B_BASE, 4),                // 20-23
            (COL_VALUE_C_BASE, 4),                // 24-27
            (COL_HELPER1_BASE, 4),                // 63-66
            (COL_HELPER2_BASE, 4),                // 67-70
            (COL_HELPER3_BASE, 4),                // 71-74
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
            IS_FENCE, IS_ECALL, IS_EBREAK, IS_PADDING,
        ];
        assert_eq!(indicators.len(), NUM_INSTRUCTION_CATEGORIES);
        for &col in &indicators {
            assert!(
                col >= COL_IS_BASE && col < COL_IS_BASE + NUM_INSTRUCTION_CATEGORIES,
                "IS_* 列 {} 不在 indicator 范围 [28, 62]",
                col
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
            IS_FENCE, IS_ECALL, IS_EBREAK, IS_PADDING,
        ];
        let unique: HashSet<_> = indicators.iter().collect();
        assert_eq!(unique.len(), indicators.len(), "IS_* 列有重复");
    }

    #[test]
    fn test_category_to_indicator_col() {
        assert_eq!(category_to_indicator_col(0), IS_LUI);
        assert_eq!(category_to_indicator_col(21), IS_ADD);
        assert_eq!(category_to_indicator_col(34), IS_PADDING);
    }

    #[test]
    #[should_panic(expected = "category 35 >= 35")]
    fn test_category_to_indicator_col_out_of_range() {
        let _ = category_to_indicator_col(35);
    }

    #[test]
    fn test_helper_columns() {
        assert_eq!(COL_HELPER1_BASE, 63);
        assert_eq!(COL_HELPER2_BASE, 67);
        assert_eq!(COL_HELPER3_BASE, 71);
        assert_eq!(COL_HELPER4_BASE, 75);
        assert_eq!(COL_HELPER4_BASE + WORD_LIMB_COUNT, 79);
    }

    #[test]
    fn test_auxiliary_columns() {
        assert_eq!(COL_TAKEN, 79);
        assert_eq!(COL_MEM_ADDR_BASE, 80);
        assert_eq!(COL_SYSCALL_ID, 84);
        assert_eq!(ECALL_DISPATCH_NUM_COLUMNS, 1);
        assert_eq!(COL_PC_CARRY_FLAG_BASE, 85);
        assert_eq!(COL_PC_CARRY_FLAG_BASE + 2, NUM_COLUMNS);
    }
}
