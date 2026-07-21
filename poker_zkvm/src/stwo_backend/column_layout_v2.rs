//! # Stwo Trace 列布局 v3.3 — P1.3 优化（73 列）
//!
//! 在 v3.2（77 列）基础上移除 PcNextAux 列：
//! - PcNextAux 仅用于 JALR 约束，与 HelperA 使用互斥
//! - JALR 行 HelperA 复用为 PcNextAux 值
//!
//! ## 列布局（73 列）
//!
//! | 范围 | 列名 | 说明 |
//! |------|------|------|
//! | 0-3 | Pc (4×8-bit limb) | 当前 PC |
//! | 4-7 | PcNext (4×8-bit limb) | 下一 PC |
//! | 8-9 | ArithFlag (2 列) | 算术标志（ADD/ADDI=carry, SUB=borrow） |
//! | 10-13 | ValueAEffective (4×8-bit limb) | 操作数 A 有效值（rd=0 时为 0） |
//! | 14-17 | ValueB (4×8-bit limb) | 操作数 B 值 |
//! | 18-21 | ValueC (4×8-bit limb) | 操作数 C 值 |
//! | 22-56 | Is* indicators (35 列) | 指令 one-hot 标记 |
//! | 57-60 | HelperA (4×8-bit limb) | 复用：LUI imm / JAL/Branch/AUIPC Pc+imm / Load/Store MemAddr / JALR PcNextAux |
//! | 61-64 | HelperB (4×8-bit limb) | 复用：Load mem_value / Store rs2_value |
//! | 65 | Taken | 分支跳转标记 |
//! | 66-69 | MemAddr (4×8-bit limb) | Load/Store 地址（logup claim 用） |
//! | 70 | SyscallId | ECALL syscall ID（1 列 M31） |
//! | 71-72 | PcCarryFlag (2 列) | PC 进位标志 |

/// 32-bit 值的 limb 数量（4×8-bit）。
pub const WORD_LIMB_COUNT: usize = 4;

/// 字大小（字节），与 `WORD_LIMB_COUNT` 一致。
pub const WORD_SIZE: usize = 4;

// ===========================================================================
// 主 trace 列索引常量（73 列）
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

// ----- 指令 indicator（35 列，one-hot）-----
/// indicator 列起始索引（col 22-56，共 35 列）
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
/// padding 行 indicator（类别 34）
pub const IS_PADDING: usize = 56;

/// indicator 列数量（35 个指令类别）
pub const NUM_INSTRUCTION_CATEGORIES: usize = 35;

// ----- 辅助变量（4×8-bit limb each，2 个 helper）-----
/// col 57-60：辅助变量 A（4×8-bit limb）
///
/// 复用模式（LUI/JAL/Branch/AUIPC/Load/Store/JALR 互斥）：
/// - LUI 行：imm 值（用于 rd_eff = imm 约束）
/// - JAL/Branch taken/AUIPC 行：Pc + imm 预计算值
/// - Load/Store 行：MemAddr 值（rs1 + imm，与 MemAddr 列一致）
/// - JALR 行：PcNextAux 值（JALR 目标地址 = (rs1 + imm) & !1）
/// - 其他行：0（不被约束）
pub const COL_HELPER_A_BASE: usize = 57;
/// col 61-64：辅助变量 B（4×8-bit limb）
///
/// 复用模式（Load/Store 互斥）：
/// - Load 行：mem_value（加载值，用于 rd_eff = mem_value 约束）
/// - Store 行：rs2_value（存储值，用于 rs2 = mem_value 约束）
/// - 其他行：0（不被约束）
pub const COL_HELPER_B_BASE: usize = 61;

// ----- 分支辅助 -----
/// col 65：分支跳转标记（0/1）
pub const COL_TAKEN: usize = 65;

// ----- Phase 3：Load/Store 内存地址（4×8-bit limb）-----
/// col 66-69：Load/Store 指令的内存地址（4×8-bit limb，非 Load/Store 时为 0）
///
/// 注：HelperA 在 Load/Store 行也存 MemAddr 值，但 MemAddr 列单独保留用于 logup claim
/// 和调试输出。
pub const COL_MEM_ADDR_BASE: usize = 66;

// ----- Phase 4：ECALL（仅保留 SyscallId 1 列）-----
/// col 70：SyscallId（1 列 M31，直接表示 syscall_id 0-127）。
///
/// ECALL 行填 syscall_id，非 ECALL 行填 0。
/// v3 移除了 v2 的 24 列 Args/Outputs（texas_poker 不使用）。
pub const COL_SYSCALL_ID: usize = 70;

// ----- Phase 4：PC carry（2 列）-----
/// col 71-72：PC 进位标志（16-bit 边界，仅 IsNonFlow=1 或 Branch not-taken 时使用）。
pub const COL_PC_CARRY_FLAG_BASE: usize = 71;

/// v3.3 列布局总列数（73 列）。
///
/// 73 列 = PC(8) + ArithFlag(2) + ValueAEff/B/C(12) + Indicator(35)
///       + HelperA(4) + HelperB(4) + Taken(1) + MemAddr(4) + SyscallId(1) + PcCarry(2)
pub const NUM_COLUMNS: usize = 73;

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
            73,
            "v3.3 列布局应为 73 列（v3.2 77 列移除 PcNextAux 节省 4 列）"
        );
    }

    #[test]
    fn test_word_limb_count() {
        assert_eq!(WORD_LIMB_COUNT, 4, "4×8-bit limb 方案，WORD_LIMB_COUNT=4");
        assert_eq!(WORD_SIZE, 4);
    }

    #[test]
    fn test_column_ranges_no_overlap() {
        let ranges: [(usize, usize); 8] = [
            (COL_PC_BASE, 4),                     // 0-3
            (COL_PC_NEXT_BASE, 4),                // 4-7
            (COL_CARRY_FLAG_BASE, 2),             // 8-9（合并 carry/borrow）
            (COL_VALUE_A_EFF_BASE, 4),            // 10-13
            (COL_VALUE_B_BASE, 4),                // 14-17
            (COL_VALUE_C_BASE, 4),                // 18-21
            (COL_HELPER_A_BASE, 4),               // 57-60
            (COL_HELPER_B_BASE, 4),               // 61-64
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
                "IS_* 列 {} 不在 indicator 范围 [22, 56]",
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
        assert_eq!(COL_HELPER_A_BASE, 57);
        assert_eq!(COL_HELPER_B_BASE, 61);
        assert_eq!(COL_HELPER_B_BASE + WORD_LIMB_COUNT, 65);
    }

    #[test]
    fn test_auxiliary_columns() {
        assert_eq!(COL_TAKEN, 65);
        assert_eq!(COL_MEM_ADDR_BASE, 66);
        assert_eq!(COL_SYSCALL_ID, 70);
        assert_eq!(ECALL_DISPATCH_NUM_COLUMNS, 1);
        assert_eq!(COL_PC_CARRY_FLAG_BASE, 71);
        assert_eq!(COL_PC_CARRY_FLAG_BASE + 2, NUM_COLUMNS);
    }
}
