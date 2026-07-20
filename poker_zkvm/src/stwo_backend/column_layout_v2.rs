//! # Stwo Trace 列布局 v2 — 4×8-bit Limb 方案（Phase 1）
//!
//! 严格遵循 `.trae/documents/hypernova_to_stwo_migration_plan_v2.md`（v2 FROZEN）+
//! `.trae/documents/stwo_phase1_native_trace_design.md`：
//! - **设计参考**：Nexus zkVM 0.3.6 `prover/src/column.rs`
//! - **核心变更**：32-bit 值用 4×8-bit limb（替代 v1 的 2×30-bit limb）
//! - **优势**：每个 limb ∈ [0, 255] ⊂ [0, M31_MAX]，无域转换，无 soundness 隐患
//!
//! ## 列布局（Phase 4 Tier 1，126 列）
//!
//! | 范围 | 列名 | 说明 |
//! |------|------|------|
//! | 0-3 | Pc (4×8-bit limb) | 当前 PC |
//! | 4-7 | PcNext (4×8-bit limb) | 下一 PC |
//! | 8-11 | PcNextAux (4×8-bit limb) | PC 辅助（JALR 等） |
//! | 12 | OpA | 目标寄存器索引 |
//! | 13 | OpB | 源寄存器 1 索引 |
//! | 14 | OpC | 源寄存器 2 索引/立即数 |
//! | 15-16 | CarryFlag (2 列) | 16-bit 边界进位 |
//! | 17-18 | BorrowFlag (2 列) | 16-bit 边界借位 |
//! | 19 | ImmC | 立即数标志 |
//! | 20-23 | InstrVal (4×8-bit limb) | 指令编码 |
//! | 24-27 | ValueA (4×8-bit limb) | 操作数 A 值 |
//! | 28-31 | ValueAEffective (4×8-bit limb) | 操作数 A 有效值 |
//! | 32-35 | ValueB (4×8-bit limb) | 操作数 B 值 |
//! | 36-39 | ValueC (4×8-bit limb) | 操作数 C 值 |
//! | 40-74 | Is* indicators (35 列) | 指令 one-hot 标记 |
//! | 75-78 | Helper1 (4×8-bit limb) | 辅助变量 1 |
//! | 79-82 | Helper2 (4×8-bit limb) | 辅助变量 2 |
//! | 83-86 | Helper3 (4×8-bit limb) | 辅助变量 3 |
//! | 87-90 | Helper4 (4×8-bit limb) | 辅助变量 4 |
//! | 91 | Taken | 分支跳转标记 |
//! | 92 | BranchCond | 分支条件中间值 |
//! | 93 | Shamt | 移位量 |
//! | 94 | SgnA | 操作数 A 符号位 |
//! | 95 | SgnB | 操作数 B 符号位 |
//! | 96 | SgnC | 操作数 C 符号位 |
//! | 97-100 | MemAddr (4×8-bit limb) | Phase 3 新增：Load/Store 地址 |
//! | 101 | SyscallId | Phase 4 Tier 1 新增：ECALL syscall ID（1 列 M31） |
//! | 102-125 | Syscall Args/Outputs (24 列) | Phase 4 Tier 1 新增：6×4-limb |
//!
//! ## 与 v1 的差异
//!
//! - **v1**：2×30-bit limb（low 30 bit + high 2 bit），需要 `fr_to_m31_single` 域转换
//! - **v2**：4×8-bit limb，原生 M31，无域转换，参考 Nexus zkVM 0.3.6

/// 32-bit 值的 limb 数量（4×8-bit）。
///
/// 参考 Nexus zkVM 0.3.6 `WORD_SIZE = 4`。
pub const WORD_LIMB_COUNT: usize = 4;

/// 字大小（字节），与 `WORD_LIMB_COUNT` 一致。
pub const WORD_SIZE: usize = 4;

// ===========================================================================
// 主 trace 列索引常量（97 列）
// ===========================================================================

// ----- PC 相关（4×8-bit limb each）-----
/// col 0-3：当前 PC（4×8-bit limb）
pub const COL_PC_BASE: usize = 0;
/// col 4-7：下一 PC（4×8-bit limb）
pub const COL_PC_NEXT_BASE: usize = 4;
/// col 8-11：PC 辅助值（4×8-bit limb，JALR 等用）
pub const COL_PC_NEXT_AUX_BASE: usize = 8;

// ----- 操作数索引（1 列 each）-----
/// col 12：目标寄存器索引（OpA）
pub const COL_OP_A: usize = 12;
/// col 13：源寄存器 1 索引（OpB）
pub const COL_OP_B: usize = 13;
/// col 14：源寄存器 2 索引或立即数（OpC）
pub const COL_OP_C: usize = 14;

// ----- 进位/借位标志（2 列 each，16-bit 边界）-----
/// col 15-16：进位标志（CarryFlag，16-bit 边界）
pub const COL_CARRY_FLAG_BASE: usize = 15;
/// col 17-18：借位标志（BorrowFlag，16-bit 边界）
pub const COL_BORROW_FLAG_BASE: usize = 17;

// ----- 立即数标志 -----
/// col 19：OpC 是否为立即数
pub const COL_IMM_C: usize = 19;

// ----- 指令值（4×8-bit limb）-----
/// col 20-23：指令编码（4×8-bit limb）
pub const COL_INSTR_VAL_BASE: usize = 20;

// ----- 操作数值（4×8-bit limb each）-----
/// col 24-27：操作数 A 值（4×8-bit limb）
pub const COL_VALUE_A_BASE: usize = 24;
/// col 28-31：操作数 A 有效值（4×8-bit limb，rd=0 时为 0）
pub const COL_VALUE_A_EFF_BASE: usize = 28;
/// col 32-35：操作数 B 值（4×8-bit limb）
pub const COL_VALUE_B_BASE: usize = 32;
/// col 36-39：操作数 C 值（4×8-bit limb）
pub const COL_VALUE_C_BASE: usize = 36;

// ----- 指令 indicator（35 列，one-hot）-----
/// indicator 列起始索引（col 40-74，共 35 列）
pub const COL_IS_BASE: usize = 40;

// 指令类别 indicator 偏移（与 `crate::constraints::instruction_category` 对齐）
// 注意：v2 不再依赖 constraints 模块，但保留相同类别编号以兼容语义
/// LUI indicator（类别 0）
pub const IS_LUI: usize = 40;
/// AUIPC indicator（类别 1）
pub const IS_AUIPC: usize = 41;
/// JAL indicator（类别 2）
pub const IS_JAL: usize = 42;
/// JALR indicator（类别 3）
pub const IS_JALR: usize = 43;
/// BEQ indicator（类别 4）
pub const IS_BEQ: usize = 44;
/// BNE indicator（类别 5）
pub const IS_BNE: usize = 45;
/// BLT indicator（类别 6）
pub const IS_BLT: usize = 46;
/// BGE indicator（类别 7）
pub const IS_BGE: usize = 47;
/// BLTU indicator（类别 8）
pub const IS_BLTU: usize = 48;
/// BGEU indicator（类别 9）
pub const IS_BGEU: usize = 49;
/// LB/LH/LW/LBU/LHU 共用 indicator（类别 10）
pub const IS_LOAD: usize = 50;
/// SB/SH/SW 共用 indicator（类别 11）
pub const IS_STORE: usize = 51;
/// ADDI indicator（类别 12）
pub const IS_ADDI: usize = 52;
/// SLTI indicator（类别 13）
pub const IS_SLTI: usize = 53;
/// SLTIU indicator（类别 14）
pub const IS_SLTIU: usize = 54;
/// XORI indicator（类别 15）
pub const IS_XORI: usize = 55;
/// ORI indicator（类别 16）
pub const IS_ORI: usize = 56;
/// ANDI indicator（类别 17）
pub const IS_ANDI: usize = 57;
/// SLLI indicator（类别 18）
pub const IS_SLLI: usize = 58;
/// SRLI indicator（类别 19）
pub const IS_SRLI: usize = 59;
/// SRAI indicator（类别 20）
pub const IS_SRAI: usize = 60;
/// ADD indicator（类别 21）
pub const IS_ADD: usize = 61;
/// SUB indicator（类别 22）
pub const IS_SUB: usize = 62;
/// SLL indicator（类别 23）
pub const IS_SLL: usize = 63;
/// SLT indicator（类别 24）
pub const IS_SLT: usize = 64;
/// SLTU indicator（类别 25）
pub const IS_SLTU: usize = 65;
/// XOR indicator（类别 26）
pub const IS_XOR: usize = 66;
/// SRL indicator（类别 27）
pub const IS_SRL: usize = 67;
/// SRA indicator（类别 28）
pub const IS_SRA: usize = 68;
/// OR indicator（类别 29）
pub const IS_OR: usize = 69;
/// AND indicator（类别 30）
pub const IS_AND: usize = 70;
/// FENCE indicator（类别 31）
pub const IS_FENCE: usize = 71;
/// ECALL indicator（类别 32）
pub const IS_ECALL: usize = 72;
/// EBREAK indicator（类别 33）
pub const IS_EBREAK: usize = 73;
/// padding 行 indicator（类别 34）
pub const IS_PADDING: usize = 74;

/// indicator 列数量（35 个指令类别）
pub const NUM_INSTRUCTION_CATEGORIES: usize = 35;

// ----- 辅助变量（4×8-bit limb each，4 个 helper）-----
/// col 75-78：辅助变量 1（4×8-bit limb）
pub const COL_HELPER1_BASE: usize = 75;
/// col 79-82：辅助变量 2（4×8-bit limb）
pub const COL_HELPER2_BASE: usize = 79;
/// col 83-86：辅助变量 3（4×8-bit limb）
pub const COL_HELPER3_BASE: usize = 83;
/// col 87-90：辅助变量 4（4×8-bit limb）
pub const COL_HELPER4_BASE: usize = 87;

// ----- 分支/移位辅助 -----
/// col 91：分支跳转标记（0/1）
pub const COL_TAKEN: usize = 91;
/// col 92：分支条件中间值
pub const COL_BRANCH_COND: usize = 92;
/// col 93：移位量（0-31）
pub const COL_SHAMT: usize = 93;

// ----- 符号位 -----
/// col 94：操作数 A 符号位
pub const COL_SGN_A: usize = 94;
/// col 95：操作数 B 符号位
pub const COL_SGN_B: usize = 95;
/// col 96：操作数 C 符号位
pub const COL_SGN_C: usize = 96;

// ----- Phase 3 新增：Load/Store 内存地址（4×8-bit limb）-----
/// col 97-100：Load/Store 指令的内存地址（4×8-bit limb，非 Load/Store 时为 0）
///
/// Phase 3 新增，用于 CPU AIR 发送 MemoryLookup logup claim。
/// 地址 = rs1 + imm，由 trace_native.rs 预计算填充。
pub const COL_MEM_ADDR_BASE: usize = 97;

// ===========================================================================
// Phase 4 Tier 1 新增：ECALL dispatch 列（25 列，col 101-125）
// ===========================================================================
//
// 用于关闭 CPU AIR 的 ECALL soundness 缺口（CRITICAL）：
// - 非 ECALL 行所有 ECALL 列必须为 0（zero gating 约束）
// - ECALL 行发送 logup claim（Tier 2 启用，与 Precompile AIR yield 配对）
//
// 列布局（参考 stwo_phase4_precompile_air_design.md §3.1）：
// | 范围    | 名称             | 说明                                  |
// |---------|------------------|---------------------------------------|
// | 101     | SyscallId        | 1 列 M31，直接表示 syscall_id (0-127) |
// | 102-105 | SyscallArg0      | 4×8-bit limb（如 input_ptr）          |
// | 106-109 | SyscallArg1      | 4×8-bit limb（如 input_len）          |
// | 110-113 | SyscallArg2      | 4×8-bit limb（如 output_ptr）         |
// | 114-117 | SyscallArg3      | 4×8-bit limb（reserved）              |
// | 118-121 | SyscallOutput0   | 4×8-bit limb（output[0]）             |
// | 122-125 | SyscallOutput1   | 4×8-bit limb（output[1]）             |

/// col 101：SyscallId（1 列 M31，直接表示 syscall_id 0-127）。
///
/// Phase 4 Tier 1 新增。ECALL 行填 syscall_id（如 0x01=PoseidonHash），
/// 非 ECALL 行填 0。SyscallId 用 1 列 M31 表示（而非 4×8-bit limb），
/// 因为 syscall_id < 128 < M31_MAX，无需 limb 分解。
pub const COL_SYSCALL_ID: usize = 101;

/// col 102-105：SyscallArg0（4×8-bit limb）。
pub const COL_SYSCALL_ARG0_BASE: usize = 102;

/// col 106-109：SyscallArg1（4×8-bit limb）。
pub const COL_SYSCALL_ARG1_BASE: usize = 106;

/// col 110-113：SyscallArg2（4×8-bit limb）。
pub const COL_SYSCALL_ARG2_BASE: usize = 110;

/// col 114-117：SyscallArg3（4×8-bit limb）。
pub const COL_SYSCALL_ARG3_BASE: usize = 114;

/// col 118-121：SyscallOutput0（4×8-bit limb）。
pub const COL_SYSCALL_OUTPUT0_BASE: usize = 118;

/// col 122-125：SyscallOutput1（4×8-bit limb）。
pub const COL_SYSCALL_OUTPUT1_BASE: usize = 122;

/// Phase 4 Tier 1 ECALL dispatch 列数量。
pub const ECALL_DISPATCH_NUM_COLUMNS: usize = 25;

/// Phase 4 v2 列布局总列数。
///
/// 126 列 = Phase 3 的 101 列 + Phase 4 Tier 1 的 25 列（ECALL dispatch）
pub const NUM_COLUMNS: usize = 126;

/// 将指令类别 ID（0-34）映射为 indicator 列索引。
///
/// # 参数
/// - `category` — 指令类别 ID ∈ [0, 34]
///
/// # 返回
/// indicator 列索引 ∈ [40, 74]
///
/// # Panics
/// 若 `category >= 35`，panic
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
            126,
            "Phase 4 Tier 1 v2 列布局应为 126 列（97 + MemAddr 4 + ECALL dispatch 25）"
        );
    }

    #[test]
    fn test_word_limb_count() {
        assert_eq!(WORD_LIMB_COUNT, 4, "4×8-bit limb 方案，WORD_LIMB_COUNT=4");
        assert_eq!(WORD_SIZE, 4);
    }

    #[test]
    fn test_column_ranges_no_overlap() {
        // 验证各列范围互不重叠
        let ranges: [(usize, usize); 13] = [
            (COL_PC_BASE, 4),                     // 0-3
            (COL_PC_NEXT_BASE, 4),                // 4-7
            (COL_PC_NEXT_AUX_BASE, 4),            // 8-11
            (COL_OP_A, 1),                        // 12
            (COL_OP_B, 1),                        // 13
            (COL_OP_C, 1),                        // 14
            (COL_CARRY_FLAG_BASE, 2),             // 15-16
            (COL_BORROW_FLAG_BASE, 2),            // 17-18
            (COL_IMM_C, 1),                       // 19
            (COL_INSTR_VAL_BASE, 4),              // 20-23
            (COL_VALUE_A_BASE, 4),                // 24-27
            (COL_VALUE_A_EFF_BASE, 4),            // 28-31
            (COL_VALUE_B_BASE, 4),                // 32-35
        ];
        let mut all_cols = HashSet::new();
        for (base, count) in &ranges {
            for offset in 0..*count {
                let col = base + offset;
                assert!(
                    all_cols.insert(col),
                    "列 {} 重复分配",
                    col
                );
            }
        }
    }

    #[test]
    fn test_indicator_columns_range() {
        // 验证所有 IS_* 常量在 [40, 74] 范围内
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
                "IS_* 列 {} 不在 indicator 范围 [40, 74]",
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
        // 验证 helper 列在 [75, 90] 范围内
        assert_eq!(COL_HELPER1_BASE, 75);
        assert_eq!(COL_HELPER2_BASE, 79);
        assert_eq!(COL_HELPER3_BASE, 83);
        assert_eq!(COL_HELPER4_BASE, 87);
        // 每个 helper 4 列，总共 16 列（75-90）
        assert_eq!(COL_HELPER4_BASE + WORD_LIMB_COUNT, 91);
    }

    #[test]
    fn test_auxiliary_columns() {
        // 验证辅助列（91-96）在末尾
        assert_eq!(COL_TAKEN, 91);
        assert_eq!(COL_BRANCH_COND, 92);
        assert_eq!(COL_SHAMT, 93);
        assert_eq!(COL_SGN_A, 94);
        assert_eq!(COL_SGN_B, 95);
        assert_eq!(COL_SGN_C, 96);
        // Phase 3 新增 MemAddr 列（97-100）
        assert_eq!(COL_MEM_ADDR_BASE, 97);
        // Phase 4 Tier 1 新增 ECALL dispatch 列（101-125）
        assert_eq!(COL_SYSCALL_ID, 101);
        assert_eq!(COL_SYSCALL_ARG0_BASE, 102);
        assert_eq!(COL_SYSCALL_ARG1_BASE, 106);
        assert_eq!(COL_SYSCALL_ARG2_BASE, 110);
        assert_eq!(COL_SYSCALL_ARG3_BASE, 114);
        assert_eq!(COL_SYSCALL_OUTPUT0_BASE, 118);
        assert_eq!(COL_SYSCALL_OUTPUT1_BASE, 122);
        assert_eq!(ECALL_DISPATCH_NUM_COLUMNS, 25);
        // 最后一列 + 1 = NUM_COLUMNS
        assert_eq!(COL_SYSCALL_OUTPUT1_BASE + WORD_LIMB_COUNT, NUM_COLUMNS);
    }

    #[test]
    fn test_ecall_dispatch_columns_no_overlap() {
        // 验证 Phase 4 Tier 1 ECALL dispatch 列范围 [101, 126) 互不重叠且不与前面冲突
        let ecall_ranges: [(usize, usize); 7] = [
            (COL_SYSCALL_ID, 1),                // 101
            (COL_SYSCALL_ARG0_BASE, 4),         // 102-105
            (COL_SYSCALL_ARG1_BASE, 4),         // 106-109
            (COL_SYSCALL_ARG2_BASE, 4),         // 110-113
            (COL_SYSCALL_ARG3_BASE, 4),         // 114-117
            (COL_SYSCALL_OUTPUT0_BASE, 4),      // 118-121
            (COL_SYSCALL_OUTPUT1_BASE, 4),      // 122-125
        ];
        let mut ecall_cols = HashSet::new();
        for (base, count) in &ecall_ranges {
            for offset in 0..*count {
                let col = base + offset;
                assert!(col >= 101 && col < 126, "ECALL col {} 不在 [101, 126) 范围", col);
                assert!(ecall_cols.insert(col), "ECALL 列 {} 重复分配", col);
            }
        }
        assert_eq!(ecall_cols.len(), ECALL_DISPATCH_NUM_COLUMNS);
        // 验证与 Phase 3 MemAddr 列（97-100）不重叠
        for col in 97..101 {
            assert!(!ecall_cols.contains(&col), "ECALL 列与 MemAddr 列 {} 重叠", col);
        }
    }
}
