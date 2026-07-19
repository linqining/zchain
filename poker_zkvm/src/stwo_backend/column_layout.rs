//! # Stwo Trace 列布局 — Phase 2.2 精简方案 + Phase 2.3.4-b Limb Decomposition
//!
//! 严格遵循 `.trae/documents/stwo_phase2_2_trace_column_reduction_plan.md`（v1）+ `.trae/documents/stwo_phase2_3_4b_limb_decomposition_plan.md`：
//! - **Phase 2.2 目标**：将 Hypernova 47 列 `STEP_VARS` 精简为 Stwo 13 列布局
//! - **Phase 2.3.4-b 扩展**：新增 5 个 limb 列（rs1_high/rs2_high/rd_high/imm_high/carry_low），
//!   列数 13→18，支持 ADDI/ADD/SUB 算术约束的 limb decomposition
//!
//! ## 列布局（Phase 2.3.4-b，18 列）
//!
//! | col | 列名       | 来源（Hypernova 47 列）           | 用途                          |
//! |-----|-----------|-----------------------------------|-------------------------------|
//! | 0   | `idx`     | `idx`                             | step_index（Group A 用）      |
//! | 1   | `pc`      | `pc`                              | 当前 PC                       |
//! | 2   | `next_pc` | `next_pc`                         | 下一 PC（Group B 用）         |
//! | 3   | `rs1_val` | `rs1_val`（low 30 bit）           | 源寄存器 1 值（low limb）     |
//! | 4   | `rs2_val` | `rs2_val`（low 30 bit）           | 源寄存器 2 值（low limb）     |
//! | 5   | `rd_val`  | `rd_val`（low 30 bit）            | 目标寄存器值（low limb）      |
//! | 6   | `imm`     | `imm`（low 30 bit）               | 立即数（low limb）            |
//! | 7   | `carry`   | `carry`（= carry_high，u32 overflow） | 加法进位（Group F, Group E SLT） |
//! | 8   | `taken`   | `taken`                           | 分支跳转标记                  |
//! | 9   | `shamt`   | `shamt`                           | 移位量                        |
//! | 10  | `branch_cond` | `branch_cond`                 | 分支条件中间值                |
//! | 11  | `aux`     | `aux`                             | 辅助值                        |
//! | 12  | `opcode`  | `argmax(sel_0..sel_34)`           | 指令类别（替代 35 列 selector）|
//! | 13  | `rs1_high`| `rs1_val >> 30`（高 2 bit）       | rs1_val high limb（Phase 2.3.4-b） |
//! | 14  | `rs2_high`| `rs2_val >> 30`（高 2 bit）       | rs2_val high limb（Phase 2.3.4-b） |
//! | 15  | `rd_high` | `rd_val >> 30`（高 2 bit）        | rd_val high limb（Phase 2.3.4-b）  |
//! | 16  | `imm_high`| `imm >> 30`（高 2 bit）           | imm high limb（Phase 2.3.4-b）     |
//! | 17  | `carry_low`| 新增 witness 列                  | low limb 进位位（Phase 2.3.4-b）   |
//!
//! ## 约束映射
//!
//! | Group | Hypernova 约束              | Stwo Phase 2.3.4-b 实现                       |
//! |-------|----------------------------|-------------------------------------------|
//! | A     | `idx_{i+1} - idx_i - 1 = 0` | 保持不变（Phase 2.1d 已实现）             |
//! | B     | `next_pc_i - pc_{i+1} = 0`  | Phase 2.3.1 已实现                        |
//! | C     | `Σ_j sel_j - 1 = 0`         | LogUp range check（Phase 2.3.2 已实现）   |
//! | D     | `sel_j² - sel_j = 0`        | 消除，opcode 是单值                        |
//! | E     | `sel_j * constraint_j = 0`  | `I_j(opcode) * constraint_j`（Phase 2.3.3 + 2.3.4-b） |
//! | F     | `carry² - carry = 0`        | `carry * (carry - 1)` + `carry_low * (carry_low - 1)`（Phase 2.3.4-a/b） |
//!
//! ## 当前状态（Phase 2.3.4-b）
//!
//! 列数从 13 扩展为 18，新增 5 个 limb 列支持 ADDI/ADD/SUB 算术约束。

use crate::ccs::Fr;
use crate::constraints::{NUM_CATEGORIES, STEP_VARS};
use crate::field::ZkvmField;

use super::field::{M31, M31_LIMB_MASK};

/// Stwo trace 列数（Phase 2.3.4-b limb decomposition 布局）。
///
/// - Phase 2.2：47（Hypernova `STEP_VARS`）→ 13（12 数据列 + 1 opcode 列），缩减比 3.6×
/// - Phase 2.3.4-b：13 → 18（新增 5 个 limb 列：rs1_high/rs2_high/rd_high/imm_high/carry_low）
pub const NUM_COLUMNS: usize = 18;

/// 数据列数（col 0-16），与 Hypernova `STEP_VARS` 前 12 列 1:1 映射 + 5 个 limb 列。
pub const NUM_DATA_COLUMNS: usize = 17;

// ===========================================================================
// 列索引常量
// ===========================================================================

/// col 0：step_index（Group A 约束用，保持 Phase 2.1d 修复逻辑不变）
pub const COL_IDX: usize = 0;
/// col 1：当前 PC
pub const COL_PC: usize = 1;
/// col 2：下一 PC（Group B 约束用）
pub const COL_NEXT_PC: usize = 2;
/// col 3：源寄存器 1 值（low 30 bit limb）
pub const COL_RS1_VAL: usize = 3;
/// col 4：源寄存器 2 值（low 30 bit limb）
pub const COL_RS2_VAL: usize = 4;
/// col 5：目标寄存器值（low 30 bit limb）
pub const COL_RD_VAL: usize = 5;
/// col 6：立即数（low 30 bit limb）
pub const COL_IMM: usize = 6;
/// col 7：加法进位（= carry_high，u32 overflow bit；Group F 约束用）
pub const COL_CARRY: usize = 7;
/// col 8：分支跳转标记（0/1）
pub const COL_TAKEN: usize = 8;
/// col 9：移位量（0-31）
pub const COL_SHAMT: usize = 9;
/// col 10：分支条件中间值
pub const COL_BRANCH_COND: usize = 10;
/// col 11：辅助值（多 limb 运算中间值）
pub const COL_AUX: usize = 11;
/// col 12：指令类别 opcode（0-34，替代 35 列 one-hot selector）
pub const COL_OPCODE: usize = 12;
/// col 13：rs1_val 高 2 bit limb（Phase 2.3.4-b 新增）
pub const COL_RS1_HIGH: usize = 13;
/// col 14：rs2_val 高 2 bit limb（Phase 2.3.4-b 新增）
pub const COL_RS2_HIGH: usize = 14;
/// col 15：rd_val 高 2 bit limb（Phase 2.3.4-b 新增）
pub const COL_RD_HIGH: usize = 15;
/// col 16：imm 高 2 bit limb（Phase 2.3.4-b 新增）
pub const COL_IMM_HIGH: usize = 16;
/// col 17：low limb 进位位（Phase 2.3.4-b 新增，ADDI/ADD/SUB 用）
pub const COL_CARRY_LOW: usize = 17;

/// Hypernova `STEP_VARS` 中数据列的起始偏移（与 `constraints/mod.rs::OFF_IDX` 一致）。
const HYPERNOVA_DATA_OFFSET: usize = 0;

/// Hypernova `STEP_VARS` 中 selector 列的起始偏移（与 `constraints/mod.rs::OFF_SEL_START` 一致）。
const HYPERNOVA_SEL_START: usize = 12;

// ===========================================================================
// 映射函数
// ===========================================================================

/// 将 Hypernova 47 列 `STEP_VARS` witness 映射为 Stwo 18 列 witness（Phase 2.3.4-b limb decomposition）。
///
/// # 映射规则
/// - **数据列（col 0-11）**：1:1 直接复制，BN254 Fr → M31（30-bit limb 掩码，low limb）
/// - **opcode 列（col 12）**：`argmax(sel_0..sel_34)`，即 `selector_to_opcode(sels)` 的结果
/// - **high limb 列（col 13-16）**：从 rs1_val/rs2_val/rd_val/imm 的高 2 bit 提取
/// - **carry_low 列（col 17）**：默认 0（prover 在 ADDI/ADD/SUB 行根据 low limb 加法结果设置）
///
/// # 参数
/// - `step_vars` — Hypernova `compile_step_witness` 返回的 47 个 BN254 Fr 值
///
/// # 返回
/// 18 个 M31 值的 `Vec`，按 [`NUM_COLUMNS`] 顺序排列
///
/// # Panics
/// - 若 `step_vars.len() != STEP_VARS`（47），debug 模式下 panic
/// - 若 selector 全为零（无 one-hot），opcode 默认为 0（LUI），不 panic
///
/// # 安全性
/// - 30-bit limb 掩码避免 M31 模数陷阱（P = 2^31 - 1，`M31::from(P)` 归约为 0）
/// - high limb 提取 `v >> 30` 确保 ∈ [0, 3] ⊂ [0, P-1]
/// - carry_low 默认 0，prover 负责在 ADDI/ADD/SUB 行设置正确值
pub fn map_step_vars_to_stwo(step_vars: &[Fr]) -> Vec<M31> {
    debug_assert_eq!(
        step_vars.len(),
        STEP_VARS,
        "map_step_vars_to_stwo: 期望 {} 个 Fr 值，实际 {}",
        STEP_VARS,
        step_vars.len()
    );

    let mut result = vec![M31::from(0u32); NUM_COLUMNS];

    // 数据列 1:1 复制（col 0-11，low 30-bit limb）
    // 注意：NUM_DATA_COLUMNS=17，但前 12 列是 Hypernova 数据列，后 5 列是 limb 列
    for i in 0..12 {
        result[i] = fr_to_m31_single(&step_vars[HYPERNOVA_DATA_OFFSET + i]);
    }

    // opcode 列：argmax(sel_0..sel_34)
    let sels = &step_vars[HYPERNOVA_SEL_START..HYPERNOVA_SEL_START + NUM_CATEGORIES];
    let opcode = selector_to_opcode(sels);
    result[COL_OPCODE] = M31::from(opcode as u32);

    // Phase 2.3.4-b：high limb 列（col 13-16）从 rs1_val/rs2_val/rd_val/imm 提取
    result[COL_RS1_HIGH] = fr_to_m31_high(&step_vars[HYPERNOVA_DATA_OFFSET + COL_RS1_VAL]);
    result[COL_RS2_HIGH] = fr_to_m31_high(&step_vars[HYPERNOVA_DATA_OFFSET + COL_RS2_VAL]);
    result[COL_RD_HIGH] = fr_to_m31_high(&step_vars[HYPERNOVA_DATA_OFFSET + COL_RD_VAL]);
    result[COL_IMM_HIGH] = fr_to_m31_high(&step_vars[HYPERNOVA_DATA_OFFSET + COL_IMM]);

    // Phase 2.3.4-b：carry_low 列（col 17）默认 0
    // prover 在 ADDI/ADD/SUB 行根据 low limb 加法结果设置：
    //   - ADD/ADDI: carry_low = (rs1_low + rs2_low/imm_low) >= 2^30 ? 1 : 0
    //   - SUB: carry_low = (rs1_low < rs2_low) ? 1 : 0（borrow 语义）
    result[COL_CARRY_LOW] = M31::from(0u32);

    result
}

/// 从 35 个 one-hot selector 中提取 opcode（指令类别 ID）。
///
/// # 算法
/// 遍历 selector 数组，找到值为 `Fr::one()` 的索引 j，返回 `j as u8`。
/// 若无 one-hot（全零），返回 0（LUI 类别，作为安全 fallback）。
///
/// # 参数
/// - `sels` — 35 个 one-hot selector 值
///
/// # 返回
/// opcode ∈ [0, 34]
///
/// # Panics
/// - 若 `sels.len() != NUM_CATEGORIES`（35），debug 模式下 panic
///
/// # 示例
/// ```
/// // LUI 指令：sel_0 = 1，其余 = 0 → opcode = 0
/// // ADD 指令：sel_21 = 1，其余 = 0 → opcode = 21
/// ```
pub fn selector_to_opcode(sels: &[Fr]) -> u8 {
    debug_assert_eq!(
        sels.len(),
        NUM_CATEGORIES,
        "selector_to_opcode: 期望 {} 个 selector，实际 {}",
        NUM_CATEGORIES,
        sels.len()
    );

    for (j, sel) in sels.iter().enumerate() {
        if *sel == Fr::one() {
            return j as u8;
        }
    }

    // 安全 fallback：无 one-hot selector 时返回 0（LUI）
    // 这通常对应 padding 行（Hypernova trace padding 行 selector 全零）
    0
}

/// 将 opcode 反向映射为 35 个 one-hot selector（用于测试与验证）。
///
/// # 参数
/// - `opcode` — 指令类别 ID ∈ [0, 34]
///
/// # 返回
/// 35 个 Fr 值的 `Vec`，`opcode` 位置为 `Fr::one()`，其余为 `Fr::zero()`
///
/// # Panics
/// - 若 `opcode >= NUM_CATEGORIES`（35），panic
pub fn opcode_to_selector(opcode: u8) -> Vec<Fr> {
    assert!(
        opcode < NUM_CATEGORIES as u8,
        "opcode_to_selector: opcode {} >= NUM_CATEGORIES {}",
        opcode,
        NUM_CATEGORIES
    );

    let mut sels = vec![Fr::zero(); NUM_CATEGORIES];
    sels[opcode as usize] = Fr::one();
    sels
}

/// 将单个 BN254 Fr 转换为 M31（取低 30 bit）。
///
/// 与 `trace.rs::fr_to_m31_single` 保持逻辑一致（Phase 2.2.4 将统一到 `field.rs`）。
///
/// # 安全性
/// - 30-bit limb 掩码避免 M31 模数陷阱（P = 2^31 - 1，`M31::from(P)` 归约为 0）
/// - 仅用于 step_index（u64 < 2^30 实际值）等小数值
/// - Phase 3.x：将替换为 9-limb 完整 Fr → M31 转换
fn fr_to_m31_single(fr: &Fr) -> M31 {
    let v = fr.to_u32();
    M31::from(v & M31_LIMB_MASK)
}

/// 将单个 BN254 Fr 转换为 M31（取高 2 bit，Phase 2.3.4-b 新增）。
///
/// 用于 limb decomposition：u32 值 `v = v_low + 2^30 * v_high`，
/// 其中 `v_low = v & 0x3FFFFFFF`（`fr_to_m31_single`），`v_high = v >> 30`（本函数）。
///
/// # 返回
/// `v_high` ∈ [0, 3] ⊂ [0, P-1]，可直接作为 M31 域元素。
///
/// # 安全性
/// - high limb ∈ [0, 3]，远小于 M31 模数 P = 2^31 - 1，无溢出风险
/// - 与 `field.rs::split_u32_to_m31_limbs` 的 high limb 提取逻辑一致
fn fr_to_m31_high(fr: &Fr) -> M31 {
    let v = fr.to_u32();
    M31::from(v >> 30)
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Instruction;

    // ----- 列布局常量测试 -----

    #[test]
    fn test_column_layout_num_columns() {
        assert_eq!(NUM_COLUMNS, 18, "Phase 2.3.4-b limb decomposition 布局应为 18 列");
        assert_eq!(NUM_DATA_COLUMNS, 17, "数据列应为 17 列（12 原始 + 5 limb）");
    }

    #[test]
    fn test_column_layout_indices_distinct() {
        // 18 个列索引应互不相同且覆盖 0..18
        let indices = [
            COL_IDX,
            COL_PC,
            COL_NEXT_PC,
            COL_RS1_VAL,
            COL_RS2_VAL,
            COL_RD_VAL,
            COL_IMM,
            COL_CARRY,
            COL_TAKEN,
            COL_SHAMT,
            COL_BRANCH_COND,
            COL_AUX,
            COL_OPCODE,
            COL_RS1_HIGH,
            COL_RS2_HIGH,
            COL_RD_HIGH,
            COL_IMM_HIGH,
            COL_CARRY_LOW,
        ];
        assert_eq!(indices.len(), NUM_COLUMNS);
        assert_eq!(
            (0..NUM_COLUMNS).collect::<std::collections::HashSet<_>>(),
            indices.iter().copied().collect::<std::collections::HashSet<_>>(),
            "列索引应覆盖 0..NUM_COLUMNS"
        );
    }

    #[test]
    fn test_opcode_column_index() {
        assert_eq!(COL_OPCODE, 12, "opcode 列应为 col 12");
    }

    #[test]
    fn test_limb_column_indices() {
        // Phase 2.3.4-b：limb 列索引应为 13-17
        assert_eq!(COL_RS1_HIGH, 13, "rs1_high 应为 col 13");
        assert_eq!(COL_RS2_HIGH, 14, "rs2_high 应为 col 14");
        assert_eq!(COL_RD_HIGH, 15, "rd_high 应为 col 15");
        assert_eq!(COL_IMM_HIGH, 16, "imm_high 应为 col 16");
        assert_eq!(COL_CARRY_LOW, 17, "carry_low 应为 col 17");
    }

    // ----- selector_to_opcode 测试 -----

    #[test]
    fn test_selector_to_opcode_lui() {
        // LUI = category 0
        let sels = opcode_to_selector(0);
        assert_eq!(selector_to_opcode(&sels), 0);
    }

    #[test]
    fn test_selector_to_opcode_auipc() {
        // AUIPC = category 1
        let sels = opcode_to_selector(1);
        assert_eq!(selector_to_opcode(&sels), 1);
    }

    #[test]
    fn test_selector_to_opcode_add() {
        // ADD = category 21
        let sels = opcode_to_selector(21);
        assert_eq!(selector_to_opcode(&sels), 21);
    }

    #[test]
    fn test_selector_to_opcode_ecall() {
        // ECALL = category 33
        let sels = opcode_to_selector(33);
        assert_eq!(selector_to_opcode(&sels), 33);
    }

    #[test]
    fn test_selector_to_opcode_ebreak() {
        // EBREAK = category 34（最大 opcode）
        let sels = opcode_to_selector(34);
        assert_eq!(selector_to_opcode(&sels), 34);
    }

    #[test]
    fn test_selector_to_opcode_no_onehot_returns_zero() {
        // 全零 selector（padding 行）应返回 0（LUI fallback）
        let sels = vec![Fr::zero(); NUM_CATEGORIES];
        assert_eq!(selector_to_opcode(&sels), 0);
    }

    // ----- opcode_to_selector 测试 -----

    #[test]
    fn test_opcode_to_selector_onehot() {
        for opcode in 0..NUM_CATEGORIES as u8 {
            let sels = opcode_to_selector(opcode);
            assert_eq!(sels.len(), NUM_CATEGORIES);
            // 仅 opcode 位置为 1，其余为 0
            for (j, sel) in sels.iter().enumerate() {
                if j == opcode as usize {
                    assert_eq!(*sel, Fr::one(), "opcode {} 位置应为 Fr::one()", opcode);
                } else {
                    assert_eq!(*sel, Fr::zero(), "位置 {} 应为 Fr::zero()", j);
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "opcode_to_selector")]
    fn test_opcode_to_selector_out_of_range_panics() {
        // opcode = 35 越界，应 panic
        let _ = opcode_to_selector(35);
    }

    // ----- roundtrip 测试 -----

    #[test]
    fn test_opcode_selector_roundtrip() {
        // opcode → selector → opcode 应保持一致
        for opcode in 0..NUM_CATEGORIES as u8 {
            let sels = opcode_to_selector(opcode);
            let recovered = selector_to_opcode(&sels);
            assert_eq!(recovered, opcode, "roundtrip 失败: opcode {}", opcode);
        }
    }

    // ----- map_step_vars_to_stwo 测试 -----

    /// 构造一个全零的 Hypernova step_vars（47 列），用于测试数据列映射。
    fn make_zero_step_vars() -> Vec<Fr> {
        vec![Fr::zero(); STEP_VARS]
    }

    /// 构造一个指定 opcode 的 Hypernova step_vars（数据列全零，selector one-hot）。
    fn make_step_vars_with_opcode(opcode: u8) -> Vec<Fr> {
        let mut vars = vec![Fr::zero(); STEP_VARS];
        let sels = opcode_to_selector(opcode);
        for (j, sel) in sels.into_iter().enumerate() {
            vars[HYPERNOVA_SEL_START + j] = sel;
        }
        vars
    }

    #[test]
    fn test_map_step_vars_to_stwo_length() {
        let vars = make_zero_step_vars();
        let mapped = map_step_vars_to_stwo(&vars);
        assert_eq!(mapped.len(), NUM_COLUMNS);
    }

    #[test]
    fn test_map_step_vars_to_stwo_data_columns_zero() {
        // 全零输入 → 数据列全零
        let vars = make_zero_step_vars();
        let mapped = map_step_vars_to_stwo(&vars);
        for i in 0..NUM_DATA_COLUMNS {
            assert_eq!(mapped[i], M31::from(0u32), "数据列 {} 应为零", i);
        }
    }

    #[test]
    fn test_map_step_vars_to_stwo_data_columns_nonzero() {
        // 设置数据列为非零值，验证 1:1 映射 + high limb 提取
        let mut vars = make_zero_step_vars();
        vars[HYPERNOVA_DATA_OFFSET + COL_IDX] = Fr::from(42u32);
        vars[HYPERNOVA_DATA_OFFSET + COL_PC] = Fr::from(0x1000u32);
        vars[HYPERNOVA_DATA_OFFSET + COL_NEXT_PC] = Fr::from(0x1004u32);
        vars[HYPERNOVA_DATA_OFFSET + COL_RS1_VAL] = Fr::from(0xDeadBeefu32);
        vars[HYPERNOVA_DATA_OFFSET + COL_CARRY] = Fr::from(1u32);
        vars[HYPERNOVA_DATA_OFFSET + COL_SHAMT] = Fr::from(31u32);

        let mapped = map_step_vars_to_stwo(&vars);

        // 30-bit limb 掩码：0xDeadBeef & 0x3FFFFFFF = 0x1EADBEEF
        assert_eq!(mapped[COL_IDX], M31::from(42u32));
        assert_eq!(mapped[COL_PC], M31::from(0x1000u32));
        assert_eq!(mapped[COL_NEXT_PC], M31::from(0x1004u32));
        assert_eq!(mapped[COL_RS1_VAL], M31::from(0x1EADBEEFu32));
        assert_eq!(mapped[COL_CARRY], M31::from(1u32));
        assert_eq!(mapped[COL_SHAMT], M31::from(31u32));

        // Phase 2.3.4-b：high limb 验证
        // 0xDeadBeef >> 30 = 0x3（高 2 bit）
        assert_eq!(mapped[COL_RS1_HIGH], M31::from(3u32), "rs1_high 应为 0xDeadBeef >> 30 = 3");
        // 其他 high limb 为 0（未设置）
        assert_eq!(mapped[COL_RS2_HIGH], M31::from(0u32));
        assert_eq!(mapped[COL_RD_HIGH], M31::from(0u32));
        assert_eq!(mapped[COL_IMM_HIGH], M31::from(0u32));
        // carry_low 默认 0
        assert_eq!(mapped[COL_CARRY_LOW], M31::from(0u32));
    }

    #[test]
    fn test_map_step_vars_to_stwo_opcode_lui() {
        // LUI = opcode 0
        let vars = make_step_vars_with_opcode(0);
        let mapped = map_step_vars_to_stwo(&vars);
        assert_eq!(mapped[COL_OPCODE], M31::from(0u32));
    }

    #[test]
    fn test_map_step_vars_to_stwo_opcode_add() {
        // ADD = opcode 21
        let vars = make_step_vars_with_opcode(21);
        let mapped = map_step_vars_to_stwo(&vars);
        assert_eq!(mapped[COL_OPCODE], M31::from(21u32));
    }

    #[test]
    fn test_map_step_vars_to_stwo_opcode_ecall() {
        // ECALL = opcode 33
        let vars = make_step_vars_with_opcode(33);
        let mapped = map_step_vars_to_stwo(&vars);
        assert_eq!(mapped[COL_OPCODE], M31::from(33u32));
    }

    #[test]
    fn test_map_step_vars_to_stwo_opcode_ebreak() {
        // EBREAK = opcode 34（最大值）
        let vars = make_step_vars_with_opcode(34);
        let mapped = map_step_vars_to_stwo(&vars);
        assert_eq!(mapped[COL_OPCODE], M31::from(34u32));
    }

    #[test]
    fn test_map_step_vars_to_stwo_padding_row() {
        // padding 行：全零 selector → opcode = 0（LUI fallback）
        let vars = make_zero_step_vars();
        let mapped = map_step_vars_to_stwo(&vars);
        assert_eq!(
            mapped[COL_OPCODE],
            M31::from(0u32),
            "padding 行 opcode 应为 0（LUI fallback）"
        );
    }

    // ----- 与 Hypernova instruction_category 集成测试 -----

    #[test]
    fn test_map_step_vars_to_stwo_real_instructions() {
        // 验证真实指令的 opcode 与 instruction_category 一致
        use crate::constraints::instruction_category;

        let instructions = vec![
            (Instruction::Lui { rd: 0, imm: 0 }, 0),
            (Instruction::Auipc { rd: 0, imm: 0 }, 1),
            (Instruction::Jal { rd: 0, imm: 0 }, 2),
            (Instruction::Jalr { rd: 0, rs1: 0, imm: 0 }, 3),
            (Instruction::Beq { rs1: 0, rs2: 0, imm: 0 }, 4),
            (Instruction::Addi { rd: 0, rs1: 0, imm: 0 }, 12),
            (Instruction::Add { rd: 0, rs1: 0, rs2: 0 }, 21),
            (Instruction::Sub { rd: 0, rs1: 0, rs2: 0 }, 22),
            (Instruction::Ecall, 33),
            (Instruction::Ebreak, 34),
        ];

        for (insn, expected_opcode) in instructions {
            let category = instruction_category(&insn);
            assert_eq!(
                category, expected_opcode as usize,
                "instruction_category({:?}) = {}, 期望 {}",
                insn, category, expected_opcode
            );

            // 构造 selector → opcode 验证
            let sels = opcode_to_selector(category as u8);
            let recovered = selector_to_opcode(&sels);
            assert_eq!(recovered, category as u8);
        }
    }
}
