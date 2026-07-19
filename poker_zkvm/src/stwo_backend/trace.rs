//! # Trace 转换 — poker_zkvm Trace → Stwo TraceTable
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"可复用的约束逻辑"：
//! - 复用 `compile_step_witness`（[constraints/mod.rs:271](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)）
//! - 域转换：BN254 Fr → M31（30-bit limb 单值转换）
//!
//! ## 当前状态（Phase 2.2.4）
//!
//! `convert_trace_to_stwo` 改用 Phase 2.2 精简布局：
//! - 遍历 `Trace` 每步，调用 `compile_step_witness` 生成 47 个 BN254 Fr 值
//! - 通过 [`super::column_layout::map_step_vars_to_stwo`] 映射为 13 个 M31 值
//!   （12 数据列 1:1 复制 + opcode 列 = argmax(sel_0..sel_34)）
//! - padding 到 2 的幂行数（Stwo FRI 要求），padding 行保持 M31::from(0u32)
//!
//! Phase 3.x 将替换为 9-limb 完整 Fr → M31 转换以支持 254-bit 非原生域运算。

use crate::ccs::Fr as ZkvmFr;
use crate::constraints::compile_step_witness;
use crate::error::ZkvmError;
use crate::trace::Trace;

use super::column_layout::{map_step_vars_to_stwo, NUM_COLUMNS};
use super::field::M31;

/// Stwo trace 列（一列 M31 值，对应一个 witness 变量在所有 step 上的取值）。
pub type StwoTraceColumn = Vec<M31>;

/// Stwo trace 表（多列 witness，每列对应一个变量）。
///
/// Phase 2.2 精简布局对应 [`super::column_layout::NUM_COLUMNS`] = 13 个变量/step：
/// - `[idx, pc, next_pc, rs1_val, rs2_val, rd_val, imm, carry, taken, shamt, branch_cond, aux, opcode]`
///
/// Phase 1.2-2.1 使用 Hypernova `STEP_VARS = 47`（含 35 列 one-hot selector），
/// Phase 2.2 改用 13 列布局（opcode 列替代 35 列 selector），缩减比 3.6×。
#[derive(Clone, Debug)]
pub struct StwoTraceTable {
    /// 列数 = `column_layout::NUM_COLUMNS` = 13（Phase 2.2 精简布局）
    pub num_columns: usize,
    /// 行数 = trace 步数（已 padding 到 2 的幂）
    pub num_rows: usize,
    /// 列主序存储：`columns[col][row]`
    pub columns: Vec<StwoTraceColumn>,
}

impl StwoTraceTable {
    /// 创建指定大小的空 trace 表（所有元素初始化为 `M31::from(0u32)`）。
    pub fn new(num_columns: usize, num_rows: usize) -> Self {
        Self {
            num_columns,
            num_rows,
            columns: vec![vec![M31::from(0u32); num_rows]; num_columns],
        }
    }

    /// 设置指定 `(col, row)` 位置的值。
    pub fn set(&mut self, col: usize, row: usize, value: M31) {
        debug_assert!(col < self.num_columns, "col {} >= num_columns {}", col, self.num_columns);
        debug_assert!(row < self.num_rows, "row {} >= num_rows {}", row, self.num_rows);
        self.columns[col][row] = value;
    }

    /// 获取指定 `(col, row)` 位置的值。
    pub fn get(&self, col: usize, row: usize) -> M31 {
        self.columns[col][row]
    }
}

/// 将 poker_zkvm `Trace` 转换为 `StwoTraceTable`。
///
/// # 转换流程（Phase 2.2.4）
/// 1. 遍历 `trace.step(i)`，对每步调用 `compile_step_witness` 生成 47 个 BN254 Fr 值
///    （Hypernova `STEP_VARS` 布局：12 数据列 + 35 one-hot selector）
/// 2. 通过 [`map_step_vars_to_stwo`] 映射为 13 个 M31 值（Phase 2.2 精简布局）：
///    - 数据列（col 0-11）：1:1 直接复制，BN254 Fr → M31（30-bit limb 掩码）
///    - opcode 列（col 12）：`argmax(sel_0..sel_34)`，值域 [0, 34]
/// 3. padding 到 2 的幂行数（Stwo FRI 要求），padding 行保持 M31::from(0u32)
///
/// # Phase 2.2 POC 安全性
/// - 30-bit limb 掩码避免 M31 模数陷阱（`M31::from(2^31 - 1)` 归约为 0）
/// - 仅对 step_index / pc / 寄存器值等 u32 值有效；254-bit Fr 完整转换留待 Phase 3.x
///
/// # Errors
/// - `trace.is_empty()` 返回 `ZkvmError::Other`
pub fn convert_trace_to_stwo(trace: &Trace) -> Result<StwoTraceTable, ZkvmError> {
    if trace.is_empty() {
        return Err(ZkvmError::Other(
            "convert_trace_to_stwo: trace 为空".to_string(),
        ));
    }
    let num_steps = trace.len();
    // Stwo FRI 要求 trace 行数为 2 的幂；至少 2 行（log_size >= 1）。
    let padded_rows = num_steps.next_power_of_two().max(2);
    // Phase 2.2：列数从 STEP_VARS=47 精简为 NUM_COLUMNS=13。
    let num_columns = NUM_COLUMNS;
    let mut table = StwoTraceTable::new(num_columns, padded_rows);

    for i in 0..num_steps {
        let step = trace.step(i)?;
        let prev_step = if i > 0 {
            Some(trace.step(i - 1)?)
        } else {
            None
        };
        let next_step_pc = if i + 1 < num_steps {
            Some(trace.step(i + 1)?.pc)
        } else {
            None
        };
        // compile_step_witness 返回 Hypernova 47 列 Fr witness（12 数据 + 35 selector）。
        let witness: Vec<ZkvmFr> = compile_step_witness(step, prev_step, next_step_pc);
        debug_assert_eq!(
            witness.len(),
            crate::constraints::STEP_VARS,
            "compile_step_witness 返回 {} 个值，但 STEP_VARS = {}",
            witness.len(),
            crate::constraints::STEP_VARS
        );
        // Phase 2.2.4：47 列 Fr → 13 列 M31（数据列 1:1 + opcode = argmax(selector)）。
        let mapped: Vec<M31> = map_step_vars_to_stwo(&witness);
        debug_assert_eq!(
            mapped.len(),
            NUM_COLUMNS,
            "map_step_vars_to_stwo 返回 {} 个值，但 NUM_COLUMNS = {}",
            mapped.len(),
            NUM_COLUMNS
        );
        for (col, m31_val) in mapped.iter().enumerate() {
            table.set(col, i, *m31_val);
        }
    }
    // padding 行（num_steps..padded_rows）保持 M31::from(0u32)（StwoTraceTable::new 已初始化）
    // Phase 1.2 POC：Group A 约束（idx 连续性）仅检查原始 step 行；
    // padding 行的 idx=0 不会触发约束失败（Stwo FrameworkEval 默认对 padding 行豁免）。
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Instruction;
    use crate::trace::{MemAccess, Step, StepLog};

    /// 构造最小可执行 Step（Lui x0, 0 + 全零寄存器）。
    ///
    /// `step_index` 由调用方指定，用于验证 Group A 约束（idx 连续性）。
    ///
    /// **Phase 2.3.1**：`pc = step_index * 4`（与 `test_helpers::make_minimal_step` 一致），
    /// 使 Group B 约束（`pc[next] == next_pc[cur]`）在 step order 下成立。
    fn make_minimal_step(step_index: u64) -> Step {
        Step::from_log(
            step_index,
            StepLog {
                pc: (step_index as u32).wrapping_mul(4),
                instruction: Instruction::Lui { rd: 0, imm: 0 },
                registers: [0u32; 32],
                mem_access: Vec::<MemAccess>::new(),
            },
        )
    }

    /// 构造指定步数的 trace（idx 列严格连续递增）。
    fn make_sequential_trace(num_steps: usize) -> Trace {
        let mut trace = Trace::new();
        for i in 0..num_steps {
            trace.push_step(make_minimal_step(i as u64));
        }
        trace
    }

    #[test]
    fn test_stwo_trace_table_set_get() {
        let mut table = StwoTraceTable::new(3, 4);
        table.set(1, 2, M31::from(42u32));
        assert_eq!(table.get(1, 2), M31::from(42u32));
        // 默认零值
        assert_eq!(table.get(0, 0), M31::from(0u32));
    }

    #[test]
    fn test_convert_trace_empty_returns_error() {
        let trace = Trace::new();
        let result = convert_trace_to_stwo(&trace);
        assert!(result.is_err());
        match result {
            Err(ZkvmError::Other(msg)) => {
                assert!(msg.contains("trace 为空"), "unexpected msg: {msg}");
            }
            other => panic!("expected ZkvmError::Other, got {other:?}"),
        }
    }

    #[test]
    fn test_convert_trace_padding_to_power_of_two() {
        // 5 步 trace 应 padding 到 8 行（next_power_of_two(5) = 8）
        let trace = make_sequential_trace(5);
        let table = convert_trace_to_stwo(&trace).expect("5 步 trace 应转换成功");
        assert_eq!(table.num_rows, 8, "5 步应 padding 到 8 行");
        // Phase 2.2：列数从 STEP_VARS=47 精简为 NUM_COLUMNS=13。
        assert_eq!(table.num_columns, NUM_COLUMNS);

        // padding 行（5..8）应保持零值
        for col in 0..table.num_columns {
            for row in 5..8 {
                assert_eq!(table.get(col, row), M31::from(0u32), "padding 行 ({col},{row}) 应为零");
            }
        }
    }

    #[test]
    fn test_convert_trace_step_index_column() {
        // col 0 = idx = step_index（见 constraints/mod.rs::compile_step_witness 行 372）
        let trace = make_sequential_trace(4);
        let table = convert_trace_to_stwo(&trace).expect("4 步 trace 应转换成功");
        assert_eq!(table.num_rows, 4);
        for i in 0..4 {
            let idx_val = table.get(0, i);
            assert_eq!(
                idx_val,
                M31::from(i as u32),
                "idx[{i}] 应等于 step_index {i}, 实际 = {idx_val:?}"
            );
        }
    }

    #[test]
    fn test_convert_trace_num_columns_matches_layout() {
        // Phase 2.2：列数应等于 column_layout::NUM_COLUMNS = 13（替代原 STEP_VARS = 47）。
        let trace = make_sequential_trace(2);
        let table = convert_trace_to_stwo(&trace).expect("2 步 trace 应转换成功");
        assert_eq!(
            table.num_columns,
            NUM_COLUMNS,
            "列数应等于 NUM_COLUMNS = {}",
            NUM_COLUMNS
        );
        assert_eq!(table.columns.len(), NUM_COLUMNS);
    }

    #[test]
    fn test_convert_trace_opcode_column_lui() {
        // Phase 2.2：col 12 = opcode，Lui 指令对应 opcode = 0（NUM_CATEGORIES 中第一个）。
        // 验证 map_step_vars_to_stwo 正确将 35 个 one-hot selector 压缩为单个 opcode 值。
        let trace = make_sequential_trace(2);
        let table = convert_trace_to_stwo(&trace).expect("2 步 trace 应转换成功");
        // make_minimal_step 使用 Lui 指令，instruction_category(Lui) = 0
        for i in 0..2 {
            let opcode_val = table.get(NUM_COLUMNS - 1, i);
            assert_eq!(
                opcode_val,
                M31::from(0u32),
                "opcode[{i}] 应为 0（LUI category），实际 = {opcode_val:?}"
            );
        }
    }

    #[test]
    fn test_convert_trace_minimum_two_rows() {
        // 1 步 trace 应 padding 到 2 行（log_size >= 1）
        let trace = make_sequential_trace(1);
        let table = convert_trace_to_stwo(&trace).expect("1 步 trace 应转换成功");
        assert_eq!(table.num_rows, 2, "1 步应 padding 到 2 行");
    }
}