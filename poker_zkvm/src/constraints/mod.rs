//! Trace → CCS 约束编译器（Phase 5 — Task 5.1）。
//!
//! 严格遵循 spec.md L268-279（v1.4 FROZEN）：
//! - [`compile_trace_to_ccs`] — 主入口，将 trace 按 `batch_size` 分批编译为 CCS 实例
//! - **Batching 策略**：每 K = [`ZKVM_BATCH_SIZE`]（默认 1024）步生成 1 个 CCS 实例
//! - **实例数上限**：≤ [`MAX_FOLD_STEP_COUNT`] = 1000（即 N ≤ 1,024,000 ≈ MAX_ZKVM_TRACE_STEPS）
//! - **连续性约束**：batch 内 step_index 单调递增（`idx_{i+1} - idx_i - 1 = 0`）
//! - **batch 间连续性**：通过 public_inputs 传递（前一 batch 末步 idx + 1 == 后一 batch 首步 idx）
//!
//! ## MVP 范围（Step 8）
//!
//! Step 8 仅实现 batching 框架 + step_index 连续性约束。
//! 指令子电路（算术 / 内存 / 控制流 / syscall）在 Step 9-12 实现，
//! 届时每步指令的语义约束将附加到本框架生成的 CCS 实例中。
//!
//! ## 子模块
//!
//! - [`algebra`] — 算术指令子电路（Step 9 实现）
//! - [`memory`] — 内存访问与一致性电路（Step 10 实现）
//! - [`control_flow`] — 控制流指令子电路（Step 11 实现）
//! - [`syscall_circuit`] — Syscall 子电路（Step 12 实现）
//! - [`lookup`] — LogUp lookup 协议（Step 13 实现）

pub mod algebra;
pub mod control_flow;
pub mod lookup;
pub mod memory;
pub mod syscall_circuit;

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::isa::Instruction;
use crate::trace::{Step, Trace};

/// 默认 batch 大小（spec L276：K = 1024）。
///
/// 每 K 步执行生成 1 个 CCS 实例。
pub const ZKVM_BATCH_SIZE: usize = 1024;

/// 最大折叠步数（spec L277：MAX_FOLD_STEP_COUNT = 1000）。
///
/// `compile_trace_to_ccs` 返回的 CCS 实例数上限。
/// 即 trace 步数 N ≤ 1000 × 1024 = 1,024,000 ≈ MAX_ZKVM_TRACE_STEPS。
pub const MAX_FOLD_STEP_COUNT: usize = 1000;

// ===========================================================================
// Stage 2 — 统一 witness 布局 + selector-gated 约束
// ===========================================================================

/// 每步 witness 变量数（Stage 2 设计）。
///
/// 布局：`[idx, pc, next_pc, rs1_val, rs2_val, rd_val, imm, carry, taken, shamt, branch_cond, aux, sel_0..sel_34]`
pub const STEP_VARS: usize = 47;

/// 指令语义组数（one-hot selector 数量）。
pub const NUM_CATEGORIES: usize = 35;

// Witness 偏移量（每步内部）
const OFF_IDX: usize = 0;
const OFF_PC: usize = 1;
const OFF_NEXT_PC: usize = 2;
#[cfg_attr(not(test), allow(dead_code))]
const OFF_RS1_VAL: usize = 3;
#[cfg_attr(not(test), allow(dead_code))]
const OFF_RS2_VAL: usize = 4;
#[allow(dead_code)]
const OFF_RD_VAL: usize = 5;
#[allow(dead_code)]
const OFF_IMM: usize = 6;
#[allow(dead_code)]
const OFF_CARRY: usize = 7;
#[cfg_attr(not(test), allow(dead_code))]
const OFF_TAKEN: usize = 8;
#[allow(dead_code)]
const OFF_SHAMT: usize = 9;
#[allow(dead_code)]
const OFF_BRANCH_COND: usize = 10;
const OFF_AUX: usize = 11;
const OFF_SEL_START: usize = 12;

// 42-matrix CCS 矩阵索引
const M_A_NEXT: usize = 0;
const M_A_CUR: usize = 1;
const M_CONST_A: usize = 2;
const M_B_NEXT: usize = 3;
const M_B_CUR: usize = 4;
const M_C_BASE: usize = 5; // M_C_0..M_C_{NUM_CATEGORIES-1} = 5..(5+NUM_CATEGORIES-1)
const M_CONST_C: usize = M_C_BASE + NUM_CATEGORIES; // 5 + 35 = 40
const M_D_SQ: usize = M_CONST_C + 1; // 41
const M_D_LIN: usize = M_CONST_C + 2; // 42

// Phase 2b — 算术指令约束矩阵
const M_E_RS1: usize = M_D_LIN + 1; // 43
const M_E_RS2: usize = M_D_LIN + 2; // 44
const M_E_RD: usize = M_D_LIN + 3; // 45
const M_E_IMM: usize = M_D_LIN + 4; // 46
const M_E_CARRY: usize = M_D_LIN + 5; // 47
const M_E_PC: usize = M_D_LIN + 6; // 48
const M_E_AUX: usize = M_D_LIN + 7; // 49
const NUM_CCS_MATRICES: usize = M_E_AUX + 1; // 50

/// 算术指令类别列表（对应 [`instruction_category`] 返回值）。
///
/// 顺序决定 Group E 行内偏移：LUI=0, AUIPC=1, ADDI=2, SLTI=3, SLTIU=4, ADD=5, SUB=6, SLT=7, SLTU=8。
#[allow(dead_code)]
const ARITH_CATEGORIES: [usize; 9] = [0, 1, 12, 13, 14, 21, 22, 24, 25];
#[allow(dead_code)]
const NUM_ARITH: usize = 9;

/// 返回指令的语义组 ID（0..33）。
fn instruction_category(insn: &Instruction) -> usize {
    match insn {
        Instruction::Lui { .. } => 0,
        Instruction::Auipc { .. } => 1,
        Instruction::Jal { .. } => 2,
        Instruction::Jalr { .. } => 3,
        Instruction::Beq { .. } => 4,
        Instruction::Bne { .. } => 5,
        Instruction::Blt { .. } => 6,
        Instruction::Bge { .. } => 7,
        Instruction::Bltu { .. } => 8,
        Instruction::Bgeu { .. } => 9,
        Instruction::Lb { .. }
        | Instruction::Lh { .. }
        | Instruction::Lw { .. }
        | Instruction::Lbu { .. }
        | Instruction::Lhu { .. } => 10,
        Instruction::Sb { .. } | Instruction::Sh { .. } | Instruction::Sw { .. } => 11,
        Instruction::Addi { .. } => 12,
        Instruction::Slti { .. } => 13,
        Instruction::Sltiu { .. } => 14,
        Instruction::Xori { .. } => 15,
        Instruction::Ori { .. } => 16,
        Instruction::Andi { .. } => 17,
        Instruction::Slli { .. } => 18,
        Instruction::Srli { .. } => 19,
        Instruction::Srai { .. } => 20,
        Instruction::Add { .. } => 21,
        Instruction::Sub { .. } => 22,
        Instruction::Sll { .. } => 23,
        Instruction::Slt { .. } => 24,
        Instruction::Sltu { .. } => 25,
        Instruction::Xor { .. } => 26,
        Instruction::Srl { .. } => 27,
        Instruction::Sra { .. } => 28,
        Instruction::Or { .. } => 29,
        Instruction::And { .. } => 30,
        Instruction::Mul { .. }
        | Instruction::Mulh { .. }
        | Instruction::Mulhsu { .. }
        | Instruction::Mulhu { .. }
        | Instruction::Div { .. }
        | Instruction::Divu { .. }
        | Instruction::Rem { .. }
        | Instruction::Remu { .. } => 31,
        Instruction::Fence => 32,
        Instruction::Ecall => 33,
        Instruction::Ebreak => 34,
    }
}

/// 根据指令类型返回 one-hot selector 数组。
fn assign_selectors(insn: &Instruction) -> [Fr; NUM_CATEGORIES] {
    let mut sels = [Fr::zero(); NUM_CATEGORIES];
    sels[instruction_category(insn)] = Fr::one();
    sels
}

/// 从指令中提取寄存器索引和立即数。
///
/// 返回 `(rs1_idx, rs2_idx, rd_idx, imm, shamt)`，不适用的字段为 `None` / `0`。
fn extract_insn_fields(insn: &Instruction) -> (Option<u8>, Option<u8>, Option<u8>, u32, u8) {
    match insn {
        Instruction::Lui { rd, imm } => (None, None, Some(*rd), *imm, 0),
        Instruction::Auipc { rd, imm } => (None, None, Some(*rd), *imm, 0),
        Instruction::Jal { rd, imm } => (None, None, Some(*rd), *imm, 0),
        Instruction::Jalr { rd, rs1, imm } => (Some(*rs1), None, Some(*rd), *imm, 0),
        Instruction::Beq { rs1, rs2, imm }
        | Instruction::Bne { rs1, rs2, imm }
        | Instruction::Blt { rs1, rs2, imm }
        | Instruction::Bge { rs1, rs2, imm }
        | Instruction::Bltu { rs1, rs2, imm }
        | Instruction::Bgeu { rs1, rs2, imm } => (Some(*rs1), Some(*rs2), None, *imm, 0),
        Instruction::Lb { rd, rs1, imm }
        | Instruction::Lh { rd, rs1, imm }
        | Instruction::Lw { rd, rs1, imm }
        | Instruction::Lbu { rd, rs1, imm }
        | Instruction::Lhu { rd, rs1, imm } => (Some(*rs1), None, Some(*rd), *imm, 0),
        Instruction::Sb { rs1, rs2, imm }
        | Instruction::Sh { rs1, rs2, imm }
        | Instruction::Sw { rs1, rs2, imm } => (Some(*rs1), Some(*rs2), None, *imm, 0),
        Instruction::Addi { rd, rs1, imm }
        | Instruction::Slti { rd, rs1, imm }
        | Instruction::Sltiu { rd, rs1, imm }
        | Instruction::Xori { rd, rs1, imm }
        | Instruction::Ori { rd, rs1, imm }
        | Instruction::Andi { rd, rs1, imm } => (Some(*rs1), None, Some(*rd), *imm, 0),
        Instruction::Slli { rd, rs1, shamt }
        | Instruction::Srli { rd, rs1, shamt }
        | Instruction::Srai { rd, rs1, shamt } => (Some(*rs1), None, Some(*rd), 0, *shamt),
        Instruction::Add { rd, rs1, rs2 }
        | Instruction::Sub { rd, rs1, rs2 }
        | Instruction::Sll { rd, rs1, rs2 }
        | Instruction::Slt { rd, rs1, rs2 }
        | Instruction::Sltu { rd, rs1, rs2 }
        | Instruction::Xor { rd, rs1, rs2 }
        | Instruction::Srl { rd, rs1, rs2 }
        | Instruction::Sra { rd, rs1, rs2 }
        | Instruction::Or { rd, rs1, rs2 }
        | Instruction::And { rd, rs1, rs2 }
        | Instruction::Mul { rd, rs1, rs2 }
        | Instruction::Mulh { rd, rs1, rs2 }
        | Instruction::Mulhsu { rd, rs1, rs2 }
        | Instruction::Mulhu { rd, rs1, rs2 }
        | Instruction::Div { rd, rs1, rs2 }
        | Instruction::Divu { rd, rs1, rs2 }
        | Instruction::Rem { rd, rs1, rs2 }
        | Instruction::Remu { rd, rs1, rs2 } => (Some(*rs1), Some(*rs2), Some(*rd), 0, 0),
        Instruction::Fence | Instruction::Ecall | Instruction::Ebreak => {
            (None, None, None, 0, 0)
        }
    }
}

/// 计算分支 taken flag。
fn compute_taken(insn: &Instruction, rs1_val: u32, rs2_val: u32) -> bool {
    match insn {
        Instruction::Beq { .. } => rs1_val == rs2_val,
        Instruction::Bne { .. } => rs1_val != rs2_val,
        Instruction::Blt { .. } => (rs1_val as i32) < (rs2_val as i32),
        Instruction::Bge { .. } => (rs1_val as i32) >= (rs2_val as i32),
        Instruction::Bltu { .. } => rs1_val < rs2_val,
        Instruction::Bgeu { .. } => rs1_val >= rs2_val,
        _ => false,
    }
}

/// 从指令语义计算后继 PC。
fn compute_next_pc(pc: u32, insn: &Instruction, rs1_val: u32, rs2_val: u32) -> u32 {
    match insn {
        Instruction::Jal { imm, .. } => pc.wrapping_add(*imm),
        Instruction::Jalr { imm, .. } => (rs1_val.wrapping_add(*imm)) & !1,
        Instruction::Beq { imm, .. }
        | Instruction::Bne { imm, .. }
        | Instruction::Blt { imm, .. }
        | Instruction::Bge { imm, .. }
        | Instruction::Bltu { imm, .. }
        | Instruction::Bgeu { imm, .. } => {
            if compute_taken(insn, rs1_val, rs2_val) {
                pc.wrapping_add(*imm)
            } else {
                pc.wrapping_add(4)
            }
        }
        _ => pc.wrapping_add(4),
    }
}

/// 编译单步 witness（46 个变量）。
///
/// # 参数
/// - `step` — 当前步
/// - `prev_step` — 前一步（用于提取 rs1/rs2 值），首步为 `None`
/// - `next_step_pc` — 下一步的 PC（用于 next_pc），末步为 `None` 时从指令计算
#[allow(clippy::collapsible_match)]
fn compile_step_witness(
    step: &Step,
    prev_step: Option<&Step>,
    next_step_pc: Option<u32>,
) -> Vec<Fr> {
    let (rs1_idx, rs2_idx, rd_idx, imm, extracted_shamt) = extract_insn_fields(&step.instruction);

    let (rs1_val, rs2_val) = match prev_step {
        Some(prev) => {
            let rs1 = rs1_idx.map_or(0, |idx| prev.registers[idx as usize]);
            let rs2 = rs2_idx.map_or(0, |idx| prev.registers[idx as usize]);
            (rs1, rs2)
        }
        None => (0, 0),
    };

    let shamt = match &step.instruction {
        Instruction::Sll { .. } | Instruction::Srl { .. } | Instruction::Sra { .. } => {
            (rs2_val & 0x1F) as u8
        }
        _ => extracted_shamt,
    };

    let rd_val = rd_idx.map_or(0, |idx| step.registers[idx as usize]);

    let next_pc = next_step_pc
        .unwrap_or_else(|| compute_next_pc(step.pc, &step.instruction, rs1_val, rs2_val));

    let taken = compute_taken(&step.instruction, rs1_val, rs2_val);
    let selectors = assign_selectors(&step.instruction);

    let carry: u32 = match &step.instruction {
        Instruction::Add { .. } => {
            if (rs1_val as u64) + (rs2_val as u64) >= (1u64 << 32) {
                1
            } else {
                0
            }
        }
        Instruction::Addi { .. } => {
            if (rs1_val as u64) + (imm as u64) >= (1u64 << 32) {
                1
            } else {
                0
            }
        }
        Instruction::Sub { .. } => {
            if rs1_val < rs2_val {
                1
            } else {
                0
            }
        }
        Instruction::Slt { .. } => {
            if (rs1_val as i32) < (rs2_val as i32) {
                1
            } else {
                0
            }
        }
        Instruction::Sltu { .. } => {
            if rs1_val < rs2_val {
                1
            } else {
                0
            }
        }
        Instruction::Slti { .. } => {
            if (rs1_val as i32) < (imm as i32) {
                1
            } else {
                0
            }
        }
        Instruction::Sltiu { .. } => {
            if rs1_val < imm {
                1
            } else {
                0
            }
        }
        _ => 0,
    };

    let aux: u32 = match &step.instruction {
        Instruction::Xori { .. } => rs1_val ^ imm,
        Instruction::Ori { .. } => rs1_val | imm,
        Instruction::Andi { .. } => rs1_val & imm,
        Instruction::Xor { .. } => rs1_val ^ rs2_val,
        Instruction::Or { .. } => rs1_val | rs2_val,
        Instruction::And { .. } => rs1_val & rs2_val,
        Instruction::Slli { .. } => rs1_val << shamt,
        Instruction::Srli { .. } => rs1_val >> shamt,
        Instruction::Srai { .. } => ((rs1_val as i32) >> shamt) as u32,
        Instruction::Sll { .. } => rs1_val << shamt,
        Instruction::Srl { .. } => rs1_val >> shamt,
        Instruction::Sra { .. } => ((rs1_val as i32) >> shamt) as u32,
        _ => 0,
    };

    let mut witness = Vec::with_capacity(STEP_VARS);
    witness.push(Fr::from_u64(step.step_index));
    witness.push(Fr::from_u32_with_wrap(step.pc));
    witness.push(Fr::from_u32_with_wrap(next_pc));
    witness.push(Fr::from_u32_with_wrap(rs1_val));
    witness.push(Fr::from_u32_with_wrap(rs2_val));
    witness.push(Fr::from_u32_with_wrap(rd_val));
    witness.push(Fr::from_u32_with_wrap(imm));
    witness.push(Fr::from_u32_with_wrap(carry));
    witness.push(Fr::from_u32_with_wrap(if taken { 1 } else { 0 }));
    witness.push(Fr::from_u32_with_wrap(shamt as u32));
    witness.push(Fr::zero()); // branch_cond — Phase 2d 填充
    witness.push(Fr::from_u32_with_wrap(aux));
    witness.extend_from_slice(&selectors);

    assert_eq!(witness.len(), STEP_VARS);
    witness
}

/// 将 execution trace 编译为 CCS 实例列表（spec L268-279）。
///
/// 每 `batch_size` 步生成 1 个 CCS 实例，返回 ⌈N/K⌉ 个实例。
/// 实例数 ≤ [`MAX_FOLD_STEP_COUNT`]，超出返回 [`ZkvmError::FoldStepCountExceeded`]。
///
/// # 参数
/// - `trace` — 执行轨迹
/// - `batch_size` — 每批步数（须 > 0，默认用 [`ZKVM_BATCH_SIZE`]）
///
/// # 返回
/// - `Ok(Vec<CcsInstance>)` — CCS 实例列表（长度 = ⌈N/K⌉）
/// - `Err(ZkvmError)` — batch_size 为 0 / 实例数超限 / 内部编译错误
///
/// # 闭环验证
///
/// ```text
/// let instances = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE)?;
/// assert!(instances.len() <= MAX_FOLD_STEP_COUNT);
/// for inst in &instances {
///     assert!(inst.is_satisfied()?);
/// }
/// ```
///
/// # 错误
/// - `ZkvmError::Other` — batch_size 为 0 或 trace 为空
/// - `ZkvmError::FoldStepCountExceeded` — 实例数 > MAX_FOLD_STEP_COUNT
pub fn compile_trace_to_ccs(
    trace: &Trace,
    batch_size: usize,
) -> Result<Vec<CcsInstance>, ZkvmError> {
    if batch_size == 0 {
        return Err(ZkvmError::Other(
            "compile_trace_to_ccs: batch_size 须 > 0".to_string(),
        ));
    }
    if trace.is_empty() {
        return Err(ZkvmError::Other(
            "compile_trace_to_ccs: trace 为空".to_string(),
        ));
    }

    let num_steps = trace.len();
    let num_batches = num_steps.div_ceil(batch_size);

    if num_batches > MAX_FOLD_STEP_COUNT {
        return Err(ZkvmError::FoldStepCountExceeded {
            actual: num_batches as u32,
            limit: MAX_FOLD_STEP_COUNT as u32,
        });
    }

    let mut instances = Vec::with_capacity(num_batches);
    for batch_id in 0..num_batches {
        let start = batch_id * batch_size;
        let end = usize::min(start + batch_size, num_steps);
        let batch_steps: Vec<&crate::trace::Step> =
            (start..end).map(|i| trace.step(i)).collect::<Result<Vec<_>, _>>()?;
        let instance = compile_batch_to_ccs(&batch_steps, batch_id as u64)?;
        instances.push(instance);
    }

    Ok(instances)
}

/// 编译单个 batch 为 CCS 实例（Stage 2 Phase 2c — 49-matrix selector-gated 框架）。
///
/// # 49-matrix CCS 设计
///
/// Witness 布局：`z = [1, w_0, w_1, ..., w_{K-1}, padding]`，每步 `STEP_VARS=46` 个变量。
/// 详见 [`compile_step_witness`] 和 [`STEP_VARS`]。
///
/// 6 个约束组（共享 93 个 subset，矩阵仅在对应组行有非零条目）：
///
/// | 组 | 行范围 | 行数 | 约束 |
/// |----|--------|------|------|
/// | A | 0..K-2 | K-1 | `idx_{i+1} - idx_i - 1 = 0`（step_index 连续性） |
/// | B | K-1..2K-3 | K-1 | `next_pc_i - pc_{i+1} = 0`（PC 连续性） |
/// | C | 2K-2..3K-3 | K | `Σ_j sel_j(i) - 1 = 0`（selector one-hot） |
/// | D | 3K-2..37K-3 | 34K | `sel_j(i)² - sel_j(i) = 0`（selector 二值性） |
/// | E | 37K-2..38K-3 | K | 算术/逻辑/移位语义 + carry²-carry（selector-gated） |
/// | F | 38K-2..39K-3 | K | `carry(i)² - carry(i) = 0`（carry 二值性） |
///
/// Group E 每步 1 行，通过 selector gating 同时检查所有指令类别。
/// M_CONST_C 在 Group E 行使用 +1（非 Group C 行的 -1），维持 `Σ sel_j - 1 = 0`。
///
/// 总行数 = 39K-2，矩阵数 = 49，subset 数 = 93。
///
/// # Power-of-2 Padding
///
/// Hypernova 折叠要求 `num_vars` 和 `num_rows` 均为 2 的幂。padding 行/列为隐式 0
/// （dummy 约束 `0 = 0`，vacuously satisfied）。
fn compile_batch_to_ccs(
    steps: &[&crate::trace::Step],
    batch_id: u64,
) -> Result<CcsInstance, ZkvmError> {
    let k = steps.len();
    if k == 0 {
        return Err(ZkvmError::Other(
            "compile_batch_to_ccs: batch 为空".to_string(),
        ));
    }

    let raw_num_vars = 1 + k * STEP_VARS;
    let raw_num_rows = (NUM_CATEGORIES + 5) * k - 2; // (K-1)+(K-1)+K+NUM_CATEGORIES*K+K(Group E)+K(Group F)
    let padded_num_vars = raw_num_vars.next_power_of_two().max(2);
    let padded_num_rows = raw_num_rows.max(1).next_power_of_two();

    // --- Witness: [1, w_0, w_1, ..., w_{K-1}, padding] ---
    let mut witness = Vec::with_capacity(padded_num_vars);
    witness.push(Fr::one());
    for (i, step) in steps.iter().enumerate() {
        let prev_step = if i > 0 { Some(steps[i - 1]) } else { None };
        let step_witness = compile_step_witness(step, prev_step, None);
        witness.extend_from_slice(&step_witness);
    }
    witness.resize(padded_num_vars, Fr::zero());

    // --- 49 矩阵（padded 维度，padding 行/列隐式为 0） ---
    let neg_one = Fr::zero().sub(&Fr::one());
    let mut matrices: Vec<SparseMatrix> = (0..NUM_CCS_MATRICES)
        .map(|_| SparseMatrix::new(padded_num_rows, padded_num_vars))
        .collect();

    // Group A: step_index continuity (rows 0..K-2)
    for i in 0..k.saturating_sub(1) {
        let row = i;
        let col_next = 1 + (i + 1) * STEP_VARS + OFF_IDX;
        let col_cur = 1 + i * STEP_VARS + OFF_IDX;
        matrices[M_A_NEXT].add_entry(row, col_next, Fr::one())?;
        matrices[M_A_CUR].add_entry(row, col_cur, neg_one)?;
        matrices[M_CONST_A].add_entry(row, 0, neg_one)?;
    }

    // Group B: PC continuity (rows K-1..2K-3)
    for i in 0..k.saturating_sub(1) {
        let row = (k - 1) + i;
        let col_next_pc = 1 + i * STEP_VARS + OFF_NEXT_PC;
        let col_next_step_pc = 1 + (i + 1) * STEP_VARS + OFF_PC;
        matrices[M_B_NEXT].add_entry(row, col_next_pc, Fr::one())?;
        matrices[M_B_CUR].add_entry(row, col_next_step_pc, neg_one)?;
    }

    // Group C: selector one-hot (rows 2K-2..3K-3)
    for i in 0..k {
        let row = 2 * (k - 1) + i; // 2K-2 + i
        for j in 0..NUM_CATEGORIES {
            let col = 1 + i * STEP_VARS + OFF_SEL_START + j;
            matrices[M_C_BASE + j].add_entry(row, col, Fr::one())?;
        }
        // M_CONST_C entry = +1; sign comes from subset coefficient (-1)
        // Contribution: (-1) * (+1 * z[0]) = -1, giving Σ sel_j - 1 = 0
        matrices[M_CONST_C].add_entry(row, 0, Fr::one())?;
    }

    // Group D: selector binary (rows 3K-2..37K-3)
    for i in 0..k {
        for j in 0..NUM_CATEGORIES {
            let row = 3 * k - 2 + i * NUM_CATEGORIES + j; // 3K-2 + i*34 + j
            let col = 1 + i * STEP_VARS + OFF_SEL_START + j;
            matrices[M_D_SQ].add_entry(row, col, Fr::one())?;
            matrices[M_D_LIN].add_entry(row, col, Fr::one())?;
        }
    }

    // Group E: arithmetic constraints (rows (NUM_CATEGORIES+3)K-2..(NUM_CATEGORIES+4)K-3, K rows)
    // 每步 1 行，所有 9 个算术类别通过 selector gating 同时检查。
    // M_CONST_C 使用 +1（非 Group C 的 -1）以维持 Σ sel_j - 1 = 0。
    for i in 0..k {
        let row = (NUM_CATEGORIES + 3) * k - 2 + i;
        let base = 1 + i * STEP_VARS;
        // 所有 selector 矩阵 +1（使 M_C_j·z[row] = sel_j(i)）
        for j in 0..NUM_CATEGORIES {
            matrices[M_C_BASE + j].add_entry(row, base + OFF_SEL_START + j, Fr::one())?;
        }
        // M_CONST_C +1（使 Group C 在此行：Σ sel_j - 1 = 0）
        matrices[M_CONST_C].add_entry(row, 0, Fr::one())?;
        // 6 个操作数矩阵 +1
        matrices[M_E_RS1].add_entry(row, base + OFF_RS1_VAL, Fr::one())?;
        matrices[M_E_RS2].add_entry(row, base + OFF_RS2_VAL, Fr::one())?;
        matrices[M_E_RD].add_entry(row, base + OFF_RD_VAL, Fr::one())?;
        matrices[M_E_IMM].add_entry(row, base + OFF_IMM, Fr::one())?;
        matrices[M_E_CARRY].add_entry(row, base + OFF_CARRY, Fr::one())?;
        matrices[M_E_PC].add_entry(row, base + OFF_PC, Fr::one())?;
        matrices[M_E_AUX].add_entry(row, base + OFF_AUX, Fr::one())?;
    }

    // Group F: carry binary (rows (NUM_CATEGORIES+4)K-2..(NUM_CATEGORIES+5)K-3, K rows)
    for i in 0..k {
        let row = (NUM_CATEGORIES + 4) * k - 2 + i;
        let col = 1 + i * STEP_VARS + OFF_CARRY;
        matrices[M_E_CARRY].add_entry(row, col, Fr::one())?;
    }

    // --- 93 subsets + coefficients ---
    let neg_two_pow_32 = Fr::zero().sub(&Fr::from_u64(1u64 << 32));
    let mut subsets: Vec<Vec<usize>> = Vec::with_capacity(93);
    let mut coeffs: Vec<Fr> = Vec::with_capacity(93);
    // Group A: {0}→1, {1}→1, {2}→1
    subsets.push(vec![M_A_NEXT]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_A_CUR]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_CONST_A]);
    coeffs.push(Fr::one());
    // Group B: {3}→1, {4}→1
    subsets.push(vec![M_B_NEXT]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_B_CUR]);
    coeffs.push(Fr::one());
    // Group C: {5+j}→1 for j=0..33, {39}→-1
    for j in 0..NUM_CATEGORIES {
        subsets.push(vec![M_C_BASE + j]);
        coeffs.push(Fr::one());
    }
    subsets.push(vec![M_CONST_C]);
    coeffs.push(neg_one);
    // Group D: {40,40}→1, {41}→-1
    subsets.push(vec![M_D_SQ, M_D_SQ]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_D_LIN]);
    coeffs.push(neg_one);
    // Group E: 25 arithmetic subsets (selector-gated degree-2)
    // LUI (cat=0): sel_0 * (rd - imm) = 0
    subsets.push(vec![M_C_BASE, M_E_RD]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE, M_E_IMM]);
    coeffs.push(neg_one);
    // AUIPC (cat=1): sel_1 * (rd - pc - imm) = 0
    subsets.push(vec![M_C_BASE + 1, M_E_RD]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 1, M_E_PC]);
    coeffs.push(neg_one);
    subsets.push(vec![M_C_BASE + 1, M_E_IMM]);
    coeffs.push(neg_one);
    // ADDI (cat=12): sel_12 * (rs1 + imm - rd - 2^32*carry) = 0
    subsets.push(vec![M_C_BASE + 12, M_E_RS1]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 12, M_E_IMM]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 12, M_E_RD]);
    coeffs.push(neg_one);
    subsets.push(vec![M_C_BASE + 12, M_E_CARRY]);
    coeffs.push(neg_two_pow_32);
    // SLTI (cat=13): sel_13 * (rd - carry) = 0
    subsets.push(vec![M_C_BASE + 13, M_E_RD]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 13, M_E_CARRY]);
    coeffs.push(neg_one);
    // SLTIU (cat=14): sel_14 * (rd - carry) = 0
    subsets.push(vec![M_C_BASE + 14, M_E_RD]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 14, M_E_CARRY]);
    coeffs.push(neg_one);
    // ADD (cat=21): sel_21 * (rs1 + rs2 - rd - 2^32*carry) = 0
    subsets.push(vec![M_C_BASE + 21, M_E_RS1]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 21, M_E_RS2]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 21, M_E_RD]);
    coeffs.push(neg_one);
    subsets.push(vec![M_C_BASE + 21, M_E_CARRY]);
    coeffs.push(neg_two_pow_32);
    // SUB (cat=22): sel_22 * (rd - rs1 + rs2 - 2^32*carry) = 0
    subsets.push(vec![M_C_BASE + 22, M_E_RD]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 22, M_E_RS1]);
    coeffs.push(neg_one);
    subsets.push(vec![M_C_BASE + 22, M_E_RS2]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 22, M_E_CARRY]);
    coeffs.push(neg_two_pow_32);
    // SLT (cat=24): sel_24 * (rd - carry) = 0
    subsets.push(vec![M_C_BASE + 24, M_E_RD]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 24, M_E_CARRY]);
    coeffs.push(neg_one);
    // SLTU (cat=25): sel_25 * (rd - carry) = 0
    subsets.push(vec![M_C_BASE + 25, M_E_RD]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + 25, M_E_CARRY]);
    coeffs.push(neg_one);
    // Phase 2c: 逻辑 + 移位指令约束（12 类 × 2 subset = 24）
    // 模式：sel_cat × (rd - aux) = 0
    // XORI(15), ORI(16), ANDI(17), SLLI(18), SRLI(19), SRAI(20),
    // SLL(23), XOR(26), SRL(27), SRA(28), OR(29), AND(30)
    for &cat in &[15, 16, 17, 18, 19, 20, 23, 26, 27, 28, 29, 30] {
        subsets.push(vec![M_C_BASE + cat, M_E_RD]);
        coeffs.push(Fr::one());
        subsets.push(vec![M_C_BASE + cat, M_E_AUX]);
        coeffs.push(neg_one);
    }
    // Group F: carry² - carry = 0
    subsets.push(vec![M_E_CARRY, M_E_CARRY]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_E_CARRY]);
    coeffs.push(neg_one);

    let ccs = Ccs::new(padded_num_vars, matrices, subsets, coeffs)?;

    // public_inputs: [batch_id, first_idx, last_idx]
    let first_idx = steps
        .first()
        .ok_or_else(|| ZkvmError::Other("batch 为空".to_string()))?
        .step_index;
    let last_idx = steps
        .last()
        .ok_or_else(|| ZkvmError::Other("batch 为空".to_string()))?
        .step_index;
    let public_inputs = vec![
        Fr::from_u64(batch_id),
        Fr::from_u64(first_idx),
        Fr::from_u64(last_idx),
    ];

    CcsInstance::new(ccs, witness, public_inputs)
}

/// 校验 batch 间连续性（前一 batch 末步 idx + 1 == 后一 batch 首步 idx）。
///
/// 每组 public_inputs 格式为 `[batch_id, first_idx, last_idx]`。
/// 校验：对相邻两组，`prev.last_idx + 1 == next.first_idx`。
///
/// 此函数由 verifier 在 fold 验证后调用，确保 batch 序列连续无间断。
pub fn verify_batch_continuity(public_inputs: &[Vec<Fr>]) -> bool {
    for w in public_inputs.windows(2) {
        let prev_last = &w[0];
        let next_first = &w[1];
        // public_inputs: [batch_id, first_idx, last_idx]
        if prev_last.len() < 3 || next_first.len() < 3 {
            return false;
        }
        // prev.last_idx + 1 == next.first_idx
        let expected_next = prev_last[2].add(&Fr::one());
        if expected_next != next_first[1] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Instruction;
    use crate::trace::{MemAccess, MemOp, Step};

    /// 构造测试用 Step（step_index 可控，其余默认）。
    fn make_step(step_index: u64) -> Step {
        Step {
            step_index,
            pc: (step_index * 4) as u32,
            instruction: Instruction::Ecall,
            registers: [0u32; 32],
            mem_access: vec![],
        }
    }

    /// 构造测试用 Trace（n 步，step_index = 0..n-1）。
    fn make_trace(n: usize) -> Trace {
        let mut trace = Trace::new();
        for i in 0..n {
            trace.push_step(make_step(i as u64));
        }
        trace
    }

    #[test]
    fn test_compile_trace_empty_trace_errors() {
        let trace = Trace::new();
        let err = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("为空")));
    }

    #[test]
    fn test_compile_trace_zero_batch_size_errors() {
        let trace = make_trace(10);
        let err = compile_trace_to_ccs(&trace, 0).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("batch_size")));
    }

    #[test]
    fn test_compile_trace_single_batch() {
        let trace = make_trace(5);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 1);

        let inst = &instances[0];
        // num_vars = 1 + 5*46 = 231 → padding 到 256
        assert_eq!(inst.ccs.num_vars, 256);
        // num_rows = 39*5 - 2 = 193 → padding 到 256
        assert_eq!(inst.ccs.num_rows(), 256);
        // NUM_CCS_MATRICES 个矩阵
        assert_eq!(inst.ccs.num_matrices(), NUM_CCS_MATRICES);
        // witness 满足约束（padding 列为 0，dummy 约束 vacuously true）
        assert!(inst.is_satisfied().expect("应满足"));
        // public_inputs: [batch_id=0, first_idx=0, last_idx=4]
        assert_eq!(inst.public_inputs.len(), 3);
    }

    #[test]
    fn test_compile_trace_multiple_batches() {
        let trace = make_trace(25);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 3); // ⌈25/10⌉ = 3

        // batch 0: steps 0-9
        assert_eq!(instances[0].public_inputs[1], Fr::from_u64(0)); // first_idx
        assert_eq!(instances[0].public_inputs[2], Fr::from_u64(9)); // last_idx

        // batch 1: steps 10-19
        assert_eq!(instances[1].public_inputs[1], Fr::from_u64(10));
        assert_eq!(instances[1].public_inputs[2], Fr::from_u64(19));

        // batch 2: steps 20-24（部分 batch）
        assert_eq!(instances[2].public_inputs[1], Fr::from_u64(20));
        assert_eq!(instances[2].public_inputs[2], Fr::from_u64(24));

        // 全部满足约束
        for inst in &instances {
            assert!(inst.is_satisfied().expect("应满足"));
        }
    }

    #[test]
    fn test_compile_trace_default_batch_size() {
        let trace = make_trace(ZKVM_BATCH_SIZE + 1);
        let instances = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE).expect("应成功");
        assert_eq!(instances.len(), 2);
    }

    #[test]
    fn test_compile_trace_exceeds_fold_step_count() {
        // 构造 trace 使 num_batches > MAX_FOLD_STEP_COUNT
        // batch_size=1 → num_batches = num_steps
        let n = MAX_FOLD_STEP_COUNT + 1;
        let trace = make_trace(n);
        let err = compile_trace_to_ccs(&trace, 1).unwrap_err();
        assert!(matches!(
            err,
            ZkvmError::FoldStepCountExceeded {
                actual,
                limit
            } if actual as usize == n && limit as usize == MAX_FOLD_STEP_COUNT
        ));
    }

    #[test]
    fn test_compile_trace_at_fold_step_limit() {
        // 恰好等于上限应成功
        let trace = make_trace(MAX_FOLD_STEP_COUNT);
        let instances = compile_trace_to_ccs(&trace, 1).expect("应成功");
        assert_eq!(instances.len(), MAX_FOLD_STEP_COUNT);
    }

    #[test]
    fn test_batch_continuity_constraint_satisfied() {
        // step_index 连续递增的 trace 应满足约束
        let trace = make_trace(10);
        let instances = compile_trace_to_ccs(&trace, 5).expect("应成功");
        assert_eq!(instances.len(), 2);

        // batch 0: steps 0-4
        assert!(instances[0].is_satisfied().expect("batch 0 应满足"));
        // batch 1: steps 5-9
        assert!(instances[1].is_satisfied().expect("batch 1 应满足"));

        // batch 间连续性：batch 0 last_idx(4) + 1 == batch 1 first_idx(5)
        let public_inputs: Vec<Vec<Fr>> = instances.iter().map(|i| i.public_inputs.clone()).collect();
        assert!(verify_batch_continuity(&public_inputs));
    }

    #[test]
    fn test_continuity_constraint_violated_by_gap() {
        // 构造 step_index 不连续的 trace（手动构造非连续 step_index）
        let mut trace = Trace::new();
        trace.push_step(make_step(0));
        trace.push_step(make_step(5)); // 跳跃！idx 0 → 5，差 5 不是 1
        trace.push_step(make_step(6));

        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 1);

        // 约束应不满足（idx_1 - idx_0 - 1 = 5 - 0 - 1 = 4 ≠ 0）
        let inst = &instances[0];
        assert!(!inst.is_satisfied().expect("应返回 false"));
    }

    #[test]
    fn test_batch_continuity_between_batches_violated() {
        // 构造 trace 使 batch 间不连续（通过手动修改 step_index）
        let mut trace = Trace::new();
        // batch 0 (batch_size=5): steps 0-4
        for i in 0..5 {
            trace.push_step(make_step(i));
        }
        // batch 1: steps 100-104（与 batch 0 末步 4 不连续）
        for i in 0..5 {
            trace.push_step(make_step(100 + i));
        }

        let instances = compile_trace_to_ccs(&trace, 5).expect("应成功");
        assert_eq!(instances.len(), 2);

        // batch 内部约束各自满足
        assert!(instances[0].is_satisfied().expect("batch 0 应满足"));
        assert!(instances[1].is_satisfied().expect("batch 1 应满足"));

        // batch 间连续性应失败：batch 0 last_idx(4) + 1 = 5 ≠ batch 1 first_idx(100)
        let public_inputs: Vec<Vec<Fr>> = instances.iter().map(|i| i.public_inputs.clone()).collect();
        assert!(!verify_batch_continuity(&public_inputs));
    }

    #[test]
    fn test_single_step_batch_no_continuity_constraint() {
        // 单步 batch（K=1）：Group A/B 各 0 行，Group C 1 行，Group D 34 行
        let trace = make_trace(1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 1);

        let inst = &instances[0];
        // num_vars = 1 + 1*46 = 47 → padding 到 64
        assert_eq!(inst.ccs.num_vars, 64);
        // num_rows = 39*1 - 2 = 37 → padding 到 64
        assert_eq!(inst.ccs.num_rows(), 64);
        // 仍然满足（selector one-hot + binary + padding dummy 约束 vacuously true）
        assert!(inst.is_satisfied().expect("应满足"));
    }

    #[test]
    fn test_witness_layout() {
        // 验证 witness 布局：z = [1, w_0, w_1, w_2, padding]
        // 每步 STEP_VARS 变量，步 i 的 idx 位于 z[1 + i*STEP_VARS + OFF_IDX]
        let trace = make_trace(3);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        let inst = &instances[0];

        // z[0] = 1（常数）
        assert_eq!(inst.witness[0], Fr::one());
        // 步 0 的 idx = 0
        assert_eq!(inst.witness[1 + 0 * STEP_VARS + OFF_IDX], Fr::from_u64(0));
        // 步 1 的 idx = 1
        assert_eq!(inst.witness[1 + 1 * STEP_VARS + OFF_IDX], Fr::from_u64(1));
        // 步 2 的 idx = 2
        assert_eq!(inst.witness[1 + 2 * STEP_VARS + OFF_IDX], Fr::from_u64(2));
    }

    #[test]
    fn test_public_inputs_contain_batch_metadata() {
        let trace = make_trace(10);
        let instances = compile_trace_to_ccs(&trace, 4).expect("应成功");
        assert_eq!(instances.len(), 3); // ⌈10/4⌉ = 3

        // batch 0: [batch_id=0, first_idx=0, last_idx=3]
        assert_eq!(instances[0].public_inputs[0], Fr::from_u64(0)); // batch_id
        assert_eq!(instances[0].public_inputs[1], Fr::from_u64(0)); // first_idx
        assert_eq!(instances[0].public_inputs[2], Fr::from_u64(3)); // last_idx

        // batch 1: [batch_id=1, first_idx=4, last_idx=7]
        assert_eq!(instances[1].public_inputs[0], Fr::from_u64(1));
        assert_eq!(instances[1].public_inputs[1], Fr::from_u64(4));
        assert_eq!(instances[1].public_inputs[2], Fr::from_u64(7));

        // batch 2: [batch_id=2, first_idx=8, last_idx=9]
        assert_eq!(instances[2].public_inputs[0], Fr::from_u64(2));
        assert_eq!(instances[2].public_inputs[1], Fr::from_u64(8));
        assert_eq!(instances[2].public_inputs[2], Fr::from_u64(9));
    }

    #[test]
    fn test_batch_with_memory_access_steps() {
        // 含内存访问的 step 也应正确编译（MVP 不约束内存，仅约束 step_index 连续性）
        let mut trace = Trace::new();
        for i in 0..5 {
            let mut step = make_step(i);
            step.mem_access.push(MemAccess {
                addr: 0x100 + i as u32,
                op: MemOp::Write,
                value: i as u32,
                size: 4,
            });
            trace.push_step(step);
        }

        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 1);
        assert!(instances[0].is_satisfied().expect("应满足"));
    }

    #[test]
    fn test_large_batch_default_size() {
        // 测试默认 batch_size=1024 的边界
        let trace = make_trace(ZKVM_BATCH_SIZE);
        let instances = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE).expect("应成功");
        assert_eq!(instances.len(), 1);
        // num_vars = 1 + 1024*46 = 47105 → padding 到 65536
        assert_eq!(instances[0].ccs.num_vars, 65536);
        // num_rows = 39*1024 - 2 = 39934 → padding 到 65536
        assert_eq!(instances[0].ccs.num_rows(), 65536);
        assert!(instances[0].is_satisfied().expect("应满足"));
    }

    #[test]
    fn test_padding_power_of_two_invariant() {
        // 验证 padding 后 num_vars 和 num_rows 均为 2 的幂
        for k in [1usize, 2, 3, 5, 7, 10, 100, 255, 256, 257, 1023, 1024] {
            let trace = make_trace(k);
            let instances = compile_trace_to_ccs(&trace, k.max(1)).expect("应成功");
            let inst = &instances[0];
            assert!(
                inst.ccs.num_vars.is_power_of_two(),
                "k={k}: num_vars={} 应为 2 的幂",
                inst.ccs.num_vars
            );
            assert!(
                inst.ccs.num_rows().is_power_of_two(),
                "k={k}: num_rows={} 应为 2 的幂",
                inst.ccs.num_rows()
            );
            assert!(
                inst.ccs.num_vars >= 2,
                "k={k}: num_vars 应 >= 2",
            );
            assert!(
                inst.ccs.num_rows() >= 1,
                "k={k}: num_rows 应 >= 1",
            );
            assert!(inst.is_satisfied().expect("应满足"));
        }
    }

    #[test]
    fn test_padding_witness_zero_filled() {
        // 验证 padding 后 witness 尾部为 0
        // k=5, num_vars = 1 + 5*46 = 231, padded to 256
        let trace = make_trace(5);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        let inst = &instances[0];
        assert_eq!(inst.ccs.num_vars, 256);
        assert_eq!(inst.witness.len(), 256);
        // z[0] = 1, z[1..231] = step witnesses, z[231..256] = 0 (padding)
        assert_eq!(inst.witness[0], Fr::one());
        assert_eq!(inst.witness[231], Fr::zero());
        assert_eq!(inst.witness[255], Fr::zero());
    }

    #[test]
    fn test_compile_trace_returns_correct_instance_count() {
        // 边界测试：N % K == 0
        let trace = make_trace(20);
        let instances = compile_trace_to_ccs(&trace, 5).expect("应成功");
        assert_eq!(instances.len(), 4);

        // N % K != 0
        let trace = make_trace(22);
        let instances = compile_trace_to_ccs(&trace, 5).expect("应成功");
        assert_eq!(instances.len(), 5); // ⌈22/5⌉ = 5
    }

    #[test]
    fn test_batch_id_monotonic() {
        let trace = make_trace(30);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert_eq!(instances.len(), 3);

        for (i, inst) in instances.iter().enumerate() {
            assert_eq!(inst.public_inputs[0], Fr::from_u64(i as u64));
        }
    }

    // ===== Phase 5 集成测试 =====

    #[test]
    fn test_phase5_integration_all_subcircuits_satisfied() {
        // 验证所有 Phase 5 子电路的 CCS 实例可独立构造且满足约束
        use crate::constraints::algebra::{AddCircuit, AndCircuit, SubCircuit};
        use crate::constraints::control_flow::{JalCircuit, LuiCircuit};
        use crate::constraints::lookup::LogUpProof;
        use crate::constraints::syscall_circuit::SyscallAbiCircuit;
        use crate::field::ZkvmField;

        // 算术子电路（associated function 调用，u32 参数）
        let add_witness = AddCircuit::assign_witness(100, 200);
        assert!(
            AddCircuit::build_ccs()
                .satisfied_by(&add_witness)
                .expect("Add CCS")
        );

        let sub_witness = SubCircuit::assign_witness(300, 100);
        assert!(
            SubCircuit::build_ccs()
                .satisfied_by(&sub_witness)
                .expect("Sub CCS")
        );

        let and_witness = AndCircuit::assign_witness(0b1010, 0b1100);
        assert!(
            AndCircuit::build_ccs()
                .satisfied_by(&and_witness)
                .expect("And CCS")
        );

        // 控制流子电路（associated function 调用）
        let jal_witness = JalCircuit::assign_witness(0x1000, 0x20);
        assert!(
            JalCircuit::build_ccs()
                .satisfied_by(&jal_witness)
                .expect("Jal CCS")
        );

        let lui_witness = LuiCircuit::assign_witness(0xABCDE);
        assert!(
            LuiCircuit::build_ccs()
                .satisfied_by(&lui_witness)
                .expect("Lui CCS")
        );

        // Syscall 子电路（实例方法，u32 参数）
        let syscall_abi = SyscallAbiCircuit::new(crate::syscalls::SyscallId::Poseidon);
        let abi_witness = syscall_abi.assign_witness(0x03);
        assert!(
            SyscallAbiCircuit::build_ccs()
                .satisfied_by(&abi_witness)
                .expect("SyscallAbi CCS")
        );

        // LogUp lookup 子电路
        let table = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
        let witness = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
        let multiplicity = vec![Fr::one(), Fr::one()];
        let (proof, commits) =
            LogUpProof::create(table, witness, multiplicity).expect("LogUp create");
        assert!(proof.verify(&commits).expect("LogUp verify"));
        let logup_instance = proof.to_ccs_instance().expect("LogUp CCS instance");
        assert!(logup_instance.is_satisfied().expect("LogUp is_satisfied"));
    }

    #[test]
    fn test_phase5_integration_memory_byte_expansion() {
        // 内存子电路：byte-level permutation 展开
        use crate::constraints::memory::expand_to_bytes;
        use crate::trace::{MemAccess, MemOp};

        // LW 4 字节写
        let lw_access = MemAccess {
            addr: 0x1000,
            op: MemOp::Write,
            value: 0xDEADBEEF,
            size: 4,
        };
        let bytes = expand_to_bytes(&lw_access, 42).expect("expand_to_bytes");
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0].byte_addr, 0x1000);
        assert_eq!(bytes[0].byte_val, 0xEF); // little-endian
        assert_eq!(bytes[1].byte_val, 0xBE);
        assert_eq!(bytes[2].byte_val, 0xAD);
        assert_eq!(bytes[3].byte_val, 0xDE);
        assert_eq!(bytes[0].step_index, 42);

        // LB 1 字节读
        let lb_access = MemAccess {
            addr: 0x1000,
            op: MemOp::Read,
            value: 0xEF,
            size: 1,
        };
        let bytes = expand_to_bytes(&lb_access, 43).expect("expand_to_bytes");
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0].byte_val, 0xEF);
    }

    #[test]
    fn test_phase5_integration_memory_uninitialized_read_detection() {
        // 内存子电路：未初始化读取检测
        use crate::constraints::memory::{check_uninitialized_read, ByteAccess};

        // write 在 step 10，read 在 step 20 → 合法
        let writes = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 42,
            step_index: 10,
        }];
        let reads = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 42,
            step_index: 20,
        }];
        assert!(
            check_uninitialized_read(&reads, &writes).is_ok(),
            "read-after-write 应合法"
        );

        // read 在 step 5，write 在 step 10 → 未初始化读取
        let reads_early = vec![ByteAccess {
            byte_addr: 0x100,
            byte_val: 42,
            step_index: 5,
        }];
        assert!(
            check_uninitialized_read(&reads_early, &writes).is_err(),
            "write-before-read 应检测为未初始化读取"
        );
    }

    #[test]
    fn test_phase5_integration_logup_with_u8_range() {
        // 端到端：u8 range table + 多个 witness 值
        use crate::constraints::lookup::{compute_multiplicity, LogUpProof, LookupTable};
        use crate::field::ZkvmField;

        let table = LookupTable::u8_range();
        let witness: Vec<Fr> = [0, 1, 127, 128, 255, 42, 42, 100]
            .iter()
            .map(|v| Fr::from_u32_with_wrap(*v))
            .collect();
        let multiplicity = compute_multiplicity(&table, &witness);

        // 验证 multiplicity 正确性
        assert_eq!(multiplicity[0], Fr::one(), "0 出现 1 次");
        assert_eq!(multiplicity[1], Fr::one(), "1 出现 1 次");
        assert_eq!(multiplicity[42], Fr::from_u32_with_wrap(2), "42 出现 2 次");

        let (proof, commits) =
            LogUpProof::create(table.entries, witness, multiplicity).expect("LogUp create");
        assert!(proof.verify(&commits).expect("LogUp verify 应通过"));
    }

    #[test]
    fn test_phase5_integration_logup_with_truth_tables() {
        // 端到端：AND/OR/XOR 真值表 lookup
        use crate::constraints::lookup::{compute_multiplicity, LogUpProof, LookupTable};

        for table in [
            LookupTable::and_truth_table(),
            LookupTable::or_truth_table(),
            LookupTable::xor_truth_table(),
        ] {
            // witness = 所有表项（每个引用 1 次）
            let witness = table.entries.clone();
            let multiplicity = compute_multiplicity(&table, &witness);

            let (proof, commits) =
                LogUpProof::create(table.entries, witness, multiplicity).expect("LogUp create");
            assert!(
                proof.verify(&commits).expect("LogUp verify"),
                "真值表 lookup 应通过"
            );
        }
    }

    #[test]
    fn test_phase5_integration_compile_trace_with_ecall() {
        // 集成测试：compile_trace_to_ccs 处理含 ECALL 指令的 trace
        let trace = make_trace(10);
        let instances = compile_trace_to_ccs(&trace, ZKVM_BATCH_SIZE).expect("应成功");
        assert_eq!(instances.len(), 1, "10 步 / 1024 batch = 1 实例");
        // 每个 instance 的 witness 应非空
        assert!(!instances[0].witness.is_empty());
        // 每个 instance 应满足 CCS 约束
        assert!(
            instances[0].is_satisfied().expect("is_satisfied"),
            "batch CCS 实例应满足约束"
        );
    }

    #[test]
    fn test_phase5_integration_multiple_batches_continuity() {
        // 集成测试：多 batch 连续性 — batch_id 单调递增
        let trace = make_trace(2500);
        let instances = compile_trace_to_ccs(&trace, 1024).expect("应成功");
        assert_eq!(instances.len(), 3, "2500 步 / 1024 = 3 batches");

        // batch_id 单调递增
        for (i, inst) in instances.iter().enumerate() {
            assert_eq!(inst.public_inputs[0], Fr::from_u64(i as u64));
        }

        // 所有 batch 的 CCS 实例应满足约束
        for inst in &instances {
            assert!(inst.is_satisfied().expect("is_satisfied"));
        }
    }

    #[test]
    fn test_phase5_integration_logup_ccs_foldable() {
        // 验证 LogUp 的 CCS 实例结构可被 Hypernova 折叠
        // （num_vars / num_matrices / num_rows 合理）
        use crate::constraints::lookup::LogUpProof;
        use crate::field::ZkvmField;

        let table = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
        let witness = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
        let multiplicity = vec![Fr::one(), Fr::one()];

        let (proof, _) = LogUpProof::create(table, witness, multiplicity).expect("create");
        let instance = proof.to_ccs_instance().expect("to_ccs_instance");

        // CCS 结构合理性
        assert!(instance.ccs.num_vars >= 3, "num_vars 应 >= 3");
        assert!(instance.ccs.num_matrices() >= 2, "num_matrices 应 >= 2");
        assert!(instance.ccs.num_constraints() >= 2, "num_constraints 应 >= 2");
        assert!(instance.ccs.num_rows() >= 1, "num_rows 应 >= 1");

        // witness 长度 = num_vars
        assert_eq!(instance.witness.len(), instance.ccs.num_vars);

        // CCS 满足
        assert!(instance.is_satisfied().expect("is_satisfied"));
    }

    // ===== Stage 2 Phase 2a 测试 =====

    #[test]
    fn test_49_matrix_ccs_structure() {
        // 验证 CCS 结构：NUM_CCS_MATRICES 矩阵、subset 布局
        let trace = make_trace(3);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        let inst = &instances[0];

        assert_eq!(inst.ccs.num_matrices(), NUM_CCS_MATRICES, "矩阵数应匹配");
        // subset 数 = 3(A)+2(B)+NUM_CATEGORIES(C)+1(const_C)+2(D)+25(E_arith)+24(Phase2c)+2(F)
        let expected_subsets = 3 + 2 + NUM_CATEGORIES + 1 + 2 + 25 + 24 + 2;
        assert_eq!(
            inst.ccs.num_constraints(),
            expected_subsets,
            "subset 数应匹配"
        );

        // Group D 的 sel² 子集索引 = 3(A)+2(B)+NUM_CATEGORIES(C)+1(const_C)
        let idx_d_sq = 3 + 2 + NUM_CATEGORIES + 1;
        let subset_d_sq = &inst.ccs.subsets[idx_d_sq];
        assert_eq!(
            subset_d_sq,
            &vec![M_D_SQ, M_D_SQ],
            "Group D square subset 应为 [M_D_SQ, M_D_SQ]"
        );

        // Group E LUI 第一个 subset 索引 = idx_d_sq + 2(D)
        let idx_e_lui = idx_d_sq + 2;
        let subset_e_lui = &inst.ccs.subsets[idx_e_lui];
        assert_eq!(
            subset_e_lui,
            &vec![M_C_BASE, M_E_RD],
            "Group E LUI subset 应为 [M_C_BASE, M_E_RD]"
        );

        // Phase 2c XORI 第一个 subset 索引 = idx_e_lui + 25(E_arith)
        let idx_p2c_xori = idx_e_lui + 25;
        let subset_p2c_xori = &inst.ccs.subsets[idx_p2c_xori];
        assert_eq!(
            subset_p2c_xori,
            &vec![M_C_BASE + 15, M_E_RD],
            "Phase 2c XORI subset 应为 [M_C_BASE+15, M_E_RD]"
        );

        // Group F carry² 子集索引 = idx_p2c_xori + 24(Phase 2c)
        let idx_f_sq = idx_p2c_xori + 24;
        let subset_f_sq = &inst.ccs.subsets[idx_f_sq];
        assert_eq!(
            subset_f_sq,
            &vec![M_E_CARRY, M_E_CARRY],
            "Group F carry² subset 应为 [M_E_CARRY, M_E_CARRY]"
        );
    }

    #[test]
    fn test_group_a_step_index_continuity() {
        // step_index 连续 → Group A 满足
        let trace = make_trace(5); // step_index = 0,1,2,3,4
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(
            instances[0].is_satisfied().expect("连续 step_index 应满足")
        );

        // step_index 跳跃 → Group A 不满足
        let mut trace_gap = Trace::new();
        trace_gap.push_step(make_step(0));
        trace_gap.push_step(make_step(5)); // 跳跃：0 → 5
        trace_gap.push_step(make_step(6));

        let instances_gap = compile_trace_to_ccs(&trace_gap, 10).expect("应成功");
        assert!(
            !instances_gap[0].is_satisfied().expect("跳跃 step_index 应不满足"),
            "Group A 应检测到 step_index 不连续"
        );
    }

    #[test]
    fn test_group_b_pc_continuity() {
        // pc 连续（pc = step_index * 4，ECALL → next_pc = pc + 4）→ Group B 满足
        let trace = make_trace(5);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("连续 PC 应满足"));

        // pc 跳跃 → Group B 不满足
        let mut trace_pc_gap = Trace::new();
        trace_pc_gap.push_step(make_step(0)); // pc=0
        let mut bad_step = make_step(1);
        bad_step.pc = 100; // 错误 PC：0+4≠100
        trace_pc_gap.push_step(bad_step);
        trace_pc_gap.push_step(make_step(2));

        let instances_gap = compile_trace_to_ccs(&trace_pc_gap, 10).expect("应成功");
        assert!(
            !instances_gap[0].is_satisfied().expect("跳跃 PC 应不满足"),
            "Group B 应检测到 PC 不连续"
        );
    }

    #[test]
    fn test_group_c_selector_one_hot() {
        // ECALL 步的 selector one-hot：sel_{Ecall}=1，其余=0
        let trace = make_trace(2); // 每步都是 ECALL
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        let inst = &instances[0];

        let ecall_cat = instruction_category(&Instruction::Ecall);
        let sel_start_0 = 1 + OFF_SEL_START;
        for j in 0..NUM_CATEGORIES {
            let val = inst.witness[sel_start_0 + j];
            if j == ecall_cat {
                assert_eq!(val, Fr::one(), "ECALL selector (idx {ecall_cat}) 应为 1");
            } else {
                assert_eq!(val, Fr::zero(), "非 ECALL selector (idx {j}) 应为 0");
            }
        }

        // Group C 约束满足（Σ sel = 1）
        assert!(inst.is_satisfied().expect("one-hot selector 应满足"));
    }

    #[test]
    fn test_group_d_selector_binary() {
        // 验证所有 selector 为 0 或 1（满足 sel² - sel = 0）
        let trace = make_trace(3);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        let inst = &instances[0];

        // 检查每步的每个 selector 是 0 或 1
        for i in 0..3 {
            let sel_start = 1 + i * STEP_VARS + OFF_SEL_START;
            for j in 0..NUM_CATEGORIES {
                let val = inst.witness[sel_start + j];
                assert!(
                    val == Fr::zero() || val == Fr::one(),
                    "步 {i} selector {j} 应为 0 或 1，实际 {:?}",
                    val
                );
            }
        }

        // Group D 约束满足
        assert!(inst.is_satisfied().expect("binary selector 应满足"));
    }

    #[test]
    fn test_compile_step_witness_layout() {
        // 验证 compile_step_witness 返回 46 个变量，布局正确
        let step = make_step(5);
        let witness = compile_step_witness(&step, None, None);

        assert_eq!(witness.len(), STEP_VARS, "witness 长度应为 46");

        // idx = step_index = 5
        assert_eq!(witness[OFF_IDX], Fr::from_u64(5));
        // pc = 5 * 4 = 20
        assert_eq!(witness[OFF_PC], Fr::from_u32_with_wrap(20));
        // next_pc = pc + 4 = 24（ECALL 非分支）
        assert_eq!(witness[OFF_NEXT_PC], Fr::from_u32_with_wrap(24));
        // rs1_val = 0（无 prev_step）
        assert_eq!(witness[OFF_RS1_VAL], Fr::zero());
        // rs2_val = 0
        assert_eq!(witness[OFF_RS2_VAL], Fr::zero());
        // taken = 0（ECALL 非分支）
        assert_eq!(witness[OFF_TAKEN], Fr::zero());
        // ECALL selector = 1
        let ecall_cat = instruction_category(&Instruction::Ecall);
        assert_eq!(witness[OFF_SEL_START + ecall_cat], Fr::one());
        // 其余 selector = 0
        assert_eq!(witness[OFF_SEL_START], Fr::zero());
    }

    #[test]
    fn test_instruction_category_coverage() {
        // 验证所有 40 个 Instruction 变体映射到有效 category 0..33
        let insns: Vec<Instruction> = vec![
            Instruction::Lui { rd: 1, imm: 0x1000 },
            Instruction::Auipc { rd: 1, imm: 0x1000 },
            Instruction::Jal { rd: 1, imm: 0x100 },
            Instruction::Jalr { rd: 1, rs1: 2, imm: 0 },
            Instruction::Beq { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Bne { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Blt { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Bge { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Bltu { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Bgeu { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Lb { rd: 1, rs1: 2, imm: 0 },
            Instruction::Lh { rd: 1, rs1: 2, imm: 0 },
            Instruction::Lw { rd: 1, rs1: 2, imm: 0 },
            Instruction::Lbu { rd: 1, rs1: 2, imm: 0 },
            Instruction::Lhu { rd: 1, rs1: 2, imm: 0 },
            Instruction::Sb { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Sh { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Sw { rs1: 1, rs2: 2, imm: 0 },
            Instruction::Addi { rd: 1, rs1: 2, imm: 0 },
            Instruction::Slti { rd: 1, rs1: 2, imm: 0 },
            Instruction::Sltiu { rd: 1, rs1: 2, imm: 0 },
            Instruction::Xori { rd: 1, rs1: 2, imm: 0 },
            Instruction::Ori { rd: 1, rs1: 2, imm: 0 },
            Instruction::Andi { rd: 1, rs1: 2, imm: 0 },
            Instruction::Slli { rd: 1, rs1: 2, shamt: 1 },
            Instruction::Srli { rd: 1, rs1: 2, shamt: 1 },
            Instruction::Srai { rd: 1, rs1: 2, shamt: 1 },
            Instruction::Add { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Sub { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Sll { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Slt { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Sltu { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Xor { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Srl { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Sra { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Or { rd: 1, rs1: 2, rs2: 3 },
            Instruction::And { rd: 1, rs1: 2, rs2: 3 },
            Instruction::Fence,
            Instruction::Ecall,
            Instruction::Ebreak,
        ];

        assert_eq!(insns.len(), 40, "应有 40 个 Instruction 变体");

        for insn in &insns {
            let cat = instruction_category(insn);
            assert!(
                cat < NUM_CATEGORIES,
                "category {cat} >= NUM_CATEGORIES {NUM_CATEGORIES}"
            );
        }

        // 验证 assign_selectors 返回的 one-hot 数组恰好有一个 1
        for insn in &insns {
            let sels = assign_selectors(insn);
            let sum: usize = sels
                .iter()
                .map(|s| if *s == Fr::one() { 1 } else { 0 })
                .sum();
            assert_eq!(sum, 1, "每条指令应恰好激活 1 个 selector");
        }
    }

    // ===== Stage 2 Phase 2b 测试 =====

    /// 构造测试用 Step（指定指令和寄存器状态）。
    fn make_step_with_insn(
        step_index: u64,
        instruction: Instruction,
        registers: [u32; 32],
    ) -> Step {
        Step {
            step_index,
            pc: (step_index * 4) as u32,
            instruction,
            registers,
            mem_access: vec![],
        }
    }

    /// 构造 ECALL 步并设置寄存器（用于算术指令的 prev_step）。
    fn make_ecall_step_with_regs(step_index: u64, registers: [u32; 32]) -> Step {
        make_step_with_insn(step_index, Instruction::Ecall, registers)
    }

    #[test]
    fn test_group_e_add_constraint() {
        // K=2: 步 0 ECALL 设 regs[2]=100, regs[3]=200; 步 1 ADD {rd:1,rs1:2,rs2:3} regs[1]=300
        let mut regs0 = [0u32; 32];
        regs0[2] = 100;
        regs0[3] = 200;
        let mut regs1 = [0u32; 32];
        regs1[1] = 300;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Add { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 ADD 应满足"));

        // 篡改 rd_val → 约束失败
        let mut inst = instances[0].clone();
        let rd_col = 1 + STEP_VARS + OFF_RD_VAL;
        inst.witness[rd_col] = Fr::from_u32_with_wrap(301);
        assert!(
            !inst.is_satisfied().expect("篡改 rd 应不满足"),
            "Group E 应检测到 ADD rd 错误"
        );
    }

    #[test]
    fn test_group_e_add_overflow_constraint() {
        // K=2: 步 0 设 regs[2]=0xFFFFFFFF, regs[3]=1; 步 1 ADD regs[1]=0（wrapping）
        let mut regs0 = [0u32; 32];
        regs0[2] = 0xFFFFFFFF;
        regs0[3] = 1;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Add { rd: 1, rs1: 2, rs2: 3 }, [0u32; 32]);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        // carry=1, rs1+rs2-rd-2^32*carry = 0xFFFFFFFF+1-0-2^32 = 0
        assert!(instances[0].is_satisfied().expect("ADD overflow 应满足"));
    }

    #[test]
    fn test_group_e_sub_constraint() {
        // K=2: 步 0 设 regs[2]=100, regs[3]=200; 步 1 SUB {rd:1,rs1:2,rs2:3} regs[1]=0xFFFFFF9C
        let mut regs0 = [0u32; 32];
        regs0[2] = 100;
        regs0[3] = 200;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0xFFFFFF9C; // 100 - 200 wrapping
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Sub { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        // carry=1(borrow), rd-rs1+rs2-2^32*carry = 0xFFFFFF9C-100+200-2^32 = 0
        assert!(instances[0].is_satisfied().expect("正确 SUB 应满足"));

        // 篡改 carry → 0（应为 1），约束失败
        let mut inst = instances[0].clone();
        let carry_col = 1 + STEP_VARS + OFF_CARRY;
        inst.witness[carry_col] = Fr::zero();
        assert!(
            !inst.is_satisfied().expect("篡改 carry 应不满足"),
            "Group E 应检测到 SUB carry 错误"
        );
    }

    #[test]
    fn test_group_e_lui_constraint() {
        // K=1: LUI {rd:1, imm:0x12340000}, regs[1]=0x12340000
        let mut regs = [0u32; 32];
        regs[1] = 0x12340000;
        let step0 = make_step_with_insn(0, Instruction::Lui { rd: 1, imm: 0x12340000 }, regs);

        let mut trace = Trace::new();
        trace.push_step(step0);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 LUI 应满足"));

        // 篡改 rd → 0，约束失败
        let mut inst = instances[0].clone();
        let rd_col = 1 + OFF_RD_VAL;
        inst.witness[rd_col] = Fr::zero();
        assert!(
            !inst.is_satisfied().expect("篡改 rd 应不满足"),
            "Group E 应检测到 LUI rd 错误"
        );
    }

    #[test]
    fn test_group_e_auipc_constraint() {
        // K=1: AUIPC {rd:1, imm:0x1000}, pc=0, regs[1]=0x1000
        let mut regs = [0u32; 32];
        regs[1] = 0x1000;
        let step0 = make_step_with_insn(0, Instruction::Auipc { rd: 1, imm: 0x1000 }, regs);

        let mut trace = Trace::new();
        trace.push_step(step0);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        // rd - pc - imm = 0x1000 - 0 - 0x1000 = 0
        assert!(instances[0].is_satisfied().expect("正确 AUIPC 应满足"));
    }

    #[test]
    fn test_group_e_addi_constraint() {
        // K=2: 步 0 设 regs[2]=100; 步 1 ADDI {rd:1,rs1:2,imm:50} regs[1]=150
        let mut regs0 = [0u32; 32];
        regs0[2] = 100;
        let mut regs1 = [0u32; 32];
        regs1[1] = 150;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Addi { rd: 1, rs1: 2, imm: 50 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        // rs1 + imm - rd - 2^32*carry = 100 + 50 - 150 - 0 = 0
        assert!(instances[0].is_satisfied().expect("正确 ADDI 应满足"));
    }

    #[test]
    fn test_group_f_carry_binary() {
        // K=1 ECALL batch，篡改 carry=2 → carry²-carry = 4-2 = 2 ≠ 0
        let trace = make_trace(1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");

        let mut inst = instances[0].clone();
        let carry_col = 1 + OFF_CARRY;
        inst.witness[carry_col] = Fr::from_u32_with_wrap(2);
        assert!(
            !inst.is_satisfied().expect("carry=2 应不满足"),
            "Group F 应检测到 carry 非二值"
        );
    }

    #[test]
    fn test_arith_soundness_wrong_operand() {
        // K=2 ADD batch: regs[2]=100, [3]=200, [1]=300
        // 篡改 rd_val 为 301 → rs1+rs2-rd = 100+200-301 = -1 ≠ 0
        let mut regs0 = [0u32; 32];
        regs0[2] = 100;
        regs0[3] = 200;
        let mut regs1 = [0u32; 32];
        regs1[1] = 300;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Add { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 witness 应满足"));

        // 篡改 rd_val → 301
        let mut inst = instances[0].clone();
        let rd_col = 1 + STEP_VARS + OFF_RD_VAL;
        inst.witness[rd_col] = Fr::from_u32_with_wrap(301);
        assert!(
            !inst.is_satisfied().expect("篡改 rd 应不满足"),
            "Group E 算术 soundness 应检测到错误 operand"
        );
    }

    // ===== Stage 2 Phase 2c 测试（逻辑 + 移位指令）=====

    #[test]
    fn test_group_e_xor_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0xF0;
        regs0[3] = 0x0F;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0xFF;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Xor { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 XOR 应满足"));

        let mut inst = instances[0].clone();
        let rd_col = 1 + STEP_VARS + OFF_RD_VAL;
        inst.witness[rd_col] = Fr::from_u32_with_wrap(0xFE);
        assert!(
            !inst.is_satisfied().expect("篡改 rd 应不满足"),
            "XOR soundness 应检测到 rd ≠ aux"
        );
    }

    #[test]
    fn test_group_e_or_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0xF0;
        regs0[3] = 0x0F;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0xFF;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Or { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 OR 应满足"));

        let mut inst = instances[0].clone();
        let rd_col = 1 + STEP_VARS + OFF_RD_VAL;
        inst.witness[rd_col] = Fr::from_u32_with_wrap(0xF0);
        assert!(
            !inst.is_satisfied().expect("篡改 rd 应不满足"),
            "OR soundness 应检测到 rd ≠ aux"
        );
    }

    #[test]
    fn test_group_e_and_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0xFF;
        regs0[3] = 0x0F;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0x0F;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::And { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 AND 应满足"));

        let mut inst = instances[0].clone();
        let rd_col = 1 + STEP_VARS + OFF_RD_VAL;
        inst.witness[rd_col] = Fr::from_u32_with_wrap(0xFF);
        assert!(
            !inst.is_satisfied().expect("篡改 rd 应不满足"),
            "AND soundness 应检测到 rd ≠ aux"
        );
    }

    #[test]
    fn test_group_e_xori_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0xF0;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0xFF;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Xori { rd: 1, rs1: 2, imm: 0x0F }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 XORI 应满足"));
    }

    #[test]
    fn test_group_e_ori_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0xF0;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0xFF;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Ori { rd: 1, rs1: 2, imm: 0x0F }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 ORI 应满足"));
    }

    #[test]
    fn test_group_e_andi_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0xFF;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0x0F;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Andi { rd: 1, rs1: 2, imm: 0x0F }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 ANDI 应满足"));
    }

    #[test]
    fn test_group_e_slli_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0x1;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0x10;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Slli { rd: 1, rs1: 2, shamt: 4 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 SLLI 应满足"));

        let mut inst = instances[0].clone();
        let rd_col = 1 + STEP_VARS + OFF_RD_VAL;
        inst.witness[rd_col] = Fr::from_u32_with_wrap(0x20);
        assert!(
            !inst.is_satisfied().expect("篡改 rd 应不满足"),
            "SLLI soundness 应检测到 rd ≠ aux"
        );
    }

    #[test]
    fn test_group_e_srli_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0x80000000;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0x40000000;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Srli { rd: 1, rs1: 2, shamt: 1 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 SRLI 应满足"));
    }

    #[test]
    fn test_group_e_srai_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0x80000000;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0xC0000000;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Srai { rd: 1, rs1: 2, shamt: 1 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 SRAI 算术右移应满足"));
    }

    #[test]
    fn test_group_e_sll_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0x1;
        regs0[3] = 4;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0x10;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Sll { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 SLL 应满足"));

        let inst = &instances[0];
        let shamt_col = 1 + STEP_VARS + OFF_SHAMT;
        assert_eq!(
            inst.witness[shamt_col],
            Fr::from_u32_with_wrap(4),
            "SLL shamt 应为 rs2 & 0x1F = 4"
        );
    }

    #[test]
    fn test_group_e_srl_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0x80000000;
        regs0[3] = 1;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0x40000000;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Srl { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 SRL 应满足"));
    }

    #[test]
    fn test_group_e_sra_constraint() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0x80000000;
        regs0[3] = 1;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0xC0000000;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Sra { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 SRA 算术右移应满足"));
    }

    #[test]
    fn test_shift_shamt_from_rs2_low_5_bits() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0x1;
        regs0[3] = 35;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0x8;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Sll { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");

        let inst = &instances[0];
        let shamt_col = 1 + STEP_VARS + OFF_SHAMT;
        assert_eq!(
            inst.witness[shamt_col],
            Fr::from_u32_with_wrap(3),
            "SLL shamt 应为 35 & 0x1F = 3，而非 35"
        );
        assert!(
            inst.is_satisfied().expect("1 << 3 = 8 应满足"),
            "shamt=3 时 rd=0x8 应满足约束"
        );
    }

    #[test]
    fn test_logical_shift_soundness_wrong_operand() {
        let mut regs0 = [0u32; 32];
        regs0[2] = 0xF0;
        regs0[3] = 0x0F;
        let mut regs1 = [0u32; 32];
        regs1[1] = 0xFF;
        let step0 = make_ecall_step_with_regs(0, regs0);
        let step1 = make_step_with_insn(1, Instruction::Xor { rd: 1, rs1: 2, rs2: 3 }, regs1);

        let mut trace = Trace::new();
        trace.push_step(step0);
        trace.push_step(step1);
        let instances = compile_trace_to_ccs(&trace, 10).expect("应成功");
        assert!(instances[0].is_satisfied().expect("正确 witness 应满足"));

        let mut inst = instances[0].clone();
        let rd_col = 1 + STEP_VARS + OFF_RD_VAL;
        inst.witness[rd_col] = Fr::from_u32_with_wrap(0xEE);
        assert!(
            !inst.is_satisfied().expect("篡改 rd 应不满足"),
            "逻辑指令 soundness 应检测到 rd ≠ aux"
        );
    }

}
