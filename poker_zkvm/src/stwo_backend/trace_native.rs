//! # Native M31 Trace 生成（Phase 1 v2）
//!
//! 严格遵循 `.trae/documents/hypernova_to_stwo_migration_plan_v2.md`（v2 FROZEN）+
//! `.trae/documents/stwo_phase1_native_trace_design.md`：
//! - **核心设计**：emulator 执行后直接输出 `Vec<Vec<M31>>`（列主序），无 BN254 Fr 域转换
//! - **32-bit 表达**：4×8-bit limb（`u32::to_le_bytes()` → 4 个 M31）
//! - **参考实现**：Nexus zkVM 0.3.6 `prover/src/trace/trace_builder.rs`
//!
//! ## 与 v1 的差异
//!
//! - **v1**：`compile_step_witness` → `Vec<Fr>`（BN254）→ `fr_to_m31_single` 域转换 → `Vec<M31>`
//! - **v2**：emulator `Step` → `step_to_m31_row` → `Vec<M31>`（原生，无域转换）
//!
//! ## 模块结构
//!
//! - [`NativeTrace`] — 列主序 trace 存储（`Vec<Vec<M31>>`）
//! - [`u32_to_m31_limbs`] / [`m31_limbs_to_u32`] — 32-bit ↔ 4×8-bit limb 转换
//! - [`TraceBuilder`] — trace 构造器（填充列 + padding + finalize）
//! - [`trace_to_native`] — 从 emulator `Trace` 生成 `NativeTrace` 主入口

use stwo::core::fields::m31::M31;

use super::column_layout_v2::{NUM_COLUMNS, WORD_LIMB_COUNT};

// ===========================================================================
// u32 ↔ M31 limb 转换
// ===========================================================================

/// 将 u32 拆分为 4 个 M31 limb（little-endian 8-bit）。
///
/// # 算法
/// `value.to_le_bytes()` → 4 个 u8 → 4 个 M31
///
/// # 安全性
/// 每个 limb ∈ [0, 255] ⊂ [0, M31_MAX=2^31-2]，无溢出风险。
/// 这是 v2 方案的核心优势：不需要 v1 的 30-bit 掩码 workaround。
///
/// # 参考
/// Nexus zkVM 0.3.6 `prover/src/trace/utils.rs::IntoBaseFields for u32`
///
/// # 示例
/// ```
/// use poker_zkvm::stwo_backend::trace_native::u32_to_m31_limbs;
/// let limbs = u32_to_m31_limbs(0x12345678);
/// // little-endian: [0x78, 0x56, 0x34, 0x12]
/// assert_eq!(limbs[0].0, 0x78);
/// assert_eq!(limbs[1].0, 0x56);
/// assert_eq!(limbs[2].0, 0x34);
/// assert_eq!(limbs[3].0, 0x12);
/// ```
#[must_use]
pub fn u32_to_m31_limbs(value: u32) -> [M31; WORD_LIMB_COUNT] {
    let bytes = value.to_le_bytes();
    [
        M31::from(bytes[0] as u32),
        M31::from(bytes[1] as u32),
        M31::from(bytes[2] as u32),
        M31::from(bytes[3] as u32),
    ]
}

/// 将 4 个 M31 limb 重建为 u32（[`u32_to_m31_limbs`] 的逆操作）。
///
/// # 参数
/// - `limbs` — 4 个 M31 limb（little-endian 8-bit）
///
/// # 返回
/// 重建的 u32 值
///
/// # 注意
/// 调用方需确保每个 limb ∈ [0, 255]，否则重建结果不正确。
///
/// # 示例
/// ```
/// use poker_zkvm::stwo_backend::trace_native::{u32_to_m31_limbs, m31_limbs_to_u32};
/// let original = 0xDEADBEEF;
/// let limbs = u32_to_m31_limbs(original);
/// let reconstructed = m31_limbs_to_u32(&limbs);
/// assert_eq!(reconstructed, original);
/// ```
#[must_use]
pub fn m31_limbs_to_u32(limbs: &[M31; WORD_LIMB_COUNT]) -> u32 {
    let bytes = [
        limbs[0].0 as u8,
        limbs[1].0 as u8,
        limbs[2].0 as u8,
        limbs[3].0 as u8,
    ];
    u32::from_le_bytes(bytes)
}

// ===========================================================================
// NativeTrace
// ===========================================================================

/// 原生 M31 trace（列主序）。
///
/// 参考 Nexus zkVM 0.3.6 `TracesBuilder`。
///
/// # 结构
/// - `cols[col_idx][row_idx]` — 列主序存储，每列一个 `Vec<M31>`
/// - `log_size` — log2(行数)，行数 = `1 << log_size`
///
/// # 设计理由
/// Stwo Circle STARK 要求 trace 行数为 2 的幂。列主序便于：
/// 1. 按列填充（emulator 逐 step 填充每列的对应行）
/// 2. 转换为 Stwo `CircleEvaluation`（每列独立 bit_reverse）
/// 3. 并行处理（rayon 按列并行）
#[derive(Debug, Clone)]
pub struct NativeTrace {
    /// 列主序存储：`cols[col_idx][row_idx]`
    pub cols: Vec<Vec<M31>>,
    /// log2(行数)
    pub log_size: u32,
}

impl NativeTrace {
    /// 创建指定 log_size 的空 trace（所有列初始化为 M31::zero()）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，行数 = `1 << log_size`，最小 10（1024 行，SIMD 对齐）
    #[must_use]
    pub fn new(log_size: u32) -> Self {
        let num_rows = 1usize << log_size;
        Self {
            cols: vec![vec![M31::from(0u32); num_rows]; NUM_COLUMNS],
            log_size,
        }
    }

    /// 获取列数。
    #[must_use]
    pub fn num_columns(&self) -> usize {
        self.cols.len()
    }

    /// 获取行数（`1 << log_size`）。
    #[must_use]
    pub fn num_rows(&self) -> usize {
        1usize << self.log_size
    }

    /// 填充一行的多个列值。
    ///
    /// # 参数
    /// - `row` — 行索引
    /// - `values` — 该行各列的值（长度 ≤ NUM_COLUMNS）
    ///
    /// # Panics
    /// 若 `values.len() > NUM_COLUMNS` 或 `row >= num_rows()`，panic
    pub fn fill_row(&mut self, row: usize, values: &[M31]) {
        assert!(
            values.len() <= self.cols.len(),
            "fill_row: values.len()={} > NUM_COLUMNS={}",
            values.len(),
            self.cols.len()
        );
        assert!(
            row < self.num_rows(),
            "fill_row: row={} >= num_rows={}",
            row,
            self.num_rows()
        );
        for (col, val) in values.iter().enumerate() {
            self.cols[col][row] = *val;
        }
    }

    /// 填充 32-bit 值到 4×8-bit limb 列（col_base..col_base+4）。
    ///
    /// # 参数
    /// - `row` — 行索引
    /// - `col_base` — 起始列索引（4 列连续）
    /// - `value` — 32-bit 值
    ///
    /// # Panics
    /// 若 `col_base + WORD_LIMB_COUNT > NUM_COLUMNS`，panic
    pub fn fill_word(&mut self, row: usize, col_base: usize, value: u32) {
        assert!(
            col_base + WORD_LIMB_COUNT <= self.cols.len(),
            "fill_word: col_base={} + {} > NUM_COLUMNS={}",
            col_base,
            WORD_LIMB_COUNT,
            self.cols.len()
        );
        let limbs = u32_to_m31_limbs(value);
        for (offset, limb) in limbs.iter().enumerate() {
            self.cols[col_base + offset][row] = *limb;
        }
    }

    /// 填充单个 M31 值到指定列。
    pub fn fill_scalar(&mut self, row: usize, col: usize, value: M31) {
        assert!(
            col < self.cols.len(),
            "fill_scalar: col={} >= NUM_COLUMNS={}",
            col,
            self.cols.len()
        );
        assert!(
            row < self.num_rows(),
            "fill_scalar: row={} >= num_rows={}",
            row,
            self.num_rows()
        );
        self.cols[col][row] = value;
    }
}

// ===========================================================================
// TraceBuilder
// ===========================================================================

/// Trace 构造器：逐行填充 + padding + finalize。
///
/// 参考 Nexus zkVM 0.3.6 `TracesBuilder`。
///
/// # 使用流程
/// 1. `TraceBuilder::new(log_size)` 创建空 builder
/// 2. `add_step(&step)` 逐行添加真实 step
/// 3. `fill_padding(&last_step)` 填充到 2^log_size 行
/// 4. `finalize()` 返回 `NativeTrace`
pub struct TraceBuilder {
    /// 内部 trace
    trace: NativeTrace,
    /// 下一待填充行索引
    next_row: usize,
}

impl TraceBuilder {
    /// 创建指定 log_size 的空 builder。
    #[must_use]
    pub fn new(log_size: u32) -> Self {
        Self {
            trace: NativeTrace::new(log_size),
            next_row: 0,
        }
    }

    /// 获取当前已填充行数。
    #[must_use]
    pub fn current_row(&self) -> usize {
        self.next_row
    }

    /// 获取总行数（`1 << log_size`）。
    #[must_use]
    pub fn num_rows(&self) -> usize {
        self.trace.num_rows()
    }

    /// 计算 log_size（取 ≥ num_steps 的最小 2 的幂，最小 10）。
    ///
    /// # 参数
    /// - `num_steps` — 真实 step 数量
    ///
    /// # 返回
    /// log_size ∈ [10, 24]（最小 1024 行，最大 16M 行）
    #[must_use]
    pub fn compute_log_size(num_steps: usize) -> u32 {
        let mut log_size: u32 = 10; // 最小 10（1024 行，SIMD 对齐）
        while (1usize << log_size) < num_steps {
            log_size += 1;
        }
        // 上限保护：MAX_ZKVM_TRACE_STEPS = 1<<20 = 1M 步
        assert!(
            log_size <= 24,
            "compute_log_size: num_steps={} 过大，log_size={} > 24",
            num_steps,
            log_size
        );
        log_size
    }

    /// 填充一行（直接提供 97 个 M31 值）。
    ///
    /// # Panics
    /// 若 `next_row >= num_rows()`，panic（须先 fill_padding）
    pub fn fill_row(&mut self, values: &[M31]) {
        assert!(
            self.next_row < self.num_rows(),
            "TraceBuilder::fill_row: next_row={} >= num_rows={}（须先增大 log_size）",
            self.next_row,
            self.num_rows()
        );
        self.trace.fill_row(self.next_row, values);
        self.next_row += 1;
    }

    /// 填充 padding 行（所有列清零，IsPadding=1）。
    ///
    /// # 参数
    /// - `num_padding_rows` — 要填充的 padding 行数
    pub fn fill_padding(&mut self, num_padding_rows: usize) {
        use super::column_layout_v2::IS_PADDING;

        let available = self.num_rows().saturating_sub(self.next_row);
        let to_fill = num_padding_rows.min(available);

        for _ in 0..to_fill {
            // padding 行：所有列清零（NativeTrace::new 已初始化为 0）
            // 仅设置 IsPadding = 1
            self.trace
                .fill_scalar(self.next_row, IS_PADDING, M31::from(1u32));
            self.next_row += 1;
        }
    }

    /// 自动填充 padding 到 2^log_size 行。
    pub fn fill_padding_to_full(&mut self) {
        let remaining = self.num_rows().saturating_sub(self.next_row);
        self.fill_padding(remaining);
    }

    /// finalize：返回 `NativeTrace`。
    ///
    /// # Panics
    /// 若未填满（`next_row < num_rows()`），panic（须先 `fill_padding_to_full`）
    #[must_use]
    pub fn finalize(self) -> NativeTrace {
        assert_eq!(
            self.next_row,
            self.num_rows(),
            "TraceBuilder::finalize: next_row={} != num_rows={}（须先 fill_padding_to_full）",
            self.next_row,
            self.num_rows()
        );
        self.trace
    }
}

// ===========================================================================
// 主入口：trace_to_native（Phase 2 实现）
// ===========================================================================

/// 从 emulator `Trace` 生成 `NativeTrace`。
///
/// # 算法
/// 1. 遍历 `trace.steps()`
/// 2. 对每个 step 调用 [`step_to_m31_row`] 生成 97 个 M31 值
/// 3. 用 `TraceBuilder::fill_row` 填充
/// 4. `fill_padding_to_full` 填充到 2^log_size 行（padding 行 IsPadding=1）
/// 5. `finalize` 返回 `NativeTrace`
///
/// # 参数
/// - `trace` — emulator 执行 trace
///
/// # 返回
/// 列主序 `NativeTrace`，列数 = `NUM_COLUMNS` (97)，行数 = 2^log_size
#[must_use]
pub fn trace_to_native(trace: &crate::trace::Trace) -> NativeTrace {
    let num_steps = trace.len();
    let log_size = TraceBuilder::compute_log_size(num_steps.max(1));
    let mut builder = TraceBuilder::new(log_size);

    // 初始寄存器快照（全零，x0 永远为 0）
    let mut prev_registers = [0u32; 32];

    for step in trace.iter() {
        let row = step_to_m31_row(step, &prev_registers);
        builder.fill_row(&row);
        // 更新 prev_registers 为本步结束后的寄存器快照
        prev_registers.copy_from_slice(&step.registers);
    }

    // 填充 padding 行（IsPadding=1，其余列=0）
    builder.fill_padding_to_full();
    builder.finalize()
}

/// 将单个 emulator `Step` 转换为 97 列 M31 row。
///
/// # 参数
/// - `step` — emulator 执行的单步记录
/// - `prev_registers` — 前一步的寄存器快照（用于计算 ValueB = prev[rs1] 等）
///
/// # 返回
/// 长度 = `NUM_COLUMNS` (97) 的 `Vec<M31>`
///
/// # Phase 2 实现范围
/// - 所有 RV32I 指令的 indicator one-hot 设置
/// - PC / OpA / OpB / OpC / ValueA / ValueAEff / ValueB / ValueC 填充
/// - ADD/ADDI/SUB 的 CarryFlag / BorrowFlag 计算
/// - 其他指令的 Helper / Branch / Shift 字段暂填 0（Phase 2.6 完善）
#[must_use]
pub fn step_to_m31_row(
    step: &crate::trace::Step,
    prev_registers: &[u32; 32],
) -> Vec<M31> {
    use crate::isa::Instruction;
    use crate::stwo_backend::column_layout_v2::*;
    use super::column_layout_v2::WORD_LIMB_COUNT;

    let mut row = vec![M31::from(0u32); NUM_COLUMNS];

    // ----- PC 相关 -----
    let pc_limbs = u32_to_m31_limbs(step.pc);
    for i in 0..WORD_LIMB_COUNT {
        row[COL_PC_BASE + i] = pc_limbs[i];
    }

    // 计算 next_pc（默认 = pc + 4）
    let (next_pc, taken, pc_next_aux) = compute_next_pc(step);
    let pc_next_limbs = u32_to_m31_limbs(next_pc);
    for i in 0..WORD_LIMB_COUNT {
        row[COL_PC_NEXT_BASE + i] = pc_next_limbs[i];
    }
    let pc_next_aux_limbs = u32_to_m31_limbs(pc_next_aux);
    for i in 0..WORD_LIMB_COUNT {
        row[COL_PC_NEXT_AUX_BASE + i] = pc_next_aux_limbs[i];
    }
    row[COL_TAKEN] = M31::from(u32::from(taken));

    // ----- 提取操作数索引和立即数 -----
    let (op_a, op_b, op_c, imm_c_flag, imm_value) = extract_operands(&step.instruction);
    row[COL_OP_A] = M31::from(u32::from(op_a));
    row[COL_OP_B] = M31::from(u32::from(op_b));
    row[COL_OP_C] = M31::from(u32::from(op_c));
    row[COL_IMM_C] = M31::from(u32::from(imm_c_flag));

    // ----- 指令编码（暂填 0，Phase 2.6 完善 encode）-----
    // TODO: 实现 Instruction::encode() 后填充 InstrVal
    // 当前：保留全零（AIR 约束不依赖 InstrVal，依赖 indicator 列）

    // ----- 操作数值 -----
    let value_a = prev_registers[op_a as usize];          // 写前值
    let value_b = prev_registers[op_b as usize];          // rs1 读值
    let value_c = if imm_c_flag == 1 {
        imm_value
    } else {
        prev_registers[op_c as usize]                    // rs2 读值
    };
    let value_a_eff = if op_a == 0 { 0 } else { step.registers[op_a as usize] };

    fill_word(&mut row, COL_VALUE_A_BASE, value_a);
    fill_word(&mut row, COL_VALUE_A_EFF_BASE, value_a_eff);
    fill_word(&mut row, COL_VALUE_B_BASE, value_b);
    fill_word(&mut row, COL_VALUE_C_BASE, value_c);

    // ----- 符号位 -----
    row[COL_SGN_A] = M31::from((value_a >> 31) & 1);
    row[COL_SGN_B] = M31::from((value_b >> 31) & 1);
    row[COL_SGN_C] = M31::from((value_c >> 31) & 1);

    // ----- Indicator one-hot -----
    let indicator_col = instruction_to_indicator_col(&step.instruction);
    row[indicator_col] = M31::from(1u32);

    // ----- ADD/ADDI/SUB 的 carry/borrow 计算 -----
    match &step.instruction {
        Instruction::Add { .. } | Instruction::Addi { .. } => {
            let (carry0, carry1) = compute_add_carries(value_b, value_c, value_a_eff);
            row[COL_CARRY_FLAG_BASE] = M31::from(carry0);
            row[COL_CARRY_FLAG_BASE + 1] = M31::from(carry1);
        }
        Instruction::Sub { .. } => {
            let (borrow0, borrow1) = compute_sub_borrows(value_b, value_c, value_a_eff);
            row[COL_BORROW_FLAG_BASE] = M31::from(borrow0);
            row[COL_BORROW_FLAG_BASE + 1] = M31::from(borrow1);
        }
        _ => {}
    }

    row
}

/// 填充一个 4×8-bit limb word 到指定列起点。
fn fill_word(row: &mut [M31], base: usize, value: u32) {
    let limbs = u32_to_m31_limbs(value);
    for i in 0..WORD_LIMB_COUNT {
        row[base + i] = limbs[i];
    }
}

/// 计算下一条 PC 地址。
///
/// # 返回
/// (next_pc, taken, pc_next_aux)
/// - `next_pc` — 下一 PC（分支跳转时为目标地址）
/// - `taken` — 分支是否跳转（0/1）
/// - `pc_next_aux` — JALR 目标地址（其他指令为 0）
fn compute_next_pc(step: &crate::trace::Step) -> (u32, u8, u32) {
    use crate::isa::Instruction::*;
    let pc = step.pc;
    match &step.instruction {
        // 无条件跳转
        Jal { imm, .. } => (pc.wrapping_add(*imm), 1, 0),
        Jalr { rs1, imm, .. } => {
            let target = step.registers[*rs1 as usize].wrapping_add(*imm) & !1;
            (target, 1, target)
        }
        // 条件分支：根据 step.registers 判断是否跳转
        // 注意：step.registers 是 post-state，无法直接判断分支是否跳转
        // 简化处理：用 prev_registers 比较（但 step 不含 prev_registers）
        // Phase 2.6 完善：在 step_to_m31_row 中传入 prev_registers 后重写
        Beq { rs1, rs2, imm, .. }
        | Bne { rs1, rs2, imm, .. }
        | Blt { rs1, rs2, imm, .. }
        | Bge { rs1, rs2, imm, .. }
        | Bltu { rs1, rs2, imm, .. }
        | Bgeu { rs1, rs2, imm, .. } => {
            // 简化：默认 not taken（pc+4），Phase 2.6 完善
            let _ = (rs1, rs2);
            (pc.wrapping_add(4), 0, 0)
        }
        // 其他指令：PC + 4
        _ => (pc.wrapping_add(4), 0, 0),
    }
}

/// 从 Instruction 提取操作数索引和立即数。
///
/// # 返回
/// (op_a (rd), op_b (rs1), op_c (rs2 或 0), imm_c_flag, imm_value)
fn extract_operands(insn: &crate::isa::Instruction) -> (u8, u8, u8, u8, u32) {
    use crate::isa::Instruction::*;
    match insn {
        // R-type：rd, rs1, rs2
        Add { rd, rs1, rs2 }
        | Sub { rd, rs1, rs2 }
        | Sll { rd, rs1, rs2 }
        | Slt { rd, rs1, rs2 }
        | Sltu { rd, rs1, rs2 }
        | Xor { rd, rs1, rs2 }
        | Srl { rd, rs1, rs2 }
        | Sra { rd, rs1, rs2 }
        | Or { rd, rs1, rs2 }
        | And { rd, rs1, rs2 }
        | Mul { rd, rs1, rs2 }
        | Mulh { rd, rs1, rs2 }
        | Mulhsu { rd, rs1, rs2 }
        | Mulhu { rd, rs1, rs2 }
        | Div { rd, rs1, rs2 }
        | Divu { rd, rs1, rs2 }
        | Rem { rd, rs1, rs2 }
        | Remu { rd, rs1, rs2 } => (*rd, *rs1, *rs2, 0, 0),

        // I-type：rd, rs1, imm
        Addi { rd, rs1, imm }
        | Slti { rd, rs1, imm }
        | Sltiu { rd, rs1, imm }
        | Xori { rd, rs1, imm }
        | Ori { rd, rs1, imm }
        | Andi { rd, rs1, imm } => (*rd, *rs1, 0, 1, *imm),

        // I-type 移位：rd, rs1, shamt
        Slli { rd, rs1, shamt }
        | Srli { rd, rs1, shamt }
        | Srai { rd, rs1, shamt } => (*rd, *rs1, *shamt, 1, u32::from(*shamt)),

        // I-type Load：rd, rs1, imm
        Lb { rd, rs1, imm }
        | Lh { rd, rs1, imm }
        | Lw { rd, rs1, imm }
        | Lbu { rd, rs1, imm }
        | Lhu { rd, rs1, imm } => (*rd, *rs1, 0, 1, *imm),

        // S-type：rs1, rs2, imm（无 rd）
        Sb { rs1, rs2, imm }
        | Sh { rs1, rs2, imm }
        | Sw { rs1, rs2, imm } => (0, *rs1, *rs2, 1, *imm),

        // B-type：rs1, rs2, imm（无 rd）
        Beq { rs1, rs2, imm }
        | Bne { rs1, rs2, imm }
        | Blt { rs1, rs2, imm }
        | Bge { rs1, rs2, imm }
        | Bltu { rs1, rs2, imm }
        | Bgeu { rs1, rs2, imm } => (0, *rs1, *rs2, 1, *imm),

        // U-type：rd, imm
        Lui { rd, imm } | Auipc { rd, imm } => (*rd, 0, 0, 1, *imm),

        // J-type：rd, imm
        Jal { rd, imm } => (*rd, 0, 0, 1, *imm),

        // J-type I：rd, rs1, imm
        Jalr { rd, rs1, imm } => (*rd, *rs1, 0, 1, *imm),

        // 系统指令：无操作数
        Ecall | Ebreak | Fence { .. } => (0, 0, 0, 0, 0),
    }
}

/// 计算 ADD/ADDI 的 16-bit 边界进位。
///
/// 4×8-bit limb 加法：limb0 + limb1 = byte-level，进位到 16-bit 边界产生 carry0；
/// limb2 + limb3 = byte-level，进位到 32-bit 边界产生 carry1。
///
/// # 返回
/// (carry0, carry1) — 每个 ∈ {0, 1}
fn compute_add_carries(rs1: u32, rs2: u32, _rd: u32) -> (u32, u32) {
    let rs1_bytes = rs1.to_le_bytes();
    let rs2_bytes = rs2.to_le_bytes();
    // 低 16 位加法：byte0 + byte1 + carry
    let low_sum = u32::from(rs1_bytes[0]) + u32::from(rs2_bytes[0])
        + u32::from(rs1_bytes[1]) * 256 + u32::from(rs2_bytes[1]) * 256;
    let carry0 = low_sum >> 16;
    // 高 16 位加法：byte2 + byte3 + carry0
    let high_sum = u32::from(rs1_bytes[2]) + u32::from(rs2_bytes[2])
        + u32::from(rs1_bytes[3]) * 256 + u32::from(rs2_bytes[3]) * 256
        + carry0;
    let carry1 = high_sum >> 16;
    (carry0 & 1, carry1 & 1)
}

/// 计算 SUB 的 16-bit 边界借位。
///
/// 4×8-bit limb 减法：limb0 - limb1，借位方向与 ADD 相反。
///
/// # 返回
/// (borrow0, borrow1) — 每个 ∈ {0, 1}
fn compute_sub_borrows(rs1: u32, rs2: u32, _rd: u32) -> (u32, u32) {
    let rs1_bytes = rs1.to_le_bytes();
    let rs2_bytes = rs2.to_le_bytes();
    // 低 16 位减法
    let low_diff = i64::from(rs1_bytes[0]) + i64::from(rs1_bytes[1]) * 256
        - i64::from(rs2_bytes[0]) - i64::from(rs2_bytes[1]) * 256;
    let borrow0 = if low_diff < 0 { 1 } else { 0 };
    // 高 16 位减法
    let high_diff = i64::from(rs1_bytes[2]) + i64::from(rs1_bytes[3]) * 256
        - i64::from(rs2_bytes[2]) - i64::from(rs2_bytes[3]) * 256
        - i64::from(borrow0);
    let borrow1 = if high_diff < 0 { 1 } else { 0 };
    (borrow0, borrow1)
}

/// 将 Instruction 映射到 indicator 列索引。
fn instruction_to_indicator_col(insn: &crate::isa::Instruction) -> usize {
    use crate::isa::Instruction::*;
    use crate::stwo_backend::column_layout_v2::*;
    match insn {
        Lui { .. } => IS_LUI,
        Auipc { .. } => IS_AUIPC,
        Jal { .. } => IS_JAL,
        Jalr { .. } => IS_JALR,
        Beq { .. } => IS_BEQ,
        Bne { .. } => IS_BNE,
        Blt { .. } => IS_BLT,
        Bge { .. } => IS_BGE,
        Bltu { .. } => IS_BLTU,
        Bgeu { .. } => IS_BGEU,
        Lb { .. } | Lh { .. } | Lw { .. } | Lbu { .. } | Lhu { .. } => IS_LOAD,
        Sb { .. } | Sh { .. } | Sw { .. } => IS_STORE,
        Addi { .. } => IS_ADDI,
        Slti { .. } => IS_SLTI,
        Sltiu { .. } => IS_SLTIU,
        Xori { .. } => IS_XORI,
        Ori { .. } => IS_ORI,
        Andi { .. } => IS_ANDI,
        Slli { .. } => IS_SLLI,
        Srli { .. } => IS_SRLI,
        Srai { .. } => IS_SRAI,
        Add { .. } => IS_ADD,
        Sub { .. } => IS_SUB,
        Sll { .. } => IS_SLL,
        Slt { .. } => IS_SLT,
        Sltu { .. } => IS_SLTU,
        Xor { .. } => IS_XOR,
        Srl { .. } => IS_SRL,
        Sra { .. } => IS_SRA,
        Or { .. } => IS_OR,
        And { .. } => IS_AND,
        Fence { .. } => IS_FENCE,
        Ecall => IS_ECALL,
        Ebreak => IS_EBREAK,
        // M 扩展暂归类到对应 R-type indicator（Phase 2.6 单独处理）
        Mul { .. } | Mulh { .. } | Mulhsu { .. } | Mulhu { .. } => IS_ADD,  // 占位
        Div { .. } | Divu { .. } | Rem { .. } | Remu { .. } => IS_SUB,      // 占位
    }
}

/// Phase 1 占位函数（保留以兼容现有测试，Phase 2 已由 `trace_to_native` 替代）。
#[must_use]
pub fn trace_to_native_trace_placeholder(num_steps: usize) -> NativeTrace {
    let log_size = TraceBuilder::compute_log_size(num_steps.max(1));
    let builder = TraceBuilder::new(log_size);
    let mut trace = builder.trace.clone();
    use super::column_layout_v2::IS_PADDING;
    for row in 0..trace.num_rows() {
        trace.fill_scalar(row, IS_PADDING, M31::from(1u32));
    }
    trace
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::column_layout_v2::{
        COL_PC_BASE, COL_VALUE_A_BASE, IS_ADD, IS_PADDING, NUM_COLUMNS,
    };

    // ----- u32 ↔ M31 limb 转换测试 -----

    #[test]
    fn test_u32_to_m31_limbs_basic() {
        let limbs = u32_to_m31_limbs(0x12345678);
        // little-endian: [0x78, 0x56, 0x34, 0x12]
        assert_eq!(limbs[0].0, 0x78);
        assert_eq!(limbs[1].0, 0x56);
        assert_eq!(limbs[2].0, 0x34);
        assert_eq!(limbs[3].0, 0x12);
    }

    #[test]
    fn test_u32_to_m31_limbs_boundary_values() {
        // 边界值测试
        for &value in &[
            0u32,
            1,
            0xFF,           // u8::MAX
            0x100,          // 256
            0xFFFF,         // u16::MAX
            0x10000,        // 65536
            0xFFFFFF,       // 24-bit max
            0xFFFFFFFF,     // u32::MAX
            0xDEADBEEF,     // 随机值
            0x80000000,     // 最高位为 1
        ] {
            let limbs = u32_to_m31_limbs(value);
            assert_eq!(limbs.len(), WORD_LIMB_COUNT);

            // 验证每个 limb ∈ [0, 255]（8-bit 范围）
            for (i, limb) in limbs.iter().enumerate() {
                assert!(
                    limb.0 < 256,
                    "value=0x{:08X} 的 limb[{}]={} 超出 8-bit 范围",
                    value,
                    i,
                    limb.0
                );
            }

            // roundtrip 验证
            let reconstructed = m31_limbs_to_u32(&limbs);
            assert_eq!(
                reconstructed, value,
                "u32 roundtrip 失败: original=0x{:08X}, reconstructed=0x{:08X}",
                value, reconstructed
            );
        }
    }

    #[test]
    fn test_m31_limbs_to_u32_roundtrip() {
        // 大量随机值 roundtrip 测试
        for value in 0..1000 {
            let limbs = u32_to_m31_limbs(value);
            let reconstructed = m31_limbs_to_u32(&limbs);
            assert_eq!(reconstructed, value, "roundtrip 失败: {}", value);
        }
    }

    // ----- NativeTrace 测试 -----

    #[test]
    fn test_native_trace_new() {
        let trace = NativeTrace::new(10);
        assert_eq!(trace.num_columns(), NUM_COLUMNS);
        assert_eq!(trace.num_rows(), 1024);
        assert_eq!(trace.log_size, 10);

        // 所有列初始化为 0
        for col in &trace.cols {
            for val in col {
                assert_eq!(*val, M31::from(0u32));
            }
        }
    }

    #[test]
    fn test_native_trace_fill_word() {
        let mut trace = NativeTrace::new(10);
        trace.fill_word(0, COL_PC_BASE, 0x12345678);

        // 验证 4 个 limb（little-endian）
        assert_eq!(trace.cols[COL_PC_BASE][0], M31::from(0x78u32));
        assert_eq!(trace.cols[COL_PC_BASE + 1][0], M31::from(0x56u32));
        assert_eq!(trace.cols[COL_PC_BASE + 2][0], M31::from(0x34u32));
        assert_eq!(trace.cols[COL_PC_BASE + 3][0], M31::from(0x12u32));
    }

    #[test]
    fn test_native_trace_fill_scalar() {
        let mut trace = NativeTrace::new(10);
        trace.fill_scalar(5, IS_ADD, M31::from(1u32));
        assert_eq!(trace.cols[IS_ADD][5], M31::from(1u32));
    }

    #[test]
    fn test_native_trace_fill_row() {
        let mut trace = NativeTrace::new(10);
        let values: Vec<M31> = (0..NUM_COLUMNS).map(|i| M31::from(i as u32)).collect();
        trace.fill_row(3, &values);

        for col in 0..NUM_COLUMNS {
            assert_eq!(trace.cols[col][3], M31::from(col as u32));
        }
    }

    #[test]
    #[should_panic(expected = "values.len()")]
    fn test_native_trace_fill_row_too_many_values() {
        let mut trace = NativeTrace::new(10);
        let values = vec![M31::from(0u32); NUM_COLUMNS + 1];
        trace.fill_row(0, &values);
    }

    // ----- TraceBuilder 测试 -----

    #[test]
    fn test_trace_builder_compute_log_size() {
        assert_eq!(TraceBuilder::compute_log_size(1), 10); // 最小 10
        assert_eq!(TraceBuilder::compute_log_size(1024), 10);
        assert_eq!(TraceBuilder::compute_log_size(1025), 11);
        assert_eq!(TraceBuilder::compute_log_size(1_000_000), 20);
        assert_eq!(TraceBuilder::compute_log_size(1 << 20), 20); // 1M
    }

    #[test]
    fn test_trace_builder_new() {
        let builder = TraceBuilder::new(10);
        assert_eq!(builder.current_row(), 0);
        assert_eq!(builder.num_rows(), 1024);
    }

    #[test]
    fn test_trace_builder_fill_row() {
        let mut builder = TraceBuilder::new(10);
        let values = vec![M31::from(0u32); NUM_COLUMNS];
        builder.fill_row(&values);
        assert_eq!(builder.current_row(), 1);

        // 再填一行
        builder.fill_row(&values);
        assert_eq!(builder.current_row(), 2);
    }

    #[test]
    fn test_trace_builder_fill_padding() {
        let mut builder = TraceBuilder::new(10); // 1024 行

        // 填 100 行真实数据
        let values = vec![M31::from(0u32); NUM_COLUMNS];
        for _ in 0..100 {
            builder.fill_row(&values);
        }
        assert_eq!(builder.current_row(), 100);

        // 填充 padding 到满
        builder.fill_padding_to_full();
        assert_eq!(builder.current_row(), 1024);
    }

    #[test]
    fn test_trace_builder_finalize() {
        let mut builder = TraceBuilder::new(10);
        let values = vec![M31::from(0u32); NUM_COLUMNS];

        // 填 10 行
        for _ in 0..10 {
            builder.fill_row(&values);
        }

        // 填充 padding
        builder.fill_padding_to_full();

        // finalize
        let trace = builder.finalize();
        assert_eq!(trace.num_rows(), 1024);
        assert_eq!(trace.num_columns(), NUM_COLUMNS);

        // 验证 padding 行的 IsPadding = 1
        for row in 10..1024 {
            assert_eq!(
                trace.cols[IS_PADDING][row],
                M31::from(1u32),
                "padding 行 {} 的 IsPadding 应为 1",
                row
            );
        }

        // 验证真实行的 IsPadding = 0
        for row in 0..10 {
            assert_eq!(
                trace.cols[IS_PADDING][row],
                M31::from(0u32),
                "真实行 {} 的 IsPadding 应为 0",
                row
            );
        }
    }

    #[test]
    #[should_panic(expected = "next_row=")]
    fn test_trace_builder_finalize_without_padding() {
        let mut builder = TraceBuilder::new(10);
        let values = vec![M31::from(0u32); NUM_COLUMNS];
        builder.fill_row(&values); // 只填 1 行
        // 未 fill_padding_to_full，应 panic
        let _ = builder.finalize();
    }

    #[test]
    fn test_trace_to_native_placeholder() {
        // Phase 1 占位函数测试
        let trace = trace_to_native_trace_placeholder(100);
        assert_eq!(trace.num_rows(), 1024); // log_size = 10
        assert_eq!(trace.num_columns(), NUM_COLUMNS);

        // 所有行应为 padding（IsPadding=1）
        for row in 0..trace.num_rows() {
            assert_eq!(trace.cols[IS_PADDING][row], M31::from(1u32));
        }
    }

    /// 辅助测试：验证 fill_word 与 fill_scalar 一致性
    #[test]
    fn test_fill_word_consistency_with_fill_scalar() {
        let mut trace1 = NativeTrace::new(10);
        let mut trace2 = NativeTrace::new(10);

        let value = 0xDEADBEEFu32;
        trace1.fill_word(0, COL_VALUE_A_BASE, value);

        // 用 fill_scalar 手动填充
        let limbs = u32_to_m31_limbs(value);
        for (offset, limb) in limbs.iter().enumerate() {
            trace2.fill_scalar(0, COL_VALUE_A_BASE + offset, *limb);
        }

        // 两者应一致
        for offset in 0..WORD_LIMB_COUNT {
            assert_eq!(
                trace1.cols[COL_VALUE_A_BASE + offset][0],
                trace2.cols[COL_VALUE_A_BASE + offset][0],
                "fill_word 与 fill_scalar 不一致 (offset={})",
                offset
            );
        }
    }
}
