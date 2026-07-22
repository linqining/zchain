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
    /// - `log_size` — log2(行数)，行数 = `1 << log_size`，最小 8（256 行，Stwo FFT 最低 5）
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

    /// 计算 log_size（取 ≥ num_steps 的最小 2 的幂，最小 8）。
    ///
    /// # 参数
    /// - `num_steps` — 真实 step 数量
    ///
    /// # 返回
    /// log_size ∈ [8, 24]（最小 256 行，最大 16M 行）
    ///
    /// # 最小 log_size 选择理由
    /// - Stwo SimdBackend FFT 最低要求 log_size >= 5（VECWISE_FFT_BITS = LOG_N_LANES + 1 = 5）
    /// - Stwo bit_reverse 对 log_size < 10 自动回退到 CPU 实现（功能正确，仅性能略低）
    /// - 设为 8（256 行）兼顾实用性和性能：texas_poker 173 步仅需 83 padding 行
    #[must_use]
    pub fn compute_log_size(num_steps: usize) -> u32 {
        let mut log_size: u32 = 8; // 最小 8（256 行，Stwo FFT 最低 5，bit_reverse 有 CPU 回退）
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

    /// 填充一行（直接提供 NUM_COLUMNS 个 M31 值，v3 = 87）。
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
/// 2. 对每个 step 调用 [`step_to_m31_row`] 生成 NUM_COLUMNS 个 M31 值（v3 = 87）
/// 3. 用 `TraceBuilder::fill_row` 填充
/// 4. `fill_padding_to_full` 填充到 2^log_size 行（padding 行 IsPadding=1）
/// 5. `finalize` 返回 `NativeTrace`
///
/// # 参数
/// - `trace` — emulator 执行 trace
///
/// # 返回
/// 列主序 `NativeTrace`，列数 = `NUM_COLUMNS`（v3 = 87），行数 = 2^log_size
#[must_use]
pub fn trace_to_native(trace: &crate::trace::Trace) -> NativeTrace {
    let num_steps = trace.len();
    let log_size = TraceBuilder::compute_log_size(num_steps.max(1));
    let mut builder = TraceBuilder::new(log_size);

    // 初始寄存器快照（来自 Trace::initial_registers，默认全零）
    // 用于第 0 步的 prev_registers，使 compute_mem_addr/extract_operands 能正确
    // 读取 rs1/rs2 的初值（如 LW x1, x2, 8 时 prev[x2] 为基址）
    let mut prev_registers = *trace.initial_registers();

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

/// 将单个 emulator `Step` 转换为 73 列 M31 row（v3.3 布局）。
///
/// # 参数
/// - `step` — emulator 执行的单步记录
/// - `prev_registers` — 前一步的寄存器快照（用于计算 ValueB = prev[rs1] 等）
///
/// # 返回
/// 长度 = `NUM_COLUMNS`（v3.3 = 73）的 `Vec<M31>`
///
/// # v3.3 实现（P1.3）
/// 在 v3.2（77 列）基础上移除 PcNextAux 列：
/// - PcNextAux 仅用于 JALR 约束，与 HelperA 使用互斥
/// - JALR 行 HelperA 复用为 PcNextAux 值
/// 保留：PC/PcNext (8) + ArithFlag (2) + ValueAEff/B/C (12) +
///       Indicator (35) + HelperA/B (8) + Taken (1) + MemAddr (4) + SyscallId (1) + PcCarry (2) = 73
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

    // ----- 提取操作数索引和立即数 -----
    // v3：不再写入 OpA/OpB/OpC/ImmC 死列，仅用于本地计算 ValueB/ValueC
    let (op_a, op_b, op_c, imm_c_flag, imm_value) = extract_operands(&step.instruction);

    // ----- Phase 3: MemAddr 填充（Load/Store 地址 = rs1 + imm）-----
    // 非 Load/Store 指令填 0；Load/Store 填 rs1_value + imm
    let mem_addr = compute_mem_addr(&step.instruction, prev_registers);
    fill_word(&mut row, COL_MEM_ADDR_BASE, mem_addr);

    // 计算 next_pc（默认 = pc + 4；分支指令根据 prev_registers 判断 taken）
    let (next_pc, taken, pc_next_aux) = compute_next_pc(step, prev_registers);
    let pc_next_limbs = u32_to_m31_limbs(next_pc);
    for i in 0..WORD_LIMB_COUNT {
        row[COL_PC_NEXT_BASE + i] = pc_next_limbs[i];
    }
    // v3.3（P1.3）：PcNextAux 列已移除，JALR 目标地址复用 HelperA 列
    // （PcNextAux 仅在 JALR 行被约束，与 HelperA 使用互斥）
    row[COL_TAKEN] = M31::from(u32::from(taken));

    // ----- HelperA: 复用列（4×8-bit limb）-----
    // LUI 行：imm 值（用于 rd_eff = imm 约束）
    // JAL/Branch taken/AUIPC 行：Pc + imm 预计算值
    // Load/Store 行：MemAddr 值（rs1 + imm，与 MemAddr 列一致）
    // JALR 行：PcNextAux 值（JALR 目标地址 = (rs1 + imm) & !1，用于 PcNext 约束）
    // 其他行：0（不被约束）
    //
    // 互斥性：LUI/JAL/Branch/AUIPC/Load/Store/JALR 的 indicator one-hot 互斥，
    // 可安全复用同一组 4 列。
    let helper_a_value: u32 = match &step.instruction {
        Instruction::Lui { .. } => imm_value,
        Instruction::Jal { .. }
        | Instruction::Beq { .. }
        | Instruction::Bne { .. }
        | Instruction::Blt { .. }
        | Instruction::Bge { .. }
        | Instruction::Bltu { .. }
        | Instruction::Bgeu { .. }
        | Instruction::Auipc { .. } => compute_pc_plus_imm(step, imm_value),
        // Load/Store: HelperA = MemAddr（rs1 + imm）
        Instruction::Lb { .. }
        | Instruction::Lh { .. }
        | Instruction::Lw { .. }
        | Instruction::Lbu { .. }
        | Instruction::Lhu { .. }
        | Instruction::Sb { .. }
        | Instruction::Sh { .. }
        | Instruction::Sw { .. } => mem_addr,
        // v3.3（P1.3）：JALR 行复用 HelperA 存 PcNextAux 值
        Instruction::Jalr { .. } => pc_next_aux,
        _ => 0,
    };
    fill_word(&mut row, COL_HELPER_A_BASE, helper_a_value);

    // ----- 操作数值（v3：移除 ValueA 死列，仅保留 ValueAEff/ValueB/ValueC）-----
    let value_b = prev_registers[op_b as usize];          // rs1 读值
    let value_c = if imm_c_flag == 1 {
        imm_value
    } else {
        prev_registers[op_c as usize]                    // rs2 读值
    };
    let value_a_eff = if op_a == 0 { 0 } else { step.registers[op_a as usize] };

    fill_word(&mut row, COL_VALUE_A_EFF_BASE, value_a_eff);
    fill_word(&mut row, COL_VALUE_B_BASE, value_b);
    fill_word(&mut row, COL_VALUE_C_BASE, value_c);

    // ----- HelperB: 复用列（4×8-bit limb）-----
    // Load 行：mem_value（加载值，用于 rd_eff = mem_value 约束）
    // Store 行：rs2_value（存储值，用于 rs2 = mem_value 约束）
    // 其他行：0（不被约束）
    //
    // 互斥性：Load/Store indicator one-hot 互斥。
    // 注：Store 行的 mem_value = rs2_value = value_c，直接复用 value_c 即可。
    //     Load 行的 mem_value 来自 step.mem_access[0].value（由 extract_mem_value 提取）。
    let helper_b_value: u32 = match &step.instruction {
        Instruction::Lb { .. }
        | Instruction::Lh { .. }
        | Instruction::Lw { .. }
        | Instruction::Lbu { .. }
        | Instruction::Lhu { .. } => {
            extract_mem_value(&step.instruction, step.mem_access.as_slice(), value_c)
        }
        // Store: HelperB = rs2_value = value_c
        Instruction::Sb { .. }
        | Instruction::Sh { .. }
        | Instruction::Sw { .. } => value_c,
        _ => 0,
    };
    fill_word(&mut row, COL_HELPER_B_BASE, helper_b_value);

    // ----- Indicator one-hot -----
    let indicator_col = instruction_to_indicator_col(&step.instruction);
    row[indicator_col] = M31::from(1u32);

    // ----- ADD/ADDI/SUB 的算术标志计算（合并 carry/borrow 到同一组列）-----
    // ADD/ADDI 行：COL_CARRY_FLAG_BASE 写入 carry0, carry1
    // SUB 行：COL_CARRY_FLAG_BASE 写入 borrow0, borrow1（ADD/ADDI 与 SUB 互斥，可复用）
    match &step.instruction {
        Instruction::Add { .. } | Instruction::Addi { .. } => {
            let (carry0, carry1) = compute_add_carries(value_b, value_c, value_a_eff);
            row[COL_CARRY_FLAG_BASE] = M31::from(carry0);
            row[COL_CARRY_FLAG_BASE + 1] = M31::from(carry1);
        }
        Instruction::Sub { .. } => {
            let (borrow0, borrow1) = compute_sub_borrows(value_b, value_c, value_a_eff);
            row[COL_CARRY_FLAG_BASE] = M31::from(borrow0);
            row[COL_CARRY_FLAG_BASE + 1] = M31::from(borrow1);
        }
        _ => {}
    }

    // ----- PC carry 计算（Phase 4 Tier 1.1）-----
    // 用于修复 PC 递增约束的 limb 进位 bug
    // 适用情形：
    //   1. IsNonFlow=1 的指令（非 JAL/JALR/Branch/Padding）：PcNext = Pc + 4
    //   2. Branch not-taken（Taken=0 但 IsBranch=1）：PcNext = Pc + 4
    // 不适用：
    //   - JAL/JALR：PcNext 由 HelperA 直接 limb-wise 等式约束（JALR 复用 HelperA 存 PcNextAux，无需 carry）
    //   - Branch taken：PcNext = HelperA（limb-wise 等式）
    //   - Padding：IsNonFlow=0，约束 gated off
    //
    // 注：分支指令在 not-taken 情形下 (Taken=0) 仍需 PcNext = Pc + 4，
    // 此时 IsBranch=1 但 IsNonFlow=0，AIR 约束需用 (1-Taken)*IsBranch 路径
    // 单独 gate PC carry 约束。
    let needs_pc_carry = match &step.instruction {
        // IsNonFlow=1 的指令：需要 PC carry
        Instruction::Lui { .. }
        | Instruction::Auipc { .. }
        | Instruction::Lb { .. }
        | Instruction::Lh { .. }
        | Instruction::Lw { .. }
        | Instruction::Lbu { .. }
        | Instruction::Lhu { .. }
        | Instruction::Sb { .. }
        | Instruction::Sh { .. }
        | Instruction::Sw { .. }
        | Instruction::Addi { .. }
        | Instruction::Slti { .. }
        | Instruction::Sltiu { .. }
        | Instruction::Xori { .. }
        | Instruction::Ori { .. }
        | Instruction::Andi { .. }
        | Instruction::Slli { .. }
        | Instruction::Srli { .. }
        | Instruction::Srai { .. }
        | Instruction::Add { .. }
        | Instruction::Sub { .. }
        | Instruction::Sll { .. }
        | Instruction::Slt { .. }
        | Instruction::Sltu { .. }
        | Instruction::Xor { .. }
        | Instruction::Srl { .. }
        | Instruction::Sra { .. }
        | Instruction::Or { .. }
        | Instruction::And { .. }
        | Instruction::Mul { .. }
        | Instruction::Mulh { .. }
        | Instruction::Mulhsu { .. }
        | Instruction::Mulhu { .. }
        | Instruction::Div { .. }
        | Instruction::Divu { .. }
        | Instruction::Rem { .. }
        | Instruction::Remu { .. }
        | Instruction::Fence
        | Instruction::Ecall
        | Instruction::Ebreak => true,
        // Branch 指令：仅在 not-taken 情形下需要 PC carry
        // 但 trace 生成时我们不知道 AIR 端的 Taken gating，
        // 所以无条件填入 PC carry（AIR 端用 (1-Taken) gating 决定是否使用）
        Instruction::Beq { .. }
        | Instruction::Bne { .. }
        | Instruction::Blt { .. }
        | Instruction::Bge { .. }
        | Instruction::Bltu { .. }
        | Instruction::Bgeu { .. } => true,
        // JAL/JALR/Padding：不需要 PC carry（保持 0）
        Instruction::Jal { .. } | Instruction::Jalr { .. } => false,
    };
    if needs_pc_carry {
        let (pc_carry0, pc_carry1) = compute_pc_carries(step.pc, next_pc);
        row[COL_PC_CARRY_FLAG_BASE] = M31::from(pc_carry0);
        row[COL_PC_CARRY_FLAG_BASE + 1] = M31::from(pc_carry1);
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
/// # 参数
/// - `step` — emulator 单步记录（含 `pc` 和 `instruction`）
/// - `prev_registers` — 执行前的寄存器快照（用于读取 rs1/rs2 实际值）
///
/// # 返回
/// (next_pc, taken, pc_next_aux)
/// - `next_pc` — 下一 PC（分支跳转时为目标地址）
/// - `taken` — 分支是否跳转（0/1）
/// - `pc_next_aux` — JALR 目标地址（其他指令为 0）
///
/// # Phase 2.7 修复
/// - 旧版默认条件分支不跳转（bug：`compute_next_pc` 无 prev_registers 参数）
/// - 新版正确读取 prev_registers 评估分支条件
fn compute_next_pc(step: &crate::trace::Step, prev_registers: &[u32; 32]) -> (u32, u8, u32) {
    use crate::isa::Instruction::*;
    let pc = step.pc;
    match &step.instruction {
        // 无条件跳转 JAL：next_pc = pc + imm
        Jal { imm, .. } => (pc.wrapping_add(*imm), 1, 0),
        // 无条件跳转 JALR：next_pc = (rs1 + imm) & !1
        Jalr { rs1, imm, .. } => {
            let target = prev_registers[*rs1 as usize].wrapping_add(*imm) & !1;
            (target, 1, target)
        }
        // 条件分支：根据 prev_registers 评估
        Beq { rs1, rs2, imm, .. } => {
            let taken = prev_registers[*rs1 as usize] == prev_registers[*rs2 as usize];
            let next_pc = if taken {
                pc.wrapping_add(*imm)
            } else {
                pc.wrapping_add(4)
            };
            (next_pc, u8::from(taken), 0)
        }
        Bne { rs1, rs2, imm, .. } => {
            let taken = prev_registers[*rs1 as usize] != prev_registers[*rs2 as usize];
            let next_pc = if taken {
                pc.wrapping_add(*imm)
            } else {
                pc.wrapping_add(4)
            };
            (next_pc, u8::from(taken), 0)
        }
        Blt { rs1, rs2, imm, .. } => {
            // 有符号比较
            let a = prev_registers[*rs1 as usize] as i32;
            let b = prev_registers[*rs2 as usize] as i32;
            let taken = a < b;
            let next_pc = if taken {
                pc.wrapping_add(*imm)
            } else {
                pc.wrapping_add(4)
            };
            (next_pc, u8::from(taken), 0)
        }
        Bge { rs1, rs2, imm, .. } => {
            let a = prev_registers[*rs1 as usize] as i32;
            let b = prev_registers[*rs2 as usize] as i32;
            let taken = a >= b;
            let next_pc = if taken {
                pc.wrapping_add(*imm)
            } else {
                pc.wrapping_add(4)
            };
            (next_pc, u8::from(taken), 0)
        }
        Bltu { rs1, rs2, imm, .. } => {
            // 无符号比较
            let taken = prev_registers[*rs1 as usize] < prev_registers[*rs2 as usize];
            let next_pc = if taken {
                pc.wrapping_add(*imm)
            } else {
                pc.wrapping_add(4)
            };
            (next_pc, u8::from(taken), 0)
        }
        Bgeu { rs1, rs2, imm, .. } => {
            let taken = prev_registers[*rs1 as usize] >= prev_registers[*rs2 as usize];
            let next_pc = if taken {
                pc.wrapping_add(*imm)
            } else {
                pc.wrapping_add(4)
            };
            (next_pc, u8::from(taken), 0)
        }
        // 其他指令：PC + 4
        _ => (pc.wrapping_add(4), 0, 0),
    }
}

/// 预计算 (Pc + imm) 用于 JAL/Branch/AUIPC 的 PC 约束。
///
/// # 参数
/// - `step` — emulator 单步记录
/// - `imm_value` — 由 `extract_operands` 提取的立即数
///
/// # 返回
/// - 对于 JAL/JALR/BEQ/BNE/BLT/BGE/BLTU/BGEU/AUIPC：`step.pc + imm_value`
/// - 对于其他指令：0（无 PC+imm 语义）
fn compute_pc_plus_imm(step: &crate::trace::Step, imm_value: u32) -> u32 {
    use crate::isa::Instruction::*;
    match &step.instruction {
        Jal { .. }
        | Jalr { .. }
        | Beq { .. }
        | Bne { .. }
        | Blt { .. }
        | Bge { .. }
        | Bltu { .. }
        | Bgeu { .. }
        | Auipc { .. } => step.pc.wrapping_add(imm_value),
        _ => 0,
    }
}

/// Phase 3: 计算 Load/Store 指令的内存地址（rs1 + imm）。
///
/// # 参数
/// - `insn` — 当前指令
/// - `prev_registers` — 执行前寄存器快照（用于读取 rs1 值）
///
/// # 返回
/// - 对于 LB/LH/LW/LBU/LHU/SB/SH/SW：`prev_registers[rs1] + imm`
/// - 对于其他指令：0
fn compute_mem_addr(insn: &crate::isa::Instruction, prev_registers: &[u32; 32]) -> u32 {
    use crate::isa::Instruction::*;
    match insn {
        Lb { rs1, imm, .. }
        | Lh { rs1, imm, .. }
        | Lw { rs1, imm, .. }
        | Lbu { rs1, imm, .. }
        | Lhu { rs1, imm, .. }
        | Sb { rs1, imm, .. }
        | Sh { rs1, imm, .. }
        | Sw { rs1, imm, .. } => prev_registers[*rs1 as usize].wrapping_add(*imm),
        _ => 0,
    }
}

/// Phase 3: 提取 Load/Store 指令对应的内存值（用于 Helper4 填充）。
///
/// # 语义
/// - **Load**：返回加载的值（= `mem_access[0].value` = 写入 rd 的值）
///   - 用于约束 `rd_eff[i] - Helper4[i] = 0`（加载的值必须写入 rd）
/// - **Store**：返回存储的值（= `mem_access[0].value` = rs2 的值）
///   - 用于约束 `rs2[i] - Helper4[i] = 0`（存储的值必须来自 rs2）
/// - **其他指令**：返回 0（AIR 约束由 IsLoad/IsStore gating 保证不强制约束）
///
/// # 参数
/// - `insn` — 当前指令
/// - `mem_access` — 本步内存访问记录（Load/Store 应有且仅有 1 条）
/// - `_default_value` — 保留参数（兼容旧调用点），未使用
///
/// # 返回
/// 内存值（u32），非 Load/Store 返回 0
///
/// # 注意
/// 当前实现假设 Load/Store 每步仅有 1 条 mem_access（参考 `isa/mod.rs` L813-902，
/// 每个 Load/Store 指令 push 且仅 push 一次 MemAccess）。Phase 3.2 Memory AIR
/// 将独立处理多访问场景（如未来扩展的 LR/SC 指令）。
fn extract_mem_value(
    insn: &crate::isa::Instruction,
    mem_access: &[crate::trace::MemAccess],
    _default_value: u32,
) -> u32 {
    use crate::isa::Instruction::*;
    match insn {
        Lb { .. } | Lh { .. } | Lw { .. } | Lbu { .. } | Lhu { .. }
        | Sb { .. } | Sh { .. } | Sw { .. } => {
            mem_access.first().map(|ma| ma.value).unwrap_or(0)
        }
        _ => 0,
    }
}

/// 从 Instruction 提取操作数索引和立即数。
///
/// # 返回
/// (op_a (rd), op_b (rs1), op_c (rs2 或 0), imm_c_flag, imm_value)
///
/// # v3 注意
/// 返回的操作数索引仅用于本地计算 ValueB/ValueC，不再写入 trace 死列。
/// Shamt 列已在 v3 中移除，因此 `extract_shamt` 函数已删除。
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
        // 注：imm_c_flag = 0，因为 OpC = rs2 是寄存器索引（非立即数）。
        // imm 值通过 Helper1 列传递（所有指令均填充 Helper1 = imm_value）。
        // 这样 ValueC = prev_registers[rs2] = rs2 值，用于 Store 值约束
        // （ValueC[i] - Helper4[i] = 0，即 rs2_value - mem_value = 0）。
        Sb { rs1, rs2, imm }
        | Sh { rs1, rs2, imm }
        | Sw { rs1, rs2, imm } => (0, *rs1, *rs2, 0, *imm),

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

/// 计算 PC + 4 → PcNext 的 16-bit 边界进位。
///
/// 与 [`compute_add_carries`] 同结构，但加数为常量 4（imm=4）。
/// 用于 IsNonFlow 和 Branch not-taken 情形下的 PC 递增约束。
///
/// # 算法
/// - low16(PcNext) = low16(Pc) + 4 - 65536 * pc_carry0
/// - high16(PcNext) = high16(Pc) + pc_carry0 - 65536 * pc_carry1
///
/// # 参数
/// - `pc` — 当前 PC
/// - `pc_next` — 下一 PC（应等于 `pc.wrapping_add(4)`）
///
/// # 返回
/// (pc_carry0, pc_carry1) — 每个 ∈ {0, 1}
fn compute_pc_carries(pc: u32, pc_next: u32) -> (u32, u32) {
    // 等价于 compute_add_carries(pc, 4, pc_next)
    compute_add_carries(pc, 4, pc_next)
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
// Phase 3: Memory Trace 生成（sorted memory log 模式）
// ===========================================================================

use super::memory_air::{
    MEM_COL_ADDR_BASE, MEM_COL_IS_FIRST_ACCESS, MEM_COL_IS_PADDING,
    MEM_COL_IS_STORE, MEM_COL_TS_CUR, MEM_COL_TS_PREV, MEM_COL_VAL_CUR_BASE,
    MEM_COL_VAL_PREV_BASE, MEM_NUM_COLUMNS,
};
use crate::trace::MemOp;
use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

/// 原生 M31 Memory trace（列主序，17 列，v3.3 P1.4）。
///
/// 参考 Nexus zkVM 0.3.6 `memory_check` 模块的 sorted memory log 模式。
///
/// # 结构
/// - `cols[col_idx][row_idx]` — 列主序存储
/// - `log_size` — log2(行数)
///
/// # 设计
/// - 行按 (addr, ts) 排序
/// - 连续行同 addr 时 ValPrev=prev.ValCur、TsPrev=prev.TsCur
/// - 首次访问时 ValPrev=0、TsPrev=0、IsFirstAccess=1
#[derive(Debug, Clone)]
pub struct MemoryTrace {
    /// 列主序存储：`cols[col_idx][row_idx]`
    pub cols: Vec<Vec<M31>>,
    /// log2(行数)
    pub log_size: u32,
}

impl MemoryTrace {
    /// 创建指定 log_size 的空 Memory trace（所有列初始化为 0）。
    #[must_use]
    pub fn new(log_size: u32) -> Self {
        let num_rows = 1usize << log_size;
        Self {
            cols: vec![vec![M31::from(0u32); num_rows]; MEM_NUM_COLUMNS],
            log_size,
        }
    }

    /// 获取行数。
    #[must_use]
    pub fn num_rows(&self) -> usize {
        1usize << self.log_size
    }

    /// 填充 32-bit 值到 4×8-bit limb 列。
    fn fill_word(&mut self, row: usize, col_base: usize, value: u32) {
        let limbs = u32_to_m31_limbs(value);
        for (offset, limb) in limbs.iter().enumerate() {
            self.cols[col_base + offset][row] = *limb;
        }
    }

    /// 填充单个 M31 值到指定列。
    fn fill_scalar(&mut self, row: usize, col: usize, value: M31) {
        self.cols[col][row] = value;
    }
}

/// 单条内存访问记录（内部用于排序）。
///
/// v3.3 P1.4：移除 `size` 字段（原 MEM_COL_SIZE 列已移除，约束未使用）
#[derive(Clone, Debug)]
struct MemEntry {
    addr: u32,
    value: u32,
    is_store: u8,  // 1=Store, 0=Load
    ts: u32,       // step_index
}

/// 从 emulator `Trace` 生成 sorted Memory trace。
///
/// # 算法
/// 1. 遍历 `trace.steps()`，收集所有 MemAccess，附加 step_index 作为 TsCur
/// 2. 按 (addr, ts) 排序
/// 3. 填充 trace：
///    - 同 addr 连续行：ValPrev=prev.ValCur、TsPrev=prev.TsCur、IsFirstAccess=0
///    - 首次访问 addr：ValPrev=0、TsPrev=0、IsFirstAccess=1
/// 4. Padding 到 2^log_size 行（IsPadding=1）
///
/// # 参数
/// - `trace` — emulator 执行 trace
///
/// # 返回
/// 列主序 `MemoryTrace`，列数 = `MEM_NUM_COLUMNS` (17, v3.3 P1.4)，行数 = 2^log_size
#[must_use]
pub fn trace_to_memory_trace(trace: &crate::trace::Trace) -> MemoryTrace {
    // Step 1: 收集所有 MemAccess
    let mut entries: Vec<MemEntry> = Vec::new();
    for step in trace.iter() {
        for ma in &step.mem_access {
            entries.push(MemEntry {
                addr: ma.addr,
                value: ma.value,
                is_store: if ma.op == MemOp::Write { 1 } else { 0 },
                ts: u32::try_from(step.step_index).unwrap_or(u32::MAX),
            });
        }
    }

    // Step 2: 按 (addr, ts) 排序
    entries.sort_by(|a, b| {
        (a.addr, a.ts).cmp(&(b.addr, b.ts))
    });

    // Step 3: 计算 log_size 并填充 trace
    let num_entries = entries.len();
    let log_size = TraceBuilder::compute_log_size(num_entries.max(1));
    trace_to_memory_trace_inner(&entries, log_size)
}

/// 将 emulator trace 转换为 Memory trace，使用指定的 `target_log_size`。
///
/// 与 [`trace_to_memory_trace`] 的区别：当 CPU trace 与 Memory trace 合并为单一 AIR
/// 时（`prove_cpu_memory_trace`），两者 `log_size` 必须一致。对于步数远多于内存访问
/// 数的 trace（如 guest ELF：算术密集、内存访问稀疏），`trace_to_memory_trace` 基于
/// 内存访问数计算的 `log_size` 会小于 CPU trace 的 `log_size`，导致
/// `prove_cpu_memory_trace` 的 `assert_eq!(log_size, mem_trace.log_size)` 失败。
///
/// 本函数强制 Memory trace padding 到 `target_log_size`（须 ≥ 基于内存访问数计算的
/// 最小 log_size），使两者对齐。多余行填充为 IsPadding=1。
///
/// # 参数
/// - `trace` — emulator trace
/// - `target_log_size` — 目标 log2(行数)，应等于 CPU trace 的 `log_size`
///
/// # Panics
/// 若 `target_log_size < compute_log_size(num_entries)`（内存访问放不下）则 panic。
#[must_use]
pub fn trace_to_memory_trace_with_log_size(
    trace: &crate::trace::Trace,
    target_log_size: u32,
) -> MemoryTrace {
    // Step 1: 收集所有 MemAccess（与 trace_to_memory_trace 一致）
    let mut entries: Vec<MemEntry> = Vec::new();
    for step in trace.iter() {
        for ma in &step.mem_access {
            entries.push(MemEntry {
                addr: ma.addr,
                value: ma.value,
                is_store: if ma.op == MemOp::Write { 1 } else { 0 },
                ts: u32::try_from(step.step_index).unwrap_or(u32::MAX),
            });
        }
    }
    // Step 2: 按 (addr, ts) 排序
    entries.sort_by(|a, b| (a.addr, a.ts).cmp(&(b.addr, b.ts)));

    trace_to_memory_trace_inner(&entries, target_log_size)
}

/// 内部：从已排序的 MemEntry 列表构建 MemoryTrace，padding 到 2^log_size 行。
fn trace_to_memory_trace_inner(entries: &[MemEntry], log_size: u32) -> MemoryTrace {
    let num_entries = entries.len();
    let min_log_size = TraceBuilder::compute_log_size(num_entries.max(1));
    assert!(
        log_size >= min_log_size,
        "trace_to_memory_trace_with_log_size: target_log_size={log_size} < min_log_size={min_log_size} \
         (num_entries={num_entries} 放不下)"
    );
    let mut mem_trace = MemoryTrace::new(log_size);

    let mut prev_addr: Option<u32> = None;
    let mut prev_val_cur: u32 = 0;
    let mut prev_ts_cur: u32 = 0;

    for (row_idx, entry) in entries.iter().enumerate() {
        // 判断是否首次访问该 addr
        let is_first_access = prev_addr != Some(entry.addr);

        // 填充 MemAddr
        mem_trace.fill_word(row_idx, MEM_COL_ADDR_BASE, entry.addr);
        // 填充 MemValCur
        mem_trace.fill_word(row_idx, MEM_COL_VAL_CUR_BASE, entry.value);
        // 填充 MemTsCur（v3.3 P1.4：单 M31 标量，不再用 4×8-bit limb）
        mem_trace.fill_scalar(row_idx, MEM_COL_TS_CUR, M31::from(entry.ts));

        if is_first_access {
            // 首次访问：ValPrev=0, TsPrev=0
            mem_trace.fill_word(row_idx, MEM_COL_VAL_PREV_BASE, 0);
            mem_trace.fill_scalar(row_idx, MEM_COL_TS_PREV, M31::from(0u32));
            mem_trace.fill_scalar(row_idx, MEM_COL_IS_FIRST_ACCESS, M31::from(1u32));
        } else {
            // 连续访问：ValPrev=prev.ValCur, TsPrev=prev.TsCur
            mem_trace.fill_word(row_idx, MEM_COL_VAL_PREV_BASE, prev_val_cur);
            mem_trace.fill_scalar(row_idx, MEM_COL_TS_PREV, M31::from(prev_ts_cur));
            mem_trace.fill_scalar(row_idx, MEM_COL_IS_FIRST_ACCESS, M31::from(0u32));
        }

        // 填充 flags（v3.3 P1.4：移除 IsLoad 和 Size）
        mem_trace.fill_scalar(row_idx, MEM_COL_IS_STORE, M31::from(u32::from(entry.is_store)));
        mem_trace.fill_scalar(row_idx, MEM_COL_IS_PADDING, M31::from(0u32));

        // 更新 prev 状态
        prev_addr = Some(entry.addr);
        prev_val_cur = entry.value;
        prev_ts_cur = entry.ts;
    }

    // Step 4: Padding 到 2^log_size 行
    for row_idx in num_entries..mem_trace.num_rows() {
        // Padding 行：IsPadding=1，其余=0（MemoryTrace::new 已初始化为 0）
        mem_trace.fill_scalar(row_idx, MEM_COL_IS_PADDING, M31::from(1u32));
        // 注：Padding 行 IsStore=0, IsFirstAccess=0（v3.3 P1.4：不再有 IsLoad/Size）
    }

    mem_trace
}

/// 将 `MemoryTrace` 转换为 Stwo `CircleEvaluation` 列。
///
/// # 参数
/// - `trace` — 17 列 × 2^log_size 行的 Memory trace（v3.3 P1.4）
///
/// # 返回
/// 17 个 `CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>` 列
#[must_use]
pub fn memory_trace_to_evaluations(
    trace: &MemoryTrace,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    assert_eq!(
        trace.cols.len(),
        MEM_NUM_COLUMNS,
        "memory_trace_to_evaluations: trace.cols.len()={} != MEM_NUM_COLUMNS={}",
        trace.cols.len(),
        MEM_NUM_COLUMNS
    );
    let domain = CanonicCoset::new(trace.log_size).circle_domain();
    trace
        .cols
        .iter()
        .map(|col| {
            let base_col = BaseColumn::from_cpu(col.as_slice());
            CircleEvaluation::<SimdBackend, BaseField>::new(domain, base_col).bit_reverse()
        })
        .collect()
}

// ===========================================================================
// Phase 4 Tier 2: Poseidon Trace 生成（Step 4.2.3）
// ===========================================================================

use super::poseidon_air::{
    POSEIDON_AIR_COL_INPUT_BASE, POSEIDON_AIR_COL_IS_FIRST_ROUND, POSEIDON_AIR_COL_IS_FULL_ROUND,
    POSEIDON_AIR_COL_IS_LAST_ROUND, POSEIDON_AIR_COL_IS_PADDING, POSEIDON_AIR_COL_IS_PARTIAL_ROUND,
    POSEIDON_AIR_COL_OUTPUT_BASE, POSEIDON_AIR_COL_ROUND_CONSTANT_BASE,
    POSEIDON_AIR_COL_ROUND_COUNTER, POSEIDON_AIR_COL_SBOX_OUT_BASE, POSEIDON_AIR_COL_SBOX_SQ1_BASE,
    POSEIDON_AIR_COL_SBOX_SQ2_BASE, POSEIDON_AIR_COL_STATE_BASE,
    POSEIDON_AIR_COL_STATE_NEXT_BASE, POSEIDON_AIR_NUM_COLUMNS, POSEIDON_AIR_TOTAL_ROUNDS,
};
use super::poseidon_m31::{
    poseidon_m31_round_constants, poseidon_permutation_m31, poseidon_permutation_m31_steps,
    POSEIDON_M31_FULL_ROUNDS, POSEIDON_M31_PARTIAL_ROUNDS, POSEIDON_M31_WIDTH,
};

/// 单次 Poseidon hash 调用记录（用于生成 Poseidon trace）。
///
/// # 字段
/// - `input_state` — hash 输入的 3 元素 state（sponge permutation 输入）
/// - `output_state` — hash 输出的 3 元素 state（30 轮 permutation 后的最终 state）
///
/// # 一致性
/// `output_state` 应等于 `poseidon_permutation_m31(input_state)`。
/// [`gen_poseidon_trace`] 会通过 `poseidon_permutation_m31_steps` 重新计算中间 state，
/// 不依赖 `output_state` 字段；该字段仅供调用方/测试用作一致性校验参考。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonHashCall {
    /// Hash 输入 state（3 M31）
    pub input_state: [BaseField; 3],
    /// Hash 输出 state（3 M31）
    pub output_state: [BaseField; 3],
}

impl PoseidonHashCall {
    /// 从 `input_state` 创建 [`PoseidonHashCall`]，自动计算 `output_state`。
    ///
    /// # 参数
    /// - `input_state` — hash 输入的 3 元素 state
    #[must_use]
    pub fn from_input(input_state: [BaseField; 3]) -> Self {
        let output_state = poseidon_permutation_m31(input_state);
        Self { input_state, output_state }
    }
}

/// 原生 M31 Poseidon trace（列主序，30 列，v2.1）。
///
/// 参考 [`MemoryTrace`] 的列主序存储模式。
///
/// # 结构
/// - `cols[col_idx][row_idx]` — 列主序存储，30 列（v2.1：21 原列 + 9 S-box 中间列）
/// - `log_size` — log2(行数)，行数 = `1 << log_size`
///
/// # 行布局
/// - 每次 hash 调用占 30 行（每行一个 round）
/// - Padding 行：`IsPadding=1`，其余列=0（包括 S-box 中间列，保证 unconditional 约束满足）
#[derive(Debug, Clone)]
pub struct PoseidonTrace {
    /// 列主序存储：`cols[col_idx][row_idx]`
    pub cols: Vec<Vec<M31>>,
    /// log2(行数)
    pub log_size: u32,
}

impl PoseidonTrace {
    /// 创建指定 log_size 的空 Poseidon trace（所有列初始化为 0）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，行数 = `1 << log_size`
    #[must_use]
    pub fn new(log_size: u32) -> Self {
        let num_rows = 1usize << log_size;
        Self {
            cols: vec![vec![M31::from(0u32); num_rows]; POSEIDON_AIR_NUM_COLUMNS],
            log_size,
        }
    }

    /// 获取行数（`1 << log_size`）。
    #[must_use]
    pub fn num_rows(&self) -> usize {
        1usize << self.log_size
    }

    /// 获取列数（30，v2.1）。
    #[must_use]
    pub fn num_columns(&self) -> usize {
        self.cols.len()
    }

    /// 填充单个 M31 值到指定列。
    fn fill_scalar(&mut self, row: usize, col: usize, value: M31) {
        self.cols[col][row] = value;
    }

    /// 填充单个 `BaseField` 值到指定列（`BaseField = M31`，同类型）。
    fn fill_base(&mut self, row: usize, col: usize, value: BaseField) {
        self.cols[col][row] = value;
    }

    /// 填充 3 元素 state 到连续 3 列。
    fn fill_state(&mut self, row: usize, col_base: usize, state: &[BaseField; 3]) {
        for j in 0..POSEIDON_M31_WIDTH {
            self.cols[col_base + j][row] = state[j];
        }
    }
}

/// 计算 Poseidon trace 的 log_size。
///
/// # 参数
/// - `total_rounds_needed` — 所需总行数（hash 数 × 30）
///
/// # 返回
/// log_size ∈ [5, 24]
/// - 最小 5（32 行，容纳 1 hash 30 行 + 2 padding）
/// - 最大 24（16M 行）
fn compute_poseidon_log_size(total_rounds_needed: usize) -> u32 {
    let mut log_size: u32 = 5; // 最小 5（32 行）
    while (1usize << log_size) < total_rounds_needed {
        log_size += 1;
    }
    assert!(
        log_size <= 24,
        "compute_poseidon_log_size: total_rounds_needed={} 过大，log_size={} > 24",
        total_rounds_needed,
        log_size
    );
    log_size
}

/// 从 `&[PoseidonHashCall]` 生成 Poseidon trace。
///
/// # 算法
/// 1. 计算 log_size：每次 hash 占 30 行，取 `≥ total_rounds` 的最小 2 的幂，最小 5（32 行）
/// 2. 对每次 hash 调用 [`poseidon_permutation_m31_steps`] 获取 31 个中间 state
/// 3. 填充 30 行 × 30 列（每行一个 round，v2.1 含 9 个 S-box 中间列）
/// 4. Padding 到 2^log_size 行（`IsPadding=1`，其余列=0）
///
/// # 行布局（每次 hash 占 30 行，`round` ∈ 0..30）
/// - `State[0..3]` = `states[round]`（第 `round` 轮的输入 state）
/// - `StateNext[0..3]` = `states[round + 1]`（第 `round` 轮的输出 state）
/// - `IsFullRound` / `IsPartialRound`：根据轮序号
///   - 前 4 轮 (`round` ∈ 0..4)：full
///   - 中 22 轮 (`round` ∈ 4..26)：partial
///   - 后 4 轮 (`round` ∈ 26..30)：full
/// - `IsFirstRound` = (`round` == 0)
/// - `IsLastRound` = (`round` == 29)
/// - `RoundCounter` = `round`
/// - `Input[0..3]` = `states[0]`（首次输入，所有 round 都填，由 `IsFirstRound` gating）
/// - `Output[0..3]` = `states[30]`（最终输出，所有 round 都填，由 `IsLastRound` gating）
/// - `IsPadding` = 0
/// - `RoundConstant[0..3]` = `rcs[round]`（当前轮的 round constants）
/// - `SboxSq1[0..3]` = `(State[j] + RC[j])^2`（v2.1 新增，S-box 中间列）
/// - `SboxSq2[0..3]` = `SboxSq1[j]^2 = SboxInput[j]^4`（v2.1 新增，S-box 中间列）
/// - `SboxOut[0..3]` = `SboxSq2[j] * SboxInput[j] = SboxInput[j]^5`（v2.1 新增，S-box 输出列）
///
/// # Padding 行
/// - `IsPadding` = 1
/// - 其他列 = 0（包括 S-box 中间列，保证 unconditional 约束 P13-P21 满足）
///
/// # 参数
/// - `hash_calls` — Poseidon hash 调用列表
///
/// # 返回
/// 列主序 [`PoseidonTrace`]，列数 = `POSEIDON_AIR_NUM_COLUMNS` (30，v2.1)，行数 = `2^log_size`
#[must_use]
pub fn gen_poseidon_trace(hash_calls: &[PoseidonHashCall]) -> PoseidonTrace {
    // Step 1: 计算 log_size
    let total_rounds_needed = hash_calls.len() * POSEIDON_AIR_TOTAL_ROUNDS;
    let log_size = compute_poseidon_log_size(total_rounds_needed);

    let mut trace = PoseidonTrace::new(log_size);

    // 预计算 round constants（一次即可，所有 hash 共用）
    let rcs = poseidon_m31_round_constants();
    let full_half = POSEIDON_M31_FULL_ROUNDS as usize / 2; // 4
    let partial_end = full_half + POSEIDON_M31_PARTIAL_ROUNDS as usize; // 26

    // Step 2 + 3: 对每次 hash 生成 30 行
    let mut row_idx: usize = 0;
    for call in hash_calls {
        // 调用 poseidon_permutation_m31_steps 获取 31 个中间 state
        // states[0] = input, states[30] = output（30 轮后）
        let states = poseidon_permutation_m31_steps(call.input_state);
        assert_eq!(
            states.len(),
            POSEIDON_AIR_TOTAL_ROUNDS + 1,
            "poseidon_permutation_m31_steps 应返回 31 个 state（初始 + 30 轮）"
        );

        // 可选：验证 output_state 一致性（debug 模式）
        debug_assert_eq!(
            states[POSEIDON_AIR_TOTAL_ROUNDS],
            call.output_state,
            "PoseidonHashCall output_state 与 permutation 计算结果不一致"
        );

        // 填充 30 行（每行一个 round）
        for round in 0..POSEIDON_AIR_TOTAL_ROUNDS {
            // State[0..3] = states[round]
            trace.fill_state(row_idx, POSEIDON_AIR_COL_STATE_BASE, &states[round]);
            // StateNext[0..3] = states[round + 1]
            trace.fill_state(row_idx, POSEIDON_AIR_COL_STATE_NEXT_BASE, &states[round + 1]);

            // IsFullRound / IsPartialRound
            let (is_full, is_partial) = if round < full_half {
                (1u32, 0u32)
            } else if round < partial_end {
                (0u32, 1u32)
            } else {
                (1u32, 0u32)
            };
            trace.fill_scalar(row_idx, POSEIDON_AIR_COL_IS_FULL_ROUND, M31::from(is_full));
            trace.fill_scalar(row_idx, POSEIDON_AIR_COL_IS_PARTIAL_ROUND, M31::from(is_partial));

            // IsFirstRound / IsLastRound
            trace.fill_scalar(
                row_idx,
                POSEIDON_AIR_COL_IS_FIRST_ROUND,
                M31::from(u32::from(round == 0)),
            );
            trace.fill_scalar(
                row_idx,
                POSEIDON_AIR_COL_IS_LAST_ROUND,
                M31::from(u32::from(round == POSEIDON_AIR_TOTAL_ROUNDS - 1)),
            );

            // RoundCounter
            trace.fill_scalar(
                row_idx,
                POSEIDON_AIR_COL_ROUND_COUNTER,
                M31::from(round as u32),
            );

            // Input[0..3] = states[0]（首次输入，由 IsFirstRound gating）
            trace.fill_state(row_idx, POSEIDON_AIR_COL_INPUT_BASE, &states[0]);

            // Output[0..3] = states[30]（最终输出，由 IsLastRound gating）
            trace.fill_state(
                row_idx,
                POSEIDON_AIR_COL_OUTPUT_BASE,
                &states[POSEIDON_AIR_TOTAL_ROUNDS],
            );

            // IsPadding = 0
            trace.fill_scalar(row_idx, POSEIDON_AIR_COL_IS_PADDING, M31::from(0u32));

            // RoundConstant[0..3] = rcs[round]
            for j in 0..POSEIDON_M31_WIDTH {
                trace.fill_base(row_idx, POSEIDON_AIR_COL_ROUND_CONSTANT_BASE + j, rcs[round][j]);
            }

            // ===== v2.1 新增：填充 S-box 中间列（SboxSq1/SboxSq2/SboxOut）=====
            // S-box 分解：x^5 = x * (x^2)^2
            //   SboxInput[j]  = State[j] + RC[j]                  (inline)
            //   SboxSq1[j]    = SboxInput[j]^2                    (degree 2 约束 P13-P15)
            //   SboxSq2[j]    = SboxSq1[j]^2 = SboxInput[j]^4     (degree 2 约束 P16-P18)
            //   SboxOut[j]    = SboxSq2[j] * SboxInput[j] = SboxInput[j]^5  (degree 2 约束 P19-P21)
            //
            // 这些中间列是 unconditional 约束的 RHS，必须在每一行（包括 padding 行）正确填充。
            // - 真实行：按上述公式计算
            // - padding 行：State=0, RC=0 → SboxSq1=SboxSq2=SboxOut=0（PoseidonTrace::new 已初始化为 0）
            for j in 0..POSEIDON_M31_WIDTH {
                let sbox_input = states[round][j] + rcs[round][j];
                let sbox_sq1 = sbox_input * sbox_input;
                let sbox_sq2 = sbox_sq1 * sbox_sq1;
                let sbox_out = sbox_sq2 * sbox_input;
                trace.fill_base(row_idx, POSEIDON_AIR_COL_SBOX_SQ1_BASE + j, sbox_sq1);
                trace.fill_base(row_idx, POSEIDON_AIR_COL_SBOX_SQ2_BASE + j, sbox_sq2);
                trace.fill_base(row_idx, POSEIDON_AIR_COL_SBOX_OUT_BASE + j, sbox_out);
            }

            row_idx += 1;
        }
    }

    // Step 4: Padding 到 2^log_size 行
    // Padding 行：IsPadding=1，其余列=0（PoseidonTrace::new 已初始化为 0）
    for r in row_idx..trace.num_rows() {
        trace.fill_scalar(r, POSEIDON_AIR_COL_IS_PADDING, M31::from(1u32));
    }

    trace
}

/// 从 `&[PoseidonHashCall]` 生成 Poseidon trace，支持指定最小 log_size。
///
/// 与 [`gen_poseidon_trace`] 相同，但使用 `max(compute_poseidon_log_size(...), min_log_size)`
/// 作为最终 log_size。用于多组件集成（CPU + Memory + Poseidon）时对齐 log_size。
///
/// # 参数
/// - `hash_calls` — Poseidon hash 调用列表
/// - `min_log_size` — 最小 log_size（若 computed < min，则使用 min）
///
/// # 返回
/// `PoseidonTrace`，log_size = `max(computed, min_log_size)`
#[must_use]
pub fn gen_poseidon_trace_with_min_log_size(
    hash_calls: &[PoseidonHashCall],
    min_log_size: u32,
) -> PoseidonTrace {
    let total_rounds_needed = hash_calls.len() * POSEIDON_AIR_TOTAL_ROUNDS;
    let computed_log_size = compute_poseidon_log_size(total_rounds_needed);
    let log_size = computed_log_size.max(min_log_size);

    let mut trace = PoseidonTrace::new(log_size);

    // 预计算 round constants
    let rcs = poseidon_m31_round_constants();
    let full_half = POSEIDON_M31_FULL_ROUNDS as usize / 2; // 4
    let partial_end = full_half + POSEIDON_M31_PARTIAL_ROUNDS as usize; // 26

    let mut row_idx: usize = 0;
    for call in hash_calls {
        let states = poseidon_permutation_m31_steps(call.input_state);
        assert_eq!(
            states.len(),
            POSEIDON_AIR_TOTAL_ROUNDS + 1,
            "poseidon_permutation_m31_steps 应返回 31 个 state（初始 + 30 轮）"
        );

        debug_assert_eq!(
            states[POSEIDON_AIR_TOTAL_ROUNDS],
            call.output_state,
            "PoseidonHashCall output_state 与 permutation 计算结果不一致"
        );

        for round in 0..POSEIDON_AIR_TOTAL_ROUNDS {
            trace.fill_state(row_idx, POSEIDON_AIR_COL_STATE_BASE, &states[round]);
            trace.fill_state(row_idx, POSEIDON_AIR_COL_STATE_NEXT_BASE, &states[round + 1]);

            let (is_full, is_partial) = if round < full_half {
                (1u32, 0u32)
            } else if round < partial_end {
                (0u32, 1u32)
            } else {
                (1u32, 0u32)
            };
            trace.fill_scalar(row_idx, POSEIDON_AIR_COL_IS_FULL_ROUND, M31::from(is_full));
            trace.fill_scalar(row_idx, POSEIDON_AIR_COL_IS_PARTIAL_ROUND, M31::from(is_partial));
            trace.fill_scalar(
                row_idx,
                POSEIDON_AIR_COL_IS_FIRST_ROUND,
                M31::from(u32::from(round == 0)),
            );
            trace.fill_scalar(
                row_idx,
                POSEIDON_AIR_COL_IS_LAST_ROUND,
                M31::from(u32::from(round == POSEIDON_AIR_TOTAL_ROUNDS - 1)),
            );
            trace.fill_scalar(
                row_idx,
                POSEIDON_AIR_COL_ROUND_COUNTER,
                M31::from(round as u32),
            );
            trace.fill_state(row_idx, POSEIDON_AIR_COL_INPUT_BASE, &states[0]);
            trace.fill_state(
                row_idx,
                POSEIDON_AIR_COL_OUTPUT_BASE,
                &states[POSEIDON_AIR_TOTAL_ROUNDS],
            );
            trace.fill_scalar(row_idx, POSEIDON_AIR_COL_IS_PADDING, M31::from(0u32));

            // Round constants
            for j in 0..POSEIDON_M31_WIDTH {
                trace.fill_base(
                    row_idx,
                    POSEIDON_AIR_COL_ROUND_CONSTANT_BASE + j,
                    rcs[round][j],
                );
            }

            // v2.1 S-box 中间列
            for j in 0..POSEIDON_M31_WIDTH {
                let sbox_input = states[round][j] + rcs[round][j];
                let sbox_sq1 = sbox_input * sbox_input;
                let sbox_sq2 = sbox_sq1 * sbox_sq1;
                let sbox_out = sbox_sq2 * sbox_input;
                trace.fill_base(row_idx, POSEIDON_AIR_COL_SBOX_SQ1_BASE + j, sbox_sq1);
                trace.fill_base(row_idx, POSEIDON_AIR_COL_SBOX_SQ2_BASE + j, sbox_sq2);
                trace.fill_base(row_idx, POSEIDON_AIR_COL_SBOX_OUT_BASE + j, sbox_out);
            }

            row_idx += 1;
        }
    }

    // Padding
    for r in row_idx..trace.num_rows() {
        trace.fill_scalar(r, POSEIDON_AIR_COL_IS_PADDING, M31::from(1u32));
    }

    trace
}

/// 将 [`PoseidonTrace`] 转换为 Stwo `CircleEvaluation` 列。
///
/// # 参数
/// - `trace` — 30 列 × 2^log_size 行的 Poseidon trace（v2.1）
///
/// # 返回
/// 30 个 `CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>` 列（v2.1）
#[must_use]
pub fn poseidon_trace_to_evaluations(
    trace: &PoseidonTrace,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    assert_eq!(
        trace.cols.len(),
        POSEIDON_AIR_NUM_COLUMNS,
        "poseidon_trace_to_evaluations: trace.cols.len()={} != POSEIDON_AIR_NUM_COLUMNS={}",
        trace.cols.len(),
        POSEIDON_AIR_NUM_COLUMNS
    );
    let domain = CanonicCoset::new(trace.log_size).circle_domain();
    trace
        .cols
        .iter()
        .map(|col| {
            let base_col = BaseColumn::from_cpu(col.as_slice());
            CircleEvaluation::<SimdBackend, BaseField>::new(domain, base_col).bit_reverse()
        })
        .collect()
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::column_layout_v2::{
        COL_PC_BASE, COL_VALUE_A_EFF_BASE, IS_ADD, IS_PADDING, NUM_COLUMNS,
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
        assert_eq!(TraceBuilder::compute_log_size(1), 8); // 最小 8（256 行）
        assert_eq!(TraceBuilder::compute_log_size(256), 8);
        assert_eq!(TraceBuilder::compute_log_size(257), 9);
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
        // 100 步 → compute_log_size(100) = 8（256 行，最小 log_size=8）
        let trace = trace_to_native_trace_placeholder(100);
        assert_eq!(trace.num_rows(), 256); // log_size = 8
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
        trace1.fill_word(0, COL_VALUE_A_EFF_BASE, value);

        // 用 fill_scalar 手动填充
        let limbs = u32_to_m31_limbs(value);
        for (offset, limb) in limbs.iter().enumerate() {
            trace2.fill_scalar(0, COL_VALUE_A_EFF_BASE + offset, *limb);
        }

        // 两者应一致
        for offset in 0..WORD_LIMB_COUNT {
            assert_eq!(
                trace1.cols[COL_VALUE_A_EFF_BASE + offset][0],
                trace2.cols[COL_VALUE_A_EFF_BASE + offset][0],
                "fill_word 与 fill_scalar 不一致 (offset={})",
                offset
            );
        }
    }

    // ----- Phase 3: Memory trace 生成测试 -----

    /// 辅助：构造一个带内存访问的 Step。
    fn make_mem_step(
        step_index: u64,
        pc: u32,
        instruction: crate::isa::Instruction,
        post_registers: [u32; 32],
        mem_access: Vec<crate::trace::MemAccess>,
    ) -> crate::trace::Step {
        crate::trace::Step {
            step_index,
            pc,
            instruction,
            registers: post_registers,
            mem_access,
        }
    }

    #[test]
    fn test_memory_trace_empty() {
        // 空 trace（无内存访问）应生成全 padding 的 Memory trace
        let trace = crate::trace::Trace::new();
        let mem_trace = trace_to_memory_trace(&trace);
        assert_eq!(mem_trace.cols.len(), MEM_NUM_COLUMNS);
        // 所有行应为 padding
        for row in 0..mem_trace.num_rows() {
            assert_eq!(
                mem_trace.cols[MEM_COL_IS_PADDING][row],
                M31::from(1u32),
                "row {} 应为 padding",
                row
            );
        }
    }

    #[test]
    fn test_memory_trace_single_store() {
        // 单条 SW 指令：存储 0xDEADBEEF 到地址 0x1000
        let mut trace = crate::trace::Trace::new();
        let step = make_mem_step(
            0,
            0,
            crate::isa::Instruction::Sw { rs1: 1, rs2: 2, imm: 0 },
            [0u32; 32],
            vec![crate::trace::MemAccess {
                addr: 0x1000,
                op: crate::trace::MemOp::Write,
                value: 0xDEADBEEF,
                size: 4,
            }],
        );
        trace.push_step(step);

        let mem_trace = trace_to_memory_trace(&trace);

        // 第 0 行应为 Store 访问
        assert_eq!(mem_trace.cols[MEM_COL_IS_STORE][0], M31::from(1u32));
        // v3.3 P1.4：已移除 IsLoad 列（由 1 - IsStore - IsPadding 推导）
        assert_eq!(mem_trace.cols[MEM_COL_IS_PADDING][0], M31::from(0u32));
        assert_eq!(mem_trace.cols[MEM_COL_IS_FIRST_ACCESS][0], M31::from(1u32));

        // 验证地址
        let addr_limbs = &mem_trace.cols[MEM_COL_ADDR_BASE..MEM_COL_ADDR_BASE + 4];
        let addr = m31_limbs_to_u32(&[
            addr_limbs[0][0],
            addr_limbs[1][0],
            addr_limbs[2][0],
            addr_limbs[3][0],
        ]);
        assert_eq!(addr, 0x1000);

        // 验证值
        let val_limbs = &mem_trace.cols[MEM_COL_VAL_CUR_BASE..MEM_COL_VAL_CUR_BASE + 4];
        let val = m31_limbs_to_u32(&[
            val_limbs[0][0],
            val_limbs[1][0],
            val_limbs[2][0],
            val_limbs[3][0],
        ]);
        assert_eq!(val, 0xDEADBEEF);

        // 首次访问：ValPrev = 0, TsPrev = 0
        // v3.3 P1.4：TsPrev 改为单 M31 标量
        for i in 0..4 {
            assert_eq!(mem_trace.cols[MEM_COL_VAL_PREV_BASE + i][0], M31::from(0u32));
        }
        assert_eq!(mem_trace.cols[MEM_COL_TS_PREV][0], M31::from(0u32));

        // 其余行应为 padding
        for row in 1..mem_trace.num_rows() {
            assert_eq!(mem_trace.cols[MEM_COL_IS_PADDING][row], M31::from(1u32));
        }
    }

    #[test]
    fn test_memory_trace_sorted_by_addr() {
        // 两条 Store 指令，地址不同，验证按 addr 排序
        // Step 0: SW 到 addr=0x2000
        // Step 1: SW 到 addr=0x1000
        // 排序后：0x1000 在前，0x2000 在后
        let mut trace = crate::trace::Trace::new();
        trace.push_step(make_mem_step(
            0, 0,
            crate::isa::Instruction::Sw { rs1: 1, rs2: 2, imm: 0 },
            [0u32; 32],
            vec![crate::trace::MemAccess {
                addr: 0x2000, op: crate::trace::MemOp::Write, value: 0x1111, size: 4,
            }],
        ));
        trace.push_step(make_mem_step(
            1, 4,
            crate::isa::Instruction::Sw { rs1: 1, rs2: 2, imm: 0 },
            [0u32; 32],
            vec![crate::trace::MemAccess {
                addr: 0x1000, op: crate::trace::MemOp::Write, value: 0x2222, size: 4,
            }],
        ));

        let mem_trace = trace_to_memory_trace(&trace);

        // 第 0 行应为 addr=0x1000（排序后在前）
        let addr0 = m31_limbs_to_u32(&[
            mem_trace.cols[MEM_COL_ADDR_BASE][0],
            mem_trace.cols[MEM_COL_ADDR_BASE + 1][0],
            mem_trace.cols[MEM_COL_ADDR_BASE + 2][0],
            mem_trace.cols[MEM_COL_ADDR_BASE + 3][0],
        ]);
        assert_eq!(addr0, 0x1000);

        // 第 1 行应为 addr=0x2000
        let addr1 = m31_limbs_to_u32(&[
            mem_trace.cols[MEM_COL_ADDR_BASE][1],
            mem_trace.cols[MEM_COL_ADDR_BASE + 1][1],
            mem_trace.cols[MEM_COL_ADDR_BASE + 2][1],
            mem_trace.cols[MEM_COL_ADDR_BASE + 3][1],
        ]);
        assert_eq!(addr1, 0x2000);
    }

    #[test]
    fn test_memory_trace_continuity() {
        // 同一地址的两次访问，验证 ValPrev/TsPrev 连续性
        // Step 0: SW 0x1111 到 addr=0x1000
        // Step 1: SW 0x2222 到 addr=0x1000（同地址）
        let mut trace = crate::trace::Trace::new();
        trace.push_step(make_mem_step(
            0, 0,
            crate::isa::Instruction::Sw { rs1: 1, rs2: 2, imm: 0 },
            [0u32; 32],
            vec![crate::trace::MemAccess {
                addr: 0x1000, op: crate::trace::MemOp::Write, value: 0x1111, size: 4,
            }],
        ));
        trace.push_step(make_mem_step(
            1, 4,
            crate::isa::Instruction::Sw { rs1: 1, rs2: 2, imm: 0 },
            [0u32; 32],
            vec![crate::trace::MemAccess {
                addr: 0x1000, op: crate::trace::MemOp::Write, value: 0x2222, size: 4,
            }],
        ));

        let mem_trace = trace_to_memory_trace(&trace);

        // 第 0 行：首次访问，IsFirstAccess=1
        assert_eq!(mem_trace.cols[MEM_COL_IS_FIRST_ACCESS][0], M31::from(1u32));

        // 第 1 行：连续访问，IsFirstAccess=0
        assert_eq!(mem_trace.cols[MEM_COL_IS_FIRST_ACCESS][1], M31::from(0u32));

        // 第 1 行：ValPrev 应等于第 0 行的 ValCur = 0x1111
        let val_prev_1 = m31_limbs_to_u32(&[
            mem_trace.cols[MEM_COL_VAL_PREV_BASE][1],
            mem_trace.cols[MEM_COL_VAL_PREV_BASE + 1][1],
            mem_trace.cols[MEM_COL_VAL_PREV_BASE + 2][1],
            mem_trace.cols[MEM_COL_VAL_PREV_BASE + 3][1],
        ]);
        assert_eq!(val_prev_1, 0x1111);

        // 第 1 行：TsPrev 应等于第 0 行的 TsCur = 0
        // v3.3 P1.4：TsPrev 改为单 M31 标量
        let ts_prev_1 = mem_trace.cols[MEM_COL_TS_PREV][1].0;
        assert_eq!(ts_prev_1, 0);

        // 第 1 行：TsCur 应等于 1
        // v3.3 P1.4：TsCur 改为单 M31 标量
        let ts_cur_1 = mem_trace.cols[MEM_COL_TS_CUR][1].0;
        assert_eq!(ts_cur_1, 1);
    }

    #[test]
    fn test_memory_trace_to_evaluations() {
        // 验证 Memory trace 可转换为 CircleEvaluation 列
        let mem_trace = MemoryTrace::new(10);
        let evals = memory_trace_to_evaluations(&mem_trace);
        assert_eq!(evals.len(), MEM_NUM_COLUMNS);
    }

    // ----- Phase 4 Tier 2: Poseidon trace 生成测试 -----

    #[test]
    fn test_poseidon_hash_call_from_input() {
        // PoseidonHashCall::from_input 应自动计算 output_state
        let input = [BaseField::from(1u32), BaseField::from(2u32), BaseField::from(3u32)];
        let call = PoseidonHashCall::from_input(input);
        assert_eq!(call.input_state, input);

        // output_state 应等于 poseidon_permutation_m31(input)
        let expected_output = poseidon_permutation_m31(input);
        assert_eq!(
            call.output_state, expected_output,
            "PoseidonHashCall::from_input 自动计算的 output_state 应与 poseidon_permutation_m31 一致"
        );

        // input != output（permutation 是非平凡的）
        assert_ne!(call.input_state, call.output_state, "permutation 应改变 state");
    }

    #[test]
    fn test_compute_poseidon_log_size() {
        // 最小 5（32 行），即使无 hash 调用
        assert_eq!(compute_poseidon_log_size(0), 5);
        // 1 hash = 30 行 → log_size = 5（32 行，30 + 2 padding）
        assert_eq!(compute_poseidon_log_size(30), 5);
        // 2 hash = 60 行 → log_size = 6（64 行）
        assert_eq!(compute_poseidon_log_size(60), 6);
        // 3 hash = 90 行 → log_size = 7（128 行）
        assert_eq!(compute_poseidon_log_size(90), 7);
        // 4 hash = 120 行 → log_size = 7（128 行）
        assert_eq!(compute_poseidon_log_size(120), 7);
        // 5 hash = 150 行 → log_size = 8（256 行）
        assert_eq!(compute_poseidon_log_size(150), 8);
    }

    #[test]
    fn test_poseidon_trace_empty() {
        // 空 hash_calls 应生成全 padding 的 trace
        let trace = gen_poseidon_trace(&[]);
        assert_eq!(trace.num_columns(), POSEIDON_AIR_NUM_COLUMNS);
        assert_eq!(trace.num_rows(), 32); // log_size = 5
        assert_eq!(trace.log_size, 5);

        // 所有行应为 padding（IsPadding=1，其余列=0）
        for row in 0..trace.num_rows() {
            assert_eq!(
                trace.cols[POSEIDON_AIR_COL_IS_PADDING][row],
                M31::from(1u32),
                "row {} 应为 padding",
                row
            );
            // 其余列应为 0（除 IsPadding 外）
            for col in 0..POSEIDON_AIR_NUM_COLUMNS {
                if col != POSEIDON_AIR_COL_IS_PADDING {
                    assert_eq!(
                        trace.cols[col][row],
                        M31::from(0u32),
                        "padding 行 {} 的 col {} 应为 0",
                        row,
                        col
                    );
                }
            }
        }
    }

    #[test]
    fn test_poseidon_trace_single_hash_dimensions() {
        // 单次 hash：30 行真实 + 2 行 padding = 32 行（log_size=5）
        let call = PoseidonHashCall::from_input([
            BaseField::from(10u32),
            BaseField::from(20u32),
            BaseField::from(30u32),
        ]);
        let trace = gen_poseidon_trace(&[call]);

        // 列数 = 30（v2.1：21 原列 + 9 S-box 中间列）
        assert_eq!(trace.num_columns(), POSEIDON_AIR_NUM_COLUMNS);
        assert_eq!(trace.num_columns(), 30);

        // 行数 = 32（log_size=5）
        assert_eq!(trace.num_rows(), 32);
        assert_eq!(trace.log_size, 5);
    }

    #[test]
    fn test_poseidon_trace_single_hash_round_flags() {
        // 验证 IsFullRound/IsPartialRound/IsFirstRound/IsLastRound/RoundCounter
        let call = PoseidonHashCall::from_input([
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(3u32),
        ]);
        let trace = gen_poseidon_trace(&[call]);

        // 轮序号 → (is_full, is_partial, is_first, is_last)
        // 0..4: full, 4..26: partial, 26..30: full
        // round 0: first; round 29: last
        let expected = |round: usize| -> (u32, u32, u32, u32) {
            let is_full = if round < 4 || round >= 26 { 1 } else { 0 };
            let is_partial = if (4..26).contains(&round) { 1 } else { 0 };
            let is_first = if round == 0 { 1 } else { 0 };
            let is_last = if round == 29 { 1 } else { 0 };
            (is_full, is_partial, is_first, is_last)
        };

        for round in 0..30 {
            let (is_full, is_partial, is_first, is_last) = expected(round);
            assert_eq!(
                trace.cols[POSEIDON_AIR_COL_IS_FULL_ROUND][round],
                M31::from(is_full),
                "round {}: IsFullRound 应为 {}",
                round,
                is_full
            );
            assert_eq!(
                trace.cols[POSEIDON_AIR_COL_IS_PARTIAL_ROUND][round],
                M31::from(is_partial),
                "round {}: IsPartialRound 应为 {}",
                round,
                is_partial
            );
            assert_eq!(
                trace.cols[POSEIDON_AIR_COL_IS_FIRST_ROUND][round],
                M31::from(is_first),
                "round {}: IsFirstRound 应为 {}",
                round,
                is_first
            );
            assert_eq!(
                trace.cols[POSEIDON_AIR_COL_IS_LAST_ROUND][round],
                M31::from(is_last),
                "round {}: IsLastRound 应为 {}",
                round,
                is_last
            );
            assert_eq!(
                trace.cols[POSEIDON_AIR_COL_ROUND_COUNTER][round],
                M31::from(round as u32),
                "round {}: RoundCounter 应为 {}",
                round,
                round
            );
            // 真实行 IsPadding = 0
            assert_eq!(
                trace.cols[POSEIDON_AIR_COL_IS_PADDING][round],
                M31::from(0u32),
                "round {}: IsPadding 应为 0",
                round
            );
        }

        // one-hot 验证：每行 Full + Partial + Padding = 1
        for round in 0..30 {
            let sum = trace.cols[POSEIDON_AIR_COL_IS_FULL_ROUND][round].0
                + trace.cols[POSEIDON_AIR_COL_IS_PARTIAL_ROUND][round].0
                + trace.cols[POSEIDON_AIR_COL_IS_PADDING][round].0;
            assert_eq!(sum, 1, "round {}: Full+Partial+Padding 应为 1", round);
        }

        // padding 行（30, 31）：IsPadding=1，Full=Partial=0
        for row in 30..32 {
            assert_eq!(trace.cols[POSEIDON_AIR_COL_IS_PADDING][row], M31::from(1u32));
            assert_eq!(trace.cols[POSEIDON_AIR_COL_IS_FULL_ROUND][row], M31::from(0u32));
            assert_eq!(trace.cols[POSEIDON_AIR_COL_IS_PARTIAL_ROUND][row], M31::from(0u32));
        }
    }

    #[test]
    fn test_poseidon_trace_single_hash_state_transition() {
        // 验证 State[i] → StateNext[i] 一致性：
        // StateNext[i] 应等于 states[i+1]（即第 i 轮 permutation 后的 state）
        let input = [
            BaseField::from(42u32),
            BaseField::from(100u32),
            BaseField::from(200u32),
        ];
        let call = PoseidonHashCall::from_input(input);
        let trace = gen_poseidon_trace(&[call]);

        // 重新计算 states 用于对照
        let states = poseidon_permutation_m31_steps(input);
        assert_eq!(states.len(), 31);

        for round in 0..30 {
            // State[0..3] = states[round]
            for j in 0..3 {
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_STATE_BASE + j][round],
                    states[round][j],
                    "round {} State[{}] 不匹配",
                    round,
                    j
                );
            }
            // StateNext[0..3] = states[round + 1]
            for j in 0..3 {
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_STATE_NEXT_BASE + j][round],
                    states[round + 1][j],
                    "round {} StateNext[{}] 不匹配",
                    round,
                    j
                );
            }
        }
    }

    #[test]
    fn test_poseidon_trace_single_hash_input_output() {
        // 验证 Input[0..3] = states[0]（首次输入），Output[0..3] = states[30]（最终输出）
        // 所有 round 行都填这两个值（由 IsFirstRound/IsLastRound gating）
        let input = [
            BaseField::from(7u32),
            BaseField::from(11u32),
            BaseField::from(13u32),
        ];
        let call = PoseidonHashCall::from_input(input);
        let trace = gen_poseidon_trace(&[call]);

        let states = poseidon_permutation_m31_steps(input);
        let initial_state = states[0];
        let final_state = states[30];

        for round in 0..30 {
            // Input[0..3] = states[0]
            for j in 0..3 {
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_INPUT_BASE + j][round],
                    initial_state[j],
                    "round {} Input[{}] 应等于 initial state",
                    round,
                    j
                );
            }
            // Output[0..3] = states[30]
            for j in 0..3 {
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_OUTPUT_BASE + j][round],
                    final_state[j],
                    "round {} Output[{}] 应等于 final state",
                    round,
                    j
                );
            }
        }

        // 额外验证：initial_state == input
        assert_eq!(initial_state, input);
        // final_state != input（permutation 是非平凡的）
        assert_ne!(final_state, input);
    }

    #[test]
    fn test_poseidon_trace_single_hash_round_constants() {
        // 验证 RoundConstant[0..3] = rcs[round]
        let call = PoseidonHashCall::from_input([
            BaseField::from(0u32),
            BaseField::from(0u32),
            BaseField::from(0u32),
        ]);
        let trace = gen_poseidon_trace(&[call]);

        let rcs = poseidon_m31_round_constants();
        assert_eq!(rcs.len(), POSEIDON_AIR_TOTAL_ROUNDS);

        for round in 0..POSEIDON_AIR_TOTAL_ROUNDS {
            for j in 0..3 {
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_ROUND_CONSTANT_BASE + j][round],
                    rcs[round][j],
                    "round {} RoundConstant[{}] 不匹配 rcs",
                    round,
                    j
                );
            }
        }
    }

    #[test]
    fn test_poseidon_trace_multiple_hashes() {
        // 多次 hash：3 次 hash = 90 行 → log_size = 7（128 行）
        let calls = vec![
            PoseidonHashCall::from_input([
                BaseField::from(1u32),
                BaseField::from(2u32),
                BaseField::from(3u32),
            ]),
            PoseidonHashCall::from_input([
                BaseField::from(4u32),
                BaseField::from(5u32),
                BaseField::from(6u32),
            ]),
            PoseidonHashCall::from_input([
                BaseField::from(7u32),
                BaseField::from(8u32),
                BaseField::from(9u32),
            ]),
        ];
        let trace = gen_poseidon_trace(&calls);

        // 3 hash × 30 rounds = 90 行 → log_size = 7（128 行）
        assert_eq!(trace.log_size, 7);
        assert_eq!(trace.num_rows(), 128);
        // v2.1：30 列（21 原列 + 9 S-box 中间列）
        assert_eq!(trace.num_columns(), 30);

        // 验证第 2 次 hash 的第 0 轮（row=30）IsFirstRound=1
        assert_eq!(
            trace.cols[POSEIDON_AIR_COL_IS_FIRST_ROUND][30],
            M31::from(1u32),
            "第 2 次 hash 第 0 轮（row=30）IsFirstRound 应为 1"
        );

        // 验证第 3 次 hash 的最后一轮（row=89）IsLastRound=1
        assert_eq!(
            trace.cols[POSEIDON_AIR_COL_IS_LAST_ROUND][89],
            M31::from(1u32),
            "第 3 次 hash 最后一轮（row=89）IsLastRound 应为 1"
        );

        // 验证第 2 次 hash 的 input（row=30..60）== 第 2 个 call 的 input_state
        for round in 0..30 {
            for j in 0..3 {
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_INPUT_BASE + j][30 + round],
                    calls[1].input_state[j],
                    "第 2 hash round {} Input[{}] 不匹配",
                    round,
                    j
                );
            }
        }

        // padding 行（90..128）IsPadding=1
        for row in 90..128 {
            assert_eq!(trace.cols[POSEIDON_AIR_COL_IS_PADDING][row], M31::from(1u32));
        }

        // 真实行（0..90）IsPadding=0
        for row in 0..90 {
            assert_eq!(trace.cols[POSEIDON_AIR_COL_IS_PADDING][row], M31::from(0u32));
        }
    }

    #[test]
    fn test_poseidon_trace_padding_correctness() {
        // 验证 padding 行：IsPadding=1，其余列=0
        let call = PoseidonHashCall::from_input([
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(3u32),
        ]);
        let trace = gen_poseidon_trace(&[call]);

        // padding 行：30..32
        for row in 30..32 {
            assert_eq!(trace.cols[POSEIDON_AIR_COL_IS_PADDING][row], M31::from(1u32));
            // 其余列应为 0
            for col in 0..POSEIDON_AIR_NUM_COLUMNS {
                if col != POSEIDON_AIR_COL_IS_PADDING {
                    assert_eq!(
                        trace.cols[col][row],
                        M31::from(0u32),
                        "padding 行 {} 的 col {} 应为 0",
                        row,
                        col
                    );
                }
            }
        }
    }

    #[test]
    fn test_poseidon_trace_to_evaluations() {
        // 验证 Poseidon trace 可转换为 CircleEvaluation 列
        let call = PoseidonHashCall::from_input([
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(3u32),
        ]);
        let trace = gen_poseidon_trace(&[call]);
        let evals = poseidon_trace_to_evaluations(&trace);
        assert_eq!(evals.len(), POSEIDON_AIR_NUM_COLUMNS);
        // v2.1：30 列（21 原列 + 9 S-box 中间列）
        assert_eq!(evals.len(), 30);
    }

    #[test]
    fn test_poseidon_trace_output_state_consistency() {
        // 验证 gen_poseidon_trace 在 debug 模式下检查 output_state 一致性
        // 构造一个 output_state 正确的 call
        let input = [
            BaseField::from(99u32),
            BaseField::from(88u32),
            BaseField::from(77u32),
        ];
        let correct_call = PoseidonHashCall::from_input(input);
        // 不应 panic
        let trace = gen_poseidon_trace(&[correct_call.clone()]);
        assert_eq!(trace.num_rows(), 32);

        // 验证最后一轮的 Output == correct_call.output_state
        for j in 0..3 {
            assert_eq!(
                trace.cols[POSEIDON_AIR_COL_OUTPUT_BASE + j][29],
                correct_call.output_state[j],
                "最后一轮 Output[{}] 应等于 call.output_state",
                j
            );
        }
    }
}
