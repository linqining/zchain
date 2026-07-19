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
// 主入口：trace_to_native（骨架，Phase 2 完善 step_to_m31_row）
// ===========================================================================

/// 从 emulator `Trace` 生成 `NativeTrace`。
///
/// # 当前状态（Phase 1）
/// 仅提供骨架，`step_to_m31_row` 留待 Phase 2（CPU AIR 实现）完善。
/// Phase 1 重点：验证 `NativeTrace` 结构 + `u32_to_m31_limbs` + `TraceBuilder`。
///
/// # Phase 2 将实现
/// 1. 遍历 `trace.steps()`
/// 2. 对每个 step 调用 `step_to_m31_row` 生成 97 个 M31 值
/// 3. 用 `TraceBuilder::fill_row` 填充
/// 4. `fill_padding_to_full` 填充到 2^log_size 行
/// 5. `finalize` 返回 `NativeTrace`
pub fn trace_to_native_trace_placeholder(_num_steps: usize) -> NativeTrace {
    // Phase 1 占位：返回全零 trace
    let log_size = TraceBuilder::compute_log_size(_num_steps.max(1));
    let builder = TraceBuilder::new(log_size);
    // 注意：不调用 finalize（因为未 fill_padding），仅返回 trace 副本
    let mut trace = builder.trace.clone();
    // 填充 padding 标记（所有行 IsPadding=1，因为无真实 step）
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
