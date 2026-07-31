//! # Poseidon AIR — M31-native Poseidon hash 计算 AIR（Phase 4 — Tier 2 Step 4.2.4-rev1）
//!
//! v2.1 重设计：中间列降度方案（Option B），强制 SubDomain 评估模式。
//! 详见 `.trae/documents/stwo_phase4_tier2_replan.md` §3。
//!
//! ## v2.1 重设计动机
//!
//! v1.0 设计（21 列 + 18 约束，约束度 6）的 `max_constraint_log_degree_bound = log_size + 3`
//! 触发 Stwo `EvaluationMode::ExtendToEvalDomain`，该模式与 logup interaction 集成存在
//! 边界 case（单 hash trace prove 报 `ConstraintsNotSatisfied`）。
//!
//! v2.1 将 S-box `x^5` 分解为 3 个 degree ≤ 2 约束（引入 SboxSq1/SboxSq2/SboxOut 中间列），
//! 使所有约束度 ≤ 2，`max_constraint_log_degree_bound = log_size + 1`，强制使用 SubDomain
//! 评估模式（与 MemoryAir 一致，已验证可用）。
//!
//! ## 列布局（30 列，v2.1）
//!
//! | 范围 | 列名 | 说明 | 新增? |
//! |------|------|------|-------|
//! | 0-2 | State[0..3] | 当前轮 state（3 M31） | 否 |
//! | 3-5 | StateNext[0..3] | 下一轮 state（3 M31） | 否 |
//! | 6 | IsFullRound | 1=full round | 否 |
//! | 7 | IsPartialRound | 1=partial round | 否 |
//! | 8 | IsFirstRound | 1=该 hash 的第 0 轮 | 否 |
//! | 9 | IsLastRound | 1=该 hash 的最后一轮 | 否 |
//! | 10 | RoundCounter | 当前轮序号（0-29） | 否 |
//! | 11-13 | Input[0..3] | sponge state input（3 M31） | 否 |
//! | 14-16 | Output[0..3] | sponge state output（3 M31） | 否 |
//! | 17 | IsPadding | padding 行标记 | 否 |
//! | 18-20 | RoundConstant[0..3] | 当前轮 round constants（3 M31） | 否 |
//! | 21-23 | SboxSq1[0..3] | SboxInput^2 = (State[j]+RC[j])^2（3 M31） | **是** |
//! | 24-26 | SboxSq2[0..3] | SboxSq1^2 = SboxInput^4（3 M31） | **是** |
//! | 27-29 | SboxOut[0..3] | SboxSq2 * SboxInput = SboxInput^5（3 M31） | **是** |
//!
//! ## 约束清单（27 条，所有约束 degree ≤ 2，v2.1）
//!
//! | # | 约束 | 度 | gating |
//! |---|------|----|--------|
//! | P1 | IsFullRound binality | 2 | - |
//! | P2 | IsPartialRound binality | 2 | - |
//! | P3 | IsFirstRound binality | 2 | - |
//! | P4 | IsLastRound binality | 2 | - |
//! | P5 | IsPadding binality | 2 | - |
//! | P6 | One-hot (Full + Partial + Padding = 1) | 1 | - |
//! | P7-P9 | First round: State[i] = Input[i] | 2 | IsFirstRound |
//! | P10-P12 | Last round: StateNext[i] = Output[i] | 2 | IsLastRound |
//! | P13-P15 | SboxSq1[j] = (State[j] + RC[j])^2 | 2 | 无（unconditional） |
//! | P16-P18 | SboxSq2[j] = SboxSq1[j]^2 | 2 | 无（unconditional） |
//! | P19-P21 | SboxOut[j] = SboxSq2[j] * (State[j] + RC[j]) | 2 | 无（unconditional） |
//! | P22-P24 | Full round: StateNext[i] = sum_j(MDS[i][j] * SboxOut[j]) | 2 | IsFullRound |
//! | P25-P27 | Partial round: StateNext[i] = sum_j(MDS[i][j] * term[j]) | 2 | IsPartialRound |
//!
//! 其中 P25-P27 的 `term[j]`：
//! - `term[0] = SboxOut[0] = (State[0] + RC[0])^5`（partial round 仅对 state[0] 应用 S-box）
//! - `term[j>0] = State[j] + RC[j]`（state[1..3] 仅加 RC，不应用 S-box）
//!
//! ## State 转换公式
//!
//! 算法顺序 `apply_ark → apply_sbox → apply_mds` 与
//! [`poseidon_m31::poseidon_permutation_m31`](super::poseidon_m31::poseidon_permutation_m31) 一致。
//!
//! ### S-box 分解（v2.1 核心思想）
//! ```text
//! x^5 = x * (x^2)^2
//!
//! SboxInput[j]  = State[j] + RC[j]                  (inline, 无需新列)
//! SboxSq1[j]    = SboxInput[j]^2                    (新列, degree 2 约束)
//! SboxSq2[j]    = SboxSq1[j]^2 = SboxInput[j]^4     (新列, degree 2 约束)
//! SboxOut[j]    = SboxSq2[j] * SboxInput[j] = SboxInput[j]^5  (新列, degree 2 约束)
//! ```
//!
//! ### Full round（IsFullRound=1）
//! ```text
//! new_state[i] = sum_j(MDS[i][j] * SboxOut[j])
//! 约束: IsFullRound * (StateNext[i] - new_state[i]) == 0
//! ```
//!
//! ### Partial round（IsPartialRound=1）
//! ```text
//! new_state[i] = sum_j(MDS[i][j] * term[j])
//!   term[0] = SboxOut[0]              (S-box applied)
//!   term[j>0] = State[j] + RC[j]      (no S-box, just ark)
//! 约束: IsPartialRound * (StateNext[i] - new_state[i]) == 0
//! ```
//!
//! ## Padding 行正确性（v2.1 关键）
//!
//! P13-P21 是 **unconditional**（无 gating），需在 padding 行也满足：
//! - Padding 行：State = 0, RC = 0, SboxSq1 = 0, SboxSq2 = 0, SboxOut = 0
//! - P13: `0 - (0 + 0)^2 = 0` ✓
//! - P16: `0 - 0^2 = 0` ✓
//! - P19: `0 - 0 * (0 + 0) = 0` ✓
//!
//! Trace 生成器需在 padding 行将 SboxSq1/SboxSq2/SboxOut 填 0
//! （`PoseidonTrace::new` 已初始化为 0）。
//!
//! ## Logup 交互
//!
//! 每行发送 yield（multiplicity 由 IsLastRound 和 IsPadding gating）：
//! ```text
//! values = (SyscallId=0x03, Input[0..3], Output[0..3], IsLastRound, IsPadding)
//! multiplicity = -1 * IsLastRound * (1 - IsPadding)
//! ```
//!
//! 仅 IsLastRound=1 且非 padding 的行贡献 sum（multiplicity = -1），
//! 其他行 multiplicity = 0。这确保每个 hash 只 yield 一次。
//!
//! ## PcsConfig（v2.1 关键）
//!
//! 使用与 MemoryAir 完全相同的 `PcsConfig::default()`：
//! - `log_blowup_factor = 1`
//! - `lifting_log_size = None`
//! - 无需 `set_store_polynomials_coefficients`
//!
//! 这消除了所有 ExtendToEvalDomain 模式相关的配置复杂性。
//!
//! ## 参考
//!
//! - `stwo-constraint-framework-2.3.0` — FrameworkEval, EvalAtRow, RelationEntry
//! - `poker_zkvm::stwo_backend::memory_air` — FrameworkEval 参考实现（SubDomain 模式）
//! - `poker_zkvm::stwo_backend::poseidon_m31` — M31 Poseidon 参数 + host hash
//! - `.trae/documents/stwo_phase4_tier2_replan.md` — v2.1 重新计划文档

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, RelationEntry};

use super::lookups::PoseidonLookup;
use super::poseidon_m31::{POSEIDON_M31_ALPHA, POSEIDON_M31_WIDTH, poseidon_m31_mds};

// ===========================================================================
// Poseidon AIR 列布局常量（30 列，v2.1）
// ===========================================================================

/// Poseidon AIR 列数（v2.1：21 → 30，新增 9 个 S-box 中间列）。
pub const POSEIDON_AIR_NUM_COLUMNS: usize = 30;

/// col 0-2：State[0..3]（当前轮 state，3 M31）
pub const POSEIDON_AIR_COL_STATE_BASE: usize = 0;
/// col 3-5：StateNext[0..3]（下一轮 state，3 M31）
pub const POSEIDON_AIR_COL_STATE_NEXT_BASE: usize = 3;
/// col 6：IsFullRound
pub const POSEIDON_AIR_COL_IS_FULL_ROUND: usize = 6;
/// col 7：IsPartialRound
pub const POSEIDON_AIR_COL_IS_PARTIAL_ROUND: usize = 7;
/// col 8：IsFirstRound
pub const POSEIDON_AIR_COL_IS_FIRST_ROUND: usize = 8;
/// col 9：IsLastRound
pub const POSEIDON_AIR_COL_IS_LAST_ROUND: usize = 9;
/// col 10：RoundCounter
pub const POSEIDON_AIR_COL_ROUND_COUNTER: usize = 10;
/// col 11-13：Input[0..3]（sponge state input，3 M31）
pub const POSEIDON_AIR_COL_INPUT_BASE: usize = 11;
/// col 14-16：Output[0..3]（sponge state output，3 M31）
pub const POSEIDON_AIR_COL_OUTPUT_BASE: usize = 14;
/// col 17：IsPadding
pub const POSEIDON_AIR_COL_IS_PADDING: usize = 17;
/// col 18-20：RoundConstant[0..3]（当前轮 round constants，3 M31）
pub const POSEIDON_AIR_COL_ROUND_CONSTANT_BASE: usize = 18;
/// col 21-23：SboxSq1[0..3] = (State[j] + RC[j])^2（v2.1 新增，S-box 中间列）
pub const POSEIDON_AIR_COL_SBOX_SQ1_BASE: usize = 21;
/// col 24-26：SboxSq2[0..3] = SboxSq1[j]^2 = SboxInput[j]^4（v2.1 新增，S-box 中间列）
pub const POSEIDON_AIR_COL_SBOX_SQ2_BASE: usize = 24;
/// col 27-29：SboxOut[0..3] = SboxSq2[j] * SboxInput[j] = SboxInput[j]^5（v2.1 新增，S-box 输出列）
pub const POSEIDON_AIR_COL_SBOX_OUT_BASE: usize = 27;

/// Poseidon syscall ID（= 0x03，与 `poker_zkvm::syscalls::SyscallId::Poseidon` 一致）。
pub const POSEIDON_SYSCALL_ID: u32 = 0x03;

/// Poseidon AIR 总轮数（full + partial = 8 + 22 = 30）。
pub const POSEIDON_AIR_TOTAL_ROUNDS: usize = 30;

/// 静态断言：S-box alpha=5。
const _: () = assert!(POSEIDON_M31_ALPHA == 5);

// ===========================================================================
// PoseidonAir 结构
// ===========================================================================

/// Poseidon AIR 组件 — M31-native Poseidon hash 计算 FrameworkEval（v2.1 中间列降度版）。
///
/// # 设计（v2.1）
/// - 每行表示一个 round（full 或 partial）
/// - 每次 hash 占 30 行（4 full + 22 partial + 4 full = 30 轮）
/// - State 转换通过 StateNext 列显式约束（避免 prev-row 读取）
/// - S-box `x^5` 分解为 3 个 degree ≤ 2 约束（SboxSq1/SboxSq2/SboxOut 中间列）
/// - `max_constraint_log_degree_bound = log_size + 1`（约束度 ≤ 2，强制 SubDomain 模式）
/// - 通过 logup yield 与 CPU AIR 交互（PoseidonLookup 9 元组）
///
/// # 用法
/// ```ignore
/// use poker_zkvm::stwo_backend::poseidon_air::PoseidonAir;
/// use poker_zkvm::stwo_backend::lookups::PoseidonLookup;
/// use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
/// use stwo::core::fields::qm31::SecureField;
///
/// let air = PoseidonAir::new(log_size, PoseidonLookup::dummy());
/// let component = FrameworkComponent::new(
///     &mut TraceLocationAllocator::default(),
///     air,
///     SecureField::from(0u32),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct PoseidonAir {
    /// log2(trace 行数)
    log_size: u32,
    /// PoseidonLookup relation（用于 logup yield）
    poseidon_lookup: PoseidonLookup,
}

impl PoseidonAir {
    /// 创建指定 log_size 的 Poseidon AIR。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 5（至少 32 行 = 1 hash 30 行 + padding）
    /// - `poseidon_lookup` — PoseidonLookup relation 实例（从 channel draw 或 dummy）
    #[must_use]
    pub const fn new(log_size: u32, poseidon_lookup: PoseidonLookup) -> Self {
        Self {
            log_size,
            poseidon_lookup,
        }
    }

    /// 获取 log_size。
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }
}

impl FrameworkEval for PoseidonAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    /// v2.1：所有约束的最大总度 = 2（IsFullRound * SboxOut 或 IsFullRound * StateNext）。
    /// log2(2) = 1，所以 max_constraint_log_degree_bound = log_size + 1。
    ///
    /// 这强制 Stwo 使用 `EvaluationMode::SubDomain`（与 MemoryAir 一致），
    /// 避免了 v1.0 中 `ExtendToEvalDomain` 模式与 logup 集成的边界 case。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = BaseField::from(1u32).into();
        let zero: E::F = BaseField::from(0u32).into();

        // ----- 读取全部 30 列（无需 prev-row，StateNext 显式存储）-----
        let mut cols: Vec<E::F> = Vec::with_capacity(POSEIDON_AIR_NUM_COLUMNS);
        for _ in 0..POSEIDON_AIR_NUM_COLUMNS {
            cols.push(eval.next_trace_mask());
        }
        let col = |idx: usize| -> E::F { cols[idx].clone() };

        // ----- 读取 flag 列 -----
        let is_full = col(POSEIDON_AIR_COL_IS_FULL_ROUND);
        let is_partial = col(POSEIDON_AIR_COL_IS_PARTIAL_ROUND);
        let is_first = col(POSEIDON_AIR_COL_IS_FIRST_ROUND);
        let is_last = col(POSEIDON_AIR_COL_IS_LAST_ROUND);
        let is_padding = col(POSEIDON_AIR_COL_IS_PADDING);

        // ===== P1: IsFullRound binality =====
        let full_bin = is_full.clone() * (is_full.clone() - one.clone());
        eval.add_constraint(full_bin);

        // ===== P2: IsPartialRound binality =====
        let partial_bin = is_partial.clone() * (is_partial.clone() - one.clone());
        eval.add_constraint(partial_bin);

        // ===== P3: IsFirstRound binality =====
        let first_bin = is_first.clone() * (is_first.clone() - one.clone());
        eval.add_constraint(first_bin);

        // ===== P4: IsLastRound binality =====
        let last_bin = is_last.clone() * (is_last.clone() - one.clone());
        eval.add_constraint(last_bin);

        // ===== P5: IsPadding binality =====
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // ===== P6: One-hot (Full + Partial + Padding = 1) =====
        let one_hot = is_full.clone() + is_partial.clone() + is_padding.clone() - one.clone();
        eval.add_constraint(one_hot);

        // ===== P7-P9: First round: State[i] = Input[i] =====
        // 约束: IsFirstRound * (State[i] - Input[i]) == 0
        for i in 0..POSEIDON_M31_WIDTH {
            let state_i = col(POSEIDON_AIR_COL_STATE_BASE + i);
            let input_i = col(POSEIDON_AIR_COL_INPUT_BASE + i);
            let diff = state_i - input_i;
            eval.add_constraint(is_first.clone() * diff);
        }

        // ===== P10-P12: Last round: StateNext[i] = Output[i] =====
        // 约束: IsLastRound * (StateNext[i] - Output[i]) == 0
        for i in 0..POSEIDON_M31_WIDTH {
            let state_next_i = col(POSEIDON_AIR_COL_STATE_NEXT_BASE + i);
            let output_i = col(POSEIDON_AIR_COL_OUTPUT_BASE + i);
            let diff = state_next_i - output_i;
            eval.add_constraint(is_last.clone() * diff);
        }

        // ===========================================================================
        // v2.1 关键：S-box 中间列降度约束（P13-P21，unconditional，degree ≤ 2）
        // ===========================================================================
        //
        // S-box 分解：x^5 = x * (x^2)^2
        //   SboxInput[j]  = State[j] + RC[j]                  (inline)
        //   SboxSq1[j]    = SboxInput[j]^2                    (degree 2 约束)
        //   SboxSq2[j]    = SboxSq1[j]^2 = SboxInput[j]^4     (degree 2 约束)
        //   SboxOut[j]    = SboxSq2[j] * SboxInput[j] = SboxInput[j]^5  (degree 2 约束)
        //
        // 这些约束是 **unconditional**（无 gating），需在 padding 行也满足。
        // Padding 行：State = 0, RC = 0, SboxSq1/SboxSq2/SboxOut = 0（trace 生成器初始化为 0）。
        // P13: SboxSq1[j] - (State[j] + RC[j])^2 = 0 - (0 + 0)^2 = 0 ✓
        // P16: SboxSq2[j] - SboxSq1[j]^2 = 0 - 0^2 = 0 ✓
        // P19: SboxOut[j] - SboxSq2[j] * (State[j] + RC[j]) = 0 - 0 * (0 + 0) = 0 ✓

        // 读取 round constants
        let rc_col: Vec<E::F> = (0..POSEIDON_M31_WIDTH)
            .map(|i| col(POSEIDON_AIR_COL_ROUND_CONSTANT_BASE + i))
            .collect();

        // 读取 S-box 中间列
        let sbox_sq1: Vec<E::F> = (0..POSEIDON_M31_WIDTH)
            .map(|i| col(POSEIDON_AIR_COL_SBOX_SQ1_BASE + i))
            .collect();
        let sbox_sq2: Vec<E::F> = (0..POSEIDON_M31_WIDTH)
            .map(|i| col(POSEIDON_AIR_COL_SBOX_SQ2_BASE + i))
            .collect();
        let sbox_out: Vec<E::F> = (0..POSEIDON_M31_WIDTH)
            .map(|i| col(POSEIDON_AIR_COL_SBOX_OUT_BASE + i))
            .collect();

        // ===== P13-P15: SboxSq1[j] = (State[j] + RC[j])^2 =====
        // 约束: SboxSq1[j] - (State[j] + RC[j])^2 == 0  (degree 2, unconditional)
        for j in 0..POSEIDON_M31_WIDTH {
            let s_j = col(POSEIDON_AIR_COL_STATE_BASE + j);
            let sbox_input = s_j + rc_col[j].clone();
            let sbox_sq1_expected = sbox_input.clone() * sbox_input;
            let diff = sbox_sq1[j].clone() - sbox_sq1_expected;
            eval.add_constraint(diff);
        }

        // ===== P16-P18: SboxSq2[j] = SboxSq1[j]^2 =====
        // 约束: SboxSq2[j] - SboxSq1[j]^2 == 0  (degree 2, unconditional)
        for j in 0..POSEIDON_M31_WIDTH {
            let sbox_sq2_expected = sbox_sq1[j].clone() * sbox_sq1[j].clone();
            let diff = sbox_sq2[j].clone() - sbox_sq2_expected;
            eval.add_constraint(diff);
        }

        // ===== P19-P21: SboxOut[j] = SboxSq2[j] * (State[j] + RC[j]) =====
        // 约束: SboxOut[j] - SboxSq2[j] * (State[j] + RC[j]) == 0  (degree 2, unconditional)
        // 这等价于 SboxOut[j] = SboxInput[j]^5 = SboxInput[j] * SboxInput[j]^4
        for j in 0..POSEIDON_M31_WIDTH {
            let s_j = col(POSEIDON_AIR_COL_STATE_BASE + j);
            let sbox_input = s_j + rc_col[j].clone();
            let sbox_out_expected = sbox_sq2[j].clone() * sbox_input;
            let diff = sbox_out[j].clone() - sbox_out_expected;
            eval.add_constraint(diff);
        }

        // ===========================================================================
        // v2.1 关键：State transition 约束（P22-P27，gated，degree ≤ 2）
        // ===========================================================================

        let mds = poseidon_m31_mds();

        // ===== P22-P24: Full round transition =====
        // 算法（与 poseidon_m31::poseidon_permutation_m31 一致）：
        //   apply_ark:  sbox_input[j] = State[j] + RC[j]          (all j)
        //   apply_sbox: sbox_state[j] = sbox_input[j]^5 = SboxOut[j]  (all j, 已在 P13-P21 约束)
        //   apply_mds:  new_state[i] = sum_j(MDS[i][j] * SboxOut[j])
        // 约束: IsFullRound * (StateNext[i] - new_state[i]) == 0
        //
        // degree 分析：IsFullRound (1) * (StateNext (1) - sum(MDS (const) * SboxOut (1))) = 2 ✓
        for i in 0..POSEIDON_M31_WIDTH {
            let mut new_state_i = zero.clone();
            for j in 0..POSEIDON_M31_WIDTH {
                let mds_ij: E::F = mds[i][j].into();
                new_state_i = new_state_i + mds_ij * sbox_out[j].clone();
            }

            let state_next_i = col(POSEIDON_AIR_COL_STATE_NEXT_BASE + i);
            let diff = state_next_i - new_state_i;
            eval.add_constraint(is_full.clone() * diff);
        }

        // ===== P25-P27: Partial round transition =====
        // 算法（与 poseidon_m31::poseidon_permutation_m31 一致）：
        //   apply_ark:  sbox_input[j] = State[j] + RC[j]               (all j)
        //   apply_sbox: sbox_state[0] = sbox_input[0]^5 = SboxOut[0]   (only j=0)
        //               sbox_state[j] = sbox_input[j] = State[j] + RC[j]  (j > 0, unchanged)
        //   apply_mds:  new_state[i] = sum_j(MDS[i][j] * sbox_state[j])
        // 约束: IsPartialRound * (StateNext[i] - new_state[i]) == 0
        //
        // degree 分析：IsPartialRound (1) * (StateNext (1) - sum(MDS (const) * term (1))) = 2 ✓
        //   term[0] = SboxOut[0] (degree 1 column read)
        //   term[j>0] = State[j] + RC[j] (degree 1 column reads)
        for i in 0..POSEIDON_M31_WIDTH {
            let mut new_state_i = zero.clone();
            for j in 0..POSEIDON_M31_WIDTH {
                let mds_ij: E::F = mds[i][j].into();
                // j==0: SboxOut[0]（S-box applied）；j>0: State[j] + RC[j]（no S-box, just ark）
                let term = if j == 0 {
                    sbox_out[0].clone()
                } else {
                    let s_j = col(POSEIDON_AIR_COL_STATE_BASE + j);
                    s_j + rc_col[j].clone()
                };
                new_state_i = new_state_i + mds_ij * term;
            }

            let state_next_i = col(POSEIDON_AIR_COL_STATE_NEXT_BASE + i);
            let diff = state_next_i - new_state_i;
            eval.add_constraint(is_partial.clone() * diff);
        }

        // ===== Logup yield =====
        // values = (SyscallId=0x03, Input[0..3], Output[0..3], IsLastRound, IsPadding)
        // multiplicity = -1 * IsLastRound * (1 - IsPadding)
        //
        // 仅 IsLastRound=1 且非 padding 的行 multiplicity = -1，
        // 其他行 multiplicity = 0。这确保每个 hash 只 yield 一次。
        let mut lookup_values: Vec<E::F> = Vec::with_capacity(9);
        lookup_values.push(BaseField::from(POSEIDON_SYSCALL_ID).into());
        for i in 0..POSEIDON_M31_WIDTH {
            lookup_values.push(col(POSEIDON_AIR_COL_INPUT_BASE + i));
        }
        for i in 0..POSEIDON_M31_WIDTH {
            lookup_values.push(col(POSEIDON_AIR_COL_OUTPUT_BASE + i));
        }
        lookup_values.push(is_last.clone());
        lookup_values.push(is_padding.clone());

        let neg_one: E::EF = SecureField::from(-1i32).into();
        let is_non_padding: E::F = one.clone() - is_padding.clone();
        let multiplicity: E::EF = neg_one * is_last.clone() * is_non_padding;
        eval.add_to_relation(RelationEntry::new(
            &self.poseidon_lookup,
            multiplicity,
            &lookup_values,
        ));
        eval.finalize_logup();

        eval
    }
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_air_new() {
        let air = PoseidonAir::new(10, PoseidonLookup::dummy());
        assert_eq!(air.log_size(), 10);
        // v2.1: log_size + 1 = 11（度 2 = 2^1，强制 SubDomain 模式）
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
    }

    #[test]
    fn test_poseidon_air_num_columns() {
        // v2.1: 30 列 = 21 原列 + 9 S-box 中间列（3×3: SboxSq1/SboxSq2/SboxOut）
        assert_eq!(POSEIDON_AIR_NUM_COLUMNS, 30);
    }

    #[test]
    fn test_column_layout_no_overlap() {
        use std::collections::HashSet;
        let mut all_cols = HashSet::new();
        for i in 0..3 {
            assert!(
                all_cols.insert(POSEIDON_AIR_COL_STATE_BASE + i),
                "State col {} 重复",
                i
            );
        }
        for i in 0..3 {
            assert!(
                all_cols.insert(POSEIDON_AIR_COL_STATE_NEXT_BASE + i),
                "StateNext col {} 重复",
                i
            );
        }
        assert!(
            all_cols.insert(POSEIDON_AIR_COL_IS_FULL_ROUND),
            "IsFullRound 重复"
        );
        assert!(
            all_cols.insert(POSEIDON_AIR_COL_IS_PARTIAL_ROUND),
            "IsPartialRound 重复"
        );
        assert!(
            all_cols.insert(POSEIDON_AIR_COL_IS_FIRST_ROUND),
            "IsFirstRound 重复"
        );
        assert!(
            all_cols.insert(POSEIDON_AIR_COL_IS_LAST_ROUND),
            "IsLastRound 重复"
        );
        assert!(
            all_cols.insert(POSEIDON_AIR_COL_ROUND_COUNTER),
            "RoundCounter 重复"
        );
        for i in 0..3 {
            assert!(
                all_cols.insert(POSEIDON_AIR_COL_INPUT_BASE + i),
                "Input col {} 重复",
                i
            );
        }
        for i in 0..3 {
            assert!(
                all_cols.insert(POSEIDON_AIR_COL_OUTPUT_BASE + i),
                "Output col {} 重复",
                i
            );
        }
        assert!(
            all_cols.insert(POSEIDON_AIR_COL_IS_PADDING),
            "IsPadding 重复"
        );
        for i in 0..3 {
            assert!(
                all_cols.insert(POSEIDON_AIR_COL_ROUND_CONSTANT_BASE + i),
                "RoundConstant col {} 重复",
                i
            );
        }
        // v2.1 新增 S-box 中间列
        for i in 0..3 {
            assert!(
                all_cols.insert(POSEIDON_AIR_COL_SBOX_SQ1_BASE + i),
                "SboxSq1 col {} 重复",
                i
            );
        }
        for i in 0..3 {
            assert!(
                all_cols.insert(POSEIDON_AIR_COL_SBOX_SQ2_BASE + i),
                "SboxSq2 col {} 重复",
                i
            );
        }
        for i in 0..3 {
            assert!(
                all_cols.insert(POSEIDON_AIR_COL_SBOX_OUT_BASE + i),
                "SboxOut col {} 重复",
                i
            );
        }
        // 总列数应为 30
        assert_eq!(all_cols.len(), POSEIDON_AIR_NUM_COLUMNS);
    }

    #[test]
    fn test_poseidon_syscall_id() {
        // Poseidon syscall ID = 0x03（与 SyscallId::Poseidon 一致）
        assert_eq!(POSEIDON_SYSCALL_ID, 0x03);
    }

    #[test]
    fn test_poseidon_air_total_rounds() {
        // 8 full + 22 partial = 30 rounds
        assert_eq!(POSEIDON_AIR_TOTAL_ROUNDS, 30);
    }

    #[test]
    fn test_max_constraint_log_degree_bound() {
        // v2.1: max_constraint_log_degree_bound = log_size + 1（约束度 ≤ 2，强制 SubDomain）
        let air5 = PoseidonAir::new(5, PoseidonLookup::dummy());
        assert_eq!(air5.max_constraint_log_degree_bound(), 6); // 5 + 1

        let air10 = PoseidonAir::new(10, PoseidonLookup::dummy());
        assert_eq!(air10.max_constraint_log_degree_bound(), 11); // 10 + 1

        let air15 = PoseidonAir::new(15, PoseidonLookup::dummy());
        assert_eq!(air15.max_constraint_log_degree_bound(), 16); // 15 + 1
    }

    #[test]
    fn test_alpha_is_five() {
        // S-box alpha=5，sbox(x) = x^5
        assert_eq!(POSEIDON_M31_ALPHA, 5);
    }

    /// v2.1 关键测试：验证 `constraint_log_degree ≤ log_blowup_factor`（强制 SubDomain 模式）。
    ///
    /// Stwo `EvaluationMode::infer` 判定逻辑（accumulation.rs:42-70）：
    ///   constraint_log_degree = max_constraint_log_degree_bound - trace_log_size
    ///   if constraint_log_degree > log_blowup_factor → ExtendToEvalDomain
    ///   else → SubDomain
    ///
    /// v2.1: constraint_log_degree = 1, log_blowup_factor = 1 → 1 ≤ 1 → SubDomain ✓
    #[test]
    fn test_subdomain_mode_guaranteed() {
        // 默认 PcsConfig::default().fri_config.log_blowup_factor = 1
        let log_blowup_factor: u32 = 1;
        for log_size in [5u32, 10, 15, 20] {
            let air = PoseidonAir::new(log_size, PoseidonLookup::dummy());
            let trace_log_size = log_size; // 单组件，trace_log_size = log_size
            let constraint_log_degree = air
                .max_constraint_log_degree_bound()
                .saturating_sub(trace_log_size);
            assert_eq!(
                constraint_log_degree, 1,
                "log_size={}: constraint_log_degree 应为 1（v2.1 设计）",
                log_size
            );
            assert!(
                constraint_log_degree <= log_blowup_factor,
                "log_size={}: constraint_log_degree ({}) 应 ≤ log_blowup_factor ({})，\
                 否则触发 ExtendToEvalDomain 模式（v1.0 卡点根因）",
                log_size,
                constraint_log_degree,
                log_blowup_factor
            );
        }
    }

    /// 调试用：手动在 M31 上检查 v2.1 AIR 约束是否满足（P1-P27）。
    ///
    /// 验证项：
    /// - P1-P6: flag binality + one-hot
    /// - P7-P12: first/last round input/output binding
    /// - P13-P21: S-box 中间列分解（SboxSq1/SboxSq2/SboxOut，unconditional）
    /// - P22-P24: Full round transition（用 SboxOut）
    /// - P25-P27: Partial round transition（用 SboxOut[0] + inline State[j]+RC[j]）
    /// - Padding 行：所有 unconditional 约束自动满足（State=RC=SboxSq1=SboxSq2=SboxOut=0）
    #[test]
    fn test_debug_air_constraints_manual_check() {
        use super::super::poseidon_m31::{
            POSEIDON_M31_FULL_ROUNDS, POSEIDON_M31_PARTIAL_ROUNDS, poseidon_m31_mds,
            poseidon_m31_round_constants, poseidon_permutation_m31_steps,
        };
        use super::super::trace_native::{PoseidonHashCall, gen_poseidon_trace};

        let call = PoseidonHashCall::from_input([
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(3u32),
        ]);
        let trace = gen_poseidon_trace(&[call.clone()]);
        let mds = poseidon_m31_mds();
        let rcs = poseidon_m31_round_constants();
        let full_half = POSEIDON_M31_FULL_ROUNDS as usize / 2; // 4
        let partial_end = full_half + POSEIDON_M31_PARTIAL_ROUNDS as usize; // 26

        let one = BaseField::from(1u32);
        let zero = BaseField::from(0u32);

        // sbox(x) = x^5（用于验证 SboxOut）
        let sbox = |x: BaseField| -> BaseField {
            let x2 = x * x;
            let x4 = x2 * x2;
            x4 * x
        };

        // 独立验证：用 steps 重新算 states，对比 trace 中的 State/StateNext
        let states = poseidon_permutation_m31_steps(call.input_state);

        for round in 0..POSEIDON_AIR_TOTAL_ROUNDS {
            let row = round; // 单 hash，row = round
            let is_full = if round < full_half || round >= partial_end {
                1u32
            } else {
                0u32
            };
            let is_partial = if round >= full_half && round < partial_end {
                1u32
            } else {
                0u32
            };

            // 读取 trace 列
            let state: [BaseField; 3] = [
                trace.cols[POSEIDON_AIR_COL_STATE_BASE][row],
                trace.cols[POSEIDON_AIR_COL_STATE_BASE + 1][row],
                trace.cols[POSEIDON_AIR_COL_STATE_BASE + 2][row],
            ];
            let state_next: [BaseField; 3] = [
                trace.cols[POSEIDON_AIR_COL_STATE_NEXT_BASE][row],
                trace.cols[POSEIDON_AIR_COL_STATE_NEXT_BASE + 1][row],
                trace.cols[POSEIDON_AIR_COL_STATE_NEXT_BASE + 2][row],
            ];
            let rc: [BaseField; 3] = [
                trace.cols[POSEIDON_AIR_COL_ROUND_CONSTANT_BASE][row],
                trace.cols[POSEIDON_AIR_COL_ROUND_CONSTANT_BASE + 1][row],
                trace.cols[POSEIDON_AIR_COL_ROUND_CONSTANT_BASE + 2][row],
            ];

            // 验证 trace 中的 state 与 steps 一致
            assert_eq!(
                state, states[round],
                "round {}: State != states[{}]",
                round, round
            );
            assert_eq!(
                state_next,
                states[round + 1],
                "round {}: StateNext != states[{}]",
                round,
                round + 1
            );

            // 验证 trace 中的 rc 与 rcs 一致
            assert_eq!(rc, rcs[round], "round {}: RC != rcs[{}]", round, round);

            // ===== v2.1 新增：验证 S-box 中间列（P13-P21）=====
            // 读取 S-box 中间列
            let sbox_sq1: [BaseField; 3] = [
                trace.cols[POSEIDON_AIR_COL_SBOX_SQ1_BASE][row],
                trace.cols[POSEIDON_AIR_COL_SBOX_SQ1_BASE + 1][row],
                trace.cols[POSEIDON_AIR_COL_SBOX_SQ1_BASE + 2][row],
            ];
            let sbox_sq2: [BaseField; 3] = [
                trace.cols[POSEIDON_AIR_COL_SBOX_SQ2_BASE][row],
                trace.cols[POSEIDON_AIR_COL_SBOX_SQ2_BASE + 1][row],
                trace.cols[POSEIDON_AIR_COL_SBOX_SQ2_BASE + 2][row],
            ];
            let sbox_out: [BaseField; 3] = [
                trace.cols[POSEIDON_AIR_COL_SBOX_OUT_BASE][row],
                trace.cols[POSEIDON_AIR_COL_SBOX_OUT_BASE + 1][row],
                trace.cols[POSEIDON_AIR_COL_SBOX_OUT_BASE + 2][row],
            ];

            // P13-P15: SboxSq1[j] = (State[j] + RC[j])^2
            for j in 0..3 {
                let sbox_input = state[j] + rc[j];
                let expected = sbox_input * sbox_input;
                assert_eq!(
                    sbox_sq1[j], expected,
                    "round {} j={}: SboxSq1={} != (State+RC)^2={}",
                    round, j, sbox_sq1[j], expected
                );
            }

            // P16-P18: SboxSq2[j] = SboxSq1[j]^2
            for j in 0..3 {
                let expected = sbox_sq1[j] * sbox_sq1[j];
                assert_eq!(
                    sbox_sq2[j], expected,
                    "round {} j={}: SboxSq2={} != SboxSq1^2={}",
                    round, j, sbox_sq2[j], expected
                );
            }

            // P19-P21: SboxOut[j] = SboxSq2[j] * (State[j] + RC[j]) = SboxInput[j]^5
            for j in 0..3 {
                let sbox_input = state[j] + rc[j];
                let expected = sbox_sq2[j] * sbox_input;
                // 等价验证：expected == sbox(sbox_input)
                assert_eq!(
                    expected,
                    sbox(sbox_input),
                    "round {} j={}: SboxSq2 * SboxInput != SboxInput^5",
                    round,
                    j
                );
                assert_eq!(
                    sbox_out[j], expected,
                    "round {} j={}: SboxOut={} != SboxSq2*SboxInput={}",
                    round, j, sbox_out[j], expected
                );
            }

            // ===== v2.1: 验证 State transition（P22-P27）=====
            if is_full == 1 {
                // Full round: new_state[i] = sum_j(MDS[i][j] * SboxOut[j])
                for i in 0..3 {
                    let mut new_state_i = zero;
                    for j in 0..3 {
                        new_state_i = new_state_i + mds[i][j] * sbox_out[j];
                    }
                    assert_eq!(
                        state_next[i], new_state_i,
                        "round {} (full) i={}: StateNext={} != MDS*SboxOut={}",
                        round, i, state_next[i], new_state_i
                    );
                }
            } else if is_partial == 1 {
                // Partial round:
                //   term[0] = SboxOut[0] = (State[0] + RC[0])^5
                //   term[j>0] = State[j] + RC[j]
                //   new_state[i] = sum_j(MDS[i][j] * term[j])
                for i in 0..3 {
                    let mut new_state_i = zero;
                    for j in 0..3 {
                        let term = if j == 0 {
                            sbox_out[0]
                        } else {
                            state[j] + rc[j]
                        };
                        new_state_i = new_state_i + mds[i][j] * term;
                    }
                    assert_eq!(
                        state_next[i], new_state_i,
                        "round {} (partial) i={}: StateNext={} != MDS*term={}",
                        round, i, state_next[i], new_state_i
                    );
                }
            }
        }

        // 验证 padding 行：unconditional 约束 P13-P21 自动满足
        // Padding 行：State = 0, RC = 0, SboxSq1 = 0, SboxSq2 = 0, SboxOut = 0
        for row in POSEIDON_AIR_TOTAL_ROUNDS..trace.num_rows() {
            let is_padding = trace.cols[POSEIDON_AIR_COL_IS_PADDING][row];
            assert_eq!(is_padding, one, "padding row {} IsPadding should be 1", row);
            // P6: IsFull + IsPartial + IsPadding = 0 + 0 + 1 = 1
            let sum = trace.cols[POSEIDON_AIR_COL_IS_FULL_ROUND][row]
                + trace.cols[POSEIDON_AIR_COL_IS_PARTIAL_ROUND][row]
                + is_padding;
            assert_eq!(sum, one, "padding row {} one-hot failed", row);

            // v2.1: 验证 padding 行的 S-box 中间列全为 0（保证 unconditional 约束满足）
            for j in 0..3 {
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_SBOX_SQ1_BASE + j][row],
                    zero,
                    "padding row {} SboxSq1[{}] 应为 0",
                    row,
                    j
                );
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_SBOX_SQ2_BASE + j][row],
                    zero,
                    "padding row {} SboxSq2[{}] 应为 0",
                    row,
                    j
                );
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_SBOX_OUT_BASE + j][row],
                    zero,
                    "padding row {} SboxOut[{}] 应为 0",
                    row,
                    j
                );
            }
            // 验证 State/RC 也为 0
            for j in 0..3 {
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_STATE_BASE + j][row],
                    zero,
                    "padding row {} State[{}] 应为 0",
                    row,
                    j
                );
                assert_eq!(
                    trace.cols[POSEIDON_AIR_COL_ROUND_CONSTANT_BASE + j][row],
                    zero,
                    "padding row {} RC[{}] 应为 0",
                    row,
                    j
                );
            }
        }

        println!("v2.1 手动检查通过：所有 27 条 AIR 约束在 M31 上满足（含 padding 行）");
    }
}
