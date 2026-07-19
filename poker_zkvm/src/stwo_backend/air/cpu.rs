//! # CPU AIR 组件 — RV32I 指令约束
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"Phase 1.2" 与 §"Phase 2.1"：
//! - Phase 1.2：实现 `CpuAirEval`（`FrameworkEval`，仅 step_index 连续性约束，对应 Group A）
//! - Phase 2.1：完整算术指令约束（LUI/AUIPC/ADDI/.../SRA）
//! - Phase 2.2：控制流约束（JAL/JALR/BEQ/.../BGEU）
//!
//! ## 当前状态（Phase 1.2）
//!
//! `CpuAirEval` 实现 `FrameworkEval`，由 `FrameworkComponent<CpuAirEval>` 自动生成
//! `Component` + `ComponentProver<SimdBackend>` 实现。当前仅包含 Group A 约束
//!（step_index 连续性），用于 POC 验证 M31 field 性能。

use crate::error::ZkvmError;

use super::super::trace::StwoTraceTable;
use super::opcode_table::OpcodeLookupElements;
use super::StwoAirComponent;

// Stwo FrameworkEval 相关导入
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{
    preprocessed_columns::PreProcessedColumnId, EvalAtRow, FrameworkEval, ORIGINAL_TRACE_IDX,
    RelationEntry,
};

/// CPU AIR 组件（RV32I 指令约束）。
///
/// 对应 Hypernova CCS 的 49-matrix 结构（[`crate::constraints::NUM_CCS_MATRICES`]），
/// Stwo 迁移后改为独立的 AIR component，通过 LogUp 连接其他组件。
///
/// ## 约束组对应关系（来自 [`crate::constraints::mod.rs`]）
///
/// | CCS Group | 约束内容 | Stwo AIR 表达 |
/// |-----------|---------|---------------|
/// | A | step_index 连续性 | `transition: idx[i+1] - idx[i] - 1 == 0` |
/// | B | PC 连续性 | `transition: pc[i+1] - next_pc[i] == 0` |
/// | C | selector one-hot | `boundary + transition: sum(sel_*) == 1` |
/// | D | selector 二值性 | `range_check: sel * (sel - 1) == 0` |
/// | E | 算术/逻辑/移位语义 | `transition` per-instruction |
/// | F | carry 二值性 | `range_check: carry * (carry - 1) == 0` |
#[derive(Clone, Debug, Default)]
pub struct CpuAirComponent {
    /// trace 行数（须为 2 的幂）。
    pub num_rows: usize,
}

impl CpuAirComponent {
    /// 创建新 CPU AIR 组件。
    pub fn new(num_rows: usize) -> Self {
        Self { num_rows }
    }
}

impl StwoAirComponent for CpuAirComponent {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn num_columns(&self) -> usize {
        // Phase 2.2：13 列精简布局（12 数据列 + 1 opcode），
        // 替代 Hypernova `STEP_VARS = 47`（含 35 列 one-hot selector）。
        // 详见 `stwo_backend/column_layout.rs`。
        crate::stwo_backend::column_layout::NUM_COLUMNS
    }

    fn num_rows(&self) -> usize {
        self.num_rows
    }

    fn evaluate_transition(&self, _trace: &StwoTraceTable) -> Result<Vec<super::super::field::M31>, ZkvmError> {
        // TODO(Phase 2.1): 实现 Group A-F 完整约束
        // Phase 1.2 改用 CpuAirEval (FrameworkEval) 实现真实 Stwo 约束
        Err(ZkvmError::Other(
            "CpuAirComponent::evaluate_transition 已迁移至 CpuAirEval::evaluate — Phase 2.1".to_string(),
        ))
    }
}

/// CPU AIR 约束评估器（Phase 2.3.3-a：Group A + B + C LogUp claim + E LUI dispatch）。
///
/// 实现 [`FrameworkEval`]，由 `FrameworkComponent<CpuAirEval>` 自动生成
/// `Component` + `ComponentProver<SimdBackend>` 实现，免手写 6 个底层方法。
///
/// # 约束范围
///
/// ## Group A — step_index 连续性（Phase 2.1）
///
/// **约束**：`(idx_next - idx_cur - 1) * (1 - is_last_row) == 0`
/// - 非末行（`is_last_row=0`）：`idx_next - idx_cur - 1 == 0`（step_index 连续递增）
/// - 末行（`is_last_row=1`）：约束乘以 0，自动满足（cyclic 边界豁免）
///
/// ## Group B — PC 连续性（Phase 2.3.1）
///
/// **约束**：`(pc_next - next_pc_cur) * (1 - is_last_row) == 0`
/// - 非末行：`pc_next == next_pc_cur`（下一行 pc 等于当前行 next_pc）
/// - 末行：约束乘以 0，自动满足
///
/// ## Group C — opcode range check via LogUp claim（Phase 2.3.2）
///
/// CPU 侧声明 LogUp claim：每行贡献 `+1 / (opcode - z)`。
/// 配合 [`super::opcode_table::OpcodeTableEval`]（table 侧 yield `-count_j / (j - z)`），
/// 通过 LogUp 协议证明 CPU trace 中所有 opcode ∈ [0, 34]。
///
/// 替代 Hypernova 的 Group C（`Σ_j sel_j - 1 = 0`）和 Group D（`sel_j² - sel_j = 0`）。
///
/// ## Group E — opcode dispatch via indicator（Phase 2.3.3-a：仅 LUI）
///
/// **LUI 约束**：`is_lui * (rd_val - imm) == 0`
/// - `is_lui` 为 preprocessed column（值 = 1 if opcode[row]==0 else 0）
/// - LUI 语义：`rd = imm`（高 20 位立即数加载到寄存器）
/// - 在 M31 域中，约束等价于 `is_lui * (rd_val_m31 - imm_m31) == 0`
/// - `rd_val_m31 = rd_val_u32 & 0x3FFFFFFF`（30-bit limb 掩码）
/// - `imm_m31 = imm_u32 & 0x3FFFFFFF`（30-bit limb 掩码）
/// - 因 LUI 指令 `rd_val_u32 == imm_u32`，故 `rd_val_m31 == imm_m31`，约束成立 ✓
///
/// **Phase 2.3.3 后续子阶段**：扩展到其他指令（AUIPC/ADDI/.../SRA），通过添加对应
/// preprocessed indicator column（`is_auipc`/`is_addi`/...）实现完整 Group E。
///
/// # trace 列布局（Phase 2.2 精简后）
///
/// 13 列（对应 [`crate::stwo_backend::column_layout::NUM_COLUMNS`]）：
/// `[idx, pc, next_pc, rs1_val, rs2_val, rd_val, imm, carry, taken, shamt, branch_cond, aux, opcode]`
///
/// - col 0-11：数据列，与 Hypernova `STEP_VARS` 前 12 列 1:1 映射
/// - col 12：opcode（0-34），替代 35 列 one-hot selector
///
/// Group A/B 约束 col 0-2，Group C LogUp claim 读取 col 12（opcode），
/// Group E LUI 约束读取 col 5 (rd_val) + col 6 (imm) + preprocessed `is_lui`。
pub struct CpuAirEval {
    /// trace 行数的 log2（如 1024 行 → log_size = 10）。
    pub log_size: u32,
    /// Opcode lookup 的随机挑战元素（z, alpha），从 channel 抽取。
    /// 用于 Group C LogUp claim：`combine([opcode]) = opcode - z`。
    pub opcode_lookup: OpcodeLookupElements,
}

impl CpuAirEval {
    /// 创建新 CPU AIR 评估器。
    ///
    /// # 参数
    /// - `log_size` — trace 行数的 log2
    /// - `opcode_lookup` — Opcode LogUp 随机挑战（z, alpha），由 prover 在 original trace
    ///   commit 后从 channel 抽取；测试中可用 [`OpcodeLookupElements::dummy()`]
    pub fn new(log_size: u32, opcode_lookup: OpcodeLookupElements) -> Self {
        Self {
            log_size,
            opcode_lookup,
        }
    }

    /// `is_last_row` preprocessed column 的 ID。
    /// 末行 = 1，其余 = 0，用于 Group A/B cyclic 边界豁免。
    pub const IS_LAST_ROW_COL_ID: &'static str = "cpu_is_last_row";

    /// `is_lui` preprocessed column 的 ID（Phase 2.3.3-a）。
    ///
    /// 值 = 1 if `opcode[row] == 0`（LUI），else 0。
    /// 用于 Group E LUI 约束的 indicator gating：
    /// `is_lui * (rd_val - imm) == 0`，仅当本行为 LUI 指令时强制语义约束。
    pub const IS_LUI_COL_ID: &'static str = "cpu_is_lui";

    /// `is_auipc` preprocessed column 的 ID（Phase 2.3.3-b）。
    ///
    /// 值 = 1 if `opcode[row] == 1`（AUIPC），else 0。
    /// 用于 Group E AUIPC 约束的 indicator gating：
    /// `is_auipc * (rd_val - pc - imm) == 0`，仅当本行为 AUIPC 指令时强制语义约束。
    pub const IS_AUIPC_COL_ID: &'static str = "cpu_is_auipc";

    /// `is_slt` preprocessed column 的 ID（Phase 2.3.3-b）。
    ///
    /// 值 = 1 if `opcode[row] ∈ {13, 14, 24, 25}`（SLTI/SLTIU/SLT/SLTU），else 0。
    /// 这 4 条指令共享同一约束形式 `rd_val - carry == 0`（carry 为比较结果 0/1），
    /// 故使用单个 group indicator 覆盖，减少 preprocessed 列数。
    pub const IS_SLT_COL_ID: &'static str = "cpu_is_slt";

    /// `is_logical_shift` preprocessed column 的 ID（Phase 2.3.3-b）。
    ///
    /// 值 = 1 if `opcode[row] ∈ {15,16,17,18,19,20,23,26,27,28,29,30}`
    ///（XORI/ORI/ANDI/SLLI/SRLI/SRAI/SLL/XOR/SRL/SRA/OR/AND），else 0。
    /// 这 12 条逻辑/移位指令共享同一约束形式 `rd_val - aux == 0`，
    /// 故使用单个 group indicator 覆盖，减少 preprocessed 列数。
    pub const IS_LOGICAL_SHIFT_COL_ID: &'static str = "cpu_is_logical_shift";

    /// `is_addi` preprocessed column 的 ID（Phase 2.3.4-b）。
    ///
    /// 值 = 1 if `opcode[row] == 12`（ADDI），else 0。
    /// 用于 Group E ADDI 约束的 indicator gating（limb decomposition）：
    ///   - Low:  `is_addi * (rs1_low + imm - rd_val - 2^30 * carry_low) == 0`
    ///   - High: `is_addi * (rs1_high + imm_high + carry_low - rd_high - 4 * carry) == 0`
    pub const IS_ADDI_COL_ID: &'static str = "cpu_is_addi";

    /// `is_add` preprocessed column 的 ID（Phase 2.3.4-b）。
    ///
    /// 值 = 1 if `opcode[row] == 21`（ADD），else 0。
    /// 用于 Group E ADD 约束的 indicator gating（limb decomposition）：
    ///   - Low:  `is_add * (rs1_low + rs2_low - rd_val - 2^30 * carry_low) == 0`
    ///   - High: `is_add * (rs1_high + rs2_high + carry_low - rd_high - 4 * carry) == 0`
    pub const IS_ADD_COL_ID: &'static str = "cpu_is_add";

    /// `is_sub` preprocessed column 的 ID（Phase 2.3.4-b）。
    ///
    /// 值 = 1 if `opcode[row] == 22`（SUB），else 0。
    /// 用于 Group E SUB 约束的 indicator gating（limb decomposition，borrow 语义）：
    ///   - Low:  `is_sub * (rs1_low - rs2_low - rd_val + 2^30 * carry_low) == 0`
    ///   - High: `is_sub * (rs1_high - rs2_high - carry_low - rd_high + 4 * carry) == 0`
    ///
    /// **注意**：SUB 中 `carry` 列表示 borrow bit（=1 表示借位），与 ADD 中 `carry` 列表示
    /// overflow bit 语义不同，但 Group F 二值性约束对两者都适用。
    /// `carry_low` 在 SUB 中表示 low limb 的 borrow bit（borrow_low）。
    pub const IS_SUB_COL_ID: &'static str = "cpu_is_sub";

    /// `is_jal` preprocessed column 的 ID（Phase 2.3.3-c）。
    ///
    /// 值 = 1 if `opcode[row] == 2`（JAL），else 0。
    /// 用于 Group E JAL 约束的 indicator gating：
    ///   `is_jal * (next_pc - pc - imm) == 0`
    /// 仅当本行为 JAL 指令时强制 `next_pc == pc + imm`（JAL 语义：无条件跳转 rd = pc+4, pc = pc+imm）。
    pub const IS_JAL_COL_ID: &'static str = "cpu_is_jal";

    /// `is_branch` preprocessed column 的 ID（Phase 2.3.3-c）。
    ///
    /// 值 = 1 if `opcode[row] ∈ {4, 5, 6, 7, 8, 9}`（BEQ/BNE/BLT/BGE/BLTU/BGEU），else 0。
    /// 用于 Group F 扩展约束的 indicator gating：
    ///   `(1 - is_branch) * taken == 0`
    /// 确保 `taken` 列仅在分支指令行可为 1，非分支指令行 `taken` 必须为 0。
    ///
    /// **注意**：Phase 2.3.3-c 暂不添加分支目标约束（`taken * (next_pc - pc - imm)` 形式
    /// 为 degree 3，会改变 `max_constraint_log_degree_bound`）。分支目标约束留待
    /// Phase 2.3.3-d（需引入辅助列或 degree-3 bound 调整）。
    pub const IS_BRANCH_COL_ID: &'static str = "cpu_is_branch";
}

/// 计算 CircleDomain ordering 中 row 的"下一行"索引（自然顺序 row）。
///
/// 复刻 `AssertEvaluator::next_interaction_mask` 的 `off=1` 逻辑：
/// ```text
/// coset_index = circle_domain_index_to_coset_index(bit_reverse_index(row, log_size), log_size)
/// next_coset_index = (coset_index + 1) rem domain_size
/// next_row = bit_reverse_index(
///     coset_index_to_circle_domain_index(next_coset_index, log_size), log_size)
/// ```
///
/// 此函数用于：
/// - Phase 2.1c：`assert_constraints_on_trace` 单元测试（`AssertEvaluator`）
/// - Phase 2.1d：`prover.rs` 中构造满足 Group A 约束的 trace（`SimdDomainEvaluator`）
///
/// 两者都期望 trace 按 CircleDomain ordering 排列：`idx[row] = position`，
/// 其中 `position` 是 row 在 CircleDomain order 中的位置（通过此函数遍历得到）。
pub(crate) fn circle_domain_next_row(row: usize, log_size: u32) -> usize {
    use stwo::core::utils::{
        bit_reverse_index, circle_domain_index_to_coset_index,
        coset_index_to_circle_domain_index,
    };
    let domain_size = 1usize << log_size;
    let coset_index =
        circle_domain_index_to_coset_index(bit_reverse_index(row, log_size), log_size);
    let next_coset_index = (coset_index as isize + 1).rem_euclid(domain_size as isize) as usize;
    let next_circle_index = coset_index_to_circle_domain_index(next_coset_index, log_size);
    bit_reverse_index(next_circle_index, log_size)
}

/// 构造 `row_to_position` 映射：`row_to_position[row]` = row 在 CircleDomain order 中的 position。
///
/// 遍历 CircleDomain order（从 row=0 开始，每步调用 `circle_domain_next_row`），
/// 记录每个自然顺序 row 的 position。
///
/// 此映射用于将 trace 从自然顺序转换为 CircleDomain ordering：
/// - `idx[row]` 应设为 `row_to_position[row]`（Group A 约束要求 idx 按 position 递增）
/// - `is_last_row[row]` 应设为 `1 if row_to_position[row] == n_rows - 1 else 0`
///   （末 position 对应的 row 为 1）
pub(crate) fn build_row_to_position(log_size: u32) -> Vec<usize> {
    let n_rows = 1usize << log_size;
    let mut row_to_position = vec![0usize; n_rows];
    let mut current_row = 0usize;
    for position in 0..n_rows {
        row_to_position[current_row] = position;
        current_row = circle_domain_next_row(current_row, log_size);
    }
    row_to_position
}

impl FrameworkEval for CpuAirEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Group A 约束 `(idx_next - idx_cur - 1) * (1 - is_last_row)` 为 degree 2
        //（两个线性表达式的乘积）。
        //
        // 按 Stwo book 公式：`log_size + max(1, ceil(log2(max_degree - 1)))`。
        // 对于 max_degree=2：`ceil(log2(1)) = 0`，`max(1, 0) = 1`，故 bound = log_size + 1。
        //
        // **Phase 2.1d 关键修复**：之前错误地返回 `log_size + 2`，导致：
        // 1. `EvaluationMode::infer` 返回 `ExtendToEvalDomain`（因 constraint_log_degree=2 > log_blowup_factor=1）
        // 2. verifier mask_points step = `G_{2^(L+2)}`，而 prover SimdDomainEvaluator step = `G_{2^L}`
        // 3. 两者 step 不匹配 → `ConstraintsNotSatisfied`（OODS 检查失败）
        //
        // 修正为 `log_size + 1` 后：
        // - `EvaluationMode::infer` 返回 `SubDomain { log_expansion: 0 }`（因 1 > 1 为 false）
        // - verifier step = `G_{2^L}`，与 prover step 一致 ✓
        // - 无需 `set_store_polynomials_coefficients()`（SubDomain 直接借用 committed evals）
        // - 无需显式 `lifting_log_size`（所有 tree commitment domain 大小一致）
        //
        // Phase 2.3.3-a：新增 Group E LUI 约束 `is_lui * (rd_val - imm)` 也是 degree 2，
        // bound 仍为 log_size + 1（与 Group A/B/C LogUp cumsum 约束一致）。
        // Phase 2.3.3-b：新增 Group E AUIPC/SLT/logical_shift 约束均为 degree 2，bound 不变。
        // Phase 2.3.4-a：新增 Group F 约束 `carry * (carry - 1)` 也是 degree 2，bound 不变。
        // Phase 2.3.4-b：新增 Group F `carry_low * (carry_low - 1)` + Group E ADD/ADDI/SUB
        //（各 2 个 limb 约束，形式 `is_* * (linear_expr)`）均为 degree 2，bound 不变。
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Phase 2.2：基于 13 列精简布局重写（替代 Phase 2.1d 的 47 列 mask 注册）。
        //
        // Phase 2.1：真实 Group A 约束 — step_index 连续性
        // Phase 2.3.1：真实 Group B 约束 — PC 连续性
        //
        // Group A 约束：`(idx_next - idx_cur - 1) * (1 - is_last_row) == 0`
        // - 非末行（is_last_row=0）：idx_next - idx_cur - 1 == 0（idx 连续递增）
        // - 末行（is_last_row=1）：约束乘以 0，自动满足（cyclic 边界豁免）
        //
        // Group B 约束：`(pc_next - next_pc_cur) * (1 - is_last_row) == 0`
        // - 非末行：pc_next == next_pc_cur（下一行的 pc 等于当前行的 next_pc）
        // - 末行：约束乘以 0，自动满足（cyclic 边界豁免）
        //
        // ORIGINAL_TRACE_IDX = 1（Stwo 约定：preprocessed=0, original=1, interaction=2）
        //
        // **关键**：必须为 trace 的每一列（`column_layout::NUM_COLUMNS = 13`）注册 mask。
        // Stwo 的 `CommitmentSchemeProver::build_weights_hash_map` 调用
        // `polynomials().zip_cols(sampled_points)`，要求两者每树列数完全一致。
        // 若仅注册部分列，`itertools::zip_eq` 会在 `zip_cols` 内层 panic。
        //
        // 列布局（见 `stwo_backend/column_layout.rs`）：
        //   col 0=idx, 1=pc, 2=next_pc, 3=rs1_val, 4=rs2_val, 5=rd_val,
        //   col 6=imm, 7=carry, 8=taken, 9=shamt, 10=branch_cond, 11=aux, 12=opcode
        let one: E::F = BaseField::from(1u32).into();

        // col 0 = idx，Group A 约束需要 [0, 1] 两个行偏移（当前行 + 下一行）
        let [idx_cur, idx_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);

        // col 1 = pc，Group B 约束需要 [0, 1] 两个行偏移（当前行 pc + 下一行 pc_next）
        let [pc_cur, pc_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);

        // col 2 = next_pc，Group B 约束需要 [0]（当前行 next_pc_cur）
        let [next_pc_cur] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);

        // col 3-11：注册 mask 但不参与 Group A/B/C 约束
        //（Stwo 要求所有已提交列在 sampled_points 中有条目）
        // Phase 2.3.3+ 将使用这些列实现 Group E/F 约束：
        //   - Group E: opcode dispatch via indicator（使用 rs1_val/rs2_val/rd_val/imm/...）
        //   - Group F: carry (col 7) 二值性
        // Phase 2.3.4-b：rs1_val/rs2_val 现已供 Group E ADD/ADDI/SUB 约束使用（low limb）
        let [rs1_val] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 3: rs1_val
        let [rs2_val] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 4: rs2_val
        // Phase 2.3.3-a：col 5 (rd_val) 与 col 6 (imm) 供 Group E LUI 约束使用
        let [rd_val] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 5: rd_val
        let [imm] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 6: imm
        // Phase 2.3.3-b：col 7 (carry) 供 Group E SLT 约束使用
        // Phase 2.3.4-b：col 7 (carry) 还供 Group E ADD/ADDI/SUB high limb 约束使用
        let [carry] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 7: carry
        // Phase 2.3.3-c：col 8 (taken) 供 Group F taken 二值性 + non-branch taken=0 约束使用
        let [taken] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 8: taken
        let [_] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 9: shamt
        let [_] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 10: branch_cond
        // Phase 2.3.3-b：col 11 (aux) 供 Group E logical/shift 约束使用
        let [aux] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 11: aux

        // col 12: opcode — Phase 2.3.2 Group C LogUp claim
        // 读取 opcode 值，声明 LogUp 条目：multiplicity = +1（"claim/use"），
        // 即 CPU 侧贡献 `+1 / (opcode - z)` 到 LogUp 累积和。
        // 配合 OpcodeTableEval（yield `-count_j / (j - z)`），证明所有 opcode ∈ [0, 34]。
        let [opcode_val] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 12: opcode

        // Phase 2.3.4-b：col 13-17（limb decomposition 列）
        // - col 13 (rs1_high): rs1_val 高 2 bit limb
        // - col 14 (rs2_high): rs2_val 高 2 bit limb
        // - col 15 (rd_high):  rd_val 高 2 bit limb
        // - col 16 (imm_high): imm 高 2 bit limb
        // - col 17 (carry_low): low limb 进位位（ADD/ADDI）或借位位（SUB）
        //
        // 这些列由 `map_step_vars_to_stwo` 从 Hypernova witness 提取（high limb = v >> 30，
        // carry_low 默认 0，prover 在 ADDI/ADD/SUB 行根据 low limb 加法结果设置）。
        //
        // 当前 Phase 2.3.4-b：仅在 cpu.rs 单元测试中验证约束形式正确，
        // prover.rs 中 trace 构造仍使用默认 carry_low=0（map_step_vars_to_stwo 行为），
        // 故 e2e 测试中若 trace 含 ADD/ADDI/SUB 指令且 low limb 溢出，约束将失败。
        // 后续 Phase 2.3.4-c/d 将扩展 prover.rs 在 trace 构造时正确填充 carry_low。
        let [rs1_high] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 13: rs1_high
        let [rs2_high] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 14: rs2_high
        let [rd_high] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 15: rd_high
        let [imm_high] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 16: imm_high
        let [carry_low] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]); // col 17: carry_low

        // is_last_row preprocessed column（末行=1，其余=0）
        let is_last_row = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_LAST_ROW_COL_ID.into(),
        });

        // Phase 2.3.3-a：is_lui preprocessed column（LUI 行=1，其余=0）
        // 用于 Group E LUI 约束的 indicator gating：`is_lui * (rd_val - imm) == 0`
        let is_lui = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_LUI_COL_ID.into(),
        });

        // Phase 2.3.3-b：is_auipc preprocessed column（AUIPC 行=1，其余=0）
        // 用于 Group E AUIPC 约束：`is_auipc * (rd_val - pc - imm) == 0`
        let is_auipc = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_AUIPC_COL_ID.into(),
        });

        // Phase 2.3.3-b：is_slt preprocessed column（SLTI/SLTIU/SLT/SLTU 行=1，其余=0）
        // 用于 Group E SLT 约束：`is_slt * (rd_val - carry) == 0`（carry 为比较结果 0/1）
        let is_slt = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_SLT_COL_ID.into(),
        });

        // Phase 2.3.3-b：is_logical_shift preprocessed column
        //（XORI/ORI/ANDI/SLLI/SRLI/SRAI/SLL/XOR/SRL/SRA/OR/AND 行=1，其余=0）
        // 用于 Group E logical/shift 约束：`is_logical_shift * (rd_val - aux) == 0`
        let is_logical_shift = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_LOGICAL_SHIFT_COL_ID.into(),
        });

        // Phase 2.3.4-b：is_addi preprocessed column（ADDI 行=1，其余=0）
        // 用于 Group E ADDI 约束（limb decomposition）：
        //   - Low:  `is_addi * (rs1_val + imm - rd_val - 2^30 * carry_low) == 0`
        //   - High: `is_addi * (rs1_high + imm_high + carry_low - rd_high - 4 * carry) == 0`
        let is_addi = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_ADDI_COL_ID.into(),
        });

        // Phase 2.3.4-b：is_add preprocessed column（ADD 行=1，其余=0）
        // 用于 Group E ADD 约束（limb decomposition）：
        //   - Low:  `is_add * (rs1_val + rs2_val - rd_val - 2^30 * carry_low) == 0`
        //   - High: `is_add * (rs1_high + rs2_high + carry_low - rd_high - 4 * carry) == 0`
        let is_add = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_ADD_COL_ID.into(),
        });

        // Phase 2.3.4-b：is_sub preprocessed column（SUB 行=1，其余=0）
        // 用于 Group E SUB 约束（limb decomposition，borrow 语义）：
        //   - Low:  `is_sub * (rs1_val - rs2_val - rd_val + 2^30 * carry_low) == 0`
        //   - High: `is_sub * (rs1_high - rs2_high - carry_low - rd_high + 4 * carry) == 0`
        let is_sub = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_SUB_COL_ID.into(),
        });

        // Phase 2.3.3-c：is_jal preprocessed column（JAL 行=1，其余=0）
        // 用于 Group E JAL 约束：`is_jal * (next_pc - pc - imm) == 0`
        // JAL 语义：无条件跳转，next_pc = pc + imm
        let is_jal = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_JAL_COL_ID.into(),
        });

        // Phase 2.3.3-c：is_branch preprocessed column
        //（BEQ/BNE/BLT/BGE/BLTU/BGEU 行=1，其余=0）
        // 用于 Group F 扩展约束：`(1 - is_branch) * taken == 0`
        // 确保 taken 列仅在分支指令行可为 1，非分支指令行 taken 必须为 0。
        let is_branch = eval.get_preprocessed_column(PreProcessedColumnId {
            id: Self::IS_BRANCH_COL_ID.into(),
        });

        // Group A 约束：(idx_next - idx_cur - 1) * (1 - is_last_row) == 0
        // 注意：E::F 不实现 Copy，需 clone（EvalAtRow::F: Clone 是 trait bound）
        let diff_a = idx_next - idx_cur - one.clone();
        let mask = one.clone() - is_last_row.clone();
        eval.add_constraint(diff_a * mask);

        // Group B 约束（Phase 2.3.1）：(pc_next - next_pc_cur) * (1 - is_last_row) == 0
        // - pc_cur 暂未直接使用，但已注册 mask 供后续 Group E（指令语义）使用
        // - pc_next = 下一行的 pc 列值
        // - next_pc_cur = 当前行的 next_pc 列值
        // - 末行豁免：is_last_row=1 时约束乘以 0
        let diff_b = pc_next - next_pc_cur.clone();
        let mask_b = one.clone() - is_last_row;
        eval.add_constraint(diff_b * mask_b);

        // pc_cur 供 Phase 2.3.3-b Group E AUIPC 约束使用（rd_val - pc_cur - imm）

        // Group C 约束（Phase 2.3.2）：opcode range check via LogUp claim
        //
        // CPU 侧声明 LogUp 条目：`+1 / (opcode - z)`。
        // - multiplicity = +1（"claim/use"，表示 CPU 中出现一次该 opcode）
        // - values = [opcode_val]
        // - combine([opcode_val]) = opcode_val - z（N=1，alpha^0 = 1）
        //
        // `finalize_logup()` 生成 cumsum 约束：
        //   (cur_cumsum - prev_row_cumsum + cumsum_shift) * (opcode - z) - 1 == 0
        //
        // 其中 `cumsum_shift = claimed_sum_cpu / n_rows`，由 `LogupAtRow` 管理。
        // interaction trace 中须有 4 个 BaseField 列（1 SecureField cumsum）供此约束读取。
        //
        // 注意：multiplicity 必须是 E::EF 类型。`E::EF: From<E::F>` + `E::F: From<BaseField>`
        // 允许通过 `E::EF::from(one)` 构造 +1 的 SecureField 表示。
        // Phase 2.3.4-a：one 在 Group F 约束中再次使用（`carry - one`），故此处 clone。
        let one_ef: E::EF = E::EF::from(one.clone());
        eval.add_to_relation(RelationEntry::new(
            &self.opcode_lookup,
            one_ef,
            &[opcode_val],
        ));
        eval.finalize_logup();

        // Group E 约束（Phase 2.3.3-a）：LUI opcode dispatch via indicator
        //
        // `is_lui * (rd_val - imm) == 0`
        // - is_lui = 1（本行为 LUI 指令）：强制 rd_val == imm（LUI 语义：rd = imm）
        // - is_lui = 0（本行非 LUI）：约束乘以 0，自动满足
        //
        // LUI 语义在 M31 域中的表达：
        // - Hypernova 中 `rd_val_u32 == imm_u32`（compile_step_witness 保证）
        // - Stwo 中 `rd_val_m31 = rd_val_u32 & 0x3FFFFFFF`，`imm_m31 = imm_u32 & 0x3FFFFFFF`
        // - 因 LUI 指令 `rd_val_u32 == imm_u32`，故 `rd_val_m31 == imm_m31`，约束成立 ✓
        //
        // 约束 degree = 2（is_lui 线性 × (rd_val - imm) 线性），
        // max_constraint_log_degree_bound 仍为 log_size + 1（与 Group A/B/C 一致）。
        let diff_e_lui = rd_val.clone() - imm.clone();
        eval.add_constraint(is_lui * diff_e_lui);

        // Group E 约束（Phase 2.3.3-b）：AUIPC opcode dispatch via indicator
        //
        // `is_auipc * (rd_val - pc_cur - imm) == 0`
        // - is_auipc = 1（本行为 AUIPC 指令）：强制 rd_val == pc + imm（AUIPC 语义：rd = pc + imm）
        // - is_auipc = 0（本行非 AUIPC）：约束乘以 0，自动满足
        //
        // AUIPC 语义在 M31 域中的表达：
        // - Hypernova 中 `rd_val_u32 == pc_u32 + imm_u32`（compile_step_witness 保证）
        // - Stwo 中 30-bit limb 掩码后，`rd_val_m31 == (pc_m31 + imm_m31) mod P`
        // - 因 AUIPC 的 rd/pc/imm 值通常 < 2^30，加法不溢出 M31，约束成立 ✓
        //
        // 约束 degree = 2（is_auipc 线性 × (rd_val - pc_cur - imm) 线性）。
        let diff_e_auipc = rd_val.clone() - pc_cur.clone() - imm.clone();
        eval.add_constraint(is_auipc * diff_e_auipc);

        // Group E 约束（Phase 2.3.3-b）：SLT group dispatch via indicator
        //
        // `is_slt * (rd_val - carry) == 0`
        // - is_slt = 1（本行为 SLTI/SLTIU/SLT/SLTU）：
        //   强制 rd_val == carry（比较结果 0 或 1）
        // - is_slt = 0（本行非 SLT 组）：约束乘以 0，自动满足
        //
        // SLT 语义：rd = (rs1 < rs2) ? 1 : 0，carry 列存储比较结果
        // 在 M31 域中，rd_val_m31 ∈ {0, 1}，carry_m31 ∈ {0, 1}，约束成立 ✓
        //
        // 约束 degree = 2（is_slt 线性 × (rd_val - carry) 线性）。
        let diff_e_slt = rd_val.clone() - carry.clone();
        eval.add_constraint(is_slt * diff_e_slt);

        // Group E 约束（Phase 2.3.3-b）：logical/shift group dispatch via indicator
        //
        // `is_logical_shift * (rd_val - aux) == 0`
        // - is_logical_shift = 1（本行为 XORI/ORI/ANDI/SLLI/SRLI/SRAI/SLL/XOR/SRL/SRA/OR/AND）：
        //   强制 rd_val == aux（aux 列存储预计算的逻辑/移位结果）
        // - is_logical_shift = 0（本行非逻辑/移位组）：约束乘以 0，自动满足
        //
        // 逻辑/移位语义：rd = f(rs1, rs2/imm)（XOR/OR/AND/shift），aux 存储预计算结果
        // 在 M31 域中，rd_val_m31 == aux_m31（30-bit limb 掩码后相同值），约束成立 ✓
        //
        // 约束 degree = 2（is_logical_shift 线性 × (rd_val - aux) 线性）。
        // Phase 2.3.4-b：rd_val 还需供 ADD/ADDI/SUB 约束使用，故此处 clone。
        let diff_e_logshift = rd_val.clone() - aux;
        eval.add_constraint(is_logical_shift * diff_e_logshift);

        // Group E 约束（Phase 2.3.3-c）：JAL opcode dispatch via indicator
        //
        // `is_jal * (next_pc - pc - imm) == 0`
        // - is_jal = 1（本行为 JAL 指令）：强制 next_pc == pc + imm（JAL 语义：无条件跳转）
        // - is_jal = 0（本行非 JAL）：约束乘以 0，自动满足
        //
        // JAL 语义在 M31 域中的表达：
        // - Hypernova 中 `next_pc_u32 == pc_u32 + imm_u32`（compile_step_witness 保证）
        // - Stwo 中 30-bit limb 掩码后，`next_pc_m31 == (pc_m31 + imm_m31) mod P`
        // - 因 JAL 的 pc/imm 值通常 < 2^30，加法不溢出 M31，约束成立 ✓
        //
        // 约束 degree = 2（is_jal 线性 × (next_pc - pc - imm) 线性），
        // max_constraint_log_degree_bound 仍为 log_size + 1。
        //
        // **Hypernova 对比**：Hypernova 不约束 JAL（cat=2 不在 Group E subsets 中），
        // JAL 语义完全信任 executor。Stwo 迁移中添加此约束是安全性增强。
        let diff_e_jal = next_pc_cur.clone() - pc_cur.clone() - imm.clone();
        eval.add_constraint(is_jal * diff_e_jal);

        // Group F 约束（Phase 2.3.4-a）：carry 二值性（universal，无 indicator gating）
        //
        // `carry * (carry - 1) == 0`
        // - carry = 0: 0 * (0 - 1) = 0 ✓
        // - carry = 1: 1 * (1 - 1) = 0 ✓
        // - carry ≥ 2: carry * (carry - 1) ≠ 0 → 约束失败
        //
        // 对所有行强制 carry ∈ {0, 1}，替代 Hypernova Group F（`carry² - carry = 0`）。
        // Hypernova Group F 通过 M_D_SQ * M_D_LIN 实现二次约束，Stwo 中直接 `add_constraint` 即可。
        //
        // 用途：
        // - Group E SLT 约束 `is_slt * (rd_val - carry)` 中 carry 是比较结果（0/1），Group F 保证其二值性
        // - Phase 2.3.4-b ADDI/ADD/SUB 约束将使用 carry 作为 high limb 进位/借位，Group F 是其前置依赖
        //
        // 约束 degree = 2（carry 线性 × (carry - 1) 线性），
        // max_constraint_log_degree_bound 仍为 log_size + 1（与 Group A/B/C/E 一致）。
        // Phase 2.3.4-b：carry 还需供 ADD/ADDI/SUB high limb 约束使用，故此处 clone。
        let diff_f = carry.clone() - one.clone();
        eval.add_constraint(carry.clone() * diff_f);

        // Group F 约束（Phase 2.3.4-b）：carry_low 二值性（universal，无 indicator gating）
        //
        // `carry_low * (carry_low - 1) == 0`
        // - carry_low = 0: 0 * (0 - 1) = 0 ✓
        // - carry_low = 1: 1 * (1 - 1) = 0 ✓
        // - carry_low ≥ 2: carry_low * (carry_low - 1) ≠ 0 → 约束失败
        //
        // 对所有行强制 carry_low ∈ {0, 1}，保证 ADD/ADDI/SUB low limb 约束中 carry_low 是合法进位位。
        // carry_low 在 ADD/ADDI 中表示 low limb 加法进位（max rs1_low + rs2_low = 2*(2^30-1) < 2^31，
        // 故 carry_low ∈ {0, 1}）；在 SUB 中表示 low limb 减法借位（同理 ∈ {0, 1}）。
        //
        // 约束 degree = 2，max_constraint_log_degree_bound 仍为 log_size + 1。
        let diff_f_low = carry_low.clone() - one.clone();
        eval.add_constraint(carry_low.clone() * diff_f_low);

        // Group F 约束（Phase 2.3.3-c）：taken 二值性（universal，无 indicator gating）
        //
        // `taken * (taken - 1) == 0`
        // - taken = 0: 0 * (0 - 1) = 0 ✓
        // - taken = 1: 1 * (1 - 1) = 0 ✓
        // - taken ≥ 2: taken * (taken - 1) ≠ 0 → 约束失败
        //
        // 对所有行强制 taken ∈ {0, 1}。taken 列存储分支指令的比较结果（0=不跳转, 1=跳转），
        // 对非分支指令行 taken=0（由下方 non-branch taken=0 约束强制）。
        //
        // **Hypernova 对比**：Hypernova 不约束 taken 二值性（taken 列由 executor 计算，无约束验证）。
        // Stwo 迁移中添加此约束是安全性增强，防止攻击者伪造 taken 值。
        //
        // 约束 degree = 2，max_constraint_log_degree_bound 仍为 log_size + 1。
        let diff_f_taken = taken.clone() - one.clone();
        eval.add_constraint(taken.clone() * diff_f_taken);

        // Group F 约束（Phase 2.3.3-c）：non-branch taken=0（indicator gating）
        //
        // `(1 - is_branch) * taken == 0`
        // - is_branch = 1（本行为分支指令 BEQ/BNE/BLT/BGE/BLTU/BGEU）：
        //   约束乘以 0，自动满足（taken 可为 0 或 1，由 taken 二值性约束保证）
        // - is_branch = 0（本行非分支指令）：
        //   强制 taken == 0（非分支指令不应有 taken=1）
        //
        // 用途：防止攻击者在非分支指令行设置 taken=1（可能影响后续分支目标约束）。
        // 这是 Phase 2.3.3-d 分支目标约束的前置依赖。
        //
        // 约束 degree = 2（(1 - is_branch) 线性 × taken 线性），
        // max_constraint_log_degree_bound 仍为 log_size + 1。
        let mask_non_branch = one.clone() - is_branch;
        eval.add_constraint(mask_non_branch * taken);

        // Phase 2.3.4-b：limb decomposition 常量
        // - two_pow_30 = 2^30 = 0x40000000（M31 中 < P = 2^31-1，可直接作为常数）
        // - four = 4（high limb 进位系数，因 high limb 是 2-bit，进位模 4）
        //
        // ADD 语义：a + b = result + 2^32 * carry
        // limb decomposition：a_low + 2^30*a_high + b_low + 2^30*b_high
        //                  = result_low + 2^30*result_high + 2^30*4*carry
        // 拆为两级：
        //   Low:  a_low + b_low = result_low + 2^30 * carry_low
        //   High: a_high + b_high + carry_low = result_high + 4 * carry
        let two_pow_30: E::F = BaseField::from(1u32 << 30).into();
        let four: E::F = BaseField::from(4u32).into();

        // Group E 约束（Phase 2.3.4-b）：ADD opcode dispatch via indicator（limb decomposition）
        //
        // Low:  `is_add * (rs1_val + rs2_val - rd_val - 2^30 * carry_low) == 0`
        // High: `is_add * (rs1_high + rs2_high + carry_low - rd_high - 4 * carry) == 0`
        //
        // - is_add = 1（本行为 ADD 指令）：两级 limb 约束同时强制
        //   - Low:  rs1_low + rs2_low == rd_low + 2^30 * carry_low（low limb 加法 + 进位）
        //   - High: rs1_high + rs2_high + carry_low == rd_high + 4 * carry（high limb 加法 + 进位）
        // - is_add = 0（本行非 ADD）：约束乘以 0，自动满足
        //
        // 约束 degree = 2（is_add 线性 × linear_expr 线性），bound 不变。
        let diff_e_add_low = rs1_val.clone() + rs2_val.clone() - rd_val.clone()
            - two_pow_30.clone() * carry_low.clone();
        eval.add_constraint(is_add.clone() * diff_e_add_low);
        let diff_e_add_high = rs1_high.clone() + rs2_high.clone() + carry_low.clone()
            - rd_high.clone() - four.clone() * carry.clone();
        eval.add_constraint(is_add.clone() * diff_e_add_high);

        // Group E 约束（Phase 2.3.4-b）：ADDI opcode dispatch via indicator（limb decomposition）
        //
        // Low:  `is_addi * (rs1_val + imm - rd_val - 2^30 * carry_low) == 0`
        // High: `is_addi * (rs1_high + imm_high + carry_low - rd_high - 4 * carry) == 0`
        //
        // ADDI 与 ADD 形式相同，仅 rs2 → imm（立即数）。
        let diff_e_addi_low = rs1_val.clone() + imm.clone() - rd_val.clone()
            - two_pow_30.clone() * carry_low.clone();
        eval.add_constraint(is_addi.clone() * diff_e_addi_low);
        let diff_e_addi_high = rs1_high.clone() + imm_high + carry_low.clone()
            - rd_high.clone() - four.clone() * carry.clone();
        eval.add_constraint(is_addi.clone() * diff_e_addi_high);

        // Group E 约束（Phase 2.3.4-b）：SUB opcode dispatch via indicator（limb decomposition，borrow 语义）
        //
        // SUB 语义：a - b = result - 2^32 * borrow（borrow = 1 if a < b）
        //   即：result = a - b + 2^32 * borrow（u32 wrap-around）
        // limb decomposition：
        //   a_low + 2^30*a_high - b_low - 2^30*b_high
        //   = result_low + 2^30*result_high - 2^30*4*borrow
        // 拆为两级（注意符号方向与 ADD 相反）：
        //   Low:  a_low - b_low = result_low - 2^30 * borrow_low
        //         → a_low - b_low - result_low + 2^30 * borrow_low = 0
        //   High: a_high - b_high - borrow_low = result_high - 4 * borrow
        //         → a_high - b_high - borrow_low - result_high + 4 * borrow = 0
        //
        // 其中 carry_low 表示 borrow_low，carry 表示 borrow（最终借位）。
        //
        // Low:  `is_sub * (rs1_val - rs2_val - rd_val + 2^30 * carry_low) == 0`
        // High: `is_sub * (rs1_high - rs2_high - carry_low - rd_high + 4 * carry) == 0`
        //
        // **关键差异**（vs ADD/ADDI）：
        // - Low limb: `+ 2^30 * carry_low`（ADD 是 `-`，SUB 是 `+`，因 borrow 方向相反）
        // - High limb: `- carry_low + 4 * carry`（ADD 是 `+ carry_low - 4*carry`）
        //
        // 约束 degree = 2，bound 不变。
        let diff_e_sub_low = rs1_val.clone() - rs2_val.clone() - rd_val.clone()
            + two_pow_30.clone() * carry_low.clone();
        eval.add_constraint(is_sub.clone() * diff_e_sub_low);
        let diff_e_sub_high = rs1_high.clone() - rs2_high.clone() - carry_low.clone()
            - rd_high.clone() + four.clone() * carry.clone();
        eval.add_constraint(is_sub.clone() * diff_e_sub_high);

        // 显式 drop 未使用的变量，避免 unused_variables 警告
        //（is_addi/is_add/is_sub 在约束中使用，rd_high/imm_high 同上；rs1_high/rs2_high 亦同）
        // 此处仅标注：rs1_val/rs2_val/carry/rd_val/carry_low/two_pow_30/four 在前面已 move 出最后一项
        let _ = (rs1_val, rs2_val, rd_val, carry, carry_low, two_pow_30, four, is_add, is_addi, is_sub, rd_high);

        eval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::qm31::SecureField;

    #[test]
    fn test_cpu_air_component_construction() {
        let comp = CpuAirComponent::new(1024);
        assert_eq!(comp.name(), "cpu");
        assert_eq!(comp.num_rows(), 1024);
        // Phase 2.2：列数从 Hypernova `STEP_VARS = 47` 精简为 `NUM_COLUMNS = 13`。
        assert_eq!(
            comp.num_columns(),
            crate::stwo_backend::column_layout::NUM_COLUMNS
        );
    }

    #[test]
    fn test_cpu_air_component_default() {
        let comp = CpuAirComponent::default();
        assert_eq!(comp.num_rows, 0);
    }

    #[test]
    fn test_cpu_air_component_evaluate_returns_unimplemented() {
        let comp = CpuAirComponent::new(1024);
        let trace = StwoTraceTable::new(comp.num_columns(), comp.num_rows());
        assert!(comp.evaluate_transition(&trace).is_err());
        assert!(comp.evaluate_boundary(&trace).is_err());
    }

    // ===== Phase 1.2: CpuAirEval (FrameworkEval) 测试 =====

    #[test]
    fn test_cpu_air_eval_log_size() {
        let eval = CpuAirEval::new(10, OpcodeLookupElements::dummy());
        assert_eq!(eval.log_size(), 10);
        assert_eq!(eval.log_size, 10);
    }

    #[test]
    fn test_cpu_air_eval_max_constraint_log_degree_bound() {
        let eval = CpuAirEval::new(10, OpcodeLookupElements::dummy());
        // log_size + 1 = 11（degree-2 约束 `(idx_next - idx_cur - 1) * (1 - is_last_row)` 的 degree bound）
        // 按 Stwo book 公式：`log_size + max(1, ceil(log2(max_degree - 1)))` = `10 + max(1, 0)` = 11。
        // Phase 2.1d：从 log_size+2 修正为 log_size+1，以避免 verifier/prover step 不匹配。
        // Phase 2.3.2：LogUp 约束 `(cur_cumsum - prev_row_cumsum + shift) * (opcode - z) - 1` 也是 degree 2，
        // bound 仍为 log_size + 1。
        // Phase 2.3.3-a：Group E LUI 约束 `is_lui * (rd_val - imm)` 也是 degree 2，bound 不变。
        assert_eq!(eval.max_constraint_log_degree_bound(), 11);
    }

    #[test]
    fn test_cpu_air_eval_constraint_count_via_info() {
        // 用 InfoEvaluator 验证约束数为 15：
        //   - Group A: step_index 连续性
        //   - Group B: PC 连续性
        //   - Group C LogUp: opcode range check
        //   - Group E LUI: rd_val - imm（Phase 2.3.3-a）
        //   - Group E AUIPC: rd_val - pc - imm（Phase 2.3.3-b）
        //   - Group E SLT: rd_val - carry（Phase 2.3.3-b）
        //   - Group E logical_shift: rd_val - aux（Phase 2.3.3-b）
        //   - Group F: carry 二值性 carry * (carry - 1)（Phase 2.3.4-a）
        //   - Group F: carry_low 二值性 carry_low * (carry_low - 1)（Phase 2.3.4-b）
        //   - Group E ADD low: rs1_val + rs2_val - rd_val - 2^30 * carry_low（Phase 2.3.4-b）
        //   - Group E ADD high: rs1_high + rs2_high + carry_low - rd_high - 4 * carry（Phase 2.3.4-b）
        //   - Group E ADDI low: rs1_val + imm - rd_val - 2^30 * carry_low（Phase 2.3.4-b）
        //   - Group E ADDI high: rs1_high + imm_high + carry_low - rd_high - 4 * carry（Phase 2.3.4-b）
        //   - Group E SUB low: rs1_val - rs2_val - rd_val + 2^30 * carry_low（Phase 2.3.4-b）
        //   - Group E SUB high: rs1_high - rs2_high - carry_low - rd_high + 4 * carry（Phase 2.3.4-b）
        use stwo_constraint_framework::InfoEvaluator;
        use stwo::core::fields::qm31::SecureField;

        let eval = CpuAirEval::new(10, OpcodeLookupElements::dummy());
        // QM31 无 `zero()` 关联函数（需 num_traits::Zero trait），
        // 用 `SecureField::default()` 构造零值（Stwo InfoEvaluator::empty() 同款做法）。
        let info = eval.evaluate(InfoEvaluator::new(10, vec![], SecureField::default()));
        assert_eq!(
            info.n_constraints, 15,
            "Phase 2.3.4-b CpuAirEval 应包含 15 个约束（Group A + B + C LogUp + E LUI/AUIPC/SLT/logical_shift + F carry/carry_low 二值性 + E ADD/ADDI/SUB limb 约束 2x3）"
        );
    }

    // ===== Phase 2.1c: assert_constraints_on_trace 真实约束验证 =====
    //
    // 使用 `stwo_constraint_framework::assert_constraints_on_trace` 直接在 trace 上验证
    // Group A 约束 `(idx_next - idx_cur - 1) * (1 - is_last_row) == 0`。
    //
    // `assert_constraints_on_trace` 签名：
    //   fn(evals: &TreeVec<Vec<&Vec<M31>>>, log_size: u32,
    //      assert_func: impl Fn(AssertEvaluator<'_>) + Sync, claimed_sum: SecureField)
    //
    // evals 结构（按 interaction 索引）：
    //   evals[0] = preprocessed columns（PREPROCESSED_TRACE_IDX=0）
    //   evals[1] = original trace columns（ORIGINAL_TRACE_IDX=1）
    //
    // CpuAirEval::evaluate 的 mask 访问顺序（Phase 2.2 精简后）：
    //   1. next_interaction_mask(ORIGINAL_TRACE_IDX=1, [0, 1]) → col 0 (idx)
    //   2. 12 次 next_interaction_mask(ORIGINAL_TRACE_IDX=1, [0]) → col 1..12
    //      （col 1=pc, 2=next_pc, 3=rs1_val, 4=rs2_val, 5=rd_val, 6=imm,
    //        7=carry, 8=taken, 9=shamt, 10=branch_cond, 11=aux, 12=opcode）
    //   3. get_preprocessed_column(...) → next_interaction_mask(PREPROCESSED_TRACE_IDX=0, [0]) → col 0 (is_last_row)
    //
    // **关键**：`AssertEvaluator` 期望 trace 按 CircleDomain ordering 排列（与
    // `poly.evaluate(domain).values.to_cpu()` 一致），不是自然顺序或 BitReversedOrder。
    // CircleDomain ordering 中，"下一行"通过 `bit_reverse_index` + coset 索引转换计算。
    // 因此 `idx_col[row]` 必须设为 row 在 CircleDomain order 中的 position，
    // `is_last_row[row]` 必须在 CircleDomain order 最后一个 position 对应的 row 上为 1。

    /// 计算 CircleDomain ordering 中 row 的"下一行"索引。
    ///
    /// 复刻 `AssertEvaluator::next_interaction_mask` 的 `off=1` 逻辑：
    /// ```text
    /// coset_index = circle_domain_index_to_coset_index(bit_reverse_index(row, log_size), log_size)
    /// next_coset_index = (coset_index + 1) rem domain_size
    /// next_index = bit_reverse_index(
    ///     coset_index_to_circle_domain_index(next_coset_index, log_size), log_size)
    /// ```
    fn circle_domain_next_row(row: usize, log_size: u32) -> usize {
        use stwo::core::utils::{
            bit_reverse_index, circle_domain_index_to_coset_index,
            coset_index_to_circle_domain_index,
        };
        let domain_size = 1usize << log_size;
        let coset_index =
            circle_domain_index_to_coset_index(bit_reverse_index(row, log_size), log_size);
        let next_coset_index = (coset_index as isize + 1).rem_euclid(domain_size as isize) as usize;
        let next_circle_index =
            coset_index_to_circle_domain_index(next_coset_index, log_size);
        bit_reverse_index(next_circle_index, log_size)
    }

    /// 构造满足 Group A + Group B + Group E LUI 约束的 CircleDomain ordering trace。
    ///
    /// 返回 `(idx_col, pc_col, next_pc_col, is_last_row_col, is_lui_col, is_auipc_col,
    ///          is_slt_col, is_logical_shift_col, is_addi_col, is_add_col, is_sub_col,
    ///          zero_cols)`：
    /// - `idx_col[row]` = row 在 CircleDomain order 中的 position（0..n_rows）
    ///   使得 CircleDomain order 中"下一行"的 idx 比当前行大 1（Group A）
    /// - `pc_col[row]` = position * 4（模拟 RV32I 4 字节指令对齐）
    /// - `next_pc_col[row]` = (position + 1) * 4（下一 PC，满足 Group B: pc[next] == next_pc[cur]）
    /// - `is_last_row_col[row]` = 1 if row 是 CircleDomain order 最后一个 position，else 0
    /// - `is_lui_col[row]` = 1（所有行 opcode = 0 = LUI，故 is_lui 全为 1）
    ///   Phase 2.3.3-a：用于 Group E LUI 约束 `is_lui * (rd_val - imm) == 0`
    ///   因 zero_cols 中 col 5 (rd_val) 和 col 6 (imm) 均为 0，约束 1 * (0 - 0) = 0 ✓ 满足
    /// - `is_auipc_col[row]` = 0（所有行 opcode = 0 ≠ 1 = AUIPC，故 is_auipc 全为 0）
    ///   Phase 2.3.3-b：约束 `is_auipc * (rd_val - pc - imm)` = 0 * (...) = 0 ✓ 自动满足
    /// - `is_slt_col[row]` = 0（所有行 opcode = 0 ∉ {13,14,24,25}，故 is_slt 全为 0）
    ///   Phase 2.3.3-b：约束 `is_slt * (rd_val - carry)` = 0 * (...) = 0 ✓ 自动满足
    /// - `is_logical_shift_col[row]` = 0（所有行 opcode = 0 ∉ {15..=20,23,26..=30}，故全为 0）
    ///   Phase 2.3.3-b：约束 `is_logical_shift * (rd_val - aux)` = 0 * (...) = 0 ✓ 自动满足
    /// - `is_addi_col[row]` = 0（所有行 opcode = 0 ≠ 12 = ADDI，故 is_addi 全为 0）
    ///   Phase 2.3.4-b：约束 `is_addi * (rs1_val + imm - rd_val - 2^30 * carry_low)` = 0 * (...) = 0 ✓ 自动满足
    /// - `is_add_col[row]` = 0（所有行 opcode = 0 ≠ 21 = ADD，故 is_add 全为 0）
    ///   Phase 2.3.4-b：约束 `is_add * (rs1_val + rs2_val - rd_val - 2^30 * carry_low)` = 0 * (...) = 0 ✓ 自动满足
    /// - `is_sub_col[row]` = 0（所有行 opcode = 0 ≠ 22 = SUB，故 is_sub 全为 0）
    ///   Phase 2.3.4-b：约束 `is_sub * (rs1_val - rs2_val - rd_val + 2^30 * carry_low)` = 0 * (...) = 0 ✓ 自动满足
    /// - `zero_cols` = `NUM_COLUMNS - 3` = 15 个全零列（Phase 2.3.4-b 18 列布局 col 3-17，
    ///   不参与 Group A/B 约束但需注册 mask）。col 5 (rd_val) 和 col 6 (imm) 均为 0，
    ///   满足 Group E LUI 约束 `is_lui * (rd_val - imm) = 1 * 0 = 0`。
    ///
    /// **Group B 验证**：CircleDomain order 中 position 的下一行（position+1）对应的 row 上，
    /// `pc[next_row] = (position+1)*4`，而当前行 `next_pc[cur_row] = (position+1)*4`，两者相等 ✓
    ///
    /// **Group E LUI 验证**：所有行 opcode = 0（LUI），is_lui = 1；
    /// rd_val = imm = 0（zero_cols），约束 `1 * (0 - 0) = 0` ✓ 满足
    ///
    /// **Group E AUIPC/SLT/logical_shift/ADDI/ADD/SUB 验证**：
    /// is_auipc/is_slt/is_logical_shift/is_addi/is_add/is_sub 全为 0，
    /// 约束乘以 0 自动满足（无论 rd_val/pc/imm/carry/aux/limbs 取何值）✓
    ///
    /// **Group F carry/carry_low 验证**：carry=0, carry_low=0（zero_cols），
    /// 约束 `0 * (0 - 1) = 0` ✓ 满足
    fn build_group_ab_circle_domain_trace(
        log_size: u32,
    ) -> (
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<BaseField>,
        Vec<Vec<BaseField>>,
    ) {
        let n_rows = 1usize << log_size;
        let mut idx_col = vec![BaseField::from(0u32); n_rows];
        let mut pc_col = vec![BaseField::from(0u32); n_rows];
        let mut next_pc_col = vec![BaseField::from(0u32); n_rows];
        let mut is_last_row = vec![BaseField::from(0u32); n_rows];
        // Phase 2.3.3-a：is_lui 全为 1（所有行 opcode = 0 = LUI）
        let is_lui: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        // Phase 2.3.3-b：is_auipc / is_slt / is_logical_shift 全为 0（opcode=0 不属于这些组）
        let is_auipc: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        // Phase 2.3.4-b：is_addi / is_add / is_sub 全为 0（opcode=0 不属于这些组）
        let is_addi: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_add: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_sub: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        // Phase 2.3.4-b：zero_cols 数量 = NUM_COLUMNS - 3 = 15（col 0=idx, 1=pc, 2=next_pc 已单独构造）
        // col 3=rs1_val, 4=rs2_val, 5=rd_val, 6=imm, 7=carry, 8=taken, 9=shamt,
        // 10=branch_cond, 11=aux, 12=opcode, 13=rs1_high, 14=rs2_high, 15=rd_high,
        // 16=imm_high, 17=carry_low
        let zero_cols: Vec<Vec<BaseField>> =
            (0..crate::stwo_backend::column_layout::NUM_COLUMNS - 3)
                .map(|_| vec![BaseField::from(0u32); n_rows])
                .collect();

        // 遍历 CircleDomain order：position 0 → row 0 → next_row → ...
        let mut current_row = 0usize;
        for position in 0..n_rows {
            idx_col[current_row] = BaseField::from(position as u32);
            // PC 按 4 字节递增（模拟 RV32I 指令对齐）
            pc_col[current_row] = BaseField::from((position as u32).wrapping_mul(4));
            // next_pc = (position + 1) * 4，满足 Group B: pc[next_row] == next_pc[cur_row]
            // 注意：末行的 next_pc 不参与约束（is_last_row=1 豁免），设为 0 即可
            if position < n_rows - 1 {
                next_pc_col[current_row] = BaseField::from(((position + 1) as u32).wrapping_mul(4));
            }
            if position == n_rows - 1 {
                is_last_row[current_row] = BaseField::from(1u32);
            }
            current_row = circle_domain_next_row(current_row, log_size);
        }

        (
            idx_col,
            pc_col,
            next_pc_col,
            is_last_row,
            is_lui,
            is_auipc,
            is_slt,
            is_logical_shift,
            is_addi,
            is_add,
            is_sub,
            zero_cols,
        )
    }

    /// 为 Phase 2.3.2 LogUp 测试构造 interaction trace（evals[2]）。
    ///
    /// 当 CPU trace 的 opcode 列全为 0 时，每行 LogUp fraction 为：
    /// `frac = +1 / (combine([0]) ) = 1 / (0 - z) = -1/z`（常数，与行无关）。
    ///
    /// `claimed_sum = n_rows * frac`，`cumsum_shift = frac`，
    /// cumsum[position p] = (p+1) * frac - (p+1) * cumsum_shift = 0。
    ///
    /// 因此 interaction trace 的 cumsum 列（1 SecureField = 4 BaseField）全为 0。
    ///
    /// 返回 4 个全零 BaseField 列，代表 1 个全零 SecureField cumsum 列。
    ///
    /// # 参数
    /// - `n_rows` — trace 行数
    ///
    /// # 返回
    /// 4 个 `Vec<BaseField>`，每个长度 `n_rows`，全为 0。
    fn build_logup_interaction_trace_zero(
        n_rows: usize,
    ) -> [Vec<BaseField>; 4] {
        [
            vec![BaseField::from(0u32); n_rows],
            vec![BaseField::from(0u32); n_rows],
            vec![BaseField::from(0u32); n_rows],
            vec![BaseField::from(0u32); n_rows],
        ]
    }

    /// 为 Phase 2.3.2 LogUp 测试计算 CPU 侧的 `claimed_sum`。
    ///
    /// 当 opcode 全为 0 时：
    /// - `denom = combine([0]) = 0 - z = -z`
    /// - `frac = 1 / denom = -1/z`
    /// - `claimed_sum = n_rows * frac = n_rows * (-1/z)`
    ///
    /// 此值传入 `assert_constraints_on_trace` 的 `claimed_sum` 参数，
    /// 使 `LogupAtRow` 计算正确的 `cumsum_shift = -1/z`，
    /// 从而使全零 cumsum 列满足 LogUp 约束：
    /// `(0 - 0 + (-1/z)) * (-z) - 1 = (-1/z) * (-z) - 1 = 1 - 1 = 0` ✓
    fn compute_cpu_claimed_sum_for_zero_opcode(
        lookup: &OpcodeLookupElements,
        n_rows: usize,
    ) -> SecureField {
        use stwo::core::fields::FieldExpOps;
        use stwo::core::fields::qm31::SecureField;
        use stwo_constraint_framework::Relation;
        let opcode_val = BaseField::from(0u32);
        // denom = combine([0]) = 0 - z = -z
        let denom: SecureField =
            Relation::<BaseField, SecureField>::combine(lookup, &[opcode_val]);
        // frac = 1 / denom = -1/z
        let frac = denom.inverse();
        // claimed_sum = n_rows * frac
        SecureField::from(BaseField::from(n_rows as u32)) * frac
    }

    #[test]
    fn test_cpu_air_eval_group_a_sequential_passes() {
        // 正例：CircleDomain ordering trace 满足 Group A + Group B + Group C LogUp 约束
        // Phase 2.3.1 后改用 build_group_ab_circle_domain_trace，
        // 该 helper 同时满足 Group A (idx 连续) 与 Group B (pc[next] == next_pc[cur])。
        // Phase 2.3.2 新增 Group C LogUp：opcode 全为 0，配合 interaction trace（全零 cumsum）
        // 和 computed claimed_sum，LogUp 约束自动满足。
        //
        // Group A：非末行 idx_next - idx_cur - 1 = (position+1) - position - 1 = 0 ✓
        //          末行 is_last_row=1，约束乘以 0 自动满足 ✓
        // Group B：非末行 pc_next - next_pc_cur = (position+1)*4 - (position+1)*4 = 0 ✓
        //          末行 is_last_row=1，约束乘以 0 自动满足 ✓
        // Group C：(0 - 0 + cumsum_shift) * (0 - z) - 1 = (-1/z) * (-z) - 1 = 1 - 1 = 0 ✓
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, is_lui, is_auipc, is_slt, is_logical_shift, _is_addi_default, _is_add_default, _is_sub_default, zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // Phase 2.3.2：构造 interaction trace（4 个全零 BaseField 列 = 1 全零 SecureField cumsum）
        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        // 构造 evals: TreeVec<Vec<&Vec<BaseField>>>
        // evals[0] = preprocessed columns (5 cols: is_last_row, is_lui, is_auipc, is_slt, is_logical_shift)
        // evals[1] = original trace columns (13 cols: idx, pc, next_pc + 10 zero cols)
        // evals[2] = interaction trace columns (4 cols: CPU cumsum SecureField coords)
        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui,
            &is_auipc,
            &is_slt,
            &is_logical_shift,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        // Phase 2.3.2：claimed_sum = n_rows * (-1/z)，使 cumsum_shift = -1/z
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明所有行 Group A + Group B + Group C + Group E 约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_a_nonsequential_fails() {
        // 负例：交换 CircleDomain order 中两个 position 的 idx 值，违反 Group A 约束
        // 在 position 0 和 1 对应的两个 row 之间交换 idx，使得 idx_next - idx_cur - 1 = -2 ≠ 0
        // 注意：仅破坏 Group A，Group B (pc/next_pc) 未改动仍满足。
        // Phase 2.3.2：Group A panic 在 add_to_relation 之前发生，
        // LogupAtRow.is_finalized 仍为初始值 true，Drop 不会二次 panic。
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (mut idx_col, pc_col, next_pc_col, is_last_row, is_lui, is_auipc, is_slt, is_logical_shift, _is_addi_default, _is_add_default, _is_sub_default, zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 找到 CircleDomain order 中 position 0 和 1 对应的两个 row
        let row_pos0 = 0usize; // position 0 对应 row 0（起始）
        let row_pos1 = circle_domain_next_row(row_pos0, log_size); // position 1 对应的 row

        // 交换 idx 值：原来 idx[row_pos0]=0, idx[row_pos1]=1；交换后 idx[row_pos0]=1, idx[row_pos1]=0
        idx_col.swap(row_pos0, row_pos1);
        // 现在 row_pos0 的约束：idx_next - idx_cur - 1 = 0 - 1 - 1 = -2 ≠ 0 → panic

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui,
            &is_auipc,
            &is_slt,
            &is_logical_shift,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    // ===== Phase 2.3.1: Group B 约束专项测试 =====
    //
    // Group B 约束：`(pc_next - next_pc_cur) * (1 - is_last_row) == 0`
    // - 非末行：pc[next_row] == next_pc[cur_row]
    // - 末行：约束乘以 0，自动满足（cyclic 边界豁免）
    //
    // 专项测试覆盖：
    // 1. 正例 — Group A 与 Group B 同时通过（helper 默认构造即满足两者）
    // 2. 负例 — 仅破坏 Group B（交换 pc 值），Group A 保持通过

    #[test]
    fn test_cpu_air_eval_group_b_sequential_passes() {
        // 正例：CircleDomain ordering trace 满足 Group B 约束
        // - 非末行：pc_next - next_pc_cur = pc[row_{p+1}] - next_pc[row_p]
        //         = (p+1)*4 - (p+1)*4 = 0 ✓
        // - 末行：is_last_row=1，约束乘以 0 自动满足 ✓
        //
        // 同时也满足 Group A（idx 连续）和 Group C LogUp（opcode 全 0），
        // 故此测试等同于"Group A + B + C 同时通过"正例。
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, is_lui, is_auipc, is_slt, is_logical_shift, _is_addi_default, _is_add_default, _is_sub_default, zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui,
            &is_auipc,
            &is_slt,
            &is_logical_shift,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group B（及 Group A + C + E）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_b_pc_nonsequential_fails() {
        // 负例：交换 CircleDomain order 中两个 position 的 pc 值，违反 Group B 约束
        // 在 position 0 和 1 对应的两个 row 之间交换 pc，使得
        //   pc_next - next_pc_cur = pc[row_pos1] - next_pc[row_pos0]
        //                        = 0 - 4 = -4 ≠ 0
        // 注意：仅破坏 Group B，Group A (idx) 未改动仍满足。
        // Phase 2.3.2：Group B panic 在 add_to_relation 之前发生，
        // LogupAtRow.is_finalized 仍为初始值 true，Drop 不会二次 panic。
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, mut pc_col, next_pc_col, is_last_row, is_lui, is_auipc, is_slt, is_logical_shift, _is_addi_default, _is_add_default, _is_sub_default, zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 找到 CircleDomain order 中 position 0 和 1 对应的两个 row
        let row_pos0 = 0usize; // position 0 对应 row 0（起始）
        let row_pos1 = circle_domain_next_row(row_pos0, log_size); // position 1 对应的 row

        // 交换 pc 值：原来 pc[row_pos0]=0, pc[row_pos1]=4；交换后 pc[row_pos0]=4, pc[row_pos1]=0
        pc_col.swap(row_pos0, row_pos1);
        // 现在 row_pos0 (position 0) 的 Group B 约束：
        //   pc_next = pc[row_pos1] = 0
        //   next_pc_cur = next_pc[row_pos0] = 4
        //   pc_next - next_pc_cur = 0 - 4 = -4 ≠ 0 → panic
        // Group A 约束（idx 未改动）：
        //   idx_next - idx_cur - 1 = 1 - 0 - 1 = 0 ✓ 不触发 panic

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui,
            &is_auipc,
            &is_slt,
            &is_logical_shift,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    // ===== Phase 2.3.3-a: Group E LUI 约束专项测试 =====
    //
    // Group E LUI 约束：`is_lui * (rd_val - imm) == 0`
    // - is_lui = 1（LUI 行）：强制 rd_val == imm
    // - is_lui = 0（非 LUI 行）：约束乘以 0，自动满足
    //
    // 专项测试覆盖：
    // 1. 正例 — is_lui=1 且 rd_val == imm（非零值 7），Group E 通过
    // 2. 负例 — is_lui=1 但 rd_val ≠ imm（rd_val=5, imm=3），Group E 失败
    //
    // 注意：zero_cols 索引对应列布局：
    //   zero_cols[0] = col 3 (rs1_val), [1] = col 4 (rs2_val),
    //   [2] = col 5 (rd_val), [3] = col 6 (imm), [4] = col 7 (carry), ...
    //   [9] = col 12 (opcode)

    #[test]
    fn test_cpu_air_eval_group_e_lui_rd_eq_imm_passes() {
        // 正例：所有行 opcode=0 (LUI), is_lui=1, rd_val=imm=7（非零）
        // Group E 约束：1 * (7 - 7) = 0 ✓ 满足
        // 同时 Group A (idx 连续)、Group B (pc 连续)、Group C (opcode=0 LogUp) 均满足
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, is_lui, is_auipc, is_slt, is_logical_shift, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 替换 col 5 (rd_val) 和 col 6 (imm) 为非零等值（7）
        // 验证 Group E LUI 约束在非零 rd_val=imm 情况下也成立
        zero_cols[2] = vec![BaseField::from(7u32); n_rows]; // col 5: rd_val = 7
        zero_cols[3] = vec![BaseField::from(7u32); n_rows]; // col 6: imm = 7

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui,
            &is_auipc,
            &is_slt,
            &is_logical_shift,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E LUI（及 Group A + B + C）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_e_lui_rd_neq_imm_fails() {
        // 负例：所有行 opcode=0 (LUI), is_lui=1, 但 rd_val=5 ≠ imm=3
        // Group E 约束：1 * (5 - 3) = 2 ≠ 0 → panic
        // Group A (idx 连续)、Group B (pc 连续)、Group C (opcode=0 LogUp) 均满足
        // 仅 Group E LUI 失败
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, is_lui, is_auipc, is_slt, is_logical_shift, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 替换 col 5 (rd_val) = 5, col 6 (imm) = 3 → rd_val ≠ imm
        zero_cols[2] = vec![BaseField::from(5u32); n_rows]; // col 5: rd_val = 5
        zero_cols[3] = vec![BaseField::from(3u32); n_rows]; // col 6: imm = 3

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui,
            &is_auipc,
            &is_slt,
            &is_logical_shift,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    // ===== Phase 2.3.3-b: Group E AUIPC/SLT/logical_shift 约束专项测试 =====
    //
    // Group E 扩展约束（基于 indicator gating `I_j * constraint_j == 0`）：
    // - AUIPC:  `is_auipc * (rd_val - pc - imm) == 0`        （opcode = 1）
    // - SLT:    `is_slt * (rd_val - carry) == 0`              （opcode ∈ {13,14,24,25}）
    // - LogShift:`is_logical_shift * (rd_val - aux) == 0`     （opcode ∈ {15..=20,23,26..=30}）
    //
    // 测试策略：
    // - 正例：手动构造 1 行 AUIPC（或 SLT / LogShift）+ 其余行 LUI（仍满足 Group A/B/C/E LUI）
    //   通过 `is_*` indicator 在 AUIPC 行置 1、其余行置 0
    //   注意：opcode 列必须与 indicator 一致（AUIPC 行 opcode=1, LUI 行 opcode=0），
    //   否则 Group C LogUp 失败（OpcodeTable 不含 opcode=1 之外的非 LUI 行 j，且 dummy lookup 需修正 claimed_sum）
    //
    // - 负例：is_auipc=1 但 rd_val ≠ pc + imm（AUIPC 语义违反）→ panic
    //
    // **关键**：opcode 列原本在 zero_cols[9]（col 12）。测试需替换该列以反映真实 opcode 分配。
    //
    // **Group C LogUp 处理**：当 opcode 全为 0 时，CPU 侧 claimed_sum = n_rows * (-1/z)。
    // 若掺入 1 行 opcode=1（AUIPC），则 claimed_sum = (n_rows - 1) * (-1/z) + 1 / (1 - z)。
    // 为简化测试，本组测试**手动构造单行特殊场景**：仅验证 Group E 单点约束是否触发 panic，
    // 不要求 Group C LogUp 精确匹配（用 dummy claimed_sum = 0 会导致 LogUp 失败，
    // 但 `assert_constraints_on_trace` 按行检查 add_to_relation 与 add_constraint，
    // Group E 约束先于 finalize_logup 执行 add_to_relation 顺序由 evaluate 函数决定）。
    //
    // 经检查 `CpuAirEval::evaluate`，约束顺序为：
    //   1. Group A add_constraint
    //   2. Group B add_constraint
    //   3. add_to_relation（Group C LogUp）
    //   4. finalize_logup（Group C LogUp）
    //   5. Group E LUI add_constraint
    //   6. Group E AUIPC add_constraint
    //   7. Group E SLT add_constraint
    //   8. Group E logical_shift add_constraint
    //
    // AssertEvaluator 在 add_constraint 时立即检查约束值是否为 0，若不为 0 立即 panic。
    // 故 Group E 负例可在 LogUp 约束被检查前触发 panic（因 LogUp 用 add_to_relation，
    // 仅累积 frac 不立即检查；finalize_logup 在 Group E 之前但仅写入 cumsum 列约束，
    // 若 cumsum 列满足，则 finalize_logup 不触发 panic）。
    //
    // 但 finalize_logup 写入的约束 `(cur_cumsum - prev_row_cumsum + cumsum_shift) * (opcode - z) - 1 == 0`
    // 必须满足，否则 panic。当 opcode 掺入 1 时，cumsum 列与 claimed_sum 需匹配。
    //
    // **简化方案**：测试中保持 opcode 全为 0（即 LUI），仅修改 is_auipc / is_slt / is_logical_shift
    // 为 1（"声称"是 AUIPC/SLT/LogShift），强制 Group E 约束被触发。这违反了
    // indicator 必须与 opcode 一致的业务约束（生产环境由 prover.rs 的 make_indicator 保证），
    // 但**单元测试**目的是验证 CpuAirEval::evaluate 的 Group E 约束逻辑本身，
    // 不验证 indicator 与 opcode 的一致性（这是 prover.rs 的责任）。

    #[test]
    fn test_cpu_air_eval_group_e_auipc_rd_eq_pc_plus_imm_passes() {
        // 正例：手动置 is_auipc=1（声称所有行为 AUIPC），且 rd_val == pc + imm
        // Group E AUIPC 约束：1 * (rd_val - pc - imm) = 1 * (pc+4 - pc - 4) = 0 ✓ 满足
        //
        // **冲突避免**：若同时 is_lui=1 且 is_auipc=1，则 LUI 约束与 AUIPC 约束都对 rd_val/imm 提要求，
        // 二者无法同时满足（除非 rd_val=imm 且 pc=0）。
        // 故构造 is_lui=0（取消 LUI indicator），is_auipc=1（启用 AUIPC 约束），
        // 同时 rd_val == pc + imm 满足 AUIPC 约束。
        // opcode 列仍为 0（Group C LogUp 不受影响），但 indicator 不一致——单元测试可接受。
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 构造自定义 indicator 列
        // - is_lui_manual = 0（取消 LUI 约束，避免与 AUIPC 约束冲突）
        // - is_auipc_manual = 1（启用 AUIPC 约束）
        // - is_slt_manual = 0
        // - is_logical_shift_manual = 0
        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        // 构造 rd_val = pc + imm，使 Group E AUIPC 约束 1 * (rd_val - pc - imm) = 0
        // pc_col[row] = position * 4，imm = 4，故 rd_val[row] = position*4 + 4
        // 必须按 CircleDomain order 填充（与 pc_col 一致）
        let imm_col: Vec<BaseField> = vec![BaseField::from(4u32); n_rows];
        let mut rd_val_col: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let mut current_row = 0usize;
        for position in 0..n_rows {
            let pc_val = (position as u32).wrapping_mul(4);
            rd_val_col[current_row] = BaseField::from(pc_val.wrapping_add(4));
            current_row = circle_domain_next_row(current_row, log_size);
        }
        zero_cols[2] = rd_val_col; // col 5: rd_val = pc + 4
        zero_cols[3] = imm_col;    // col 6: imm = 4

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E AUIPC（及 Group A + B + C）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_e_auipc_rd_neq_pc_plus_imm_fails() {
        // 负例：is_auipc=1 但 rd_val ≠ pc + imm
        // 构造 rd_val = pc + imm + 1（违反 AUIPC 语义）
        // Group E AUIPC 约束：1 * (rd_val - pc - imm) = 1 * 1 = 1 ≠ 0 → panic
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        // rd_val = pc + imm + 1（违反 AUIPC 语义）
        let mut rd_val_col: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let imm_col: Vec<BaseField> = vec![BaseField::from(4u32); n_rows];
        let mut current_row = 0usize;
        for position in 0..n_rows {
            let pc_val = (position as u32).wrapping_mul(4);
            rd_val_col[current_row] = BaseField::from(pc_val.wrapping_add(4).wrapping_add(1));
            current_row = circle_domain_next_row(current_row, log_size);
        }
        zero_cols[2] = rd_val_col;
        zero_cols[3] = imm_col;

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    #[test]
    fn test_cpu_air_eval_group_e_slt_rd_eq_carry_passes() {
        // 正例：is_slt=1（声称所有行为 SLT 组），rd_val == carry
        // Group E SLT 约束：1 * (rd_val - carry) = 1 * (1 - 1) = 0 ✓ 满足
        // 取消 is_lui=0 避免与 LUI 约束冲突
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        // rd_val = carry = 1（SLT 比较结果）
        zero_cols[2] = vec![BaseField::from(1u32); n_rows]; // col 5: rd_val = 1
        // col 7 (carry) 在 zero_cols[4]，需替换
        zero_cols[4] = vec![BaseField::from(1u32); n_rows]; // col 7: carry = 1

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E SLT（及 Group A + B + C）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_e_slt_rd_neq_carry_fails() {
        // 负例：is_slt=1 但 rd_val=1 ≠ carry=0
        // Group E SLT 约束：1 * (1 - 0) = 1 ≠ 0 → panic
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        // rd_val = 1, carry = 0
        zero_cols[2] = vec![BaseField::from(1u32); n_rows]; // col 5: rd_val = 1
        zero_cols[4] = vec![BaseField::from(0u32); n_rows]; // col 7: carry = 0

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    #[test]
    fn test_cpu_air_eval_group_e_logical_shift_rd_eq_aux_passes() {
        // 正例：is_logical_shift=1（声称所有行为逻辑/移位组），rd_val == aux
        // Group E LogShift 约束：1 * (rd_val - aux) = 1 * (7 - 7) = 0 ✓ 满足
        // 取消 is_lui=0 避免与 LUI 约束冲突
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];

        // rd_val = aux = 7（逻辑运算结果）
        zero_cols[2] = vec![BaseField::from(7u32); n_rows]; // col 5: rd_val = 7
        // col 11 (aux) 在 zero_cols[8]，需替换
        zero_cols[8] = vec![BaseField::from(7u32); n_rows]; // col 11: aux = 7

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E logical_shift（及 Group A + B + C）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_e_logical_shift_rd_neq_aux_fails() {
        // 负例：is_logical_shift=1 但 rd_val=5 ≠ aux=3
        // Group E LogShift 约束：1 * (5 - 3) = 2 ≠ 0 → panic
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];

        // rd_val = 5, aux = 3
        zero_cols[2] = vec![BaseField::from(5u32); n_rows]; // col 5: rd_val = 5
        zero_cols[8] = vec![BaseField::from(3u32); n_rows]; // col 11: aux = 3

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    // ===== Phase 2.3.4-a: Group F carry 二值性约束专项测试 =====
    //
    // Group F 约束：`carry * (carry - 1) == 0`（universal，无 indicator gating）
    // - carry = 0: 0 * (0 - 1) = 0 ✓
    // - carry = 1: 1 * (1 - 1) = 0 ✓
    // - carry ≥ 2: carry * (carry - 1) ≠ 0 → 约束失败
    //
    // 测试策略：
    // - 所有 indicator (is_lui/is_auipc/is_slt/is_logical_shift) 设为 0，
    //   避免其他 Group E 约束干扰 Group F 测试
    // - opcode 列仍为 0（Group C LogUp 不受影响）
    // - Group E 约束全部乘以 0 自动满足（is_lui * (rd_val - imm) = 0 * (...) = 0 等）
    // - 仅 Group F 约束对所有行强制 carry ∈ {0, 1}

    #[test]
    fn test_cpu_air_eval_group_f_carry_zero_passes() {
        // 正例：carry=0（全行），Group F 约束 0*(0-1)=0 ✓ 满足
        //
        // 默认 build_group_ab_circle_domain_trace 的 zero_cols[4] (col 7: carry) 已全为 0，
        // 满足 carry=0 正例。所有 indicator=0，避免 Group E 干扰。
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 所有 indicator=0，仅 Group F 约束对所有行生效
        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group F carry=0（及 Group A + B + C）所有行约束均满足
    }

    #[test]
    fn test_cpu_air_eval_group_f_carry_one_passes() {
        // 正例：carry=1（全行），Group F 约束 1*(1-1)=0 ✓ 满足
        //
        // 修改 zero_cols[4] (col 7: carry) 为全 1。
        // 所有 indicator=0，Group E 约束乘以 0 自动满足（不检查 rd_val/carry 关系）。
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 修改 carry=1（col 7 = zero_cols[4]）
        zero_cols[4] = vec![BaseField::from(1u32); n_rows];

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group F carry=1（及 Group A + B + C）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_f_carry_two_fails() {
        // 负例：carry=2（全行），Group F 约束 2*(2-1)=2≠0 → panic
        //
        // 修改 zero_cols[4] (col 7: carry) 为全 2，违反 Group F carry 二值性。
        // 所有 indicator=0，仅 Group F 约束触发 panic。
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 修改 carry=2（col 7 = zero_cols[4]），违反 Group F carry 二值性
        zero_cols[4] = vec![BaseField::from(2u32); n_rows];

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &_is_addi_default,
            &_is_add_default,
            &_is_sub_default,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    // ===== Phase 2.3.4-b: Group E ADD/ADDI/SUB limb decomposition 约束专项测试 =====
    //
    // Group E 扩展约束（limb decomposition，每条指令 2 个约束：low + high limb）：
    // - ADD:    `is_add * (rs1_val + rs2_val - rd_val - 2^30 * carry_low) == 0`            (low)
    //           `is_add * (rs1_high + rs2_high + carry_low - rd_high - 4 * carry) == 0`    (high)
    // - ADDI:   `is_addi * (rs1_val + imm - rd_val - 2^30 * carry_low) == 0`               (low)
    //           `is_addi * (rs1_high + imm_high + carry_low - rd_high - 4 * carry) == 0`   (high)
    // - SUB:    `is_sub * (rs1_val - rs2_val - rd_val + 2^30 * carry_low) == 0`            (low, borrow)
    //           `is_sub * (rs1_high - rs2_high - carry_low - rd_high + 4 * carry) == 0`    (high, borrow)
    //
    // **关键设计点**：
    // 1. SUB 中 carry_low 和 carry 的符号方向与 ADD 相反（borrow vs overflow 语义）
    // 2. Group F 扩展：`carry_low * (carry_low - 1) == 0`（universal，无 indicator gating）
    //
    // 测试策略（参考 Phase 2.3.3-b AUIPC/SLT/LogShift 测试）：
    // - 手动构造 indicator（is_add=1 或 is_addi=1 或 is_sub=1），其余 indicator=0
    // - opcode 列仍为 0（Group C LogUp 不受影响），indicator 与 opcode 不一致——单元测试可接受
    // - 验证 Group E ADD/ADDI/SUB 约束在正确 limb 值下满足，错误 limb 值下 panic
    //
    // **zero_cols 索引**（Phase 2.3.4-b 18 列布局）：
    //   zero_cols[0]=col 3 (rs1_val),  [1]=col 4 (rs2_val), [2]=col 5 (rd_val),
    //   [3]=col 6 (imm), [4]=col 7 (carry), [5]=col 8 (taken), [6]=col 9 (shamt),
    //   [7]=col 10 (branch_cond), [8]=col 11 (aux), [9]=col 12 (opcode),
    //   [10]=col 13 (rs1_high), [11]=col 14 (rs2_high), [12]=col 15 (rd_high),
    //   [13]=col 16 (imm_high), [14]=col 17 (carry_low)

    #[test]
    fn test_cpu_air_eval_group_e_add_no_overflow_passes() {
        // 正例：is_add=1，构造 ADD a=10 + b=20 = result=30（无溢出）
        // - a_low=10, a_high=0, b_low=20, b_high=0, rd_low=30, rd_high=0
        // - carry=0 (无 u32 溢出), carry_low=0 (无 low limb 溢出)
        // Low:  10 + 20 - 30 - 2^30 * 0 = 0 ✓
        // High: 0 + 0 + 0 - 0 - 4 * 0 = 0 ✓
        // Group F: carry=0 → 0*(0-1)=0 ✓; carry_low=0 → 0*(0-1)=0 ✓
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 构造 indicator：仅 is_add=1，其余=0
        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        // 设置 ADD 操作数：a=10, b=20, result=30, carry=0, carry_low=0
        zero_cols[0] = vec![BaseField::from(10u32); n_rows]; // col 3: rs1_val = 10
        zero_cols[1] = vec![BaseField::from(20u32); n_rows]; // col 4: rs2_val = 20
        zero_cols[2] = vec![BaseField::from(30u32); n_rows]; // col 5: rd_val = 30
        zero_cols[4] = vec![BaseField::from(0u32); n_rows];  // col 7: carry = 0
        // col 13-16 (high limbs) 全为 0（已默认）
        zero_cols[14] = vec![BaseField::from(0u32); n_rows]; // col 17: carry_low = 0

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E ADD（及 Group A + B + C + F）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_e_add_wrong_result_fails() {
        // 负例：is_add=1，构造 ADD a=10 + b=20 ≠ result=31（错误结果）
        // Low:  10 + 20 - 31 - 2^30 * 0 = -1 ≠ 0 → panic
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        // 构造错误结果：a=10 + b=20 = 30, 但 rd_val=31（错误）
        zero_cols[0] = vec![BaseField::from(10u32); n_rows]; // col 3: rs1_val = 10
        zero_cols[1] = vec![BaseField::from(20u32); n_rows]; // col 4: rs2_val = 20
        zero_cols[2] = vec![BaseField::from(31u32); n_rows]; // col 5: rd_val = 31 (错误)
        zero_cols[4] = vec![BaseField::from(0u32); n_rows];  // col 7: carry = 0
        zero_cols[14] = vec![BaseField::from(0u32); n_rows]; // col 17: carry_low = 0

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    #[test]
    fn test_cpu_air_eval_group_e_add_limb_boundary_carry_low_one_passes() {
        // 正例：is_add=1，构造 ADD a=0x3FFFFFFF + b=1 = result=0x40000000
        // - a_low=0x3FFFFFFF (2^30-1), a_high=0
        // - b_low=1, b_high=0
        // - rd_low=0, rd_high=1 (因 0x40000000 = 0 + 2^30 * 1)
        // - carry=0 (无 u32 溢出), carry_low=1 (low limb 溢出：2^30-1 + 1 = 2^30)
        // Low:  (2^30-1) + 1 - 0 - 2^30 * 1 = 0 ✓
        // High: 0 + 0 + 1 - 1 - 4 * 0 = 0 ✓
        // Group F: carry=0 → 0*(0-1)=0 ✓; carry_low=1 → 1*(1-1)=0 ✓
        //
        // 此测试验证 low limb 溢出（carry_low=1）场景，是 Phase 2.3.4-b limb decomposition 的核心边界
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        // a = 0x3FFFFFFF (2^30 - 1)
        zero_cols[0] = vec![BaseField::from(0x3FFFFFFFu32); n_rows]; // col 3: rs1_val = 2^30-1
        zero_cols[1] = vec![BaseField::from(1u32); n_rows];          // col 4: rs2_val = 1
        zero_cols[2] = vec![BaseField::from(0u32); n_rows];          // col 5: rd_val = 0 (low limb)
        zero_cols[4] = vec![BaseField::from(0u32); n_rows];          // col 7: carry = 0 (无 u32 溢出)
        zero_cols[10] = vec![BaseField::from(0u32); n_rows];         // col 13: rs1_high = 0
        zero_cols[11] = vec![BaseField::from(0u32); n_rows];         // col 14: rs2_high = 0
        zero_cols[12] = vec![BaseField::from(1u32); n_rows];         // col 15: rd_high = 1
        zero_cols[14] = vec![BaseField::from(1u32); n_rows];         // col 17: carry_low = 1

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E ADD limb 边界（carry_low=1）约束满足
    }

    #[test]
    fn test_cpu_air_eval_group_e_addi_no_overflow_passes() {
        // 正例：is_addi=1，构造 ADDI a=10 + imm=20 = result=30（无溢出）
        // - a_low=10, a_high=0, imm_low=20, imm_high=0, rd_low=30, rd_high=0
        // - carry=0, carry_low=0
        // Low:  10 + 20 - 30 - 2^30 * 0 = 0 ✓
        // High: 0 + 0 + 0 - 0 - 4 * 0 = 0 ✓
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        // ADDI: a=10, imm=20, result=30
        zero_cols[0] = vec![BaseField::from(10u32); n_rows]; // col 3: rs1_val = 10
        zero_cols[3] = vec![BaseField::from(20u32); n_rows]; // col 6: imm = 20
        zero_cols[2] = vec![BaseField::from(30u32); n_rows]; // col 5: rd_val = 30
        zero_cols[4] = vec![BaseField::from(0u32); n_rows];  // col 7: carry = 0
        zero_cols[14] = vec![BaseField::from(0u32); n_rows]; // col 17: carry_low = 0

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E ADDI（及 Group A + B + C + F）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_e_addi_wrong_result_fails() {
        // 负例：is_addi=1，构造 ADDI a=10 + imm=20 ≠ result=31（错误结果）
        // Low:  10 + 20 - 31 - 2^30 * 0 = -1 ≠ 0 → panic
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        zero_cols[0] = vec![BaseField::from(10u32); n_rows]; // col 3: rs1_val = 10
        zero_cols[3] = vec![BaseField::from(20u32); n_rows]; // col 6: imm = 20
        zero_cols[2] = vec![BaseField::from(31u32); n_rows]; // col 5: rd_val = 31 (错误)
        zero_cols[4] = vec![BaseField::from(0u32); n_rows];  // col 7: carry = 0
        zero_cols[14] = vec![BaseField::from(0u32); n_rows]; // col 17: carry_low = 0

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    #[test]
    fn test_cpu_air_eval_group_e_sub_no_borrow_passes() {
        // 正例：is_sub=1，构造 SUB a=30 - b=10 = result=20（无借位）
        // - a_low=30, a_high=0, b_low=10, b_high=0, rd_low=20, rd_high=0
        // - carry=0 (无 borrow), carry_low=0 (无 low limb borrow)
        // Low:  30 - 10 - 20 + 2^30 * 0 = 0 ✓
        // High: 0 - 0 - 0 - 0 + 4 * 0 = 0 ✓
        // Group F: carry=0 ✓; carry_low=0 ✓
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];

        // SUB: a=30, b=10, result=20
        zero_cols[0] = vec![BaseField::from(30u32); n_rows]; // col 3: rs1_val = 30
        zero_cols[1] = vec![BaseField::from(10u32); n_rows]; // col 4: rs2_val = 10
        zero_cols[2] = vec![BaseField::from(20u32); n_rows]; // col 5: rd_val = 20
        zero_cols[4] = vec![BaseField::from(0u32); n_rows];  // col 7: carry = 0 (无 borrow)
        zero_cols[14] = vec![BaseField::from(0u32); n_rows]; // col 17: carry_low = 0

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E SUB（及 Group A + B + C + F）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_e_sub_wrong_result_fails() {
        // 负例：is_sub=1，构造 SUB a=30 - b=10 ≠ result=21（错误结果）
        // Low:  30 - 10 - 21 + 2^30 * 0 = -1 ≠ 0 → panic
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];

        zero_cols[0] = vec![BaseField::from(30u32); n_rows]; // col 3: rs1_val = 30
        zero_cols[1] = vec![BaseField::from(10u32); n_rows]; // col 4: rs2_val = 10
        zero_cols[2] = vec![BaseField::from(21u32); n_rows]; // col 5: rd_val = 21 (错误)
        zero_cols[4] = vec![BaseField::from(0u32); n_rows];  // col 7: carry = 0
        zero_cols[14] = vec![BaseField::from(0u32); n_rows]; // col 17: carry_low = 0

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }

    #[test]
    fn test_cpu_air_eval_group_e_sub_with_borrow_passes() {
        // 正例：is_sub=1，构造 SUB a=3 - b=5 = result=0xFFFFFFFE（u32 wrap-around，borrow=1）
        // - a_low=3, a_high=0, b_low=5, b_high=0
        // - rd_low=0x3FFFFFFE (low 30 bit of 0xFFFFFFFE), rd_high=3 (high 2 bit)
        // - carry=1 (borrow), carry_low=1 (low limb borrow: 3 - 5 + 2^30 = 0x3FFFFFFE)
        // Low:  3 - 5 - 0x3FFFFFFE + 2^30 * 1 = -2 - 0x3FFFFFFE + 0x40000000 = -2 + 2 = 0 ✓
        // High: 0 - 0 - 1 - 3 + 4 * 1 = 0 ✓
        // Group F: carry=1 → 1*(1-1)=0 ✓; carry_low=1 → 1*(1-1)=0 ✓
        //
        // **关键验证**：SUB high limb 约束符号方向（`- carry_low + 4 * carry`，与 ADD 相反）
        // 此测试是 SUB borrow 语义的核心验证
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(1u32); n_rows];

        // SUB: a=3, b=5, result=0xFFFFFFFE (u32 wrap-around)
        zero_cols[0] = vec![BaseField::from(3u32); n_rows];          // col 3: rs1_val = 3
        zero_cols[1] = vec![BaseField::from(5u32); n_rows];          // col 4: rs2_val = 5
        zero_cols[2] = vec![BaseField::from(0x3FFFFFFEu32); n_rows]; // col 5: rd_val = 0x3FFFFFFE (low 30 bit)
        zero_cols[4] = vec![BaseField::from(1u32); n_rows];          // col 7: carry = 1 (borrow)
        zero_cols[10] = vec![BaseField::from(0u32); n_rows];         // col 13: rs1_high = 0
        zero_cols[11] = vec![BaseField::from(0u32); n_rows];         // col 14: rs2_high = 0
        zero_cols[12] = vec![BaseField::from(3u32); n_rows];         // col 15: rd_high = 3 (high 2 bit of 0xFFFFFFFE)
        zero_cols[14] = vec![BaseField::from(1u32); n_rows];         // col 17: carry_low = 1 (low limb borrow)

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明 Group E SUB with borrow（及 Group A + B + C + F）所有行约束均满足
    }

    #[test]
    #[should_panic(expected = "constraint")]
    fn test_cpu_air_eval_group_f_carry_low_two_fails() {
        // 负例：carry_low=2（全行），Group F 扩展约束 2*(2-1)=2≠0 → panic
        //
        // 所有 indicator=0（Group E 约束乘以 0 自动满足），仅 Group F carry_low 约束触发 panic。
        // 修改 zero_cols[14] (col 17: carry_low) 为全 2，违反 Group F carry_low 二值性。
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();
        let (idx_col, pc_col, next_pc_col, is_last_row, _is_lui_default, _is_auipc_default, _is_slt_default, _is_logshift_default, _is_addi_default, _is_add_default, _is_sub_default, mut zero_cols) =
            build_group_ab_circle_domain_trace(log_size);

        // 修改 carry_low=2（col 17 = zero_cols[14]），违反 Group F carry_low 二值性
        zero_cols[14] = vec![BaseField::from(2u32); n_rows];

        let is_lui_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_auipc_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_slt_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_logical_shift_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_addi_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_add_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];
        let is_sub_manual: Vec<BaseField> = vec![BaseField::from(0u32); n_rows];

        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        let mut original: Vec<&Vec<BaseField>> = vec![&idx_col, &pc_col, &next_pc_col];
        for col in &zero_cols {
            original.push(col);
        }
        let preprocessed: Vec<&Vec<BaseField>> = vec![
            &is_last_row,
            &is_lui_manual,
            &is_auipc_manual,
            &is_slt_manual,
            &is_logical_shift_manual,
            &is_addi_manual,
            &is_add_manual,
            &is_sub_manual,
        ];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let cpu_eval = CpuAirEval::new(log_size, lookup.clone());
        let claimed_sum = compute_cpu_claimed_sum_for_zero_opcode(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = cpu_eval.evaluate(e);
            },
            claimed_sum,
        );
    }
}