//! # Opcode Table AIR 组件 — Phase 2.3.2 Group C
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"Phase 2.3.2" 与
//! `stwo_phase2_2_trace_column_reduction_plan.md`（Group C opcode range check via LogUp）：
//!
//! - 通过 LogUp 协议证明 CPU trace 中每行的 `opcode` 列值 ∈ [0, 34]
//! - 替代 Hypernova 的 Group C（`Σ_j sel_j - 1 = 0`）和 Group D（`sel_j² - sel_j = 0`）
//!
//! ## LogUp 协议原理
//!
//! LogUp（Logarithmic Derivative Lookup）通过累积和（cumsum）列证明某个值在预定义表中存在。
//!
//! 对于 CPU 与 OpcodeTable 两组件，LogUp 约束为：
//! ```text
//! sum_{i in CPU rows} (1 / (combine(opcode_i) - z))
//!   + sum_{j in table rows} (mult_j / (combine(opcode_value_j) - z)) == 0
//! ```
//!
//! 其中 `combine(v) = alpha^0 * v - z = v - z`（N=1，单值 lookup）。
//!
//! 当 `mult_j = -count_j`（count_j = opcode j 在 CPU 中的出现次数），且 table 行 0..34
//! 的 `opcode_value = j`，padding 行 `mult = 0` 时，等式成立当且仅当 CPU opcode 多重集
//! = {j 重复 count_j 次 : j ∈ [0, 34]}，即 CPU 中所有 opcode ∈ [0, 34]。
//!
//! ## 两组件布局
//!
//! ### OpcodeTable original trace（2 列，与 CPU 13 列拼接于同一 original tree）
//!
//! | col（在 original tree 中） | 列名           | 内容                                          |
//! |---------------------------|----------------|-----------------------------------------------|
//! | 13                        | `opcode_value` | row j (0..34): j；row 35..N-1: 任意（如 0）   |
//! | 14                        | `multiplicity`| row j (0..34): P - count_j（即 -count_j）；padding: 0 |
//!
//! ### Interaction trace（4 列 × 2 组件 = 8 BaseField 列）
//!
//! 每个组件的 cumsum 列为 1 个 SecureField（QM31）= 4 个 BaseField（M31）列。
//! CPU cumsum 占 interaction col 0-3，Table cumsum 占 interaction col 4-7。
//!
//! ## 安全性
//!
//! - `multiplicity` 列无需额外约束：LogUp 和约束本身强制 `sum(mult_j / denom_j) = -sum(CPU claims)`
//! - 恶意 prover 若使用错误的 `mult_j`，cumsum 约束将失败（因 denominators 依赖随机挑战 z）
//! - `z` 和 `alpha` 在 original trace commit 后从 channel 抽取，防止 prover 适配

// `relation!` 宏生成的 struct/方法无法直接添加 doc 注释，而 crate 全局
// `#![deny(missing_docs)]` 会报错。此模块级 `#![allow(missing_docs)]` 仅作用于本文件。
#![allow(missing_docs)]

use stwo_constraint_framework::{
    relation, EvalAtRow, FrameworkEval, ORIGINAL_TRACE_IDX, RelationEntry,
};

// Opcode lookup 的 relation 类型：每次 lookup 1 个值（opcode）。
//
// `combine(&[opcode]) = alpha^0 * opcode - z = opcode - z`，作为 LogUp 分母。
//
// 由 `relation!` 宏自动生成 `Relation` trait 实现 + `draw(channel)` / `dummy()` 方法。
// 模块级 `#![allow(missing_docs)]` 已在文件顶部声明，覆盖宏生成项的文档要求。
relation!(OpcodeLookupElements, 1);

/// OpcodeTable AIR 约束评估器（Phase 2.3.2：Group C opcode range check via LogUp）。
///
/// 实现 [`FrameworkEval`]，由 `FrameworkComponent<OpcodeTableEval>` 自动生成
/// `Component` + `ComponentProver<SimdBackend>` 实现。
///
/// # 约束
///
/// 单个 LogUp 约束（degree 2）：
/// ```text
/// (cur_cumsum - prev_row_cumsum + cumsum_shift) * (opcode_value - z) - multiplicity == 0
/// ```
///
/// 其中 `cumsum_shift = claimed_sum / N`，由 `LogupAtRow` 管理。
///
/// # trace 列布局（2 列）
///
/// - col 0：`opcode_value`（row j ∈ [0,34]: j；padding: 任意）
/// - col 1：`multiplicity`（row j ∈ [0,34]: -count_j；padding: 0）
///
/// # 注意
///
/// `multiplicity` 作为 BaseField (M31) 存储：负值 `-count_j` 表示为 `P - count_j`
///（P = 2^31 - 1 = M31 模数）。转换为 SecureField 时自动成为正确的负值表示。
pub struct OpcodeTableEval {
    /// trace 行数的 log2（与 CPU 组件相同，2^log_size 行）。
    pub log_size: u32,
    /// Opcode lookup 的随机挑战元素（z, alpha），从 channel 抽取。
    pub opcode_lookup: OpcodeLookupElements,
}

impl OpcodeTableEval {
    /// 创建新 OpcodeTable 评估器。
    pub fn new(log_size: u32, opcode_lookup: OpcodeLookupElements) -> Self {
        Self {
            log_size,
            opcode_lookup,
        }
    }
}

impl FrameworkEval for OpcodeTableEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // LogUp 约束 `(cur_cumsum - prev_row_cumsum + shift) * (opcode_value - z) - multiplicity`
        // 为 degree 2（cumsum_diff 与 denom 的乘积，各 degree 1）。
        //
        // 按 Stwo book 公式：`log_size + max(1, ceil(log2(max_degree - 1)))`。
        // 对于 max_degree=2：`ceil(log2(1)) = 0`，`max(1, 0) = 1`，故 bound = log_size + 1。
        // 与 CpuAirEval 一致，确保 FRI 域大小匹配。
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // col 0: opcode_value（table row j 时为 j，padding 时为任意值）
        let [opcode_value] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);

        // col 1: multiplicity（table row j 时为 -count_j，padding 时为 0）
        // 作为 BaseField 读取，后续转换为 SecureField 供 RelationEntry 使用
        let [multiplicity] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);

        // 将 multiplicity (BaseField) 转换为 SecureField。
        // trait bound `E::EF: From<E::F>` 保证此转换合法。
        // 负值 `-count_j` 以 M31 表示 `P - count_j`，转换后为 QM31 中正确的 `-count_j`。
        let multiplicity_ef: E::EF = multiplicity.clone().into();

        // 声明 LogUp 条目：multiplicity / (opcode_value - z)
        // - 正 multiplicity = "claim/use"（CPU 侧）
        // - 负 multiplicity = "yield"（Table 侧，本组件）
        // - 零 multiplicity = padding 行，贡献 0
        eval.add_to_relation(RelationEntry::new(
            &self.opcode_lookup,
            multiplicity_ef,
            &[opcode_value],
        ));

        // 生成 LogUp cumsum 约束：
        // (cur_cumsum - prev_row_cumsum + cumsum_shift) * denom - num == 0
        // 读取 interaction trace 的 cumsum 列（4 BaseField 列 = 1 SecureField 列）
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
    use stwo::core::fields::m31::BaseField;
    use stwo::core::fields::qm31::SecureField;
    // 导入 Relation trait 以使用 `lookup.combine(...)`
    use stwo_constraint_framework::Relation;

    #[test]
    fn test_opcode_lookup_elements_dummy() {
        // dummy() 应返回非 panic 的实例（用于测试）
        let _lookup = OpcodeLookupElements::dummy();
    }

    #[test]
    fn test_opcode_lookup_elements_combine() {
        // combine(&[opcode]) = opcode - z（N=1，alpha^0 = 1）
        let lookup = OpcodeLookupElements::dummy();
        let opcode_val = BaseField::from(21u32); // ADD opcode
        // 通过 Relation trait 调用 combine（泛型在 trait 上，不在方法上）
        let combined: SecureField = Relation::<BaseField, SecureField>::combine(&lookup, &[opcode_val]);
        // combined = opcode_val - lookup.0.z
        let expected = SecureField::from(opcode_val) - lookup.0.z;
        assert_eq!(combined, expected);
    }

    #[test]
    fn test_opcode_table_eval_log_size() {
        let eval = OpcodeTableEval::new(10, OpcodeLookupElements::dummy());
        assert_eq!(eval.log_size(), 10);
        assert_eq!(eval.log_size, 10);
    }

    #[test]
    fn test_opcode_table_eval_max_constraint_log_degree_bound() {
        let eval = OpcodeTableEval::new(10, OpcodeLookupElements::dummy());
        // log_size + 1 = 11（degree-2 LogUp 约束）
        assert_eq!(
            eval.max_constraint_log_degree_bound(),
            11,
            "OpcodeTableEval max_constraint_log_degree_bound 应为 log_size + 1"
        );
    }

    #[test]
    fn test_opcode_table_eval_constraint_count_via_info() {
        // 用 InfoEvaluator 验证约束数：
        // - 0 个显式 add_constraint
        // - finalize_logup（单 batch）通过 add_constraint 添加 1 个约束
        use stwo_constraint_framework::InfoEvaluator;

        let eval = OpcodeTableEval::new(10, OpcodeLookupElements::dummy());
        let info = eval.evaluate(InfoEvaluator::new(
            10,
            vec![],
            SecureField::default(),
        ));
        // finalize_logup（单 batch）添加 1 个约束
        assert_eq!(
            info.n_constraints, 1,
            "OpcodeTableEval 应包含 1 个 LogUp 约束（单 batch finalize_logup）"
        );
    }

    // ===== Phase 2.3.2: Group C LogUp 约束专项测试（assert_constraints_on_trace）=====
    //
    // 验证 OpcodeTableEval 的 LogUp 约束：
    //   `(cur_cumsum - prev_row_cumsum + cumsum_shift) * (opcode_value - z) - multiplicity == 0`
    //
    // 测试策略：
    // 1. 正例 — 所有行 (opcode_value=0, multiplicity=-1)，frac = 1/z 常数，
    //    全零 cumsum + 正确 claimed_sum → 约束满足
    // 2. 负例 — 同样 trace 但传入错误 claimed_sum=0 → cumsum_shift=0，
    //    约束变为 `0 * (-z) - (-1) = 1 ≠ 0` → panic

    /// 构造全零 interaction trace（4 BaseField 列 = 1 全零 SecureField cumsum）。
    ///
    /// 与 cpu.rs 中 `build_logup_interaction_trace_zero` 同款，供 OpcodeTable LogUp 测试复用。
    /// 全零 cumsum 在 frac 为常数时满足 LogUp 约束（cumsum_shift 抵消每行 frac 贡献）。
    fn build_logup_interaction_trace_zero(n_rows: usize) -> [Vec<BaseField>; 4] {
        [
            vec![BaseField::from(0u32); n_rows],
            vec![BaseField::from(0u32); n_rows],
            vec![BaseField::from(0u32); n_rows],
            vec![BaseField::from(0u32); n_rows],
        ]
    }

    /// 计算 OpcodeTable 侧的 `claimed_sum`（所有行 opcode_value=0, multiplicity=-1）。
    ///
    /// 数学推导：
    /// - `denom = combine([0]) = 0 - z = -z`
    /// - `frac_per_row = multiplicity / denom = -1 / (-z) = 1/z`
    /// - `claimed_sum = n_rows * frac_per_row = n_rows / z`
    ///
    /// 此值传入 `assert_constraints_on_trace`，使 `LogupAtRow` 计算
    /// `cumsum_shift = claimed_sum / n_rows = 1/z`，从而使全零 cumsum 列满足 LogUp 约束：
    /// `(0 - 0 + 1/z) * (-z) - (-1) = -1 - (-1) = 0` ✓
    fn compute_table_claimed_sum_for_neg_one_multiplicity(
        lookup: &OpcodeLookupElements,
        n_rows: usize,
    ) -> SecureField {
        use stwo::core::fields::FieldExpOps;
        // denom = combine([0]) = -z
        let denom: SecureField =
            Relation::<BaseField, SecureField>::combine(lookup, &[BaseField::from(0u32)]);
        // -1 in SecureField（M31 中 P-1，转 SecureField 后为 -1）
        let neg_one = SecureField::from(BaseField::from(0u32)) - SecureField::from(BaseField::from(1u32));
        // frac_per_row = -1 / (-z) = 1/z
        let frac_per_row = neg_one * denom.inverse();
        // claimed_sum = n_rows * (1/z)
        SecureField::from(BaseField::from(n_rows as u32)) * frac_per_row
    }

    #[test]
    fn test_opcode_table_eval_logup_constant_neg_one_passes() {
        // 正例：所有行 opcode_value = 0, multiplicity = -1（M31: P-1）
        //
        // 每行 frac = multiplicity / denom = -1 / (-z) = 1/z（常数，与行无关）
        // claimed_sum = n_rows * (1/z), cumsum_shift = 1/z（per row）
        // 全零 cumsum 满足约束：
        //   (cur_cumsum - prev_row_cumsum + cumsum_shift) * denom - multiplicity
        //   = (0 - 0 + 1/z) * (-z) - (-1)
        //   = -1 - (-1)
        //   = 0 ✓
        use stwo::core::pcs::TreeVec;
        use stwo_constraint_framework::assert_constraints_on_trace;

        let log_size: u32 = 10;
        let n_rows = 1usize << log_size;
        let lookup = OpcodeLookupElements::dummy();

        // 构造 OpcodeTable original trace（2 列）
        // col 0: opcode_value（所有行 = 0）
        let opcode_value_col = vec![BaseField::from(0u32); n_rows];
        // col 1: multiplicity（所有行 = -1，M31 表示为 P - 1 = 0 - 1）
        let multiplicity_col = vec![BaseField::from(0u32) - BaseField::from(1u32); n_rows];

        // interaction trace（4 个全零 BaseField 列 = 1 全零 SecureField cumsum）
        let interaction_cols = build_logup_interaction_trace_zero(n_rows);

        // evals 结构：
        //   evals[0] = preprocessed columns（OpcodeTableEval 不使用 preprocessed，空）
        //   evals[1] = original trace columns（2 cols: opcode_value, multiplicity）
        //   evals[2] = interaction trace columns（4 cols: cumsum SecureField 坐标）
        let preprocessed: Vec<&Vec<BaseField>> = vec![];
        let original: Vec<&Vec<BaseField>> = vec![&opcode_value_col, &multiplicity_col];
        let interaction: Vec<&Vec<BaseField>> = vec![
            &interaction_cols[0],
            &interaction_cols[1],
            &interaction_cols[2],
            &interaction_cols[3],
        ];
        let evals: TreeVec<Vec<&Vec<BaseField>>> =
            TreeVec::new(vec![preprocessed, original, interaction]);

        let table_eval = OpcodeTableEval::new(log_size, lookup.clone());
        let claimed_sum = compute_table_claimed_sum_for_neg_one_multiplicity(&lookup, n_rows);
        assert_constraints_on_trace(
            &evals,
            log_size,
            |e| {
                let _ = table_eval.evaluate(e);
            },
            claimed_sum,
        );
        // 若执行到这里，说明所有行 LogUp 约束均满足
    }

    #[test]
    fn test_opcode_table_eval_logup_claimed_sum_scales_with_n_rows() {
        // LogUp 数学性质测试：claimed_sum 与 n_rows 成线性关系（当 multiplicity 固定时）。
        //
        // 对于所有行 (opcode_value=0, multiplicity=-1)：
        //   frac_per_row = -1 / (-z) = 1/z
        //   claimed_sum = n_rows * (1/z)
        //
        // 因此 claimed_sum(n_rows=2N) / claimed_sum(n_rows=N) = 2
        //
        // 此测试验证 `compute_table_claimed_sum_for_neg_one_multiplicity` 的数学正确性，
        // 间接验证 LogUp 约束的 claimed_sum 计算（cumsum_shift = claimed_sum / n_rows = 1/z）。
        //
        // 注意：不使用 `assert_constraints_on_trace` 做负例测试，因为 OpcodeTableEval
        // 的唯一约束是 LogUp（在 `finalize_logup` 中添加），而 AssertEvaluator 会立即
        // 检查约束并在 `is_finalized=false` 时 panic，导致 LogupAtRow 析构函数二次 panic
        // （SIGABRT）。cpu.rs 的 Group A/B 负例测试可行是因为其 `add_constraint` 在
        // `add_to_relation` 之前调用，panic 时 `is_finalized` 仍为初始值 `true`。
        // OpcodeTableEval 的 LogUp 约束检查发生在 `add_to_relation` 之后，无法避免
        // 析构函数二次 panic。负例覆盖由 e2e 测试（stwo_poc_e2e.rs）间接保证。
        use stwo::core::fields::FieldExpOps;
        let lookup = OpcodeLookupElements::dummy();

        let claimed_sum_n = compute_table_claimed_sum_for_neg_one_multiplicity(&lookup, 1024);
        let claimed_sum_2n = compute_table_claimed_sum_for_neg_one_multiplicity(&lookup, 2048);

        // claimed_sum_2n / claimed_sum_n = 2
        let ratio = claimed_sum_2n * claimed_sum_n.inverse();
        let two = SecureField::from(BaseField::from(2u32));
        assert_eq!(
            ratio, two,
            "claimed_sum 应与 n_rows 成线性关系：claimed_sum(2N) / claimed_sum(N) 应为 2"
        );
    }

    #[test]
    fn test_opcode_table_eval_logup_claimed_sum_nonzero() {
        // LogUp 数学性质测试：claimed_sum 不为零（当 multiplicity 非零时）。
        //
        // 这验证了 LogUp 约束不会平凡满足（claimed_sum=0 时 cumsum_shift=0，
        // 约束退化为 `0 * denom - multiplicity == 0`，仅当 multiplicity=0 时成立）。
        // 恶意 prover 无法通过 claimed_sum=0 欺骗 verifier（除非所有 multiplicity=0，
        // 即空表，但 CPU 侧的 claim 非零会导致 LogUp 和不为零，约束失败）。
        let lookup = OpcodeLookupElements::dummy();
        let claimed_sum = compute_table_claimed_sum_for_neg_one_multiplicity(&lookup, 1024);
        assert_ne!(
            claimed_sum,
            SecureField::default(),
            "claimed_sum 不应为零（multiplicity=-1 非零）"
        );
    }
}
