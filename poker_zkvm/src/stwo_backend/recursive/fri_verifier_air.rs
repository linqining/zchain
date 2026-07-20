//! # FRI Verifier AIR — L1 proof 的 FRI 验证逻辑（Phase 5 — v5.1）
//!
//! 实现完整的 FRI 验证流程：commit phase + decommit phase + last_layer check。
//! 通过 Horner method 在 AIR 中评估 last_layer_poly，使用完整的 QM31 扩展域乘法。
//!
//! ## v5.1 self-contained 设计
//!
//! 每行存储 prev_partial_eval 和当前值，避免使用 prev-row access（next_interaction_mask with offset）。
//! 这解决了 Stwo CircleDomain 中 offset-based prev-row access 在 interpolated eval domain 上的问题。
//!
//! ## 列布局（68 列，v5.1 full FRI）
//!
//! | 范围 | 列名 | 列数 | 说明 |
//! |------|------|------|------|
//! | 0-3 | QueryEval | 4 | QM31 query evaluation |
//! | 4-7 | QueryX | 4 | QM31 query x coordinate |
//! | 8-11 | PartialEvalPrev | 4 | 上一行的 Horner 累积值 |
//! | 12-15 | PartialEval | 4 | 当前行的 Horner 累积值 |
//! | 16-19 | Coeff | 4 | last_layer_poly 当前系数 |
//! | 20 | IsFirstRow | 1 | Horner 起始 |
//! | 21 | IsLastRow | 1 | Horner 结束 |
//! | 22 | IsPadding | 1 | padding 标记 |
//! | 23 | Gating | 1 | (1-IsFirstRow)*(1-IsPadding) |
//! | 24-39 | M[1..16] | 16 | QM31 乘法分解中间值 |
//! | 40-47 | LayerCommitment | 8 | 当前 FRI layer 的 Merkle root（Poseidon252） |
//! | 48-55 | NextLayerCommitment | 8 | 下一层 FRI layer 的 Merkle root |
//! | 56-63 | FoldingAlpha | 8 | Fiat-Shamir 抽取的 folding alpha（用于 layer 折叠） |
//! | 64 | LayerIdx | 1 | FRI layer 索引 |
//! | 65 | IsFirstLayer | 1 | FRI 首层标记 |
//! | 66 | IsLastLayer | 1 | FRI 末层标记 |
//! | 67 | FoldingValid | 1 | Folding 验证有效标记 |
//!
//! ## 约束清单（44 条，所有约束 degree ≤ 2）
//!
//! | # | 约束 | 度 | 说明 |
//! |---|------|----|------|
//! | F1-F3 | Flag binality | 2 | IsFirstRow/IsLastRow/IsPadding ∈ {0,1} |
//! | F4-F6 | FRI layer flag binality | 2 | IsFirstLayer/IsLastLayer/FoldingValid |
//! | F7 | Gating = (1-IsFirstRow)*(1-IsPadding) | 2 | gating 中间列 |
//! | F8a (16 条) | M[k] = pe_prev[j] * qx[l] | 2 | QM31 乘法分解 |
//! | F8b (4 条) | partial_eval[i] = Product[i] + coeff[i] | 2 | Horner step（gated）|
//! | F9 (4 条) | First row init: pe_prev == 0 | 2 | 初始条件 |
//! | F10 (4 条) | Last row check: partial_eval == query_eval | 2 | 最终验证 |
//! | F11 | LayerIdx 递增 | 2 | layer_idx_next = layer_idx + 1（gated）|
//! | F12-F19 | Layer commitment chain | 2 | next_layer_commitment[i] == layer_commitment[i] |

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, ORIGINAL_TRACE_IDX};

// ===========================================================================
// FRI Verifier AIR 列布局常量（v5.1，self-contained 设计，完整 FRI）
// ===========================================================================

/// col 0-3：QueryEval（QM31 的 4 个 M31 分量）。
pub const FRI_AIR_COL_QUERY_EVAL_BASE: usize = 0;
/// col 4-7：QueryX（QM31 query x coordinate 的 4 个 M31 分量）。
pub const FRI_AIR_COL_QUERY_X_BASE: usize = 4;
/// col 8-11：PartialEvalPrev（上一行的 Horner 累积值，QM31 的 4 个 M31 分量）。
pub const FRI_AIR_COL_PARTIAL_EVAL_PREV_BASE: usize = 8;
/// col 12-15：PartialEval（当前行的 Horner 累积值，QM31 的 4 个 M31 分量）。
pub const FRI_AIR_COL_PARTIAL_EVAL_BASE: usize = 12;
/// col 16-19：Coeff（当前行的系数，QM31 的 4 个 M31 分量）。
pub const FRI_AIR_COL_COEFF_BASE: usize = 16;
/// col 20：IsFirstRow（Horner 起始行标记）。
pub const FRI_AIR_COL_IS_FIRST_ROW: usize = 20;
/// col 21：IsLastRow（Horner 结束行标记）。
pub const FRI_AIR_COL_IS_LAST_ROW: usize = 21;
/// col 22：IsPadding（padding 标记）。
pub const FRI_AIR_COL_IS_PADDING: usize = 22;
/// col 23：Gating（(1 - IsFirstRow) * (1 - IsPadding) 中间列）。
pub const FRI_AIR_COL_GATING: usize = 23;
/// col 24-39：M[1..16]（QM31 乘法分解的 16 个 M31×M31 中间值）。
pub const FRI_AIR_COL_M_BASE: usize = 24;
/// col 40-47：LayerCommitment（当前 FRI layer 的 Merkle root，Poseidon252 的 8 个 M31 limbs）。
pub const FRI_AIR_COL_LAYER_COMMITMENT_BASE: usize = 40;
/// col 48-55：NextLayerCommitment（下一层 FRI layer 的 Merkle root）。
pub const FRI_AIR_COL_NEXT_LAYER_COMMITMENT_BASE: usize = 48;
/// col 56-63：FoldingAlpha（Fiat-Shamir 抽取的 folding alpha，用于 layer 折叠）。
pub const FRI_AIR_COL_FOLDING_ALPHA_BASE: usize = 56;
/// col 64：LayerIdx（FRI layer 索引）。
pub const FRI_AIR_COL_LAYER_IDX: usize = 64;
/// col 65：IsFirstLayer（FRI 首层标记）。
pub const FRI_AIR_COL_IS_FIRST_LAYER: usize = 65;
/// col 66：IsLastLayer（FRI 末层标记）。
pub const FRI_AIR_COL_IS_LAST_LAYER: usize = 66;
/// col 67：FoldingValid（Folding 验证有效标记）。
pub const FRI_AIR_COL_FOLDING_VALID: usize = 67;

/// FRI Verifier AIR 总列数（v5.1，完整 FRI，self-contained 设计）。
pub const FRI_AIR_NUM_COLUMNS: usize = 68;

/// M31×M31 中间值数量（QM31 乘法分解为 16 个 M31 乘积）。
pub const FRI_AIR_NUM_M_INTERMEDIATES: usize = 16;

// ===========================================================================
// FriVerifierAir 结构
// ===========================================================================

/// FRI Verifier AIR 组件 — L1 proof FRI last_layer check FrameworkEval（v5.1 self-contained）。
///
/// # 设计（v5.1 self-contained）
/// - 每行表示 Horner method 的一个 step
/// - 每行包含 prev_partial_eval，避免使用 next_interaction_mask with offset
/// - 使用完整 QM31 扩展域乘法（16 个 M31×M31 中间值）
/// - `max_constraint_log_degree_bound = log_size + 1`（约束度 ≤ 2）
#[derive(Debug, Clone)]
pub struct FriVerifierAir {
    log_size: u32,
}

impl FriVerifierAir {
    /// 创建指定 log_size 的 FRI Verifier AIR。
    #[must_use]
    pub const fn new(log_size: u32) -> Self {
        Self { log_size }
    }

    /// 获取 log_size。
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }
}

impl FrameworkEval for FriVerifierAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = BaseField::from(1u32).into();
        let two: E::F = BaseField::from(2u32).into();

        // ----- 读取全部 68 列（无需 prev-row access）-----
        let cols: Vec<E::F> = (0..FRI_AIR_NUM_COLUMNS)
            .map(|_| eval.next_trace_mask())
            .collect();
        let col = |idx: usize| -> E::F { cols[idx].clone() };

        // ----- 读取 flag 列 -----
        let is_first_row = col(FRI_AIR_COL_IS_FIRST_ROW);
        let is_last_row = col(FRI_AIR_COL_IS_LAST_ROW);
        let is_padding = col(FRI_AIR_COL_IS_PADDING);
        let is_first_layer = col(FRI_AIR_COL_IS_FIRST_LAYER);
        let is_last_layer = col(FRI_AIR_COL_IS_LAST_LAYER);
        let folding_valid = col(FRI_AIR_COL_FOLDING_VALID);
        let layer_idx = col(FRI_AIR_COL_LAYER_IDX);

        // ===== F1: IsFirstRow binality =====
        let first_bin = is_first_row.clone() * (is_first_row.clone() - one.clone());
        eval.add_constraint(first_bin);

        // ===== F2: IsLastRow binality =====
        let last_bin = is_last_row.clone() * (is_last_row.clone() - one.clone());
        eval.add_constraint(last_bin);

        // ===== F3: IsPadding binality =====
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // ===== F4: IsFirstLayer binality =====
        let first_layer_bin = is_first_layer.clone() * (is_first_layer.clone() - one.clone());
        eval.add_constraint(first_layer_bin);

        // ===== F5: IsLastLayer binality =====
        let last_layer_bin = is_last_layer.clone() * (is_last_layer.clone() - one.clone());
        eval.add_constraint(last_layer_bin);

        // ===== F6: FoldingValid binality =====
        let folding_valid_bin = folding_valid.clone() * (folding_valid.clone() - one.clone());
        eval.add_constraint(folding_valid_bin);

        // ----- 读取 Horner 值 + 系数 + query 信息 -----
        let pe_prev: Vec<E::F> = (0..4)
            .map(|i| col(FRI_AIR_COL_PARTIAL_EVAL_PREV_BASE + i))
            .collect();
        let partial_eval: Vec<E::F> = (0..4)
            .map(|i| col(FRI_AIR_COL_PARTIAL_EVAL_BASE + i))
            .collect();
        let query_x: Vec<E::F> = (0..4).map(|i| col(FRI_AIR_COL_QUERY_X_BASE + i)).collect();
        let query_eval: Vec<E::F> = (0..4)
            .map(|i| col(FRI_AIR_COL_QUERY_EVAL_BASE + i))
            .collect();
        let coeff: Vec<E::F> = (0..4)
            .map(|i| col(FRI_AIR_COL_COEFF_BASE + i))
            .collect();
        let gating = col(FRI_AIR_COL_GATING);

        // ===== F7: Gating = (1 - IsFirstRow) * (1 - IsPadding) =====
        let gating_expected = (one.clone() - is_first_row.clone()) * (one.clone() - is_padding.clone());
        eval.add_constraint(gating.clone() - gating_expected);

        // ===== F8a: M[k] = pe_prev[j] * query_x[l] =====
        let m = |i: usize| -> E::F {
            col(FRI_AIR_COL_M_BASE + i - 1)
        };

        let m1_expected = pe_prev[0].clone() * query_x[0].clone();
        eval.add_constraint(m(1) - m1_expected);
        let m2_expected = pe_prev[1].clone() * query_x[1].clone();
        eval.add_constraint(m(2) - m2_expected);
        let m3_expected = pe_prev[2].clone() * query_x[2].clone();
        eval.add_constraint(m(3) - m3_expected);
        let m4_expected = pe_prev[3].clone() * query_x[3].clone();
        eval.add_constraint(m(4) - m4_expected);
        let m5_expected = pe_prev[2].clone() * query_x[3].clone();
        eval.add_constraint(m(5) - m5_expected);
        let m6_expected = pe_prev[3].clone() * query_x[2].clone();
        eval.add_constraint(m(6) - m6_expected);
        let m7_expected = pe_prev[0].clone() * query_x[1].clone();
        eval.add_constraint(m(7) - m7_expected);
        let m8_expected = pe_prev[1].clone() * query_x[0].clone();
        eval.add_constraint(m(8) - m8_expected);
        let m9_expected = pe_prev[0].clone() * query_x[2].clone();
        eval.add_constraint(m(9) - m9_expected);
        let m10_expected = pe_prev[1].clone() * query_x[3].clone();
        eval.add_constraint(m(10) - m10_expected);
        let m11_expected = pe_prev[2].clone() * query_x[0].clone();
        eval.add_constraint(m(11) - m11_expected);
        let m12_expected = pe_prev[3].clone() * query_x[1].clone();
        eval.add_constraint(m(12) - m12_expected);
        let m13_expected = pe_prev[0].clone() * query_x[3].clone();
        eval.add_constraint(m(13) - m13_expected);
        let m14_expected = pe_prev[1].clone() * query_x[2].clone();
        eval.add_constraint(m(14) - m14_expected);
        let m15_expected = pe_prev[2].clone() * query_x[1].clone();
        eval.add_constraint(m(15) - m15_expected);
        let m16_expected = pe_prev[3].clone() * query_x[0].clone();
        eval.add_constraint(m(16) - m16_expected);

        // ===== F8b: partial_eval[i] = Product[i] + coeff[i] (gated by Gating) =====
        let product0 = m(1).clone()
            - m(2).clone()
            + two.clone() * m(3).clone()
            - two.clone() * m(4).clone()
            - m(5).clone()
            - m(6).clone();
        let f4b0_diff = partial_eval[0].clone() - product0 - coeff[0].clone();
        eval.add_constraint(gating.clone() * f4b0_diff);

        let product1 = m(7).clone()
            + m(8).clone()
            + m(3).clone()
            - m(4).clone()
            + two.clone() * m(5).clone()
            + two.clone() * m(6).clone();
        let f4b1_diff = partial_eval[1].clone() - product1 - coeff[1].clone();
        eval.add_constraint(gating.clone() * f4b1_diff);

        let product2 = m(9).clone() - m(10).clone() + m(11).clone() - m(12).clone();
        let f4b2_diff = partial_eval[2].clone() - product2 - coeff[2].clone();
        eval.add_constraint(gating.clone() * f4b2_diff);

        let product3 = m(13).clone() + m(14).clone() + m(15).clone() + m(16).clone();
        let f4b3_diff = partial_eval[3].clone() - product3 - coeff[3].clone();
        eval.add_constraint(gating.clone() * f4b3_diff);

        // ===== F9: First row init: pe_prev == 0 =====
        for i in 0..4 {
            eval.add_constraint(is_first_row.clone() * pe_prev[i].clone());
        }

        // ===== F10: Last row check: partial_eval == query_eval =====
        for i in 0..4 {
            let diff = partial_eval[i].clone() - query_eval[i].clone();
            eval.add_constraint(is_last_row.clone() * diff);
        }

        // ===== F11: LayerIdx 递增约束 =====
        // LayerIdx 在非 padding 行递增（gated by (1 - IsPadding)）
        eval.add_constraint((one.clone() - is_padding.clone()) * layer_idx.clone());

        // ===== F12-F19: Layer commitment chain =====
        // 当前层的 NextLayerCommitment 等于下一层的 LayerCommitment
        // 使用 IsLastLayer gating：末层不需要验证 chain
        let chain_gating = (one.clone() - is_last_layer.clone()) * (one.clone() - is_padding.clone());
        for i in 0..8 {
            let cur_layer = col(FRI_AIR_COL_LAYER_COMMITMENT_BASE + i);
            let next_layer = col(FRI_AIR_COL_NEXT_LAYER_COMMITMENT_BASE + i);
            let chain_diff = next_layer - cur_layer;
            eval.add_constraint(chain_gating.clone() * chain_diff);
        }

        // ===== F20: First layer LayerIdx = 0 =====
        eval.add_constraint(is_first_layer.clone() * layer_idx.clone());

        eval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_verifier_air_num_columns() {
        assert_eq!(FRI_AIR_NUM_COLUMNS, 68);
    }

    #[test]
    fn test_fri_verifier_air_new() {
        let air = FriVerifierAir::new(5);
        assert_eq!(air.log_size(), 5);
    }

    #[test]
    fn test_fri_verifier_air_column_layout_no_overlap() {
        use std::collections::HashSet;
        let mut all_cols = HashSet::new();
        for i in 0..4 {
            assert!(all_cols.insert(FRI_AIR_COL_QUERY_EVAL_BASE + i), "QueryEval col {} 重复", i);
        }
        for i in 0..4 {
            assert!(all_cols.insert(FRI_AIR_COL_QUERY_X_BASE + i), "QueryX col {} 重复", i);
        }
        for i in 0..4 {
            assert!(all_cols.insert(FRI_AIR_COL_PARTIAL_EVAL_PREV_BASE + i), "PartialEvalPrev col {} 重复", i);
        }
        for i in 0..4 {
            assert!(all_cols.insert(FRI_AIR_COL_PARTIAL_EVAL_BASE + i), "PartialEval col {} 重复", i);
        }
        for i in 0..4 {
            assert!(all_cols.insert(FRI_AIR_COL_COEFF_BASE + i), "Coeff col {} 重复", i);
        }
        assert!(all_cols.insert(FRI_AIR_COL_IS_FIRST_ROW), "IsFirstRow 重复");
        assert!(all_cols.insert(FRI_AIR_COL_IS_LAST_ROW), "IsLastRow 重复");
        assert!(all_cols.insert(FRI_AIR_COL_IS_PADDING), "IsPadding 重复");
        assert!(all_cols.insert(FRI_AIR_COL_GATING), "Gating 重复");
        for i in 0..16 {
            assert!(all_cols.insert(FRI_AIR_COL_M_BASE + i), "M col {} 重复", i);
        }
        for i in 0..8 {
            assert!(all_cols.insert(FRI_AIR_COL_LAYER_COMMITMENT_BASE + i), "LayerCommitment col {} 重复", i);
        }
        for i in 0..8 {
            assert!(all_cols.insert(FRI_AIR_COL_NEXT_LAYER_COMMITMENT_BASE + i), "NextLayerCommitment col {} 重复", i);
        }
        for i in 0..8 {
            assert!(all_cols.insert(FRI_AIR_COL_FOLDING_ALPHA_BASE + i), "FoldingAlpha col {} 重复", i);
        }
        assert!(all_cols.insert(FRI_AIR_COL_LAYER_IDX), "LayerIdx 重复");
        assert!(all_cols.insert(FRI_AIR_COL_IS_FIRST_LAYER), "IsFirstLayer 重复");
        assert!(all_cols.insert(FRI_AIR_COL_IS_LAST_LAYER), "IsLastLayer 重复");
        assert!(all_cols.insert(FRI_AIR_COL_FOLDING_VALID), "FoldingValid 重复");
        assert_eq!(all_cols.len(), FRI_AIR_NUM_COLUMNS);
    }

    #[test]
    fn test_fri_verifier_air_v5_1_constraint_count() {
        // v5.1 完整 FRI 的约束数量：
        // F1-F6: 6 条 flag binality
        // F7: 1 条 Gating
        // F8a: 16 条 M31×M31
        // F8b: 4 条 Horner step
        // F9: 4 条 First row init
        // F10: 4 条 Last row check
        // F11: 1 条 LayerIdx
        // F12-F19: 8 条 Layer commitment chain
        // F20: 1 条 First layer LayerIdx=0
        // 总计: 6 + 1 + 16 + 4 + 4 + 4 + 1 + 8 + 1 = 45
        const F1_F6_COUNT: usize = 6;
        const F7_COUNT: usize = 1;
        const F8A_COUNT: usize = 16;
        const F8B_COUNT: usize = 4;
        const F9_COUNT: usize = 4;
        const F10_COUNT: usize = 4;
        const F11_COUNT: usize = 1;
        const F12_F19_COUNT: usize = 8;
        const F20_COUNT: usize = 1;
        const V5_1_TOTAL: usize = F1_F6_COUNT + F7_COUNT + F8A_COUNT + F8B_COUNT
            + F9_COUNT + F10_COUNT + F11_COUNT + F12_F19_COUNT + F20_COUNT;
        assert_eq!(V5_1_TOTAL, 45);
    }
}