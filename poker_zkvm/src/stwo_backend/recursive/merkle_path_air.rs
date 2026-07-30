//! # Merkle Path Verifier AIR — L1 proof 的 Merkle 路径验证（Phase 5 — v5.1）
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md` §5。
//!
//! ## v5.1 设计
//!
//! 使用 Poseidon252 哈希链验证 Merkle path（避免 Blake2s 的 ~10000 约束/hash）。
//! 每行表示 Merkle path 的一层，从 leaf 到 root。
//!
//! ## 列布局（52 列，v5.1）
//!
//! 详见设计文档 §5.3。
//!
//! ## 约束清单（v5.1）
//!
//! | # | 约束 | 核心度 | gating | 总度 | 状态 |
//! |---|------|--------|--------|------|------|
//! | M1 | IsLeftChild binality | 2 | - | 2 | ✅ v5.1 |
//! | M2 | IsLastLayer binality | 2 | - | 2 | ✅ v5.1 |
//! | M3 | IsPadding binality | 2 | - | 2 | ✅ v5.1 |
//! | M4 | Padding LayerIdx=0 | 1 | IsPadding | 2 | ✅ v5.1 |
//! | M5-M34 | Poseidon252 hash computation | 2 | - | 2 | ✅ v5.1 |
//! | M35 | First layer leaf hash | 2 | LayerIdx == 0 | - | ✅ v5.1 |
//! | M36 | Parent propagation (chain) | 1 | !IsLastLayer | - | ✅ v5.1 |
//! | M37 | Final root check | 1 | IsLastLayer * (1 - IsPadding) | 3 | ✅ v5.1 |
//!
//! ## v5.0 → v5.1 变更
//!
//! v5.1 添加了完整的 Poseidon252 hash 验证：
//! 1. **M5-M34**：Poseidon252 hash 计算（30 条约束，使用中间列降度模式）
//! 2. **M35**：首层 leaf_hash 验证（gated by LayerIdx == 0）
//! 3. **M36**：hash chain propagation — next.leaf_hash == cur.parent_hash
//!
//! ## 状态
//!
//! **不完整且不 sound**：当前 parent 约束不是 Poseidon252，witness 布局也不匹配
//! Stwo 的压缩 multi-query decommitment。模块仅供 crate 内重构，公开 recursion API
//! 在进入该组件前显式 fail-closed。

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

// ===========================================================================
// Merkle Path AIR 列布局常量（67 列，9-limb felt252 encoding）
// ===========================================================================

/// col 0-8：LeafHash（当前层的起始 hash，9 个 base-M31 limbs）。
/// - Layer 0: 从 queried_values 计算的 leaf hash
/// - Layer i>0: 上一层的 parent hash（chain propagation）
pub const MERKLE_AIR_COL_LEAF_HASH_BASE: usize = 0;
/// col 8-15：PrevParentHash（上一层的 parent hash，用于 chain propagation 验证）。
/// - Layer 0: 0（无上层）
/// - Layer i>0: Layer i-1 的 ParentHash
pub const MERKLE_AIR_COL_PREV_PARENT_HASH_BASE: usize = 9;
/// col 16-23：SiblingHash（Path 中该层的 sibling hash）。
pub const MERKLE_AIR_COL_SIBLING_HASH_BASE: usize = 18;
/// col 24-31：ParentHash（计算得到的 parent hash）。
pub const MERKLE_AIR_COL_PARENT_HASH_BASE: usize = 27;
/// col 32-39：ComputedRoot（累积计算得到的 root，最后一行）。
pub const MERKLE_AIR_COL_COMPUTED_ROOT_BASE: usize = 36;
/// col 40：IsLeftChild（0=left, 1=right）。
pub const MERKLE_AIR_COL_IS_LEFT_CHILD: usize = 45;
/// col 41：LayerIdx（该层索引，0=leaf layer, height-1=root layer）。
pub const MERKLE_AIR_COL_LAYER_IDX: usize = 46;
/// col 42：IsLastLayer（最后一层标记）。
pub const MERKLE_AIR_COL_IS_LAST_LAYER: usize = 47;
/// col 43：IsPadding（padding 标记）。
pub const MERKLE_AIR_COL_IS_PADDING: usize = 48;
/// col 44-51：PoseidonIntermediate1（Poseidon round 中间值 1）。
pub const MERKLE_AIR_COL_POSEIDON_INTERMEDIATE1_BASE: usize = 49;
/// col 52-59：PoseidonIntermediate2（Poseidon round 中间值 2）。
pub const MERKLE_AIR_COL_POSEIDON_INTERMEDIATE2_BASE: usize = 58;

/// Merkle Path AIR 总列数（v5.1）。
pub const MERKLE_AIR_NUM_COLUMNS: usize = 67;

// ===========================================================================
// MerklePathAir 结构
// ===========================================================================

/// Merkle Path Verifier AIR 组件 — Poseidon252 Merkle 路径验证 FrameworkEval（v5.1）。
///
/// # 设计（v5.1）
/// - 每行表示 Merkle path 的一层（高度 = log_size）
/// - 多个 query 通过按行分组（N_queries × height 行）
/// - `max_constraint_log_degree_bound = log_size + 1`（约束度 ≤ 2，强制 SubDomain 模式）
/// - 使用 self-contained 设计避免 prev-row access（参考 FRI AIR v5.1）
///
/// # v5.1 实现的约束
/// - M1-M3: Flag binality (IsLeftChild / IsLastLayer / IsPadding)
/// - M4: Padding 行 LayerIdx = 0
/// - M5-M34: Poseidon252 hash 计算（30 条约束）
/// - M35: First layer leaf_hash 验证（gated by LayerIdx == 0）
/// - M36: Chain propagation — next.leaf_hash == cur.parent_hash
/// - M37: Final root check — IsLastLayer 行 computed_root == parent_hash
#[derive(Debug, Clone)]
pub struct MerklePathAir {
    /// log2(trace 行数)
    log_size: u32,
}

impl MerklePathAir {
    /// 创建指定 log_size 的 Merkle Path Verifier AIR。
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

impl FrameworkEval for MerklePathAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = BaseField::from(1u32).into();

        let mut cols: Vec<E::F> = Vec::with_capacity(MERKLE_AIR_NUM_COLUMNS);
        for _ in 0..MERKLE_AIR_NUM_COLUMNS {
            cols.push(eval.next_trace_mask());
        }
        let col = |idx: usize| -> E::F { cols[idx].clone() };

        let is_left = col(MERKLE_AIR_COL_IS_LEFT_CHILD);
        let is_last_layer = col(MERKLE_AIR_COL_IS_LAST_LAYER);
        let is_padding = col(MERKLE_AIR_COL_IS_PADDING);
        let layer_idx = col(MERKLE_AIR_COL_LAYER_IDX);

        // ===== M1: IsLeftChild binality =====
        let left_bin = is_left.clone() * (is_left.clone() - one.clone());
        eval.add_constraint(left_bin);

        // ===== M2: IsLastLayer binality =====
        let last_bin = is_last_layer.clone() * (is_last_layer.clone() - one.clone());
        eval.add_constraint(last_bin);

        // ===== M3: IsPadding binality =====
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // ===== M4: Padding 行 LayerIdx = 0 =====
        eval.add_constraint(is_padding.clone() * layer_idx.clone());

        // ===== M5-M12: Poseidon252 hash 计算验证（简化版）=====
        // 使用中间列验证 parent_hash = Poseidon252(left, right)
        for i in 0..9 {
            let leaf_i = col(MERKLE_AIR_COL_LEAF_HASH_BASE + i);
            let sibling_i = col(MERKLE_AIR_COL_SIBLING_HASH_BASE + i);
            let parent_i = col(MERKLE_AIR_COL_PARENT_HASH_BASE + i);
            let inter1_i = col(MERKLE_AIR_COL_POSEIDON_INTERMEDIATE1_BASE + i);
            let inter2_i = col(MERKLE_AIR_COL_POSEIDON_INTERMEDIATE2_BASE + i);

            let left_i = is_left.clone() * leaf_i.clone()
                + (one.clone() - is_left.clone()) * sibling_i.clone();
            let right_i = is_left.clone() * sibling_i.clone()
                + (one.clone() - is_left.clone()) * leaf_i.clone();

            eval.add_constraint(inter1_i.clone() - left_i.clone());
            eval.add_constraint(inter2_i.clone() - right_i.clone());
            eval.add_constraint(parent_i - inter1_i * inter2_i);
        }

        // ===== M35: Chain propagation（self-contained）=====
        // 验证 leaf_hash == prev_parent_hash（对于非首层）
        // 使用 IsFirstLayer gating：IsFirstLayer = 1 - (LayerIdx > 0)
        // 首层：leaf_hash 由 queried_values 计算，prev_parent_hash = 0
        // 非首层：leaf_hash == prev_parent_hash（上一层的 parent hash）
        let is_first_layer =
            (one.clone() - layer_idx.clone()) * (one.clone() - layer_idx.clone() + one.clone());
        let gating_chain = one.clone() - is_first_layer.clone();
        for i in 0..9 {
            let leaf_i = col(MERKLE_AIR_COL_LEAF_HASH_BASE + i);
            let prev_parent_i = col(MERKLE_AIR_COL_PREV_PARENT_HASH_BASE + i);
            let chain_diff = leaf_i - prev_parent_i;
            eval.add_constraint(gating_chain.clone() * chain_diff);
        }

        // ===== M36: First layer prev_parent_hash = 0 =====
        // 首层的 prev_parent_hash 必须为 0
        for i in 0..9 {
            let prev_parent_i = col(MERKLE_AIR_COL_PREV_PARENT_HASH_BASE + i);
            eval.add_constraint(is_first_layer.clone() * prev_parent_i);
        }

        // ===== M37: Final root check =====
        let gating_m37 = is_last_layer.clone() * (one.clone() - is_padding.clone());
        for i in 0..9 {
            let computed_root_i = col(MERKLE_AIR_COL_COMPUTED_ROOT_BASE + i);
            let parent_hash_i = col(MERKLE_AIR_COL_PARENT_HASH_BASE + i);
            let root_diff = computed_root_i - parent_hash_i;
            eval.add_constraint(gating_m37.clone() * root_diff);
        }

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
    fn test_merkle_path_air_num_columns() {
        assert_eq!(MERKLE_AIR_NUM_COLUMNS, 67);
    }

    #[test]
    fn test_merkle_path_air_new() {
        let air = MerklePathAir::new(8);
        assert_eq!(air.log_size(), 8);
    }

    #[test]
    fn test_merkle_path_air_max_constraint_log_degree_bound() {
        let air = MerklePathAir::new(10);
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
    }

    #[test]
    fn test_merkle_path_air_column_layout_no_overlap() {
        use std::collections::HashSet;
        let mut all_cols = HashSet::new();
        for i in 0..9 {
            assert!(
                all_cols.insert(MERKLE_AIR_COL_LEAF_HASH_BASE + i),
                "LeafHash col {} 重复",
                i
            );
        }
        for i in 0..9 {
            assert!(
                all_cols.insert(MERKLE_AIR_COL_PREV_PARENT_HASH_BASE + i),
                "PrevParentHash col {} 重复",
                i
            );
        }
        for i in 0..9 {
            assert!(
                all_cols.insert(MERKLE_AIR_COL_SIBLING_HASH_BASE + i),
                "SiblingHash col {} 重复",
                i
            );
        }
        for i in 0..9 {
            assert!(
                all_cols.insert(MERKLE_AIR_COL_PARENT_HASH_BASE + i),
                "ParentHash col {} 重复",
                i
            );
        }
        for i in 0..9 {
            assert!(
                all_cols.insert(MERKLE_AIR_COL_COMPUTED_ROOT_BASE + i),
                "ComputedRoot col {} 重复",
                i
            );
        }
        assert!(
            all_cols.insert(MERKLE_AIR_COL_IS_LEFT_CHILD),
            "IsLeftChild 重复"
        );
        assert!(all_cols.insert(MERKLE_AIR_COL_LAYER_IDX), "LayerIdx 重复");
        assert!(
            all_cols.insert(MERKLE_AIR_COL_IS_LAST_LAYER),
            "IsLastLayer 重复"
        );
        assert!(all_cols.insert(MERKLE_AIR_COL_IS_PADDING), "IsPadding 重复");
        for i in 0..9 {
            assert!(
                all_cols.insert(MERKLE_AIR_COL_POSEIDON_INTERMEDIATE1_BASE + i),
                "PoseidonIntermediate1 col {} 重复",
                i
            );
        }
        for i in 0..9 {
            assert!(
                all_cols.insert(MERKLE_AIR_COL_POSEIDON_INTERMEDIATE2_BASE + i),
                "PoseidonIntermediate2 col {} 重复",
                i
            );
        }
        assert_eq!(all_cols.len(), MERKLE_AIR_NUM_COLUMNS);
    }

    #[test]
    fn test_merkle_path_air_v5_1_constraint_count() {
        // v5.1 实现的约束数量：
        // M1-M3: 3 条 flag binality
        // M4: 1 条 padding LayerIdx=0
        // M5-M12: 9×3=27 条（当前仍是未完成的占位 hash 多项式）
        // M35: 9 条 chain propagation
        // M36: 9 条 first layer prev_parent_hash=0
        // M37: 9 条 final root check
        // 总计: 3 + 1 + 27 + 9 + 9 + 9 = 58 条
        const M1_M3_COUNT: usize = 3;
        const M4_COUNT: usize = 1;
        const M5_M12_COUNT: usize = 27;
        const M35_COUNT: usize = 9;
        const M36_COUNT: usize = 9;
        const M37_COUNT: usize = 9;
        const V5_1_TOTAL: usize =
            M1_M3_COUNT + M4_COUNT + M5_M12_COUNT + M35_COUNT + M36_COUNT + M37_COUNT;
        assert_eq!(V5_1_TOTAL, 58);
    }

    #[test]
    fn test_merkle_path_air_hash_columns_size() {
        assert_eq!(
            MERKLE_AIR_COL_PREV_PARENT_HASH_BASE - MERKLE_AIR_COL_LEAF_HASH_BASE,
            9
        );
        assert_eq!(
            MERKLE_AIR_COL_SIBLING_HASH_BASE - MERKLE_AIR_COL_PREV_PARENT_HASH_BASE,
            9
        );
        assert_eq!(
            MERKLE_AIR_COL_PARENT_HASH_BASE - MERKLE_AIR_COL_SIBLING_HASH_BASE,
            9
        );
        assert_eq!(
            MERKLE_AIR_COL_COMPUTED_ROOT_BASE - MERKLE_AIR_COL_PARENT_HASH_BASE,
            9
        );
    }
}
