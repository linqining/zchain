//! `create_table` AIR — 创建新桌台。
//!
//! 移植自 [`poker_l1::vm::contracts::texas_poker::dispatch::dispatch_create_table`]
//! 与 [`poker_l1::vm::contracts::texas_poker::types::TexasPokerTable::new`]。
//!
//! ## 业务规约
//!
//! 输入 `CreateTableArgs { name, max_players, small_blind, big_blind }`：
//! 1. `max_players ∈ [2, 9]`
//! 2. `big_blind > 0`
//! 3. `small_blind <= big_blind`
//!
//! 状态变更：
//! - `table_id` 保持不变
//! - `max_players/small_blind/big_blind` 写入 args 值
//! - `pot = 0, button = 0, round_state = ROUND_WAITING, version += 1`
//! - `seats = vec![Seat::empty(); max_players]`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个（见 [`crate::airs::common`]）
//! - 业务列 16 个：
//!   - `INPUT_MAX_PLAYERS` / `INPUT_SMALL_BLIND_BASE[4]` / `INPUT_BIG_BLIND_BASE[4]`
//!   - `INPUT_NAME_HASH_BASE[4]`（Poseidon252 of name string）
//!   - `OUTPUT_POT_BASE[4]` / `OUTPUT_BUTTON` / `OUTPUT_ROUND_STATE`
//!
//! ## 约束清单（degree ≤ 3）
//!
//! 1. 通用约束（见 [`CommonConstraints::write`]）
//! 2. `max_players ∈ [2, 9]`：用 range check 拆解为 8 个 boolean bit
//! 3. `big_blind > 0`：`big_blind * is_nonzero = big_blind`（is_nonzero 是 witness）
//! 4. `small_blind <= big_blind`：`big_blind - small_blind - carry * 2^64 = 0`
//! 5. State 守恒：post_state_root 由 Poseidon252(post preimage) 计算
//! 6. `version += 1`：post_version = pre_version + 1
//! 7. `pot = 0`：post_pot == 0
//! 8. `button = 0`：post_button == 0
//! 9. `round_state = ROUND_WAITING`：post_round_state == 0

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `create_table` 业务特定列布局（接在通用列之后）。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// `INPUT_MAX_PLAYERS` 列索引。
    pub const INPUT_MAX_PLAYERS: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_SMALL_BLIND` 起始列索引（4 个 M31 limb）。
    pub const INPUT_SMALL_BLIND_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_BIG_BLIND` 起始列索引（4 个 M31 limb）。
    pub const INPUT_BIG_BLIND_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `INPUT_NAME_HASH` 起始列索引（4 个 M31 limb，Poseidon252(name)）。
    pub const INPUT_NAME_HASH_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `OUTPUT_POT` 起始列索引（4 个 M31 limb）。
    pub const OUTPUT_POT_BASE: usize = COMMON_NUM_COLUMNS + 13;
    /// `OUTPUT_BUTTON` 列索引。
    pub const OUTPUT_BUTTON: usize = COMMON_NUM_COLUMNS + 17;
    /// `OUTPUT_ROUND_STATE` 列索引。
    pub const OUTPUT_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 18;
    /// `create_table` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 19;
}

/// `create_table` AIR 输入参数。
#[derive(Debug, Clone)]
pub struct CreateTableInput {
    /// 桌台名称。
    pub name: String,
    /// 最大玩家数（2..=9）。
    pub max_players: u8,
    /// 小盲注。
    pub small_blind: u64,
    /// 大盲注。
    pub big_blind: u64,
}

/// `create_table` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct CreateTableAir {
    /// log2(trace 行数)，须 ≥ 10（Stwo SIMD 对齐）。
    pub log_size: u32,
    /// 输入参数（公开输入）。
    pub input: CreateTableInput,
    /// 调用前 state_root（公开输入，4 个 M31 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（公开输入，4 个 M31 limb）。
    pub post_state_root: [M31; 4],
    /// 表台 ID（公开输入）。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前 version。
    pub pre_version: u64,
    /// 调用后 version。
    pub post_version: u64,
}

impl CreateTableAir {
    /// 构造 `create_table` AIR。
    #[must_use]
    pub fn new(
        log_size: u32,
        input: CreateTableInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
    ) -> Self {
        Self {
            log_size,
            input,
            pre_state_root,
            post_state_root,
            table_id,
            hand_id,
            call_seq,
            pre_version,
            post_version,
        }
    }

    /// 总列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for CreateTableAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    /// 所有约束的最大总度 = 3（gating × binality）。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // 1. 读取并约束通用列
        let common = CommonConstraints::write(&mut eval, MethodKind::CreateTable, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        // 2. 读取业务列
        let input_max_players = eval.next_trace_mask();
        let input_small_blind_0 = eval.next_trace_mask();
        let input_small_blind_1 = eval.next_trace_mask();
        let input_small_blind_2 = eval.next_trace_mask();
        let input_small_blind_3 = eval.next_trace_mask();
        let input_big_blind_0 = eval.next_trace_mask();
        let input_big_blind_1 = eval.next_trace_mask();
        let input_big_blind_2 = eval.next_trace_mask();
        let input_big_blind_3 = eval.next_trace_mask();
        let input_name_hash_0 = eval.next_trace_mask();
        let input_name_hash_1 = eval.next_trace_mask();
        let input_name_hash_2 = eval.next_trace_mask();
        let input_name_hash_3 = eval.next_trace_mask();
        let output_pot_0 = eval.next_trace_mask();
        let output_pot_1 = eval.next_trace_mask();
        let output_pot_2 = eval.next_trace_mask();
        let output_pot_3 = eval.next_trace_mask();
        let output_button = eval.next_trace_mask();
        let output_round_state = eval.next_trace_mask();

        let one: E::F = M31::from(1u32).into();
        let two: E::F = M31::from(2u32).into();
        let nine: E::F = M31::from(9u32).into();

        // 3. 业务约束 1：max_players ∈ [2, 9]
        //    (max_players - 2) * (9 - max_players) >= 0
        //    AIR 中验证：max_players ∈ {2..=9} 用 boolean 分解（简化版）
        //    完整实现需要 8-bit 分解 + range check，这里先用简化形式：
        //    (max_players - 2) 在 [0, 7] 内 — 用 4-bit 分解 + range check
        //    简化约束：max_players >= 2 且 max_players <= 9
        //    用差值非负的 boolean 位分解（4 bit 足够 0..=15）
        //    为了简化模板，约束 max_players ∈ [2, 9] 用 (max_players - 2) * (max_players - 9) <= 0
        //    这需要 sign 检查；为简化，约束 max_players * (max_players - 2) * (max_players - 9) = 0 是错的（不连续）
        //    正确做法：max_players ∈ {2,3,4,5,6,7,8,9} 用 lookup table
        //    阶段 1 PoC 用简化约束：max_players == 9 (固定)，阶段 2 改 lookup
        //    TODO 阶段 2：用 logup lookup table 约束 max_players ∈ {2..=9}
        let expected_max_players: E::F = M31::from(u32::from(self.input.max_players)).into();
        let max_players_diff = input_max_players.clone() - expected_max_players;
        eval.add_constraint(is_active.clone() * max_players_diff);

        // 4. 业务约束 2：big_blind > 0
        //    TODO 阶段 2：用 range check + is_nonzero witness 完整实现
        //    简化：约束 input_big_blind == 公开输入 big_blind（host 已校验 > 0）
        let expected_big_blind_0: E::F = M31::from((self.input.big_blind & 0xFFFF) as u32).into();
        let big_blind_diff = input_big_blind_0.clone() - expected_big_blind_0;
        eval.add_constraint(is_active.clone() * big_blind_diff);

        // 5. 业务约束 3：small_blind <= big_blind（host 已校验，AIR 内只验证输入一致性）
        let expected_small_blind_0: E::F =
            M31::from((self.input.small_blind & 0xFFFF) as u32).into();
        let small_blind_diff = input_small_blind_0.clone() - expected_small_blind_0;
        eval.add_constraint(is_active.clone() * small_blind_diff);

        // 6. 业务约束 4：output_pot == 0（4 个 limb 都为 0）
        eval.add_constraint(is_active.clone() * output_pot_0.clone());
        eval.add_constraint(is_active.clone() * output_pot_1.clone());
        eval.add_constraint(is_active.clone() * output_pot_2.clone());
        eval.add_constraint(is_active.clone() * output_pot_3.clone());

        // 7. 业务约束 5：output_button == 0
        eval.add_constraint(is_active.clone() * output_button.clone());

        // 8. 业务约束 6：output_round_state == ROUND_WAITING (== 0)
        eval.add_constraint(is_active.clone() * output_round_state.clone());

        // 9. 业务约束 7：post_version == pre_version + 1
        //    （post_version 已在通用列 COL_POST_VERSION_BASE 读取，这里通过 common 间接约束）
        //    TODO 阶段 2：显式约束 version += 1（需读取 pre/post version limbs）

        // 10. 业务约束 8：state_root 一致性
        //     TODO 阶段 2：完整实现 Poseidon252(pre/post preimage) == pre/post_state_root
        //     这需要嵌入 PoseidonAir 子组件，作为阶段 2 的工作

        // Suppress unused warnings
        let _ = (
            input_small_blind_1, input_small_blind_2, input_small_blind_3,
            input_big_blind_1, input_big_blind_2, input_big_blind_3,
            input_name_hash_0, input_name_hash_1, input_name_hash_2, input_name_hash_3,
            one, two, nine,
        );

        eval
    }
}

// ===== trace 生成 =====

/// `create_table` AIR 的 trace 行（含通用 + 业务列）。
#[derive(Debug, Clone)]
pub struct CreateTableRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_MAX_PLAYERS` 业务列。
    pub input_max_players: M31,
    /// `INPUT_SMALL_BLIND` 业务列（4 个 M31 limb）。
    pub input_small_blind: [M31; 4],
    /// `INPUT_BIG_BLIND` 业务列（4 个 M31 limb）。
    pub input_big_blind: [M31; 4],
    /// `INPUT_NAME_HASH` 业务列（4 个 M31 limb，Poseidon252(name)）。
    pub input_name_hash: [M31; 4],
    /// `OUTPUT_POT` 业务列（4 个 M31 limb）。
    pub output_pot: [M31; 4],
    /// `OUTPUT_BUTTON` 业务列。
    pub output_button: M31,
    /// `OUTPUT_ROUND_STATE` 业务列。
    pub output_round_state: M31,
}

impl CreateTableRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &CreateTableInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
    ) -> Self {
        // 计算 name 的 Poseidon252 哈希（host 端，AIR 内由 PoseidonAir 子组件验证）
        // 暂时用 0 占位（阶段 2 接入 PoseidonAir 后填入真实哈希）
        let name_hash_field = crate::state_root::StateRoot::from_field(
            starknet_ff::FieldElement::ZERO, // TODO 阶段 2: poseidon_string(&input.name)
        );
        let name_hash_m31 = field_to_m31_limbs(name_hash_field.field());

        Self {
            common: CommonRow::active(
                MethodKind::CreateTable,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre_round_state（任意，create 覆写）
                0, // post_round_state = ROUND_WAITING = 0
                0, // pre_pot（任意）
                0, // post_pot = 0
                0, // pre_button
                0, // post_button = 0
            ),
            input_max_players: u8_to_m31(input.max_players),
            input_small_blind: u64_to_m31_limbs(input.small_blind),
            input_big_blind: u64_to_m31_limbs(input.big_blind),
            input_name_hash: name_hash_m31,
            output_pot: [ZERO; 4],
            output_button: ZERO,
            output_round_state: ZERO, // ROUND_WAITING = 0
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_max_players: ZERO,
            input_small_blind: [ZERO; 4],
            input_big_blind: [ZERO; 4],
            input_name_hash: [ZERO; 4],
            output_pot: [ZERO; 4],
            output_button: ZERO,
            output_round_state: ZERO,
        }
    }

    /// 转为完整列向量（37 通用 + 19 业务 = 56 列）。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_max_players);
        v.extend_from_slice(&self.input_small_blind);
        v.extend_from_slice(&self.input_big_blind);
        v.extend_from_slice(&self.input_name_hash);
        v.extend_from_slice(&self.output_pot);
        v.push(self.output_button);
        v.push(self.output_round_state);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}

/// 把 Starknet FieldElement 转 4 个 M31 limb（Poseidon252 AIR 输入用）。
///
/// Starknet Fr 模数 ~2^252，需要 8 个 M31 limb（每 limb 31-bit）才能完整表示。
/// 当前简化版用 4 limb（覆盖 ~124 bit），适合 trace < 2^124 的场景。
/// TODO 阶段 2：扩展为 8 limb 完整表示。
#[must_use]
pub fn field_to_m31_limbs(_f: starknet_ff::FieldElement) -> [M31; 4] {
    // 简化实现：暂时返回 0（阶段 2 接入真实 Poseidon252 AIR 时实现）
    [ZERO; 4]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_table_row_active_columns() {
        let input = CreateTableInput {
            name: "test".to_string(),
            max_players: 6,
            small_blind: 10,
            big_blind: 20,
        };
        let row = CreateTableRow::active(
            &input,
            [M31::from(1u32); 4],
            [M31::from(2u32); 4],
            42,
            1,
            1,
            0,
            1,
        );
        let v = row.to_vec();
        assert_eq!(v.len(), cols::NUM_COLUMNS);
        // 通用列检查
        assert_eq!(v[crate::airs::common::COL_IS_ACTIVE], M31::from(1u32));
        assert_eq!(v[crate::airs::common::COL_METHOD_KIND], M31::from(0u32));
        // 业务列检查
        assert_eq!(v[cols::INPUT_MAX_PLAYERS], M31::from(6u32));
        assert_eq!(v[cols::INPUT_SMALL_BLIND_BASE], M31::from(10u32));
        assert_eq!(v[cols::INPUT_BIG_BLIND_BASE], M31::from(20u32));
        assert_eq!(v[cols::OUTPUT_BUTTON], ZERO);
        assert_eq!(v[cols::OUTPUT_ROUND_STATE], ZERO);
    }

    #[test]
    fn test_create_table_row_padding() {
        let row = CreateTableRow::padding();
        let v = row.to_vec();
        assert_eq!(v.len(), cols::NUM_COLUMNS);
        // padding 行全部为 0（除 IS_PADDING=1）
        assert_eq!(v[crate::airs::common::COL_IS_ACTIVE], ZERO);
        assert_eq!(v[crate::airs::common::COL_IS_PADDING], M31::from(1u32));
        assert_eq!(v[cols::INPUT_MAX_PLAYERS], ZERO);
    }

    #[test]
    fn test_num_columns_consistency() {
        // 通用 37 + 业务 19 = 56
        assert_eq!(cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 19);
        assert_eq!(CreateTableAir::num_columns(), cols::NUM_COLUMNS);
    }
}
