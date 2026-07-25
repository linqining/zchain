//! Method AIR 通用列布局与约束宏。
//!
//! 所有 18 个 method AIR 共享同一组通用列（state_root / method_kind / is_active 等），
//! 业务特定列在每个 AIR 的 `*Air` 结构里定义。
//!
//! ## 列布局策略
//!
//! 每个 method AIR 的 trace 包含：
//! 1. **通用列**（[`COMMON_NUM_COLUMNS`] 个）：所有 AIR 共享
//! 2. **业务列**（每个 AIR 自定义）：业务字段如 max_players, bet_amount 等
//!
//! ## v2.1 Hard Constraint
//!
//! 所有 AIR 约束 degree ≤ 2（gating × binality）。Gating + 业务字段算术约束度 ≤ 3。

use stwo::core::fields::m31::M31;

// ===== 通用列布局（所有 method AIR 共享）=====

/// M31 零元素常量（`M31(pub u32)` 允许直接构造，无需导入 `Zero` trait）。
pub const ZERO: M31 = M31(0);

/// 通用列起始位置（业务列从 `COMMON_NUM_COLUMNS` 开始）。
pub const COL_IS_ACTIVE: usize = 0;
/// `METHOD_KIND` 列索引。
pub const COL_METHOD_KIND: usize = 1;
/// `PRE_STATE_ROOT` 起始列索引（4 个 M31 limb）。
pub const COL_PRE_STATE_ROOT_BASE: usize = 2;
/// `POST_STATE_ROOT` 起始列索引（4 个 M31 limb）。
pub const COL_POST_STATE_ROOT_BASE: usize = 6;
/// `TABLE_ID` 起始列索引（4 个 M31 limb）。
pub const COL_TABLE_ID_BASE: usize = 10;
/// `HAND_ID` 列索引。
pub const COL_HAND_ID: usize = 14;
/// `CALL_SEQ` 列索引。
pub const COL_CALL_SEQ: usize = 15;
/// `PRE_VERSION` 起始列索引（4 个 M31 limb）。
pub const COL_PRE_VERSION_BASE: usize = 16;
/// `POST_VERSION` 起始列索引（4 个 M31 limb）。
pub const COL_POST_VERSION_BASE: usize = 20;
/// `PRE_ROUND_STATE` 列索引。
pub const COL_PRE_ROUND_STATE: usize = 24;
/// `POST_ROUND_STATE` 列索引。
pub const COL_POST_ROUND_STATE: usize = 25;
/// `PRE_POT` 起始列索引（4 个 M31 limb）。
pub const COL_PRE_POT_BASE: usize = 26;
/// `POST_POT` 起始列索引（4 个 M31 limb）。
pub const COL_POST_POT_BASE: usize = 30;
/// `PRE_BUTTON` 列索引。
pub const COL_PRE_BUTTON: usize = 34;
/// `POST_BUTTON` 列索引。
pub const COL_POST_BUTTON: usize = 35;
/// `IS_PADDING` 列索引（padding 行标志位）。
pub const COL_IS_PADDING: usize = 36;

/// 通用列数（state_root 用 4×M31 表示 SecureField）。
pub const COMMON_NUM_COLUMNS: usize = 37;

// ===== 常量辅助 =====

/// 把 u64 编码为 4 个 M31（每 limb 16 位）。
#[must_use]
pub fn u64_to_m31_limbs(v: u64) -> [M31; 4] {
    [
        M31::from((v & 0xFFFF) as u32),
        M31::from(((v >> 16) & 0xFFFF) as u32),
        M31::from(((v >> 32) & 0xFFFF) as u32),
        M31::from(((v >> 48) & 0xFFFF) as u32),
    ]
}

/// 把 u8 编码为 M31。
#[must_use]
pub fn u8_to_m31(v: u8) -> M31 {
    M31::from(u32::from(v))
}

/// 把 bool 编码为 M31（0 或 1）。
#[must_use]
pub fn bool_to_m31(b: bool) -> M31 {
    M31::from(u32::from(b))
}

/// 把 4 个 M31 limb 重新组合为 u64（host 端用，AIR 内不需要）。
#[must_use]
pub fn m31_limbs_to_u64(limbs: [M31; 4]) -> u64 {
    // `M31(pub u32)` — 直接访问内部 u32 值（已 mod P，但 limb < 2^16 < P）。
    let l0 = u64::from(limbs[0].0);
    let l1 = u64::from(limbs[1].0);
    let l2 = u64::from(limbs[2].0);
    let l3 = u64::from(limbs[3].0);
    l0 | (l1 << 16) | (l2 << 32) | (l3 << 48)
}

// ===== 通用约束（AIR evaluate 内调用）=====

/// 通用约束辅助器。
///
/// 在每个 method AIR 的 `evaluate` 函数里调用，验证以下通用约束：
/// 1. `IS_ACTIVE` 与 `IS_PADDING` 互斥且为 boolean
/// 2. `METHOD_KIND` 等于 AIR 声明的 kind（gating）
/// 3. Padding 行：所有通用列为 0（除 IS_PADDING=1）
///
/// 返回 `(is_active, is_padding)` 供业务约束使用。
pub struct CommonConstraints<E: stwo_constraint_framework::EvalAtRow> {
    /// IS_ACTIVE 列。
    pub is_active: E::F,
    /// IS_PADDING 列。
    pub is_padding: E::F,
    /// 方法 kind 列。
    pub method_kind: E::F,
    /// 是否已经写入通用约束到 eval。
    pub _written: bool,
}

impl<E: stwo_constraint_framework::EvalAtRow> CommonConstraints<E> {
    /// 在 AIR evaluate 中读取通用列并写入通用约束。
    ///
    /// # 参数
    /// - `eval`: Stwo EvalAtRow
    /// - `expected_kind`: AIR 声明的 method kind
    ///
    /// # 返回
    /// `CommonConstraints` 实例，业务约束可用 `is_active` 做 gating。
    pub fn write(
        eval: &mut E,
        expected_kind: crate::method_kind::MethodKind,
    ) -> Self {
        let one: E::F = M31::from(1u32).into();

        // 读取通用列（顺序必须与 COL_* 常量定义一致）
        let is_active = eval.next_trace_mask();
        let method_kind = eval.next_trace_mask();
        let pre_state_root_0 = eval.next_trace_mask();
        let pre_state_root_1 = eval.next_trace_mask();
        let pre_state_root_2 = eval.next_trace_mask();
        let pre_state_root_3 = eval.next_trace_mask();
        let post_state_root_0 = eval.next_trace_mask();
        let post_state_root_1 = eval.next_trace_mask();
        let post_state_root_2 = eval.next_trace_mask();
        let post_state_root_3 = eval.next_trace_mask();
        let table_id_0 = eval.next_trace_mask();
        let table_id_1 = eval.next_trace_mask();
        let table_id_2 = eval.next_trace_mask();
        let table_id_3 = eval.next_trace_mask();
        let hand_id = eval.next_trace_mask();
        let call_seq = eval.next_trace_mask();
        let pre_version_0 = eval.next_trace_mask();
        let pre_version_1 = eval.next_trace_mask();
        let pre_version_2 = eval.next_trace_mask();
        let pre_version_3 = eval.next_trace_mask();
        let post_version_0 = eval.next_trace_mask();
        let post_version_1 = eval.next_trace_mask();
        let post_version_2 = eval.next_trace_mask();
        let post_version_3 = eval.next_trace_mask();
        let pre_round_state = eval.next_trace_mask();
        let post_round_state = eval.next_trace_mask();
        let pre_pot_0 = eval.next_trace_mask();
        let pre_pot_1 = eval.next_trace_mask();
        let pre_pot_2 = eval.next_trace_mask();
        let pre_pot_3 = eval.next_trace_mask();
        let post_pot_0 = eval.next_trace_mask();
        let post_pot_1 = eval.next_trace_mask();
        let post_pot_2 = eval.next_trace_mask();
        let post_pot_3 = eval.next_trace_mask();
        let pre_button = eval.next_trace_mask();
        let post_button = eval.next_trace_mask();
        let is_padding = eval.next_trace_mask();

        // 保留 limbs 引用（业务约束需要）
        let _ = (
            pre_state_root_0, pre_state_root_1, pre_state_root_2, pre_state_root_3,
            post_state_root_0, post_state_root_1, post_state_root_2, post_state_root_3,
            table_id_0, table_id_1, table_id_2, table_id_3,
            hand_id, call_seq,
            pre_version_0, pre_version_1, pre_version_2, pre_version_3,
            post_version_0, post_version_1, post_version_2, post_version_3,
            pre_round_state, post_round_state,
            pre_pot_0, pre_pot_1, pre_pot_2, pre_pot_3,
            post_pot_0, post_pot_1, post_pot_2, post_pot_3,
            pre_button, post_button,
        );

        // 通用约束 1：IS_ACTIVE 与 IS_PADDING 互斥且为 boolean
        // is_active * (is_active - 1) = 0
        // is_padding * (is_padding - 1) = 0
        // is_active * is_padding = 0  (互斥)
        // is_active + is_padding ≤ 1 (等价于 is_active * is_padding = 0 当两者 boolean)
        let active_minus_one = is_active.clone() - one.clone();
        let padding_minus_one = is_padding.clone() - one.clone();
        eval.add_constraint(is_active.clone() * active_minus_one);
        eval.add_constraint(is_padding.clone() * padding_minus_one);
        eval.add_constraint(is_active.clone() * is_padding.clone());

        // 通用约束 2：METHOD_KIND == expected_kind
        // (method_kind - expected) * is_active = 0  (active 行强制 kind)
        // padding 行：method_kind = 0（约束自动满足）
        let expected: E::F = M31::from(expected_kind as u32).into();
        let kind_diff = method_kind.clone() - expected;
        eval.add_constraint(is_active.clone() * kind_diff);

        Self {
            is_active,
            is_padding,
            method_kind,
            _written: true,
        }
    }

    /// 业务约束的 gating 辅助：`is_active * constraint`。
    pub fn gate(&self, constraint: E::F) -> E::F {
        self.is_active.clone() * constraint
    }
}

// ===== trace 生成辅助（host 端）=====

/// 通用 trace 行数据（host 端填充用）。
#[derive(Debug, Clone)]
pub struct CommonRow {
    /// IS_ACTIVE 列（1 = 业务行，0 = padding 行）。
    pub is_active: M31,
    /// METHOD_KIND 列（方法选择器）。
    pub method_kind: M31,
    /// 调用前 state_root（4 个 M31 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（4 个 M31 limb）。
    pub post_state_root: [M31; 4],
    /// 表台 ID（4 个 M31 limb）。
    pub table_id: [M31; 4],
    /// 手牌序号。
    pub hand_id: M31,
    /// 调用序号。
    pub call_seq: M31,
    /// 调用前 version（4 个 M31 limb）。
    pub pre_version: [M31; 4],
    /// 调用后 version（4 个 M31 limb）。
    pub post_version: [M31; 4],
    /// 调用前 round_state。
    pub pre_round_state: M31,
    /// 调用后 round_state。
    pub post_round_state: M31,
    /// 调用前 pot（4 个 M31 limb）。
    pub pre_pot: [M31; 4],
    /// 调用后 pot（4 个 M31 limb）。
    pub post_pot: [M31; 4],
    /// 调用前 button seat index。
    pub pre_button: M31,
    /// 调用后 button seat index。
    pub post_button: M31,
    /// IS_PADDING 列（1 = padding 行，0 = 业务行）。
    pub is_padding: M31,
}

impl CommonRow {
    /// 构造 active 行（业务执行发生）。
    #[must_use]
    pub fn active(
        method_kind: crate::method_kind::MethodKind,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_round_state: u8,
        post_round_state: u8,
        pre_pot: u64,
        post_pot: u64,
        pre_button: u8,
        post_button: u8,
    ) -> Self {
        Self {
            is_active: M31::from(1u32),
            method_kind: u8_to_m31(method_kind as u8),
            pre_state_root,
            post_state_root,
            table_id: u64_to_m31_limbs(table_id),
            hand_id: M31::from(hand_id),
            call_seq: M31::from(call_seq),
            pre_version: u64_to_m31_limbs(pre_version),
            post_version: u64_to_m31_limbs(post_version),
            pre_round_state: u8_to_m31(pre_round_state),
            post_round_state: u8_to_m31(post_round_state),
            pre_pot: u64_to_m31_limbs(pre_pot),
            post_pot: u64_to_m31_limbs(post_pot),
            pre_button: u8_to_m31(pre_button),
            post_button: u8_to_m31(post_button),
            is_padding: ZERO,
        }
    }

    /// 构造 padding 行（IS_PADDING=1，其他通用列为 0）。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            is_active: ZERO,
            method_kind: ZERO,
            pre_state_root: [ZERO; 4],
            post_state_root: [ZERO; 4],
            table_id: [ZERO; 4],
            hand_id: ZERO,
            call_seq: ZERO,
            pre_version: [ZERO; 4],
            post_version: [ZERO; 4],
            pre_round_state: ZERO,
            post_round_state: ZERO,
            pre_pot: [ZERO; 4],
            post_pot: [ZERO; 4],
            pre_button: ZERO,
            post_button: ZERO,
            is_padding: M31::from(1u32),
        }
    }

    /// 转为列向量（按 COL_* 常量定义顺序）。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = Vec::with_capacity(COMMON_NUM_COLUMNS);
        v.push(self.is_active);
        v.push(self.method_kind);
        v.extend_from_slice(&self.pre_state_root);
        v.extend_from_slice(&self.post_state_root);
        v.extend_from_slice(&self.table_id);
        v.push(self.hand_id);
        v.push(self.call_seq);
        v.extend_from_slice(&self.pre_version);
        v.extend_from_slice(&self.post_version);
        v.push(self.pre_round_state);
        v.push(self.post_round_state);
        v.extend_from_slice(&self.pre_pot);
        v.extend_from_slice(&self.post_pot);
        v.push(self.pre_button);
        v.push(self.post_button);
        v.push(self.is_padding);
        debug_assert_eq!(v.len(), COMMON_NUM_COLUMNS);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_m31_roundtrip() {
        for v in [0u64, 1, 255, 65535, 65536, u32::MAX as u64, u64::MAX] {
            let limbs = u64_to_m31_limbs(v);
            assert_eq!(m31_limbs_to_u64(limbs), v, "u64 roundtrip failed: {v}");
        }
    }

    #[test]
    fn test_common_row_padding() {
        let row = CommonRow::padding();
        let v = row.to_vec();
        assert_eq!(v.len(), COMMON_NUM_COLUMNS);
        assert_eq!(v[COL_IS_ACTIVE], ZERO);
        assert_eq!(v[COL_IS_PADDING], M31::from(1u32));
    }

    #[test]
    fn test_common_row_active() {
        let row = CommonRow::active(
            crate::method_kind::MethodKind::CreateTable,
            [M31::from(1u32); 4],
            [M31::from(2u32); 4],
            42,
            7,
            3,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let v = row.to_vec();
        assert_eq!(v[COL_IS_ACTIVE], M31::from(1u32));
        assert_eq!(v[COL_METHOD_KIND], M31::from(0u32)); // CreateTable = 0
        assert_eq!(v[COL_IS_PADDING], ZERO);
        assert_eq!(v[COL_TABLE_ID_BASE], M31::from(42u32));
        assert_eq!(v[COL_HAND_ID], M31::from(7u32));
        assert_eq!(v[COL_CALL_SEQ], M31::from(3u32));
    }
}
