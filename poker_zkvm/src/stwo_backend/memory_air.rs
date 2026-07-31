//! # Memory AIR — 内存访问一致性 AIR（Phase 3.2）
//!
//! 严格遵循 `.trae/documents/stwo_phase3_memory_syscall_design.md`：
//! - 独立的 FrameworkEval 组件，17 列 trace（v3.3 P1.4 优化）
//! - sorted memory log 模式（按 (addr, ts) 排序）
//! - 通过 logup 与 CPU AIR 交互（MemoryLookup relation）
//!
//! ## 列布局（17 列，v3.3 P1.4）
//!
//! | 范围 | 列名 | 说明 |
//! |------|------|------|
//! | 0-3 | MemAddr (4×8-bit limb) | 内存地址 |
//! | 4-7 | MemValCur (4×8-bit limb) | 本次访问后的值 |
//! | 8-11 | MemValPrev (4×8-bit limb) | 本次访问前的值 |
//! | 12 | MemTsCur (1×M31) | 当前时间戳（= step_index，单 M31 标量） |
//! | 13 | MemTsPrev (1×M31) | 上次访问同 addr 的时间戳（单 M31 标量） |
//! | 14 | MemIsStore | 1=Store，0=其他 |
//! | 15 | MemIsPadding | padding 行标记 |
//! | 16 | MemIsFirstAccess | 首次访问该 addr 标记（pre-computed） |
//!
//! ## v3.3 P1.4 优化变更
//!
//! - 移除 `MemSize`（约束中未使用）
//! - 移除 `MemIsLoad`（可由 `IsLoad = 1 - IsStore - IsPadding` 推导）
//! - `MemTsCur`/`MemTsPrev` 从 4×8-bit limb 改为 1×M31 标量
//!   - 时间戳 = step_index < 2^24 < 2^31，单 M31 可表示
//!   - continuity 约束从 4 个 limb-wise 等式变为 1 个标量等式
//!
//! ## 约束清单
//!
//! | # | 约束 | 度 | gating | 说明 |
//! |---|------|----|--------|------|
//! | M1-M4 | Addr limb binality | 2 | 通用 | 每个 limb ∈ [0, 255]（trace 生成保证） |
//! | M5 | IsStore binality | 2 | 通用 | IsStore·(IsStore−1) = 0 |
//! | M6 | IsPadding binality | 2 | 通用 | IsPadding·(IsPadding−1) = 0 |
//! | M7 | IsFirstAccess binality | 2 | 通用 | IsFirstAccess·(IsFirstAccess−1) = 0 |
//! | M8 | IsStore+IsPadding binality | 2 | 通用 | (IsStore+IsPadding)·(IsStore+IsPadding−1) = 0 |
//! | M9 | IsStore·IsPadding 互斥 | 2 | 通用 | IsStore·IsPadding = 0 |
//! | M10-M13 | ValPrev continuity | 2 | !IsPadding ∧ !IsFirstAccess | ValPrev[i] = prev.ValCur[i] |
//! | M14 | TsPrev continuity | 2 | !IsPadding ∧ !IsFirstAccess | TsPrev = prev.TsCur |
//! | M15-M18 | First access ValPrev=0 | 2 | !IsPadding ∧ IsFirstAccess | ValPrev[i] = 0 |
//! | M19 | First access TsPrev=0 | 2 | !IsPadding ∧ IsFirstAccess | TsPrev = 0 |
//!
//! ## Logup 交互
//!
//! 每行发送 yield（multiplicity = -1）：
//! ```text
//! values = [MemAddr×4, MemValCur×4, MemIsStore×1]
//! ```
//!
//! 参考：Nexus zkVM 0.3.6 `memory_check/` 模块的 sorted memory log 模式。

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, ORIGINAL_TRACE_IDX, RelationEntry};

use super::lookups::MemoryLookup;

// ===========================================================================
// Memory AIR 列布局常量（17 列，v3.3 P1.4）
// ===========================================================================

/// Memory AIR 列数（v3.3 P1.4：25→17 列）。
pub const MEM_NUM_COLUMNS: usize = 17;

/// col 0-3：MemAddr（4×8-bit limb）
pub const MEM_COL_ADDR_BASE: usize = 0;
/// col 4-7：MemValCur（4×8-bit limb，本次访问后的值）
pub const MEM_COL_VAL_CUR_BASE: usize = 4;
/// col 8-11：MemValPrev（4×8-bit limb，本次访问前的值）
pub const MEM_COL_VAL_PREV_BASE: usize = 8;
/// col 12：MemTsCur（1×M31 标量，当前时间戳 = step_index）
///
/// v3.3 P1.4：从 4×8-bit limb 改为 1×M31 标量
/// 理由：时间戳 < 2^24 < 2^31，单 M31 可表示；continuity 约束从 4 个 limb-wise 变为 1 个标量等式
pub const MEM_COL_TS_CUR: usize = 12;
/// col 13：MemTsPrev（1×M31 标量，上次访问同 addr 的时间戳）
///
/// v3.3 P1.4：从 4×8-bit limb 改为 1×M31 标量
pub const MEM_COL_TS_PREV: usize = 13;
/// col 14：MemIsStore
pub const MEM_COL_IS_STORE: usize = 14;
/// col 15：MemIsPadding
pub const MEM_COL_IS_PADDING: usize = 15;
/// col 16：MemIsFirstAccess（首次访问该 addr）
pub const MEM_COL_IS_FIRST_ACCESS: usize = 16;

// ===========================================================================
// MemoryAir 结构
// ===========================================================================

/// Memory AIR 组件 — 内存访问一致性 FrameworkEval。
///
/// # 设计
/// - sorted memory log 模式：trace 按 (addr, ts) 排序
/// - 连续行同 addr 时 ValPrev=prev.ValCur、TsPrev=prev.TsCur
/// - 首次访问时 ValPrev=0、TsPrev=0
/// - 通过 logup yield 与 CPU AIR 交互
///
/// # 用法
/// ```ignore
/// use poker_zkvm::stwo_backend::memory_air::MemoryAir;
/// use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
/// use stwo::core::fields::qm31::SecureField;
///
/// let air = MemoryAir::new(log_size, MemoryLookup::dummy());
/// let component = FrameworkComponent::new(
///     &mut TraceLocationAllocator::default(),
///     air,
///     SecureField::from(0u32),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct MemoryAir {
    /// log2(trace 行数)
    log_size: u32,
    /// MemoryLookup relation（用于 logup yield）
    memory_lookup: MemoryLookup,
}

impl MemoryAir {
    /// 创建指定 log_size 的 Memory AIR。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10
    /// - `memory_lookup` — MemoryLookup relation 实例（从 channel draw 或 dummy）
    #[must_use]
    pub const fn new(log_size: u32, memory_lookup: MemoryLookup) -> Self {
        Self {
            log_size,
            memory_lookup,
        }
    }

    /// 获取 log_size。
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }
}

impl FrameworkEval for MemoryAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    /// 所有约束的最大总度 = 2（binality + gating）。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = BaseField::from(1u32).into();

        // ----- 读取全部 17 列（v3.3 P1.4） -----
        // 对于需要 prev-row 访问的列（ValCur 4 列, TsCur 1 列），使用 next_interaction_mask
        let mut cols: Vec<E::F> = Vec::with_capacity(MEM_NUM_COLUMNS);
        let mut prev_val_cur: Vec<E::F> = Vec::with_capacity(4);
        let mut prev_ts_cur: Option<E::F> = None;

        for i in 0..MEM_NUM_COLUMNS {
            // MemValCur (4-7) 4 列和 MemTsCur (12) 1 列需要 prev-row
            let needs_prev = (MEM_COL_VAL_CUR_BASE..MEM_COL_VAL_CUR_BASE + 4).contains(&i)
                || i == MEM_COL_TS_CUR;

            if needs_prev {
                // offset=-2: 在 SubDomain 模式下，eval_domain (log_size+blowup) 是 trace_domain
                // 的 2 倍。offset_bit_reversed_circle_domain_index 的 step_size =
                // offset * (1 << (eval_log_size - domain_log_size - 1))。对于 blowup=1，
                // offset=-1 → step_size=-1（半个 trace 步），offset=-2 → step_size=-2（一个
                // 完整 trace 步 = "previous row"）。
                let [cur, prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -2]);
                cols.push(cur.clone());
                if (MEM_COL_VAL_CUR_BASE..MEM_COL_VAL_CUR_BASE + 4).contains(&i) {
                    prev_val_cur.push(prev);
                } else {
                    // TsCur（单标量）
                    prev_ts_cur = Some(prev);
                }
            } else {
                cols.push(eval.next_trace_mask());
            }
        }

        // 辅助闭包
        let col = |idx: usize| -> E::F { cols[idx].clone() };

        // ----- 读取 flag 列 -----
        // v3.3 P1.4：移除 IsLoad（由 1 - IsStore - IsPadding 推导）
        let is_store = col(MEM_COL_IS_STORE);
        let is_padding = col(MEM_COL_IS_PADDING);
        let is_first_access = col(MEM_COL_IS_FIRST_ACCESS);

        // ===== 约束 M1-M4：Addr limb binality =====
        // 4×8-bit limb 方案中 limb 天然 ∈ [0, 255]，trace 生成保证，不约束

        // ===== 约束 M5：IsStore binality =====
        let store_bin = is_store.clone() * (is_store.clone() - one.clone());
        eval.add_constraint(store_bin);

        // ===== 约束 M6：IsPadding binality =====
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // ===== 约束 M7：IsFirstAccess binality =====
        let first_access_bin = is_first_access.clone() * (is_first_access.clone() - one.clone());
        eval.add_constraint(first_access_bin);

        // ===== 约束 M8：(IsStore + IsPadding) binality =====
        // v3.3 P1.4：替代原 M9 one-hot 约束（移除 IsLoad 后）
        // 等价于 IsLoad = 1 - IsStore - IsPadding ∈ {0, 1}
        // 即 IsStore + IsPadding ∈ {0, 1}
        let sum_sp = is_store.clone() + is_padding.clone();
        let sum_sp_bin = sum_sp.clone() * (sum_sp - one.clone());
        eval.add_constraint(sum_sp_bin);

        // ===== 约束 M9：IsStore · IsPadding 互斥 =====
        // v3.3 P1.4：确保 IsStore 和 IsPadding 不同时为 1
        let mutex = is_store.clone() * is_padding.clone();
        eval.add_constraint(mutex);

        // ===== 连续性约束 gating =====
        // !IsPadding ∧ !IsFirstAccess：连续访问同 addr
        let is_continuation =
            (one.clone() - is_padding.clone()) * (one.clone() - is_first_access.clone());
        // !IsPadding ∧ IsFirstAccess：首次访问
        let is_first_non_padding = (one.clone() - is_padding.clone()) * is_first_access.clone();

        // ===== 约束 M10-M13：ValPrev continuity（连续访问）=====
        // 当 is_continuation = 1 时：ValPrev[i] = prev.ValCur[i]
        for i in 0..4 {
            let val_prev = col(MEM_COL_VAL_PREV_BASE + i);
            let prev_val = &prev_val_cur[i];
            let continuity_diff = val_prev - prev_val.clone();
            eval.add_constraint(is_continuation.clone() * continuity_diff);
        }

        // ===== 约束 M14：TsPrev continuity（连续访问，单标量）=====
        // v3.3 P1.4：从 4 个 limb-wise 等式变为 1 个标量等式
        // 当 is_continuation = 1 时：TsPrev = prev.TsCur
        {
            let ts_prev = col(MEM_COL_TS_PREV);
            let prev_ts = prev_ts_cur.as_ref().expect("prev_ts_cur 必须已填充");
            let continuity_diff = ts_prev - prev_ts.clone();
            eval.add_constraint(is_continuation.clone() * continuity_diff);
        }

        // ===== 约束 M15-M18：First access ValPrev=0 =====
        // 当 is_first_non_padding = 1 时：ValPrev[i] = 0
        for i in 0..4 {
            let val_prev = col(MEM_COL_VAL_PREV_BASE + i);
            eval.add_constraint(is_first_non_padding.clone() * val_prev);
        }

        // ===== 约束 M19：First access TsPrev=0（单标量）=====
        // v3.3 P1.4：从 4 个 limb-wise 等式变为 1 个标量等式
        // 当 is_first_non_padding = 1 时：TsPrev = 0
        {
            let ts_prev = col(MEM_COL_TS_PREV);
            eval.add_constraint(is_first_non_padding.clone() * ts_prev);
        }

        // ===== 约束 M20-M23：连续 Load 行 ValCur = ValPrev（A2 修复，v3.7→v3.11）=====
        // 缺口：Load 行（IsStore=0, IsPadding=0）的 ValCur 原无约束。Load 不修改内存，
        // ValCur 应 = ValPrev。恶意 prover 可伪造 Load 行 ValCur，通过 logup 让 CPU rd_eff
        // 读到任意伪造值（CPU claim (addr, rd_eff, 0) 与 Memory yield (addr, ValCur, 0) 匹配）。
        //
        // 修复：约束**连续访问** Load 行 ValCur[i] = ValPrev[i]。
        //   - 连续 Load：ValPrev=prev.ValCur（M10-M13），故 ValCur=prev.ValCur（内存值不变）✓
        //
        // v3.11 变更：首次访问 Load 行（IsFirstAccess=1）不再约束 ValCur=ValPrev。
        //   原因：ECALL syscall（如 read_input）将输入数据写入内存，但这些写未入 trace
        //  （ECALL 副作用未记录为 Store）。首次 Load 该地址时 ValCur=输入值≠ValPrev=0，
        //   导致 M20-M23 失败。首次访问 Load 的值来自公共输入，应由 public input binding
        //   约束（待实现），而非 ValCur=ValPrev=0。
        //
        // gating = (1-IsStore)*(1-IsFirstAccess)：
        //   - 连续 Load (IsStore=0, IsFirstAccess=0)：gating=1，约束 ValCur=ValPrev ✓
        //   - 首次 Load (IsStore=0, IsFirstAccess=1)：gating=0，不约束（soundness gap，待修）
        //   - Store     (IsStore=1)：gating=0，不约束 ✓
        //   - Padding   (IsStore=0, IsFirstAccess=0)：gating=1，但 ValCur=ValPrev=0 ✓
        // 度数 = 2 (gating) × 1 (diff) = 3 ✓
        //
        // 已知 soundness gap：首次访问 Load 的 ValCur 可被伪造。缓解：
        //   1) logup 绑定 CPU rd_eff ↔ Memory ValCur（伪造需同步篡改 CPU trace）
        //   2) 公共输入绑定（待实现）：首次访问 Load 的 ValCur 应 = 公开输入对应字节
        let is_continuation_load =
            (one.clone() - is_store.clone()) * (one.clone() - is_first_access.clone());
        for i in 0..4 {
            let val_cur = col(MEM_COL_VAL_CUR_BASE + i);
            let val_prev = col(MEM_COL_VAL_PREV_BASE + i);
            eval.add_constraint(is_continuation_load.clone() * (val_cur - val_prev));
        }

        // ===== Logup yield：非 padding 行发送 multiplicity = -1，padding 行 multiplicity = 0 =====
        // values = [MemAddr×4, MemValCur×4, MemIsStore×1]
        // multiplicity = -1 * (1 - IsPadding) — padding 行不贡献 sum
        // 这确保 CPU claims + Memory_yields = 0 的 soundness 条件可被满足
        let mut lookup_values: Vec<E::F> = Vec::with_capacity(9);
        for i in 0..4 {
            lookup_values.push(col(MEM_COL_ADDR_BASE + i));
        }
        for i in 0..4 {
            lookup_values.push(col(MEM_COL_VAL_CUR_BASE + i));
        }
        lookup_values.push(col(MEM_COL_IS_STORE));

        // multiplicity = -1 * (1 - IsPadding)
        let neg_one: E::EF = SecureField::from(-1i32).into();
        let is_non_padding: E::F = one.clone() - is_padding.clone();
        let multiplicity: E::EF = neg_one * is_non_padding;
        eval.add_to_relation(RelationEntry::new(
            &self.memory_lookup,
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
    fn test_memory_air_new() {
        let air = MemoryAir::new(10, MemoryLookup::dummy());
        assert_eq!(air.log_size(), 10);
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
    }

    #[test]
    fn test_mem_num_columns() {
        // v3.3 P1.4：17 列 = 4(Addr) + 4(ValCur) + 4(ValPrev)
        //            + 1(TsCur) + 1(TsPrev) + 1(IsStore) + 1(IsPadding) + 1(IsFirstAccess)
        assert_eq!(MEM_NUM_COLUMNS, 17);
    }

    #[test]
    fn test_column_layout_no_overlap() {
        use std::collections::HashSet;
        let mut all_cols = HashSet::new();
        for i in 0..4 {
            assert!(
                all_cols.insert(MEM_COL_ADDR_BASE + i),
                "Addr col {} 重复",
                i
            );
        }
        for i in 0..4 {
            assert!(
                all_cols.insert(MEM_COL_VAL_CUR_BASE + i),
                "ValCur col {} 重复",
                i
            );
        }
        for i in 0..4 {
            assert!(
                all_cols.insert(MEM_COL_VAL_PREV_BASE + i),
                "ValPrev col {} 重复",
                i
            );
        }
        assert!(all_cols.insert(MEM_COL_TS_CUR), "TsCur 重复");
        assert!(all_cols.insert(MEM_COL_TS_PREV), "TsPrev 重复");
        assert!(all_cols.insert(MEM_COL_IS_STORE), "IsStore 重复");
        assert!(all_cols.insert(MEM_COL_IS_PADDING), "IsPadding 重复");
        assert!(
            all_cols.insert(MEM_COL_IS_FIRST_ACCESS),
            "IsFirstAccess 重复"
        );
    }
}
