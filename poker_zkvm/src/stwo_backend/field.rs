//! # 域转换工具 — BN254 Fr ↔ M31
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"M31 field 转换策略"：
//! - BN254 Fr (254-bit) → M31 (31-bit)：9 limb × 32-bit
//! - 32-bit 地址/立即数：2 limb M31（high + low）
//! - 范围检查：M31 原生 31-bit，需多 limb 拼接
//!
//! ## M31 简介
//!
//! M31 = 2^31 - 1（Mersenne 31-bit prime），是 Stwo Circle STARK 的基域。
//! 31-bit 运算可原生用 CPU 32-bit word 完成，无需大整数运算。
//!
//! ## 转换策略
//!
//! | 源类型 | BN254 Fr 表达 | M31 表达 | 说明 |
//! |--------|--------------|---------|------|
//! | `u32` 值 | 1 个 Fr | 1-2 个 M31 | ≤ 2^31 - 1 → 1 个 M31；> 2^31 - 1 → 2 limb |
//! | 32-bit 地址 | 1 个 Fr | 2 limb M31 | high 1 bit + low 31 bit |
//! | 254-bit Fr | 1 个 Fr | 9 limb M31 | 9 × 28-bit 切片（避免溢出） |
//!
//! ## 当前状态（Phase 1.1）
//!
//! 仅提供类型别名与基础转换函数骨架。完整的非原生域算术（add_mod / mul_mod）留待
//! Phase 3.x precompile 迁移时实现。

use crate::ccs::Fr as ZkvmFr;
use crate::field::ZkvmField;

/// Stwo M31 域元素类型别名（重导出自 stwo crate）。
///
/// M31 = 2^31 - 1，31-bit Mersenne prime。
pub type M31 = stwo::core::fields::m31::M31;

/// Stwo 二次扩域 QM31（用于随机线性组合）。
pub type QM31 = stwo::core::fields::qm31::QM31;

/// M31 域模数 = 2^31 - 1（Mersenne 31-bit prime）。
pub const M31_MAX: u32 = (1u32 << 31) - 1;

/// 单 limb 最大位数（30 bit，确保 limb 值 < M31 模数 P = 2^31 - 1）。
///
/// 注意：不能直接用 31-bit limb，因为 `2^31 - 1 = P` 在 M31 中归约为 0。
/// 故 u32 拆分为 30-bit low + 2-bit high，两者均 < P。
pub const M31_LIMB_BITS: u32 = 30;

/// 30-bit limb 掩码。
pub const M31_LIMB_MASK: u32 = (1u32 << M31_LIMB_BITS) - 1;

/// 将 u32 拆分为 2 个 M31 limb（low 30 bit + high 2 bit）。
///
/// # 设计原因
///
/// M31 模数 P = 2^31 - 1。若用 31-bit limb，则值 `2^31 - 1 = P` 会归约为 0，
/// 导致 roundtrip 失败。改用 30-bit limb 确保 limb 值 ∈ [0, 2^30 - 1] ⊂ [0, P-1]。
///
/// # 返回
/// `(low, high)`：
/// - `low` = `value & 0x3FFFFFFF`（低 30 位，max 2^30 - 1）
/// - `high` = `value >> 30`（高 2 位，max 3）
///
/// # 重建
/// `value = low + (high << 30)`
pub fn split_u32_to_m31_limbs(value: u32) -> (M31, M31) {
    let low = value & M31_LIMB_MASK;
    let high = value >> M31_LIMB_BITS;
    (M31::from(low), M31::from(high))
}

/// 将 2 个 M31 limb 重建为 u32（`split_u32_to_m31_limbs` 的逆操作）。
///
/// # 参数
/// - `low` — 低 30 位（须 ≤ 2^30 - 1）
/// - `high` — 高 2 位（须 ≤ 3）
pub fn merge_m31_limbs_to_u32(low: M31, high: M31) -> u32 {
    // M31 是 `pub struct M31(pub u32)`，直接访问 `.0` 取原始 u32 值
    low.0 | (high.0 << M31_LIMB_BITS)
}

/// 将 poker_zkvm BN254 Fr 转换为 9 个 M31 limb（用于 254-bit 非原生域运算）。
///
/// # 算法
/// 将 254-bit Fr 切片为 9 个 29-bit limb（9 × 29 = 261 > 254，避免乘法溢出）。
///
/// # 当前状态
/// Phase 1.1 仅提供骨架，实际转换留待 Phase 3.x precompile 迁移。
pub fn fr_to_m31_limbs(_fr: &ZkvmFr) -> [M31; 9] {
    // TODO(Phase 3.x): 实现 BN254 Fr → 9 limb M31 转换
    // 当前返回零数组，仅用于占位编译
    [M31::from(0u32); 9]
}

/// 将 9 个 M31 limb 重建为 BN254 Fr（`fr_to_m31_limbs` 的逆操作）。
///
/// # 当前状态
/// Phase 1.1 仅提供骨架，实际转换留待 Phase 3.x precompile 迁移。
pub fn m31_limbs_to_fr(_limbs: &[M31; 9]) -> ZkvmFr {
    // TODO(Phase 3.x): 实现 9 limb M31 → BN254 Fr 转换
    ZkvmFr::zero()
}

/// 将 u32 值转换为单个 M31（若值 ≤ M31_MAX）。
///
/// # 错误
/// 若 `value > M31_MAX`，返回 `Err`（调用方须改用 `split_u32_to_m31_limbs`）。
pub fn u32_to_m31(value: u32) -> Result<M31, ZkvmFr> {
    if value <= M31_MAX {
        Ok(M31::from(value))
    } else {
        Err(ZkvmFr::from_u64(value as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_merge_u32_roundtrip() {
        // 边界值测试
        for &value in &[0u32, 1, 100, M31_MAX, M31_MAX + 1, u32::MAX] {
            let (low, high) = split_u32_to_m31_limbs(value);
            let reconstructed = merge_m31_limbs_to_u32(low, high);
            assert_eq!(reconstructed, value, "u32 split/merge roundtrip 失败: {}", value);
        }
    }

    #[test]
    fn test_u32_to_m31_within_range() {
        assert!(u32_to_m31(0).is_ok());
        assert!(u32_to_m31(M31_MAX).is_ok());
        assert!(u32_to_m31(M31_MAX + 1).is_err());
        assert!(u32_to_m31(u32::MAX).is_err());
    }
}
