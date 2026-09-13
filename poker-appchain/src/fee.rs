//! M5：费率模块。
//!
//! 核心原则（plan §0）：**费率是状态机里的数据（策略注册表），不是协议参数**。
//! v1 两种策略：`ZERO`（零费休闲桌）与 `FIXED_RAKE`（固定比例 + 封顶 +
//! 分账）；TE-E0 追加枚举先行的 `FIXED_RAKE_BURN`（判别值 2，GAME 桌
//! 销毁计费）。策略在开桌时绑定并**冻结**（注册表无更新路径），结算关系
//! （M2）按 policy_commitment 验证抽取，篡改即不可证明。
//!
//! 对齐既有资产：`canonical_rake_opening` 的 `rake_mode`（NONE=0 /
//! PERCENTAGE=1 / FIXED_RAKE_BURN=2）与本模块语义一致，ABI 层保持相同
//! 判别值（三仓对照见 `docs/ABI_TE.md`）。判别值一经发布即冻结。
//!
//! ## FIXED_RAKE_BURN 语义边界（TE-E0，枚举先行）
//!
//! `FixedRakeBurn` 只承载**计价**（rate_bps/cap 与 `FixedRake` 同式：
//! `min(base * rate_bps / 10_000, cap)`，`split_of` 同式）——fee 层不管
//! 资金去向。**销毁语义在合约侧实现（poker_l1，TE-M4 排期）**：燃烧的
//! 资金处置规则（燃烧份额、事件、守恒闭合）由合约定义；在合约规则落地
//! 前，结算/分账路径（`settlement.rs` / `note_v2.rs` 的 `FixedRake`
//! 分支）不会匹配该变体，且现有流程不会构造 burn 策略，故行为不变。
//!
//! ## rake 计费基数（ABI v1.2.2，BLOCKERS B9 口径统一）
//!
//! `rake_of` 的输入语义是 **rake 基数**（rake base），不是结算记录的全额
//! gross pot：结算关系（M2）以 `policy.rake_of(plan.rake_base())` 校验
//! 抽取，其中 `plan.rake_base()` = plan 内 **contested 层**（eligible ≥ 2
//! 座）的 gross 之和。uncalled 返还层（uncontested）不计费——`plan.validate`
//! 强制其 rake == 0，因此 `plan.rake` 只能来自 contested 层。这与 poker_l1
//! canonical 的 contested-only 计费（`derive_settlement_plan` 对 contested
//! gross 取费）**唯一同口径**：无 uncalled 层的手二者数值恒等（rake_base ==
//! gross_pot）；含 uncalled 层的手按 contested 基数计费（v1.2.1 前误按全额
//! gross 计费导致此类手被 fail-closed 误拒，已修正）。

use std::collections::BTreeMap;

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::error::{AppchainError, AppchainResult};
use crate::felt::{bytes32_to_felts, domain_felt, felt_from_u64, felt_to_bytes32, DOMAIN_FEE_POLICY};

/// rake 模式判别值，对齐 `canonical_rake_opening`（NONE=0, PERCENTAGE=1,
/// FIXED_RAKE_BURN=2）。判别值一经发布即冻结，不得重排或复用。
pub mod rake_mode {
    /// 零费。
    pub const NONE: u8 = 0;
    /// 固定比例。
    pub const PERCENTAGE: u8 = 1;
    /// 固定比例计费 + GAME 桌销毁处置（TE-E0 枚举先行；销毁的资金处置
    /// 规则在 poker_l1 合约侧实现，fee 层只承载计价）。
    pub const FIXED_RAKE_BURN: u8 = 2;
}

/// 分账配置：treasury 按 bps 取 rake，其余归 operator。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct FeeSplit {
    /// treasury 份额（bps of rake，≤ 10000），其余为 operator。
    pub treasury_bps: u16,
    /// treasury 收款公钥（压缩）。
    pub treasury: [u8; 33],
    /// operator 收款公钥（压缩）。
    pub operator: [u8; 33],
}

/// 费率策略（ABI v1）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum FeePolicy {
    /// 零费（休闲/测试桌）。
    Zero,
    /// 固定比例 rake。
    FixedRake {
        /// 比例（bps of pot，≤ 10000）。
        rate_bps: u16,
        /// 单手封顶（0 = 无封顶）。
        cap: u64,
        /// 分账。
        split: FeeSplit,
    },
    /// 固定比例计费 + GAME 桌销毁处置（TE-E0，borsh 判别值 2，末位追加）。
    ///
    /// **判别值冻结**：borsh 枚举判别值 = 声明序，本变体必须保持末位，
    /// 已有序列化数据（判别值 0/1）不受影响。计费数学与 [`FeePolicy::FixedRake`]
    /// 完全同式——burn 只是合约侧的资金处置语义（poker_l1，TE-M4），
    /// fee 层只承载计价，不改抽取/分账数学。
    FixedRakeBurn {
        /// 比例（bps of pot，≤ 10000）。
        rate_bps: u16,
        /// 单手封顶（0 = 无封顶）。
        cap: u64,
        /// 分账（计价层拆分；合约侧销毁处置如何映射该拆分由合约规则定义）。
        split: FeeSplit,
    },
}

impl FeePolicy {
    /// rake 模式判别值。
    #[must_use]
    pub const fn mode(&self) -> u8 {
        match self {
            Self::Zero => rake_mode::NONE,
            Self::FixedRake { .. } => rake_mode::PERCENTAGE,
            Self::FixedRakeBurn { .. } => rake_mode::FIXED_RAKE_BURN,
        }
    }

    /// 计算抽取额：`min(base * rate_bps / 10000, cap)`，向下取整。
    ///
    /// 零费策略恒 0；Zero 桌上基数任意大抽取仍为 0（M5-ACC-1）。
    /// `base` 语义见模块文档"rake 计费基数"：结算路径传入
    /// `plan.rake_base()`（contested 层 gross 之和，uncalled 返还不计费），
    /// 单层 contested plan 退化为 `rake_of(gross_pot)`。
    #[must_use]
    pub fn rake_of(&self, base: u64) -> u64 {
        match self {
            Self::Zero => 0,
            Self::FixedRake { rate_bps, cap, .. }
            | Self::FixedRakeBurn { rate_bps, cap, .. } => {
                let raw = (u128::from(base) * u128::from(*rate_bps)) / 10_000;
                let capped = if *cap == 0 {
                    raw
                } else {
                    raw.min(u128::from(*cap))
                };
                u64::try_from(capped).unwrap_or(u64::MAX)
            }
        }
    }

    /// 分账拆分：返回 (treasury_amount, operator_amount)。
    ///
    /// 向下取整保证两份之和 == total（零头归 operator）。
    #[must_use]
    pub fn split_of(&self, total: u64) -> (u64, u64) {
        match self {
            Self::Zero => (0, 0),
            Self::FixedRake { split, .. } | Self::FixedRakeBurn { split, .. } => {
                let t = (u128::from(total) * u128::from(split.treasury_bps)) / 10_000;
                let t = u64::try_from(t).unwrap_or(u64::MAX);
                (t, total - t)
            }
        }
    }

    /// 策略承诺：`poseidon(DOMAIN, mode, rate, cap, treasury_bps, t_x*, t_y*,
    /// o_x*, o_y*)`（公钥 32B 走 hi/lo 无损拆分）。
    ///
    /// `FixedRakeBurn` 复用同一 preimage 形状，仅 mode 判别值不同（2 vs 1）：
    /// mode 进承诺 ⇒ 同参数的 burn 与 percentage 策略 commitment 必然不同，
    /// 结算关系按 policy_commitment 抽取时二者不可混淆。
    #[must_use]
    pub fn commitment(&self) -> FieldElement {
        let mut parts = vec![domain_felt(DOMAIN_FEE_POLICY), felt_from_u64(u64::from(self.mode()))];
        if let Self::FixedRake { rate_bps, cap, split }
        | Self::FixedRakeBurn { rate_bps, cap, split } = self
        {
            parts.push(felt_from_u64(u64::from(*rate_bps)));
            parts.push(felt_from_u64(*cap));
            parts.push(felt_from_u64(u64::from(split.treasury_bps)));
            for pk in [&split.treasury, &split.operator] {
                let (x, y) = crate::keys::public_xy_bytes_from_compressed(pk);
                let (x_hi, x_lo) = bytes32_to_felts(&x);
                let (y_hi, y_lo) = bytes32_to_felts(&y);
                parts.push(x_hi);
                parts.push(x_lo);
                parts.push(y_hi);
                parts.push(y_lo);
            }
        }
        poseidon_hash_many(&parts)
    }

    /// 承诺的 32 字节编码（结算记录携带）。
    #[must_use]
    pub fn commitment_bytes(&self) -> [u8; 32] {
        felt_to_bytes32(&self.commitment())
    }

    /// 构造校验。
    ///
    /// # Errors
    /// rate_bps > 10000 或 treasury_bps > 10000 → [`AppchainError::OutOfRange`]。
    pub fn validate(&self) -> AppchainResult<()> {
        if let Self::FixedRake { rate_bps, split, .. }
        | Self::FixedRakeBurn { rate_bps, split, .. } = self
        {
            if u32::from(*rate_bps) > 10_000 {
                return Err(AppchainError::OutOfRange("rate_bps"));
            }
            if u32::from(split.treasury_bps) > 10_000 {
                return Err(AppchainError::OutOfRange("treasury_bps"));
            }
        }
        Ok(())
    }
}

/// 策略注册表：table_id → 冻结策略。
///
/// **无更新路径**：开桌即冻结（M5-ACC-4）。BTreeMap 保证重放与根哈希确定性。
#[derive(Debug, Clone, Default)]
pub struct FeeRegistry {
    policies: BTreeMap<u64, FeePolicy>,
}

impl FeeRegistry {
    /// 空注册表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 开桌绑定策略（幂等：同策略重复绑定允许，异策略拒绝）。
    ///
    /// # Errors
    /// 同桌异策略 → [`AppchainError::PolicyNotRegistered`]（语义上即冻结冲突）；
    /// 策略自身非法 → [`AppchainError::OutOfRange`]。
    pub fn bind(&mut self, table_id: u64, policy: FeePolicy) -> AppchainResult<()> {
        policy.validate()?;
        match self.policies.get(&table_id) {
            Some(existing) if existing == &policy => Ok(()),
            Some(_) => Err(AppchainError::PolicyNotRegistered(table_id)),
            None => {
                self.policies.insert(table_id, policy);
                Ok(())
            }
        }
    }

    /// 查询。
    #[must_use]
    pub fn get(&self, table_id: u64) -> Option<&FeePolicy> {
        self.policies.get(&table_id)
    }

    /// 查询（错误版，结算路径用）。
    ///
    /// # Errors
    /// 未注册 → [`AppchainError::PolicyNotRegistered`]。
    pub fn require(&self, table_id: u64) -> AppchainResult<&FeePolicy> {
        self.get(table_id).ok_or(AppchainError::PolicyNotRegistered(table_id))
    }

    /// 注册表根（审计/状态根输入）：BTreeMap 序确定性折叠。
    #[must_use]
    pub fn root(&self) -> FieldElement {
        let mut acc = FieldElement::ZERO;
        for (table_id, policy) in &self.policies {
            acc = poseidon_hash_many(&[acc, felt_from_u64(*table_id), policy.commitment()]);
        }
        acc
    }

    /// 已注册桌数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize as _;

    fn pk(seed: u8) -> [u8; 33] {
        crate::keys::OwnerKey::from_seed(&[seed; 32])
            .unwrap()
            .public_bytes()
    }

    #[test]
    fn zero_policy_rake_is_always_zero() {
        let p = FeePolicy::Zero;
        assert_eq!(p.rake_of(0), 0);
        assert_eq!(p.rake_of(u64::MAX), 0);
    }

    #[test]
    fn fixed_rake_floor_and_cap() {
        let p = FeePolicy::FixedRake {
            rate_bps: 250, // 2.5%
            cap: 500,
            split: FeeSplit { treasury_bps: 2_000, treasury: pk(1), operator: pk(2) },
        };
        assert_eq!(p.rake_of(10_000), 250);
        assert_eq!(p.rake_of(30_000), 500); // 750 → cap 500
        assert_eq!(p.rake_of(1), 0); // floor
    }

    #[test]
    fn split_sums_to_total() {
        let p = FeePolicy::FixedRake {
            rate_bps: 500,
            cap: 0,
            split: FeeSplit { treasury_bps: 3_333, treasury: pk(1), operator: pk(2) },
        };
        for total in [1u64, 7, 100, 999, 123_456] {
            let (t, o) = p.split_of(total);
            assert_eq!(t + o, total);
        }
    }

    #[test]
    fn registry_freezes_policy() {
        let mut r = FeeRegistry::new();
        let p1 = FeePolicy::FixedRake {
            rate_bps: 100,
            cap: 0,
            split: FeeSplit { treasury_bps: 0, treasury: pk(1), operator: pk(2) },
        };
        r.bind(1, p1).unwrap();
        r.bind(1, p1).unwrap(); // 同策略幂等
        let p2 = FeePolicy::Zero;
        assert!(r.bind(1, p2).is_err()); // 换策略拒绝
        assert_eq!(r.get(2), None);
    }

    #[test]
    fn bps_out_of_range_rejected() {
        let mut r = FeeRegistry::new();
        let bad = FeePolicy::FixedRake {
            rate_bps: 10_001,
            cap: 0,
            split: FeeSplit { treasury_bps: 0, treasury: pk(1), operator: pk(2) },
        };
        assert!(r.bind(1, bad).is_err());
    }

    // ---- TE-E0：FixedRakeBurn（判别值 2，计价同式，销毁语义在合约侧）----

    fn fixed_rake(rate_bps: u16, cap: u64, treasury_bps: u16) -> FeePolicy {
        FeePolicy::FixedRake {
            rate_bps,
            cap,
            split: FeeSplit { treasury_bps, treasury: pk(1), operator: pk(2) },
        }
    }

    fn fixed_rake_burn(rate_bps: u16, cap: u64, treasury_bps: u16) -> FeePolicy {
        FeePolicy::FixedRakeBurn {
            rate_bps,
            cap,
            split: FeeSplit { treasury_bps, treasury: pk(1), operator: pk(2) },
        }
    }

    /// borsh 判别值 = 声明序：Zero=0、FixedRake=1、FixedRakeBurn=2。
    /// 判别值冻结，不得重排（既有 0/1 序列化数据兼容性依赖此序）。
    #[test]
    fn borsh_discriminants_are_frozen() {
        let tag = |policy: &FeePolicy| borsh::to_vec(policy).unwrap()[0];
        assert_eq!(tag(&FeePolicy::Zero), 0);
        assert_eq!(tag(&fixed_rake(500, 0, 0)), 1);
        assert_eq!(tag(&fixed_rake_burn(500, 0, 0)), 2);
    }

    /// 计费数学与 FixedRake 完全同式（burn 只是合约侧资金处置语义）。
    #[test]
    fn fixed_rake_burn_pricing_matches_fixed_rake() {
        let burn = fixed_rake_burn(250, 500, 2_000);
        for base in [0u64, 1, 10_000, 30_000, u64::MAX] {
            assert_eq!(burn.rake_of(base), fixed_rake(250, 500, 2_000).rake_of(base));
        }
        assert_eq!(burn.rake_of(10_000), 250); // 2.5% floor
        assert_eq!(burn.rake_of(30_000), 500); // 750 → cap 500
        assert_eq!(burn.rake_of(1), 0); // floor
        for total in [1u64, 7, 100, 999, 123_456] {
            let (t, o) = burn.split_of(total);
            assert_eq!(t + o, total, "零头归 operator，两份之和守恒");
        }
        assert!(burn.validate().is_ok());
        // 越界拒绝与 FixedRake 同口径（fail-closed）。
        let mut bad = fixed_rake_burn(10_001, 0, 0);
        assert!(bad.validate().is_err());
        bad = fixed_rake_burn(100, 0, 10_001);
        assert!(bad.validate().is_err());
    }

    /// mode=2 进 commitment：同参数 burn 与 percentage 承诺必然不同；
    /// 注册表绑定/冲突拒绝语义不变。
    #[test]
    fn fixed_rake_burn_mode_and_commitment_distinct() {
        let burn = fixed_rake_burn(500, 1_000, 3_333);
        let percentage = fixed_rake(500, 1_000, 3_333);
        assert_eq!(burn.mode(), 2);
        assert_eq!(percentage.mode(), 1);
        assert_ne!(burn.commitment(), percentage.commitment());
        assert_ne!(burn.commitment_bytes(), percentage.commitment_bytes());
        assert_eq!(burn.commitment(), burn.commitment()); // 确定性

        // borsh roundtrip：判别值与字段无损。
        let decoded =
            FeePolicy::try_from_slice(&borsh::to_vec(&burn).unwrap()).expect("borsh roundtrip");
        assert_eq!(decoded, burn);
        assert_eq!(decoded.mode(), 2);
        assert_eq!(decoded.commitment_bytes(), burn.commitment_bytes());

        // 注册表：burn 策略可绑定、幂等；与同参数 percentage 互为异策略。
        let mut r = FeeRegistry::new();
        r.bind(7, burn).unwrap();
        r.bind(7, burn).unwrap();
        assert!(r.bind(7, percentage).is_err());
    }
}
