//! M5：费率模块。
//!
//! 核心原则（plan §0）：**费率是状态机里的数据（策略注册表），不是协议参数**。
//! v1 仅两种策略：`ZERO`（零费休闲桌）与 `FIXED_RAKE`（固定比例 + 封顶 +
//! 分账）。策略在开桌时绑定并**冻结**（注册表无更新路径），结算关系
//! （M2）按 policy_commitment 验证抽取，篡改即不可证明。
//!
//! 对齐既有资产：`canonical_rake_opening` 的 `rake_mode`（NONE=0 /
//! PERCENTAGE=1）与本模块语义一致，ABI 层保持相同判别值。

use std::collections::BTreeMap;

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::error::{AppchainError, AppchainResult};
use crate::felt::{bytes32_to_felts, domain_felt, felt_from_u64, felt_to_bytes32, DOMAIN_FEE_POLICY};

/// rake 模式判别值，对齐 `canonical_rake_opening`（NONE=0, PERCENTAGE=1）。
pub mod rake_mode {
    /// 零费。
    pub const NONE: u8 = 0;
    /// 固定比例。
    pub const PERCENTAGE: u8 = 1;
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
}

impl FeePolicy {
    /// rake 模式判别值。
    #[must_use]
    pub const fn mode(&self) -> u8 {
        match self {
            Self::Zero => rake_mode::NONE,
            Self::FixedRake { .. } => rake_mode::PERCENTAGE,
        }
    }

    /// 计算抽取额：`min(pot * rate_bps / 10000, cap)`，向下取整。
    ///
    /// 零费策略恒 0；Zero 桌上 pot 任意大抽取仍为 0（M5-ACC-1）。
    #[must_use]
    pub fn rake_of(&self, pot: u64) -> u64 {
        match self {
            Self::Zero => 0,
            Self::FixedRake { rate_bps, cap, .. } => {
                let raw = (u128::from(pot) * u128::from(*rate_bps)) / 10_000;
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
            Self::FixedRake { split, .. } => {
                let t = (u128::from(total) * u128::from(split.treasury_bps)) / 10_000;
                let t = u64::try_from(t).unwrap_or(u64::MAX);
                (t, total - t)
            }
        }
    }

    /// 策略承诺：`poseidon(DOMAIN, mode, rate, cap, treasury_bps, t_x*, t_y*,
    /// o_x*, o_y*)`（公钥 32B 走 hi/lo 无损拆分）。
    #[must_use]
    pub fn commitment(&self) -> FieldElement {
        let mut parts = vec![domain_felt(DOMAIN_FEE_POLICY), felt_from_u64(u64::from(self.mode()))];
        if let Self::FixedRake { rate_bps, cap, split } = self {
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
        if let Self::FixedRake { rate_bps, split, .. } = self {
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
}
