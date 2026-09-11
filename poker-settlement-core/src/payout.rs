//! 结算输出完整绑定原语（plan-appchain §5.2-2 / §5.2-7，本 crate 新增）。
//!
//! - [`PayoutLeaf`]：单条赔付的**完整**绑定（asset_class、amount、owner、
//!   table_id、pot_index、runout_index）——修复"只签 owner 和金额"的缺口；
//! - [`payout_root`]：全部赔付聚合为单一 32B 根（blake2b + RFC 6962 域分离）；
//! - [`side_pot_root`]：pot 分层结构承诺；
//! - [`rake_for`]：与 poker_l1 舍入规则一致的 `floor(gross·num/den)` 原语。
//!
//! ## payout_root 树规则（checklist R3-M2/R4-M1 house convention）
//!
//! 1. 规范化：叶子按 borsh 编码字节序**字典排序**后建树（顺序无关输入）；
//! 2. 叶子 `H(0x00 ‖ leaf_borsh)`，内部节点 `H(0x01 ‖ l ‖ r)`
//!    （RFC 6962 域分离，防二次原像）；
//! 3. 每次 blake2b 调用整体前缀 [`PAYOUT_ROOT_DOMAIN`]；
//! 4. 空树 → `H(0x00 ‖ b"")`；单叶 → `H(0x00 ‖ leaf)`；
//!    不平衡 → 以空叶哈希补齐到 2 的幂
//!    （与 `poker_l1/src/offline/ack_chain.rs` 同一构造）。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use crate::plan::SettlementPlan;

/// payout_root 域标签。
pub const PAYOUT_ROOT_DOMAIN: &[u8] = b"zchain.settlement.payout_root.v1";
/// side_pot_root 域标签。
pub const SIDE_POT_ROOT_DOMAIN: &[u8] = b"zchain.settlement.side_pot_root.v1";

/// RFC 6962 叶子前缀。
const LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 内部节点前缀。
const INTERNAL_PREFIX: u8 = 0x01;

/// 单条赔付的完整绑定（plan-appchain §5.2-7）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, borsh::BorshSerialize,
    borsh::BorshDeserialize, Hash,
)]
pub struct PayoutLeaf {
    /// 资产类判别值（REAL=1 / PLAY=2，与 `poker_appchain::note::AssetClass` 一致）。
    pub asset_class: u8,
    /// 面额 > 0。
    pub amount: u64,
    /// 收款人压缩公钥（33B，secp256k1）。
    pub owner: [u8; 33],
    /// 桌绑定。
    pub table_id: u64,
    /// pot 分层索引（0 = 主池）。
    pub pot_index: u8,
    /// runout 索引（run-it-twice 的第几块板；单板恒 0）。
    pub runout_index: u8,
}

/// blake2b-256，输入整体前缀域标签。
fn domained_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= Blake2b maximum output");
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("32 <= Blake2b maximum output");
    out
}

/// RFC 6962 叶子哈希：`H(0x00 ‖ leaf)`（域前缀整体包裹）。
fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    domained_hash(PAYOUT_ROOT_DOMAIN, &[&[LEAF_PREFIX], leaf])
}

/// RFC 6962 内部节点哈希：`H(0x01 ‖ l ‖ r)`。
fn internal_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    domained_hash(PAYOUT_ROOT_DOMAIN, &[&[INTERNAL_PREFIX], l, r])
}

/// 空 Merkle 根 = `H(0x00 ‖ b"")`（SEC-L5 / checklist R4-M1 边界规则）。
fn empty_leaf_hash() -> [u8; 32] {
    leaf_hash(b"")
}

/// 规范化赔付集 → 32B payout root。
///
/// 输入顺序无关（叶子按 borsh 编码排序后建树）；同一赔付集**必须**得到
/// 同一根，任何字段（含 pot_index/runout_index）差异都改变根。
#[must_use]
pub fn payout_root(leaves: &[PayoutLeaf]) -> [u8; 32] {
    let mut encoded: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| borsh::to_vec(leaf).expect("PayoutLeaf borsh is infallible"))
        .collect();
    encoded.sort();
    if encoded.is_empty() {
        return empty_leaf_hash();
    }
    let mut level: Vec<[u8; 32]> = encoded.iter().map(|bytes| leaf_hash(bytes)).collect();
    // 不平衡 → 空叶哈希补齐到 2 的幂（house convention，见模块文档）。
    let mut width = level.len().next_power_of_two();
    level.resize(width, empty_leaf_hash());
    while width > 1 {
        let mut next = Vec::with_capacity(width / 2);
        for pair in level.chunks_exact(2) {
            next.push(internal_hash(&pair[0], &pair[1]));
        }
        level = next;
        width /= 2;
    }
    level[0]
}

/// pot 分层结构承诺：`H(borsh(plan.pots))`，域 [`SIDE_POT_ROOT_DOMAIN`]。
///
/// 绑定全部层（主池/边池索引、gross/rake/net、eligible 掩码、两个 runout
/// 槽位的完整投影），使赔付的 (pot_index, runout_index) 引用不可漂移。
#[must_use]
pub fn side_pot_root(plan: &SettlementPlan) -> [u8; 32] {
    let encoded = borsh::to_vec(&plan.pots).expect("SettlementPotPlan borsh is infallible");
    domained_hash(SIDE_POT_ROOT_DOMAIN, &[&encoded])
}

/// rake 计算原语：`floor(gross · rate_num / rate_den)`，u128 中间量不回绕。
///
/// 与 poker_l1 既有舍入规则一致（`contested_gross · rake_bps / 10_000`
/// 向下取整）；封顶/对 gross 的钳制由调用方施加（poker_l1 语义：
/// `min(raw, cap, gross)`，poker_texas_air `canonical_settlement_rake` 同式）。
///
/// `rate_den == 0` 视为零费（无除零 panic 路径）；结果饱和到 `u64::MAX`。
#[must_use]
pub fn rake_for(gross: u64, rate_num: u64, rate_den: u64) -> u64 {
    if rate_den == 0 {
        return 0;
    }
    let raw = u128::from(gross) * u128::from(rate_num) / u128::from(rate_den);
    u64::try_from(raw).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hand_rank::HandRank;
    use crate::plan::{
        RunoutPotPlan, SettlementPlan, SettlementPotPlan, SettlementRunoutSchedule,
        SETTLEMENT_SEATS, SETTLEMENT_PLAN_VERSION,
    };

    fn leaf(seed: u8, amount: u64, pot_index: u8, runout_index: u8) -> PayoutLeaf {
        PayoutLeaf {
            asset_class: 1,
            amount,
            owner: [seed; 33],
            table_id: 7,
            pot_index,
            runout_index,
        }
    }

    #[test]
    fn payout_root_golden_vector() {
        // 冻结 golden 常量：防域标签/树规则/编码被无声更改。
        let leaves = [leaf(1, 500, 0, 0), leaf(2, 2_350, 0, 0)];
        assert_eq!(
            hex_of(payout_root(&leaves)),
            "68183b9f2cc69692e5dfaf5325cf67ec6c511db0cc5f651a98d4cade80506fb6"
        );
        let empty = payout_root(&[]);
        assert_eq!(hex_of(empty), hex_of(leaf_hash(b"")));
    }

    fn hex_of(bytes: [u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn payout_root_is_order_independent_and_field_sensitive() {
        let a = leaf(1, 500, 0, 0);
        let b = leaf(2, 2_350, 0, 0);
        assert_eq!(payout_root(&[a, b]), payout_root(&[b, a]), "canonical sort");
        // 每个绑定字段都改变根（防"只签 owner+amount"回归）
        assert_ne!(payout_root(&[a]), payout_root(&[leaf(1, 501, 0, 0)]));
        assert_ne!(payout_root(&[a]), payout_root(&[PayoutLeaf { asset_class: 2, ..a }]));
        assert_ne!(payout_root(&[a]), payout_root(&[PayoutLeaf { table_id: 8, ..a }]));
        assert_ne!(payout_root(&[a]), payout_root(&[PayoutLeaf { pot_index: 1, ..a }]));
        assert_ne!(payout_root(&[a]), payout_root(&[PayoutLeaf { runout_index: 1, ..a }]));
    }

    #[test]
    fn payout_root_empty_and_single_leaf_boundaries() {
        let single = leaf(3, 100, 0, 0);
        // 单叶 → H(0x00 ‖ leaf)（不再折叠）
        assert_eq!(payout_root(&[single]), leaf_hash(&borsh::to_vec(&single).unwrap()));
        // 空树 → H(0x00 ‖ b"")（与 ack_chain 空根惯例一致）
        assert_eq!(payout_root(&[]), empty_leaf_hash());
        // 空树根 ≠ 任意单叶根
        assert_ne!(payout_root(&[]), payout_root(&[single]));
    }

    #[test]
    fn payout_root_handles_unbalanced_tree_with_empty_padding() {
        let leaves: Vec<PayoutLeaf> = (1..=3u8).map(|s| leaf(s, u64::from(s), 0, 0)).collect();
        let three = payout_root(&leaves);
        // 手工展开：3 叶补一个空叶 → 2 层折叠
        let mut padded: Vec<[u8; 32]> = leaves
            .iter()
            .map(|l| leaf_hash(&borsh::to_vec(l).unwrap()))
            .collect();
        let e = empty_leaf_hash();
        padded.push(e);
        let l0 = internal_hash(&padded[0], &padded[1]);
        let l1 = internal_hash(&padded[2], &padded[3]);
        assert_eq!(three, internal_hash(&l0, &l1));
    }

    #[test]
    fn payout_root_domain_separation_blocks_second_preimage() {
        // 叶子与内部节点域分离：内部节点值 ≠ 任何叶子哈希（防二次原像）
        let a = leaf(1, 100, 0, 0);
        let b = leaf(2, 100, 0, 0);
        let la = leaf_hash(&borsh::to_vec(&a).unwrap());
        let lb = leaf_hash(&borsh::to_vec(&b).unwrap());
        let internal = internal_hash(&la, &lb);
        // 混淆攻击：把内部节点字节当叶子提交，得到的叶子哈希不同
        assert_ne!(leaf_hash(&internal.to_vec()), internal);
        // 双叶根 ≠ 任一单叶根
        assert_ne!(payout_root(&[a, b]), la);
        // 双叶根 ≠ 三叶根（形状敏感）
        let leaves3: Vec<PayoutLeaf> = (1..=3u8).map(|s| leaf(s, u64::from(s), 0, 0)).collect();
        assert_ne!(payout_root(&leaves3[..2]), payout_root(&leaves3));
    }

    fn sample_plan() -> SettlementPlan {
        let mut awards = [0u64; SETTLEMENT_SEATS];
        awards[0] = 150;
        awards[1] = 100;
        let mut runout0 = RunoutPotPlan::inactive();
        runout0.amount = 250;
        runout0.winner_mask = 0b11;
        runout0.ranks[0] = Some(HandRank::new(1, &[13, 5, 4, 3, 2]));
        runout0.ranks[1] = Some(HandRank::new(1, &[13, 5, 4, 3, 2]));
        runout0.awards = awards;
        SettlementPlan {
            version: SETTLEMENT_PLAN_VERSION,
            schedule: SettlementRunoutSchedule::Single,
            gross_pot: 250,
            rake: 0,
            total_awards: 250,
            winner_mask: 0b11,
            awards,
            pots: vec![SettlementPotPlan {
                pot_index: 0,
                gross_amount: 250,
                rake: 0,
                net_amount: 250,
                eligible_mask: 0b11,
                runouts: [runout0, RunoutPotPlan::inactive()],
            }],
        }
    }

    #[test]
    fn side_pot_root_binds_layer_structure() {
        let plan = sample_plan();
        let root = side_pot_root(&plan);
        assert_eq!(root, side_pot_root(&plan.clone()));
        // 分层结构任何变化（净额、eligible、runout 投影）都改变根
        let mut tampered = plan.clone();
        tampered.pots[0].net_amount = 249;
        assert_ne!(root, side_pot_root(&tampered));
        let mut tampered2 = plan.clone();
        tampered2.pots[0].eligible_mask = 0b01;
        assert_ne!(root, side_pot_root(&tampered2));
        let mut extra = plan.clone();
        extra.pots.push(extra.pots[0].clone());
        assert_ne!(root, side_pot_root(&extra));
    }

    #[test]
    fn rake_for_matches_floor_division_and_edge_rules() {
        assert_eq!(rake_for(1_500, 500, 10_000), 75);
        assert_eq!(rake_for(9, 500, 10_000), 0, "floor rounding");
        assert_eq!(rake_for(100_000, 500, 10_000), 5_000);
        assert_eq!(rake_for(3, 10_000, 10_000), 3);
        assert_eq!(rake_for(1_000, 1, 0), 0, "zero denominator is zero-fee, no panic");
        assert_eq!(rake_for(0, 500, 10_000), 0);
    }
}
