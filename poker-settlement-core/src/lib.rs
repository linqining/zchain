//! # poker-settlement-core — 结算语义唯一事实源（plan-appchain §5.2-1，P0-1）
//!
//! 本 crate 是德州扑克结算语义的**唯一**定义点：VM（`poker_l1`）、appchain
//! （`poker-appchain`）、verifier 共用同一套 [`SettlementPlan`]、side-pot、
//! run-it-twice、odd-chip、rake 分配与摘要算法。任何一方不得本地重新实现
//! 这些语义——重复建模即分叉（plan-appchain §5.2 第 1 项主网阻断项）。
//!
//! ## 从 poker_l1 搬运的语义（行为逐字节等价）
//!
//! 搬运自 `poker_l1/src/vm/contracts/texas_poker/settlement.rs` 与
//! `side_pot.rs`（poker_l1 侧现为再导出 + VM 集成胶水；poker_l1 既有结算
//! 测试是等价性裁判，golden digest 跨 crate 一致性测试钉住字节兼容）：
//!
//! - [`SettlementPlan`] / [`SettlementPotPlan`] / [`RunoutPotPlan`] /
//!   [`SettlementRunoutSchedule`] / [`RitStartStreet`]（borsh 编码与
//!   poker_l1 v2 规范编码逐字节一致）；
//! - [`SETTLEMENT_PLAN_VERSION`] / [`SETTLEMENT_SEATS`] / [`MAX_RUNOUTS`] /
//!   [`MAX_PLAYERS`] / [`MAX_TOTAL_BET`] 常量；
//! - [`SettlementPlan::validate`]（守恒/形状校验）与
//!   [`SettlementPlan::digest`]（**保持 blake2b 域
//!   `zchain.texas_poker.settlement_plan.v2` 不变**——跨组件唯一事实源，
//!   字节兼容必须保留）；
//! - [`derive_settlement_plan`]（牌用 u8 规范索引 `0..=51` 表示：
//!   `suit = idx / 13`，`rank = idx % 13 + 2`）与
//!   [`calculate_side_pots`] / odd-chip / run-it-twice 派生逻辑；
//! - [`HandRank`] 与 [`evaluate_best`]（7 选 5 评估，borsh/序与 poker_l1
//!   `hand_evaluator` 一致）。
//!
//! ## 本 crate 新增的绑定原语（plan-appchain §5.2-2/§5.2-7）
//!
//! - [`PayoutLeaf`] + [`payout_root`]：结算输出**完整绑定**（asset_class、
//!   amount、owner、table_id、pot_index、runout_index），聚合为单一
//!   32B 根——玩家花费签名从而覆盖精确赔付结构，不再"只签 owner 和金额"；
//! - [`side_pot_root`]：pot 分层结构（主池/边池、eligible、runout 投影）承诺；
//! - [`rake_for`]：与 poker_l1 既有舍入规则一致（`floor(gross·num/den)`，
//!   u128 中间量，不回绕）的 rake 计算原语。
//!
//! ## 哈希选型记录
//!
//! | 用途 | 哈希 | 域标签 |
//! |---|---|---|
//! | plan 摘要（跨组件事实源） | blake2b-256 | `zchain.texas_poker.settlement_plan.v2`（历史冻结，不变） |
//! | payout_root（输出绑定） | blake2b-256 + RFC 6962 域分离 | `zchain.settlement.payout_root.v1` |
//! | side_pot_root（分层承诺） | blake2b-256 | `zchain.settlement.side_pot_root.v1` |
//! | deck_chain_digest（deck 承诺链，hand_binding v2 输入） | Poseidon252（上游同源，2026-09-12 裁决） | `zchain.texas.canonical-shuffle-chain.v1`（与上游 stage0 逐字节一致） |
//! | AIR 绑定层（appchain 承诺树/批次根/结算绑定） | Poseidon252 | 见 `poker-appchain/src/felt.rs` |
//!
//! blake2b 用于**字节对象**（borsh 计划、赔付叶），与 VM/归档栈一致；
//! Poseidon 用于 zk 域内对象（felt 树）与**必须与生产者重导一致**的链
//! 摘要（deck 链裁决：消费侧算法冻结为上游 `fold_chain` 逐字节复制，
//! 早期 blake2b 提案已删除——理由与两侧对照证据见 SHUFFLE_CONSUME.md
//! §1.2/§5 与 `deck_chain` 模块文档）。两层不混用。
//!
//! ## payout_root 的树规则（与 checklist R3-M2/R4-M1 house convention 一致）
//!
//! - 规范化：叶子按 borsh 编码字节序字典排序后建树（调用方顺序无关）；
//! - 叶子 `H(0x00 ‖ leaf_borsh)`，内部节点 `H(0x01 ‖ l ‖ r)`（防二次原像）；
//! - 每次哈希调用整体前缀域标签 `zchain.settlement.payout_root.v1`；
//! - 空树 → `H(0x00 ‖ b"")`；单叶 → `H(0x00 ‖ leaf)`；
//!   不平衡 → 以空叶哈希补齐到 2 的幂（`poker_l1/src/offline/ack_chain.rs`
//!   同一 house convention）。
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod deck_chain;
mod derive;
mod error;
mod hand_rank;
mod plan;
mod payout;
mod side_pot;

pub use derive::{
    derive_settlement_plan, split_among_winners, split_across_runouts, SettlementBoards,
    TableSnapshot,
};
pub use error::SettlementError;
pub use hand_rank::{evaluate_best, HandRank};
pub use plan::{
    RitStartStreet, RunoutPotPlan, SettlementPlan, SettlementPotPlan, SettlementRunoutSchedule,
    MAX_PLAYERS, MAX_RUNOUTS, MAX_TOTAL_BET, SETTLEMENT_PLAN_VERSION, SETTLEMENT_SEATS,
};
pub use deck_chain::{
    deck_chain_digest, DECK_CHAIN_DIGEST_DOMAIN, DECK_CHAIN_FOLD_LABEL, DECK_CHAIN_MAX,
};
pub use payout::{rake_for, side_pot_root, payout_root, PayoutLeaf, PAYOUT_ROOT_DOMAIN,
    SIDE_POT_ROOT_DOMAIN};
pub use side_pot::{calculate_side_pots, is_eligible, seat_bit, SidePot, SidePotError,
    SidePotResult};

// rake 模式判别值（与 poker_l1 constants 及 canonical_rake_opening 对齐）。
// 判别值一经发布即冻结（TE-E0）：0/1/2 三值三仓（settlement-core 常量 /
// appchain borsh 判别值 / 上游 canonical rake_mode）一致，不得重排或复用。
/// 零费 rake 模式（`RAKE_MODE_NONE`）。
pub const RAKE_MODE_NONE: u8 = 0;
/// 固定比例 rake 模式（`RAKE_MODE_PERCENTAGE`）。
pub const RAKE_MODE_PERCENTAGE: u8 = 1;
/// 固定比例计费 + GAME 桌销毁处置模式（`RAKE_MODE_FIXED_RAKE_BURN`，
/// TE-E0 枚举先行，判别值冻结 = 2）。
///
/// **语义边界（TE-M4 定稿）**：本 crate 承载三模式的**计价数量关系**——
/// mode 2 与 mode 1 同式（canonical AIR opening
/// `canonical_settlement_rake` 对 mode ∈ {1, 2} 同式，数量关系已证并
/// 冻结）。**资金处置**（rake 份额入 treasury/operator 还是销毁）不在
/// [`SettlementPlan`] 内建模：plan 只编码数量切分
/// （gross = awards + rake），处置规则落在 poker_l1 合约侧
/// （`texas_poker::settlement::rake_disposal`）与 poker-appchain
/// admission/结算层（v2 结算 burn 处置）。同一手在 mode 1 与 mode 2 下
/// 的 plan 及 digest 逐字节相等（两侧对照测试钉住）。
pub const RAKE_MODE_FIXED_RAKE_BURN: u8 = 2;
