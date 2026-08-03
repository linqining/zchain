//! Texas Poker 原生 Precompile 合约（移植自 `/Users/mac/projects/zgame/texas_poker_move`）。
//!
//! 本模块将 Sui Move 德州扑克合约（~8000 行，含完整 Mental Poker 协议）
//! 移植为 zchain 原生预编译合约。合约字节码内嵌于 zchain 节点二进制，
//! 通过 `PrecompileRegistry` 注册，ObjectID = `reserved::texas_poker_contract_id()`
//! （`0xFF..02`）。
//!
//! # 模块结构
//!
//! - `constants`：状态常量（ROUND_*/SHUFFLE_PHASE_*/REVEAL_PHASE_*/...）
//! - `card`：扑克牌数据结构（Card/PlayingCard + 花色映射）
//! - `hand_evaluator`：7选5最佳手牌评估（10 种牌型）
//! - `betting`：下注规则（BettingRound + all-in 处理）
//! - `side_pot`：边池分层算法（统一 pots 结构 + 位掩码 eligible）
//! - `events`：40 种事件类型枚举
//! - `types`：核心数据结构（TexasPokerTable/Seat/DeckState/ShuffleState/...）
//! - `state_machine`：状态机推进 + tick + reveal/reconstruct 编排
//! - `dispatch`：23 个 method selector 路由
//! - `utils`：Mental Poker 密码学适配层（包 `poker_protocol` crate，提供 G1/Scalar 自由函数 + verify_or_skip）
//!
//! # Mental Poker 协议
//!
//! 1. 玩家轮流 shuffle 加密牌组并提交 shuffle proof
//! 2. 每个玩家为非自己手牌提交 reveal token（部分解密）
//! 3. 牌主用自己 sk 完成解密（showdown 阶段）
//! 4. 公共牌由所有玩家 reveal token 聚合解密
//!
//! 链上仅做 verify，链下做 prove（`#[cfg(feature = "client")]` 门控）。
//!
//! # ZK 跳过回退（仅 crate 内单元测试）
//!
//! 为了兼容已有状态，`TableConfig` 仍保留 `zk_skip_*` 字段；但它们只在
//! `poker_l1` crate 自身的 `cfg(test)` 单元测试构建中生效。生产、普通库和
//! 集成测试构建始终执行真实密码学验证，不依赖尚未实现的 governance 强制。

pub mod betting;
pub mod card;
pub mod constants;
pub mod events;
pub mod hand_evaluator;
pub mod side_pot;
pub mod types;
pub mod utils;

/// Canonical Object type tag for persisted Texas Poker table state.
///
/// Keep this separate from the reserved precompile contract ID: reconciliation, snapshots and
/// proof anchors identify table escrow by this stable type tag, while the current MVP happens to
/// store its single table at the precompile ID.
pub const TEXAS_POKER_TABLE_OBJECT_TYPE: &str = "TexasPokerTable";

// Phase 3: 状态机 + dispatch
pub mod dispatch;
pub mod state_machine;

// Post-commit Prover：证明任务（return_value 的 prove_task 部分）。
// 与 poker_texas_air::prove_task 保持 borsh 二进制兼容（MethodInput 共享自 vm-common）。
pub mod prove_task;

// Phase 3.3: TexasPokerPrecompile impl（待 state_machine/dispatch 完成后补）
// pub struct TexasPokerPrecompile { ... }
// impl
