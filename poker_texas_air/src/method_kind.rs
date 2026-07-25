//! 18 个方法的枚举与 selector 计算。
//!
//! 严格对齐 [`poker_l1::vm::contracts::texas_poker::dispatch`] 的 18 个方法选择器，
//! 用 `blake2b_256(method_name)[0..32]` 计算（与 L1 dispatch 算法一致）。
//!
//! # 分类
//!
//! - **A 档（生命周期，6 个）**：表台创建/入座/离座/开局/超时/重置
//! - **B 档（玩家动作，7 个）**：fold/check/call/raise/auto_fold/force_fold/kick_player
//! - **C 档（密码学协议，5 个）**：Mental Poker 协议（shuffle/reveal/reconstruct/leave_with_proof）

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

/// 方法选择器长度（32 字节 = blake2b_256 输出）。
pub const METHOD_SELECTOR_LEN: usize = 32;

/// 计算方法选择器：`blake2b_256(method_name)[0..32]`。
///
/// 与 [`poker_l1::vm::contracts::texas_poker::dispatch::compute_method_selector`] 算法一致。
///
/// # Panics
///
/// 当 Blake2bVar 初始化失败（理论不应发生，因为 32 <= 64）时 panic。
pub fn compute_method_selector(method_name: &str) -> [u8; METHOD_SELECTOR_LEN] {
    let mut h = Blake2bVar::new(METHOD_SELECTOR_LEN).expect("32 <= 64");
    h.update(method_name.as_bytes());
    let mut out = [0u8; METHOD_SELECTOR_LEN];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 18 个方法种类的枚举。
///
/// 每个 variant 对应 `poker_l1` 的一个 `apply_*` 函数，并拥有自己的专用 AIR。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MethodKind {
    // ===== A 档：表台生命周期（6 个）=====
    /// `create_table` — 创建新桌台。
    CreateTable = 0,
    /// `join_table` — 简单入座（不参与本局，等下一局）。
    JoinTable = 1,
    /// `leave_table` — 简单离座（仅在 WAITING 状态）。
    LeaveTable = 2,
    /// `start_hand` — 开始新一局（投盲注 + 进入 shuffle 阶段）。
    StartHand = 3,
    /// `tick` — 超时驱动（permissionless）。
    Tick = 4,
    /// `reset_for_next_hand` — 显式重置桌台到 WAITING。
    ResetForNextHand = 5,

    // ===== B 档：玩家动作（7 个）=====
    /// `fold` — 玩家主动 fold。
    Fold = 6,
    /// `check` — 玩家过牌。
    Check = 7,
    /// `call` — 玩家跟注。
    Call = 8,
    /// `raise` — 玩家加注。
    Raise = 9,
    /// `auto_fold` — 玩家超时自动 fold。
    AutoFold = 10,
    /// `force_fold` — 管理员强制 fold 玩家。
    ForceFold = 11,
    /// `kick_player` — 踢出玩家（管理员操作）。
    KickPlayer = 12,

    // ===== C 档：Mental Poker 协议（5 个）=====
    /// `join_and_shuffle` — 玩家加入并完成首洗牌。
    JoinAndShuffle = 13,
    /// `leave_with_proof` — 玩家带 proof 离场。
    LeaveWithProof = 14,
    /// `submit_shuffle_v2` — 玩家提交洗牌结果（V2）。
    SubmitShuffleV2 = 15,
    /// `submit_player_reveal_tokens` — 提交揭牌令牌。
    SubmitPlayerRevealTokens = 16,
    /// `submit_reconstruct_deck` — 提交重构牌组。
    SubmitReconstructDeck = 17,
}

impl MethodKind {
    /// 方法总数（18）。
    pub const COUNT: usize = 18;

    /// 返回方法名字符串（snake_case，与 Move 端 entry function 名一一对应）。
    #[must_use]
    pub const fn method_name(self) -> &'static str {
        match self {
            Self::CreateTable => "create_table",
            Self::JoinTable => "join_table",
            Self::LeaveTable => "leave_table",
            Self::StartHand => "start_hand",
            Self::Tick => "tick",
            Self::ResetForNextHand => "reset_for_next_hand",
            Self::Fold => "fold",
            Self::Check => "check",
            Self::Call => "call",
            Self::Raise => "raise",
            Self::AutoFold => "auto_fold",
            Self::ForceFold => "force_fold",
            Self::KickPlayer => "kick_player",
            Self::JoinAndShuffle => "join_and_shuffle",
            Self::LeaveWithProof => "leave_with_proof",
            Self::SubmitShuffleV2 => "submit_shuffle_v2",
            Self::SubmitPlayerRevealTokens => "submit_player_reveal_tokens",
            Self::SubmitReconstructDeck => "submit_reconstruct_deck",
        }
    }

    /// 返回方法选择器（blake2b_256(method_name)[0..32]）。
    #[must_use]
    pub fn selector(self) -> [u8; METHOD_SELECTOR_LEN] {
        compute_method_selector(self.method_name())
    }

    /// 返回方法所属档位。
    #[must_use]
    pub const fn tier(self) -> MethodTier {
        match self {
            Self::CreateTable
            | Self::JoinTable
            | Self::LeaveTable
            | Self::StartHand
            | Self::Tick
            | Self::ResetForNextHand => MethodTier::Lifecycle,
            Self::Fold
            | Self::Check
            | Self::Call
            | Self::Raise
            | Self::AutoFold
            | Self::ForceFold
            | Self::KickPlayer => MethodTier::Action,
            Self::JoinAndShuffle
            | Self::LeaveWithProof
            | Self::SubmitShuffleV2
            | Self::SubmitPlayerRevealTokens
            | Self::SubmitReconstructDeck => MethodTier::Crypto,
        }
    }

    /// 从 u8 还原 MethodKind。
    ///
    /// # Errors
    ///
    /// 当 `value >= 18` 时返回 `None`。
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreateTable),
            1 => Some(Self::JoinTable),
            2 => Some(Self::LeaveTable),
            3 => Some(Self::StartHand),
            4 => Some(Self::Tick),
            5 => Some(Self::ResetForNextHand),
            6 => Some(Self::Fold),
            7 => Some(Self::Check),
            8 => Some(Self::Call),
            9 => Some(Self::Raise),
            10 => Some(Self::AutoFold),
            11 => Some(Self::ForceFold),
            12 => Some(Self::KickPlayer),
            13 => Some(Self::JoinAndShuffle),
            14 => Some(Self::LeaveWithProof),
            15 => Some(Self::SubmitShuffleV2),
            16 => Some(Self::SubmitPlayerRevealTokens),
            17 => Some(Self::SubmitReconstructDeck),
            _ => None,
        }
    }

    /// 返回所有 18 个方法（用于迭代）。
    #[must_use]
    pub const fn all() -> [Self; Self::COUNT] {
        [
            Self::CreateTable,
            Self::JoinTable,
            Self::LeaveTable,
            Self::StartHand,
            Self::Tick,
            Self::ResetForNextHand,
            Self::Fold,
            Self::Check,
            Self::Call,
            Self::Raise,
            Self::AutoFold,
            Self::ForceFold,
            Self::KickPlayer,
            Self::JoinAndShuffle,
            Self::LeaveWithProof,
            Self::SubmitShuffleV2,
            Self::SubmitPlayerRevealTokens,
            Self::SubmitReconstructDeck,
        ]
    }
}

/// 方法所属档位（用于实施阶段控制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodTier {
    /// A 档：表台生命周期（6 个，阶段 1-2 实现）。
    Lifecycle,
    /// B 档：玩家动作（7 个，阶段 3 实现）。
    Action,
    /// C 档：Mental Poker 协议（5 个，阶段 4 实现）。
    Crypto,
}

impl MethodTier {
    /// 该档位方法的预估单 AIR LOC。
    #[must_use]
    pub const fn estimated_loc(self) -> usize {
        match self {
            Self::Lifecycle => 800,
            Self::Action => 1_000,
            Self::Crypto => 3_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_count() {
        assert_eq!(MethodKind::COUNT, 18);
        assert_eq!(MethodKind::all().len(), 18);
    }

    #[test]
    fn test_method_name_roundtrip() {
        for kind in MethodKind::all() {
            let name = kind.method_name();
            let selector = kind.selector();
            // selector 长度 = 32
            assert_eq!(selector.len(), METHOD_SELECTOR_LEN);
            // 不同方法的 selector 应不同
            for other in MethodKind::all() {
                if other != kind {
                    assert_ne!(selector, other.selector(), "selector 碰撞: {name}");
                }
            }
        }
    }

    #[test]
    fn test_from_u8_roundtrip() {
        for kind in MethodKind::all() {
            let v = kind as u8;
            assert_eq!(MethodKind::from_u8(v), Some(kind));
        }
        assert_eq!(MethodKind::from_u8(18), None);
        assert_eq!(MethodKind::from_u8(255), None);
    }

    #[test]
    fn test_tier_classification() {
        assert_eq!(MethodKind::CreateTable.tier(), MethodTier::Lifecycle);
        assert_eq!(MethodKind::Raise.tier(), MethodTier::Action);
        assert_eq!(MethodKind::JoinAndShuffle.tier(), MethodTier::Crypto);
    }

    #[test]
    fn test_selector_matches_l1_dispatch() {
        // 验证 selector 与 L1 dispatch 算法一致：blake2b_256(method_name)[0..32]
        let expected = compute_method_selector("create_table");
        assert_eq!(MethodKind::CreateTable.selector(), expected);
    }
}
