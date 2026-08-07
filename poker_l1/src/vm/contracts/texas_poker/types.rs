//! Texas Poker 核心数据结构（移植自 `texas_poker_move/sources/table.move` 的 struct 定义）。
//!
//! 包含桌台、座位、洗牌状态、揭示状态、重构状态、超时配置、时间戳、
//! 牌组状态等所有状态机所需数据结构。
//!
//! 所有结构 `#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]`，
//! borsh 兼容，便于 `TexasPokerPrecompile::call` 通过 borsh 序列化/反序列化存入 ObjectDb。
//!
//! # typed 化说明
//!
//! 密码学相关字段（pk、token、coefficient、ciphertext_bytes、plaintext_bytes、aggregated_pk、
//! plaintext）已从 `Vec<u8>` 改为 typed `poker_protocol` 类型（`ECPoint` / `ECScalar` /
//! `ElGamalCiphertext`），消除 state_machine.rs 中的 bytes↔G1 转换样板代码。
//! `ElGamalCiphertext` 直接复用 `poker_protocol::crypto::types::ElGamalCiphertext`
//! （= `ElGamalCiphertextGeneric<Bls12381Curve>`，字段 `c1/c2: G1Projective`）。
//!
//! # Borsh orphan rule 处理
//!
//! `G1Projective` / `BlsScalar` 是外部 blstrs 类型，无法在 poker_l1 直接 impl
//! `BorshSerialize`/`BorshDeserialize`（orphan rule）。所有 struct 字段使用本地 newtype
//! `ECPoint(pub G1Projective)` / `ECScalar(pub BlsScalar)` 包装，borsh impl 在
//! `poker_protocol::borsh_impls` 中实现（48B G1 compressed / 32B scalar big-endian）。

use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use group::Group;

use blstrs::G1Projective;
use poker_protocol::crypto::types::{ECPoint, ECScalar};
// 注：`ElGamalCiphertext` 通过下方 `pub use` 重导出，避免重复导入。

use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;

use super::betting::BettingRound;
use super::card::{BoardCards, Card, HoleCards};
// 复用 constants.rs 中与 Move 端逐字节一致的 phase 常量（避免本地重复定义导致语义分叉）
use super::constants::{
    RECONSTRUCT_PHASE_NONE, REVEAL_PHASE_NONE, ROUND_FLOP, ROUND_PREFLOP, ROUND_RIVER,
    ROUND_SHOWDOWN, ROUND_TURN, ROUND_WAITING, SHUFFLE_PHASE_NONE, SHUFFLE_PHASE_RECONSTRUCT,
};

// ========== 常量 ==========

/// 公共牌 owner_seat_index 特殊值（u8 域：表示该牌不属于任何玩家）。
///
/// 注意：constants.rs 中的 `COMMUNITY_CARD_OWNER` 是 u64（与 Move 一致），
/// 但 `DecryptedCard.owner_seat_index` 在 Rust 端使用 u8（座位数最多 9），
/// 因此这里用 `u8::MAX` 作为等价哨兵。
pub const OWNER_SEAT_PUBLIC: u8 = u8::MAX;

/// 空座位标识（player = [0; 20]）。
pub const EMPTY_PLAYER: Address = [0u8; 20];

/// Maximum supported seat count. Seat membership is encoded in a [`SeatMask`].
pub const MAX_SEATS: u8 = 9;

/// Canonical sentinel for a missing seat index in persisted state and AIR projections.
pub const NO_SEAT: u8 = u8::MAX;

/// Bit `i` denotes seat `i`. Only the low `max_players` bits may be set.
pub type SeatMask = u16;

#[must_use]
/// Return the mask containing only `seat_index`.
pub const fn seat_mask_bit(seat_index: u8) -> SeatMask {
    1u16 << seat_index
}

#[must_use]
/// Return whether `seat_index` is present in a canonical seat mask.
pub const fn seat_mask_contains(mask: SeatMask, seat_index: u8) -> bool {
    seat_index < MAX_SEATS && mask & seat_mask_bit(seat_index) != 0
}

/// Insert `seat_index`, rejecting indices outside the supported table size.
pub fn seat_mask_insert(mask: &mut SeatMask, seat_index: u8) -> PokerL1Result<()> {
    if seat_index >= MAX_SEATS {
        return Err(PokerL1Error::Serialization(format!(
            "Texas seat index {seat_index} exceeds mask capacity {MAX_SEATS}"
        )));
    }
    *mask |= seat_mask_bit(seat_index);
    Ok(())
}

/// Remove `seat_index`; out-of-range indices are harmless no-ops.
pub fn seat_mask_remove(mask: &mut SeatMask, seat_index: u8) {
    if seat_index < MAX_SEATS {
        *mask &= !seat_mask_bit(seat_index);
    }
}

#[must_use]
/// Count the seats present in `mask`.
pub const fn seat_mask_count(mask: SeatMask) -> u8 {
    mask.count_ones() as u8
}

#[must_use]
/// Return the lowest-numbered seat in `mask`.
pub fn seat_mask_first(mask: SeatMask) -> Option<u8> {
    (mask != 0).then(|| mask.trailing_zeros() as u8)
}

#[must_use]
/// Expand a canonical mask into ascending seat indices below `max_players`.
pub fn seat_mask_to_indices(mask: SeatMask, max_players: u8) -> Vec<u8> {
    (0..max_players)
        .filter(|seat| seat_mask_contains(mask, *seat))
        .collect()
}

/// Build a canonical seat mask, rejecting duplicates and out-of-range indices.
pub fn seat_mask_from_indices(
    indices: &[u8],
    max_players: u8,
    label: &str,
) -> PokerL1Result<SeatMask> {
    if max_players > MAX_SEATS {
        return Err(PokerL1Error::Serialization(format!(
            "{label}: max_players {max_players} exceeds {MAX_SEATS}"
        )));
    }
    let mut mask = 0;
    for &seat_index in indices {
        if seat_index >= max_players {
            return Err(PokerL1Error::Serialization(format!(
                "{label}: seat index {seat_index} outside max_players {max_players}"
            )));
        }
        let bit = seat_mask_bit(seat_index);
        if mask & bit != 0 {
            return Err(PokerL1Error::Serialization(format!(
                "{label}: duplicate seat index {seat_index}"
            )));
        }
        mask |= bit;
    }
    Ok(mask)
}

#[must_use]
/// Return whether `mask` contains only seats below `max_players`.
pub const fn seat_mask_is_canonical(mask: SeatMask, max_players: u8) -> bool {
    max_players <= MAX_SEATS && (max_players == MAX_SEATS || mask < (1u16 << max_players))
}

// ========== ElGamal 密文 ==========

// `ElGamalCiphertext` 直接复用 `poker_protocol::crypto::types::ElGamalCiphertext`
// （= `ElGamalCiphertextGeneric<Bls12381Curve>`，字段 `c1/c2: G1Projective`，
//   已在 `poker_protocol::borsh_impls` impl BorshSerialize/BorshDeserialize）。
// 重导出供外部模块使用。
pub use poker_protocol::crypto::types::ElGamalCiphertext;

// ========== 座位 ==========

/// 玩家座位状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SeatStatus {
    /// 空座位（player = [0; 20]）。
    Empty,
    /// 等待下一局（已入座但本局不参与）。
    Waiting,
    /// 活跃（本局参与）。
    Active,
    /// 已弃牌（本局不再参与下注，但 total_bet 保留供 side pot 计算）。
    Folded,
    /// All-in（已全押，本局不再下注）。
    AllIn,
    /// 出局（stack=0 或被踢后清理）。
    Out,
}

impl Default for SeatStatus {
    fn default() -> Self {
        Self::Empty
    }
}

/// 玩家座位（镜像 Move `Seat` struct，table.move:102-115）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Seat {
    /// 玩家地址（[0; 20] 表示空座位）。
    pub player: Address,
    /// 玩家筹码栈。
    pub stack: u64,
    /// 玩家手牌（最多 2 张）。
    pub hand: HoleCards,
    /// 本轮已下注（每轮开始时清零，累加到 total_bet）。
    pub bet: u64,
    /// 本局总下注（用于 side pot 计算）。
    pub total_bet: u64,
    /// 互斥的座位生命周期状态。
    pub status: SeatStatus,
    /// 玩家 ElGamal 公钥（G1 点，使用 ECPoint newtype 以支持 Borsh）。
    pub pk: ECPoint,
    /// 待入账的 addon 金额（下一手 `reset_for_next_hand` 时合并到 `stack`）。
    ///
    /// 业务语义：玩家可在任意时刻调用 `addon(amount)` 追加筹码，但**不影响当前手牌**：
    /// - 调用时只累加 `pending_addon`，不动 `stack`（避免破坏当前 pot/side_pot）
    /// - 在 `reset_for_next_hand` 第一阶段合并：`stack += pending_addon; pending_addon = 0`
    /// - 合并发生在清理 stack==0 的 seat 之前（确保 addon 后玩家不会被误踢）
    pub pending_addon: u64,
    /// 玩家 Time Bank 剩余额度（毫秒）。
    ///
    /// 业务语义：玩家在 betting 阶段超时后，若 time_bank_ms > 0，
    /// 系统自动消耗 time_bank 续命（而非直接 auto_fold）。
    /// 每手开始时按 `TIME_BANK_REFILL_PER_HAND_MS` 补充（上限 DEFAULT_TIME_BANK_MS）。
    pub time_bank_ms: u64,
}

impl Seat {
    /// 构造空座位。
    #[must_use]
    pub fn empty() -> Self {
        Self {
            player: EMPTY_PLAYER,
            stack: 0,
            hand: HoleCards::empty(),
            bet: 0,
            total_bet: 0,
            status: SeatStatus::Empty,
            pk: ECPoint(G1Projective::identity()),
            pending_addon: 0,
            time_bank_ms: super::constants::DEFAULT_TIME_BANK_MS,
        }
    }

    /// 判断座位是否被活跃占用（player != [0;20] 且未中途离开）。
    #[must_use]
    pub fn is_occupied(&self) -> bool {
        self.player != EMPTY_PLAYER && self.status != SeatStatus::Out
    }

    /// 获取座位状态枚举。
    #[must_use]
    pub fn status(&self) -> SeatStatus {
        self.status
    }

    /// Whether the seat has folded this hand.
    #[must_use]
    pub fn is_folded(&self) -> bool {
        self.status == SeatStatus::Folded
    }

    /// Whether the seat is all-in this hand.
    #[must_use]
    pub fn is_all_in(&self) -> bool {
        self.status == SeatStatus::AllIn
    }

    /// Whether the occupied seat is waiting for the next hand.
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        self.status == SeatStatus::Waiting
    }

    /// Whether the player left or was removed during the current hand.
    #[must_use]
    pub fn has_left_hand(&self) -> bool {
        self.status == SeatStatus::Out
    }

    /// Replace the mutually-exclusive lifecycle state.
    pub fn set_status(&mut self, status: SeatStatus) {
        self.status = status;
    }

    /// 校验可持久化的 canonical seat 表达。
    pub fn validate_canonical(&self) -> PokerL1Result<()> {
        if (self.player == EMPTY_PLAYER) != (self.status == SeatStatus::Empty) {
            return Err(PokerL1Error::Serialization(
                "Texas seat player/status mismatch".into(),
            ));
        }
        self.hand.validate_canonical().map_err(|error| {
            PokerL1Error::Serialization(format!("Texas seat hand is non-canonical: {error}"))
        })?;
        if self.status == SeatStatus::Empty && !self.hand.is_empty() {
            return Err(PokerL1Error::Serialization(
                "Texas empty seat contains hole cards".into(),
            ));
        }
        Ok(())
    }
}

// ========== 洗牌状态 ==========

/// 洗牌状态（镜像 Move `ShuffleState`，table.move:124-129）。
///
/// `phase` 取值见 `constants::SHUFFLE_PHASE_*`（与 Move 端逐字节一致）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShuffleState {
    /// 洗牌阶段（SHUFFLE_PHASE_NONE/WAITING/RECONSTRUCT/BEFORE_PREFLOP）。
    pub phase: u8,
    /// 等待洗牌的玩家集合。
    pub pending_mask: SeatMask,
    /// 已完成洗牌的玩家集合。
    pub completed_mask: SeatMask,
}

impl Default for ShuffleState {
    fn default() -> Self {
        Self {
            phase: SHUFFLE_PHASE_NONE,
            pending_mask: 0,
            completed_mask: 0,
        }
    }
}

impl ShuffleState {
    /// Canonical actor is always the lowest pending seat; no independent scheduling fact exists.
    #[must_use]
    pub fn derived_current_shuffler(&self) -> u8 {
        seat_mask_first(self.pending_mask).unwrap_or(NO_SEAT)
    }
}

// ========== Reveal Token 状态 ==========

/// Canonical destination of one encrypted card reveal.
///
/// Hole-card and public-board targets are mutually exclusive. Encoding them as a tagged union
/// removes the legacy `board_position = 0xff` sentinel and prevents a hole assignment from also
/// carrying a runout/board position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RevealTarget {
    /// One private card belonging to `seat_index` at canonical slot `0..=1`.
    Hole {
        /// Owning seat.
        seat_index: u8,
        /// Hole-card slot in dealing order.
        card_slot: u8,
    },
    /// One public card on runout zero or one at canonical board position `0..=4`.
    Board {
        /// Public runout (`0` for the first board, `1` for the RIT second board).
        runout_index: u8,
        /// Position in the full target board.
        board_position: u8,
    },
}

impl RevealTarget {
    /// Stable sort key used to keep assignment order canonical after completed entries are drained.
    #[must_use]
    pub const fn canonical_key(self) -> (u8, u8, u8) {
        match self {
            Self::Hole {
                seat_index,
                card_slot,
            } => (0, seat_index, card_slot),
            Self::Board {
                runout_index,
                board_position,
            } => (1, runout_index, board_position),
        }
    }
}

/// Canonical reveal collection/resolution state.
///
/// Submitted tokens are stored in ascending seat order. `submitted_mask` is the only seat-to-token
/// index: token `n` belongs to the `n`th set bit. Ready values normally exist only transiently while
/// deterministic normalization drains them; the tagged variants are retained so legacy states with
/// out-of-order completed board positions can migrate without losing a valid reveal result.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RevealProgress {
    /// More authenticated reveal-token submissions are required.
    Collecting {
        /// Seats that still owe a token.
        pending_mask: SeatMask,
        /// Seats whose tokens are already present in `reveal_tokens`.
        submitted_mask: SeatMask,
        /// Verified tokens in ascending seat-index order.
        reveal_tokens: Vec<ECPoint>,
    },
    /// A preflop private card has been partially decrypted for its owner.
    ReadyPartial {
        /// Self-contained partial ciphertext used later by the showdown owner proof.
        ciphertext: ElGamalCiphertext,
    },
    /// A public or showdown card has resolved to a canonical card id.
    ReadyCard {
        /// Resolved canonical card.
        card: Card,
    },
}

impl RevealProgress {
    /// Pending seats, or zero after the cryptographic collection has resolved.
    #[must_use]
    pub const fn pending_mask(&self) -> SeatMask {
        match self {
            Self::Collecting { pending_mask, .. } => *pending_mask,
            Self::ReadyPartial { .. } | Self::ReadyCard { .. } => 0,
        }
    }

    /// Whether this assignment already contains its deterministic reveal result.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(
            self,
            Self::ReadyPartial { .. }
                | Self::ReadyCard { .. }
                | Self::Collecting {
                    pending_mask: 0,
                    ..
                }
        )
    }
}

/// Reveal assignment with one typed target and one canonical progress variant.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealAssignment {
    /// 牌组中的加密牌索引。
    pub encrypted_card_index: u8,
    /// Typed destination of this reveal.
    pub target: RevealTarget,
    /// Collection or ready-to-materialize result.
    pub progress: RevealProgress,
}

impl RevealAssignment {
    /// Seats that still owe a reveal token.
    #[must_use]
    pub const fn pending_mask(&self) -> SeatMask {
        self.progress.pending_mask()
    }

    /// Whether the assignment has resolved and can be drained by normalization.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.progress.is_ready()
    }
}

/// Number of active public-board runouts for the current hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RunoutMode {
    /// Normal single-board play.
    Single,
    /// Two runouts sharing the already exposed first-board prefix.
    Twice,
}

impl Default for RunoutMode {
    fn default() -> Self {
        Self::Single
    }
}

/// Per-hand Run It Twice state.
///
/// `community_cards` is the canonical first board. The second board stores only cards after the
/// shared prefix; the prefix is reconstructed from the first board.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RunItTwiceState {
    /// Single or double runout mode.
    pub mode: RunoutMode,
    /// Number of already exposed community cards shared by both boards.
    pub shared_board_len: u8,
    /// Canonical second-board suffix after `shared_board_len` cards.
    pub second_board_suffix: BoardCards,
}

impl Default for RunItTwiceState {
    fn default() -> Self {
        Self {
            mode: RunoutMode::Single,
            shared_board_len: 0,
            second_board_suffix: BoardCards::empty(),
        }
    }
}

impl RunItTwiceState {
    /// Whether this hand has two active runouts.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.mode, RunoutMode::Twice)
    }

    /// Current second-board length including its shared first-board prefix.
    #[must_use]
    pub fn second_board_len(&self) -> usize {
        usize::from(self.shared_board_len) + self.second_board_suffix.len()
    }

    /// Materialize the full second board for settlement or event output.
    pub fn full_second_board(&self, first_board: &BoardCards) -> PokerL1Result<Vec<Card>> {
        if usize::from(self.shared_board_len) > first_board.len() {
            return Err(PokerL1Error::Serialization(
                "Texas RIT shared prefix exceeds first board".into(),
            ));
        }
        let mut board = first_board[..usize::from(self.shared_board_len)].to_vec();
        board.extend_from_slice(&self.second_board_suffix);
        Ok(board)
    }

    /// Validate the canonical single/twice tagged representation.
    pub fn validate_canonical(&self, first_board: &BoardCards) -> PokerL1Result<()> {
        self.second_board_suffix
            .validate_canonical()
            .map_err(|error| {
                PokerL1Error::Serialization(format!(
                    "Texas RIT second-board suffix is non-canonical: {error}"
                ))
            })?;
        match self.mode {
            RunoutMode::Single => {
                if self.shared_board_len != 0 || !self.second_board_suffix.is_empty() {
                    return Err(PokerL1Error::Serialization(
                        "Texas single runout carries RIT state".into(),
                    ));
                }
            }
            RunoutMode::Twice => {
                let shared = usize::from(self.shared_board_len);
                if shared > 4 || shared > first_board.len() {
                    return Err(PokerL1Error::Serialization(
                        "Texas RIT shared prefix is outside the first board".into(),
                    ));
                }
                if shared + self.second_board_suffix.len() > 5 {
                    return Err(PokerL1Error::Serialization(
                        "Texas RIT second board exceeds five cards".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Reveal Token 状态（镜像 Move `RevealTokenState`，table.move:146-149）。
///
/// `reveal_phase` 取值见 `constants::REVEAL_PHASE_*`（与 Move 端逐字节一致）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealTokenState {
    /// Reveal 阶段（REVEAL_PHASE_NONE/PREFLOP/REDEAL/FLOP/TURN/RIVER/SHOWDOWN）。
    pub reveal_phase: u8,
    /// 当前阶段的分配列表。
    pub assignments: Vec<RevealAssignment>,
}

impl Default for RevealTokenState {
    fn default() -> Self {
        Self {
            reveal_phase: REVEAL_PHASE_NONE,
            assignments: vec![],
        }
    }
}

// ========== Reconstruct 状态 ==========

/// Reconstruct 状态（镜像 Move `ReconstructState`，table.move:158-164）。
///
/// `phase` 取值见 `constants::RECONSTRUCT_PHASE_*`（与 Move 端逐字节一致）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReconstructState {
    /// Reconstruct 阶段（RECONSTRUCT_PHASE_NONE/COLLECTING/COMPLETE）。
    pub phase: u8,
    /// 待提交 reconstruct deck 的玩家列表。
    pub pending_mask: SeatMask,
    /// 随机系数（None = 未设置，使用 ECScalar newtype 以支持 Borsh）。
    pub coefficient: Option<ECScalar>,
    /// 已验证 contribution 逐次合入 canonical aggregate-key base deck 后的结果。
    ///
    /// `None` 表示尚无玩家提交；`Some` 始终恰好包含 52 张密文。这样无论参与者数量
    /// 是 2 还是 9，hot state 都只保存一副 deck，而不是每位玩家各保存一副 deck。
    pub accumulated_deck: Option<Vec<ElGamalCiphertext>>,
}

impl Default for ReconstructState {
    fn default() -> Self {
        Self {
            phase: RECONSTRUCT_PHASE_NONE,
            pending_mask: 0,
            coefficient: None,
            accumulated_deck: None,
        }
    }
}

// ========== 超时配置 ==========

/// 超时配置（镜像 Move `TimeoutConfig`，table.move:167-175）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TimeoutConfig {
    /// 洗牌超时（默认 10000ms）。
    pub shuffle_timeout_ms: u64,
    /// 揭牌超时（默认 10000ms）。
    pub reveal_timeout_ms: u64,
    /// 下注超时（默认 30000ms）。
    pub betting_timeout_ms: u64,
    /// 重构投票超时（默认 10000ms）。
    pub reconstruct_timeout_ms: u64,
    /// 摊牌展示时间（默认 3000ms）。
    pub showdown_display_ms: u64,
    /// 一手结束后等待时间（默认 5000ms）。
    pub hand_complete_wait_ms: u64,
    /// 开始倒计时（默认 5000ms）。
    pub ready_wait_ms: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 10_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            hand_complete_wait_ms: 5_000,
            ready_wait_ms: 5_000,
        }
    }
}

// ========== 时间戳 ==========

/// 时间戳集合（镜像 Move `Timestamps`，table.move:178-186）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct Timestamps {
    /// 当前洗牌者开始时间。
    pub shuffle_started_at: u64,
    /// 当前 reveal 阶段开始时间。
    pub reveal_started_at: u64,
    /// 当前下注者开始时间。
    pub betting_started_at: u64,
    /// reconstruct 投票开始时间。
    pub reconstruct_started_at: u64,
    /// 摊牌展示结束时间。
    pub showdown_at: u64,
}

// ========== Canonical hand phase projection ==========

/// Stable tag used by source normalization and the persisted `HandPhase` union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum HandPhaseTag {
    /// Waiting for an explicit start-hand command.
    Waiting = 0,
    /// One shuffle/remask participant must submit a proof.
    Shuffling = 1,
    /// Reveal-token assignments are being collected or materialized.
    Revealing = 2,
    /// Reconstruction contributions are being collected.
    Reconstructing = 3,
    /// A signed betting action is required.
    Betting = 4,
    /// Hole cards are visible and settlement waits for the display deadline.
    ShowdownDisplay = 5,
}

/// Canonical tagged representation of a hand phase.
///
/// Reconstruction and reconstruct-shuffle temporarily suspend the reveal assignments that will
/// be restarted after the deck is rebuilt; that suspended payload belongs to the same variant and
/// is not treated as a second simultaneously active phase. Persisted schema v7+ stores this union
/// directly; the runtime flattened fields are temporary compatibility caches being removed.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum HandPhase {
    /// No hand transition is active.
    Waiting,
    /// Active shuffle state, optionally carrying a suspended reveal during reconstruction.
    Shuffling {
        /// Betting street that will resume after shuffling.
        street: u8,
        /// Canonical shuffle payload.
        state: ShuffleState,
        /// Reveal payload suspended while a reconstructed deck is shuffled.
        suspended_reveal: Option<RevealTokenState>,
        /// Absolute timeout deadline, or zero while the timer is not armed.
        deadline_ms: u64,
    },
    /// Active reveal-token collection/materialization.
    Revealing {
        /// Current betting street.
        street: u8,
        /// Canonical reveal payload.
        state: RevealTokenState,
        /// Absolute timeout deadline, or zero while the timer is not armed.
        deadline_ms: u64,
    },
    /// Active reconstruct collection with its resume target.
    Reconstructing {
        /// Betting street that will resume after reconstruction.
        street: u8,
        /// Canonical reconstruct payload.
        state: ReconstructState,
        /// Reveal payload suspended until reconstruction and reshuffle finish.
        suspended_reveal: RevealTokenState,
        /// Transcript epoch used by reconstruction proofs.
        epoch_ms: u64,
        /// Absolute timeout deadline for the reconstruction collection.
        deadline_ms: u64,
    },
    /// Active betting round.
    Betting {
        /// Preflop/flop/turn/river discriminator.
        street: u8,
        /// Current bet and minimum raise.
        round: BettingRound,
        /// Current actor or `NO_SEAT` while deterministic normalization is pending.
        current_turn: u8,
        /// Absolute timeout deadline, including any consumed time bank extension.
        deadline_ms: u64,
    },
    /// Canonical showdown-display wait before settlement.
    ShowdownDisplay {
        /// Absolute settlement deadline, or zero before the display timer is armed.
        deadline_ms: u64,
    },
}

impl HandPhase {
    /// Stable union tag used by AIR projections.
    #[must_use]
    pub const fn tag(&self) -> HandPhaseTag {
        match self {
            Self::Waiting => HandPhaseTag::Waiting,
            Self::Shuffling { .. } => HandPhaseTag::Shuffling,
            Self::Revealing { .. } => HandPhaseTag::Revealing,
            Self::Reconstructing { .. } => HandPhaseTag::Reconstructing,
            Self::Betting { .. } => HandPhaseTag::Betting,
            Self::ShowdownDisplay { .. } => HandPhaseTag::ShowdownDisplay,
        }
    }
}

fn canonical_absolute_deadline(
    started_at: u64,
    timeout_ms: u64,
    label: &str,
) -> PokerL1Result<u64> {
    if started_at == 0 {
        return Ok(0);
    }
    started_at.checked_add(timeout_ms).ok_or_else(|| {
        PokerL1Error::Serialization(format!(
            "Texas {label} deadline overflows u64: started_at={started_at}, timeout_ms={timeout_ms}"
        ))
    })
}

// ========== 解密牌账本 ==========

/// Mutually-exclusive state of one reveal-ledger record.
///
/// A record is either a self-contained partial ciphertext that still needs the
/// owner reveal, or a resolved plaintext waiting for the same normalization
/// step to materialize it. The enum prevents the old illegal combinations
/// `(ciphertext = Some, plaintext = Some)` and `(None, None)` at the type level.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum DecryptedCardState {
    /// Partial ciphertext retained across reconstruct until showdown.
    Partial {
        /// Ciphertext after all non-owner reveal layers were removed.
        ciphertext: ElGamalCiphertext,
    },
    /// Canonical plaintext card waiting to be materialized and removed.
    Plaintext {
        /// Decrypted point in the protocol's canonical 52-card domain.
        plaintext: ECPoint,
    },
}

/// One authenticated reveal-ledger record.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DecryptedCard {
    /// Original encrypted deck index (lineage only; not a card identity).
    pub encrypted_card_index: u8,
    /// Owner seat (`OWNER_SEAT_PUBLIC` for community cards).
    pub owner_seat_index: u8,
    /// Exactly one partial/plaintext payload.
    pub state: DecryptedCardState,
}

impl DecryptedCard {
    /// Construct a partial owner-readable record.
    #[must_use]
    pub fn partial(
        encrypted_card_index: u8,
        owner_seat_index: u8,
        ciphertext: ElGamalCiphertext,
    ) -> Self {
        Self {
            encrypted_card_index,
            owner_seat_index,
            state: DecryptedCardState::Partial { ciphertext },
        }
    }

    /// Construct a resolved plaintext record.
    #[must_use]
    pub fn resolved(encrypted_card_index: u8, owner_seat_index: u8, plaintext: ECPoint) -> Self {
        Self {
            encrypted_card_index,
            owner_seat_index,
            state: DecryptedCardState::Plaintext { plaintext },
        }
    }

    /// Borrow the partial ciphertext, if this record is still owner-readable.
    #[must_use]
    pub fn ciphertext(&self) -> Option<&ElGamalCiphertext> {
        match &self.state {
            DecryptedCardState::Partial { ciphertext } => Some(ciphertext),
            DecryptedCardState::Plaintext { .. } => None,
        }
    }

    /// Borrow the resolved plaintext, if this record is ready to materialize.
    #[must_use]
    pub fn plaintext(&self) -> Option<&ECPoint> {
        match &self.state {
            DecryptedCardState::Partial { .. } => None,
            DecryptedCardState::Plaintext { plaintext } => Some(plaintext),
        }
    }
}

// ========== 牌组状态 ==========

/// 牌组状态（镜像 Move `DeckState`，table.move:211-217）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeckState {
    /// 加密牌组（52 个 ElGamalCiphertext）。
    pub encrypted: Vec<ElGamalCiphertext>,
    /// 聚合公钥（None = 未初始化，使用 ECPoint newtype 以支持 Borsh）。
    pub aggregated_pk: Option<ECPoint>,
    /// Seats whose public-key encryption layer is still present in the deck lineage.
    pub contributor_mask: SeatMask,
    /// 已从牌组发出的牌数量。
    pub cards_dealt: u8,
    /// 已解密的合法牌列表。
    pub decrypted_cards: Vec<DecryptedCard>,
}

impl Default for DeckState {
    fn default() -> Self {
        Self {
            encrypted: vec![],
            aggregated_pk: None,
            contributor_mask: 0,
            cards_dealt: 0,
            decrypted_cards: vec![],
        }
    }
}

// ========== 桌台主结构 ==========

/// Texas Poker 桌台（镜像 Move `Table` struct，table.move:270-304）。
///
/// 这是预编译合约的核心状态对象，borsh 编码后存入 ObjectDb，
/// ObjectID = `reserved::texas_poker_contract_id()`（`0xFF..02`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TexasPokerTable {
    /// 桌台 ObjectID（保留 `0xFF..02`）。
    pub id: ObjectID,
    /// Persisted table-state schema version.
    pub state_schema_version: u8,
    /// 桌台名称。
    pub name: String,
    /// 桌台创建者（管理类方法权限基准：kick_player/force_fold/reset_for_next_hand）。
    ///
    /// P0-2：在 `dispatch_create_table` 时记录为 `context.caller`。
    /// 管理类方法在 dispatch 层校验 `caller == creator`，使权限可被
    /// `poker_texas_air` 电路约束（与同步电路目标契合）。
    /// 旧对象反序列化时若为 `EMPTY_PLAYER`，管理类校验会失败，需 governance 重设。
    pub creator: Address,
    /// 最大玩家数（2..=9）。
    pub max_players: u8,
    /// 小盲注金额。
    pub small_blind: u64,
    /// 大盲注金额。
    pub big_blind: u64,

    /// 座位列表（长度 = max_players）。
    pub seats: Vec<Seat>,
    /// 本轮已经完成行动的座位集合。
    pub acted_mask: SeatMask,
    /// 请求在本手结束后离场的座位集合。
    pub leave_after_hand_mask: SeatMask,
    /// 庄家位（button seat_index）。
    pub button: u8,

    /// 当前底池。
    pub pot: u64,
    /// 公共牌（最多 5 张：flop 3 + turn 1 + river 1）。
    pub community_cards: BoardCards,

    /// 唯一运行时手牌阶段；互斥 phase payload 与当前 deadline 只保存于 active variant。
    pub hand_phase: HandPhase,

    /// 加密牌组状态。
    pub deck_state: DeckState,

    /// 超时配置。
    pub timeout_config: TimeoutConfig,

    /// 桌台实际锁仓的 ZCN 总额。
    ///
    /// 这是嵌入 Texas shared object 的 `TableVault.balance`。join/addon/rebuy 的生产
    /// precompile 路径必须先消费等额 native Coin UTXO 才能增加该值；任何退款/离场
    /// 创建 Coin 输出前必须先减少该值。
    pub chip_pool: u64,

    /// 尚未并入玩家 stack 的 pending addon 总额。
    ///
    /// 该值是 `chip_pool` 的子集而不是第二份资产：addon 时两者同时增加；下一手
    /// pending_addon 合并进 stack 时本字段减少、chip_pool 不变。
    pub addon_pool: u64,

    /// Ante 模式（`ANTE_MODE_NONE/NORMAL/BBA`）。
    ///
    /// 默认 NONE。设置后在 `start_hand` 时按模式投 ante：
    /// - NORMAL：每个玩家投 `ante_amount`
    /// - BBA：仅大盲位投 `ante_amount`（简化投注流程）
    pub ante_mode: u8,
    /// Ante 金额（每手投注的 ante 数额）。
    pub ante_amount: u64,
    /// 本手已累积的 ante 总额（settle 时统一分配，或计入 pot）。
    pub ante_collected: u64,

    /// Rake 模式（`RAKE_MODE_NONE/PERCENTAGE`）。
    ///
    /// 默认 NONE。设置为 PERCENTAGE 后，`settle_hand` 时按 `rake_bps` 比例抽水：
    /// `rake = min(pot * rake_bps / 10000, rake_cap)`
    pub rake_mode: u8,
    /// Rake 比例（基点 bps，500 = 5%）。
    pub rake_bps: u64,
    /// Rake 上限（单手最多抽水金额）。
    pub rake_cap: u64,
    /// 本次结算已抽水金额。
    ///
    /// 此字段不是 TableVault 余额；它是状态机在同一 dispatch 中留给
    /// `TexasPokerPrecompile` 的 Treasury Coin 出金收据。结算的
    /// `reset_for_next_hand` 会在持久化前将其清零。
    pub rake_collected: u64,

    /// Run It Twice 模式（`RIT_MODE_DISABLED/TWICE`）。
    ///
    /// 默认 DISABLED。设置为 TWICE 后，无进一步争议下注时，已公开公共牌成为共享前缀，
    /// 后续公共牌按两个独立 runout 发牌并由规范化结算计划逐层拆池。
    pub rit_mode: u8,

    /// Current hand's two-runout state. Empty outside an active RIT hand.
    pub run_it_twice_state: RunItTwiceState,

    /// 当前手牌序号。
    ///
    /// 初始为 0；每当一次成功 dispatch 产生 `HandStarted` 事件时递增。
    /// 该值随桌台状态持久化，并写入 ProveTask 公开输入，避免跨手牌任务混淆。
    pub hand_id: u32,

    /// 成功改变桌台状态的 dispatch 序号。
    ///
    /// 初始为 0；每次成功且 `pre_table != post_table` 的 dispatch 严格递增一次。
    /// 无状态变化的 permissionless `tick` 不消耗序号，保证证明任务连续。
    pub call_seq: u32,

    /// 状态版本号（每次更新 +1，用于乐观锁）。
    pub version: u64,
}

impl TexasPokerTable {
    /// Canonical betting street/outer round projection.
    #[must_use]
    pub const fn round_state(&self) -> u8 {
        match &self.hand_phase {
            HandPhase::Waiting => ROUND_WAITING,
            HandPhase::Shuffling { street, .. }
            | HandPhase::Revealing { street, .. }
            | HandPhase::Reconstructing { street, .. }
            | HandPhase::Betting { street, .. } => *street,
            HandPhase::ShowdownDisplay { .. } => ROUND_SHOWDOWN,
        }
    }

    /// Canonical betting-round payload, if the active hand phase is betting.
    #[must_use]
    pub const fn betting_round(&self) -> Option<BettingRound> {
        match &self.hand_phase {
            HandPhase::Betting { round, .. } => Some(*round),
            _ => None,
        }
    }

    /// Canonical current betting actor or [`NO_SEAT`] outside an actionable betting phase.
    #[must_use]
    pub const fn current_turn(&self) -> u8 {
        match &self.hand_phase {
            HandPhase::Betting { current_turn, .. } => *current_turn,
            _ => NO_SEAT,
        }
    }

    /// Read-only projection of the active shuffle payload.
    #[must_use]
    pub fn shuffle_state(&self) -> Cow<'_, ShuffleState> {
        match &self.hand_phase {
            HandPhase::Shuffling { state, .. } => Cow::Borrowed(state),
            _ => Cow::Owned(ShuffleState::default()),
        }
    }

    /// Read-only compatibility projection of the active or suspended reveal payload.
    #[must_use]
    pub fn reveal_token_state(&self) -> Cow<'_, RevealTokenState> {
        match &self.hand_phase {
            HandPhase::Revealing { state, .. } => Cow::Borrowed(state),
            HandPhase::Reconstructing {
                suspended_reveal, ..
            } => Cow::Borrowed(suspended_reveal),
            HandPhase::Shuffling {
                suspended_reveal: Some(state),
                ..
            } => Cow::Borrowed(state),
            _ => Cow::Owned(RevealTokenState::default()),
        }
    }

    /// Read-only compatibility projection of the active reconstruct payload.
    #[must_use]
    pub fn reconstruct_state(&self) -> Cow<'_, ReconstructState> {
        match &self.hand_phase {
            HandPhase::Reconstructing { state, .. } => Cow::Borrowed(state),
            _ => Cow::Owned(ReconstructState::default()),
        }
    }

    /// Read-only compatibility projection of phase timing data.
    #[must_use]
    pub fn timestamps(&self) -> Cow<'_, Timestamps> {
        let mut timestamps = Timestamps::default();
        match &self.hand_phase {
            HandPhase::Shuffling { deadline_ms, .. } => {
                timestamps.shuffle_started_at =
                    deadline_ms.saturating_sub(self.timeout_config.shuffle_timeout_ms);
            }
            HandPhase::Revealing { deadline_ms, .. } => {
                timestamps.reveal_started_at =
                    deadline_ms.saturating_sub(self.timeout_config.reveal_timeout_ms);
            }
            HandPhase::Reconstructing { epoch_ms, .. } => {
                timestamps.reconstruct_started_at = *epoch_ms;
            }
            HandPhase::Betting { deadline_ms, .. } => {
                timestamps.betting_started_at =
                    deadline_ms.saturating_sub(self.timeout_config.betting_timeout_ms);
            }
            HandPhase::ShowdownDisplay { deadline_ms } => {
                timestamps.showdown_at = *deadline_ms;
            }
            HandPhase::Waiting => {}
        }
        Cow::Owned(timestamps)
    }

    /// Mutable payload of the active shuffle variant.
    pub fn active_shuffle_state_mut(&mut self) -> PokerL1Result<&mut ShuffleState> {
        match &mut self.hand_phase {
            HandPhase::Shuffling { state, .. } => Ok(state),
            _ => Err(PokerL1Error::Serialization(
                "Texas table is not in an active shuffle phase".into(),
            )),
        }
    }

    /// Mutable payload of the active reveal variant.
    pub fn active_reveal_state_mut(&mut self) -> PokerL1Result<&mut RevealTokenState> {
        match &mut self.hand_phase {
            HandPhase::Revealing { state, .. } => Ok(state),
            _ => Err(PokerL1Error::Serialization(
                "Texas table is not in an active reveal phase".into(),
            )),
        }
    }

    /// Take the active or suspended reveal payload while performing an atomic phase transition.
    pub fn take_reveal_payload(&mut self) -> PokerL1Result<RevealTokenState> {
        let phase = std::mem::replace(&mut self.hand_phase, HandPhase::Waiting);
        match phase {
            HandPhase::Revealing { state, .. } => Ok(state),
            HandPhase::Reconstructing {
                suspended_reveal, ..
            } => Ok(suspended_reveal),
            HandPhase::Shuffling {
                suspended_reveal: Some(state),
                ..
            } => Ok(state),
            other => {
                self.hand_phase = other;
                Err(PokerL1Error::Serialization(
                    "Texas phase has no active or suspended reveal payload".into(),
                ))
            }
        }
    }

    /// Mutable payload of the active reconstruction variant.
    pub fn active_reconstruct_state_mut(&mut self) -> PokerL1Result<&mut ReconstructState> {
        match &mut self.hand_phase {
            HandPhase::Reconstructing { state, .. } => Ok(state),
            _ => Err(PokerL1Error::Serialization(
                "Texas table is not in an active reconstruct phase".into(),
            )),
        }
    }

    /// Transcript epoch of the active reconstruction variant.
    #[must_use]
    pub const fn reconstruct_epoch_ms(&self) -> Option<u64> {
        match &self.hand_phase {
            HandPhase::Reconstructing { epoch_ms, .. } => Some(*epoch_ms),
            _ => None,
        }
    }

    /// Absolute deadline of the active reconstruction phase, or zero while unarmed.
    pub fn reconstruct_deadline_ms(&self) -> PokerL1Result<Option<u64>> {
        if self.reconstruct_state.phase == RECONSTRUCT_PHASE_NONE {
            return Ok(None);
        }
        canonical_absolute_deadline(
            self.timestamps.reconstruct_started_at,
            self.timeout_config.reconstruct_timeout_ms,
            "reconstruct",
        )
        .map(Some)
    }

    /// Arm the active reconstruction deadline from consensus time.
    pub fn arm_reconstruct_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        if self.reconstruct_state.phase == RECONSTRUCT_PHASE_NONE {
            return Err(PokerL1Error::Serialization(
                "cannot arm reconstruct deadline outside phase".into(),
            ));
        }
        let deadline_ms = canonical_absolute_deadline(
            now_ms,
            self.timeout_config.reconstruct_timeout_ms,
            "reconstruct",
        )?;
        self.timestamps.reconstruct_started_at = now_ms;
        Ok(deadline_ms)
    }

    /// Absolute deadline of the active shuffle phase, or zero while unarmed.
    pub fn shuffle_deadline_ms(&self) -> PokerL1Result<Option<u64>> {
        if self.shuffle_state.phase == SHUFFLE_PHASE_NONE {
            return Ok(None);
        }
        canonical_absolute_deadline(
            self.timestamps.shuffle_started_at,
            self.timeout_config.shuffle_timeout_ms,
            "shuffle",
        )
        .map(Some)
    }

    /// Arm the active shuffle deadline from consensus time.
    pub fn arm_shuffle_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        if self.shuffle_state.phase == SHUFFLE_PHASE_NONE {
            return Err(PokerL1Error::Serialization(
                "cannot arm shuffle deadline outside phase".into(),
            ));
        }
        let deadline_ms = canonical_absolute_deadline(
            now_ms,
            self.timeout_config.shuffle_timeout_ms,
            "shuffle",
        )?;
        self.timestamps.shuffle_started_at = now_ms;
        Ok(deadline_ms)
    }

    /// Disarm the active shuffle deadline when its canonical actor changes.
    pub fn disarm_shuffle_deadline(&mut self) -> PokerL1Result<()> {
        if self.shuffle_state.phase == SHUFFLE_PHASE_NONE {
            return Err(PokerL1Error::Serialization(
                "cannot disarm shuffle deadline outside phase".into(),
            ));
        }
        self.timestamps.shuffle_started_at = 0;
        Ok(())
    }

    /// Absolute deadline of the active reveal phase, or zero while unarmed.
    pub fn reveal_deadline_ms(&self) -> PokerL1Result<Option<u64>> {
        if self.reveal_token_state.reveal_phase == REVEAL_PHASE_NONE
            || self.reconstruct_state.phase != RECONSTRUCT_PHASE_NONE
            || self.shuffle_state.phase == SHUFFLE_PHASE_RECONSTRUCT
        {
            return Ok(None);
        }
        canonical_absolute_deadline(
            self.timestamps.reveal_started_at,
            self.timeout_config.reveal_timeout_ms,
            "reveal",
        )
        .map(Some)
    }

    /// Arm the active reveal deadline from consensus time.
    pub fn arm_reveal_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        if self.reveal_deadline_ms()?.is_none() {
            return Err(PokerL1Error::Serialization(
                "cannot arm reveal deadline outside phase".into(),
            ));
        }
        let deadline_ms = canonical_absolute_deadline(
            now_ms,
            self.timeout_config.reveal_timeout_ms,
            "reveal",
        )?;
        self.timestamps.reveal_started_at = now_ms;
        Ok(deadline_ms)
    }

    /// Absolute deadline of the active betting phase, or zero while unarmed.
    pub fn betting_deadline_ms(&self) -> PokerL1Result<Option<u64>> {
        if self.betting_round.is_none() {
            return Ok(None);
        }
        canonical_absolute_deadline(
            self.timestamps.betting_started_at,
            self.timeout_config.betting_timeout_ms,
            "betting",
        )
        .map(Some)
    }

    /// Arm the active betting deadline from consensus time.
    pub fn arm_betting_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        if self.betting_round.is_none() {
            return Err(PokerL1Error::Serialization(
                "cannot arm betting deadline outside phase".into(),
            ));
        }
        let deadline_ms = canonical_absolute_deadline(
            now_ms,
            self.timeout_config.betting_timeout_ms,
            "betting",
        )?;
        self.timestamps.betting_started_at = now_ms;
        Ok(deadline_ms)
    }

    /// Extend the active betting deadline after consuming time bank.
    pub fn extend_betting_deadline(&mut self, extension_ms: u64) -> PokerL1Result<u64> {
        if self.betting_round.is_none() || self.timestamps.betting_started_at == 0 {
            return Err(PokerL1Error::Serialization(
                "cannot extend an unarmed betting deadline".into(),
            ));
        }
        let started_at_ms = self
            .timestamps
            .betting_started_at
            .checked_add(extension_ms)
            .ok_or_else(|| {
                PokerL1Error::Serialization(
                    "Texas betting deadline extension overflows u64".into(),
                )
            })?;
        let deadline_ms = canonical_absolute_deadline(
            started_at_ms,
            self.timeout_config.betting_timeout_ms,
            "betting",
        )?;
        self.timestamps.betting_started_at = started_at_ms;
        Ok(deadline_ms)
    }

    /// Absolute showdown-display settlement deadline, or zero while unarmed.
    #[must_use]
    pub const fn showdown_deadline_ms(&self) -> Option<u64> {
        if self.round_state == ROUND_SHOWDOWN
            && self.reveal_token_state.reveal_phase == REVEAL_PHASE_NONE
        {
            Some(self.timestamps.showdown_at)
        } else {
            None
        }
    }

    /// Arm the showdown-display settlement deadline from consensus time.
    pub fn arm_showdown_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        if self.showdown_deadline_ms().is_none() {
            return Err(PokerL1Error::Serialization(
                "cannot arm showdown deadline outside display phase".into(),
            ));
        }
        let deadline_ms = now_ms
            .checked_add(self.timeout_config.showdown_display_ms)
            .ok_or_else(|| {
                PokerL1Error::Serialization("Texas showdown deadline overflows u64".into())
            })?;
        self.timestamps.showdown_at = deadline_ms;
        Ok(deadline_ms)
    }

    /// Mutable payload of the active betting variant.
    pub fn active_betting_round_mut(&mut self) -> PokerL1Result<&mut BettingRound> {
        self.betting_round.as_mut().ok_or_else(|| {
            PokerL1Error::Serialization("Texas table is not in an active betting phase".into())
        })
    }

    /// Update the actor inside the current betting variant and disarm its deadline.
    pub fn set_betting_turn(&mut self, current_turn: u8) -> PokerL1Result<()> {
        if self.betting_round.is_none() {
            return Err(PokerL1Error::Serialization(
                "cannot set current turn outside betting".into(),
            ));
        }
        if current_turn != NO_SEAT && current_turn >= self.max_players {
            return Err(PokerL1Error::Serialization(format!(
                "Texas current turn {current_turn} is outside max_players {}",
                self.max_players
            )));
        }
        self.current_turn = current_turn;
        self.disarm_betting_deadline()?;
        Ok(())
    }

    /// Disarm the current betting actor's deadline after an accepted action/turn change.
    pub fn disarm_betting_deadline(&mut self) -> PokerL1Result<()> {
        if self.betting_round.is_none() {
            return Err(PokerL1Error::Serialization(
                "cannot disarm betting deadline outside betting".into(),
            ));
        }
        self.timestamps.betting_started_at = 0;
        Ok(())
    }

    /// Remove one seat from the payload of the single active protocol variant.
    ///
    /// Betting has no protocol participant mask; reconstruction and reconstruct-shuffle also
    /// carry a suspended reveal payload whose pending bits must be scrubbed consistently.
    pub fn remove_seat_from_active_phase(&mut self, seat_index: u8) -> PokerL1Result<()> {
        if seat_index >= self.max_players {
            return Err(PokerL1Error::Serialization(format!(
                "cannot remove out-of-range seat {seat_index} from Texas phase"
            )));
        }
        if self.reconstruct_state.phase != RECONSTRUCT_PHASE_NONE {
            seat_mask_remove(&mut self.reconstruct_state.pending_mask, seat_index);
            for assignment in &mut self.reveal_token_state.assignments {
                if let RevealProgress::Collecting { pending_mask, .. } = &mut assignment.progress {
                    seat_mask_remove(pending_mask, seat_index);
                }
            }
            return Ok(());
        }
        if self.shuffle_state.phase != SHUFFLE_PHASE_NONE {
            seat_mask_remove(&mut self.shuffle_state.pending_mask, seat_index);
            seat_mask_remove(&mut self.shuffle_state.completed_mask, seat_index);
            if self.shuffle_state.phase == SHUFFLE_PHASE_RECONSTRUCT {
                for assignment in &mut self.reveal_token_state.assignments {
                    if let RevealProgress::Collecting { pending_mask, .. } =
                        &mut assignment.progress
                    {
                        seat_mask_remove(pending_mask, seat_index);
                    }
                }
            }
            return Ok(());
        }
        if self.reveal_token_state.reveal_phase != REVEAL_PHASE_NONE {
            for assignment in &mut self.reveal_token_state.assignments {
                if let RevealProgress::Collecting { pending_mask, .. } = &mut assignment.progress {
                    seat_mask_remove(pending_mask, seat_index);
                }
            }
        }
        Ok(())
    }

    /// Atomically enter the idle phase and clear every phase-local compatibility payload.
    ///
    /// These helpers are the only supported boundary for cross-phase state-machine writes. The
    /// flattened fields remain temporarily for schema migration, but are updated as one logical
    /// tagged union so an intermediate reveal/shuffle/betting overlap cannot escape.
    pub fn enter_waiting(&mut self) {
        self.round_state = ROUND_WAITING;
        self.betting_round = None;
        self.current_turn = NO_SEAT;
        self.shuffle_state = ShuffleState::default();
        self.reveal_token_state = RevealTokenState::default();
        self.reconstruct_state = ReconstructState::default();
        self.timestamps = Timestamps::default();
    }

    /// Atomically enter a shuffle phase.
    pub fn enter_shuffling(
        &mut self,
        street: u8,
        state: ShuffleState,
        suspended_reveal: Option<RevealTokenState>,
        started_at_ms: u64,
    ) {
        self.round_state = street;
        self.betting_round = None;
        self.current_turn = NO_SEAT;
        self.shuffle_state = state;
        self.reveal_token_state = suspended_reveal.unwrap_or_default();
        self.reconstruct_state = ReconstructState::default();
        self.timestamps = Timestamps {
            shuffle_started_at: started_at_ms,
            ..Timestamps::default()
        };
    }

    /// Atomically enter a reveal-token phase.
    pub fn enter_revealing(
        &mut self,
        street: u8,
        state: RevealTokenState,
        started_at_ms: u64,
    ) {
        self.round_state = street;
        self.betting_round = None;
        self.current_turn = NO_SEAT;
        self.shuffle_state = ShuffleState::default();
        self.reveal_token_state = state;
        self.reconstruct_state = ReconstructState::default();
        self.timestamps = Timestamps {
            reveal_started_at: started_at_ms,
            ..Timestamps::default()
        };
    }

    /// Atomically suspend a reveal and enter reconstruction collection.
    pub fn enter_reconstructing(
        &mut self,
        street: u8,
        state: ReconstructState,
        suspended_reveal: RevealTokenState,
        epoch_ms: u64,
    ) {
        self.round_state = street;
        self.betting_round = None;
        self.current_turn = NO_SEAT;
        self.shuffle_state = ShuffleState::default();
        self.reveal_token_state = suspended_reveal;
        self.reconstruct_state = state;
        self.timestamps = Timestamps {
            reconstruct_started_at: epoch_ms,
            ..Timestamps::default()
        };
    }

    /// Atomically enter an actionable betting round.
    pub fn enter_betting(
        &mut self,
        street: u8,
        round: BettingRound,
        current_turn: u8,
        started_at_ms: u64,
    ) {
        self.round_state = street;
        self.betting_round = Some(round);
        self.current_turn = current_turn;
        self.shuffle_state = ShuffleState::default();
        self.reveal_token_state = RevealTokenState::default();
        self.reconstruct_state = ReconstructState::default();
        self.timestamps = Timestamps {
            betting_started_at: started_at_ms,
            ..Timestamps::default()
        };
    }

    /// Atomically enter the showdown display wait after all hole cards are materialized.
    pub fn enter_showdown_display(&mut self, deadline_ms: u64) {
        self.round_state = ROUND_SHOWDOWN;
        self.betting_round = None;
        self.current_turn = NO_SEAT;
        self.shuffle_state = ShuffleState::default();
        self.reveal_token_state = RevealTokenState::default();
        self.reconstruct_state = ReconstructState::default();
        self.timestamps = Timestamps {
            showdown_at: deadline_ms,
            ..Timestamps::default()
        };
    }

    fn aggregated_pk_for_contributor_mask(
        &self,
        contributor_mask: SeatMask,
    ) -> PokerL1Result<Option<ECPoint>> {
        if !seat_mask_is_canonical(contributor_mask, self.max_players) {
            return Err(PokerL1Error::Serialization(
                "Texas deck contributor mask contains out-of-range bits".into(),
            ));
        }
        let mut aggregate: Option<ECPoint> = None;
        for seat_index in 0..self.max_players {
            if !seat_mask_contains(contributor_mask, seat_index) {
                continue;
            }
            let seat = &self.seats[usize::from(seat_index)];
            if !seat.is_occupied() || super::utils::g1_is_identity(&seat.pk) {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas deck contributor seat {seat_index} is empty, out, or has identity pk"
                )));
            }
            aggregate = Some(match aggregate {
                None => seat.pk,
                Some(current) => ECPoint::from(super::utils::g1_add(&current.0, &seat.pk.0)),
            });
        }
        if aggregate
            .as_ref()
            .is_some_and(|point| super::utils::g1_is_identity(&point.0))
        {
            return Err(PokerL1Error::Serialization(
                "Texas non-empty contributor set has identity aggregate pk".into(),
            ));
        }
        Ok(aggregate)
    }

    /// Derive the aggregate deck key from the canonical contributor lineage.
    pub fn derived_aggregated_pk(&self) -> PokerL1Result<Option<ECPoint>> {
        self.aggregated_pk_for_contributor_mask(self.deck_state.contributor_mask)
    }

    /// Rebuild the runtime aggregate-key cache from the contributor mask.
    pub fn sync_aggregated_pk(&mut self) -> PokerL1Result<()> {
        self.deck_state.aggregated_pk = self.derived_aggregated_pk()?;
        Ok(())
    }

    /// Add a seat to the deck-key lineage and refresh the aggregate cache.
    pub fn add_deck_contributor(&mut self, seat_index: u8) -> PokerL1Result<()> {
        if seat_index >= self.max_players {
            return Err(PokerL1Error::Serialization(format!(
                "Texas contributor seat {seat_index} is out of range"
            )));
        }
        let contributor_mask = self.deck_state.contributor_mask | seat_mask_bit(seat_index);
        let aggregated_pk = self.aggregated_pk_for_contributor_mask(contributor_mask)?;
        self.deck_state.contributor_mask = contributor_mask;
        self.deck_state.aggregated_pk = aggregated_pk;
        Ok(())
    }

    /// Remove a seat from the deck-key lineage and refresh the aggregate cache.
    pub fn remove_deck_contributor(&mut self, seat_index: u8) -> PokerL1Result<()> {
        let mut contributor_mask = self.deck_state.contributor_mask;
        seat_mask_remove(&mut contributor_mask, seat_index);
        let aggregated_pk = self.aggregated_pk_for_contributor_mask(contributor_mask)?;
        self.deck_state.contributor_mask = contributor_mask;
        self.deck_state.aggregated_pk = aggregated_pk;
        Ok(())
    }

    /// 构造新桌台（空座位，WAITING 状态）。
    #[must_use]
    pub fn new(
        id: ObjectID,
        name: String,
        creator: Address,
        max_players: u8,
        small_blind: u64,
        big_blind: u64,
    ) -> Self {
        assert!(
            max_players >= 2 && max_players <= 9,
            "max_players 必须 2..=9"
        );
        assert!(big_blind > 0, "big_blind 必须 > 0");
        assert!(small_blind <= big_blind, "small_blind 必须 <= big_blind");

        let seats = (0..max_players).map(|_| Seat::empty()).collect();

        Self {
            id,
            state_schema_version: super::TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name,
            creator,
            max_players,
            small_blind,
            big_blind,
            seats,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            button: 0,
            pot: 0,
            community_cards: BoardCards::empty(),
            round_state: super::constants::ROUND_WAITING,
            betting_round: None,
            current_turn: NO_SEAT,
            deck_state: DeckState::default(),
            shuffle_state: ShuffleState::default(),
            reveal_token_state: RevealTokenState::default(),
            reconstruct_state: ReconstructState::default(),
            timeout_config: TimeoutConfig::default(),
            timestamps: Timestamps::default(),
            chip_pool: 0,
            addon_pool: 0,
            ante_mode: super::constants::ANTE_MODE_NONE,
            ante_amount: 0,
            ante_collected: 0,
            rake_mode: super::constants::RAKE_MODE_NONE,
            rake_bps: super::constants::DEFAULT_RAKE_BPS,
            rake_cap: super::constants::DEFAULT_RAKE_CAP,
            rake_collected: 0,
            rit_mode: super::constants::RIT_MODE_DISABLED,
            run_it_twice_state: RunItTwiceState::default(),
            hand_id: 0,
            call_seq: 0,
            version: 0,
        }
    }

    /// 统计活跃玩家数（未 fold 且未 left_during_hand）。
    #[must_use]
    pub fn active_count(&self) -> u8 {
        self.seats
            .iter()
            .filter(|s| s.is_occupied() && !s.is_folded())
            .count() as u8
    }

    /// 统计已入座玩家数（含 waiting）。
    #[must_use]
    pub fn occupied_count(&self) -> u8 {
        self.seats.iter().filter(|s| s.is_occupied()).count() as u8
    }

    /// 查找指定玩家的座位索引。
    #[must_use]
    pub fn find_seat(&self, player: &Address) -> Option<u8> {
        self.seats
            .iter()
            .position(|s| &s.player == player)
            .map(|i| i as u8)
    }

    /// 查找第一个空座位。
    #[must_use]
    pub fn find_empty_seat(&self) -> Option<u8> {
        self.seats
            .iter()
            .position(|s| s.player == EMPTY_PLAYER)
            .map(|i| i as u8)
    }

    /// Whether `seat_index` has completed its current betting action.
    #[must_use]
    pub fn seat_acted_this_round(&self, seat_index: u8) -> bool {
        seat_mask_contains(self.acted_mask, seat_index)
    }

    /// Set or clear the current-round acted bit for one seat.
    pub fn set_seat_acted_this_round(&mut self, seat_index: u8, value: bool) {
        if value {
            debug_assert!(seat_index < self.max_players);
            self.acted_mask |= seat_mask_bit(seat_index);
        } else {
            seat_mask_remove(&mut self.acted_mask, seat_index);
        }
    }

    /// Whether `seat_index` requested removal after the current hand.
    #[must_use]
    pub fn seat_wants_leave(&self, seat_index: u8) -> bool {
        seat_mask_contains(self.leave_after_hand_mask, seat_index)
    }

    /// Set or clear the leave-after-hand bit for one seat.
    pub fn set_seat_wants_leave(&mut self, seat_index: u8, value: bool) {
        if value {
            debug_assert!(seat_index < self.max_players);
            self.leave_after_hand_mask |= seat_mask_bit(seat_index);
        } else {
            seat_mask_remove(&mut self.leave_after_hand_mask, seat_index);
        }
    }

    /// Decode the canonical current-turn sentinel.
    #[must_use]
    pub fn current_turn_option(&self) -> Option<u8> {
        (self.current_turn != NO_SEAT).then_some(self.current_turn)
    }

    /// Project the temporary flattened runtime cache into one fail-closed canonical hand phase.
    pub fn canonical_hand_phase(&self) -> PokerL1Result<HandPhase> {
        let reconstruct_active = self.reconstruct_state.phase != RECONSTRUCT_PHASE_NONE;
        let shuffle_active = self.shuffle_state.phase != SHUFFLE_PHASE_NONE;
        let reveal_active = self.reveal_token_state.reveal_phase != REVEAL_PHASE_NONE;
        let betting_active = self.betting_round.is_some();

        if reconstruct_active {
            if shuffle_active || betting_active || !reveal_active {
                return Err(PokerL1Error::Serialization(
                    "Texas reconstruct phase has an invalid active-phase combination".into(),
                ));
            }
            return Ok(HandPhase::Reconstructing {
                street: self.round_state,
                state: self.reconstruct_state.clone(),
                suspended_reveal: self.reveal_token_state.clone(),
                epoch_ms: self.timestamps.reconstruct_started_at,
                deadline_ms: canonical_absolute_deadline(
                    self.timestamps.reconstruct_started_at,
                    self.timeout_config.reconstruct_timeout_ms,
                    "reconstruct",
                )?,
            });
        }

        if shuffle_active {
            if betting_active
                || (reveal_active && self.shuffle_state.phase != SHUFFLE_PHASE_RECONSTRUCT)
            {
                return Err(PokerL1Error::Serialization(
                    "Texas shuffle phase has an invalid active-phase combination".into(),
                ));
            }
            return Ok(HandPhase::Shuffling {
                street: self.round_state,
                state: self.shuffle_state.clone(),
                suspended_reveal: reveal_active.then(|| self.reveal_token_state.clone()),
                deadline_ms: canonical_absolute_deadline(
                    self.timestamps.shuffle_started_at,
                    self.timeout_config.shuffle_timeout_ms,
                    "shuffle",
                )?,
            });
        }

        if reveal_active {
            if betting_active {
                return Err(PokerL1Error::Serialization(
                    "Texas reveal and betting phases cannot both be active".into(),
                ));
            }
            return Ok(HandPhase::Revealing {
                street: self.round_state,
                state: self.reveal_token_state.clone(),
                deadline_ms: canonical_absolute_deadline(
                    self.timestamps.reveal_started_at,
                    self.timeout_config.reveal_timeout_ms,
                    "reveal",
                )?,
            });
        }

        if let Some(round) = self.betting_round {
            if !matches!(
                self.round_state,
                ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
            ) {
                return Err(PokerL1Error::Serialization(
                    "Texas betting phase is outside a live street".into(),
                ));
            }
            return Ok(HandPhase::Betting {
                street: self.round_state,
                round,
                current_turn: self.current_turn,
                deadline_ms: canonical_absolute_deadline(
                    self.timestamps.betting_started_at,
                    self.timeout_config.betting_timeout_ms,
                    "betting",
                )?,
            });
        }

        match self.round_state {
            ROUND_WAITING => Ok(HandPhase::Waiting),
            ROUND_SHOWDOWN => Ok(HandPhase::ShowdownDisplay {
                deadline_ms: self.timestamps.showdown_at,
            }),
            ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER => {
                Err(PokerL1Error::Serialization(format!(
                    "Texas live street {} has no active phase",
                    self.round_state
                )))
            }
            round => Err(PokerL1Error::Serialization(format!(
                "Texas table contains unknown round_state {round}"
            ))),
        }
    }

    /// Reject a table encoded for a different persisted state schema.
    pub fn validate_state_schema(&self) -> PokerL1Result<()> {
        if self.state_schema_version != super::TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported TexasPokerTable state schema {}, expected {}",
                self.state_schema_version,
                super::TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION
            )));
        }
        if !(2..=MAX_SEATS).contains(&self.max_players)
            || self.seats.len() != usize::from(self.max_players)
        {
            return Err(PokerL1Error::Serialization(format!(
                "Texas seat layout mismatch: max_players={}, seats={}",
                self.max_players,
                self.seats.len()
            )));
        }
        if !seat_mask_is_canonical(self.acted_mask, self.max_players)
            || !seat_mask_is_canonical(self.leave_after_hand_mask, self.max_players)
        {
            return Err(PokerL1Error::Serialization(
                "Texas table contains out-of-range seat flag bits".into(),
            ));
        }
        if self.current_turn != NO_SEAT && self.current_turn >= self.max_players {
            return Err(PokerL1Error::Serialization(format!(
                "Texas current_turn {} is outside max_players {}",
                self.current_turn, self.max_players
            )));
        }
        for (seat_index, seat) in self.seats.iter().enumerate() {
            seat.validate_canonical()?;
            if seat.status == SeatStatus::Empty
                && (seat_mask_contains(self.acted_mask, seat_index as u8)
                    || seat_mask_contains(self.leave_after_hand_mask, seat_index as u8))
            {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas empty seat {seat_index} contains live table flags"
                )));
            }
        }
        let derived_aggregate = self.derived_aggregated_pk()?;
        if self.deck_state.aggregated_pk != derived_aggregate {
            return Err(PokerL1Error::Serialization(
                "Texas cached aggregate pk does not match contributor mask".into(),
            ));
        }
        self.community_cards.validate_canonical().map_err(|error| {
            PokerL1Error::Serialization(format!("Texas first board is non-canonical: {error}"))
        })?;
        self.run_it_twice_state
            .validate_canonical(&self.community_cards)?;
        let mut seen_cards = [false; 52];
        for card in self
            .community_cards
            .iter()
            .chain(self.run_it_twice_state.second_board_suffix.iter())
            .chain(self.seats.iter().flat_map(|seat| seat.hand.iter()))
        {
            let card_id = usize::from(card.to_index());
            if card_id >= seen_cards.len() || seen_cards[card_id] {
                return Err(PokerL1Error::Serialization(
                    "Texas table contains an invalid or duplicate materialized card".into(),
                ));
            }
            seen_cards[card_id] = true;
        }
        for (record_index, record) in self.deck_state.decrypted_cards.iter().enumerate() {
            if usize::from(record.encrypted_card_index) >= 52 {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas reveal ledger record {record_index} has out-of-range deck index {}",
                    record.encrypted_card_index
                )));
            }
            if record.owner_seat_index != OWNER_SEAT_PUBLIC
                && record.owner_seat_index >= self.max_players
            {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas reveal ledger record {record_index} has out-of-range owner {}",
                    record.owner_seat_index
                )));
            }
            if self.deck_state.decrypted_cards[..record_index]
                .iter()
                .any(|prior| {
                    prior.encrypted_card_index == record.encrypted_card_index
                        && prior.owner_seat_index == record.owner_seat_index
                })
            {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas reveal ledger contains duplicate lineage owner={} deck_index={}",
                    record.owner_seat_index, record.encrypted_card_index
                )));
            }
            match &record.state {
                DecryptedCardState::Partial { .. } => {
                    if record.owner_seat_index == OWNER_SEAT_PUBLIC {
                        return Err(PokerL1Error::Serialization(
                            "Texas public reveal ledger record cannot remain partial".into(),
                        ));
                    }
                }
                DecryptedCardState::Plaintext { .. } => {
                    let matching_ready =
                        self.reveal_token_state
                            .assignments
                            .iter()
                            .any(|assignment| {
                                if assignment.encrypted_card_index != record.encrypted_card_index
                                    || !matches!(
                                        assignment.progress,
                                        RevealProgress::ReadyCard { .. }
                                    )
                                {
                                    return false;
                                }
                                match assignment.target {
                                    RevealTarget::Hole { seat_index, .. } => {
                                        record.owner_seat_index == seat_index
                                    }
                                    RevealTarget::Board { .. } => {
                                        record.owner_seat_index == OWNER_SEAT_PUBLIC
                                    }
                                }
                            });
                    if !matching_ready {
                        return Err(PokerL1Error::Serialization(format!(
                            "Texas plaintext reveal ledger record {record_index} has no matching ready assignment"
                        )));
                    }
                }
            }
        }
        let validate_mask = |mask: SeatMask, label: &str| -> PokerL1Result<()> {
            if seat_mask_is_canonical(mask, self.max_players) {
                Ok(())
            } else {
                Err(PokerL1Error::Serialization(format!(
                    "Texas {label} contains out-of-range seat bits"
                )))
            }
        };
        validate_mask(self.shuffle_state.pending_mask, "shuffle pending mask")?;
        validate_mask(self.shuffle_state.completed_mask, "shuffle completed mask")?;
        if self.shuffle_state.pending_mask & self.shuffle_state.completed_mask != 0 {
            return Err(PokerL1Error::Serialization(
                "Texas shuffle pending/completed masks overlap".into(),
            ));
        }
        for assignment in &self.reveal_token_state.assignments {
            validate_mask(assignment.pending_mask(), "reveal pending mask")?;
        }
        validate_mask(
            self.reconstruct_state.pending_mask,
            "reconstruct pending mask",
        )?;
        match &self.reconstruct_state.accumulated_deck {
            Some(deck) => {
                if deck.len() != 52 {
                    return Err(PokerL1Error::Serialization(format!(
                        "Texas reconstruct accumulator has {} cards, expected 52",
                        deck.len()
                    )));
                }
            }
            None => {}
        }
        Ok(())
    }

    /// 状态版本号自增（每次 mutation 后调用）。
    pub fn bump_version(&mut self) {
        // 用 saturating_add 避免 version 达到 u64::MAX 时 panic（DoS）。
        // version 仅用于乐观锁，溢出后仍单调，语义不受影响。
        self.version = self.version.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_table_id() -> ObjectID {
        ObjectID::new([0xFF; 20], 0)
    }

    #[test]
    fn test_table_new() {
        let table = TexasPokerTable::new(dummy_table_id(), "test".into(), EMPTY_PLAYER, 6, 50, 100);
        assert_eq!(
            table.state_schema_version,
            super::super::TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION
        );
        assert_eq!(table.max_players, 6);
        assert_eq!(table.seats.len(), 6);
        assert_eq!(table.small_blind, 50);
        assert_eq!(table.big_blind, 100);
        assert_eq!(table.round_state, super::super::constants::ROUND_WAITING);
        assert_eq!(table.active_count(), 0);
        assert_eq!(table.occupied_count(), 0);
        assert_eq!(
            table.canonical_hand_phase().unwrap().tag(),
            HandPhaseTag::Waiting
        );
    }

    #[test]
    fn canonical_hand_phase_rejects_reveal_and_betting_overlap() {
        let mut table =
            TexasPokerTable::new(dummy_table_id(), "test".into(), EMPTY_PLAYER, 6, 50, 100);
        table.round_state = ROUND_FLOP;
        table.reveal_token_state.reveal_phase = super::super::constants::REVEAL_PHASE_FLOP;
        table.betting_round = Some(BettingRound::new(100, 0));

        assert!(table.canonical_hand_phase().is_err());
    }

    #[test]
    fn canonical_hand_phase_carries_suspended_reveal_during_reconstruct() {
        let mut table =
            TexasPokerTable::new(dummy_table_id(), "test".into(), EMPTY_PLAYER, 6, 50, 100);
        table.round_state = ROUND_TURN;
        table.reveal_token_state.reveal_phase = super::super::constants::REVEAL_PHASE_TURN;
        table.reconstruct_state.phase = super::super::constants::RECONSTRUCT_PHASE_COLLECTING;

        let phase = table.canonical_hand_phase().unwrap();
        assert_eq!(phase.tag(), HandPhaseTag::Reconstructing);
        assert!(matches!(
            phase,
            HandPhase::Reconstructing {
                street: ROUND_TURN,
                suspended_reveal: RevealTokenState {
                    reveal_phase: super::super::constants::REVEAL_PHASE_TURN,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn phase_helpers_clear_incompatible_payloads_and_deadline_overflow_is_atomic() {
        let mut table =
            TexasPokerTable::new(dummy_table_id(), "test".into(), EMPTY_PLAYER, 6, 50, 100);
        table.enter_revealing(
            ROUND_FLOP,
            RevealTokenState {
                reveal_phase: super::super::constants::REVEAL_PHASE_FLOP,
                assignments: vec![],
            },
            0,
        );
        table.enter_betting(ROUND_FLOP, BettingRound::new(100, 0), 1, 0);

        assert_eq!(table.reveal_token_state, RevealTokenState::default());
        assert_eq!(table.shuffle_state, ShuffleState::default());
        assert_eq!(table.reconstruct_state, ReconstructState::default());
        assert_eq!(
            table.canonical_hand_phase().unwrap().tag(),
            HandPhaseTag::Betting
        );

        table.timeout_config.betting_timeout_ms = 10;
        let before = table.clone();
        assert!(table.arm_betting_deadline(u64::MAX - 5).is_err());
        assert_eq!(table, before);
    }

    #[test]
    fn test_table_new_invalid_params() {
        // max_players < 2
        let result = std::panic::catch_unwind(|| {
            TexasPokerTable::new(dummy_table_id(), "x".into(), EMPTY_PLAYER, 1, 50, 100);
        });
        assert!(result.is_err());

        // max_players > 9
        let result = std::panic::catch_unwind(|| {
            TexasPokerTable::new(dummy_table_id(), "x".into(), EMPTY_PLAYER, 10, 50, 100);
        });
        assert!(result.is_err());

        // big_blind = 0
        let result = std::panic::catch_unwind(|| {
            TexasPokerTable::new(dummy_table_id(), "x".into(), EMPTY_PLAYER, 6, 50, 0);
        });
        assert!(result.is_err());

        // small_blind > big_blind
        let result = std::panic::catch_unwind(|| {
            TexasPokerTable::new(dummy_table_id(), "x".into(), EMPTY_PLAYER, 6, 200, 100);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_seat_empty() {
        let seat = Seat::empty();
        assert_eq!(seat.player, EMPTY_PLAYER);
        assert_eq!(seat.stack, 0);
        assert!(!seat.is_occupied());
        assert_eq!(seat.status(), SeatStatus::Empty);
    }

    #[test]
    fn test_seat_status_transitions() {
        let mut seat = Seat::empty();
        seat.player = [0xAB; 20];
        seat.stack = 1000;
        seat.set_status(SeatStatus::Active);
        assert_eq!(seat.status(), SeatStatus::Active);

        seat.set_status(SeatStatus::Folded);
        assert_eq!(seat.status(), SeatStatus::Folded);

        seat.set_status(SeatStatus::AllIn);
        assert_eq!(seat.status(), SeatStatus::AllIn);

        seat.set_status(SeatStatus::Waiting);
        assert_eq!(seat.status(), SeatStatus::Waiting);

        seat.set_status(SeatStatus::Out);
        assert_eq!(seat.status(), SeatStatus::Out);
    }

    #[test]
    fn test_table_find_seat() {
        let mut table =
            TexasPokerTable::new(dummy_table_id(), "t".into(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[2].player = [0x02; 20];

        assert_eq!(table.find_seat(&[0x01; 20]), Some(0));
        assert_eq!(table.find_seat(&[0x02; 20]), Some(2));
        assert_eq!(table.find_seat(&[0x03; 20]), None);
    }

    #[test]
    fn test_table_find_empty_seat() {
        let mut table =
            TexasPokerTable::new(dummy_table_id(), "t".into(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[1].player = [0x02; 20];

        assert_eq!(table.find_empty_seat(), Some(2));
    }

    #[test]
    fn test_table_active_count() {
        let mut table =
            TexasPokerTable::new(dummy_table_id(), "t".into(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[1].player = [0x02; 20];
        table.seats[2].player = [0x03; 20];
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].set_status(SeatStatus::Active);
        table.seats[2].set_status(SeatStatus::Active);
        assert_eq!(table.active_count(), 3);

        table.seats[1].set_status(SeatStatus::Folded);
        assert_eq!(table.active_count(), 2);
    }

    #[test]
    fn test_table_borsh_roundtrip() {
        let mut table = TexasPokerTable::new(
            dummy_table_id(),
            "test-table".into(),
            EMPTY_PLAYER,
            4,
            50,
            100,
        );
        table.seats[0].player = [0xAB; 20];
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].stack = 1_000_000;
        table.pot = 200;
        table.community_cards.try_push(Card::new(0, 14)).unwrap(); // A♠
        table.version = 42;

        let bytes = borsh::to_vec(&table).unwrap();
        let recovered: TexasPokerTable = borsh::from_slice(&bytes).unwrap();
        assert_eq!(table, recovered);
    }

    #[test]
    fn test_table_rejects_wrong_state_schema() {
        let mut table =
            TexasPokerTable::new(dummy_table_id(), "test".into(), EMPTY_PLAYER, 4, 50, 100);
        table.state_schema_version = 1;
        let error = table.validate_state_schema().unwrap_err();
        assert!(error.to_string().contains("state schema 1"));
    }

    #[test]
    fn test_table_bump_version() {
        let mut table =
            TexasPokerTable::new(dummy_table_id(), "t".into(), EMPTY_PLAYER, 4, 50, 100);
        assert_eq!(table.version, 0);
        table.bump_version();
        assert_eq!(table.version, 1);
        table.bump_version();
        assert_eq!(table.version, 2);
    }

    #[test]
    fn test_shuffle_state_default() {
        let state = ShuffleState::default();
        assert_eq!(state.phase, SHUFFLE_PHASE_NONE);
        assert_eq!(state.derived_current_shuffler(), NO_SEAT);
        assert_eq!(state.pending_mask, 0);
        assert_eq!(state.completed_mask, 0);
    }

    #[test]
    fn test_reveal_token_state_default() {
        let state = RevealTokenState::default();
        assert_eq!(state.reveal_phase, REVEAL_PHASE_NONE);
        assert!(state.assignments.is_empty());
    }

    #[test]
    fn test_reconstruct_state_default() {
        let state = ReconstructState::default();
        assert_eq!(state.phase, RECONSTRUCT_PHASE_NONE);
        assert_eq!(state.pending_mask, 0);
        assert!(state.coefficient.is_none());
        assert!(state.accumulated_deck.is_none());
    }

    #[test]
    fn test_timeout_config_defaults_match_move() {
        let cfg = TimeoutConfig::default();
        assert_eq!(cfg.shuffle_timeout_ms, 10_000);
        assert_eq!(cfg.reveal_timeout_ms, 10_000);
        assert_eq!(cfg.betting_timeout_ms, 30_000);
        assert_eq!(cfg.reconstruct_timeout_ms, 10_000);
        assert_eq!(cfg.showdown_display_ms, 3_000);
        assert_eq!(cfg.hand_complete_wait_ms, 5_000);
        assert_eq!(cfg.ready_wait_ms, 5_000);
    }

    #[test]
    fn test_seat_borsh_roundtrip() {
        let seat = Seat {
            player: [0xCD; 20],
            stack: 5_000,
            hand: [Card::new(0, 14), Card::new(1, 13)].into(),
            bet: 100,
            total_bet: 250,
            status: SeatStatus::Active,
            pk: ECPoint(G1Projective::identity()),
            pending_addon: 0,
            time_bank_ms: super::super::constants::DEFAULT_TIME_BANK_MS,
        };
        let bytes = borsh::to_vec(&seat).unwrap();
        let recovered: Seat = borsh::from_slice(&bytes).unwrap();
        assert_eq!(seat, recovered);
    }
}
