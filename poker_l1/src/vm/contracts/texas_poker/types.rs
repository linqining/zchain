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

use borsh::{BorshDeserialize, BorshSerialize};
use group::Group;

use blstrs::G1Projective;
use poker_protocol::crypto::types::{ECPoint, ECScalar};
// 注：`ElGamalCiphertext` 通过下方 `pub use` 重导出，避免重复导入。

use crate::object_model::ObjectID;
use crate::Address;

use super::betting::BettingRound;
use super::card::Card;
// 复用 constants.rs 中与 Move 端逐字节一致的 phase 常量（避免本地重复定义导致语义分叉）
use super::constants::{
    RECONSTRUCT_PHASE_COLLECTING, RECONSTRUCT_PHASE_COMPLETE, RECONSTRUCT_PHASE_NONE,
    REVEAL_PHASE_FLOP, REVEAL_PHASE_NONE, REVEAL_PHASE_PREFLOP, REVEAL_PHASE_REDEAL,
    REVEAL_PHASE_RIVER, REVEAL_PHASE_SHOWDOWN, REVEAL_PHASE_TURN, ROUND_WAITING,
    SHUFFLE_PHASE_BEFORE_PREFLOP, SHUFFLE_PHASE_NONE, SHUFFLE_PHASE_RECONSTRUCT,
    SHUFFLE_PHASE_WAITING,
};
use super::side_pot::SidePot;

// ========== 常量 ==========

/// 公共牌 owner_seat_index 特殊值（u8 域：表示该牌不属于任何玩家）。
///
/// 注意：constants.rs 中的 `COMMUNITY_CARD_OWNER` 是 u64（与 Move 一致），
/// 但 `DecryptedCard.owner_seat_index` 在 Rust 端使用 u8（座位数最多 9），
/// 因此这里用 `u8::MAX` 作为等价哨兵。
pub const OWNER_SEAT_PUBLIC: u8 = u8::MAX;

/// 空座位标识（player = [0; 20]）。
pub const EMPTY_PLAYER: Address = [0u8; 20];

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
    pub hand: Vec<Card>,
    /// 本轮已下注（每轮开始时清零，累加到 total_bet）。
    pub bet: u64,
    /// 本局总下注（用于 side pot 计算）。
    pub total_bet: u64,
    /// 是否已弃牌。
    pub folded: bool,
    /// 是否 all-in。
    pub all_in: bool,
    /// 本轮是否已行动（用于判断是否需要等待行动）。
    pub acted_this_round: bool,
    /// 本局不参与，等下一局开始（对应 Move `is_waiting`）。
    pub is_waiting: bool,
    /// 本局中途离开（被踢），total_bet 保留供 side pot 计算。
    pub left_during_hand: bool,
    /// 玩家 ElGamal 公钥（G1 点，使用 ECPoint newtype 以支持 Borsh）。
    pub pk: ECPoint,
    /// total_bet 是否已退款（避免重复退款）。
    pub refunded: bool,
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
    /// 玩家请求「下局开始前离场」（sit out next hand / stand up next hand）。
    ///
    /// 业务语义：玩家可在**任意时刻**（含对局进行中）通过
    /// `request_leave_after_hand` 方法切换此标志（toggle，再次调用取消）。
    /// 当下一手在 `reset_for_next_hand`（由 settle_hand / end_without_showdown /
    /// 超时路径触发）时，所有 `want_leave=true` 的 occupied seat 会被强制
    /// 踢出并退还 stack + pending_addon。
    ///
    /// 解决的问题：`leave_table` 仅在 WAITING 状态可用，而 creator / `tick`
    /// 可能在 settle 后立即 `start_hand`，玩家来不及离场。此标志让玩家
    /// 在对局中即可预约离场，由 reset 强制执行（在线扑克标准模式）。
    pub want_leave: bool,
}

impl Seat {
    /// 构造空座位。
    #[must_use]
    pub fn empty() -> Self {
        Self {
            player: EMPTY_PLAYER,
            stack: 0,
            hand: vec![],
            bet: 0,
            total_bet: 0,
            folded: false,
            all_in: false,
            acted_this_round: false,
            is_waiting: false,
            left_during_hand: false,
            pk: ECPoint(G1Projective::identity()),
            refunded: false,
            pending_addon: 0,
            time_bank_ms: super::constants::DEFAULT_TIME_BANK_MS,
            want_leave: false,
        }
    }

    /// 判断座位是否被活跃占用（player != [0;20] 且未中途离开）。
    #[must_use]
    pub fn is_occupied(&self) -> bool {
        self.player != EMPTY_PLAYER && !self.left_during_hand
    }

    /// 获取座位状态枚举。
    #[must_use]
    pub fn status(&self) -> SeatStatus {
        if self.player == EMPTY_PLAYER {
            SeatStatus::Empty
        } else if self.left_during_hand {
            SeatStatus::Out
        } else if self.is_waiting {
            SeatStatus::Waiting
        } else if self.folded {
            SeatStatus::Folded
        } else if self.all_in {
            SeatStatus::AllIn
        } else {
            SeatStatus::Active
        }
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
    /// 当前洗牌者 seat_index（None 表示未开始或已完成）。
    pub current_shuffler: Option<u8>,
    /// 等待洗牌的玩家列表（按顺序）。
    pub pending_players: Vec<u8>,
    /// 已完成洗牌的玩家列表。
    pub completed_players: Vec<u8>,
}

impl Default for ShuffleState {
    fn default() -> Self {
        Self {
            phase: SHUFFLE_PHASE_NONE,
            current_shuffler: None,
            pending_players: vec![],
            completed_players: vec![],
        }
    }
}

// ========== Reveal Token 状态 ==========

/// 单个玩家的 reveal token 数据（镜像 Move `RevealTokenData`，table.move:140-143）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealTokenData {
    /// 提交者 seat_index。
    pub seat_index: u8,
    /// token = c1 * sk（G1 点，使用 ECPoint newtype 以支持 Borsh）。
    pub token: ECPoint,
}

/// Reveal 分配（镜像 Move `RevealAssignment`，table.move:132-137）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealAssignment {
    /// 牌组中的加密牌索引。
    pub encrypted_card_index: u8,
    /// 待提交 reveal token 的玩家 seat_index 列表。
    pub pending_players: Vec<u8>,
    /// 已收集的 reveal tokens。
    pub reveal_tokens: Vec<RevealTokenData>,
    /// 是否已解密。
    pub decrypted: bool,
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

/// 单个玩家提交的 reconstruct 输出（镜像 Move `ReconstructPlayerDeck`，table.move:153-156）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReconstructPlayerDeck {
    /// 提交者 seat_index。
    pub seat_index: u8,
    /// 该玩家重建后的牌组（52 个 ElGamalCiphertext）。
    pub output_cts: Vec<ElGamalCiphertext>,
}

/// Reconstruct 状态（镜像 Move `ReconstructState`，table.move:158-164）。
///
/// `phase` 取值见 `constants::RECONSTRUCT_PHASE_*`（与 Move 端逐字节一致）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReconstructState {
    /// Reconstruct 阶段（RECONSTRUCT_PHASE_NONE/COLLECTING/COMPLETE）。
    pub phase: u8,
    /// 待提交 reconstruct deck 的玩家列表。
    pub pending_players: Vec<u8>,
    /// 随机系数（None = 未设置，使用 ECScalar newtype 以支持 Borsh）。
    pub coefficient: Option<ECScalar>,
    /// 所有玩家提交的重建牌组。
    pub player_decks: Vec<ReconstructPlayerDeck>,
}

impl Default for ReconstructState {
    fn default() -> Self {
        Self {
            phase: RECONSTRUCT_PHASE_NONE,
            pending_players: vec![],
            coefficient: None,
            player_decks: vec![],
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
    /// 准备好开始的时间戳（0=未设置）。
    pub ready_at: u64,
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
    /// 一手结束时间。
    pub hand_complete_at: u64,
}

// ========== 已解密牌 ==========

/// 已解密牌（镜像 Move `DecryptedCard`，table.move:194-199）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DecryptedCard {
    /// 原始加密牌组中的索引。
    pub encrypted_card_index: u8,
    /// 牌主 seat_index（公共牌为 `OWNER_SEAT_PUBLIC` = 255）。
    pub owner_seat_index: u8,
    /// 部分解密密文（None = 已完全解密）。
    pub ciphertext: Option<ElGamalCiphertext>,
    /// 完全解密明文（None = 仅部分解密，使用 ECPoint newtype 以支持 Borsh）。
    pub plaintext: Option<ECPoint>,
}

// ========== 牌组状态 ==========

/// 牌组状态（镜像 Move `DeckState`，table.move:211-217）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeckState {
    /// 加密牌组（52 个 ElGamalCiphertext）。
    pub encrypted: Vec<ElGamalCiphertext>,
    /// 聚合公钥（None = 未初始化，使用 ECPoint newtype 以支持 Borsh）。
    pub aggregated_pk: Option<ECPoint>,
    /// 52 张明文牌（G1 点，由合约生成；使用 ECPoint newtype 以支持 Borsh）。
    pub plaintext: Vec<ECPoint>,
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
            plaintext: vec![],
            cards_dealt: 0,
            decrypted_cards: vec![],
        }
    }
}

// ========== 桌台配置 ==========

/// 桌台配置（控制 ZK skip 等行为，dev chain 友好）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TableConfig {
    /// 是否启用 ZK skip 模式（dev chain 友好；mainnet 强制 false）。
    /// true 时所有 ZK verify 调用直接返回 true。
    pub zk_skip_enabled: bool,
    /// 是否跳过 shuffle proof 验证。
    pub zk_skip_shuffle: bool,
    /// 是否跳过 reveal token proof 验证。
    pub zk_skip_reveal: bool,
    /// 是否跳过 reconstruct proof 验证。
    pub zk_skip_reconstruct: bool,
    /// 是否跳过 remask proof 验证。
    pub zk_skip_remask: bool,
}

impl Default for TableConfig {
    fn default() -> Self {
        // dev chain 默认全部 skip，便于首版跑通流程
        // mainnet 启动时由 governance 强制设为 false
        Self {
            zk_skip_enabled: true,
            zk_skip_shuffle: true,
            zk_skip_reveal: true,
            zk_skip_reconstruct: true,
            zk_skip_remask: true,
        }
    }
}

impl TableConfig {
    /// 是否跳过 shuffle proof 验证。
    #[must_use]
    pub fn skip_shuffle(&self) -> bool {
        self.zk_skip_enabled && self.zk_skip_shuffle
    }

    /// 是否跳过 reveal token proof 验证。
    #[must_use]
    pub fn skip_reveal(&self) -> bool {
        self.zk_skip_enabled && self.zk_skip_reveal
    }

    /// 是否跳过 reconstruct proof 验证。
    #[must_use]
    pub fn skip_reconstruct(&self) -> bool {
        self.zk_skip_enabled && self.zk_skip_reconstruct
    }

    /// 是否跳过 remask proof 验证。
    #[must_use]
    pub fn skip_remask(&self) -> bool {
        self.zk_skip_enabled && self.zk_skip_remask
    }
}

// ========== 桌台主结构 ==========

/// Texas Poker 桌台（镜像 Move `Table` struct，table.move:270-304）。
///
/// 这是预编译合约的核心状态对象，borsh 编码后存入 ObjectDb，
/// ObjectID = `reserved::texas_poker_contract_id()`（`0xFF..02`）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasPokerTable {
    /// 桌台 ObjectID（保留 `0xFF..02`）。
    pub id: ObjectID,
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
    /// 庄家位（button seat_index）。
    pub button: u8,

    /// 当前底池。
    pub pot: u64,
    /// 边池列表（side pot 分层结果）。
    pub side_pots: Vec<SidePot>,
    /// 公共牌（最多 5 张：flop 3 + turn 1 + river 1）。
    pub community_cards: Vec<Card>,

    /// 当前回合状态（ROUND_*，见 constants.rs）。
    pub round_state: u8,
    /// 当前下注轮状态（None = 未在下注阶段）。
    pub betting_round: Option<BettingRound>,
    /// 当前行动玩家 seat_index（None = 无需行动）。
    pub current_turn: Option<u8>,

    /// 加密牌组状态。
    pub deck_state: DeckState,

    /// 协议状态：洗牌。
    pub shuffle_state: ShuffleState,
    /// 协议状态：reveal token。
    pub reveal_token_state: RevealTokenState,
    /// 协议状态：reconstruct。
    pub reconstruct_state: ReconstructState,

    /// 超时配置。
    pub timeout_config: TimeoutConfig,
    /// 时间戳集合。
    pub timestamps: Timestamps,

    /// 玩家存入资金池（用于 buy_in 兑换 stack，离开时兑换回）。
    /// 对应 Move 的 `sui_balance: Balance<SUI>`，zchain 无原生 SUI，用 u64。
    pub chip_pool: u64,

    /// Addon 资金池（与 `chip_pool` 平行，记录所有 addon 入金总额）。
    ///
    /// 业务语义：玩家调用 `addon(amount)` 时，`addon_pool += amount`，
    /// 同时 `seats[i].pending_addon += amount`（下一手合并到 stack）。
    /// 离开桌台时，`pending_addon` 与 `stack` 一起退还。
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
    /// 本手已抽水金额（settle 时计算并扣除）。
    pub rake_collected: u64,

    /// Run It Twice 模式（`RIT_MODE_DISABLED/TWICE`）。
    ///
    /// 默认 DISABLED。设置为 TWICE 后，all-in 时发两次 board，降低方差。
    /// v2 PoC：仅作为配置标记，完整双 board 流程留待后续。
    pub rit_mode: u8,

    /// 桌台配置（ZK skip 等）。
    pub config: TableConfig,

    /// 状态版本号（每次更新 +1，用于乐观锁）。
    pub version: u64,
}

impl TexasPokerTable {
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
        assert!(max_players >= 2 && max_players <= 9, "max_players 必须 2..=9");
        assert!(big_blind > 0, "big_blind 必须 > 0");
        assert!(
            small_blind <= big_blind,
            "small_blind 必须 <= big_blind"
        );

        let seats = (0..max_players).map(|_| Seat::empty()).collect();

        Self {
            id,
            name,
            creator,
            max_players,
            small_blind,
            big_blind,
            seats,
            button: 0,
            pot: 0,
            side_pots: vec![],
            community_cards: vec![],
            round_state: super::constants::ROUND_WAITING,
            betting_round: None,
            current_turn: None,
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
            config: TableConfig::default(),
            version: 0,
        }
    }

    /// 统计活跃玩家数（未 fold 且未 left_during_hand）。
    #[must_use]
    pub fn active_count(&self) -> u8 {
        self.seats
            .iter()
            .filter(|s| s.is_occupied() && !s.folded)
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

    /// 状态版本号自增（每次 mutation 后调用）。
    pub fn bump_version(&mut self) {
        self.version = self
            .version
            .checked_add(1)
            .expect("version 溢出（u64 最大值）");
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
        assert_eq!(table.max_players, 6);
        assert_eq!(table.seats.len(), 6);
        assert_eq!(table.small_blind, 50);
        assert_eq!(table.big_blind, 100);
        assert_eq!(table.round_state, super::super::constants::ROUND_WAITING);
        assert_eq!(table.active_count(), 0);
        assert_eq!(table.occupied_count(), 0);
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
        assert_eq!(seat.status(), SeatStatus::Active);

        seat.folded = true;
        assert_eq!(seat.status(), SeatStatus::Folded);

        seat.folded = false;
        seat.all_in = true;
        assert_eq!(seat.status(), SeatStatus::AllIn);

        seat.all_in = false;
        seat.is_waiting = true;
        assert_eq!(seat.status(), SeatStatus::Waiting);

        seat.is_waiting = false;
        seat.left_during_hand = true;
        assert_eq!(seat.status(), SeatStatus::Out);
    }

    #[test]
    fn test_table_find_seat() {
        let mut table = TexasPokerTable::new(dummy_table_id(), "t".into(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[2].player = [0x02; 20];

        assert_eq!(table.find_seat(&[0x01; 20]), Some(0));
        assert_eq!(table.find_seat(&[0x02; 20]), Some(2));
        assert_eq!(table.find_seat(&[0x03; 20]), None);
    }

    #[test]
    fn test_table_find_empty_seat() {
        let mut table = TexasPokerTable::new(dummy_table_id(), "t".into(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[1].player = [0x02; 20];

        assert_eq!(table.find_empty_seat(), Some(2));
    }

    #[test]
    fn test_table_active_count() {
        let mut table = TexasPokerTable::new(dummy_table_id(), "t".into(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[1].player = [0x02; 20];
        table.seats[2].player = [0x03; 20];
        assert_eq!(table.active_count(), 3);

        table.seats[1].folded = true;
        assert_eq!(table.active_count(), 2);
    }

    #[test]
    fn test_table_borsh_roundtrip() {
        let mut table = TexasPokerTable::new(dummy_table_id(), "test-table".into(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].player = [0xAB; 20];
        table.seats[0].stack = 1_000_000;
        table.pot = 200;
        table.community_cards.push(Card::new(0, 14)); // A♠
        table.version = 42;

        let bytes = borsh::to_vec(&table).unwrap();
        let recovered: TexasPokerTable = borsh::from_slice(&bytes).unwrap();
        assert_eq!(table, recovered);
    }

    #[test]
    fn test_table_config_skip_flags() {
        let cfg = TableConfig::default();
        assert!(cfg.skip_shuffle());
        assert!(cfg.skip_reveal());
        assert!(cfg.skip_reconstruct());
        assert!(cfg.skip_remask());

        let strict = TableConfig {
            zk_skip_enabled: false,
            zk_skip_shuffle: true,
            zk_skip_reveal: true,
            zk_skip_reconstruct: true,
            zk_skip_remask: true,
        };
        assert!(!strict.skip_shuffle());
        assert!(!strict.skip_reveal());
    }

    #[test]
    fn test_table_bump_version() {
        let mut table = TexasPokerTable::new(dummy_table_id(), "t".into(), EMPTY_PLAYER, 4, 50, 100);
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
        assert!(state.current_shuffler.is_none());
        assert!(state.pending_players.is_empty());
        assert!(state.completed_players.is_empty());
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
        assert!(state.pending_players.is_empty());
        assert!(state.coefficient.is_none());
        assert!(state.player_decks.is_empty());
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
            hand: vec![Card::new(0, 14), Card::new(1, 13)],
            bet: 100,
            total_bet: 250,
            folded: false,
            all_in: false,
            acted_this_round: true,
            is_waiting: false,
            left_during_hand: false,
            pk: ECPoint(G1Projective::identity()),
            refunded: false,
            pending_addon: 0,
            time_bank_ms: super::super::constants::DEFAULT_TIME_BANK_MS,
            want_leave: false,
        };
        let bytes = borsh::to_vec(&seat).unwrap();
        let recovered: Seat = borsh::from_slice(&bytes).unwrap();
        assert_eq!(seat, recovered);
    }
}
