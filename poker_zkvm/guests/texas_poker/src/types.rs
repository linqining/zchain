//! Texas Poker 核心数据结构（Phase 3.4 移植）。
//!
//! 原 `poker_l1/src/vm/contracts/texas_poker/types.rs` 的 no_std 移植。
//!
//! # 移植变更
//!
//! - **ECPoint/ECScalar**：原为 blstrs 类型的 newtype（borsh orphan rule），
//!   guest 端直接用 `guest_sdk::bls::{G1Point, Scalar}`（字节数组 newtype，已 derive Borsh）
//! - **ObjectID/Address**：原 `crate::object_model::ObjectID` / `crate::Address`，
//!   guest 端用本地类型别名 `[u8; 32]` / `[u8; 20]`
//! - **ElGamalCiphertext**：原 `poker_protocol::crypto::types::ElGamalCiphertext`，
//!   guest 端用 `guest_sdk::bls::ElGamalCiphertext`
//! - **Seat::empty() pk**：用 `G1Point([0; 48])` 占位（不调 syscall），
//!   真正的 identity 在 state_machine 初始化时按需设置

use alloc::string::String;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

use zkvm_guest_sdk::bls::{ElGamalCiphertext, G1Point, Scalar};

use super::betting::BettingRound;
use super::card::Card;
use super::constants::{
    RECONSTRUCT_PHASE_COLLECTING, RECONSTRUCT_PHASE_COMPLETE, RECONSTRUCT_PHASE_NONE,
    REVEAL_PHASE_FLOP, REVEAL_PHASE_NONE, REVEAL_PHASE_PREFLOP, REVEAL_PHASE_REDEAL,
    REVEAL_PHASE_RIVER, REVEAL_PHASE_SHOWDOWN, REVEAL_PHASE_TURN, ROUND_WAITING,
    SHUFFLE_PHASE_BEFORE_PREFLOP, SHUFFLE_PHASE_NONE, SHUFFLE_PHASE_RECONSTRUCT,
    SHUFFLE_PHASE_WAITING,
};
use super::side_pot::SidePot;

// ========== 类型别名 ==========

/// ObjectID（与 zchain 一致，32 字节）。
pub type ObjectID = [u8; 32];

/// 地址（20 字节）。
pub type Address = [u8; 20];

/// ECPoint 兼容别名（原为 blstrs newtype，guest 端直接用 G1Point）。
pub type ECPoint = G1Point;

/// ECScalar 兼容别名（原为 blstrs newtype，guest 端直接用 Scalar）。
pub type ECScalar = Scalar;

// ========== 常量 ==========

/// 公共牌 owner_seat_index 特殊值（u8 域：表示该牌不属于任何玩家）。
pub const OWNER_SEAT_PUBLIC: u8 = u8::MAX;

/// 空座位标识（player = [0; 20]）。
pub const EMPTY_PLAYER: Address = [0u8; 20];

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

/// 玩家座位（镜像 Move `Seat` struct）。
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
    /// 玩家 ElGamal 公钥（G1 点）。
    pub pk: ECPoint,
    /// total_bet 是否已退款（避免重复退款）。
    pub refunded: bool,
}

impl Seat {
    /// 构造空座位。
    ///
    /// pk 用全零占位（非真正 identity），不调 syscall。
    #[must_use]
    pub fn empty() -> Self {
        Self {
            player: EMPTY_PLAYER,
            stack: 0,
            hand: Vec::new(),
            bet: 0,
            total_bet: 0,
            folded: false,
            all_in: false,
            acted_this_round: false,
            is_waiting: false,
            left_during_hand: false,
            pk: G1Point([0u8; 48]),
            refunded: false,
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

/// 洗牌状态。
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
            pending_players: Vec::new(),
            completed_players: Vec::new(),
        }
    }
}

// ========== Reveal Token 状态 ==========

/// 单个玩家的 reveal token 数据。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealTokenData {
    /// 提交者 seat_index。
    pub seat_index: u8,
    /// token = c1 * sk（G1 点）。
    pub token: ECPoint,
}

/// Reveal 分配。
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

/// Reveal Token 状态。
///
/// 注意：`BorshDeserialize` 为**手动实现**（非 derive），与 `TexasPokerTable` 同理。
/// 派生宏生成的 `deserialize_reader` 会将 `u8` 和 `Vec<RevealAssignment>` 反序列化
/// 深度内联（包括 `Vec<RevealAssignment>` 内部的 `Vec<RevealTokenData>` 等），在
/// nightly-2026-04-15 riscv32im-unknown-none-elf target 上触发 panic。
/// 手动覆盖 `deserialize(buf: &mut &[u8])` 避免泛型 `deserialize_reader<R>` 的
/// sret codegen 问题，并保持每个字段反序列化为独立函数调用。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct RevealTokenState {
    /// Reveal 阶段（REVEAL_PHASE_NONE/PREFLOP/REDEAL/FLOP/TURN/RIVER/SHOWDOWN）。
    pub reveal_phase: u8,
    /// 当前阶段的分配列表。
    pub assignments: Vec<RevealAssignment>,
}

impl BorshDeserialize for RevealTokenState {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, borsh::io::Error> {
        // 逐字段调用 deserialize，每个 <T>::deserialize(buf) 内部调用
        // <T>::deserialize_reader(&mut *buf)，对于派生类型这是独立函数调用（非 #[inline]）。
        Ok(Self {
            reveal_phase: <u8 as BorshDeserialize>::deserialize(buf)?,
            assignments: <Vec<RevealAssignment> as BorshDeserialize>::deserialize(buf)?,
        })
    }

    fn deserialize_reader<R: borsh::io::Read>(
        reader: &mut R,
    ) -> Result<Self, borsh::io::Error> {
        // 将所有剩余字节读入 Vec，再委托给 deserialize。
        // 这会消费 reader 中的全部字节——仅适用于 RevealTokenState 是输入中
        // 唯一字段的情况。嵌入它的复合类型（TexasPokerTable / ZkvmInput / ZkvmOutput）
        // 均已手动覆盖 deserialize，直接调用 RevealTokenState::deserialize。
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e),
            }
        }
        let mut slice: &[u8] = &buf;
        Self::deserialize(&mut slice)
    }
}

impl Default for RevealTokenState {
    fn default() -> Self {
        Self {
            reveal_phase: REVEAL_PHASE_NONE,
            assignments: Vec::new(),
        }
    }
}

// ========== Reconstruct 状态 ==========

/// 单个玩家提交的 reconstruct 输出。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReconstructPlayerDeck {
    /// 提交者 seat_index。
    pub seat_index: u8,
    /// 该玩家重建后的牌组（52 个 ElGamalCiphertext）。
    pub output_cts: Vec<ElGamalCiphertext>,
}

/// Reconstruct 状态。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReconstructState {
    /// Reconstruct 阶段（RECONSTRUCT_PHASE_NONE/COLLECTING/COMPLETE）。
    pub phase: u8,
    /// 待提交 reconstruct deck 的玩家列表。
    pub pending_players: Vec<u8>,
    /// 随机系数（None = 未设置）。
    pub coefficient: Option<ECScalar>,
    /// 所有玩家提交的重建牌组。
    pub player_decks: Vec<ReconstructPlayerDeck>,
}

impl Default for ReconstructState {
    fn default() -> Self {
        Self {
            phase: RECONSTRUCT_PHASE_NONE,
            pending_players: Vec::new(),
            coefficient: None,
            player_decks: Vec::new(),
        }
    }
}

// ========== 超时配置 ==========

/// 超时配置。
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

/// 时间戳集合。
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

/// 已解密牌。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DecryptedCard {
    /// 原始加密牌组中的索引。
    pub encrypted_card_index: u8,
    /// 牌主 seat_index（公共牌为 `OWNER_SEAT_PUBLIC` = 255）。
    pub owner_seat_index: u8,
    /// 部分解密密文（None = 已完全解密）。
    pub ciphertext: Option<ElGamalCiphertext>,
    /// 完全解密明文（None = 仅部分解密）。
    pub plaintext: Option<ECPoint>,
}

// ========== 牌组状态 ==========

/// 牌组状态。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeckState {
    /// 加密牌组（52 个 ElGamalCiphertext）。
    pub encrypted: Vec<ElGamalCiphertext>,
    /// 聚合公钥（None = 未初始化）。
    pub aggregated_pk: Option<ECPoint>,
    /// 52 张明文牌（G1 点，由合约生成）。
    pub plaintext: Vec<ECPoint>,
    /// 已从牌组发出的牌数量。
    pub cards_dealt: u8,
    /// 已解密的合法牌列表。
    pub decrypted_cards: Vec<DecryptedCard>,
}

impl Default for DeckState {
    fn default() -> Self {
        Self {
            encrypted: Vec::new(),
            aggregated_pk: None,
            plaintext: Vec::new(),
            cards_dealt: 0,
            decrypted_cards: Vec::new(),
        }
    }
}

// ========== 桌台配置 ==========

/// 桌台配置（控制 ZK skip 等行为，dev chain 友好）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TableConfig {
    /// 是否启用 ZK skip 模式（dev chain 友好；mainnet 强制 false）。
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

/// Texas Poker 桌台（核心状态对象）。
///
/// 注意：`BorshDeserialize` 为**手动实现**（非 derive），与 `RevealTokenState` 同理。
/// 派生宏会将全部 22 个字段的 `deserialize_reader` 深度内联为单体函数，在
/// nightly-2026-04-15 riscv32im-unknown-none-elf target 上触发 panic。
/// 手动实现通过函数指针强制分离每个字段的反序列化调用边界。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct TexasPokerTable {
    /// 桌台 ObjectID（32 字节）。
    pub id: ObjectID,
    /// 桌台名称。
    pub name: String,
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

    /// 玩家存入资金池。
    pub chip_pool: u64,

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
            max_players,
            small_blind,
            big_blind,
            seats,
            button: 0,
            pot: 0,
            side_pots: Vec::new(),
            community_cards: Vec::new(),
            round_state: ROUND_WAITING,
            betting_round: None,
            current_turn: None,
            deck_state: DeckState::default(),
            shuffle_state: ShuffleState::default(),
            reveal_token_state: RevealTokenState::default(),
            reconstruct_state: ReconstructState::default(),
            timeout_config: TimeoutConfig::default(),
            timestamps: Timestamps::default(),
            chip_pool: 0,
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

    /// Out-param 反序列化（避免 RV32I sret codegen bug）。
    ///
    /// 与 `BorshDeserialize::deserialize` 功能等价，但返回 `Result<(), Error>`
    /// （1 字节 discriminant，无 sret），通过 `&mut self` 写入字段。
    ///
    /// `BorshDeserialize::deserialize` 返回 `Result<TexasPokerTable, Error>`
    /// （~500 字节 sret），在 nightly-2026-04-15 riscv32im-unknown-none-elf 上触发
    /// `uninitialized read at 0x00000004`（sret 指针被错误设为 NULL）。
    ///
    /// **field 16 (reveal_token_state) 内联**：不调用 `<RevealTokenState>::deserialize`，
    /// 直接读取 `u8 + Vec`，避免 `Result<RevealTokenState, Error>` sret 触发
    /// `unaligned access at 0x00000001`。
    ///
    /// 诊断历史：
    /// - M6（22 字段逐个调用放在 zkvm_main_logic 中）→ 成功
    /// - L2（调用 TexasPokerTable::deserialize 作为函数）→ 失败（sret bug）
    /// - 本方法将 22 字段调用移入返回 `Result<(), Error>` 的函数 → 无 sret
    pub fn deserialize_into(&mut self, buf: &mut &[u8]) -> Result<(), borsh::io::Error> {
        self.id = <ObjectID as BorshDeserialize>::deserialize(buf)?;
        self.name = <String as BorshDeserialize>::deserialize(buf)?;
        self.max_players = <u8 as BorshDeserialize>::deserialize(buf)?;
        self.small_blind = <u64 as BorshDeserialize>::deserialize(buf)?;
        self.big_blind = <u64 as BorshDeserialize>::deserialize(buf)?;
        self.seats = <Vec<Seat> as BorshDeserialize>::deserialize(buf)?;
        self.button = <u8 as BorshDeserialize>::deserialize(buf)?;
        self.pot = <u64 as BorshDeserialize>::deserialize(buf)?;
        self.side_pots = <Vec<SidePot> as BorshDeserialize>::deserialize(buf)?;
        self.community_cards = <Vec<Card> as BorshDeserialize>::deserialize(buf)?;
        self.round_state = <u8 as BorshDeserialize>::deserialize(buf)?;
        self.betting_round = <Option<BettingRound> as BorshDeserialize>::deserialize(buf)?;
        self.current_turn = <Option<u8> as BorshDeserialize>::deserialize(buf)?;
        self.deck_state = <DeckState as BorshDeserialize>::deserialize(buf)?;
        self.shuffle_state = <ShuffleState as BorshDeserialize>::deserialize(buf)?;
        // field 16: reveal_token_state 内联（不调用 <RevealTokenState>::deserialize）
        self.reveal_token_state.reveal_phase =
            <u8 as BorshDeserialize>::deserialize(buf)?;
        self.reveal_token_state.assignments =
            <Vec<RevealAssignment> as BorshDeserialize>::deserialize(buf)?;
        self.reconstruct_state = <ReconstructState as BorshDeserialize>::deserialize(buf)?;
        self.timeout_config = <TimeoutConfig as BorshDeserialize>::deserialize(buf)?;
        self.timestamps = <Timestamps as BorshDeserialize>::deserialize(buf)?;
        self.chip_pool = <u64 as BorshDeserialize>::deserialize(buf)?;
        self.config = <TableConfig as BorshDeserialize>::deserialize(buf)?;
        self.version = <u64 as BorshDeserialize>::deserialize(buf)?;
        Ok(())
    }
}

impl Default for TexasPokerTable {
    fn default() -> Self {
        // 最小有效占位（deserialize_into 会覆写所有字段）
        Self::new([0u8; 32], String::new(), 2, 1, 2)
    }
}

// ========== TexasPokerTable 手动 BorshDeserialize ==========

/// 手动 `BorshDeserialize` for `TexasPokerTable`。
///
/// **策略**：覆盖 `deserialize(buf: &mut &[u8])` 而非 `deserialize_reader<R: Read>`。
/// `deserialize` 接收 `&mut &[u8]`（具体类型，非泛型），直接调用每个字段的
/// `deserialize(buf)`。这避免了泛型 `deserialize_reader<R>` 在 RV32I 上的 sret
/// codegen 问题（之前尝试 `#[inline(never)]` 泛型辅助函数和 `black_box` 函数指针
/// 均触发 `uninitialized read` 或 `unaligned access`）。
///
/// 每个字段的 `deserialize(buf)` 默认实现调用 `deserialize_reader(&mut *buf)`，
/// 对于派生类型（DeckState 等），`deserialize_reader` 是独立函数（非 `#[inline]`），
/// 不会被内联到 `TexasPokerTable::deserialize` 中，因此函数体保持小尺寸。
impl BorshDeserialize for TexasPokerTable {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, borsh::io::Error> {
        // 逐字段调用 deserialize。每个 <T>::deserialize(buf) 内部调用
        // <T>::deserialize_reader(&mut *buf)，对于派生类型这是一个独立函数调用。
        //
        // **重要**：`reveal_token_state` 字段**内联**读取（u8 + Vec 直接 deserialize），
        // 而非调用 <RevealTokenState>::deserialize(buf)。原因：RV32I codegen bug —
        // 调用返回 Result<RevealTokenState, Error>（sret，~20 字节）的函数时，
        // sret 指针被错误设为 NULL，导致 unaligned access at 0x00000001。
        // 直接读取 u8（无 sret）和 Vec（sret 但工作正常）可避免此问题。
        // 诊断历史：M3（调用 RevealTokenState::deserialize）→ unaligned access 0x01；
        //           M5/M6（内联 field 16）→ 成功。
        Ok(Self {
            id: <ObjectID as BorshDeserialize>::deserialize(buf)?,
            name: <String as BorshDeserialize>::deserialize(buf)?,
            max_players: <u8 as BorshDeserialize>::deserialize(buf)?,
            small_blind: <u64 as BorshDeserialize>::deserialize(buf)?,
            big_blind: <u64 as BorshDeserialize>::deserialize(buf)?,
            seats: <Vec<Seat> as BorshDeserialize>::deserialize(buf)?,
            button: <u8 as BorshDeserialize>::deserialize(buf)?,
            pot: <u64 as BorshDeserialize>::deserialize(buf)?,
            side_pots: <Vec<SidePot> as BorshDeserialize>::deserialize(buf)?,
            community_cards: <Vec<Card> as BorshDeserialize>::deserialize(buf)?,
            round_state: <u8 as BorshDeserialize>::deserialize(buf)?,
            betting_round: <Option<BettingRound> as BorshDeserialize>::deserialize(buf)?,
            current_turn: <Option<u8> as BorshDeserialize>::deserialize(buf)?,
            deck_state: <DeckState as BorshDeserialize>::deserialize(buf)?,
            shuffle_state: <ShuffleState as BorshDeserialize>::deserialize(buf)?,
            reveal_token_state: RevealTokenState {
                reveal_phase: <u8 as BorshDeserialize>::deserialize(buf)?,
                assignments: <Vec<RevealAssignment> as BorshDeserialize>::deserialize(buf)?,
            },
            reconstruct_state: <ReconstructState as BorshDeserialize>::deserialize(buf)?,
            timeout_config: <TimeoutConfig as BorshDeserialize>::deserialize(buf)?,
            timestamps: <Timestamps as BorshDeserialize>::deserialize(buf)?,
            chip_pool: <u64 as BorshDeserialize>::deserialize(buf)?,
            config: <TableConfig as BorshDeserialize>::deserialize(buf)?,
            version: <u64 as BorshDeserialize>::deserialize(buf)?,
        })
    }

    fn deserialize_reader<R: borsh::io::Read>(
        reader: &mut R,
    ) -> Result<Self, borsh::io::Error> {
        // 将所有剩余字节读入 Vec，再委托给 deserialize。
        // 这会消费 reader 中的全部字节，因此仅适用于 TexasPokerTable 是输入中
        // 唯一字段的情况。对于嵌入 TexasPokerTable 的复合类型（ZkvmInput/ZkvmOutput），
        // 它们的 deserialize 也被手动覆盖，直接调用 TexasPokerTable::deserialize。
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e),
            }
        }
        let mut slice: &[u8] = &buf;
        Self::deserialize(&mut slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_table_id() -> ObjectID {
        [0xFF; 32]
    }

    #[test]
    fn test_table_new() {
        let table = TexasPokerTable::new(dummy_table_id(), "test".into(), 6, 50, 100);
        assert_eq!(table.max_players, 6);
        assert_eq!(table.seats.len(), 6);
        assert_eq!(table.small_blind, 50);
        assert_eq!(table.big_blind, 100);
        assert_eq!(table.round_state, crate::constants::ROUND_WAITING);
        assert_eq!(table.active_count(), 0);
        assert_eq!(table.occupied_count(), 0);
    }

    #[test]
    fn test_table_new_invalid_params() {
        // max_players < 2
        let result = std::panic::catch_unwind(|| {
            TexasPokerTable::new(dummy_table_id(), "x".into(), 1, 50, 100);
        });
        assert!(result.is_err());

        // max_players > 9
        let result = std::panic::catch_unwind(|| {
            TexasPokerTable::new(dummy_table_id(), "x".into(), 10, 50, 100);
        });
        assert!(result.is_err());

        // big_blind = 0
        let result = std::panic::catch_unwind(|| {
            TexasPokerTable::new(dummy_table_id(), "x".into(), 6, 50, 0);
        });
        assert!(result.is_err());

        // small_blind > big_blind
        let result = std::panic::catch_unwind(|| {
            TexasPokerTable::new(dummy_table_id(), "x".into(), 6, 200, 100);
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
        let mut table = TexasPokerTable::new(dummy_table_id(), "t".into(), 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[2].player = [0x02; 20];

        assert_eq!(table.find_seat(&[0x01; 20]), Some(0));
        assert_eq!(table.find_seat(&[0x02; 20]), Some(2));
        assert_eq!(table.find_seat(&[0x03; 20]), None);
    }

    #[test]
    fn test_table_find_empty_seat() {
        let mut table = TexasPokerTable::new(dummy_table_id(), "t".into(), 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[1].player = [0x02; 20];

        assert_eq!(table.find_empty_seat(), Some(2));
    }

    #[test]
    fn test_table_active_count() {
        let mut table = TexasPokerTable::new(dummy_table_id(), "t".into(), 4, 50, 100);
        table.seats[0].player = [0x01; 20];
        table.seats[1].player = [0x02; 20];
        table.seats[2].player = [0x03; 20];
        assert_eq!(table.active_count(), 3);

        table.seats[1].folded = true;
        assert_eq!(table.active_count(), 2);
    }

    #[test]
    fn test_table_borsh_roundtrip() {
        let mut table = TexasPokerTable::new(dummy_table_id(), "test-table".into(), 4, 50, 100);
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
        let mut table = TexasPokerTable::new(dummy_table_id(), "t".into(), 4, 50, 100);
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
            pk: G1Point([0u8; 48]),
            refunded: false,
        };
        let bytes = borsh::to_vec(&seat).unwrap();
        let recovered: Seat = borsh::from_slice(&bytes).unwrap();
        assert_eq!(seat, recovered);
    }
}
