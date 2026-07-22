//! Texas Poker 合约 dispatch 路由（17 method selector）— guest 移植。
//!
//! 严格对齐 `texas_poker_move/sources/table.move` 的 public entry function 清单：
//! - 表台生命周期：create_table / join_table / leave_table / start_hand / tick
//! - 玩家动作：fold / check / call / raise / auto_fold / force_fold / kick_player
//! - Mental Poker 协议：join_and_shuffle / leave_with_proof / submit_shuffle_v2
//!   / submit_player_reveal_tokens / submit_reconstruct_deck
//!
//! # Selector 计算
//!
//! `blake2b_256(method_name)[0..32]`，使用 guest 内置纯 Rust blake2b 实现
//!（不经 syscall），使 selector 计算在 riscv32 ELF 与 host std-test 均可用。
//!
//! # Args 编码
//!
//! 每个 method 对应一个 `*Args` 结构体，使用 **borsh** 序列化。
//! 密码学字段：pk/ciphertexts 为 typed `G1Point`/`ElGamalCiphertext`，
//! proofs 为 `Vec<u8>`（Borsh 序列化的 proof bytes，由 host syscall 验证）。
//!
//! # 移植变更
//!
//! - `PokerL1Error` → `DispatchError`（包裹 `StateMachineError`）
//! - `DispatchContext` 简化（移除 `TaggedPubkey`，guest 无签名验证）
//! - `DispatchResult` 简化（`modified_objects` + `events`，Phase 4.4 起返回 events）
//! - proof 字段全部改为 `Vec<u8>`（与 state_machine 一致）
//! - `ECPoint` → `G1Point`（类型别名，Borsh 布局一致）
//! - `log_events` / `tracing::debug!` 移除（no_std 无 tracing）

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

use zkvm_guest_sdk::bls::{ElGamalCiphertext, G1Point};

use super::blake2b;
use super::betting::BettingError;

use super::constants::{FOLD_REASON_AUTO_TIMEOUT, FOLD_REASON_FORCE_ADMIN, KICK_REASON_ADMIN};
use super::events::{self, TexasPokerEvent};
use super::state_machine::{self, StateMachineError};
use super::types::{Address, ObjectID, Seat, TexasPokerTable};

// ========== DispatchContext / DispatchResult ==========

/// 执行上下文（简化版，无 TaggedPubkey）。
///
/// Borsh 布局：`caller(20) + chain_id(8) + block_height(8) + block_timestamp(8)` = 44 字节。
#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct DispatchContext {
    /// 调用者地址。
    pub caller: Address,
    /// 链 ID。
    pub chain_id: u64,
    /// 当前区块高度。
    pub block_height: u64,
    /// 当前区块时间戳（毫秒）。
    pub block_timestamp: u64,
}

/// dispatch 结果（记录被修改的 object IDs + 收集的事件）。
#[derive(Debug, Clone)]
pub struct DispatchResult {
    /// 被修改的 object ID 列表。
    pub modified_objects: Vec<ObjectID>,
    /// 本次 dispatch 收集的所有事件（供 host 索引/emit）。
    pub events: Vec<TexasPokerEvent>,
}

// ========== DispatchError ==========

/// dispatch 错误类型（替代 `PokerL1Error`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// 序列化/反序列化或参数校验错误。
    Serialization(String),
    /// 未知方法选择器。
    UnknownMethod { selector: [u8; 32] },
    /// 状态机错误（转发 `StateMachineError`）。
    StateMachine(StateMachineError),
}

impl From<StateMachineError> for DispatchError {
    fn from(e: StateMachineError) -> Self {
        Self::StateMachine(e)
    }
}

impl From<BettingError> for DispatchError {
    fn from(e: BettingError) -> Self {
        Self::StateMachine(StateMachineError::Betting(e))
    }
}

// ========== RV32I sret workaround: Box<DispatchError> ==========

/// `Box<DispatchError>` 作为 dispatch_* 函数的返回错误类型。
///
/// # RV32I sret workaround
///
/// `Result<(), DispatchError>` 的大小 > 2×XLEN（RV32 = 8 字节），因为
/// `DispatchError` 包含 `String`（12B）+ `[u8; 32]`（32B）+ `StateMachineError`。
/// 这导致 `Result<(), DispatchError>` 通过 sret 返回，sret 指针占用 `a0`，
/// 覆盖 dispatch_* 函数的第一个参数（`table` / `context`），触发 sret codegen bug。
///
/// `Result<(), Box<DispatchError>>` = 8 字节（1B 判别 + 4B 指针 + 3B padding），
/// 恰好 2×XLEN，通过 a0+a1 返回，不使用 sret。
impl From<StateMachineError> for Box<DispatchError> {
    fn from(e: StateMachineError) -> Self {
        Box::new(DispatchError::StateMachine(e))
    }
}

impl From<BettingError> for Box<DispatchError> {
    fn from(e: BettingError) -> Self {
        Box::new(DispatchError::StateMachine(StateMachineError::Betting(e)))
    }
}

/// 解引用 `Box<DispatchError>` → `DispatchError`，供 `dispatch` 函数的 `?` 使用。
impl From<Box<DispatchError>> for DispatchError {
    fn from(e: Box<DispatchError>) -> Self {
        *e
    }
}

// ========== Selector 计算 ==========

/// 方法选择器长度（32 字节 = blake2b_256 输出）。
pub const METHOD_SELECTOR_LEN: usize = 32;

/// 计算方法选择器：`blake2b_256(method_name)[0..32]`。
///
/// `const fn` 使 selector 可在编译时计算为 `const` 常量，避免 RV32I 运行时
/// sret 调用（`blake2b_256` 返回 `[u8; 32]` = 32 字节 > 2×XLEN = 8 字节，
/// 通过 sret 返回，触发 RV32I sret codegen bug）。
#[must_use]
pub const fn compute_method_selector(method_name: &str) -> [u8; METHOD_SELECTOR_LEN] {
    blake2b::blake2b_256(method_name.as_bytes())
}

/// 18 个方法选择器常量。
///
/// 所有方法名使用 snake_case，与 Move 端 entry function 名一一对应。
///
/// # RV32I sret workaround
///
/// 所有 selector 在编译时计算为 `const` 常量。`dispatch` 的 `match` 使用
/// 这些常量比较，避免运行时调用 `blake2b_256`（sret bug）。
/// 函数包装器（`create_table()` 等）仅供 host 测试使用。
pub mod selectors {
    use alloc::vec::Vec;

    use super::compute_method_selector;

    /// `create_table` — 创建新桌台。
    pub const CREATE_TABLE: [u8; 32] = compute_method_selector("create_table");
    /// `join_and_shuffle` — 玩家加入并完成首洗牌（含 remask + shuffle proof）。
    pub const JOIN_AND_SHUFFLE: [u8; 32] = compute_method_selector("join_and_shuffle");
    /// `leave_with_proof` — 玩家带 proof 离场（保留手牌贡献）。
    pub const LEAVE_WITH_PROOF: [u8; 32] = compute_method_selector("leave_with_proof");
    /// `join_table` — 简单入座（不参与本局，等下一局）。
    pub const JOIN_TABLE: [u8; 32] = compute_method_selector("join_table");
    /// `leave_table` — 简单离座（仅在 WAITING 状态）。
    pub const LEAVE_TABLE: [u8; 32] = compute_method_selector("leave_table");
    /// `start_hand` — 开始新一局（投盲注 + 进入 shuffle 阶段）。
    pub const START_HAND: [u8; 32] = compute_method_selector("start_hand");
    /// `tick` — 超时驱动（permissionless）。
    pub const TICK: [u8; 32] = compute_method_selector("tick");
    /// `auto_fold` — 玩家超时自动 fold。
    pub const AUTO_FOLD: [u8; 32] = compute_method_selector("auto_fold");
    /// `force_fold` — 管理员强制 fold 玩家。
    pub const FORCE_FOLD: [u8; 32] = compute_method_selector("force_fold");
    /// `kick_player` — 踢出玩家（管理员操作）。
    pub const KICK_PLAYER: [u8; 32] = compute_method_selector("kick_player");
    /// `submit_shuffle_v2` — 玩家提交洗牌结果（第二手及以后）。
    pub const SUBMIT_SHUFFLE_V2: [u8; 32] = compute_method_selector("submit_shuffle_v2");
    /// `submit_player_reveal_tokens` — 提交揭牌令牌。
    pub const SUBMIT_PLAYER_REVEAL_TOKENS: [u8; 32] =
        compute_method_selector("submit_player_reveal_tokens");
    /// `submit_reconstruct_deck` — 提交重构牌组。
    pub const SUBMIT_RECONSTRUCT_DECK: [u8; 32] =
        compute_method_selector("submit_reconstruct_deck");
    /// `fold` — 玩家主动 fold。
    pub const FOLD: [u8; 32] = compute_method_selector("fold");
    /// `check` — 玩家过牌。
    pub const CHECK: [u8; 32] = compute_method_selector("check");
    /// `call` — 玩家跟注。
    pub const CALL: [u8; 32] = compute_method_selector("call");
    /// `raise` — 玩家加注。
    pub const RAISE: [u8; 32] = compute_method_selector("raise");
    /// `reset_for_next_hand` — 显式重置桌台到 WAITING（管理员/测试场景）。
    pub const RESET_FOR_NEXT_HAND: [u8; 32] = compute_method_selector("reset_for_next_hand");

    // ===== 函数包装器（仅供 host std-test 使用，guest match 不调用）=====

    /// `create_table` selector（host 测试用）。
    #[must_use]
    pub fn create_table() -> [u8; 32] {
        CREATE_TABLE
    }
    /// `join_and_shuffle` selector（host 测试用）。
    #[must_use]
    pub fn join_and_shuffle() -> [u8; 32] {
        JOIN_AND_SHUFFLE
    }
    /// `leave_with_proof` selector（host 测试用）。
    #[must_use]
    pub fn leave_with_proof() -> [u8; 32] {
        LEAVE_WITH_PROOF
    }
    /// `join_table` selector（host 测试用）。
    #[must_use]
    pub fn join_table() -> [u8; 32] {
        JOIN_TABLE
    }
    /// `leave_table` selector（host 测试用）。
    #[must_use]
    pub fn leave_table() -> [u8; 32] {
        LEAVE_TABLE
    }
    /// `start_hand` selector（host 测试用）。
    #[must_use]
    pub fn start_hand() -> [u8; 32] {
        START_HAND
    }
    /// `tick` selector（host 测试用）。
    #[must_use]
    pub fn tick() -> [u8; 32] {
        TICK
    }
    /// `auto_fold` selector（host 测试用）。
    #[must_use]
    pub fn auto_fold() -> [u8; 32] {
        AUTO_FOLD
    }
    /// `force_fold` selector（host 测试用）。
    #[must_use]
    pub fn force_fold() -> [u8; 32] {
        FORCE_FOLD
    }
    /// `kick_player` selector（host 测试用）。
    #[must_use]
    pub fn kick_player() -> [u8; 32] {
        KICK_PLAYER
    }
    /// `submit_shuffle_v2` selector（host 测试用）。
    #[must_use]
    pub fn submit_shuffle_v2() -> [u8; 32] {
        SUBMIT_SHUFFLE_V2
    }
    /// `submit_player_reveal_tokens` selector（host 测试用）。
    #[must_use]
    pub fn submit_player_reveal_tokens() -> [u8; 32] {
        SUBMIT_PLAYER_REVEAL_TOKENS
    }
    /// `submit_reconstruct_deck` selector（host 测试用）。
    #[must_use]
    pub fn submit_reconstruct_deck() -> [u8; 32] {
        SUBMIT_RECONSTRUCT_DECK
    }
    /// `fold` selector（host 测试用）。
    #[must_use]
    pub fn fold() -> [u8; 32] {
        FOLD
    }
    /// `check` selector（host 测试用）。
    #[must_use]
    pub fn check() -> [u8; 32] {
        CHECK
    }
    /// `call` selector（host 测试用）。
    #[must_use]
    pub fn call() -> [u8; 32] {
        CALL
    }
    /// `raise` selector（host 测试用）。
    #[must_use]
    pub fn raise() -> [u8; 32] {
        RAISE
    }
    /// `reset_for_next_hand` selector（host 测试用）。
    #[must_use]
    pub fn reset_for_next_hand() -> [u8; 32] {
        RESET_FOR_NEXT_HAND
    }

    /// 返回所有 18 个 selector。
    #[must_use]
    pub fn all() -> Vec<[u8; 32]> {
        vec![
            CREATE_TABLE,
            JOIN_AND_SHUFFLE,
            LEAVE_WITH_PROOF,
            JOIN_TABLE,
            LEAVE_TABLE,
            START_HAND,
            TICK,
            AUTO_FOLD,
            FORCE_FOLD,
            KICK_PLAYER,
            SUBMIT_SHUFFLE_V2,
            SUBMIT_PLAYER_REVEAL_TOKENS,
            SUBMIT_RECONSTRUCT_DECK,
            FOLD,
            CHECK,
            CALL,
            RAISE,
            RESET_FOR_NEXT_HAND,
        ]
    }
}

// ========== Args 结构体（borsh 序列化 + typed 密码学字段） ==========

/// `create_table` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct CreateTableArgs {
    /// 桌台名称。
    pub name: String,
    /// 最大玩家数（2..=9）。
    pub max_players: u8,
    /// 小盲注金额。
    pub small_blind: u64,
    /// 大盲注金额。
    pub big_blind: u64,
}

/// `join_and_shuffle` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct JoinAndShuffleArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 玩家地址。
    pub player: Address,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家 ElGamal 公钥（G1 点）。
    pub pk: G1Point,
    /// pk 所有权证明（80 字节 Schnorr 自定义格式，保留 Vec<u8>）。
    pub pk_ownership_proof: Vec<u8>,
    /// remask 后的牌组掩码（typed ElGamalCiphertext 列表）。
    pub mask_cards: Vec<ElGamalCiphertext>,
    /// shuffle 输出牌组（typed ElGamalCiphertext 列表）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// remask proof（Borsh 序列化 bytes，由 host syscall 验证）。
    pub remask_proof: Vec<u8>,
    /// shuffle proof（Borsh 序列化 bytes，由 host syscall 验证）。
    pub shuffle_proof: Vec<u8>,
}

/// `leave_with_proof` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct LeaveWithProofArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 离场时的牌组输出（typed ElGamalCiphertext 列表，用于验证贡献连续性）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// leave proof（Borsh 序列化 bytes，由 host syscall 验证）。
    pub leave_proof: Vec<u8>,
}

/// `join_table` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct JoinTableArgs {
    /// 玩家地址。
    pub player: Address,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家 ElGamal 公钥（G1 点）。
    pub pk: G1Point,
}

/// `leave_table` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct LeaveTableArgs {
    /// 座位索引。
    pub seat_index: u8,
}

/// `tick` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TickArgs {
    /// 当前时间戳（毫秒）。
    pub now_ms: u64,
}

/// `auto_fold` / `force_fold` / `fold` / `check` / `call` 参数（仅 seat_index）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SeatIndexArgs {
    /// 座位索引。
    pub seat_index: u8,
}

/// `kick_player` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct KickPlayerArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 踢出原因（KICK_REASON_*）。
    pub reason: u8,
}

/// `submit_shuffle_v2` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitShuffleV2Args {
    /// 座位索引。
    pub seat_index: u8,
    /// shuffle 输出牌组（typed ElGamalCiphertext 列表）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// shuffle proof（Borsh 序列化 bytes，由 host syscall 验证）。
    pub shuffle_proof: Vec<u8>,
}

/// `submit_player_reveal_tokens` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitRevealTokensArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 揭牌分配索引列表（每张待揭示牌在 deck 中的位置）。
    pub assignment_indices: Vec<u8>,
    /// 揭牌令牌列表（typed G1Point）。
    pub reveal_tokens: Vec<G1Point>,
    /// 揭牌 proof 列表（Borsh 序列化 bytes，与 reveal_tokens 一一对应）。
    pub proofs: Vec<Vec<u8>>,
}

/// `submit_reconstruct_deck` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitReconstructDeckArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 重构输出牌组（typed ElGamalCiphertext 列表）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// swap 牌组（typed ElGamalCiphertext 列表，暂时未用，保留）。
    pub swap_cards: Vec<ElGamalCiphertext>,
    /// user_readable 牌组（typed ElGamalCiphertext 列表，暂时未用，保留）。
    pub user_readable_cards: Vec<ElGamalCiphertext>,
    /// reconstruct proof（Borsh 序列化 bytes，由 host syscall 验证）。
    pub proof: Vec<u8>,
}

/// `raise` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RaiseArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 加注后该玩家本轮总下注额（不是加注增量）。
    pub total_bet: u64,
}

// ========== Dispatch 路由入口 ==========

/// Dispatch 路由入口。
///
/// 将 selector 路由到对应的 Texas Poker 合约方法。
///
/// # 参数
/// - `context`：执行上下文（调用者、block 信息等）
/// - `table`：可变的 `TexasPokerTable` 引用（状态变更目标）
/// - `selector`：方法选择器（32 字节）
/// - `args`：调用参数（borsh 编码）
/// - `events`：事件收集器（调用方创建，dispatch_* 内部追加事件）
///
/// # 返回
/// `Result<(), Box<DispatchError>>` — 8 字节，**不使用 sret**，避免 RV32I codegen bug。
///
/// # RV32I sret workaround
///
/// 原 `Result<DispatchResult, DispatchError>` 返回值 > 2×XLEN → sret 指针占用 `a0`，
/// 导致参数位移 + codegen bug。改为 out-parameter 模式：`events` 由调用方传入，
/// `modified_objects` 由调用方从 `table.id` 构造（恒为 `vec![table.id]`）。
pub fn dispatch(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    selector: &[u8; 32],
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    match selector {
        s if s == &selectors::CREATE_TABLE => dispatch_create_table(table, args, events),
        s if s == &selectors::JOIN_AND_SHUFFLE => {
            dispatch_join_and_shuffle(context, table, args, events)
        }
        s if s == &selectors::LEAVE_WITH_PROOF => dispatch_leave_with_proof(table, args, events),
        s if s == &selectors::JOIN_TABLE => dispatch_join_table(context, table, args, events),
        s if s == &selectors::LEAVE_TABLE => dispatch_leave_table(table, args, events),
        s if s == &selectors::START_HAND => dispatch_start_hand(table, args, events),
        s if s == &selectors::TICK => dispatch_tick(table, args, events),
        s if s == &selectors::AUTO_FOLD => dispatch_auto_fold(table, args, events),
        s if s == &selectors::FORCE_FOLD => dispatch_force_fold(table, args, events),
        s if s == &selectors::KICK_PLAYER => dispatch_kick_player(table, args, events),
        s if s == &selectors::SUBMIT_SHUFFLE_V2 => dispatch_submit_shuffle_v2(table, args, events),
        s if s == &selectors::SUBMIT_PLAYER_REVEAL_TOKENS => {
            dispatch_submit_player_reveal_tokens(table, args, events)
        }
        s if s == &selectors::SUBMIT_RECONSTRUCT_DECK => {
            dispatch_submit_reconstruct_deck(table, args, events)
        }
        s if s == &selectors::FOLD => dispatch_fold(table, args, events),
        s if s == &selectors::CHECK => dispatch_check(table, args, events),
        s if s == &selectors::CALL => dispatch_call(table, args, events),
        s if s == &selectors::RAISE => dispatch_raise(table, args, events),
        s if s == &selectors::RESET_FOR_NEXT_HAND => {
            dispatch_reset_for_next_hand(table, args, events)
        }
        _ => Err(Box::new(DispatchError::UnknownMethod { selector: *selector })),
    }
}

/// borsh 反序列化辅助。
///
/// 返回 `Result<T, Box<DispatchError>>`：错误通过 `Box` 装箱，
/// 使 `dispatch_*` 函数的返回类型 `Result<(), Box<DispatchError>>` = 8 字节，
/// 避免 RV32I sret codegen bug。
fn decode_args<T: BorshDeserialize>(args: &[u8], method: &str) -> Result<T, Box<DispatchError>> {
    borsh::from_slice(args)
        .map_err(|e| Box::new(DispatchError::Serialization(format!("{method} args borsh: {e}"))))
}

// ========== 18 个 dispatch_* 子函数 ==========

/// `create_table` — 初始化桌台（覆写默认空桌台）。
fn dispatch_create_table(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: CreateTableArgs = decode_args(args, "create_table")?;
    if !(2..=9).contains(&input.max_players) {
        return Err(Box::new(DispatchError::Serialization(format!(
            "max_players {} out of range [2, 9]",
            input.max_players
        ))));
    }
    if input.big_blind == 0 {
        return Err(Box::new(DispatchError::Serialization(
            "big_blind must > 0".into(),
        )));
    }
    if input.small_blind > input.big_blind {
        return Err(Box::new(DispatchError::Serialization(
            "small_blind must <= big_blind".into(),
        )));
    }
    let id = table.id;
    let name = input.name.clone();
    // 保留旧 version（跨覆写）：stateless ZK 模型下，host 持久化 table，
    // 每次 create_table 应视为对同一桌台对象的 mutation，version 应递增而非重置。
    // 否则第二次 create_table 后 version 仍为 1，破坏乐观锁不变量。
    let prev_version = table.version;
    // RV32I sret workaround: 不能用 `*table = TexasPokerTable::new(...)`，
    // 因为 sret 指针会使用 `a0`（table 指针），导致 LLVM 不保存 table 指针，
    // 后续 `table.bump_version()` 访问被覆盖的指针 → uninitialized read。
    // 改为先在局部变量上构造（sret 指针指向栈局部变量，编译器必须保存 table
    // 指针供后续赋值使用），再整体赋值。
    let new_table = TexasPokerTable::new(
        id,
        input.name,
        input.max_players,
        input.small_blind,
        input.big_blind,
    );
    *table = new_table;
    // 恢复旧 version，再 bump：使 create_table 与其他 mutation 一致地 +1。
    // 首次 create_table（prev_version=0）→ 1；后续 → 2, 3, ...
    table.version = prev_version;
    table.bump_version();
    // ZKVM guest 中 dispatch 是最顶层入口（无 Move 层 emit），此处自行 emit TableCreated。
    // 源 poker_l1 在 Move 合约层 emit，dispatch helper 不 emit；guest 移植合并了二者。
    events.push(TexasPokerEvent::TableCreated { table_id: id, name });
    Ok(())
}

/// `join_and_shuffle` — 玩家加入并完成首洗牌。
fn dispatch_join_and_shuffle(
    _context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: JoinAndShuffleArgs = decode_args(args, "join_and_shuffle")?;
    state_machine::apply_join_and_shuffle(
        table,
        input.seat_index,
        input.player,
        input.buy_in,
        input.pk,
        input.pk_ownership_proof,
        input.mask_cards,
        input.output_cards,
        input.remask_proof,
        input.shuffle_proof,
        events,
    )?;
    Ok(())
}

/// `leave_with_proof` — 带 proof 离场。
fn dispatch_leave_with_proof(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: LeaveWithProofArgs = decode_args(args, "leave_with_proof")?;
    state_machine::apply_leave_with_proof(
        table,
        input.seat_index,
        input.output_cards,
        input.leave_proof,
        events,
    )?;
    Ok(())
}

/// `join_table` — 简单入座（不参与本局，标记 is_waiting=true）。
///
/// 仅在 WAITING 状态允许；占第一个空座位；玩家不能已在桌台。
fn dispatch_join_table(
    _context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: JoinTableArgs = decode_args(args, "join_table")?;
    if !state_machine::can_join_state(table) {
        return Err(Box::new(DispatchError::Serialization(
            "not in WAITING state, cannot join_table".into(),
        )));
    }
    if state_machine::is_pk_registered(&table.seats, &input.pk) {
        return Err(Box::new(DispatchError::Serialization(
            "pk already registered at this table".into(),
        )));
    }
    if input.buy_in < table.big_blind {
        return Err(Box::new(DispatchError::Serialization(format!(
            "buy_in {} < big_blind {}",
            input.buy_in, table.big_blind
        ))));
    }
    let seat_idx = table
        .find_empty_seat()
        .ok_or_else(|| Box::new(DispatchError::Serialization("no empty seat available".into())))?;
    let seat = &mut table.seats[seat_idx as usize];
    seat.player = input.player;
    seat.stack = input.buy_in;
    seat.pk = input.pk;
    seat.is_waiting = false;
    seat.folded = false;
    seat.left_during_hand = false;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.bet = 0;
    seat.total_bet = 0;
    seat.hand.clear();

    let active_count_after = (state_machine::count_active_occupied(&table.seats) as u64) + 1;
    events.push(TexasPokerEvent::PlayerJoined {
        table_id: table.id,
        seat_index: seat_idx,
        player: input.player,
        buy_in: input.buy_in,
        is_waiting: false,
        active_count_after,
    });
    table.bump_version();
    Ok(())
}

/// `leave_table` — 简单离座（仅 WAITING 状态）。
fn dispatch_leave_table(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: LeaveTableArgs = decode_args(args, "leave_table")?;
    if !state_machine::can_leave_state(table) {
        return Err(Box::new(DispatchError::Serialization(
            "not in WAITING state, cannot leave_table".into(),
        )));
    }
    if input.seat_index >= table.max_players {
        return Err(Box::new(DispatchError::Serialization(format!(
            "seat_index {} out of range",
            input.seat_index
        ))));
    }
    let seat = &mut table.seats[input.seat_index as usize];
    if !seat.is_occupied() {
        return Err(Box::new(DispatchError::Serialization(
            "seat not occupied, cannot leave".into(),
        )));
    }
    let refund_amt = seat.stack;
    let player = seat.player;
    *seat = Seat::empty();

    if refund_amt > 0 {
        events.push(TexasPokerEvent::PlayerRefund {
            table_id: table.id,
            seat_index: input.seat_index,
            player,
            amount: refund_amt,
            refund_type: super::constants::REFUND_TYPE_STACK_ONLY,
        });
    }
    events.push(TexasPokerEvent::PlayerLeft {
        table_id: table.id,
        seat_index: input.seat_index,
        player,
    });
    table.bump_version();
    Ok(())
}

/// `start_hand` — 开始新一局。
fn dispatch_start_hand(
    table: &mut TexasPokerTable,
    _args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    state_machine::start_hand(table, events)?;
    Ok(())
}

/// `tick` — 超时驱动。
fn dispatch_tick(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    // 允许空 args（兼容无参调用）；非空则解析为 TickArgs
    let now_ms = if args.is_empty() {
        0u64
    } else {
        decode_args::<TickArgs>(args, "tick")?.now_ms
    };
    state_machine::tick(table, now_ms, events)?;
    Ok(())
}

/// `auto_fold` — 玩家超时自动 fold。
fn dispatch_auto_fold(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: SeatIndexArgs = decode_args(args, "auto_fold")?;
    state_machine::apply_fold_internal(table, input.seat_index, FOLD_REASON_AUTO_TIMEOUT, events)?;
    Ok(())
}

/// `force_fold` — 管理员强制 fold。
fn dispatch_force_fold(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: SeatIndexArgs = decode_args(args, "force_fold")?;
    state_machine::apply_fold_internal(table, input.seat_index, FOLD_REASON_FORCE_ADMIN, events)?;
    Ok(())
}

/// `kick_player` — 踢出玩家。
fn dispatch_kick_player(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: KickPlayerArgs = decode_args(args, "kick_player")?;
    let reason = if input.reason == 0 {
        KICK_REASON_ADMIN
    } else {
        input.reason
    };
    state_machine::kick_player_internal(table, input.seat_index, reason, events);
    table.bump_version();
    Ok(())
}

/// `submit_shuffle_v2` — 提交洗牌结果。
fn dispatch_submit_shuffle_v2(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: SubmitShuffleV2Args = decode_args(args, "submit_shuffle_v2")?;
    state_machine::apply_submit_shuffle_v2(
        table,
        input.seat_index,
        input.output_cards,
        input.shuffle_proof,
        events,
    )?;
    Ok(())
}

/// `submit_player_reveal_tokens` — 提交揭牌令牌。
fn dispatch_submit_player_reveal_tokens(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: SubmitRevealTokensArgs = decode_args(args, "submit_player_reveal_tokens")?;
    state_machine::apply_submit_player_reveal_tokens(
        table,
        input.seat_index,
        input.assignment_indices,
        input.reveal_tokens,
        input.proofs,
        events,
    )?;
    Ok(())
}

/// `submit_reconstruct_deck` — 提交重构牌组。
fn dispatch_submit_reconstruct_deck(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: SubmitReconstructDeckArgs = decode_args(args, "submit_reconstruct_deck")?;
    state_machine::apply_submit_reconstruct_deck(
        table,
        input.seat_index,
        input.output_cards,
        input.swap_cards,
        input.user_readable_cards,
        input.proof,
        events,
    )?;
    Ok(())
}

/// `fold` — 玩家主动 fold。
fn dispatch_fold(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: SeatIndexArgs = decode_args(args, "fold")?;
    state_machine::apply_fold(table, input.seat_index, events)?;
    Ok(())
}

/// `check` — 玩家过牌。
fn dispatch_check(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: SeatIndexArgs = decode_args(args, "check")?;
    state_machine::apply_check(table, input.seat_index, events)?;
    Ok(())
}

/// `call` — 玩家跟注。
fn dispatch_call(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: SeatIndexArgs = decode_args(args, "call")?;
    state_machine::apply_call(table, input.seat_index, events)?;
    Ok(())
}

/// `raise` — 玩家加注。
fn dispatch_raise(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    let input: RaiseArgs = decode_args(args, "raise")?;
    state_machine::apply_raise(table, input.seat_index, input.total_bet, events)?;
    Ok(())
}

/// `reset_for_next_hand` — 显式重置桌台到 WAITING 状态。
fn dispatch_reset_for_next_hand(
    table: &mut TexasPokerTable,
    _args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> Result<(), Box<DispatchError>> {
    state_machine::reset_for_next_hand(table, events)?;
    Ok(())
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::constants::ROUND_WAITING;
    use super::super::utils::{g1_generator, g1_identity};

    fn dummy_id() -> ObjectID {
        [0xFF; 32]
    }

    fn make_table() -> TexasPokerTable {
        TexasPokerTable::new(dummy_id(), "test".into(), 6, 50, 100)
    }

    fn make_context() -> DispatchContext {
        DispatchContext {
            caller: [0xAA; 20],
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
    }

    #[test]
    fn selector_deterministic() {
        let h1 = selectors::create_table();
        let h2 = compute_method_selector("create_table");
        assert_eq!(h1, h2);
    }

    #[test]
    fn all_selectors_unique() {
        let sels = selectors::all();
        assert_eq!(sels.len(), 18, "应有 18 个 selector");
        for i in 0..sels.len() {
            for j in (i + 1)..sels.len() {
                assert_ne!(sels[i], sels[j], "selector[{i}] == selector[{j}] 不应相等");
            }
        }
    }

    #[test]
    fn dispatch_unknown_method_returns_error() {
        let ctx = make_context();
        let mut table = make_table();
        let unknown = [0xFE; 32];
        let mut events = Vec::new();
        let result = dispatch(&ctx, &mut table, &unknown, &[], &mut events);
        assert!(matches!(result, Err(ref b) if matches!(**b, DispatchError::UnknownMethod { .. })));
    }

    #[test]
    fn dispatch_create_table_initializes() {
        let ctx = make_context();
        let mut table = make_table();
        // 把 table 改成非初始状态，验证 create_table 会覆写
        table.pot = 999;

        let args = CreateTableArgs {
            name: "new_game".into(),
            max_players: 9,
            small_blind: 25,
            big_blind: 50,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes, &mut events)
            .expect("create_table 应成功");

        assert_eq!(table.name, "new_game");
        assert_eq!(table.max_players, 9);
        assert_eq!(table.small_blind, 25);
        assert_eq!(table.big_blind, 50);
        assert_eq!(table.pot, 0, "create_table 应覆写为初始状态");
        // RV32I sret workaround 后，dispatch 返回 `()`；modified_objects 由调用方
        // 从 `table.id` 构造。此处校验 events 应包含 TableCreated 事件。
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::TableCreated { .. })),
            "create_table 应 emit TableCreated 事件"
        );
    }

    #[test]
    fn dispatch_create_table_rejects_invalid_max_players() {
        let ctx = make_context();
        let mut table = make_table();
        let args = CreateTableArgs {
            name: "bad".into(),
            max_players: 10, // 越界
            small_blind: 25,
            big_blind: 50,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let mut events = Vec::new();
        let result = dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes, &mut events);
        assert!(result.is_err());
    }

    /// 校验 create_table 在已有桌台上调用时 version 应递增（stateless 模型下的乐观锁语义）。
    #[test]
    fn dispatch_create_table_bumps_version_on_overwrite() {
        let ctx = make_context();
        let mut table = make_table();
        // 第一次 create_table：version 从 0 → 1
        let args1 = CreateTableArgs {
            name: "first".into(),
            max_players: 6,
            small_blind: 25,
            big_blind: 50,
        };
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::create_table(), &borsh::to_vec(&args1).unwrap(), &mut events)
            .expect("第一次 create_table 应成功");
        assert_eq!(table.version, 1);

        // 第二次 create_table（不同参数）：version 应从 1 → 2
        let args2 = CreateTableArgs {
            name: "second".into(),
            max_players: 9,
            small_blind: 100,
            big_blind: 200,
        };
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::create_table(), &borsh::to_vec(&args2).unwrap(), &mut events)
            .expect("第二次 create_table 应成功");
        assert_eq!(table.version, 2, "第二次 create_table 后 version 应为 2");
        assert_eq!(table.name, "second");
        assert_eq!(table.max_players, 9);
    }

    // ========== BLS-touching 测试（仅 riscv32 运行）==========
    // 以下测试调用 g1_generator/g1_identity 或 start_hand（→ set_initial_encrypted_deck
    // → g1_generator），需要 BLS syscall，在非 riscv32 target 上会 panic。

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn dispatch_join_table_then_leave_table() {
        let ctx = make_context();
        let mut table = make_table();
        // WAITING 状态允许 join_table
        let join_args = JoinTableArgs {
            player: [0x11; 20],
            buy_in: 1000,
            pk: g1_identity(),
        };
        let join_bytes = borsh::to_vec(&join_args).unwrap();
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::join_table(), &join_bytes, &mut events).unwrap();
        assert_eq!(table.occupied_count(), 1);
        assert_eq!(table.seats[0].stack, 1000);

        // leave_table
        let leave_args = LeaveTableArgs { seat_index: 0 };
        let leave_bytes = borsh::to_vec(&leave_args).unwrap();
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::leave_table(), &leave_bytes, &mut events).unwrap();
        assert_eq!(table.occupied_count(), 0);
    }

    /// 端到端：完整一局生命周期 create_table → join_table ×2 → start_hand → reset_for_next_hand。
    #[cfg(target_arch = "riscv32")]
    #[test]
    fn e2e_full_hand_lifecycle_create_join_start_reset() {
        let ctx = make_context();
        let mut table = make_table();

        // Step 1: create_table
        let create_args = CreateTableArgs {
            name: "e2e_table".into(),
            max_players: 2,
            small_blind: 10,
            big_blind: 20,
        };
        let create_bytes = borsh::to_vec(&create_args).unwrap();
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::create_table(), &create_bytes, &mut events).unwrap();
        assert_eq!(table.name, "e2e_table");
        assert_eq!(table.max_players, 2);
        assert_eq!(table.round_state, ROUND_WAITING);

        // Step 2a: join_table player 1（pk = identity）
        let join1 = JoinTableArgs {
            player: [0x11; 20],
            buy_in: 1000,
            pk: g1_identity(),
        };
        let mut events = Vec::new();
        dispatch(
            &ctx,
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&join1).unwrap(),
            &mut events,
        )
        .unwrap();
        assert_eq!(table.occupied_count(), 1);

        // Step 2b: join_table player 2（pk = generator，与 player 1 不同）
        let join2 = JoinTableArgs {
            player: [0x22; 20],
            buy_in: 2000,
            pk: g1_generator(),
        };
        let mut events = Vec::new();
        dispatch(
            &ctx,
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&join2).unwrap(),
            &mut events,
        )
        .unwrap();
        assert_eq!(table.occupied_count(), 2);

        // Step 3: start_hand
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::start_hand(), &[], &mut events).unwrap();
        assert_eq!(
            table.shuffle_state.phase,
            super::super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP
        );
        assert_eq!(table.deck_state.encrypted.len(), 52);

        // Step 4: reset_for_next_hand
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::reset_for_next_hand(), &[], &mut events).unwrap();
        assert_eq!(table.round_state, ROUND_WAITING);
        assert_eq!(table.pot, 0);
        assert_eq!(table.occupied_count(), 2, "reset 不应踢出有筹码的玩家");
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn dispatch_kick_player_marks_seat() {
        let ctx = make_context();
        let mut table = make_table();
        // 设置 3 个玩家，确保 kick 后不触发 reset_for_next_hand
        table.round_state = super::super::constants::ROUND_PREFLOP;
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 500;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 500;
        table.seats[2].player = [0x03; 20];
        table.seats[2].stack = 500;

        let args = KickPlayerArgs {
            seat_index: 0,
            reason: 0,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let mut events = Vec::new();
        dispatch(&ctx, &mut table, &selectors::kick_player(), &args_bytes, &mut events).unwrap();
        assert!(table.seats[0].folded);
        assert!(table.seats[0].left_during_hand);
        assert_eq!(table.seats[0].stack, 0);
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn dispatch_tick_with_empty_args_uses_zero() {
        let ctx = make_context();
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        // 空 args 调用 tick：等价于 now_ms=0，触发 start_hand
        let mut events = Vec::new();
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &[], &mut events);
        assert!(result.is_ok());
        assert_eq!(
            table.shuffle_state.phase,
            super::super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP
        );
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn dispatch_tick_with_args_uses_provided_timestamp() {
        let ctx = make_context();
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        let args = TickArgs { now_ms: 5_000_000 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let mut events = Vec::new();
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &args_bytes, &mut events);
        assert!(result.is_ok());
    }
}
