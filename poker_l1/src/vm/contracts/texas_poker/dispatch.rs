//! Texas Poker 合约 dispatch 路由（23 method selector）。
//!
//! 严格对齐 `texas_poker_move/sources/table.move` 的 public entry function 清单：
//! - 表台生命周期：create_table / join_table / leave_table / start_hand / tick
//! - 玩家动作：fold / check / call / raise / auto_fold / force_fold / kick_player
//! - 离场预约：request_leave_after_hand（sit out next hand，toggle，任意时刻可调用）
//! - Mental Poker 协议：join_and_shuffle / leave_with_proof / fold_with_proof
//!   / submit_shuffle_v2 / submit_player_reveal_tokens / submit_reconstruct_deck
//!
//! # Selector 计算
//!
//! `blake2b_256(method_name)[0..32]`，与 `contracts/dispatch.rs` 保持一致。
//!
//! # Args 编码
//!
//! 每个 method 对应一个 `*Args` 结构体，使用 **borsh** 序列化（B.4 迁移后）。
//! 密码学字段（pk/ciphertexts/proofs）为 typed `poker_protocol` 类型，
//! 消除 dispatch 子函数中手动 `ser::deserialize_*` 调用。
//!
//! # Events 处理
//!
//! state_machine 函数会通过 `events: &mut Vec<TexasPokerEvent>` 收集事件。
//! dispatch 层目前仅记录日志（tracing::debug!）并丢弃，后续 Precompile
//! 实现可在 Phase 3.3 / Phase 4 中扩展 DispatchResult 携带 events 字段。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use blstrs::G1Projective;
use borsh::{BorshDeserialize, BorshSerialize};
use group::Group;

use poker_protocol::crypto::types::{DefaultCurve, ECPoint, ElGamalCiphertext};
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, LeaveKind, RemaskKind};
use poker_protocol::zk_shuffle::reconstruction::{ReconstructProofV3, ReconstructionV3Statement};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;

use super::constants::{FOLD_REASON_AUTO_TIMEOUT, FOLD_REASON_FORCE_ADMIN};
use super::events::TexasPokerEvent;
use super::state_machine;
use super::types::TexasPokerTable;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;
use crate::vm::contracts::dispatch::{DispatchContext, DispatchResult};
use crate::{Address, BlockHeight, ChainId};

/// 方法选择器长度（32 字节 = blake2b_256 输出）。
pub const METHOD_SELECTOR_LEN: usize = 32;

/// 计算方法选择器：`blake2b_256(method_name)[0..32]`。
///
/// 与 `contracts::dispatch::compute_method_selector` 算法一致，
/// 但独立定义以避免循环依赖（texas_poker 不应被父 dispatch 模块引用）。
pub fn compute_method_selector(method_name: &str) -> [u8; METHOD_SELECTOR_LEN] {
    let mut h = Blake2bVar::new(METHOD_SELECTOR_LEN).expect("32 <= 64");
    h.update(method_name.as_bytes());
    let mut out = [0u8; METHOD_SELECTOR_LEN];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 17 个方法选择器常量。
///
/// 所有方法名使用 snake_case，与 Move 端 entry function 名一一对应。
pub mod selectors {
    use super::compute_method_selector;

    /// `create_table` — 创建新桌台。
    pub fn create_table() -> [u8; 32] {
        compute_method_selector("create_table")
    }

    /// `join_and_shuffle` — 玩家加入并完成首洗牌（含 remask + shuffle proof）。
    pub fn join_and_shuffle() -> [u8; 32] {
        compute_method_selector("join_and_shuffle")
    }

    /// `leave_with_proof` — 玩家带 proof 离场（保留手牌贡献）。
    pub fn leave_with_proof() -> [u8; 32] {
        compute_method_selector("leave_with_proof")
    }

    /// `join_table` — 简单入座（不参与本局，等下一局）。
    pub fn join_table() -> [u8; 32] {
        compute_method_selector("join_table")
    }

    /// `leave_table` — 简单离座（仅在 WAITING 状态）。
    pub fn leave_table() -> [u8; 32] {
        compute_method_selector("leave_table")
    }

    /// `start_hand` — 开始新一局（投盲注 + 进入 shuffle 阶段）。
    pub fn start_hand() -> [u8; 32] {
        compute_method_selector("start_hand")
    }

    /// `tick` — 超时驱动（permissionless）。
    pub fn tick() -> [u8; 32] {
        compute_method_selector("tick")
    }

    /// `auto_fold` — 玩家超时自动 fold。
    pub fn auto_fold() -> [u8; 32] {
        compute_method_selector("auto_fold")
    }

    /// `force_fold` — 管理员强制 fold 玩家。
    pub fn force_fold() -> [u8; 32] {
        compute_method_selector("force_fold")
    }

    /// `kick_player` — 踢出玩家（管理员操作）。
    pub fn kick_player() -> [u8; 32] {
        compute_method_selector("kick_player")
    }

    /// `submit_shuffle_v2` — 玩家提交洗牌结果（第二手及以后）。
    pub fn submit_shuffle_v2() -> [u8; 32] {
        compute_method_selector("submit_shuffle_v2")
    }

    /// `submit_player_reveal_tokens` — 提交揭牌令牌。
    pub fn submit_player_reveal_tokens() -> [u8; 32] {
        compute_method_selector("submit_player_reveal_tokens")
    }

    /// `submit_reconstruct_deck` — 提交重构牌组。
    pub fn submit_reconstruct_deck() -> [u8; 32] {
        compute_method_selector("submit_reconstruct_deck")
    }

    /// `fold` — 玩家主动 fold。
    pub fn fold() -> [u8; 32] {
        compute_method_selector("fold")
    }

    /// `check` — 玩家过牌。
    pub fn check() -> [u8; 32] {
        compute_method_selector("check")
    }

    /// `call` — 玩家跟注。
    pub fn call() -> [u8; 32] {
        compute_method_selector("call")
    }

    /// `raise` — 玩家加注。
    pub fn raise() -> [u8; 32] {
        compute_method_selector("raise")
    }

    /// `bet` — 玩家主动下注（postflop 第一个下注者，语义等同于 raise 但更清晰）。
    pub fn bet() -> [u8; 32] {
        compute_method_selector("bet")
    }

    /// `reset_for_next_hand` — 显式重置桌台到 WAITING（管理员/测试场景）。
    ///
    /// 正常对局流程中由 `settle_hand` / `end_without_showdown` / 超时路径内部调用；
    /// 暴露为 dispatch selector 便于端到端测试与异常恢复。
    pub fn reset_for_next_hand() -> [u8; 32] {
        compute_method_selector("reset_for_next_hand")
    }

    /// `addon` — 玩家追加筹码（下一手生效）。
    pub fn addon() -> [u8; 32] {
        compute_method_selector("addon")
    }

    /// `rebuy` — 玩家重购（立即生效，MTT 早期用）。
    pub fn rebuy() -> [u8; 32] {
        compute_method_selector("rebuy")
    }

    /// `request_leave_after_hand` — 玩家请求「下局开始前离场」（toggle）。
    ///
    /// 在线扑克 "sit out next hand / stand up next hand" 模式：玩家可在任意
    /// round_state 调用切换 `seat.want_leave` 标志，下一手 `reset_for_next_hand`
    /// 时强制踢出并退款。解决 `leave_table` 仅 WAITING 可用、creator/tick 可能
    /// 立即 start_hand 导致玩家来不及离场的问题。
    ///
    /// 该方法使用稳定的独立 MethodKind discriminant 21 产生 ProveTask，
    /// 不能借用 Tick/ResetForNextHand，否则会把 toggle 状态变化伪装成其他语义。
    pub fn request_leave_after_hand() -> [u8; 32] {
        compute_method_selector("request_leave_after_hand")
    }

    /// `fold_with_proof` — 玩家 fold 并提交 fold proof（剥离加密层 + 退出后续 reveal）。
    ///
    /// `leave_with_proof` 的「对局中」版本：在**下注轮**调用，玩家 fold 时通过
    /// DLEqProof（LeaveKind）剥离自己的加密层（remove pk from aggregated_pk +
    /// remask deck），并从所有 reveal pending 列表中移除——后续解牌不需要该玩家
    /// 参加。区别于普通 fold：普通 fold 玩家仍需为后续公共牌提交 reveal token
    /// （或被超时踢出）；fold_with_proof 让玩家立即从协议中「物理退出」。
    ///
    /// 该方法使用稳定的独立 MethodKind discriminant 22 产生 ProveTask，并保留
    /// 完整原始 proof 参数，供证明消费侧重验复合状态转换。
    pub fn fold_with_proof() -> [u8; 32] {
        compute_method_selector("fold_with_proof")
    }

    /// 返回所有 23 个 selector，供 `supports_selector` 等使用。
    #[must_use]
    pub fn all() -> Vec<[u8; 32]> {
        vec![
            create_table(),
            join_and_shuffle(),
            leave_with_proof(),
            join_table(),
            leave_table(),
            start_hand(),
            tick(),
            auto_fold(),
            force_fold(),
            kick_player(),
            submit_shuffle_v2(),
            submit_player_reveal_tokens(),
            submit_reconstruct_deck(),
            fold(),
            check(),
            call(),
            raise(),
            bet(),
            reset_for_next_hand(),
            addon(),
            rebuy(),
            request_leave_after_hand(),
            fold_with_proof(),
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
    /// 玩家 ElGamal 公钥（G1 点，使用 ECPoint newtype 以支持 Borsh）。
    pub pk: ECPoint,
    /// pk 所有权证明（80 字节 Schnorr 自定义格式，保留 Vec<u8>）。
    pub pk_ownership_proof: Vec<u8>,
    /// remask 后的牌组掩码（typed ElGamalCiphertext 列表）。
    pub mask_cards: Vec<ElGamalCiphertext>,
    /// shuffle 输出牌组（typed ElGamalCiphertext 列表）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// remask proof（typed DLEqProof<RemaskKind>）。
    pub remask_proof: DLEqProof<DefaultCurve, RemaskKind>,
    /// Versioned shuffle proof；生产验证仅接受 Bayer--Groth V2。
    pub shuffle_proof: ShuffleProof,
}

/// `leave_with_proof` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct LeaveWithProofArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 离场时的牌组输出（typed ElGamalCiphertext 列表，用于验证贡献连续性）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// leave proof（typed DLEqProof<LeaveKind>）。
    pub leave_proof: DLEqProof<DefaultCurve, LeaveKind>,
}

/// `fold_with_proof` 参数（局中 fold + 剥离加密层）。
///
/// 与 `LeaveWithProofArgs` 字段布局完全一致，仅方法语义不同：
/// leave 在 WAITING 状态调用（局间离场），fold_with_proof 在下注轮调用
/// （局中弃牌 + 退出后续 reveal 协议）。proof 复用 `LeaveKind`。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct FoldWithProofArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// fold 时的牌组输出（typed ElGamalCiphertext 列表，剥离玩家加密层后的新牌组）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// fold proof（typed DLEqProof<LeaveKind>，与 leave proof 同型）。
    pub fold_proof: DLEqProof<DefaultCurve, LeaveKind>,
}

/// `join_table` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct JoinTableArgs {
    /// 玩家地址。
    pub player: Address,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家 ElGamal 公钥（G1 点，使用 ECPoint newtype 以支持 Borsh）。
    pub pk: ECPoint,
}

/// `leave_table` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct LeaveTableArgs {
    /// 座位索引。
    pub seat_index: u8,
}

/// `tick` 的兼容参数。
///
/// 新调用应传空参数；若旧客户端仍携带时间戳，该值必须与共识提供的
/// [`DispatchContext::block_timestamp`] 完全一致。状态机绝不使用调用者提供的
/// 时间作为超时依据。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TickArgs {
    /// 兼容字段：必须等于当前区块时间戳（毫秒）。
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
    /// Versioned shuffle proof；生产验证仅接受 Bayer--Groth V2。
    pub shuffle_proof: ShuffleProof,
}

/// `submit_player_reveal_tokens` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitRevealTokensArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 揭牌分配索引列表（每张待揭示牌在 deck 中的位置）。
    pub assignment_indices: Vec<u8>,
    /// 揭牌令牌列表（typed ECPoint，Borsh 兼容的 G1 点包装）。
    pub reveal_tokens: Vec<ECPoint>,
    /// 揭牌 proof 列表（typed RevealTokenProof，与 reveal_tokens 一一对应）。
    pub proofs: Vec<RevealTokenProof<DefaultCurve>>,
}

/// `submit_reconstruct_deck` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitReconstructDeckArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// Complete V3 public statement. The hidden readable-to-canonical mapping
    /// is not serialized in this value.
    pub statement: ReconstructionV3Statement<DefaultCurve>,
    /// Reconstruction V3 proof for the exact statement above.
    pub proof: ReconstructProofV3<DefaultCurve>,
}

/// `raise` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RaiseArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 加注后该玩家本轮总下注额（不是加注增量）。
    pub total_bet: u64,
}

/// `bet` 参数（postflop 主动下注，amount 是下注增量，不是总下注）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BetArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 下注金额（增量，必须 > 0）。
    pub amount: u64,
}

/// `addon` 参数（追加筹码，下一手生效）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct AddonArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 追加金额（必须 > 0）。
    pub amount: u64,
}

/// `rebuy` 参数（重购，立即生效）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RebuyArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 重购金额（必须 > 0）。
    pub amount: u64,
}

/// Decode the native ZCN amount required by a funded Texas Poker method.
///
/// This is the canonical selector-to-funding mapping shared by consensus execution and
/// frictionless wallet builders. Non-funding methods return `Ok(None)`.
pub fn required_funding(method_selector: &[u8; 32], args: &[u8]) -> PokerL1Result<Option<u64>> {
    let amount = if method_selector == &selectors::join_and_shuffle() {
        borsh::from_slice::<JoinAndShuffleArgs>(args)
            .map_err(|error| {
                PokerL1Error::Serialization(format!("join_and_shuffle funding args: {error}"))
            })?
            .buy_in
    } else if method_selector == &selectors::join_table() {
        borsh::from_slice::<JoinTableArgs>(args)
            .map_err(|error| {
                PokerL1Error::Serialization(format!("join_table funding args: {error}"))
            })?
            .buy_in
    } else if method_selector == &selectors::addon() {
        borsh::from_slice::<AddonArgs>(args)
            .map_err(|error| PokerL1Error::Serialization(format!("addon funding args: {error}")))?
            .amount
    } else if method_selector == &selectors::rebuy() {
        borsh::from_slice::<RebuyArgs>(args)
            .map_err(|error| PokerL1Error::Serialization(format!("rebuy funding args: {error}")))?
            .amount
    } else {
        return Ok(None);
    };
    if amount == 0 {
        return Err(PokerL1Error::Other(
            "funded Texas call amount must be greater than zero".into(),
        ));
    }
    Ok(Some(amount))
}

// ========== Dispatch 路由入口 ==========

/// Dispatch 路由入口。
///
/// 将 ContractCall 路由到对应的 Texas Poker 合约方法。
///
/// 参数：
/// - `context`：执行上下文（调用者、block 信息等）
/// - `table`：可变的 `TexasPokerTable` 引用（状态变更目标）
/// - `selector`：方法选择器（32 字节）
/// - `args`：调用参数（BCS 编码）
///
/// 返回：`DispatchResult` 包含状态变更信息。
///
/// 失败时返回 `PokerL1Error::UnknownContractMethod`（未知方法）或各业务方法的具体错误。
pub fn dispatch(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    selector: &[u8; 32],
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    // Post-commit Prover：执行前捕获 pre_table 快照（用于构造证明任务）。
    // clone 成本可接受（TexasPokerTable ~KB 级，且 prove_task 是异步消费的离线数据）。
    let pre_table = table.clone();
    let mut events: Vec<TexasPokerEvent> = Vec::new();
    let result = match selector {
        s if s == &selectors::create_table() => {
            dispatch_create_table(context, table, args, &mut events)
        }
        s if s == &selectors::join_and_shuffle() => {
            dispatch_join_and_shuffle(context, table, args, &mut events)
        }
        s if s == &selectors::leave_with_proof() => {
            dispatch_leave_with_proof(context, table, args, &mut events)
        }
        s if s == &selectors::join_table() => {
            dispatch_join_table(context, table, args, &mut events)
        }
        s if s == &selectors::leave_table() => {
            dispatch_leave_table(context, table, args, &mut events)
        }
        s if s == &selectors::start_hand() => {
            dispatch_start_hand(context, table, args, &mut events)
        }
        s if s == &selectors::tick() => dispatch_tick(context, table, args, &mut events),
        s if s == &selectors::auto_fold() => dispatch_auto_fold(context, table, args, &mut events),
        s if s == &selectors::force_fold() => {
            dispatch_force_fold(context, table, args, &mut events)
        }
        s if s == &selectors::kick_player() => {
            dispatch_kick_player(context, table, args, &mut events)
        }
        s if s == &selectors::submit_shuffle_v2() => {
            dispatch_submit_shuffle_v2(context, table, args, &mut events)
        }
        s if s == &selectors::submit_player_reveal_tokens() => {
            dispatch_submit_player_reveal_tokens(context, table, args, &mut events)
        }
        s if s == &selectors::submit_reconstruct_deck() => {
            dispatch_submit_reconstruct_deck(context, table, args, &mut events)
        }
        s if s == &selectors::fold() => dispatch_fold(context, table, args, &mut events),
        s if s == &selectors::check() => dispatch_check(context, table, args, &mut events),
        s if s == &selectors::call() => dispatch_call(context, table, args, &mut events),
        s if s == &selectors::raise() => dispatch_raise(context, table, args, &mut events),
        s if s == &selectors::bet() => dispatch_bet(context, table, args, &mut events),
        s if s == &selectors::reset_for_next_hand() => {
            dispatch_reset_for_next_hand(context, table, args, &mut events)
        }
        s if s == &selectors::addon() => dispatch_addon(context, table, args, &mut events),
        s if s == &selectors::rebuy() => dispatch_rebuy(context, table, args, &mut events),
        s if s == &selectors::request_leave_after_hand() => {
            dispatch_request_leave_after_hand(context, table, args, &mut events)
        }
        s if s == &selectors::fold_with_proof() => {
            dispatch_fold_with_proof(context, table, args, &mut events)
        }
        _ => {
            return Err(PokerL1Error::UnknownContractMethod {
                selector: *selector,
            });
        }
    };
    result?;

    // 证明任务元数据只在成功且真正改变状态的 dispatch 上推进。
    // 使用 pre_table 作为计数基准，防止 create_table 覆写结构时把序号重置为 0。
    let state_changed = *table != pre_table;
    if state_changed {
        let next_call_seq = pre_table
            .call_seq
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Serialization("texas_poker call_seq overflow".into()))?;
        let hand_started = events
            .iter()
            .any(|event| matches!(event, TexasPokerEvent::HandStarted { .. }));
        let next_hand_id = if hand_started {
            pre_table
                .hand_id
                .checked_add(1)
                .ok_or_else(|| PokerL1Error::Serialization("texas_poker hand_id overflow".into()))?
        } else {
            pre_table.hand_id
        };
        table.call_seq = next_call_seq;
        table.hand_id = next_hand_id;
    }
    log_events(&events);

    // Post-commit Prover：构造证明任务（pre/post table + method 元数据）。
    // return_value = borsh(L1DispatchOutput { events, prove_task })，
    // Orchestrator 从链层取回后反序列化生成 proof。
    let return_value = build_dispatch_output(context, &events, selector, args, pre_table, table)?;

    Ok(DispatchResult {
        created_objects: vec![],
        modified_objects: vec![table.id],
        return_value,
    })
}

/// 构造 `L1DispatchOutput` 并序列化为 return_value 字节。
///
/// 根据 selector 推导 method_kind discriminant + 构造 MethodInput，
/// 封装为 `L1DispatchOutput { events, prove_task }`。
/// 没有状态变化（例如 no-op tick）时仅返回 events；所有 23 个已注册 selector
/// 一旦改变状态都必须产生 task。未知 selector 返回错误，不能静默丢 task。
fn build_dispatch_output(
    context: &DispatchContext,
    events: &[TexasPokerEvent],
    selector: &[u8; 32],
    args: &[u8],
    pre_table: TexasPokerTable,
    post_table: &TexasPokerTable,
) -> PokerL1Result<Vec<u8>> {
    use super::prove_task::{L1DispatchOutput, L1ProveTask};

    if pre_table == *post_table {
        let out = L1DispatchOutput::events_only(events.to_vec());
        return borsh::to_vec(&out)
            .map_err(|e| PokerL1Error::Serialization(format!("dispatch output borsh: {e}")));
    }

    let (kind, method_input) = build_method_input(selector, args)?;
    let table_id = post_table.id.creation_nonce;
    let hand_id = post_table.hand_id;
    let call_seq = post_table.call_seq;
    let task = L1ProveTask::new(
        kind,
        method_input,
        context.clone(),
        *selector,
        args.to_vec(),
        pre_table,
        post_table.clone(),
        table_id,
        hand_id,
        call_seq,
    );
    let out = L1DispatchOutput::with_task(events.to_vec(), task);
    borsh::to_vec(&out)
        .map_err(|e| PokerL1Error::Serialization(format!("dispatch output borsh: {e}")))
}

/// 根据 selector + args 构造 `(method_kind_discriminant, MethodInput)`。
///
/// method_kind discriminant 与 `poker_texas_air::MethodKind` 对齐
/// （`#[repr(u8)]` + `use_discriminant=true`）。
///
/// 六个密码学方法先按各自真实 Args 类型完整解码，再把原始 borsh 字节写入
/// 专用 MethodInput variant。这样证明端能重新验证完整 proof，而不是只拿 seat_index。
fn build_method_input(
    selector: &[u8; 32],
    args: &[u8],
) -> PokerL1Result<(u8, super::prove_task::MethodInput)> {
    use super::prove_task::MethodInput;
    // method_kind discriminant（与 poker_texas_air::MethodKind 对齐）
    const K_CREATE_TABLE: u8 = 0;
    const K_JOIN_TABLE: u8 = 1;
    const K_LEAVE_TABLE: u8 = 2;
    const K_START_HAND: u8 = 3;
    const K_TICK: u8 = 4;
    const K_RESET: u8 = 5;
    const K_FOLD: u8 = 6;
    const K_CHECK: u8 = 7;
    const K_CALL: u8 = 8;
    const K_RAISE: u8 = 9;
    const K_AUTO_FOLD: u8 = 10;
    const K_FORCE_FOLD: u8 = 11;
    const K_KICK: u8 = 12;
    const K_ADDON: u8 = 13;
    const K_REBUY: u8 = 14;
    const K_JOIN_SHUFFLE: u8 = 15;
    const K_LEAVE_PROOF: u8 = 16;
    const K_SUBMIT_SHUFFLE: u8 = 17;
    const K_SUBMIT_REVEAL: u8 = 18;
    const K_SUBMIT_RECONSTRUCT: u8 = 19;
    const K_BET: u8 = 20;
    const K_REQUEST_LEAVE_AFTER_HAND: u8 = 21;
    const K_FOLD_WITH_PROOF: u8 = 22;

    if selector == &selectors::create_table() {
        let a: CreateTableArgs = decode_args(args, "create_table prove task")?;
        return Ok((
            K_CREATE_TABLE,
            MethodInput::CreateTable {
                name: a.name,
                max_players: a.max_players,
                small_blind: a.small_blind,
                big_blind: a.big_blind,
            },
        ));
    }
    if selector == &selectors::join_and_shuffle() {
        let a: JoinAndShuffleArgs = decode_args(args, "join_and_shuffle prove task")?;
        return Ok((
            K_JOIN_SHUFFLE,
            MethodInput::JoinAndShuffle {
                seat_index: a.seat_index,
                player: a.player,
                buy_in: a.buy_in,
                raw_args: args.to_vec(),
            },
        ));
    }
    if selector == &selectors::leave_with_proof() {
        let a: LeaveWithProofArgs = decode_args(args, "leave_with_proof prove task")?;
        return Ok((
            K_LEAVE_PROOF,
            MethodInput::LeaveWithProof {
                seat_index: a.seat_index,
                raw_args: args.to_vec(),
            },
        ));
    }
    if selector == &selectors::join_table() {
        let a: JoinTableArgs = decode_args(args, "join_table prove task")?;
        return Ok((
            K_JOIN_TABLE,
            MethodInput::Join {
                player: a.player,
                buy_in: a.buy_in,
            },
        ));
    }
    if selector == &selectors::leave_table() {
        let a: LeaveTableArgs = decode_args(args, "leave_table prove task")?;
        return Ok((
            K_LEAVE_TABLE,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::start_hand() {
        return Ok((K_START_HAND, MethodInput::Empty));
    }
    if selector == &selectors::tick() {
        if !args.is_empty() {
            let _: TickArgs = decode_args(args, "tick prove task")?;
        }
        return Ok((K_TICK, MethodInput::Empty));
    }
    if selector == &selectors::auto_fold() {
        let a: SeatIndexArgs = decode_args(args, "auto_fold prove task")?;
        return Ok((
            K_AUTO_FOLD,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::force_fold() {
        let a: SeatIndexArgs = decode_args(args, "force_fold prove task")?;
        return Ok((
            K_FORCE_FOLD,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::kick_player() {
        let a: KickPlayerArgs = decode_args(args, "kick_player prove task")?;
        return Ok((
            K_KICK,
            MethodInput::Kick {
                seat_index: a.seat_index,
                reason: a.reason,
            },
        ));
    }
    if selector == &selectors::submit_shuffle_v2() {
        let a: SubmitShuffleV2Args = decode_args(args, "submit_shuffle_v2 prove task")?;
        return Ok((
            K_SUBMIT_SHUFFLE,
            MethodInput::SubmitShuffleV2 {
                seat_index: a.seat_index,
                raw_args: args.to_vec(),
            },
        ));
    }
    if selector == &selectors::submit_player_reveal_tokens() {
        let a: SubmitRevealTokensArgs =
            decode_args(args, "submit_player_reveal_tokens prove task")?;
        return Ok((
            K_SUBMIT_REVEAL,
            MethodInput::SubmitPlayerRevealTokens {
                seat_index: a.seat_index,
                raw_args: args.to_vec(),
            },
        ));
    }
    if selector == &selectors::submit_reconstruct_deck() {
        let a: SubmitReconstructDeckArgs = decode_args(args, "submit_reconstruct_deck prove task")?;
        return Ok((
            K_SUBMIT_RECONSTRUCT,
            MethodInput::SubmitReconstructDeck {
                seat_index: a.seat_index,
                raw_args: args.to_vec(),
            },
        ));
    }
    if selector == &selectors::fold() {
        let a: SeatIndexArgs = decode_args(args, "fold prove task")?;
        return Ok((
            K_FOLD,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::check() {
        let a: SeatIndexArgs = decode_args(args, "check prove task")?;
        return Ok((
            K_CHECK,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::call() {
        let a: SeatIndexArgs = decode_args(args, "call prove task")?;
        return Ok((
            K_CALL,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::raise() {
        let a: RaiseArgs = decode_args(args, "raise prove task")?;
        return Ok((
            K_RAISE,
            MethodInput::Raise {
                seat_index: a.seat_index,
                total_bet: a.total_bet,
            },
        ));
    }
    if selector == &selectors::bet() {
        let a: BetArgs = decode_args(args, "bet prove task")?;
        return Ok((
            K_BET,
            MethodInput::Bet {
                seat_index: a.seat_index,
                amount: a.amount,
            },
        ));
    }
    if selector == &selectors::reset_for_next_hand() {
        return Ok((K_RESET, MethodInput::Empty));
    }
    if selector == &selectors::addon() {
        let a: AddonArgs = decode_args(args, "addon prove task")?;
        return Ok((
            K_ADDON,
            MethodInput::Funds {
                seat_index: a.seat_index,
                amount: a.amount,
            },
        ));
    }
    if selector == &selectors::rebuy() {
        let a: RebuyArgs = decode_args(args, "rebuy prove task")?;
        return Ok((
            K_REBUY,
            MethodInput::Funds {
                seat_index: a.seat_index,
                amount: a.amount,
            },
        ));
    }
    if selector == &selectors::request_leave_after_hand() {
        let a: SeatIndexArgs = decode_args(args, "request_leave_after_hand prove task")?;
        return Ok((
            K_REQUEST_LEAVE_AFTER_HAND,
            MethodInput::RequestLeaveAfterHand {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::fold_with_proof() {
        let a: FoldWithProofArgs = decode_args(args, "fold_with_proof prove task")?;
        return Ok((
            K_FOLD_WITH_PROOF,
            MethodInput::FoldWithProof {
                seat_index: a.seat_index,
                raw_args: args.to_vec(),
            },
        ));
    }

    Err(PokerL1Error::UnknownContractMethod {
        selector: *selector,
    })
}

/// 将 events 列表以 debug 级别记录到 tracing。
fn log_events(events: &[TexasPokerEvent]) {
    if events.is_empty() {
        return;
    }
    tracing::debug!("texas_poker dispatch emitted {} events", events.len());
}

/// borsh 反序列化辅助。
fn decode_args<T: BorshDeserialize>(args: &[u8], method: &str) -> PokerL1Result<T> {
    borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("{method} args borsh: {e}")))
}

// ========== P0-2 权限校验辅助 ==========
//
// TexasPokerTable 此前在 dispatch 层与 precompile 层都没有任何调用方权限校验
// （routing 层的 validate_game_turn_tx 只覆盖 GameStatus，未覆盖 TexasPokerTable）。
// 这意味着任意地址都能对任意座位执行 fold/raise/kick/rebuy 等方法。
//
// 本模块在 dispatch 层补齐 caller 权限校验：
// - 动作类（fold/check/call/raise/bet/auto_fold/addon/rebuy/leave_table）：
//   caller == seats[seat_index].player
// - 管理类（kick_player/force_fold/reset_for_next_hand）：
//   caller == table.creator（create_table 时记录）
// - 协议类（join_and_shuffle/submit_*/leave_with_proof）：
//   caller == seats[seat_index].player（与动作类一致）
//
// 选择 dispatch 层（而非 routing 层）的原因：caller 校验可被 poker_texas_air
// 电路直接约束，与同步电路目标契合；且合约自包含，不引入跨对象同步负担。

/// 校验 caller 是指定座位的玩家。
fn require_caller_is_seat_player(
    context: &DispatchContext,
    table: &TexasPokerTable,
    seat_index: u8,
    method: &str,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    let seat = &table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: seat {seat_index} not occupied"
        )));
    }
    if seat.player != context.caller {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: caller {:?} is not seat {seat_index} player",
            context.caller
        )));
    }
    Ok(())
}

/// 校验 caller 是桌台创建者（管理类方法）。
fn require_caller_is_creator(
    context: &DispatchContext,
    table: &TexasPokerTable,
    method: &str,
) -> PokerL1Result<()> {
    if table.creator != context.caller {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: caller {:?} is not table creator",
            context.caller
        )));
    }
    Ok(())
}

// ========== dispatch_* 子函数 ==========

/// `create_table` — 初始化桌台（覆写默认空桌台）。
fn dispatch_create_table(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    _events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: CreateTableArgs = decode_args(args, "create_table")?;
    if !(2..=9).contains(&input.max_players) {
        return Err(PokerL1Error::Serialization(format!(
            "max_players {} out of range [2, 9]",
            input.max_players
        )));
    }
    if input.big_blind == 0 {
        return Err(PokerL1Error::Serialization("big_blind must > 0".into()));
    }
    if input.small_blind > input.big_blind {
        return Err(PokerL1Error::Serialization(
            "small_blind must <= big_blind".into(),
        ));
    }
    let id = table.id;
    // P0-2：记录 creator 为调用方，作为后续管理类方法的权限基准。
    *table = TexasPokerTable::new(
        id,
        input.name,
        context.caller,
        input.max_players,
        input.small_blind,
        input.big_blind,
    );
    table.bump_version();
    Ok(())
}

/// `join_and_shuffle` — 玩家加入并完成首洗牌。
fn dispatch_join_and_shuffle(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: JoinAndShuffleArgs = decode_args(args, "join_and_shuffle")?;
    // 入座方法：校验 caller == input.player（此时座位尚空，无法用 seat.player 校验）
    if input.player != context.caller {
        return Err(PokerL1Error::Serialization(format!(
            "join_and_shuffle: caller {:?} != player {:?}",
            context.caller, input.player
        )));
    }
    // ECPoint → G1Projective（state_machine 接口使用裸 G1Projective）
    let pk: G1Projective = input.pk.into();
    state_machine::apply_join_and_shuffle(
        table,
        input.seat_index,
        input.player,
        input.buy_in,
        pk,
        input.pk_ownership_proof,
        input.mask_cards,
        input.output_cards,
        input.remask_proof,
        input.shuffle_proof,
        events,
    )
}

/// `leave_with_proof` — 带 proof 离场。
fn dispatch_leave_with_proof(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: LeaveWithProofArgs = decode_args(args, "leave_with_proof")?;
    require_caller_is_seat_player(context, table, input.seat_index, "leave_with_proof")?;
    state_machine::apply_leave_with_proof(
        table,
        input.seat_index,
        input.output_cards,
        input.leave_proof,
        events,
    )
}

/// `fold_with_proof` — 带 proof 的局中 fold（剥离加密层 + 退出后续 reveal）。
///
/// 权限：`caller == seat.player`（与 leave_with_proof / fold 一致）。
/// 仅在下注轮可用（`is_betting_round`）；与 `leave_with_proof`（仅 WAITING）互补。
///
/// 调用 `state_machine::apply_fold_with_proof`：验证 DLEqProof（LeaveKind）→
/// 从 aggregated_pk 移除玩家 pk → remask encrypted deck → scrub 所有 reveal
/// pending → 标记 folded → 推进轮次。
fn dispatch_fold_with_proof(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: FoldWithProofArgs = decode_args(args, "fold_with_proof")?;
    require_caller_is_seat_player(context, table, input.seat_index, "fold_with_proof")?;
    state_machine::apply_fold_with_proof(
        table,
        input.seat_index,
        input.output_cards,
        input.fold_proof,
        events,
    )
}

/// `join_table` — 简单入座（不参与本局，标记 is_waiting=true）。
///
/// 仅在 WAITING 状态允许；占第一个空座位；玩家不能已在桌台。
fn dispatch_join_table(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: JoinTableArgs = decode_args(args, "join_table")?;
    // 入座方法：校验 caller == input.player（座位尚空，无法用 seat.player 校验）
    if input.player != context.caller {
        return Err(PokerL1Error::Serialization(format!(
            "join_table: caller {:?} != player {:?}",
            context.caller, input.player
        )));
    }
    if !state_machine::can_join_state(table) {
        return Err(PokerL1Error::Serialization(
            "not in WAITING state, cannot join_table".into(),
        ));
    }
    // ECPoint → G1Projective（state_machine::is_pk_registered / Seat.pk 使用裸 G1Projective）
    let pk: G1Projective = input.pk.into();
    if state_machine::is_pk_registered(&table.seats, &pk) {
        return Err(PokerL1Error::Serialization(
            "pk already registered at this table".into(),
        ));
    }
    if input.buy_in < table.big_blind {
        return Err(PokerL1Error::Serialization(format!(
            "buy_in {} < big_blind {}",
            input.buy_in, table.big_blind
        )));
    }
    let seat_idx = table
        .find_empty_seat()
        .ok_or_else(|| PokerL1Error::Serialization("no empty seat available".into()))?;
    let seat = &mut table.seats[seat_idx as usize];
    seat.player = input.player;
    seat.stack = input.buy_in;
    seat.pk = ECPoint::from(pk);
    seat.is_waiting = false; // WAITING 状态加入，立即参与下一局
    seat.folded = false;
    seat.left_during_hand = false;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.bet = 0;
    seat.total_bet = 0;
    seat.hand.clear();

    // P0 修复：与 apply_join_shuffle 保持一致的资金记账——buy_in 必须进入 chip_pool，
    // 否则离座退款时 chip_pool 会出现负差额（资金凭空多退）。
    table.chip_pool = table
        .chip_pool
        .checked_add(input.buy_in)
        .ok_or_else(|| PokerL1Error::Serialization("chip_pool overflow on join_table".into()))?;

    // 座位已设置完毕后再统计活跃人数（与 apply_join_shuffle 一致，不再 +1）。
    let active_count_after = state_machine::count_active_occupied(&table.seats) as u64;
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
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: LeaveTableArgs = decode_args(args, "leave_table")?;
    require_caller_is_seat_player(context, table, input.seat_index, "leave_table")?;
    if !state_machine::can_leave_state(table) {
        return Err(PokerL1Error::Serialization(
            "not in WAITING state, cannot leave_table".into(),
        ));
    }
    if input.seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "seat_index {} out of range",
            input.seat_index
        )));
    }
    let seat = &table.seats[input.seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(
            "seat not occupied, cannot leave".into(),
        ));
    }
    // 退还 stack + pending_addon（玩家离开时未入账的 addon 也必须退还）
    let refund_amt = seat
        .stack
        .checked_add(seat.pending_addon)
        .ok_or_else(|| PokerL1Error::Serialization("leave_table refund overflow".into()))?;
    let post_chip_pool = table
        .chip_pool
        .checked_sub(refund_amt)
        .ok_or_else(|| PokerL1Error::Serialization("leave_table chip_pool underflow".into()))?;
    let post_addon_pool = table
        .addon_pool
        .checked_sub(seat.pending_addon)
        .ok_or_else(|| PokerL1Error::Serialization("leave_table addon_pool underflow".into()))?;
    let player = seat.player;
    if refund_amt > 0 {
        // 同步扣减 addon_pool（资金流出）
        table.addon_pool = post_addon_pool;
        // chip_pool 是总锁仓，必须扣除 stack + pending_addon 的完整退款。
        table.chip_pool = post_chip_pool;
    }
    table.seats[input.seat_index as usize] = super::types::Seat::empty();

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
///
/// 权限：仅 creator 可发起对局（管理员动作）。
fn dispatch_start_hand(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !args.is_empty() {
        return Err(PokerL1Error::Serialization(
            "start_hand does not accept arguments".into(),
        ));
    }
    require_caller_is_creator(context, table, "start_hand")?;
    state_machine::start_hand(table, events)
}

/// `tick` — 超时驱动。
fn dispatch_tick(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // 时间属于共识上下文，不能由 permissionless 调用者选择。为兼容旧 wire
    // format，非空 args 仍可解析，但仅接受与区块时间完全一致的值。
    if !args.is_empty() {
        let supplied = decode_args::<TickArgs>(args, "tick")?.now_ms;
        if supplied != context.block_timestamp {
            return Err(PokerL1Error::Other(format!(
                "tick timestamp must equal consensus block timestamp: supplied={supplied}, consensus={}",
                context.block_timestamp
            )));
        }
    }
    state_machine::tick(table, context.block_timestamp, events)
}

/// `auto_fold` — 玩家超时自动 fold。
///
/// 权限：仅 creator 可触发（超时处理属管理动作）。
fn dispatch_auto_fold(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "auto_fold")?;
    require_caller_is_creator(context, table, "auto_fold")?;
    if !state_machine::is_betting_round(table) {
        return Err(PokerL1Error::Other(
            "auto_fold requires an active betting round".into(),
        ));
    }
    if table.current_turn != Some(input.seat_index) {
        return Err(PokerL1Error::Other(format!(
            "auto_fold seat is not current turn: requested={}, current={:?}",
            input.seat_index, table.current_turn
        )));
    }
    let seat = table
        .seats
        .get(input.seat_index as usize)
        .ok_or_else(|| PokerL1Error::Other("auto_fold seat index out of range".into()))?;
    if seat.time_bank_ms > 0 {
        return Err(PokerL1Error::Other(format!(
            "auto_fold cannot bypass time bank: remaining_ms={}",
            seat.time_bank_ms
        )));
    }
    let started = table.timestamps.betting_started_at;
    if started == 0 {
        return Err(PokerL1Error::Other(
            "auto_fold betting timer has not started".into(),
        ));
    }
    let deadline = started.saturating_add(table.timeout_config.betting_timeout_ms);
    if context.block_timestamp < deadline {
        return Err(PokerL1Error::Other(format!(
            "auto_fold before timeout: block_timestamp={}, deadline={deadline}",
            context.block_timestamp
        )));
    }
    state_machine::apply_fold_internal(table, input.seat_index, FOLD_REASON_AUTO_TIMEOUT, events)
}

/// `force_fold` — 管理员强制 fold。
fn dispatch_force_fold(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "force_fold")?;
    require_caller_is_creator(context, table, "force_fold")?;
    state_machine::apply_fold_internal(table, input.seat_index, FOLD_REASON_FORCE_ADMIN, events)
}

/// `kick_player` — 踢出玩家。
///
/// P2-1 修复：reason 透传，不再把 `0`（KICK_REASON_TIMEOUT）改写为 KICK_REASON_ADMIN。
/// 调用方应显式传入正确的 reason 常量。
fn dispatch_kick_player(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: KickPlayerArgs = decode_args(args, "kick_player")?;
    // P0-2 权限校验：仅 creator 可执行管理类操作。
    // 注意：reason==0 是合法的 KICK_REASON_TIMEOUT，但在非超时路径由 creator 主动踢人时，
    // 调用方应传 KICK_REASON_ADMIN。此处不再做 0→ADMIN 的隐式改写。
    if context.caller != table.creator {
        return Err(PokerL1Error::Serialization(format!(
            "kick_player: caller {:?} is not table creator",
            context.caller
        )));
    }
    state_machine::kick_player_internal(table, input.seat_index, input.reason, events)?;
    table.bump_version();
    Ok(())
}

/// `submit_shuffle_v2` — 提交洗牌结果。
fn dispatch_submit_shuffle_v2(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitShuffleV2Args = decode_args(args, "submit_shuffle_v2")?;
    require_caller_is_seat_player(context, table, input.seat_index, "submit_shuffle_v2")?;
    state_machine::apply_submit_shuffle_v2(
        table,
        input.seat_index,
        input.output_cards,
        input.shuffle_proof,
        events,
    )
}

/// `submit_player_reveal_tokens` — 提交揭牌令牌。
fn dispatch_submit_player_reveal_tokens(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitRevealTokensArgs = decode_args(args, "submit_player_reveal_tokens")?;
    require_caller_is_seat_player(
        context,
        table,
        input.seat_index,
        "submit_player_reveal_tokens",
    )?;
    // ECPoint → G1Projective（state_machine 接口使用裸 G1Projective）
    let reveal_tokens: Vec<G1Projective> =
        input.reveal_tokens.into_iter().map(Into::into).collect();
    state_machine::apply_submit_player_reveal_tokens(
        table,
        input.seat_index,
        input.assignment_indices,
        reveal_tokens,
        input.proofs,
        events,
    )
}

/// `submit_reconstruct_deck` — 提交重构牌组。
fn dispatch_submit_reconstruct_deck(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitReconstructDeckArgs = decode_args(args, "submit_reconstruct_deck")?;
    require_caller_is_seat_player(context, table, input.seat_index, "submit_reconstruct_deck")?;
    state_machine::apply_submit_reconstruct_deck(
        table,
        input.seat_index,
        input.statement,
        input.proof,
        events,
    )
}

/// `fold` — 玩家主动 fold。
fn dispatch_fold(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "fold")?;
    require_caller_is_seat_player(context, table, input.seat_index, "fold")?;
    state_machine::apply_fold(table, input.seat_index, events)
}

/// `check` — 玩家过牌。
fn dispatch_check(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "check")?;
    require_caller_is_seat_player(context, table, input.seat_index, "check")?;
    state_machine::apply_check(table, input.seat_index, events)
}

/// `call` — 玩家跟注。
fn dispatch_call(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "call")?;
    require_caller_is_seat_player(context, table, input.seat_index, "call")?;
    state_machine::apply_call(table, input.seat_index, events)
}

/// `raise` — 玩家加注。
fn dispatch_raise(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: RaiseArgs = decode_args(args, "raise")?;
    require_caller_is_seat_player(context, table, input.seat_index, "raise")?;
    state_machine::apply_raise(table, input.seat_index, input.total_bet, events)
}

/// `bet` — 玩家主动下注（postflop 第一个下注者）。
///
/// 调用 `state_machine::apply_bet`：内部复用 `apply_raise(total_bet = seat.bet + amount)`。
fn dispatch_bet(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: BetArgs = decode_args(args, "bet")?;
    require_caller_is_seat_player(context, table, input.seat_index, "bet")?;
    state_machine::apply_bet(table, input.seat_index, input.amount, events)
}

/// `reset_for_next_hand` — 显式重置桌台到 WAITING 状态。
///
/// 不接受 args（空 slice），直接调用 `state_machine::reset_for_next_hand`。
/// 用于端到端测试验证完整对局生命周期：create_table → join_table → start_hand
/// → reset_for_next_hand。生产环境正常流程中由 settle/end_without_showdown 内部触发。
fn dispatch_reset_for_next_hand(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !args.is_empty() {
        return Err(PokerL1Error::Serialization(
            "reset_for_next_hand does not accept arguments".into(),
        ));
    }
    require_caller_is_creator(context, table, "reset_for_next_hand")?;
    state_machine::reset_for_next_hand(table, events)
}

/// `addon` — 玩家追加筹码（下一手生效）。
///
/// 调用 `state_machine::apply_addon`：累加 `pending_addon`，不动 `stack`。
/// 在下一手 `reset_for_next_hand` 第一阶段合并到 `stack`。
///
/// 资金来源由 Texas Poker precompile 统一校验：executor 传入 NativeCoin
/// UTXO，precompile 按 [`required_funding`] 消费 amount、生成确定性 change，
/// 并校验 `chip_pool` 的 TableVault 转移与实际到账一致。
fn dispatch_addon(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: AddonArgs = decode_args(args, "addon")?;
    require_caller_is_seat_player(context, table, input.seat_index, "addon")?;
    state_machine::apply_addon(table, input.seat_index, input.amount, events)
}

/// `rebuy` — 玩家重购（立即生效）。
///
/// 调用 `state_machine::apply_rebuy`：直接改 `stack`（影响下一动作可用筹码）。
///
/// 资金来源与 `addon` 一样由 Texas Poker precompile 消费 NativeCoin UTXO；
/// rebuy 金额立即进入 `stack` 和完整 TableVault `chip_pool`，不进入
/// 仅记录 pending addon 子集的 `addon_pool`。
fn dispatch_rebuy(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: RebuyArgs = decode_args(args, "rebuy")?;
    require_caller_is_seat_player(context, table, input.seat_index, "rebuy")?;
    state_machine::apply_rebuy(table, input.seat_index, input.amount, events)
}

/// `request_leave_after_hand` — 玩家请求「下局开始前离场」（toggle）。
///
/// 权限：`caller == seat.player`（与 leave_table / addon 一致）。
/// 允许在任意 round_state 调用（玩家可在对局进行中预约离场）。
///
/// 实际离场（座位清空 + 退款）在下一手 `reset_for_next_hand` 内强制执行；
/// 本次 toggle 本身仍是独立状态转换，会产出 MethodKind=21 的 ProveTask。
fn dispatch_request_leave_after_hand(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "request_leave_after_hand")?;
    require_caller_is_seat_player(context, table, input.seat_index, "request_leave_after_hand")?;
    state_machine::apply_request_leave(table, input.seat_index, events)
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use crate::signature::TaggedPubkey;

    fn make_table() -> TexasPokerTable {
        // creator 设为 [0xAA;20]，与 make_context().caller 一致，
        // 使需要 creator 权限的测试（kick/start_hand/reset）天然通过。
        TexasPokerTable::new(
            ObjectID::new([0xFF; 20], 0),
            "test".to_string(),
            [0xAA; 20],
            6,
            50,
            100,
        )
    }

    fn make_context() -> DispatchContext {
        DispatchContext {
            caller: [0xAA; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0xBB; 32],
            },
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
    }

    /// 构造指定 caller 的 context（用于多玩家权限校验测试）。
    fn make_context_as(caller: Address) -> DispatchContext {
        let mut ctx = make_context();
        ctx.caller = caller;
        ctx
    }

    fn decode_output(result: &DispatchResult) -> super::super::prove_task::L1DispatchOutput {
        borsh::from_slice(&result.return_value).expect("dispatch output 应是有效 borsh")
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
        assert_eq!(sels.len(), 23, "应有 23 个 selector");
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
        let result = dispatch(&ctx, &mut table, &unknown, &[]);
        assert!(matches!(
            result,
            Err(PokerL1Error::UnknownContractMethod { .. })
        ));
    }

    #[test]
    fn zero_argument_admin_methods_reject_trailing_bytes_atomically() {
        let context = make_context();
        for (name, selector) in [
            ("start_hand", selectors::start_hand()),
            ("reset_for_next_hand", selectors::reset_for_next_hand()),
        ] {
            let mut table = make_table();
            let before = table.clone();
            let error = dispatch(&context, &mut table, &selector, &[0x01])
                .expect_err("zero-argument admin method must reject trailing bytes");
            assert!(error.to_string().contains("does not accept arguments"));
            assert_eq!(table, before, "{name} argument rejection must be atomic");
        }
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
        let result = dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes).unwrap();

        assert_eq!(table.name, "new_game");
        assert_eq!(table.max_players, 9);
        assert_eq!(table.small_blind, 25);
        assert_eq!(table.big_blind, 50);
        assert_eq!(table.pot, 0, "create_table 应覆写为初始状态");
        assert!(!result.modified_objects.is_empty());
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
        let result = dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn dispatch_join_table_then_leave_table() {
        let mut table = make_table();
        // P0-2：join_table 校验 caller == player，故 player 须用自己的 context 调用。
        let player_addr: Address = [0x11; 20];
        let ctx_p1 = make_context_as(player_addr);
        // WAITING 状态允许 join_table
        let join_args = JoinTableArgs {
            player: player_addr,
            buy_in: 1000,
            pk: ECPoint(G1Projective::identity()),
        };
        let join_bytes = borsh::to_vec(&join_args).unwrap();
        dispatch(&ctx_p1, &mut table, &selectors::join_table(), &join_bytes).unwrap();
        assert_eq!(table.occupied_count(), 1);
        assert_eq!(table.seats[0].stack, 1000);

        // leave_table（seat 0 的玩家本人调用）
        let leave_args = LeaveTableArgs { seat_index: 0 };
        let leave_bytes = borsh::to_vec(&leave_args).unwrap();
        dispatch(&ctx_p1, &mut table, &selectors::leave_table(), &leave_bytes).unwrap();
        assert_eq!(table.occupied_count(), 0);
    }

    #[test]
    fn dispatch_leave_table_rejects_pool_underflow_without_mutation() {
        let player: Address = [0x11; 20];
        let context = make_context_as(player);
        let mut table = make_table();
        table.seats[0].player = player;
        table.seats[0].stack = 10;
        table.seats[0].pending_addon = 5;
        table.chip_pool = 9;
        table.addon_pool = 5;
        let before = table.clone();
        let mut events = vec![];
        let args = borsh::to_vec(&LeaveTableArgs { seat_index: 0 }).unwrap();

        let error = dispatch_leave_table(&context, &mut table, &args, &mut events).unwrap_err();

        assert!(error.to_string().contains("chip_pool underflow"));
        assert_eq!(table, before, "failed refund must be atomic");
        assert!(events.is_empty());
    }

    /// 端到端：完整一局生命周期 create_table → join_table ×2 → start_hand → reset_for_next_hand。
    ///
    /// 验证 4 个核心入口通过 dispatch 路由串联：
    /// 1. `create_table` 覆写桌台为初始 WAITING 状态
    /// 2. `join_table` 让 2 名玩家入座（pk 必须不同，避免 is_pk_registered 冲突）
    /// 3. `start_hand` 投盲注 + 设置加密牌组 + 进入 shuffle 阶段
    /// 4. `reset_for_next_hand` 清理状态回到 WAITING（模拟一局结束后的重置）
    #[test]
    fn e2e_full_hand_lifecycle_create_join_start_reset() {
        // P0-2：create_table/start_hand/reset 需 creator 权限；join 需 player 本人。
        let ctx_creator = make_context(); // caller = [0xAA;20] = make_table 的 creator
        let mut table = make_table();

        // ========== Step 1: create_table ==========
        let create_args = CreateTableArgs {
            name: "e2e_table".into(),
            max_players: 2,
            small_blind: 10,
            big_blind: 20,
        };
        let create_bytes = borsh::to_vec(&create_args).unwrap();
        dispatch(
            &ctx_creator,
            &mut table,
            &selectors::create_table(),
            &create_bytes,
        )
        .unwrap();
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 1);

        // 验证 WAITING 状态 + 参数已设置
        assert_eq!(table.name, "e2e_table");
        assert_eq!(table.max_players, 2);
        assert_eq!(table.small_blind, 10);
        assert_eq!(table.big_blind, 20);
        assert_eq!(table.round_state, super::super::constants::ROUND_WAITING);
        assert_eq!(table.occupied_count(), 0);
        assert_eq!(table.pot, 0);

        // ========== Step 2a: join_table player 1 ==========
        let p1: Address = [0x11; 20];
        let join1 = JoinTableArgs {
            player: p1,
            buy_in: 1000,
            pk: ECPoint(G1Projective::identity()),
        };
        dispatch(
            &make_context_as(p1),
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&join1).unwrap(),
        )
        .unwrap();
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 2);
        assert_eq!(table.occupied_count(), 1);
        assert_eq!(table.seats[0].player, [0x11; 20]);
        assert_eq!(table.seats[0].stack, 1000);

        // ========== Step 2b: join_table player 2（pk 必须不同）==========
        let p2: Address = [0x22; 20];
        let join2 = JoinTableArgs {
            player: p2,
            buy_in: 2000,
            pk: ECPoint(G1Projective::generator()),
        };
        dispatch(
            &make_context_as(p2),
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&join2).unwrap(),
        )
        .unwrap();
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 3);
        assert_eq!(table.occupied_count(), 2);
        assert_eq!(table.seats[1].player, [0x22; 20]);
        assert_eq!(table.seats[1].stack, 2000);

        // ========== Step 3: start_hand（creator 发起）==========
        dispatch(&ctx_creator, &mut table, &selectors::start_hand(), &[]).unwrap();
        assert_eq!(table.hand_id, 1, "HandStarted 后 hand_id 应递增");
        assert_eq!(table.call_seq, 4);

        // 验证：进入 SHUFFLE 阶段，加密牌组已初始化（52 张）。
        //
        // 注意：start_hand 不会立即改变 round_state（仍为 ROUND_WAITING），
        // 因为 round_state 仅在下注阶段开始时切换到 ROUND_PREFLOP。
        // 对局已开始的标志是 shuffle_state.phase == SHUFFLE_PHASE_BEFORE_PREFLOP
        // 且 deck_state.encrypted 已填充 52 张加密牌。
        assert_eq!(
            table.shuffle_state.phase,
            super::super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP,
            "start_hand 后应进入 shuffle BEFORE_PREFLOP 阶段"
        );
        assert_eq!(
            table.deck_state.encrypted.len(),
            52,
            "start_hand 应设置 52 张加密牌"
        );

        // ========== Step 4: reset_for_next_hand（creator 发起）==========
        dispatch(
            &ctx_creator,
            &mut table,
            &selectors::reset_for_next_hand(),
            &[],
        )
        .unwrap();
        assert_eq!(table.hand_id, 1, "局内后续调用不应改变 hand_id");
        assert_eq!(table.call_seq, 5);

        // 验证：回到 WAITING 状态，所有对局状态清理
        assert_eq!(table.round_state, super::super::constants::ROUND_WAITING);
        assert_eq!(table.pot, 0, "reset 后 pot 应清零");
        assert_eq!(table.community_cards.len(), 0);
        assert!(table.side_pots.is_empty());
        assert_eq!(
            table.deck_state.encrypted.len(),
            52,
            "reset 后重新初始化 52 张牌"
        );
        assert_eq!(
            table.shuffle_state.phase,
            super::super::constants::SHUFFLE_PHASE_NONE,
            "reset 后 shuffle 阶段应清零"
        );
        assert_eq!(
            table.reveal_token_state.reveal_phase,
            super::super::constants::REVEAL_PHASE_NONE
        );
        assert_eq!(
            table.reconstruct_state.phase,
            super::super::constants::RECONSTRUCT_PHASE_NONE
        );
        // 玩家仍在座位上（reset 不踢人，除非 stack=0）
        assert_eq!(table.occupied_count(), 2, "reset 不应踢出有筹码的玩家");
        assert_eq!(table.seats[0].stack, 1000);
        assert_eq!(table.seats[1].stack, 2000);
        // bet/total_bet 应清零
        assert_eq!(table.seats[0].bet, 0);
        assert_eq!(table.seats[0].total_bet, 0);
        assert_eq!(table.seats[1].bet, 0);
        assert_eq!(table.seats[1].total_bet, 0);
    }

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
        table.chip_pool = 1_500;

        let args = KickPlayerArgs {
            seat_index: 0,
            reason: 0,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        dispatch(&ctx, &mut table, &selectors::kick_player(), &args_bytes).unwrap();
        assert!(table.seats[0].folded);
        assert!(table.seats[0].left_during_hand);
        assert_eq!(table.seats[0].stack, 0);
    }

    #[test]
    fn dispatch_tick_with_empty_args_uses_consensus_timestamp() {
        let ctx = make_context();
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        // 空 args 调用 tick：时间来自共识 context，并可触发无需等待的 start_hand。
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &[]).unwrap();
        let output = decode_output(&result);
        let task = output
            .prove_task
            .expect("自动 start_hand 的 tick 必须产生 task");
        assert_eq!(task.method_kind, 4);
        assert_eq!(
            task.method_input,
            super::super::prove_task::MethodInput::Empty
        );
        assert_eq!(task.hand_id, 1);
        assert_eq!(task.call_seq, 1);
        assert_eq!(table.hand_id, 1);
        assert_eq!(table.call_seq, 1);
        assert_eq!(
            table.shuffle_state.phase,
            super::super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP
        );
    }

    #[test]
    fn dispatch_tick_without_state_change_has_no_task_or_sequence_increment() {
        let ctx = make_context();
        let mut table = make_table();
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &[]).unwrap();
        let output = decode_output(&result);
        assert!(output.prove_task.is_none());
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 0);
    }

    #[test]
    fn dispatch_tick_timestamp_change_produces_task() {
        let ctx = make_context();
        let mut table = make_table();
        table.shuffle_state.phase = super::super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP;
        table.shuffle_state.pending_players = vec![0];
        table.shuffle_state.current_shuffler = Some(0);
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &[]).unwrap();
        let task = decode_output(&result)
            .prove_task
            .expect("tick 修改超时起点后必须产生 task");
        assert_eq!(table.timestamps.shuffle_started_at, ctx.block_timestamp);
        assert_eq!(table.version, 1);
        assert_eq!(table.call_seq, 1);
        assert_eq!(task.method_kind, 4);
        assert_eq!(task.call_seq, 1);
    }

    #[test]
    fn dispatch_tick_rejects_timestamp_different_from_consensus() {
        let ctx = make_context();
        let mut table = make_table();
        let args = TickArgs { now_ms: 5_000_000 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &args_bytes);
        assert!(result.is_err());
        assert_eq!(table, make_table());
    }

    #[test]
    fn dispatch_tick_accepts_legacy_timestamp_equal_to_consensus() {
        let ctx = make_context();
        let mut table = make_table();
        let args = TickArgs {
            now_ms: ctx.block_timestamp,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &args_bytes);
        assert!(result.is_ok());
    }

    fn make_auto_fold_table() -> TexasPokerTable {
        let mut table = make_table();
        table.round_state = super::super::constants::ROUND_PREFLOP;
        table.betting_round = Some(super::super::betting::BettingRound::new(100, 100));
        table.current_turn = Some(0);
        for index in 0..3 {
            table.seats[index].player = [u8::try_from(index + 1).unwrap(); 20];
            table.seats[index].stack = 1_000;
        }
        table
    }

    #[test]
    fn dispatch_auto_fold_rejects_before_consensus_timeout() {
        let ctx = make_context();
        let mut table = make_auto_fold_table();
        table.timestamps.betting_started_at = ctx.block_timestamp - 1;
        let pre = table.clone();
        let args = borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap();

        let result = dispatch(&ctx, &mut table, &selectors::auto_fold(), &args);

        assert!(result.is_err());
        assert_eq!(table, pre);
    }

    #[test]
    fn dispatch_auto_fold_rejects_while_time_bank_remains() {
        let ctx = make_context();
        let mut table = make_auto_fold_table();
        table.timestamps.betting_started_at = 1;
        table.seats[0].time_bank_ms = 1;
        let pre = table.clone();
        let args = borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap();

        let result = dispatch(&ctx, &mut table, &selectors::auto_fold(), &args);

        assert!(result.is_err());
        assert_eq!(table, pre);
    }

    #[test]
    fn dispatch_auto_fold_accepts_expired_turn_without_time_bank() {
        let ctx = make_context();
        let mut table = make_auto_fold_table();
        table.timestamps.betting_started_at = 1;
        table.seats[0].time_bank_ms = 0;
        let args = borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap();

        let result = dispatch(&ctx, &mut table, &selectors::auto_fold(), &args);

        assert!(result.is_ok());
        assert!(table.seats[0].folded);
        assert_eq!(table.call_seq, 1);
    }

    // ========== P0-1 / P0-2 回归测试 ==========

    /// P0-2：非座位玩家调用 fold 应被拒绝。
    #[test]
    fn dispatch_fold_rejects_non_seat_player() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        table.round_state = super::super::constants::ROUND_PREFLOP;
        table.betting_round = Some(super::super::betting::BettingRound::new(100, 100));
        table.current_turn = Some(0);

        // seat 0 的玩家是 [0x01;20]，用 [0x99;20] 冒充调用应失败
        let ctx_impersonator = make_context_as([0x99; 20]);
        let args = SeatIndexArgs { seat_index: 0 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_impersonator,
            &mut table,
            &selectors::fold(),
            &args_bytes,
        );
        assert!(result.is_err(), "非座位玩家不应能 fold 别人的牌");
    }

    /// P0-2：非 creator 调用 kick_player 应被拒绝。
    #[test]
    fn dispatch_kick_rejects_non_creator() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 500;

        // make_table 的 creator = [0xAA;20]，用 [0x99;20] 调用应失败
        let ctx_non_creator = make_context_as([0x99; 20]);
        let args = KickPlayerArgs {
            seat_index: 0,
            reason: super::super::constants::KICK_REASON_ADMIN,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_non_creator,
            &mut table,
            &selectors::kick_player(),
            &args_bytes,
        );
        assert!(result.is_err(), "非 creator 不应能 kick 玩家");
    }

    /// P0-1：kick_player 越界 seat_index 应返回错误而非 panic。
    #[test]
    fn dispatch_kick_rejects_out_of_range_seat() {
        let ctx = make_context(); // caller = [0xAA;20] = creator
        let mut table = make_table(); // max_players = 6
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 500;

        // seat_index=200 远超 max_players=6，应返回 Err 而非 panic
        let args = KickPlayerArgs {
            seat_index: 200,
            reason: super::super::constants::KICK_REASON_ADMIN,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::kick_player(), &args_bytes);
        assert!(result.is_err(), "越界 seat_index 应返回错误而非 panic");
    }

    // ========== request_leave_after_hand 单元测试 ==========

    /// 辅助：构造一个已入座的 table（seat 0 = p1，seat 1 = p2）。
    fn make_table_with_two_players() -> TexasPokerTable {
        let mut table = make_table();
        table.seats[0].player = [0x11; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x22; 20];
        table.seats[1].stack = 2000;
        // 同步 chip_pool（join 时 buy_in 计入），便于后续资金账断言
        table.chip_pool = 3000;
        table
    }

    /// toggle 测试：连续两次调用 request_leave_after_hand，第二次 want_leave 应回到 false。
    #[test]
    fn request_leave_toggles_flag() {
        let mut table = make_table_with_two_players();
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = SeatIndexArgs { seat_index: 0 };
        let args_bytes = borsh::to_vec(&args).unwrap();

        // 第一次：false → true（预约离场）
        let first = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::request_leave_after_hand(),
            &args_bytes,
        )
        .unwrap();
        let first_task = decode_output(&first)
            .prove_task
            .expect("request_leave_after_hand 状态变化必须产生 task");
        assert_eq!(first_task.method_kind, 21);
        assert_eq!(
            first_task.method_input,
            super::super::prove_task::MethodInput::RequestLeaveAfterHand { seat_index: 0 }
        );
        assert_eq!(first_task.call_seq, 1);
        assert!(
            table.seats[0].want_leave,
            "第一次调用后 want_leave 应为 true"
        );

        // 第二次：true → false（取消预约）
        dispatch(
            &ctx_p1,
            &mut table,
            &selectors::request_leave_after_hand(),
            &args_bytes,
        )
        .unwrap();
        assert_eq!(table.call_seq, 2);
        assert!(
            !table.seats[0].want_leave,
            "第二次调用后 want_leave 应回到 false（toggle）"
        );

        // 其余座位不受影响
        assert!(!table.seats[1].want_leave);
    }

    /// 权限校验：非 seat player 调用应失败。
    #[test]
    fn request_leave_rejects_non_seat_player() {
        let mut table = make_table_with_two_players();
        // seat 0 玩家是 [0x11;20]，用 [0x99;20] 冒充调用应失败
        let ctx_impersonator = make_context_as([0x99; 20]);
        let args = SeatIndexArgs { seat_index: 0 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_impersonator,
            &mut table,
            &selectors::request_leave_after_hand(),
            &args_bytes,
        );
        assert!(result.is_err(), "非座位玩家不应能为他人的座位预约离场");
        assert!(
            !table.seats[0].want_leave,
            "失败调用不应改变 want_leave 标志"
        );
    }

    /// 对局中调用：在 ROUND_PREFLOP 状态调用应成功（验证「任意时刻可预约」）。
    #[test]
    fn request_leave_works_mid_hand() {
        let mut table = make_table_with_two_players();
        // 模拟对局进行中
        table.round_state = super::super::constants::ROUND_PREFLOP;
        table.betting_round = Some(super::super::betting::BettingRound::new(100, 100));
        table.current_turn = Some(0);

        let ctx_p1 = make_context_as([0x11; 20]);
        let args = SeatIndexArgs { seat_index: 0 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::request_leave_after_hand(),
            &args_bytes,
        );
        assert!(result.is_ok(), "对局中应可预约离场: {result:?}");
        assert!(table.seats[0].want_leave);
        // 对局状态不被破坏
        assert_eq!(table.round_state, super::super::constants::ROUND_PREFLOP);
    }

    /// 越界 seat_index 应返回错误而非 panic。
    #[test]
    fn request_leave_rejects_out_of_range_seat() {
        let mut table = make_table_with_two_players();
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = SeatIndexArgs { seat_index: 200 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::request_leave_after_hand(),
            &args_bytes,
        );
        assert!(result.is_err(), "越界 seat_index 应返回错误而非 panic");
    }

    /// reset_for_next_hand 强制执行：设置 want_leave → reset → seat 清空 + chip_pool 扣减。
    #[test]
    fn reset_for_next_hand_enforces_want_leave() {
        let mut table = make_table_with_two_players();
        // p1 预约离场
        table.seats[0].want_leave = true;

        // reset 前：2 名玩家，chip_pool = 3000
        assert_eq!(table.occupied_count(), 2);
        assert_eq!(table.chip_pool, 3000);

        state_machine::reset_for_next_hand(&mut table, &mut Vec::new()).unwrap();

        // reset 后：seat 0 被清空（退款 1000），seat 1 保留
        assert_eq!(table.occupied_count(), 1, "want_leave 玩家应被踢出");
        assert_eq!(table.seats[0].player, super::super::types::EMPTY_PLAYER);
        assert_eq!(table.seats[0].stack, 0);
        assert_eq!(table.seats[1].player, [0x22; 20], "未预约的玩家应保留");
        assert_eq!(table.seats[1].stack, 2000);
        // chip_pool 扣减退款（3000 - 1000 = 2000）
        assert_eq!(table.chip_pool, 2000, "chip_pool 应扣减已退款的 stack");
    }

    /// 资金账平衡 + 事件：join (buy_in=X) → request_leave → reset
    /// → 退款 X 后 chip_pool 回到 join 前，并发出 PlayerRefund + PlayerLeft。
    #[test]
    fn request_leave_full_lifecycle_refund_and_events() {
        let ctx_creator = make_context(); // caller = [0xAA;20] = creator
        let mut table = make_table();

        // create_table（creator 发起）
        let create_args = CreateTableArgs {
            name: "leave-test".into(),
            max_players: 4,
            small_blind: 10,
            big_blind: 20,
        };
        dispatch(
            &ctx_creator,
            &mut table,
            &selectors::create_table(),
            &borsh::to_vec(&create_args).unwrap(),
        )
        .unwrap();
        assert_eq!(table.chip_pool, 0, "create_table 后 chip_pool 应为 0");

        // p1 join_table（buy_in = 1500）
        let p1: Address = [0x11; 20];
        dispatch(
            &make_context_as(p1),
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&JoinTableArgs {
                player: p1,
                buy_in: 1500,
                pk: ECPoint(G1Projective::identity()),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(table.chip_pool, 1500);

        // p2 join_table（buy_in = 2500）
        let p2: Address = [0x22; 20];
        dispatch(
            &make_context_as(p2),
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&JoinTableArgs {
                player: p2,
                buy_in: 2500,
                pk: ECPoint(G1Projective::generator()),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(table.chip_pool, 4000);

        // p1 预约离场（任意时刻，此处 WAITING 状态）
        dispatch(
            &make_context_as(p1),
            &mut table,
            &selectors::request_leave_after_hand(),
            &borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap(),
        )
        .unwrap();
        assert!(table.seats[0].want_leave);

        // reset：强制执行 p1 离场
        let mut events = Vec::new();
        state_machine::reset_for_next_hand(&mut table, &mut events).unwrap();

        // 资金账：chip_pool 扣减退款 1500 → 4000 - 1500 = 2500
        assert_eq!(table.chip_pool, 2500);
        assert_eq!(table.seats[0].player, super::super::types::EMPTY_PLAYER);
        assert_eq!(table.seats[1].player, p2);

        // 事件：应包含 PlayerRefund(seat 0, 1500) + PlayerLeft(seat 0)
        let has_refund = events.iter().any(|e| {
            matches!(
                e,
                super::super::events::TexasPokerEvent::PlayerRefund {
                    seat_index: 0,
                    amount: 1500,
                    ..
                }
            )
        });
        let has_left = events.iter().any(|e| {
            matches!(
                e,
                super::super::events::TexasPokerEvent::PlayerLeft { seat_index: 0, .. }
            )
        });
        assert!(has_refund, "应发出 seat 0 的 PlayerRefund(1500) 事件");
        assert!(has_left, "应发出 seat 0 的 PlayerLeft 事件");
    }

    /// want_leave=false 的玩家在 reset 后不应被踢出（回归：不应误清）。
    #[test]
    fn reset_does_not_remove_players_without_leave_request() {
        let mut table = make_table_with_two_players();
        // 无人预约离场
        assert!(!table.seats[0].want_leave);
        assert!(!table.seats[1].want_leave);

        state_machine::reset_for_next_hand(&mut table, &mut Vec::new()).unwrap();

        // 两名玩家都应保留（stack > 0）
        assert_eq!(table.occupied_count(), 2);
        assert_eq!(table.seats[0].player, [0x11; 20]);
        assert_eq!(table.seats[1].player, [0x22; 20]);
    }

    // ========== fold_with_proof 单元测试 ==========

    /// 辅助：构造一个处于下注轮、3 名玩家的桌台。
    /// - seat 0/1/2 各有 stack 与已下注 total_bet
    /// - round_state = PREFLOP，betting_round 已设置，current_turn = turn
    /// - aggregated_pk = generator（= seat.pk，方便验证「移除后变为 None」）
    fn make_betting_table_with_players(turn: u8, set_aggregated_pk: bool) -> TexasPokerTable {
        let mut table = make_table();
        table.round_state = super::super::constants::ROUND_PREFLOP;
        table.betting_round = Some(super::super::betting::BettingRound::new(100, 100));
        table.current_turn = Some(turn);

        // 3 名玩家，pk 都用 generator（aggregated_pk = generator 时移除任一 pk → None）
        let g = G1Projective::generator();
        for i in 0..3u8 {
            table.seats[i as usize].player = [0x11 + i; 20];
            table.seats[i as usize].stack = 1000;
            table.seats[i as usize].total_bet = 100;
            table.seats[i as usize].pk = ECPoint(g);
        }
        if set_aggregated_pk {
            table.deck_state.aggregated_pk = Some(ECPoint(g));
        }
        // 模拟已发牌（52 张加密牌），c1 = generator（DLEq verify 强制 c1 不变）
        table.deck_state.encrypted = (0..52)
            .map(|_| ElGamalCiphertext {
                c1: g,
                c2: g, // 占位，skip_remask=true 不验证
            })
            .collect();
        table
    }

    /// 辅助：构造一个空的 DLEqProof<LeaveKind>（skip_remask=true 时不会真正验证）。
    fn empty_fold_proof() -> DLEqProof<DefaultCurve, LeaveKind> {
        // _kind 字段私有，必须用 from_parts 构造（DLEqProof 不 derive Default）。
        // skip_remask=true（默认 dev config）时 verify 不执行，字段值不影响测试。
        // 零标量复用 utils::scalar_zero()（封装了 ff::Field trait 的 ZERO 常量）。
        let zero = super::super::utils::scalar_zero();
        DLEqProof::from_parts(
            vec![],                   // per_card_commitments
            G1Projective::identity(), // commitment_pk（C::Point）
            zero,                     // response（C::Scalar = BlsScalar）
            zero,                     // nonce（C::Scalar = BlsScalar）
        )
    }

    fn empty_remask_proof() -> DLEqProof<DefaultCurve, RemaskKind> {
        let zero = super::super::utils::scalar_zero();
        DLEqProof::from_parts(vec![], G1Projective::identity(), zero, zero)
    }

    fn empty_schnorr_proof()
    -> poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<DefaultCurve>
    {
        poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof {
            commitment: G1Projective::identity(),
            responses: vec![],
        }
    }

    fn empty_shuffle_proof() -> ShuffleProof {
        let schnorr = empty_schnorr_proof();
        let legacy = poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof {
            sum_c1_commit: G1Projective::identity(),
            sum_c2_commit: G1Projective::identity(),
            combined_schnorr_proof: schnorr.clone(),
            sum_c1_schnorr_proof: schnorr.clone(),
            sum_c2_schnorr_proof: schnorr,
            nonce: super::super::utils::scalar_zero(),
        };
        ShuffleProof::LegacyV1(legacy)
    }

    fn empty_reconstruct_v3() -> (
        ReconstructionV3Statement<DefaultCurve>,
        ReconstructProofV3<DefaultCurve>,
    ) {
        use poker_protocol::zk_shuffle::bayer_groth::{
            BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument,
        };
        use poker_protocol::zk_shuffle::reconstruction::{
            CrossKeyNegationProof, SlotContributionOrProof,
        };

        let zero = super::super::utils::scalar_zero();
        let identity = G1Projective::identity();
        let generator = super::super::utils::g1_generator();
        let aggregate_pk = generator * super::super::utils::scalar_from_u64(17);
        let owner_pk = generator * super::super::utils::scalar_from_u64(19);
        let cards = vec![
            generator * super::super::utils::scalar_from_u64(23),
            generator * super::super::utils::scalar_from_u64(29),
        ];
        let identity_ciphertext = ElGamalCiphertext {
            c1: identity,
            c2: identity,
        };
        // `build_method_input` validates the strict V3 wire shape even though
        // these dispatch tests never execute the proof. Use a structurally
        // valid public statement and keep only the proof equations as dummies.
        let readable_ciphertext = ElGamalCiphertext::encrypt(
            &cards[0],
            &owner_pk,
            &super::super::utils::scalar_from_u64(31),
        );
        let contributions = vec![
            ElGamalCiphertext::encrypt(
                &identity,
                &aggregate_pk,
                &super::super::utils::scalar_from_u64(37),
            ),
            ElGamalCiphertext::encrypt(
                &identity,
                &aggregate_pk,
                &super::super::utils::scalar_from_u64(41),
            ),
        ];
        let contribution_shuffle_proof = BayerGrothShuffleProof {
            c_permutation: identity,
            c_permuted_powers: identity,
            multi_exponentiation: MultiExponentiationArgument {
                c_alpha: identity,
                c_beta: identity,
                ciphertext_0: identity_ciphertext,
                ciphertext_1: identity_ciphertext,
                alpha_response: vec![zero; 2],
                commitment_response: zero,
                beta: zero,
                beta_blinding_response: zero,
                rerandomization_response: zero,
            },
            product: ProductArgument {
                c_d: identity,
                c_delta: identity,
                c_capital_delta: identity,
                a_response: vec![zero; 2],
                b_response: vec![zero; 2],
                r_response: zero,
                s_response: zero,
            },
        };
        let statement = ReconstructionV3Statement {
            version: 3,
            context_digest: [0; 32],
            reconstruction_epoch: 0,
            prior_state_digest: [0; 32],
            aggregate_pk,
            owner_pk,
            cards,
            user_readable_cards: vec![readable_ciphertext],
            contributions,
        };
        let cross_key = CrossKeyNegationProof {
            commitment_owner_key: identity,
            commitment_contribution_c1: identity,
            commitment_joint_c2: identity,
            response_owner_sk: zero,
            response_contribution_randomness: zero,
        };
        let slot = SlotContributionOrProof {
            commitment_g: [identity; 2],
            commitment_pk: [identity; 2],
            challenges: [zero; 2],
            responses: [zero; 2],
        };
        let proof = ReconstructProofV3 {
            negative_contributions: vec![identity_ciphertext],
            cross_key_proofs: vec![cross_key],
            contribution_shuffle_proof,
            slot_membership_proofs: vec![slot; 2],
        };
        (statement, proof)
    }

    fn crypto_args() -> Vec<([u8; 32], Vec<u8>, u8)> {
        let join = JoinAndShuffleArgs {
            seat_index: 1,
            player: [0x31; 20],
            buy_in: 1_000,
            pk: ECPoint(G1Projective::identity()),
            pk_ownership_proof: vec![1, 2],
            mask_cards: vec![],
            output_cards: vec![],
            remask_proof: empty_remask_proof(),
            shuffle_proof: empty_shuffle_proof(),
        };
        let leave = LeaveWithProofArgs {
            seat_index: 2,
            output_cards: vec![],
            leave_proof: empty_fold_proof(),
        };
        let shuffle = SubmitShuffleV2Args {
            seat_index: 3,
            output_cards: vec![],
            shuffle_proof: empty_shuffle_proof(),
        };
        let reveal = SubmitRevealTokensArgs {
            seat_index: 4,
            assignment_indices: vec![],
            reveal_tokens: vec![],
            proofs: vec![],
        };
        let (statement, proof) = empty_reconstruct_v3();
        let reconstruct = SubmitReconstructDeckArgs {
            seat_index: 5,
            statement,
            proof,
        };
        let fold = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        vec![
            (
                selectors::join_and_shuffle(),
                borsh::to_vec(&join).unwrap(),
                15,
            ),
            (
                selectors::leave_with_proof(),
                borsh::to_vec(&leave).unwrap(),
                16,
            ),
            (
                selectors::submit_shuffle_v2(),
                borsh::to_vec(&shuffle).unwrap(),
                17,
            ),
            (
                selectors::submit_player_reveal_tokens(),
                borsh::to_vec(&reveal).unwrap(),
                18,
            ),
            (
                selectors::submit_reconstruct_deck(),
                borsh::to_vec(&reconstruct).unwrap(),
                19,
            ),
            (
                selectors::fold_with_proof(),
                borsh::to_vec(&fold).unwrap(),
                22,
            ),
        ]
    }

    #[test]
    fn build_method_input_covers_all_23_selectors() {
        let mut cases = vec![
            (
                selectors::create_table(),
                borsh::to_vec(&CreateTableArgs {
                    name: "coverage".into(),
                    max_players: 6,
                    small_blind: 50,
                    big_blind: 100,
                })
                .unwrap(),
                0,
            ),
            (
                selectors::join_table(),
                borsh::to_vec(&JoinTableArgs {
                    player: [0x41; 20],
                    buy_in: 1_000,
                    pk: ECPoint(G1Projective::identity()),
                })
                .unwrap(),
                1,
            ),
            (
                selectors::leave_table(),
                borsh::to_vec(&LeaveTableArgs { seat_index: 1 }).unwrap(),
                2,
            ),
            (selectors::start_hand(), vec![], 3),
            (
                selectors::tick(),
                borsh::to_vec(&TickArgs { now_ms: 123 }).unwrap(),
                4,
            ),
            (selectors::reset_for_next_hand(), vec![], 5),
            (
                selectors::fold(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                6,
            ),
            (
                selectors::check(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                7,
            ),
            (
                selectors::call(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                8,
            ),
            (
                selectors::raise(),
                borsh::to_vec(&RaiseArgs {
                    seat_index: 1,
                    total_bet: 200,
                })
                .unwrap(),
                9,
            ),
            (
                selectors::auto_fold(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                10,
            ),
            (
                selectors::force_fold(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                11,
            ),
            (
                selectors::kick_player(),
                borsh::to_vec(&KickPlayerArgs {
                    seat_index: 1,
                    reason: 2,
                })
                .unwrap(),
                12,
            ),
            (
                selectors::addon(),
                borsh::to_vec(&AddonArgs {
                    seat_index: 1,
                    amount: 500,
                })
                .unwrap(),
                13,
            ),
            (
                selectors::rebuy(),
                borsh::to_vec(&RebuyArgs {
                    seat_index: 1,
                    amount: 500,
                })
                .unwrap(),
                14,
            ),
            (
                selectors::bet(),
                borsh::to_vec(&BetArgs {
                    seat_index: 1,
                    amount: 100,
                })
                .unwrap(),
                20,
            ),
            (
                selectors::request_leave_after_hand(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                21,
            ),
        ];
        cases.extend(crypto_args());
        assert_eq!(cases.len(), 23);
        for (selector, args, expected_kind) in cases {
            let (kind, _) = build_method_input(&selector, &args).unwrap();
            assert_eq!(kind, expected_kind);
        }
    }

    #[test]
    fn crypto_method_inputs_preserve_validated_raw_args() {
        for (selector, raw_args, expected_kind) in crypto_args() {
            let (kind, input) = build_method_input(&selector, &raw_args).unwrap();
            assert_eq!(kind, expected_kind);
            let (seat_index, preserved) = match input {
                super::super::prove_task::MethodInput::JoinAndShuffle {
                    seat_index,
                    raw_args,
                    ..
                }
                | super::super::prove_task::MethodInput::LeaveWithProof {
                    seat_index,
                    raw_args,
                }
                | super::super::prove_task::MethodInput::SubmitShuffleV2 {
                    seat_index,
                    raw_args,
                }
                | super::super::prove_task::MethodInput::SubmitPlayerRevealTokens {
                    seat_index,
                    raw_args,
                }
                | super::super::prove_task::MethodInput::SubmitReconstructDeck {
                    seat_index,
                    raw_args,
                }
                | super::super::prove_task::MethodInput::FoldWithProof {
                    seat_index,
                    raw_args,
                } => (seat_index, raw_args),
                other => panic!("crypto selector 映射到了错误 variant: {other:?}"),
            };
            assert!(seat_index < 6);
            assert_eq!(preserved, raw_args);
        }
    }

    #[test]
    fn crypto_selectors_reject_seat_only_substitution() {
        let seat_only = borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap();
        for (selector, _, _) in crypto_args() {
            assert!(
                build_method_input(&selector, &seat_only).is_err(),
                "crypto selector 不得把 SeatIndexArgs 当作完整参数"
            );
        }
    }

    /// 基本流程：下注中 → p1 fold_with_proof → folded=true + pk 已从 aggregated_pk 移除
    /// + deck 已替换 + reveal assignments 中无 p1（下注轮本就为空）+ total_bet 保留。
    #[test]
    fn fold_with_proof_basic_flow() {
        let mut table = make_betting_table_with_players(0, true);
        let agg_pk_before = table.deck_state.aggregated_pk;
        let deck_before = table.deck_state.encrypted.clone();

        let ctx_p1 = make_context_as([0x11; 20]);
        // output_cards 用一个新的占位牌组（与 deck_before 不同，验证替换生效）
        let g = G1Projective::generator();
        let output_cards: Vec<ElGamalCiphertext> = (0..52)
            .map(|_| ElGamalCiphertext {
                c1: g,
                c2: g + g, // 不同于 deck_before 的 c2=g
            })
            .collect();
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: output_cards.clone(),
            fold_proof: empty_fold_proof(),
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &args_bytes,
        )
        .unwrap();
        let task = decode_output(&result)
            .prove_task
            .expect("fold_with_proof 状态变化必须产生 task");
        assert_eq!(task.method_kind, 22);
        assert_eq!(task.call_seq, 1);
        assert_eq!(
            task.method_input,
            super::super::prove_task::MethodInput::FoldWithProof {
                seat_index: 0,
                raw_args: args_bytes,
            }
        );

        // folded 标记
        assert!(table.seats[0].folded, "folded 应为 true");
        assert!(table.seats[0].acted_this_round);
        // 关键：total_bet / bet / stack / pk 保留（side-pot 记账）
        assert_eq!(table.seats[0].total_bet, 100, "total_bet 应保留");
        assert_eq!(table.seats[0].stack, 1000, "stack 应保留");
        assert_eq!(
            table.seats[0].pk,
            ECPoint(G1Projective::generator()),
            "seat.pk 应保留（不置 identity）"
        );
        assert!(
            !table.seats[0].left_during_hand,
            "left_during_hand 不应设置"
        );

        // aggregated_pk 已移除 p1.pk（移除后可能为 None 或不同点）
        assert_ne!(
            table.deck_state.aggregated_pk, agg_pk_before,
            "aggregated_pk 应已移除 p1 的 pk"
        );

        // encrypted deck 已替换为 output_cards
        assert_eq!(
            table.deck_state.encrypted.len(),
            52,
            "deck 大小不变（52 张）"
        );
        assert_ne!(
            table.deck_state.encrypted[0].c2, deck_before[0].c2,
            "deck 应已被 output_cards 替换"
        );
        // c1 不变（DLEq 不变量）
        assert_eq!(table.deck_state.encrypted[0].c1, deck_before[0].c1);

        // reveal_token_state.assignments 中无 p1（下注轮本就为空）
        for a in &table.reveal_token_state.assignments {
            assert!(
                !super::super::state_machine::is_in_list(&a.pending_players, 0),
                "p1 不应在任何 reveal pending_players 中"
            );
        }
    }

    /// 权限校验：非 seat player 调用应失败。
    #[test]
    fn fold_with_proof_rejects_non_seat_player() {
        let mut table = make_betting_table_with_players(0, true);
        let ctx_impersonator = make_context_as([0x99; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_impersonator,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(result.is_err(), "非座位玩家不应能 fold_with_proof");
        assert!(!table.seats[0].folded, "失败调用不应改变 folded 标志");
    }

    /// 非下注轮拒绝：在 WAITING 状态调用应失败。
    #[test]
    fn fold_with_proof_rejects_waiting_state() {
        let mut table = make_table_with_two_players();
        // round_state = WAITING（make_table 默认），betting_round = None
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(
            result.is_err(),
            "WAITING 状态不应能 fold_with_proof（应在下注轮）"
        );
    }

    /// 非该玩家行动轮拒绝：current_turn != seat_index 应失败。
    #[test]
    fn fold_with_proof_rejects_not_turn() {
        // current_turn = 1，但调用 seat 0
        let mut table = make_betting_table_with_players(1, true);
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(result.is_err(), "非该玩家行动轮不应能 fold_with_proof");
    }

    /// 越界 seat_index 应返回错误而非 panic。
    #[test]
    fn fold_with_proof_rejects_out_of_range_seat() {
        // current_turn 设为远超 max_players 的值，使 is_player_turn 为 false 不会先触发
        let mut table = make_betting_table_with_players(200, false);
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 200,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(result.is_err(), "越界 seat_index 应返回错误而非 panic");
    }

    /// 重复 fold 拒绝：已 folded 的 seat 再次调用应失败。
    #[test]
    fn fold_with_proof_rejects_already_folded() {
        let mut table = make_betting_table_with_players(0, true);
        table.seats[0].folded = true; // 预设已 folded

        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(result.is_err(), "已 folded 的座位不应再次 fold_with_proof");
    }

    /// last-player-standing：fold 后只剩 1 活跃玩家 → 触发 end_without_showdown（pot 分配）。
    #[test]
    fn fold_with_proof_last_player_standing_ends_hand() {
        // 2 名玩家（只有 seat 0 和 1 入座），p1 fold_with_proof 后只剩 p2 → 结算
        let mut table = make_table();
        table.round_state = super::super::constants::ROUND_PREFLOP;
        table.betting_round = Some(super::super::betting::BettingRound::new(100, 100));
        table.current_turn = Some(0);
        table.seats[0].player = [0x11; 20];
        table.seats[0].stack = 1000;
        table.seats[0].total_bet = 100;
        table.seats[0].pk = ECPoint(G1Projective::generator());
        table.seats[1].player = [0x22; 20];
        table.seats[1].stack = 1000;
        table.seats[1].total_bet = 100;
        table.seats[1].pk = ECPoint(G1Projective::generator());
        table.deck_state.aggregated_pk = Some(table.seats[0].pk);
        let g = G1Projective::generator();
        table.deck_state.encrypted = (0..52)
            .map(|_| ElGamalCiphertext { c1: g, c2: g })
            .collect();
        // Prior-round pot plus live current-round bets. Terminal fold must
        // collect the live bets before payout instead of clearing them in reset.
        table.pot = 200;
        table.seats[0].bet = 25;
        table.seats[1].bet = 75;

        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        )
        .unwrap();

        // end_without_showdown：p2（seat 1）独得 pot，随后 reset_for_next_hand 清理 folded 标志。
        // （reset 第二阶段会把所有 seat.folded 重置为 false，故此处不能断言 folded=true）
        assert_eq!(
            table.seats[1].stack,
            1000 + 300,
            "p2 应独得 prior pot + current-round bets（end_without_showdown）"
        );
        assert_eq!(table.pot, 0, "pot 应清零");
        // reset 后回到 WAITING
        assert_eq!(table.round_state, super::super::constants::ROUND_WAITING);
        // p1 仍在座位上（reset 不踢有筹码的玩家），stack 不变（未参与底池分配）
        assert_eq!(table.seats[0].player, [0x11; 20]);
        assert_eq!(table.seats[0].stack, 1000);
    }
}
