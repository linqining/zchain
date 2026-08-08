//! `FullHandRunner` —— 驱动一局**真实完整 Texas Hold'em 牌局**（性能报告模式）。
//!
//! 在 [`crate::HandRunner`]（6 步 lifecycle/funds 片段）基础上扩展，串起完整的对局：
//!
//! ```text
//! create_table → join_table×2 → start_hand
//!   → submit_shuffle_v2×2          (Mental Poker 洗牌)
//!   → preflop reveal (4 token)
//!   → call + check                   (preflop 下注)
//!   → flop reveal (6 token) → check×2
//!   → turn reveal (2 token) → check×2
//!   → river reveal (2 token) → check×2
//!   → showdown reveal (4 token)
//!   → [settle_hand / reset_for_next_hand 内部触发]
//! ```
//!
//! 每步经 [`crate::contracts::TexasPokerPlugin`] 真实 dispatch，产出的 `ProveTask`
//! 非 composite 方法仍立即生成并验证 method proof；连续 composite transition 仅入队，
//! 在牌局结束时统一生成一份 narrow tagged method proof 和一份 tagged Stage proof。
//!
//! # 容错与覆盖范围
//!
//! 本 runner 采用**容错**策略：任一步 dispatch 或 prove 失败时，记录 `ok=false`
//! 并把首个失败原因写入 `stopped_at`，后续步骤标记为跳过（不再 dispatch），
//! 最终仍返回一份 [`FullHandReport`]，便于性能评估。
//!
//! 目前的 heads-up 回归覆盖 create/join/start、两次 shuffle、preflop 到 showdown
//! 的所有 reveal token、四轮下注，以及最后一次 showdown reveal 触发的结算/reset。
//! 各任务均经 canonical VM replay、Stwo prove 和 host verify；批量 Stage verifier 还会重算
//! verifier-owned trace commitment。该链仍不是递归聚合
//! 证明，也不构成区块共识锚定。
//!
//! # 不声称的内容
//!
//! 与 [`crate::HandRunner`] 一致：本地 state_root 链只校验相邻连续性，不声称
//! block inclusion / 共识锚定。

use std::time::{Duration, Instant};

use borsh::BorshSerialize;

use blstrs::G1Projective;
use group::Group;
use poker_l1::Address;
use poker_l1::object_model::ObjectID;
use poker_l1::vm::contracts::texas_poker::constants::REVEAL_PHASE_SHOWDOWN;
use poker_l1::vm::contracts::texas_poker::dispatch::{
    CreateTableArgs, JoinTableArgs, SeatIndexArgs, SubmitRevealTokensArgs, SubmitShuffleV2Args,
    selectors,
};
use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};
use poker_protocol::crypto::{ECPoint, ElGamalCiphertext};

use crate::contracts::TexasPokerPlugin;
use crate::crypto_driver::{
    ShufflePlayer, apply_add_pk_to_c2, build_reveal_token, build_shuffle_v2,
};
use crate::plugin::ContractPlugin;

/// 单步计时记录（用于性能报告）。
#[derive(Debug, Clone)]
pub struct StepTiming {
    /// 方法名。
    pub method: String,
    /// dispatch 耗时。
    pub dispatch: Duration,
    /// prove + verify 耗时（无 prove_task 则为 0）。
    pub prove: Duration,
    /// 是否成功（dispatch + 可选 prove 均成功）。
    pub ok: bool,
    /// Per-proof breakdown collected during `prove` (empty unless
    /// `TEXAS_PROVE_TIMING` is set): legacy method prove/verify plus up to
    /// four component stage prove/verify records.
    pub proof_breakdown: Vec<poker_texas_air::prove_timing::TimingRecord>,
}

/// 完整牌局性能 + 正确性报告。
#[derive(Debug, Clone)]
pub struct FullHandReport {
    /// 每步计时。
    pub steps: Vec<StepTiming>,
    /// 总耗时（含全部 dispatch + prove）。
    pub total: Duration,
    /// state_root 链校验是否通过。
    pub chain_ok: bool,
    /// 最终统计。
    pub stats: crate::PluginStats,
    /// 赢家座位（settle 后按 stack 观察；`None` 表示平局、未结算或异常）。
    pub winner_seat: Option<u8>,
    /// 提前停止的原因（None = 跑完整局）。
    pub stopped_at: Option<String>,
}

/// 驱动一局完整对局的 runner。
pub struct FullHandRunner {
    /// 桌台创建者地址（也作为起手/重置的 caller）。
    creator: Address,
    /// 2 个玩家地址（座位 0、1）。
    players: [Address; 2],
}

impl Default for FullHandRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl FullHandRunner {
    /// 构造 runner（1 个 creator + 2 个玩家）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            creator: [0xAA; 20],
            players: [[0x10; 20], [0x20; 20]],
        }
    }

    /// 跑通一局完整牌局序列（容错），返回 (plugin, report)。
    ///
    /// 即使某步失败也返回已收集的步骤计时 + `stopped_at`，便于性能评估。
    pub fn run(self) -> (TexasPokerPlugin, FullHandReport) {
        let mut ctx = HandCtx::new();
        let start_total = Instant::now();

        // ===== Step 0: create_table =====
        let placeholder = make_placeholder_table(self.creator);
        let mut plugin = TexasPokerPlugin::new(placeholder);
        let create_args = CreateTableArgs {
            name: "full_hand_table".into(),
            max_players: 6,
            small_blind: 50,
            big_blind: 100,
        };
        dispatch_and_prove(
            &mut plugin,
            &mut ctx,
            self.creator,
            &selectors::create_table(),
            &create_args,
            "create_table",
        );

        // ===== Step 1-2: join_table ×2（每个玩家一个独立的 shuffle key）=====
        for (seat, &player) in self.players.iter().enumerate() {
            let sp = ShufflePlayer::deterministic(seat as u64 + 1);
            ctx.players[seat] = Some(sp.clone());
            let join_args = JoinTableArgs::with_key(
                player,
                1_000,
                sp.sk,
                poker_l1::vm::contracts::texas_poker::utils::scalar_from_u64(30_000 + seat as u64),
            )
            .expect("deterministic join key proof");
            dispatch_and_prove(
                &mut plugin,
                &mut ctx,
                player,
                &selectors::join_table(),
                &join_args,
                "join_table",
            );
        }

        // ===== Step 3: start_hand（creator 发起）=====
        // 先注册聚合公钥 aggregated_pk = pk0 + pk1（真实协议由 join_and_shuffle 累加）。
        // submit_shuffle_v2 的 shuffle proof 把 aggregated_pk 作为广义 Schnorr 基点，
        // 禁止 identity，故必须先设非 identity 值。
        let agg_pk = ctx
            .players
            .iter()
            .filter_map(|p| p.as_ref().map(|p| p.pk))
            .fold(G1Projective::identity(), |acc, pk| acc + pk);
        if let Err(error) = plugin.register_aggregated_pk(ECPoint(agg_pk)) {
            ctx.stopped_at = Some(format!("register_aggregated_pk: {error}"));
        }

        // start_hand 使 hand_id 0→1；verified receipt 链以单局 hand_id 为边界，
        // 必须在 prove start_hand 前开新链片段，否则 crosses-hands 校验失败。
        if ctx.stopped_at.is_none() {
            let args_bytes = borsh::to_vec(&()).unwrap_or_default();
            let d_start = Instant::now();
            match plugin.dispatch(self.creator, &selectors::start_hand(), &args_bytes) {
                Ok(outcome) => {
                    let d_dur = d_start.elapsed();
                    plugin.start_new_chain_segment();
                    let (prove_dur, ok) = if let Some(task) = &outcome.prove_task {
                        let p_start = Instant::now();
                        let _drained_before = poker_texas_air::prove_timing::take_drain();
                        let ok = plugin.prove_task_archived(task).is_ok();
                        if !ok {
                            ctx.stopped_at = Some("start_hand prove/verify failed".to_string());
                        }
                        (p_start.elapsed(), ok)
                    } else {
                        (Duration::ZERO, true)
                    };
                    ctx.steps.push(StepTiming {
                        method: "start_hand".into(),
                        dispatch: d_dur,
                        prove: prove_dur,
                        ok,
                        proof_breakdown: poker_texas_air::prove_timing::take_drain(),
                    });
                }
                Err(error) => {
                    ctx.stopped_at = Some(format!("start_hand dispatch: {error}"));
                    ctx.steps.push(StepTiming {
                        method: "start_hand".into(),
                        dispatch: d_start.elapsed(),
                        prove: Duration::ZERO,
                        proof_breakdown: Vec::new(),
                        ok: false,
                    });
                }
            }
        }
        // start_hand 重置 deck 到 canonical (G, plaintext)，初始化 deck_view。
        ctx.deck_view = canonical_initial_deck();

        // ===== Step 4-5: submit_shuffle_v2 ×2（两人顺序洗牌）=====
        for seat in 0..2u8 {
            if ctx.stopped_at.is_some() {
                ctx.steps.push(StepTiming {
                    method: format!("submit_shuffle_v2[seat{seat}]"),
                    dispatch: Duration::ZERO,
                    prove: Duration::ZERO,
                    proof_breakdown: Vec::new(),
                    ok: false,
                });
                continue;
            }
            let sp = ctx.players[seat as usize].clone().expect("player set");
            let step = match build_shuffle_v2(
                &ctx.deck_view,
                &sp.sk,
                &sp.pk,
                &agg_pk,
                seat as u64 * 1000 + 7,
            ) {
                Ok(s) => s,
                Err(e) => {
                    ctx.stopped_at = Some(format!("shuffle_v2 seat {seat} proof gen: {e}"));
                    ctx.steps.push(StepTiming {
                        method: format!("submit_shuffle_v2[seat{seat}]"),
                        dispatch: Duration::ZERO,
                        prove: Duration::ZERO,
                        proof_breakdown: Vec::new(),
                        ok: false,
                    });
                    continue;
                }
            };
            let args = SubmitShuffleV2Args {
                seat_index: seat,
                output_cards: step.output_cards.clone(),
                shuffle_proof: step.shuffle_proof,
            };
            dispatch_and_prove(
                &mut plugin,
                &mut ctx,
                self.players[seat as usize],
                &selectors::submit_shuffle_v2(),
                &args,
                &format!("submit_shuffle_v2[seat{seat}]"),
            );
            // 链下复现合约存储：deck = add_pk_to_c2(output_cards, player_pk)。
            ctx.deck_view = step.output_cards;
            apply_add_pk_to_c2(&mut ctx.deck_view, &sp.pk);
        }

        // ===== Step 6: preflop reveal（4 张底牌，每张由对方提交 reveal token）=====
        submit_reveal_round(
            &mut plugin,
            &mut ctx,
            &self.players,
            &[1, 0],
            "reveal_preflop",
        );

        // ===== Step 7: preflop 下注 =====
        // `start_hand` rotates the button before the first hand, so seat 0 is not
        // intrinsically the small blind. Read the contract's authoritative current_turn
        // before every action rather than reproducing its button/blind policy here.
        dispatch_current_turn(
            &mut plugin,
            &mut ctx,
            &self.players,
            &selectors::call(),
            "call(preflop)",
        );
        dispatch_current_turn(
            &mut plugin,
            &mut ctx,
            &self.players,
            &selectors::check(),
            "check(preflop)",
        );

        // ===== Step 8: flop reveal（3 张公共牌）=====
        submit_community_reveal(&mut plugin, &mut ctx, &self.players, 3, "reveal_flop");

        // ===== Step 9: flop 下注 =====
        dispatch_current_turn(
            &mut plugin,
            &mut ctx,
            &self.players,
            &selectors::check(),
            "check(flop0)",
        );
        dispatch_current_turn(
            &mut plugin,
            &mut ctx,
            &self.players,
            &selectors::check(),
            "check(flop1)",
        );

        // ===== Step 10: turn reveal（1 张公共牌）=====
        submit_community_reveal(&mut plugin, &mut ctx, &self.players, 1, "reveal_turn");

        // ===== Step 11: turn 下注 =====
        dispatch_current_turn(
            &mut plugin,
            &mut ctx,
            &self.players,
            &selectors::check(),
            "check(turn0)",
        );
        dispatch_current_turn(
            &mut plugin,
            &mut ctx,
            &self.players,
            &selectors::check(),
            "check(turn1)",
        );

        // ===== Step 12: river reveal（1 张公共牌）=====
        submit_community_reveal(&mut plugin, &mut ctx, &self.players, 1, "reveal_river");

        // ===== Step 13: river 下注 =====
        dispatch_current_turn(
            &mut plugin,
            &mut ctx,
            &self.players,
            &selectors::check(),
            "check(river0)",
        );
        dispatch_current_turn(
            &mut plugin,
            &mut ctx,
            &self.players,
            &selectors::check(),
            "check(river1)",
        );

        // ===== Step 14: showdown reveal（每人 reveal 自己 2 张底牌）=====
        submit_reveal_round(
            &mut plugin,
            &mut ctx,
            &self.players,
            &[0, 1],
            "reveal_showdown",
        );

        // All composite transitions after the shuffle phase are contiguous. Generate exactly one
        // narrow tagged method proof plus one tagged Stage proof for the whole run.
        if ctx.stopped_at.is_none() {
            let p_start = Instant::now();
            let _drained_before = poker_texas_air::prove_timing::take_drain();
            match plugin.finalize_tagged_batches() {
                Ok(batch_count) => {
                    let stage_rows = plugin
                        .tagged_batches()
                        .iter()
                        .rev()
                        .take(batch_count)
                        .map(|package| usize::from(package.stages().stage_row_count()))
                        .sum::<usize>();
                    ctx.steps.push(StepTiming {
                        method: format!(
                            "tagged_batch[{batch_count} packages/2 proofs each/{stage_rows} Stage rows]"
                        ),
                        dispatch: Duration::ZERO,
                        prove: p_start.elapsed(),
                        ok: true,
                        proof_breakdown: poker_texas_air::prove_timing::take_drain(),
                    });
                }
                Err(error) => {
                    ctx.stopped_at = Some(format!("tagged batch prove/verify: {error}"));
                    ctx.steps.push(StepTiming {
                        method: "tagged_batch".into(),
                        dispatch: Duration::ZERO,
                        prove: p_start.elapsed(),
                        ok: false,
                        proof_breakdown: poker_texas_air::prove_timing::take_drain(),
                    });
                }
            }
        }

        let winner_seat = if ctx.stopped_at.is_none() {
            observe_winner(plugin.table())
        } else {
            None
        };
        let total = start_total.elapsed();
        let chain_ok = plugin.verify_chain().is_ok();
        let stats = plugin.stats();
        let HandCtx {
            steps, stopped_at, ..
        } = ctx;

        (
            plugin,
            FullHandReport {
                steps,
                total,
                chain_ok,
                stats,
                winner_seat,
                stopped_at,
            },
        )
    }
}

// ===== 内部辅助 =====

/// 一手牌的链下上下文：玩家 crypto key + 链下 deck 视图 + 计时/停止记录。
struct HandCtx {
    /// 2 个玩家的 shuffle key（None = 未入座）。
    players: [Option<ShufflePlayer>; 2],
    /// 链下 deck 视图，与合约 deck_state.encrypted 同步。
    deck_view: Vec<ElGamalCiphertext>,
    /// 每步计时（贯穿整个 run）。
    steps: Vec<StepTiming>,
    /// 首个失败点（None = 全部成功）。
    stopped_at: Option<String>,
}

impl HandCtx {
    fn new() -> Self {
        Self {
            players: [None, None],
            deck_view: Vec::new(),
            steps: Vec::new(),
            stopped_at: None,
        }
    }
}

/// 执行一步 dispatch + （若有 prove_task）prove，记录到 `ctx.steps`（容错）。
fn dispatch_and_prove<A: BorshSerialize>(
    plugin: &mut TexasPokerPlugin,
    ctx: &mut HandCtx,
    caller: Address,
    selector: &[u8; 32],
    args: &A,
    name: &str,
) {
    if ctx.stopped_at.is_some() {
        ctx.steps.push(StepTiming {
            method: name.to_string(),
            dispatch: Duration::ZERO,
            prove: Duration::ZERO,
            proof_breakdown: Vec::new(),
            ok: false,
        });
        return;
    }
    let Ok(args_bytes) = borsh::to_vec(args) else {
        return;
    };
    let d_start = Instant::now();
    let outcome = match plugin.dispatch(caller, selector, &args_bytes) {
        Ok(o) => o,
        Err(error) => {
            ctx.stopped_at = Some(format!("{name} dispatch: {error}"));
            ctx.steps.push(StepTiming {
                method: name.to_string(),
                dispatch: d_start.elapsed(),
                prove: Duration::ZERO,
                proof_breakdown: Vec::new(),
                ok: false,
            });
            return;
        }
    };
    let d_dur = d_start.elapsed();
    let (prove_dur, ok) = if let Some(task) = &outcome.prove_task {
        let p_start = Instant::now();
        let _drained_before = poker_texas_air::prove_timing::take_drain();
        let prove_result =
            if poker_texas_air::airs::composition::supports_composite_proof(task.method_kind) {
                plugin.queue_tagged_batch_task(task)
            } else {
                plugin.prove_task_archived(task).map(|_| ())
            };
        match prove_result {
            Ok(()) => (p_start.elapsed(), true),
            Err(error) => {
                ctx.stopped_at = Some(format!("{name} prove/verify: {error}"));
                ctx.steps.push(StepTiming {
                    method: name.to_string(),
                    dispatch: d_dur,
                    prove: p_start.elapsed(),
                    ok: false,
                    proof_breakdown: poker_texas_air::prove_timing::take_drain(),
                });
                return;
            }
        }
    } else {
        (Duration::ZERO, true)
    };
    ctx.steps.push(StepTiming {
        method: name.to_string(),
        dispatch: d_dur,
        prove: prove_dur,
        ok,
        proof_breakdown: poker_texas_air::prove_timing::take_drain(),
    });
}

/// Dispatch a seat-indexed betting action for the contract's current actor.
///
/// Button placement changes at `start_hand`, and future rules may skip folded, all-in or waiting
/// seats. Resolving the actor from the table immediately before dispatch makes this integration
/// runner exercise the state machine instead of duplicating its turn-selection rules.
fn dispatch_current_turn(
    plugin: &mut TexasPokerPlugin,
    ctx: &mut HandCtx,
    players: &[Address; 2],
    selector: &[u8; 32],
    name: &str,
) {
    if ctx.stopped_at.is_some() {
        dispatch_and_prove(
            plugin,
            ctx,
            [0u8; 20],
            selector,
            &SeatIndexArgs { seat_index: 0 },
            name,
        );
        return;
    }

    let Some(seat_index) = plugin.table().current_turn_option() else {
        ctx.stopped_at = Some(format!("{name}: table has no current_turn"));
        ctx.steps.push(StepTiming {
            method: name.to_string(),
            dispatch: Duration::ZERO,
            prove: Duration::ZERO,
            proof_breakdown: Vec::new(),
            ok: false,
        });
        return;
    };
    let Some(&caller) = players.get(usize::from(seat_index)) else {
        ctx.stopped_at = Some(format!(
            "{name}: current_turn seat {seat_index} is not a runner player"
        ));
        ctx.steps.push(StepTiming {
            method: name.to_string(),
            dispatch: Duration::ZERO,
            prove: Duration::ZERO,
            proof_breakdown: Vec::new(),
            ok: false,
        });
        return;
    };

    dispatch_and_prove(
        plugin,
        ctx,
        caller,
        selector,
        &SeatIndexArgs { seat_index },
        name,
    );
}

/// 提交一轮 reveal token：每个 seat 一次批量提交当前所有欠下的 assignment。
fn submit_reveal_round(
    plugin: &mut TexasPokerPlugin,
    ctx: &mut HandCtx,
    players: &[Address; 2],
    submitter_seats: &[u8],
    name: &str,
) {
    for (step_no, &submitter_seat) in submitter_seats.iter().enumerate() {
        submit_reveal_batch_for_seat(plugin, ctx, players, submitter_seat, step_no as u32, name);
    }
}

fn submit_reveal_batch_for_seat(
    plugin: &mut TexasPokerPlugin,
    ctx: &mut HandCtx,
    players: &[Address; 2],
    submitter_seat: u8,
    step_no: u32,
    name: &str,
) {
    let method = format!("{name}[{step_no}]");
    if ctx.stopped_at.is_some() {
        ctx.steps.push(StepTiming {
            method,
            dispatch: Duration::ZERO,
            prove: Duration::ZERO,
            proof_breakdown: Vec::new(),
            ok: false,
        });
        return;
    }
    let Some(sp) = ctx.players[usize::from(submitter_seat)].clone() else {
        ctx.stopped_at = Some(format!("{method}: missing shuffle player"));
        ctx.steps.push(StepTiming {
            method,
            dispatch: Duration::ZERO,
            prove: Duration::ZERO,
            proof_breakdown: Vec::new(),
            ok: false,
        });
        return;
    };

    let Some(reveal_state) = plugin.table().reveal_token_state() else {
        ctx.stopped_at = Some(format!("{method}: table has no active reveal state"));
        ctx.steps.push(StepTiming {
            method,
            dispatch: Duration::ZERO,
            prove: Duration::ZERO,
            proof_breakdown: Vec::new(),
            ok: false,
        });
        return;
    };
    let reveal_phase = plugin.table().reveal_phase();
    let assignment_cards = reveal_state
        .assignments
        .iter()
        .enumerate()
        .filter(|(_, assignment)| assignment.pending_mask() & (1u16 << submitter_seat) != 0)
        .map(|(index, assignment)| (index, assignment.encrypted_card_index))
        .collect::<Vec<_>>();
    if assignment_cards.is_empty() {
        ctx.stopped_at = Some(format!("{method}: seat has no pending reveal assignments"));
        ctx.steps.push(StepTiming {
            method,
            dispatch: Duration::ZERO,
            prove: Duration::ZERO,
            proof_breakdown: Vec::new(),
            ok: false,
        });
        return;
    }

    let mut assignment_indices = Vec::with_capacity(assignment_cards.len());
    let mut reveal_tokens = Vec::with_capacity(assignment_cards.len());
    let mut proofs = Vec::with_capacity(assignment_cards.len());
    for (batch_offset, (assignment_index, card_index)) in assignment_cards.into_iter().enumerate() {
        // Showdown binds the owner proof to the self-contained partial ciphertext retained from
        // preflop. Every other phase binds to the current encrypted deck view.
        let card = if reveal_phase == REVEAL_PHASE_SHOWDOWN {
            plugin
                .table()
                .deck_state
                .decrypted_cards
                .iter()
                .find(|card| card.encrypted_card_index == card_index)
                .map(|card| card.ciphertext)
        } else {
            ctx.deck_view.get(usize::from(card_index)).cloned()
        };
        let Some(card) = card else {
            ctx.stopped_at = Some(format!(
                "{method}: proof ciphertext for card {card_index} is absent from canonical table state"
            ));
            ctx.steps.push(StepTiming {
                method,
                dispatch: Duration::ZERO,
                prove: Duration::ZERO,
                proof_breakdown: Vec::new(),
                ok: false,
            });
            return;
        };
        let rstep = build_reveal_token(
            &sp,
            &card,
            u64::from(step_no) * 256 + batch_offset as u64 + 1,
        );
        let Ok(assignment_index) = u8::try_from(assignment_index) else {
            ctx.stopped_at = Some(format!("{method}: assignment index exceeds u8"));
            ctx.steps.push(StepTiming {
                method,
                dispatch: Duration::ZERO,
                prove: Duration::ZERO,
                proof_breakdown: Vec::new(),
                ok: false,
            });
            return;
        };
        assignment_indices.push(assignment_index);
        reveal_tokens.push(ECPoint(rstep.reveal_token));
        proofs.push(rstep.proof);
    }
    let args = SubmitRevealTokensArgs {
        seat_index: submitter_seat,
        assignment_indices,
        reveal_tokens,
        proofs,
    };
    dispatch_and_prove(
        plugin,
        ctx,
        players[usize::from(submitter_seat)],
        &selectors::submit_player_reveal_tokens(),
        &args,
        &method,
    );
}

/// 提交公共牌 reveal：每个 phase 的 assignment 索引从零开始，每张牌两人都提交。
///
/// 密文在整副牌中的索引从合约的当前 assignment 读取，不能把前一阶段的 deck 索引
/// 当作新的 assignment 索引。
fn submit_community_reveal(
    plugin: &mut TexasPokerPlugin,
    ctx: &mut HandCtx,
    players: &[Address; 2],
    count: usize,
    name: &str,
) {
    if ctx.stopped_at.is_none() {
        let actual = plugin
            .table()
            .reveal_token_state()
            .map(|state| state.assignments.len());
        if actual != Some(count) {
            ctx.stopped_at = Some(format!(
                "{name}: expected {count} canonical assignments, got {actual:?}"
            ));
        }
    }
    for seat in 0..2u8 {
        submit_reveal_batch_for_seat(plugin, ctx, players, seat, u32::from(seat), name);
    }
}

/// 观察赢家：比较两手 stack，较大者为赢家（settle 后 pot 已分配）。
fn observe_winner(table: &TexasPokerTable) -> Option<u8> {
    let s0 = table.seats[0].stack();
    let s1 = table.seats[1].stack();
    match s0.cmp(&s1) {
        std::cmp::Ordering::Greater => Some(0),
        std::cmp::Ordering::Less => Some(1),
        std::cmp::Ordering::Equal => None,
    }
}

/// 构造占位桌台（create_table 会覆写）。
fn make_placeholder_table(_creator: Address) -> TexasPokerTable {
    let id = ObjectID::new([0xFF; 20], 0);
    TexasPokerTable::new(id, String::new(), EMPTY_PLAYER, 2, 1, 1)
}

/// 构造 canonical 初始 deck：52 张 (G, plaintext_i)，与合约 set_initial_encrypted_deck 一致。
fn canonical_initial_deck() -> Vec<ElGamalCiphertext> {
    let plaintexts = poker_l1::vm::contracts::texas_poker::utils::generate_plaintext_cards();
    let g = G1Projective::generator();
    plaintexts
        .into_iter()
        .map(|m| ElGamalCiphertext { c1: g, c2: m })
        .collect()
}
