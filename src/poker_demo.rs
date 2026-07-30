//! Texas Poker 演示：通过直接调用 state_machine 函数完成一局完整牌局。
//!
//! 本演示绕过区块生产、RPC、Mental Poker 密码学协议（shuffle/reveal/reconstruct），
//! 直接调用 `state_machine::start_hand` + `tick` + `apply_*` 函数，演示一局完整的
//! 德州扑克牌局流程：preflop → flop → turn → river → showdown → 结算。
//!
//! # 设计动机
//!
//! 经调研发现三个架构问题阻止 RPC-based demo 跑通：
//! 1. `build_block_from_vertex` 不执行 tx（使用上一 block 的 state_root）
//! 2. `validate_block` 只执行 `public_txs`，不执行 `gameturn_txs`
//! 3. `apply_join_and_shuffle` 要求真实 BLS12-381 密文反序列化（无法用 dummy data）
//!
//! 因此本 demo 采用 in-process 直接调用方式，跳过 shuffle（设置
//! `shuffle_state.completed_players = [0,1]`），跳过 reveal token 提交
//! （patch `decrypted=true` + 清空 `pending_players`），手动填充 community cards
//! 和 hole cards，演示完整的下注流程 + 摊牌 + 结算。
//!
//! # 牌局设定
//!
//! - Alice (seat 0, button/SB): A♠ A♥ （口袋对 A）
//! - Bob   (seat 1, BB):        K♠ K♥ （口袋对 K）
//! - 公共牌: 2♣ 7♦ 9♣ J♠ 3♥ （均不改善双方手牌）
//! - 期望结果: Alice 以"对 A + J-9-7 kicker"胜出
//!
//! 用法：`zchain poker-demo`

use poker_l1::vm::contracts::texas_poker::{
    card::{Card, ACE, CLUBS, DIAMONDS, HEARTS, JACK, KING, NINE, SEVEN, SPADES, THREE, TWO},
    events::TexasPokerEvent,
    state_machine,
    types::TexasPokerTable,
};
use poker_l1::vm::precompile::reserved::texas_poker_contract_id;

/// Alice 地址（seat 0，button/SB）。
const ALICE: [u8; 20] = [0x01; 20];
/// Bob 地址（seat 1，BB）。
const BOB: [u8; 20] = [0x02; 20];

/// poker-demo 子命令入口。
pub fn run(_args: &[String]) -> Result<(), String> {
    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       zchain Texas Poker Demo — 完整牌局演示            ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("本演示绕过 Mental Poker 密码学协议（shuffle/reveal/reconstruct），");
    println!("直接调用 state_machine 函数演示完整下注流程 + 摊牌结算。");
    println!();
    println!("牌局设定：");
    println!("  Alice (seat 0, button/SB): A♠ A♥  起始筹码 1000");
    println!("  Bob   (seat 1, BB):        K♠ K♥  起始筹码 1000");
    println!("  盲注: SB=5, BB=10");
    println!();

    run_showdown_hand()?;

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                   Demo 完成                              ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    Ok(())
}

/// 运行一局完整到摊牌的牌局。
fn run_showdown_hand() -> Result<(), String> {
    // ===== 1. 创建桌台 =====
    let table_id = texas_poker_contract_id();
    let mut table = TexasPokerTable::new(
        table_id,
        "Demo Table".to_string(),
        ALICE, // creator
        2,  // max_players
        5,  // small_blind
        10, // big_blind
    );

    // ===== 2. 设置两个座位 =====
    table.seats[0].player = ALICE;
    table.seats[0].stack = 1000;
    table.seats[1].player = BOB;
    table.seats[1].stack = 1000;

    // ===== 3. 预设 completed_players 跳过 Mental Poker shuffle =====
    // 这样 start_hand 内部 advance_shuffle 检测到 pending_players 为空时，
    // 会直接触发 ShuffleComplete + start_preflop_reveal_phase。
    table.shuffle_state.completed_players = vec![0, 1];

    // ===== 3.1 设置初始 button=1，使 start_hand 的 move_button 将 button 移到 seat 0 (Alice) =====
    // heads-up: button=SB，preflop SB 先行动，postflop BB 先行动。
    // 默认 button=0 时 move_button 会移到 seat 1 (Bob)，这里反转使 Alice 成为 button。
    table.button = 1;

    let mut events: Vec<TexasPokerEvent> = Vec::new();

    println!("━━━ Step 1: start_hand（开局，跳过 shuffle）━━━━━━━━━━━━━━━");
    state_machine::start_hand(&mut table, &mut events).map_err(|e| format!("start_hand: {e:?}"))?;
    print_events(&events);
    events.clear();
    // 此时: shuffle completed, round_state=PREFLOP, reveal_phase=PREFLOP
    // start_preflop_reveal_phase 已设置 4 个 reveal assignments（2 玩家 * 2 张牌）

    // ===== 4. 跳过 reveal token 提交 =====
    skip_reveal_phase(&mut table);
    println!("[patch] 已跳过 reveal token 提交（4 个 assignments 标记为 decrypted）");
    println!();

    // ===== 5. tick 触发 check_reveal_phase_complete → post_blinds + start_betting_round(true) =====
    println!("━━━ Step 2: tick → 进入 preflop 下注 ━━━━━━━━━━━━━━━━━━━━━━");
    state_machine::tick(&mut table, 1_000, &mut events).map_err(|e| format!("tick: {e:?}"))?;
    print_events(&events);
    events.clear();
    print_table_state("Preflop 下注开始", &table);

    // 验证: heads-up preflop, button=SB 先行动 → current_turn=Some(0)=Alice
    // Alice.bet=5 (SB), Bob.bet=10 (BB), pot=0
    assert_eq!(table.current_turn, Some(0), "preflop heads-up: button/SB 应先行动");
    assert_eq!(table.seats[0].bet, 5, "Alice SB bet");
    assert_eq!(table.seats[1].bet, 10, "Bob BB bet");

    // ===== 6. Preflop 下注: Alice raise to 30, Bob call =====
    println!("━━━ Step 3: Preflop 下注 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("[action] Alice raises to 30 (total_bet=30, delta=25)");
    state_machine::apply_raise(&mut table, 0, 30, &mut events)
        .map_err(|e| format!("apply_raise(Alice, 30): {e:?}"))?;
    print_events(&events);
    events.clear();
    print_table_state("Alice raise 后", &table);
    assert_eq!(table.current_turn, Some(1), "raise 后轮到 Bob");

    println!("[action] Bob calls 30 (delta=20)");
    state_machine::apply_call(&mut table, 1, &mut events)
        .map_err(|e| format!("apply_call(Bob): {e:?}"))?;
    print_events(&events);
    events.clear();
    // apply_call 内部 advance_turn 检测 is_betting_complete=true
    // → collect_bets_to_pot (pot=60) + advance_round → ROUND_FLOP + start_community_reveal_phase
    assert_eq!(table.round_state, 3 /* ROUND_FLOP */, "Bob call 后应进入 flop");
    assert_eq!(table.pot, 60, "preflop 下注 30+30=60 应入 pot");
    assert_eq!(table.seats[0].bet, 0, "collect_bets_to_pot 清零 Alice bet");
    assert_eq!(table.seats[1].bet, 0, "collect_bets_to_pot 清零 Bob bet");
    assert_eq!(table.seats[0].stack, 970, "Alice stack: 1000-30=970");
    assert_eq!(table.seats[1].stack, 970, "Bob stack: 1000-30=970");
    print_table_state("Flop round 开始（reveal 待跳过）", &table);

    // ===== 7. Flop: 跳过 reveal + 填充 3 张公共牌 =====
    println!("━━━ Step 4: Flop — 翻 3 张公共牌 ━━━━━━━━━━━━━━━━━━━━━━━━━");
    skip_reveal_phase(&mut table);
    table.community_cards.push(Card::new(CLUBS, TWO));
    table.community_cards.push(Card::new(DIAMONDS, SEVEN));
    table.community_cards.push(Card::new(CLUBS, NINE));
    println!("[patch] 跳过 reveal + 公共牌: 2♣ 7♦ 9♣");
    state_machine::tick(&mut table, 2_000, &mut events).map_err(|e| format!("tick: {e:?}"))?;
    print_events(&events);
    events.clear();
    print_table_state("Flop 下注开始", &table);
    // postflop: BB(Bob) 先行动 → current_turn=Some(1)
    assert_eq!(table.current_turn, Some(1), "postflop heads-up: BB 先行动");

    // ===== 8. Flop 下注: Bob check, Alice check =====
    println!("[action] Bob checks");
    state_machine::apply_check(&mut table, 1, &mut events)
        .map_err(|e| format!("apply_check(Bob): {e:?}"))?;
    events.clear();
    println!("[action] Alice checks");
    state_machine::apply_check(&mut table, 0, &mut events)
        .map_err(|e| format!("apply_check(Alice): {e:?}"))?;
    events.clear();
    assert_eq!(table.round_state, 4 /* ROUND_TURN */, "check/check 后进入 turn");
    print_table_state("Turn round 开始", &table);

    // ===== 9. Turn: 跳过 reveal + 填充第 4 张公共牌 =====
    println!("━━━ Step 5: Turn — 翻第 4 张公共牌 ━━━━━━━━━━━━━━━━━━━━━━━");
    skip_reveal_phase(&mut table);
    table.community_cards.push(Card::new(SPADES, JACK));
    println!("[patch] 跳过 reveal + 公共牌: J♠");
    state_machine::tick(&mut table, 3_000, &mut events).map_err(|e| format!("tick: {e:?}"))?;
    print_events(&events);
    events.clear();
    print_table_state("Turn 下注开始", &table);

    // ===== 10. Turn 下注: Bob check, Alice bet 50, Bob call =====
    println!("[action] Bob checks");
    state_machine::apply_check(&mut table, 1, &mut events)
        .map_err(|e| format!("apply_check(Bob): {e:?}"))?;
    events.clear();
    println!("[action] Alice bets 50");
    state_machine::apply_raise(&mut table, 0, 50, &mut events)
        .map_err(|e| format!("apply_raise(Alice, 50): {e:?}"))?;
    events.clear();
    println!("[action] Bob calls 50");
    state_machine::apply_call(&mut table, 1, &mut events)
        .map_err(|e| format!("apply_call(Bob): {e:?}"))?;
    events.clear();
    // apply_call 内部 advance_turn 检测 complete → collect + advance_round → ROUND_RIVER
    assert_eq!(table.round_state, 5 /* ROUND_RIVER */, "Bob call 后进入 river");
    assert_eq!(table.pot, 60 + 100, "pot: preflop 60 + turn 100 = 160");
    assert_eq!(table.seats[0].stack, 920, "Alice stack: 970-50=920");
    assert_eq!(table.seats[1].stack, 920, "Bob stack: 970-50=920");
    print_table_state("River round 开始", &table);

    // ===== 11. River: 跳过 reveal + 填充第 5 张公共牌 =====
    println!("━━━ Step 6: River — 翻第 5 张公共牌 ━━━━━━━━━━━━━━━━━━━━━━━");
    skip_reveal_phase(&mut table);
    table.community_cards.push(Card::new(HEARTS, THREE));
    println!("[patch] 跳过 reveal + 公共牌: 3♥");
    state_machine::tick(&mut table, 4_000, &mut events).map_err(|e| format!("tick: {e:?}"))?;
    print_events(&events);
    events.clear();
    print_table_state("River 下注开始", &table);

    // ===== 12. River 下注: Bob check, Alice check =====
    println!("[action] Bob checks");
    state_machine::apply_check(&mut table, 1, &mut events)
        .map_err(|e| format!("apply_check(Bob): {e:?}"))?;
    events.clear();
    println!("[action] Alice checks");
    state_machine::apply_check(&mut table, 0, &mut events)
        .map_err(|e| format!("apply_check(Alice): {e:?}"))?;
    events.clear();
    assert_eq!(table.round_state, 6 /* ROUND_SHOWDOWN */, "check/check 后进入 showdown");
    print_table_state("Showdown 阶段开始", &table);

    // ===== 13. Showdown: 跳过 reveal + 填充双方手牌 =====
    println!("━━━ Step 7: Showdown — 摊牌 + 结算 ━━━━━━━━━━━━━━━━━━━━━━━");
    skip_reveal_phase(&mut table);
    table.seats[0].hand.push(Card::new(SPADES, ACE));
    table.seats[0].hand.push(Card::new(HEARTS, ACE));
    table.seats[1].hand.push(Card::new(SPADES, KING));
    table.seats[1].hand.push(Card::new(HEARTS, KING));
    println!("[patch] 跳过 reveal + Alice 手牌: A♠ A♥, Bob 手牌: K♠ K♥");

    // tick → check_reveal_phase_complete → write_decrypted_cards_to_hands (no-op) + settle_hand
    state_machine::tick(&mut table, 5_000, &mut events).map_err(|e| format!("tick: {e:?}"))?;
    print_events(&events);
    events.clear();

    // ===== 14. 验证最终结果 =====
    println!();
    println!("━━━ Step 8: 最终结果 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    print_table_state("牌局结束（已 reset for next hand）", &table);

    // settle_hand 应将 pot=160 分给 Alice（对 A 击败对 K）
    // 注意: settle_hand → reset_for_next_hand 会清空 hand/community/pot，stack 保留分配结果
    assert_eq!(table.pot, 0, "settle_hand 后 pot 应清零");
    assert_eq!(
        table.seats[0].stack, 920 + 160,
        "Alice 赢得 pot=160: 920+160=1080"
    );
    assert_eq!(table.seats[1].stack, 920, "Bob 输掉本局: 920");
    assert_eq!(table.round_state, 0 /* ROUND_WAITING */, "reset 后回到 WAITING");

    println!();
    println!("✓ Alice (A♠ A♥) 以「对 A + J-9-7 kicker」击败 Bob (K♠ K♥)");
    println!("  Alice 筹码: 1000 → {} (净 +{})", table.seats[0].stack, table.seats[0].stack as i64 - 1000);
    println!("  Bob   筹码: 1000 → {} (净 {})", table.seats[1].stack, table.seats[1].stack as i64 - 1000);
    println!();

    Ok(())
}

/// 跳过 reveal token 提交阶段。
///
/// 通过将所有 assignments 标记为 `decrypted=true` + 清空 `pending_players`，
/// 使下一次 `tick` 检测到 reveal 已完成，触发 `check_reveal_phase_complete`。
fn skip_reveal_phase(table: &mut TexasPokerTable) {
    for a in &mut table.reveal_token_state.assignments {
        a.decrypted = true;
        a.pending_players.clear();
        a.reveal_tokens.clear();
    }
}

/// 打印桌台状态。
fn print_table_state(label: &str, table: &TexasPokerTable) {
    println!();
    println!("┌─── {} ───", label);
    println!("│ Round: {} | Pot: {} | Current turn: {:?}",
        round_name(table.round_state),
        table.pot,
        table.current_turn);
    let community: Vec<String> = table.community_cards.iter().map(|c| c.display()).collect();
    println!("│ Community cards: {}", if community.is_empty() { "(none)".to_string() } else { community.join(" ") });
    if let Some(br) = &table.betting_round {
        println!("│ Betting round: current_bet={}, min_raise={}",
            br.current_bet, br.min_raise);
    } else {
        println!("│ Betting round: (none)");
    }
    for (i, s) in table.seats.iter().enumerate() {
        if s.is_occupied() {
            let name = if s.player == ALICE { "Alice" }
                else if s.player == BOB { "Bob" }
                else { "?" };
            let hand_str = if s.hand.is_empty() {
                "[hidden]".to_string()
            } else {
                s.hand.iter().map(|c| c.display()).collect::<Vec<_>>().join(" ")
            };
            let button_mark = if table.button == i as u8 { " (button)" } else { "" };
            println!("│ Seat {}: {}{}  stack={} bet={} total_bet={} folded={} all_in={} hand={}",
                i, name, button_mark, s.stack, s.bet, s.total_bet, s.folded, s.all_in, hand_str);
        }
    }
    println!("└─────────────────────────────────────────────────────────────");
}

/// 回合名称。
fn round_name(r: u8) -> &'static str {
    match r {
        0 => "WAITING",
        2 => "PREFLOP",
        3 => "FLOP",
        4 => "TURN",
        5 => "RIVER",
        6 => "SHOWDOWN",
        _ => "UNKNOWN",
    }
}

/// 打印事件（紧凑形式）。
fn print_events(events: &[TexasPokerEvent]) {
    for e in events {
        let summary = event_summary(e);
        println!("  [event] {summary}");
    }
}

/// 事件摘要（避免打印整个 Debug 输出过长）。
fn event_summary(e: &TexasPokerEvent) -> String {
    use TexasPokerEvent::*;
    match e {
        HandStarted { button, small_blind, big_blind, participants, .. } => {
            format!("HandStarted: button={button} SB={small_blind} BB={big_blind} participants={participants:?}")
        }
        ShuffleComplete { phase, participant_count, deck_size, .. } => {
            format!("ShuffleComplete: phase={phase} participants={participant_count} deck={deck_size}")
        }
        BlindsPosted { sb_seat, bb_seat, sb_amount, bb_amount, first_to_act, .. } => {
            format!("BlindsPosted: SB=seat{sb_seat}({sb_amount}) BB=seat{bb_seat}({bb_amount}) first_to_act={first_to_act}")
        }
        BettingRoundStarted { round_state, current_bet, min_raise, first_to_act, pot_before, .. } => {
            format!("BettingRoundStarted: round={} current_bet={} min_raise={} first={first_to_act} pot_before={pot_before}",
                round_name(*round_state), current_bet, min_raise)
        }
        CurrentTurnChanged { old_turn, new_turn, round_state, .. } => {
            format!("CurrentTurnChanged: {old_turn:?} → {new_turn:?} (round={})", round_name(*round_state))
        }
        PlayerRaised { seat_index, raise_delta, total_bet, round_state, .. } => {
            format!("PlayerRaised: seat{seat_index} delta={raise_delta} total_bet={total_bet} round={}", round_name(*round_state))
        }
        PlayerCalled { seat_index, call_delta, round_state, .. } => {
            format!("PlayerCalled: seat{seat_index} delta={call_delta} round={}", round_name(*round_state))
        }
        PlayerChecked { seat_index, round_state, .. } => {
            format!("PlayerChecked: seat{seat_index} round={}", round_name(*round_state))
        }
        PlayerFolded { seat_index, reason, round_state, .. } => {
            format!("PlayerFolded: seat{seat_index} reason={reason} round={}", round_name(*round_state))
        }
        PotCollected { round_state, pot_after, collected_from_seats, .. } => {
            format!("PotCollected: round={} pot_after={pot_after} from={collected_from_seats:?}", round_name(*round_state))
        }
        RoundAdvanced { from_round, to_round, pot, community_cards_count, .. } => {
            format!("RoundAdvanced: {} → {} pot={pot} community={community_cards_count}",
                round_name(*from_round), round_name(*to_round))
        }
        RevealPhaseComplete { phase, .. } => {
            format!("RevealPhaseComplete: phase={phase}")
        }
        CommunityCardRevealed { card_ranks, card_suits, .. } => {
            format!("CommunityCardRevealed: ranks={card_ranks:?} suits={card_suits:?}")
        }
        ShowdownHoleCardsRevealed { seat_index, card_ranks, card_suits, .. } => {
            format!("ShowdownHoleCardsRevealed: seat{seat_index} ranks={card_ranks:?} suits={card_suits:?}")
        }
        HandSettled { pot, winners, .. } => {
            format!("HandSettled: pot={pot} winners={winners:?}")
        }
        WinnerAwarded { seat_index, amount, pot_type, .. } => {
            format!("WinnerAwarded: seat{seat_index} amount={amount} pot_type={pot_type}")
        }
        PlayerAllIn { seat_index, trigger_action, amount, .. } => {
            format!("PlayerAllIn: seat{seat_index} trigger={trigger_action} amount={amount}")
        }
        ShuffleTurn { seat_index, pending_count, completed_count, .. } => {
            format!("ShuffleTurn: seat{seat_index} pending={pending_count} completed={completed_count}")
        }
        other => format!("{other:?}"),
    }
}
