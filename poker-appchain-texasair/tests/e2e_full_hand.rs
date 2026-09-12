//! 端到端验收：完整一手 REAL 牌局——poker_texas_air 真实 STARK 出证 →
//! zchain appchain 验证、结算、资金转移、提现闭环。
//!
//! 牌局叙事（3 人 REAL 桌，桌面筹码 500/500/500，盲注 25/50）：
//! - hand start（preflop，盲注已发布：SB=座1 25、BB=座2 50，UTG=按钮座0）；
//! - UTG（座0，按钮）加注到 200；SB（座1）全下 500；BB（座2）弃牌（盲注 50 成死钱）；
//!   UTG 全下跟注 500（两家等额全下，无 uncalled 返还层）；
//! - AdvanceRound 微步把全部下注收池：**终态镜像 pot = 1050**（== gross_pot）。
//!
//! 覆盖的 canonical transition kind（一个 batch 内 5 行）：
//! `Raise(13)`、`Fold(10)`、`Call(12)`、`AdvanceRound(19)`。
//! 桌务生命周期（CreateTable/JoinTable/StartHand）与洗牌/发牌协议行
//! （SubmitShuffle/SubmitReveal 含盲注发布）属于 canonical AIR 的**相邻
//! batch 段**：Revealing→Betting 桥在 SubmitReveal 专用 crypto AIR 接入前
//! 是 poker_texas_air 的已知续链缺口（texas_canonical_air.rs
//! `canonical_full_hand_proof_perf_sweep` 文档：一手牌拆 4 段证明，本测试
//! 取其"下注街→收池"段并绑定为结算事实源）。 reveal-completion 行还要求
//! rules-opening 证明通道（`TableRules` 类型不经 poker_texas_air 公开再导出，
//! 外部集成测试不可构造），故盲注以 hand-start 镜像的座位 `bet` 字段进入
//! 证明范围——终局 pot 的 custody 恒等式（pot + Σ(stack+bet) == chip_pool）
//! 逐行由 AIR 约束，盲注面额因此同样被证明覆盖。
//!
//! 终局选择 AdvanceRound（收池）而非 EndWithoutShowdown（独赢重置）：
//! 后者的 reset 投影强制 post.pot == 0（奖励并入赢家筹码堆），与结算侧
//! "gross_pot == 已证明终态镜像 pot 字段（偏移 74）"的逐字节绑定不可调和；
//! 选取无 uncalled 的等额全下牌局在收池点终止，pot 语义两侧严格一致
//! （不改弱任何校验）。
//!
//! 资金流（与 canonical 镜像逐一对账）：
//! - 3 笔 REAL deposit（50/500/500）→ 3 张 seat note；
//! - 1 笔 REAL settle：plan 由 `poker-settlement-core::derive_settlement_plan`
//!   从牌局结果派生（分层/抽水/赢家评选纯函数），gross_pot == 1050 ==
//!   终态镜像 pot；赢家座1 payout 998（pot_index 0/runout 0）、rake 52
//!   （treasury 10 + operator 42）；
//! - ProofPipeline（TexasAirEngine，verifier key 钉扎 + StarkRequired）出证
//!   → 批次根 → 水位/finality 证据推进；
//! - 赢家 payout note REAL 提现：finality 门负例（无水位/无批次根）→
//!   批次根记录后放行 → mark_paid；
//! - 防篡改支线：归档 post 状态镜像尾字节翻转 → 引擎端到端拒绝；
//!   赔付结构篡改 → 纯函数校验拒绝。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use poker_appchain::error::AppchainError;
use poker_appchain::fee::{FeePolicy, FeeSplit};
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{OwnerKey, SequencerKey, spend_digest};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::ops::{Operation, scope};
use poker_appchain::pipeline::{
    PipelineConfig, Priority, ProofJob, ProofPipeline, SettlementProver,
};
use poker_appchain::real_policy::RealSettlementPolicy;
use poker_appchain::sequencer::{NoteStatus, Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    CANONICAL_STATE_IMAGE_BORSH_BYTES, HandProofBinding, RakeSplitRecord,
    STATE_IMAGE_CHIP_POOL_OFFSET, STATE_IMAGE_POT_OFFSET, SettleInput, SettlementRecord, SpendAuth,
    parse_archive_scope, settle_effect, settle_spend_scope, validate_settlement,
};
use poker_appchain::vault::{CustodyLedger, WithdrawalRequest, WithdrawalStatus};
use poker_appchain_texasair::TexasAirEngine;
use poker_settlement_core::{SettlementBoards, TableSnapshot, derive_settlement_plan};
use poker_texas_air::texas_canonical::{
    CANONICAL_ABI_VERSION, CanonicalActionPayload, CanonicalBoardRevealAssignment, CanonicalPhase,
    CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus, CanonicalStateImage,
    CanonicalTransitionKind, CanonicalTransitionWitness, MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS,
    MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
};
use poker_texas_air::texas_canonical_air::{
    ArchivedCanonicalTaggedProof, prove_canonical_tagged_batch, verify_canonical_tagged_proof,
};

// ===== 场景常量（牌局/结算数字单一事实源） =====

/// 桌 ID（canonical 镜像与 appchain 账本同值——归档绑定判据）。
const TABLE_ID: u64 = 42;
/// 买入/手牌起始筹码（canonical 座位堆与 seat note 同值）。
const BUY_IN: u64 = 500;
/// BB 弃牌后的死钱（其 seat note 面额 = 本手投入）。
const FOLDER_NOTE: u64 = 50;
/// gross pot == Σ seat note（500 + 500 + 50）== 终态镜像 pot。
const GROSS_POT: u64 = BUY_IN * 2 + FOLDER_NOTE;
/// 5% rake（费率策略与计划派生同参数）：floor(1050 × 500 / 10⁴)。
const RAKE: u64 = 52;
/// 赢家赔付（pot0：1050 − 52；单层 contested pot，单板 runout）。
const AWARD: u64 = GROSS_POT - RAKE;
/// 分账：treasury 20% of rake（10.4 → floor 10），零头归 operator。
const TREASURY_OUT: u64 = 10;
const OPERATOR_OUT: u64 = RAKE - TREASURY_OUT;

// ===== 测试用户（密钥与 spend secret 成对，生产由客户端派生） =====

struct Player {
    key: OwnerKey,
    secret: [u8; 32],
}

impl Player {
    fn new(seed: u8) -> Self {
        Self {
            key: OwnerKey::from_seed(&[seed; 32]).expect("seed key"),
            secret: [seed; 32],
        }
    }

    fn pk(&self) -> [u8; 33] {
        self.key.public_bytes()
    }

    fn nullifier(&self, note: &Note) -> [u8; 32] {
        felt_to_bytes32(&note.nullifier(&self.secret))
    }

    /// 对 (commitment, nullifier, scope, effect) 的花费授权（通用）。
    fn auth(&self, note: &Note, scope_tag: &[u8], effect: &[u8; 32]) -> SpendAuth {
        let nf = self.nullifier(note);
        let d = spend_digest(&note.commitment_bytes(), &nf, scope_tag, effect);
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: nf,
            sig: self.key.sign(&d),
        }
    }

    /// 结算输入授权：scope = 结算域 + hand_binding，effect = 完整结算效果
    /// 摘要（含 payout_root——赔付结构篡改必然签名失败）。记录完整后调用。
    fn settle_auth(&self, note: &Note, record: &SettlementRecord) -> SpendAuth {
        let scope_tag = settle_spend_scope(&record.hand_binding);
        let effect = settle_effect(record);
        self.auth(note, &scope_tag, &effect)
    }
}

// ===== canonical witness 构造（镜像 hand-bench/perf-sweep 已证模式） =====

fn active_seat(stack: u64, bet: u64, total_bet: u64, index: usize) -> CanonicalSeat {
    CanonicalSeat {
        status: CanonicalSeatStatus::Active,
        acted: false,
        stack,
        bet,
        total_bet,
        pending_addon: 0,
        time_bank_ms: 30_000,
        identity_commitment: [70 + index as u8; 32],
        key_commitment: [80 + index as u8; 32],
        hole_cards_commitment: [90 + index as u8; 32],
    }
}

/// hand-start 镜像：preflop 下注街，盲注已发布（SB 座1=25、BB 座2=50），
/// UTG（按钮座0）行动。custody 恒等式：pot 0 + Σ(stack+bet) == chip_pool。
fn hand_start_image() -> CanonicalStateImage {
    let mut image = CanonicalStateImage {
        abi_version: CANONICAL_ABI_VERSION,
        table_id: TABLE_ID,
        hand_id: 1,
        call_seq: 0,
        phase: CanonicalPhase::Betting,
        phase_subtag: 1,
        street: 1,
        current_turn: 0,
        deadline_ms: 42_500,
        shuffle_timeout_ms: 10_000,
        reveal_timeout_ms: 3_000,
        betting_timeout_ms: 30_000,
        reconstruct_timeout_ms: 10_000,
        showdown_display_ms: 3_000,
        current_bet: 50,
        min_raise: 50,
        chip_pool: BUY_IN * 3,
        pot: 0,
        button: 0,
        max_players: 3,
        acted_mask: 0,
        leave_after_hand_mask: 0,
        protocol_pending_mask: 0,
        board_cards_commitment: [1; 32],
        deck_commitment: [2; 32],
        reveal_commitment: [3; 32],
        reconstruction_commitment: [4; 32],
        run_it_twice_commitment: [5; 32],
        rules_commitment: [6; 32],
        governance_commitment: [7; 32],
        settlement_commitment: [8; 32],
        custody_commitment: [9; 32],
        lifecycle_root: [10; 32],
        overlay_root: [11; 32],
        state_root: [12; 32],
        seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
    };
    image.seats[0] = active_seat(BUY_IN, 0, 0, 0); // 按钮/UTG
    image.seats[1] = active_seat(BUY_IN - 25, 25, 25, 1); // SB
    image.seats[2] = active_seat(BUY_IN - 50, 50, 50, 2); // BB
    image
}

/// 完整一手牌 witness 序列（单 batch，5 行）：加注 → 全下 → 弃牌 → 全下跟注
/// → 收池。构造即自检：每行先过 host 侧 `validate_shape`（含
/// `validate_transition_relation` 与 custody 恒等式）。
fn full_hand_witnesses() -> Vec<CanonicalTransitionWitness> {
    let mut rows: Vec<CanonicalTransitionWitness> = Vec::new();
    let mut seq = 0u32;
    let mut step = |kind: CanonicalTransitionKind,
                    actor: [u8; 32],
                    seat: u8,
                    amount: u64,
                    edit: &dyn Fn(&mut CanonicalStateImage)| {
        let pre = rows
            .last()
            .map(|r| r.post.clone())
            .unwrap_or_else(hand_start_image);
        seq += 1;
        let mut post = pre.clone();
        post.call_seq = seq;
        edit(&mut post);
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind,
            actor,
            action: CanonicalActionPayload {
                seat,
                amount,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: poker_texas_air::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: poker_texas_air::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
            .validate_shape()
            .unwrap_or_else(|e| panic!("witness {seq} ({kind:?}) shape invalid: {e}"));
        rows.push(witness);
    };

    // R1：UTG（座0，按钮）加注到 200（increment 150 ≥ min_raise 50 →
    // 重开行动，min_raise 抬到 150）。
    step(
        CanonicalTransitionKind::Raise,
        [70; 32],
        0,
        200,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 1;
            post.current_bet = 200;
            post.min_raise = 150;
            post.acted_mask = 0b001;
            post.seats[0].acted = true;
            post.seats[0].stack = BUY_IN - 200;
            post.seats[0].bet = 200;
            post.seats[0].total_bet = 200;
        },
    );

    // R2：SB（座1）全下 500（needed 475 == stack → AllIn；increment 300 ≥
    // min_raise 150 → 再次重开：已行动的 Active 座位 acted 复位）。
    step(
        CanonicalTransitionKind::Raise,
        [71; 32],
        1,
        500,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 2;
            post.current_bet = 500;
            post.min_raise = 300;
            post.acted_mask = 0b010;
            post.seats[1].acted = true;
            post.seats[1].status = CanonicalSeatStatus::AllIn;
            post.seats[1].stack = 0;
            post.seats[1].bet = 500;
            post.seats[1].total_bet = 500;
            post.seats[0].acted = false;
        },
    );

    // R3：BB（座2）弃牌——盲注 50 成死钱（fold 保留 bet/stack，由收池行入池）。
    step(
        CanonicalTransitionKind::Fold,
        [72; 32],
        2,
        0,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 0;
            post.acted_mask = 0b110;
            post.seats[2].status = CanonicalSeatStatus::Folded;
            post.seats[2].acted = true;
        },
    );

    // R4：UTG（座0）全下跟注 300（owed 300 == stack → AllIn，bet 归 500）。
    // 无剩余可行动座位 → 轮转哨兵 NO_SEAT。
    step(
        CanonicalTransitionKind::Call,
        [70; 32],
        0,
        300,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = NO_CANONICAL_SEAT;
            post.acted_mask = 0b111;
            post.seats[0].acted = true;
            post.seats[0].status = CanonicalSeatStatus::AllIn;
            post.seats[0].stack = 0;
            post.seats[0].bet = 500;
            post.seats[0].total_bet = 500;
        },
    );

    // R5：AdvanceRound 微步——全部下注收池（pot 0 → 1050），翻牌 reveal
    // 开局（镜像 perf-sweep 段2 的已证 AdvanceRound 形状：street 1→2、
    // subtag 2、3 张 flop 指派）。终态镜像 pot == GROSS_POT（结算绑定）。
    // round_advance 开局在 seal 前挂上（收池行专属；其余行保持 canonical 零）。
    let advance_pre = rows.last().expect("pre-advance row").post.clone();
    let mut advance_post = advance_pre.clone();
    advance_post.call_seq = 5;
    advance_post.phase = CanonicalPhase::Revealing;
    advance_post.phase_subtag = 2;
    advance_post.street = 2;
    advance_post.deadline_ms = 45_000;
    advance_post.current_turn = NO_CANONICAL_SEAT;
    advance_post.current_bet = 0;
    advance_post.min_raise = 0;
    advance_post.pot = GROSS_POT;
    advance_post.protocol_pending_mask = 0b111;
    for seat in &mut advance_post.seats {
        seat.bet = 0;
    }
    let mut advance = CanonicalTransitionWitness {
        pre: advance_pre,
        post: advance_post,
        kind: CanonicalTransitionKind::AdvanceRound,
        actor: [0; 32],
        action: CanonicalActionPayload {
            seat: NO_CANONICAL_SEAT,
            amount: 0,
            auxiliary: 0,
            flag: false,
            proof_commitment: [0; 32],
        },
        round_advance: CanonicalRoundAdvanceOpening {
            pre_cards_dealt: 6,  // 3 名参与者 × 2 张底牌
            post_cards_dealt: 9, // + 3 张翻牌
            pre_board_len: 0,
            post_board_len: 0, // reveal token 兑现前牌面长度不变
            pre_second_board_len: 0,
            post_second_board_len: 0,
            run_it_twice: false,
            reveal_purpose: 2,
            assignment_count: 3,
            assignments: {
                let mut slots =
                    [CanonicalBoardRevealAssignment::EMPTY; MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS];
                for (position, slot) in slots.iter_mut().take(3).enumerate() {
                    *slot = CanonicalBoardRevealAssignment {
                        present: true,
                        encrypted_card_index: 6 + position as u8,
                        runout_index: 0,
                        board_position: position as u8,
                        pending_mask: 0b111,
                        submitted_mask: 0,
                    };
                }
                slots
            },
        },
        protocol_completion: Default::default(),
        rake_opening: poker_texas_air::canonical_rake_opening::CanonicalRakeOpening::ZERO,
        blind_opening: poker_texas_air::canonical_rake_opening::CanonicalBlindOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    advance.seal();
    advance.validate_shape().expect("advance opening shape");
    rows.push(advance);
    rows
}

/// 真实 stwo 出证（log_size 10，release 秒级）。
fn proven_hand_archive() -> ArchivedCanonicalTaggedProof {
    let witnesses = full_hand_witnesses();
    assert_eq!(witnesses.len(), 5);
    let archive = prove_canonical_tagged_batch(&witnesses).expect("canonical batch proof");
    // 独立验证器复核（不信任 prover）。
    verify_canonical_tagged_proof(&archive).expect("canonical batch verify");
    archive
}

// ===== appchain 侧脚手架 =====

/// 按 owner+amount+桌绑定查找账本 note。
fn find_note(seq: &Sequencer, owner: &[u8; 33], amount: u64, table: Option<u64>) -> Note {
    seq.state()
        .notes
        .values()
        .find(|e| e.note.owner == *owner && e.note.amount == amount && e.note.table_id == table)
        .unwrap_or_else(|| panic!("note not found: owner {:?} amount {amount}", owner[32]))
        .note
        .clone()
}

fn deposit(seq: &mut Sequencer, player: &Player, amount: u64, id_byte: u8) {
    let mut deposit_id = [0u8; 32];
    deposit_id[0] = id_byte;
    seq.submit(
        Operation::Deposit {
            deposit_id,
            owner: player.pk(),
            asset_class: AssetClass::Real,
            amount,
        },
        1_000,
    )
    .expect("REAL deposit");
}

fn buy_in(seq: &mut Sequencer, player: &Player, deposit_note: &Note, ts_ms: u64) {
    let effect = Operation::BuyIn {
        table_id: TABLE_ID,
        spends: vec![],
        notes: vec![],
        seat_owner: player.pk(),
    }
    .effect_digest();
    seq.submit(
        Operation::BuyIn {
            table_id: TABLE_ID,
            spends: vec![player.auth(deposit_note, scope::BUYIN, &effect)],
            notes: vec![deposit_note.clone()],
            seat_owner: player.pk(),
        },
        ts_ms,
    )
    .expect("REAL buy-in");
}

/// 软确认一笔提现销毁（§5.1：销毁无证明门槛；finality 门在托管打款侧）。
fn burn_note(seq: &mut Sequencer, player: &Player, note: &Note, request_id: [u8; 32]) {
    let effect = Operation::WithdrawRequest {
        spend: SpendAuth {
            commitment: [0; 32],
            nullifier: [0; 32],
            sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
        },
        note: note.clone(),
        request_id,
    }
    .effect_digest();
    seq.submit(
        Operation::WithdrawRequest {
            spend: player.auth(note, scope::WITHDRAW, &effect),
            note: note.clone(),
            request_id,
        },
        9_000,
    )
    .expect("soft-confirm withdrawal burn");
}

/// 托管打款侧提现申请（provenance/finality 证据取自 sequencer 快照）。
fn vault_request(
    ledger: &mut CustodyLedger,
    seq: &Sequencer,
    note: &Note,
    request_id: [u8; 32],
) -> Result<poker_appchain::vault::WithdrawalEntry, AppchainError> {
    let provenance = seq.withdrawal_provenance(note).expect("note in ledger");
    ledger
        .enqueue_withdrawal(
            WithdrawalRequest {
                request_id,
                payout_address: [0xEE; 32],
                amount: note.amount,
            },
            provenance,
            seq.finality_evidence(),
        )
        .cloned()
}

// ===== 端到端主测试 =====

#[test]
fn full_hand_real_stark_to_settlement_to_withdrawal() {
    // ===== A. 完整一手牌：真实 STARK 出证（单 canonical batch）=====
    let archive = proven_hand_archive();
    assert_eq!(archive.table_id, TABLE_ID);
    assert_eq!(archive.transition_count, 5);
    assert_eq!(
        archive.first_transition_kind,
        CanonicalTransitionKind::Raise as u8
    );
    assert_eq!(
        archive.last_transition_kind,
        CanonicalTransitionKind::AdvanceRound as u8
    );
    // 归档 scope（appchain 侧可解析）：终态镜像 pot/chip_pool 与结算口径一致
    let archive_bytes = borsh::to_vec(&archive).expect("archive encoding");
    let scope = parse_archive_scope(&archive_bytes).expect("scope v2 parse");
    assert_eq!(
        scope.pre_state_image_bytes.len(),
        CANONICAL_STATE_IMAGE_BORSH_BYTES
    );
    assert_eq!(
        scope.post_state_image_bytes.len(),
        CANONICAL_STATE_IMAGE_BORSH_BYTES
    );
    let image_pot = u64::from_le_bytes(
        scope.post_state_image_bytes[STATE_IMAGE_POT_OFFSET..][..8]
            .try_into()
            .unwrap(),
    );
    let image_chip_pool = u64::from_le_bytes(
        scope.post_state_image_bytes[STATE_IMAGE_CHIP_POOL_OFFSET..][..8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(image_pot, GROSS_POT, "terminal image pot == gross pot");
    assert_eq!(image_chip_pool, BUY_IN * 3, "custody preserved");
    assert!(scope.rake_opening.is_none());
    assert!(scope.blind_opening.is_none());

    // ===== B. 结算计划派生（poker-settlement-core 纯函数，牌局结果输入）=====
    // 座0/座1 等额全下（各 500），座2 弃牌（盲注 50 死钱）；
    // 座0 ♠2♠3（三条2），座1 ♠A♠K（皇家同花顺）→ 座1 独赢。
    let total_bets = [BUY_IN, BUY_IN, FOLDER_NOTE];
    let inactive = [false, false, true];
    let all_in = [true, true, false];
    let hole_seat0: &[u8] = &[0, 1]; // ♠2 ♠3
    let hole_seat1: &[u8] = &[12, 11]; // ♠A ♠K
    let hole_seat2: &[u8] = &[];
    let hole_cards: [&[u8]; 3] = [hole_seat0, hole_seat1, hole_seat2];
    let snapshot = TableSnapshot {
        seat_count: 3,
        button: 0,
        total_bets: &total_bets,
        inactive: &inactive,
        all_in: &all_in,
        hole_cards: &hole_cards,
        rake_mode: poker_settlement_core::RAKE_MODE_PERCENTAGE,
        rake_bps: 500,
        rake_cap: 1_000,
    };
    // 单板：♠Q ♠J ♠10 ♥2 ♦2（座1 成 ♠A 高皇家同花顺）。
    let boards = SettlementBoards::single(vec![10, 9, 8, 13, 26]);
    let plan = derive_settlement_plan(&snapshot, &boards).expect("settlement plan");
    assert_eq!(
        plan.gross_pot, GROSS_POT,
        "plan pot == canonical terminal pot"
    );
    assert_eq!(plan.rake, RAKE);
    assert_eq!(plan.total_awards, AWARD);
    assert_eq!(plan.awards[1], AWARD, "seat 1 (SB all-in) wins the pot");
    assert_eq!(plan.awards[0], 0);
    assert_eq!(plan.awards[2], 0);
    assert_eq!(plan.pots.len(), 1, "single contested pot (equal all-ins)");
    assert!(plan.pots[0].is_contested());
    plan.validate(3).expect("plan internal conservation");

    // ===== C. 链上装配：WAL sequencer + REAL 桌 + 存入/买入 =====
    let dir = std::env::temp_dir().join("poker-appchain-texasair-e2e");
    std::fs::create_dir_all(&dir).unwrap();
    let wal_path = dir.join(format!("e2e-full-hand-{}.wal", std::process::id()));
    let _ = std::fs::remove_file(&wal_path);
    let seq_key = SequencerKey::from_seed(&[77u8; 32]);
    let mut seq = Sequencer::new(
        seq_key.clone(),
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    );
    seq.attach_wal(&wal_path)
        .expect("WAL attach（先写日志后生效）");

    let folder = Player::new(11); // 座0：BB 弃牌，投入 50
    let winner = Player::new(12); // 座1：SB 全下，赢家
    let loser = Player::new(13); // 座2：BB…全下跟注被弃，投入 500
    let treasury = Player::new(14);
    let operator = Player::new(15);
    let policy = FeePolicy::FixedRake {
        rate_bps: 500,
        cap: 0, // FeePolicy 语义：0 = 无封顶
        split: FeeSplit {
            treasury_bps: 2_000,
            treasury: treasury.pk(),
            operator: operator.pk(),
        },
    };
    seq.submit(
        Operation::OpenTable {
            table_id: TABLE_ID,
            policy,
        },
        1_000,
    )
    .expect("open REAL table");
    deposit(&mut seq, &folder, FOLDER_NOTE, 1);
    deposit(&mut seq, &winner, BUY_IN, 2);
    deposit(&mut seq, &loser, BUY_IN, 3);
    assert_eq!(seq.state().seq, 4, "ops: open + 3 deposits");
    // 桌准入只收 proven note（M8 污染防御）：存款段先行证明化
    seq.mark_proven_through(seq.state().seq - 1);
    assert_eq!(seq.proven_watermark(), 3);

    let dep_folder = find_note(&seq, &folder.pk(), FOLDER_NOTE, None);
    let dep_winner = find_note(&seq, &winner.pk(), BUY_IN, None);
    let dep_loser = find_note(&seq, &loser.pk(), BUY_IN, None);
    buy_in(&mut seq, &folder, &dep_folder, 1_100);
    buy_in(&mut seq, &winner, &dep_winner, 1_200);
    buy_in(&mut seq, &loser, &dep_loser, 1_300);
    let seat_folder = find_note(&seq, &folder.pk(), FOLDER_NOTE, Some(TABLE_ID));
    let seat_winner = find_note(&seq, &winner.pk(), BUY_IN, Some(TABLE_ID));
    let seat_loser = find_note(&seq, &loser.pk(), BUY_IN, Some(TABLE_ID));
    assert_eq!(
        seat_folder.amount + seat_winner.amount + seat_loser.amount,
        GROSS_POT,
        "seat notes == gross pot（本手投入）"
    );
    assert_eq!(seq.state().tables.get(&TABLE_ID).unwrap().seats, 3);
    assert_eq!(seq.state().seq, 7, "settle op 将落在帧链 index 7");

    // ===== D. REAL 结算记录（plan 投影 + 归档绑定 + 授权签名）=====
    let mut record = SettlementRecord {
        table_id: TABLE_ID,
        hand_binding: archive.batch_digest, // 手牌绑定 = 已证明批次摘要
        policy_commitment: policy.commitment_bytes(),
        pot: GROSS_POT,
        inputs: vec![
            SettleInput {
                note: seat_folder.clone(),
                spend: SpendAuth {
                    commitment: seat_folder.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInput {
                note: seat_winner.clone(),
                spend: SpendAuth {
                    commitment: seat_winner.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInput {
                note: seat_loser.clone(),
                spend: SpendAuth {
                    commitment: seat_loser.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
        ],
        // plan 投影：单层 contested pot、单板 runout → 恰一个 (pot 0, runout 0)
        // 非零 award 三元组（seat 1）
        payouts: vec![NoteSpec {
            asset_class: AssetClass::Real,
            amount: AWARD,
            owner: winner.pk(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        }],
        rake: RakeSplitRecord {
            total: RAKE,
            treasury_out: Some(NoteSpec {
                asset_class: AssetClass::Real,
                amount: TREASURY_OUT,
                owner: treasury.pk(),
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            }),
            operator_out: Some(NoteSpec {
                asset_class: AssetClass::Real,
                amount: OPERATOR_OUT,
                owner: operator.pk(),
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            }),
        },
        plan: plan.clone(),
        hand_proof: Some(HandProofBinding {
            archive_bytes: archive_bytes.clone(),
            post_state_commitment: archive.post_state_commitment,
            pre_state_root: archive.pre_state_root,
            post_state_root: archive.post_state_root,
        }),
    };
    // S1：每个输入 note 的 owner 对完整结算效果签名（记录完整后构造）
    record.inputs[0].spend = folder.settle_auth(&seat_folder, &record);
    record.inputs[1].spend = winner.settle_auth(&seat_winner, &record);
    record.inputs[2].spend = loser.settle_auth(&seat_loser, &record);
    // 纯函数校验先行（守恒/费率/分账/投影/签名/归档镜像 pot 绑定）
    validate_settlement(&record, &policy).expect("settlement record is valid");
    // 守恒等式：Σpayouts + rake.total == gross_pot == Σdeposits（本手投入）
    let payouts_sum: u64 = record.payouts.iter().map(|p| p.amount).sum();
    assert_eq!(payouts_sum + record.rake.total, GROSS_POT);
    assert_eq!(GROSS_POT, FOLDER_NOTE + BUY_IN + BUY_IN);

    let settle_op_index = seq.state().seq; // 7
    seq.submit(Operation::Settle(Box::new(record.clone())), 1_400)
        .expect("REAL settle applied at soft-confirm");
    assert_eq!(seq.state().seq, settle_op_index + 1);

    // ===== E. 资金转移断言（软确认账本层）=====
    // 输家 seat notes 已消耗：nullifier 入集、note 出账
    for (player, seat) in [
        (&folder, &seat_folder),
        (&winner, &seat_winner),
        (&loser, &seat_loser),
    ] {
        assert!(
            seq.state()
                .nullifiers
                .contains(&seat.nullifier(&player.secret)),
            "seat note nullifier must be consumed"
        );
        assert!(
            !seq.state().notes.contains_key(&seat.commitment_bytes()),
            "seat note must be removed from the ledger"
        );
    }
    // 赢家 payout note（plan 投影数额）+ rake note（treasury/operator）
    let payout_note = find_note(&seq, &winner.pk(), AWARD, None);
    assert_eq!(payout_note.asset_class, AssetClass::Real);
    // find_note 即存在性断言：rake note 已铸给 treasury / operator
    let treasury_note = find_note(&seq, &treasury.pk(), TREASURY_OUT, None);
    let operator_note = find_note(&seq, &operator.pk(), OPERATOR_OUT, None);
    assert_eq!(treasury_note.asset_class, AssetClass::Real);
    assert_eq!(operator_note.asset_class, AssetClass::Real);
    assert!(
        seq.state()
            .notes
            .contains_key(&treasury_note.commitment_bytes())
    );
    assert!(
        seq.state()
            .notes
            .contains_key(&operator_note.commitment_bytes())
    );
    assert_eq!(seq.state().balances_of(&folder.pk()), (0, 0));
    assert_eq!(
        seq.state().balances_of(&winner.pk()),
        (u128::from(AWARD), 0)
    );
    assert_eq!(seq.state().balances_of(&loser.pk()), (0, 0));
    assert_eq!(
        seq.state().balances_of(&treasury.pk()),
        (u128::from(TREASURY_OUT), 0)
    );
    assert_eq!(
        seq.state().balances_of(&operator.pk()),
        (u128::from(OPERATOR_OUT), 0)
    );
    let total_real: u128 = [&folder, &winner, &loser, &treasury, &operator]
        .iter()
        .map(|p| seq.state().balances_of(&p.pk()).0)
        .sum();
    assert_eq!(
        u64::try_from(total_real).unwrap(),
        GROSS_POT,
        "Σoutputs == gross pot == Σdeposits（资金守恒）"
    );
    // payout note 尚未证明（结算 op 等批次覆盖）——finality 拒绝的第一现场
    let prov = seq
        .withdrawal_provenance(&payout_note)
        .expect("payout note provenance");
    assert_eq!(prov.asset_class, AssetClass::Real);
    assert_eq!(prov.source_op_index, settle_op_index);

    // ===== F. 证明管道：StarkRequired + 钉扎 TexasAirEngine =====
    let attestor = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let pinned_key = attestor.verifying_key().to_bytes();
    let engine: Arc<dyn SettlementProver> =
        Arc::new(TexasAirEngine::new(attestor).with_verifier_key(pinned_key));
    let metrics = Arc::new(MetricsRegistry::new());
    let pipeline = ProofPipeline::with_real_policy(
        PipelineConfig {
            workers: 1,
            batch_size: 1,
            queue_bound: 8,
            high_watermark: 8,
            batch_interval_ms: 1_000,
        },
        engine,
        Arc::clone(&metrics),
        RealSettlementPolicy::stark_required(pinned_key),
    );
    let seq = Arc::new(Mutex::new(seq));
    // P0-5 生产装配点：批次验证通过回调推进 sequencer 证明水位
    pipeline.set_on_batch_proven({
        let seq = Arc::clone(&seq);
        Arc::new(move |through| seq.lock().unwrap().mark_proven_through(through))
    });
    pipeline
        .submit(ProofJob {
            op_index: settle_op_index,
            table_id: TABLE_ID,
            record: Arc::new(record.clone()),
            policy,
            priority: Priority::Real,
        })
        .expect("REAL job admitted（StarkRequired + 钉扎 + hand_proof）");

    // 负例支线 A：批次根记录前（此处水位尚未覆盖结算 op）→ WithdrawalNotFinalized
    let mut ledger = CustodyLedger::new().with_metrics(Arc::clone(&metrics));
    let request_id = [0x5A; 32];
    let err =
        vault_request(&mut ledger, &seq.lock().unwrap(), &payout_note, request_id).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::WithdrawalNotFinalized { op_index: 7, .. }
        ),
        "unproven settlement must not finalize withdrawal"
    );
    assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 1);

    for _ in 0..6_000 {
        if pipeline.completed_count() >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(pipeline.completed_count(), 1, "prove = real stwo path");
    assert_eq!(metrics.counter("real_settlement_rejected_total"), 0);
    let batch = pipeline
        .try_build_batch()
        .expect("batch build")
        .expect("REAL batch proven");
    assert_eq!(batch.through_op, settle_op_index);
    assert_eq!(seq.lock().unwrap().proven_watermark(), settle_op_index);

    // 负例支线 B：水位已覆盖但批次根未记录 → 仍拒（§5.4 v1 finality 双判据）
    let err =
        vault_request(&mut ledger, &seq.lock().unwrap(), &payout_note, request_id).unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalNotFinalized { .. }));
    assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 2);

    // 批次根记录（mark_proven_through_with_root：水位 + finality 证据齐备）
    seq.lock()
        .unwrap()
        .mark_proven_through_with_root(batch.through_op, batch.root);
    assert_eq!(
        seq.lock().unwrap().batch_covered_through(),
        Some(settle_op_index)
    );
    assert_eq!(
        seq.lock().unwrap().batch_root_at(settle_op_index),
        Some(batch.root)
    );
    // 覆盖后 payout note 翻 Proven
    let entry = seq
        .lock()
        .unwrap()
        .state()
        .notes
        .get(&payout_note.commitment_bytes())
        .expect("payout note in ledger")
        .status;
    assert_eq!(entry, NoteStatus::Proven);
    // 释放管道（其批次回调持有 sequencer 句柄）后再做 WAL 重放断言
    drop(pipeline);

    // ===== G. attestation v2.1 独立复验 + 深篡改拒绝 =====
    {
        let engine_direct = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]))
            .with_verifier_key(pinned_key);
        let bundle = engine_direct
            .prove(&ProofJob {
                op_index: settle_op_index,
                table_id: TABLE_ID,
                record: Arc::new(record.clone()),
                policy,
                priority: Priority::Real,
            })
            .expect("direct engine prove (full stwo verify path)");
        assert_eq!(bundle.payload.len(), 192, "attestation v2.1 payload");
        assert_eq!(bundle.attestor_public, pinned_key);
        engine_direct.verify(&bundle).expect("attestation verify");
        let stranger = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]))
            .with_verifier_key(pinned_key);
        let mut foreign = bundle.clone();
        foreign.attestor_public = [0xAA; 32];
        assert!(matches!(
            stranger.verify(&foreign).unwrap_err(),
            AppchainError::VerifierKeyMismatch
        ));

        // 深篡改（端到端）：post 状态镜像尾字节翻转——borsh 可解码、声明
        // 承诺不变 → 只有完整 STARK 验证器能拒
        let mut tampered = archive.clone();
        let last = tampered.post_state_image_bytes.len() - 1;
        tampered.post_state_image_bytes[last] ^= 1;
        let mut tampered_record = record.clone();
        tampered_record.hand_proof = Some(HandProofBinding {
            archive_bytes: borsh::to_vec(&tampered).expect("tampered archive encoding"),
            post_state_commitment: archive.post_state_commitment,
            pre_state_root: archive.pre_state_root,
            post_state_root: archive.post_state_root,
        });
        let err = engine_direct
            .prove(&ProofJob {
                op_index: settle_op_index,
                table_id: TABLE_ID,
                record: Arc::new(tampered_record),
                policy,
                priority: Priority::Real,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            AppchainError::AdmissionRejected("archive stark verify failed")
        ));

        // 深篡改（结算侧）：赔付数额改动 → plan 投影/守恒/签名判据拒绝
        let mut tampered_payout = record.clone();
        tampered_payout.payouts[0].amount = AWARD - 1;
        assert!(validate_settlement(&tampered_payout, &policy).is_err());
    }

    // ===== H. 提现闭环：finality 门放行 → enqueue → mark_paid =====
    {
        let mut seq = seq.lock().unwrap();
        burn_note(&mut seq, &winner, &payout_note, request_id);
        assert!(
            !seq.state()
                .notes
                .contains_key(&payout_note.commitment_bytes())
        );
        assert!(
            seq.state()
                .nullifiers
                .contains(&payout_note.nullifier(&winner.secret)),
            "payout note nullifier consumed at withdrawal"
        );
        // provenance 消费后保留（托管打款侧判定依据）
        let prov = seq
            .withdrawal_provenance(&payout_note)
            .expect("origin survives burn");
        assert_eq!(prov.source_op_index, settle_op_index);
    }
    let entry = vault_request(&mut ledger, &seq.lock().unwrap(), &payout_note, request_id)
        .expect("finalized REAL withdrawal enqueued");
    assert_eq!(entry.status, WithdrawalStatus::Queued);
    assert_eq!(ledger.queued_withdrawals(), 1);
    ledger
        .mark_paid(request_id, [0xEE; 32])
        .expect("custody payout recorded");
    assert_eq!(ledger.queued_withdrawals(), 0);
    // 幂等：同 id 同载荷重复申请不冲突
    vault_request(&mut ledger, &seq.lock().unwrap(), &payout_note, request_id)
        .expect("idempotent re-request");
    assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 2);

    // ===== I. WAL 原子提交：重启重放出同一账本 =====
    // （原 sequencer 句柄由管道回调持有；重放只读 WAL 文件，无需回收）
    {
        let replayed = Sequencer::replay(
            &wal_path,
            seq_key.public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .expect("WAL replay");
        assert_eq!(
            replayed.state().balances_of(&winner.pk()),
            (0, 0),
            "赢家已全额提现"
        );
        assert_eq!(
            replayed.state().balances_of(&treasury.pk()),
            (u128::from(TREASURY_OUT), 0)
        );
        assert_eq!(
            replayed.state().balances_of(&operator.pk()),
            (u128::from(OPERATOR_OUT), 0)
        );
        assert_eq!(replayed.state().balances_of(&folder.pk()), (0, 0));
        assert_eq!(replayed.state().balances_of(&loser.pk()), (0, 0));
        let _ = std::fs::remove_file(&wal_path);
    }
}

// ===== B9（ABI v1.2.2）：含 uncalled 返还层的手 =====

/// 含 uncalled 返还层的结算回归（BLOCKERS B9 / ABI v1.2.2）。
///
/// 牌局叙事（对照主测试的等额全下，此处**不等额**）：3 人 REAL 桌——
/// UTG（座0）全下加注 200、SB（座1）覆盖全下 500、BB（座2）弃牌 50 死钱。
/// plan 分层 = [450 contested（含死钱）, 300 uncalled 返还座1]：
/// - rake 计费基数 = `plan.rake_base()` = **450**（5% → 22 = treasury 4 +
///   operator 18）——与 poker_l1 canonical 的 contested-only 计费同口径；
/// - 旧口径（v1.2.1 前）按全额 gross pot 750 计 37，与计划 rake 22 必然
///   FeeMismatch——这正是 B9 修复前此类合法手被 fail-closed 拒绝的原因。
///
/// STARK 出证路径由主测试覆盖；本手走 sequencer 软确认结算
/// （`hand_proof = None` 与 REAL 结算的 sequencer 准入语义一致——
/// REAL 出证门在 pipeline/引擎层，不在纯函数校验/账本层）。
#[test]
fn uncalled_return_layer_hand_settles_end_to_end() {
    use poker_appchain::settlement::{RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth};

    // ===== 1. plan 派生（poker-settlement-core，与 poker_l1 canonical 同码）=====
    let total_bets = [200u64, 500, 50];
    let inactive = [false, false, true];
    let all_in = [true, true, false];
    let hole_utg: &[u8] = &[0, 1]; // ♠2 ♠3
    let hole_sb: &[u8] = &[12, 11]; // ♠A ♠K
    let hole_bb: &[u8] = &[]; // 弃牌无手牌
    let hole_cards: [&[u8]; 3] = [hole_utg, hole_sb, hole_bb];
    let snapshot = TableSnapshot {
        seat_count: 3,
        button: 0,
        total_bets: &total_bets,
        inactive: &inactive,
        all_in: &all_in,
        hole_cards: &hole_cards,
        rake_mode: poker_settlement_core::RAKE_MODE_PERCENTAGE,
        rake_bps: 500,
        rake_cap: 1_000,
    };
    // 单板：♠Q ♠J ♠10 ♥2 ♦2 → 座1 皇家同花顺独大（对照主测试同板）。
    let boards = SettlementBoards::single(vec![10, 9, 8, 13, 26]);
    let plan = derive_settlement_plan(&snapshot, &boards).expect("settlement plan");
    assert_eq!(plan.gross_pot, 750, "200 + 500 + 50（死钱入主层）");
    assert_eq!(plan.pots.len(), 2);
    assert!(plan.pots[0].is_contested());
    assert_eq!(plan.pots[0].gross_amount, 450);
    assert!(!plan.pots[1].is_contested(), "uncalled 返还层");
    assert_eq!(plan.pots[1].gross_amount, 300);
    assert_eq!(plan.pots[1].rake, 0, "uncalled 层零 rake（plan.validate 强制）");
    assert_eq!(plan.rake_base(), 450, "rake 基数 = contested 层 gross 之和");
    assert_eq!(plan.rake, 22, "5% × 450（contested-only）");
    assert_eq!(plan.pots[0].runouts[0].awards[1], 428, "contested 层净额归座1");
    assert_eq!(plan.pots[1].runouts[0].awards[1], 300, "uncalled 300 全额返还座1");
    assert_eq!(plan.total_awards, 728);
    plan.validate(3).expect("plan internal conservation");

    // ===== 2. 账本流：REAL 存入 → 买入 → 结算 =====
    let dir = std::env::temp_dir().join("poker-appchain-texasair-e2e");
    std::fs::create_dir_all(&dir).unwrap();
    let wal_path = dir.join(format!("e2e-uncalled-{}.wal", std::process::id()));
    let _ = std::fs::remove_file(&wal_path);
    let seq_key = SequencerKey::from_seed(&[78u8; 32]);
    let mut seq = Sequencer::new(
        seq_key.clone(),
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    );
    seq.attach_wal(&wal_path).expect("WAL attach");

    let utg = Player::new(21); // 座0：全下 200，输
    let sb = Player::new(22); // 座1：全下 500，赢家（含 uncalled 返还）
    let bb = Player::new(23); // 座2：弃牌，死钱 50
    let treasury = Player::new(24);
    let operator = Player::new(25);
    let policy = FeePolicy::FixedRake {
        rate_bps: 500,
        cap: 0,
        split: FeeSplit {
            treasury_bps: 2_000,
            treasury: treasury.pk(),
            operator: operator.pk(),
        },
    };
    seq.submit(
        Operation::OpenTable {
            table_id: TABLE_ID,
            policy,
        },
        1_000,
    )
    .expect("open REAL table");
    deposit(&mut seq, &utg, 200, 1);
    deposit(&mut seq, &sb, 500, 2);
    deposit(&mut seq, &bb, 50, 3);
    seq.mark_proven_through(seq.state().seq - 1);
    let dep_utg = find_note(&seq, &utg.pk(), 200, None);
    let dep_sb = find_note(&seq, &sb.pk(), 500, None);
    let dep_bb = find_note(&seq, &bb.pk(), 50, None);
    buy_in(&mut seq, &utg, &dep_utg, 1_100);
    buy_in(&mut seq, &sb, &dep_sb, 1_200);
    buy_in(&mut seq, &bb, &dep_bb, 1_300);
    let seat_utg = find_note(&seq, &utg.pk(), 200, Some(TABLE_ID));
    let seat_sb = find_note(&seq, &sb.pk(), 500, Some(TABLE_ID));
    let seat_bb = find_note(&seq, &bb.pk(), 50, Some(TABLE_ID));
    assert_eq!(seq.state().tables.get(&TABLE_ID).unwrap().seats, 3);

    let mk_payout = |amount: u64, pot_index: u8| NoteSpec {
        asset_class: AssetClass::Real,
        amount,
        owner: sb.pk(),
        table_id: None,
        pot_index,
        runout_index: 0,
    };
    let mk_rake = |amount: u64, owner: [u8; 33]| NoteSpec {
        asset_class: AssetClass::Real,
        amount,
        owner,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let mut record = SettlementRecord {
        table_id: TABLE_ID,
        hand_binding: [0xC9; 32],
        policy_commitment: policy.commitment_bytes(),
        pot: 750,
        inputs: vec![
            SettleInput {
                note: seat_utg.clone(),
                spend: SpendAuth {
                    commitment: seat_utg.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInput {
                note: seat_sb.clone(),
                spend: SpendAuth {
                    commitment: seat_sb.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInput {
                note: seat_bb.clone(),
                spend: SpendAuth {
                    commitment: seat_bb.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
        ],
        // plan 投影：(pot 0, runout 0, 座1, 428) + (pot 1, runout 0, 座1, 300)
        payouts: vec![mk_payout(428, 0), mk_payout(300, 1)],
        rake: RakeSplitRecord {
            total: 22,
            treasury_out: Some(mk_rake(4, treasury.pk())),
            operator_out: Some(mk_rake(18, operator.pk())),
        },
        plan: plan.clone(),
        hand_proof: None,
    };
    record.inputs[0].spend = utg.settle_auth(&seat_utg, &record);
    record.inputs[1].spend = sb.settle_auth(&seat_sb, &record);
    record.inputs[2].spend = bb.settle_auth(&seat_bb, &record);

    // B9 核心断言：纯函数校验放行（v1.2.1 前同记录因
    // plan.rake(22) != policy.rake_of(750)(37) 被 fail-closed 误拒）
    assert_eq!(policy.rake_of(plan.rake_base()), 22);
    assert_eq!(policy.rake_of(record.pot), 37, "旧口径基数（对照）");
    assert_ne!(record.rake.total, policy.rake_of(record.pot));
    validate_settlement(&record, &policy).expect("uncalled-layer hand must settle (B9)");
    seq.submit(Operation::Settle(Box::new(record)), 1_400)
        .expect("previously rejected hand now settles at soft-confirm");

    // ===== 3. 资金断言：守恒 + uncalled 返还 + rake 分账 =====
    assert_eq!(seq.state().balances_of(&utg.pk()), (0, 0));
    assert_eq!(
        seq.state().balances_of(&sb.pk()),
        (728, 0),
        "428（contested 赢额）+ 300（uncalled 返还）"
    );
    assert_eq!(seq.state().balances_of(&bb.pk()), (0, 0));
    assert_eq!(seq.state().balances_of(&treasury.pk()), (4, 0));
    assert_eq!(seq.state().balances_of(&operator.pk()), (18, 0));
    let total_real: u128 = [&utg, &sb, &bb, &treasury, &operator]
        .iter()
        .map(|p| seq.state().balances_of(&p.pk()).0)
        .sum();
    assert_eq!(
        u64::try_from(total_real).unwrap(),
        750,
        "Σoutputs == gross pot == Σdeposits（资金守恒）"
    );
    assert_eq!(seq.state().tables.get(&TABLE_ID).unwrap().seats, 0);

    // ===== 4. WAL 重放：结算被持久化且重放一致 =====
    {
        let replayed = Sequencer::replay(
            &wal_path,
            seq_key.public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .expect("WAL replay");
        assert_eq!(replayed.state().balances_of(&sb.pk()), (728, 0));
        assert_eq!(replayed.state().balances_of(&treasury.pk()), (4, 0));
        let _ = std::fs::remove_file(&wal_path);
    }
}
