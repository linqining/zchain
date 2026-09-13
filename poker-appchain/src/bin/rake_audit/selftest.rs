//! `rake_audit selftest`：生成 demo WAL。
//!
//! 默认（无 `--hands`）：3 手，覆盖三种计费口径（M5-ACC-3 v1 演练口径）：
//!
//! - hand 1（table 1）：单层 contested pot 2_000 → rake_base=2_000，rake=100；
//! - hand 2（table 1）：**含 uncalled 返还层**（contested 层 1_000 + uncontested
//!   返还层 1_000）→ rake_base 只含 contested gross = 1_000，rake=50
//!   （B9 contested-only 口径；若误按全额 gross 计费会是 100）；
//! - hand 3（table 2）：ZERO 桌 pot 2_000 → rake=0（零费口径）。
//!
//! `--hands N`（M5-ACC-3 外部独立复验用）：生成 ≥N 手混合桌 WAL——
//! table 1 = FIXED_RAKE 5% 无封顶（每第 2 手含 uncalled 返还层）、
//! table 2 = FIXED_RAKE 10% 封顶 30（cap 生效路径）、table 3 = ZERO，
//! 按手序轮转；全部走真实 sequencer 管线（真实 spend 签名 + 逐 input
//! 结算签名）。批量模式 WAL 以 `export_chain` + `with_fsync(false)` 一次性
//! 落盘（提速；帧内容与逐帧提交路径完全一致，重放等价由集成测试覆盖）。
//!
//! stdout 输出机器可读字段（`WAL=` / `SEQUENCER_PUBLIC=` / `WAL_HEAD_HASH=` /
//! `HANDS=` / `TABLES=` / `FIRST_TS=` / `LAST_TS=`），供演练脚本、集成测试
//! 与外部复验工具解析。

use std::path::Path;
use std::sync::Arc;

use poker_appchain::fee::{FeePolicy, FeeSplit};
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{spend_digest, OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::ops::{scope, Operation};
use poker_appchain::sequencer::{NoteStatus, Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    settle_effect, settle_spend_scope, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};
use poker_settlement_core::{
    RunoutPotPlan, SettlementPlan, SettlementPotPlan, SettlementRunoutSchedule,
    SETTLEMENT_PLAN_VERSION, SETTLEMENT_SEATS,
};

/// 测试玩家：密钥与 spend secret 成对（生产中 secret 由客户端派生）。
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

    fn buyin_auth(&self, note: &Note, effect: &[u8; 32]) -> SpendAuth {
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(
            &note.commitment_bytes(),
            &felt_to_bytes32(&nf),
            scope::BUYIN,
            effect,
        );
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }

    fn settle_auth(&self, note: &Note, binding: &[u8; 32], effect: &[u8; 32]) -> SpendAuth {
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(
            &note.commitment_bytes(),
            &felt_to_bytes32(&nf),
            &settle_spend_scope(binding),
            effect,
        );
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }
}

/// 生成 demo WAL（默认 3 手口径）。返回 (head_hash, hands, tables)。
///
/// # Errors
/// 任何 sequencer 拒绝（demo 构造自身不变量破坏）或 IO 失败 → 输入错误。
#[allow(dead_code)] // 保留旧入口（run_with_hands(None) 同义）；供外部脚本/测试复用
pub fn run(dir: &Path) -> Result<([u8; 32], usize, usize), String> {
    run_with_hands(dir, None)
}

/// 生成 demo WAL；`hands = Some(n)` 时生成 n 手混合桌批量口径（见模块
/// 注释）。返回 (head_hash, hands, tables)。
///
/// # Errors
/// 任何 sequencer 拒绝（demo 构造自身不变量破坏）或 IO 失败 → 输入错误。
pub fn run_with_hands(dir: &Path, hands: Option<usize>) -> Result<([u8; 32], usize, usize), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("创建 {} 失败: {e}", dir.display()))?;
    let wal_path = dir.join("selftest.wal");
    if wal_path.exists() {
        std::fs::remove_file(&wal_path).map_err(|e| format!("清除旧 WAL 失败: {e}"))?;
    }

    let key = SequencerKey::from_seed(&[0xA5u8; 32]);
    let mut seq = Sequencer::new(
        key.clone(),
        SequencerConfig {
            // demo 一次生成全部帧：放开限流（口径与 bin/loadtest 相同）
            ops_per_min: u32::MAX,
            open_table_per_min: u32::MAX,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    );
    // 批量模式：不挂 WAL（提交路径与生产完全一致），收尾 export_chain 后
    // 用 with_fsync(false) 一次性落盘（提速；重放等价由集成测试覆盖）。
    // 默认模式：attach_wal 逐帧 fsync 提交（与生产写路径一致）。
    let bulk = hands.is_some();
    if !bulk {
        seq.attach_wal(&wal_path).map_err(|e| format!("挂 WAL 失败: {e}"))?;
    }

    let alice = Player::new(0xAA);
    let bob = Player::new(0xBB);
    let raked_policy = FeePolicy::FixedRake {
        rate_bps: 500,
        cap: 0,
        split: FeeSplit {
            treasury_bps: 2_000,
            treasury: Player::new(0x51).pk(),
            operator: Player::new(0x61).pk(),
        },
    };
    // 封顶策略（cap 生效路径）：10% 无封顶应为 200，封顶 30 生效 → rake=30
    let capped_policy = FeePolicy::FixedRake {
        rate_bps: 1_000,
        cap: 30,
        split: FeeSplit {
            treasury_bps: 2_000,
            treasury: Player::new(0x52).pk(),
            operator: Player::new(0x62).pk(),
        },
    };
    let zero_policy = FeePolicy::Zero;

    let mut ts: u64 = 1_700_000_000_000;
    let first_ts: u64;
    let last_ts: u64;
    let mut deposit_seq: u64 = 0;
    let mut binding_seq: u64 = 0;

    if hands.is_none() {
        // ===== 默认：v1 演练口径（3 手，table 1 计费 + table 2 零费）=====
        // ===== 开桌（策略开桌即冻结）=====
        submit(&mut seq, &mut ts, Operation::OpenTable { table_id: 1, policy: raked_policy })?;
        submit(&mut seq, &mut ts, Operation::OpenTable { table_id: 2, policy: zero_policy })?;

        // ===== hand 1：table 1，单层 contested pot（标准 5% 计费）=====
        let (seat_a, seat_b) =
            buy_in_hand(&mut seq, &mut ts, &mut deposit_seq, &alice, &bob, 1, 1_000)?;
        binding_seq += 1;
        let record = raked_record(
            1,
            &alice,
            &bob,
            &raked_policy,
            binding_seq,
            vec![pot_layer(0, 2_000, 100, 0b11, &[(0, 950), (1, 950)])],
        );
        submit_settle(&mut seq, &mut ts, &alice, &bob, &[seat_a, seat_b], record)?;

        // ===== hand 2：table 1，含 uncalled 返还层（rake_base 只含 contested 层）=====
        let (seat_a, seat_b) =
            buy_in_hand(&mut seq, &mut ts, &mut deposit_seq, &alice, &bob, 1, 1_000)?;
        binding_seq += 1;
        let record = raked_record(
            1,
            &alice,
            &bob,
            &raked_policy,
            binding_seq,
            vec![
                // contested 层 1_000（rake 50，净 950）+ uncalled 返还层 1_000（rake 0）
                pot_layer(0, 1_000, 50, 0b11, &[(0, 475), (1, 475)]),
                pot_layer(1, 1_000, 0, 0b10, &[(1, 1_000)]),
            ],
        );
        submit_settle(&mut seq, &mut ts, &alice, &bob, &[seat_a, seat_b], record)?;

        // ===== hand 3：table 2，ZERO 桌（rake 恒 0）=====
        let (seat_a, seat_b) =
            buy_in_hand(&mut seq, &mut ts, &mut deposit_seq, &alice, &bob, 2, 1_000)?;
        binding_seq += 1;
        let record = raked_record(
            2,
            &alice,
            &bob,
            &zero_policy,
            binding_seq,
            vec![pot_layer(0, 2_000, 0, 0b11, &[(0, 1_000), (1, 1_000)])],
        );
        submit_settle(&mut seq, &mut ts, &alice, &bob, &[seat_a, seat_b], record)?;
        first_ts = 1_700_000_001_000; // 首笔 OpenTable 的 ts（初始 1.7e12 + 1s 步进）
        last_ts = ts;
        let hands_out = 3usize;
        let head = finish_wal(&mut seq, &wal_path, bulk, &key)?;
        println!("WAL={}", wal_path.display());
        println!("SEQUENCER_PUBLIC={}", hex::encode(key.public));
        println!("WAL_HEAD_HASH={}", hex::encode(head));
        println!("HANDS={hands_out}");
        println!("TABLES=2");
        println!("FIRST_TS={first_ts}");
        println!("LAST_TS={last_ts}");
        return Ok((head, hands_out, 2));
    }

    // ===== 批量混合桌口径（--hands N）=====
    let n = hands.unwrap_or(0).max(1);
    // 桌注册：1 = 5% 无封顶（部分手含 uncalled 层）、2 = 10% 封顶 30、
    // 3 = ZERO；开桌即冻结策略。
    submit(&mut seq, &mut ts, Operation::OpenTable { table_id: 1, policy: raked_policy })?;
    submit(&mut seq, &mut ts, Operation::OpenTable { table_id: 2, policy: capped_policy })?;
    submit(&mut seq, &mut ts, Operation::OpenTable { table_id: 3, policy: zero_policy })?;
    first_ts = ts;

    for i in 0..n {
        let table = (i % 3) as u64 + 1;
        // 桌策略 + 该桌标准手（单层 contested 2_000）的费/分账：
        //   table 1: 5% 无封顶 → rake 100 → 各得 950
        //   table 2: 10% 封顶 30（cap 生效）→ rake 30 → 各得 985
        //   table 3: ZERO → rake 0 → 各得 1_000
        let policy = match table {
            1 => &raked_policy,
            2 => &capped_policy,
            _ => &zero_policy,
        };
        let (seat_a, seat_b) =
            buy_in_hand(&mut seq, &mut ts, &mut deposit_seq, &alice, &bob, table, 1_000)?;
        binding_seq += 1;
        // 每第 4 手（i % 4 == 1，仅计费桌）构造 uncalled 返还层手：
        // contested 层 1_000 + uncalled 返还层 1_000（rake_base 只含
        // contested 层 gross = 1_000；B9 口径锚点）。
        let uncalled = i % 4 == 1 && table != 3;
        let pots = if uncalled {
            match table {
                // contested 1_000 → rake 50 → 各 475；uncalled 1_000 → 座 1
                1 => vec![
                    pot_layer(0, 1_000, 50, 0b11, &[(0, 475), (1, 475)]),
                    pot_layer(1, 1_000, 0, 0b10, &[(1, 1_000)]),
                ],
                // contested 1_000 → raw 100 → cap 30 生效 → 各 485
                2 => vec![
                    pot_layer(0, 1_000, 30, 0b11, &[(0, 485), (1, 485)]),
                    pot_layer(1, 1_000, 0, 0b10, &[(1, 1_000)]),
                ],
                _ => unreachable!("uncalled 只出现在计费桌"),
            }
        } else {
            match table {
                1 => vec![pot_layer(0, 2_000, 100, 0b11, &[(0, 950), (1, 950)])],
                2 => vec![pot_layer(0, 2_000, 30, 0b11, &[(0, 985), (1, 985)])],
                _ => vec![pot_layer(0, 2_000, 0, 0b11, &[(0, 1_000), (1, 1_000)])],
            }
        };
        let record = raked_record(table, &alice, &bob, policy, binding_seq, pots);
        submit_settle(&mut seq, &mut ts, &alice, &bob, &[seat_a, seat_b], record)?;
    }
    last_ts = ts;
    let head = finish_wal(&mut seq, &wal_path, bulk, &key)?;
    println!("WAL={}", wal_path.display());
    println!("SEQUENCER_PUBLIC={}", hex::encode(key.public));
    println!("WAL_HEAD_HASH={}", hex::encode(head));
    println!("HANDS={n}");
    println!("TABLES=3");
    println!("FIRST_TS={first_ts}");
    println!("LAST_TS={last_ts}");
    Ok((head, n, 3))
}

/// 收尾：批量模式 export_chain → with_fsync(false) 一次性落盘；默认模式
/// 仅 drop（WalWriter 随 drop flush，每次提交已 sync）。返回链头哈希。
fn finish_wal(
    seq: &mut Sequencer,
    wal_path: &Path,
    bulk: bool,
    _key: &SequencerKey,
) -> Result<[u8; 32], String> {
    let head = seq.head_hash().map_err(|e| format!("head hash: {e}"))?;
    if bulk {
        let mut wal = poker_appchain::wal::WalWriter::create(wal_path)
            .map_err(|e| format!("创建 WAL 失败: {e}"))?
            .with_fsync(false);
        for f in seq.export_chain() {
            wal.append(&f).map_err(|e| format!("WAL 写入失败: {e}"))?;
        }
        wal.sync().map_err(|e| format!("WAL flush 失败: {e}"))?;
    }
    Ok(head)
}

/// 提交一笔操作（demo 时钟单调 +1s；拒绝即 demo 不变量破坏）。
fn submit(seq: &mut Sequencer, ts: &mut u64, op: Operation) -> Result<(), String> {
    *ts += 1_000;
    seq.submit(op, *ts)
        .map(|_| ())
        .map_err(|e| format!("demo 提交被拒: {e}"))
}

/// 两个玩家各入金 `amount` → 推证明水位 → 各买入（seat note `amount`）。
fn buy_in_hand(
    seq: &mut Sequencer,
    ts: &mut u64,
    deposit_seq: &mut u64,
    alice: &Player,
    bob: &Player,
    table_id: u64,
    amount: u64,
) -> Result<(Note, Note), String> {
    for player in [alice, bob] {
        *deposit_seq += 1;
        let mut deposit_id = [0u8; 32];
        deposit_id[..8].copy_from_slice(&deposit_seq.to_be_bytes());
        submit(
            seq,
            ts,
            Operation::Deposit {
                deposit_id,
                owner: player.pk(),
                asset_class: AssetClass::Play,
                amount,
            },
        )?;
    }
    // 桌准入只收 proven note：先推水位再买入
    seq.mark_proven_through(seq.state().seq);
    let mut seats: Vec<Note> = Vec::new();
    for player in [alice, bob] {
        let note = seq
            .state()
            .note_entries_of(&player.pk())
            .into_iter()
            .find(|e| {
                e.note.amount == amount
                    && e.note.table_id.is_none()
                    && e.status == NoteStatus::Proven
            })
            .map(|e| e.note.clone())
            .ok_or("demo：找不到可用 proven note")?;
        let effect = Operation::BuyIn {
            table_id,
            spends: vec![],
            notes: vec![],
            seat_owner: player.pk(),
        }
        .effect_digest();
        let auth = player.buyin_auth(&note, &effect);
        submit(
            seq,
            ts,
            Operation::BuyIn {
                table_id,
                spends: vec![auth],
                notes: vec![note],
                seat_owner: player.pk(),
            },
        )?;
        let seat = seq
            .state()
            .note_entries_of(&player.pk())
            .into_iter()
            .find(|e| e.note.table_id == Some(table_id))
            .map(|e| e.note.clone())
            .ok_or("demo：找不到 seat note")?;
        seats.push(seat);
    }
    let seat_b = seats.pop().expect("two seats");
    let seat_a = seats.pop().expect("two seats");
    Ok((seat_a, seat_b))
}

/// 单个 pot 层（Schedule::Single；runout awards 由 `(seat, amount)` 给出）。
fn pot_layer(
    pot_index: u8,
    gross: u64,
    rake: u64,
    eligible_mask: u16,
    awards: &[(usize, u64)],
) -> SettlementPotPlan {
    let mut runout = RunoutPotPlan::inactive();
    runout.amount = gross - rake;
    runout.winner_mask = eligible_mask;
    for (seat, amount) in awards {
        runout.awards[*seat] = *amount;
    }
    SettlementPotPlan {
        pot_index,
        gross_amount: gross,
        rake,
        net_amount: gross - rake,
        eligible_mask,
        runouts: [runout, RunoutPotPlan::inactive()],
    }
}

/// 组装记录：payouts 直接从 pots 展开（与校验器的 plan 投影规范序一致：
/// 逐 pot → runout0 → seat 升序，只含非零 award；seat0 = alice，seat1 = bob）。
/// inputs 由 [`submit_settle`] 用真实 seat note 填充并签名。
fn raked_record(
    table_id: u64,
    alice: &Player,
    bob: &Player,
    policy: &FeePolicy,
    binding_seq: u64,
    pots: Vec<SettlementPotPlan>,
) -> SettlementRecord {
    let mut binding32 = [0u8; 32];
    binding32[..8].copy_from_slice(&binding_seq.to_be_bytes());
    let gross_pot: u64 = pots.iter().map(|p| p.gross_amount).sum();
    let plan_rake: u64 = pots.iter().map(|p| p.rake).sum();
    let mut awards = [0u64; SETTLEMENT_SEATS];
    let mut winner_mask = 0u16;
    for pot in &pots {
        for (seat, amount) in pot.runouts[0].awards.iter().enumerate() {
            awards[seat] += *amount;
        }
        winner_mask |= pot.runouts[0].winner_mask;
    }
    let owner_of = |seat: usize| -> [u8; 33] {
        if seat == 0 { alice.pk() } else { bob.pk() }
    };
    let mk = |amount: u64, owner: [u8; 33], pot_index: u8| NoteSpec {
        asset_class: AssetClass::Play,
        amount,
        owner,
        table_id: None,
        pot_index,
        runout_index: 0,
    };
    let (treasury_out, operator_out) = if plan_rake == 0 {
        (None, None)
    } else {
        let FeePolicy::FixedRake { split, .. } = policy else {
            unreachable!("demo：非零 rake 只出现在 FixedRake 桌");
        };
        let (t, o) = policy.split_of(plan_rake);
        (Some(mk(t, split.treasury, 0)), Some(mk(o, split.operator, 0)))
    };
    // plan 投影规范序（Schedule::Single → 每 pot 只取 runout 0）
    let payouts: Vec<NoteSpec> = pots
        .iter()
        .flat_map(|pot| {
            pot.runouts[0]
                .awards
                .iter()
                .enumerate()
                .filter(|(_, amount)| **amount > 0)
                .map(move |(seat, amount)| mk(*amount, owner_of(seat), pot.pot_index))
        })
        .collect();
    SettlementRecord {
        table_id,
        hand_binding: binding32,
        policy_commitment: policy.commitment_bytes(),
        pot: gross_pot,
        inputs: Vec::new(),
        payouts,
        rake: RakeSplitRecord {
            total: plan_rake,
            treasury_out,
            operator_out,
        },
        plan: SettlementPlan {
            version: SETTLEMENT_PLAN_VERSION,
            schedule: SettlementRunoutSchedule::Single,
            gross_pot,
            rake: plan_rake,
            total_awards: awards.iter().sum(),
            winner_mask,
            awards,
            pots,
        },
        hand_proof: None,
    }
}

/// 填充真实 seat note 输入并按结算效果摘要逐个签名（S1：签名覆盖
/// `settle_effect`，记录必须已完整）后提交。
fn submit_settle(
    seq: &mut Sequencer,
    ts: &mut u64,
    alice: &Player,
    bob: &Player,
    seats: &[Note],
    mut record: SettlementRecord,
) -> Result<(), String> {
    record.inputs = seats
        .iter()
        .map(|n| SettleInput {
            note: n.clone(),
            spend: SpendAuth {
                commitment: n.commitment_bytes(),
                nullifier: [0; 32],
                sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
            },
        })
        .collect();
    let effect = settle_effect(&record);
    for (i, n) in seats.iter().enumerate() {
        let player = if i == 0 { alice } else { bob };
        record.inputs[i].spend = player.settle_auth(n, &record.hand_binding, &effect);
    }
    submit(seq, ts, Operation::Settle(Box::new(record)))
}
