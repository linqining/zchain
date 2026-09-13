//! TE-M4（排期表 §6）：GAME 桌 FixedRakeBurn 结算规则——合约侧销毁处置 +
//! appchain 准入/应用 + e2e（GAME 桌一手）。
//!
//! 覆盖（对应交付清单）：
//! 1. e2e（GAME 桌一手）：注册 token → Issue 给玩家 → 开 FixedRakeBurn 桌 →
//!    一手下注结算（SettleV2）→ 守恒 + rake burn 进 `game_outstanding` +
//!    供给对账闭合（INV-TE-7）+ WAL 重放恢复；
//! 2. v1/v2 边界：v1 结算遇 burn 策略 fail-closed 拒（v2 结算先行——GAME
//!    note 本就是 v2 账本资产）；
//! 3. 资金流混淆负例：burn 记录携带 treasury/operator 输出（双计）拒、
//!    percentage 桌 burn 化守恒拒、burn 低报 rake FeeMismatch 拒；
//! 4. burn rake 重复计入 outstanding：同 hand_binding 重放拒（outstanding
//!    不变）；
//! 5. REAL 域误用 burn 策略拒 / 遗留 PLAY(0) 与未注册 token 拒（GAME 域
//!    注册 GTS token 门）；
//! 6. 两侧一致性：settlement-core mode 2 plan ↔ `FeePolicy::rake_of` 费率
//!    关系 ↔ mode 1 plan 逐字段相等（计价同式，处置在合约/appchain）。
//!
//! 全部走 release（`cargo test -p poker-appchain --release --test te_m4`）。
//!
//! 边界（如实声明）：
//! - canonical AIR 出证路径不可达（burn 桌归档需 texasair 适配器管线；
//!   AIR 侧 opening 对 mode 2 的计费数量关系已在 TE-E0 实测——
//!   `canonical_settlement_rake` 对 mode ∈ {1, 2} 同式），故本文件为
//!   host 级 e2e；
//! - v2 seat 生命周期（BuyInV2）未引入：GAME 桌一手以 Issue 铸出的自由
//!   余额 note 直接作为结算输入（`validate_settlement_v2` 第 3 条允许
//!   v2 自由余额参与），账本变化口径为 issue → settle → outstanding 收缩；
//! - 合约侧（poker_l1 texas_poker）的 `rake_disposal` / prove_task burn
//!   视图测试在 poker_l1 套件（`settlement.rs` / `prove_task.rs`）。

use std::sync::Arc;

use poker_appchain::asset_id::AssetId;
use poker_appchain::error::AppchainError;
use poker_appchain::fee::{FeePolicy, FeeSplit};
use poker_appchain::game_token::{GameTokenSpec, IssuanceMode};
use poker_appchain::keys::OwnerKey;
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::AssetClass;
use poker_appchain::note_v2::{
    default_network_id, settle_effect_v2, settle_scope_v2, SettleInputV2, NoteSpec2, NoteV2,
    SettlementRecordV2,
};
use poker_appchain::ops::{IssueGameTokenOp, Operation, RegisterGameTokenOp};
use poker_appchain::owner_v2::{
    legacy_account_id, v2_spend_digest, OwnerRef, SignatureEnvelope, SignatureScheme,
    VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::settlement::RakeSplitRecord;
use poker_settlement_core::{
    derive_settlement_plan, SettlementBoards, TableSnapshot, RAKE_MODE_FIXED_RAKE_BURN,
    RAKE_MODE_PERCENTAGE,
};

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

/// 单字节前缀 32B id（测试幂等键构造）。
fn id32(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

/// 测试时钟（帧时间戳 ms；now = ts/1000 秒参与信封新鲜度）。
const T0: u64 = 1_000;
/// 信封有效期（unix 秒；远晚于测试时钟）。
const EXPIRY: u64 = 10_000;

/// v2 测试用户：secp256k1 密钥 + LegacySecp256k1 [`OwnerRef`]。
struct V2User {
    key: OwnerKey,
    secret: [u8; 32],
    owner: OwnerRef,
}

impl V2User {
    fn new(seed: u8) -> Self {
        let key = OwnerKey::from_seed(&[seed; 32]).unwrap();
        let owner = OwnerRef {
            scheme: SignatureScheme::LegacySecp256k1,
            account_id: legacy_account_id(&key.public_bytes()),
            key_version: 0,
            binding_id: None,
        };
        Self {
            key,
            secret: [seed; 32],
            owner,
        }
    }
}

/// 新 sequencer（内存模式；默认配置 = devnet network_id + 默认价带）。
fn new_sequencer() -> (Sequencer, Arc<MetricsRegistry>) {
    let metrics = Arc::new(MetricsRegistry::new());
    let seq = Sequencer::new(
        poker_appchain::keys::SequencerKey::from_seed(&[42u8; 32]),
        SequencerConfig::default(),
        Arc::clone(&metrics),
    );
    (seq, metrics)
}

/// TE-M4 标准 burn 策略：5%、无封顶、treasury 抽 20% of rake（**计价层
/// 拆分**；burn 处置下不产生 treasury/operator 现金输出，见 ABI_TE_M4.md）。
fn burn_policy(treasury: &V2User, operator: &V2User) -> FeePolicy {
    FeePolicy::FixedRakeBurn {
        rate_bps: 500,
        cap: 0,
        split: FeeSplit {
            treasury_bps: 2_000,
            treasury: treasury.key.public_bytes(),
            operator: operator.key.public_bytes(),
        },
    }
}

/// 同参数 percentage 策略（资金流混淆对照用）。
fn percentage_policy(treasury: &V2User, operator: &V2User) -> FeePolicy {
    FeePolicy::FixedRake {
        rate_bps: 500,
        cap: 0,
        split: FeeSplit {
            treasury_bps: 2_000,
            treasury: treasury.key.public_bytes(),
            operator: operator.key.public_bytes(),
        },
    }
}

/// RegisterGameToken op（Paid：anchor USDT、R = 1e6；genesis 摘要客户端
/// 预计算 = 链侧重算，同一函数无第二种换算）。
fn register_op(token_id: u32) -> Operation {
    let issuer = [0x02u8; 33];
    let mode = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDT,
        rate: 1_000_000,
    };
    let digest = GameTokenSpec::genesis_digest_of(token_id, &issuer, &mode, 0);
    Operation::RegisterGameToken(Box::new(RegisterGameTokenOp {
        token_id,
        issuer,
        mode,
        max_supply: 0,
        genesis_digest: digest,
    }))
}

/// IssueGameToken op（pay_amount = 1e18 wei/百万币刻度：1e18 × 1e6 / 1e18
/// = 1_000_000 游戏币）。
fn issue_op(id_byte: u8, token_id: u32, buyer: &OwnerRef, millions_e18: u64) -> Operation {
    Operation::IssueGameToken(Box::new(IssueGameTokenOp {
        issue_id: id32(id_byte),
        token_id,
        buyer: buyer.clone(),
        pay_amount: millions_e18 * 1_000_000_000_000_000_000,
    }))
}

/// 某 owner 名下指定 GAME token 的 live v2 note（测试辅助：账本扫描）。
fn game_note_of(seq: &Sequencer, owner: &OwnerRef, token_id: u32) -> NoteV2 {
    seq.state()
        .note_entries_v2_of(owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.asset_id == AssetId::game(token_id))
        .unwrap_or_else(|| panic!("no live GAME({token_id}) note"))
}

/// 构造**已签名**的 SettleV2 op（客户端侧流程：scope → nullifier → effect
/// 摘要 → v2_spend_digest → 信封签名；镜像 tests/note_v2.rs 纪律）。
///
/// 赢家取全部净额（输家 payout 为零 → 不出现在输出中）。
fn signed_settle_v2(
    table_id: u64,
    hand_binding_byte: u8,
    inputs: &[(&V2User, &NoteV2)],
    payout: NoteSpec2,
    rake_total: u64,
    policy: &FeePolicy,
) -> Operation {
    let net = default_network_id();
    let hand_binding = [hand_binding_byte; 32];
    let scope = settle_scope_v2(&net, OWNER_V2_ABI_VERSION, &hand_binding);
    let mut record = SettlementRecordV2 {
        table_id,
        hand_binding,
        policy_commitment: policy.commitment_bytes(),
        pot: inputs.iter().map(|(_, n)| n.amount).sum(),
        inputs: inputs
            .iter()
            .map(|(user, note)| SettleInputV2::V2 {
                note: (*note).clone(),
                nullifier: note.nullifier(&user.secret, &scope),
                envelope: SignatureEnvelope {
                    scheme: user.owner.scheme,
                    signer_ref: user.owner.clone(),
                    typed_data_digest: [0u8; 32],
                    signature: [0u8; 64],
                    nonce: 1,
                    expiry: EXPIRY,
                },
                material: VerifierMaterial::LegacySecp256k1 {
                    presented_public: user.key.public_bytes(),
                },
            })
            .collect(),
        payouts: vec![payout],
        rake: RakeSplitRecord {
            total: rake_total,
            treasury_out: None,
            operator_out: None,
        },
    };
    // 回填签名（效果摘要依赖完整记录）
    let effect = settle_effect_v2(&record);
    for (input, (user, note)) in record.inputs.iter_mut().zip(inputs) {
        if let SettleInputV2::V2 { envelope, .. } = input {
            let nullifier = note.nullifier(&user.secret, &scope);
            envelope.typed_data_digest = v2_spend_digest(
                &note.owner,
                &note.commitment_bytes(),
                &nullifier,
                &scope,
                &effect,
            );
            envelope.signature = user.key.sign(&envelope.typed_data_digest).bytes;
        }
    }
    Operation::SettleV2(Box::new(record))
}

// ---------------------------------------------------------------------------
// 1. e2e：GAME 桌一手（register → issue → open burn table → settle →
//    outstanding 收缩 → 对账闭合 → WAL 重放）
// ---------------------------------------------------------------------------

#[test]
fn game_burn_table_one_hand_e2e() {
    let dir = std::env::temp_dir().join("poker-appchain-te-m4");
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("te_m4_one_hand.wal");
    let _ = std::fs::remove_file(&wal);

    let (mut seq, metrics) = new_sequencer();
    seq.attach_wal(&wal).unwrap();
    let alice = V2User::new(1);
    let bob = V2User::new(2);
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let token = 1u32;
    let table = 77u64;

    // (1) 注册 GAME token（genesis 冻结）
    seq.submit(register_op(token), T0).unwrap();

    // (2) Issue 给玩家：各 1_000_000 币（1U = 100 万币，Paid 价率换算）
    seq.submit(issue_op(1, token, &alice.owner, 1), T0 + 1).unwrap();
    seq.submit(issue_op(2, token, &bob.owner, 1), T0 + 2).unwrap();
    assert_eq!(seq.state().game_outstanding(token), 2_000_000, "issue 后 outstanding = Σminted");
    assert_eq!(
        metrics.gauge(&format!("game_token_outstanding{{token=\"{token}\"}}")),
        2_000_000
    );

    // (3) 开 FixedRakeBurn 桌（策略开桌即冻结）
    let policy = burn_policy(&treasury, &operator);
    seq.submit(Operation::OpenTable { table_id: table, policy }, T0 + 3).unwrap();

    // (4) 一手：双方各推入 1_000_000（pot 2_000_000），alice 独赢；
    //     5% → rake 100_000，处置 = burn（无 treasury/operator 输出）；
    //     赢家拿全部净额 1_900_000。
    let alice_note = game_note_of(&seq, &alice.owner, token);
    let bob_note = game_note_of(&seq, &bob.owner, token);
    assert_eq!(alice_note.amount, 1_000_000);
    let settle = signed_settle_v2(
        table,
        0xA4,
        &[(&alice, &alice_note), (&bob, &bob_note)],
        NoteSpec2 {
            asset_id: AssetId::game(token),
            amount: 1_900_000,
            owner: alice.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        },
        100_000,
        &policy,
    );
    seq.submit(settle, T0 + 4).unwrap();

    // (5) 账本断言：赢家 1_900_000、输家 0、treasury/operator 现金为 0
    //    （burn ≠ 分账——资金流与 percentage 桌的硬差异）。
    let balances = |seq: &Sequencer, owner: &OwnerRef| {
        seq.state().balances_v2_of(owner).1
    };
    assert_eq!(balances(&seq, &alice.owner), 1_900_000);
    assert_eq!(balances(&seq, &bob.owner), 0);
    assert_eq!(seq.state().balances_of(&treasury.key.public_bytes()), (0, 0), "treasury 无现金入账");
    assert_eq!(seq.state().balances_of(&operator.key.public_bytes()), (0, 0), "operator 无现金入账");

    // (6) 供给恒等联动：rake burn 进 Σburned → outstanding 收缩 100_000，
    //    且 == 存续 GAME note 面额合计（INV-TE-7 三边闭合）。
    assert_eq!(seq.state().game_outstanding(token), 1_900_000);
    assert_eq!(seq.state().game_burned.get(&token), Some(&100_000u128));
    let rec = seq.state().game_reconciliation();
    assert!(rec.all_consistent);
    let report = rec.tokens.iter().find(|t| t.token_id == token).unwrap();
    assert_eq!(report.minted_total, 2_000_000);
    assert_eq!(report.burned_total, 100_000);
    assert_eq!(report.outstanding, 1_900_000);
    assert_eq!(report.live_note_sum, 1_900_000, "outstanding == Σ 存续 GAME note 面额");
    assert_eq!(
        metrics.gauge(&format!("game_token_outstanding{{token=\"{token}\"}}")),
        1_900_000,
        "outstanding gauge 随 burn 收缩"
    );
    assert_eq!(metrics.counter("game_settle_burn_admitted_total"), 1);
    assert_eq!(metrics.counter("game_settle_burn_amount_total"), 100_000);

    // (7) WAL 重放：game_burned / outstanding / 注册表 / 账本逐位恢复
    let root_before = seq.state().root();
    let rec_before = seq.state().game_reconciliation();
    drop(seq);
    let seq2 = Sequencer::replay(
        &wal,
        poker_appchain::keys::SequencerKey::from_seed(&[42u8; 32]).public,
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    )
    .unwrap();
    assert_eq!(seq2.state().root(), root_before, "重放逐位重现状态根");
    assert_eq!(seq2.state().game_outstanding(token), 1_900_000, "burn 记账随 apply 路径恢复");
    assert_eq!(seq2.state().game_reconciliation(), rec_before, "对账导出等价重建");
}

// ---------------------------------------------------------------------------
// 2. v1/v2 边界：v1 结算遇 burn 策略 fail-closed 拒
// ---------------------------------------------------------------------------

#[test]
fn v1_settlement_on_burn_table_rejected_fail_closed() {
    use poker_appchain::ops::scope;
    use poker_appchain::settlement::{SettleInput, SettlementRecord, SpendAuth};

    let (mut seq, _metrics) = new_sequencer();
    let key_a = poker_appchain::keys::OwnerKey::from_seed(&[11u8; 32]).unwrap();
    let key_b = poker_appchain::keys::OwnerKey::from_seed(&[12u8; 32]).unwrap();
    let secret_a = [11u8; 32];
    let secret_b = [12u8; 32];
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let policy = burn_policy(&treasury, &operator);
    let table = 88u64;
    seq.submit(Operation::OpenTable { table_id: table, policy }, T0).unwrap();

    // v1 资金流夹具：两名玩家 Deposit → BuyIn（该形态在 FixedRake 桌可完整
    // 走通到校验通过——拒因确为 v1 × burn 边界而非记录畸形）。
    let buy_in = |seq: &mut Sequencer, key: &OwnerKey, secret: [u8; 32], deposit_byte: u8, ts: u64| {
        seq.submit(
            Operation::Deposit {
                deposit_id: id32(deposit_byte),
                owner: key.public_bytes(),
                asset_class: AssetClass::Play,
                amount: 250,
            },
            ts,
        )
        .unwrap();
        let note = seq
            .state()
            .note_entries_of(&key.public_bytes())
            .into_iter()
            .find(|e| e.note.amount == 250)
            .unwrap()
            .note
            .clone();
        // 桌准入只收 proven note（M8 污染防御；与 settlement_flow 同路径）
        seq.mark_proven_through(seq.state().seq);
        let effect = Operation::BuyIn {
            table_id: table,
            spends: vec![],
            notes: vec![],
            seat_owner: key.public_bytes(),
        }
        .effect_digest();
        let nf = felt_to_bytes32(note.nullifier(&secret));
        let d = poker_appchain::keys::spend_digest(&note.commitment_bytes(), &nf, scope::BUYIN, &effect);
        seq.submit(
            Operation::BuyIn {
                table_id: table,
                spends: vec![SpendAuth {
                    commitment: note.commitment_bytes(),
                    nullifier: nf,
                    sig: key.sign(&d),
                }],
                notes: vec![note],
                seat_owner: key.public_bytes(),
            },
            ts + 1,
        )
        .unwrap();
    };
    buy_in(&mut seq, &key_a, secret_a, 1, T0 + 1);
    buy_in(&mut seq, &key_b, secret_b, 2, T0 + 3);
    let seat_of = |seq: &Sequencer, owner: [u8; 33]| {
        seq.state()
            .notes
            .values()
            .find(|e| e.note.table_id == Some(table) && e.note.owner == owner)
            .unwrap()
            .note
            .clone()
    };
    let seat_a = seat_of(&seq, key_a.public_bytes());
    let seat_b = seat_of(&seq, key_b.public_bytes());

    // 完整合法形态的 v1 结算记录（percentage 形状：contested 单层 plan +
    // 投影 + 分账）——同一记录在 FixedRake 桌可通过校验，在 burn 桌被拒。
    let hand_binding = [0xB4; 32];
    let mut awards = [0u64; poker_settlement_core::SETTLEMENT_SEATS];
    awards[0] = 240;
    awards[1] = 235;
    let plan = poker_appchain::settlement::flat_settlement_plan(500, 0b11, awards);
    let mk = |amount: u64, owner: [u8; 33]| poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Play,
        amount,
        owner,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let (t_exp, o_exp) = policy.split_of(25);
    let mut record = SettlementRecord {
        table_id: table,
        hand_binding,
        policy_commitment: policy.commitment_bytes(),
        pot: 500,
        inputs: vec![
            SettleInput {
                note: seat_a.clone(),
                spend: SpendAuth {
                    commitment: seat_a.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInput {
                note: seat_b.clone(),
                spend: SpendAuth {
                    commitment: seat_b.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
        ],
        payouts: vec![mk(240, key_a.public_bytes()), mk(235, key_b.public_bytes())],
        rake: RakeSplitRecord {
            total: 25,
            treasury_out: Some(mk(t_exp, treasury.key.public_bytes())),
            operator_out: Some(mk(o_exp, operator.key.public_bytes())),
        },
        plan,
        hand_proof: None,
    };
    let scope = poker_appchain::settlement::settle_spend_scope(&record.hand_binding);
    let effect = poker_appchain::settlement::settle_effect(&record);
    for (input, (key, secret, seat)) in record
        .inputs
        .iter_mut()
        .zip([(&key_a, secret_a, &seat_a), (&key_b, secret_b, &seat_b)])
    {
        let nf = felt_to_bytes32(seat.nullifier(&secret));
        let d = poker_appchain::keys::spend_digest(&seat.commitment_bytes(), &nf, &scope, &effect);
        input.spend = SpendAuth {
            commitment: seat.commitment_bytes(),
            nullifier: nf,
            sig: key.sign(&d),
        };
    }

    // 纯函数层：burn 策略 → 拒（第 0 条，先于一切计价/投影检查）
    let err = poker_appchain::settlement::validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("v1 settlement cannot settle a FixedRakeBurn table")),
        "v1 × burn 桌必须 fail-closed 拒，got {err:?}"
    );
    // 对照：同形态记录在 FixedRake 桌通过全部校验（拒因隔离证据）。
    // settle_effect 不覆盖 policy_commitment → 换绑 percentage 承诺后签名
    // 仍有效，唯一差异即策略承诺（mode 1 vs mode 2 preimage 分离的证据）。
    let mut control = record.clone();
    control.policy_commitment = percentage_policy(&treasury, &operator).commitment_bytes();
    assert!(
        poker_appchain::settlement::validate_settlement(
            &control,
            &percentage_policy(&treasury, &operator)
        )
        .is_ok(),
        "percentage 形状记录在 FixedRake 桌必须可校验（拒因隔离证据）"
    );
    // sequencer 层：v1 Settle op 入账路径同样拒、零状态变更
    let (r_before, _) = seq.state().balances_of(&key_a.public_bytes());
    let err = seq
        .submit(Operation::Settle(Box::new(record)), T0 + 5)
        .unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(s) if s.contains("FixedRakeBurn")));
    assert_eq!(seq.chain().len(), 5, "拒绝帧不入链（open + 2×(deposit+buyin)）");
    let (r_after, _) = seq.state().balances_of(&key_a.public_bytes());
    assert_eq!(r_before, r_after, "拒绝零状态变更");
}

// ---------------------------------------------------------------------------
// 3. 资金流混淆负例（纯函数层，validate_settlement_v2）
// ---------------------------------------------------------------------------

/// 两输入 GAME_PLAY 结算夹具（未签名——投影/守恒/分账检查在签名前）。
fn unsigned_v2_record(
    policy: &FeePolicy,
    rake_total: u64,
    treasury_out: Option<poker_appchain::note::NoteSpec>,
    operator_out: Option<poker_appchain::note::NoteSpec>,
    payout_amount: u64,
) -> SettlementRecordV2 {
    let owner = V2User::new(1);
    let other = V2User::new(2);
    let notes = [
        NoteV2::new(AssetId::GAME_PLAY, 1_000_000, owner.owner.clone(), 1, None, 0, 0).unwrap(),
        NoteV2::new(AssetId::GAME_PLAY, 1_000_000, other.owner.clone(), 1, None, 0, 0).unwrap(),
    ];
    SettlementRecordV2 {
        table_id: 1,
        hand_binding: [0xCC; 32],
        policy_commitment: policy.commitment_bytes(),
        pot: 2_000_000,
        inputs: notes
            .iter()
            .map(|note| SettleInputV2::V2 {
                note: note.clone(),
                nullifier: [9u8; 32],
                envelope: SignatureEnvelope {
                    scheme: SignatureScheme::LegacySecp256k1,
                    signer_ref: note.owner.clone(),
                    typed_data_digest: [0; 32],
                    signature: [0; 64],
                    nonce: 1,
                    expiry: EXPIRY,
                },
                material: VerifierMaterial::LegacySecp256k1 {
                    presented_public: owner.key.public_bytes(),
                },
            })
            .collect(),
        payouts: vec![NoteSpec2 {
            asset_id: AssetId::GAME_PLAY,
            amount: payout_amount,
            owner: owner.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        }],
        rake: RakeSplitRecord {
            total: rake_total,
            treasury_out,
            operator_out,
        },
    }
}

#[test]
fn burn_record_carrying_rake_outputs_rejected_no_double_count() {
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let burn = burn_policy(&treasury, &operator);
    // "既入账又销毁"的双计形态：burn 桌记录携带分账输出 → 拒
    let (t, o) = burn.split_of(100_000);
    let mk = |amount: u64, owner: [u8; 33]| poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Play,
        amount,
        owner,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let record = unsigned_v2_record(
        &burn,
        100_000,
        Some(mk(t, treasury.key.public_bytes())),
        Some(mk(o, operator.key.public_bytes())),
        1_900_000,
    );
    let err = poker_appchain::note_v2::validate_settlement_v2(
        &record,
        &burn,
        &default_network_id(),
        OWNER_V2_ABI_VERSION,
        T0 / 1000,
        &|_| None,
    )
    .unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("must not carry treasury/operator outputs")),
        "burn 记账与分账互斥（防 rake 双计），got {err:?}"
    );
}

#[test]
fn percentage_table_burn_shaped_record_rejected_by_conservation() {
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let percentage = percentage_policy(&treasury, &operator);
    // percentage 桌试图 burn 化（无分账输出）→ 守恒拒（分账路径不可绕过）
    let record = unsigned_v2_record(&percentage, 100_000, None, None, 1_900_000);
    let err = poker_appchain::note_v2::validate_settlement_v2(
        &record,
        &percentage,
        &default_network_id(),
        OWNER_V2_ABI_VERSION,
        T0 / 1000,
        &|_| None,
    )
    .unwrap_err();
    assert!(
        matches!(err, AppchainError::ConservationViolated { inputs: 2_000_000, outputs: 1_900_000, .. }),
        "percentage 桌缺分账输出必须守恒拒，got {err:?}"
    );
}

#[test]
fn burn_under_reported_rake_rejected_by_fee_relation() {
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let burn = burn_policy(&treasury, &operator);
    // 低报销毁额：99_999 ≠ policy.rake_of(2_000_000) = 100_000 → FeeMismatch
    //（守恒自洽：1_900_001 + 99_999 = pot——唯一拒点是费率关系）
    let record = unsigned_v2_record(&burn, 99_999, None, None, 1_900_001);
    let err = poker_appchain::note_v2::validate_settlement_v2(
        &record,
        &burn,
        &default_network_id(),
        OWNER_V2_ABI_VERSION,
        T0 / 1000,
        &|_| None,
    )
    .unwrap_err();
    assert!(
        matches!(err, AppchainError::FeeMismatch { expected: 100_000, got: 99_999 }),
        "burn 桌低报 rake 必须费率关系拒，got {err:?}"
    );

    // 正例对照：正确 burn 形态（payout 1_900_000 + 销毁 100_000 = pot、
    // 无分账输出）通过投影/守恒/费率全部检查，仅在签名步失败（未签名夹具）
    let ok = unsigned_v2_record(&burn, 100_000, None, None, 1_900_000);
    let res = poker_appchain::note_v2::validate_settlement_v2(
        &ok,
        &burn,
        &default_network_id(),
        OWNER_V2_ABI_VERSION,
        T0 / 1000,
        &|_| None,
    );
    match res {
        Err(AppchainError::BadSignature) | Err(AppchainError::AdmissionRejected(_)) => {}
        other => panic!("expected signature-stage failure only, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. burn rake 重复计入 outstanding：重放拒
// ---------------------------------------------------------------------------

#[test]
fn burn_settlement_replay_rejected_outstanding_unchanged() {
    let (mut seq, _metrics) = new_sequencer();
    let alice = V2User::new(1);
    let bob = V2User::new(2);
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let token = 3u32;
    let table = 79u64;
    seq.submit(register_op(token), T0).unwrap();
    seq.submit(issue_op(1, token, &alice.owner, 1), T0 + 1).unwrap();
    seq.submit(issue_op(2, token, &bob.owner, 1), T0 + 2).unwrap();
    let policy = burn_policy(&treasury, &operator);
    seq.submit(Operation::OpenTable { table_id: table, policy }, T0 + 3).unwrap();

    let alice_note = game_note_of(&seq, &alice.owner, token);
    let bob_note = game_note_of(&seq, &bob.owner, token);
    let settle = signed_settle_v2(
        table,
        0xA5,
        &[(&alice, &alice_note), (&bob, &bob_note)],
        NoteSpec2 {
            asset_id: AssetId::game(token),
            amount: 1_900_000,
            owner: alice.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        },
        100_000,
        &policy,
    );
    seq.submit(settle.clone(), T0 + 4).unwrap();
    let outstanding_after_first = seq.state().game_outstanding(token);
    assert_eq!(outstanding_after_first, 1_900_000);

    // 重放同一手（同 hand_binding，输出重新签名）→ SettlementReplay，
    // outstanding 不得二次收缩（burn 重复计入被重放防线阻断）。
    let replay = signed_settle_v2(
        table,
        0xA5,
        &[(&alice, &alice_note), (&bob, &bob_note)],
        NoteSpec2 {
            asset_id: AssetId::game(token),
            amount: 1_900_000,
            owner: alice.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        },
        100_000,
        &policy,
    );
    let err = seq.submit(replay, T0 + 5).unwrap_err();
    assert!(matches!(err, AppchainError::SettlementReplay));
    assert_eq!(seq.state().game_outstanding(token), outstanding_after_first, "重放不得二次收缩");
    assert_eq!(seq.state().game_burned.get(&token), Some(&100_000u128));
    let _ = settle;
}

// ---------------------------------------------------------------------------
// 5. GAME 域注册门：REAL 域误用 burn 策略 / 遗留 PLAY / 未注册 token
// ---------------------------------------------------------------------------

#[test]
fn burn_policy_requires_registered_game_domain_token() {
    let (mut seq, metrics) = new_sequencer();
    let alice = V2User::new(1);
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let policy = burn_policy(&treasury, &operator);

    // (a) REAL 域误用 burn 策略：NATIVE 存款 + burn 桌 → 准入门拒
    let net = default_network_id();
    seq.submit(register_op(1), T0).unwrap();
    seq.submit(
        poker_appchain::ops::DepositV2Op {
            deposit_id: id32(1),
            owner: alice.owner.clone(),
            asset_id: AssetId::REAL_NATIVE,
            amount: 1_000,
        }
        .into_op(),
        T0 + 1,
    )
    .unwrap();
    seq.submit(Operation::OpenTable { table_id: 90, policy }, T0 + 2).unwrap();
    let real_note = seq
        .state()
        .note_entries_v2_of(&alice.owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.asset_id == AssetId::REAL_NATIVE)
        .unwrap();
    let real_record = SettlementRecordV2 {
        table_id: 90,
        hand_binding: [0xE1; 32],
        policy_commitment: policy.commitment_bytes(),
        pot: 1_000,
        inputs: vec![SettleInputV2::V2 {
            note: real_note.clone(),
            nullifier: real_note.nullifier(&alice.secret, &settle_scope_v2(
                &net,
                OWNER_V2_ABI_VERSION,
                &[0xE1; 32],
            )),
            envelope: SignatureEnvelope {
                scheme: SignatureScheme::LegacySecp256k1,
                signer_ref: alice.owner.clone(),
                typed_data_digest: [0; 32],
                signature: [0; 64],
                nonce: 1,
                expiry: EXPIRY,
            },
            material: VerifierMaterial::LegacySecp256k1 {
                presented_public: alice.key.public_bytes(),
            },
        }],
        payouts: vec![NoteSpec2 {
            asset_id: AssetId::REAL_NATIVE,
            amount: 950,
            owner: alice.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        }],
        rake: RakeSplitRecord {
            total: 50,
            treasury_out: None,
            operator_out: None,
        },
    };
    let err = seq
        .submit(Operation::SettleV2(Box::new(real_record)), T0 + 3)
        .unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("requires a registered GAME domain token")),
        "REAL 域误用 burn 策略必须拒，got {err:?}"
    );
    assert!(metrics.counter("game_token_rejected_total") >= 1);

    // (b) 未注册 GAME token（伪造 game(999) 持仓形态）：门在账本核对前拒
    let forged = NoteV2::new(AssetId::game(999), 500, alice.owner.clone(), 7, None, 0, 0).unwrap();
    let forged_record = SettlementRecordV2 {
        table_id: 90,
        hand_binding: [0xE2; 32],
        policy_commitment: policy.commitment_bytes(),
        pot: 500,
        inputs: vec![SettleInputV2::V2 {
            note: forged,
            nullifier: [3u8; 32],
            envelope: SignatureEnvelope {
                scheme: SignatureScheme::LegacySecp256k1,
                signer_ref: alice.owner.clone(),
                typed_data_digest: [0; 32],
                signature: [0; 64],
                nonce: 2,
                expiry: EXPIRY,
            },
            material: VerifierMaterial::LegacySecp256k1 {
                presented_public: alice.key.public_bytes(),
            },
        }],
        payouts: vec![NoteSpec2 {
            asset_id: AssetId::game(999),
            amount: 475,
            owner: alice.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        }],
        rake: RakeSplitRecord {
            total: 25,
            treasury_out: None,
            operator_out: None,
        },
    };
    let err = seq
        .submit(Operation::SettleV2(Box::new(forged_record)), T0 + 4)
        .unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("requires a registered GAME domain token")),
        "未注册 token 的 burn 桌结算必须拒，got {err:?}"
    );
}

#[test]
fn burn_policy_rejects_legacy_play_token() {
    let (mut seq, _metrics) = new_sequencer();
    let alice = V2User::new(1);
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let policy = burn_policy(&treasury, &operator);
    seq.submit(Operation::OpenTable { table_id: 91, policy }, T0).unwrap();
    // 遗留 PLAY(0)：无 GTS 规格、outstanding 恒等式不经 Issue 维护 → 拒
    let play_note = NoteV2::new(AssetId::GAME_PLAY, 500, alice.owner.clone(), 7, None, 0, 0).unwrap();
    let record = SettlementRecordV2 {
        table_id: 91,
        hand_binding: [0xE3; 32],
        policy_commitment: policy.commitment_bytes(),
        pot: 500,
        inputs: vec![SettleInputV2::V2 {
            note: play_note,
            nullifier: [4u8; 32],
            envelope: SignatureEnvelope {
                scheme: SignatureScheme::LegacySecp256k1,
                signer_ref: alice.owner.clone(),
                typed_data_digest: [0; 32],
                signature: [0; 64],
                nonce: 1,
                expiry: EXPIRY,
            },
            material: VerifierMaterial::LegacySecp256k1 {
                presented_public: alice.key.public_bytes(),
            },
        }],
        payouts: vec![NoteSpec2 {
            asset_id: AssetId::GAME_PLAY,
            amount: 475,
            owner: alice.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        }],
        rake: RakeSplitRecord {
            total: 25,
            treasury_out: None,
            operator_out: None,
        },
    };
    let err = seq
        .submit(Operation::SettleV2(Box::new(record)), T0 + 1)
        .unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("requires a registered GAME domain token")),
        "遗留 PLAY(0) 不得走 burn 处置，got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. 两侧一致性：settlement-core mode 2 plan ↔ FeePolicy 费率关系
//    （合约/共识层对 mode 2 的处置建立在同一数量关系上）
// ---------------------------------------------------------------------------

#[test]
fn settlement_core_mode2_plan_matches_fee_policy_and_mode1() {
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let burn = burn_policy(&treasury, &operator);
    let percentage = percentage_policy(&treasury, &operator);

    // 单层 contested 一手：两座各 1_000_000，座0 ♠A♠K、座1 ♣Q♣J，
    // board ♠Q♠J♠10♥2♦2 → 座0 黑桃皇家同花顺独大（与 settlement-core /
    // poker_l1 对照测试同一牌局形态；底牌与板无重复）。
    let total_bets = [1_000_000u64, 1_000_000];
    let inactive = [false, false];
    let all_in = [true, true];
    let holes: [&[u8]; 2] = [&[12u8, 11], &[36, 35]];
    let snap = |rake_mode: u8| TableSnapshot {
        seat_count: 2,
        button: 0,
        total_bets: &total_bets,
        inactive: &inactive,
        all_in: &all_in,
        hole_cards: &holes,
        rake_mode,
        rake_bps: 500,
        // TableSnapshot.rake_cap 是硬上限数值（非 FeePolicy 的 0=无封顶
        // 语义）；取 MAX 与下方无封顶策略的费率关系对齐。
        rake_cap: u64::MAX,
    };
    let boards = SettlementBoards::single(vec![10, 9, 8, 13, 26]);
    let burn_plan = derive_settlement_plan(&snap(RAKE_MODE_FIXED_RAKE_BURN), &boards).unwrap();
    let percentage_plan = derive_settlement_plan(&snap(RAKE_MODE_PERCENTAGE), &boards).unwrap();

    // 计价同式：mode 2 plan == mode 1 plan（逐字段 + digest）
    assert_eq!(burn_plan, percentage_plan, "TE-M4 定稿：mode 2 与 mode 1 计价数量关系同式");
    assert_eq!(burn_plan.gross_pot, 2_000_000);
    assert_eq!(burn_plan.rake, 100_000);
    assert_eq!(burn_plan.total_awards, 1_900_000);

    // 费率关系（appchain 结算同式）：plan.rake == policy.rake_of(rake_base)
    assert_eq!(burn_plan.rake_base(), 2_000_000);
    assert_eq!(u64::from(burn_plan.rake), burn.rake_of(burn_plan.rake_base()));
    assert_eq!(u64::from(burn_plan.rake), percentage.rake_of(burn_plan.rake_base()));
    // burn 处置守恒：gross = awards + 销毁额（rake.total 即销毁份额）
    assert_eq!(
        u128::from(burn_plan.gross_pot),
        u128::from(burn_plan.total_awards) + u128::from(burn_plan.rake),
    );
    // 分账拆分（计价层）只是审计口径，不产生现金输出（e2e 已断言余额为 0）
    let (t, o) = burn.split_of(burn_plan.rake);
    assert_eq!(t + o, u64::from(burn_plan.rake));
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// bytes32 felt 工具（v1 花费授权 nullifier 编码用）。
fn felt_to_bytes32(felt: starknet_crypto::FieldElement) -> [u8; 32] {
    poker_appchain::felt::felt_to_bytes32(&felt)
}

/// DepositV2Op → Operation 便捷转换（本文件可读性）。
trait IntoOp {
    fn into_op(self) -> Operation;
}

impl IntoOp for poker_appchain::ops::DepositV2Op {
    fn into_op(self) -> Operation {
        Operation::DepositV2(Box::new(self))
    }
}
