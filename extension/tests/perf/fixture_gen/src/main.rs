//! M6-ACC-1 夹具生成器（一次性工具，不改任何仓库源码/既有测试）。
//!
//! 复刻 `poker-appchain/tests/common/mod.rs` 的 `two_player_settlement` +
//! `TestUser::settle_auth` 构造路径（同一公开 API，不重实现密码学），为
//! 10 手牌各产出一份真实结算验证输入 JSON：
//!   - SettlementRecord（ABI v1.2，含 SettlementPlan）+ FeePolicy 的 borsh hex；
//!   - 每输入 SpendAuth（owner ECDSA 签名覆盖 scope+effect，真实可验）；
//!   - 软确认链（OpenTable → Settle 两帧，sequencer ed25519 签名，链可全量重验）；
//!   - settlement_binding 与批次根（单手绑定集的 batch_root 复算值）。
//! 手 10 为负例：对正例记录的一个 SpendAuth 签名字节翻转（伪造证明注入），
//! 生成器内自检 `validate_settlement` 必须拒绝。
//!
//! 生成器内的自检（正例全过 / 负例被拒 / 软确认链 verify_chain 过 / 批次根
//! 复算一致）失败即 panic，保证入库夹具的有效性。

use poker_appchain::fee::{FeePolicy, FeeSplit};
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{blake2s32, spend_digest, OwnerKey, SequencerKey};
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::ops::Operation;
use poker_appchain::pipeline::batch_root;
use poker_appchain::settlement::{
    flat_settlement_plan, settle_effect, settle_spend_scope, settlement_binding,
    validate_settlement, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};
use poker_appchain::soft_confirm::{genesis_prev_hash, verify_chain, SignedFrame, SoftConfirmFrame};
use serde::Serialize;

fn main() {
    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/m6acc1");
    std::fs::create_dir_all(&out_dir).expect("create fixture dir");

    // 固定 sequencer（与 poker-appchain 测试口径一致：seed 42）
    let sequencer = SequencerKey::from_seed(&[42u8; 32]);
    let sequencer_public = sequencer.public;
    // treasury/operator 固定（seed 7/8，同 tests/common rake_policy）
    let treasury = user(7);
    let operator = user(8);

    let mut manifest_files = Vec::new();
    for hand in 1..=10u32 {
        let negative = hand == 10;
        let fixture = build_hand(
            hand,
            negative,
            &treasury,
            &operator,
            &sequencer,
            sequencer_public,
        );
        let name = format!("hand_{hand:02}.json");
        let path = out_dir.join(&name);
        std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
        println!(
            "wrote {} (variant={}, pot={}, rake={})",
            path.display(),
            fixture.variant,
            fixture.amounts.pot,
            fixture.amounts.rake
        );
        manifest_files.push(name);
    }

    let manifest = serde_json::json!({
        "what": "M6-ACC-1 浏览器验证吞吐夹具（10 手 = 9 正例 + 1 伪造负例）",
        "generated_by": "extension/tests/perf/fixture_gen（一次性 Rust 工具，公开 API 构造，含生成期自检）",
        "abi": "SettlementRecord ABI v1.2（含 SettlementPlan）；FeePolicy FixedRake 5%/cap 0/split 20% treasury",
        "asset_class": "PLAY",
        "self_checks_at_generation": [
            "validate_settlement(positive) == Ok（全部 10 份正例记录）",
            "validate_settlement(negative twin) == Err（手 10 翻转 inputs[1].spend.sig 末字节后）",
            "soft_confirm::verify_chain(frames, sequencer_public) == Ok（每手两帧链）",
            "pipeline::batch_root(bindings) == claimed_root（每手单绑定批次根）"
        ],
        "files": manifest_files,
        "sequencer_public": hex::encode(sequencer_public),
    });
    std::fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    println!("wrote {}", out_dir.join("manifest.json").display());
}

struct TestUser {
    key: OwnerKey,
    secret: [u8; 32],
}

fn user(seed: u8) -> TestUser {
    TestUser { key: OwnerKey::from_seed(&[seed; 32]).expect("owner key"), secret: [seed; 32] }
}

impl TestUser {
    fn pk(&self) -> [u8; 33] {
        self.key.public_bytes()
    }
    /// 与 tests/common/mod.rs `settle_auth` 同构（scope = 结算域 + hand_binding，
    /// effect = 完整结算效果摘要）。
    fn settle_auth(&self, note: &Note, record: &SettlementRecord) -> SpendAuth {
        let scope = settle_spend_scope(&record.hand_binding);
        let effect = settle_effect(record);
        let nf = felt_to_bytes32(&note.nullifier(&self.secret));
        let d = spend_digest(&note.commitment_bytes(), &nf, &scope, &effect);
        SpendAuth { commitment: note.commitment_bytes(), nullifier: nf, sig: self.key.sign(&d) }
    }
}

#[derive(Serialize)]
struct Fixture {
    hand: u32,
    variant: &'static str,
    expected: &'static str,
    description: String,
    chain_id: &'static str,
    table_id: u64,
    policy_borsh: String,
    /// 浏览器面要验证的记录：正例 = 完整签名记录；负例 = 翻转签名字节后的记录。
    record_borsh: String,
    /// 正例记录的 settlement_binding（32B hex；负例的 binding 应随之改变，
    /// 故这里给出的是未被篡改正例的绑定，仅作对照）。
    expected_binding: String,
    soft_chain: SoftChain,
    batch: Batch,
    amounts: Amounts,
}

#[derive(Serialize)]
struct SoftChain {
    sequencer_public: String,
    frames: Vec<Frame>,
}

#[derive(Serialize)]
struct Frame {
    frame_borsh: String,
    sig: String,
}

#[derive(Serialize)]
struct Batch {
    bindings: Vec<String>,
    claimed_root: String,
}

#[derive(Serialize)]
struct Amounts {
    pot: u64,
    rake: u64,
    payout_a: u64,
    payout_b: u64,
}

fn build_hand(
    hand: u32,
    negative: bool,
    treasury: &TestUser,
    operator: &TestUser,
    sequencer: &SequencerKey,
    sequencer_public: [u8; 32],
) -> Fixture {
    let a = user(hand as u8);
    let b = user((hand + 20) as u8);
    let table_id = u64::from(1_000 + hand);
    let policy = FeePolicy::FixedRake {
        rate_bps: 500,
        cap: 0,
        split: FeeSplit {
            treasury_bps: 2_000,
            treasury: treasury.pk(),
            operator: operator.pk(),
        },
    };

    // seat notes（本手下注贡献；nonce 每手唯一）
    let seat_a_amount = 1_000 + u64::from(hand) * 10;
    let seat_b_amount = 2_000 + u64::from(hand) * 10;
    let mut nonce_a = [0u8; 32];
    nonce_a[0] = 0xA0 + hand as u8;
    let mut nonce_b = [0u8; 32];
    nonce_b[0] = 0xB0 + hand as u8;
    let seat_a = Note::new(AssetClass::Play, seat_a_amount, a.pk(), nonce_a, Some(table_id))
        .expect("seat note a");
    let seat_b = Note::new(AssetClass::Play, seat_b_amount, b.pk(), nonce_b, Some(table_id))
        .expect("seat note b");

    let pot = seat_a_amount + seat_b_amount;
    let rake_total = policy.rake_of(pot);
    let payout_a = pot / 4 + u64::from(hand) * 15;
    let payout_b = pot - rake_total - payout_a;
    assert!(payout_b > 0, "payout_b must stay positive");

    // plan：单层 contested（两人都 eligible），awards 与 payouts 一一对应
    let mut awards = [0u64; 9];
    awards[0] = payout_a;
    awards[1] = payout_b;
    let plan = flat_settlement_plan(pot, 0b11, awards);

    let (t_amt, o_amt) = policy.split_of(rake_total);
    let mk = |amount: u64, owner: [u8; 33]| NoteSpec {
        asset_class: AssetClass::Play,
        amount,
        owner,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };

    let mut record = SettlementRecord {
        table_id,
        hand_binding: [hand as u8; 32],
        policy_commitment: policy.commitment_bytes(),
        pot,
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
        payouts: vec![mk(payout_a, a.pk()), mk(payout_b, b.pk())],
        rake: RakeSplitRecord {
            total: rake_total,
            treasury_out: Some(mk(t_amt, treasury.pk())),
            operator_out: Some(mk(o_amt, operator.pk())),
        },
        plan,
        hand_proof: None,
    };
    // S1/P0-7：授权对完整结算效果签名（记录完整后构造，与测试夹具同序）
    record.inputs[0].spend = a.settle_auth(&seat_a, &record);
    record.inputs[1].spend = b.settle_auth(&seat_b, &record);

    // 生成期自检 1：正例必须通过账本全量校验
    validate_settlement(&record, &policy).expect("positive record must validate");

    let binding = felt_to_bytes32(&settlement_binding(&record));

    // 负例：翻转 inputs[1] SpendAuth 签名末字节（伪造证明注入；M6-ACC-3 面）
    let record_for_browser = if negative {
        let mut tampered = record.clone();
        let n = tampered.inputs[1].spend.sig.bytes.len();
        tampered.inputs[1].spend.sig.bytes[n - 1] ^= 1;
        let err = validate_settlement(&tampered, &policy)
            .err()
            .expect("tampered signature must be rejected");
        println!("  hand 10 negative self-check: rejected as expected ({err})");
        tampered
    } else {
        record.clone()
    };

    // 软确认链：OpenTable（index 0）→ Settle（index 1），sequencer ed25519 签名
    let ts_ms = 1_700_000_000_000u64 + u64::from(hand) * 1_000;
    let f0_op = Operation::OpenTable { table_id, policy };
    let state0 = blake2s32(&[b"m6acc1-state", &table_id.to_be_bytes(), &[0u8]]);
    let frame0 = SoftConfirmFrame {
        index: 0,
        prev_hash: genesis_prev_hash(),
        op: f0_op,
        state_root: state0,
        ts_ms,
    };
    let signed0 = SignedFrame::sign(frame0, sequencer).expect("sign frame0");
    let h0 = signed0.hash().expect("hash frame0");
    let frame1 = SoftConfirmFrame {
        index: 1,
        prev_hash: h0,
        op: Operation::Settle(Box::new(record.clone())),
        state_root: blake2s32(&[b"m6acc1-state", &table_id.to_be_bytes(), &[1u8]]),
        ts_ms: ts_ms + 200,
    };
    let signed1 = SignedFrame::sign(frame1, sequencer).expect("sign frame1");

    // 生成期自检 2：链全量重验（ed25519 + 接续性）
    let frames = vec![signed0.clone(), signed1.clone()];
    verify_chain(&frames, &sequencer_public).expect("soft chain must verify");

    // 批次根：单手绑定集的确定性折叠复算
    let claimed_root = batch_root(&[binding]).expect("batch root");
    // 生成期自检 3：复算一致性（重算一遍逐字节比对）
    assert_eq!(batch_root(&[binding]).expect("batch root again"), claimed_root);

    Fixture {
        hand,
        variant: if negative { "negative_forged_sig" } else { "positive" },
        expected: if negative { "reject" } else { "pass" },
        description: if negative {
            "负例：正例记录 inputs[1].spend.sig 末字节翻转（伪造 P 层签名）。\
             预期 wallet-core 校验面 VerifierRejected 拒绝。计入吞吐。"
                .to_string()
        } else {
            "正例：两人桌 PLAY 结算（ABI v1.2 含 plan），双输入 SpendAuth 真实签名，\
             预期 wallet-core 校验面通过并产出结算操作。"
                .to_string()
        },
        chain_id: "zchain-devnet-1",
        table_id,
        policy_borsh: hex::encode(borsh::to_vec(&policy).unwrap()),
        record_borsh: hex::encode(borsh::to_vec(&record_for_browser).unwrap()),
        expected_binding: hex::encode(binding),
        soft_chain: SoftChain {
            sequencer_public: hex::encode(sequencer_public),
            frames: vec![
                Frame {
                    frame_borsh: hex::encode(borsh::to_vec(&signed0.frame).unwrap()),
                    sig: hex::encode(signed0.sig),
                },
                Frame {
                    frame_borsh: hex::encode(borsh::to_vec(&signed1.frame).unwrap()),
                    sig: hex::encode(signed1.sig),
                },
            ],
        },
        batch: Batch {
            bindings: vec![hex::encode(binding)],
            claimed_root: hex::encode(claimed_root),
        },
        amounts: Amounts { pot, rake: rake_total, payout_a, payout_b },
    }
}
