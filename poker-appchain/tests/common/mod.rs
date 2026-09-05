//! 集成测试共享工具：测试用户（密钥+spend secret 成对）与标准牌局流。

use poker_appchain::fee::{FeePolicy, FeeSplit};
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{spend_digest, OwnerKey};
use poker_appchain::merkle::PoseidonMerkleTree;
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::nullifier_set::NullifierSet;
use poker_appchain::ops::Operation;
use poker_appchain::sequencer::{NoteStatus, Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};
use std::sync::Arc;

/// 测试用户：OwnerKey 与 spend secret 绑定（生产中 secret 由客户端派生）。
#[derive(Clone)]
pub struct TestUser {
    pub key: OwnerKey,
    pub secret: [u8; 32],
}

impl TestUser {
    #[must_use]
    pub fn new(seed: u8) -> Self {
        Self {
            key: OwnerKey::from_seed(&[seed; 32]).unwrap(),
            secret: [seed; 32],
        }
    }

    #[must_use]
    pub fn pk(&self) -> [u8; 33] {
        self.key.public_bytes()
    }

    /// 构造 note（nonce 手工指定，测试内保证唯一）。
    #[must_use]
    pub fn note(&self, amount: u64, class: AssetClass, nonce_byte: u8) -> Note {
        let mut nonce = [0u8; 32];
        nonce[0] = nonce_byte;
        Note::new(class, amount, self.pk(), nonce, None).unwrap()
    }

    /// 对 note 构造花费授权（S1：签名绑定操作效果摘要）。
    #[must_use]
    pub fn auth(&self, note: &Note, scope_tag: &[u8], effect: &[u8; 32]) -> SpendAuth {
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(
            &note.commitment_bytes(),
            &felt_to_bytes32(&nf),
            scope_tag,
            effect,
        );
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }

    /// 对结算输入构造花费授权（scope = 结算域 + hand_binding；
    /// effect = 完整结算效果摘要，由记录本身导出）。
    #[must_use]
    pub fn settle_auth(&self, note: &Note, record: &SettlementRecord) -> SpendAuth {
        let scope =
            poker_appchain::settlement::settle_spend_scope(&record.hand_binding);
        let effect = poker_appchain::settlement::settle_effect(record);
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(
            &note.commitment_bytes(),
            &felt_to_bytes32(&nf),
            &scope,
            &effect,
        );
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }

    /// 买入授权（effect 自动从 (table_id, seat_owner) 导出）。
    #[must_use]
    pub fn buyin_auth(&self, note: &Note, table_id: u64, seat_owner: [u8; 33]) -> SpendAuth {
        let effect = poker_appchain::ops::Operation::BuyIn {
            table_id,
            spends: vec![],
            notes: vec![],
            seat_owner,
        }
        .effect_digest();
        self.auth(note, poker_appchain::ops::scope::BUYIN, &effect)
    }

    /// 转账授权（effect 自动从 outputs 导出）。
    #[must_use]
    pub fn transfer_auth(&self, note: &Note, outputs: &[NoteSpec]) -> SpendAuth {
        let effect = poker_appchain::ops::Operation::Transfer {
            spends: vec![],
            notes: vec![],
            outputs: outputs.to_vec(),
        }
        .effect_digest();
        self.auth(note, poker_appchain::ops::scope::TRANSFER, &effect)
    }
}

/// 标准费率：5% rake，treasury 抽 20% of rake。
#[must_use]
pub fn rake_policy(treasury: &TestUser, operator: &TestUser) -> FeePolicy {
    FeePolicy::FixedRake {
        rate_bps: 500,
        cap: 0,
        split: FeeSplit {
            treasury_bps: 2_000,
            treasury: treasury.pk(),
            operator: operator.pk(),
        },
    }
}

/// 新建内存 sequencer。
#[must_use]
pub fn new_sequencer() -> Sequencer {
    Sequencer::new(
        poker_appchain::keys::SequencerKey::from_seed(&[42u8; 32]),
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    )
}

/// 入金并返回账本中的 note（按 owner+amount 查找）。
pub fn deposit_and_find(
    seq: &mut Sequencer,
    user: &TestUser,
    amount: u64,
    class: AssetClass,
    deposit_id_byte: u8,
) -> Note {
    let mut deposit_id = [0u8; 32];
    deposit_id[0] = deposit_id_byte;
    seq.submit(
        Operation::Deposit {
            deposit_id,
            owner: user.pk(),
            asset_class: class,
            amount,
        },
        1_000,
    )
    .unwrap();
    find_note(seq, user, amount)
}

/// 按 owner+amount 查找账本 note。
#[must_use]
pub fn find_note(seq: &Sequencer, user: &TestUser, amount: u64) -> Note {
    seq.state()
        .notes
        .values()
        .find(|e| e.note.owner == user.pk() && e.note.amount == amount)
        .unwrap()
        .note
        .clone()
}

/// 构造结算记录（两人桌）。`pot` 是本手**下注额**（rake 计费基数），
/// `payout_a/b` 是结算后的新筹码堆（inputs 总额 = payouts + rake）。
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn two_player_settlement(
    table_id: u64,
    a: &TestUser,
    b: &TestUser,
    seat_a: &Note,
    seat_b: &Note,
    pot: u64,
    payout_a: u64,
    payout_b: u64,
    policy: &FeePolicy,
    hand_binding_byte: u8,
) -> SettlementRecord {
    let rake_total = policy.rake_of(pot);
    let (t_amt, o_amt) = policy.split_of(rake_total);
    let class = seat_a.asset_class;
    let mk = |amount: u64, owner: [u8; 33]| NoteSpec {
        asset_class: class,
        amount,
        owner,
        table_id: None,
    };
    let (treasury_out, operator_out) = if rake_total == 0 {
        (None, None)
    } else if let FeePolicy::FixedRake { split, .. } = policy {
        (Some(mk(t_amt, split.treasury)), Some(mk(o_amt, split.operator)))
    } else {
        (None, None)
    };
    let mut record = SettlementRecord {
        table_id,
        hand_binding: [hand_binding_byte; 32],
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
        payouts: vec![
            mk(payout_a, a.pk()),
            mk(payout_b, b.pk()),
        ],
        rake: RakeSplitRecord {
            total: rake_total,
            treasury_out,
            operator_out,
        },
        hand_proof: None,
    };
    // S1：授权对完整结算效果签名（记录完整后构造）
    record.inputs[0].spend = a.settle_auth(seat_a, &record);
    record.inputs[1].spend = b.settle_auth(seat_b, &record);
    record
}

/// 从账本导出全部 note 的包含证明（证明注册表/客户端分发模拟）。
#[must_use]
pub fn export_credentials(
    seq: &Sequencer,
) -> Vec<(poker_appchain::note::Note, poker_appchain::merkle::InclusionProof)> {
    let mut out = Vec::new();
    for e in seq.state().notes.values() {
        let proof = seq.state().tree.proof(e.leaf_index).unwrap();
        out.push((e.note.clone(), proof));
    }
    out
}

/// 简易证明注册表（watcher 审计输入）：已证明 hand_binding 集合。
#[derive(Default)]
pub struct ProofRegistry {
    pub bindings: std::collections::HashSet<[u8; 32]>,
    pub nullifiers: NullifierSet,
    pub tree: PoseidonMerkleTree,
}

impl ProofRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_settled(&mut self, binding: [u8; 32]) {
        self.bindings.insert(binding);
    }
}

/// 断言 note 状态。
#[track_caller]
pub fn assert_note_status(seq: &Sequencer, note: &Note, expected: NoteStatus) {
    let e = seq
        .state()
        .notes
        .get(&note.commitment_bytes())
        .unwrap_or_else(|| panic!("note {:?} not in ledger", note.commitment_bytes()));
    assert_eq!(e.status, expected, "unexpected note status");
}
