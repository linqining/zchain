//! TE-M1 集成测试：AssetId 资产模型（`poker-appchain/src/asset_id.rs` +
//! v2 note 路径资产字段推广）。
//!
//! 全部走 release（`cargo test -p poker-appchain --release --test asset_id`）。
//!
//! 覆盖矩阵（对应交付 5）：
//! - 承诺区分：同 owner 同 nonce 不同 `asset_id`（跨域 / 同域跨 token）
//!   → 不同承诺；
//! - 同类守恒：同 AssetId 正例（纯 v2 / 纯 v1 两形态）；
//! - 跨 AssetId 混合拒：跨域 / 同域跨 token / v1 输入升维后混合 /
//!   赔付混资产 / rake 输出混资产（负例全部 fail-closed，
//!   `AssetMismatch`）；
//! - 迁移：migrate minted 的 asset_id 保持（REAL→REAL/0、
//!   PLAY→GAME/0），篡改（跨域 / 同域跨 token）拒；
//! - REAL/GAME finality 豁免语义：**按 domain 判，不按 token**
//!   （语义决策冻结：REAL 域任何 token 走 finality 门，GAME 域豁免）；
//! - v1 路径零回退：v1 AssetClass 判别值 / v1 note 隔离语义 /
//!   v1 Operation 判别值不变；`AssetId::of_v1` 是唯一 v1↔v2 资产桥。

use poker_appchain::asset_id::{
    asset_commitment, AssetDomain, AssetId, GAME_TOKEN_PLAY, TOKEN_NATIVE, TOKEN_USDC, TOKEN_USDT,
};
use poker_appchain::client_view::{account_view, v2_balances_by_asset};
use poker_appchain::error::AppchainError;
use poker_appchain::fee::FeePolicy;
use poker_appchain::keys::{blake2s32, spend_digest, OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::note_v2::{
    default_network_id, settle_effect_v2, settle_scope_v2, validate_settlement_v2, NoteSpec2,
    NoteV2, SettleInputV2, SettlementRecordV2,
};
use poker_appchain::ops::{MigrateNoteOp, Operation};
use poker_appchain::owner_v2::{
    legacy_account_id, migrate_digest, v2_spend_digest, MigrateNoteRecord, OwnerRef,
    SignatureEnvelope, SignatureScheme, VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::settlement::{settle_spend_scope, RakeSplitRecord, SpendAuth};
use std::collections::BTreeMap;
use std::sync::Arc;
use starknet_crypto::FieldElement;

// ---------------------------------------------------------------------------
// 夹具（与 tests/note_v2.rs 同源纪律；本文件自足不引 common）
// ---------------------------------------------------------------------------

/// 测试时钟（unix 秒）与毫秒。
const NOW: u64 = 1_700_000_000;
const NOW_MS: u64 = NOW * 1_000;
/// 信封有效期（NOW 之后 1 小时）。
const EXPIRY: u64 = NOW + 3_600;

fn felt32(byte: u8) -> [u8; 32] {
    let mut f = [0u8; 32];
    f[31] = byte;
    f
}

fn felt_to_bytes32(f: &FieldElement) -> [u8; 32] {
    f.to_bytes_be()
}

/// v1 测试用户（密钥与 spend secret 成对）。
struct V1User {
    key: OwnerKey,
    secret: [u8; 32],
}

impl V1User {
    fn new(seed: u8) -> Self {
        Self {
            key: OwnerKey::from_seed(&[seed; 32]).unwrap(),
            secret: [seed; 32],
        }
    }

    fn pk(&self) -> [u8; 33] {
        self.key.public_bytes()
    }

    fn note(&self, amount: u64, class: AssetClass, nonce_byte: u8) -> Note {
        Note::new(class, amount, self.pk(), felt32(nonce_byte), None).unwrap()
    }
}

/// v2 签名者（Legacy secp256k1 / StarkCurve 双 scheme）。
enum V2Signer {
    Legacy(u8),
    Stark(u64),
}

impl V2Signer {
    fn owner_ref(&self) -> OwnerRef {
        match self {
            Self::Legacy(seed) => OwnerRef {
                scheme: SignatureScheme::LegacySecp256k1,
                account_id: legacy_account_id(
                    &OwnerKey::from_seed(&[*seed; 32]).unwrap().public_bytes(),
                ),
                key_version: 0,
                binding_id: None,
            },
            Self::Stark(seed) => OwnerRef {
                scheme: SignatureScheme::StarkCurve,
                account_id: stark_pubkey(*seed),
                key_version: 0,
                binding_id: None,
            },
        }
    }

    fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        match self {
            Self::Legacy(seed) => OwnerKey::from_seed(&[*seed; 32]).unwrap().sign(digest).bytes,
            Self::Stark(seed) => stark_sign(*seed, digest),
        }
    }

    fn material(&self) -> VerifierMaterial {
        match self {
            Self::Legacy(seed) => VerifierMaterial::LegacySecp256k1 {
                presented_public: OwnerKey::from_seed(&[*seed; 32]).unwrap().public_bytes(),
            },
            Self::Stark(_) => VerifierMaterial::StarkCurve,
        }
    }
}

/// Stark 公钥（secret felt seed → 32B 规范编码）。
fn stark_pubkey(seed: u64) -> [u8; 32] {
    starknet_crypto::get_public_key(&FieldElement::from(seed)).to_bytes_be()
}

/// Stark 曲线签名（r/s 全零时换 k 重试）。
fn stark_sign(secret: u64, digest: &[u8; 32]) -> [u8; 64] {
    let s = FieldElement::from(secret);
    let msg = FieldElement::from_bytes_be(digest).expect("poseidon digests are canonical felts");
    let mut k = 1u64;
    loop {
        match starknet_crypto::sign(&s, &msg, &FieldElement::from(k)) {
            Ok(sig) if sig.r != FieldElement::ZERO && sig.s != FieldElement::ZERO => {
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&sig.r.to_bytes_be());
                out[32..].copy_from_slice(&sig.s.to_bytes_be());
                return out;
            }
            _ => k += 1,
        }
    }
}

fn new_sequencer() -> Sequencer {
    Sequencer::new(
        SequencerKey::from_seed(&[11u8; 32]),
        SequencerConfig {
            admission_proven_only: false,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    )
}

/// 存入并取回新铸出的 v1 note。
fn deposit_and_take(s: &mut Sequencer, user: &V1User, amount: u64, class: AssetClass, id: u8) -> Note {
    let mut deposit_id = [0u8; 32];
    deposit_id[0] = id;
    let before: Vec<[u8; 32]> = s
        .state()
        .notes
        .values()
        .map(|e| e.note.commitment_bytes())
        .collect();
    s.submit(
        Operation::Deposit {
            deposit_id,
            owner: user.pk(),
            asset_class: class,
            amount,
        },
        NOW_MS,
    )
    .unwrap();
    s.state()
        .notes
        .values()
        .find(|e| e.note.owner == user.pk() && !before.contains(&e.note.commitment_bytes()))
        .map(|e| e.note.clone())
        .unwrap()
}

/// 构造已签名的 MigrateNote op（record 全量签名 + minted 按冻结映射升维）。
fn signed_migrate_op(
    old: &V2Signer,
    old_note: &Note,
    new_owner: OwnerRef,
    migration_nonce: [u8; 32],
    envelope_nonce: u64,
    minted_nonce: u64,
) -> (Operation, VerifierMaterial) {
    let mut record = MigrateNoteRecord {
        old_commitment: old_note.commitment_bytes(),
        old_owner_sig: SignatureEnvelope {
            scheme: old.owner_ref().scheme,
            signer_ref: old.owner_ref(),
            typed_data_digest: [0u8; 32],
            signature: [0u8; 64],
            nonce: envelope_nonce,
            expiry: EXPIRY,
        },
        new_owner_ref: new_owner,
        amount: old_note.amount,
        asset_class: old_note.asset_class,
        migration_nonce,
        network_id: default_network_id(),
        abi_version: OWNER_V2_ABI_VERSION,
    };
    let digest = migrate_digest(&record);
    record.old_owner_sig.typed_data_digest = digest;
    record.old_owner_sig.signature = old.sign(&digest);
    let minted = NoteV2::new(
        AssetId::of_v1(record.asset_class),
        record.amount,
        record.new_owner_ref.clone(),
        minted_nonce,
        None,
        0,
        0,
    )
    .unwrap();
    let op = Operation::MigrateNote(Box::new(MigrateNoteOp { record, minted }));
    (op, old.material())
}

/// 为 v2 输入构造已签名信封。
fn v2_settle_envelope(
    signer: &V2Signer,
    note: &NoteV2,
    nullifier: &[u8; 32],
    scope: &[u8],
    effect: &[u8; 32],
    nonce: u64,
) -> SignatureEnvelope {
    let digest = v2_spend_digest(&note.owner, &note.commitment_bytes(), nullifier, scope, effect);
    SignatureEnvelope {
        scheme: signer.owner_ref().scheme,
        signer_ref: signer.owner_ref(),
        typed_data_digest: digest,
        signature: signer.sign(&digest),
        nonce,
        expiry: EXPIRY,
    }
}

/// 零分账 rake 记录。
fn zero_rake() -> RakeSplitRecord {
    RakeSplitRecord {
        total: 0,
        treasury_out: None,
        operator_out: None,
    }
}

/// 结算记录构造（policy_commitment / pot 自动导出）。
fn build_settle_v2(
    table_id: u64,
    hand_binding: [u8; 32],
    inputs: Vec<SettleInputV2>,
    payouts: Vec<NoteSpec2>,
    rake: RakeSplitRecord,
    policy: &FeePolicy,
) -> SettlementRecordV2 {
    let pot = inputs.iter().map(|i| i.amount()).sum();
    SettlementRecordV2 {
        table_id,
        hand_binding,
        policy_commitment: policy.commitment_bytes(),
        pot,
        inputs,
        payouts,
        rake,
    }
}

/// 存入 → 迁移（把一张 v1 note 变成指定 v2 owner 名下的 v2 note）。
/// 信封 nonce 随序号单调（同 signer 多次迁移的新鲜度纪律）。
fn migrate_in(s: &mut Sequencer, old_signer_seed: u8, note: &Note, new_owner: OwnerRef, n: u8) {
    let (op, m) = signed_migrate_op(
        &V2Signer::Legacy(old_signer_seed),
        note,
        new_owner,
        felt32(0xA0 + n),
        u64::from(n) + 10,
        u64::from(n),
    );
    s.submit_migrate(op, &m, NOW_MS).unwrap();
}

// ---------------------------------------------------------------------------
// 1) 承诺区分：asset_id（domain 与 token_id）参与 v2 note 承诺
// ---------------------------------------------------------------------------

#[test]
fn commitment_separates_asset_ids() {
    let key = OwnerKey::from_seed(&[7; 32]).unwrap();
    let owner = OwnerRef {
        scheme: SignatureScheme::LegacySecp256k1,
        account_id: legacy_account_id(&key.public_bytes()),
        key_version: 0,
        binding_id: None,
    };
    // 同 owner 同 nonce 同面额，仅 asset_id 不同 → 承诺必不同
    let native = NoteV2::new(AssetId::REAL_NATIVE, 100, owner.clone(), 1, None, 0, 0).unwrap();
    let usdt = NoteV2::new(AssetId::REAL_USDT, 100, owner.clone(), 1, None, 0, 0).unwrap();
    let play = NoteV2::new(AssetId::GAME_PLAY, 100, owner.clone(), 1, None, 0, 0).unwrap();
    assert_eq!(native.commitment(), native.commitment(), "deterministic");
    assert_ne!(
        native.commitment(),
        play.commitment(),
        "cross-domain asset ids must separate commitments"
    );
    assert_ne!(
        native.commitment(),
        usdt.commitment(),
        "same-domain different-token asset ids must separate commitments (TE-M1 core)"
    );
    assert_ne!(usdt.commitment(), play.commitment());
    // token_id 逐位敏感（USDT vs USDC 仅差一个 u32）
    let usdc = NoteV2::new(AssetId::REAL_USDC, 100, owner.clone(), 1, None, 0, 0).unwrap();
    assert_ne!(usdt.commitment(), usdc.commitment());
    // 资产承诺域分离哈希：与 note 承诺域（zchain.note.v2）不同源——
    // 同输入经 asset 域标签的 32B 编码稳定且两两区分
    let ac_native = felt_to_bytes32(&asset_commitment(&AssetId::REAL_NATIVE));
    let ac_play = felt_to_bytes32(&asset_commitment(&AssetId::GAME_PLAY));
    assert_ne!(ac_native, ac_play);
    assert_eq!(ac_native, felt_to_bytes32(&asset_commitment(&AssetId::REAL_NATIVE)));
    println!(
        "[commitment] native={:?}", native.commitment_bytes().iter().take(6).collect::<Vec<_>>(),
    );
}

// ---------------------------------------------------------------------------
// 2) 同 AssetId 守恒正例（REAL 域端到端：迁移 → 纯 v2 结算）
// ---------------------------------------------------------------------------

#[test]
fn same_asset_settlement_positive_real_domain() {
    let mut s = new_sequencer();
    s.submit(
        Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
        NOW_MS,
    )
    .unwrap();
    // 两名 v1 用户各存 400/600 REAL → 迁移成 v2（asset_id = REAL/NATIVE）
    let u1 = V1User::new(10);
    let u2 = V1User::new(20);
    let n1 = deposit_and_take(&mut s, &u1, 400, AssetClass::Real, 1);
    let n2 = deposit_and_take(&mut s, &u2, 600, AssetClass::Real, 2);
    let v2o1 = V2Signer::Legacy(10);
    let v2o2 = V2Signer::Stark(0x5A17);
    migrate_in(&mut s, 10, &n1, v2o1.owner_ref(), 1);
    migrate_in(&mut s, 20, &n2, v2o2.owner_ref(), 2);
    let take = |s: &Sequencer, owner: &OwnerRef| -> NoteV2 {
        s.state()
            .notes_v2
            .values()
            .find(|e| e.note.owner == *owner)
            .map(|e| e.note.clone())
            .unwrap()
    };
    let v2n1 = take(&s, &v2o1.owner_ref());
    let v2n2 = take(&s, &v2o2.owner_ref());
    assert_eq!(v2n1.asset_id, AssetId::REAL_NATIVE);
    assert_eq!(v2n2.asset_id, AssetId::REAL_NATIVE);

    // 纯 v2 结算（同 AssetId：REAL/NATIVE），400/600 各回各主
    let hand_binding = felt32(0x5D);
    let policy = FeePolicy::Zero;
    let net = default_network_id();
    let scope = settle_scope_v2(&net, OWNER_V2_ABI_VERSION, &hand_binding);
    let nf1 = v2n1.nullifier(&[10u8; 32], &scope);
    let nf2 = v2n2.nullifier(&blake2s32(&[b"stark secret"]), &scope);
    let mk_payout = |amount: u64, owner: OwnerRef, table: Option<u64>| NoteSpec2 {
        asset_id: AssetId::REAL_NATIVE,
        amount,
        owner,
        table_id: table,
        pot_index: 0,
        runout_index: 0,
    };
    // 信封 nonce 必须高于迁移消费水位（v2o1 的旧 signer 是 Legacy(10)，
    // 迁移信封已推到 11；per-signer 严格单调）
    let mut record = build_settle_v2(
        1,
        hand_binding,
        vec![
            SettleInputV2::V2 {
                note: v2n1.clone(),
                nullifier: nf1,
                envelope: SignatureEnvelope {
                    scheme: v2o1.owner_ref().scheme,
                    signer_ref: v2o1.owner_ref(),
                    typed_data_digest: [0; 32],
                    signature: [0; 64],
                    nonce: 20,
                    expiry: EXPIRY,
                },
                material: v2o1.material(),
            },
            SettleInputV2::V2 {
                note: v2n2.clone(),
                nullifier: nf2,
                envelope: SignatureEnvelope {
                    scheme: v2o2.owner_ref().scheme,
                    signer_ref: v2o2.owner_ref(),
                    typed_data_digest: [0; 32],
                    signature: [0; 64],
                    nonce: 20,
                    expiry: EXPIRY,
                },
                material: v2o2.material(),
            },
        ],
        vec![
            mk_payout(400, v2o1.owner_ref(), Some(1)),
            mk_payout(600, v2o2.owner_ref(), None),
        ],
        zero_rake(),
        &policy,
    );
    let effect = settle_effect_v2(&record);
    for (input, signer) in [(0usize, &v2o1), (1, &v2o2)] {
        let (note, nullifier) = match &record.inputs[input] {
            SettleInputV2::V2 { note, nullifier, .. } => (note.clone(), *nullifier),
            _ => unreachable!(),
        };
        let envelope = v2_settle_envelope(signer, &note, &nullifier, &scope, &effect, 20);
        if let SettleInputV2::V2 { envelope: e, .. } = &mut record.inputs[input] {
            *e = envelope;
        }
    }
    s.submit(Operation::SettleV2(Box::new(record)), NOW_MS + 5)
        .unwrap();

    // REAL 域分栏（balances_v2_of 列 0）+ 逐 AssetId 分组
    assert_eq!(s.state().balances_v2_of(&v2o1.owner_ref()), (400, 0));
    assert_eq!(s.state().balances_v2_of(&v2o2.owner_ref()), (600, 0));
    let by_asset = v2_balances_by_asset(s.state(), &v2o1.owner_ref());
    assert_eq!(by_asset.get(&AssetId::REAL_NATIVE), Some(&400));
    assert_eq!(by_asset.len(), 1);
    println!(
        "[same-asset positive] v1(400 REAL)+v1(600 REAL) migrated and settled; balances_v2 = {:?}",
        v2_balances_by_asset(s.state(), &v2o2.owner_ref())
    );
}

// ---------------------------------------------------------------------------
// 3) 同 AssetId 守恒正例（纯 v1 输入经 of_v1 升维参与 v2 校验）
// ---------------------------------------------------------------------------

#[test]
fn same_asset_v1_inputs_upgrade_through_frozen_mapping() {
    let alice = V1User::new(30);
    let bob = V1User::new(31);
    // v1 纪律：SettleV2 的 v1 输入是 seat note（table_id == 记录桌号）
    let a = Note::new(AssetClass::Real, 500, alice.pk(), felt32(1), Some(9)).unwrap();
    let b = Note::new(AssetClass::Real, 400, bob.pk(), felt32(2), Some(9)).unwrap();
    let hand_binding = felt32(0x6A);
    let policy = FeePolicy::Zero;
    let record = SettlementRecordV2 {
        table_id: 9,
        hand_binding,
        policy_commitment: policy.commitment_bytes(),
        pot: 900,
        inputs: vec![
            SettleInputV2::V1 {
                note: a.clone(),
                spend: SpendAuth {
                    commitment: a.commitment_bytes(),
                    nullifier: felt_to_bytes32(&a.nullifier(&alice.secret)),
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInputV2::V1 {
                note: b.clone(),
                spend: SpendAuth {
                    commitment: b.commitment_bytes(),
                    nullifier: felt_to_bytes32(&b.nullifier(&bob.secret)),
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
        ],
        payouts: vec![
            NoteSpec2 {
                asset_id: AssetId::REAL_NATIVE,
                amount: 500,
                owner: OwnerRef {
                    scheme: SignatureScheme::LegacySecp256k1,
                    account_id: legacy_account_id(&alice.pk()),
                    key_version: 0,
                    binding_id: None,
                },
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            },
            NoteSpec2 {
                asset_id: AssetId::REAL_NATIVE,
                amount: 400,
                owner: OwnerRef {
                    scheme: SignatureScheme::LegacySecp256k1,
                    account_id: legacy_account_id(&bob.pk()),
                    key_version: 0,
                    binding_id: None,
                },
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            },
        ],
        rake: zero_rake(),
    };
    // 回填 v1 花费签名（效果摘要已含 TE-M1 的赔付 asset_commitment）
    let effect = settle_effect_v2(&record);
    let scope = settle_spend_scope(&hand_binding);
    let mut record = record;
    for (i, user, note) in [(0usize, &alice, &a), (1, &bob, &b)] {
        let nf = felt_to_bytes32(&note.nullifier(&user.secret));
        let d = spend_digest(&note.commitment_bytes(), &nf, &scope, &effect);
        if let SettleInputV2::V1 { spend, .. } = &mut record.inputs[i] {
            spend.sig = user.key.sign(&d);
        }
    }
    // v1 note 本身零变更（v1 AssetClass 仍是 REAL/PLAY），经冻结映射
    // of_v1(Real) = REAL/NATIVE 参与同一 AssetId 守恒校验 → 通过
    validate_settlement_v2(
        &record,
        &policy,
        &default_network_id(),
        OWNER_V2_ABI_VERSION,
        NOW,
        &|_| None,
    )
    .unwrap();
    println!("[v1-arm positive] two v1 REAL notes validated through AssetId upgrade path");
}

// ---------------------------------------------------------------------------
// 4) 跨 AssetId 混合拒（校验在签名步骤之前——负例无需有效签名）
// ---------------------------------------------------------------------------

/// 构造最小混合记录（信封占位；AssetMismatch 在第 2 步先于签名触发）。
fn mixed_record(inputs: Vec<SettleInputV2>, payouts: Vec<NoteSpec2>, rake: RakeSplitRecord) -> SettlementRecordV2 {
    let mut rec = build_settle_v2(
        9,
        felt32(0x6B),
        inputs,
        payouts,
        rake,
        &FeePolicy::Zero,
    );
    rec.pot = rec.inputs.iter().map(|i| i.amount()).sum();
    rec
}

fn v2_input(note: NoteV2) -> SettleInputV2 {
    SettleInputV2::V2 {
        nullifier: blake2s32(&[b"placeholder nullifier"]),
        envelope: SignatureEnvelope {
            scheme: SignatureScheme::StarkCurve,
            signer_ref: note.owner.clone(),
            typed_data_digest: [0; 32],
            signature: [0; 64],
            nonce: 1,
            expiry: EXPIRY,
        },
        material: VerifierMaterial::StarkCurve,
        note,
    }
}

fn v1_input(note: Note) -> SettleInputV2 {
    SettleInputV2::V1 {
        spend: SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: blake2s32(&[b"placeholder nullifier"]),
            sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
        },
        note,
    }
}

fn v2_note(asset: AssetId, amount: u64, seed: u64) -> NoteV2 {
    NoteV2::new(
        asset,
        amount,
        OwnerRef {
            scheme: SignatureScheme::StarkCurve,
            account_id: stark_pubkey(seed),
            key_version: 0,
            binding_id: None,
        },
        1,
        None,
        0,
        0,
    )
    .unwrap()
}

fn payout(asset: AssetId, amount: u64, seed: u64) -> NoteSpec2 {
    NoteSpec2 {
        asset_id: asset,
        amount,
        owner: OwnerRef {
            scheme: SignatureScheme::StarkCurve,
            account_id: stark_pubkey(seed),
            key_version: 0,
            binding_id: None,
        },
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    }
}

#[test]
fn cross_asset_mixing_rejected() {
    let net = default_network_id();
    let policy = FeePolicy::Zero;
    let validate = |rec: &SettlementRecordV2| {
        validate_settlement_v2(rec, &policy, &net, OWNER_V2_ABI_VERSION, NOW, &|_| None)
    };

    // (a) 跨域混合：REAL/NATIVE + GAME/PLAY → AssetMismatch
    let rec = mixed_record(
        vec![v2_input(v2_note(AssetId::REAL_NATIVE, 100, 1)), v2_input(v2_note(AssetId::GAME_PLAY, 100, 2))],
        vec![payout(AssetId::REAL_NATIVE, 200, 3)],
        zero_rake(),
    );
    match validate(&rec) {
        Err(AppchainError::AssetMismatch { expected, got }) => {
            assert_eq!(expected, AssetId::REAL_NATIVE);
            assert_eq!(got, AssetId::GAME_PLAY);
            println!("[neg a] cross-domain: expected {expected}, got {got}");
        }
        other => panic!("cross-domain mixing must be rejected, got {other:?}"),
    }

    // (b) 同域跨 token 混合（TE-M1 新粒度，v1 二元模型表达不了的负例）：
    //     REAL/NATIVE + REAL/USDT → AssetMismatch
    let rec = mixed_record(
        vec![v2_input(v2_note(AssetId::REAL_NATIVE, 100, 1)), v2_input(v2_note(AssetId::REAL_USDT, 100, 2))],
        vec![payout(AssetId::REAL_NATIVE, 200, 3)],
        zero_rake(),
    );
    match validate(&rec) {
        Err(AppchainError::AssetMismatch { expected, got }) => {
            assert_eq!(expected, AssetId::REAL_NATIVE);
            assert_eq!(got, AssetId::REAL_USDT);
            println!("[neg b] same-domain cross-token: expected {expected}, got {got}");
        }
        other => panic!("same-domain cross-token mixing must be rejected, got {other:?}"),
    }

    // (c) v1 输入升维后混合：v1 Real note + v2 GAME/PLAY → AssetMismatch
    //     （of_v1(Real)=REAL/NATIVE ≠ GAME/PLAY）
    let alice = V1User::new(32);
    let rec = mixed_record(
        vec![
            v1_input(alice.note(300, AssetClass::Real, 3)),
            v2_input(v2_note(AssetId::GAME_PLAY, 300, 4)),
        ],
        vec![payout(AssetId::REAL_NATIVE, 600, 5)],
        zero_rake(),
    );
    match validate(&rec) {
        Err(AppchainError::AssetMismatch { expected, got }) => {
            assert_eq!(expected, AssetId::REAL_NATIVE);
            assert_eq!(got, AssetId::GAME_PLAY);
            println!("[neg c] v1-real vs v2-play: expected {expected}, got {got}");
        }
        other => panic!("v1/v2 cross-asset mixing must be rejected, got {other:?}"),
    }

    // (d) 赔付混资产：输入 REAL/NATIVE，赔付掺 REAL/USDT → AssetMismatch
    let rec = mixed_record(
        vec![v2_input(v2_note(AssetId::REAL_NATIVE, 200, 1))],
        vec![
            payout(AssetId::REAL_NATIVE, 100, 3),
            payout(AssetId::REAL_USDT, 100, 4),
        ],
        zero_rake(),
    );
    match validate(&rec) {
        Err(AppchainError::AssetMismatch { expected, got }) => {
            assert_eq!(expected, AssetId::REAL_NATIVE);
            assert_eq!(got, AssetId::REAL_USDT);
            println!("[neg d] payout asset mixing: expected {expected}, got {got}");
        }
        other => panic!("mixed-asset payouts must be rejected, got {other:?}"),
    }

    // (e) rake 输出混资产：记录资产 GAME/PLAY，rake treasury_out 是 v1
    //     REAL note → of_v1 升维后不等 → AssetMismatch（v1 rake 通道
    //     无法承载 GAME 资产，fail-closed；TE-M2/M3 前的诚实边界）
    let rec = mixed_record(
        vec![v2_input(v2_note(AssetId::GAME_PLAY, 200, 1))],
        vec![payout(AssetId::GAME_PLAY, 180, 3)],
        RakeSplitRecord {
            // total 0（Zero 策略要求）但带 v1 REAL 输出：第 6 步 rake 资产
            // 比对先于第 8 步的 (0,0)-None 检查触发 → AssetMismatch
            total: 0,
            treasury_out: Some(poker_appchain::note::NoteSpec {
                asset_class: AssetClass::Real,
                amount: 12,
                owner: [9u8; 33],
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            }),
            operator_out: Some(poker_appchain::note::NoteSpec {
                asset_class: AssetClass::Real,
                amount: 8,
                owner: [8u8; 33],
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            }),
        },
    );
    match validate(&rec) {
        Err(AppchainError::AssetMismatch { expected, got }) => {
            assert_eq!(expected, AssetId::GAME_PLAY);
            assert_eq!(got, AssetId::REAL_NATIVE);
            println!("[neg e] rake asset mismatch: expected {expected}, got {got}");
        }
        other => panic!("rake asset mismatch must be rejected, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5) 迁移：minted 的 asset_id 保持（正例 ×2 + 篡改负例 ×2）
// ---------------------------------------------------------------------------

#[test]
fn migrate_preserves_asset_id() {
    let mut s = new_sequencer();
    let alice = V1User::new(40);

    // 正例 1：REAL v1 note → REAL/NATIVE 保持
    let real_note = deposit_and_take(&mut s, &alice, 100, AssetClass::Real, 1);
    let v2o = V2Signer::Stark(0x50C);
    migrate_in(&mut s, 40, &real_note, v2o.owner_ref(), 1);
    let minted_real = s
        .state()
        .notes_v2
        .values()
        .find(|e| e.note.owner == v2o.owner_ref())
        .map(|e| e.note.clone())
        .unwrap();
    assert_eq!(minted_real.asset_id, AssetId::REAL_NATIVE);
    assert_eq!(minted_real.amount, 100);
    assert_eq!(s.state().balances_v2_of(&v2o.owner_ref()), (100, 0));

    // 正例 2：PLAY v1 note → GAME/PLAY（遗留特例）保持
    let play_note = deposit_and_take(&mut s, &alice, 200, AssetClass::Play, 2);
    migrate_in(&mut s, 40, &play_note, v2o.owner_ref(), 2);
    let minted_play = s
        .state()
        .notes_v2
        .values()
        .find(|e| e.note.owner == v2o.owner_ref() && e.note.amount == 200)
        .map(|e| e.note.clone())
        .unwrap();
    assert_eq!(minted_play.asset_id, AssetId::GAME_PLAY);
    // 域分栏 + 逐 AssetId 分组一致
    assert_eq!(s.state().balances_v2_of(&v2o.owner_ref()), (100, 200));
    let mut expect = BTreeMap::new();
    expect.insert(AssetId::REAL_NATIVE, 100u128);
    expect.insert(AssetId::GAME_PLAY, 200u128);
    assert_eq!(v2_balances_by_asset(s.state(), &v2o.owner_ref()), expect);
    // 客户端账户视图：v2 侧 REAL 域 / GAME 域分栏
    let view = account_view(s.state(), None, Some(&v2o.owner_ref()));
    assert_eq!(view.v2.real, 100);
    assert_eq!(view.v2.play, 200);
    println!(
        "[migrate preserve] v2 balances by asset = {expect:?}; domain columns = ({}, {})",
        view.v2.real, view.v2.play
    );

    // 负例 1：REAL 旧 note 配跨域 minted（GAME/PLAY）→ minted/record 拒
    let note3 = deposit_and_take(&mut s, &alice, 50, AssetClass::Real, 3);
    let (op, m) = signed_migrate_op(&V2Signer::Legacy(40), &note3, v2o.owner_ref(), felt32(0xF1), 5, 5);
    let mut op = op;
    if let Operation::MigrateNote(mig) = &mut op {
        mig.minted.asset_id = AssetId::GAME_PLAY;
    }
    match s.submit_migrate(op, &m, NOW_MS + 1) {
        Err(AppchainError::AdmissionRejected("migrate minted/record mismatch")) => {}
        other => panic!("cross-domain minted must be rejected, got {other:?}"),
    }

    // 负例 2：同域跨 token 篡改（REAL/0 → REAL/1）→ 同一拒绝路径
    // （v1 二元模型下不可表达的攻击面，TE-M1 后被精确阻断）
    let (op, m) = signed_migrate_op(&V2Signer::Legacy(40), &note3, v2o.owner_ref(), felt32(0xF2), 6, 6);
    let mut op = op;
    if let Operation::MigrateNote(mig) = &mut op {
        mig.minted.asset_id = AssetId::REAL_USDT;
    }
    match s.submit_migrate(op, &m, NOW_MS + 2) {
        Err(AppchainError::AdmissionRejected("migrate minted/record mismatch")) => {}
        other => panic!("cross-token minted must be rejected, got {other:?}"),
    }
    // 账本零污染（fail-closed）
    assert_eq!(s.state().balances_v2_of(&v2o.owner_ref()), (100, 200));
}

// ---------------------------------------------------------------------------
// 6) REAL/GAME finality 豁免语义：按 domain 判，不按 token（冻结决策）
// ---------------------------------------------------------------------------

#[test]
fn finality_exemption_is_domain_scoped() {
    // 语义决策（asset_id.rs / ABI_ASSET_ID.md 冻结）：提现 finality 门
    // 的判据是 `AssetId::is_real_domain`——REAL 域**任何** token 走门
    // （TE-M2 的 USDT/USDC 与 NATIVE 同门），GAME 域**任何** token 豁免
    // （含遗留 PLAY）。绝不允许退化为逐 token 白名单。
    let gate_applies = |a: AssetId| a.is_real_domain();

    // REAL 域三 token：全部走门（TE-M2 三币种 finality 回归基线）
    for (name, token) in [
        ("NATIVE", TOKEN_NATIVE),
        ("USDT", TOKEN_USDT),
        ("USDC", TOKEN_USDC),
    ] {
        let a = AssetId::real(token).unwrap();
        assert!(gate_applies(a), "REAL:{name} must be gated by finality");
        println!("[finality] real:{} ({name}) -> gate applies", token);
    }
    // GAME 域：遗留 PLAY 与未来注册 token 一律豁免
    assert!(!gate_applies(AssetId::GAME_PLAY));
    assert!(!gate_applies(AssetId::game(GAME_TOKEN_PLAY)));
    assert!(!gate_applies(AssetId::game(4_242)));
    println!("[finality] game:play(legacy) and future game tokens -> exempt");

    // v1 语义逐点保持：v1 finality 门判 `AssetClass::Real`（vault.rs，
    // 冻结不动）；经冻结映射后与 v2 domain 判据完全重合——
    // of_v1(Real) 走门 ≡ (class == Real)；of_v1(Play) 豁免 ≡ (class != Real)
    let v1_gate = |class: AssetClass| class == AssetClass::Real;
    for class in [AssetClass::Real, AssetClass::Play] {
        assert_eq!(
            gate_applies(AssetId::of_v1(class)),
            v1_gate(class),
            "finality predicate must coincide with the frozen v1 gate through the mapping"
        );
    }
}

// ---------------------------------------------------------------------------
// 7) v1 路径零回退：判别值 / 隔离语义 / 唯一资产桥
// ---------------------------------------------------------------------------

#[test]
fn v1_path_zero_regression() {
    // v1 AssetClass 判别值冻结（Real=1 / Play=2，note.rs 冻结不动）
    assert_eq!(AssetClass::Real.as_u8(), 1);
    assert_eq!(AssetClass::Play.as_u8(), 2);
    assert_eq!(AssetClass::from_u8(1).unwrap(), AssetClass::Real);
    assert_eq!(AssetClass::from_u8(2).unwrap(), AssetClass::Play);
    assert!(AssetClass::from_u8(0).is_err());
    assert!(AssetClass::from_u8(3).is_err());

    // v1 note 隔离语义不变：跨类断言仍是 AssetClassMismatch（v1 错误
    // 变体语义冻结；v2 路径才用新变体 AssetMismatch）
    let a = V1User::new(50).note(10, AssetClass::Real, 1);
    let b = V1User::new(51).note(10, AssetClass::Play, 1);
    assert!(matches!(
        a.assert_same_class(&b),
        Err(AppchainError::AssetClassMismatch("REAL", "PLAY"))
    ));
    assert!(a.assert_same_class(&a).is_ok());

    // v1 Operation 判别值不回退（Deposit = 2）
    let bytes = borsh::to_vec(&Operation::Deposit {
        deposit_id: [0; 32],
        owner: V1User::new(52).pk(),
        asset_class: AssetClass::Play,
        amount: 1,
    })
    .unwrap();
    assert_eq!(bytes[0], 2, "v1 Deposit discriminant frozen");

    // of_v1 是唯一 v1↔v2 资产桥：映射冻结、遗留资产双射、非遗留资产
    // 在 v1 无表示（to_v1_class = None → 调用方必须 fail-closed）
    assert_eq!(AssetId::of_v1(AssetClass::Real), AssetId::REAL_NATIVE);
    assert_eq!(AssetId::of_v1(AssetClass::Play), AssetId::GAME_PLAY);
    assert_eq!(AssetId::REAL_NATIVE.to_v1_class(), Some(AssetClass::Real));
    assert_eq!(AssetId::GAME_PLAY.to_v1_class(), Some(AssetClass::Play));
    assert_eq!(AssetId::REAL_USDT.to_v1_class(), None);
    assert_eq!(AssetId::REAL_USDC.to_v1_class(), None);

    // TE-M1 类型层判别值与 borsh 布局冻结（wire 记录见 ABI_ASSET_ID.md）
    assert_eq!(AssetDomain::Real.as_u8(), 1);
    assert_eq!(AssetDomain::Game.as_u8(), 2);
    assert_eq!(borsh::to_vec(&AssetId::REAL_NATIVE).unwrap(), [1u8, 0, 0, 0, 0]);
    assert_eq!(borsh::to_vec(&AssetId::GAME_PLAY).unwrap(), [2u8, 0, 0, 0, 0]);
    // REAL 域封闭枚举在构造器层 fail-closed
    assert!(AssetId::real(3).is_err());
    println!("[v1 zero-regression] v1 discriminants, isolation semantics, op discriminants unchanged; of_v1 is the only bridge");
}
