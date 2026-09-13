//! ABI v2 正式版端到端集成测试：v2 Note 账本 + MigrateNote 链准入 +
//! 双 verifier 并行结算（纯 v1 / 纯 v2 / 混合）。
//!
//! 全部走 release（`cargo test -p poker-appchain --release --test note_v2`）。
//!
//! 覆盖矩阵：
//! - 迁移端到端：开桌 → 存入 → 买入 → 迁移（旧 note 消费 + NoteV2 铸造）；
//! - 软确认链含 migrate 帧、水位覆盖、WAL 重放后 v2 账本/nonce 集等价；
//! - 负例：migration_nonce 重放、旧 note 双花、record↔minted 不一致、
//!   网络绑定、信封过期/nonce 单调、submit 通道缺材料、混合结算交叉伪造、
//!   结算重放/守恒。

use poker_appchain::asset_id::AssetId;
use poker_appchain::client_view::account_view;
use poker_appchain::error::AppchainError;
use poker_appchain::fee::FeePolicy;
use poker_appchain::keys::{blake2s32, spend_digest, OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::note_v2::{
    default_network_id, settle_effect_v2, settle_scope_v2, settle_spend_verifier_v2, NoteSpec2,
    NoteV2, SettleInputV2, SettlementRecordV2,
};
use poker_appchain::ops::{scope, MigrateNoteOp, Operation};
use poker_appchain::owner_v2::{
    legacy_account_id, migrate_digest, v2_spend_digest, MigrateNoteRecord, OwnerRef,
    SignatureEnvelope, SignatureScheme, VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use poker_appchain::sequencer::{NoteStatus, Sequencer, SequencerConfig};
use poker_appchain::settlement::{settle_spend_scope, RakeSplitRecord, SpendAuth};
use std::sync::Arc;
use starknet_crypto::FieldElement;

// ---------------------------------------------------------------------------
// 夹具
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
        let mut nonce = [0u8; 32];
        nonce[0] = nonce_byte;
        Note::new(class, amount, self.pk(), nonce, None).unwrap()
    }

    /// v1 结算花费授权（scope = v1 结算域 + hand_binding）。
    fn settle_auth(&self, note: &Note, scope_tag: &[u8], effect: &[u8; 32]) -> SpendAuth {
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(&note.commitment_bytes(), &felt_to_bytes32(&nf), scope_tag, effect);
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }
}

fn felt_to_bytes32(f: &starknet_crypto::FieldElement) -> [u8; 32] {
    f.to_bytes_be()
}/// v2 签名者抽象（Legacy secp256k1 / StarkCurve 双 scheme）。
enum V2Signer {
    Legacy(u8),
    Stark(u64),
}

impl V2Signer {
    fn owner_ref(&self) -> OwnerRef {
        match self {
            Self::Legacy(seed) => OwnerRef {
                scheme: SignatureScheme::LegacySecp256k1,
                account_id: legacy_account_id(&OwnerKey::from_seed(&[*seed; 32]).unwrap().public_bytes()),
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

/// 构造已签名的 MigrateNote op（record 全量签名 + minted 一致）。
#[allow(clippy::too_many_arguments)]
fn signed_migrate_op(
    old: &V2Signer,
    old_note: &Note,
    new_owner: OwnerRef,
    migration_nonce: [u8; 32],
    network_id: [u8; 32],
    abi_version: u32,
    envelope_nonce: u64,
    expiry: u64,
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
            expiry,
        },
        new_owner_ref: new_owner,
        amount: old_note.amount,
        asset_class: old_note.asset_class,
        migration_nonce,
        network_id,
        abi_version,
    };
    let digest = migrate_digest(&record);
    record.old_owner_sig.typed_data_digest = digest;
    record.old_owner_sig.signature = old.sign(&digest);
    // TE-M1：v2 note 资产身份 = v1 资产类经冻结映射升维（Real→REAL/0，
    // Play→GAME/0）；minted/record 一致性由 sequencer 按同款映射校验
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

/// 测试 sequencer（内存模式；可关 proven 门）。
fn new_sequencer(proven_only: bool) -> Sequencer {
    Sequencer::new(
        SequencerKey::from_seed(&[11u8; 32]),
        SequencerConfig {
            admission_proven_only: proven_only,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    )
}

/// 存入并取回**新铸出**的 v1 note（提交前快照排除既有承诺，同一用户
/// 多张 note 场景安全）。
fn deposit_and_take(s: &mut Sequencer, user: &V1User, amount: u64, class: AssetClass, id: u8, ts: u64) -> Note {
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
        ts,
    )
    .unwrap();
    s.state()
        .notes
        .values()
        .find(|e| e.note.owner == user.pk() && !before.contains(&e.note.commitment_bytes()))
        .map(|e| e.note.clone())
        .unwrap()
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

/// 零分账 rake 记录。
fn zero_rake() -> RakeSplitRecord {
    RakeSplitRecord {
        total: 0,
        treasury_out: None,
        operator_out: None,
    }
}

/// 为 v2 输入构造已签名信封（digest 绑定 v2 scope + 结算效果）。
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

// ---------------------------------------------------------------------------
// 1) 迁移端到端：存入 → 迁移 → 账本状态（迁移前后证据输出）
// ---------------------------------------------------------------------------

#[test]
fn migrate_end_to_end_ledger_transitions() {
    let mut s = new_sequencer(false);
    let alice = V1User::new(1);
    let v2_owner = V2Signer::Stark(0xA11CE).owner_ref();

    let note = deposit_and_take(&mut s, &alice, 1_000, AssetClass::Play, 1, NOW_MS);
    // 迁移前：v1 账本持有，v2 账本为空
    let before_v1 = s.state().balances_of(&alice.pk());
    let before_v2 = s.state().balances_v2_of(&v2_owner);
    println!(
        "[e2e] before migrate: v1(owner33) real/play = {before_v1:?}, v2(OwnerRef) = {before_v2:?}, notes={} notes_v2={}",
        s.state().notes.len(),
        s.state().notes_v2.len()
    );
    assert_eq!(before_v1, (0, 1_000));
    assert_eq!(before_v2, (0, 0));

    let (op, material) = signed_migrate_op(
        &V2Signer::Legacy(1),
        &note,
        v2_owner.clone(),
        blake2s32(&[b"migration nonce e2e"]),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        5,
        EXPIRY,
        777,
    );
    let old_commitment = note.commitment_bytes();
    s.submit_migrate(op, &material, NOW_MS).unwrap();

    // 迁移后：旧 v1 note 已消费（nullifier 入集）、NoteV2 在 v2 账本
    let after_v1 = s.state().balances_of(&alice.pk());
    let after_v2 = s.state().balances_v2_of(&v2_owner);
    println!(
        "[e2e] after migrate:  v1(owner33) real/play = {after_v1:?}, v2(OwnerRef) = {after_v2:?}, notes={} notes_v2={}",
        s.state().notes.len(),
        s.state().notes_v2.len()
    );
    assert_eq!(after_v1, (0, 0), "old v1 note must be consumed");
    assert_eq!(after_v2, (0, 1_000), "NoteV2 minted same amount/asset (GAME domain column)");
    assert!(!s.state().notes.contains_key(&old_commitment));
    let entry = s
        .state()
        .notes_v2
        .values()
        .next()
        .expect("v2 ledger must hold the minted note");
    assert_eq!(entry.note.amount, 1_000);
    // TE-M1：v1 Play 迁移后保持资产身份（冻结映射 Play → GAME 域 token 0）
    assert_eq!(entry.note.asset_id, AssetId::GAME_PLAY);
    assert_eq!(entry.note.owner, v2_owner);
    assert_eq!(entry.note.nonce, 777);
    assert_eq!(entry.note.table_id, None);
    // migration nonce 与信封 nonce 水位登记
    assert!(s
        .state()
        .migration_nonces
        .contains(&blake2s32(&[b"migration nonce e2e"])));
    let signer = poker_appchain::owner_v2::owner_commitment(&V2Signer::Legacy(1).owner_ref());
    assert_eq!(s.state().owner_nonces_v2.get(&signer), Some(&5));
}

// ---------------------------------------------------------------------------
// 2) 软确认链含 migrate 帧 + 水位覆盖（op_index 单调）
// ---------------------------------------------------------------------------

#[test]
fn migrate_frame_in_chain_and_watermark_covers_it() {
    let mut s = new_sequencer(false);
    let alice = V1User::new(2);
    let note = deposit_and_take(&mut s, &alice, 500, AssetClass::Real, 1, NOW_MS);
    let (op, material) = signed_migrate_op(
        &V2Signer::Legacy(2),
        &note,
        V2Signer::Stark(0xB2).owner_ref(),
        felt32(0xB2),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        1,
    );
    let frame = s.submit_migrate(op, &material, NOW_MS).unwrap();
    // 帧在链上且 op 是 MigrateNote
    assert!(matches!(frame.frame.op, Operation::MigrateNote(_)));
    assert_eq!(frame.frame.index, 1);
    assert!(matches!(
        s.chain().last().unwrap().frame.op,
        Operation::MigrateNote(_)
    ));
    // v2 note 待证明；水位覆盖 migrate op_index 后翻 Proven
    let commitment = s.state().notes_v2.values().next().unwrap().note.commitment_bytes();
    assert_eq!(
        s.state().notes_v2.get(&commitment).unwrap().status,
        NoteStatus::Pending
    );
    let head = s.state().seq - 1; // migrate 帧的 op_index
    s.mark_proven_through(head);
    assert_eq!(s.proven_watermark(), head);
    assert_eq!(s.state().notes_v2.get(&commitment).unwrap().status, NoteStatus::Proven);
    // 链头哈希可复算（软确认链完整）
    assert!(s.head_hash().is_ok());
}

// ---------------------------------------------------------------------------
// 3) WAL 重放：v2 账本 / migration nonce 集 / signer nonce 水位等价
// ---------------------------------------------------------------------------

#[test]
fn replay_restores_v2_ledger_and_nonce_sets() {
    let dir = std::env::temp_dir().join("poker-appchain-note-v2-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("note_v2.wal");
    let _ = std::fs::remove_file(&wal);
    let key = SequencerKey::from_seed(&[31u8; 32]);
    let mut s = Sequencer::new(
        key.clone(),
        SequencerConfig {
            admission_proven_only: false,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    );
    s.attach_wal(&wal).unwrap();
    let alice = V1User::new(3);
    let n1 = deposit_and_take(&mut s, &alice, 300, AssetClass::Play, 1, NOW_MS);
    let n2 = deposit_and_take(&mut s, &alice, 400, AssetClass::Real, 2, NOW_MS + 1_000);
    let (op1, m1) = signed_migrate_op(
        &V2Signer::Legacy(3),
        &n1,
        V2Signer::Stark(0xC3).owner_ref(),
        felt32(0xC1),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        5,
        EXPIRY,
        11,
    );
    s.submit_migrate(op1, &m1, NOW_MS + 2_000).unwrap();
    let (op2, m2) = signed_migrate_op(
        &V2Signer::Legacy(3),
        &n2,
        V2Signer::Stark(0xC3).owner_ref(),
        felt32(0xC2),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        6,
        EXPIRY,
        12,
    );
    s.submit_migrate(op2, &m2, NOW_MS + 3_000).unwrap();

    let root_before = s.state().root();
    let notes_v2_before: Vec<([u8; 32], NoteV2, u64, NoteStatus)> = s
        .state()
        .notes_v2
        .iter()
        .map(|(c, e)| (*c, e.note.clone(), e.created_at_op, e.status))
        .collect();
    let nonces_before = s.state().migration_nonces.clone();
    let owner_nonces_before = s.state().owner_nonces_v2.clone();
    assert_eq!(notes_v2_before.len(), 2);
    drop(s);

    let r = Sequencer::replay(
        &wal,
        key.public,
        SequencerConfig {
            admission_proven_only: false,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    )
    .unwrap();
    // 状态根等价（v2 账本段参与状态根折叠）
    assert_eq!(r.state().root(), root_before, "replay must reproduce v2 ledger state root");
    // v2 账本逐条等价
    for (c, note, created, _status) in &notes_v2_before {
        let e = r.state().notes_v2.get(c).expect("v2 entry must survive replay");
        assert_eq!(&e.note, note);
        assert_eq!(e.created_at_op, *created);
    }
    assert_eq!(r.state().notes_v2.len(), notes_v2_before.len());
    // nonce 集等价
    assert_eq!(r.state().migration_nonces, nonces_before);
    assert_eq!(r.state().owner_nonces_v2, owner_nonces_before);
    // 恢复实例的 v2 余额视图一致
    let owner = V2Signer::Stark(0xC3).owner_ref();
    assert_eq!(r.state().balances_v2_of(&owner), (400, 300));
}

// ---------------------------------------------------------------------------
// 4) migration_nonce 全局重放拒（同 nonce 换 note / 原样重提交）
// ---------------------------------------------------------------------------

#[test]
fn migrate_nonce_replay_rejected() {
    let mut s = new_sequencer(false);
    let alice = V1User::new(4);
    let n1 = deposit_and_take(&mut s, &alice, 100, AssetClass::Play, 1, NOW_MS);
    let n2 = deposit_and_take(&mut s, &alice, 200, AssetClass::Play, 2, NOW_MS + 1);
    let shared_nonce = felt32(0xDD);

    let (op1, m1) = signed_migrate_op(
        &V2Signer::Legacy(4),
        &n1,
        V2Signer::Stark(0xD4).owner_ref(),
        shared_nonce,
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        1,
    );
    s.submit_migrate(op1, &m1, NOW_MS + 2).unwrap();

    // 同 migration_nonce、不同旧 note → 全局查重拒绝
    let (op2, m2) = signed_migrate_op(
        &V2Signer::Legacy(4),
        &n2,
        V2Signer::Stark(0xD4).owner_ref(),
        shared_nonce,
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        2,
        EXPIRY,
        2,
    );
    match s.submit_migrate(op2, &m2, NOW_MS + 3) {
        Err(AppchainError::SettlementReplay) => {}
        other => panic!("shared migration nonce must be rejected, got {other:?}"),
    }

    // 原样重提交第一笔 → 旧 note 已消费，NoteNotFound 先于 nonce 查重
    let (op1b, m1b) = signed_migrate_op(
        &V2Signer::Legacy(4),
        &n1,
        V2Signer::Stark(0xD4).owner_ref(),
        felt32(0xEE),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        3,
        EXPIRY,
        3,
    );
    match s.submit_migrate(op1b, &m1b, NOW_MS + 4) {
        Err(AppchainError::NoteNotFound) => {}
        other => panic!("spent old note must be rejected, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5) 旧 note 双花拒（迁移消费后 v1 路径再花 / 二次迁移）
// ---------------------------------------------------------------------------

#[test]
fn migrate_old_note_double_spend_rejected() {
    let mut s = new_sequencer(false);
    let alice = V1User::new(5);
    let note = deposit_and_take(&mut s, &alice, 700, AssetClass::Play, 1, NOW_MS);
    let (op, material) = signed_migrate_op(
        &V2Signer::Legacy(5),
        &note,
        V2Signer::Stark(0xD5).owner_ref(),
        felt32(0xD5),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        1,
    );
    s.submit_migrate(op, &material, NOW_MS + 1).unwrap();

    // v1 Transfer 再花同一 note → 拒
    let out = poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Play,
        amount: 700,
        owner: alice.pk(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let effect = Operation::Transfer {
        spends: vec![],
        notes: vec![],
        outputs: vec![out.clone()],
    }
    .effect_digest();
    let err = s
        .submit(
            Operation::Transfer {
                spends: vec![alice.settle_auth(&note, scope::TRANSFER, &effect)],
                notes: vec![note.clone()],
                outputs: vec![out],
            },
            NOW_MS + 2,
        )
        .unwrap_err();
    assert!(matches!(err, AppchainError::NoteNotFound | AppchainError::DoubleSpend));

    // 二次迁移（不同 nonce）同一 note → 拒
    let (op2, m2) = signed_migrate_op(
        &V2Signer::Legacy(5),
        &note,
        V2Signer::Stark(0xD5).owner_ref(),
        felt32(0xD6),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        2,
        EXPIRY,
        2,
    );
    assert!(matches!(
        s.submit_migrate(op2, &m2, NOW_MS + 3),
        Err(AppchainError::NoteNotFound)
    ));
}

// ---------------------------------------------------------------------------
// 6) record ↔ minted 一致性负例
// ---------------------------------------------------------------------------

#[test]
fn migrate_minted_record_mismatch_rejected() {
    let mut s = new_sequencer(false);
    let alice = V1User::new(6);
    let note = deposit_and_take(&mut s, &alice, 250, AssetClass::Play, 1, NOW_MS);
    let new_owner = V2Signer::Stark(0xD6).owner_ref();

    let build = |minted_override: fn(&mut NoteV2)| -> (Operation, VerifierMaterial) {
        let (mut op, material) = signed_migrate_op(
            &V2Signer::Legacy(6),
            &note,
            new_owner.clone(),
            felt32(0xE6),
            default_network_id(),
            OWNER_V2_ABI_VERSION,
            1,
            EXPIRY,
            9,
        );
        if let Operation::MigrateNote(m) = &mut op {
            minted_override(&mut m.minted);
        }
        (op, material)
    };

    // 金额不一致
    let (op, m) = build(|minted| minted.amount = 251);
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS + 1),
        Err(AppchainError::AdmissionRejected("migrate minted/record mismatch"))
    ));
    // 资产身份不一致（TE-M1：v1 语义等价改造——Play 旧 note 配 REAL 域
    // minted，冻结映射后不等 → 同一拒绝路径）
    let (op, m) = build(|minted| minted.asset_id = AssetId::REAL_NATIVE);
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS + 2),
        Err(AppchainError::AdmissionRejected("migrate minted/record mismatch"))
    ));
    // owner 不一致
    let (op, m) = build(|minted| minted.owner = V2Signer::Stark(0x999).owner_ref());
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS + 3),
        Err(AppchainError::AdmissionRejected("migrate minted/record mismatch"))
    ));
    // 桌绑定不在 migrate_digest 签名覆盖内 → fail-closed 拒
    let (op, m) = build(|minted| minted.table_id = Some(1));
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS + 4),
        Err(AppchainError::AdmissionRejected("migrate mints free balance notes only"))
    ));
    // 结算投影非零拒
    let (op, m) = build(|minted| minted.pot_index = 1);
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS + 5),
        Err(AppchainError::AdmissionRejected("migrate mints free balance notes only"))
    ));
}

// ---------------------------------------------------------------------------
// 7) 网络 / ABI 版本绑定负例
// ---------------------------------------------------------------------------

#[test]
fn migrate_network_and_abi_binding_rejected() {
    // 本链 network_id 为自定义值 → 携带默认网络 id 的迁移记录拒绝
    let custom_net = blake2s32(&[b"zchain-poker-mainnet-1"]);
    let mut s = Sequencer::new(
        SequencerKey::from_seed(&[17u8; 32]),
        SequencerConfig {
            admission_proven_only: false,
            network_id: custom_net,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    );
    let alice = V1User::new(7);
    let note = deposit_and_take(&mut s, &alice, 90, AssetClass::Play, 1, NOW_MS);
    let (op, m) = signed_migrate_op(
        &V2Signer::Legacy(7),
        &note,
        V2Signer::Stark(0xD7).owner_ref(),
        felt32(0xD7),
        default_network_id(), // ≠ custom_net
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        1,
    );
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS + 1),
        Err(AppchainError::AdmissionRejected("migrate network id mismatch"))
    ));

    // abi_version ≠ 2 → 拒
    let (op, m) = signed_migrate_op(
        &V2Signer::Legacy(7),
        &note,
        V2Signer::Stark(0xD7).owner_ref(),
        felt32(0xD8),
        custom_net,
        3,
        2,
        EXPIRY,
        2,
    );
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS + 2),
        Err(AppchainError::AdmissionRejected("migrate abi version mismatch"))
    ));

    // 网络/版本全部一致 → 通过
    let (op, m) = signed_migrate_op(
        &V2Signer::Legacy(7),
        &note,
        V2Signer::Stark(0xD7).owner_ref(),
        felt32(0xD9),
        custom_net,
        OWNER_V2_ABI_VERSION,
        3,
        EXPIRY,
        3,
    );
    s.submit_migrate(op, &m, NOW_MS + 3).unwrap();
}

// ---------------------------------------------------------------------------
// 8) 信封过期 / nonce 单调负例；submit 通道缺材料拒
// ---------------------------------------------------------------------------

#[test]
fn migrate_envelope_freshness_and_channel_discipline() {
    let mut s = new_sequencer(false);
    let alice = V1User::new(8);
    let note = deposit_and_take(&mut s, &alice, 60, AssetClass::Play, 1, NOW_MS);

    // 过期（expiry == now，fail-closed 边界）
    let (op, m) = signed_migrate_op(
        &V2Signer::Legacy(8),
        &note,
        V2Signer::Stark(0xD8).owner_ref(),
        felt32(0xE1),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        5,
        NOW, // now == expiry → 过期
        1,
    );
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS),
        Err(AppchainError::OutOfRange("owner_v2 envelope expired"))
    ));

    // 首个信封 nonce=5 通过
    let (op, m) = signed_migrate_op(
        &V2Signer::Legacy(8),
        &note,
        V2Signer::Stark(0xD8).owner_ref(),
        felt32(0xE2),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        5,
        EXPIRY,
        1,
    );
    s.submit_migrate(op, &m, NOW_MS + 1).unwrap();

    // 同 signer 第二张 note，信封 nonce 回退（≤ 5）→ SettlementReplay
    let note2 = deposit_and_take(&mut s, &alice, 61, AssetClass::Play, 2, NOW_MS + 2);
    let (op, m) = signed_migrate_op(
        &V2Signer::Legacy(8),
        &note2,
        V2Signer::Stark(0xD8).owner_ref(),
        felt32(0xE3),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        4,
        EXPIRY,
        2,
    );
    assert!(matches!(
        s.submit_migrate(op, &m, NOW_MS + 3),
        Err(AppchainError::SettlementReplay)
    ));

    // nonce 严格递增 → 通过
    let (op, m) = signed_migrate_op(
        &V2Signer::Legacy(8),
        &note2,
        V2Signer::Stark(0xD8).owner_ref(),
        felt32(0xE4),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        6,
        EXPIRY,
        2,
    );
    s.submit_migrate(op, &m, NOW_MS + 4).unwrap();

    // submit 通道不带材料 → fail-closed 拒
    let note3 = deposit_and_take(&mut s, &alice, 62, AssetClass::Play, 3, NOW_MS + 5);
    let (op, _) = signed_migrate_op(
        &V2Signer::Legacy(8),
        &note3,
        V2Signer::Stark(0xD8).owner_ref(),
        felt32(0xE5),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        7,
        EXPIRY,
        3,
    );
    assert!(matches!(
        s.submit(op.clone(), NOW_MS + 6),
        Err(AppchainError::AdmissionRejected(
            "migrate requires submit_migrate with verifier material"
        ))
    ));
    // submit_migrate 通道收非迁移 op → 拒
    assert!(matches!(
        s.submit_migrate(
            Operation::OpenTable { table_id: 9, policy: FeePolicy::Zero },
            &VerifierMaterial::StarkCurve,
            NOW_MS + 7,
        ),
        Err(AppchainError::AdmissionRejected(
            "submit_migrate requires an Operation::MigrateNote op"
        ))
    ));
}

// ---------------------------------------------------------------------------
// 9) 纯 v1 结算正例（v1 路径回归护栏：Settle 纪律零回退）
// ---------------------------------------------------------------------------

#[test]
fn settle_v1_pure_positive_regression() {
    let mut s = new_sequencer(false);
    let alice = V1User::new(9);
    let bob = V1User::new(19);
    s.submit(
        Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
        NOW_MS,
    )
    .unwrap();
    let n1 = deposit_and_take(&mut s, &alice, 500, AssetClass::Play, 1, NOW_MS + 1);
    let n2 = deposit_and_take(&mut s, &bob, 400, AssetClass::Play, 2, NOW_MS + 2);
    let buyin_effect = |user: &V1User| {
        Operation::BuyIn {
            table_id: 1,
            spends: vec![],
            notes: vec![],
            seat_owner: user.pk(),
        }
        .effect_digest()
    };
    for (user, n) in [(&alice, n1.clone()), (&bob, n2.clone())] {
        s.submit(
            Operation::BuyIn {
                table_id: 1,
                spends: vec![user.settle_auth(&n, scope::BUYIN, &buyin_effect(user))],
                notes: vec![n],
                seat_owner: user.pk(),
            },
            NOW_MS + 3,
        )
        .unwrap();
    }
    let seat = |owner: [u8; 33], amount: u64| -> Note {
        s.state()
            .notes
            .values()
            .find(|e| e.note.table_id == Some(1) && e.note.owner == owner && e.note.amount == amount)
            .map(|e| e.note.clone())
            .unwrap()
    };
    let seat_a = seat(alice.pk(), 500);
    let seat_b = seat(bob.pk(), 400);

    // 纯 v1 结算（FeePolicy::Zero：rake 0；plan 与记录按 v1.2 纪律构造）
    let pot = seat_a.amount + seat_b.amount; // 900
    let mut awards = [0u64; 9];
    awards[0] = 500;
    awards[1] = 400;
    let plan = poker_appchain::settlement::flat_settlement_plan(pot, 0b11, awards);
    let mk = |amount: u64, owner: [u8; 33]| poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Play,
        amount,
        owner,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let mut record = poker_appchain::settlement::SettlementRecord {
        table_id: 1,
        hand_binding: felt32(0xF1),
        policy_commitment: FeePolicy::Zero.commitment_bytes(),
        pot,
        inputs: vec![
            poker_appchain::settlement::SettleInput {
                note: seat_a.clone(),
                spend: SpendAuth {
                    commitment: seat_a.commitment_bytes(),
                    nullifier: felt_to_bytes32(&seat_a.nullifier(&alice.secret)),
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            poker_appchain::settlement::SettleInput {
                note: seat_b.clone(),
                spend: SpendAuth {
                    commitment: seat_b.commitment_bytes(),
                    nullifier: felt_to_bytes32(&seat_b.nullifier(&bob.secret)),
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
        ],
        payouts: vec![mk(500, alice.pk()), mk(400, bob.pk())],
        rake: zero_rake(),
        plan,
        hand_proof: None,
    };
    // v1 花费授权对完整结算效果签名（v1 纪律）
    let scope = settle_spend_scope(&record.hand_binding);
    let effect = poker_appchain::settlement::settle_effect(&record);
    for (input, user, note) in [
        (0usize, &alice, &seat_a),
        (1usize, &bob, &seat_b),
    ] {
        let spend = user.settle_auth(note, &scope, &effect);
        record.inputs[input].spend = spend;
    }
    s.submit(Operation::Settle(Box::new(record)), NOW_MS + 5)
        .unwrap();
    assert_eq!(s.state().balances_of(&alice.pk()), (0, 500));
    assert_eq!(s.state().balances_of(&bob.pk()), (0, 400));
    assert_eq!(s.state().tables.get(&1).unwrap().seats, 0);
}

// ---------------------------------------------------------------------------
// 10) 纯 v2 结算正例（双 scheme：Legacy + StarkCurve 输入）
// ---------------------------------------------------------------------------

#[test]
fn settle_v2_pure_positive_two_schemes() {
    let mut s = new_sequencer(false);
    s.submit(
        Operation::OpenTable { table_id: 2, policy: FeePolicy::Zero },
        NOW_MS,
    )
    .unwrap();

    // 两名 v1 用户存款 → 各自迁移成 v2 note（Legacy → v2 Legacy，Stark → v2 Stark）
    let u1 = V1User::new(10);
    let u2 = V1User::new(20);
    let n1 = deposit_and_take(&mut s, &u1, 400, AssetClass::Play, 1, NOW_MS + 1);
    let n2 = deposit_and_take(&mut s, &u2, 600, AssetClass::Play, 2, NOW_MS + 2);
    let v2o1 = V2Signer::Legacy(10);
    let v2o2 = V2Signer::Stark(0x5A17);
    for (note, signer, nonce) in [(n1, &v2o1, felt32(0x51)), (n2, &v2o2, felt32(0x52))] {
        let (op, m) = signed_migrate_op(
            signer,
            &note,
            signer.owner_ref(),
            nonce,
            default_network_id(),
            OWNER_V2_ABI_VERSION,
            1,
            EXPIRY,
            u64::from(nonce[31]),
        );
        s.submit_migrate(op, &m, NOW_MS + 3).unwrap();
    }

    // 从 v2 账本取回两张 note
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
    assert_eq!((v2n1.amount, v2n2.amount), (400, 600));

    // 纯 v2 结算：v2o1 拿 400，v2o2 拿 600（零费）
    let hand_binding = felt32(0x5D);
    let policy = FeePolicy::Zero;
    let net = default_network_id();
    let scope = settle_scope_v2(&net, OWNER_V2_ABI_VERSION, &hand_binding);
    let secret1 = [10u8; 32];
    let secret2 = blake2s32(&[b"stark secret"]);
    let nf1 = v2n1.nullifier(&secret1, &scope);
    let nf2 = v2n2.nullifier(&secret2, &scope);

    let payout1 = NoteSpec2 {
        asset_id: AssetId::GAME_PLAY,
        amount: 400,
        owner: v2o1.owner_ref(),
        table_id: Some(2),
        pot_index: 0,
        runout_index: 0,
    };
    let payout2 = NoteSpec2 {
        asset_id: AssetId::GAME_PLAY,
        amount: 600,
        owner: v2o2.owner_ref(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let mut record = build_settle_v2(
        2,
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
                    nonce: 2,
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
                    nonce: 2,
                    expiry: EXPIRY,
                },
                material: v2o2.material(),
            },
        ],
        vec![payout1, payout2],
        zero_rake(),
        &policy,
    );
    // 回填签名（效果摘要依赖完整记录）
    let effect = settle_effect_v2(&record);
    for (input, signer, nonce) in [(0usize, &v2o1, 2u64), (1, &v2o2, 2u64)] {
        let (note, nullifier) = match &record.inputs[input] {
            SettleInputV2::V2 { note, nullifier, .. } => (note.clone(), *nullifier),
            _ => unreachable!(),
        };
        let envelope = v2_settle_envelope(signer, &note, &nullifier, &scope, &effect, nonce);
        if let SettleInputV2::V2 { envelope: e, .. } = &mut record.inputs[input] {
            *e = envelope;
        }
    }
    s.submit(Operation::SettleV2(Box::new(record)), NOW_MS + 5)
        .unwrap();

    // 消费 + 铸出核对
    assert!(!s.state().notes_v2.contains_key(&v2n1.commitment_bytes()));
    assert!(!s.state().notes_v2.contains_key(&v2n2.commitment_bytes()));
    assert_eq!(s.state().balances_v2_of(&v2o1.owner_ref()), (0, 400));
    assert_eq!(s.state().balances_v2_of(&v2o2.owner_ref()), (0, 600));
    assert!(s.state().settled_bindings.contains(&hand_binding));
    // v2 输入信封 nonce 水位已登记（两位 signer 各 1）
    for signer in [&v2o1, &v2o2] {
        let key = poker_appchain::owner_v2::owner_commitment(&signer.owner_ref());
        assert_eq!(s.state().owner_nonces_v2.get(&key), Some(&2));
    }
}

// ---------------------------------------------------------------------------
// 11) 混合结算正例（v1 seat note + v2 自由余额 note）
// ---------------------------------------------------------------------------

#[test]
fn settle_mixed_v1_v2_positive() {
    let mut s = new_sequencer(false);
    s.submit(
        Operation::OpenTable { table_id: 3, policy: FeePolicy::Zero },
        NOW_MS,
    )
    .unwrap();
    // v1 侧：alice 买入 seat note
    let alice = V1User::new(11);
    let n = deposit_and_take(&mut s, &alice, 500, AssetClass::Play, 1, NOW_MS + 1);
    let buyin_effect = Operation::BuyIn {
        table_id: 3,
        spends: vec![],
        notes: vec![],
        seat_owner: alice.pk(),
    }
    .effect_digest();
    s.submit(
        Operation::BuyIn {
            table_id: 3,
            spends: vec![alice.settle_auth(&n, scope::BUYIN, &buyin_effect)],
            notes: vec![n],
            seat_owner: alice.pk(),
        },
        NOW_MS + 2,
    )
    .unwrap();
    let seat = s
        .state()
        .notes
        .values()
        .find(|e| e.note.table_id == Some(3))
        .map(|e| e.note.clone())
        .unwrap();
    // v2 侧：bob 迁移出一张自由余额 v2 note
    let bob = V1User::new(21);
    let bn = deposit_and_take(&mut s, &bob, 300, AssetClass::Play, 2, NOW_MS + 3);
    let v2bob = V2Signer::Stark(0xB0B);
    let (op, m) = signed_migrate_op(
        &v2bob,
        &bn,
        v2bob.owner_ref(),
        felt32(0xB1),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        42,
    );
    s.submit_migrate(op, &m, NOW_MS + 4).unwrap();
    let v2n = s
        .state()
        .notes_v2
        .values()
        .find(|e| e.note.owner == v2bob.owner_ref())
        .map(|e| e.note.clone())
        .unwrap();

    // 混合结算：v1 seat（500）+ v2 余额（300）→ v1 赢家拿 seat 面 + v2 找零
    let hand_binding = felt32(0x5E);
    let policy = FeePolicy::Zero;
    let net = default_network_id();
    let scope_v1 = settle_spend_scope(&hand_binding);
    let scope_v2 = settle_scope_v2(&net, OWNER_V2_ABI_VERSION, &hand_binding);
    let secret_bob = [21u8; 32];
    let nf_v2 = v2n.nullifier(&secret_bob, &scope_v2);

    let payouts = vec![NoteSpec2 {
        asset_id: AssetId::GAME_PLAY,
        amount: 800,
        owner: v2bob.owner_ref(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    }];
    let mut record = build_settle_v2(
        3,
        hand_binding,
        vec![
            SettleInputV2::V1 {
                note: seat.clone(),
                spend: SpendAuth {
                    commitment: seat.commitment_bytes(),
                    nullifier: felt_to_bytes32(&seat.nullifier(&alice.secret)),
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInputV2::V2 {
                note: v2n.clone(),
                nullifier: nf_v2,
                envelope: SignatureEnvelope {
                    scheme: v2bob.owner_ref().scheme,
                    signer_ref: v2bob.owner_ref(),
                    typed_data_digest: [0; 32],
                    signature: [0; 64],
                    nonce: 2,
                    expiry: EXPIRY,
                },
                material: v2bob.material(),
            },
        ],
        payouts,
        zero_rake(),
        &policy,
    );
    let effect = settle_effect_v2(&record);
    // v1 臂签名（v1 spend_digest + v1 结算 scope）
    if let SettleInputV2::V1 { note, spend } = &mut record.inputs[0] {
        let nf = felt_to_bytes32(&note.nullifier(&alice.secret));
        let d = spend_digest(&spend.commitment, &nf, &scope_v1, &effect);
        spend.sig = alice.key.sign(&d);
    }
    // v2 臂签名（v2 域 + 网络/版本绑定 scope）
    if let SettleInputV2::V2 { note, envelope, .. } = &mut record.inputs[1] {
        *envelope = v2_settle_envelope(&v2bob, note, &nf_v2, &scope_v2, &effect, 2);
    }
    s.submit(Operation::SettleV2(Box::new(record)), NOW_MS + 5)
        .unwrap();

    // 两侧账本核对
    assert!(!s.state().notes.contains_key(&seat.commitment_bytes()));
    assert!(!s.state().notes_v2.contains_key(&v2n.commitment_bytes()));
    assert_eq!(s.state().balances_v2_of(&v2bob.owner_ref()), (0, 800));
    assert_eq!(s.state().balances_of(&alice.pk()), (0, 0));
    println!(
        "[mixed settle] v1 notes={} v2 notes={} settled_bindings={}",
        s.state().notes.len(),
        s.state().notes_v2.len(),
        s.state().settled_bindings.len()
    );
}

// ---------------------------------------------------------------------------
// 12) 交叉伪造负例：v2 输入配 v1 验签 → 拒（双层）
// ---------------------------------------------------------------------------

#[test]
fn settle_v2_cross_forgery_rejected() {
    // 层 1（verifier 单元）：材料变体与 scheme 不匹配（v2 输入配 v1 验签材料）
    let owner = V2Signer::Stark(0xCF).owner_ref();
    let note = NoteV2::new(AssetId::GAME_PLAY, 10, owner.clone(), 1, None, 0, 0).unwrap();
    let scope = settle_scope_v2(&default_network_id(), OWNER_V2_ABI_VERSION, &felt32(0xCF));
    let effect = blake2s32(&[b"cross forgery effect"]);
    let nullifier = note.nullifier(&[7u8; 32], &scope);
    let signer = V2Signer::Stark(0xCF);
    let envelope = v2_settle_envelope(&signer, &note, &nullifier, &scope, &effect, 1);
    // Legacy 材料（v1 验签材料）→ MaterialMismatch；v1 臂进 v2 验证器 → 分派层拒
    let as_v2_input = |material: VerifierMaterial| SettleInputV2::V2 {
        note: note.clone(),
        nullifier,
        envelope: envelope.clone(),
        material,
    };
    assert!(matches!(
        settle_spend_verifier_v2(
            &as_v2_input(VerifierMaterial::LegacySecp256k1 {
                presented_public: OwnerKey::from_seed(&[1u8; 32]).unwrap().public_bytes()
            }),
            &scope,
            &effect,
            NOW,
            None,
        ),
        Err(AppchainError::AdmissionRejected("owner_v2 material mismatch"))
    ));
    assert!(matches!(
        settle_spend_verifier_v2(
            &SettleInputV2::V1 {
                note: V1User::new(1).note(1, AssetClass::Play, 1),
                spend: SpendAuth {
                    commitment: [0; 32],
                    nullifier: [1; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            &scope,
            &effect,
            NOW,
            None,
        ),
        Err(AppchainError::AdmissionRejected(
            "v1 input cannot enter the v2 spend verifier"
        ))
    ));

    // 层 2（sequencer 准入）：v2 note 的信封按 **v1 验签摘要**（v1 域 +
    // v1 spend_digest）构造 → v2 验签路径摘要不一致 → 拒
    let mut s = new_sequencer(false);
    s.submit(
        Operation::OpenTable { table_id: 4, policy: FeePolicy::Zero },
        NOW_MS,
    )
    .unwrap();
    let alice = V1User::new(12);
    let n = deposit_and_take(&mut s, &alice, 120, AssetClass::Play, 1, NOW_MS + 1);
    let v2alice = V2Signer::Legacy(12);
    let (op, m) = signed_migrate_op(
        &v2alice,
        &n,
        v2alice.owner_ref(),
        felt32(0xCA),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        7,
    );
    s.submit_migrate(op, &m, NOW_MS + 2).unwrap();
    let v2n = s
        .state()
        .notes_v2
        .values()
        .find(|e| e.note.owner == v2alice.owner_ref())
        .map(|e| e.note.clone())
        .unwrap();

    let hand_binding = felt32(0xCB);
    let secret = [12u8; 32];
    let nf = v2n.nullifier(&secret, &scope);
    let payouts = vec![NoteSpec2 {
        asset_id: AssetId::GAME_PLAY,
        amount: 120,
        owner: v2alice.owner_ref(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    }];
    let mut record = build_settle_v2(
        4,
        hand_binding,
        vec![SettleInputV2::V2 {
            note: v2n.clone(),
            nullifier: nf,
            envelope: SignatureEnvelope {
                scheme: v2alice.owner_ref().scheme,
                signer_ref: v2alice.owner_ref(),
                typed_data_digest: [0; 32],
                signature: [0; 64],
                nonce: 2,
                expiry: EXPIRY,
            },
            material: v2alice.material(),
        }],
        payouts,
        zero_rake(),
        &FeePolicy::Zero,
    );
    let effect = settle_effect_v2(&record);
    // 伪造：按 **v1** spend_digest（v1 结算域 scope）签名并塞进 v2 输入
    let v1_digest = spend_digest(
        &v2n.commitment_bytes(),
        &nf,
        &settle_spend_scope(&hand_binding),
        &effect,
    );
    if let SettleInputV2::V2 { envelope, .. } = &mut record.inputs[0] {
        envelope.typed_data_digest = v1_digest;
        envelope.signature = v2alice.sign(&v1_digest);
    }
    match s.submit(Operation::SettleV2(Box::new(record)), NOW_MS + 3) {
        Err(AppchainError::AdmissionRejected("owner_v2 digest mismatch")) => {}
        other => panic!("cross-signed v2 input must be rejected, got {other:?}"),
    }
    // 账本零变更（fail-closed）
    assert!(s.state().notes_v2.contains_key(&v2n.commitment_bytes()));
    assert!(!s.state().settled_bindings.contains(&hand_binding));
}

// ---------------------------------------------------------------------------
// 13) 结算重放 / 守恒负例（SettleV2）
// ---------------------------------------------------------------------------

#[test]
fn settle_v2_replay_and_conservation_rejected() {
    // 首次结算成功；同 hand_binding 重放 → SettlementReplay
    let (mut s, record) = settled_v2_fixture();
    s.submit(Operation::SettleV2(Box::new(record.clone())), NOW_MS + 9)
        .unwrap();
    match s.submit(Operation::SettleV2(Box::new(record)), NOW_MS + 10) {
        Err(AppchainError::SettlementReplay) => {}
        other => panic!("settle v2 replay must be rejected, got {other:?}"),
    }
    // 守恒破坏：赔付多铸 → 拒（签名基于原 effect，篡改后必然失配）
    let (mut s2, mut record2) = settled_v2_fixture();
    record2.payouts[0].amount += 1;
    // 签名是对原 effect 的 → 篡改赔付后先撞签名/守恒；这里直接断言拒绝
    assert!(s2
        .submit(Operation::SettleV2(Box::new(record2)), NOW_MS + 11)
        .is_err());
    let _ = s;
}

/// 纯 v2 结算夹具：返回已就绪（未提交）的 SettleV2 记录 + 已迁入的 sequencer。
fn settled_v2_fixture() -> (Sequencer, SettlementRecordV2) {
    let mut s = new_sequencer(false);
    s.submit(
        Operation::OpenTable { table_id: 5, policy: FeePolicy::Zero },
        NOW_MS,
    )
    .unwrap();
    let u = V1User::new(13);
    let n = deposit_and_take(&mut s, &u, 250, AssetClass::Play, 1, NOW_MS + 1);
    let v2u = V2Signer::Stark(0x5E7);
    let (op, m) = signed_migrate_op(
        &v2u,
        &n,
        v2u.owner_ref(),
        felt32(0xE7),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        5,
    );
    s.submit_migrate(op, &m, NOW_MS + 2).unwrap();
    let v2n = s
        .state()
        .notes_v2
        .values()
        .find(|e| e.note.owner == v2u.owner_ref())
        .map(|e| e.note.clone())
        .unwrap();

    let hand_binding = felt32(0xE8);
    let net = default_network_id();
    let scope = settle_scope_v2(&net, OWNER_V2_ABI_VERSION, &hand_binding);
    let secret = [13u8; 32];
    let nf = v2n.nullifier(&secret, &scope);
    let payouts = vec![NoteSpec2 {
        asset_id: AssetId::GAME_PLAY,
        amount: 250,
        owner: v2u.owner_ref(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    }];
    let mut record = build_settle_v2(
        5,
        hand_binding,
        vec![SettleInputV2::V2 {
            note: v2n.clone(),
            nullifier: nf,
            envelope: SignatureEnvelope {
                scheme: v2u.owner_ref().scheme,
                signer_ref: v2u.owner_ref(),
                typed_data_digest: [0; 32],
                signature: [0; 64],
                nonce: 2,
                expiry: EXPIRY,
            },
            material: v2u.material(),
        }],
        payouts,
        zero_rake(),
        &FeePolicy::Zero,
    );
    let effect = settle_effect_v2(&record);
    if let SettleInputV2::V2 { envelope, .. } = &mut record.inputs[0] {
        *envelope = v2_settle_envelope(&v2u, &v2n, &nf, &scope, &effect, 2);
    }
    (s, record)
}

// ---------------------------------------------------------------------------
// 14) 客户端视图：v1 / v2 账户分离 + REAL/PLAY 隔离
// ---------------------------------------------------------------------------

#[test]
fn client_view_separates_v1_v2_accounts() {
    let mut s = new_sequencer(false);
    let alice = V1User::new(14);
    // v1 侧留一张 REAL、一张 PLAY
    let _r = deposit_and_take(&mut s, &alice, 100, AssetClass::Real, 1, NOW_MS);
    let p = deposit_and_take(&mut s, &alice, 200, AssetClass::Play, 2, NOW_MS + 1);
    // 迁移 PLAY 出去（REAL 留在 v1）
    let v2o = V2Signer::Legacy(14);
    let (op, m) = signed_migrate_op(
        &v2o,
        &p,
        v2o.owner_ref(),
        felt32(0xF4),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        3,
    );
    s.submit_migrate(op, &m, NOW_MS + 2).unwrap();
    // 再迁移一张 REAL 出去
    let real_note = s
        .state()
        .notes
        .values()
        .find(|e| e.note.asset_class == AssetClass::Real)
        .map(|e| e.note.clone())
        .unwrap();
    let (op, m) = signed_migrate_op(
        &v2o,
        &real_note,
        v2o.owner_ref(),
        felt32(0xF5),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        2,
        EXPIRY,
        4,
    );
    s.submit_migrate(op, &m, NOW_MS + 3).unwrap();

    let view = account_view(
        s.state(),
        Some(&alice.pk()),
        Some(&v2o.owner_ref()),
    );
    assert_eq!(view.v1.real, 0, "REAL migrated out of v1");
    assert_eq!(view.v1.play, 0);
    assert_eq!(view.v2.real, 100);
    assert_eq!(view.v2.play, 200);
    // 只查一侧
    let v1_only = account_view(s.state(), Some(&alice.pk()), None);
    assert_eq!((v1_only.v1.real, v1_only.v1.play), (0, 0));
    assert_eq!(v1_only.v2, poker_appchain::client_view::ClassPair::default());
}

// ---------------------------------------------------------------------------
// 15) borsh 判别值冻结（追加变体 MigrateNote=7 / SettleV2=8）+ v1 兼容
// ---------------------------------------------------------------------------

#[test]
fn operation_borsh_discriminants_frozen() {
    let alice = V1User::new(15);
    let note = alice.note(1, AssetClass::Play, 1);
    let (op, _) = signed_migrate_op(
        &V2Signer::Legacy(15),
        &note,
        V2Signer::Stark(0xF5).owner_ref(),
        felt32(0xF6),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        1,
    );
    let bytes = borsh::to_vec(&op).unwrap();
    assert_eq!(bytes[0], 7, "MigrateNote discriminant must be 7 (append-only)");

    let record = build_settle_v2(
        1,
        felt32(1),
        vec![],
        vec![],
        zero_rake(),
        &FeePolicy::Zero,
    );
    let bytes = borsh::to_vec(&Operation::SettleV2(Box::new(record))).unwrap();
    assert_eq!(bytes[0], 8, "SettleV2 discriminant must be 8 (append-only)");

    // v1 变体判别值不回退
    let bytes = borsh::to_vec(&Operation::Deposit {
        deposit_id: [0; 32],
        owner: alice.pk(),
        asset_class: AssetClass::Play,
        amount: 1,
    })
    .unwrap();
    assert_eq!(bytes[0], 2, "v1 Deposit discriminant frozen");

    // MigrateNoteOp roundtrip
    if let Operation::MigrateNote(m) = op {
        let back: MigrateNoteOp =
            borsh::from_slice(&borsh::to_vec(&m).unwrap()).unwrap();
        assert_eq!(back, *m);
    }
}

// ---------------------------------------------------------------------------
// 16) 端到端叙事：开桌 → 存入 → 买入 → 迁移 → 软确认链 → 重放等价
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_open_deposit_buyin_migrate_replay() {
    let dir = std::env::temp_dir().join("poker-appchain-note-v2-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("e2e.wal");
    let _ = std::fs::remove_file(&wal);
    let key = SequencerKey::from_seed(&[41u8; 32]);
    let mut s = Sequencer::new(
        key.clone(),
        SequencerConfig {
            admission_proven_only: false,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    );
    s.attach_wal(&wal).unwrap();

    // 开桌 → 存入 → 买入（v1 seat）
    s.submit(
        Operation::OpenTable { table_id: 7, policy: FeePolicy::Zero },
        NOW_MS,
    )
    .unwrap();
    let alice = V1User::new(16);
    let n = deposit_and_take(&mut s, &alice, 900, AssetClass::Play, 1, NOW_MS + 1);
    let buyin_effect = Operation::BuyIn {
        table_id: 7,
        spends: vec![],
        notes: vec![],
        seat_owner: alice.pk(),
    }
    .effect_digest();
    s.submit(
        Operation::BuyIn {
            table_id: 7,
            spends: vec![alice.settle_auth(&n, scope::BUYIN, &buyin_effect)],
            notes: vec![n],
            seat_owner: alice.pk(),
        },
        NOW_MS + 2,
    )
    .unwrap();
    // 第二张余额 note 迁移成 v2
    let n2 = deposit_and_take(&mut s, &alice, 100, AssetClass::Play, 2, NOW_MS + 3);
    let v2o = V2Signer::Stark(0xE2E);
    let (op, m) = signed_migrate_op(
        &v2o,
        &n2,
        v2o.owner_ref(),
        felt32(0xE9),
        default_network_id(),
        OWNER_V2_ABI_VERSION,
        1,
        EXPIRY,
        8,
    );
    s.submit_migrate(op, &m, NOW_MS + 4).unwrap();

    let root_before = s.state().root();
    let chain_before = s.export_chain();
    let v2_before = s.state().balances_v2_of(&v2o.owner_ref());
    drop(s);

    let r = Sequencer::replay(
        &wal,
        key.public,
        SequencerConfig {
            admission_proven_only: false,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    )
    .unwrap();
    assert_eq!(r.state().root(), root_before);
    assert_eq!(r.export_chain(), chain_before);
    assert_eq!(r.state().balances_v2_of(&v2o.owner_ref()), v2_before);
    // 迁移帧在重放链上
    assert!(r
        .chain()
        .iter()
        .any(|f| matches!(f.frame.op, Operation::MigrateNote(_))));
    println!(
        "[e2e replay] chain_len={} v1_notes={} v2_notes={} migration_nonces={}",
        r.chain().len(),
        r.state().notes.len(),
        r.state().notes_v2.len(),
        r.state().migration_nonces.len()
    );
}
