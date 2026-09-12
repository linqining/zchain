//! 集成验收测试：M6-ACC / WALLET-ACC 中可由逻辑测试验证的门槛
//! （浏览器/外部钱包集成面除外，见 README 覆盖对照表）。
//!
//! 每个测试名对应一条验收条目；正例 + 每类负例全部覆盖。

use poker_appchain::fee::{FeePolicy, FeeSplit};
use poker_appchain::keys::SequencerKey;
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::ops::Operation;
use poker_appchain::settlement::{
    flat_settlement_plan, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};
use poker_appchain::soft_confirm::{genesis_prev_hash, SignedFrame, SoftConfirmFrame};
use starknet_crypto::FieldElement;

use wallet_core::account_binding::{
    authorize_message_hash, binding_admission, binding_status, constraints_from_message,
    verify_account_signature, AuthorizeZChainKeyMessage, BindingRegistry, BindingStatus,
    SessionBinding, Snip12Domain, StarkSignature,
};
use wallet_core::backup::{
    collect_indexes, export_backup, import_backup, BackupPayloadV1, EncryptedBackup,
};
use wallet_core::display::{play_page_view, real_page_view, ReadinessFlags};
use wallet_core::error::{SessionRejectReason, WalletError, WalletResult};
use wallet_core::key_manager::{
    session_admission, OwnerKeyPair, Scope, SecretBytes, SessionAdmission, SessionConstraints,
};
use wallet_core::keystore::{open_owner_key, seal_owner_key, params_test};
use wallet_core::note_store::{NoteRecord, OriginFrame, ProofState, WalletStores};
use wallet_core::operation_signer::{
    parse_domain, NetworkCtx, NonceTracker, OutputSpec, RequestContext, Signer, SigningRequest,
};
use wallet_core::verifier::{
    batch_root_golden_ok, meta, verify_batch_root, verify_settlement, verify_soft_chain,
};

// ---------------------------------------------------------------------------
// 测试夹具
// ---------------------------------------------------------------------------

const CHAIN: &str = "zchain-devnet-1";

fn ctx(nonce: u64, expiry: u64, chain: &str, abi: u32) -> RequestContext {
    RequestContext {
        network: NetworkCtx {
            domain: parse_domain("zchain").unwrap(),
            chain_id: chain.to_string(),
            abi_version: abi,
        },
        nonce,
        expiry,
    }
}

fn owner(seed: u8) -> OwnerKeyPair {
    OwnerKeyPair::from_seed(&[seed; 32]).unwrap()
}

/// canonical felt 测试常量（< 域模数）。
fn felt_test(byte: u8) -> [u8; 32] {
    let mut f = [0u8; 32];
    f[31] = byte;
    f
}

/// 钱包 + note 库夹具：owner(7) 持有 REAL 100 与 PLAY 50/30。
fn wallet_with_notes() -> (OwnerKeyPair, WalletStores, Vec<[u8; 32]>) {
    let key = owner(7);
    let mut stores = WalletStores::new();
    let mut commitments = Vec::new();
    let real = Note::new(AssetClass::Real, 100, key.public_bytes(), [1; 32], None).unwrap();
    let play1 = Note::new(AssetClass::Play, 50, key.public_bytes(), [2; 32], None).unwrap();
    let play2 = Note::new(AssetClass::Play, 30, key.public_bytes(), [3; 32], None).unwrap();
    for (note, proof) in [
        (real, ProofState::Proven { batch_root: [9; 32], batch_index: 1 }),
        (play1, ProofState::Soft),
        (play2, ProofState::Soft),
    ] {
        let rec = NoteRecord::with_secret(
            note,
            [0xAB; 32],
            OriginFrame { op_index: 0, frame_hash: genesis_prev_hash() },
            proof,
        );
        commitments.push(stores.store(rec.note.asset_class).insert(rec).unwrap());
    }
    (key, stores, commitments)
}

fn rake_policy(treasury: [u8; 33], operator: [u8; 33]) -> FeePolicy {
    FeePolicy::FixedRake {
        rate_bps: 500,
        cap: 0,
        split: FeeSplit { treasury_bps: 2_000, treasury, operator },
    }
}

/// 正例结算：owner(7)/owner(8) 各持 1_000 seat（桌 1），5% rake →
/// pot 2000，rake 100，payout = 900 / 1000，treasury 20 + operator 80。
/// 返回骨架（spend 空签名，待各方 `sign_settle_input` 补签）。
fn good_settlement(policy: &FeePolicy) -> (SettlementRecord, Note, Note) {
    let a = owner(7);
    let b = owner(8);
    let seat_a = Note::new(AssetClass::Play, 1_000, a.public_bytes(), [4; 32], Some(1)).unwrap();
    let seat_b = Note::new(AssetClass::Play, 1_000, b.public_bytes(), [5; 32], Some(1)).unwrap();
    let pot = 2_000u64;
    let rake_total = policy.rake_of(pot);
    let (t_amt, o_amt) = policy.split_of(rake_total);
    let mk = |amount: u64, owner_key: [u8; 33]| NoteSpec {
        asset_class: AssetClass::Play,
        amount,
        owner: owner_key,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let mut awards = [0u64; 9];
    awards[0] = pot - rake_total - seat_b.amount;
    awards[1] = seat_b.amount;
    // 骨架占位 spend：commitment 必须是真实值（settle_effect 绑定全部输入
    // 承诺）；nullifier/sig 为占位，由各玩家 sign_settle_input 补齐。
    let placeholder_spend = |note: &Note| SpendAuth {
        commitment: note.commitment_bytes(),
        nullifier: [0; 32],
        sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
    };
    let record = SettlementRecord {
        table_id: 1,
        hand_binding: felt_test(0x42),
        policy_commitment: policy.commitment_bytes(),
        pot,
        inputs: vec![
            SettleInput { note: seat_a.clone(), spend: placeholder_spend(&seat_a) },
            SettleInput { note: seat_b.clone(), spend: placeholder_spend(&seat_b) },
        ],
        payouts: vec![
            mk(pot - rake_total - seat_b.amount, a.public_bytes()),
            mk(seat_b.amount, b.public_bytes()),
        ],
        rake: RakeSplitRecord {
            total: rake_total,
            treasury_out: Some(mk(t_amt, match policy {
                FeePolicy::FixedRake { split, .. } => split.treasury,
                _ => unreachable!(),
            })),
            operator_out: Some(mk(o_amt, match policy {
                FeePolicy::FixedRake { split, .. } => split.operator,
                _ => unreachable!(),
            })),
        },
        plan: flat_settlement_plan(pot, 0b11, awards),
        hand_proof: None,
    };
    (record, seat_a, seat_b)
}

/// 会话授权夹具（约束；per-tx 50 / daily 100 / 白名单桌 [1]）。
fn session_constraints() -> SessionConstraints {
    SessionConstraints {
        binding_id: felt_test(1),
        chain_id: CHAIN.into(),
        account_address: felt_test(2),
        delegated_public: owner(9).public_bytes(),
        allowed_scopes: vec![Scope::Play, Scope::BuyIn, Scope::Settle, Scope::Transfer],
        per_tx_limit: Some(50),
        daily_limit: Some(100),
        table_allowlist: Some(vec![1]),
        valid_after: 1_000,
        valid_until: 2_000,
        nonce: 3,
    }
}

fn session_key_for(constraints: SessionConstraints) -> wallet_core::key_manager::SessionKey {
    // 测试向量：delegated secret = [9; 32]（与 owner(9) 同钥）。
    wallet_core::key_manager::SessionKey::from_secret(
        constraints,
        secp256k1::SecretKey::from_slice(&[9; 32]).unwrap(),
    )
}

/// 全链路备份 payload（owner 信封 + DEK 信封 + 双库快照 + 索引）。
fn full_backup_payload(
    stores: &WalletStores,
    dek: &SecretBytes,
    owner_env: Option<wallet_core::keystore::SealedEnvelope>,
    password: &str,
) -> BackupPayloadV1 {
    BackupPayloadV1 {
        keystore: owner_env,
        dek_envelope: Some(wallet_core::keystore::seal_dek(dek, password.as_bytes(), params_test()).unwrap()),
        real_store: Some(stores.real().seal(dek).unwrap()),
        play_store: Some(stores.play().seal(dek).unwrap()),
        bindings: BindingRegistry::new(),
        checkpoint: None,
        indexes: collect_indexes(stores),
        created_unix: 1_700_000_000,
    }
}

// ---------------------------------------------------------------------------
// M6-ACC-7：签名可读性（预览完整性 + 三类拒绝）
// ---------------------------------------------------------------------------

#[test]
fn m6_acc_7_preview_fields_complete() {
    let (key, stores, commitments) = wallet_with_notes();
    let mut nonces = NonceTracker::new();
    let mut signer = Signer::new(&stores, 1_500, &mut nonces);
    let req = SigningRequest::Transfer {
        ctx: ctx(1, 9_000, CHAIN, 1),
        asset_class: AssetClass::Play,
        inputs: vec![commitments[1]],
        outputs: vec![OutputSpec { owner: owner(8).public_bytes(), amount: 50 }],
    };
    let preview = signer.preview(&req).unwrap();
    assert_eq!(preview.kind, "transfer");
    assert_eq!(preview.chain_id, CHAIN);
    assert_eq!(preview.domain, "zchain");
    assert_eq!(preview.abi_version, 1);
    assert_eq!(preview.asset_class, "PLAY");
    assert_eq!(preview.amount_in, 50);
    assert_eq!(preview.amount_out, 50);
    assert_eq!(preview.rake, 0);
    assert_eq!(preview.outputs.len(), 1);
    assert_eq!(preview.outputs[0].owner, hex::encode(owner(8).public_bytes()));
    assert_eq!(preview.proof_states, vec!["soft".to_string()]);
    assert_eq!(preview.expiry, 9_000);
    assert_eq!(preview.nonce, 1);
    assert!(!preview.digest.is_empty());
    // 人类可读文本包含全部关键字段（M6-ACC-7 可读性）
    let text = format!("{preview}");
    for needle in [
        "transfer", CHAIN, "zchain", "PLAY", "amount_in", "amount_out", "rake", "proof", "expiry",
        "nonce", "digest",
    ] {
        assert!(text.contains(needle), "preview text missing {needle}:\n{text}");
    }
    // 签名成功且摘要一致
    let signed = signer.sign(&req, &key).unwrap();
    assert_eq!(hex::encode(signed.digest), preview.digest);
    assert!(matches!(signed.operation, Operation::Transfer { .. }));
}

#[test]
fn m6_acc_7_reject_unknown_domain() {
    // 未知域标签 fail-closed：SN_MAIN / eip155 / 乱串 / 空串全部拒绝
    for tag in ["SN_MAIN", "SN_SEPOLIA", "eip155", "evm", ""] {
        assert!(
            matches!(parse_domain(tag), Err(WalletError::UnknownDomainTag(_))),
            "domain {tag} must be rejected"
        );
    }
    assert!(parse_domain("zchain").is_ok());
}

#[test]
fn m6_acc_7_reject_unknown_abi_version() {
    let (_key, stores, commitments) = wallet_with_notes();
    let mut nonces = NonceTracker::new();
    let mut signer = Signer::new(&stores, 1_500, &mut nonces);
    for abi in [0u32, 2, 99, u32::MAX] {
        let req = SigningRequest::Transfer {
            ctx: ctx(1, 9_000, CHAIN, abi),
            asset_class: AssetClass::Play,
            inputs: vec![commitments[1]],
            outputs: vec![OutputSpec { owner: owner(8).public_bytes(), amount: 10 }],
        };
        assert!(matches!(
            signer.preview(&req),
            Err(WalletError::UnknownAbiVersion(v)) if v == abi
        ));
    }
}

#[test]
fn m6_acc_7_reject_amount_overflow_and_conservation() {
    let (_key, stores, commitments) = wallet_with_notes();
    let mut nonces = NonceTracker::new();
    let mut signer = Signer::new(&stores, 1_500, &mut nonces);
    let max = u64::MAX;
    // 超过 u64 账本上限（Σoutputs > u64::MAX）
    let req = SigningRequest::Transfer {
        ctx: ctx(1, 9_000, CHAIN, 1),
        asset_class: AssetClass::Play,
        inputs: vec![commitments[1]],
        outputs: vec![
            OutputSpec { owner: owner(8).public_bytes(), amount: max },
            OutputSpec { owner: owner(9).public_bytes(), amount: max },
        ],
    };
    assert!(matches!(
        signer.preview(&req),
        Err(WalletError::AmountOverflow("exceeds u64 ledger amounts"))
    ));
    // 守恒破坏（Σinputs != Σoutputs）
    let req = SigningRequest::Transfer {
        ctx: ctx(2, 9_000, CHAIN, 1),
        asset_class: AssetClass::Play,
        inputs: vec![commitments[1]],
        outputs: vec![OutputSpec { owner: owner(8).public_bytes(), amount: 49 }],
    };
    assert!(matches!(
        signer.preview(&req),
        Err(WalletError::AmountOverflow("inputs != outputs"))
    ));
    // 重量级：两张 u64::MAX 输入 → 输入聚合超 u64 上限（买入路径）
    let mut stores = stores;
    let big1 = Note::new(AssetClass::Play, max, owner(7).public_bytes(), [11; 32], None).unwrap();
    let big2 = Note::new(AssetClass::Play, max, owner(7).public_bytes(), [12; 32], None).unwrap();
    let c1 = stores.store(AssetClass::Play).insert(NoteRecord::with_secret(
        big1, [1; 32], OriginFrame { op_index: 1, frame_hash: [0; 32] }, ProofState::Soft,
    )).unwrap();
    let c2 = stores.store(AssetClass::Play).insert(NoteRecord::with_secret(
        big2, [2; 32], OriginFrame { op_index: 2, frame_hash: [0; 32] }, ProofState::Soft,
    )).unwrap();
    let mut nonces2 = NonceTracker::new();
    let mut signer = Signer::new(&stores, 1_500, &mut nonces2);
    let req = SigningRequest::BuyIn {
        ctx: ctx(3, 9_000, CHAIN, 1),
        asset_class: AssetClass::Play,
        table_id: 1,
        seat_owner: owner(8).public_bytes(),
        inputs: vec![c1, c2],
    };
    assert!(matches!(
        signer.preview(&req),
        Err(WalletError::AmountOverflow("exceeds u64 ledger amounts"))
    ));
}

// ---------------------------------------------------------------------------
// M6-ACC-2/8 + WALLET-ACC-5：备份恢复与 fail-closed
// ---------------------------------------------------------------------------

#[test]
fn m6_acc_2_8_backup_roundtrip_restores_everything() {
    let password = "correct horse battery";
    let (key, stores, commitments) = wallet_with_notes();
    let owner_env = seal_owner_key(&key, password.as_bytes(), params_test()).unwrap();
    let dek = SecretBytes::new([0x5A; 32]);
    let payload = full_backup_payload(&stores, &dek, Some(owner_env), password);
    let backup = export_backup(&payload, password.as_bytes(), params_test()).unwrap();
    let bytes = backup.to_bytes().unwrap();

    // 新实例导入：note/nullifier/proof 状态完整
    let backup = EncryptedBackup::from_bytes(&bytes).unwrap();
    let restored = import_backup(&backup, password.as_bytes()).unwrap();
    let new_dek = wallet_core::keystore::open_dek(
        restored.dek_envelope.as_ref().unwrap(),
        password.as_bytes(),
    )
    .unwrap();
    let mut new_stores = WalletStores::new();
    new_stores.set_real(
        wallet_core::note_store::NoteStore::open(
            &new_dek,
            AssetClass::Real,
            restored.real_store.as_ref().unwrap(),
        )
        .unwrap(),
    );
    new_stores.set_play(
        wallet_core::note_store::NoteStore::open(
            &new_dek,
            AssetClass::Play,
            restored.play_store.as_ref().unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(new_stores.real().len(), 1);
    assert_eq!(new_stores.play().len(), 2);
    // commitment 完整
    for c in &commitments {
        assert!(
            new_stores.real().get(c).is_some() || new_stores.play().get(c).is_some(),
            "commitment missing after restore"
        );
    }
    // nullifier 索引完整（与导出声明一致）
    assert_eq!(collect_indexes(&new_stores), payload.indexes);
    // proof 状态完整（REAL proven、PLAY soft）
    let real_rec = new_stores.real().get(&commitments[0]).unwrap();
    assert!(matches!(real_rec.proof, ProofState::Proven { batch_index: 1, .. }));
    let play_rec = new_stores.play().get(&commitments[1]).unwrap();
    assert!(matches!(play_rec.proof, ProofState::Soft));
    // 恢复索引自检通过
    assert!(wallet_core::backup::verify_stores_against_indexes(&mut new_stores, &restored.indexes).is_ok());
    // 新设备上 owner key 也恢复（同一口令）
    let new_owner = open_owner_key(restored.keystore.as_ref().unwrap(), password.as_bytes()).unwrap();
    assert_eq!(new_owner.public_bytes(), key.public_bytes());
}

#[test]
fn m6_acc_8_backup_never_exports_plaintext_keys() {
    let password = "pw";
    let (key, stores, _) = wallet_with_notes();
    let owner_env = seal_owner_key(&key, password.as_bytes(), params_test()).unwrap();
    let dek = SecretBytes::new([0x5A; 32]);
    let payload = full_backup_payload(&stores, &dek, Some(owner_env), password);
    let backup = export_backup(&payload, password.as_bytes(), params_test()).unwrap();
    let bytes = backup.to_bytes().unwrap();
    // 原始私钥字节不在导出中
    let secret_raw = key.secret_bytes();
    assert!(!bytes.windows(32).any(|w| w == secret_raw.as_ref()), "raw secret in backup");
    // hex 私钥/spend secret 前缀也不在
    let hexed = hex::encode(&bytes);
    assert!(!hexed.contains(&hex::encode(secret_raw)[..16]), "hex secret prefix in backup");
    assert!(!hexed.contains(&hex::encode([0xAB; 32])[..16]), "spend secret prefix in backup");
}

#[test]
fn wallet_acc_5_backup_fail_closed() {
    let password = "pw";
    let (key, stores, _) = wallet_with_notes();
    let owner_env = seal_owner_key(&key, password.as_bytes(), params_test()).unwrap();
    let dek = SecretBytes::new([0x5A; 32]);
    let payload = full_backup_payload(&stores, &dek, Some(owner_env), password);
    let backup = export_backup(&payload, password.as_bytes(), params_test()).unwrap();

    // 错误口令
    assert!(matches!(
        import_backup(&backup, b"wrong"),
        Err(WalletError::BadPassword)
    ));
    // 篡改字节
    let mut bytes = backup.to_bytes().unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    let tampered = EncryptedBackup::from_bytes(&bytes).unwrap();
    assert!(matches!(
        import_backup(&tampered, password.as_bytes()),
        Err(WalletError::BadPassword)
    ));
    // 未来版本（解密之前拒绝）
    let mut future = backup.clone();
    future.version = 99;
    assert!(matches!(
        import_backup(&future, password.as_bytes()),
        Err(WalletError::UnsupportedVersion { found: 99, max_supported: 1 })
    ));
    // 魔数篡改
    let mut bad_magic_bytes = backup.to_bytes().unwrap();
    bad_magic_bytes[0] = b'X';
    assert!(EncryptedBackup::from_bytes(&bad_magic_bytes).is_err());
}

// ---------------------------------------------------------------------------
// M6-ACC-3：verifier 篡改拒绝
// ---------------------------------------------------------------------------

#[test]
fn m6_acc_3_verifier_accepts_valid_and_rejects_tampering() {
    let policy = rake_policy(owner(90).public_bytes(), owner(91).public_bytes());
    let (record, seat_a, seat_b) = good_settlement(&policy);

    // 两个钱包各自持有 seat note（桌 1 结算输入）
    let mut stores_a = WalletStores::new();
    stores_a.store(AssetClass::Play).insert(NoteRecord::with_secret(
        seat_a.clone(), [0x21; 32],
        OriginFrame { op_index: 1, frame_hash: [1; 32] }, ProofState::Soft,
    )).unwrap();
    let mut stores_b = WalletStores::new();
    stores_b.store(AssetClass::Play).insert(NoteRecord::with_secret(
        seat_b.clone(), [0x22; 32],
        OriginFrame { op_index: 2, frame_hash: [2; 32] }, ProofState::Soft,
    )).unwrap();
    let key_a = owner(7);
    let key_b = owner(8);

    // 多人桌协议路径：各玩家只签自己的输入（signer 持各自库）
    let mut nonces_a = NonceTracker::new();
    let signer_a = Signer::new(&stores_a, 1_500, &mut nonces_a);
    let spend_a = signer_a.sign_settle_input(&record, 0, &key_a).unwrap();
    let mut nonces_b = NonceTracker::new();
    let signer_b = Signer::new(&stores_b, 1_500, &mut nonces_b);
    let spend_b = signer_b.sign_settle_input(&record, 1, &key_b).unwrap();

    // operator 组装完整记录
    let mut complete = record.clone();
    complete.inputs[0].spend = spend_a;
    complete.inputs[1].spend = spend_b;

    // 验证即确认（level = soft）
    let verdict = verify_settlement(&complete, &policy).expect("complete settlement must verify");
    assert_eq!(verdict.level.name(), "soft");
    assert_eq!(verdict.inputs, 2);
    assert_eq!(verdict.payouts, 2);

    // 钱包侧结构化 Settle 请求路径（预览 + 全员签名后 validate 才放行）：
    // 输入含他人零签名 → 拒绝出签名（fail-closed）
    let mut stores_all = WalletStores::new();
    stores_all.store(AssetClass::Play).insert(NoteRecord::with_secret(
        seat_a, [0x21; 32], OriginFrame { op_index: 1, frame_hash: [1; 32] }, ProofState::Soft,
    )).unwrap();
    let mut nonces = NonceTracker::new();
    let mut signer = Signer::new(&stores_all, 1_500, &mut nonces);
    let req = SigningRequest::Settle {
        ctx: ctx(10, 9_000, CHAIN, 1),
        policy: policy.clone(),
        record: record.clone(),
    };
    let preview = signer.preview(&req).unwrap();
    assert_eq!(preview.kind, "settle");
    assert_eq!(preview.rake, 100);
    assert_eq!(preview.amount_in, 2_000);
    assert_eq!(preview.hand_binding, hex::encode(record.hand_binding));
    assert!(matches!(
        signer.sign(&req, &key_a),
        Err(WalletError::VerifierRejected(_))
    ));

    // 篡改 payouts → 拒绝并给原因（M6-ACC-3）
    let mut tampered = complete.clone();
    tampered.payouts[0].amount += 1;
    let err = verify_settlement(&tampered, &policy).unwrap_err();
    assert!(matches!(err, WalletError::VerifierRejected(_)), "{err}");

    // 篡改 pot → 拒绝
    let mut tampered = complete.clone();
    tampered.pot += 1;
    assert!(verify_settlement(&tampered, &policy).is_err());

    // 篡改 hand_binding（换手重放）→ 输入签名不再覆盖 → 拒绝
    let mut tampered = complete;
    tampered.hand_binding[31] ^= 0x01;
    assert!(verify_settlement(&tampered, &policy).is_err());
}

#[test]
fn m6_acc_3_verifier_rejects_tampered_soft_frames_and_batch_root() {
    let seq = SequencerKey::from_seed(&[42; 32]);
    let frame = SoftConfirmFrame {
        index: 0,
        prev_hash: genesis_prev_hash(),
        op: Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
        state_root: [7; 32],
        ts_ms: 1_000,
    };
    let signed = SignedFrame::sign(frame, &seq).unwrap();
    // 正例
    let verdict = verify_soft_chain(&[signed.clone()], &seq.public).unwrap();
    assert_eq!(verdict.level.name(), "soft");
    assert_eq!(verdict.head, signed.hash().unwrap());
    // 篡改载荷（state_root）→ 签名失效
    let mut tampered = signed.clone();
    tampered.frame.state_root[0] ^= 0x01;
    let err = verify_soft_chain(&[tampered], &seq.public).unwrap_err();
    assert!(err.to_string().contains("signature"), "{err}");
    // 换 sequencer 公钥 → 拒绝
    let other = SequencerKey::from_seed(&[43; 32]);
    assert!(verify_soft_chain(&[signed], &other.public).is_err());
    // 批次根：golden 复算 + 声明不符拒绝
    assert!(batch_root_golden_ok());
    let bindings = [[0xAA; 32], [0xBB; 32]];
    let root = poker_appchain::pipeline::batch_root(&bindings).unwrap();
    verify_batch_root(&bindings, &root).unwrap();
    let mut wrong = root;
    wrong[0] ^= 1;
    assert!(matches!(
        verify_batch_root(&bindings, &wrong),
        Err(WalletError::VerifierRejected(_))
    ));
    // verifier 元信息
    let m = meta();
    assert_eq!(m.abi_version, 1);
    assert!(m.version.contains('.'));
}

// ---------------------------------------------------------------------------
// M6-ACC-4：恢复演练（生成 → 销毁 → 恢复 → 余额与 note 完整）
// ---------------------------------------------------------------------------

#[test]
fn m6_acc_4_recovery_drill() {
    let password = "drill-pw";
    // 1. 生成钱包 + note
    let (key, stores, commitments) = wallet_with_notes();
    let before = stores.balances();
    assert_eq!(before.real_free, 100);
    assert_eq!(before.play_free, 80);
    // 标记一张已花费（提现状态）
    let mut stores = stores;
    let store = stores.store(AssetClass::Play);
    store.get_mut(&commitments[2]).unwrap().spent_by_op = Some(77);
    // 2. 备份导出
    let owner_env = seal_owner_key(&key, password.as_bytes(), params_test()).unwrap();
    let dek = SecretBytes::new([0x77; 32]);
    let payload = full_backup_payload(&stores, &dek, Some(owner_env), password);
    let backup = export_backup(&payload, password.as_bytes(), params_test()).unwrap();
    // 3. 销毁实例（drop；密钥随 Zeroizing 清零）
    drop(stores);
    drop(key);
    // 4. "新设备"恢复
    let restored = import_backup(&backup, password.as_bytes()).unwrap();
    let new_dek = wallet_core::keystore::open_dek(restored.dek_envelope.as_ref().unwrap(), password.as_bytes()).unwrap();
    let mut new_stores = WalletStores::new();
    new_stores.set_real(
        wallet_core::note_store::NoteStore::open(&new_dek, AssetClass::Real, restored.real_store.as_ref().unwrap()).unwrap(),
    );
    new_stores.set_play(
        wallet_core::note_store::NoteStore::open(&new_dek, AssetClass::Play, restored.play_store.as_ref().unwrap()).unwrap(),
    );
    // 5. 余额与 note 完整（含 spent 状态）
    let after = new_stores.balances();
    assert_eq!(after.real_free, 100);
    assert_eq!(after.play_free, 50, "spent note must not count toward free balance");
    let spent_rec = new_stores.play().get(&commitments[2]).unwrap();
    assert_eq!(spent_rec.spent_by_op, Some(77));
    // nullifier 索引完整
    for store in [new_stores.real(), new_stores.play()] {
        assert_eq!(store.nullifiers().count(), store.len());
    }
}

// ---------------------------------------------------------------------------
// WALLET-ACC-2（逻辑面）：摘要确定性与域/网络分离
// ---------------------------------------------------------------------------

#[test]
fn wallet_acc_2_digest_separation() {
    let (_key, stores, commitments) = wallet_with_notes();
    let mk = |chain: &str, nonce: u64| SigningRequest::Transfer {
        ctx: ctx(nonce, 9_000, chain, 1),
        asset_class: AssetClass::Play,
        inputs: vec![commitments[1]],
        outputs: vec![OutputSpec { owner: owner(8).public_bytes(), amount: 50 }],
    };
    // 同请求 → 同摘要（确定性）
    let d1 = Signer::new(&stores, 1_500, &mut NonceTracker::new())
        .preview(&mk(CHAIN, 1))
        .unwrap()
        .digest;
    let d1_again = Signer::new(&stores, 1_500, &mut NonceTracker::new())
        .preview(&mk(CHAIN, 1))
        .unwrap()
        .digest;
    assert_eq!(d1, d1_again);
    // 换网络 → 不同摘要
    let d2 = Signer::new(&stores, 1_500, &mut NonceTracker::new())
        .preview(&mk("zchain-testnet-1", 1))
        .unwrap()
        .digest;
    assert_ne!(d1, d2);
    // 换 nonce → 不同摘要
    let d3 = Signer::new(&stores, 1_500, &mut NonceTracker::new())
        .preview(&mk(CHAIN, 2))
        .unwrap()
        .digest;
    assert_ne!(d1, d3);
    // 预览文本含 chain_id（展示字段 = 摘要绑定字段）
    assert!(d1.len() == 64);
}

// ---------------------------------------------------------------------------
// WALLET-ACC-3：session 攻击面（逻辑面）
// ---------------------------------------------------------------------------

#[test]
fn wallet_acc_3_reject_raw_bytes_replay_and_expiry() {
    let (key, stores, commitments) = wallet_with_notes();
    let mut nonces = NonceTracker::new();
    let mut signer = Signer::new(&stores, 1_500, &mut nonces);

    // 任意 bytes 签名：恒拒绝（无 signBytes 默认能力）
    assert!(matches!(
        signer.sign_raw_bytes("malicious dapp", b"\xde\xad\xbe\xef"),
        Err(WalletError::RawBytesRejected)
    ));

    let req = SigningRequest::Transfer {
        ctx: ctx(5, 9_000, CHAIN, 1),
        asset_class: AssetClass::Play,
        inputs: vec![commitments[1]],
        outputs: vec![OutputSpec { owner: owner(8).public_bytes(), amount: 50 }],
    };
    // 第一次签名成功（消耗 nonce 5）
    signer.sign(&req, &key).unwrap();
    // 同 (chain, nonce) 第二次签名 → nonce 重放拒绝
    let err = signer.sign(&req, &key).unwrap_err();
    assert!(
        matches!(&err, WalletError::NonceReplay { chain, nonce: 5 } if chain == CHAIN),
        "{err}"
    );

    // 过期请求（expiry < now）
    let mut nonces2 = NonceTracker::new();
    let mut signer = Signer::new(&stores, 9_001, &mut nonces2);
    let req = SigningRequest::Transfer {
        ctx: ctx(6, 9_000, CHAIN, 1),
        asset_class: AssetClass::Play,
        inputs: vec![commitments[1]],
        outputs: vec![OutputSpec { owner: owner(8).public_bytes(), amount: 50 }],
    };
    assert!(matches!(
        signer.preview(&req),
        Err(WalletError::Expired { expiry: 9_000, now: 9_001 })
    ));
}

#[test]
fn wallet_acc_3_session_scope_limit_expiry_revocation() {
    let (owner_key, stores, commitments) = wallet_with_notes();
    let constraints = session_constraints();
    let session = session_key_for(constraints.clone());
    assert_eq!(session.public_bytes(), owner(9).public_bytes());

    // transfer 守恒：输入 = [note50] 时 amount_out=50；输入 = [note50, note30] 时 80。
    let transfer_req = |inputs: &[usize], nonce: u64| SigningRequest::Transfer {
        ctx: ctx(nonce, 9_000, CHAIN, 1),
        asset_class: AssetClass::Play,
        inputs: inputs.iter().map(|i| commitments[*i]).collect(),
        outputs: vec![OutputSpec {
            owner: owner(8).public_bytes(),
            amount: inputs.iter().map(|i| [50u64, 30][*i - 1]).sum(),
        }],
    };

    // 正例：scope 内 + 限额内（单笔 50 ≤ 50，当日 0 → 50 ≤ 100）
    {
        let mut nonces = NonceTracker::new();
        let mut signer = Signer::new(&stores, 1_500, &mut nonces);
        let signed = signer
            .sign_with_session(&transfer_req(&[1], 20), &session, false, (1, 0))
            .expect("in-scope, in-limit session transfer must sign");
        assert!(matches!(signed.operation, Operation::Transfer { .. }));
    }

    // 超单笔限额（80 > 50）
    {
        let mut nonces = NonceTracker::new();
        let mut signer = Signer::new(&stores, 1_500, &mut nonces);
        assert!(matches!(
            signer.sign_with_session(&transfer_req(&[1, 2], 22), &session, false, (1, 0)),
            Err(WalletError::SessionRejected(SessionRejectReason::OverPerTxLimit))
        ));
    }

    // 超日限额（50 + 已用 60 = 110 > 100）
    {
        let mut nonces = NonceTracker::new();
        let mut signer = Signer::new(&stores, 1_500, &mut nonces);
        assert!(matches!(
            signer.sign_with_session(&transfer_req(&[1], 23), &session, false, (1_500 / 86_400, 60)),
            Err(WalletError::SessionRejected(SessionRejectReason::DailyLimitExhausted))
        ));
    }

    // 过期 session（now ≥ valid_until）
    {
        let mut nonces = NonceTracker::new();
        let mut signer = Signer::new(&stores, 2_000, &mut nonces);
        assert!(matches!(
            signer.sign_with_session(&transfer_req(&[1], 24), &session, false, (2, 0)),
            Err(WalletError::SessionRejected(SessionRejectReason::Expired))
        ));
    }

    // 未生效 session
    {
        let mut nonces = NonceTracker::new();
        let mut signer = Signer::new(&stores, 999, &mut nonces);
        assert!(matches!(
            signer.sign_with_session(&transfer_req(&[1], 25), &session, false, (0, 0)),
            Err(WalletError::SessionRejected(SessionRejectReason::NotYetValid))
        ));
    }

    // 撤销后全拒
    {
        let mut nonces = NonceTracker::new();
        let mut signer = Signer::new(&stores, 1_500, &mut nonces);
        assert!(matches!(
            signer.sign_with_session(&transfer_req(&[1], 26), &session, true, (1, 0)),
            Err(WalletError::SessionRejected(SessionRejectReason::Revoked))
        ));
    }

    // 换网（chain_id 不一致）
    {
        let mut nonces = NonceTracker::new();
        let mut signer = Signer::new(&stores, 1_500, &mut nonces);
        let req = SigningRequest::Transfer {
            ctx: ctx(27, 9_000, "zchain-testnet-1", 1),
            asset_class: AssetClass::Play,
            inputs: vec![commitments[1]],
            outputs: vec![OutputSpec { owner: owner(8).public_bytes(), amount: 50 }],
        };
        assert!(matches!(
            signer.sign_with_session(&req, &session, false, (1, 0)),
            Err(WalletError::SessionRejected(SessionRejectReason::ChainMismatch))
        ));
    }

    // KeyRotation（高风险）→ 会话密钥必须拒绝（OwnerRequired）；主 owner 可以签
    {
        let mut nonces = NonceTracker::new();
        let mut signer = Signer::new(&stores, 1_500, &mut nonces);
        let req = SigningRequest::KeyRotation {
            ctx: ctx(28, 9_000, CHAIN, 1),
            asset_class: AssetClass::Play,
            inputs: vec![commitments[1]],
            new_owner: owner(10).public_bytes(),
        };
        assert!(matches!(
            signer.sign_with_session(&req, &session, false, (1, 0)),
            Err(WalletError::SessionRejected(SessionRejectReason::OwnerRequired))
        ));
        let mut nonces2 = NonceTracker::new();
        let mut signer2 = Signer::new(&stores, 1_500, &mut nonces2);
        let req2 = SigningRequest::KeyRotation {
            ctx: ctx(29, 9_000, CHAIN, 1),
            asset_class: AssetClass::Play,
            inputs: vec![commitments[1]],
            new_owner: owner(10).public_bytes(),
        };
        let signed = signer2.sign(&req2, &owner_key).unwrap();
        assert!(matches!(signed.operation, Operation::Transfer { .. }));
        assert_eq!(signed.preview.kind, "key_rotation");
    }
}

// ---------------------------------------------------------------------------
// WALLET-ACC-3a：SNIP-12 授权摘要 + admission 全负例
// ---------------------------------------------------------------------------

/// Stark 密钥对（测试向量；生产由外部 Starknet 钱包持有）。
fn stark_keypair(seed: u64) -> (FieldElement, FieldElement) {
    let secret = FieldElement::from(seed);
    (secret, starknet_crypto::get_public_key(&secret))
}

#[test]
fn wallet_acc_3a_authorize_digest_verifiable_by_stark_crypto() {
    let (account_secret, account_public) = stark_keypair(0xBEEF);
    let msg = AuthorizeZChainKeyMessage {
        zchain_chain_id: CHAIN.into(),
        account_address: felt_test(2),
        delegated_public_key: owner(9).public_bytes(),
        signature_scheme: "secp256k1".into(),
        allowed_scopes: vec![Scope::Play, Scope::BuyIn, Scope::Settle, Scope::Transfer],
        per_tx_limit: Some(50),
        per_day_limit: Some(100),
        table_allowlist: Some(vec![1]),
        binding_id: felt_test(1),
        nonce: 3,
        valid_after: 1_000,
        valid_until: 2_000,
    };
    let domain = Snip12Domain::zchain(CHAIN);
    let hash = authorize_message_hash(&domain, &msg).unwrap();

    // 外部账户签名（RFC6979 k）
    let sig = loop {
        match starknet_crypto::sign(&account_secret, &hash, &FieldElement::from(1u64)) {
            Ok(s) => {
                if s.r != FieldElement::ZERO && s.s != FieldElement::ZERO {
                    break StarkSignature { r: s.r, s: s.s };
                }
            }
            Err(e) => panic!("stark sign failed: {e}"),
        }
    };
    // 标准验证路径（starknet-crypto）验证通过
    assert!(verify_account_signature(&account_public, &hash, &sig).unwrap());
    // 换公钥 → 拒绝
    let (_other_secret, other_public) = stark_keypair(0xF00D);
    assert!(!verify_account_signature(&other_public, &hash, &sig).unwrap());
    // 换摘要 → 拒绝
    let tampered_hash = hash + FieldElement::from(1u64);
    assert!(!verify_account_signature(&account_public, &tampered_hash, &sig).unwrap());
    // 换签名 → 拒绝
    let tampered_sig = StarkSignature { r: sig.r, s: sig.s + FieldElement::from(1u64) };
    assert!(!verify_account_signature(&account_public, &hash, &tampered_sig).unwrap());
    // 摘要确定性 + 字段敏感
    assert_eq!(hash, authorize_message_hash(&domain, &msg).unwrap());
    let mut other_msg = msg.clone();
    other_msg.per_tx_limit = Some(51);
    assert_ne!(hash, authorize_message_hash(&domain, &other_msg).unwrap());
    let mut other_msg = msg.clone();
    other_msg.allowed_scopes = vec![Scope::Play];
    assert_ne!(hash, authorize_message_hash(&domain, &other_msg).unwrap());

    // constraints 与 message 字段一一对应（WALLET-ACC-2 v2：展示 = verifier 字段）
    let constraints = constraints_from_message(&msg);
    assert_eq!(constraints, session_constraints());
}

#[test]
fn wallet_acc_3a_admission_all_reject_reasons() {
    let constraints = session_constraints();
    let binding = SessionBinding::new(constraints.clone());
    let req = |scope, table, amount| SessionAdmission {
        scope,
        table_id: table,
        amount,
        chain_id: CHAIN.into(),
    };

    // 正例
    assert_eq!(binding.status(1_500), BindingStatus::Active);
    binding_admission(&binding, &req(Scope::BuyIn, Some(1), 40), 1_500).unwrap();

    // 撤销（粘滞）
    let mut revoked = SessionBinding::new(constraints.clone());
    revoked.revoked = true;
    assert_eq!(revoked.status(1_500), BindingStatus::Revoked);
    assert!(matches!(
        binding_admission(&revoked, &req(Scope::BuyIn, Some(1), 1), 1_500),
        Err(WalletError::SessionRejected(SessionRejectReason::Revoked))
    ));

    // 未生效
    assert!(matches!(
        binding_admission(&binding, &req(Scope::BuyIn, Some(1), 1), 999),
        Err(WalletError::SessionRejected(SessionRejectReason::NotYetValid))
    ));

    // 过期
    assert_eq!(binding.status(2_000), BindingStatus::Expired);
    assert!(matches!(
        binding_admission(&binding, &req(Scope::BuyIn, Some(1), 1), 2_000),
        Err(WalletError::SessionRejected(SessionRejectReason::Expired))
    ));

    // 越权 scope（Withdraw 未授权）
    assert!(matches!(
        binding_admission(&binding, &req(Scope::Withdraw, Some(1), 1), 1_500),
        Err(WalletError::SessionRejected(SessionRejectReason::ScopeNotAllowed))
    ));

    // 越权桌（桌 2 不在白名单 [1]）
    assert!(matches!(
        binding_admission(&binding, &req(Scope::BuyIn, Some(2), 1), 1_500),
        Err(WalletError::SessionRejected(SessionRejectReason::TableNotAllowed))
    ));

    // 超单笔限额
    assert!(matches!(
        binding_admission(&binding, &req(Scope::BuyIn, Some(1), 51), 1_500),
        Err(WalletError::SessionRejected(SessionRejectReason::OverPerTxLimit))
    ));

    // 超日限额（单笔 50 ≤ 50 合规，但当日已用 60 + 50 = 110 > 100）
    let mut partially_used = SessionBinding::new(constraints.clone());
    partially_used.daily_used_day = 1_500 / 86_400;
    partially_used.daily_used_amount = 60;
    assert!(matches!(
        binding_admission(&partially_used, &req(Scope::BuyIn, Some(1), 50), 1_500),
        Err(WalletError::SessionRejected(SessionRejectReason::DailyLimitExhausted))
    ));

    // exhausted 状态机（当日用满 100）
    let mut exhausted = SessionBinding::new(constraints.clone());
    exhausted.daily_used_day = 1_500 / 86_400;
    exhausted.daily_used_amount = 100;
    assert_eq!(exhausted.status(1_500), BindingStatus::Exhausted);
    // 跨天窗自动重置（日界另一天）
    assert_eq!(exhausted.status(2 * 86_400), BindingStatus::Expired); // 超出 valid_until → Expired 优先
    let mut long_lived = SessionBinding::new(SessionConstraints {
        valid_until: u64::MAX - 1,
        ..constraints.clone()
    });
    long_lived.daily_used_day = 1;
    long_lived.daily_used_amount = 100;
    assert_eq!(long_lived.status(3 * 86_400 + 5), BindingStatus::Active);

    // 换网
    assert!(matches!(
        session_admission(
            &constraints,
            false,
            (0, 0),
            &SessionAdmission { scope: Scope::Play, table_id: None, amount: 1, chain_id: "SN_MAIN".into() },
            1_500,
        ),
        Err(WalletError::SessionRejected(SessionRejectReason::ChainMismatch))
    ));

    // 未知 binding（registry fail-closed）
    let mut registry = BindingRegistry::new();
    registry.authorize(binding);
    assert!(registry.get(&felt_test(99)).is_none());
    assert!(registry.revoke(&felt_test(99)).is_err());
    // 已知 binding 撤销后粘滞
    let id = constraints.binding_id;
    registry.revoke(&id).unwrap();
    assert!(registry.get(&id).unwrap().revoked);
}

// ---------------------------------------------------------------------------
// WALLET-ACC-6：REAL/PLAY 展示门（状态机）
// ---------------------------------------------------------------------------

#[test]
fn wallet_acc_6_real_claim_gating_and_play_isolation() {
    // Vault/verifier/BFT 未就绪 → claim 隐藏 + 托管风险提示
    let offline = real_page_view(&ReadinessFlags::offline(), 100);
    assert!(!offline.show_claim);
    assert!(offline.custody_risk_notice.is_some());
    // 部分就绪（缺 finality）仍隐藏
    let partial = real_page_view(
        &ReadinessFlags { vault_online: true, verifier_ready: true, bft_finality_ready: false },
        100,
    );
    assert!(!partial.show_claim);
    // 全就绪 → claim 可用
    let ready = real_page_view(&ReadinessFlags::ready(), 100);
    assert!(ready.show_claim);
    // PLAY 页：类型上无 REAL 字段；序列化不含 "real"
    let play = play_page_view(80, true);
    let json = serde_json::to_string(&play).unwrap();
    assert!(!json.to_ascii_lowercase().contains("real"), "{json}");
    // vault_adapter 联动：非 finalized 不可 claim
    let provider = wallet_core::vault_adapter::InMemoryVaultProvider::devnet(CHAIN);
    let claim = wallet_core::vault_adapter::ClaimRequest {
        withdrawal_request_id: felt_test(5),
        vault_address: felt_test(6),
        asset_class: AssetClass::Real,
        amount: 50,
        proof_level: wallet_core::verifier::FinalityLevel::Proven,
    };
    assert!(
        wallet_core::vault_adapter::VaultProvider::request_claim(&provider, CHAIN, &claim).is_err()
    );
}

// ---------------------------------------------------------------------------
// REAL/PLAY 物理分库：跨库不可见
// ---------------------------------------------------------------------------

#[test]
fn physical_split_cross_store_invisibility() {
    let (key, stores, commitments) = wallet_with_notes();
    // REAL 承诺在 PLAY 库不可见，反之亦然
    assert!(stores.play().get(&commitments[0]).is_none());
    assert!(stores.real().get(&commitments[1]).is_none());
    assert!(stores.real().get(&commitments[2]).is_none());
    // REAL 库插入 PLAY note 被拒（fail-closed）
    let mut stores = stores;
    let play = Note::new(AssetClass::Play, 1, key.public_bytes(), [99; 32], None).unwrap();
    assert!(matches!(
        stores.store(AssetClass::Real).insert(NoteRecord::with_secret(
            play, [1; 32], OriginFrame { op_index: 0, frame_hash: [0; 32] }, ProofState::Soft,
        )),
        Err(WalletError::AssetClassMismatch(_))
    ));
    // 余额按资产类聚合正确
    let b = stores.balances();
    assert_eq!(b.real_free, 100);
    assert_eq!(b.play_free, 80);
}

// ---------------------------------------------------------------------------
// sync 断点续传 + vault 能力探测（补充逻辑面）
// ---------------------------------------------------------------------------

#[test]
fn sync_resume_with_checkpoint_and_idempotence() {
    use wallet_core::sync::{
        sync_all, sync_step, ChainSource, InMemoryChainSource, OwnerNoteUpdate, SyncCheckpoint,
        SyncOutcome,
    };
    let seq = SequencerKey::from_seed(&[42; 32]);
    let f0 = SignedFrame::sign(
        SoftConfirmFrame {
            index: 0,
            prev_hash: genesis_prev_hash(),
            op: Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
            state_root: [1; 32],
            ts_ms: 1,
        },
        &seq,
    )
    .unwrap();
    let h0 = f0.hash().unwrap();
    let mut source = InMemoryChainSource::new(vec![f0], seq.public).unwrap();
    let key = owner(7);
    let note = Note::new(AssetClass::Play, 25, key.public_bytes(), [21; 32], None).unwrap();
    source.push_event(OwnerNoteUpdate {
        note,
        spend_secret: [0x31; 32],
        origin: OriginFrame { op_index: 0, frame_hash: h0 },
        proof: ProofState::Soft,
        spent: false,
    });
    let mut stores = WalletStores::new();
    let owner_bytes = key.public_bytes();
    // 首拉（无 checkpoint）拿到 op_index 0 事件
    let cp = sync_all(&source, &owner_bytes, None, &mut stores).unwrap();
    assert_eq!(stores.play().len(), 1);
    assert_eq!(cp.last_op_index, 0);
    // 幂等
    assert_eq!(
        sync_step(&source, &owner_bytes, Some(&cp), &mut stores).unwrap(),
        SyncOutcome::UpToDate
    );
    // 断点续传：新帧/新事件（op 1）后继续同步
    let f1 = SignedFrame::sign(
        SoftConfirmFrame {
            index: 1,
            prev_hash: h0,
            op: Operation::OpenTable { table_id: 2, policy: FeePolicy::Zero },
            state_root: [2; 32],
            ts_ms: 2,
        },
        &seq,
    )
    .unwrap();
    let h1 = f1.hash().unwrap();
    source.frames_mut().push(f1);
    source.push_event(OwnerNoteUpdate {
        note: Note::new(AssetClass::Play, 35, owner_bytes, [22; 32], None).unwrap(),
        spend_secret: [0x32; 32],
        origin: OriginFrame { op_index: 1, frame_hash: h1 },
        proof: ProofState::Soft,
        spent: false,
    });
    let outcome = sync_step(&source, &owner_bytes, Some(&cp), &mut stores).unwrap();
    assert!(matches!(outcome, SyncOutcome::Applied { applied: 1, .. }));
    assert_eq!(stores.play().len(), 2);
    // 新 checkpoint 前进到 op 1
    let SyncCheckpoint { last_op_index, .. } = match sync_step(&source, &owner_bytes, None, &mut stores).unwrap() {
        SyncOutcome::UpToDate => (source.head()),
        SyncOutcome::Applied { checkpoint, .. } => checkpoint,
    };
    assert_eq!(last_op_index, 1);
}

#[test]
fn vault_capabilities_probe() {
    let provider = wallet_core::vault_adapter::InMemoryVaultProvider::devnet(CHAIN);
    let caps = wallet_core::vault_adapter::VaultProvider::get_capabilities(&provider);
    assert!(caps.supports_network(CHAIN));
    assert!(!caps.supports_network("SN_MAIN"));
    assert!(caps.supports_session_authorization());
    assert!(!caps.supports_claim);
    assert!(!caps.supports_signer(wallet_core::vault_adapter::SignerKind::Ledger));
}

// ---------------------------------------------------------------------------
// keystore 错误口令 fail-closed（WALLET-ACC-5 的 keystore 侧）
// ---------------------------------------------------------------------------

#[test]
fn keystore_wrong_passphrase_fails_closed() {
    let key = owner(7);
    let env = seal_owner_key(&key, b"right", params_test()).unwrap();
    assert!(open_owner_key(&env, b"wrong").is_err());
    let back = open_owner_key(&env, b"right").unwrap();
    assert_eq!(back.public_bytes(), key.public_bytes());
}
