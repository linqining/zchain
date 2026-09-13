//! zwallet 集成测试：wallet-core 调用层的每个 MVP 功能都要有可复验的执行痕迹。
//!
//! 覆盖（对应 plan §6.12.5 MVP 仓库内可达子集）：
//! 1. 创建/导入 ZChain Account（keystore 信封 + 口令策略）
//! 2. 口令错误 fail-closed（BadPassword；状态不被破坏）
//! 3. PLAY note 列表/余额 + 本地演示 faucet（明示 demo，不伪造链上）
//! 4. 逐字段签名确认（预览 → 签名；nonce 重放拒绝；任意 bytes 签名恒拒绝）
//! 5. 加密备份导出/导入 + 错误口令/篡改 fail-closed + 恢复自检
//! 6. 应用锁 + 自动锁屏计时
//! 7. 与 poker-wallet CLI 的数据目录格式互通（同一 HexBlob/borsh 信封布局）
//! 8. REAL/PLAY 展示门（wallet-core display 决定：离线无 claim/提现入口）

use zwallet::dto::{SignRequestDto, OutputDto};
use zwallet::{Wallet, ZWalletError};
use wallet_core::keystore::params_test;

const PW: &str = "correct horse battery";

/// 轻量参数钱包（测试用 params_test；生产走 params_interactive）。
fn fresh_wallet(dir: &std::path::Path) -> Wallet {
    let mut w = Wallet::open(dir).expect("open");
    if !w.status().initialized {
        w.create_wallet_with_params(PW, None, params_test()).expect("create");
        // create 后处于解锁态；测试各自显式控制状态。
    }
    w
}

fn locked_wallet(dir: &std::path::Path) -> Wallet {
    let mut w = fresh_wallet(dir);
    w.lock();
    w
}

fn transfer_req(recipient: &str, amount: u64) -> SignRequestDto {
    SignRequestDto {
        kind: "transfer".into(),
        asset_class: "PLAY".into(),
        inputs: vec![],
        outputs: vec![OutputDto { owner: recipient.into(), amount }],
        table_id: None,
        seat_owner: None,
        nonce: None,
        expiry: None,
    }
}

// 全部同步 API，不需要 async runtime。
mod account {
    use super::*;

    #[test]
    fn create_then_status_shows_network_and_owner() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        let s = w.unlock(PW).expect("unlock");
        assert!(s.initialized);
        assert!(!s.locked);
        // devnet 固定网络上下文（MVP 写明，不连网）。
        assert_eq!(s.chain_id, "zchain-devnet-1");
        assert_eq!(s.domain, "zchain");
        assert_eq!(s.abi_version, 1);
        // owner 公钥 66 hex（33B 压缩 secp256k1）。
        let pk = s.owner_public_hex.expect("owner public visible when unlocked");
        assert_eq!(pk.len(), 66);
        assert!(hex::decode(&pk).is_ok());
        assert!(!s.locked);
        // 环境徽章存在（每页展示）。
        assert!(s.environment_badge.contains("devnet"));
        assert!(s.environment_badge.contains("PLAY"));
    }

    #[test]
    fn import_owner_secret_is_deterministic() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = Wallet::open(dir.path()).expect("open");
        w.create_wallet_with_params(PW, Some(&"11".repeat(32)), params_test()).expect("import");
        let s = w.unlock(PW).expect("unlock");
        let expected = wallet_core::key_manager::OwnerKeyPair::from_seed(&[0x11; 32])
            .expect("valid seed")
            .public_bytes();
        assert_eq!(s.owner_public_hex.expect("pk"), hex::encode(expected));
    }

    #[test]
    fn create_rejects_short_password_and_double_init() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = Wallet::open(dir.path()).expect("open");
        assert!(matches!(
            w.create_wallet_with_params("short", None, params_test()),
            Err(ZWalletError::PasswordTooShort)
        ));
        w.create_wallet_with_params(PW, None, params_test()).expect("create");
        assert!(matches!(
            w.create_wallet_with_params(PW, None, params_test()),
            Err(ZWalletError::AlreadyInitialized)
        ));
        // 失败路径不破坏现有钱包。
        let s = w.unlock(PW).expect("still unlockable");
        assert!(s.owner_public_hex.is_some());
    }

    #[test]
    fn wrong_password_unlock_fails_closed() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = locked_wallet(dir.path());
        let err = w.unlock("wrong password!").unwrap_err();
        assert!(matches!(err, ZWalletError::Core(wallet_core::error::WalletError::BadPassword)));
        // fail-closed：拒绝后仍锁定，且正确口令仍可解锁（目录未被破坏）。
        assert!(w.unlock(PW).is_ok());
    }
}

mod notes {
    use super::*;

    #[test]
    fn demo_faucet_then_balances_and_notes() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        let n1 = w.demo_faucet(100).expect("faucet");
        let n2 = w.demo_faucet(50).expect("faucet");
        assert!(n1.demo && n2.demo);
        assert_eq!(n1.proof, "soft");

        let page = w.play_notes().expect("notes");
        assert_eq!(page.play.len(), 2);
        assert_eq!(page.play_free, "150");
        assert_eq!(page.play_locked, "0");
        // 明示本地演示数据（不伪造链上余额）。
        assert!(page.data_source_notice.contains("本地演示数据"));
        // wallet-core display：PLAY faucet 可用（休闲筹码运营功能）。
        assert!(page.play_view.faucet_available);
        // 余额视图与持久化一致：重开后仍在。
        drop(w);
        let mut w2 = Wallet::open(dir.path()).expect("reopen");
        let s = w2.unlock(PW).expect("unlock");
        let b = s.balances.expect("balances when unlocked");
        assert_eq!(b.play_free, "150");
        assert_eq!(b.real_free, "0");
    }

    #[test]
    fn real_display_gate_offline_has_no_claim_entry() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        let s = w.unlock(PW).expect("unlock");
        let b = s.balances.expect("balances");
        // devnet 离线：REAL claim/提现入口必须隐藏 + 托管风险提示常显
        //（WALLET-ACC-6，由 wallet-core display 决定）。
        assert!(!b.real_view.show_claim);
        assert_eq!(b.real_view.claim_disabled_reason, Some("vault_offline"));
        assert!(b.real_view.custody_risk_notice.is_some());
    }

    #[test]
    fn locked_wallet_rejects_note_views() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = locked_wallet(dir.path());
        assert!(matches!(w.play_notes(), Err(ZWalletError::Locked(_))));
        assert!(matches!(w.demo_faucet(1), Err(ZWalletError::Locked(_))));
    }
}

mod signing {
    use super::*;

    fn faucet(w: &mut Wallet, amount: u64) {
        w.demo_faucet(amount).expect("faucet");
    }

    #[test]
    fn transfer_preview_then_sign_field_by_field() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        faucet(&mut w, 100);
        let recipient =
            hex::encode(wallet_core::key_manager::OwnerKeyPair::from_seed(&[0x22; 32]).unwrap().public_bytes());
        let req = transfer_req(&recipient, 100);

        // 第一屏：预览（逐字段；不占用 nonce）。
        let p = w.preview_sign(&req).expect("preview");
        assert_eq!(p.kind, "transfer");
        assert_eq!(p.domain, "zchain");
        assert_eq!(p.chain_id, "zchain-devnet-1");
        assert_eq!(p.abi_version, 1);
        assert_eq!(p.asset_class, "PLAY");
        assert_eq!(p.amount_in, 100);
        assert_eq!(p.amount_out, 100);
        assert_eq!(p.rake, 0);
        assert_eq!(p.table_id, None);
        assert_eq!(p.outputs.len(), 1);
        assert_eq!(p.outputs[0].owner, recipient);
        assert_eq!(p.outputs[0].amount, 100);
        assert!(p.request_id.is_empty());
        assert!(p.hand_binding.is_empty());
        assert_eq!(p.proof_states, vec!["soft".to_string()]);
        assert_eq!(p.digest.len(), 64);

        // 第二屏：确认签名。
        let signed = w.confirm_sign(&req).expect("sign");
        assert_eq!(signed.digest_hex, p.digest);
        let op_bytes = hex::decode(&signed.operation_borsh_hex).expect("hex");
        let op: poker_appchain::ops::Operation =
            borsh::BorshDeserialize::try_from_slice(&op_bytes).expect("borsh op");
        assert!(matches!(op, poker_appchain::ops::Operation::Transfer { .. }));

        // 同一请求重复确认（自动 nonce 递增也能成功；显式 nonce 则重放拒绝）。
        let mut replay = transfer_req(&recipient, 100);
        replay.nonce = Some(0);
        w.confirm_sign(&replay).expect_err("nonce replay must be rejected");
    }

    #[test]
    fn buy_in_preview_carries_table() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        faucet(&mut w, 80);
        let req = SignRequestDto {
            kind: "buy_in".into(),
            asset_class: "PLAY".into(),
            inputs: vec![],
            outputs: vec![],
            table_id: Some(7),
            seat_owner: None, // 缺省 = 本钱包 owner
            nonce: None,
            expiry: None,
        };
        let p = w.preview_sign(&req).expect("preview");
        assert_eq!(p.kind, "buy_in");
        assert_eq!(p.table_id, Some(7));
        assert_eq!(p.amount_in, 80);
        let signed = w.confirm_sign(&req).expect("sign");
        assert_eq!(signed.preview.kind, "buy_in");
    }

    #[test]
    fn expired_request_rejected() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        faucet(&mut w, 10);
        let recipient =
            hex::encode(wallet_core::key_manager::OwnerKeyPair::from_seed(&[0x33; 32]).unwrap().public_bytes());
        let mut req = transfer_req(&recipient, 10);
        req.expiry = Some(1_000); // 早已过期
        assert!(matches!(
            w.confirm_sign(&req),
            Err(ZWalletError::Core(wallet_core::error::WalletError::Expired { .. }))
        ));
    }

    #[test]
    fn real_asset_rejected_at_app_boundary() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        let recipient =
            hex::encode(wallet_core::key_manager::OwnerKeyPair::from_seed(&[0x44; 32]).unwrap().public_bytes());
        let mut req = transfer_req(&recipient, 1);
        req.asset_class = "REAL".into();
        assert!(matches!(
            w.preview_sign(&req),
            Err(ZWalletError::Core(wallet_core::error::WalletError::AssetClassMismatch(_)))
        ));
    }

    #[test]
    fn raw_bytes_signing_is_always_rejected() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        let err = w.sign_raw_bytes("login message", b"arbitrary unstructured bytes").unwrap_err();
        assert!(matches!(
            err,
            ZWalletError::Core(wallet_core::error::WalletError::RawBytesRejected)
        ));
    }
}

mod backup {
    use super::*;

    #[test]
    fn export_import_roundtrip_restores_notes() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        w.demo_faucet(120).expect("faucet");
        let (info, bytes) = w.backup_export_with_params(PW, params_test()).expect("export");
        assert_eq!(info.magic, "ZCBK");
        assert_eq!(info.notes_play, 1);
        // borsh 定长数组内联：文件以魔数 ZCBK 开头（导入侧先验魔数再解密）。
        assert!(bytes.starts_with(b"ZCBK"));
        assert!(bytes.len() > 64);

        // 导入到全新目录 → 锁定态 → 重新解锁 → note 全量恢复（含索引自检）。
        let dir2 = tempfile::tempdir().expect("tmp2");
        let mut w2 = Wallet::open(dir2.path()).expect("open fresh");
        let s = w2.backup_import(&bytes, PW).expect("import");
        assert!(s.locked, "import ends locked (explicit re-unlock boundary)");
        let s = w2.unlock(PW).expect("re-unlock after import");
        assert_eq!(s.balances.expect("balances").play_free, "120");
        let page = w2.play_notes().expect("notes");
        assert_eq!(page.play.len(), 1);
    }

    #[test]
    fn wrong_password_import_fails_closed_and_does_not_touch_dir() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        w.demo_faucet(30).expect("faucet");
        let (_info, bytes) = w.backup_export_with_params(PW, params_test()).expect("export");

        let dir2 = tempfile::tempdir().expect("tmp2");
        let mut w2 = Wallet::open(dir2.path()).expect("open fresh");
        let err = w2.backup_import(&bytes, "wrong password!").unwrap_err();
        assert!(matches!(err, ZWalletError::Core(wallet_core::error::WalletError::BadPassword)));
        // fail-closed：坏口令不污染目标目录（仍为未初始化）。
        assert!(!w2.status().initialized);
    }

    #[test]
    fn tampered_backup_rejected() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        w.demo_faucet(5).expect("faucet");
        let (_info, mut bytes) = w.backup_export_with_params(PW, params_test()).expect("export");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let dir2 = tempfile::tempdir().expect("tmp2");
        let mut w2 = Wallet::open(dir2.path()).expect("open fresh");
        let err = w2.backup_import(&bytes, PW).unwrap_err();
        // AEAD 认证失败 → BadPassword（wallet-core 不区分原因，fail-closed）。
        assert!(matches!(err, ZWalletError::Core(wallet_core::error::WalletError::BadPassword)));
    }

    #[test]
    fn future_version_backup_rejected_before_decryption() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        let (_info, bytes) = w.backup_export_with_params(PW, params_test()).expect("export");
        let mut backup = wallet_core::backup::EncryptedBackup::from_bytes(&bytes).expect("parse");
        backup.version = 99;
        let mutated = backup.to_bytes().expect("re-encode");
        let dir2 = tempfile::tempdir().expect("tmp2");
        let mut w2 = Wallet::open(dir2.path()).expect("open fresh");
        assert!(matches!(
            w2.backup_import(&mutated, PW),
            Err(ZWalletError::Core(wallet_core::error::WalletError::UnsupportedVersion { found: 99, .. }))
        ));
    }
}

mod app_lock {
    use super::*;

    #[test]
    fn auto_lock_fires_after_timeout_and_relock_works() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        w.set_auto_lock_secs(0).expect("set 0 = lock on next op");
        // 空闲超时（0 秒）→ 下一次操作前自动回锁（fail-closed）。
        assert!(matches!(w.play_notes(), Err(ZWalletError::Locked(_))));
        let s = w.status();
        assert!(s.locked);
        assert_eq!(s.lock_remaining_secs, 0);
        // 重新解锁后恢复正常。
        w.set_auto_lock_secs(600).expect("set 600");
        w.unlock(PW).expect("unlock");
        assert!(w.play_notes().is_ok());
    }

    #[test]
    fn settings_persist_across_reopen() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        w.set_auto_lock_secs(42).expect("set");
        drop(w);
        let mut w2 = Wallet::open(dir.path()).expect("reopen");
        assert_eq!(w2.auto_lock_secs(), 42);
    }
}

mod cli_interop {
    use super::*;

    #[test]
    fn data_dir_files_match_poker_wallet_cli_layout() {
        // CLI 的 read_envelope：JSON {"data":[...]} → SealedEnvelope::try_from_slice。
        // 桌面钱包写出的文件必须能走完全相同的读取路径（互读数据目录）。
        let dir = tempfile::tempdir().expect("tmp");
        let mut w = fresh_wallet(dir.path());
        w.demo_faucet(60).expect("faucet");
        w.lock();

        for file in ["keystore.json", "dek.json", "notes_real.json", "notes_play.json"] {
            let bytes = std::fs::read(dir.path().join(file)).expect(file);
            let blob: std::collections::BTreeMap<String, serde_json::Value> =
                serde_json::from_slice(&bytes).expect("json object");
            assert!(blob.contains_key("data"), "{file} must be a HexBlob");
        }
        // 信封可被 wallet-core 直接打开（与 CLI 同一函数）。
        let paths = zwallet::persist::WalletPaths::new(dir.path().to_path_buf());
        let keystore_env = paths
            .read_envelope(&paths.keystore())
            .expect("read")
            .expect("keystore exists");
        let owner = wallet_core::keystore::open_owner_key(&keystore_env, PW.as_bytes())
            .expect("CLI-compatible envelope opens with wallet-core");
        assert_eq!(owner.public_bytes().len(), 33);

        // PLAY 库快照用 DEK 解开（AAD 钉 PLAY）。
        let dek_env = paths.read_envelope(&paths.dek()).expect("read").expect("dek");
        let dek = wallet_core::keystore::open_dek(&dek_env, PW.as_bytes()).expect("dek");
        let play_blob = paths
            .read_blob::<zwallet::persist::HexBlob>(&paths.stores(poker_appchain::note::AssetClass::Play))
            .expect("read")
            .expect("play store");
        let play = wallet_core::note_store::NoteStore::open(
            &dek,
            poker_appchain::note::AssetClass::Play,
            &play_blob.data,
        )
        .expect("CLI-compatible store snapshot");
        assert_eq!(play.len(), 1);
        // REAL 库是独立文件：PLAY 期间也应存在（物理分库落盘）。
        assert!(dir.path().join("notes_real.json").exists());
    }
}
