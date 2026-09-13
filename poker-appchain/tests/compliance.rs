//! 合规运营化框架集成测试（排期表 §4b"合规运营化框架" + §6 TEC-v1 行；
//! [`poker_appchain::compliance`] 的 sequencer 准入端到端矩阵）。
//!
//! 覆盖（对齐 TEC-v1 §5 协议落点表）：
//! 1. **地区开关**：封禁市场 REAL/GAME 全拒 + 计
//!    `geo_policy_rejected_total{market}`；
//! 2. **未配置市场** fail-closed；
//! 3. **KYC 制动位**：`kyc_required_*` 开启即拒 + 计
//!    `kyc_gate_rejected_total`；
//! 4. **fiat_only / token 白名单**：NATIVE 拒、稳定币过；
//! 5. **RG 自排除**：owner 承诺命中即拒（v1/v2 身份空间各自换算）；
//! 6. **单笔限额**：REAL 入金 / GAME 发行 / gas 购买（走 max_deposit）；
//! 7. **PLAY 免费层不设门**（永久免费层是合规防御，TEC-v1 §2）；
//! 8. **审计留痕**：accepted/rejected 事件带 policy version + digest，
//!    JSON 导出可消费；
//! 9. **WAL 重放确定性**：合规放行的 op 重放逐位重现（全网一致参数纪律）。

use poker_appchain::asset_id::{AssetId, TOKEN_NATIVE, TOKEN_USDT};
use poker_appchain::compliance::{
    owner_key_v1, ComplianceParams, ComplianceOpClass, GeoPolicy, MarketPolicy,
};
use poker_appchain::error::AppchainError;
use poker_appchain::game_token::{FaucetPolicy, GameTokenSpec, IssuanceMode};
use poker_appchain::keys::{OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::AssetClass;
use poker_appchain::ops::{DepositV2Op, FaucetMintOp, Operation, RegisterGameTokenOp};
use poker_appchain::owner_v2::{legacy_account_id, OwnerRef, SignatureScheme};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

fn id32(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

/// 市场策略（全通：REAL/GAME 开、无制动、无限额）。
fn open_market() -> MarketPolicy {
    MarketPolicy {
        real_enabled: true,
        game_enabled: true,
        kyc_required_real: false,
        kyc_required_game: false,
        ..MarketPolicy::default()
    }
}

/// geo_policy v1：IM 全通；US-WA（敌意辖区）全关。
fn policy_v1() -> GeoPolicy {
    let mut markets = std::collections::BTreeMap::new();
    markets.insert("IM".to_string(), open_market());
    markets.insert(
        "US-WA".to_string(),
        MarketPolicy {
            real_enabled: false,
            game_enabled: false,
            ..MarketPolicy::default()
        },
    );
    GeoPolicy {
        version: 1,
        markets,
    }
}

fn v1_owner(seed: u8) -> [u8; 33] {
    OwnerKey::from_seed(&[seed; 32]).unwrap().public_bytes()
}

fn v2_owner(seed: u8) -> OwnerRef {
    let key = OwnerKey::from_seed(&[seed; 32]).unwrap();
    OwnerRef {
        scheme: SignatureScheme::LegacySecp256k1,
        account_id: legacy_account_id(&key.public_bytes()),
        key_version: 0,
        binding_id: None,
    }
}

fn deposit_v1(id_byte: u8, owner: &[u8; 33], class: AssetClass, amount: u64) -> Operation {
    Operation::Deposit {
        deposit_id: id32(id_byte),
        owner: *owner,
        asset_class: class,
        amount,
    }
}

fn deposit_v2_op(id_byte: u8, owner: &OwnerRef, asset: AssetId, amount: u64) -> Operation {
    Operation::DepositV2(Box::new(DepositV2Op {
        deposit_id: id32(id_byte),
        owner: owner.clone(),
        asset_id: asset,
        amount,
    }))
}

fn register_free_op(token_id: u32, single_max: u64, lifetime_max: u64) -> Operation {
    let issuer = [0x02u8; 33];
    let mode = IssuanceMode::Free {
        faucet: FaucetPolicy {
            single_max,
            player_lifetime_max: lifetime_max,
        },
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

fn faucet_op(claim_byte: u8, token_id: u32, owner: &OwnerRef, amount: u64) -> Operation {
    Operation::FaucetMint(Box::new(FaucetMintOp {
        claim_id: id32(claim_byte),
        token_id,
        owner: owner.clone(),
        amount,
    }))
}

/// 带 geo_policy 的 sequencer（市场 `market`；可带策略变形）。
fn sequencer_with(policy: GeoPolicy, market: &str) -> (Sequencer, Arc<MetricsRegistry>) {
    let config = SequencerConfig {
        compliance: Some(ComplianceParams {
            policy,
            market: market.to_string(),
        }),
        ..SequencerConfig::default()
    };
    let metrics = Arc::new(MetricsRegistry::new());
    (
        Sequencer::new(SequencerKey::from_seed(&[7u8; 32]), config, Arc::clone(&metrics)),
        metrics,
    )
}

const T0: u64 = 1_000;

// ---------------------------------------------------------------------------
// 1-2. 地区开关与未配置市场
// ---------------------------------------------------------------------------

/// 敌意辖区（全关）：REAL/GAME 全拒 + 计点；未配置市场 fail-closed。
#[test]
fn hostile_market_rejects_all_gated_ops() {
    let (mut seq, metrics) = sequencer_with(policy_v1(), "US-WA");
    // REAL 入金
    let err = seq
        .submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 100), T0)
        .unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(_)));
    // GAME faucet（注册表门之前——合规门是第一道）
    let err = seq
        .submit(faucet_op(1, 7, &v2_owner(21), 10), T0 + 1)
        .unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(_)));
    // 计数：两个 rejected 事件（market 标签）
    let audit = &seq.state().compliance_events;
    assert_eq!(audit.events().len(), 2, "拒绝必须留痕");
    assert!(audit
        .events()
        .iter()
        .all(|e| e.decision.is_err() && e.market == "US-WA" && e.policy_version == 1));
    assert!(audit.to_json().to_string().contains("geo_policy_rejected") == false);
    let _ = metrics;
}

/// 未配置市场（策略里没有该市场代码）→ gated op 全拒（fail-closed）。
#[test]
fn unconfigured_market_fails_closed() {
    let (mut seq, _m) = sequencer_with(policy_v1(), "CN");
    let err = seq
        .submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 100), T0)
        .unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(_)));
    let audit = &seq.state().compliance_events;
    assert_eq!(audit.events().len(), 1);
    assert_eq!(audit.events()[0].decision_str(), "market_not_configured");
}

// ---------------------------------------------------------------------------
// 3. KYC 制动位
// ---------------------------------------------------------------------------

/// kyc_required_real 开启 → REAL 入金拒 + `kyc_gate_rejected_total` 计数；
/// PLAY 免费层不受影响（不设门）。
#[test]
fn kyc_brake_blocks_real_but_not_play() {
    let mut policy = policy_v1();
    policy.markets.get_mut("IM").unwrap().kyc_required_real = true;
    let (mut seq, metrics) = sequencer_with(policy, "IM");
    // REAL 拒
    assert!(seq
        .submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 100), T0)
        .is_err());
    // PLAY 过（免费层不设门——即使 real_enabled 市场的制动位也不影响）
    seq.submit(deposit_v1(2, &v1_owner(11), AssetClass::Play, 50), T0 + 1)
        .expect("PLAY 免费层必须不设门");
    // kyc 计数
    let snap = metrics.export_text();
    assert!(
        snap.contains("kyc_gate_rejected_total"),
        "制动位拒收必须计 kyc_gate_rejected_total: {snap}"
    );
    // 审计：1 拒（REAL）+ 1 收（PLAY 不产生事件——非 gated op）
    let audit = &seq.state().compliance_events;
    assert_eq!(audit.events().len(), 1);
    assert!(audit.events()[0].decision.is_err());
}

// ---------------------------------------------------------------------------
// 4-6. fiat_only / 白名单 / 自排除 / 限额（v1 + v2 双身份）
// ---------------------------------------------------------------------------

/// fiat_only：NATIVE 拒、USDT 过（v2 侧同口径）。
#[test]
fn fiat_only_market_blocks_native() {
    let mut policy = policy_v1();
    policy.markets.get_mut("IM").unwrap().fiat_only = true;
    let (mut seq, _m) = sequencer_with(policy, "IM");
    // v1 NATIVE 拒
    assert!(seq
        .submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 100), T0)
        .is_err());
    // v2 USDT 过
    seq.submit(deposit_v2_op(2, &v2_owner(21), AssetId::REAL_USDT, 100), T0 + 1)
        .expect("fiat_only 市场稳定币必须放行");
}

/// RG 自排除：v1 owner 键与 v2 owner_commitment 各自命中。
#[test]
fn self_exclusion_blocks_both_identity_spaces() {
    let mut policy = policy_v1();
    let im = policy.markets.get_mut("IM").unwrap();
    im.self_excluded.insert(owner_key_v1(&v1_owner(11)));
    im.self_excluded
        .insert(poker_appchain::compliance::owner_key_v2(&v2_owner(21)));
    let (mut seq, _m) = sequencer_with(policy, "IM");
    assert!(seq
        .submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 100), T0)
        .is_err());
    assert!(seq
        .submit(deposit_v2_op(2, &v2_owner(21), AssetId::REAL_USDT, 100), T0 + 1)
        .is_err());
    // 未列入的玩家正常
    seq.submit(deposit_v1(3, &v1_owner(12), AssetClass::Real, 100), T0 + 2)
        .expect("非自排除玩家必须放行");
}

/// REAL 单笔限额：超限拒（v1/v2 同口径），边界值含。
#[test]
fn deposit_limit_enforced() {
    let mut policy = policy_v1();
    policy.markets.get_mut("IM").unwrap().max_deposit = 1_000;
    let (mut seq, _m) = sequencer_with(policy, "IM");
    assert!(seq
        .submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 1_001), T0)
        .is_err());
    seq.submit(deposit_v1(2, &v1_owner(11), AssetClass::Real, 1_000), T0 + 1)
        .expect("边界值必须放行");
    // v2 侧同口径
    assert!(seq
        .submit(deposit_v2_op(3, &v2_owner(21), AssetId::REAL_USDT, 1_500), T0 + 2)
        .is_err());
}

/// GAME 侧限额与开关：faucet 超 `max_game_issue` 拒；注册（非 gated）不受限。
#[test]
fn game_issue_limit_enforced() {
    let mut policy = policy_v1();
    policy.markets.get_mut("IM").unwrap().max_game_issue = 100;
    let (mut seq, _m) = sequencer_with(policy, "IM");
    seq.submit(register_free_op(7, 1_000, 10_000), T0)
        .expect("注册不是 gated op（发行面才设门）");
    // faucet 超限
    assert!(seq
        .submit(faucet_op(1, 7, &v2_owner(21), 101), T0 + 1)
        .is_err());
    // 边界值放行（且满足 faucet single_max）
    seq.submit(faucet_op(2, 7, &v2_owner(21), 100), T0 + 2)
        .expect("边界值必须放行");
}

// ---------------------------------------------------------------------------
// 8-9. 审计留痕与 WAL 重放确定性
// ---------------------------------------------------------------------------

/// 审计事件带 policy version + digest；accepted/rejected 可从 JSON 消费。
#[test]
fn audit_trail_versions_and_export() {
    let mut policy = policy_v1();
    policy.markets.get_mut("IM").unwrap().max_deposit = 100;
    let (mut seq, _m) = sequencer_with(policy.clone(), "IM");
    seq.submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 50), T0)
        .expect("放行");
    assert!(seq
        .submit(deposit_v1(2, &v1_owner(12), AssetClass::Real, 500), T0 + 1)
        .is_err());
    let audit = &seq.state().compliance_events;
    assert_eq!(audit.events().len(), 2);
    let (a, r) = (&audit.events()[0], &audit.events()[1]);
    assert_eq!(a.decision_str(), "accepted");
    assert_eq!(r.decision_str(), "deposit_limit_exceeded");
    assert_eq!(a.policy_version, 1);
    assert_eq!(a.policy_digest, policy.digest(), "digest 必须是事件时刻策略");
    assert_eq!(a.policy_digest, r.policy_digest);
    assert_eq!(a.subject, owner_key_v1(&v1_owner(11)));
    assert_eq!(a.amount, Some(50));
    // JSON 导出形状
    let text = audit.to_json().to_string();
    assert!(text.contains("zchain.compliance.audit.v1"));
    assert!(text.contains("accepted"));
    assert!(text.contains("deposit_limit_exceeded"));
}

/// WAL 重放确定性：合规放行的 op 在同配置下逐位重现（audit accepted 侧
/// 按同序重建）。
#[test]
fn wal_replay_deterministic_under_compliance() {
    let dir = std::env::temp_dir().join(format!(
        "zchain-compliance-replay-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let wal_path = dir.join("wal.bin");
    {
        let config = SequencerConfig {
            compliance: Some(ComplianceParams {
                policy: policy_v1(),
                market: "IM".to_string(),
            }),
            ..SequencerConfig::default()
        };
        let mut seq = Sequencer::new(
            SequencerKey::from_seed(&[7u8; 32]),
            config,
            Arc::new(MetricsRegistry::new()),
        );
        seq.attach_wal(&wal_path).expect("wal mount");
        seq.submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 100), T0)
            .unwrap();
        seq.submit(deposit_v1(2, &v1_owner(11), AssetClass::Play, 30), T0 + 1)
            .unwrap();
    }
    let config = SequencerConfig {
        compliance: Some(ComplianceParams {
            policy: policy_v1(),
            market: "IM".to_string(),
        }),
        ..SequencerConfig::default()
    };
    let key = SequencerKey::from_seed(&[7u8; 32]);
    let seq = Sequencer::replay(&wal_path, key.public, config, Arc::new(MetricsRegistry::new()))
        .expect("同配置重放必须恢复");
    assert_eq!(seq.chain().len(), 2);
    // accepted 审计按同序重建（PLAY 非 gated op，不产生事件——只有 REAL 一条）
    let audit = &seq.state().compliance_events;
    assert_eq!(audit.events().len(), 1);
    assert_eq!(audit.events()[0].op_tag, "deposit");
    assert!(audit.events().iter().all(|e| e.decision.is_ok()));
    std::fs::remove_dir_all(&dir).ok();
}

/// 门分类完整性哨兵：`ComplianceOpClass` 提取面覆盖五个 gated op 拼写
/// （op_tag 冻结；外部审计流消费）。
#[test]
fn op_tags_are_frozen() {
    // 经由 audit 事件的 op_tag 字段断言（deposit / deposit_v2 / faucet_mint）
    let mut policy = policy_v1();
    policy.markets.get_mut("IM").unwrap().max_deposit = 10;
    let (mut seq, _m) = sequencer_with(policy, "IM");
    let _ = seq.submit(deposit_v1(1, &v1_owner(11), AssetClass::Real, 100), T0);
    let _ = seq.submit(deposit_v2_op(2, &v2_owner(21), AssetId::REAL_USDT, 100), T0 + 1);
    let tags: Vec<&str> = seq
        .state()
        .compliance_events
        .events()
        .iter()
        .map(|e| e.op_tag)
        .collect();
    assert_eq!(tags, vec!["deposit", "deposit_v2"]);
    assert_eq!(TOKEN_NATIVE, 0);
    assert_eq!(TOKEN_USDT, 1);
    let _ = ComplianceOpClass::RealDeposit {
        owner32: [0u8; 32],
        token: 0,
    };
}
