//! TE-M3（排期表 §6）：GTS 游戏币标准集成测试——token 注册表 genesis 冻结、
//! Paid 铸造 floor 公式、发行价带（INV-TE-4）、max_supply 上限、单向封闭
//! （INV-TE-3：Issue 唯一入口 / Burn 唯一出口 / REAL 域双向拒）、供给恒等
//! （INV-TE-7：`outstanding = Σminted − Σburned == Σ 存续 GAME note 面额`）。
//!
//! 覆盖（对应交付清单 §5）：
//! 1. 注册冻结 / 重注册拒 / 重定价 = 发新 token；
//! 2. Paid 铸造 floor 公式精确断言（含 1U = 100 万币示例）；
//! 3. 价带上下界拒 + 边界值过（治理参数经 SequencerConfig 注入）；
//! 4. max_supply 超限拒；
//! 5. 幂等（issue_id 族内 + 跨路径 deposit_id 双向互斥）；
//! 6. Burn 闭环 + 双花/幂等拒 + REAL 域拒入；
//! 7. outstanding 恒等 + 日终对账 JSON 导出 + client_view 一致性；
//! 8. REAL 域双向拒（DepositV2 对 GAME 既有断言保持 + 计数）；
//! 9. WAL 重放恢复注册表与 outstanding（全链路）；
//! 10. borsh 判别值冻结（RegisterGameToken=11 / IssueGameToken=12 /
//!     BurnGameToken=13）+ 效果摘要形状。
//!
//! 全部走 release（`cargo test -p poker-appchain --release --test game_token`）。
//!
//! 边界（如实声明，不在此测试）：Free 模式 gas 服务费与时间窗限流（TE-M6）、
//! GAME 桌 / FixedRakeBurn（TE-M4）、链上 anchor 支付通道（部署面）、
//! AIR 层价带公共输入（证明层接线）。

use std::sync::Arc;

use poker_appchain::asset_id::AssetId;
use poker_appchain::client_view::v2_balances_by_asset;
use poker_appchain::error::AppchainError;
use poker_appchain::game_token::{
    paid_mint_amount, validate_rate, FaucetPolicy, GameTokenSpec, IssuanceMode, RateBand,
    RATE_MAX_DEFAULT, RATE_MIN_DEFAULT, RECONCILIATION_FORMAT,
};
use poker_appchain::keys::{blake2s32, OwnerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::AssetClass;
use poker_appchain::note_v2::{default_network_id, spend_scope, NoteV2};
use poker_appchain::ops::{scope, BurnGameTokenOp, DepositV2Op, IssueGameTokenOp, Operation};
use poker_appchain::owner_v2::{
    legacy_account_id, v2_spend_digest, OwnerRef, SignatureEnvelope, SignatureScheme,
    VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};

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
fn new_sequencer() -> Sequencer {
    Sequencer::new(
        poker_appchain::keys::SequencerKey::from_seed(&[42u8; 32]),
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    )
}

/// 带自定义价带的 sequencer（治理参数注入路径）。
fn new_sequencer_with_band(min: u64, max: u64) -> Sequencer {
    Sequencer::new(
        poker_appchain::keys::SequencerKey::from_seed(&[42u8; 32]),
        SequencerConfig {
            game_rate_min: min,
            game_rate_max: max,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    )
}

/// RegisterGameToken op 构造（genesis_digest 由规格定义的同一函数预计算
/// ——客户端与链侧不存在第二种换算）。
fn register_op(token_id: u32, mode: IssuanceMode, max_supply: u64) -> Operation {
    let issuer = [0x02u8; 33];
    let digest =
        GameTokenSpec::genesis_digest_of(token_id, &issuer, &mode, max_supply);
    Operation::RegisterGameToken(Box::new(poker_appchain::ops::RegisterGameTokenOp {
        token_id,
        issuer,
        mode,
        max_supply,
        genesis_digest: digest,
    }))
}

/// 典型 Paid 注册：anchor USDT、R = 1e6（1U = 100 万币）、不限供给。
fn paid_mode_default() -> IssuanceMode {
    IssuanceMode::Paid {
        anchor: AssetId::REAL_USDT,
        rate: 1_000_000,
    }
}

/// IssueGameToken op 构造。
fn issue_op(id_byte: u8, token_id: u32, buyer: &OwnerRef, pay_amount: u64) -> Operation {
    Operation::IssueGameToken(Box::new(IssueGameTokenOp {
        issue_id: id32(id_byte),
        token_id,
        buyer: buyer.clone(),
        pay_amount,
    }))
}

/// DepositV2 op 构造（REAL 域双向拒用例复用）。
fn deposit_op(id_byte: u8, owner: &OwnerRef, asset: AssetId, amount: u64) -> Operation {
    Operation::DepositV2(Box::new(DepositV2Op {
        deposit_id: id32(id_byte),
        owner: owner.clone(),
        asset_id: asset,
        amount,
    }))
}

/// 构造**已签名**的 BurnGameToken op（客户端侧流程：scope → nullifier →
/// effect 摘要 → v2_spend_digest → 信封签名；镜像 WithdrawRequestV2 纪律）。
fn signed_burn(
    user: &V2User,
    note: &NoteV2,
    burn_id_byte: u8,
    nonce: u64,
    network_id: &[u8; 32],
) -> Operation {
    let scope_tag = spend_scope(network_id, OWNER_V2_ABI_VERSION, scope::BURN_GAME);
    let nullifier = note.nullifier(&user.secret, &scope_tag);
    let mut op = BurnGameTokenOp {
        burn_id: id32(burn_id_byte),
        token_id: note.asset_id.token_id,
        note: note.clone(),
        nullifier,
        owner_sig: SignatureEnvelope {
            scheme: SignatureScheme::LegacySecp256k1,
            signer_ref: user.owner.clone(),
            typed_data_digest: [0u8; 32],
            signature: [0u8; 64],
            nonce,
            expiry: EXPIRY,
        },
        material: VerifierMaterial::LegacySecp256k1 {
            presented_public: user.key.public_bytes(),
        },
    };
    let effect = Operation::BurnGameToken(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(
        &note.owner,
        &note.commitment_bytes(),
        &nullifier,
        &scope_tag,
        &effect,
    );
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = user.key.sign(&digest).bytes;
    Operation::BurnGameToken(Box::new(op))
}

/// 构造**已签名**的 WithdrawRequestV2 op（REAL 域双向拒负例用；镜像
/// tests/te_m2.rs 同款构造）。
fn signed_withdraw(
    user: &V2User,
    note: &NoteV2,
    request_id_byte: u8,
    nonce: u64,
    network_id: &[u8; 32],
) -> Operation {
    let scope_tag = spend_scope(network_id, OWNER_V2_ABI_VERSION, scope::WITHDRAW_V2);
    let nullifier = note.nullifier(&user.secret, &scope_tag);
    let mut op = poker_appchain::ops::WithdrawRequestV2Op {
        request_id: id32(request_id_byte),
        owner_sig: SignatureEnvelope {
            scheme: SignatureScheme::LegacySecp256k1,
            signer_ref: user.owner.clone(),
            typed_data_digest: [0u8; 32],
            signature: [0u8; 64],
            nonce,
            expiry: EXPIRY,
        },
        asset_id: note.asset_id,
        gross_amount: note.amount,
        external_recipient: [0xB0; 32],
        created_at_ms: T0,
        note: note.clone(),
        nullifier,
        material: VerifierMaterial::LegacySecp256k1 {
            presented_public: user.key.public_bytes(),
        },
    };
    let effect = Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(
        &note.owner,
        &note.commitment_bytes(),
        &nullifier,
        &scope_tag,
        &effect,
    );
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = user.key.sign(&digest).bytes;
    Operation::WithdrawRequestV2(Box::new(op))
}

/// 某 owner 名下指定资产的 live v2 note（测试辅助：账本扫描）。
fn note_of(seq: &Sequencer, owner: &OwnerRef, asset: AssetId) -> NoteV2 {
    seq.state()
        .note_entries_v2_of(owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.asset_id == asset)
        .unwrap_or_else(|| panic!("no live v2 note for {asset}"))
}

/// 注册 + Paid 铸造的最小闭环（多数用例的前置）。
fn register_and_issue(
    seq: &mut Sequencer,
    token_id: u32,
    buyer: &OwnerRef,
    pay_amount: u64,
) {
    seq.submit(register_op(token_id, paid_mode_default(), 0), T0).unwrap();
    seq.submit(issue_op(token_id as u8, token_id, buyer, pay_amount), T0 + 1)
        .unwrap();
}

// ---------------------------------------------------------------------------
// 1. 注册冻结 / 重注册拒 / 重定价 = 发新 token
// ---------------------------------------------------------------------------

#[test]
fn register_is_frozen_and_reregistration_rejected() {
    let mut seq = new_sequencer();
    seq.submit(register_op(1, paid_mode_default(), 0), T0).unwrap();
    let root = seq.state().root();
    assert_eq!(seq.state().game_registry.len(), 1, "注册表 +1");
    let spec = seq.state().game_registry.get(1).unwrap();
    assert_eq!(spec.rate(), Some(1_000_000), "rate 冻结在 genesis");
    assert_eq!(spec.anchor(), Some(AssetId::REAL_USDT));

    // 同 id 重注册（同载荷）→ 拒（重放防护的注册面）
    let err = seq.submit(register_op(1, paid_mode_default(), 0), T0 + 1).unwrap_err();
    assert!(
        matches!(err, AppchainError::GameRegistryRejected(_)),
        "同 id 重注册必须拒：{err:?}"
    );
    // 同 id 重注册（试图改 rate = 重定价）→ 同样拒
    let repriced = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDT,
        rate: 2_000_000,
    };
    let err = seq.submit(register_op(1, repriced, 0), T0 + 2).unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    assert_eq!(seq.state().root(), root, "全部拒绝零状态变更");
    assert_eq!(seq.chain().len(), 1, "拒绝帧不入链");
    assert_eq!(
        seq.state().game_registry.get(1).unwrap().rate(),
        Some(1_000_000),
        "冻结语义：原规格逐位不变"
    );

    // 重定价 = 发新 token（正例）：token 2 独立注册、独立供给
    let repriced = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDC,
        rate: 2_000_000,
    };
    seq.submit(register_op(2, repriced, 777), T0 + 3).unwrap();
    assert_eq!(seq.state().game_registry.len(), 2);
    assert_eq!(seq.state().game_registry.get(1).unwrap().rate(), Some(1_000_000));
    assert_eq!(seq.state().game_registry.get(2).unwrap().rate(), Some(2_000_000));
}

#[test]
fn register_rejects_reserved_slot_and_bad_payloads() {
    let mut seq = new_sequencer();
    // token 0 = 遗留 PLAY 保留位（不可注册/重定义）
    let err = seq.submit(register_op(0, paid_mode_default(), 0), T0).unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    // Paid anchor 用 GAME 域资产 → 拒（anchor 只能 REAL 域，对称纪律注册面）
    let game_anchor = IssuanceMode::Paid {
        anchor: AssetId::GAME_PLAY,
        rate: 1_000_000,
    };
    let err = seq.submit(register_op(1, game_anchor, 0), T0 + 1).unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    // 零 issuer → 拒
    let issuer = [0u8; 33];
    let digest = GameTokenSpec::genesis_digest_of(1, &issuer, &paid_mode_default(), 0);
    let err = seq
        .submit(
            Operation::RegisterGameToken(Box::new(
                poker_appchain::ops::RegisterGameTokenOp {
                    token_id: 1,
                    issuer,
                    mode: paid_mode_default(),
                    max_supply: 0,
                    genesis_digest: digest,
                },
            )),
            T0 + 2,
        )
        .unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    assert!(seq.chain().is_empty(), "全部拒绝、零帧入链");
}

/// genesis 摘要被篡改（中间人改载荷）→ 链侧重算失配拒。
#[test]
fn genesis_digest_tamper_rejected() {
    let mut seq = new_sequencer();
    let issuer = [0x02u8; 33];
    let mut digest = GameTokenSpec::genesis_digest_of(1, &issuer, &paid_mode_default(), 0);
    digest[0] ^= 0xFF; // 篡改一位
    let err = seq
        .submit(
            Operation::RegisterGameToken(Box::new(
                poker_appchain::ops::RegisterGameTokenOp {
                    token_id: 1,
                    issuer,
                    mode: paid_mode_default(),
                    max_supply: 0,
                    genesis_digest: digest,
                },
            )),
            T0,
        )
        .unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(s) if s.contains("genesis digest mismatch")));
    assert!(seq.state().game_registry.is_empty(), "坏注册不入表");
}

// ---------------------------------------------------------------------------
// 2. 价带（INV-TE-4 validation 层）
// ---------------------------------------------------------------------------

#[test]
fn rate_band_out_of_bounds_rejected_with_metric() {
    let mut seq = new_sequencer();
    // 下界之下：R = 99_999（< R_min = 1e5）
    let below = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDT,
        rate: RATE_MIN_DEFAULT - 1,
    };
    let err = seq.submit(register_op(1, below, 0), T0).unwrap_err();
    assert!(
        matches!(err, AppchainError::RateOutOfBand { rate: 99_999, min: 100_000, max: 10_000_000 }),
        "下界越界必须 RateOutOfBand：{err:?}"
    );
    // 上界之上：R = 10_000_001（> R_max = 1e7）
    let above = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDT,
        rate: RATE_MAX_DEFAULT + 1,
    };
    let err = seq.submit(register_op(2, above, 0), T0 + 1).unwrap_err();
    assert!(matches!(err, AppchainError::RateOutOfBand { rate: 10_000_001, .. }));
    assert_eq!(seq.state().game_registry.len(), 0, "越界注册不入表");
    assert_eq!(seq.chain().len(), 0, "拒绝帧不入链");
}

/// 边界值（闭区间）过 + 纯函数口径一致。
#[test]
fn rate_band_edges_accepted() {
    // 纯函数：边界值含
    let band = RateBand::default();
    validate_rate(RATE_MIN_DEFAULT, &band).unwrap();
    validate_rate(RATE_MAX_DEFAULT, &band).unwrap();
    // 链上：R_min 边界注册 + 铸造
    let mut seq = new_sequencer();
    let min_mode = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDT,
        rate: RATE_MIN_DEFAULT,
    };
    seq.submit(register_op(1, min_mode, 0), T0).unwrap();
    let max_mode = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDC,
        rate: RATE_MAX_DEFAULT,
    };
    seq.submit(register_op(2, max_mode, 0), T0 + 1).unwrap();
    // 自定义治理带：窄带内过、带外拒
    let mut narrow = new_sequencer_with_band(500_000, 2_000_000);
    narrow
        .submit(register_op(
            3,
            IssuanceMode::Paid { anchor: AssetId::REAL_USDT, rate: 1_000_000 },
            0,
        ), T0)
        .unwrap();
    let err = narrow
        .submit(register_op(
            4,
            IssuanceMode::Paid { anchor: AssetId::REAL_USDT, rate: 100_000 },
            0,
        ), T0 + 1)
        .unwrap_err();
    assert!(matches!(err, AppchainError::RateOutOfBand { rate: 100_000, min: 500_000, max: 2_000_000 }));
}

// ---------------------------------------------------------------------------
// 3. Paid 铸造 floor 公式（含 1U = 100 万币示例）
// ---------------------------------------------------------------------------

#[test]
fn paid_issue_floor_formula_exact_on_chain() {
    // 纯函数口径（设计 §3.1 冻结公式）
    assert_eq!(paid_mint_amount(1_000_000, 1_000_000_000_000_000_000), 1_000_000);
    assert_eq!(paid_mint_amount(3, 1_500_000_000_000_000_000), 4, "4.5 → 4 floor");

    // 链上：1U = 100 万币（R = 1e6, anchor USDT）
    let mut seq = new_sequencer();
    let alice = V2User::new(1);
    let game1 = AssetId::game(1);
    register_and_issue(&mut seq, 1, &alice.owner, 1_000_000_000_000_000_000);
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner).get(&game1).copied(),
        Some(1_000_000),
        "1U anchor → 恰好 100 万游戏币"
    );
    // 同 token 第二次发行：2.5U → 250 万（floor 无截断误差）
    seq.submit(issue_op(2, 1, &alice.owner, 2_500_000_000_000_000_000), T0 + 2)
        .unwrap();
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner).get(&game1).copied(),
        Some(3_500_000)
    );
    // 向下取整尾差：pay = 1.000...001e18 → 仍 1_000_000（1 wei 尘埃留在未铸侧）
    seq.submit(issue_op(3, 1, &alice.owner, 1_000_000_000_000_000_001), T0 + 3)
        .unwrap();
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner).get(&game1).copied(),
        Some(4_500_000),
        "1 wei 尘埃不铸出（floor）"
    );
    // 供给聚合与账本一致（INV-TE-7 聚合侧）
    assert_eq!(seq.state().game_outstanding(1), 4_500_000);
    assert!(seq.state().game_reconciliation().all_consistent);
}

/// 尘埃支付（不足 1 币）→ 拒、零状态变更。
#[test]
fn issue_dust_payment_rejected() {
    let mut seq = new_sequencer();
    let alice = V2User::new(2);
    seq.submit(register_op(1, paid_mode_default(), 0), T0).unwrap();
    let root = seq.state().root();
    // pay 999_999 wei（< 1 币 = R 分母份额）→ 0 币 → 拒（无零面额 note）
    let err = seq
        .submit(issue_op(1, 1, &alice.owner, 999_999), T0 + 1)
        .unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("dust")),
        "尘埃支付必须拒：{err:?}"
    );
    assert_eq!(seq.state().root(), root, "拒绝零状态变更");
    assert!(seq.state().note_entries_v2_of(&alice.owner).is_empty());
    assert_eq!(seq.state().game_outstanding(1), 0);
}

// ---------------------------------------------------------------------------
// 4. 幂等（族内 + 跨路径）
// ---------------------------------------------------------------------------

#[test]
fn issue_idempotent_within_family_and_cross_path() {
    let mut seq = new_sequencer();
    let alice = V2User::new(3);
    let game1 = AssetId::game(1);
    register_and_issue(&mut seq, 1, &alice.owner, 1_000_000_000_000_000_000);
    let root = seq.state().root();
    let len = seq.chain().len();

    // 族内：同 issue_id 重放 → 拒（不重复铸）
    let err = seq
        .submit(issue_op(1, 1, &alice.owner, 1_000_000_000_000_000_000), T0 + 2)
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));
    assert_eq!(seq.state().root(), root, "重放零状态变更");
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner).get(&game1).copied(),
        Some(1_000_000),
        "同 issue_id 不重复铸"
    );

    // 跨路径 A：GAME Issue 已用 id → DepositV2 拒（同一支付不得改道 REAL 存款）
    let err = seq
        .submit(deposit_op(1, &alice.owner, AssetId::REAL_USDT, 1), T0 + 3)
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));

    // 跨路径 B：DepositV2 已用 id → GAME Issue 拒
    seq.submit(deposit_op(7, &alice.owner, AssetId::REAL_USDT, 55), T0 + 4)
        .unwrap();
    let err = seq
        .submit(issue_op(7, 1, &alice.owner, 1_000_000_000_000_000_000), T0 + 5)
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));

    // v1 Deposit 的 id 也进跨路径防线
    seq.submit(
        Operation::Deposit {
            deposit_id: id32(9),
            owner: alice.key.public_bytes(),
            asset_class: AssetClass::Play,
            amount: 5,
        },
        T0 + 6,
    )
    .unwrap();
    let err = seq
        .submit(issue_op(9, 1, &alice.owner, 1_000_000_000_000_000_000), T0 + 7)
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));

    // 不同 id 的合法发行照常放行（负例不是过度拒绝）
    seq.submit(issue_op(11, 1, &alice.owner, 1_000_000_000_000_000_000), T0 + 8)
        .unwrap();
    // 正例帧：register、issue(id1)、deposit(id7)、v1 deposit(id9)、issue(id11)
    assert_eq!(seq.chain().len(), len + 3, "3 正例帧入链");
}

// ---------------------------------------------------------------------------
// 5. 未注册 token / 遗留 PLAY 拒入发行
// ---------------------------------------------------------------------------

#[test]
fn issue_rejects_unregistered_and_play_slot() {
    let mut seq = new_sequencer();
    let alice = V2User::new(4);
    // 未注册 token
    let err = seq
        .submit(issue_op(1, 42, &alice.owner, 1_000_000_000_000_000_000), T0)
        .unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    // 遗留 PLAY(0)：即便结构上"GAME 域已注册"（is_registered_token_in 对
    // 0 为 true），GTS 发行入口仍拒（无规格、无 anchor、无供给记账）
    let err = seq
        .submit(issue_op(2, 0, &alice.owner, 1_000), T0 + 1)
        .unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    // 注册后同 token 放行（负例不是过度拒绝）
    register_and_issue(&mut seq, 42, &alice.owner, 1_000_000_000_000_000_000);
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner)
            .get(&AssetId::game(42))
            .copied(),
        Some(1_000_000)
    );
}

// ---------------------------------------------------------------------------
// 6. max_supply 上限
// ---------------------------------------------------------------------------

#[test]
fn max_supply_cap_enforced() {
    let mut seq = new_sequencer();
    let alice = V2User::new(5);
    // R = 1e6、cap = 2_500_000（= 2.5U 等值币量）
    seq.submit(register_op(1, paid_mode_default(), 2_500_000), T0).unwrap();
    // 恰好打满 cap：2.5U → 2_500_000 币（== cap，放行）
    seq.submit(issue_op(1, 1, &alice.owner, 2_500_000_000_000_000_000), T0 + 1)
        .unwrap();
    assert_eq!(seq.state().game_outstanding(1), 2_500_000);
    // 再铸 1U → 超限拒
    let err = seq
        .submit(issue_op(2, 1, &alice.owner, 1_000_000_000_000_000_000), T0 + 2)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::SupplyCapExceeded {
                token_id: 1,
                minted: 2_500_000,
                requested: 1_000_000,
                cap: 2_500_000
            }
        ),
        "超限必须 SupplyCapExceeded：{err:?}"
    );
    // 再铸最小非尘单位（0.001U → 1_000 币）也拒（无部分铸造——超限即全拒）
    let err = seq
        .submit(issue_op(3, 1, &alice.owner, 1_000_000_000_000_000), T0 + 3)
        .unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::SupplyCapExceeded {
                token_id: 1,
                minted: 2_500_000,
                requested: 1_000,
                cap: 2_500_000
            }
        ),
        "超限必须 SupplyCapExceeded（无部分铸造）：{err:?}"
    );
    assert_eq!(seq.state().game_outstanding(1), 2_500_000, "超限部分一律未铸");
    // cap = 0 = 不限（对照）
    seq.submit(register_op(2, paid_mode_default(), 0), T0 + 4).unwrap();
    for i in 0..3u8 {
        seq.submit(issue_op(20 + i, 2, &alice.owner, 1_000_000_000_000_000_000), T0 + 5 + u64::from(i))
            .unwrap();
    }
    assert_eq!(seq.state().game_outstanding(2), 3_000_000);
}

// ---------------------------------------------------------------------------
// 7. Burn 闭环（唯一出口）+ 负例
// ---------------------------------------------------------------------------

#[test]
fn burn_closed_loop_and_replays_rejected() {
    let mut seq = new_sequencer();
    let alice = V2User::new(6);
    let game1 = AssetId::game(1);
    register_and_issue(&mut seq, 1, &alice.owner, 1_000_000_000_000_000_000);
    let note = note_of(&seq, &alice.owner, game1);

    // 销毁整张 note
    seq.submit(signed_burn(&alice, &note, 5, 5, &default_network_id()), T0 + 10)
        .unwrap();
    assert!(
        seq.state().note_entries_v2_of(&alice.owner).is_empty(),
        "销毁后无存续 note"
    );
    assert_eq!(seq.state().game_outstanding(1), 0, "outstanding 归零");
    assert_eq!(seq.state().game_burned.get(&1).copied(), Some(1_000_000));
    assert!(seq.state().game_reconciliation().all_consistent);

    let root = seq.state().root();
    // 双花：同 note（nullifier 已消费）换 burn_id → DoubleSpend
    let err = seq
        .submit(signed_burn(&alice, &note, 6, 6, &default_network_id()), T0 + 11)
        .unwrap_err();
    assert!(matches!(err, AppchainError::DoubleSpend | AppchainError::NoteNotFound));
    // 幂等：同 burn_id（新 nonce、但 note 已不存在/nullifier 已消费）
    // ——防线次序不承诺具体错误类别，只承诺拒绝且零状态变更
    assert_eq!(seq.state().root(), root, "全部拒绝零状态变更");
    assert_eq!(seq.chain().len(), 3, "拒绝帧不入链（注册/发行/销毁三帧）");
}

#[test]
fn burn_rejects_real_domain_notes() {
    let mut seq = new_sequencer();
    let alice = V2User::new(7);
    // REAL 域 note（DepositV2 合法路径）
    seq.submit(deposit_op(1, &alice.owner, AssetId::REAL_USDT, 500), T0)
        .unwrap();
    let usdt_note = note_of(&seq, &alice.owner, AssetId::REAL_USDT);
    let rejected = signed_burn(&alice, &usdt_note, 5, 5, &default_network_id());
    let err = seq.submit(rejected, T0 + 1).unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("GAME domain")),
        "REAL 域拒入 Burn（对称纪律）：{err:?}"
    );
    // note 仍在、REAL 余额不变
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner)
            .get(&AssetId::REAL_USDT)
            .copied(),
        Some(500)
    );
}

#[test]
fn burn_rejects_token_mismatch_and_play_slot() {
    let mut seq = new_sequencer();
    let alice = V2User::new(8);
    register_and_issue(&mut seq, 1, &alice.owner, 1_000_000_000_000_000_000);
    let note = note_of(&seq, &alice.owner, AssetId::game(1));

    // token_id 声明与 note 资产不一致 → 拒
    let mut op = match signed_burn(&alice, &note, 5, 5, &default_network_id()) {
        Operation::BurnGameToken(b) => *b,
        _ => unreachable!(),
    };
    op.token_id = 2; // 声明换 token（未注册）
    let op = Operation::BurnGameToken(Box::new(op));
    let err = seq.submit(op, T0 + 1).unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));

    // 遗留 PLAY note（MigrateNote 合法产物）→ 无 GTS 规格，拒入 Burn
    seq.submit(
        Operation::Deposit {
            deposit_id: id32(3),
            owner: alice.key.public_bytes(),
            asset_class: AssetClass::Play,
            amount: 70,
        },
        T0 + 2,
    )
    .unwrap();
    let v1_note = seq
        .state()
        .notes_of(&alice.key.public_bytes())
        .into_iter()
        .next()
        .unwrap();
    let mut record = poker_appchain::owner_v2::MigrateNoteRecord {
        old_commitment: v1_note.commitment_bytes(),
        old_owner_sig: SignatureEnvelope {
            scheme: SignatureScheme::LegacySecp256k1,
            signer_ref: alice.owner.clone(),
            typed_data_digest: [0u8; 32],
            signature: [0u8; 64],
            nonce: 1,
            expiry: EXPIRY,
        },
        new_owner_ref: alice.owner.clone(),
        amount: 70,
        asset_class: AssetClass::Play,
        migration_nonce: blake2s32(&[b"te-m3 play migration"]),
        network_id: default_network_id(),
        abi_version: OWNER_V2_ABI_VERSION,
    };
    let digest = poker_appchain::owner_v2::migrate_digest(&record);
    record.old_owner_sig.typed_data_digest = digest;
    record.old_owner_sig.signature = alice.key.sign(&digest).bytes;
    let minted = NoteV2::new(AssetId::GAME_PLAY, 70, alice.owner.clone(), 777, None, 0, 0).unwrap();
    seq.submit_migrate(
        Operation::MigrateNote(Box::new(poker_appchain::ops::MigrateNoteOp {
            record,
            minted,
        })),
        &VerifierMaterial::LegacySecp256k1 {
            presented_public: alice.key.public_bytes(),
        },
        T0 + 3,
    )
    .unwrap();
    let play_note = note_of(&seq, &alice.owner, AssetId::GAME_PLAY);
    let err = seq
        .submit(signed_burn(&alice, &play_note, 7, 7, &default_network_id()), T0 + 4)
        .unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)), "PLAY(0) 无 GTS 规格调入 Burn：{err:?}");
    // PLAY note 不受影响
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner)
            .get(&AssetId::GAME_PLAY)
            .copied(),
        Some(70)
    );
}

// ---------------------------------------------------------------------------
// 8. REAL 域双向拒（既有断言保持 + 计数）
// ---------------------------------------------------------------------------

#[test]
fn real_domain_two_way_rejection_preserved() {
    let metrics = Arc::new(MetricsRegistry::new());
    let mut seq = Sequencer::new(
        poker_appchain::keys::SequencerKey::from_seed(&[42u8; 32]),
        SequencerConfig::default(),
        Arc::clone(&metrics),
    );
    let alice = V2User::new(9);
    // 注册 GAME token 1（重点：已注册也不改变 REAL 通道的 GAME 拒入）
    seq.submit(register_op(1, paid_mode_default(), 0), T0).unwrap();

    // 方向 A：DepositV2 × GAME（已注册 token）→ 拒（TE-M2 断言保持）
    let err = seq
        .submit(deposit_op(1, &alice.owner, AssetId::game(1), 100), T0 + 1)
        .unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(_)));
    assert!(seq.state().note_entries_v2_of(&alice.owner).is_empty());

    // 正常发行拿一张 GAME note
    seq.submit(issue_op(2, 1, &alice.owner, 1_000_000_000_000_000_000), T0 + 2)
        .unwrap();
    let game_note = note_of(&seq, &alice.owner, AssetId::game(1));

    // 方向 B：WithdrawRequestV2 × GAME note → 拒（TE-M2 断言保持）+
    // game_withdraw_rejected_total 计数（设计 §6：出现非零即审计信号）
    let op = signed_withdraw(&alice, &game_note, 3, 5, &default_network_id());
    let err = seq.submit(op, T0 + 3).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(_)));
    // GAME note 完好（提现路径未消耗它）
    assert_eq!(seq.state().note_entries_v2_of(&alice.owner).len(), 1);

    // 计数面：GAME 域拒入（deposit 1 次 + withdraw 1 次）
    assert_eq!(metrics.counter("game_token_rejected_total"), 2);
    assert_eq!(metrics.counter("game_withdraw_rejected_total"), 1);
}

// ---------------------------------------------------------------------------
// 9. Free 模式骨架（注册 + faucet 限量；gas 服务费 TE-M6）
// ---------------------------------------------------------------------------

#[test]
fn free_mode_faucet_skeleton_limits() {
    let mut seq = new_sequencer();
    let alice = V2User::new(10);
    // Free 注册：价带不适用（无 rate）——即便价带之外的数值也不涉 band
    let free = IssuanceMode::Free {
        faucet: FaucetPolicy {
            single_max: 100,
            player_lifetime_max: 250,
        },
    };
    seq.submit(register_op(1, free, 0), T0).unwrap();
    let spec = seq.state().game_registry.get(1).unwrap().clone();
    assert!(!spec.is_paid() && spec.rate().is_none() && spec.anchor().is_none());

    let game1 = AssetId::game(1);
    // 单次 ≤ single_max：100 币直铸（无 anchor 换算）
    seq.submit(issue_op(1, 1, &alice.owner, 100), T0 + 1).unwrap();
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner).get(&game1).copied(),
        Some(100)
    );
    // 单次超限 → RateLimited
    let err = seq.submit(issue_op(2, 1, &alice.owner, 101), T0 + 2).unwrap_err();
    assert!(matches!(err, AppchainError::RateLimited(_)));
    // 终身累计：100 + 100 = 200 ok；+50 = 250 == max ok；+1 拒
    seq.submit(issue_op(3, 1, &alice.owner, 100), T0 + 3).unwrap();
    seq.submit(issue_op(4, 1, &alice.owner, 50), T0 + 4).unwrap();
    assert_eq!(seq.state().game_outstanding(1), 250);
    let err = seq.submit(issue_op(5, 1, &alice.owner, 1), T0 + 5).unwrap_err();
    assert!(matches!(err, AppchainError::RateLimited(_)));
    // 终身记账按 owner 隔离：bob 有自己的额度
    let bob = V2User::new(11);
    seq.submit(issue_op(6, 1, &bob.owner, 100), T0 + 6).unwrap();
    assert_eq!(
        v2_balances_by_asset(seq.state(), &bob.owner).get(&game1).copied(),
        Some(100)
    );
    // Free 铸造不进 Paid 换算：mint_for 恒 0（纯函数口径）
    assert_eq!(spec.mint_for(1_000_000_000_000_000_000), 0);
    assert!(seq.state().game_reconciliation().all_consistent);
}

// ---------------------------------------------------------------------------
// 10. 供给恒等（INV-TE-7）+ 日终对账导出 + client_view 一致性
// ---------------------------------------------------------------------------

#[test]
fn supply_identity_outstanding_and_reconciliation() {
    let mut seq = new_sequencer();
    let alice = V2User::new(12);
    let bob = V2User::new(13);

    // 双 token：token 1（R=1e6）与 token 2（R=1e5），独立供给
    register_and_issue(&mut seq, 1, &alice.owner, 2_000_000_000_000_000_000);
    seq.submit(register_op(
        2,
        IssuanceMode::Paid { anchor: AssetId::REAL_USDC, rate: RATE_MIN_DEFAULT },
        0,
    ), T0 + 2)
    .unwrap();
    seq.submit(issue_op(3, 2, &alice.owner, 3_000_000_000_000_000_000), T0 + 3)
        .unwrap();
    seq.submit(issue_op(4, 1, &bob.owner, 500_000_000_000_000_000), T0 + 4)
        .unwrap();

    // bob 转 1/3 币给 alice 走 Transfer 是 TE-M4 桌外语义——这里直接用
    // Burn 抽减供给（rake 回收与主动销毁同通道）
    let bob_note = note_of(&seq, &bob.owner, AssetId::game(1));
    seq.submit(signed_burn(&bob, &bob_note, 5, 5, &default_network_id()), T0 + 5)
        .unwrap();

    // 恒等式：outstanding = Σminted − Σburned == Σ 存续 note 面额
    let rec = seq.state().game_reconciliation();
    assert!(rec.all_consistent, "日终对账全绿：{rec:?}");
    assert_eq!(rec.tokens.len(), 2, "双 token 各一行（升序）");
    let t1 = rec.tokens.iter().find(|t| t.token_id == 1).unwrap();
    let t2 = rec.tokens.iter().find(|t| t.token_id == 2).unwrap();
    // token 1: minted = 2_000_000 + 500_000；burned = 500_000；live = 2_000_000
    assert_eq!(t1.minted_total, 2_500_000);
    assert_eq!(t1.burned_total, 500_000);
    assert_eq!(t1.outstanding, 2_000_000);
    assert_eq!(t1.live_note_sum, 2_000_000);
    assert_eq!(seq.state().game_outstanding(1), 2_000_000);
    // token 2: 只铸不烧
    assert_eq!(t2.minted_total, 300_000);
    assert_eq!(t2.burned_total, 0);
    assert_eq!(t2.outstanding, t2.live_note_sum);
    assert_eq!(seq.state().game_outstanding(2), 300_000);
    // client_view 域分栏与供给恒等交叉核对（GAME 域合计 = 两 token live 和）
    let alice_view = v2_balances_by_asset(seq.state(), &alice.owner);
    assert_eq!(alice_view.get(&AssetId::game(1)).copied(), Some(2_000_000));
    assert_eq!(alice_view.get(&AssetId::game(2)).copied(), Some(300_000));
    let (_, game_total) = seq.state().balances_v2_of(&alice.owner);
    assert_eq!(game_total, t1.live_note_sum + t2.live_note_sum);
}

/// 日终对账 JSON 导出：结构冻结、可被 explorer 直接消费。
#[test]
fn reconciliation_json_export_shape() {
    let mut seq = new_sequencer();
    let alice = V2User::new(14);
    register_and_issue(&mut seq, 1, &alice.owner, 1_000_000_000_000_000_000);
    let note = note_of(&seq, &alice.owner, AssetId::game(1));
    seq.submit(signed_burn(&alice, &note, 5, 5, &default_network_id()), T0 + 2)
        .unwrap();

    let v = seq.state().game_reconciliation_json();
    assert_eq!(v["format"], RECONCILIATION_FORMAT, "格式标签冻结");
    assert_eq!(v["all_consistent"], true);
    let tokens = v["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["token_id"], 1);
    assert_eq!(tokens[0]["minted_total"], "1000000", "u128 十进制字符串");
    assert_eq!(tokens[0]["burned_total"], "1000000");
    assert_eq!(tokens[0]["outstanding"], "0");
    assert_eq!(tokens[0]["live_note_sum"], "0");
    assert_eq!(tokens[0]["consistent"], true);
    // 可再次反序列化（serde_json roundtrip）
    let text = v.to_string();
    let back: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(back, v);
    // 日终对账导出样例（explorer/运营月报消费形态）
    println!("[TE-M3 日终对账导出样例] {text}");
}

// ---------------------------------------------------------------------------
// 11. WAL 全链路：重放恢复注册表与 outstanding
// ---------------------------------------------------------------------------

#[test]
fn wal_roundtrip_restores_registry_and_outstanding() {
    let dir = std::env::temp_dir().join("poker-appchain-te-m3");
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("te_m3_game.wal");
    let _ = std::fs::remove_file(&wal);
    let key = poker_appchain::keys::SequencerKey::from_seed(&[46u8; 32]);
    let mut seq = Sequencer::new(key.clone(), SequencerConfig::default(), Arc::new(MetricsRegistry::new()));
    seq.attach_wal(&wal).unwrap();

    let alice = V2User::new(15);
    register_and_issue(&mut seq, 1, &alice.owner, 1_500_000_000_000_000_000);
    let note = note_of(&seq, &alice.owner, AssetId::game(1));
    seq.submit(signed_burn(&alice, &note, 5, 5, &default_network_id()), T0 + 2)
        .unwrap();
    let root_before = seq.state().root();
    let registry_before = seq.state().game_registry.clone();
    let outstanding_before = seq.state().game_outstanding(1);
    drop(seq);

    // 全量重放：链签名 + 每帧状态根重验（fail-closed）
    let mut seq2 = Sequencer::replay(&wal, key.public, SequencerConfig::default(), Arc::new(MetricsRegistry::new()))
        .unwrap();
    assert_eq!(seq2.state().root(), root_before, "重放逐位重现状态根");
    assert_eq!(seq2.state().game_registry, registry_before, "注册表恢复（冻结规格逐位一致）");
    assert_eq!(seq2.state().game_outstanding(1), outstanding_before, "outstanding 恢复");
    assert_eq!(
        seq2.state().game_minted.get(&1).copied(),
        Some(1_500_000),
        "Σminted 聚合恢复"
    );
    assert!(seq2.state().game_reconciliation().all_consistent);
    // 幂等集恢复的行为证据：同 issue_id 再发行 → 拒
    let err = seq2
        .submit(issue_op(1, 1, &alice.owner, 1_500_000_000_000_000_000), T0 + 3)
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));
    // 重注册同 token（注册表冻结语义随重放保持）→ 拒
    let err = seq2.submit(register_op(1, paid_mode_default(), 0), T0 + 4).unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    assert_eq!(seq2.chain().len(), 3, "拒绝帧不入链");
}

// ---------------------------------------------------------------------------
// 12. borsh 判别值冻结 + op 形状
// ---------------------------------------------------------------------------

#[test]
fn borsh_discriminants_frozen_and_op_shape() {
    let alice = V2User::new(16);
    let note = NoteV2::new(AssetId::game(1), 100, alice.owner.clone(), 1, None, 0, 0).unwrap();
    let burn = Operation::BurnGameToken(Box::new(BurnGameTokenOp {
        burn_id: id32(1),
        token_id: 1,
        note,
        nullifier: id32(2),
        owner_sig: SignatureEnvelope {
            scheme: SignatureScheme::LegacySecp256k1,
            signer_ref: alice.owner.clone(),
            typed_data_digest: [0u8; 32],
            signature: [0u8; 64],
            nonce: 1,
            expiry: EXPIRY,
        },
        material: VerifierMaterial::LegacySecp256k1 {
            presented_public: alice.key.public_bytes(),
        },
    }));
    let issue = issue_op(3, 1, &alice.owner, 1_000);
    let reg = register_op(1, paid_mode_default(), 0);

    // 判别值 = 声明序（首字节）：11 / 12 / 13（冻结；TE-M6 从 14 起排）
    assert_eq!(borsh::to_vec(&reg).unwrap()[0], 11, "RegisterGameToken 判别值冻结");
    assert_eq!(borsh::to_vec(&issue).unwrap()[0], 12, "IssueGameToken 判别值冻结");
    assert_eq!(borsh::to_vec(&burn).unwrap()[0], 13, "BurnGameToken 判别值冻结");
    // v1/v2 既有判别值不受追加影响
    let v1_dep = Operation::Deposit {
        deposit_id: [1; 32],
        owner: alice.key.public_bytes(),
        asset_class: AssetClass::Real,
        amount: 1,
    };
    assert_eq!(borsh::to_vec(&v1_dep).unwrap()[0], 2);
    let v2_dep = deposit_op(4, &alice.owner, AssetId::REAL_USDT, 1);
    assert_eq!(borsh::to_vec(&v2_dep).unwrap()[0], 9);
    // roundtrip
    let back: Operation = borsh::from_slice(&borsh::to_vec(&burn).unwrap()).unwrap();
    assert_eq!(back, burn);

    // 授权形状：三变体 spends() 均空（Register/Issue 是 operator 帧；
    // Burn 授权走 SignatureEnvelope）
    assert!(Operation::spends(&reg).is_empty());
    assert!(Operation::spends(&issue).is_empty());
    assert!(Operation::spends(&burn).is_empty());
    // Register/Issue 效果摘要 = 零（operator 帧，同 Deposit 纪律）
    assert_eq!(Operation::effect_digest(&reg), [0u8; 32]);
    assert_eq!(Operation::effect_digest(&issue), [0u8; 32]);
    // Burn 效果摘要绑定全部语义载荷（非零、确定、篡改敏感）
    let e = Operation::effect_digest(&burn);
    assert_ne!(e, [0u8; 32]);
    let mut tampered = match &burn {
        Operation::BurnGameToken(b) => (**b).clone(),
        _ => unreachable!(),
    };
    tampered.burn_id = id32(9);
    assert_ne!(
        Operation::effect_digest(&Operation::BurnGameToken(Box::new(tampered))),
        e,
        "burn_id 进效果摘要（S1 纪律）"
    );
}

// ---------------------------------------------------------------------------
// 13. metrics 观测面（发行/注册/销毁计数与 outstanding gauge）
// ---------------------------------------------------------------------------

#[test]
fn issuance_metrics_and_outstanding_gauge() {
    let metrics = Arc::new(MetricsRegistry::new());
    let mut seq = Sequencer::new(
        poker_appchain::keys::SequencerKey::from_seed(&[47u8; 32]),
        SequencerConfig::default(),
        Arc::clone(&metrics),
    );
    let alice = V2User::new(17);
    seq.submit(register_op(1, paid_mode_default(), 0), T0).unwrap();
    seq.submit(issue_op(1, 1, &alice.owner, 2_000_000_000_000_000_000), T0 + 1)
        .unwrap();
    seq.submit(issue_op(2, 1, &alice.owner, 1_000_000_000_000_000_000), T0 + 2)
        .unwrap();
    // 确定性取面额 1_000_000 的那张 note（账本 owner 索引是 HashSet，
    // 迭代序不确定——按面额选择消除烧毁对象歧义）
    let note = seq
        .state()
        .note_entries_v2_of(&alice.owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.amount == 1_000_000)
        .unwrap();
    seq.submit(signed_burn(&alice, &note, 5, 5, &default_network_id()), T0 + 3)
        .unwrap();

    assert_eq!(metrics.counter("game_token_registered_total"), 1);
    assert_eq!(metrics.counter("game_token_minted_total"), 2, "两次发行");
    assert_eq!(metrics.counter("game_token_minted_amount_total"), 3_000_000);
    assert_eq!(metrics.counter("ops_game_register_total"), 1);
    assert_eq!(metrics.counter("ops_game_issue_total"), 2);
    assert_eq!(metrics.counter("ops_game_burn_total"), 1);
    // outstanding gauge：随最后一次变更刷新为终值
    assert_eq!(
        metrics.gauge("game_token_outstanding{token=\"1\"}"),
        2_000_000,
        "gauge = 终态 outstanding"
    );
    // 价带拒绝计数（负例补一脚）
    let above = IssuanceMode::Paid { anchor: AssetId::REAL_USDT, rate: RATE_MAX_DEFAULT + 1 };
    let _ = seq.submit(register_op(2, above, 0), T0 + 4).unwrap_err();
    assert_eq!(metrics.counter("issuance_rate_rejected_total"), 1);
}
