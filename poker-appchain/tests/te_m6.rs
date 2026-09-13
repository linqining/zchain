//! TE-M6（排期表 §6）：Free 模式 gas 服务费——faucet 限量领取 + gas credit
//! 预付额度计量账 + Free 桌 GasPolicy 绑定 + 结算准入收费。
//!
//! 设计依据 `docs/plan-token-economy-v1.md` §3.8；判别值 14/15/16（TE-M3
//! 预留位落地）。覆盖（对应交付清单）：
//!
//! 1. **faucet 限量**：`FaucetMint` 单次上限 / 玩家终身上限 / claim_id
//!    幂等 / Paid token 与遗留 PLAY 拒 / max_supply / owner 隔离；
//! 2. **gas credit**：`BuyGasCredits` 1:1 入账、pay_digest 幂等（op 族 +
//!    跨路径前向查重）、INV-TE-8 消耗前置校验（不足拒、零状态变更）、
//!    额度按 (owner, 计价 asset) 隔离；
//! 3. **INV-TE-9**：Free 桌未绑 GasPolicy（或绑定 token 不匹配）→ 本手
//!    受理拒绝；绑 policy 后正常扣费（固定费额，与底池无关）；
//! 4. **TE-D7**：Paid 桌绑定拒；Paid token 桌结算不受影响（零 gas 扣减）；
//! 5. **成本覆盖**：绑定时刻 `fee_per_hand ≥ min_coverage_k · c_hand`
//!    （k ≥ 3 冻结下限；c_hand 为配置注入的运营参数——如实标注）；
//! 6. **重放恢复**：WAL 重放逐位恢复 credit 账本 / gas 绑定 / faucet 幂等集；
//! 7. **托管隔离**：credit 活动不污染 CustodyLedger 对账恒等式输入
//!    （`issued_v2_real_by_token` / `burned_v2` / REAL 存续 note 面额
//!    逐位不变——收入非储备的物理隔离证据）。
//!
//! 全部走 release（`cargo test -p poker-appchain --release --test te_m6`）。
//!
//! 边界（如实声明）：
//! - INV-TE-9 的"首次买入拒绝"强制点落在 SettleV2 受理——v2 seat 生命
//!   周期（BuyInV2）未引入（TE-M4 同款边界），Free token 进入桌生命
//!   周期的首个受理点即结算；BuyInV2 落地时必须镜像本门；
//! - 时间窗限流（每玩家单位时间上限）v1 不做，限量 = single_max +
//!   player_lifetime_max 双上限（弱于设计 §3.8.3 最终口径）；
//! - gas 服务费的 FeeSplit 分账（设计 §3.8.2）v1 不做——credit 消耗只
//!   进计量账，收入分账属运营审计层；
//! - 真实 c_hand 计量属部署面；每手费用/计价币种的 UI 呈现属 TE-M5 面。

use std::sync::Arc;

use poker_appchain::asset_id::AssetId;
use poker_appchain::error::AppchainError;
use poker_appchain::fee::FeePolicy;
use poker_appchain::game_token::{FaucetPolicy, GameTokenSpec, GasPolicy, IssuanceMode};
use poker_appchain::keys::{OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note_v2::{
    default_network_id, settle_effect_v2, settle_scope_v2, NoteSpec2, NoteV2, SettleInputV2,
    SettlementRecordV2,
};
use poker_appchain::ops::{
    BindGasPolicyOp, BuyGasCreditsOp, FaucetMintOp, IssueGameTokenOp, Operation,
    RegisterGameTokenOp,
};
use poker_appchain::owner_v2::{
    legacy_account_id, v2_spend_digest, OwnerRef, SignatureEnvelope, SignatureScheme,
    VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use poker_appchain::sequencer::{LedgerState, Sequencer, SequencerConfig};
use poker_appchain::settlement::RakeSplitRecord;

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

/// 新 sequencer（内存模式；可注入 c_hand 运营参数）。
fn new_sequencer_with(c_hand: u64) -> (Sequencer, Arc<MetricsRegistry>) {
    let metrics = Arc::new(MetricsRegistry::new());
    let config = SequencerConfig {
        gas_c_hand_estimate: c_hand,
        ..SequencerConfig::default()
    };
    let seq = Sequencer::new(SequencerKey::from_seed(&[42u8; 32]), config, Arc::clone(&metrics));
    (seq, metrics)
}

fn new_sequencer() -> (Sequencer, Arc<MetricsRegistry>) {
    new_sequencer_with(0)
}

/// RegisterGameToken op（Free 模式：faucet 限量参数）。
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

/// RegisterGameToken op（Paid 模式：anchor USDT、R = 1e6；可带 max_supply）。
fn register_paid_op(token_id: u32, max_supply: u64) -> Operation {
    let issuer = [0x02u8; 33];
    let mode = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDT,
        rate: 1_000_000,
    };
    let digest = GameTokenSpec::genesis_digest_of(token_id, &issuer, &mode, max_supply);
    Operation::RegisterGameToken(Box::new(RegisterGameTokenOp {
        token_id,
        issuer,
        mode,
        max_supply,
        genesis_digest: digest,
    }))
}

/// FaucetMint op（判别值 14）。
fn faucet_op(claim_byte: u8, token_id: u32, owner: &OwnerRef, amount: u64) -> Operation {
    Operation::FaucetMint(Box::new(FaucetMintOp {
        claim_id: id32(claim_byte),
        token_id,
        owner: owner.clone(),
        amount,
    }))
}

/// BuyGasCredits op（判别值 15）。
fn buy_credits_op(
    digest_byte: u8,
    payer: &OwnerRef,
    asset: AssetId,
    amount: u64,
) -> Operation {
    Operation::BuyGasCredits(Box::new(BuyGasCreditsOp {
        pay_digest: id32(digest_byte),
        payer: payer.clone(),
        pricing_asset_id: asset,
        pay_amount: amount,
    }))
}

/// BindGasPolicy op（判别值 16）。
fn bind_op(table_id: u64, token_id: u32, policy: GasPolicy) -> Operation {
    Operation::BindGasPolicy(Box::new(BindGasPolicyOp {
        table_id,
        token_id,
        policy,
    }))
}

/// 测试用 GasPolicy（USDT 计价、费额 fee、k = 3）。
fn gas_policy(fee: u64) -> GasPolicy {
    GasPolicy::new(fee, AssetId::REAL_USDT, 3).unwrap()
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

/// 构造**已签名**的 SettleV2 op（镜像 tests/te_m4.rs 纪律：scope →
/// nullifier → effect 摘要 → v2_spend_digest → 信封签名；赢家 = 首输入
/// owner 独赢拿全部净额）。`base_nonce` 是全部信封的 per-signer nonce
/// （严格单调——同一用户跨手必须递增）。
fn signed_settle_v2(
    table_id: u64,
    hand_binding_byte: u8,
    base_nonce: u64,
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
                    nonce: base_nonce,
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

/// DepositV2 op（REAL 域存款——托管隔离断言的非平凡基线）。
fn deposit_v2_op(id_byte: u8, owner: &OwnerRef, asset: AssetId, amount: u64) -> Operation {
    Operation::DepositV2(Box::new(poker_appchain::ops::DepositV2Op {
        deposit_id: id32(id_byte),
        owner: owner.clone(),
        asset_id: asset,
        amount,
    }))
}

/// credit 余额视图（测试可读性）。
fn credit_of(seq: &Sequencer, owner: &OwnerRef, asset: AssetId) -> u64 {
    seq.state()
        .gas_credit_ledger()
        .balance_of(&poker_appchain::owner_v2::owner_commitment(owner), asset)
}

/// CustodyLedger 对账恒等式输入快照（appchain 侧权威口径）：
/// REAL 域各 token issued（live + burned 毛额）与已销毁记录。
fn custody_snapshot(state: &LedgerState) -> (std::collections::BTreeMap<AssetId, u128>, usize) {
    (state.issued_v2_real_by_token(), state.burned_v2.len())
}

/// REAL 域存续 note 面额合计（issued 的 live 侧）。
fn real_live_sum(state: &LedgerState) -> u128 {
    state
        .notes_v2
        .values()
        .filter(|e| e.note.asset_id.is_real_domain())
        .map(|e| u128::from(e.note.amount))
        .sum()
}

// ---------------------------------------------------------------------------
// 1. 判别值冻结（borsh 首字节 14/15/16；TE-M3 判别值 11/12/13 不受影响）
// ---------------------------------------------------------------------------

#[test]
fn ops_discriminants_frozen_te_m6() {
    let faucet = faucet_op(1, 1, &V2User::new(1).owner, 10);
    let credits = buy_credits_op(1, &V2User::new(1).owner, AssetId::REAL_USDT, 100);
    let bind = bind_op(1, 1, gas_policy(10));
    // TE-M6 判别值 = 声明序（14/15/16，TE-M3 预留位落地）
    assert_eq!(borsh::to_vec(&faucet).unwrap()[0], 14, "FaucetMint 判别值冻结");
    assert_eq!(borsh::to_vec(&credits).unwrap()[0], 15, "BuyGasCredits 判别值冻结");
    assert_eq!(borsh::to_vec(&bind).unwrap()[0], 16, "BindGasPolicy 判别值冻结");
    // 既有判别值不受追加影响（抽查：Settle=6 / BurnGameToken=13）
    let burn = {
        use poker_appchain::ops::BurnGameTokenOp;
        use poker_appchain::owner_v2::{SignatureEnvelope, SignatureScheme, VerifierMaterial};
        let u = V2User::new(2);
        let note = NoteV2::new(AssetId::game(1), 1, u.owner.clone(), 1, None, 0, 0).unwrap();
        Operation::BurnGameToken(Box::new(BurnGameTokenOp {
            burn_id: id32(1),
            token_id: 1,
            note: note.clone(),
            nullifier: [1u8; 32],
            owner_sig: SignatureEnvelope {
                scheme: SignatureScheme::LegacySecp256k1,
                signer_ref: u.owner.clone(),
                typed_data_digest: [0; 32],
                signature: [0; 64],
                nonce: 1,
                expiry: EXPIRY,
            },
            material: VerifierMaterial::LegacySecp256k1 {
                presented_public: u.key.public_bytes(),
            },
        }))
    };
    assert_eq!(borsh::to_vec(&burn).unwrap()[0], 13, "TE-M3 判别值不受 TE-M6 追加影响");
    // roundtrip：新载荷 borsh 往返保真
    for op in [faucet, credits, bind] {
        let bytes = borsh::to_vec(&op).unwrap();
        let back: Operation = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back, op);
    }
}

// ---------------------------------------------------------------------------
// 2. faucet 限量（单次 / 终身 / 幂等 / 通道互斥 / owner 隔离）
// ---------------------------------------------------------------------------

#[test]
fn faucet_mint_enforces_single_and_lifetime_limits() {
    let (mut seq, metrics) = new_sequencer();
    let alice = V2User::new(1);
    seq.submit(register_free_op(1, 100, 250), T0).unwrap();

    // 单次 ≤ single_max：100 直铸（无 anchor 换算）
    seq.submit(faucet_op(1, 1, &alice.owner, 100), T0 + 1).unwrap();
    assert_eq!(seq.state().game_outstanding(1), 100);
    assert_eq!(metrics.counter("ops_faucet_mint_total"), 1);
    assert_eq!(metrics.counter("faucet_mint_total"), 1);

    // 单次超限 → RateLimited（101 > single_max = 100）
    let err = seq.submit(faucet_op(2, 1, &alice.owner, 101), T0 + 2).unwrap_err();
    assert!(matches!(err, AppchainError::RateLimited(_)));
    assert!(metrics.counter("faucet_rate_limited_total") >= 1);

    // 终身累计：+100 = 200 ok；+50 = 250 == lifetime ok；+1 拒
    seq.submit(faucet_op(3, 1, &alice.owner, 100), T0 + 3).unwrap();
    seq.submit(faucet_op(4, 1, &alice.owner, 50), T0 + 4).unwrap();
    assert_eq!(seq.state().game_outstanding(1), 250);
    let err = seq.submit(faucet_op(5, 1, &alice.owner, 1), T0 + 5).unwrap_err();
    assert!(matches!(err, AppchainError::RateLimited(_)));
    // 拒绝零状态变更（outstanding 不动）
    assert_eq!(seq.state().game_outstanding(1), 250);

    // 通道互斥：Paid token 走 FaucetMint 拒（Paid 铸造通道是 IssueGameToken）
    seq.submit(register_paid_op(2, 0), T0 + 6).unwrap();
    let err = seq.submit(faucet_op(6, 2, &alice.owner, 1), T0 + 7).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(s) if s.contains("Free-mode")));
    // 遗留 PLAY(0) 拒（无 GTS 规格）
    let err = seq.submit(faucet_op(7, 0, &alice.owner, 1), T0 + 8).unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    // 零面额拒
    let err = seq.submit(faucet_op(8, 1, &alice.owner, 0), T0 + 9).unwrap_err();
    assert!(matches!(err, AppchainError::InvalidAmount(0)));
    // 供给对账闭合（INV-TE-7）
    assert!(seq.state().game_reconciliation().all_consistent);
}

#[test]
fn faucet_mint_claim_id_idempotent_and_supply_cap() {
    let (mut seq, _metrics) = new_sequencer();
    let alice = V2User::new(1);
    let bob = V2User::new(2);
    // Free 注册 + max_supply = 300（结构上限）；faucet single_max = 250
    let issuer = [0x02u8; 33];
    let mode = IssuanceMode::Free {
        faucet: FaucetPolicy { single_max: 250, player_lifetime_max: 1_000 },
    };
    let digest = GameTokenSpec::genesis_digest_of(1, &issuer, &mode, 300);
    seq.submit(Operation::RegisterGameToken(Box::new(RegisterGameTokenOp {
        token_id: 1, issuer, mode, max_supply: 300, genesis_digest: digest,
    })), T0).unwrap();

    // claim_id 幂等：同 claim_id 重复领取拒（即使换 owner / 换量）
    seq.submit(faucet_op(1, 1, &alice.owner, 100), T0 + 1).unwrap();
    let err = seq.submit(faucet_op(1, 1, &bob.owner, 50), T0 + 2).unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(s) if s.contains("faucet claim")));
    assert_eq!(seq.state().game_outstanding(1), 100, "重复领取零状态变更");

    // max_supply 上限：已铸 100，再领 250 → 350 > 300 拒（SupplyCapExceeded）
    let err = seq.submit(faucet_op(2, 1, &bob.owner, 250), T0 + 3).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::SupplyCapExceeded { token_id: 1, minted: 100, requested: 250, cap: 300 }
    ));
    // 200 ok（100 + 200 = 300 == cap）
    seq.submit(faucet_op(3, 1, &bob.owner, 200), T0 + 4).unwrap();
    assert_eq!(seq.state().game_outstanding(1), 300);
    // 终身记账按 owner 隔离：alice 100 / bob 200（faucet_issued）
    assert_eq!(seq.state().game_faucet_issued.get(&(1, poker_appchain::owner_v2::owner_commitment(&alice.owner))), Some(&100));
    assert_eq!(seq.state().game_faucet_issued.get(&(1, poker_appchain::owner_v2::owner_commitment(&bob.owner))), Some(&200));
    assert!(seq.state().game_reconciliation().all_consistent);
}

// ---------------------------------------------------------------------------
// 3. BuyGasCredits（1:1 入账 / 幂等 / 跨路径前向查重 / 结构门）
// ---------------------------------------------------------------------------

#[test]
fn buy_gas_credits_books_balance_and_is_idempotent() {
    let (mut seq, metrics) = new_sequencer();
    let alice = V2User::new(1);
    let bob = V2User::new(2);

    // 1:1 入账（USDT 计价）
    seq.submit(buy_credits_op(1, &alice.owner, AssetId::REAL_USDT, 5_000), T0).unwrap();
    assert_eq!(credit_of(&seq, &alice.owner, AssetId::REAL_USDT), 5_000);
    assert_eq!(metrics.counter("ops_buy_gas_credits_total"), 1);
    assert_eq!(metrics.counter("gas_credits_purchased_total"), 5_000);
    assert_eq!(
        metrics.gauge(&format!("gas_credit_balance{{currency=\"{}\"}}", AssetId::REAL_USDT)),
        5_000
    );

    // 同 pay_digest 重复购买拒（幂等，零状态变更）
    let err = seq.submit(buy_credits_op(1, &alice.owner, AssetId::REAL_USDT, 5_000), T0 + 1).unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(s) if s.contains("gas credit")));
    assert_eq!(credit_of(&seq, &alice.owner, AssetId::REAL_USDT), 5_000);

    // 跨路径前向查重：与 v1/v2 deposit / GAME issue 已用的外部支付 id 冲突拒
    seq.submit(
        deposit_v2_op(2, &bob.owner, AssetId::REAL_USDC, 1_000),
        T0 + 2,
    )
    .unwrap();
    let err = seq.submit(buy_credits_op(2, &alice.owner, AssetId::REAL_USDC, 500), T0 + 3).unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(s) if s.contains("gas credit")));
    // GAME issue id 同拒
    seq.submit(register_paid_op(3, 0), T0 + 4).unwrap();
    seq.submit(
        Operation::IssueGameToken(Box::new(IssueGameTokenOp {
            issue_id: id32(4),
            token_id: 3,
            buyer: alice.owner.clone(),
            pay_amount: 1_000_000_000_000_000_000,
        })),
        T0 + 5,
    )
    .unwrap();
    let err = seq.submit(buy_credits_op(4, &alice.owner, AssetId::REAL_USDT, 500), T0 + 6).unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(s) if s.contains("gas credit")));

    // 结构门：零面额 / GAME 域计价 / 伪造 REAL token 拒
    let err = seq.submit(buy_credits_op(5, &alice.owner, AssetId::REAL_USDT, 0), T0 + 7).unwrap_err();
    assert!(matches!(err, AppchainError::InvalidAmount(0)));
    let err = seq.submit(buy_credits_op(6, &alice.owner, AssetId::GAME_PLAY, 100), T0 + 8).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(s) if s.contains("REAL domain")));
    let err = seq.submit(buy_credits_op(7, &alice.owner, AssetId::game(9), 100), T0 + 9).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(s) if s.contains("REAL domain")));

    // 计价币种隔离 + owner 隔离
    seq.submit(buy_credits_op(8, &alice.owner, AssetId::REAL_USDC, 700), T0 + 10).unwrap();
    seq.submit(buy_credits_op(9, &bob.owner, AssetId::REAL_USDC, 300), T0 + 11).unwrap();
    assert_eq!(credit_of(&seq, &alice.owner, AssetId::REAL_USDC), 700);
    assert_eq!(credit_of(&seq, &bob.owner, AssetId::REAL_USDC), 300);
    // 计量账 INV-TE-8 恒等（Σ余额 == Σpurchased − Σconsumed）与格式标签
    let ledger = seq.state().gas_credit_ledger();
    assert!(ledger.invariant_holds());
    assert_eq!(ledger.to_json()["format"], poker_appchain::game_token::GAS_CREDIT_LEDGER_FORMAT);
}

// ---------------------------------------------------------------------------
// 4. BindGasPolicy（正例冻结 / TE-D7 / 结构门 / 桌门 / 成本覆盖）
// ---------------------------------------------------------------------------

#[test]
fn bind_gas_policy_happy_path_and_frozen() {
    let (mut seq, metrics) = new_sequencer();
    let operator = V2User::new(8);
    seq.submit(register_free_op(1, 100, 1_000), T0).unwrap();
    seq.submit(Operation::OpenTable { table_id: 50, policy: FeePolicy::Zero }, T0 + 1).unwrap();

    // 绑定正例：Free token 桌 + USDT 计价 + k = 3
    seq.submit(bind_op(50, 1, gas_policy(10)), T0 + 2).unwrap();
    let (token, policy) = seq.state().gas_policy_of(50).unwrap();
    assert_eq!(token, 1);
    assert_eq!(policy, gas_policy(10));
    assert_eq!(metrics.counter("ops_bind_gas_policy_total"), 1);
    assert_eq!(metrics.counter("gas_policy_bound_total"), 1);

    // 绑定即冻结：重绑拒（同载荷/异载荷一律）
    let err = seq.submit(bind_op(50, 1, gas_policy(10)), T0 + 3).unwrap_err();
    assert!(matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("frozen")));
    let err = seq.submit(bind_op(50, 1, gas_policy(20)), T0 + 4).unwrap_err();
    assert!(matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("frozen")));
    // 绑定值不被重绑改写
    assert_eq!(seq.state().gas_policy_of(50).unwrap().1.fee_per_hand, 10);
    // 分裂开桌操作者的 treasury 身份仅为构造完整性（未使用）
    let _ = operator;
}

#[test]
fn bind_rejects_paid_token_play_and_unregistered_te_d7() {
    let (mut seq, metrics) = new_sequencer();
    seq.submit(register_paid_op(1, 0), T0).unwrap();
    seq.submit(register_free_op(2, 100, 1_000), T0 + 1).unwrap();
    seq.submit(Operation::OpenTable { table_id: 60, policy: FeePolicy::Zero }, T0 + 2).unwrap();

    // TE-D7：Paid 模式 token 的桌绑定拒（双重收费 v1 禁止）
    let err = seq.submit(bind_op(60, 1, gas_policy(10)), T0 + 3).unwrap_err();
    assert!(
        matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("TE-D7")),
        "Paid 桌绑定必须 TE-D7 拒，got {err:?}"
    );
    assert!(metrics.counter("gas_policy_rejected_total") >= 1);
    // 遗留 PLAY(0) / 未注册 token 拒
    let err = seq.submit(bind_op(60, 0, gas_policy(10)), T0 + 4).unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    let err = seq.submit(bind_op(60, 9, gas_policy(10)), T0 + 5).unwrap_err();
    assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
    // 未开放桌拒
    let err = seq.submit(bind_op(61, 2, gas_policy(10)), T0 + 6).unwrap_err();
    assert!(matches!(err, AppchainError::TableNotOpen(61)));
    // 全部拒绝零状态变更
    assert!(seq.state().gas_policy_of(60).is_none() && seq.state().gas_policy_of(61).is_none());
}

#[test]
fn bind_rejects_bad_policy_structure() {
    let (mut seq, _metrics) = new_sequencer();
    seq.submit(register_free_op(1, 100, 1_000), T0).unwrap();
    seq.submit(Operation::OpenTable { table_id: 62, policy: FeePolicy::Zero }, T0 + 1).unwrap();
    // 零费拒
    let bad_zero = GasPolicy { fee_per_hand: 0, pricing_asset_id: AssetId::REAL_USDT, min_coverage_k: 3 };
    let err = seq.submit(bind_op(62, 1, bad_zero), T0 + 2).unwrap_err();
    assert!(matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("fee_per_hand")));
    // k < 3（冻结下限）拒
    let bad_k = GasPolicy { fee_per_hand: 10, pricing_asset_id: AssetId::REAL_USDT, min_coverage_k: 2 };
    let err = seq.submit(bind_op(62, 1, bad_k), T0 + 3).unwrap_err();
    assert!(matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("k >= 3")));
    // GAME 域计价拒（服务费必须真实价值资产）
    let bad_asset = GasPolicy { fee_per_hand: 10, pricing_asset_id: AssetId::GAME_PLAY, min_coverage_k: 3 };
    let err = seq.submit(bind_op(62, 1, bad_asset), T0 + 4).unwrap_err();
    assert!(matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("REAL domain")));
    // 伪造 REAL token 计价拒
    let forged = AssetId { domain: poker_appchain::asset_id::AssetDomain::Real, token_id: 999 };
    let bad_forged = GasPolicy { fee_per_hand: 10, pricing_asset_id: forged, min_coverage_k: 3 };
    let err = seq.submit(bind_op(62, 1, bad_forged), T0 + 5).unwrap_err();
    assert!(matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("REAL domain")));
    assert!(seq.state().gas_policy_of(62).is_none(), "全部拒绝零状态变更");
}

#[test]
fn cost_coverage_enforced_at_bind_time() {
    // c_hand = 1000（运营参数注入）；k 冻结下限 3 → fee < 3000 拒
    let (mut seq, metrics) = new_sequencer_with(1_000);
    let alice = V2User::new(1);
    seq.submit(register_free_op(1, 100, 1_000), T0).unwrap();
    seq.submit(Operation::OpenTable { table_id: 70, policy: FeePolicy::Zero }, T0 + 1).unwrap();

    // fee = 2999 < 3 × 1000 → 成本覆盖拒
    let err = seq.submit(bind_op(70, 1, gas_policy(2_999)), T0 + 2).unwrap_err();
    assert!(
        matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("cost coverage")),
        "fee < k·c_hand 必须拒，got {err:?}"
    );
    assert_eq!(metrics.counter("gas_coverage_rejected_total"), 1);
    // 边界含：fee = 3000 == 3 × 1000 过
    seq.submit(bind_op(70, 1, gas_policy(3_000)), T0 + 3).unwrap();
    assert_eq!(seq.state().gas_policy_of(70).unwrap().1.fee_per_hand, 3_000);
    let _ = alice;

    // c_hand = 0（诚实缺省）：覆盖强制未激活，k ≥ 3 与费额 > 0 仍强制
    let (mut seq0, _metrics0) = new_sequencer_with(0);
    seq0.submit(register_free_op(1, 100, 1_000), T0).unwrap();
    seq0.submit(Operation::OpenTable { table_id: 71, policy: FeePolicy::Zero }, T0 + 1).unwrap();
    seq0.submit(bind_op(71, 1, gas_policy(1)), T0 + 2).unwrap();
    assert_eq!(seq0.state().gas_policy_of(71).unwrap().1.fee_per_hand, 1);
}

// ---------------------------------------------------------------------------
// 5. Free 桌结算（INV-TE-9 未绑拒 / 绑定后固定费扣减 / INV-TE-8 不足拒）
// ---------------------------------------------------------------------------

/// 公共前置：注册 Free token → 玩家 faucet 领币 → 开 Zero 桌 → （可选绑 gas）。
struct FreeTable {
    seq: Sequencer,
    metrics: Arc<MetricsRegistry>,
    alice: V2User,
    bob: V2User,
    table: u64,
    token: u32,
}

impl FreeTable {
    fn new(table_id: u64, token_id: u32, c_hand: u64) -> Self {
        let (mut seq, metrics) = new_sequencer_with(c_hand);
        seq.submit(register_free_op(token_id, 100, 1_000), T0).unwrap();
        let alice = V2User::new(1);
        let bob = V2User::new(2);
        seq.submit(faucet_op(1, token_id, &alice.owner, 100), T0 + 1).unwrap();
        seq.submit(faucet_op(2, token_id, &bob.owner, 100), T0 + 2).unwrap();
        seq.submit(
            Operation::OpenTable { table_id, policy: FeePolicy::Zero },
            T0 + 3,
        )
        .unwrap();
        Self {
            seq,
            metrics,
            alice,
            bob,
            table: table_id,
            token: token_id,
        }
    }

    fn bind(&mut self, fee: u64) {
        self.seq.submit(bind_op(self.table, self.token, gas_policy(fee)), T0 + 4).unwrap();
    }

    fn alice_note(&self) -> NoteV2 {
        game_note_of(&self.seq, &self.alice.owner, self.token)
    }

    fn bob_note(&self) -> NoteV2 {
        game_note_of(&self.seq, &self.bob.owner, self.token)
    }
}

#[test]
fn free_table_settle_without_binding_rejected_inv_te9() {
    let mut ft = FreeTable::new(80, 1, 0);
    let alice_note = ft.alice_note();
    let bob_note = ft.bob_note();
    let settle = signed_settle_v2(
        ft.table,
        0xA6, 1,
        &[(&ft.alice, &alice_note), (&ft.bob, &bob_note)],
        NoteSpec2 {
            asset_id: AssetId::game(ft.token),
            amount: 200,
            owner: ft.alice.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        },
        0,
        &FeePolicy::Zero,
    );
    // INV-TE-9：Free token 的结算出现在未绑定 GasPolicy 的桌 → 受理拒绝
    let root_before = ft.seq.state().root();
    let err = ft.seq.submit(settle, T0 + 5).unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("bound gas policy")),
        "Free 桌未绑 GasPolicy 必须拒（INV-TE-9），got {err:?}"
    );
    assert_eq!(ft.metrics.counter("gas_policy_missing_rejected_total"), 1);
    // 拒绝零状态变更（notes 未被消费、binding 未烧掉）
    assert_eq!(ft.seq.state().root(), root_before);
    assert_eq!(ft.seq.state().game_outstanding(ft.token), 200);
    assert!(ft.seq.state().note_entries_v2_of(&ft.alice.owner).len() == 1);
}

#[test]
fn free_table_settle_with_binding_deducts_fixed_fee() {
    let mut ft = FreeTable::new(81, 1, 0);
    ft.bind(10);
    // 预购额度（发起方 alice：USDT 计价 100）
    ft.seq.submit(buy_credits_op(3, &ft.alice.owner, AssetId::REAL_USDT, 100), T0 + 5).unwrap();

    // 第一手：底池 200（与费用无关——固定费额 10）
    let alice_note = ft.alice_note();
    let bob_note = ft.bob_note();
    ft.seq
        .submit(
            signed_settle_v2(
                ft.table,
                0xB1, 1,
                &[(&ft.alice, &alice_note), (&ft.bob, &bob_note)],
                NoteSpec2 {
                    asset_id: AssetId::game(ft.token),
                    amount: 200,
                    owner: ft.alice.owner.clone(),
                    table_id: None,
                    pot_index: 0,
                    runout_index: 0,
                },
                0,
                &FeePolicy::Zero,
            ),
            T0 + 6,
        )
        .unwrap();
    // 恰好扣减固定费 10（结算守恒不动：GAME 面内 alice 200 全拿）
    assert_eq!(credit_of(&ft.seq, &ft.alice.owner, AssetId::REAL_USDT), 90);
    assert_eq!(ft.seq.state().balances_v2_of(&ft.alice.owner).1, 200);
    assert_eq!(ft.metrics.counter("gas_credits_consumed_total"), 10);
    assert_eq!(
        ft.metrics
            .gauge(&format!("gas_credit_balance{{currency=\"{}\"}}", AssetId::REAL_USDT)),
        90
    );

    // 第二手：不同底池（300 = alice 200 + bob 重新领取的 100）→ 扣费仍是
    // 固定 10（费额与底池无关；首手其 note 已被消费、无赔付）
    ft.seq.submit(faucet_op(5, ft.token, &ft.bob.owner, 100), T0 + 5).unwrap();
    let alice_note2 = ft.seq
        .state()
        .note_entries_v2_of(&ft.alice.owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.asset_id == AssetId::game(ft.token))
        .unwrap();
    let bob_note2 = ft.bob_note();
    ft.seq
        .submit(
            signed_settle_v2(
                ft.table,
                0xB2, 2,
                &[(&ft.alice, &alice_note2), (&ft.bob, &bob_note2)],
                NoteSpec2 {
                    asset_id: AssetId::game(ft.token),
                    amount: 300,
                    owner: ft.alice.owner.clone(),
                    table_id: None,
                    pot_index: 0,
                    runout_index: 0,
                },
                0,
                &FeePolicy::Zero,
            ),
            T0 + 7,
        )
        .unwrap();
    assert_eq!(credit_of(&ft.seq, &ft.alice.owner, AssetId::REAL_USDT), 80, "第二手仍扣固定 10");
    assert_eq!(ft.metrics.counter("gas_credits_consumed_total"), 20);
    // 参战方 bob 未被扣费（发起方 = 首输入 owner 口径）
    assert_eq!(credit_of(&ft.seq, &ft.bob.owner, AssetId::REAL_USDT), 0);
    // INV-TE-8 恒等保持 + GAME 供给不受 credit 影响
    assert!(ft.seq.state().gas_credit_ledger().invariant_holds());
    assert_eq!(ft.seq.state().game_outstanding(ft.token), 300);
    assert!(ft.seq.state().game_reconciliation().all_consistent);
}

#[test]
fn free_table_settle_insufficient_credit_rejected_inv_te8() {
    let mut ft = FreeTable::new(82, 1, 0);
    ft.bind(10);
    // 额度不足：5 < fee 10
    ft.seq.submit(buy_credits_op(3, &ft.alice.owner, AssetId::REAL_USDT, 5), T0 + 5).unwrap();
    let alice_note = ft.alice_note();
    let bob_note = ft.bob_note();
    let settle = signed_settle_v2(
        ft.table,
        0xC1, 1,
        &[(&ft.alice, &alice_note), (&ft.bob, &bob_note)],
        NoteSpec2 {
            asset_id: AssetId::game(ft.token),
            amount: 200,
            owner: ft.alice.owner.clone(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        },
        0,
        &FeePolicy::Zero,
    );
    let root_before = ft.seq.state().root();
    let err = ft.seq.submit(settle.clone(), T0 + 6).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::GasCreditInsufficient { asset, balance: 5, required: 10 }
            if asset == AssetId::REAL_USDT
        ),
        "额度不足必须 INV-TE-8 拒，got {err:?}"
    );
    assert_eq!(ft.metrics.counter("gas_credit_insufficient_total"), 1);
    // 拒绝零状态变更（notes 未消费、credit 未动、binding 未烧）
    assert_eq!(ft.seq.state().root(), root_before);
    assert_eq!(credit_of(&ft.seq, &ft.alice.owner, AssetId::REAL_USDT), 5);
    // 补足额度后同一手可受理（binding 未被失败尝试烧掉——C1 纪律）
    ft.seq.submit(buy_credits_op(4, &ft.alice.owner, AssetId::REAL_USDT, 5), T0 + 7).unwrap();
    ft.seq.submit(settle, T0 + 8).unwrap();
    assert_eq!(credit_of(&ft.seq, &ft.alice.owner, AssetId::REAL_USDT), 0, "10 全额扣减");
    assert_eq!(ft.seq.state().balances_v2_of(&ft.alice.owner).1, 200);
    assert!(ft.seq.state().gas_credit_ledger().invariant_holds());
}

#[test]
fn free_table_binding_token_mismatch_rejected() {
    // 桌绑定 token 1；结算资产是 token 2（同为 Free）→ INV-TE-9 拒
    let (mut seq, metrics) = new_sequencer();
    seq.submit(register_free_op(1, 100, 1_000), T0).unwrap();
    seq.submit(register_free_op(2, 100, 1_000), T0 + 1).unwrap();
    let alice = V2User::new(1);
    let bob = V2User::new(2);
    seq.submit(faucet_op(1, 2, &alice.owner, 100), T0 + 2).unwrap();
    seq.submit(faucet_op(2, 2, &bob.owner, 100), T0 + 3).unwrap();
    seq.submit(Operation::OpenTable { table_id: 83, policy: FeePolicy::Zero }, T0 + 4).unwrap();
    // 绑定的是 token 1（非本手 token 2）
    seq.submit(bind_op(83, 1, gas_policy(10)), T0 + 5).unwrap();
    let alice_note = game_note_of(&seq, &alice.owner, 2);
    let bob_note = game_note_of(&seq, &bob.owner, 2);
    let err = seq
        .submit(
            signed_settle_v2(
                83,
                0xC2, 1,
                &[(&alice, &alice_note), (&bob, &bob_note)],
                NoteSpec2 {
                    asset_id: AssetId::game(2),
                    amount: 200,
                    owner: alice.owner.clone(),
                    table_id: None,
                    pot_index: 0,
                    runout_index: 0,
                },
                0,
                &FeePolicy::Zero,
            ),
            T0 + 6,
        )
        .unwrap_err();
    assert!(
        matches!(err, AppchainError::AdmissionRejected(s) if s.contains("bound gas policy")),
        "绑定 token 与结算 token 不匹配必须拒，got {err:?}"
    );
    assert!(metrics.counter("gas_policy_missing_rejected_total") >= 1);
}

// ---------------------------------------------------------------------------
// 6. Paid 桌不受影响（TE-D7：无 gas 扣减；结算照常）
// ---------------------------------------------------------------------------

#[test]
fn paid_token_table_settle_unaffected_by_te_m6() {
    let (mut seq, metrics) = new_sequencer();
    let alice = V2User::new(1);
    let bob = V2User::new(2);
    seq.submit(register_paid_op(1, 0), T0).unwrap();
    seq.submit(
        Operation::IssueGameToken(Box::new(IssueGameTokenOp {
            issue_id: id32(1),
            token_id: 1,
            buyer: alice.owner.clone(),
            pay_amount: 1_000_000_000_000_000_000,
        })),
        T0 + 1,
    )
    .unwrap();
    seq.submit(
        Operation::IssueGameToken(Box::new(IssueGameTokenOp {
            issue_id: id32(2),
            token_id: 1,
            buyer: bob.owner.clone(),
            pay_amount: 1_000_000_000_000_000_000,
        })),
        T0 + 2,
    )
    .unwrap();
    seq.submit(Operation::OpenTable { table_id: 84, policy: FeePolicy::Zero }, T0 + 3).unwrap();
    // Paid token 桌**未绑** GasPolicy（TE-D7 下也绑不了）——结算零 gas 门
    let alice_note = game_note_of(&seq, &alice.owner, 1);
    let bob_note = game_note_of(&seq, &bob.owner, 1);
    seq.submit(
        signed_settle_v2(
            84,
            0xD1, 1,
            &[(&alice, &alice_note), (&bob, &bob_note)],
            NoteSpec2 {
                asset_id: AssetId::game(1),
                amount: 2_000_000,
                owner: alice.owner.clone(),
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            },
            0,
            &FeePolicy::Zero,
        ),
        T0 + 4,
    )
    .unwrap();
    // 结算照常受理、零 gas 计量（Paid 桌不受 TE-M6 影响）
    assert_eq!(seq.state().balances_v2_of(&alice.owner).1, 2_000_000);
    assert_eq!(metrics.counter("gas_credits_consumed_total"), 0);
    assert_eq!(metrics.counter("gas_policy_missing_rejected_total"), 0);
    assert!(seq.state().gas_credit_ledger().invariant_holds());
}

// ---------------------------------------------------------------------------
// 7. Free 桌 × TE-M4 burn 桌组合（gas 门与 burn 处置共存）
// ---------------------------------------------------------------------------

#[test]
fn free_table_on_burn_policy_charges_gas_and_burns_rake() {
    let (mut seq, metrics) = new_sequencer();
    let treasury = V2User::new(7);
    let operator = V2User::new(8);
    let burn_policy = FeePolicy::FixedRakeBurn {
        rate_bps: 500,
        cap: 0,
        split: poker_appchain::fee::FeeSplit {
            treasury_bps: 2_000,
            treasury: treasury.key.public_bytes(),
            operator: operator.key.public_bytes(),
        },
    };
    seq.submit(register_free_op(1, 100, 1_000), T0).unwrap();
    let alice = V2User::new(1);
    let bob = V2User::new(2);
    seq.submit(faucet_op(1, 1, &alice.owner, 100), T0 + 1).unwrap();
    seq.submit(faucet_op(2, 1, &bob.owner, 100), T0 + 2).unwrap();
    seq.submit(Operation::OpenTable { table_id: 85, policy: burn_policy }, T0 + 3).unwrap();
    seq.submit(bind_op(85, 1, gas_policy(10)), T0 + 4).unwrap();
    seq.submit(buy_credits_op(3, &alice.owner, AssetId::REAL_USDT, 50), T0 + 5).unwrap();

    // 一手：pot 200，5% burn rake = 10，gas 固定费 10（两门并存）
    let alice_note = game_note_of(&seq, &alice.owner, 1);
    let bob_note = game_note_of(&seq, &bob.owner, 1);
    seq.submit(
        signed_settle_v2(
            85,
            0xE1, 1,
            &[(&alice, &alice_note), (&bob, &bob_note)],
            NoteSpec2 {
                asset_id: AssetId::game(1),
                amount: 190,
                owner: alice.owner.clone(),
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            },
            10,
            &burn_policy,
        ),
        T0 + 6,
    )
    .unwrap();
    // GAME 域：rake burn 处置（outstanding 200 → 190）；REAL 域：gas 扣 10
    assert_eq!(seq.state().game_outstanding(1), 190);
    assert_eq!(seq.state().game_burned.get(&1), Some(&10u128));
    assert_eq!(credit_of(&seq, &alice.owner, AssetId::REAL_USDT), 40);
    assert_eq!(metrics.counter("gas_credits_consumed_total"), 10);
    assert!(seq.state().game_reconciliation().all_consistent);
    assert!(seq.state().gas_credit_ledger().invariant_holds());
}

// ---------------------------------------------------------------------------
// 8. 托管隔离：credit 活动不污染 CustodyLedger 对账恒等式（收入非储备）
// ---------------------------------------------------------------------------

#[test]
fn gas_credits_do_not_pollute_custody_identity() {
    let (mut seq, _metrics) = new_sequencer();
    let alice = V2User::new(1);
    let bob = V2User::new(2);

    // 非平凡托管基线：REAL USDT 存款（issued == live note 面额，burned 空）
    seq.submit(deposit_v2_op(1, &alice.owner, AssetId::REAL_USDT, 10_000), T0).unwrap();
    seq.submit(deposit_v2_op(2, &bob.owner, AssetId::REAL_USDC, 500), T0 + 1).unwrap();
    let custody_before = custody_snapshot(seq.state());
    let live_before = real_live_sum(seq.state());
    assert_eq!(custody_before.0.get(&AssetId::REAL_USDT), Some(&10_000u128));
    assert_eq!(live_before, 10_500);

    // TE-M6 全流程：faucet 领币 / credit 购买 / Free 桌绑定 / 结算扣费
    seq.submit(register_free_op(1, 100, 1_000), T0 + 2).unwrap();
    seq.submit(faucet_op(1, 1, &alice.owner, 100), T0 + 3).unwrap();
    seq.submit(faucet_op(2, 1, &bob.owner, 100), T0 + 4).unwrap();
    seq.submit(buy_credits_op(3, &alice.owner, AssetId::REAL_USDT, 1_000), T0 + 5).unwrap();
    seq.submit(Operation::OpenTable { table_id: 86, policy: FeePolicy::Zero }, T0 + 6).unwrap();
    seq.submit(bind_op(86, 1, gas_policy(10)), T0 + 7).unwrap();
    let alice_note = game_note_of(&seq, &alice.owner, 1);
    let bob_note = game_note_of(&seq, &bob.owner, 1);
    seq.submit(
        signed_settle_v2(
            86,
            0xF1, 1,
            &[(&alice, &alice_note), (&bob, &bob_note)],
            NoteSpec2 {
                asset_id: AssetId::game(1),
                amount: 200,
                owner: alice.owner.clone(),
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            },
            0,
            &FeePolicy::Zero,
        ),
        T0 + 8,
    )
    .unwrap();
    assert_eq!(credit_of(&seq, &alice.owner, AssetId::REAL_USDT), 990);

    // 托管恒等式输入逐位不变：REAL issued / burned 计数 / REAL live 面额
    // ——gas credit 的购买与消耗**不进** reserved/issued 的任何一边
    //（服务费收入无储备义务，物理隔离）
    let custody_after = custody_snapshot(seq.state());
    assert_eq!(custody_after.0, custody_before.0, "REAL issued 不因 credit 活动变化");
    assert_eq!(custody_after.1, custody_before.1, "REAL burned 记录不因 credit 活动变化");
    assert_eq!(real_live_sum(seq.state()), live_before);
    // REAL 域余额（玩家现金）也未被触碰：alice USDT 现金仍 10_000
    assert_eq!(seq.state().balances_v2_of(&alice.owner).0, 10_000);
    // 计量账自洽 + 导出中显式声明非储备
    let ledger = seq.state().gas_credit_ledger();
    assert!(ledger.invariant_holds());
    let v = ledger.to_json();
    assert_eq!(v["invariant_holds"], true);
    assert!(v.to_string().contains("NOT reserve"), "导出必须携带非储备声明");
}

// ---------------------------------------------------------------------------
// 9. WAL 重放恢复：credit 账本 / gas 绑定 / faucet 幂等集逐位重建
// ---------------------------------------------------------------------------

#[test]
fn wal_replay_restores_gas_ledger_bindings_and_faucet_ids() {
    let dir = std::env::temp_dir().join("poker-appchain-te-m6");
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("te_m6_replay.wal");
    let _ = std::fs::remove_file(&wal);

    let (mut seq, _metrics) = new_sequencer();
    seq.attach_wal(&wal).unwrap();
    seq.submit(register_free_op(1, 100, 1_000), T0).unwrap();
    let alice = V2User::new(1);
    let bob = V2User::new(2);
    seq.submit(faucet_op(1, 1, &alice.owner, 100), T0 + 1).unwrap();
    seq.submit(faucet_op(2, 1, &bob.owner, 100), T0 + 2).unwrap();
    seq.submit(buy_credits_op(3, &alice.owner, AssetId::REAL_USDT, 100), T0 + 3).unwrap();
    seq.submit(Operation::OpenTable { table_id: 87, policy: FeePolicy::Zero }, T0 + 4).unwrap();
    seq.submit(bind_op(87, 1, gas_policy(10)), T0 + 5).unwrap();
    let alice_note = game_note_of(&seq, &alice.owner, 1);
    let bob_note = game_note_of(&seq, &bob.owner, 1);
    seq.submit(
        signed_settle_v2(
            87,
            0xE7, 1,
            &[(&alice, &alice_note), (&bob, &bob_note)],
            NoteSpec2 {
                asset_id: AssetId::game(1),
                amount: 200,
                owner: alice.owner.clone(),
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            },
            0,
            &FeePolicy::Zero,
        ),
        T0 + 6,
    )
    .unwrap();

    // 重放前快照：状态根 / gas 绑定 / credit 账 / faucet 幂等集 / 终身记账
    let root_before = seq.state().root();
    let policies_before = seq.state().gas_policies.clone();
    let credits_before = seq.state().gas_credits.clone();
    let faucet_ids_before = seq.state().game_faucet_ids.clone();
    let issued_before = seq.state().game_faucet_issued.clone();
    assert_eq!(credit_of(&seq, &alice.owner, AssetId::REAL_USDT), 90);
    drop(seq);

    let mut seq2 = Sequencer::replay(
        &wal,
        SequencerKey::from_seed(&[42u8; 32]).public,
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    )
    .unwrap();
    assert_eq!(seq2.state().root(), root_before, "重放逐位重现状态根");
    assert_eq!(seq2.state().gas_policies, policies_before, "gas 绑定随 apply 路径恢复");
    assert_eq!(seq2.state().gas_credits, credits_before, "credit 计量账逐位恢复（INV-TE-8）");
    assert_eq!(seq2.state().game_faucet_ids, faucet_ids_before, "faucet 幂等集恢复");
    assert_eq!(seq2.state().game_faucet_issued, issued_before, "faucet 终身记账恢复");
    assert_eq!(
        credit_of(&seq2, &alice.owner, AssetId::REAL_USDT),
        90,
        "重放后 credit 余额一致"
    );
    assert!(seq2.state().gas_credit_ledger().invariant_holds());
    // 重放后继续受理：同一幂等键仍拒（幂等集恢复生效）
    let err = seq2.submit(buy_credits_op(3, &alice.owner, AssetId::REAL_USDT, 100), T0 + 7).unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(s) if s.contains("gas credit")));
}
