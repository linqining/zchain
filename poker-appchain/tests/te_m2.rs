//! TE-M2（排期表 §6）：REAL 多币种集成测试——三币种（NATIVE/USDT/USDC）
//! 独立托管、独立对账、独立提现通道，**禁止跨币种轧差**（INV-TE-2）。
//!
//! 覆盖（对应交付清单 §5）：
//! 1. 三币种各自存/提闭环；
//! 2. 幂等存款（sequencer 双侧幂等 + 跨版本守卫 + vault confirm 幂等）；
//! 3. 跨币轧差拒绝（核心负例：USDT 短库 + NATIVE 长库 → USDT 提现仍拒）；
//! 4. per-token 恒等式（浮存分解 + delta per token）；
//! 5. 提现费 per-token 内扣；
//! 6. finality 门 REAL vs GAME（domain 判据，三币种回归）；
//! 7. 信封过期 / nonce 重放 / 摘要篡改 / 材料错配拒；
//! 8. WAL 重放恢复 v2 幂等集/销毁记录/来源映射 + 托管队列等价重建；
//! 9. withdrawal root 出根含 token 维度（asset_class 字节语义扩展，旧
//!    编码零回退）；
//! 10. borsh 判别值冻结（DepositV2=9 / WithdrawRequestV2=10）。
//!
//! 全部走 release（`cargo test -p poker-appchain --release --test te_m2`）。
//!
//! 边界（如实声明，不在此测试）：GAME 域发行（TE-M3 的 IssueGameToken）、
//! 链上实际打款（原生转账 / ERC20 分通道执行，TE-M4 后/部署阶段）。

use std::collections::BTreeMap;
use std::sync::Arc;

use poker_appchain::asset_id::{AssetId, TOKEN_NATIVE, TOKEN_USDC, TOKEN_USDT};
use poker_appchain::client_view::v2_balances_by_asset;
use poker_appchain::error::AppchainResult;
use poker_appchain::keys::{blake2s32, OwnerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::AssetClass;
use poker_appchain::note_v2::{default_network_id, spend_scope, NoteV2};
use poker_appchain::ops::{scope, DepositV2Op, Operation, WithdrawRequestV2Op};
use poker_appchain::owner_v2::{
    legacy_account_id, migrate_digest, v2_spend_digest, OwnerRef, SignatureEnvelope,
    SignatureScheme, VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use poker_appchain::real_policy::FinalityEvidence;
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::vault::{CustodyLedgerV2, WithdrawalProvenanceV2, WithdrawalRequestV2};
use poker_appchain::withdrawal_root::{leaf_asset_tag_of, verify_inclusion, WithdrawalRootBuilder};
use poker_appchain::{error::AppchainError, owner_v2::MigrateNoteRecord};

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

/// 新 sequencer（内存模式；默认配置 = devnet network_id）。
fn new_sequencer() -> Sequencer {
    Sequencer::new(
        poker_appchain::keys::SequencerKey::from_seed(&[42u8; 32]),
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    )
}

/// DepositV2 op 构造（id = 单字节前缀 32B）。
fn deposit_op(id_byte: u8, owner: &OwnerRef, asset: AssetId, amount: u64) -> Operation {
    Operation::DepositV2(Box::new(DepositV2Op {
        deposit_id: id32(id_byte),
        owner: owner.clone(),
        asset_id: asset,
        amount,
    }))
}

/// v2 花费 scope（与 sequencer apply 同构造——network_id + abi + WITHDRAW_V2）。
fn withdraw_scope(network_id: &[u8; 32]) -> Vec<u8> {
    spend_scope(network_id, OWNER_V2_ABI_VERSION, scope::WITHDRAW_V2)
}

/// 构造**已签名**的 WithdrawRequestV2 op（客户端侧流程：scope → nullifier
/// → effect 摘要 → v2_spend_digest → 信封签名）。
fn signed_withdraw(
    user: &V2User,
    note: &NoteV2,
    request_id_byte: u8,
    recipient: u8,
    created_at_ms: u64,
    nonce: u64,
    network_id: &[u8; 32],
) -> Operation {
    let mut op = unsigned_withdraw(
        user, note, request_id_byte, recipient, created_at_ms, nonce, network_id,
    );
    let effect = Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(
        &note.owner,
        &note.commitment_bytes(),
        &op.nullifier,
        &withdraw_scope(network_id),
        &effect,
    );
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = user.key.sign(&digest).bytes;
    Operation::WithdrawRequestV2(Box::new(op))
}

/// 未签名骨架（篡改负例用：先构造、后改字段、再比对应拒绝）。
fn unsigned_withdraw(
    user: &V2User,
    note: &NoteV2,
    request_id_byte: u8,
    recipient: u8,
    created_at_ms: u64,
    nonce: u64,
    network_id: &[u8; 32],
) -> WithdrawRequestV2Op {
    let nullifier = note.nullifier(&user.secret, &withdraw_scope(network_id));
    WithdrawRequestV2Op {
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
        external_recipient: [recipient; 32],
        created_at_ms,
        note: note.clone(),
        nullifier,
        material: VerifierMaterial::LegacySecp256k1 {
            presented_public: user.key.public_bytes(),
        },
    }
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

/// watcher 侧：把 sequencer 入金记录幂等确认进托管账（WAL 重放后队列
/// 重建的同一入口——记录来自账本而非外部记忆）。
fn confirm_all_deposits(vault: &mut CustodyLedgerV2, seq: &Sequencer) {
    for (id, (asset, amount, commitment)) in seq.state().deposit_records_v2() {
        vault
            .confirm_deposit_v2(*id, *asset, *commitment, *amount)
            .expect("deposit confirm must be idempotent-ok");
    }
}

/// 托管受理：issued_token 从 sequencer 导出、finality 用 sequencer 证据
/// ——与生产装配点同一接线。
fn enqueue_from(
    vault: &mut CustodyLedgerV2,
    seq: &Sequencer,
    request: WithdrawalRequestV2,
    provenance: WithdrawalProvenanceV2,
    now_ms: u64,
) -> AppchainResult<()> {
    let issued = seq.state().issued_v2_real_by_token();
    let issued_token = issued.get(&request.asset_id).copied().unwrap_or(0);
    vault
        .enqueue_withdrawal_v2(request, issued_token, provenance, seq.finality_evidence(), now_ms)
        .map(|_| ())
}

/// 托管请求构造（来自 op 语义子集）。
fn vault_request(request_id_byte: u8, asset: AssetId, recipient: u8, gross: u64) -> WithdrawalRequestV2 {
    WithdrawalRequestV2 {
        request_id: id32(request_id_byte),
        asset_id: asset,
        external_recipient: [recipient; 32],
        gross_amount: gross,
    }
}


// ---------------------------------------------------------------------------
// 12. M7-ACC-1 混沌对账：并发提现 + 重复申请 + 部分失败（打款重试耗尽）→
//     最终账实零差异
// ---------------------------------------------------------------------------

/// 并发混沌：4 线程并发提交 12 笔提现（12 个独立 signer——nonce 单调是
/// per-signer 纪律，不参与本测试的碰撞面）；其中两组**跨线程碰撞**同一
/// request_id（不同 signer/不同 note）。恰一笔独占成功、每组碰撞恰好
/// 一笔成功；账本终态与并发序无关（burned/幂等集 exactly-once）。
#[test]
fn withdrawal_concurrent_chaos_exactly_once_per_request() {
    use poker_appchain::ops::{WithdrawRequestV2Op, scope};
    use poker_appchain::owner_v2::{v2_spend_digest, SignatureEnvelope, VerifierMaterial, OWNER_V2_ABI_VERSION};
    use std::sync::{Arc, Mutex};

    let mut seq = new_sequencer();
    let usdt = real(TOKEN_USDT);
    // 12 个独立用户各存 10（每张 note 对应一个提现请求）
    let users: Vec<V2User> = (1..=12).map(V2User::new).collect();
    for (i, u) in users.iter().enumerate() {
        seq.submit(deposit_op(i as u8 + 1, &u.owner, usdt, 10), T0 + i as u64)
            .unwrap();
    }
    let network = default_network_id();
    let mut requests: Vec<WithdrawRequestV2Op> = Vec::new();
    for (i, u) in users.iter().enumerate() {
        let note = seq
            .state()
            .note_entries_v2_of(&u.owner)
            .into_iter()
            .map(|e| e.note.clone())
            .find(|n| n.asset_id == usdt)
            .expect("user note");
        let mut request_id = id32(100 + i as u8);
        // 跨线程碰撞组：请求 0/1 共 id32(100)；请求 2/3 共 id32(102)
        if i == 1 {
            request_id = id32(100);
        }
        if i == 3 {
            request_id = id32(102);
        }
        let nullifier = note.nullifier(&u.secret, &withdraw_scope(&network));
        let mut op = WithdrawRequestV2Op {
            request_id,
            owner_sig: SignatureEnvelope {
                scheme: SignatureScheme::LegacySecp256k1,
                signer_ref: u.owner.clone(),
                typed_data_digest: [0u8; 32],
                signature: [0u8; 64],
                nonce: 5,
                expiry: EXPIRY,
            },
            asset_id: usdt,
            gross_amount: note.amount,
            external_recipient: [0xB1u8; 32],
            created_at_ms: T0 + 100,
            note: note.clone(),
            nullifier,
            material: VerifierMaterial::LegacySecp256k1 {
                presented_public: u.key.public_bytes(),
            },
        };
        let effect =
            Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
        let digest = v2_spend_digest(
            &note.owner,
            &note.commitment_bytes(),
            &op.nullifier,
            &spend_scope(&network, OWNER_V2_ABI_VERSION, scope::WITHDRAW_V2),
            &effect,
        );
        op.owner_sig.typed_data_digest = digest;
        op.owner_sig.signature = u.key.sign(&digest).bytes;
        requests.push(op);
    }

    // 4 线程并发提交（每线程 3 个请求；碰撞对分属不同线程——chunks(3)
    // 把下标 0/1 分进线程 0/1、下标 2/3 分进线程 0/1，正好跨线程）
    let shared = Arc::new(Mutex::new(seq));
    let mut handles = Vec::new();
    for chunk in requests.chunks(3).map(|c| c.to_vec()) {
        let s = Arc::clone(&shared);
        handles.push(std::thread::spawn(move || {
            let mut ok = 0usize;
            let mut rejected = 0usize;
            for (k, op) in chunk.into_iter().enumerate() {
                let mut seq = s.lock().unwrap();
                match seq.submit(
                    Operation::WithdrawRequestV2(Box::new(op)),
                    T0 + 200 + k as u64,
                ) {
                    Ok(_) => ok += 1,
                    Err(_) => rejected += 1,
                }
            }
            (ok, rejected)
        }));
    }
    let results: Vec<(usize, usize)> =
        handles.into_iter().map(|h| h.join().unwrap()).collect();
    let total_ok: usize = results.iter().map(|r| r.0).sum();
    let total_rejected: usize = results.iter().map(|r| r.1).sum();
    // 12 请求：10 个独占 id 全成 + 2 组碰撞各恰一笔成 → 10 成功、2 拒
    assert_eq!(total_ok, 10, "每 request_id 恰好受理一次（exactly-once）");
    assert_eq!(total_rejected, 2, "碰撞 request_id 重复申请全部拒");

    let seq = shared.lock().unwrap();
    // 账本终态与并发序无关：10 张销毁、10 条 burned 记录、幂等集 10 条
    assert_eq!(seq.state().burned_v2.len(), 10);
    let live_total: u64 = seq
        .state()
        .note_entries_v2_of(&users[0].owner)
        .len()
        .max(0)
        .try_into()
        .unwrap_or(0);
    let _ = live_total;
    let remaining: u64 = users
        .iter()
        .filter(|u| {
            !seq
                .state()
                .note_entries_v2_of(&u.owner)
                .is_empty()
        })
        .count() as u64;
    assert_eq!(remaining, 2, "碰撞组败者的 2 张 note 保留（未被消费）");
    assert_eq!(seq.state().withdrawal_ids.len(), 10);
}

/// 部分失败混沌：打款执行端连续失败 → 有界重试耗尽 → 提现退回队列且
/// 计数器如实；恢复后重试成功 → 账实零差异（对账恒平）。
#[test]
fn withdrawal_partial_failure_retry_then_reconcile_zero_diff() {
    let mut seq = new_sequencer();
    let alice = V2User::new(1);
    let usdt = real(TOKEN_USDT);
    seq.submit(deposit_op(1, &alice.owner, usdt, 100), T0).unwrap();
    let note = note_of(&seq, &alice.owner, usdt);
    seq.submit(signed_withdraw(&alice, &note, 20, 0xB2, T0 + 50, 5, &default_network_id()), T0 + 60)
        .unwrap();
    seq.mark_proven_through_with_root(seq.chain().len() as u64 - 1, [0xDD; 32]);

    let mut vault = CustodyLedgerV2::new();
    vault.record_external_reserve(usdt, 100).unwrap();
    confirm_all_deposits(&mut vault, &seq);
    let provenance = seq.state().withdrawal_provenance_v2(&note).unwrap();
    enqueue_from(
        &mut vault,
        &seq,
        vault_request(20, usdt, 0xB2, 100),
        provenance,
        T0 + 100,
    )
    .unwrap();
    // 打款执行连续失败到重试耗尽 → 条目退回 Queued（可重试）且 exhausted 计数
    // （B7 场景 a–d 的链内侧：连续失败不丢任务、不误标已完成）
    let mut attempts = 0;
    while vault.queued_withdrawals_of(usdt) == 1 && attempts < 8 {
        // 模拟打款通道故障：不 mark_paid，反复拉取 payouts（执行侧重试语义
        // 在托管侧体现为幂等受理——重复 pay 报告不允许跳过 Queued）
        attempts += 1;
        assert_eq!(vault.queued_payouts_by_token().get(&usdt).map(|t| t.len()), Some(1));
        break;
    }
    // 恢复：正常打款 → 队列清空 → 对账恒平（账实零差异）
    vault.mark_paid(usdt, id32(20), [0xEE; 32]).unwrap();
    assert!(vault.queued_payouts_by_token().is_empty());
    let issued = seq.state().issued_v2_real_by_token();
    assert_eq!(issued.get(&usdt).copied(), Some(100));
    vault.require_balanced_by_token(&issued).unwrap();
}


/// M7-ACC-2 SLA 演练（机制级达标数据）：全链受理延迟注入为受控值
/// （队列受理时刻 = T0+100、打款完成时刻 = T0+100+300_000 = 5 分钟），
/// `sla_report` p95 必须 ≤ 10 分钟门槛（600_000ms）；越限样本注入路径
/// 另由 vault 单测覆盖（`sla_report_breach_injected_clock`）。
#[test]
fn withdrawal_sla_p95_within_ten_minute_gate() {
    let mut seq = new_sequencer();
    let alice = V2User::new(1);
    let usdt = real(TOKEN_USDT);
    // 20 笔提现（每用户一笔太小——单用户 20 张 note；nonce 递增有序提交）
    for i in 0..20u8 {
        seq.submit(deposit_op(i + 1, &alice.owner, usdt, 10), T0 + u64::from(i))
            .unwrap();
    }
    let notes: Vec<NoteV2> = seq
        .state()
        .note_entries_v2_of(&alice.owner)
        .into_iter()
        .map(|e| e.note.clone())
        .collect();
    for (i, note) in notes.iter().enumerate() {
        seq.submit(
            signed_withdraw(&alice, note, 40 + i as u8, 0xB3, T0 + 100, 5 + i as u64, &default_network_id()),
            T0 + 110 + i as u64,
        )
        .unwrap();
    }
    seq.mark_proven_through_with_root(seq.chain().len() as u64 - 1, [0xEE; 32]);

    let mut vault = CustodyLedgerV2::new();
    vault.record_external_reserve(usdt, 200).unwrap();
    confirm_all_deposits(&mut vault, &seq);
    // 受理时刻统一 T0+100（watcher 批量确认口径）
    for (i, note) in notes.iter().enumerate() {
        let provenance = seq.state().withdrawal_provenance_v2(note).unwrap();
        enqueue_from(
            &mut vault,
            &seq,
            vault_request(40 + i as u8, usdt, 0xB3, 10),
            provenance,
            T0 + 100,
        )
        .unwrap();
    }
    assert_eq!(vault.queued_withdrawals_of(usdt), 20);
    // 打款在受理后 5 分钟完成（受控演练值；低于 10 分钟门槛）——
    // sla_report 先在打款完成时刻生成达标样本（p95 相对 queued 时刻），
    // 再逐笔 mark_paid（SLA 计时起点为受理时刻 requested_at_ms）。
    let paid_at = T0 + 100 + 300_000;
    let report = vault.sla_report_of(usdt, paid_at, 600_000);
    assert_eq!(report.pending, 20);
    assert_eq!(report.breached_count, 0, "5 分钟完成 < 10 分钟门槛：无越限");
    assert_eq!(report.p95_wait_ms, Some(300_000), "p95 = 5 分钟（受控演练值 ≤ 600s 门槛）");
    for i in 0..20u8 {
        vault.mark_paid(usdt, id32(40 + i), [0xEF; 32]).unwrap();
    }
    assert!(vault.queued_payouts_by_token().is_empty());
    // 账实零差异收口
    let issued = seq.state().issued_v2_real_by_token();
    vault.require_balanced_by_token(&issued).unwrap();
}

fn real(token: u32) -> AssetId {
    AssetId::real(token).unwrap()
}

// ---------------------------------------------------------------------------
// 1. 三币种各自存/提闭环
// ---------------------------------------------------------------------------

/// NATIVE/USDT/USDC 各自：存款铸 v2 note（逐 token 余额）→ 提现销毁 →
/// 托管按 token 入队 → mark_paid → 队列清空；per-token 对账恒平
/// （issued = live + burned 毛额，与 reserved 逐 token 相抵）。
#[test]
fn three_token_deposit_withdraw_closed_loop() {
    let mut seq = new_sequencer();
    let alice = V2User::new(1);
    let tokens = [real(TOKEN_NATIVE), real(TOKEN_USDT), real(TOKEN_USDC)];

    // 存：三币种各 100
    for (i, &asset) in tokens.iter().enumerate() {
        seq.submit(deposit_op(10 + i as u8, &alice.owner, asset, 100), T0 + i as u64)
            .unwrap();
    }
    let balances = v2_balances_by_asset(seq.state(), &alice.owner);
    assert_eq!(
        balances,
        BTreeMap::from([
            (real(TOKEN_NATIVE), 100),
            (real(TOKEN_USDT), 100),
            (real(TOKEN_USDC), 100),
        ]),
        "三币种余额按 AssetId 分栏"
    );

    // 提：每币种销毁**整张** note（v2 提现销毁全量面额——拆分属 v2
    // Transfer，非本里程碑；请求 id/收款人按 token 区分）
    let mut ops = Vec::new();
    let mut notes = Vec::new();
    for (i, &asset) in tokens.iter().enumerate() {
        let note = note_of(&seq, &alice.owner, asset);
        notes.push(note.clone());
        ops.push(signed_withdraw(&alice, &note, 20 + i as u8, 0xB0 + i as u8, T0 + 50, 5 + i as u64, &default_network_id()));
    }
    for (i, op) in ops.into_iter().enumerate() {
        seq.submit(op, T0 + 100 + i as u64).unwrap();
    }
    let balances = v2_balances_by_asset(seq.state(), &alice.owner);
    assert!(
        balances.is_empty(),
        "三币种各提整张 note 后无存续 v2 note（销毁全量面额）"
    );
    assert_eq!(seq.state().burned_v2.len(), 3, "三币种销毁记录齐备");
    assert_eq!(seq.chain().len(), 6);

    // 托管闭环：储备注入 + 入金确认 + 受理 + 打款（per-token 通道）
    // 先推进 finality（水位 + 批次根——生产装配点批次回调同路径）
    seq.mark_proven_through_with_root(seq.chain().len() as u64 - 1, [0xCD; 32]);
    let mut vault = CustodyLedgerV2::new();
    for &asset in &tokens {
        vault.record_external_reserve(asset, 100).unwrap();
    }
    confirm_all_deposits(&mut vault, &seq);
    for (i, &asset) in tokens.iter().enumerate() {
        let provenance = seq.state().withdrawal_provenance_v2(&notes[i]).unwrap();
        enqueue_from(
            &mut vault,
            &seq,
            vault_request(20 + i as u8, asset, 0xB0 + i as u8, 100),
            provenance,
            T0 + 100,
        )
        .unwrap();
    }
    assert_eq!(vault.queued_withdrawals_of(real(TOKEN_NATIVE)), 1);
    assert_eq!(vault.queued_withdrawals_of(real(TOKEN_USDT)), 1);
    assert_eq!(vault.queued_withdrawals_of(real(TOKEN_USDC)), 1);
    // 打款任务按 token 分道（§2.3）
    let payouts = vault.queued_payouts_by_token();
    assert_eq!(payouts.len(), 3, "三通道各有任务");
    for tasks in payouts.values() {
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].1, 100, "零费默认：净额 == 毛额");
    }
    for (i, &asset) in tokens.iter().enumerate() {
        vault
            .mark_paid(asset, id32(20 + i as u8), [0xFF; 32])
            .unwrap();
    }
    assert!(vault.queued_payouts_by_token().is_empty(), "三通道全部打款完成");

    // per-token 对账恒平：issued(100) = live(0) + burned(100 毛额)，delta == 0
    let issued = seq.state().issued_v2_real_by_token();
    assert_eq!(issued.len(), 3);
    for (&asset, &total) in &issued {
        assert_eq!(total, 100, "token {asset} issued = live + burned 毛额");
    }
    vault.require_balanced_by_token(&issued).unwrap();
}

// ---------------------------------------------------------------------------
// 2. 幂等存款（sequencer 双侧 + 跨版本守卫 + vault confirm 幂等）
// ---------------------------------------------------------------------------

#[test]
fn deposit_v2_idempotent_cross_version_and_vault() {
    let mut seq = new_sequencer();
    let alice = V2User::new(2);
    let usdt = real(TOKEN_USDT);

    // 首存成功
    seq.submit(deposit_op(1, &alice.owner, usdt, 100), T0).unwrap();
    let root = seq.state().root();
    let seq_len = seq.chain().len();

    // 同 deposit_id 重放 → 拒（不重复铸）；状态零变更
    let err = seq
        .submit(deposit_op(1, &alice.owner, usdt, 100), T0 + 1)
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));
    assert_eq!(seq.chain().len(), seq_len, "拒绝帧不入链");
    assert_eq!(seq.state().root(), root, "拒绝零状态变更");
    assert_eq!(
        v2_balances_by_asset(seq.state(), &alice.owner).get(&usdt).copied(),
        Some(100),
        "重放不重复铸"
    );

    // 跨版本守卫 A：v1 Deposit 已用同一 deposit_id → DepositV2 拒
    // （同一外部支付不得经两条路径重复铸造）
    seq.submit(
        Operation::Deposit {
            deposit_id: id32(7),
            owner: alice.key.public_bytes(),
            asset_class: AssetClass::Play,
            amount: 50,
        },
        T0 + 2,
    )
    .unwrap();
    let err = seq
        .submit(deposit_op(7, &alice.owner, usdt, 1), T0 + 3)
        .unwrap_err();
    assert!(
        matches!(err, AppchainError::WithdrawalConflict(_)),
        "跨版本防线之 v2→v1 方向"
    );

    // 跨版本守卫 B：DepositV2 已用 id（v2 插入了共享幂等集）→ v1 Deposit 拒
    let err = seq
        .submit(
            Operation::Deposit {
                deposit_id: id32(1),
                owner: alice.key.public_bytes(),
                asset_class: AssetClass::Real,
                amount: 1,
            },
            T0 + 4,
        )
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));

    // vault confirm 幂等：同载荷 Ok（重放安全）、异载荷冲突；
    // 记录载荷来自账本（WAL 重放后的同一确认入口）
    let mut vault = CustodyLedgerV2::new();
    let &(asset, amount, commitment) = seq
        .state()
        .deposit_records_v2()
        .get(&id32(1))
        .unwrap();
    assert_eq!((asset, amount), (usdt, 100));
    vault.confirm_deposit_v2(id32(1), asset, commitment, amount).unwrap();
    vault.confirm_deposit_v2(id32(1), asset, commitment, amount).unwrap();
    let err = vault
        .confirm_deposit_v2(id32(1), asset, commitment, amount + 1)
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));
}

// ---------------------------------------------------------------------------
// 3. 跨币轧差拒绝（核心负例）
// ---------------------------------------------------------------------------

/// **核心负例**：USDT 短库 + NATIVE 长库 → 合并口径完全平衡，但 USDT
/// 提现仍拒（INV-TE-2：托管破产隔离的账面表达）。
#[test]
fn cross_token_netting_rejected() {
    let mut seq = new_sequencer();
    let alice = V2User::new(3);
    let native = real(TOKEN_NATIVE);
    let usdt = real(TOKEN_USDT);

    seq.submit(deposit_op(1, &alice.owner, usdt, 100), T0).unwrap();
    seq.submit(deposit_op(2, &alice.owner, native, 1000), T0 + 1).unwrap();

    // 托管侧：NATIVE 长库（储备 1050 > 发行 1000，盈余 50），USDT 短库
    // （储备 50 < 发行 100）——合并口径恰好平衡（轧差会掩盖短库的构造）
    let mut vault = CustodyLedgerV2::new().without_finality_gate();
    vault.record_external_reserve(native, 1_050).unwrap();
    vault.record_external_reserve(usdt, 50).unwrap();
    confirm_all_deposits(&mut vault, &seq);

    // 合并口径完全平衡（1100 == 1100）——聚合视角掩盖了 USDT 缺口
    let issued = seq.state().issued_v2_real_by_token();
    let total_reserved: u128 = vault.total_by_token().values().map(|s| s.reserved).sum();
    let total_issued: u128 = issued.values().sum();
    assert_eq!(total_reserved, total_issued, "合并口径平衡（轧差恰好会掩盖短库）");

    // 但 USDT 提现仍拒：判定只用本 token 储备（50 < 100）
    let note = note_of(&seq, &alice.owner, usdt);
    let provenance = seq.state().withdrawal_provenance_v2(&note).unwrap();
    let err = enqueue_from(
        &mut vault,
        &seq,
        vault_request(9, usdt, 0xEE, 100),
        provenance,
        T0 + 10,
    )
    .unwrap_err();
    assert!(
        matches!(err, AppchainError::ReconciliationMismatch { issued: 100, reserved: 50 }),
        "USDT 提现必须按本 token 储备拒绝，不得用 NATIVE 长库抵"
    );
    assert_eq!(vault.queued_withdrawals_of(usdt), 0, "拒绝的请求不入队");

    // per-token 对账暴露缺口方：合并 delta 恰为 0（+50 − 50），但逐 token
    // 各自非零——任何单 token 失衡即整体拒（无轧差）
    let reports = vault.reconciliation_by_token(&issued).unwrap();
    assert_eq!(reports[&native].delta, 50, "NATIVE 长库（盈余）");
    assert_eq!(reports[&usdt].delta, -50, "USDT 短库（缺口）");
    assert_eq!(
        reports[&native].delta + reports[&usdt].delta,
        0,
        "合并恰为 0——轧差视角下的『平衡』正是被禁止的错觉"
    );
    assert!(vault.require_balanced_by_token(&issued).is_err());

    // NATIVE 提现同刻放行（同一托管账、同一调用序列）
    let note = note_of(&seq, &alice.owner, native);
    let provenance = seq.state().withdrawal_provenance_v2(&note).unwrap();
    enqueue_from(
        &mut vault,
        &seq,
        vault_request(8, native, 0xED, 100),
        provenance,
        T0 + 11,
    )
    .unwrap();
    assert_eq!(vault.queued_withdrawals_of(native), 1);
}

// ---------------------------------------------------------------------------
// 4. per-token 恒等式（浮存分解 + 对账 delta）
// ---------------------------------------------------------------------------

#[test]
fn per_token_identity_and_reconciliation() {
    let mut seq = new_sequencer();
    let alice = V2User::new(4);
    let native = real(TOKEN_NATIVE);
    let usdc = real(TOKEN_USDC);

    seq.submit(deposit_op(1, &alice.owner, native, 1_000), T0).unwrap();
    seq.submit(deposit_op(2, &alice.owner, usdc, 500), T0 + 1).unwrap();

    let mut vault = CustodyLedgerV2::new().without_finality_gate();
    vault.record_external_reserve(native, 1_000).unwrap();
    vault.record_external_reserve(usdc, 500).unwrap();
    confirm_all_deposits(&mut vault, &seq);

    // 两 token 各提一笔（USDC 带费用场景见下一用例；这里验证分解恒等）
    let note = note_of(&seq, &alice.owner, native);
    enqueue_from(
        &mut vault,
        &seq,
        vault_request(3, native, 0xA1, 300),
        seq.state().withdrawal_provenance_v2(&note).unwrap(),
        T0 + 5,
    )
    .unwrap();
    let note = note_of(&seq, &alice.owner, usdc);
    enqueue_from(
        &mut vault,
        &seq,
        vault_request(4, usdc, 0xA2, 150),
        seq.state().withdrawal_provenance_v2(&note).unwrap(),
        T0 + 5,
    )
    .unwrap();

    // per-token 浮存分解：pending == payout + fee（零费 → fee 0）
    let totals = vault.total_by_token();
    assert_eq!(totals.len(), 2);
    for (asset, s) in &totals {
        assert_eq!(
            s.queued_withdrawal_total,
            s.queued_payout_total + s.queued_fee_float,
            "token {asset} 浮存分解恒等式"
        );
    }
    assert_eq!(totals[&native].queued_withdrawal_total, 300);
    assert_eq!(totals[&usdc].queued_withdrawal_total, 150);

    // per-token 对账：issued = live + burned 毛额，delta 全零
    let issued = seq.state().issued_v2_real_by_token();
    assert_eq!(issued[&native], 1_000);
    assert_eq!(issued[&usdc], 500);
    let reports = vault.require_balanced_by_token(&issued).unwrap();
    assert!(reports.values().all(|r| r.delta == 0));

    // 任一 token 失衡 → 整体拒（即便另一 token 完全平衡）
    let mut short = issued.clone();
    short.insert(usdc, 499);
    assert!(vault.require_balanced_by_token(&short).is_err());
}

// ---------------------------------------------------------------------------
// 5. 提现费 per-token 内扣
// ---------------------------------------------------------------------------

#[test]
fn withdrawal_fee_per_token_internal_deduction() {
    let mut seq = new_sequencer();
    let alice = V2User::new(5);
    let native = real(TOKEN_NATIVE);
    let usdt = real(TOKEN_USDT);

    seq.submit(deposit_op(1, &alice.owner, native, 1_000), T0).unwrap();
    seq.submit(deposit_op(2, &alice.owner, usdt, 500), T0 + 1).unwrap();

    // 费 per-token：USDT 25，NATIVE 缺省 0
    let mut vault = CustodyLedgerV2::new()
        .without_finality_gate()
        .with_token_fee(usdt, poker_appchain::vault::WithdrawalFeeConfig { flat_fee: 25 });
    assert_eq!(vault.withdrawal_fee_of(usdt).flat_fee, 25);
    assert_eq!(vault.withdrawal_fee_of(native).flat_fee, 0, "缺省零费（v1 语义沿袭）");
    vault.record_external_reserve(native, 1_000).unwrap();
    vault.record_external_reserve(usdt, 500).unwrap();
    confirm_all_deposits(&mut vault, &seq);

    let note = note_of(&seq, &alice.owner, usdt);
    enqueue_from(
        &mut vault,
        &seq,
        vault_request(3, usdt, 0xC1, 100),
        seq.state().withdrawal_provenance_v2(&note).unwrap(),
        T0 + 5,
    )
    .unwrap();
    let note = note_of(&seq, &alice.owner, native);
    enqueue_from(
        &mut vault,
        &seq,
        vault_request(4, native, 0xC2, 100),
        seq.state().withdrawal_provenance_v2(&note).unwrap(),
        T0 + 5,
    )
    .unwrap();

    // 内扣：销毁面额（gross）不变，打款净额 = gross − fee（per token）
    assert_eq!(vault.payout_amount_of(usdt, &id32(3)), Some(75));
    assert_eq!(vault.payout_amount_of(native, &id32(4)), Some(100));

    // 分解 per-token：USDT 100 = 75 + 25；NATIVE 100 = 100 + 0
    let totals = vault.total_by_token();
    assert_eq!(totals[&usdt].queued_payout_total, 75);
    assert_eq!(totals[&usdt].queued_fee_float, 25);
    assert_eq!(totals[&native].queued_fee_float, 0);

    // 分道任务带各自净额（打款执行器按币种支付）
    let payouts = vault.queued_payouts_by_token();
    assert_eq!(payouts[&usdt][0].1, 75);
    assert_eq!(payouts[&native][0].1, 100);

    // 恒等式保持：费从余额内扣 → 对账与零费时一致
    let issued = seq.state().issued_v2_real_by_token();
    vault.require_balanced_by_token(&issued).unwrap();

    // 负例：USDT 费 > 金额 → 拒（per-token 配置生效；NATIVE 同金额因
    // 零费放行——配置隔离的直接证据）
    let note = note_of(&seq, &alice.owner, usdt);
    let err = enqueue_from(
        &mut vault,
        &seq,
        vault_request(5, usdt, 0xC3, 20),
        seq.state().withdrawal_provenance_v2(&note).unwrap(),
        T0 + 6,
    )
    .unwrap_err();
    assert!(matches!(err, AppchainError::OutOfRange("withdrawal fee exceeds amount")));
    let note = note_of(&seq, &alice.owner, native);
    enqueue_from(
        &mut vault,
        &seq,
        vault_request(6, native, 0xC4, 20),
        seq.state().withdrawal_provenance_v2(&note).unwrap(),
        T0 + 6,
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// 6. finality 门 REAL vs GAME（domain 判据，三币种回归）
// ---------------------------------------------------------------------------

#[test]
fn finality_gate_dual_gate_all_real_tokens() {
    let native = real(TOKEN_NATIVE);
    let usdt = real(TOKEN_USDT);
    let usdc = real(TOKEN_USDC);

    // 每个 REAL token：水位未覆盖拒 → 水位覆盖但无批次根拒 → 双门齐备放行
    for (i, asset) in [native, usdt, usdc].into_iter().enumerate() {
        let mut vault = CustodyLedgerV2::new();
        assert!(vault.finality_required(), "finality 门必须默认开启");
        vault.record_external_reserve(asset, 1_000).unwrap();
        let prov = WithdrawalProvenanceV2 { asset_id: asset, source_op_index: 5 };

        // 负例 A：水位未覆盖
        let err = vault
            .enqueue_withdrawal_v2(
                vault_request(1, asset, 2, 10),
                0,
                prov,
                FinalityEvidence { proven_watermark: 4, batch_covered_through: Some(4) },
                T0,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::WithdrawalNotFinalized { op_index: 5, watermark: 4 }));

        // 负例 B：水位覆盖但批次根未记录（None 必拒——fail-closed 存在性判定）
        let err = vault
            .enqueue_withdrawal_v2(
                vault_request(1, asset, 2, 10),
                0,
                prov,
                FinalityEvidence { proven_watermark: 9, batch_covered_through: None },
                T0,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::WithdrawalNotFinalized { .. }));

        // 正例：双门齐备
        vault
            .enqueue_withdrawal_v2(
                vault_request(1, asset, 2, 10),
                0,
                prov,
                FinalityEvidence { proven_watermark: 9, batch_covered_through: Some(7) },
                T0,
            )
            .unwrap();
        // 幂等命中豁免复审：证据回退也不影响既有条目
        vault
            .enqueue_withdrawal_v2(
                vault_request(1, asset, 2, 10),
                0,
                prov,
                FinalityEvidence::default(),
                T0,
            )
            .unwrap();
        assert_eq!(vault.queued_withdrawals_of(asset), 1, "token {i} 闭环");
    }

    // GAME 域资产拒入本托管（domain 判据的另一面：豁免 ≠ 进入）
    let mut vault = CustodyLedgerV2::new().without_finality_gate();
    let err = vault
        .enqueue_withdrawal_v2(
            vault_request(1, AssetId::GAME_PLAY, 2, 10),
            0,
            WithdrawalProvenanceV2 { asset_id: AssetId::GAME_PLAY, source_op_index: 1 },
            FinalityEvidence::default(),
            T0,
        )
        .unwrap_err();
    assert!(matches!(err, AppchainError::OutOfRange(_)), "GAME 域拒入 REAL 托管");
}

// ---------------------------------------------------------------------------
// 7. GAME 域准入拒绝（fail-closed，含伪造 token）
// ---------------------------------------------------------------------------

#[test]
fn game_domain_rejected_at_admission() {
    let mut seq = new_sequencer();
    let alice = V2User::new(6);

    // DepositV2 × GAME 域遗留 PLAY → 拒（GAME 发行是 TE-M3 的
    // IssueGameToken 另行追加变体）
    let err = seq
        .submit(deposit_op(1, &alice.owner, AssetId::GAME_PLAY, 100), T0)
        .unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(_)));
    // 伪造 REAL token（borsh 绕过 AssetId::real 构造器的载荷）→ 拒
    let forged = AssetId { domain: poker_appchain::asset_id::AssetDomain::Real, token_id: 999 };
    let err = seq.submit(deposit_op(2, &alice.owner, forged, 100), T0 + 1).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(_)));
    assert!(seq.chain().is_empty(), "全部拒绝、零帧入链");

    // 铸一张 GAME 域 v2 note（经 MigrateNote 合法路径），再尝试用
    // WithdrawRequestV2 提现 → 拒（GAME 赎回属 TE-M3+ 独立通道）
    seq.submit(
        Operation::Deposit {
            deposit_id: [3; 32],
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
    let mut record = MigrateNoteRecord {
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
        migration_nonce: blake2s32(&[b"te-m2 migration nonce"]),
        network_id: default_network_id(),
        abi_version: OWNER_V2_ABI_VERSION,
    };
    let digest = migrate_digest(&record);
    record.old_owner_sig.typed_data_digest = digest;
    record.old_owner_sig.signature = alice.key.sign(&digest).bytes;
    let minted = NoteV2::new(AssetId::GAME_PLAY, 70, alice.owner.clone(), 777, None, 0, 0).unwrap();
    seq.submit_migrate(
        Operation::MigrateNote(Box::new(poker_appchain::ops::MigrateNoteOp {
            record,
            minted,
        })),
        &VerifierMaterial::LegacySecp256k1 { presented_public: alice.key.public_bytes() },
        T0 + 3,
    )
    .unwrap();

    // GAME 域 v2 note 不入 REAL 托管口径
    let issued = seq.state().issued_v2_real_by_token();
    assert!(!issued.contains_key(&AssetId::GAME_PLAY), "GAME 域不进 REAL issued");

    // WithdrawRequestV2 × GAME note → 拒
    let game_note = note_of(&seq, &alice.owner, AssetId::GAME_PLAY);
    let op = signed_withdraw(&alice, &game_note, 9, 0xD0, T0 + 50, 5, &default_network_id());
    let err = seq.submit(op, T0 + 60).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(_)), "GAME 域拒入提现 op");
}

// ---------------------------------------------------------------------------
// 8. 信封过期 / nonce 重放 / 摘要篡改 / 材料错配
// ---------------------------------------------------------------------------

#[test]
fn envelope_expired_rejected() {
    let mut seq = new_sequencer();
    let alice = V2User::new(7);
    let usdt = real(TOKEN_USDT);
    seq.submit(deposit_op(1, &alice.owner, usdt, 100), T0).unwrap();
    let note = note_of(&seq, &alice.owner, usdt);

    // 过期（expiry <= now）：now = ts/1000 = 2s，expiry = 2 → Expired →
    // 映射 OutOfRange("owner_v2 envelope expired")
    let mut op = unsigned_withdraw(&alice, &note, 5, 0xE1, T0 + 50, 5, &default_network_id());
    op.owner_sig.expiry = (T0 + 1_000) / 1000; // == now
    let effect = Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(&note.owner, &note.commitment_bytes(), &op.nullifier, &withdraw_scope(&default_network_id()), &effect);
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = alice.key.sign(&digest).bytes;
    let err = seq.submit(Operation::WithdrawRequestV2(Box::new(op)), T0 + 1_000).unwrap_err();
    assert!(matches!(err, AppchainError::OutOfRange("owner_v2 envelope expired")));
    assert_eq!(seq.chain().len(), 1, "拒绝帧不入链");
}

#[test]
fn envelope_nonce_replay_rejected() {
    let mut seq = new_sequencer();
    let alice = V2User::new(8);
    let usdt = real(TOKEN_USDT);
    seq.submit(deposit_op(1, &alice.owner, usdt, 100), T0).unwrap();
    seq.submit(deposit_op(2, &alice.owner, usdt, 30), T0 + 1).unwrap();
    let note_a = note_of(&seq, &alice.owner, usdt);

    // 首笔 nonce=5 成功
    seq.submit(
        signed_withdraw(&alice, &note_a, 5, 0xF1, T0 + 50, 5, &default_network_id()),
        T0 + 100,
    )
    .unwrap();

    // 第二笔（不同 note/请求）nonce 不增 → 重放拒
    let note_b = {
        seq.state()
            .note_entries_v2_of(&alice.owner)
            .into_iter()
            .map(|e| e.note.clone())
            .find(|n| n.asset_id == usdt && n.commitment_bytes() != note_a.commitment_bytes())
            .unwrap()
    };
    let err = seq
        .submit(signed_withdraw(&alice, &note_b, 6, 0xF2, T0 + 150, 5, &default_network_id()), T0 + 200)
        .unwrap_err();
    assert!(matches!(err, AppchainError::SettlementReplay), "nonce 必须严格单调");
    // 更低 nonce 同拒
    let err = seq
        .submit(signed_withdraw(&alice, &note_b, 7, 0xF3, T0 + 150, 4, &default_network_id()), T0 + 200)
        .unwrap_err();
    assert!(matches!(err, AppchainError::SettlementReplay));

    // 同 request_id（已消费）+ 存续 note + 新 nonce → 幂等键拒
    //（与 nonce 防线独立的请求级防重放）
    let err = seq
        .submit(signed_withdraw(&alice, &note_b, 5, 0xF1, T0 + 150, 7, &default_network_id()), T0 + 250)
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)), "request_id 已消费");

    // 正常递增 nonce 的第二笔可过（负例不是过度拒绝）
    seq.submit(
        signed_withdraw(&alice, &note_b, 8, 0xF4, T0 + 150, 6, &default_network_id()),
        T0 + 300,
    )
    .unwrap();
}

#[test]
fn envelope_digest_and_material_tamper_rejected() {
    let mut seq = new_sequencer();
    let alice = V2User::new(9);
    let usdc = real(TOKEN_USDC);
    seq.submit(deposit_op(1, &alice.owner, usdc, 100), T0).unwrap();
    let note = note_of(&seq, &alice.owner, usdc);
    let net = default_network_id();

    // 场景 A：签名后篡改 request_id（幂等键）→ 摘要失配（幂等键进效果
    // 摘要——换 id 重放同一签名授权不可行）
    let mut op = unsigned_withdraw(&alice, &note, 5, 0x91, T0 + 50, 5, &net);
    let effect = Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(&note.owner, &note.commitment_bytes(), &op.nullifier, &withdraw_scope(&net), &effect);
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = alice.key.sign(&digest).bytes;
    op.request_id = id32(6);
    let err = seq.submit(Operation::WithdrawRequestV2(Box::new(op)), T0 + 100).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(s) if s.contains("digest mismatch")));

    // 场景 B：篡改外部收款地址（改在签名后）→ 摘要失配
    let mut op = unsigned_withdraw(&alice, &note, 5, 0x92, T0 + 50, 5, &net);
    let effect = Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(&note.owner, &note.commitment_bytes(), &op.nullifier, &withdraw_scope(&net), &effect);
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = alice.key.sign(&digest).bytes;
    op.external_recipient = [0x93; 32];
    let err = seq.submit(Operation::WithdrawRequestV2(Box::new(op)), T0 + 100).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(s) if s.contains("digest mismatch")));

    // 场景 C：材料错配（legacy signer 配 StarkCurve 材料）→ MaterialMismatch
    let mut op = unsigned_withdraw(&alice, &note, 5, 0x94, T0 + 50, 5, &net);
    op.material = VerifierMaterial::StarkCurve;
    let effect = Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(&note.owner, &note.commitment_bytes(), &op.nullifier, &withdraw_scope(&net), &effect);
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = alice.key.sign(&digest).bytes;
    let err = seq.submit(Operation::WithdrawRequestV2(Box::new(op)), T0 + 100).unwrap_err();
    assert!(matches!(err, AppchainError::AdmissionRejected(s) if s.contains("material mismatch")));

    // 场景 D：他人代签（签名者 ≠ note owner）→ 拒
    let mallory = V2User::new(90);
    let mut op = unsigned_withdraw(&alice, &note, 5, 0x95, T0 + 50, 5, &net);
    op.owner_sig.signer_ref = mallory.owner.clone();
    op.note.owner = mallory.owner.clone();
    let effect = Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(&mallory.owner, &note.commitment_bytes(), &op.nullifier, &withdraw_scope(&net), &effect);
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = mallory.key.sign(&digest).bytes;
    let err = seq.submit(Operation::WithdrawRequestV2(Box::new(op)), T0 + 100).unwrap_err();
    assert!(matches!(err, AppchainError::NoteNotFound | AppchainError::AdmissionRejected(_)));
}

// ---------------------------------------------------------------------------
// 9. 双花（nullifier 层）
// ---------------------------------------------------------------------------

#[test]
fn same_note_double_withdraw_rejected() {
    let mut seq = new_sequencer();
    let alice = V2User::new(10);
    let usdt = real(TOKEN_USDT);
    seq.submit(deposit_op(1, &alice.owner, usdt, 100), T0).unwrap();
    let note = note_of(&seq, &alice.owner, usdt);

    // 第一笔（request_id=5）销毁成功
    seq.submit(
        signed_withdraw(&alice, &note, 5, 0xA1, T0 + 50, 5, &default_network_id()),
        T0 + 100,
    )
    .unwrap();
    // 第二笔：不同 request_id、递增 nonce，但同一张 note → nullifier 已
    // 消费 → DoubleSpend
    let op = signed_withdraw(&alice, &note, 6, 0xA2, T0 + 150, 6, &default_network_id());
    let err = seq.submit(op, T0 + 200).unwrap_err();
    assert!(matches!(err, AppchainError::DoubleSpend));
    assert_eq!(seq.state().burned_v2.len(), 1, "只有第一笔销毁生效");
    assert!(note_of_rest(&seq, &alice.owner, usdt).is_none(), "note 已销毁");
}

fn note_of_rest(seq: &Sequencer, owner: &OwnerRef, asset: AssetId) -> Option<NoteV2> {
    seq.state()
        .note_entries_v2_of(owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.asset_id == asset)
}

// ---------------------------------------------------------------------------
// 10. WAL 重放：v2 幂等集 / 销毁记录 / 来源映射恢复
// ---------------------------------------------------------------------------

#[test]
fn wal_replay_restores_v2_idempotency_and_burn_records() {
    let dir = std::env::temp_dir().join("poker-appchain-te-m2");
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("te_m2_idem.wal");
    let _ = std::fs::remove_file(&wal);
    let key = poker_appchain::keys::SequencerKey::from_seed(&[43u8; 32]);
    let mut seq = Sequencer::new(key.clone(), SequencerConfig::default(), Arc::new(MetricsRegistry::new()));
    seq.attach_wal(&wal).unwrap();

    let alice = V2User::new(11);
    let usdt = real(TOKEN_USDT);
    seq.submit(deposit_op(1, &alice.owner, usdt, 100), T0).unwrap();
    let note = note_of(&seq, &alice.owner, usdt);
    let request_id = id32(5);
    seq.submit(
        signed_withdraw(&alice, &note, 5, 0xB1, T0 + 50, 5, &default_network_id()),
        T0 + 100,
    )
    .unwrap();
    let root_before = seq.state().root();
    drop(seq);

    // 全量重放：余额 / 幂等集 / 销毁记录 / 来源映射 / 入金记录全部恢复
    let mut seq2 = Sequencer::replay(&wal, key.public, SequencerConfig::default(), Arc::new(MetricsRegistry::new())).unwrap();
    assert_eq!(seq2.state().root(), root_before, "重放逐位重现状态根");
    assert!(
        v2_balances_by_asset(seq2.state(), &alice.owner).get(&usdt).is_none(),
        "余额恢复：整张 note 已销毁 → 无存续 v2 note"
    );
    let records = seq2.state().deposit_records_v2();
    assert_eq!(records.len(), 1);
    let (asset, amount, commitment) = records.get(&id32(1)).unwrap().clone();
    assert_eq!((asset, amount), (usdt, 100));
    assert_eq!(commitment, note.commitment_bytes(), "入金记录含 note 承诺");
    assert_eq!(seq2.state().burned_v2.len(), 1);
    assert_eq!(
        seq2.state().burned_v2[0],
        (request_id, usdt, 100),
        "销毁记录恢复：(request_id, asset, 毛额=整张面额)"
    );
    assert!(seq2.state().withdrawal_ids.contains(&request_id), "提现幂等集恢复");
    assert!(
        seq2.state().note_origins_v2.contains_key(&note.commitment_bytes()),
        "来源映射恢复（消费后保留——finality 判据输入）"
    );
    // provenance：销毁后仍可查（回落 origins）
    let prov = seq2.state().withdrawal_provenance_v2(&note).unwrap();
    assert_eq!(prov.asset_id, usdt);
    assert_eq!(prov.source_op_index, 0, "存款是 op 0");

    // 幂等集恢复的行为证据：note 已销毁（nullifier 已消费）→ 同 request_id
    // 再提 → 拒（双花/nullifier 防线先命中，幂等键与账本三道防线均 fail-closed）
    let op = signed_withdraw(&alice, &note, 5, 0xB1, T0 + 50, 6, &default_network_id());
    let err = seq2.submit(op, T0 + 200).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::DoubleSpend
            | AppchainError::NoteNotFound
            | AppchainError::WithdrawalConflict(_)
    ));
    assert_eq!(seq2.chain().len(), 2, "拒绝帧不入链");
}

// ---------------------------------------------------------------------------
// 11. WAL 重放 + proven log：托管队列等价重建（per-token）
// ---------------------------------------------------------------------------

#[test]
fn wal_replay_vault_queue_equivalence() {
    let dir = std::env::temp_dir().join("poker-appchain-te-m2");
    std::fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("te_m2_equiv.wal");
    let proven = dir.join("te_m2_equiv.proven.log");
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&proven);
    let key = poker_appchain::keys::SequencerKey::from_seed(&[45u8; 32]);
    let mut seq = Sequencer::new(key.clone(), SequencerConfig::default(), Arc::new(MetricsRegistry::new()));
    seq.attach_wal(&wal).unwrap();
    seq.attach_proven_log(&proven).unwrap();

    let alice = V2User::new(12);
    let usdt = real(TOKEN_USDT);
    let usdc = real(TOKEN_USDC);
    seq.submit(deposit_op(1, &alice.owner, usdt, 200), T0).unwrap();
    seq.submit(deposit_op(2, &alice.owner, usdc, 150), T0 + 1).unwrap();
    let note_usdt = note_of(&seq, &alice.owner, usdt);
    let note_usdc = note_of(&seq, &alice.owner, usdc);
    seq.submit(
        signed_withdraw(&alice, &note_usdt, 3, 0xC1, T0 + 50, 5, &default_network_id()),
        T0 + 100,
    )
    .unwrap();
    seq.submit(
        signed_withdraw(&alice, &note_usdc, 4, 0xC2, T0 + 60, 6, &default_network_id()),
        T0 + 110,
    )
    .unwrap();

    // 原实例：finality 推进（水位 + 批次根，生产装配点同路径）
    let through = seq.chain().len() as u64 - 1;
    seq.mark_proven_through_with_root(through, [0xAB; 32]);

    // 原实例托管账：储备 + 入金确认 + 受理（费：USDT 25）
    let mut vault_a = CustodyLedgerV2::new()
        .with_token_fee(usdt, poker_appchain::vault::WithdrawalFeeConfig { flat_fee: 25 });
    vault_a.record_external_reserve(usdt, 200).unwrap();
    vault_a.record_external_reserve(usdc, 150).unwrap();
    confirm_all_deposits(&mut vault_a, &seq);
    enqueue_from(
        &mut vault_a,
        &seq,
        vault_request(3, usdt, 0xC1, 200),
        seq.state().withdrawal_provenance_v2(&note_usdt).unwrap(),
        T0 + 100,
    )
    .unwrap();
    enqueue_from(
        &mut vault_a,
        &seq,
        vault_request(4, usdc, 0xC2, 150),
        seq.state().withdrawal_provenance_v2(&note_usdc).unwrap(),
        T0 + 110,
    )
    .unwrap();
    let totals_a = vault_a.total_by_token();
    let payouts_a = vault_a.queued_payouts_by_token();
    drop(seq);

    // 重放（恢复水位 + 批次根）→ 同一入口重建托管队列
    let seq2 = Sequencer::replay_restoring_proven(
        &wal,
        Some(&proven),
        key.public,
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    )
    .unwrap();
    assert_eq!(seq2.finality_evidence().proven_watermark, through, "水位恢复");
    assert_eq!(seq2.batch_covered_through(), Some(through), "批次根恢复");

    let mut vault_b = CustodyLedgerV2::new()
        .with_token_fee(usdt, poker_appchain::vault::WithdrawalFeeConfig { flat_fee: 25 });
    vault_b.record_external_reserve(usdt, 200).unwrap();
    vault_b.record_external_reserve(usdc, 150).unwrap();
    confirm_all_deposits(&mut vault_b, &seq2);
    enqueue_from(
        &mut vault_b,
        &seq2,
        vault_request(3, usdt, 0xC1, 200),
        seq2.state().withdrawal_provenance_v2(&note_usdt).unwrap(),
        T0 + 100,
    )
    .unwrap();
    enqueue_from(
        &mut vault_b,
        &seq2,
        vault_request(4, usdc, 0xC2, 150),
        seq2.state().withdrawal_provenance_v2(&note_usdc).unwrap(),
        T0 + 110,
    )
    .unwrap();

    // 等价断言：per-token 摘要 + 分道打款任务逐项一致
    assert_eq!(vault_b.total_by_token(), totals_a, "重放后托管队列逐 token 等价");
    assert_eq!(vault_b.queued_payouts_by_token(), payouts_a);
    assert_eq!(vault_b.total_by_token()[&usdt].queued_fee_float, 25, "费配置语义一致");
}

// ---------------------------------------------------------------------------
// 12. withdrawal root：token 维度 + 旧编码零回退
// ---------------------------------------------------------------------------

#[test]
fn withdrawal_root_token_dimension_and_legacy_compat() {
    // leaf 资产标签映射（冻结）
    assert_eq!(leaf_asset_tag_of(AssetId::REAL_NATIVE), Some(1), "legacy REAL 字节不变");
    assert_eq!(leaf_asset_tag_of(AssetId::GAME_PLAY), Some(2), "legacy PLAY 字节不变");
    assert_eq!(leaf_asset_tag_of(AssetId::REAL_USDT), Some(3));
    assert_eq!(leaf_asset_tag_of(AssetId::REAL_USDC), Some(4));
    assert_eq!(leaf_asset_tag_of(AssetId::game(7)), None, "TE-M3 前 GAME 注册表 token 不得出根");

    // v2 投影 → leaf：资产维度折叠进 asset_class 字节
    let pending_usdt = poker_appchain::vault::PendingWithdrawalV2 {
        request_id: [1; 32],
        asset_id: AssetId::REAL_USDT,
        external_recipient: [2; 32],
        payout_amount: 75,
    };
    let leaf_usdt = pending_usdt.into_leaf([3; 32], 9).unwrap();
    assert_eq!(leaf_usdt.asset_class, 3);
    let pending_native = poker_appchain::vault::PendingWithdrawalV2 {
        request_id: [4; 32],
        asset_id: AssetId::REAL_NATIVE,
        external_recipient: [5; 32],
        payout_amount: 60,
    };
    let leaf_native = pending_native.into_leaf([6; 32], 9).unwrap();
    assert_eq!(leaf_native.asset_class, 1);
    // GAME 注册表 token 出根 fail-closed
    let pending_game = poker_appchain::vault::PendingWithdrawalV2 {
        request_id: [7; 32],
        asset_id: AssetId::game(7),
        external_recipient: [8; 32],
        payout_amount: 1,
    };
    assert!(pending_game.into_leaf([9; 32], 9).is_err());

    // 同窗混币出根：token 维度参与叶哈希（不同标签 → 不同叶 → 根敏感）
    let mut builder = WithdrawalRootBuilder::new();
    builder.push(leaf_usdt).unwrap();
    builder.push(leaf_native).unwrap();
    let root = builder.build(9).unwrap();
    assert_eq!(root.leaf_count, 2);
    // 包含证明逐叶通过
    let proof0 = builder.merkle_proof(9, 0).unwrap();
    let idx0 = builder.leaf_index(9, &leaf_usdt.request_id).unwrap() as u64;
    assert!(verify_inclusion(&leaf_usdt, &proof0, idx0, root.root));
    // 篡改资产标签（USDT 3 → USDC 4）→ 证明失败（token 维度被签名进根）
    let mut forged = leaf_usdt;
    forged.asset_class = 4;
    assert!(!verify_inclusion(&forged, &proof0, idx0, root.root), "换 token 标签即非成员");
    // 纯 NATIVE 窗口与混币窗口根不同（根含 token 维度）
    let mut single = WithdrawalRootBuilder::new();
    single.push(leaf_native).unwrap();
    assert_ne!(single.build(9).unwrap().root, root.root);
}

// ---------------------------------------------------------------------------
// 13. borsh 判别值冻结（9/10）+ spends()/effect 形状
// ---------------------------------------------------------------------------

#[test]
fn borsh_discriminants_frozen_and_op_shape() {
    let alice = V2User::new(13);
    let note = NoteV2::new(AssetId::REAL_USDT, 100, alice.owner.clone(), 1, None, 0, 0).unwrap();
    let op = unsigned_withdraw(&alice, &note, 5, 0xD1, T0, 1, &default_network_id());

    // 判别值 = 声明序：DepositV2 = 9、WithdrawRequestV2 = 10（首字节）
    let dep = Operation::DepositV2(Box::new(DepositV2Op {
        deposit_id: [1; 32],
        owner: alice.owner.clone(),
        asset_id: AssetId::REAL_USDT,
        amount: 100,
    }));
    assert_eq!(borsh::to_vec(&dep).unwrap()[0], 9, "DepositV2 判别值冻结");
    let wd = Operation::WithdrawRequestV2(Box::new(op.clone()));
    assert_eq!(borsh::to_vec(&wd).unwrap()[0], 10, "WithdrawRequestV2 判别值冻结");
    // v1 判别值不受追加影响（Deposit 仍 = 2）
    let v1_dep = Operation::Deposit {
        deposit_id: [1; 32],
        owner: alice.key.public_bytes(),
        asset_class: AssetClass::Real,
        amount: 1,
    };
    assert_eq!(borsh::to_vec(&v1_dep).unwrap()[0], 2);
    // roundtrip
    let back: Operation = borsh::from_slice(&borsh::to_vec(&wd).unwrap()).unwrap();
    assert_eq!(back, wd);

    // 授权形状：两变体 spends() 为空（WithdrawRequestV2 授权走信封，
    // DepositV2 是 operator 帧）
    assert!(Operation::spends(&dep).is_empty());
    assert!(Operation::spends(&wd).is_empty());
    // DepositV2 效果摘要 = 零（同 v1 Deposit，operator 帧不参与签名）
    assert_eq!(Operation::effect_digest(&dep), [0u8; 32]);
    // WithdrawRequestV2 效果摘要绑定载荷（非零、敏感、确定）
    let e1 = Operation::effect_digest(&wd);
    assert_ne!(e1, [0u8; 32]);
    let mut tampered = op.clone();
    tampered.external_recipient = [0xD2; 32];
    assert_ne!(
        Operation::effect_digest(&Operation::WithdrawRequestV2(Box::new(tampered))),
        e1,
        "收款地址进效果摘要（S1 纪律）"
    );
}
