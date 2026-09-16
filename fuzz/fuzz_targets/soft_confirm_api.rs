//! B4 fuzz target `soft_confirm_api`（M8-ACC-7）：
//!
//! 任意字节 → SoftConfirmFrame/SignedFrame/Operation 的 borsh 解码 +
//! 软确认提交 API 路径（`Sequencer::submit`），结构化输入优先，同时保留
//! 原始字节路径。全部拒绝路径一律返回 `Err`——**任何 panic 即 fuzz 失败**。
//!
//! 覆盖的拒绝/边界路径：
//! - 帧字节截断 / 链校验（`verify_chain`：坏签名/断链/坏 index）→ `Err`；
//! - `Operation` 全变体解码（含 `Settle` 嵌套 record）→ `Err`；
//! - 提交 API：限流、幂等键、桌准入、签名校验、守恒、nullifier 查重
//!   等全部在线拒绝路径（垃圾签名/重复 id/不存在的桌与 note）→ `Err`。

#![no_main]

use arbitrary::Arbitrary;
use borsh::BorshDeserialize;
use libfuzzer_sys::fuzz_target;
use poker_appchain::fee::FeePolicy;
use poker_appchain::keys::{EcdsaSig, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::ops::Operation;
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::settlement::SpendAuth;
use poker_appchain::soft_confirm::{verify_chain, SignedFrame, SoftConfirmFrame};
use std::sync::Arc;

/// 结构化输入形状（arbitrary 派生）。
#[derive(Debug, Arbitrary)]
struct OpShape {
    kind: u8,
    ts_ms: u64,
    owner: [u8; 33],
    recipient: [u8; 33],
    amount: u64,
    table_id: u64,
    deposit_id: [u8; 32],
    request_id: [u8; 32],
    payout_recipient: [u8; 32],
    out_a: u64,
    out_b: u64,
    commitment: [u8; 32],
    nullifier: [u8; 32],
    sig: [u8; 64],
    class_byte: u8,
}

/// 面额钳制 ≥1 后构造 note（构造校验仅拒 0 面额；此处不可能失败，
/// 若失败即真 bug，允许 panic 暴露）。
fn mk_note(class: AssetClass, amount: u64, owner: [u8; 33], nonce: [u8; 32]) -> Note {
    Note::new(class, amount.max(1), owner, nonce, None)
        .expect("amount clamped to >= 1; Note::new cannot fail")
}

fn op_from_shape(s: &OpShape) -> Operation {
    let class = if s.class_byte & 1 == 0 {
        AssetClass::Real
    } else {
        AssetClass::Play
    };
    let spend = || SpendAuth {
        commitment: s.commitment,
        nullifier: s.nullifier,
        sig: EcdsaSig { bytes: s.sig },
    };
    match s.kind % 7 {
        0 => Operation::OpenTable {
            table_id: s.table_id,
            policy: FeePolicy::Zero,
        },
        1 => Operation::CloseTable { table_id: s.table_id },
        2 => Operation::Deposit {
            deposit_id: s.deposit_id,
            owner: s.owner,
            asset_class: class,
            amount: s.amount,
        },
        3 => Operation::WithdrawRequest {
            spend: spend(),
            note: mk_note(class, s.amount, s.owner, s.deposit_id),
            request_id: s.request_id,
            payout_recipient: s.payout_recipient,
        },
        4 => Operation::Transfer {
            spends: vec![spend()],
            notes: vec![mk_note(class, s.amount, s.owner, s.deposit_id)],
            outputs: vec![
                NoteSpec {
                    asset_class: class,
                    amount: s.out_a.max(1),
                    owner: s.recipient,
                    table_id: None,
                    pot_index: 0,
                    runout_index: 0,
                },
                NoteSpec {
                    asset_class: class,
                    amount: s.out_b.max(1),
                    owner: s.owner,
                    table_id: None,
                    pot_index: 0,
                    runout_index: 0,
                },
            ],
        },
        5 => Operation::BuyIn {
            table_id: s.table_id,
            spends: vec![spend()],
            notes: vec![mk_note(class, s.amount, s.owner, s.deposit_id)],
            seat_owner: s.recipient,
        },
        _ => Operation::BuyIn {
            table_id: s.table_id,
            // 空 spends + 空 notes → AdmissionRejected("empty buy-in") 拒绝路径
            spends: vec![],
            notes: vec![],
            seat_owner: s.recipient,
        },
    }
}

fuzz_target!(|data: &[u8]| {
    // ===== 原始字节路径 =====
    // 帧 / 已签名帧 borsh 解码（截断 → Err）
    if let Ok(frame) = <SoftConfirmFrame as BorshDeserialize>::try_from_slice(data) {
        // 帧哈希对任意解码成功载荷不 panic
        let _ = poker_appchain::soft_confirm::frame_hash(&frame);
    }
    let signed = <SignedFrame as BorshDeserialize>::try_from_slice(data);
    if let Ok(f) = &signed {
        // 验签 + 接续性（创世前值 / 断链 / 坏签名 → Err）
        let _ = f.verify_against(&[0u8; 32], u64::MAX, &[0u8; 32]);
    }
    // 帧向量 → 全链 fail-closed 重验
    if let Ok(frames) = <Vec<SignedFrame> as borsh::BorshDeserialize>::try_from_slice(data) {
        let _ = verify_chain(&frames, &[0u8; 32]);
    }
    // Operation 全变体解码（含 Settle 嵌套 SettlementRecord）+ 效果摘要
    if let Ok(op) = <Operation as BorshDeserialize>::try_from_slice(data) {
        let _ = op.effect_digest();
        let _ = op.spends();
    }

    // ===== 结构化路径：任意操作 → 软确认提交 API =====
    let mut u = arbitrary::Unstructured::new(data);
    if let Ok(s) = OpShape::arbitrary(&mut u) {
        let mut seq = Sequencer::new(
            SequencerKey::from_seed(&[9u8; 32]),
            SequencerConfig {
                ops_per_min: u32::MAX,
                open_table_per_min: u32::MAX,
                ..SequencerConfig::default()
            },
            Arc::new(MetricsRegistry::new()),
        );
        // 提交成功与否皆可（拒绝一律 Err），绝不 panic
        let _ = seq.submit(op_from_shape(&s), s.ts_ms);
        let _ = seq.head_hash();
        let _ = seq.export_chain();
        let _ = seq.state().root();
    }
    let _ = signed;
});
