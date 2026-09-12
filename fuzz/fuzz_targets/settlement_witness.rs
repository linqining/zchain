//! B4 fuzz target `settlement_witness`（M8-ACC-7）：
//!
//! 任意字节 → SettlementRecord 的 borsh 解码 + `validate_settlement`
//! （配默认 Zero 策略）+ `settlement_binding` 摘要计算，结构化输入优先，
//! 同时保留原始字节路径。全部拒绝路径一律返回 `Err`——**任何 panic 即
//! fuzz 失败**。
//!
//! 覆盖的拒绝/边界路径：
//! - record 字节截断 / 嵌套结构（SettleInput/NoteSpec/plan/hand_proof）
//!   解码失败 → borsh `Err`；
//! - fail-closed 校验清单：零 hand_binding、空 inputs、plan 版本/边界/
//!   守恒/runout 投影、pot != plan.gross_pot、承诺不匹配、零 nullifier、
//!   垃圾 ECDSA 签名、费率不匹配、守恒破裂、分账缺失 → `Err`；
//! - `settlement_binding`/`payout_root`/`settle_effect` 摘要对任意解码
//!   成功载荷（含未通过校验的）必须可计算且确定。

#![no_main]

use arbitrary::Arbitrary;
use borsh::BorshDeserialize;
use libfuzzer_sys::fuzz_target;
use poker_appchain::fee::FeePolicy;
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::settlement::{
    flat_settlement_plan, payout_root_bytes, settle_effect, settlement_binding,
    validate_settlement, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};

/// 结构化输入形状（arbitrary 派生）：构造"形似合法"的双输入结算 witness
/// （垃圾签名/任意金额 → 走遍校验拒绝路径）。
#[derive(Debug, Arbitrary)]
struct WitnessShape {
    table_id: u64,
    hand_binding: [u8; 32],
    policy_commitment: [u8; 32],
    pot: u64,
    seat_a: [u8; 33],
    seat_b: [u8; 33],
    amount_a: u64,
    amount_b: u64,
    payout_a: u64,
    payout_b: u64,
    rake_total: u64,
    commitment_a: [u8; 32],
    commitment_b: [u8; 32],
    nullifier_a: [u8; 32],
    nullifier_b: [u8; 32],
    sig_a: [u8; 64],
    sig_b: [u8; 64],
    class_byte: u8,
    zero_binding: bool,
}

fn witness_from_shape(s: &WitnessShape) -> SettlementRecord {
    let class = if s.class_byte & 1 == 0 {
        AssetClass::Real
    } else {
        AssetClass::Play
    };
    let mk_note = |owner: [u8; 33], amount: u64, nonce: [u8; 32]| {
        Note::new(class, amount.max(1), owner, nonce, Some(s.table_id))
            .expect("amount clamped to >= 1; Note::new cannot fail")
    };
    let na = mk_note(s.seat_a, s.amount_a, s.commitment_a);
    let nb = mk_note(s.seat_b, s.amount_b, s.commitment_b);
    // `flat_settlement_plan` 的文档化调用方前置条件：Σawards ≤ gross_pot
    //（净额 = gross_pot - Σawards 全记为该层 rake）。构造侧满足之——
    // 违反前置条件的输入不属于本 target 的 fuzz 面（生产中该计划由
    // validate_settlement 的费率/守恒关系独立强制）。
    let pot = s.pot;
    let mut awards = [0u64; 9];
    awards[0] = if pot == 0 { 0 } else { s.payout_a % pot };
    awards[1] = if pot == 0 { 0 } else { s.payout_b % (pot - awards[0]) };
    let mk_out = |owner: [u8; 33], amount: u64| NoteSpec {
        asset_class: class,
        amount: amount.max(1),
        owner,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    SettlementRecord {
        table_id: s.table_id,
        // 零 binding → "zero hand binding" 拒绝路径
        hand_binding: if s.zero_binding {
            [0u8; 32]
        } else {
            s.hand_binding
        },
        policy_commitment: s.policy_commitment,
        pot,
        inputs: vec![
            SettleInput {
                note: na,
                spend: SpendAuth {
                    commitment: s.commitment_a,
                    nullifier: s.nullifier_a,
                    sig: poker_appchain::keys::EcdsaSig { bytes: s.sig_a },
                },
            },
            SettleInput {
                note: nb,
                spend: SpendAuth {
                    commitment: s.commitment_b,
                    nullifier: s.nullifier_b,
                    sig: poker_appchain::keys::EcdsaSig { bytes: s.sig_b },
                },
            },
        ],
        payouts: vec![mk_out(s.seat_a, s.payout_a), mk_out(s.seat_b, s.payout_b)],
        rake: RakeSplitRecord {
            total: s.rake_total,
            treasury_out: None,
            operator_out: None,
        },
        plan: flat_settlement_plan(pot, 0b11, awards),
        hand_proof: None,
    }
}

fuzz_target!(|data: &[u8]| {
    // ===== 原始字节路径：SettlementRecord borsh 解码 =====
    if let Ok(record) = <SettlementRecord as BorshDeserialize>::try_from_slice(data) {
        // 配默认（Zero）策略校验——拒绝一律 Err，不 panic
        let _ = validate_settlement(&record, &FeePolicy::Zero);
        // 绑定摘要 / 赔付根 / 结算效果摘要对任意解码成功载荷必须可计算
        let _ = settlement_binding(&record);
        let _ = payout_root_bytes(&record);
        let _ = settle_effect(&record);
        let _ = poker_appchain::settlement::settlement_input_class(&record);
    }

    // ===== 结构化路径：形似合法 witness（垃圾签名/任意金额）=====
    let mut u = arbitrary::Unstructured::new(data);
    if let Ok(s) = WitnessShape::arbitrary(&mut u) {
        let record = witness_from_shape(&s);
        let _ = validate_settlement(&record, &FeePolicy::Zero);
        let _ = settlement_binding(&record);
    }
});
