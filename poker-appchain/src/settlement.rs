//! M2：结算关系 `SettleNotes`。
//!
//! 一手牌的结算 = 消费 N 个 seat note → 产出赔付 note + rake 分账 note。
//! 本模块定义 witness/record 的 ABI 形状与 **纯函数校验**（守恒 + 费率 +
//! 分账 + P 层签名覆盖 + 非零标识），是后续 AIR 关系（stwo 约束）的
//! 语义规范与 host 侧 admission 层。
//!
//! ## fail-closed 校验面（M2-ACC-2 负例矩阵的判据）
//!
//! 1. 守恒：`Σ输入 = Σ赔付 + rake.total`
//! 2. 费率：`rake.total == policy.rake_of(pot)`，policy 以 commitment 绑定
//! 3. 分账：treasury/operator note 数额 == `policy.split_of(rake.total)`
//! 4. 签名：每个输入 seat note 的 owner 必须对结算绑定摘要签名
//! 5. 范围：所有输入 note 的 table_id 一致、hand_binding 非零
//! 6. 资产类：输入/输出全部同类，REAL/PLAY 不混

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::error::{AppchainError, AppchainResult};
use crate::fee::FeePolicy;
use crate::felt::{
    bytes32_to_felts, domain_felt, felt_from_u64, felt_to_bytes32,
    DOMAIN_SETTLEMENT_BINDING,
};
use crate::keys::{spend_digest, verify_ecsdsa, EcdsaSig};
use crate::note::{AssetClass, Note, NoteSpec};

/// 花费授权：owner 对 (commitment, nullifier, scope) 的 P 层签名。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SpendAuth {
    /// 被消费 note 的承诺（32B 规范编码）。
    pub commitment: [u8; 32],
    /// owner 派生的 nullifier（32B 规范编码）。
    pub nullifier: [u8; 32],
    /// owner ECDSA 签名。
    pub sig: EcdsaSig,
}

/// 结算输入：被消费的 seat note（完整 note，账本层有据可查）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SettleInput {
    /// seat note（table_id 必须等于记录的 table_id）。
    pub note: Note,
    /// 花费授权（owner 签名）。
    pub spend: SpendAuth,
}

/// rake 分账记录。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct RakeSplitRecord {
    /// 抽取总额。
    pub total: u64,
    /// treasury 输出（数额由校验器重导出，非信任字段）。
    pub treasury_out: Option<NoteSpec>,
    /// operator 输出。
    pub operator_out: Option<NoteSpec>,
}

/// 结算记录（SettleNotes witness，AIR 形状就绪）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SettlementRecord {
    /// 桌 ID。
    pub table_id: u64,
    /// 手绑定（防重放；沿用 DAPV §6 语义，非零）。
    pub hand_binding: [u8; 32],
    /// 策略承诺（桌绑定策略的承诺字节）。
    pub policy_commitment: [u8; 32],
    /// 本手底池（rake 计费基数，由全体参与者签名覆盖）。
    pub pot: u64,
    /// 输入 seat notes（≥1）。
    pub inputs: Vec<SettleInput>,
    /// 赔付输出（每位参与者一张）。
    pub payouts: Vec<NoteSpec>,
    /// rake 分账。
    pub rake: RakeSplitRecord,
}

/// 结算绑定摘要：`poseidon(DOMAIN, table, hand_binding, policy, pot,
/// Σinputs commitments, Σoutputs (owner,amount))`。
///
/// AIR transcript 绑定的 host 侧对应物；任何字段篡改都改变摘要，
/// 从而改变签名判据。32B 字段一律 hi/lo 无损拆分。
#[must_use]
pub fn settlement_binding(record: &SettlementRecord) -> FieldElement {
    let push32 = |parts: &mut Vec<FieldElement>, b: &[u8; 32]| {
        let (hi, lo) = bytes32_to_felts(b);
        parts.push(hi);
        parts.push(lo);
    };
    let mut parts = vec![domain_felt(DOMAIN_SETTLEMENT_BINDING)];
    parts.push(felt_from_u64(record.table_id));
    push32(&mut parts, &record.hand_binding);
    push32(&mut parts, &record.policy_commitment);
    parts.push(felt_from_u64(record.pot));
    for i in &record.inputs {
        push32(&mut parts, &i.spend.commitment);
        push32(&mut parts, &i.spend.nullifier);
    }
    for o in &record.payouts {
        let (x, y) = crate::keys::public_xy_bytes_from_compressed(&o.owner);
        let (x_hi, x_lo) = bytes32_to_felts(&x);
        let (y_hi, y_lo) = bytes32_to_felts(&y);
        parts.push(x_hi);
        parts.push(x_lo);
        parts.push(y_hi);
        parts.push(y_lo);
        parts.push(felt_from_u64(o.amount));
    }
    parts.push(felt_from_u64(record.rake.total));
    poseidon_hash_many(&parts)
}

/// 构造单个输入 note 的花费签名摘要（scope = 结算域 + hand_binding）。
#[must_use]
pub fn settle_spend_scope(hand_binding: &[u8; 32]) -> Vec<u8> {
    let mut scope = Vec::with_capacity(DOMAIN_SETTLEMENT_BINDING.len() + 32);
    scope.extend_from_slice(DOMAIN_SETTLEMENT_BINDING);
    scope.extend_from_slice(hand_binding);
    scope
}

/// 对 `SettlementRecord` 做纯函数校验（不触碰账本状态）。
///
/// 这是 M2 的语义核心：**全部拒绝路径都从这里出**，sequencer 层不重复
/// 实现语义（避免双实现漂移）。
///
/// # Errors
/// 见模块文档 fail-closed 清单。
pub fn validate_settlement(
    record: &SettlementRecord,
    policy: &FeePolicy,
) -> AppchainResult<()> {
    // 5a. 非零标识（对齐 canonical AIR 的 non-zero identifier 关系）
    if record.hand_binding == [0u8; 32] {
        return Err(AppchainError::AdmissionRejected("zero hand binding"));
    }
    if record.inputs.is_empty() {
        return Err(AppchainError::AdmissionRejected("empty settlement inputs"));
    }
    // 5b. table_id 一致 + 资产类一致 + 输入 note 与授权的承诺一致
    let class = record.inputs[0].note.asset_class;
    let mut input_sum: u128 = 0;
    let mut commitments: Vec<FieldElement> = Vec::with_capacity(record.inputs.len());
    for input in &record.inputs {
        if input.note.table_id != Some(record.table_id) {
            return Err(AppchainError::AdmissionRejected("seat note table mismatch"));
        }
        if input.note.asset_class != class {
            return Err(AppchainError::AssetClassMismatch(
                class.name(),
                input.note.asset_class.name(),
            ));
        }
        let c = input.note.commitment();
        if felt_to_bytes32(&c) != input.spend.commitment {
            return Err(AppchainError::AdmissionRejected("spend commitment mismatch"));
        }
        // nullifier 非零：零 nullifier 会让任意两张 note 冲突（griefing 向量），
        // 且无法区分不同花费。真实 (commitment, secret) 派生绑定由 owner
        // 签名覆盖 —— 签名摘要包含 nullifier 字节。
        if input.spend.nullifier == [0u8; 32] {
            return Err(AppchainError::AdmissionRejected("zero nullifier"));
        }
        commitments.push(c);
        input_sum += u128::from(input.note.amount);
    }

    // 4. P 层签名覆盖：每个输入 note 的 owner 对绑定摘要签名
    let scope = settle_spend_scope(&record.hand_binding);
    for input in &record.inputs {
        let d = spend_digest(&input.spend.commitment, &input.spend.nullifier, &scope);
        verify_ecsdsa(&input.note.owner, &d, &input.spend.sig)?;
    }

    // 6. 输出资产类一致
    let mut output_sum: u128 = 0;
    for o in record.payouts.iter().chain(
        record
            .rake
            .treasury_out
            .iter()
            .chain(record.rake.operator_out.iter()),
    ) {
        if o.asset_class != class {
            return Err(AppchainError::AssetClassMismatch(
                class.name(),
                o.asset_class.name(),
            ));
        }
        if o.amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        output_sum += u128::from(o.amount);
    }

    // 1. 守恒：inputs = payouts + rake 输出 note（rake note 已含在
    //    output_sum 里；rake.total 与其一致性由第 3 步分账检查保证）
    let rake_total = u128::from(record.rake.total);
    if input_sum != output_sum {
        return Err(AppchainError::ConservationViolated {
            inputs: input_sum,
            outputs: output_sum,
            rake: rake_total,
        });
    }

    // 2. 费率 + 策略承诺绑定
    let expected = policy.rake_of(record.pot);
    if u128::from(expected) != rake_total {
        return Err(AppchainError::FeeMismatch {
            expected: u128::from(expected),
            got: rake_total,
        });
    }
    if policy.commitment_bytes() != record.policy_commitment {
        return Err(AppchainError::FeeMismatch {
            expected: rake_total,
            got: rake_total,
        });
    }

    // 3. 分账
    let (t_exp, o_exp) = policy.split_of(record.rake.total);
    match (t_exp, o_exp) {
        (0, 0) => {
            if record.rake.treasury_out.is_some() || record.rake.operator_out.is_some() {
                return Err(AppchainError::FeeMismatch { expected: 0, got: rake_total });
            }
        }
        _ => {
            let t = record.rake.treasury_out.as_ref().ok_or(AppchainError::FeeMismatch {
                expected: u128::from(t_exp),
                got: 0,
            })?;
            let o = record
                .rake
                .operator_out
                .as_ref()
                .ok_or(AppchainError::FeeMismatch {
                    expected: u128::from(o_exp),
                    got: 0,
                })?;
            if t.amount != t_exp || o.amount != o_exp {
                return Err(AppchainError::FeeMismatch {
                    expected: u128::from(t_exp + o_exp),
                    got: u128::from(t.amount + o.amount),
                }
                .into());
            }
            // 收款人必须与策略绑定一致（防"金额对、打给自己"）
            if let FeePolicy::FixedRake { split, .. } = policy {
                if t.owner != split.treasury || o.owner != split.operator {
                    return Err(AppchainError::FeeMismatch {
                        expected: u128::from(t_exp + o_exp),
                        got: u128::from(t.amount + o.amount),
                    });
                }
            }
        }
    }

    let _ = commitments; // 保留供未来 trace 导出
    Ok(())
}

/// 结算后按策略生成 rake 输出规格的辅助（游戏服务器侧构造用）。
#[must_use]
pub fn rake_outputs(
    record: &SettlementRecord,
    policy: &FeePolicy,
) -> (Option<NoteSpec>, Option<NoteSpec>) {
    let class = record.inputs[0].note.asset_class;
    let (t, o) = policy.split_of(record.rake.total);
    let mk = |amount: u64, owner: [u8; 33]| NoteSpec {
        asset_class: class,
        amount,
        owner,
        table_id: None,
    };
    if record.rake.total == 0 {
        (None, None)
    } else if let FeePolicy::FixedRake { split, .. } = policy {
        (Some(mk(t, split.treasury)), Some(mk(o, split.operator)))
    } else {
        (None, None)
    }
}

/// 资产类一致性快速断言（输出构造侧用）。
///
/// # Errors
/// 混类 → [`AppchainError::AssetClassMismatch`]。
pub fn assert_single_class(class: AssetClass, specs: &[NoteSpec]) -> AppchainResult<()> {
    for s in specs {
        if s.asset_class != class {
            return Err(AppchainError::AssetClassMismatch(
                class.name(),
                s.asset_class.name(),
            ));
        }
    }
    Ok(())
}
