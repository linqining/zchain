//! M3：封闭操作集（closed operation set）。
//!
//! 链只处理这组操作——防滥用由封闭性给出，不依赖定价（plan §0）。
//! 任何新操作 = 协议版本升级，走 ABI 版本号，不允许运行时扩展。

use crate::fee::FeePolicy;
use crate::note::{AssetClass, NoteSpec};
use crate::settlement::{SettlementRecord, SpendAuth};

/// 操作集 v1。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum Operation {
    /// 开桌并冻结费率策略（operator，帧签名即授权）。
    OpenTable {
        /// 桌 ID。
        table_id: u64,
        /// 费率策略（注册表冻结）。
        policy: FeePolicy,
    },
    /// 关桌（operator）。
    CloseTable {
        /// 桌 ID。
        table_id: u64,
    },
    /// 入金铸币（operator 托管路径；deposit_id 幂等）。
    Deposit {
        /// 外部充值幂等键。
        deposit_id: [u8; 32],
        /// 收款人。
        owner: [u8; 33],
        /// 资产类。
        asset_class: AssetClass,
        /// 面额。
        amount: u64,
    },
    /// 出金销毁（owner 签名授权；vault 侧打款）。
    WithdrawRequest {
        /// 花费授权（销毁 balance note）。
        spend: SpendAuth,
        /// 被销毁 note 的完整内容（账本核对）。
        note: crate::note::Note,
        /// 提现幂等键。
        request_id: [u8; 32],
    },
    /// 玩家间转账（守恒，同类）。
    Transfer {
        /// 消费授权（≥1）。
        spends: Vec<SpendAuth>,
        /// 被消费 note 内容（≥1，与 spends 对齐）。
        notes: Vec<crate::note::Note>,
        /// 输出（≥1）。
        outputs: Vec<NoteSpec>,
    },
    /// 买入：消费 balance note → 铸一张 seat note（桌准入约束）。
    BuyIn {
        /// 桌 ID。
        table_id: u64,
        /// 消费授权。
        spends: Vec<SpendAuth>,
        /// 被消费 note 内容。
        notes: Vec<crate::note::Note>,
        /// seat 归属。
        seat_owner: [u8; 33],
    },
    /// 一手牌结算（M2 关系）。
    Settle(Box<SettlementRecord>),
}

impl Operation {
    /// 本操作消耗的全部花费授权（签名验证入口）。
    #[must_use]
    pub fn spends(&self) -> Vec<&SpendAuth> {
        match self {
            Operation::OpenTable { .. } | Operation::CloseTable { .. }
            | Operation::Deposit { .. } => Vec::new(),
            Operation::WithdrawRequest { spend, .. } => vec![spend],
            Operation::Transfer { spends, .. } | Operation::BuyIn { spends, .. } => {
                spends.iter().collect()
            }
            Operation::Settle(record) => {
                record.inputs.iter().map(|i| &i.spend).collect()
            }
        }
    }
}

/// 花费 scope 标签（防跨操作重放：同一 note 在不同操作类型下摘要不同）。
pub mod scope {
    /// 出金销毁 scope。
    pub const WITHDRAW: &[u8] = b"withdraw.v1";
    /// 转账 scope。
    pub const TRANSFER: &[u8] = b"transfer.v1";
    /// 买入 scope。
    pub const BUYIN: &[u8] = b"buyin.v1";
}
