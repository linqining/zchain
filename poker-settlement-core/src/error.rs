//! 结算语义错误（fail-closed；全部拒绝路径显式消息）。
//!
//! poker_l1 通过 `From<SettlementError> for PokerL1Error` 映射到
//! `PokerL1Error::Serialization`，消息前缀与搬运前逐字一致。

/// 结算派生/校验错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettlementError {
    /// 形状/守恒/编码违规（消息与 poker_l1 搬运前一致，`settlement: ` 前缀）。
    #[error("settlement: {0}")]
    Invalid(String),
}

impl SettlementError {
    /// 构造形状违规错误（crate 内部便捷构造）。
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}
