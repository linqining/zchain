//! 统一错误类型（thiserror；daemon 侧逐项重试/跳过，错误只描述不决策）。

use thiserror::Error;

/// 结算适配层错误。
#[derive(Debug, Error)]
pub enum SettlementError {
    /// L1 JSON-RPC 返回 error 对象（message 内嵌）。
    #[error("l1 rpc error ({method}): {message}")]
    Rpc {
        /// 出错的方法名（诊断用）。
        method: String,
        /// 节点返回的 message。
        message: String,
    },
    /// 传输/响应形状失败（HTTP 状态、连接、JSON 解析；描述内嵌 method）。
    #[error("l1 transport error ({0}): {1}")]
    Transport(String, String),
    /// 响应形状不符合预期（字段缺失/类型不符；描述内嵌 method）。
    #[error("unexpected l1 response shape ({0}): {1}")]
    Shape(String, String),
    /// L1 chainId 与预期不符（防错链：143 / 10143 之外的链一律拒绝）。
    #[error("chain id mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch {
        /// 期望 chainId。
        expected: u64,
        /// 实际 chainId。
        actual: u64,
    },
    /// 签名/编码参数错误。
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// EIP-155 签名失败（secp256k1 层）。
    #[error("signing error: {0}")]
    Signing(String),
    /// hex 解析失败。
    #[error("hex error: {0}")]
    Hex(String),
}

impl SettlementError {
    /// 便捷构造：传输错误（method + 描述）。
    pub fn transport(method: &str, message: impl Into<String>) -> Self {
        Self::Transport(method.to_string(), message.into())
    }

    /// 便捷构造：响应形状错误（method + 描述）。
    pub fn shape(method: &str, message: impl Into<String>) -> Self {
        Self::Shape(method.to_string(), message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_descriptive() {
        let e = SettlementError::ChainIdMismatch { expected: 143, actual: 1 };
        assert!(e.to_string().contains("143"));
        assert!(e.to_string().contains("expected"));
    }
}
