//! 合约模块统一错误（对标 aztec.js 的错误分类：artifact / instance /
//! deploy / chain 四类 + 编码）。

use thiserror::Error;

/// 合约模块错误。
#[derive(Debug, Error)]
pub enum ContractsError {
    /// 产物（sierra/casm）缺失、不完整或解析失败。
    #[error("artifact error: {0}")]
    Artifact(String),
    /// 合约实例地址推导 / salt / 构造参数不合法。
    #[error("instance error: {0}")]
    Instance(String),
    /// 部署流水线错误（declare / deploy / 接线）。
    #[error("deploy error: {0}")]
    Deploy(String),
    /// 链交互错误（RPC / 签名 / 回执状态）。
    #[error("chain error: {0}")]
    Chain(String),
    /// calldata 编码 / felt 解析错误。
    #[error("codec error: {0}")]
    Codec(String),
    /// 配置错误（env / 注册表 / 网络预设）。
    #[error("config error: {0}")]
    Config(String),
    /// 主网等不可逆操作缺少显式确认。
    #[error("confirmation required: {0}")]
    ConfirmationRequired(String),
    /// 部署后回读与预期不一致（readiness 状态三不过）。
    #[error("readback mismatch on {what}: expected {expected}, got {actual}")]
    ReadbackMismatch {
        /// 回读项标签（如 `vault.token`）。
        what: String,
        /// 期望值（hex）。
        expected: String,
        /// 实际值（hex）。
        actual: String,
    },
}

/// 合约模块统一 [`ContractsResult`]。
pub type ContractsResult<T> = Result<T, ContractsError>;
