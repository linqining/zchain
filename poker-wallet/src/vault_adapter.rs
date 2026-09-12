//! `vault_adapter`：外部 Starknet 钱包连接面（plan §6.12.3）。
//!
//! **只负责**：能力探测（`getCapabilities` 风格）、deposit/claim 请求构造。
//! **绝不**：持有 Starknet 钱包私钥（类型层没有能放它的字段——外部签名
//! 永远发生在外部钱包里）；不把外部钱包冒充成 ZChain Note owner。
//!
//! claim 可用性与 [`crate::verifier::FinalityLevel`] 联动：未 finalized 的
//! 提现不得发起 claim（WALLET-ACC-6 联动，fail-closed）。

use poker_appchain::note::AssetClass;

use crate::error::WalletResult;
use crate::verifier::FinalityLevel;

/// 外部 signer 种类（能力矩阵维度；WALLET-ACC-7 的逻辑面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum SignerKind {
    /// Starknet 智能合约钱包（Argent X / Braavos 等）。
    StarknetWallet,
    /// 硬件钱包（官方 Stark app；仅可读签名）。
    Ledger,
    /// Passkey/WebAuthn（账户抽象 recovery key；不替代 Stark curve 签名）。
    Passkey,
    /// EVM 外部钱包（仅限未来 EVM bridge 适配；不得当 Note owner）。
    EvmWallet,
}

impl SignerKind {
    /// 静态名。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StarknetWallet => "starknet_wallet",
            Self::Ledger => "ledger",
            Self::Passkey => "passkey",
            Self::EvmWallet => "evm_wallet",
        }
    }
}

/// 外部 Vault 能力集（`getCapabilities` 返回结构）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct VaultCapabilities {
    /// 适配协议版本。
    pub protocol_version: u32,
    /// 支持的网络（版本化 chain id 列表）。
    pub networks: Vec<String>,
    /// 支持 deposit 发起。
    pub supports_deposit: bool,
    /// 支持 withdrawal claim 发起。
    pub supports_claim: bool,
    /// 支持 `starknet_signTypedData`（SNIP-12 会话授权前提）。
    pub supports_typed_data: bool,
    /// 可用的 signer 种类。
    pub signer_kinds: Vec<SignerKind>,
}

impl VaultCapabilities {
    /// 指定网络是否受支持。
    #[must_use]
    pub fn supports_network(&self, chain_id: &str) -> bool {
        self.networks.iter().any(|n| n == chain_id)
    }

    /// 指定 signer 是否受支持。
    #[must_use]
    pub fn supports_signer(&self, kind: SignerKind) -> bool {
        self.signer_kinds.contains(&kind)
    }

    /// 会话密钥授权（SNIP-12）是否可行：typed data + Starknet 钱包两者齐备。
    #[must_use]
    pub fn supports_session_authorization(&self) -> bool {
        self.supports_typed_data && self.supports_signer(SignerKind::StarknetWallet)
    }
}

/// deposit 请求（发给外部 Vault 钱包确认；本侧不签名）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct DepositRequest {
    /// 外部充值幂等键（对账用）。
    pub deposit_id: [u8; 32],
    /// 资产类。
    pub asset_class: AssetClass,
    /// 金额（STRK wei）。
    pub amount: u64,
    /// ZChain Note owner（33B 压缩公钥；充值铸币收款方）。
    pub zchain_owner: [u8; 33],
    /// 展示备注（不参与对账）。
    pub memo: String,
}

/// claim 请求（提现终态后的打款确认发起）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ClaimRequest {
    /// 提现幂等键（与账本 `WithdrawRequest.request_id` 一致）。
    pub withdrawal_request_id: [u8; 32],
    /// Vault 账户地址（felt252 规范 32B；不是 ZChain owner）。
    pub vault_address: [u8; 32],
    /// 资产类。
    pub asset_class: AssetClass,
    /// 金额。
    pub amount: u64,
    /// 发起时已知的最终性层级（必须 Finalized 才可发起）。
    pub proof_level: FinalityLevel,
}

/// vault 回执。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct VaultTicket {
    /// 回执 ID（外部钱包生成）。
    pub id: String,
    /// 请求种类。
    pub kind: VaultTicketKind,
    /// 网络 chain id。
    pub chain_id: String,
}

/// 回执种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum VaultTicketKind {
    /// deposit 已提交。
    Deposit,
    /// claim 已提交。
    Claim,
}

/// 外部 Vault 提供方接入缝（真实钱包连接实现此 trait；本 crate 不做网络 IO）。
pub trait VaultProvider {
    /// 能力探测（连接阶段调用；能力不足即拒绝签名，不允许退化成盲签）。
    fn get_capabilities(&self) -> VaultCapabilities;
    /// 发起 deposit（外部钱包确认）。
    ///
    /// # Errors
    /// 能力/网络不符 → [`crate::error::WalletError::VaultRejected`]。
    fn request_deposit(&self, chain_id: &str, req: &DepositRequest) -> WalletResult<VaultTicket>;
    /// 发起 claim（必须 finalized）。
    ///
    /// # Errors
    /// 能力/网络/finality 不符 → [`crate::error::WalletError::VaultRejected`]。
    fn request_claim(&self, chain_id: &str, req: &ClaimRequest) -> WalletResult<VaultTicket>;
}

/// 内存实现（能力驱动；无网络、无私钥字段——编译期保证不持外部私钥）。
#[derive(Debug, Clone)]
pub struct InMemoryVaultProvider {
    caps: VaultCapabilities,
}

impl InMemoryVaultProvider {
    /// 按能力集构造。
    #[must_use]
    pub fn new(caps: VaultCapabilities) -> Self {
        Self { caps }
    }

    /// 典型 devnet 能力（deposit + typed data，无 claim——用于演示
    /// claim 关闭路径）。
    #[must_use]
    pub fn devnet(chain_id: &str) -> Self {
        Self::new(VaultCapabilities {
            protocol_version: 1,
            networks: vec![chain_id.to_string()],
            supports_deposit: true,
            supports_claim: false,
            supports_typed_data: true,
            signer_kinds: vec![SignerKind::StarknetWallet],
        })
    }
}

impl VaultProvider for InMemoryVaultProvider {
    fn get_capabilities(&self) -> VaultCapabilities {
        self.caps.clone()
    }

    fn request_deposit(&self, chain_id: &str, req: &DepositRequest) -> WalletResult<VaultTicket> {
        let caps = &self.caps;
        if !caps.supports_deposit || !caps.supports_network(chain_id) {
            return Err(crate::error::WalletError::VaultRejected("deposit unsupported"));
        }
        if req.amount == 0 {
            return Err(crate::error::WalletError::VaultRejected("zero deposit"));
        }
        Ok(VaultTicket {
            id: hex::encode(req.deposit_id),
            kind: VaultTicketKind::Deposit,
            chain_id: chain_id.to_string(),
        })
    }

    fn request_claim(&self, chain_id: &str, req: &ClaimRequest) -> WalletResult<VaultTicket> {
        let caps = &self.caps;
        if !caps.supports_claim || !caps.supports_network(chain_id) {
            return Err(crate::error::WalletError::VaultRejected("claim unsupported"));
        }
        // WALLET-ACC-6 联动：未 finalized 一律不可 claim。
        if req.proof_level != FinalityLevel::Finalized {
            return Err(crate::error::WalletError::VaultRejected("withdrawal not finalized"));
        }
        Ok(VaultTicket {
            id: hex::encode(req.withdrawal_request_id),
            kind: VaultTicketKind::Claim,
            chain_id: chain_id.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_requires_finality_and_capability() {
        let provider = InMemoryVaultProvider::devnet("zchain-devnet-1");
        let req = ClaimRequest {
            withdrawal_request_id: [1; 32],
            vault_address: [2; 32],
            asset_class: AssetClass::Real,
            amount: 100,
            proof_level: FinalityLevel::Proven,
        };
        assert!(provider.request_claim("zchain-devnet-1", &req).is_err());
        let mut soft = req.clone();
        soft.proof_level = FinalityLevel::Soft;
        assert!(provider.request_claim("zchain-devnet-1", &soft).is_err());
        assert!(provider.request_deposit("other-net", &DepositRequest {
            deposit_id: [3; 32],
            asset_class: AssetClass::Real,
            amount: 1,
            zchain_owner: [4; 33],
            memo: String::new(),
        }).is_err());
    }
}
