//! PokerDualSettlement（DAPV 双证明结算 v5）绑定：注册入口 + owner 接线 +
//! 状态核验。
//!
//! 语义边界：`verify_and_settle_dapv_stark[_private*]` 的 15-felt 公开段 /
//! SNIP-36 proof facts 载荷由 poker_texas_air 的证明侧（settlement 电路 +
//! prove_log）产出，形状归其 ABI 管——本绑定只提供 `register_hand`
//! （#18 Phase B 形：7 标量）与状态/接线面，结算提交不在此构造。

use starknet::core::types::Call;

use crate::client::ChainClient;
use crate::codec::{u256_from_felts, Felt, Uint256};
use crate::error::{ContractsError, ContractsResult};

use super::vault::felt_scalar;

/// PokerDualSettlement 句柄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualSettlement {
    /// 合约地址。
    pub address: Felt,
}

impl DualSettlement {
    /// 绑定地址（对标 `Contract.at`）。
    #[must_use]
    pub fn at(address: Felt) -> Self {
        Self { address }
    }

    // ===== 视图核验 =====

    /// `vault()`。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn vault(&self, client: &ChainClient) -> ContractsResult<Felt> {
        let res = client.call(self.address, "vault", vec![]).await?;
        res.into_iter().next().ok_or_else(|| ContractsError::Chain("vault: empty".into()))
    }

    /// `circuit_program_hash()`（接线核验锚点）。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn circuit_program_hash(&self, client: &ChainClient) -> ContractsResult<Felt> {
        let res = client.call(self.address, "circuit_program_hash", vec![]).await?;
        res.into_iter()
            .next()
            .ok_or_else(|| ContractsError::Chain("circuit_program_hash: empty".into()))
    }

    /// `claim_helper()`（派奖 helper 地址）。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn claim_helper(&self, client: &ChainClient) -> ContractsResult<Felt> {
        let res = client.call(self.address, "claim_helper", vec![]).await?;
        res.into_iter().next().ok_or_else(|| ContractsError::Chain("claim_helper: empty".into()))
    }

    /// `hand_settled(hand_binding)`。
    ///
    /// # Errors
    /// RPC 失败 → 上游错误。
    pub async fn hand_settled(&self, client: &ChainClient, binding: Felt) -> ContractsResult<bool> {
        let res = client.call(self.address, "hand_settled", vec![binding]).await?;
        felt_scalar(&res, "hand_settled").map(|v| v == 1)
    }

    /// `hand_action_log(hand_binding)`（动作日志哈希读回）。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn hand_action_log(&self, client: &ChainClient, binding: Felt) -> ContractsResult<Felt> {
        let res = client.call(self.address, "hand_action_log", vec![binding]).await?;
        res.into_iter()
            .next()
            .ok_or_else(|| ContractsError::Chain("hand_action_log: empty".into()))
    }

    /// `amounts_hidden(hand_binding)`（v2 private 零明文结算标记）。
    ///
    /// # Errors
    /// RPC 失败 → 上游错误。
    pub async fn amounts_hidden(&self, client: &ChainClient, binding: Felt) -> ContractsResult<bool> {
        let res = client.call(self.address, "amounts_hidden", vec![binding]).await?;
        felt_scalar(&res, "amounts_hidden").map(|v| v == 1)
    }

    /// `claim_amount(hand_binding, seat_index)`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn claim_amount(
        &self,
        client: &ChainClient,
        binding: Felt,
        seat_index: u32,
    ) -> ContractsResult<Uint256> {
        let res = client
            .call(self.address, "claim_amount", vec![binding, Felt::from(seat_index)])
            .await?;
        u256_from_felts(&res)
    }

    // ===== operator 写 =====

    /// `register_hand(hand_binding, settlement_digest, g_attestation,
    /// action_log_digest, exp_reveal, exp_leave, exp_recon)`
    /// （#18 Phase B 形，7 标量）。
    #[must_use]
    pub fn register_hand_call(
        &self,
        hand_binding: Felt,
        settlement_digest: Felt,
        g_attestation: Felt,
        action_log_digest: Felt,
        exp_reveal: Felt,
        exp_leave: Felt,
        exp_recon: Felt,
    ) -> Call {
        ChainClient::make_call(
            self.address,
            "register_hand",
            vec![
                hand_binding,
                settlement_digest,
                g_attestation,
                action_log_digest,
                exp_reveal,
                exp_leave,
                exp_recon,
            ],
        )
    }

    // ===== owner 接线（部署器复用） =====

    /// `set_claim_helper(helper)`。
    #[must_use]
    pub fn set_claim_helper_call(&self, helper: Felt) -> Call {
        ChainClient::make_call(self.address, "set_claim_helper", vec![helper])
    }

    /// `set_circuit_program_hash(program_hash)`。
    #[must_use]
    pub fn set_circuit_program_hash_call(&self, program_hash: Felt) -> Call {
        ChainClient::make_call(self.address, "set_circuit_program_hash", vec![program_hash])
    }

    /// `set_hand_verify_program_hash(program_hash)`。
    #[must_use]
    pub fn set_hand_verify_program_hash_call(&self, program_hash: Felt) -> Call {
        ChainClient::make_call(self.address, "set_hand_verify_program_hash", vec![program_hash])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_hand_calldata_is_seven_scalars() {
        let dual = DualSettlement::at(Felt::from(0xD_u64));
        let f = |n: u64| Felt::from(n);
        let c = dual.register_hand_call(f(1), f(2), f(3), f(4), f(5), f(6), f(7));
        assert_eq!(c.to, dual.address);
        assert_eq!(
            c.calldata,
            vec![f(1), f(2), f(3), f(4), f(5), f(6), f(7)],
            "7 标量（hand_binding..exp_recon）——顺序即 ABI"
        );
        assert_eq!(c.selector, crate::codec::selector("register_hand"));
    }
}
