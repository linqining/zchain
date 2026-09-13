//! PokerTableRegistry 绑定：桌台注册（"关桌后不开新手"的链上锚定层）。
//!
//! 跨端契约（与 poker_texas_air `texas/src/starknet/table_registry.rs`
//! 逐位对齐）：`params_hash = poseidon_hash_many([max_players, small_blind,
//! big_blind])`，字段顺序即契约，KAT 见 `tests/params_hash.rs`。
//! 注册表不碰钱、不进证明约束；全接口尽力而为（链故障只告警不阻塞牌局）。

use starknet::core::types::Call;

use crate::client::ChainClient;
use crate::codec::{felt_to_u128, Felt};
use crate::error::{ContractsError, ContractsResult};
use starknet_crypto::poseidon_hash_many;

use super::vault::felt_scalar;

/// 桌台规则承诺：`poseidon_hash_many([max_players, small_blind, big_blind])`。
///
/// 字段顺序即跨端契约：字段错位 = 不同承诺（texas 侧 KAT 同式锁定）。
#[must_use]
pub fn compute_params_hash(max_players: u32, small_blind: u64, big_blind: u64) -> Felt {
    poseidon_hash_many(&[
        Felt::from(max_players),
        Felt::from(small_blind),
        Felt::from(big_blind),
    ])
}

/// TableRecord 生命周期状态（Vacant → Open → Closed，只追加）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableStatus {
    /// 未登记（id 未分配）。
    Vacant,
    /// 开放（可入座开局）。
    Open,
    /// 已关闭（终态）。
    Closed,
    /// 未知状态值（链上枚举扩展时的兜底，携带原始值）。
    Unknown(u64),
}

impl TableStatus {
    fn from_u64(v: u64) -> Self {
        match v {
            0 => Self::Vacant,
            1 => Self::Open,
            2 => Self::Closed,
            other => Self::Unknown(other),
        }
    }
}

/// `get_table(table_id)` 返回的桌台记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRecord {
    /// 规则承诺（[`compute_params_hash`]）。
    pub params_hash: Felt,
    /// 建桌者。
    pub creator: Felt,
    /// 生命周期状态。
    pub status: TableStatus,
    /// 创建时间戳（秒）。
    pub created_at: u64,
    /// 关闭时间戳（未关为 0）。
    pub closed_at: u64,
}

/// PokerTableRegistry 句柄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableRegistry {
    /// 合约地址。
    pub address: Felt,
}

impl TableRegistry {
    /// 绑定地址（对标 `Contract.at`）。
    #[must_use]
    pub fn at(address: Felt) -> Self {
        Self { address }
    }

    /// `table_count()`（建桌 id = count_before + 1 的推导基准）。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn table_count(&self, client: &ChainClient) -> ContractsResult<u64> {
        felt_scalar(&client.call(self.address, "table_count", vec![]).await?, "table_count")
    }

    /// `is_open(table_id)`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn is_open(&self, client: &ChainClient, table_id: u64) -> ContractsResult<bool> {
        let res = client
            .call(self.address, "is_open", vec![Felt::from(table_id)])
            .await?;
        felt_scalar(&res, "is_open").map(|v| v == 1)
    }

    /// `close_grace_secs()`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn close_grace_secs(&self, client: &ChainClient) -> ContractsResult<u64> {
        felt_scalar(&client.call(self.address, "close_grace_secs", vec![]).await?, "close_grace_secs")
    }

    /// `owner()`。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn owner(&self, client: &ChainClient) -> ContractsResult<Felt> {
        let res = client.call(self.address, "owner", vec![]).await?;
        res.into_iter().next().ok_or_else(|| ContractsError::Chain("owner: empty".into()))
    }

    /// `get_table(table_id)`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn get_table(&self, client: &ChainClient, table_id: u64) -> ContractsResult<TableRecord> {
        let res = client
            .call(self.address, "get_table", vec![Felt::from(table_id)])
            .await?;
        if res.len() < 5 {
            return Err(ContractsError::Codec(format!(
                "get_table: expected 5 felts, got {}",
                res.len()
            )));
        }
        Ok(TableRecord {
            params_hash: res[0],
            creator: res[1],
            status: TableStatus::from_u64(felt_to_u128(res[2])
                .map_err(|e| ContractsError::Codec(format!("get_table status: {e}")))? as u64),
            created_at: super::vault::felt_scalar(&res[3..4], "created_at")?,
            closed_at: super::vault::felt_scalar(&res[4..5], "closed_at")?,
        })
    }

    // ===== 写 =====

    /// `create_table(params_hash)`（permissionless；合约分配 id 从 1 递增）。
    #[must_use]
    pub fn create_table_call(&self, params_hash: Felt) -> Call {
        ChainClient::make_call(self.address, "create_table", vec![params_hash])
    }

    /// `close_table(table_id)`（creator/owner 随时；他人需过宽限期；终态）。
    #[must_use]
    pub fn close_table_call(&self, table_id: u64) -> Call {
        ChainClient::make_call(self.address, "close_table", vec![Felt::from(table_id)])
    }

    /// 建桌并推导合约分配的 table_id（texas 服务端同式：invoke 前读
    /// `table_count`，id = count_before + 1；交易接受后 `is_open` 读回，
    /// 读回失败只告警——id 推导基于计数器，不依赖本检查）。
    ///
    /// # Errors
    /// 计数读失败 → `None`；交易失败 → [`ContractsError::Chain`]。
    pub async fn create_table_and_read_id(
        &self,
        client: &ChainClient,
        params_hash: Felt,
    ) -> ContractsResult<Option<u64>> {
        let count_before = match self.table_count(client).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("[poker-contracts] table_count read failed: {e}");
                return Ok(None);
            }
        };
        let new_id = count_before
            .checked_add(1)
            .ok_or_else(|| ContractsError::Chain("table_count overflow".into()))?;
        let tx = client
            .invoke(self.address, "create_table", vec![params_hash])
            .await?;
        client.wait_default(tx).await?;
        // 读回核验（尽力而为，3 次 × 2s，与 texas 侧一致）
        for _ in 0..3 {
            tokio::time::sleep(crate::client::DEFAULT_POLL_INTERVAL).await;
            if let Ok(true) = self.is_open(client, new_id).await {
                return Ok(Some(new_id));
            }
        }
        tracing::warn!("[poker-contracts] table {new_id} read-back inconclusive");
        Ok(Some(new_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_decoding() {
        assert_eq!(TableStatus::from_u64(0), TableStatus::Vacant);
        assert_eq!(TableStatus::from_u64(1), TableStatus::Open);
        assert_eq!(TableStatus::from_u64(2), TableStatus::Closed);
        assert_eq!(TableStatus::from_u64(9), TableStatus::Unknown(9));
    }

    #[test]
    fn calldata_shapes() {
        let reg = TableRegistry::at(Felt::from(0x33_u64));
        assert_eq!(reg.close_table_call(7).calldata, vec![Felt::from(7_u64)]);
        let c = reg.create_table_call(Felt::from(0x99_u64));
        assert_eq!(c.selector, crate::codec::selector("create_table"));
        assert_eq!(c.calldata, vec![Felt::from(0x99_u64)]);
    }
}
