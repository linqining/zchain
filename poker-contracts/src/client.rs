//! 链客户端（对标 aztec.js `Wallet` + 节点连接）：JSON-RPC provider +
//! 单签账户，视图调用 / 交易提交 / 回执等待。

use std::sync::Arc;
use std::time::Duration;

use starknet::accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
use starknet::core::types::{
    BlockId, BlockTag, Call, ExecutionResult, FunctionCall, PriceUnit, TransactionReceipt,
    TransactionReceiptWithBlockInfo, TransactionStatus,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet::signers::{LocalWallet, SigningKey};

use crate::codec::Felt;
use crate::config::ContractsConfig;
use crate::error::{ContractsError, ContractsResult};

/// STRK / ETH 小数位（gas 换算，starknet 资产通用精度）。
pub const FEE_TOKEN_DECIMALS: u32 = 18;

/// 单签账户类型别名（snops 同构：OZ 账户 + ExecutionEncoding::New）。
pub type NodeAccount = SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>;

/// 交易等待默认轮询间隔（devnet/sepolia 秒级出块；对标脚本 2s 轮询）。
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// 交易等待默认上限（对标部署脚本 `seq 1 90` × 2s ≈ 3 分钟）。
pub const DEFAULT_MAX_POLLS: u32 = 90;

/// 链客户端：provider + 操作员账户。
pub struct ChainClient {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    account: Arc<NodeAccount>,
    chain_id: Felt,
}

impl ChainClient {
    /// 连接 RPC 并构造操作员账户（chain id 从节点取，与 snops 一致）。
    ///
    /// # Errors
    /// 缺账户/私钥、URL 非法 → [`ContractsError::Config`] / [`ContractsError::Chain`]。
    pub async fn connect(config: &ContractsConfig) -> ContractsResult<Self> {
        let address = config
            .account_address
            .ok_or_else(|| ContractsError::Config("account address required (ADDRESS)".into()))?;
        let pk = config
            .private_key
            .ok_or_else(|| ContractsError::Config("private key required (PRIVATE_KEY)".into()))?;
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            url::Url::parse(&config.rpc_url)
                .map_err(|e| ContractsError::Config(format!("rpc url {}: {e}", config.rpc_url)))?,
        )));
        let chain_id = provider
            .chain_id()
            .await
            .map_err(|e| ContractsError::Chain(format!("chain_id: {e}")))?;
        let account = Arc::new(SingleOwnerAccount::new(
            provider.clone(),
            LocalWallet::from_signing_key(SigningKey::from_secret_scalar(pk)),
            address,
            chain_id,
            ExecutionEncoding::New,
        ));
        Ok(Self { provider, account, chain_id })
    }

    /// 链 id（felt 短串，如 `SN_MAIN`）。
    #[must_use]
    pub fn chain_id(&self) -> Felt {
        self.chain_id
    }

    /// 操作员账户地址。
    #[must_use]
    pub fn account_address(&self) -> Felt {
        self.account.address()
    }

    /// 账户句柄（deployer / factory 用）。
    #[must_use]
    pub fn account(&self) -> &Arc<NodeAccount> {
        &self.account
    }

    /// 构造 Call（视图与交易共用）。
    #[must_use]
    pub fn make_call(to: Felt, entrypoint: &str, calldata: Vec<Felt>) -> Call {
        Call { to, selector: crate::codec::selector(entrypoint), calldata }
    }

    /// 视图调用（`latest`；devnet 上未确认交易读取请用服务端 pre-confirmed
    /// 通道——与 poker_texas_air texas 侧同限制）。
    ///
    /// # Errors
    /// RPC 错误 / 合约 revert → [`ContractsError::Chain`]。
    pub async fn call(
        &self,
        to: Felt,
        entrypoint: &str,
        calldata: Vec<Felt>,
    ) -> ContractsResult<Vec<Felt>> {
        self.provider
            .call(
                FunctionCall {
                    contract_address: to,
                    entry_point_selector: crate::codec::selector(entrypoint),
                    calldata,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|e| ContractsError::Chain(format!("call {to:#x}::{entrypoint}: {e}")))
    }

    /// 单调用交易（v3），返回 tx hash。
    ///
    /// # Errors
    /// RPC / 估算 / 签名错误 → [`ContractsError::Chain`]。
    pub async fn invoke(
        &self,
        to: Felt,
        entrypoint: &str,
        calldata: Vec<Felt>,
    ) -> ContractsResult<Felt> {
        self.invoke_batch(vec![Self::make_call(to, entrypoint, calldata)]).await
    }

    /// 多调用交易（对标 aztec `BatchCall`：一次签名原子执行）。
    ///
    /// # Errors
    /// RPC / 估算 / 签名错误 → [`ContractsError::Chain`]。
    pub async fn invoke_batch(&self, calls: Vec<Call>) -> ContractsResult<Felt> {
        let res = self
            .account
            .execute_v3(calls)
            .send()
            .await
            .map_err(|e| ContractsError::Chain(format!("invoke: {e}")))?;
        Ok(res.transaction_hash)
    }

    /// 等待交易被接受（对标 aztec `waitForTx`）：`AcceptedOnL2` 及以上且
    /// 执行成功返回 tx hash；revert 即报错（带节点回执原因）；超时报错
    /// （轮询间隔/上限可调）。
    ///
    /// # Errors
    /// 交易 revert / 轮询超时 / RPC 错误 → [`ContractsError::Chain`]。
    pub async fn wait_for_acceptance(
        &self,
        tx_hash: Felt,
        max_polls: u32,
        interval: Duration,
    ) -> ContractsResult<Felt> {
        for attempt in 1..=max_polls.max(1) {
            match self.provider.get_transaction_status(tx_hash).await {
                Ok(TransactionStatus::AcceptedOnL2(res) | TransactionStatus::AcceptedOnL1(res)) => {
                    return match res {
                        ExecutionResult::Succeeded => Ok(tx_hash),
                        ExecutionResult::Reverted { reason } => Err(ContractsError::Chain(
                            format!("tx {tx_hash:#x} reverted: {reason}"),
                        )),
                    };
                }
                Ok(TransactionStatus::PreConfirmed(res)) => {
                    // pre-confirmed 即 revert 基本终局（devnet 常态），早退
                    if let ExecutionResult::Reverted { reason } = res {
                        return Err(ContractsError::Chain(format!(
                            "tx {tx_hash:#x} reverted (pre-confirmed): {reason}"
                        )));
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    // 公共 RPC 偶发 5xx：不放弃，继续轮询
                    tracing::debug!("[poker-contracts] status poll {attempt}: {e}");
                }
            }
            tokio::time::sleep(interval).await;
        }
        Err(ContractsError::Chain(format!(
            "tx {tx_hash:#x} not accepted after {max_polls} polls"
        )))
    }

    /// `wait_for_acceptance` 默认参数版。
    ///
    /// # Errors
    /// 同 [`Self::wait_for_acceptance`]。
    pub async fn wait_default(&self, tx_hash: Felt) -> ContractsResult<Felt> {
        self.wait_for_acceptance(tx_hash, DEFAULT_MAX_POLLS, DEFAULT_POLL_INTERVAL).await
    }

    /// 拉取交易回执摘要（`starknet_getTransactionReceipt`）：区块号 +
    /// 实际 gas 费 + 执行终态。牌桌 G2「链上验证」卡的区块号/Gas 行、
    /// 结算回执落账（D2）共用此入口。
    ///
    /// # Errors
    /// 交易未入块（TXN_HASH_NOT_FOUND / pre-confirm 未上链）或 RPC 错误 →
    /// [`ContractsError::Chain`]。
    pub async fn transaction_receipt(
        &self,
        tx_hash: Felt,
    ) -> ContractsResult<TxReceiptSummary> {
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| ContractsError::Chain(format!("receipt {tx_hash:#x}: {e}")))?;
        TxReceiptSummary::from_receipt(&receipt)
    }
}

/// 交易回执摘要：只保留接入侧（结算回执 / 面板展示）需要的字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReceiptSummary {
    /// 交易所在区块号（pre-confirmed 块也有高度）。
    pub block_number: u64,
    /// 实际 gas 费（原始整数，单位见 `fee_unit`）。
    pub actual_fee: Felt,
    /// 费用单位："FRI"（STRK，v3 交易常态）或 "WEI"（ETH）。
    pub fee_unit: &'static str,
    /// 执行是否成功（revert = false）。
    pub execution_succeeded: bool,
}

impl TxReceiptSummary {
    fn from_receipt(r: &TransactionReceiptWithBlockInfo) -> ContractsResult<Self> {
        let (actual_fee, fee_unit) = match &r.receipt {
            TransactionReceipt::Invoke(t) => (t.actual_fee.amount, unit_label(t.actual_fee.unit)),
            TransactionReceipt::L1Handler(t) => {
                (t.actual_fee.amount, unit_label(t.actual_fee.unit))
            }
            TransactionReceipt::Declare(t) => (t.actual_fee.amount, unit_label(t.actual_fee.unit)),
            TransactionReceipt::Deploy(t) => (t.actual_fee.amount, unit_label(t.actual_fee.unit)),
            TransactionReceipt::DeployAccount(t) => {
                (t.actual_fee.amount, unit_label(t.actual_fee.unit))
            }
        };
        let execution_succeeded = matches!(r.receipt.execution_result(), ExecutionResult::Succeeded);
        Ok(Self {
            block_number: r.block.block_number(),
            actual_fee,
            fee_unit,
            execution_succeeded,
        })
    }

    /// gas 费的十进制展示串（如 `"0.0031"`）；不足 1 单位的最小单位时保留
    /// 全精度（`"0.000000000000031"`）。FRI = STRK，WEI = ETH。
    #[must_use]
    pub fn fee_display(&self) -> String {
        format_fee(self.actual_fee, self.fee_unit)
    }
}

fn unit_label(unit: PriceUnit) -> &'static str {
    match unit {
        PriceUnit::Fri => "FRI",
        PriceUnit::Wei => "WEI",
    }
}

/// 原始费用整数 → 十进制字符串（18 位小数，末尾零裁剪；整数部分无零填充）。
#[must_use]
pub fn format_fee(amount: Felt, unit: &str) -> String {
    let digits = felt_decimal_string(&amount.to_bytes_be());
    let (int_part, frac_part) = if digits.len() > FEE_TOKEN_DECIMALS as usize {
        let split = digits.len() - FEE_TOKEN_DECIMALS as usize;
        (digits[..split].to_owned(), digits[split..].to_owned())
    } else {
        let padded = format!("{digits:0>width$}", width = FEE_TOKEN_DECIMALS as usize);
        ("0".to_owned(), padded)
    };
    let frac = frac_part.trim_end_matches('0');
    let value = if frac.is_empty() { int_part } else { format!("{int_part}.{frac}") };
    format!("{value} {unit}")
}

/// 32 字节大端整数 → 无前导零十进制串（不依赖 num-bigint feature：
/// 按 u32 limb 反复除 10⁹ 的教科书除法，gas 费量级下循环次数个位数）。
fn felt_decimal_string(bytes: &[u8; 32]) -> String {
    let mut limbs: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    while limbs.len() > 1 && limbs[0] == 0 {
        limbs.remove(0);
    }
    if limbs == [0] {
        return "0".to_owned();
    }
    let mut out: Vec<u32> = Vec::new(); // 十进制 9 位一组，小端
    while limbs != [0] {
        let mut rem: u64 = 0;
        let mut next = Vec::with_capacity(limbs.len());
        for &limb in &limbs {
            let cur = (rem << 32) | u64::from(limb);
            next.push((cur / 1_000_000_000) as u32);
            rem = cur % 1_000_000_000;
        }
        while next.len() > 1 && next[0] == 0 {
            next.remove(0);
        }
        out.push(rem as u32);
        limbs = next;
    }
    let mut s = String::new();
    for (i, group) in out.iter().enumerate().rev() {
        if i == out.len() - 1 {
            s.push_str(&group.to_string());
        } else {
            s.push_str(&format!("{group:09}"));
        }
    }
    s
}

/// 从 `.env` 文件快速连链的便捷入口（CLI 用）。
///
/// # Errors
/// env 解析 / 连接失败 → 上游错误。
pub async fn connect_env_file(path: &std::path::Path) -> ContractsResult<ChainClient> {
    let cfg = ContractsConfig::from_env_file(path)?;
    ChainClient::connect(&cfg).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt_dec(s: &str) -> Felt {
        Felt::from_dec_str(s).expect("test decimal parses")
    }

    /// 设计稿 G2 参考值量级：0.0031 STRK = 3100000000000000 wei（FRI）。
    #[test]
    fn fee_display_matches_g2_reference() {
        let fee = felt_dec("3100000000000000");
        assert_eq!(format_fee(fee, "FRI"), "0.0031 FRI");
    }

    #[test]
    fn fee_display_zero_and_integral() {
        assert_eq!(format_fee(Felt::ZERO, "FRI"), "0 FRI");
        let one = felt_dec("1000000000000000000");
        assert_eq!(format_fee(one, "FRI"), "1 FRI");
        // 2.5 STRK
        let two_half = felt_dec("2500000000000000000");
        assert_eq!(format_fee(two_half, "FRI"), "2.5 FRI");
    }

    /// 超过 u128 的极端值也不能崩（felt_decimal_string 逐 limb 除法）。
    #[test]
    fn fee_display_large_felt() {
        let bytes = [0xff; 32];
        let s = felt_decimal_string(&bytes);
        assert!(s.len() >= 70, "2^256 ≈ 1.16e77，实际 {s}");
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn decimal_string_known_values() {
        assert_eq!(felt_decimal_string(&[0u8; 32]), "0");
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(felt_decimal_string(&one), "1");
        let mut bignum = [0u8; 32];
        // 2^120（byte 16 置 1）= 1329227995784915872903807060280344576
        bignum[16] = 1;
        assert_eq!(
            felt_decimal_string(&bignum),
            "1329227995784915872903807060280344576"
        );
    }
}
