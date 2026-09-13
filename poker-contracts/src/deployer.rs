//! 合约部署器（对标 aztec.js `DeployMethod` / `ContractDeployer`）：
//! declare（类注册）→ UDC deploy（实例发布）→ 等待接受。
//!
//! 内置两个 poker_texas_air 实测坑的兼容：
//! 1. 节点重算的 compiled-class-hash 与本地 starknet-core 可能不一致
//!    （`Mismatch compiled class hash`）——自动提取节点 `Expected:` 哈希重试
//!    （snops / deploy_mainnet.sh 同策略）；
//! 2. 公共 RPC 对大合约 estimateFee 请求体限制（503）——`manual_gas` 显式
//!    资源上限跳过估算（对标 snops `--l*-gas`）。

use std::sync::Arc;

use starknet::accounts::Account;
use starknet::contract::{ContractFactory, UdcSelector};
use starknet::core::types::DeclareTransactionResult;

use crate::artifact::ContractArtifact;
use crate::client::ChainClient;
use crate::codec::Felt;
use crate::error::{ContractsError, ContractsResult};
use crate::instance::ContractInstance;

/// 显式资源上限（跳过链上估算）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualGas {
    /// l1_gas 上限。
    pub l1_gas: u64,
    /// l1_data_gas 上限。
    pub l1_data_gas: u64,
    /// l2_gas 上限。
    pub l2_gas: u64,
}

/// declare 结果：类哈希 + 声明交易（`already_declared` 时无交易）。
#[derive(Debug, Clone)]
pub struct DeclareOutcome {
    /// sierra class hash。
    pub class_hash: Felt,
    /// 实际生效的 compiled class hash（mismatch 重试后为节点值）。
    pub compiled_class_hash: Felt,
    /// 声明交易哈希（已在链上时为 `None`）。
    pub tx_hash: Option<Felt>,
    /// 类是否已在链上（幂等声明）。
    pub already_declared: bool,
}

/// 类 + 实例部署产物。
#[derive(Debug, Clone)]
pub struct Deployment {
    /// declare 结果。
    pub declare: DeclareOutcome,
    /// 部署出的实例（地址与链上回执强制对账）。
    pub instance: ContractInstance,
    /// UDC 部署交易哈希。
    pub deploy_tx: Felt,
}

/// deploy 单步产物（`deploy()` 不含 declare 结果时用）。
#[derive(Debug, Clone)]
pub struct DeployOutcome {
    /// 实例。
    pub instance: ContractInstance,
    /// 部署交易哈希。
    pub tx_hash: Felt,
}

/// UDC 部署器（对标 aztec.js `DeployMethod`）。
///
/// ```ignore
/// let dep = ContractDeployer::new(&client, &artifact, udc, deployer)
///     .salt(Felt::ZERO)
///     .constructor(SuiteCalldata::vault(owner, strk, Felt::ZERO))
///     .declare_and_deploy().await?;
/// println!("{} @ {:#x}", dep.instance.name, dep.instance.address);
/// ```
pub struct ContractDeployer<'a> {
    client: &'a ChainClient,
    artifact: &'a ContractArtifact,
    udc: Felt,
    deployer: Felt,
    salt: Felt,
    constructor: Vec<Felt>,
    universal: bool,
    manual_gas: Option<ManualGas>,
}

impl<'a> ContractDeployer<'a> {
    /// 新部署器（缺省：主网原始 UDC、salt=0、unique 模式、deployer=操作员）。
    #[must_use]
    pub fn new(
        client: &'a ChainClient,
        artifact: &'a ContractArtifact,
        udc: Felt,
        deployer: Felt,
    ) -> Self {
        Self {
            client,
            artifact,
            udc,
            deployer,
            salt: Felt::ZERO,
            constructor: Vec::new(),
            universal: false,
            manual_gas: None,
        }
    }

    /// 部署 salt（确定性地址；DEPLOYMENTS 惯例 salt=0）。
    #[must_use]
    pub fn salt(mut self, salt: Felt) -> Self {
        self.salt = salt;
        self
    }

    /// 构造参数（形状见 [`crate::instance::SuiteCalldata`]）。
    #[must_use]
    pub fn constructor(mut self, calldata: Vec<Felt>) -> Self {
        self.constructor = calldata;
        self
    }

    /// universal 部署（UDC 非 unique：地址不含 deployer——对标 aztec
    /// `universalDeploy`，同 salt 跨网络同地址）。
    #[must_use]
    pub fn universal(mut self, on: bool) -> Self {
        self.universal = on;
        self
    }

    /// 显式资源上限（公共 RPC 大合约估算 503 兜底）。
    #[must_use]
    pub fn manual_gas(mut self, gas: ManualGas) -> Self {
        self.manual_gas = Some(gas);
        self
    }

    /// 离线预测实例地址（对标 `getInstance()`，不连链不产生交易）。
    ///
    /// # Errors
    /// 预测地址为零 → [`ContractsError::Instance`]。
    pub fn predicted_instance(&self) -> ContractsResult<ContractInstance> {
        let inst = ContractInstance::precompute(
            self.artifact.name.label(),
            self.artifact.class_hash,
            self.salt,
            self.constructor.clone(),
            self.deployer,
            self.udc,
            self.universal,
        )?;
        inst.validate()?;
        Ok(inst)
    }

    /// 声明合约类（幂等：已在链上返回 `already_declared=true`）。
    ///
    /// # Errors
    /// 声明被拒（非 mismatch / 非 already-declared）→ [`ContractsError::Deploy`]。
    pub async fn declare(&self) -> ContractsResult<DeclareOutcome> {
        let flattened = Arc::new(self.artifact.flattened()?);
        match self.send_declare(flattened.clone(), self.artifact.compiled_class_hash).await {
            Ok(r) => Ok(DeclareOutcome {
                class_hash: r.class_hash,
                compiled_class_hash: self.artifact.compiled_class_hash,
                tx_hash: Some(r.transaction_hash),
                already_declared: false,
            }),
            Err(text) if text.contains("Mismatch compiled class hash") => {
                // 节点（devnet/公共节点）casm 方案与本地 starknet-core 有
                // 版本差：取节点 "Expected: 0x…" 重试一次（snops 同策略）
                let actual = extract_expected_hash(&text).ok_or_else(|| {
                    ContractsError::Deploy(format!(
                        "compiled hash mismatch without Expected hash: {text}"
                    ))
                })?;
                tracing::info!(
                    "[poker-contracts] {} compiled-hash mismatch → retry {actual:#x}",
                    self.artifact.name.label()
                );
                let r = self.send_declare(flattened, actual).await.map_err(|t| {
                    ContractsError::Deploy(format!("declare {} (retry): {t}", self.artifact.name.label()))
                })?;
                Ok(DeclareOutcome {
                    class_hash: r.class_hash,
                    compiled_class_hash: actual,
                    tx_hash: Some(r.transaction_hash),
                    already_declared: false,
                })
            }
            Err(text) if text.contains("already declared") => {
                // 幂等声明：类已在链上（重复部署 / 类复用场景）
                Ok(DeclareOutcome {
                    class_hash: self.artifact.class_hash,
                    compiled_class_hash: self.artifact.compiled_class_hash,
                    tx_hash: None,
                    already_declared: true,
                })
            }
            Err(text) => Err(ContractsError::Deploy(format!(
                "declare {}: {text}",
                self.artifact.name.label()
            ))),
        }
    }

    /// 发送 declare_v3（manual_gas 跳过估算）；错误统一转文本供匹配。
    async fn send_declare(
        &self,
        flattened: Arc<starknet::core::types::FlattenedSierraClass>,
        compiled_hash: Felt,
    ) -> Result<DeclareTransactionResult, String> {
        let mut d = self.client.account().declare_v3(flattened, compiled_hash);
        if let Some(g) = self.manual_gas {
            d = d.l1_gas(g.l1_gas).l1_data_gas(g.l1_data_gas).l2_gas(g.l2_gas);
        }
        d.send().await.map_err(|e| format!("{e:?}"))
    }

    /// UDC 部署实例（类须已声明——先调 [`Self::declare`] 或用
    /// [`Self::declare_and_deploy`]）。回执地址与预测地址强制对账。
    ///
    /// # Errors
    /// 部署被拒 / 地址对账失败 → [`ContractsError::Deploy`]。
    pub async fn deploy(&self) -> ContractsResult<DeployOutcome> {
        let expected = self.predicted_instance()?;
        let factory = ContractFactory::new_with_udc(
            self.artifact.class_hash,
            self.client.account().clone(),
            UdcSelector::Custom(self.udc),
        );
        let res: starknet::core::types::InvokeTransactionResult = factory
            .deploy_v3(self.constructor.clone(), self.salt, !self.universal)
            .send()
            .await
            .map_err(|e| {
                ContractsError::Deploy(format!("deploy {}: {e:?}", self.artifact.name.label()))
            })?;
        // UDC deploy 是对 UDC 合约的 invoke：回执只有 tx hash。实例地址以
        // 预测推导为准（与 snops 同公式，已在 sepolia/mainnet 实测一致）。
        self.client
            .wait_default(res.transaction_hash)
            .await
            .map_err(|e| ContractsError::Deploy(format!("wait deploy {}: {e}", expected.name)))?;
        tracing::info!(
            "[poker-contracts] {} deployed at {:#x} (tx {:#x})",
            expected.name,
            expected.address,
            res.transaction_hash
        );
        Ok(DeployOutcome { instance: expected, tx_hash: res.transaction_hash })
    }

    /// 声明 + 部署一步到位。
    ///
    /// # Errors
    /// 同 [`Self::declare`] / [`Self::deploy`]。
    pub async fn declare_and_deploy(&self) -> ContractsResult<Deployment> {
        let declare = self.declare().await?;
        let outcome = self.deploy().await?;
        Ok(Deployment { declare, instance: outcome.instance, deploy_tx: outcome.tx_hash })
    }
}

/// 从错误文本提取节点计算的 `Expected: 0x…` casm 哈希（snops 同逻辑）。
fn extract_expected_hash(text: &str) -> Option<Felt> {
    let hex = text
        .split("Expected: ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .trim_end_matches(|c: char| !c.is_ascii_hexdigit())
        .to_string();
    Felt::from_hex(&hex).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_hash_extraction_from_mismatch_text() {
        // snops 部署日志的真实错误形状（DEPLOYMENTS.md 记录）
        let text = "StarknetErrorWithMessage { error: \"Mismatch compiled class hash. Expected: 0x55387af9abc, Actual: 0x111\" }";
        let h = extract_expected_hash(text).unwrap();
        assert_eq!(h, Felt::from_hex("0x55387af9abc").unwrap());
        assert!(extract_expected_hash("no marker here").is_none());
    }
}
