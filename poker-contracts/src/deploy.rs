//! poker 协议套件部署编排（对标 Aztec 协议合约部署脚本 + registry 引导）。
//!
//! 顺序冻结自 poker_texas_air `DEPLOYMENTS.md` / `scripts/deploy_mainnet.sh`
//! （同序等价替换 bash+snops）：
//!
//! 1. declare ×5（+Registry 可选）——类注册（readiness ①）
//! 2. `PokerVault(owner, STRK, settlement=0)`（settlement 占位 0）
//! 3. `PokerSettlement(owner, vault, prover)`、`PokerDualSettlement(owner, vault, prover)`
//! 4. `PokerVaultAnonymizer(owner, vault, pool)`、`SettlementPayoutAnonymizer(vault, pool, dual)`
//! 5. `PokerTableRegistry(owner, grace)`（可选）
//! 6. 接线（owner）：vault.settlement=dual、vault.unshield_helper=anonymizer、
//!    dual.claim_helper=payout、dual.circuit_program_hash、dual.hand_verify_program_hash
//! 7. 链上回读（readiness ③ initialized）+ 注册表回写 + env 回填输出

use crate::artifact::{ContractArtifact, ContractName};
use crate::bindings::dual_settlement::DualSettlement;
use crate::bindings::table_registry::TableRegistry;
use crate::bindings::vault::Vault;
use crate::client::ChainClient;
use crate::codec::Felt;
use crate::config::{ContractsConfig, DeployedAddresses, Network};
use crate::deployer::{ContractDeployer, Deployment, ManualGas};
use crate::error::{ContractsError, ContractsResult};
use crate::instance::SuiteCalldata;
use crate::registry::{CanonicalAddressRegistry, RegistryEntry};

/// 接线步骤标签（固定序，报告与注册表共用）。
pub const WIRE_LABELS: [&str; 5] = [
    "vault.set_settlement_contract",
    "vault.set_unshield_helper",
    "dual.set_claim_helper",
    "dual.set_circuit_program_hash",
    "dual.set_hand_verify_program_hash",
];

/// 套件部署选项。
#[derive(Debug, Clone)]
pub struct SuiteOptions {
    /// 部署 TableRegistry（sepolia/mainnet 批量脚本暂未含它，默认关）。
    pub with_table_registry: bool,
    /// 跳过接线与回读（只 declare+deploy，接线走独立运维）。
    pub skip_wiring: bool,
    /// 显式资源上限（公共 RPC 大合约估算 503 兜底）。
    pub manual_gas: Option<ManualGas>,
    /// 部署 salt（DEPLOYMENTS 惯例 0；unique 模式下同 owner 同 salt 地址稳定）。
    pub salt: Felt,
}

impl Default for SuiteOptions {
    fn default() -> Self {
        Self {
            with_table_registry: false,
            skip_wiring: false,
            manual_gas: None,
            salt: Felt::ZERO,
        }
    }
}

/// 部署计划步骤（`plan` 子命令展示 + 顺序回归测试锚点）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStep {
    /// 声明类。
    Declare(ContractName),
    /// 部署实例（calldata 在执行期由已部署地址解析；此处给形状标签）。
    Deploy {
        /// 合约。
        name: ContractName,
        /// 构造器形状说明。
        shape: &'static str,
    },
    /// owner 接线（[`WIRE_LABELS`] 之一）。
    Wire(&'static str),
    /// 链上回读。
    Readback(&'static str),
}

/// 纯函数：生成部署计划（顺序即 [`deploy_suite`] 执行顺序）。
#[must_use]
pub fn build_plan(with_table_registry: bool) -> Vec<PlanStep> {
    let mut plan = Vec::new();
    // 1. declare（套件序）
    for name in declare_order(with_table_registry) {
        plan.push(PlanStep::Declare(name));
    }
    // 2-5. 部署（依赖序：vault 先行，settlement/dual/anonymizer/payout 依赖其地址）
    plan.push(PlanStep::Deploy {
        name: ContractName::PokerVault,
        shape: "constructor(owner, STRK, settlement=0)",
    });
    plan.push(PlanStep::Deploy {
        name: ContractName::PokerSettlement,
        shape: "constructor(owner, vault, prover)",
    });
    plan.push(PlanStep::Deploy {
        name: ContractName::PokerDualSettlement,
        shape: "constructor(owner, vault, prover)",
    });
    plan.push(PlanStep::Deploy {
        name: ContractName::PokerVaultAnonymizer,
        shape: "constructor(owner, vault, pool)",
    });
    plan.push(PlanStep::Deploy {
        name: ContractName::SettlementPayoutAnonymizer,
        shape: "constructor(vault, pool, dual)",
    });
    if with_table_registry {
        plan.push(PlanStep::Deploy {
            name: ContractName::PokerTableRegistry,
            shape: "constructor(owner, close_grace_secs)",
        });
    }
    // 6. 接线（固定序）
    if with_table_registry {
        // registry 无接线（不碰钱）
    }
    for label in WIRE_LABELS {
        plan.push(PlanStep::Wire(label));
    }
    // 7. 回读
    plan.push(PlanStep::Readback("vault.token"));
    plan.push(PlanStep::Readback("vault.unshield_helper"));
    plan.push(PlanStep::Readback("dual.claim_helper"));
    plan.push(PlanStep::Readback("dual.circuit_program_hash"));
    if with_table_registry {
        plan.push(PlanStep::Readback("registry.close_grace_secs"));
    }
    plan
}

/// declare 顺序（与 deploy_mainnet.sh [1/7] 一致）。
fn declare_order(with_table_registry: bool) -> Vec<ContractName> {
    let mut v = vec![
        ContractName::PokerVault,
        ContractName::PokerSettlement,
        ContractName::PokerDualSettlement,
        ContractName::PokerVaultAnonymizer,
        ContractName::SettlementPayoutAnonymizer,
    ];
    if with_table_registry {
        v.push(ContractName::PokerTableRegistry);
    }
    v
}

/// 套件部署报告。
#[derive(Debug, Clone)]
pub struct SuiteDeploymentReport {
    /// 网络。
    pub network: Network,
    /// deployer（UDC unique 地址推导参与方）。
    pub deployer: Felt,
    /// 合约 owner。
    pub owner: Felt,
    /// 结算 initial_prover（= operator）。
    pub prover: Felt,
    /// 筹码代币。
    pub strk: Felt,
    /// STRK20 privacy pool。
    pub pool: Felt,
    /// (name, class_hash, compiled_class_hash)。
    pub class_hashes: Vec<(ContractName, Felt, Felt)>,
    /// declare 交易（already_declared 的合约无条目）。
    pub declare_txs: Vec<(ContractName, Felt)>,
    /// (name, deploy_tx)。
    pub deploy_txs: Vec<(ContractName, Felt)>,
    /// (wire label, tx)。
    pub wire_txs: Vec<(&'static str, Felt)>,
    /// (readback label, 结果描述)。
    pub readbacks: Vec<(&'static str, String)>,
    /// 部署地址。
    pub addresses: DeployedAddresses,
}

impl SuiteDeploymentReport {
    /// env 回填片段（对标 deploy_mainnet.sh 尾部 `cat <<EOF`，直接可贴
    /// texas/.env 与 client/.env.production）。
    #[must_use]
    pub fn env_backfill(&self) -> String {
        let a = &self.addresses;
        let chain_hex = format!("{:#x}", crate::codec::short_string(chain_id_name(self.network)).expect("chain id"));
        let fmt = |f: &Option<Felt>| f.map(|v| format!("{v:#x}")).unwrap_or_else(|| "<unset>".into());
        format!(
            "texas/.env: STARKNET_RPC_URL=<rpc> STARKNET_CHAIN_ID={chain}\n            STARKNET_STRK_ADDRESS={strk:#x} STARKNET_VAULT_ADDRESS={vault}\n            STARKNET_SETTLEMENT_ADDRESS={settle} STARKNET_DUAL_SETTLEMENT_ADDRESS={dual}\n            STARKNET_CLAIM_HELPER_ADDRESS={payout}\nclient/.env.production: VITE_STARKNET_CHAIN_ID={chain_hex}\n            VITE_STRK_TOKEN_ADDRESS={strk:#x} VITE_POKER_VAULT_ADDRESS={vault}\n            VITE_POKER_SETTLEMENT_ADDRESS={settle}\n            VITE_POKER_VAULT_ANONYMIZER_ADDRESS={anon}\n            VITE_STRK20_POOL_ADDRESS={pool:#x}",
            chain = chain_id_name(self.network),
            strk = self.strk,
            vault = fmt(&a.vault),
            settle = fmt(&a.settlement),
            dual = fmt(&a.dual),
            payout = fmt(&a.payout_anonymizer),
            anon = fmt(&a.vault_anonymizer),
            pool = self.pool,
        )
    }
}

/// 网络的 chain id 短串名。
#[must_use]
pub fn chain_id_name(network: Network) -> &'static str {
    network.preset().chain_id
}

/// 执行套件部署。
///
/// # Errors
/// 产物缺失 / 链交互失败 / 回读不一致 → 上游错误。
pub async fn deploy_suite(
    client: &ChainClient,
    config: &ContractsConfig,
    options: &SuiteOptions,
) -> ContractsResult<SuiteDeploymentReport> {
    let dir = &config.artifacts_dir;
    if !ContractArtifact::suite_complete(dir) {
        return Err(ContractsError::Artifact(format!(
            "scarb artifacts incomplete at {} — 先 `cd poker_contracts && PATH=\"$HOME/.local/opt/toolchains/scarb-2.19.4/bin:$PATH\" scarb build`",
            dir.display()
        )));
    }
    let owner = config.effective_owner()?;
    let prover = config.effective_prover()?;
    let pool = config.pool.ok_or_else(|| {
        ContractsError::Config(format!(
            "privacy pool required on {} (POKER_CONTRACTS_POOL)",
            config.network
        ))
    })?;

    let artifacts = ContractArtifact::load_suite(dir)?;
    let art = |name: ContractName| artifacts.iter().find(|a| a.name == name).expect("loaded above");
    let deployer_addr = client.account_address();

    let mut declare_txs = Vec::new();
    let mut class_hashes = Vec::new();
    let mut deploy_txs = Vec::new();
    let mut addresses = DeployedAddresses::default();

    // [1] declare（幂等）
    for name in declare_order(options.with_table_registry) {
        let dep = make_deployer(client, art(name), config, options, deployer_addr);
        let outcome = dep.declare().await?;
        class_hashes.push((name, outcome.class_hash, outcome.compiled_class_hash));
        if let Some(tx) = outcome.tx_hash {
            client.wait_default(tx).await.map_err(|e| ContractsError::Deploy(e.to_string()))?;
            declare_txs.push((name, tx));
        } else {
            tracing::info!("[poker-contracts] {} already declared", name.label());
        }
    }

    // [2] vault（settlement 占位 0）
    let vault = deploy_one(
        client,
        art(ContractName::PokerVault),
        config,
        options,
        deployer_addr,
        SuiteCalldata::vault(owner, config.strk, Felt::ZERO),
    )
    .await?;
    deploy_txs.push((ContractName::PokerVault, tx_of(&vault)));
    addresses.vault = Some(vault.instance.address);

    // [3] settlement + dual（prover 即 operator）
    let settlement = deploy_one(
        client,
        art(ContractName::PokerSettlement),
        config,
        options,
        deployer_addr,
        SuiteCalldata::settlement(owner, vault.instance.address, prover),
    )
    .await?;
    deploy_txs.push((ContractName::PokerSettlement, tx_of(&settlement)));
    addresses.settlement = Some(settlement.instance.address);

    let dual = deploy_one(
        client,
        art(ContractName::PokerDualSettlement),
        config,
        options,
        deployer_addr,
        SuiteCalldata::dual(owner, vault.instance.address, prover),
    )
    .await?;
    deploy_txs.push((ContractName::PokerDualSettlement, tx_of(&dual)));
    addresses.dual = Some(dual.instance.address);

    // [4] anonymizers
    let anonymizer = deploy_one(
        client,
        art(ContractName::PokerVaultAnonymizer),
        config,
        options,
        deployer_addr,
        SuiteCalldata::vault_anonymizer(owner, vault.instance.address, pool),
    )
    .await?;
    deploy_txs.push((ContractName::PokerVaultAnonymizer, tx_of(&anonymizer)));
    addresses.vault_anonymizer = Some(anonymizer.instance.address);

    let payout = deploy_one(
        client,
        art(ContractName::SettlementPayoutAnonymizer),
        config,
        options,
        deployer_addr,
        SuiteCalldata::payout_anonymizer(vault.instance.address, pool, dual.instance.address),
    )
    .await?;
    deploy_txs.push((ContractName::SettlementPayoutAnonymizer, tx_of(&payout)));
    addresses.payout_anonymizer = Some(payout.instance.address);

    // [5] table registry（可选）
    if options.with_table_registry {
        let registry = deploy_one(
            client,
            art(ContractName::PokerTableRegistry),
            config,
            options,
            deployer_addr,
            SuiteCalldata::table_registry(owner, config.registry_grace_secs),
        )
        .await?;
        deploy_txs.push((ContractName::PokerTableRegistry, tx_of(&registry)));
        addresses.table_registry = Some(registry.instance.address);
    }

    let mut wire_txs = Vec::new();
    let mut readbacks = Vec::new();

    // [6] 接线（owner）
    if !options.skip_wiring {
        let vault_h = Vault::at(vault.instance.address);
        let dual_h = DualSettlement::at(dual.instance.address);
        let wires = [
            (WIRE_LABELS[0], vault_h.set_settlement_contract_call(dual.instance.address)),
            (WIRE_LABELS[1], vault_h.set_unshield_helper_call(anonymizer.instance.address)),
            (WIRE_LABELS[2], dual_h.set_claim_helper_call(payout.instance.address)),
            (WIRE_LABELS[3], dual_h.set_circuit_program_hash_call(config.circuit_program_hash)),
            (WIRE_LABELS[4], dual_h.set_hand_verify_program_hash_call(config.hand_verify_program_hash)),
        ];
        for (label, call) in wires {
            let tx = client.invoke_batch(vec![call]).await?;
            client.wait_default(tx).await.map_err(|e| ContractsError::Deploy(e.to_string()))?;
            tracing::info!("[poker-contracts] wire {label} tx={tx:#x}");
            wire_txs.push((label, tx));
        }
    }

    // [7] 链上回读（readiness ③）
    let vault_h = Vault::at(vault.instance.address);
    let dual_h = DualSettlement::at(dual.instance.address);
    readback_eq("vault.token", || vault_h.token(client), config.strk).await?;
    readbacks.push(("vault.token", format!("{:#x}", config.strk)));
    if !options.skip_wiring {
        readback_eq(
            "vault.unshield_helper",
            || vault_h.unshield_helper(client),
            anonymizer.instance.address,
        )
        .await?;
        readbacks.push(("vault.unshield_helper", format!("{:#x}", anonymizer.instance.address)));
        readback_eq(
            "dual.claim_helper",
            || dual_h.claim_helper(client),
            payout.instance.address,
        )
        .await?;
        readbacks.push(("dual.claim_helper", format!("{:#x}", payout.instance.address)));
        readback_eq(
            "dual.circuit_program_hash",
            || dual_h.circuit_program_hash(client),
            config.circuit_program_hash,
        )
        .await?;
        readbacks.push(("dual.circuit_program_hash", format!("{:#x}", config.circuit_program_hash)));
    }
    if options.with_table_registry {
        let reg = TableRegistry::at(addresses.table_registry.expect("set above"));
        let grace = reg.close_grace_secs(client).await?;
        readbacks.push(("registry.close_grace_secs", format!("{grace}")));
    }

    Ok(SuiteDeploymentReport {
        network: config.network,
        deployer: deployer_addr,
        owner,
        prover,
        strk: config.strk,
        pool,
        class_hashes,
        declare_txs,
        deploy_txs,
        wire_txs,
        readbacks,
        addresses,
    })
}

/// 部署报告 → canonical 注册表（写盘用）。
#[must_use]
pub fn registry_from_report(report: &SuiteDeploymentReport) -> CanonicalAddressRegistry {
    let mut reg = CanonicalAddressRegistry::new(report.network);
    for name in ContractName::all() {
        let Some(addr) = report.addresses.get(name) else { continue };
        let class = report
            .class_hashes
            .iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, c, _)| format!("{c:#x}"));
        let compiled = report
            .class_hashes
            .iter()
            .find(|(n, _, _)| *n == name)
            .and_then(|(_, _, cc)| if *cc == Felt::ZERO { None } else { Some(format!("{cc:#x}")) });
        let deploy_tx = report
            .deploy_txs
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, t)| format!("{t:#x}"));
        let wiring = report
            .wire_txs
            .iter()
            .filter(|(l, _)| wire_label_targets(name, l))
            .map(|(l, t)| (l.to_string(), format!("{t:#x}")))
            .collect();
        reg.insert(
            name,
            RegistryEntry {
                address: format!("{addr:#x}"),
                class_hash: class,
                compiled_class_hash: compiled,
                deploy_tx,
                wiring,
            },
        );
    }
    reg.constants
        .insert("strk".into(), format!("{:#x}", report.strk));
    reg.constants
        .insert("pool".into(), format!("{:#x}", report.pool));
    reg
}

/// 接线标签是否作用于目标合约（注册表 wiring 归属）。
fn wire_label_targets(name: ContractName, label: &str) -> bool {
    match name {
        ContractName::PokerVault => label.starts_with("vault."),
        ContractName::PokerDualSettlement => label.starts_with("dual."),
        _ => false,
    }
}

fn make_deployer<'a>(
    client: &'a ChainClient,
    artifact: &'a ContractArtifact,
    config: &ContractsConfig,
    options: &SuiteOptions,
    deployer_addr: Felt,
) -> ContractDeployer<'a> {
    let mut d = ContractDeployer::new(client, artifact, config.udc, deployer_addr)
        .salt(options.salt);
    if let Some(g) = options.manual_gas {
        d = d.manual_gas(g);
    }
    d
}

async fn deploy_one(
    client: &ChainClient,
    artifact: &ContractArtifact,
    config: &ContractsConfig,
    options: &SuiteOptions,
    deployer_addr: Felt,
    calldata: Vec<Felt>,
) -> ContractsResult<Deployment> {
    make_deployer(client, artifact, config, options, deployer_addr)
        .constructor(calldata)
        .declare_and_deploy()
        .await
}

fn tx_of(dep: &Deployment) -> Felt {
    dep.deploy_tx
}

/// 回读断言（节点索引有秒级延迟：不一致重试 3 次，仍不一致报错）。
async fn readback_eq<F, Fut>(what: &'static str, mut fetch: F, expected: Felt) -> ContractsResult<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ContractsResult<Felt>>,
{
    let mut last = Felt::ZERO;
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(crate::client::DEFAULT_POLL_INTERVAL).await;
        }
        last = fetch().await?;
        if last == expected {
            return Ok(());
        }
    }
    Err(ContractsError::ReadbackMismatch {
        what: what.to_owned(),
        expected: format!("{expected:#x}"),
        actual: format!("{last:#x}"),
    })
}

/// 计划顺序回归测试的固定锚点（含 registry）。
#[cfg(test)]
mod tests {
    use crate::codec::parse_felt;

    use super::*;
    use crate::codec::Felt;

    #[test]
    fn plan_order_matches_deploy_mainnet_sh() {
        let plan = build_plan(false);
        let labels: Vec<String> = plan
            .iter()
            .map(|s| match s {
                PlanStep::Declare(n) => format!("declare:{}", n.label()),
                PlanStep::Deploy { name, .. } => format!("deploy:{}", name.label()),
                PlanStep::Wire(l) => format!("wire:{l}"),
                PlanStep::Readback(l) => format!("readback:{l}"),
            })
            .collect();
        let expected = [
            // [1/7] declare 5
            "declare:PokerVault",
            "declare:PokerSettlement",
            "declare:PokerDualSettlement",
            "declare:PokerVaultAnonymizer",
            "declare:SettlementPayoutAnonymizer",
            // [2/7]-[4/7] 依赖序部署
            "deploy:PokerVault",
            "deploy:PokerSettlement",
            "deploy:PokerDualSettlement",
            "deploy:PokerVaultAnonymizer",
            "deploy:SettlementPayoutAnonymizer",
            // [5/7]-[6/7] 接线
            "wire:vault.set_settlement_contract",
            "wire:vault.set_unshield_helper",
            "wire:dual.set_claim_helper",
            "wire:dual.set_circuit_program_hash",
            "wire:dual.set_hand_verify_program_hash",
            // [7/7] 回读
            "readback:vault.token",
            "readback:vault.unshield_helper",
            "readback:dual.claim_helper",
            "readback:dual.circuit_program_hash",
        ];
        assert_eq!(labels, expected);
    }

    #[test]
    fn plan_with_registry_appends_only() {
        let base = build_plan(false);
        let with = build_plan(true);
        assert_eq!(with.len(), base.len() + 3); // declare + deploy + readback（registry 无接线）
        assert!(matches!(with[5], PlanStep::Declare(ContractName::PokerTableRegistry)));
        // registry 部署在 payout 之后（deploy 段第 6 步）
        assert!(matches!(
            &with[11],
            PlanStep::Deploy { name: ContractName::PokerTableRegistry, .. }
        ));
        // 回读段追加 registry.close_grace_secs
        assert!(matches!(with[21], PlanStep::Readback("registry.close_grace_secs")));
    }

    #[test]
    fn env_backfill_snippet_shape() {
        let mut addresses = DeployedAddresses::default();
        addresses.vault = Some(parse_felt("0xabc").unwrap());
        let report = SuiteDeploymentReport {
            network: Network::Mainnet,
            deployer: Felt::ONE,
            owner: Felt::ONE,
            prover: Felt::ONE,
            strk: parse_felt(crate::config::CANONICAL_STRK).unwrap(),
            pool: parse_felt(crate::config::MAINNET_STRK20_POOL).unwrap(),
            class_hashes: vec![],
            declare_txs: vec![],
            deploy_txs: vec![],
            wire_txs: vec![],
            readbacks: vec![],
            addresses,
        };
        let s = report.env_backfill();
        assert!(s.contains("STARKNET_CHAIN_ID=SN_MAIN"));
        assert!(s.contains("VITE_STARKNET_CHAIN_ID=0x534e5f4d41494e"), "SN_MAIN 短串 hex");
        assert!(s.contains("STARKNET_VAULT_ADDRESS=0xabc"));
        assert!(s.contains("STARKNET_SETTLEMENT_ADDRESS=<unset>"));
    }

    #[test]
    fn registry_from_report_roundtrip() {
        let mut addresses = DeployedAddresses::default();
        addresses.vault = Some(Felt::from(0xB_u64));
        addresses.dual = Some(Felt::from(0xC_u64));
        let report = SuiteDeploymentReport {
            network: Network::Devnet,
            deployer: Felt::ONE,
            owner: Felt::ONE,
            prover: Felt::ONE,
            strk: Felt::from(2_u64),
            pool: Felt::from(3_u64),
            class_hashes: vec![(ContractName::PokerVault, Felt::from(0x10_u64), Felt::from(0x20_u64))],
            declare_txs: vec![],
            deploy_txs: vec![(ContractName::PokerVault, Felt::from(0x40_u64))],
            wire_txs: vec![("vault.set_settlement_contract", Felt::from(0x50_u64))],
            readbacks: vec![],
            addresses,
        };
        let reg = registry_from_report(&report);
        assert_eq!(reg.address_of(ContractName::PokerVault).unwrap(), Felt::from(0xB_u64));
        assert_eq!(reg.contracts["PokerVault"].deploy_tx.as_deref(), Some("0x40"));
        assert_eq!(
            reg.contracts["PokerVault"].wiring["vault.set_settlement_contract"],
            "0x50"
        );
        assert!(reg.contracts.get("PokerSettlement").is_none());
        assert_eq!(reg.constants["strk"], "0x2");
        let addrs = reg.to_deployed_addresses();
        assert_eq!(addrs.dual, Some(Felt::from(0xC_u64)));
    }
}
