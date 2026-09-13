//! poker-contracts CLI — poker_texas_air 合约的部署与接入运维入口。
//!
//! ```text
//! # 部署前预览（离线：产物 + 计划 + 构造参数）
//! cargo run -p poker-contracts -- plan --network devnet
//!
//! # 全量部署（devnet；sepolia/mainnet 需 ADDRESS/PRIVATE_KEY）
//! cargo run -p poker-contracts -- deploy --network devnet --with-registry
//! # mainnet 必须显式 --yes（对标 CONFIRM_MAINNET=yes）
//! cargo run -p poker-contracts -- deploy --network mainnet --yes
//!
//! # 接入：读现网接线 / 输出 env 回填 / 通用视图调用
//! cargo run -p poker-contracts -- --env-file ../poker_texas_air/texas/.env status
//! cargo run -p poker-contracts -- env-backfill
//! cargo run -p poker-contracts -- call <VAULT> chip_balance <PLAYER>
//! ```
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use poker_contracts::artifact::{ContractArtifact, ContractName};
use poker_contracts::bindings::table_registry::{TableRegistry, compute_params_hash};
use poker_contracts::bindings::vault::Vault;
use poker_contracts::client::ChainClient;
use poker_contracts::codec::{Felt, parse_calldata, parse_felt};
use poker_contracts::config::{ContractsConfig, Network};
use poker_contracts::deploy::{SuiteOptions, build_plan, registry_from_report};
use poker_contracts::deployer::ManualGas;
use poker_contracts::error::ContractsResult;
use poker_contracts::registry::CanonicalAddressRegistry;

#[derive(Parser)]
#[command(
    name = "poker-contracts",
    about = "poker_texas_air 合约部署与接入（架构对标 Aztec：artifact/instance/deployer/bindings/registry）"
)]
struct Cli {
    /// devnet | sepolia | mainnet（或 env POKER_CONTRACTS_NETWORK）。
    #[arg(long, global = true)]
    network: Option<String>,
    /// dotenv 文件（texas/.env、.env.mainnet 等可直读）。
    #[arg(long, global = true)]
    env_file: Option<PathBuf>,
    /// scarb 产物目录（默认 ../poker_texas_air/poker_contracts/target/dev）。
    #[arg(long, global = true)]
    artifacts_dir: Option<PathBuf>,
    /// 覆盖 RPC 端点。
    #[arg(long, global = true)]
    rpc_url: Option<String>,
    /// canonical 注册表目录（默认 <crate>/registry）。
    #[arg(long, global = true)]
    registry_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 离线输出部署计划（产物齐备性检查 + 步骤表）。
    Plan,
    /// 全量部署：declare ×N → deploy ×N → 接线 → 回读 → 注册表回写。
    Deploy {
        /// 部署 TableRegistry（默认关，与现行部署状态一致）。
        #[arg(long)]
        with_registry: bool,
        /// 只 declare+deploy，跳过接线与回读。
        #[arg(long)]
        skip_wiring: bool,
        /// 显式资源上限 `l1:l1_data:l2`（公共 RPC 大合约估算 503 兜底）。
        #[arg(long)]
        manual_gas: Option<String>,
        /// 主网部署确认（对标 CONFIRM_MAINNET=yes）。
        #[arg(long)]
        yes: bool,
    },
    /// 读现网接线（地址取 env / 注册表 / --env-file）。
    Status,
    /// 输出 texas/.env 与 client/.env.production 回填片段（读注册表）。
    EnvBackfill,
    /// canonical 注册表管理。
    Registry {
        #[command(subcommand)]
        op: RegistryOp,
    },
    /// 通用视图调用（calldata：0x/十进制，`@str:` ByteArray）。
    Call {
        /// 合约地址。
        #[arg(long)]
        contract: String,
        /// 入口名。
        #[arg(long)]
        r#fn: String,
        /// 逗号分隔参数（空串 = 无参）。
        #[arg(long, default_value = "")]
        calldata: String,
    },
    /// 通用交易（显式确认；失败不上链回滚）。
    Invoke {
        /// 合约地址。
        #[arg(long)]
        contract: String,
        /// 入口名。
        #[arg(long)]
        r#fn: String,
        /// 逗号分隔参数。
        #[arg(long, default_value = "")]
        calldata: String,
        /// 确认发送。
        #[arg(long)]
        yes: bool,
    },
    /// 桌台注册表：规则承诺公式与建桌 id 预演（离线）。
    ParamsHash {
        /// 最大玩家数。
        #[arg(long)]
        max_players: u32,
        /// 小盲注。
        #[arg(long)]
        small_blind: u64,
        /// 大盲注。
        #[arg(long)]
        big_blind: u64,
    },
}

#[derive(Subcommand)]
enum RegistryOp {
    /// 打印注册表内容。
    Show,
    /// 打印注册表文件路径。
    Path,
    /// 手工写一条地址（名 = 合约 label，如 PokerVault）。
    Set {
        /// 合约名。
        name: String,
        /// 地址。
        address: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("[poker-contracts] error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> ContractsResult<()> {
    let cfg = load_config(&cli)?;
    let registry_dir = cli
        .registry_dir
        .unwrap_or_else(default_registry_dir);
    let registry_path = CanonicalAddressRegistry::path_for(&registry_dir, cfg.network);

    match cli.cmd {
        Cmd::Plan => plan(&cfg),
        Cmd::Deploy { with_registry, skip_wiring, manual_gas, yes } => {
            deploy(&cfg, registry_dir, with_registry, skip_wiring, manual_gas, yes)
        }
        Cmd::Status => status(&cfg),
        Cmd::EnvBackfill => env_backfill(&registry_path, cfg.network),
        Cmd::Registry { op } => registry(op, &registry_path, cfg.network),
        Cmd::Call { contract, r#fn, calldata } => call(&cfg, &contract, &r#fn, &calldata),
        Cmd::Invoke { contract, r#fn, calldata, yes } => {
            invoke(&cfg, &contract, &r#fn, &calldata, yes)
        }
        Cmd::ParamsHash { max_players, small_blind, big_blind } => {
            let h = compute_params_hash(max_players, small_blind, big_blind);
            println!("params_hash = {h:#x}");
            println!("公式 = poseidon_hash_many([max_players, small_blind, big_blind])");
            println!("字段顺序即跨端契约（texas/src/starknet/table_registry.rs 同式）");
            Ok(())
        }
    }
}

fn load_config(cli: &Cli) -> ContractsResult<ContractsConfig> {
    let mut cfg = match &cli.env_file {
        Some(p) => ContractsConfig::from_env_file(p)?,
        None => ContractsConfig::from_env()?,
    };
    if let Some(n) = &cli.network {
        cfg.network = Network::parse(n)?;
        let preset = cfg.network.preset();
        if cli.rpc_url.is_none() && std::env::var("STARKNET_RPC_URL").map_or(true, |v| v.is_empty()) {
            cfg.rpc_url = preset.rpc_url.to_owned();
        }
    }
    if let Some(url) = &cli.rpc_url {
        cfg.rpc_url = url.clone();
    }
    if let Some(d) = &cli.artifacts_dir {
        cfg.artifacts_dir = d.clone();
    }
    Ok(cfg)
}

fn default_registry_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("registry")
}

fn plan(cfg: &ContractsConfig) -> ContractsResult<()> {
    let complete = ContractArtifact::suite_complete(&cfg.artifacts_dir);
    println!("network       = {}", cfg.network);
    println!("rpc           = {}", cfg.rpc_url);
    println!("artifacts     = {} ({})", cfg.artifacts_dir.display(), if complete { "OK" } else { "MISSING — 先 scarb build" });
    println!("strk          = {:#x}", cfg.strk);
    if let Some(p) = cfg.pool {
        println!("pool          = {p:#x}");
    }
    println!("program_hash  = {:#x}", cfg.circuit_program_hash);
    println!("hand_verify   = {:#x}", cfg.hand_verify_program_hash);
    println!();
    let with_registry = cfg.with_table_registry;
    for (i, step) in build_plan(with_registry).into_iter().enumerate() {
        match step {
            poker_contracts::deploy::PlanStep::Declare(n) => println!("{i:>3} declare {n}"),
            poker_contracts::deploy::PlanStep::Deploy { name, shape } => {
                println!("{i:>3} deploy  {name}  {shape}")
            }
            poker_contracts::deploy::PlanStep::Wire(l) => println!("{i:>3} wire    {l}"),
            poker_contracts::deploy::PlanStep::Readback(l) => println!("{i:>3} readback {l}"),
        }
    }
    Ok(())
}

fn deploy(
    cfg: &ContractsConfig,
    registry_dir: PathBuf,
    with_registry: bool,
    skip_wiring: bool,
    manual_gas: Option<String>,
    yes: bool,
) -> ContractsResult<()> {
    if cfg.network == Network::Mainnet && !yes {
        return Err(poker_contracts::error::ContractsError::ConfirmationRequired(
            "mainnet deploy: rerun with --yes (对标 CONFIRM_MAINNET=yes)".into(),
        ));
    }
    let manual = manual_gas.map(|s| parse_manual_gas(&s)).transpose()?;
    let options = SuiteOptions {
        with_table_registry: with_registry || cfg.with_table_registry,
        skip_wiring,
        manual_gas: manual,
        salt: Felt::ZERO,
    };
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| poker_contracts::error::ContractsError::Chain(format!("tokio rt: {e}")))?;
    runtime.block_on(async {
        let client = ChainClient::connect(cfg).await?;
        println!("== deployer {:#x} @ {} ({})", client.account_address(), cfg.network, cfg.rpc_url);
        let report = poker_contracts::deploy::deploy_suite(&client, cfg, &options).await?;
        let reg = registry_from_report(&report);
        let path = CanonicalAddressRegistry::path_for(&registry_dir, cfg.network);
        reg.save(&path)?;
        println!("\n== class hashes");
        for (n, c, _) in &report.class_hashes {
            println!("  {n:<28} {c:#x}");
        }
        println!("== addresses");
        println!("  vault       = {:#x}", report.addresses.vault.unwrap_or_default());
        println!("  settlement  = {:#x}", report.addresses.settlement.unwrap_or_default());
        println!("  dual        = {:#x}", report.addresses.dual.unwrap_or_default());
        println!("  anonymizer  = {:#x}", report.addresses.vault_anonymizer.unwrap_or_default());
        println!("  payout      = {:#x}", report.addresses.payout_anonymizer.unwrap_or_default());
        if let Some(r) = report.addresses.table_registry {
            println!("  registry    = {r:#x}");
        }
        println!("== wire txs");
        for (l, t) in &report.wire_txs {
            println!("  {l:<36} {t:#x}");
        }
        println!("== readbacks");
        for (l, v) in &report.readbacks {
            println!("  {l:<36} {v}");
        }
        println!("\nregistry → {}", path.display());
        println!("\n回填素材：\n{}", report.env_backfill());
        Ok(())
    })
}

fn parse_manual_gas(s: &str) -> ContractsResult<ManualGas> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return Err(poker_contracts::error::ContractsError::Config(format!(
            "manual-gas 形如 `800:1000:20000000`，got {s:?}"
        )));
    }
    let parse = |t: &str| -> ContractsResult<u64> {
        parse_felt(t)?
            .to_string()
            .parse()
            .map_err(|e| poker_contracts::error::ContractsError::Config(format!("gas {t}: {e}")))
    };
    Ok(ManualGas {
        l1_gas: parse(parts[0])?,
        l1_data_gas: parse(parts[1])?,
        l2_gas: parse(parts[2])?,
    })
}

fn status(cfg: &ContractsConfig) -> ContractsResult<()> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| poker_contracts::error::ContractsError::Chain(format!("tokio rt: {e}")))?;
    runtime.block_on(async {
        let client = ChainClient::connect(cfg).await?;
        println!("chain_id = {:#x}（{}）", client.chain_id(), cfg.network);
        let a = &cfg.addresses;
        if let Some(v) = a.vault {
            let vault = Vault::at(v);
            println!("vault        = {v:#x}");
            println!("  token           = {:#x}", vault.token(&client).await?);
            println!("  unshield_helper = {:#x}", vault.unshield_helper(&client).await?);
            println!("  lock_ttl        = {}s", vault.lock_ttl(&client).await?);
            println!("  paused          = {}", vault.paused(&client).await?);
        }
        if let Some(dual_addr) = a.dual {
            let dual = poker_contracts::bindings::dual_settlement::DualSettlement::at(dual_addr);
            println!("dual         = {dual_addr:#x}");
            println!("  vault              = {:#x}", dual.vault(&client).await?);
            println!("  circuit_program    = {:#x}", dual.circuit_program_hash(&client).await?);
            println!("  claim_helper       = {:#x}", dual.claim_helper(&client).await?);
        }
        if let Some(r) = a.table_registry {
            let reg = TableRegistry::at(r);
            println!("registry     = {r:#x}");
            println!("  table_count        = {}", reg.table_count(&client).await?);
            println!("  close_grace_secs   = {}s", reg.close_grace_secs(&client).await?);
        }
        Ok(())
    })
}

fn env_backfill(registry_path: &std::path::Path, network: Network) -> ContractsResult<()> {
    let reg = CanonicalAddressRegistry::load(registry_path)?;
    println!("{}", reg.to_markdown());
    let chain = network.preset().chain_id;
    let chain_hex = format!("{:#x}", poker_contracts::codec::short_string(chain).expect("chain id"));
    let f = |k: &str| {
        reg.contracts
            .get(k)
            .map(|e| e.address.clone())
            .unwrap_or_else(|| "<unset>".into())
    };
    println!(
        "texas/.env: STARKNET_CHAIN_ID={chain}\n            STARKNET_STRK_ADDRESS={}\n            STARKNET_VAULT_ADDRESS={}\n            STARKNET_SETTLEMENT_ADDRESS={}\n            STARKNET_DUAL_SETTLEMENT_ADDRESS={}\n            STARKNET_CLAIM_HELPER_ADDRESS={}\nclient/.env.production: VITE_STARKNET_CHAIN_ID={chain_hex}\n            VITE_POKER_VAULT_ADDRESS={}\n            VITE_POKER_VAULT_ANONYMIZER_ADDRESS={}",
        reg.constants.get("strk").cloned().unwrap_or_else(|| "<unset>".into()),
        f("PokerVault"),
        f("PokerSettlement"),
        f("PokerDualSettlement"),
        f("SettlementPayoutAnonymizer"),
        f("PokerVault"),
        f("PokerVaultAnonymizer"),
    );
    Ok(())
}

fn registry(op: RegistryOp, registry_path: &std::path::Path, network: Network) -> ContractsResult<()> {
    match op {
        RegistryOp::Path => {
            println!("{}", registry_path.display());
            Ok(())
        }
        RegistryOp::Show => {
            let reg = CanonicalAddressRegistry::load(registry_path)?;
            println!("{}", serde_json::to_string_pretty(&reg).map_err(|e| {
                poker_contracts::error::ContractsError::Config(format!("render: {e}"))
            })?);
            Ok(())
        }
        RegistryOp::Set { name, address } => {
            let mut reg = CanonicalAddressRegistry::load(registry_path)
                .unwrap_or_else(|_| CanonicalAddressRegistry::new(network));
            let addr = parse_felt(&address)?;
            let known = ContractName::all().iter().copied().find(|n| n.label() == name);
            match known {
                Some(n) => {
                    let entry = reg.contracts.get(name.as_str()).cloned().unwrap_or_default();
                    let mut entry = entry;
                    entry.address = format!("{addr:#x}");
                    reg.insert(n, entry);
                }
                None => {
                    reg.contracts.insert(
                        name.clone(),
                        poker_contracts::registry::RegistryEntry {
                            address: format!("{addr:#x}"),
                            ..Default::default()
                        },
                    );
                }
            }
            reg.save(registry_path)?;
            println!("set {name} = {addr:#x} → {}", registry_path.display());
            Ok(())
        }
    }
}

fn call(cfg: &ContractsConfig, contract: &str, r#fn: &str, calldata: &str) -> ContractsResult<()> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| poker_contracts::error::ContractsError::Chain(format!("tokio rt: {e}")))?;
    runtime.block_on(async {
        let client = ChainClient::connect(cfg).await?;
        let to = parse_felt(contract)?;
        let cd = parse_calldata(calldata)?;
        let res = client.call(to, r#fn, cd).await?;
        for f in res {
            println!("OUT={f:#x}");
        }
        Ok(())
    })
}

fn invoke(
    cfg: &ContractsConfig,
    contract: &str,
    r#fn: &str,
    calldata: &str,
    yes: bool,
) -> ContractsResult<()> {
    if !yes {
        return Err(poker_contracts::error::ContractsError::ConfirmationRequired(
            "invoke 上链操作：--yes 确认".into(),
        ));
    }
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| poker_contracts::error::ContractsError::Chain(format!("tokio rt: {e}")))?;
    runtime.block_on(async {
        let client = ChainClient::connect(cfg).await?;
        let to = parse_felt(contract)?;
        let cd = parse_calldata(calldata)?;
        let tx = client.invoke(to, r#fn, cd).await?;
        println!("TX={tx:#x}");
        let _ = client.wait_default(tx).await;
        Ok(())
    })
}
