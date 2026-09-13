//! 公共 API 接入面测试：以外部消费者视角走一遍「配置 → 计划 → 构造参数
//! → 注册表」的离线路径（不发交易），保证库形态可用（对标 aztec starter
//! 的离线编译期验证）。

use poker_contracts::artifact::{ContractArtifact, ContractName};
use poker_contracts::config::{ContractsConfig, DeployedAddresses, Network};
use poker_contracts::deploy::{PlanStep, build_plan, registry_from_report, chain_id_name};
use poker_contracts::instance::SuiteCalldata;
use poker_contracts::registry::{CanonicalAddressRegistry, RegistryEntry};
use poker_contracts::codec::Felt;

#[test]
fn config_to_plan_to_calldata_end_to_end_offline() {
    // 1) 接入侧从 texas 风格 env 构造配置
    let mut map = std::collections::BTreeMap::new();
    map.insert("POKER_CONTRACTS_NETWORK".to_string(), "sepolia".to_string());
    map.insert("STARKNET_VAULT_ADDRESS".to_string(), "0x3f4e".to_string());
    let cfg = ContractsConfig::from_env_map(&map).unwrap();
    assert_eq!(cfg.network, Network::Sepolia);
    assert_eq!(chain_id_name(cfg.network), "SN_SEPOLIA");

    // 2) 部署计划：5 declare + 5 deploy + 5 wire + 4 readback
    let plan = build_plan(false);
    assert_eq!(plan.len(), 19);
    assert!(matches!(plan[0], PlanStep::Declare(ContractName::PokerVault)));
    assert!(matches!(
        plan[5],
        PlanStep::Deploy { name: ContractName::PokerVault, .. }
    ));

    // 3) 构造参数形状（vault 占位 settlement=0 → 接线再绑定）
    let owner = Felt::from(0xA_u64);
    let vault_cd = SuiteCalldata::vault(owner, cfg.strk, Felt::ZERO);
    assert_eq!(vault_cd.len(), 3);
    let dual_cd = SuiteCalldata::dual(owner, Felt::from(0xB_u64), owner);
    assert_eq!(dual_cd.len(), 3);

    // 4) 产物齐备性检查（离线可调；本机已构建时应为 true）
    let complete = ContractArtifact::suite_complete(&cfg.artifacts_dir);
    println!("artifacts complete: {complete}");
}

#[test]
fn registry_write_then_read_as_integration_entry() {
    // 部署报告（模拟）→ 注册表 → 接入地址集
    let mut addresses = DeployedAddresses::default();
    addresses.vault = Some(Felt::from(0xB_u64));
    addresses.dual = Some(Felt::from(0xC_u64));
    let report = poker_contracts::deploy::SuiteDeploymentReport {
        network: Network::Sepolia,
        deployer: Felt::ONE,
        owner: Felt::ONE,
        prover: Felt::ONE,
        strk: Felt::from(2_u64),
        pool: Felt::from(3_u64),
        class_hashes: vec![(ContractName::PokerDualSettlement, Felt::from(0x10_u64), Felt::from(0x20_u64))],
        declare_txs: vec![],
        deploy_txs: vec![(ContractName::PokerDualSettlement, Felt::from(0x40_u64))],
        wire_txs: vec![("dual.set_circuit_program_hash", Felt::from(0x50_u64))],
        readbacks: vec![],
        addresses,
    };
    let mut reg = registry_from_report(&report);
    // 手工补一条（redeploy_anonymizer 场景）
    reg.insert(
        ContractName::PokerVaultAnonymizer,
        RegistryEntry { address: "0x7ee0".into(), ..Default::default() },
    );

    let dir = std::env::temp_dir().join("poker-contracts-it");
    let path = CanonicalAddressRegistry::path_for(&dir, Network::Sepolia);
    reg.save(&path).unwrap();
    let loaded = CanonicalAddressRegistry::load(&path).unwrap();

    let addrs = loaded.to_deployed_addresses();
    assert_eq!(addrs.vault, Some(Felt::from(0xB_u64)));
    assert_eq!(addrs.dual, Some(Felt::from(0xC_u64)));
    assert_eq!(
        addrs.vault_anonymizer,
        Some(Felt::from(0x7ee0_u64)),
        "手工补录的 anonymizer 可被接入侧解析"
    );
    // markdown 回填素材含全部条目
    let md = loaded.to_markdown();
    assert!(md.contains("PokerVault"));
    assert!(md.contains("PokerVaultAnonymizer"));
    assert!(md.contains("PokerDualSettlement"));
}
