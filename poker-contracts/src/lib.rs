//! # poker-contracts — 合约模块
//!
//! zchain 的 Starknet 合约部署与接入层：把 [poker_texas_air] 的
//! `poker_contracts`（Cairo/Starknet，Cairo 2.19.4 + OpenZeppelin 1.0）从
//! 「snops + bash 脚本 + 手工回填文档」升级为**类型化的 Rust 部署流水线与
//! 接入绑定**。
//!
//! ## 架构对标（Stark 系实现，参考 Aztec）
//!
//! Aztec 的合约栈把"部署"拆成两段——**发布合约类（class）**与**创建合约
//! 实例（instance）**，实例地址由 (class, 构造参数, salt, deployer) 确定性
//! 推导；Starknet 的 declare / UDC deploy 与之一一对应。本模块按同一分层
//! 组织（括号内为 Aztec 对应物）：
//!
//! | 本模块 | 对标 Aztec | 说明 |
//! |---|---|---|
//! | [`artifact::ContractArtifact`] | `ContractArtifact` | 合约类包：sierra+casm+class hash（aztec 为 Noir→ACIR 产物包） |
//! | [`instance::ContractInstance`] | `ContractInstance` / `getContractInstanceFromInstantiationParams` | 实例 = 类 + salt + 构造参数 + deployer/UDC；地址可离线预推导 |
//! | [`deployer::ContractDeployer`] | aztec.js `DeployMethod` / `ContractDeployer` | builder：`.salt()` / `.constructor()` / `.universal()` → `declare()` / `deploy()` |
//! | [`client::ChainClient`] | aztec.js `Wallet` + PXE | provider + 单签账户；`call` / `invoke` / `wait_for_acceptance`（对标 `waitForTx`） |
//! | `bindings::*::at()` | 生成的 `MyContract.at(address, wallet)` | 已部署实例的类型化调用句柄 |
//! | [`registry::CanonicalAddressRegistry`] | canonical 地址注册表（`get-canonical-*` CLI） | 每网络机器可读地址注册表（`deployments/<network>.json`） |
//! | [`deploy::SuiteDeployer`] | 协议合约部署脚本（含 registry 引导） | poker 协议套件的有序部署：declare×N → deploy×N → 接线 → 回读 → 注册表回写 |
//!
//! 语义对应：declare = 类注册（readiness 状态一：class registered）；
//! UDC deploy = 实例发布（状态二：instance published）；构造器执行 + 接线
//! 回读 = 初始化（状态三：initialized）。UDC **unique** 模式（地址含
//! deployer）对标 Aztec 默认（deployer 参与地址推导）；UDC 非 unique
//! （`universal(true)`）对标 Aztec `universalDeploy`——同 salt 跨网络同地址。
//!
//! ## 部署与接入的分工
//!
//! - **部署**（[`deploy`]）：产物取自 poker_texas_air 的 scarb 构建输出
//!   （`poker_contracts/target/dev/*.json`），部署顺序冻结自其
//!   `DEPLOYMENTS.md` / `scripts/deploy_mainnet.sh`（同序等价替换）。
//! - **接入**（`bindings`）：zchain 侧组件（结算出口 / 运维 CLI / 后续
//!   wallet 集成）消费部署注册表 + 类型化绑定，直接读写 Vault、
//!   DualSettlement、TableRegistry 与规范 STRK。
//!
//! [poker_texas_air]: https://github.com/ (外部仓库，见 DEPLOYMENTS.md)
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod artifact;
pub mod bindings;
pub mod client;
pub mod codec;
pub mod config;
pub mod deploy;
pub mod deployer;
pub mod error;
pub mod instance;
pub mod registry;

pub use artifact::ContractArtifact;
pub use client::ChainClient;
pub use config::ContractsConfig;
pub use deployer::ContractDeployer;
pub use error::{ContractsError, ContractsResult};
pub use instance::ContractInstance;
