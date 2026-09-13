# poker-contracts — 合约模块

zchain 的 **Starknet 合约部署与接入层**：把 [poker_texas_air] 的
`poker_contracts`（Cairo 2.19.4 + OpenZeppelin，Sepolia/主网已在网）从
「snops + bash 脚本 + 手工回填文档」升级为**类型化的 Rust 部署流水线与
接入绑定**。

## 架构对标（Stark 系实现，参考 Aztec）

Aztec 把"部署"拆成两段——**发布合约类（class）**与**创建合约实例
（instance）**，实例地址由 (class, 构造参数, salt, deployer) 确定性推导。
Starknet 的 declare / UDC deploy 与之同构，本模块按同一分层组织：

| 本模块 | 对标 Aztec | 说明 |
|---|---|---|
| `artifact::ContractArtifact` | `ContractArtifact` | 合约类包：sierra + casm + 两级类哈希 |
| `instance::ContractInstance` | `ContractInstance` / `getInstance()` | 实例 = 类 + salt + 构造参数 + deployer/UDC；地址离线可推导 |
| `deployer::ContractDeployer` | aztec.js `DeployMethod` / `ContractDeployer` | `.salt()` / `.constructor()` / `.universal()` → `declare()` / `deploy()` |
| `client::ChainClient` | aztec.js `Wallet` + PXE | `call` / `invoke` / `invoke_batch`（对标 `BatchCall`）/ `wait_for_acceptance`（对标 `waitForTx`） |
| `bindings::*::at()` | 生成的 `MyContract.at(address, wallet)` | 已部署实例的类型化调用句柄 |
| `registry::CanonicalAddressRegistry` | canonical 地址注册表（`get-canonical-*`） | 每网络机器可读 `registry/<network>.json` |
| `deploy::deploy_suite` | 协议合约部署脚本 + registry 引导 | declare×N → deploy×N → 接线 → 回读 → 注册表回写 |

语义对应：**declare = 类注册**（readiness ①）；**UDC deploy = 实例发布**
（readiness ②）；**接线 + 回读 = 初始化**（readiness ③）。UDC **unique**
模式（地址含 deployer，DEPLOYMENTS 惯例）对标 Aztec 默认；`.universal(true)`
（UDC 非 unique）对标 Aztec `universalDeploy`——同 salt 跨网络同地址。

## 目录

```
src/
  codec.rs      felt/ByteArray/uint256/selector 编码（与 snops/corelib 逐字节一致）
  config.rs     网络预设（devnet/sepolia/mainnet）+ env 加载（texas .env 可直读）
  artifact.rs   scarb 产物加载（poker_contracts/target/dev）
  instance.rs   实例地址推导 + 套件构造参数（SuiteCalldata）
  client.rs     RPC + 单签账户 + 回执等待
  deployer.rs   ContractDeployer（mismatch 重试 / already-declared 幂等 / manual_gas）
  deploy.rs     套件编排 + 部署计划 + env 回填输出
  bindings/     STRK / Vault / Settlement(legacy) / DualSettlement / TableRegistry
  registry.rs   canonical 注册表（JSON + markdown 回填素材）
bin/poker-contracts.rs   CLI（plan / deploy / status / env-backfill / registry / call / invoke）
```

## 前置条件

```bash
# 合约产物（scarb 2.19.4，poker_texas_air 侧工具链）
cd ../poker_texas_air/poker_contracts
PATH="$HOME/.local/opt/toolchains/scarb-2.19.4/bin:$PATH" scarb build
# 产物落在 poker_contracts/target/dev/poker_contracts_*.json
```

产物目录缺省解析为 `<zchain>/../poker_texas_air/poker_contracts/target/dev`，
可用 `POKER_CONTRACTS_ARTIFACTS_DIR` / `--artifacts-dir` 覆盖。

## 部署

```bash
cargo build -p poker-contracts

# 离线预览：产物齐备性 + 计划步骤表（不连链）
cargo run -p poker-contracts -- plan --network devnet

# devnet 全量部署（starknet-devnet --seed 0，端口 5051；ADDRESS/PRIVATE_KEY
# 取 devnet 预充值账户）
ADDRESS=0x… PRIVATE_KEY=0x… \
cargo run -p poker-contracts -- deploy --network devnet --with-registry

# Sepolia（env 文件直读 poker_texas_air 的 .env.dev）
cargo run -p poker-contracts -- --env-file ../poker_texas_air/.env.dev deploy --network sepolia

# 主网：必须显式 --yes（对标 CONFIRM_MAINNET=yes）
ADDRESS=0x… PRIVATE_KEY=0x… \
cargo run -p poker-contracts -- deploy --network mainnet --yes
```

执行顺序冻结自 poker_texas_air `DEPLOYMENTS.md` / `scripts/deploy_mainnet.sh`
（同序等价替换 bash+snops）：

1. declare ×5（+Registry 可选）；
2. `PokerVault(owner, STRK, settlement=0)`；
3. `PokerSettlement(owner, vault, prover)`、`PokerDualSettlement(owner, vault, prover)`；
4. `PokerVaultAnonymizer(owner, vault, pool)`、`SettlementPayoutAnonymizer(vault, pool, dual)`；
5. `PokerTableRegistry(owner, grace)`（可选，默认关——与 2026-09-11 部署状态一致）；
6. 接线：vault.settlement=dual、vault.unshield_helper=anonymizer、
   dual.claim_helper=payout、dual.circuit_program_hash、dual.hand_verify_program_hash；
7. 链上回读（不严重试 3 次）→ `registry/<network>.json` 回写 → env 回填输出。

内置兼容（poker_texas_air 实测坑，与 snops 同策略）：

- 节点 casm 哈希方案与本地不一致（`Mismatch compiled class hash`）→ 自动提取
  节点 `Expected:` 哈希重试；
- 类已在链上 → 幂等（`already_declared`）；
- 公共 RPC 对大合约 estimateFee 限制（503）→ `--manual-gas l1:l1d:l2` 显式上限。

## 接入

```bash
# 读现网接线（地址取 env / 注册表；可直读 texas/.env）
cargo run -p poker-contracts -- --env-file ../poker_texas_air/texas/.env status

# 输出 texas/.env 与 client/.env.production 回填片段（读注册表）
cargo run -p poker-contracts -- env-backfill

# 通用视图调用 / 交易（--yes 确认）
cargo run -p poker-contracts -- call --contract <VAULT> --fn chip_balance --calldata <PLAYER>
```

库形态（zchain 内其他 crate 的接入面）：

```rust
use poker_contracts::{ChainClient, ContractsConfig, bindings::vault::Vault};

let cfg = ContractsConfig::from_env()?;          // texas .env 变量名兼容
let client = ChainClient::connect(&cfg).await?;
let vault = Vault::at(cfg.addresses.vault.unwrap());
let chips = vault.chip_balance(&client, player).await?;   // [low, high] u256
// 写调用可合并一次签名（对标 BatchCall）
client.invoke_batch(vec![
    vault.deposit_call(chips),
    vault.unlock_after_deadline_call(player),
]).await?;
```

绑定覆盖：STRK（balance/approve/transfer）、Vault（deposit/withdraw/lock/
TTL 解锁/chip_balance/set_settlement_contract）、DualSettlement
（register_hand 七标量形 + 状态核验 + owner 接线）、Settlement legacy
（只读核验）、TableRegistry（`compute_params_hash` Poseidon 锚点 +
create/close/is_open，与 texas `table_registry.rs` 同式，KAT 见
`tests/params_hash.rs`）。

### canonical 注册表

部署完成后写 `registry/<network>.json`（合约地址 + class hash + 交易 +
接线记录 + strk/pool 常量），是 `DEPLOYMENTS.md` 的机器可读镜像；接入侧
`to_deployed_addresses()` 直接解析，`to_markdown()` 生成文档回填素材。
`registry set <Name> <addr>` 支持手工补录（如重部署 anonymizer）。

## 测试

```bash
cargo test -p poker-contracts --all-targets
```

32 例全离线（真实产物冒烟在本机已 `scarb build` 时自动生效，缺失软跳过），
覆盖：ByteArray/felt 编码（与 snops 逐字节一致）、实例地址推导
（unique/universal 分离）、构造参数形状（对照 deploy_mainnet.sh）、部署
计划顺序（对照 [1/7]–[7/7]）、env/注册表往返、poseidon params_hash KAT。

## 语义边界（诚实清单）

- **结算提交不在此构造**：`verify_and_settle_dapv_*` 的 15-felt 公开段 /
  SNIP-36 proof facts 载荷由 poker_texas_air 证明侧产出，形状归其 ABI——
  本模块提供 `register_hand` 与状态/接线面；
- 注册表**不碰钱**、不进证明约束（锚定增强而非缰绳）；
- **TableRegistry 部署尚未进 sepolia/mainnet 批量脚本**（2026-09-11 状态），
  `--with-registry` 显式开启。

[poker_texas_air]: ../poker_texas_air/README.md
