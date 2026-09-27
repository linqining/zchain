# 多结算层架构（Multi-Settlement）—— 设计与落地计划 v1

> 目标：zchain 同一套引擎（poker-appchain + poker_l1 + poker_texas_air）支持
> **多种部署形态**：既是自主主网（sovereign，BFT 终结），也可作为 L2 接入
> Monad（已落地验收），后续接入 Solana 或任意 EVM host。
> **新增一条结算链的代价 = 实现一个 `SettlementAdapter` trait + 在钱包注册表
> 登记一个条目**，引擎与钱包的登录/买入链路零改动。
>
> 状态：Phase 0 ✅（Monad 测试网 attestation 结算验收 7/7）、Phase 1 进行中
> （本文 + settlement-adapter crate + 钱包加链即用）。2026-09-27 起 zkVM 路线
> （poker_zkvm）已移除，validity 结算的证明完备性由 poker_texas_air 自定义 AIR
> 覆盖全部业务语义 + 递归聚合承担（见 00-architecture-overview.md §4.2）。

---

## 1. 模式模型：一套引擎，两种部署 profile

| | profile: sovereign（自主主网） | profile: L2（宿主结算） |
| --- | --- | --- |
| 执行 | poker-appchain 引擎（soft-confirm 帧 + WAL） | **同一引擎** |
| 状态根产出 | 帧内 state_root | 同左 |
| 最终性 | poker_l1 BFT（Narwhal-Bullshark） | 宿主链结算合约（SettlementAdapter 推进） |
| 数据可用 | 自托管（WAL + 网关归档） | 宿主 calldata / 外部 DA（`DaBackend` trait，Phase 1.5） |
| 信任根 | 验证者集 | 宿主链 + 承诺/证明 |
| 资产归属 | ZCN 归本链 | USDT/USDC/MON 归宿主（per-asset canonical，不允许双信任根） |

**决策**：部署形态二选一，不并行双跑同一资产；三层信任模型（docs/37-10）中的
L2/L3 通道在两种 profile 下语义一致。

## 2. SettlementAdapter trait（已形式化：`settlement-adapter/` crate）

四个职责面（与 L2 承诺产物一一对应）：

| trait 方法 | L2 侧产物 | 宿主侧落点 |
| --- | --- | --- |
| `submit_anchor(AnchorTask)` | batch_root / aggregate_root / checkpoint | Inbox（EVM: `contracts/monad` L1Inbox；Solana: Anchor program） |
| `poll()` / `pending_finality()` / `snapshot()` / `restore()` | — | 回执 + 最终性（EVM `finalized` 标签 / Solana finalized commitment） |
| `poll_deposits()` | `DepositV2` op（deposit_id 幂等） | Bridge 入金事件 |
| `claim_payload(ClaimRequest)` | withdrawal_root + Merkle proof | Outbox claim |

**字节纪律**：`AnchorTask.payload` 是不透明字节——适配器不解释内容，承诺语义
由 poker-appchain / poker_texas_air 冻结。同一份承诺产物换宿主链零转换。

**实现契约**（trait 级测试强制，见 `settlement-adapter/src/lib.rs` 与
`monad-settlement/tests/adapter_trait.rs`）：
1. `connect`/构造期做链身份校验（chainId 不符 fail-closed）；
2. `submit_anchor` 按 key 幂等；状态机 `Submitted → Included → Finalized`；
3. `poll_deposits` 只产出**已终结**入金，nonce 去重；
4. PLAY（tag 2）不可跨链兑付；快照/恢复幂等。

**已有实现**：`monad-settlement::MonadAdapter`（锚定/入金/claim 全走通，
Monad 测试网 E2E 7/7）。新增链（如 Solana）= 新 crate（如
`solana-settlement`）实现同 trait，daemon 与引擎按 `dyn SettlementAdapter` 消费。

## 3. poker_texas_air 适配面（加链时 AIR 本体零改动）

外部 crate（`/Users/mac/projects/poker_texas_air`）的分工边界，保证**加链不碰
电路**：

| 层 | 加链时是否改动 | 说明 |
| --- | --- | --- |
| `airs/*`（21 method AIR）+ `texas_canonical*` | **不改** | 业务语义直写电路，链无关 |
| `proof_archive` / `public_inputs` / `outer_aggregate` | **不改** | 证明产物 = 链无关字节（batch_root/aggregate_root/public inputs） |
| `settlement_binding` / `starknet_settlement` | **新增一个兄弟模块** | 按链出 calldata/调用编码：Starknet 先例 → 新 host 加 `host_evm_settlement`（Monad 已由 zchain 侧 `monad-settlement::abi` 承担，可回迁合并） |
| `orchestrator` / `prove_task` | 不改 | 消费 vm-common `ProveTask`，输出承诺字节 |

**证明产物契约**（poker_texas_air 对所有宿主链的稳定承诺）：
`batch_root: [u8;32]`、`aggregate_root: [u8;32]`、`withdrawal_root: [u8;32]`
（树构造域 `zchain.vault.withdrawal_root.v1`，三方对齐守卫见
`monad-settlement/tests/withdrawal_crosscheck.rs`）、`proof_archive` 字节。
任何宿主链的结算合约/程序只消费这些字节 + 验证器；**AIR 与证明器永远是
链无关的单例**。

## 4. 钱包"加链即用"（登录 + 买入）

### 4.1 extension（浏览器钱包，已落地）

**加链即用契约**：在 `extension/common/evm/networks.js` 登记条目并携带

```js
{ id, name, chainIdHex, kind, rpcUrl, explorerUrl,
  settlement: true, bridgeAddress: '0x…', inboxAddress: '0x…' }
```

⇒ 三个能力**自动开启**（无需改任何其他代码）：

| 能力 | 载体 | 状态 |
| --- | --- | --- |
| 登录（网络视图/RPC/explorer） | `evmNetworkView`（service_worker 已按注册表驱动） | ✅ 登记即有 |
| 买入（原生币） | `common/evm/settlement.js::buildDepositIntent` → L1Bridge `depositNative`（value=金额，data=收款人） | ✅ 本轮落地 |
| 买入（ERC-20） | `buildTokenDepositIntents` → approve + `depositToken` 两步 | ✅ 本轮落地 |

门位纪律：`bridgeAddress: null` = 该链结算合约未部署，**买入门位关闭但登录
不受影响**（Monad 主网条目即此状态）；非结算链调用买入 → typed 错误
`ChainNotSettlement`。能力视图 `settlementCapabilities(network)` 供 popup 按
capability 渲染。

守卫测试：`extension/tests/evm/settlement.test.js`（7 项，含**加链模拟测试**
——登记新条目后登录+买入即刻可用的端到端断言）。

### 4.2 wallet-app（Rust 桌面/移动）

`zwallet` 的 `SETTLEMENT_L1/SETTLEMENT_L1_CHAIN_ID` 常量为 devnet 占位；下一
步骤改为从部署配置读取（与 extension 同一注册表数据源的 JSON 导出），登录页
展示结算层网络。真实买入/提现走 daemon（monad_settlementd），钱包侧不直签
宿主链交易（密钥隔离）。

## 5. host 差距矩阵

| 能力 | Monad（现状） | Solana（差距） |
| --- | --- | --- |
| 结算合约/程序 | ✅ L1Inbox/Outbox/Bridge（测试网验收 7/7） | ❌ Anchor 版待建（PDA 账户模型、SPL token-2022） |
| SettlementAdapter | ✅ `MonadAdapter`（trait 契约测试全绿） | ❌ `SolanaAdapter`（ed25519 + durable nonce + blockhash） |
| 入金事件面 | ✅ EVM log（DepositWatcher） | ❌ 程序日志/CPI event 解析（无 EVM log） |
| 最终性 | ✅ `finalized` 标签 | ❌ `finalized` commitment（~13s，同构） |
| 证明验证 | ⏳ attestation 先行；validity = poker_texas_air AIR 覆盖 + 递归 → SP1 包装上 EVM 验证器 | ❌ **`stwo-solana-probe`**（SBF 跑 Stwo 验证器的 CU/内存实测；先探针后实现） |
| DA | ⏳ 自托管（现状）+ 宿主 calldata 备选 | 同左 |
| 强制包含 | ⏳ 宿主侧 escape 通道（经桥进 Inbox 的 force tx）待建 | 同左 |

## 6. 里程碑（zkVM 移除后修订版）

- **Phase 1（进行中）**：SettlementAdapter 形式化 ✅（本轮）；钱包加链即用 ✅（本轮）；
  剩余：宿主侧强制包含通道、`DaBackend` trait、daemon 按 `dyn SettlementAdapter`
  装配（monad_settlementd 收敛到 adapter 调用面）。
- **Phase 2（validity 结算）**：poker_texas_air AIR 从"21 method PoC + 输入一致性
  约束"扩展到**全业务语义覆盖**；递归聚合到常量尺寸（Layer 2/3 落地）；
  Monad 侧 SP1 包装验证器上 EVM。唯一硬性里程碑。
- **Phase 3（Solana）**：`stwo-solana-probe` → Anchor Inbox/Outbox/Bridge →
  `SolanaAdapter` → 钱包注册表登记条目（按 §4 契约自动获得登录/买入）。
- **Phase 4**：sequencer 去中心化叙事（poker_l1 BFT 作为 shared sequencer 的
  可选形态）另行立项。

## 7. 新结算链接入 runbook（checklist）

1. **合约/程序**：按 `contracts/monad` 形状实现该链 Inbox/Outbox/Bridge
   （承诺哈希逐字节对齐 poker_texas_air / poker-appchain；金标准向量测试强制）。
2. **适配器**：新 crate 实现 `SettlementAdapter`（对照 `MonadAdapter` 与
   `monad-settlement/tests/adapter_trait.rs` 契约测试）。
3. **daemon**：以 `dyn SettlementAdapter` 装配（anchor/bridge 模式逻辑复用）。
4. **部署 + E2E**：带水钥执行该链版 `monad_e2e` 等价验收（7 项）。
5. **钱包**：`networks.js` 登记条目（settlement + 地址）→ 登录/买入自动可用；
   能力测试（§4.1 模拟加链测试复制一份）。
6. **poker_texas_air**：仅在需要该链原生 calldata 编码时加一个 settlement
   binding 模块（AIR/证明器零改动）。
7. **审计**：承诺哈希三方对齐、reorg/最终性窗口、入金幂等、authority 多签。

---

## 8. 相关文档

- [monad-l2-settlement.md](monad-l2-settlement.md) — Monad 结算层设计与验收（Phase 0）
- [00-architecture-overview.md](00-architecture-overview.md) §4.2 — zkVM 移除决策
- `settlement-adapter/` — trait 与契约测试（本文 §2 的代码形态）
- `extension/common/evm/settlement.js` + `tests/evm/settlement.test.js` — 钱包加链即用（§4.1）
