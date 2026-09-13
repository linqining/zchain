# DA（数据可用性）选型决策报告

> 状态：评审建议 1 的出口交付物（工程决策文档）。
> 日期：2026-09-12 起草，决策记录定稿 2026-09-13。
> 性质：只做选型论证与对接面草案，**不含实现**。
> 诚实纪律：所有外部数字标注来源与查询日期（2026-09-12）；查不到一手数据
> 的一律标"量级估算"或"未获得一手数据，需询价/实测"。
> 仓库证据均给出文件路径；数据量级估算方法见 §2.1。

---

## 1. 背景与问题定义

### 1.1 DA 在本项目中的角色（评审结论复述）

- v1 是托管式单 Sequencer 软确认链；v1.5 引入 4–7 validator 的 BFT
  checkpoint（`docs/plan-appchain-v1.md` §5.1、§5.5）。
- ForceWithdraw / ForceSettle 逃生舱依赖"从最后一个 finalized checkpoint
  恢复"（plan §5.3 第 5 条）。**checkpoint 目前只落运营方自有存储**
  （`poker-appchain/src/checkpoint.rs` 导出本地 JSON；`docs/runbook.md`
  明确 BFT checkpoint 属 v1.5 尚未上线）——sequencer 扣数据时，
  proven 状态本身救不了用户：恢复所需的 checkpoint 与底层数据同样不可得。
- 因此 DA 不是锦上添花，而是 v1.5"抗审查最终性"叙事的**前置条件**：
  没有独立于 sequencer 的数据可得性，"从 checkpoint 恢复"只是运营方
  自我担保的口头承诺。

### 1.2 语义边界（与仓库现有三个"DA"字样的区分）

仓库里有三处出现 DA 字样，语义不同，避免混淆：

| 位置 | 语义 | 与本报告关系 |
|---|---|---|
| `poker_l1/src/consensus/da.rs` | v1.5 DA **凭证原语**：DaRequest/DaReceipt/DaCertificate（validator 对数据摘要签"可得"回执，2f+1 BLS 聚合） | 本报告选型的直接对接面（§5） |
| `poker_l1/src/vm/contracts/request_da.rs` | 游戏对局"操作方故障恢复"的 `request_da` 信号 tx（`da_window_blocks` 等，`docs/37-1-node-deployment.md` 默认 500 块） | 无关层；仅命名撞车 |
| 本报告的 DA | 系统级数据可得性：checkpoint / 根 / 软确认链数据的**独立于 sequencer 的可得性** | 选型对象 |

`da.rs` 模块头对自身边界的自述必须原样带入选型语境：它**不是**完整 DA 层
——没有擦除码、没有随机采样（DAS）、没有挑战/扣分游戏，"validator 签
回执"的诚实性由签名者自律承担（`da.rs` 文件头注释原文）。凭证成立
**不等于**数据可取回，这是本报告推荐方案要补的第一个缺口。

---

## 2. 需要哪些数据、多大、分几层

### 2.1 数据量级估算（方法学先行）

**方法**：全部从仓库实测数字外推，不做无来源假设。输入：

1. **ops/手 = 5.02**：64 桌 × 50 手压测 → 3200 结算 / 16064 操作
   （`docs/plan-appchain-v1.md` §实现状态 2026-09-05，`poker-appchain`
   loadtest 实测）。
2. **批次 = 64 ops**（`poker-appchain/src/pipeline.rs:248` `batch_size: 64`）。
3. **checkpoint 间隔 = 32 高度**（`poker_l1/src/consensus/checkpoint.rs:193`
   `DEFAULT_CHECKPOINT_INTERVAL_BLOCKS = 32`，v1.5 运行期默认；注意另有一个
   legacy `CHECKPOINT_INTERVAL = 10_000` 是审查检测窗口基准，语义不同）。
4. **出块节奏目标约 3 秒**（plan §5.5 Bullshark 行"当前目标约 3 秒"）。
5. **帧结构**（`poker-appchain/src/soft_confirm.rs`）：SignedFrame =
   index(8B) + prev_hash(32B) + op + state_root(32B) + ts(8B) + 签名(64B)；
   op 体积由变体决定（Settle 帧含 SettlementRecord/payout 向量，是大头）。
6. **单手批次证明归档 ≈ 1.19 MB**（`docs/plan-appchain-perf.md` M4-ACC-1
   表，borsh 信封整档长度实测）。

**任务给定的业务量**"64 桌 × 每天约 5 万手"存在两种读法，两个口径都给出：

| 项 | 保守口径（全网 5 万手/天） | 激进口径（64 桌 × 各 5 万手 = 320 万手/天） |
|---|---|---|
| 操作数/天 | ≈ 25 万 | ≈ 1,600 万 |
| 批次数/天（÷64） | ≈ 3,900 | ≈ 25 万 |
| 软确认链（WAL）体积/天 | 75–380 MB（帧按 0.3–1.5 KB 结构推算区间*） | 4.8–24 GB |
| 软确认链年归档 | 27–140 GB | 1.7–8.8 TB |
| 批次证明归档/天 | 4.7–7.8 GB（3,900 批 × 1.2–2 MB**） | 300–500 GB |
| batch root 原始字节/天 | ≈ 0.16 MB（3,900 × 40B 规范字节） | ≈ 10 MB |
| checkpoint QC/天 | 32 块 × 1–3 s ⇒ 900–2,700 个/天；每个约 1 KB（7 个 G2 公钥 672B + 48B 聚合签 + 字段）⇒ **1–3 MB/天** | 同左（频率由块高驱动，与手数无关） |

\* 帧字节数未实测——borsh 编码的 Settle 帧含 payout 向量与签名，数量级
在此区间；**需一次性基准实测后修订**（工程量 S 档）。
\*\* 1.19 MB 是 log_size 8（单手、256 行 trace）的实测下限；64-op 批次
行数上升，STARK 证明字节数随 log_size 缓增，取 1.2–2 MB 区间，**未实测**。

**核心结论：DA 关键层（checkpoint + 各类根）在两个口径下都是
"小而低频"（MB/天量级），与手数增长基本解耦；全量软确认链与证明归档
才是体量大头（GB–TB/天量级），且它们不是逃生舱的必要条件（见 §2.2）。**

### 2.2 论证：全量区块数据是否需要 DA？

**结论：逃生舱只需要 checkpoint + 根（withdrawal_root、batch root 表、
state_root）达到强 DA；全量软确认链不需要外部强 DA。** 论证链：

1. **提现路径只需要根 + Merkle proof。** plan §5.4 的提款流程：
   REAL note burn → WithdrawalLeaf → checkpoint 携带 withdrawal_root →
   用户拿 Merkle proof 在 Vault permissionless claim。Vault 合约只验证
   proof 对已锚定的 withdrawal_root。用户自有数据（note/spend secret）
   在钱包本地（poker-wallet 加密备份纪律）。
2. **ForceSettle/ForceWithdraw 的重放恢复需要的是"从 checkpoint 起的状态
   重建数据"，而重建数据可以由 4–7 validator 副本供给。** v1.5 形态下每
   个 validator 本就是全量数据的持有者/见证者——`da.rs` 的回执语义正是
   "本 validator 已持有/可提供 digest 对应数据"。sequencer 扣数据时，
   只要 ≥1 个诚实 validator 副本存活即可恢复；validator 全体与 sequencer
   合谋（关联失败）才是残余风险，对应缓解见 §4 与风险 R3。
3. **经济上反过来看更清楚**：把 4.7–500 GB/天的证明归档与 WAL 塞进外部
   DA（Celestia/EigenDA），成本与运维增长两个数量级，而换来的是
   "第三方也存了一份全量数据"——但全量数据的**完整性验证**已经由
   状态根/批次根/checkpoint 链承担，第三方全量副本只在"validator 全灭 +
   运营方归档全灭"的双灾场景才有增量价值，该场景下有更便宜的答案
   （冷备份 + 逻辑快照）。
4. **反面约束（诚实记录）**：若 v1.5 的 4–7 validator 实际由运营方-affiliated
   主体运行（招募不足时的现实可能），"validator 副本"退化为运营方自己的
   多副本，论证 2 失效。此时**不是**把全量数据搬上外部 DA，而是把
   checkpoint 链锚定到外部（§4 主选），并把"validator 独立性"作为治理
   门槛跟踪。

### 2.3 数据分层建议

```text
┌─ L1 逃生舱层（强 DA，小而低频，MB/天）────────────────────┐
│ checkpoint QC 链（含 state_root、批次根表摘要/增量、        │
│ withdrawal_root）+ 每检查点 batch root 增量表               │
│ → 多副本对象存储 + validator 见证凭证 + 外部锚定（§4）      │
├─ L2 归档层（弱 DA，GB/天，容许 RPO 小时级）────────────────┤
│ 软确认链 WAL 全量、批次证明归档（~1.2MB/批）、proof 注册表  │
│ → 自托管对象存储 + 内容寻址（blake2s digest 已内建）；      │
│   丢失不困死资金（L1 层可独立支撑逃生舱），只伤审计/浏览器  │
├─ L3 冷备层（合规/审计快照）────────────────────────────────┤
│ rake_audit 导出、checkpoint 全量快照、账实对账报告          │
│ → 归档存储 + 逻辑快照，保留策略按合规定                     │
└─────────────────────────────────────────────────────────────┘
```

现有代码对分层友好：`poker-appchain/src/archive_index.rs`（JSONL 索引、
blake2s 全文件 digest）已给 L2 内容寻址；`checkpoint.rs` 的
`payload_digest`（blake2s32 规范字节）已给 L1 一个可独立验证的对象摘要。

---

## 3. 候选对比

> 维度：信任假设 / 额外依赖与攻击面 / 延迟 / 成本量级 / 运维复杂度 /
> 与 4–7 validator 形态匹配度 / 退出迁移成本。
> 所有成本为**量级估算**，查询日 2026-09-12，来源见 §7。

### 3.1 对比矩阵

| 维度 | Celestia | EigenDA | Avail | 自托管对象存储 + 见证签名（现状增强） | Ethereum blobs（简述） |
|---|---|---|---|---|---|
| 信任假设 | 独立 PoS 链 + DAS 轻客户端抽样；多钱包/生态独立验证 | EigenLayer 再质押运营者集（ETH/EIGEN）；Disperser 角色中心化（官方架构文档明示该角色） | 独立 PoS 链 + KZG 有效性证明 + 轻客户端 DAS | 运营方 + 4–7 validator 签名自律（挑战机制补强后）+ 外部锚定点 | 以太坊 L1 共识；**blob 约 18 天后被节点修剪（EIP-4844 规范）**，只适合"短期可用窗口" |
| 额外依赖 | 轻节点/桥接节点、TIA gas 管理、namespace 客户端 | disperser client、检索组件、证书验证、EIGEN/ETH 敞口 | 轻客户端、AVAIL 敞口 | 无新外部依赖（S3/R2 兼容客户端） | 无独立依赖，但本项目结算层在 Starknet，直接用 blobs 需另起以太坊通道 |
| 延迟 | blob 上链随区块（秒–分钟级确认） | 官方文档：完整 dispersal 生命周期平均 5s、p99 <10s（V2 博客另宣称 5ms 用户延迟——官方口径不一致，需实测） | 未获得一手数据，需实测 | 写即达（本地/区域 ms 级） | 区块间隔 ~12s + blob 费市场波动 |
| 成本量级 | ~$0.07–0.81/MB（第三方聚合）；L1 层 1–4 MB/天 ⇒ 美分/天 | 未获得一手公开单价（reserved bandwidth 定价模型），需询价 | 未获得一手数据，需询价 | 公开列表价（量级估算）：保守口径 $1–5/月；激进口径 TB 级 ⇒ 数十–数百美元/月 | Pectra 后中位 blob 费近零（第三方研究），但**不可作档案** |
| 运维复杂度 | 中–高：需常驻轻节点 + TIA 余额监控 | 中–高：多组件 + 证书流 + 再质押参数治理 | 中：轻客户端生态较新 | 低：云存储 + 既有 watcher/演练纪律 | 低使用门槛，但引入以太坊侧 gas 运维 |
| 与 4–7 validator 匹配 | 需要额外节点角色，validator 集不参与其安全 | 安全不来自我方 validator；我方只成 disperser 客户 | 同左 | **天然匹配**：da.rs 已复用 checkpoint QC 的 BLS 基建（2f+1 聚合） | 无交互 |
| 退出/迁移成本 | 低：digest 引用可换 sink | 低：同左，但证书格式绑定其协议 | 低 | **最低**：任何外部 DA 都可后挂为附加 sink | 低 |

### 3.2 各候选要点

**Celestia**：独立 DA 链，数据经擦除码 + Namespaced Merkle Tree 发布，
轻客户端做 DAS 抽样（官方文档）。Blob 费用第三方聚合口径
~$0.07–0.81/MB（低需 vs 均值），本项目 L1 层 1–4 MB/天即美分/天量级；
即使激进口径全量 WAL（4.8–24 GB/天）也在 $0.35–19/天区间（按低价档
$0.07/MB 外推，**量级估算**）。风险：TIA 价格波动大（2026-06 第三方行情
~$0.38、历史低点 $0.28，标记为第三方数据），gas 资金管理与轻节点常驻
运维是真实成本；数据保留期参数需对照当前文档复核（未复核到一手数字）。

**EigenDA**：基于 EigenLayer 再质押的 AVS。官方文档明确 disperser 负责
收取 blob、擦除编码、KZG 承诺并分发；官方延迟口径"完整 dispersal
平均 5s / p99 <10s"（其 V2 博客宣称 5ms——官方两处口径不一致，如实记录，
需实测裁决）。安全来自再质押的 ETH/EIGEN 与罚没；LlamaRisk 等第三方
评估指出 disperser 角色的中心化关注点。对本项目的错配在于：我们 4–7
validator 自带签名/聚合基建，而 EigenDA 的安全完全不经过我方 validator；
小对象场景下引入其客户端组件栈与 token 敞口收益低。

**Avail**（即历史上 Polygon 生态孵化的 "Polygon Avail"，2024-07 主网
上线后为独立 Avail DA 项目，统一按 Avail 对待）：独立 DA 链，KZG 有效性
证明 + 轻客户端 DAS。与 Celestia 同类；生态成熟度、AVAIL 单价与延迟
均**未获得一手数据，需询价/实测**。不作为首选外部集成点的理由同
EigenDA（安全不经过我方 validator）加上一手数据缺失。

**自托管对象存储 + 见证签名（现状增强，主选）**：在运营方自有存储之上
加三件事：(a) 跨区域/跨 provider 双副本 + 内容寻址键（digest 即
blake2s/blake2b，已内建）；(b) validator 见证凭证——把 `da.rs` 的
DaCertificate 从"自证持有"升级为带挑战窗口的可验证持有（§5）；(c)
checkpoint digest 链周期锚定到 Starknet Vault（事件/存储，随 B7/vault
侧落地）。信任弱于外部 DA（独立第三方只提供锚定点的不可篡改性，不提供
全量数据第三方副本），但延迟最低、依赖最少、与现有 BLS 基建天然匹配、
迁移成本最低，且 L1 层数据量（MB/天）使锚定成本可忽略。

**Ethereum calldata / blobs（简述）**：Pectra 后 blob 目标 6/块（上限 9），
第三方研究口径中位 blob 费近零；但 blob 数据按规范约 18 天被节点修剪，
**只能作短期可用性窗口，不能作档案**；对本项目直接价值有限——更贴合的
形态是经由 Starknet Vault 合约做根锚定（本项目结算层已在 Starknet），
锚定事件 900–2,700 条/天 × 0.1–0.3 KB，成本量级估算为美元/天以下，
**未获得一手 gas 报价，需实测**。

---

## 4. 推荐方案与决策记录

### 4.1 推荐（分层 + 触发式备份）

```text
主选（v1.5 落地）：
  L1 逃生舱层 = 跨区域双副本对象存储（不同 provider）
              + validator 见证凭证（da.rs 演进：+object_type 域、+挑战应答）
              + checkpoint digest 链周期锚定 Starknet Vault 事件
  L2 归档层   = 自托管对象存储 + 内容寻址（archive_index 已有 digest 纪律）
  L3 冷备层   = 合规快照（复用 rake_audit/checkpoint 导出）

备选（触发式启用，见 4.3）：
  Celestia namespace 作为 L1 层附加 sink（第三方永久性与独立性来源）
```

**为什么不是直接上 Celestia/EigenDA**：(1) L1 层数据 MB/天，外部 DA 买
的"第三方全量副本"在小对象场景边际收益极小，锚定根即可获得不可篡改性；
(2) 我方已有 2f+1 BLS 聚合基建（checkpoint QC 与 da.rs 同源），validator
见证是与网络形态最匹配的安全来源；(3) 外部 DA 引入新节点角色、token
敞口与询价/实测成本，收益要等 validator 独立性或数据量增长才兑现。

**为什么现状（纯运营方自有存储）不够**：逃生舱的信任目标要求"sequencer
与运营方存储同时不可用时仍可恢复"。现状增强方案的三件事分别补：
双副本补单 provider 风险；见证凭证 + 挑战把"validator 自律"变成可验证
承诺；外部锚定给 checkpoint 链一个独立于我方全部基础设施的顺序与
不可篡改性记录（这是第三方审计叙事的最低要求）。

### 4.2 与现有 checkpoint / da.rs 原型的对接面草案

| # | 变更点 | 现状 | 需要变成 | 兼容性 |
|---|---|---|---|---|
| 1 | DA 签名域 v2（`da.rs`） | `DA_SIG_DOMAIN=0x44`，签名对象 `blake2b(0x44‖epoch‖height‖digest)`；digest 语义 = tx_hash 或 batch root，文档含糊 | 加 `object_type` 枚举（Checkpoint / BatchRootTable / WithdrawalRoot / FrameRange / Aggregate）入签名对象，域字节换 v2（或加版本字节）；消除跨对象类型重放 | 不兼容，版本化升级 + golden vector |
| 2 | `DaRequest`/`DaReceipt` 字段 | 只有 (digest, epoch, height, requester) | `object_type` 随签名对象入域；`DaCertificate` 的聚合/验证逻辑**不动**（复用 checkpoint QC BLS 函数，仅域不同） | 增量 |
| 3 | 回执语义缺口 | 模块头自认"诚实性由签名者自律承担；没有挑战游戏" | 加挑战窗口：receipt 后 N 块内可被随机偏移取数挑战；失败 → 不入 certificate + 记入 bond 记账（`bond.rs` v1"只记录不罚没"纪律一致） | 新增，不改既有类型 |
| 4 | 存储面 | `da.rs` 只管签名，数据搬运无归属 | 新增 sink trait：`DaSink { put(obj)->digest; get(digest)->obj; anchor(digest, meta); list_since(cursor) }`；实现 ObjectStoreSink（双 provider）、StarknetAnchorSink；CelestiaSink 备选后挂 | 新增 trait，零侵入 |
| 5 | checkpoint 格式（`poker-appchain/src/checkpoint.rs`） | v1：`batch_roots` 全量表**无界增长**；**无 withdrawal_root**；无链式引用 | v2：+ `withdrawal_root`（plan §5.4 提款流程硬要求）、+ `prev_checkpoint_digest` 链、batch_roots 改增量窗口（有界）；域标签 `zchain.appchain.checkpoint.v2.payload` | 版本号升级，v1 校验路径保留 |
| 6 | watcher / 恢复 | watcher 已做 checkpoint 对拍；恢复走 WAL replay（`replay_restoring_proven`） | watcher 加 `--da-verify`（凭证对拍 + 抽样取数）；恢复工具加 restore-from-DA 模式（checkpoint + 增量数据 → 重建 sequencer） | 增量 |
| 7 | 验收 | M8-ACC-8 只测"凭证在 sequencer 停机后可验证" | 扩展负例：**凭证成立但数据不可取**（挑战失败）必须被检出；恢复演练从 DA 副本完成 RTO 记录 | 验收项扩展 |

### 4.3 触发重评估的条件

1. **validator 独立性不达标**：v1.5 招募后 validator 与运营方存在关联
   （治理审计口径），见证凭证独立性论证失效 → 启用 Celestia 作为
   L1 层强 sink。
2. **外部审计/合规要求第三方数据托管**：审计方要求 checkpoint 链有
   独立第三方副本 → Celestia（优先）或询价 EigenDA/Avail。
3. **数据量跨档**：激进口径（>100 万手/天）持续，或 L2 归档年增 >1 TB
   使自托管成本/可靠性失衡 → 重新评估全量数据的 DA 归属。
4. **v2 Starknet Vault verifier 上线**：withdrawal root 需 permissionless
   验证时，锚定格式若不满足 Vault 合约消费需求 → 重新设计锚定载荷。
5. **Celestia 自身风险**：TIA 价格/网络治理/保留期参数异动（其 2026 年
   价格波动已被第三方行情记录）→ 备选内部重排（Avail/EigenDA 询价）。
6. **挑战应答失败率**：validator 挑战失败率超阈值（建议 >1%/周）说明
   "副本持有"承诺不可靠 → 提前引入外部 sink，不等条件 1。

---

## 5. 落地工作量估计（T-shirt 档位）

| 项 | 档位 | 依赖 | 备注 |
|---|---|---|---|
| da.rs 域 v2 + object_type 枚举 + golden vectors | **S** | 无 | 域分隔测试已有同类（da vs QC 域） |
| checkpoint 格式 v2（withdrawal_root / prev_digest / 增量 batch_roots） | **M** | §5.4 提款流程对齐 | ABI 增量纪律 + 冻结向量；withdrawal_root 的树构造需与 vault 侧定一次接口 |
| 双 provider 对象存储 sink + 内容寻址 + 取回工具 | **M** | 无新依赖 | 复用 archive_index 的 digest 纪律；含季度取回演练 |
| Starknet Vault 锚定（事件 + 链下索引对拍） | **M** | vault/桥侧（B7 后续） | 载荷小；gas 报价需实测 |
| 挑战-应答 + M8-ACC-8 负例扩展 | **M** | bond 记账框架（已有 v1） | 先记录不罚没，与 v1.5 slash 路线一致 |
| watcher `--da-verify` + restore-from-DA 演练 | **M** | 上述 sink | RTO 数字进 runbook |
| **主选合计** | **M–L**（约 2–3 人周量级，工程估算） | | |
| CelestiaSink（备选触发后） | **L** | 轻节点运维 + TIA 资金流 | 含 namespace 规划、取回监控、保留期复核 |

---

## 6. 风险清单

| # | 风险 | 影响 | 缓解 |
|---|---|---|---|
| R1 | 见证凭证"自证持有"缺口：certificate 成立 ≠ 数据可取（da.rs 模块头自认） | 逃生舱在演练之外的真实故障中失效 | 挑战-应答（§4.2 #3）+ M8-ACC-8 负例扩展 + 定期取回演练 |
| R2 | checkpoint v1 `batch_roots` 无界增长，DA 对象随时间膨胀 | 锚定/存储成本与验证负担线性涨 | v2 增量窗口 + prev_digest 链 |
| R3 | 4–7 validator 与运营方关联（招募不足的现实可能） | 见证独立性论证失效，多副本退化为运营方单点 | 重评估条件 1 触发 Celestia；validator 独立性列治理门槛 |
| R4 | Starknet 锚定依赖 Starknet 自身活性/排序器 | 锚定暂停（不损已锚数据） | 锚定是增量凭证非唯一事实源；对象存储双副本独立可用 |
| R5 | 对象存储 provider 风险（账号/封禁/锁定） | 副本瞬时不可用 | 双 provider + 出口演练（恢复工具全量下载到本地） |
| R6 | 外部 DA token 敞口与费率波动（TIA 2026 价格波动有第三方记录；EigenDA 无公开单价） | 成本不可预算 | 备选触发制 + 询价后才立项 |
| R7 | EigenDA disperser 中心化（官方架构文档明示该角色；第三方评估提示关注点） | 若选它则引入新的信任上游 | 当前不选；若重评估，要求 disperser 故障演练数据 |
| R8 | Ethereum blob 修剪（~18 天）被误当作档案 | 数据静默丢失 | 本报告已排除该用法；仅 Starknet 事件锚定入主选 |
| R9 | 成本/延迟数字多为第三方聚合，无一手实测 | 选型数字漂移 | 全部标注查询日期；立项前实测/询价闭环（Celestia 小额 PFB 实测为 S 档） |
| R10 | 命名撞车（`request_da`/`da_window_blocks`）导致文档与实现混淆 | 沟通成本/误实现 | §1.2 语义表随本报告成为引用基准 |

---

## 7. 引用来源（查询日期均为 2026-09-12）

**仓库证据（一手）**

- `poker_l1/src/consensus/da.rs`：DaRequest/DaReceipt/DaCertificate、0x44 域、模块头边界自述
- `poker_l1/src/consensus/checkpoint.rs`：BLS QC 聚合、`DEFAULT_CHECKPOINT_INTERVAL_BLOCKS = 32`
- `poker-appchain/src/checkpoint.rs`：checkpoint v1 JSON 格式、payload_digest、无 withdrawal_root
- `poker-appchain/src/pipeline.rs`（`batch_size: 64`）、`poker-appchain/src/soft_confirm.rs`（帧结构）
- `docs/plan-appchain-v1.md` §5.1/§5.3/§5.4/§5.5/§5.6（v1.5 checkpoint、逃生舱、提款流程、出块节奏、M8-ACC-8）
- `docs/plan-appchain-perf.md`（证明归档 1,187,652 B/单手批次、M4-ACC-1/2 实测）
- `docs/plan-appchain-v1.md` §实现状态 2026-09-05（64 桌压测：3200 结算/16064 操作）
- `poker-appchain/src/archive_index.rs`（L2 内容寻址纪律）；`docs/runbook.md`（checkpoint 尚未上 BFT，v1.5）

**官方文档**

- EigenDA Overview（官方）：完整 dispersal 平均 5s / p99 <10s、吞吐宣称 100 MB/s、disperser/validator/检索角色、KZG + Reed–Solomon、再质押安全与定价模式（ETH/EIGEN/原生代币、reserved bandwidth）— https://docs.eigencloud.xyz/eigenda/core-concepts/overview
- Celestia DA layer（官方）：DAS 轻客户端、NMT、PoS 链承载 — https://docs.celestia.org/learn/how-celestia-works/data-availability-layer
- Celestia Paying for Blobspace（官方，费机制）— https://github.com/celestiaorg/docs/blob/main/app/learn/TIA/paying-for-blobspace/page.mdx
- Avail DA（官方）：KZG 有效性证明、轻客户端 DAS、App ID — https://docs.availproject.org/docs/da/concepts/what-is-avail-da ；主网上线公告（2024-07）— https://blog.availproject.org/avail-da-mainnet-is-live/
- EIP-4844（官方规范）：blob 结构与约 4096 epochs（~18 天）修剪窗口 — https://eips.ethereum.org/EIPS/eip-4844

**第三方（明确标注非一手，用于量级与行情）**

- Celestia blob 成本 ~$0.07–0.81/MB — https://www.spark.money/tools/bitcoin-vs-celestia
- TIA 行情（2026-06 ~$0.38、低点 $0.28，波动大）— https://revolut.com/en-BG/crypto/price/tia/ 、https://www.onebullex.com/explore/what-is-celestia-tia-beginner-guide
- Ethereum blobs Pectra 后中位费近零、目标 6/上限 9 — https://www.galaxy.com/insights/research/ethereum-blob-market-post-pectra 、https://www.binance.com/en/academy/articles/what-is-eip-4844-in-ethereum-and-how-can-it-benefit-users
- EigenDA 第三方风险评估（disperser 中心化关注点）— https://llamarisk.com/research/avs-risk-assessment-eigenda ；L2BEAT DA 档案 — https://l2beat.com/data-availability/projects/eigenda/eigenda 、https://l2beat.com/data-availability/projects/avail/vector

**未获得一手数据（需询价/实测）**：EigenDA 单价与实际 dispersal 延迟
（官方文档 5s/10s 与 V2 博客宣称口径不一致）；Avail 单价/延迟；
Starknet 锚定事件的实际 gas；Celestia 数据保留期当前参数；
帧/批次证明的实际字节数基准（仓库内）。

---

## 8. 决策记录

```text
决策：DA 采用分层方案——L1 逃生舱层（checkpoint QC 链 + withdrawal_root +
      batch root 增量表）落跨区域双 provider 对象存储 + validator 见证凭证
      （da.rs 演进：签名域加 object_type、回执加挑战-应答），并周期锚定
      checkpoint digest 链到 Starknet Vault 事件；L2 全量软确认链/证明归档
      走自托管对象存储 + 内容寻档（不进外部 DA）；Celestia 作为触发式备选
      sink。EigenDA / Avail 本期不引入。

理由：L1 层数据小而低频（两个业务口径下均为 MB/天量级，方法见 §2.1），
      逃生舱只需 checkpoint + 根的强可得性，全量数据由 4–7 validator
      副本 + 归档层承接；现有 da.rs/checkpoint QC 已提供 2f+1 BLS 见证
      基建，匹配 v1.5 网络形态；外部 DA 的增量价值（第三方副本与永久性）
      对小对象场景可由"外部锚定"以更低依赖获得，全量上 DA 成本运维翻
      量级而无对应信任收益。现状（纯运营方自有存储）不满足"sequencer 与
      运营方存储同时不可用仍可恢复"的 v1.5 承诺，必须按本方案增强。

备选：Celestia（触发条件：validator 独立性不达标 / 合规要求第三方托管 /
      数据量跨档 / TIA 侧风险重排）；询价队列 EigenDA、Avail。
      Ethereum blobs 仅作背景评估，因 ~18 天修剪窗口排除用作档案。

重评估条件：§4.3 六条（validator 关联审计不达标、合规要求、>100 万手/天
      持续量、v2 Vault verifier 载荷不匹配、Celestia 侧异动、挑战失败率
      >1%/周）。

日期：2026-09-13
```
