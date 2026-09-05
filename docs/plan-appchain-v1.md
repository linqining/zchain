# 自研扑克 L1（appchain）v1 技术方案

> 状态：2026-09-05 立项草案。功能模块 / 实现内容清单 / 验收测试三段式。
> 决策依据与推导过程见会话结论（Hyperliquid 模式、费率即数据、可证明 rake、
> 流式证明、note 账本）。基线锚点 `plan_d_perf.md`、`TEXAS_TAGGED_AIR.md` 及
> §1 复用映射引用的 AIR/证明栈文件位于全量仓库 `/Users/mac/projects/poker_texas_air`
> （本仓库内的同名 crate 是精简集成版）；实现 crate `poker-appchain/` 落在
> **本仓库**根下，2026-09-05 迁入。

## ⭐ 实现状态（2026-09-05 v1.1：审计修复 + poker_texas_air 接入缝）

**v1.1 增量**（poker_vm 路线搁置，证明路线定为 poker_texas_air 手写约束
AIR）：① 审计修复 S1/C1/C3（见 BLOCKERS"已解决"）；② 新 crate
`poker-appchain-texasair`——`TexasAirEngine` 适配器：验证 poker_texas_air
手写约束 AIR 批次归档（`verify_tagged_texas_proof`）+ 终态承诺绑定 +
attestation 签名，5 项负例回归全过；③ `SettlementRecord` v1.1 增加
`hand_proof` 可选绑定；④ zchain 根 Cargo.toml 悬空依赖修复（P0）。
测试：poker-appchain 61/61 + texasair 适配器 5/5（release）。

## 实现状态（2026-09-05 首轮落地）

实现载体：新 crate `poker-appchain/`（未触碰主 lib），零新增外部依赖。
测试：**61 通过 / 0 失败**（release：48 lib + 8 attacks + 3 settlement_flow
+ 2 proptest）。压测：`cargo run -p poker-appchain --release --bin loadtest`
64 桌 × 50 手 → 3200 结算 / 16064 操作全通过，买入软确认 p50 2.1ms /
p99 3.5ms（门槛 100ms），0 告警。

| 模块 | 状态 | 落点 |
|---|---|---|
| M0 | **部分**：ABI 规范冻结（`poker-appchain/docs/ABI.md`）；逐街 stwo 实验未做（blockers B3） | docs + loadtest 机制基准 |
| M1 | **完成**（note/树/nullifier/资产类隔离 + proptest） | `note.rs` `merkle.rs` `nullifier_set.rs` |
| M2 | **完成（host 关系层）**：校验 + 负例矩阵全过；AIR 约束 = B1 | `settlement.rs` |
| M3 | **完成**（软确认链/查重/准入/限流/WAL 重放）；texas 接线 = B6 | `sequencer.rs` `soft_confirm.rs` `wal.rs` |
| M4 | **完成（机制）**：管道/批次/降级/背压；stwo 真引擎 = B1 | `pipeline.rs` |
| M5 | **完成**（策略注册表冻结/分账/rake 记账）；独立审计导出工具部分 | `fee.rs` |
| M6 | **最小**（client_view 余额验证聚合）；wasm 集成后续 | `client_view.rs` |
| M7 | **完成（托管账+对账+幂等）**；链上侧接线 = B7 | `vault.rs` |
| M8 | **完成（6 类攻击回归 + watcher 分叉检测）**；fuzz targets = B4 | `tests/attacks.rs` `watcher.rs` |
| M9 | **完成（metrics/告警/loadtest）**；runbook 文档未写 | `metrics.rs` `bin/loadtest.rs` |

阻塞项与后续工作全清单：**`poker-appchain/docs/BLOCKERS.md`**（B1 stwo
引擎接入、B2 pot 状态链绑定、B3 逐街实验、B4 fuzz、B5 账本二级索引、
B6 texas 接线、B7 出入金链上侧）。


## 0. 定位与范围

**模式**：Hyperliquid 式专用链——链内无 gas，收入来自 rake；费率是状态机里的
数据（策略注册表），不是协议参数。链的防滥用由封闭操作集 + 桌准入 + 限流给出，
不依赖定价。

**v1 收费策略（仅两种）**：
- `ZERO`：零费（休闲/测试桌）
- `FIXED_RAKE`：固定比例 rake，结算时抽取，按固定分账比例输出

**信任模型 v1**：托管筹码（赌场模式）+ 全量可证明公平 + **可证明 rake**。
外部锚定、退出协议、多运营方共识全部推迟到 v2/v3（见里程碑）。

**v1 非目标（明确不做）**：
- 不锚定外部链（无 validium 退出协议；出金走托管对账）
- 不做多运营方 / BFT 共识（单 sequencer）
- 不做通用 VM / 第三方游戏接入（操作集封闭为扑克）
- 不做 B2B API 计费 / SLA 档位（接口预留，见 M4/M5）
- 不做链上隐私池（note 承诺模型天然私密，替代 anonymizer 的内部职能）

## 1. 总体架构

```
┌─ 扑克 L1（本方案）──────────────────────────────────────┐
│                                                          │
│  M3 Sequencer ── 软确认链(签名/哈希链) ── M8 检查点/watcher │
│      │  nullifier 查重 / 桌准入 / 限流                     │
│      ▼                                                   │
│  M1 Note 账本 ── 承诺树 + nullifier集 + 资产类隔离           │
│      ▲                                                   │
│  M2 AIR 扩展（结算选择子 + 可证明费率关系）                   │
│      ▲                                                   │
│  M4 证明管道 ── 逐街流式(v0 校准) / 按桌并行 / 递归聚合        │
│                                                          │
│  M5 费率模块（策略注册表 ZERO|FIXED_RAKE + 分账 + 审计）      │
│  M6 客户端（note 托管 / wasm 验证）                          │
│  M7 出入金（v1 托管对账；数据结构对齐 v2 储备证明）             │
│  M9 可观测                                                │
└──────────────────────────────────────────────────────────┘
外部：Starknet（v1 仅收款通道；v2 锚定层候选）
```

**现有资产复用映射**：

| 资产 | 在 v1 中的角色 |
|---|---|
| `src/texas_canonical_air.rs`（29 选择子、状态镜像链、nullifier） | 状态转移函数核心，M2 在其上扩展结算选择子 |
| `src/outer_aggregate.rs` | M4 批次递归聚合 |
| `poker-protocol-proofs`（sigma 套件） | P 层签名，每个消耗 note 的动作 |
| `client-wasm` | M6 浏览器端证明/软确认验证 |
| `proving-tool` / `hand-bench` | M0 基准改造 |
| `poker_protocol_lean` | v2 退出协议健全性形式化（v1 不阻塞） |
| `texas/` 游戏服务器 | 对局循环保留，结算出口改接 M3 |

---

## 2. 功能模块

### M0 决策基准（先行实验，阻塞 M4 架构定型）

**职责**：用数据决定两个关键架构选择。

**实现内容**：
- [ ] 逐街流式证明基准：4 段 street 部分证明 + 4 次递归聚合 vs 整手一次性证明，
      在 release / pinned nightly / 参考硬件上测延迟与 CPU 成本曲线（1/2/4/8 桌并发）
- [ ] GPU 路线探测（可选）：stwo GPU prover 可行性调研，仅出报告不实施
- [ ] 规范冻结：note ABI、FeePolicy ABI、软确认链帧格式、结算选择子 witness 形状
- [ ] 决策记录落档（沿用 `PERFORMANCE_FOLLOWUPS.md` #24 的处置格式）

**验收测试**：
- M0-ACC-1 基准报告入 `docs/plan-appchain-perf.md`，含逐街 vs 整手的
  延迟/成本对比表与最终选择及理由
- M0-ACC-2 三份 ABI 规范文档评审通过（note / FeePolicy / 软确认帧），字段有版本号

### M1 Note 账本核心

**职责**：筹码的唯一真身。owned note + nullifier，资产类物理隔离。

**实现内容**：
- [ ] note 结构：`asset_class(REAL|PLAY)`、面额、owner 公钥、nonce、可选 table_id
- [ ] 承诺树（Poseidon，复用 `poker-protocol-core` 后端）+ nullifier 集双状态
- [ ] 生成/消费 API：包含证明签发（客户端可自证持有）
- [ ] 资产类隔离不变量：REAL 与 PLAY 不可互转、不可混树（AIR 层强制，非仅业务层）
- [ ] 状态镜像与 canonical AIR 的 pre/post image 衔接（复用相邻状态镜像承诺链）
- [ ] 序列化走 `poker-protocol-abi` 的稳定字节 ABI 纪律

**验收测试**：
- M1-ACC-1 树操作属性测试（proptest）：任意插入/消费序列下包含证明正确、
  nullifier 全局唯一
- M1-ACC-2 资产类隔离负例：PLAY→REAL 互转 witness 构造后 **AIR 不可证明**（fail-closed），
  mutation 测试确认不是靠业务层断言挡的
- M1-ACC-3 ABI 稳定性：golden bytes 测试，跨版本解码兼容
- M1-ACC-4 双花单元：同一 note 两次消费，第二次 nullifier 冲突被拒（账本层 + AIR 层双挡）

### M2 AIR 扩展：结算选择子 + 可证明费率

**职责**：把"结算 = 消费 note → 产出 note + 抽取 rake"变成被证明的关系。

**实现内容**：
- [ ] `SettleNotes` 选择子族：N 个输入 seat note → 输出 notes + 抽取输出
- [ ] 守恒 + 费率关系：`Σ输入 = Σ输出 + 抽取额`；`抽取额 = rate × pot`，
      rate 由 `policy_commitment` 绑定进 transcript
- [ ] 分账关系：抽取输出按策略承诺的分账比例拆分（v1：treasury / operator 两地址）
- [ ] P 层签名覆盖：结算 witness 必须含全部参与者动作签名（复用 DAPV 每动作签名）
- [ ] hand_binding 防重放沿用现有编码，扩展 note 维度
- [ ] fail-closed 矩阵更新：未覆盖语义一律拒绝进 admission

**验收测试**：
- M2-ACC-1 正例矩阵：零费桌（抽取=0）与固定比例桌（抽取=rate×pot）均可证明，落基准
- M2-ACC-2 负例矩阵：篡改面额 / 少抽 / 多抽 / 分账比例不符 / 缺任一玩家签名 /
  换 policy_commitment——全部**不可证明**或 admission 拒绝
- M2-ACC-3 mutation tests 直接攻击 AIR（延续现有纪律）
- M2-ACC-4 证明可被 `client-wasm` 独立验证（不依赖 host 状态）

### M3 Sequencer 服务

**职责**：软确认、查重、准入、限流。构造性无冲突——不需要 Block-STM，
只需 nullifier 查重 + 桌级互斥。

**实现内容**：
- [ ] 软确认 API（复用 socket.io 通道）：验 P 层签名 → nullifier 查重 → 记账
- [ ] 软确认链：哈希链 + sequencer 签名，帧含（桌ID、批次、note 消费/产出、策略哈希）
- [ ] nullifier 查重 O(1) 内存索引 + O(log n) 持久验证
- [ ] 桌准入：只收 proven note；桌绑定 FeePolicy（注册表读取）
- [ ] 限流：建桌/加入/离桌频率限制；play 桌与 real 桌独立配额
- [ ] WAL + 重启恢复（软确认链可重放）
- [ ] 对局循环集成：`texas/` 结算出口改接 sequencer（保留 dev 模式）

**验收测试**：
- M3-ACC-1 延迟门槛：单笔软确认 p99 ≤ 100ms（参考硬件，release）
- M3-ACC-2 双花并发测试：同一 note 并发两笔结算，恰一笔成功
- M3-ACC-3 软确认链完整性：任意中断/重启后链无分叉、可重放
- M3-ACC-4 限流负例：超频建桌被拒且有告警事件
- M3-ACC-5 桌准入负例：pending note 上桌被拒（v1 证明即时后此规则应恒真，
  仍需测试防证明管道积压退化）

### M4 证明管道

**职责**：让"账和证明同时到"。节奏：M0 定型（目标为逐街流式，整手 GPU 为备选）。

**实现内容**：
- [ ] 街级证明任务流水线：street 结束触发部分证明，递归聚合衔接（若 M0 通过）
- [ ] 按桌并行 worker 池：任务队列背压、优先级（real 桌 > play 桌）
- [ ] 批次聚合：`outer_aggregate` 定期（如 5 min）聚合已验证证明，产出批次根
- [ ] 证明注册表 + host 验证器（复用现有 witness 兼容验证器）
- [ ] 降级档位：证明积压时自动降为整手批量慢档 + 告警（SLA 接口预留）
- [ ] 桌级证明产出指标（延迟直方图）

**验收测试**：
- M4-ACC-1 手结束 → 证明可验证就绪：目标 ≤ 3s p95（M0 校准后修订，写死进回归门槛）
- M4-ACC-2 吞吐线性：1/4/16/64 桌并发下单位手证明成本增长 ≤ 线性 + 15%
- M4-ACC-3 故障注入：kill prover worker 中途，证明不丢失、可重试、账本不回滚
- M4-ACC-4 积压降级：灌入超容量任务，降级路径触发、告警、恢复后积压清空
- M4-ACC-5 浏览器端验证延迟：单手证明 wasm 验证 ≤ 500ms（中位）

### M5 费率模块

**职责**：策略注册表 + 分账 + 第三方可验证的 rake 审计。

**实现内容**：
- [ ] FeePolicy 注册表：`ZERO` / `FIXED_RAKE{rate, split}`，桌创建时绑定并冻结
- [ ] 分账执行：抽取输出按 split 铸 treasury/operator note
- [ ] rake 审计导出：给定时间窗，输出（结算证明集 + 策略承诺 + 抽取明细），
  第三方可离线复验总抽取额
- [ ] 会计对账：链内累计抽取 vs 分账 note 余额恒等

**验收测试**：
- M5-ACC-1 零费桌全程抽取 = 0 且可证明（M2-ACC-1 联动）
- M5-ACC-2 rake 桌抽取精确按 rate，分账 note 归属与 split 一致
- M5-ACC-3 审计端到端：外部工具（独立仓库/独立代码路径）复验 1000 手随机混合
  桌的抽取总额，与链内会计零差异
- M5-ACC-4 策略不可变：桌绑定后尝试换策略 hash，结算证明失效

### M6 客户端与钱包

**职责**：note 自托管 + 验证即确认。

**实现内容**：
- [ ] note 钱包：加密存储、余额聚合视图、备份导出
- [ ] wasm 验证集成：结算证明本地验证 + 软确认链跟随
- [ ] REAL / PLAY 模式 UI 隔离与明确标识
- [ ] 密钥恢复流程（v1 托管模式：二次验证 + 客服路径；流程文档化）

**验收测试**：
- M6-ACC-1 浏览器验证吞吐：连续 10 手证明验证，全部通过且无内存泄漏（长会话）
- M6-ACC-2 离线恢复：备份导入后 note 完整、包含证明可重建
- M6-ACC-3 伪造拒绝：篡改证明/软确认帧注入，客户端拒绝并提示
- M6-ACC-4 恢复演练：模拟密钥丢失走恢复流程，note 不损失（测试环境脚本化）

### M7 出入金（v1 托管模式）

**职责**：真实资产边界。v1 托管对账，数据结构为 v2 储备证明预对齐。

**实现内容**：
- [ ] 充值通道：Starknet STRK 收款（复用现有收款合约/地址体系）→ 半自动对账 → 铸 REAL note
- [ ] 提现通道：note 销毁申请（P 层签名）→ 审核队列 → 链上打款 → 对账闭环
- [ ] 账实核对：`Σ已发 REAL note 面额` vs `储备 + 浮存` 每日对账，差异告警
- [ ] 提现费定价配置（覆盖外部 gas，v1 简单固定值）
- [ ] 报表结构对齐未来 STARK 储备证明的输入（note 集 + 储备证明可导出）

**验收测试**：
- M7-ACC-1 对账混沌测试：并发提现 + 部分失败 + 重复申请，最终账实零差异
- M7-ACC-2 提现 SLA：p95 ≤ 10 分钟（人工环节计时规则单列）
- M7-ACC-3 负例：未销毁 note 的提现申请被拒；重复提现申请幂等拒绝
- M7-ACC-4 日终对账报告自动生成，差异 > 阈值触发告警（注入测试）

### M8 安全与反滥用

**职责**：攻击面回归 + 等价性防御地基。

**实现内容**：
- [ ] 软确认链检查点导出接口（v1 落本地/对象存储；上链锚定推迟 v2，格式就绪）
- [ ] watcher 工具：独立进程验证（软确认链 vs 证明注册表 vs 批次根）三者一致性
- [ ] bond 内部记账框架（v1 记录、v2 真实罚没）
- [ ] 攻击回归套件（见下）纳入 CI（release 档）与 fuzz 目标
- [ ] 密钥管理：sequencer 签名密钥轮换流程

**验收测试**（每项 = 注入攻击 + 期望拒绝/告警）：
- M8-ACC-1 双花（软确认层并发、跨桌重放）
- M8-ACC-2 伪造结算（缺 P 层签名的 SettleNotes）
- M8-ACC-3 污染 note 上桌（未证明产出试图买入）
- M8-ACC-4 结算重放（hand_binding 重复）
- M8-ACC-5 费率篡改（换策略/篡改抽取额）
- M8-ACC-6 等价性分叉：向 watcher 同时喂两条冲突软确认链，检测时间 ≤ 2 个检查点间隔
- M8-ACC-7 fuzz：软确认 API、note ABI、结算 witness 的结构 fuzzing 无 panic（延续 `fuzz/`）

### M9 可观测与运维

**职责**：把性能与资金流变成可运维的数字。

**实现内容**：
- [ ] metrics：软确认延迟、证明就绪延迟、prover 队列深度/积压、每桌 TPH、
  rake 累计、note 供给、出入金队列
- [ ] 告警规则：证明积压、对账差异、软确认链异常、提现 SLA 逼近
- [ ] 压测脚本：N 桌机器人对局（复用 `dev_bot`）+ 容量报告
- [ ] runbook：sequencer 重启、prover 重启、积压处置、提现故障

**验收测试**：
- M9-ACC-1 64 桌机器人压测 1 小时：无积压、软确认 p99 ≤ 100ms、
  证明就绪 p95 ≤ 门槛值，容量报告落档
- M9-ACC-2 每条告警规则有注入验证（触发一次并记录）
- M9-ACC-3 runbook 演练：按手册完成 sequencer/prover 重启，RTO ≤ 文档承诺

---

## 3. 里程碑

| 阶段 | 内容 | 出口判据 |
|---|---|---|
| **Phase 0** | M0（基准 + 规范冻结） | M0-ACC 全过；流式 vs 整手定型 |
| **Phase 1（MVP）** | M1–M6、M8、M9 + M7 托管出入金 | 全部模块 ACC 过；64 桌压测达标；内测（休闲 + 真金小流量） |
| **Phase 2** | 储备证明 / Starknet 锚定（cairo verifier）/ 退出协议 + Lean 形式化 | 第三方可独立验证偿付能力；出金信任升级 |
| **Phase 3** | 多租户 API 计费 / SLA 档位 / 检查点上链锚定 + 真实 bond | B2B 租户接入 |

## 4. 风险与开放问题

1. **逐街流式证明可行性**未实证——M0 阻塞项，未通过则 v1 退整手证明 +
   放宽 M4-ACC-1 至 ≤ 30s（产品层用"证明后到"话术兜底）。
2. **单运营方活性**：sequencer/prover 停机 = 全场停摆。M9 告警 + runbook 是
   v1 唯一缓解；v2 多运营方。
3. **托管偿付风险**：v1 筹码是运营方负债。M7 账实对账是底线，储备证明（v2）
   才是外部可验证答案。
4. **Phase 2 依赖**：stwo 证明的 Cairo 验证器是外部关键路径，v1 期间保持跟踪
   starkware-libs/proving 进度。
5. **监管分市场**：REAL/PLAY 资产类隔离已给出版本答案；各市场开关策略
   属运营决策，另行立项。

---

## 附：与既有纪律的衔接

- 所有基准/回归测试：pinned nightly + `--release`，debug 证明测试一律排除
  （延续 `PERFORMANCE_FOLLOWUPS.md` 尾注）。
- AIR 改动延续 fail-closed 纪律与 mutation test 攻击矩阵。
- ABI 改动走 `poker-protocol-abi` 稳定字节 ABI 流程。
- 本文档为 v1 唯一范围基准（scope baseline），新需求先进"开放问题"再入范围。
