# 桥回归门 + 共识事件驱动化 POC + P0-4 修复 + watcher 入金筛查接线（2026-09-24）

本日工作源于 2026-09-24 代码审查的三项建议（①桥回归门 ②共识事件驱动化
③P0-4 修复后推桥白名单与 watcher 筛查接线），实施过程中故障注入门额外
暴露并修复了两个**存量**活性缺陷。全部改动在本机 debug 构建 + 4 节点
本地演练验证。

## 一、桥回归门（建议①）

### 新增脚本

| 脚本 | 内容 | 首跑结果 |
|---|---|---|
| `scripts/scenario_bridge_anchor.sh` | 正常锚定路径门：rake_audit selftest WAL（6 笔 Settle）→ explorer_gateway --write-index → 4 节点起链（桥账户 genesis 预充值）→ `poker_air_bridge.py bridge --stream-only --target 6` → 断言：anchored=6/6、nonce 恰为 {0..5}（连续唯一，同 nonce 双记=幽灵）、4 节点链上账户 nonce 全部=6 | PASS |
| `scripts/scenario_bridge_ghost_nonce.sh` | 故障注入门（复刻 4b3da1a 触发条件）：Phase A 锚定 2 笔 → kill 全部 4 节点 → 断言桥两条 fail-closed 消息（"chain nonce 不可读，本轮跳过批量" + "chain nonce 持续不可读，退出本轮 stream"）且 anchored 无新增 → 同数据目录重启（120s 窗口，实测首笔恢复 commit ~20s）→ 续跑锚完 8 笔 → 终检无幽灵（nonce 0..7 连续唯一 + 全部已执行 + 4 节点链上 nonce=8 一致） | PASS（五相全过；链侧修复见 §三） |
| `scripts/probe_tx_latency.sh` | tx→链上确认（nonce 推进）延迟探针：串行逐笔 p50/p95/max + 突发吞吐，补"commit 延迟无直接回归测试"的缺口 | 见 §二数据 |

两个桥门已收进 `scripts/e2e_acceptance.sh`（`drill:bridge-anchor` /
`drill:bridge-ghost-nonce`）。脚本端口默认 18549/19010（避开 deploy_4node
的 18545/19000 与常驻部署；RPC_BASE 保持 (port-5)%4==0 以兼容桥的 fan
端口推导），并带 PID 退出收割（节点优雅关闭实测需 ~2.5 分钟，不等会
bind 冲突假阴性）。

> 脚本层教训（macOS bash 3.2）：`set -o pipefail` 下 `tail | grep -q`
> 是陷阱——grep -q 命中即退出使 tail 收 SIGPIPE（141），整条管道恰在
> **匹配成功时**被判失败。轮询断言必须用 `grep -a … > /dev/null`。

### Rust 侧测试

- `fact-bridge/tests/proof_plan.rs`（新增，6 例）：证明验证失败拒绝构造
  计划（文件缺失/非 JSON/结构不符）、真实证明计划形状（钉扎1+分块N+
  finalize1 + nonce 连续）、**分块重组逐字节还原 wire**（边界完整性）、
  损坏 wire 节点侧验证拒绝、Submitter 密钥解析、签名恢复一致性。
  6/6 通过（<1s，真实 12.2MB settlement 证明夹具）。
- `poker_l1/tests/bridge_executor_integration.rs`（新增，5 例）：经
  `Node::execute_block_on_state`（put_block 同路径）覆盖 executor 铸币
  特判分支——正常铸币（对象类型/owner/金额/来源 + nonce 持久化）、同
  deposit 换账户 nonce 重放被桥层拒绝、**同块并发同 nonce 双花恰好一笔
  成功**、无桥 store fail-closed、P0-4 后置失败不烧 nonce（见 §四）。
  5/5 通过。

## 二、共识事件驱动化 POC（建议②，最高优先级降延迟项）

### 实现（`src/main.rs` + `poker_l1/src/node/mod.rs`）

纯本地调度/产速策略，共识语义（wave 评估、投票、装配、验证）零改动：

1. **threshold clock**：`DagWake` 通道（`accept_p2p_vertex` 在 live-Dag
   插入后记录进展 + `Node::notify_validator_wake()` 唤醒产块循环）。某轮
   首次凑齐 2n/3+1 distinct author 时豁免 `EMPTY_VERTEX_PACE`（1s）提前
   产下一轮；`QUORUM_WAKE_FLOOR=200ms` 下限配速防 round 风暴（对齐
   Mysticeti leader_timeout 职能，诚实多数自身产速即天然上限）。
2. **收块即评估 wave**：有新 vertex 落地但不满足产速条件时，不再整周期
   `continue`（原行为会把 commit 发现一并吞掉最多 1 个周期），改为
   `skip_production` 只跑 commit 扫描。

### 验证

- `cargo test -p zchain` 17/17、`cargo test -p poker_l1 --lib` 1923/1923
  （含 bullshark 全部 wave 单测）。
- 4 节点 200ms 间隔本地演练（即上述两个桥门全程使用新共识二进制）：
  出块/锚定/kill-全灭-重启续跑均正常。
- 延迟 A/B（`scripts/probe_tx_latency.sh`，4 节点 / 12-20 笔串行+管道突发 / 本机）：

  | 配置 | 二进制 | p50 | p95 | max | mean | 突发管道 |
  |---|---|---|---|---|---|---|
  | 200ms 间隔 | 基线（HEAD 4b3da1a） | 1743ms | 5148ms | 5148ms | 1953ms | 3170ms/tx |
  | 200ms 间隔 | 事件驱动 POC | 2053ms | 5082ms | 5082ms | 2187ms | 3126ms/tx |
  | 1000ms 间隔（默认） | 基线 | 2779ms | **8948ms** | 8948ms | 3788ms | 5917ms/tx |
  | 1000ms 间隔（默认） | 事件驱动 POC | 2676ms | **2803ms** | 2803ms | 2652ms | 6281ms/tx |

  **判读**：
  - 默认 1000ms 间隔下 POC 把 **p95/max 砍 69%**（8.9s→2.8s）、mean 降 30%——
    收块即评估消除了「commit 发现在配速跳过的整周期里睡觉」的长尾。
  - p50 两版持平（~2.7s）：中位延迟受 commit 投票/装配路径
    （VOTE_MICRO_WAIT 800ms + leader-only 装配 + 块广播）支配，正是审查
    清单的下一项（本地装配 + 块字节规范化，共识语义级变更，POC 范围外）。
  - 200ms 间隔无差异：计时器本就以 200ms 唤醒，quorum 唤醒无增量；
    实测该 regime 下轮次推进 ~530ms/轮（受 PROD_LEADER_WAIT 等待支配），
    出块速率与轮次速率持平（1.9/s vs 1.9/s，无 commit 积压）。
  - 探针 burst 相位采用「在途窗口 + 2s 重提」（对齐生产桥语义：节点为
    严格 nonce 准入，一次性批量提交会被 nonce-too-high 拒收）。

## 三、存量缺陷两个（故障注入门暴露，已修）

### 缺陷 A：全灭重启后全网停产（equivocation 风暴）

- **机理**：`validate_vertex` 的 equivocation 检查查**持久 vertex store**
  （跨重启）。重启节点虽把 `round` 变量恢复到自家最高轮+1，但
  `last_vertex=None` 使 parent 选择走「引导」分支把 round 重置回 1；
  从 round 1/2 重新产出的 vertex 与 store 里旧 incarnation 的同
  (epoch, round) vertex 内容不同 → 永久判 equivocation → 该作者永不推进。
  4 节点全灭重启 = 全网停产。实测 4 节点全部卡 round 2 equivocation
  风暴（~410ms/次重试）。
- **为何从未暴露**：`scenario_restart_catchup.sh` 只重启 3 节点中的 2 个，
  且断言基于 catch-up 导入高度，不要求恢复产块。
- **修复**：`run_validator_loop` 启动时从 vertex store 恢复当前 epoch 的
  自家最高轮 vertex 为 `last_vertex`（`src/main.rs`），生产行为与停机前
  连续。

### 缺陷 B：补洞响应只读易失 live DAG，重启后永远回空

- **机理**：`collect_vertices_by_round` 只读 live DAG（重启即空），持久
  vertex store 里的历史 vertex 无法服务 `RequestVerticesByRange` →
  重启后 parent 补洞 accepted=0 → parent quorum 无法重组。
- **修复**：响应合并持久 store 同轮 vertex（按 hash 去重，
  `src/main.rs`），补洞跨重启可用。

修复后 `scenario_bridge_ghost_nonce.sh` 全 5 相 PASS（fail-closed 消息、
anchored 无幽灵、重启恢复出块 ~20s、续跑锚完、终检 nonce 0..7 连续且 4
节点链上 nonce=8 一致）。

**遗留（未修，需立项）**：BlockStore 重启后 tip 归零——本次演练中重启
节点从 height 1 重建链（历史波重放式再提交，账户层因 AccountStore 持久
而无幽灵），块持久化/重载语义需与 vertex store 对齐；另有
`request_blocks_by_range` 的 gossip 混流读取在无人持块时 30s 超时后
逐 peer 重试的恢复放大（全灭场景每 peer 白等 30s）。

## 四、P0-4 修复（建议③前置）：桥 nonce 消费延迟到合并点原子生效

审计 P0-4（失败交易非全有或全无）的桥子项：原 executor 桥分支在执行期
立即消费 nonce（内存 registry）+ 立即持久化，tx 后续阶段失败则留下
「nonce 已烧、无铸币」半状态（该 deposit 永久不可桥入）。

- `bridge_verify_check`（只验证不消费）+ `ObjectBackend::stage_bridge_deposit`
  （捕获型后端暂存进写日志；直接后端默认 false 保持串行立即语义）+
  `ObjectWriteLog::apply_to_with_bridge`（合并点：nonce 全量预检 → 对象写
  回放 → 统一消费+持久化；失败 tx 整体丢弃）。
- 回归测试 `later_stage_failure_leaves_bridge_nonce_unconsumed`：合法桥
  载荷 + 保留类型 output（后置必败）→ 断言回执失败、无对象、**nonce 未
  消费**、同 deposit 干净重提成功。

审计中 transfer/precompile/outputs 的通用事务层（每笔 tx 临时视图 + 单
原子 batch）仍为长期项，本次未做。

## 五、桥资产白名单（建议③）

- `BridgeValidatorSlot.allowed_assets: Option<BTreeSet<Hash>>` +
  `new_with_asset_allowlist`；`bridge_verify` 步骤 4a：slot 声明白名单时
  未注册资产 fail-closed（`BridgeAssetNotAllowed`）。`None` = 兼容期不
  限制，既有行为与测试零改动。
- 单测 `test_slot_asset_allowlist_enforced`（白名单资产放行 / 非白名单
  拒绝 / 未配置放行）；bridge 模块 25/25 通过。
- 这是 B-TE-1（USDT/USDC 外部合约白名单治理流程）的第一段执行点；
  治理签名 + 版本化注入流程待后续设计。

## 六、测试汇总

| 套件 | 结果 |
|---|---|
| `cargo test -p zchain` | 17/17 |
| `cargo test -p poker_l1 --lib` | 1923/1923 |
| `cargo test -p poker_l1 --test bridge_executor_integration` | 5/5 |
| `cargo test -p fact-bridge` | 6/6 |
| `cargo test -p poker-appchain --lib` | 180/180（含 watcher 筛查 4 例 + sequencer 合规负例 4 例） |
| `scenario_bridge_anchor.sh` | PASS |
| `scenario_bridge_ghost_nonce.sh` | PASS（五相全过；含链侧修复 A/B 与脚本 pipefail 修复） |

## 七、watcher 入金来源筛查接线（建议③收尾；TEC-v1 §5 AML 落点）

### 实现（`poker-appchain/src/watcher.rs`）

REAL 域入金的来源筛查（制裁/混合器/自排除）按 TEC-v1 设计"不在链上"，
由 watcher 在确认外部支付时前置执行：

- **可插拔数据源** `DepositScreeningSource` trait：`Ok(true)`=命中、
  `Ok(false)`=查询成功未命中、`Err`=数据源不可用——三者必须可区分
  （fail-closed 的契约基础）。内置 `StaticDenylist`（RG 自排除/小型
  制裁集，地址键 blake2s32 域分离）与 `UnavailableSource`（降级演练）；
  Chainalysis/TRM 类商业 API 走适配器实现同一 trait。
- **fail-closed 筛查** `screen_deposit`：未配置数据源 / 查询失败 / 命中
  → `Deny(NoSourceConfigured | SourceUnavailable | SanctionHit)`。
- **入金确认** `confirm_deposit`：筛查放行才产生 deposit_id
  （= blake2s32(DOMAIN ‖ chain ‖ address ‖ tx_hash ‖ owner)，对同一
  (来源, owner) 确定性幂等，可直接作 `Operation::Deposit`/`DepositV2`
  的幂等键）；命中/不可用/未配置 → **不确认、不产生 deposit_id**，链上
  无该笔入金任何痕迹。
- 与 sequencer 侧 `compliance`（市场/token/限额/制动）互补不重叠：前者
  管"这笔钱从哪来"，后者管"谁能在本市场入多少"。

单测 4 例（watcher 模块共 8/8）：干净来源确定性幂等 id、命中不产生 id
（同地址不同 tx 全拒）、数据源不可用 fail-closed、未配置 fail-closed。

### sequencer compliance_gate 端到端负例（C-M2 出口判据）

`compliance.rs` 的门函数矩阵此前已覆盖判定逻辑，但 apply 路径零覆盖。
新增 4 例（sequencer 模块）补齐完整闭环——拒绝 → `AdmissionRejected` +
审计事件（decision=Err，含 policy 版本/摘要）+ 账本零变更（deposit_ids
空、无 note 铸出）：

- 封禁市场（real_enabled=false）负例 + 审计断言；
- 负例矩阵：fiat_only 拒 NATIVE、超单笔限额、KYC 制动位、RG 自排除
  （owner_key_v1 命中）、市场未配置（部署错配 fail-closed）；
- 正例对照：限额边界值（==max）放行 → accepted 审计 + deposit_id 入账；
- 无合规配置直通（现网部署前形态对照）。

`cargo test -p poker-appchain --lib` 180/180。

### 遗留（接线后续）

- 生产 watcher 进程把 `confirm_deposit` 接到真实外部链支付确认流
  （当前为库接口 + 静态名单；商业筛查 API 适配器待选型）；
- 筛查拒绝的运营侧日志/指标通道（`ScreeningDenyReason` 已带语义，落
  地为 metrics 留给部署层）；
- B-TE-1 治理签名 + 版本化注入流程（与 §五 的 slot 白名单衔接）。

## 八、环境备注

- 本机并存常驻 4 节点链（/tmp/zchain-local4，18545/19000，已运行多日）
  与另一会话的 aeneas/charon 形式化验证作业（共用 target/ 目录与 CPU）。
  本次构建/演练使用独立 CARGO_TARGET_DIR=/tmp/zchain-target-isolated 与
  18549+/19010+ 端口段避开干扰；延迟 A/B 两轮均在同等条件下串行执行。
