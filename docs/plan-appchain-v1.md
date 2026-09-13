# 自研扑克 L1（appchain）v1 技术方案

> 状态：2026-09-13 v1.4 增补稿（v1.3 产品化基础上：代币经济 + v1.5 共识 +
> 钱包全线 + 外部评审采纳，排期与状态见 `docs/roadmap-schedule.md`）。
> 功能模块 / 实现内容清单 / 验收测试 / 官网与文档发布四段式。
> 决策依据与推导过程见会话结论（Hyperliquid 模式、费率即数据、可证明 rake、
> 流式证明、note 账本）。基线锚点 `plan_d_perf.md`、`TEXAS_TAGGED_AIR.md` 及
> §1 复用映射引用的 AIR/证明栈文件位于全量仓库 `/Users/mac/projects/poker_texas_air`
> （本仓库内的同名 crate 是精简集成版）；实现 crate `poker-appchain/` 落在
> **本仓库**根下，2026-09-05 迁入。

## ⭐ 实现状态（2026-09-13 第六轮：M0–M9 缺口收口 + 常规测试立档）

对照 §2 全部 47 项 ACC 判据逐项审计（36 达成 / 10 部分达成 / 0 未达成），
本轮收口 6 项部分达成项：

- **M0-ACC-2**：ABI v1.3 实现-规范一致性核对**评审记录归档**
  （`poker-appchain/docs/ABI.md` 头注，判别值冻结/golden/additive 三类证据）；
- **M3-ACC-4**：限流告警规则 `rate_limit_storm` 进 `evaluate_alerts`
  （`HealthInputs.rate_limit_rejected_window` + 注入断言，M9-ACC-2 口径）；
- **M4-ACC-4**：积压降级**端到端注入**（门控引擎灌 12 任务过高水位 →
  degraded + `proof_backlog_degraded` 告警 → 放行 → 积压清空、降级解除，
  `pipeline.rs::backlog_degraded_end_to_end_injection_and_recovery`）；
- **M5-ACC-3**：1000 手批量审计**实测留痕**（selftest --hands 1000 →
  export → verify 零差异，5003 帧 / rake_total 39240；独立性边界维持
  runbook 如实声明）；
- **M7-ACC-1**：提现**并发混沌**专项（4 线程 12 请求、2 组跨线程碰撞
  request_id，exactly-once 10 成功 / 2 幂等拒，账本终态与并发序无关，
  `tests/te_m2.rs::withdrawal_concurrent_chaos_exactly_once_per_request`）；
- **M7-ACC-2**：SLA **达标演练**（20 笔受控 5 分钟打款 → p95 = 300s
  ≤ 600s 门槛、breached_count = 0，`withdrawal_sla_p95_within_ten_minute_gate`）。

余 4 项部分达成为外部依赖/决策门（M4-ACC-5 用户豁免口径、M6-ACC-5 真机
矩阵、M9-ACC-1 host-validate 引擎口径、M9-ACC-3 prover 演练未脚本化），
如实维持。

**复验修复**：① 重启回归——`apply_genesis_alloc` genesis 幂等对拍
version 硬编码 0，与运行期推进的持久化 validator-set version 必然失配
（全节点重启 fail）；修复为沿用持久化对象版本号（restart_catchup 演练
修复后 PASS skew=0）。② `zchain test-e2e` 夹具过时（epoch/空集/零
state_root/假签名）——修复为真实 genesis validator + 真实执行 state_root
+ 真实可恢复证书签名。

**常规测试立档**：`scripts/e2e_acceptance.sh`（full/quick 两档）成为
e2e 验收唯一入口——workspace release 套件 + 节点 e2e + 4 场景演练
（**串行强制**）+ extension 浏览器 E2E + 独立 workspace + fuzz 冒烟 +
1000 手审计留痕；逐门结果时间戳落档 `docs/test-records/`。立档日全量
记录见 `docs/e2e-acceptance-2026-09-13.md`（本日另一教训：并行跑两套
7 节点演练会因 CPU 争用产生 commit 引擎时序假阴性，脚本已强制单流程）。

## ⭐ 实现状态（2026-09-13 第五轮：二次盘点核验 + kill-2 死锁修复）

对照 `docs/roadmap-schedule.md` 全量复验二次盘点五项交付——阈值 BLS（t-of-n
DKG）、DA v2（object_type 签名域 + Merkle 分块挑战-应答）、withdrawal_root
进 appchain checkpoint（additive）、bond/slash 对账恒等（`SlashLedger::
reconciliation_digest` 链式摘要 + `slash.rs`/`bond.rs` 两侧 reconcile +
`slash_ledger_digest:<hex>` 跨仓锚定）、合规运营化框架（geo_policy 版本化 +
sequencer 准入门接线 + 审计账 + 指标）——实现与测试全部在树。**测试基线**：
全量 release 套件 3714/0（54 目标；`--exclude stwo-cairo-prover`，套件口径
见排期表表头如实标注）+ extension 154/154 + zwallet 19/19。

**复验发现的回归与修复**：阈值/聚合 7 节点演练 kill-2 场景（存活恰 = quorum）
3 次尝试全败——引用轮闭合检查把掉线 validator 永不产出的 vertex 当 gossip
在途无限等待，且候选按 round-asc 序最老者优先、失败即整体弃权 → commit 冻死
（vertex 平面持续推进而 tip 停滞，二次盘点声明的 PASS=9 不可复现）。修复：
`bullshark::author_has_vertex_since` + `COMMIT_ABSENCE_ROUNDS` 前沿缺席分类
（DAG 内容纯函数，finality 口径不变，见 `consensus/bullshark.rs` 模块头 L6）。
修复后：阈值演练第 1 次尝试 PASS=9 FAIL=0（kill-2 后 QC 24→32、mode=
threshold、重启恢复 fail-closed），聚合演练 PASS=5 FAIL=0；受影响目标
poker_l1 lib 1896 / poker-appchain 390 / zchain 17 全绿。上游洗牌链阶段 0
（2026-09-12 PASS，`poker-appchain/docs/SHUFFLE_STAGE0.md`）状态同步入表。

## ⭐ 实现状态（2026-09-13 第四轮：排期表全线开发）

按 `docs/roadmap-schedule.md` 完成各组开发（多工作流并行，逐项证据见排期表
行内标注与各 docs/ 报告）。**测试基线（终验实测）**：poker_l1 lib 1873 /
poker-appchain 389 / settlement-core 36 / wallet 43 / zchain 17 / texasair 16
全绿；网关 smoke 85 PASS；扩展 node 154/154 + E2E 30/30+36/36+12/12；可复现
构建 PASS 6/6；网站三扫描 0/0/全过（ABI v1.3）。

**v1.5 共识**：ForceInclude 强化（receipt sidecar 持久化、forced 集进 vertex
载荷）；SlashLedger 真实罚没（stake 扣减→归零停出块）；checkpoint + 聚合 QC
（blstrs 零新依赖，7 节点演练 kill-2 后 QC 推进；如实命名聚合 QC 非阈值 BLS）；
DA 凭证闭环（独立域防重放，M8-ACC-8 场景过）。修复 commit 路径 sig 排序
load-bearing 既有 bug。

**代币经济 TE**：TE-E0 三仓枚举（FIXED_RAKE_BURN=2，上游 mode2 完整 STARK
实测）；TE-M1 AssetId{domain,token}（v2 一次性改型，同域跨 token 攻击面
fail-closed）；TE-M2 REAL 多币种（DepositV2=9/WithdrawRequestV2=10，per-token
托管恒等式，轧差拒绝结构性强制）；TE-M3 GTS（RegisterGameToken=11/Issue=12/
Burn=13，价带双向，供给恒等对账）；TE-M4 FixedRakeBurn 合约侧销毁处置
（rake_disposal 单一判定点，GAME 桌一手 e2e：outstanding 收缩闭环）；
TE-M5 多币种呈现（网关资产摘要+扩展分栏+网站说明）；TE-M6 Free 模式
（14/15/16，GasCreditLedger 与 CustodyLedger 物理隔离，INV-TE-8/9）。
合规运营化框架（GeoPolicy 版本化/KYC 制动位/限额）实现已并入工作树。

**钱包全线**：Extension 0.2→0.4.0-alpha（多账户/网络切换/备份恢复/proof
portal 含 wasm 复验/SNIP-12 会话密钥授权/限额双层/capability matrix/
可复现构建 PASS 6/6）；Tauri 桌面钱包 MVP（Tauri v2 + zwallet，CLI 互通）。

**探针与决策**：stwo-wasm 探针 CONDITIONAL GO → **路径 A 已拍板并交付**
（vendored cfg 门解除，canonical 真证明浏览器验证 p50 ~1.7s，超 500ms
3.5× 按低频口径如实标注；路径 B 留后续）；Cairo 递归桥 PoC CONDITIONAL
（官方 verifier_core 写 Cairo 验证程序全链路跑通；直接合约验 AIR 24.7B gas
NO-GO，递归桥 10M–100M gas，无信任退出 CONDITIONAL——前置 FRI 降 q 等）；
GPU 探测 v1 不引入。

**洗牌/发牌证明链（路线 A+B，用户拍板）**：上游阶段 0 PASS——全链单批
13 行（shuffle×4→reveal×4→下注→终局）prove+verify 通过，协议行边际成本
≈0，log 8 维持；原生 sidecar 校验必拒 deck 篡改（AIR 盲区的实证正当性）。
消费侧：hand_binding v2（poseidon 域，deck_chain_digest+reveal_commitment
进绑定）、REAL×协议行 fail-closed、镜像偏移表钉扎、deck 摘要算法裁决冻结
（上游同源 poseidon 折叠）。待办：wire 格式冻结、hooks 实时接线（阶段 1 C5）、
v2 owner 进 AIR。

**密钥与合规**：KeyProvider 可插拔注入（Env/File/Remote 三实现，无固定种子
回退双重钉住）+ 轮换工具整合。

**待办与边界（如实）**：洗牌链 wire 冻结与实时接线；阈值 BLS（聚合 QC 已
预留接入点）；TE-M5 对账页部署面；stwo-wasm 优化（如需达标 500ms 需路径 B
或 simd 深化）；canonical AIR 未纳入 v2 owner（v2 证明覆盖为水位级）；
fold-win 计费语义（业务决策）；部署依赖项仍以 `RELEASE_PREREQUISITES.md`
为准。

## ⭐ 实现状态（2026-09-12 第二轮：BLOCKERS 全关 + wallet-core + 产品化站点）

**BLOCKERS.md：B1–B9 全部关闭。** 逐项：B9 rake 口径统一（`rake_base()` =
contested 层 gross 之和，uncalled 返还不计费，ABI v1.2.2，含 uncalled 手
e2e 正例）；B5 owner 二级索引（proptest 全量扫描 oracle 等价 + loadtest）；
B4 三个 fuzz target（note_abi 112k / soft_confirm_api 70k /
settlement_witness 71k runs，ASan 0 crash）；B1 性能基准落档
`docs/plan-appchain-perf.md`（证明就绪 777ms p95，M4-ACC-1/2 PASS，回归
断言写死）；B3 逐街实验 DR-1（机制成立、经济学失败——log_size 8 下限使
单证明成本与行数解耦，v1 定整手，数据落档）；B6 texas 结算出口接
appchain sequencer（`texas/src/starknet/appchain/`：进程内 SettlementProver
真调 canonical 验证、plan 派生、嵌入式 Sequencer+管道、SOFT_CONFIRM 事件、
Starknet 旧路径保留可配回退）；B7 出入金链上侧（VaultProvider trait +
Mock/Starknet 双实现、存款幂等桥、提现 finality 执行、自动对账告警）。
B6/B7 残余边界如实记录于 BLOCKERS（REAL 归档实时生产者、fold-win 手回退、
客户端密钥托管、线上桥校准）。

**钱包（§6.12 / M6）**：新 crate `poker-wallet`（§6.12.3 九模块：key_manager /
keystore Argon2id+AEAD / note_store REAL-PLAY 物理分库 / operation_signer
结构化预览+拒绝任意字节 / sync / verifier / backup / vault_adapter /
account_binding SNIP-12 rev1 AuthorizeZChainKey 实测可验签），43 测试；
CLI 钱包 `poker-wallet` bin；**Extension 0.1**（MV3 + wallet-core WASM +
`zchain_*` provider + origin/nonce/expiry 安全层 28 用例 + 真实浏览器 E2E）。
M6-ACC 覆盖：2/3/4/7/8 全覆盖，1/5/6 部分（浏览器吞吐/真机兼容矩阵/插件
发布工程为集成面），连接协议 WalletConnect/EIP-1193 适配器为 0.3。
WALLET-ACC 覆盖对照见 `poker-wallet/README.md` 与 `extension/ACCEPTANCE.md`。

**产品化（§6）**：`website/` 静态站（构建脚本 python3 标准库，41 页）——
官网 13 路由（含 §6.3 中英文案与首屏四入口）、文档站 13 板块 28 页
（15 分钟 quickstart、协议提炼、安全公式"数学式+伪代码"）、media-kit v0.1
21 文件（logo/品牌规范/one-pager/新闻稿/FAQ/whitepaper/litepaper/90s 脚本/
发布节奏模板）、/legal 全项。验收扫描：禁用词 0 命中（11 词表）、2567 内链
0 断链、a11y 规则全过（对比度 ≥7.85:1）、桌面+375px 移动端实测截图
（`website/ACCEPTANCE.md` 逐项记录，TLS/portal 后端/release 基础设施如实
标"待部署"）。§6.10 指标面板为定义+数据源文档（实时面板属 portal 服务，
待部署）。

**测试基线（本轮收尾时）**：zchain workspace 全量 release 构建通过；
poker_l1 / poker-appchain / poker-settlement-core / poker-wallet / zchain
bin / poker-appchain-texasair / texas（poker_texas_air 工作区）全部套件
绿（数字见最终验证报告）。

## ⭐ 实现状态（2026-09-13：E2 闭环 + outer_aggregate + GPU 探测结题）

**explorer E2 闭环（§6.5）**：证明注册表 `proof_registry.rs`（冻结 JSONL
契约 + pipeline `attach_proof_registry` 挂账，写失败不吞完成项的 sidecar
语义；base64 手写实现钉 RFC 4648 向量，零新依赖）；网关
`/api/v1/proofs` + `/api/v1/proof/{binding}`（引擎响应头 + base64 归档
字节）+ settlement 明细补 `payout_root` 与 proof 链接。**E2 验收链路
实测通过**：帧 → settlement(hand_binding) → payout_root → 归档下载
（HTTP 200 + 独立引擎 verify），smoke 62 PASS。

**M4 outer_aggregate**：`aggregate.rs`（域 `poker-appchain.aggregate_root.v1`
确定性 Poseidon 折叠，golden 冻结）+ pipeline `aggregate_due(now, interval)`
时间窗触发（空窗 None、不重复聚合）+ sequencer `record_aggregate`/
`attach_aggregate_log` sidecar/恢复等价 + watcher `--aggregate-log` 独立
重算校验（换根负例 exit 1 `aggregate_mismatch`）+ 网关
`/api/v1/aggregates` 与 status 聚合字段。ABI **v1.2.3**（加法式：聚合根、
注册表契约、端点表；网站版本串同步，史实性 v1.2.2 引用保留）。

**M0 GPU 探测结题**：`docs/gpu-prover-probe.md`——结论 v1 不引入 GPU
prover（CPU 基线 777ms p95 对 ≤3s 门槛余量 ~4×；DR-1 结构性结论不因
GPU 改变），含重启评估触发条件。

**终验 B（独立复跑）**：appchain 155 / poker_l1 1809 / settlement-core 29
/ wallet 43 / zchain 17 全绿；E2 链路与聚合 watcher 正负例 HTTP 级实录；
网站三扫描 0/0/全过；ci_local **14 PASS / 0 FAIL**（含 fuzz-smoke 实跑）。
仍开放：indexer 持久化（archive 节点级）、E3 proof portal 部署面、
E4 BFT 视图（v1.5）、线上桥校准、钱包产品线（RELEASE_PREREQUISITES）。

## ⭐ 实现状态（2026-09-12 第三轮：Phase 1 收尾 + 浏览器开发 E1/E2）

**M3-ACC-6 ForceInclude（plan §5.3）**：新模块 `poker_l1/src/force_include.rs`
——SeenReceipt（节点 secp256k1 签名回执，域 `0x53||chain_id||tx_hash||
seen_at`）+ RPC `get_seen_receipt`/`check_censorship`；inclusion deadline
（`--inclusion-deadline-ms`，默认 10000，0=禁用且与旧路径对拍回归）到期
交易强制包含、组内 tx_hash 升序先于普通交易、included 去重；CensorshipProof
三态（Censored/Included/NotYetDue）+ 命中计数（`zchain_censorship_detected_
total`，v1 只记录不罚没）。测试：poker_l1 lib 1788→1809 全绿 + 端到端
小样；3 节点组网回归 PASS。边界如实：receipt 内存态、多 validator forced
集不进共识载荷（活性风险已文档化）、checkpoint 窗口用块数近似。

**M3-ACC-7 watcher 独立化（收尾）**：`appchain_watcher` 独立进程——软确认
链完整性、结算语义（表策略逐条 validate_settlement）、proven log 批次根
按窗口独立重算、checkpoint 对拍、双链分叉检测；四类篡改负例全部退出码 1
且类别定位正确；exit 0/1/2 语义 + `--json-out` 接告警。

**M8**：① proven-log sidecar（`attach_proven_log`/`replay_restoring_proven`，
JSONL 契约冻结、撕裂尾行容错、越界拒绝）——关闭"水位/批次根重启即失"
的观测缺口；② checkpoint 导出/校验（`checkpoint.rs`，digest 全字段对拍）；
③ bond 内部记账框架 v1（`bond.rs`，只记录不真实罚没）；④ 密钥轮换停机
清单工具（`rotation.rs`+`seq_key_rotate` bin，域分离签名，篡改拒绝；链内
热轮换属 v1.5，runbook §5 流程）。

**M5-ACC-3（v1）**：`rake_audit` 工具——export（WAL 重放→逐手 pots/rake
base/分账/守恒数字 JSON）+ verify（**只用 poker-settlement-core 的独立
代码路径**：contested-only 口径、费率/分账/守恒全重算）；4 类篡改负例
（改 rake/改分账/翻 contested 标记/删明细）全部退出码 1。边界：同仓独立
路径 ≠ 第三方独立仓库，最终形态仍待外审。

**M9**：runbook `docs/runbook.md`（sequencer 重启/prover 积压/提现故障/
工具/密钥轮换，含 evaluate_alerts 5 条告警对照）+ 重启演练脚本
（head_hash 一致，实测 RTO 26ms 开发机样本）；四延迟指标 M9-ACC-4
（`latency_report`：soft_confirm p50/p95/p99 + proof_ready p50/p95，
bft/claimable 未上线如实输出 null）。

**区块链浏览器 E1/E2（§6.5 Explorer）**：`explorer_gateway` 只读网关——
appchain WAL 回放态（replay + proven-log 恢复水位）+ L1 节点 RPC 代理
（HTTP 优先、newline TCP 回落）；端点 status/frames/settlements/
settlement/{binding}/batch_roots/metrics/l1.{metrics,block,tx}；每 IP 令牌
桶限流、默认只绑回环（`--public` 显式并告警）、篡改 WAL 拒启。网站接线：
explorer 页同源 fetch 实时数据 + 刷新按钮，无网关静默保持 SAMPLE DATA。
**E1 验收实测**：3 节点 devnet 起网，经网关取回真实高度与块（代理
`zchain_block_height` 与节点直连一致，块含 DAG commit certificate）；
**契约交叉校验**：watcher 对网关 fixture 独立重算判定 CONSISTENT（该对拍
曾暴露 fixture 用 settlement_binding 而非 hand_binding 折叠的漂移，已修
正对齐 pipeline 生产语义）。E2 剩余：proof 归档下载、archive 级持久化
indexer（见路线图 open 项）。

**CI**：`.github/workflows/ci.yml`（build/test-core/test-extension/
website-scans/gateway-smoke 五 job）+ `scripts/ci_local.sh` 本地等价门
（11 PASS / 0 FAIL 实测）。

**测试基线（本轮终验实测）**：poker_l1 lib 1809 / poker-appchain 全目标
131 / poker-settlement-core 29 / poker-wallet 43 / zchain bin 17 全绿；
extension 79/79；gateway smoke 41/41；网站三扫描 0 命中/0 断链/全过。
记录：n=1 单 validator 不出块（n=1 从非目标形态，组网验收以 n≥3 为准）。

**仍开放（后续轮次）**：M4 批次递归聚合（outer_aggregate 定期聚合）、
M7 线上桥校准、proof 归档下载 + 持久化 indexer、
Extension 0.2/0.4、独立钱包应用、stwo-wasm——发布依赖项仍以
`website/RELEASE_PREREQUISITES.md` 为准。GPU 路线探测已结题（报告
`docs/gpu-prover-probe.md`，结论 v1 不引入）。

## ⭐ 实现状态（2026-09-12：§5.2 P0 全部关闭 + stwo 端到端 + 多节点组网验收）

**本节为 §5.2 复核结论（v1.2 P0）的落地记录。** 验收基线：workspace 全量
`cargo build --release` 通过；测试 poker_l1 全套件 + poker-appchain 86 +
poker-settlement-core 26 + poker-appchain-texasair 13（含 E2E 正例）+
zchain bin 17 全绿。

**§5.2 P0 逐项状态**：
1. **结算单一事实源 ✅** — 新 crate `poker-settlement-core`（workspace
   成员）：`SettlementPlan/SidePot/RunoutSchedule/PayoutVector(PayoutLeaf)/
   rake/SettlementPlanDigest`（blake2b 域 `zchain.texas_poker.settlement_plan.v2`
   冻结）；poker_l1 全部再导出（既有测试期望零改动通过）。
2. **pot 派生 ✅** — `SettlementRecord` 携带 plan；`validate_settlement`
   强制 `plan.gross_pot == record.pot == Σinputs == 已证明终态镜像 pot`
   （状态镜像字节偏移 74）；scope v2 镜像 pre/post_state_root；
   payout_root、side_pot_root、plan_digest 进入 Poseidon
   `settlement_binding`，payout_root 进入 `settle_effect`（玩家签名覆盖
   精确赔付结构）。
3. **REAL 真证明 ✅** — `RealSettlementPolicy` 默认 `StarkRequired`
   （fail-closed）：host-validate-v2 对 REAL 一律拒；三层门（引擎/管道
   准入/批次水位复查）+ 固定 verifier key 钉扎；attestation v2.1（192B
   payload）覆盖 verifier key、引擎版本、pre/post 状态根、已验证 plan
   digest。vault REAL 提现要求水位 + 批次根双重 finality（PLAY 豁免）。
4. **原子提交 ✅** — submit 改为克隆态试算 → 签名 → WAL append + 真
   fsync（`WalSink::sync_all`）→ 原子换入；WAL 失败零状态变更；E2E
   揭露并修复重放期准入门与水位入状态根两个恢复缺口。
5. **连续水位 ✅** — `mark_proven` 缺口集实现只推进最大连续前缀；prove
   失败/panic 带退避重试不丢任务；批次验证失败不丢 completion；管道→
   水位经 `ProvenCallback` 真实接线（loadtest 水位由批次驱动）。
6. **哈希/顺序统一 ✅** — 批次根实现改为 Poseidon（域
   `poker-appchain.batch_root.v1`），与文档一致，golden vector 冻结进
   ABI.md §7；poker_l1 通道顺序此前已统一。
7. **输出完整绑定 ✅** — `NoteSpec` 增 `pot_index/runout_index`；
   `PayoutLeaf` 五元组绑定 + RFC 6962 风格 `payout_root`（域
   `zchain.settlement.payout_root.v1`，golden vector）。
8. **共识校验 ✅** — poker_l1 四项审计 P0（quorum/空集/通道一致性/原子
   回滚）已修复；bridge 非原子性维持 fail-closed 整块拒绝；全仓库可构建
   （含 poker_zkvm：registry stwo-cairo-common 经 `[patch.crates-io]`
   重定向到 vendored 补丁版）。

**证明系统（stwo / Stark curve）**：适配器 `poker-appchain-texasair` 迁移
到 poker_texas_air canonical AIR API（`verify_canonical_tagged_proof`；
上游已删除旧 `texas_tagged`）；测试含真实 `prove_canonical_tagged_batch`
出证正例与深度篡改负例（Fiat–Shamir 流/状态镜像字节翻转均被 stwo 验证器
拒绝）。app 的 Stark curve 深依赖（Felt252 + 手写 StarkCurve sigma 套件）
经 poker_texas_air path 依赖完整保留。另修复 poker_l1 对上游 poker_protocol
漂移的 4 处编译错误（V3 reconstruction + Bayer-Groth 内联为
`reconstruction_v3/`，wire 行为兼容）。

**多节点组网**：`zchain node` 修复三个活性 bug（轮次偏斜死锁、commit 语
句去同步、epoch 分叉）+ 持久拨号/PEX 升级/启动追块（全验块）。验收：
`scripts/multi_node_e2e.sh` 3/4 节点全收敛（skew=0）；4 节点 kill-one 容
错（quorum(4)=3，存活继续出块，`scenario_kill_one_of_four.sh`）；重启
catch-up 追平。n=3 容 0 错为 quorum 语义（`scenario_kill_one_validator.sh`
记录）。移除阻塞 bin 构建的 stale `poker-demo`。

**E2E 验收**：`poker-appchain-texasair/tests/e2e_full_hand.rs` —— 3 人
REAL 桌完整一手（盲注入镜像、raise/all-in/fold/call、收池），单 canonical
batch 真实 stwo 出证；`StarkRequired` 结算：nullifier 销毁、赢家 payout、
treasury/operator rake、守恒恒等式成立；批次根 + 水位后 REAL 提现
finality 闭环（双负例拒 + 幂等）；双防篡改支线通过。
遗留（BLOCKERS B9）：rake 口径——poker_l1 contested-only 计费 vs appchain
全额 gross 费率关系，含 uncalled 返还层的手 fail-closed 拒绝，待统一；
Revealing→Betting 洗牌/发牌续链属 poker_texas_air 上游路线（当前一手证
明自 hand-start 镜像起，盲注面额已被 custody 恒等式覆盖）。

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
- [x] GPU 路线探测（可选，仅出报告）：`docs/gpu-prover-probe.md`——v1 不引入 GPU prover（CPU 基线 777ms p95 对 ≤3s 门槛余量 ~4×）；含重启评估触发条件
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
- [x] 批次聚合：`outer_aggregate` 定期聚合已验证证明产出聚合根（2026-09-13 交付：`aggregate.rs` Poseidon 域 `poker-appchain.aggregate_root.v1` 折叠 + pipeline `aggregate_due` 时间窗触发 + sequencer 记录/sidecar 持久化 + watcher 独立重算校验；注：聚合根为确定性承诺折叠，stwo 递归证明聚合属上游/Phase 2）
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
- [x] note 钱包：加密存储、余额聚合视图、备份导出（`poker-wallet`：Argon2id+AEAD
      keystore、REAL/PLAY 物理分库、加密备份/恢复）
- [x] wasm 验证集成：结算证明本地验证 + 软确认链跟随（wallet-core 编译 wasm
      供扩展使用；本地 verifier 覆盖 settlement/软确认链/批次根）
- [x] REAL / PLAY 模式 UI 隔离与明确标识（逻辑层类型隔离 + 扩展徽章 + claim 门）
- [x] 密钥恢复流程分模式：自托管账户只允许加密备份/恢复因子恢复；托管恢复必须
      经过旧 note 冻结、延迟窗口和可审计迁移，客服不能绕过账本直接重建私钥或增发
      （§6.12.6 恢复/轮换纪律 + 备份恢复全链路 fail-closed 测试）
- [x] 钱包兼容性矩阵与适配层：区分 ZChain Note owner key、Starknet Vault account
      和可选 EVM 外部账户，禁止把地址/签名格式混用；评估并实现 ABI v2 的
      Stark curve/SNIP-12 typed-data 路径（§6.12.1 矩阵 + SNIP-12 rev1
      AuthorizeZChainKey 实测可验签）
- [x] 原生钱包插件（浏览器扩展）和独立钱包应用的最小可用版本（Extension 0.1：
      MV3 + wallet-core WASM + 真实浏览器 E2E；CLI 钱包 `poker-wallet`）
- [x] 钱包连接协议：优先实现 Wallet Standard 风格能力发现；外部连接分别适配
      WalletConnect v2 / EIP-1193 / Starknet 钱包接口，不把这些协议伪装成原生共识账户
      （getCapabilities 能力发现；`extension/adapters/`：EIP-1193 只读白名单+
      `zchain_*` 透传、WC v2 namespace 映射+能力∩白名单授予+重放/过期拒（生产
      SignClient 注入点就绪）、Starknet SNIP-12 授权委托（无 note spend 路由）；
      79 用例钉住红线；真机矩阵归 WALLET-ACC-1）
- [x] 交易签名预览：显示网络、资产、金额、桌、输出 owner、rake、request id、
      hand binding 和 proof 状态；拒绝无法结构化解析的签名请求

**验收测试**：
- M6-ACC-1 浏览器验证吞吐：连续 10 手证明验证，全部通过且无内存泄漏（长会话）
- M6-ACC-2 离线恢复：备份导入后 note 完整、包含证明可重建
- M6-ACC-3 伪造拒绝：篡改证明/软确认帧注入，客户端拒绝并提示
- M6-ACC-4 恢复演练：模拟密钥丢失走恢复流程，note 不损失（测试环境脚本化）
- M6-ACC-5 钱包兼容性：主流外部钱包只能访问其明确支持的 Vault/桥接网络，
  不得被误识别为 ZChain Note owner；secp v1 与 Stark/SNIP-12 v2 的签名及 verifier
  交叉验证通过
- M6-ACC-6 插件安全：扩展页面、dapp 页面和后台 worker 的消息来源校验、
  origin 绑定、重放 nonce、网络隔离和权限最小化测试通过
- M6-ACC-7 签名可读性：所有提现、转账、买入和结算签名均能显示人类可读摘要，
  未知域标签、未知 ABI 版本和金额溢出一律拒绝
- M6-ACC-8 备份恢复：在新设备导入加密备份后，note commitment、spend secret、
  已消费 nullifier 索引和未完成提现状态可完整恢复，且不导出明文私钥

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

## 5. 2026-09-11 架构复核与 v1.2 修订结论

本节是对本计划、`poker-appchain` 实现、`poker_l1` 既有合约/共识代码以及
`SECURITY_ARCHITECTURE_AUDIT.md` 的联合复核结论。它覆盖前文未明确的信任边界，
并作为 REAL 资产上线前的新增门槛。

### 5.1 总体定位与分阶段承诺

当前实现应明确定位为：**托管式扑克应用链 + 单 Sequencer 软确认**，而不是
已经具备抗审查和无信任退出能力的公共 L1。

- v1 MVP 可以保留单 Sequencer，以获得毫秒级软确认；软确认只代表运营方承诺，
  不代表 BFT 最终性，也不能单独授权 REAL 提现。
- v1.5 引入 4–7 个 validator 的 BFT checkpoint；每桌仍可按独立状态分片执行，
  全局只对批次根、提款根和状态根做最终确认。
- v2 再接入 Starknet Vault 的可验证 checkpoint、STARK verifier、挑战和
  permissionless withdrawal，完成从托管对账到密码学退出。

因此，产品与文档中应区分以下四种状态：

```text
soft accepted → BFT ordered → proven → finalized/claimable
```

REAL 资产只有在 `proven + finalized` 后才可进入外部提现流程；PLAY 资产可在
软确认阶段提供更快的游戏体验。

### 5.2 P0：上线前必须修复的实现问题

以下项目应从“后续工作”提升为主网阻断项：

1. **结算语义只能有一个事实源。** 当前 `poker-appchain` 的简单
   `SettlementRecord` 与 `poker_l1` 已有的 side-pot、run-it-twice、odd-chip
   结算逻辑存在重复建模风险。新增共享 `poker-settlement-core`，统一定义
   `SettlementPlan`、`SidePot`、`RunoutSchedule`、`PayoutVector`、rake 分配和
   `SettlementPlanDigest`，由 VM、appchain、Texas AIR、Lean 和 verifier 共用。
2. **pot 必须从已验证的牌局状态派生。** 不再把 `record.pot` 作为独立可信输入。
   手牌证明的 public input 必须包含 `pre_state_root`、`post_state_root`、
   `gross_pot`、side-pot 根、payout 根、rake 和 `policy_commitment`，并证明
   `gross_pot` 来自下注贡献。
3. **REAL 结算必须使用真实证明。** `host-validate-v2` attestation 仅允许用于
   testnet、PLAY 或封闭内测；REAL 提现必须要求固定 verifier key、证明系统版本、
   状态前后根和已验证的结算计划摘要。
4. **状态变更必须原子提交。** 当前 Sequencer 存在“先 apply、后写 WAL”的崩溃窗口；
   WAL 的 `flush` 也不等于 `fsync`。改为 intent/WAL fsync/临时状态校验/原子提交，
   并对 ObjectDb、AccountStore、BridgeRegistry 和事件做同一事务边界。
5. **证明水位必须只推进连续前缀。** 证明完成可以乱序，但 `proven_watermark`
   只能推进到最大的连续 `op_index`。批次验证失败时不得先丢弃 completion；批次根、
   证明验证和水位推进必须具备失败恢复语义。
6. **协议哈希和状态执行顺序必须统一。** 文档、producer、projection、validator
   replay 对交易通道使用同一个 canonical order；批次根的 Poseidon/Blake2s 选择、
   域标签和 ABI 版本必须统一，不能出现“文档写 Poseidon、实现用 Blake2s”的漂移。
7. **结算输出完整绑定。** payout leaf 至少绑定 `asset_class`、`amount`、`owner`、
   `table_id`、`pot_index`、`runout_index`；所有输出聚合成 `payout_root`。不能只
   签名 owner 和金额。
8. **共识校验阻断项必须纳入本计划。** 既有审计记录的低 quorum certificate、
   空 validator 集、public/GameTurn 执行不一致、失败交易非原子回滚，均须在
   Phase 1 出口前关闭。全仓库测试未通过时，不得宣称“全部模块 ACC 通过”。

### 5.3 抗审查设计

watcher 只能发现 Sequencer 分叉，不能解决交易被永久拒绝的问题。v1.2 增加
以下协议对象：

```text
SeenReceipt      = relay/validator 对 tx_hash 的签名接收回执
ForceIncludeTx   = 超过 inclusion_deadline 后的强制包含交易
CensorshipProof  = SeenReceipt + 有效交易 + 超时证明
```

处理流程：

1. 用户可以向 Sequencer、任意 validator 或公共 relay 并行提交交易；relay 返回
   `SeenReceipt`。
2. 交易在 `inclusion_deadline`（初始建议为 2 个 checkpoint）内未被 Sequencer
   包含时，任意 validator 可以提交 `ForceIncludeTx`。
3. canonical block 将强制包含队列排在普通游戏交易之前，并按 `tx_hash` 做确定性
   排序，避免 validator 之间再次产生排序分歧。
4. 多个独立入口的回执、有效签名和超时条件共同构成 `CensorshipProof`；证明成立后
   扣罚 Sequencer bond、记录审查事件并触发 proposer/Sequencer 轮换。
5. Sequencer 停机、数据不可用或长期不包含交易时，用户可从最后一个 finalized
   checkpoint 走 `ForceWithdraw` / `ForceSettle`，不能把逃生路径放在被审查的
   Sequencer 自己手中。

扑克隐私不应被抗审查机制破坏。手牌秘密、note secret 和私有 witness 不进入
`SeenReceipt`；如后续需要隐藏下注内容，可在共识排序后增加 threshold decryption，
但强制包含只处理交易承诺和有效性证明。

### 5.4 合约结算与 Starknet 边界

不建议逐手牌把结算直接发送到 Starknet。正确边界是：

```text
扑克 Appchain：下注、牌局状态、结算计划、note、rake、证明
Starknet Vault：充值、提款、checkpoint、外部资产最终释放
```

充值流程：

```text
Vault Deposit event
→ 等待外部确认
→ validator 验证 source_chain/vault/tx_hash/event_index
→ 幂等铸造 REAL note
```

提款流程：

```text
REAL note burn
→ 生成 WithdrawalLeaf
→ STARK proof 验证
→ BFT finalized checkpoint
→ checkpoint 携带 withdrawal_root
→ 用户用 Merkle proof 在 Vault permissionless claim
```

`WithdrawalLeaf` 至少绑定 `request_id`、外部收款地址、资产、金额、被销毁 note
承诺和 checkpoint。Vault 必须自己检查“未领取”，不能只信运营方的打款队列。

在 Starknet verifier 尚未上线前，v1 的提现仍属于多签/托管流程，文档必须明确写明
这是运营方负债，而不是无信任桥。`rebuy`、`addon` 等没有真实资金来源的接口在
Treasury/PaymentProof 接通前，生产构建应硬禁用。

### 5.5 共识选型结论

“结算最快”不能只看 TPS；端到端延迟还包括交易进入、执行、证明、最终性和数据可用。
本项目推荐：**桌级快速执行 + 全局批次 BFT 最终性**。

全局共识优先选择 **HotStuff-2/Jolteon 风格的流水线 BFT + 阈值 BLS QC**：

| 方案 | 最终性特征 | 本项目结论 |
|---|---|---|
| 单 Sequencer | 毫秒级软确认，无 BFT 最终性 | 仅用于 MVP 快速路径 |
| Tendermint/CometBFT | 通常 1–3 秒，成熟稳定 | 可用但不是首选低延迟方案 |
| 当前 Bullshark | 代码复用好，当前目标约 3 秒 | 作为过渡，不直接宣称最快 |
| HotStuff-2/Jolteon | 约 2 RTT，适合小 validator 集 | **推荐用于 v1.5 最终性** |
| Narwhal + HotStuff | 高吞吐、工程复杂度较高 | 扩容阶段再引入 |
| Sui Mysticeti | 需要对象模型和执行模型重构 | 不建议当前直接迁移 |

初始 validator 集建议为 4–7 个，满足 `n ≥ 3f + 1`，QC 为 `2f + 1`。目标值只作为
部署基准，不作为协议保证：同地域可先测 `p50 100–250ms / p95 300–800ms`，
跨地域部署需按真实 RTT 重新校准。

### 5.6 新增验收门槛与里程碑调整

新增验收项：

- **M3-ACC-6**：有效交易在 inclusion deadline 内未被包含时，任意 validator 可
  提交 `ForceIncludeTx`，端到端包含不超过 2 个 checkpoint。
- **M3-ACC-7**：Sequencer 双签、审查证据、状态根冲突均可被独立 watcher 生成证据。
- **M4-ACC-6**：证明乱序、证明失败、worker 崩溃不会错误推进 proven watermark。
- **M7-ACC-5**：finalized withdrawal 可由用户自行提交 Merkle proof 领取；重复领取
  和未 finalized 的根全部拒绝。
- **M8-ACC-8**：DA 请求、ForceCheckpoint、ForceSettle、ForceWithdraw 在 Sequencer
  停机和数据延迟注入下可用。
- **M9-ACC-4**：报告 soft-confirm、BFT finality、proof-ready、claimable 四种延迟，
  不再只报告软确认 p99。

里程碑调整为：

| 阶段 | 修订后的出口 |
|---|---|
| **Phase 0** | 统一结算核心、修复 P0 原子性/共识校验、完成连续证明水位和 ABI/hash 冻结 |
| **Phase 1（MVP）** | 单 Sequencer + 多入口 + ForceInclude + 托管出入金；REAL 仅限受控小流量 |
| **Phase 1.5** | 4–7 validator HotStuff-2/Jolteon checkpoint、阈值 BLS、DA 和 bond/slash |
| **Phase 2** | Starknet Vault verifier、withdrawal root、挑战/退出协议、储备证明 |
| **Phase 3** | table sharding、Narwhal 风格 mempool、多运营方和 B2B SLA |

在 Phase 1.5 和 Phase 2 完成前，不能对外宣称“抗审查最终性”“无信任提现”或
“REAL 结算由链上合约独立保证”。

## 6. 项目产品化与对外发布蓝图

本节把技术方案转成可交付的区块链项目：官网、开发者文档、区块浏览器、状态页、
品牌叙事、宣传材料、社区运营和合规披露必须与代码及信任模型同步发布。所有对外
页面必须显示网络环境（`devnet` / `testnet` / `mainnet`）、资产类型（`PLAY` /
`REAL`）和当前最终性级别，禁止把测试网能力写成主网承诺。

### 6.1 项目身份与品牌基线

项目名称、域名和视觉资产在代码冻结前统一登记；下列名称是工作名，可在品牌评审时
替换，但协议中的 chain id、网络名称和资产符号必须保持版本化：

| 项目元素 | 工作定义 |
|---|---|
| 项目名 | ZChain Poker / ZChain Poker L1 |
| 网络名 | `zchain-poker-devnet`、`zchain-poker-testnet`、`zchain-poker-mainnet` |
| 原生费用 | v1 游戏操作免 gas；不发行“必须购买才能使用”的原生代币 |
| 主要资产 | `PLAY`（测试/娱乐筹码）、`REAL`（托管真实资产映射） |
| 官网 | `https://zchain.example`（上线前替换为已完成 DNS、TLS 和品牌审核的域名） |
| 文档 | `https://docs.zchain.example` |
| 浏览器 | `https://scan.zchain.example` |
| 状态页 | `https://status.zchain.example` |
| 代码仓库 | 公开仓库地址、commit、release 和 SBOM 作为官网固定入口 |

品牌语气：技术准确、克制、可验证、面向玩家和开发者；避免“稳赚”“零风险”“
绝对公平”“不可阻止”“银行级安全”等无法由当前系统证明的词语。视觉上区分
`PLAY` 与 `REAL`，默认深色牌桌风格，所有资金页面显示风险和托管状态。

### 6.2 官网信息架构

官网首页不应只是营销落地页，而应成为信任入口。第一版信息架构如下：

```text
/                         首页：定位、网络状态、立即试玩
/product                  产品：牌桌、钱包、证明公平、结算流程
/technology               技术：Appchain、Note、AIR、Sequencer、BFT 路线
/proofs                   公平证明：手牌证明、结算证明、独立验证入口
/explorer                 区块浏览器：交易、手、结算、rake、checkpoint
/developers               开发者入口：SDK、RPC、ABI、运行节点、示例
/docs                     文档入口（跳转 docs.zchain.example）
/roadmap                  路线图：v1 / v1.5 / v2 / v3 与完成状态
/security                 安全：威胁模型、审计、漏洞披露、暂停开关
/transparency              透明度：储备、托管、提现队列、服务指标
/community                社区：论坛、Discord/Telegram、贡献指南
/legal                    条款、隐私、地区限制、负责任使用
/status                   服务状态（跳转 status.zchain.example）
```

首页首屏必须包含四个可验证入口：

1. **Play Now**：只进入 PLAY 测试/娱乐环境，不默认触发充值。
2. **Verify a Hand**：输入 hand id 或 proof digest，跳转到独立验证页面。
3. **Read the Docs**：进入版本化文档，而不是把关键安全说明藏在 FAQ。
4. **Network Status**：展示 Sequencer、prover、BFT checkpoint、提现服务状态。

官网前端功能要求：

- 钱包连接按网络隔离；devnet/testnet 不得误连 mainnet。
- REAL 页面展示托管提示、充值确认数、提现状态和人工审核（如仍存在）。
- 所有 explorer 数据显示来源：软确认、BFT ordered、proven、finalized、claimable。
- 证明验证在浏览器本地执行时，显示 verifier 版本、proof digest 和验证耗时。
- 文档和下载页面提供 SHA-256、release tag、SBOM 和签名校验说明。
- 前端只读接口设置缓存和限流；钱包签名、提现和外部转账必须二次确认。

### 6.3 官网首页文案（可直接作为 v1 草案）

#### 中文主文案

```text
让每一手牌，都有可验证的结算记录。

ZChain Poker 是面向扑克场景的专用 Appchain：快速确认牌局操作，
用可验证证明约束结算与 rake，并把最终资金释放交给明确的 Vault 与退出协议。

[立即试玩 PLAY]  [阅读技术文档]  [验证一手牌]
```

产品三点说明：

```text
快：桌级软确认提供毫秒级操作反馈。
明：每手牌都有结算摘要、rake 关系和可审计的状态变化。
稳：从单 Sequencer 逐步升级到 BFT checkpoint 与可验证提现。
```

信任声明：

```text
当前 v1 是托管式网络。PLAY 可用于测试和娱乐；REAL 资产仍受运营方托管与
提现流程约束。无信任提现、抗审查最终性和多运营方共识属于后续里程碑，
只有在对应 verifier、BFT 和退出协议上线并通过验收后才会启用。
```

#### English short copy

```text
Every hand. A verifiable settlement.

ZChain Poker is a purpose-built appchain for poker: fast table-level confirmations,
provable settlement and rake accounting, with final asset release handled by an
explicit Vault and exit protocol.

[Play with PLAY] [Read the docs] [Verify a hand]
```

英文页面必须保留 custodial、PLAY/REAL 和 roadmap 限制，不得用 “trustless casino”、
“censorship-proof” 或 “guaranteed fair returns” 等表述替代技术事实。

### 6.4 文档站信息架构

文档站使用版本化结构，`latest` 只能指向已发布 release；草案进入 `next`，不覆盖
已部署网络的规范。

```text
docs.zchain.example/
├── getting-started/       玩家、钱包、PLAY 试玩、网络配置
├── concepts/              Note、nullifier、桌、手、rake、四阶段最终性
├── protocol/              ABI、Operation、SoftConfirmFrame、SettlementPlan
├── architecture/          Appchain、证明管道、Vault、DA、抗审查设计
├── developers/            RPC、SDK、事件、示例、错误码、限流与重试
├── validators/            节点部署、validator set、BFT、密钥、监控、升级
├── operators/             牌桌运营、费率注册、充值提现、对账和故障处置
├── proofs/                Texas AIR、结算 proof、验证器、公开输入和审计导出
├── security/              威胁模型、审计报告、漏洞披露、暂停和恢复
├── economics/             rake 公式、分账、托管边界、费用和风险说明
├── api-reference/         OpenAPI/RPC/ABI 自动生成页面
├── changelog/             版本、协议变更、迁移和兼容性
└── legal/                 条款、隐私、地区限制、责任边界
```

文档发布最低要求：

- 每个代码 release 对应一个 docs tag、ABI 版本和 genesis/config hash。
- API 文档从源码 schema 生成，并包含正例、负例、错误码、幂等和重试语义。
- 每个安全关键公式同时给出数学表达式、规范伪代码和测试向量。
- Note、结算、提现和 checkpoint 提供独立验证命令，不要求运营方私有服务。
- 明确列出“已实现 / 部分实现 / 仅 PoC / 禁止生产使用”，与 `BLOCKERS.md` 同步。
- 所有“性能数字”附硬件、网络、并发、版本、样本数、p50/p95/p99 和原始报告链接。

开发者快速开始必须在 15 分钟内完成：启动 devnet、创建 PLAY note、开桌、完成一手、
读取 settlement proof、运行本地 verifier。示例不得默认使用 REAL 或真实外部地址。

### 6.5 必备公开服务

完整项目至少需要以下五个公开服务，且互相链接：

| 服务 | v1 必备能力 | 不应隐藏的信息 |
|---|---|---|
| Explorer | block/tx/hand/settlement/rake 查询，proof 下载 | confirmation 层级和失败原因 |
| Status | Sequencer、prover、RPC、relay、提现状态 | 事故开始时间、影响范围、恢复进度 |
| Proof portal | 输入 digest/hand id，浏览器验证 proof | verifier 版本、公开输入、失败原因 |
| Transparency | rake 汇总、托管余额、已发行 REAL、待提现 | 数据时间、来源、是否人工调整 |
| Developer portal | API key（如需要）、限流、SDK、webhook | 配额、SLA、破坏性变更通知 |

v1 的 Transparency 页面只能展示托管对账和运营方签名报告，不能命名为“储备证明”
或“链上偿付保证”；只有 Phase 2 的独立 verifier 和 Vault root 上线后才能使用
“proof of reserves”等术语。

### 6.6 对外叙事和宣传素材包

#### 一页项目简介

```text
ZChain Poker 把扑克牌局执行、可验证结算和资金边界拆成清晰的三层：
桌级快速执行负责体验，证明管道负责结算正确性，Vault/退出协议负责外部资产。
项目从托管式 v1 起步，逐步增加多 validator BFT checkpoint、强制包含和
permissionless withdrawal。每个阶段都以公开规范、测试向量和可复验指标为出口。
```

#### 技术型宣传语

- “Fast at the table. Verifiable at settlement.”
- “The appchain for provable poker settlement.”
- “从软确认开始，以可验证退出为目标。”
- “证明结算关系，不承诺未经验证的收益。”

#### 社交媒体短文案

```text
我们正在构建一个面向扑克的专用 Appchain：桌级操作追求低延迟，
结算由 proof 约束，rake 关系可审计，REAL 资产边界由 Vault 明确管理。
当前开放 PLAY 测试环境；REAL、抗审查最终性和无信任提现按路线图逐阶段启用。
```

#### 新闻稿模板

```text
ZChain Poker 发布 [网络版本/测试网版本]：面向扑克场景的专用 Appchain

ZChain Poker 今日开放 [devnet/testnet/MVP]。该网络将桌级操作、结算证明和外部
资产边界分层设计：玩家可在 PLAY 环境体验低延迟牌局，开发者可以通过公开 ABI、
RPC 和 proof portal 复验结算记录。当前 REAL 资产仍处于 [托管/白名单/限额] 阶段；
BFT checkpoint、强制包含和 permissionless withdrawal 按公开路线图逐步启用。

本次发布包含：版本化协议文档、可复现 devnet、区块浏览器、状态页、漏洞披露流程
和公开测试指标。项目不会把测试网性能、托管对账或第三方审计表述为无信任保证。
```

#### FAQ 必答问题

```text
这是公链还是中心化服务器？      v1 是单 Sequencer 的托管式 Appchain，逐步增加 BFT。
PLAY 和 REAL 有什么区别？        PLAY 是测试/娱乐筹码；REAL 是运营方托管的真实资产映射。
软确认是不是最终确认？           不是；最终性要看 BFT、proof 和 checkpoint 状态。
运营方能否修改牌局或 rake？       协议会拒绝不满足签名、守恒、费率和 proof 绑定的记录，
                                  但 v1 的活性和提现仍依赖运营方，风险必须明示。
如何验证一手牌？                 使用 explorer 的 proof portal 或独立 verifier 命令。
Sequencer 审查交易怎么办？        通过 relay SeenReceipt、ForceInclude 和后续 DA/退出协议处理。
出金是否无需许可？               v1 不是；permissionless claim 需等 Vault verifier 上线。
是否发行代币或承诺收益？           v1 不以收益或代币升值为产品承诺，任何经济设计另行治理和合规评审。
```

#### 媒体包与白皮书交付物

发布前建立 `website/media-kit/<version>/`，包含 Logo（SVG/PNG）、颜色与字体规范、
产品截图、90 秒演示视频、架构图、团队/贡献者简介和可引用的项目事实表。技术白皮书
至少包含系统模型、协议 ABI、结算公式、证明边界、威胁模型、性能方法和路线图；
Litepaper 只保留产品、用户流程和风险摘要，不能删去 custodial 或 PLAY/REAL 限制。

#### 发布视频/演示脚本（90 秒）

```text
0–15s  玩家连接 PLAY 钱包并进入牌桌。
15–35s 下注操作获得 soft accepted，展示 frame index 和状态根。
35–55s 手牌结束，展示 SettlementPlan、rake 和 payout root。
55–70s 浏览器本地验证 proof，显示 verifier 版本和结果。
70–82s 展示 explorer、status、docs 和代码仓库入口。
82–90s 明示当前是 v1 托管网络，REAL 提现和后续 BFT/退出协议按路线图开放。
```

所有宣传素材必须带版本和环境水印，例如 `PLAY / TESTNET / v1.3`；旧视频在协议
升级后归档，不得继续展示已经失效的 API、费率或最终性承诺。

### 6.7 发布节奏与运营内容

| 阶段 | 对外内容 | 资金范围 | 退出条件 |
|---|---|---|---|
| Devnet | 开源代码、开发者 quickstart、模拟牌局 | 仅 PLAY | devnet smoke test 和文档可复现 |
| Testnet | faucet、explorer、proof portal、漏洞赏金 | PLAY；REAL 关闭 | P0/P1 安全项关闭、事故演练通过 |
| MVP | 受控 PLAY + 小规模 REAL 内测、透明度报告 | REAL 白名单/限额 | 账实对账、提现 SLA、人工 runbook |
| BFT preview | validator 招募、checkpoint、DA、ForceInclude 演示 | REAL 仍受限 | 4–7 validator 容错和审查演练 |
| Mainnet candidate | 第三方审计、公开 release、迁移手册 | 按地区和合规策略 | 全部主网门槛和回滚演练 |

建议内容节奏：每周一次开发周报（变更、测试、风险）、每两周一次社区演示、每月
一次透明度报告；事故期间停止营销内容，优先发布影响范围、用户操作建议和修复时间线。

### 6.8 社区与生态计划

最小社区结构：

- `#announcements`：仅发布已签名 release、网络变更和事故通告。
- `#developers`：SDK、RPC、proof、节点和 issue 讨论。
- `#players`：PLAY 试玩、反馈和牌局问题。
- `#security`：漏洞披露入口，不在公开频道发布未修复细节。
- `#validators`：节点版本、checkpoint、密钥轮换和故障演练。

贡献路径：文档修复 → 测试向量 → verifier/SDK → 节点/共识 → 生态应用。每个贡献
必须有 `CONTRIBUTING.md`、DCO/CLA 选择、代码风格、测试命令和安全披露规则。
社区激励优先使用 PLAY 积分、黑客松奖金或公开署名；在没有治理、分配、监管和
审计方案前，不设计“早期参与者代币空投”宣传。

### 6.9 合规、安全和责任披露

官网和文档的 `/legal` 至少包含：

- 服务条款、隐私政策、Cookie 和数据保留期限；
- 支持/禁止地区、年龄和身份验证要求；
- PLAY 与 REAL 的法律属性、托管关系和提现处理方式；
- 牌局公平证明、运营方仍可影响的活性边界；
- 风险提示：智能合约、证明器、网络停机、密钥丢失、监管变化和提现延迟；
- 漏洞披露邮箱、PGP key、响应 SLA 和安全公告归档；
- 负责任游戏、充值限额、冷静期和自我排除（如适用）。

安全页面必须公开当前安全状态，而不是只放“已审计”徽章。第三方审计报告要注明
范围、commit、未修复问题、审计日期和不覆盖的组件；审计不等于无漏洞保证。

### 6.10 项目指标与控制面板

官网内部运营仪表盘和月度透明度报告至少跟踪：

```text
体验：soft-confirm p50/p95/p99、手结束到 proof-ready、RPC 错误率
正确性：proof verify 成功率、settlement 覆盖率、watcher 分叉告警
资金：已发行 REAL、已销毁 REAL、待提现、已完成提现、对账差异
活性：Sequencer uptime、relay seen-to-include、BFT checkpoint 延迟、DA 响应
生态：活跃桌数、PLAY 活跃玩家、开发者调用量、文档成功运行率
安全：漏洞数量/等级、修复时间、事故次数、密钥轮换状态
```

每个指标都要有定义、数据源、时间窗口和“不可用/延迟数据”标记；不能用 TPH、
注册数或交易数替代资金安全和证明覆盖率。

### 6.11 官网/文档交付验收

- **WEB-ACC-1**：官网在移动端和桌面端通过可访问性、TLS、性能和断链检查。
- **WEB-ACC-2**：官网可发布页面中的性能、最终性、托管和路线图表述与本计划一致；
  针对首页、产品页、新闻稿和广告素材的禁用词扫描为零（技术文档中的风险讨论不计入）。
- **WEB-ACC-3**：从文档 quickstart 可在干净环境启动 devnet，15 分钟内完成 PLAY 一手。
- **WEB-ACC-4**：任意 explorer settlement 均可跳转 proof portal，并由浏览器本地复验。
- **WEB-ACC-5**：版本发布自动同步 docs tag、ABI、genesis hash、changelog、SBOM 和签名。
- **WEB-ACC-6**：status page 可模拟 Sequencer/prover/RPC/relay 故障，显示影响和恢复记录。
- **WEB-ACC-7**：REAL 页面在 verifier、BFT 或 Vault 未就绪时自动显示“不可无信任提现”，
  不出现误导性 claim 按钮。
- **WEB-ACC-8**：法律、风险、地区、负责任使用和漏洞披露页面在首次充值/提现前可见。

本节完成后，Phase 1 的“完成”定义不再只是 crate 测试和压测，还必须包括一个
可复现的开发者入口、一个可验证的玩家入口、一个透明度入口和一个可审计的运营入口。

### 6.12 钱包兼容性结论与开发计划

#### 6.12.1 当前方案与主流钱包的兼容性结论

结论：**当前 ABI v1 的 ZChain Note 钱包不能直接被主流 EVM 或 Starknet 钱包当作
原生钱包使用**。如果目标只是解决“钱包看不懂摘要、无法安全确认”的问题，可以
采用 **Stark curve + SNIP-12 typed data** 作为 ABI v2 的签名模式；但这不是只改
摘要字符串，必须同时增加 Stark curve 验签、账户/地址编码、owner key 类型、
域分离和钱包 RPC 适配。ABI v1 的 secp256k1 owner 仍需保留一段迁移期。

当前不兼容的原因：

- Note owner 使用 secp256k1 压缩公钥（33B），花费签名是对自定义
  `Blake2s(domain || commitment || nullifier || scope || effect)` 的 ECDSA 签名；
- Note、nullifier、Settlement 和 SoftConfirmFrame 使用版本化 Borsh ABI，
  不使用 EVM transaction/RLP、EIP-712 typed data 或 ERC-4337 UserOperation；
- ZChain 地址由 tagged public key 派生，不等于 Ethereum `0x` 地址，也不等于
  Starknet `felt252` 地址；
- Starknet 主流钱包（如 Argent X、Braavos）默认管理 Stark curve 账户和
  SNIP-12 消息，不能直接产生 ZChain owner 的 secp256k1 spend signature；
- MetaMask、Rabby、OKX 等 EVM 钱包可管理 secp256k1，但只认识 EVM chain/RPC，
  不会自动理解 ZChain Note、nullifier 或自定义 Borsh 签名请求；
- WalletConnect 是会话传输协议，不会自动解决曲线、地址、ABI 或签名语义兼容。

兼容性矩阵：

| 钱包/标准 | ZChain Note v1 | ZChain Note v2（Stark/SNIP-12 目标） | Starknet Vault |
|---|---:|---:|---|
| MetaMask / Rabby / OKX EVM | 否（原生） | 否（除非另做 EVM signer/AA 适配） | 仅可作为未来 EVM bridge/登录适配器；不能伪装成 Note owner |
| Argent X / Braavos | 否（Stark curve 不匹配） | **可作为目标钱包**，前提是支持 `starknet_signTypedData`、自定义 ZChain chain id 和对应 account verifier | 是，前提是 Vault 遵循标准账户/代币调用 |
| WalletConnect v2 | 不是钱包本身 | 通过 Starknet namespace 传输 typed-data 请求，具体能力需探测 | v1 只连接 Vault；v2 注册版本化 ZChain namespace/方法 |
| Ledger / Trezor | 部分，取决于是否支持盲签自定义摘要 | 需官方 Stark app 支持可读 SNIP-12 字段 | 取决于对应 Starknet app；未审计前不开放 REAL 盲签 |
| Passkey/WebAuthn | 默认否（P-256） | 仍需账户抽象适配，不能冒充 Stark curve 签名 | 作为未来 recovery/auth key，不直接替代 owner |
| ZChain 原生扩展/应用 | 是 | 是，优先实现 SNIP-12 和 legacy secp 双模式 | 可通过外部 Vault 钱包连接 |

因此，官网应分阶段表述：v1 支持 ZChain Wallet 和外部 Starknet Vault 钱包；v2
alpha 支持经过 capability 检测的 Starknet typed-data 钱包；只有真实钱包版本、
WalletConnect session、链上 verifier 和迁移测试全部通过后，才可写“兼容支持的
Starknet 钱包”。不能笼统写“兼容 MetaMask/所有主流钱包”。

#### 6.12.1a Stark curve/SNIP-12 妥协方案

如果业务优先级是“让用户用主流 Starknet 钱包确认操作”，采用双轨方案：

```text
ABI v1（兼容现有资产）
  secp256k1 compressed pubkey + custom digest + ECDSA

ABI v2（钱包友好）
  Stark curve public key/felt252 + SNIP-12 typed data + Stark signature
```

SNIP-12 typed data 的 domain 至少包含 `name`、`version`、版本化 ZChain `chain_id`
和 `revision`；message 至少包含 `operation`、`table_id`、`asset_class`、输入/输出
金额、`rake`、`hand_binding`、`request_id`、`nonce` 和 `expiry`。typed data、钱包
展示字段和 verifier 实际验证字段必须一一对应。

注意事项：

1. 不复用 `SN_MAIN`、`SN_SEPOLIA` 或 EVM chain id；ZChain 必须有独立 network id。
2. SNIP-12 只解决消息编码和签名展示，不解决 nullifier、note commitment、proof、
   状态根和结算守恒；这些仍由 Appchain verifier 验证。
3. ZChain 需要新增 `SignatureScheme::StarkCurve`、Stark public key/address 编码、
   nonce/replay protection 和自己的 account verifier；SNIP-12 签名不是 Starknet L1
   交易本身。
4. Argent X/Braavos 对自定义链和 typed-data 方法的支持可能随版本变化；连接时用
   `getCapabilities` 探测，能力不足即拒绝签名，不允许退化成 blind signing。

兼容策略分两步：

- **最小改动**：v1 Note 继续使用 secp256k1；新增 SNIP-12 仅用于 Vault、登录和
  授权委托，快速接入 Starknet 钱包但不改变 Note owner。
- **完整路径**：ABI v2 将 `Note.owner` 改为带 scheme 的 `OwnerKey`（Secp256k1/
  StarkCurve），承诺、摘要和 address derivation 全部版本化；通过迁移交易将旧
  secp note 消费并铸造新 owner note。

推荐的生产形态是 **Starknet Account + SNIP-12 授权的 ZChain 会话密钥**，而不是
假设 Argent X/Braavos 都能暴露一个可由 Appchain 直接验证的裸 Stark 公钥。Starknet
钱包是合约账户，可能使用单签、多签、Passkey、硬件 signer 或可升级验证逻辑；仅按
`account_address → public_key` 验签会破坏账户抽象兼容性。

```text
Starknet account
  └─ SNIP-12 AuthorizeZChainKey
       ├─ zchain_chain_id
       ├─ delegated_public_key + signature_scheme
       ├─ allowed_scopes（PLAY / buy-in / bet / settle / transfer）
       ├─ per-tx / per-day amount limits
       ├─ table allowlist（可选）
       ├─ nonce
       └─ valid_after / valid_until

ZChain delegated/session key
  └─ 对高频牌局 Operation 本地签名
```

授权签名由 Starknet account 的标准签名验证路径确认，并将授权摘要登记到 ZChain
`AccountBindingRegistry`；Appchain 之后只需验证受限会话密钥。撤销、到期、换网、
超额和越权 scope 必须 fail-closed。提现、恢复、主 owner 迁移、提高限额等高风险操作
不得只靠会话密钥，必须回到 Starknet 主账户或 ZChain 主 owner 二次授权。

这一模式同时解决：钱包弹窗频率、合约账户验证差异、移动端断连和高频下注延迟。
“每笔操作直接 SNIP-12”保留为低频高价值操作的慢路径，不作为实时牌局默认路径。

不建议只把现有 Blake2s 摘要包进 SNIP-12，却继续要求 secp256k1 签名；这只是外层
编码变化，不能称为 Starknet 钱包兼容。

#### 6.12.1b ABI v2 与迁移方案

ABI v2 不应继续把 `Note.owner` 固定为 `[u8; 33]`，而应使用显式 owner 引用：

```text
OwnerRef {
  scheme: LegacySecp256k1 | StarkCurve | StarknetAccountBinding
  account_id: 32B/field252 canonical bytes
  key_version: u32
  binding_id: Option<32B>
}

SignatureEnvelope {
  scheme
  signer_ref
  typed_data_digest
  signature
  nonce
  expiry
}
```

v2 Note commitment、nullifier scope、Operation digest 和 payout leaf 必须明确包含
`OwnerRef` 的 scheme/version，防止相同公钥在不同验证器下产生同一承诺。对于
`StarknetAccountBinding`，`account_id` 是账户地址，`binding_id` 指向已锚定的
`AuthorizeZChainKey`；对于 `StarkCurve`，`account_id` 是规范化 felt252 公钥。

迁移规则：

1. v1 和 v2 在迁移期并行存在，v1 note 不自动改变 owner 或签名方式。
2. 新增 `MigrateNote`，由旧 owner 授权消费旧 note，再按同额和同资产类别铸造 v2
   note；迁移必须绑定 `old_commitment`、`new_owner_ref`、`migration_nonce` 和
   目标 network/ABI 版本。
3. 迁移操作进入 proof 和 BFT checkpoint；不能通过后台数据库直接改 owner。
4. v2 verifier 必须同时验证 legacy secp、Stark curve 和 account binding 三类输入；
   迁移完成后再通过治理关闭 legacy spend，而不是立即删除旧路径。
5. 一个结算可以包含不同 owner scheme 的输入，但每个输入必须携带自己的
   `SignatureEnvelope`，最终 payout/状态根只能由统一 `SettlementPlanDigest` 绑定。

推荐实施顺序：先完成 SNIP-12 `AuthorizeZChainKey`（不改变 v1 Note ABI），再完成
Stark owner Note 和迁移；这样可以先获得主流 Starknet 钱包的登录、Vault 和会话密钥
能力，避免一次性替换整个资产账本。

#### 6.12.2 钱包账户模型

钱包必须把两种账户分开显示和存储：

```text
ZChainAccount
  ├─ legacy secp256k1 owner，或 Starknet account binding
  ├─ ZChain versioned owner/address
  ├─ delegated/session key（可选，带 scope/limit/expiry）
  ├─ note commitments + spend secrets
  └─ P 层 Operation/Settlement/SNIP-12 authorization

VaultAccount
  ├─ Starknet account address
  ├─ Argent X/Braavos/Ledger 等外部 signer
  └─ Deposit、Withdrawal Claim、Vault 管理调用
```

legacy 模式和 Vault 账户默认不共享私钥，也不假设可从同一助记词安全推导。SNIP-12
账户绑定模式不导出 Starknet 私钥，只保存 account address、授权证明和本地会话密钥。
若未来支持 HD wallet，必须制定版本化路径和域分离，例如：

```text
ZChain owner:  zchain/<network>/<account>/note
Vault signer:  starknet/<network>/<account>
```

并通过独立测试向量、密钥轮换和迁移方案后再启用。ZChain owner 的地址格式、
chain id、signature domain、ABI version 和 network id 必须共同参与签名摘要，
防止跨网络重放。

#### 6.12.3 共享钱包核心 `wallet-core`

先实现 Rust `wallet-core`，再编译为 WASM 和移动/桌面原生库；浏览器扩展、Web
钱包、桌面应用和移动应用不得各自实现一套密码学和 Note 逻辑。

核心模块：

- `key_manager`：生成、派生、锁定、轮换和销毁 legacy secp256k1、Stark owner 或
  delegated/session key，并强制执行 scope、limit、expiry 和 revocation；
- `keystore`：Argon2id（或经审计的同等级 KDF）+ AEAD 加密，平台 Keychain/KeyStore
  包装，禁止明文私钥进入 localStorage、日志或遥测；
- `note_store`：加密保存 note、spend secret、Merkle proof、nullifier、创建帧和
  proof 状态，支持 REAL/PLAY 独立数据库；
- `operation_signer`：只接受结构化 Operation，重建并显示摘要后签名，拒绝任意
  `signBytes` 作为默认能力；
- `sync`：按 checkpoint、owner commitment 和索引同步，断点续传、幂等和重组检测；
- `verifier`：本地验证 Settlement/hand proof/SoftConfirmFrame，并显示 verifier
  版本、proof digest 和状态层级；
- `backup`：加密备份导出、恢复校验、版本迁移和备份完整性 MAC；
- `vault_adapter`：仅负责外部 Starknet wallet 的连接和 claim/deposit 请求，不持有
  Starknet 钱包私钥。
- `account_binding`：构造 SNIP-12 `AuthorizeZChainKey` / `RevokeZChainKey`，验证
  account signature、登记授权摘要并同步撤销状态；不得把合约账户简化为裸公钥。

#### 6.12.4 浏览器钱包插件计划

目标平台：Chromium Manifest V3、Firefox；Safari 作为后续适配。插件由三部分组成：

```text
Web page content bridge
        ↕ origin-bound message
Inpage provider (window.zchain)
        ↕ validated internal RPC
Extension background service worker
        ↕
wallet-core + encrypted vault
```

推荐接口（版本化 `zchain_*`，不冒充 EIP-1193）：

```text
zchain_requestAccounts()
zchain_getNetwork()
zchain_getCapabilities()
zchain_switchNetwork(network_id)
zchain_getAccounts()
zchain_signOperation(operation, preview_hash)
zchain_signSettlement(settlement_digest, preview)
zchain_authorizeSessionKey(request)
zchain_revokeSessionKey(binding_id)
zchain_getNotes(filter)
zchain_verifyProof(proof)
zchain_watchProof(binding)
zchain_lock()
```

插件必须支持：

- EIP-6963 风格的钱包发现只用于 EVM 外部钱包共存；ZChain provider 使用独立名称、
  icon 和 namespace，避免被 dapp 当成 MetaMask；
- 每个 origin 的权限、网络和账户选择单独保存；首次连接、换网、提现和批量签名二次确认；
- 签名前展示结构化内容：`chain_id`、`table_id`、`asset_class`、输入/输出金额、
  收款 owner、rake、hand binding、request id、proof 状态和过期时间；
- 会话密钥授权单独展示 delegated key、scope、单笔/每日限额、桌白名单、有效期和
  撤销方式；默认只勾选 PLAY 和低风险牌局操作；
- 站点消息必须带 request nonce、origin、expiry 和 session id，后台校验来源、
  replay、ABI/domain/version 和用户取消状态；
- CSP 禁止远程脚本和运行时下载代码；构建产物可复现、签名发布、权限清单最小化；
- 断网可查看和签署已缓存操作，但不能伪造 finalized 或 claimable 状态；
- 插件只向页面暴露公钥、地址、签名结果和脱敏状态，不暴露 spend secret、助记词或
  其他 note 的明文内容。

插件迭代：

| 版本 | 交付内容 |
|---|---|
| Extension 0.1 | PLAY、本地 keystore、ZChain provider、开桌/买入/结算签名、devnet |
| Extension 0.2 | testnet、多账户、REAL/PLAY 隔离、proof portal、备份恢复、网络切换 |
| Extension 0.3 | WalletConnect Vault adapter、提现预览、relay/ForceInclude 状态、SNIP-12 会话密钥授权 |
| Extension 0.4 | account binding registry、会话密钥撤销/过期、单笔/每日限额、Stark wallet capability matrix |
| Extension 1.0 | 第三方安全审查、可复现构建、硬件钱包适配（仅支持可读签名） |

#### 6.12.5 独立钱包应用计划

独立应用解决浏览器扩展不适合的密钥隔离、移动生物识别、硬件钱包和牌局通知场景。
推荐技术路线：`wallet-core` + Tauri（桌面）+ React Native/原生壳（移动），但密码学、
keystore、同步和 verifier 全部复用 Rust 核心。

MVP 功能：

- 创建/导入 ZChain Account，显示网络和 chain id；
- PLAY faucet、余额、note 列表、按 owner/桌/状态筛选；
- 开桌、买入、转账、结算和提现请求的逐字段签名确认；
- proof 验证、settlement explorer 跳转和 soft/BFT/proven/finalized 状态；
- 加密备份、二维码/深链、设备锁定、自动锁屏和离线恢复检查；
- REAL 充值跳转外部 Vault 钱包，避免在应用内重复实现 Starknet signer；
- 设备更换、旧设备撤销、可疑签名提醒和安全公告订阅。

后续功能：

- iOS Secure Enclave/Android Keystore 只作为加密 vault 包装或 recovery key；
- Ledger/Trezor 通过官方应用进行可读签名，禁止无法显示摘要的 blind signing；
- 多设备 watch-only、阈值恢复、社交恢复和企业托管策略；
- 本地牌局 proof 缓存和可选的隐私增强同步节点。

#### 6.12.6 恢复、轮换与丢失处理

自托管和托管恢复必须在 UI、协议和法律页面明确区分：

```text
自托管：丢失备份可能永久失去 note；客服不能替用户重建私钥。
托管模式：运营方可冻结账户并按公开恢复策略迁移未消费余额，必须有延迟、审计和用户通知。
```

密钥轮换不是修改 Note owner 字段，而是：

```text
旧 key 对 Transfer/KeyRotation 授权
→ 消费旧 note
→ 铸造新 owner note
→ 等待 proof/finality
→ 延迟窗口后撤销旧 key
```

任何“客服找回余额”流程都必须落成可验证的账本操作；不得通过后台数据库直接
改余额、重置 nullifier 或重新铸造 REAL note。

#### 6.12.7 钱包安全与验收门槛

- **WALLET-ACC-1**：MetaMask/Rabby、Argent X/Braavos、WalletConnect 的兼容性测试
  明确验证“可用范围”和“拒绝范围”，不存在错误连接或错误签名提示。
- **WALLET-ACC-2**：相同 Operation 在 WASM、桌面和移动端生成完全相同的 digest、
  signature bytes 和 tx hash；不同 network/ABI/domain 必须不同；v2 typed-data 的
  钱包展示字段与 verifier 字段逐项相等。
- **WALLET-ACC-3**：恶意 dapp 不能通过任意 bytes、伪造 origin、过期 session、
  换链或字段溢出诱导签名；取消、超时和重放测试全部通过。
- **WALLET-ACC-3a**：Starknet account 对 `AuthorizeZChainKey` 的签名可由标准 account
  verifier 验证；会话密钥超 scope、超额度、过期或撤销后，ZChain admission 必须拒绝。
- **WALLET-ACC-4**：插件和独立应用不记录私钥、助记词、spend secret 或未脱敏 note；
  crash dump、日志、分析 SDK 和 clipboard 均通过敏感数据扫描。
- **WALLET-ACC-5**：加密备份在错误密码、篡改、旧版本和跨设备恢复时 fail-closed；
  恢复后 nullifier/commitment 索引与链上状态一致。
- **WALLET-ACC-6**：REAL 页面在 Vault/verifier/BFT 未就绪时隐藏 claim 操作并显示
  托管风险；PLAY 页面不能误显示 REAL 余额或充值地址。
- **WALLET-ACC-7**：硬件钱包、Passkey 和外部 Starknet 钱包能力按 capability 显示，
  不支持的曲线或签名格式必须在连接阶段拒绝。
- **WALLET-ACC-8**：钱包发布具备可复现构建、签名包、SBOM、权限清单、第三方审查报告
  和安全更新回滚策略。

在钱包插件和独立应用完成前，官网只能提供 watch-only explorer、PLAY 测试钱包或
明确标注的实验性签名器；不能让用户误以为任意主流钱包都能直接保护 ZChain REAL note。

---

## 附：与既有纪律的衔接

- 所有基准/回归测试：pinned nightly + `--release`，debug 证明测试一律排除
  （延续 `PERFORMANCE_FOLLOWUPS.md` 尾注）。
- AIR 改动延续 fail-closed 纪律与 mutation test 攻击矩阵。
- ABI 改动走 `poker-protocol-abi` 稳定字节 ABI 流程。
- 本文档为 v1 唯一范围基准（scope baseline），新需求先进"开放问题"再入范围。
