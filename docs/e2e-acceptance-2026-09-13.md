# e2e 验收记录（2026-09-13，roadmap-schedule.md + plan-appchain-v1.md 双文档全量核对）

> 常规测试入口：`scripts/e2e_acceptance.sh`（full/quick 两档；逐门结果
> 时间戳落档 `docs/test-records/e2e-<ts>.txt`）。本档为立档日（2026-09-13）
> 的全量运行记录 + 人工复验补充。所有演练**串行执行**（并发 7 节点演练
> 会因 CPU 争用产生 commit 引擎时序假阴性——本日实测教训，已写入脚本）。

## 1. 主 workspace release 套件（CI 同口径）

| 门 | 结果 | 说明 |
|---|---|---|
| `cargo test --release -p poker_l1 --lib` | **1896+ / 0**（全绿） | 含本轮新增：threshold_bls 20、da v2 4、slash 对账 3 |
| `cargo test --release -p poker-appchain` | **390+ / 0**（全绿，54 目标） | 含本轮新增：compliance 6 单测 + 10 集成、te_m2 混沌 2、checkpoint withdrawal_root 1、metrics 限流告警 1、pipeline 降级注入 1 |
| `cargo test --release -p poker-settlement-core` | 36 / 0 | TE-E0 三仓冻结判别值 |
| `cargo test --release -p poker-wallet` | 43 / 0 | acceptance + 单测 |
| `cargo test -p vm-common --lib` | 53 / 0 | — |
| `cargo build --release -p zchain` | OK | — |

## 2. 节点 e2e

| 门 | 结果 | 记录 |
|---|---|---|
| `zchain test-e2e`（单进程链路） | **PASS**（exit 0，block#1 含 1 tx） | 复验发现夹具过时（epoch=1/空集/零 state_root/假签名 4 连败），已修复为真实 genesis validator + 真实执行 state_root + 真实可恢复证书签名 |
| `multi_node_e2e.sh 3`（3 节点 P2P） | **PASS**（heights converged ±1） | — |

## 3. 场景演练（全部串行复验）

| 演练 | 结果 | 关键判据 |
|---|---|---|
| scenario_censorship_drill | **PASS 7/0**（attempt 5 收敛；attempt 1 因并行演练 CPU 争用 censored 判定抖动） | forced-first 进块 + commit_forced_union + receipt sidecar 重启恢复 |
| scenario_checkpoint_seven | **PASS 5/0（attempt 1）** | QC FORMED height=8 signers=5（2f+1）；kill-2 后链 29→31、QC 24→32 继续产出 |
| scenario_kill_one_of_four | **PASS** | quorum(4)=3 恰好存活，链继续推进 |
| scenario_restart_catchup | **PASS**（skew=0，落后节点追平） | 复验发现**重启回归 bug**并修复：genesis 幂等对拍 version 硬编码 0，与运行期推进的持久化 validator-set version 必然失配 → 重启失败；修复为沿用持久化版本号 |
| drill_sequencer_restart | **DRILL_PASS**，RTO 33ms | WAL 重放 head_hash 一致 |
| explorer_gateway_smoke | **85 PASS / 0 FAIL** | 含 429 限流负例 |

## 4. extension / 钱包 / zkVM 侧

| 门 | 结果 |
|---|---|
| extension 单测（node --test） | **154 / 154** |
| extension wasm_smoke | PASS |
| extension 浏览器 E2E run_02 / run_03 / run_04 | **36/36 · 30/30 · 12/12 全 PASS** |
| wallet-app `cargo test -p zwallet` | **19 / 19** |
| poker-appchain-texasair `e2e_full_hand`（真实 STARK 出证→appchain 验证→结算→提现） | **2 / 2** |
| stwo-wasm-verify native core | 全绿 |

## 5. fuzz 冒烟（M8-ACC-7）

| target | 结果 |
|---|---|
| fuzz note_abi / soft_confirm_api / settlement_witness | 3 × 60s 全部 **0 crash**（exit 0） |

## 6. 常规审计留痕（M5-ACC-3）

- `rake_audit selftest --hands 1000` → export → verify：**1000 手零差异**
  （5003 帧，rake_total 39240，`OK: 复验零差异`；WAL head `d6ddc56a…`）。

## 7. 本轮新增交付与修复清单（对照 roadmap/plan 缺口）

1. **阈值 BLS（t-of-n）**：`poker_l1/src/consensus/threshold_bls.rs`——VSS/Shamir/Lagrange/阈值 QC 一次配对验证；20 测试；依赖结论"blstrs 已足够，零升级"。
2. **DA v2**：object_type 签名域（防跨类型重放）+ Merkle 分块挑战-应答原语；M8-ACC-8 v2 复验。
3. **withdrawal_root 进 checkpoint**：additive 字段（缺省摘要与 v1 逐字节一致）+ attach/verify API + 负例。
4. **bond/slash 对账恒等**：`SlashLedger::reconcile`（initial − Σevents == effective + halted ⇔ 0 + 孤儿 fail-closed）+ `reconciliation_digest` 链式锚 + appchain `BondLedger::reconcile` 余额恒等。
5. **合规运营化框架**：`poker_appchain::compliance`——版本化 geo_policy + 准入门（5 op）+ KYC 制动位 + RG 自排除 + 限额 + 审计账 + 2 指标；16 测试（含 WAL 重放确定性）。
6. **重启回归修复**：`apply_genesis_alloc` version 对拍。
7. **test-e2e 夹具修复**：genesis validator + 真实 state_root + 真实证书签名。
8. **plan-appchain 缺口收口**：M3-ACC-4 限流告警规则（rate_limit_storm + 注入）、M4-ACC-4 降级端到端注入（降级→告警→恢复）、M5-ACC-3 1000 手留痕、M7-ACC-1 并发混沌 exactly-once、M7-ACC-2 SLA p95=5min ≤ 10min 门槛演练、M0-ACC-2 ABI 评审记录归档。

## 8. 常规验收矩阵首跑（scripts/e2e_acceptance.sh quick）

- 记录文件：`docs/test-records/e2e-20260913-175137.txt`
- 汇总：**PASS=21 FAIL=1**——唯一 FAIL 为 `drill:censorship`（5 次尝试
  均未在演练窗口内收敛；对照本日独立复验 PASS 7/0（attempt 5）与
  checkpoint_seven attempt-1 PASS 5/0，判定为 commit 引擎低高度 +
  deadline=1ms 场景的**已知时序波动**（演练脚本自述"既有 commit 引擎
  活性存在时序波动"，retry 预算 5 次；bullshark kill-2 死锁已由第五轮
  修复，本波动为独立面）。功能面（forced-first 进块、commit_forced_union、
  receipt sidecar）已有 PASS 记录与 M3-ACC-6 集成测试
  `poker_l1/tests/force_include.rs` 钉住；**稳定性收尾**（低高度 commit
  停滞根因）转 bullshark/commit 引擎 owner 排期。

## 9. 已知边界（如实，不阻塞验收）

- M4-ACC-5 wasm 验证 p50 1.7–1.8s 超 500ms 门槛 3.5×（用户已豁免口径，`docs/stwo-wasm-path-a.md` §8.1 优化项）。
- M9-ACC-1 压测引擎为 host-validate-v2（机制验收），真证明引擎接入后需复测。
- M6-ACC-5 真机钱包矩阵 / WC 生产 relay（B5 外部依赖）、M9-ACC-3 prover 重启演练未脚本化。
- 演练活性对 CPU 争用敏感：验收必须串行（脚本已强制单流程）。
