# poker-appchain 运维手册（runbook）v1

适用范围：v1 单 sequencer + 内存证明管道 + 托管出入金形态（`poker-appchain`
crate，详见 `docs/plan-appchain-v1.md`）。

**诚实声明（先读）**

- v1 是**单运营方**架构：sequencer / prover 停机即全场停摆。本手册是 v1 的
  主要运维缓解手段，不是分布式高可用方案。
- 所有 RTO/RPO 数字凡未标注"实测"者均为**目标值（待实测校准）**。文中的
  实测样本来自开发机单次演练（数据量小），**不构成生产基线**。
- BFT checkpoint、claimable、链内密钥轮换等能力属 v1.5 / Phase 2，**尚未
  上线**；相关段落只描述现状，不描述承诺。
- 手册中引用的函数/指标名与仓库代码一一对应（`poker-appchain/src/`），
  升级代码时同步核对本手册。

---

## 1. Sequencer 重启

### 1.1 数据目录布局与持久化语义

v1 的 sequencer **没有快照**，软确认链是完整历史，持久化只有一个文件：

```text
<data-dir>/
└── appchain.wal        # 追加式 WAL：u32 LE 帧长 || borsh(SignedFrame)，逐条
```

- 每帧 = 一个已应用操作 + 应用后账本状态根 + sequencer ed25519 签名
  （`soft_confirm.rs::SignedFrame`）。
- 写入顺序（P0-4 原子提交）：克隆态试算 → 帧签名 → WAL append + fsync
  （**承诺点**）→ 内存态换入。fsync 默认开启；崩溃窗口内最多丢"未过承诺
  点"的软确认，已过承诺点的帧必然可重放（RPO 目标 = 0 已承诺帧）。
- **证明水位 / 批次根不入 WAL**：重启后保守归零，由证明管道对已验证批次
  重新回调恢复（`sequencer.rs::replay` 文档注释）。重放期间
  `admission_proven_only` 单项被覆盖放宽（否则任何含买入的 WAL 都无法恢
  复），重放完成后恢复原配置，重启后的**新**提交仍受完整准入约束。

### 1.2 重启流程（WAL replay）

重启 = 用**同一数据目录、同一 sequencer 公钥**重放 WAL：

```rust
// poker_appchain::sequencer::Sequencer::replay
let seq = Sequencer::replay(
    &wal_path,              // <data-dir>/appchain.wal
    &sequencer_public,      // [u8; 32] ed25519 公钥（创世参数，64 hex）
    SequencerConfig::default(), // 生产配置
    metrics_registry,
)?;
```

重放是 fail-closed 全量重验（`sequencer.rs::replay` → `soft_confirm::
verify_chain`）：

1. 链完整性：index 严格 +1、prev_hash 接续（`ChainBroken`）；
2. 每帧 ed25519 验签（`BadFrameSignature`）；
3. 逐帧重新应用操作并比对帧内状态根（`WalCorrupted("state root divergence
   on replay")`——通常是软件版本/ABI 与 WAL 不一致）；
4. WAL 物理损坏（截断帧 / 非法长度 / 坏编码）→ `WalCorrupted`。

重放成功后：

```text
seq.head_hash()   // 必须与重启前记录的链头哈希一致
seq.state().root()// 与最后帧 state_root 一致（重放内部已比对）
```

随后 `attach_wal`（追加模式）恢复写入。**禁止**用新公钥对着旧 WAL 重放
（必然 `BadFrameSignature`）；密钥更换走 §5 停机轮换流程。

### 1.3 验签失败 / 重放失败处置

| 错误 | 可能原因 | 处置 |
|---|---|---|
| `BadFrameSignature` | 公钥配置错（不是创世公钥）；WAL 被篡改 | 先核对公钥配置；公钥无误则视为安全事件：隔离现场、留档 WAL，按披露流程上报 |
| `ChainBroken` | WAL 尾部截断（半帧）；手工拼接/删帧 | 半帧 = 崩溃窗口残留，去掉不完整尾帧前先备份原文件；中间断链 = 篡改，按安全事件处理，**禁止跳帧续链** |
| `state root divergence` | 重放二进制版本与出帧版本不一致 | 核对 git commit / ABI 版本，用与 WAL 同版本的二进制重放；确认版本后再升级 |
| `WalCorrupted("truncated frame" / "frame length insane")` | 磁盘/文件系统损坏 | 从归档副本恢复（§1.5 归档纪律），损坏文件留证 |

### 1.4 RTO：目标与实测方法

- **目标值（待实测校准）**：sequencer 重启 RTO ≤ 5 分钟（含进程拉起 + 全量
  重放 + 水位恢复）。注意重放是 O(链长)：WAL 越长重启越慢，v1 无快照截断
  机制——这是已知限制，链长逼近 RTO 目标前需要评估 checkpoint 方案（路线
  图 v1.5）。
- **实测方法**：`scripts/drill_sequencer_restart.sh`（M9-ACC-3 演练证据）。
  它完成"生成 WAL → 记录重启前 head hash → 重新 replay → 比对 head hash
  → 打印 RTO → PASS/FAIL"。

开发机单次演练样本（2026-09-12，17 帧 demo WAL，**非生产基线**）：

```text
HEAD_before = 1dd74ac97eb2459f0563ca0c01924bab31e4f5b7bce50539c434db658124a87b
HEAD_after  = 1dd74ac97eb2459f0563ca0c01924bab31e4f5b7bce50539c434db658124a87b
RTO(replay+export) = 26 ms  [目标值（待实测校准）；计时含审计 JSON 写出，为 RTO 上界]
DRILL_PASS: sequencer restart (WAL replay) head_hash 一致性 + RTO 见上
```

### 1.5 演练步骤（sequencer 重启）

1. 预备：`cargo build --release -p poker-appchain --bin rake_audit`。
2. 执行 `scripts/drill_sequencer_restart.sh`。
3. **预期输出**：四步日志（生成 WAL → 重放导出 → 双通道哈希比对 → verify
   零差异）+ `DRILL_PASS`；RTO 一行同时打印。
4. 记录本次 RTO 到值班日志；连续两次演练 RTO 差异 > 2× 时排查环境（磁盘、
   负载）后再下结论。
5. 附加检查（可选）：对同目录 `audit.json` 执行
   `rake_audit verify --audit audit.json`，退出码 0 = 导出可独立复验。

### 1.6 归档纪律

- WAL 是唯一事实源：生产环境至少异地保留一份**带 head hash 清单**的副本
  （每日 + 停机前各一次）。
- 归档条目：WAL 文件、字节数、帧数、`head_hash`、sequencer 公钥、归档时间。
  恢复演练时按此清单核对（head hash 不一致 = 副本损坏）。

---

## 2. Prover 重启与积压处置

### 2.1 组件与语义

证明管道 = `pipeline.rs::ProofPipeline`：worker 池（rayon 并行 prove）+
有界队列（背压）+ 批次聚合。关键语义：

- **连续前缀组批**：批次只从最早的未批次化任务起收集连续已完成前缀，遇
  缺口（失败/未完成）即停——水位**绝不越过未证明操作**；
- prove 失败/panic 带尝试计数回队有界重试（`MAX_PROVE_RETRIES = 3`），超限
  后**留在队列**并计 `prove_retry_exhausted_total`，绝不丢弃；
- 批次验证通过 → `on_batch_proven(through_op)` 回调 → 生产装配点接
  `Sequencer::mark_proven_through` 推进水位。

### 2.2 观测与健康接口

| 接口 | 用途 |
|---|---|
| `pipeline.health() -> HealthInputs` | 采集 `proof_queue_depth`（inflight）与 `proof_degraded`，供告警评估 |
| `pipeline.alerts() -> Vec<Alert>` | 当前触发的告警（`metrics::evaluate_alerts` 规则） |
| `pipeline.degraded() -> bool` | inflight 超过 `high_watermark` → 积压降级档 |
| `pipeline.drain_completions() -> usize` | 收割已完成 bundle（非阻塞），返回本轮收割数 |
| `pipeline.completed_count()` / `inflight_count()` | 完成数 / 在途数 |

配套指标（`MetricsRegistry`）：`prove_us`（单次 prove 耗时直方图）、
`proof_ready_ms`（任务入队→证明完成，M9-ACC-4）、`proof_queue_depth`（gauge）、
`proof_submitted_total` / `prove_failed_total` / `prove_panicked_total` /
`prove_retry_exhausted_total` / `batch_total` / `batch_verify_failed_total`。

### 2.3 降档判据

- `pipeline.degraded() == true`（inflight > `high_watermark`，默认 3_000）
  → 进入降级档：降低新结算提交速率、优先 REAL 桌（管道按 `Priority::Real >
  Play` 调度）、必要时按预案扩 worker / batch_size 后重启管道；
- `alerts()` 出现 `proof_queue_overflow`（见 2.4）→ **停止接受新证明任务**，
  先清积压再恢复；
- `prove_retry_exhausted_total` 增长 → 存在毒任务（结构性失败，不是瞬态），
  单独排查该结算记录，不要靠重启清零。

### 2.4 告警规则对照表（`metrics::evaluate_alerts` 全部 5 条）

| 规则 | 级别 | 触发条件 | 确认命令 | 处置动作 |
|---|---|---|---|---|
| `proof_backlog_degraded` | Warn | `proof_degraded`（inflight > high_watermark） | `pipeline.degraded()`；gauge `proof_queue_depth` | 降档（2.3）；观察 `completed_count` 是否持续增长；持续增长则只限流不重启 |
| `proof_queue_overflow` | Critical | `proof_queue_depth > 10_000` | `pipeline.inflight_count()` | 停新任务提交；确认 worker 存活（`prove_panicked_total` 是否跳变）；必要时扩容后重启管道；恢复后确认连续前缀组批恢复推进水位 |
| `reconciliation_delta` | Critical | 托管对账差异 ≠ 0 | `vault.health(issued).reconciliation_delta` / 日终 `CustodyLedger::reconciliation` | **资金相关，最高优先**：冻结提现打款，逐笔核对 issued（链上存续+已销毁）与外部储备；差异未解释前不恢复 |
| `withdrawal_backlog` | Warn | 提现队列深度 > 1_000 | `vault.queued_withdrawals()`；`vault.queued_requests()` 快照 | 按 §3 排查 finality 门槛与打款执行侧；确认是积压（打款慢）还是卡死（门槛不过） |
| `soft_confirm_idle` | Warn | 软确认链空闲 > 30_000 ms | 最近帧 `ts_ms`；sequencer 进程活性 | 检查 sequencer 是否停写（§1）；是业务静默（无对局）还是链停摆——静默属正常，停摆走 §1 |

每条规则的注入触发验证见 M9-ACC-2（`metrics.rs` 单元测试 `alerts_fire_on_inputs`
与 vault/pipeline 相关用例）。

### 2.5 Prover 重启

- 管道是内存态（pending 队列、inflight、重试计数都在内存）：**重启丢弃
  未完成的证明任务**。这些任务对应的结算仍在上（WAL 已承诺），重启装配层
  必须从链上"未证明的 Settle"重新构造 `ProofJob` 重新提交——这是装配层
  （server）职责，v1 内置二进制不代办。处置时先确认这一点再动手。
- 水位/批次根恢复：重启后 sequencer 侧水位归零，由管道对已验证批次重新
  回调 `mark_proven_through` 恢复（不需要、也**不应该**手工改水位）。
- 重启后确认（积压清空判据，三条同时满足）：
  1. `proof_queue_depth` gauge 归 0；
  2. `completed_count` 停止增长且 `drain_completions()` 返回 0；
  3. `try_build_batch()` 连续前缀组批成功，`proven_watermark` 追平
     `ops_total`（无缺口）。

### 2.6 演练步骤（prover 积压）

1. 用 `bin/loadtest`（大 `--tables`）灌入任务直到 `pipeline.degraded() ==
   true`（**预期输出**：`proof_queue_depth` 超过 high_watermark，`alerts()`
   含 `proof_backlog_degraded`）。
2. 停止灌入，观察 `completed_count` 单调增长至 `submit` 总数。
3. `try_build_batch()` 反复调用直到返回 `None`（**预期输出**：水位追平，
   `alerts()` 清空）。
4. 记录"降档→清空"耗时；该数字同样标注**目标值（待实测校准）**，生产门槛
   待压测（M9-ACC-1）校准后回填本手册。

---

## 3. 提现故障

### 3.1 队列与状态

提现两段式：链上 `WithdrawRequest`（销毁 note，软确认即承诺）→ 托管侧打款
（`CustodyLedger`）。托管侧条目只有 `Queued → Paid` 两态；排查入口：

```rust
vault.queued_withdrawals()            // 排队笔数
vault.queued_requests()               // 排队请求快照（request_id/收款地址/金额）
vault.mark_paid(request_id, tx_hash)  // 打款回执登记
```

### 3.2 Finality 门槛（REAL note）

v1 fail-closed 门槛（`vault.rs::enqueue_withdrawal`）：REAL 类提现要求
**同时**满足（`FinalityEvidence::covers(op_index)`）：

1. `proven_watermark >= 来源 op_index`（来源 op 已证明）；
2. `batch_covered_through >= 来源 op_index`（该 op 所属批次根已记录）。

未满足 → `WithdrawalNotFinalized` 并计 `withdrawal_finality_rejected_total`。
PLAY note 豁免（软确认即可提，§5.1 分层）。幂等命中（已受理的同 id 同载荷
申请）不重复过门。

来源 op 定位：`sequencer.withdrawal_provenance(&note)`（note 承诺 → 铸出
op；消费后仍保留，WAL 重放重建）。

### 3.3 门槛未达时的处置

1. 读 `sequencer.finality_evidence()`：比较 `proven_watermark` /
   `batch_covered_through` 与卡住提现的 `source_op_index`。
2. 水位停住 → 证明管道有缺口：按 §2.5 查 `prove_retry_exhausted_total` 与
   连续前缀缺口；缺口清除后水位自动推进，提现自动可受理。
3. 水位已过但批次根未记录 → 装配层批次回调（`mark_proven_through_with_root`）
   未接线或重启后未恢复——修复接线，不要绕过门槛。
4. 门槛本身不可放宽：`without_finality_gate` 是显式非生产构造（docs/ABI.md
   §9），生产禁止。
5. 排除上述后仍拒绝 → `withdrawal_finality_rejected_total` 增长但证据齐备，
   收集 request_id / op_index / 证据截图报研发。

### 3.4 SLA 计时规则

- 计时起点 = 该提现 `WithdrawRequest` 软确认帧入链（note 销毁）时刻（帧
  `ts_ms`）；终点 = 托管侧 `mark_paid` 登记时刻。
- v1 现状（如实标注）：**代码内未实现自动 SLA 计时器**。当前唯一自动护栏
  是 `withdrawal_backlog` 告警（队列 > 1_000 笔，Warn）。值班按对账周期
  （日终）人工核对排队时长；SLA 分档与自动计时属后续交付，未上线前不得对
  外承诺提现时限。

### 3.5 演练步骤（提现 finality）

1. 构造一笔 REAL note 提现，在水位未覆盖其来源 op 时提交入队（**预期输
   出**：`WithdrawalNotFinalized`，`withdrawal_finality_rejected_total` +1，
   对应 `vault.rs` 测试 `withdrawal_finality_gate_real_note` 的负例 A/B）。
2. 推进水位 + 批次根回调后重新申请（**预期输出**：入队成功，状态 `Queued`）。
3. `mark_paid` 登记打款（**预期输出**：`queued_withdrawals()` 减 1；重复
   `mark_paid` 被拒 `already paid`）。

---

## 4. 工具页

### 4.1 rake_audit（rake 独立审计导出与复验）——已交付（v1）

```text
rake_audit export  --appchain-wal <path> --sequencer-public <64hex>
                   --from-ts <ms> --to-ts <ms> [--table-id N] --out <file.json>
rake_audit verify  --audit <file.json>
rake_audit selftest --dir <dir>
```

- `export`：全量重放 WAL（验签 + 状态根重验）后导出 `zchain.rake_audit.v1`
  JSON：头部（`wal_head_hash`、帧范围、策略承诺清单、Σrake）+ 每条结算明细
  （frame_index / ts_ms / table_id / hand_binding / 每层 pot
  {gross_amount, contested, eligible_seats} / rake_base / rake.total /
  rate_bps·cap·treasury_bps（来源注明 `ledger_fee_registry`）/ 分账输出 /
  守恒数字）。
- `verify`：**独立代码路径**复验——重算 rake_base（只计 contested 层 gross）、
  期望 rake `min(floor(base×rate/10⁴), cap)`、分账 `floor(rake×treasury_bps/10⁴)`
  、守恒与汇总一致性、hand_binding 非零。退出码：**0 = 零差异 / 1 = 差异 /
  2 = 输入错误**；差异逐条打印。
- `selftest`：生成 demo WAL（3 手：标准 5% 手、含 uncalled 返还层的手、
  ZERO 桌手），供演练与测试。
- **独立性现状（如实标注）**：verify 与链内校验器（`validate_settlement` /
  `fee.rs`）不共享代码，但同处一个仓库、由同一方维护。M5-ACC-3 的最终形态
  是"外部工具（独立仓库/独立代码路径）复验"——当前同仓独立路径是 v1 步骤，
  **不能据此宣称已达成第三方审计独立性**。

### 4.2 explorer_gateway（只读实时网关）——已交付（v1）

只读 JSON 网关（路线图 E1）：从 appchain WAL 全量重放构建视图（验签 +
逐帧状态根重验，fail-closed），运行期**无任何写路径**。

```text
explorer_gateway --appchain-wal <path> --sequencer-public <64hex>
                 [--proven-log <path>] [--l1-rpc <http://host:port>]
                 [--listen 127.0.0.1:8900] [--snapshot-out <dir>]
                 [--snapshot-interval-secs N] [--public]
```

- 只读 GET 路由：`/api/v1/status`、`/api/v1/frames`、
  `/api/v1/settlements`（支持 `table_id` 过滤/分页）、
  `/api/v1/settlement/<binding_hex>`、`/api/v1/batch_roots`、
  `/api/v1/metrics`，以及可选 L1 代理 `/api/v1/l1/{metrics,block,tx}`；
  未知路径 404、非 GET 405、坏参数 400。
- v1.2.3 追加只读端点（ABI v1.2.3 §13）：`/api/v1/proofs?offset=&limit=`
  （proof 归档元数据分页）、`/api/v1/proof/<binding_hex>`（归档下载，
  响应头 `X-Zchain-Engine`，未命中 404/坏 hex 400）、
  `/api/v1/aggregates`（M4 outer aggregate 聚合记录列表）；
  `/api/v1/settlement/<binding_hex>` 响应追加 `payout_root` 与 `proof`
  链接字段；`/api/v1/status` 追加 `latest_aggregate_root` /
  `latest_aggregate_through_op`（无则 null）。
- v1.2.3 追加启动参数：`--proof-registry <path>`（proof 归档注册表，
  `proof_registry.jsonl` 冻结契约）与 `--aggregate-log <path>`
  （聚合记录，`aggregate.log` 冻结契约）；二者均可选，损坏时网关
  fail-closed 拒绝启动（撕裂尾行忽略 + 告警）。
- 运维纪律：**默认只绑回环**，非回环监听必须显式 `--public`（启动时打印
  "非生产配置"警告）；每 IP 令牌桶限流（10 req/s、突发 20），超限 429。
- 故障处置：启动即退出非零 = WAL 重放失败——按 §1.3 的错误表处置后重启
  网关；网关自身无状态，重启 RTO 即重放时长（O(链长)，同 §1.4 注意事项）。

### 4.3 watcher（独立进程，三者一致性）

`appchain_watcher` 是独立进程，不信任任何单一来源：独立重算并交叉核对
软确认链完整性（验签 + prev_hash 链接 + 状态根重放）、结算语义（按表策略
逐条 `validate_settlement`）、proven log 一致性（按窗口重算批次根）、
checkpoint 对拍，以及双链分叉检测。

独立部署启动（与 sequencer 分机运行）：

```bash
appchain_watcher --appchain-wal <path> --sequencer-public <64hex> \
  [--proven-log <path>] [--aggregate-log <path>] [--checkpoint <path>] [--wal-b <path>] \
  [--follow-interval-secs N] [--json-out <path>]
```

- 退出码：`0` 一致 / `1` 发现不一致 / `2` 用法错误。
- findings 类别：`chain_integrity`（帧链损坏）、`proven_log_root_mismatch`
  （批次根重算不符）、`proven_log_range`（水位越界/非递增）、
  `checkpoint_mismatch`、`fork_detected`（双链分歧帧位）。
- v1.2.3 追加：`--aggregate-log <path>`（可选）——校验 `index` 连续、
  `through_op` 单调且 ≤ 链头（`aggregate_range`），并从 proven log 取窗口
  内批次根独立重算 `aggregate_roots` 比对聚合根；不符 → finding
  `aggregate_mismatch`（exit 1；缺 `--proven-log` 基准时同样 fail-closed）。
- 策略不可得的结算记 WARN 并明确列出，不算失败（诚实边界）。
- `--follow-interval-secs N` 常驻轮询；`--json-out` 供告警管道消费。
- 部署纪律：只读访问 WAL 与 proven log 副本；建议不同机/不同账户运行，
  发现 `fork_detected`/`chain_integrity` 即按 §2 积压/停机预案升级处置。

---

## 5. 密钥轮换（sequencer 签名密钥）——v1 停机轮换流程

**边界（如实标注）**：链内轮换语义（帧链中途更换签名密钥、新旧密钥交叠验
证）属 **v1.5**；v1 的 `verify_chain` 只接受单一固定公钥。因此当前唯一
安全路径是**停机轮换**：旧链封存，新链用新公钥从零开始，两段链的衔接由
轮换清单人工核对。本节是 M8"密钥轮换流程"的 v1 交付形态。

### 5.1 流程（停机窗口内执行）

1. **停写**：关闭入口（游戏服务器/充值通道），确认最近帧 `ts_ms` 静默，
   `ops_total` 不再增长。
2. **封存快照**：记录旧链四元组——
   `{旧公钥(64hex), head_hash, 帧数(state.seq), 终态状态根}`；
   用 `Sequencer::export_chain()` 导出全链，或直接归档 WAL 文件（§1.6 清单）。
3. **生成新密钥**：新 ed25519 seed（生产走随机源），并经 **KeyProvider**
   通道注入新 sequencer 实例（`poker_appchain::key_provider`）：配置
   `ZCHAIN_KEY_PROVIDER=env` + `ZCHAIN_SEQUENCER_KEY_HEX=<64hex>`（或
   `file`：密钥文件 + Unix 权限校验 / `remote`：KMS 端点接缝）。取钥
   失败一律 fail-closed 拒绝启动，**无默认种子回退**；`from_seed` 仅限
   测试工具。得新公钥；旧私钥即刻停用并按密钥管理制度销毁/归档。
4. **新 key 起新 WAL**：新 sequencer（新 key）挂**新** WAL 文件，从 index 0
   开始新软确认链；旧目录只读保留。
5. **轮换清单**（离线文档 + 旧 key 签名声明，模板见 5.3）：v1 链内没有
   轮换操作，"旧 key 认可交接"只能作为**链外声明**存在——用旧 sequencer
   私钥对清单（旧 pub ‖ 新 pub ‖ 交接时间 ‖ 旧链 head_hash）签名留档，
   供审计核对。签名用 `seq_key_rotate generate`：旧钥经 `--old-key-file`
   或 `--provider <env|file|remote>`（KeyProvider 同源通道，fail-closed）
   提供，二者互斥、无默认。声明本身不上链，效力来自随后的锚定/披露
   流程，不能更多。
6. **归档旧 WAL**：按 §1.6 归档纪律留存；新链监控指标、告警阈值同步切换。
7. **回退预案**：新链未产生业务帧前，可直接弃用新 WAL 回到旧链（旧目录未
   动）；新链已承接业务后回退 = 再做一次反向轮换，按同一流程执行。

### 5.2 演练步骤（轮换）

1. 用 `rake_audit selftest --dir <tmp>` 生成旧链，记录其
   `SEQUENCER_PUBLIC` / `WAL_HEAD_HASH`（**预期输出**：三行机器可读字段）。
2. 按上节完成新 key 新 WAL 起链，提交一笔 Deposit（**预期输出**：新链
   `head_hash` 变化，新链帧验签用新公钥通过；旧公钥对新链帧验签**必须失
   败**——这是轮换生效的判据）。
3. 填写轮换清单并用旧 key 签名声明，归档旧 WAL（**预期输出**：清单字段
   齐全、签名可验、归档 head hash 与第 1 步一致）。

### 5.3 轮换清单模板

| 字段 | 值 |
|---|---|
| 旧 sequencer 公钥（64 hex） | |
| 旧链 head_hash（64 hex） | |
| 旧链帧数（state.seq） | |
| 旧链终态状态根（64 hex） | |
| 新 sequencer 公钥（64 hex） | |
| 新链首帧时间 / 起 chain 时间 | |
| 交接时刻（UTC） | |
| 旧 key 签名（对上表规范化字节，64B hex） | |
| 操作人 / 复核人 | |

---

## 6. 开发者环境前置（Developer environment prerequisites）

- **poker_protocol 必须以同级目录形式检出**：根 `Cargo.toml` 的
  `poker_protocol` 是 path 依赖 `../zgame/poker_protocol`（独立仓库
  https://github.com/linqining/poker_protocol ）。本仓库检出后需执行：

  ```bash
  git clone --depth 1 https://github.com/linqining/poker_protocol ../zgame/poker_protocol
  ```

  缺少该目录时，任何 `cargo build` / `cargo test` 都会在依赖解析阶段
  直接失败（不是编译错误，不要按代码问题排查）。
- **CI 自动克隆**：`.github/workflows/ci.yml` 中所有运行 cargo 的 job
  已在 cargo 步骤前克隆该仓库到 `$GITHUB_WORKSPACE/../zgame/poker_protocol`
  （见各 job 的 `checkout poker_protocol (path dependency)` 步骤）。

---

## 附：与其他验收项的对应

| 手册章节 | 对应验收项 | 现状 |
|---|---|---|
| §1 sequencer 重启 + 演练脚本 | M9-ACC-3（演练 + RTO） | 演练脚本已交付；RTO 为目标值（待实测校准），开发机样本 30 ms |
| §2 prover/积压 + §2.4 告警表 | M9-ACC-2（告警注入验证） | 规则实现与注入测试在 `metrics.rs` |
| §3 提现故障 | §5.4 finality 门 | 已交付（`vault.rs`），SLA 自动计时未实现 |
| §4.1 rake_audit | M5-ACC-3（v1 步骤） | 同仓独立代码路径已交付；独立仓库形态未达成，见 §4.1 声明 |
| §5 密钥轮换 | M8 密钥轮换流程（v1 形态） | 停机轮换已文档化；链内轮换属 v1.5 |
| 四延迟报告 | M9-ACC-4 | `MetricsRegistry::latency_report()`；`bin/loadtest` 报告含该 JSON；bft/claimable 未上线输出 null |
