# poker-appchain v1 阻塞项与后续工作记录

> 纪律来源：用户指令"遇到阻塞项不要停，做记录，继续下一项"。
> 格式沿用 `PERFORMANCE_FOLLOWUPS.md` 的处置风格：每项标注状态与
> 解除条件。更新时间：2026-09-12（v1.2.1 修订：P0-3 REAL 出证策略三层门
> + attestation v2.1 + §5.4 提现 finality 门槛落地；B2 收尾、B1 状态更新；
> 新增遗留项 rake 口径。同日 v1.2.2：B9 rake 口径统一落地，**B9 关闭**。
> 同日 v1.2.3：M4-ACC-1/2 性能基准落档 `docs/plan-appchain-perf.md`
> （双 PASS），B1 关闭；逐街 vs 整手实验落档（不通过 → v1 整手），
> B3 关闭）。

## 已解决（第二轮：审计修复 + 接入缝，2026-09-05）

- **[已修复][S1] 花费签名不绑定操作载荷**：`spend_digest` 升级 v2，新增
  `effect_digest`（`Operation::effect_digest`）——Transfer 绑定 outputs、
  BuyIn 绑定 (table, seat_owner)、Withdraw 绑定 request_id、Settle 绑定
  `settle_effect`（hand_binding/pot/inputs/outputs/rake.total，刻意不含
  policy_commitment——该字段由注册表冻结检查独立强制，acc5a 验证两层
  防线各司其职）。恶意 sequencer 拿授权改打给别人从此签名无效。
- **[已修复][C1] 幂等键/重放键在校验前插入**：`apply_deposit`/
  `apply_withdraw`/`apply_settle` 全部改为"先校验后变更"——校验失败的
  操作不再烧掉 deposit_id/request_id/hand_binding（此前合法修正版结算
  会被误判 SettlementReplay）。
- **[已修复][C3] attestation 无签名可伪造**：`ValidationEngine` v2——
  payload 由 attestor ed25519 签名（可归属、不可伪造），`verify` 独立
  复验签名。默认构造使用确定性开发密钥，生产必须 `new(key)` 注入。
- **[已落地][B1/B2 缝] `poker-appchain-texasair` 适配器 crate**：独立
  crate（自带 lockfile，因外部 poker_texas_air 携带同名不同源的
  poker_l1，无法共享依赖图）。`TexasAirEngine` prove = 归档解析 →
  table/终态承诺绑定检查 → **`verify_tagged_texas_proof` 完整 STARK
  验证**（poker_texas_air 手写约束 AIR 独立验证器）→ 结算关系校验 →
  attestor 签名（覆盖绑定 + 已验证终态承诺）。5 项负例回归全过
  （垃圾 STARK 字节/承诺不一致/桌不一致/缺绑定/坏签名）。
- **[决议] WAL 帧校验和不加**：replay 全量验证链签名（ed25519 over
  blake2s(frame)），任何位翻转/截断必然在签名或 borsh 解析处
  fail-closed——checksum 是冗余防御，决议不做（省每帧一次哈希）。

## 已解决（过程中发现并当场修复）

- **[已修复] 域编码丢位**：初版 `felt_from_bytes32` 用 `byte0 & 0x03` 掩码，
  而 starknet 域元素可达 2^251（byte0 ∈ {0x04..0x07}），哈希值往返后改变，
  Merkle 证明全错（13 叶用例暴露）。修复：32B 一律 hi/lo 双 felt 无损拆分；
  felt→bytes 走裸 `to_bytes_be`。回归测试 `felt::tests::felt_byte_roundtrip_lossless`
  锁定 0x04 区域。
- **[已修复] 守恒双计**：结算校验曾把 rake 输出 note 与 rake.total 各计一次。
  修复后：`Σinputs == Σpayouts + Σrake_notes`，rake.total 与费率函数的
  一致性由分账检查独立保证。
- **[已修复] sequencer seq 未推进**：帧序号/created_at_op 恒 0，
  proven 水位机制失效。修复：apply 成功路径末尾 `seq += 1`，
  帧序号捕获于 apply 前。

## 已解决（第三轮：P0-3 REAL 出证策略 + §5.4 finality，2026-09-12）

- **[已落地][P0-3] REAL 结算必须使用真实证明**：`real_policy` 模块
  （`RealSettlementPolicy`/`RealMode`，默认 = `StarkRequired` + 未钉 key →
  REAL 全拒，fail-closed）+ 三层门：① 引擎层 `ValidationEngine::prove` 对
  REAL 一律 `RealRequiresStarkProof`；② 管道提交层准入（模式/引擎能力
  `texas-air-*`/钉扎/`hand_proof`）；③ 批次层允许集 + attestor 钉扎复查
  （`VerifierKeyMismatch`），违反则 op 不标记已证明、水位不推进并计
  `real_settlement_rejected_total`。负例矩阵全过（REAL×ValidationEngine、
  REAL×texas-air×Disabled、REAL×钉扎不匹配、REAL 缺 hand_proof、PLAY 对照
  照常）。
- **[已落地][P0-3] attestation v2.1**：texas-air 适配器消息追加
  `pre_state_root` 与 `plan_digest`（域不变、payload 128B → 192B）——REAL
  结算 attestation 覆盖四要素（verifier key=签名者、引擎版本、pre/post
  状态根、已验证计划摘要）。正例仍走真实 stwo（`prove_canonical_tagged_batch`）。
- **[已落地][§5.4] vault 提现 finality 门槛**：`CustodyLedger`
  （`withdrawal_requires_finality` 默认 true）对 REAL note 提现要求来源 op
  已证明 **且** 批次根已记录（`LedgerState.note_origins` provenance +
  sequencer `record_batch_root`/`mark_proven_through_with_root` 证据；未满足
  → `WithdrawalNotFinalized` + `withdrawal_finality_rejected_total`）。
  PLAY 豁免；开关关闭为显式 opt-out（仅限非生产，文档标注）。
- **[已解决][B2 收尾] pot 与牌局状态链绑定**：v1.2 的
  `post_state_image_bytes` 镜像 pot 逐字节绑定（偏移 74）使"合谋低报 pot"
  从不可检变为**密码学不可行**（状态镜像被 Fiat--Shamir 范围绑定 + 端点
  投影约束 + STARK 全约束复核）。B2 关闭。
  ⚠️ 已知语义缺口（**如实记录，不粉饰**；**已于同日 v1.2.2 关闭，见 B9**）：
  rake 口径未统一——
  `poker_l1` canonical rake 只对 contested 层计费（contested-only），而
  appchain 费率关系 `rake.total == policy.rake_of(plan.gross_pot)` 按
  **全额 gross pot** 计费。含 uncalled 返还层的计划（plan.rake <
  policy.rake_of(gross_pot)）会被 fail-closed 拒绝（ABI.md §4 第 8 条注记）；
  归档含 rake opening 的"sole-survivor 有抽水"终局同样拒绝。此类手暂不能
  走 appchain 结算，需后续在 policy 或 plan 侧统一口径（见"当前阻塞项"
  B9）。

## 当前阻塞项（不阻塞其余模块推进）

### B9. rake 口径统一：contested-only vs 全额 gross pot（**已关闭，2026-09-12，v1.2.2**）
- 状态：**关闭**。采用 plan 侧建模，把口径差异变成显式数据：
  `poker-settlement-core` 的 `SettlementPlan` 新增派生方法
  `rake_base() -> u64` = Σ **contested 层**（`is_contested()`：eligible ≥ 2
  座）的 `gross_amount`；uncontested 层（uncalled 返还）显式不参与计费。
  appchain `validate_settlement` 费率关系改为
  **`rake.total == plan.rake == policy.rake_of(plan.rake_base())`**
  （ABI v1.2.2），与 poker_l1 canonical（`derive_settlement_plan` 只对
  contested gross 取费）语义唯一对齐。
- 不变量保持（此前被拒的手仍拒，绝不放行错误手）：
  - `plan.gross_pot == record.pot == Σinputs == 镜像 pot@74`（第 3/4/11 条
    不变，gross 全额仍全额守恒）；
  - `plan.validate` 强制 **uncontested 层 rake == 0**（core 侧原有约束，
    本次补单测钉住）→ "跨层挪 rake 到 uncalled 层"整体封死（负例回归）；
  - `plan.rake == rake.total`、分账/收款人绑定（第 10 条）不变；
  - 低报 rake：整体自洽重签后仍被 `rake.total(21) != rake_of(rake_base
    450)=22` 拒（负例回归）。
- 残余边界（不放宽）：归档 rake opening（批级 raked 终局）计费基数是终态
  全池 pot，与 contested-only 在"含 uncalled 层的 raked 终局"上仍基数不同
  → 此类组合维持 fail-closed 拒绝（ABI.md §4 注记）。
- 测试证据（真实执行，全绿）：
  - `cargo test -p poker-settlement-core -p poker-appchain --release`：
    core 29 + appchain lib 63 + attacks 14 + finality 4 + proptests 3 +
    settlement_flow 4（含新增 `uncalled_return_layer_hand_settles_with_
    contested_only_rake` 正例 + 2 负例），0 failed；
  - `cargo test -p poker_l1 --release --test texas_poker_unit`：243 passed /
    0 failed（uncalled 层/multiway RIT 测试新增 `rake_base()` 锚点断言）；
  - `cd poker-appchain-texasair && cargo test --release`：adapter 12 +
    e2e 2（含新增 `uncalled_return_layer_hand_settles_end_to_end`），
    0 failed。
- 行为变化边界：仅"此前被误拒的合法手（含 uncalled 返还层）现在可结算"。

### B1. stwo 真引擎：已接线并有真实 stwo 正例（**已关闭，2026-09-12**）
- 状态：**关闭**。`poker-appchain-texasair` 的 `TexasAirEngine` 实现
  `SettlementProver`：验证 poker_texas_air 手写约束 AIR 的批次归档
  （`verify_canonical_tagged_proof`，poker_vm 路线搁置后的正式证明路线），
  绑定终态承诺/pre-post 状态根/计划摘要后出 attestation v2.1；REAL 出证受
  `real_policy` 三层门约束。管道机制（队列/并行/批次/降级）不变，换引擎
  即换 `Arc<dyn SettlementProver>`。真实 stwo 正例端到端由适配器测试覆盖
  （`canonical_stark_proof_end_to_end_admits_and_deep_tamper_rejected` 与
  `real_settlement_stark_required_end_to_end_with_real_stwo`）。
- 性能数字（M4-ACC-1/2，2026-09-12 落档，关闭 B1 尾）：基准源码
  `poker-appchain-texasair/tests/perf_baseline.rs`（`#[ignore]`，不拖慢
  默认套件），数字与判定全部落档 zchain `docs/plan-appchain-perf.md`：
  - **M4-ACC-1 PASS**：手结束→证明可验证就绪 777.4 ms p95（n=20，
    prove p50 515.2 + verify p50 196.6；Apple M3 Pro 12 核 /
    nightly-2026-04-15 / stwo 2.3.0），≤ 3s 门槛余量 3.9×，回归断言
    已写死（3s 主门槛 + 30s 退路上限双保险）；
  - **M4-ACC-2 PASS**：1/4/16/64 桌并发单位手成本增长 1.00/0.56/0.56/
    0.52（≤ 线性+15%），64 档（12 核 5.3× 超订）无超线性劣化，聚合
    吞吐 ~1.9× 饱和（单证明已内部 rayon 并行的机制解释自洽）。
- 期间姿态（不变）：PLAY = host attestation（`ValidationEngine` v2 签名
  形态）；REAL = 必须 texas-air STARK 引擎（P0-3，默认 StarkRequired）。

### B2. pot 与牌局状态链的绑定（**已关闭，2026-09-12**）
- 状态：**关闭**。v1.2 三重收敛 + 镜像 pot 逐字节绑定全部落地——① pot 在
  `settle_effect` 签名内（篡改需重签）；② `hand_proof.post_state_commitment`
  把结算绑到已验证的手牌终态承诺（跨手混装不可行）；③ 费率关系
  `rake.total == rate_of(pot)` 独立强制；④（收尾）`post_state_image_bytes`
  中 `pot` 字段（偏移 74，8B LE）与 `record.pot` 逐字节绑定——状态镜像被
  Fiat--Shamir 范围绑定 + STARK 端点投影约束，"合谋低报 pot"已不可行。
- 遗留（非绑定问题）：rake 口径缺口见 B9（**已关闭，2026-09-12 v1.2.2**）。

### B3. 逐街流式证明实验（M0-ACC-1）（**已关闭，2026-09-12：不通过 → v1 整手**）
- 状态：**关闭**。实验落档 zchain `docs/plan-appchain-perf.md` §4/§5
  （DR-1）：同一手 witness 序列按 k=1/2/5 切段独立 prove
  （`tests/perf_baseline.rs::m0_acc_1_street_split_vs_whole_hand`，
  段间 `pre/post_state_commitment` + 状态根链连续断言全过——管道支持
  任意切分的**机制**成立），但经济学不成立：tagged batch trace 域下限
  log_size 8（256 行，`trace_gen/generic_trace.rs::MIN_LOG_SIZE`）使
  单证明成本与批内行数解耦（1/4/5 行批次单段 prove p50 均 ~510-525ms），
  切分不降低首证明就绪（×1.01–1.03），总 prove/verify/字节 ×k
  （k=2：×2.04；k=5：×5.05），5 段并发的"流式上界"亦因 12 核争用
  首就绪劣化 ×3.10。
- 决策：v1 定型**整手批处理**（现管道形态）；M4-ACC-1 实测 0.78s p95
  达标，**不触发** ≤30s 放宽，门槛保持 3s。重访条件（行数比例化域 /
  outer_aggregate 跨批聚合 / TODO #22 多街续链后行数进入 log 9/10）
  已在 DR-1 记录。

### B8. 仓库外依赖漂移（zchain 侧）——**已解决（2026-09-12，方式=vendor）**
- 状态：**关闭**。poker_l1 的 4 处编译错误（zgame poker_protocol 从未有过
  V3 API——git 历史证实漂移方向判断有误，真实来源是 poker_texas_air 的
  poker-protocol-proofs）已通过内联解决：`reconstruction_v3/`（V3 家族 +
  Bayer-Groth 后端，来源 poker_texas_air/poker-protocol-proofs 与
  poker-protocol-bg，wire 行为兼容）+ import 重定向到 zgame 类型世界。
  `cargo build -p poker_l1` 0 error；`cargo test -p poker_l1 --release`
  2350 passed / 0 failed。
- 长期建议维持：跨仓库 API 漂移优先 vendor + 行为等价测试钉住，而非追上游。

### B4. fuzz 目标未建（M8-ACC-7 部分）——**已关闭（2026-09-12）**
- 状态：**关闭**。`fuzz/`（cargo-fuzz 0.13.2 传统布局，独立 workspace，
  不并入主 workspace）新建三个 target，全部走 `poker_appchain` 公开 API，
  `arbitrary` 结构化输入 + 原始字节 borsh 解码双路径，约定 panic 即失败：
  - `note_abi`：Note/NoteSpec borsh 解码 + 承诺/nullifier 计算 + 往返
    承诺一致。`cargo fuzz run note_abi -- -max_total_time=60` →
    **Done 112080 runs in 61 second(s)，0 crash**。
  - `soft_confirm_api`：SoftConfirmFrame/SignedFrame/Operation 解码 +
    `verify_chain` + `Sequencer::submit` 提交 API 全部在线拒绝路径。
    → **Done 69865 runs in 61 second(s)，0 crash**。
  - `settlement_witness`：SettlementRecord 解码 + `validate_settlement`
    （默认 Zero 策略）+ `settlement_binding`/`payout_root`/
    `settle_effect` 摘要。→ **Done 70745 runs in 61 second(s)，0 crash**。
  - 环境：nightly + asan（asan 构建正常，未降级 `--sanitizer none`）。
  - 如实记录（不粉饰）：fuzz 首轮在 **fuzz 侧结构化构造器** 撞出 2 个
    crash——`flat_settlement_plan` 的文档化调用方前置条件
    （Σawards ≤ gross_pot；`settlement.rs` `gross_pot - total_awards`
    在 debug-assertions 下减法下溢 panic；`awards.iter().sum()` 溢出），
    非校验层缺陷（生产 release 下该差值回绕后仍会被 validate_settlement
    的费率/守恒关系 fail-closed 拒绝）。target 构造侧已按前置条件约束
    （awards ∈ [0, pot]），两个 crash 输入复跑均通过。
  - 覆盖路径与用法见 `fuzz/README.md`。

### B5. 账本二级索引——**已关闭（2026-09-12）**
- 状态：**关闭**。`LedgerState.owner_index: HashMap<[u8;33],
  HashSet<[u8;32]>>`（owner 压缩公钥 → live note 承诺集）落地于
  `src/sequencer.rs`：
  - 维护点：铸造/消费全部路径都经 `mint_note`/`consume_note` 原语同步
    维护（deposit、buy-in seat、transfer 输出、settle payout、settle
    rake note 铸入即登记；withdraw/transfer/buyin/settle 消费即移除，
    空集删键）。消费段与 `notes.remove` 同步推进，投毒双花（同
    nullifier）导致的消费段部分失败下索引仍与账本一致。WAL 重放复用
    同一 `apply_op` 路径自然重建（`replay_roundtrip_with_wal` 回归：
    重放后 `balances_of` 走索引正确）。
  - O(1) 查询接口：`commitments_of` / `notes_of` / `note_entries_of`，
    `balances_of` 重写为索引路径。调用点替换清单：loadtest 的
    `find_proven_note` 与桌内 seat note 收集（原全账本 O(n) 扫描，
    压测脚本主因）、`tests/common::find_note`。`client_view` 为客户端
    自持凭证聚合，不触账本扫描（无需替换）。
  - 纯性能结构：不入状态根，验证语义零改动。
  - 正确性 proptest：`tests/proptests.rs::owner_index_matches_full_scan`
    （64 cases × 至多 48 步随机序列，deposit/buyin/settle/transfer/
    withdraw + 投毒同 nullifier 双花），每步后断言索引 == 全量扫描
    （精确相等、空集删键）、REAL/PLAY 余额分开统计等价、notes_of ==
    扫描集。release 全绿。
  - loadtest 前后（默认参数 64 桌 × 50 手 × 2 玩家，`--release`）：
    **41.98s → 41.70s（持平）**。扫描替换后默认参数下墙钟由证明管道
    等待与每笔提交的 `root()` 全桌折叠主导，owner 扫描非当前瓶颈
    （大账本/多玩家下扫描替换收益随账本规模线性放大）。

### B6. texas 游戏服务器接线（M3 尾项）（**已关闭，2026-09-12**）
- 状态：**关闭**。texas 游戏服务器（poker_texas_air 工作区 `texas/` crate）
  结算出口改接嵌入式 appchain sequencer，遗留 Starknet 路径保留可配。
- 落点（新增 `texas/src/starknet/appchain/` 模块）：
  - `runtime.rs`：进程单例装配——`Sequencer`（WAL 追加 + 启动时
    `Sequencer::replay` fail-closed 恢复）+ `ProofPipeline`
    （`RealSettlementPolicy::stark_required` 钉扎本进程 attestor）+
    `CustodyLedger`（finality 门开）+ provider；`SOFT_CONFIRM` 软确认
    socket.io 事件（载荷 `{frame_index, state_root_hex, watermark, level}`，
    level ∈ soft/proven；沿 texas SCREAMING 事件命名）。
  - `prover.rs`：进程内 `SettlementProver`（引擎名 `texas-air-v2`）——
    与 `poker-appchain-texasair::TexasAirEngine` 同语义的本地实例（那边是
    外部第三方接缝；这边是游戏服务器内置——texas 已依赖 poker_texas_air，
    再引适配器 crate 会把 poker_texas_air 拉成两份 lockfile 实例，故本地
    重实现）。prove = 归档绑定检查（table/终态承诺/前后状态根）→
    **`verify_canonical_tagged_proof` 完整 STARK 验证** →
    `validate_settlement`（含镜像 pot@74 绑定）→ attestation v2.1
    （域 `poker-appchain.texas-air-v2`，payload 192B 布局一致）；
    无 hand_proof 的 PLAY 记录走 host attestation 档（64B 签名，REAL 在
    该档 fail-closed 拒绝）；`with_verifier_key` 钉扎。
  - `exit.rs`：`SettlementExit::{Appchain(默认), Starknet}` 出口路由
    （hooks 在终局对账通过后、legacy prove 之前先走 Appchain 出口，任何
    失败回退遗留路径，两条证明栈不重复执行）；镜像 pre-payout 快照 →
    `poker_settlement_core::derive_settlement_plan` 派生 plan
    （`plan.gross_pot == 镜像 pot`、`plan.rake == 游戏层 rake_collected`
    口径对账）→ 账本事实补齐（OpenTable/Deposit/BuyIn/Transfer 拆 seat）
    → `SettlementRecord`（payouts 按 plan 投影规范序 + rake 分账 +
    settle_effect 签名）→ sequencer 软确认 → pipeline 出证 →
    `mark_proven_through_with_root`（水位 + §5.4 批次根）。
  - `keys.rs`：确定性托管密钥派生（v1 内嵌运营方托管模型，与 legacy 路径
    的 operator 信任面一致；客户端持钥是 v2 升级项，文档如实记录）。
- 配置：`STARKNET_SETTLEMENT_EXIT`（`appchain` 默认 dev / `starknet`
  遗留）；`TEXAS_APPCHAIN`（=0 关闭运行时）、`TEXAS_APPCHAIN_WAL_DIR`、
  `TEXAS_APPCHAIN_SEQUENCER_SEED`、`TEXAS_APPCHAIN_ATTESTOR_SEED`、
  `TEXAS_APPCHAIN_ASSET`（play 默认/real）、`TEXAS_APPCHAIN_TREASURY_BPS`、
  `TEXAS_APPCHAIN_PROVIDER`（mock/starknet）、`TEXAS_APPCHAIN_POLL_MS`、
  `TEXAS_APPCHAIN_RECONCILE_SECS`、`TEXAS_APPCHAIN_PROVE_TIMEOUT_SECS`。
- 测试证据（真实执行，`cargo test -p texas --release --bin texas`，含真实
  stwo 出证：`prove_canonical_tagged_batch` 5 行 canonical 批 + prover 内
  独立验证器全量复核）：场景 a–d 全绿（deposit 桥幂等 / REAL 手 Appchain
  出口 proven + 水位 + 批次根 + SOFT_CONFIRM 载荷 / 提现 finality 闭环 /
  对账差异告警），见 `scenario_tests.rs`；prover 单测（PLAY host 档 +
  REAL 引擎层门 + 钉扎负例）、bridge 单测（幂等键四元组敏感 / mock 打款
  回冲 / 游标增量）全绿。
- 残余边界（如实记录）：① REAL 手的 canonical 归档**生产者**未接线——
  实时镜像产出的是 legacy ProveTask 链，canonical witness 归档目前仅在
  测试夹具构造；hooks 的 Appchain 出口对无归档的 REAL 手显式回退遗留
  路径（fail-closed，不放宽）。② fold-win/早街结束的手不支持 Appchain
  出口（settlement-core 无 derive_fold_win_plan 同源函数，不在出口层
  重实现第二套结算语义），回退遗留路径。③ 客户端 P 层密钥协议未接——
  v1 为服务器托管派生密钥（见 keys.rs 信任模型）。

### B7. M7 出入金的链上侧（**已关闭，2026-09-12**）
- 状态：**关闭**。texas 侧事件桥 + 打款执行 + 自动对账接入嵌入式
  sequencer/托管账（`texas/src/starknet/appchain/bridge.rs`）。
- 落点：
  - `VaultProvider` trait（存款事件拉取 / `pay_withdrawal` 打款 /
    `reserve_snapshot` 储备快照）+ `MockVaultProvider`（devnet 默认，
    测试全用 mock）+ `StarknetVaultProvider`（生产：`starknet_getEvents`
    拉 vault `Deposit` 事件（事件键可配 `STARKNET_VAULT_DEPOSIT_EVENT_KEY`，
    默认按 poker_vault.cairo 全路径 selector）、operator ERC20 `transfer`
    打款（`STARKNET_TOKEN_ADDRESS`）、`balance_of` 储备快照）。
  - 存款桥：`DepositEvent` → `deposit_id = blake2s(source_chain, vault,
    tx_hash, event_index)` 幂等（sequencer `deposit_ids` + custody
    `confirm_deposit` 双层）→ `Operation::Deposit` 铸 REAL note（面额 =
    STRK wei 1:1）→ 处理游标推进。
  - 提现执行：`CustodyLedger::queued_requests()`（本批纯增量公开 API）
    轮询 → `pay_withdrawal` → `mark_paid`；有界重试
    （`MAX_PAY_ATTEMPTS=5`，超限 `withdrawal_pay_exhausted_total` 告警）。
    §5.4 finality 门在入队侧强制（水位 + 批次根，`request_withdrawal`
    为链下入口形态）。
  - 自动对账（周期 `TEXAS_APPCHAIN_RECONCILE_SECS`，默认 300s）：
    Σ已发 REAL note（存续 + 已销毁）vs 储备（链上快照 + 打款回冲）；
    差异 → `tracing::error` + `reconciliation_mismatch_total` 计数 +
    `reconciliation_delta` 告警规则（M7-ACC-4 形态）；
    `ReconciliationSnapshot` serde 可导出（含存续 note 清单，预对齐
    v2 STARK 储备证明输入）。
  - 装配：`appchain::runtime::init`（main.rs 启动流程）拉起三循环
    （存款桥+提现执行同周期 / 对账独立周期）。
- zchain 侧改动：仅 `vault.rs` 纯增量公开 API
  `CustodyLedger::queued_requests()`（打款执行器轮询用）；
  `cargo test -p poker-appchain --release` 全绿（lib 63 + attacks 14 +
  finality 4 + proptests 3 + settlement_flow 4）。
- 测试证据（真实执行）：场景 a（deposit 事件 → REAL note，重复事件
  只铸一次）、c（proven → 烧毁 → finality 放行 → mock pay → mark_paid →
  队列清空）、d（零差异 + mock 储备少记注入 → 告警计数触发）随
  `scenario_tests.rs` 全绿。
- 残余边界：真实 Starknet 事件桥（`starknet_getEvents` 分页续传、事件键
  按部署校准）需要线上环境验证，当前为 best-effort 实现并在文档标注；
  测试覆盖全部走 mock（纪律要求）。

## 处置结论（v1 内不做，理由落档）

- **Block-STM / 乐观并发**：不实施。桌与桌 note 集合构造性无冲突，
  单 sequencer 串行 + nullifier 查重即满足（plan §M3 论证成立）。
- **L1 锚定 / 等价性罚没**：推迟 v2（Hyperliquid 同款分期）。v1 落地了
  检查点导出格式（软确认链本身）与 watcher 分叉检测，锚定合约是
  v2 的事。
- **STARK 储备证明**：推迟 v2。`CustodyLedger` 报表结构已预对齐
  （note 集 + 储备数字可导出）。
