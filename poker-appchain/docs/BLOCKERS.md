# poker-appchain v1 阻塞项与后续工作记录

> 纪律来源：用户指令"遇到阻塞项不要停，做记录，继续下一项"。
> 格式沿用 `PERFORMANCE_FOLLOWUPS.md` 的处置风格：每项标注状态与
> 解除条件。更新时间：2026-09-12（v1.2.1 修订：P0-3 REAL 出证策略三层门
> + attestation v2.1 + §5.4 提现 finality 门槛落地；B2 收尾、B1 状态更新；
> 新增遗留项 rake 口径）。

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
  ⚠️ 已知语义缺口（**如实记录，不粉饰**）：rake 口径未统一——
  `poker_l1` canonical rake 只对 contested 层计费（contested-only），而
  appchain 费率关系 `rake.total == policy.rake_of(plan.gross_pot)` 按
  **全额 gross pot** 计费。含 uncalled 返还层的计划（plan.rake <
  policy.rake_of(gross_pot)）会被 fail-closed 拒绝（ABI.md §4 第 8 条注记）；
  归档含 rake opening 的"sole-survivor 有抽水"终局同样拒绝。此类手暂不能
  走 appchain 结算，需后续在 policy 或 plan 侧统一口径（见"当前阻塞项"
  B9）。

## 当前阻塞项（不阻塞其余模块推进）

### B9（新增遗留）. rake 口径统一：contested-only vs 全额 gross pot
- 状态：**已知语义缺口，未修**。appchain 结算关系要求
  `plan.rake == policy.rake_of(plan.gross_pot)`（全额口径），而 poker_l1
  canonical 语义是 contested-only 计费。两条口径在含 uncalled 返还层/
  sole-survivor 抽水的手上一致性不成立，当前行为是 fail-closed 拒绝
  （不产生错误结算，但该类手无法结算）。
- 解除条件：在 policy 侧引入 contested-only 费率档，或 plan 侧将
  uncalled 返还显式建模为非计费层；两侧口径一致后补正负例回归。
- 期间姿态：维持 fail-closed 拒绝（宁拒不错）。

### B1. stwo 真引擎：已接线并有真实 stwo 正例，剩余为性能数字
- 状态：**已接线（2026-09-12 更新）**。`poker-appchain-texasair` 的
  `TexasAirEngine` 实现 `SettlementProver`：验证 poker_texas_air 手写约束
  AIR 的批次归档（`verify_canonical_tagged_proof`，poker_vm 路线搁置后的
  正式证明路线），绑定终态承诺/pre-post 状态根/计划摘要后出 attestation
  v2.1；REAL 出证受 `real_policy` 三层门约束（见上）。管道机制（队列/并行/
  批次/降级）不变，换引擎即换 `Arc<dyn SettlementProver>`。
- 剩余：**性能数字**（M4-ACC-1/2）——适配器测试已含真实 stwo 正例端到端
  （`canonical_stark_proof_end_to_end_admits_and_deep_tamper_rejected` 与
  `real_settlement_stark_required_end_to_end_with_real_stwo`，B1 ①已解除），
  但更长批次/逐街切分的吞吐与延迟基准未落档。
- 解除条件：基准落档 `plan-appchain-perf.md`。
- 期间姿态：PLAY = host attestation（`ValidationEngine` v2 签名形态）；
  REAL = 必须 texas-air STARK 引擎（P0-3，默认 StarkRequired）。

### B2. pot 与牌局状态链的绑定（**已关闭，2026-09-12**）
- 状态：**关闭**。v1.2 三重收敛 + 镜像 pot 逐字节绑定全部落地——① pot 在
  `settle_effect` 签名内（篡改需重签）；② `hand_proof.post_state_commitment`
  把结算绑到已验证的手牌终态承诺（跨手混装不可行）；③ 费率关系
  `rake.total == rate_of(pot)` 独立强制；④（收尾）`post_state_image_bytes`
  中 `pot` 字段（偏移 74，8B LE）与 `record.pot` 逐字节绑定——状态镜像被
  Fiat--Shamir 范围绑定 + STARK 端点投影约束，"合谋低报 pot"已不可行。
- 遗留（非绑定问题）：rake 口径缺口见 B9。

### B3. 逐街流式证明实验（M0-ACC-1）未做
- 状态：需要 hand-bench 与 `texas_canonical_air` 的 street 级切分接线，
  独立工作量约一周。**不阻塞 v1 其余模块**（管道节奏可配置，
  退化为整手批处理）。
- 解除条件：`docs/plan-appchain-perf.md` 出具逐街 vs 整手对比表。

### B8. 仓库外依赖漂移（zchain 侧，2026-09-05 实证）
- 状态：`poker_protocol = { path = "../zgame/poker_protocol" }` 的
  reconstruction API 已变化，`poker_l1` 当前 4 处编译错误
  （dispatch.rs/state_machine.rs/utils.rs 的 ReconstructProofV3 等导入）。
  属用户并行改动（zgame 或 poker_l1 任一侧 WIP），本 crate 审核不修。
- 解除条件：pin zgame 修订或同步 poker_l1 调用点；长期应 vendor。

### B4. fuzz 目标未建（M8-ACC-7 部分）
- 状态：主 workspace `fuzz/` 已从本 crate 的成员列表排除；攻击回归以
  集成测试 + 属性测试覆盖（tests/attacks.rs, proptest 计划中）。
- 解除条件：在 `fuzz/` 增加 `soft_confirm_api`、`note_abi`、
  `settlement_witness` 三个 target。

### B5. 账本二级索引
- 状态：loadtest 显示按 owner 线性扫账本在大账本下成为瓶颈
  （64 桌压测 34s 墙钟的主因是压测脚本 O(n) 查找）。
- 解除条件：`LedgerState` 增加 `owner_index: HashMap<[u8;33], HashSet<承诺>>`
  并同步维护；补 idx 正确性 proptest。

### B6. texas 游戏服务器接线（M3 尾项）
- 状态：sequencer 以库形式就绪；`texas/` 的结算出口仍走旧的
  Starknet 提交路径，未切换到 sequencer submit。
- 解除条件：`texas/src/starknet/settlement_prover.rs` 改接
  `poker_appchain::sequencer`，socket.io 软确认事件对齐。

### B7. M7 出入金的链上侧
- 状态：`CustodyLedger` 对账/幂等已完成；Starknet 收款监听与打款
  执行（`texas/src/starknet/chips.rs` 复用）未接线。
- 解除条件：deposit/withdraw 事件桥 + 自动对账定时任务。

## 处置结论（v1 内不做，理由落档）

- **Block-STM / 乐观并发**：不实施。桌与桌 note 集合构造性无冲突，
  单 sequencer 串行 + nullifier 查重即满足（plan §M3 论证成立）。
- **L1 锚定 / 等价性罚没**：推迟 v2（Hyperliquid 同款分期）。v1 落地了
  检查点导出格式（软确认链本身）与 watcher 分叉检测，锚定合约是
  v2 的事。
- **STARK 储备证明**：推迟 v2。`CustodyLedger` 报表结构已预对齐
  （note 集 + 储备数字可导出）。
