# poker-appchain v1 阻塞项与后续工作记录

> 纪律来源：用户指令"遇到阻塞项不要停，做记录，继续下一项"。
> 格式沿用 `PERFORMANCE_FOLLOWUPS.md` 的处置风格：每项标注状态与
> 解除条件。更新时间：2026-09-05。

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

## 当前阻塞项（不阻塞其余模块推进）

### B1. stwo 真引擎未接入证明管道
- 状态：**阻塞 M4-ACC-1/2 的真实数字**。管道机制（队列/并行/批次/降级/
  背压）已完成并用 `ValidationEngine`（host 关系校验）验收；`SettlementProver`
  trait 是接入 seam。
- 解除条件：实现 `SettlementProver` for stwo 引擎——把 `SettlementRecord`
  编译进 canonical AIR 的异构 trace（复用 `texas_canonical_air` 框架），
  归档证明进 `ProofBundle.payload`。
- 期间姿态：v1 = host attestation（与主仓库 Phase 1 一致），浏览器复验
  走 client-wasm（既有能力）。

### B2. pot 与牌局状态链的绑定缺 AIR 层
- 状态：结算关系接受**声明值** pot（P 层签名不覆盖它）。谎报 pot 的
  攻击形态已被 `acc5` 测试证明只能被费率关系拒绝"过度声明"，
  而"合谋低报 pot"在 host 层不可检。
- 解除条件：M2 完整版——settlement witness 携带本手的
  AdvanceRound/结算 receipts（或其聚合承诺），AIR 证明
  `pot == Σ街道累计下注`（canonical AIR 已有该算术关系，缺接线）。
- 缓解：合谋低报需要全体玩家 + operator 共谋，且只逃 rake 不偷钱。

### B3. 逐街流式证明实验（M0-ACC-1）未做
- 状态：需要 hand-bench 与 `texas_canonical_air` 的 street 级切分接线，
  独立工作量约一周。**不阻塞 v1 其余模块**（管道节奏可配置，
  退化为整手批处理）。
- 解除条件：`docs/plan-appchain-perf.md` 出具逐街 vs 整手对比表。

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
