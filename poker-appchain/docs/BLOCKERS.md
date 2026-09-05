# poker-appchain v1 阻塞项与后续工作记录

> 纪律来源：用户指令"遇到阻塞项不要停，做记录，继续下一项"。
> 格式沿用 `PERFORMANCE_FOLLOWUPS.md` 的处置风格：每项标注状态与
> 解除条件。更新时间：2026-09-05（v1.1 修订：S1/C1/C3 修复落地、
> texasair 适配器 crate 接入缝成立、poker_vm 路线搁置转手写约束 AIR）。

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

## 当前阻塞项（不阻塞其余模块推进）

### B1. stwo 真引擎：适配器已落地，剩余为"真实归档端到端"
- 状态：**缝已成立**。`poker-appchain-texasair` 的 `TexasAirEngine` 实现
  `SettlementProver`：验证 poker_texas_air 手写约束 AIR 的批次归档
  （`verify_tagged_texas_proof`，poker_vm 路线搁置后的正式证明路线），
  绑定终态承诺后出 attestation。管道机制（队列/并行/批次/降级）不变，
  换引擎即换 `Arc<dyn SettlementProver>`。
- 剩余：① 用 proving-tool 产出的**真实归档**跑一次正例端到端
  （当前 5 项测试均为负例/密码学路径）；② 性能数字（M4-ACC-1/2）。
- 解除条件：真实归档正例测试 + 基准落档 `plan-appchain-perf.md`。
- 期间姿态：v1 = host attestation（`ValidationEngine` v2 签名形态）。

### B2. pot 与牌局状态链的绑定（v1.1 后剩余尾巴）
- 状态：v1.1 三重收敛——① pot 在 `settle_effect` 签名内（篡改需重签，
  acc5b 验证合谋重签仍被费率关系拒绝）；② `hand_proof.post_state_commitment`
  把结算绑到**已验证的手牌终态承诺**（TexasAirEngine 强制，跨手混装
  不可行）；③ 费率关系 `rake.total == rate_of(pot)` 独立强制。
- 剩余尾巴：终态承诺 → pot 数值的逐字节绑定（状态镜像哈希复算或
  poker_texas_air 公开范围暴露 pot）。届时"合谋低报 pot"从
  不可检变为密码学不可行。

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
