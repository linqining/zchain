# Checklist — 扩展游戏协议：多玩家并行提交阶段

> **change-id**：`extend-game-multiplayer-phases`
> **验证依据**：spec.md / tasks.md

## Phase 1: 类型与状态扩展

- [x] `GamePhase` 枚举定义包含 `Betting { round }` 与 `MultiPlayerSubmit { kind }` 两个变体
- [x] `SubmitPhaseKind` 枚举包含 `Shuffle` / `RevealToken` / `Reconstruct` / `LeaveProof` 四个变体
- [x] 两个枚举派生 `Serialize`/`Deserialize`/`Debug`/`Clone`/`PartialEq`/`Eq`/`Copy`（若可行）
- [x] `GameStatus` 新增 `phase` / `pending_submitters` / `phase_started_height` / `completed_submitters` 四个字段
- [x] 新字段有合理默认值，既有 `GameStatus::new()` 与测试无需修改即可通过
- [x] 阶段切换时 `pending_submitters` 与 `completed_submitters` 正确重置

## Phase 2: TurnRule trait 扩展

- [x] `TurnRule` trait 新增 `current_submitters()` / `is_submission_complete()` / `advance_phase()` 三个方法
- [x] `PhaseTransitionError` 错误类型定义（含 `PendingSubmittersNotEmpty` / `InvalidPhaseTransition`）
- [x] `SimpleTurnRule` 实现三个新方法，下注阶段行为正确（`current_submitters` 返回空集合）
- [x] `TexasHoldemTurnRule` 实现完整 4 种 SubmitPhaseKind 的提交者集合计算
- [x] `TexasHoldemTurnRule::advance_phase()` 状态机正确：
  - Shuffle → RevealToken（若有牌待揭）/ Betting（若无）
  - RevealToken → Betting
  - Reconstruct → Shuffle（重新洗牌）/ Betting（继续）
- [x] `current_turn()` 在 `MultiPlayerSubmit` 阶段返回 `None`
- [x] `current_submitters()` 在 `Betting` 阶段返回空集合

## Phase 3: GameTurn tx 校验逻辑

- [x] `validate_game_turn()` 函数按 `game.phase` 分支校验
- [x] `Betting` 分支保持原 `current_turn_player` 匹配逻辑（向后兼容）
- [x] `MultiPlayerSubmit` 分支校验提交者在 `pending_submitters` 中
- [x] `LeaveProof` 特殊分支校验提交者在 `active_participants` 中（不要求在 pending_submitters）
- [x] 成功提交后 `pending_submitters` 移除该玩家，`completed_submitters` 插入
- [x] `NotYourTurn` 错误新增 `phase: GamePhase` 字段
- [x] 新增 `NotEligibleSubmitter` 错误类型（含 phase / pending / actor 字段）
- [x] 既有 `NotYourTurn` 测试用例已更新添加 phase 字段

## Phase 4: 阶段超时与惩罚

- [x] `TimeConsensusConfig` 新增 `shuffle_timeout_blocks` / `reveal_token_timeout_blocks` / `reconstruct_timeout_blocks` 字段
- [x] 默认值：Shuffle=100, RevealToken=50, Reconstruct=100
- [x] `is_submit_phase_timed_out()` 函数正确判定超时（LeaveProof 不超时）
- [x] `handle_submit_phase_timeout()` 执行 kick + 退款 + 移除 active_participants
- [x] 剩余 `active_participants < 2` 时触发 `end_without_showdown`
- [x] 超时玩家从 `pending_submitters` 与 `completed_submitters` 同时移除

## Phase 5: vertex 排序与共识集成

- [x] `build_game_sub_block()` 按 `game.phase` 选择排序键
- [x] `Betting` 阶段保持 `(current_turn 优先, arrival)` 排序（既有行为不变）
- [x] `MultiPlayerSubmit` 阶段按 `(phase_kind, arrival)` 排序
- [x] SEC-H6 force_advance 抢跑防护扩展覆盖 `MultiPlayerSubmit` 阶段
- [x] 前一 commit 内有 GameTurn tx 时，多玩家阶段的 force_advance 被拒绝

## Phase 6: 集成测试与文档

- [x] 完整一手牌流程测试通过：Betting → Shuffle → RevealToken → Betting → ... → Showdown
- [x] 多玩家阶段超时恢复测试通过
- [x] LeaveProof 随时提交测试通过（下注阶段 + 多玩家阶段）
- [x] 跨 commit 排序测试通过
- [x] `docs/37-1-node-deployment.md` 更新阶段超时配置说明
- [x] `docs/37-6-dag-consensus-ops.md` 更新多玩家阶段运维说明
- [x] `docs/37-8-game-phase-protocol.md` 新建完整阶段状态机文档

## 向后兼容性验证

- [x] 既有 Phase 1-7 所有测试（49 个端到端测试）仍通过
- [x] 既有 `SimpleTurnRule` 行为不变（下注阶段）
- [x] 既有 `GameStatus` 序列化向后兼容（新字段有默认值，旧数据可反序列化）
- [x] 既有 `NotYourTurn` 错误的下游消费者（vertex_production / rpc）编译通过

## 安全性验证

- [x] 多玩家阶段无法绕过提交者校验（非 active_participants 无法提交）
- [x] 阶段切换原子性（pending_submitters 清空与 phase 更新在同一 tx 内）
- [x] 超时惩罚不可被攻击者利用踢出诚实玩家（需 block height 单调性保证）
- [x] LeaveProof 提交后玩家状态一致性（active_participants / pending_submitters / total_bet 同步更新）
- [x] 跨 commit force_advance 防护在多玩家阶段不被绕过
