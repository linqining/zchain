# Tasks — 扩展游戏协议：多玩家并行提交阶段

> **change-id**：`extend-game-multiplayer-phases`
> **依赖**：`build-poker-l1-chain`（spec.md FROZEN）— 本任务列表为 v2 backlog 增量
> **参考**：[texas_poker_move/sources/table.move](../../../zgame/texas_poker_move/sources/table.move) L1702-L2209

## Phase 1: 类型与状态扩展（无破坏性，向后兼容）

- [x] Task 1: 新增 `GamePhase` 与 `SubmitPhaseKind` 枚举
  - [x] SubTask 1.1: 在 `poker_l1/src/consensus/routing.rs` 定义 `GamePhase` 枚举（`Betting { round: BettingRound }` / `MultiPlayerSubmit { kind: SubmitPhaseKind }`）
  - [x] SubTask 1.2: 定义 `SubmitPhaseKind` 枚举（`Shuffle` / `RevealToken` / `Reconstruct` / `LeaveProof`）
  - [x] SubTask 1.3: 实现 `Serialize`/`Deserialize`/`Debug`/`Clone`/`PartialEq`/`Eq` 派生
  - [x] SubTask 1.4: 编写单元测试：枚举序列化往返、phase 转换合法性

- [x] Task 2: 扩展 `GameStatus` 结构体
  - [x] SubTask 2.1: 新增字段 `phase: GamePhase`（默认 `Betting { round: Preflop }`）
  - [x] SubTask 2.2: 新增字段 `pending_submitters: BTreeSet<Address>`（默认空）
  - [x] SubTask 2.3: 新增字段 `phase_started_height: BlockHeight`（默认 0）
  - [x] SubTask 2.4: 新增字段 `completed_submitters: BTreeSet<Address>`（默认空）
  - [x] SubTask 2.5: 更新 `GameStatus::new()` / 测试辅助函数，保证既有测试通过（向后兼容默认值）
  - [x] SubTask 2.6: 编写单元测试：新字段默认值、阶段切换时字段重置

## Phase 2: TurnRule trait 扩展

- [x] Task 3: 扩展 `TurnRule` trait 新增三个方法
  - [x] SubTask 3.1: 新增 `current_submitters(&self, game: &GameStatus) -> BTreeSet<Address>`（下注阶段返回空集合）
  - [x] SubTask 3.2: 新增 `is_submission_complete(&self, game: &GameStatus) -> bool`（下注阶段返回 true）
  - [x] SubTask 3.3: 新增 `advance_phase(&self, game: &mut GameStatus) -> Result<GamePhase, PhaseTransitionError>`
  - [x] SubTask 3.4: 定义 `PhaseTransitionError` 错误类型（`PendingSubmittersNotEmpty` / `InvalidPhaseTransition`）
  - [x] SubTask 3.5: 为 `SimpleTurnRule` 实现三个新方法（下注阶段行为）
  - [x] SubTask 3.6: 编写单元测试：下注阶段三方法行为、错误路径

- [x] Task 4: 新增 `TexasHoldemTurnRule` 实现完整扑克轮转
  - [x] SubTask 4.1: 创建 `poker_l1/src/consensus/texas_holdem_turn_rule.rs`
  - [x] SubTask 4.2: 实现 `current_turn()`（下注阶段按 button 顺序轮转）
  - [x] SubTask 4.3: 实现 `current_submitters()`：Shuffle 返回 active_participants；RevealToken 返回密钥持有者；Reconstruct 返回 active_participants；LeaveProof 返回 active_participants
  - [x] SubTask 4.4: 实现 `is_submission_complete()`：`pending_submitters.is_empty()`
  - [x] SubTask 4.5: 实现 `advance_phase()`：Shuffle→RevealToken→Betting / Reconstruct→Shuffle-or-Betting 状态机
  - [x] SubTask 4.6: 实现 `advance_turn()`（下注阶段推进）
  - [x] SubTask 4.7: 编写单元测试：4 种阶段切换、提交者集合计算、完成判定

## Phase 3: GameTurn tx 校验逻辑扩展

- [x] Task 5: 修改 validator 校验逻辑
  - [x] SubTask 5.1: 在 `poker_l1/src/consensus/routing.rs` 新增 `validate_game_turn()` 函数，按 `game.phase` 分支
  - [x] SubTask 5.2: `Betting` 分支：保持原 `current_turn_player` 匹配逻辑
  - [x] SubTask 5.3: `MultiPlayerSubmit` 分支：校验提交者在 `pending_submitters` 中
  - [x] SubTask 5.4: `LeaveProof` 特殊分支：校验提交者在 `active_participants` 中（不要求在 pending_submitters）
  - [x] SubTask 5.5: 成功后更新 `pending_submitters` / `completed_submitters`（多玩家阶段）
  - [x] SubTask 5.6: 编写单元测试：4 种阶段校验正向 + 反向（NotYourTurn / NotEligibleSubmitter）

- [x] Task 6: 扩展错误类型
  - [x] SubTask 6.1: 在 `poker_l1/src/error.rs` 修改 `NotYourTurn` 新增 `phase: GamePhase` 字段
  - [x] SubTask 6.2: 新增 `NotEligibleSubmitter` 错误（含 `phase`、`pending_submitters`、`actor` 字段）
  - [x] SubTask 6.3: 更新既有 `NotYourTurn` 测试用例（添加 phase 字段）
  - [x] SubTask 6.4: 编写 `NotEligibleSubmitter` 测试用例

## Phase 4: 阶段超时与惩罚

- [x] Task 7: 多玩家阶段超时配置
  - [x] SubTask 7.1: 在 `poker_l1/src/block/time_consensus.rs` 的 `TimeConsensusConfig` 新增字段：
    - `shuffle_timeout_blocks: u64`（默认 100）
    - `reveal_token_timeout_blocks: u64`（默认 50）
    - `reconstruct_timeout_blocks: u64`（默认 100）
  - [x] SubTask 7.2: 新增 `is_submit_phase_timed_out(game, current_height, config) -> Option<SubmitPhaseKind>` 函数
  - [x] SubTask 7.3: 编写单元测试：超时判定边界（恰好超时 / 未超时 / LeaveProof 不超时）

- [x] Task 8: 超时惩罚执行
  - [x] SubTask 8.1: 新增 `poker_l1/src/consensus/phase_timeout.rs` 模块
  - [x] SubTask 8.2: 实现 `handle_submit_phase_timeout(game, timed_out_players) -> Vec<KickResult>`
  - [x] SubTask 8.3: kick 逻辑：从 `active_participants` / `pending_submitters` 移除，退款 `total_bet`
  - [x] SubTask 8.4: 若剩余 `active_participants < 2`，触发 `end_without_showdown`
  - [x] SubTask 8.5: 编写单元测试：单玩家超时 / 多玩家超时 / 剩余不足两人

## Phase 5: vertex 排序与共识集成

- [x] Task 9: 修改 game sub-block 排序逻辑
  - [x] SubTask 9.1: 在 `poker_l1/src/consensus/vertex_production.rs` 修改 `build_game_sub_block()`，按 `game.phase` 选择排序键
  - [x] SubTask 9.2: `Betting` 阶段：保持 `(current_turn 优先, arrival)` 排序
  - [x] SubTask 9.3: `MultiPlayerSubmit` 阶段：按 `(phase_kind, arrival)` 排序
  - [x] SubTask 9.4: 编写单元测试：两种阶段排序正确性

- [x] Task 10: 扩展 SEC-H6 force_advance 抢跑防护
  - [x] SubTask 10.1: 在 force_advance 判定逻辑中新增 `game.phase` 检查
  - [x] SubTask 10.2: `MultiPlayerSubmit` 阶段：前一 commit 内有 GameTurn tx → force_advance 判定为 false
  - [x] SubTask 10.3: 编写单元测试：跨 commit force_advance 在多玩家阶段被拒绝

## Phase 6: 集成测试与文档

- [x] Task 11: 端到端集成测试
  - [x] SubTask 11.1: 测试完整一手牌流程：Betting → Shuffle → RevealToken → Betting → ... → Showdown
  - [x] SubTask 11.2: 测试多玩家阶段超时恢复：Shuffle 超时 → kick → 继续
  - [x] SubTask 11.3: 测试 LeaveProof 随时提交：下注阶段 / 多玩家阶段均可
  - [x] SubTask 11.4: 测试跨 commit 排序：多玩家阶段 tx 分布在多个 vertex 仍按 arrival 排序

- [x] Task 12: 文档更新
  - [x] SubTask 12.1: 更新 `docs/37-1-node-deployment.md`：新增阶段超时配置说明
  - [x] SubTask 12.2: 更新 `docs/37-6-dag-consensus-ops.md`：新增多玩家阶段排序与超时运维
  - [x] SubTask 12.3: 新增 `docs/37-8-game-phase-protocol.md`：完整阶段状态机文档（Betting ↔ MultiPlayerSubmit 转换图）

# Task Dependencies

- Task 2 依赖 Task 1（GamePhase 枚举）
- Task 3 依赖 Task 1、Task 2
- Task 4 依赖 Task 3
- Task 5 依赖 Task 3、Task 4、Task 6
- Task 6 依赖 Task 1（GamePhase）
- Task 7 依赖 Task 1、Task 2
- Task 8 依赖 Task 7
- Task 9 依赖 Task 1、Task 5
- Task 10 依赖 Task 1、Task 5
- Task 11 依赖 Task 1-10 全部完成
- Task 12 依赖 Task 11

# 并行化建议

- Phase 1（Task 1、Task 2）必须先完成，是后续所有任务的基础
- Phase 2 的 Task 3 与 Phase 3 的 Task 6 可并行（都依赖 Task 1）
- Phase 2 的 Task 4 依赖 Task 3，必须串行
- Phase 3 的 Task 5 依赖 Task 3、Task 4、Task 6
- Phase 4 的 Task 7、Task 8 与 Phase 3 可并行（仅依赖 Phase 1）
- Phase 5 的 Task 9、Task 10 依赖 Phase 3，可并行
- Phase 6 必须最后
