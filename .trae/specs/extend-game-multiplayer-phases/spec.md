# 扩展游戏协议：多玩家并行提交阶段 Spec

> **change-id**：`extend-game-multiplayer-phases`
> **依赖**：`build-poker-l1-chain`（spec.md FROZEN 2026-06-27）— 本 spec 为 v2 backlog 增量
> **参考实现**：[texas_poker_move/sources/table.move](../../../zgame/texas_poker_move/sources/table.move)

## Why

当前 zchain poker_l1 的 `TurnRule` trait 与 `GameStatus.current_turn_player` 只能表达**单玩家轮转**（betting 阶段：fold/check/call/raise），但实际德州扑克协议存在 4 类**多玩家并行/顺序提交**阶段（来自 texas_poker_move Move 合约）：

1. **Shuffle 提交**：所有活跃玩家依次提交洗牌结果（顺序，但非"下注轮"）
2. **Reveal Token 提交**：每张待揭牌的所有持有密钥玩家并行提交 reveal token
3. **Reconstruct Deck 提交**：所有活跃玩家并行提交重建牌组
4. **Leave Proof 提交**：任意活跃玩家可随时提交离开证明

这些阶段中**没有单一"当前轮次玩家"**，而是**一组待提交者**（`pending_players`）。当前 L1 强制 `current_turn_player` 单点校验会导致这些合法 tx 被拒绝（返回 `NotYourTurn`），无法支撑完整扑克协议。

## What Changes

* **新增** `GamePhase` 枚举：区分 `Betting`（单玩家轮转）与 `MultiPlayerSubmit`（多玩家提交）两大类阶段
* **新增** `SubmitPhaseKind` 枚举：`Shuffle` / `RevealToken` / `Reconstruct` / `LeaveProof` 四种子阶段
* **新增** `TurnRule::current_submitters()` 方法：返回当前阶段允许提交的玩家集合（多玩家阶段）；`current_turn()` 在多玩家阶段返回 `None`
* **新增** `TurnRule::is_submission_complete()` 方法：判定多玩家阶段是否所有提交者已完成
* **新增** `TurnRule::advance_phase()` 方法：推进到下一阶段（多玩家 → 下一个多玩家 / 回到 Betting）
* **修改** `GameStatus`：新增 `phase: GamePhase`、`pending_submitters: BTreeSet<Address>`、`phase_started_height: BlockHeight` 字段
* **修改** GameTurn tx 校验逻辑：多玩家阶段允许 `pending_submitters` 中任意玩家提交，不再强制 `current_turn_player` 匹配
* **修改** `NotYourTurn` 错误：新增 `phase` 字段区分"非你的下注轮"与"非合法提交者"
* **新增** 多玩家阶段超时与惩罚：每种子阶段独立超时，未提交者按 phase 语义惩罚（kick / auto-fold / 视为放弃 shuffle）
* **修改** vertex 排序规则：同一 commit 内多玩家阶段的 GameTurn tx 按 `(phase, arrival)` 排序，不再按 `current_turn` 优先

## Impact

- **Affected specs**：
  - `build-poker-l1-chain/spec.md` SubTask 7.3（TurnRule）/ 7.4（轮转校验）/ 8.4（game sub-block 排序）/ 8.6（Block 内排序）
  - `build-poker-l1-chain/spec.md` SEC-L3（gameturn_nonce 存储）
  - `build-poker-l1-chain/spec.md` NEW-M9（GameTurn nonce 解耦）
- **Affected code**：
  - `poker_l1/src/consensus/routing.rs` — `TurnRule` trait、`GameStatus`、`SimpleTurnRule`
  - `poker_l1/src/consensus/vertex_production.rs` — game sub-block 排序、`current_turn` 用法
  - `poker_l1/src/error.rs` — `NotYourTurn` 错误结构、新增 `NotEligibleSubmitter` 错误
  - `poker_l1/src/transaction.rs` — `TxLane::GameTurn` 语义扩展（可能需要 phase 标记）
  - `poker_l1/src/block/time_consensus.rs` — 多玩家阶段超时配置
  - `poker_l1/src/consensus/mod.rs` — 阶段状态机
- **Reference**：[texas_poker_move/sources/table.move](../../../zgame/texas_poker_move/sources/table.move) L1702-L2209（submit_shuffle / submit_player_reveal_tokens / submit_reconstruct_deck）

## ADDED Requirements

### Requirement: GamePhase 阶段模型

系统 SHALL 引入 `GamePhase` 枚举，区分两大类游戏阶段：

```rust
pub enum GamePhase {
    /// 下注阶段：单玩家轮转（Preflop / Flop / Turn / River / Showdown betting）
    Betting { round: BettingRound },
    /// 多玩家提交阶段：一组玩家并行/顺序提交
    MultiPlayerSubmit { kind: SubmitPhaseKind },
}

pub enum SubmitPhaseKind {
    /// 洗牌提交：活跃玩家依次提交 shuffle proof（顺序）
    Shuffle,
    /// Reveal Token 提交：每张牌的密钥持有者并行提交
    RevealToken,
    /// Reconstruct Deck 提交：所有活跃玩家并行提交重建牌组
    Reconstruct,
    /// Leave Proof 提交：任意活跃玩家可随时提交（非阶段绑定，但需登记）
    LeaveProof,
}
```

#### Scenario: 下注阶段判定
- **WHEN** Game 处于 Preflop/Flop/Turn/River 下注轮
- **THEN** `game.phase = GamePhase::Betting { round }`
- **AND** `current_turn()` 返回 `Some(player)`，`current_submitters()` 返回空集合

#### Scenario: 多玩家提交阶段判定
- **WHEN** Game 进入 shuffle / reveal / reconstruct / leave 阶段
- **THEN** `game.phase = GamePhase::MultiPlayerSubmit { kind }`
- **AND** `current_turn()` 返回 `None`，`current_submitters()` 返回合法提交者集合

### Requirement: TurnRule trait 扩展

系统 SHALL 扩展 `TurnRule` trait，新增三个方法：

```rust
pub trait TurnRule: Send + Sync {
    // 既有方法（保持向后兼容）
    fn current_turn(&self, game: &GameStatus) -> Option<Address>;
    fn advance_turn(&self, game: &mut GameStatus) -> Option<Address>;

    // 新增：多玩家阶段合法提交者集合
    fn current_submitters(&self, game: &GameStatus) -> BTreeSet<Address>;

    // 新增：判定多玩家阶段是否所有提交者已完成
    fn is_submission_complete(&self, game: &GameStatus) -> bool;

    // 新增：推进到下一阶段（多玩家 → 下阶段 / 回到 Betting）
    fn advance_phase(&self, game: &mut GameStatus) -> Result<GamePhase, PhaseTransitionError>;
}
```

#### Scenario: 下注阶段调用 current_submitters
- **WHEN** `game.phase = GamePhase::Betting { .. }`
- **THEN** `current_submitters()` 返回空集合 `BTreeSet::new()`
- **AND** validator 仅依赖 `current_turn()` 校验

#### Scenario: 多玩家阶段调用 current_turn
- **WHEN** `game.phase = GamePhase::MultiPlayerSubmit { .. }`
- **THEN** `current_turn()` 返回 `None`
- **AND** validator 依赖 `current_submitters()` 校验

#### Scenario: Shuffle 阶段提交者集合
- **GIVEN** Game 进入 `SubmitPhaseKind::Shuffle`
- **WHEN** 调用 `current_submitters()`
- **THEN** 返回所有活跃玩家（`active_participants`）
- **AND** `pending_submitters` 初始等于 `active_participants`

#### Scenario: Reveal Token 阶段提交者集合
- **GIVEN** Game 进入 `SubmitPhaseKind::RevealToken`，当前有 N 张牌待揭牌
- **WHEN** 调用 `current_submitters()`
- **THEN** 返回持有这些牌密钥的玩家集合（可能为全部活跃玩家）
- **AND** 玩家可一次性为多张牌提交 reveal tokens（参考 Move 合约 `submit_player_reveal_tokens` 批量接口）

#### Scenario: Reconstruct 阶段提交者集合
- **GIVEN** Game 进入 `SubmitPhaseKind::Reconstruct`
- **WHEN** 调用 `current_submitters()`
- **THEN** 返回所有活跃玩家（`active_participants`）

#### Scenario: Leave Proof 阶段提交者集合
- **GIVEN** Game 处于任意阶段
- **WHEN** 玩家提交 leave proof
- **THEN** 不需要阶段切换，`current_submitters()` 在 LeaveProof 阶段返回所有活跃玩家
- **AND** leave proof 提交后该玩家从 `active_participants` 移除

### Requirement: GameStatus 状态扩展

系统 SHALL 在 `GameStatus` 新增以下字段：

```rust
pub struct GameStatus {
    // 既有字段...
    /// 当前游戏阶段（Betting 或 MultiPlayerSubmit）。
    pub phase: GamePhase,
    /// 多玩家阶段待提交者集合（下注阶段为空）。
    pub pending_submitters: BTreeSet<Address>,
    /// 当前阶段开始的 block height（用于超时判定）。
    pub phase_started_height: BlockHeight,
    /// 多玩家阶段已提交者集合（用于进度追踪）。
    pub completed_submitters: BTreeSet<Address>,
}
```

#### Scenario: 阶段切换时重置追踪集合
- **WHEN** `advance_phase()` 切换到新的 `MultiPlayerSubmit` 阶段
- **THEN** `pending_submitters` 重置为该阶段的合法提交者集合
- **AND** `completed_submitters` 清空
- **AND** `phase_started_height` 更新为当前 block height

#### Scenario: 单次提交后更新追踪
- **WHEN** 玩家 P 在多玩家阶段成功提交 GameTurn tx
- **THEN** `pending_submitters.remove(&P)`
- **AND** `completed_submitters.insert(P)`

### Requirement: GameTurn tx 校验逻辑扩展

系统 SHALL 修改 GameTurn tx 校验逻辑，根据 `game.phase` 分支：

#### Scenario: 下注阶段校验（既有行为，保持兼容）
- **GIVEN** `game.phase = GamePhase::Betting { .. }`
- **WHEN** 玩家 P 提交 GameTurn tx
- **THEN** validator 校验 `P == game.current_turn_player`
- **AND** 失败返回 `NotYourTurn { phase: Betting, current_turn: Some(...), actor: P }`

#### Scenario: 多玩家阶段校验（新行为）
- **GIVEN** `game.phase = GamePhase::MultiPlayerSubmit { .. }`
- **WHEN** 玩家 P 提交 GameTurn tx
- **THEN** validator 校验 `game.pending_submitters.contains(&P)`
- **AND** 失败返回 `NotEligibleSubmitter { phase, pending: [...], actor: P }`
- **AND** 成功后从 `pending_submitters` 移除 P

#### Scenario: LeaveProof 阶段特殊处理
- **GIVEN** 玩家 P 想要离开
- **WHEN** P 提交 leave proof tx（lane = GameTurn，phase 标记 = LeaveProof）
- **THEN** validator 校验 P 在 `active_participants` 中
- **AND** 成功后 P 从 `active_participants` 与 `pending_submitters`（若在）同时移除
- **AND** 若 `pending_submitters` 因此变空，触发 `advance_phase()`

### Requirement: 阶段完成与推进

系统 SHALL 定义多玩家阶段完成条件与推进规则：

#### Scenario: 所有提交者完成
- **GIVEN** 多玩家阶段，`pending_submitters` 非空
- **WHEN** 最后一个提交者完成提交
- **THEN** `is_submission_complete()` 返回 `true`
- **AND** assigned_validator 调用 `advance_phase()` 切换到下一阶段

#### Scenario: Shuffle → RevealToken 推进
- **GIVEN** Shuffle 阶段所有玩家完成
- **WHEN** `advance_phase()` 被调用
- **THEN** 切换到 `MultiPlayerSubmit { kind: RevealToken }`（若有牌待揭）
- **OR** 切换到 `Betting { round: Preflop }`（若无牌待揭，直接进入下注）

#### Scenario: RevealToken → Betting 推进
- **GIVEN** RevealToken 阶段所有牌已解密
- **WHEN** `advance_phase()` 被调用
- **THEN** 切换到 `Betting { round: <对应轮次> }`

#### Scenario: Reconstruct → 重新洗牌或结束
- **GIVEN** Reconstruct 阶段所有玩家完成
- **WHEN** `advance_phase()` 被调用
- **THEN** 切换到 `MultiPlayerSubmit { kind: Shuffle }`（重新洗牌）
- **OR** 切换到 `Betting`（继续游戏）

### Requirement: 多玩家阶段超时与惩罚

系统 SHALL 为每种多玩家提交阶段定义独立超时：

| 阶段 | 默认超时（blocks） | 超时惩罚 |
|------|-------------------|----------|
| `Shuffle` | 100 | 未提交者 kick + 退款 |
| `RevealToken` | 50 | 未提交者 kick + 退款 |
| `Reconstruct` | 100 | 未提交者 kick + 退款 |
| `LeaveProof` | 不限（被动） | 无（玩家主动行为） |

#### Scenario: Shuffle 阶段超时
- **GIVEN** `game.phase = MultiPlayerSubmit { kind: Shuffle }`
- **AND** `current_height > phase_started_height + shuffle_timeout_blocks`
- **WHEN** 任意 validator 触发超时检测
- **THEN** `pending_submitters` 中的玩家被 kick
- **AND** 他们的 `total_bet` 退款
- **AND** 从 `active_participants` 移除
- **AND** 若剩余 `active_participants >= 2`，继续 shuffle；否则结束本手

#### Scenario: RevealToken 阶段超时
- **GIVEN** `game.phase = MultiPlayerSubmit { kind: RevealToken }`
- **AND** 超时触发
- **THEN** `pending_submitters` 中的玩家被 kick + 退款
- **AND** 已提交者的 reveal token 保留，可继续解密

### Requirement: vertex 内 GameTurn tx 排序调整

系统 SHALL 修改 game sub-block 内 GameTurn tx 排序规则：

#### Scenario: 下注阶段排序（既有，保持）
- **GIVEN** `game.phase = GamePhase::Betting { .. }`
- **WHEN** assigned_validator 装入 GameTurn tx 到 vertex
- **THEN** 按 `(current_turn 优先, arrival)` 排序

#### Scenario: 多玩家阶段排序（新）
- **GIVEN** `game.phase = GamePhase::MultiPlayerSubmit { kind }`
- **WHEN** assigned_validator 装入 GameTurn tx 到 vertex
- **THEN** 按 `(kind, arrival)` 排序（同阶段按到达顺序）
- **AND** 不再使用 `current_turn` 优先级（多玩家阶段无单一 current_turn）

### Requirement: 跨 commit force_advance 抢跑防护扩展

系统 SHALL 扩展 SEC-H6 修复的 force_advance 抢跑防护，覆盖多玩家阶段：

#### Scenario: 多玩家阶段 force_advance 拒绝
- **GIVEN** `game.phase = GamePhase::MultiPlayerSubmit { .. }`
- **AND** 前一 commit 内有该 Game 的 GameTurn tx
- **WHEN** 当前 commit 内出现 force_advance tx
- **THEN** force_advance 判定为 false（`last_action_height` 视为已更新）
- **AND** 拒绝该 force_advance tx

## MODIFIED Requirements

### Requirement: TurnRule trait（修改 spec SubTask 7.3）

**原 spec**：`TurnRule` 仅含 `current_turn()` 与 `advance_turn()` 两个方法，返回单个玩家地址。

**修改后**：`TurnRule` 新增 `current_submitters()`、`is_submission_complete()`、`advance_phase()` 三个方法。`current_turn()` 在多玩家阶段返回 `None`。原 `current_turn()` / `advance_turn()` 语义不变（仅下注阶段使用）。

### Requirement: GameTurn tx 轮转校验（修改 spec SubTask 7.4）

**原 spec**：validator 校验 `tx.chain_id == network_chain_id` 且 `tx.nonce == account.nonce`，且 GameTurn tx 必须由 `current_turn_player` 提交，否则返回 `NotYourTurn`。

**修改后**：validator 根据 `game.phase` 分支校验：
- `Betting` 阶段：保持原逻辑（`current_turn_player` 匹配）
- `MultiPlayerSubmit` 阶段：校验提交者在 `pending_submitters` 中，否则返回 `NotEligibleSubmitter`
- `gameturn_nonce` 校验逻辑不变（per-game per-player）

### Requirement: game sub-block 排序（修改 spec SubTask 8.4 / 8.6）

**原 spec**：assigned_validator 把 GameTurn tx 分组为 game sub-block，按 `(current_turn, arrival)` 排序。

**修改后**：排序键根据 `game.phase` 选择：
- `Betting` 阶段：`(current_turn 优先, arrival)`（保持原逻辑）
- `MultiPlayerSubmit` 阶段：`(phase_kind, arrival)`（按阶段类型 + 到达顺序）

## REMOVED Requirements

无（本 spec 为增量扩展，不移除既有功能）。
