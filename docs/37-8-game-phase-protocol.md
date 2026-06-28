# poker_l1 游戏阶段协议文档（SubTask 12.3）

> 本文档覆盖 `extend-game-multiplayer-phases` spec Phase 6 SubTask 12.3：完整阶段状态机文档（Betting ↔ MultiPlayerSubmit 转换图）。
>
> 严格对齐 `poker_l1` 源码实现：
> - `poker_l1/src/consensus/routing.rs` — `GamePhase` / `SubmitPhaseKind` / `BettingRound` / `GameStatus` / `TurnRule` / `SimpleTurnRule` / `PhaseTransitionError` / `validate_game_turn_phase_aware`
> - `poker_l1/src/consensus/texas_holdem_turn_rule.rs` — `TexasHoldemTurnRule`
> - `poker_l1/src/consensus/phase_timeout.rs` — `handle_submit_phase_timeout` / `KickResult`
> - `poker_l1/src/block/time_consensus.rs` — `TimeConsensusConfig` / `is_submit_phase_timed_out`
> - `poker_l1/src/consensus/vertex_production.rs` — `build_game_sub_block` / `check_sech6_cross_commit_force_advance`
> - `poker_l1/src/error.rs` — `PokerL1Error::NotYourTurn` / `PokerL1Error::NotEligibleSubmitter`

---

## 1. 概述

poker_l1 游戏阶段协议（Game Phase Protocol）定义 Game 生命周期内的阶段状态机，覆盖下注（Betting）与多玩家并行提交（MultiPlayerSubmit）两大类阶段。本协议在 `extend-game-multiplayer-phases` spec Phase 1-5 中实现，是 Texas Hold'em 等扑克变体的链上阶段管理基础。

### 1.1 设计目标

| 目标 | 实现方式 |
| --- | --- |
| 向后兼容 | 新字段 `phase` / `pending_submitters` / `phase_started_height` / `completed_submitters` 有默认值，既有 `GameStatus` 序列化向后兼容 |
| 多扑克变体支持 | `TurnRule` trait 抽象，`SimpleTurnRule`（仅下注）+ `TexasHoldemTurnRule`（完整扑克） |
| 多玩家并行提交 | `MultiPlayerSubmit` 阶段允许多玩家同时提交，无需单一轮次锁定 |
| 超时安全 | 每个多玩家子阶段独立超时阈值，以 `block.height` 为权威（SEC-M5） |
| 跨 commit 防护 | SEC-H6 扩展覆盖多玩家阶段，防止 force_advance 抢跑 |

### 1.2 关键概念

- **GamePhase**：游戏阶段顶层枚举，区分 `Betting` 与 `MultiPlayerSubmit`
- **BettingRound**：下注轮次（Preflop / Flop / Turn / River / Showdown）
- **SubmitPhaseKind**：多玩家提交子阶段（Shuffle / RevealToken / Reconstruct / LeaveProof）
- **TurnRule**：阶段轮转规则 trait，抽象不同扑克变体的轮转逻辑
- **pending_submitters**：多玩家阶段待提交玩家集合
- **completed_submitters**：多玩家阶段已提交玩家集合

---

## 2. 阶段类型定义

### 2.1 GamePhase 枚举

源码：`poker_l1/src/consensus/routing.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GamePhase {
    /// 下注阶段：单一玩家轮次（按 active_participants 顺序）
    Betting { round: BettingRound },
    /// 多玩家并行提交阶段：多个玩家可同时提交
    MultiPlayerSubmit { kind: SubmitPhaseKind },
}
```

| 变体 | 字段 | 说明 |
| --- | --- | --- |
| `Betting` | `round: BettingRound` | 下注阶段，标记当前下注轮次 |
| `MultiPlayerSubmit` | `kind: SubmitPhaseKind` | 多玩家并行提交阶段，标记子阶段类型 |

辅助方法：
- `is_betting() -> bool`：当前是否为下注阶段
- `is_multi_player_submit() -> bool`：当前是否为多玩家提交阶段

### 2.2 BettingRound 枚举

Texas Hold'em 四轮下注 + 摊牌阶段：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BettingRound {
    Preflop,   // 翻牌前（盲注后、翻牌前）
    Flop,      // 翻牌后（前三张公共牌发出后）
    Turn,      // 转牌（第四张公共牌发出后）
    River,     // 河牌（第五张公共牌发出后）
    Showdown,  // 摊牌（所有下注结束，比较手牌）
}
```

下注轮次推进顺序：`Preflop → Flop → Turn → River → Showdown`，由 `SimpleTurnRule::advance_turn()` 或 `TexasHoldemTurnRule::advance_turn()` 在玩家行动后推进。

### 2.3 SubmitPhaseKind 枚举

多玩家并行提交子阶段：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmitPhaseKind {
    Shuffle,       // 洗牌阶段
    RevealToken,   // 揭牌阶段
    Reconstruct,   // 重构阶段
    LeaveProof,    // 离场证明阶段（被动，永不超时）
}
```

| 子阶段 | 用途 | 提交者集合 | 超时阈值 |
| --- | --- | --- | --- |
| `Shuffle` | 玩家提交洗牌随机性（VRF output） | `active_participants` | `shuffle_timeout_blocks` (100) |
| `RevealToken` | 玩家揭牌（揭示密钥/承诺） | `active_participants`（合约层可收缩为密钥持有者） | `reveal_token_timeout_blocks` (50) |
| `Reconstruct` | 玩家提交重构数据（重建牌堆） | `active_participants` | `reconstruct_timeout_blocks` (100) |
| `LeaveProof` | 玩家提交离场证明（随时可提交） | `active_participants` | **永不超时** |

---

## 3. 状态转换总览

### 3.1 顶层阶段转换图

```
                    ┌─────────────────────────────────┐
                    │  Betting { round: BettingRound } │
                    │  （下注阶段，单一玩家轮次）        │
                    └────────────┬────────────────────┘
                                 │
                  advance_phase() 在 Betting 阶段返回 Err
                                 │
                                 ▼
                    ┌─────────────────────────────────┐
                    │  MultiPlayerSubmit { kind }      │
                    │  （多玩家并行提交阶段）            │
                    └────────────┬────────────────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            ▼                    ▼                    ▼
     ┌──────────┐        ┌──────────────┐      ┌──────────────┐
     │ Shuffle  │───────►│ RevealToken  │─────►│ Betting{PF}  │
     └──────────┘        └──────────────┘      └──────────────┘
                                 ▲
                                 │
     ┌──────────────┐            │
     │ Reconstruct  │────────────┘
     └──────────────┘

     ┌──────────────┐
     │ LeaveProof   │─── advance_phase() 返回当前阶段（保持不变）
     └──────────────┘
```

### 3.2 阶段切换条件

| 源阶段 | 目标阶段 | 触发条件 | 失败原因 |
| --- | --- | --- | --- |
| `Betting` | — | `advance_phase()` 返回 `Err` | 下注阶段不可直接切换到多玩家阶段（须由合约层触发） |
| `Shuffle` | `RevealToken` | `advance_phase()` 成功，`pending_submitters` 为空 | `PendingSubmittersNotEmpty`（仍有玩家未提交） |
| `RevealToken` | `Betting { Preflop }` | `advance_phase()` 成功，`pending_submitters` 为空 | `PendingSubmittersNotEmpty` |
| `Reconstruct` | `Betting { Preflop }` | `advance_phase()` 成功 | `InvalidPhaseTransition`（非法转换） |
| `LeaveProof` | `LeaveProof` | `advance_phase()` 返回当前阶段（保持不变） | LeaveProof 为被动行为，不主动切换 |

---

## 4. Betting 阶段详解

### 4.1 阶段语义

Betting 阶段为传统扑克下注轮次，**单一玩家轮次锁定**：

- `current_turn_player` 字段标记当前行动玩家
- 玩家按 `active_participants` 顺序轮转（由 `TurnRule::advance_turn` 推进）
- 非 `current_turn_player` 提交 GameTurn tx → 返回 `PokerL1Error::NotYourTurn`

### 4.2 下注轮次推进

`BettingRound` 推进由 `TurnRule::advance_turn()` 在玩家行动后触发：

```
Preflop ──(advance_turn)──► Flop ──(advance_turn)──► Turn
   ──(advance_turn)──► River ──(advance_turn)──► Showdown
```

> 注：`advance_turn` 的具体推进规则（何时切换 BettingRound）由扑克变体实现决定。`SimpleTurnRule` 仅按 `active_participants` 顺序轮转 `current_turn_player`，不推进 `BettingRound`；`TexasHoldemTurnRule` 复用 `SimpleTurnRule` 逻辑。

### 4.3 current_turn 计算

源码：`SimpleTurnRule::current_turn()` / `TexasHoldemTurnRule::current_turn()`

```rust
// SimpleTurnRule: 按 active_participants BTreeSet 顺序查找 current_turn_player 的下一个
fn current_turn(&self, game: &GameStatus) -> Option<Address> {
    // 从 active_participants 中找 current_turn_player，返回其后继
    // 若无后继，返回首个 active participant（循环）
}

// TexasHoldemTurnRule: MultiPlayerSubmit 阶段返回 None，Betting 复用 SimpleTurnRule
fn current_turn(&self, game: &GameStatus) -> Option<Address> {
    if game.phase.is_multi_player_submit() {
        return None;  // 多玩家阶段无单一 current_turn
    }
    SimpleTurnRule.current_turn(game)
}
```

### 4.4 Betting 阶段不切换到 MultiPlayerSubmit

`advance_phase()` 在 Betting 阶段返回 `Err(InvalidPhaseTransition)`：

```rust
// TexasHoldemTurnRule::advance_phase()
fn advance_phase(&self, game: &mut GameStatus) -> Result<GamePhase, PhaseTransitionError> {
    match game.phase {
        GamePhase::Betting { .. } => Err(PhaseTransitionError::InvalidPhaseTransition),
        // ... 多玩家阶段切换逻辑
    }
}
```

> **设计决策**：Betting → MultiPlayerSubmit 的切换由合约层（Phase 3）在适当时机（如手牌开始时进入 Shuffle）触发，非 `advance_phase()` 职责。

---

## 5. MultiPlayerSubmit 阶段详解

### 5.1 Shuffle 子阶段

**语义**：所有 active_participants 并行提交洗牌随机性（VRF output）。

| 属性 | 值 |
| --- | --- |
| `pending_submitters` | `active_participants`（全集） |
| `completed_submitters` | 初始为空，玩家提交后插入 |
| `current_turn()` | `None`（无单一轮次） |
| 超时阈值 | `shuffle_timeout_blocks` (100 block) |
| 完成判定 | `pending_submitters.is_empty()` |

**提交校验**：玩家提交 GameTurn tx → `validate_game_turn_phase_aware()` 校验 actor ∈ `pending_submitters` → 移除出 pending、插入 completed。

**阶段切换**：`pending_submitters` 清空后，`advance_phase()` 切换到 `RevealToken`。

### 5.2 RevealToken 子阶段

**语义**：玩家揭牌（揭示密钥/承诺），用于验证 Shuffle 阶段的随机性。

| 属性 | 值 |
| --- | --- |
| `pending_submitters` | `active_participants`（默认，合约层可收缩为密钥持有者） |
| `completed_submitters` | 初始为空 |
| `current_turn()` | `None` |
| 超时阈值 | `reveal_token_timeout_blocks` (50 block，最短) |
| 完成判定 | `pending_submitters.is_empty()` |

> **超时阈值最短原因**：RevealToken 阶段玩家若故意拖延揭牌，会阻塞游戏流程。50 block 阈值（约 50 秒，假设 1 block/s）足够诚实玩家完成揭牌，同时快速惩罚拖延者。

**阶段切换**：`pending_submitters` 清空后，`advance_phase()` 切换到 `Betting { round: Preflop }`（开始新一手牌下注）。

### 5.3 Reconstruct 子阶段

**语义**：玩家提交重构数据，用于重建牌堆（如争议后重新计算）。

| 属性 | 值 |
| --- | --- |
| `pending_submitters` | `active_participants` |
| `completed_submitters` | 初始为空 |
| `current_turn()` | `None` |
| 超时阈值 | `reconstruct_timeout_blocks` (100 block) |
| 完成判定 | `pending_submitters.is_empty()` |

**阶段切换**：`pending_submitters` 清空后，`advance_phase()` 切换到 `Betting { round: Preflop }`（继续游戏）。

### 5.4 LeaveProof 子阶段

**语义**：玩家提交离场证明（退出当前 Game），**被动行为**，可随时提交。

| 属性 | 值 |
| --- | --- |
| `pending_submitters` | `active_participants`（但 LeaveProof 不要求在 pending 中） |
| `completed_submitters` | 初始为空 |
| `current_turn()` | `None` |
| 超时阈值 | **永不超时**（`is_submit_phase_timed_out` 返回 `None`） |
| 完成判定 | 不适用（LeaveProof 不切换阶段） |

**特殊校验**：`validate_game_turn_phase_aware()` 对 LeaveProof 分支校验 actor ∈ `active_participants`（**不要求**在 `pending_submitters` 中），成功后从 `active_participants` 移除。

**阶段切换**：`advance_phase()` 返回当前阶段（`LeaveProof` 保持不变），LeaveProof 为被动行为，不主动切换。

> **跨阶段提交**：LeaveProof 可在任意阶段提交（Betting 或 MultiPlayerSubmit）。当 `game.phase = MultiPlayerSubmit { kind: LeaveProof }` 时，走 LeaveProof 分支；其他阶段的 LeaveProof 提交由合约层处理。

---

## 6. 阶段切换规则（advance_phase）

### 6.1 TexasHoldemTurnRule::advance_phase 状态机

源码：`poker_l1/src/consensus/texas_holdem_turn_rule.rs`

```rust
fn advance_phase(&self, game: &mut GameStatus) -> Result<GamePhase, PhaseTransitionError> {
    match game.phase {
        GamePhase::Betting { .. } => Err(PhaseTransitionError::InvalidPhaseTransition),
        GamePhase::MultiPlayerSubmit { kind } => match kind {
            SubmitPhaseKind::Shuffle => {
                // 校验 pending_submitters 为空
                if !game.pending_submitters.is_empty() {
                    return Err(PhaseTransitionError::PendingSubmittersNotEmpty);
                }
                // 切换到 RevealToken
                let new_phase = GamePhase::MultiPlayerSubmit { kind: SubmitPhaseKind::RevealToken };
                Self::reset_phase_fields(game, new_phase);
                Ok(new_phase)
            }
            SubmitPhaseKind::RevealToken => {
                if !game.pending_submitters.is_empty() {
                    return Err(PhaseTransitionError::PendingSubmittersNotEmpty);
                }
                // 切换到 Betting { Preflop }
                let new_phase = GamePhase::Betting { round: BettingRound::Preflop };
                Self::reset_phase_fields(game, new_phase);
                Ok(new_phase)
            }
            SubmitPhaseKind::Reconstruct => {
                // Reconstruct → Betting { Preflop }（继续游戏）
                let new_phase = GamePhase::Betting { round: BettingRound::Preflop };
                Self::reset_phase_fields(game, new_phase);
                Ok(new_phase)
            }
            SubmitPhaseKind::LeaveProof => {
                // LeaveProof 保持当前阶段（被动行为，不切换）
                Ok(game.phase)
            }
        },
    }
}
```

### 6.2 阶段字段重置（reset_phase_fields）

切换阶段时执行的字段重置逻辑：

```rust
fn reset_phase_fields(game: &mut GameStatus, new_phase: GamePhase) {
    game.phase = new_phase;
    // 重置 pending_submitters 为新阶段的合法提交者集合
    game.pending_submitters = Self::compute_submitters_for_phase(new_phase, game);
    // 清空 completed_submitters
    game.completed_submitters.clear();
    // 更新 phase_started_height = last_action_height + 1
    game.phase_started_height = game.last_action_height + 1;
}
```

| 字段 | 重置值 | 说明 |
| --- | --- | --- |
| `phase` | `new_phase` | 更新为新阶段 |
| `pending_submitters` | `compute_submitters_for_phase(new_phase)` | 新阶段的合法提交者集合 |
| `completed_submitters` | 空 | 清空已提交记录 |
| `phase_started_height` | `last_action_height + 1` | 新阶段起始 height（用于超时判定） |

### 6.3 compute_submitters_for_phase 规则

| 新阶段 | `pending_submitters` 初始值 |
| --- | --- |
| `Betting { .. }` | 空集合（下注阶段不用 pending） |
| `MultiPlayerSubmit { kind: Shuffle }` | `active_participants` |
| `MultiPlayerSubmit { kind: RevealToken }` | `active_participants`（合约层可后续收缩为密钥持有者） |
| `MultiPlayerSubmit { kind: Reconstruct }` | `active_participants` |
| `MultiPlayerSubmit { kind: LeaveProof }` | `active_participants` |

### 6.4 PhaseTransitionError 错误

```rust
pub enum PhaseTransitionError {
    /// pending_submitters 非空，不可切换阶段
    PendingSubmittersNotEmpty,
    /// 非法阶段转换（如 Betting 直接切换）
    InvalidPhaseTransition,
}
```

---

## 7. 提交者集合管理

### 7.1 集合字段语义

| 字段 | 类型 | 语义 |
| --- | --- | --- |
| `pending_submitters` | `BTreeSet<Address>` | 多玩家阶段待提交玩家集合（下注阶段为空） |
| `completed_submitters` | `BTreeSet<Address>` | 多玩家阶段已提交玩家集合（下注阶段为空） |
| `active_participants` | `BTreeSet<Address>` | 当前在座玩家集合（未 fold / 未 sit-out） |

### 7.2 集合变化时机

| 事件 | `pending_submitters` | `completed_submitters` | `active_participants` |
| --- | --- | --- | --- |
| 阶段切换（进入多玩家阶段） | 重置为 `active_participants` | 清空 | 不变 |
| 玩家成功提交（Shuffle/RevealToken/Reconstruct） | 移除该玩家 | 插入该玩家 | 不变 |
| 玩家成功提交 LeaveProof | 移除该玩家（若在） | 插入该玩家 | **移除该玩家** |
| 超时 kick | 移除被踢玩家 | 移除被踢玩家 | **移除被踢玩家** |
| 玩家 fold（下注阶段） | 不变 | 不变 | 移除该玩家（合约层处理） |

### 7.3 is_submission_complete 判定

```rust
// TexasHoldemTurnRule
fn is_submission_complete(&self, game: &GameStatus) -> bool {
    game.pending_submitters.is_empty()
}
```

- **Betting 阶段**：`current_submitters()` 返回空集合，`is_submission_complete()` 返回 `true`（下注阶段不依赖此判定）
- **MultiPlayerSubmit 阶段**：`pending_submitters.is_empty()` 时返回 `true`，可触发 `advance_phase()`

### 7.4 current_submitters 计算

```rust
fn current_submitters(&self, game: &GameStatus) -> BTreeSet<Address> {
    match game.phase {
        GamePhase::Betting { .. } => BTreeSet::new(),  // 下注阶段返回空
        GamePhase::MultiPlayerSubmit { kind } => match kind {
            SubmitPhaseKind::Shuffle
            | SubmitPhaseKind::RevealToken
            | SubmitPhaseKind::Reconstruct
            | SubmitPhaseKind::LeaveProof => game.active_participants.clone(),
        },
    }
}
```

---

## 8. 超时与惩罚

### 8.1 超时判定函数

源码：`poker_l1/src/block/time_consensus.rs`

```rust
pub fn is_submit_phase_timed_out(
    game: &GameStatus,
    current_height: BlockHeight,
    config: &TimeConsensusConfig,
) -> Option<SubmitPhaseKind>
```

**判定逻辑**：

| 当前 `game.phase` | 使用阈值 | 判定条件 | 返回值 |
| --- | --- | --- | --- |
| `Betting { .. }` | 不适用 | — | `None` |
| `MultiPlayerSubmit { kind: Shuffle }` | `shuffle_timeout_blocks` (100) | `current > phase_started_height + 100` | `Some(Shuffle)` |
| `MultiPlayerSubmit { kind: RevealToken }` | `reveal_token_timeout_blocks` (50) | `current > phase_started_height + 50` | `Some(RevealToken)` |
| `MultiPlayerSubmit { kind: Reconstruct }` | `reconstruct_timeout_blocks` (100) | `current > phase_started_height + 100` | `Some(Reconstruct)` |
| `MultiPlayerSubmit { kind: LeaveProof }` | 不适用 | — | `None`（永不超时） |

**边界判定**（严格大于 `>`）：
- `current == phase_started_height + timeout_blocks` → **未超时**（边界值不触发）
- `current == phase_started_height + timeout_blocks + 1` → **已超时**

**overflow 保护**：`checked_add` 失败时返回 `None`（保守不超时，避免误 kick）。

### 8.2 超时惩罚执行

源码：`poker_l1/src/consensus/phase_timeout.rs`

```rust
pub fn handle_submit_phase_timeout<F>(
    game: &mut GameStatus,
    timed_out_phase: SubmitPhaseKind,
    current_height: BlockHeight,
    refund_calc: F,
) -> Vec<KickResult>
where
    F: Fn(&Address) -> u64,
```

**执行步骤**：

1. 遍历 `game.pending_submitters`，对每个未提交玩家执行 kick
2. 从 `active_participants` / `pending_submitters` / `completed_submitters` 同时移除该玩家
3. 退款 `refund_calc(&player)`（通常返回玩家 `total_bet`，全额退款无罚没）
4. 若剩余 `active_participants < 2` → 触发 `end_without_showdown` 直接结算

**返回值**：`Vec<KickResult>`，每项含：

```rust
pub struct KickResult {
    pub player: Address,
    pub refund_amount: u64,
}
```

### 8.3 超时惩罚流程图

```
┌─────────────────────────────────────────────────────┐
│  is_submit_phase_timed_out() 返回 Some(kind)         │
│  （如 Some(Shuffle)，current > phase_started + 100） │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  handle_submit_phase_timeout() 执行：                │
│  1. 遍历 pending_submitters                          │
│  2. kick 每个未提交玩家                              │
│  3. 退款 total_bet（refund_calc 闭包）               │
└─────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  检查剩余 active_participants 数量：                 │
│  - >= 2：继续游戏（pending 已清空，可 advance_phase）│
│  - < 2：触发 end_without_showdown 直接结算           │
└─────────────────────────────────────────────────────┘
```

### 8.4 LeaveProof 不超时的设计理由

LeaveProof 为**被动行为**：玩家可因各种原因（离线、放弃、紧急退出）随时提交离场证明。若 LeaveProof 设超时阈值：

- 诚实玩家因网络问题延迟提交 → 被误 kick
- 恶意玩家可利用超时机制强制踢出其他玩家

因此 LeaveProof **永不超时**，`is_submit_phase_timed_out()` 对此阶段始终返回 `None`。

---

## 9. tx 校验逻辑（validate_game_turn_phase_aware）

### 9.1 函数签名

源码：`poker_l1/src/consensus/routing.rs`

```rust
pub fn validate_game_turn_phase_aware(
    tx: &Transaction,
    game: &mut GameStatus,
    actor: Address,
    turn_rule: &dyn TurnRule,
) -> PokerL1Result<()>
```

### 9.2 分支校验逻辑

```rust
match game.phase {
    GamePhase::Betting { .. } => {
        // 下注阶段：校验 actor == current_turn_player
        validate_turn_order(tx, game, actor, turn_rule)
    }
    GamePhase::MultiPlayerSubmit { kind } => match kind {
        SubmitPhaseKind::LeaveProof => {
            // LeaveProof：校验 actor ∈ active_participants（不要求在 pending_submitters）
            if !game.active_participants.contains(&actor) {
                return Err(PokerL1Error::NotEligibleSubmitter { ... });
            }
            // 成功：从 active_participants 移除，从 pending_submitters 移除（若在），插入 completed
            game.active_participants.remove(&actor);
            game.pending_submitters.remove(&actor);
            game.completed_submitters.insert(actor);
            Ok(())
        }
        _ => {
            // Shuffle / RevealToken / Reconstruct：校验 actor ∈ pending_submitters
            if !game.pending_submitters.contains(&actor) {
                return Err(PokerL1Error::NotEligibleSubmitter { ... });
            }
            // 成功：从 pending_submitters 移除，插入 completed_submitters
            game.pending_submitters.remove(&actor);
            game.completed_submitters.insert(actor);
            Ok(())
        }
    },
}
```

### 9.3 校验规则汇总

| 当前阶段 | 校验条件 | 成功动作 | 失败错误 |
| --- | --- | --- | --- |
| `Betting { .. }` | `actor == current_turn_player` | 推进 `current_turn`（由 `advance_turn`） | `NotYourTurn { phase }` |
| `MultiPlayerSubmit { Shuffle/RevealToken/Reconstruct }` | `actor ∈ pending_submitters` | 移出 pending，插入 completed | `NotEligibleSubmitter { phase, pending, actor }` |
| `MultiPlayerSubmit { LeaveProof }` | `actor ∈ active_participants` | 从 active + pending 移除，插入 completed | `NotEligibleSubmitter { phase, pending, actor }` |

### 9.4 错误类型定义

源码：`poker_l1/src/error.rs`

```rust
pub enum PokerL1Error {
    /// 非当前轮次玩家提交（下注阶段）
    NotYourTurn {
        phase: GamePhase,
    },
    /// 非合格提交者（多玩家阶段）
    NotEligibleSubmitter {
        game_id: ObjectID,
        phase: GamePhase,
        pending: BTreeSet<Address>,  // 当前 pending_submitters 快照
        actor: Address,              // 被拒绝的提交者
    },
}
```

> **SEC-M5 约束**：`NotYourTurn` 含 `phase` 字段，便于客户端区分下注阶段与多玩家阶段的轮次错误。

### 9.5 actor 地址计算

`actor` 由 `derive_address(&tx.tagged_pubkey)` 计算（源码：`poker_l1/src/account/mod.rs`）：

```rust
pub fn derive_address(tagged_pubkey: &TaggedPubkey) -> Address {
    // blake2b_256(tag || raw)[0..20]
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&tagged_pubkey.tag);
    h.update(&tagged_pubkey.raw);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[0..20]);
    addr
}
```

---

## 10. 跨 commit 排序与 SEC-H6 防护

### 10.1 build_game_sub_block 排序规则

源码：`poker_l1/src/consensus/vertex_production.rs`

```rust
pub fn build_game_sub_block(
    txs: &[Transaction],
    game: &GameStatus,
    turn_rule: &dyn TurnRule,
) -> Vec<Transaction>
```

**按 `game.phase` 分支排序**：

| 当前 `game.phase` | 排序键 | 说明 |
| --- | --- | --- |
| `Betting { round }` | `(current_turn 优先, arrival)` | 当前轮次玩家 tx 排首位，其余按 arrival |
| `MultiPlayerSubmit { kind }` | `arrival`（FIFO） | 多玩家阶段纯 arrival 顺序，不区分优先级 |

**tx 过滤**：仅保留 `tx.lane_hint == TxLane::GameTurn`，Public / ForceSync / CheckpointAnchor 通道 tx 被过滤。

### 10.2 跨 commit 排序保证

多玩家阶段的 tx 可能分布在多个 vertex（跨多个 commit），排序保证：

1. **commit 内**：按 `build_game_sub_block` 规则排序
2. **commit 间**：由 `bullshark_linear_order` 按 `(round, author_pubkey_bytes, vertex_hash)` 线性排序 vertex
3. **跨 commit 防护**：`check_sech6_cross_commit_force_advance()` 校验多玩家阶段前一 commit 有 GameTurn tx 时拒绝 force_advance

### 10.3 SEC-H6 跨 commit 抢跑防护

源码：`poker_l1/src/consensus/vertex_production.rs`

```rust
pub fn check_sech6_cross_commit_force_advance(
    prev_commit_game_turns: &[Transaction],  // 前一 commit 内该 Game 的 GameTurn tx
    force_advance_game_id: &ObjectID,
    game_id: &ObjectID,
    game_phase: GamePhase,
) -> PokerL1Result<()>
```

**校验逻辑**：

| 步骤 | 校验项 | 失败返回 |
| --- | --- | --- |
| 1 | `force_advance_game_id == game_id` | `PokerL1Error::GameNotFound` |
| 2 | `prev_commit_game_turns.is_empty()` | 通过（允许 force_advance） |
| 3 | `!prev_commit_game_turns.is_empty()` | `PokerL1Error::Other("SEC-H6 rejected")`（拒绝） |

**多玩家阶段覆盖**（Phase 5 Task 10 扩展）：

| 当前 `game_phase` | force_advance 行为 |
| --- | --- |
| `Betting { .. }` | 前一 commit 有 GameTurn tx → 拒绝（既有行为） |
| `MultiPlayerSubmit { kind: Shuffle }` | 前一 commit 有 GameTurn tx → **拒绝**（新增） |
| `MultiPlayerSubmit { kind: RevealToken }` | 前一 commit 有 GameTurn tx → **拒绝**（新增） |
| `MultiPlayerSubmit { kind: Reconstruct }` | 前一 commit 有 GameTurn tx → **拒绝**（新增） |
| `MultiPlayerSubmit { kind: LeaveProof }` | 前一 commit 有 GameTurn tx → **拒绝**（新增） |

> **安全语义**：多玩家阶段的 GameTurn tx 会更新 `last_action_height`，因此前一 commit 有此类 tx 时，force_advance 的"超时"前提不成立，须被拒绝。这防止恶意参与者在多玩家阶段中途抢跑 force_advance 偷走底池。

### 10.4 调用示例

```rust
use poker_l1::consensus::{
    build_game_sub_block, check_sech6_cross_commit_force_advance,
    GamePhase, SubmitPhaseKind, TexasHoldemTurnRule,
};

let turn_rule = TexasHoldemTurnRule::new();

// 1. 构建 game sub-block（按阶段排序）
let sub_block = build_game_sub_block(&txs, &game, &turn_rule);

// 2. SEC-H6 校验（多玩家阶段抢跑防护）
let result = check_sech6_cross_commit_force_advance(
    &prev_commit_game_turns,
    &force_advance.game_id,
    &game.id,
    game.phase,  // 如 MultiPlayerSubmit { kind: Shuffle }
);
assert!(result.is_err(), "前一 commit 有 GameTurn tx 时应拒绝 force_advance");
```

---

## 11. 完整一手牌流程示例

### 11.1 流程图

```
┌────────────────────────────────────────────────────────────────┐
│ 1. 新手牌开始：合约层触发，进入 Shuffle 阶段                     │
│    game.phase = MultiPlayerSubmit { kind: Shuffle }              │
│    pending_submitters = active_participants（如 {A, B, C}）       │
│    phase_started_height = last_action_height + 1                 │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 2. 玩家 A/B/C 并行提交 Shuffle tx（VRF output）                  │
│    validate_game_turn_phase_aware():                            │
│      A 提交 → pending = {B, C}, completed = {A}                 │
│      B 提交 → pending = {C},    completed = {A, B}              │
│      C 提交 → pending = {},     completed = {A, B, C}           │
│    is_submission_complete() = true（pending 为空）              │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 3. advance_phase()：Shuffle → RevealToken                       │
│    pending_submitters = active_participants（重置）              │
│    completed_submitters = {}（清空）                             │
│    phase_started_height = last_action_height + 1                │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 4. 玩家 A/B/C 并行提交 RevealToken tx（揭牌）                    │
│    （同上流程，pending 逐步清空）                                 │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 5. advance_phase()：RevealToken → Betting { Preflop }            │
│    pending_submitters = {}（Betting 阶段为空）                   │
│    phase_started_height = last_action_height + 1                │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 6. Betting { Preflop }：按 current_turn 顺序下注                 │
│    A → B → C → A → ...（直至下注结束）                          │
│    advance_turn() 推进 current_turn_player                       │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 7. 后续下注轮次：Flop → Turn → River → Showdown                 │
│    （由合约层推进 BettingRound）                                  │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ 8. 结算：Game 对象 is_finalized = true（冻结为 Immutable）        │
└────────────────────────────────────────────────────────────────┘
```

### 11.2 超时恢复示例

```
┌────────────────────────────────────────────────────────────────┐
│  场景：Shuffle 阶段，玩家 B/C 离线，仅 A 提交                     │
│  pending_submitters = {B, C}（A 已提交，移出 pending）           │
│  completed_submitters = {A}                                     │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  超时触发：current_height > phase_started_height + 100            │
│  is_submit_phase_timed_out() = Some(Shuffle)                    │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  handle_submit_phase_timeout() 执行：                            │
│  1. kick B：active = {A}, pending = {C}, refund B.total_bet     │
│  2. kick C：active = {A}, pending = {},  refund C.total_bet     │
│  3. 检查剩余 active_participants = 1 < 2                        │
│  4. 触发 end_without_showdown：A 获得底池                        │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  返回 Vec<KickResult>:                                          │
│  [                                                              │
│    KickResult { player: B, refund_amount: B.total_bet },        │
│    KickResult { player: C, refund_amount: C.total_bet },        │
│  ]                                                              │
└────────────────────────────────────────────────────────────────┘
```

### 11.3 LeaveProof 跨阶段提交示例

```
┌────────────────────────────────────────────────────────────────┐
│  场景：Betting { Preflop } 阶段，玩家 B 紧急退出                  │
│  game.phase = Betting { round: Preflop }                         │
│  B 提交 LeaveProof tx                                            │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  合约层处理（非 validate_game_turn_phase_aware 职责）：            │
│  1. 校验 B ∈ active_participants                                │
│  2. 从 active_participants 移除 B                                │
│  3. 退款 B.total_bet                                             │
│  4. 若剩余 < 2 → end_without_showdown                            │
│  5. 否则继续下注（current_turn 重新计算）                        │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  场景：MultiPlayerSubmit { kind: LeaveProof } 阶段，玩家 C 退出   │
│  game.phase = MultiPlayerSubmit { kind: LeaveProof }             │
│  C 提交 LeaveProof tx                                            │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  validate_game_turn_phase_aware() 处理（LeaveProof 分支）：       │
│  1. 校验 C ∈ active_participants                                │
│  2. 从 active_participants 移除 C                                │
│  3. 从 pending_submitters 移除 C（若在）                         │
│  4. 插入 completed_submitters                                   │
│  5. 不切换阶段（LeaveProof 保持当前阶段）                        │
└────────────────────────────────────────────────────────────────┘
```

---

## 12. 源码索引与参考

### 12.1 源文件索引

| 模块 | 源文件 | 关键 API |
| --- | --- | --- |
| 阶段枚举与 GameStatus | `poker_l1/src/consensus/routing.rs` | `GamePhase` / `BettingRound` / `SubmitPhaseKind` / `GameStatus` / `ExecutionMode` |
| TurnRule trait | `poker_l1/src/consensus/routing.rs` | `TurnRule` / `SimpleTurnRule` / `PhaseTransitionError` |
| Texas Hold'em 规则 | `poker_l1/src/consensus/texas_holdem_turn_rule.rs` | `TexasHoldemTurnRule` |
| tx 校验 | `poker_l1/src/consensus/routing.rs` | `validate_game_turn_phase_aware` / `validate_turn_order` |
| 超时判定 | `poker_l1/src/block/time_consensus.rs` | `is_submit_phase_timed_out` / `TimeConsensusConfig` |
| 超时惩罚 | `poker_l1/src/consensus/phase_timeout.rs` | `handle_submit_phase_timeout` / `KickResult` |
| sub-block 排序 | `poker_l1/src/consensus/vertex_production.rs` | `build_game_sub_block` / `check_sech6_cross_commit_force_advance` |
| 错误类型 | `poker_l1/src/error.rs` | `PokerL1Error::NotYourTurn` / `PokerL1Error::NotEligibleSubmitter` |
| 地址派生 | `poker_l1/src/account/mod.rs` | `derive_address` |
| 模块 re-export | `poker_l1/src/consensus/mod.rs` | 所有公共 API re-export |

### 12.2 相关文档

| 文档 | 覆盖内容 |
| --- | --- |
| `docs/37-1-node-deployment.md` 5.4 节 | 多玩家阶段超时配置（genesis 参数 + 部署建议） |
| `docs/37-6-dag-consensus-ops.md` 4.5.1 节 | 多玩家阶段 sub-block 排序规则 |
| `docs/37-6-dag-consensus-ops.md` 4.6.1 节 | SEC-H6 多玩家阶段扩展 |
| `docs/37-6-dag-consensus-ops.md` 9.8 节 | 多玩家阶段超时故障排查 |
| `docs/37-6-dag-consensus-ops.md` 10.1 节 | 多玩家阶段监控指标 |
| `docs/37-6-dag-consensus-ops.md` 12.5 节 | 多玩家阶段运维检查清单 |

### 12.3 集成测试参考

| 测试文件 | 覆盖范围 |
| --- | --- |
| `poker_l1/tests/phase6_game_flow.rs` | Phase 6 端到端集成测试（25 个测试，覆盖 SubTask 11.1-11.4） |

测试清单：
- SubTask 11.1（完整一手牌流程）：3 个测试
- SubTask 11.2（超时恢复）：5 个测试
- SubTask 11.3（LeaveProof 随时提交）：4 个测试
- SubTask 11.4（跨 commit 排序）：12 个测试
- E2E（超时后继续游戏）：1 个测试

### 12.4 spec 参考

| spec 文件 | 章节 |
| --- | --- |
| `.trae/specs/extend-game-multiplayer-phases/spec.md` | Phase 1-5 完整规范（FROZEN） |
| `.trae/specs/extend-game-multiplayer-phases/tasks.md` | Task 1-12 任务列表 |
| `.trae/specs/extend-game-multiplayer-phases/checklist.md` | Phase 6 验证项 |

---

## 附录 A：阶段字段速查

| 字段 | 类型 | 默认值 | 阶段切换时变化 |
| --- | --- | --- | --- |
| `phase` | `GamePhase` | `Betting { Preflop }` | 更新为新阶段 |
| `pending_submitters` | `BTreeSet<Address>` | 空 | 重置为新阶段合法提交者 |
| `completed_submitters` | `BTreeSet<Address>` | 空 | 清空 |
| `phase_started_height` | `BlockHeight` | 0 | 更新为 `last_action_height + 1` |
| `current_turn_player` | `Address` | 由 `TurnRule` 计算 | Betting 阶段推进，MultiPlayerSubmit 阶段忽略 |
| `active_participants` | `BTreeSet<Address>` | 初始玩家集 | LeaveProof / kick / fold 时收缩 |
| `last_action_height` | `BlockHeight` | 0 | 每次 GameTurn / checkpoint_anchor 更新 |
| `hand_start_height` | `BlockHeight` | 0 | 新手牌开始时更新 |
| `is_finalized` | `bool` | `false` | 结算后冻结为 `true` |

## 附录 B：超时阈值速查

| 阶段 | 超时阈值（block） | 判定条件 | 超时动作 |
| --- | --- | --- | --- |
| `Betting` | `turn_timeout_blocks` (30) | `current > last_action + 30` | 触发 fallback tx |
| `Shuffle` | `shuffle_timeout_blocks` (100) | `current > phase_started + 100` | kick pending + 退款 |
| `RevealToken` | `reveal_token_timeout_blocks` (50) | `current > phase_started + 50` | kick pending + 退款 |
| `Reconstruct` | `reconstruct_timeout_blocks` (100) | `current > phase_started + 100` | kick pending + 退款 |
| `LeaveProof` | **不超时** | — | — |
| 单手牌最大持续 | `hand_max_duration_blocks` (120/300) | `current > hand_start + max` | 触发 `force_advance` / `request_revert` |

> 注：`turn_timeout_blocks` 默认 30（GovernanceParams）/ 30（TimeConsensusConfig）；`hand_max_duration_blocks` 默认 120（GovernanceParams）/ 300（TimeConsensusConfig），运行时以 `GovernanceParams` 为权威。

---

*文档版本：SubTask 12.3 — 游戏阶段协议文档（`extend-game-multiplayer-phases` spec Phase 6，FROZEN 2026-06-27 spec 对齐）*
