# Texas Poker 核心 vs 外部模块化架构讨论

> 基于 `poker_l1/src/vm/contracts/texas_poker` 现状，讨论 4 个议题：
> 1. Hand History 外部化
> 2. Addon/Rebuy 下一手生效设计
> 3. 核心电路精简（哪些状态可剥离）
> 4. 游戏变体（Omaha / ShortDeck / MTT）架构评估

---

## 议题 1：Hand History 外部化（同意，但需要分层）

### 1.1 为什么必须外部化

当前 `events.rs` 有 **40 种事件**，每次 mutation 都 `events.push(...)`：
- 状态对象不直接存历史（events 是 ephemeral `&mut Vec`）
- 但 ZK 证明要保证**事件真实发生**（不能漏报 fold/raise，否则影响结算正确性）

**电路成本对比**：

| 方案 | state_root 输入 | AIR 列数 | 验证内容 |
|------|---------------|---------|---------|
| A. HH 进核心 AIR | events_hash 作为公开输入 | +2 列（hh_pre/post_hash） | 每个 method 内联 `hash_update(event)` |
| B. HH 外部化（推荐） | 不变 | 不变 | 链下索引器从 L1 事件日志读取 |

**方案 B 的正确性保证**：
- 事件本身由 `DispatchResult` 已携带到链层（区块事件日志）
- 核心电路只保证**状态转移正确**（pre_state_root → post_state_root）
- 事件 = 状态转移的「副作用」，由 L1 共识保证不可篡改
- 链下索引器（Hand History Service）订阅区块事件 → 写入独立 DB → 提供 REST/GraphQL 查询

### 1.2 分层设计

```text
┌──────────────────────────────────────────────────────────┐
│  Layer 1: L1 链层（共识保证）                            │
│  ├─ TexasPokerTable 状态（核心）                          │
│  └─ Event Log（40 种事件，每方法 emit） ← 已有，免费       │
├──────────────────────────────────────────────────────────┤
│  Layer 2: ZK 电路层（核心电路）                          │
│  └─ 只证明 state_root 转移，不包含 HH                     │
├──────────────────────────────────────────────────────────┤
│  Layer 3: 索引器（外部服务，可多实现）                    │
│  ├─ 订阅 L1 event log                                    │
│  ├─ 按 hand_id 聚合 → HandHistory 结构                   │
│  └─ 提供查询 API（/player/{addr}/hands、/table/{id}/hh）  │
├──────────────────────────────────────────────────────────┤
│  Layer 4: 客户端（Hand Replayer / 统计）                 │
│  └─ 拉 Layer 3 API 渲染                                  │
└──────────────────────────────────────────────────────────┘
```

**结论**：HH 完全外置，零电路成本。当前 events 机制已经为此设计好了。

---

## 议题 2：Addon / Rebuy 的「下一手生效」设计

### 2.1 业务规约（用户提出的方案）

> "用户 addon 买入下一手牌的筹码，下一手牌记入到筹码"

这是**正确的现金桌/MTT 设计**。原因：

| 当前手牌内入账 | 下一手入账（推荐） |
|--------------|-----------------|
| ❌ 破坏当前 `side_pot` 分层（all-in 后的钱不能凭空增加） | ✅ 当前手牌 pot 不可变 |
| ❌ 玩家可利用 addon 在 all-in 后"加码"破坏结算 | ✅ addon 只影响 `stack`，不动 `bet/total_bet` |
| ❌ 电路需约束 addon 不参与当前 pot | ✅ 电路简单：addon 只改 stack |

### 2.2 状态设计

在 `Seat` 新增字段：

```rust
pub struct Seat {
    // ... 现有字段
    /// 待入账的 addon 金额（下一手 reset_for_next_hand 时合并到 stack）
    pub pending_addon: u64,
    /// addon 总次数（统计用，可选）
    pub addon_count: u8,
}
```

在 `TexasPokerTable` 新增（或外置到资金合约）：

```rust
pub struct TexasPokerTable {
    // ... 现有字段
    /// addon 资金池（与 chip_pool 平行，记录链上资金流）
    pub addon_pool: u64,
}
```

### 2.3 新增 method：`addon`

```rust
pub struct AddonArgs {
    pub seat_index: u8,
    pub amount: u64,
    /// 支付凭证（链上转账 proof / signature）
    pub payment: PaymentProof,
}

pub fn apply_addon(table, seat_index, amount, ...) {
    // 1. 验证 seat 存在且是本桌玩家
    // 2. 验证支付（amount 真实到账）
    // 3. **不立即改 stack**，只累加 pending_addon
    table.seats[seat_index].pending_addon += amount;
    table.addon_pool += amount;
    // 4. emit AddonRequested event（链下索引器记录）
}
```

### 2.4 在 `reset_for_next_hand` 合并 addon

```rust
pub fn reset_for_next_hand(table, events) {
    // 第一阶段：合并 pending_addon 到 stack（在清理 stack==0 之前）
    for s in &mut table.seats {
        if s.pending_addon > 0 && s.is_occupied() {
            s.stack += s.pending_addon;
            s.pending_addon = 0;
            events.push(TexasPokerEvent::AddonCredited { ... });
        }
    }
    // 第二阶段：原有清理逻辑（stack==0 的 seat 被踢）
    // ...
}
```

### 2.5 ZK 电路约束

**新增 1 个 Method AIR：`AddonAir`**

```text
公开输入：seat_index, amount, pre/post_state_root
约束清单（degree ≤ 2）：
  1. is_active * (input_seat_index - expected_seat) = 0
  2. is_active * (pending_addon_post - pending_addon_pre - amount) = 0
     ↑ 关键：约束 pending_addon 精确增加 amount
  3. version_post == version_pre + 1
```

**修改 `ResetForNextHandAir`**（已有 AIR 扩展）：
- 增加 `pending_addon_pre / pending_addon_post` 列
- 约束 `stack_post == stack_pre + pending_addon_pre`
- 约束 `pending_addon_post == 0`

### 2.6 MTT 的 Rebuy vs Addon 区别

| 维度 | Rebuy（MTT 早期） | Addon（MTT 中场休息 / 现金桌） |
|------|-----------------|------------------------------|
| 触发时间 | 玩家筹码 < BB 时 | 任意时刻（或中场休息窗口） |
| 次数限制 | 通常无限制（rebuy 期） | 通常 1 次/手或 1 次/中场 |
| 生效时机 | **立即**（影响下一动作） | **下一手**（不影响当前 pot） |

**建议**：先实现 `addon`（下一手生效），后续 MTT 再加 `rebuy`（立即生效，约束更复杂）。

---

## 议题 3：核心电路精简（剥离非核心状态）

### 3.1 `TexasPokerTable` 字段分类

| 字段 | 类别 | 电路是否需要 | 理由 |
|------|------|------------|------|
| `id` | 标识 | ✅ | 公开输入 |
| `name` | 元数据 | ❌ | 不影响逻辑，state_root 不含 |
| `max_players` / `small_blind` / `big_blind` | 规则 | ✅ | 影响 bet 合法性 |
| `seats[].player/stack/bet/total_bet/folded/all_in/acted_this_round/pk` | 核心 | ✅ | 影响 side_pot/结算 |
| `seats[].is_waiting/left_during_hand/refunded` | 状态标记 | ✅ | 影响退款/aggregated_pk |
| `button` | 位置 | ✅ | 决定盲注/行动顺序 |
| `pot` / `side_pots` | 资金 | ✅ | 结算核心 |
| `community_cards` | 牌 | ✅ | 评估 |
| `round_state` / `betting_round` / `current_turn` | 流程 | ✅ | 状态机核心 |
| `deck_state` | 加密牌 | ✅ | Mental Poker 核心 |
| `shuffle_state` / `reveal_token_state` / `reconstruct_state` | 协议 | ✅ | Mental Poker 核心 |
| **`timestamps`** | ⚠️ 超时 | **可剥离** | 见 3.2 |
| **`timeout_config`** | ⚠️ 配置 | **可剥离** | 见 3.2 |
| **`chip_pool`** | ⚠️ 资金 | **可剥离** | 见 3.3 |
| **`config` (ZK skip)** | dev | **可剥离** | mainnet 强制 false |
| `version` | 锁 | ✅ | 乐观锁 |

### 3.2 超时管理外部化（最大优化点）

**当前痛点**：`timestamps` 7 个字段 + `timeout_config` 7 个字段 = **14 列** 在每个 AIR 里都有。

**外部化方案：Timeout Oracle 合约**

```text
┌─────────────────────────────────────────┐
│  TexasPokerTable（核心，电路化）         │
│  ├─ 移除 timestamps                     │
│  ├─ 移除 timeout_config                  │
│  └─ 只保留：当前阶段 + current_turn       │
├─────────────────────────────────────────┤
│  TimeoutOracle（独立合约，不入电路）     │
│  ├─ table_id → {phase_started_at, ...}   │
│  ├─ table_id → timeout_config            │
│  └─ permissionless tick 查询此合约       │
└─────────────────────────────────────────┘
```

**tick 重构**：
- `tick(now_ms)` 改为 `tick()`（不传时间）
- 核心合约只读 Oracle 提供的 `now_ms`
- Oracle 是独立预编译，不入电路

**电路收益**：每个 AIR 减少 **~14 列**，约束数量减半。

**代价**：tick 不再是核心方法（变成 Oracle 触发 → 核心只处理 `auto_fold`/`on_shuffle_timeout` 等**结果**）。

### 3.3 资金管理外部化

**`chip_pool` 当前只用于记账**（buy_in 累加，无实际转账逻辑）。

**外部化方案**：独立 `Treasury` 合约

```rust
// Treasury 合约（不入电路）
contract Treasury {
    balance: Mapping<player, u64>,
    table_pool: Mapping<table_id, u64>,
    
    fn deposit(player, amount)  // 充值
    fn withdraw(player, amount) // 提现
    fn join_table(player, table_id, buy_in)  // 锁定到桌台
    fn settle(table_id, payouts)  // 结算分发
}
```

**核心合约只持有 `seat.stack`**（虚拟筹码），真实资金在 Treasury。

### 3.4 精简后的核心 state_root 组成

```text
精简前（~30 字段）：           精简后（~18 字段）：
─────────────────────         ─────────────────────
id, name, ...config           id, max_players, sb, bb
max_players, sb, bb           seats[核心 9 字段 × N]
seats[13 字段 × N]            button, pot, side_pots
timestamps (7)         ──→    community_cards
timeout_config (7)     ──→    round_state, betting_round
chip_pool              ──→    current_turn
config (5)             ──→    deck_state
deck_state, ...3 协议状态     shuffle/reveal/reconstruct_state
version                       version
```

**state_root 列数估算**：
- 精简前：~60 列（含 timestamps/config/chip_pool）
- 精简后：~40 列
- **减少 ~33% 电路成本**

### 3.5 建议剥离清单（按收益排序）

| # | 剥离项 | 电路收益 | 业务复杂度 | 风险 |
|---|-------|---------|----------|------|
| 1 | `timestamps` + `timeout_config` | 高（-14 列） | 中（需 Oracle 合约） | 低 |
| 2 | `chip_pool` | 低（-1 列） | 中（需 Treasury 合约） | 低 |
| 3 | `config` (ZK skip) | 低（-5 列） | 低（mainnet 直接硬编码 false） | 低 |
| 4 | `name` | 极低 | 极低 | 无 |

---

## 议题 4：游戏变体架构评估

### 4.1 设计原则

变体差异主要在 3 个维度：
1. **牌型评估规则**（Omaha 9选5、ShortDeck 重排、Stud 7 张）
2. **下注规则**（NL/PL/FL、Ante、Bring-in、Straddle）
3. **流程编排**（MTT 盲注升阶、Spin&Go 随机奖池）

### 4.2 架构方案对比

#### 方案 A：单合约 + game_mode 字段（不推荐）

```rust
pub struct TexasPokerTable {
    game_mode: GameMode,  // Holdem | Omaha | ShortDeck
    // 所有变体字段塞一起
}
```

**问题**：
- 字段膨胀（Omaha 4 张手牌 + Holdem 2 张共存）
- 电路需要 `is_holdem * (...) + is_omaha * (...)` 多路选择，约束复杂
- 每新增变体都要改核心合约

#### 方案 B：Trait 抽象 + 每变体独立合约（推荐）

```rust
// 核心 trait（poker_core crate）
pub trait PokerGame {
    type TableState: BorshSerialize;
    type Action: BorshSerialize;
    type EvalResult;

    fn validate_action(state: &Self::TableState, action: &Self::Action) -> Result<()>;
    fn apply_action(state: &mut Self::TableState, action: &Self::Action) -> Result<()>;
    fn evaluate_hand(...) -> Self::EvalResult;
    fn round_flow() -> RoundFlow;
}

// 每变体独立合约
pub mod holdem_nl { pub struct HoldemTable { ... } impl PokerGame for ... }
pub mod omaha_pl  { pub struct OmahaTable { ... } impl PokerGame for ... }
pub mod short_deck{ pub struct ShortDeckTable { ... } impl PokerGame for ... }
```

**优点**：
- 核心合约各自精简（Holdem 合约无 Omaha 字段）
- 电路各自独立（HoldemNL 的 AIR 不受 Omaha 影响）
- 新增变体 = 新增 crate + 新增 AIR 系列，不动现有

**缺点**：
- 共享逻辑（Mental Poker、side_pot、blind）需抽到公共 crate
- 合约数量增加（每变体一个预编译地址）

#### 方案 C：核心不变 + 变体作为「插件」分层（最佳）

```text
┌──────────────────────────────────────────────┐
│  poker_texas_air (核心电路，已完成)           │
│  ├─ 18 个 Holdem NL Method AIR               │
│  └─ Aggregator AIR (通用聚合)                │
├──────────────────────────────────────────────┤
│  poker_omaha_air (Omaha 变体电路)            │
│  ├─ 复用 Mental Poker AIR (shuffle/reveal)   │
│  ├─ 复用 side_pot AIR                        │
│  └─ 新增: OmahaHandEvalAir (9选5约束)        │
├──────────────────────────────────────────────┤
│  poker_short_deck_air (ShortDeck 变体)       │
│  ├─ 复用大部分 Holdem AIR                    │
│  └─ 新增: ShortDeckEvalAir (牌型重排)        │
├──────────────────────────────────────────────┤
│  poker_tournament_air (MTT 锦标赛)           │
│  ├─ BlindScheduleAir (盲注升阶)              │
│  ├─ PrizePayoutAir (奖池分配 ICM)            │
│  └─ BubbleAir (泡沫阶段)                     │
└──────────────────────────────────────────────┘
```

### 4.3 共享模块抽取（关键重构）

变体之间共享的逻辑应抽到 `poker_common`：

| 共享模块 | 当前位置 | 抽取后 |
|---------|---------|-------|
| Mental Poker 协议 | `state_machine` 内联 | `poker_common::mental_poker` |
| Side Pot 分层 | `side_pot.rs` | `poker_common::side_pot` ✅ 已独立 |
| BettingRound | `betting.rs` | `poker_common::betting` ✅ 已独立 |
| Hand Evaluator | `hand_evaluator.rs` | `poker_common::eval::holdem` |
| Card 类型 | `card.rs` | `poker_common::card` ✅ 已独立 |
| Events | `events.rs` | `poker_common::events` |

**当前项目其实已经接近方案 C**：`side_pot.rs` / `betting.rs` / `card.rs` 都是独立模块。只需把 `hand_evaluator` 按 eval strategy 拆分。

### 4.4 电路影响评估

| 变体 | 复用 AIR | 新增 AIR | 电路工作量 |
|------|---------|---------|----------|
| **Omaha** | Mental Poker (5) + side_pot + betting + Aggregator | `OmahaDealAir`（4 张手牌）、`OmahaEvalAir`（9 选 5，~60 路选择）、`OmahaMustUse2Air`（2 手牌约束） | 高 |
| **ShortDeck** | 几乎全部 Holdem AIR | `ShortDeckDeckAir`（36 张发牌）、`ShortDeckEvalAir`（牌型重排：三条 > 顺子，A 低顺） | 中 |
| **Pot-Limit** | 全部（只改 raise 上限约束） | 无新增（修改 `RaiseAir` 加 `raise <= pot` 约束） | 低 |
| **Fixed-Limit** | 全部 | 无新增（修改 `RaiseAir` 固定额度 + 计数轮次） | 低 |
| **MTT** | 单桌流程复用 | `BlindScheduleAir`、`PrizePoolAir`、`ICMPayoutAir`、`BubbleBreakAir`、`FinalTableAir` | 极高 |

### 4.5 推荐实施顺序

1. **先做 PL/FL**（方案 C 的"低悬果实"）：只改 `RaiseAir`，验证变体架构
2. **再做 ShortDeck**：验证 eval strategy 可替换
3. **最后做 Omaha / MTT**：工作量大，需独立 crate

### 4.6 关键架构决策（需要你拍板）

| 决策点 | 选项 A | 选项 B | 建议 |
|-------|-------|-------|------|
| 变体共享 state_root 编码？ | 共享（统一 layout） | 各自编码 | **B**（各变体独立，避免字段膨胀） |
| Aggregator AIR 跨变体？ | 跨（混合聚合） | 不跨（同变体内聚合） | **B**（同变体内，简化约束） |
| Mental Poker 是否变体无关？ | 是（Omaha 也用） | 否（每变体重写） | **A**（Omaha 也用 ElGamal，可共享） |
| Hand Evaluator 抽 trait？ | 是 | 否 | **A**（已接近） |

---

## 总结：4 议题的联动建议

```text
议题 3（精简核心）  ─┐
                    ├──→ 先做，降低现有电路成本
议题 1（HH 外部化） ─┘

议题 2（Addon）    ────→ 中等优先级，1 个新 AIR + 改 reset AIR

议题 4（变体架构） ────→ 最后做，依赖前 3 议题的稳定核心
                         先 PL/FL 验证架构，再 ShortDeck/Omaha
```

**最小可行路径（MVP）**：
1. 剥离 timestamps/config（议题 3）→ 核心 AIR 减 14 列
2. HH 完全外置（议题 1）→ 零成本
3. 加 Addon AIR（议题 2）→ 现金桌可玩
4. PL/FL 变体（议题 4 起步）→ 验证架构
5. 之后按市场需求推 ShortDeck / Omaha / MTT
