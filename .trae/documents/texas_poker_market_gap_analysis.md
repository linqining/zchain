# Texas Poker 市面对比 & 功能补全 + AIR 电路规划

> 对比对象：PokerStars / GGPoker / Winning / PokerBRO / CoinPoker 等主流在线扑克平台
> 当前项目：`poker_l1/src/vm/contracts/texas_poker`（18 个 dispatch method）
> AIR 现状：`poker_texas_air`（18 个 Method AIR + Aggregator AIR，阶段 4 PoC 已完成）

---

## 1. 当前项目已实现的功能盘点

### 1.1 业务层（poker_l1）— 18 个方法

| 档位 | 方法 | 状态 |
|------|------|------|
| A. 生命周期（6） | `create_table` / `join_table` / `leave_table` / `start_hand` / `tick` / `reset_for_next_hand` | ✅ |
| B. 玩家动作（7） | `fold` / `check` / `call` / `raise` / `auto_fold` / `force_fold` / `kick_player` | ✅ |
| C. Mental Poker 协议（5） | `join_and_shuffle` / `leave_with_proof` / `submit_shuffle_v2` / `submit_player_reveal_tokens` / `submit_reconstruct_deck` | ✅ |

### 1.2 核心机制

- ✅ **游戏类型**：Texas Hold'em（NL）
- ✅ **牌型评估**：7 选 5 最佳手牌，10 种牌型（royal_flush → high_card）
- ✅ **下注轮**：preflop / flop / turn / river / showdown（5 轮）
- ✅ **盲注**：SB / BB
- ✅ **All-in**：含短 all-in（M-D7 修复）
- ✅ **边池分层**：含 M-A3 empty eligible 合并修复
- ✅ **超时驱动**：permissionless `tick`（shuffle / reveal / betting / reconstruct）
- ✅ **Mental Poker 协议**：完整 shuffle / reveal token / reconstruct（BLS12-381 + ElGamal + DLEq / ZKShuffle / RevealTokenProof / ReconstructProof）
- ✅ **管理员操作**：kick / force_fold
- ✅ **状态版本号**：乐观锁（version bump）
- ✅ **ZK skip 模式**：dev chain 友好（mainnet 强制 false）

### 1.3 AIR 层（poker_texas_air）

- ✅ **18 个 Method AIR**（每方法一个专用 AIR）
- ✅ **Aggregator AIR**（二叉树递归聚合 N 个 proof → 1 个）
- ✅ **通用 trace 生成**（`gen_method_trace`）
- ✅ **soundness 测试**（96 个测试全过）

---

## 2. 与市面在线扑克的差距矩阵

### 2.1 P0 — 核心玩法缺失（必须补，影响"可玩性 + 商业化"）

| # | 缺失功能 | 市面参考 | 影响 | 实现复杂度 |
|---|---------|---------|------|----------|
| **G1** | **`bet` 动作**（postflop 主动下注，与 raise 分离） | 所有平台 | postflop 第一个下注者必须用 `raise`，语义混乱 | 低 |
| **G2** | **Rake（抽水）** | 所有真钱平台 | 在线扑克核心收入，无 rake 无法商业化 | 中 |
| **G3** | **Ante / Big Blind Ante (BBA)** | 所有 MTT | 锦标赛前置，无 ante 锦标赛无法跑 | 中 |
| **G4** | **Run It Twice / Three Times** | PokerStars / GGPoker | all-in 时发多次降低方差，高端玩家刚需 | 中 |
| **G5** | **Hand History（对局历史）** | 所有平台 | 玩家复盘、合规审计、反作弊数据源 | 中 |
| **G6** | **Time Bank（思考时间银行）** | 所有平台 | 玩家关键牌可多用时间，避免每手都 30s 限时 | 低 |

### 2.2 P1 — 游戏变体（市场覆盖，扩大用户群）

| # | 缺失功能 | 市面参考 | 用户群占比 | 实现复杂度 |
|---|---------|---------|----------|----------|
| **V1** | **Omaha / Omaha Hi-Lo**（4/5/6 Card） | 所有平台 | ~20% 玩家 | **高**（需 9 选 5 评估、新发牌规则、Hi-Lo split） |
| **V2** | **Short Deck / Six Plus Hold'em**（去 2-5，36 张） | GGPoker 主推 | ~10% 玩家，亚洲市场热门 | 中（牌型重排：A-6-7-8-9 是顺子，三条 > 顺子） |
| **V3** | **Pot-Limit (PL)** | 所有平台 | Omaha 标配 | 低（raise 上限 = pot） |
| **V4** | **Fixed-Limit (FL)** | 老牌平台 | Stud / 老派玩家 | 低（固定加注额度） |
| **V5** | **MTT / SNG（锦标赛）** | 所有平台 | ~40% 玩家 | **极高**（盲注升阶、奖池分配、ICM、bubble、final table） |
| **V6** | **Spin & Go / Jackpot SNG** | PokerStars | 快速休闲 | 高（随机奖池倍数） |

### 2.3 P2 — 增强玩法（差异化 + 留存）

| # | 缺失功能 | 市面参考 | 说明 | 实现复杂度 |
|---|---------|---------|------|----------|
| **E1** | **Straddle / Re-straddle** | Winning / 现金桌 | UTG 自愿双倍盲注，增加行动 | 低 |
| **E2** | **Bring-in** | Stud 游戏 | Stud 强制开注 | 中 |
| **E3** | **Show / Muck 选项** | 所有平台 | showdown 时选择亮牌或埋牌 | 低 |
| **E4** | **Pre-select Actions** | 所有平台 | 预先勾选 fold/check，UX | 低（客户端层） |
| **E5** | **Auto-rebuy / Top-up** | 所有平台 | 筹码低于阈值自动补货 | 低 |
| **E6** | **Bad Beat Jackpot** | 很多平台 | 强牌被爆冷累积奖池 | 中（需要全局累积池合约） |
| **E7** | **Deal Making / Final Table Chop** | MTT | 按剩余筹码分配奖金 | 中（ICM 计算） |

### 2.4 P3 — 经济/运营系统

| # | 缺失功能 | 市面参考 | 说明 | 实现复杂度 |
|---|---------|---------|------|----------|
| **O1** | **Rakeback / VIP / Rewards** | 所有真钱平台 | 玩家返水，影响留存 | 高（需要独立积分系统） |
| **O2** | **Leaderboard / Ranking** | 所有平台 | 周/月排行 | 低（独立合约） |
| **O3** | **Spectator / 观战模式** | 部分平台 | 延迟观战，社交 | 中 |
| **O4** | **Table Cap / Waitlist** | 所有平台 | 满桌排队 | 中 |
| **O5** | **Pause Table** | 现金桌 | 玩家暂停 | 低 |

### 2.5 P4 — 反作弊与公平

| # | 缺失功能 | 市面参考 | 说明 | 实现复杂度 |
|---|---------|---------|------|----------|
| **A1** | **Collusion Detection（串通检测）** | 所有平台 | 同桌玩家合谋，链下分析 | 极高（ML + 规则） |
| **A2** | **RTA / Bot Detection** | 所有平台 | 实时辅助/机器人检测 | 极高（行为指纹） |
| **A3** | **Multi-Accounting Prevention** | 所有平台 | 一人多号 | 中（KYC + 设备指纹） |
| **A4** | **Hand History 审计 API** | 合规平台 | 监管/审计接口 | 低（基于 G5） |

### 2.6 P5 — 社交 / UX

| # | 缺失功能 | 市面参考 | 说明 | 实现复杂度 |
|---|---------|---------|------|----------|
| **U1** | **Chat** | 所有平台 | 桌内聊天 | 低 |
| **U2** | **Emotes / Reactions** | GGPoker / PokerBRO | 表情/互动 | 低 |
| **U3** | **Avatar / Profile** | 所有平台 | 头像/个人页 | 低（独立资源合约） |
| **U4** | **Hand Replayer** | 所有平台 | 复盘回放 | 中（基于 G5） |

---

## 3. 补全优先级与 AIR 电路规划

### 3.1 总体路线图（建议 4 阶段）

```text
┌─────────────────────────────────────────────────────────────┐
│  Phase α (P0 核心)  →  Phase β (P1 变体)  →               │
│  Phase γ (P2 增强)  →  Phase δ (P3/P4/P5 运营/社交)        │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Phase α — P0 核心补全（优先级最高）

每项功能都需要 **3 件套**：① poker_l1 业务实现 ② poker_texas_air Method AIR ③ E2E + soundness 测试

| # | 功能 | 新增 method | 新增 AIR | 业务工作量 | AIR 工作量 |
|---|------|-----------|---------|----------|----------|
| α1 | `bet` 动作 | `bet` | `BetAir` | 0.5d | 0.5d |
| α2 | Rake 抽水 | `collect_rake`（hook in `start_hand`/`settle`） | `RakeAir` | 2d | 1.5d |
| α3 | Ante / BBA | 修改 `start_hand` + 新增 `TableConfig.ante_mode` | `AnteAir`（并入 start_hand 或独立） | 1.5d | 1d |
| α4 | Run It Twice | `run_it_twice` + 修改 all-in 流程 | `RunItTwiceAir` | 3d | 2d |
| α5 | Hand History | `get_hand_history`（view 方法）+ event 索引 | `HandHistoryAir`（聚合 event） | 2d | 1.5d |
| α6 | Time Bank | 修改 `tick` + `seat.time_bank_ms` | `TimeBankAir`（并入 tick） | 1d | 0.5d |

**Phase α 合计**：约 6 个新 AIR，业务 ~10d，AIR ~7d

### 3.3 Phase β — P1 游戏变体

| # | 功能 | 新增 method | 新增 AIR | 业务工作量 | AIR 工作量 |
|---|------|-----------|---------|----------|----------|
| β1 | **Pot-Limit (PL)** | 修改 `raise` 加上限 | `RaisePLAir`（或参数化 RaiseAir） | 1d | 0.5d |
| β2 | **Fixed-Limit (FL)** | 修改 `raise` 固定额度 + 轮次数 | `RaiseFLAir` | 1.5d | 1d |
| β3 | **Short Deck (6+)** | 新 `game_mode=ShortDeck` + 牌型重排 | `ShortDeckEvalAir` + 修改发牌 | 3d | 2d |
| β4 | **Omaha** | 新合约 `omaha_poker`（4 张手牌，必须用 2 张） | `OmahaEvalAir`（9 选 5） | 8d | 5d |
| β5 | **MTT 锦标赛** | 新合约 `tournament`（盲注升阶、奖池、bubble） | `TournamentAir` 系列 | 15d | 8d |

**Phase β 合计**：~10 个新 AIR，业务 ~30d，AIR ~17d

### 3.4 Phase γ — P2 增强玩法

| # | 功能 | 新增 method | 新增 AIR |
|---|------|-----------|---------|
| γ1 | Straddle | `post_straddle` | `StraddleAir` |
| γ2 | Show / Muck | 修改 showdown 流程 | `ShowMuckAir` |
| γ3 | Pre-select | 客户端为主 | 无（链下） |
| γ4 | Auto-rebuy | `auto_rebuy` | `AutoRebuyAir` |
| γ5 | Bad Beat Jackpot | 全局 `jackpot_pool` 合约 | `JackpotAir` |
| γ6 | Deal Making | `propose_chop` / `accept_chop` | `ChopAir` |

### 3.5 Phase δ — 运营/社交（多为独立合约，不影响主牌局 AIR）

O1-O5、A1-A4、U1-U4 基本都是独立模块，对核心 18 + α + β 的 AIR 无侵入。

---

## 4. 关键技术挑战

### 4.1 Rake 抽水的 ZK 约束（α2）

```text
难点：rake 计算 = f(pot, stake_level, cap)
- pot 的金额必须由 side_pot 累加而来（已有 side_pot_air）
- rake_rate 通常非线性（5% 上限，cap by stake）
- 需要 range_check_air 保证 rake 在 [0, cap] 内
```

**AIR 设计**：新增 `RakeAir`，约束 `rake_collected == pot * rate / 10000` 且 `rake_collected <= cap`。

### 4.2 Run It Twice 的状态分叉（α4）

```text
难点：all-in 后状态分叉成两条独立路径
- 需要两个独立的 board（flop/turn/river ×2）
- 每条路径独立 settle
- 总奖金 = board1_pot + board2_pot
```

**AIR 设计**：`RunItTwiceAir` 约束两条 board 的 `deck_state.cards_dealt` 连续性 + 双 settle 的金额总和守恒。

### 4.3 Omaha 的手牌评估（β4）

```text
难点：9 选 5 且必须用恰好 2 张手牌 + 3 张公共牌
- 评估复杂度从 C(7,5)=21 → C(4,2)×C(5,3) = 6×10 = 60
- 需要新的 hand_evaluator
```

**AIR 设计**：`OmahaEvalAir` 嵌入 60 路选择约束 + 手牌/公共牌数量强约束。

### 4.4 MTT 锦标赛的盲注升阶（β5）

```text
难点：全局时间驱动 + 多桌同步
- 盲注每 N 分钟升阶（level 1 → 2 → ...）
- 全局奖池累积 + 分配
- bubble 阶段（差一人进钱圈）
- final table deal making
```

**AIR 设计**：新增 `TournamentAir` 系列（`LevelUpAir` / `PrizePayoutAir` / `BubbleAir`），是最大的工作量。

---

## 5. 当前建议的执行顺序

### 推荐：先做 Phase α（P0 核心），因为

1. **G1 bet 动作**：当前语义混乱，影响所有 postflop 逻辑清晰度，**必须先做**
2. **G2 Rake**：无 rake = 无商业模式，是链上扑克能否落地的关键
3. **G3 Ante**：锦标赛前置依赖
4. **G5 Hand History**：合规 + 反作弊数据基础
5. **G4 Run It Twice / G6 Time Bank**：高端玩家体验

### Phase α 完成后，可选择性推进 Phase β：

- **若主攻亚洲市场** → 优先 V2 Short Deck（GGPoker 亚洲主推）
- **若主攻欧美市场** → 优先 V5 MTT（欧美锦标赛文化强）
- **若主攻 Omni 游戏** → 优先 V1 Omaha

---

## 6. AIR 电路架构的扩展性

当前 `poker_texas_air` 架构对扩展友好：

```text
Layer 0: Method AIRs
  ├─ 现有 18 个（已完成）
  ├─ Phase α 新增 6 个（bet/rake/ante/rit2/hh/timebank）
  ├─ Phase β 新增 ~10 个（PL/FL/ShortDeck/Omaha/Tournament）
  └─ Phase γ 新增 ~6 个（straddle/showmuck/autorebuy/jackpot/chop）

Layer 2: Aggregator AIR
  └─ 当前已支持任意 N 个 proof 二叉树聚合（IS_TOP_LEVEL 修复后）

Layer 3: Final Recursion（阶段 5 接入）
  └─ 嵌入 Verifier AIR 递归验证每个子 proof
```

**关键收益**：新增 method 只需添加 MethodKind variant + Method AIR，Aggregator AIR 无需改动（已通用）。
