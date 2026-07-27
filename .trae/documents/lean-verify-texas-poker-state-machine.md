# 用 Lean 证明 texas_poker 合约满足德州扑克规范与状态流转正确性

## Context（背景与动机）

`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/` 是 zchain L1 上的德州扑克原生预编译合约（~10,000 行 Rust），移植自 Sui Move 版本。合约包含 4 个嵌套状态机（round / shuffle phase / reveal phase / reconstruct phase）、Mental Poker 密码学协议、以及纯算法（`hand_evaluator` / `side_pot` / `betting`）。

现有补充验证 `poker_texas_air/` 用 Stwo（STARK）证明/验证**单方法** AIR 约束（`e2e_lifecycle.rs` 测 join_table / leave_table / start_hand / tick / reset_for_next_hand 等）。这是**每方法** ZK 证明，**不**覆盖：

- 跨方法的**全局状态机**合法流转（round 单调推进、子相位合法转移、跨机一致性）
- **chip 守恒**（筹码不增不减、不双花）
- **side pot** 分层正确性（守恒、资格单调、folded 玩家永不合格）
- **hand evaluator** 全序性与 best-5-of-7 正确性
- **betting** 规则合法性

用户的诉求是用 Lean 4 形式化证明填补上述缺口。已确认决策：**手工镜像建模** + **完整 6 模块范围** + **范围内严禁 `sorry`**。

## 关键发现：现有 `poker_lean/` 项目

`/Users/mac/projects/zchain/poker_lean/` 已存在完整 Lake 项目（Lean 4.13.0 + Mathlib v4.13.0，5.5 GB 缓存），143,390 行 Lean，含 13 个 Contract 模块 + 13 个 AIR 模块 + 13 个 Soundness 证明，焦点是 per-method AIR soundness（与 `poker_texas_air` 对齐）。

类型镜像现状：
- `RoundState.toNat`（`PokerLean/Contract/Types.lean:78-80`）**已正确**保留 PREFLOP=2 跳号，与 Rust 一致 ✓
- `BettingRoundState`（`Types.lean:108`）有 8 字段（含 current_turn / dealer_seat / pot / side_pots / last_aggressor / num_raises），而 Rust `BettingRound` 仅 2 字段（current_bet, min_raise）✗
- `TexasPokerTable`（`Types.lean:151`）约 25 字段，Rust 实际 64 字段（缺 id / name / creator / community_cards / deck_state / timeout_config / timestamps / ante_* / rake_* / rit_mode / config / version 等约 40 个）✗

## 架构决策

1. **扩展现有 `poker_lean/`，不新建项目**：复用 Mathlib 缓存（节省 30-60 min 首编）；新增 `PokerLean/State/` 子目录承载状态机正确性工作；不动现有 `Contract/` / `AIR/` / `Proofs/`，避免破坏 AIR soundness。
2. **`State/Types.lean` 重新定义类型**：不复用陈旧的 `Contract/Types.lean.TexasPokerTable`；新类型用 `namespace TexasPoker`，与现有 `PokerLean` 命名空间隔离。长期可在 `Refinement.lean` 写桥接引理。
3. **Chip 用 `Nat` + 显式上界不变量** `inv_chip_bounds`：Rust `saturating_sub` → Lean `Nat` 减法配 `a ≥ b` 前置；`checked_add` → `a + b ≤ MAX_TOTAL_BET` 前置。不用 `Fin (10^18+1)`（不归约、`omega` 弱）。
4. **座位用 `List Seat` + 长度不变量** `seats.length = max_players ∧ max_players ≤ 9`：与现有项目一致；`Fin 9` 在变量 `max_players` 下不归约。
5. **依赖 Mathlib**：chip 守恒需 `omega` / `linarith` / `BigOperators`；`evaluate_best_is_maximum` 需 `List.subsets` 系列。缓存已存在，零成本。
6. **范围内严禁 `sorry`**；硬定理拆引理逐个攻破。`axiom` 仅限抽象密码学（M31/Poseidon/state preimage），与状态机证明无关。

## 项目结构

```
poker_lean/                                 # 现有项目根
├── lakefile.lean                            # 已 require mathlib v4.13.0，不动
├── lean-toolchain                          # leanprover/lean4:v4.13.0，不动
├── PokerLean.lean                          # 顶层，追加 State/* 的 import
├── PokerLean/{Contract,AIR,Proofs,Common,Audit}/   # 现有，不动
└── PokerLean/State/                        # 新增：状态机正确性
    ├── Basic.lean                          # Nat/List/位掩码工具引理
    ├── Constants.lean                      # 镜像 constants.rs（保留 PREFLOP=2 跳号）
    ├── Card.lean                           # 镜像 card.rs（Card, 花色常量）
    ├── Types.lean                          # 镜像 types.rs（TexasPokerTable 64 字段 / Seat 14 字段 / 4 个 State 子结构）
    ├── RoundMachine.lean                   # Phase 1
    ├── Betting.lean                        # Phase 2（BettingRound + process_*）
    ├── Transitions.lean                    # Phase 2（apply_fold/check/call/raise 镜像）
    ├── Invariants.lean                     # Phase 2/6（chip 守恒 + 状态不变量）
    ├── SidePot.lean                        # Phase 3
    ├── HandEvaluator.lean                  # Phase 4
    ├── SubPhases.lean                      # Phase 5（shuffle/reveal/reconstruct）
    ├── Theorems.lean                       # Phase 6（顶层集成）
    └── Refinement.lean                     # Phase 6（模型↔代码精化论证 + Rust panic-freedom 义务）
```

命名空间：所有新工作用 `namespace TexasPoker`，与现有 `PokerLean.*` 并存无冲突。

## 6 阶段实施计划

每阶段产出**可编译、无 `sorry`** 的检查点。Phase 2 是最高风险阶段（chip 流路径多），故拆分最细。

### Phase 1 — 基础与 Round 状态机（~400-700 LOC，低风险）

**目标**：搭骨架 + 证 round 状态机单调推进。

**文件**：`Basic.lean` / `Constants.lean` / `Card.lean` / `Types.lean` / `RoundMachine.lean`

**关键镜像**（`constants.rs` ↔ `Constants.lean`）：
- `ROUND_WAITING=0, ROUND_PREFLOP=2, ROUND_FLOP=3, ROUND_TURN=4, ROUND_RIVER=5, ROUND_SHOWDOWN=6`
- `SHUFFLE_PHASE_NONE/WAITING/RECONSTRUCT/BEFORE_PREFLOP = 0/1/2/3`
- `REVEAL_PHASE_NONE/PREFLOP/REDEAL/FLOP/TURN/RIVER/SHOWDOWN = 0/1/2/3/4/5/6`
- `RECONSTRUCT_PHASE_NONE/COLLECTING/COMPLETE = 0/1/2`
- `MAX_PLAYERS=9, CARDS_PER_PLAYER=2, N_CARDS=52, MAX_TOTAL_BET=10^18`

**关键镜像**（`types.rs:462-565` ↔ `Types.lean`）：`TexasPokerTable` 全 64 字段；`Seat` 全 14 字段；`ShuffleState` / `RevealTokenState` / `ReconstructState` / `DeckState` / `TimeoutConfig` / `Timestamps` / `TableConfig`。密码学字段（`pk: ECPoint`、`coefficient`、`ciphertext`）用不透明 `ECPoint : Type` 占位。

**关键定理**（`RoundMachine.lean`）：
- `round_step_legal : RoundState → RoundState → Prop`，定义为白名单 `{(WAITING,PREFLOP), (PREFLOP,FLOP), (FLOP,TURN), (TURN,RIVER), (RIVER,SHOWDOWN), (∀X, X→WAITING on reset)}`
- `round_monotonic`：`∀ s s', round_step_legal s s' → s.toNat ≤ s'.toNat ∨ s' = WAITING`
- `round_no_skip`：`round_step_legal ROUND_PREFLOP ROUND_RIVER = False`
- `round_reset_only_to_waiting`：`round_step_legal s s' → s' ≠ WAITING → s.toNat < s'.toNat`

**对应 Rust**：`state_machine.rs:586-613`（`advance_round`），`state_machine.rs:2837`（`reset_for_next_hand` 设 `ROUND_WAITING`）。

**验证**：`lake build PokerLean.State.RoundMachine` 通过且无 `sorry`。

### Phase 2 — Betting 规则 + Chip 守恒（~1500-2500 LOC，**极高风险**）

**目标**：证 betting 规则合法 + 单步 `apply_*` chip 守恒 + 状态不变量。

**文件**：`Betting.lean` / `Transitions.lean` / `Invariants.lean`

**关键镜像**（`betting.rs:17-122` ↔ `Betting.lean`）：`BettingRound { current_bet, min_raise }`、`process_call`、`process_raise`、`available_actions`、`chips_to_call`、`can_check/can_call/can_raise`。

**关键镜像**（`state_machine.rs:1895-2123` ↔ `Transitions.lean`）：`apply_fold_internal` / `apply_check` / `apply_call` / `apply_raise`（仅这 4 个纯下注动作；`tick` / `settle_hand` / `reset_for_next_hand` 推到 Phase 6）。

**关键定理**（`Betting.lean`）：
- `process_raise_strictly_increases_current_bet`：`process_raise r tb sb st = Ok n → (result r).current_bet > r.current_bet`（前置来自 `betting.rs:100`）
- `min_raise_nondecreasing`：`(result r).min_raise ≥ r.min_raise`（**无需 except 子句**：短 all-in 时 `min_raise` 不变仍满足非递减）
- `chips_to_call_correct`：`chips_to_call r sb = max (r.current_bet - sb) 0`
- `available_actions_sound`：mask 中每个 bit 对应的 action 都满足其 `can_*` 前置

**关键定理**（`Invariants.lean`，chip 守恒**拆分**为多个独立引理）：
- `total_chips_def`：`totalChips t = Σ seats[i].stack + Σ seats[i].bet + Σ seats[i].total_bet + t.pot + t.rake_collected + t.addon_pool + Σ seats[i].pending_addon`
- `apply_fold_chip_conservation`：`apply_fold t i → totalChips t' = totalChips t`（fold 不动 chip，仅切 folded 标志）
- `apply_check_chip_conservation`：同上
- `apply_call_chip_conservation`：`Δ(seats[i].stack) = -Δ(seats[i].bet)`，`totalChips` 不变
- `apply_raise_chip_conservation`：同 call
- `collect_ante_chip_conservation`（独立引理）：`ΔΣ(stack) = -Δ(ante_collected)`
- `collect_rake_chip_conservation`（独立引理）：`Δ(pot) = -Δ(rake_collected)`
- `apply_addon_chip_conservation`（独立引理）：`Δ(pending_addon) = +amount`，`totalChips` 增 `amount`
- `apply_rebuy_chip_conservation`（独立引理）：`Δ(stack) = +amount`，`totalChips` 增 `amount`
- `refund_all_bets_chip_conservation`（独立引理）：退还总额 = `Σ total_bet`
- `inv_chip_bounds`：`∀ i, seats[i].total_bet ≤ MAX_TOTAL_BET ∧ t.pot ≤ MAX_TOTAL_BET ∧ Σ total_bet ≤ MAX_TOTAL_BET`，证各 `apply_*` 保持

**关键状态不变量**（`Invariants.lean`，对应 Plan agent 第 5 节缺失项）：
- `current_turn_well_formed`：`current_turn = some i → i < max_players ∧ is_participating(seats[i]) ∧ ¬folded ∧ ¬all_in`
- `betting_round_completion`：`is_betting_complete t = true → ∀ i, is_participating(seats[i]) → acted_this_round ∧ bet = current_bet`
- `inv_state_consistency`（原 cross_machine_consistency，**改归 Phase 2**）：`is_betting_round t.round_state → t.shuffle_state.phase = NONE ∧ t.reveal_state.reveal_phase = NONE ∧ t.reconstruct_state.phase = NONE`
- `addon_pending_semantics`：`pending_addon > 0 → stack` 在当前手不变
- `version_strictly_monotone`：每次 mutation `version' = version + 1`（前置 `version < u64::MAX`）

证 `apply_fold/check/call/raise` 保持上述所有不变量。

**对应 Rust**：`betting.rs`、`state_machine.rs:1895-2123`、`state_machine.rs:3281-3344`（collect_ante）、`state_machine.rs:3345-3382`（collect_rake）、`state_machine.rs:2984-3133`（addon/rebuy）。

**验证**：`lake build PokerLean.State.{Betting,Transitions,Invariants}` 通过且无 `sorry`。

### Phase 3 — Side Pot 正确性（~800-1200 LOC，中风险）

**目标**：证 `calculate_side_pots` 守恒、资格正确、决定性。

**文件**：`SidePot.lean`

**关键镜像**（`side_pot.rs:110-200` ↔ `SidePot.lean`）：`SidePot { amount, eligible_seats: Nat (u16 位掩码) }`、`calculate_side_pots`、`slice_layer`、`push_or_merge`、`sum_bets`。Rust `sort_unstable` → Lean `List.mergeSort`。

**关键定理**：
- `side_pot_conservation`：`(calculate_side_pots bets folded all_in).pots.map amount |>.sum = bets.sum`（关键：`push_or_merge` 的合并不破坏守恒，需 telescope）
- `folded_not_eligible`：`folded[i] = true → ∀ p ∈ result.pots, ¬is_eligible p.eligible_seats i`（来自 `side_pot.rs:178`）
- `all_in_eligible_up_to_level`：`all_in[i] ∧ ¬folded[i] → ∀ p with level ≥ bets[i], is_eligible p i`
- `side_pot_eligibility_nested`：`∀ i < j, eligible(pots[j]) ⊆ eligible(pots[i])`（Plan agent 缺失项 #3）
- `side_pot_deterministic`：同输入 → 同输出（来自 `mergeSort` 决定性）
- `side_pot_amount_nonneg` / `side_pot_amount_bounded`

**删除** `side_pot_no_panic`（Lean 全函数天然无 panic；Rust panic-freedom 移到 `Refinement.lean` 作为精化义务）。

**对应 Rust**：`side_pot.rs:110-200`。

**验证**：`lake build PokerLean.State.SidePot` 通过且无 `sorry`。

### Phase 4 — Hand Evaluator（~1000-1500 LOC，中风险）

**目标**：证 `HandRank` 全序 + `evaluate_best` 是 5-子集最大值。

**文件**：`HandEvaluator.lean`

**关键镜像**（`hand_evaluator.rs:32-129` ↔ `HandEvaluator.lean`）：`HandRank { category: Nat, kickers: List Nat }`（用 List 配长度不变量，避免 `[u8;5]` 麻烦）；`evaluate_five`、`evaluate_best`（用 `List.subsetsLen 5` 替代 Rust 五重循环）。

**关键定理**：
- `handrank_total_order`：`DecidableEq HandRank ∧ trichotomy ∧ antisymmetry ∧ transitivity`
- `handrank_category_order`：category 优先，category 高者胜
- `evaluate_best_is_maximum`：`evaluate_best cards ≥ evaluate_five sub` 对所有 `sub ∈ cards.subsetsLen 5`（用 `List.foldl_max_is_maximum` 类引理）
- `evaluate_best_deterministic`：全函数即决定性
- `hand_unique_cards`（Plan agent 缺失项 #4，作为前置不变量）：`community_cards ++ seats[i].hand` 无重复

**对应 Rust**：`hand_evaluator.rs:32-129`。

**验证**：`lake build PokerLean.State.HandEvaluator` 通过且无 `sorry`。

### Phase 5 — 子相位状态机（~600-900 LOC，中风险）

**目标**：证 shuffle / reveal / reconstruct 三个子相位合法转移 + 跨机一致性。

**文件**：`SubPhases.lean`

**关键镜像**（`state_machine.rs:636-712` `advance_shuffle`、`state_machine.rs:920-940` `advance_reveal`、`state_machine.rs:1594-1668` `apply_submit_reconstruct_deck`）。

**关键定理**：
- `shuffle_phase_legal_transitions`：白名单 `{NONE→WAITING, WAITING→RECONSTRUCT, RECONSTRUCT→BEFORE_PREFLOP, BEFORE_PREFLOP→NONE, X→NONE on reset}`
- `shuffle_phase_monotonic`：非 reset 路径 `toNat` 单调
- `reveal_phase_legal_transitions`：白名单 `{NONE→PREFLOP, PREFLOP→REDEAL, REDEAL→FLOP, FLOP→TURN, TURN→RIVER, RIVER→SHOWDOWN, SHOWDOWN→NONE, X→NONE on reset}`
- `reveal_phase_monotonic`：非 reset 路径单调
- `reconstruct_phase_legal_transitions`：白名单 `{NONE→COLLECTING, COLLECTING→COMPLETE, COMPLETE→NONE}`
- `subphase_chip_neutral`：shuffle / reveal / reconstruct 转移**不修改** chip 字段（`stack / bet / total_bet / pot` 不动），为 Phase 6 `tick` 守恒铺路

**对应 Rust**：`state_machine.rs:636-712, 920-940, 1594-1668, 2179-2335`。

**验证**：`lake build PokerLean.State.SubPhases` 通过且无 `sorry`。

### Phase 6 — 集成定理与精化论证（~1500-2500 LOC，高风险）

**目标**：组合 Phase 1-5 的结果，证顶层集成定理 + 写模型↔代码精化论证。

**文件**：`Theorems.lean` / `Refinement.lean`

**关键定理**（`Theorems.lean`）：
- `tick_chip_conservation`：`tick t → totalChips t' = totalChips t`（依赖 Phase 2 + Phase 5 `subphase_chip_neutral`）
- `settle_hand_chip_conservation`：`settle_hand t → totalChips t' + rake_collected' = totalChips t`（依赖 Phase 2 + Phase 3 + Phase 4）
- `reset_for_next_hand_clears_per_hand_state`（Plan agent 缺失项 #9）：reset 后 `round_state = WAITING ∧ pot = 0 ∧ side_pots = [] ∧ community_cards = [] ∧ ∀ i, bet = 0 ∧ total_bet = 0 ∧ folded = false ∧ all_in = false`
- `button_advances_to_next_active`（Plan agent 缺失项 #5）
- `refund_no_double_refund`（Plan agent 缺失项 #8）：`refunded = true → 不再退款`
- `rake_bounded`（Plan agent 缺失项 #7）：`rake ≤ pot_before ∧ rake ≤ rake_cap`
- `find_winners_in_seats_soundness`（Plan agent 缺失项 #11）：winners 中每个 seat 的 HandRank ≥ 所有 eligible seat 的 HandRank
- `distribute_pot_no_overflow`（Plan agent 缺失项 #12）：`Σ amount = pot`
- `state_transition_preserves_invariants`：任意 `dispatch_* → apply_*` 链保持 `inv_chip_bounds ∧ inv_state_consistency ∧ current_turn_well_formed ∧ betting_round_completion`
- `hand_lifecycle_legal`：完整一手生命周期（start_hand → shuffle → preflop → ... → showdown → settle → reset）的状态序列满足所有不变量

**精化论证**（`Refinement.lean`，文档化 + 部分桥接引理）：
- 列出每个 Lean 类型/函数 ↔ Rust file:line 的对应表
- 列出 Rust panic-freedom 义务（如 `side_pot.rs:196` `pots.last_mut().expect`、`betting.rs:29` `assert!(big_blind > 0)`、`state_machine.rs:196` `expect("pots 非空")`），证明在不变量成立时这些不可达
- 列出抽象密码学 `axiom`（M31 / Poseidon / state preimage）与状态机证明的隔离性

**对应 Rust**：`state_machine.rs:2179-2474`（tick/end_without_showdown）、`state_machine.rs:2479-2541`（settle_hand）、`state_machine.rs:2682-2855`（reset_for_next_hand）、`dispatch.rs:442-499`。

**验证**：`lake build PokerLean.State.{Theorems,Refinement}` 通过且无 `sorry`；`#print axioms` 仅显示 `propext` / `Classical.choice` / 已声明的密码学 axiom。

## 关键不变量清单（贯穿各阶段）

1. `inv_chip_bounds` — Phase 2
2. `inv_state_consistency` — Phase 2
3. `current_turn_well_formed` — Phase 2
4. `betting_round_completion` — Phase 2
5. `addon_pending_semantics` — Phase 2
6. `version_strictly_monotone` — Phase 2
7. `side_pot_eligibility_nested` — Phase 3
8. `hand_unique_cards` — Phase 4
9. `subphase_chip_neutral` — Phase 5
10. `reset_clears_per_hand_state` — Phase 6
11. `rake_bounded` — Phase 6
12. `refund_no_double_refund` — Phase 6

## 验证方法（端到端）

1. **每阶段编译检查**：`cd /Users/mac/projects/zchain/poker_lean && lake build PokerLean.State.<Module>`
2. **全量构建**：`lake build PokerLean`（含现有 AIR + 新 State）
3. **无 sorry 审计**：
   ```bash
   cd /Users/mac/projects/zchain/poker_lean
   # 确认 PokerLean/State/ 下无 sorry
   grep -rn "sorry" PokerLean/State/ && echo "FOUND SORRY" || echo "NO SORRY"
   # 顶层定理仅依赖允许的 axiom
   lake env lean PokerLean/State/Theorems.lean 2>&1 | grep axiom
   ```
4. **`#print axioms` 抽查**：在 `Theorems.lean` 末尾对 `state_transition_preserves_invariants` 加 `#print axioms`，确认输出仅 `propext` / `Classical.choice` / 显式声明的密码学 axiom。
5. **与 Rust 测试对账**：`poker_l1` 现有单元测试（`betting.rs` tests、`side_pot.rs` tests、`hand_evaluator.rs` tests、`dispatch.rs:1410 e2e_full_hand_lifecycle`）的断言应作为 Lean 定理的具体实例，确认 Lean 模型语义与 Rust 一致。

## 风险与缓解

| 风险 | 缓解 |
|---|---|
| Phase 2 chip 守恒路径多，撞 `sorry` 墙 | 已拆分为 8 个独立引理；先证 4 个纯下注动作，ante/rake/addon/refund 各自单独 |
| `evaluate_best_is_maximum` 21 组合枚举冗长 | 用 `List.subsetsLen 5` + `List.foldl_max_is_maximum`，不手展开 21 路 |
| 类型镜像再次陈旧 | `Refinement.lean` 强制列出每个字段的 Rust file:line；任何 Rust 改动需同步 |
| Lean 4.13.0 与 Mathlib v4.13.0 锁定 | 沿用现有 `lean-toolchain` 与 `lake-manifest.json`，不升级 |
| 现有 `Contract/Types.lean` 陈旧类型误导 | `State/Types.lean` 用 `namespace TexasPoker` 隔离；`Refinement.lean` 写桥接引理记录差异 |

## 不在范围内

- Mental Poker 密码学协议正确性（VRF / ElGamal / Chaum-Pedersen DLEq / ZK 证明系统）
- `poker_protocol` crate 内部密码学实现
- ZK proof 验证逻辑（`utils.rs` 的 `verify_or_skip` 在 `zk_skip_enabled` 下的 dev chain 路径）
- `trigger_run_it_twice` 的两次发牌语义
- `tick` 的完整超时状态空间枚举（仅证 chip 守恒 + 不破坏不变量，不证超时触发顺序）
- 现有 `poker_lean/Contract/` / `AIR/` / `Proofs/` 的迁移到新类型

## 实施顺序

Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6。

Phase 4 可与 Phase 2/3 并行（无依赖），但本轮按顺序推进以控制上下文。每阶段完成后 `lake build` 验证再进入下一阶段。
