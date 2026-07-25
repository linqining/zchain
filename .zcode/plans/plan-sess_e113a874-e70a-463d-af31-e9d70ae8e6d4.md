# Texas Poker 简化重构方案

目标：消除历史包袱、统一数据结构、对齐电路友好形式。可自由改字段，Rust 主动改为电路友好表示。

## 第 1 步：side_pot.rs — 统一 pot 结构 + 简化分层算法

**数据结构变更**：
- `SidePotResult`：删除 `main_pot`/`main_eligible` 单独字段，统一为 `pots: Vec<SidePot>`（始终含主池作为 `pots[0]`）。`total()` 退化为 `pots.iter().map(|p| p.amount).sum()`。
- `SidePot.eligible_seats`: `Vec<u8>` → `u16` 位掩码（MAX_PLAYERS=9，9 bit 足够）。消除 4 处 `u8::try_from(j).expect(...)` panic 路径，电路友好。

**算法简化**：
- 删除整个 `distribute_pots` 函数（66 行死代码，生产从未调用）。
- 内层 contribution 的 if/else → `min(bet, level) - prev_level`（1 行）。
- 删除单层 `checked_add` 溢出保护（sum_bets 已做全局校验，单层不可能溢出）。
- M-A3/m5 合并逻辑重构为「push 前判断」：构造每层时若 eligible 为空且 pots 非空，直接累加到 `pots.last_mut()`，不 push。删除 pop/push-back/回溯扫描/m5 特例。
- `collect_all_in_bets` 不再去重（循环内 `level <= prev_level` 已跳过重复 level），sort 后直接用。

## 第 2 步：betting.rs — 删死字段 + 合并分支

- 删除 `BettingRound.actions_taken`（全仓 0 次外部读取）。
- 删除 `BettingRound.last_raiser_seat`（全仓 0 次外部读取）。
- 删除 `BettingRound.big_blind`（全仓 0 次外部读取，min_raise 初始值已足够）。
- `process_raise` 的 all-in/非 all-in 两分支合并为：`if raise_amount >= min_raise { 更新 min_raise } else if !is_all_in { return Err }`。
- 删除 M-D8 冗余 assert（136/139 行 early return 已保证不减法下溢）。
- 合并 `new_preflop`/`new_postflop` 为 `new(big_blind, current_bet)`。

## 第 3 步：state_machine.rs — 适配 side_pot 变更 + 简化 rake

- `settle_hand`：适配 `SidePotResult.pots` 统一结构（循环遍历 `result.pots`，`pots[0]` 是主池），删除 main/side 不对称处理。
- `apply_rake_to_pots`：大幅简化——统一 vec 后，rake 按各 pot 占比扣除变成对单一 vec 的循环，删除 main/side 分离逻辑。
- 适配 `eligible_seats` 位掩码：`find_winners_in_seats` 接收位掩码而非 `Vec<u8>`，内部用 bit test 展开。

## 第 4 步：hand_evaluator.rs — 删三态比较 + 简化评估

- 删除 `compare`/`compare_kickers`，直接实现 `Ord`：`category.cmp(...).then_with(|| kickers.cmp(...))`。
- `HandRank.kickers`: `Vec<u8>` → `[u8; 5]`（定长，电路友好）。哨兵改为 `HIGH_CARD + [0,0,0,0,0]`，删除空 kickers 特判。
- 合并 `best_hand` + `evaluate_best_or_partial`：删除占位牌补齐路径（有潜在重复牌 bug），改为 <5 张时返回 `HIGH_CARD` + 现有牌降序 + 0 填充。
- straight 检测合并为单一函数 `straight_high(ranks: &[u8;5]) -> Option<u8>`，删除重复调用和 saturating_sub 防御。
- `evaluate_five_impl` 内删除三处重复的 `kickers.sort`（groups 排序后已降序）。

## 第 5 步：验证

- `cargo build -p poker_l1`
- `cargo test -p poker_l1 --lib texas_poker`（148 个测试需全过，部分测试需适配新 API）
- 手动核对 settle_hand 的资金守恒（rake + 分配 == 原始 pot）

## 风险与回滚

- 测试中直接构造 `SidePot`/`BettingRound`/`HandRank` 的地方需同步改（主要是 side_pot.rs、betting.rs、hand_evaluator.rs 自身的测试）。
- `events.rs` 若事件里引用了 eligible_seats 的 Vec 形式，需适配位掩码（检查后决定）。
- 不动 types.rs 的 `TexasPokerTable`/`Seat` 等核心状态结构（本轮聚焦算法层简化）。