# 专项排查：betting-authority 与 VM mirror 失步（盲注反向）导致桌面永久卡死

- 日期：2026-09-20
- 触发来源：1000 手真实浏览器联调（`/tmp/poker-air-zchain-1000/`）运行中一次永久卡死（10:24–10:44 UTC，人工重启 texas 恢复）；存证 `/tmp/poker-air-desync-evidence.log`
- 影响面：`poker_texas_air` 服务端（texas crate）；zchain 侧无涉
- 状态：**已修复 + 红绿验证 + 全量回归 209/209 + 实战验证（钉出拦截实证）**
- 排查中追加发现并修复第二独立缺陷：**bot 重注入 join 缓冲竞态**（见 §6）

## 1. 现象

失步手（hand 1789813453）开局 1 秒起，本手全部下注动作被 VM 镜像拒绝：

```
[betting-authority] table 1 call rejected by VM: serialization error: not player's turn
[betting-authority] table 1 check rejected by VM: serialization error: cannot check: bet < current_bet
  [mirror hand_phase=Betting { street: 2(=PreFlop), BettingRound { current_bet: 100, ... }, current_turn: 1 }]
```

拒绝后 `refresh_from_vm` 无法收敛，超时代打（`check_betting_timeout`）fold 的也是游戏层视角的行动者，被 VM 拒后走「强吃 fold」降级路径，仍无法对齐——桌面永久卡死，仅重启可恢复。全程约 2600 条 mirror 拒绝日志中绝大多数是良性客户端噪音（`bet_fail` 为观测指标非结算门），但本类一旦发生即永久卡死。

## 2. 根因（证据链）

两层在**不同时刻**采样座位状态，窗口内状态被并发事件翻转：

1. **10:24:13.01** 新手开局：浏览器座位（seat1，钱包 027e786d…/pk 83cc7e2e…）因断线被转换为 `sitting_out=true`（`start_preflop_shuffle` 的 disconnected→sitting_out 转换）。它的 pk 仍在本手洗牌注册表且完成了洗牌（13.264）。
2. **10:24:14.16–17** 洗牌完成：deal 跳过 seat1（"is sitting out,no deal"）；`record_hand_start` 冻结计划 = **2 人**（seat2/seat3，`[prove-log] plan: 2 participant(s)`），VM 按冻结计划 bootstrap 并**已发好盲注**（HU：SB/BB 落点、current_turn）。
3. **14.17–14.91 之间**：浏览器页面处于 bust-重入座重载循环，websocket **每 ~4 秒重连**，`reconnect_player()`（seat_mgmt.rs:401）**无条件清 `sitting_out=false`**——seat1 在游戏层视角"复活"。
4. **10:24:14.91** HandReveal 完成 → `set_blinds()` 用**当时**的活座标志计算：`active_players().len()==3` → 走**非单挑**盲注路径 → SB/BB/首行动者与 VM（按 2 人冻结计划发的 HU 盲注）**完全反向**。
5. 之后每个动作：游戏层/bot 按自己的盲注布局行动 → VM 按自己的布局拒绝 → `refresh_from_vm` 只同步注额/turn，**无法重排盲注布局** → 永久活锁。

设计缺口：`BettingView` 不携带 street/盲注布局差异检测，且盲注在两层各自独立计算（VM 于 bootstrap、游戏层于 HandReveal 完成时），唯一一致性保障是"两层扫描语义对拍"的静态假设——被窗口内座位标志翻转击穿。

## 3. 修复（三层）

| # | 文件 | 内容 |
|---|---|---|
| 1 | `texas/src/pokergame/table/reveal.rs`（HandReveal 完成分支） | **盲注唯一权威 = VM**：`set_blinds()` 保留（按钮/last_bb 簿记）后，若 VM 视图 `in_betting` 则 `apply_betting_view` 覆写本地盲注账本（bets/stack/pot/turn/call_amount），两层从首动作起逐位一致；同时把**计划外座位钉回 sitting_out**并清掉 `set_blinds` 可能挂上的幻影注额/turn 残影 |
| 2 | `texas/src/pokergame/table/mod.rs` | Table 新增 `hand_excluded_seats: Vec<u32>`（本手钉出名单） |
| 3 | `texas/src/pokergame/table/phases.rs`（`start_preflop_shuffle`） | 下一手开局召回钉出座位（socket 仍存活者清 sitting_out 正常参与）；**玩家主动坐出（SITTING_OUT）不经此名单**，仍需显式 SITTING_IN，语义不受影响 |

`in_betting` 守卫确保 VM 尚在 DealHole 窗口时不会误触发 `advance_to_next_phase` 联锁；无 VM 模式（`TEXAS_SHADOW_PROVER=0`）行为不变。

## 4. 验证

- **回归测试** `reconnect_flap_between_plan_freeze_and_blinds_cannot_invert_blinds`（`full_hand_tests.rs`）：完整复刻事故时序（3 座开局 → seat1 断线转 sitting_out 仍完成洗牌 → 计划冻结 2 人 → `reconnect_player` 翻转 → HandReveal → 盲注），断言游戏层 turn/盲注与 VM 权威逐位一致、计划外座位钉出无残影、首行动 call→check 后正常进翻牌圈。
- **红灯验证**：禁用修复 → 测试在 turn≠VM 断言处 panic（即事故现场）；启用修复 → 通过。
- **全量回归**：`cargo test -p texas` **209/209 通过**（含 shadow_e2e 结算对账、9 人满桌、all-in 终局等既有套件）。

## 5. 遗留观察（非阻塞）

- `check_betting_timeout` 使用游戏层 turn 选超时者：盲注权威化后两层 turn 从首动作起一致，该窗口已闭合；如后续仍见"fold rejected by VM — degrading"告警需另行排查。
- `bet_fail`（客户端噪音拒绝）与 `dleq_proof c1 mismatch`（bot 并发 join 预热路径）为独立观测项，不影响手牌正确性（本手之后所有手的 parity 均干净）。

## 6. 追加排查：bot 重注入 join 缓冲竞态（实战验证中发现）

**现象**（修复验证第一轮）：`[reveal-authority] reveal from unknown pk <bot新pk>` 每手重复（13 分钟 942 次），每手 45s 揭示超时作废、桌面每小时仅 ~10 手（旧 1000 手运行中同症状出现 210 次，量级低未阻断验收）。

**根因**：dev bot 任务的 `record_join`（join 证明预写，`record_hand_start` 下一手消费）**先于入座执行**——bots 注入循环在旧 bot 仍占座时触发重注入，新任务预写新 pk 后 `join_player_and_shuffle` 返回 `PlayerAlreadyInGame`。此时 join 缓冲已指向「没坐下的 pk」，而座位/洗牌注册表/揭示 assignment 用的是在座旧 pk → 计划（VM 参与者）与 assignment 分叉 → VM 拒绝在座 pk 的一切揭示。

**修复（三层，写入侧为主）**：
1. `dev_bot.rs`：**写入守卫**——钱包已有不同 pk 在座时不预写 join 缓冲（防止污染在座 pk 的证明来源）；座位空闲才允许预写。
2. `prove_log.rs`：**消费守卫**——`record_hand_start` 发现缓冲 pk ≠ 座位 pk 时不再采信，并**踢出失配座位（退款）**：在座旧 pk 永远等不到自己的缓冲项（被后来者覆盖），不踢则每手被跳过、桌面卡在「不足 2 人可证明」的 abort 循环；踢出后驱动层 3s 内带新 pk 重进即对齐。
3. 中途实验过「PlayerAlreadyInGame 时回滚缓冲」，实测**错误**：回滚把整条删除而非恢复旧值，留下「有玩家无证明」死座（每手 abort "missing join proof"），已撤销——写入守卫 + 失配踢座才是完备收敛。

**验证**：209/209 回归通过；实战验证轮 `reveal from unknown` 与 `aborted (unprovable)` 归零、节奏恢复 ~40s/手。

## 7. 实战验证（修复后真实浏览器轮，150 手全量收官）

- **150/150 手全部结算锚定 zchain**（`target reached: 150 >= 150`，链高 151），浏览器 DONE sentinel + 扩展 Proof Portal 本地验证 **verified**（Σinputs == pot 守恒，9ms）。
- **盲注钉出拦截 ×14**：`[blinds-authority] seat N in-seat but not in frozen plan — pinned out` 在浏览器重连抖动/bot 换 pk 窗口触发 14 次，每次钉出后手牌正常推进——**事故场景（2026-09-19 单次发生即永久卡死）在修复后 14 次 occurrences 全部无感拦截**。
- join 缓冲竞态收敛：失配踢座 ×3（每次一脚恢复对齐）、`reveal from unknown` 仅 22（单 pk 瞬态脉冲，数秒自愈；坏状态时 13 分钟 942 次）、misalign 型 abort ×0。
- 边缘场景照常覆盖：all-in ×36、bust-重入座 ×27、故意超时代打 ×6 等共 231 次。
- 回归全量 `cargo test -p texas`：**209/209**；红灯验证：禁用盲注修复后 `reconnect_flap_between_plan_freeze_and_blinds_cannot_invert_blinds` 在 turn≠VM 断言处 panic（复现事故），启用即过。

## 8. 修复清单（poker_texas_air，全部已验证）

| # | 文件 | 修复 |
|---|---|---|
| 1 | `texas/src/pokergame/table/reveal.rs` | HandReveal 完成分支：盲注以 VM 权威覆写（in_betting 守卫）+ 计划外座位钉出/清残影 |
| 2 | `texas/src/pokergame/table/mod.rs` | Table 新增 `hand_excluded_seats`（钉出名单） |
| 3 | `texas/src/pokergame/table/phases.rs` | 下一手开局召回钉出座位（socket 存活者）；玩家主动坐出不受影响 |
| 4 | `texas/src/dev_bot.rs` | join 预写写入守卫（在座异 pk 不覆盖） |
| 5 | `texas/src/socket/mod.rs` | `join_player_and_shuffle` 成功路径写锁内**权威覆写** join 缓冲（座位与缓冲原子对齐，竞态终局修复） |
| 6 | `texas/src/starknet/prove_log.rs` | 消费守卫：缓冲 pk ≠ 座位 pk → 踢出退款重对齐 |
| 7 | `texas/src/pokergame/table/full_hand_tests.rs` | 回归测试（红绿验证） |
