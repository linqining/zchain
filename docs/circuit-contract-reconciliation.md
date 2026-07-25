# 电路 ↔ 合约一致性核对报告

> 范围：`poker_texas_air/src/`（AIR 电路）vs `poker_l1/src/vm/contracts/texas_poker/`（rBPF 合约）。
> 日期：2026-07-25。
> 结论：**21 个方法 AIR 目前均为 PoC，仅约束"输入一致性 + 极少量输出 flag"，绝大多数业务算术/状态守卫未在电路中强制**。本报告逐方法列出差异，并标注哪些是"明确的语义错误（必修）"、哪些是"低悬挂果实（本轮补约束）"、哪些是"阶段 5 高级约束（本轮不做）"。

## 0. 架构总览

- 电路侧 `method_kind.rs` 的 21 个 variant 与合约 `dispatch::selectors::all()` 的 21 个方法名一一对齐；selector 算法两端一致（`blake2b_256(method_name)`）。
- 电路侧 **不 import 合约业务逻辑**：`airs/` 下无任何 `use poker_l1::` 导入，业务规则全靠人工转录成注释 + 极少量约束。唯一耦合点是 `state_root.rs`/`merkle_tree.rs`/`prove_task.rs`/`orchestrator.rs` 引用合约类型（`TexasPokerTable`/`Seat` 等）。
- 通用列布局 `common.rs`：37 列，含 `pre/post_round_state`、`pre/post_pot[4]`、`pre/post_button`。**但 `CommonConstraints::write` 把这些列读出后丢弃**（`let _ = (...)`），业务约束目前无法引用它们 —— 这是补"低悬挂约束"前必须先改的一处。

## 1. 明确的语义错误（本轮必修）

### 1.1 `start_hand` AIR 的 `round_state` 凭空造出 `ROUND_SHUFFLE=1`

| 项 | 电路 | 合约 |
|---|---|---|
| `start_hand.rs:107-110,164-166,170` | 约束 `post_round_state == 1`，注释称 `ROUND_SHUFFLE` | 合约 `constants.rs` **无 `ROUND_SHUFFLE`** 常量；`ROUND_WAITING=0, ROUND_PREFLOP=2`（跳过 1） |
| 实际语义 | — | `state_machine::start_hand`（state_machine.rs:1991）执行后 **`round_state` 仍为 `ROUND_WAITING=0`**；只在 preflop reveal phase 完成时（`check_reveal_phase_complete` state_machine.rs:921）才转为 `ROUND_PREFLOP=2` |

**修正**：`start_hand` AIR 的 `post_round_state` 改为 `ROUND_WAITING=0`（与 pre 相同）。Shuffle 阶段语义由独立的 `shuffle_state.phase` 字段表达（`SHUFFLE_PHASE_BEFORE_PREFLOP=3`），不属于 `round_state`。

### 1.2 5 个 crypto AIR 把 `round_state` 当 phase 用

| AIR | 电路硬编码 | 合约实际 |
|---|---|---|
| `join_and_shuffle.rs:183-184` | pre/post `round_state = 1 (ROUND_SHUFFLE)` | `round_state` 全程 `ROUND_WAITING=0`；阶段在 `shuffle_state.phase` |
| `submit_shuffle_v2.rs:157-158` | pre/post `round_state = 1` | 同上 |
| `leave_with_proof.rs:150-151` | pre/post `round_state = 1` | 同上（leave 时 `round_state==WAITING`） |
| `submit_player_reveal_tokens.rs:149-150` | pre/post `round_state = 2 (ROUND_REVEAL)` | 阶段在 `reveal_token_state.reveal_phase`；`round_state` 为 WAITING/PREFLOP/FLOP/... |
| `submit_reconstruct_deck.rs:150-151` | pre/post `round_state = 3 (ROUND_RECONSTRUCT)` | 阶段在 `reconstruct_state.phase`；`round_state` 全程 WAITING |

合约 `constants.rs:22-58` 明确：`round_state` 是 ROUND_* 系列（0/2/3/4/5/6），而 SHUFFLE/REVEAL/RECONSTRUCT 是**三个独立结构体的 `phase` 字段**，命名空间完全不同。

**修正**：本轮把这些魔数改为正确的 `round_state` 值（crypto 方法执行时 `round_state` 通常保持不变，pre==post），并在注释里标注"真正的阶段守卫在 `*_state.phase`，需阶段 5 加列约束"。详细相位语义列入"已知缺口"。

### 1.3 文档数字不一致（18 vs 21）

- `method_kind.rs` 模块注释与 enum doc 写"18 个方法"，实际 21 个 variant。
- `lib.rs`/`airs/mod.rs` 标题行 "21 个"/"18 个" 混用。
- 订正为统一的 21。

## 2. 低悬挂果实：补 limb-0 级约束（本轮做）

风格对齐现有 `addon.rs`/`rebuy.rs`（已有真实的 limb-0 算术不变量）。本轮只加 **limb-0** 约束 + **public input 一致性**，不做完整多 limb 进位（阶段 3 引入 carry witness）。

需先改 `common.rs`：让 `CommonConstraints::write` 把 `pre_round_state`/`post_round_state`/`pre_pot_0`/`post_pot_0` 暴露到返回结构体（当前丢弃）。

| 方法 | 缺失约束（合约出处） | 本轮补法 |
|---|---|---|
| `bet` | `round_state != ROUND_PREFLOP`（state_machine.rs:2939）；`current_bet <= seat.bet` | 加 `pre_round_state != 2` 守卫（用 `(pre_round_state-2)` 非零无法直接表达，改用 public-input 等价：把 host 校验后的 `is_postflop` flag 作为 public input 约束 —— 见下方说明） |
| `check` | `current_bet == seat.bet`（state_machine.rs:1826） | 已有 `INPUT_CURRENT_BET`，加"limb-0 等于 host 提供的 seat.bet limb-0"约束（需扩 CheckInput 带 seat_bet） |
| `call` | `stack -= call_amt`；`bet += call_amt`；`all_in = (stack==0 && call_amt>0)` | 加 limb-0：`post_stack_0 - pre_stack_0 + call_amt_0 == 0`（需 pre_stack_0 列 / public input） |
| `raise` | `stack -= needed`；`bet = total_bet`；`min_raise` 规则 | 加 limb-0：`post_stack_0 - pre_stack_0 + needed_0 == 0`（needed = total_bet - seat_bet，host 算好作 public input） |
| `kick_player` | `pot += seat.bet; seat.bet = 0`（state_machine.rs:2689，与 fold 不同） | 用通用列 `post_pot_0 - pre_pot_0 - kicked_bet_0 == 0`（kicked_bet 作 public input） |

**关于 `!=` 守卫的说明**：AIR 中表达"某个域元素 ≠ 常数"需要额外 witness（如 `x - c` 的逆元）。为避免引入复杂度，本轮 `bet` 的 postflop 守卫采用 **host-range-check-as-public-input** 方案：host 端校验 `round_state != PREFLOP` 后把一个 `is_valid_context: u8` flag 写进 public input，电路约束 `trace_flag == input_flag`。这与现有"host 保证、电路记录"的 PoC 风格一致，明确记为阶段 3 的过渡方案。

## 3. 已知缺口（阶段 5，本轮不做）

以下在报告建档，不在本轮实现：

1. **state_root 的 Poseidon 嵌入未在 AIR 中强制**：`state_root.rs:11` 注释声称 AIR 用 `poker_zkvm::stwo_backend::poseidon_air::PoseidonAir` 验证 host 计算的 root，但实际没有任何 AIR 嵌入 PoseidonAir。`orchestrator.rs:55 state_root_to_m31_limbs` 与 `create_table_trace.rs:99 starknet_field_to_m31_limbs` 均为占位（返回 `[ZERO;4]`）—— trace 内 state_root 承诺与 host 计算值脱节。
2. **`TexasPokerTable` 32 字段中仅 24 个进 state_root preimage**；`addon_pool`/`ante_*`/`rake_*`/`rit_mode` 完全无槽位；`betting_round`/`deck_state`/`shuffle_state`/`reveal_token_state`/`reconstruct_state`/`timeout_config`/`timestamps`/`config`/`side_pots` 均为 stub（返回 0 或 len）。→ addon/rebuy/ante/rake 等方法改这些字段后 state_root 不变。
3. **`SeatLeaf::from_seat` 只编码 `status + stack` 2 字段**（merkle_tree.rs:33），文档列 7 字段；`player`/`pk`/`bet`/`total_bet`/`hand` 未编码。
4. **crypto 方法（join_and_shuffle/submit_shuffle_v2/submit_player_reveal_tokens/submit_reconstruct_deck/leave_with_proof）的真实 ZK 密码学验证**（ElGamal/DLEq/ZKShuffle/RevealToken/Reconstruct proof）完全未电路化，`airs/crypto/mod.rs:9-23` 自承需阶段 5 嵌入 Verifier AIR。
5. **签名约束**：`force_fold`/`kick_player`/`reset_for_next_hand`/`start_hand` 的 admin 权限（`require_caller_is_creator`）与 seat-action 的 `require_caller_is_seat_player` 均未电路化（需 ECDSA AIR）。
6. **多 limb 算术**：所有 `u64` 运算目前只查 limb-0（低 16 位），高 limb 进位未约束。
7. **Aggregator 的 `RIGHT_CALL_SEQ == LEFT_CALL_SEQ + 1`**（aggregator_air.rs 文档承诺）未实际约束，只在 top-level 约束等于 public input。

## 4. 逐方法状态表

| # | 方法 | 合约关键逻辑 | 电路现状 | 状态 |
|---|---|---|---|---|
| 0 | create_table | max_players∈[2,9], bb>0, sb≤bb | 只约束 max_players/bb_limb0/sb_limb0/pot==0/button==0/round==0；范围检查 TODO 且注释承认提议约束错 | **本轮修范围检查** |
| 1 | join_table | WAITING, buy_in≥bb, 空座, chip_pool+=buy_in | 只约束 seat_index | 缺口（阶段3） |
| 2 | leave_table | WAITING, 退 stack, chip_pool-=stack | 只约束 seat_index | 缺口 |
| 3 | start_hand | WAITING, ≥2 人, 移 button, **round 仍 WAITING** | **错误：post round=1(ROUND_SHUFFLE)** | **本轮修** |
| 4 | tick | 超时级联 | 只约束 timeout_kind/time_bank/rake 的 limb0 | 缺口（无 prove_task，dispatch 返回 None） |
| 5 | reset_for_next_hand | 三段重置, stack+=pending_addon, 清牌局字段 | 约束 post round==0、pending_addon==0 | 部分（缺口） |
| 6 | fold | betting 轮, 当前轮, folded=true | 约束 seat、output_folded==1 | 守卫缺口 |
| 7 | check | betting, seat.bet≥current_bet | 约束 seat、current_bet_limb0、acted==1 | **本轮补 seat.bet 约束** |
| 8 | call | stack-=amt, bet+=amt, all_in | 约束 seat、call_amt_limb0、acted==1 | **本轮补 limb0 算术** |
| 9 | raise | stack-=needed, bet=total_bet, min_raise | 约束 seat、raise_to_limb0、acted==1 | **本轮补 limb0 算术** |
| 10 | auto_fold | fold reason=1 | 约束 seat、current_time_limb0、folded==1 | 守卫缺口 |
| 11 | force_fold | fold reason=2, admin | 约束 seat、folded==1 | 签名缺口 |
| 12 | kick_player | pot+=bet, 退款, admin | 约束 seat、refund_limb0、kicked==1 | **本轮补 pot 增量** |
| 13 | addon | pending_addon+=amt | **已有真约束**：post_pending_0 - pre_pending_0 - amt_0==0 | OK |
| 14 | rebuy | stack+=amt 立即 | **已有真约束**：post_stack_0 - pre_stack_0 - amt_0==0 | OK |
| 15 | join_and_shuffle | ZK 验证 + 入座 + deck 替换 | **错误：round=1**；约束 deck_commitment 一致 | **本轮修 round**；ZK 缺口 |
| 16 | leave_with_proof | DLEq 验证 + 退款 | **错误：round=1**；约束 seat/leave_kind | **本轮修 round**；ZK 缺口 |
| 17 | submit_shuffle_v2 | ZKShuffle 验证 + c2 注入 | **错误：round=1** | **本轮修 round**；ZK 缺口 |
| 18 | submit_player_reveal_tokens | RevealToken 验证 + 链解密 | **错误：round=2** | **本轮修 round**；ZK 缺口 |
| 19 | submit_reconstruct_deck | Reconstruct 验证 | **错误：round=3** | **本轮修 round**；ZK 缺口 |
| 20 | bet | postflop, current_bet≤seat.bet, 调 raise | 约束 seat、amount_limb0、acted==1 | **本轮补 postflop 守卫** |

## 5. 本轮修改清单

1. `common.rs`：`CommonConstraints` 暴露 `pre_round_state`/`post_round_state`/`pre_pot_0`/`post_pot_0`。
2. `start_hand.rs`：post round_state 0→`ROUND_WAITING`（0）；注释订正。
3. 5 个 crypto AIR：round_state 魔数改为正确值（pre==post，通常 0），注释说明真实 phase 字段。
4. `create_table.rs`：max_players 范围检查 —— 用 host range-check + public-input flag 方案（`is_valid_max_players`）。
5. `bet.rs`：加 postflop 守卫（public-input flag）。
6. `check.rs`：`CheckInput` 加 `seat_bet`，约束 `current_bet_limb0 == seat_bet_limb0`。
7. `call.rs`/`raise.rs`：加 limb-0 stack 算术（需 `pre_seat_stack` 作 public input）。
8. `kick_player.rs`：加 `post_pot_0 - pre_pot_0 - kicked_bet_0 == 0`（kicked_bet 作 input）。
9. 文档订正：18→21（method_kind.rs / lib.rs / airs/mod.rs）。

> 说明：第 4/5 项采用"host 校验 + public input flag"过渡方案，是因为在 M31 域上直接表达范围/不等式约束需要额外 witness（位分解/逆元），属于阶段 3 的 carry-witness 工作。该方案与现有 PoC 风格一致，并在每个改动处以注释标注其为过渡方案。
