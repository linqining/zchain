# poker_texas_air Soundness 修复记录

> **历史记录，已被 P05/P06 审计边界取代。** 本文保留早期 AIR 加固工作的背景，
> 其中“21/21 sound”、固定字段 state-root、动作时立即 `pot += amount` 和测试数量等
> 旧结论都不是当前可信声明。当前权威状态见
> [`docs/PO5_PO6_DESIGN_NOTES.md`](docs/PO5_PO6_DESIGN_NOTES.md)：21 个 AIR 路径中只有
> host 完整 dispatch replay + 原生逐 proof 验证形成 P05-H；P05-R 递归聚合未完成；
> P06 下注动作只覆盖 pot 不变、same-round、`current_turn = Some(next)` 的 mid-round
> 子集，收池/推进/结算 fail-closed。

本文档记录针对 `poker_lean`（`Audit/SoundnessAudit.lean`）形式化审计所列反例的
Rust AIR 修复，并明确残余风险。

## 当时的审计结论回顾（非当前完成度声明）

`poker_lean` 证明了：

- **create_table** AIR 是 sound 的（1/21）。
- **其余 20 个方法** 的 AIR 均不是 sound 的（每个都有反例）。
- 四大共性缺陷：C1 state root、C2 version 递增、前置守卫缺失、资金守恒未验证。

## 本轮修复（degree-2 约束框架内）

### 1. 通用层 `version += 1`（审计 C2，全 21 方法）

文件：`src/airs/common.rs`，`CommonConstraints::write`。

新增通用约束：`post_version = pre_version + 1`。

实现方式：由 host 已知的 `pre_version`(u64) 在 evaluate 内计算期望的 4 个
post limb（`pre_version + 1` 的完整 ripple-carry 结果），作为常量逐 limb 约束
trace 的 `post_version` 列与之相等。这是完整的 u64 加法约束，无需额外 witness
列，对任意 u64 值（含 limb0=0xFFFF 进位情形）均 sound —— 彻底消除
「version 不递增」反例。

回归测试：`test_soundness_fold_version_not_incremented`（构造 post=pre 的 trace，
prove 失败）。

### 2. round_state gating（审计「前置守卫缺失」）

为每个方法在 `evaluate` 内追加 degree-2 约束：

| 方法 | 约束 |
|------|------|
| join_table / leave_table / start_hand | `pre_round_state == WAITING(0)`（等式，消除「PREFLOP 下 join/leave/start」反例） |
| fold / check / call / raise / bet / auto_fold / force_fold / kick_player | `post_round_state == pre_round_state`（round 不变） |
| reset_for_next_hand | `post_round_state == WAITING(0)`（已有） |
| 5 个 crypto 方法 | `post_round_state == pre_round_state`（shuffle/reveal/reconstruct 阶段 round 恒为 WAITING） |
| tick | 不约束 round_state（tick 合法驱动状态机阶段转换） |

> **残余缺口**：完整的 `round_state ∈ {PREFLOP=2,FLOP=3,TURN=4,RIVER=5}`
> 归属判定需要 degree>2 的 vanishing 多项式或 logup lookup table。Stwo 当前
> AIR 框架要求约束 degree ≤ 2（见 `common.rs` 文档）。本修复以「等式 / 不变」
> 形式消除自由列漏洞；严格的集合归属判定列为后续工作（需引入 logup 子组件）。

### 3. 资金守恒（审计「资金守恒未验证」）

全 4-limb delta 约束（`pot_delta_4limb`，配合 Lean `decodeU64_limb_add` 推出 u64 级守恒）：

| 方法 | 约束 |
|------|------|
| fold / check / auto_fold / force_fold | `post_pot == pre_pot`（pot 不变，全 4 limb） |
| call / raise / bet | 当前已更正为 mid-round `post_pot == pre_pot`；筹码暂存在 `seat.bet` |
| kick_player | `post_pot == pre_pot + kicked_bet`（全 4 limb delta，kicked_bet witness 对齐 seat.bet） |
| leave_table | `post_chip_pool == pre_chip_pool - refund`、`post_addon_pool == pre_addon_pool - pending`（全 4 limb delta） |

回归测试：`test_soundness_fold_pot_changed`（构造 fold 改 pot 的 trace，prove 失败）。

> **残余缺口**：call/raise/bet 的完整 `stack -= delta`、`bet += delta`、
> `pot += delta` 三联守恒，以及 amount > 0、seat 状态检查，需要新增业务列
> （pre_seat_bet / pre_seat_stack）与 invertibility witness（degree-2 表达 `x ≠ 0`
> 需 `x * inv - 1 = 0`）。本轮以全 limb pot 守恒 + 各方法 round 不变为增量；
> 完整资金守恒列为后续工作。

### 4. addon / rebuy / join_table — 全局上界 range check

合约使用 `checked_add` 修复溢出，并增加全局上界检查：
`chip_pool + addon_pool + amount <= MAX_TOTAL_BET (10^18)`。

AIR 使用 `bound_check_4limb`（2-bit carry 分解的 4-limb range check）：
- 验证 `chip_pool + addon_pool + amount + diff = MAX_TOTAL_BET`（逐 limb + carry）
- `BOUND_DIFF`（4 limb）= `MAX_TOTAL_BET - total_chips` ≥ 0
- `BOUND_CARRY_LO`（3 bit）+ `BOUND_CARRY_HI`（3 bit）= 2-bit carry 分解

| 方法 | 全局上界检查 |
|------|-------------|
| join_table | `chip_pool + addon_pool + buy_in <= MAX_TOTAL_BET`（`bound_check_4limb`） |
| addon | `chip_pool + addon_pool + amount <= MAX_TOTAL_BET`（`bound_check_4limb`） |
| rebuy | `chip_pool + addon_pool + amount <= MAX_TOTAL_BET`（`bound_check_4limb`） |

Lean 证明使用 `bound_check_4limb_le` 引理直接推出 `decodeU64` 级上界不等式。

## 不覆盖项（明确声明，与 Lean 审计一致）

1. **C1 State Root Poseidon252 验证**：需嵌入哈希 AIR 子组件，工程量大且独立，
   本次不实现，列为残余风险。
2. **密码学 ZK proof 嵌入**（DLEq / ZKShuffle / RevealToken / Reconstruct）：
   靠 host 公开输入 + round_state 不变约束；完整嵌入列为阶段 5。
3. **集合归属 / 非负 / 全 limb 比较**：受 degree ≤ 2 限制，本轮用等式/不变 + host
   公开输入；严格判定需 logup / invertibility witness（TODO 已在各 AIR 标注）。

## 当时的验证快照（不可替代当前测试结果）

- `cargo build -p poker_texas_air` 通过。
- `cargo test -p poker_texas_air` 全绿（122 通过，含 soundness 回归测试）。
- `lake build`（PokerLean）通过，`Proofs/` 目录 0 个 `sorry`。
- 三层一致性：合约 `checked_add` 修复 → AIR `bound_check_4limb` / `pot_delta_4limb` 约束 → Lean `bound_check_4limb_le` / `pot_delta_implies_decode_eq` 证明。
