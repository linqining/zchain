# poker_texas_air Soundness 修复记录

本文档记录针对 `poker_lean`（`Audit/SoundnessAudit.lean`）形式化审计所列反例的
Rust AIR 修复，并明确残余风险。

## 审计结论回顾

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

degree-2 limb0 约束：

| 方法 | 约束 |
|------|------|
| fold / check / auto_fold / force_fold | `post_pot == pre_pot`（pot 不变） |
| call | `post_pot - pre_pot == call_amount`（limb0） |
| kick_player | `post_pot - pre_pot == kicked_bet`（limb0，已有） |

回归测试：`test_soundness_fold_pot_changed`（构造 fold 改 pot 的 trace，prove 失败）。

> **残余缺口**：call/raise/bet 的完整 `stack -= delta`、`bet += delta`、
> `pot += delta` 三联守恒，以及 amount > 0、seat 状态检查，需要新增业务列
> （pre_seat_bet / pre_seat_stack）与 invertibility witness（degree-2 表达 `x ≠ 0`
> 需 `x * inv - 1 = 0`）。本轮以 call 的 pot 守恒 + 各方法 round 不变为增量；
> 完整资金守恒列为后续工作。

### 4. addon / rebuy

已有 `post_pending_addon == pre + amount`（addon）、`post_stack == pre_stack + amount`
（rebuy）的 limb0 守恒。本轮追加 round_state 不变约束。

> 残余：amount > 0、addon_pool 守恒需新增列（TODO 已标注）。

## 不覆盖项（明确声明，与 Lean 审计一致）

1. **C1 State Root Poseidon252 验证**：需嵌入哈希 AIR 子组件，工程量大且独立，
   本次不实现，列为残余风险。
2. **密码学 ZK proof 嵌入**（DLEq / ZKShuffle / RevealToken / Reconstruct）：
   靠 host 公开输入 + round_state 不变约束；完整嵌入列为阶段 5。
3. **集合归属 / 非负 / 全 limb 比较**：受 degree ≤ 2 限制，本轮用等式/不变 + host
   公开输入；严格判定需 logup / invertibility witness（TODO 已在各 AIR 标注）。

## 验证

- `cargo build -p poker_texas_air` 通过。
- `cargo test -p poker_texas_air` 全绿（122 通过，含 2 个新增 soundness 回归测试）。
- 新增回归测试覆盖 Lean 反例核心场景（version 不递增、fold 改 pot）。
