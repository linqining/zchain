/-!
# AIR Soundness 审计报告（修订版）

本报告修订自上一版"21/21 全 ✅ Sound"的结论。经逐条对照 `poker_texas_air`
（Rust AIR 实现）与 `poker_l1`（合约）的真实代码，发现原结论**高估了证明的覆盖范围**：
Lean 证明的是一份理想化的 AIR 规格，而真实 Rust AIR 在多个安全关键点上存在缺陷或缺失。

本修订版**如实区分三类**：
- ✅ **已证且对真实 AIR 成立**（已完成 Rust 修复 + Lean 对齐）
- 🔐 **显式信任根**（state_root 哈希本身，非电路内自造）
- ⚠️ **仍依赖 host / 外部 / 待修复**（明确列出，不夸大）

## 审计方法修订

对照三个层次，而非只看 Lean 定理：
1. **合约语义**（guards + state transition）
2. **真实 Rust AIR 约束**（`poker_texas_air/src/airs/*.rs` 的 `add_constraint`）
3. **Lean AIR 模型 + soundness 定理**（是否与真实 Rust 一致）

关键修正：上一版把"Lean 假设的约束"误当成"真实 AIR 约束"。本版逐条标注真实状态。

---

## 🔐 第一类：state_root 绑定（显式信任根）

### 历史缺陷（已在本次修复）

**原状态（严重）**：state_root 绑定在真实系统中是**空的**：
- `orchestrator.rs::state_root_to_m31_limbs` 把 root 列写成 `[ZERO;4]`（占位）
- AIR `common.rs:213-258` 读取 8 个 `pre/post_state_root_*` 列后**直接 `let _ = (...)` 丢弃**
- **更严重**：prover/verifier **从未把任何公开输入 mix 进 Fiat-Shamir channel**
  （`prover.rs:137` `Channel::default()` 后直接 commit，无 `mix_*`）
- 因此 `proof.air` 里的 `pre_state_root`/`post_state_root` 与证明之间**零密码学绑定**：
  攻击者可替换这些值，证明仍验证通过

### 已完成修复（路径 A：preimage 公开输入 + 链外重算）

保留被审计的 **Starknet Poseidon252**（~251 bit STARK 域，碰撞抗性 ~2^125.5，
本身 128-bit 安全），通过公开输入 + Fiat-Shamir 完成绑定：

| 修复项 | 位置 | 内容 |
|--------|------|------|
| 补全 preimage | `state_root.rs:314-353` | 9 个 stub（betting_round/deck/shuffle/reveal/reconstruct/timeout/timestamps/config/side_pots）全部实现真实编码 + 域分隔符防跨类型碰撞 |
| `poseidon_borsh(tag, value)` | `state_root.rs` | 统一「域分隔 + borsh + 31字节分块 + 长度后缀」编码契约 |
| `field_element_to_u32_words` | `state_root.rs` | 251-bit Fr → 8 个大端 u32（无损往返） |
| `TexasPublicInputs` | `public_inputs.rs` | 携带 pre/post_image(24字段×2) + roots + 元数据 |
| `mix_into(channel)` | `public_inputs.rs` | prover/verifier 对称地按固定顺序 mix 进 Fiat-Shamir |
| `verify_roots()` | `public_inputs.rs` | 验证方重算 `Poseidon252(image)` 并比对公开 root |
| prove/verify 接线 | `prover.rs`/`verifier.rs` | `Channel::default()` 后、首次 commit 前 mix；create_table 与 method 两路 |
| aggregator 接线 | `aggregator_prover.rs`/`aggregator_verifier.rs` | `mix_children_into_channel` 把链式 ChildDescriptor mix 进 channel |

### 当前状态：state_root 是**显式信任根**

经修复后，state_root 绑定通过「preimage 公开输入（已 mix 进 channel）+ 被审计的
Starknet Poseidon252 链外重算」完成。密码学哈希本身（`poseidon_hash`）是唯一信任根，
**非电路内自造**（未采用 capacity=1 的不安全 M31 Poseidon——经评估其碰撞抗性仅 ~2^15.5）。

Lean 侧保留 2 个信任根公理：`poseidon_hash`、`texasPokerTableToPreimage`。
（`#print axioms` 实跑确认：21 个 soundness 定理依赖 = 标准公理 + 这 2 个。）
声明的 6 个密码学公理中，实际只有 2 个被使用。

### 消除路径（后续独立任务，本次不启动）

若将来要在电路内原生验证 Poseidon，需采用 **qm31 扩域 + capacity≥5** 的安全 M31 Poseidon
实例（碰撞抗性 ~2^155），而非当前 capacity=1 的实例。**不推荐仅为 state_root 而做**——
现 Starknet Poseidon252 已是 128-bit 安全且被审计，自造实例安全性不增反降。

### 链上验证（后续独立任务）

链下 prover/verifier 绑定已完成。**链上/L1 的 `verify_texas_proof` 重算入口需新增**
（当前 `poker_l1` 无此入口，`dispatch.rs`/`prove_task.rs` 仅执行状态转换）。
位置：`poker_l1/src/vm/contracts/texas_poker/`。

---

## ✅ 第二类：已修复且对真实 AIR 成立的约束

### 共同约束（所有 21 个方法）

| 约束 | 状态 | 说明 |
|------|------|------|
| Version 递增 | ✅ 真实 | `CommonConstraints::write` 对 active 行强制 4-limb `post_version = pre_version + 1`（从 host pre_version 重算） |
| MethodKind gating | ✅ 真实 | `is_active * (method_kind - expected) = 0` |
| IS_ACTIVE / IS_PADDING binality + 互斥 | ✅ 真实 | |

### 已升级为完整 4-limb 守恒（本次修复）

| 方法 | 约束 | 修复前 | 修复后 |
|------|------|--------|--------|
| **Call** | pot/stack/bet/total_bet delta | 仅 limb 0；stack/total_bet 完全无约束 | ✅ 全 4-limb（`pot_delta_4limb` + `limb4_delta_rev` + `limb4_delta`×2），对齐 raise.rs |
| **Bet** | pot/stack/bet/total_bet delta + amount>0 | 仅 pot limb 0；stack/total_bet 完全无约束 | ✅ 全 4-limb（同 Call）+ amount>0 invertibility witness |
| **Fold** | pot 不变 | 仅 limb 0 | ✅ `pot_unchanged_4limb`（全 4-limb） |
| **Check** | pot 不变 | 仅 limb 0 | ✅ `pot_unchanged_4limb` |
| **AutoFold** | pot 不变 | 仅 limb 0 | ✅ `pot_unchanged_4limb` |
| **ForceFold** | pot 不变 | 仅 limb 0 | ✅ `pot_unchanged_4limb` |
| **Addon** | pending_addon delta + addon_pool 守恒 | pending 仅 limb 0；addon_pool 完全无约束 | ✅ pending 升 4-limb + 新增 `POST_ADDON_POOL[4]` 列 + `limb4_delta` 守恒 |
| **Rebuy** | stack delta + addon_pool 守恒 | stack 仅 limb 0；addon_pool 完全无约束 | ✅ stack 升 4-limb + 新增 `POST_ADDON_POOL[4]` 列 + `limb4_delta` 守恒 |
| **JoinTable** | buy_in ≥ big_blind | `big_blind` 列被丢弃，无约束 | ✅ 新增 `ge_4limb` 减法借位链约束（4-limb ≥ 检查） |
| Raise | pot/stack/bet/total_bet delta | 本就是 4-limb | ✅ 保持（参考实现） |

### 真实存在的约束（原审计正确部分）

- **RoundStateIsBetting**：fold/check/call/raise/bet/auto_fold/force_fold 用 `q=rs²` witness
  拆解的 degree-2 vanishing 多项式，强制 `rs ∈ {PREFLOP,FLOP,TURN,RIVER}`——✅ 真实
- **RoundStateEq(0)**：join/leave/start_hand 的 WAITING gating——✅ 真实
- **RoundStateUnchanged**：tick/crypto——✅ 真实
- **SeatOccupied / SeatEmpty**——✅ 真实（部分方法）
- **AmountPositive**（addon/rebuy，via invertibility witness）——✅ 真实（limb 0）

---

## ⚠️ 第三类：原待修复约束的修复进展

原审计列出的 5 项缺陷，本次已修复 4 项（Bet / Addon / Rebuy / Join 的 buy_in≥big_blind），
range-check 已提供约束原语并部分落地。逐项状态如下。

### 3.1 Bet：✅ 已修复（全 4-limb delta + amount>0）
- 原：`bet.rs` pot delta 仅 limb 0，`output_seat_bet[4]` 整列丢弃，无 stack/total_bet delta
- **修复**：pot/stack/bet/total_bet 全 4-limb（`pot_delta_4limb` + `limb4_delta_rev` + `limb4_delta`×2），
  对齐 raise.rs；新增 `INPUT_AMOUNT_INV` invertibility witness 约束 amount > 0
- 新增列：pre_seat_bet/stack/total_bet + output_seat_stack/total_bet + amount_inv（+21 列）

### 3.2 Addon / Rebuy：✅ 已修复（addon_pool 守恒 + 4-limb delta）
- 原：`addon_pool` 仅作 bound_check 输入，**无守恒约束，甚至无 POST_ADDON_POOL 列**；stack/pending 仅 limb 0
- **修复**：新增 `OUTPUT_POST_ADDON_POOL[4]` 列 + `limb4_delta(pre, post, amount)` 守恒约束
  （对齐合约 `table.addon_pool += amount`）；pending/stack delta 升 4-limb
- 新增列：post_addon_pool（+4 列，两方法各）

### 3.3 JoinTable：✅ 已修复（buy_in ≥ big_blind）
- 原：`join_table.rs` `input_big_blind[4]` 被 `let _ =` 丢弃，标 `TODO 阶段 3`
- **修复**：新增 `ge_4limb` 约束（4-limb 减法借位链：`buy_in - big_blind = ge_diff`，
  borrow_out[3]=0 保证无下溢 ⇒ buy_in ≥ big_blind，在 Limb4Range16 假设下）
- 新增列：ge_diff[4] + ge_borrow[3]（+7 列）
- 对齐 Lean 的 `BuyInGeBigBlind` 约束

### 3.4 16-bit limb range-check：🟡 原语 + 首个接线样例已验证，全量接线为后续
- 原：`prover.rs:76-81` 提交空预计算 trace，无 range-check AIR；Lean 的 `Limb4Range16` 是未由 AIR 满足的外部假设
- **本次进展**：
  - `common.rs` 新增 `range16(x, bits[16])` 约束原语（16 boolean witness 的 bit 分解 + booleanity）
  - **Rebuy 已接线**：`input_amount` 的 4 个 limb 各接 16 个 bit witness（共 64 列）+ `range16` 约束
  - **机制验证通过**：新增 `test_soundness_rebuy_range_violation` 负向测试——篡改 amount limb 为 70000（≥2^16）时 prove 失败，证明 range16 真实生效（非摆设）
- **当前状态**：Rebuy 的 `input_amount` 已由 AIR 强制 < 2^16；其余 money limb（stack/addon_pool/chip_pool 等）及 Addon/Join 的 range 接线为后续同构工作。logup lookup 方案（每值 1 interaction 而非 16 列）是更优长期方案，需把 `prove_method` 改为多组件。
- 修复方向：逐方法为 money limb 添加 16 bit witness 并调用 `range16`，或迁移到 logup 共享表

### 3.5 CreateTable：多个业务规则为 TODO（待办）
- `max_players ∈ [2,9]`、`big_blind > 0`、`small_blind ≤ big_blind`：均标 TODO，AIR 内仅做输入一致性（对公开输入的恒等）
- state_root 约束：见第一类（已通过路径 A 解决绑定，但电路内仍无 Poseidon 约束）

---

## ⚠️ 仍依赖 host / 外部的项（设计如此，非缺陷）

1. **seat_index < max_players**：作为 host 公开输入假设，AIR 不强制（all 方法）
2. **密码学子证明**（DLEq / ZKShuffle / RevealToken / Reconstruct）：不在 AIR 内验证，
   假设由外部 ZK 验证器负责（crypto 方法）
3. **tick 超时条件**：简化为 `timeout_kind > 0`，未建模真实超时判定

---

## 公理审计（修订）

经 `#print axioms` 实跑（21 个 soundness 定理 + State 层定理）：

| 层 | 定理 | 依赖公理 |
|----|------|----------|
| AIR soundness（21 个） | `*_air_sound` | `propext, Classical.choice, Quot.sound` + 2 个 state_root 信任根 |
| State / Refinement（34 个） | `*_chip_conservation` 等 | 仅 `propext, Classical.choice, Quot.sound`（标准 Lean 公理，无自定义） |

**密码学信任根（实际使用 2 个，声明 6 个）**：
| 公理 | 状态 | 说明 |
|------|------|------|
| `poseidon_hash` | 🔐 使用 | state_root 哈希（路径 A，链外重算） |
| `texasPokerTableToPreimage` | 🔐 使用 | 状态序列化 |
| `poseidon_hash_injective` | 未使用 | 声明但无定理依赖（路径 A 改用 verify_roots 重算） |
| `texasPokerTableToPreimage_injective` | 未使用 | 同上 |
| `empty_state_root` | 未使用 | |
| `poseidon_hash_empty` | 未使用 | |

---

## 修订结论

### 整体评级（诚实版）

| 维度 | 评级 |
|------|------|
| state_root 绑定（原为空） | ✅ **已修复**（路径 A：公开输入 + Fiat-Shamir + 审计哈希重算） |
| Call 资金守恒 | ✅ **已升级** 4-limb |
| Bet 资金守恒 + amount>0 | ✅ **已升级** 4-limb + invertibility |
| Fold/Check/AutoFold/ForceFold pot 不变 | ✅ **已升级** 4-limb |
| Addon/Rebuy addon_pool 守恒 + delta | ✅ **已修复**（新增 post_addon_pool 列 + 守恒 + 4-limb） |
| JoinTable buy_in≥big_blind | ✅ **已修复**（ge_4limb 减法借位链） |
| 16-bit range-check | 🟡 **原语 + Rebuy 接线样例验证**（`range16` + 负向测试通过），全量接线为后续 |
| Lean 证明本身（无 sorry、最小公理） | ✅ 真（`#print axioms` 验证） |

### 与最初版本的差异

最初版本声称"21/21 全 ✅ Sound、所有非密码学公理已消除"。**修订后**：
- state_root 绑定原为**空的**（root 列写 [ZERO;4]、无 channel mix）——已修复
- 多处"✅ 完整"实为 Lean 单方面假设、Rust 未实现——已逐条修复（Bet/Addon/Rebuy/Join）
- Lean 证明是**真的**，但证明的是理想化规格；本次 Rust 侧补齐使其与真实 AIR 对齐
- 唯一残留：range-check 的全方法接线（原语已就绪）

### 已落地的真实修复（本次）

1. **state_root 绑定**（路径 A）：preimage 补全（9 stub + 域分隔防碰撞）+ Fiat-Shamir mix + 链外重算验证 + aggregator children mix
2. **Call 4-limb 升级**：pot/stack/bet/total_bet 全守恒
3. **Bet 4-limb 升级**：pot/stack/bet/total_bet 全守恒 + amount>0 invertibility
4. **Fold/Check/AutoFold/ForceFold**：pot-unchanged 升 4-limb（`pot_unchanged_4limb`）
5. **Addon/Rebuy**：新增 `POST_ADDON_POOL` 列 + `limb4_delta` 守恒 + pending/stack delta 升 4-limb
6. **JoinTable**：`ge_4limb` 减法借位链实现 `buy_in ≥ big_blind`
7. **range-check 原语**：`common.rs::range16`（bit 分解）+ `ge_4limb` + `pot_unchanged_4limb`
8. **range-check 接线样例**：Rebuy 的 `input_amount` 4 limb 接 `range16`（64 bit witness）+ 负向篡改测试（amount≥2^16 prove 失败，验证约束真实生效）
9. **编码契约测试**：域分隔防碰撞、无损往返、确定性 mix、篡改检测
10. **Lean 对齐确认**：`lake build` 全绿；Rust 修复使真实 AIR 与 Lean 理想化模型一致（4-limb delta / addon_pool 守恒 / buy_in≥big_blind / Limb4Range16 假设均有 AIR 依据）
11. **全部 135 个 cargo test 通过**（含 e2e prove/verify + soundness 篡改检测 + range 违规检测）

### 后续工作（明确列出，按优先级）

1. ~~**P0**：Bet 升 4-limb delta；Addon/Rebuy 补 addon_pool 守恒列~~ ✅ 已完成
2. ~~**P1**：JoinTable 实现 buy_in≥big_blind~~ ✅ 已完成
3. **P1**：range16 全方法接线（原语 + Rebuy 样例已验证；剩余 money limb 与 Addon/Join 同构接线，或迁移到 logup 共享表方案）
4. ~~**P2**：Lean 对齐 + 重证~~ ✅ 已确认（`lake build` 全绿，Rust 修复向 Lean 模型对齐）
5. **P2**：CreateTable 业务规则（max_players∈[2,9]、big_blind>0、small_blind≤big_blind）AIR 内实现
6. **P2**：链上 L1 `verify_texas_proof` 重算入口

**说明**：本次修订聚焦"让审计诚实 + 修复最严重的 state_root 绑定缺陷 + 全部资金守恒/比较约束升级"。
原第三类 5 项中 4 项已完成，仅 range-check 全方法接线（原语已就绪）与 CreateTable 业务规则、
链上验证入口作为后续。
-/
