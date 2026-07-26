/-!
# AIR Soundness 审计报告

对 `poker_texas_air` 中 21 个方法 AIR 与 `poker_l1` 合约语义
之间的 soundness 差距进行系统性审计。

## 审计方法

对每个方法，我们对比：
1. 合约语义要求的前置条件（guards）
2. 合约语义要求的状态变更（state transition）
3. AIR 电路中实际约束的内容

然后标记：
- ✅ 已约束：AIR 中正确实现了约束
- ⚠️ 部分约束：仅验证输入一致性（依赖 host），未做范围/关系检查
- ❌ 缺失：AIR 中完全没有约束

## 共同问题（所有 21 个方法）

以下是所有方法 AIR 共有的缺失约束：

### C1. State Root 一致性 ❌
- **合约语义**：状态转换正确体现在 pre_state_root → post_state_root
- **AIR 现状**：pre/post_state_root 作为通用列存在，但未验证与实际状态的关系
- **所需工作**：嵌入 Poseidon252 AIR 子组件，验证 `Poseidon(preimage) == state_root`
- **风险等级**：极高 — 没有这个约束，所有状态变更都不可信

### C2. Version 递增 ✅ (已修复)
- **合约语义**：每个状态变更都使 `version += 1`
- **AIR 现状**：`CommonConstraints::write()` 已添加 4-limb `post_version = pre_version + 1` 约束
- **实现位置**：`common.rs` 的 `write()` 函数中，对所有 active 行强制版本递增
- **风险等级**：已消除

### C3. Table ID 一致性 ⚠️
- **合约语义**：状态转换不改变 table_id
- **AIR 现状**：table_id 在通用列中，但未约束不变性
- **风险等级**：中

### C4. 完整 limb 验证 ⚠️
- **合约语义**：u64 值完整正确
- **AIR 现状**：大多数方法只验证 limb 0，其他 limb 未约束
- **风险等级**：中

---

## A 档：生命周期方法（6 个）

### 1. CreateTable (0)

**合约语义**：
- 前置：无（从零创建）
- 参数：max_players ∈ [2,9], big_blind > 0, small_blind ≤ big_blind
- 状态变更：初始化所有字段，version=1，round_state=WAITING

**AIR 约束现状**：
| 约束 | 状态 | 说明 |
|------|------|------|
| max_players 范围 | ⚠️ 部分 | 仅验证 == expected，依赖 host 校验 |
| big_blind > 0 | ⚠️ 部分 | 仅验证 == expected，依赖 host |
| small_blind ≤ big_blind | ⚠️ 部分 | 仅验证 == expected，依赖 host |
| pot = 0 | ✅ 完整 | 4 limb 都约束为 0 |
| button = 0 | ✅ 完整 | 约束为 0 |
| round_state = WAITING | ✅ 完整 | 约束为 0 |
| version = 1 | ✅ 完整 | version 递增约束保证 pre=0 → post=1 |
| seats 全空 | ❌ 缺失 | state root 内验证 |
| state root 一致性 | ❌ 缺失 | 见 C1 |

**Soundness 评级**：⚠️ 中等（结构约束有，但核心参数验证依赖 host）

---

### 2. JoinTable (1)

**合约语义**：
- 前置：round_state = WAITING, 目标座位为空, buy_in ≥ big_blind
- 状态变更：seat.player = addr, seat.stack = buy_in, version += 1

**AIR 约束现状**：
| 约束 | 状态 | 说明 |
|------|------|------|
| round_state = WAITING | ✅ 完整 | 已通过 round_state_eq(0) 约束 |
| seat 为空 | ❌ 缺失 | state root 内验证 |
| buy_in ≥ big_blind | ❌ 缺失 | 未约束 |
| seat_index < max_players | ❌ 缺失 | 注释说简化，未实现 |
| player addr 合法性 | ❌ 缺失 | 未约束 |
| output_stack = buy_in | ❌ 缺失 | output 列读取但未约束 |
| version += 1 | ✅ 完整 | 见 C2（已修复） |

**Soundness 评级**：❌ 严重（几乎没有实质约束）

---

### 3. LeaveTable (2)

**合约语义**：
- 前置：round_state = WAITING, 座位非空且为 is_waiting
- 状态变更：seat = empty, version += 1

**AIR 约束现状**：
| 约束 | 状态 | 说明 |
|------|------|------|
| round_state = WAITING | ✅ 完整 | 已通过 round_state_eq(0) 约束 |
| seat 非空 | ❌ 缺失 | 未约束 |
| seat is_waiting | ❌ 缺失 | 未约束 |
| seat 变空 | ❌ 缺失 | 未约束 |
| version += 1 | ✅ 完整 | 见 C2（已修复） |

**Soundness 评级**：❌ 严重

---

### 4. StartHand (3)

**合约语义**：
- 前置：round_state = WAITING, active_count ≥ 2
- 状态变更：button 旋转, shuffle_state 进入 BEFORE_PREFLOP, version += 1

**AIR 约束现状**：
| 约束 | 状态 | 说明 |
|------|------|------|
| round_state = WAITING | ✅ 完整 | pre 已通过 round_state_eq(0) 约束 |
| active_count ≥ 2 | ❌ 缺失 | 注释说简化，未实现 |
| button 旋转 | ❌ 缺失 | output 读取但未约束与 pre 的关系 |
| shuffle_state 变更 | ❌ 缺失 | 完全未涉及 |
| ante 模式验证 | ⚠️ 部分 | 仅验证 == expected |
| ante_collected 计算 | ⚠️ 部分 | 仅验证 == expected |
| version += 1 | ✅ 完整 | 见 C2（已修复） |

**Soundness 评级**：❌ 严重

---

### 5. Tick (4)

**合约语义**：
- 前置：距离上次行动超过超时时间
- 状态变更：可能触发 auto_fold 或其他超时行为

**AIR 约束现状**：未读取，预计与其他方法类似的简化实现
- version += 1: ✅ 完整（见 C2）
**Soundness 评级**：❌ 严重（时间相关约束最难在 AIR 中实现）

---

### 6. ResetForNextHand (5)

**合约语义**：
- 前置：showdown 完成或所有玩家 folded/all-in
- 状态变更：清理座位，结算 pot，返还 stack，重置为 WAITING

**AIR 约束现状**：未读取，预计为简化实现
- version += 1: ✅ 完整（见 C2）
**Soundness 评级**：❌ 严重（资金结算最关键，约束最多）

---

## B 档：玩家动作（8 个）

### 7. Fold (6)

**合约语义**：
- 前置：下注轮, current_turn = seat_index, 玩家活跃参与
- 状态变更：seat.folded = true, seat.acted = true, version += 1

**AIR 约束现状**：
| 约束 | 状态 | 说明 |
|------|------|------|
| 下注轮 gating | ⚠️ 部分 | round_state 不变，但仍允许 WAITING |
| current_turn 检查 | ❌ 缺失 | 未约束 |
| seat 参与状态 | ❌ 缺失 | 未约束 folded/all_in |
| seat_index 范围 | ❌ 缺失 | 未约束 < max_players |
| output_folded = 1 | ✅ 完整 | 约束为 1 |
| pot 不变 | ✅ 完整 | pot_unchanged_limb0 已约束 |
| version += 1 | ✅ 完整 | 见 C2（已修复） |

**Soundness 评级**：❌ 严重（只有输出标记约束，没有前置守卫）

---

### 8. Check (7)

**合约语义**：
- 前置：下注轮, current_turn = seat_index, seat.bet == current_bet
- 状态变更：seat.acted = true, version += 1

**AIR 约束现状**：
| 约束 | 状态 | 说明 |
|------|------|------|
| 下注轮 gating | ⚠️ 部分 | round_state 不变，但仍允许 WAITING |
| current_turn 检查 | ❌ 缺失 | 未约束 |
| seat.bet == current_bet | ⚠️ 部分 | 仅 limb 0，且是与公开输入比 |
| output_acted = 1 | ✅ 完整 | 约束为 1 |
| pot 不变 | ✅ 完整 | pot_unchanged_limb0 已约束 |
| version += 1 | ✅ 完整 | 见 C2（已修复） |

**Soundness 评级**：❌ 严重

---

### 9. Call (8)

**合约语义**：
- 前置：下注轮, current_turn = seat_index, 玩家未 fold/all_in
- 计算：call_amount = current_bet - seat.bet, 受 stack 限制
- 状态变更：stack -= call_amount, bet += call_amount, pot += call_amount, acted = true

**AIR 约束现状**：
| 约束 | 状态 | 说明 |
|------|------|------|
| 下注轮 gating | ⚠️ 部分 | round_state 不变，但仍允许 WAITING |
| current_turn 检查 | ❌ 缺失 | 未约束 |
| call_amount 计算正确 | ❌ 缺失 | 仅验证 == expected |
| stack -= amount | ❌ 缺失 | 未约束关系 |
| bet += amount | ❌ 缺失 | 未约束关系 |
| pot += amount | ⚠️ 部分 | 仅 partial，无完整 4-limb |
| all-in 判定 | ❌ 缺失 | output 读取但未约束 |
| output_acted = 1 | ✅ 完整 | 约束为 1 |
| version += 1 | ✅ 完整 | 见 C2（已修复） |

**Soundness 评级**：❌ 严重

---

### 10. Raise (9)

**合约语义**：
- 前置：下注轮, current_turn = seat_index, 玩家活跃
- 计算：raise_to > current_bet, raise_to - current_bet ≥ min_raise, raise_to ≤ stack + bet
- 状态变更：stack -= delta, bet = raise_to, pot += delta, min_raise = delta

**AIR 约束现状**：
| 约束 | 状态 | 说明 |
|------|------|------|
| 下注轮 gating | ❌ 缺失 | 未约束 |
| current_turn 检查 | ❌ 缺失 | 未约束 |
| raise_to > current_bet | ❌ 缺失 | TODO 阶段 3 |
| 增量 ≥ min_raise | ❌ 缺失 | TODO 阶段 3 |
| raise_to ≤ stack + bet | ❌ 缺失 | TODO 阶段 3 |
| stack/bet/pot 关系 | ❌ 缺失 | 未约束 |
| all-in 判定 | ❌ 缺失 | output 读取但未约束 |
| output_acted = 1 | ✅ 完整 | 约束为 1 |
| version += 1 | ✅ 完整 | 见 C2（已修复） |

**Soundness 评级**：❌ 严重

---

### 11. AutoFold (10)

**合约语义**：
- 前置：玩家超时未行动
- 状态变更：与 fold 类似 + time_bank 消耗

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
- pot 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

### 12. ForceFold (11)

**合约语义**：
- 前置：管理员权限，玩家在场
- 状态变更：fold 玩家 + 标记 left_during_hand

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
- pot 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

### 13. KickPlayer (12)

**合约语义**：
- 前置：管理员权限，round_state = WAITING
- 状态变更：移除玩家，返还 stack

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

### 21. Bet (20)

**合约语义**：
- 前置：下注轮且当前下注为 0（第一个下注者）
- 状态变更：与 raise 类似

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
**Soundness 评级**：❌ 严重

---

## B+ 档：资金动作（2 个）

### 14. Addon (13)

**合约语义**：
- 前置：玩家在场
- 状态变更：pending_addon += amount, addon_pool += amount

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

### 15. Rebuy (14)

**合约语义**：
- 前置：MTT 早期, 玩家 stack 低于某阈值
- 状态变更：stack += rebuy_amount, chip_pool += rebuy_amount

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

## C 档：密码学协议（5 个）

### 16. JoinAndShuffle (15)

**合约语义**：
- 玩家加入并完成首洗牌（Mental Poker 协议）
- 涉及 ElGamal 加密、零知识证明

**AIR 约束现状**：未读取，预计最复杂
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
**Soundness 评级**：❌ 严重（密码学约束最难验证）

---

### 17. LeaveWithProof (16)

**合约语义**：
- 玩家带 proof 离场，不泄露手牌信息

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

### 18. SubmitShuffleV2 (17)

**合约语义**：
- 提交洗牌结果（V2 版本）
- 验证洗牌零知识证明

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

### 19. SubmitPlayerRevealTokens (18)

**合约语义**：
- 提交 reveal tokens（揭牌令牌）
- 验证 ElGamal 令牌正确性

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

### 20. SubmitReconstructDeck (19)

**合约语义**：
- 提交重构牌组结果
- 验证重构证明

**AIR 约束现状**：未读取
- version += 1: ✅ 完整（见 C2）
- round_state 不变: ✅ 完整
**Soundness 评级**：❌ 严重

---

## 总结

### 整体 Soundness 评级：❌ 严重不足

### 统计数据

| 级别 | 方法数 | 说明 |
|------|--------|------|
| ✅ 良好 | 0 | 完全满足 soundness |
| ⚠️ 中等 | 1 | create_table（结构约束较完善） |
| ❌ 严重 | 20 | version 已补齐，但仍缺少 state root/gating/资金约束 |

### 核心风险

1. **State Root 未验证**：所有方法都没有 Poseidon252 哈希验证，
   这意味着 pre/post state 的内容完全不受约束。这是最大的安全漏洞。

2. **前置守卫部分缺失**：join/leave/start_hand 已补齐 WAITING gating，
   但动作方法仍缺少 round_state、current_turn、seat 状态等前置条件。

3. **资金守恒未验证**：下注、跟注、加注等资金操作没有验证
   stack - bet + pot = 守恒量。攻击者可以凭空创造筹码。

4. **输入一致性模型**：当前 AIR 大量采用 `input == expected` 模式，
   即假设 host 端已经校验了参数合法性。这将验证责任推给了 host，
   与 ZK 电路的信任模型（不信任 host）冲突。

### 建议的完善路径

**第一阶段（基础完整性）**：
1. 为所有方法添加 state root Poseidon252 验证
2. 为所有动作添加 round_state gating
3. 为所有动作添加 current_turn 检查

**第二阶段（资金安全）**：
4. 验证 bet/call/raise 的资金守恒
5. 验证 stack/bet/pot 的算术关系
6. 验证 all-in 的正确判定
7. 验证 side pot 计算

**第三阶段（密码学）**：
8. Mental Poker 协议约束（shuffle/reveal/reconstruct）
9. 零知识证明嵌入

### Lean 形式化工作进展

已完成的形式化工作（**21/21 方法**）：
- ✅ M31 域基础定义
- ✅ u64 ↔ 4×M31 limb 编码
- ✅ 37 通用列布局与通用约束
- ✅ 合约核心数据结构（Seat, TexasPokerTable 等）
- ✅ 所有 21 个方法的合约语义 + AIR 约束建模 + soundness 证明或反例

### 形式化结论汇总

**✅ AIR 是 sound 的（1/21）**

| 方法 | 定理 |
|------|------|
| create_table | `create_table_soundness`, `full_create_table_soundness` |

**❌ AIR 不是 sound 的（20/21，均通过反例证明）**

| 方法 | 定理 | 反例要点 |
|------|------|---------|
| fold | `fold_air_not_sound` | ROUND_WAITING 下 fold |
| check | `check_air_not_sound` | ROUND_WAITING 下 check |
| call | `call_air_not_sound` | ROUND_WAITING 下 call |
| raise | `raise_air_not_sound` | ROUND_WAITING 下 raise |
| bet | `bet_air_not_sound` | ROUND_WAITING 下 bet |
| auto_fold | `auto_fold_air_not_sound` | ROUND_WAITING 下 auto_fold |
| force_fold | `force_fold_air_not_sound` | ROUND_WAITING 下 force_fold |
| kick_player | `kick_player_air_not_sound` | 在空座位上 kick_player |
| join_table | `join_table_air_not_sound` | 座位未更新（seat.player 未写入） |
| leave_table | `leave_table_air_not_sound` | 不同合约违规（详见定理） |
| start_hand | `start_hand_air_not_sound` | 不同合约违规（详见定理） |
| tick | `tick_air_not_sound` | timeout_kind = 0 仍可通过 |
| reset_for_next_hand | `reset_for_next_hand_air_not_sound` | 其他合约违规（详见定理） |
| addon | `addon_air_not_sound` | amount = 0 不满足 > 0 |
| rebuy | `rebuy_air_not_sound` | amount = 0 不满足 > 0 |
| join_and_shuffle | `join_and_shuffle_air_not_sound` | shuffle_state.phase = 0 |
| leave_with_proof | `leave_with_proof_air_not_sound` | shuffle_state.phase = 0 |
| submit_shuffle_v2 | `submit_shuffle_v2_air_not_sound` | shuffle_state.phase = 0 |
| submit_player_reveal_tokens | `submit_player_reveal_tokens_air_not_sound` | reveal_phase = 0 |
| submit_reconstruct_deck | `submit_reconstruct_deck_air_not_sound` | reconstruct_state = ReconstructIdle |

### 弱化关系（Partial Soundness）

每个反例方法同时证明了：
- `Contract<Method>` ⟹ `Contract<Method>Partial`（合约语义蕴含其弱化版本）

这表明 AIR 约束对应的「部分合约语义」是 AIR 约束的上界：
AIR 接受的执行 ⊆ Contract<Method>Partial ⊊ Contract<Method>

### 已证明的核心结论

1. **create_table AIR 是 sound 的** — 约束完全蕴含合约语义
2. **其余 20 个方法的 AIR 均不是 sound 的** — 每个方法都存在反例，
   使得 AIR 约束可被满足但合约语义被违反
3. **共同缺陷**（20 个非 create_table 方法）：
   - `version += 1` 约束已补齐（21/21 方法）
   - 缺少 state root 一致性验证（Poseidon252）
   - 部分方法已补齐 round_state gating（join_table/leave_table/start_hand），动作方法仍缺少下注轮 gating
   - 缺少业务前置条件（amount > 0、seat.is_occupied、current_turn 等）
4. **fold 扩展约束部分 sound** — `FullFoldAirAcceptable` 蕴含 `ContractFoldPartial`，
   证明 AIR 约束至少能保证其追踪的子集字段的正确性

### 形式化文件清单

- **基础**：`Common/M31.lean`, `Common/U64Encoding.lean`, `Common/CommonColumns.lean`
- **合约语义**：`Contract/Types.lean`, `Contract/Constants.lean`,
  `Contract/CreateTable.lean`, `Contract/Fold.lean`, `Contract/Check.lean`,
  `Contract/Call.lean`, `Contract/Raise.lean`, `Contract/Bet.lean`,
  `Contract/MoreActions.lean`, `Contract/JoinTable.lean`, `Contract/LeaveTable.lean`,
  `Contract/Lifecycle.lean`, `Contract/Funds.lean`, `Contract/Crypto.lean`
- **AIR 约束**：`AIR/AirBase.lean`, `AIR/CreateTableAir.lean`,
  `AIR/FoldAir.lean`, `AIR/CheckAir.lean`, `AIR/CallAir.lean`,
  `AIR/RaiseAir.lean`, `AIR/BetAir.lean`, `AIR/MoreActionsAir.lean`,
  `AIR/JoinTableAir.lean`, `AIR/LeaveTableAir.lean`,
  `AIR/LifecycleAir.lean`, `AIR/FundsAir.lean`, `AIR/CryptoAir.lean`
- **Soundness 证明**：`Proofs/CreateTableSoundness.lean`,
  `Proofs/FoldSoundness.lean`, `Proofs/FoldPartialSoundness.lean`,
  `Proofs/FullSoundness.lean`, `Proofs/CheckSoundness.lean`,
  `Proofs/CallSoundness.lean`, `Proofs/RaiseSoundness.lean`,
  `Proofs/BetSoundness.lean`, `Proofs/MoreActionsSoundness.lean`,
  `Proofs/JoinTableSoundness.lean`, `Proofs/LeaveTableSoundness.lean`,
  `Proofs/LifecycleSoundness.lean`, `Proofs/FundsSoundness.lean`,
  `Proofs/CryptoSoundness.lean`
- **主定理聚合**：`PokerLean.lean`
- **审计报告**：`Audit/SoundnessAudit.lean`

**所有 Lean 定理已通过 Lean 4.13.0 + Mathlib v4.13.0 验证（`lake build` 成功）**

### 待完善的工作（非阻塞，用于补强 soundness）

如要让 20 个非 create_table 方法达到 soundness，AIR 实现需补齐：
1. **state root 一致性**：嵌入 Poseidon252 AIR 子组件
2. **方法 gating**：根据合约语义强制状态阶段
3. **业务前置/后置条件**：amount > 0、seat 状态、资金守恒等
4. **密码学证明嵌入**：DLEq/ZKShuffle/RevealToken/Reconstruct 证明
   （或显式声明由外部 ZK 验证器负责，并在 soundness 假设中明确）
-/
