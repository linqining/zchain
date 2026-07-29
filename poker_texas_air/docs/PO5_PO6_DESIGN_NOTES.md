# P0-5 / P0-6 设计备注(待处理)

> 这两个 P0 **不可机械修复**,需要密码学设计决策或 AIR 层重设计。
> 本文档记录根因、评估结论、可选修复路径,供后续专家处理。

---

## P0-5:Aggregator 不验证任何子证明

### 根因
`AggregatorAir` 是 descriptor-only PoC:
- 接口只接收 `ChildDescriptor`(`aggregator_air.rs:107`),仅含 `pre/post_state_root` + `call_seq` + `method_kind`,**不含 StarkProof**。
- `evaluate`(`aggregator_air.rs:175-256`)只约束链式连续性(`left.post_state_root == right.pre_state_root`)+ method_kind/call_seq 一致性,**零个约束触及 StarkProof/commitment/FRI**。
- 生产入口 `prove_aggregator`/`verify_aggregator` 已 fail-closed(`UntrustedAggregationDisabled`),仅 `*_unchecked_for_tests` 跑。

### 数据流问题
`orchestrator.rs:82-103` 的 `ProvenTask` 只保留 root/call_seq 摘要,**StarkProof 在 prove 后即丢弃**。聚合时拿不到子证明。

### 现有递归基础设施(存在但不 sound)
`poker_zkvm::stwo_backend::recursive` 有递归层,但:
1. **被项目自己的审计测试标记为 unsound**:`tests/recursive_backend_unsoundness.rs:26-72` 实证——篡改 L1 的 `l1_commitments`/`fri_first_layer_commitment`/`query_positions`/`log_size` 后,L2 proof 仍验证通过。
2. 根因:`l1_commitments` 从未 mix 进 Fiat-Shamir channel(`recursion_prover.rs:409-433`);Merkle 组件在 `query_positions` 为空时是 no-op(`trace_gen.rs:881-885`),而所有生产调用方都传空。
3. 递归只包裹**单个** L1 proof,**无 N-proof 聚合机制**。
4. 递归只测试过 trivial padding CPU trace,从未跑过真实 Texas method AIR。

### 修复路径(均需密码学专家)
- **(a) 让单 proof 递归 sound**:wire 真实 `l1_commitments`+`query_positions` 进 `RecursivePublicInputs` + `mix_public_inputs_into_channel`;让 `gen_merkle_path_trace` 非空并绑定 root;证明结果 AIR sound。(~1-2 周 + 密码学 review)
- **(b) 构建 N-proof 聚合**:在 sound 的单 proof 递归之上,设计二叉树折叠或专用多验证器 AIR。(~1-2 周 + 设计决策)
- **(c) host-side 逐子验证**(临时):aggregator 在 host 对每个子 proof 跑 `stwo::verify()`,AIR 只做 chaining。但失去聚合的 succinctness(验证方仍需 O(N) 全验证)。仅作过渡姿态。

### 结论
**不可机械修复。** 需 ~(1-2)周让单 proof 递归 sound + ~(1)周集成到真实 method AIR + ~(1-2)周设计 N-proof 聚合 + 密码学 sign-off。总量约一个月专家工作。

**当前 fail-closed 已就位**(生产入口拒绝),所以是"已知未完成特性",非活跃漏洞。

---

## P0-6:下注语义与 VM 不等价(最难,根本性建模缺口)

### 根因
VM 的 `apply_call`/`apply_raise`/`apply_bet` **不是单步 seat 更新**——它们在更新 seat 字段后**无条件调用 `advance_turn`**(`state_machine.rs:2110`/`2185`,bet 经 `3367` 委托 raise)。

`advance_turn`(`state_machine.rs:557-570`)分支:
- **mid-round**(`is_betting_complete==false`):仅推进 `current_turn`。pot/round_state 不变。← **AIR/Lean 唯一正确捕获的情形**
- **end-of-round**(`is_betting_complete==true`):`collect_bets_to_pot`(`573-599`)扫所有 seat 的 bet→pot 并清零;`advance_round`(`604-659`)改变 round_state(PREFLOP→FLOP→...→SHOWDOWN),可能触发结算(`end_without_showdown`/`settle_hand`)。

### 具体反例(heads-up preflop)
SB=BB=10。SB call(amt=0)→ mid-round → AIR 成立。BB check → `is_betting_complete==true` → **单个 apply_check 产生**:
- round_state: PREFLOP→FLOP(**违反** AIR `round_state_unchanged`)
- pot: += 20(SB.bet+BB.bet,非 call_amount 的 0)(**违反** `pot += call_amount`)
- 两 seat 的 bet 清零(**违反** Lean "其他 seat 不变")
- current_turn: Some→None

**所以单个 VM-legal apply_call/raise/check 常规性地产生 AIR/Lean 声明不可能的 post-state。** AIR 的 `round_state_unchanged` + `pot_delta(call_amount)` 对收尾动作根本不可满足。

### AIR 是单步 seat-update 模型
AIR/Lean 只建模 actor 的 stack/bet/total_bet/pot 增量 + round 不变,无列承载:其他 seat 的 bet、betting_round、current_turn→None、round 推进、结算。AIR 对 seat-update 子步 sound,但对完整 VM transition unsound。

### 修复路径
- **(a) 单 AIR 建模完整 transition**:需多 seat bet-sweep、is_betting_complete 谓词、4 态 round 状态机、side-pot、手牌评估、rake。**极复杂,拒绝。**
- **(b) 多 AIR 分解**(正确的 sound 修复,大重设计):
  1. seat-update AIR(≈现有,但 post-state 弱化为 advance_turn 前的中间快照)
  2. bet-collection AIR(`collect_bets_to_pot` 多 seat 扫)
  3. round-advance AIR(`advance_round` + reveal-phase 触发)
  4. settlement AIR(`end_without_showdown`/`settle_hand`,含手牌评估+side-pot)
  经中间 state root 组合。**可行但量大**:3-4 个新 AIR + 组合层;settlement AIR 继承手牌评估+side-pot 复杂度。
- **(c) 收窄 AIR 声明范围 + 加 "仍在 mid-round" 守卫**(低工作量的诚实过渡):
  - 保留现有约束,但 post-state 声明为"advance_turn 前的中间态"
  - 加守卫:`post.current_turn = Some(next_seat)`(非 None),因 advance_round/结算都置 None,而 mid-round 置真实 seat
  - 诚实表述:"本 AIR 证明 seat 更新,**条件是该动作未收尾本轮**"
  - 工作量小(每 action AIR 加 1-2 witness 列 + 守卫约束),但**收尾动作/结算完全不验证**(覆盖部分)
  - 注意:`current_turn ≠ None` 是单向 sound 代理(若 None 则必然推进/结算),但恶意 prover 可能伪造 mid-round 外观。故 (c) 是文档+部分守卫缓解,非完整 soundness 修复。
- **(d) 纯文档记录为已知限制**:必须伴随 (b) 或 (c)。

### 结论
**不可机械修复,是最难的 P0。** 根因结构性:VM 的 call/raise/bet 把 seat 更新和无条件的 advance_turn(可能收注/推进/结算)捆绑在同一个函数,AIR 只约束前半。

- 正确修复 = **(b) 多 AIR 分解**(大重设计,非补丁)
- 务实过渡 = **(c)** 收窄范围 + current_turn≠None 守卫(小工作量,但覆盖部分)
- (a) 不现实;(d) 单独留系统 unsound

---

## 总结对照

| P0 | 状态 | 处理建议 |
|---|---|---|
| P0-4 | ✅ **已修复**(`f38bc51` canonical Borsh 全字段) | 可选清理死代码 |
| P0-5 | ❌ 不可机械修复 | 留本文档;需密码学专家(~1 月) |
| P0-6 | ❌ 不可机械修复 | 留本文档;需 AIR 重设计(最难) |
