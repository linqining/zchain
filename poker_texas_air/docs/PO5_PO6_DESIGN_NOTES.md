# P0-5 / P0-6 设计备注(待处理)

> 这两个 P0 **不可机械修复**,需要密码学设计决策或 AIR 层重设计。
> 本文档记录根因、评估结论、可选修复路径,供后续专家处理。

---

## P0-5:Aggregator 不验证任何子证明

本项拆分为两个不同的交付边界：
- **P05-H（Host O(N) batch verification）：✅ 已完成。** 逐个原生验证子 proof，
  只从 verifier-issued receipt 构造可信链。
- **P05-R（Recursive/succinct aggregation）：❌ 未完成。** 当前递归后端不 sound，
  不存在可转移的单聚合 proof。

### 根因
`AggregatorAir` 是 descriptor-only PoC:
- 接口只接收 `ChildDescriptor`(`aggregator_air.rs:107`),仅含 `pre/post_state_root` + `call_seq` + `method_kind`,**不含 StarkProof**。
- `evaluate`(`aggregator_air.rs:175-256`)只约束链式连续性(`left.post_state_root == right.pre_state_root`)+ method_kind/call_seq 一致性,**零个约束触及 StarkProof/commitment/FRI**。
- 生产入口 `prove_aggregator`/`verify_aggregator` 已 fail-closed(`UntrustedAggregationDisabled`),仅 `*_unchecked_for_tests` 跑。

### 数据流问题
`ProvenTask` 仍只是 root/call_seq descriptor，不能作为子证明已验证的证据。
当前可信过渡路径已改为：Orchestrator 对每个 `MethodProof` 调用原生
Stwo verifier，成功后才签发字段私有的 `VerificationReceipt`，然后由
`VerifiedChainBuilder` 检查 table/hand/call_seq/完整 Poseidon252 root/version 连续性。
proof 在当次原生验证后仍不会被压缩成可转移的 recursive proof；因此这只是
可信宿主进程内的 O(N) 接受产物。

### 现有递归基础设施(存在但不 sound)
`poker_zkvm::stwo_backend::recursive` 有递归层,但:
1. **被项目自己的审计测试标记为 unsound**:`tests/recursive_backend_unsoundness.rs:26-72` 实证——篡改 L1 的 `l1_commitments`/`fri_first_layer_commitment`/`query_positions`/`log_size` 后,L2 proof 仍验证通过。
2. 根因:`l1_commitments` 从未 mix 进 Fiat-Shamir channel(`recursion_prover.rs:409-433`);Merkle 组件在 `query_positions` 为空时是 no-op(`trace_gen.rs:881-885`),而所有生产调用方都传空。
3. 递归只包裹**单个** L1 proof,**无 N-proof 聚合机制**。
4. 递归只测试过 trivial padding CPU trace,从未跑过真实 Texas method AIR。

### 修复路径(均需密码学专家)
- **(a) 让单 proof 递归 sound**:wire 真实 `l1_commitments`+`query_positions` 进 `RecursivePublicInputs` + `mix_public_inputs_into_channel`;让 `gen_merkle_path_trace` 非空并绑定 root;证明结果 AIR sound。(~1-2 周 + 密码学 review)
- **(b) 构建 N-proof 聚合**:在 sound 的单 proof 递归之上,设计二叉树折叠或专用多验证器 AIR。(~1-2 周 + 设计决策)
- **(c) host-side 逐子验证**(已实现的过渡路径):host 对每个子 proof 跑
  `stwo::verify()`，只允许 verifier-issued receipt 进入 `VerifiedChain`。该路径失去
  succinctness，验证方仍需 O(N) 全验证；仅作过渡姿态。

### 结论
**真正的 recursive/succinct 聚合仍不可机械修复。** 需 ~(1-2)周让单 proof
递归 sound + ~(1)周集成到真实 method AIR + ~(1-2)周设计 N-proof 聚合 +
密码学 sign-off。总量约一个月专家工作。

**当前状态**：
- descriptor-only prove/verify 生产入口继续 fail-closed；
- **P05-H** 可信 O(N) 宿主批量验证已闭合；
- **P05-R** 单个可转移的 recursive aggregate proof 仍是已知未完成特性。

---

## P0-6:下注语义的 mid-round 收窄与完整 VM transition 缺口

### 根因
VM 的 `apply_call`/`apply_raise`/`apply_bet` **不是单步 seat 更新**——它们在更新 seat 字段后**无条件调用 `advance_turn`**(`state_machine.rs:2110`/`2185`,bet 经 `3367` 委托 raise)。

`advance_turn`(`state_machine.rs:557-570`)分支:
- **mid-round**(`is_betting_complete==false`):仅推进 `current_turn`。pot/round_state 不变。
- **end-of-round**(`is_betting_complete==true`):`collect_bets_to_pot`(`573-599`)扫所有 seat 的 bet→pot 并清零;`advance_round`(`604-659`)改变 round_state(PREFLOP→FLOP→...→SHOWDOWN),可能触发结算(`end_without_showdown`/`settle_hand`)。

当前 Rust P06 改动选择了诚实的收窄边界：生产任务只在 post-state 仍是
same round、pot 不变、`betting_round/current_turn = Some(next)` 时构造动作 AIR；
收池、推进和结算分支返回 `UnsupportedBettingTransition`，不伪装成已证明。

### 具体反例(heads-up preflop)
SB=BB=10。SB call(amt=0)→ mid-round。BB check 使 `is_betting_complete==true`，则
**单个 apply_check 产生**:
- round_state: PREFLOP→FLOP
- pot: += 20(SB.bet+BB.bet，不是当前动作 amount)
- 两 seat 的 bet 清零
- current_turn: Some→None

**该合法 post-state 不满足 mid-round 谓词。** 当前生产路径对其 fail-closed；
这避免了错证，但也意味着此类常规收尾动作尚无 AIR 覆盖。

### 当前是 mid-round 局部模型
Rust AIR 现约束 actor 的 stack/bet/total_bet 更新、pot/round 不变，并绑定
verifier-trusted pre 金额与 `post_current_turn`。Lean Contract/AIR 的 pot 语义也已
改为 mid-round pot 不变。

但 Lean 列布局尚未镜像 Rust 新增的 trusted pre-amount/`post_current_turn`，
且 raise/bet 仍未建模对其他玩家 `acted_this_round` 的重置，也无模型承载
多 seat bet sweep、`current_turn→None`、round 推进和 settlement。
因此只能声称“mid-round 局部路径 fail-closed”，不能声称完整 VM transition
或 Rust↔Lean 精化已证明。

### 修复路径
- **(a) 单 AIR 建模完整 transition**:需多 seat bet-sweep、is_betting_complete 谓词、4 态 round 状态机、side-pot、手牌评估、rake。**极复杂,拒绝。**
- **(b) 多 AIR 分解**(正确的 sound 修复,大重设计):
  1. seat-update AIR(≈现有,但 post-state 弱化为 advance_turn 前的中间快照)
  2. bet-collection AIR(`collect_bets_to_pot` 多 seat 扫)
  3. round-advance AIR(`advance_round` + reveal-phase 触发)
  4. settlement AIR(`end_without_showdown`/`settle_hand`,含手牌评估+side-pot)
  经中间 state root 组合。**可行但量大**:3-4 个新 AIR + 组合层;settlement AIR 继承手牌评估+side-pot 复杂度。
- **(c) 收窄 AIR 声明范围 + mid-round 守卫**(当前过渡路径):
  - 生产任务从真实 pre/post table 提取 trusted 金额和 `post_current_turn`；
  - 仅 same-round、pot unchanged、`current_turn = Some(next)` 时证明；
  - 收池/推进/结算返回不支持，不产生证明；
  - 这是诚实的覆盖收窄，不是完整 P0-6 修复。
- **(d) 纯文档记录为已知限制**:必须伴随 (b) 或 (c)。

### 结论
**完整 P0-6 仍不可靠小补丁闭合。** 根因是 VM 将 seat 更新和
`advance_turn`（可能收注/推进/结算）捆绑在同一个方法中。

- 正确修复 = **(b) 多 AIR 分解**(大重设计,非补丁)
- 务实过渡 = **(c)** 生产 fail-closed 到 mid-round（已实现的收窄方向）
- Lean 仍需补齐新 Rust 列/spec 并证明逐约束等价
- (a) 不现实；(d) 只能作为边界记录

---

## 总结对照

| P0 | 状态 | 处理建议 |
|---|---|---|
| P0-4 | ✅ **已修复**(`f38bc51` canonical Borsh 全字段) | 可选清理死代码 |
| P0-5 | P05-H ✅；P05-R ❌ | 生产使用 `VerifiedChain`；succinct 聚合需密码学专家(~1 月) |
| P0-6 | mid-round 生产路径已收窄；full transition ❌ | 继续 fail-closed；收池/推进/结算需多 AIR 重设计 |
