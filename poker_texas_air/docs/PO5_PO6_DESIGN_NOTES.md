# P0-5 / P0-6 实现与剩余可信边界

> 本文区分已落地的 fail-closed/host 机制和仍需密码学或 AIR 重设计的部分。
> “测试通过”不等于递归聚合、Rust↔Lean 精化或完整下注状态机已经证明。

---

## P0-5:Aggregator 不验证任何子证明

本项拆分为两个不同的交付边界：
- **P05-H-core（Host O(N) verification）：✅ 已完成。** 完整 VM dispatch replay、
  逐 proof 原生验证、opaque receipt、连续性和显式 `ExpectedChainAnchor` 首尾/范围/
  调用 digest 校验均已实现。
- **P05-H-source（共识来源接入）：🟡 未在本 crate 闭合。** 调用方必须从已认证
  block/receipt 构造 anchor；当前 proving service 只是本地 dispatch demo，不是 inclusion proof。
- **P05-R（Recursive/succinct aggregation）：❌ 未完成。** 当前递归后端不 sound，
  不存在可转移的单聚合 proof。

### 根因
`AggregatorAir` 是 descriptor-only PoC:
- 接口只接收 `ChildDescriptor`(`aggregator_air.rs:107`),仅含 `pre/post_state_root` + `call_seq` + `method_kind`,**不含 StarkProof**。
- `evaluate`(`aggregator_air.rs:175-256`)只约束链式连续性(`left.post_state_root == right.pre_state_root`)+ method_kind/call_seq 一致性,**零个约束触及 StarkProof/commitment/FRI**。
- 生产入口 `prove_aggregator`/`verify_aggregator` 已 fail-closed(`UntrustedAggregationDisabled`),仅 `*_unchecked_for_tests` 跑。

### 数据流问题
`ProvenTask` 仍只是 root/call_seq descriptor，不能作为子证明已验证的证据。
当前可信过渡路径已改为：Orchestrator 先用任务携带的完整
`DispatchContext + selector + raw_args` 重放公开 VM dispatch，要求完整 post table、
method input 与任务元数据逐字段一致；随后对每个 `MethodProof` 调用原生
Stwo verifier，成功后才签发字段私有的 `VerificationReceipt`，然后由
`VerifiedChainBuilder` 检查 table/hand/call_seq/完整 Poseidon252 root/version 连续性。
dispatch 调用摘要也被混入 method proof transcript。receipt 字段和链构造 API 已收窄为
crate-private，因此 descriptor 不能伪造 receipt；但外部仍可向 public Orchestrator 提交
任意自洽的离线 task，并获得“该转移经 VM replay + native verify”的 opaque receipt。
proof 在当次原生验证后仍不会被压缩成可转移的 recursive proof；因此这只是
可信宿主进程内的 O(N) 接受产物。

这里的“可信”依赖外部锚：`ExpectedChainAnchor` 校验 table/hand、精确 receipt 数量与
call_seq 范围、链首/链尾 full-width state root/version，以及每个
`dispatch_call_digest`。这些 anchor 字段必须来自已认证 block/receipt；若从同一批
待证 task 反推 anchor，不会增加信任。Orchestrator 能证明“给定 pre-state 上的完整
dispatch replay 与 proof 均被 host 接受”，但不能单靠任务里自带的 `DispatchContext`
证明调用真实被区块收录。

当前 wire metadata 的 `table_id` 是 `ObjectID.creation_nonce`，本身不是跨 creator
全局唯一。action 泛型 verifier 已把它绑定到 canonical pre/post table；可信链还依赖
包含完整 `ObjectID` 的 full-width state roots。后续若升级公开 schema，宜直接锚定完整
`ObjectID`（或其共识 key），而不是只把 nonce 当作全局桌号。

### 现有递归基础设施（公开输入重标记漏洞已修复，完整递归仍不 sound）
`poker_zkvm::stwo_backend::recursive` 的 P05-R public-input binding 已加固：统一的
`RecursivePublicInputs::mix_into` 现在以域分隔、长度前缀、完整 felt252/u64 编码绑定
`l1_commitments`、`fri_first_layer_commitment`、`fri_last_layer_poly`、
`query_positions`、`log_size` 以及其余 OODS/FRI 字段。审计回归验证同一个 L2 proof
在任一字段被替换后均失败。

但完整递归仍有以下缺口：
1. Merkle 组件在 `query_positions` 为空时仍是 no-op(`trace_gen.rs:881-885`)，而现有
   PoC 调用方仍可传空；transcript 绑定只能防止 proof 被事后重标记，不能证明任意声明的
   commitment/query 就来自被递归验证的 L1 proof。
2. 递归只包裹**单个** L1 proof，**无 N-proof 聚合机制**。
3. 递归只测试过 trivial padding CPU trace，从未跑过真实 Texas method AIR。

### 修复路径(均需密码学专家)
- **(a) 让单 proof 递归 sound**：公开输入 transcript binding 已完成；仍需强制从真实
  L1 proof 构造非空 commitments/query positions，让 `gen_merkle_path_trace` 非空并绑定
  所有 root/decommitment，再证明各 verifier AIR 的组合 sound。（~1-2 周 + 密码学 review）
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
- `test-helpers` 仅用于集成测试，release 构建若误启用该 feature 会在编译期拒绝；
- **P05-H-core** O(N) 宿主验证与完整范围 anchor 校验已闭合；
- **P05-H-source** 仍需上层把 anchor 接到已认证 block/receipt；
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
该守卫覆盖 fold/check/call/raise/bet/auto_fold/force_fold 七个会推进 turn 的动作。

`kick_player` 还有一条独立的复合转移边界：在 `WAITING` 状态踢掉最后一个活跃玩家时，
VM 可能在 `kick_player_internal` 内触发 `reset_for_next_hand`，随后 dispatch 再次
`bump_version`，因此一个 selector 会产生 reset/清理和多次 version bump。生产
Orchestrator 只接受 round 不变、`post_pot = pre_pot + kicked_bet` 且恰好单次 version
推进的 kick；触发嵌套 reset、settlement 或其他多步变化时同样返回
`UnsupportedBettingTransition`，不签发 proof/receipt。

VM 新注册的 `request_leave_after_hand` 与 `fold_with_proof` 仍可进入统一
ProveTask wire format，但生产 Orchestrator 在 dispatch replay/prove 之前显式
`NotImplemented` fail-closed，不生成 proof/receipt；泛型 `prove_method` /
`verify_method_against` 也通过 production AIR allowlist 拒绝二者。尤其 `fold_with_proof` 的
DLEq layer removal 及其可能触发的 advance/settlement 尚未进入可信 AIR。

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
verifier-trusted pre 金额与 `post_current_turn`。Lean Contract/AIR 的手写逻辑模型也已
同步为 mid-round pot/round 不变，加入 trusted pre-amount、Nat 级 checked-u64
算术、short all-in/conditional min-raise 和下一行动座位绑定；bet 只接受
FLOP/TURN/RIVER。

但尚未证明 Rust physical row layout 与这些 Lean logical records 的逐列/逐约束
refinement，也未建立 `expected_trace_row → BoundAir → transcript → Lean` 桥。
特别地，Lean bet 的 post `current_bet`/`min_raise` 是从 canonical post table 重建的
逻辑字段，当前 Rust `BetRow` 没有对应独立 physical columns。raise/bet 仍未建模
对其他玩家 `acted_this_round` 的重置，也无模型承载多 seat bet sweep、
`current_turn→None`、round 推进和 settlement。
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
- Lean logical spec 已同步 trusted amounts/next-turn；仍需证明 Rust physical
  row/约束到 Lean 的实现级 refinement
- (a) 不现实；(d) 只能作为边界记录

---

## 总结对照

| P0 | 状态 | 处理建议 |
|---|---|---|
| P0-4 | ✅ **已修复**(`f38bc51` canonical Borsh 全字段) | 可选清理死代码 |
| P0-5 | H-core ✅；H-source 🟡；R ❌ | 生产使用 consensus-derived `ExpectedChainAnchor` + `VerifiedChain`；succinct 聚合需密码学专家 |
| P0-6 | mid-round 生产路径已收窄；full transition ❌ | 继续 fail-closed；收池/推进/结算需多 AIR 重设计 |
