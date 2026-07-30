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

Mental Poker 方法的 AIR 仍未嵌入 DLEq/shuffle/reveal/reconstruct verifier AIR；
当前 host 路径依赖上述完整 VM replay 执行原生密码学验证。原有
`TableConfig.zk_skip_*` 运行时开关曾使默认桌台可跳过这一步；现已收窄为
`poker_l1` crate 自身 `cfg(test)` 单元测试专用。普通库、集成测试与生产
构建即使解析到旧的 skip 字段，`skip_*()` 也始终返回 false。这闭合了
host replay 的默认绕过，但不代替 recursive crypto verifier AIR。
此外，`leave_with_proof` 的退款已与 `leave_table` 对齐为 checked-u64：
refund 溢出或 chip_pool/addon_pool 下溢会在修改牌组、聚合公钥、座位或事件前
fail-closed，不再用 saturating arithmetic 静默截断坏状态。

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
1. ~~Merkle 组件在 `query_positions` 为空时仍是 no-op(`trace_gen.rs:881-885`)~~
   **已收窄闭合（P05-R gap #1）**：`prove_recursive[_with_fri]` 与
   `verify_recursive[_with_fri]` 入口现新增 `ensure_nonempty_public_inputs` 守卫，
   空的 `l1_commitments` / `query_positions` / `log_size==0` 一律返回
   `L1CommitmentsMissing` / `QueryPositionsMissing` / `InvalidLogSize`；
   `gen_merkle_path_trace` 的空-query 早退分支已删除。审计 e2e 已改为从真实 L1 proof
   提取 `commitments`（`l1_proof.0.commitments`）与 transcript-sampled
   `query_positions`（新增 `extract_query_positions_from_l1`），使 Merkle Path AIR
   不再走 no-op 路径。
   - **gap #3-A（felt252→M31 编码非法/有损，已闭合）**：深入后发现 `field_element_252_to_m31_limbs`
     原把 felt252 大端字节切成 8×32-bit chunk 直接 `from_u32_unchecked` 装入 M31，但 32-bit chunk
     可达 `2^32-1` 远超 M31 的 `2^31-1`，debug profile 下 `partial_reduce` add-with-overflow panic
     （release 下静默产生非法 M31）。上一版改成 8×31-bit 后虽然不 panic，却又截断 felt252 高 4 bit，
     且 radix `2^31` 的 digit `2^31-1` 本身等于 M31 模数、仍不是合法 canonical field element。
     现改为 **9-limb radix-(2^31-1)** 小端分解，每个 limb 严格小于 M31 模数，编码/解码完整可逆；
     新增高于 bit 248 的碰撞回归和 `FieldElement252::MAX` 往返回归。
   - **gap #3-B（真实 Merkle verifier AIR 未实现，未闭合但已显式 fail-closed）**：对照 Stwo 2.3 后确认，
     `MerkleDecommitmentLifted.hash_witness` 是跨 query 合并、仅在 sibling 未由其他 query 推导时才消费的
     压缩序列；当前 `query_idx * tree_height + layer_idx` 的 dense-path 索引模型错误，且只触及
     `decommitments[0]`/`l1_commitments[0]`。leaf 构造也没有携带 verifier 侧的 per-tree column log sizes，
     无法复现 Stwo 对列排序和 row hashing。更关键的是 `MerklePathAir` 的所谓 Poseidon 约束仍只是
     `parent_limb = left_limb * right_limb`，并未约束 Starknet Poseidon252。故真实数据上的
     `Constraints not satisfied` 只是偶然失败，不是安全边界；恶意输入仍可能满足这些错误多项式。
     现在 `prove_recursive_with_fri` / `verify_recursive_with_fri` 在 crate 内测试路径也显式返回
     `IncompleteMerkleVerifierAir`，不再执行该组件；回归测试
     `gap3b_incomplete_merkle_air_is_explicitly_disabled` 固化这一 fail-closed 行为。相关成功往返测试继续
     `#[ignore]`，直到压缩 multi-query replay、所有 tree commitment、column metadata 和真实 Poseidon252
     AIR 全部实现并经过密码学审计。未完成的 verifier AIR 模块与 Merkle trace 生成器也已收窄为
     crate-private，外部调用方不能绕过高层 gate 直接复用占位组件。
2. 递归只包裹**单个** L1 proof，**无 N-proof 聚合机制**（未变）。
3. 递归只测试过 trivial padding CPU trace，从未跑过真实 Texas method AIR
   （未变；且 `poker_zkvm` 的 guest crate `guests/texas_poker` 本轮尚未迁入 zchain
   workspace，真实 method proof 端到端路径暂不可用）。

由于这些缺口允许恶意 prover 针对任意声明重新生成一个满足当前局部 AIR 的 L2 proof，
`poker_zkvm` 的 OODS-only 实验路径仅在 crate 自身 `cfg(test)` 中执行；含 FRI/Merkle 的
`*_with_fri` 路径在 crate 内也因 `IncompleteMerkleVerifierAir` fail-closed。跨 crate 调用
统一返回 `UnsoundBackendDisabled`。L1 的 `StwoZkVerifier` 即使治理状态为 Production 也
返回 `verified = false`，不再使用 `RecursivePublicInputs::default()` 接受未绑定
`ZkPublicIo` 的 proof。

### 修复路径(均需密码学专家)
- **(a) 让单 proof 递归 sound**：公开输入 transcript binding 已完成；gap #1 的
  空-input no-op 守卫与 felt252 无损编码已闭合（见上）；**仍需**把 verifier 的 per-tree
  column log sizes/lifting metadata 加入递归 statement，按 Stwo 算法消费压缩 multi-query
  decommitment、覆盖全部 commitments，并实现真实的 non-native Poseidon252 AIR（或经过证明的等价 lookup），
  再证明 OODS/FRI/Merkle verifier AIR 的组合 sound。（密码学/AIR 大改 + review）
- **(b) 构建 N-proof 聚合**:在 sound 的单 proof 递归之上,设计二叉树折叠或专用多验证器 AIR。(~1-2 周 + 设计决策)
- **(c) host-side 逐子验证**(已实现的过渡路径):host 对每个子 proof 跑
  `stwo::verify()`，只允许 verifier-issued receipt 进入 `VerifiedChain`。该路径失去
  succinctness，验证方仍需 O(N) 全验证；仅作过渡姿态。

### 结论
**真正的 recursive/succinct 聚合仍不可机械修复。** 需剩余 ~1 周让单 proof
递归 sound（leaf/sibling 真实绑定 + 组合 sound 证明）+ ~(1)周集成到真实 method AIR +
~(1-2)周设计 N-proof 聚合 + 密码学 sign-off。

**当前状态**：
- descriptor-only prove/verify 生产入口继续 fail-closed；
- `poker_zkvm` recursive PoC 与 L1 `StwoZkVerifier` 生产路径均 fail-closed；
- `poker_zkvm` 主 crate 已迁入 zchain workspace（`members` 含 `poker_zkvm`）；其
  guest 子 crate（`guest_sdk` / `guests/texas_poker`）暂未迁入，依赖它们的 E2E
  测试与 bench 暂留外部目录；
- `test-helpers` 已从 root / `poker_l1` 普通依赖移除，仅保留在 `poker_l1` dev-dependency；
  release 依赖图不再暴露测试 ELF/证明构造器；
- **P05-R gap #1**（空-input Merkle no-op）已收窄闭合 + 回归（守卫拒绝空 commitments/query/log_size）；
  **gap #3-A**（felt252→M31 非法/有损编码）已修复为 9-limb radix-(2^31-1) 无损编码；
  **gap #3-B**（压缩 multi-query witness / 全 tree commitment / column metadata / 真实 Poseidon252 AIR）
  尚未实现，但 `_with_fri` 已改为显式 `IncompleteMerkleVerifierAir` fail-closed，不再依赖偶然的
  `Constraints not satisfied`（回归测试 `gap3b_incomplete_merkle_air_is_explicitly_disabled`）；
  gap #2（N-proof 聚合）、gap #3 主体（leaf/sibling 真实绑定 + verifier AIR 组合 sound + 真实 method proof 端到端）未闭合；
  `poker_zkvm` 当前定向回归：OODS-only 路径、空输入守卫、9-limb 无损往返/高位保留、gap#3-B 显式关闭均通过；
  `_with_fri` 成功往返测试因 gap #3-B 暂时 `#[ignore]`（修复后应解除）；
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
