# P0-5 / P0-6 当前实现与可信边界

本文只描述 `poker_texas_air` 当前生产架构。`poker_zkvm` 不在 zchain workspace、依赖图或
本轮交付范围内；这里不把旧 zkVM/递归实验当作可用能力或待修前置条件。

## P0-5：Host-native 验证、digest 绑定与聚合边界

### 已完成

- Orchestrator 从完整 `ProveTask` 重放 canonical VM dispatch，要求 pre/post table、
  `DispatchContext + selector + raw_args`、method input、table/hand/call/version 全部一致。
- 每个 method STARK 由 host-native Stwo verifier 验证，成功后才能签发字段私有的
  `VerificationReceipt`。
- `VerifiedChain` 检查 table/hand、连续 call sequence、完整 state root/version 链；
  `ExpectedChainAnchor` 再绑定精确 receipt 数量、调用 digest 和首尾状态。
- consensus anchor 路径会验证 block/certificate 与 SMT inclusion proof，避免仅从同一批
  未认证 task 反推 anchor。
- 六条 Mental Poker crypto route 均有 stage-3 dual-proof package：
  `fold_with_proof`、
  `join_and_shuffle`、`submit_shuffle_v2`、`leave_with_proof`、
  `submit_player_reveal_tokens`、`submit_reconstruct_deck`。

### Crypto proof 的当前信任模型

当前选择是 `host-native verifier + canonical request/receipt digest + context binding`，不是
BLS12-381 AIR，也不是 Cairo verifier execution proof：

1. verifier 从已认证 task/pre-state 重建唯一 canonical crypto request；
2. 对该 request 执行一次 host-native BLS12-381 verifier；
3. 成功后签发 `PrecompileCallBinding`。其字段私有、无 wire deserializer、无 unchecked
   constructor，safe Rust 调用者不能伪造；
4. method AIR 约束完整 256-bit request digest 与 receipt digest；
5. production verifier 再校验 canonical bytes、precompile id、ABI、backend、digest，以及
   table/hand/call/seat/pre-post state scope，但不重复同一昂贵 BLS 验证。

公开的 `PrecompileCallBinding::reverify()` 仍保留，供跨进程持久化边界或显式要求独立二次
重放的调用方使用；正常 Orchestrator/dual-proof 路径依赖 verifier-issued capability，一次
native crypto 验证即可。

### 未完成且不应误报

- 当前没有 sound recursive/succinct aggregate proof；验证成本仍是 O(N)。
- descriptor-only `AggregatorAir` 不验证 child proof，生产聚合入口保持 fail-closed。
- host receipt 或 outer digest package 不是“链上常数成本验证”的替代品；若未来需要链上压缩，
  必须另行实现并审计固定 Texas/Stwo verifier program。
- 本地验证不能单独证明交易已被共识收录，必须使用 consensus-derived anchor。

## P0-6：下注动作覆盖范围

### 已完成

- fold/check/call/raise/bet/auto-fold/force-fold 都会从 canonical pre/post table 重放真实 VM
  action，并把 trusted row 绑定进 STARK transcript。
- mid-round 路径约束 actor 的 stack/bet/total_bet、pot/round 不变和下一行动座位。
- heads-up 最后一个 `check` 已支持 terminal end-of-round：可收池、清零 seat bets、推进
  round、令 `current_turn = None`，并用 sentinel trace encoding 与 canonical post-state 对齐。
- last-opponent `fold` / `fold_with_proof` 已支持 clean terminal settlement：先收集全部 live
  `seat.bet`，再约束 `pre_pot + collected_bets = gross_pot`、`award + rake = gross_pot`、
  `pre_winner_stack + award = post_winner_stack`，最后 reset 到 `WAITING`。生产 verifier 仍从
  canonical VM replay 派生 winner 与完整 pre/post table；`fold_with_proof` 同时保留 native
  DLEq request/receipt digest 和调用上下文绑定。
- terminal showdown reveal 的 settlement + reset 双 version bump 已有专门允许路径。
- showdown 已先在 `poker_l1::texas_poker` 规范化为确定性的 `SettlementPlan`：固定 9 座位、
  最多 9 层 side pot、1/2 个 runout、完整 hand rank/winner mask、按 button 顺时针分配奇数
  筹码，并对完整 Borsh plan 做 domain-separated Blake2b digest。单座位外层 pot 被视为
  uncalled return，不抽水且不拆成两次 runout。
- 最后一个 showdown reveal 的 canonical replay 必须恰好产生一个
  `SettlementPlanCommitted`。verifier 从事件重建 plan digest、runout count、gross/rake/
  total awards 和固定 9 座位 award；submit-reveal AIR 绑定全部投影，并用 4×16-bit ripple
  carry 约束 `total_awards + rake = gross_pot`。非终局 reveal 出现任何 settlement event
  会 fail-closed。
- Run It Twice 已具备完整 native 状态与 reveal routing：记录触发轮次、共享 board 前缀和
  第二 board；后续公共牌 assignment 显式绑定 `(encrypted index, runout, board position)`，
  reconstruct restart 使用新 deck index 且保留两块已公开 board，终局 plan 的
  `runout_count = 2` 会进入上述 AIR 投影。

### 本轮补齐的 fail-closed 分支

- terminal fold reset 已覆盖 pending addon credit、`want_leave` seat removal/refund，并在
  Settlement component 中固定绑定 9 座位 post stack、post pending addon、post occupancy、
  addon credit/refund 与 chip refund；reset 后所有 pending addon 必须为 0。
- `kick_player` 在 WAITING 状态触发的 nested reset 已规范化为 `ResetOnly` settlement，
  method AIR 只允许该 canonical 路径使用 version increment 2，其他未建模 multi-version
  transition 继续 fail-closed。

showdown side pot、多人 winner、hand evaluator、rake 和 RIT 结算现在可由当前生产架构接受，
但其可信性来自 verifier 对 canonical native dispatch 的重放与完整 `SettlementPlan` digest
绑定；STWO AIR 本身不重新执行 hand evaluator 或 side-pot planner。若目标改为“即使 host
verifier 恶意也能由单个 STARK 独立证明结算计算”，仍需把这些算法改写为 AIR/固定 verifier
program，这不属于当前 host-native + digest 架构。

terminal `call` / `raise` / `bet` 的 clean round completion 已支持：native replay 先重建动作后
的下注状态，再约束所有 live `seat.bet` 收池、`pre_pot + collected_bets = post_pot`、清零
seat bets 和下一 reveal phase。这些此前未覆盖的分支不能只增加一个布尔列完成：VM transition
会同时扫描多个 seat、推进 round/reveal phase，甚至执行 settlement/reset。因此现通过下述
四段可组合 AIR；现有 method AIR 仍作为兼容层保留，但完整生产 archive 还必须携带四段独立
proof bundle，不能只提交 method proof 绕过 component 验证。

### 可组合 transition plan / 四份独立 STARK proof

新增 `airs::composition`，canonical native replay 会把一个原子 dispatch 规范化为固定顺序：

```text
dispatch pre image
  -> SeatUpdate
  -> BetCollection
  -> RoundAdvance
  -> Settlement/Reset
  -> dispatch post image
```

`CompositeTransitionPlan` 固定绑定 schema version、method/table/hand/call scope、完整 canonical
pre/post table image digest 和四段业务 payload。每段都有相同的 stage header：

- `active + stage_kind + stage_index`；
- 完整 256-bit `plan_digest`（16 个精确 u16/M31 limb）；
- 完整 256-bit `input_digest` / `output_digest`；
- 相邻段强制使用同一 boundary digest。

这里的 boundary digest 是 verifier 从完整原子 replay 生成的 projection commitment，不冒充链上
持久化的 intermediate table root。四个 component 现在分别生成独立 Stwo proof、独立 trace
commitment 和独立 Fiat–Shamir transcript；bundle 验证固定检查
`stage[i].output_digest == stage[i+1].input_digest`，而不要求 VM 在一个 atomic dispatch 中额外
落盘四份中间 table。

四个固定宽度 component 当前包含：

- `SeatUpdate`：acting seat 的 stack/bet/total_bet checked-u64 delta、fold/all-in 和固定 9 座
  `acted_this_round` 前后投影；raise/bet 对其他可行动座位的 acted reset 也进入 payload。
- `BetCollection`：action 后固定 9 座 seat bets，使用 9 段 4×16-bit ripple-carry 在 AIR 内求和，
  再约束 `pre_pot + collected_bets = post_pot`；全员 check 的零金额 collection 仍是 active stage。
- `RoundAdvance`：pre/post round、reveal phase、current turn sentinel、pot 和 community-card count，
  并限制合法的 preflop→flop→turn→river→showdown 边。
- `Settlement`：复用 showdown `SettlementPlanBinding`，无摊牌路径生成 domain-separated deterministic
  plan digest；固定 9 座 awards、addon credits、chip/addon refunds、post stacks、post pending
  addons 和 post occupancy 均进入 AIR，并约束 chip pool / addon pool / rake 守恒和 reset。

production verifier 已在 fold/check/call/raise/bet/auto-fold/force-fold、`fold_with_proof` 和
`submit_player_reveal_tokens` 的 canonical replay 后派生并验证该 plan，因而旧 method row 与新
component ABI 迁移期间不会形成第二套可自由选择的业务解释。

`AirStatement` / `TexasPublicInputs` 已加入完整 `ComponentStatement`，把 component kind、plan
digest、stage index、input/output boundary commitment 混入 transcript。`ArchivedCompositionProofBundle`
固定保存 SeatUpdate、BetCollection、RoundAdvance、Settlement 四份 proof；缺失、重复、重排、
plan digest 不符或 task scope 不符都会拒绝。proving service durable package 已升级为 schema v2，
启动恢复、下载验证和 P2P proof repair 都同时验证 method archive 与所需 component bundle。

这仍不是 recursive/succinct aggregation：验证一个 composite transition 需要验证原 method proof
和四份 component proof，成本与包体均增加。它解决的是职责拆分、可组合性和 fail-closed 边界，
不解决链上常数成本压缩。

现有 `DualProofBundle` 仍是“method STARK + native crypto request”的两部分传输格式；对
`fold_with_proof` / terminal reveal 这类 composite method，它不能替代 durable v2 package 中的
四份 component proof，也不能单独作为完整 composite archive。

## 其他仍存在的证明缺口

- `kick_player` / `force_fold` 的管理员签名尚未放入 AIR；权限当前依赖 canonical dispatch
  replay 和已认证调用上下文。
- 金额字段尚未全部统一为完整 nonnegative/range/checked-u64 AIR 约束。
- `TexasPokerTable` Borsh ABI 已升级为 schema v2 并显式校验；旧 v1 singleton table 不会被
  静默解释为 v2，部署升级时必须迁移或重建。
- 多 validator `CommitVote` 已接入 P2P 签名校验、按 signer 去重、2/3 quorum 收集、
  certificate 组装与成功提交后的清理；它不再属于“消息结构存在但未收集”的缺口。
- PEX 目前会校验、去重并传播发现地址，但尚无针对新地址的后台主动拨号、失败退避与
  peer 生命周期管理；VRF proposer gossip 和 background proof repair 也仍是节点/网络/运维
  缺口，不由当前 method AIR 修复覆盖。

## 结论

当前主线适合“不追求链上压缩”的目标：host-native crypto/Stwo 验证性能最高，digest 与
canonical context 防止 proof、receipt、table 或 call scope 被替换。它提供可信 host acceptance，
但不声称递归压缩；剩余产品功能缺口仍需后续独立设计。
