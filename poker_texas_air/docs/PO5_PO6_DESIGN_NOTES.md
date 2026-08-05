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
- 五条 Mental Poker crypto route 均有 stage-3 dual-proof package：
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
- terminal showdown reveal 的 settlement + reset 双 version bump 已有专门允许路径。

### 仍 fail-closed

- last-opponent fold 触发的结算；
- terminal `call` / `raise` / `bet` 的通用收池与 round advance；
- side pot、winner distribution、完整 hand evaluator 与 rake settlement 的 AIR；
- `fold_with_proof` 的 DLEq layer removal 与可能的 settlement；
- `kick_player` 在 WAITING 状态触发 nested reset/multi-version transition 的复合路径。

这些分支不能只增加一个布尔列完成：VM transition 会同时扫描多个 seat、收集 bets、推进
round/reveal phase，甚至执行 settlement/reset。正确方向是把 seat update、bet collection、
round advance 和 settlement 拆成可组合的多 AIR，或继续在现有单步 AIR 入口 fail-closed。

## 其他仍存在的证明缺口

- `kick_player` / `force_fold` 的管理员签名尚未放入 AIR；权限当前依赖 canonical dispatch
  replay 和已认证调用上下文。
- 金额字段尚未全部统一为完整 nonnegative/range/checked-u64 AIR 约束。
- Run It Twice 仍只有配置标记，没有完整双 board 证明流程。
- 多 validator `CommitVote` 已接入 P2P 签名校验、按 signer 去重、2/3 quorum 收集、
  certificate 组装与成功提交后的清理；它不再属于“消息结构存在但未收集”的缺口。
- PEX 目前会校验、去重并传播发现地址，但尚无针对新地址的后台主动拨号、失败退避与
  peer 生命周期管理；VRF proposer gossip 和 background proof repair 也仍是节点/网络/运维
  缺口，不由当前 method AIR 修复覆盖。

## 结论

当前主线适合“不追求链上压缩”的目标：host-native crypto/Stwo 验证性能最高，digest 与
canonical context 防止 proof、receipt、table 或 call scope 被替换。它提供可信 host acceptance，
但不声称递归压缩；上述 terminal settlement 与产品功能缺口仍需后续独立设计。
