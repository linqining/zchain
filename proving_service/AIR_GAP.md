# proving_service 完整牌局验证说明

运行：`cargo run -p proving_service -- --full-hand`

`FullHandRunner` 现在会完成一局双人 Texas Hold'em 的真实 VM dispatch：建桌、两人入座、
开局、两次 shuffle、preflop/flop/turn/river/showdown reveal，以及四轮下注。每个状态变更都
由 `poker_texas_air::Orchestrator` 重放 canonical VM dispatch、生成 Stwo proof 并进行 host
verify；完整流程产生 32 个连续 receipt，state-root 链可验证。

## 已修复的终态转换

- 终结 shuffle 使用 **pre-dispatch** shuffle phase；post phase 允许被状态机推进到 `NONE`。
- 终结 reveal 使用 **pre-dispatch** reveal phase；post phase 可推进到 `NONE`。
- 完成下注轮的最后一个 `check` 显式约束 VM replay 导出的 round/pot，并用 sentinel 表达
  `current_turn: None`（进入 reveal phase）。
- terminal `call` / `raise` / `bet` 同样支持 clean round completion：按 native replay
  重建动作后的 `seat.bet`，约束 live bet 总和收池、pot 加法、下注清零和下一 reveal phase。
- 最后一个 showdown reveal 同时执行结算和 `reset_for_next_hand`，因此版本从 pre-state
  递增两次；仅该 canonical terminal transition 被允许使用 version increment 2。
- showdown 结算先生成并原子应用规范化 `SettlementPlan`。verifier 从 canonical replay
  事件提取完整 plan digest、1/2 runout、gross/rake/total awards 和固定 9 座位 award；
  submit-reveal AIR 绑定这些字段并约束 `total_awards + rake = gross_pot`。非终局 reveal
  携带 settlement 投影、缺少 plan event、重复 plan event 或 award 汇总不一致都会拒绝。
- Run It Twice 的 native 状态机会在无后续 contested betting 且 board 未完成时触发，后续
  assignment 显式路由到两个 board；reconstruct 保留已公开双 board 并从新 deck index
  继续。终局 RIT canonical replay + Orchestrator prove/verify 已有集成测试。
- last-opponent `fold` / `fold_with_proof` 会先收集 live bets，再证明 gross pot、rake、winner
  award 与 winner stack 的三条资金等式并 reset 到 `WAITING`；pending addon credit、leave
  refund 和 seat removal 由独立 Settlement/Reset component proof 绑定。
- active heads-up `kick_player`（无论是否踢当前行动者）已消除 native 双 reset/version bump
  或 bare reset 丢失底池的分支，并规范化为一次
  `BetCollection -> WithoutShowdown -> reset`：method AIR 绑定 `reset_cascade`、最终 WAITING/零
  pot 和双 version bump，四段 proof 再绑定被踢下注、其余 live bets、winner award、refund 与
  完整 reset。WAITING nested kick 继续使用 `ResetOnly`；其他未知 multi-version kick fail-closed。
- runner 按每个 reveal phase 的 assignment（局部索引）读取加密牌索引，并在 showdown 对
  保存的 partial ciphertext 构造 DLEq token proof。

## 证明时间

composite dispatch 的 method proof 与四段 bundle 已并行生成；四个 component proof/verify、
method archive 与 component archive 的验证也并行执行。参考开发机上，单个 composite check
约由 22.97s 降至 7.2s，完整牌局约由 425.03s 降至 213.46s。设置
`TEXAS_PROVE_TIMING=1` 后，`--full-hand` 会额外打印 method/SeatUpdate/BetCollection/
RoundAdvance/Settlement 的 prove/verify 明细；默认不启用计时。

## 仍需解决的安全与产品边界

- `kick_player` / `force_fold` 已把 canonical table-creator authorization request/receipt
  digest 放入 AIR；consensus anchor 会显式验证 included transaction signature，并从签名
  pubkey 重建 caller。AIR 不模拟 ECDSA/Ed25519，因此未锚定的单 proof 不能单独证明交易授权。
- production trace-visible u64 金额已统一为 verifier-reconstructed 4×16-bit limbs；资金运算
  使用完整 carry/borrow。此次补齐了 check 高 limb、kick refund checked-add、start-hand ante
  与 pot checked-add，以及 auto/force-fold、addon/rebuy、reconstruct、create/join/leave/reset、
  join-and-shuffle/submit-shuffle/leave-with-proof 的真实 pot 投影；不改变 pot 的路径使用完整
  4-limb equality，create/reset 的 canonical post pot 必须为零。
- terminal auto-fold/force-fold settlement、tick 间接触发的复合状态变更仍 fail-closed 或依赖
  canonical native replay，尚未全部拆成独立 component proof。
- `reset_for_next_hand`、`join_and_shuffle`、`leave_with_proof` 的完整座位与资金约束位于 durable
  四段 component bundle；裸 method STARK 只绑定方法级投影和 canonical pot，不能脱离 bundle
  当作完整结算证明。
- `request_leave_after_hand` 已有可签发 receipt 的独立 toggle AIR；`fold_with_proof`
  的 mid-round 与 clean last-opponent settlement 路径均绑定 native DLEq receipt、前后牌组
  commitment 与 canonical fold outcome。terminal reset 同时处理 pending addon/leave 时，
  完整生产 archive 必须携带四段 component proof bundle。
- stage-3 dual-proof package 已覆盖全部六条 crypto route：`fold_with_proof`、
  `join_and_shuffle`、
  `submit_shuffle_v2`、`leave_with_proof`、`submit_player_reveal_tokens` 与
  `submit_reconstruct_deck`。每条 route 都先对 canonical request 执行一次 host-native
  BLS12-381 verifier，再签发字段私有、无反序列化入口的 binding；AIR verifier 只重算
  canonical bytes、ABI/backend、request/receipt digest 与 table/hand/call/state scope，
  不重复同一昂贵密码学验证。这不是 BLS12-381 verifier AIR，也不是递归 proof。
- GameTurn / CheckpointAnchor 的 gas-free 仅表示不扣 caller fee、不推进 account nonce；
  成功或失败的 native crypto 调用仍按确定性 `gas_cost` 计入 block resource gas，超过
  block limit 的后续调用会在执行昂贵 verifier 前被 admission 拒绝。
- 聚合器仅维护 descriptor 链，不验证 child proof；递归聚合生产入口保持 fail-closed。
- 本地 receipt 链不等同于区块包含或共识锚定；调用方仍需提供经认证的任务来源与链端锚点。
- `TexasPokerTable` 当前 Borsh schema version 为 v2；旧 v1 table 需要在部署升级边界显式
  迁移或重建，不能直接按 v2 解码继续运行。
