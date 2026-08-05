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
- 最后一个 showdown reveal 同时执行结算和 `reset_for_next_hand`，因此版本从 pre-state
  递增两次；仅该 canonical terminal transition 被允许使用 version increment 2。
- runner 按每个 reveal phase 的 assignment（局部索引）读取加密牌索引，并在 showdown 对
  保存的 partial ciphertext 构造 DLEq token proof。

## 仍需解决的安全与产品边界

- 管理签名、超时和完整 range checks 尚未全部放入 AIR；当前生产 receipt 依赖
  Orchestrator 的 canonical VM replay 与绑定的 trace row。
- `request_leave_after_hand` 已有可签发 receipt 的独立 toggle AIR；`fold_with_proof`
  仍没有覆盖 DLEq layer removal 与可能的 settlement，入口保持 fail-closed。
- stage-3 dual-proof package 已覆盖全部五条 crypto route：`join_and_shuffle`、
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
