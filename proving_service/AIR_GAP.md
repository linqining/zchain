# proving_service 完整牌局验证说明

运行：`cargo run -p proving_service -- --full-hand`

`FullHandRunner` 现在会完成一局双人 Texas Hold'em 的真实 VM dispatch：建桌、两人入座、
开局、两次 shuffle、preflop/flop/turn/river/showdown reveal，以及四轮下注。每个状态变更都
由 `poker_texas_air::Orchestrator` 重放 canonical VM dispatch、生成 Stwo proof 并进行 host
verify；reveal 采用每个 seat 一次覆盖其全部 pending assignment 的 canonical 批量提交，完整
流程产生 24 个连续 receipt。建桌与两次入座仍各自生成 legacy Method proof；从 `start_hand`
开始的 21 个同 hand transition（含两次 shuffle 与 18 个 composite transition）共享一份 tagged
method proof 与一份 tagged Stage proof，其中仅 16 个 active Stage row 进入 Stage trace。

## 已修复的终态转换

- 终结 shuffle 使用 **pre-dispatch** shuffle phase；post phase 允许被状态机推进到 `NONE`。
- 终结 reveal 使用 **pre-dispatch** reveal phase；post phase 可推进到 `NONE`。
- 完成下注轮的最后一个 `check` 显式约束 VM replay 导出的 round/pot，并用 sentinel 表达
  `current_turn: None`（进入 reveal phase）。
- terminal `call` / `raise` / `bet` 同样支持 clean round completion：按 native replay
  重建动作后的 `seat.bet`，约束 live bet 总和收池、pot 加法、下注清零和下一 reveal phase。
- 最后一个 showdown reveal 同时执行结算和内部 reset；外部事实始终只递增一次 `call_seq`，
  结算与 reset 的顺序由 tagged Stage rows 绑定。
- showdown 结算先生成并原子应用规范化 `SettlementPlan` v2。runout shape 由 typed
  `Single | Twice { RitStartStreet }` 唯一表达；verifier 从 canonical replay
  事件提取完整 plan digest、1/2 runout、gross/rake/total awards 和固定 9 座位 award；
  submit-reveal AIR 绑定这些字段并约束 `total_awards + rake = gross_pot`。非终局 reveal
  携带 settlement 投影、缺少 plan event、重复 plan event 或 award 汇总不一致都会拒绝。
- Run It Twice 的 native 状态机会在无后续 contested betting 且 board 未完成时触发，后续
  assignment 显式路由到两个 board；reconstruct 保留已公开双 board 并从新 deck index
  继续。终局 RIT canonical replay + Orchestrator prove/verify 已有集成测试。
- last-opponent `fold` / `fold_with_proof` 会先收集 live bets，再证明 gross pot、rake、winner
  award 与 winner stack 的三条资金等式并 reset 到 `WAITING`；pending addon credit、leave
  refund 和 seat removal 由独立 Settlement/Reset component proof 绑定。
- terminal timeout fold 由 `advance_deadline` 使用 `EndWithoutShowdown` projection 和四段
  component bundle；`force_fold` 绑定 canonical table-creator authorization request/receipt
  digest，归档重启后会同时重验 method 与四份 component proof。
- `tick` 已进入四段 durable archive：betting-timeout fold、收池/round advance、无摊牌、showdown
  与 reset-only 分支会激活对应 component，不能再只持久化 Tick method proof。
- active heads-up `kick_player`（无论是否踢当前行动者）已消除 native 双 reset/version bump
  或 bare reset 丢失底池的分支，并规范化为一次
  `BetCollection -> WithoutShowdown -> reset`：method AIR 绑定 `reset_cascade`、最终 WAITING/零
  pot 和双 version bump，四段 proof 再绑定被踢下注、其余 live bets、winner award、refund 与
  完整 reset。WAITING nested kick 继续使用 `ResetOnly`；其他未知 multi-version kick fail-closed。
- runner 按每个 reveal phase 的 assignment（局部索引）读取加密牌索引，并在 showdown 对
  保存的 partial ciphertext 构造 DLEq token proof。

## 证明时间

分项基准确认主要开销是每份 Stwo proof 的固定启动成本。优化路径先把每类 Stage 的连续 rows
装入四份 1024 行 proof，再收敛为一份 Tagged-union Stage proof，最后加入一份窄 tagged method
proof，删除 batch 内逐 task legacy Method prover。`TEXAS_PROVE_TIMING=1` 可打印 legacy setup、
tagged method 与 tagged Stage 的 prove/verify 明细；默认不启用计时。

当前 `--full-hand` 共 24 个 dispatch：create/join×2 保留 3 次 legacy Method proof；其余
`start_hand + shuffle×2 + 18 composite transition` 形成一个 21-row tagged method proof，并只把
16 个 active Stage row 写入同一 tagged Stage proof。非 composite method row 的
`stage_row_count = 0`，但仍由连续 state stream、method row、batch transcript 与逐 row receipt
绑定。2026-08-09 debug test profile 的端到端 prove/verify 回归耗时 26.55–26.92s；此前只批量化
18 个 composite rows、仍单独证明 start/shuffle 的版本约 36.30s。

durable service 已支持同 hand mixed HTTP jobs 的共享 tagged sidecar、重启恢复、P2P repair 与
validated-package cache：`start_hand` 开启 stream，后续 shuffle、资金/离场标记等 zero-Stage 方法
可与 composite rows 连续入队；下一次 `start_hand` 或 batch 满时先原子 finalize。create/join 等
未进入 hand stream 的孤立 setup job 仍走 single archive，因此不能声称所有 production legacy
Method route 已经退休。completed package 在重启恢复时也会从首 row 检测 hand 边界，并在 staged
Orchestrator 上切换 receipt segment；proof/stream 校验失败不会提前破坏已恢复链。

## 仍需解决的安全与产品边界

- `start_hand` / `kick_player` / `force_fold` 已把 canonical table-creator
  authorization request/receipt
  digest 放入 AIR；consensus anchor 会显式验证 included transaction signature，并从签名
  pubkey 重建 caller。AIR 不模拟 ECDSA/Ed25519，因此未锚定的单 proof 不能单独证明交易授权。
- production trace-visible u64 金额已统一为 verifier-reconstructed 4×16-bit limbs；资金运算
  使用完整 carry/borrow。此次补齐了 check 高 limb、kick refund checked-add、start-hand ante
  与 pot checked-add，以及 deadline/force-fold、addon/rebuy、reconstruct、create/join/leave、
  submit-shuffle/fold-with-proof 的真实 pot 投影；不改变 pot 的路径使用完整
  4-limb equality，create 的 canonical post pot 必须为零。
- `advance_deadline` 的 shuffle/reconstruct/reveal 修复分支仍依赖 canonical
  native replay 与完整 table/plan digest；当前四段 AIR 对这些 lifecycle 变化保持 inactive，不能
  解释成独立执行了 start-hand、deck rebuild 或 reconstruct 算法。若要消除恶意 host 信任，需新增
  lifecycle-specific component/verifier program。
- 内部 `reset_for_next_hand` 的完整座位与资金约束位于触发 settlement/normalize 的 durable 四段
  component bundle；独立 reset MethodKind/AIR 已删除。退休的 `join_and_shuffle` / `leave_with_proof`
  已从 source/task/AIR/package 全链路删除；加入、fresh-deck shuffle、WAITING 离场与 active layer
  removal 分别由 `join_table`、`submit_shuffle_v2`、`leave_table`、`fold_with_proof` 承担。
- `start_hand` 的零参数 dispatch 已 fail-closed 拒绝尾随 bytes；退休 reset selector 在解码前拒绝。
- showdown settlement projection 严格校验唯一 `HandSettled` marker、固定升序 winners 与
  award 聚合，以及 `RakeCollected` 的唯一性和 pot/rake 数值；不完整或错配的事件集合不会
  进入四段 component plan。
- `set_leave_after_hand` 已有可签发 receipt 的独立幂等 AIR；`fold_with_proof`
  的 mid-round 与 clean last-opponent settlement 路径均绑定 native DLEq receipt、前后牌组
  commitment 与 canonical fold outcome。terminal reset 同时处理 pending addon/leave 时，
  完整生产 archive 必须携带四段 component proof bundle。
- stage-3 dual-proof package 已覆盖全部四条 active crypto route：`fold_with_proof`、
  `submit_shuffle_v2`、`submit_player_reveal_tokens` 与 `submit_reconstruct_deck`。每条 route
  都先对 canonical request 执行一次 host-native
  BLS12-381 verifier，再签发字段私有、无反序列化入口的 binding；AIR verifier 只重算
  canonical bytes、ABI/backend、request/receipt digest 与 table/hand/call/state scope，
  不重复同一昂贵密码学验证。这不是 BLS12-381 verifier AIR，也不是递归 proof。
- reveal wire/canonical payload 不再携带 `assignment_indices`。service/full-hand producer 与 verifier
  都从 authenticated pre-table 派生该 seat 的全部 pending assignment；派生索引仍进入 native
  BLS12-381 request statement，所以缩短 payload 不会放松 ciphertext/proof lineage 绑定。
- GameTurn / CheckpointAnchor 的 gas-free 仅表示不扣 caller fee、不推进 account nonce；
  成功或失败的 native crypto 调用仍按确定性 `gas_cost` 计入 block resource gas，超过
  block limit 的后续调用会在执行昂贵 verifier 前被 admission 拒绝。
- 聚合器仅维护 descriptor 链，不验证 child proof；递归聚合生产入口保持 fail-closed。
- 本地 receipt 链不等同于区块包含或共识锚定；调用方仍需提供经认证的任务来源与链端锚点。
- `TexasPokerTable` 当前 Borsh schema version 为 v2；旧 v1 table 需要在部署升级边界显式
  迁移或重建，不能直接按 v2 解码继续运行。
