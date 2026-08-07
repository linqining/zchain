# Texas 源状态瘦身、命令归一化与批量证明设计

## 目标

在实现 Tagged-union Stage proof 与 heterogeneous method batch 前，先让
`poker_l1::texas_poker` 的 canonical 状态满足三条原则：

1. 一个事实只保存一次；可从 canonical 状态确定性派生的缓存不进入 state root。
2. 互斥状态使用 enum/tagged union；正交开关才使用 bit flags。
3. 每个外部命令执行后都运行 `normalize_until_blocked`，一次性推进所有不依赖新签名、
   proof 或时间到期的内部步骤。

外部 selector 可以在迁移期保留兼容 wrapper；proof 的 method tag 应绑定归一化后的内部命令，
而不是永久复制 23 套业务实现。

## 已安全删除的字段

本轮还补齐了 schema v7 -> v8 的真实解码路径：旧 v7 的平铺 reveal assignment 使用独立
legacy mirror 解码，经过 `migrate_reveal_state_v7`/`migrate_hand_phase_v7` 后再进入 v8 的
`HandPhase`。因此 v7 bytes 不会被 v8 parser 误接受，也不会因为升级缺少 fallback 而被拒绝。

schema v3 已删除以下 derived/transient 数据：

- `TexasPokerTable.side_pots`：由 `Seat.total_bet` 和 seat eligibility 确定性重建。
- `Seat.refunded`：退款在同一原子 transition 内完成；迁移拒绝有未清 wager 的歧义状态。
- `DeckState.plaintext`：52 个 BLS12-381 明文点是协议常量。
- `Timestamps.ready_at`、`hand_complete_at`：生产状态机未读取。
- `RunItTwiceState.trigger_round`：由 `shared_board_len` 的 canonical 边界推导。
- `TableConfig.zk_skip_*`：测试跳过属于编译期属性，不应成为共识状态。

schema v4 进一步把 seat 生命周期压成 `SeatStatus`。schema v5 删除了 `SeatFlags`，把
`acted_this_round` 与 `want_leave` 提升为桌级 `u16` mask，同时把 current turn/current shuffler
改成 `NO_SEAT`，把 shuffle/reveal/reconstruct participant vectors 改成 seat masks。
v2/v3/v4 -> v5 迁移精确读取旧布局，并对不规范 plaintext、refund、RIT、重复/越界 participant、
unknown flag bits 和冲突 seat 生命周期组合 fail-closed。

## 已完成的 schema v6/v7 与命令归一化

schema v6 已完成以下 canonical 化，并提供 v5 -> v6 精确迁移：

- `Card` 已改为 `CardId(u8)`，持久化值只允许 `0..51`；
- hole cards 与两张 board 均使用固定容量、canonical padding；
- RIT 只保存共享前缀长度与 second-board suffix；
- 所有成功 selector 末尾统一执行有界、原子的 `normalize_until_blocked`；
- 23 个兼容 selector 已先解码为稳定的 `CanonicalCommand` tag；
- `tick`/`auto_fold` 的超时逻辑已汇入 `AdvanceDeadline`，`force_fold` 复用统一 fold transition；
- WAITING 状态没有隐式 deadline，`tick` 不再启动牌局；当前生产语义要求显式 `start_hand`。

schema v7 已把持久化/state-root/prove-task 编码收敛为唯一 `HandPhase` tagged union：每个 active
variant 只保存一个绝对 `deadline_ms`，reconstruct 额外保存 proof transcript 所需的 `epoch_ms`。
五个生产 timeout 已缩窄为 checked `u32`；从未被生产状态机读取的 `ready_wait_ms` 与
`hand_complete_wait_ms` 不再持久化。v2-v6 exact migration 会立即 canonicalize timeout，并对
deadline 小于 timeout、reconstruct epoch 溢出、timeout 超过 `u32` 等输入 fail-closed。

运行时 `TexasPokerTable` 暂时仍保留 v6 flattened phase 字段作为迁移期兼容缓存，但自定义 Borsh
codec 保证这些缓存不会进入共识编码。后续物理删除缓存字段不再需要升级 persisted schema。

运行时物理删除的第一批边界现已落地：AIR、composition、orchestrator、precompile binding、
proving service 以及状态机的 phase 判定改为通过 typed accessor 读取；跨 phase 的生产写入开始统一
经过 `enter_waiting/enter_shuffling/enter_revealing/enter_reconstructing/enter_betting/
enter_showdown_display`。这些 helper 会原子清除互斥 payload 和旧 timer，避免迁移期缓存产生
reveal + betting 或 reconstruct + shuffle 的短暂重叠。剩余工作是把同 variant 内的 mask、assignment、
turn 与 deadline 原地更新改成 variant-aware mutable API。

同 variant 更新现也已通过 `active_*_mut`、`set_betting_turn`、`remove_seat_from_active_phase` 和
phase-specific deadline API 收口；deadline arm/extend 使用 checked `u64` 并在写状态前预检溢出。
踢出当前 shuffler 时先记录 actor 身份、再清 participant bit，避免从更新后的 pending mask 反推旧 actor
而漏掉推进。下一批可以直接替换 runtime 字段为 `hand_phase: HandPhase`，不再需要改状态机调用边界。

schema v9 已完成 reveal ledger 的 fail-closed 类型迁移。v2-v8 的旧
`ciphertext: Option<_> + plaintext: Option<_>` 使用精确 legacy mirror 解码：`Some/None` 迁移为
`Partial`，`None/Some` 迁移为 `Plaintext`，旧 `None/None` tombstone 被清除，`Some/Some` 非法组合
直接拒绝。新 v9 bytes 也有回归测试保证不会被旧 v8 parser 接受。因此运行时 enum 压缩现在已进入
真实共识 schema，而不只是源码层类型替换。

schema v10 已完成 deck contributor lineage 的 canonical 化：持久化 deck 只保存
`contributor_mask`，`aggregated_pk` 不再进入 Borsh/state root，而是在 decode 后由 mask 中每个
occupied seat 的非 identity `seat.pk` 确定性重建。v2-v9 migration 最多枚举 9-seat 的 511 个非空
子集，只有 aggregate 恰好对应唯一 contributor 子集时才接受；无匹配、多解和 identity aggregate
全部 fail-closed。join/leave/fold-with-proof/kick/reset 均原子维护 mask，普通 fold、shuffle、reveal、
reconstruct 不改变 lineage。跨局 reset 会从所有仍占座且公钥有效的玩家重建新牌组 lineage，避免
`fold_with_proof` 玩家留座后永久丢失下一手密钥贡献。

schema v11 已物理删除运行时与持久化 `ShuffleState.current_shuffler`。当前洗牌者始终是
`first(pending_mask)`，因此不再需要写同步字段，也不再需要 normalize 为“选择 actor”单独产生一个
micro-step。v5-v10 的精确 legacy phase mirror 仍读取旧字段；迁移只接受它等于 pending mask 的最低
seat（空 mask 时必须为 `NO_SEAT`），随后丢弃，任何错配均 fail-closed。

WAITING 状态不再用隐藏的 `ShuffleState.completed_mask` 镜像长期 contributor lineage。
`DeckState.contributor_mask` 只描述 aggregate-key 成员并派生验证公钥；active shuffle variant 内的
completed mask 则只描述当前手牌新牌组的提交进度。由于 `start_hand` 会重新生成 canonical
plaintext-base deck，新一手的 completed mask 必须从零开始、pending mask 覆盖所有 active seat；
不能从长期 contributor mask 复制，否则会把尚未应用到新 deck 的加密层误判为已提交。
`leave_with_proof` 仍依据 contributor lineage 验证成员资格。

外部命令序号也已完成收口。所有真正改变状态的 dispatch 在原子提交边界统一写入
`post.version = pre.version + 1` 与 `post.call_seq = pre.call_seq + 1`；内部 normalize、reset、settlement
执行多少个 micro-stage 都不再改变该事实。no-op `tick` 不递增序号、也不产生 proof task。
Kick/reveal/tick 的复合分支改由 canonical replay events 与四阶段 composition plan 判定，禁止再用
`version + 2/+N` 猜测 settlement。这使 method batch 的每一行都能使用固定的命令序号约束，Stage
顺序只由 batch id/row index 表达。

## 下一步字段处理

### A. 保守方案：应优先完成

| 当前字段 | 建议表示 | 原因与约束 |
|---|---|---|
| ~~`Seat.folded/all_in/is_waiting/left_during_hand`~~ | 已完成：`SeatStatus: u8` | enum 已消灭 `folded && all_in` 等非法组合。|
| ~~`Seat.acted_this_round/want_leave`~~ | 已完成：桌级 `acted_mask/leave_after_hand_mask: u16` | 九个 seat 的正交 bool 分别只占一个 bit；空 seat 的 live bit 被拒绝。|
| ~~`current_turn: Option<u8>`~~ | 已完成：`u8` + `NO_SEAT = 0xff` | Borsh `Option<u8>` 使用 tag+value；固定哨兵更适合一列 AIR。|
| ~~`ShuffleState.current_shuffler`~~ | schema v11 已删除 | 始终由 `first(pending_mask)` 派生；旧 schema 字段仅用于迁移校验。|
| ~~`pending_players/completed_players: Vec<u8>`~~ | 已完成：`u16` seat mask | 最多 9 seat；mask 消除重复、顺序和变长编码。|
| ~~每个 reveal/reconstruct pending vector~~ | 已完成：`u16` seat mask | 提交即清 bit；越界 bit 在 state codec 和 canonical validation 拒绝。|
| ~~`Card { suit, rank }`~~ | 已完成：canonical `card_id: u8` (`0..51`) | suit/rank 由 canonical id 确定性派生。|
| ~~`Seat.hand: Vec<Card>`~~ | 已完成：`HoleCards { len, cards: [u8; 2] }` | 固定上界并拒绝非零 padding。|
| ~~`community_cards: Vec<Card>`~~ | 已完成：`BoardCards { len, cards: [u8; 5] }` | 固定上界并提供唯一编码。|
| ~~`second_board_cards`~~ | 已完成：仅保存非共享 suffix | shared prefix 只保存在 board 1。|

最大 9 人桌的两个正交 seat bool 已从 18 个独立字段降为两个 `u16` mask；更重要的是 AIR
不再为每个 seat 携带两个常驻 bool 列。mask 与固定数组还会消除 vector 顺序、重复和长度的
额外 canonicality 检查。

### A.1 当前源码的明确字段决策

| 分类 | 字段 | 决策 |
|---|---|---|
| 必须保留 | `stack/bet/total_bet/pot/chip_pool` | 保持 checked `u64`；这些是资产与 side-pot 的 canonical 输入，不能为了减列缩窄。|
| 必须保留 | seat `player/pk`、当前 encrypted deck | Mental Poker custody 与 proof request 的 canonical statement。|
| 已从 persisted state 删除 | `aggregated_pk` | schema v10 只持久化 `DeckState.contributor_mask`；runtime cache 必须等于 mask + seat pk 派生值。|
| 已收口，待删除重复字段 | `version` + `call_seq` | 两者现在每个外部命令都只增长一次；下一 schema 删除桌内 `version`，证明顺序只保留 `call_seq`。|
| 已删除 | `ShuffleState.current_shuffler` | schema v11 使用 `first(pending_mask)`；v5-v10 迁移校验后丢弃旧字段。|
| 可立即派生 | `RevealTokenData.seat_index` | token 按 seat slot 或 seat-index 升序存放后，提交者由 slot/bitmap 决定。|
| normalize 后可删 | `RevealAssignment.decrypted` | `pending_mask == 0` 时立即 materialize card 并移除 assignment，不持久化“已完成但未消费”状态。|
| normalize 后可删 | 已 materialize 的 `DecryptedCard` | 明文已经写入 hole/board 后不再重复保存在 deck ledger；只保留仍需继续部分解密的记录。|
| 可移出 hot state | `name` 与不变 rules | 拆成 `TableRules`，hot table 只保存 `rules_id/rules_hash`；事件/RPC 仍可展开。|
| 可移出 table | `rake_collected` | 改成原子 settlement output/treasury receipt，持久化 table 不做“写入后立刻清零”的中转。|
| 可派生 | `addon_pool` | 等于 `sum(seat.pending_addon)`；删除前必须先把所有 custody delta 统一为 checked plan。|
| 可派生 | `ante_collected` | 由 start-hand plan 的逐 seat debit 与 pot delta 决定，不应成为第二份下注事实。|
| ~~必须合并~~ | `round_state/betting Option/shuffle phase/reveal phase/reconstruct phase` | schema v7 persisted encoding 已改成唯一 `HandPhase`；运行时兼容缓存待逐调用点删除。|
| ~~必须合并~~ | 五个 timestamps | schema v7 每个 active `HandPhase` 只持久化一个绝对 deadline；runtime `Timestamps` 待删除。|

数值位宽建议：`rake_bps: u16`、timeout duration/time-bank 配额用 bounded `u32`、card id 用 6 bit、
seat index 用 4 bit、board position 用 3 bit、runout index 用 1 bit。Rust persisted schema 可以继续用
`u8/u16/u32` 保持清晰；AIR 中再做 range/bit decomposition。不要把 `u64` 资产字段降成较窄整数。

`Seat.time_bank_ms` 当前仍是 runtime/persisted `u64`，但默认、补充和消费语义都远小于 `u32::MAX`；
应在下一 schema 中改成 checked `u32`。绝对 `deadline_ms` 仍保留 `u64`，因为它表示共识时间点而不是时长。

`SeatStatus` 应保留为互斥 enum，而不是退回多个 bool。若后续还需压列，可以把九个 3-bit status
打包到一个 27-bit word，但这是偏激进方案：每次 seat update 都要做选择性 bit extraction，只有
Tagged-union Stage 已稳定且 status 列确认为热点后再做。

### A.2 补充源码审计：可删除、可派生与不应过度打包的字段

| 当前字段 | 建议 | 说明 |
|---|---|---|
| `TimeoutConfig.ready_wait_ms/hand_complete_wait_ms` | schema v7 直接删除 | 当前生产状态机没有读取；显式 `start_hand` 和 normalize 后的原子 reset 已取代这两个计时器。|
| `TexasPokerTable.id` | 中期移出 table payload | ObjectDb key、dispatch context 和 AIR 公共输入已经绑定 table id；前提是对象存储层保证 key/payload 不可错配。事件从执行上下文取 id。|
| `state_schema_version` | 中期移到 codec envelope | schema 版本属于编码层，不是扑克业务状态；state-root domain 仍必须包含版本，迁移入口继续 fail-closed。|
| `max_players` | 与 `seats` 表示二选一 | 若继续使用长度永久不变的 `Vec<Seat>`，容量可由 `seats.len()` 派生；若改固定 `[Seat; 9]`，则必须保留独立 `seat_capacity`。不要同时保存两份容量事实。|
| `ShuffleState.current_shuffler` | schema v11 已删除 | 当前洗牌者是 `first(pending_mask)`，不再产生仅用于同步缓存的 normalize step。|
| `ShuffleState.completed_mask` | 仅表示当前手牌 freshly initialized deck 的本轮已提交者 | 它不能与 `DeckState.contributor_mask` 合并：后者是长期 aggregate-key 成员，前者在每次 `start_hand` 重建 deck 后必须从零开始。|
| `DeckState.aggregated_pk` | schema v10 已由持久化 `contributor_mask + seat.pk` 派生 | host-native verifier 最多做 9 次 G1 加法；join 置 bit，leave/fold proof 清 bit，跨局 reset 为仍占座玩家重建 mask。|
| `DeckState.cards_dealt` | 暂时保留 | reconstruct 会开启新的 deck epoch，旧 hole/board 仍存在，不能只用已公开牌数量推导新 deck 游标。引入显式 deck epoch 和 lineage 后才可重新评估。|
| `RevealAssignment.encrypted_card_index/runout_index/board_position` | 合并成 `RevealTarget` tagged payload + deck index | `Hole { seat, slot }` 与 `Board { runout_bit, position }` 消灭 `board_position=0xff` 等哨兵组合；deck index 仍是独立 lineage。|
| `RevealTokenData.seat_index` | 删除 | 保存 `submitted_mask` 和按 seat 升序排列的 token；提交者由 mask 中第 n 个 bit 唯一确定。若 required participant mask 可由 deck lineage 和 target 推导，则只需保存 pending/submitted 二者之一。|
| `RevealAssignment.decrypted` | 删除 | `pending_mask == 0` 后必须在同一 normalize 中验证、materialize 并移除 assignment，不能持久化完成但未消费的 bool。|
| `DeckState.decrypted_cards` 的 completed record | 删除 | plaintext 写入 hole/board 后立即移除；ledger 改成只允许 `PartialHole { target, deck_epoch, ciphertext }`，从类型上消灭 ciphertext/plaintext 两个 Option 的非法组合。|
| `RunItTwiceState.shared_board_len` | 改成 `RitStartStreet::{Preflop, Flop, Turn}` | 合法值只有 `0/3/4`；street tag 可确定性映射到共享前缀长度，避免接受 `1/2` 等无业务语义值。|

`bool -> bit` 只适合正交、经常一起扫描的开关，例如九个 seat 的 acted/leave flags。互斥状态必须用
enum/tagged union。不要为了 Borsh 少几个字节把 `SeatStatus`、phase tag、runout mode 和各种 rule mode
塞进同一个整数：AIR 每次使用仍要拆位和 range-check，可能减少状态字节却增加证明列。

规则字段应先类型化并移出 hot state，再考虑压位：`AnteMode` 需要 2 bit，`RakeMode`/RIT enabled
各需 1 bit，但把它们压成 `rules_flags` 只节省几个状态字节，不会像 `TableRules -> rules_hash` 那样
减少每个 transition 的 state-root preimage。故推荐在 rules object 内保留清晰 enum，AIR 只绑定 rules
hash；不要让每个 method row重复携带所有 rules 位。

`TexasPokerTable.version` 不是 `Object.version`：真实 CAS version 位于 ObjectDb/object envelope。
当前已把增长收口到 dispatch 原子提交点，Stage 内部顺序由 batch row index 表示；任何已提交命令
都严格满足 `post.version = pre.version + 1`，不再允许 `+2/+N`。下一 schema 可直接删除桌内
`version`，由 object version 提供并发控制，证明链只保留 `call_seq`。

### B. 中等方案：先建立 custody/phase invariant 再删除

| 当前字段 | 处理 | 前置条件 |
|---|---|---|
| `addon_pool` | 删除，派生为 `sum(seat.pending_addon)` | 所有资金入口/退款先统一走 checked custody delta；AIR 改为约束求和。|
| `ante_collected` | 删除，start-hand transition 的 ante 量由 seat `total_bet` delta 与 pot delta 派生 | start-hand plan 必须列出每 seat ante debit。|
| `rake_collected` | 移出 table，作为 `DispatchOutput/SettlementReceipt` | Treasury 输出继续由唯一 `RakeCollected` settlement receipt 产生，持久化前无需写入再清零。|
| `pot` | 暂时保留；最终可由 vault conservation 派生 | 每次读取都需对 9 seat 求和，可能减少状态但增加 AIR 列/约束，不一定划算。|
| `max_players` | 保留 `seat_capacity`，不要仅由 `seats.len()` 猜测 | 若改成固定 `[Seat; 9]`，仍需配置允许的 seat 范围。|
| `version` 与 `call_seq` | 收口后删除桌内 `version` | ObjectDb 已有独立 object version；桌内证明顺序由 `call_seq` 唯一表达。|

`addon_pool` 是 `chip_pool` 的子集，任何上界公式都不得把两者当成两份资产相加。

### C. 激进方案：收益最大，但需要协议状态重构

1. 把 `round_state + betting_round + current_turn + shuffle/reveal/reconstruct phase + timestamps`
   改成一个 `HandPhase` tagged union：

   ```text
   Waiting
   Shuffling { purpose, current_seat, pending_mask, completed_mask, deadline }
   Revealing { target, assignments, deadline }
   Reconstructing { pending_mask, coefficient, accumulator, deadline }
   Betting { street, current_bet, min_raise, current_seat, deadline }
   ShowdownDisplay { settle_at }
   ```

   `street`、RIT runout schedule 和恢复目标作为 variant payload；不再允许多个 phase 同时 active。

2. `Timestamps` 五个 u64 合并为当前 Stage 的一个 `deadline_ms`。当前任何时刻最多只有一个可执行
   deadline；time bank 直接延长 betting deadline。

3. 已完成：`ReconstructState.player_decks` 不再保存每位玩家的 52 张 contribution。验证一份
   proof 后立刻 fold 到 52-card accumulator，随后丢弃该玩家 contribution。最坏状态从
   `9 * 52 * ciphertext` 降为一个 52-card accumulator，通常可减少数十 KB。
   v5/v6 migration 会读取旧 deck 列表并 fail-closed 地折叠，重复 contributor、仍 pending
   contributor、越界 seat 或非 52-card 输入均拒绝。原 `OUTPUT_SUBMITTED_COUNT` AIR 列未参与
   任何约束，现已连同重复的 runtime count 字段删除。

4. `decrypted_cards` 只保留尚需用于 owner/showdown/reconstruct 的 partial ciphertext。
   已写入 `hand/board` 的 plaintext record 立即删除；assignment id 与目标位置提供 lineage。

5. 不可变配置（name、blinds、timeouts、ante/rake/RIT rules）拆到 `TableRules`，hot table 只绑定
   `rules_hash/rules_id`。这主要减少每个 transition 的 state-root preimage，而不是业务信息。

6. `ProveTask` 不再同时持有 `method_input + selector + raw_args` 三份等价命令事实。迁移后的 canonical
   command bytes 是唯一输入；`method_tag`、typed payload 和 dispatch digest 都从它派生。兼容 selector
   只在 L1 边界解码，不能继续进入 proof archive 形成三份可错配表示。

## 方法归一化

### 源码审计结论（Tagged Stage proof 前的冻结清单）

以下结论针对当前 `poker_l1/src/vm/contracts/texas_poker` 源码，而不是只针对 AIR trace：

| 处理 | 字段/方法 | 当前决定 |
|---|---|---|
| 立即采用 | `acted_this_round`、`want_leave`、各 pending/completed participant vectors | seat bit mask；互斥生命周期继续用 `SeatStatus` enum |
| 立即采用 | `Card { suit, rank }`、可变长 hole/board、重复 RIT prefix | `CardId(u8)` + 固定容量数组 + second-board suffix |
| 已在 v8-v10 codec 生效 | `round_state`/`betting_round`/crypto phase/timestamps/reveal ledger/contributor lineage | persisted state 只保留 `HandPhase`、互斥 reveal enum 与 contributor mask；aggregate/runtime flattened 字段仅为派生缓存 |
| 下一 schema | `Seat.time_bank_ms`、`rake_bps`、时长类 `u64` | 分别收窄到 checked `u32`/`u16`；绝对 deadline 仍为 `u64` |
| 已完成 | `ShuffleState.current_shuffler`、`DeckState.aggregated_pk` | schema v11 已删除 shuffler；schema v10 已删除 persisted aggregate，crypto statement 从 validated runtime-derived cache 读取 |
| 不应删除 | `stack/bet/total_bet/pot/chip_pool`、`deck.encrypted`、`hand/board`、`total_bet` side-pot 输入 | 这些是资产守恒、牌组 lineage 或结算唯一事实 |
| 可合并入口 | `check`/`call`/`raise`/`bet` | canonical `PlayerAction::{MatchBet,RaiseTo}`；旧 selector 只做参数转换和严格语义断言 |
| 可合并入口 | `auto_fold`/`force_fold`/手动 `fold` | canonical `Fold { cause }`；timeout、admin、player 授权在 wrapper 校验 |
| 可合并入口 | `addon`/`rebuy` | canonical `FundSeat { timing }`；金额仍必须 checked-u64 且绑定 coin receipt |
| 可合并入口 | `tick`/`auto_fold`/`reset_for_next_hand` | `AdvanceDeadline` 与 normalize 内部步骤；保留 ABI wrapper，不再保留独立业务 AIR |

`bool -> bit` 只用于正交 seat flags；`SeatStatus`、phase、RIT mode 等互斥值不能硬塞进同一个
flags word。这样能减少常驻列而不会把 AIR 的选择性拆位成本转移到每一行。

### 推荐内部命令

23 个 selector 可以归一化为以下内部命令族：

| 内部命令 | 兼容 selector |
|---|---|
| `CreateTable` | `create_table` |
| `SeatCommand::{Join, LeaveNow, LeaveAfterHand, Kick}` | `join_table`, `leave_table`, `request_leave_after_hand`, `kick_player` |
| `FundSeat::{NextHand, Immediate}` | `addon`, `rebuy` |
| `PlayerAction::{Fold, MatchBet, RaiseTo}` | `fold`, `check`, `call`, `raise`, `bet`, `force_fold`；`MatchBet` 根据需补金额为 0/非 0 自动成为 check/call |
| `CryptoCommand::{JoinShuffle, Shuffle, Reveal, Reconstruct, RemoveLayer}` | 六个 Mental Poker selector；`RemoveLayer { exit: Leave/Fold }` 复用同型 DLEq payload |
| `Lifecycle::{StartHand, AdvanceDeadline, EmergencyReset}` | `start_hand`, `tick`, `auto_fold`, `reset_for_next_hand` |

最终 proof 层不需要 23 个 `MethodKind`。建议保留 6 个顶层 command tag：
`Create`、`Seat`、`Funds`、`Action`、`Crypto`、`Lifecycle`；具体语义放在二级 tag。
旧 23 selector 可长期作为 RPC/ABI wrapper，但 wrapper 必须先产生同一 canonical command bytes，
因此不会继续制造 23 套 AIR、23 套 trace shape 或 23 个 batch 类型。

源码现已增加 `CanonicalCommandFamily + CanonicalBatchTag { family, subtag }`，并把兼容入口实际
折叠到上述六个 family：`check/call` 共用 `Action/MatchBet`，`raise/bet` 共用
`Action/RaiseTo`，`fold/force_fold` 共用 `Action/Fold`，`tick/auto_fold` 共用
`Lifecycle/AdvanceDeadline`。旧 23 个 `CanonicalCommand` discriminant 暂时只用于现有 Method AIR
兼容和 archive 解码，新的 method batch 不再把它当作最终 trace tag。

归一化不等于取消授权：`Fold` payload 仍携带 canonical `FoldCause::{Player, Timeout, Admin}`，
并分别校验 seat signature、deadline 或 creator authorization。

### 可以舍弃的方法

先冻结牌组生命周期。当前源码同时存在两套互相冲突的模型：

1. `join_and_shuffle` 在 WAITING 时把加入者的 layer 写入 deck；
2. `start_hand` 又调用 `set_initial_encrypted_deck` 重建 plaintext-base deck，并要求 active seat
   对新 deck 执行本手 shuffle。

第二步会丢弃第一步的牌组输出，所以不能再把 WAITING 的 contributor membership 当作“本手已
shuffle”。推荐明确采用 **fresh deck per hand**：

- canonical join 只做 seat/funding、非 identity key 与 key-ownership proof；不携带两副 52-card
  deck、remask proof 或 shuffle proof；
- `start_hand` 初始化 canonical deck，并令 `pending_mask = active contributor mask`、
  `completed_mask = 0`；
- 每个参与者仅通过本手 `SubmitShuffle` 应用一次 layer；
- WAITING 下没有需要保全的 live hand deck，因此普通 `LeaveNow` 直接删除 contributor membership，
  不再要求 `leave_with_proof`；
- 对局中的物理退出仍保留 `fold_with_proof/RemoveLayer`，因为这时移除 live deck layer 会影响后续
  reveal/reconstruct。

这样可从 canonical method 集合删除 `JoinAndShuffle` 与 WAITING-only `LeaveWithProof`，并删除对应的
大体积 deck/proof args。旧 selector 可在兼容期拒绝新建调用或转换为 `JoinWithKeyProof`；不能继续
验证一份随后被 `start_hand` 丢弃的 shuffle output。

- `bet`：内部完全等价于 `RaiseTo`；旧 selector 只做参数换算与“postflop、尚无下注”的附加校验。
- `check` 与 `call` 的独立内部实现：合并为 `MatchBet`。`current_bet == seat.bet` 时金额为 0，产生
  check；否则扣除 `min(current_bet - seat.bet, stack)`，产生 call/all-in call。ABI wrapper 可继续区分并
  在边界附加“必须为 check/call”的断言。
- `auto_fold`：由 `AdvanceDeadline` 在 betting deadline 到期且 time bank 为零时产生
  `FoldCause::Timeout`。
- `start_hand`：当前保留为显式 canonical command。WAITING 没有 permissionless deadline，避免任意
  caller 在玩家刚入座时隐式开局。若未来需要自动开局，应新增已签名/共识化的 table policy 与
  `ReadyToStart` deadline，而不是恢复 `tick` 的隐式启动职责。
- public `reset_for_next_hand`：正常 settlement/reset 是 normalize 的内部步骤；只保留显式的
  emergency/governance 路径。
- `force_fold` 的独立业务实现：保留兼容 selector 和管理员授权，但映射到统一 `Fold` transition。
- `addon/rebuy`、`fold/MatchBet/RaiseTo` 的重复 dispatch/state-machine 骨架：保留不同 action tag，
  共享一套 command validation 与 transition plan。
- `TickArgs.now_ms`：兼容期后删除；deadline 时间只能来自 authenticated `DispatchContext`。
- `request_leave_after_hand` 的 toggle 语义：改成显式 `SetLeaveAfterHand(bool)`，使重试/批处理幂等。

### 可以从 canonical command 舍弃的入参

兼容 selector 的 wire args 可以暂时不变，但进入 method batch 前应解码成更窄的 canonical command：

| 当前入参 | canonical 处理 | 理由 |
|---|---|---|
| `player`（join） | 从 authenticated `context.caller` 派生 | 避免 caller/player 两份可错配身份；旧 ABI 只校验相等。|
| 玩家命令的 `seat_index` | 从唯一 `caller -> occupied seat` 映射或 `current_turn/current_shuffler` 派生 | table 已禁止同一 player 重复入座；admin target seat 仍必须显式携带。|
| `KickPlayerArgs.reason` | 由 command path 产生 typed cause | admin kick 固定 `Admin`，deadline path 固定 `Timeout/ReconstructTimeout`，不允许 caller 伪造事件原因。|
| reveal `assignment_indices` | 默认要求一次提交 caller 当前全部 pending assignment，按 canonical assignment 顺序匹配 | 删除任意索引列表、重复/乱序检查并减少 reveal 调用数；若必须分片，仅保留连续 `start/count`。|
| `bet.amount` | wrapper 转成 `RaiseTo(total_bet)` | command 层只保留一种加注金额语义。|
| `TickArgs.now_ms` | 删除 | 使用认证的 block timestamp。|
| `selector + method_kind + typed input + raw_args` | 单一 `canonical_command_bytes` | tag、payload 与 digest 均从同一字节串派生；重型 crypto request 只保存一次。|

特别是当前 `ProveTask` 同时保存顶层 `raw_args`，部分 crypto `MethodInput` 内又保存一份
`raw_args`，还额外保存 selector/method kind。这不仅增大 archive，也制造多份可错配事实，应在
method batch 前优先消除。

### `tick` 为什么不能直接消失

只让 `auto_fold/force_fold` 推进到底仍不能处理：

- shuffle participant 超时；
- reveal token participant 超时；
- reconstruct participant 超时；
- showdown display deadline；
- 无调用者继续提交业务交易时的 permissionless liveness。

因此应删除的是 tick 的“万能状态修复/普通推进”职责，而不是 deadline 驱动能力本身。
`AdvanceDeadline` 每次只消费当前 Stage 的 canonical deadline，之后调用
`normalize_until_blocked` 连续推进到下一个真正需要外部输入的位置。

## `normalize_until_blocked`

每个成功命令末尾执行有上限的确定性循环：

1. 若只剩一个 eligible player：收集 live bets，生成 settlement plan，结算并 reset。
2. 若 betting 已完成：collect bets，advance street，触发 RIT/reveal/showdown。
3. 若 shuffle pending 为空或 current 未选择：选择下一 canonical shuffler/进入 reveal。
4. 若 reveal assignments 全完成：写入 hand/board，进入 betting/下一 reveal/settlement。
5. 若 reconstruct pending 为空：提交 accumulator 为新 deck，进入 shuffle。
6. 遇到需要玩家签名、crypto proof、未到 deadline 或显式 start-hand 时停止。

循环必须设置小的静态上限，并在超过上限时 fail-closed；不能保留当前 tick fallback 那种退款后
继续掩盖非法 phase 组合的行为。

## 对 Tagged-union Stage proof 与 method batch 的影响

- Stage proof 使用 `stage_tag + shared columns + variant payload columns`。inactive payload 必须为零，
  且 tag one-hot/range constrained。
- 一行可以表示 SeatUpdate、BetCollection、RoundAdvance、Settlement 中任一 Stage；不再为每个
  transition 固定启动四份 proof。
- method batch 使用 `method_tag` 装入异构 canonical command rows；tag 选择对应约束，公共列统一
  绑定 table/hand/call/root/version/context digest。
- crypto/admin receipt 作为可选 tagged payload；没有 receipt 的 row 必须把相关列全部约束为零。
- `normalize_until_blocked` 输出 bounded `TransitionPlan`，同一 method row 引用连续 Stage row 范围，
  从而允许一笔 action 覆盖 fold -> collect -> round advance -> settlement，而无需额外 tick row。

不要把现有 23 份 Method AIR 的列布局直接扩成一个“最大宽度”全局 union。当前资金、timeout、
reveal 方法包含大量 checked-u64、deadline、receipt 和 settlement witness；若直接取最大宽度，简单
`check/fold` 行也会支付最宽方法的所有列 commitment 成本。

推荐把 method batch row 收敛为较窄的授权/编排层：

```text
method_tag + subtag + table/hand/call_seq + pre_root/post_root
+ canonical_command_digest
+ actor/admin/crypto receipt tag and digest
+ stage_batch_id + stage_start_row + stage_row_count
+ transition_plan_digest
```

金额更新、bet collection、round advance、settlement 和 checked-u64 witness 全部只出现在对应的
tagged Stage rows。这样 heterogeneous method batch 的宽度由“命令与 Stage 绑定”决定，而不是由
旧 `rebuy/auto_fold/reveal` 中最宽的一份 AIR 决定。旧 selector 只负责在 L1 边界解码 canonical
command，不再决定 proof trace shape。

在删除桌内逻辑 `version` 后，method row 中的 `root/version` 应改成 `pre_root/post_root/call_seq`；真实
ObjectDb CAS version 属于区块执行/包含证明，而不是扑克业务 AIR 的重复状态字段。

连续 method batch 也不应为每个 task 保存完整 `pre_table + post_table` 两份快照。对同一 table/hand
的连续 batch，可编码为：

```text
initial_state + [canonical_command, authenticated_context, transition_plan]* + final_state
```

中间状态由前一 transition 的 post 唯一成为下一 transition 的 pre；archive 若需要随机访问，只保存
row index/root checkpoint，不再复制整张 table。这个优化对含 52 张密文的 deck state 比压几个 bool
更有价值。

### 当前实现状态

Stage batch v2 已实现单份 tagged-union STARK：active Stage 行按 task/stage canonical 顺序紧凑写入
1024 行 trace，四种 Stage 共用最大 variant 宽度并以 2-bit tag 区分，inactive/padding 行全零；
verifier 重放完整异构 method task 列表并重建 trace commitment。它已经把 batch 固定启动从四份
Stage proof 降为一份。单 task 的兼容 durable bundle 暂时仍保留四份独立 component proof；待
batch id/row index 持久化完成后再统一 archive，避免破坏现有恢复协议。

这里的 “heterogeneous method” 已在 composition batch 输入层成立：同一连续 batch 可混合
fold/check/call/raise/bet/tick/crypto reveal 等所有 `supports_composite_proof` 方法。尚未完成的是把
原始 method AIR 自身也合并为单份 tagged method proof；当前每个 method proof 仍即时生成，只有
它们派生出的 Stage suffix 被批量合并。

本轮源码也已把动作入口进一步收敛：`state_machine::PlayerAction` 是唯一普通下注实现，包含
`Fold { reason }`、`MatchBet`、`RaiseTo(u64)` 三个 tag；`check`/`call` 仍在 wrapper 中分别检查
“不欠注/确实欠注”，然后都进入 `MatchBet`。`bet` 只保留 postflop、无当前下注和金额大于零的
兼容检查，再转换为 `RaiseTo(seat.bet + amount)`。同理，`FundTiming::{NextHand, Immediate}`
统一了 `addon` 与 `rebuy` 的 checked-u64、chip-pool 和 seat 更新骨架，事件类型仍按旧 ABI 语义
分别输出。超时和管理员 fold 已经通过 `AdvanceDeadline`/`apply_fold_internal` 使用同一 fold
transition，不再有第三套自动 fold 业务逻辑。

因此当前可以冻结以下字段决策，作为 method batch 和 Stage 列设计的输入：

| 字段组 | 处理 | 约束 |
|---|---|---|
| `acted_this_round`、`want_leave` 以及所有 participant 列表 | `u16 SeatMask` | 只允许 `0..max_players` 的 bit；空座位 bit 必须为零。|
| `SeatStatus`、`HandPhase`、`RevealTarget`、`RevealProgress`、`RunoutMode` | 保持 enum/tagged union | 这些值互斥；硬塞进 flags 会把非法组合转移到 AIR 拆位。|
| `Card { suit, rank }`、可变长 hand/board、重复 RIT prefix | `CardId` + 固定容量数组 + suffix | 只接受 0..51 card id 和 canonical zero padding。|
| `side_pots`、`refunded`、`DeckState.plaintext`、ready/complete 的 transient reveal record | 删除或 normalize 后删除 | 删除前必须由同一 checked settlement/reveal plan 唯一重建，并 fail-closed 拒绝歧义旧状态。|
| `aggregated_pk`、`current_shuffler`、`ante_collected`、`addon_pool`、`rake_collected` | aggregate 与 shuffler 已删除；其余继续派生/移出 hot state | contributor mask 与 mask-derived actor 已落地；剩余资金字段仍需 custody delta 或 treasury receipt。|
| `stack`、`bet`、`total_bet`、`pot`、`chip_pool`、encrypted deck、seat player/pk | 必须保留 | 它们分别是资产守恒、side-pot eligibility、Mental Poker lineage 和身份授权的唯一事实。|
| duration/time-bank/rake parameters | bounded `u32`/`u16` | AIR 做 range/checked-u64；绝对 `deadline_ms` 继续 `u64`。|

`bool -> bit` 的适用边界是“正交且批量扫描”的 seat flags；不适用于互斥生命周期、phase 或规则
模式。对九个 seat，两个桌级 mask 只需 18 个活跃 bit；将九个 `SeatStatus` 再压成一个 27-bit
word 属于激进优化，只有 status extraction 已成为实测热点时才值得承担复杂度。证明列通常比
Borsh 字节更贵，所以优先删除重复事实和变长容器，再考虑 bit packing。

## 推荐实施顺序

1. 已完成 schema v3 字段删除、尺寸回归和 active RIT migration 测试。
2. 已完成 schema v4 `SeatStatus` 与 v2/v3 fail-closed migration。
3. 已完成 schema v5 桌级 seat masks、`NO_SEAT`、participant masks 与 v2/v3/v4 exact migration。
4. 已完成 schema v6：Card 改 canonical id/fixed hole-board/RIT suffix。
5. 已完成 `normalize_until_blocked`，旧 selector 在成功执行后统一 normalize，并对非法 phase 原子失败。
6. 已引入 `CanonicalCommand`；旧 selector 先映射为稳定 command tag 再 dispatch。
7. 已用 `AdvanceDeadline` 统一 reconstruct/shuffle/reveal/betting/showdown timeout；`tick` 和
   `auto_fold` 仅保留兼容 wrapper。public reset 的 governance 收口仍待后续完成。
8. 已完成 schema v7 persisted `HandPhase` tagged union、单 deadline 与 reconstruct streaming
   accumulator；schema v9 已完成 reveal ledger enum，schema v10 已完成 contributor lineage、
   aggregate cache 派生与 v2-v9 fail-closed migration。下一步物理删除 runtime flattened phase caches。
9. 已完成 throughput 路径的 Tagged-union Stage proof，并支持异构 composite method task 输入；
   下一步实现原始 method AIR batch 与 durable batch-id/row-index。
10. method batch 前按顺序完成：已完成 reveal ledger canonicalization、
    `DeckState.contributor_mask` 与 `aggregated_pk` 派生；继续完成 `bump_version` 收口并删除桌内 version；TableRules/metadata 分离；单一
    canonical command bytes 与连续 state stream。
