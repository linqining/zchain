# 牌桌设计稿 · D 组数据缺口 —— 链上 / 证明层移交文档

对应 `zchain-table-ui.html` 的 G2（证明面板）、T6（本手凭证第三段）、T4（已结算印章）、
G1（观战桌链上元数据）。A/B/C 组缺口（客户端渲染、派生计算、texas 服务端下发）
已于 2026-09-24 落地，见文末「前置：已落地数据」——本文只覆盖**需要链上 / RPC /
gateway 配合**的部分，供单独开发。

仓库定位：

| 层 | 仓库 / 目录 | 角色 |
|---|---|---|
| 客户端 | `poker_texas_air/client` | 两套牌桌 UI |
| 游戏服务端 | `poker_texas_air/texas`（bin `texas`，端口 9001） | socket.io 牌桌、`/api/tables/*`、history、crypto_event 广播 |
| 链 / 证明层 | `/Users/mac/projects/zchain`（`poker_l1`、`poker-appchain`、`poker-contracts`、`poker-settlement-core`、`fact-bridge`、`proving_service`） | 共识状态、洗牌证明验证、结算、explorer_gateway |
| 观战服务端 | **未定位**：client 调 `GET /api/games/:id` + `WS /api/games/:id/ws`（`client/src/api/secretPokerClient.ts:213`、`api/wsClient.ts:49`），texas 无此路由 | G1/G2 数据源（见附录 C10） |

---

## D1 · 洗牌证明通道（最大项，G2 主屏 / T6 承诺值）

### 设计稿要求

G2 四栏：① 承诺层（sum_c1_commit / sum_c2_commit / aggregate_pk / deck_size）
② 证明层（combined_schnorr_proof / sum_c1_schnorr_proof / sum_c2_schnorr_proof /
global_challenge）③ 防重放（本手 nonce、重加密轮次 6/6）④ 链上验证。
T6 第三段：承诺值 4 行 + 逐层 shuffle/remask 事件 + tx hash。

### 现状：同一份证明存在三套互不一致的字段名

| 处 | 位置 | 结构 |
|---|---|---|
| **texas 服务端（权威）** | `texas/src/pokergame/game_state.rs:745` | `enum ShuffleProofJson { BayerGrothV2{version, proof{c_permutation_hex, c_permuted_powers_hex, multi_exponentiation{…}, product{…}}}, LegacyV1{sum_c1_commit_hex, sum_c2_commit_hex, combined_schnorr_proof, sum_c1_schnorr_proof, sum_c2_schnorr_proof, nonce_hex} }`（serde untagged） |
| **客户端类型** | `client/src/api/secretPokerClient.ts:105` | `{zk_consistency, triple_dleq, product_arg, global_challenge_hex, nonce_hex}` —— 与服务端两边都对不上（历史遗留） |
| **UI 已写死的行名** | `client/src/components/crypto/ShuffleProofVisualizer.tsx:177-193` | `sum_c1_commit / sum_c2_commit / combined_schnorr_proof / sum_c1_schnorr_proof / sum_c2_schnorr_proof / nonce`（= V1 名，无 `_hex`），且 `proof={null}` 硬编码（`SecretPokerGameTable.tsx:328`） |

关键事实：

1. **证明验证后即弃**：`table/shuffle.rs:259` 把 `ShuffleProofJson::to_proof()` 解析→验证后
   不留存，`ShuffleState`（game_state.rs:94）无 proof 字段。要下发必须先**新增留存**
   （建议按 hand_id 存 `Vec<{seat, player_pk, proof, verified, tx_digest, ts}>`，容量按层裁剪）。
2. **生产走 V2，V1 fail-closed**：zchain 侧 `VersionedShuffleProof::BayerGrothV2`
   （poker-protocol，V1 被验证器无条件拒绝）。设计稿 G2 画的是 **V1 字段名**——
   这是设计稿自己声明的「沿用现桌字段名、落地以服务端为准」的取舍点，**必须先决策**：
   - 方案 a：G2 改画 V2 结构（c_permutation / multi_exponentiation / product + transcript challenge），设计稿需同步更新；
   - 方案 b：UI 保持 V1 布局，服务端下发时做 V2→展示字段的投影（诚实标注哪些是派生摘要）。
3. **global_challenge 在 V2 无独立字段**：由 Fiat-Shamir transcript 派生（label 前缀
   `bg12_*`，`poker-protocol-bg/src/proof.rs:135-144`）。若 G2 要展示，需在验证时顺手
   计算并留存 transcript challenge。
4. **nonce 同理**：V2 证明无 nonce；现成的防重放 nonce 在
   `RevealTokenProofJson.nonce_hex`（game_state.rs:798，M4 anti-replay）。
   G2「本手 nonce」卡建议换数据源：reveal nonce 或
   `zchain.texas.canonical-shuffle-chain.v1` 的 deck commitment
   （`poker-settlement-core/src/deck_chain.rs:59`）。
5. zchain 侧**没有任何 JSON 证明暴露口**：`proving_service` 是 loopback dev 工具，
   `DispatchResponse` 只回 `events_count`；证明只进 canonical AIR archive。所以通道只能建在 texas。

### 建议通道

```
GET /api/tables/:table_id/hands/:hand_seq/proof
→ {
  handSeq, tableId, handId,
  aggregatePk,            // 来自 shuffle_state.aggregate_pk（已随 ClientTable 下发）
  deckSize: 52,
  layers: [{
    seat, playerPk, playerName,
    proof: ShuffleProofJson,   // 服务端原样结构（untagged）
    verified, txDigest, ts
  }]
}
```

- texas 已有按桌的 history 路由模式（`main.rs:161-162`），加一条同级路由即可；
- `aggregate_pk` / `deck_size` 不需要新数据（前者已下发，后者常量 52）；
- 前端：删掉 `proof={null}` 硬编码，`ShuffleProofVisualizer` 的字段行按上面的方案 a/b 决策重写；
- 修掉 `secretPokerClient.ts:105` 那套孤儿类型（或迁移为服务端结构的 TS 镜像）。

### 验收

T6/G2 能按手查出每一层的证明本体 + 每层的 verified/tx；V1/V2 两种形状都能渲染
（老回放里可能仍有 V1）。

---

## D2 · 区块号 / Gas（G2「链上验证」卡）

现状：`zchain/poker-contracts/src/client.rs:117-188` 的 `invoke / wait_for_acceptance`
只返回 `transaction_hash`（轮询 `get_transaction_status`）；**全仓库没有
`get_transaction_receipt` 调用**，区块号与 gas 无来源。

方案：`ChainClient` 加 `transaction_receipt(hash)`（starknet RPC
`starknet_getTransactionReceipt`），取 `block_number` 与 `actual_fee`（换算 STRK）；
texas 在记录 crypto_event / 结算回执时一并落 `block_number` + `gas`，随证明通道或
事件下发。设计稿 G2 的「区块 #842,119 / Gas 0.0031 STRK」两行即闭环。

注意：链下验证场景（tx_digest=null，「待上链」）没有 receipt——这两行应只在
已上链时显示。

---

## D3 · 验证者 / 合约地址（G2「链上验证」卡）

现状：

- 合约地址已有、未下发：zchain `poker-contracts/src/config.rs:117-131`
  `DeployedAddresses{vault, settlement, dual, vault_anonymizer, payout_anonymizer,
  table_registry}`（env `STARKNET_*_ADDRESS`）；client 侧另有
  `client/src/starknet/config.ts:149`（`pokerVaultAddress` 等 env）。
- 「验证者 starknet verifier」目前只能是展示标签——真实验证发生在哪份合约
  （settlement / dual / fact-bridge `CairoFactRegistry`）按部署拓扑定。

方案：把 `DeployedAddresses` 里与本手相关的合约（按结算路径选 settlement 或 dual）
随 D1 的 proof 响应（或 settlement 元数据）下发；G2「合约 0x049c…d2f1 / 验证者」两行
即闭环。**不要**在客户端再造一份地址配置——以服务端下发为准，client env 只留 fallback。

---

## D4 · 结算凭证与台费金库（T4 印章 / T6 托管提示）

现状：zchain `poker-appchain/src/bin/explorer_gateway/api.rs` 已有完整接口：

- `GET /api/v1/settlements` 摘要：`{frame_index, ts_ms, table_id, hand_binding, pot,
  rake_base, rake_total, payouts[{owner_short, amount}], level}`
- `GET /api/v1/settlement/{binding}` 详情：`policy_commitment / payout_root /
  inputs[] / payouts[]（NoteSpec：owner, amount, asset_class, table_id, pot_index,
  runout_index）/ rake{total, treasury_out, operator_out} / plan{gross_pot, rake,
  total_awards, winner_mask, pots[{gross_amount, rake, net_amount, eligible_mask,
  contested, active_runouts}]} / hand_proof{…}`

对应设计稿：

| 设计稿元素 | 数据来源 |
|---|---|
| T4/T6「已上链结算」印章 | settlement 存在该 hand 的记录（`hand_settled(binding)` 也可链上查） |
| T6「台费进入链上金库合约，可核验入账地址」 | 详情 `rake.treasury_out: NoteSpec`（owner 即入账凭据）；金库地址见 D3 |
| T6 借贷平衡 Σ、毛派彩/净增 | 详情 `plan.{gross_pot, rake, total_awards}`（本地 nets 已下发，可互为校验） |
| 「在 starkscan 查看」 | gateway `GET /api/v1/proof/{binding_hex}`（192 B attestation）+ tx digest |

**核心待解问题：hand_binding ↔ (table_id, hand_id) 映射**。texas 侧
`starknet/hooks::on_hand_complete` → appchain settlement 产生 binding，客户端目前
拿不到 binding。方案二选一：

1. texas 在结算回执里把 `hand_binding` 落到 crypto_event / history 记录（推荐，改动小）；
2. 客户端直接查 gateway `/api/v1/settlements` 按 table_id 过滤（依赖 gateway 可达性与 CORS）。

---

## D5 · 徽章三态（G2 底部）

数据已齐：`CryptoEventPayload{verified, tx_digest}`（`texas/src/socket/broadcast.rs:375`）
即可表达三态——`tx_digest=null` = PENDING、`verified=true` = VERIFIED、
`verified=false` = FAILED。本轮已把「待上链」态补进 `CryptoEventStream`；
剩余工作是 G2 的三枚示例徽章 + FAILED 态的完整面板呈现（验证失败时应能展开原因）。
纯渲染，无新数据。

---

## 附录 · 未定位归属的小项

- **C10 观战人数（G1「观战 42 人」）**：`/api/games/:id/ws` 不在 texas——先定位该
  服务端在哪（可能已废弃或由独立 spectator 服务承载），再在连接注册表上计数下发。
- **C12「下注轮 2/4」**：zchain `HandPhase::Betting{street, round}` 有轮计数，texas
  未跟踪。信息价值低，建议随 C10 一并评估是否值得。

---

## 前置：本轮已落地、D 组可直接依赖的数据

| 数据 | 位置 | 说明 |
|---|---|---|
| `showdownHandRanks[{seat, rank}]` | `ClientTable` + `HandHistoryRecord` | 摊牌各家牌型（texas `evaluate_player_hands`） |
| `nets[[seat, net]]` | `HandHistoryRecord` | 每家净结果（期初 stack 快照法） |
| `actions[{seat, player, action, amount, street, ts, auto}]` | `HandHistoryRecord` | 逐动作流水 |
| `handStartedAt` / `handOverAt` | `HandHistoryRecord` | 用时 |
| `rakeBps` / `rakeCap` | `ClientTable` | 台费费率/上限（`rake_params()` 与链上 env 同源） |
| `bettingStartedAt` / `bettingTimeoutMs` / `handCompleteAt` / `handCompleteWaitMs` | `ClientTable` | 回合计时与下一手倒计时 |
| `totalBet`（每座位） / `sidePots[].players` | `ClientSeat` / `SidePot` | 本手累计投入 / 边池资格 |
| `minBuyIn` / `maxBuyIn` 真值 | `ClientTable` | 原 client 硬编码 5000 已废除 |

T6 凭证的第一段（流水）、第二段（结算）已可由上述数据渲染；**第三段（证明）与
「已上链结算」印章即 D1–D4 的全部范围**。

## 建议实施顺序

1. **决策 D1 的字段口径**（方案 a 改画 V2 / 方案 b 服务端投影）——这是 G2 一切工作的前置；
2. D2 + D3（receipt 查询 + 合约地址下发，两者同属 `poker-contracts` 一轮改完）；
3. D1（证明留存 + REST 通道 + 前端 Visualizer 重写）；
4. D4（hand_binding 映射 + gateway 接入）；
5. D5 / C10 / C12 收尾。

---

## 落地记录（2026-09-24，D 组实现）

**决策**：D1 走**方案 b**（UI 保持 V1 布局，服务端下发 V2→展示字段投影，
`derived: true` 诚实标注派生摘要；证明本体 V1/V2 原样随层下发，前端两形状
都能渲染）；D4 走**方案 1**（texas 落 hand_binding）。

### 服务端（texas，`poker_texas_air`）

- **D1 证明留存**：新增 `texas/src/pokergame/proof_ledger.rs`——
  `Table.proof_ledger`（有界 FIFO，20 手/桌）按 hand_id 留存每层
  `{round, seat, playerPk, playerName, proofVersion, proof, display,
  globalChallenge, verified, txDigest, ts}`。接线点：
  - `submit_verified_shuffle`（开局/reconstruct 洗牌，`table/shuffle.rs`）；
  - `join_player_and_shuffle`（Waiting 阶段 join 洗牌 → pending 桶，
    开局创建本手条目时收编为首层）；
  - `global_challenge`：V2 验证成功后从生产域 transcript squeeze
    （label `bg12_global_challenge`）——完整 transcript 状态的确定性摘要，
    非协议独立字段；
  - `display`：方案 b 投影——V2 的 sumC1/sumC2Commit = Σ 输出牌组 c1/c2
    派生摘要（`derived: true`），Schnorr 行置 null；V1 直取证明字段。
- **D1 REST 通道**：`GET /api/tables/:table_id/hands/:hand_seq/proof`
  （`handlers.rs` + `main.rs` 路由）。`hand_seq=0` = 当前进行中的手；
  `?handId=N` 直查。响应 `{tableId, handSeq, handId, aggregatePk,
  deckSize, layers[], settlement, chain}`。`HandHistoryRecord` 新增
  `handId` 字段（seq↔hand_id 映射锚点；0 = 升级前记录 → 404）。
- **D4 结算回执注册表**：新增 `texas/src/starknet/settle_receipt.rs`——
  `HandSettleReceipt{status(settled/refused/failed), exit(appchain/dual/
  legacy), handBinding, txDigests, blockNumber, gasFee, contract,
  verifier, settleOpIndex, batchRoot, proven, reason, tsMs}`，进程内
  有界注册表（200 条/桌）。接线：appchain 成功 / dual 成功（binding =
  `compute_hand_binding` 注册值）/ legacy 成功（aggregate digest 锚）/
  `refuse_settlement`（refused + 原因）/ 构建失败与重试上限放弃
  （failed）。`settlement_result` WS 事件实时广播（`actions::
  SETTLEMENT_RESULT`）。
- **D2 block/gas**：starknet 出口成功后 `attach_tx_meta` 异步拉
  `starknet_getTransactionReceipt` 回填 blockNumber + gasFee
  （FRI/STRK 18 位小数十进制串，多笔合计；失败仅告警不阻塞结算）。
- **D3 链上元数据**：`ChainMeta::from_config()`（exit / contract（dual
  优先回退 settlement）/ vault / verifier 标签 / gateway 基址）随证明
  通道下发；新增 env `STARKNET_GATEWAY_URL`（explorer gateway 基址，
  空则不下发）。客户端以服务端下发为准。

### 链侧（zchain，`poker-contracts`）

- **D2**：`ChainClient::transaction_receipt(hash)` → `TxReceiptSummary
  {block_number, actual_fee, fee_unit, execution_succeeded}` +
  `format_fee`（STRK 十进制展示）。`cargo test -p poker-contracts` 35 过。

### 客户端（`poker_texas_air/client`）

- `secretPokerClient.ts`：孤儿类型（zk_consistency/triple_dleq）已替换为
  服务端结构的 TS 镜像（untagged V1/V2 + `isV2Proof` 判别）；新增
  `getHandProof(tableId, handSeq, handId?)` 与响应类型。
- `ShuffleProofVisualizer.tsx`：按层渲染——承诺层（V1 行名 + 派生标注 +
  aggregate_pk/deck_size）、证明层（V1 = 3 Schnorr 行 / V2 = Bayer-Groth
  原生行）、防重放（V1 nonce / V2 global challenge + 轮次 i/N）、链上验证
  （block/gas/合约/binding，仅已上链时）；FAILED 态展开验证失败原因（D5）。
- `SecretPokerGameTable.tsx`：删除 `proof={null}` 硬编码，改为证明通道
  拉取当前手（seq=0）回退最新终局记录。
- 主牌桌（GameUI 线）：`GameState` 监听 `settlement_result` →
  `settlementReceipts`（GameContext）+ 系统消息；`CryptoPanel` 顶部 T4
  印章（settled/refused/failed 三态 + block/gas/原因）；
  `HandHistoryPanel` 展开时按手拉证明通道——T4 印章 + T6 第三段
  （逐层 proof 事件行 + tx + gateway attestation 链接）。

### 验证

- texas：`cargo test -p texas` 217 过（含 2 个新增 D1 全流程测试：
  `verified_shuffle_retains_proof_layers`、`join_shuffle_layer_pending_
  then_adopted`——真实 V2 证明经服务端验证路径后留存断言）。
- client：`tsc --noEmit` 0 错误、`vite build` 通过。
- zchain：`cargo test -p poker-contracts` 35 过。

### 未落地（按文档归属延后）

- C10 观战人数 / C12 下注轮计数：观战服务端仍未定位（非链侧）。
- D5 的 G2 三枚"示例徽章"纯装饰元素（三态数据与 FAILED 面板已具备）。
