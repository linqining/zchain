# proving_service：打一局真实完整 Texas Hold'em 牌局 + 性能数据

## 目标
在 `proving_service` 中加载 `poker_texas_air`，驱动 `poker_l1` 合约**真实 dispatch 完整一手牌**（开局→洗牌→preflop/flop/turn/river 下注→摊牌结算→重置），每步产出 `ProveTask` 并由 Orchestrator **prove + verify**，最终给出每步/总体性能数据。

当前 `--once` 只跑 6 步 lifecycle/funds 片段（0.31s），**没有任何真实牌局动作**。本计划把它扩展到一局真实完整对局。

## 调研结论（已逐行验证）
1. **证明端完全可用**：Orchestrator 对 5 个 crypto 方法 + 全部 lifecycle/action 方法都有真实 prove+verify 路径（只有 `RequestLeaveAfterHand`/`FoldWithProof` fail-closed，本流程不涉及）。
2. **Transcript 陷阱（已解决）**：合约用 `MerlinTranscript`（STROBE），而 `z_poker` 的 `ClientPlayer` 辅助类硬编码 `FiatShamirTranscript`（面向 Move）—— 不能直接用。但 `CryptoTranscript` trait + `MerlinTranscript` 都是 public，所以**直接用 `MerlinTranscript::new(label)` 调底层 prove 函数**即可与合约 verify 对齐。
3. **入座策略（决定性）**：`start_hand` 会 `set_initial_encrypted_deck` **重置牌组**但保留 `completed_players`。用 `join_and_shuffle` 入座会进 `completed_players`→start_hand 后无人洗牌（错）；用 **`join_table` 入座**→start_hand 后 `pending=[0,1]`→两人 `submit_shuffle_v2` 正确洗牌。这还避开了最复杂的 remask+pk_ownership，只需 `submit_shuffle_v2` + `submit_player_reveal_tokens`。
4. **牌组变换必须链下复现**：`submit_shuffle_v2` 验 proof 用原始 output_cards，但存储的是 `add_pk_to_c2(output)`（每张 **c2 += player_pk**，c1 不变）。所有 card 的 `c1=G` 全程不变 → `reveal_token = c1·sk = G·sk = pk`。shuffle proof 绑定 identity（agg_pk=None→identity，prove 不拒绝）。
5. **完整流程（2 人 heads-up，无需 tick）**：create→join×2→start_hand→shuffle_v2×2→preflop reveal(4 token)→[call(SB)+check(BB)]→flop reveal(6 token)→check×2→turn reveal(2 token)→check×2→river reveal(2 token)→check×2→showdown reveal(4 token)→settle→reset。**约 30 次 dispatch + 30 次 prove+verify。**

## 文件改动
1. **新增 `proving_service/src/crypto_driver.rs`**：Mental Poker 客户端，跟踪每玩家 sk/pk，链下精确复现牌组变换（`add_pk_to_c2`），用 `MerlinTranscript` 生成每个 crypto proof。
2. **新增 `proving_service/src/full_hand.rs`**：`FullHandRunner`，编排完整牌局序列 + 性能计时；复用现有 `TexasPokerPlugin`（dispatch + prove_task + verify_chain）。
3. **改 `proving_service/Cargo.toml`**：加 `poker_protocol = { workspace = true }`、`rand = { workspace = true }`。
4. **改 `proving_service/src/lib.rs`**：导出两个新模块。
5. **改 `proving_service/src/main.rs`**：新增 `--full-hand` 模式（跑完整牌局 + 性能报告）；保留 `--once`/`serve` 不变。
6. **新增 `proving_service/tests/full_hand_complete.rs`**：集成测试，断言完整牌局全部 prove+verify 成功 + chain 衔接 + 性能数据存在。

## crypto_driver 核心逻辑
- `build_shuffle_v2(deck_view, agg_pk=identity, rng)`：随机置换 + re_encrypt 出 output_cards，`ShuffleProof::prove`（transcript=`zk_shuffle_proof_v1`）。dispatch 后 `deck_view` 同步 `c2 += player_pk`。
- `build_reveal_token(sk, pk, deck_view[card_index], rng)`：`token = c1·sk = pk`，`RevealTokenProof::prove`（transcript=`reveal_token_proof_v3`）。

## full_hand 编排
每步：`dispatch`（真实合约执行）→ 若有 `prove_task` 则 `prove_task`（Orchestrator prove+verify）→ 计时 → crypto 步骤同步 deck_view。最终打印：每步 method/dispatch 耗时/prove+verify 耗时/总耗时/dispatch 次数/prove 次数/chain 长度/全成功 + chain 校验。

## 验证
- `cargo build -p proving_service --release`
- `./target/release/proving_service --full-hand`（看完整牌局 + 性能数据，这是用户要的产物）
- `cargo test -p proving_service --test full_hand_complete`

## 风险与缓解
- transcript label 必须逐字匹配合约（已核对：`zk_shuffle_proof_v1`、`reveal_token_proof_v3`）
- deck_view 必须精确复现 `add_pk_to_c2`（已确认只改 c2 += pk）
- 首次跑可能较慢（~30 次 Stwo prove），性能数据正是用户想要的产物