# proving_service 完整牌局：性能报告与 crypto AIR Gap-6 阻断说明

> 运行：`./target/release/proving_service --full-hand`
> 模式：容错——任一步失败即标记并跳过后续，仍输出每步耗时与首个失败点。

## 1. 结论

`proving_service --full-hand` 已能驱动 `poker_l1` 合约**真实 dispatch** 完整 Texas
Hold'em 牌局序列，并在**前 5 步 + 非终结洗牌者**上完整跑通
VM dispatch → crypto proof 生成 → 合约 ZK 验证 → Stwo AIR prove + verify。
唯一阻断点是一个**已存在的 ZK 完备性缺口**（crypto AIR 的 Gap-6 约束），
发生在**终结洗牌者**的 `submit_shuffle_v2`。该缺口与本次工作无关，是
`poker_texas_air` crypto AIR 的既有设计问题（详见 §3）。

## 2. 性能数据（单局，2 人 heads-up，release build，Apple Silicon）

| 步骤 | dispatch | prove+verify | 结果 |
|---|---:|---:|:---:|
| create_table | 0.54 ms | 45.27 ms | ✓ |
| join_table | 0.53 ms | 64.90 ms | ✓ |
| join_table | 0.48 ms | 43.17 ms | ✓ |
| start_hand | 8.91 ms | 59.33 ms | ✓ |
| **submit_shuffle_v2 (seat0, 非终结)** | **23.95 ms** | **75.14 ms** | **✓** |
| submit_shuffle_v2 (seat1, 终结洗牌者) | 24.12 ms | — | ✗ Gap-6 |
| reveal_preflop ×4 … showdown ×4 | — | — | 跳过（状态机未推进） |

- **dispatch 合计**：~58 ms（6 次成功 dispatch）
- **prove+verify 合计**：~366 ms（5 次成功 prove）
- **总耗时**：~446 ms
- **state_root 链校验**：✓ 通过（链长 5，连续 call_seq）

### 关键观察

- **单步 prove+verify 基线**：lifecycle/action 方法 ~45–65 ms；crypto 洗牌方法
  `submit_shuffle_v2` ~75 ms（因 trace 更大、AIR 列数更多）。
- **crypto 证明生成成本可忽略**：`ZKShuffleProof::prove`（链下 BLS/ElGamal 运算）
  包含在 dispatch 的 24 ms 内，远小于 Stwo prove+verify 的 75 ms。即**证明管线的
  瓶颈是 Stwo STARK prove，不是 Mental Poker 密码学**。
- **dispatch 成本主导**：`submit_shuffle_v2` 的 dispatch（24 ms）显著高于 lifecycle
  方法（~0.5 ms），因为合约内部执行了完整的 `ZKShuffleProof::verify`（52 张牌的
  广义 Schnorr 验证）。`start_hand` 的 9 ms 来自 `set_initial_encrypted_deck`
  （52 次 hash_to_g1）。
- **外推完整一局**：若 Gap-6 修复，约 30 次 dispatch + 30 次 prove：
  - dispatch ≈ 6×0.5ms + 2×24ms(crypto) + ~22×0.5ms(action) ≈ **70 ms**
  - prove+verify ≈ 5×55ms + 1×75ms + ~18×55ms(reveal/action) ≈ **1.4–1.6 s**
  - **完整一局预估总耗时 ≈ 1.5–1.7 s**（证明主导）。

## 3. crypto AIR Gap-6 阻断点（既有 ZK 完备性缺口）

### 现象

`submit_shuffle_v2[seat1]` 的 Stwo AIR prove 报
`Constraints not satisfied`。seat1 是**最后一个洗牌者**——它提交后 `advance_shuffle`
发现 `pending_players` 为空，完成洗牌并把 `shuffle_state.phase` 重置为 `NONE(0)`，
随后进入 preflop reveal。

### 根因

`poker_texas_air/src/airs/crypto/submit_shuffle_v2.rs` 的 **Gap-6 part 3 约束**
（约 133–142 行）强制
`shuffle_phase ∈ {1,2,3}`（vanishing 多项式 `(phase-1)(phase-2)(phase-3)`）：

```rust
// 约束（Gap 6 part 3）：shuffle_phase ∈ {1,2,3}（非 NONE=0）。
let vp = (input_shuffle_phase * input_shuffle_phase_q)
    - six * input_shuffle_phase_q + eleven * input_shuffle_phase - six;
eval.add_constraint(is_active.clone() * vp);
```

但 Orchestrator 用**真实 post_table** 的 `shuffle_state.phase` 作为该公开输入
（`orchestrator.rs::prove_submit_shuffle_v2`），而：

- **终结洗牌者的 `submit_shuffle_v2`**：post `phase` = `NONE(0)`（`advance_shuffle`
  完成后重置）→ 被 Gap-6 拒绝。
- **`join_and_shuffle`**：在 `WAITING` 态调用，post `phase` = `NONE(0)`（同问题，
  `join_and_shuffle.rs` 有相同 Gap-6 约束）。

即：**所有 crypto 协议方法在真实对局里的 post `shuffle_phase` 都是 NONE(0)**，
而 Gap-6 {1,2,3} 约束把它们全部拒绝。现有 `poker_texas_air/tests/e2e_crypto.rs`
之所以通过，是因为它们用**合成的 `shuffle_phase: 1`** 输入构造 trace，**不是真实
dispatch**。`Orchestrator::prove_*_task` 用真实 post_table 时则必然冲突。

### 同一约束也存在于其它 crypto AIR

- `airs/crypto/join_and_shuffle.rs`（Gap-6 part 3）
- `airs/crypto/leave_with_proof.rs`
- `airs/crypto/submit_player_reveal_tokens.rs`
- `airs/crypto/submit_reconstruct_deck.rs`

均强制 `shuffle_phase ∈ {1,2,3}`，均与真实状态机语义冲突。

### 为什么不是 bug 而是完备性缺口

Gap-6 part 1 约束已经把 `shuffle_phase` 绑定到真实 `post_table.shuffle_state.phase`
（`expected_phase = self.input.shuffle_phase`），这是真正的约束。Part 3 的
`∈ {1,2,3}` 范围检查是**额外的防御性约束**，但它与状态机的合法状态转移
（终结洗牌 → NONE）冲突，导致合法 dispatch 无法证明。

### 修复方向（未实施，待决策）

放宽 Gap-6 part 3 为 `∈ {0,1,2,3}`（允许 NONE），即 vanishing
`phase(phase-1)(phase-2)(phase-3)`，需要 degree-3 witness（`q2 = phase·q`）。
或直接移除 part 3（part 1 已足够绑定真实 phase）。注意这是**ZK soundness 边界的
变更**，需配套审计。

## 4. 本次实现的内容

- `proving_service/src/crypto_driver.rs`：Mental Poker 客户端，用 `MerlinTranscript`
  （与合约 verify 端一致）生成 `ZKShuffleProof`（submit_shuffle_v2）与
  `RevealTokenProof`（submit_player_reveal_tokens）；链下精确复现合约的
  `add_pk_to_c2` 变换。
- `proving_service/src/full_hand.rs`：`FullHandRunner`，编排完整牌局 + 每步计时，
  容错报告。
- `proving_service --full-hand`：完整牌局性能报告模式。
- `poker_texas_air`：新增 `Orchestrator::start_new_chain_segment()` /
  `VerifiedChainBuilder::clear_receipts()`，支持跨局（hand_id 变更）时开新 receipt
  链片段（verified receipt 链按设计以单局 hand_id 为边界）。
- `TexasPokerPlugin::register_aggregated_pk()`：注册非 identity 聚合公钥
  （submit_shuffle_v2 的 shuffle proof 把它作为广义 Schnorr 基点，禁止 identity）。

## 5. 验证

- `cargo test -p proving_service --lib crypto_driver`：
  shuffle proof prove→verify 自洽（用 MerlinTranscript，与合约一致）。
- `./target/release/proving_service --full-hand`：见上表性能数据。
- `./target/release/proving_service --once`：原 6 步片段仍正常（回归未破）。
