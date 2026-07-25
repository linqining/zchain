# 实施计划

## 总览

两个任务串行：先做任务1（核对电路 + 修低悬挂果实），再做任务2（新建独立 proving 服务，复用 `poker_l1::dispatch` 产生快照，跑通一整手牌）。

---

## 任务 1：核对 `poker_texas_air` 电路 vs `poker_l1` texas_poker 合约

### 1.1 产出核对报告（文档）

新建 `docs/circuit-contract-reconciliation.md`，逐方法对照 21 个 AIR 与合约 `state_machine.rs`/`dispatch.rs` 的差异。已探明的关键不一致点（写进报告）：

**数值/语义类（明确错误，需修）：**
- `airs/lifecycle/start_hand.rs:109,170`：硬编码 `post_round_state == 1 (ROUND_SHUFFLE)`。但合约里 `round_state` 在 start_hand 后**仍是 ROUND_WAITING=0**，只在 preflop reveal phase 完成时才转 ROUND_PREFLOP=2（state_machine.rs:1995, 921）。**合约无 ROUND_SHUFFLE=1 这个常量**（constants.rs 的 round_state 序列跳过 1）。这是电路凭空造出的状态值。
- `airs/crypto/*.rs`：5 个 crypto AIR 全部硬编码 `ROUND_SHUFFLE=1 / ROUND_REVEAL=2 / ROUND_RECONSTRUCT=3`（如 `join_and_shuffle.rs:183`、`submit_player_reveal_tokens.rs:149`、`submit_reconstruct_deck.rs:150`）。合约里这些阶段**用的是独立的 phase 字段**（`shuffle_state.phase` / `reveal_token_state.reveal_phase` / `reconstruct_state.phase`，见 constants.rs:39-58），`round_state` 在整个 crypto 流程中始终是 WAITING/PREFLOP。电路把 round_state 当成 phase 用，语义错配。
- `method_kind.rs` 文档说"18 个方法"，实际 21 个 variant（lib.rs/airs/mod.rs 也说 18/21 不一致）—— 文档订正。
- `airs/common.rs` 与各 AIR 的 round_state 魔数未从 `poker_l1::...::constants` 导入，重复定义易漂移。

**文档写了但代码漏约束（低悬挂果实，补约束）：**
- `create_table.rs:190`：注释承认 `max_players ∈ [2,9]` 范围检查 TODO 且"提议约束数学错误"。改用正确的位分解约束（或 host 端 range check 写进 public input）。
- `bet.rs`：合约要求 `round_state != ROUND_PREFLOP`（state_machine.rs:2939）、`current_bet <= seat.bet`，电路未约束。
- `check.rs`：合约要求 `seat.bet >= current_bet`（state_machine.rs:1826），电路未约束。
- `call.rs` / `raise.rs`：`stack -= delta`、`bet`/`total_bet += delta`、`all_in = (stack==0 && delta>0)` 算术不变量未约束（文档承认）。
- `kick_player.rs`：合约 `pot += seat.bet; seat.bet = 0`（state_machine.rs:2689）—— kick 与 fold 的资金流向不同，电路完全没体现。

### 1.2 修复低悬挂果实（改代码）

按"不改架构、不补阶段5高级约束（Poseidon state_root embedding / ECDSA / 真 Fr→M31 转换）"原则，做以下修改：

1. **修正 start_hand / 5 个 crypto AIR 的 round_state 常量**：从 `poker_l1::vm::contracts::texas_poker::constants` 导入真实常量；start_hand 的 post_round_state 改为 `ROUND_WAITING`（合约语义），crypto AIR 改为约束对应的 `*_state.phase` 字段（需把这些 phase 加进 AIR 的 public input / witness 列）。若加 phase 列改动过大，则至少把魔数注释清楚并在报告中标注为"已知待办"。
2. **`create_table.rs` 范围检查**：用正确的 4-bit 位分解约束 `max_players ∈ [2,9]`（或退而求其次，把 host range check 结果作为 public input 约束）。
3. **补 `bet`/`check`/`call`/`raise`/`kick_player` 的低悬挂约束**：bet 的 postflop 守卫、check 的 `seat.bet==current_bet`、call/raise 的 limb0 算术、kick 的 `pot` 增量。仅加 limb0 级约束（与现有 addon/rebuy 风格一致），不做完整多 limb 进位。
4. **订正文档数字**（18→21）。

**不做的**：state_root 的 Poseidon 嵌入、`starknet_field_to_m31_limbs` 真实现、SeatLeaf 7 字段补全、ECDSA 签名约束 —— 这些是阶段5，在报告中列为已知缺口。

---

## 任务 2：独立 proving 服务，加载合约跑通一整手牌

### 2.1 新建 crate `proving_service/`

加入 zchain workspace（`Cargo.toml` members 增加 `proving_service`）。结构：
```
proving_service/
  Cargo.toml            # 依赖 poker_texas_air, poker_l1, vm-common, axum, tokio, tracing, borsh
  src/
    lib.rs
    contract_plugin.rs  # ContractPlugin trait：统一的"加载合约"抽象
    contracts/
      texas_poker.rs    # TexasPokerPlugin：封装 poker_l1 dispatch + poker_texas_air Orchestrator
    runner.rs           # HandRunner：按牌局阶段顺序驱动 dispatch→快照→prove，串联 call_seq/state_root 链
    server.rs           # axum HTTP 服务（POST /prove/hand 等）
    main.rs             # bin：启动 server 或跑 --once 一手牌
```

### 2.2 `ContractPlugin` trait（可扩展架构）

```rust
pub trait ContractPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn dispatch(&self, selector: &[u8;32], args: &[u8]) -> Result<DispatchOutput>;
    fn prove_task(&self, task: &ProveTask) -> Result<ProvenTask>;
    fn verify_chain(&self) -> Result<()>;
}
```
`texas_poker.rs` 实现该 trait：内部持有 `TexasPokerTable` 状态 + `Orchestrator`，dispatch 委托 `poker_l1::vm::contracts::texas_poker::dispatch::dispatch`，prove 委托 `Orchestrator::prove_and_verify_task`。未来其他合约实现同 trait 即可加载。

### 2.3 给 `Orchestrator` 补全 19 个方法的 trace 构造

当前 `orchestrator.rs:119-127` 只接 `CreateTable`/`Fold`。补全其余 19 个方法的 `prove_<method>`：每个方法从 `task.method_input` 反序列化出对应 `*Input`，调对应 `*Air`/`*Row::active`，与现有 `prove_create_table`/`prove_fold` 同模板（这些 AIR/Row 已存在，只是没在 Orchestrator 接线）。复用 `prove_method`/`verify_method`。

> 关键：trace 构造只做"输入一致性 + AIR 现有约束"的证明（即任务1修完后的约束集），不依赖合约逻辑重算——pre/post 快照由 dispatch 真实产生，保证状态转移正确性来自合约。

### 2.4 `HandRunner` 跑通一整手牌

按真实牌局顺序编排（参考 state_machine 阶段）：
1. `create_table` → 2. `join_table` ×2-3 玩家 → 3. `start_hand` → 4. crypto 阶段（shuffle/reveal/reconstruct，用 `config.skip_*` 跳过 ZK 验证以简化 e2e）→ 5. 下注轮（preflop: fold/call/raise；flop/turn/river: check/bet）→ 6. showdown 摊牌分池 → 7. `reset_for_next_hand`。

每步：构造 `DispatchContext`+args → 调 `dispatch` → 取 `return_value` 反序列化 `DispatchOutput` → `prove_task` 喂 Orchestrator → 累积 `call_seq`。最后 `verify_chain()` 校验整手牌的 state_root 链连续，并可 `aggregate_proofs` 生成单聚合证明。

为让 e2e 可跑通，跳过 Mental Poker 的真实 ZK 密码学验证（合约 `config` 已有 `skip_remask/skip_shuffle/skip_reveal/skip_reconstruct` 开关），保证流程聚焦在"证明管线"而非密码学。

### 2.5 HTTP 服务（axum）

最小端点：
- `POST /hands/run`：触发一次完整牌局编排，返回各步 proof 摘要 + 最终聚合 proof。
- `POST /dispatch`：单步 dispatch+prove（手动驱动）。
- `GET /plugins`：列出已加载合约插件。

`main.rs` 支持 `--once`（跑一手牌到 stdout）和默认 HTTP server 两种模式。

### 2.6 验收测试

- `proving_service/tests/full_hand_e2e.rs`：调 `HandRunner` 跑完整手 2-3 人牌局，断言每步 prove+verify 通过、`verify_chain` 通过、聚合证明 verify 通过。
- 每个新增的 19 个 Orchestrator 方法接线，各加一个 smoke test（复用现有 e2e_* 测试的快照构造模式）。

---

## 执行顺序

1. 写核对报告（任务1.1）→ 2. 改任务1的代码修复（1.2）→ 3. 新建 `proving_service` crate 骨架 + workspace 接入 → 4. 补 Orchestrator 19 方法 → 5. ContractPlugin + TexasPokerPlugin → 6. HandRunner 跑通 → 7. axum server → 8. 验收测试。

每步跑 `cargo check -p <crate>` / `cargo test` 验证。

## 不在范围内（已与你确认）
- state_root Poseidon 嵌入、真 Fr→M31 转换、SeatLeaf 字段补全（阶段5）。
- ECDSA / BLS 签名 AIR、crypto 方法的真实密码学验证。
- 链上验证器集成、proof 持久化存储。
