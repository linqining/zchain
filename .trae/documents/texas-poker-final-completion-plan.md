# Texas Poker 合约移植与部署完成计划

> 目标：完成 `texas_poker_move` → zchain 原生 Precompile 合约移植、节点部署、合约部署、跑通一局牌局。
>
> 本计划基于上一会话已完成的工作继续，聚焦剩余阶段（2.6 验证 → 7 牌局验证）。

## 1. 当前状态分析（基于 Phase 1 探索）

### 1.1 已完成（上一会话）

| 阶段 | 文件 | 行数 | 状态 |
|------|------|------|------|
| Phase 1 | `events.rs` | 709 | ✅ 修了 40→39 变体，74 tests pass |
| Phase 2.1 | `crypto/bls_scalar.rs` | 414 | ✅ 12 tests pass |
| Phase 2.2 | `crypto/bls_elgamal.rs` | 308 | ✅ 11 tests pass |
| Phase 2.3 | `crypto/transcript.rs` | 214 | ✅ 9 tests pass |
| Phase 2.4 | `crypto/schnorr_proof.rs` | 306 | ✅ 6 tests pass |
| Phase 2.5 | `crypto/chaum_pedersen.rs` | 296 | ✅ 6 tests pass |
| Phase 2.6 | `crypto/shuffle_proof.rs` | 525 | ⏳ 已修 `rho[permutation[i]]`，待验证 |
| 业务模块 | `betting/card/constants/hand_evaluator/side_pot/types/events` | 3420 | ✅ 已完成 |

### 1.2 待完成（本计划范围）

| 阶段 | 任务 | 预估行数 |
|------|------|---------|
| 2.6 | shuffle_proof 测试验证 | 0（验证） |
| 2.7-2.8 | remask/reveal_token/reconstruct/leave proof | ~1500 |
| 2.9 | serialization + zk_verifier + crypto/mod.rs 更新 | ~600 |
| 3.1 | state_machine.rs | ~900 |
| 3.2 | dispatch.rs（17 method 路由） | ~500 |
| 3.3 | TexasPokerPrecompile impl + mod.rs | ~200 |
| 4.1-4.4 | wire-up（precompile.rs / node/mod.rs / contracts/mod.rs / Cargo.toml） | ~100 |
| 5.1-5.2 | CLI 客户端（poker_demo.rs + main.rs 子命令） | ~800 |
| 6.1-6.5 | 本地编译 + zigbuild + 上传 + 启动节点 + 部署合约 | 0（操作） |
| 7 | 跑一局完整牌局验证 | 0（操作） |

### 1.3 关键已知约束

- **BPF 不可用** → 走 Native Precompile 路径
- **ObjectID**：`0xFF..02`（`reserved::texas_poker_contract_id()`，待加）
- **BCS 序列化** `TexasPokerTable` 存入 ObjectDb
- **`is_gas_free() = true`**（GameTurn 通道免 gas）
- **`TableConfig::default()` 已设 `zk_skip_enabled=true`**（dev chain 友好，跑通流程优先）
- **PrecompileRegistry 未在 Node 中注入**：`node/mod.rs:680` `ExecutionEnvironment::new(...)` 默认 `precompile_registry: None`，需 Phase 4 修复
- **`GamePrecompile` 同样未注册**（grep 验证）— Phase 4 一并修复
- **executor.rs:246-262** 已实现 precompile 调用路径，无需修改
- **服务器**：`ssh zchain` → `root@47.120.51.203:22`，密码 `123456Ab!`，用户 root，base path `/root/`
- **sshpass**：未安装，需 `brew install hudochenkov/sshpass/sshpass`
- **cargo-zigbuild**：已安装 `/Users/mac/.cargo/bin/cargo-zigbuild`
- **目标平台**：`x86_64-unknown-linux-gnu`

## 2. 决策（Decision-Complete）

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 合约形态 | Native Precompile | BPF 工具链不可用 |
| ZK 验证策略 | dev chain 默认 `zk_skip_enabled=true` 跑通流程 | 首版验证流程，mainnet 由 governance 强制 false |
| 客户端形态 | Rust CLI 子命令 `zchain poker-demo` | 与 zchain 主二进制同源 |
| 部署方式 | cargo zigbuild 交叉编译 + sshpass 上传 | 用户指定 |
| 节点角色 | validator（单 validator 自闭环模式） | 跑通端到端 |
| 合约"部署" | 调用 `create_table` method 创建初始 table 对象 | Precompile 内嵌二进制，无需单独部署字节码 |
| 执行模式 | 一次性完整实现（不分阶段） | 用户已批准 |

## 3. 实施步骤

### 阶段 2.6：验证 shuffle_proof 修复

**操作**：运行 `cargo test -p poker_l1 texas_poker::crypto::shuffle_proof`，确认 6 tests 全部通过。

**验证标准**：`test result: ok. 6 passed; 0 failed`。

---

### 阶段 2.7-2.8：剩余 4 个 ZK proof 模块

**文件**：
- `poker_l1/src/vm/contracts/texas_poker/crypto/remask_proof.rs`（~280 行）
- `poker_l1/src/vm/contracts/texas_poker/crypto/reveal_token_proof.rs`（~220 行）
- `poker_l1/src/vm/contracts/texas_poker/crypto/reconstruct_proof.rs`（~550 行）
- `poker_l1/src/vm/contracts/texas_poker/crypto/leave_proof.rs`（~280 行）

**实现要点**（参考 Move 端逐字节移植）：

#### remask_proof.rs
- `RemaskProof { per_card_commitments: Vec<Vec<u8>>, commitment_pk: Vec<u8>, response: Vec<u8>, nonce: Vec<u8> }`
- `verify(proof, input_cts, output_cts, player_pk, transcript) -> bool`
- 关键：`d2_i = output.c2 - input.c2`，验证 `g1·s == comm_pk + pk·c` 和每张牌 `input.c1·s == per_card_comm[i] + d2_i·c`
- M6/M7/M-P15/M-P17 安全检查
- prove 函数 `#[cfg(any(test, feature = "client"))]`
- 6 unit tests（roundtrip + 各安全检查）

#### reveal_token_proof.rs
- `RevealTokenProof { user_public_key, commitment_t1, commitment_t2, response_s, nonce }`
- `verify(proof, encrypted_card, reveal_token, expected_pk) -> bool`（注意：独立 transcript，不传外部 t）
- 验证 `log_G(pk) == log_c1(reveal_token)`
- 5 unit tests

#### reconstruct_proof.rs（最复杂）
- `SwapOutCardProof` + `ReconstructionDLEQProof` + `ReconstructProof`
- `verify(proof, cards, output_cards, swap_out_cards, user_readable_cards, user_pk, transcript)`
- 6 步验证（swap_out_proofs → rho → weighted sums → blind_dleq → 3 层 swap schnorr → total_dleq）
- 4 unit tests（roundtrip + 各失败路径）

#### leave_proof.rs
- 结构与 remask_proof 完全相同，仅 `d2_i = input.c2 - output.c2`（方向相反）
- 复用 remask_proof 的逻辑骨架

---

### 阶段 2.9：serialization + zk_verifier + crypto/mod.rs

**文件**：
- `poker_l1/src/vm/contracts/texas_poker/crypto/serialization.rs`（~400 行）
- `poker_l1/src/vm/contracts/texas_poker/crypto/zk_verifier.rs`（~250 行）
- `poker_l1/src/vm/contracts/texas_poker/crypto/mod.rs`（更新激活所有子模块）

#### serialization.rs
- `deserialize_schnorr_proof(data, offset) -> (GeneralizedSchnorrProof, u64)`
- `deserialize_shuffle_proof(data) -> ShuffleProof`
- `deserialize_remask_proof(data) -> RemaskProof`
- `deserialize_leave_proof(data) -> LeaveProof`
- `deserialize_reveal_token_proof(data) -> RevealTokenProof`
- `deserialize_reconstruct_proof(data) -> ReconstructProof`
- `deserialize_ciphertexts(data) -> Vec<ElGamalCiphertext>`
- `deserialize_g1_points(data) -> Vec<G1Projective>`
- 6 unit tests

#### zk_verifier.rs
- `new_shuffle_transcript() / new_remask_transcript() / new_leave_transcript() / new_reconstruct_transcript() / new_mask_shuffle_transcript()`
- `verify_shuffle(input_cts, output_cts, pk, proof) -> bool`
- `verify_remask(input_cts, output_cts, player_pk, proof) -> bool`
- `verify_leave(...) -> bool`
- `verify_reveal_token(encrypted_card, reveal_token, expected_pk, proof) -> bool`
- `verify_reconstruct(cards, output_cards, swap_out_cards, user_readable_cards, user_pk, proof) -> bool`
- `verify_pk_ownership(pk, proof_bytes) -> bool`（80 字节：48 commitment + 32 response，`hash_to_scalar` 派生挑战）
- `verify_or_skip(table_config, verify_fn) -> bool` 辅助：dev chain skip

#### crypto/mod.rs 更新
激活所有 6 个新子模块声明：`remask_proof / reveal_token_proof / reconstruct_proof / leave_proof / serialization / zk_verifier`

---

### 阶段 3.1：state_machine.rs（~900 行）

**文件**：`poker_l1/src/vm/contracts/texas_poker/state_machine.rs`

**实现内容**（移植自 `table.move` 的内部函数）：
- `set_initial_encrypted_deck(table)` — 初始化 52 个零密文 + 生成 52 明文 G1 点
- `can_join_state(table) -> bool`
- `is_pk_registered(table, pk) -> bool`
- `start_hand(table)` — 投盲注 + 进入 SHUFFLE_PHASE_WAITING + 设置 pending_players
- `tick(table, now_ms)` — 推进超时（shuffle/reveal/betting/reconstruct）
- `apply_join_and_shuffle(table, seat_index, player, pk, mask_cards, output_cards, remask_proof, shuffle_proof)` — 玩家加入并完成 remask+shuffle
- `apply_submit_shuffle_v2(table, seat_index, mask_cards, output_cards, remask_proof_bytes, shuffle_proof_bytes)` — 后续玩家提交 shuffle
- `apply_submit_reveal_tokens(table, seat_index, encrypted_card_indexes, reveal_tokens, proofs)` — 提交揭牌令牌
- `apply_submit_reconstruct_deck(table, seat_index, output_cts, proof)` — 提交重建牌组
- `apply_fold/apply_check/apply_call/apply_raise(table, seat_index, ...)` — 下注动作
- `apply_leave_with_proof(table, seat_index, output_cards, leave_proof)` — 玩家离场
- `deal_hole_cards(table)` / `deal_flop/turn/river(table)` — 发牌
- `advance_to_showdown(table)` — 摊牌结算
- `settle_side_pots(table)` — 边池结算
- `reset_for_next_hand(table)` — 重置进入下一局

**ZK 验证策略**：所有 verify 调用经 `zk_verifier::verify_or_skip(table.config, ...)` 包装，dev chain 跳过。

**单元测试**：8-12 个核心测试（state transitions + 边界条件）。

---

### 阶段 3.2：dispatch.rs（17 method 路由，~500 行）

**文件**：`poker_l1/src/vm/contracts/texas_poker/dispatch.rs`

**实现内容**：
```rust
pub struct DispatchContext {
    pub caller: Address,
    pub caller_pubkey: TaggedPubkey,
    pub chain_id: ChainId,
    pub block_height: BlockHeight,
    pub block_timestamp: u64,
}

pub struct DispatchResult {
    pub created_objects: Vec<ObjectID>,
    pub modified_objects: Vec<ObjectID>,
    pub return_value: Vec<u8>,
}

pub fn compute_method_selector(method_name: &str) -> [u8; 32]
pub fn dispatch(ctx, table, method_selector, args) -> PokerL1Result<DispatchResult>

pub mod selectors {
    pub fn create_table() -> [u8; 32]
    pub fn join_and_shuffle() -> [u8; 32]
    pub fn leave_with_proof() -> [u8; 32]
    pub fn join_table() -> [u8; 32]
    pub fn leave_table() -> [u8; 32]
    pub fn start_hand() -> [u8; 32]
    pub fn tick() -> [u8; 32]
    pub fn auto_fold() -> [u8; 32]
    pub fn force_fold() -> [u8; 32]
    pub fn kick_player() -> [u8; 32]
    pub fn submit_shuffle_v2() -> [u8; 32]
    pub fn submit_player_reveal_tokens() -> [u8; 32]
    pub fn submit_reconstruct_deck() -> [u8; 32]
    pub fn fold() -> [u8; 32]
    pub fn check() -> [u8; 32]
    pub fn call() -> [u8; 32]
    pub fn raise() -> [u8; 32]
}
```

**args 编码**：BCS 序列化的 tuple/struct，每个 method 一个对应的 `*Args` 结构体。
**selector 计算**：`blake2b_256(method_name)[0..32]`（与现有 `dispatch.rs:48` 一致）。

**单元测试**：4-6 个路由测试（selector 计算 + 至少 2 个 method dispatch）。

---

### 阶段 3.3：TexasPokerPrecompile impl + mod.rs（~200 行）

**文件**：
- `poker_l1/src/vm/contracts/texas_poker/mod.rs`（更新，激活 state_machine + dispatch）
- 新增内嵌 `TexasPokerPrecompile` 结构体（参考 `game_precompile.rs`）

**实现要点**：
```rust
pub struct TexasPokerPrecompile {
    version: u32,
}

impl TexasPokerPrecompile {
    pub fn new(version: u32) -> Self { Self { version } }
    pub fn new_arc(version: u32) -> Arc<dyn Precompile> { Arc::new(Self::new(version)) }
}

impl Precompile for TexasPokerPrecompile {
    fn id(&self) -> ObjectID { reserved::texas_poker_contract_id() }
    fn version(&self) -> u32 { self.version }
    fn call(&self, caller, caller_pubkey, method_selector, args, env, object_db) -> PokerL1Result<DispatchResult> {
        // 1. 读 ObjectDb → 反序列化 TexasPokerTable（首次调用时为空 → 创建新表）
        // 2. dispatch::dispatch(ctx, &mut table, method_selector, args)
        // 3. BCS 序列化 → object_db.update
        // 4. 返回 DispatchResult
    }
    fn supports_selector(&self, selector) -> bool { /* 17 个 selector 之一 */ }
    fn is_gas_free(&self) -> bool { true }
}
```

**首次调用处理**：当 `method_selector == selectors::create_table()` 且 ObjectDb 中无 `texas_poker_contract_id()` 对象时，构造初始 `TexasPokerTable::new(...)` 并写入。

**单元测试**：3-4 个测试（id/version/supports_selector/is_gas_free）。

---

### 阶段 4：Wire-up 集成

#### 4.1 precompile.rs — 添加 reserved ID

**文件**：`poker_l1/src/vm/precompile.rs`（修改 `reserved` 模块）

```rust
pub mod reserved {
    // ... existing game_contract_id ...
    
    /// Texas Poker 合约预编译地址。
    pub const TEXAS_POKER_CONTRACT_ADDRESS: Address = [PRECOMPILE_PREFIX, 0x00, ..., 0x02];
    
    /// Texas Poker 合约预编译 ObjectID。
    pub const fn texas_poker_contract_id() -> ObjectID {
        ObjectID::new(TEXAS_POKER_CONTRACT_ADDRESS, 0)
    }
}
```

#### 4.2 node/mod.rs — 注入 PrecompileRegistry

**文件**：`poker_l1/src/node/mod.rs`（修改 `verify_block` 中的 `ExecutionEnvironment::new`，约 line 680）

**问题**：现有 `ExecutionEnvironment::new(chain_id, height, timestamp_ms)` 不含 registry。

**方案**：
- 在 `Node::open` 初始化时构造 `PrecompileRegistry`，注册 `GamePrecompile::new_arc(1)` 和 `TexasPokerPrecompile::new_arc(1)`
- 将 `Arc<PrecompileRegistry>` 存为 `Node` 字段
- `verify_block` 中用 `ExecutionEnvironment::with_precompile_registry(...).precompile_registry(Arc::clone(&self.precompile_registry))` 或在 `execute_block` 入参链路传递

**实施细节**：
- 检查 `ExecutionEnvironment` 是否有 `with_precompile_registry` builder 方法（已确认有）
- 修改 `execute_block` 调用点，传入 registry
- 影响范围：`node/mod.rs` 中所有 `ExecutionEnvironment::new(...)` 调用点（grep 验证）

#### 4.3 contracts/mod.rs — 导出 TexasPokerPrecompile

**文件**：`poker_l1/src/vm/contracts/mod.rs`

在 `pub use game_precompile::GamePrecompile;` 下方添加：
```rust
pub use texas_poker::TexasPokerPrecompile;
```

#### 4.4 poker_l1/Cargo.toml — 添加 client feature

**文件**：`poker_l1/Cargo.toml`

```toml
[features]
test-helpers = []
client = []  # 启用 prove_* 函数，CLI 客户端使用
```

---

### 阶段 5：CLI 客户端

#### 5.1 poker_demo.rs（~800 行）

**文件**：`poker_l1/src/bin/poker_demo.rs` 或 `poker_l1/src/client/poker_demo.rs`（mod 树）

**实现内容**：
- `PokerDemoClient` 结构体：持有 RPC client、player sk、player ElGamal sk/pk
- `cmd_create_table(name, max_players, small_blind, big_blind)` — 构造 tx → 签名 → 提交
- `cmd_join_and_shuffle(seat_index, buy_in)` — 客户端生成 ElGamal key + remask + shuffle + 生成 proofs → 提交
- `cmd_start_hand()` — 提交 start_hand tx
- `cmd_submit_reveal_tokens()` — 客户端为每张非自己手牌生成 reveal token + proof → 提交
- `cmd_submit_reconstruct_deck()` — 客户端重建牌组 + proof → 提交
- `cmd_fold/check/call/raise(seat_index, amount)` — 下注动作 tx
- `cmd_tick()` — 触发状态机推进
- `cmd_query_table()` — 查询当前 table 状态

**prove 函数**：所有 `prove_*` 在 `#[cfg(any(test, feature = "client"))]` 下；CLI 编译用 `--features client`。

#### 5.2 main.rs — 新增 poker-demo 子命令

**文件**：`src/main.rs`

在 `match subcommand` 中添加：
```rust
"poker-demo" => {
    if let Err(e) = run_poker_demo(rest) {
        error!("poker-demo 失败：{e}");
        std::process::exit(1);
    }
}
```

`run_poker_demo` 解析子参数：
- `--rpc <addr>` — RPC 地址（默认 127.0.0.1:8545）
- `--data-dir <path>` — 客户端本地数据（存 ElGamal sk）
- `--action <create_table|join|start|reveal|reconstruct|bet|tick|query>`
- `--seat <index>` / `--amount <chips>` / `--action-type <fold|check|call|raise>`

**注意**：`poker-demo` 子命令依赖 `poker_l1` 的 `client` feature。需要在 zchain 主二进制 Cargo.toml 启用：
```toml
[dependencies]
poker_l1 = { path = "poker_l1", features = ["client"] }
```

---

### 阶段 6：编译与部署

#### 6.1 本地编译验证

```bash
cd /Users/mac/projects/zchain
cargo check --workspace 2>&1 | tail -20
cargo test -p poker_l1 texas_poker 2>&1 | tail -20
```

**验证标准**：`cargo check` 0 errors；`texas_poker` 全部测试通过。

#### 6.2 cargo zigbuild 交叉编译

```bash
cd /Users/mac/projects/zchain
cargo zigbuild --release --target x86_64-unknown-linux-gnu --features poker_l1/client
# 输出：target/x86_64-unknown-linux-gnu/release/zchain
```

**验证标准**：生成 `target/x86_64-unknown-linux-gnu/release/zchain` 二进制（大小 ~50-100MB）。

#### 6.3 安装 sshpass

```bash
brew install hudochenkov/sshpass/sshpass
# 验证：which sshpass
```

#### 6.4 上传二进制 + 启动节点

```bash
# 上传
sshpass -p '123456Ab!' scp -o StrictHostKeyChecking=no \
  target/x86_64-unknown-linux-gnu/release/zchain \
  zchain:/root/zchain/zchain

# SSH 启动 validator 节点（后台）
sshpass -p '123456Ab!' ssh -o StrictHostKeyChecking=no zchain \
  'cd /root/zchain && nohup ./zchain node --role validator \
    --data-dir /root/zchain/data \
    --rpc-listen 0.0.0.0:8545 \
    --p2p-listen 0.0.0.0:9000 \
    --block-interval-ms 2000 \
    --validator-key-file /root/zchain/validator.key \
    > /root/zchain/node.log 2>&1 &'
```

**前置准备**：
- 在服务器上生成 validator.key（如已存在则跳过）：
  ```bash
  sshpass -p '123456Ab!' ssh zchain 'cd /root/zchain && ./zchain keygen --scheme secp256k1 > validator.key.json'
  # 提取 secret_key_hex 字段写入 /root/zchain/validator.key
  ```

**验证标准**：
- `curl -s http://47.120.51.203:8545` 返回 RPC 响应（或端口可达）
- `sshpass -p '123456Ab!' ssh zchain 'tail -20 /root/zchain/node.log'` 显示"出块成功"

#### 6.5 部署合约（创建初始 table）

Precompile 合约已内嵌于二进制，"部署"= 调用 `create_table` method 创建初始 table 对象：

```bash
# 在本地用 poker-demo 客户端调用
./target/x86_64-unknown-linux-gnu/release/zchain poker-demo \
  --rpc 47.120.51.203:8545 \
  --action create_table \
  --name "Demo Table" \
  --max-players 2 \
  --small-blind 10 \
  --big-blind 20
```

**验证标准**：返回 table_id（即 `0xFF..02`），table 对象已写入 ObjectDb。

---

### 阶段 7：跑一局完整牌局

**流程**（2 玩家 heads-up）：

1. **Player 1 join_and_shuffle**：
   ```bash
   zchain poker-demo --rpc 47.120.51.203:8545 \
     --action join_and_shuffle --seat 0 --buy-in 10000 \
     --player-key-file /tmp/p1.key
   ```
   - 客户端生成 ElGamal key + remask 52 张牌 + shuffle + 生成 proofs
   - 提交 tx → 链上 verify（dev chain skip）

2. **Player 2 join_and_shuffle**：
   ```bash
   zchain poker-demo --rpc 47.120.51.203:8545 \
     --action join_and_shuffle --seat 1 --buy-in 10000 \
     --player-key-file /tmp/p2.key
   ```

3. **start_hand**：
   ```bash
   zchain poker-demo --rpc 47.120.51.203:8545 --action start_hand
   ```
   - 投盲注（SB=10, BB=20）
   - 进入 SHUFFLE_PHASE_BEFORE_PREFLOP

4. **submit_reveal_tokens**（每个玩家为对方手牌提交 reveal token）：
   ```bash
   zchain poker-demo --rpc 47.120.51.203:8545 \
     --action submit_reveal_tokens --seat 0 --player-key-file /tmp/p1.key
   zchain poker-demo --rpc 47.120.51.203:8545 \
     --action submit_reveal_tokens --seat 1 --player-key-file /tmp/p2.key
   ```

5. **下注**（preflop: P1 call 20, P2 check）：
   ```bash
   zchain poker-demo --rpc 47.120.51.203:8545 --action bet --seat 0 --bet-action call --player-key-file /tmp/p1.key
   zchain poker-demo --rpc 47.120.51.203:8545 --action bet --seat 1 --bet-action check --player-key-file /tmp/p2.key
   ```

6. **flop/turn/river 发牌 + 下注**（每个阶段：tick → reveal_tokens → bet）

7. **showdown**：
   ```bash
   zchain poker-demo --rpc 47.120.51.203:8545 --action showdown
   ```
   - 评估双方手牌
   - 结算 pot 到赢家 stack

**验证标准**：
- 全程无错误
- 最终 table 状态：`round_state = ROUND_WAITING`，一方 stack 增加，另一方 stack 减少
- 链上 block 包含所有 tx，state_root 正确推进

---

## 4. 验证步骤（端到端）

| 验证点 | 命令 | 期望结果 |
|--------|------|---------|
| shuffle_proof 修复 | `cargo test -p poker_l1 texas_poker::crypto::shuffle_proof` | 6 passed |
| 所有 crypto 测试 | `cargo test -p poker_l1 texas_poker::crypto` | 全部通过 |
| 所有 texas_poker 测试 | `cargo test -p poker_l1 texas_poker` | 全部通过 |
| workspace check | `cargo check --workspace` | 0 errors |
| 交叉编译 | `cargo zigbuild --release --target x86_64-unknown-linux-gnu` | 生成二进制 |
| 节点启动 | `curl http://47.120.51.203:8545` | 端口可达 |
| 出块 | `ssh zchain 'tail /root/zchain/node.log'` | "出块成功" |
| 合约部署 | `poker-demo --action create_table` | 返回 table_id |
| 牌局 join | `poker-demo --action join_and_shuffle`（2 次） | 2 玩家入座 |
| 牌局完成 | `poker-demo --action showdown` | 一方胜出 |

## 5. 假设与风险

### 假设
- 上一会话的 6 个 crypto 文件无需大改（仅 shuffle_proof 需测试验证）
- `ExecutionEnvironment` 有 `with_precompile_registry` builder（已确认 line 246-262）
- 服务器 `47.120.51.203` 可从本机直连，22 端口开放
- 服务器为 x86_64 Linux（与交叉编译目标一致）
- `brew install sshpass` 在 macOS 可用（hudochenkov tap）

### 风险与缓解
| 风险 | 缓解 |
|------|------|
| `state_machine.rs` 移植规模大（~900 行） | 优先实现最小可运行流程（join+shuffle+deal+bet+showdown），高级功能（timeout/reconstruct/leave）后置 |
| PrecompileRegistry 注入改动面大 | 仅修改 `Node::open` + `verify_block`，保持其他路径不变 |
| sshpass 在 macOS 难装 | 备选：用 expect 脚本或 `ssh -o StrictHostKeyChecking=no` + ssh-agent |
| cargo zigbuild 缺少 Linux glibc | zigbuild 自带 zig 交叉工具链，无需系统 glibc |
| ElGamal prove 在客户端慢 | 52 张牌 shuffle+prove 约 1-3 秒，可接受 |
| 牌局流程中某步失败 | 每步打印 table 状态，定位失败点 |

## 6. 实施顺序（TodoList）

1. ⏳ **2.6** 验证 shuffle_proof 测试通过
2. ⏳ **2.7** remask_proof.rs
3. ⏳ **2.8** reveal_token_proof.rs + reconstruct_proof.rs + leave_proof.rs
4. ⏳ **2.9** serialization.rs + zk_verifier.rs + crypto/mod.rs 更新
5. ⏳ **3.1** state_machine.rs
6. ⏳ **3.2** dispatch.rs
7. ⏳ **3.3** TexasPokerPrecompile impl + mod.rs 更新
8. ⏳ **4.1-4.4** wire-up（4 个文件）
9. ⏳ **5.1-5.2** poker_demo.rs + main.rs 子命令
10. ⏳ **6.1-6.5** 编译 + 部署
11. ⏳ **7** 跑一局牌局

每完成一步，运行对应测试验证；