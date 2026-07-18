# Texas Poker 移植到 zchain — 续作执行计划（Resume）

## Summary

本计划承接上一轮已批准的总计划 [`texas-poker-implementation-continue.md`](./texas-poker-implementation-continue.md)，聚焦剩余工作：

1. **修复 Phase 1 残留测试失败**（events.rs 断言 40→39）
2. **Phase 2**：Mental Poker 密码学层（crypto/ 子目录 12 个文件）
3. **Phase 3**：状态机 + dispatch + TexasPokerPrecompile impl
4. **Phase 4**：集成 wire-up（precompile.rs / node/mod.rs / Cargo.toml / main.rs）
5. **Phase 5**：CLI 客户端（poker_demo.rs）
6. **Phase 6**：cargo zigbuild 交叉编译 + sshpass 部署到 `root@47.120.51.203`
7. **Phase 7**：跑通一局完整牌局

**用户原始 4 项 goal**（保持不变）：
1. `/Users/mac/projects/zgame/texas_poker_move` → zchain 兼容合约（Native Precompile + 完整 Mental Poker）
2. cargo zigbuild 编译 + sshpass 部署到 `ssh zchain`（密码 `123456Ab!`）
3. 部署合约（原生预编译 = 启动新二进制即生效）
4. 跑一局完整牌局

**用户已确认的关键决策**（不再重问）：
- 合约形态：原生 Precompile（BPF 工具链不可用）
- Mental Poker：一次性完整移植（BLS12-381 ElGamal + 7 种 ZK proof）
- 客户端：Rust CLI 脚本（`zchain poker-demo` 子命令）
- 实现节奏：一次性完整实现

---

## Current State Analysis

### 已完成（Phase 1 8/8 文件，1 处测试待修）

| 文件 | 行数 | 状态 |
|---|---|---|
| `poker_l1/src/vm/contracts/texas_poker/constants.rs` | ~150 | ✅ |
| `poker_l1/src/vm/contracts/texas_poker/card.rs` | ~180 | ✅ |
| `poker_l1/src/vm/contracts/texas_poker/hand_evaluator.rs` | ~470 | ✅（compare_kickers 已修） |
| `poker_l1/src/vm/contracts/texas_poker/betting.rs` | ~280 | ✅ |
| `poker_l1/src/vm/contracts/texas_poker/side_pot.rs` | ~534 | ✅ |
| `poker_l1/src/vm/contracts/texas_poker/events.rs` | ~709 | ⚠️ line 707 断言 `40` 需改 `39` |
| `poker_l1/src/vm/contracts/texas_poker/types.rs` | ~830 | ✅ |
| `poker_l1/src/vm/contracts/texas_poker/mod.rs` | 51 | ✅（Phase 2/3 模块声明注释中） |

`crypto/` 和 `tests/` 子目录已创建但为空。

### 关键发现（探索阶段确认）

1. **`events.rs:707`**：`assert_eq!(samples.len(), 40, ...)` 仍是错误断言，需改为 39（Move 源实际 39 个事件变体）。

2. **`node/mod.rs:680`**：`verify_block` 用 `ExecutionEnvironment::new(chain_id, height, timestamp)` 构造 env，**完全未注入 PrecompileRegistry**——意味着 GamePrecompile 和 TexasPokerPrecompile 当前都不会被调用。这是必须修复的集成缺口。

3. **`executor.rs:88`**：`with_precompile_registry(mut self, registry: PrecompileRegistry)` 按值接收（内部转 `Arc::new(registry)`）。Node 侧需要持有 `Arc<PrecompileRegistry>` 并在每次 `verify_block` 调用时 `(*arc).clone()` 复制整个 BTreeMap（首版可接受）。

4. **`precompile.rs:412-427`** `reserved` 模块当前只有 `game_contract_id()`（ObjectID `0xFF..01`），需新增 `texas_poker_contract_id()`（ObjectID `0xFF..02`）。

5. **`contracts/mod.rs`** 已声明 `pub mod texas_poker;`（line 44），但未 `pub use texas_poker::TexasPokerPrecompile;`（待 Phase 3.3 实现）。

6. **`Cargo.toml`** 顶层无 `[features]` 段；`poker_l1/Cargo.toml` 有 `[features]` 仅 `test-helpers`。需新增 `client` feature（控制链下 prove 代码 + rand 依赖）。

7. **`main.rs:75`** `match subcommand` 入口，需新增 `"poker-demo"` 分支。

8. **SSH 配置**：`ssh zchain` → `root@47.120.51.203:22`（IdentityFile `~/keys/aibot.pem`）。**服务器用户是 root，路径基目录 `/root/`**（非 `/home/zchain/`）。密码 `123456Ab!` 是 SSH 密码认证回退（服务器同时接受 key + password）。

9. **工具链**：`cargo-zigbuild` 已安装于 `/Users/mac/.cargo/bin/cargo-zigbuild`；`sshpass` 未安装，需 `brew install hudochenkov/sshpass/sshpass`。

10. **BLS 基础设施**：`poker_l1/src/crypto_precompiles/bls.rs:41` 已定义 `BLS_G1_DST = b"POKER_L1_BLS12381G1_XMD:SHA-256_SSWU_RO_"`；`blstrs = { workspace = true }` 已是 poker_l1 依赖。可复用。

11. **Move 源**：`/Users/mac/projects/zgame/texas_poker_move/sources/` 共 19 个 `.move` 文件，其中 `table.move` 172KB（主状态机 + 17 个 method dispatcher），其余 18 个为辅助模块（合计约 100KB）。

---

## Proposed Changes

### 阶段 1 收尾：修复 events.rs 测试断言

**文件**：`poker_l1/src/vm/contracts/texas_poker/events.rs:707`

**修改**：
```rust
// 验证样本数量（39 个变体）
assert_eq!(samples.len(), 39, "事件变体数应为 39");
```

**验证**：`cargo test -p poker_l1 texas_poker::events` 全绿。

---

### 阶段 2：Mental Poker 密码学层（crypto/ 12 个文件）

**目录**：`poker_l1/src/vm/contracts/texas_poker/crypto/`

详细设计见总计划 [`texas-poker-implementation-continue.md`](./texas-poker-implementation-continue.md) 阶段 2.1-2.9。本节仅列文件清单与关键约束：

| 文件 | 内容 | 关键约束 |
|---|---|---|
| `bls_scalar.rs` | G1/Scalar 序列化 + hash_to_scalar + generate_plaintext_cards(52) | 复用 `crate::crypto_precompiles::bls::BLS_G1_DST` |
| `bls_elgamal.rs` | encrypt/decrypt/remask/add_pk_to_c2 | `(sk·G, m + sk·pk)`；remask 后原 sk 仍可解密 |
| `transcript.rs` | Transcript { Sha3_256 } + append/challenge | **M-P13 长度前缀编码 `u32_be_len || data`**；label 逐字节对照 Move |
| `schnorr_proof.rs` | GeneralizedSchnorrProof + verify + prove | `#[cfg(feature = "client")] prove` |
| `chaum_pedersen.rs` | ChaumPedersenProof (DLEq) + verify + prove | `#[cfg(feature = "client")] prove` |
| `shuffle_proof.rs` | ShuffleProof (3 层 Schnorr) + verify + prove | 7 步验证流程；最复杂 |
| `remask_proof.rs` | RemaskProof + verify + prove | 基于 DLEq |
| `reveal_token_proof.rs` | RevealTokenProof + verify + prove | token 与 pk 同离散对数 |
| `reconstruct_proof.rs` | ReconstructProof + verify + prove | ~750 行；首版可走 zk_skip 回退 |
| `leave_proof.rs` | LeaveProof + verify + prove | 玩家离场 |
| `serialization.rs` | proof 字节流 ↔ struct | BCS + 长度前缀 |
| `zk_verifier.rs` | verify_proof(kind, bytes, public_inputs) → bool | dispatch + `verify_or_skip(config, ...)` 回退 |

**单测要求**（每个 proof）：
- `#[cfg(feature = "client")] test_prove_verify_roundtrip`
- `test_verify_tampered`（篡改任意字段后必失败）
- `test_verify_wrong_public_input`

**`crypto/mod.rs`**：声明所有 12 个子模块，导出公共 API。

---

### 阶段 3：状态机 + dispatch + Precompile impl

#### 3.1 `state_machine.rs`（~900 行）

详细设计见总计划阶段 3.1。要点：
- `tick(table: &mut TexasPokerTable, env: &ExecutionEnvironment) -> Vec<TexasPokerEvent>`
- 状态转移：`WAITING → JOINING → SHUFFLING → REVEAL_TOKEN → PREFLOP → (FLOP→TURN→RIVER) → SHOWDOWN → SETTLED`
- shuffle 编排：`current_shuffler` 轮转
- reveal 编排：每个玩家为非自己手牌提交 reveal_token
- reconstruct 编排：所有 reveal_token 收齐后 reconstruct deck
- showdown：解密手牌 → `hand_evaluator::find_winners` → `side_pot::distribute_pots`

**参考 Move 源**：`table.move` 状态机部分（约 1700 行）。

#### 3.2 `dispatch.rs`（~650 行）

详细设计见总计划阶段 3.2。要点：
- 17 个 method selector 常量
- `dispatch(ctx, table, selector, args) -> DispatchResult`
- Public 通道（付费）：`texas_create_table` / `texas_join_and_shuffle` / `texas_join_table` / `texas_leave_with_proof` / `texas_start_hand` / `texas_tick` / `texas_kick_player` / `texas_set_timeout_config` / `texas_get_table_summary`
- GameTurn 通道（免 gas）：`texas_submit_shuffle_v2` / `texas_submit_player_reveal_tokens` / `texas_submit_reconstruct_deck` / `texas_fold` / `texas_check` / `texas_call` / `texas_raise`

#### 3.3 `mod.rs` 补 `TexasPokerPrecompile` impl（~250 行）

镜像 `game_precompile.rs` 模式：
```rust
pub struct TexasPokerPrecompile { version: u32 }

impl Precompile for TexasPokerPrecompile {
    fn id(&self) -> ObjectID { reserved::texas_poker_contract_id() }
    fn call(...) -> PokerL1Result<DispatchResult> {
        let table_id = reserved::texas_poker_contract_id();
        let obj = object_db.read(&table_id)?;
        let mut table: TexasPokerTable = bcs::from_bytes(&obj.data)?;
        let result = dispatch::dispatch(&ctx, &mut table, method_selector, args)?;
        let data = bcs::to_bytes(&table)?;
        object_db.update(&table_id, caller, data)?;
        Ok(DispatchResult { ... })
    }
    fn supports_selector(&self, selector: &[u8; 32]) -> bool { /* 17 selectors */ }
    fn is_gas_free(&self) -> bool { true }
}
```

`mod.rs` 取消注释：`pub mod state_machine; pub mod dispatch; pub mod crypto;` 并导出 `TexasPokerPrecompile`。

---

### 阶段 4：集成 wire-up（4 处修改）

#### 4.1 `poker_l1/src/vm/precompile.rs`（reserved 模块扩展，line 427 之后）

```rust
/// Texas Poker 合约预编译地址（0xFF..02）。
pub const TEXAS_POKER_CONTRACT_ADDRESS: Address = [
    PRECOMPILE_PREFIX, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02,
];

/// Texas Poker 合约预编译 ObjectID。
#[must_use]
pub const fn texas_poker_contract_id() -> ObjectID {
    ObjectID::new(TEXAS_POKER_CONTRACT_ADDRESS, 0)
}
```

#### 4.2 `poker_l1/src/node/mod.rs`（PrecompileRegistry 注册 + env 注入）

**关键缺口**：`node/mod.rs:680` 当前未注入 registry。修改点：

1. **Node struct** 新增字段：`precompile_registry: Arc<PrecompileRegistry>`
2. **Node::open**（或等价构造）创建并注册：
   ```rust
   let mut registry = PrecompileRegistry::new();
   registry.register(GamePrecompile::new_arc(1));
   registry.register(TexasPokerPrecompile::new_arc(1));
   registry.set_status(config.chain_id, PrecompileStatus::Production);
   let registry = Arc::new(registry);
   ```
3. **Node::verify_block** line 680：
   ```rust
   let env = ExecutionEnvironment::new(chain_id, height, timestamp)
       .with_precompile_registry((*self.precompile_registry).clone());
   ```
4. **搜索所有 `ExecutionEnvironment::new(` 调用点**（execute_block 路径），全部追加 `.with_precompile_registry(...)`。

#### 4.3 `poker_l1/src/vm/contracts/mod.rs`

在 `pub mod texas_poker;` 之后追加：
```rust
pub use texas_poker::TexasPokerPrecompile;
```

#### 4.4 `Cargo.toml` features 配置

**顶层 `Cargo.toml`** 追加：
```toml
[features]
default = []
client = ["poker_l1/client"]
```

**`poker_l1/Cargo.toml`** `[features]` 段追加 `client = []`（`blstrs`/`rand` 已是无条件依赖，无需重复声明）。

---

### 阶段 5：CLI 客户端

#### 5.1 `src/poker_demo.rs`（~800 行，新增）

详细设计见总计划阶段 5.1。要点：
- `PokerRpcClient { stream: TcpStream }`：connect / submit_tx / get_object / chain_head
- `build_signed_tx(tagged_pubkey, secret_key, chain_id, method_name, args_bcs, lane, nonce, gameturn_nonce) -> Transaction`
- `run_poker_demo(args: &[String]) -> Result<(), String>`：
  1. 解析 `--nodes <rpc_url>`（默认 127.0.0.1:8545）`--players <N>`（默认 2）
  2. 每玩家生成 secp256k1 sk + BLS sk
  3. 等待节点 height >= 1
  4. Player0 调用 `texas_create_table`
  5. 轮流 `texas_join_and_shuffle`
  6. `texas_start_hand`
  7. 轮询 shuffle_state.current_shuffler，链下 prove + `texas_submit_shuffle_v2`
  8. preflop reveal：批量 `texas_submit_player_reveal_tokens`
  9. 下注（简单策略：preflop pair+ call 否则 fold；postflop best_hand 评估）
  10. FLOP/TURN/RIVER：每轮公共牌 reveal + 下注
  11. SHOWDOWN：提交 reveal token 解密手牌，结算
  12. 查询 table summary，打印最终筹码

**RPC 协议**：newline-delimited JSON-RPC 2.0 over TCP（参考 `main.rs:1333-1556` test-e2e 子命令构造 tx 流程）。

#### 5.2 `src/main.rs`（新增子命令分支）

在 line 75 `match subcommand` 增加：
```rust
"poker-demo" => {
    if let Err(e) = run_poker_demo(rest) {
        eprintln!("poker-demo 失败：{e}");
        std::process::exit(1);
    }
}
```

文件顶部追加 `mod poker_demo;` + `use poker_demo::run_poker_demo;`，`print_usage()` 增加帮助文本。

---

### 阶段 6：编译 + 部署

#### 6.1 本地编译验证
```bash
cd /Users/mac/projects/zchain
cargo check --workspace --features client
cargo test -p poker_l1 texas_poker:: --features client
```

#### 6.2 安装 sshpass
```bash
brew install hudochenkov/sshpass/sshpass
```

#### 6.3 交叉编译
```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu --features client --bin zchain
# 输出 target/x86_64-unknown-linux-gnu/release/zchain
```

#### 6.4 上传 + 启动节点

**服务器路径**：基目录 `/root/zchain/`（用户是 root）。

```bash
sshpass -p '123456Ab!' ssh -o StrictHostKeyChecking=no zchain 'mkdir -p /root/zchain'

sshpass -p '123456Ab!' scp -o StrictHostKeyChecking=no \
    target/x86_64-unknown-linux-gnu/release/zchain \
    zchain:/root/zchain/zchain.new

sshpass -p '123456Ab!' ssh zchain '
    pkill -f zchain 2>/dev/null || true
    sleep 1
    mv /root/zchain/zchain.new /root/zchain/zchain
    chmod +x /root/zchain/zchain
    # 若 validator.key 不存在，先生成
    [ -f /root/zchain/validator.key ] || /root/zchain/zchain keygen --scheme secp256k1 > /root/zchain/validator.key
    nohup /root/zchain/zchain node --role validator --data-dir /root/zchain/data \
        --rpc-listen 0.0.0.0:8545 --p2p-listen 0.0.0.0:9000 \
        --validator-key-file /root/zchain/validator.key \
        > /root/zchain/node.log 2>&1 &
    sleep 3
    tail -50 /root/zchain/node.log
'
```

#### 6.5 部署合约

TexasPokerPrecompile 是**原生预编译**（编译进二进制），部署合约 = 启动新二进制即可。节点启动后 `texas_poker_contract_id()` 立即可用。只需通过 `texas_create_table` tx 初始化桌台对象（写入 ObjectDb）。

---

### 阶段 7：跑一局完整牌局

#### 7.1 本地编译 CLI 版 + 连接服务器
```bash
cargo build --release --features client --bin zchain
./target/release/zchain poker-demo --nodes 47.120.51.203:8545 --players 2
```

#### 7.2 验证完整流程

CLI 输出应依次出现：
1. `✓ 已连接节点 47.120.51.203:8545，当前高度 N`
2. `✓ Player0 创建桌台成功，table_id = 0xFF..02`
3. `✓ Player1 加入并提交初始 shuffle`
4. `✓ 洗牌完成（2 轮）`
5. `✓ Reveal tokens 提交完成`
6. `✓ 牌局开始，button=0, SB=Player0, BB=Player1`
7. `✓ Preflop 下注完成`
8. `✓ Flop: [As Kh 7d]`
9. `✓ Turn: [As Kh 7d Qc]`
10. `✓ River: [As Kh 7d Qc 2s]`
11. `✓ Showdown: Player1 wins with Two Pair`
12. `✓ 最终筹码: Player0=980, Player1=1020`

---

## Assumptions & Decisions

### 关键假设

1. **blstrs zigbuild 可用**：blstrs 是 workspace 依赖（0.7），假设其 C 依赖（BLST）可被 zigbuild 正确交叉编译。**回退**：若失败，改用 `ark-bls12-381`（纯 Rust，但性能略低）。

2. **服务器环境**：`ssh zchain` 已配置（`~/.ssh/config` Host zchain → root@47.120.51.203）。服务器是 Linux x86_64。基目录 `/root/zchain/`。

3. **validator.key**：若服务器无此文件，先 `zchain keygen --scheme secp256k1` 生成并上传。

4. **Move 端 transcript label**：需逐字节对照 Move 源（`bls_transcript.move`）确保 Rust 端 label 完全一致，否则 ZK verify 失败。计划阶段已识别此风险，实施时用单测硬编码 Move golden vector 交叉验证。

5. **PrecompileRegistry clone 性能**：每次 `verify_block` 调用 `(*arc).clone()` 复制整个 `BTreeMap`。首版可接受（单 validator 场景 block 间隔 1s，map 仅 2-3 个 entry）。后续优化为直接 `Arc::clone`（需 executor.rs 同步修改 `with_precompile_registry` 签名）。

6. **GamePrecompile 未注册**：探索发现 `node/mod.rs` 当前连 GamePrecompile 都没注册。本计划在 4.2 一并注册两个预编译。

### 设计决策

1. **zk_skip_enabled 默认 true**（dev chain）：首版启用 `TableConfig { zk_skip_enabled: true }`，让链上 verify 直接返回 true，先用链下 prove 跑通流程。mainnet 强制 false。

2. **CLI 用本地编译版本**：服务器版（linux x86_64）只跑节点；CLI 客户端用本地 macOS 编译版本连接服务器 RPC。

3. **Phase 4 集成顺序**：先改 `precompile.rs`（加 reserved id）→ 再改 `node/mod.rs`（注册）→ 最后改 `contracts/mod.rs`（导出）。这样编译错误能逐层暴露。

4. **不修改 executor.rs**：executor.rs 的 precompile 调用路径已实现完整（line 246-254），无需修改。只需在 node/mod.rs 注入 registry 即可。

---

## Verification Steps

### 阶段 1 验证
```bash
cargo test -p poker_l1 texas_poker::events
cargo test -p poker_l1 texas_poker:: --features client
# 全绿
```

### 阶段 2 验证
```bash
cargo test -p poker_l1 texas_poker::crypto:: --features client
# 每个 ZK proof：prove→verify roundtrip + 篡改负样本
```

### 阶段 3 验证
```bash
cargo test -p poker_l1 texas_poker::state_machine --features client
cargo test -p poker_l1 texas_poker::dispatch --features client
cargo test -p poker_l1 texas_poker::tests::test_full_hand --features client
```

### 阶段 4 验证
```bash
cargo check --workspace --features client
# 应无错误，仅有 pre-existing warnings
```

### 阶段 5 验证
```bash
cargo build --features client --bin zchain
# 本地编译通过
```

### 阶段 6 验证
```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu --features client --bin zchain
sshpass -p '123456Ab!' ssh zchain 'tail -50 /root/zchain/node.log'
# 应看到 "JSON-RPC server 监听 0.0.0.0:8545" + validator 产块日志
```

### 阶段 7 验证
```bash
./target/release/zchain poker-demo --nodes 47.120.51.203:8545 --players 2
# 应看到完整牌局流程 + 最终筹码分配（见 7.2）
```

---

## 风险与回退

| 风险 | 概率 | 缓解 |
|---|---|---|
| blstrs zigbuild 失败 | 中 | 改用 ark-bls12-381（纯 Rust） |
| ZK proof prove 实现错误 | 中 | 用 Move 端 prover 生成 golden test vector，Rust verify 必须通过 |
| Transcript label 不匹配 | 中 | 单测硬编码 Move 测试 vector 交叉验证 |
| ReconstructProof 太复杂（750 行） | 高 | 首版启用 `zk_skip_reveal=true`，跑通流程后再补 |
| PrecompileRegistry clone 性能 | 低 | 首版接受；优化时改 Arc 直接 clone |
| 服务器防火墙阻断 8545 | 低 | SSH 验证后开放端口 |
| sshpass brew 安装失败 | 低 | 改用 expect 脚本或 ssh key 认证（服务器已配 aibot.pem） |

### 终极回退

若完整 Mental Poker 移植在阶段 7 前发现重大问题，启用 `zk_skip_enabled=true` + `zk_skip_shuffle=true` + `zk_skip_reveal=true` 三个开关全部跳过 ZK 验证，让链上仅做"信任玩家提交"的简化流程跑通一局牌局。这能保证用户 goal 4（完成牌局）至少在简化模式下达成，再逐步关闭 skip 实现严格模式。

---

## 实施顺序（TodoList）

1. **阶段 1 收尾**：修 `events.rs:707` 断言 40→39 + 跑测试确认全绿
2. **阶段 2.1-2.3**：bls_scalar + bls_elgamal + transcript（基础密码学）
3. **阶段 2.4-2.5**：schnorr + chaum_pedersen（基础 proof）
4. **阶段 2.6**：shuffle_proof（3 层 Schnorr 核心）
5. **阶段 2.7-2.8**：remask/reveal_token/reconstruct/leave proof
6. **阶段 2.9**：serialization + zk_verifier + crypto/mod.rs
7. **阶段 3.1**：state_machine.rs（~900 行）
8. **阶段 3.2**：dispatch.rs（17 个 method 路由）
9. **阶段 3.3**：mod.rs 补 TexasPokerPrecompile impl
10. **阶段 4.1-4.4**：集成 wire-up（precompile.rs / node/mod.rs / contracts/mod.rs / Cargo.toml）
11. **阶段 5.1-5.2**：CLI 客户端（poker_demo.rs + main.rs 子命令）
12. **阶段 6.1-6.3**：本地编译 + cargo zigbuild 交叉编译 + sshpass 安装
13. **阶段 6.4-6.5**：sshpass 上传 + 启动节点 + 部署合约（即启动二进制）
14. **阶段 7**：跑一局完整牌局验证
