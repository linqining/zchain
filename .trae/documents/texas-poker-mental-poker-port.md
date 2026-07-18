# Texas Poker Move → zchain 完整移植与部署计划

## Context

**目标**：将 `/Users/mac/projects/zgame/texas_poker_move`（Sui Move 德州扑克合约，~8000 行，含完整 Mental Poker 协议）移植到 zchain 作为原生 Precompile 合约，部署到远程服务器，并跑通一局完整牌局。

**动机**：zchain 是自研 L1 区块链，已有 GamePrecompile 模式但 BPF 工具链不可用。原 Move 合约实现了基于 BLS12-381 ElGamal + 7 种 ZK proof 的去中心化发牌（Mental Poker），需完整移植以保留密码学安全性。

**预期结果**：
1. zchain 节点二进制内含 `TexasPokerPrecompile`（ObjectID `0xFF..02`）
2. 远程服务器运行 zchain validator 节点
3. 本地 `zchain poker-demo` CLI 连接服务器，2 玩家完成 preflop→flop→turn→river→showdown 全流程

**关键决策**（用户确认）：
- 合约形态：原生 Precompile（非 BPF）
- Mental Poker：一次性完整移植（BLS ElGamal + 7 种 ZK proof + shuffle/reveal/reconstruct 协议）
- 客户端：Rust CLI 脚本（`zchain poker-demo` 子命令）
- 部署：cargo zigbuild 交叉编译 + sshpass 自动化

---

## 模块结构

新增目录 `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/`：

```
texas_poker/
├── mod.rs                    # TexasPokerPrecompile impl + 模块导出 (~250 行)
├── constants.rs              # 状态常量 ROUND_PREFLOP=2 等 (~90 行)
├── types.rs                  # Table/Seat/DeckState/ShuffleState 等 (~480 行)
├── card.rs                   # Card/PlayingCard + 花色映射 (~120 行)
├── hand_evaluator.rs         # 7选5最佳手牌评估 (10 种牌型) (~370 行)
├── betting.rs                # BettingRound + fold/check/call/raise 规则 (~160 行)
├── side_pot.rs               # 边池分层算法 (含 M-A3 修复) (~200 行)
├── events.rs                 # ~40 种事件类型 (~530 行)
├── state_machine.rs          # 状态机推进 + tick + reveal/reconstruct 编排 (~900 行)
├── dispatch.rs               # 17 个 method_selector 路由 (~650 行)
├── crypto/
│   ├── mod.rs                # 子模块导出 (~30 行)
│   ├── bls_scalar.rs         # 标量运算 + hash_to_scalar + generate_plaintext_cards (~270 行)
│   ├── bls_elgamal.rs        # ElGamalCiphertext + encrypt/decrypt/remask (~230 行)
│   ├── transcript.rs         # Fiat-Shamir Transcript (sha3-256) (~140 行)
│   ├── schnorr_proof.rs      # GeneralizedSchnorrProof verify/prove (~260 行)
│   ├── chaum_pedersen.rs     # ChaumPedersenProof DLEq verify/prove (~190 行)
│   ├── shuffle_proof.rs      # ShuffleProof (3层Schnorr) verify/prove (~430 行)
│   ├── remask_proof.rs       # RemaskProof verify/prove (~330 行)
│   ├── leave_proof.rs        # LeaveProof verify/prove (~330 行)
│   ├── reveal_token_proof.rs # RevealTokenProof verify/prove (~260 行)
│   ├── reconstruct_proof.rs  # ReconstructProof verify/prove (~750 行)
│   ├── zk_verifier.rs        # 统一 ZK 验证入口 + transcript factory (~360 行)
│   └── serialization.rs      # proof 字节流 ↔ struct 反序列化 (~260 行)
└── tests/                    # 集成测试 (test_full_hand.rs 等)
```

预估总行数 ~7800 行（与 Move 源对齐）。

---

## 数据结构映射

| Move | Rust | 说明 |
|---|---|---|
| `address` (Sui 32B) | `poker_l1::Address = [u8;20]` | `derive_address(&tagged_pubkey)` |
| `UID`/`ID` | `ObjectID` (28B) | Table 用保留 `0xFF..02` |
| `Balance<SUI>`/`Coin<SUI>` | `u64` (stack) + `chip_pool: u64` | zchain 无原生 SUI，直接 u64 |
| `ElGamalCiphertext` (G1 element) | `ElGamalCiphertext { c1: [u8;48], c2: [u8;48] }` | 存 compressed bytes，verify 时反序列化为 `blstrs::G1Projective` |
| `group_ops::Element<G1>` | `[u8;48]` (G1 compressed) | 状态/proof 里均存压缩字节 |
| `vector<u8>` proof | `Vec<u8>` | BCS 兼容 |
| `Table` (shared object) | `TexasPokerTable` BCS 编码存入单 Object | 镜像 GamePrecompile 模式 |
| `AdminCap` | (省略) | admin 通过 caller_address 白名单 |

核心 struct（types.rs）：
```rust
pub struct TexasPokerTable {
    pub id: ObjectID, pub name: String, pub max_players: u8,
    pub small_blind: u64, pub big_blind: u64,
    pub seats: Vec<Seat>, pub button: u8, pub pot: u64,
    pub side_pots: Vec<SidePot>, pub community_cards: Vec<Card>,
    pub round_state: u8, pub betting_round: Option<BettingRound>,
    pub current_turn: Option<u8>,
    pub deck_state: DeckState, pub shuffle_state: ShuffleState,
    pub reveal_token_state: RevealTokenState, pub reconstruct_state: ReconstructState,
    pub timeout_config: TimeoutConfig, pub timestamps: Timestamps,
    pub chip_pool: u64, pub config: TableConfig, pub version: u64,
}
```

---

## Precompile 方法清单（17 个）

method_selector = `blake2b_256(method_name)[0..32]`（复用 `dispatch.rs:48` 的 `compute_method_selector`）

**Public 通道（付费）**：
- `texas_create_table` / `texas_join_and_shuffle` / `texas_join_table` / `texas_leave_with_proof`
- `texas_start_hand` / `texas_tick` / `texas_kick_player` / `texas_set_timeout_config`
- `texas_get_table_summary`

**GameTurn 通道（免 gas）**：
- `texas_submit_shuffle_v2` / `texas_submit_player_reveal_tokens` / `texas_submit_reconstruct_deck`
- `texas_fold` / `texas_check` / `texas_call` / `texas_raise`

所有 args/return 用 BCS 编码。

---

## Mental Poker 实现策略

### BLS 操作（链上 precompile 直接用 blstrs）

复用 `poker_l1/src/crypto_precompiles/bls.rs` 的反序列化模式（含子群检查），但直接 `use blstrs::{G1Projective, Scalar}`：

```rust
// bls_scalar.rs 关键函数
pub fn parse_g1(bytes: &[u8]) -> PokerL1Result<G1Projective>  // 48B → G1，含子群检查
pub fn serialize_g1(p: &G1Projective) -> [u8; 48]
pub fn parse_scalar(bytes: &[u8]) -> PokerL1Result<Scalar>     // 32B BE → Scalar
pub fn hash_to_scalar(data: &[u8]) -> PokerL1Result<Scalar>    // SHA3-256 + 清高2位
pub fn generate_plaintext_cards() -> Vec<[u8; 48]>              // 52 张 G1，DST = BLS_G1_DST
pub fn g1_msm(scalars: &[Scalar], points: &[G1Projective]) -> G1Projective
```

### ZK Proof：链上 verify + 链下 prove

- 链上 `verify()` 函数：所有 proof 类型实现 `pub fn verify(&self, ...) -> bool`，用 blstrs + transcript
- 链下 `prove()` 函数：用 `#[cfg(feature = "client")]` 门控，仅 poker-demo 编译时引入
- Transcript label 字符串必须与 Move 端逐字节一致（"shuffle_pk"、"rho_challenge" 等）
- Scalar 字节序：blstrs `to_bytes_be`/`from_bytes_be`（与 Move 一致）

### Fiat-Shamir Transcript（transcript.rs）

镜像 `bls_transcript.move`，用 `sha3::Sha3_256`，长度前缀防歧义编码（M-P13）。

### ZK 跳过回退（dev chain）

`TableConfig { zk_skip_enabled: bool, zk_skip_shuffle: bool, ... }`，mainnet 强制 false。每个 verify 调用点包 `verify_xxx_or_skip()`。

---

## 状态存储

- `texas_poker_contract_id()` = `ObjectID::new([0xFF, 0, ..., 0, 0x02], 0)`
- 单 Object 存 `TexasPokerContract` 的 BCS 编码
- 每次 call：`object_db.read(id)` → BCS 反序列化 → mutate → BCS 序列化 → `object_db.update(id, caller, ...)`
- 完全镜像 `GamePrecompile::call`（game_precompile.rs:69-89）

---

## 关键修改文件

### 新增文件
- `poker_l1/src/vm/contracts/texas_poker/` 整个目录（~7800 行）
- `src/poker_demo.rs`（CLI 客户端，~800 行）

### 修改文件
1. **`poker_l1/src/vm/contracts/mod.rs`**：增加 `pub mod texas_poker;` + `pub use texas_poker::TexasPokerPrecompile;`
2. **`poker_l1/src/vm/precompile.rs`**（reserved 模块，line 412-427）：
   ```rust
   pub const TEXAS_POKER_CONTRACT_ADDRESS: Address = [PRECOMPILE_PREFIX, 0, ..., 0x02];
   pub const fn texas_poker_contract_id() -> ObjectID { ObjectID::new(TEXAS_POKER_CONTRACT_ADDRESS, 0) }
   ```
3. **`poker_l1/src/node/mod.rs`**（Node::open，line 342 附近）：
   - Node struct 增加 `precompile_registry: Arc<PrecompileRegistry>` 字段
   - `Node::open` 中创建 registry，注册 `GamePrecompile::new_arc(1)` + `TexasPokerPrecompile::new_arc(1)`
   - `set_status(chain_id, PrecompileStatus::Production)`
   - `verify_block`/`execute_block` 构造 env 时调用 `.with_precompile_registry((*self.precompile_registry).clone())`
4. **`poker_l1/Cargo.toml`**：增加 `[features] client = ["rand"]`
5. **`Cargo.toml`**（顶层）：增加 `[features] client = ["poker_l1/client"]`
6. **`src/main.rs`**：增加 `"poker-demo" => run_poker_demo(rest)` 分支 + `run_poker_demo` 函数

### 参考文件（不修改，复用模式）
- `poker_l1/src/vm/contracts/game_precompile.rs`（Precompile trait 实现模板）
- `poker_l1/src/crypto_precompiles/bls.rs`（BLS 反序列化 + BLS_G1_DST 常量）
- `poker_l1/src/vm/contracts/dispatch.rs`（method_selector 计算）
- `src/main.rs:1333-1556`（test-e2e，tx 构造/签名/提交流程参考）

---

## CLI 客户端（`zchain poker-demo`）

### 流程
1. 解析参数：`--nodes <rpc_url>`（默认 127.0.0.1:8545）、`--players <N>`（默认 2）
2. 每个玩家生成 secp256k1 密钥对（tx 签名）+ BLS 标量 sk（Mental Poker）
3. 等待节点出块到 height >= 1
4. Player0 调用 `texas_create_table`
5. 轮流 `texas_join_and_shuffle`：客户端链下计算 pk/remask/shuffle proof，构造 tx 提交
6. `texas_start_hand`
7. 轮询 `get_object(texas_id)` 读 shuffle_state.current_shuffler
8. 当前 shuffler 链下生成 shuffle proof + 调用 `texas_submit_shuffle_v2`
9. 重复 7-8 直到所有玩家洗牌完成
10. preflop reveal：每个玩家（非牌主）为每张手牌链下计算 reveal_token + proof，批量调用 `texas_submit_player_reveal_tokens`
11. 下注阶段：根据玩家手牌强度做简单策略，轮流 fold/check/call/raise
12. FLOP/TURN/RIVER：每轮公共牌 reveal + 下注
13. SHOWDOWN：所有玩家提交 reveal token 解密手牌，结算
14. 查询 table summary，打印最终筹码

### RPC 客户端 helper
```rust
pub struct PokerRpcClient { stream: TcpStream }
impl PokerRpcClient {
    pub fn connect(addr: &str) -> Result<Self, String>
    pub fn submit_tx(&mut self, tx: &Transaction) -> Result<Hash, String>
    pub fn get_object(&mut self, id: &ObjectID) -> Result<Option<Object>, String>
    pub fn get_block_by_height(&mut self, h: BlockHeight) -> Result<Option<Block>, String>
}
pub fn build_signed_tx(tagged_pubkey, secret_key, chain_id, contract_id, method_name, args_bcs, lane, nonce, gameturn_nonce) -> Transaction
```

### 玩家策略（最简）
- preflop: pair 以上 call，否则 fold
- postflop: 评估 best_hand(2 hole + community)，三张以上 call，否则 check/fold

---

## 部署流程

### 1. 编译
```bash
cd /Users/mac/projects/zchain
cargo zigbuild --release --target x86_64-unknown-linux-gnu --features client --bin zchain
```
输出：`target/x86_64-unknown-linux-gnu/release/zchain`

### 2. 安装 sshpass
```bash
brew install hudochenkov/sshpass/sshpass
```

### 3. 上传 + 启动
```bash
sshpass -p '123456Ab!' scp -o StrictHostKeyChecking=no \
    target/x86_64-unknown-linux-gnu/release/zchain zchain:/home/zchain/zchain.new

sshpass -p '123456Ab!' ssh zchain '
    pkill -f zchain || true; sleep 1
    mv /home/zchain/zchain.new /home/zchain/zchain
    chmod +x /home/zchain/zchain
    nohup /home/zchain/zchain node --role validator --data-dir /home/zchain/data \
        --rpc-listen 0.0.0.0:8545 --p2p-listen 0.0.0.0:9000 \
        --validator-key-file /home/zchain/validator.key \
        > /home/zchain/node.log 2>&1 &
    sleep 2; tail -50 /home/zchain/node.log
'
```

### 4. 验证 + 跑牌局
```bash
# 本地连接服务器跑牌局
./target/release/zchain poker-demo --nodes <server>:8545 --players 2
```

---

## 实施阶段（按顺序执行）

### 阶段 1：核心游戏逻辑（无 crypto）
1.1 `card.rs` + `constants.rs` + `types.rs`（数据结构）
1.2 `hand_evaluator.rs`（7选5评估，含 A-low straight）
1.3 `betting.rs`（fold/check/call/raise，含 all-in 短堆处理）
1.4 `side_pot.rs`（边池分层，含 M-A3 empty eligible 合并）
1.5 `events.rs`

### 阶段 2：Mental Poker 密码学层
2.1 `bls_scalar.rs`（parse_g1/parse_scalar/hash_to_scalar/generate_plaintext_cards）
2.2 `bls_elgamal.rs`（encrypt/decrypt/remask/add_pk_to_c2）
2.3 `transcript.rs`（Fiat-Shamir，sha3-256）
2.4 `schnorr_proof.rs`（verify + prove，基础模块）
2.5 `chaum_pedersen.rs`（DLEq verify + prove）
2.6 `shuffle_proof.rs`（3层Schnorr，最复杂）
2.7 `remask_proof.rs` + `reveal_token_proof.rs`（基于 DLEq）
2.8 `reconstruct_proof.rs` + `leave_proof.rs`
2.9 `serialization.rs` + `zk_verifier.rs`（统一入口）

### 阶段 3：状态机 + dispatch
3.1 `state_machine.rs`（WAITING→PREFLOP→...→SHOWDOWN，含 shuffle/reveal/reconstruct 编排）
3.2 `dispatch.rs`（17 个 method selector 路由）
3.3 `mod.rs`（TexasPokerPrecompile impl）

### 阶段 4：集成 + wire up
4.1 `precompile.rs` reserved namespace 扩展
4.2 `node/mod.rs` PrecompileRegistry 注册 + env 注入
4.3 `contracts/mod.rs` 模块导出
4.4 `Cargo.toml` features 配置

### 阶段 5：CLI 客户端
5.1 `src/poker_demo.rs`（RPC client + 玩家逻辑 + 链下 prove）
5.2 `src/main.rs` 子命令注册

### 阶段 6：编译 + 部署
6.1 `cargo zigbuild --release --target x86_64-unknown-linux-gnu --features client`
6.2 安装 sshpass + 上传二进制
6.3 远程启动节点 + 验证

### 阶段 7：跑牌局
7.1 本地 `zchain poker-demo --nodes <server>:8545 --players 2`
7.2 验证完整流程：create→join→shuffle→deal→bet→showdown→settle

---

## 验证方法

### 单元测试（每模块内）
```bash
cargo test -p poker_l1 texas_poker::hand_evaluator
cargo test -p poker_l1 texas_poker::side_pot
cargo test -p poker_l1 texas_poker::betting
cargo test -p poker_l1 texas_poker::crypto::bls_elgamal
cargo test -p poker_l1 texas_poker::crypto::shuffle_proof
# 每个 ZK proof：prove→verify roundtrip + 篡改负样本
```

### 集成测试
```bash
cargo test -p poker_l1 --features client texas_poker::tests::test_full_hand
# 2 玩家完整牌局：create→join_and_shuffle→start_hand→submit_shuffle→reveal→bet→showdown
```

### workspace 编译检查
```bash
cargo check --workspace --features client
cargo zigbuild --release --target x86_64-unknown-linux-gnu --features client --bin zchain
```

### E2E 部署验证
```bash
# 远程节点运行
sshpass -p '123456Ab!' ssh zchain 'tail -50 /home/zchain/node.log'
# 应看到 "JSON-RPC server 监听 0.0.0.0:8545" + validator 产块日志

# 本地跑牌局
./target/release/zchain poker-demo --nodes <server>:8545 --players 2
# 应看到完整牌局流程 + 最终筹码分配
```

### Move 一致性验证（可选）
在 `texas_poker/tests/test_move_parity.rs` 中硬编码 Move 测试 vector（固定 seed + permutation 的 proof 字节），Rust verify 必须通过。

---

## 风险与回退

| 风险 | 缓解 |
|---|---|
| ZK proof prove 实现错误 | 用 Move 端 prover 生成 golden test vector，Rust verify 必须通过 |
| Transcript label 不匹配 | 单测硬编码 Move 测试 vector 交叉验证 |
| Scalar 字节序混淆 | 单测 `test_scalar_roundtrip` |
| ReconstructProof 太复杂（399 行）| 首版可跳过 reconstruct 路径（首手牌用 submit_shuffle_v2 plain shuffle） |
| blstrs zigbuild 不可用 | 已在 workspace 依赖；若失败换 ark-bls12-381 |
| PrecompileRegistry clone 性能 | 首版可接受；优化时改 Arc<PrecompileRegistry> |
| ZK proof 全部实现耗时过长 | 启用 `zk_skip_enabled` 先跑通流程，再逐步关闭 skip |

### ZK 跳过回退（dev chain）
`TableConfig { zk_skip_enabled: bool, ... }`，mainnet 强制 false。每个 verify 调用点包 `verify_xxx_or_skip()`。若完整实现耗时过长，可先用 skip 模式