# Texas Poker 移植到 zchain — 续作执行计划

## Summary

承接上一轮会话（已批准总计划 `texas-poker-mental-poker-port.md` 并完成阶段 1 的 4/7 文件），本计划聚焦剩余工作：阶段 1 收尾 → 阶段 2 Mental Poker 密码学层 → 阶段 3 状态机/dispatch/Precompile → 阶段 4 集成 wire-up → 阶段 5 CLI 客户端 → 阶段 6 编译部署 → 阶段 7 跑通牌局。

**用户原始 4 项 goal**：
1. `/Users/mac/projects/zgame/texas_poker_move` → zchain 兼容合约（Native Precompile 形态，完整 Mental Poker 移植）
2. cargo zigbuild 编译 + sshpass 部署到 `ssh zchain`（密码 `123456Ab!`）
3. 部署合约
4. 跑一局完整牌局

**用户已确认的关键决策**（不再重问）：
- 合约形态：原生 Precompile（非 BPF，因为 BPF 工具链不可用）
- Mental Poker：一次性完整移植（BLS12-381 ElGamal + 7 种 ZK proof + shuffle/reveal/reconstruct）
- 客户端：Rust CLI 脚本（`zchain poker-demo` 子命令）
- 部署：cargo zigbuild 交叉编译 + sshpass 自动化
- 实现节奏：一次性完整实现

---

## Current State Analysis（已完成）

### 已创建文件（阶段 1 的 4/7）

| 文件 | 行数 | 内容 | 状态 |
|---|---|---|---|
| `poker_l1/src/vm/contracts/texas_poker/constants.rs` | ~150 | ROUND_*/ACTION_*/timeout 常量 | ✅ |
| `poker_l1/src/vm/contracts/texas_poker/card.rs` | ~180 | Card/PlayingCard + 花色映射 + 单测 | ✅ |
| `poker_l1/src/vm/contracts/texas_poker/hand_evaluator.rs` | ~470 | 7选5最佳手牌评估 + 10 种牌型 + 单测 | ✅ |
| `poker_l1/src/vm/contracts/texas_poker/betting.rs` | ~280 | BettingRound + all-in 短堆处理 + 单测 | ✅ |

### 关键发现（探索阶段确认）

1. **executor.rs:248-254** 已实现 precompile 调用路径：`env.precompile_registry` 存在时，构造 `crate::vm::precompile::ExecutionEnvironment` 并调用 `registry.execute(...)`。executor 的 ExecutionEnvironment（含 `precompile_registry: Option<Arc<PrecompileRegistry>>`）与 precompile.rs 的 ExecutionEnvironment（仅 chain_id/height/timestamp）在调用边界做转换。

2. **node/mod.rs:680** 当前 `verify_block` 构造 env 时调用 `ExecutionEnvironment::new(...)`，该构造函数（executor.rs:75）默认 `precompile_registry: None`。**生产环境完全没有 wire up PrecompileRegistry**——意味着 GamePrecompile 和即将新增的 TexasPokerPrecompile 当前都不会被调用。这是必须修复的集成缺口。

3. **precompile.rs:412-427** `reserved` 模块当前只暴露 `game_contract_id()`（ObjectID `0xFF..01`），需要新增 `texas_poker_contract_id()`（ObjectID `0xFF..02`）。

4. **contracts/mod.rs** 已声明 `pub mod game_precompile;` + `pub use game_precompile::GamePrecompile;`，但**未声明 `pub mod texas_poker;`**。

5. **Cargo.toml** 顶层无 `[features]` 段，poker_l1 的 `[features]` 仅有 `test-helpers`。需要新增 `client` feature（控制链下 prove 代码 + rand 依赖）。

6. **main.rs** 子命令分支在 line 75 的 `match subcommand`，需新增 `"poker-demo" => run_poker_demo(rest)` 分支。

7. **环境**：`cargo-zigbuild` 已安装在 `/Users/mac/.cargo/bin/cargo-zigbuild`；`sshpass` 未安装，需 `brew install hudochenkov/sshpass/sshpass`。

8. **Move 源**：`/Users/mac/projects/zgame/texas_poker_move/sources/` 共 19 个 `.move` 文件，其中 `table.move` 172KB（主状态机 + 17 个 method dispatcher），其余 18 个为辅助模块（合计约 100KB）。

---

## Proposed Changes

### 阶段 1 收尾：核心游戏逻辑剩余 3 个文件

#### 1.4 `side_pot.rs`（边池分层，含 M-A3 empty eligible 合并修复）

**文件路径**：`poker_l1/src/vm/contracts/texas_poker/side_pot.rs`

**实现内容**：
- `SidePot { eligible_seats: BTreeSet<u8>, amount: u64 }` 结构
- `compute_side_pots(seats: &[Seat]) -> Vec<SidePot>` 算法：
  1. 收集所有 `total_bet > 0` 的座位按 `total_bet` 升序排序
  2. 逐层切片：当前最小 bet × eligible 人数 → 一层 side pot
  3. **M-A3 修复**：若某层 eligible 集合为空（所有人都 fold 了），该层筹码合并到下一层（而非丢弃），避免筹码凭空消失
  4. 最外层 ineligible（fold 了的座位贡献的筹码）按规则归入最近一个有 eligible 的 side pot
- `distribute_pots(seats: &mut [Seat], pots: &[SidePot], winners_by_pot: &[Vec<u8>]) -> u64`：按 pot 分配奖金到赢家 stack
- 单测覆盖：单 pot、双 side pot、三 side pot、全员 fold 仅剩一人、M-A3 empty eligible 场景

**参考 Move 源**：`/Users/mac/projects/zgame/texas_poker_move/sources/side_pot.move`（6177 字节）

#### 1.5 `events.rs`（~40 种事件类型）

**文件路径**：`poker_l1/src/vm/contracts/texas_poker/events.rs`

**实现内容**：
- `TexasPokerEvent` 枚举（变体约 40 个），每个变体 `#[derive(Serialize, Deserialize, Clone, Debug)]`，BCS 友好
- 主要事件分类：
  - 桌台生命周期：`TableCreated`、`PlayerJoined`、`PlayerLeft`、`HandStarted`、`HandEnded`
  - 洗牌阶段：`ShuffleStarted`、`ShuffleSubmitted`、`ShuffleCompleted`
  - Reveal/Reconstruct：`RevealTokensSubmitted`、`DeckReconstructed`、`CommunityCardsRevealed`
  - 下注：`PlayerFolded`、`PlayerChecked`、`PlayerCalled`、`PlayerRaised`、`PlayerAllIn`
  - 回合推进：`BettingRoundCompleted`、`FlopDealt`、`TurnDealt`、`RiverDealt`
  - 摊牌：`ShowdownStarted`、`WinnersDetermined`、`PotDistributed`
  - 异常/超时：`PlayerTimedOut`、`PlayerKicked`、`TimeoutConfigUpdated`
- `emit_event(events: &mut Vec<TexasPokerEvent>, evt: TexasPokerEvent)` helper
- 单测：BCS 序列化 roundtrip

**参考 Move 源**：`/Users/mac/projects/zgame/texas_poker_move/sources/table_events.move`（16450 字节）

#### 1.6 `types.rs`（核心数据结构，~480 行）

**文件路径**：`poker_l1/src/vm/contracts/texas_poker/types.rs`

**实现内容**（基于计划文件第 73-86 行的 struct 设计）：
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
pub struct Seat { pub player: Address, pub stack: u64, pub total_bet: u64,
    pub hand_cards: [Option<Card>; 2], pub status: SeatStatus, pub last_action: u8 }
pub struct DeckState { pub plaintext_cards: Vec<[u8;48]>, pub encrypted_cards: Vec<ElGamalCiphertext> }
pub struct ShuffleState { pub current_shuffler: Option<u8>, pub shuffled_cards: Vec<ElGamalCiphertext>,
    pub shuffle_proof: Vec<u8>, pub shuffle_done: bool }
pub struct RevealTokenState { pub tokens: Vec<Vec<u8>>, pub proofs: Vec<Vec<u8>>, pub submitted: Vec<bool> }
pub struct ReconstructState { pub reconstructed: Vec<bool>, pub reveal_tokens: Vec<Vec<u8>> }
pub struct TableConfig { pub zk_skip_enabled: bool, pub zk_skip_shuffle: bool, pub zk_skip_reveal: bool }
pub struct TimeoutConfig { pub shuffle_timeout_ms: u64, pub reveal_timeout_ms: u64, pub action_timeout_ms: u64 }
pub struct Timestamps { pub last_action_ms: u64, pub hand_start_ms: u64, pub last_shuffle_ms: u64 }
pub struct ElGamalCiphertext { pub c1: [u8;48], pub c2: [u8;48] }
pub enum SeatStatus { Empty, Waiting, Active, Folded, AllIn, Out }
```

全部 `#[derive(Serialize, Deserialize, Clone, Debug)]`，BCS 兼容。单测：BCS roundtrip + 默认构造。

**参考 Move 源**：`table.move` 顶部的 struct 定义部分。

---

### 阶段 2：Mental Poker 密码学层（crypto/ 子目录，12 个文件）

**目录**：`poker_l1/src/vm/contracts/texas_poker/crypto/`

#### 2.1 `bls_scalar.rs`
- `parse_g1(bytes) -> PokerL1Result<G1Projective>`（48B → G1，复用 bls.rs:62 的 `from_compressed` 子群检查模式）
- `serialize_g1(p: &G1Projective) -> [u8; 48]`
- `parse_scalar(bytes) -> PokerL1Result<Scalar>`（32B BE）
- `hash_to_scalar(data: &[u8]) -> PokerL1Result<Scalar>`（SHA3-256 → 清高 2 位 → Scalar）
- `generate_plaintext_cards() -> Vec<[u8; 48]>`（52 张 G1，DST = `BLS_G1_DST`）
- `g1_msm(scalars, points) -> G1Projective`
- 复用 `poker_l1::crypto_precompiles::bls::BLS_G1_DST` 常量

#### 2.2 `bls_elgamal.rs`
- `ElGamalCiphertext` 的 crypto 视图（区别于 types.rs 的纯字节版）
- `encrypt(pk: &G1Projective, sk: &Scalar, plaintext: &G1Projective) -> ElGamalCiphertext`：`(sk·G, plaintext + sk·pk)`
- `decrypt(sk: &Scalar, ct: &ElGamalCiphertext) -> Option<G1Projective>`：`c2 - sk·c1`
- `remask(ct: &ElGamalCiphertext, pk: &G1Projective, r: &Scalar) -> ElGamalCiphertext`：`(c1 + r·G, c2 + r·pk)`
- `add_pk_to_c2(ct: &mut ElGamalCiphertext, pk: &G1Projective, r: &Scalar)`：`c2 += r·pk`
- 单测：encrypt→decrypt roundtrip、remask 后用原 sk 仍能解密

#### 2.3 `transcript.rs`
- `Transcript { state: Sha3_256 }` 结构
- `new(label: &str)`、`append_bytes(label: &str, data: &[u8])`、`append_scalar(label, &Scalar)`、`append_g1(label, &G1Projective)`、`challenge_scalar(label: &str) -> Scalar`、`challenge_scalars(label, n) -> Vec<Scalar>`
- **M-P13 长度前缀编码**：`append` 时写入 `u32_be_len || data`
- label 字符串必须与 Move 端逐字节一致（"shuffle_pk"、"rho_challenge" 等）

#### 2.4 `schnorr_proof.rs`
- `GeneralizedSchnorrProof { commitment: [u8;48], responses: Vec<[u8;32]> }`
- `verify(&self, transcript: &mut Transcript, statement: &SchnorrStatement) -> bool`
- `#[cfg(feature = "client")] prove(transcript, witness, statement) -> Self`
- `SchnorrStatement { bases: Vec<G1Projective>, target: G1Projective }`：证明 `Σ xi·Bi = T`

#### 2.5 `chaum_pedersen.rs`
- `ChaumPedersenProof { c1_commit: [u8;48], c2_commit: [u8;48], response: [u8;32] }`
- DLEq 证明：`(g^r, h^r) ↔ (g^x, h^x)` 同离散对数
- `verify` + `#[cfg(feature = "client")] prove`

#### 2.6 `shuffle_proof.rs`（3 层 Schnorr，最复杂）
- `ShuffleProof { commitment_a: [u8;48], commitment_b: [u8;48], commitment_c: [u8;48], response_rho: [u8;32], response_sigma: [u8;32], response_tau: [u8;32] }`
- 验证 7 步流程（对应 Move shuffle_proof.move 第 200-430 行）：
  1. 反序列化 commitment A/B/C
  2. transcript append 原 deck + 新 deck + A/B/C
  3. challenge rho/sigma/tau
  4. 验证 `A^rho · B^sigma . C^tau == g^(Σ ci·pi) · (Σ ci·yi)^tau` 形式等式
- `#[cfg(feature = "client")] prove(deck_in, deck_out, permutation, masks, sk) -> ShuffleProof`

#### 2.7 `remask_proof.rs` + `reveal_token_proof.rs`
- `RemaskProof`：基于 DLEq，证明 remask 操作正确
- `RevealTokenProof`：证明 reveal_token 与 pk 同离散对数

#### 2.8 `reconstruct_proof.rs` + `leave_proof.rs`
- `ReconstructProof`：reconstruct 阶段 proof（最复杂，~750 行）
- `LeaveProof`：玩家离场 proof

#### 2.9 `serialization.rs` + `zk_verifier.rs`
- `serialization.rs`：proof 字节流 ↔ struct 反序列化（BCS + 长度前缀）
- `zk_verifier.rs`：统一 ZK 验证入口 `verify_proof(proof_kind, proof_bytes, public_inputs) -> bool`，内部 dispatch 到对应 verifier；含 `verify_or_skip(config, ...)` 回退逻辑

**单测要求**（每个 proof 文件）：
- `#[cfg(feature = "client")] test_prove_verify_roundtrip`：prove→verify 必须通过
- `test_verify_tampered`：篡改任意一个字段后 verify 必须失败
- `test_verify_wrong_public_input`：public input 不匹配时 verify 失败

---

### 阶段 3：状态机 + dispatch + Precompile impl

#### 3.1 `state_machine.rs`（~900 行）

**实现内容**：
- `tick(table: &mut TexasPokerTable, env: &ExecutionEnvironment) -> Vec<TexasPokerEvent>`：推进状态机
- 状态转移：`WAITING → JOINING → SHUFFLING → REVEAL_TOKEN → PREFLOP → (FLOP→TURN→RIVER) → SHOWDOWN → SETTLED`
- 每个状态的进入/退出逻辑 + 超时检测 + 玩家轮换
- shuffle 编排：`current_shuffler` 轮转，所有玩家 shuffle 完成后进入 REVEAL_TOKEN
- reveal 编排：每个玩家为非自己手牌提交 reveal_token
- reconstruct 编排：所有 reveal_token 收齐后 reconstruct deck
- betting 轮次推进：preflop→flop→turn→river→showdown，每轮发公共牌 + reveal
- showdown：解密手牌 → `hand_evaluator::find_winners` → `side_pot::distribute_pots`

**参考 Move 源**：`table.move` 的状态机部分（约 1700 行）

#### 3.2 `dispatch.rs`（~650 行）

**实现内容**：
- `compute_method_selector(name: &str) -> [u8; 32]`（复用 `poker_l1::vm::contracts::dispatch::compute_method_selector`）
- 17 个 method selector 常量：`texas_create_table()`、`texas_join_and_shuffle()`、`texas_submit_shuffle_v2()` 等
- `dispatch(ctx: &DispatchContext, table: &mut TexasPokerTable, selector: &[u8;32], args: &[u8]) -> DispatchResult`
- 每个 method 对应一个 handler 函数：解析 BCS args → 调用 state_machine/business 逻辑 → BCS 序列化 return → 收集 events

**Method 清单**（来自计划文件第 90-103 行）：
- Public 通道（付费）：`texas_create_table` / `texas_join_and_shuffle` / `texas_join_table` / `texas_leave_with_proof` / `texas_start_hand` / `texas_tick` / `texas_kick_player` / `texas_set_timeout_config` / `texas_get_table_summary`
- GameTurn 通道（免 gas）：`texas_submit_shuffle_v2` / `texas_submit_player_reveal_tokens` / `texas_submit_reconstruct_deck` / `texas_fold` / `texas_check` / `texas_call` / `texas_raise`

#### 3.3 `mod.rs`（TexasPokerPrecompile impl，~250 行）

**实现内容**：
- `pub mod constants; pub mod card; pub mod hand_evaluator; pub mod betting; pub mod side_pot; pub mod events; pub mod types; pub mod state_machine; pub mod dispatch; pub mod crypto;`
- `pub struct TexasPokerPrecompile { version: u32 }`
- `impl Precompile for TexasPokerPrecompile`：
  - `id()` → `crate::vm::precompile::reserved::texas_poker_contract_id()`
  - `call()` 镜像 `GamePrecompile::call`（game_precompile.rs:52-89）：
    ```rust
    let table_id = reserved::texas_poker_contract_id();
    let obj = object_db.read(&table_id)?;
    let mut table: TexasPokerTable = bcs::from_bytes(&obj.data)?;
    let result = dispatch::dispatch(&ctx, &mut table, method_selector, args)?;
    let data = bcs::to_bytes(&table)?;
    object_db.update(&table_id, caller, data)?;
    Ok(DispatchResult { ... })
    ```
  - `supports_selector()`：检查 17 个 selector 之一
  - `is_gas_free()` → `true`（GameTurn 通道免 gas）

---

### 阶段 4：集成 wire-up（4 处修改）

#### 4.1 `poker_l1/src/vm/precompile.rs`（reserved 模块扩展）

在 line 420-426 之后新增：
```rust
/// Texas Poker 合约预编译地址（0xFF..02）。
pub const TEXAS_POKER_CONTRACT_ADDRESS: Address = [PRECOMPILE_PREFIX, 0x00, ..., 0x02];

/// Texas Poker 合约预编译 ObjectID。
#[must_use]
pub const fn texas_poker_contract_id() -> ObjectID {
    ObjectID::new(TEXAS_POKER_CONTRACT_ADDRESS, 0)
}
```

#### 4.2 `poker_l1/src/node/mod.rs`（PrecompileRegistry 注册 + env 注入）

**关键缺口**：当前 `verify_block`（line 680）构造 env 时未注入 registry。修改点：

1. **Node struct**（line 342 附近）：新增字段 `precompile_registry: Arc<PrecompileRegistry>`
2. **Node::open**（line 342-364）：创建 registry 并注册：
   ```rust
   let mut registry = PrecompileRegistry::new();
   registry.register(GamePrecompile::new_arc(1));
   registry.register(TexasPokerPrecompile::new_arc(1));
   registry.set_status(config.chain_id, PrecompileStatus::Production);
   let registry = Arc::new(registry);
   ```
3. **Node::verify_block**（line 680-687）：
   ```rust
   let env = ExecutionEnvironment::new(chain_id, height, timestamp)
       .with_precompile_registry((*self.precompile_registry).clone());
   ```
   **注意**：`with_precompile_registry` 接受 `PrecompileRegistry`（按值 clone），而 `PrecompileRegistry` 内部用 `BTreeMap`。性能可接受（首版）。若后续性能瓶颈，需重构为 `with_precompile_registry_arc(arc: Arc<PrecompileRegistry>)`。
4. **同步检查**：搜索所有 `ExecutionEnvironment::new(` 调用点（execute_block 路径），全部追加 `.with_precompile_registry(...)`

#### 4.3 `poker_l1/src/vm/contracts/mod.rs`

在 line 39 之后新增：
```rust
pub mod texas_poker;
pub use texas_poker::TexasPokerPrecompile;
```

#### 4.4 `Cargo.toml` features 配置

**顶层 `Cargo.toml`**（在 `[dependencies]` 之后）：
```toml
[features]
default = []
client = ["poker_l1/client"]
```

**`poker_l1/Cargo.toml`**（在 `[features]` 段）：
```toml
[features]
test-helpers = []
client = ["rand"]
```
（rand 已是 workspace 依赖，poker_l1 已有 `rand = { workspace = true }`，但需要确保 `client` feature 启用时 rand 仍可用；若 rand 是非 optional 依赖则无需在 feature 里重复声明——需验证 poker_l1 当前是否已无条件依赖 rand。若已无条件依赖，则 `client = []` 即可，因为 rand 已可用。）

---

### 阶段 5：CLI 客户端

#### 5.1 `src/poker_demo.rs`（~800 行，新增）

**实现内容**：

```rust
//! zchain poker-demo — Texas Poker 端到端 CLI 客户端
use poker_l1::{Address, Hash};
use poker_l1::transaction::{Transaction, TxLane, Gas};
use poker_l1::signature::{TaggedPubkey, CURRENT_VERSION, SignatureScheme};
use poker_l1::vm::contracts::texas_poker::crypto::*;
use poker_l1::vm::precompile::reserved::texas_poker_contract_id;
use secp256k1::SecretKey;
use std::net::TcpStream;

pub struct PokerRpcClient { stream: TcpStream }
impl PokerRpcClient {
    pub fn connect(addr: &str) -> Result<Self, String>
    pub fn submit_tx(&mut self, tx: &Transaction) -> Result<Hash, String>
    pub fn get_object(&mut self, id: &ObjectID) -> Result<Option<Object>, String>
    pub fn get_block_by_height(&mut self, h: BlockHeight) -> Result<Option<Block>, String>
    pub fn chain_head(&mut self) -> Result<BlockHeight, String>
}

pub fn build_signed_tx(
    tagged_pubkey: &TaggedPubkey,
    secret_key: &SecretKey,
    chain_id: ChainId,
    method_name: &str,
    args_bcs: Vec<u8>,
    lane: TxLane,
    nonce: u64,
    gameturn_nonce: Option<u64>,
) -> Transaction

pub fn run_poker_demo(args: &[String]) -> Result<(), String> {
    // 1. 解析 --nodes <rpc_url>（默认 127.0.0.1:8545） --players <N>（默认 2）
    // 2. 每个玩家生成 secp256k1 sk + BLS sk
    // 3. 等待节点 height >= 1
    // 4. Player0 调用 texas_create_table
    // 5. 轮流 texas_join_and_shuffle（链下计算 pk/remask/shuffle proof）
    // 6. texas_start_hand
    // 7. 轮询 shuffle_state.current_shuffler，当前 shuffler 链下 prove + texas_submit_shuffle_v2
    // 8. preflop reveal：每个玩家为对手手牌计算 reveal_token + proof，批量 texas_submit_player_reveal_tokens
    // 9. 下注：根据手牌强度简单策略（preflop pair+ call 否则 fold；postflop best_hand 评估）
    // 10. FLOP/TURN/RIVER：每轮公共牌 reveal + 下注
    // 11. SHOWDOWN：提交 reveal token 解密手牌，结算
    // 12. 查询 table summary，打印最终筹码
}
```

**RPC 协议**：newline-delimited JSON-RPC 2.0 over TCP（参考 main.rs:88 的 test-e2e 子命令构造 tx 流程，main.rs:1333-1556）。

**玩家策略（最简）**：
- preflop：pair 以上 call，否则 fold（单人对局时 check）
- postflop：`best_hand(2 hole + community)`，三张以上 call，否则 check/fold

#### 5.2 `src/main.rs`（新增子命令分支）

在 line 75 的 `match subcommand` 增加分支：
```rust
"poker-demo" => {
    if let Err(e) = run_poker_demo(rest) {
        error!("poker-demo 失败：{e}");
        std::process::exit(1);
    }
}
```

并在文件顶部 `mod poker_demo;` + `use poker_demo::run_poker_demo;`，`print_usage()` 增加帮助文本。

---

### 阶段 6：编译 + 部署

#### 6.1 本地编译验证

```bash
cd /Users/mac/projects/zchain
cargo check --workspace --features client
cargo test -p poker_l1 texas_poker:: --features client
```

#### 6.2 交叉编译

```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu --features client --bin zchain
# 输出 target/x86_64-unknown-linux-gnu/release/zchain
```

#### 6.3 安装 sshpass

```bash
brew install hudochenkov/sshpass/sshpass
```

#### 6.4 上传 + 启动节点

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

**前置条件**（需通过 SSH 验证）：
- 服务器 `zchain` 用户存在，家目录 `/home/zchain/`
- `validator.key` 文件已存在（若不存在，先 `zchain keygen` 生成并上传）
- 服务器是 Linux x86_64（与交叉编译 target 匹配）
- 防火墙开放 8545（RPC）+ 9000（P2P）端口

#### 6.5 部署合约

由于 TexasPokerPrecompile 是**原生预编译**（编译进二进制），部署合约 = 启动新二进制即可。**无需单独部署步骤**——节点启动后 `texas_poker_contract_id()` 立即可用。

只需通过 `texas_create_table` tx 初始化桌台对象（写入 ObjectDb）。

---

### 阶段 7：跑一局完整牌局

#### 7.1 本地连接服务器跑牌局

```bash
./target/x86_64-unknown-linux-gnu/release/zchain poker-demo \
    --nodes <server_ip>:8545 --players 2
```

> 注：本地 macOS 也可编译一个本地版用于跑 CLI：
> ```bash
> cargo build --release --features client --bin zchain
> ./target/release/zchain poker-demo --nodes <server_ip>:8545 --players 2
> ```

#### 7.2 验证完整流程

CLI 输出应依次出现：
1. `✓ 已连接节点 <server>，当前高度 N`
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

2. **服务器环境**：假设 `ssh zchain` 已配置 `~/.ssh/config`（用户已确认可用）。若服务器无 `/home/zchain/` 目录，将二进制放 `/tmp/zchain/` 并在 SSH 命令中相应调整路径。

3. **validator.key**：若服务器无此文件，先用 `zchain keygen --scheme secp256k1` 生成并上传。

4. **Move 端 transcript label**：需逐字节对照 Move 源（`bls_transcript.move`）确保 Rust 端 label 完全一致，否则 ZK verify 失败。计划阶段已识别此风险，实施时用单测硬编码 Move golden vector 交叉验证。

5. **with_precompile_registry 性能**：每次 verify_block 调用 `(*arc).clone()` 复制整个 `BTreeMap`。首版可接受（单 validator 场景 block 间隔 1s，map 仅 2-3 个 entry）。后续优化为 `Arc<PrecompileRegistry>` 直接 clone（需 executor.rs 同步修改 `with_precompile_registry` 签名）。

### 设计决策

1. **zk_skip_enabled 默认 true**（dev chain）：首版启用 `TableConfig { zk_skip_enabled: true }`，让链上 verify 直接返回 true，先用链下 prove 跑通流程。**mainnet 强制 false**（mainnet 启动时 assert）。这降低首版风险——若某个 ZK verifier 实现有 bug，dev chain 仍能跑通；逐步关闭 skip 实现严格验证。

2. **CLI 用本地编译版本**：服务器版（linux x86_64）只跑节点；CLI 客户端用本地 macOS 编译版本连接服务器 RPC。避免在服务器上跑 CLI（减少服务器依赖）。

3. **Phase 4 集成顺序**：先改 `precompile.rs`（加 reserved id）→ 再改 `node/mod.rs`（注册）→ 最后改 `contracts/mod.rs`（导出）。这样编译错误能逐层暴露，便于定位。

4. **不修改 executor.rs**：executor.rs 的 precompile 调用路径已实现完整（line 246-254），无需修改。只需在 node/mod.rs 注入 registry 即可。

---

## Verification Steps

### 阶段 1 验证
```bash
cargo test -p poker_l1 texas_poker::side_pot
cargo test -p poker_l1 texas_poker::events
cargo test -p poker_l1 texas_poker::types
```

### 阶段 2 验证
```bash
cargo test -p poker_l1 texas_poker::crypto::bls_scalar --features client
cargo test -p poker_l1 texas_poker::crypto::bls_elgamal --features client
cargo test -p poker_l1 texas_poker::crypto::transcript --features client
cargo test -p poker_l1 texas_poker::crypto::shuffle_proof --features client
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
# 交叉编译通过，输出 target/x86_64-unknown-linux-gnu/release/zchain

sshpass -p '123456Ab!' ssh zchain 'tail -50 /home/zchain/node.log'
# 应看到 "JSON-RPC server 监听 0.0.0.0:8545" + validator 产块日志
```

### 阶段 7 验证
```bash
./target/release/zchain poker-demo --nodes <server>:8545 --players 2
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
| 服务器无 /home/zchain 目录 | 低 | SSH 验证后调整路径 |
| 服务器防火墙阻断 8545 | 低 | SSH 验证后开放端口 |
| sshpass brew 安装失败 | 低 | 改用 expect 脚本或手动 ssh |

### 终极回退

若完整 Mental Poker 移植在阶段 7 前发现重大问题，启用 `zk_skip_enabled=true` + `zk_skip_shuffle=true` + `zk_skip_reveal=true` 三个开关全部跳过 ZK 验证，让链上仅做"信任玩家提交"的简化流程跑通一局牌局。这能保证用户 goal 4（完成牌局）至少在简化模式下达成，再逐步关闭 skip 实现严格模式。

---

## 实施顺序（推荐 TodoList）

1. 阶段 1.4：`side_pot.rs`
2. 阶段 1.5：`events.rs`
3. 阶段 1.6：`types.rs`
4. 阶段 1.7：`mod.rs`（仅声明模块，Precompile impl 等 3.3 再补）
5. 阶段 2.1-2.3：bls_scalar + bls_elgamal + transcript（基础密码学）
6. 阶段 2.4-2.5：schnorr + chaum_pedersen（基础 proof）
7. 阶段 2.6：shuffle_proof（核心）
8. 阶段 2.7-2.8：remask/reveal_token/reconstruct/leave
9. 阶段 2.9：serialization + zk_verifier
10. 阶段 3.1：state_machine
11. 阶段 3.2：dispatch
12. 阶段 3.3：mod.rs 补 TexasPokerPrecompile impl
13. 阶段 4.1-4.4：集成 wire-up（4 处修改）
14. 阶段 5.1-5.2：CLI 客户端
15. 阶段 6.1-6.3：本地编译 + 交叉编译 + sshpass
16. 阶段 6.4-6.5：上传 + 启动节点 + 部署
17. 阶段 7：跑牌局验证
