# 在 zkvm 完成完整一手牌 — 实施计划

## Context

用户目标：创建链上桌子（通过部署在服务器的 zchain 节点 RPC），本地启用 `poker_zkvm`，在 zkvm 中完成完整的一手牌，tracing + 文件输出记录耗时以评估 zkvm 性能。

用户已确认范围：

* **范围**：两者组合（最完整）— ZK 洗牌协议（precompiles）+ RV32I 牌型评估+比较

* **链上角色**：真实数据源 — 从链上 TexasPokerTable 提取真实加密牌作为 zkvm 输入

* **性能日志**：tracing + 文件输出

## 关键阻断性发现：BLS12-381 vs BN254 曲线不兼容

**物理事实**（已验证）：

* 链上 `poker_l1` 用 **BLS12-381**（`blstrs::G1Projective`），`generate_plaintext_cards()` 在 [utils.rs:221](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs#L221) 用 `hash_to_g1("texas_poker/card/{i}")` 生成牌面点

* 本地 `poker_zkvm` precompiles 用 **BN254**（`ark_bn254::G1Affine`），`card_to_point(card_id) = card_id · G` 在 [elgamal.rs:129](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/elgamal.rs#L129)

* 两条曲线群元素之间**不存在保群结构映射**，链上 BLS12-381 密文无法直接作为 `poker_zkvm` sigma 协议输入

**应对策略**（满足"链上真实数据源"约束）：

* 链上 RPC 真实调用：创建桌子、入座、start\_hand、查询 table state

* 链上数据作"牌序权威源"：确认 52 张牌存在、顺序、phase=3（BEFORE\_PREFLOP）

* 本地 改用`bls12381实现card加密，而不是bn254`

  <br />

## 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│  zchain poker-zkvm-demo 子命令（新建 src/poker_zkvm_demo.rs）│
├─────────────────────────────────────────────────────────────┤
│  Phase D: 链上 RPC 创建桌子（复用 poker_rpc_demo 模板）      │
│    create_table → join_table ×2 → start_hand                │
│    提取 52 张牌序 + PLAYER2 pk=generator                     │
├─────────────────────────────────────────────────────────────┤
│  Phase C: sigma 协议本地编排（host 端，BN254）               │
│    1. ZKShuffleProof: prove + verify + 测时                 │
│    2. RevealTokenAndProof: prove + verify + 测时            │
│    3. ReconstructProof: prove + verify + 测时               │
├─────────────────────────────────────────────────────────────┤
│  Phase B: RV32I zkvm 牌型评估+比较（真实 Hypernova proof）   │
│    1. build_poker_hand_eval_v2_elf ×2 (P1, P2)              │
│    2. build_poker_hand_compare_elf                          │
│    每步 prove + verify_production + 测时 + proof_size       │
├─────────────────────────────────────────────────────────────┤
│  Phase E: 性能日志（tracing + 文件 + JSON 摘要）             │
└─────────────────────────────────────────────────────────────┘
```

**关键语义区分**（防性能评估混淆）：

* `sigma_stage`：host 端 sigma 协议（Fiat-Shamir + Schnorr-like），不经过 RV32I/Hypernova

* `rv32i_stage`：真实 zkvm proof（`prover::prove` → `verifier::verify_production`，Hypernova 折叠）

* 两段分别测时、分别报告

## 文件清单

### 新建

* [`src/poker_zkvm_demo.rs`](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs) — 子命令编排入口（\~600 行）

* [`poker_zkvm/tests/e2e_poker_hand_compare.rs`](file:///Users/mac/projects/zchain/poker_zkvm/tests/e2e_poker_hand_compare.rs) — RV32I 牌型评估+比较 e2e 测试

### 修改

* [`Cargo.toml`](file:///Users/mac/projects/zchain/Cargo.toml) — zchain package 新增 `poker_zkvm`、`ark-bn254`、`ark-ff`、`ark-ec`、`ark-std`、`tracing-appender` 依赖

* [`src/main.rs`](file:///Users/mac/projects/zchain/src/main.rs) — 注册 `poker-zkvm-demo` 子命令

* [`poker_zkvm/tests/common/mod.rs`](file:///Users/mac/projects/zchain/poker_zkvm/tests/common/mod.rs) — 扩展 `build_poker_hand_eval_v2_elf()`、`build_poker_hand_compare_elf()`、`poker_hand_eval_v2_expected()`、`poker_hand_compare_expected()`

### 复用（不修改）

* [`src/poker_rpc_demo.rs`](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs) — 复用 `rpc_call`、`build_signed_tx`、`submit_tx_via_rpc`、`wait_for_block_with_tx`、`query_table_state`

* [`poker_zkvm/src/precompiles/`](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles) — 复用 `shuffle_proof::ZKShuffleProof`、`reveal_token::RevealTokenAndProof`、`reconstruction::ReconstructProof`、`elgamal::*`、`poker_transcript::PokerTranscript`

* [`poker_zkvm/src/prover/mod.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs) — 复用 `prove()`、`ProverConfig`、`MAX_PROOF_TOTAL_SIZE`

* [`poker_zkvm/src/verifier.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs) — 复用 `verify_production()`

* [`poker_zkvm/src/test_helpers.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/test_helpers.rs) — 复用 RV32I 编码器 `add/addi/beq/lb/sw/lui/ecall/nop/encode_text/build_elf32`

## RV32I 牌型评估+比较程序设计（简化版）

### 评估 ELF：输入 5 字节 rank，输出 4 字节 u32 评分

**寄存器分配**：x20=0x2000(输入缓冲区), x1-x5=5张牌, x6=pair\_count, x7=category, x8=tie1(max rank), x17=syscall\_num

**评分格式**（小端 u32）：`[tie3:8][tie2:8][tie1:8][category:8]`

* category: 5=straight, 4=trips, 2=pair, 0=highcard（简化版省略 two\_pair/quads/fullhouse/flush）

* tie1: max rank（2..=14）

**算法**：

1. `read_input(0x2000, 5)` 读 5 张牌
2. 遍历 C(5,2)=10 对统计 pair\_count
3. 推断 category：pair\_count>=3 → 4(trips), pair\_count>=1 → 2(pair), else 0
4. 求 max/min，若 max-min==4 且 pair\_count==0 → category=5(straight)
5. tie1 = max rank
6. 用 SB 逐字节写入 4 字节评分
7. `commit_output(0, 4)`

**步数估算**：80-100 步（远低于 `MAX_FOLD_STEP_COUNT=1000`，单 batch 完成）

### 比较 ELF：输入 8 字节（两个 u32 评分），输出 1 字节赢家

**算法**：

1. `read_input(0x2000, 8)`
2. `LW x1, 0(x20)` / `LW x2, 4(x20)` 加载两个 u32
3. `SLT x3, x1, x2` / `SLT x4, x2, x1` 比较
4. x4!=0 → 输出 1（P1 胜）；x3!=0 → 输出 2（P2 胜）；else 输出 0（平局）
5. `commit_output(0, 1)`

**步数估算**：18-22 步

### host 端参考实现

```rust
pub fn poker_hand_eval_v2_expected(cards: &[u8; 5]) -> u32 {
    let mut pair_count = 0u32;
    for i in 0..5 {
        for j in (i+1)..5 {
            if cards[i] == cards[j] { pair_count += 1; }
        }
    }
    let mut category: u8 = 0;
    if pair_count >= 3 { category = 4; }
    else if pair_count >= 1 { category = 2; }
    let max = *cards.iter().max().unwrap();
    let min = *cards.iter().min().unwrap();
    if max - min == 4 && pair_count == 0 { category = 5; }
    (category as u32) | ((max as u32) << 8)
}

pub fn poker_hand_compare_expected(s1: u32, s2: u32) -> u8 {
    if s1 > s2 { 1 } else if s2 > s1 { 2 } else { 0 }
}
```

## ZK 洗牌协议编排（sigma precompiles，BN381）

### Step 0: ZKShuffleProof，RevealTokenAndProof，ReconstructProof，RemaskProof,LeaveProof 预编译

 以上几个proof该用poker\_protocol协议改成预编译的形式，提供zkvm调用

### Step 1: ZKShuffleProof（洗牌证明）

* 输入：52 张 BN381 重建密文 `input_cts`（c=generator, d=card\_to\_point(i)）

* 本地生成随机排列 `permute` + 52 个 reencrypt 随机数 `r_values`

* 计算 `output_cts[i] = reencrypt(pk, input_cts[permute[i]], r_values[i])`

* zkvm不需要prove,prove是客户端提供的，zkvm负责验证，测试时使用poker\_protocol prove生成即可

* verify也不需要写成点路

* 验证 `proof.verify(&input_cts, &output_cts, &pk, &mut transcript_v)`

* 测时：`sigma_shuffle_prove_ms` / `sigma_shuffle_verify_ms`

### Step 2: RevealTokenAndProof（揭示令牌证明）

* 输入：PLAYER2 sk=Fr::from(1u64), pk=generator, 任选一张 output\_cts（如索引 0）

* 调用 `RevealTokenAndProof::prove(&sk, &pk, &ct, &mut transcript, &mut rng)`

* 验证 `reveal.verify(&ct, &pk, &mut transcript_v)`

* 测时：`sigma_reveal_prove_ms` / `sigma_reveal_verify_ms`

### Step 3: ReconstructProof（重构证明）

* 输入：52 张 BN254 card\_to\_point, PLAYER2 可读密文（取 2 张作为示例）, coefficient=Fr::from(7u64)

* 调用 `reconstruct_deck(&cards, &user_readable, &sk, &pk, &coefficient)` 得到 output\_cards + swap\_out\_cards + s\_vec

* 调用 `ReconstructProof::prove(...)`

* 验证 `proof.verify(...)`

* 测时：`sigma_reconstruct_prove_ms` / `sigma_reconstruct_verify_ms`

## 阶段分解与验证

### Phase A: 依赖与脚手架（独立验证）

* 修改 `Cargo.toml`：zchain package 新增依赖

  ```toml
  poker_zkvm = { workspace = true, features = ["test-helpers"] }
  ark-bn254 = { workspace = true }
  ark-ff = { workspace = true }
  ark-ec = { workspace = true }
  ark-std = { workspace = true }
  tracing-appender = "0.2"
  ```

* 修改 `src/main.rs`：注册 `poker-zkvm-demo` 子命令（先 stub `run` 函数）

* 新建 `src/poker_zkvm_demo.rs`：空骨架

* **验证**：`cargo check -p zchain` 通过；`cargo test --workspace` 仍 1608 通过

### Phase B: RV32I 牌型评估+比较 ELF（独立验证）

* 在 `poker_zkvm/tests/common/mod.rs` 扩展：

  * `build_poker_hand_eval_v2_elf() -> Vec<u8>` — 5 字节输入 → 4 字节 u32 评分

  * `build_poker_hand_compare_elf() -> Vec<u8>` — 8 字节输入 → 1 字节赢家

  * `poker_hand_eval_v2_expected(cards: &[u8;5]) -> u32` — host 参考实现

  * `poker_hand_compare_expected(s1: u32, s2: u32) -> u8`

* 新建 `poker_zkvm/tests/e2e_poker_hand_compare.rs`：

  * 测试 P1=\[2,3,4,5,6]（straight）vs P2=\[10,10,10,7,8]（trips）→ P1 胜

  * 测试 P1=\[5,5,5,5,7]（quads 简化为 trips）vs P2=\[2,3,4,5,6]（straight）→ P2 胜（straight > trips，简化版正确性）

  * 每步 `prove` + `verify_production` + 校验 output

* **验证**：`cargo test -p poker_zkvm --test e2e_poker_hand_compare` 通过

### Phase C: sigma 协议本地编排（独立验证）

* 在 `poker_zkvm_demo.rs` 实现：

  * `rebuild_bn254_deck(card_seq: &[u8]) -> Vec<ElGamalCiphertext>` — BN254 重建等价密文

  * `run_shuffle_protocol(deck, player2_sk) -> ShuffleStageResult` — sigma 三步编排 + 测时

* 子命令支持 `--local-only` flag：跳过链上 RPC，仅本地跑 sigma + RV32I

* tracing 输出每步耗时

* **验证**：`cargo run -p zchain -- poker-zkvm-demo --local-only` 输出 sigma + rv32i 各阶段耗时，所有 verify 返回 true

### Phase D: 链上 RPC 集成（真实数据源）

* 在 `poker_zkvm_demo.rs` 实现：

  * `create_onchain_table(rpc_listen) -> TexasPokerTable` — 复用 poker\_rpc\_demo 模板，create/join/start，等待 phase=3 + encrypted.len()==52

  * `extract_card_sequence(table) -> Vec<u8>` — 提取 52 张牌的索引序（0..51）

* 子命令默认模式（无 `--local-only`）：

  * RPC 创建桌子 → 提取牌序 → 本地 BN254 重建 → sigma + RV32I

* **验证**：`cargo run -p zchain -- poker-zkvm-demo --rpc 127.0.0.1:8545` 端到端跑通；日志含链上 tx hash + block height

### Phase E: 性能日志与摘要

* 实现 `init_tracing_with_file(log_path) -> WorkerGuard`：用 `tracing_subscriber::fmt().with_writer(NonBlocking)` 同时输出 stderr + 文件

* 实现 `write_perf_summary(log_path, summary)`：追加 JSON 摘要

* 子命令支持 `--log-file <path>`（默认 `/tmp/zkvm_poker_perf_<timestamp>.log`）

* **验证**：日志文件真实存在、非空；JSON 摘要可被 `jq` 解析；所有耗时字段 > 0

## 性能日志格式

### tracing 输出（每步）

```
INFO stage=shuffle phase=prove ms=123.4
INFO stage=shuffle phase=verify ms=5.6
INFO stage=reveal phase=prove ms=7.8
...
INFO stage=rv32i_eval_p1 phase=prove ms=456.7 proof_size=12345
INFO stage=rv32i_compare phase=verify ms=5.6 proof_size=5678
```

### JSON 摘要（日志末尾）

```json
{
  "timestamp": "2026-07-19T12:34:56Z",
  "mode": "onchain",
  "rpc_endpoint": "127.0.0.1:8545",
  "curve_adaptation": "BLS12-381 -> BN254",
  "onchain_table_id": "0xFF..02",
  "onchain_tx_count": 4,
  "onchain_final_block": 9,
  "sigma_stage": {
    "shuffle_prove_ms": 123.4, "shuffle_verify_ms": 5.6,
    "reveal_prove_ms": 7.8, "reveal_verify_ms": 0.9,
    "reconstruct_prove_ms": 234.5, "reconstruct_verify_ms": 12.3
  },
  "rv32i_stage": {
    "eval_p1_prove_ms": 456.7, "eval_p1_verify_ms": 23.4, "eval_p1_proof_size_bytes": 12345,
    "eval_p2_prove_ms": 456.7, "eval_p2_verify_ms": 23.4, "eval_p2_proof_size_bytes": 12345,
    "compare_prove_ms": 78.9, "compare_verify_ms": 5.6, "compare_proof_size_bytes": 5678
  },
  "total_time_ms": 1400.5,
  "winner": 1
}
```

## 子命令接口

```bash
# 本地模式（无链上 RPC，快速验证 zkvm 性能）
cargo run -p zchain --release -- poker-zkvm-demo \
  --local-only \
  --log-file /tmp/zkvm_poker_perf_local.log

# 链上模式（真实 RPC 数据源）
cargo run -p zchain --release -- poker-zkvm-demo \
  --rpc 127.0.0.1:8545 \
  --log-file /tmp/zkvm_poker_perf_onchain.log
```

**参数**：

* `--rpc <host:port>`：链上 RPC 端点（默认 `127.0.0.1:8545`）

* `--local-only`：跳过链上 RPC，仅本地 sigma + RV32I

* `--log-file <path>`：性能日志路径（默认 `/tmp/zkvm_poker_perf_<timestamp>.log`）

* `--deck-size <n>`：牌组大小（默认 52，调试时可减为 4）

## 风险点与回退

| 风险                                      | 应对                                                                                           |
| --------------------------------------- | -------------------------------------------------------------------------------------------- |
| BLS12-381 vs BN254 不兼容（物理事实）            | 链上作牌序权威源，本地 BN254 重建等价密文；日志透明记录                                                              |
| RV32I 步数超限（MAX\_FOLD\_STEP\_COUNT=1000） | 简化版预估 80-100 步；若超限回退到"仅 pair 检测"版本（\~40 步）                                                   |
| sigma 协议 vs zkvm proof 语义混淆             | 日志严格分 `sigma_stage` / `rv32i_stage` 两段                                                       |
| 链上 RPC 不可达                              | 支持 `--local-only` 回退；RPC 超时 10s                                                              |
| tracing-appender 依赖冲突                   | 备选：用 `std::fs::OpenOptions + tracing_subscriber::fmt::layer().with_writer(Mutex<File>)` 手动实现 |
| unsafe\_code 约束                         | 所有新代码不使用 unsafe；bin crate 不强制 deny                                                           |

## 验证清单

* [ ] Phase A: `cargo check -p zchain` 通过；`cargo test --workspace` 1608 通过

* [ ] Phase B: `cargo test -p poker_zkvm --test e2e_poker_hand_compare` 通过

* [ ] Phase C: `cargo run -p zchain -- poker-zkvm-demo --local-only` 输出各阶段耗时，所有 verify=true

* [ ] Phase D: `cargo run -p zchain -- poker-zkvm-demo --rpc 127.0.0.1:8545` 端到端跑通；日志含链上 tx hash + block height

* [ ] Phase E: 日志文件存在且非空；JSON 摘要可被 `jq` 解析；所有耗时字段 > 0

## 实施顺序与依赖

```
Phase A（脚手架，无依赖）
   ↓
Phase B（RV32I ELF，独立于链上）   ←─┐
   ↓                              │ 可并行
Phase C（sigma 协议，独立于链上）  ←─┘
   ↓
Phase D（链上 RPC 集成，依赖 A/B/C）
   ↓
Phase E（性能日志，贯穿 B/C/D，最后整理）
```

## Assumptions & Decisions

### Assumptions

1. 链上 zchain 节点（RPC `127.0.0.1:8545` 或服务器 `47.120.51.203:8545`）已部署并可用，阶段一已验证 RPC 路径通畅
2. `poker_zkvm` 的 `test-helpers` feature 提供 RV32I 编码器（`add/addi/beq/lb/sw/lui/ecall/nop/encode_text/build_elf32`），阶段一已验证可用
3. sigma precompiles（`ZKShuffleProof`/`RevealTokenAndProof`/`ReconstructProof`）的 prove/verify API 已在 `poker_zkvm/tests/poker_proofs_integration.rs` 中验证可用
4. workspace 已有 `ark-bn254`/`ark-ff`/`ark-ec`/`ark-std` 依赖声明（poker\_zkvm 使用，zchain 可 `{ workspace = true }` 复用）

### Decisions

1. **曲线适配策略**：本地 BN254 改用BLS12-381实现，一个原则，bn254 用于zkvm电路，BLS12-381用于业务逻辑 （物理事实阻断，不可绕过）；链上仅作"牌序权威源"，不传递群元素
2. **RV32I 简化范围**：评估只覆盖 pair/trips/straight/highcard（4 类），比较只比 u32 大小；省略 two\_pair/quads/fullhouse/flush（电路复杂度非线性增长）
3. **sigma vs rv32i 分段**：严格分 `sigma_stage`（host 端 Fiat-Shamir，不进 RV32I）和 `rv32i_stage`（真实 Hypernova proof），分别测时分别报告
4. **链上集成边界**：链上只跑 `create_table → join ×2 → start_hand`，sigma 三步和 RV32I 评估比较全部在本地执行
5. **日志实现**：`tracing_subscriber::fmt::layer().with_writer(NonBlocking)` 双写（stderr + 文件），不引入 `tracing-appender` 额外依赖（用 `tracing_subscriber` 自带能力）
6. **回退机制**：`--local-only` 跳过链上 RPC，仅跑本地 sigma + RV32I，用于快速验证 zkvm 性能

## 完整执行命令序列

```bash
# 1. Phase A 验证
cargo check -p zchain
cargo test --workspace 2>&1 | tail -5

# 2. Phase B 验证
cargo test -p poker_zkvm --test e2e_poker_hand_compare -- --nocapture

# 3. Phase C 验证（本地模式）
cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log

# 4. Phase D 验证（链上模式，需先在服务器启动 zchain 节点或本地 8545 转发）
cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log

# 5. Phase E 验证
test -s /tmp/zkvm_poker_perf_onchain.log && echo "log non-empty"
tail -1 /tmp/zkvm_poker_perf_onchain.log | jq . >/dev/null && echo "JSON valid"
```

