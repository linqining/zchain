# zkvm 完整一手牌 — 执行计划（Phase B-E）

## Summary

承接上一会话已批准的总体计划（[zkvm_full_hand_lifecycle.md](file:///Users/mac/projects/zchain/.trae/documents/zkvm_full_hand_lifecycle.md)）与细化计划（[zkvm_full_hand_implementation_continued.md](file:///Users/mac/projects/zchain/.trae/documents/zkvm_full_hand_implementation_continued.md)），Phase A 脚手架已完成。本计划基于对源码的二次验证（修正若干 API 误用），提供执行级别的 Phase B-E 实施步骤。

**目标**：在 zkvm 中完成完整一手牌（链上桌子 → sigma 协议本地编排 → RV32I 牌型评估+比较），全程记录耗时日志以评估 zkvm 性能。

**用户决策（已批准，无需再问）**：
1. 曲线分工：BLS12-381（业务/sigma）+ BN254（zkvm 电路）
2. sigma 协议范围：5 个全跑（ShuffleProof + RevealTokenAndProof + ReconstructProof + RemaskProof + LeaveProof）
3. 牌序映射：解密查表（sigma 解密 → 与 52 个 `hash_to_g1("texas_poker/card/{i}")` 比对 → rank = (i % 13) + 2）
4. sigma 是 host 端 Rust 调用（不进 RV32I 电路，不写成电路）；prove 由本地 poker_protocol 生成，zkvm 仅 verify
5. 链上仅作牌序权威源（0..52 索引序），本地用 `generate_plaintext_cards()` 重建等价 BLS12-381 密文

## Current State Analysis

### Phase A 已完成（验证通过）
- [Cargo.toml](file:///Users/mac/projects/zchain/Cargo.toml) line 13-31：已加 `poker_protocol`/`poker_zkvm`/`blstrs`/`group`/`ark-bn254`/`ark-ff`/`ark-ec`/`ark-std` 依赖
- [src/main.rs](file:///Users/mac/projects/zchain/src/main.rs)：已注册 `poker-zkvm-demo` 子命令 + 条件 tracing init
- [src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs) 388 行骨架：
  - `PerfSummary` / `SigmaStageTimings`（3 对字段，待扩 remask/leave）/ `Rv32iStageTimings`（9 字段已全）
  - `perf_summary()` OnceLock 单例、`chrono_now_iso8601()`、`init_tracing_with_file()` 双写、`write_perf_summary()` JSON 追加
  - `run_full_hand()` 编排 D→C→B
  - 3 个 stub：`create_onchain_table_and_extract_cards`（Err）/`run_shuffle_protocol`（Ok）/`run_rv32i_eval_and_compare`（Ok(1)）

### 现有可用资产（已读取源码确认）

#### poker_zkvm RV32I 编码器（[test_helpers.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/test_helpers.rs) 361 行）
- 全部 `pub`：`add/addi/sub/slt/sw/sb/lw/lb/bne/beq/lui/jal/ecall/nop/encode_text/build_elf32`
- 已通过 `test-helpers` feature 暴露给 zchain bin
- **待新增 4 个 pub 函数**：`build_poker_hand_eval_v2_elf` / `build_poker_hand_compare_elf` / `poker_hand_eval_v2_expected` / `poker_hand_compare_expected`

#### poker_zkvm prove/verify API
- [prover/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs)：`prove(&elf, cards: &[u8], &config) -> (Vec<u8>, ZkPublicIo)` + `ProverConfig` + `MAX_PROOF_TOTAL_SIZE` + `default_ccs_registry()`
- [verifier.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs)：`verify_production(&proof_bytes, &public_io, &ccs_registry) -> Result<bool, ZkvmError>`

#### poker_protocol sigma 协议（[zk_shuffle/](file:///Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/) 5 个 proof）
**关键修正**：所有 sigma proof 的 `Scalar::from_u64(x)` 而非 `Scalar::from(x)`（来自 `CurveScalar` trait，[curve.rs:185](file:///Users/mac/projects/zgame/poker_protocol/src/crypto/curve.rs#L185)）

| Proof | API 关键点 |
|-------|-----------|
| `ZKShuffleProof<C>` | `prove(&input_cts, &output_cts, &permute, &r_values, &pk, &mut rng, &mut transcript) -> Result<Self, VerificationError>`；`verify(&self, &input_cts, &output_cts, &pk, &mut transcript) -> bool` |
| `RevealTokenProof<C>` | `prove(&sk, &user_pk, &encrypted_card, &reveal_token, &mut rng, &mut transcript) -> Self`；`verify(&self, &encrypted_card, &reveal_token, &expected_pk, &mut transcript) -> bool` |
| `ReconstructProof<C>` | 先调 `reconstruct_deck(&cards, &user_readable, &sk, &pk, &coefficient) -> Result<(s_vec, output_cards, swap_out_cards), _>`（**coefficient ≠ 0 且 ≠ 1**）；再 `prove(cards, user_readable, output_cards, swap_out_cards, &sk, &pk, s_vec, &mut transcript) -> Result<Self, _>`；`verify(&self, &cards, &output_cards, &swap_out_cards, &user_readable, &pk, &mut transcript) -> bool` |
| `RemaskProof<C> = DLEqProof<C, RemaskKind>` | `remask_ciphertext(&ct, &sk, &pk, &mut rng) -> Result<ElGamalCiphertextGeneric<C>, _>`（**实现：c2 += c1*sk，c1 不变**；c1=identity 时返回 Err）；`prove(&input_cts, &output_cts, &sk, &pk, &mut transcript) -> Self`；`verify(&self, &input_cts, &output_cts, &pk, &mut transcript) -> bool` |
| `LeaveProof<C> = DLEqProof<C, LeaveKind>` | `leave_ciphertext(&ct, &sk, &pk, &mut rng) -> Result<...>`（**实现：c2 -= c1*sk**）；`prove/verify` 签名同 RemaskProof |

#### Curve/Transcript 类型
- `DefaultCurve = Bls12381Curve`（[crypto/types.rs:12](file:///Users/mac/projects/zgame/poker_protocol/src/crypto/types.rs#L12)），`type Point = blstrs::G1Projective`，`type Scalar = blstrs::Scalar`
- `ElGamalCiphertext = ElGamalCiphertextGeneric<DefaultCurve>`（字段 `c1: G1Projective, c2: G1Projective`）
- `Curve::base_g() -> Self::Point`、`Curve::base_h() -> Self::Point`、`Curve::hash_to_scalar(&[u8]) -> Self::Scalar`
- `CurveScalar::from_u64(u64)`、`CurveScalar::random(&mut rng)`、`CurveScalar::zero()/one()`
- `MerlinTranscript::new(b"label")`、`CryptoTranscript` trait

#### 链上数据源
- [poker_l1/utils.rs:221](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs#L221)：`pub fn generate_plaintext_cards() -> Vec<G1Projective>` 用 `hash_to_g1("texas_poker/card/{i}")` 生成 52 张明文牌点
- `set_initial_encrypted_deck()`：c1=G, c2=plaintext_cards[i]（与本地重建等价）
- [poker_rpc_demo.rs](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs)：8 个 RPC helper（line 293/336/365/403/430/437/461/477），全部为私有 `fn`，需改 `pub(crate)`
- `texas_poker_contract_id()`：返回 `ObjectID`（`[u8; 32]`）
- `TexasPokerTable.deck_state.encrypted: Vec<ElGamalCiphertext>`，`shuffle_state.phase == 3` 表示 start_hand 成功

## Proposed Changes

### Phase B: RV32I 牌型评估 v2 + 比较 ELF（BN254 zkvm 电路）

#### B.1 扩展 [poker_zkvm/src/test_helpers.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/test_helpers.rs)

在文件末尾（line 361 之后，`mod tests` 之前或之后均可，建议放在 `build_nop_elf` 之后 line 251）新增 4 个 `pub` 函数：

**函数 1：`build_poker_hand_eval_v2_elf() -> Vec<u8>`**

5 字节 rank 输入 → 4 字节 u32 评分输出。

寄存器分配：
- `x20 = 0x2000`（输入缓冲区基址，`LUI x20, 0x2`）
- `x1-x5` = 5 张牌的 rank
- `x6` = pair_count、`x7` = category、`x8` = max、`x9` = min
- `x13, x14, x15` = 临时寄存器
- `x10/x11/x17` = syscall 参数（a0/a1/a7）

评分格式（小端 u32）：`[category:8][max_rank:8][0:8][0:8]`，category: 5=straight, 4=trips, 2=pair, 0=highcard

RV32I 程序：
1. `LUI x20, 0x2` + read_input(0x2000, 5)
2. `LB x1..x5, 0..4(x20)` 加载 5 张牌
3. 初始化 `pair_count=0`、`max=card[0]`、`min=card[0]`
4. 展开双重循环 C(5,2)=10 对比较（不使用 loop，全部 inline）：
   - 若 `cards[i]==cards[j]` → `pair_count += 1`（用 `SUB x13, xi, xj` + `BEQ x13, x0, +8` + `ADDI x6, x6, 1`）
   - 若 `cards[i]>max` → `max=cards[i]`（用 `SLT x14, max, xi` + `BNE x14, x0, +8` + `ADDI x8, xi, 0`）
   - 若 `cards[i]<min` → `min=cards[i]`（用 `SLT x15, xi, min` + `BNE x15, x0, +8` + `ADDI x9, xi, 0`）
5. 推断 category：默认 0；`pair_count >= 1` → 2；`pair_count >= 3` → 4
6. 检测 straight：`pair_count == 0 && (max - min) == 4` → category = 5
7. 输出 `category | (max << 8)` 到 addr 0（`SB x7, 0(x0)` + `SB x8, 1(x0)` + `SB x0, 2(x0)` + `SB x0, 3(x0)`）
8. `commit_output(0, 4)`

步数估算：~80-100 步（10 对比较 × ~6 步 + setup/output ~20 步）。

**函数 2：`build_poker_hand_compare_elf() -> Vec<u8>`**

8 字节输入（两个 u32 评分）→ 1 字节赢家输出。

算法：`SLT x3, x1, x2`（s1<s2?）+ `SLT x4, x2, x1`（s2<s1?）+ `BNE x4, x0, winner=1` + `BNE x3, x0, winner=2` + 默认 winner=0 + `SB x5, 0(x0)` + `commit_output(0, 1)`。步数 ~18-22。

**函数 3：`poker_hand_eval_v2_expected(cards: &[u8; 5]) -> u32`**

host 参考实现（与 RV32I 算法严格一致）：
```rust
pub fn poker_hand_eval_v2_expected(cards: &[u8; 5]) -> u32 {
    let mut pair_count = 0u32;
    for i in 0..5 {
        for j in (i + 1)..5 {
            if cards[i] == cards[j] { pair_count += 1; }
        }
    }
    let mut category: u8 = 0;
    if pair_count >= 3 { category = 4; }
    else if pair_count >= 1 { category = 2; }
    let max = *cards.iter().max().unwrap();
    let min = *cards.iter().min().unwrap();
    if pair_count == 0 && (max - min) == 4 { category = 5; }
    (category as u32) | ((max as u32) << 8)
}
```

**函数 4：`poker_hand_compare_expected(s1: u32, s2: u32) -> u8`**
```rust
pub fn poker_hand_compare_expected(s1: u32, s2: u32) -> u8 {
    if s1 > s2 { 1 } else if s2 > s1 { 2 } else { 0 }
}
```

#### B.2 修改 [poker_zkvm/tests/common/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/common/mod.rs)

- 修改 line 11 import，增加 `bne, jal, lb, lw, sb, slt, sub`（部分已有）
- 在文件末尾 re-export：`pub use poker_zkvm::test_helpers::{build_poker_hand_eval_v2_elf, build_poker_hand_compare_elf, poker_hand_eval_v2_expected, poker_hand_compare_expected};`

#### B.3 新建 [poker_zkvm/tests/e2e_poker_hand_compare.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/e2e_poker_hand_compare.rs)

9 个测试用例（4 eval + 3 compare + 2 full_pipeline），完整代码见原计划 [zkvm_full_hand_implementation_continued.md](file:///Users/mac/projects/zchain/.trae/documents/zkvm_full_hand_implementation_continued.md) Phase B.2（line 180-290）。

测试矩阵：
- `eval_v2_straight`：[2,3,4,5,6] → 0x0605
- `eval_v2_trips`：[10,10,10,7,8] → 0x0A04
- `eval_v2_pair`：[5,5,9,7,8] → 0x0902
- `eval_v2_highcard`：[2,5,9,11,7] → 0x0B00
- `compare_p1_wins`：0x0605 vs 0x0A04 → 1
- `compare_p2_wins`：0x0A04 vs 0x0605 → 2
- `compare_tie`：0x0605 vs 0x0605 → 0
- `full_pipeline_straight_vs_trips`：P1=[2,3,4,5,6] vs P2=[10,10,10,7,8] → 1
- `full_pipeline_quads_simplified_vs_straight`：P1=[5,5,5,5,7] vs P2=[2,3,4,5,6] → 2

#### B.4 验证
```bash
cargo test -p poker_zkvm --test e2e_poker_hand_compare -- --nocapture
# 期望：9 个测试全过
```

---

### Phase C: sigma 协议本地编排（5 个 proof，BLS12-381）

#### C.1 扩展 [src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs)

**修改 SigmaStageTimings**（line 72-86）增加 remask/leave 字段：
```rust
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct SigmaStageTimings {
    pub shuffle_prove_ms: f64, pub shuffle_verify_ms: f64,
    pub reveal_prove_ms: f64, pub reveal_verify_ms: f64,
    pub reconstruct_prove_ms: f64, pub reconstruct_verify_ms: f64,
    pub remask_prove_ms: f64, pub remask_verify_ms: f64,
    pub leave_prove_ms: f64, pub leave_verify_ms: f64,
}
```

**新增 import**（文件顶部）：
```rust
use std::time::Instant;
use rand::rngs::OsRng;
use rand::Rng;
use poker_protocol::crypto::types::{DefaultCurve, ElGamalCiphertext};
use poker_protocol::crypto::curve::Curve;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::reconstruction::{reconstruct_deck, ReconstructProof};
use poker_protocol::zk_shuffle::remask_proof::{remask_ciphertext, RemaskProof};
use poker_protocol::zk_shuffle::leave_proof::{leave_ciphertext, LeaveProof};
use poker_l1::vm::contracts::texas_poker::utils::generate_plaintext_cards;
```

#### C.2 替换 `run_shuffle_protocol(card_seq)` 实现

签名改为 `fn run_shuffle_protocol(card_seq: &[u8]) -> Result<Vec<u8>, String>`（返回 P1+P2 共 10 字节牌序）。

实现要点：
1. **准备输入**：`let plaintext_cards = generate_plaintext_cards();`（52 张 BLS12-381 明文点，类型 `Vec<G1Projective>` = `Vec<<DefaultCurve as Curve>::Point>`）
2. **玩家密钥**：`player2_sk = <DefaultCurve as Curve>::Scalar::from_u64(1u64)`，`player2_pk = <DefaultCurve as Curve>::base_g() * player2_sk`
3. **构造 input_cts**（52 张）：`ElGamalCiphertext { c1: base_g(), c2: plaintext_cards[i] }`
4. **ZKShuffleProof**：随机 permute + 52 个 r_values → 计算 output_cts[i] = reencrypt(input_cts[permute[i]], r_values[i]) → `prove + verify + 测时`
   - reencrypt 公式：`output_ct.c1 = input.c1 + base_g() * r`，`output_ct.c2 = input.c2 + pk * r`
5. **RevealTokenProof**（取 output_cts[0]）：`reveal_token = ct.c1 * sk` → `prove + verify + 测时`
6. **ReconstructProof**（取 output_cts[0..2] 作 user_readable）：`coefficient = Scalar::from_u64(7u64)`（**≠0, ≠1**）→ 调 `reconstruct_deck` → `prove + verify + 测时`
7. **RemaskProof**（取 output_cts[0..5]）：每张调 `remask_ciphertext(ct, &sk, &pk, &mut rng)?` → `prove + verify + 测时`
8. **LeaveProof**（取 remask_output 作 leave_input）：每张调 `leave_ciphertext(ct, &sk, &pk, &mut rng)?` → `prove + verify + 测时`
9. **解密查表**（取 output_cts[0..5] 为 P1，output_cts[5..10] 为 P2）：
   - `pt = ct.c2 - ct.c1 * player2_sk`
   - 与 `plaintext_cards` 52 张逐一比对（`pt == known`，用 `PartialEq`）
   - 找到索引 i → `rank = (i % 13) as u8 + 2`
10. 累加 `SigmaStageTimings` 10 个字段到 `perf_summary()`
11. 返回 `[p1_cards, p2_cards].concat()`（10 字节）

**辅助函数**：
```rust
fn plaintext_to_rank(pt: &<DefaultCurve as Curve>::Point, table: &[<DefaultCurve as Curve>::Point]) -> u8 {
    for (i, known) in table.iter().enumerate() {
        if pt == known { return (i % 13) as u8 + 2; }
    }
    panic!("解密出的明文点不在 52 张已知牌中");
}
```

#### C.3 替换 `run_rv32i_eval_and_compare(p1, p2)` 实现

签名改为 `fn run_rv32i_eval_and_compare(p1: &[u8; 5], p2: &[u8; 5]) -> Result<u8, String>`。

实现要点：
1. P1 评估：`build_poker_hand_eval_v2_elf()` + `prove(&elf, p1, &config)` + `verify_production` + 测时 + 提取 score1
2. P2 评估：同上 → score2
3. 比较：`build_poker_hand_compare_elf()` + 输入 `[s1.le, s2.le]` 8 字节 + `prove + verify_production` + 测时 + 提取 winner
4. 累加 `Rv32iStageTimings` 9 个字段（含 proof_size_bytes）
5. 返回 winner

#### C.4 修改 `run_full_hand` 调用链（line 314-336）

```rust
let cards_bytes = run_shuffle_protocol(&card_seq)?;
let p1_cards: [u8; 5] = cards_bytes[0..5].try_into().unwrap();
let p2_cards: [u8; 5] = cards_bytes[5..10].try_into().unwrap();
let winner = run_rv32i_eval_and_compare(&p1_cards, &p2_cards)?;
```

#### C.5 验证（本地模式）
```bash
cargo check -p zchain
cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log
# 期望：5 个 sigma + 3 个 rv32i 全部 ok=true + JSON 摘要
```

---

### Phase D: 链上 RPC 集成（真实数据源）

#### D.1 修改 [src/poker_rpc_demo.rs](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs) — RPC helper 改 `pub(crate)`

8 个函数（line 293, 336, 365, 403, 430, 437, 461, 477）签名前缀由 `fn` 改为 `pub(crate) fn`：
- `build_signed_tx` / `submit_tx_via_rpc` / `wait_for_block_with_tx` / `query_block_by_height`
- `query_chain_id` / `query_table_state` / `verify_table_state` / `rpc_call`

#### D.2 替换 `create_onchain_table_and_extract_cards(rpc_listen, deck_size)` 实现

返回 `Vec<u8>`（52 张牌的索引序 0..52）。

实现流程（参考 [poker_rpc_demo.rs:88-237](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs#L88)）：
1. 生成 secp256k1 keypair + tagged_pubkey
2. `chain_id = query_chain_id(rpc_listen)?`（或用 `poker_l1::DEFAULT_CHAIN_ID`）
3. **Step 1 create_table**：`CreateTableArgs { name: "zkvm_demo_table", max_players: 2, small_blind: 5, big_blind: 10 }` → `build_signed_tx` → `submit_tx_via_rpc` → `wait_for_block_with_tx`
4. **Step 2a join_table P1**：`JoinTableArgs { player: [0x11;20], buy_in: 1000, pk: ECPoint(G1Projective::identity()) }`
5. **Step 2b join_table P2**：`JoinTableArgs { player: [0x22;20], buy_in: 1000, pk: ECPoint(G1Projective::generator()) }`
6. **Step 3 start_hand**：空 args
7. **校验状态**：`query_table_state` 返回的 `t.shuffle_state.phase == 3` 且 `t.deck_state.encrypted.len() == 52`
8. **提取牌序**：链上仅作权威源，返回 `(0..52u8).collect()`（本地 sigma 用 `generate_plaintext_cards()` 重建等价密文）
9. 累加 `PerfSummary.onchain_table_id` / `onchain_tx_count` / `onchain_final_block`

#### D.3 验证（链上模式）
```bash
# 前置：本地 8545 端口有 zchain 节点运行
cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log
# 期望：4 笔链上 tx + 5 sigma + 3 rv32i + JSON 摘要
```

---

### Phase E: 性能日志格式（贯穿 B/C/D）

#### E.1 tracing 日志格式标准化

每步 tracing 输出统一格式（便于 grep 解析）：
```
INFO stage=shuffle     phase=prove   ms=123.4
INFO stage=shuffle     phase=verify  ms=5.6   ok=true
INFO stage=reveal      phase=prove   ms=7.8
... (5 sigma × 2 = 10 行)
INFO stage=rv32i_eval_p1  phase=prove   ms=456.7  proof_size=12345
INFO stage=rv32i_eval_p1  phase=verify  ms=23.4   ok=true
... (3 rv32i × 2 = 6 行)
```

#### E.2 JSON 摘要最终格式

`PerfSummary` 已包含全部字段（Phase C.1 扩展后）：
```json
{
  "timestamp": "2026-07-19T...",
  "mode": "onchain",
  "rpc_endpoint": "127.0.0.1:8545",
  "curve_adaptation": "BLS12-381 (business) + BN254 (zkvm circuit)",
  "onchain_table_id": "0xFF..02",
  "onchain_tx_count": 4,
  "onchain_final_block": 9,
  "sigma_stage": { "shuffle_prove_ms":..., "shuffle_verify_ms":..., "reveal_":..., "reconstruct_":..., "remask_":..., "leave_":... },
  "rv32i_stage": { "eval_p1_prove_ms":..., "eval_p1_verify_ms":..., "eval_p1_proof_size_bytes":..., "eval_p2_":..., "compare_":... },
  "total_time_ms": 1400.5,
  "winner": 1
}
```

#### E.3 验证
```bash
test -s /tmp/zkvm_poker_perf_local.log && echo "log non-empty"
grep -c 'ok=true' /tmp/zkvm_poker_perf_local.log  # ≥ 8（5 sigma + 3 rv32i）
tail -1 /tmp/zkvm_poker_perf_local.log | jq . >/dev/null && echo "JSON valid"
```

## Assumptions & Decisions

### Assumptions
1. **poker_protocol crate 可达**：通过 workspace `poker_protocol = { path = "../zgame/poker_protocol", features = ["borsh"] }` 引用（zchain/Cargo.toml line 13 + workspace line 35）
2. **`generate_plaintext_cards()` 是 pub**：[utils.rs:221](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs#L221) 已确认 `pub fn`
3. **类型一致性**：`blstrs::G1Projective`（poker_l1 utils 返回类型）= `<DefaultCurve as Curve>::Point`（poker_protocol Bls12381Curve::Point），类型相同
4. **RV32I v2 评估步数 ≤ 1000**：~80-100 步，远低于 `MAX_FOLD_STEP_COUNT=1000`
5. **sigma verify 返回 bool**：5 个 proof 的 verify 都返回 `bool`，非 Result
6. **tracing 重复初始化**：main.rs 已加 `if subcommand != "poker-zkvm-demo"` 跳过全局 init

### Decisions
1. **ELF 函数暴露**：4 个新函数放在 [test_helpers.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/test_helpers.rs)（已 `pub`），bin 和 tests 共享单一来源
2. **链上数据集成边界**：链上仅返回索引序，本地用 `generate_plaintext_cards()` 重建（链上密文与本地等价，因 `set_initial_encrypted_deck` 用相同算法）
3. **sigma prove 是"客户端"职责**：本地用 poker_protocol prove 生成；zkvm 仅 verify（与"zkvm不需要prove"一致）。sigma 是 host 端 Rust 调用，非 RV32I 电路（与"verify也不需要写成电路"一致）
4. **Scalar 构造**：使用 `CurveScalar::from_u64(x)`（trait 方法），不使用 `Scalar::from(x)`（ff::Field 可能不存在）
5. **coefficient 选择**：`from_u64(7u64)`（≠0, ≠1，满足 `reconstruct_deck` 约束）

## Verification Steps

### Phase B 验证
```bash
cargo test -p poker_zkvm --test e2e_poker_hand_compare -- --nocapture
# 期望：9 个测试全过
```

### Phase C 验证（本地模式）
```bash
cargo check -p zchain
cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log
# 期望：5 sigma + 3 rv32i 全 ok=true + JSON 摘要
grep -c 'ok=true' /tmp/zkvm_poker_perf_local.log  # ≥ 8
```

### Phase D 验证（链上模式）
```bash
# 前置：zchain 节点在 127.0.0.1:8545 运行
cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log
# 期望：4 笔链上 tx 出块 + 5 sigma + 3 rv32i + JSON 摘要
```

### Phase E 验证
```bash
test -s /tmp/zkvm_poker_perf_local.log && echo "log non-empty"
tail -1 /tmp/zkvm_poker_perf_local.log | jq . >/dev/null && echo "JSON valid"
grep -c 'ok=true' /tmp/zkvm_poker_perf_local.log  # ≥ 8
```

## 实施顺序

```
Phase B.1 扩展 test_helpers.rs（4 个 pub 函数）
   ↓
Phase B.2 tests/common/mod.rs re-export + 修改 import
   ↓
Phase B.3 新建 e2e_poker_hand_compare.rs + cargo test
   ↓
Phase C.1 扩展 poker_zkvm_demo.rs：SigmaStageTimings 加 remask/leave
   ↓
Phase C.2 实现 run_shuffle_protocol（5 sigma + 解密查表）
   ↓
Phase C.3 实现 run_rv32i_eval_and_compare
   ↓
Phase C.4 修改 run_full_hand 调用链
   ↓
Phase C.5 cargo run --local-only 验证
   ↓
Phase D.1 poker_rpc_demo.rs 8 个 RPC helper 改 pub(crate)
   ↓
Phase D.2 实现 create_onchain_table_and_extract_cards
   ↓
Phase D.3 cargo run --rpc 验证（需节点）
   ↓
Phase E 日志格式整理 + JSON 摘要验证
```

## 风险点与回退

| 风险 | 应对 |
|------|------|
| RV32I v2 评估步数超 1000 | 回退到"仅 pair 检测"版本（~40 步），不检测 straight |
| sigma 协议 prove 失败 | 先检查 transcript label 是否匹配；poker_protocol tests 已验证 API 可用 |
| 链上 RPC 不可达 | `--local-only` 回退；RPC 超时 10s |
| 类型不兼容（G1Projective vs Curve::Point） | 实际类型相同（都是 `blstrs::G1Projective`），无需转换 |
| tracing 重复初始化 | main.rs 已条件判断跳过 |
| BLS12-381 点相等比较 | `pt == known` 用 `PartialEq`（blstrs 实现，常数时间） |
| `reconstruct_deck` 因 coefficient 无效报错 | 用 `from_u64(7u64)`（已验证 ≠0, ≠1） |
| `remask_ciphertext` 因 c1=identity 报错 | input_cts 的 c1