# zkvm 完整一手牌 — 继续实施计划（Phase B-E）

## Summary

承接 `zkvm_full_hand_lifecycle.md`（已批准的总体计划），Phase A 脚手架已完成（`Cargo.toml`、`src/main.rs`、`src/poker_zkvm_demo.rs` 388 行骨架）。本计划细化 Phase B-E 的具体实施步骤，基于用户最新澄清的 2 个决策点：

1. **sigma 协议范围**：5 个全跑（ShuffleProof + RevealTokenAndProof + ReconstructProof + RemaskProof + LeaveProof）
2. **链上牌到 RV32I 映射**：解密查表 — sigma RevealTokenAndProof 解密出 BLS12-381 明文点 → 与 `generate_plaintext_cards()` 52 个 `hash_to_g1("texas_poker/card/{i}")` 比对 → 找到 i → rank = (i % 13) + 2

## Current State Analysis

### 已完成（Phase A）
- [Cargo.toml](file:///Users/mac/projects/zchain/Cargo.toml) 已加 `poker_zkvm`、`ark-bn254`、`ark-ff`、`ark-ec`、`ark-std` 依赖（line 14, 28-31）
- [src/main.rs](file:///Users/mac/projects/zchain/src/main.rs) 已注册 `poker-zkvm-demo` 子命令（line 53, 75-82, 114-119, 147）
- [src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs) 已有 388 行骨架：
  - `PerfSummary` / `SigmaStageTimings` / `Rv32iStageTimings` 结构体（serde::Serialize）
  - `perf_summary()` 全局 OnceLock 单例
  - `chrono_now_iso8601()` ISO 8601 时间戳（不依赖 chrono）
  - `run(args)` 子命令入口，解析 `--rpc`/`--local-only`/`--log-file`/`--deck-size`
  - `init_tracing_with_file(log_path)` tracing 双写初始化（stderr + Mutex<File>）
  - `run_full_hand(local_only, rpc_listen, deck_size)` 编排 D→C→B
  - Phase D stub `create_onchain_table_and_extract_cards` 返回 Err
  - Phase C stub `run_shuffle_protocol` 打 log + Ok
  - Phase B stub `run_rv32i_eval_and_compare` 打 log + Ok(1)
  - `write_perf_summary(log_path)` JSON 摘要追加写入

### 现有可用资产（无需修改）

#### poker_protocol BLS12-381 sigma 协议（5 个 proof）
路径：`/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/`

| Proof | 路径 | prove/verify 签名 |
|-------|------|-------------------|
| `ZKShuffleProof<C>` | `shuffle_proof.rs:47` | `prove(input_cts, output_cts, permute, r_values, pk, rng, transcript)` / `verify(&self, input_cts, output_cts, pk, transcript)` |
| `RevealTokenAndProof<C>` | `reveal_token_proof.rs:50,72` | `RevealTokenProof::prove(sk, user_pk, encrypted_card, reveal_token, rng, transcript)` / `verify(&self, encrypted_card, reveal_token, expected_pk, transcript)` |
| `ReconstructProof<C>` | `reconstruction/mod.rs:135` | 需先调 `reconstruct_deck(cards, user_readable, user_sk, user_pk, coefficient) -> (s_vec, output_cards, swap_out_cards)`，再 `ReconstructProof::prove(cards, user_readable, output_cards, swap_out_cards, user_sk, user_pk, s_vec, transcript)` / `verify(&self, cards, output_cards, swap_out_cards, user_readable, user_pk, transcript)` |
| `RemaskProof<C> = DLEqProof<C, RemaskKind>` | `remask_proof.rs:7,9` | `remask_ciphertext(ct, sk, pk, rng)` 生成 output，`RemaskProof::prove(&input_cts, &output_cts, &sk, &pk, &mut transcript)` / `verify(&self, &input_cts, &output_cts, &pk, &mut transcript)` |
| `LeaveProof<C> = DLEqProof<C, LeaveKind>` | `leave_proof.rs:7,9` | `leave_ciphertext(ct, sk, pk, rng)` 生成 output，`LeaveProof::prove(&input_cts, &output_cts, &sk, &pk, &mut transcript)` / `verify(&self, &input_cts, &output_cts, &pk, &mut transcript)` |

关键类型（`poker_protocol::crypto::types`）：
- `DefaultCurve = Bls12381Curve`
- `ElGamalCiphertext = ElGamalCiphertextGeneric<DefaultCurve>`（含 `c1: G1Projective`, `c2: G1Projective`）
- `ECPoint(pub EcPoint)` — 链上 RPC 用的 Borsh 友好包装
- `ECScalar(pub Scalar)` — Borsh 友好的标量包装
- `BASE_G: EcPoint` lazy_static 全局生成元

Transcript：
- `poker_protocol::zk_shuffle::transcript_ext::CryptoTranscript` trait
- `MerlinTranscript::new(b"label")` 实现

#### 链上数据源（poker_l1）
- `TexasPokerTable.deck_state.encrypted: Vec<ElGamalCiphertext>` — 52 个 BLS12-381 密文
- 每个 `ElGamalCiphertext = { c1: G1Projective, c2: G1Projective }`
- 初始牌序：`generate_plaintext_cards()` 在 [utils.rs:221](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs#L221) 用 `hash_to_g1("texas_poker/card/{i}")` 生成 52 张明文牌点
- `set_initial_encrypted_deck()` 在 `state_machine.rs:217` 用 G 作 c1、明文点作 c2 构造 52 个密文
- `shuffle_state.phase = 3 (BEFORE_PREFLOP)` 表示 start_hand 已触发
- [poker_rpc_demo.rs](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs) 提供 `rpc_call`/`build_signed_tx`/`submit_tx_via_rpc`/`wait_for_block_with_tx`/`query_table_state`/`verify_table_state` 可复用模板

#### RV32I 编码器与 prove API（poker_zkvm）
- [test_helpers.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/test_helpers.rs) 提供：`add/addi/sub/slt/sw/sb/lw/lb/bne/beq/lui/jal/ecall/nop/encode_text/build_elf32`
- [prover/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs) 提供：`prove(&elf, cards, &config) -> (proof_bytes, public_io)` + `ProverConfig` + `MAX_PROOF_TOTAL_SIZE` + `default_ccs_registry()`
- [verifier.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs) 提供：`verify_production(&proof_bytes, &public_io, &ccs_registry) -> Result<bool, ZkvmError>`
- [common/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/common/mod.rs) 已有 `build_poker_hand_eval_elf()`（19 步求和）、`build_fibonacci_elf(n)`、`build_sha256_chain_elf(iters)`、`build_minimal_valid_elf()`

## Proposed Changes

### Phase B: RV32I 牌型评估 v2 + 比较 ELF（BN254 zkvm 电路）

#### B.1 扩展 [poker_zkvm/tests/common/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/common/mod.rs)

**新增 import**（line 11 修改）：
```rust
use poker_zkvm::test_helpers::{
    add, addi, beq, bne, build_elf32, ecall, encode_text, lb, lui, lw, nop, sb, slt, sub, sw,
};
```

**新增函数 1：`build_poker_hand_eval_v2_elf() -> Vec<u8>`**

5 字节 rank 输入 → 4 字节 u32 评分输出。

寄存器分配：
- `x20 = 0x2000`（输入缓冲区基址）
- `x1-x5` = 5 张牌的 rank
- `x6` = pair_count（累加器）
- `x7` = category（最终牌型分类）
- `x8` = max rank（用于 tie-break）
- `x9` = min rank（用于 straight 检测）
- `x10-x12` = syscall 参数 (a0, a1, a2)
- `x17` = syscall 编号 (a7)
- `x13, x14, x15` = 临时寄存器

评分格式（小端 u32）：`[category:8][max_rank:8][0:8][0:8]`
- category: 5=straight, 4=trips, 2=pair, 0=highcard
- max_rank: 牌中最大值（2..=14）

算法：
1. `LUI x20, 0x2` + `read_input(0x2000, 5)` 读取 5 张牌
2. `LB x1, 0(x20)` ... `LB x5, 4(x20)` 加载 5 张牌到寄存器
3. 初始化 `pair_count=0`、`max=card[0]`、`min=card[0]`
4. 双重循环展开 C(5,2)=10 对比较：
   - 若 `cards[i]==cards[j]` → `pair_count += 1`
   - 若 `cards[i]>max` → `max=cards[i]`
   - 若 `cards[i]<min` → `min=cards[i]`
5. 推断 category：
   - 默认 `category=0`（highcard）
   - 若 `pair_count >= 1` → `category=2`（pair）
   - 若 `pair_count >= 3` → `category=4`（trips，简化版含 quads/fullhouse）
6. 检测 straight：若 `pair_count == 0 && (max - min) == 4` → `category=5`
7. 输出：`category | (max << 8)`（u32 小端）
8. `commit_output(0, 4)`

步数估算：~80-100 步（10 对比较 × ~6 步/对 + setup/output ~20 步）。低于 `MAX_FOLD_STEP_COUNT=1000`，单 batch 完成。

**新增函数 2：`build_poker_hand_compare_elf() -> Vec<u8>`**

8 字节输入（两个 u32 评分）→ 1 字节赢家输出。

寄存器分配：
- `x20 = 0x2000`（输入缓冲区）
- `x1` = score1（P1 评分）
- `x2` = score2（P2 评分）
- `x3, x4` = 临时（SLT 结果）
- `x5` = winner（输出值）

算法：
1. `LUI x20, 0x2` + `read_input(0x2000, 8)`
2. `LW x1, 0(x20)` 加载 P1 评分
3. `LW x2, 4(x20)` 加载 P2 评分
4. `SLT x3, x1, x2` → x3 = (s1 < s2) ? 1 : 0
5. `SLT x4, x2, x1` → x4 = (s2 < s1) ? 1 : 0
6. `BNE x4, x0, +12` → 若 x4!=0（s1>s2），跳到 winner=1 分支
7. `BNE x3, x0, +12` → 若 x3!=0（s2>s1），跳到 winner=2 分支
8. 默认 `ADDI x5, x0, 0`（平局）
9. `JAL x0, +20` 跳过 winner=1/winner=2 分支
10. winner=1 分支：`ADDI x5, x0, 1`
11. winner=2 分支：`ADDI x5, x0, 2`
12. `SB x5, 0(x0)` 存储赢家到 addr 0
13. `commit_output(0, 1)`

步数估算：~18-22 步。

**新增函数 3：`poker_hand_eval_v2_expected(cards: &[u8; 5]) -> u32`**

host 端参考实现（与上述 RV32I 算法一致）：
```rust
pub fn poker_hand_eval_v2_expected(cards: &[u8; 5]) -> u32 {
    let mut pair_count = 0u32;
    for i in 0..5 {
        for j in (i + 1)..5 {
            if cards[i] == cards[j] {
                pair_count += 1;
            }
        }
    }
    let mut category: u8 = 0;
    if pair_count >= 3 {
        category = 4;
    } else if pair_count >= 1 {
        category = 2;
    }
    let max = *cards.iter().max().unwrap();
    let min = *cards.iter().min().unwrap();
    if pair_count == 0 && (max - min) == 4 {
        category = 5;
    }
    (category as u32) | ((max as u32) << 8)
}
```

**新增函数 4：`poker_hand_compare_expected(s1: u32, s2: u32) -> u8`**
```rust
pub fn poker_hand_compare_expected(s1: u32, s2: u32) -> u8 {
    if s1 > s2 { 1 } else if s2 > s1 { 2 } else { 0 }
}
```

#### B.2 新建 [poker_zkvm/tests/e2e_poker_hand_compare.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/e2e_poker_hand_compare.rs)

```rust
//! Phase B 端到端测试 — RV32I 牌型评估 v2 + 比较。
//!
//! 测试流程：
//! 1. build_poker_hand_eval_v2_elf ×2 (P1, P2) → prove → verify_production → 校验 output
//! 2. build_poker_hand_compare_elf → prove → verify_production → 校验 winner

mod common;

use common::{build_poker_hand_compare_elf, build_poker_hand_eval_v2_elf, poker_hand_compare_expected, poker_hand_eval_v2_expected};
use poker_zkvm::prover::{MAX_PROOF_TOTAL_SIZE, ProverConfig, default_ccs_registry, prove};
use poker_zkvm::verifier::verify_production;

fn poker_config() -> ProverConfig {
    ProverConfig { proof_size_limit: MAX_PROOF_TOTAL_SIZE, ..Default::default() }
}

fn run_eval_e2e(cards: &[u8; 5]) -> u32 {
    let elf = build_poker_hand_eval_v2_elf();
    let config = poker_config();
    let (proof_bytes, public_io) = prove(&elf, cards, &config).expect("prove 失败");
    let ccs = default_ccs_registry();
    let ok = verify_production(&proof_bytes, &public_io, &ccs).expect("verify 失败");
    assert!(ok, "verify_production 应返回 true");
    assert_eq!(public_io.output.len(), 4);
    let got = u32::from_le_bytes(public_io.output[..4].try_into().unwrap());
    let expected = poker_hand_eval_v2_expected(cards);
    assert_eq!(got, expected, "eval 不符: cards={cards:?}, got={got}, expected={expected}");
    got
}

fn run_compare_e2e(s1: u32, s2: u32) -> u8 {
    let input = {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&s1.to_le_bytes());
        buf.extend_from_slice(&s2.to_le_bytes());
        buf
    };
    let elf = build_poker_hand_compare_elf();
    let config = poker_config();
    let (proof_bytes, public_io) = prove(&elf, &input, &config).expect("prove 失败");
    let ccs = default_ccs_registry();
    let ok = verify_production(&proof_bytes, &public_io, &ccs).expect("verify 失败");
    assert!(ok);
    assert_eq!(public_io.output.len(), 1);
    let got = public_io.output[0];
    let expected = poker_hand_compare_expected(s1, s2);
    assert_eq!(got, expected, "compare 不符: s1={s1}, s2={s2}, got={got}, expected={expected}");
    got
}

#[test]
fn test_poker_hand_eval_v2_straight() {
    // 2,3,4,5,6 → straight (category=5, max=6) → score = 5 | (6<<8) = 0x0605
    assert_eq!(run_eval_e2e(&[2, 3, 4, 5, 6]), 0x0605);
}

#[test]
fn test_poker_hand_eval_v2_trips() {
    // 10,10,10,7,8 → pair_count=3 → trips (category=4, max=10) → score = 4 | (10<<8) = 0x0A04
    assert_eq!(run_eval_e2e(&[10, 10, 10, 7, 8]), 0x0A04);
}

#[test]
fn test_poker_hand_eval_v2_pair() {
    // 5,5,9,7,8 → pair_count=1 → pair (category=2, max=9) → score = 2 | (9<<8) = 0x0902
    assert_eq!(run_eval_e2e(&[5, 5, 9, 7, 8]), 0x0902);
}

#[test]
fn test_poker_hand_eval_v2_highcard() {
    // 2,5,9,11,7 → pair_count=0, max-min=9≠4 → highcard (category=0, max=11) → score = 0 | (11<<8) = 0x0B00
    assert_eq!(run_eval_e2e(&[2, 5, 9, 11, 7]), 0x0B00);
}

#[test]
fn test_poker_hand_compare_p1_wins() {
    // P1 straight (0x0605) vs P2 trips (0x0A04) → P1 胜 (0x0605 > 0x0A04)
    // 注意：straight category=5 > trips category=4，所以 0x0605 > 0x0A04（高字节 category 占优）
    assert_eq!(run_compare_e2e(0x0605, 0x0A04), 1);
}

#[test]
fn test_poker_hand_compare_p2_wins() {
    // P1 trips (0x0A04) vs P2 straight (0x0605) → P2 胜
    assert_eq!(run_compare_e2e(0x0A04, 0x0605), 2);
}

#[test]
fn test_poker_hand_compare_tie() {
    assert_eq!(run_compare_e2e(0x0605, 0x0605), 0);
}

#[test]
fn test_poker_hand_full_pipeline_straight_vs_trips() {
    // 完整管线：P1=[2,3,4,5,6] (straight) vs P2=[10,10,10,7,8] (trips) → P1 胜
    let s1 = run_eval_e2e(&[2, 3, 4, 5, 6]);
    let s2 = run_eval_e2e(&[10, 10, 10, 7, 8]);
    let winner = run_compare_e2e(s1, s2);
    assert_eq!(winner, 1, "straight 应胜 trips");
}

#[test]
fn test_poker_hand_full_pipeline_quads_simplified_vs_straight() {
    // P1=[5,5,5,5,7] (quads 简化为 trips，pair_count=6→category=4) vs P2=[2,3,4,5,6] (straight, category=5) → P2 胜
    let s1 = run_eval_e2e(&[5, 5, 5, 5, 7]);
    let s2 = run_eval_e2e(&[2, 3, 4, 5, 6]);
    let winner = run_compare_e2e(s1, s2);
    assert_eq!(winner, 2, "straight 应胜 trips（quads 简化）");
}
```

#### B.3 验证
```bash
cargo test -p poker_zkvm --test e2e_poker_hand_compare -- --nocapture
```

---

### Phase C: sigma 协议本地编排（5 个 proof，BLS12-381）

#### C.1 扩展 [src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs)

**扩展 PerfSummary 与 SigmaStageTimings**：

在 `SigmaStageTimings` 结构体中增加 RemaskProof 和 LeaveProof 字段：
```rust
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct SigmaStageTimings {
    // ZKShuffleProof
    pub shuffle_prove_ms: f64,
    pub shuffle_verify_ms: f64,
    // RevealTokenAndProof
    pub reveal_prove_ms: f64,
    pub reveal_verify_ms: f64,
    // ReconstructProof
    pub reconstruct_prove_ms: f64,
    pub reconstruct_verify_ms: f64,
    // RemaskProof
    pub remask_prove_ms: f64,
    pub remask_verify_ms: f64,
    // LeaveProof
    pub leave_prove_ms: f64,
    pub leave_verify_ms: f64,
}
```

**新增 import**（文件顶部）：
```rust
use std::time::Instant;
use rand::rngs::OsRng;
use poker_protocol::crypto::types::{DefaultCurve, ElGamalCiphertext, EcPoint, ECScalar, BASE_G};
use poker_protocol::crypto::curve::Curve;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::zk_shuffle::reveal_token_proof::{RevealTokenProof, RevealTokenAndProof};
use poker_protocol::zk_shuffle::reconstruction::{reconstruct_deck, ReconstructProof};
use poker_protocol::zk_shuffle::remask_proof::{remask_ciphertext, RemaskProof};
use poker_protocol::zk_shuffle::leave_proof::{leave_ciphertext, LeaveProof};
```

**替换 `run_shuffle_protocol(card_seq)` 实现**：

```rust
fn run_shuffle_protocol(card_seq: &[u8]) -> Result<Vec<u8>, String> {
    // === 1. 准备输入：将 0..51 索引转换为 BLS12-381 明文牌点 ===
    // 复用 poker_l1 的 generate_plaintext_cards 算法：hash_to_g1("texas_poker/card/{i}")
    // 但 poker_protocol 没有暴露 hash_to_g1，需要用 poker_l1 的 utils::generate_plaintext_cards()
    use poker_l1::vm::contracts::texas_poker::utils::generate_plaintext_cards;
    let plaintext_cards = generate_plaintext_cards(); // Vec<G1Projective> 52 张

    // PLAYER2 sk=Fr::from(1u64), pk=generator（与链上一致）
    let player2_sk = <DefaultCurve as Curve>::Scalar::from(1u64);
    let player2_pk = <DefaultCurve as Curve>::base_g() * player2_sk;

    // 构造 52 张初始 ElGamal 密文：c1=G, c2=plaintext_cards[i]
    // 链上 set_initial_encrypted_deck 的本地等价
    let input_cts: Vec<ElGamalCiphertext> = plaintext_cards.iter().map(|p| {
        ElGamalCiphertext {
            c1: <DefaultCurve as Curve>::base_g(),
            c2: *p,
        }
    }).collect();

    // === 2. ZKShuffleProof ===
    info!("  [sigma 1/5] ZKShuffleProof (BLS12-381)...");
    let mut rng = OsRng;
    // 生成随机排列 + 52 个 reencrypt 随机数
    let permute: Vec<usize> = {
        let mut p: Vec<usize> = (0..52).collect();
        // Fisher-Yates shuffle
        for i in (1..p.len()).rev() {
            let j = rand::Rng::gen_range(&mut rng, 0..=i);
            p.swap(i, j);
        }
        p
    };
    let r_values: Vec<_> = (0..52).map(|_| <DefaultCurve as Curve>::Scalar::random(&mut rng)).collect();
    // 计算 output_cts[i] = reencrypt(pk, input_cts[permute[i]], r_values[i])
    let output_cts: Vec<ElGamalCiphertext> = (0..52).map(|i| {
        let src = &input_cts[permute[i]];
        // reencrypt: c1' = c1 * g^r = G * (G * r) ... 实际是 c1' = G * r_new, c2' = c2 + pk * r_new
        let r = r_values[i];
        ElGamalCiphertext {
            c1: src.c1 + <DefaultCurve as Curve>::base_g() * r,
            c2: src.c2 + player2_pk * r,
        }
    }).collect();

    let t_prove = Instant::now();
    let mut ts_prove = MerlinTranscript::new(b"shuffle_proof_v1");
    let shuffle_proof = ZKShuffleProof::<DefaultCurve>::prove(
        &input_cts, &output_cts, &permute, &r_values, &player2_pk, &mut rng, &mut ts_prove,
    ).map_err(|e| format!("ZKShuffleProof::prove 失败：{e:?}"))?;
    let shuffle_prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let t_verify = Instant::now();
    let mut ts_verify = MerlinTranscript::new(b"shuffle_proof_v1");
    let shuffle_ok = shuffle_proof.verify(&input_cts, &output_cts, &player2_pk, &mut ts_verify);
    let shuffle_verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
    info!("    prove={shuffle_prove_ms:.2}ms verify={shuffle_verify_ms:.2}ms ok={shuffle_ok}");
    assert!(shuffle_ok, "ZKShuffleProof::verify 失败");

    // === 3. RevealTokenAndProof（取 output_cts[0] 作为示例）===
    info!("  [sigma 2/5] RevealTokenAndProof (BLS12-381)...");
    let target_ct = &output_cts[0];
    // reveal_token = c1 * sk = G * r * sk
    let reveal_token = target_ct.c1 * player2_sk;

    let t_prove = Instant::now();
    let mut ts_prove = MerlinTranscript::new(b"reveal_token_proof_v3");
    let reveal_proof = RevealTokenProof::<DefaultCurve>::prove(
        &player2_sk, &player2_pk, target_ct, &reveal_token, &mut rng, &mut ts_prove,
    );
    let reveal_prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let t_verify = Instant::now();
    let mut ts_verify = MerlinTranscript::new(b"reveal_token_proof_v3");
    let reveal_ok = reveal_proof.verify(target_ct, &reveal_token, &player2_pk, &mut ts_verify);
    let reveal_verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
    info!("    prove={reveal_prove_ms:.2}ms verify={reveal_verify_ms:.2}ms ok={reveal_ok}");
    assert!(reveal_ok, "RevealTokenProof::verify 失败");

    // === 4. ReconstructProof ===
    info!("  [sigma 3/5] ReconstructProof (BLS12-381)...");
    // 用前 2 张牌作为 user_readable_cards（玩家可读）
    let user_readable_cards: Vec<ElGamalCiphertext> = output_cts[0..2].to_vec();
    let cards_ref: Vec<_> = plaintext_cards.iter().copied().collect();
    let coefficient = <DefaultCurve as Curve>::Scalar::from(7u64);

    let (s_vec, rec_output_cards, swap_out_cards) = reconstruct_deck::<DefaultCurve>(
        &cards_ref, &user_readable_cards, &player2_sk, &player2_pk, &coefficient,
    ).map_err(|e| format!("reconstruct_deck 失败：{e:?}"))?;

    let t_prove = Instant::now();
    let mut ts_prove = MerlinTranscript::new(b"reconstruct_proof_v1");
    let rec_proof = ReconstructProof::<DefaultCurve>::prove(
        cards_ref.clone(), user_readable_cards.clone(), rec_output_cards.clone(),
        swap_out_cards.clone(), &player2_sk, &player2_pk, s_vec.clone(),
        &mut ts_prove,
    ).map_err(|e| format!("ReconstructProof::prove 失败：{e:?}"))?;
    let reconstruct_prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let t_verify = Instant::now();
    let mut ts_verify = MerlinTranscript::new(b"reconstruct_proof_v1");
    let rec_ok = rec_proof.verify(
        &cards_ref, &rec_output_cards, &swap_out_cards, &user_readable_cards, &player2_pk, &mut ts_verify,
    );
    let reconstruct_verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
    info!("    prove={reconstruct_prove_ms:.2}ms verify={reconstruct_verify_ms:.2}ms ok={rec_ok}");
    assert!(rec_ok, "ReconstructProof::verify 失败");

    // === 5. RemaskProof ===
    info!("  [sigma 4/5] RemaskProof (BLS12-381)...");
    // 用前 5 张做 remask 示例
    let remask_input: Vec<ElGamalCiphertext> = output_cts[0..5].to_vec();
    let remask_output: Vec<ElGamalCiphertext> = remask_input.iter().map(|ct| {
        remask_ciphertext(ct, &player2_sk, &player2_pk, &mut rng).unwrap()
    }).collect();

    let t_prove = Instant::now();
    let mut ts_prove = MerlinTranscript::new(b"remask_proof_v1");
    let remask_proof = RemaskProof::<DefaultCurve>::prove(
        &remask_input, &remask_output, &player2_sk, &player2_pk, &mut ts_prove,
    );
    let remask_prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let t_verify = Instant::now();
    let mut ts_verify = MerlinTranscript::new(b"remask_proof_v1");
    let remask_ok = remask_proof.verify(&remask_input, &remask_output, &player2_pk, &mut ts_verify);
    let remask_verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
    info!("    prove={remask_prove_ms:.2}ms verify={remask_verify_ms:.2}ms ok={remask_ok}");
    assert!(remask_ok, "RemaskProof::verify 失败");

    // === 6. LeaveProof ===
    info!("  [sigma 5/5] LeaveProof (BLS12-381)...");
    // leave 输入用 remask 输出，输出再 leave 回去
    let leave_input = remask_output.clone();
    let leave_output: Vec<ElGamalCiphertext> = leave_input.iter().map(|ct| {
        leave_ciphertext(ct, &player2_sk, &player2_pk, &mut rng).unwrap()
    }).collect();

    let t_prove = Instant::now();
    let mut ts_prove = MerlinTranscript::new(b"leave_proof_v1");
    let leave_proof = LeaveProof::<DefaultCurve>::prove(
        &leave_input, &leave_output, &player2_sk, &player2_pk, &mut ts_prove,
    );
    let leave_prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let t_verify = Instant::now();
    let mut ts_verify = MerlinTranscript::new(b"leave_proof_v1");
    let leave_ok = leave_proof.verify(&leave_input, &leave_output, &player2_pk, &mut ts_verify);
    let leave_verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
    info!("    prove={leave_prove_ms:.2}ms verify={leave_verify_ms:.2}ms ok={leave_ok}");
    assert!(leave_ok, "LeaveProof::verify 失败");

    // === 7. 解密查表：从 output_cts 提取 P1/P2 各 5 张牌的 rank ===
    // P1 取 output_cts[0..5]（解密后查表得 i，rank = (i % 13) + 2）
    // P2 取 output_cts[5..10]
    let mut p1_cards = [0u8; 5];
    let mut p2_cards = [0u8; 5];
    for idx in 0..5 {
        // 解密：plaintext = c2 - c1 * sk
        let pt1 = output_cts[idx].c2 - output_cts[idx].c1 * player2_sk;
        let pt2 = output_cts[5 + idx].c2 - output_cts[5 + idx].c1 * player2_sk;
        p1_cards[idx] = plaintext_to_rank(&pt1, &plaintext_cards);
        p2_cards[idx] = plaintext_to_rank(&pt2, &plaintext_cards);
    }
    info!("  解密查表：P1={p1_cards:?} P2={p2_cards:?}");

    // 累加到 PerfSummary
    {
        let mut s = perf_summary().lock().map_err(|e| format!("锁中毒：{e}"))?;
        s.sigma_stage = SigmaStageTimings {
            shuffle_prove_ms, shuffle_verify_ms,
            reveal_prove_ms, reveal_verify_ms,
            reconstruct_prove_ms, reconstruct_verify_ms,
            remask_prove_ms, remask_verify_ms,
            leave_prove_ms, leave_verify_ms,
        };
    }

    // 返回 P1+P2 牌序（10 字节）供 Phase B 评估
    Ok([p1_cards.as_slice(), p2_cards.as_slice()].concat())
}

/// 将解密出的 BLS12-381 明文点与 generate_plaintext_cards() 的 52 张已知点比对，
/// 找到索引 i，返回 rank = (i % 13) + 2。
fn plaintext_to_rank(pt: &<DefaultCurve as Curve>::Point, table: &[<DefaultCurve as Curve>::Point]) -> u8 {
    for (i, known) in table.iter().enumerate() {
        if pt == known {
            return (i % 13) as u8 + 2;
        }
    }
    panic!("解密出的明文点不在 52 张已知牌中");
}
```

**修改 `run_full_hand` 的 Phase B 调用**：
```rust
// Phase C 返回 P1+P2 共 10 字节牌
let cards_bytes = run_shuffle_protocol(&card_seq)?;
let p1_cards: [u8; 5] = cards_bytes[0..5].try_into().unwrap();
let p2_cards: [u8; 5] = cards_bytes[5..10].try_into().unwrap();

// Phase B: RV32I zkvm 牌型评估+比较（BN254）
let winner = run_rv32i_eval_and_compare(&p1_cards, &p2_cards)?;
```

#### C.2 修改 `run_rv32i_eval_and_compare(p1, p2)` 签名与实现

```rust
fn run_rv32i_eval_and_compare(p1: &[u8; 5], p2: &[u8; 5]) -> Result<u8, String> {
    use poker_zkvm::prover::{prove, default_ccs_registry, ProverConfig, MAX_PROOF_TOTAL_SIZE};
    use poker_zkvm::verifier::verify_production;

    // 注意：build_poker_hand_eval_v2_elf 和 build_poker_hand_compare_elf 定义在
    // poker_zkvm/tests/common/mod.rs，是测试代码。为在 bin 中复用，需要把
    // 这两个函数和参考实现移到一个公开的 helper 模块中。
    // 方案：在 poker_zkvm crate 的 test_helpers.rs 中新增这些函数（已 pub），
    // 这样 zchain bin 可以通过 `poker_zkvm::test_helpers::*` 直接调用。

    let config = ProverConfig { proof_size_limit: MAX_PROOF_TOTAL_SIZE, ..Default::default() };
    let ccs = default_ccs_registry();

    // P1 评估
    info!("  [rv32i 1/3] P1 牌型评估 (BN254 zkvm)...");
    let elf_p1 = poker_zkvm::test_helpers::build_poker_hand_eval_v2_elf();
    let t = Instant::now();
    let (proof_p1, io_p1) = prove(&elf_p1, p1, &config).map_err(|e| format!("P1 prove 失败：{e:?}"))?;
    let p1_prove_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let ok = verify_production(&proof_p1, &io_p1, &ccs).map_err(|e| format!("P1 verify 失败：{e:?}"))?;
    let p1_verify_ms = t.elapsed().as_secs_f64() * 1000.0;
    assert!(ok, "P1 verify_production 应返回 true");
    let s1 = u32::from_le_bytes(io_p1.output[..4].try_into().unwrap());
    info!("    prove={p1_prove_ms:.2}ms verify={p1_verify_ms:.2}ms proof_size={}B score=0x{s1:08X}", proof_p1.len());

    // P2 评估
    info!("  [rv32i 2/3] P2 牌型评估 (BN254 zkvm)...");
    let elf_p2 = poker_zkvm::test_helpers::build_poker_hand_eval_v2_elf();
    let t = Instant::now();
    let (proof_p2, io_p2) = prove(&elf_p2, p2, &config).map_err(|e| format!("P2 prove 失败：{e:?}"))?;
    let p2_prove_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let ok = verify_production(&proof_p2, &io_p2, &ccs).map_err(|e| format!("P2 verify 失败：{e:?}"))?;
    let p2_verify_ms = t.elapsed().as_secs_f64() * 1000.0;
    assert!(ok);
    let s2 = u32::from_le_bytes(io_p2.output[..4].try_into().unwrap());
    info!("    prove={p2_prove_ms:.2}ms verify={p2_verify_ms:.2}ms proof_size={}B score=0x{s2:08X}", proof_p2.len());

    // 比较
    info!("  [rv32i 3/3] 牌型比较 (BN254 zkvm)...");
    let mut cmp_input = Vec::with_capacity(8);
    cmp_input.extend_from_slice(&s1.to_le_bytes());
    cmp_input.extend_from_slice(&s2.to_le_bytes());
    let elf_cmp = poker_zkvm::test_helpers::build_poker_hand_compare_elf();
    let t = Instant::now();
    let (proof_cmp, io_cmp) = prove(&elf_cmp, &cmp_input, &config).map_err(|e| format!("cmp prove 失败：{e:?}"))?;
    let cmp_prove_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let ok = verify_production(&proof_cmp, &io_cmp, &ccs).map_err(|e| format!("cmp verify 失败：{e:?}"))?;
    let cmp_verify_ms = t.elapsed().as_secs_f64() * 1000.0;
    assert!(ok);
    let winner = io_cmp.output[0];
    info!("    prove={cmp_prove_ms:.2}ms verify={cmp_verify_ms:.2}ms proof_size={}B winner=P{winner}", proof_cmp.len());

    // 累加 PerfSummary
    {
        let mut s = perf_summary().lock().map_err(|e| format!("锁中毒：{e}"))?;
        s.rv32i_stage.eval_p1_prove_ms = p1_prove_ms;
        s.rv32i_stage.eval_p1_verify_ms = p1_verify_ms;
        s.rv32i_stage.eval_p1_proof_size_bytes = proof_p1.len();
        s.rv32i_stage.eval_p2_prove_ms = p2_prove_ms;
        s.rv32i_stage.eval_p2_verify_ms = p2_verify_ms;
        s.rv32i_stage.eval_p2_proof_size_bytes = proof_p2.len();
        s.rv32i_stage.compare_prove_ms = cmp_prove_ms;
        s.rv32i_stage.compare_verify_ms = cmp_verify_ms;
        s.rv32i_stage.compare_proof_size_bytes = proof_cmp.len();
    }

    Ok(winner)
}
```

#### C.3 关键依赖：将 ELF 构建函数暴露到 bin

由于 `build_poker_hand_eval_v2_elf` / `build_poker_hand_compare_elf` 原本在 `poker_zkvm/tests/common/mod.rs`（仅测试可见），bin crate 无法直接使用。**解决方案**：把这两个函数和参考实现一并新增到 [poker_zkvm/src/test_helpers.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/test_helpers.rs)（已经 `pub`），这样 bin 可通过 `poker_zkvm::test_helpers::*` 调用，且测试文件也可改用 `poker_zkvm::test_helpers::*` 引用（保持单一来源）。

具体操作：
1. 在 `test_helpers.rs` 末尾新增 4 个 `pub` 函数：`build_poker_hand_eval_v2_elf`、`build_poker_hand_compare_elf`、`poker_hand_eval_v2_expected`、`poker_hand_compare_expected`
2. `poker_zkvm/tests/common/mod.rs` 改为 `pub use poker_zkvm::test_helpers::{build_poker_hand_eval_v2_elf, build_poker_hand_compare_elf, poker_hand_eval_v2_expected, poker_hand_compare_expected};` re-export（或保留 stub 调用 test_helpers 的版本）
3. `e2e_poker_hand_compare.rs` 通过 `common::*` 间接调用

#### C.4 验证（Phase C 本地模式）
```bash
cargo check -p zchain
cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log
# 期望：日志含 5 个 sigma proof 的 prove/verify 耗时 + 3 个 rv32i prove/verify 耗时 + JSON 摘要
```

---

### Phase D: 链上 RPC 集成（真实数据源）

#### D.1 实现 `create_onchain_table_and_extract_cards(rpc_listen, deck_size) -> Result<Vec<u8>, String>`

替换 [src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs) 中的 stub。

实现要点：
- **复用 poker_rpc_demo 的 RPC 调用模式**：`rpc_call` / `build_signed_tx` / `submit_tx_via_rpc` / `wait_for_block_with_tx` / `query_table_state` / `verify_table_state`
- 由于这些函数在 `poker_rpc_demo.rs` 中是 `fn`（非 `pub`），需要把它们提升为 `pub(crate)` 或在 `poker_zkvm_demo.rs` 中复制一份（推荐前者，符合 DRY）

**步骤**：
1. 在 [src/poker_rpc_demo.rs](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs) 把以下函数改为 `pub(crate)`：`rpc_call` / `build_signed_tx` / `submit_tx_via_rpc` / `wait_for_block_with_tx` / `query_table_state` / `verify_table_state` / `query_chain_id`（如有）
2. 在 `poker_zkvm_demo.rs` 实现：

```rust
fn create_onchain_table_and_extract_cards(
    rpc_listen: &str,
    deck_size: usize,
) -> Result<Vec<u8>, String> {
    use crate::poker_rpc_demo::{
        rpc_call, build_signed_tx, submit_tx_via_rpc, wait_for_block_with_tx,
        query_table_state, verify_table_state,
    };
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};
    use blstrs::G1Projective;
    use group::Group;
    use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
    use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
    use poker_l1::vm::contracts::texas_poker::dispatch::selectors;
    use poker_l1::vm::contracts::texas_poker::dispatch::{CreateTableArgs, JoinTableArgs};
    use poker_l1::vm::precompile::reserved::texas_poker_contract_id;
    use poker_protocol::crypto::types::ECPoint;

    const PLAYER1: [u8; 20] = [0x11; 20];
    const PLAYER2: [u8; 20] = [0x22; 20];

    info!("  RPC endpoint: {rpc_listen}");
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let compressed = public_key.serialize();
    let tagged_pubkey = TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, compressed.to_vec())
        .map_err(|e| format!("构造 tagged_pubkey 失败：{e}"))?;

    // 查询 chain_id
    let chain_id = poker_l1::DEFAULT_CHAIN_ID; // 简化：用默认值；可改为 query_chain_id

    // Step 1: create_table
    info!("  [1/4] create_table...");
    let create_args = CreateTableArgs {
        name: "zkvm_demo_table".to_string(),
        max_players: 2, small_blind: 5, big_blind: 10,
    };
    let create_args_bytes = borsh::to_vec(&create_args).map_err(|e| format!("borsh: {e}"))?;
    let tx1 = build_signed_tx(&secp, &secret_key, &tagged_pubkey, chain_id,
        selectors::create_table(), create_args_bytes, 0, 0);
    let tx1_hash = tx1.tx_hash();
    submit_tx_via_rpc(rpc_listen, &tx1)?;
    wait_for_block_with_tx(rpc_listen, tx1_hash)?;
    info!("    tx_hash={}", hex::encode(tx1_hash));

    // Step 2: join_table ×2
    info!("  [2/4] join_table P1 (pk=identity)...");
    let join1_args = JoinTableArgs { player: PLAYER1, buy_in: 1000, pk: ECPoint(G1Projective::identity()) };
    let join1_bytes = borsh::to_vec(&join1_args).map_err(|e| format!("borsh: {e}"))?;
    let tx2 = build_signed_tx(&secp, &secret_key, &tagged_pubkey, chain_id,
        selectors::join_table(), join1_bytes, 0, 0);
    let tx2_hash = tx2.tx_hash();
    submit_tx_via_rpc(rpc_listen, &tx2)?;
    wait_for_block_with_tx(rpc_listen, tx2_hash)?;
    info!("    tx_hash={}", hex::encode(tx2_hash));

    info!("  [3/4] join_table P2 (pk=generator)...");
    let join2_args = JoinTableArgs { player: PLAYER2, buy_in: 1000, pk: ECPoint(G1Projective::generator()) };
    let join2_bytes = borsh::to_vec(&join2_args).map_err(|e| format!("borsh: {e}"))?;
    let tx3 = build_signed_tx(&secp, &secret_key, &tagged_pubkey, chain_id,
        selectors::join_table(), join2_bytes, 0, 0);
    let tx3_hash = tx3.tx_hash();
    submit_tx_via_rpc(rpc_listen, &tx3)?;
    wait_for_block_with_tx(rpc_listen, tx3_hash)?;
    info!("    tx_hash={}", hex::encode(tx3_hash));

    // Step 3: start_hand
    info!("  [4/4] start_hand...");
    let tx4 = build_signed_tx(&secp, &secret_key, &tagged_pubkey, chain_id,
        selectors::start_hand(), vec![], 0, 0);
    let tx4_hash = tx4.tx_hash();
    submit_tx_via_rpc(rpc_listen, &tx4)?;
    wait_for_block_with_tx(rpc_listen, tx4_hash)?;
    info!("    tx_hash={}", hex::encode(tx4_hash));

    // 查询最终 table state
    let table = query_table_state(rpc_listen)?
        .ok_or("start_hand 后 table 不存在")?;
    if table.shuffle_state.phase != 3 {
        return Err(format!("shuffle_state.phase != 3 (BEFORE_PREFLOP)，got={}", table.shuffle_state.phase));
    }
    if table.deck_state.encrypted.len() != 52 {
        return Err(format!("encrypted.len() != 52，got={}", table.deck_state.encrypted.len()));
    }

    // 提取牌序：链上 52 张牌的索引 0..51
    // 注：链上 ElGamalCiphertext (c1=G, c2=hash_to_g1("texas_poker/card/{i}"))
    // 这里只返回 0..52 索引序，sigma 协议在本地用此序重建 BLS12-381 密文
    let card_seq: Vec<u8> = (0..52u8).collect();

    // 累加 PerfSummary 链上信息
    {
        let mut s = perf_summary().lock().map_err(|e| format!("锁中毒：{e}"))?;
        s.onchain_table_id = Some(hex::encode(texas_poker_contract_id()));
        s.onchain_tx_count = Some(4);
        // block height 可后续从 wait_for_block_with_tx 返回值提取
    }

    info!("  ✓ 链上桌子创建成功，提取 52 张牌序");
    Ok(card_seq)
}
```

#### D.2 关键决策：链上 BLS12-381 密文 vs 本地重建

链上 `t.deck_state.encrypted` 是 `Vec<ElGamalCiphertext>`（poker_protocol 类型），与 sigma 协议本地重建的 `input_cts` 在密码学上等价（都遵循 `c1=G, c2=plaintext_cards[i]` 的初始化约定）。因此：

- **简化方案**：链上仅作"牌序权威源"，返回 `0..52` 索引序。本地 `run_shuffle_protocol` 用 `poker_l1::utils::generate_plaintext_cards()` 重建 52 张明文点 → 构造等价 input_cts → 跑 sigma 协议。这样无需在 RPC 响应中传递 G1 点的字节序列化（避免序列化兼容性问题）。
- **完整方案（可选）**：直接从 RPC 响应中解析 52 个 `ElGamalCiphertext`，喂给 sigma。需要处理 `ECPoint` ↔ `EcPoint` 的字节序列化。

本计划采用**简化方案**，与原计划文件 Decision 1 一致（"链上作牌序权威源，不传递群元素"）。

#### D.3 验证（Phase D 链上模式）
```bash
# 前置：服务器或本地 8545 端口有 zchain 节点运行
cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log
# 期望：日志含 4 笔链上 tx_hash + 5 个 sigma + 3 个 rv32i + JSON 摘要
```

---

### Phase E: 性能日志与摘要（贯穿 B/C/D，最后整理）

#### E.1 已完成
- `PerfSummary` / `SigmaStageTimings` / `Rv32iStageTimings` 结构体（serde::Serialize）
- `init_tracing_with_file(log_path)` tracing 双写（stderr + Mutex<File>）
- `write_perf_summary(log_path)` JSON 摘要追加写入

#### E.2 待修订：扩展 SigmaStageTimings
新增 `remask_*` 和 `leave_*` 字段（已在 Phase C.1 描述）。

#### E.3 待修订：tracing 日志格式标准化

每步 tracing 输出统一格式（便于 grep 解析）：
```
INFO stage=shuffle     phase=prove   ms=123.4
INFO stage=shuffle     phase=verify  ms=5.6   ok=true
INFO stage=reveal      phase=prove   ms=7.8
INFO stage=reveal      phase=verify  ms=0.9   ok=true
INFO stage=reconstruct phase=prove   ms=234.5
INFO stage=reconstruct phase=verify  ms=12.3  ok=true
INFO stage=remask      phase=prove   ms=11.1
INFO stage=remask      phase=verify  ms=1.2   ok=true
INFO stage=leave       phase=prove   ms=10.0
INFO stage=leave       phase=verify  ms=1.0   ok=true
INFO stage=rv32i_eval_p1  phase=prove   ms=456.7  proof_size=12345
INFO stage=rv32i_eval_p1  phase=verify  ms=23.4   proof_size=12345 ok=true
INFO stage=rv32i_eval_p2  phase=prove   ms=456.7  proof_size=12345
INFO stage=rv32i_eval_p2  phase=verify  ms=23.4   proof_size=12345 ok=true
INFO stage=rv32i_compare  phase=prove   ms=78.9   proof_size=5678
INFO stage=rv32i_compare  phase=verify  ms=5.6    proof_size=5678  ok=true
```

#### E.4 JSON 摘要最终格式

```json
{
  "timestamp": "2026-07-19T...",
  "mode": "onchain",
  "rpc_endpoint": "127.0.0.1:8545",
  "curve_adaptation": "BLS12-381 (business) + BN254 (zkvm circuit)",
  "onchain_table_id": "0xFF..02",
  "onchain_tx_count": 4,
  "onchain_final_block": 9,
  "sigma_stage": {
    "shuffle_prove_ms": 123.4, "shuffle_verify_ms": 5.6,
    "reveal_prove_ms": 7.8, "reveal_verify_ms": 0.9,
    "reconstruct_prove_ms": 234.5, "reconstruct_verify_ms": 12.3,
    "remask_prove_ms": 11.1, "remask_verify_ms": 1.2,
    "leave_prove_ms": 10.0, "leave_verify_ms": 1.0
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

#### E.5 验证
```bash
test -s /tmp/zkvm_poker_perf_onchain.log && echo "log non-empty"
tail -2 /tmp/zkvm_poker_perf_onchain.log | head -1  # 应为 --- PERF_SUMMARY_JSON ---
tail -1 /tmp/zkvm_poker_perf_onchain.log | jq . >/dev/null && echo "JSON valid"
grep -c 'ok=true' /tmp/zkvm_poker_perf_onchain.log  # 应 ≥ 8（5 sigma + 3 rv32i）
```

## Assumptions & Decisions

### Assumptions
1. **poker_protocol crate 可达**：`/Users/mac/projects/zgame/poker_protocol` 通过 workspace `poker_protocol = { path = "../zgame/poker_protocol", features = ["borsh"] }` 引用，zchain 已依赖
2. **poker_l1 utils 函数公开**：`poker_l1::vm::contracts::texas_poker::utils::generate_plaintext_cards()` 是 pub fn，可被 bin 调用
3. **RV32I v2 评估算法步数 ≤ 1000**：C(5,2)=10 对比较展开后 ~80-100 步，远低于 `MAX_FOLD_STEP_COUNT=1000`
4. **sigma proof verify 返回 bool**：5 个 proof 的 verify 都返回 `bool`（非 Result），简化错误处理

### Decisions
1. **曲线分工（用户已批准）**：
   - 链上 + sigma 协议 = **BLS12-381**（poker_protocol 实现，与链上一致）
   - zkvm 电路（RV32I 评估+比较）= **BN254**（poker_zkvm 内部）
2. **sigma 范围（用户已批准）**：5 个全跑（ShuffleProof + RevealTokenAndProof + ReconstructProof + RemaskProof + LeaveProof）
3. **牌序映射（用户已批准）**：解密查表 — sigma 解密出 BLS12-381 明文点 → 与 `generate_plaintext_cards()` 52 个 `hash_to_g1("texas_poker/card/{i}")` 比对 → rank = (i % 13) + 2
4. **ELF 函数暴露**：将 `build_poker_hand_eval_v2_elf` / `build_poker_hand_compare_elf` / `poker_hand_eval_v2_expected` / `poker_hand_compare_expected` 放在 `poker_zkvm/src/test_helpers.rs`（已 `pub`），bin 和 tests 共享单一来源
5. **链上数据集成边界**：链上仅返回 52 张牌的索引序（0..51），本地用 `generate_plaintext_cards()` 重建 BLS12-381 密文（链上密文与本地重建等价，因 `set_initial_encrypted_deck` 用相同算法）
6. **sigma prove 是"客户端"职责**：测试时本地用 poker_protocol prove 生成；zkvm 仅负责 verify（与用户"zkvm不需要prove"一致）。sigma 是 host 端 Rust 调用，非 RV32I 电路（与"verify也不需要写成电路"一致）

## Verification Steps

### Phase B 验证
```bash
# 1. 扩展 ELF 构建函数 + 参考实现到 test_helpers.rs（pub）
# 2. tests/common/mod.rs re-export
# 3. 新建 e2e_poker_hand_compare.rs
cargo test -p poker_zkvm --test e2e_poker_hand_compare -- --nocapture
# 期望：8 个测试全过（4 eval + 3 compare + 2 full_pipeline = 9 个，或按实际测试数）
```

### Phase C 验证（本地模式）
```bash
cargo check -p zchain
cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log
# 期望：
#   - 5 个 sigma proof 都输出 prove/verify 耗时 + ok=true
#   - 3 个 rv32i 评估/比较都输出 prove/verify 耗时 + proof_size + ok=true
#   - 日志末尾有 PERF_SUMMARY_JSON
#   - JSON 含 sigma_stage（10 字段）+ rv32i_stage（9 字段）+ winner
```

### Phase D 验证（链上模式）
```bash
# 前置：服务器或本地 8545 端口有 zchain 节点运行
cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log
# 期望：
#   - 4 笔链上 tx 都提交成功 + 出块
#   - 后续与 Phase C 一致
```

### Phase E 验证
```bash
test -s /tmp/zkvm_poker_perf_local.log && echo "local log non-empty"
tail -2 /tmp/zkvm_poker_perf_local.log | head -1  # --- PERF_SUMMARY_JSON ---
tail -1 /tmp/zkvm_poker_perf_local.log | jq . > /dev/null && echo "JSON valid"
grep -c 'ok=true' /tmp/zkvm_poker_perf_local.log  # ≥ 8
```

## 实施顺序

```
Phase B.1 扩展 test_helpers.rs（pub 函数）
   ↓
Phase B.2 tests/common/mod.rs re-export
   ↓
Phase B.3 新建 e2e_poker_hand_compare.rs + cargo test
   ↓
Phase C.1 扩展 poker_zkvm_demo.rs：SigmaStageTimings 新增 remask/leave 字段
   ↓
Phase C.2 实现 run_shuffle_protocol（5 个 sigma proof + 解密查表）
   ↓
Phase C.3 实现 run_rv32i_eval_and_compare（接 P1/P2 输入）
   ↓
Phase C.4 cargo run --local-only 验证
   ↓
Phase D.1 poker_rpc_demo.rs 改 RPC helper 为 pub(crate)
   ↓
Phase D.2 实现 create_onchain_table_and_extract_cards
   ↓
Phase D.3 cargo run --rpc 验证
   ↓
Phase E 整理日志格式 + JSON 摘要验证
```

## 风险点与回退

| 风险 | 应对 |
|------|------|
| RV32I v2 评估步数超 1000 | 回退到"仅 pair 检测"版本（~40 步），仅统计 pair_count 不检测 straight |
| sigma 协议 prove 失败 | poker_protocol API 已在 tests 中验证；若失败先检查 transcript label 是否匹配 |
| 链上 RPC 不可达 | `--local-only` 回退；RPC 超时 10s |
| poker_protocol 类型与 bin crate 类型不兼容 | sigma proof 全用 `DefaultCurve = Bls12381Curve`，与链上一致；`ECPoint` 包装仅在 RPC 传输时用 |
| `generate_plaintext_cards()` 返回 `Vec<G1Projective>`（blstrs）vs sigma 协议用 `<DefaultCurve as Curve>::Point` | 实际 `Bls12381Curve::Point = blstrs::G1Projective`，类型一致 |
| tracing 重复初始化 | main.rs 已加 `if subcommand != "poker-zkvm-demo"` 条件判断跳过全局 init |
| BLS12-381 点相等比较 | `pt == known` 使用 `PartialEq`；blstrs 的 `G1Projective` 实现了 `PartialEq`（常数时间比较） |
