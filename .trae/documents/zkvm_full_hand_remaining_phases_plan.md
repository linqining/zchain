# zkvm 完整一手牌 — 剩余阶段执行计划（Phase C.5 / D.1 / D.2 / E）

## Summary

承接上下文丢失前的进度：Phase A 脚手架 + Phase B.1（test_helpers.rs 4 个新 pub 函数）+ Phase B.2（tests/common/mod.rs re-export）+ Phase B.3（9 个 E2E 测试通过）+ Phase C.1-C.4（poker_zkvm_demo.rs 完整实现）已完成。

**当前状态（已验证）**：
- `cargo check -p zchain` 通过（仅有 poker_l1 预存 warnings，无 errors）
- `src/poker_zkvm_demo.rs` 完整实现 5 个 sigma proof + 3 个 RV32I proof，input_cts 构造修复已就位（使用 `ElGamalCiphertext::encrypt` 标准加密）
- `src/poker_rpc_demo.rs` 8 个 RPC helper 仍为私有 `fn`
- `create_onchain_table_and_extract_cards` 仍为 stub（返回 `Err("Phase D 尚未实现")`）

**本计划范围**：完成剩余 4 个阶段，达成 `/goal` 目标 — 创建链上桌子，本地启用 poker_zkvm，在 zkvm 完成完整的一手牌，记录耗时日志评估 zkvm 性能。

## Current State Analysis

### Phase C.1-C.4 已完成（验证通过）

[src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs)（790 行）已完整实现：

1. **PerfSummary / SigmaStageTimings / Rv32iStageTimings** 结构体完整（10 + 9 字段）
2. **`run_shuffle_protocol(card_seq: &[u8]) -> Result<Vec<u8>, String>`**（line 396-632）：
   - 5 个 sigma proof 完整 prove + verify + 测时（ZKShuffle / RevealToken / Reconstruct / Remask / Leave）
   - `decrypt_to_ranks` 辅助函数（line 639-661）— sigma 解密 → 查表 → rank
   - input_cts 用 `ElGamalCiphertext::encrypt(&plaintext_cards[i], &player2_pk, &input_r_values[i])` 标准加密（line 416-418）
   - 返回 P1 (5 字节) + P2 (5 字节) rank 数组
3. **`run_rv32i_eval_and_compare(p1: &[u8; 5], p2: &[u8; 5]) -> Result<u8, String>`**（line 672-773）：
   - P1 评估 + P2 评估 + 比较，每步 prove + verify + 测时 + proof_size
4. **`run_full_hand(local_only, rpc_listen, deck_size) -> Result<u8, String>`**（line 340-368）：
   - 调用链 D → C → B 完整
5. **`write_perf_summary(log_path)`**（line 778-790）：追加 `--- PERF_SUMMARY_JSON ---` 段

### Phase C.5 验证状态

- ✅ `cargo check -p zchain` 通过
- ⏳ `cargo run --local-only` 未重新运行（修复 input_cts 构造后未验证）

### Phase D 待实现

- **D.1**：[src/poker_rpc_demo.rs](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs) 8 个 RPC helper 仍为私有 `fn`，需改 `pub(crate) fn` 以供 `poker_zkvm_demo.rs` 复用
- **D.2**：`create_onchain_table_and_extract_cards` 仍为 stub（line 375-382），需实现 5-tx 链上流程

### 链上数据源已二次验证

- [poker_l1/src/vm/contracts/texas_poker/state_machine.rs:217-237](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/state_machine.rs#L217) — `set_initial_encrypted_deck` 用 `c1 = G, c2 = plaintext_cards[i]` 初始化 52 张牌（index 0..51 顺序写入）
- [poker_l1/src/vm/contracts/texas_poker/utils.rs:218-228](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs#L218) — `generate_plaintext_cards() -> Vec<G1Projective>` 返回 52 张明文牌（index 0..51 顺序）
- [poker_l1/src/vm/contracts/texas_poker/constants.rs:42](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/constants.rs#L42) — `SHUFFLE_PHASE_BEFORE_PREFLOP: u8 = 3`
- [poker_l1/src/vm/contracts/texas_poker/types.rs:171-180](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs#L171) — `ShuffleState.phase: u8`
- [poker_l1/src/vm/contracts/texas_poker/types.rs:93-118](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs#L93) — `Seat` 含 `player`, `stack`, `is_occupied()`

## Proposed Changes

### Phase C.5: 本地模式端到端验证

**操作**：运行 `cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log`

**期望输出**（基于已修复的 input_cts 构造）：
```
[sigma] plaintext_cards 数量: 52（card_seq.len=52）
[sigma] ZKShuffleProof:        prove=  17.xx ms verify=   3.xx ms ok=true
[sigma] RevealTokenProof:      prove=   0.xx ms verify=   0.xx ms ok=true
[sigma] ReconstructProof:      prove=   x.xx ms verify=   x.xx ms ok=true
[sigma] RemaskProof:           prove=   x.xx ms verify=   x.xx ms ok=true
[sigma] LeaveProof:            prove=   x.xx ms verify=   x.xx ms ok=true
[sigma] P1 牌序 (rank): [x, x, x, x, x]
[sigma] P2 牌序 (rank): [x, x, x, x, x]
[rv32i] P1 eval:     prove= xxx.xx ms verify= xx.xx ms size= xxxxxxB score=0xXXXX
[rv32i] P2 eval:     prove= xxx.xx ms verify= xx.xx ms size= xxxxxxB score=0xXXXX
[rv32i] compare:     prove=  xx.xx ms verify=  x.xx ms size= xxxxxxB winner=Px
```

**风险点与应对**：
1. **reconstruct_deck InvalidPlaintext 错误**（曾发生）— 已修复 input_cts 构造（改用标准 ElGamal 加密）。若仍报错，需检查 `decrypt(sk) = c2 - c1*sk` 是否等于 `plaintext_cards[i]`：标准加密下 `c2 - c1*sk = (m + pk*r) - (G*r)*sk = m + pk*r - pk*r = m` ✓
2. **解密查表找不到匹配**（panic）— 若 sigma 协议的 output_cts 解密后明文点不在 `generate_plaintext_cards()` 列表中，说明 output_cts 构造有误。当前实现 `output.c1 = input.c1 + base_g()*r, output.c2 = input.c2 + pk*r` 是标准 reencrypt，解密 `output.c2 - output.c1*sk = input.c2 + pk*r - (input.c1 + G*r)*sk = (input.c2 - input.c1*sk) + pk*r - pk*r = input.c2 - input.c1*sk = m` ✓
3. **cargo run 性能**：release 模式下 RV32I prove 单次约 100-500ms（参考 e2e_poker_hand_compare.rs 9 个测试 72s ≈ 8s/test）

**验证步骤**：
```bash
cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log
# 期望退出码 0，日志末尾有 --- PERF_SUMMARY_JSON --- 段
grep -A 30 PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_local.log
# 期望 JSON 含 sigma_stage (10 字段) + rv32i_stage (9 字段) + total_time_ms + winner
```

---

### Phase D.1: poker_rpc_demo.rs 8 个 RPC helper 改 `pub(crate)`

**文件**：[src/poker_rpc_demo.rs](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs)

**修改**：8 个函数签名前缀由 `fn` 改为 `pub(crate) fn`：

| 行号 | 函数名 | 修改前 | 修改后 |
|------|--------|--------|--------|
| 293 | `build_signed_tx` | `#[allow(clippy::too_many_arguments)]\nfn build_signed_tx(` | `#[allow(clippy::too_many_arguments)]\npub(crate) fn build_signed_tx(` |
| 336 | `submit_tx_via_rpc` | `fn submit_tx_via_rpc(` | `pub(crate) fn submit_tx_via_rpc(` |
| 365 | `wait_for_block_with_tx` | `fn wait_for_block_with_tx(` | `pub(crate) fn wait_for_block_with_tx(` |
| 403 | `query_block_by_height` | `fn query_block_by_height(` | `pub(crate) fn query_block_by_height(` |
| 430 | `query_chain_id` | `fn query_chain_id(` | `pub(crate) fn query_chain_id(` |
| 437 | `query_table_state` | `fn query_table_state(` | `pub(crate) fn query_table_state(` |
| 461 | `verify_table_state` | `fn verify_table_state(` | `pub(crate) fn verify_table_state(` |
| 477 | `rpc_call` | `fn rpc_call(` | `pub(crate) fn rpc_call(` |

**原因**：`poker_zkvm_demo.rs::create_onchain_table_and_extract_cards` 需复用这些 RPC helper 完成 5-tx 链上桌子创建流程。

**附加修改**：常量也改 `pub(crate)`（供 D.2 使用）：
- line 45: `const RPC_TIMEOUT` → `pub(crate) const RPC_TIMEOUT`
- line 48: `const BLOCK_WAIT_INTERVAL` → `pub(crate) const BLOCK_WAIT_INTERVAL`
- line 51: `const BLOCK_WAIT_MAX` → `pub(crate) const BLOCK_WAIT_MAX`
- line 54: `const PLAYER1` → `pub(crate) const PLAYER1`
- line 56: `const PLAYER2` → `pub(crate) const PLAYER2`

**验证**：`cargo check -p zchain` 应通过（无新增 errors）。

---

### Phase D.2: 实现 `create_onchain_table_and_extract_cards`

**文件**：[src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs)（替换 line 375-382 的 stub）

**实现策略**（基于已批准的简化策略）：
- 链上仅作"牌序权威源"——验证 table 已创建、phase==3、52 张加密牌已初始化
- 本地 `run_shuffle_protocol` 使用 `generate_plaintext_cards()` 重建密文（不依赖链上 encrypted 字段的具体值）
- 返回 `Vec<u8>` = `(0..52).collect()`（链上 set_initial_encrypted_deck 写入顺序为 0..51）

**实现流程**（参考 [poker_rpc_demo.rs:88-237](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs#L88) 的 5-tx 流程）：

```rust
use crate::poker_rpc_demo::{
    build_signed_tx, query_chain_id, query_table_state, rpc_call, submit_tx_via_rpc,
    verify_table_state, wait_for_block_with_tx, BLOCK_WAIT_INTERVAL, BLOCK_WAIT_MAX,
    PLAYER1, PLAYER2, RPC_TIMEOUT,
};
use poker_l1::vm::contracts::texas_poker::dispatch::{CreateTableArgs, JoinTableArgs};
use poker_l1::vm::contracts::texas_poker::dispatch::selectors;
use poker_l1::vm::precompile::reserved::texas_poker_contract_id;
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;
use poker_protocol::crypto::types::ECPoint;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1};

/// 通过 RPC 创建链上桌子并提取牌序。
///
/// 流程：create_table → join_table ×2 → start_hand → 校验 phase==3
/// 返回 `(0..52).collect::<Vec<u8>>()` 作为牌序索引（链上 set_initial_encrypted_deck 写入顺序）。
fn create_onchain_table_and_extract_cards(
    rpc_listen: &str,
    deck_size: usize,
) -> Result<Vec<u8>, String> {
    info!("  [chain] RPC endpoint: {rpc_listen}");
    info!("  [chain] 目标合约: texas_poker (ObjectID = {:?})", texas_poker_contract_id());

    // 1. 生成 secp256k1 密钥对
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let compressed = public_key.serialize();
    let tagged_pubkey =
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, compressed.to_vec())
            .map_err(|e| format!("构造 tagged_pubkey 失败：{e}"))?;
    let _signer_address: poker_l1::Address = poker_l1::account::derive_address(&tagged_pubkey);
    info!("  [chain] signer tagged_pubkey raw={}B", tagged_pubkey.raw.len());

    // 2. 查询 chain_id
    let chain_id = query_chain_id(rpc_listen).unwrap_or(poker_l1::DEFAULT_CHAIN_ID);
    info!("  [chain] chain_id=0x{chain_id:08X}");

    // 3. 查询初始桌台状态（应不存在）
    if let Some(existing) = query_table_state(rpc_listen)? {
        return Err(format!("桌台对象已存在（预期应不存在）：{existing:?}"));
    }
    info!("  [chain] ✓ 桌台对象尚不存在");

    // 4. Step 1: create_table
    let create_args = CreateTableArgs {
        name: "zkvm_demo_table".to_string(),
        max_players: 2,
        small_blind: 5,
        big_blind: 10,
    };
    let create_args_bytes = borsh::to_vec(&create_args).map_err(|e| format!("borsh: {e}"))?;
    let tx1 = build_signed_tx(
        &secp, &secret_key, &tagged_pubkey, chain_id,
        selectors::create_table(), create_args_bytes, 0, 0,
    );
    let tx1_hash = tx1.tx_hash();
    info!("  [chain] create_table tx_hash={}", hex::encode(tx1_hash));
    submit_tx_via_rpc(rpc_listen, &tx1)?;
    wait_for_block_with_tx(rpc_listen, tx1_hash)?;
    verify_table_state(rpc_listen, "create_table 后", |t| {
        t.name == "zkvm_demo_table" && t.max_players == 2 && t.small_blind == 5 && t.big_blind == 10
    })?;

    // 5. Step 2a: join_table P1
    let join1_args = JoinTableArgs {
        player: PLAYER1, buy_in: 1000,
        pk: ECPoint(blstrs::G1Projective::identity()),
    };
    let join1_bytes = borsh::to_vec(&join1_args).map_err(|e| format!("borsh: {e}"))?;
    let tx2 = build_signed_tx(
        &secp, &secret_key, &tagged_pubkey, chain_id,
        selectors::join_table(), join1_bytes, 0, 0,
    );
    let tx2_hash = tx2.tx_hash();
    info!("  [chain] join_table P1 tx_hash={}", hex::encode(tx2_hash));
    submit_tx_via_rpc(rpc_listen, &tx2)?;
    wait_for_block_with_tx(rpc_listen, tx2_hash)?;
    verify_table_state(rpc_listen, "join_table P1 后", |t| {
        t.seats[0].player == PLAYER1 && t.seats[0].stack == 1000 && t.seats[0].is_occupied()
    })?;

    // 6. Step 2b: join_table P2
    let join2_args = JoinTableArgs {
        player: PLAYER2, buy_in: 1000,
        pk: ECPoint(blstrs::G1Projective::generator()),
    };
    let join2_bytes = borsh::to_vec(&join2_args).map_err(|e| format!("borsh: {e}"))?;
    let tx3 = build_signed_tx(
        &secp, &secret_key, &tagged_pubkey, chain_id,
        selectors::join_table(), join2_bytes, 0, 0,
    );
    let tx3_hash = tx3.tx_hash();
    info!("  [chain] join_table P2 tx_hash={}", hex::encode(tx3_hash));
    submit_tx_via_rpc(rpc_listen, &tx3)?;
    wait_for_block_with_tx(rpc_listen, tx3_hash)?;
    verify_table_state(rpc_listen, "join_table P2 后", |t| {
        t.seats[1].player == PLAYER2 && t.seats[1].stack == 1000
    })?;

    // 7. Step 3: start_hand
    let tx4 = build_signed_tx(
        &secp, &secret_key, &tagged_pubkey, chain_id,
        selectors::start_hand(), vec![], 0, 0,
    );
    let tx4_hash = tx4.tx_hash();
    info!("  [chain] start_hand tx_hash={}", hex::encode(tx4_hash));
    submit_tx_via_rpc(rpc_listen, &tx4)?;
    wait_for_block_with_tx(rpc_listen, tx4_hash)?;
    verify_table_state(rpc_listen, "start_hand 后", |t| {
        t.shuffle_state.phase == 3 /* SHUFFLE_PHASE_BEFORE_PREFLOP */
            && t.deck_state.encrypted.len() == 52
    })?;

    // 8. 提取牌序（链上 set_initial_encrypted_deck 按 0..51 顺序写入）
    let card_seq: Vec<u8> = (0..deck_size.min(52) as u8).collect();
    info!("  [chain] ✓ 提取牌序索引: {} 张（0..{}）", card_seq.len(), card_seq.len());

    // 9. 更新 PerfSummary 链上字段
    {
        let mut s = perf_summary().lock().map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
        s.onchain_table_id = Some(hex::encode(texas_poker_contract_id()));
        s.onchain_tx_count = Some(4); // create + join×2 + start_hand
        // final_block 可选，此处不查询以简化
    }

    Ok(card_seq)
}
```

**关键 import 块**（在 poker_zkvm_demo.rs 顶部追加）：
```rust
use crate::poker_rpc_demo::{
    build_signed_tx, query_chain_id, query_table_state, submit_tx_via_rpc,
    verify_table_state, wait_for_block_with_tx, PLAYER1, PLAYER2,
};
use poker_l1::vm::contracts::texas_poker::dispatch::{CreateTableArgs, JoinTableArgs};
use poker_l1::vm::contracts::texas_poker::dispatch::selectors;
use poker_l1::vm::precompile::reserved::texas_poker_contract_id;
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
```

**注意**：
- 由于 `poker_rpc_demo` 是同 crate 内的兄弟模块，`poker_zkvm_demo` 通过 `use crate::poker_rpc_demo::*` 即可访问 `pub(crate)` 项
- `ECPoint` 已在 `poker_rpc_demo.rs` import，但 `poker_zkvm_demo.rs` 需独立 import（或直接用 `blstrs::G1Projective`）
- 此函数**不调用 reset_for_next_hand**——保留 table 在 `BEFORE_PREFLOP` 状态以便后续真实牌局；若需重置可由用户单独触发

**验证**：
```bash
# 启动一个本地 zchain 节点（单独终端）
cargo run -p zchain --release -- node --validator --rpc-listen 127.0.0.1:8545

# 另一终端运行 onchain 模式
cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log
```

**降级策略**：若链上 RPC 不可用（节点未启动），用户可继续用 `--local-only` 跑通 zkvm 性能评估（用户主要目标）。

---

### Phase E: 日志格式整理 + JSON 摘要验证

**操作**：验证 `/tmp/zkvm_poker_perf_local.log` 与 `/tmp/zkvm_poker_perf_onchain.log` 末尾的 JSON 摘要完整性。

**期望 JSON 结构**（19 个性能字段 + 4 个元数据字段）：
```json
{
  "timestamp": "2026-07-19T...",
  "mode": "local" | "onchain",
  "rpc_endpoint": null | "127.0.0.1:8545",
  "curve_adaptation": "BLS12-381 (business) + BN254 (zkvm circuit)",
  "onchain_table_id": null | "0x...",
  "onchain_tx_count": null | 4,
  "onchain_final_block": null,
  "sigma_stage": {
    "shuffle_prove_ms": 17.xx,
    "shuffle_verify_ms": 3.xx,
    "reveal_prove_ms": 0.xx,
    "reveal_verify_ms": 0.xx,
    "reconstruct_prove_ms": x.xx,
    "reconstruct_verify_ms": x.xx,
    "remask_prove_ms": x.xx,
    "remask_verify_ms": x.xx,
    "leave_prove_ms": x.xx,
    "leave_verify_ms": x.xx
  },
  "rv32i_stage": {
    "eval_p1_prove_ms": xxx.xx,
    "eval_p1_verify_ms": xx.xx,
    "eval_p1_proof_size_bytes": xxxxx,
    "eval_p2_prove_ms": xxx.xx,
    "eval_p2_verify_ms": xx.xx,
    "eval_p2_proof_size_bytes": xxxxx,
    "compare_prove_ms": xx.xx,
    "compare_verify_ms": x.xx,
    "compare_proof_size_bytes": xxxxx
  },
  "total_time_ms": xxxx.xx,
  "winner": 1 | 2 | 0
}
```

**验证命令**：
```bash
# 本地模式 JSON 摘要
grep -A 30 PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_local.log | tail -30

# 字段数检查（应输出 19）
grep -oE '"(shuffle|reveal|reconstruct|remask|leave|eval_p1|eval_p2|compare)_(prove|verify)_ms"|"eval_p[12]_proof_size_bytes"|"compare_proof_size_bytes"' /tmp/zkvm_poker_perf_local.log | sort -u | wc -l
```

## Assumptions & Decisions

1. **不需要再次问用户**：所有关键决策（曲线分工、sigma 范围、牌序映射、prove/verify 分工、链上角色、日志方式）在前序会话已通过 AskUserQuestion 批准
2. **input_cts 修复已就位**：标准 ElGamal 加密 `Enc(m, pk, r) = (G*r, m + pk*r)`，与 `reconstruct_deck` 的 `decrypt(sk) = c2 - c1*sk = m` 兼容
3. **链上 encrypted 字段不直接复用**：链上 `set_initial_encrypted_deck` 用 `(G, plaintext)` 简化形式（sk=0 等价），本地用标准加密模拟真实洗牌前的初始牌组——两者都是合法 ElGamal 密文，但本地版本更接近真实场景
4. **链上 table 不重置**：`create_onchain_table_and_extract_cards` 不调用 `reset_for_next_hand`，保留 `BEFORE_PREFLOP` 状态以便后续真实牌局
5. **降级策略**：若 Phase D 链上 RPC 不可用，`--local-only` 模式仍可端到端验证 zkvm 性能（用户主要目标）
6. **Phase D.1 包含常量改 pub(crate)**：5 个常量（RPC_TIMEOUT / BLOCK_WAIT_INTERVAL / BLOCK_WAIT_MAX / PLAYER1 / PLAYER2）也需改 `pub(crate)` 供 D.2 使用

## Verification Steps

| Phase | 验证命令 | 期望结果 |
|-------|---------|---------|
| C.5 | `cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log` | 5 sigma + 3 rv32i 全部 ok=true，退出码 0 |
| C.5 | `grep -A 30 PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_local.log` | JSON 含 19 个性能字段 |
| D.1 | `cargo check -p zchain` | 编译通过，无新增 errors |
| D.2 | 启动节点 + `cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log` | 链上 5-tx 流程成功 + sigma + rv32i 全部 ok=true |
| E | `grep -oE '"(shuffle\|reveal\|reconstruct\|remask\|leave\|eval_p1\|eval_p2\|compare)_(prove\|verify)_ms"' /tmp/zkvm_poker_perf_local.log \| sort -u \| wc -l` | 输出 16（10 sigma + 6 rv32i prove/verify） |
| E | `grep -oE '"eval_p[12]_proof_size_bytes"\|"compare_proof_size_bytes"' /tmp/zkvm_poker_perf_local.log \| sort -u \| wc -l` | 输出 3（3 个 proof_size_bytes） |

## Implementation Order

```
Phase C.5: cargo run --local-only 验证（input_cts 修复后）    ← 起点
   ↓
Phase D.1: poker_rpc_demo.rs 8 fn + 5 const 改 pub(crate)
   ↓
Phase D.2: 实现 create_onchain_table_and_extract_cards
   ↓
Phase E: 验证 JSON 摘要完整性（19 个性能字段）
```

## Notes

- **C.5 是关键验证**：input_cts 修复后未重新运行，需先确认 sigma + rv32i 全部 ok=true 才能继续 Phase D
- **D.2 可选**：若链上节点启动困难或 RPC 调试耗时过长，可优先确保 C.5 通过（用户主要目标已达成），D.2 作为增强功能后置
- **JSON 摘要写入时机**：`write_perf_summary` 在 `run()` 末尾调用，确保所有