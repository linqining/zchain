# zkvm 完整一手牌 — 最终阶段计划（Phase E Bug 修复 / D.1 / D.2 / E 验证）

## Summary

承接上下文丢失前的进度：Phase A + B.1-B.3 + C.1-C.5 全部完成。`cargo run --local-only` 已验证 5 个 sigma proof + 3 个 RV32I proof 全部 ok=true，总耗时 2980.39ms，赢家 P2。

**本计划范围**：完成剩余 4 项工作，达成 `/goal` 目标 — 创建链上桌子，本地启用 poker_zkvm，在 zkvm 完成完整的一手牌，记录耗时日志评估 zkvm 性能。

1. **Phase E Bug 修复**（NEW，最高优先级）— JSON 摘要的 `--- PERF_SUMMARY_JSON ---` 标记被 tracing 后续写入覆盖
2. **Phase D.1** — poker_rpc_demo.rs 8 个 fn + 5 个 const 改 `pub(crate)`
3. **Phase D.2** — 实现 `create_onchain_table_and_extract_cards`（5-tx 链上流程）
4. **Phase E 最终验证** — 19 个性能字段完整性检查

## Current State Analysis

### 已完成（验证通过）

[src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs)（790 行）：
- `PerfSummary` / `SigmaStageTimings` / `Rv32iStageTimings` 结构体完整（10 + 9 字段）
- `run_shuffle_protocol` — 5 个 sigma proof + 解密查表，input_cts 用标准 ElGamal 加密
- `run_rv32i_eval_and_compare` — P1/P2 评估 + 比较，每步 prove + verify + 测时
- `run_full_hand` — 调用链 D → C → B 完整
- `write_perf_summary` — 追加 `--- PERF_SUMMARY_JSON ---` 段（但被 bug 覆盖）

C.5 运行结果（`/tmp/zkvm_poker_perf_local.log`，37 行）：
```
[sigma] ZKShuffleProof:        prove=   9.73ms verify=  2.68ms ok=true
[sigma] RevealTokenProof:      prove=   0.19ms verify=  0.24ms ok=true
[sigma] ReconstructProof:      prove=   3.69ms verify=  2.49ms ok=true
[sigma] RemaskProof:           prove=   0.71ms verify=  0.69ms ok=true
[sigma] LeaveProof:            prove=   0.67ms verify=  0.70ms ok=true
[rv32i] P1 eval:     prove= 749.54ms verify=157.14ms size=  6990B score=0x0C00
[rv32i] P2 eval:     prove= 854.97ms verify=163.74ms size=  6990B score=0x0E00
[rv32i] compare:     prove= 775.51ms verify=247.59ms size=  6990B winner=P2
✓ zkvm 完整一手牌完成，总耗时: 2980.39 ms，赢家: P2
```

### Phase E Bug 根因分析（本次会话新发现）

**现象**：`grep PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_local.log` 返回空，但日志末尾有 JSON 尾部（`"total_time_ms": 2980.386958, "winner": 2`）。

**根因**：[src/poker_zkvm_demo.rs:302-307](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L302) 的 `init_tracing_with_file` 用 `.create(true).write(true).truncate(true)` 打开文件（**非 O_APPEND**），tracing 写入走文件位置指针（从 0 开始递增）。而 [src/poker_zkvm_demo.rs:783-786](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L783) 的 `write_perf_summary` 用 `.append(true)` 打开同一文件（O_APPEND，写到末尾）。

**覆盖时序**：
1. `write_perf_summary` 在 [line 280](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L280) 调用，在文件末尾追加 marker + JSON
2. 紧接着 [line 282-288](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L282) 的 final info!() 块通过 tracing 写入到**原文件位置**（非末尾），覆盖了 marker + JSON 开头
3. 由于 JSON 比较长，只有 marker 和 JSON 开头被覆盖，尾部（`total_time_ms` / `winner`）幸存

**修复方案**：两处协同修复
- 修复 1：`init_tracing_with_file` 增加 `.append(true)`（与 `.truncate(true)` 共存：先截断为 0，后续写入均走 O_APPEND 到末尾）
- 修复 2：将 `write_perf_summary(&log_path)?;` 从 [line 280](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L280) 移到 final info!() 块之后（[line 288](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L288) 之后），确保所有 tracing 写入完成后再追加 JSON

### Phase D 待实现

- **D.1**：[src/poker_rpc_demo.rs](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs) 8 个 RPC helper 仍为私有 `fn`，5 个常量为私有 `const`
- **D.2**：[src/poker_zkvm_demo.rs:375-382](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L375) 的 `create_onchain_table_and_extract_cards` 仍为 stub（返回 `Err("Phase D 尚未实现")`）

### 链上数据源 API 已二次验证

- [poker_l1/src/vm/contracts/texas_poker/dispatch.rs:69/84/94](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/dispatch.rs#L69) — `selectors::create_table() / join_table() / start_hand()` 返回 `[u8; 32]`
- [poker_l1/src/vm/contracts/texas_poker/dispatch.rs:189/236](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/dispatch.rs#L189) — `CreateTableArgs { name, max_players, small_blind, big_blind }` / `JoinTableArgs { player, buy_in, pk }`
- [poker_l1/src/vm/contracts/texas_poker/types.rs:439-494](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs#L439) — `TexasPokerTable` 含 `name / max_players / small_blind / big_blind / seats / shuffle_state.phase / deck_state.encrypted`
- [poker_l1/src/vm/contracts/texas_poker/types.rs:93-118](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs#L93) — `Seat` 含 `player / stack / is_occupied()`
- [poker_l1/src/vm/contracts/texas_poker/constants.rs:42](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/constants.rs#L42) — `SHUFFLE_PHASE_BEFORE_PREFLOP: u8 = 3`

## Proposed Changes

### Phase E Bug 修复：JSON 摘要标记覆盖（最高优先级）

**文件**：[src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs)

**修复 1**：`init_tracing_with_file` 的 OpenOptions 增加 `.append(true)`

修改 [line 302-307](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L302)：
```rust
// 修改前
let file = OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true)
    .open(log_path)
    .map_err(|e| format!("打开日志文件 {} 失败：{e}", log_path.display()))?;

// 修改后
let file = OpenOptions::new()
    .create(true)
    .write(true)
    .append(true)   // O_APPEND：所有写入走文件末尾，避免与 write_perf_summary 的 append 写入互相覆盖
    .truncate(true) // O_TRUNC：打开时截断为 0（与 append 共存：截断后所有写入均追加到末尾）
    .open(log_path)
    .map_err(|e| format!("打开日志文件 {} 失败：{e}", log_path.display()))?;
```

**原理**：`.append(true)` 设置 O_APPEND 标志，所有写入（含 tracing layer 的 Mutex<File>）都走文件末尾，与 `write_perf_summary` 的 `.append(true)` 一致，彻底消除位置冲突。

**修复 2**：将 `write_perf_summary` 调用移到 final info!() 块之后

修改 [line 274-290](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L274)：
```rust
// 修改前（line 274-290）
let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

// 写入 JSON 摘要
{
    let mut s = perf_summary().lock().map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
    s.total_time_ms = total_ms;
    s.winner = winner;
}
write_perf_summary(&log_path)?;   // ← 移走

info!("");
info!("╔══════════════════════════════════════════════════════════╗");
info!("║  ✓ zkvm 完整一手牌完成                                   ║");
info!("║    总耗时: {total_ms:.2} ms                                ");
info!("║    赢家: P{winner}                                          ");
info!("║    日志: {}                          ", log_path.display());
info!("╚══════════════════════════════════════════════════════════╝");

Ok(())

// 修改后
let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

// 更新 PerfSummary 总字段
{
    let mut s = perf_summary().lock().map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
    s.total_time_ms = total_ms;
    s.winner = winner;
}

info!("");
info!("╔══════════════════════════════════════════════════════════╗");
info!("║  ✓ zkvm 完整一手牌完成                                   ║");
info!("║    总耗时: {total_ms:.2} ms                                ");
info!("║    赢家: P{winner}                                          ");
info!("║    日志: {}                          ", log_path.display());
info!("╚══════════════════════════════════════════════════════════╝");

// 所有 tracing 写入完成后，最后追加 JSON 摘要（避免被后续 tracing 写入覆盖）
write_perf_summary(&log_path)?;

Ok(())
```

**验证**：
```bash
cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log
grep -A 30 PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_local.log
# 期望：输出完整 JSON，含 19 个性能字段
```

---

### Phase D.1: poker_rpc_demo.rs 8 fn + 5 const 改 pub(crate)

**文件**：[src/poker_rpc_demo.rs](file:///Users/mac/projects/zchain/src/poker_rpc_demo.rs)

**修改**：8 个函数签名前缀由 `fn` 改为 `pub(crate) fn`，5 个常量前缀由 `const` 改为 `pub(crate) const`：

| 行号 | 名称 | 修改前 | 修改后 |
|------|------|--------|--------|
| 45 | `RPC_TIMEOUT` | `const RPC_TIMEOUT` | `pub(crate) const RPC_TIMEOUT` |
| 48 | `BLOCK_WAIT_INTERVAL` | `const BLOCK_WAIT_INTERVAL` | `pub(crate) const BLOCK_WAIT_INTERVAL` |
| 51 | `BLOCK_WAIT_MAX` | `const BLOCK_WAIT_MAX` | `pub(crate) const BLOCK_WAIT_MAX` |
| 54 | `PLAYER1` | `const PLAYER1` | `pub(crate) const PLAYER1` |
| 56 | `PLAYER2` | `const PLAYER2` | `pub(crate) const PLAYER2` |
| 293 | `build_signed_tx` | `#[allow(clippy::too_many_arguments)]\nfn build_signed_tx(` | `#[allow(clippy::too_many_arguments)]\npub(crate) fn build_signed_tx(` |
| 336 | `submit_tx_via_rpc` | `fn submit_tx_via_rpc(` | `pub(crate) fn submit_tx_via_rpc(` |
| 365 | `wait_for_block_with_tx` | `fn wait_for_block_with_tx(` | `pub(crate) fn wait_for_block_with_tx(` |
| 403 | `query_block_by_height` | `fn query_block_by_height(` | `pub(crate) fn query_block_by_height(` |
| 430 | `query_chain_id` | `fn query_chain_id(` | `pub(crate) fn query_chain_id(` |
| 437 | `query_table_state` | `fn query_table_state(` | `pub(crate) fn query_table_state(` |
| 461 | `verify_table_state` | `fn verify_table_state(` | `pub(crate) fn verify_table_state(` |
| 477 | `rpc_call` | `fn rpc_call(` | `pub(crate) fn rpc_call(` |

**原因**：`poker_zkvm_demo.rs::create_onchain_table_and_extract_cards` 需复用这些 RPC helper 完成 5-tx 链上桌子创建流程。`poker_rpc_demo` 与 `poker_zkvm_demo` 是同 crate 内的兄弟模块（均在 `src/` 下），`pub(crate)` 即可访问。

**验证**：`cargo check -p zchain` 应通过（无新增 errors）。

---

### Phase D.2: 实现 `create_onchain_table_and_extract_cards`

**文件**：[src/poker_zkvm_demo.rs](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs)（替换 [line 370-382](file:///Users/mac/projects/zchain/src/poker_zkvm_demo.rs#L370) 的 stub）

**实现策略**（基于已批准的简化策略）：
- 链上仅作"牌序权威源"——验证 table 已创建、phase==3、52 张加密牌已初始化
- 本地 `run_shuffle_protocol` 使用 `generate_plaintext_cards()` 重建密文（不依赖链上 encrypted 字段的具体值）
- 返回 `Vec<u8>` = `(0..deck_size).collect()`（链上 set_initial_encrypted_deck 写入顺序为 0..51）

**实现代码**（替换 stub）：

```rust
// ===== Phase D: 链上 RPC 集成 =====

/// 通过 RPC 创建链上桌子并提取牌序。
///
/// 流程：create_table → join_table ×2 → start_hand → 校验 phase==3
/// 返回 `(0..deck_size).collect::<Vec<u8>>()` 作为牌序索引（链上 set_initial_encrypted_deck 按 0..51 顺序写入）。
fn create_onchain_table_and_extract_cards(
    rpc_listen: &str,
    deck_size: usize,
) -> Result<Vec<u8>, String> {
    use crate::poker_rpc_demo::{
        build_signed_tx, query_chain_id, query_table_state, submit_tx_via_rpc,
        verify_table_state, wait_for_block_with_tx, PLAYER1, PLAYER2,
    };
    use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
    use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
    use poker_l1::vm::contracts::texas_poker::dispatch::{selectors, CreateTableArgs, JoinTableArgs};
    use poker_l1::vm::precompile::reserved::texas_poker_contract_id;
    use poker_protocol::crypto::types::ECPoint;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};

    info!("  [chain] RPC endpoint: {rpc_listen}");
    info!("  [chain] 目标合约: texas_poker (ObjectID = {:?})", texas_poker_contract_id());

    // 1. 生成 secp256k1 密钥对（签名所有 tx）
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let compressed = public_key.serialize();
    let tagged_pubkey =
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, compressed.to_vec())
            .map_err(|e| format!("构造 tagged_pubkey 失败：{e}"))?;
    info!("  [chain] signer tagged_pubkey raw={}B", tagged_pubkey.raw.len());

    // 2. 查询 chain_id（节点默认 = DEFAULT_CHAIN_ID）
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
    }

    Ok(card_seq)
}
```

**注意事项**：
- `build_signed_tx` 签名包含 `gameturn_nonce` 参数（第 8 个参数，传 0）— TexasPokerPrecompile::is_gas_free()=true，走 GameTurn 通道跳过 nonce 预检
- `ECPoint(blstrs::G1Projective::identity())` / `ECPoint(blstrs::G1Projective::generator())` — JoinTableArgs.pk 字段类型为 `ECPoint`（newtype 包装 `G1Projective`）
- `blstrs::G1Projective::generator()` 需要 `group::Group` trait 在作用域内（poker_rpc_demo.rs 已 import，本函数内需 `use group::Group` 或直接用完整路径）
- 此函数**不调用 reset_for_next_hand**——保留 table 在 `BEFORE_PREFLOP` 状态以便后续真实牌局

**验证**：
```bash
# 终端 1：启动本地节点
cargo run -p zchain --release -- node --validator --rpc-listen 127.0.0.1:8545

# 终端 2：运行 onchain 模式
cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log
# 期望：4 个链上 tx 全部确认 + 5 sigma + 3 rv32i 全部 ok=true
```

**降级策略**：若链上 RPC 不可用（节点未启动），用户可继续用 `--local-only` 跑通 zkvm 性能评估（用户主要目标）。

---

### Phase E 最终验证: JSON 摘要完整性

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
    "shuffle_prove_ms": 9.73,
    "shuffle_verify_ms": 2.68,
    "reveal_prove_ms": 0.19,
    "reveal_verify_ms": 0.24,
    "reconstruct_prove_ms": 3.69,
    "reconstruct_verify_ms": 2.49,
    "remask_prove_ms": 0.71,
    "remask_verify_ms": 0.69,
    "leave_prove_ms": 0.67,
    "leave_verify_ms": 0.70
  },
  "rv32i_stage": {
    "eval_p1_prove_ms": 749.54,
    "eval_p1_verify_ms": 157.14,
    "eval_p1_proof_size_bytes": 6990,
    "eval_p2_prove_ms": 854.97,
    "eval_p2_verify_ms": 163.74,
    "eval_p2_proof_size_bytes": 6990,
    "compare_prove_ms": 775.51,
    "compare_verify_ms": 247.59,
    "compare_proof_size_bytes": 6990
  },
  "total_time_ms": 2980.39,
  "winner": 2
}
```

**验证命令**：
```bash
# 1. 标记存在性
grep -c PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_local.log
# 期望：1

# 2. 完整 JSON 输出
grep -A 30 PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_local.log

# 3. 19 个性能字段计数
grep -oE '"(shuffle|reveal|reconstruct|remask|leave|eval_p1|eval_p2|compare)_(prove|verify)_ms"|"eval_p[12]_proof_size_bytes"|"compare_proof_size_bytes"' /tmp/zkvm_poker_perf_local.log | sort -u | wc -l
# 期望：19（10 sigma prove/verify + 6 rv32i prove/verify + 3 proof_size_bytes）
```

## Assumptions & Decisions

1. **不需要再次问用户**：所有关键决策（曲线分工、sigma 范围、牌序映射、prove/verify 分工、链上角色、日志方式）在前序会话已通过 AskUserQuestion 批准
2. **input_cts 修复已就位**：标准 ElGamal 加密 `Enc(m, pk, r) = (G*r, m + pk*r)`，与 `reconstruct_deck` 的 `decrypt(sk) = c2 - c1*sk = m` 兼容（C.5 已验证通过）
3. **链上 encrypted 字段不直接复用**：链上 `set_initial_encrypted_deck` 用 `(G, plaintext)` 简化形式（sk=0 等价），本地用标准加密模拟真实洗牌前的初始牌组——两者都是合法 ElGamal 密文，但本地版本更接近真实场景
4. **链上 table 不重置**：`create_onchain_table_and_extract_cards` 不调用 `reset_for_next_hand`，保留 `BEFORE_PREFLOP` 状态以便后续真实牌局
5. **降级策略**：若 Phase D 链上 RPC 不可用，`--local-only` 模式仍可端到端验证 zkvm 性能（用户主要目标）
6. **Phase E Bug 修复优先级最高**：即使 D.2 链上模式不可用，E Bug 修复也能确保 `--local-only` 模式的 JSON 摘要正确输出，达成"记录耗时日志以评估 zkvm 性能"目标
7. **`.append(true)` + `.truncate(true)` 共存语义**：Rust OpenOptions 允许同时设置 O_APPEND 和 O_TRUNC；O_TRUNC 在 open 时截断文件为 0，O_APPEND 使后续每次 write 走文件末尾。两者组合等价于"打开时清空，后续写入均追加"

## Verification Steps

| Phase | 验证命令 | 期望结果 |
|-------|---------|---------|
| E Bug 修复 | `cargo run -p zchain --release -- poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log` | 退出码 0，5 sigma + 3 rv32i 全部 ok=true |
| E Bug 修复 | `grep -c PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_local.log` | 输出 1（标记存在） |
| E Bug 修复 | `grep -oE '"(shuffle\|reveal\|reconstruct\|remask\|leave\|eval_p1\|eval_p2\|compare)_(prove\|verify)_ms"' /tmp/zkvm_poker_perf_local.log \| sort -u \| wc -l` | 输出 16（10 sigma + 6 rv32i prove/verify） |
| E Bug 修复 | `grep -oE '"eval_p[12]_proof_size_bytes"\|"compare_proof_size_bytes"' /tmp/zkvm_poker_perf_local.log \| sort -u \| wc -l` | 输出 3（3 个 proof_size_bytes） |
| D.1 | `cargo check -p zchain` | 编译通过，无新增 errors |
| D.2 | 启动节点 + `cargo run -p zchain --release -- poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log` | 链上 4-tx 流程成功 + sigma + rv32i 全部 ok=true |
| E 最终 | `grep -A 30 PERF_SUMMARY_JSON /tmp/zkvm_poker_perf_onchain.log` | JSON 含 19 个性能字段 + onchain_table_id/onchain_tx_count 非 null |

## Implementation Order

```
Phase E Bug 修复: init_tracing_with_file + write_perf_summary 调用位置    ← 起点（最高优先级）
   ↓
Phase E Bug 验证: cargo run --local-only + grep PERF_SUMMARY_JSON
   ↓
Phase D.1: poker_rpc_demo.rs 8 fn + 5 const 改 pub(crate)
   ↓
Phase D.1 验证: cargo check -p zchain
   ↓
Phase D.2: 实现 create_onchain_table_and_extract_cards
   ↓
Phase D.2 验证: 启动节点 + cargo run --rpc 127.0.0.1:8545
   ↓
Phase E 最终验证: 19 个性能字段完整性检查
```

## Notes

- **Phase E Bug 修复是关键**：即使不实施 D.1/D.2，仅修复 E Bug 即可让 `--local-only` 模式正确输出 JSON 摘要，达成用户"记录耗时日志以评估 zkvm 性能"的核心目标
- **D.2 可选**：若链上节点启动困难或 RPC 调试耗时过长，可优先确保 E Bug 修复 + D.1 + 本地模式验证通过（用户主要目标已达成），D.2 作为增强功能后置
- **O_APPEND 兼容性**：`.append(true)` + `.truncate(true)` 在 Linux/macOS 上语义明确，Windows 上行为一致（R