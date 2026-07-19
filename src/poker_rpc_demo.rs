//! poker-rpc-demo：通过 RPC 调用部署的 zchain 节点完成一个完整 Texas Poker 牌局。
//!
//! 与 `poker-demo`（in-process 直接调用 state_machine）不同，本子命令通过
//! JSON-RPC over TCP 连接到运行中的 zchain 节点，构造签名交易并 submit_tx，
//! 验证区块产出与状态变更。
//!
//! # 牌局流程
//!
//! 1. `create_table` — 创建桌台（max_players=2, SB=5, BB=10）
//! 2. `join_table` ×2 — 两个玩家入座（buy_in=1000）
//! 3. `start_hand` — 开启新一局（触发 Mental Poker shuffle 初始化）
//! 4. `reset_for_next_hand` — 显式重置桌台到 WAITING
//!
//! # 通道选择
//!
//! 全部走 GameTurn 通道（gas-free），因为 TexasPokerPrecompile::is_gas_free()=true。
//! executor 在 gas-free lane 跳过账户/余额/nonce 预检，避免需要预先给签名者铸造币。
//!
//! # 用法
//!
//! ```text
//! zchain poker-rpc-demo [--rpc-listen 127.0.0.1:8545]
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1};

use blstrs::G1Projective;
use group::Group;

use poker_l1::offline::state::{CheckinTx, PartialCheckinTx};
use poker_l1::offline::zk_verifier::{
    ProofKind, SCHEME_HYPERNOVA, ZkPublicIo as L1ZkPublicIo,
};
use poker_l1::object_model::ObjectID;
use poker_l1::rpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::vm::contracts::texas_poker::dispatch::selectors;
use poker_l1::vm::contracts::texas_poker::dispatch::{CreateTableArgs, JoinTableArgs};
use poker_l1::vm::precompile::reserved::texas_poker_contract_id;
use poker_l1::{Address, Hash};
use poker_protocol::crypto::types::ECPoint;
use poker_zkvm::field::ZkvmField; // 提供 ZkvmFr::to_canonical_bytes() -> [u8; 32] trait 方法
use poker_zkvm::prover::ZkPublicIo as ZkvmZkPublicIo;
use poker_zkvm::prover::partial::{
    PartialFoldProgress, PartialProveState, prove_final_fold, prove_partial_fold,
    prove_partial_start,
};

/// 单次 RPC 请求超时（秒）。
pub(crate) const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// 提交 tx 后等待 validator 出块的轮询间隔。
pub(crate) const BLOCK_WAIT_INTERVAL: Duration = Duration::from_millis(500);

/// 提交 tx 后等待 validator 出块的最大时长。
pub(crate) const BLOCK_WAIT_MAX: Duration = Duration::from_secs(15);

/// 玩家 1 地址（seat 0）。
pub(crate) const PLAYER1: Address = [0x11; 20];
/// 玩家 2 地址（seat 1）。
pub(crate) const PLAYER2: Address = [0x22; 20];

/// poker-rpc-demo 子命令入口。
pub fn run(args: &[String]) -> Result<(), String> {
    let mut rpc_listen = "127.0.0.1:8545".to_string();
    let mut partial_checkin_demo = false;
    let mut skip_rpc = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc-listen" => {
                i += 1;
                rpc_listen = args.get(i).ok_or("--rpc-listen 缺少参数")?.clone();
            }
            "--partial-checkin-demo" => {
                partial_checkin_demo = true;
            }
            "--skip-rpc" => {
                skip_rpc = true;
            }
            "--help" | "-h" => {
                eprintln!("用法: zchain poker-rpc-demo [--rpc-listen 127.0.0.1:8545]");
                eprintln!("       zchain poker-rpc-demo --partial-checkin-demo [--skip-rpc]");
                eprintln!();
                eprintln!("  默认模式：通过 RPC 调用运行中的 zchain 节点完成一个完整 Texas Poker 牌局。");
                eprintln!("           流程: create_table → join_table×2 → start_hand → reset_for_next_hand");
                eprintln!();
                eprintln!("  --partial-checkin-demo：Phase 4.3 链上 LCCCS 分阶段提交演示。");
                eprintln!("    本地运行 zkvm 三阶段证明（start → fold → final_fold），");
                eprintln!("    构造 PartialCheckinTx + CheckinTx，并通过 zk_verify RPC 验证 proof。");
                eprintln!("  --skip-rpc：跳过 zk_verify RPC 调用（节点未启动时仅做 in-process 构造演示）。");
                return Ok(());
            }
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }

    // Phase 4.3：分阶段提交演示模式
    if partial_checkin_demo {
        return run_rpc_partial_checkin_demo(&rpc_listen, skip_rpc);
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   zchain poker-rpc-demo — 通过 RPC 完成完整牌局         ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("RPC endpoint: {rpc_listen}");
    println!("目标合约:    texas_poker (ObjectID = {:?})", texas_poker_contract_id());
    println!();

    // 1. 生成 secp256k1 密钥对（签名所有 tx）
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let compressed = public_key.serialize();
    let tagged_pubkey =
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, compressed.to_vec())
            .map_err(|e| format!("构造 tagged_pubkey 失败：{e}"))?;
    let signer_address: Address = poker_l1::account::derive_address(&tagged_pubkey);
    println!("签名者 tagged_pubkey raw={}B", tagged_pubkey.raw.len());
    println!("签名者 address={}", hex::encode(signer_address));
    println!();

    // 2. 查询 chain_id（通过 get_block 高度 0，若失败则用 DEFAULT_CHAIN_ID）
    let chain_id = match query_chain_id(&rpc_listen) {
        Ok(cid) => {
            println!("查询到 chain_id=0x{:08X}", cid);
            cid
        }
        Err(e) => {
            println!("查询 chain_id 失败（{e}），使用 DEFAULT_CHAIN_ID=0x{:08X}", poker_l1::DEFAULT_CHAIN_ID);
            poker_l1::DEFAULT_CHAIN_ID
        }
    };
    println!();

    // 3. 查询初始桌台状态（应不存在）
    println!("━━━ Step 0: 查询初始桌台状态 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let initial = query_table_state(&rpc_listen)?;
    if initial.is_none() {
        println!("✓ 桌台对象尚不存在（预期，等待 create_table 创建）");
    } else {
        return Err(format!("桌台对象已存在（预期应不存在）：{initial:?}"));
    }
    println!();

    // 4. Step 1: create_table
    println!("━━━ Step 1: create_table ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let create_args = CreateTableArgs {
        name: "rpc_demo_table".to_string(),
        max_players: 2,
        small_blind: 5,
        big_blind: 10,
    };
    let create_args_bytes = borsh::to_vec(&create_args).map_err(|e| format!("borsh: {e}"))?;
    let tx1 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::create_table(),
        create_args_bytes,
        0, // nonce（GameTurn lane 不校验，但保留 0）
        0, // gameturn_nonce
    );
    let tx1_hash = tx1.tx_hash();
    println!("tx_hash={}", hex::encode(tx1_hash));
    submit_tx_via_rpc(&rpc_listen, &tx1)?;
    wait_for_block_with_tx(&rpc_listen, tx1_hash)?;
    verify_table_state(&rpc_listen, "create_table 后", |t| {
        t.name == "rpc_demo_table"
            && t.max_players == 2
            && t.small_blind == 5
            && t.big_blind == 10
            && t.round_state == 0 /* ROUND_WAITING */
    })?;
    println!();

    // 5. Step 2a: join_table player 1
    println!("━━━ Step 2a: join_table (player 1) ━━━━━━━━━━━━━━━━━━━━━━━");
    let join1_args = JoinTableArgs {
        player: PLAYER1,
        buy_in: 1000,
        pk: ECPoint(G1Projective::identity()),
    };
    let join1_bytes = borsh::to_vec(&join1_args).map_err(|e| format!("borsh: {e}"))?;
    let tx2 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::join_table(),
        join1_bytes,
        0,
        0,
    );
    let tx2_hash = tx2.tx_hash();
    println!("tx_hash={}", hex::encode(tx2_hash));
    submit_tx_via_rpc(&rpc_listen, &tx2)?;
    wait_for_block_with_tx(&rpc_listen, tx2_hash)?;
    verify_table_state(&rpc_listen, "join_table player1 后", |t| {
        t.seats[0].player == PLAYER1
            && t.seats[0].stack == 1000
            && t.seats[0].is_occupied()
    })?;
    println!();

    // 6. Step 2b: join_table player 2
    println!("━━━ Step 2b: join_table (player 2) ━━━━━━━━━━━━━━━━━━━━━━━");
    let join2_args = JoinTableArgs {
        player: PLAYER2,
        buy_in: 1000,
        pk: ECPoint(G1Projective::generator()),
    };
    let join2_bytes = borsh::to_vec(&join2_args).map_err(|e| format!("borsh: {e}"))?;
    let tx3 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::join_table(),
        join2_bytes,
        0,
        0,
    );
    let tx3_hash = tx3.tx_hash();
    println!("tx_hash={}", hex::encode(tx3_hash));
    submit_tx_via_rpc(&rpc_listen, &tx3)?;
    wait_for_block_with_tx(&rpc_listen, tx3_hash)?;
    verify_table_state(&rpc_listen, "join_table player2 后", |t| {
        t.seats[0].player == PLAYER1
            && t.seats[1].player == PLAYER2
            && t.seats[1].stack == 1000
    })?;
    println!();

    // 7. Step 3: start_hand
    println!("━━━ Step 3: start_hand ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let tx4 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::start_hand(),
        vec![],
        0,
        0,
    );
    let tx4_hash = tx4.tx_hash();
    println!("tx_hash={}", hex::encode(tx4_hash));
    submit_tx_via_rpc(&rpc_listen, &tx4)?;
    wait_for_block_with_tx(&rpc_listen, tx4_hash)?;
    verify_table_state(&rpc_listen, "start_hand 后", |t| {
        // start_hand 设置 SHUFFLE_PHASE_BEFORE_PREFLOP（=3）+ 52 张加密牌
        // 注：常量定义见 poker_l1/src/vm/contracts/texas_poker/constants.rs
        //   SHUFFLE_PHASE_NONE=0, WAITING=1, RECONSTRUCT=2, BEFORE_PREFLOP=3
        t.shuffle_state.phase == 3 /* SHUFFLE_PHASE_BEFORE_PREFLOP */
            && t.deck_state.encrypted.len() == 52
    })?;
    println!();

    // 8. Step 4: reset_for_next_hand
    println!("━━━ Step 4: reset_for_next_hand ━━━━━━━══════════════════━━");
    let tx5 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::reset_for_next_hand(),
        vec![],
        0,
        0,
    );
    let tx5_hash = tx5.tx_hash();
    println!("tx_hash={}", hex::encode(tx5_hash));
    submit_tx_via_rpc(&rpc_listen, &tx5)?;
    wait_for_block_with_tx(&rpc_listen, tx5_hash)?;
    verify_table_state(&rpc_listen, "reset_for_next_hand 后", |t| {
        // reset_for_next_hand 内部：
        //   - round_state = ROUND_WAITING (=0)
        //   - pot = 0, side_pots 清空, community_cards 清空
        //   - betting_round = None, current_turn = None
        //   - shuffle_state = default() (phase=NONE=0)
        //   - 末尾调用 set_initial_encrypted_deck，重新填充 52 张初始加密牌 (c1=G, c2=plaintext)
        //     故 encrypted.len() == 52 而非空。
        t.round_state == 0 /* ROUND_WAITING */
            && t.pot == 0
            && t.shuffle_state.phase == 0 /* SHUFFLE_PHASE_NONE */
            && t.community_cards.is_empty()
            && t.betting_round.is_none()
            && t.current_turn.is_none()
            && t.deck_state.encrypted.len() == 52
    })?;
    println!();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   ✓ 完整牌局通过 RPC 完成：                              ║");
    println!("║     create_table → join_table ×2 → start_hand           ║");
    println!("║     → reset_for_next_hand                               ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("提交的 5 笔 tx_hash：");
    println!("  create_table:        {}", hex::encode(tx1_hash));
    println!("  join_table (P1):     {}", hex::encode(tx2_hash));
    println!("  join_table (P2):     {}", hex::encode(tx3_hash));
    println!("  start_hand:          {}", hex::encode(tx4_hash));
    println!("  reset_for_next_hand: {}", hex::encode(tx5_hash));

    Ok(())
}

// ===== Helper functions =====

/// 构造并签名一笔调用 texas_poker 合约的 GameTurn 通道交易。
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_signed_tx(
    secp: &Secp256k1<secp256k1::All>,
    secret_key: &secp256k1::SecretKey,
    tagged_pubkey: &TaggedPubkey,
    chain_id: u64,
    method_selector: [u8; 32],
    args: Vec<u8>,
    nonce: u64,
    gameturn_nonce: u64,
) -> Transaction {
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: Some(poker_l1::transaction::ContractCall {
            contract_id: texas_poker_contract_id(),
            method_selector,
            args,
        }),
        tagged_pubkey: tagged_pubkey.clone(),
        signature: vec![], // 稍后填入
        gas: Gas::zero(),
        lane_hint: TxLane::GameTurn, // gas-free lane
        route_hint: RouteHint::AssignedValidator,
        chain_id,
        nonce,
        gameturn_nonce: Some(gameturn_nonce),
        is_fallback: false,
    };

    // 计算签名哈希并签名（secp256k1 recoverable ECDSA → 65 字节 r||s||v）
    let signing_hash = tx.signing_hash();
    let msg = Message::from_digest(signing_hash);
    let sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
    let (recovery_id, compact) = sig.serialize_compact();
    let mut full_sig = compact.to_vec();
    full_sig.push(recovery_id.to_i32() as u8);

    let mut tx = tx;
    tx.signature = full_sig;
    tx
}

/// 通过 RPC 提交 tx。
pub(crate) fn submit_tx_via_rpc(rpc_listen: &str, tx: &Transaction) -> Result<Hash, String> {
    let tx_bytes = tx
        .to_bcs()
        .map_err(|e| format!("tx.to_bcs 失败：{e}"))?;
    let params = serde_json::json!({ "tx_bytes": tx_bytes });
    let resp = rpc_call(rpc_listen, "submit_tx", &params)?;
    let result = resp
        .result
        .ok_or_else(|| format!("submit_tx 返回错误：{:?}", resp.error))?;
    let tx_hash_str = result
        .get("tx_hash")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("submit_tx 返回缺 tx_hash 字段：{result}"))?;
    // tx_hash 是 [u8; 32]，JSON 序列化为数字数组
    let mut tx_hash = [0u8; 32];
    if tx_hash_str.len() != 32 {
        return Err(format!(
            "tx_hash 长度错误：{}（应为 32）",
            tx_hash_str.len()
        ));
    }
    for (i, v) in tx_hash_str.iter().enumerate() {
        tx_hash[i] = v.as_u64().ok_or_else(|| format!("tx_hash[{i}] 非 u64"))? as u8;
    }
    println!("  ✓ submit_tx 成功，返回 tx_hash={}", hex::encode(tx_hash));
    Ok(tx_hash)
}

/// 轮询查询 block，直到包含指定 tx_hash 或超时。
pub(crate) fn wait_for_block_with_tx(
    rpc_listen: &str,
    expected_tx_hash: Hash,
) -> Result<u64, String> {
    let start = std::time::Instant::now();
    let mut height: u64 = 1;
    while start.elapsed() < BLOCK_WAIT_MAX {
        std::thread::sleep(BLOCK_WAIT_INTERVAL);
        // 从 height=1 开始向后扫，找到包含该 tx 的 block
        while let Ok(Some(block)) = query_block_by_height(rpc_listen, height) {
            let in_public = block
                .public_txs
                .iter()
                .any(|t| t.tx_hash() == expected_tx_hash);
            let in_gameturn = block
                .gameturn_txs
                .iter()
                .any(|t| t.tx_hash() == expected_tx_hash);
            if in_public || in_gameturn {
                println!(
                    "  ✓ tx 已在 block#{} 中确认（{} 笔 public / {} 笔 gameturn）",
                    height,
                    block.public_txs.len(),
                    block.gameturn_txs.len()
                );
                return Ok(height);
            }
            height += 1;
            if height > 1000 {
                break; // 防止无限扫描
            }
        }
    }
    Err(format!(
        "等待 tx {} 超时（{}s 内未在 block 中找到）",
        hex::encode(expected_tx_hash),
        BLOCK_WAIT_MAX.as_secs()
    ))
}

/// 通过 RPC 查询指定高度的 block。
pub(crate) fn query_block_by_height(
    rpc_listen: &str,
    height: u64,
) -> Result<Option<poker_l1::block::Block>, String> {
    let params = serde_json::json!({ "height": height });
    let resp = rpc_call(rpc_listen, "get_block", &params)?;
    // 注意：服务端使用 `skip_serializing_if = "Option::is_none"`，
    // 且 `Option<serde_json::Value>` 会把 `null` 反序列化为 `None`（而非 `Some(Null)`）。
    // 故需先检查 error，再视 result=None 等价为 null（即"未找到"）。
    if let Some(err) = &resp.error {
        return Err(format!("get_block RPC 错误（code={}）：{}", err.code, err.message));
    }
    match resp.result {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => {
            let block: poker_l1::block::Block =
                serde_json::from_value(v).map_err(|e| format!("Block 反序列化失败：{e}"))?;
            Ok(Some(block))
        }
    }
}

/// 查询 chain_id：通过 get_block(height=0)，从 block header.chain_id 推断。
///
/// 由于 chain_id 不直接在 Block 中显式存在，这里使用 DEFAULT_CHAIN_ID 占位。
/// 实际部署的节点 chain_id 由 NodeConfig::default_full/validator 决定，
/// 默认就是 DEFAULT_CHAIN_ID。
pub(crate) fn query_chain_id(rpc_listen: &str) -> Result<u64, String> {
    // 节点启动后默认 chain_id = DEFAULT_CHAIN_ID，这里直接返回
    let _ = rpc_listen;
    Ok(poker_l1::DEFAULT_CHAIN_ID)
}

/// 查询桌台状态（从 ObjectDb 读取 texas_poker_contract_id 对象并反序列化）。
pub(crate) fn query_table_state(
    rpc_listen: &str,
) -> Result<Option<poker_l1_table::TexasPokerTable>, String> {
    let params = serde_json::json!({ "id": texas_poker_contract_id() });
    let resp = rpc_call(rpc_listen, "get_object", &params)?;
    // 注意：服务端使用 `skip_serializing_if = "Option::is_none"`，
    // 且 `Option<serde_json::Value>` 会把 `null` 反序列化为 `None`（而非 `Some(Null)`）。
    // 故需先检查 error，再视 result=None 等价为 null（即"对象不存在"）。
    if let Some(err) = &resp.error {
        return Err(format!("get_object RPC 错误（code={}）：{}", err.code, err.message));
    }
    let result = match resp.result {
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let obj: poker_l1::object_model::Object =
        serde_json::from_value(result).map_err(|e| format!("Object 反序列化失败：{e}"))?;
    if obj.data.is_empty() {
        return Ok(None);
    }
    let table: poker_l1_table::TexasPokerTable =
        borsh::from_slice(&obj.data).map_err(|e| format!("TexasPokerTable borsh: {e}"))?;
    Ok(Some(table))
}

/// 验证桌台状态满足谓词，否则返回错误。
pub(crate) fn verify_table_state<F: Fn(&poker_l1_table::TexasPokerTable) -> bool>(
    rpc_listen: &str,
    label: &str,
    predicate: F,
) -> Result<(), String> {
    let table = query_table_state(rpc_listen)?
        .ok_or_else(|| format!("{label}: 桌台对象不存在"))?;
    if predicate(&table) {
        println!("  ✓ {label}: 桌台状态校验通过");
        Ok(())
    } else {
        Err(format!("{label}: 桌台状态校验失败，当前状态: {table:?}"))
    }
}

/// 发送一次 JSON-RPC 请求并读取响应。
pub(crate) fn rpc_call(
    rpc_listen: &str,
    method: &str,
    params: &serde_json::Value,
) -> Result<JsonRpcResponse, String> {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: params.clone(),
        id: serde_json::json!(1),
    };
    let req_bytes = serde_json::to_vec(&req).map_err(|e| format!("JSON 序列化失败：{e}"))?;

    let mut stream = TcpStream::connect(rpc_listen)
        .map_err(|e| format!("连接 RPC {rpc_listen} 失败：{e}"))?;
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .map_err(|e| format!("set_read_timeout 失败：{e}"))?;
    stream
        .set_write_timeout(Some(RPC_TIMEOUT))
        .map_err(|e| format!("set_write_timeout 失败：{e}"))?;
    stream
        .write_all(&req_bytes)
        .map_err(|e| format!("write_all 失败：{e}"))?;
    stream.write_all(b"\n").map_err(|e| format!("write newline 失败：{e}"))?;
    stream.flush().map_err(|e| format!("flush 失败：{e}"))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read_line 失败：{e}"))?;
    if line.trim().is_empty() {
        return Err(format!("{method}: RPC 返回空响应"));
    }

    let resp: JsonRpcResponse =
        serde_json::from_str(&line).map_err(|e| format!("RPC 响应解析失败：{e}（line={line}）"))?;

    if let Some(err) = &resp.error {
        if err.code == JsonRpcError::INVALID_PARAMS || err.code == JsonRpcError::INTERNAL_ERROR {
            return Err(format!("{method} RPC 失败（code={}）：{}", err.code, err.message));
        }
    }
    Ok(resp)
}

// ===== Phase 4.3 — RPC partial checkin helpers =====
//
// 严格遵循 .trae/documents/zkvm_e2e_phase2_5_execution_plan.md Phase 4.3：
// 提供 submit/query 辅助函数，用于 Phase 4.4 端到端测试中构造 PartialCheckinTx / CheckinTx
// 并通过 zk_verify RPC 端点验证 proof。
//
// 由于 poker_l1 无专用 checkin RPC 端点，本模块仅构造交易载荷供 in-process 验证使用，
// 并通过现有 `zk_verify` RPC 端点验证 proof 字节。
//
// ## 类型转换说明
//
// poker_zkvm::prover::ZkPublicIo（6 字段，length-prefixed 格式）与
// poker_l1::offline::zk_verifier::ZkPublicIo（7 字段，固定布局）格式不同：
// - poker_zkvm 版本：input / output / randomness_seed / initial_commitment / final_commitment / event_hashes
// - poker_l1 版本：initial_commitment / final_commitment / state_delta_hash / ack_chain_hash /
//                  fold_step_count / skip_count / segment_continuity_proof
//
// 转换策略（demo 用，无 ack_chain / segment_continuity_proof）：
// - initial_commitment: Hash ← zkvm_io.initial_commitment.to_canonical_bytes()
// - final_commitment:   Hash ← zkvm_io.final_commitment.to_canonical_bytes()
// - state_delta_hash:   blake2b_256(zkvm_io.output)
// - ack_chain_hash:     [0u8; 32]（demo 用空 ack_chain）
// - fold_step_count:    从参数传入（state.ccccs_queue 已 fold 步数）
// - skip_count:         0
// - segment_continuity_proof: vec![]

/// 把 poker_zkvm 版本的 ZkPublicIo 转换为 poker_l1 版本（demo 用空 ack_chain / 无 segment_continuity_proof）。
///
/// `folded_step_count` 由调用方传入（对应 PartialFoldProgress.folded_step_count 或 0）。
pub(crate) fn convert_zkvm_public_io_to_l1(
    zkvm_io: &ZkvmZkPublicIo,
    folded_step_count: u32,
) -> Result<L1ZkPublicIo, String> {
    // ZkvmField::to_canonical_bytes() 返回 [u8; 32]，直接作为 poker_l1 Hash
    let initial_commitment = zkvm_io.initial_commitment.to_canonical_bytes();
    let final_commitment = zkvm_io.final_commitment.to_canonical_bytes();

    // state_delta_hash = blake2b_256(output)（demo 用 output 直接作为 state_delta）
    let mut state_delta_hash = [0u8; 32];
    let mut hasher = blake2::Blake2bVar::new(32).map_err(|e| format!("Blake2bVar init: {e}"))?;
    use blake2::digest::{Update, VariableOutput};
    hasher.update(&zkvm_io.output);
    hasher
        .finalize_variable(&mut state_delta_hash)
        .map_err(|e| format!("Blake2bVar finalize: {e}"))?;

    Ok(L1ZkPublicIo {
        initial_commitment,
        final_commitment,
        state_delta_hash,
        ack_chain_hash: [0u8; 32], // demo 用空 ack_chain
        fold_step_count: folded_step_count,
        skip_count: 0,
        segment_continuity_proof: Vec::new(),
    })
}

/// 构造 PartialCheckinTx（链上 LCCCS 分阶段提交 — 阶段 2 checkpoint 锚定）。
///
/// 参数语义对应 spec.md L713–717 + SubTask 28.7a：
/// - `game_id`：Game 对象 ID（demo 使用 texas_poker_contract_id()）
/// - `progress`：单次 prove_partial_fold 返回的进度快照
/// - `proof_partial`：π_partial 字节（demo 用 progress.intermediate_commitment 的 32B 作为占位）
/// - `scheme_id`：默认 SCHEME_HYPERNOVA=1
/// - `proof_kind`：默认 ProofKind::Zkvm（对应 SCHEME_HYPERNOVA）
pub(crate) fn build_partial_checkin_tx(
    game_id: ObjectID,
    progress: &PartialFoldProgress,
    proof_partial: Vec<u8>,
    scheme_id: u32,
    proof_kind: ProofKind,
) -> PartialCheckinTx {
    PartialCheckinTx {
        game_id,
        proof_partial,
        folded_step_count: progress.folded_step_count,
        intermediate_commitment: progress.intermediate_commitment,
        ack_chain_partial: Vec::new(), // demo 用空 ack_chain
        scheme_id,
        proof_kind,
    }
}

/// 构造完整 CheckinTx（链上 LCCCS 最终 proof 提交 — 阶段 3 final_fold）。
///
/// 参数语义对应 spec.md L665–669：
/// - `game_id`：Game 对象 ID
/// - `proof`：完整 HypernovaProof 序列化字节
/// - `state_delta`：状态增量（demo 用 zkvm_io.output）
/// - `new_commitment`：结算后状态承诺（用 zkvm_io.final_commitment 转 Hash）
/// - `folded_step_count`：已折叠步数（来自 PartialProveState.fold_steps.len()）
/// - `has_partial_checkin`：是否基于 partial_checkin 衔接（SEC2-M8）
pub(crate) fn build_final_checkin_tx(
    game_id: ObjectID,
    proof: Vec<u8>,
    state_delta: Vec<u8>,
    new_commitment: Hash,
    folded_step_count: u32,
    has_partial_checkin: bool,
) -> CheckinTx {
    CheckinTx {
        game_id,
        proof,
        state_delta,
        new_commitment,
        ack_chain: Vec::new(), // demo 用空 ack_chain
        scheme_id: SCHEME_HYPERNOVA,
        proof_kind: ProofKind::Zkvm,
        has_partial_checkin,
        folded_step_count,
        skip_count: 0,
        segment_continuity_proof: Vec::new(),
    }
}

/// 通过 `zk_verify` RPC 端点验证 proof 字节。
///
/// 调用 poker_l1 节点的 `zk_verify(scheme_id, proof, public_io_bytes, max_skip_segments, max_ack_chain_length)`。
/// 节点会根据 chain_id 查询 verifier_status（Stub / Production），Production 状态下执行完整 ZK 验证。
///
/// # 返回
/// `true` 当且仅当 RPC 返回 `verified=true`。
pub(crate) fn verify_proof_via_rpc(
    rpc_listen: &str,
    scheme_id: u32,
    proof: &[u8],
    public_io: &L1ZkPublicIo,
    max_skip_segments: u32,
    max_ack_chain_length: u32,
) -> Result<bool, String> {
    let public_io_bytes = public_io.to_bytes();
    let params = serde_json::json!({
        "scheme_id": scheme_id,
        "proof": proof,
        "public_io_bytes": public_io_bytes,
        "max_skip_segments": max_skip_segments,
        "max_ack_chain_length": max_ack_chain_length,
    });
    let resp = rpc_call(rpc_listen, "zk_verify", &params)?;
    if let Some(err) = &resp.error {
        return Err(format!(
            "zk_verify RPC 错误（code={}）：{}",
            err.code, err.message
        ));
    }
    let result = resp
        .result
        .ok_or_else(|| "zk_verify 返回空 result".to_string())?;
    let verified = result
        .get("verified")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| format!("zk_verify 返回缺 verified 字段：{result}"))?;
    let verifier_status = result
        .get("verifier_status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let returned_scheme = result
        .get("scheme_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    println!(
        "  ✓ zk_verify RPC 返回：verified={} verifier_status={} scheme_id={}",
        verified, verifier_status, returned_scheme
    );
    Ok(verified)
}

/// Phase 4.3 演示：在本地运行 zkvm 三阶段证明，构造 PartialCheckinTx + CheckinTx，
/// 并通过 RPC 调用 `zk_verify` 验证最终 proof。
///
/// # 流程
/// 1. prove_partial_start — 构造 PartialProveState（持有 initial_lcccs）
/// 2. prove_partial_fold — 推进 fold（若 ccccs_queue 非空）+ 构造 PartialCheckinTx（仅展示，无 submit）
/// 3. prove_final_fold — 产出完整 proof + 构造 CheckinTx
/// 4. zk_verify RPC — 通过 RPC 验证 proof（要求节点已启动且 scheme_id=1 verifier 已注册）
///
/// # 参数
/// - `rpc_listen`：zchain 节点 RPC 监听地址（如 "127.0.0.1:8545"）
/// - `skip_rpc`：true 时跳过 RPC 验证（节点未启动场景下仅做 in-process 构造演示）
pub fn run_rpc_partial_checkin_demo(
    rpc_listen: &str,
    skip_rpc: bool,
) -> Result<(), String> {
    use poker_zkvm::prover::{MAX_PROOF_TOTAL_SIZE, default_ccs_registry};
    use poker_zkvm::test_helpers::build_poker_hand_eval_v2_elf;
    use poker_zkvm::verifier::verify_production as zkvm_verify_production;
    use std::time::Instant;

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   zchain rpc-partial-checkin-demo — 链上 LCCCS 分阶段   ║");
    println!("║   提交 + zk_verify RPC 验证                              ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("RPC endpoint: {rpc_listen}（skip_rpc={skip_rpc}）");
    println!("目标合约:    texas_poker (ObjectID = {:?})", texas_poker_contract_id());
    println!();

    // 1. 构造 ELF + input + config（与 poker_zkvm_demo.rs::run_lcccs_partial_prove_demo 一致）
    let elf = build_poker_hand_eval_v2_elf();
    let input: Vec<u8> = vec![14, 13, 12, 11, 10]; // [A,K,Q,J,10] → straight A-high
    let config = ZkvmProverConfigShared {
        batch_size: 256,
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        ..Default::default()
    };
    let registry = default_ccs_registry();
    println!("ELF: poker_hand_eval_v2 (~80 instrs, 5B input, 4B output)");
    println!("输入: [A,K,Q,J,10] → 期望 straight (category=5, max=14)");
    println!("batch_size={} → 单实例路径（0 fold 步）", config.batch_size);
    println!();

    // 2. 阶段 1: prove_partial_start
    println!("━━━ 阶段 1: prove_partial_start ━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let start_t = Instant::now();
    let mut state: PartialProveState = prove_partial_start(&elf, &input, &config)
        .map_err(|e| format!("prove_partial_start 失败：{e:?}"))?;
    let start_ms = start_t.elapsed().as_secs_f64() * 1000.0;
    let initial_lcccs_anchor = state.ccs_commitment;
    let total_fold_steps = state.ccccs_queue.len() as u32;
    println!("  ✓ prove_partial_start: {:.2}ms", start_ms);
    println!("    initial_lcccs_anchor (ccs_commitment) = {}", hex::encode(initial_lcccs_anchor));
    println!("    ccccs_queue = {} 个 CCCCS（fold 步数上限）", state.ccccs_queue.len());
    println!();

    // 3. 阶段 2: prove_partial_fold（若有 CCCCS）+ 构造 PartialCheckinTx
    println!("━━━ 阶段 2: prove_partial_fold + PartialCheckinTx ━━━━━━━━━");
    let mut partial_checkin_txs: Vec<PartialCheckinTx> = Vec::new();
    let game_id = texas_poker_contract_id();

    while !state.ccccs_queue.is_empty() {
        let step_t = Instant::now();
        let progress = prove_partial_fold(&mut state, 1)
            .map_err(|e| format!("prove_partial_fold 失败：{e:?}"))?;
        let step_ms = step_t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "  ✓ fold step {}/{}: {:.2}ms remaining={} intermediate_commitment={}",
            progress.folded_step_count,
            total_fold_steps,
            step_ms,
            progress.remaining_steps,
            hex::encode(progress.intermediate_commitment)
        );

        // 构造 PartialCheckinTx（demo 用 intermediate_commitment 作为 π_partial 占位）
        let proof_partial = progress.intermediate_commitment.to_vec();
        let tx = build_partial_checkin_tx(
            game_id,
            &progress,
            proof_partial,
            SCHEME_HYPERNOVA,
            ProofKind::Zkvm,
        );
        println!(
            "    → PartialCheckinTx: game_id={} folded_step_count={} π_partial_hash={}",
            tx.game_id,
            tx.folded_step_count,
            hex::encode(tx.proof_partial_hash())
        );
        partial_checkin_txs.push(tx);
    }
    if partial_checkin_txs.is_empty() {
        println!("  （单实例路径，无 partial_fold 步骤，跳过 PartialCheckinTx 构造）");
    } else {
        println!(
            "  ✓ 共构造 {} 笔 PartialCheckinTx（仅展示，无专用 submit 端点）",
            partial_checkin_txs.len()
        );
    }
    println!();

    // 4. 阶段 3: prove_final_fold + 构造 CheckinTx
    println!("━━━ 阶段 3: prove_final_fold + CheckinTx ━━━━━━━━━━━━━━━━━");
    let final_t = Instant::now();
    let (proof_bytes, public_io) = prove_final_fold(state)
        .map_err(|e| format!("prove_final_fold 失败：{e:?}"))?;
    let final_fold_ms = final_t.elapsed().as_secs_f64() * 1000.0;
    println!(
        "  ✓ prove_final_fold: {:.2}ms proof_size={}B",
        final_fold_ms,
        proof_bytes.len()
    );

    // 转换 ZkPublicIo（poker_zkvm → poker_l1）
    let l1_public_io = convert_zkvm_public_io_to_l1(&public_io, total_fold_steps)?;
    println!(
        "  ✓ convert_zkvm_public_io_to_l1: initial_commitment={} final_commitment={}",
        hex::encode(&l1_public_io.initial_commitment[..8]),
        hex::encode(&l1_public_io.final_commitment[..8])
    );

    // 构造完整 CheckinTx
    let has_partial = !partial_checkin_txs.is_empty();
    let final_new_commitment = l1_public_io.final_commitment;
    let checkin_tx = build_final_checkin_tx(
        game_id,
        proof_bytes.clone(),
        public_io.output.clone(), // demo 用 output 作为 state_delta
        final_new_commitment,
        total_fold_steps,
        has_partial,
    );
    println!(
        "  → CheckinTx: game_id={} proof={}B folded_step_count={} has_partial_checkin={}",
        checkin_tx.game_id,
        checkin_tx.proof.len(),
        checkin_tx.folded_step_count,
        checkin_tx.has_partial_checkin
    );
    println!(
        "    proof_hash={} state_delta_hash={}",
        hex::encode(&checkin_tx.proof_hash()[..8]),
        hex::encode(&checkin_tx.state_delta_hash()[..8])
    );
    println!();

    // 5. 本地 verify_production 校验（确保 proof 字节合法）
    println!("━━━ 本地 verify_production 校验 ━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let verify_t = Instant::now();
    let valid = zkvm_verify_production(&proof_bytes, &public_io, &registry)
        .map_err(|e| format!("verify_production 失败：{e:?}"))?;
    let verify_ms = verify_t.elapsed().as_secs_f64() * 1000.0;
    println!("  ✓ verify_production: {:.2}ms valid={}", verify_ms, valid);
    if !valid {
        return Err("verify_production 验证失败".to_string());
    }
    println!();

    // 6. zk_verify RPC 验证（要求节点已启动）
    println!("━━━ zk_verify RPC 验证 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if skip_rpc {
        println!("  （skip_rpc=true，跳过 RPC 验证）");
    } else {
        let verified = verify_proof_via_rpc(
            rpc_listen,
            SCHEME_HYPERNOVA,
            &proof_bytes,
            &l1_public_io,
            3,    // max_skip_segments 默认
            1000, // max_ack_chain_length 默认
        )?;
        if verified {
            println!("  ✓ zk_verify RPC 返回 verified=true（节点 verifier 接受 proof）");
        } else {
            println!("  ⚠ zk_verify RPC 返回 verified=false（节点 verifier 拒绝 proof）");
            println!("    可能原因：节点未注册 SCHEME_HYPERNOVA verifier，或 verifier_status=Stub 仅校验格式");
        }
    }
    println!();

    // 7. 输出摘要
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   ✓ rpc-partial-checkin-demo 完成                       ║");
    println!("║     start {:.2}ms + fold ({}) + final {:.2}ms          ║",
        start_ms, partial_checkin_txs.len(), final_fold_ms);
    println!("║     proof={}B verify_ms={:.2}ms                          ║",
        proof_bytes.len(), verify_ms);
    println!("╚══════════════════════════════════════════════════════════╝");

    Ok(())
}

/// ZkvmProverConfig 路径别名（保持代码简洁）。
type ZkvmProverConfigShared = poker_zkvm::prover::ProverConfig;

/// 本模块内部使用的 TexasPokerTable 路径别名（保持代码简洁）。
mod poker_l1_table {
    pub use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;
}