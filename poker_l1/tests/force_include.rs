//! M3-ACC-6 ForceInclude 抗审查机制端到端小样（plan §5.3 v1 语义子集）。
//!
//! 场景：
//! 1. validator 节点（fake clock）接收 submit_tx → 签发 SeenReceipt；
//! 2. 提交交易但人为不 drain，推进时钟越过 `inclusion_deadline_ms`；
//! 3. 下一次出块 drain：交易被强制包含，且强制包含队列按 tx_hash 字节序升序、
//!    先于未过期的普通交易；
//! 4. CensorshipProof 检测三态：包含前（超时未进块）→ `Censored`（证据成立，
//!    且 `zchain_censorship_detected_total` 计数 +1）；交易进块后 → `Included`
//!    （指控不成立）；未超 deadline 时 → `NotYetDue`。
//!
//! v1 边界（与 `poker_l1::force_include` 模块头一致）：receipt 内存态、罚没仅
//! 记录指标、近 K 个块用块数近似。

use std::sync::{Arc, Mutex};

use poker_l1::force_include::{
    CensorshipCheckOutcome, CensorshipProof, SeenReceipt,
};
use poker_l1::node::{Node, NodeConfig, ValidatorKey};
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::{DEFAULT_CHAIN_ID, Hash};

const DEADLINE_MS: u64 = 1_000;

/// 带 validator 密钥与 fake clock 的内存 validator 节点。
fn validator_node() -> (Node, Arc<Mutex<u64>>) {
    let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
    let mut config = NodeConfig::validator(std::path::PathBuf::from("/tmp/poker_l1_fi_e2e"), vkey);
    config.inclusion_deadline_ms = DEADLINE_MS;
    // 审查窗口用小块数（测试链只有 1-2 个块）。
    config.censorship_window_blocks = 16;
    let node = Node::open_inmemory_with_config(config).unwrap();
    let clock = Arc::new(Mutex::new(1_000u64));
    let handle = Arc::clone(&clock);
    node.set_time_source(Box::new(move || *handle.lock().unwrap()));
    (node, clock)
}

/// 构造真实 secp256k1 签名的 Public 通道交易（不同 caller → 不同 tx_hash）。
fn signed_public_tx(seed: u8) -> Transaction {
    let secp = secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[0] = seed;
    let secret = secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
    let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let tagged =
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, public.serialize().to_vec())
            .unwrap();
    let mut tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey: tagged,
        signature: vec![0u8; 65],
        gas: Gas::new(1_000, 1),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id: DEFAULT_CHAIN_ID,
        nonce: 0,
        gameturn_nonce: None,
        is_fallback: false,
    };
    let msg = secp256k1::Message::from_digest(tx.signing_hash());
    let sig = secp.sign_ecdsa_recoverable(&msg, &secret);
    let (rid, compact) = sig.serialize_compact();
    let mut sig_bytes = compact.to_vec();
    sig_bytes.push(rid.to_i32() as u8);
    tx.signature = sig_bytes;
    tx
}

fn dummy_certificate() -> poker_l1::consensus::DagCommitCertificate {
    poker_l1::consensus::DagCommitCertificate {
        epoch: 0,
        commit_round: 0,
        prev_commit_hash: [0u8; 32],
        vertex_hash_list: vec![],
        round_attendance_bitmap: vec![],
        state_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        signature_list: vec![],
        signer_bitmap: vec![],
    }
}

#[test]
fn force_include_end_to_end_receipt_deadline_and_censorship_proof() {
    let (node, clock) = validator_node();

    // 1) t=1000：提交 3 笔交易（人为不 drain）。乱序提交（hash 降序）以验证确定性排序。
    let mut txs: Vec<Transaction> = (1..=3).map(signed_public_tx).collect();
    txs.sort_by(|a, b| b.tx_hash().cmp(&a.tx_hash()));
    for tx in &txs {
        node.submit_tx(tx.clone()).unwrap();
    }
    let hashes: Vec<Hash> = txs.iter().map(|t| t.tx_hash()).collect();

    // 2) SeenReceipt 已签发且可验证（§5.3-1）。
    let receipts: Vec<SeenReceipt> = hashes
        .iter()
        .map(|h| node.get_seen_receipt(h).unwrap().expect("receipt 应存在"))
        .collect();
    for receipt in &receipts {
        assert_eq!(receipt.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(receipt.seen_at_ms, 1_000);
        receipt.verify().expect("receipt 签名必须有效");
    }

    // 3) 未超 deadline：check_censorship → NotYetDue。
    let proof0 = CensorshipProof {
        receipt: receipts[0].clone(),
        tx_bytes: txs[0].to_bcs().unwrap(),
        deadline_ms: DEADLINE_MS,
        current_height_hint: 0,
    };
    assert_eq!(
        node.check_censorship(&proof0).unwrap(),
        CensorshipCheckOutcome::NotYetDue,
        "未超 deadline 时证据不可成立"
    );

    // 4) 推进时钟越 deadline，下一次出块 drain：强制包含且顺序确定（§5.3-2/3）。
    *clock.lock().unwrap() = 1_000 + DEADLINE_MS + 1;
    // 同 tick 再提交一笔未过期的普通交易（arrived_at = 当前时钟）。
    let fresh = signed_public_tx(9);
    node.submit_tx(fresh.clone()).unwrap();

    let drained = node.drain_pending_tx_for_block();
    assert_eq!(drained.len(), 4, "3 笔强制包含 + 1 笔普通");
    let mut expected_forced = hashes.clone();
    expected_forced.sort();
    let got_forced: Vec<Hash> = drained[..3].iter().map(|t| t.tx_hash()).collect();
    assert_eq!(
        got_forced, expected_forced,
        "强制包含组必须按 tx_hash 字节序升序先于普通交易"
    );
    assert_eq!(
        drained[3].tx_hash(),
        fresh.tx_hash(),
        "未过期交易按普通排序跟随在强制包含组之后"
    );

    // 5) 包含前（已超时、未进块）：check_censorship → Censored（证据成立）+ 指标计数。
    let proof = CensorshipProof {
        receipt: receipts[0].clone(),
        tx_bytes: txs[0].to_bcs().unwrap(),
        deadline_ms: DEADLINE_MS,
        current_height_hint: 1,
    };
    assert_eq!(
        node.check_censorship(&proof).unwrap(),
        CensorshipCheckOutcome::Censored,
        "超时且未进块 → 审查证据成立"
    );
    let metrics = node.metrics().export();
    assert!(
        metrics.contains("zchain_censorship_detected_total 1"),
        "censorship_detected_total 应记 1（v1 仅记录不罚没）:\n{metrics}"
    );

    // 6) 交易进块后：同一 proof → Included（指控不成立）。
    let header = poker_l1::block::BlockHeader {
        height: 1,
        timestamp_ms: 2_000,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        public_tx_root: poker_l1::block::compute_tx_merkle_root(&drained),
        gameturn_tx_root: poker_l1::block::compute_tx_merkle_root(&[]),
        dag_commit_certificate: dummy_certificate(),
    };
    let block = poker_l1::block::Block::new(header, drained, vec![]);
    node.block_store().put(&block, DEFAULT_CHAIN_ID).unwrap();

    assert_eq!(
        node.check_censorship(&proof).unwrap(),
        CensorshipCheckOutcome::Included,
        "交易已进块（近 K 块窗口内）→ 指控不成立"
    );
}
