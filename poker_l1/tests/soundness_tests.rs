//! poker_l1 Soundness 负向测试 — 验证安全边界与错误路径。
//!
//! 参考 poker_zkvm `tests/soundness_tests.rs` 模式，覆盖 6 类安全边界：
//! 1. 交易校验 — 输入/输出/签名/参数长度限制边界
//! 2. 签名验证 — 篡改签名/非规范编码/错误长度/跨 scheme 路由
//! 3. SMT — 篡改兄弟/截断路径/错误 key/空非空不一致
//! 4. Bridge — 非协议调用/重放/目标链不匹配
//! 5. Block 时间共识 — 高度不递增/时间回退/间隔超限
//! 6. 网络大小限制 — tx/vertex 超限

mod common;

use common::{
    dummy_commit_cert, make_real_ed25519_keypair, make_real_secp_keypair,
    make_tagged_pubkey_ed25519, make_tagged_pubkey_secp, make_tx,
};
use poker_l1::DEFAULT_CHAIN_ID;
use poker_l1::bridge::{
    BridgeDeposit, BridgeRegistry, BridgeValidatorSlot, BridgeVerifyTx, bridge_verify,
};
use poker_l1::error::PokerL1Error;
use poker_l1::network::{validate_tx_size, validate_vertex_size};
use poker_l1::object_model::{Object, ObjectID, Ownership, SparseMerkleTree};
use poker_l1::signature::unified::verify_signature;
use poker_l1::transaction::TxLane;

use std::collections::BTreeSet;

use ed25519_dalek::Signer;
use secp256k1::Message;

// ===========================================================================
// 1. 交易校验 — 长度限制边界
// ===========================================================================

#[test]
fn test_soundness_tx_inputs_at_limit_passes() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    tx.inputs = vec![ObjectID::new([0u8; 20], 0); 256]; // 恰好 MAX_INPUTS
    assert!(
        poker_l1::transaction::validate_tx_limits(&tx).is_ok(),
        "256 inputs（恰好 MAX_INPUTS）应通过校验"
    );
}

#[test]
fn test_soundness_tx_outputs_at_limit_passes() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    let dummy_obj = Object::new(
        ObjectID::new([0u8; 20], 0),
        Ownership::Shared,
        "TestType",
        vec![],
        None,
    );
    tx.outputs = vec![dummy_obj; 256]; // 恰好 MAX_OUTPUTS
    assert!(
        poker_l1::transaction::validate_tx_limits(&tx).is_ok(),
        "256 outputs（恰好 MAX_OUTPUTS）应通过校验"
    );
}

#[test]
fn test_soundness_tx_outputs_above_limit_fails() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    let dummy_obj = Object::new(
        ObjectID::new([0u8; 20], 0),
        Ownership::Shared,
        "TestType",
        vec![],
        None,
    );
    tx.outputs = vec![dummy_obj; 257]; // 超过 MAX_OUTPUTS
    let err = poker_l1::transaction::validate_tx_limits(&tx).unwrap_err();
    assert!(
        matches!(
            err,
            PokerL1Error::InputTooLong {
                actual: 257,
                limit: 256
            }
        ),
        "257 outputs 应返回 InputTooLong {{ actual: 257, limit: 256 }}, got: {err:?}"
    );
}

#[test]
fn test_soundness_tx_sig_above_limit_fails() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    tx.signature = vec![0u8; 66]; // 超过 MAX_SIG_LEN (65)
    let err = poker_l1::transaction::validate_tx_limits(&tx).unwrap_err();
    assert!(
        matches!(
            err,
            PokerL1Error::InputTooLong {
                actual: 66,
                limit: 65
            }
        ),
        "66 字节签名应返回 InputTooLong {{ actual: 66, limit: 65 }}, got: {err:?}"
    );
}

// ===========================================================================
// 2. 签名验证 — 篡改/非规范/错误长度/跨 scheme
// ===========================================================================

#[test]
fn test_soundness_sig_tampered_secp_bytes_fails() {
    let (_sk, _pk, tagged) = make_real_secp_keypair();
    let secp = secp256k1::Secp256k1::new();
    let msg_hash = [0x42u8; 32];
    let msg = Message::from_digest(msg_hash);
    let sig = secp.sign_ecdsa_recoverable(&msg, &_sk);
    let (recid, compact) = sig.serialize_compact();
    let mut sig_bytes = compact.to_vec();
    sig_bytes.push(recid.to_i32() as u8);

    // 翻转 r 首字节
    sig_bytes[0] ^= 0xFF;

    let result = verify_signature(&tagged, &sig_bytes, &msg_hash);
    assert!(
        result.is_err(),
        "篡改 secp 签名字节应验证失败, got: {result:?}"
    );
}

#[test]
fn test_soundness_sig_ed25519_non_canonical_s_fails() {
    let (sk, _vk, tagged) = make_real_ed25519_keypair();
    let msg = [0x42u8; 32];
    let sig = sk.sign(&msg);
    let mut sig_bytes = sig.to_bytes().to_vec();

    // 将 S（字节 32-63）设为全 0xFF（远大于 L，非 canonical）
    for b in &mut sig_bytes[32..64] {
        *b = 0xFF;
    }

    let result = verify_signature(&tagged, &sig_bytes, &msg);
    assert!(
        matches!(result, Err(PokerL1Error::InvalidSignatureCanonical)),
        "S 非规范应返回 InvalidSignatureCanonical, got: {result:?}"
    );
}

#[test]
fn test_soundness_sig_ed25519_wrong_pubkey_length_fails() {
    let (sk, _vk, _tagged) = make_real_ed25519_keypair();
    let msg = [0x42u8; 32];
    let sig = sk.sign(&msg);
    let sig_bytes = sig.to_bytes().to_vec();

    // 构造 raw.len()=31 的 ed25519 tagged pubkey
    let wrong_tp = poker_l1::signature::TaggedPubkey {
        tag: poker_l1::signature::tagged_pubkey::encode_tag(
            poker_l1::signature::SignatureScheme::Ed25519,
            1,
        ),
        raw: vec![0u8; 31],
    };

    let result = verify_signature(&wrong_tp, &sig_bytes, &msg);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::InvalidPubkeyLength {
                actual: 31,
                expected: 32,
                ..
            })
        ),
        "raw.len()=31 应返回 InvalidPubkeyLength {{ actual: 31, expected: 32 }}, got: {result:?}"
    );
}

#[test]
fn test_soundness_sig_cross_scheme_routing_fails() {
    // ed25519 tagged pubkey + 65 字节签名（secp256k1 长度）
    let tp = make_tagged_pubkey_ed25519(0x42);
    let sig_65 = vec![0u8; 65];
    let msg = [0x42u8; 32];

    let result = verify_signature(&tp, &sig_65, &msg);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::InvalidSignatureLength {
                actual: 65,
                expected: 64
            })
        ),
        "ed25519 + 65B sig 应返回 InvalidSignatureLength {{ actual: 65, expected: 64 }}, got: {result:?}"
    );
}

// ===========================================================================
// 3. SMT — 篡改兄弟/截断路径/错误 key/空非空不一致
// ===========================================================================

#[test]
fn test_soundness_smt_tampered_sibling_fails() {
    let mut t = SparseMerkleTree::new();
    let key = [7u8; 32];
    let value = b"hello";
    t.upsert(key, value);

    let mut path = t.prove(&key);
    // 翻转 siblings[0] 首字节
    path.siblings[0][0] ^= 0xFF;

    assert!(
        !SparseMerkleTree::verify(&t.root(), &key, Some(value), &path),
        "篡改兄弟哈希应导致 verify 返回 false"
    );
}

#[test]
fn test_soundness_smt_truncated_path_fails() {
    let mut t = SparseMerkleTree::new();
    let key = [7u8; 32];
    t.upsert(key, b"v");

    let mut path = t.prove(&key);
    // 截断 siblings 到 100（非 256）
    path.siblings.truncate(100);

    assert!(
        !SparseMerkleTree::verify(&t.root(), &key, Some(b"v"), &path),
        "截断路径应导致 verify 返回 false"
    );
}

#[test]
fn test_soundness_smt_wrong_key_fails() {
    let mut t = SparseMerkleTree::new();
    let key_a = [7u8; 32];
    let key_b = [8u8; 32];
    t.upsert(key_a, b"real");

    let path = t.prove(&key_a);
    // 用 key_b 调 verify
    assert!(
        !SparseMerkleTree::verify(&t.root(), &key_b, Some(b"real"), &path),
        "用错误 key 调 verify 应返回 false"
    );
}

#[test]
fn test_soundness_smt_empty_nonempty_mismatch_fails() {
    let mut t = SparseMerkleTree::new();
    let key = [7u8; 32];
    t.upsert(key, b"real");

    let mut path = t.prove(&key);
    // 设置 is_empty_leaf=true 但 value=Some(...)
    path.is_empty_leaf = true;

    assert!(
        !SparseMerkleTree::verify(&t.root(), &key, Some(b"real"), &path),
        "is_empty_leaf=true + value=Some 应返回 false"
    );
}

// ===========================================================================
// 4. Bridge — 非协议调用/重放/目标链不匹配
// ===========================================================================

fn make_bridge_deposit(nonce: u64, dest_chain_id: u64) -> BridgeDeposit {
    BridgeDeposit {
        nonce,
        source_chain_id: 0xAAAA,
        dest_chain_id,
        asset: [0xAB; 32],
        amount: 100,
        recipient: [0x01; 20],
        source_tx_hash: [0xCD; 32],
    }
}

fn make_bridge_tx(deposit: BridgeDeposit) -> BridgeVerifyTx {
    BridgeVerifyTx {
        deposit,
        validator_signatures: vec![],
        recipient_sig: vec![],
        recipient_pubkey: make_tagged_pubkey_secp(0x01),
        preferred_relayer: None,
    }
}

#[test]
fn test_soundness_bridge_not_protocol_caller_fails() {
    let mut registry = BridgeRegistry::new();
    let tx = make_bridge_tx(make_bridge_deposit(1, DEFAULT_CHAIN_ID));
    let result = bridge_verify(&mut registry, &tx, DEFAULT_CHAIN_ID, false);
    assert!(
        matches!(result, Err(PokerL1Error::BridgeVerifyNotAuthorized)),
        "is_protocol_caller=false 应返回 BridgeVerifyNotAuthorized, got: {result:?}"
    );
}

#[test]
fn test_soundness_bridge_replay_nonce_fails() {
    let mut registry = BridgeRegistry::new();
    // 注册 slot
    let validators: BTreeSet<_> = (0..5).map(|i| make_tagged_pubkey_secp(0x10 + i)).collect();
    let slot = BridgeValidatorSlot::new(0xAAAA, validators);
    registry.register_slot(slot);
    // 预消费 nonce=1
    registry.consume_nonce(0xAAAA, 1);

    let tx = make_bridge_tx(make_bridge_deposit(1, DEFAULT_CHAIN_ID));
    let result = bridge_verify(&mut registry, &tx, DEFAULT_CHAIN_ID, true);
    assert!(
        matches!(result, Err(PokerL1Error::BridgeNonceConsumed(1))),
        "重放 nonce=1 应返回 BridgeNonceConsumed(1), got: {result:?}"
    );
}

#[test]
fn test_soundness_bridge_wrong_dest_chain_fails() {
    let mut registry = BridgeRegistry::new();
    let tx = make_bridge_tx(make_bridge_deposit(1, 0x9999)); // 错误 dest_chain_id
    let result = bridge_verify(&mut registry, &tx, DEFAULT_CHAIN_ID, true);
    assert!(
        matches!(result, Err(PokerL1Error::BridgeSignatureInvalid(_))),
        "dest_chain_id 不匹配应返回 BridgeSignatureInvalid, got: {result:?}"
    );
}

// ===========================================================================
// 5. Block 时间共识 — 高度不递增/时间回退/间隔超限
// ===========================================================================

#[test]
fn test_soundness_block_height_not_increasing_fails() {
    use poker_l1::block::{BlockHeader, TimeConsensusConfig, validate_block_time};

    let config = TimeConsensusConfig::new();
    let prev = BlockHeader {
        height: 10,
        timestamp_ms: 10_000,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        dag_commit_certificate: dummy_commit_cert(),
    };
    let curr = BlockHeader {
        height: 10, // 不递增（应 = 11）
        timestamp_ms: 11_000,
        ..prev.clone()
    };

    let result = validate_block_time(Some(&prev), &curr, &config);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::BlockHeightNotIncreasing { prev: 10, got: 10 })
        ),
        "高度不递增应返回 BlockHeightNotIncreasing, got: {result:?}"
    );
}

#[test]
fn test_soundness_block_timestamp_backwards_fails() {
    use poker_l1::block::{BlockHeader, TimeConsensusConfig, validate_block_time};

    let config = TimeConsensusConfig::new();
    let prev = BlockHeader {
        height: 10,
        timestamp_ms: 10_000,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        dag_commit_certificate: dummy_commit_cert(),
    };
    let curr = BlockHeader {
        height: 11,
        timestamp_ms: 9_000, // 回退
        ..prev.clone()
    };

    let result = validate_block_time(Some(&prev), &curr, &config);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::BlockTimestampMovedBackwards { .. })
        ),
        "时间回退应返回 BlockTimestampMovedBackwards, got: {result:?}"
    );
}

#[test]
fn test_soundness_block_timestamp_interval_exceeded_fails() {
    use poker_l1::block::{BlockHeader, TimeConsensusConfig, validate_block_time};

    let config = TimeConsensusConfig::new(); // max_interval_ms = 30_000
    let prev = BlockHeader {
        height: 10,
        timestamp_ms: 10_000,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        dag_commit_certificate: dummy_commit_cert(),
    };
    let curr = BlockHeader {
        height: 11,
        timestamp_ms: 10_000 + 30_001, // 超过 max_interval_ms
        ..prev.clone()
    };

    let result = validate_block_time(Some(&prev), &curr, &config);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::BlockTimestampIntervalExceeded { .. })
        ),
        "间隔超限应返回 BlockTimestampIntervalExceeded, got: {result:?}"
    );
}

// ===========================================================================
// 6. 网络大小限制 — tx/vertex 超限
// ===========================================================================

#[test]
fn test_soundness_tx_too_large_fails() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    // 设置超大 signature 使 BCS 序列化后 > 128KB
    tx.signature = vec![0u8; 200_000];

    let result = validate_tx_size(&tx);
    assert!(
        matches!(result, Err(PokerL1Error::TxTooLarge { .. })),
        "200KB tx 应返回 TxTooLarge, got: {result:?}"
    );
}

#[test]
fn test_soundness_vertex_too_large_fails() {
    let vertex = poker_l1::consensus::DagVertex {
        epoch: 1,
        round: 1,
        author_pubkey: make_tagged_pubkey_secp(0x02),
        tx_list: vec![],
        parent_hashes: vec![],
        author_sig: vec![0u8; 300_000], // 300KB > 256KB
    };

    let result = validate_vertex_size(&vertex);
    assert!(
        matches!(result, Err(PokerL1Error::VertexTooLarge { .. })),
        "300KB vertex 应返回 VertexTooLarge, got: {result:?}"
    );
}
