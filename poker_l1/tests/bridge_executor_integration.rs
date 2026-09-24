//! 资产桥 executor 铸币路径集成测试（Node::with_bridge 全链路；缺口 #9）。
//!
//! 此前 `poker_l1/src/bridge/mod.rs` 的 24 个单测只覆盖 registry/签名语义，
//! executor 的 bridge contract_call 特判分支（解码 → bridge_verify → 铸
//! wrapped Object → 落 nonce）从未经 Node 级执行路径验证。本文件经
//! [`Node::execute_block_on_state`]（put_block 同路径）覆盖：
//!
//! 1. 正常铸币：quorum 签名 → wrapped Object 落库（类型/owner/金额/来源）
//!    + deposit nonce 持久化；
//! 2. 同 deposit 重放（换新账户 nonce 重签）：桥 nonce 已消费 → 回执失败；
//! 3. **同块并发同 nonce 双花**：同 nonce 不同收款人乱序提交，必须恰好
//!    一笔成功（BridgeRegistry 互斥），失败方不得铸出对象；
//! 4. fail-closed：节点未注入 bridge store（未 `with_bridge`）→ 拒绝。

use poker_l1::account::{derive_address, Account};
use poker_l1::bridge::{
    BridgeDeposit, BridgeRegistry, BridgeValidatorSig, BridgeValidatorSlot, BridgeVerifyTx,
    WrappedAsset, BRIDGE_WRAPPED_OBJECT_TYPE,
};
use poker_l1::executor::ExecutionEnvironment;
use poker_l1::node::{Node, NodeRole};
use poker_l1::object_model::{Object, ObjectID, Ownership};
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use poker_l1::storage::BridgeRegistryStore;
use poker_l1::transaction::{ContractCall, Gas, RouteHint, Transaction, TxLane};
use poker_l1::{DEFAULT_CHAIN_ID};
use secp256k1::{Message, Secp256k1};
use std::collections::BTreeSet;
use std::sync::{Arc, MutexGuard};

/// 确定性 secp 密钥（测试只需签名有效，不要求密码学随机）。
fn key(byte: u8) -> (secp256k1::SecretKey, TaggedPubkey) {
    let mut sk = [0u8; 32];
    sk[31] = byte;
    sk[30] = 0xAB;
    let secret = secp256k1::SecretKey::from_slice(&sk).expect("deterministic key");
    let tagged = tagged_of(&secret);
    (secret, tagged)
}

fn tagged_of(sk: &secp256k1::SecretKey) -> TaggedPubkey {
    let secp = Secp256k1::new();
    let public = secp256k1::PublicKey::from_secret_key(&secp, sk);
    TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        public.serialize().to_vec(),
    )
    .expect("tagged pubkey")
}

/// 65B recoverable 签名（r||s||v；bridge verify_signature 的期望格式）。
fn sign(secp: &Secp256k1<secp256k1::All>, sk: &secp256k1::SecretKey, msg: &[u8; 32]) -> Vec<u8> {
    let m = Message::from_digest_slice(msg).expect("32B");
    let (rid, compact) = secp.sign_ecdsa_recoverable(&m, sk).serialize_compact();
    let mut sig = compact.to_vec();
    sig.push(rid.to_i32() as u8);
    sig
}

/// 完整签名 bridge_verify 载荷（recipient + quorum 验证者签名）。
fn signed_bridge_payload(
    secp: &Secp256k1<secp256k1::All>,
    recipient_sk: &secp256k1::SecretKey,
    recipient: &TaggedPubkey,
    validator_sks: &[secp256k1::SecretKey],
    deposit: BridgeDeposit,
) -> Vec<u8> {
    let msg = deposit.message_hash();
    let validator_signatures: Vec<BridgeValidatorSig> = validator_sks
        .iter()
        .map(|sk| BridgeValidatorSig {
            validator: tagged_of(sk),
            signature: sign(secp, sk, &msg),
        })
        .collect();
    let payload = BridgeVerifyTx {
        deposit,
        validator_signatures,
        recipient_sig: sign(secp, recipient_sk, &msg),
        recipient_pubkey: recipient.clone(),
        preferred_relayer: None,
    };
    borsh::to_vec(&payload).expect("borsh BridgeVerifyTx")
}

fn make_deposit(nonce: u64, amount: u64, recipient: [u8; 20]) -> BridgeDeposit {
    BridgeDeposit {
        nonce,
        source_chain_id: 0xAAAA,
        dest_chain_id: DEFAULT_CHAIN_ID,
        asset: [0xAB; 32],
        amount,
        recipient,
        source_tx_hash: [0xCD; 32],
    }
}

/// 签名一笔 Public 通道 bridge contract_call tx（sender 独立于 recipient）。
fn bridge_call_tx(
    secp: &Secp256k1<secp256k1::All>,
    sender_sk: &secp256k1::SecretKey,
    sender: &TaggedPubkey,
    account_nonce: u64,
    args: Vec<u8>,
) -> Transaction {
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: Some(ContractCall {
            contract_id: poker_l1::vm::precompile::reserved::bridge_contract_id(),
            method_selector: [0u8; 32],
            args,
        }),
        tagged_pubkey: sender.clone(),
        signature: vec![0u8; 65],
        gas: Gas::new(10_000_000, 1),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id: DEFAULT_CHAIN_ID,
        nonce: account_nonce,
        gameturn_nonce: None,
        is_fallback: false,
    };
    let sig = sign(secp, sender_sk, &tx.signing_hash());
    Transaction { signature: sig, ..tx }
}

/// 带 5 验证者 slot 的桥节点（quorum=4）。
/// 预注册发送方账户（executor 要求 caller 账户存在；Free 策略无需余额）。
fn register_sender(node: &Node, sender: &TaggedPubkey) {
    node.put_account(Account::new(sender.clone(), 0)).expect("put sender account");
}

fn bridge_node() -> (Node, Arc<BridgeRegistryStore>, Vec<secp256k1::SecretKey>) {
    let store = Arc::new(BridgeRegistryStore::open_inmemory().expect("bridge store"));
    let mut validator_sks = Vec::new();
    let mut validators = BTreeSet::new();
    for byte in 1_u8..=5_u8 {
        let (sk, tagged) = key(byte);
        validator_sks.push(sk);
        validators.insert(tagged);
    }
    let mut registry: MutexGuard<'_, BridgeRegistry> = store.registry();
    registry.register_slot(BridgeValidatorSlot::new(0xAAAA, validators));
    drop(registry);
    let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID)
        .expect("node")
        .with_bridge(Arc::clone(&store));
    (node, store, validator_sks)
}

fn env_for(node: &Node, height: u64) -> ExecutionEnvironment {
    node.execution_environment(height, 1_700_000_000_000 + height * 1000)
}

/// executor 铸币路径的确定性 ObjectID（与 executor/mod.rs 同公式：
/// block_height 高 32 位 | tx_hash 低 32 位）。
fn expected_wrapped_id(tx: &Transaction, height: u64, recipient: [u8; 20]) -> ObjectID {
    let hi = height << 32;
    let lo = u32::from_le_bytes(tx.tx_hash()[0..4].try_into().unwrap()) as u64;
    ObjectID::new(recipient, hi | lo)
}

fn wrapped_of(node: &Node, id: &ObjectID) -> WrappedAsset {
    let obj: Object = node.get_object(id).expect("get_object").expect("wrapped minted");
    assert_eq!(obj.object_type, BRIDGE_WRAPPED_OBJECT_TYPE);
    borsh::from_slice(&obj.data).expect("decode WrappedAsset")
}

#[test]
fn executor_mints_wrapped_asset_and_persists_nonce() {
    let (node, store, validator_sks) = bridge_node();
    let secp = Secp256k1::new();
    let (recipient_sk, recipient) = key(0x77);
    let (sender_sk, sender) = key(0x88);
    let recipient_addr = derive_address(&recipient);

    register_sender(&node, &sender);
    let deposit = make_deposit(1, 1000, recipient_addr);
    let args =
        signed_bridge_payload(&secp, &recipient_sk, &recipient, &validator_sks[..4], deposit);
    let tx = bridge_call_tx(&secp, &sender_sk, &sender, 0, args);

    let outcome = node
        .execute_block_on_state(&env_for(&node, 1), &[tx.clone()])
        .expect("execute block");
    assert!(
        outcome.receipts[0].success,
        "铸币必须成功：{:?}",
        outcome.receipts[0].error
    );

    // wrapped Object：类型 / owner / 金额 / 来源链全部正确
    let id = expected_wrapped_id(&tx, 1, recipient_addr);
    let wrapped = wrapped_of(&node, &id);
    assert_eq!(wrapped.source_chain_id, 0xAAAA);
    assert_eq!(wrapped.asset, [0xAB; 32]);
    assert_eq!(wrapped.amount, 1000);
    let obj = node.get_object(&id).expect("get").expect("obj");
    assert_eq!(obj.owner, Ownership::AddressOwned { owner: recipient_addr });

    // deposit nonce 已持久化（防重启重放）
    assert!(store.registry().is_nonce_consumed(0xAAAA, 1));
}

/// 重放语义：换新账户 nonce 重签同一 deposit（绕过账户层）→ 必须被
/// **桥层** nonce 消费记录拒绝。
#[test]
fn same_deposit_replay_with_fresh_account_nonce_rejected() {
    let (node, _store, validator_sks) = bridge_node();
    let secp = Secp256k1::new();
    let (recipient_sk, recipient) = key(0x77);
    let (sender_sk, sender) = key(0x88);
    let recipient_addr = derive_address(&recipient);

    register_sender(&node, &sender);
    let deposit = make_deposit(7, 500, recipient_addr);
    let args =
        signed_bridge_payload(&secp, &recipient_sk, &recipient, &validator_sks[..4], deposit);

    let first = node
        .execute_block_on_state(&env_for(&node, 1), &[bridge_call_tx(&secp, &sender_sk, &sender, 0, args.clone())])
        .expect("exec1");
    assert!(first.receipts[0].success, "首笔必须成功：{:?}", first.receipts[0].error);

    // 重放：账户 nonce 推进到 1 重签（排除账户层拒绝），deposit 原样
    let second = node
        .execute_block_on_state(&env_for(&node, 2), &[bridge_call_tx(&secp, &sender_sk, &sender, 1, args)])
        .expect("exec2");
    assert!(!second.receipts[0].success, "桥 nonce 已消费，重放必须失败");
    assert!(
        second.receipts[0]
            .error
            .as_deref()
            .is_some_and(|e| e.to_lowercase().contains("nonce")),
        "失败原因必须是桥 nonce 已消费：{:?}",
        second.receipts[0].error
    );
}

/// 同块并发双花：同 source nonce、两个收款人。BridgeRegistry 互斥必须保证
/// 恰好一笔成功——失败方在 nonce 检查处被拒，不得铸出第二个 Object。
#[test]
fn concurrent_same_nonce_double_spend_in_one_block() {
    let (node, store, validator_sks) = bridge_node();
    let secp = Secp256k1::new();
    let (sk_a, tagged_a) = key(0x51);
    let (sk_b, tagged_b) = key(0x52);
    let (sender_sk, sender) = key(0x88);
    let addr_a = derive_address(&tagged_a);
    let addr_b = derive_address(&tagged_b);

    register_sender(&node, &sender);
    // 两笔同 nonce=9、不同收款人的合规签名载荷
    let args_a = signed_bridge_payload(
        &secp,
        &sk_a,
        &tagged_a,
        &validator_sks[..4],
        make_deposit(9, 100, addr_a),
    );
    let args_b = signed_bridge_payload(
        &secp,
        &sk_b,
        &tagged_b,
        &validator_sks[..4],
        make_deposit(9, 100, addr_b),
    );
    let tx_a = bridge_call_tx(&secp, &sender_sk, &sender, 0, args_a);
    let tx_b = bridge_call_tx(&secp, &sender_sk, &sender, 1, args_b);

    // 乱序提交：无论调度顺序，同 nonce 只允许一笔
    let outcome = node
        .execute_block_on_state(&env_for(&node, 1), &[tx_b.clone(), tx_a.clone()])
        .expect("exec");
    let success_count = outcome.receipts.iter().filter(|r| r.success).count();
    assert_eq!(
        success_count, 1,
        "同 nonce 双花必须恰好一笔成功：{:?}",
        outcome.receipts
    );

    // 恰好一个 wrapped Object（成功的那笔），另一地址无对象
    let id_a = expected_wrapped_id(&tx_a, 1, addr_a);
    let id_b = expected_wrapped_id(&tx_b, 1, addr_b);
    let a_exists = node.get_object(&id_a).expect("get").is_some();
    let b_exists = node.get_object(&id_b).expect("get").is_some();
    assert_ne!(a_exists, b_exists, "两个地址不能都铸出对象");
    if a_exists {
        assert_eq!(wrapped_of(&node, &id_a).amount, 100);
    } else {
        assert_eq!(wrapped_of(&node, &id_b).amount, 100);
    }

    // nonce 已消费（幂等标记）
    assert!(store.registry().is_nonce_consumed(0xAAAA, 9));
}

/// 节点未注入 bridge store（未配置桥）→ bridge 合约调用 fail-closed。
#[test]
fn bridge_call_without_store_fails_closed() {
    let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).expect("node");
    let secp = Secp256k1::new();
    let (_recipient_sk, recipient) = key(0x77);
    let (sender_sk, sender) = key(0x88);
    let recipient_addr = derive_address(&recipient);

    register_sender(&node, &sender);
    let payload = BridgeVerifyTx {
        deposit: make_deposit(1, 100, recipient_addr),
        validator_signatures: vec![],
        recipient_sig: vec![0u8; 65],
        recipient_pubkey: recipient.clone(),
        preferred_relayer: None,
    };
    let tx = bridge_call_tx(
        &secp,
        &sender_sk,
        &sender,
        0,
        borsh::to_vec(&payload).expect("borsh"),
    );

    let outcome = node.execute_block_on_state(&env_for(&node, 1), &[tx]).expect("exec");
    assert!(
        !outcome.receipts[0].success,
        "无桥 store 的节点必须拒绝 bridge 调用"
    );
    assert!(
        outcome.receipts[0]
            .error
            .as_deref()
            .is_some_and(|e| e.to_lowercase().contains("bridge")),
        "失败原因应指向桥未授权：{:?}",
        outcome.receipts[0].error
    );
}

/// P0-4 回归（审计 2026-08-01）：bridge 铸币路径的前置写入不得在后置失败时
/// 留下半状态。
///
/// 构造：合法 quorum 签名的 bridge contract_call + 一个声明保留经济对象类型
/// 的显式 output → 桥分支验证/铸造成功后，`apply_tx_outputs` 预检拒绝 →
/// 整笔回执失败。断言：
/// 1. 回执失败且原因指向保留对象；
/// 2. wrapped Object 未落库；
/// 3. **deposit nonce 未被消费**（修复前：立即持久化导致「nonce 已烧、
///    无铸币」，该 deposit 永久不可桥入）；
/// 4. 同 deposit 重新提交干净 tx → 成功（证明 nonce 完好）。
#[test]
fn later_stage_failure_leaves_bridge_nonce_unconsumed() {
    let (node, store, validator_sks) = bridge_node();
    let secp = Secp256k1::new();
    let (recipient_sk, recipient) = key(0x77);
    let (sender_sk, sender) = key(0x88);
    let recipient_addr = derive_address(&recipient);
    register_sender(&node, &sender);

    let deposit = make_deposit(21, 300, recipient_addr);
    let args =
        signed_bridge_payload(&secp, &recipient_sk, &recipient, &validator_sks[..4], deposit);

    // 坏 tx：携带保留类型 output（apply_tx_outputs 预检必拒）
    let mut bad_tx = bridge_call_tx(&secp, &sender_sk, &sender, 0, args.clone());
    bad_tx.outputs = vec![Object::new(
        ObjectID::new(recipient_addr, 0xBAD),
        Ownership::AddressOwned { owner: recipient_addr },
        poker_l1::economics::NATIVE_COIN_OBJECT_TYPE,
        vec![0u8; 8],
        None,
    )];
    // 重签（outputs 参与 signing_hash）
    let sig = sign(&secp, &sender_sk, &bad_tx.signing_hash());
    bad_tx.signature = sig;

    let outcome = node
        .execute_block_on_state(&env_for(&node, 1), &[bad_tx.clone()])
        .expect("exec bad tx");
    assert!(!outcome.receipts[0].success, "保留类型 output 必须使整笔失败");
    assert!(
        outcome.receipts[0]
            .error
            .as_deref()
            .is_some_and(|e| e.contains("reserved") || e.contains("native ZCN")),
        "失败原因应指向保留对象预检：{:?}",
        outcome.receipts[0].error
    );

    // wrapped 未落库 + nonce 未消费（P0-4 核心：无半状态）
    let id = expected_wrapped_id(&bad_tx, 1, recipient_addr);
    assert!(node.get_object(&id).expect("get").is_none(), "失败 tx 不得铸出对象");
    assert!(
        !store.registry().is_nonce_consumed(0xAAAA, 21),
        "失败 tx 不得消费 deposit nonce（P0-4：nonce 烧毁 = deposit 永久不可桥入）"
    );

    // 同 deposit 干净重提 → 成功（nonce 完好如初）
    let good = bridge_call_tx(&secp, &sender_sk, &sender, 1, args);
    let outcome2 = node
        .execute_block_on_state(&env_for(&node, 2), &[good.clone()])
        .expect("exec good tx");
    assert!(outcome2.receipts[0].success, "同 deposit 干净重提必须成功：{:?}", outcome2.receipts[0].error);
    let id2 = expected_wrapped_id(&good, 2, recipient_addr);
    assert_eq!(wrapped_of(&node, &id2).amount, 300);
    assert!(store.registry().is_nonce_consumed(0xAAAA, 21));
}
