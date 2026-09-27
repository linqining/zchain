//! mock L1 全流程：chainId 闸门 → 上锚状态机（Submitted → Included →
//! Finalized）→ 入金监听（finalized 窗口 + nonce 去重）。

mod common;

use std::sync::{Arc, Mutex};

use common::{MockL1, MockState};
use monad_settlement::{AnchorState, AnchorSubmitter, Credentials, DepositWatcher, L1Rpc, SettlementError};

fn credentials() -> Credentials {
    Credentials::from_hex("0x4646464646464646464646464646464646464646464646464646464646464646")
        .expect("valid key")
}

#[test]
fn chain_id_gate_rejects_wrong_chain() {
    let mock = MockL1::spawn(Arc::new(Mutex::new(MockState::new(1)))); // 以太坊主网 ≠ Monad
    let rpc = L1Rpc::new(&mock.url).expect("url");
    let err = AnchorSubmitter::connect(rpc, credentials(), [9u8; 20], 143)
        .expect_err("must reject");
    assert!(matches!(err, SettlementError::ChainIdMismatch { expected: 143, actual: 1 }));
}

#[test]
fn anchor_lifecycle_submitted_included_finalized() {
    let state = Arc::new(Mutex::new(MockState::new(143)));
    let mock = MockL1::spawn(Arc::clone(&state));
    let rpc = L1Rpc::new(&mock.url).expect("url");
    let mut submitter =
        AnchorSubmitter::connect(rpc, credentials(), [0x42u8; 20], 143).expect("connects");

    // 提交批次根。
    let task = monad_settlement::anchor_task(0, [1u8; 32], 64);
    let tx = submitter.submit(&task).expect("submits").expect("fresh key");
    assert_ne!(tx, [0u8; 32]);
    // 同 key 幂等跳过。
    assert!(submitter.submit(&task).expect("dedupe").is_none());

    // mock 立即打包（receipt block=100）→ 首轮 poll 即 Included。
    submitter.poll().expect("polls");
    match &submitter.snapshot()[&task.key] {
        AnchorState::Included { block, .. } => assert_eq!(*block, 100),
        other => panic!("expected Included, got {other:?}"),
    }

    // finalized < block → 未终结；finalized ≥ block → Finalized。
    state.lock().expect("lock").finalized = 99;
    submitter.poll().expect("polls");
    assert!(!submitter.snapshot()[&task.key].is_finalized());
    state.lock().expect("lock").finalized = 100;
    submitter.poll().expect("polls");
    assert!(submitter.snapshot()[&task.key].is_finalized());
    assert_eq!(submitter.pending_finality(), 0);
}

#[test]
fn submit_nonce_advances_locally() {
    let state = Arc::new(Mutex::new(MockState::new(143)));
    let mock = MockL1::spawn(Arc::clone(&state));
    let rpc = L1Rpc::new(&mock.url).expect("url");
    let mut submitter =
        AnchorSubmitter::connect(rpc, credentials(), [0x42u8; 20], 143).expect("connects");

    let t1 = monad_settlement::anchor_task(0, [1u8; 32], 1);
    let t2 = monad_settlement::anchor_task(1, [2u8; 32], 2);
    let tx1 = submitter.submit(&t1).expect("ok").expect("fresh");
    let tx2 = submitter.submit(&t2).expect("ok").expect("fresh");
    // 两笔 nonce 相邻 → tx hash 不同（mock hash = keccak(raw)）。
    assert_ne!(tx1, tx2);
    // mock 侧 nonce 被消费（初始 0 → 2）。
    assert_eq!(state.lock().expect("lock").nonce, 2);
}

#[test]
fn deposit_watcher_finalized_window_and_dedupe() {
    let state = Arc::new(Mutex::new(MockState::new(143)));
    let mock = MockL1::spawn(Arc::clone(&state));
    let rpc = L1Rpc::new(&mock.url).expect("url");
    let mut watcher = DepositWatcher::new(rpc, [0x77u8; 20], 100);

    // finalized=90 < next_block=100 → 无事件。
    assert!(watcher.poll_once().expect("polls").is_empty());

    // 注入两条 DepositInitiated（block 120 落在 [100, 110] 窗外先测）；
    // 再把窗口推进到位。
    state.lock().expect("lock").finalized = 110;
    state
        .lock()
        .expect("lock")
        .logs
        .push((105, deposit_log(1, [0x11u8; 20], [0x22u8; 20], 1_000_000)));
    let events = watcher.poll_once().expect("polls");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].nonce, 1);
    assert_eq!(events[0].token, [0x11; 20]);
    assert_eq!(events[0].to, [0x22; 20]);
    assert_eq!(events[0].amount, 1_000_000);
    // 窗口推进到 finalized+1。
    assert_eq!(watcher.next_block(), 111);

    // 同 nonce 重复入仓 → 去重；新 nonce → 出事件。
    state.lock().expect("lock").finalized = 120;
    {
        let mut st = state.lock().expect("lock");
        st.logs.push((115, deposit_log(1, [0x11u8; 20], [0x22u8; 20], 1_000_000)));
        st.logs.push((115, deposit_log(2, [0x11u8; 20], [0x33u8; 20], 42)));
    }
    let events = watcher.poll_once().expect("polls");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].nonce, 2);
    assert_eq!(events[0].amount, 42);
}

/// 组一个 `DepositInitiated(uint256,address,address,uint256)` eth log 对象。
fn deposit_log(nonce: u64, token: [u8; 20], to: [u8; 20], amount: u128) -> serde_json::Value {
    let topic = |bytes: [u8; 32]| format!("0x{}", hex::encode(bytes));
    let addr_word = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let mut data = [0u8; 32];
    data[16..].copy_from_slice(&amount.to_be_bytes());
    serde_json::json!({
        "address": format!("0x{}", hex::encode([0x77u8; 20])),
        "topics": [
            topic(monad_settlement::abi::deposit_initiated_topic0()),
            topic(monad_settlement::abi::word_u64(nonce)),
            topic(addr_word(token)),
            topic(addr_word(to)),
        ],
        "data": format!("0x{}", hex::encode(data)),
        "blockNumber": "0x69",
    })
}
