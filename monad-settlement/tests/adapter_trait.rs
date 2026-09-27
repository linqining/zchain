//! MonadAdapter 的 SettlementAdapter trait 契约测试（mock L1 全流程）。
//!
//! 验证"新增结算链 = 实现 trait"的引擎侧承诺：引擎代码只面向
//! `dyn SettlementAdapter`，Monad 实现经 mock 全流程满足契约
//! （幂等提交 / 状态机 / 入金映射 / claim 门位 / 快照恢复）。

mod common;

use std::sync::{Arc, Mutex};

use common::{MockL1, MockState};
use monad_settlement::{Credentials, MonadAdapter};
use settlement_adapter::{
    AdapterError, AnchorKind, AnchorTask, ClaimRequest, SettlementAdapter,
};

fn credentials() -> Credentials {
    Credentials::from_hex("0x4646464646464646464646464646464646464646464646464646464646464646")
        .expect("valid key")
}

fn adapter_on(mock: &MockL1) -> MonadAdapter {
    MonadAdapter::new(
        &mock.url,
        credentials(),
        [0x42u8; 20], // inbox
        [0x77u8; 20], // bridge
        10143,
    )
    .expect("constructs")
}

#[test]
fn monad_adapter_full_lifecycle_via_dyn_trait() {
    let state = Arc::new(Mutex::new(MockState::new(10143)));
    let mock = MockL1::spawn(Arc::clone(&state));
    let mut adapter: Box<dyn SettlementAdapter> = Box::new(adapter_on(&mock));

    // chainId 闸门（connect 内置）。
    adapter.connect().expect("connects");
    assert_eq!(adapter.chain_id(), 10143);
    assert_eq!(adapter.host(), "monad");

    // 提交 + 幂等。
    let task = AnchorTask::new("batch:0:aa".into(), AnchorKind::Batch, vec![1, 2, 3]);
    let tx = adapter.submit_anchor(&task).expect("submits").expect("fresh");
    assert_ne!(tx, [0u8; 32]);
    assert!(adapter.submit_anchor(&task).expect("dedupe").is_none());
    assert_eq!(adapter.pending_finality(), 1);

    // mock 立即打包 → poll 推进；再把 finalized 拉到打包高度 → Finalized。
    adapter.poll().expect("poll1");
    state.lock().expect("lock").finalized = 100;
    adapter.poll().expect("poll2");
    assert_eq!(adapter.pending_finality(), 0);

    // 快照 → 新适配器恢复（重启续跑语义）。
    let snap = adapter.snapshot();
    let mut revived: Box<dyn SettlementAdapter> = Box::new(adapter_on(&mock));
    revived.restore(&snap);
    assert_eq!(revived.pending_finality(), 0, "恢复后无未终结项");
}

#[test]
fn monad_adapter_deposits_map_to_records() {
    let state = Arc::new(Mutex::new(MockState::new(10143)));
    let mock = MockL1::spawn(Arc::clone(&state));
    let mut adapter: Box<dyn SettlementAdapter> = Box::new(adapter_on(&mock));
    adapter.connect().expect("connects");

    // finalized 窗口推进 + 注入 DepositInitiated（token=0x11, to=0x22, 1.5 MON）。
    {
        let mut st = state.lock().expect("lock");
        st.finalized = 110;
        let topic = |b: [u8; 32]| format!("0x{}", hex::encode(b));
        let word = |low: [u8; 20]| {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&low);
            w
        };
        let mut data = [0u8; 32];
        data[16..].copy_from_slice(&1_500_000_000_000_000_000u128.to_be_bytes());
        st.logs.push((
            105,
            serde_json::json!({
                "address": format!("0x{}", hex::encode([0x77u8; 20])),
                "topics": [
                    topic(monad_settlement::abi::deposit_initiated_topic0()),
                    topic(monad_settlement::abi::word_u64(0)),
                    topic(word([0x11; 20])),
                    topic(word([0x22; 20])),
                ],
                "data": format!("0x{}", hex::encode(data)),
                "blockNumber": "0x69",
            }),
        ));
    }

    let records = adapter.poll_deposits().expect("drains");
    assert_eq!(records.len(), 1);
    let d = records[0];
    assert_eq!(d.nonce, 0);
    assert_eq!(&d.token[12..], &[0x11; 20]);
    assert_eq!(&d.token[..12], &[0u8; 12], "EVM 地址零填充高 12B");
    assert_eq!(&d.recipient[12..], &[0x22; 20]);
    assert_eq!(d.amount, 1_500_000_000_000_000_000);
    assert_eq!(d.host_block, 0x69);
    // 幂等：同轮窗口不重复产出。
    assert!(adapter.poll_deposits().expect("re-poll").is_empty());
}

#[test]
fn monad_adapter_forced_ops_escape_channel() {
    let state = Arc::new(Mutex::new(MockState::new(10143)));
    let mock = MockL1::spawn(Arc::clone(&state));
    let mut adapter: Box<dyn SettlementAdapter> = Box::new(adapter_on(&mock));
    adapter.connect().expect("connects");

    // 注入两条 ForcedOp（seq 0/1，用户提交的 L2 op 字节）。
    {
        let mut st = state.lock().expect("lock");
        st.finalized = 110;
        let topic = |b: [u8; 32]| format!("0x{}", hex::encode(b));
        let addr_word = |low: [u8; 20]| {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&low);
            w
        };
        for (seq, payload) in [(0u64, vec![0x01u8, 0x02]), (1u64, vec![0x03])] {
            // data = [offset=0x20][len][payload padded]（单动态参数 ABI 布局）
            let mut data = vec![0u8; 32];
            data[31] = 0x20; // offset = 32（指向 len 字）
            data.extend_from_slice(&monad_settlement::abi::word_u64(payload.len() as u64));
            data.extend_from_slice(&payload);
            while data.len() % 32 != 0 {
                data.push(0);
            }
            st.logs.push((
                106,
                serde_json::json!({
                    "address": format!("0x{}", hex::encode([0x77u8; 20])),
                    "topics": [
                        topic(monad_settlement::abi::forced_op_topic0()),
                        topic(monad_settlement::abi::word_u64(seq)),
                        topic(addr_word([0x33; 20])),
                    ],
                    "data": format!("0x{}", hex::encode(data)),
                    "blockNumber": "0x6a",
                }),
            ));
        }
    }

    let ops = adapter.poll_forced_ops().expect("drains");
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].seq, 0);
    assert_eq!(ops[0].payload, vec![1, 2]);
    assert_eq!(&ops[0].submitter[12..], &[0x33; 20]);
    assert_eq!(ops[1].seq, 1);
    // 幂等。
    assert!(adapter.poll_forced_ops().expect("re-poll").is_empty());
}

#[test]
fn monad_adapter_claim_gates_and_payload_shape() {
    let state = Arc::new(Mutex::new(MockState::new(10143)));
    let mock = MockL1::spawn(Arc::clone(&state));
    let adapter: Box<dyn SettlementAdapter> = Box::new(adapter_on(&mock));

    let base = ClaimRequest {
        request_id: [1; 32],
        recipient: [2; 32],
        asset_tag: 1,
        amount: 5_000_000_000_000_000_000,
        burned_note_commitment: [4; 32],
        checkpoint_height: 7,
        withdrawal_root: [6; 32],
        leaf_count: 1,
        leaf_index: 0,
        proof: vec![[9; 32]; 2],
    };

    // 原生可领：payload = selector(4) + 10 head words + len + 2 nodes。
    let payload = adapter.claim_payload(&base).expect("native claim encodes");
    assert_eq!(payload.len(), 4 + 10 * 32 + 32 + 2 * 32);

    // PLAY（tag 2）不可跨链兑付（与 L1Outbox 合约 fail-closed 一致）。
    let play = ClaimRequest { asset_tag: 2, proof: base.proof.clone(), ..base };
    assert!(matches!(adapter.claim_payload(&play), Err(AdapterError::NotConfigured(_))));

    // 未知 tag 拒绝。
    let junk = ClaimRequest { asset_tag: 9, ..base };
    assert!(matches!(adapter.claim_payload(&junk), Err(AdapterError::NotConfigured(_))));
}

#[test]
fn monad_adapter_rejects_wrong_chain_at_construction() {
    // chainId 闸门在构造期（AnchorSubmitter::connect）即触发——错链根本拿不到适配器。
    let mock = MockL1::spawn(Arc::new(Mutex::new(MockState::new(1)))); // 以太坊主网
    let err = MonadAdapter::new(
        &mock.url,
        credentials(),
        [0x42u8; 20],
        [0x77u8; 20],
        10143,
    )
    .expect_err("wrong chain must fail at construction");
    assert!(
        format!("{err}").contains("chain id mismatch"),
        "error should name the chain mismatch: {err}"
    );
}
