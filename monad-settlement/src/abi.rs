//! 结算合约 calldata 编码 + 入金事件解码。
//!
//! 只覆盖 `contracts/monad/` 的入口面；静态类型（uintN/bytes32/bool/uint8）
//! 一律 32B 大端补齐，动态 `bytes32[]` 走 head/tail（唯一动态参数排尾部）。

use crate::error::SettlementError;
use crate::keccak::{keccak256, selector};

/// 32B 字（大端补齐 u64）。
#[must_use]
pub fn word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// 32B 字（bool）。
#[must_use]
pub fn word_bool(value: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = u8::from(value);
    word
}

/// 32B 字（uint8）。
#[must_use]
pub fn word_u8(value: u8) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = value;
    word
}

/// selector + 静态参数拼接（全部参数定长时的通用小工具）。
fn encode_static(sig: &str, params: &[&[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + params.len() * 32);
    out.extend_from_slice(&selector(sig));
    for p in params {
        out.extend_from_slice(*p);
    }
    out
}

/// `L1Inbox.submitBatch(uint64,bytes32,uint64)`。
#[must_use]
pub fn encode_submit_batch(index: u64, root: [u8; 32], through_op: u64) -> Vec<u8> {
    encode_static(
        "submitBatch(uint64,bytes32,uint64)",
        &[&word_u64(index), &root, &word_u64(through_op)],
    )
}

/// `L1Inbox.submitAggregate(uint64,bytes32,uint64,uint64)`。
#[must_use]
pub fn encode_submit_aggregate(
    index: u64,
    root: [u8; 32],
    through_op: u64,
    batch_count: u64,
) -> Vec<u8> {
    encode_static(
        "submitAggregate(uint64,bytes32,uint64,uint64)",
        &[&word_u64(index), &root, &word_u64(through_op), &word_u64(batch_count)],
    )
}

/// `L1Inbox.submitCheckpoint(uint64,bytes32,bytes32,uint64)`。
#[must_use]
pub fn encode_submit_checkpoint(
    l2_height: u64,
    state_root: [u8; 32],
    withdrawal_root: [u8; 32],
    leaf_count: u64,
) -> Vec<u8> {
    encode_static(
        "submitCheckpoint(uint64,bytes32,bytes32,uint64)",
        &[
            &word_u64(l2_height),
            &state_root,
            &withdrawal_root,
            &word_u64(leaf_count),
        ],
    )
}

/// `L1Outbox.commitRoot(uint64,uint64,bytes32,bool)`。
#[must_use]
pub fn encode_commit_root(
    l2_height: u64,
    leaf_count: u64,
    root: [u8; 32],
    finalized: bool,
) -> Vec<u8> {
    encode_static(
        "commitRoot(uint64,uint64,bytes32,bool)",
        &[
            &word_u64(l2_height),
            &word_u64(leaf_count),
            &root,
            &word_bool(finalized),
        ],
    )
}

/// `L1Outbox.markFinalized(bytes32)`。
#[must_use]
pub fn encode_mark_finalized(digest: [u8; 32]) -> Vec<u8> {
    encode_static("markFinalized(bytes32)", &[&digest])
}

/// 提现承诺字段（与 L1Outbox.WithdrawalLeaf / poker-appchain
/// `WithdrawalLeaf` 一一对应；见 [`crate::proof::LeafFields`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimLeaf {
    /// 提现请求幂等键。
    pub request_id: [u8; 32],
    /// 外部收款地址（低 20B = EVM 地址）。
    pub external_recipient: [u8; 32],
    /// 资产标签（1=MON / 3=USDT / 4=USDC；2=PLAY 不可领）。
    pub asset_tag: u8,
    /// 打款净额。
    pub amount: u64,
    /// 被销毁 note 承诺。
    pub burned_note_commitment: [u8; 32],
    /// 承载 checkpoint 高度。
    pub checkpoint_height: u64,
}

/// `L1Outbox.claim((bytes32,bytes32,uint8,uint64,bytes32,uint64),bytes32,uint64,uint64,bytes32[])`。
///
/// head 段 = selector + tuple(6 静态字) + root + leafCount + index + 数组偏移；
/// tail 段 = 数组长度 + 元素。
#[must_use]
pub fn encode_claim(
    leaf: &ClaimLeaf,
    root: [u8; 32],
    leaf_count: u64,
    index: u64,
    proof: &[[u8; 32]],
) -> Vec<u8> {
    let head_words = 6 + 3; // tuple 静态展开 + root + leafCount + index
    let offset_words = head_words + 1; // 动态数组 data 偏移（word 计）
    let mut out = encode_static(
        "claim((bytes32,bytes32,uint8,uint64,bytes32,uint64),bytes32,uint64,uint64,bytes32[])",
        &[
            &leaf.request_id,
            &leaf.external_recipient,
            &word_u8(leaf.asset_tag),
            &word_u64(leaf.amount),
            &leaf.burned_note_commitment,
            &word_u64(leaf.checkpoint_height),
            &root,
            &word_u64(leaf_count),
            &word_u64(index),
            &word_u64(offset_words as u64 * 32),
        ],
    );
    out.extend_from_slice(&word_u64(proof.len() as u64));
    for node in proof {
        out.extend_from_slice(node);
    }
    out
}

/// `L1Bridge.depositNative(address)`。
#[must_use]
pub fn encode_deposit_native(to: [u8; 20]) -> Vec<u8> {
    let mut to32 = [0u8; 32];
    to32[12..].copy_from_slice(&to);
    encode_static("depositNative(address)", &[&to32])
}

/// 20B 地址字（E2E/部署脚本共用）。
#[must_use]
pub fn word_address(to: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&to);
    word
}

/// 32B 字（u128 大端补齐；uint256 参数面）。
#[must_use]
pub fn word_u128(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// `setInbox(address)` / `setBridge(address)` / `setOutbox(address)` 的
/// 通用形态（同签名族；selector 由 sig 决定）。
#[must_use]
pub fn encode_set_address(sig: &str, to: [u8; 20]) -> Vec<u8> {
    encode_static(sig, &[&word_address(to)])
}

/// `L1Outbox.setClaimDelayBlocks(uint64)`。
#[must_use]
pub fn encode_set_claim_delay_blocks(blocks: u64) -> Vec<u8> {
    encode_static("setClaimDelayBlocks(uint64)", &[&word_u64(blocks)])
}

/// `L1Outbox.setLargePayoutThreshold(uint8,uint256)`。
#[must_use]
pub fn encode_set_large_payout_threshold(tag: u8, threshold: u128) -> Vec<u8> {
    encode_static(
        "setLargePayoutThreshold(uint8,uint256)",
        &[&word_u8(tag), &word_u128(threshold)],
    )
}

/// `L1Inbox.batchCount()` 的 selector（eth_call 返回 uint64 字）。
#[must_use]
pub fn batch_count_selector() -> [u8; 4] {
    selector("batchCount()")
}

// ---------------------------------------------------------------------------
// 事件解码
// ---------------------------------------------------------------------------

/// `DepositInitiated(uint256,uint256,uint256,uint256)` 的 topic0。
///
/// event DepositInitiated(uint256 indexed nonce, address indexed token,
/// address indexed to, uint256 amount);
#[must_use]
pub fn deposit_initiated_topic0() -> [u8; 32] {
    keccak256(b"DepositInitiated(uint256,address,address,uint256)")
}

/// 解析后的入金事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositEvent {
    /// 入金 nonce（L2 侧 deposit_id 幂等键的原料）。
    pub nonce: u64,
    /// L1 代币地址（`[0u8;20]` = 原生 MON）。
    pub token: [u8; 20],
    /// L2 收款人（EVM 地址投影）。
    pub to: [u8; 20],
    /// 锁仓金额（wei / 最小单位）。
    pub amount: u128,
}

/// 从 log（topics + data）解析 [`DepositEvent`]。
///
/// # Errors
/// topics 数量/长度不符 → [`SettlementError::Shape`]。
pub fn parse_deposit_log(topics: &[[u8; 32]], data: &[u8]) -> Result<DepositEvent, SettlementError> {
    if topics.len() != 4 {
        return Err(SettlementError::shape(
            "deposit_log",
            format!("expected 4 topics (sig+3 indexed), got {}", topics.len()),
        ));
    }
    if topics[0] != deposit_initiated_topic0() {
        return Err(SettlementError::shape("deposit_log", "topic0 mismatch"));
    }
    if data.len() < 32 {
        return Err(SettlementError::shape(
            "deposit_log",
            "data too short for amount",
        ));
    }
    let nonce_full = word_to_u128(&topics[1]);
    let nonce = u64::try_from(nonce_full)
        .map_err(|_| SettlementError::shape("deposit_log", "nonce exceeds u64"))?;
    let amount = u128::from_be_bytes({
        let mut b = [0u8; 16];
        b.copy_from_slice(&data[16..32]);
        b
    });
    Ok(DepositEvent {
        nonce,
        token: topics[2][12..].try_into().expect("20 of 32"),
        to: topics[3][12..].try_into().expect("20 of 32"),
        amount,
    })
}

fn word_to_u128(word: &[u8; 32]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&word[16..32]);
    u128::from_be_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_batch_calldata_shape() {
        let calldata = encode_submit_batch(1, [2u8; 32], 3);
        // 4 + 3*32 静态字。
        assert_eq!(calldata.len(), 100);
        assert_eq!(&calldata[4..36], &word_u64(1));
        assert_eq!(&calldata[36..68], &[2u8; 32]);
        assert_eq!(&calldata[68..100], &word_u64(3));
    }

    #[test]
    fn claim_head_offsets() {
        let leaf = ClaimLeaf {
            request_id: [1u8; 32],
            external_recipient: {
                let mut w = [0u8; 32];
                w[31] = 2;
                w
            },
            asset_tag: 1,
            amount: 3,
            burned_note_commitment: [4u8; 32],
            checkpoint_height: 5,
        };
        let proof = vec![[9u8; 32]; 3];
        let calldata = encode_claim(&leaf, [7u8; 32], 1, 0, &proof);
        // 4 + 10*32 (head) + 32 (len) + 3*32 (elements)。
        assert_eq!(calldata.len(), 4 + 320 + 32 + 96);
        // 数组偏移 word = 320。
        assert_eq!(&calldata[4 + 9 * 32..4 + 10 * 32], &word_u64(320));
        // 数组长度 = 3。
        assert_eq!(&calldata[324..356], &word_u64(3));
    }

    #[test]
    fn deposit_log_roundtrip() {
        let topics = [
            deposit_initiated_topic0(),
            word_u64(42),               // nonce
            address_word(&[0x11; 20]),  // token
            address_word(&[0x22; 20]),  // to
        ];
        let mut data = [0u8; 32];
        data[16..].copy_from_slice(&1_000_000u128.to_be_bytes());
        let ev = parse_deposit_log(&topics, &data).expect("parses");
        assert_eq!(ev.nonce, 42);
        assert_eq!(ev.token, [0x11; 20]);
        assert_eq!(ev.to, [0x22; 20]);
        assert_eq!(ev.amount, 1_000_000);
    }

    fn address_word(addr: &[u8; 20]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(addr);
        w
    }
}
