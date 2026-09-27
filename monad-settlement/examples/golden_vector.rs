//! 金标准向量：zchain `monad-settlement::abi` 独立计算的编码期望值，
//! 硬编码进外部 poker_texas_air `host_evm_settlement` 的测试（跨仓字节锁）。
use monad_settlement::abi::{
    encode_claim, encode_commit_root, encode_deposit_native, encode_force_op,
    encode_mark_finalized, encode_submit_aggregate, encode_submit_batch,
    encode_submit_checkpoint, word_address, ClaimLeaf,
};
use monad_settlement::keccak::keccak256;
use monad_settlement::abi as zabi;

fn hx(v: &[u8]) -> String {
    format!("0x{}", hex::encode(v))
}

fn main() {
    // selectors
    for sig in [
        "submitBatch(uint64,bytes32,uint64)",
        "submitAggregate(uint64,bytes32,uint64,uint64)",
        "submitCheckpoint(uint64,bytes32,bytes32,uint64)",
        "commitRoot(uint64,uint64,bytes32,bool)",
        "markFinalized(bytes32)",
        "claim((bytes32,bytes32,uint8,uint64,bytes32,uint64),bytes32,uint64,uint64,bytes32[])",
        "depositNative(address)",
        "forceOp(bytes)",
    ] {
        println!("SEL  {:<80} 0x{}", sig, hex::encode(monad_settlement::keccak::selector(sig)));
    }
    println!("TOPIC_DEPOSIT  0x{}", hex::encode(zabi::deposit_initiated_topic0()));
    println!("TOPIC_FORCED   0x{}", hex::encode(zabi::forced_op_topic0()));

    // 金标准叶子（与 golden_vector 输出同源）
    let leaf = ClaimLeaf {
        request_id: keccak256(b"golden-request"),
        external_recipient: word_address([0x22; 20]),
        asset_tag: 1,
        amount: 123,
        burned_note_commitment: keccak256(b"golden-burn"),
        checkpoint_height: 7,
    };
    let root = monad_settlement::proof::leaf_hash(&leaf);
    println!("LEAF_ROOT  0x{}", hex::encode(root));
    println!("SUBMIT_BATCH  {}", hx(&encode_submit_batch(1, root, 64)));
    println!("SUBMIT_AGGREGATE  {}", hx(&encode_submit_aggregate(2, root, 128, 5)));
    println!("SUBMIT_CHECKPOINT  {}", hx(&encode_submit_checkpoint(7, root, root, 1)));
    println!("COMMIT_ROOT  {}", hx(&encode_commit_root(7, 1, root, true)));
    println!("MARK_FINALIZED  {}", hx(&encode_mark_finalized(root)));
    println!("DEPOSIT_NATIVE  {}", hx(&encode_deposit_native([0x33; 20])));
    println!("FORCE_OP  {}", hx(&encode_force_op(&[0x01, 0x02])));
    println!("CLAIM  {}", hx(&encode_claim(&leaf, root, 1, 0, &[[9; 32]; 2])));
}
