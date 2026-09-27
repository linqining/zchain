//! 金标准向量：Rust 侧 leaf_hash/digest_of → 硬编码进 forge 测试，
//! 锁死 Solidity 镜像的字节级正确性（_sha256 栈指针 bug 的防回归）。
use monad_settlement::abi::{word_address, ClaimLeaf};
use monad_settlement::keccak::keccak256;
use monad_settlement::proof;

fn main() {
    let leaf = ClaimLeaf {
        request_id: keccak256(b"golden-request"),
        external_recipient: word_address([
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        ]),
        asset_tag: 1,
        amount: 123,
        burned_note_commitment: keccak256(b"golden-burn"),
        checkpoint_height: 7,
    };
    let root = proof::leaf_hash(&leaf);
    let digest = proof::digest_of(7, 1, root);
    println!("GOLDEN_ROOT   0x{}", hex::encode(root));
    println!("GOLDEN_DIGEST 0x{}", hex::encode(digest));
}
