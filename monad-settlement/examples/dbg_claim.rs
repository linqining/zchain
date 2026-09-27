//! 调试辅助：从钥文件派生 claim calldata（供 eth_call 仿真）。
use monad_settlement::abi::{encode_claim, ClaimLeaf};
use monad_settlement::keccak::keccak256;
use monad_settlement::proof;
use monad_settlement::Credentials;

fn main() {
    let key_path = std::env::var("KEY_FILE").unwrap_or_else(|_| "/tmp/monad_e2e_key.txt".into());
    let key = Credentials::from_hex(std::fs::read_to_string(&key_path).expect("key file").trim())
        .expect("key");
    let leaf = ClaimLeaf {
        request_id: keccak256(b"zchain-e2e.withdraw.1"),
        external_recipient: monad_settlement::abi::word_address(key.address()),
        asset_tag: 1,
        amount: 50_000_000_000_000_000,
        burned_note_commitment: keccak256(b"zchain-e2e.burn"),
        checkpoint_height: 1,
    };
    let root = proof::leaf_hash(&leaf);
    println!("addr  0x{}", hex::encode(key.address()));
    println!("root  0x{}", hex::encode(root));
    println!("claim 0x{}", hex::encode(encode_claim(&leaf, root, 1, 0, &[])));
}
