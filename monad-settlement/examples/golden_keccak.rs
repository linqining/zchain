//! 打印金标准向量的 keccak 常量（forge 测试用）。
use monad_settlement::keccak::keccak256;
fn main() {
    println!("REQ_ID  0x{}", hex::encode(keccak256(b"golden-request")));
    println!("BURN    0x{}", hex::encode(keccak256(b"golden-burn")));
}
