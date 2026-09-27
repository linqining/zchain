//! 打印 ForcedOp topic0（链上排查用）。
use monad_settlement::abi::forced_op_topic0;
fn main() {
    println!("0x{}", hex::encode(forced_op_topic0()));
}
