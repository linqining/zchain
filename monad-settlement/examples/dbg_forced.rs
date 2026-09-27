//! 调试：活链 forceOp 提交 → watcher 捕获全流程。
use monad_settlement::{DepositWatcher, L1Rpc};
use monad_settlement::Credentials;
use monad_settlement::signer::LegacyTx;
fn main() {
    let url = "https://testnet-rpc.monad.xyz";
    let bridge: [u8; 20] = {
        let s = "0x57815a79519c4788497ca522325f4cb760f231ec";
        let t = s.trim().strip_prefix("0x").unwrap_or(s);
        let mut o = [0u8; 20];
        hex::decode_to_slice(t, &mut o).expect("bridge");
        o
    };
    let key = Credentials::from_hex(std::fs::read_to_string("/tmp/monad_e2e_key.txt").expect("key").trim())
        .expect("key");
    let rpc = L1Rpc::new(url).expect("rpc");

    // 1. 提交 forceOp(payload)
    let payload = monad_settlement::keccak::keccak256(b"zchain-dbg-force").to_vec();
    let mut calldata = vec![0u8; 4];
    calldata.extend_from_slice(&monad_settlement::abi::word_u64(0x20));
    calldata.extend_from_slice(&monad_settlement::abi::word_u64(payload.len() as u64));
    calldata.extend_from_slice(&payload);
    while calldata.len() % 32 != 0 {
        calldata.push(0);
    }
    calldata[0..4].copy_from_slice(&monad_settlement::keccak::keccak256(b"forceOp(bytes)")[0..4]);
    let nonce = rpc.transaction_count(&key.address()).expect("nonce");
    let gas_price = rpc.gas_price().expect("gp").saturating_mul(11) / 10;
    let tx = LegacyTx { nonce, gas_price, gas_limit: 200_000, to: Some(bridge), value: 0, data: calldata };
    let signed = key.sign_eip155(&tx, 10143).expect("signs");
    let tx_hash = rpc.send_raw_transaction(&signed.raw).expect("sends");
    println!("forceOp tx 0x{}", hex::encode(tx_hash));
    let receipt = rpc.wait_receipt(&tx_hash, 1500, 40).expect("mined");
    println!("mined at block {}, success={}", receipt.block_number, receipt.success);

    // 2. watcher 捕获（窗口从回执高度起）
    let mut watcher = DepositWatcher::new(L1Rpc::new(url).expect("rpc"), bridge, receipt.block_number);
    for i in 0..30 {
        match watcher.poll_forced_ops() {
            Ok(events) => {
                println!("poll {i}: {} events (window from {})", events.len(), receipt.block_number);
                if let Some(ev) = events.into_iter().find(|ev| ev.payload == payload) {
                    println!("CAPTURED seq={} payload len={}", ev.seq, ev.payload.len());
                    return;
                }
            }
            Err(e) => println!("poll {i}: err {e}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }
    println!("NOT CAPTURED");
}
