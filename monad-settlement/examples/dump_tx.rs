//! 开发/验收辅助：按参数打印 EIP-155 legacy 原始交易 hex。
//!
//! 用法（参数均为 hex 或十进制字符串）：
//! ```
//! cargo run -p monad-settlement --example dump_tx -- \
//!   --key 0x46…46 --chain-id 10143 --nonce 0 \
//!   --gas-price 110000000000 --gas 53000 \
//!   [--to 0x…20B] [--value 0] [--data 0x00] [--create]
//! ```

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let get = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a.as_str() == format!("--{name}"))
            .and_then(|i| args.get(i + 1).cloned())
    };
    let key = monad_settlement::Credentials::from_hex(
        &get("key").unwrap_or_else(|| "0x4646464646464646464646464646464646464646464646464646464646464646".into()),
    )
    .expect("key");
    let chain_id: u64 = get("chain-id").unwrap_or_else(|| "10143".into()).parse().expect("chain id");
    let nonce: u64 = get("nonce").unwrap_or_else(|| "0".into()).parse().expect("nonce");
    let gas_price: u128 = get("gas-price").unwrap_or_else(|| "110000000000".into()).parse().expect("gas price");
    let gas_limit: u128 = get("gas").unwrap_or_else(|| "53000".into()).parse().expect("gas");
    let value: u128 = get("value").unwrap_or_else(|| "0".into()).parse().expect("value");
    let to = get("to").map(|s| {
        let trimmed = s.strip_prefix("0x").unwrap_or(&s);
        let mut out = [0u8; 20];
        hex::decode_to_slice(trimmed, &mut out).expect("to address");
        out
    });
    let data = get("data")
        .map(|s| hex::decode(s.strip_prefix("0x").unwrap_or(&s)).expect("data hex"))
        .unwrap_or_default();

    let tx = monad_settlement::signer::LegacyTx { nonce, gas_price, gas_limit, to, value, data };
    let signed = key.sign_eip155(&tx, chain_id).expect("signs");
    println!("from   0x{}", hex::encode(key.address()));
    println!("hash   0x{}", hex::encode(signed.hash));
    println!("raw    0x{}", hex::encode(&signed.raw));
}
