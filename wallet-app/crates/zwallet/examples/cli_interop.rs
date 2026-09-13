//! CLI 互通演示：用 zwallet 创建钱包数据目录，之后 poker-wallet CLI（上游
//! wallet-core 自带 bin）可直接 `unlock`/`balances`/`notes`/`faucet-play`
//! 同一目录——桌面钱包与 CLI 共享数据格式（同为 wallet-core 信封/库快照）。
//!
//! 运行：
//!   cargo run -p zwallet --example cli_interop -- <dir> [--import-secret HEX]
//! 然后：
//!   cargo run -p poker-wallet -- --dir <dir> unlock --password demo-pass-123
use zwallet::Wallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: cli_interop <dir> [--import-secret HEX]");
    let mut secret = None;
    let mut it = args;
    while let Some(a) = it.next() {
        if a == "--import-secret" {
            secret = it.next();
        }
    }
    let mut w = Wallet::open(&dir)?;
    let status = w.status();
    if !status.initialized {
        w.create_wallet("demo-pass-123", secret.as_deref())?;
        w.demo_faucet(120)?;
        w.demo_faucet(80)?;
        w.lock();
    }
    println!("wallet ready at {dir}");
    println!("CLI: cargo run -p poker-wallet -- --dir {dir} unlock --password demo-pass-123");
    Ok(())
}
