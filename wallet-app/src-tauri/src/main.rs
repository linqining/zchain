//! ZChain 桌面钱包 MVP — Tauri v2 壳（plan §6.12.5）。
//!
//! 壳层纪律：本 crate 只做 IPC 命令暴露 + 原生对话框 + 数据目录落位；
//! 全部钱包逻辑在 `zwallet`（→ wallet-core）。见 `commands.rs`。

#![deny(unsafe_code)]

pub mod commands;

use std::sync::Mutex;
use tauri::Manager;
use zwallet::Wallet;

/// 全局钱包状态（单实例；所有命令串行访问）。
pub struct AppState {
    /// 钱包（数据目录在 setup 时定位）。
    pub wallet: Mutex<Wallet>,
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // 数据目录：macOS → ~/Library/Application Support/dev.zchain.wallet-mvp
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir).map_err(|e| format!("io: {e}"))?;
            let wallet = Wallet::open(&dir)
                .map_err(|e| format!("wallet open failed: {e}"))?;
            app.manage(AppState { wallet: Mutex::new(wallet) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::create_wallet,
            commands::unlock,
            commands::lock_wallet,
            commands::set_auto_lock,
            commands::play_notes,
            commands::demo_faucet,
            commands::preview_sign,
            commands::confirm_sign,
            commands::sign_raw_bytes,
            commands::backup_export,
            commands::backup_import,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ZChain Wallet");
}
