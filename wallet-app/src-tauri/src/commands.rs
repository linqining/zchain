//! Tauri IPC 命令层：`zwallet::Wallet` 的 1:1 薄暴露（不添加/绕过任何钱包
//! 逻辑；错误 `to_string` 直传前端——fail-closed 语义与 wallet-core 一致）。
//!
//! 注意：命令内部不打印任何口令/私钥材料；`ZWalletError` 的 Display 不含
//! secret（wallet-core 纪律：secret 永不进日志）。

use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, FilePath};
use zwallet::dto::{BackupInfoDto, NotesPageDto, SignRequestDto, SignedDto, StatusDto};
use zwallet::{SigningPreview, Wallet, ZWalletError};

use crate::AppState;

type CmdResult<T> = Result<T, String>;

fn err(e: ZWalletError) -> String {
    e.to_string()
}

fn with_wallet<T>(state: &State<'_, AppState>, f: impl FnOnce(&mut Wallet) -> Result<T, ZWalletError>) -> CmdResult<T> {
    let mut guard = state.wallet.lock().map_err(|_| "wallet mutex poisoned")?;
    f(&mut guard).map_err(err)
}

/// [`crate::main`] 的命令清单文档化入口（保持 main.rs 简洁）。
#[tauri::command]
pub fn status(state: State<'_, AppState>) -> CmdResult<StatusDto> {
    with_wallet(&state, |w| Ok(w.status()))
}

/// 创建（或经 secret_hex 导入 owner key）钱包。
#[tauri::command]
pub fn create_wallet(
    state: State<'_, AppState>,
    password: String,
    secret_hex: Option<String>,
) -> CmdResult<StatusDto> {
    with_wallet(&state, |w| w.create_wallet(&password, secret_hex.as_deref()))
}

#[tauri::command]
pub fn unlock(state: State<'_, AppState>, password: String) -> CmdResult<StatusDto> {
    with_wallet(&state, |w| w.unlock(&password))
}

#[tauri::command]
pub fn lock_wallet(state: State<'_, AppState>) -> CmdResult<StatusDto> {
    with_wallet(&state, |w| {
        w.lock();
        Ok(w.status())
    })
}

#[tauri::command]
pub fn set_auto_lock(state: State<'_, AppState>, secs: u64) -> CmdResult<StatusDto> {
    with_wallet(&state, |w| {
        w.set_auto_lock_secs(secs)?;
        Ok(w.status())
    })
}

#[tauri::command]
pub fn play_notes(state: State<'_, AppState>) -> CmdResult<NotesPageDto> {
    with_wallet(&state, |w| w.play_notes())
}

/// 本地演示 faucet（**明示 demo**：本地铸造 PLAY note，不连网、非链上余额）。
#[tauri::command]
pub fn demo_faucet(state: State<'_, AppState>, amount: u64) -> CmdResult<zwallet::dto::NoteDto> {
    with_wallet(&state, |w| w.demo_faucet(amount))
}

/// 签名预览（确认页第一屏：逐字段）。
#[tauri::command]
pub fn preview_sign(
    state: State<'_, AppState>,
    req: SignRequestDto,
) -> CmdResult<SigningPreview> {
    with_wallet(&state, |w| w.preview_sign(&req))
}

/// 签名确认（确认页第二屏）。
#[tauri::command]
pub fn confirm_sign(state: State<'_, AppState>, req: SignRequestDto) -> CmdResult<SignedDto> {
    with_wallet(&state, |w| w.confirm_sign(&req))
}

/// 负例入口：任意 bytes 签名恒被拒绝（WALLET-ACC-3）。返回值仅在 wallet-core
/// 放行时为 Ok；当前恒走 Err 分支（原文透传拒绝原因）。
#[tauri::command]
pub fn sign_raw_bytes(state: State<'_, AppState>, label: String, bytes: Vec<u8>) -> CmdResult<String> {
    with_wallet(&state, |w| match w.sign_raw_bytes(&label, &bytes) {
        Ok(()) => Ok("signed".into()),
        Err(e) => Err(e),
    })
}

/// 加密备份导出：wallet-core `export_backup` 字节 → 原生保存对话框写盘。
#[tauri::command]
pub fn backup_export(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> CmdResult<BackupSavedDto> {
    let (info, bytes) = with_wallet(&state, |w| w.backup_export(&password))?;
    let file = app
        .dialog()
        .file()
        .set_file_name(&info.suggested_filename)
        .blocking_save_file();
    match file {
        Some(FilePath::Path(p)) => {
            std::fs::write(&p, &bytes).map_err(|e| format!("io: {e}"))?;
            Ok(BackupSavedDto { info, saved_to: Some(p.display().to_string()), bytes_len: bytes.len() })
        }
        Some(other) => Err(format!("unsupported dialog path: {other:?}")),
        None => Ok(BackupSavedDto { info, saved_to: None, bytes_len: bytes.len() }),
    }
}

/// 备份导出结果（对话框取消 → saved_to None）。
#[derive(serde::Serialize)]
pub struct BackupSavedDto {
    /// 备份信息。
    pub info: BackupInfoDto,
    /// 实际写盘路径（取消保存 → None）。
    pub saved_to: Option<String>,
    /// 文件字节数。
    pub bytes_len: usize,
}

/// 加密备份导入：原生打开对话框 → wallet-core `import_backup`
/// （口令错/篡改/未来版本/索引不一致 fail-closed；成功后回锁定态）。
#[tauri::command]
pub fn backup_import(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> CmdResult<StatusDto> {
    let file = app.dialog().file().blocking_pick_file();
    let path = match file {
        Some(FilePath::Path(p)) => p,
        Some(other) => return Err(format!("unsupported dialog path: {other:?}")),
        None => return Err("canceled".into()),
    };
    let bytes = std::fs::read(&path).map_err(|e| format!("io: {e}"))?;
    with_wallet(&state, |w| w.backup_import(&bytes, &password))
}
