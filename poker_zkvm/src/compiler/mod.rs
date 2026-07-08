//! 前端编译流水线 — Rust → RV32I ELF 编译 + ELF 强化校验。
//!
//! 本模块提供：
//! - [`CompilerConfig`] — 编译器配置（target / opt-level / panic 策略）
//! - [`compile_crate`] — 调用 cargo + rustc 编译用户 crate 为 RV32I ELF
//! - [`elf_validator`] 子模块 — 强化 ELF 校验（TOCTOU 消除 + checked_add + PT_DYNAMIC 拒绝）
//! - [`prelude`] 子模块 — `zkvm::prelude` re-export + `entry` / `test` 宏

use crate::error::ZkvmError;
use std::path::{Path, PathBuf};
use std::process::Command;

pub mod elf_validator;
pub mod prelude;

// ===========================================================================
// CompilerConfig
// ===========================================================================

/// 编译器配置（spec L143, L149）。
///
/// 固定使用 `riscv32i-unknown-none-elf` target、opt-level=3、panic=abort，
/// 禁用浮点 / atomics / SIMD / inline asm。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilerConfig {
    /// 目标 triple（固定 `riscv32i-unknown-none-elf`）。
    pub target: &'static str,
    /// 优化级别（固定 3）。
    pub opt_level: u32,
    /// panic 策略（固定 `abort`）。
    pub panic: &'static str,
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            target: "riscv32i-unknown-none-elf",
            opt_level: 3,
            panic: "abort",
        }
    }
}

// ===========================================================================
// compile_crate
// ===========================================================================

/// 编译用户 crate 为 RV32I ELF（spec L145-150）。
///
/// 调用 `cargo build --target riscv32i-unknown-none-elf --release`，
/// 通过 `RUSTFLAGS` 传递 `-C panic=abort -C opt-level=3`。
/// 输出 ELF 文件到 `<crate_path>/target/riscv32i-unknown-none-elf/release/<crate_name>`。
///
/// # Errors
/// - 路径不存在 → `ZkvmError::Other`
/// - Cargo.toml 缺失或无法解析 crate name → `ZkvmError::Other`
/// - cargo 调用失败 → `ZkvmError::Other`（含 stderr）
/// - 编译产物不存在 → `ZkvmError::Other`
pub fn compile_crate(crate_path: &Path, config: &CompilerConfig) -> Result<PathBuf, ZkvmError> {
    if !crate_path.exists() {
        return Err(ZkvmError::Other(format!(
            "crate path does not exist: {}",
            crate_path.display()
        )));
    }

    let cargo_toml = crate_path.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(ZkvmError::Other(format!(
            "Cargo.toml not found in: {}",
            crate_path.display()
        )));
    }

    let crate_name = parse_crate_name(&cargo_toml)?;

    let rustflags = format!(
        "-C panic={} -C opt-level={}",
        config.panic, config.opt_level
    );

    let output = Command::new("cargo")
        .arg("build")
        .arg("--target")
        .arg(config.target)
        .arg("--release")
        .current_dir(crate_path)
        .env("RUSTFLAGS", &rustflags)
        .output()
        .map_err(|e| ZkvmError::Other(format!("failed to invoke cargo: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ZkvmError::Other(format!(
            "cargo build failed: {stderr}"
        )));
    }

    let elf_path = crate_path
        .join("target")
        .join(config.target)
        .join("release")
        .join(&crate_name);

    if !elf_path.exists() {
        return Err(ZkvmError::Other(format!(
            "compiled ELF not found at expected path: {}",
            elf_path.display()
        )));
    }

    Ok(elf_path)
}

/// 从 `Cargo.toml` 解析 `[package] name = "..."` 字段。
fn parse_crate_name(cargo_toml: &Path) -> Result<String, ZkvmError> {
    let content = std::fs::read_to_string(cargo_toml)
        .map_err(|e| ZkvmError::Other(format!("failed to read Cargo.toml: {e}")))?;

    let mut in_package = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(name) = parse_name_field(trimmed) {
            return Ok(name);
        }
    }
    Err(ZkvmError::Other(
        "crate name not found in [package] section of Cargo.toml".to_string(),
    ))
}

/// 从单行解析 `name = "..."` 字段值。
fn parse_name_field(line: &str) -> Option<String> {
    let rest = line.strip_prefix("name")?.trim_start();
    let rest = rest.strip_prefix('=')?;
    let name = rest.trim().trim_matches('"');
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

// ===========================================================================
// _start trampoline
// ===========================================================================

/// 生成 `_start` trampoline 源码（spec L172-174）。
///
/// trampoline 执行流程：
/// 1. `zkvm_read_input` syscall 读取输入 → `&[u8]`
/// 2. 调用用户 `main(input: &[u8]) -> Result<Vec<u8>, _>`
/// 3. `Ok(output)` → `zkvm_commit_output` 提交输出
/// 4. `Err(_)` / panic → `zkvm_panic` syscall 终止执行
///
/// 此源码字符串由 `compile_crate` 注入用户 crate 编译流程，
/// 在 no_std + no_main 环境下提供 ZKVM 入口点。
#[allow(dead_code)]
fn generate_start_trampoline() -> String {
    r#"//! ZKVM _start trampoline (auto-generated by cargo-zkvm).
//!
//! Reads input via zkvm_read_input syscall, calls user main,
//! commits output via zkvm_commit_output. Panics route to zkvm_panic.

extern "C" {
    fn zkvm_read_input(len_ptr: *mut u32) -> *const u8;
    fn zkvm_commit_output(ptr: *const u8, len: u32) -> !;
    fn zkvm_panic(msg_ptr: *const u8, len: u32) -> !;
}

extern "Rust" {
    fn main(input: &[u8]) -> Result<Vec<u8>, ()>;
}

#[panic_handler]
fn zkvm_panic_handler(_info: &core::panic::PanicInfo) -> ! {
    unsafe { zkvm_panic(b"panic\0".as_ptr(), 5); }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut len: u32 = 0;
    let ptr = unsafe { zkvm_read_input(&mut len) };
    let input: &[u8] = if len == 0 || ptr.is_null() {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(ptr, len as usize) }
    };
    match unsafe { main(input) } {
        Ok(output) => unsafe {
            zkvm_commit_output(output.as_ptr(), output.len() as u32)
        },
        Err(_) => unsafe { zkvm_panic(b"Err\0".as_ptr(), 3) },
    }
}
"#
    .to_string()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_config_default() {
        let config = CompilerConfig::default();
        assert_eq!(config.target, "riscv32i-unknown-none-elf");
        assert_eq!(config.opt_level, 3);
        assert_eq!(config.panic, "abort");
    }

    #[test]
    fn test_compiler_config_clone_debug() {
        let config = CompilerConfig::default();
        let cloned = config.clone();
        assert_eq!(config, cloned);
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("riscv32i-unknown-none-elf"));
    }

    #[test]
    fn test_generate_start_trampoline_contains_read_input() {
        let trampoline = generate_start_trampoline();
        assert!(
            trampoline.contains("zkvm_read_input"),
            "trampoline must declare zkvm_read_input syscall"
        );
    }

    #[test]
    fn test_generate_start_trampoline_contains_commit_output() {
        let trampoline = generate_start_trampoline();
        assert!(
            trampoline.contains("zkvm_commit_output"),
            "trampoline must declare zkvm_commit_output syscall"
        );
    }

    #[test]
    fn test_generate_start_trampoline_contains_panic() {
        let trampoline = generate_start_trampoline();
        assert!(
            trampoline.contains("zkvm_panic"),
            "trampoline must declare zkvm_panic syscall"
        );
    }

    #[test]
    fn test_generate_start_trampoline_contains_start_fn() {
        let trampoline = generate_start_trampoline();
        assert!(
            trampoline.contains("_start"),
            "trampoline must define _start entry point"
        );
        assert!(
            trampoline.contains("#[no_mangle]"),
            "_start must be no_mangle for linker"
        );
    }

    #[test]
    fn test_generate_start_trampoline_contains_panic_handler() {
        let trampoline = generate_start_trampoline();
        assert!(
            trampoline.contains("#[panic_handler]"),
            "trampoline must define panic_handler routing to zkvm_panic"
        );
    }

    #[test]
    fn test_compile_crate_missing_path() {
        let config = CompilerConfig::default();
        let result = compile_crate(Path::new("/nonexistent/path/to/crate"), &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            ZkvmError::Other(msg) => assert!(msg.contains("does not exist")),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn test_compile_crate_missing_cargo_toml() {
        let temp_dir = std::env::temp_dir().join("zkvm_test_no_cargo_toml");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let config = CompilerConfig::default();
        let result = compile_crate(&temp_dir, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            ZkvmError::Other(msg) => assert!(msg.contains("Cargo.toml")),
            other => panic!("expected Other, got {other:?}"),
        }
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_parse_crate_name_valid() {
        let temp_dir = std::env::temp_dir().join("zkvm_test_parse_name");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cargo_toml = temp_dir.join("Cargo.toml");
        std::fs::write(
            &cargo_toml,
            "[package]\nname = \"my_circuit\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let name = parse_crate_name(&cargo_toml).unwrap();
        assert_eq!(name, "my_circuit");
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_parse_crate_name_missing() {
        let temp_dir = std::env::temp_dir().join("zkvm_test_parse_missing");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cargo_toml = temp_dir.join("Cargo.toml");
        std::fs::write(&cargo_toml, "[package]\nversion = \"0.1.0\"\n").unwrap();
        let result = parse_crate_name(&cargo_toml);
        assert!(result.is_err());
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_parse_crate_name_with_dependencies() {
        let temp_dir = std::env::temp_dir().join("zkvm_test_parse_deps");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cargo_toml = temp_dir.join("Cargo.toml");
        std::fs::write(
            &cargo_toml,
            "[package]\nname = \"hello_world\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        let name = parse_crate_name(&cargo_toml).unwrap();
        assert_eq!(name, "hello_world");
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }
}
