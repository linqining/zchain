//! `cargo-zkvm` — ZKVM 编译、执行、证明与验证 CLI 工具。
//!
//! 子命令：
//! - `build` — 编译 crate 为 RV32I ELF + 强化校验
//! - `run --elf <PATH> --input <PATH>` — 执行 ELF 并输出步数 + output 长度
//! - `prove --elf <PATH> --input <PATH> --output <PATH>` — 生成 proof + public_io 文件
//! - `verify --proof <PATH> --public-io <PATH>` — 验证 proof（Phase 11 未就绪，stub）
//! - `test` — 扫描 `#[zkvm::test]` 标记函数（Phase 3 未就绪，stub）
//!
//! 作为 cargo 子命令运行：`cargo zkvm build`（cargo 自动调用 `cargo-zkvm build`）。
//! 也可直接运行：`cargo-zkvm build`。

use poker_zkvm::compiler::elf_validator::validate_elf;
use poker_zkvm::compiler::{CompilerConfig, compile_crate};
use poker_zkvm::prover::{ProverConfig, prove};
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match dispatch(&args[1..], &cwd) {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

/// 路由子命令到对应处理函数。
fn dispatch(args: &[String], cwd: &Path) -> Result<String, String> {
    // cargo 子命令约定：`cargo zkvm build` → args = ["zkvm", "build", ...]
    let args = if args.first().map(String::as_str) == Some("zkvm") {
        &args[1..]
    } else {
        args
    };

    let subcommand = args.first().ok_or_else(|| {
        "missing subcommand. Usage: cargo zkvm <build|run|prove|verify|test>".to_string()
    })?;

    match subcommand.as_str() {
        "build" => cmd_build(&args[1..], cwd),
        "run" => cmd_run(&args[1..]),
        "prove" => cmd_prove(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "test" => cmd_test(&args[1..], cwd),
        "--help" | "-h" | "help" => Ok(usage_string()),
        _ => Err(format!(
            "unknown subcommand: '{subcommand}'. Available: build, run, prove, verify, test"
        )),
    }
}

/// `build` 子命令 — 编译 crate + ELF 校验。
fn cmd_build(_args: &[String], cwd: &Path) -> Result<String, String> {
    let config = CompilerConfig::default();

    let elf_path = compile_crate(cwd, &config).map_err(|e| format!("compile failed: {e}"))?;

    let elf_bytes = std::fs::read(&elf_path)
        .map_err(|e| format!("failed to read ELF {}: {e}", elf_path.display()))?;

    let metadata = validate_elf(&elf_bytes).map_err(|e| format!("ELF validation failed: {e}"))?;

    let text_size = metadata.text.as_ref().map(|t| t.data.len()).unwrap_or(0);
    Ok(format!(
        "Build successful: {} (entry=0x{:08x}, {} segment(s), text={} bytes)",
        elf_path.display(),
        metadata.entry,
        metadata.segments.len(),
        text_size,
    ))
}

/// `run` 子命令 — 执行 ELF 并输出步数 + output 长度。
fn cmd_run(args: &[String]) -> Result<String, String> {
    let elf_path = parse_arg(args, "--elf")?;
    let input_path = parse_arg(args, "--input")?;

    let elf_bytes = std::fs::read(&elf_path)
        .map_err(|e| format!("failed to read ELF {}: {e}", elf_path.display()))?;
    let input = std::fs::read(&input_path)
        .map_err(|e| format!("failed to read input {}: {e}", input_path.display()))?;

    let result = poker_zkvm::isa::executor::execute_elf(&elf_bytes, &input)
        .map_err(|e| format!("execution failed: {e}"))?;

    Ok(format!(
        "Execution complete: {} steps, {} byte(s) output, {} event(s), {} log(s)",
        result.trace.len(),
        result.output.len(),
        result.events.len(),
        result.logs.len()
    ))
}

/// `prove` 子命令 — 生成 proof 并写出 proof + public_io 文件。
///
/// 输出文件：
/// - `<output>` — proof 二进制
/// - `<output>.public_io` — ZkPublicIo 二进制（verifier 验证时需要）
fn cmd_prove(args: &[String]) -> Result<String, String> {
    let elf_path = parse_arg(args, "--elf")?;
    let input_path = parse_arg(args, "--input")?;
    let output_path = parse_arg(args, "--output")?;

    let elf_bytes = std::fs::read(&elf_path)
        .map_err(|e| format!("failed to read ELF {}: {e}", elf_path.display()))?;
    let input = std::fs::read(&input_path)
        .map_err(|e| format!("failed to read input {}: {e}", input_path.display()))?;

    let config = ProverConfig::default();
    let (proof_bytes, public_io) =
        prove(&elf_bytes, &input, &config).map_err(|e| format!("prove failed: {e}"))?;

    std::fs::write(&output_path, &proof_bytes)
        .map_err(|e| format!("failed to write proof {}: {e}", output_path.display()))?;

    let public_io_path = {
        let mut p = output_path.clone();
        let mut name = p.file_name().unwrap().to_os_string();
        name.push(".public_io");
        p.set_file_name(name);
        p
    };
    let public_io_bytes = public_io.to_bytes();
    std::fs::write(&public_io_path, &public_io_bytes).map_err(|e| {
        format!(
            "failed to write public_io {}: {e}",
            public_io_path.display()
        )
    })?;

    Ok(format!(
        "Prove successful: {} bytes proof + {} bytes public_io (output={})",
        proof_bytes.len(),
        public_io_bytes.len(),
        output_path.display()
    ))
}

/// `verify` 子命令 — 验证 proof（Phase 11 未就绪）。
fn cmd_verify(args: &[String]) -> Result<String, String> {
    let proof_path = parse_arg(args, "--proof")?;
    let public_io_path = parse_arg(args, "--public-io")?;

    Err(format!(
        "verify not implemented (Phase 11 — verifier pending). proof={}, public-io={}",
        proof_path.display(),
        public_io_path.display()
    ))
}

/// `test` 子命令 — 扫描 `#[zkvm::test]` 标记函数（Phase 3 未就绪）。
fn cmd_test(_args: &[String], cwd: &Path) -> Result<String, String> {
    let src_dir = cwd.join("src");
    if !src_dir.exists() {
        return Err(format!("src/ directory not found in {}", cwd.display()));
    }

    let test_fns = scan_zkvm_tests(&src_dir)?;

    if test_fns.is_empty() {
        return Ok("No #[zkvm::test] functions found".to_string());
    }

    Err(format!(
        "test not implemented (Phase 3 pending). Found {} test function(s): {}",
        test_fns.len(),
        test_fns.join(", ")
    ))
}

/// 从参数列表解析 `--key <value>` 对。
fn parse_arg(args: &[String], key: &str) -> Result<PathBuf, String> {
    let idx = args
        .iter()
        .position(|a| a == key)
        .ok_or_else(|| format!("missing required argument: {key}"))?;

    let value = args
        .get(idx + 1)
        .ok_or_else(|| format!("missing value for {key}"))?;

    Ok(PathBuf::from(value))
}

/// 递归扫描 `src/` 目录，查找 `#[zkvm::test]` 标记的函数名。
fn scan_zkvm_tests(src_dir: &Path) -> Result<Vec<String>, String> {
    let mut tests = Vec::new();
    scan_dir_recursive(src_dir, &mut tests)?;
    Ok(tests)
}

/// 递归扫描目录下所有 `.rs` 文件。
fn scan_dir_recursive(dir: &Path, tests: &mut Vec<String>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("failed to read dir: {e}"))? {
        let entry = entry.map_err(|e| format!("failed to read entry: {e}"))?;
        let path = entry.path();

        if path.is_dir() {
            scan_dir_recursive(&path, tests)?;
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            scan_rust_file(&path, tests)?;
        }
    }
    Ok(())
}

/// 扫描单个 `.rs` 文件，查找 `#[zkvm::test]` 标记后的函数定义。
fn scan_rust_file(path: &Path, tests: &mut Vec<String>) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    let lines: Vec<&str> = content.lines().collect();
    for i in 0..lines.len() {
        let trimmed = lines[i].trim();
        if !trimmed.contains("#[zkvm::test]") {
            continue;
        }
        // 在后续行中查找函数名（跳过其他属性）
        for next in lines.iter().skip(i + 1).take(4) {
            let next = next.trim();
            if next.starts_with("#[") {
                continue;
            }
            if let Some(name) = extract_fn_name(next) {
                tests.push(name);
                break;
            }
            // 非属性、非函数行则停止搜索
            break;
        }
    }
    Ok(())
}

/// 从 `fn my_func(...)` 行提取函数名。
fn extract_fn_name(line: &str) -> Option<String> {
    let fn_idx = line.find("fn ")?;
    let rest = &line[fn_idx + 3..];
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() || name == "fn" {
        None
    } else {
        Some(name)
    }
}

/// 返回帮助文本。
fn usage_string() -> String {
    "cargo-zkvm: ZKVM compilation and proving tool\n\n\
     USAGE:\n    \
     cargo zkvm <SUBCOMMAND> [OPTIONS]\n\n\
     SUBCOMMANDS:\n    \
     build                                         Compile crate to RV32I ELF + validate\n    \
     run --elf <PATH> --input <PATH>               Execute ELF (Phase 3)\n    \
     prove --elf --input --output <PATH>           Generate proof + public_io\n    \
     verify --proof <PATH> --public-io <PATH>      Verify proof (Phase 11)\n    \
     test                                          Run #[zkvm::test] functions (Phase 3)\n    \
     help                                          Show this help message"
        .to_string()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ===== dispatch 测试 =====

    #[test]
    fn test_dispatch_unknown_subcommand() {
        let cwd = Path::new(".");
        let result = dispatch(&["unknown".to_string()], cwd);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown subcommand"));
    }

    #[test]
    fn test_dispatch_missing_subcommand() {
        let cwd = Path::new(".");
        let result = dispatch(&[], cwd);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing subcommand"));
    }

    #[test]
    fn test_dispatch_help() {
        let cwd = Path::new(".");
        let result = dispatch(&["--help".to_string()], cwd);
        assert!(result.is_ok());
        let help = result.unwrap();
        assert!(help.contains("build"));
        assert!(help.contains("run"));
        assert!(help.contains("prove"));
        assert!(help.contains("verify"));
        assert!(help.contains("test"));
    }

    #[test]
    fn test_dispatch_skips_zkvm_prefix() {
        let cwd = Path::new(".");
        let result = dispatch(&["zkvm".to_string(), "--help".to_string()], cwd);
        assert!(result.is_ok());
    }

    // ===== cmd_build 测试 =====

    #[test]
    fn test_build_missing_cargo_toml() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_build_no_cargo");
        fs::create_dir_all(&temp_dir).unwrap();
        let result = cmd_build(&[], &temp_dir);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Cargo.toml") || err.contains("compile failed"),
            "error should mention Cargo.toml or compile failure: {err}"
        );
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    // ===== cmd_run 测试 =====

    #[test]
    fn test_run_missing_elf_arg() {
        let result = cmd_run(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--elf"));
    }

    #[test]
    fn test_run_missing_input_arg() {
        let result = cmd_run(&["--elf".to_string(), "/tmp/test.elf".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--input"));
    }

    #[test]
    fn test_run_nonexistent_elf_file() {
        let result = cmd_run(&[
            "--elf".to_string(),
            "/tmp/nonexistent_test_elf_12345.elf".to_string(),
            "--input".to_string(),
            "/tmp/nonexistent_test_input_12345.bin".to_string(),
        ]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("failed to read ELF"),
            "expected IO error, got: {err}"
        );
    }

    #[test]
    fn test_run_executes_minimal_elf() {
        // 构造最小 ELF：ADDI a7, x0, 2 (commit_output) + ECALL → 2 steps, 0 byte output
        fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
            ((imm12 & 0xFFF) << 20)
                | ((rs1 as u32) << 15)
                | ((funct3 as u32) << 12)
                | ((rd as u32) << 7)
                | opcode
        }

        let text: Vec<u8> = [encode_i(0x13, 0, 17, 0, 2), 0x00000073]
            .iter()
            .copied()
            .flat_map(u32::to_le_bytes)
            .collect();

        let mut elf = Vec::with_capacity(84 + text.len());
        // ELF32 header (52 bytes)
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        elf.extend_from_slice(&0xF3u16.to_le_bytes()); // e_machine = EM_RISCV
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0x1000u32.to_le_bytes()); // e_entry
        elf.extend_from_slice(&52u32.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&52u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&32u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&40u16.to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(elf.len(), 52);
        // PH1: PT_LOAD (32 bytes)
        elf.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        elf.extend_from_slice(&84u32.to_le_bytes()); // p_offset
        elf.extend_from_slice(&0x1000u32.to_le_bytes()); // p_vaddr
        elf.extend_from_slice(&0x1000u32.to_le_bytes()); // p_paddr
        elf.extend_from_slice(&(text.len() as u32).to_le_bytes()); // p_filesz
        elf.extend_from_slice(&(text.len() as u32).to_le_bytes()); // p_memsz
        elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags = PF_R|PF_X
        elf.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align
        assert_eq!(elf.len(), 84);
        // .text
        elf.extend_from_slice(&text);

        // 写入临时文件
        let temp_dir = std::env::temp_dir().join("zkvm_cli_run_test");
        fs::create_dir_all(&temp_dir).unwrap();
        let elf_path = temp_dir.join("test.elf");
        let input_path = temp_dir.join("test.bin");
        fs::write(&elf_path, &elf).unwrap();
        fs::write(&input_path, b"").unwrap();

        let result = cmd_run(&[
            "--elf".to_string(),
            elf_path.to_string_lossy().into_owned(),
            "--input".to_string(),
            input_path.to_string_lossy().into_owned(),
        ]);
        fs::remove_dir_all(&temp_dir).unwrap();

        assert!(result.is_ok(), "expected success, got: {:?}", result.err());
        let msg = result.unwrap();
        assert!(
            msg.contains("Execution complete") && msg.contains("2 steps"),
            "expected 'Execution complete' + '2 steps', got: {msg}"
        );
    }

    // ===== cmd_prove 测试 =====

    #[test]
    fn test_prove_missing_elf_arg() {
        let result = cmd_prove(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--elf"));
    }

    #[test]
    fn test_prove_missing_output_arg() {
        let result = cmd_prove(&[
            "--elf".to_string(),
            "/tmp/test.elf".to_string(),
            "--input".to_string(),
            "/tmp/input.bin".to_string(),
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--output"));
    }

    #[test]
    fn test_prove_writes_proof_and_public_io_files() {
        // 构造最小 ELF：3 NOP + commit_output + ECALL = 5 步
        // ProverConfig::default() batch_size=3 → padding 到 6 步 → 2 batches
        fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
            ((imm12 & 0xFFF) << 20)
                | ((rs1 as u32) << 15)
                | ((funct3 as u32) << 12)
                | ((rd as u32) << 7)
                | opcode
        }

        let text: Vec<u8> = [
            encode_i(0x13, 0, 1, 0, 0),  // NOP
            encode_i(0x13, 0, 1, 0, 0),  // NOP
            encode_i(0x13, 0, 1, 0, 0),  // NOP
            encode_i(0x13, 0, 17, 0, 2), // commit_output
            0x00000073,                  // ECALL
        ]
        .iter()
        .copied()
        .flat_map(u32::to_le_bytes)
        .collect();

        let mut elf = Vec::with_capacity(84 + text.len());
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        elf.extend_from_slice(&2u16.to_le_bytes());
        elf.extend_from_slice(&0xF3u16.to_le_bytes());
        elf.extend_from_slice(&1u32.to_le_bytes());
        elf.extend_from_slice(&0x1000u32.to_le_bytes());
        elf.extend_from_slice(&52u32.to_le_bytes());
        elf.extend_from_slice(&0u32.to_le_bytes());
        elf.extend_from_slice(&0u32.to_le_bytes());
        elf.extend_from_slice(&52u16.to_le_bytes());
        elf.extend_from_slice(&32u16.to_le_bytes());
        elf.extend_from_slice(&1u16.to_le_bytes());
        elf.extend_from_slice(&40u16.to_le_bytes());
        elf.extend_from_slice(&0u16.to_le_bytes());
        elf.extend_from_slice(&0u16.to_le_bytes());
        elf.extend_from_slice(&1u32.to_le_bytes());
        elf.extend_from_slice(&84u32.to_le_bytes());
        elf.extend_from_slice(&0x1000u32.to_le_bytes());
        elf.extend_from_slice(&0x1000u32.to_le_bytes());
        elf.extend_from_slice(&(text.len() as u32).to_le_bytes());
        elf.extend_from_slice(&(text.len() as u32).to_le_bytes());
        elf.extend_from_slice(&5u32.to_le_bytes());
        elf.extend_from_slice(&0x1000u32.to_le_bytes());
        elf.extend_from_slice(&text);

        let temp_dir = std::env::temp_dir().join("zkvm_cli_prove_test");
        fs::create_dir_all(&temp_dir).unwrap();
        let elf_path = temp_dir.join("test.elf");
        let input_path = temp_dir.join("test.bin");
        let output_path = temp_dir.join("test.proof");
        fs::write(&elf_path, &elf).unwrap();
        fs::write(&input_path, b"").unwrap();

        let result = cmd_prove(&[
            "--elf".to_string(),
            elf_path.to_string_lossy().into_owned(),
            "--input".to_string(),
            input_path.to_string_lossy().into_owned(),
            "--output".to_string(),
            output_path.to_string_lossy().into_owned(),
        ]);

        // 清理（无论成功失败）
        let _ = fs::remove_dir_all(&temp_dir);

        assert!(result.is_ok(), "expected success, got: {:?}", result.err());
        let msg = result.unwrap();
        assert!(
            msg.contains("Prove successful"),
            "expected 'Prove successful', got: {msg}"
        );
        assert!(
            msg.contains("bytes proof"),
            "expected proof size in message, got: {msg}"
        );
    }

    // ===== cmd_verify 测试 =====

    #[test]
    fn test_verify_missing_proof_arg() {
        let result = cmd_verify(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--proof"));
    }

    #[test]
    fn test_verify_missing_public_io_arg() {
        let result = cmd_verify(&["--proof".to_string(), "/tmp/test.proof".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--public-io"));
    }

    #[test]
    fn test_verify_returns_phase11_pending() {
        let result = cmd_verify(&[
            "--proof".to_string(),
            "/tmp/test.proof".to_string(),
            "--public-io".to_string(),
            "/tmp/io.bin".to_string(),
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Phase 11"));
    }

    // ===== cmd_test 测试 =====

    #[test]
    fn test_test_missing_src_dir() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_test_no_src");
        fs::create_dir_all(&temp_dir).unwrap();
        let result = cmd_test(&[], &temp_dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("src/"));
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_test_no_markers() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_test_no_markers");
        let src = temp_dir.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("main.rs"), "fn main() {}\n").unwrap();
        let result = cmd_test(&[], &temp_dir);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("No #[zkvm::test]"));
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_test_finds_marker() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_test_finds");
        let src = temp_dir.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("main.rs"),
            "#[zkvm::test]\nfn my_zkvm_test() -> u32 { 42 }\n",
        )
        .unwrap();
        let result = cmd_test(&[], &temp_dir);
        assert!(result.is_err()); // Phase 3 not implemented
        let err = result.unwrap_err();
        assert!(err.contains("Phase 3"));
        assert!(err.contains("my_zkvm_test"));
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    // ===== parse_arg 测试 =====

    #[test]
    fn test_parse_arg_present() {
        let args = vec!["--elf".to_string(), "/path/to/file".to_string()];
        let result = parse_arg(&args, "--elf").unwrap();
        assert_eq!(result, PathBuf::from("/path/to/file"));
    }

    #[test]
    fn test_parse_arg_missing_key() {
        let args: Vec<String> = vec![];
        let result = parse_arg(&args, "--elf");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--elf"));
    }

    #[test]
    fn test_parse_arg_missing_value() {
        let args = vec!["--elf".to_string()];
        let result = parse_arg(&args, "--elf");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("value"));
    }

    #[test]
    fn test_parse_arg_multiple_args() {
        let args = vec![
            "--input".to_string(),
            "/tmp/in.bin".to_string(),
            "--elf".to_string(),
            "/tmp/test.elf".to_string(),
            "--output".to_string(),
            "/tmp/out.proof".to_string(),
        ];
        let elf = parse_arg(&args, "--elf").unwrap();
        let input = parse_arg(&args, "--input").unwrap();
        let output = parse_arg(&args, "--output").unwrap();
        assert_eq!(elf, PathBuf::from("/tmp/test.elf"));
        assert_eq!(input, PathBuf::from("/tmp/in.bin"));
        assert_eq!(output, PathBuf::from("/tmp/out.proof"));
    }

    // ===== scan_zkvm_tests 测试 =====

    #[test]
    fn test_scan_empty_dir() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_scan_empty");
        fs::create_dir_all(&temp_dir).unwrap();
        let result = scan_zkvm_tests(&temp_dir).unwrap();
        assert!(result.is_empty());
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_scan_finds_test_marker() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_scan_finds");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            temp_dir.join("test.rs"),
            "#[zkvm::test]\nfn my_test() { assert!(true); }\n",
        )
        .unwrap();
        let result = scan_zkvm_tests(&temp_dir).unwrap();
        assert_eq!(result, vec!["my_test"]);
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_scan_finds_multiple_markers() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_scan_multi");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            temp_dir.join("a.rs"),
            "#[zkvm::test]\nfn test_a() {}\n\n#[zkvm::test]\nfn test_b() {}\n",
        )
        .unwrap();
        let result = scan_zkvm_tests(&temp_dir).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"test_a".to_string()));
        assert!(result.contains(&"test_b".to_string()));
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_scan_recursive() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_scan_recursive");
        let sub = temp_dir.join("subdir");
        fs::create_dir_all(&sub).unwrap();
        fs::write(
            sub.join("nested.rs"),
            "#[zkvm::test]\nfn nested_test() {}\n",
        )
        .unwrap();
        let result = scan_zkvm_tests(&temp_dir).unwrap();
        assert_eq!(result, vec!["nested_test"]);
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_scan_skips_non_rust_files() {
        let temp_dir = std::env::temp_dir().join("zkvm_cli_scan_nonrust");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            temp_dir.join("readme.md"),
            "#[zkvm::test]\nfn not_rust() {}\n",
        )
        .unwrap();
        let result = scan_zkvm_tests(&temp_dir).unwrap();
        assert!(result.is_empty());
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    // ===== extract_fn_name 测试 =====

    #[test]
    fn test_extract_fn_name_simple() {
        assert_eq!(
            extract_fn_name("fn my_func() {}"),
            Some("my_func".to_string())
        );
    }

    #[test]
    fn test_extract_fn_name_with_args() {
        assert_eq!(
            extract_fn_name("fn add(a: u32, b: u32) -> u32 { a + b }"),
            Some("add".to_string())
        );
    }

    #[test]
    fn test_extract_fn_name_pub() {
        assert_eq!(
            extract_fn_name("pub fn public_fn() {}"),
            Some("public_fn".to_string())
        );
    }

    #[test]
    fn test_extract_fn_name_no_fn() {
        assert_eq!(extract_fn_name("let x = 42;"), None);
    }
}
