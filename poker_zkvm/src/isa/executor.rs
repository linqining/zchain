//! 执行循环（Phase 4 — Task 4.3 迁移）。
//!
//! 提供：
//! - [`ZkvmExecutionConfig`] — 执行配置（input + randomness + host_state）
//! - [`ExecuteResult`] — 执行结果（trace + output + events + logs）
//! - [`execute_elf`] — 执行 ELF + input（向后兼容）
//! - [`execute_elf_with_config`] — 执行 ELF + 完整配置
//! - [`execute_elf_with_limits_and_config`] — 可配置步数 / 内存上限
//!
//! # 执行循环
//!
//! 1. `validate_elf` → `load_elf`（复用 Phase 2 校验，消除 TOCTOU）
//! 2. 循环：检查 halt → 检查步数上限 → 检查 host 内存上限 → fetch → decode → execute
//! 3. `ECALL` 后调 `SyscallRegistry::dispatch` 分派 syscall（10 个 syscall）
//! 4. `Step::from_log` 组装并追加到 `Trace`

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::compiler::elf_validator::validate_elf;
use crate::error::ZkvmError;
use crate::isa::state::{VmState, load_elf};
use crate::syscalls::{StubHostState, SyscallContext, SyscallRegistry, ZkvmHostState};
use crate::trace::{MAX_TRACE_HOST_MEMORY, Step, Trace};

/// 最大 trace 步数（spec L257）。
pub const MAX_ZKVM_TRACE_STEPS: usize = 1_048_576;

/// ZKVM 执行配置 — 持有 host 侧输入和 randomness 参数。
///
/// 通过 [`execute_elf_with_config`] 或 [`execute_elf_with_limits_and_config`] 传入。
/// [`Default`] 提供空 input + 零 randomness + [`StubHostState`]。
pub struct ZkvmExecutionConfig {
    /// 程序输入
    pub input: Vec<u8>,
    /// `get_randomness` 派生 seed（spec L221）。
    pub randomness_seed: Fr,
    /// `get_randomness` 派生 initial_commitment（spec L222）。
    pub initial_commitment: Fr,
    /// `get_randomness` 派生 final_commitment（spec L222）。
    pub final_commitment: Fr,
    /// Host 状态读取实现（`read_state` 用）。
    pub host_state: Box<dyn ZkvmHostState>,
}

impl Default for ZkvmExecutionConfig {
    fn default() -> Self {
        Self {
            input: Vec::new(),
            randomness_seed: Fr::zero(),
            initial_commitment: Fr::zero(),
            final_commitment: Fr::zero(),
            host_state: Box::new(StubHostState),
        }
    }
}

impl std::fmt::Debug for ZkvmExecutionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkvmExecutionConfig")
            .field("input_len", &self.input.len())
            .field("randomness_seed", &self.randomness_seed)
            .field("initial_commitment", &self.initial_commitment)
            .field("final_commitment", &self.final_commitment)
            .field("host_state", &self.host_state)
            .finish()
    }
}

// ===========================================================================
// ExecuteResult
// ===========================================================================

/// 执行结果。
#[derive(Debug)]
pub struct ExecuteResult {
    /// 执行轨迹
    pub trace: Trace,
    /// 程序输出（`commit_output` 写入）
    pub output: Vec<u8>,
    /// `emit_event` 产生的事件哈希列表
    pub events: Vec<Fr>,
    /// `log` 产生的日志消息列表
    pub logs: Vec<Vec<u8>>,
}

// ===========================================================================
// execute_elf / execute_elf_with_config / execute_elf_with_limits_and_config
// ===========================================================================

/// 执行 ELF（默认上限：`MAX_ZKVM_TRACE_STEPS` 步 / `MAX_TRACE_HOST_MEMORY` 内存）。
///
/// 向后兼容 Phase 3 API — 仅传入 input，其余用默认值。
///
/// # Errors
/// - `ZkvmError::InvalidZkProofFormat` — ELF 校验失败（透传 `validate_elf`）
/// - `ZkvmError::OutOfMemory` — 段加载超 16MB
/// - `ZkvmError::UninitializedRead` — fetch 指向未初始化内存
/// - `ZkvmError::UnsupportedInstruction` — decode 遇到非法指令
/// - `ZkvmError::UnalignedAccess` — fetch 地址未 4B 对齐
/// - `ZkvmError::TraceTooLong` — 步数超限
/// - `ZkvmError::TraceHostMemoryExceeded` — host 内存超限
/// - `ZkvmError::Other` — panic syscall 或未注册 syscall
#[allow(clippy::missing_errors_doc)]
pub fn execute_elf(elf_bytes: &[u8], input: &[u8]) -> Result<ExecuteResult, ZkvmError> {
    let config = ZkvmExecutionConfig {
        input: input.to_vec(),
        ..Default::default()
    };
    execute_elf_with_limits_and_config(
        elf_bytes,
        config,
        MAX_ZKVM_TRACE_STEPS,
        MAX_TRACE_HOST_MEMORY,
    )
}

/// 执行 ELF（完整配置，默认上限）。
///
/// # Errors
/// 同 [`execute_elf`]。
#[allow(clippy::missing_errors_doc)]
pub fn execute_elf_with_config(
    elf_bytes: &[u8],
    config: ZkvmExecutionConfig,
) -> Result<ExecuteResult, ZkvmError> {
    execute_elf_with_limits_and_config(
        elf_bytes,
        config,
        MAX_ZKVM_TRACE_STEPS,
        MAX_TRACE_HOST_MEMORY,
    )
}

/// 执行 ELF（可配置步数 / 内存上限，向后兼容 Phase 3）。
///
/// # Errors
/// 同 [`execute_elf`]。
#[allow(clippy::missing_errors_doc)]
pub fn execute_elf_with_limits(
    elf_bytes: &[u8],
    input: &[u8],
    step_limit: usize,
    mem_limit: usize,
) -> Result<ExecuteResult, ZkvmError> {
    let config = ZkvmExecutionConfig {
        input: input.to_vec(),
        ..Default::default()
    };
    execute_elf_with_limits_and_config(elf_bytes, config, step_limit, mem_limit)
}

/// 执行 ELF（完整配置 + 可配置步数 / 内存上限）。
///
/// # 执行循环
///
/// 1. `validate_elf` → `load_elf`
/// 2. 创建 `SyscallRegistry::new()`（注册全部 10 个 syscall）
/// 3. 创建 `SyscallContext`（注入 input + randomness + host_state）
/// 4. 循环：halt 检查 → 步数检查 → 内存检查 → fetch → decode → execute → ECALL 分派
/// 5. 返回 `ExecuteResult { trace, output, events, logs }`
///
/// # Errors
/// - `ZkvmError::InvalidZkProofFormat` — ELF 校验失败
/// - `ZkvmError::OutOfMemory` — 段加载超 16MB
/// - `ZkvmError::UninitializedRead` — fetch 指向未初始化内存
/// - `ZkvmError::UnsupportedInstruction` — decode 遇到非法指令
/// - `ZkvmError::UnalignedAccess` — fetch 地址未 4B 对齐
/// - `ZkvmError::TraceTooLong` — 步数超限
/// - `ZkvmError::TraceHostMemoryExceeded` — host 内存超限
/// - `ZkvmError::Other` — panic syscall 或未注册 syscall
#[allow(clippy::missing_errors_doc)]
pub fn execute_elf_with_limits_and_config(
    elf_bytes: &[u8],
    config: ZkvmExecutionConfig,
    step_limit: usize,
    mem_limit: usize,
) -> Result<ExecuteResult, ZkvmError> {
    // 1. 校验 + 加载 ELF
    let metadata = validate_elf(elf_bytes)?;
    let mut state = VmState::new();
    load_elf(&mut state, &metadata)?;

    // 2. 初始化 syscall registry + context
    let registry = SyscallRegistry::new();
    let mut ctx = SyscallContext::new(config.input)
        .with_randomness(
            config.randomness_seed,
            config.initial_commitment,
            config.final_commitment,
        )
        .with_host_state(config.host_state);
    let mut trace = Trace::new();
    // 注入 initial_registers（load_elf 后的寄存器快照），使 trace_to_native
    // 在第 0 步能用正确的 prev_registers 计算 MemAddr = prev[rs1] + imm 等。
    trace.set_initial_registers(state.registers);

    // 3. 执行循环
    loop {
        // 检查 halt
        if ctx.is_halted() {
            break;
        }

        // 检查步数上限
        if trace.len() >= step_limit {
            return Err(ZkvmError::TraceTooLong {
                actual: trace.len() + 1,
                limit: step_limit,
            });
        }

        // 检查 host 内存上限
        let usage = trace.host_memory_usage();
        if usage > mem_limit {
            return Err(ZkvmError::TraceHostMemoryExceeded {
                actual: usage,
                limit: mem_limit,
            });
        }

        // fetch + decode + execute
        let word = state.fetch_word()?;
        let insn = crate::isa::decode(word)?;
        ctx.step_index = trace.len() as u64;
        let log = crate::isa::execute(&mut state, insn.clone())?;

        // ECALL → syscall 分派
        if matches!(insn, crate::isa::Instruction::Ecall) {
            let syscall_id = state.read_register(crate::syscalls::REG_A7);
            registry.dispatch(syscall_id, &mut ctx, &mut state)?;
        }

        // 组装 Step 并追加
        let step = Step::from_log(ctx.step_index, log);
        trace.push_step(step);
    }

    // 4. 提取结果
    let events = std::mem::take(&mut ctx.events);
    let logs = std::mem::take(&mut ctx.logs);
    Ok(ExecuteResult {
        trace,
        output: ctx.into_output(),
        events,
        logs,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 测试辅助函数 =====

    /// 编码 I-type 指令。
    fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
        ((imm12 & 0xFFF) << 20)
            | ((rs1 as u32) << 15)
            | ((funct3 as u32) << 12)
            | ((rd as u32) << 7)
            | opcode
    }

    /// 构造最小 ELF32（52B header + 32B PH + text_bytes）。
    ///
    /// entry = `entry`，PT_LOAD 段 vaddr = `text_vaddr`，flags = PF_R|PF_X。
    fn build_test_elf(entry: u32, text_vaddr: u32, text_bytes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(84 + text_bytes.len());

        // --- ELF32 header (52 bytes) ---
        bytes.extend_from_slice(&[
            0x7f, b'E', b'L', b'F', // magic
            1, 1, 1, 0, // class=32, LE, version=1, OS/ABI=none
            0, 0, 0, 0, 0, 0, 0, 0, // padding
        ]);
        bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        bytes.extend_from_slice(&0xF3u16.to_le_bytes()); // e_machine = EM_RISCV
        bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
        bytes.extend_from_slice(&entry.to_le_bytes()); // e_entry
        bytes.extend_from_slice(&52u32.to_le_bytes()); // e_phoff
        bytes.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
        bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        bytes.extend_from_slice(&52u16.to_le_bytes()); // e_ehsize
        bytes.extend_from_slice(&32u16.to_le_bytes()); // e_phentsize
        bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        bytes.extend_from_slice(&40u16.to_le_bytes()); // e_shentsize
        bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(bytes.len(), 52);

        // --- PH1: PT_LOAD (32 bytes) ---
        let p_offset = 84u32;
        let p_filesz = text_bytes.len() as u32;
        let p_memsz = text_bytes.len() as u32;
        bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        bytes.extend_from_slice(&p_offset.to_le_bytes());
        bytes.extend_from_slice(&text_vaddr.to_le_bytes());
        bytes.extend_from_slice(&text_vaddr.to_le_bytes()); // p_paddr = p_vaddr
        bytes.extend_from_slice(&p_filesz.to_le_bytes());
        bytes.extend_from_slice(&p_memsz.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = PF_R|PF_X
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align
        assert_eq!(bytes.len(), 84);

        // --- .text ---
        bytes.extend_from_slice(text_bytes);
        bytes
    }

    /// 将多个 u32 指令编码为 LE 字节序列。
    fn encode_text(words: &[u32]) -> Vec<u8> {
        words.iter().copied().flat_map(u32::to_le_bytes).collect()
    }

    // ===== TDD 测试 =====

    #[test]
    fn test_execute_elf_minimal_halt() {
        // ADDI a7, x0, 2 (commit_output) + ECALL
        // a0=0, a1=0 → 空 output → halt
        let text = encode_text(&[encode_i(0x13, 0, 17, 0, 2), 0x00000073]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let result = execute_elf(&elf, &[]).unwrap();
        assert_eq!(result.trace.len(), 2, "ADDI + ECALL = 2 steps");
        assert!(
            result.output.is_empty(),
            "commit_output with a0=0, a1=0 → empty output"
        );
    }

    #[test]
    fn test_execute_elf_trace_too_long() {
        // JAL x0, 0 (infinite loop: pc = pc + 0)
        let text = encode_text(&[0x0000006Fu32]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let err = execute_elf_with_limits(&elf, &[], 2, MAX_TRACE_HOST_MEMORY).unwrap_err();
        assert!(
            matches!(
                err,
                ZkvmError::TraceTooLong {
                    actual: 3,
                    limit: 2
                }
            ),
            "expected TraceTooLong, got {err:?}"
        );
    }

    #[test]
    fn test_execute_elf_host_memory_exceeded() {
        // JAL x0, 0 (infinite loop)
        let text = encode_text(&[0x0000006Fu32]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let err = execute_elf_with_limits(&elf, &[], MAX_ZKVM_TRACE_STEPS, 100).unwrap_err();
        assert!(
            matches!(err, ZkvmError::TraceHostMemoryExceeded { limit: 100, .. }),
            "expected TraceHostMemoryExceeded, got {err:?}"
        );
    }

    #[test]
    fn test_execute_elf_read_input_commit_output_echo() {
        // ADDI a7, x0, 1 (read_input) + ADDI a1, x0, 5 (len=5) + ECALL
        // + ADDI a7, x0, 2 (commit_output) + ECALL
        // read_input: a0=0 → HEAP_START, a1=5 → 写 5 字节
        // commit_output: a0=HEAP_START, a1=5 → 读 5 字节 → halt
        let text = encode_text(&[
            encode_i(0x13, 0, 17, 0, 1), // ADDI a7, x0, 1 (read_input)
            encode_i(0x13, 0, 11, 0, 5), // ADDI a1, x0, 5 (len=5)
            0x00000073,                  // ECALL
            encode_i(0x13, 0, 17, 0, 2), // ADDI a7, x0, 2 (commit_output)
            0x00000073,                  // ECALL
        ]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let result = execute_elf(&elf, b"hello").unwrap();
        assert_eq!(result.trace.len(), 5, "5 instructions");
        assert_eq!(result.output, b"hello", "echo: input == output");
    }

    #[test]
    fn test_execute_elf_panic_terminates() {
        // ADDI a7, x0, 8 (panic) + ECALL
        // a0=0, a1=0 → "zkvm_panic: "
        let text = encode_text(&[encode_i(0x13, 0, 17, 0, 8), 0x00000073]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let err = execute_elf(&elf, &[]).unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg.contains("zkvm_panic:")),
            "expected zkvm_panic, got {err:?}"
        );
    }

    #[test]
    fn test_execute_elf_unknown_syscall() {
        // ADDI a7, x0, 0x16 (unknown，0x15 BLS 与 0x20 GameState 之间的间隙) + ECALL
        let text = encode_text(&[encode_i(0x13, 0, 17, 0, 0x16), 0x00000073]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let err = execute_elf(&elf, &[]).unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg.contains("unknown syscall id: 0x16")),
            "expected unknown syscall id error, got {err:?}"
        );
    }

    #[test]
    fn test_execute_elf_pc_out_of_bounds() {
        // JAL x0, 0x1000 (jump to 0x1000 + 0x1000 = 0x2000, uninitialized)
        let text = encode_text(&[0x0000106Fu32]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let err = execute_elf(&elf, &[]).unwrap_err();
        assert!(
            matches!(err, ZkvmError::UninitializedRead { addr: 0x2000 }),
            "expected UninitializedRead at 0x2000, got {err:?}"
        );
    }

    #[test]
    fn test_execute_elf_with_config_events_and_logs() {
        // ADDI a7, x0, 7 (log) + ADDI a1, x0, 3 + ECALL
        // 先写 "hi\n" 到内存，然后 log
        // 使用 LUI + ADDI 构造地址太复杂，直接用 STORE 指令
        // 简化：用 read_input 读入数据后用 log 输出
        // ADDI a7, x0, 1 (read_input) + ADDI a1, x0, 3 + ECALL → a0=HEAP_START, a1=3
        // ADDI a7, x0, 7 (log) + ECALL → log(a0=HEAP_START, a1=3)
        let text = encode_text(&[
            encode_i(0x13, 0, 17, 0, 1), // ADDI a7, x0, 1 (read_input)
            encode_i(0x13, 0, 11, 0, 3), // ADDI a1, x0, 3 (len=3)
            0x00000073,                  // ECALL
            encode_i(0x13, 0, 17, 0, 7), // ADDI a7, x0, 7 (log)
            0x00000073,                  // ECALL
            encode_i(0x13, 0, 17, 0, 2), // ADDI a7, x0, 2 (commit_output)
            0x00000073,                  // ECALL → halt
        ]);
        let elf = build_test_elf(0x1000, 0x1000, &text);

        let config = ZkvmExecutionConfig {
            input: b"hi\n".to_vec(),
            ..Default::default()
        };
        let result = execute_elf_with_config(&elf, config).unwrap();

        assert_eq!(result.trace.len(), 7);
        assert_eq!(result.logs.len(), 1, "应有 1 条 log");
        assert_eq!(result.logs[0], b"hi\n");
        assert_eq!(
            result.output, b"hi\n",
            "commit_output with a0=HEAP_START, a1=3 → 3 bytes"
        );
    }
}
