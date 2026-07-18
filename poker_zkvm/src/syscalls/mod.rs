//! ZKVM Syscall 注册表与 ABI 版本化（Phase 4 — Task 4.1）。
//!
//! 严格遵循 spec.md L193-265 / L637-669（v1.4 FROZEN）：
//! - [`ZKVM_ABI_VERSION`] — ABI 版本号，写入 proof header
//! - [`SyscallId`] — 15 个 syscall ID 枚举（0x01-0x0F）
//!
//! # Syscall 列表
//!
//! | ID | 名称 | ABI | 说明 |
//! |----|------|-----|------|
//! | 0x01 | `read_input` | (ptr, len) | 从 host input buffer 读取 |
//! | 0x02 | `commit_output` | (ptr, len) | 写入 host output buffer |
//! | 0x03 | `poseidon` | (ptr, len, out_ptr) | Poseidon 哈希 |
//! | 0x04 | `sha256` | (ptr, len, out_ptr) | SHA-256 哈希 |
//! | 0x05 | `ecdsa_verify` | (msg_ptr, msg_len, sig_ptr, pubkey_ptr) → bool | ECDSA 验证 |
//! | 0x06 | `emit_event` | (ptr, len) | 事件进 public_io（绑定 step_index） |
//! | 0x07 | `log` | (ptr, len) | 写入 host event log |
//! | 0x08 | `panic` | (ptr, len) | 终止执行 |
//! | 0x09 | `get_randomness` | (out_ptr) | 从 host seed 派生（deterministic） |
//! | 0x0A | `read_state` | (slot, out_ptr) | 仅允许白名单 slot |
//! | 0x0B | `keccak256` | (ptr, len, out_ptr) | Keccak-256 哈希（Phase I） |
//! | 0x0C | `modexp` | (base_ptr, exp_ptr, mod_ptr, result_ptr, num_bits) | 大数模幂（Phase I） |
//! | 0x0D | `merkle_verify` | (leaf, path, indices, root, depth) | Merkle 路径验证（Phase I） |
//! | 0x0E | `ed25519_verify` | (msg_ptr, msg_len, sig_ptr, pubkey_ptr) → bool | Ed25519 验签（Phase I Batch 2） |
//! | 0x0F | `bn254_pairing` | (a_ptr, b_ptr, c_ptr, d_ptr) → bool | BN254 配对等式验证（Phase I Batch 2） |

use crate::error::ZkvmError;
use crate::isa::state::VmState;

/// Gas 计费常量与 [`syscall_gas`] 函数（Task 4.3）。
pub mod gas;

/// Phase 4 — GasStrategy trait 的 zkvm 实现（无 gas 费）。
pub mod gas_strategy;

/// Host 状态读取 trait + StubHostState 默认实现（Task 4.2.10）。
pub mod host_state;

/// Poseidon 哈希封装（Task 4.2.3）。
pub mod poseidon;

/// 10 个 ZKVM Syscall 的 Host 实现（Task 4.2，0x0B-0x0D 暂无 host 实现）。
pub mod host;

/// Host 状态读取 trait 的 re-export（便利访问）。
pub use host_state::{StubHostState, ZkvmHostState};

/// a0 寄存器索引（x10，buffer pointer / 返回值）。
pub const REG_A0: u8 = 10;
/// a1 寄存器索引（x11，buffer length / 返回值）。
pub const REG_A1: u8 = 11;
/// a2 寄存器索引（x12，out_ptr / sig_ptr）。
pub const REG_A2: u8 = 12;
/// a3 寄存器索引（x13，pubkey_ptr）。
pub const REG_A3: u8 = 13;
/// a7 寄存器索引（x17，syscall number）。
pub const REG_A7: u8 = 17;

/// ZKVM ABI 版本号（spec L210-215）。
///
/// 写入 proof header，链上 verifier 校验。
/// 未来 ABI 升级须 bump 版本号 + 链上 verifier 兼容性矩阵。
pub const ZKVM_ABI_VERSION: u32 = 1;

/// Syscall ID 枚举（spec L196-206，15 个 syscall）。
///
/// `#[repr(u32)]` 确保 `as u32` 转换得到正确的 ID 值。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SyscallId {
    /// `zkvm_read_input(ptr, len)` — 从 host input buffer 读取。
    ReadInput = 0x01,
    /// `zkvm_commit_output(ptr, len)` — 写入 host output buffer。
    CommitOutput = 0x02,
    /// `zkvm_poseidon(ptr, len, out_ptr)` — Poseidon 哈希。
    Poseidon = 0x03,
    /// `zkvm_sha256(ptr, len, out_ptr)` — SHA-256 哈希。
    Sha256 = 0x04,
    /// `zkvm_ecdsa_verify(msg_ptr, msg_len, sig_ptr, pubkey_ptr) -> bool` — ECDSA 验证。
    EcdsaVerify = 0x05,
    /// `zkvm_emit_event(ptr, len)` — 事件进 public_io（绑定 step_index）。
    EmitEvent = 0x06,
    /// `zkvm_log(ptr, len)` — 写入 host event log。
    Log = 0x07,
    /// `zkvm_panic(ptr, len)` — 终止执行。
    Panic = 0x08,
    /// `zkvm_get_randomness(out_ptr)` — 从 host seed 派生（deterministic）。
    GetRandomness = 0x09,
    /// `zkvm_read_state(slot, out_ptr)` — 仅允许白名单 slot。
    ReadState = 0x0A,
    /// `zkvm_keccak256(ptr, len, out_ptr)` — Keccak-256 哈希。
    Keccak256 = 0x0B,
    /// `zkvm_modexp(base_ptr, exp_ptr, mod_ptr, result_ptr, num_bits)` — 大数模幂。
    Modexp = 0x0C,
    /// `zkvm_merkle_verify(leaf, path, indices, root, depth)` — Merkle 路径验证。
    MerkleVerify = 0x0D,
    /// `zkvm_ed25519_verify(msg_ptr, msg_len, sig_ptr, pubkey_ptr) -> bool` — Ed25519 验签。
    Ed25519Verify = 0x0E,
    /// `zkvm_bn254_pairing(a_ptr, b_ptr, c_ptr, d_ptr) -> bool` — BN254 配对等式验证。
    Bn254Pairing = 0x0F,
}

impl SyscallId {
    /// 从 `u32` 构造 [`SyscallId`]，非法 ID 返回 `Err(ZkvmError::Other)`。
    ///
    /// # Errors
    /// - `ZkvmError::Other` — `id` 不在 0x01-0x0F 范围内。
    pub fn from_u32(id: u32) -> Result<Self, ZkvmError> {
        match id {
            0x01 => Ok(Self::ReadInput),
            0x02 => Ok(Self::CommitOutput),
            0x03 => Ok(Self::Poseidon),
            0x04 => Ok(Self::Sha256),
            0x05 => Ok(Self::EcdsaVerify),
            0x06 => Ok(Self::EmitEvent),
            0x07 => Ok(Self::Log),
            0x08 => Ok(Self::Panic),
            0x09 => Ok(Self::GetRandomness),
            0x0A => Ok(Self::ReadState),
            0x0B => Ok(Self::Keccak256),
            0x0C => Ok(Self::Modexp),
            0x0D => Ok(Self::MerkleVerify),
            0x0E => Ok(Self::Ed25519Verify),
            0x0F => Ok(Self::Bn254Pairing),
            _ => Err(ZkvmError::Other(format!("unknown syscall id: 0x{id:02x}"))),
        }
    }

    /// 返回全部 15 个 syscall ID（按枚举顺序）。
    #[must_use]
    pub fn all() -> [Self; 15] {
        [
            Self::ReadInput,
            Self::CommitOutput,
            Self::Poseidon,
            Self::Sha256,
            Self::EcdsaVerify,
            Self::EmitEvent,
            Self::Log,
            Self::Panic,
            Self::GetRandomness,
            Self::ReadState,
            Self::Keccak256,
            Self::Modexp,
            Self::MerkleVerify,
            Self::Ed25519Verify,
            Self::Bn254Pairing,
        ]
    }
}

// ===========================================================================
// SyscallContext
// ===========================================================================

/// Syscall 执行上下文 — 持有 host 侧状态（spec L193-265）。
///
/// 在执行循环中由 executor 创建并传递给每个 syscall 的 `host_execute`。
///
/// # 字段说明
///
/// - `input` / `output` — 程序输入输出 buffer
/// - `events` — event_hash 列表（[`poseidon::poseidon_hash`] 生成）
/// - `logs` — log 消息列表
/// - `halted` — 是否已 halt（`commit_output` / `panic` 触发）
/// - `step_index` — 当前步序号（`emit_event` 绑定用，spec L246）
/// - `randomness_seed` / `initial_commitment` / `final_commitment` — `get_randomness` 派生参数（spec L220-223）
/// - `randomness_counter` — `get_randomness` 调用计数器（单调递增，spec L223）
/// - `host_state` — host 状态读取 trait object（`read_state` 用）
pub struct SyscallContext {
    /// 程序输入。
    pub input: Vec<u8>,
    /// 程序输出（`commit_output` 写入）。
    pub output: Vec<u8>,
    /// event_hash 列表（`emit_event` 生成）。
    pub events: Vec<ark_bn254::Fr>,
    /// log 消息列表（`log` 写入）。
    pub logs: Vec<Vec<u8>>,
    /// 是否已 halt。
    pub halted: bool,
    /// 当前步序号（`emit_event` 绑定用）。
    pub step_index: u64,
    /// `get_randomness` 派生 seed（spec L221）。
    pub randomness_seed: ark_bn254::Fr,
    /// `get_randomness` 派生 initial_commitment（spec L222）。
    pub initial_commitment: ark_bn254::Fr,
    /// `get_randomness` 派生 final_commitment（spec L222）。
    pub final_commitment: ark_bn254::Fr,
    /// `get_randomness` 调用计数器（spec L223）。
    pub randomness_counter: u64,
    /// Host 状态读取 trait object。
    pub host_state: Box<dyn ZkvmHostState>,
}

impl std::fmt::Debug for SyscallContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyscallContext")
            .field("input_len", &self.input.len())
            .field("output_len", &self.output.len())
            .field("events_count", &self.events.len())
            .field("logs_count", &self.logs.len())
            .field("halted", &self.halted)
            .field("step_index", &self.step_index)
            .field("randomness_counter", &self.randomness_counter)
            .field("host_state", &self.host_state)
            .finish()
    }
}

impl SyscallContext {
    /// 创建新的 SyscallContext（使用默认 StubHostState）。
    ///
    /// # 参数
    /// - `input` — 程序输入
    #[must_use]
    pub fn new(input: Vec<u8>) -> Self {
        use ark_bn254::Fr;
        use ark_ff::Zero;
        Self {
            input,
            output: Vec::new(),
            events: Vec::new(),
            logs: Vec::new(),
            halted: false,
            step_index: 0,
            randomness_seed: Fr::zero(),
            initial_commitment: Fr::zero(),
            final_commitment: Fr::zero(),
            randomness_counter: 0,
            host_state: Box::new(StubHostState),
        }
    }

    /// 注入 host state（builder 模式）。
    #[must_use]
    pub fn with_host_state(mut self, host_state: Box<dyn ZkvmHostState>) -> Self {
        self.host_state = host_state;
        self
    }

    /// 注入 randomness 参数（builder 模式）。
    #[must_use]
    pub fn with_randomness(
        mut self,
        seed: ark_bn254::Fr,
        initial: ark_bn254::Fr,
        final_: ark_bn254::Fr,
    ) -> Self {
        self.randomness_seed = seed;
        self.initial_commitment = initial;
        self.final_commitment = final_;
        self
    }

    /// 消费 self 返回 output。
    #[must_use]
    pub fn into_output(self) -> Vec<u8> {
        self.output
    }

    /// 是否已 halt。
    #[must_use]
    pub fn is_halted(&self) -> bool {
        self.halted
    }
}

// ===========================================================================
// Syscall trait
// ===========================================================================

/// Syscall trait（spec Task 4.1.2）。
///
/// 每个 syscall 实现此 trait，提供：
/// - `id()` — 返回 [`SyscallId`]
/// - `host_execute()` — host 侧执行（读寄存器 / 内存，写结果）
/// - `gas_cost()` — 估算 gas 开销（读寄存器估算）
///
/// # 设计说明
///
/// `gas_cost` 是 trait 方法而非独立函数，因为不同 syscall 的 gas 计算逻辑不同
/// （有的固定，有的按字节计费）。executor 循环中不实际扣 gas（gas 计费是 on-chain 概念）。
pub trait Syscall: std::fmt::Debug + Send + Sync {
    /// 返回 syscall ID。
    fn id(&self) -> SyscallId;

    /// Host 侧执行。
    ///
    /// # 参数
    /// - `ctx` — syscall 上下文（host 侧状态）
    /// - `state` — VM 状态（读寄存器 / 内存）
    ///
    /// # Errors
    /// 返回 [`ZkvmError`] 表示执行失败（如非法内存访问、非法 slot 等）。
    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError>;

    /// 估算 gas 开销（读寄存器估算）。
    ///
    /// executor 循环中不实际扣 gas，此方法供 prover / 链上计费使用。
    fn gas_cost(&self, state: &VmState) -> u64;
}

// ===========================================================================
// SyscallRegistry
// ===========================================================================

/// Syscall 注册表 — 按 [`SyscallId`] 分派到对应实现。
///
/// 内部使用 `Vec<Option<Box<dyn Syscall>>>`，index = `SyscallId as usize - 1`。
/// `new()` 注册全部 10 个 host syscall（0x0B-0x0F 暂无 host 实现，slot 为 None）。
pub struct SyscallRegistry {
    /// 15 个 syscall 实现，index = SyscallId as usize - 1。
    syscalls: [Option<Box<dyn Syscall>>; 15],
}

impl std::fmt::Debug for SyscallRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registered: Vec<&str> = self
            .syscalls
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                s.as_ref().map(|_| match i + 1 {
                    1 => "ReadInput",
                    2 => "CommitOutput",
                    3 => "Poseidon",
                    4 => "Sha256",
                    5 => "EcdsaVerify",
                    6 => "EmitEvent",
                    7 => "Log",
                    8 => "Panic",
                    9 => "GetRandomness",
                    10 => "ReadState",
                    11 => "Keccak256",
                    12 => "Modexp",
                    13 => "MerkleVerify",
                    14 => "Ed25519Verify",
                    15 => "Bn254Pairing",
                    _ => "Unknown",
                })
            })
            .collect();
        f.debug_struct("SyscallRegistry")
            .field("registered", &registered)
            .finish()
    }
}

impl SyscallRegistry {
    /// 创建空注册表。
    #[must_use]
    pub fn new_empty() -> Self {
        Self {
            syscalls: Default::default(),
        }
    }

    /// 创建注册表并注册全部 10 个 host syscall。
    ///
    /// 委托到 [`host::create_full_registry`]。
    #[must_use]
    pub fn new() -> Self {
        host::create_full_registry()
    }

    /// 注册一个 syscall。
    ///
    /// # Errors
    /// - `ZkvmError::Other` — syscall ID 已被注册
    pub fn register(&mut self, syscall: Box<dyn Syscall>) -> Result<(), ZkvmError> {
        let id = syscall.id();
        let idx = id as usize - 1;
        if self.syscalls[idx].is_some() {
            return Err(ZkvmError::Other(format!(
                "syscall {id:?} already registered"
            )));
        }
        self.syscalls[idx] = Some(syscall);
        Ok(())
    }

    /// 分派 syscall 执行。
    ///
    /// # 参数
    /// - `id` — syscall ID（u32）
    /// - `ctx` — syscall 上下文
    /// - `state` — VM 状态
    ///
    /// # Errors
    /// - `ZkvmError::Other` — 非法 ID 或未注册
    /// - 透传 syscall `host_execute` 的错误
    pub fn dispatch(
        &self,
        id: u32,
        ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let syscall_id = SyscallId::from_u32(id)?;
        let idx = syscall_id as usize - 1;
        let syscall = self.syscalls[idx]
            .as_ref()
            .ok_or_else(|| ZkvmError::Other(format!("syscall {syscall_id:?} not registered")))?;
        syscall.host_execute(ctx, state)
    }

    /// 获取已注册的 syscall 数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.syscalls.iter().filter(|s| s.is_some()).count()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SyscallRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_version_is_one() {
        assert_eq!(ZKVM_ABI_VERSION, 1, "ABI 版本号应为 1");
    }

    // ===== SyscallId from_u32 正向测试 =====

    #[test]
    fn test_from_u32_all_valid_ids() {
        let cases = [
            (0x01u32, SyscallId::ReadInput),
            (0x02, SyscallId::CommitOutput),
            (0x03, SyscallId::Poseidon),
            (0x04, SyscallId::Sha256),
            (0x05, SyscallId::EcdsaVerify),
            (0x06, SyscallId::EmitEvent),
            (0x07, SyscallId::Log),
            (0x08, SyscallId::Panic),
            (0x09, SyscallId::GetRandomness),
            (0x0A, SyscallId::ReadState),
            (0x0B, SyscallId::Keccak256),
            (0x0C, SyscallId::Modexp),
            (0x0D, SyscallId::MerkleVerify),
            (0x0E, SyscallId::Ed25519Verify),
            (0x0F, SyscallId::Bn254Pairing),
        ];
        for (id, expected) in cases {
            let result = SyscallId::from_u32(id).unwrap();
            assert_eq!(result, expected, "from_u32(0x{id:02x}) 应为 {expected:?}");
        }
    }

    // ===== SyscallId from_u32 负向测试 =====

    #[test]
    fn test_from_u32_invalid_ids() {
        let invalid_ids = [0x00u32, 0x10, 0xFF, 0x100, u32::MAX];
        for id in invalid_ids {
            let result = SyscallId::from_u32(id);
            assert!(result.is_err(), "from_u32(0x{id:02x}) 应返回错误");
            assert!(
                matches!(result, Err(ZkvmError::Other(_))),
                "from_u32(0x{id:02x}) 应返回 Other 错误"
            );
        }
    }

    // ===== SyscallId as u32 测试 =====

    #[test]
    fn test_syscall_id_as_u32() {
        assert_eq!(SyscallId::ReadInput as u32, 0x01);
        assert_eq!(SyscallId::CommitOutput as u32, 0x02);
        assert_eq!(SyscallId::Poseidon as u32, 0x03);
        assert_eq!(SyscallId::Sha256 as u32, 0x04);
        assert_eq!(SyscallId::EcdsaVerify as u32, 0x05);
        assert_eq!(SyscallId::EmitEvent as u32, 0x06);
        assert_eq!(SyscallId::Log as u32, 0x07);
        assert_eq!(SyscallId::Panic as u32, 0x08);
        assert_eq!(SyscallId::GetRandomness as u32, 0x09);
        assert_eq!(SyscallId::ReadState as u32, 0x0A);
        assert_eq!(SyscallId::Keccak256 as u32, 0x0B);
        assert_eq!(SyscallId::Modexp as u32, 0x0C);
        assert_eq!(SyscallId::MerkleVerify as u32, 0x0D);
        assert_eq!(SyscallId::Ed25519Verify as u32, 0x0E);
        assert_eq!(SyscallId::Bn254Pairing as u32, 0x0F);
    }

    // ===== SyscallId all() 测试 =====

    #[test]
    fn test_all_returns_fifteen_syscalls() {
        let all = SyscallId::all();
        assert_eq!(all.len(), 15, "应有 15 个 syscall");
        // 验证 ID 连续递增
        for (i, id) in all.iter().enumerate() {
            assert_eq!(
                *id as u32,
                (i + 1) as u32,
                "all()[{i}] 的 ID 应为 {}",
                i + 1
            );
        }
    }

    // ===== derive trait 测试 =====

    #[test]
    fn test_derive_traits() {
        let a = SyscallId::ReadInput;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, SyscallId::CommitOutput);
        // Debug 可用
        let debug_str = format!("{a:?}");
        assert!(debug_str.contains("ReadInput"));
        // Hash 可用（放入 HashMap）
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(set.contains(&a));
    }

    // ===== SyscallContext 测试 =====

    #[test]
    fn test_syscall_context_new_defaults() {
        let ctx = SyscallContext::new(vec![1, 2, 3]);
        assert_eq!(ctx.input, vec![1, 2, 3]);
        assert!(ctx.output.is_empty());
        assert!(ctx.events.is_empty());
        assert!(ctx.logs.is_empty());
        assert!(!ctx.halted);
        assert_eq!(ctx.step_index, 0);
        assert_eq!(ctx.randomness_counter, 0);
    }

    #[test]
    fn test_syscall_context_halt() {
        let mut ctx = SyscallContext::new(vec![]);
        assert!(!ctx.is_halted());
        ctx.halted = true;
        assert!(ctx.is_halted());
    }

    #[test]
    fn test_syscall_context_into_output() {
        let mut ctx = SyscallContext::new(vec![]);
        ctx.output = vec![0xAB, 0xCD];
        let output = ctx.into_output();
        assert_eq!(output, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_syscall_context_with_host_state() {
        use crate::syscalls::host_state::StubHostState;
        let ctx = SyscallContext::new(vec![]).with_host_state(Box::new(StubHostState));
        // host_state 应为 StubHostState（返回错误）
        assert!(ctx.host_state.read_slot(0x01).is_err());
    }

    #[test]
    fn test_syscall_context_debug() {
        let ctx = SyscallContext::new(vec![1, 2]);
        let debug_str = format!("{ctx:?}");
        assert!(debug_str.contains("SyscallContext"));
        assert!(debug_str.contains("input_len"));
    }

    // ===== SyscallRegistry 测试 =====

    #[test]
    fn test_syscall_registry_new_empty() {
        let registry = SyscallRegistry::new_empty();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_syscall_registry_dispatch_invalid_id() {
        let registry = SyscallRegistry::new_empty();
        let mut ctx = SyscallContext::new(vec![]);
        let mut state = VmState::new();
        // 非法 ID
        let err = registry.dispatch(0x00, &mut ctx, &mut state).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(_)));
        let err = registry.dispatch(0x10, &mut ctx, &mut state).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(_)));
    }

    #[test]
    fn test_syscall_registry_dispatch_unregistered() {
        let registry = SyscallRegistry::new_empty();
        let mut ctx = SyscallContext::new(vec![]);
        let mut state = VmState::new();
        // 合法 ID 但未注册
        let err = registry.dispatch(0x01, &mut ctx, &mut state).unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg.contains("not registered")),
            "应返回 not registered 错误，got {err:?}"
        );
    }

    #[test]
    fn test_syscall_registry_register_and_dispatch() {
        /// 测试用 syscall — 返回固定 gas_cost。
        #[derive(Debug)]
        struct TestSyscall;

        impl Syscall for TestSyscall {
            fn id(&self) -> SyscallId {
                SyscallId::ReadInput
            }
            fn host_execute(
                &self,
                ctx: &mut SyscallContext,
                _state: &mut VmState,
            ) -> Result<(), ZkvmError> {
                ctx.output = ctx.input.clone();
                Ok(())
            }
            fn gas_cost(&self, _state: &VmState) -> u64 {
                42
            }
        }

        let mut registry = SyscallRegistry::new_empty();
        registry.register(Box::new(TestSyscall)).unwrap();
        assert_eq!(registry.len(), 1);

        let mut ctx = SyscallContext::new(vec![0xAB]);
        let mut state = VmState::new();
        registry.dispatch(0x01, &mut ctx, &mut state).unwrap();
        assert_eq!(ctx.output, vec![0xAB]);
    }

    #[test]
    fn test_syscall_registry_duplicate_register() {
        #[derive(Debug)]
        struct TestSyscall;
        impl Syscall for TestSyscall {
            fn id(&self) -> SyscallId {
                SyscallId::ReadInput
            }
            fn host_execute(
                &self,
                _ctx: &mut SyscallContext,
                _state: &mut VmState,
            ) -> Result<(), ZkvmError> {
                Ok(())
            }
            fn gas_cost(&self, _state: &VmState) -> u64 {
                0
            }
        }

        let mut registry = SyscallRegistry::new_empty();
        registry.register(Box::new(TestSyscall)).unwrap();
        // 重复注册应失败
        let err = registry.register(Box::new(TestSyscall)).unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg.contains("already registered")),
            "应返回 already registered 错误"
        );
    }

    #[test]
    fn test_syscall_registry_debug() {
        let registry = SyscallRegistry::new_empty();
        let debug_str = format!("{registry:?}");
        assert!(debug_str.contains("SyscallRegistry"));
        assert!(debug_str.contains("registered"));
    }

    #[test]
    fn test_syscall_registry_default() {
        let registry = SyscallRegistry::default();
        // default() = new() = 全部 10 个 syscall 已注册
        assert_eq!(registry.len(), 10);
        assert!(!registry.is_empty());
    }
}
