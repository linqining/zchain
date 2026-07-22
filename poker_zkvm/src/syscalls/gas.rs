//! ZKVM Syscall gas 计费（Phase 4 — Task 4.3）。
//!
//! 严格遵循 spec.md L646 / L653 / L660 / L669（v1.4 FROZEN）：
//! - Poseidon: `GAS_ZKVM_POSEIDON_BASE + GAS_ZKVM_POSEIDON_PER_BLOCK * num_blocks`
//! - SHA-256: 按字节计费
//! - ECDSA: `GAS_ZKVM_ECDSA_VERIFY = 100_000`（spec L660）
//! - ReadState: `GAS_ZKVM_READ_STATE_PER_SLOT * num_slots`（spec L669）
//!
//! # 设计说明
//!
//! gas 计费是 on-chain 概念，host 执行不实际扣 gas。
//! [`syscall_gas`] 函数供 executor / prover 估算 syscall gas 开销。
//!
//! # Phase 1 迁移说明
//!
//! 跨 VM 共享的 syscall 级 gas 常量已迁至 `vm_common::gas`，本模块通过
//! `pub use vm_common::gas::*;` re-export 保持外部 API 完全兼容。
//! 仅 RV32I 指令级常量（`GAS_INSN_*`）与依赖 `Instruction`/`SyscallId` 的
//! 函数（`SyscallGasArgs`/`syscall_gas`/`instruction_gas`/`total_step_gas`）保留本地。

use crate::isa::Instruction;
use crate::syscalls::SyscallId;

// ===== 跨 VM 共享 gas 常量（单一事实源：vm_common::gas）=====
pub use vm_common::gas::*;

// ===== Per-Instruction Gas（Phase L — 对齐 L1 BPF + SP1 模型，RV32I 专有）=====

/// 算术指令 gas（ADD/SUB/AND/OR/XOR/SLT/SLTU + I-type 变体）。
/// 对齐 L1 GAS_ARITHMETIC=1 + SP1 per-insn base。
pub const GAS_INSN_ARITHMETIC: u64 = 1;

/// 内存加载/存储指令基础 gas（LB/LH/LW/LBU/LHU/SB/SH/SW）。
/// 对齐 L1 GAS_MEMORY_BASE=3。
pub const GAS_INSN_MEMORY_BASE: u64 = 3;

/// 内存加载/存储指令每字节附加 gas。
/// 对齐 L1 GAS_MEMORY_PER_BYTE=2（IMPL-SEC-4 修复）。
pub const GAS_INSN_MEMORY_PER_BYTE: u64 = 2;

/// 分支指令 gas（BEQ/BNE/BLT/BGE/BLTU/BGEU/JAL/JALR）。
/// 对齐 L1 GAS_BRANCH=2。
pub const GAS_INSN_BRANCH: u64 = 2;

/// 移位指令 gas（SLL/SRL/SRA/SLLI/SRLI/SRAI）。
/// 移位约束复杂度高于算术，设为 2。
pub const GAS_INSN_SHIFT: u64 = 2;

/// M 扩展乘法指令 gas（MUL/MULH/MULHSU/MULHU）。
/// 乘法约束（64-bit 乘积分解）远重于算术，对齐 modexp PER_BIT 量级。
pub const GAS_INSN_MUL: u64 = 20;

/// M 扩展除法指令 gas（DIV/DIVU/REM/REMU）。
/// MVP trust witness 模式下约束轻，但语义复杂；完整约束后应提升。
pub const GAS_INSN_DIV: u64 = 20;

/// LUI/AUIPC gas（高位立即数，等同算术）。
pub const GAS_INSN_UPPER_IMM: u64 = 1;

/// FENCE/ECALL/EBREAK gas。
pub const GAS_INSN_SYSTEM: u64 = 2;

/// Syscall gas 参数（从寄存器读取后传入）。
///
/// 不同 syscall 使用不同字段：
/// - `read_input` / `commit_output` / `poseidon` / `sha256` / `emit_event` / `log` / `panic` / `keccak256` → `input_len`
/// - `read_state` → `num_slots`
/// - `modexp` → `num_bits`
/// - `merkle_verify` → `depth`
/// - `ecdsa_verify` / `get_randomness` → 不使用参数（固定 gas）
#[derive(Debug, Clone, Copy, Default)]
pub struct SyscallGasArgs {
    /// 输入长度（字节）— 用于 PER_BYTE / PER_BLOCK 计算。
    pub input_len: u32,
    /// slot 数量 — 用于 `read_state` 的 PER_SLOT 计算。
    pub num_slots: u32,
    /// 指数位数 — 用于 `modexp` 的 PER_BIT 计算。
    pub num_bits: u32,
    /// Merkle 树深度 — 用于 `merkle_verify` 的 PER_LEVEL 计算。
    pub depth: u32,
}

/// 计算 syscall 的 gas 开销。
///
/// # 公式
///
/// | Syscall | 公式 |
/// |---------|------|
/// | `ReadInput` | `GAS_ZKVM_READ_INPUT_BASE` |
/// | `CommitOutput` | `GAS_ZKVM_COMMIT_OUTPUT_BASE` |
/// | `Poseidon` | `BASE + PER_BLOCK * ceil(input_len / 32)` |
/// | `Sha256` | `PER_BYTE * input_len` |
/// | `EcdsaVerify` | `GAS_ZKVM_ECDSA_VERIFY`（固定） |
/// | `EmitEvent` | `BASE + PER_BYTE * input_len` |
/// | `Log` | `BASE + PER_BYTE * input_len` |
/// | `Panic` | `GAS_ZKVM_PANIC`（固定） |
/// | `GetRandomness` | `GAS_ZKVM_GET_RANDOMNESS`（固定） |
/// | `ReadState` | `PER_SLOT * num_slots` |
/// | `Keccak256` | `PER_ROUND * 24 + PER_BYTE * input_len` |
/// | `Modexp` | `BASE + PER_BIT * num_bits` |
/// | `MerkleVerify` | `PER_LEVEL * depth` |
/// | `Ed25519Verify` | `BASE + PER_BIT * num_bits` |
/// | `Bn254Pairing` | `GAS_ZKVM_BN254_PAIRING_FULL`（固定） |
/// | `Bls12381HashToCurve` | `GAS_ZKVM_BLS_HASH_TO_CURVE`（固定） |
/// | `Bls12381ScalarMul` | `GAS_ZKVM_BLS_SCALAR_MUL`（固定） |
/// | `Bls12381G1Add` | `GAS_ZKVM_BLS_G1_ADD`（固定） |
/// | `Bls12381G1Mul` | `GAS_ZKVM_BLS_G1_MUL`（固定） |
/// | `Bls12381Pairing` | `GAS_ZKVM_BLS_PAIRING`（固定） |
/// | `Bls12381HashToScalar` | `GAS_ZKVM_BLS_HASH_TO_SCALAR + PER_BYTE * input_len` |
/// | `GameStateRead` | `GAS_ZKVM_GAME_STATE_READ`（固定） |
/// | `GameStateWrite` | `GAS_ZKVM_GAME_STATE_WRITE + PER_BYTE * input_len` |
/// | `CardEncode` | `GAS_ZKVM_CARD_ENCODE`（固定） |
/// | `CardDecode` | `GAS_ZKVM_CARD_DECODE`（固定） |
/// | `ShuffleVerify` | `GAS_ZKVM_SHUFFLE_VERIFY + PER_BYTE * input_len` |
#[must_use]
pub fn syscall_gas(id: SyscallId, args: &SyscallGasArgs) -> u64 {
    match id {
        SyscallId::ReadInput => GAS_ZKVM_READ_INPUT_BASE,
        SyscallId::CommitOutput => GAS_ZKVM_COMMIT_OUTPUT_BASE,
        SyscallId::Poseidon => {
            let num_blocks = (args.input_len as u64).div_ceil(32);
            GAS_ZKVM_POSEIDON_BASE + GAS_ZKVM_POSEIDON_PER_BLOCK * num_blocks
        }
        SyscallId::Sha256 => GAS_ZKVM_SHA256_PER_BYTE * args.input_len as u64,
        SyscallId::EcdsaVerify => GAS_ZKVM_ECDSA_VERIFY,
        SyscallId::EmitEvent => {
            GAS_ZKVM_EMIT_EVENT_BASE + GAS_ZKVM_EMIT_EVENT_PER_BYTE * args.input_len as u64
        }
        SyscallId::Log => GAS_ZKVM_LOG_BASE + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64,
        SyscallId::Panic => GAS_ZKVM_PANIC,
        SyscallId::GetRandomness => GAS_ZKVM_GET_RANDOMNESS,
        SyscallId::ReadState => GAS_ZKVM_READ_STATE_PER_SLOT * args.num_slots as u64,
        SyscallId::Keccak256 => {
            GAS_ZKVM_KECCAK256_PER_ROUND * 24 + GAS_ZKVM_KECCAK256_PER_BYTE * args.input_len as u64
        }
        SyscallId::Modexp => GAS_ZKVM_MODEXP_BASE + GAS_ZKVM_MODEXP_PER_BIT * args.num_bits as u64,
        SyscallId::MerkleVerify => GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL * args.depth as u64,
        SyscallId::Ed25519Verify => {
            GAS_ZKVM_ED25519_BASE + GAS_ZKVM_ED25519_PER_BIT * args.num_bits as u64
        }
        SyscallId::Bn254Pairing => GAS_ZKVM_BN254_PAIRING_FULL,
        // ===== BLS12-381 syscall gas（E2E Phase 1）=====
        // BLS12-381 比 BN254 字段更大（381-bit vs 254-bit），gas 略高于 BN254 对应操作。
        SyscallId::Bls12381HashToCurve => GAS_ZKVM_BLS_HASH_TO_CURVE,
        SyscallId::Bls12381ScalarMul => GAS_ZKVM_BLS_SCALAR_MUL,
        SyscallId::Bls12381G1Add => GAS_ZKVM_BLS_G1_ADD,
        SyscallId::Bls12381G1Mul => GAS_ZKVM_BLS_G1_MUL,
        SyscallId::Bls12381Pairing => GAS_ZKVM_BLS_PAIRING,
        SyscallId::Bls12381HashToScalar => {
            GAS_ZKVM_BLS_HASH_TO_SCALAR + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64
        }
        // ===== BLS12-381 扩展 syscall gas（Phase 3.2 — D2 决策）=====
        // 标量算术：381-bit field add/sub/neg 轻于乘法；inv 接近乘法（Fermat 小定理指数）。
        SyscallId::Bls12381ScalarAdd => GAS_ZKVM_BLS_SCALAR_ADD,
        SyscallId::Bls12381ScalarSub => GAS_ZKVM_BLS_SCALAR_SUB,
        SyscallId::Bls12381ScalarNeg => GAS_ZKVM_BLS_SCALAR_NEG,
        SyscallId::Bls12381ScalarInv => GAS_ZKVM_BLS_SCALAR_INV,
        // G1 点减：同点加量级（一次 Jacobian→Affine 加法）。
        SyscallId::Bls12381G1Sub => GAS_ZKVM_BLS_G1_SUB,
        // G1 生成元：返回常量，极轻。
        SyscallId::Bls12381G1Generator => GAS_ZKVM_BLS_G1_GENERATOR,
        // ===== GameState mock syscall gas（E2E Phase 1）=====
        SyscallId::GameStateRead => GAS_ZKVM_GAME_STATE_READ,
        SyscallId::GameStateWrite => {
            GAS_ZKVM_GAME_STATE_WRITE + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64
        }
        // ===== Game-specific syscall gas（E2E Phase 1）=====
        SyscallId::CardEncode => GAS_ZKVM_CARD_ENCODE,
        SyscallId::CardDecode => GAS_ZKVM_CARD_DECODE,
        SyscallId::ShuffleVerify => {
            GAS_ZKVM_SHUFFLE_VERIFY + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64
        }
        // ===== Phase 4: Mental Poker proof verify + hash syscall gas（0x33-0x36）=====
        SyscallId::Blake2b256 => {
            GAS_ZKVM_BLAKE2B_256_BASE + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64
        }
        // DLEq/ZKShuffle proof 验证：基于 input_cts 长度（proof 通常 < 1KB，cts 占大头）。
        SyscallId::VerifyDleqProof => {
            GAS_ZKVM_VERIFY_DLEQ_PROOF_BASE + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64
        }
        SyscallId::VerifyReconstructProof => {
            GAS_ZKVM_VERIFY_RECONSTRUCT_PROOF_BASE + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64
        }
        SyscallId::VerifyRevealTokenProof => {
            GAS_ZKVM_VERIFY_REVEAL_TOKEN_PROOF_BASE + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64
        }
    }
}

// ===== BLS12-381 / GameState / Game-specific syscall gas 常量（E2E Phase 1）=====
//
// 这些常量定义在 gas.rs 本地（而非 vm_common::gas），因为它们是 poker_zkvm 专有的
// E2E 测试用 syscall，不属于跨 VM 共享的 cross-cutting concern。

/// BLS12-381 hash-to-G1 gas（RFC 9380，重于普通哈希）。
pub const GAS_ZKVM_BLS_HASH_TO_CURVE: u64 = 120_000;

/// BLS12-381 标量乘法 gas（381-bit field mul）。
pub const GAS_ZKVM_BLS_SCALAR_MUL: u64 = 60_000;

/// BLS12-381 G1 点加 gas。
pub const GAS_ZKVM_BLS_G1_ADD: u64 = 40_000;

/// BLS12-381 G1 标量乘 gas（重于点加）。
pub const GAS_ZKVM_BLS_G1_MUL: u64 = 90_000;

/// BLS12-381 配对 gas（最重的 BLS 操作，比 BN254 pairing 高 50%）。
pub const GAS_ZKVM_BLS_PAIRING: u64 = 120_000;

/// BLS12-381 hash-to-scalar 基础 gas（不含按字节计费）。
pub const GAS_ZKVM_BLS_HASH_TO_SCALAR: u64 = 15_000;

// ===== BLS12-381 扩展 syscall gas 常量（Phase 3.2 — D2 决策）=====
//
// 为 texas_poker crypto utils 移植新增的标量算术 + G1 辅助 syscall。
// 标量算术（381-bit field）轻于标量乘法；G1 点减同点加量级。

/// BLS12-381 标量加法 gas（381-bit field add，轻量）。
pub const GAS_ZKVM_BLS_SCALAR_ADD: u64 = 5_000;

/// BLS12-381 标量减法 gas（同 add 量级）。
pub const GAS_ZKVM_BLS_SCALAR_SUB: u64 = 5_000;

/// BLS12-381 标量取负 gas（同 add 量级）。
pub const GAS_ZKVM_BLS_SCALAR_NEG: u64 = 5_000;

/// BLS12-381 标量求逆 gas（Fermat 小定理 a^(p-2)，接近乘法量级）。
pub const GAS_ZKVM_BLS_SCALAR_INV: u64 = 50_000;

/// BLS12-381 G1 点减 gas（同点加量级）。
pub const GAS_ZKVM_BLS_G1_SUB: u64 = 40_000;

/// BLS12-381 G1 生成元 gas（返回常量，极轻）。
pub const GAS_ZKVM_BLS_G1_GENERATOR: u64 = 100;

/// GameState mock 读取 gas（类似 ReadState）。
pub const GAS_ZKVM_GAME_STATE_READ: u64 = 50;

/// GameState mock 写入基础 gas（不含按字节计费）。
pub const GAS_ZKVM_GAME_STATE_WRITE: u64 = 100;

/// 扑克牌编码 gas（轻量操作）。
pub const GAS_ZKVM_CARD_ENCODE: u64 = 10;

/// 扑克牌解码 gas（轻量操作）。
pub const GAS_ZKVM_CARD_DECODE: u64 = 10;

/// ZKShuffle 验证基础 gas（不含按字节计费，shuffle proof 验证非常重）。
pub const GAS_ZKVM_SHUFFLE_VERIFY: u64 = 500_000;

// ===== Phase 4: Mental Poker proof verify + hash syscall gas 常量（0x33-0x36）=====
//
// 这些 syscall 在 host 端调用 poker_protocol 的完整 proof verify 逻辑，
// 涉及大量 BLS12-381 G1/Scalar 运算 + transcript Fiat-Shamir 挑战派生，
// gas 估算参考 BLS12-381 pairing (120K) + 多次标量乘/点加的量级。

/// Blake2b-256 哈希基础 gas（变长输入，与 SHA-256 量级相当但稍轻）。
pub const GAS_ZKVM_BLAKE2B_256_BASE: u64 = 5_000;

/// DLEq/ZKShuffle proof 验证基础 gas。
///
/// 涉及 52 张密文的 batch DLEq 验证（n×MSM），gas 接近 shuffle verify。
pub const GAS_ZKVM_VERIFY_DLEQ_PROOF_BASE: u64 = 500_000;

/// Reconstruct proof 验证基础 gas。
///
/// 涉及 52 张 swap_out proofs + reconstruct batch 验证，gas 最重。
pub const GAS_ZKVM_VERIFY_RECONSTRUCT_PROOF_BASE: u64 = 1_000_000;

/// Reveal token proof 验证基础 gas。
///
/// 单个密文 + 单 token 的 Schnorr-like 验证，gas 较轻。
pub const GAS_ZKVM_VERIFY_REVEAL_TOKEN_PROOF_BASE: u64 = 100_000;

/// 计算单条指令的 gas 开销（不含 syscall gas）。
///
/// # 模型
///
/// | 类别 | 指令 | Gas |
/// |------|------|-----|
/// | 算术 | ADD/SUB/AND/OR/XOR/SLT/SLTU + I-type | `GAS_INSN_ARITHMETIC` |
/// | 内存 | LB/LH/LW/LBU/LHU | `GAS_INSN_MEMORY_BASE + GAS_INSN_MEMORY_PER_BYTE * bytes` |
/// | Store | SB/SH/SW | `GAS_INSN_MEMORY_BASE + GAS_INSN_MEMORY_PER_BYTE * bytes` |
/// | 分支 | BEQ/BNE/BLT/BGE/BLTU/BGEU/JAL/JALR | `GAS_INSN_BRANCH` |
/// | 移位 | SLL/SRL/SRA/SLLI/SRLI/SRAI | `GAS_INSN_SHIFT` |
/// | 乘法 | MUL/MULH/MULHSU/MULHU | `GAS_INSN_MUL` |
/// | 除法 | DIV/DIVU/REM/REMU | `GAS_INSN_DIV` |
/// | 高位立即数 | LUI/AUIPC | `GAS_INSN_UPPER_IMM` |
/// | 系统 | FENCE/ECALL/EBREAK | `GAS_INSN_SYSTEM` |
///
/// # 参数
/// - `insn` — 解码后的指令
/// - `mem_bytes` — 内存访问字节数（1/2/4），非内存指令传 0
#[must_use]
pub fn instruction_gas(insn: &Instruction, mem_bytes: u32) -> u64 {
    match insn {
        Instruction::Lb { .. }
        | Instruction::Lh { .. }
        | Instruction::Lw { .. }
        | Instruction::Lbu { .. }
        | Instruction::Lhu { .. }
        | Instruction::Sb { .. }
        | Instruction::Sh { .. }
        | Instruction::Sw { .. } => {
            GAS_INSN_MEMORY_BASE + GAS_INSN_MEMORY_PER_BYTE * mem_bytes as u64
        }
        Instruction::Beq { .. }
        | Instruction::Bne { .. }
        | Instruction::Blt { .. }
        | Instruction::Bge { .. }
        | Instruction::Bltu { .. }
        | Instruction::Bgeu { .. }
        | Instruction::Jal { .. }
        | Instruction::Jalr { .. } => GAS_INSN_BRANCH,
        Instruction::Sll { .. }
        | Instruction::Srl { .. }
        | Instruction::Sra { .. }
        | Instruction::Slli { .. }
        | Instruction::Srli { .. }
        | Instruction::Srai { .. } => GAS_INSN_SHIFT,
        Instruction::Mul { .. }
        | Instruction::Mulh { .. }
        | Instruction::Mulhsu { .. }
        | Instruction::Mulhu { .. } => GAS_INSN_MUL,
        Instruction::Div { .. }
        | Instruction::Divu { .. }
        | Instruction::Rem { .. }
        | Instruction::Remu { .. } => GAS_INSN_DIV,
        Instruction::Lui { .. } | Instruction::Auipc { .. } => GAS_INSN_UPPER_IMM,
        Instruction::Fence | Instruction::Ecall | Instruction::Ebreak => GAS_INSN_SYSTEM,
        // 其余算术（ADD/SUB/AND/OR/XOR/SLT/SLTU + I-type 变体）
        _ => GAS_INSN_ARITHMETIC,
    }
}

/// 计算单步执行的 gas（指令 gas + syscall gas，若为 ECALL）。
///
/// ECALL 指令本身的 gas + 对应 syscall 的 gas。
#[must_use]
pub fn total_step_gas(
    insn: &Instruction,
    mem_bytes: u32,
    syscall_id: Option<SyscallId>,
    syscall_args: &SyscallGasArgs,
) -> u64 {
    let insn_gas = instruction_gas(insn, mem_bytes);
    let sys_gas = syscall_id
        .map(|id| syscall_gas(id, syscall_args))
        .unwrap_or(0);
    insn_gas + sys_gas
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 常量值测试 =====

    #[test]
    fn test_gas_constants_values() {
        assert_eq!(GAS_ZKVM_READ_INPUT_BASE, 10);
        assert_eq!(GAS_ZKVM_COMMIT_OUTPUT_BASE, 10);
        assert_eq!(GAS_ZKVM_POSEIDON_BASE, 100);
        assert_eq!(GAS_ZKVM_POSEIDON_PER_BLOCK, 50);
        assert_eq!(GAS_ZKVM_SHA256_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_ECDSA_VERIFY, 100_000);
        assert_eq!(GAS_ZKVM_EMIT_EVENT_BASE, 10);
        assert_eq!(GAS_ZKVM_EMIT_EVENT_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_LOG_BASE, 10);
        assert_eq!(GAS_ZKVM_LOG_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_PANIC, 10);
        assert_eq!(GAS_ZKVM_GET_RANDOMNESS, 100);
        assert_eq!(GAS_ZKVM_READ_STATE_PER_SLOT, 50);
        assert_eq!(GAS_ZKVM_KECCAK256_PER_BYTE, 2);
        assert_eq!(GAS_ZKVM_KECCAK256_PER_ROUND, 10_000);
        assert_eq!(GAS_ZKVM_MODEXP_BASE, 50_000);
        assert_eq!(GAS_ZKVM_MODEXP_PER_BIT, 600);
        assert_eq!(GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL, 100);
        assert_eq!(GAS_ZKVM_ED25519_BASE, 50_000);
        assert_eq!(GAS_ZKVM_ED25519_PER_BIT, 8_000);
        assert_eq!(GAS_ZKVM_BN254_PAIRING_MVP, 30_000);
        assert_eq!(GAS_ZKVM_BN254_PAIRING_FULL, 80_000);
    }

    // ===== 固定 gas syscall 测试 =====

    #[test]
    fn test_fixed_gas_syscalls() {
        let args = SyscallGasArgs::default();
        assert_eq!(syscall_gas(SyscallId::ReadInput, &args), 10);
        assert_eq!(syscall_gas(SyscallId::CommitOutput, &args), 10);
        assert_eq!(syscall_gas(SyscallId::EcdsaVerify, &args), 100_000);
        assert_eq!(syscall_gas(SyscallId::Panic, &args), 10);
        assert_eq!(syscall_gas(SyscallId::GetRandomness, &args), 100);
    }

    // ===== Poseidon gas 测试（PER_BLOCK 乘法）=====

    #[test]
    fn test_poseidon_gas_calculation() {
        // 0 字节 → 0 blocks → 100 (仅 base)
        let args = SyscallGasArgs {
            input_len: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 100);

        // 1 字节 → 1 block → 100 + 50 = 150
        let args = SyscallGasArgs {
            input_len: 1,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 150);

        // 32 字节 → 1 block → 150
        let args = SyscallGasArgs {
            input_len: 32,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 150);

        // 33 字节 → 2 blocks → 100 + 100 = 200
        let args = SyscallGasArgs {
            input_len: 33,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 200);

        // 64 字节 → 2 blocks → 200
        let args = SyscallGasArgs {
            input_len: 64,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 200);

        // 65 字节 → 3 blocks → 100 + 150 = 250
        let args = SyscallGasArgs {
            input_len: 65,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 250);
    }

    // ===== SHA-256 gas 测试（PER_BYTE 乘法）=====

    #[test]
    fn test_sha256_gas_calculation() {
        let args = SyscallGasArgs {
            input_len: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Sha256, &args), 0);

        let args = SyscallGasArgs {
            input_len: 1,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Sha256, &args), 1);

        let args = SyscallGasArgs {
            input_len: 100,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Sha256, &args), 100);

        let args = SyscallGasArgs {
            input_len: 1024,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Sha256, &args), 1024);
    }

    // ===== emit_event / log gas 测试（BASE + PER_BYTE）=====

    #[test]
    fn test_emit_event_gas_calculation() {
        let args = SyscallGasArgs {
            input_len: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::EmitEvent, &args), 10);

        let args = SyscallGasArgs {
            input_len: 100,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::EmitEvent, &args), 110);
    }

    #[test]
    fn test_log_gas_calculation() {
        let args = SyscallGasArgs {
            input_len: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Log, &args), 10);

        let args = SyscallGasArgs {
            input_len: 50,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Log, &args), 60);
    }

    // ===== read_state gas 测试（PER_SLOT 乘法）=====

    #[test]
    fn test_read_state_gas_calculation() {
        let args = SyscallGasArgs {
            num_slots: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::ReadState, &args), 0);

        let args = SyscallGasArgs {
            num_slots: 1,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::ReadState, &args), 50);

        let args = SyscallGasArgs {
            num_slots: 5,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::ReadState, &args), 250);
    }

    // ===== keccak256 gas 测试（PER_ROUND * 24 + PER_BYTE * input_len）=====

    #[test]
    fn test_keccak256_gas_calculation() {
        // 0 字节 → 10000 * 24 + 2 * 0 = 240_000
        let args = SyscallGasArgs {
            input_len: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Keccak256, &args), 240_000);

        // 1 字节 → 240_000 + 2 = 240_002
        let args = SyscallGasArgs {
            input_len: 1,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Keccak256, &args), 240_002);

        // 136 字节（1 rate block）→ 240_000 + 272 = 240_272
        let args = SyscallGasArgs {
            input_len: 136,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Keccak256, &args), 240_272);
    }

    // ===== modexp gas 测试（BASE + PER_BIT * num_bits）=====

    #[test]
    fn test_modexp_gas_calculation() {
        // 0 bits → 50_000
        let args = SyscallGasArgs {
            num_bits: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Modexp, &args), 50_000);

        // 8 bits → 50_000 + 4_800 = 54_800
        let args = SyscallGasArgs {
            num_bits: 8,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Modexp, &args), 54_800);

        // 256 bits → 50_000 + 153_600 = 203_600
        let args = SyscallGasArgs {
            num_bits: 256,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Modexp, &args), 203_600);
    }

    // ===== merkle_verify gas 测试（PER_LEVEL * depth）=====

    #[test]
    fn test_merkle_verify_gas_calculation() {
        // depth 0 → 0
        let args = SyscallGasArgs {
            depth: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::MerkleVerify, &args), 0);

        // depth 1 → 100
        let args = SyscallGasArgs {
            depth: 1,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::MerkleVerify, &args), 100);

        // depth 32 → 3_200
        let args = SyscallGasArgs {
            depth: 32,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::MerkleVerify, &args), 3_200);
    }

    // ===== ed25519 gas 测试（BASE + PER_BIT * num_bits）=====

    #[test]
    fn test_ed25519_gas_calculation() {
        // 0 bits → 50_000
        let args = SyscallGasArgs {
            num_bits: 0,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Ed25519Verify, &args), 50_000);

        // 8 bits → 50_000 + 64_000 = 114_000
        let args = SyscallGasArgs {
            num_bits: 8,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Ed25519Verify, &args), 114_000);

        // 252 bits → 50_000 + 2_016_000 = 2_066_000
        let args = SyscallGasArgs {
            num_bits: 252,
            ..Default::default()
        };
        assert_eq!(syscall_gas(SyscallId::Ed25519Verify, &args), 2_066_000);
    }

    // ===== bn254_pairing gas 测试（固定值）=====

    #[test]
    fn test_bn254_pairing_gas_calculation() {
        let args = SyscallGasArgs::default();
        assert_eq!(syscall_gas(SyscallId::Bn254Pairing, &args), 80_000);
    }

    // ===== 全 syscall 覆盖测试 =====

    #[test]
    fn test_all_syscalls_have_gas() {
        let args = SyscallGasArgs {
            input_len: 32,
            num_slots: 1,
            num_bits: 256,
            depth: 20,
        };
        for id in SyscallId::all() {
            let gas = syscall_gas(id, &args);
            assert!(gas < u64::MAX, "syscall {id:?} gas 不应溢出");
        }
    }

    // ===== Per-Instruction Gas 常量值测试 =====

    #[test]
    fn test_instruction_gas_constants_values() {
        assert_eq!(GAS_INSN_ARITHMETIC, 1);
        assert_eq!(GAS_INSN_MEMORY_BASE, 3);
        assert_eq!(GAS_INSN_MEMORY_PER_BYTE, 2);
        assert_eq!(GAS_INSN_BRANCH, 2);
        assert_eq!(GAS_INSN_SHIFT, 2);
        assert_eq!(GAS_INSN_MUL, 20);
        assert_eq!(GAS_INSN_DIV, 20);
        assert_eq!(GAS_INSN_UPPER_IMM, 1);
        assert_eq!(GAS_INSN_SYSTEM, 2);
    }

    // ===== instruction_gas 函数测试 =====

    #[test]
    fn test_instruction_gas_arithmetic() {
        // R-type 算术
        assert_eq!(
            instruction_gas(
                &Instruction::Add {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            1
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Sub {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            1
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Xor {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            1
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Or {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            1
        );
        assert_eq!(
            instruction_gas(
                &Instruction::And {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            1
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Slt {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            1
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Sltu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            1
        );
        // I-type 算术
        assert_eq!(
            instruction_gas(
                &Instruction::Addi {
                    rd: 1,
                    rs1: 2,
                    imm: 10
                },
                0
            ),
            1
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Xori {
                    rd: 1,
                    rs1: 2,
                    imm: 10
                },
                0
            ),
            1
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Andi {
                    rd: 1,
                    rs1: 2,
                    imm: 10
                },
                0
            ),
            1
        );
    }

    #[test]
    fn test_instruction_gas_memory() {
        // LW = 4 bytes → 3 + 2*4 = 11
        assert_eq!(
            instruction_gas(
                &Instruction::Lw {
                    rd: 1,
                    rs1: 2,
                    imm: 0
                },
                4
            ),
            11
        );
        // LH = 2 bytes → 3 + 2*2 = 7
        assert_eq!(
            instruction_gas(
                &Instruction::Lh {
                    rd: 1,
                    rs1: 2,
                    imm: 0
                },
                2
            ),
            7
        );
        // LB = 1 byte → 3 + 2*1 = 5
        assert_eq!(
            instruction_gas(
                &Instruction::Lb {
                    rd: 1,
                    rs1: 2,
                    imm: 0
                },
                1
            ),
            5
        );
        // LBU = 1 byte → 5
        assert_eq!(
            instruction_gas(
                &Instruction::Lbu {
                    rd: 1,
                    rs1: 2,
                    imm: 0
                },
                1
            ),
            5
        );
        // LHU = 2 bytes → 7
        assert_eq!(
            instruction_gas(
                &Instruction::Lhu {
                    rd: 1,
                    rs1: 2,
                    imm: 0
                },
                2
            ),
            7
        );
        // SW = 4 bytes → 11
        assert_eq!(
            instruction_gas(
                &Instruction::Sw {
                    rs1: 2,
                    rs2: 3,
                    imm: 0
                },
                4
            ),
            11
        );
        // SH = 2 bytes → 7
        assert_eq!(
            instruction_gas(
                &Instruction::Sh {
                    rs1: 2,
                    rs2: 3,
                    imm: 0
                },
                2
            ),
            7
        );
        // SB = 1 byte → 5
        assert_eq!(
            instruction_gas(
                &Instruction::Sb {
                    rs1: 2,
                    rs2: 3,
                    imm: 0
                },
                1
            ),
            5
        );
    }

    #[test]
    fn test_instruction_gas_branch() {
        assert_eq!(
            instruction_gas(
                &Instruction::Beq {
                    rs1: 1,
                    rs2: 2,
                    imm: 0
                },
                0
            ),
            2
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Bne {
                    rs1: 1,
                    rs2: 2,
                    imm: 0
                },
                0
            ),
            2
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Blt {
                    rs1: 1,
                    rs2: 2,
                    imm: 0
                },
                0
            ),
            2
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Bgeu {
                    rs1: 1,
                    rs2: 2,
                    imm: 0
                },
                0
            ),
            2
        );
        assert_eq!(instruction_gas(&Instruction::Jal { rd: 1, imm: 100 }, 0), 2);
        assert_eq!(
            instruction_gas(
                &Instruction::Jalr {
                    rd: 1,
                    rs1: 2,
                    imm: 0
                },
                0
            ),
            2
        );
    }

    #[test]
    fn test_instruction_gas_shift() {
        // R-type 移位
        assert_eq!(
            instruction_gas(
                &Instruction::Sll {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            2
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Srl {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            2
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Sra {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            2
        );
        // I-type 移位
        assert_eq!(
            instruction_gas(
                &Instruction::Slli {
                    rd: 1,
                    rs1: 2,
                    shamt: 4
                },
                0
            ),
            2
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Srli {
                    rd: 1,
                    rs1: 2,
                    shamt: 4
                },
                0
            ),
            2
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Srai {
                    rd: 1,
                    rs1: 2,
                    shamt: 4
                },
                0
            ),
            2
        );
    }

    #[test]
    fn test_instruction_gas_mul() {
        assert_eq!(
            instruction_gas(
                &Instruction::Mul {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            20
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Mulh {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            20
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Mulhsu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            20
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Mulhu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            20
        );
    }

    #[test]
    fn test_instruction_gas_div() {
        assert_eq!(
            instruction_gas(
                &Instruction::Div {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            20
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Divu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            20
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Rem {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            20
        );
        assert_eq!(
            instruction_gas(
                &Instruction::Remu {
                    rd: 1,
                    rs1: 2,
                    rs2: 3
                },
                0
            ),
            20
        );
    }

    #[test]
    fn test_instruction_gas_upper_imm() {
        assert_eq!(
            instruction_gas(&Instruction::Lui { rd: 1, imm: 0x1000 }, 0),
            1
        );
        assert_eq!(
            instruction_gas(&Instruction::Auipc { rd: 1, imm: 0x1000 }, 0),
            1
        );
    }

    #[test]
    fn test_instruction_gas_system() {
        assert_eq!(instruction_gas(&Instruction::Fence, 0), 2);
        assert_eq!(instruction_gas(&Instruction::Ecall, 0), 2);
        assert_eq!(instruction_gas(&Instruction::Ebreak, 0), 2);
    }

    #[test]
    fn test_total_step_gas_ecall() {
        // ECALL 指令 gas (2) + Poseidon syscall gas (100 + 50*1 = 150) = 152
        let insn = Instruction::Ecall;
        let syscall_args = SyscallGasArgs {
            input_len: 32,
            ..Default::default()
        };
        let total = total_step_gas(&insn, 0, Some(SyscallId::Poseidon), &syscall_args);
        // Poseidon: 100 + 50 * ceil(32/32) = 100 + 50 = 150
        // ECALL insn: 2
        // Total: 152
        assert_eq!(total, 152);
    }

    #[test]
    fn test_total_step_gas_no_syscall() {
        // ADD 指令无 syscall → 仅指令 gas = 1
        let insn = Instruction::Add {
            rd: 1,
            rs1: 2,
            rs2: 3,
        };
        let syscall_args = SyscallGasArgs::default();
        let total = total_step_gas(&insn, 0, None, &syscall_args);
        assert_eq!(total, 1);
    }

    #[test]
    fn test_total_step_gas_memory_with_syscall() {
        // LW 指令 (11) 无 syscall → 11
        let insn = Instruction::Lw {
            rd: 1,
            rs1: 2,
            imm: 0,
        };
        let syscall_args = SyscallGasArgs::default();
        let total = total_step_gas(&insn, 4, None, &syscall_args);
        assert_eq!(total, 11);
    }
}
