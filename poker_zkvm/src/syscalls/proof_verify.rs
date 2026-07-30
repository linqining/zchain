//! Mental Poker proof verify + Blake2b-256 Syscall 实现（Phase 4.1 — D2 决策）。
//!
//! 为 zkvm 新增 4 个 syscall，支持 texas_poker 合约 guest 内的 ZK proof 验证
//! 与 method selector 计算。host 端调用 `poker_protocol` 的完整 proof verify 逻辑，
//! guest 仅序列化输入并经 syscall 委托验证。
//!
//! # Syscall 列表
//!
//! | ID | 名称 | ABI | 说明 |
//! |----|------|-----|------|
//! | 0x33 | `Blake2b256` | (data_ptr, data_len, out_ptr) | Blake2b-256 变长输出（32B） |
//! | 0x34 | `VerifyDleqProof` | (kind, buf_ptr, buf_len) → bool | DLEq Remask/Leave + ZKShuffle proof 验证 |
//! | 0x35 | `VerifyReconstructProof` | (buf_ptr, buf_len) → bool | Reconstruct proof 验证 |
//! | 0x36 | `VerifyRevealTokenProof` | (buf_ptr, buf_len) → bool | Reveal token proof 验证 |
//!
//! # 缓冲区格式
//!
//! 各 proof verify syscall 接受单个 length-prefixed 缓冲区（避免 a0-a7 寄存器不够用）。
//! 详细格式见各 syscall 的 ABI 注释。
//!
//! # Borsh 兼容性
//!
//! guest 端 `guest_sdk::bls::{G1Point, Scalar, ElGamalCiphertext}` 与 host 端
//! `poker_protocol::crypto::types::{ECPoint, ECScalar, ElGamalCiphertext}` 的 Borsh
//! 布局逐字节一致（48B G1 compressed / 32B scalar big-endian / 96B ciphertext），
//! 因此 guest 序列化的 buffer 可被 host 直接 `borsh::from_slice` 反序列化。

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use borsh::BorshDeserialize;
use pairing::group::ff::Field;
use pairing::group::{Curve, Group, GroupEncoding};

use blstrs::{G1Projective, Scalar as BlsScalar};

use poker_protocol::crypto::types::{DefaultCurve, ElGamalCiphertext};
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, LeaveKind, RemaskKind};
use poker_protocol::zk_shuffle::reconstruction::ReconstructProof;
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};

use crate::error::ZkvmError;
use crate::isa::state::VmState;
use crate::syscalls::gas::{SyscallGasArgs, syscall_gas};
use crate::syscalls::host::{read_vm_bytes, write_vm_bytes};
use crate::syscalls::{Syscall, SyscallContext, SyscallId, REG_A0, REG_A1, REG_A2};

// ===== 常量 =====

/// G1 compressed 字节数（BLS12-381）。
const G1_COMPRESSED_SIZE: usize = 48;

/// 单个 ElGamalCiphertext Borsh 序列化字节数（c1 48B + c2 48B）。
const CT_SIZE: usize = 96;

/// Blake2b-256 输出字节数。
const BLAKE2B_256_OUT_SIZE: usize = 32;

// ===== 缓冲区解析辅助 =====

/// 从缓冲区读取 4 字节 LE 长度前缀 + 对应字节切片，返回 (剩余, 切片)。
fn read_len_prefixed<'a>(buf: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), ZkvmError> {
    if buf.len() < 4 {
        return Err(ZkvmError::Other("proof buf: missing length prefix".into()));
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Err(ZkvmError::Other(format!(
            "proof buf: declared len {len} exceeds remaining {}",
            buf.len() - 4
        )));
    }
    Ok((&buf[4..4 + len], &buf[4 + len..]))
}

/// 从缓冲区读取固定长度字节切片，返回 (切片, 剩余)。
fn read_fixed<'a>(buf: &'a [u8], n: usize) -> Result<(&'a [u8], &'a [u8]), ZkvmError> {
    if buf.len() < n {
        return Err(ZkvmError::Other(format!(
            "proof buf: need {n} bytes, got {}",
            buf.len()
        )));
    }
    Ok((&buf[..n], &buf[n..]))
}

/// 解析 48 字节 G1 compressed → G1Projective。
fn parse_g1(bytes: &[u8]) -> Option<G1Projective> {
    if bytes.len() != G1_COMPRESSED_SIZE {
        return None;
    }
    let mut arr = [0u8; G1_COMPRESSED_SIZE];
    arr.copy_from_slice(bytes);
    let ct = G1Projective::from_compressed(&arr);
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

/// 反序列化 Vec<ElGamalCiphertext>（与 guest 端 Borsh 布局一致）。
fn deserialize_ciphertexts(bytes: &[u8]) -> Result<Vec<ElGamalCiphertext>, ZkvmError> {
    BorshDeserialize::try_from_slice(bytes).map_err(|e| {
        ZkvmError::Other(format!("deserialize Vec<ElGamalCiphertext> failed: {e}"))
    })
}

/// 反序列化 Vec<G1Projective>（明文点列表，Borsh 布局与 guest `Vec<G1Point>` 一致）。
///
/// guest 端 `G1Point([u8; 48])` Borsh 序列化为 48B，与 host 的 `[u8; 48]` 一致；
/// host 端直接 borsh 反序列化 `[u8; 48]` 数组列表再逐个解析为 G1Projective。
fn deserialize_g1_points(bytes: &[u8]) -> Result<Vec<G1Projective>, ZkvmError> {
    let raw: Vec<[u8; G1_COMPRESSED_SIZE]> = BorshDeserialize::try_from_slice(bytes)
        .map_err(|e| ZkvmError::Other(format!("deserialize Vec<G1> failed: {e}")))?;
    raw.into_iter()
        .map(|arr| parse_g1(&arr).ok_or_else(|| ZkvmError::Other("invalid G1 in vec".into())))
        .collect()
}

/// 从 48 字节切片反序列化单个 ElGamalCiphertext（c1 || c2，各 48B）。
fn parse_single_ciphertext(bytes: &[u8]) -> Result<ElGamalCiphertext, ZkvmError> {
    if bytes.len() != CT_SIZE {
        return Err(ZkvmError::Other(format!(
            "single ct size mismatch: {} != {CT_SIZE}",
            bytes.len()
        )));
    }
    let c1 = parse_g1(&bytes[..G1_COMPRESSED_SIZE])
        .ok_or_else(|| ZkvmError::Other("invalid c1 in ciphertext".into()))?;
    let c2 = parse_g1(&bytes[G1_COMPRESSED_SIZE..])
        .ok_or_else(|| ZkvmError::Other("invalid c2 in ciphertext".into()))?;
    Ok(ElGamalCiphertext { c1, c2 })
}

// 写入验证结果（a0 = 0/1）。
fn write_verify_result(state: &mut VmState, ok: bool) {
    state.write_register(REG_A0, if ok { 1 } else { 0 });
}

// ===========================================================================
// 1. Blake2b256 (0x33)
// ===========================================================================

/// `zkvm_blake2b_256(data_ptr, data_len, out_ptr)` — Blake2b-256 变长哈希。
///
/// ABI：
/// - a0 = data_ptr（输入数据地址）
/// - a1 = data_len（输入数据长度）
/// - a2 = out_ptr（32 字节输出地址）
///
/// 与 `dispatch.rs::compute_method_selector` 算法一致：`Blake2bVar::new(32)` + `update` + `finalize_variable`。
#[derive(Debug, Clone, Default)]
pub struct Blake2b256Syscall;

impl Syscall for Blake2b256Syscall {
    fn id(&self) -> SyscallId {
        SyscallId::Blake2b256
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let data_ptr = state.read_register(REG_A0);
        let data_len = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let data = read_vm_bytes(state, data_ptr, data_len)?;
        let mut hasher = Blake2bVar::new(BLAKE2B_256_OUT_SIZE)
            .map_err(|e| ZkvmError::Other(format!("blake2b init failed: {e}")))?;
        hasher.update(&data);
        let mut out = [0u8; BLAKE2B_256_OUT_SIZE];
        hasher
            .finalize_variable(&mut out)
            .map_err(|e| ZkvmError::Other(format!("blake2b finalize failed: {e}")))?;
        write_vm_bytes(state, out_ptr, &out)?;
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::Blake2b256, &args)
    }
}

// ===========================================================================
// 2. VerifyDleqProof (0x34) — DLEq Remask/Leave + ZKShuffle 三合一
// ===========================================================================

/// `zkvm_verify_dleq_proof(kind, buf_ptr, buf_len) -> bool` — DLEq/ZKShuffle proof 验证。
///
/// # kind 值
/// - `0` = remask：`DLEqProof<DefaultCurve, RemaskKind>::verify` + transcript `zk_mask_shuffle_proof_v1`
/// - `1` = leave：`DLEqProof<DefaultCurve, LeaveKind>::verify` + transcript `zk_leave_proof_v1`
/// - `2` = shuffle：`ZKShuffleProof::verify` + transcript `zk_mask_shuffle_proof_v1`
///
/// # buf 格式
/// ```text
/// [proof_len:u32 LE][proof_bytes]
/// [input_cts_len:u32 LE][input_cts_bytes]   // Vec<ElGamalCiphertext> Borsh
/// [output_cts_len:u32 LE][output_cts_bytes] // Vec<ElGamalCiphertext> Borsh
/// [pk:48B]                                   // G1 compressed
/// ```
///
/// # 返回
/// a0 = 1 验证通过 / a0 = 0 验证失败或输入非法（不返回 Err，与 EcdsaVerify 一致）。
#[derive(Debug, Clone, Default)]
pub struct VerifyDleqProofSyscall;

/// Transcript 标签常量。
const TRANSCRIPT_MASK_SHUFFLE: &str = "zk_mask_shuffle_proof_v1";
const TRANSCRIPT_LEAVE: &str = "zk_leave_proof_v1";

impl Syscall for VerifyDleqProofSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::VerifyDleqProof
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let kind = state.read_register(REG_A0);
        let buf_ptr = state.read_register(REG_A1);
        let buf_len = state.read_register(REG_A2);

        let buf = read_vm_bytes(state, buf_ptr, buf_len)?;
        let ok = verify_dleq_proof_inner(kind, &buf).unwrap_or(false);
        write_verify_result(state, ok);
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(REG_A2);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::VerifyDleqProof, &args)
    }
}

/// 内部验证逻辑（返回 Result<bool, ZkvmError>，外层吞掉 Err 转 a0=0）。
fn verify_dleq_proof_inner(kind: u32, buf: &[u8]) -> Result<bool, ZkvmError> {
    // 先校验 kind，避免在非法 kind 时仍解析 buf
    if !matches!(kind, 0..=2) {
        return Err(ZkvmError::Other(format!(
            "verify_dleq_proof: invalid kind {kind} (expected 0/1/2)"
        )));
    }
    // 解析 buf：proof | input_cts | output_cts | pk
    let (proof_bytes, rest) = read_len_prefixed(buf)?;
    let (input_cts_bytes, rest) = read_len_prefixed(rest)?;
    let (output_cts_bytes, rest) = read_len_prefixed(rest)?;
    let (pk_bytes, _) = read_fixed(rest, G1_COMPRESSED_SIZE)?;

    let pk = match parse_g1(pk_bytes) {
        Some(p) => p,
        None => return Ok(false),
    };
    let input_cts = deserialize_ciphertexts(input_cts_bytes)?;
    let output_cts = deserialize_ciphertexts(output_cts_bytes)?;

    match kind {
        0 => {
            // DLEqProof<RemaskKind>
            let proof: DLEqProof<DefaultCurve, RemaskKind> =
                BorshDeserialize::try_from_slice(proof_bytes).map_err(|e| {
                    ZkvmError::Other(format!("deserialize DLEqProof<RemaskKind> failed: {e}"))
                })?;
            let mut t = MerlinTranscript::new(TRANSCRIPT_MASK_SHUFFLE.as_bytes());
            Ok(proof.verify(&input_cts, &output_cts, &pk, &mut t))
        }
        1 => {
            // DLEqProof<LeaveKind>
            let proof: DLEqProof<DefaultCurve, LeaveKind> =
                BorshDeserialize::try_from_slice(proof_bytes).map_err(|e| {
                    ZkvmError::Other(format!("deserialize DLEqProof<LeaveKind> failed: {e}"))
                })?;
            let mut t = MerlinTranscript::new(TRANSCRIPT_LEAVE.as_bytes());
            Ok(proof.verify(&input_cts, &output_cts, &pk, &mut t))
        }
        2 => {
            // ZKShuffleProof
            let proof: ZKShuffleProof<DefaultCurve> =
                BorshDeserialize::try_from_slice(proof_bytes).map_err(|e| {
                    ZkvmError::Other(format!("deserialize ZKShuffleProof failed: {e}"))
                })?;
            let mut t = MerlinTranscript::new(TRANSCRIPT_MASK_SHUFFLE.as_bytes());
            match proof.verify(&input_cts, &output_cts, &pk, &mut t) {
                Ok(()) => Ok(true),
                Err(e) => {
                    tracing::debug!("ZKShuffleProof verify failed: {e:?}");
                    Ok(false)
                }
            }
        }
        // unreachable：前面已校验 kind 范围
        _ => unreachable!(),
    }
}

// ===========================================================================
// 3. VerifyReconstructProof (0x35)
// ===========================================================================

/// `zkvm_verify_reconstruct_proof(buf_ptr, buf_len) -> bool` — Reconstruct proof 验证。
///
/// # buf 格式
/// ```text
/// [proof_len:u32 LE][proof_bytes]
/// [cards_len:u32 LE][cards_bytes]             // Vec<G1Point> Borsh（明文点列表）
/// [output_cts_len:u32 LE][output_cts_bytes]  // Vec<ElGamalCiphertext> Borsh
/// [swap_cts_len:u32 LE][swap_cts_bytes]      // Vec<ElGamalCiphertext> Borsh
/// [readable_cts_len:u32 LE][readable_cts_bytes] // Vec<ElGamalCiphertext> Borsh
/// [user_pk:48B]                               // G1 compressed
/// ```
///
/// # 返回
/// a0 = 1 / a0 = 0。
#[derive(Debug, Clone, Default)]
pub struct VerifyReconstructProofSyscall;

const TRANSCRIPT_RECONSTRUCT: &str = "zk_reconstruct_proof_v1";

impl Syscall for VerifyReconstructProofSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::VerifyReconstructProof
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let buf_ptr = state.read_register(REG_A0);
        let buf_len = state.read_register(REG_A1);

        let buf = read_vm_bytes(state, buf_ptr, buf_len)?;
        let ok = verify_reconstruct_proof_inner(&buf).unwrap_or(false);
        write_verify_result(state, ok);
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::VerifyReconstructProof, &args)
    }
}

fn verify_reconstruct_proof_inner(buf: &[u8]) -> Result<bool, ZkvmError> {
    let (proof_bytes, rest) = read_len_prefixed(buf)?;
    let (cards_bytes, rest) = read_len_prefixed(rest)?;
    let (output_cts_bytes, rest) = read_len_prefixed(rest)?;
    let (swap_cts_bytes, rest) = read_len_prefixed(rest)?;
    let (readable_cts_bytes, rest) = read_len_prefixed(rest)?;
    let (user_pk_bytes, _) = read_fixed(rest, G1_COMPRESSED_SIZE)?;

    let user_pk = match parse_g1(user_pk_bytes) {
        Some(p) => p,
        None => return Ok(false),
    };
    let cards = deserialize_g1_points(cards_bytes)?;
    let output_cts = deserialize_ciphertexts(output_cts_bytes)?;
    let swap_cts = deserialize_ciphertexts(swap_cts_bytes)?;
    let readable_cts = deserialize_ciphertexts(readable_cts_bytes)?;

    let proof: ReconstructProof<DefaultCurve> = BorshDeserialize::try_from_slice(proof_bytes)
        .map_err(|e| ZkvmError::Other(format!("deserialize ReconstructProof failed: {e}")))?;
    let mut t = MerlinTranscript::new(TRANSCRIPT_RECONSTRUCT.as_bytes());
    match proof.verify(
        &cards,
        &output_cts,
        &swap_cts,
        &readable_cts,
        &user_pk,
        &mut t,
    ) {
        Ok(()) => Ok(true),
        Err(e) => {
            tracing::debug!("ReconstructProof verify failed: {e:?}");
            Ok(false)
        }
    }
}

// ===========================================================================
// 4. VerifyRevealTokenProof (0x36)
// ===========================================================================

/// `zkvm_verify_reveal_token_proof(buf_ptr, buf_len) -> bool` — Reveal token proof 验证。
///
/// # buf 格式
/// ```text
/// [proof_len:u32 LE][proof_bytes]
/// [enc_card:96B]      // ElGamalCiphertext (c1||c2 各 48B)
/// [token:48B]         // G1 compressed
/// [expected_pk:48B]   // G1 compressed
/// ```
///
/// # 返回
/// a0 = 1 / a0 = 0。
#[derive(Debug, Clone, Default)]
pub struct VerifyRevealTokenProofSyscall;

const TRANSCRIPT_REVEAL_TOKEN: &str = "reveal_token_proof_v3";

impl Syscall for VerifyRevealTokenProofSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::VerifyRevealTokenProof
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let buf_ptr = state.read_register(REG_A0);
        let buf_len = state.read_register(REG_A1);

        let buf = read_vm_bytes(state, buf_ptr, buf_len)?;
        let ok = verify_reveal_token_proof_inner(&buf).unwrap_or(false);
        write_verify_result(state, ok);
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::VerifyRevealTokenProof, &args)
    }
}

fn verify_reveal_token_proof_inner(buf: &[u8]) -> Result<bool, ZkvmError> {
    let (proof_bytes, rest) = read_len_prefixed(buf)?;
    let (enc_card_bytes, rest) = read_fixed(rest, CT_SIZE)?;
    let (token_bytes, rest) = read_fixed(rest, G1_COMPRESSED_SIZE)?;
    let (expected_pk_bytes, _) = read_fixed(rest, G1_COMPRESSED_SIZE)?;

    let enc_card = parse_single_ciphertext(enc_card_bytes)?;
    let token = match parse_g1(token_bytes) {
        Some(p) => p,
        None => return Ok(false),
    };
    let expected_pk = match parse_g1(expected_pk_bytes) {
        Some(p) => p,
        None => return Ok(false),
    };

    let proof: RevealTokenProof<DefaultCurve> = BorshDeserialize::try_from_slice(proof_bytes)
        .map_err(|e| ZkvmError::Other(format!("deserialize RevealTokenProof failed: {e}")))?;
    let mut t = MerlinTranscript::new(TRANSCRIPT_REVEAL_TOKEN.as_bytes());
    match proof.verify(&enc_card, &token, &expected_pk, &mut t) {
        Ok(()) => Ok(true),
        Err(e) => {
            tracing::debug!("RevealTokenProof verify failed: {e:?}");
            Ok(false)
        }
    }
}

// 静默 unused import 警告：Field/Curve/GroupEncoding 在 parse_g1 中通过 from_compressed 间接使用，
// Scalar 类型在 type alias 上下文中保留以备未来扩展。
#[allow(dead_code)]
fn _unused_imports() {
    let _ = BlsScalar::ZERO;
    let _ = G1Projective::generator();
    let _ = <G1Projective as GroupEncoding>::to_bytes;
    let _ = <G1Projective as Curve>::to_affine;
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Blake2b256 基础测试 =====

    #[test]
    fn test_blake2b256_known_vector() {
        // 空输入 blake2b-256 已知向量
        let mut hasher = Blake2bVar::new(32).unwrap();
        hasher.update(b"");
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).unwrap();
        // blake2b-256("") = 0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
        assert_eq!(out[0], 0x0e);
        assert_eq!(out[1], 0x57);
    }

    #[test]
    fn test_blake2b256_consistency() {
        // 相同输入应产生相同输出
        let mut h1 = Blake2bVar::new(32).unwrap();
        h1.update(b"hello world");
        let mut o1 = [0u8; 32];
        h1.finalize_variable(&mut o1).unwrap();

        let mut h2 = Blake2bVar::new(32).unwrap();
        h2.update(b"hello world");
        let mut o2 = [0u8; 32];
        h2.finalize_variable(&mut o2).unwrap();

        assert_eq!(o1, o2);
    }

    // ===== SyscallId 测试 =====

    #[test]
    fn test_proof_verify_syscall_ids() {
        assert_eq!(Blake2b256Syscall.id(), SyscallId::Blake2b256);
        assert_eq!(VerifyDleqProofSyscall.id(), SyscallId::VerifyDleqProof);
        assert_eq!(
            VerifyReconstructProofSyscall.id(),
            SyscallId::VerifyReconstructProof
        );
        assert_eq!(
            VerifyRevealTokenProofSyscall.id(),
            SyscallId::VerifyRevealTokenProof
        );
    }

    #[test]
    fn test_gas_costs_nonzero() {
        let state = VmState::new();
        let sc = Blake2b256Syscall;
        assert!(sc.gas_cost(&state) > 0);
        let sc = VerifyDleqProofSyscall;
        assert!(sc.gas_cost(&state) > 0);
        let sc = VerifyReconstructProofSyscall;
        assert!(sc.gas_cost(&state) > 0);
        let sc = VerifyRevealTokenProofSyscall;
        assert!(sc.gas_cost(&state) > 0);
    }

    // ===== 缓冲区解析辅助测试 =====

    #[test]
    fn test_read_len_prefixed_valid() {
        let buf = [3u8, 0, 0, 0, b'a', b'b', b'c', b'x'];
        let (slice, rest) = read_len_prefixed(&buf).unwrap();
        assert_eq!(slice, b"abc");
        assert_eq!(rest, &[b'x']);
    }

    #[test]
    fn test_read_len_prefixed_truncated() {
        let buf = [10u8, 0, 0, 0, b'a']; // declared len=10 but only 1 byte
        assert!(read_len_prefixed(&buf).is_err());
    }

    #[test]
    fn test_read_fixed_exact() {
        let buf = [1u8, 2, 3, 4, 5];
        let (slice, rest) = read_fixed(&buf, 3).unwrap();
        assert_eq!(slice, &[1, 2, 3]);
        assert_eq!(rest, &[4, 5]);
    }

    #[test]
    fn test_read_fixed_too_short() {
        let buf = [1u8, 2];
        assert!(read_fixed(&buf, 5).is_err());
    }

    #[test]
    fn test_parse_g1_invalid_bytes() {
        // 全 0x00 不是合法 G1 compressed（infinity 在 BLS12-381 用 0xC0 前缀）
        let zeros = [0u8; 48];
        assert!(parse_g1(&zeros).is_none());
    }

    #[test]
    fn test_parse_g1_generator() {
        let g = G1Projective::generator();
        let bytes = g.to_compressed();
        let parsed = parse_g1(&bytes);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap(), g);
    }

    #[test]
    fn test_deserialize_ciphertexts_roundtrip() {
        // 构造 2 个 ElGamalCiphertext，borsh 序列化后反序列化应一致
        let g = G1Projective::generator();
        let g2 = g + g;
        let cts: Vec<ElGamalCiphertext> = vec![
            ElGamalCiphertext { c1: g, c2: g2 },
            ElGamalCiphertext { c1: g2, c2: g },
        ];
        let bytes = borsh::to_vec(&cts).unwrap();
        let recovered = deserialize_ciphertexts(&bytes).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].c1, g);
        assert_eq!(recovered[0].c2, g2);
    }

    #[test]
    fn test_deserialize_g1_points_roundtrip() {
        let g = G1Projective::generator();
        let g2 = g + g;
        let points: Vec<[u8; 48]> = vec![g.to_compressed(), g2.to_compressed()];
        let bytes = borsh::to_vec(&points).unwrap();
        let recovered = deserialize_g1_points(&bytes).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0], g);
        assert_eq!(recovered[1], g2);
    }

    #[test]
    fn test_verify_dleq_proof_invalid_kind() {
        // kind=99 应返回 Err（外层会转为 a0=0）
        let buf = vec![0u8; 200];
        let result = verify_dleq_proof_inner(99, &buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_dleq_proof_buf_too_short() {
        // buf 过短应返回 Err
        let buf = vec![0u8; 10];
        let result = verify_dleq_proof_inner(0, &buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_reconstruct_proof_buf_too_short() {
        let buf = vec![0u8; 10];
        let result = verify_reconstruct_proof_inner(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_reveal_token_proof_buf_too_short() {
        let buf = vec![0u8; 10];
        let result = verify_reveal_token_proof_inner(&buf);
        assert!(result.is_err());
    }
}
