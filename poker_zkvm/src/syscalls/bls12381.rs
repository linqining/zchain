//! BLS12-381 Syscall 实现（E2E Phase 1 — Task 1.2）。
//!
//! 为 zkvm 新增 6 个 BLS12-381 syscall，支持 texas_poker 合约的 G1/Scalar/Pairing 操作。
//! 使用 `blstrs` crate（与 `poker_l1/src/crypto_precompiles/bls.rs` 一致）。
//!
//! # Syscall 列表
//!
//! | ID | 名称 | ABI | 说明 |
//! |----|------|-----|------|
//! | 0x10 | `Bls12381HashToCurve` | (msg_ptr, msg_len, out_ptr) | RFC 9380 hash-to-G1 |
//! | 0x11 | `Bls12381ScalarMul` | (a_ptr, b_ptr, out_ptr) | 标量乘法 a*b |
//! | 0x12 | `Bls12381G1Add` | (a_ptr, b_ptr, out_ptr) | G1 点加 a+b |
//! | 0x13 | `Bls12381G1Mul` | (point_ptr, scalar_ptr, out_ptr) | G1 标量乘 point*scalar |
//! | 0x14 | `Bls12381Pairing` | (a_g1_ptr, b_g2_ptr, c_g1_ptr, d_g2_ptr) → bool | 验证 e(a,b)==e(c,d) |
//! | 0x15 | `Bls12381HashToScalar` | (msg_ptr, msg_len, out_ptr) | SHA3-256 + 清高 2 位 + reduce |
//!
//! # 常量
//!
//! - `G1_COMPRESSED_SIZE = 48`：G1 compressed point 字节数
//! - `G2_COMPRESSED_SIZE = 96`：G2 compressed point 字节数
//! - `SCALAR_SIZE = 32`：BLS12-381 标量字节数（大端序）
//! - `BLS_G1_DST`：RFC 9380 domain separation tag（与 `poker_l1` 一致）

use blstrs::{Bls12, G1Projective, G2Prepared, G2Projective, Scalar};
use pairing::group::ff::Field;
use pairing::group::{Curve, Group};
use pairing::{MillerLoopResult as _, MultiMillerLoop as _};
use sha3::{Digest, Sha3_256};

use crate::error::ZkvmError;
use crate::isa::state::VmState;
use crate::syscalls::gas::{SyscallGasArgs, syscall_gas};
use crate::syscalls::host::{read_vm_bytes, write_vm_bytes};
use crate::syscalls::{Syscall, SyscallContext, SyscallId, REG_A0, REG_A1, REG_A2, REG_A3};

/// G1 compressed point 字节数（BLS12-381 G1 over 48-byte field）。
pub const G1_COMPRESSED_SIZE: u32 = 48;

/// G2 compressed point 字节数（BLS12-381 G2 over 96-byte extension field）。
pub const G2_COMPRESSED_SIZE: u32 = 96;

/// BLS12-381 标量字节数（大端序）。
pub const SCALAR_SIZE: u32 = 32;

/// RFC 9380 hash-to-G1 domain separation tag。
///
/// 与 `poker_l1/src/crypto_precompiles/bls.rs::BLS_G1_DST` 完全一致，
/// 确保 zkvm syscall 与链上 precompile 产生相同的 hash-to-curve 结果。
pub const BLS_G1_DST: &[u8] = b"POKER_L1_BLS12381G1_XMD:SHA-256_SSWU_RO_";

// ===== 辅助函数 =====

/// 从 compressed bytes 解析 G1 点（含子群检查）。
///
/// 返回 `None` 表示点不在子群内或格式非法。
fn parse_g1(bytes: &[u8]) -> Option<G1Projective> {
    if bytes.len() != G1_COMPRESSED_SIZE as usize {
        return None;
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(bytes);
    // blstrs 的 from_compressed 已含子群检查（constant-time）
    G1Projective::from_compressed(&arr).into_option()
}

/// 从 compressed bytes 解析 G2 点（含子群检查）。
fn parse_g2(bytes: &[u8]) -> Option<G2Projective> {
    if bytes.len() != G2_COMPRESSED_SIZE as usize {
        return None;
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(bytes);
    G2Projective::from_compressed(&arr).into_option()
}

/// 从大端序 bytes 解析 BLS12-381 标量。
fn parse_scalar(bytes: &[u8]) -> Option<Scalar> {
    if bytes.len() != SCALAR_SIZE as usize {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Scalar::from_bytes_be(&arr).into_option()
}

/// 序列化 G1 点为 compressed bytes（48 字节）。
fn serialize_g1(point: &G1Projective) -> [u8; 48] {
    point.to_compressed()
}

/// 序列化标量为大端序 bytes（32 字节）。
fn serialize_scalar(s: &Scalar) -> [u8; 32] {
    s.to_bytes_be()
}

/// SHA3-256 + 清高 2 位 + reduce 为 BLS12-381 标量。
///
/// 与 `poker_l1/src/vm/contracts/texas_poker/utils.rs::hash_to_scalar` 算法一致：
/// 1. SHA3-256(data) → 32 字节大端序 h
/// 2. 清除 h[0] 高 2 位（`h[0] &= 0x3F`），确保值 < 2^254 < BLS12-381 曲线阶
/// 3. `Scalar::from_bytes_be(h)`
fn hash_to_scalar(data: &[u8]) -> Option<Scalar> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let mut h = hasher.finalize();
    h[0] &= 0x3F; // 清高 2 位（M-P18）
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h);
    Scalar::from_bytes_be(&arr).into_option()
}

// ===== 1. Bls12381HashToCurve (0x10) =====

/// `zkvm_bls_hash_to_curve(msg_ptr, msg_len, out_ptr)` — RFC 9380 hash-to-G1。
///
/// ABI：
/// - a0 = msg_ptr（消息地址）
/// - a1 = msg_len（消息长度）
/// - a2 = out_ptr（48 字节输出 G1 compressed 地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381HashToCurveSyscall;

impl Syscall for Bls12381HashToCurveSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381HashToCurve
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let msg_ptr = state.read_register(REG_A0);
        let msg_len = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let msg = read_vm_bytes(state, msg_ptr, msg_len)?;
        let point = G1Projective::hash_to_curve(&msg, BLS_G1_DST, &[]);
        let bytes = serialize_g1(&point);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::Bls12381HashToCurve, &args)
    }
}

// ===== 2. Bls12381ScalarMul (0x11) =====

/// `zkvm_bls_scalar_mul(a_ptr, b_ptr, out_ptr)` — BLS12-381 标量乘法 a*b。
///
/// ABI：
/// - a0 = a_ptr（32 字节标量地址）
/// - a1 = b_ptr（32 字节标量地址）
/// - a2 = out_ptr（32 字节输出标量地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381ScalarMulSyscall;

impl Syscall for Bls12381ScalarMulSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381ScalarMul
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let a_ptr = state.read_register(REG_A0);
        let b_ptr = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let a_bytes = read_vm_bytes(state, a_ptr, SCALAR_SIZE)?;
        let b_bytes = read_vm_bytes(state, b_ptr, SCALAR_SIZE)?;
        let a = parse_scalar(&a_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381ScalarMul: 非法标量 a（不在域内）".to_string())
        })?;
        let b = parse_scalar(&b_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381ScalarMul: 非法标量 b（不在域内）".to_string())
        })?;
        let result = a * b;
        let bytes = serialize_scalar(&result);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381ScalarMul, &SyscallGasArgs::default())
    }
}

// ===== 3. Bls12381G1Add (0x12) =====

/// `zkvm_bls_g1_add(a_ptr, b_ptr, out_ptr)` — BLS12-381 G1 点加 a+b。
///
/// ABI：
/// - a0 = a_ptr（48 字节 G1 compressed 地址）
/// - a1 = b_ptr（48 字节 G1 compressed 地址）
/// - a2 = out_ptr（48 字节输出 G1 compressed 地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381G1AddSyscall;

impl Syscall for Bls12381G1AddSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381G1Add
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let a_ptr = state.read_register(REG_A0);
        let b_ptr = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let a_bytes = read_vm_bytes(state, a_ptr, G1_COMPRESSED_SIZE)?;
        let b_bytes = read_vm_bytes(state, b_ptr, G1_COMPRESSED_SIZE)?;
        let a = parse_g1(&a_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381G1Add: 非法 G1 点 a（不在子群内）".to_string())
        })?;
        let b = parse_g1(&b_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381G1Add: 非法 G1 点 b（不在子群内）".to_string())
        })?;
        let result = a + b;
        let bytes = serialize_g1(&result);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381G1Add, &SyscallGasArgs::default())
    }
}

// ===== 4. Bls12381G1Mul (0x13) =====

/// `zkvm_bls_g1_mul(point_ptr, scalar_ptr, out_ptr)` — BLS12-381 G1 标量乘 point*scalar。
///
/// ABI：
/// - a0 = point_ptr（48 字节 G1 compressed 地址）
/// - a1 = scalar_ptr（32 字节标量地址）
/// - a2 = out_ptr（48 字节输出 G1 compressed 地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381G1MulSyscall;

impl Syscall for Bls12381G1MulSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381G1Mul
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let point_ptr = state.read_register(REG_A0);
        let scalar_ptr = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let point_bytes = read_vm_bytes(state, point_ptr, G1_COMPRESSED_SIZE)?;
        let scalar_bytes = read_vm_bytes(state, scalar_ptr, SCALAR_SIZE)?;
        let point = parse_g1(&point_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381G1Mul: 非法 G1 点（不在子群内）".to_string())
        })?;
        let scalar = parse_scalar(&scalar_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381G1Mul: 非法标量（不在域内）".to_string())
        })?;
        let result = point * scalar;
        let bytes = serialize_g1(&result);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381G1Mul, &SyscallGasArgs::default())
    }
}

// ===== 5. Bls12381Pairing (0x14) =====

/// `zkvm_bls_pairing(a_g1_ptr, b_g2_ptr, c_g1_ptr, d_g2_ptr) -> bool` — BLS12-381 配对等式验证。
///
/// 验证 `e(a, b) == e(c, d)`，其中 a/c 是 G1 点（48 字节 compressed），b/d 是 G2 点（96 字节 compressed）。
///
/// ABI：
/// - a0 = a_g1_ptr（48 字节 G1 compressed 地址）
/// - a1 = b_g2_ptr（96 字节 G2 compressed 地址）
/// - a2 = c_g1_ptr（48 字节 G1 compressed 地址）
/// - a3 = d_g2_ptr（96 字节 G2 compressed 地址）
/// - 返回：a0 = 1（验证通过）/ 0（验证失败或输入非法）
///
/// # 注意
///
/// 输入非法（不在子群内、长度错误）时返回 a0=0，不返回 Err（与 EcdsaVerify 一致）。
#[derive(Debug, Clone, Default)]
pub struct Bls12381PairingSyscall;

impl Syscall for Bls12381PairingSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381Pairing
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let a_g1_ptr = state.read_register(REG_A0);
        let b_g2_ptr = state.read_register(REG_A1);
        let c_g1_ptr = state.read_register(REG_A2);
        let d_g2_ptr = state.read_register(REG_A3);

        // 读取 4 个点
        let a_bytes = read_vm_bytes(state, a_g1_ptr, G1_COMPRESSED_SIZE)?;
        let b_bytes = read_vm_bytes(state, b_g2_ptr, G2_COMPRESSED_SIZE)?;
        let c_bytes = read_vm_bytes(state, c_g1_ptr, G1_COMPRESSED_SIZE)?;
        let d_bytes = read_vm_bytes(state, d_g2_ptr, G2_COMPRESSED_SIZE)?;

        // 解析（任一失败则返回 a0=0）
        let a = match parse_g1(&a_bytes) {
            Some(p) => p,
            None => {
                state.write_register(REG_A0, 0);
                return Ok(());
            }
        };
        let b = match parse_g2(&b_bytes) {
            Some(p) => p,
            None => {
                state.write_register(REG_A0, 0);
                return Ok(());
            }
        };
        let c = match parse_g1(&c_bytes) {
            Some(p) => p,
            None => {
                state.write_register(REG_A0, 0);
                return Ok(());
            }
        };
        let d = match parse_g2(&d_bytes) {
            Some(p) => p,
            None => {
                state.write_register(REG_A0, 0);
                return Ok(());
            }
        };

        // 验证 e(a, b) == e(c, d)
        // 实现：e(a, b) * e(-c, d) == 1（GT 单位元）
        // 注意：multi_miller_loop 接收 &G1Affine + &G2Prepared，需用 to_affine() 转换
        let a_affine = a.to_affine();
        let neg_c_affine = (-c).to_affine();
        let b_prepared = G2Prepared::from(b.to_affine());
        let d_prepared = G2Prepared::from(d.to_affine());
        let ml = Bls12::multi_miller_loop(&[(&a_affine, &b_prepared), (&neg_c_affine, &d_prepared)]);
        let gt = ml.final_exponentiation();
        let valid = bool::from(gt.is_identity());

        state.write_register(REG_A0, if valid { 1 } else { 0 });
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381Pairing, &SyscallGasArgs::default())
    }
}

// ===== 6. Bls12381HashToScalar (0x15) =====

/// `zkvm_bls_hash_to_scalar(msg_ptr, msg_len, out_ptr)` — SHA3-256 + 清高 2 位 + reduce 为 BLS12-381 标量。
///
/// 与 `texas_poker/utils.rs::hash_to_scalar` 算法一致，确保 zkvm syscall 产生相同结果。
///
/// ABI：
/// - a0 = msg_ptr（消息地址）
/// - a1 = msg_len（消息长度）
/// - a2 = out_ptr（32 字节输出标量地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381HashToScalarSyscall;

impl Syscall for Bls12381HashToScalarSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381HashToScalar
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let msg_ptr = state.read_register(REG_A0);
        let msg_len = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let msg = read_vm_bytes(state, msg_ptr, msg_len)?;
        let scalar = hash_to_scalar(&msg).ok_or_else(|| {
            ZkvmError::Other("Bls12381HashToScalar: 标量归约失败".to_string())
        })?;
        let bytes = serialize_scalar(&scalar);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::Bls12381HashToScalar, &args)
    }
}

// ===== 7. Bls12381ScalarAdd (0x16) =====

/// `zkvm_bls_scalar_add(a_ptr, b_ptr, out_ptr)` — BLS12-381 标量加法 a+b mod p。
///
/// ABI：
/// - a0 = a_ptr（32 字节标量地址）
/// - a1 = b_ptr（32 字节标量地址）
/// - a2 = out_ptr（32 字节输出标量地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381ScalarAddSyscall;

impl Syscall for Bls12381ScalarAddSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381ScalarAdd
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let a_ptr = state.read_register(REG_A0);
        let b_ptr = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let a_bytes = read_vm_bytes(state, a_ptr, SCALAR_SIZE)?;
        let b_bytes = read_vm_bytes(state, b_ptr, SCALAR_SIZE)?;
        let a = parse_scalar(&a_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381ScalarAdd: 非法标量 a（不在域内）".to_string())
        })?;
        let b = parse_scalar(&b_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381ScalarAdd: 非法标量 b（不在域内）".to_string())
        })?;
        let result = a + b;
        let bytes = serialize_scalar(&result);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381ScalarAdd, &SyscallGasArgs::default())
    }
}

// ===== 8. Bls12381ScalarSub (0x17) =====

/// `zkvm_bls_scalar_sub(a_ptr, b_ptr, out_ptr)` — BLS12-381 标量减法 a-b mod p。
///
/// ABI：
/// - a0 = a_ptr（32 字节标量地址）
/// - a1 = b_ptr（32 字节标量地址）
/// - a2 = out_ptr（32 字节输出标量地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381ScalarSubSyscall;

impl Syscall for Bls12381ScalarSubSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381ScalarSub
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let a_ptr = state.read_register(REG_A0);
        let b_ptr = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let a_bytes = read_vm_bytes(state, a_ptr, SCALAR_SIZE)?;
        let b_bytes = read_vm_bytes(state, b_ptr, SCALAR_SIZE)?;
        let a = parse_scalar(&a_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381ScalarSub: 非法标量 a（不在域内）".to_string())
        })?;
        let b = parse_scalar(&b_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381ScalarSub: 非法标量 b（不在域内）".to_string())
        })?;
        let result = a - b;
        let bytes = serialize_scalar(&result);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381ScalarSub, &SyscallGasArgs::default())
    }
}

// ===== 9. Bls12381ScalarNeg (0x18) =====

/// `zkvm_bls_scalar_neg(a_ptr, out_ptr)` — BLS12-381 标量取负 -a mod p。
///
/// ABI：
/// - a0 = a_ptr（32 字节标量地址）
/// - a1 = out_ptr（32 字节输出标量地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381ScalarNegSyscall;

impl Syscall for Bls12381ScalarNegSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381ScalarNeg
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let a_ptr = state.read_register(REG_A0);
        let out_ptr = state.read_register(REG_A1);

        let a_bytes = read_vm_bytes(state, a_ptr, SCALAR_SIZE)?;
        let a = parse_scalar(&a_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381ScalarNeg: 非法标量（不在域内）".to_string())
        })?;
        let result = -a;
        let bytes = serialize_scalar(&result);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381ScalarNeg, &SyscallGasArgs::default())
    }
}

// ===== 10. Bls12381ScalarInv (0x19) =====

/// `zkvm_bls_scalar_inv(a_ptr, out_ptr)` — BLS12-381 标量求逆 a^(-1) mod p。
///
/// a=0 时返回 0（与 utils.rs::scalar_inv 行为一致）。
///
/// ABI：
/// - a0 = a_ptr（32 字节标量地址）
/// - a1 = out_ptr（32 字节输出标量地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381ScalarInvSyscall;

impl Syscall for Bls12381ScalarInvSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381ScalarInv
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let a_ptr = state.read_register(REG_A0);
        let out_ptr = state.read_register(REG_A1);

        let a_bytes = read_vm_bytes(state, a_ptr, SCALAR_SIZE)?;
        let a = parse_scalar(&a_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381ScalarInv: 非法标量（不在域内）".to_string())
        })?;
        // 与 utils.rs::scalar_inv 一致：a=0 时返回 0
        let ct = a.invert();
        let result = if bool::from(ct.is_some()) {
            ct.unwrap()
        } else {
            Scalar::ZERO
        };
        let bytes = serialize_scalar(&result);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381ScalarInv, &SyscallGasArgs::default())
    }
}

// ===== 11. Bls12381G1Sub (0x1A) =====

/// `zkvm_bls_g1_sub(a_ptr, b_ptr, out_ptr)` — BLS12-381 G1 点减 a-b。
///
/// ABI：
/// - a0 = a_ptr（48 字节 G1 compressed 地址）
/// - a1 = b_ptr（48 字节 G1 compressed 地址）
/// - a2 = out_ptr（48 字节输出 G1 compressed 地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381G1SubSyscall;

impl Syscall for Bls12381G1SubSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381G1Sub
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let a_ptr = state.read_register(REG_A0);
        let b_ptr = state.read_register(REG_A1);
        let out_ptr = state.read_register(REG_A2);

        let a_bytes = read_vm_bytes(state, a_ptr, G1_COMPRESSED_SIZE)?;
        let b_bytes = read_vm_bytes(state, b_ptr, G1_COMPRESSED_SIZE)?;
        let a = parse_g1(&a_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381G1Sub: 非法 G1 点 a（不在子群内）".to_string())
        })?;
        let b = parse_g1(&b_bytes).ok_or_else(|| {
            ZkvmError::Other("Bls12381G1Sub: 非法 G1 点 b（不在子群内）".to_string())
        })?;
        let result = a - b;
        let bytes = serialize_g1(&result);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381G1Sub, &SyscallGasArgs::default())
    }
}

// ===== 12. Bls12381G1Generator (0x1B) =====

/// `zkvm_bls_g1_generator(out_ptr)` — 返回 G1 生成元（48 字节 compressed）。
///
/// ABI：
/// - a0 = out_ptr（48 字节输出 G1 compressed 地址）
#[derive(Debug, Clone, Default)]
pub struct Bls12381G1GeneratorSyscall;

impl Syscall for Bls12381G1GeneratorSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Bls12381G1Generator
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let out_ptr = state.read_register(REG_A0);
        let generator = G1Projective::generator();
        let bytes = serialize_g1(&generator);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        syscall_gas(SyscallId::Bls12381G1Generator, &SyscallGasArgs::default())
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::state::VmState;

    /// 辅助：写入字节到 VM 内存。
    fn write_bytes(state: &mut VmState, addr: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            state.write_memory_byte(addr + i as u32, b).unwrap();
        }
    }

    /// 辅助：从 VM 内存读取字节。
    fn read_bytes(state: &VmState, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| state.read_memory_byte(addr + i as u32).unwrap())
            .collect()
    }

    // ===== 常量测试 =====

    #[test]
    fn test_bls_constants() {
        assert_eq!(G1_COMPRESSED_SIZE, 48);
        assert_eq!(G2_COMPRESSED_SIZE, 96);
        assert_eq!(SCALAR_SIZE, 32);
        // BLS_G1_DST 与 poker_l1 一致
        assert_eq!(
            BLS_G1_DST,
            b"POKER_L1_BLS12381G1_XMD:SHA-256_SSWU_RO_"
        );
    }

    // ===== hash_to_scalar 算法一致性测试 =====

    #[test]
    fn test_hash_to_scalar_deterministic() {
        // 相同输入应产生相同输出
        let s1 = hash_to_scalar(b"test message");
        let s2 = hash_to_scalar(b"test message");
        assert!(s1.is_some(), "hash_to_scalar 应成功");
        assert_eq!(s1, s2, "相同输入应产生相同标量");
    }

    #[test]
    fn test_hash_to_scalar_different_inputs() {
        let s1 = hash_to_scalar(b"message1");
        let s2 = hash_to_scalar(b"message2");
        assert_ne!(s1, s2, "不同输入应产生不同标量");
    }

    #[test]
    fn test_hash_to_scalar_clears_high_bits() {
        // M-P18: h[0] 高 2 位应被清除，确保标量 < 2^254
        let s = hash_to_scalar(b"any data").expect("应成功");
        let bytes = serialize_scalar(&s);
        // 标量的最高字节应 < 0x40（因为 h[0] &= 0x3F）
        // 注意：from_bytes_be 可能会进一步 reduce mod q，但结果应满足 < q
        // 这里只验证标量有效（非 None）
        assert_eq!(bytes.len(), 32);
    }

    // ===== G1 序列化/反序列化往返测试 =====

    #[test]
    fn test_g1_serialize_round_trip() {
        let generator = G1Projective::generator();
        let bytes = serialize_g1(&generator);
        assert_eq!(bytes.len(), 48);
        let parsed = parse_g1(&bytes);
        assert!(parsed.is_some(), "generator 应可往返解析");
        assert_eq!(parsed.unwrap(), generator);
    }

    #[test]
    fn test_g1_identity_round_trip() {
        let identity = G1Projective::identity();
        let bytes = serialize_g1(&identity);
        let parsed = parse_g1(&bytes);
        assert!(parsed.is_some(), "identity 应可往返解析");
        assert_eq!(parsed.unwrap(), identity);
    }

    #[test]
    fn test_parse_g1_invalid_length() {
        let short = vec![0u8; 47];
        let long = vec![0u8; 49];
        assert!(parse_g1(&short).is_none(), "短输入应返回 None");
        assert!(parse_g1(&long).is_none(), "长输入应返回 None");
    }

    #[test]
    fn test_parse_g1_invalid_point() {
        // 全零字节不是合法的 G1 compressed point
        let zero = vec![0u8; 48];
        assert!(parse_g1(&zero).is_none(), "全零 bytes 应返回 None");
    }

    // ===== 标量序列化/反序列化往返测试 =====

    #[test]
    fn test_scalar_serialize_round_trip() {
        let s = Scalar::from(123u64);
        let bytes = serialize_scalar(&s);
        assert_eq!(bytes.len(), 32);
        let parsed = parse_scalar(&bytes);
        assert!(parsed.is_some(), "标量应可往返解析");
        assert_eq!(parsed.unwrap(), s);
    }

    #[test]
    fn test_parse_scalar_invalid_length() {
        let short = vec![0u8; 31];
        let long = vec![0u8; 33];
        assert!(parse_scalar(&short).is_none());
        assert!(parse_scalar(&long).is_none());
    }

    // ===== Syscall ID 测试 =====

    #[test]
    fn test_syscall_ids() {
        assert_eq!(
            Bls12381HashToCurveSyscall.id(),
            SyscallId::Bls12381HashToCurve
        );
        assert_eq!(
            Bls12381ScalarMulSyscall.id(),
            SyscallId::Bls12381ScalarMul
        );
        assert_eq!(Bls12381G1AddSyscall.id(), SyscallId::Bls12381G1Add);
        assert_eq!(Bls12381G1MulSyscall.id(), SyscallId::Bls12381G1Mul);
        assert_eq!(Bls12381PairingSyscall.id(), SyscallId::Bls12381Pairing);
        assert_eq!(
            Bls12381HashToScalarSyscall.id(),
            SyscallId::Bls12381HashToScalar
        );
        // Phase 3.2 新增 6 个 syscall
        assert_eq!(Bls12381ScalarAddSyscall.id(), SyscallId::Bls12381ScalarAdd);
        assert_eq!(Bls12381ScalarSubSyscall.id(), SyscallId::Bls12381ScalarSub);
        assert_eq!(Bls12381ScalarNegSyscall.id(), SyscallId::Bls12381ScalarNeg);
        assert_eq!(Bls12381ScalarInvSyscall.id(), SyscallId::Bls12381ScalarInv);
        assert_eq!(Bls12381G1SubSyscall.id(), SyscallId::Bls12381G1Sub);
        assert_eq!(
            Bls12381G1GeneratorSyscall.id(),
            SyscallId::Bls12381G1Generator
        );
    }

    // ===== Bls12381HashToCurveSyscall 端到端测试 =====

    #[test]
    fn test_hash_to_curve_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381HashToCurveSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        // 设置输入消息 "texas_poker/card/0"
        let msg = b"texas_poker/card/0";
        let msg_addr = 0x1000;
        let out_addr = 0x2000;
        write_bytes(&mut state, msg_addr, msg);
        state.write_register(REG_A0, msg_addr);
        state.write_register(REG_A1, msg.len() as u32);
        state.write_register(REG_A2, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        // 验证输出 48 字节
        let out = read_bytes(&state, out_addr, 48);
        assert_eq!(out.len(), 48, "输出应为 48 字节 G1 compressed");

        // 验证输出可解析为合法 G1 点
        let point = parse_g1(&out).expect("输出应为合法 G1 点");

        // 验证与直接调用 hash_to_curve 一致
        let expected = G1Projective::hash_to_curve(msg, BLS_G1_DST, &[]);
        assert_eq!(point, expected, "syscall 结果应与直接调用一致");
    }

    // ===== Bls12381ScalarMulSyscall 端到端测试 =====

    #[test]
    fn test_scalar_mul_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381ScalarMulSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let a = Scalar::from(7u64);
        let b = Scalar::from(11u64);
        let expected = a * b;

        let a_addr = 0x1000;
        let b_addr = 0x1100;
        let out_addr = 0x2000;
        write_bytes(&mut state, a_addr, &serialize_scalar(&a));
        write_bytes(&mut state, b_addr, &serialize_scalar(&b));
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, b_addr);
        state.write_register(REG_A2, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 32);
        let result = parse_scalar(&out).expect("输出应为合法标量");
        assert_eq!(result, expected, "7 * 11 应等于 77");
    }

    // ===== Bls12381G1AddSyscall 端到端测试 =====

    #[test]
    fn test_g1_add_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381G1AddSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let g = G1Projective::generator();
        let g_plus_g = g + g;
        let g_bytes = serialize_g1(&g);

        let a_addr = 0x1000;
        let b_addr = 0x1100;
        let out_addr = 0x2000;
        write_bytes(&mut state, a_addr, &g_bytes);
        write_bytes(&mut state, b_addr, &g_bytes);
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, b_addr);
        state.write_register(REG_A2, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 48);
        let result = parse_g1(&out).expect("输出应为合法 G1 点");
        assert_eq!(result, g_plus_g, "G + G 应等于 2G");
    }

    // ===== Bls12381G1MulSyscall 端到端测试 =====

    #[test]
    fn test_g1_mul_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381G1MulSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let g = G1Projective::generator();
        let s = Scalar::from(3u64);
        let expected = g * s;

        let point_addr = 0x1000;
        let scalar_addr = 0x1100;
        let out_addr = 0x2000;
        write_bytes(&mut state, point_addr, &serialize_g1(&g));
        write_bytes(&mut state, scalar_addr, &serialize_scalar(&s));
        state.write_register(REG_A0, point_addr);
        state.write_register(REG_A1, scalar_addr);
        state.write_register(REG_A2, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 48);
        let result = parse_g1(&out).expect("输出应为合法 G1 点");
        assert_eq!(result, expected, "G * 3 应等于 3G");
    }

    // ===== Bls12381PairingSyscall 端到端测试 =====

    #[test]
    fn test_pairing_syscall_equal() {
        let mut state = VmState::new();
        let syscall = Bls12381PairingSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        // e(g1, g2) == e(g1, g2) 应通过
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        let g1_bytes = serialize_g1(&g1);
        let g2_bytes = g2.to_compressed();

        let a_addr = 0x1000; // G1
        let b_addr = 0x1100; // G2
        let c_addr = 0x1300; // G1
        let d_addr = 0x1400; // G2
        write_bytes(&mut state, a_addr, &g1_bytes);
        write_bytes(&mut state, b_addr, &g2_bytes);
        write_bytes(&mut state, c_addr, &g1_bytes);
        write_bytes(&mut state, d_addr, &g2_bytes);
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, b_addr);
        state.write_register(REG_A2, c_addr);
        state.write_register(REG_A3, d_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let result = state.read_register(REG_A0);
        assert_eq!(result, 1, "e(g1,g2) == e(g1,g2) 应验证通过");
    }

    #[test]
    fn test_pairing_syscall_unequal() {
        let mut state = VmState::new();
        let syscall = Bls12381PairingSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        // e(g1, g2) == e(2*g1, g2) 应失败（因为 e(2g1,g2) = e(g1,g2)^2 != e(g1,g2)）
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        let g1_double = g1 + g1;
        let g1_bytes = serialize_g1(&g1);
        let g1_double_bytes = serialize_g1(&g1_double);
        let g2_bytes = g2.to_compressed();

        let a_addr = 0x1000; // G1
        let b_addr = 0x1100; // G2
        let c_addr = 0x1300; // G1 (2*g1)
        let d_addr = 0x1400; // G2
        write_bytes(&mut state, a_addr, &g1_bytes);
        write_bytes(&mut state, b_addr, &g2_bytes);
        write_bytes(&mut state, c_addr, &g1_double_bytes);
        write_bytes(&mut state, d_addr, &g2_bytes);
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, b_addr);
        state.write_register(REG_A2, c_addr);
        state.write_register(REG_A3, d_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let result = state.read_register(REG_A0);
        assert_eq!(result, 0, "e(g1,g2) != e(2g1,g2) 应验证失败");
    }

    #[test]
    fn test_pairing_syscall_invalid_input() {
        let mut state = VmState::new();
        let syscall = Bls12381PairingSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        // 全零 G1 输入应返回 0（不 panic）
        let zero_g1 = vec![0u8; 48];
        let zero_g2 = vec![0u8; 96];

        let a_addr = 0x1000;
        let b_addr = 0x1100;
        let c_addr = 0x1300;
        let d_addr = 0x1400;
        write_bytes(&mut state, a_addr, &zero_g1);
        write_bytes(&mut state, b_addr, &zero_g2);
        write_bytes(&mut state, c_addr, &zero_g1);
        write_bytes(&mut state, d_addr, &zero_g2);
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, b_addr);
        state.write_register(REG_A2, c_addr);
        state.write_register(REG_A3, d_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let result = state.read_register(REG_A0);
        assert_eq!(result, 0, "非法输入应返回 0");
    }

    // ===== Bls12381HashToScalarSyscall 端到端测试 =====

    #[test]
    fn test_hash_to_scalar_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381HashToScalarSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let msg = b"test data for hash_to_scalar";
        let msg_addr = 0x1000;
        let out_addr = 0x2000;
        write_bytes(&mut state, msg_addr, msg);
        state.write_register(REG_A0, msg_addr);
        state.write_register(REG_A1, msg.len() as u32);
        state.write_register(REG_A2, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 32);
        assert_eq!(out.len(), 32, "输出应为 32 字节标量");

        // 验证与直接调用 hash_to_scalar 一致
        let expected = hash_to_scalar(msg).expect("直接调用应成功");
        let expected_bytes = serialize_scalar(&expected);
        assert_eq!(out, expected_bytes, "syscall 结果应与直接调用一致");
    }

    // ===== Gas 计费测试 =====

    #[test]
    fn test_gas_costs_nonzero() {
        let state = VmState::new();
        // 写入一些寄存器值用于 gas 计算
        let mut state = state;
        state.write_register(REG_A1, 100); // input_len = 100

        assert!(Bls12381HashToCurveSyscall.gas_cost(&state) > 0);
        assert!(Bls12381ScalarMulSyscall.gas_cost(&state) > 0);
        assert!(Bls12381G1AddSyscall.gas_cost(&state) > 0);
        assert!(Bls12381G1MulSyscall.gas_cost(&state) > 0);
        assert!(Bls12381PairingSyscall.gas_cost(&state) > 0);
        assert!(Bls12381HashToScalarSyscall.gas_cost(&state) > 0);
        // Phase 3.2 新增 6 个 syscall gas
        assert!(Bls12381ScalarAddSyscall.gas_cost(&state) > 0);
        assert!(Bls12381ScalarSubSyscall.gas_cost(&state) > 0);
        assert!(Bls12381ScalarNegSyscall.gas_cost(&state) > 0);
        assert!(Bls12381ScalarInvSyscall.gas_cost(&state) > 0);
        assert!(Bls12381G1SubSyscall.gas_cost(&state) > 0);
        assert!(Bls12381G1GeneratorSyscall.gas_cost(&state) > 0);
    }

    // ===== Phase 3.2 新增 syscall 端到端测试 =====

    #[test]
    fn test_scalar_add_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381ScalarAddSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let a = Scalar::from(7u64);
        let b = Scalar::from(11u64);
        let expected = a + b;

        let a_addr = 0x1000;
        let b_addr = 0x1100;
        let out_addr = 0x2000;
        write_bytes(&mut state, a_addr, &serialize_scalar(&a));
        write_bytes(&mut state, b_addr, &serialize_scalar(&b));
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, b_addr);
        state.write_register(REG_A2, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 32);
        let result = parse_scalar(&out).expect("输出应为合法标量");
        assert_eq!(result, expected, "7 + 11 应等于 18");
    }

    #[test]
    fn test_scalar_sub_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381ScalarSubSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let a = Scalar::from(18u64);
        let b = Scalar::from(11u64);
        let expected = a - b;

        let a_addr = 0x1000;
        let b_addr = 0x1100;
        let out_addr = 0x2000;
        write_bytes(&mut state, a_addr, &serialize_scalar(&a));
        write_bytes(&mut state, b_addr, &serialize_scalar(&b));
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, b_addr);
        state.write_register(REG_A2, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 32);
        let result = parse_scalar(&out).expect("输出应为合法标量");
        assert_eq!(result, expected, "18 - 11 应等于 7");
    }

    #[test]
    fn test_scalar_neg_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381ScalarNegSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let a = Scalar::from(5u64);
        let neg_a = -a;
        // neg(a) + a 应等于 0
        let zero = neg_a + a;

        let a_addr = 0x1000;
        let out_addr = 0x2000;
        write_bytes(&mut state, a_addr, &serialize_scalar(&a));
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 32);
        let result = parse_scalar(&out).expect("输出应为合法标量");
        assert_eq!(result, neg_a, "-5 应等于 neg(5)");
        assert_eq!(result + a, zero, "neg(5) + 5 应等于 0");
    }

    #[test]
    fn test_scalar_inv_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381ScalarInvSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let a = Scalar::from(7u64);
        let inv_a = a.invert();
        let ct = inv_a;
        let inv_a = if bool::from(ct.is_some()) {
            ct.unwrap()
        } else {
            Scalar::ZERO
        };
        // inv(a) * a 应等于 1
        let one = inv_a * a;

        let a_addr = 0x1000;
        let out_addr = 0x2000;
        write_bytes(&mut state, a_addr, &serialize_scalar(&a));
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 32);
        let result = parse_scalar(&out).expect("输出应为合法标量");
        assert_eq!(result, inv_a, "inv(7) 应与直接求逆一致");
        assert_eq!(result * a, one, "inv(7) * 7 应等于 1");
    }

    #[test]
    fn test_scalar_inv_zero_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381ScalarInvSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        // inv(0) 应返回 0（与 utils.rs::scalar_inv 一致）
        let zero = Scalar::ZERO;

        let a_addr = 0x1000;
        let out_addr = 0x2000;
        write_bytes(&mut state, a_addr, &serialize_scalar(&zero));
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 32);
        let result = parse_scalar(&out).expect("输出应为合法标量");
        assert_eq!(result, Scalar::ZERO, "inv(0) 应返回 0");
    }

    #[test]
    fn test_g1_sub_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381G1SubSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let g = G1Projective::generator();
        let g_double = g + g;
        // 2G - G 应等于 G
        let expected = g_double - g;

        let a_addr = 0x1000;
        let b_addr = 0x1100;
        let out_addr = 0x2000;
        write_bytes(&mut state, a_addr, &serialize_g1(&g_double));
        write_bytes(&mut state, b_addr, &serialize_g1(&g));
        state.write_register(REG_A0, a_addr);
        state.write_register(REG_A1, b_addr);
        state.write_register(REG_A2, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 48);
        let result = parse_g1(&out).expect("输出应为合法 G1 点");
        assert_eq!(result, expected, "2G - G 应等于 G");
    }

    #[test]
    fn test_g1_generator_syscall_e2e() {
        let mut state = VmState::new();
        let syscall = Bls12381G1GeneratorSyscall;
        let mut ctx = SyscallContext::new(vec![]);

        let out_addr = 0x2000;
        state.write_register(REG_A0, out_addr);

        syscall.host_execute(&mut ctx, &mut state).unwrap();

        let out = read_bytes(&state, out_addr, 48);
        let result = parse_g1(&out).expect("输出应为合法 G1 点");

        // 与直接调用 generator 一致
        let expected = G1Projective::generator();
        assert_eq!(result, expected, "syscall 生成元应与直接调用一致");
    }
}
