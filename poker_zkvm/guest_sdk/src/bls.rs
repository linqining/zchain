//! Guest 端 BLS12-381 类型 — 字节数组 newtype，操作经 syscall。

use borsh::{BorshDeserialize, BorshSerialize};

use crate::syscalls;

/// G1 压缩点（48 字节）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct G1Point(pub [u8; 48]);

impl G1Point {
    /// 从字节切片构造。
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 48 { return None; }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(b);
        Some(Self(arr))
    }

    /// 返回字节引用。
    pub fn as_bytes(&self) -> &[u8; 48] { &self.0 }

    /// hash_to_curve（syscall 0x10）。
    pub fn hash_to_curve(msg: &[u8]) -> Self {
        let mut out = [0u8; 48];
        syscalls::bls_hash_to_curve(msg, &mut out);
        Self(out)
    }

    /// 点加（syscall 0x12）。
    pub fn add(&self, other: &Self) -> Self {
        let mut out = [0u8; 48];
        syscalls::bls_g1_add(&self.0, &other.0, &mut out);
        Self(out)
    }

    /// 标量乘（syscall 0x13）。
    pub fn mul(&self, s: &Scalar) -> Self {
        let mut out = [0u8; 48];
        syscalls::bls_g1_mul(&self.0, &s.0, &mut out);
        Self(out)
    }

    /// 字节级相等比较。
    pub fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// 点减（syscall 0x1A）。
    pub fn sub(&self, other: &Self) -> Self {
        let mut out = [0u8; 48];
        syscalls::bls_g1_sub(&self.0, &other.0, &mut out);
        Self(out)
    }

    /// G1 生成元（syscall 0x1B）。
    pub fn generator() -> Self {
        let mut out = [0u8; 48];
        syscalls::bls_g1_generator(&mut out);
        Self(out)
    }

    /// G1 单位元（无穷远点）。
    ///
    /// 通过 `generator() * 0` 获取，确保 compressed 字节编码与 host 一致
    /// （blstrs 的 identity compressed 编码非全零，直接硬编码常量有风险）。
    pub fn identity() -> Self {
        Self::generator().mul(&Scalar::ZERO)
    }

    /// 是否为单位元。
    pub fn is_identity(&self) -> bool {
        self.eq(&Self::identity())
    }
}

/// BLS12-381 标量（32 字节，大端序）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Scalar(pub [u8; 32]);

impl Scalar {
    /// 零标量。
    pub const ZERO: Self = Scalar([0u8; 32]);

    /// 单位标量（1）。
    /// 大端序 32 字节，最低字节为 1，其余为 0。
    pub const ONE: Self = Scalar([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    /// 从字节切片构造。
    pub fn from_bytes_be(b: &[u8]) -> Option<Self> {
        if b.len() != 32 { return None; }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(b);
        Some(Self(arr))
    }

    /// 返回字节引用。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 从 u64 构造标量（大端序，无 syscall）。
    ///
    /// u64 放在 32 字节大端序的低 8 字节。
    pub fn from_u64(x: u64) -> Self {
        let mut arr = [0u8; 32];
        arr[24..32].copy_from_slice(&x.to_be_bytes());
        Self(arr)
    }

    /// 标量加法 a+b mod p（syscall 0x16）。
    pub fn add(&self, other: &Self) -> Self {
        let mut out = [0u8; 32];
        syscalls::bls_scalar_add(&self.0, &other.0, &mut out);
        Self(out)
    }

    /// 标量减法 a-b mod p（syscall 0x17）。
    pub fn sub(&self, other: &Self) -> Self {
        let mut out = [0u8; 32];
        syscalls::bls_scalar_sub(&self.0, &other.0, &mut out);
        Self(out)
    }

    /// 标量乘法 a*b mod p（syscall 0x11，标量×标量）。
    pub fn mul(&self, other: &Self) -> Self {
        let mut out = [0u8; 32];
        syscalls::bls_scalar_mul(&self.0, &other.0, &mut out);
        Self(out)
    }

    /// 标量取负 -a mod p（syscall 0x18）。
    pub fn neg(&self) -> Self {
        let mut out = [0u8; 32];
        syscalls::bls_scalar_neg(&self.0, &mut out);
        Self(out)
    }

    /// 标量求逆 a^(-1) mod p（syscall 0x19）。
    /// a=0 时返回 0（与 utils.rs::scalar_inv 行为一致）。
    pub fn inv(&self) -> Self {
        let mut out = [0u8; 32];
        syscalls::bls_scalar_inv(&self.0, &mut out);
        Self(out)
    }

    /// hash_to_scalar（syscall 0x15，与 utils.rs::hash_to_scalar 一致）。
    pub fn hash_to_scalar(data: &[u8]) -> Self {
        let mut out = [0u8; 32];
        syscalls::bls_hash_to_scalar(data, &mut out);
        Self(out)
    }
}

/// ElGamal 密文 (c1, c2) — 各 48 字节 G1 点。
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ElGamalCiphertext {
    pub c1: G1Point,
    pub c2: G1Point,
}

impl ElGamalCiphertext {
    /// 从字节构造：前 48 字节 c1，后 48 字节 c2。
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 96 { return None; }
        let c1 = G1Point::from_bytes(&b[..48])?;
        let c2 = G1Point::from_bytes(&b[48..])?;
        Some(Self { c1, c2 })
    }

    /// 序列化为 96 字节。
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[..48].copy_from_slice(&self.c1.0);
        out[48..].copy_from_slice(&self.c2.0);
        out
    }
}
