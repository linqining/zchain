//! Poseidon252 域工具：字节↔felt 的**无损**规范编码、域分隔标签、u64 编码。
//!
//! 编码纪律（ABI v1，见 poker-appchain/docs/ABI.md）：
//! - 任意 32 字节 → 域输入一律走 [`bytes32_to_felts`]：**拆 hi/lo 两个
//!   16 字节 felt**（各 < 2^128 ≪ p），完全无损、确定性。
//! - felt → 32 字节走 [`felt_to_bytes32`]（裸 `to_bytes_be`，对域元素
//!   恒无损）；反向 [`felt_from_bytes32_exact`] 只接受确实是域元素的
//!   字节（≥ p 拒绝，fail-closed）。
//! - 域分隔标签 [`domain_felt`]：blake2s(domain) 拆 hi/lo 后 Poseidon 折叠
//!   （独立于 P 层 keccak 命名空间）。
//! - 多元素哈希统一 `starknet_crypto::poseidon_hash_many`。

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::error::{AppchainError, AppchainResult};

/// 32 字节 → (hi, lo) 两个 felt：hi = bytes[0..16]，lo = bytes[16..32]。
/// 16 字节 < 2^128 < p，`from_byte_slice_be` 不会失败。
#[must_use]
pub fn bytes32_to_felts(bytes: &[u8; 32]) -> (FieldElement, FieldElement) {
    let hi = FieldElement::from_byte_slice_be(&bytes[0..16])
        .expect("16-byte value always fits the field");
    let lo = FieldElement::from_byte_slice_be(&bytes[16..32])
        .expect("16-byte value always fits the field");
    (hi, lo)
}

/// felt → 32 字节大端（无损；域元素 < p < 2^252，字节表示可逆）。
#[must_use]
pub fn felt_to_bytes32(f: &FieldElement) -> [u8; 32] {
    f.to_bytes_be()
}

/// 32 字节 → felt（仅接受确实是域元素的字节，≥ p 拒绝）。
///
/// # Errors
/// 值 ≥ 域模数 → [`AppchainError::OutOfRange`]。
pub fn felt_from_bytes32_exact(bytes: &[u8; 32]) -> AppchainResult<FieldElement> {
    FieldElement::from_bytes_be(bytes).map_err(|_| AppchainError::OutOfRange("felt bytes"))
}

/// u64 → felt（无损失）。
#[must_use]
pub fn felt_from_u64(v: u64) -> FieldElement {
    FieldElement::from(v)
}

/// 域分隔标签：`poseidon(hi, lo)`，hi/lo = blake2s32(domain) 拆分。
#[must_use]
pub fn domain_felt(domain: &[u8]) -> FieldElement {
    let (hi, lo) = bytes32_to_felts(&crate::keys::blake2s32(&[domain]));
    poseidon_hash_many(&[hi, lo])
}

/// 域标签常量：note 承诺。
pub const DOMAIN_NOTE_COMMITMENT: &[u8] = b"poker-appchain.note.commitment.v1";
/// 域标签常量：note nullifier。
pub const DOMAIN_NOTE_NULLIFIER: &[u8] = b"poker-appchain.note.nullifier.v1";
/// 域标签常量：结算绑定（防重放）。
pub const DOMAIN_SETTLEMENT_BINDING: &[u8] = b"poker-appchain.settlement.binding.v1";
/// 域标签常量：费率策略承诺。
pub const DOMAIN_FEE_POLICY: &[u8] = b"poker-appchain.fee.policy.v1";
/// 域标签常量：P 层花费签名摘要。
pub const DOMAIN_SPEND_DIGEST: &[u8] = b"poker-appchain.spend.digest.v1";
/// 域标签常量：出入金操作摘要。
pub const DOMAIN_VAULT_DIGEST: &[u8] = b"poker-appchain.vault.digest.v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes32_split_is_lossless_and_ordered() {
        let b0 = [0xffu8; 32];
        let b1 = [0xffu8; 32];
        let (h0, l0) = bytes32_to_felts(&b0);
        let (h1, l1) = bytes32_to_felts(&b1);
        assert_eq!((h0, l0), (h1, l1));
        let mut b2 = b0;
        b2[0] = 0xfe;
        let (h2, _) = bytes32_to_felts(&b2);
        assert_ne!(h0, h2);
    }

    #[test]
    fn felt_byte_roundtrip_lossless() {
        // 251-bit 值（byte0 = 0x04 区域，回归覆盖旧掩码 bug）
        let mut b = [0u8; 32];
        b[0] = 0x04;
        b[31] = 0xff;
        let f = felt_from_bytes32_exact(&b).expect("0x04... < p");
        let back = felt_to_bytes32(&f);
        assert_eq!(back, b);
    }

    #[test]
    fn out_of_range_rejected() {
        let mut b = [0xffu8; 32]; // ≥ p
        b[0] = 0xff;
        assert!(felt_from_bytes32_exact(&b).is_err());
    }

    #[test]
    fn domains_are_distinct() {
        let a = domain_felt(DOMAIN_NOTE_COMMITMENT);
        let b = domain_felt(DOMAIN_NOTE_NULLIFIER);
        assert_ne!(a, b);
    }
}
