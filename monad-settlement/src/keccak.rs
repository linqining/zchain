//! keccak-256（以太坊域）：ABI selector / 签名摘要 / 事件 topic 派生。
//!
//! 用 RustCrypto `sha3` crate 的 `Keccak256`（legacy Keccak，非 NIST SHA3）。

use sha3::{Digest, Keccak256 as Keccak256State};

/// keccak-256 摘要。
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256State::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// 函数 selector：keccak256("<abi 签名>")[0..4]。
#[must_use]
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 以太坊黄金向量：keccak256("") 与 transfer selector。
    #[test]
    fn known_vectors() {
        assert_eq!(
            keccak256(b""),
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc,
                0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa,
                0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
            ]
        );
        assert_eq!(
            selector("transfer(address,uint256)"),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
    }
}
