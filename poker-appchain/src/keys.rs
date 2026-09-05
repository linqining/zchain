//! P 层签名密钥（secp256k1 ECDSA）与 sequencer 软确认链签名（ed25519）。
//!
//! v1 托管模式下 owner 密钥由客户端持有；本模块只做密钥/签名的纯函数封装，
//! 不做任何密钥存储。生产密钥走环境注入（延续仓库"私钥不入库"纪律）。

use blake2::Blake2s256;
use blake2::Digest as _;
use secp256k1::ecdsa::{RecoverableSignature, Signature};
use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};

use crate::error::{AppchainError, AppchainResult};

/// 摘要原语：Blake2s-256（workspace 既有依赖；与 P 层 keccak 挑战系无关，
/// 这是账本层的独立命名空间）。
#[must_use]
pub fn blake2s32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// 花费摘要 v2：绑定（note 承诺, nullifier, 操作 scope, **效果摘要**）四要素
/// （均为规范字节）。
///
/// P 层签名覆盖规则（plan §M2 + 审计 S1 修复）：每个消耗 note 的动作必须由
/// note owner 对该摘要签名。效果摘要（[`crate::ops::Operation::effect_digest`]
/// ）绑定操作的**全部语义载荷**（收款人、金额、桌、幂等键、结算分配），
/// 使 sequencer 无法拿签名授权改打给别人；scope 区分 spend 用途，防跨操作
/// 重放。
#[must_use]
pub fn spend_digest(
    commitment: &[u8; 32],
    nullifier: &[u8; 32],
    scope: &[u8],
    effect: &[u8; 32],
) -> [u8; 32] {
    blake2s32(&[
        crate::felt::DOMAIN_SPEND_DIGEST,
        commitment,
        nullifier,
        scope,
        effect,
    ])
}

/// secp256k1 owner 密钥（测试/客户端辅助）。
#[derive(Debug, Clone)]
pub struct OwnerKey {
    secret: SecretKey,
    /// 压缩公钥（33 字节），随 note 面额一起入库。
    pub public: [u8; 33],
}

impl OwnerKey {
    /// 从 32 字节种子生成（测试辅助；生产走随机源）。
    ///
    /// # Errors
    /// 种子非法（≥ 曲线阶）时返回 [`AppchainError::BadSignature`]。
    pub fn from_seed(seed: &[u8; 32]) -> AppchainResult<Self> {
        let secret =
            SecretKey::from_slice(seed).map_err(|_| AppchainError::BadSignature)?;
        let public = PublicKey::from_secret_key(SECP256K1, &secret)
            .serialize()
            .to_owned();
        Ok(Self { secret, public })
    }

    /// 压缩公钥字节。
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 33] {
        self.public
    }

    /// ECDSA 签名（确定性 RFC6979，同一消息同一签名，便于测试与 ABI 稳定）。
    #[must_use]
    pub fn sign(&self, digest: &[u8; 32]) -> EcdsaSig {
        let msg = Message::from_digest(*digest);
        let sig: Signature = SECP256K1.sign_ecdsa(&msg, &self.secret);
        EcdsaSig {
            bytes: sig.serialize_compact(),
        }
    }

    /// 可恢复签名（用于压缩 calldata；v1 账本走显式公钥路径）。
    #[must_use]
    pub fn sign_recoverable(&self, digest: &[u8; 32]) -> RecoverableSignature {
        let msg = Message::from_digest(*digest);
        SECP256K1.sign_ecdsa_recoverable(&msg, &self.secret)
    }
}

/// ECDSA 签名的字节容器（borsh ABI 稳定 64 字节 compact）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct EcdsaSig {
    /// 64 字节 r‖s compact。
    pub bytes: [u8; 64],
}

/// 校验 ECDSA：公钥（33B 压缩）+ 摘要 + 签名。
///
/// # Errors
/// 任何解析/验证失败一律 [`AppchainError::BadSignature`]（fail-closed，
/// 不区分格式错误与验证错误）。
pub fn verify_ecsdsa(
    public_compressed: &[u8; 33],
    digest: &[u8; 32],
    sig: &EcdsaSig,
) -> AppchainResult<()> {
    let pk = PublicKey::from_slice(public_compressed)
        .map_err(|_| AppchainError::BadSignature)?;
    let msg = Message::from_digest(*digest);
    let s = Signature::from_compact(&sig.bytes)
        .map_err(|_| AppchainError::BadSignature)?;
    if SECP256K1.verify_ecdsa(&msg, &s, &pk).is_ok() {
        Ok(())
    } else {
        Err(AppchainError::BadSignature)
    }
}

/// 从压缩公钥取 (x, y) 原始 32 字节（无掩码；调用方经 `bytes32_to_felts`
/// 进入哈希）。坏输入返回零字节，由上层签名验证拒绝。
pub fn public_xy_bytes_from_compressed(public: &[u8; 33]) -> ([u8; 32], [u8; 32]) {
    let pk = match PublicKey::from_slice(public) {
        Ok(pk) => pk,
        Err(_) => return ([0u8; 32], [0u8; 32]),
    };
    let ser = pk.serialize_uncompressed(); // 0x04 || x || y
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&ser[1..33]);
    y.copy_from_slice(&ser[33..65]);
    (x, y)
}

/// ed25519 sequencer 软确认链签名密钥。
#[derive(Debug, Clone)]
pub struct SequencerKey {
    signing: ed25519_dalek::SigningKey,
    /// 验证公钥（32 字节），随创世参数公布。
    pub public: [u8; 32],
}

impl SequencerKey {
    /// 从 32 字节种子生成。
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = ed25519_dalek::SigningKey::from_bytes(seed);
        let public = signing.verifying_key().to_bytes();
        Self { signing, public }
    }

    /// 签名（64 字节）。
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.signing.sign(msg).to_bytes()
    }

    /// 校验 sequencer 帧签名。
    #[must_use]
    pub fn verify(
        public: &[u8; 32],
        msg: &[u8],
        sig: &[u8; 64],
    ) -> bool {
        use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
        let vk = match VerifyingKey::from_bytes(public) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let s = Signature::from_bytes(sig);
        vk.verify(msg, &s).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_roundtrip() {
        let k = OwnerKey::from_seed(&[7u8; 32]).unwrap();
        let d = blake2s32(&[b"hello"]);
        let sig = k.sign(&d);
        verify_ecsdpa_helper(k.public_bytes(), &d, &sig);
    }

    fn verify_ecsdpa_helper(pk: [u8; 33], d: &[u8; 32], sig: &EcdsaSig) {
        verify_ecsdsa(&pk, d, sig).expect("valid signature must verify");
    }

    #[test]
    fn ecdsa_tamper_rejected() {
        let k = OwnerKey::from_seed(&[9u8; 32]).unwrap();
        let d = blake2s32(&[b"hello"]);
        let mut sig = k.sign(&d);
        sig.bytes[0] ^= 0x01;
        assert!(verify_ecsdsa(&k.public_bytes(), &d, &sig).is_err());
    }

    #[test]
    fn ed25519_roundtrip() {
        let k = SequencerKey::from_seed(&[1u8; 32]);
        let sig = k.sign(b"frame");
        assert!(SequencerKey::verify(&k.public, b"frame", &sig));
        assert!(!SequencerKey::verify(&k.public, b"other", &sig));
    }
}
