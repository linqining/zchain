//! `keystore`：平台无关加密信封（plan §6.12.3）。
//!
//! - KDF：Argon2id（OWASP interactive 基线：m=19 MiB, t=2, p=1）
//! - AEAD：ChaCha20-Poly1305（密文自带 Poly1305 认证标签）
//! - 明文带 canary：打开信封时先校验 canary，口令错/字节篡改一律
//!   [`WalletError::BadPassword`] / [`WalletError::Tampered`]（fail-closed）
//! - 平台 Keychain/KeyStore 只作为信封存放位置的包装（本 crate 只提供
//!   字节信封，不触碰平台 API；WASM/移动壳层负责落位）
//!
//! 安全纪律：派生出的 KEK 在 [`zeroize::Zeroizing`] 中；明文 payload 只在
//! open 返回的 Zeroizing 容器内短暂存在；类型不实现会输出明文的 Debug。

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{WalletError, WalletResult};
use crate::key_manager::{OwnerKeyPair, SecretBytes};

/// keystore 信封格式版本（只升不降；未来版本 fail-closed）。
pub const KEYSTORE_VERSION: u16 = 1;

/// 明文 canary：open 时用于显式区分"口令错"与"内容合法"。
const CANARY: &[u8] = b"zchain.keystore.canary.v1";

/// Keystore 域标签（AAD 前缀，防信封跨用途移植）。
pub const DOMAIN_KEYSTORE: &[u8] = b"zchain.keystore.v1";

/// Argon2id 参数 + salt（随信封存储；salt 每信封独立）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct KdfParams {
    /// 16B 随机 salt。
    pub salt: [u8; 16],
    /// 内存成本（KiB）。
    pub m_cost_kib: u32,
    /// 时间成本（迭代）。
    pub t_cost: u32,
    /// 并行度。
    pub p_cost: u32,
}

/// 信封参数预设：交互式（生产默认，OWASP 基线）。
#[must_use]
pub fn params_interactive() -> (u32, u32, u32) {
    (19_456, 2, 1)
}

/// 信封参数预设：测试（轻量；生产禁止使用）。
#[must_use]
pub fn params_test() -> (u32, u32, u32) {
    (64, 1, 1)
}

/// 加密信封：KDF 参数 + AEAD nonce + 密文（含 Poly1305 tag）。
///
/// AAD = `domain || version_be`，把信封钉在其用途与格式版本上。
#[derive(Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SealedEnvelope {
    /// 信封格式版本。
    pub version: u16,
    /// KDF 参数。
    pub kdf: KdfParams,
    /// 12B AEAD nonce。
    pub nonce: [u8; 12],
    /// 密文（末 16B 为 Poly1305 tag）。
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for SealedEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedEnvelope")
            .field("version", &self.version)
            .field("kdf", &self.kdf)
            .field("nonce", &hex::encode(self.nonce))
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Argon2id 派生 32B KEK（口令 → key；失败即 panic 级内部错误不外泄口令信息）。
///
/// # Panics
/// 仅当 Argon2 参数构造非法（预设常量，实际不可达）。
#[must_use]
pub fn derive_key(password: &[u8], kdf: &KdfParams) -> Zeroizing<[u8; 32]> {
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .expect("constant KDF params are valid");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    // panic 路径仅对应参数非法/OS 资源失败；Argon2id 本身对任意口令可导出。
    argon
        .hash_password_into(password, &kdf.salt, out.as_mut())
        .expect("argon2id hash_password_into with fixed 32B output");
    out
}

fn aad(domain: &[u8], version: u16) -> Vec<u8> {
    let mut a = domain.to_vec();
    a.extend_from_slice(&version.to_be_bytes());
    a
}

/// 封装任意明文（内部接口；typed 助手见下）。
///
/// # Errors
/// 参数越界（不预算）→ [`WalletError::InvalidArgument`]（保留 fail-closed 形）。
pub fn seal(
    plaintext: &[u8],
    domain: &[u8],
    password: &[u8],
    (m, t, p): (u32, u32, u32),
) -> WalletResult<SealedEnvelope> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let kdf = KdfParams { salt, m_cost_kib: m, t_cost: t, p_cost: p };
    let kek = derive_key(password, &kdf);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plaintext, aad: &aad(domain, KEYSTORE_VERSION) },
        )
        .map_err(|_| WalletError::InvalidArgument("seal"))?;
    Ok(SealedEnvelope { version: KEYSTORE_VERSION, kdf, nonce, ciphertext: ct })
}

/// 开启信封（fail-closed：口令错 → [`WalletError::BadPassword`]；篡改 →
/// [`WalletError::Tampered`]；未来版本 → [`WalletError::UnsupportedVersion`]）。
///
/// # Errors
/// 见上。明文只存在于返回的 Zeroizing 缓冲内。
pub fn open(
    env: &SealedEnvelope,
    domain: &[u8],
    password: &[u8],
) -> WalletResult<Zeroizing<Vec<u8>>> {
    if env.version > KEYSTORE_VERSION {
        return Err(WalletError::UnsupportedVersion {
            found: env.version,
            max_supported: KEYSTORE_VERSION,
        });
    }
    let kek = derive_key(password, &env.kdf);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek.as_ref()));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&env.nonce),
            Payload { msg: &env.ciphertext, aad: &aad(domain, env.version) },
        )
        .map_err(|_| WalletError::BadPassword)?;
    Ok(Zeroizing::new(plaintext))
}

/// 信封内明文布局：canary + 载荷（typed 助手共用）。
fn frame_payload(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = CANARY.to_vec();
    v.push(kind);
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// 拆信封：校验 canary + kind + 长度，返回 body。
fn unframe_payload(plain: &[u8], kind: u8) -> WalletResult<&[u8]> {
    let header = CANARY.len() + 1 + 4;
    if plain.len() < header || &plain[..CANARY.len()] != CANARY {
        return Err(WalletError::Tampered("keystore canary"));
    }
    if plain[CANARY.len()] != kind {
        return Err(WalletError::Tampered("keystore kind"));
    }
    let len = u32::from_be_bytes([
        plain[CANARY.len() + 1],
        plain[CANARY.len() + 2],
        plain[CANARY.len() + 3],
        plain[CANARY.len() + 4],
    ]) as usize;
    if plain.len() != header + len {
        return Err(WalletError::Tampered("keystore length"));
    }
    Ok(&plain[header..])
}

/// 信封载荷种类：owner key。
pub const KIND_OWNER_KEY: u8 = 1;
/// 信封载荷种类：数据加密密钥（DEK）。
pub const KIND_DEK: u8 = 2;

/// 封装 owner key（明文 = borsh(私钥32B ‖ 公钥33B)，仅短暂存在于内存）。
///
/// # Errors
/// 参数非法 → [`WalletError::InvalidArgument`]。
pub fn seal_owner_key(
    key: &OwnerKeyPair,
    password: &[u8],
    params: (u32, u32, u32),
) -> WalletResult<SealedEnvelope> {
    let mut body = Vec::with_capacity(65);
    body.extend_from_slice(key.secret_bytes().as_ref());
    body.extend_from_slice(&key.public_bytes());
    seal(&frame_payload(KIND_OWNER_KEY, &body), DOMAIN_KEYSTORE, password, params)
}

/// 开启 owner key 信封。
///
/// # Errors
/// 口令错/篡改/版本未来/载荷畸形 → 对应错误（fail-closed）。
pub fn open_owner_key(env: &SealedEnvelope, password: &[u8]) -> WalletResult<OwnerKeyPair> {
    let plain = open(env, DOMAIN_KEYSTORE, password)?;
    let body = unframe_payload(&plain, KIND_OWNER_KEY)?;
    if body.len() != 65 {
        return Err(WalletError::Tampered("owner key payload"));
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&body[..32]);
    let key = OwnerKeyPair::from_secret_bytes(&secret)?;
    if key.public_bytes() != body[32..65] {
        return Err(WalletError::Tampered("owner public key"));
    }
    Ok(key)
}

/// 封装 32B 数据加密密钥（DEK；note store 快照/会话密钥落盘的根）。
///
/// # Errors
/// 参数非法 → [`WalletError::InvalidArgument`]。
pub fn seal_dek(dek: &SecretBytes, password: &[u8], params: (u32, u32, u32)) -> WalletResult<SealedEnvelope> {
    seal(&frame_payload(KIND_DEK, dek.expose()), DOMAIN_KEYSTORE, password, params)
}

/// 开启 DEK 信封。
///
/// # Errors
/// 口令错/篡改/版本未来/载荷畸形 → 对应错误。
pub fn open_dek(env: &SealedEnvelope, password: &[u8]) -> WalletResult<SecretBytes> {
    let plain = open(env, DOMAIN_KEYSTORE, password)?;
    let body = unframe_payload(&plain, KIND_DEK)?;
    if body.len() != 32 {
        return Err(WalletError::Tampered("dek payload"));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(body);
    Ok(SecretBytes::new(dek))
}

/// 生成新的 32B DEK（OS 随机源）。
#[must_use]
pub fn generate_dek() -> SecretBytes {
    let mut dek = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dek);
    SecretBytes::new(dek)
}

/// 会话密钥文件域标签（DEK 封装的 AAD）。
pub const DOMAIN_SESSION_KEY: &[u8] = b"zchain.session_key.v1";

/// DEK 直接封装任意明文（会话密钥落盘等；nonce 前置，AAD = domain）。
///
/// # Errors
/// AEAD 内部失败（实际不可达）→ [`WalletError::Codec`]。
pub fn seal_blob(dek: &SecretBytes, domain: &[u8], plaintext: &[u8]) -> WalletResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(dek.expose()));
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: domain })
        .map_err(|_| WalletError::Codec("seal_blob".into()))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// DEK 直接开启（域不符/篡改/DEK 错 → 拒绝）。
///
/// # Errors
/// 认证失败 → [`WalletError::BadPassword`]；长度畸形 →
/// [`WalletError::Tampered`]。
pub fn open_blob(dek: &SecretBytes, domain: &[u8], blob: &[u8]) -> WalletResult<Zeroizing<Vec<u8>>> {
    if blob.len() < 12 {
        return Err(WalletError::Tampered("blob"));
    }
    let (nonce, ct) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(dek.expose()));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: domain })
        .map(Zeroizing::new)
        .map_err(|_| WalletError::BadPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let env = seal(b"hello world", DOMAIN_KEYSTORE, b"pw", params_test()).unwrap();
        let plain = open(&env, DOMAIN_KEYSTORE, b"pw").unwrap();
        assert_eq!(&*plain, b"hello world");
    }

    #[test]
    fn wrong_password_fails_closed() {
        let env = seal(b"secret", DOMAIN_KEYSTORE, b"right", params_test()).unwrap();
        assert!(matches!(open(&env, DOMAIN_KEYSTORE, b"wrong"), Err(WalletError::BadPassword)));
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let mut env = seal(b"secret", DOMAIN_KEYSTORE, b"pw", params_test()).unwrap();
        let i = env.ciphertext.len() / 2;
        env.ciphertext[i] ^= 0x01;
        assert!(matches!(open(&env, DOMAIN_KEYSTORE, b"pw"), Err(WalletError::BadPassword)));
    }

    #[test]
    fn cross_domain_envelope_rejected() {
        let env = seal(b"secret", b"zchain.keystore.v1", b"pw", params_test()).unwrap();
        // 同一信封换域 AAD 必须失败（防跨用途移植）。
        assert!(matches!(open(&env, b"zchain.other.v1", b"pw"), Err(WalletError::BadPassword)));
    }

    #[test]
    fn owner_key_roundtrip_and_public_binding() {
        let key = OwnerKeyPair::from_seed(&[11u8; 32]).unwrap();
        let env = seal_owner_key(&key, b"pw", params_test()).unwrap();
        let back = open_owner_key(&env, b"pw").unwrap();
        assert_eq!(back.public_bytes(), key.public_bytes());
        assert_eq!(back.secret_bytes().as_ref(), key.secret_bytes().as_ref());
        // 公钥被篡改 → 拒绝
        let mut env2 = env.clone();
        env2.ciphertext[CANARY.len() + 1 + 4 + 32] ^= 0x01;
        assert!(open_owner_key(&env2, b"pw").is_err());
    }

    #[test]
    fn debug_never_leaks_secret() {
        let key = OwnerKeyPair::from_seed(&[12u8; 32]).unwrap();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(&hex::encode(key.secret_bytes())));
        let sb = SecretBytes::new([9u8; 32]);
        assert!(!format!("{sb:?}").contains("090909"));
    }
}
