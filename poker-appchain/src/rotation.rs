//! M8：sequencer 密钥轮换——**停机轮换**清单工具。
//!
//! 语义：sequencer 公钥轮换发生在**停机窗口**（runbook：停写 → 链尾
//! checkpoint → 换钥 → 新钥起新链），本模块只生成/校验"旧钥授权换新钥"
//! 的签名清单记录，供 runbook 归档与 watcher 复核。**帧链中途热换签**
//! （同一链上换 sequencer 公钥）是 v1.5 的工作，v1 明确不支持。
//!
//! 签名域：`signature = ed25519_sign(old_key, blake2s32(
//! "poker-appchain.rotation.v1" || old_public || new_public || ts_ms_be))`
//! ——旧钥授权新钥，任何字段篡改都破坏验签。

use crate::keys::{blake2s32, SequencerKey};

/// 轮换签名域分隔。
pub const ROTATION_DOMAIN: &[u8] = b"poker-appchain.rotation.v1";

/// 密钥轮换记录（旧钥对新钥的签名授权清单条目）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotationRecord {
    /// 旧 sequencer 公钥（32B；验证签名的钥匙）。
    pub old_public: [u8; 32],
    /// 新 sequencer 公钥（32B）。
    pub new_public: [u8; 32],
    /// 轮换时间（墙钟毫秒；绑定进签名）。
    pub ts_ms: u64,
    /// 旧钥 ed25519 签名（64B，对 [`rotation_message`]）。
    pub signature: [u8; 64],
}

/// 轮换签名消息：`blake2s32(DOMAIN || old || new || ts_ms_be)`。
#[must_use]
pub fn rotation_message(
    old_public: &[u8; 32],
    new_public: &[u8; 32],
    ts_ms: u64,
) -> [u8; 32] {
    blake2s32(&[
        ROTATION_DOMAIN,
        old_public,
        new_public,
        &ts_ms.to_be_bytes(),
    ])
}

/// 生成轮换记录（旧钥签名授权新钥）。`new_public` 必须来自新钥持有方
/// 独立导出（本函数不生成新钥——私钥永不经过本工具进程内存之外）。
#[must_use]
pub fn generate(old: &SequencerKey, new_public: [u8; 32], ts_ms: u64) -> KeyRotationRecord {
    let signature = old.sign(&rotation_message(&old.public, &new_public, ts_ms));
    KeyRotationRecord {
        old_public: old.public,
        new_public,
        ts_ms,
        signature,
    }
}

/// 校验轮换记录：签名必须由 `old_public` 对 (old, new, ts) 域消息成立。
#[must_use]
pub fn verify(record: &KeyRotationRecord) -> bool {
    SequencerKey::verify(
        &record.old_public,
        &rotation_message(&record.old_public, &record.new_public, record.ts_ms),
        &record.signature,
    )
}

/// JSON 形态（hex 编码 32B/64B 字段；文件 IO 用）。
///
/// ```json
/// {
///   "old_public": "<64hex>", "new_public": "<64hex>",
///   "ts_ms": 1700000000000, "signature": "<128hex>"
/// }
/// ```
pub mod json {
    use crate::error::{AppchainError, AppchainResult};

    use super::KeyRotationRecord;

    /// 序列化为 JSON（pretty）。
    ///
    /// # Errors
    /// 序列化失败（实际不可达）→ [`AppchainError::Codec`]。
    pub fn to_string_pretty(r: &KeyRotationRecord) -> AppchainResult<String> {
        let v = serde_json::json!({
            "old_public": hex::encode(r.old_public),
            "new_public": hex::encode(r.new_public),
            "ts_ms": r.ts_ms,
            "signature": hex::encode(r.signature),
        });
        serde_json::to_string_pretty(&v).map_err(|e| AppchainError::Codec(e.to_string()))
    }

    /// 从 JSON 解析（字段缺失/类型错/长度错 → Err）。
    ///
    /// # Errors
    /// JSON/字段非法 → [`AppchainError`]。
    pub fn from_str(s: &str) -> AppchainResult<KeyRotationRecord> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| AppchainError::Codec(e.to_string()))?;
        let obj = v.as_object().ok_or_else(|| {
            AppchainError::Codec("rotation record: not a json object".to_string())
        })?;
        let parse32 = |key: &str| -> AppchainResult<[u8; 32]> {
            let hex_str = obj
                .get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| AppchainError::Codec(format!("{key}: missing/invalid")))?;
            let bytes = hex::decode(hex_str)
                .map_err(|_| AppchainError::Codec(format!("{key}: not hex")))?;
            bytes
                .try_into()
                .map_err(|_| AppchainError::Codec(format!("{key}: expected 32 bytes")))
        };
        let old_public = parse32("old_public")?;
        let new_public = parse32("new_public")?;
        let ts_ms = obj
            .get("ts_ms")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| AppchainError::Codec("ts_ms: missing/invalid".to_string()))?;
        let sig_hex = obj
            .get("signature")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AppchainError::Codec("signature: missing/invalid".to_string()))?;
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|_| AppchainError::Codec("signature: not hex".to_string()))?;
        let signature: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            AppchainError::Codec("signature: expected 64 bytes".to_string())
        })?;
        Ok(KeyRotationRecord {
            old_public,
            new_public,
            ts_ms,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_verify_roundtrip() {
        let old = SequencerKey::from_seed(&[81u8; 32]);
        let new_public = SequencerKey::from_seed(&[82u8; 32]).public;
        let r = generate(&old, new_public, 1_700_000_000_000);
        assert_eq!(r.old_public, old.public);
        assert!(verify(&r));
        // 域消息确定：同输入同摘要
        assert_eq!(
            rotation_message(&old.public, &new_public, 1_700_000_000_000),
            rotation_message(&old.public, &new_public, 1_700_000_000_000)
        );
    }

    /// 篡改 new_public / ts_ms → 拒绝；旧钥换人签名 → 拒绝。
    #[test]
    fn tampered_record_rejected() {
        let old = SequencerKey::from_seed(&[83u8; 32]);
        let impostor = SequencerKey::from_seed(&[84u8; 32]);
        let new_public = SequencerKey::from_seed(&[85u8; 32]).public;
        let r = generate(&old, new_public, 1_000);

        // 换 new_public（签名不覆盖）→ 拒绝
        let mut r1 = r.clone();
        r1.new_public = SequencerKey::from_seed(&[86u8; 32]).public;
        assert!(!verify(&r1));

        // 换时间戳 → 拒绝
        let mut r2 = r.clone();
        r2.ts_ms += 1;
        assert!(!verify(&r2));

        // 冒名旧钥（同一 new_public，另一把"旧钥"重签）→ 结构合法但签名
        // 对其自称的 old_public 不成立（old_public 换成了 impostor，签名
        // 仍出自真 old）→ 拒绝
        let mut r3 = r;
        r3.old_public = impostor.public;
        assert!(!verify(&r3));
    }

    #[test]
    fn json_roundtrip_and_tamper() {
        let old = SequencerKey::from_seed(&[87u8; 32]);
        let new_public = SequencerKey::from_seed(&[88u8; 32]).public;
        let r = generate(&old, new_public, 1_700_000_000_123);
        let s = json::to_string_pretty(&r).unwrap();
        let r2 = json::from_str(&s).unwrap();
        assert_eq!(r, r2);
        assert!(verify(&r2));

        // 字段篡改 → JSON 可解析但验签拒绝
        let bad = s.replace(&hex::encode(new_public), &hex::encode([9u8; 32]));
        let r3 = json::from_str(&bad).unwrap();
        assert!(!verify(&r3));

        // 结构损坏 → Err
        assert!(json::from_str("{\"old_public\":\"zz\"}").is_err());
    }
}
