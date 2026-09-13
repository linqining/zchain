//! ABI v2 alpha（owner_v2）集成测试：三 scheme 正例 + 篡改负例、
//! owner_commitment 跨 scheme 分离、MigrateNote 逐字段篡改拒、
//! SNIP-12 互操作冻结向量、borsh ABI 稳定性。
//!
//! 全部走 release（`cargo test -p poker-appchain --release --test owner_v2`）。

use poker_appchain::keys::{OwnerKey, blake2s32};
use poker_appchain::note::AssetClass;
use poker_appchain::owner_v2::{
    MigrateNoteRecord, OWNER_V2_ABI_VERSION, OwnerRef, OwnerV2Error, SignatureEnvelope,
    SignatureScheme, VerifierMaterial, binding_authorization_digest, check_envelope_freshness,
    legacy_account_id, migrate_digest, owner_commitment, v2_spend_digest, validate_migrate_note,
    validate_owner_ref, verify_owner_signature,
};
use starknet_crypto::FieldElement;

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

/// 测试时钟（unix 秒）。
const NOW: u64 = 1_700_000_000;
/// 信封有效期（NOW 之后 1 小时）。
const EXPIRY: u64 = NOW + 3_600;

/// canonical felt 测试常量（< 域模数；与 wallet 侧 felt_test 同构）。
fn felt32(byte: u8) -> [u8; 32] {
    let mut f = [0u8; 32];
    f[31] = byte;
    f
}

/// 32B hex 常量解码（冻结向量用）。
fn h32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("frozen hex vector must decode");
    v.try_into().expect("frozen hex vector must be 32B")
}

/// 33B hex 常量解码（压缩公钥冻结向量用）。
fn h33(s: &str) -> [u8; 33] {
    let v = hex::decode(s).expect("frozen hex vector must decode");
    v.try_into().expect("frozen hex vector must be 33B")
}

/// secp256k1 测试密钥（RFC6979 确定性签名）。
fn secp_key(seed: u8) -> OwnerKey {
    OwnerKey::from_seed(&[seed; 32]).expect("seed key must be valid")
}

/// Legacy OwnerRef（key-id = blake2s32(压缩公钥)）。
fn legacy_ref(key: &OwnerKey, key_version: u32) -> OwnerRef {
    OwnerRef {
        scheme: SignatureScheme::LegacySecp256k1,
        account_id: legacy_account_id(&key.public_bytes()),
        key_version,
        binding_id: None,
    }
}

/// Stark 密钥对（secret felt seed → 公钥 felt 的 32B 规范编码）。
fn stark_pubkey(seed: u64) -> [u8; 32] {
    let secret = FieldElement::from(seed);
    starknet_crypto::get_public_key(&secret).to_bytes_be()
}

/// Stark 曲线签名 → 64B r‖s（r/s 全零时换 k 重试）。
fn stark_sign(secret: u64, digest: &[u8; 32]) -> [u8; 64] {
    let s = FieldElement::from(secret);
    let msg = FieldElement::from_bytes_be(digest).expect("poseidon digests are canonical felts");
    let mut k = 1u64;
    loop {
        match starknet_crypto::sign(&s, &msg, &FieldElement::from(k)) {
            Ok(sig) if sig.r != FieldElement::ZERO && sig.s != FieldElement::ZERO => {
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&sig.r.to_bytes_be());
                out[32..].copy_from_slice(&sig.s.to_bytes_be());
                return out;
            }
            _ => k += 1,
        }
    }
}

/// StarkCurve OwnerRef。
fn stark_ref(seed: u64, key_version: u32) -> OwnerRef {
    OwnerRef {
        scheme: SignatureScheme::StarkCurve,
        account_id: stark_pubkey(seed),
        key_version,
        binding_id: None,
    }
}

/// StarknetAccountBinding OwnerRef（address = felt 测试常量）。
fn binding_ref(addr: [u8; 32], binding_id: [u8; 32], key_version: u32) -> OwnerRef {
    OwnerRef {
        scheme: SignatureScheme::StarknetAccountBinding,
        account_id: addr,
        key_version,
        binding_id: Some(binding_id),
    }
}

/// 效果摘要占位（ spend 摘要四要素之一；语义绑定由 effect 承担）。
fn effect() -> [u8; 32] {
    blake2s32(&[b"owner_v2.test.effect.v1"])
}

/// 为给定 old signer scheme 构造**已签名**的合法 MigrateNoteRecord。
/// 新 owner 一律用另一种 scheme（legacy → StarkCurve 混迁）。
fn signed_migrate(old: Signer) -> MigrateNoteRecord {
    let new_owner = legacy_ref(&secp_key(12), 0);
    let record = MigrateNoteRecord {
        old_commitment: blake2s32(&[b"old v1 note commitment"]),
        old_owner_sig: SignatureEnvelope {
            scheme: old.scheme(),
            signer_ref: old.owner_ref(),
            typed_data_digest: [0u8; 32], // 下面按真实摘要回填
            signature: [0u8; 64],
            nonce: 5,
            expiry: EXPIRY,
        },
        new_owner_ref: new_owner,
        amount: 250,
        asset_class: AssetClass::Play,
        migration_nonce: blake2s32(&[b"migration nonce 1"]),
        network_id: blake2s32(&[b"zchain-poker-devnet"]),
        abi_version: OWNER_V2_ABI_VERSION,
    };
    let digest = migrate_digest(&record);
    let signature = old.sign(&digest);
    MigrateNoteRecord {
        old_owner_sig: SignatureEnvelope {
            typed_data_digest: digest,
            signature,
            ..record.old_owner_sig
        },
        ..record
    }
}

/// 三 scheme 的签名者抽象（fixture 内部用）。
enum Signer {
    /// Legacy secp256k1（seed 字节）。
    Legacy(u8),
    /// StarkCurve（secret felt seed）。
    Stark(u64),
    /// StarknetAccountBinding（会话密钥 seed + 地址 + binding_id）。
    Binding(u8, [u8; 32], [u8; 32]),
}

impl Signer {
    fn scheme(&self) -> SignatureScheme {
        match self {
            Self::Legacy(_) => SignatureScheme::LegacySecp256k1,
            Self::Stark(_) => SignatureScheme::StarkCurve,
            Self::Binding(..) => SignatureScheme::StarknetAccountBinding,
        }
    }

    fn owner_ref(&self) -> OwnerRef {
        match self {
            Self::Legacy(seed) => legacy_ref(&secp_key(*seed), 0),
            Self::Stark(seed) => stark_ref(*seed, 0),
            Self::Binding(seed, addr, bid) => {
                let _ = seed; // 会话密钥在 material 中呈递
                binding_ref(*addr, *bid, 0)
            }
        }
    }

    /// 对摘要签名（Binding scheme：会话密钥 ECDSA）。
    fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        match self {
            Self::Legacy(seed) => secp_key(*seed).sign(digest).bytes,
            Self::Stark(seed) => stark_sign(*seed, digest),
            Self::Binding(seed, addr, bid) => {
                let session = secp_key(*seed);
                let d = binding_authorization_digest(
                    addr,
                    bid,
                    &felt32(0x7E),
                    &session.public_bytes(),
                    EXPIRY,
                )
                .expect("binding digest fixture must build");
                session.sign(&d).bytes
            }
        }
    }

    /// 配套验签材料。
    fn material(&self) -> VerifierMaterial {
        match self {
            Self::Legacy(seed) => VerifierMaterial::LegacySecp256k1 {
                presented_public: secp_key(*seed).public_bytes(),
            },
            Self::Stark(_) => VerifierMaterial::StarkCurve,
            Self::Binding(seed, _addr, _bid) => VerifierMaterial::AccountBinding {
                snip12_authorize_digest: felt32(0x7E),
                session_public: secp_key(*seed).public_bytes(),
                binding_valid_until: EXPIRY,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// 1) LegacySecp256k1：正例 + 篡改负例
// ---------------------------------------------------------------------------

#[test]
fn legacy_secp256k1_positive() {
    let key = secp_key(7);
    let owner = legacy_ref(&key, 0);
    let commitment = blake2s32(&[b"note commitment"]);
    let nullifier = blake2s32(&[b"nullifier"]);
    let digest = v2_spend_digest(
        &owner,
        &commitment,
        &nullifier,
        b"transfer.v2.test",
        &effect(),
    );
    let sig = key.sign(&digest).bytes;
    verify_owner_signature(
        &owner,
        &digest,
        &sig,
        &VerifierMaterial::LegacySecp256k1 {
            presented_public: key.public_bytes(),
        },
    )
    .expect("valid legacy signature must verify");
}

#[test]
fn legacy_secp256k1_tamper_rejected() {
    let key = secp_key(7);
    let owner = legacy_ref(&key, 0);
    let digest = v2_spend_digest(
        &owner,
        &felt32(1),
        &felt32(2),
        b"transfer.v2.test",
        &effect(),
    );
    let mut sig = key.sign(&digest).bytes;

    // 篡改签名字节
    sig[0] ^= 0x01;
    let m = VerifierMaterial::LegacySecp256k1 {
        presented_public: key.public_bytes(),
    };
    assert!(matches!(
        verify_owner_signature(&owner, &digest, &sig, &m),
        Err(OwnerV2Error::BadSignature)
    ));

    // 篡改摘要
    let sig = key.sign(&digest).bytes;
    let mut digest2 = digest;
    digest2[31] ^= 0x01;
    assert!(matches!(
        verify_owner_signature(&owner, &digest2, &sig, &m),
        Err(OwnerV2Error::BadSignature)
    ));

    // 呈递非签名密钥（哈希 != account_id）
    let other = secp_key(8);
    assert!(matches!(
        verify_owner_signature(
            &owner,
            &digest,
            &key.sign(&digest).bytes,
            &VerifierMaterial::LegacySecp256k1 {
                presented_public: other.public_bytes()
            },
        ),
        Err(OwnerV2Error::MaterialMismatch(_))
    ));

    // 换 key_version（摘要含 version → 摘要变化 → 绑定 v0 摘要的签名对
    // v1 摘要失效；ref 层换版本等价于换身份）
    let owner_v1 = legacy_ref(&key, 1);
    let digest_v1 = v2_spend_digest(
        &owner_v1,
        &felt32(1),
        &felt32(2),
        b"transfer.v2.test",
        &effect(),
    );
    assert_ne!(
        digest, digest_v1,
        "key_version must participate in the digest"
    );
    assert!(verify_owner_signature(&owner_v1, &digest_v1, &sig, &m).is_err());

    // 换 scheme 字节（owner_commitment 含 scheme → v2_spend_digest 变化）
    let mut flipped = owner.clone();
    flipped.scheme = SignatureScheme::StarkCurve;
    let digest_flipped = v2_spend_digest(
        &flipped,
        &felt32(1),
        &felt32(2),
        b"transfer.v2.test",
        &effect(),
    );
    assert_ne!(
        digest, digest_flipped,
        "scheme byte must participate in the digest"
    );
}

// ---------------------------------------------------------------------------
// 2) StarkCurve：正例 + 篡改负例
// ---------------------------------------------------------------------------

#[test]
fn stark_curve_positive() {
    let owner = stark_ref(0xACE, 0);
    let digest = v2_spend_digest(&owner, &felt32(3), &felt32(4), b"buyin.v2.test", &effect());
    let sig = stark_sign(0xACE, &digest);
    verify_owner_signature(&owner, &digest, &sig, &VerifierMaterial::StarkCurve)
        .expect("valid stark signature must verify");
}

#[test]
fn stark_curve_tamper_rejected() {
    let owner = stark_ref(0xACE, 0);
    let digest = v2_spend_digest(&owner, &felt32(3), &felt32(4), b"buyin.v2.test", &effect());
    let mut sig = stark_sign(0xACE, &digest);

    // 篡改 s 分量
    sig[63] ^= 0x01;
    assert!(matches!(
        verify_owner_signature(&owner, &digest, &sig, &VerifierMaterial::StarkCurve),
        Err(OwnerV2Error::BadSignature)
    ));

    // 篡改摘要
    let sig = stark_sign(0xACE, &digest);
    let mut digest2 = digest;
    digest2[0] ^= 0x01;
    assert!(matches!(
        verify_owner_signature(&owner, &digest2, &sig, &VerifierMaterial::StarkCurve),
        Err(OwnerV2Error::BadSignature)
    ));

    // 换公钥（同摘要他人签名）
    let other = stark_ref(0xD00D, 0);
    let sig_other = stark_sign(0xD00D, &digest);
    assert!(
        verify_owner_signature(&owner, &digest, &sig_other, &VerifierMaterial::StarkCurve).is_err()
    );
    assert!(verify_owner_signature(&other, &digest, &sig, &VerifierMaterial::StarkCurve).is_err());

    // 非 canonical felt 的 account_id（≥ 域模数）→ 结构拒绝
    let bad = OwnerRef {
        scheme: SignatureScheme::StarkCurve,
        account_id: [0xff; 32],
        key_version: 0,
        binding_id: None,
    };
    assert!(matches!(
        validate_owner_ref(&bad),
        Err(OwnerV2Error::OwnerRefInvalid(_))
    ));
    assert!(verify_owner_signature(&bad, &digest, &sig, &VerifierMaterial::StarkCurve).is_err());

    // 零公钥拒绝
    let zero = OwnerRef {
        scheme: SignatureScheme::StarkCurve,
        account_id: [0u8; 32],
        key_version: 0,
        binding_id: None,
    };
    assert!(matches!(
        validate_owner_ref(&zero),
        Err(OwnerV2Error::ZeroField(_))
    ));
}

// ---------------------------------------------------------------------------
// 3) StarknetAccountBinding：正例 + 篡改负例
// ---------------------------------------------------------------------------

#[test]
fn account_binding_positive_and_tamper() {
    let session = secp_key(11);
    let addr = felt32(0x33);
    let bid = felt32(0x44);
    let snip12 = felt32(0x7E);
    let owner = binding_ref(addr, bid, 0);
    let digest =
        binding_authorization_digest(&addr, &bid, &snip12, &session.public_bytes(), EXPIRY)
            .expect("binding digest must build");
    let sig = session.sign(&digest).bytes;
    let material = VerifierMaterial::AccountBinding {
        snip12_authorize_digest: snip12,
        session_public: session.public_bytes(),
        binding_valid_until: EXPIRY,
    };
    verify_owner_signature(&owner, &digest, &sig, &material)
        .expect("valid session-key signature must verify");

    // 换会话密钥
    let rogue = secp_key(13);
    let m2 = VerifierMaterial::AccountBinding {
        snip12_authorize_digest: snip12,
        session_public: rogue.public_bytes(),
        binding_valid_until: EXPIRY,
    };
    assert!(matches!(
        verify_owner_signature(&owner, &digest, &sig, &m2),
        Err(OwnerV2Error::BadSignature)
    ));

    // 换 SNIP-12 授权摘要（binding 摘要重算变化）
    let m3 = VerifierMaterial::AccountBinding {
        snip12_authorize_digest: felt32(0x7F),
        session_public: session.public_bytes(),
        binding_valid_until: EXPIRY,
    };
    assert!(matches!(
        verify_owner_signature(&owner, &digest, &sig, &m3),
        Err(OwnerV2Error::BadSignature)
    ));

    // binding_id 不一致（ref 指向另一条授权记录）
    let owner_other_bid = binding_ref(addr, felt32(0x45), 0);
    assert!(verify_owner_signature(&owner_other_bid, &digest, &sig, &material).is_err());

    // binding_id 缺失 → 结构拒绝
    let no_bid = OwnerRef {
        scheme: SignatureScheme::StarknetAccountBinding,
        account_id: addr,
        key_version: 0,
        binding_id: None,
    };
    assert!(matches!(
        validate_owner_ref(&no_bid),
        Err(OwnerV2Error::OwnerRefInvalid(_))
    ));

    // 材料/方案不匹配 → fail-closed
    assert!(matches!(
        verify_owner_signature(&owner, &digest, &sig, &VerifierMaterial::StarkCurve),
        Err(OwnerV2Error::MaterialMismatch(_))
    ));
}

// ---------------------------------------------------------------------------
// 4) nonce 单调 + expiry
// ---------------------------------------------------------------------------

#[test]
fn envelope_freshness_expiry_and_nonce_monotonic() {
    let key = secp_key(7);
    let envelope = |nonce: u64, expiry: u64| SignatureEnvelope {
        scheme: SignatureScheme::LegacySecp256k1,
        signer_ref: legacy_ref(&key, 0),
        typed_data_digest: felt32(1),
        signature: key.sign(&felt32(1)).bytes,
        nonce,
        expiry,
    };

    // 边界：now = expiry - 1 有效；now = expiry 过期
    assert!(check_envelope_freshness(&envelope(1, NOW + 1), NOW, None).is_ok());
    assert!(matches!(
        check_envelope_freshness(&envelope(1, NOW), NOW, None),
        Err(OwnerV2Error::Expired { .. })
    ));
    assert!(matches!(
        check_envelope_freshness(&envelope(1, NOW - 1), NOW, None),
        Err(OwnerV2Error::Expired { .. })
    ));

    // 首个信封任意 nonce
    assert!(check_envelope_freshness(&envelope(0, EXPIRY), NOW, None).is_ok());

    // 重放：等于 / 小于已见 nonce 均拒
    assert!(matches!(
        check_envelope_freshness(&envelope(5, EXPIRY), NOW, Some(5)),
        Err(OwnerV2Error::NonceReplay { got: 5, last: 5 })
    ));
    assert!(matches!(
        check_envelope_freshness(&envelope(4, EXPIRY), NOW, Some(5)),
        Err(OwnerV2Error::NonceReplay { got: 4, last: 5 })
    ));

    // 严格递增通过
    assert!(check_envelope_freshness(&envelope(6, EXPIRY), NOW, Some(5)).is_ok());
}

// ---------------------------------------------------------------------------
// 5) owner_commitment 跨 scheme 分离（同 account_id 不同 scheme 必不同）
// ---------------------------------------------------------------------------

#[test]
fn owner_commitment_scheme_separation() {
    // 同一个 felt-canonical account_id 放进三种 scheme
    let account = felt32(0x66);
    let bid = felt32(0x67);
    let legacy = OwnerRef {
        scheme: SignatureScheme::LegacySecp256k1,
        account_id: account,
        key_version: 0,
        binding_id: None,
    };
    let stark = OwnerRef {
        scheme: SignatureScheme::StarkCurve,
        account_id: account,
        key_version: 0,
        binding_id: None,
    };
    let binding = OwnerRef {
        scheme: SignatureScheme::StarknetAccountBinding,
        account_id: account,
        key_version: 0,
        binding_id: Some(bid),
    };
    let c0 = owner_commitment(&legacy);
    let c1 = owner_commitment(&stark);
    let c2 = owner_commitment(&binding);
    assert_ne!(
        c0, c1,
        "same account_id, different scheme → different commitment"
    );
    assert_ne!(c0, c2);
    assert_ne!(c1, c2);

    // key_version 参与
    let mut v1 = stark.clone();
    v1.key_version = 1;
    assert_ne!(c1, owner_commitment(&v1));

    // binding_id 参与
    let mut b2 = binding.clone();
    b2.binding_id = Some(felt32(0x68));
    assert_ne!(c2, owner_commitment(&b2));

    // 确定性
    assert_eq!(c1, owner_commitment(&stark));
}

#[test]
fn v2_spend_digest_separation() {
    let commitment = felt32(0x10);
    let nullifier = felt32(0x11);
    let scope = b"transfer.v2.test";
    let eff = effect();

    // 仅 scheme 不同的两个等价 OwnerRef → 摘要必不同
    let account = stark_pubkey(0xACE);
    let stark = OwnerRef {
        scheme: SignatureScheme::StarkCurve,
        account_id: account,
        key_version: 0,
        binding_id: None,
    };
    let legacy = OwnerRef {
        scheme: SignatureScheme::LegacySecp256k1,
        account_id: account,
        key_version: 0,
        binding_id: None,
    };
    let d_stark = v2_spend_digest(&stark, &commitment, &nullifier, scope, &eff);
    let d_legacy = v2_spend_digest(&legacy, &commitment, &nullifier, scope, &eff);
    assert_ne!(d_stark, d_legacy);

    // 仅 key_version 不同 → 摘要必不同
    let mut stark_v1 = stark.clone();
    stark_v1.key_version = 1;
    assert_ne!(
        d_stark,
        v2_spend_digest(&stark_v1, &commitment, &nullifier, scope, &eff)
    );

    // scope 参与
    assert_ne!(
        d_stark,
        v2_spend_digest(&stark, &commitment, &nullifier, b"settle.v2.test", &eff)
    );
}

// ---------------------------------------------------------------------------
// 6) MigrateNote：三 scheme 正例 + 每字段篡改拒
// ---------------------------------------------------------------------------

#[test]
fn migrate_note_positive_all_three_schemes() {
    for old in [
        Signer::Legacy(7),
        Signer::Stark(0xACE),
        Signer::Binding(11, felt32(0x33), felt32(0x44)),
    ] {
        let material = old.material();
        let record = signed_migrate(old);
        validate_migrate_note(&record, NOW, Some(4), &material)
            .unwrap_or_else(|e| panic!("valid migrate must pass: {e:?}"));
    }
}

#[test]
fn migrate_note_field_tamper_matrix() {
    let base = signed_migrate(Signer::Legacy(7));
    let material = VerifierMaterial::LegacySecp256k1 {
        presented_public: secp_key(7).public_bytes(),
    };
    let res = |r: &MigrateNoteRecord| validate_migrate_note(r, NOW, Some(4), &material);

    // 旧承诺为零
    let mut r = base.clone();
    r.old_commitment = [0u8; 32];
    assert!(matches!(res(&r), Err(OwnerV2Error::ZeroField(_))));

    // migration_nonce 为零
    let mut r = base.clone();
    r.migration_nonce = [0u8; 32];
    assert!(matches!(res(&r), Err(OwnerV2Error::ZeroField(_))));

    // amount == 0
    let mut r = base.clone();
    r.amount = 0;
    assert!(matches!(res(&r), Err(OwnerV2Error::InvalidAmount(0))));

    // 过期（now == expiry 即过期）
    assert!(matches!(
        validate_migrate_note(&base, EXPIRY, Some(4), &material),
        Err(OwnerV2Error::Expired { .. })
    ));

    // nonce 重放
    assert!(matches!(
        validate_migrate_note(&base, NOW, Some(5), &material),
        Err(OwnerV2Error::NonceReplay { got: 5, last: 5 })
    ));

    // 摘要一致：改 amount 不重签 → typed_data_digest 过期
    let mut r = base.clone();
    r.amount = 251;
    assert!(matches!(res(&r), Err(OwnerV2Error::DigestMismatch)));

    // network_id / abi_version 绑定：换网 / 换目标 ABI 版本 → 摘要不一致
    let mut r = base.clone();
    r.network_id = blake2s32(&[b"zchain-poker-othernet"]);
    assert!(matches!(res(&r), Err(OwnerV2Error::DigestMismatch)));
    let mut r = base.clone();
    r.abi_version = 3;
    assert!(matches!(res(&r), Err(OwnerV2Error::DigestMismatch)));

    // 篡改旧签名字节
    let mut r = base.clone();
    r.old_owner_sig.signature[32] ^= 0x01;
    assert!(matches!(res(&r), Err(OwnerV2Error::BadSignature)));

    // 他人签名（同 account_id 不可能，签名者密钥不符）
    let mut r = base.clone();
    let stranger = secp_key(99);
    r.old_owner_sig.signature = stranger.sign(&r.old_owner_sig.typed_data_digest).bytes;
    assert!(res(&r).is_err());

    // 换 scheme 字节（信封/签名者 scheme 改动 → 结构或摘要层面拒）
    let mut r = base.clone();
    r.old_owner_sig.signer_ref.scheme = SignatureScheme::StarkCurve;
    assert!(res(&r).is_err());

    // new_owner_ref 非法：零 account_id
    let mut r = base.clone();
    r.new_owner_ref.account_id = [0u8; 32];
    assert!(matches!(res(&r), Err(OwnerV2Error::ZeroField(_))));

    // new_owner_ref 非法：StarkCurve 非 canonical felt
    let mut r = base.clone();
    r.new_owner_ref = OwnerRef {
        scheme: SignatureScheme::StarkCurve,
        account_id: [0xff; 32],
        key_version: 0,
        binding_id: None,
    };
    assert!(matches!(res(&r), Err(OwnerV2Error::OwnerRefInvalid(_))));

    // 资产类信息在摘要内（换资产类 → 摘要不一致）
    let mut r = base.clone();
    r.asset_class = AssetClass::Real;
    assert!(matches!(res(&r), Err(OwnerV2Error::DigestMismatch)));
}

// ---------------------------------------------------------------------------
// 7) SNIP-12 互操作冻结向量（来源：poker-wallet account_binding）
// ---------------------------------------------------------------------------

/// 冻结向量：来源 `poker-wallet/tests/acceptance.rs`
/// `wallet_acc_3a_authorize_digest_verifiable_by_stark_crypto`（SNIP-12
/// rev1，域 `Snip12Domain::zchain("zchain-devnet-1")`；消息字段逐项取自
/// 该测试夹具）。摘要值由 wallet_core `authorize_message_hash` 对同一
/// 输入复算冻结（本 crate 无 keccak 依赖，不反向依赖 poker-wallet）。
mod snip12_vector {
    /// delegated/session 公钥 = secp secret `[9u8; 32]` 的压缩公钥。
    pub const DELEGATED_PUBLIC: &str =
        "0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967";
    /// `AuthorizeZChainKey` message hash（SNIP-12 rev1）。
    pub const MESSAGE_HASH: &str =
        "0108780ad34e8ed9b8cfb3ffefef7a1c0e6134a385200ce93a8820da6bb70436";
    /// 授权方 Stark 账户公钥（secret = 0xBEEF）。
    pub const ACCOUNT_PUBLIC: &str =
        "007e99a9880c7dcd3bdf55193f5a3ffc0cfab67e20fd00d51541528a4123c5da";
    /// 账户签名 r。
    pub const SIG_R: &str = "01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca";
    /// 账户签名 s。
    pub const SIG_S: &str = "016368de8bd5f6d44317b4ff6544a90b78a0707f4b9bc99230ac2e3edd636c74";
}

#[test]
fn snip12_interop_vector_binding_verification() {
    let v = &snip12_vector::DELEGATED_PUBLIC;
    let delegated = h33(v);
    let message_hash = h32(snip12_vector::MESSAGE_HASH);
    let account_public = h32(snip12_vector::ACCOUNT_PUBLIC);
    let sig_r = h32(snip12_vector::SIG_R);
    let sig_s = h32(snip12_vector::SIG_S);

    // 向量自证 1：delegated 公钥与本 crate 的 secp seed [9;32] 派生一致
    //（wallet 侧夹具 owner(9) 同源推导）。
    assert_eq!(
        secp_key(9).public_bytes(),
        delegated,
        "frozen delegated key must equal wallet fixture owner(9)"
    );

    // 向量自证 2：授权方 Stark 账户对 SNIP-12 摘要的签名（wallet 测试同款
    // 验证路径）可由 starknet-crypto 独立复核。
    let acct = FieldElement::from_bytes_be(&account_public).expect("canonical felt");
    let hash = FieldElement::from_bytes_be(&message_hash).expect("canonical felt");
    assert!(
        starknet_crypto::verify(
            &acct,
            &hash,
            &FieldElement::from_bytes_be(&sig_r).unwrap(),
            &FieldElement::from_bytes_be(&sig_s).unwrap(),
        )
        .expect("stark verify")
    );

    // appchain 侧 alpha 路径：账户地址/binding_id 取 wallet 夹具
    // （account_address = felt_test(2), binding_id = felt_test(1)），
    // 冻结 SNIP-12 摘要 + 会话密钥签名 → binding 验签通过。
    let session = secp_key(9);
    let addr = felt32(2);
    let bid = felt32(1);
    let valid_until = 2_000u64; // wallet 夹具 valid_until
    let binding_digest =
        binding_authorization_digest(&addr, &bid, &message_hash, &delegated, valid_until)
            .expect("frozen vector inputs must be canonical");
    let sig = session.sign(&binding_digest).bytes;

    let owner = binding_ref(addr, bid, 0);
    let material = VerifierMaterial::AccountBinding {
        snip12_authorize_digest: message_hash,
        session_public: delegated,
        binding_valid_until: valid_until,
    };
    verify_owner_signature(&owner, &binding_digest, &sig, &material)
        .expect("interop binding verification must pass");

    // 篡改 SNIP-12 摘要 → binding 验签拒
    let mut bad_hash = message_hash;
    bad_hash[0] ^= 0x01;
    let bad_material = VerifierMaterial::AccountBinding {
        snip12_authorize_digest: bad_hash,
        session_public: delegated,
        binding_valid_until: valid_until,
    };
    assert!(verify_owner_signature(&owner, &binding_digest, &sig, &bad_material).is_err());
}

// ---------------------------------------------------------------------------
// 8) borsh 稳定 ABI
// ---------------------------------------------------------------------------

#[test]
fn borsh_scheme_discriminants_frozen_and_roundtrip() {
    // 判别值冻结（ABI v2 附录钉死）
    assert_eq!(
        borsh::to_vec(&SignatureScheme::LegacySecp256k1).unwrap(),
        vec![0u8]
    );
    assert_eq!(
        borsh::to_vec(&SignatureScheme::StarkCurve).unwrap(),
        vec![1u8]
    );
    assert_eq!(
        borsh::to_vec(&SignatureScheme::StarknetAccountBinding).unwrap(),
        vec![2u8]
    );
    assert!(matches!(
        SignatureScheme::from_u8(3),
        Err(OwnerV2Error::SchemeMismatch(_))
    ));

    // OwnerRef / SignatureEnvelope / MigrateNoteRecord roundtrip
    let base = signed_migrate(Signer::Stark(0xACE));
    for bytes in [
        borsh::to_vec(&legacy_ref(&secp_key(7), 3)).unwrap(),
        borsh::to_vec(&base.old_owner_sig).unwrap(),
        borsh::to_vec(&base).unwrap(),
    ] {
        assert!(!bytes.is_empty());
    }
    let r: MigrateNoteRecord = borsh::from_slice(&borsh::to_vec(&base).unwrap()).unwrap();
    assert_eq!(r, base);
    let e: SignatureEnvelope =
        borsh::from_slice(&borsh::to_vec(&base.old_owner_sig).unwrap()).unwrap();
    assert_eq!(e, base.old_owner_sig);
    let o: OwnerRef = borsh::from_slice(&borsh::to_vec(&base.new_owner_ref).unwrap()).unwrap();
    assert_eq!(o, base.new_owner_ref);
}
