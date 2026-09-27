//! EIP-155 遗留交易签名（secp256k1 + low-s 规范化）。
//!
//! 选型理由：EIP-155 全网接受（含 Monad），类型面最小（无 access list /
//! 无 1559 双价格域）；sighash 域绑定 chain_id，天然防主网/测试网重放
//! （与 zchain 全签名域绑定 chain_id 的纪律一致）。

use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Message, PublicKey, SecretKey, SECP256K1,
};

use crate::error::SettlementError;
use crate::keccak::keccak256;
use crate::rlp;

/// 遗留交易字段（EIP-155 签名域：前 6 字段 + chain_id + 0,0）。
#[derive(Debug, Clone)]
pub struct LegacyTx {
    /// 账户 nonce。
    pub nonce: u64,
    /// gas 价格（wei）。
    pub gas_price: u128,
    /// gas 上限。
    pub gas_limit: u128,
    /// 收款地址（合约创建 = None）。
    pub to: Option<[u8; 20]>,
    /// 转账金额（wei）。
    pub value: u128,
    /// calldata。
    pub data: Vec<u8>,
}

/// 签名结果：原始交易 RLP（`eth_sendRawTransaction` 入参）+ 交易哈希。
#[derive(Debug, Clone)]
pub struct SignedTx {
    /// 签名后完整 RLP。
    pub raw: Vec<u8>,
    /// tx hash = keccak(签名后 RLP)。
    pub hash: [u8; 32],
}

/// 签名凭据（secp256k1 私钥 + 派生地址缓存）。
#[derive(Clone)]
pub struct Credentials {
    secret: SecretKey,
    address: [u8; 20],
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 永不打印私钥材料。
        f.debug_struct("Credentials")
            .field("address", &hex::encode(self.address))
            .finish()
    }
}

impl Credentials {
    /// 从 32B 私钥构造。
    ///
    /// # Errors
    /// 私钥非法（0 / >= 曲线阶）→ [`SettlementError::Signing`]。
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, SettlementError> {
        let secret =
            SecretKey::from_slice(secret).map_err(|e| SettlementError::Signing(e.to_string()))?;
        let address = Self::address_of(&secret);
        Ok(Self { secret, address })
    }

    /// 从 hex（0x 前缀可选，64 hex 字符）构造。
    ///
    /// # Errors
    /// hex 非法或长度不符 → [`SettlementError::InvalidArgument`]。
    pub fn from_hex(input: &str) -> Result<Self, SettlementError> {
        let trimmed = input.trim().strip_prefix("0x").unwrap_or(input.trim());
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut bytes)
            .map_err(|e| SettlementError::InvalidArgument(format!("private key hex: {e}")))?;
        Self::from_bytes(&bytes)
    }

    /// 签发方地址（20B）。
    #[must_use]
    pub fn address(&self) -> [u8; 20] {
        self.address
    }

    /// 地址派生：keccak(非压缩公钥[1..65])[12..32]。
    #[must_use]
    pub fn address_of(secret: &SecretKey) -> [u8; 20] {
        let public = PublicKey::from_secret_key(SECP256K1, secret);
        Self::address_of_pubkey(&public)
    }

    /// 从公钥派生地址（测试/校验共用）。
    #[must_use]
    pub fn address_of_pubkey(public: &PublicKey) -> [u8; 20] {
        let serialized = public.serialize_uncompressed();
        let hash = keccak256(&serialized[1..65]);
        hash[12..32].try_into().expect("20 bytes from 32")
    }

    /// EIP-155 签名。
    ///
    /// # Errors
    /// 签名失败 → [`SettlementError::Signing`]。
    pub fn sign_eip155(&self, tx: &LegacyTx, chain_id: u64) -> Result<SignedTx, SettlementError> {
        // 签名摘要域：[6 字段, chainId, 0, 0]。
        let sighash_payload = eip155_unsigned_payload(tx, chain_id);
        let sighash = keccak256(&rlp::encode_list(&sighash_payload));

        let (recid, compact) = sign_low_s(&self.secret, &sighash)?;
        // EIP-155：v = 35 + 2*chainId + parity。
        let parity = u128::from(u8::from(recid.to_i32() != 0));
        let v = 35u128 + u128::from(chain_id) * 2 + parity;

        // 广播体：**只有 9 项** = [6 字段, v, r, s]（chainId/占位段仅进
        // 签名摘要，不进广播列表——多 3 项即 "Transaction decoding error"，
        //Monad 测试网 probe 实测抓出过此布局错误）。
        let mut signed = eip155_tx_items(tx);
        signed.extend_from_slice(&rlp::encode_u128(v));
        signed.extend_from_slice(&rlp::encode_bytes(&compact[..32]));
        signed.extend_from_slice(&rlp::encode_bytes(&compact[32..]));
        let raw = rlp::encode_list(&signed);
        Ok(SignedTx { hash: keccak256(&raw), raw })
    }
}

/// 遗留交易前 6 字段（签名摘要与广播体共用）。
fn eip155_tx_items(tx: &LegacyTx) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&rlp::encode_u64(tx.nonce));
    payload.extend_from_slice(&rlp::encode_u128(tx.gas_price));
    payload.extend_from_slice(&rlp::encode_u128(tx.gas_limit));
    match tx.to {
        Some(addr) => payload.extend_from_slice(&rlp::encode_bytes(&addr)),
        None => payload.extend_from_slice(&rlp::encode_bytes(b"")),
    }
    payload.extend_from_slice(&rlp::encode_u128(tx.value));
    payload.extend_from_slice(&rlp::encode_bytes(&tx.data));
    payload
}

/// EIP-155 未签名段：rlp 编码前的 9 项列表载荷（前 6 项 + chainId + 0,0）。
#[must_use]
pub fn eip155_unsigned_payload(tx: &LegacyTx, chain_id: u64) -> Vec<u8> {
    let mut payload = eip155_tx_items(tx);
    payload.extend_from_slice(&rlp::encode_u64(chain_id));
    payload.extend_from_slice(&rlp::encode_bytes(b""));
    payload.extend_from_slice(&rlp::encode_bytes(b""));
    payload
}

/// 签名 + low-s 规范化（EIP-2 语义；high-s 时翻转 recovery parity）。
fn sign_low_s(
    secret: &SecretKey,
    digest: &[u8; 32],
) -> Result<(RecoveryId, [u8; 64]), SettlementError> {
    let message = Message::from_digest(*digest);
    let sig: RecoverableSignature = SECP256K1.sign_ecdsa_recoverable(&message, secret);
    let (mut recid, mut compact) = sig.serialize_compact();
    // normalize_s 原地规范化（无返回值）：比较规范化前后的 s 判断是否翻转。
    let mut fixed =
        Signature::from_compact(&compact).map_err(|e| SettlementError::Signing(e.to_string()))?;
    fixed.normalize_s();
    let normalized = fixed.serialize_compact();
    if normalized != compact {
        // s → -s 时恢复点 y 奇偶翻转。
        recid = RecoveryId::from_i32(recid.to_i32() ^ 1)
            .map_err(|e| SettlementError::Signing(e.to_string()))?;
        compact = normalized;
    }
    Ok((recid, compact))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::ecdsa::RecoverableSignature;

    fn reference_tx() -> LegacyTx {
        LegacyTx {
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some([
                0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
                0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
            ]),
            value: 1_000_000_000_000_000_000,
            data: Vec::new(),
        }
    }

    /// EIP-155 规范示例（https://eips.ethereum.org/EIPS/eip-155）：签名数据、
    /// sighash、派生地址均为规范给出值。
    #[test]
    fn eip155_reference_vector_sighash() {
        let payload = eip155_unsigned_payload(&reference_tx(), 1);
        // 规范 signing data。
        assert_eq!(
            hex::encode(rlp::encode_list(&payload)),
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
        );
        // 规范 sighash。
        assert_eq!(
            hex::encode(keccak256(&rlp::encode_list(&payload))),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );
    }

    /// 规范私钥的派生地址（EIP-155 示例同一节）。
    #[test]
    fn address_derivation_vector() {
        let cred = Credentials::from_hex(
            "0x4646464646464646464646464646464646464646464646464646464646464646",
        )
        .expect("valid key");
        assert_eq!(
            hex::encode(cred.address()),
            "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
        );
    }

    /// 签名广播体结构校验：恰好 **9 项** = [6 字段, v, r, s]（chainId/占位
    /// 段只进签名摘要）。v/r/s 与 recid 布局全对拍——Monad 测试网实测抓出
    /// 过"签名摘要段被误并入广播体（12 项）"的解码错误，本测试防回归。
    #[test]
    fn signed_tx_layout_is_nine_items() {
        let cred = Credentials::from_hex(
            "0x4646464646464646464646464646464646464646464646464646464646464646",
        )
        .expect("valid key");
        let signed = cred.sign_eip155(&reference_tx(), 1).expect("signs");

        let items = crate::rlp::decode_list_items(&signed.raw).expect("decodes as list");
        assert_eq!(items.len(), 9, "legacy signed tx must have exactly 9 items");

        // item[0..6] 与未签名段前 6 项逐字节一致。
        let payload = eip155_unsigned_payload(&reference_tx(), 1);
        let unsigned = crate::rlp::decode_list_items(&rlp::encode_list(&payload))
            .expect("unsigned decodes");
        assert_eq!(unsigned.len(), 9, "unsigned payload is chainId + 0x0 + 0x0 + 6");
        for (i, item) in unsigned.iter().take(6).enumerate() {
            assert_eq!(&items[i], item, "item {i} mismatch");
        }
        // item[7]/[8] = r/s（非空、定长 32）；item[6] = v = 37。
        assert_eq!(items[6], vec![37]);
        assert_eq!(items[7].len(), 32);
        assert_eq!(items[8].len(), 32);
    }

    /// 签名自洽性：ec-recover(sighash, sig) 必须还原出签发地址；v 语义
    /// （35 + 2*chainId + parity）与 recid 一致；s 满足 low-s。
    #[test]
    fn signature_recovers_signer_and_is_low_s() {
        let cred = Credentials::from_hex(
            "0x4646464646464646464646464646464646464646464646464646464646464646",
        )
        .expect("valid key");
        let signed = cred.sign_eip155(&reference_tx(), 1).expect("signs");

        // v 在倒数第三个 rlp 项；raw 尾部固定为（compact 恒 32B）：
        // [0x25(v)] [0xa0, r(32B)] [0xa0, s(32B)] →
        // s 数据 len-32..len-1，s 前缀 len-33，r 数据 len-65..len-34，
        // r 前缀 len-66，v 位于 len-67。
        let raw = &signed.raw;
        let s_start = raw.len() - 32;
        let r_start = raw.len() - 65;
        assert_eq!(raw[r_start - 1], 0xa0, "r prefix");
        assert_eq!(raw[s_start - 1], 0xa0, "s prefix");
        let v = raw[r_start - 2];
        assert_eq!(v, 37, "v = 35 + 2*1 + parity");

        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&raw[r_start..r_start + 32]);
        compact[32..].copy_from_slice(&raw[s_start..]);

        // low-s 精确校验：规范化后 s 不变 ⇔ 已是 low-s。
        let mut probe = Signature::from_compact(&compact).expect("compact sig");
        let before = probe.serialize_compact();
        probe.normalize_s();
        assert_eq!(probe.serialize_compact(), before, "signature is low-s");

        let sighash = keccak256(&rlp::encode_list(&eip155_unsigned_payload(
            &reference_tx(),
            1,
        )));
        let parity = if v == 38 { 1 } else { 0 };
        let sig = RecoverableSignature::from_compact(
            &compact,
            RecoveryId::from_i32(parity).expect("parity"),
        )
        .expect("compact sig");
        let recovered = SECP256K1
            .recover_ecdsa(&Message::from_digest(sighash), &sig)
            .expect("recovers");
        assert_eq!(
            hex::encode(Credentials::address_of_pubkey(&recovered)),
            hex::encode(cred.address())
        );

        // 确定性：同钥同 tx 同 chainId 签名逐字节一致（RFC6979 nonce）。
        let again = cred.sign_eip155(&reference_tx(), 1).expect("signs again");
        assert_eq!(signed.raw, again.raw);
    }
}
