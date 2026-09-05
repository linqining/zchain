//! M1：Note 账本核心结构。
//!
//! 筹码的唯一真身是 owned note。v1 托管模式下 note 字段在账本中公开
//! （承诺树提供防篡改绑定，不提供匿名性——匿名性由承诺模型天然给出：
//! 链上只见承诺与 nullifier，v2 隐私升级不需要推翻结构）。
//!
//! ## 资产类隔离（fail-closed）
//!
//! `REAL`（真金）与 `PLAY`（休闲）在承诺哈希里是独立输入，且跨类互转在
//! 结算关系层不可证明（M2）。隔离是 AIR 语义，不是业务层断言。

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::error::{AppchainError, AppchainResult};
use crate::felt::{
    bytes32_to_felts, domain_felt, felt_from_u64, felt_to_bytes32,
    DOMAIN_NOTE_COMMITMENT, DOMAIN_NOTE_NULLIFIER,
};

/// 资产类。隔离语义：REAL 与 PLAY 不可互转、不可混树。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum AssetClass {
    /// 真金筹码（对应外部储备）。
    Real = 1,
    /// 休闲筹码（零监管敞口）。
    Play = 2,
}

impl AssetClass {
    /// ABI 数值。
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从 ABI 数值解析。
    ///
    /// # Errors
    /// 未定义数值拒绝（fail-closed）。
    pub fn from_u8(v: u8) -> AppchainResult<Self> {
        match v {
            1 => Ok(Self::Real),
            2 => Ok(Self::Play),
            _ => Err(AppchainError::OutOfRange("asset_class")),
        }
    }

    /// 静态名（错误信息用）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Real => "REAL",
            Self::Play => "PLAY",
        }
    }
}

/// 一张 owned note（ABI v1）。
///
/// 面额单位与 PokerVault 一致（STRK wei）；`table_id` 为 Some 时是桌内
/// seat note（结算输入），None 是自由余额 note。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct Note {
    /// 资产类（REAL/PLAY 隔离）。
    pub asset_class: AssetClass,
    /// 面额 > 0。
    pub amount: u64,
    /// owner 压缩公钥（33 字节）。
    pub owner: [u8; 33],
    /// 防重复 nonce（32 字节，铸币方生成）。
    pub nonce: [u8; 32],
    /// 桌绑定（seat note 时 Some）。
    pub table_id: Option<u64>,
}

impl Note {
    /// 构造校验：面额必须 > 0。
    ///
    /// # Errors
    /// amount == 0 → [`AppchainError::InvalidAmount`]。
    pub fn new(
        asset_class: AssetClass,
        amount: u64,
        owner: [u8; 33],
        nonce: [u8; 32],
        table_id: Option<u64>,
    ) -> AppchainResult<Self> {
        if amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        Ok(Self {
            asset_class,
            amount,
            owner,
            nonce,
            table_id,
        })
    }

    /// 承诺：`poseidon(DOMAIN, class, amount, x_hi, x_lo, y_hi, y_lo,
    /// nonce_hi, nonce_lo, table)`——全部无损编码。
    ///
    /// table_id 用 0 表示 None，1+ 表示 Some(id)+1（避免 felt 空间歧义）。
    #[must_use]
    pub fn commitment(&self) -> FieldElement {
        let (x, y) = crate::keys::public_xy_bytes_from_compressed(&self.owner);
        let (x_hi, x_lo) = bytes32_to_felts(&x);
        let (y_hi, y_lo) = bytes32_to_felts(&y);
        let (n_hi, n_lo) = bytes32_to_felts(&self.nonce);
        let table = match self.table_id {
            None => FieldElement::ZERO,
            Some(id) => felt_from_u64(id.wrapping_add(1)),
        };
        poseidon_hash_many(&[
            domain_felt(DOMAIN_NOTE_COMMITMENT),
            felt_from_u64(u64::from(self.asset_class.as_u8())),
            felt_from_u64(self.amount),
            x_hi,
            x_lo,
            y_hi,
            y_lo,
            n_hi,
            n_lo,
            table,
        ])
    }

    /// 承诺的 32 字节编码。
    #[must_use]
    pub fn commitment_bytes(&self) -> [u8; 32] {
        felt_to_bytes32(&self.commitment())
    }

    /// nullifier 派生：`poseidon(DOMAIN, commitment, secret_hi, secret_lo)`。
    ///
    /// spend_secret 由 owner 客户端派生持有；账本层只验证 nullifier 与
    /// owner 签名的绑定关系（见 [`crate::settlement`]）。
    #[must_use]
    pub fn nullifier(
        &self,
        spend_secret: &[u8; 32],
    ) -> FieldElement {
        let c = self.commitment();
        let (s_hi, s_lo) = bytes32_to_felts(spend_secret);
        poseidon_hash_many(&[domain_felt(DOMAIN_NOTE_NULLIFIER), c, s_hi, s_lo])
    }

    /// 资产类匹配断言。
    ///
    /// # Errors
    /// 类别不同 → [`AppchainError::AssetClassMismatch`]。
    pub fn assert_same_class(&self, other: &Note) -> AppchainResult<()> {
        if self.asset_class != other.asset_class {
            return Err(AppchainError::AssetClassMismatch(
                self.asset_class.name(),
                other.asset_class.name(),
            ));
        }
        Ok(())
    }
}

/// 输出 note 规格（铸造侧，无 owner 公钥前置于结算输出）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct NoteSpec {
    /// 资产类。
    pub asset_class: AssetClass,
    /// 面额 > 0。
    pub amount: u64,
    /// 收款人压缩公钥。
    pub owner: [u8; 33],
    /// 桌绑定。
    pub table_id: Option<u64>,
}

impl NoteSpec {
    /// 铸造成实际 note（nonce 由铸币方补齐）。
    ///
    /// # Errors
    /// amount == 0 → [`AppchainError::InvalidAmount`]。
    pub fn mint(self, nonce: [u8; 32]) -> AppchainResult<Note> {
        Note::new(
            self.asset_class,
            self.amount,
            self.owner,
            nonce,
            self.table_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(seed: u8) -> [u8; 33] {
        let mut s = [seed; 32];
        s[31] = seed;
        crate::keys::OwnerKey::from_seed(&s)
            .unwrap()
            .public_bytes()
    }

    #[test]
    fn commitment_is_deterministic_and_sensitive() {
        let n1 = Note::new(AssetClass::Real, 100, owner(1), [1u8; 32], None).unwrap();
        let n2 = Note::new(AssetClass::Real, 100, owner(1), [1u8; 32], None).unwrap();
        let n3 = Note::new(AssetClass::Real, 101, owner(1), [1u8; 32], None).unwrap();
        assert_eq!(n1.commitment(), n2.commitment());
        assert_ne!(n1.commitment(), n3.commitment());
    }

    #[test]
    fn asset_class_isolation_in_commitment() {
        let a = Note::new(AssetClass::Real, 100, owner(1), [1u8; 32], None).unwrap();
        let b = Note::new(AssetClass::Play, 100, owner(1), [1u8; 32], None).unwrap();
        assert_ne!(a.commitment(), b.commitment());
        assert!(a.assert_same_class(&b).is_err());
    }

    #[test]
    fn zero_amount_rejected() {
        assert!(Note::new(AssetClass::Play, 0, owner(1), [0u8; 32], None).is_err());
    }

    #[test]
    fn nullifier_depends_on_secret() {
        let n = Note::new(AssetClass::Real, 100, owner(1), [1u8; 32], None).unwrap();
        assert_ne!(n.nullifier(&[1u8; 32]), n.nullifier(&[2u8; 32]));
    }
}
