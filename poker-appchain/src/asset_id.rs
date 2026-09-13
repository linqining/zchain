//! TE-M1：`AssetId` 资产模型（ABI v2 层新类型；排期表 §6 TE-M1 行）。
//!
//! 把 v1 二元 `AssetClass(Real/Play)` 推广为**资产域 + 币种/代币**两级：
//!
//! ```text
//! AssetId := { domain: AssetDomain, token_id: u32 }
//! REAL 域（domain=1）：token_id ∈ {0=NATIVE, 1=USDT, 2=USDC}（封闭枚举，
//!                     TE-M2 启用；本模块先冻结判别值与注册表结构）
//! GAME 域（domain=2）：token_id 由 GTS 注册表分配（TE-M3；本模块只留
//!                     结构，不实现发行）
//! ```
//!
//! ## 与 v1 `AssetClass` 的映射（冻结）
//!
//! | v1（`note.rs`，冻结不动） | v2（本模块） |
//! |---|---|
//! | `AssetClass::Real`（判别值 1） | `AssetId { domain: REAL, token_id: TOKEN_NATIVE(0) }` |
//! | `AssetClass::Play`（判别值 2） | `AssetId { domain: GAME, token_id: 0 }`（遗留特例） |
//!
//! - **PLAY 不建独立域/类型**：它是 GAME 域 `token_id = 0` 的遗留特例
//!   （零监管敞口语义不变：无 anchor、不可赎回，见 plan-token-economy
//!   §3.8）——本模块只以文档与常量 [`AssetId::GAME_PLAY`] 固定它。
//! - **v1 路径零变更**：`note.rs`（v1 Note ABI 冻结）、v1 结算
//!   （`settlement.rs`）、v1 托管 finality 门（`vault.rs`）继续按
//!   `AssetClass` 工作；`AssetId` 只进入 v2 note 路径
//!   （`note_v2.rs`）。v1 → v2 资产身份经 [`AssetId::of_v1`] 冻结映射
//!   升维（MigrateNote 迁移即用此映射），不存在第二种换算。
//!
//! ## 承诺与隔离（INV-TE-1）
//!
//! [`asset_commitment`] 是**域分离**的单 felt 资产承诺
//! （`poseidon("zchain.asset.v2.id", domain, token_id)`），整体进入
//! v2 note 承诺 preimage——`token_id` 不进承诺 = 同域不同币种可互换 =
//! 对账与桌绑定全盘失效，因此它是承诺/AIR 层输入而非展示字段。守恒/
//! 混转校验从"同 AssetClass"升级为"同 AssetId"（domain 与 token_id
//! **任一**不同即 [`crate::error::AppchainError::AssetMismatch`]）。
//!
//! ## finality 语义决策（冻结）
//!
//! 提现/出证 finality 门按 **domain** 判，不按 token 判：REAL 域
//! **任何** token（含 TE-M2 的 USDT/USDC）走 finality 门；GAME 域任何
//! token（含遗留 PLAY）豁免（软确认语义，§5.1 分层）。判别谓词是
//! [`AssetId::is_real_domain`]——TE-M2 扩展托管分账时以此为准，不得
//! 改为逐 token 白名单。
//!
//! ## 边界（如实声明）
//!
//! - GAME 域发行（GTS 注册表 / IssueGameToken）**本任务不实现**：
//!   注册表结构以常量与谓词占位（[`AssetDomain::is_registered_token`]
//!   是唯一扩展点）；
//! - REAL 多币种提现通道 / 托管按币种分账（CustodyLedger per-code）
//!   **属 TE-M2**：本模块只冻结 token 判别值；
//! - REAL 域封闭枚举的**强制点在铸造/准入边界的构造器**
//!   [`AssetId::real`]（fail-closed）；类型层不阻止 borsh 反序列化出
//!   "REAL 域 + 未注册 token" 的值——该值只可能来自伪造载荷，会在
//!   参与守恒/迁移比对时因与任何合法账本资产不等而被拒
//!   （fail-closed：不认识 ≠ 接受）。

use core::fmt;

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::error::{AppchainError, AppchainResult};
use crate::felt::{domain_felt, felt_from_u64};
use crate::note::AssetClass;

// ---------------------------------------------------------------------------
// 域标签（冻结）
// ---------------------------------------------------------------------------

/// 域标签：AssetId 域分离承诺（`zchain.asset.v2.id`，ABI_ASSET_ID.md 冻结；
/// 独立于 `zchain.note.v2` 命名空间，与 felt.rs v1 常量表无关）。
pub const DOMAIN_ASSET_ID_COMMITMENT: &[u8] = b"zchain.asset.v2.id";

// ---------------------------------------------------------------------------
// REAL 域 token 常量（判别值冻结；TE-M2 启用，本模块先冻结数值）
// ---------------------------------------------------------------------------

/// REAL 域：原生代币（= v1 `AssetClass::Real` 的映射目标）。
pub const TOKEN_NATIVE: u32 = 0;
/// REAL 域：USDT（TE-M2 启用）。
pub const TOKEN_USDT: u32 = 1;
/// REAL 域：USDC（TE-M2 启用）。
pub const TOKEN_USDC: u32 = 2;

/// REAL 域封闭枚举（v1 只有三种；新增币种 = ABI 版本升级，plan §1.1）。
pub const REAL_DOMAIN_TOKENS: [u32; 3] = [TOKEN_NATIVE, TOKEN_USDT, TOKEN_USDC];

/// GAME 域：遗留休闲筹码（v1 `AssetClass::Play` 的映射目标；无 anchor、
/// 不可赎回。GTS 正式发行币由注册表分配 token_id ≥ 1，TE-M3）。
pub const GAME_TOKEN_PLAY: u32 = 0;

// ---------------------------------------------------------------------------
// AssetDomain
// ---------------------------------------------------------------------------

/// 资产域（判别值**冻结**：REAL=1 / GAME=2；追加新域 = ABI 版本升级）。
///
/// borsh 编码即判别值字节（`use_discriminant = true`，与 v1 `AssetClass`
/// 同纪律）：REAL → `0x01`，GAME → `0x02`。未定义数值反序列化拒绝
/// （fail-closed）。
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum AssetDomain {
    /// REAL 域（真金筹码；外部储备 1:1，提现走 finality 门）。
    Real = 1,
    /// GAME 域（游戏筹码；含遗留 PLAY 特例，提现豁免 finality 门）。
    Game = 2,
}

impl AssetDomain {
    /// ABI 数值（判别值冻结）。
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从 ABI 数值解析。
    ///
    /// # Errors
    /// 未定义数值拒绝（fail-closed；域集合封闭）。
    pub fn from_u8(v: u8) -> AppchainResult<Self> {
        match v {
            1 => Ok(Self::Real),
            2 => Ok(Self::Game),
            _ => Err(AppchainError::OutOfRange("asset_domain")),
        }
    }

    /// 静态名（错误信息用）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Real => "REAL",
            Self::Game => "GAME",
        }
    }

    /// 该域 token_id 是否已注册（结构占位）。
    ///
    /// REAL 域：封闭枚举 [`REAL_DOMAIN_TOKENS`]（0/1/2）。GAME 域：注册
    /// 表分配属 TE-M3——本版只有遗留 token 0 结构性存在，返回
    /// `token_id == GAME_TOKEN_PLAY`；后续注册表落地时本谓词是唯一
    /// 扩展点（发行入口必须经它，不得绕过）。
    #[must_use]
    pub fn is_registered_token(self, token_id: u32) -> bool {
        match self {
            Self::Real => REAL_DOMAIN_TOKENS.contains(&token_id),
            Self::Game => token_id == GAME_TOKEN_PLAY,
        }
    }

    /// TE-M3 追加（`is_registered_token` 扩展点的**注册表感知**形式；
    /// GTS 发行/销毁入口必须经本谓词，不得绕过——见模块文档"扩展点"）：
    ///
    /// - REAL 域：与静态谓词逐点一致（封闭枚举）；
    /// - GAME 域：遗留 PLAY(0) **或**已登记 GTS 注册表
    ///   （[`crate::game_token::GameTokenRegistry`]）的 token。
    ///
    /// 注意：本谓词是**准入必要条件**不是充分条件——GTS 发行/销毁还需
    /// 注册表内的规格（faucet/rate/max_supply）与操作语义核对；遗留
    /// PLAY(0) 经此为 true 但无 GTS 规格（Issue/Burn 另拒）。
    #[must_use]
    pub fn is_registered_token_in(
        self,
        token_id: u32,
        game_registry: &crate::game_token::GameTokenRegistry,
    ) -> bool {
        match self {
            Self::Real => REAL_DOMAIN_TOKENS.contains(&token_id),
            Self::Game => token_id == GAME_TOKEN_PLAY || game_registry.contains(token_id),
        }
    }
}

// ---------------------------------------------------------------------------
// AssetId
// ---------------------------------------------------------------------------

/// 资产身份（ABI v2 / TE-M1）：`domain + token_id` 二元组。
///
/// borsh 字段序冻结：`domain`（u8 判别值）→ `token_id`（u32 LE）。
/// 整体参与 v2 note 承诺（经 [`asset_commitment`] 域分离哈希）；
/// 守恒/混转校验按本类型**全等**分组（ INV-TE-1：跨 `AssetId` 的
/// Transfer / BuyIn / Settle 一律 [`AppchainError::AssetMismatch`] 拒绝）。
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct AssetId {
    /// 资产域。
    pub domain: AssetDomain,
    /// 域内币种/代币编号（REAL：封闭枚举；GAME：注册表分配）。
    pub token_id: u32,
}

impl AssetId {
    /// REAL 域原生代币（= v1 `AssetClass::Real`）。
    pub const REAL_NATIVE: Self = Self {
        domain: AssetDomain::Real,
        token_id: TOKEN_NATIVE,
    };
    /// REAL 域 USDT（TE-M2 启用）。
    pub const REAL_USDT: Self = Self {
        domain: AssetDomain::Real,
        token_id: TOKEN_USDT,
    };
    /// REAL 域 USDC（TE-M2 启用）。
    pub const REAL_USDC: Self = Self {
        domain: AssetDomain::Real,
        token_id: TOKEN_USDC,
    };
    /// GAME 域遗留休闲筹码（= v1 `AssetClass::Play`）。
    pub const GAME_PLAY: Self = Self {
        domain: AssetDomain::Game,
        token_id: GAME_TOKEN_PLAY,
    };

    /// 构造 REAL 域资产（封闭枚举强制点，fail-closed）。
    ///
    /// # Errors
    /// `token_id` 不在 [`REAL_DOMAIN_TOKENS`] →
    /// [`AppchainError::OutOfRange`]。
    pub fn real(token_id: u32) -> AppchainResult<Self> {
        if !REAL_DOMAIN_TOKENS.contains(&token_id) {
            return Err(AppchainError::OutOfRange("real domain token_id"));
        }
        Ok(Self {
            domain: AssetDomain::Real,
            token_id,
        })
    }

    /// 构造 GAME 域资产（结构占位：TE-M3 注册表未实现，任何 token_id
    /// 结构上可表达；发行准入/注册表查重是 TE-M3 的强制点，届时必须
    /// 收紧为 `is_registered_token`——本构造器不做该检查，如实声明）。
    #[must_use]
    pub fn game(token_id: u32) -> Self {
        Self {
            domain: AssetDomain::Game,
            token_id,
        }
    }

    /// v1 → v2 冻结映射（唯一换算）：`Real → REAL/NATIVE(0)`，
    /// `Play → GAME/PLAY(0)`。v1 路径零变更；MigrateNote 迁移、
    /// `SettleInputV2::V1` 输入升维均经此函数。
    #[must_use]
    pub fn of_v1(class: AssetClass) -> Self {
        match class {
            AssetClass::Real => Self::REAL_NATIVE,
            AssetClass::Play => Self::GAME_PLAY,
        }
    }

    /// v2 → v1 逆映射（仅遗留资产可表达）。
    ///
    /// REAL 域非 NATIVE token（USDT/USDC）与 GAME 域非遗留 token 在 v1
    /// 账本**无表示**（v1 rake 输出、v1 托管打款都是 `AssetClass`）——
    /// 返回 `None`。调用方必须 fail-closed 处理 `None`（TE-M2/M3 分别
    /// 扩展 rake/提现通道后才有合法出路）。
    #[must_use]
    pub fn to_v1_class(self) -> Option<AssetClass> {
        match self {
            Self::REAL_NATIVE => Some(AssetClass::Real),
            Self::GAME_PLAY => Some(AssetClass::Play),
            _ => None,
        }
    }

    /// 是否 REAL 域（**finality 门判据，按 domain 不按 token**——
    /// 见模块文档"finality 语义决策"）。
    #[must_use]
    pub const fn is_real_domain(self) -> bool {
        matches!(self.domain, AssetDomain::Real)
    }

    /// 是否 GAME 域（finality 豁免侧；含遗留 PLAY）。
    #[must_use]
    pub const fn is_game_domain(self) -> bool {
        matches!(self.domain, AssetDomain::Game)
    }

    /// 同资产判定（domain 与 token_id 全等；守恒分组的相等谓词）。
    #[must_use]
    pub fn same_asset(self, other: Self) -> bool {
        self == other
    }

    /// 同资产断言（守恒/混转校验统一入口；fail-closed）。
    ///
    /// # Errors
    /// 跨 `AssetId`（domain 或 token_id 任一不同）→
    /// [`AppchainError::AssetMismatch`]。
    pub fn ensure_same(self, other: Self) -> AppchainResult<()> {
        if self != other {
            return Err(AppchainError::AssetMismatch {
                expected: self,
                got: other,
            });
        }
        Ok(())
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match *self {
            Self::REAL_NATIVE => "native".to_string(),
            Self::REAL_USDT => "usdt".to_string(),
            Self::REAL_USDC => "usdc".to_string(),
            Self::GAME_PLAY => "play(legacy)".to_string(),
            _ => self.token_id.to_string(),
        };
        write!(f, "{}:{token}", self.domain.name().to_ascii_lowercase())
    }
}

/// AssetId 域分离承诺：`poseidon(DOMAIN_ASSET_ID_COMMITMENT, domain,
/// token_id)`。
///
/// 单 felt 输出，整体进入 v2 note 承诺 preimage（`note_v2::NoteV2::
/// commitment`）——`token_id` 不进承诺 = 同域不同币种可互换，INV-TE-1
/// 因此在承诺层强制。域标签与 note 承诺域分离（`zchain.asset.v2.id` vs
/// `zchain.note.v2`），跨域拼装不可行。
#[must_use]
pub fn asset_commitment(asset: &AssetId) -> FieldElement {
    poseidon_hash_many(&[
        domain_felt(DOMAIN_ASSET_ID_COMMITMENT),
        felt_from_u64(u64::from(asset.domain.as_u8())),
        felt_from_u64(u64::from(asset.token_id)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt::felt_to_bytes32;

    /// 判别值冻结：REAL=1 / GAME=2（borsh 字节 == 判别值）。
    #[test]
    fn domain_discriminants_frozen() {
        assert_eq!(AssetDomain::Real.as_u8(), 1);
        assert_eq!(AssetDomain::Game.as_u8(), 2);
        assert_eq!(borsh::to_vec(&AssetDomain::Real).unwrap(), [1u8]);
        assert_eq!(borsh::to_vec(&AssetDomain::Game).unwrap(), [2u8]);
        // fail-closed：未定义数值拒绝
        assert!(AssetDomain::from_u8(0).is_err());
        assert!(AssetDomain::from_u8(3).is_err());
        assert!(AssetDomain::from_u8(255).is_err());
    }

    /// AssetId borsh 字节冻结（domain u8 + token u32 LE）+ roundtrip。
    #[test]
    fn asset_id_borsh_layout_frozen() {
        assert_eq!(
            borsh::to_vec(&AssetId::REAL_NATIVE).unwrap(),
            [1u8, 0, 0, 0, 0],
            "domain byte must be the frozen discriminant, token u32 LE"
        );
        assert_eq!(borsh::to_vec(&AssetId::GAME_PLAY).unwrap(), [2u8, 0, 0, 0, 0]);
        let usdt = AssetId::REAL_USDT;
        let back: AssetId = borsh::from_slice(&borsh::to_vec(&usdt).unwrap()).unwrap();
        assert_eq!(back, usdt);
    }

    /// v1 映射冻结 + 逆映射边界（非遗留资产在 v1 无表示）。
    #[test]
    fn v1_mapping_frozen_and_total_on_legacy() {
        assert_eq!(AssetId::of_v1(AssetClass::Real), AssetId::REAL_NATIVE);
        assert_eq!(AssetId::of_v1(AssetClass::Play), AssetId::GAME_PLAY);
        assert_eq!(AssetId::REAL_NATIVE.to_v1_class(), Some(AssetClass::Real));
        assert_eq!(AssetId::GAME_PLAY.to_v1_class(), Some(AssetClass::Play));
        assert_eq!(AssetId::REAL_USDT.to_v1_class(), None);
        assert_eq!(AssetId::REAL_USDC.to_v1_class(), None);
        assert_eq!(AssetId::game(7).to_v1_class(), None);
    }

    /// REAL 域封闭枚举强制（fail-closed）；GAME 结构占位如实声明。
    #[test]
    fn real_domain_closed_enum_enforced() {
        assert!(AssetId::real(TOKEN_NATIVE).is_ok());
        assert!(AssetId::real(TOKEN_USDT).is_ok());
        assert!(AssetId::real(TOKEN_USDC).is_ok());
        assert!(AssetId::real(3).is_err());
        assert!(AssetId::real(u32::MAX).is_err());
        // GAME 注册表未实现（TE-M3）：结构上不拒绝，is_registered_token
        // 只认遗留 0
        assert!(AssetDomain::Game.is_registered_token(GAME_TOKEN_PLAY));
        assert!(!AssetDomain::Game.is_registered_token(7));
        for t in REAL_DOMAIN_TOKENS {
            assert!(AssetDomain::Real.is_registered_token(t));
        }
        assert!(!AssetDomain::Real.is_registered_token(3));
    }

    /// 资产承诺：域分离 + token 敏感 + 确定性。
    #[test]
    fn asset_commitment_is_domain_separated_and_token_sensitive() {
        let native = asset_commitment(&AssetId::REAL_NATIVE);
        // 确定性
        assert_eq!(native, asset_commitment(&AssetId::REAL_NATIVE));
        // 同域不同 token 区分（token_id 进承诺 = INV-TE-1）
        assert_ne!(native, asset_commitment(&AssetId::REAL_USDT));
        assert_ne!(asset_commitment(&AssetId::REAL_USDT), asset_commitment(&AssetId::REAL_USDC));
        // 跨域区分（domain 进承诺）
        assert_ne!(native, asset_commitment(&AssetId::GAME_PLAY));
        assert_ne!(
            asset_commitment(&AssetId::GAME_PLAY),
            asset_commitment(&AssetId::game(1))
        );
        // 与 note 承诺域分离：同 felt 输入经不同域标签必不同（这里只
        // 钉资产承诺的 32B 编码非零且稳定）
        assert_ne!(felt_to_bytes32(&native), [0u8; 32]);
    }

    /// 同类校验 helper：全等通过，任一分量不同即 AssetMismatch。
    #[test]
    fn ensure_same_is_exact_equality() {
        AssetId::REAL_NATIVE.ensure_same(AssetId::REAL_NATIVE).unwrap();
        assert!(AssetId::REAL_NATIVE.same_asset(AssetId::REAL_NATIVE));
        // 跨域
        let err = AssetId::REAL_NATIVE
            .ensure_same(AssetId::GAME_PLAY)
            .unwrap_err();
        assert!(matches!(err, AppchainError::AssetMismatch { expected, got }
            if expected == AssetId::REAL_NATIVE && got == AssetId::GAME_PLAY));
        // 同域不同 token（TE-M1 新语义：粒度细于 v1 AssetClass）
        assert!(AssetId::REAL_NATIVE.ensure_same(AssetId::REAL_USDT).is_err());
        assert!(AssetId::GAME_PLAY.ensure_same(AssetId::game(1)).is_err());
    }

    /// finality 判据按 domain：REAL 域任何 token 走门，GAME 域豁免。
    #[test]
    fn finality_predicate_is_domain_scoped() {
        // REAL 域：所有已注册 token 都走 finality 门（TE-M2 三币种回归基线）
        for t in REAL_DOMAIN_TOKENS {
            let a = AssetId::real(t).unwrap();
            assert!(a.is_real_domain(), "REAL domain token {t} must gate finality");
            assert!(!a.is_game_domain());
        }
        // GAME 域：遗留 PLAY 与未来注册 token 一律豁免
        assert!(!AssetId::GAME_PLAY.is_real_domain());
        assert!(AssetId::GAME_PLAY.is_game_domain());
        assert!(!AssetId::game(7).is_real_domain());
        // v1 语义保持：of_v1(Real) 走门、of_v1(Play) 豁免（与 v1
        // `AssetClass::Real` 门 / `Play` 豁免逐点一致）
        assert!(AssetId::of_v1(AssetClass::Real).is_real_domain());
        assert!(!AssetId::of_v1(AssetClass::Play).is_real_domain());
    }

    /// Display 可读且无损区分（错误信息用）。
    #[test]
    fn display_distinguishes_assets() {
        assert_eq!(AssetId::REAL_NATIVE.to_string(), "real:native");
        assert_eq!(AssetId::REAL_USDT.to_string(), "real:usdt");
        assert_eq!(AssetId::REAL_USDC.to_string(), "real:usdc");
        assert_eq!(AssetId::GAME_PLAY.to_string(), "game:play(legacy)");
        assert_eq!(AssetId::game(7).to_string(), "game:7");
    }
}
