//! 合约实例（对标 Aztec `ContractInstance`）：类 + salt + 构造参数 +
//! deployer/UDC，地址离线确定性推导。
//!
//! Starknet 侧经 UDC（Universal Deployer Contract）部署：
//! - **unique** 模式（默认）：deployer 地址参与地址推导——对标 Aztec 默认
//!   （sender 参与推导）；同 owner 重跑 salt 不变则地址不变。
//! - **universal** 模式（`universal(true)`）：地址与 deployer 无关——对标
//!   Aztec `universalDeploy`，同 salt 跨网络同地址。

use crate::codec::{Felt, Uint256};
use crate::error::{ContractsError, ContractsResult};

/// UDC 部署实例：地址 = f(salt, class_hash, 构造参数, deployer, udc, unique)。
///
/// 对标 aztec.js `getContractInstanceFromInstantiationParams` / 生成绑定的
/// `getInstance()`：部署前即可离线预测地址（回执地址与预测值在
/// [`crate::deployer::ContractDeployer`] 内强制对账）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractInstance {
    /// 合约名（标签）。
    pub name: &'static str,
    /// sierra class hash。
    pub class_hash: Felt,
    /// 实例地址（链上合约位置）。
    pub address: Felt,
    /// 部署 salt（DEPLOYMENTS 惯例：salt=0 确定性部署）。
    pub salt: Felt,
    /// UDC 地址。
    pub udc: Felt,
    /// 是否 universal（非 unique）部署。
    pub universal: bool,
    /// unique 模式下参与地址推导的部署者地址。
    pub deployer: Felt,
    /// 构造参数 calldata（构造器形状见 [`crate::deploy`]）。
    pub constructor_calldata: Vec<Felt>,
}

impl ContractInstance {
    /// 离线推导实例地址（不连链）。
    ///
    /// unique：`UDCUniqueSettings { deployer_address, udc }` 参与推导；
    /// universal：仅 (salt, class, calldata)。
    #[must_use]
    pub fn derive_address(
        class_hash: Felt,
        salt: Felt,
        constructor_calldata: &[Felt],
        deployer: Felt,
        udc: Felt,
        universal: bool,
    ) -> Felt {
        let uniqueness = if universal {
            starknet::core::utils::UdcUniqueness::NotUnique
        } else {
            starknet::core::utils::UdcUniqueness::Unique(
                starknet::core::utils::UdcUniqueSettings {
                    deployer_address: deployer,
                    udc_contract_address: udc,
                },
            )
        };
        starknet::core::utils::get_udc_deployed_address(
            salt,
            class_hash,
            &uniqueness,
            constructor_calldata,
        )
    }

    /// 部署前预测实例（对标 `getInstance()`）。
    ///
    /// # Errors
    /// 构造参数为空（构造器校验会在链上失败）→ 不拦截，仅当
    /// `require_nonempty` 为 true 时检查——此处恒接受空 calldata。
    /// 实际上本函数不失败；保留 Result 以匹配部署器调用形状。
    pub fn precompute(
        name: &'static str,
        class_hash: Felt,
        salt: Felt,
        constructor_calldata: Vec<Felt>,
        deployer: Felt,
        udc: Felt,
        universal: bool,
    ) -> ContractsResult<Self> {
        let address = Self::derive_address(
            class_hash,
            salt,
            &constructor_calldata,
            deployer,
            udc,
            universal,
        );
        Ok(Self {
            name,
            class_hash,
            address,
            salt,
            udc,
            universal,
            deployer,
            constructor_calldata,
        })
    }

    /// 实例是否合法（地址非零）。
    ///
    /// # Errors
    /// 地址为零 → [`ContractsError::Instance`]。
    pub fn validate(&self) -> ContractsResult<()> {
        if self.address == Felt::ZERO {
            return Err(ContractsError::Instance(format!(
                "{}: derived zero address (check class hash/calldata)",
                self.name
            )));
        }
        Ok(())
    }
}

/// 构造参数编码器（构造器形状冻结自 poker_texas_air 合约源码 +
/// `scripts/deploy_mainnet.sh`，接线顺序见 [`crate::deploy`]）。
///
/// 每个函数的参数顺序即构造器 ABI，错序会在链上构造器断言或接线回读
/// 时暴露——部署前用 [`SuiteCalldata::preview`] 逐项核对。
#[derive(Debug, Clone, Copy, Default)]
pub struct SuiteCalldata;

impl SuiteCalldata {
    /// PokerVault：`constructor(owner, token_address, settlement_contract)`
    /// ——settlement 先占位 0，部署后接线绑定 dual。
    #[must_use]
    pub fn vault(owner: Felt, strk: Felt, settlement: Felt) -> Vec<Felt> {
        vec![owner, strk, settlement]
    }

    /// PokerSettlement：`constructor(owner, vault, initial_prover)`。
    #[must_use]
    pub fn settlement(owner: Felt, vault: Felt, prover: Felt) -> Vec<Felt> {
        vec![owner, vault, prover]
    }

    /// PokerDualSettlement：`constructor(owner, vault, initial_prover)`。
    #[must_use]
    pub fn dual(owner: Felt, vault: Felt, prover: Felt) -> Vec<Felt> {
        vec![owner, vault, prover]
    }

    /// PokerVaultAnonymizer：`constructor(owner, vault, pool)`
    /// ——owner 必须显式给（构造期 caller 是 UDC，不能拿它当 owner）。
    #[must_use]
    pub fn vault_anonymizer(owner: Felt, vault: Felt, pool: Felt) -> Vec<Felt> {
        vec![owner, vault, pool]
    }

    /// SettlementPayoutAnonymizer：`constructor(vault, pool, settlement)`
    /// ——注意无 owner 且参数顺序与 vault_anonymizer 不同。
    #[must_use]
    pub fn payout_anonymizer(vault: Felt, pool: Felt, settlement: Felt) -> Vec<Felt> {
        vec![vault, pool, settlement]
    }

    /// PokerTableRegistry：`constructor(owner, close_grace_secs)`
    /// （生产宽限期建议 604800 = 7 天）。
    #[must_use]
    pub fn table_registry(owner: Felt, close_grace_secs: u64) -> Vec<Felt> {
        vec![owner, Felt::from(close_grace_secs)]
    }

    /// 构造参数预览（部署计划展示 / dry-run）。
    #[must_use]
    pub fn preview(cd: &[Felt]) -> Vec<CalldataArg> {
        cd.iter().map(|f| CalldataArg { hex: format!("{f:#x}"), kind: ArgKind::Felt }).collect()
    }
}

/// 预览用 calldata 参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalldataArg {
    /// hex 形式。
    pub hex: String,
    /// 编码类型。
    pub kind: ArgKind,
}

/// 预览参数类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// felt252 / ContractAddress / 短串。
    Felt,
    /// u256 低字。
    U256Low,
    /// u256 高字。
    U256High,
    /// u64 标量。
    U64,
}

/// u256 金额入 calldata 的便捷构造（`approve/deposit` 等入口）。
#[must_use]
pub fn amount_felts(amount: Uint256) -> Vec<Felt> {
    crate::codec::u256_to_felts(amount).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(n: u64) -> Felt {
        Felt::from(n)
    }

    #[test]
    fn derived_address_is_deterministic_and_separates_uniqueness() {
        let class = f(0xABC);
        let cd = vec![f(1), f(2)];
        let udc = crate::codec::parse_felt(crate::config::LEGACY_UDC).unwrap();
        let a_unique = ContractInstance::derive_address(class, Felt::ZERO, &cd, f(0xD1), udc, false);
        let a_unique_again =
            ContractInstance::derive_address(class, Felt::ZERO, &cd, f(0xD1), udc, false);
        assert_eq!(a_unique, a_unique_again, "same (class,salt,cd,deployer,udc) → same address");

        // deployer 变化 → unique 地址变化；universal 地址不变
        let other_deployer =
            ContractInstance::derive_address(class, Felt::ZERO, &cd, f(0xD2), udc, false);
        assert_ne!(a_unique, other_deployer);
        let a_universal = ContractInstance::derive_address(class, Felt::ZERO, &cd, f(0xD2), udc, true);
        assert_eq!(
            a_universal,
            ContractInstance::derive_address(class, Felt::ZERO, &cd, f(0xD1), udc, true),
            "universal：同 salt 跨 deployer 同地址（对标 aztec universalDeploy）"
        );
        assert_ne!(a_unique, a_universal);

        // salt / calldata / class 任一变化都换地址
        assert_ne!(
            a_unique,
            ContractInstance::derive_address(class, f(1), &cd, f(0xD1), udc, false)
        );
        assert_ne!(
            a_unique,
            ContractInstance::derive_address(class, Felt::ZERO, &[f(1)], f(0xD1), udc, false)
        );
        assert_ne!(
            a_unique,
            ContractInstance::derive_address(f(0xABD), Felt::ZERO, &cd, f(0xD1), udc, false)
        );
    }

    #[test]
    fn precompute_matches_derive_and_validates() {
        let inst = ContractInstance::precompute(
            "PokerVault",
            f(0xABC),
            Felt::ZERO,
            vec![f(1), f(2), Felt::ZERO],
            f(0xD1),
            crate::codec::parse_felt(crate::config::LEGACY_UDC).unwrap(),
            false,
        )
        .unwrap();
        inst.validate().unwrap();
        assert_eq!(inst.address, ContractInstance::derive_address(
            f(0xABC),
            Felt::ZERO,
            &[f(1), f(2), Felt::ZERO],
            f(0xD1),
            crate::codec::parse_felt(crate::config::LEGACY_UDC).unwrap(),
            false,
        ));
        let zero = ContractInstance {
            address: Felt::ZERO,
            ..inst.clone()
        };
        assert!(zero.validate().is_err());
    }

    #[test]
    fn constructor_shapes_match_deploy_mainnet_sh() {
        // deploy_mainnet.sh 的 calldata 逐位对照（构造器 ABI 冻结）
        let owner = f(0xA);
        let strk = crate::codec::parse_felt(crate::config::CANONICAL_STRK).unwrap();
        let vault = f(0xB);
        let dual = f(0xC);
        let pool = f(0xD);
        let prover = owner;
        assert_eq!(
            SuiteCalldata::vault(owner, strk, Felt::ZERO),
            vec![owner, strk, Felt::ZERO]
        );
        assert_eq!(SuiteCalldata::settlement(owner, vault, prover), vec![owner, vault, owner]);
        assert_eq!(SuiteCalldata::dual(owner, vault, prover), vec![owner, vault, owner]);
        assert_eq!(SuiteCalldata::vault_anonymizer(owner, vault, pool), vec![owner, vault, pool]);
        // payout 无 owner 且 (vault, pool, settlement) 顺序
        assert_eq!(SuiteCalldata::payout_anonymizer(vault, pool, dual), vec![vault, pool, dual]);
        assert_eq!(SuiteCalldata::table_registry(owner, 604_800), vec![owner, f(604_800)]);
    }
}
