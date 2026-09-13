//! 合约类包（对标 Aztec `ContractArtifact`）：scarb 编译产物 → 类哈希 +
//! 待声明类。
//!
//! 产物来源：poker_texas_air `poker_contracts/target/dev/`（scarb 2.19.4
//! 构建，见其 `Scarb.toml` 的 `[[target.starknet-contract]]` sierra+casm）。

use std::path::{Path, PathBuf};

use crate::codec::Felt;
use crate::error::{ContractsError, ContractsResult};

/// 协议套件内的合约名（与 scarb 目标产物 stem 一一对应）。
///
/// 已退役合约（PokerToken/pSTRK、PokerSwap、CashoutUnshieldHelper）不在
/// 套件内——见 poker_texas_air `DEPLOYMENTS.md` 2026-09-07 清理记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContractName {
    /// PokerVault：1:1 STRK 存取 + 玩家筹码账本（在局锁定 / TTL 自助解锁）。
    PokerVault,
    /// PokerSettlement：legacy 线性结算（兜底）。
    PokerSettlement,
    /// PokerDualSettlement：DAPV 双证明结算（v5，SNIP-36 双门）。
    PokerDualSettlement,
    /// PokerVaultAnonymizer：私密买入/领取 helper。
    PokerVaultAnonymizer,
    /// SettlementPayoutAnonymizer：派奖 helper。
    SettlementPayoutAnonymizer,
    /// PokerTableRegistry：桌台注册表（可选锚定层，不碰钱）。
    PokerTableRegistry,
}

impl std::fmt::Display for ContractName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl ContractName {
    /// scarb 产物 stem（`poker_contracts_{stem}.contract_class.json`）。
    #[must_use]
    pub fn artifact_stem(self) -> &'static str {
        match self {
            Self::PokerVault => "PokerVault",
            Self::PokerSettlement => "PokerSettlement",
            Self::PokerDualSettlement => "PokerDualSettlement",
            Self::PokerVaultAnonymizer => "PokerVaultAnonymizer",
            Self::SettlementPayoutAnonymizer => "SettlementPayoutAnonymizer",
            Self::PokerTableRegistry => "PokerTableRegistry",
        }
    }

    /// 短标签（日志 / 注册表键）。
    #[must_use]
    pub fn label(self) -> &'static str {
        self.artifact_stem()
    }

    /// 套件内全部合约（按部署顺序）。
    #[must_use]
    pub fn all() -> [Self; 6] {
        [
            Self::PokerVault,
            Self::PokerSettlement,
            Self::PokerDualSettlement,
            Self::PokerVaultAnonymizer,
            Self::SettlementPayoutAnonymizer,
            Self::PokerTableRegistry,
        ]
    }
}

/// 合约类包：sierra（可声明类）+ casm（编译类）+ 两级类哈希。
///
/// 对标 Aztec `ContractArtifact`（aztec 为 Noir→ACIR 产物包；starknet 为
/// sierra→casm）。`class_hash` 参与实例地址推导与链上类注册；
/// `compiled_class_hash` 参与声明（declare_v3），节点计算方案可能与本地
/// 不同（deployer 内置重试）。
#[derive(Debug, Clone)]
pub struct ContractArtifact {
    /// 合约名。
    pub name: ContractName,
    /// sierra JSON 路径。
    pub sierra_path: PathBuf,
    /// casm JSON 路径。
    pub casm_path: PathBuf,
    /// sierra class hash（UDC 地址推导输入之一）。
    pub class_hash: Felt,
    /// casm class hash（declare 的 compiled_class_hash）。
    pub compiled_class_hash: Felt,
    sierra: starknet::core::types::contract::SierraClass,
    casm: starknet::core::types::contract::CompiledClass,
}

impl ContractArtifact {
    /// 从产物目录加载（`poker_contracts_{stem}.contract_class.json` +
    /// `.compiled_contract_class.json`）。
    ///
    /// # Errors
    /// 文件缺失 / JSON 解析 / 哈希计算失败 → [`ContractsError::Artifact`]。
    pub fn load(dir: &Path, name: ContractName) -> ContractsResult<Self> {
        let sierra_path = dir.join(format!("poker_contracts_{}.contract_class.json", name.artifact_stem()));
        let casm_path = dir.join(format!(
            "poker_contracts_{}.compiled_contract_class.json",
            name.artifact_stem()
        ));
        let raw_sierra = std::fs::File::open(&sierra_path)
            .map_err(|e| ContractsError::Artifact(format!("{}: {e}", sierra_path.display())))?;
        let sierra: starknet::core::types::contract::SierraClass = serde_json::from_reader(
            std::io::BufReader::new(raw_sierra),
        )
        .map_err(|e| ContractsError::Artifact(format!("parse sierra {}: {e}", sierra_path.display())))?;
        let raw_casm = std::fs::File::open(&casm_path)
            .map_err(|e| ContractsError::Artifact(format!("{}: {e}", casm_path.display())))?;
        let casm: starknet::core::types::contract::CompiledClass = serde_json::from_reader(
            std::io::BufReader::new(raw_casm),
        )
        .map_err(|e| ContractsError::Artifact(format!("parse casm {}: {e}", casm_path.display())))?;
        let class_hash = sierra
            .class_hash()
            .map_err(|e| ContractsError::Artifact(format!("class hash {}: {e}", name.label())))?;
        let compiled_class_hash = casm
            .class_hash()
            .map_err(|e| ContractsError::Artifact(format!("compiled hash {}: {e}", name.label())))?;
        Ok(Self {
            name,
            sierra_path,
            casm_path,
            class_hash,
            compiled_class_hash,
            sierra,
            casm,
        })
    }

    /// 从产物目录加载全部套件合约。
    ///
    /// # Errors
    /// 任一合约加载失败 → [`ContractsError::Artifact`]。
    pub fn load_suite(dir: &Path) -> ContractsResult<Vec<Self>> {
        ContractName::all().iter().map(|&n| Self::load(dir, n)).collect()
    }

    /// 产物目录是否齐备（全部 stem 的两个 JSON 都在）。
    #[must_use]
    pub fn suite_complete(dir: &Path) -> bool {
        ContractName::all().iter().all(|n| {
            let stem = n.artifact_stem();
            dir.join(format!("poker_contracts_{stem}.contract_class.json")).is_file()
                && dir
                    .join(format!("poker_contracts_{stem}.compiled_contract_class.json"))
                    .is_file()
        })
    }

    /// flatten 后的 sierra 类（declare_v3 输入）。
    ///
    /// # Errors
    /// flatten 失败 → [`ContractsError::Artifact`]。
    pub fn flattened(&self) -> ContractsResult<starknet::core::types::FlattenedSierraClass> {
        self.sierra
            .clone()
            .flatten()
            .map_err(|e| ContractsError::Artifact(format!("flatten {}: {e}", self.name.label())))
    }

    /// 编译类（声明重试时的哈希校对来源）。
    #[must_use]
    pub fn compiled_class(&self) -> &starknet::core::types::contract::CompiledClass {
        &self.casm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_stems_cover_real_scarb_output() {
        // stem 集与 poker_contracts/target/dev 实际产物一一对应
        let stems: Vec<&str> = ContractName::all().iter().map(|n| n.artifact_stem()).collect();
        assert_eq!(
            stems,
            vec![
                "PokerVault",
                "PokerSettlement",
                "PokerDualSettlement",
                "PokerVaultAnonymizer",
                "SettlementPayoutAnonymizer",
                "PokerTableRegistry",
            ]
        );
    }

    #[test]
    fn load_missing_artifact_is_artifact_error() {
        let err = ContractArtifact::load(Path::new("/nonexistent"), ContractName::PokerVault)
            .unwrap_err();
        assert!(matches!(err, ContractsError::Artifact(_)));
    }

    /// 真实产物冒烟（本机 poker_texas_air 已构建时生效；缺产物软跳过）。
    #[test]
    fn load_real_suite_when_artifacts_present() {
        let dir = crate::config::default_artifacts_dir();
        if !ContractArtifact::suite_complete(&dir) {
            eprintln!("[skip] artifacts not built at {}", dir.display());
            return;
        }
        let suite = ContractArtifact::load_suite(&dir).expect("suite loads");
        assert_eq!(suite.len(), 6);
        for a in &suite {
            assert_ne!(a.class_hash, Felt::ZERO);
            assert_ne!(a.compiled_class_hash, Felt::ZERO);
        }
        // 重复加载哈希稳定（确定性）
        let again = ContractArtifact::load(&dir, ContractName::PokerTableRegistry).unwrap();
        let first = suite
            .iter()
            .find(|a| a.name == ContractName::PokerTableRegistry)
            .unwrap();
        assert_eq!(first.class_hash, again.class_hash);
        assert_eq!(first.compiled_class_hash, again.compiled_class_hash);
    }
}
