//! canonical 地址注册表（对标 Aztec 的协议合约 canonical registry 与
//! `get-canonical-*` CLI）：每网络一份机器可读 JSON（`registry/<network>.json`），
//! 部署完成后自动回写，接入侧从这里解析现网地址；同时输出
//! poker_texas_air `DEPLOYMENTS.md` / `.env` 回填素材。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::artifact::ContractName;
use crate::codec::{parse_felt, Felt};
use crate::config::DeployedAddresses;
use crate::error::{ContractsError, ContractsResult};

/// 单合约注册条目。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RegistryEntry {
    /// 实例地址（0x…）。
    pub address: String,
    /// sierra class hash（有声明记录时）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_hash: Option<String>,
    /// casm class hash（有声明记录时）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled_class_hash: Option<String>,
    /// 部署交易哈希（有部署记录时）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy_tx: Option<String>,
    /// 接线交易哈希（label → tx）。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub wiring: BTreeMap<String, String>,
}

/// canonical 注册表（机器可读版 DEPLOYMENTS.md）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CanonicalAddressRegistry {
    /// 网络名（devnet/sepolia/mainnet）。
    pub network: String,
    /// 最近更新时间（RFC3339，写盘时打点）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// 合约名 → 条目。
    pub contracts: BTreeMap<String, RegistryEntry>,
    /// 套件级常量（strk / pool / program hashes）。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constants: BTreeMap<String, String>,
}

impl CanonicalAddressRegistry {
    /// 空注册表。
    #[must_use]
    pub fn new(network: crate::config::Network) -> Self {
        Self {
            network: network.to_string(),
            updated_at: None,
            contracts: BTreeMap::new(),
            constants: BTreeMap::new(),
        }
    }

    /// 注册表文件路径：`<dir>/<network>.json`。
    #[must_use]
    pub fn path_for(dir: &Path, network: crate::config::Network) -> PathBuf {
        dir.join(format!("{network}.json"))
    }

    /// 从 JSON 文件加载。
    ///
    /// # Errors
    /// 读取 / 解析失败 → [`ContractsError::Config`]。
    pub fn load(path: &Path) -> ContractsResult<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ContractsError::Config(format!("read {}: {e}", path.display())))?;
        serde_json::from_str(&raw)
            .map_err(|e| ContractsError::Config(format!("parse {}: {e}", path.display())))
    }

    /// 写盘（自动打时间戳）。
    ///
    /// # Errors
    /// 序列化 / 写入失败 → [`ContractsError::Config`]。
    pub fn save(&self, path: &Path) -> ContractsResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ContractsError::Config(format!("mkdir {}: {e}", parent.display())))?;
        }
        let mut out = self.clone();
        out.updated_at = Some(now_rfc3339());
        let json = serde_json::to_string_pretty(&out)
            .map_err(|e| ContractsError::Config(format!("serialize registry: {e}")))?;
        std::fs::write(path, json + "\n")
            .map_err(|e| ContractsError::Config(format!("write {}: {e}", path.display())))
    }

    /// upsert 条目。
    pub fn insert(&mut self, name: ContractName, entry: RegistryEntry) {
        self.contracts.insert(name.label().to_owned(), entry);
    }

    /// 按合约名取地址。
    #[must_use]
    pub fn address_of(&self, name: ContractName) -> Option<Felt> {
        self.contracts.get(name.label()).and_then(|e| parse_felt(&e.address).ok())
    }

    /// 解析为接入侧的 [`DeployedAddresses`]。
    #[must_use]
    pub fn to_deployed_addresses(&self) -> DeployedAddresses {
        let mut out = DeployedAddresses::default();
        for name in ContractName::all() {
            if let Some(addr) = self.address_of(name) {
                out.set(name, addr);
            }
        }
        out
    }

    /// 生成 `DEPLOYMENTS.md` 风格表格（回填素材）。
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("## Canonical registry — {}\n\n", self.network));
        s.push_str("| 合约 | 地址 | class hash | deploy TX |\n|---|---|---|---|\n");
        for (name, e) in &self.contracts {
            s.push_str(&format!(
                "| {name} | `{}` | `{}` | `{}` |\n",
                e.address,
                e.class_hash.clone().unwrap_or_default(),
                e.deploy_tx.clone().unwrap_or_default()
            ));
        }
        if !self.constants.is_empty() {
            s.push_str("\n| 常量 | 值 |\n|---|---|\n");
            for (k, v) in &self.constants {
                s.push_str(&format!("| {k} | `{v}` |\n"));
            }
        }
        s
    }
}

/// 当前时间（RFC3339；无 chrono 依赖，秒级 UTC 时间戳的 ISO 形式由
/// 标准库手工拼装——仅用于打点，不做时区处理）。
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    // 简易 civil 推算（UTC，仅打点用）
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{sec:02}Z")
}

/// days since epoch → (y, m, d)（Howard Hinnant 算法）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CanonicalAddressRegistry {
        let mut reg = CanonicalAddressRegistry::new(crate::config::Network::Mainnet);
        reg.insert(
            ContractName::PokerVault,
            RegistryEntry {
                address: "0x3f4e".into(),
                class_hash: Some("0x7c74".into()),
                compiled_class_hash: None,
                deploy_tx: Some("0x4512".into()),
                wiring: BTreeMap::new(),
            },
        );
        reg.constants.insert("strk".into(), crate::config::CANONICAL_STRK.into());
        reg
    }

    #[test]
    fn json_roundtrip_and_lookup() {
        let dir = std::env::temp_dir().join("poker-contracts-test-registry");
        std::fs::create_dir_all(&dir).unwrap();
        let path = CanonicalAddressRegistry::path_for(&dir, crate::config::Network::Mainnet);
        sample().save(&path).unwrap();
        let loaded = CanonicalAddressRegistry::load(&path).unwrap();
        assert_eq!(loaded.network, "mainnet");
        assert!(loaded.updated_at.is_some(), "save 打时间戳");
        let addr = loaded.address_of(ContractName::PokerVault).unwrap();
        assert_eq!(addr, parse_felt("0x3f4e").unwrap());
        let addrs = loaded.to_deployed_addresses();
        assert_eq!(addrs.vault, Some(addr));
        assert!(addrs.dual.is_none());
        let md = loaded.to_markdown();
        assert!(md.contains("| PokerVault | `0x3f4e` |"));
    }

    #[test]
    fn missing_registry_is_config_error() {
        assert!(CanonicalAddressRegistry::load(Path::new("/nonexistent/x.json")).is_err());
    }
}
