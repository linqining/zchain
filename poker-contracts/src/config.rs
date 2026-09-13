//! 网络与部署配置（env 驱动，变量名与 poker_texas_air 的 `.env` / 部署脚本
//! 完全对齐，texas `.env` 可直接喂给 [`ContractsConfig::from_env_file`]）。

use std::fmt;
use std::path::{Path, PathBuf};

use crate::codec::{parse_felt, Felt};
use crate::error::{ContractsError, ContractsResult};

/// 规范 STRK（原生 gas 代币）：mainnet / sepolia / devnet 同址
/// （poker_texas_air `DEPLOYMENTS.md` 主网常量表，2026-09-07 核对）。
pub const CANONICAL_STRK: &str =
    "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

/// STRK20 privacy pool（主网；anonymizer 构造写死 pool，池升级需重部署
/// helper——见 DEPLOYMENTS.md "主网常量"）。sepolia/devnet 池地址不同，
/// 必须显式提供。
pub const MAINNET_STRK20_POOL: &str =
    "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a";

/// 默认电路 program hash（#18 Phase C 切片 2，sepolia v5 与主网同版）。
pub const DEFAULT_CIRCUIT_PROGRAM_HASH: &str =
    "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4";

/// 默认 hand-verify program hash（hand-verify-native form-② composed）。
pub const DEFAULT_HAND_VERIFY_PROGRAM_HASH: &str =
    "0x303029d8ce0ec1d0295e4037fc7f87a1ada0c27423cc99bcd080d25b1c6829f";

/// 主网原始 UDC（Universal Deployer Contract，snops / 部署脚本同值）。
pub const LEGACY_UDC: &str =
    "0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf";

/// OpenZeppelin 账户类（snops gen-key / deploy_account 同值）。
pub const OPENZEPPELIN_ACCOUNT_CLASS: &str =
    "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";

/// 目标网络。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    /// 本地 starknet-devnet（`starknet-devnet --seed 0`，端口 5051）。
    #[default]
    Devnet,
    /// Starknet Sepolia 测试网。
    Sepolia,
    /// Starknet 主网（部署需显式确认，对标 `CONFIRM_MAINNET=yes`）。
    Mainnet,
}

impl Network {
    /// 解析网络名（CLI / env：`devnet` | `sepolia` | `mainnet`）。
    ///
    /// # Errors
    /// 未知名称 → [`ContractsError::Config`]。
    pub fn parse(s: &str) -> ContractsResult<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "devnet" => Ok(Self::Devnet),
            "sepolia" => Ok(Self::Sepolia),
            "mainnet" => Ok(Self::Mainnet),
            other => Err(ContractsError::Config(format!(
                "unknown network `{other}` (devnet|sepolia|mainnet)"
            ))),
        }
    }

    /// 网络预设：默认 RPC、chain id、默认 privacy pool、注册表宽限期。
    #[must_use]
    pub fn preset(self) -> NetworkPreset {
        match self {
            Self::Devnet => NetworkPreset {
                rpc_url: "http://127.0.0.1:5051",
                chain_id: "SN_SEPOLIA",
                default_pool: None,
                registry_grace_secs: 3600,
            },
            Self::Sepolia => NetworkPreset {
                rpc_url: "https://starknet-sepolia-rpc.publicnode.com",
                chain_id: "SN_SEPOLIA",
                default_pool: None,
                registry_grace_secs: 604_800,
            },
            Self::Mainnet => NetworkPreset {
                rpc_url: "https://starknet-rpc.publicnode.com",
                chain_id: "SN_MAIN",
                default_pool: Some(MAINNET_STRK20_POOL),
                registry_grace_secs: 604_800,
            },
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Devnet => "devnet",
            Self::Sepolia => "sepolia",
            Self::Mainnet => "mainnet",
        })
    }
}

/// 网络预设常量（[`Network::preset`]）。
#[derive(Debug, Clone, Copy)]
pub struct NetworkPreset {
    /// 默认公共 RPC。
    pub rpc_url: &'static str,
    /// 链 id 名（`SN_MAIN` / `SN_SEPOLIA`；devnet 与 sepolia 同为
    /// `SN_SEPOLIA`，与 poker_texas_air devnet 部署一致）。
    pub chain_id: &'static str,
    /// 默认 STRK20 privacy pool（仅主网内置；其余网络必须显式提供）。
    pub default_pool: Option<&'static str>,
    /// TableRegistry 关桌宽限期默认值（生产 7 天；devnet 1 小时）。
    pub registry_grace_secs: u64,
}

/// 已部署合约地址集合（接入侧消费；字段名对应 texas `.env`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeployedAddresses {
    /// PokerVault。
    pub vault: Option<Felt>,
    /// PokerSettlement（legacy 线性结算兜底）。
    pub settlement: Option<Felt>,
    /// PokerDualSettlement（DAPV 双证明结算）。
    pub dual: Option<Felt>,
    /// PokerVaultAnonymizer（私密买入/领取 helper）。
    pub vault_anonymizer: Option<Felt>,
    /// SettlementPayoutAnonymizer（派奖 helper；server env 名
    /// `STARKNET_CLAIM_HELPER_ADDRESS`）。
    pub payout_anonymizer: Option<Felt>,
    /// PokerTableRegistry（可选锚定层）。
    pub table_registry: Option<Felt>,
}

impl DeployedAddresses {
    /// 按合约名取地址。
    #[must_use]
    pub fn get(&self, key: crate::artifact::ContractName) -> Option<Felt> {
        use crate::artifact::ContractName as C;
        match key {
            C::PokerVault => self.vault,
            C::PokerSettlement => self.settlement,
            C::PokerDualSettlement => self.dual,
            C::PokerVaultAnonymizer => self.vault_anonymizer,
            C::SettlementPayoutAnonymizer => self.payout_anonymizer,
            C::PokerTableRegistry => self.table_registry,
        }
    }

    /// 按合约名写地址（部署报告回填）。
    pub fn set(&mut self, key: crate::artifact::ContractName, addr: Felt) {
        use crate::artifact::ContractName as C;
        match key {
            C::PokerVault => self.vault = Some(addr),
            C::PokerSettlement => self.settlement = Some(addr),
            C::PokerDualSettlement => self.dual = Some(addr),
            C::PokerVaultAnonymizer => self.vault_anonymizer = Some(addr),
            C::SettlementPayoutAnonymizer => self.payout_anonymizer = Some(addr),
            C::PokerTableRegistry => self.table_registry = Some(addr),
        }
    }
}

/// 合约模块配置。`from_env*` 变量名与 poker_texas_air 完全对齐：
///
/// | 变量 | 含义 | 缺省 |
/// |---|---|---|
/// | `POKER_CONTRACTS_NETWORK` | devnet/sepolia/mainnet | devnet |
/// | `STARKNET_RPC_URL` | RPC 端点 | 网络预设 |
/// | `ADDRESS` + `PRIVATE_KEY` | 部署者/操作员（部署脚本惯例） | 必填（连接/部署时） |
/// | `STARKNET_OPERATOR_ADDRESS` + `STARKNET_OPERATOR_PRIVATE_KEY` | 同上（server .env 惯例，回退） | — |
/// | `POKER_CONTRACTS_ARTIFACTS_DIR` | scarb 产物目录 | `<repo>/../poker_texas_air/poker_contracts/target/dev` |
/// | `POKER_CONTRACTS_UDC` | UDC 地址（devnet 0.9.x 预部署 0x2cee…） | 主网 legacy UDC |
/// | `STARKNET_STRK_ADDRESS` | 筹码代币 | 规范 STRK |
/// | `STARKNET_VAULT_ADDRESS` 等 | 已部署地址（接入） | 空 |
/// | `POKER_CONTRACTS_PROGRAM_HASH` / `POKER_CONTRACTS_HAND_VERIFY_PROGRAM_HASH` | 电路 hash | 版本默认 |
#[derive(Debug, Clone)]
pub struct ContractsConfig {
    /// 目标网络。
    pub network: Network,
    /// RPC 端点。
    pub rpc_url: String,
    /// 账户地址（部署者/操作员）。
    pub account_address: Option<Felt>,
    /// 账户私钥（仅内存，不入库不打日志）。
    pub private_key: Option<Felt>,
    /// scarb 产物目录（`poker_contracts/target/dev`）。
    pub artifacts_dir: PathBuf,
    /// UDC 地址。
    pub udc: Felt,
    /// 合约 owner（构造参数；缺省 = 账户地址）。
    pub owner: Option<Felt>,
    /// 结算 initial_prover（= operator；缺省 = owner）。
    pub prover: Option<Felt>,
    /// 筹码代币地址（规范 STRK 或自定义 ERC20）。
    pub strk: Felt,
    /// STRK20 privacy pool（anonymizer 构造必需；主网有默认）。
    pub pool: Option<Felt>,
    /// 电路 program hash（dual 接线）。
    pub circuit_program_hash: Felt,
    /// hand-verify program hash（dual 接线）。
    pub hand_verify_program_hash: Felt,
    /// TableRegistry 关桌宽限期（秒）。
    pub registry_grace_secs: u64,
    /// 是否部署 TableRegistry（sepolia/mainnet 批量部署脚本尚未含它，
    /// 默认关——与 2026-09-11 部署状态一致）。
    pub with_table_registry: bool,
    /// 已部署地址（接入侧读取；部署完成后由注册表回填）。
    pub addresses: DeployedAddresses,
}

impl Default for ContractsConfig {
    fn default() -> Self {
        let preset = Network::default().preset();
        Self {
            network: Network::default(),
            rpc_url: preset.rpc_url.to_owned(),
            account_address: None,
            private_key: None,
            artifacts_dir: default_artifacts_dir(),
            udc: parse_felt(LEGACY_UDC).expect("const felt"),
            owner: None,
            prover: None,
            strk: parse_felt(CANONICAL_STRK).expect("const felt"),
            pool: None,
            circuit_program_hash: parse_felt(DEFAULT_CIRCUIT_PROGRAM_HASH).expect("const felt"),
            hand_verify_program_hash: parse_felt(DEFAULT_HAND_VERIFY_PROGRAM_HASH)
                .expect("const felt"),
            registry_grace_secs: preset.registry_grace_secs,
            with_table_registry: false,
            addresses: DeployedAddresses::default(),
        }
    }
}

impl ContractsConfig {
    /// 从进程环境加载（见类型文档的变量表）。
    ///
    /// # Errors
    /// 网络/地址解析失败 → [`ContractsError::Config`]。
    pub fn from_env() -> ContractsResult<Self> {
        let mut map = std::collections::BTreeMap::new();
        for (k, v) in std::env::vars() {
            map.insert(k, v);
        }
        Self::from_env_map(&map)
    }

    /// 从显式键值对加载（可测；[`Self::from_env`] 的纯函数内核）。
    ///
    /// # Errors
    /// 解析失败 → [`ContractsError::Config`]。
    pub fn from_env_map(map: &std::collections::BTreeMap<String, String>) -> ContractsResult<Self> {
        let get = |k: &str| -> Option<String> {
            map.get(k).filter(|v| !v.trim().is_empty()).cloned()
        };

        let network = match get("POKER_CONTRACTS_NETWORK") {
            Some(s) => Network::parse(&s)?,
            None => Network::default(),
        };
        let preset = network.preset();
        let mut cfg = Self::default();
        cfg.network = network;
        // 网络定了但没显式给 RPC：用该网络预设端点
        if get("STARKNET_RPC_URL").is_none() {
            cfg.rpc_url = preset.rpc_url.to_owned();
        }
        if let Some(url) = get("STARKNET_RPC_URL") {
            cfg.rpc_url = url;
        }
        // 部署脚本惯例 ADDRESS/PRIVATE_KEY，回退 server .env 的 STARKNET_OPERATOR_*
        let addr = get("ADDRESS").or_else(|| get("STARKNET_OPERATOR_ADDRESS"));
        let pk = get("PRIVATE_KEY").or_else(|| get("STARKNET_OPERATOR_PRIVATE_KEY"));
        if let Some(a) = addr {
            cfg.account_address = Some(parse_felt(&a)?);
        }
        if let Some(p) = pk {
            cfg.private_key = Some(parse_felt(&p)?);
        }
        if let Some(d) = get("POKER_CONTRACTS_ARTIFACTS_DIR") {
            cfg.artifacts_dir = PathBuf::from(d);
        }
        // starknet-devnet 0.9.x 预部署 UDC 为 0x2cee…（非主网 legacy 地址）
        if let Some(u) = get("POKER_CONTRACTS_UDC") {
            cfg.udc = parse_felt(&u)?;
        }
        if let Some(s) = get("STARKNET_STRK_ADDRESS") {
            cfg.strk = parse_felt(&s)?;
        }
        if let Some(p) = get("POKER_CONTRACTS_POOL") {
            cfg.pool = Some(parse_felt(&p)?);
        }
        if cfg.pool.is_none() {
            cfg.pool = preset.default_pool.map(parse_felt).transpose()?;
        }
        if let Some(h) = get("POKER_CONTRACTS_PROGRAM_HASH") {
            cfg.circuit_program_hash = parse_felt(&h)?;
        }
        if let Some(h) = get("POKER_CONTRACTS_HAND_VERIFY_PROGRAM_HASH") {
            cfg.hand_verify_program_hash = parse_felt(&h)?;
        }
        if let Some(g) = get("POKER_CONTRACTS_REGISTRY_GRACE_SECS") {
            cfg.registry_grace_secs =
                g.trim().parse::<u64>().map_err(|e| ContractsError::Config(format!("grace secs: {e}")))?;
        }
        if let Some(w) = get("POKER_CONTRACTS_WITH_TABLE_REGISTRY") {
            cfg.with_table_registry = matches!(w.trim(), "1" | "true" | "yes");
        }
        cfg.addresses = DeployedAddresses {
            vault: get("STARKNET_VAULT_ADDRESS").map(|v| parse_felt(&v)).transpose()?,
            settlement: get("STARKNET_SETTLEMENT_ADDRESS").map(|v| parse_felt(&v)).transpose()?,
            dual: get("STARKNET_DUAL_SETTLEMENT_ADDRESS")
                .map(|v| parse_felt(&v))
                .transpose()?,
            vault_anonymizer: get("STARKNET_VAULT_ANONYMIZER_ADDRESS")
                .map(|v| parse_felt(&v))
                .transpose()?,
            payout_anonymizer: get("STARKNET_CLAIM_HELPER_ADDRESS")
                .map(|v| parse_felt(&v))
                .transpose()?,
            table_registry: get("STARKNET_TABLE_REGISTRY_ADDRESS")
                .map(|v| parse_felt(&v))
                .transpose()?,
        };
        Ok(cfg)
    }

    /// 解析 dotenv 风格 `.env` 文件（`KEY=VALUE`，`#` 注释，值可带引号），
    /// 供 CLI `--env-file <texas/.env>` 直接复用 poker_texas_air 配置。
    ///
    /// # Errors
    /// 文件不可读 → [`ContractsError::Config`]。
    pub fn from_env_file(path: &Path) -> ContractsResult<Self> {
        let map = parse_env_file(path)?;
        Self::from_env_map(&map)
    }

    /// 合约 owner（显式 > 账户地址）。
    ///
    /// # Errors
    /// 两者都缺 → [`ContractsError::Config`]。
    pub fn effective_owner(&self) -> ContractsResult<Felt> {
        self.owner
            .or(self.account_address)
            .ok_or_else(|| ContractsError::Config("owner required: set ADDRESS/owner".into()))
    }

    /// 结算 initial_prover（= operator，缺省 = owner）。
    ///
    /// # Errors
    /// 无法确定 → [`ContractsError::Config`]。
    pub fn effective_prover(&self) -> ContractsResult<Felt> {
        if let Some(p) = self.prover {
            return Ok(p);
        }
        self.effective_owner()
    }
}

/// 默认产物目录：`<crate>/../poker_texas_air/poker_contracts/target/dev`
/// （与 poker-appchain-texasair 的 `../../poker_texas_air` 同路径约定）。
#[must_use]
pub fn default_artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("../poker_texas_air/poker_contracts/target/dev"))
        .unwrap_or_default()
}

/// dotenv 风格解析（供 CLI；`#[allow]`——`parse_env_file` 也被测试用）。
///
/// # Errors
/// 文件不可读 → [`ContractsError::Config`]。
pub fn parse_env_file(
    path: &Path,
) -> ContractsResult<std::collections::BTreeMap<String, String>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| ContractsError::Config(format!("read {}: {e}", path.display())))?;
    let mut map = std::collections::BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim().to_owned();
        if k.is_empty() {
            continue;
        }
        let mut v = v.trim();
        // 去引号 + 行内 ` #` 注释（保守：仅处理带引号前的注释）
        if let Some(pos) = v.find(" #") {
            v = v[..pos].trim_end();
        }
        let v = v.trim_matches('"').trim_matches('\'').to_owned();
        map.entry(k).or_insert(v);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn network_presets_match_poker_texas_air() {
        let devnet = Network::Devnet.preset();
        assert_eq!(devnet.rpc_url, "http://127.0.0.1:5051");
        assert_eq!(devnet.chain_id, "SN_SEPOLIA"); // devnet 与 sepolia 同链 id
        assert_eq!(Network::Sepolia.preset().chain_id, "SN_SEPOLIA");
        let main = Network::Mainnet.preset();
        assert_eq!(main.chain_id, "SN_MAIN");
        assert!(main.default_pool.is_some());
        assert_eq!(main.registry_grace_secs, 604_800);
        assert!(Network::parse("DEVNET").is_ok());
        assert!(Network::parse("testnet").is_err());
    }

    #[test]
    fn env_map_full_parse() {
        let cfg = ContractsConfig::from_env_map(&map(&[
            ("POKER_CONTRACTS_NETWORK", "sepolia"),
            ("ADDRESS", "0x6e37"),
            ("PRIVATE_KEY", "0x1234"),
            ("STARKNET_VAULT_ADDRESS", "0xabc"),
            ("STARKNET_CLAIM_HELPER_ADDRESS", "0xdef"),
            ("POKER_CONTRACTS_WITH_TABLE_REGISTRY", "true"),
            ("POKER_CONTRACTS_REGISTRY_GRACE_SECS", "7200"),
        ]))
        .unwrap();
        assert_eq!(cfg.network, Network::Sepolia);
        assert_eq!(
            cfg.rpc_url,
            Network::Sepolia.preset().rpc_url
        );
        assert_eq!(cfg.account_address.unwrap(), parse_felt("0x6e37").unwrap());
        assert_eq!(cfg.addresses.vault.unwrap(), parse_felt("0xabc").unwrap());
        // STARKNET_CLAIM_HELPER_ADDRESS = payout anonymizer（server env 命名）
        assert_eq!(
            cfg.addresses.payout_anonymizer.unwrap(),
            parse_felt("0xdef").unwrap()
        );
        assert!(cfg.with_table_registry);
        assert_eq!(cfg.registry_grace_secs, 7200);
        // 主网才有内置 pool，sepolia 需显式
        assert!(cfg.pool.is_none());
    }

    #[test]
    fn env_map_operator_fallback_and_mainnet_pool_default() {
        let cfg = ContractsConfig::from_env_map(&map(&[
            ("POKER_CONTRACTS_NETWORK", "mainnet"),
            ("STARKNET_OPERATOR_ADDRESS", "0x42"),
            ("STARKNET_OPERATOR_PRIVATE_KEY", "0x99"),
        ]))
        .unwrap();
        assert_eq!(cfg.account_address.unwrap(), parse_felt("0x42").unwrap());
        // 主网默认 pool 自动带上
        assert_eq!(
            cfg.pool.unwrap(),
            parse_felt(MAINNET_STRK20_POOL).unwrap()
        );
        // 规范 STRK 默认
        assert_eq!(cfg.strk, parse_felt(CANONICAL_STRK).unwrap());
    }

    #[test]
    fn env_file_parses_quotes_and_comments() {
        let dir = std::env::temp_dir().join("poker-contracts-test-env");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".env.test");
        std::fs::write(
            &path,
            "# comment\nSTARKNET_RPC_URL=https://rpc.example\nADDRESS=\"0xabc\" # inline\nPRIVATE_KEY='0x01'\nBROKEN_LINE\n\n",
        )
        .unwrap();
        let cfg = ContractsConfig::from_env_file(&path).unwrap();
        assert_eq!(cfg.rpc_url, "https://rpc.example");
        assert_eq!(cfg.account_address.unwrap(), parse_felt("0xabc").unwrap());
        assert_eq!(cfg.private_key.unwrap(), parse_felt("0x01").unwrap());
    }

    #[test]
    fn effective_owner_prover_fallback_chain() {
        let mut cfg = ContractsConfig::default();
        assert!(cfg.effective_owner().is_err());
        cfg.account_address = Some(Felt::from(7_u64));
        // prover 缺省回落 owner（= 账户地址）
        assert_eq!(cfg.effective_prover().unwrap(), Felt::from(7_u64));
        // 显式 owner 优先于账户地址
        cfg.owner = Some(Felt::from(9_u64));
        cfg.prover = Some(Felt::from(11_u64));
        assert_eq!(cfg.effective_owner().unwrap(), Felt::from(9_u64));
        assert_eq!(cfg.effective_prover().unwrap(), Felt::from(11_u64));
    }
}
