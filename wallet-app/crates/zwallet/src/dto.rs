//! 壳层 DTO（serde JSON）：UI/命令层与 [`zwallet::Wallet`] 之间的全部数据
//! 形状。`SigningPreview` 直接复用 wallet-core 的 serde 结构——**确认页展示
//! 的每个字段与签名摘要绑定的是同一份数据**（M6-ACC-7）。

use serde::{Deserialize, Serialize};
use wallet_core::display::{PlayPageView, RealPageView};
use wallet_core::operation_signer::SigningPreview;

/// 应用固定网络上下文：devnet（MVP 不连网，写明）。
pub const CHAIN_ID: &str = "zchain-devnet-1";
/// 应用固定域标签（wallet-core `parse_domain` 只认 `zchain`）。
pub const DOMAIN: &str = "zchain";
/// Operation ABI 版本（wallet-core `SUPPORTED_ABI_VERSION`）。
pub const ABI_VERSION: u32 = wallet_core::operation_signer::SUPPORTED_ABI_VERSION;
/// 默认自动锁屏（秒）。
pub const DEFAULT_AUTO_LOCK_SECS: u64 = 300;
/// 签名请求默认有效期（秒）。
pub const REQUEST_TTL_SECS: u64 = 600;

/// 钱包整体状态视图（状态栏/锁屏/账户页共用）。
#[derive(Debug, Clone, Serialize)]
pub struct StatusDto {
    /// 数据目录是否已有 keystore。
    pub initialized: bool,
    /// 当前是否锁定（含未解锁/自动锁屏）。
    pub locked: bool,
    /// chain id（固定 `zchain-devnet-1`；MVP 无联网，写明）。
    pub chain_id: String,
    /// 域标签（`zchain`）。
    pub domain: String,
    /// Operation ABI 版本。
    pub abi_version: u32,
    /// 网络展示名。
    pub network_label: String,
    /// owner 公钥（66 hex；锁定时 None）。
    pub owner_public_hex: Option<String>,
    /// 余额视图（锁定时 None）。
    pub balances: Option<BalancesDto>,
    /// 自动锁屏秒数。
    pub auto_lock_secs: u64,
    /// 距自动锁屏剩余秒数（锁定时 0）。
    pub lock_remaining_secs: u64,
    /// 数据目录（透明展示）。
    pub data_dir: String,
    /// 环境徽章文案（每页固定显示）。
    pub environment_badge: String,
}

/// 余额视图：PLAY 主导 + REAL 展示门（wallet-core `display` 决定，壳层不自行决定）。
#[derive(Debug, Clone, Serialize)]
pub struct BalancesDto {
    /// PLAY 自由余额（十进制字符串；u128 不进 JS number）。
    pub play_free: String,
    /// PLAY 桌内锁定。
    pub play_locked: String,
    /// REAL 自由余额（十进制字符串）。
    pub real_free: String,
    /// REAL 桌内锁定。
    pub real_locked: String,
    /// PLAY 页视图（类型上没有 REAL 字段）。
    pub play_view: PlayPageView,
    /// REAL 页视图（claim/提现门 + 托管风险提示）。
    pub real_view: RealPageView,
}

/// note 列表页视图。
#[derive(Debug, Clone, Serialize)]
pub struct NotesPageDto {
    /// PLAY note 列表。
    pub play: Vec<NoteDto>,
    /// PLAY 自由余额。
    pub play_free: String,
    /// PLAY 桌内锁定。
    pub play_locked: String,
    /// PLAY 页视图（faucet 门）。
    pub play_view: PlayPageView,
    /// 数据来源说明（MVP 无联网：本地演示数据）。
    pub data_source_notice: String,
}

/// 单张 note 展示。
#[derive(Debug, Clone, Serialize)]
pub struct NoteDto {
    /// 承诺（64 hex）。
    pub commitment_hex: String,
    /// 面额。
    pub amount: u64,
    /// 桌 ID（None = 自由 note）。
    pub table_id: Option<u64>,
    /// proof 状态名（pending/soft/proven/finalized）。
    pub proof: String,
    /// 消费该 note 的 op 序号（None = 未花费）。
    pub spent_by_op: Option<u64>,
    /// nullifier（64 hex；由 spend secret 派生）。
    pub nullifier_hex: String,
    /// 创建帧 op 序号。
    pub origin_op_index: u64,
    /// 是否为本地演示铸造（faucet；MVP 无联网，如实标注）。
    pub demo: bool,
}

/// 结构化签名请求 DTO（壳层只暴露 transfer / buy_in；PLAY only，见 README 边界）。
#[derive(Debug, Clone, Deserialize)]
pub struct SignRequestDto {
    /// `"transfer"` 或 `"buy_in"`。
    pub kind: String,
    /// 资产类；devnet 演示钱包只接受 `"PLAY"`。
    #[serde(default = "default_asset")]
    pub asset_class: String,
    /// 输入 note 承诺（64 hex）；空 = 自动选择未花费 note（greedy）。
    #[serde(default)]
    pub inputs: Vec<String>,
    /// 输出条目（transfer）。
    #[serde(default)]
    pub outputs: Vec<OutputDto>,
    /// 桌 ID（buy_in）。
    #[serde(default)]
    pub table_id: Option<u64>,
    /// seat 归属（66 hex；buy_in；缺省 = 本钱包 owner）。
    #[serde(default)]
    pub seat_owner: Option<String>,
    /// 显式 nonce（缺省 = 自动分配）。
    #[serde(default)]
    pub nonce: Option<u64>,
    /// 显式过期（unix 秒；缺省 = now + 600）。
    #[serde(default)]
    pub expiry: Option<u64>,
}

fn default_asset() -> String {
    "PLAY".into()
}

/// 输出条目 DTO。
#[derive(Debug, Clone, Deserialize)]
pub struct OutputDto {
    /// 收款 owner（66 hex 压缩公钥）。
    pub owner: String,
    /// 面额 > 0。
    pub amount: u64,
}

/// 签名结果 DTO：预览 + 确认摘要 + 完整操作（borsh hex）。
#[derive(Debug, Clone, Serialize)]
pub struct SignedDto {
    /// 人类可读预览（确认页逐字段展示的就是它）。
    pub preview: SigningPreview,
    /// 钱包确认摘要（64 hex）。
    pub digest_hex: String,
    /// 完整账本操作（borsh hex；ABI 与 poker-appchain 一致）。
    pub operation_borsh_hex: String,
}

/// 备份导出信息（文件字节单独返回，供壳层写盘/下载）。
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfoDto {
    /// 魔数（`ZCBK`）。
    pub magic: String,
    /// 备份格式版本。
    pub version: u16,
    /// 创建时间（unix 秒）。
    pub created_unix: u64,
    /// REAL 库 note 数。
    pub notes_real: usize,
    /// PLAY 库 note 数。
    pub notes_play: usize,
    /// 建议文件名。
    pub suggested_filename: String,
}
