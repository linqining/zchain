//! M7-ACC-5：withdrawal root 聚合 + permissionless claim 校验关系（纯逻辑层）。
//!
//! plan §5.4 提款流程的后半段关系层：`REAL note burn → WithdrawalLeaf →
//! 聚合为 withdrawal_root（按 checkpoint 分窗）→ BFT finalized checkpoint
//! 携带 withdrawal_root → 用户持 Merkle proof 在 Vault permissionless
//! claim`。本模块交付其中**不依赖链上合约**的部分：
//!
//! 1. [`WithdrawalLeaf`]：单笔提现的完整绑定（request_id、外部收款地址、
//!    资产类、**打款净额**、被销毁 note 承诺、checkpoint 高度）；
//! 2. [`WithdrawalRootBuilder`]：按 `checkpoint_height` 分窗聚合 →
//!    [`WithdrawalRoot`]；窗口内叶子按 borsh 编码字典序规范化（顺序无关
//!    聚合，与 payout_root 同一 house convention）；空窗不产根；
//! 3. 包含证明：[`WithdrawalRootBuilder::merkle_proof`] +
//!    [`verify_inclusion`]（RFC 6962 风格域分离双 sha256）；
//! 4. [`ClaimLedger`]：claim 校验链——根存在且 **finalized**（[`ClaimLedger::
//!    mark_finalized`] 之后才可 claim；未 finalized →
//!    [`AppchainError::RootNotFinalized`]）→ 包含证明通过（失败/篡改 →
//!    [`AppchainError::WithdrawalProofInvalid`]）→ request_id 未领过（重领
//!    → [`AppchainError::AlreadyClaimed`]）→ 标记已领。claim 状态经 JSONL
//!    sidecar 持久化（契约冻结，撕裂尾行容错），重载等价。
//!
//! ## 树规则（域标签 [`WITHDRAWAL_ROOT_DOMAIN`] 先置 + RFC 6962 前缀）
//!
//! - 叶：`H(DOMAIN ‖ 0x00 ‖ borsh(leaf))`；内部节点：`H(DOMAIN ‖ 0x01 ‖ l ‖ r)`；
//!   不平衡 → 空叶哈希 `H(DOMAIN ‖ 0x00 ‖ b"")` 补齐到 2 的幂
//!   （与 `poker-settlement-core::payout_root` 同一构造，哈希换成 sha256）；
//! - 根摘要（claim 台账主键）：`H(DOMAIN ‖ 0x02 ‖ height_be ‖
//!   leaf_count_be ‖ root)`——绑定 (checkpoint_height, leaf_count, root)
//!   三元组，防跨窗/跨规模摘要混用。
//!
//! ## 边界（本任务不做，属后续阶段）
//!
//! - 链上 Vault 合约的 claim 入口（Vault verifier 阶段）；
//! - STARK proof 验证挂接（出证策略在 `real_policy`）；
//! - checkpoint v1 尚无 `withdrawal_root` 字段——字段集成由主控后续排；
//!   本模块独立定义根，届时由 checkpoint 携带 [`WithdrawalRoot`]；
//! - Starknet felt252 地址映射（`external_recipient` 为抽象 32B 外部地址）。
//!
//! ## 域标签
//!
//! [`WITHDRAWAL_ROOT_DOMAIN`] = `zchain.vault.withdrawal_root.v1` 定义于本
//! 模块，**待 ABI.md 统一收录**（见 `docs/ABI_WITHDRAWAL_ROOT.md`）。

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write as _};
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

use crate::error::{AppchainError, AppchainResult};

/// withdrawal root 域标签（待 ABI.md 统一收录；见模块文档）。
pub const WITHDRAWAL_ROOT_DOMAIN: &[u8] = b"zchain.vault.withdrawal_root.v1";

/// RFC 6962 叶子前缀。
const LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 内部节点前缀。
const INTERNAL_PREFIX: u8 = 0x01;
/// 根摘要前缀（同一域标签下的第三类域分离）。
const DIGEST_PREFIX: u8 = 0x02;

/// 单笔提现的完整绑定（§5.4 `WithdrawalLeaf`；plan 要求的五个绑定字段 +
/// checkpoint 高度，全字段进叶哈希，任一字段差异改变根）。
///
/// `amount` 语义为**打款净额**：M7 提现费从请求金额内扣
/// （`payout_amount = amount − flat_fee`，见 `vault::WithdrawalFeeConfig`），
/// 叶子承诺的是对外应付数而非含费数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct WithdrawalLeaf {
    /// 提现请求幂等键（== `vault::WithdrawalRequest.request_id`；claim 台账
    /// 按 request_id 防重放）。
    pub request_id: [u8; 32],
    /// 外部收款地址（抽象 32B；v1 语义 = Starknet 地址字节——felt252 映射
    /// 属链上 Vault 合约阶段，本层不解释字节内容）。
    pub external_recipient: [u8; 32],
    /// 资产类判别值（REAL=1 / PLAY=2，与 `note::AssetClass` /
    /// `PayoutLeaf.asset_class` 一致）。
    ///
    /// TE-M2 语义扩展（编码不变）：本字节升级为**资产标签**——追加
    /// USDT=3 / USDC=4（REAL 域 token 判别），见 [`leaf_asset_tag`] 与
    /// [`leaf_asset_tag_of`]；v1 取值 1/2 字节不变（golden 向量零回退）。
    pub asset_class: u8,
    /// 打款净额（> 0；fee 从请求金额内扣后的 `payout_amount`）。
    pub amount: u64,
    /// 被销毁 REAL/PLAY note 的承诺（`Operation::WithdrawRequest.spend.
    /// commitment`；把领取权钉死在已 burn 的 note 上）。
    pub burned_note_commitment: [u8; 32],
    /// 承载本叶的 checkpoint 高度（分窗键；根只能在其 checkpoint BFT
    /// finalized 后被 claim——M7-ACC-5"未 finalized 的根全部拒绝"）。
    pub checkpoint_height: u64,
}

// ===========================================================================
// TE-M2：leaf 资产维度（`asset_class` 字节**语义扩展为 token 判别**；
// docs/ABI_TE_M2.md §leaf 字段演进记录）
//
// 选型说明（追加字段 vs 语义扩展 二选一）：**选择语义扩展**——
// [`WithdrawalLeaf`] 的 borsh 字段布局与字节编码**完全冻结不动**
// （golden 向量零回退），资产 token 维度折叠进既有 `asset_class` 单字节
// 判别：v1 判别值 1（REAL）/ 2（PLAY）**字节不变**（旧用例零回退），
// TE-M2 新增 3 = REAL/USDT、4 = REAL/USDC；GAME 域注册表 token（TE-M3）
// 自 5 起由注册表分配。REAL 域封闭枚举只有三 token，单字节容量充足；
// 若未来需要表达任意 u32 token_id，只能升 ABI 版本换叶子编码（v2 字段）。
// ===========================================================================

/// TE-M2：[`WithdrawalLeaf.asset_class`] 字节的**资产标签**判别表
/// （语义扩展；标签值冻结，变更 = ABI 版本升级）。
pub mod leaf_asset_tag {
    /// REAL 域原生代币（== v1 `AssetClass::Real` 判别值，冻结不变）。
    pub const REAL_NATIVE: u8 = 1;
    /// GAME 域遗留休闲筹码（== v1 `AssetClass::Play` 判别值，冻结不变）。
    pub const GAME_PLAY_LEGACY: u8 = 2;
    /// REAL 域 USDT（TE-M2 新增判别值）。
    pub const REAL_USDT: u8 = 3;
    /// REAL 域 USDC（TE-M2 新增判别值）。
    pub const REAL_USDC: u8 = 4;
    /// GAME 域注册表 token 标签分配基线（TE-M3 注册表自此起分配；占位，
    /// 本版不使用）。
    pub const GAME_REGISTRY_BASE: u8 = 5;
}

/// TE-M2：[`AssetId`] → leaf 资产标签（冻结映射）。
///
/// # Errors 风格
/// 返回 `None` = 该资产在 v1 leaf 编码中**无表示**（GAME 域非遗留 token，
/// TE-M3 注册表落地前不得出根）——调用方必须 fail-closed 处理 `None`
/// （不认识 ≠ 接受）。
#[must_use]
pub fn leaf_asset_tag_of(asset: crate::asset_id::AssetId) -> Option<u8> {
    use crate::asset_id::AssetId;
    match asset {
        AssetId::REAL_NATIVE => Some(leaf_asset_tag::REAL_NATIVE),
        AssetId::REAL_USDT => Some(leaf_asset_tag::REAL_USDT),
        AssetId::REAL_USDC => Some(leaf_asset_tag::REAL_USDC),
        AssetId::GAME_PLAY => Some(leaf_asset_tag::GAME_PLAY_LEGACY),
        _ => None,
    }
}

/// sha256-256，输入各段依次拼接。
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// RFC 6962 叶子哈希：`H(DOMAIN ‖ 0x00 ‖ borsh(leaf))`。
#[must_use]
pub fn leaf_hash(leaf: &WithdrawalLeaf) -> [u8; 32] {
    let encoded = borsh::to_vec(leaf).expect("WithdrawalLeaf borsh is infallible");
    sha256(&[WITHDRAWAL_ROOT_DOMAIN, &[LEAF_PREFIX], &encoded])
}

/// RFC 6962 内部节点哈希：`H(DOMAIN ‖ 0x01 ‖ l ‖ r)`。
fn internal_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    sha256(&[WITHDRAWAL_ROOT_DOMAIN, &[INTERNAL_PREFIX], l, r])
}

/// 空叶哈希（不平衡树补齐用）：`H(DOMAIN ‖ 0x00 ‖ b"")`。
fn empty_leaf_hash() -> [u8; 32] {
    sha256(&[WITHDRAWAL_ROOT_DOMAIN, &[LEAF_PREFIX], &[]])
}

/// 一个 checkpoint 窗口的聚合产物：Merkle 根 + 其摘要（claim 台账主键）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WithdrawalRoot {
    /// 窗口 checkpoint 高度（== 窗口内全部叶子的 `checkpoint_height`）。
    pub checkpoint_height: u64,
    /// 窗口内真实叶子数（不含补齐空叶；claim 时索引用于界内判定）。
    pub leaf_count: u64,
    /// 32B Merkle 根（checkpoint 携带字段——字段集成属后续，见模块文档）。
    pub root: [u8; 32],
    /// 根摘要：`H(DOMAIN ‖ 0x02 ‖ height_be ‖ leaf_count_be ‖ root)`；
    /// claim 台账（[`ClaimLedger`]）以此为主键。
    pub digest: [u8; 32],
}

impl WithdrawalRoot {
    /// 由 (checkpoint_height, leaf_count, root) 重算根摘要。
    ///
    /// claim 时用于**摘要重绑定**：叶子声称的 checkpoint_height 必须与
    /// 台账注册记录重算出的摘要一致，否则按未 finalized 处理（fail-closed）。
    #[must_use]
    pub fn digest_of(checkpoint_height: u64, leaf_count: u64, root: [u8; 32]) -> [u8; 32] {
        sha256(&[
            WITHDRAWAL_ROOT_DOMAIN,
            &[DIGEST_PREFIX],
            &checkpoint_height.to_be_bytes(),
            &leaf_count.to_be_bytes(),
            &root,
        ])
    }
}

/// 窗口内叶子 → 折叠层级（levels[0] = 补齐后的叶哈希层，末层单元素 = 根）。
///
/// 叶子按 borsh 编码字典序规范化后建树（顺序无关聚合）；不平衡以空叶哈希
/// 补齐到 2 的幂（house convention）。
fn merkle_levels(leaves: &[WithdrawalLeaf]) -> Vec<Vec<[u8; 32]>> {
    let mut encoded: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| borsh::to_vec(leaf).expect("WithdrawalLeaf borsh is infallible"))
        .collect();
    encoded.sort();
    let mut level: Vec<[u8; 32]> = encoded
        .iter()
        .map(|bytes| sha256(&[WITHDRAWAL_ROOT_DOMAIN, &[LEAF_PREFIX], bytes]))
        .collect();
    let width = level.len().next_power_of_two();
    level.resize(width, empty_leaf_hash());
    let mut levels = vec![level];
    while levels.last().is_some_and(|l| l.len() > 1) {
        let prev = levels.last().expect("non-empty by construction");
        let next: Vec<[u8; 32]> = prev
            .chunks_exact(2)
            .map(|pair| internal_hash(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }
    levels
}

/// 按 `checkpoint_height` 分窗聚合 [`WithdrawalLeaf`] → [`WithdrawalRoot`]。
///
/// - `push` 按 `leaf.checkpoint_height` 归窗；同窗叶子按 borsh 编码字典序
///   规范化，**输入顺序不影响根**；
/// - `request_id` 全局去重（同一提现请求只能进一个窗口一次；重复 →
///   [`AppchainError::WithdrawalConflict`]，fail-closed）；
/// - 空窗不产根：`build` 对空窗返回 [`AppchainError::OutOfRange`]；
///   `build_all` 对无叶输入返回空表。
#[derive(Debug, Default)]
pub struct WithdrawalRootBuilder {
    /// 窗口高度 → 窗口叶子（保持插入序；建树时再规范化排序）。
    windows: BTreeMap<u64, Vec<WithdrawalLeaf>>,
    /// 已见 request_id（跨窗去重）。
    seen: BTreeSet<[u8; 32]>,
}

impl WithdrawalRootBuilder {
    /// 空构建器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 归窗一条叶子。
    ///
    /// # Errors
    /// `request_id` 已被本构建器收录（任意窗口）→
    /// [`AppchainError::WithdrawalConflict`]。
    pub fn push(&mut self, leaf: WithdrawalLeaf) -> AppchainResult<()> {
        if !self.seen.insert(leaf.request_id) {
            return Err(AppchainError::WithdrawalConflict(
                "duplicate withdrawal request_id in root builder".into(),
            ));
        }
        self.windows
            .entry(leaf.checkpoint_height)
            .or_default()
            .push(leaf);
        Ok(())
    }

    /// 窗口高度列表（升序）。
    #[must_use]
    pub fn window_heights(&self) -> Vec<u64> {
        self.windows.keys().copied().collect()
    }

    /// 窗口叶子数（未知窗口 → 0）。
    #[must_use]
    pub fn leaf_count(&self, checkpoint_height: u64) -> usize {
        self.windows.get(&checkpoint_height).map_or(0, Vec::len)
    }

    /// 聚合指定窗口 → [`WithdrawalRoot`]。
    ///
    /// # Errors
    /// 空窗（未 push 过该高度）→ [`AppchainError::OutOfRange`]（空窗不产根）。
    pub fn build(&self, checkpoint_height: u64) -> AppchainResult<WithdrawalRoot> {
        let leaves = self
            .windows
            .get(&checkpoint_height)
            .ok_or(AppchainError::OutOfRange("withdrawal window is empty"))?;
        let levels = merkle_levels(leaves);
        let root = levels[levels.len() - 1][0];
        let leaf_count = leaves.len() as u64;
        Ok(WithdrawalRoot {
            checkpoint_height,
            leaf_count,
            root,
            digest: WithdrawalRoot::digest_of(checkpoint_height, leaf_count, root),
        })
    }

    /// 聚合全部非空窗口（按高度升序；空构建器 → 空表——空窗不产根）。
    #[must_use]
    pub fn build_all(&self) -> Vec<WithdrawalRoot> {
        self.window_heights()
            .iter()
            .filter_map(|&h| self.build(h).ok())
            .collect()
    }

    /// 叶子在规范化（borsh 字典序）树中的位置——Merkle proof 的索引语义。
    #[must_use]
    pub fn leaf_index(&self, checkpoint_height: u64, request_id: &[u8; 32]) -> Option<usize> {
        let leaves = self.windows.get(&checkpoint_height)?;
        let mut indexed: Vec<(Vec<u8>, usize)> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| {
                (
                    borsh::to_vec(leaf).expect("WithdrawalLeaf borsh is infallible"),
                    i,
                )
            })
            .collect();
        indexed.sort();
        indexed
            .iter()
            .position(|(_, i)| leaves[*i].request_id == *request_id)
    }

    /// 窗口内某叶子的 Merkle 包含证明（兄弟路径，自叶向根）。
    ///
    /// # Errors
    /// 空窗 → [`AppchainError::OutOfRange`]；`leaf_index` 越出真实叶子数
    /// （补齐空叶不是可领取位）→ [`AppchainError::OutOfRange`]。
    pub fn merkle_proof(
        &self,
        checkpoint_height: u64,
        leaf_index: usize,
    ) -> AppchainResult<Vec<[u8; 32]>> {
        let leaves = self
            .windows
            .get(&checkpoint_height)
            .ok_or(AppchainError::OutOfRange("withdrawal window is empty"))?;
        if leaf_index >= leaves.len() {
            return Err(AppchainError::OutOfRange(
                "withdrawal leaf index beyond window",
            ));
        }
        let levels = merkle_levels(leaves);
        let mut proof = Vec::with_capacity(levels.len().saturating_sub(1));
        let mut idx = leaf_index;
        for level in &levels[..levels.len() - 1] {
            proof.push(level[idx ^ 1]);
            idx >>= 1;
        }
        Ok(proof)
    }
}

/// Merkle 包含证明校验（纯函数；claim 链的第二环）。
///
/// `index` 为叶子在规范化树中的位置；证明路径按 `index` 的低位决定左右
/// 拼接次序。fail-closed 边界：证明长度 > 64 或 `index >= 2^len(proof)`
/// 一律 `false`（形状不可能属于本树）。
#[must_use]
pub fn verify_inclusion(
    leaf: &WithdrawalLeaf,
    proof: &[[u8; 32]],
    index: u64,
    root: [u8; 32],
) -> bool {
    if proof.len() >= 64 {
        return false;
    }
    if index >= 1u64 << proof.len() {
        return false;
    }
    let mut h = leaf_hash(leaf);
    for (depth, node) in proof.iter().enumerate() {
        h = if (index >> depth) & 1 == 0 {
            internal_hash(&h, node)
        } else {
            internal_hash(node, &h)
        };
    }
    h == root
}

/// 已 finalized 的根注册记录（claim 台账侧；`digest` 为 BTreeMap 键不入记录）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedRoot {
    /// 窗口 checkpoint 高度。
    pub checkpoint_height: u64,
    /// 真实叶子数。
    pub leaf_count: u64,
    /// 32B Merkle 根。
    pub root: [u8; 32],
}

/// JSONL sidecar 事件（重放中间形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaimLogEvent {
    /// 根 finalization 记录。
    Finalized {
        /// 根摘要（主键）。
        digest: [u8; 32],
        /// 窗口高度。
        checkpoint_height: u64,
        /// 叶子数。
        leaf_count: u64,
        /// 32B 根。
        root: [u8; 32],
    },
    /// 领取记录。
    Claimed {
        /// 请求 id。
        request_id: [u8; 32],
        /// 领取所依据的根摘要。
        digest: [u8; 32],
    },
}

/// 契约行编码（字段名/顺序/编码冻结，紧凑 JSON + 换行；见
/// `docs/ABI_WITHDRAWAL_ROOT.md`）：
///
/// ```text
/// {"kind":"finalized","digest_hex":"<64hex>","checkpoint_height":<u64>,"leaf_count":<u64>,"root_hex":"<64hex>"}
/// {"kind":"claimed","request_id_hex":"<64hex>","digest_hex":"<64hex>"}
/// ```
fn encode_line(event: &ClaimLogEvent) -> String {
    match event {
        ClaimLogEvent::Finalized {
            digest,
            checkpoint_height,
            leaf_count,
            root,
        } => format!(
            "{{\"kind\":\"finalized\",\"digest_hex\":\"{}\",\"checkpoint_height\":{},\"leaf_count\":{},\"root_hex\":\"{}\"}}\n",
            hex::encode(digest),
            checkpoint_height,
            leaf_count,
            hex::encode(root),
        ),
        ClaimLogEvent::Claimed { request_id, digest } => format!(
            "{{\"kind\":\"claimed\",\"request_id_hex\":\"{}\",\"digest_hex\":\"{}\"}}\n",
            hex::encode(request_id),
            hex::encode(digest),
        ),
    }
}

/// 解析一行契约记录（缺字段/类型错/bad hex → Err）。
fn parse_line(line: &str) -> Result<ClaimLogEvent, &'static str> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|_| "bad json")?;
    let obj = v.as_object().ok_or("not a json object")?;
    let field_hex = |name: &str| -> Result<[u8; 32], &'static str> {
        let s = obj
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or("missing/invalid hex field")?;
        hex::decode(s)
            .map_err(|_| "field not hex")?
            .try_into()
            .map_err(|_| "field not 32 bytes (64 hex)")
    };
    let field_u64 = |name: &str| -> Result<u64, &'static str> {
        obj.get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or("missing/invalid u64 field")
    };
    match obj.get("kind").and_then(serde_json::Value::as_str) {
        Some("finalized") => Ok(ClaimLogEvent::Finalized {
            digest: field_hex("digest_hex")?,
            checkpoint_height: field_u64("checkpoint_height")?,
            leaf_count: field_u64("leaf_count")?,
            root: field_hex("root_hex")?,
        }),
        Some("claimed") => Ok(ClaimLogEvent::Claimed {
            request_id: field_hex("request_id_hex")?,
            digest: field_hex("digest_hex")?,
        }),
        _ => Err("missing/invalid kind"),
    }
}

/// sidecar 追加写端（与 proven log / proof registry 同写入纪律：整行追加 +
/// flush；默认只 flush 不 fsync，[`ClaimLogWriter::with_fsync`] 可开真落盘）。
#[derive(Debug)]
struct ClaimLogWriter {
    file: BufWriter<File>,
    /// `true` 时追加后 `sync_all`（数据 + 元数据真落盘）。
    fsync: bool,
}

impl ClaimLogWriter {
    /// 打开（create + append；调用方负责目录存在与单写者）。
    fn open(path: &Path) -> AppchainResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| AppchainError::WalCorrupted("withdrawal claim log open failed"))?;
        Ok(Self {
            file: BufWriter::new(file),
            fsync: false,
        })
    }

    /// fsync 开关（builder 风格）。
    fn with_fsync(&mut self, enabled: bool) -> &mut Self {
        self.fsync = enabled;
        self
    }

    /// 追加一行完整契约记录（含换行；flush；可选 fsync）。
    fn append(&mut self, line: &str) -> AppchainResult<()> {
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|_| AppchainError::WalCorrupted("withdrawal claim log write failed"))?;
        if self.fsync {
            self.file
                .get_ref()
                .sync_all()
                .map_err(|_| AppchainError::WalCorrupted("withdrawal claim log fsync failed"))?;
        }
        Ok(())
    }
}

/// 读取并解析 claim sidecar（容错语义与 proven log / proof registry 一致）：
/// 空文件合法；**最后一行无换行（撕裂写）一律忽略 + 告警**（即使恰好可
/// 解析）；中间行违反冻结契约 → Err（连续前缀承诺已破）。
///
/// 返回 `(事件序列, 截断修复点)`：撕裂尾行存在时第二项为 `Some(offset)`
/// （最后一条完整行的终点）——[`ClaimLedger::open`] 据此在打开追加写端前
/// **物理截断**残行（语义上本就被忽略；不截断则下次追加会拼接在残行上
/// 产生损坏合并行，见模块文档"写入纪律"）。
fn read_claim_log(path: &Path) -> AppchainResult<(Vec<ClaimLogEvent>, Option<u64>)> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        // 首次打开（文件尚不存在）= 空日志（create-on-open，与 WAL 同语义）
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), None)),
        Err(_) => {
            return Err(AppchainError::WalCorrupted(
                "withdrawal claim log open failed",
            ));
        }
    };
    if bytes.is_empty() {
        return Ok((Vec::new(), None));
    }
    let torn_offset: Option<u64> = if bytes.last() == Some(&b'\n') {
        None
    } else {
        Some(match bytes.iter().rposition(|&b| b == b'\n') {
            Some(pos) => pos as u64 + 1,
            None => 0,
        })
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| AppchainError::WalCorrupted("withdrawal claim log not utf-8"))?;
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    if ends_with_newline {
        lines.pop(); // split 对换行结尾产生的空尾串
    } else {
        // 撕裂尾行：无换行结尾的最后一行一律忽略并告警。
        match lines.pop() {
            Some(tail) if !tail.trim().is_empty() => {
                eprintln!(
                    "[poker-appchain::withdrawal_root] warning: torn final line \
                     ignored ({} bytes, no newline)",
                    tail.len()
                );
            }
            _ => {}
        }
    }
    let mut out = Vec::with_capacity(lines.len());
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let event = parse_line(line)
            .map_err(|why| AppchainError::Codec(format!("claim log line {}: {why}", i + 1)))?;
        out.push(event);
    }
    Ok((out, torn_offset))
}

/// 台账重放一条事件（`open` 恢复与内存写入共用同一状态转移，保证重载等价）。
/// 同 digest 幂等重放允许（identical → Ok）；任何载荷冲突 → Err（fail-closed：
/// 摘要绑定 (height, count, root)，冲突即哈希碰撞/日志损坏）。
fn apply_log_event(
    roots: &mut BTreeMap<[u8; 32], FinalizedRoot>,
    claimed: &mut BTreeMap<[u8; 32], [u8; 32]>,
    event: ClaimLogEvent,
) -> AppchainResult<()> {
    match event {
        ClaimLogEvent::Finalized {
            digest,
            checkpoint_height,
            leaf_count,
            root,
        } => {
            let record = FinalizedRoot {
                checkpoint_height,
                leaf_count,
                root,
            };
            match roots.get(&digest) {
                Some(prev) if *prev == record => Ok(()),
                Some(_) => Err(AppchainError::Codec(
                    "claim log: conflicting finalized record for digest".into(),
                )),
                None => {
                    roots.insert(digest, record);
                    Ok(())
                }
            }
        }
        ClaimLogEvent::Claimed { request_id, digest } => {
            // 领取记录必须指向已 finalized 的根（claim 链的第一环先于本事件
            // 写入；乱序 = 日志损坏，fail-closed）。
            if !roots.contains_key(&digest) {
                return Err(AppchainError::Codec(
                    "claim log: claimed record references unknown root digest".into(),
                ));
            }
            match claimed.get(&request_id) {
                Some(prev) if *prev == digest => Ok(()), // 幂等重放
                Some(_) => Err(AppchainError::Codec(
                    "claim log: conflicting claim record for request".into(),
                )),
                None => {
                    claimed.insert(request_id, digest);
                    Ok(())
                }
            }
        }
    }
}

/// claim 台账：finalized withdrawal root 注册表 + request_id 领取去重。
///
/// ## 校验链（M7-ACC-5，`claim` 按序执行，fail-closed）
///
/// 1. 根存在且 finalized：digest 必须已 [`ClaimLedger::mark_finalized`]，
///    **且**叶的 `checkpoint_height` 与注册记录重算摘要一致（摘要重绑定）；
///    任一不满足 → [`AppchainError::RootNotFinalized`]（未知 digest 按"未
///    finalized"处理）；
/// 2. 包含证明：索引界内 + [`verify_inclusion`] 通过；失败（含叶任一字段
///    被篡改）→ [`AppchainError::WithdrawalProofInvalid`]；
/// 3. 未领取：`request_id` 不在台账 → 已在 → [`AppchainError::AlreadyClaimed`]
///    （**Vault 自己检查"未领取"**，§5.4；校验顺序即 1→2→3，被篡改叶的重放
///    报证明错误而非重领错误）；
/// 4. 标记已领：先落 sidecar（写失败 → Err、内存不动——日志与状态不失步），
///    再更新内存。
///
/// ## 持久化
///
/// [`ClaimLedger::open`] 打开 JSONL sidecar（契约冻结见 [`encode_line`]；
/// 撕裂尾行容错；中间行损坏 fail-closed）并重放恢复状态——重载与原实例
/// **等价**（同一状态转移 [`apply_log_event`]）。[`ClaimLedger::new`] 为纯
/// 内存台账（测试/无盘场景）。
#[derive(Debug, Default)]
pub struct ClaimLedger {
    /// digest → finalized 根记录。
    roots: BTreeMap<[u8; 32], FinalizedRoot>,
    /// request_id → 领取依据的根摘要。
    claimed: BTreeMap<[u8; 32], [u8; 32]>,
    /// sidecar 写端（`None` = 纯内存台账）。
    log: Option<ClaimLogWriter>,
}

impl ClaimLedger {
    /// 纯内存台账（不落盘；测试/无盘场景）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 打开 sidecar 台账：重放既有日志（撕裂尾行忽略 + 物理截断修复——
    /// 残行不参与状态，截断使后续追加从完整行边界开始）+ 打开追加写端。
    /// 调用方负责目录存在与单写者。
    ///
    /// # Errors
    /// IO 失败 → [`AppchainError::WalCorrupted`]；中间行违反冻结契约或重放
    /// 语义冲突（乱序领取/载荷冲突）→ [`AppchainError::Codec`]。
    pub fn open(path: &Path) -> AppchainResult<Self> {
        let (events, torn_offset) = read_claim_log(path)?;
        let mut roots = BTreeMap::new();
        let mut claimed = BTreeMap::new();
        for event in events {
            apply_log_event(&mut roots, &mut claimed, event)?;
        }
        // 撕裂尾行修复：残行在重放中已被忽略（未入状态），物理截断使后续
        // 追加从完整行边界开始（否则追加会拼接在残行上产生损坏合并行）。
        if let Some(len) = torn_offset {
            let file = OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|_| AppchainError::WalCorrupted("claim log torn-tail repair failed"))?;
            file.set_len(len)
                .map_err(|_| AppchainError::WalCorrupted("claim log torn-tail repair failed"))?;
        }
        let log = ClaimLogWriter::open(path)?;
        Ok(Self {
            roots,
            claimed,
            log: Some(log),
        })
    }

    /// fsync 开关（builder 风格；仅 sidecar 模式有效）。
    pub fn with_fsync(&mut self, enabled: bool) -> &mut Self {
        if let Some(log) = &mut self.log {
            log.with_fsync(enabled);
        }
        self
    }

    /// 注册 finalized 根（幂等：同 digest 同载荷重复注册返回 Ok、不重复
    /// 落账）。digest 为 `root.digest`（绑定 height/leaf_count/root）。
    ///
    /// # Errors
    /// IO 失败 → [`AppchainError::WalCorrupted`]。
    pub fn mark_finalized(&mut self, root: &WithdrawalRoot) -> AppchainResult<()> {
        let record = FinalizedRoot {
            checkpoint_height: root.checkpoint_height,
            leaf_count: root.leaf_count,
            root: root.root,
        };
        if let Some(prev) = self.roots.get(&root.digest) {
            return if *prev == record {
                Ok(())
            } else {
                // 摘要绑定三元组；到不了这里除非哈希碰撞——fail-closed。
                Err(AppchainError::Codec(
                    "claim ledger: digest collision on finalized root".into(),
                ))
            };
        }
        let line = encode_line(&ClaimLogEvent::Finalized {
            digest: root.digest,
            checkpoint_height: root.checkpoint_height,
            leaf_count: root.leaf_count,
            root: root.root,
        });
        if let Some(log) = &mut self.log {
            log.append(&line)?;
        }
        self.roots.insert(root.digest, record);
        Ok(())
    }

    /// digest 是否已注册为 finalized。
    #[must_use]
    pub fn is_finalized(&self, digest: &[u8; 32]) -> bool {
        self.roots.contains_key(digest)
    }

    /// digest 的注册记录。
    #[must_use]
    pub fn finalized_root(&self, digest: &[u8; 32]) -> Option<FinalizedRoot> {
        self.roots.get(digest).copied()
    }

    /// 已注册 finalized 根数。
    #[must_use]
    pub fn finalized_count(&self) -> usize {
        self.roots.len()
    }

    /// request_id 是否已领取。
    #[must_use]
    pub fn is_claimed(&self, request_id: &[u8; 32]) -> bool {
        self.claimed.contains_key(request_id)
    }

    /// 已领取请求数。
    #[must_use]
    pub fn claimed_count(&self) -> usize {
        self.claimed.len()
    }

    /// permissionless claim（M7-ACC-5）：用户自提 Merkle proof 领取。
    ///
    /// 校验链与错误见类型文档；**重复领取与未 finalized 的根全部拒绝**。
    ///
    /// # Errors
    /// 未 finalized / 摘要重绑定失败 → [`AppchainError::RootNotFinalized`]；
    /// 证明无效（越界/篡改）→ [`AppchainError::WithdrawalProofInvalid`]；
    /// 重领 → [`AppchainError::AlreadyClaimed`]；sidecar 写失败 →
    /// [`AppchainError::WalCorrupted`]（内存状态不动）。
    pub fn claim(
        &mut self,
        root_digest: [u8; 32],
        leaf: &WithdrawalLeaf,
        proof: &[[u8; 32]],
        index: u64,
    ) -> AppchainResult<()> {
        // 1. 根存在且 finalized + 摘要重绑定（叶声称的 checkpoint_height
        //    必须与注册记录一致）
        let record =
            self.roots
                .get(&root_digest)
                .ok_or_else(|| AppchainError::RootNotFinalized {
                    digest_hex: hex::encode(root_digest),
                })?;
        if WithdrawalRoot::digest_of(leaf.checkpoint_height, record.leaf_count, record.root)
            != root_digest
        {
            return Err(AppchainError::RootNotFinalized {
                digest_hex: hex::encode(root_digest),
            });
        }
        // 2. 包含证明（索引界内 + 路径校验；篡改叶任一字段都在此被拒）
        if index >= record.leaf_count {
            return Err(AppchainError::WithdrawalProofInvalid(
                "claim index beyond root leaf_count",
            ));
        }
        if !verify_inclusion(leaf, proof, index, record.root) {
            return Err(AppchainError::WithdrawalProofInvalid(
                "merkle inclusion proof mismatch",
            ));
        }
        // 3. Vault 自检"未领取"（§5.4；防重放主键 = request_id）
        if self.claimed.contains_key(&leaf.request_id) {
            return Err(AppchainError::AlreadyClaimed {
                request_id_hex: hex::encode(leaf.request_id),
            });
        }
        // 4. 先落账（写失败 → Err、内存不动），再更新内存
        let line = encode_line(&ClaimLogEvent::Claimed {
            request_id: leaf.request_id,
            digest: root_digest,
        });
        if let Some(log) = &mut self.log {
            log.append(&line)?;
        }
        self.claimed.insert(leaf.request_id, root_digest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 固定字段叶子（测试构造）。
    fn leaf(seed: u8, amount: u64, height: u64) -> WithdrawalLeaf {
        WithdrawalLeaf {
            request_id: [seed; 32],
            external_recipient: [seed.wrapping_add(0x40); 32],
            asset_class: 1,
            amount,
            burned_note_commitment: [seed.wrapping_add(0x80); 32],
            checkpoint_height: height,
        }
    }

    fn hex_of(bytes: [u8; 32]) -> String {
        hex::encode(bytes)
    }

    // ===== 树规则：golden 常量钉住域标签/前缀/编码 =====

    #[test]
    fn leaf_hash_and_root_golden_vectors() {
        // 冻结 golden 常量：防域标签/前缀/borsh 字段序被无声更改。
        let a = leaf(1, 500, 9);
        let b = leaf(2, 2_350, 9);
        assert_eq!(
            hex_of(leaf_hash(&a)),
            "19d3fb2364cde7d1825c07fa8b930a79946c46caa385a32cd65a65dbdb9d6866"
        );
        let mut builder = WithdrawalRootBuilder::new();
        builder.push(a).unwrap();
        builder.push(b).unwrap();
        let root = builder.build(9).unwrap();
        assert_eq!(root.leaf_count, 2);
        assert_eq!(
            hex_of(root.root),
            "b6c6f098f5beaaffba3c1e7170293a84c735dd86c4390d0c02335aeaeaf04619"
        );
        assert_eq!(
            hex_of(root.digest),
            "8e3cf44238db28bc9e8222148144c5ceef597c0e8b7ac2278f65318c72de9fc5"
        );
        assert_eq!(
            root.digest,
            WithdrawalRoot::digest_of(9, 2, root.root),
            "digest == digest_of(height, count, root)"
        );
    }

    #[test]
    fn digest_binds_height_count_and_root() {
        let root = [7u8; 32];
        let base = WithdrawalRoot::digest_of(9, 2, root);
        assert_ne!(base, WithdrawalRoot::digest_of(10, 2, root), "height");
        assert_ne!(base, WithdrawalRoot::digest_of(9, 3, root), "leaf_count");
        assert_ne!(base, WithdrawalRoot::digest_of(9, 2, [8u8; 32]), "root");
        // 域分离：digest 输入 ≠ 任一叶/内部节点哈希输入（前缀 0x02 独占）
        assert_ne!(base, empty_leaf_hash());
    }

    // ===== 聚合：确定性 / 规范序 / 空窗 / 去重 =====

    #[test]
    fn aggregation_deterministic_and_order_independent() {
        let leaves = [leaf(1, 100, 9), leaf(2, 200, 9), leaf(3, 300, 9)];
        let build = |order: &[usize]| {
            let mut b = WithdrawalRootBuilder::new();
            for &i in order {
                b.push(leaves[i]).unwrap();
            }
            b.build(9).unwrap()
        };
        let r1 = build(&[0, 1, 2]);
        let r2 = build(&[2, 0, 1]);
        let r3 = build(&[1, 2, 0]);
        assert_eq!(r1, r2, "同输入（不同提交序）同根");
        assert_eq!(r1, r3);
        // 任何叶子字段差异都改变根
        let mut b = WithdrawalRootBuilder::new();
        b.push(leaves[0]).unwrap();
        b.push(leaves[1]).unwrap();
        let mut tampered = leaves[2];
        tampered.amount += 1;
        b.push(tampered).unwrap();
        assert_ne!(b.build(9).unwrap(), r1);
        // 不同 checkpoint 高度 = 不同窗口 → 不同根
        let mut b2 = WithdrawalRootBuilder::new();
        for l in leaves {
            b2.push(WithdrawalLeaf {
                checkpoint_height: 10,
                ..l
            })
            .unwrap();
        }
        assert_ne!(b2.build(10).unwrap().root, r1.root);
    }

    #[test]
    fn empty_window_yields_no_root_and_duplicates_rejected() {
        let mut b = WithdrawalRootBuilder::new();
        // 空窗不产根：build → OutOfRange；build_all → 空表
        assert!(matches!(
            b.build(9),
            Err(AppchainError::OutOfRange("withdrawal window is empty"))
        ));
        assert!(b.build_all().is_empty());
        assert!(b.window_heights().is_empty());

        b.push(leaf(1, 100, 9)).unwrap();
        b.push(leaf(2, 100, 12)).unwrap();
        assert_eq!(b.window_heights(), vec![9, 12]);
        assert_eq!(b.build_all().len(), 2, "每非空窗恰一根");
        // 同 request_id 跨窗去重（fail-closed）
        let err = b.push(leaf(1, 100, 13)).unwrap_err();
        assert!(matches!(err, AppchainError::WithdrawalConflict(_)));
        assert_eq!(b.window_heights(), vec![9, 12], "拒绝的叶不入窗");
    }

    #[test]
    fn single_leaf_root_is_leaf_hash_and_proof_is_empty() {
        let mut b = WithdrawalRootBuilder::new();
        let a = leaf(5, 42, 3);
        b.push(a).unwrap();
        let r = b.build(3).unwrap();
        assert_eq!(r.root, leaf_hash(&a), "单叶 → H(0x00 ‖ leaf)");
        assert_eq!(r.leaf_count, 1);
        let proof = b.merkle_proof(3, 0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_inclusion(&a, &proof, 0, r.root));
        // 越界索引：无证明路径可被伪造
        assert!(!verify_inclusion(&a, &proof, 1, r.root));
        assert!(b.merkle_proof(3, 1).is_err());
    }

    #[test]
    fn unbalanced_tree_pads_with_empty_leaf_hash() {
        let leaves: Vec<WithdrawalLeaf> = (1..=3u8).map(|s| leaf(s, u64::from(s), 7)).collect();
        let mut b = WithdrawalRootBuilder::new();
        for l in &leaves {
            b.push(*l).unwrap();
        }
        let three = b.build(7).unwrap();
        // 手工展开：3 叶按 borsh 编码序（与建树同一规范化）补 1 个空叶 → 2 层折叠
        let mut sorted_enc: Vec<Vec<u8>> =
            leaves.iter().map(|l| borsh::to_vec(l).unwrap()).collect();
        sorted_enc.sort();
        let mut sorted: Vec<[u8; 32]> = sorted_enc
            .iter()
            .map(|bytes| sha256(&[WITHDRAWAL_ROOT_DOMAIN, &[LEAF_PREFIX], bytes]))
            .collect();
        let e = empty_leaf_hash();
        sorted.push(e);
        let l0 = internal_hash(&sorted[0], &sorted[1]);
        let l1 = internal_hash(&sorted[2], &sorted[3]);
        assert_eq!(three.root, internal_hash(&l0, &l1));
        // 全部 3 个索引都可证
        for (i, l) in leaves.iter().enumerate() {
            let proof = b.merkle_proof(7, i).unwrap();
            assert!(verify_inclusion(l, &proof, i as u64, three.root));
        }
    }

    // ===== 包含证明：正例 / 非成员 / 形状边界 =====

    #[test]
    fn inclusion_proofs_verify_across_widths() {
        for width in 1..=9u64 {
            let height = 100 + width;
            let leaves: Vec<WithdrawalLeaf> = (1..=width as u8)
                .map(|s| leaf(s, u64::from(s) * 10, height))
                .collect();
            let mut b = WithdrawalRootBuilder::new();
            for l in &leaves {
                b.push(*l).unwrap();
            }
            let root = b.build(height).unwrap();
            for (i, l) in leaves.iter().enumerate() {
                let proof = b.merkle_proof(height, i).unwrap();
                assert!(
                    verify_inclusion(l, &proof, i as u64, root.root),
                    "width={width} index={i} 正例必须通过"
                );
                // 索引挪用：同证明换索引 → 拒（fail-closed）
                if i + 1 < leaves.len() {
                    assert!(!verify_inclusion(l, &proof, i as u64 + 1, root.root));
                }
                // 证明截断/加长 → 拒
                if !proof.is_empty() {
                    assert!(!verify_inclusion(
                        l,
                        &proof[..proof.len() - 1],
                        i as u64,
                        root.root
                    ));
                }
                let mut extended = proof.to_vec();
                extended.push(empty_leaf_hash());
                assert!(!verify_inclusion(l, &extended, i as u64, root.root));
            }
        }
    }

    #[test]
    fn non_member_leaf_rejected() {
        let mut b = WithdrawalRootBuilder::new();
        let leaves = [leaf(1, 100, 9), leaf(2, 200, 9), leaf(3, 300, 9)];
        for l in leaves {
            b.push(l).unwrap();
        }
        let root = b.build(9).unwrap();
        let alien = leaf(9, 100, 9);
        let proof0 = b.merkle_proof(9, 0).unwrap();
        assert!(!verify_inclusion(&alien, &proof0, 0, root.root));
        // 换窗口高度的叶同样非成员
        let mut other_window = leaves[0];
        other_window.checkpoint_height = 10;
        assert!(!verify_inclusion(&other_window, &proof0, 0, root.root));
    }

    #[test]
    fn verify_rejects_impossible_proof_shapes() {
        let a = leaf(1, 100, 9);
        let h = leaf_hash(&a);
        // 证明长度越限（≥ 64）
        let huge = vec![[0u8; 32]; 64];
        assert!(!verify_inclusion(&a, &huge, 0, h));
        // index 超出证明位数覆盖的树宽
        let one = vec![[0u8; 32]];
        assert!(!verify_inclusion(&a, &one, 2, h));
    }

    // ===== ClaimLedger：finality 门 / 防重放 / 摘要重绑定 =====

    fn two_leaf_window() -> (WithdrawalRoot, WithdrawalRootBuilder, [WithdrawalLeaf; 2]) {
        let leaves = [leaf(1, 100, 9), leaf(2, 200, 9)];
        let mut b = WithdrawalRootBuilder::new();
        for l in leaves {
            b.push(l).unwrap();
        }
        (b.build(9).unwrap(), b, leaves)
    }

    #[test]
    fn claim_requires_finalized_root_and_rejects_replay() {
        let (root, builder, leaves) = two_leaf_window();
        let mut ledger = ClaimLedger::new();
        let proof0 = builder.merkle_proof(9, 0).unwrap();

        // 负例 A：未知 digest → RootNotFinalized（fail-closed）
        let unknown = WithdrawalRoot::digest_of(9, 2, [0xFF; 32]);
        let err = ledger.claim(unknown, &leaves[0], &proof0, 0).unwrap_err();
        assert!(matches!(err, AppchainError::RootNotFinalized { .. }));

        // 负例 B：根已知但未 mark_finalized → RootNotFinalized
        let err = ledger
            .claim(root.digest, &leaves[0], &proof0, 0)
            .unwrap_err();
        assert!(matches!(err, AppchainError::RootNotFinalized { .. }));
        assert_eq!(ledger.claimed_count(), 0);

        // mark_finalized 后正例
        ledger.mark_finalized(&root).unwrap();
        assert!(ledger.is_finalized(&root.digest));
        ledger.claim(root.digest, &leaves[0], &proof0, 0).unwrap();
        assert!(ledger.is_claimed(&leaves[0].request_id));
        assert_eq!(ledger.claimed_count(), 1);

        // 重复领取（同叶同证明）→ AlreadyClaimed
        let err = ledger
            .claim(root.digest, &leaves[0], &proof0, 0)
            .unwrap_err();
        assert!(matches!(err, AppchainError::AlreadyClaimed { .. }));

        // 第二叶独立可领
        let proof1 = builder.merkle_proof(9, 1).unwrap();
        ledger.claim(root.digest, &leaves[1], &proof1, 1).unwrap();
        assert_eq!(ledger.claimed_count(), 2);

        // mark_finalized 幂等：重复注册 Ok、计数不变
        ledger.mark_finalized(&root).unwrap();
        assert_eq!(ledger.finalized_count(), 1);
    }

    #[test]
    fn claim_rebinds_digest_against_leaf_checkpoint_height() {
        let (root, builder, leaves) = two_leaf_window();
        let mut ledger = ClaimLedger::new();
        ledger.mark_finalized(&root).unwrap();
        let proof0 = builder.merkle_proof(9, 0).unwrap();
        // 叶被改窗（checkpoint_height 篡改）：摘要重绑定失败 → 未 finalized
        let mut wrong_window = leaves[0];
        wrong_window.checkpoint_height = 10;
        let err = ledger
            .claim(root.digest, &wrong_window, &proof0, 0)
            .unwrap_err();
        assert!(matches!(err, AppchainError::RootNotFinalized { .. }));
    }

    #[test]
    fn claim_rejects_tampered_leaf_and_bad_index() {
        let (root, builder, leaves) = two_leaf_window();
        let mut ledger = ClaimLedger::new();
        ledger.mark_finalized(&root).unwrap();
        let proof0 = builder.merkle_proof(9, 0).unwrap();

        // 索引越出真实叶子数（补齐位不可领取）
        let mut b3 = WithdrawalRootBuilder::new();
        for l in leaves {
            b3.push(l).unwrap();
        }
        b3.push(leaf(3, 300, 9)).unwrap();
        let root3 = b3.build(9).unwrap();
        ledger.mark_finalized(&root3).unwrap();
        let err = ledger
            .claim(root3.digest, &leaves[0], &b3.merkle_proof(9, 0).unwrap(), 3)
            .unwrap_err();
        assert!(
            matches!(err, AppchainError::WithdrawalProofInvalid(_)),
            "index >= leaf_count 必须 fail-closed"
        );

        // 篡改非索引字段（amount）→ 证明失败
        let mut tampered = leaves[0];
        tampered.amount = 999;
        let err = ledger
            .claim(root.digest, &tampered, &proof0, 0)
            .unwrap_err();
        assert!(matches!(err, AppchainError::WithdrawalProofInvalid(_)));
    }

    // ===== JSONL sidecar：重载等价 / 撕裂尾行 / 中间行损坏 =====

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("poker-appchain-claim-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sidecar_reload_equivalence_and_cross_instance_replay_rejected() {
        let dir = temp_dir("reload");
        let path = dir.join("claims.jsonl");
        let _ = std::fs::remove_file(&path);
        let (root, builder, leaves) = two_leaf_window();

        // 实例 A：注册根 + 领取第一叶
        {
            let mut a = ClaimLedger::open(&path).unwrap();
            a.mark_finalized(&root).unwrap();
            let proof0 = builder.merkle_proof(9, 0).unwrap();
            a.claim(root.digest, &leaves[0], &proof0, 0).unwrap();
        }
        // 实例 B（重载）：状态等价 + 跨实例重领仍拒
        let state_of = |ledger: &ClaimLedger| {
            (
                ledger.finalized_count(),
                ledger.finalized_root(&root.digest),
                ledger.claimed_count(),
                ledger.is_claimed(&leaves[0].request_id),
                ledger.is_claimed(&leaves[1].request_id),
            )
        };
        let mut b = ClaimLedger::open(&path).unwrap();
        let state_b = state_of(&b);
        assert_eq!(
            state_b,
            (
                1,
                Some(FinalizedRoot {
                    checkpoint_height: 9,
                    leaf_count: 2,
                    root: root.root,
                }),
                1,
                true,
                false
            ),
            "重载等价：finalized/claimed 状态与实例 A 一致"
        );
        let proof0 = builder.merkle_proof(9, 0).unwrap();
        let err = b.claim(root.digest, &leaves[0], &proof0, 0).unwrap_err();
        assert!(
            matches!(err, AppchainError::AlreadyClaimed { .. }),
            "跨实例重载后重复领取仍拒"
        );
        // 第二叶照常可领（未领过的请求不受影响）
        let proof1 = builder.merkle_proof(9, 1).unwrap();
        b.claim(root.digest, &leaves[1], &proof1, 1).unwrap();
        drop(b);

        // 实例 C：两笔领取全部恢复
        let c = ClaimLedger::open(&path).unwrap();
        assert_eq!(state_of(&c).0, 1);
        assert_eq!(c.claimed_count(), 2);
        assert!(c.is_claimed(&leaves[1].request_id));
    }

    #[test]
    fn sidecar_torn_tail_ignored_midfile_corruption_fail_closed() {
        let dir = temp_dir("torn");
        let (root, builder, leaves) = two_leaf_window();
        let good_finalized = format!(
            "{{\"kind\":\"finalized\",\"digest_hex\":\"{}\",\"checkpoint_height\":9,\"leaf_count\":2,\"root_hex\":\"{}\"}}\n",
            hex::encode(root.digest),
            hex::encode(root.root)
        );
        let proof0 = builder.merkle_proof(9, 0).unwrap();
        let good_claimed = format!(
            "{{\"kind\":\"claimed\",\"request_id_hex\":\"{}\",\"digest_hex\":\"{}\"}}\n",
            hex::encode(leaves[0].request_id),
            hex::encode(root.digest)
        );

        // 撕裂尾行：截掉换行再补半行 → 读取成功（忽略残行），只剩完整行
        let path = dir.join("torn.jsonl");
        std::fs::write(
            &path,
            format!("{good_finalized}{{\"kind\":\"claimed\",\"request"),
        )
        .unwrap();
        let mut torn = ClaimLedger::open(&path).unwrap();
        assert!(torn.is_finalized(&root.digest));
        assert!(!torn.is_claimed(&leaves[0].request_id), "残行被忽略");
        // 忽略残行后照常推进
        torn.claim(root.digest, &leaves[0], &proof0, 0).unwrap();
        drop(torn);
        let reopened = ClaimLedger::open(&path).unwrap();
        assert!(reopened.is_claimed(&leaves[0].request_id));

        // 中间行损坏（完整行 + 坏行 + 换行结尾）→ Err（fail-closed）
        let path = dir.join("midcorrupt.jsonl");
        std::fs::write(&path, format!("{good_finalized}not-json\n{good_claimed}")).unwrap();
        assert!(ClaimLedger::open(&path).is_err());

        // 坏 hex（digest 短）→ Err
        let path = dir.join("badhex.jsonl");
        std::fs::write(
            &path,
            format!(
                "{{\"kind\":\"claimed\",\"request_id_hex\":\"aabb\",\"digest_hex\":\"{}\"}}\n",
                hex::encode(root.digest)
            ),
        )
        .unwrap();
        assert!(ClaimLedger::open(&path).is_err());

        // 乱序：claimed 先于其 finalized 记录 → Err
        let path = dir.join("orphan-claim.jsonl");
        std::fs::write(&path, good_claimed.clone()).unwrap();
        assert!(ClaimLedger::open(&path).is_err());

        // 同 request_id 两笔不同根摘要的领取记录 → Err
        let path = dir.join("double-claim.jsonl");
        let other_root_digest = WithdrawalRoot::digest_of(9, 2, [0x33; 32]);
        let finalized_both = format!(
            "{good_finalized}{{\"kind\":\"finalized\",\"digest_hex\":\"{}\",\"checkpoint_height\":9,\"leaf_count\":2,\"root_hex\":\"{}\"}}\n",
            hex::encode(other_root_digest),
            hex::encode([0x33; 32])
        );
        std::fs::write(
            &path,
            format!(
                "{finalized_both}{good_claimed}{{\"kind\":\"claimed\",\"request_id_hex\":\"{}\",\"digest_hex\":\"{}\"}}\n",
                hex::encode(leaves[0].request_id),
                hex::encode(other_root_digest)
            ),
        )
        .unwrap();
        assert!(ClaimLedger::open(&path).is_err());
    }

    #[test]
    fn sidecar_contract_line_shape_frozen() {
        let (root, _b, leaves) = two_leaf_window();
        let finalized = encode_line(&ClaimLogEvent::Finalized {
            digest: root.digest,
            checkpoint_height: root.checkpoint_height,
            leaf_count: root.leaf_count,
            root: root.root,
        });
        assert!(finalized.ends_with('\n'));
        assert_eq!(
            finalized.trim_end(),
            format!(
                "{{\"kind\":\"finalized\",\"digest_hex\":\"{}\",\"checkpoint_height\":{},\"leaf_count\":{},\"root_hex\":\"{}\"}}",
                hex::encode(root.digest),
                root.checkpoint_height,
                root.leaf_count,
                hex::encode(root.root)
            ),
            "字段名/顺序/编码冻结"
        );
        let claimed = encode_line(&ClaimLogEvent::Claimed {
            request_id: leaves[0].request_id,
            digest: root.digest,
        });
        assert_eq!(
            claimed.trim_end(),
            format!(
                "{{\"kind\":\"claimed\",\"request_id_hex\":\"{}\",\"digest_hex\":\"{}\"}}",
                hex::encode(leaves[0].request_id),
                hex::encode(root.digest)
            ),
        );
        // 往返：编码行可解析回同一事件
        assert_eq!(
            parse_line(finalized.trim_end()).unwrap(),
            ClaimLogEvent::Finalized {
                digest: root.digest,
                checkpoint_height: root.checkpoint_height,
                leaf_count: root.leaf_count,
                root: root.root,
            }
        );
        assert_eq!(
            parse_line(claimed.trim_end()).unwrap(),
            ClaimLogEvent::Claimed {
                request_id: leaves[0].request_id,
                digest: root.digest,
            }
        );
    }
}
