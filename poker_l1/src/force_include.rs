//! M3-ACC-6 ForceInclude 抗审查机制（plan §5.3 的 v1 最小正确实现）。
//!
//! # 语义（§5.3 对应关系）
//!
//! 1. **SeenReceipt（§5.3-1）**：validator 收到合法 `submit_tx` 后立即签发
//!    `{chain_id, tx_hash, seen_at_ms, validator_pubkey, signature}`，证明
//!    "本 validator 在 `seen_at_ms` 已见证该交易"。签名沿用节点现有
//!    secp256k1 recoverable（65B r||s||v，与 DAG vertex / commit cert 同一密钥与
//!    编码），签名对象 = `blake2b_256(0x53 || chain_id || tx_hash || seen_at_ms)`
//!    （域分隔，SEC-L4 同款 chain_id 首域思想）。**不新造密码学原语**。
//! 2. **ForceIncludeTx（§5.3-2/3）**：出块 drain 时扫描 mempool，凡
//!    `now > arrived_at_ms + inclusion_deadline_ms` 的交易进入强制包含队列，
//!    **先于普通交易**进块；队列内按 `tx_hash` 字节序升序（§5.3-3 确定性排序）。
//!    同一 tx_hash 只会被强制提升一次（included 去重集合，防重复包含）。
//! 3. **CensorshipProof（§5.3-4）**：用户拿到 SeenReceipt 后可构造
//!    `{receipt, tx_bytes, deadline_ms, current_height_hint}` 提交
//!    `check_censorship`。verify 重验：receipt 签名与 chain_id 域、tx_bytes 的
//!    tx_hash 与 receipt 一致、是否已过 deadline、tx_hash 是否出现在近 K 个块。
//!    三态结果：`Included`（已包含，指控不成立）/ `NotYetDue`（未超 deadline）/
//!    `Censored`（超时且近 K 块未包含 → 审查证据成立）。
//!
//! # v1.5 更新（本次交付）
//!
//! - **receipt 持久化（v1.5-a1）**：validator 签发的 SeenReceipt 以 JSONL sidecar
//!   追加落盘（`<data_dir>/seen_receipts.jsonl`，一行一条 JSON，格式 =
//!   `SeenReceipt` 的 serde JSON，**域/格式冻结**——后续版本只许追加新行类型，
//!   不许改既有字段语义）。节点启动时重放 sidecar 恢复内存 map，
//!   `get_seen_receipt` RPC 重启后仍可答。见 [`ReceiptSidecar`]。
//!
//! # v1 边界（如实标注，属 v1.5–v2 的工作）
//!
//! - **P2P receipt 同步**：receipt 已持久化，但跨 validator 的 receipt 传播
//!   （A 节点替 B 节点的 receipt 作证）仍属后续工作。
//! - **罚没仅记录**：`check_censorship` 命中 `Censored` 时只记 tracing 事件并累加
//!   `censorship_detected_total` 指标；bond 真实罚没（slashing）属 v2。
//! - **checkpoint 间隔用块数近似**：§5.3 的"近 K 个块"语义中 K 默认取
//!   `2 * consensus::CHECKPOINT_INTERVAL`，纯块数窗口近似（无 sparse Merkle
//!   非包含证明）；真实非包含证明属 v2。
//! - **arrived_at 为节点本地时钟**：交易本身无时间戳，到达时间由接收 validator
//!   用本地（可注入）时钟记录；跨 validator 的 `included` 去重集合不经共识同步，
//!   多 validator 场景下强制包含集合可能不一致（活性风险、非安全性），完整协议
//!   需把 receipt / 强制包含集合写入 vertex 载荷使其成为共识数据（v2）。
//! - **去重语义**：`included` 集合在 drain 提升时即标记（把"已进入 vertex batch"
//!   视为"已进块"的最早保守点）；vertex 失败回排（requeue）后该交易不再二次强制
//!   提升，而是按普通排序随下一轮 drain 进块。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use serde::{Deserialize, Serialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::signature::unified::verify_signature;
use crate::transaction::Transaction;
use crate::{ChainId, Hash};

/// SeenReceipt 签名域分隔前缀（'S' for SeenReceipt；与 tx 的 0x54 'T' 区分）。
pub const RECEIPT_SIG_DOMAIN: u8 = 0x53;

/// 默认强制包含期限（毫秒）：10000ms。`0 = 禁用强制包含路径`。
pub const DEFAULT_INCLUSION_DEADLINE_MS: u64 = 10_000;

/// SeenReceipt JSONL sidecar 文件名（相对 `data_dir`；**域名冻结**）。
pub const RECEIPT_SIDECAR_FILE: &str = "seen_receipts.jsonl";

/// 审查检测窗口默认值：`2 * CHECKPOINT_INTERVAL` 个块。
///
/// §5.3 "近 2 个 checkpoint 间隔"的 v1 块数近似（见模块头边界说明）。
pub const DEFAULT_CENSORSHIP_WINDOW_BLOCKS: u64 = 2 * crate::consensus::checkpoint::CHECKPOINT_INTERVAL;

/// serde 默认值辅助（serde `default = "path"` 要求函数路径）。
pub const fn default_inclusion_deadline_ms() -> u64 {
    DEFAULT_INCLUSION_DEADLINE_MS
}

/// serde 默认值辅助（serde `default = "path"` 要求函数路径）。
pub const fn default_censorship_window_blocks() -> u64 {
    DEFAULT_CENSORSHIP_WINDOW_BLOCKS
}

/// SeenReceipt（§5.3-1）：validator 对"已见证交易"的签名回执。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenReceipt {
    /// 网络 chain_id（签名域首字段，防跨链重放）。
    pub chain_id: ChainId,
    /// 已见证的交易哈希。
    pub tx_hash: Hash,
    /// validator 本地时钟下的见证时间（毫秒）。
    pub seen_at_ms: u64,
    /// 签发 validator 的 tagged pubkey（secp256k1，与 vertex author 同源）。
    pub validator_pubkey: TaggedPubkey,
    /// secp256k1 recoverable 签名（65B r||s||v），签名对象为
    /// [`seen_receipt_signing_hash`]。
    pub signature: Vec<u8>,
}

/// 计算 SeenReceipt 的签名对象哈希。
///
/// `blake2b_256(0x53 || chain_id || tx_hash || seen_at_ms)`（全部小端）。
pub fn seen_receipt_signing_hash(
    chain_id: ChainId,
    tx_hash: &Hash,
    seen_at_ms: u64,
) -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[RECEIPT_SIG_DOMAIN]);
    h.update(&chain_id.to_le_bytes());
    h.update(tx_hash);
    h.update(&seen_at_ms.to_le_bytes());
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

impl SeenReceipt {
    /// 由 validator 私钥签发回执（secp256k1 recoverable，65B，与 vertex 签名同款）。
    pub fn issue(
        chain_id: ChainId,
        tx_hash: Hash,
        seen_at_ms: u64,
        secret_key: &secp256k1::SecretKey,
    ) -> PokerL1Result<Self> {
        let signing_hash = seen_receipt_signing_hash(chain_id, &tx_hash, seen_at_ms);
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest(signing_hash);
        let sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut signature = compact.to_vec();
        signature.push(recovery_id.to_i32() as u8);
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, secret_key);
        let validator_pubkey = TaggedPubkey::new(
            crate::signature::SignatureScheme::Secp256k1,
            crate::signature::CURRENT_VERSION,
            public_key.serialize().to_vec(),
        )?;
        Ok(Self {
            chain_id,
            tx_hash,
            seen_at_ms,
            validator_pubkey,
            signature,
        })
    }

    /// 验证回执签名与编码（不校验 chain_id 归属 —— 由 [`CensorshipProof::verify`]
    /// 对照本地 chain_id 校验）。
    pub fn verify(&self) -> PokerL1Result<()> {
        let signing_hash = seen_receipt_signing_hash(self.chain_id, &self.tx_hash, self.seen_at_ms);
        verify_signature(&self.validator_pubkey, &self.signature, &signing_hash)
    }
}

/// SeenReceipt JSONL sidecar（v1.5-a1 receipt 持久化）。
///
/// # 格式（冻结）
///
/// - 路径：`<data_dir>/seen_receipts.jsonl`；
/// - 每行一条 UTF-8 JSON = [`SeenReceipt`] 的 serde 序列化（字段名与结构体一致）；
/// - 只追加（append-only），永不改写历史行；损坏行（截断/非法 JSON）在重放时
///   跳过并计数，不中止恢复 —— 崩溃时最后一行可能不完整。
///
/// # 语义
///
/// validator 每签发一条 SeenReceipt 即同步 append 一行（`append` 内 flush），
/// 重启时 [`ReceiptSidecar::replay`] 按 FIFO 重放进内存 map（同 tx_hash 后写
/// 覆盖前写，与内存 FIFO 上限语义一致：由调用方按 max_size 驱逐）。
pub struct ReceiptSidecar {
    file: Option<std::fs::File>,
    path: std::path::PathBuf,
    /// 重放时跳过的损坏行数（诊断用）。
    corrupt_lines: usize,
}

impl ReceiptSidecar {
    /// 打开（或创建）sidecar 并重放历史行。
    ///
    /// 返回 `(sidecar, 重放出的 receipt 列表)`。`data_dir` 不存在时由调用方保证
    /// 已创建（Node::open 先建存储目录）。
    pub fn open(data_dir: &std::path::Path) -> std::io::Result<(Self, Vec<SeenReceipt>)> {
        let path = data_dir.join(RECEIPT_SIDECAR_FILE);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let (replayed, corrupt_lines) = Self::replay(&path)?;
        Ok((
            Self {
                file: Some(file),
                path,
                corrupt_lines,
            },
            replayed,
        ))
    }

    /// 重放 sidecar 文件，返回 `(receipt 列表, 损坏行数)`。
    ///
    /// 只读：不持有文件句柄，崩溃残留的半行被跳过。
    pub fn replay(path: &std::path::Path) -> std::io::Result<(Vec<SeenReceipt>, usize)> {
        let mut out = Vec::new();
        let mut corrupt = 0usize;
        let Ok(content) = std::fs::read_to_string(path) else {
            return Ok((out, 0));
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<SeenReceipt>(line) {
                Ok(receipt) => out.push(receipt),
                Err(_) => corrupt += 1,
            }
        }
        Ok((out, corrupt))
    }

    /// 追加一条 receipt 并立即落盘（行缓冲 flush，崩溃最多丢最后一条）。
    pub fn append(&mut self, receipt: &SeenReceipt) -> std::io::Result<()> {
        use std::io::Write as _;
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        let mut line = serde_json::to_string(receipt)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        file.write_all(line.as_bytes())?;
        file.flush()
    }

    /// sidecar 路径（诊断/测试用）。
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// 重放时跳过的损坏行数（诊断用；open 后不变）。
    #[must_use]
    pub const fn corrupt_lines(&self) -> usize {
        self.corrupt_lines
    }
}

/// 强制包含条目（§5.3-2）：过期的 mempool 交易与其到达时间。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceIncludeTx {
    /// 完整交易。
    pub tx: Transaction,
    /// `tx.tx_hash()`（提升时缓存，避免重复哈希）。
    pub tx_hash: Hash,
    /// 到达时间（进入 mempool 时的节点本地时钟，毫秒）。
    pub arrived_at_ms: u64,
}

/// 判断一笔 mempool 交易是否已过强制包含期限（§5.3-2）。
///
/// `deadline_ms == 0` 表示禁用强制包含路径（恒 false）。
#[must_use]
pub fn is_past_inclusion_deadline(arrived_at_ms: u64, now_ms: u64, deadline_ms: u64) -> bool {
    deadline_ms > 0 && now_ms > arrived_at_ms.saturating_add(deadline_ms)
}

/// 强制包含排序（§5.3-3）：`forced` 按 tx_hash 字节序升序排在 `normal` 之前。
///
/// 纯函数、全局确定性：同输入同输出。`normal` 的相对顺序由调用方保证
/// （Node 侧为既有 GameTurn → Public → ForceSync 通道序）。
#[must_use]
pub fn order_force_include_first(
    mut forced: Vec<ForceIncludeTx>,
    normal: Vec<Transaction>,
) -> Vec<Transaction> {
    // §5.3-3：队列内按 tx_hash 字节序升序（确定性，与到达顺序无关）。
    forced.sort_by(|a, b| a.tx_hash.cmp(&b.tx_hash));
    let mut out = Vec::with_capacity(forced.len() + normal.len());
    out.extend(forced.into_iter().map(|f| f.tx));
    out.extend(normal);
    out
}

/// `check_censorship` 三态结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensorshipCheckOutcome {
    /// 审查证据成立：已过 deadline 且近 K 个块未包含该交易。
    Censored,
    /// 交易已包含（近 K 个块内找到 tx_hash）→ 指控不成立。
    Included,
    /// 尚未超过 `seen_at_ms + deadline_ms` → 暂不可指控。
    NotYetDue,
}

/// 审查证明（§5.3-4）：用户凭 SeenReceipt 构造的 censorship 证据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensorshipProof {
    /// validator 签发的见证回执。
    pub receipt: SeenReceipt,
    /// 原始交易字节（`Transaction::to_bcs`）。
    pub tx_bytes: Vec<u8>,
    /// 声称的强制包含期限（毫秒，须与节点参数一致）。
    pub deadline_ms: u64,
    /// 提交证据时的链高提示（v1 仅记录，不参与判定）。
    pub current_height_hint: u64,
}

impl CensorshipProof {
    /// 验证审查证明（§5.3-4 的 v1 语义子集）。
    ///
    /// 校验顺序：
    /// 1. `tx_bytes` 可反序列化且其 `tx_hash` 与 `receipt.tx_hash` 一致；
    /// 2. `receipt.chain_id` 与本节点 `chain_id` 一致（签名域绑定）；
    /// 3. receipt 签名验证（secp256k1 recoverable + 域分隔哈希）；
    /// 4. `tx_hash` 出现在 `recent_window_tx_hashes`（近 K 个块的 tx 全集）→
    ///    [`CensorshipCheckOutcome::Included`]（包含优先于超时判定：已进块则
    ///    指控不成立，即使已过 deadline）；
    /// 5. `now_ms <= seen_at_ms + deadline_ms` → [`CensorshipCheckOutcome::NotYetDue`]；
    /// 6. 否则 [`CensorshipCheckOutcome::Censored`]（证据成立）。
    ///
    /// # 参数
    /// - `recent_window_tx_hashes`：调用方从近 K 个块提取的 tx_hash 全集
    ///   （v1 块数近似窗口，见模块头边界说明）。
    /// - `expected_deadline_ms`：本节点配置的强制包含期限。`deadline_ms` 是
    ///   证明自带字段，若不与节点配置核对，攻击者可自报 `deadline_ms = 0`
    ///   使任意回执立即"超期"（P0 修复）。`0` 表示本节点禁用强制包含路径，
    ///   一切证明直接拒绝。
    pub fn verify(
        &self,
        chain_id: ChainId,
        now_ms: u64,
        recent_window_tx_hashes: &[Hash],
        expected_deadline_ms: u64,
    ) -> PokerL1Result<CensorshipCheckOutcome> {
        // 0. deadline 与节点配置强一致（防自报期限攻击）
        if expected_deadline_ms == 0 {
            return Err(PokerL1Error::Other(
                "censorship proof rejected: force-include disabled on this node".into(),
            ));
        }
        if self.deadline_ms != expected_deadline_ms {
            return Err(PokerL1Error::Other(format!(
                "censorship proof deadline_ms {} != node inclusion_deadline_ms {expected_deadline_ms}",
                self.deadline_ms
            )));
        }
        // 1. tx_bytes ↔ receipt.tx_hash 一致性
        let tx = Transaction::from_bcs(&self.tx_bytes).map_err(|e| {
            PokerL1Error::Other(format!("censorship proof tx_bytes 解析失败: {e}"))
        })?;
        if tx.tx_hash() != self.receipt.tx_hash {
            return Err(PokerL1Error::Other(
                "censorship proof tx_hash 与 receipt.tx_hash 不一致".into(),
            ));
        }
        // 2. chain_id 域一致性
        if self.receipt.chain_id != chain_id {
            return Err(PokerL1Error::Other(format!(
                "censorship proof chain_id 0x{:08X} 与本节点 0x{:08X} 不一致",
                self.receipt.chain_id, chain_id
            )));
        }
        // 3. receipt 签名验证（重验 secp256k1 签名 + 域分隔哈希）
        self.receipt.verify()?;
        // 4. 近 K 个块包含 → Included（包含优先，见 doc 注释）
        if recent_window_tx_hashes.contains(&self.receipt.tx_hash) {
            return Ok(CensorshipCheckOutcome::Included);
        }
        // 5. 未超 deadline → NotYetDue
        if now_ms <= self
            .receipt
            .seen_at_ms
            .saturating_add(self.deadline_ms)
        {
            return Ok(CensorshipCheckOutcome::NotYetDue);
        }
        // 6. 证据成立
        Ok(CensorshipCheckOutcome::Censored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::CURRENT_VERSION;
    use crate::signature::tagged_pubkey::SignatureScheme;
    use crate::transaction::{Gas, RouteHint, TxLane};

    fn signed_tx(seed: u8) -> Transaction {
        let secp = secp256k1::Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[0] = seed;
        let secret = secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let tagged =
            TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, public.serialize().to_vec())
                .unwrap();
        let mut tx = Transaction {
            inputs: vec![ObjectID::new([seed; 20], 1)],
            outputs: vec![Object::new(
                ObjectID::new([seed; 20], 2),
                Ownership::Shared,
                "TestType",
                b"fi".to_vec(),
                None,
            )],
            contract_call: None,
            tagged_pubkey: tagged,
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let msg = secp256k1::Message::from_digest(tx.signing_hash());
        let sig = secp.sign_ecdsa_recoverable(&msg, &secret);
        let (rid, compact) = sig.serialize_compact();
        let mut sig_bytes = compact.to_vec();
        sig_bytes.push(rid.to_i32() as u8);
        tx.signature = sig_bytes;
        tx
    }

    #[test]
    fn seen_receipt_issue_and_verify_roundtrip() {
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let tx = signed_tx(1);
        let receipt = SeenReceipt::issue(DEFAULT_CHAIN_ID, tx.tx_hash(), 1234, &secret).unwrap();
        receipt.verify().expect("合法 receipt 必须通过验证");
        assert_eq!(receipt.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(receipt.tx_hash, tx.tx_hash());
        assert_eq!(receipt.seen_at_ms, 1234);
    }

    #[test]
    fn seen_receipt_rejects_tampered_seen_at() {
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let tx = signed_tx(2);
        let mut receipt = SeenReceipt::issue(DEFAULT_CHAIN_ID, tx.tx_hash(), 1234, &secret).unwrap();
        receipt.seen_at_ms = 999_999;
        assert!(receipt.verify().is_err(), "篡改 seen_at_ms 必须验证失败");
    }

    #[test]
    fn seen_receipt_rejects_wrong_signer() {
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let other = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let tx = signed_tx(3);
        let mut receipt = SeenReceipt::issue(DEFAULT_CHAIN_ID, tx.tx_hash(), 1234, &secret).unwrap();
        let forged = SeenReceipt::issue(DEFAULT_CHAIN_ID, tx.tx_hash(), 1234, &other).unwrap();
        receipt.validator_pubkey = forged.validator_pubkey;
        assert!(receipt.verify().is_err(), "公钥与签名不匹配必须失败");
    }

    #[test]
    fn is_past_inclusion_deadline_semantics() {
        assert!(!is_past_inclusion_deadline(1_000, 2_000, 10_000));
        assert!(!is_past_inclusion_deadline(0, 10_000, 10_000), "恰好到期不触发（严格大于）");
        assert!(is_past_inclusion_deadline(0, 10_001, 10_000));
        // deadline=0 禁用
        assert!(!is_past_inclusion_deadline(0, u64::MAX, 0));
    }

    #[test]
    fn order_force_include_first_sorts_by_tx_hash_bytes() {
        let txs: Vec<Transaction> = (1..=5).map(signed_tx).collect();
        let mut hashes: Vec<Hash> = txs.iter().map(|t| t.tx_hash()).collect();
        hashes.sort();
        // 乱序到达（逆序提交）
        let forced: Vec<ForceIncludeTx> = txs
            .iter()
            .rev()
            .map(|t| ForceIncludeTx { tx: t.clone(), tx_hash: t.tx_hash(), arrived_at_ms: 0 })
            .collect();
        let ordered = order_force_include_first(forced, vec![]);
        let got: Vec<Hash> = ordered.iter().map(|t| t.tx_hash()).collect();
        assert_eq!(got, hashes, "强制包含队列必须按 tx_hash 字节序升序");
    }

    #[test]
    fn censorship_proof_three_states() {
        let secret = secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let tx = signed_tx(4);
        let tx_bytes = tx.to_bcs().unwrap();
        let receipt = SeenReceipt::issue(DEFAULT_CHAIN_ID, tx.tx_hash(), 1_000, &secret).unwrap();
        let deadline = 10_000;
        let proof = CensorshipProof {
            receipt,
            tx_bytes,
            deadline_ms: deadline,
            current_height_hint: 7,
        };

        // 未超时
        let out = proof.verify(DEFAULT_CHAIN_ID, 5_000, &[], deadline).unwrap();
        assert_eq!(out, CensorshipCheckOutcome::NotYetDue);

        // 超时且未包含 → 证据成立
        let out = proof.verify(DEFAULT_CHAIN_ID, 11_001, &[], deadline).unwrap();
        assert_eq!(out, CensorshipCheckOutcome::Censored);

        // 已包含 → 不成立（即使已过 deadline）
        let out = proof
            .verify(DEFAULT_CHAIN_ID, 11_001, &[tx.tx_hash()], deadline)
            .unwrap();
        assert_eq!(out, CensorshipCheckOutcome::Included);

        // deadline 与节点配置不一致 → 拒绝（P0 修复：防自报期限）
        assert!(proof.verify(DEFAULT_CHAIN_ID, 11_001, &[], deadline + 1).is_err());
        // 节点禁用强制包含（deadline=0）→ 一切证明拒绝
        assert!(proof.verify(DEFAULT_CHAIN_ID, 11_001, &[], 0).is_err());
    }

    #[test]
    fn censorship_proof_rejects_hash_mismatch_and_wrong_chain() {
        let secret = secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let tx = signed_tx(5);
        let other_tx = signed_tx(6);
        let receipt = SeenReceipt::issue(DEFAULT_CHAIN_ID, tx.tx_hash(), 0, &secret).unwrap();

        // tx_bytes 与 receipt.tx_hash 不一致
        let proof = CensorshipProof {
            receipt: receipt.clone(),
            tx_bytes: other_tx.to_bcs().unwrap(),
            deadline_ms: 10,
            current_height_hint: 0,
        };
        assert!(proof.verify(DEFAULT_CHAIN_ID, u64::MAX, &[], 10).is_err());

        // chain_id 域不一致
        let proof = CensorshipProof {
            receipt,
            tx_bytes: tx.to_bcs().unwrap(),
            deadline_ms: 10,
            current_height_hint: 0,
        };
        assert!(proof.verify(0xDEAD_BEEF, u64::MAX, &[], 10).is_err());
    }

    #[test]
    fn censorship_outcome_serializes_snake_case() {
        let s = serde_json::to_string(&CensorshipCheckOutcome::Censored).unwrap();
        assert_eq!(s, "\"censored\"");
        let s = serde_json::to_string(&CensorshipCheckOutcome::NotYetDue).unwrap();
        assert_eq!(s, "\"not_yet_due\"");
        let s = serde_json::to_string(&CensorshipCheckOutcome::Included).unwrap();
        assert_eq!(s, "\"included\"");
    }

    // ===== v1.5-a1：ReceiptSidecar 持久化 =====

    #[test]
    fn receipt_sidecar_append_replay_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "pokerl1_sidecar_test_{}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::force_include::RECEIPT_SIDECAR_FILE);
        let _ = std::fs::remove_file(&path);

        let secret = secp256k1::SecretKey::from_slice(&[0x21u8; 32]).unwrap();
        let txs: Vec<Transaction> = (1..=3).map(signed_tx).collect();
        {
            let (mut sidecar, replayed) = ReceiptSidecar::open(&dir).unwrap();
            assert!(replayed.is_empty(), "新 sidecar 应无历史行");
            for (i, tx) in txs.iter().enumerate() {
                let receipt =
                    SeenReceipt::issue(crate::DEFAULT_CHAIN_ID, tx.tx_hash(), 1000 + i as u64, &secret)
                        .unwrap();
                sidecar.append(&receipt).unwrap();
            }
        }
        // 重启恢复：重放得到全部 receipt，签名仍可验证
        let (sidecar2, replayed) = ReceiptSidecar::open(&dir).unwrap();
        assert_eq!(replayed.len(), 3, "重启后必须恢复全部 receipt");
        for (i, receipt) in replayed.iter().enumerate() {
            receipt.verify().expect("重放 receipt 签名必须仍有效");
            assert_eq!(receipt.seen_at_ms, 1000 + i as u64);
        }
        assert_eq!(sidecar2.corrupt_lines(), 0);
        // 追加去重语义：同 tx_hash 重放后写覆盖前写（map 语义由 Node 侧保证）
        let receipt_dup =
            SeenReceipt::issue(crate::DEFAULT_CHAIN_ID, txs[0].tx_hash(), 7777, &secret).unwrap();
        let mut sidecar3 = sidecar2;
        sidecar3.append(&receipt_dup).unwrap();
        let (_, replayed2) = ReceiptSidecar::open(&dir).unwrap();
        assert_eq!(replayed2.len(), 4, "append-only：同 hash 追加也保留历史行");
        let recovered = replayed2
            .iter()
            .find(|r| r.tx_hash == txs[0].tx_hash() && r.seen_at_ms == 7777)
            .expect("后写行必须可重放");
        assert_eq!(recovered.seen_at_ms, 7777);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn receipt_sidecar_replay_skips_corrupt_lines() {
        let dir = std::env::temp_dir().join(format!(
            "pokerl1_sidecar_corrupt_{}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::force_include::RECEIPT_SIDECAR_FILE);
        let secret = secp256k1::SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let tx = signed_tx(9);
        let receipt =
            SeenReceipt::issue(crate::DEFAULT_CHAIN_ID, tx.tx_hash(), 42, &secret).unwrap();
        let good_line = serde_json::to_string(&receipt).unwrap();
        let truncated = good_line[..20].to_string();
        // 模拟崩溃残留：好行 + 截断半行 + 非法 JSON + 空行
        std::fs::write(
            &path,
            format!("{good_line}\n{truncated}…\n{{\"broken\":\n\n"),
        )
        .unwrap();
        let (replayed, corrupt) = ReceiptSidecar::replay(&path).unwrap();
        assert_eq!(replayed.len(), 1, "合法行必须恢复");
        assert_eq!(corrupt, 2, "损坏行必须被跳过并计数");
        std::fs::remove_dir_all(&dir).ok();
    }
}
