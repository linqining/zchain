//! M8：checkpoint 导出与校验。
//!
//! checkpoint 是 sequencer 当前状态（软确认链头 + 账本状态根 + 证明水位 +
//! 批次根表）的**只读快照文件**，供 watcher / 运维对拍。它不是信任根：
//! [`verify_checkpoint`] 将文件逐字段与独立重放的 sequencer 对拍，并用
//! blake2s 载荷摘要把"篡改后重签摘要"与"字段对不上"两类破坏都挡住。
//!
//! 文件格式（JSON，字段名冻结）：
//!
//! ```json
//! {
//!   "format": "zchain.appchain.checkpoint.v1",
//!   "head_index": 3,
//!   "head_hash": "<64hex>",
//!   "frame_count": 4,
//!   "state_root": "<64hex>",
//!   "watermark": 3,
//!   "batch_roots": [{"op_index": 3, "root": "<64hex>"}],
//!   "payload_digest": "<64hex>",
//!   "withdrawal_root": null | {
//!     "checkpoint_height": 64, "leaf_count": 2,
//!     "root": "<64hex>", "digest": "<64hex>"
//!   }
//! }
//! ```
//!
//! withdrawal_root（M7-ACC-5 字段集成，da-selection.md §4.2 #5 待办收口）：
//! **additive 可选字段**——`None`（缺省/旧文件无该键）时载荷摘要与 v1 公式
//! **逐字节一致**（零迁移）；`Some` 时摘要载荷尾部追加
//! `0x01 ‖ height_be ‖ leaf_count_be ‖ root32`。携带时机：主控在 checkpoint
//! BFT finalized 流程中用 [`crate::withdrawal_root::WithdrawalRootBuilder`]
//! 聚合窗口叶子后经 [`attach_withdrawal_root`] 挂入；[`verify_checkpoint`]
//! 对"文件带根、对拍态无根"fail-closed（见
//! [`verify_checkpoint_with_withdrawal_root`]）。
//!
//! 载荷摘要：`payload_digest = blake2s32(DOMAIN || head_index_be ||
//! head_hash32 || frame_count_be || state_root32 || watermark_be ||
//! (op_index_be || root32)*)`——规范字节序列化（无 JSON 歧义），域
//! `zchain.appchain.checkpoint.v1.payload`。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{AppchainError, AppchainResult};
use crate::keys::blake2s32;
use crate::sequencer::Sequencer;

/// 格式标识（版本冻结；不兼容升级必须换版本号）。
pub const CHECKPOINT_FORMAT: &str = "zchain.appchain.checkpoint.v1";

/// 载荷摘要域分隔。
const PAYLOAD_DOMAIN: &[u8] = b"zchain.appchain.checkpoint.v1.payload";

/// 一条批次根快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBatchRoot {
    /// 覆盖到的 op index（含）。
    pub op_index: u64,
    /// 批次根（64hex）。
    pub root: String,
}

/// checkpoint 快照（JSON 文件形态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// 格式标识（恒 [`CHECKPOINT_FORMAT`]）。
    pub format: String,
    /// 链头帧 index（空链 = 0，配合 frame_count = 0 语义）。
    pub head_index: u64,
    /// 链头帧哈希（64hex；空链 = 创世 prev 全零）。
    pub head_hash: String,
    /// 帧数。
    pub frame_count: u64,
    /// 账本状态根（64hex）。
    pub state_root: String,
    /// 证明水位。
    pub watermark: u64,
    /// 批次根表（through_op 升序）。
    pub batch_roots: Vec<CheckpointBatchRoot>,
    /// 载荷摘要（64hex；规范字节 blake2s，见模块文档）。
    pub payload_digest: String,
    /// withdrawal root（M7 字段集成；可选——缺省 None 与 v1 完全兼容）。
    #[serde(default)]
    pub withdrawal_root: Option<CheckpointWithdrawalRoot>,
}

/// checkpoint 携带的 withdrawal root 投影（[`crate::withdrawal_root::
/// WithdrawalRoot`] 的 JSON 形态；字段名冻结）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointWithdrawalRoot {
    /// 窗口 checkpoint 高度。
    pub checkpoint_height: u64,
    /// 窗口真实叶子数（不含补齐空叶）。
    pub leaf_count: u64,
    /// Merkle 根（64hex）。
    pub root: String,
    /// 根摘要（64hex；`WithdrawalRoot::digest_of` 重算核对）。
    pub digest: String,
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn decode32(s: &str, field: &'static str) -> AppchainResult<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|_| AppchainError::Codec(format!("{field}: not hex")))?;
    bytes.try_into().map_err(|_| {
        AppchainError::Codec(format!("{field}: expected 32 bytes (64 hex)"))
    })
}

/// 规范载荷字节（摘要输入；顺序冻结，见模块文档）。
fn canonical_payload(c: &Checkpoint) -> AppchainResult<Vec<u8>> {
    let head_hash = decode32(&c.head_hash, "head_hash")?;
    let state_root = decode32(&c.state_root, "state_root")?;
    let mut out = Vec::with_capacity(32 + 3 * 8 + 64 + c.batch_roots.len() * 40);
    out.extend_from_slice(PAYLOAD_DOMAIN);
    out.extend_from_slice(&c.head_index.to_be_bytes());
    out.extend_from_slice(&head_hash);
    out.extend_from_slice(&c.frame_count.to_be_bytes());
    out.extend_from_slice(&state_root);
    out.extend_from_slice(&c.watermark.to_be_bytes());
    for b in &c.batch_roots {
        out.extend_from_slice(&b.op_index.to_be_bytes());
        out.extend_from_slice(&decode32(&b.root, "batch_roots[].root")?);
    }
    // withdrawal_root（additive）：缺省不进摘要（v1 公式不变）；Some 时
    // 追加 `0x01 ‖ height_be ‖ leaf_count_be ‖ root32`（标记字节防
    // None/Some 边界歧义——32B root 与既有字段拼接的理论二义性消除）。
    if let Some(w) = &c.withdrawal_root {
        out.push(0x01);
        out.extend_from_slice(&w.checkpoint_height.to_be_bytes());
        out.extend_from_slice(&w.leaf_count.to_be_bytes());
        out.extend_from_slice(&decode32(&w.root, "withdrawal_root.root")?);
    }
    Ok(out)
}

/// withdrawal root 内部一致性核对：digest 字段必须等于
/// `WithdrawalRoot::digest_of(height, leaf_count, root)` 重算。
fn check_withdrawal_root_digest(w: &CheckpointWithdrawalRoot) -> AppchainResult<()> {
    let root = decode32(&w.root, "withdrawal_root.root")?;
    let digest = decode32(&w.digest, "withdrawal_root.digest")?;
    if crate::withdrawal_root::WithdrawalRoot::digest_of(
        w.checkpoint_height,
        w.leaf_count,
        root,
    ) != digest
    {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: withdrawal_root digest mismatch (internal)",
        ));
    }
    Ok(())
}

/// 把 M7 主控聚合的 withdrawal root 挂入快照（BFT finalized 流程的接线点；
/// 挂入后**载荷摘要必须重算**——`export_checkpoint` 已处理，手工构造路径
/// 由调用方负责）。
pub fn attach_withdrawal_root(cp: &mut Checkpoint, root: &crate::withdrawal_root::WithdrawalRoot) {
    cp.withdrawal_root = Some(CheckpointWithdrawalRoot {
        checkpoint_height: root.checkpoint_height,
        leaf_count: root.leaf_count,
        root: hex32(&root.root),
        digest: hex32(&root.digest),
    });
}

/// 从快照载荷重算摘要。
fn recompute_digest(c: &Checkpoint) -> AppchainResult<[u8; 32]> {
    Ok(blake2s32(&[&canonical_payload(c)?]))
}

/// 从 sequencer 构造快照（不落盘部分，导出/测试复用）。
#[must_use]
pub fn checkpoint_of(seq: &Sequencer) -> Checkpoint {
    let chain = seq.chain();
    let (head_index, head_hash) = match chain.last() {
        Some(f) => (
            f.frame.index,
            f.hash().unwrap_or([0u8; 32]),
        ),
        None => (0, crate::soft_confirm::genesis_prev_hash()),
    };
    Checkpoint {
        format: CHECKPOINT_FORMAT.to_string(),
        head_index,
        head_hash: hex32(&head_hash),
        frame_count: u64::try_from(chain.len()).unwrap_or(u64::MAX),
        state_root: hex32(&seq.state().root()),
        watermark: seq.proven_watermark(),
        batch_roots: seq
            .batch_roots()
            .into_iter()
            .map(|(op_index, root)| CheckpointBatchRoot {
                op_index,
                root: hex32(&root),
            })
            .collect(),
        payload_digest: String::new(),
        withdrawal_root: None,
    }
}

/// 导出 checkpoint 到 `path`（JSON，pretty；含载荷摘要）。
///
/// # Errors
/// 摘要编码失败（实际不可达）或文件写入失败 → [`AppchainError`]。
pub fn export_checkpoint(seq: &Sequencer, path: &Path) -> AppchainResult<()> {
    let mut cp = checkpoint_of(seq);
    cp.payload_digest = hex32(&recompute_digest(&cp)?);
    let json = serde_json::to_string_pretty(&cp)
        .map_err(|e| AppchainError::Codec(e.to_string()))?;
    std::fs::write(path, json)
        .map_err(|_| AppchainError::WalCorrupted("checkpoint write failed"))?;
    Ok(())
}

/// 读取并校验 checkpoint（M8 watcher / 运维对拍入口）：
///
/// 1. 格式标识必须是 [`CHECKPOINT_FORMAT`]；
/// 2. `payload_digest` 必须与按载荷重算的摘要一致（防"改字段不改摘要"；
///    "连摘要一起改"由第 3 步挡住）；
/// 3. 全部字段与 `seq` 独立重放的实时状态逐字段对拍。
///
/// # Errors
/// 文件不可读/JSON 坏 → [`AppchainError`]；任何字段或摘要不一致 →
/// [`AppchainError::AdmissionRejected`]（`&'static str` 唯一分类）。
pub fn verify_checkpoint(file: &Path, seq: &Sequencer) -> AppchainResult<()> {
    let bytes = std::fs::read(file)
        .map_err(|_| AppchainError::WalCorrupted("checkpoint open failed"))?;
    let parsed: Checkpoint = serde_json::from_slice(&bytes)
        .map_err(|e| AppchainError::Codec(format!("checkpoint json: {e}")))?;

    if parsed.format != CHECKPOINT_FORMAT {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: format mismatch",
        ));
    }
    let expect_digest = recompute_digest(&parsed)?;
    let got_digest = decode32(&parsed.payload_digest, "payload_digest")?;
    if got_digest != expect_digest {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: payload digest mismatch",
        ));
    }

    let expect = checkpoint_of(seq);
    let expect_digest = recompute_digest(&expect)?;
    if parsed.head_index != expect.head_index {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: head_index mismatch",
        ));
    }
    if parsed.head_hash != expect.head_hash {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: head_hash mismatch",
        ));
    }
    if parsed.frame_count != expect.frame_count {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: frame_count mismatch",
        ));
    }
    if parsed.state_root != expect.state_root {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: state_root mismatch",
        ));
    }
    if parsed.watermark != expect.watermark {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: watermark mismatch",
        ));
    }
    let parsed_roots: Vec<(u64, [u8; 32])> = parsed
        .batch_roots
        .iter()
        .map(|b| Ok((b.op_index, decode32(&b.root, "batch_roots[].root")?)))
        .collect::<AppchainResult<Vec<_>>>()?;
    if parsed_roots != seq.batch_roots() {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: batch_roots mismatch",
        ));
    }
    // withdrawal_root：内部摘要核对（文件自洽）+ 对拍（重放态无根而文件
    // 带根 → fail-closed——根是主控聚合产物，验证方必须显式提供期望值，
    // 走 [`verify_checkpoint_with_withdrawal_root`]）。
    if let Some(w) = &parsed.withdrawal_root {
        check_withdrawal_root_digest(w)?;
    }
    if (parsed.withdrawal_root.is_some()) != (expect.withdrawal_root.is_some()) {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: withdrawal_root presence mismatch (use verify_checkpoint_with_withdrawal_root)",
        ));
    }
    if let (Some(a), Some(b)) = (&parsed.withdrawal_root, &expect.withdrawal_root) {
        if a != b {
            return Err(AppchainError::AdmissionRejected(
                "checkpoint: withdrawal_root mismatch",
            ));
        }
    }
    if got_digest != expect_digest {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: payload digest mismatch against replayed state",
        ));
    }
    Ok(())
}

/// [`verify_checkpoint`] 的 withdrawal root 对拍版（M7 字段集成后主控路径）：
/// `expected = Some(root)` 时对拍侧以挂入该根的快照为期望（并核内部摘要）；
/// `None` 时期望文件**不带根**（旧口径）。
///
/// # Errors
/// 见 [`verify_checkpoint`]；根不一致/内部摘要不一致 →
/// [`AppchainError::AdmissionRejected`]。
pub fn verify_checkpoint_with_withdrawal_root(
    file: &Path,
    seq: &Sequencer,
    expected: Option<&crate::withdrawal_root::WithdrawalRoot>,
) -> AppchainResult<()> {
    let mut expect = checkpoint_of(seq);
    if let Some(root) = expected {
        check_withdrawal_root_digest(&CheckpointWithdrawalRoot {
            checkpoint_height: root.checkpoint_height,
            leaf_count: root.leaf_count,
            root: hex32(&root.root),
            digest: hex32(&root.digest),
        })?;
        attach_withdrawal_root(&mut expect, root);
    }
    verify_checkpoint_fields(file, seq, &expect)
}

/// 对拍核心（`verify_checkpoint` 的期望显式化版本；供 withdrawal root
/// 对拍复用）。
fn verify_checkpoint_fields(file: &Path, seq: &Sequencer, expect: &Checkpoint) -> AppchainResult<()> {
    let bytes = std::fs::read(file)
        .map_err(|_| AppchainError::WalCorrupted("checkpoint open failed"))?;
    let parsed: Checkpoint = serde_json::from_slice(&bytes)
        .map_err(|e| AppchainError::Codec(format!("checkpoint json: {e}")))?;

    if parsed.format != CHECKPOINT_FORMAT {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: format mismatch",
        ));
    }
    let got_digest = recompute_digest(&parsed)?;
    let declared = decode32(&parsed.payload_digest, "payload_digest")?;
    if declared != got_digest {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: payload digest mismatch",
        ));
    }
    if parsed.head_index != expect.head_index {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: head_index mismatch",
        ));
    }
    if parsed.head_hash != expect.head_hash {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: head_hash mismatch",
        ));
    }
    if parsed.frame_count != expect.frame_count {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: frame_count mismatch",
        ));
    }
    if parsed.state_root != expect.state_root {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: state_root mismatch",
        ));
    }
    if parsed.watermark != expect.watermark {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: watermark mismatch",
        ));
    }
    let parsed_roots: Vec<(u64, [u8; 32])> = parsed
        .batch_roots
        .iter()
        .map(|b| Ok((b.op_index, decode32(&b.root, "batch_roots[].root")?)))
        .collect::<AppchainResult<Vec<_>>>()?;
    if parsed_roots != seq.batch_roots() {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: batch_roots mismatch",
        ));
    }
    if let (Some(a), Some(b)) = (&parsed.withdrawal_root, &expect.withdrawal_root) {
        if a != b {
            return Err(AppchainError::AdmissionRejected(
                "checkpoint: withdrawal_root mismatch",
            ));
        }
    } else if parsed.withdrawal_root.is_some() || expect.withdrawal_root.is_some() {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: withdrawal_root presence mismatch",
        ));
    }
    if declared != recompute_digest(expect)? {
        return Err(AppchainError::AdmissionRejected(
            "checkpoint: payload digest mismatch against replayed state",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SequencerKey;
    use crate::metrics::MetricsRegistry;
    use crate::ops::Operation;
    use crate::sequencer::SequencerConfig;
    use std::sync::Arc;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("poker-appchain-checkpoint-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(tag)
    }

    fn seq_with_chain() -> Sequencer {
        let mut s = Sequencer::new(
            SequencerKey::from_seed(&[71u8; 32]),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        for i in 0..3u8 {
            let mut deposit_id = [0u8; 32];
            deposit_id[0] = i;
            s.submit(
                Operation::Deposit {
                    deposit_id,
                    owner: [i + 1; 33],
                    asset_class: crate::note::AssetClass::Play,
                    amount: 100,
                },
                1_000 + u64::from(i),
            )
            .unwrap();
        }
        s.mark_proven_through_with_root(2, [0x5A; 32]);
        s
    }

    #[test]
    fn checkpoint_roundtrip_and_verify() {
        let s = seq_with_chain();
        let p = temp_path("roundtrip.json");
        export_checkpoint(&s, &p).unwrap();
        verify_checkpoint(&p, &s).unwrap();

        // 结构对拍：字段齐全、格式标识、摘要自洽
        let cp: Checkpoint =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(cp.format, CHECKPOINT_FORMAT);
        assert_eq!(cp.head_index, 2);
        assert_eq!(cp.frame_count, 3);
        assert_eq!(cp.watermark, 2);
        assert_eq!(cp.batch_roots.len(), 1);
        assert_eq!(cp.batch_roots[0].op_index, 2);
        assert_eq!(cp.batch_roots[0].root, hex::encode([0x5A; 32]));
        assert_eq!(cp.head_hash, hex::encode(s.head_hash().unwrap()));
        assert_eq!(cp.state_root, hex::encode(s.state().root()));
    }

    /// 空链 checkpoint：head = 创世 prev、frame_count = 0，round-trip 通过。
    #[test]
    fn empty_chain_checkpoint() {
        let s = Sequencer::new(
            SequencerKey::from_seed(&[72u8; 32]),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        let p = temp_path("empty.json");
        export_checkpoint(&s, &p).unwrap();
        verify_checkpoint(&p, &s).unwrap();
        let cp: Checkpoint =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(cp.frame_count, 0);
        assert_eq!(cp.head_hash, hex::encode(crate::soft_confirm::genesis_prev_hash()));
    }

    /// 篡改任一字段 / 摘要 → Err（对拍 + digest 双保险，两类破坏都覆盖）。
    #[test]
    fn tampered_checkpoint_rejected() {
        let s = seq_with_chain();
        let p = temp_path("tamper.json");
        export_checkpoint(&s, &p).unwrap();
        let mut cp: Checkpoint =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();

        // (1) 改字段不改摘要 → digest 对拍挡住
        let mut c1 = cp.clone();
        c1.watermark += 1;
        std::fs::write(&p, serde_json::to_string(&c1).unwrap()).unwrap();
        assert!(verify_checkpoint(&p, &s).is_err());

        let mut c2 = cp.clone();
        c2.state_root = hex::encode([0u8; 32]);
        std::fs::write(&p, serde_json::to_string(&c2).unwrap()).unwrap();
        assert!(verify_checkpoint(&p, &s).is_err());

        let mut c3 = cp.clone();
        c3.batch_roots[0].root = hex::encode([0x33; 32]);
        std::fs::write(&p, serde_json::to_string(&c3).unwrap()).unwrap();
        assert!(verify_checkpoint(&p, &s).is_err());

        // (2) 连摘要一起重算（伪造与 seq 不一致的"自洽"checkpoint）→
        //     字段对拍挡住
        let mut c4 = cp.clone();
        c4.watermark += 1;
        c4.payload_digest = hex::encode(recompute_digest(&c4).unwrap());
        std::fs::write(&p, serde_json::to_string(&c4).unwrap()).unwrap();
        assert!(verify_checkpoint(&p, &s).is_err());

        // (3) 格式标识篡改 → Err
        let mut c5 = cp.clone();
        c5.format = "zchain.appchain.checkpoint.v0".to_string();
        c5.payload_digest = hex::encode(recompute_digest(&c5).unwrap());
        std::fs::write(&p, serde_json::to_string(&c5).unwrap()).unwrap();
        assert!(verify_checkpoint(&p, &s).is_err());

        // (4) 摘要字段本身篡改 → Err
        let mut c6 = cp;
        c6.payload_digest = hex::encode([0u8; 32]);
        std::fs::write(&p, serde_json::to_string(&c6).unwrap()).unwrap();
        assert!(verify_checkpoint(&p, &s).is_err());
    }

    // ===== M7 withdrawal_root 字段集成（additive 摘要兼容） =====

    use crate::withdrawal_root::{WithdrawalLeaf, WithdrawalRootBuilder};

    fn window_root(height: u64, n: u8) -> crate::withdrawal_root::WithdrawalRoot {
        let mut b = WithdrawalRootBuilder::new();
        for i in 0..n {
            b.push(WithdrawalLeaf {
                request_id: [i; 32],
                external_recipient: [0xEE; 32],
                asset_class: 1,
                amount: 100 + u64::from(i),
                burned_note_commitment: [i ^ 0xFF; 32],
                checkpoint_height: height,
            })
            .unwrap();
        }
        b.build(height).unwrap()
    }

    /// (1) 缺省无根：载荷摘要与 v1 公式一致（零迁移）；(2) 挂根后摘要变化
    /// 且带标记字节；(3) export → verify（带期望根）闭环；(4) 根不一致/
    /// 期望缺失 fail-closed。
    #[test]
    fn withdrawal_root_field_additive_integration() {
        let s = seq_with_chain();
        let p = temp_path("cp-wr.json");
        let _ = std::fs::remove_file(&p);

        // (1) v1 兼容：无根快照摘要 == v1 载荷公式（手动拼 v1 载荷核对）
        let cp = checkpoint_of(&s);
        let mut v1_payload: Vec<u8> = Vec::new();
        v1_payload.extend_from_slice(PAYLOAD_DOMAIN);
        v1_payload.extend_from_slice(&cp.head_index.to_be_bytes());
        v1_payload.extend_from_slice(&decode32(&cp.head_hash, "x").unwrap());
        v1_payload.extend_from_slice(&cp.frame_count.to_be_bytes());
        v1_payload.extend_from_slice(&decode32(&cp.state_root, "x").unwrap());
        v1_payload.extend_from_slice(&cp.watermark.to_be_bytes());
        for b in &cp.batch_roots {
            v1_payload.extend_from_slice(&b.op_index.to_be_bytes());
            v1_payload.extend_from_slice(&decode32(&b.root, "x").unwrap());
        }
        let v1_digest = blake2s32(&[&v1_payload]);
        assert_eq!(
            hex::encode(v1_digest),
            {
                let c = checkpoint_of(&s);
                hex::encode(recompute_digest(&c).unwrap())
            },
            "无根快照摘要必须与 v1 公式逐字节一致"
        );

        // (2) 挂根：摘要变化、字段自洽
        let root = window_root(64, 2);
        let mut cp2 = checkpoint_of(&s);
        let digest_before = recompute_digest(&cp2).unwrap();
        attach_withdrawal_root(&mut cp2, &root);
        cp2.payload_digest = hex::encode(recompute_digest(&cp2).unwrap());
        assert_ne!(
            recompute_digest(&cp2).unwrap(),
            digest_before,
            "挂根必须改变载荷摘要"
        );
        std::fs::write(&p, serde_json::to_string(&cp2).unwrap()).unwrap();

        // (3) 对拍闭环：期望 = 挂同一根的快照
        verify_checkpoint_with_withdrawal_root(&p, &s, Some(&root))
            .expect("带根对拍必须通过");
        // 旧口径 verify_checkpoint：文件带根而重放态无根 → fail-closed
        assert!(verify_checkpoint(&p, &s).is_err());

        // (4) 期望根不一致 → 拒
        let other_root = window_root(96, 1);
        assert!(verify_checkpoint_with_withdrawal_root(&p, &s, Some(&other_root)).is_err());
        assert!(verify_checkpoint_with_withdrawal_root(&p, &s, None).is_err());

        // (5) 篡改根字段（自愈摘要也重算）→ 内部 digest 核对/字段对拍挡
        let mut c3 = cp2.clone();
        let forged_root = window_root(64, 3);
        c3.withdrawal_root = Some(CheckpointWithdrawalRoot {
            checkpoint_height: forged_root.checkpoint_height,
            leaf_count: forged_root.leaf_count,
            root: hex32(&forged_root.root),
            digest: hex32(&forged_root.digest),
        });
        // digest 字段与 root/height 一致但与期望不一致 → 字段对拍挡
        c3.payload_digest = hex::encode(recompute_digest(&c3).unwrap());
        std::fs::write(&p, serde_json::to_string(&c3).unwrap()).unwrap();
        assert!(verify_checkpoint_with_withdrawal_root(&p, &s, Some(&root)).is_err());
        // digest 字段与载荷不一致（伪造 digest）→ 内部核对挡
        let mut c4 = cp2.clone();
        if let Some(w) = &mut c4.withdrawal_root {
            w.leaf_count += 1; // digest 不再匹配 (height,count,root)
        }
        c4.payload_digest = hex::encode(recompute_digest(&c4).unwrap());
        std::fs::write(&p, serde_json::to_string(&c4).unwrap()).unwrap();
        assert!(verify_checkpoint_with_withdrawal_root(&p, &s, Some(&root)).is_err());
        let _ = std::fs::remove_file(&p);
    }
}
