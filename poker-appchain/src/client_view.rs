//! M6（最小实现）：客户端余额视图。
//!
//! 客户端自持 note + 包含证明，对账本根独立验证后聚合余额。
//! wasm 侧复用同一纯函数（client-wasm 集成是后续项，见 blockers）。
//!
//! ## ABI v2 账户视图
//!
//! [`account_view`] 按**账本版本**区分聚合：v1 note（账户 = 33B 压缩
//! 公钥）与 v2 note（账户 = [`OwnerRef`]，承诺含 scheme/key_version）
//! 各自独立聚合余额，**不跨账本合并**——账本版本与资产同为隔离边界
//! （迁移通过 MigrateNote 显式消费/铸造，视图如实反映两侧存量）。
//!
//! TE-M1：v2 侧列语义从 AssetClass（REAL/PLAY）升级为 AssetDomain
//! （[`ClassPair`] 的 `real`/`play` 字段在 v2 侧读作 **REAL 域合计 /
//! GAME 域合计**，token 无关）；逐 `AssetId` 细分用
//! [`v2_balances_by_asset`]（TE-M2 多币种 / TE-M3 GAME 币的视图地基）。

use std::collections::BTreeMap;

use starknet_crypto::FieldElement;

use crate::asset_id::AssetId;
use crate::error::AppchainResult;
use crate::merkle::{InclusionProof, PoseidonMerkleTree};
use crate::note::{AssetClass, Note};
use crate::owner_v2::OwnerRef;
use crate::sequencer::LedgerState;

/// 单张客户端持有的 note 凭证。
#[derive(Debug, Clone)]
pub struct NoteCredential {
    /// note 内容。
    pub note: Note,
    /// 包含证明（由 sequencer 导出，客户端离线验证）。
    pub proof: InclusionProof,
}

/// 聚合余额（按资产类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Balances {
    /// REAL 余额。
    pub real: u128,
    /// PLAY 余额。
    pub play: u128,
    /// 通过验证的 note 数。
    pub verified_notes: usize,
}

/// 按资产拆分的余额对。
///
/// 字段名沿用 `real`/`play`（不改公开 API），语义按账本版本读：
/// - `AccountView::v1`：v1 `AssetClass`（Real / Play，v1 语义零变更）；
/// - `AccountView::v2`（TE-M1）：**REAL 域合计 / GAME 域合计**（按
///   `AssetId.domain` 分列，token 无关；与 v1 列逐点重合——冻结映射
///   Real→REAL/0、Play→GAME/0，遗留资产下两读法等价）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClassPair {
    /// REAL 侧余额（v1 = AssetClass::Real；v2 = REAL 域合计）。
    pub real: u128,
    /// PLAY/GAME 侧余额（v1 = AssetClass::Play；v2 = GAME 域合计）。
    pub play: u128,
}

/// 账户视图（ABI v2）：v1/v2 note 分账本聚合，账户身份按版本
/// （v1 = 压缩公钥，v2 = [`OwnerRef`]）。资产隔离在两侧保持（TE-M1：
/// v2 侧为 AssetId 域隔离）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountView {
    /// v1 账本聚合（`v1_owner = None` 时恒零）。
    pub v1: ClassPair,
    /// v2 账本聚合（`v2_owner = None` 时恒零）。
    pub v2: ClassPair,
}

/// 账本聚合视图（ sequencer 侧；客户端离线路径见
/// [`balances_from_credentials`]）。
///
/// `v1_owner` / `v2_owner` 分别是两个账本的账户身份（可只查一侧）。
/// v2 侧列语义见 [`ClassPair`]（TE-M1：REAL 域 / GAME 域分栏）。
#[must_use]
pub fn account_view(
    state: &LedgerState,
    v1_owner: Option<&[u8; 33]>,
    v2_owner: Option<&OwnerRef>,
) -> AccountView {
    let mut out = AccountView::default();
    if let Some(pk) = v1_owner {
        let (real, play) = state.balances_of(pk);
        out.v1 = ClassPair { real, play };
    }
    if let Some(owner) = v2_owner {
        // TE-M1：v2 侧域分栏（balances_v2_of 按 AssetId.domain 聚合）
        let (real, play) = state.balances_v2_of(owner);
        out.v2 = ClassPair { real, play };
    }
    out
}

/// v2 侧按 [`AssetId`] 分组余额（TE-M1；sequencer 侧视图）。
///
/// 键 = note 的精确资产身份（domain + token_id），值为该资产下全部
/// live v2 note 面额合计。BTreeMap 保证输出确定序（对账/导出友好）。
/// 与 [`account_view`] 的域分栏互补：域栏是本映射按 domain 的折叠。
#[must_use]
pub fn v2_balances_by_asset(state: &LedgerState, owner: &OwnerRef) -> BTreeMap<AssetId, u128> {
    let mut out = BTreeMap::new();
    for e in state.note_entries_v2_of(owner) {
        *out.entry(e.note.asset_id).or_insert(0u128) += u128::from(e.note.amount);
    }
    out
}

/// 验证 + 聚合：任何一张 note 的包含证明失败即整体拒绝（fail-closed）。
///
/// # Errors
/// 任一包含证明无效 → [`AppchainError::NoteNotFound`]。
pub fn balances_from_credentials(
    credentials: &[NoteCredential],
    ledger_root: FieldElement,
) -> AppchainResult<Balances> {
    let mut out = Balances::default();
    for c in credentials {
        let leaf = c.note.commitment();
        if !PoseidonMerkleTree::verify_proof(leaf, &c.proof, ledger_root) {
            return Err(crate::error::AppchainError::NoteNotFound);
        }
        match c.note.asset_class {
            AssetClass::Real => out.real += u128::from(c.note.amount),
            AssetClass::Play => out.play += u128::from(c.note.amount),
        }
        out.verified_notes += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_and_aggregate() {
        let k = crate::keys::OwnerKey::from_seed(&[2; 32]).unwrap();
        let mut tree = PoseidonMerkleTree::new();
        let mut notes = Vec::new();
        for i in 0..4u8 {
            notes.push(
                Note::new(
                    if i % 2 == 0 { AssetClass::Real } else { AssetClass::Play },
                    u64::from(i) + 1,
                    k.public_bytes(),
                    [i; 32],
                    None,
                )
                .unwrap(),
            );
        }
        // 全部 append 完成后再取证明（中途取出的证明对最终根失效）
        for n in &notes {
            tree.append(n.commitment()).unwrap();
        }
        let mut creds = Vec::new();
        for n in &notes {
            let idx = {
                // 由承诺反查叶序：重放 append 顺序
                notes
                    .iter()
                    .position(|m| m.commitment() == n.commitment())
                    .unwrap() as u64
            };
            creds.push(NoteCredential {
                note: n.clone(),
                proof: tree.proof(idx).unwrap(),
            });
        }
        let b = balances_from_credentials(&creds, tree.root()).unwrap();
        assert_eq!(b.real, 1 + 3);
        assert_eq!(b.play, 2 + 4);
        assert_eq!(b.verified_notes, 4);
    }

    #[test]
    fn tampered_root_rejected() {
        let k = crate::keys::OwnerKey::from_seed(&[3; 32]).unwrap();
        let mut tree = PoseidonMerkleTree::new();
        let note = Note::new(AssetClass::Real, 5, k.public_bytes(), [1; 32], None).unwrap();
        let idx = tree.append(note.commitment()).unwrap();
        let proof = tree.proof(idx).unwrap();
        let bad_root = starknet_crypto::poseidon_hash_many(&[tree.root()]);
        assert!(balances_from_credentials(
            &[NoteCredential { note, proof }],
            bad_root
        )
        .is_err());
    }
}
