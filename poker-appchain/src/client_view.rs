//! M6（最小实现）：客户端余额视图。
//!
//! 客户端自持 note + 包含证明，对账本根独立验证后聚合余额。
//! wasm 侧复用同一纯函数（client-wasm 集成是后续项，见 blockers）。

use starknet_crypto::FieldElement;

use crate::error::AppchainResult;
use crate::merkle::{InclusionProof, PoseidonMerkleTree};
use crate::note::{AssetClass, Note};

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
