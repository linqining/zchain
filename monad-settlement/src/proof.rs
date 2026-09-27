//! L1Outbox 树构造的逐字节镜像（Rust 侧 verifier + daemon 干跑校验）。
//!
//! 这是三方对齐的中枢：`poker-appchain::withdrawal_root`（L2 权威构造）、
//! `contracts/monad/src/L1Outbox.sol`（L1 校验）、本模块（Rust 交叉验证 +
//! 工具面）。规则（任意一侧改动必须三方同步 + 测试）：
//!
//! - 域标签 [`DOMAIN`] = `zchain.vault.withdrawal_root.v1`；
//! - 叶：`sha256(DOMAIN ‖ 0x00 ‖ borsh(leaf))`，borsh(leaf) = 113B 紧凑小端；
//! - 内部节点：`sha256(DOMAIN ‖ 0x01 ‖ l ‖ r)`；
//! - 空叶：`sha256(DOMAIN ‖ 0x00 ‖ "")`（不平衡补齐位）；
//! - 根摘要：`sha256(DOMAIN ‖ 0x02 ‖ height_be ‖ leaf_count_be ‖ root)`；
//! - fail-closed：证明深度 ≥ 64 或 index 超出路径覆盖 → 拒绝。

use sha2::{Digest, Sha256};

use crate::abi::ClaimLeaf;

/// 域标签（与 `poker-appchain::withdrawal_root::WITHDRAWAL_ROOT_DOMAIN` 同值）。
pub const DOMAIN: &[u8] = b"zchain.vault.withdrawal_root.v1";

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;
const DIGEST_PREFIX: u8 = 0x02;

/// sha256（各段依次拼接）。
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// borsh(WithdrawalLeaf)：113B 紧凑小端（字段序冻结）。
#[must_use]
pub fn leaf_borsh_bytes(leaf: &ClaimLeaf) -> Vec<u8> {
    let mut out = Vec::with_capacity(113);
    out.extend_from_slice(&leaf.request_id);
    out.extend_from_slice(&leaf.external_recipient);
    out.push(leaf.asset_tag);
    out.extend_from_slice(&leaf.amount.to_le_bytes());
    out.extend_from_slice(&leaf.burned_note_commitment);
    out.extend_from_slice(&leaf.checkpoint_height.to_le_bytes());
    out
}

/// 叶哈希：`sha256(DOMAIN ‖ 0x00 ‖ borsh(leaf))`。
#[must_use]
pub fn leaf_hash(leaf: &ClaimLeaf) -> [u8; 32] {
    let encoded = leaf_borsh_bytes(leaf);
    sha256(&[DOMAIN, &[LEAF_PREFIX], &encoded])
}

/// 内部节点哈希。
#[must_use]
pub fn internal_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    sha256(&[DOMAIN, &[INTERNAL_PREFIX], l, r])
}

/// 空叶哈希（不平衡树补齐位）。
#[must_use]
pub fn empty_leaf_hash() -> [u8; 32] {
    sha256(&[DOMAIN, &[LEAF_PREFIX]])
}

/// 根摘要（claim 台账主键；height/count 大端）。
#[must_use]
pub fn digest_of(checkpoint_height: u64, leaf_count: u64, root: [u8; 32]) -> [u8; 32] {
    sha256(&[
        DOMAIN,
        &[DIGEST_PREFIX],
        &checkpoint_height.to_be_bytes(),
        &leaf_count.to_be_bytes(),
        &root,
    ])
}

/// Merkle 包含证明校验（fail-closed 边界与 Rust/Solidity 两侧一致）。
#[must_use]
pub fn verify_inclusion(leaf: &ClaimLeaf, proof: &[[u8; 32]], index: u64, root: [u8; 32]) -> bool {
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

/// 全量重建根（由叶集合建树；daemon 干跑/测试用）。
///
/// 叶子按 borsh 字典序规范化（顺序无关聚合，与 L2 builder 一致），不平衡
/// 以 [`empty_leaf_hash`] 补齐到 2 的幂。
#[must_use]
pub fn rebuild_root(leaves: &[ClaimLeaf]) -> ([u8; 32], u64) {
    let mut encoded: Vec<(Vec<u8>, ClaimLeaf)> =
        leaves.iter().map(|l| (leaf_borsh_bytes(l), *l)).collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    let mut level: Vec<[u8; 32]> = encoded.iter().map(|(_, l)| leaf_hash(l)).collect();
    let leaf_count = level.len() as u64;
    let width = level.len().next_power_of_two();
    level.resize(width, empty_leaf_hash());
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| internal_hash(&pair[0], &pair[1]))
            .collect();
    }
    (level[0], leaf_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_leaf(seed: u8) -> ClaimLeaf {
        ClaimLeaf {
            request_id: [seed; 32],
            external_recipient: {
                let mut w = [0u8; 32];
                w[31] = seed;
                w
            },
            asset_tag: 1,
            amount: u64::from(seed) * 1000,
            burned_note_commitment: [seed.wrapping_mul(3); 32],
            checkpoint_height: 7,
        }
    }

    #[test]
    fn borsh_layout_is_113_bytes() {
        assert_eq!(leaf_borsh_bytes(&sample_leaf(1)).len(), 113);
    }

    #[test]
    fn rebuild_root_shape() {
        let leaves: Vec<ClaimLeaf> = (1u8..=3).map(sample_leaf).collect();
        let (root, leaf_count) = rebuild_root(&leaves);
        // 3 真实叶 + 1 空叶补齐；返回的 leaf_count 只计真实叶。
        assert_eq!(leaf_count, 3);
        // 与手动折叠一致：[l0, l1, l2, empty] → 两层。
        let mut order: Vec<(Vec<u8>, ClaimLeaf)> =
            leaves.iter().map(|l| (leaf_borsh_bytes(l), *l)).collect();
        order.sort_by(|a, b| a.0.cmp(&b.0));
        let l01 = internal_hash(&leaf_hash(&order[0].1), &leaf_hash(&order[1].1));
        let l23 = internal_hash(&leaf_hash(&order[2].1), &empty_leaf_hash());
        assert_eq!(root, internal_hash(&l01, &l23));
        // 顺序无关：打乱输入根不变。
        let mut shuffled = leaves.clone();
        shuffled.reverse();
        assert_eq!(rebuild_root(&shuffled).0, root);
    }

    #[test]
    fn tamper_rejected() {
        let leaves: Vec<ClaimLeaf> = (1u8..=2).map(sample_leaf).collect();
        let (root, _) = rebuild_root(&leaves);
        // 2 叶树：根 = H(l1, l2)；叶 1（index 0）的证明 = 兄弟 l2。
        let proof = [leaf_hash(&sample_leaf(2))];
        assert!(verify_inclusion(&sample_leaf(1), &proof, 0, root));
        // 换叶/换 index/换根 任一 → false。
        assert!(!verify_inclusion(&sample_leaf(9), &proof, 0, root));
        assert!(!verify_inclusion(&sample_leaf(1), &proof, 1, root));
        assert!(!verify_inclusion(&sample_leaf(1), &proof, 0, [7u8; 32]));
        // 越界 index：proof 深度 1 只能覆盖 index 0..2。
        assert!(!verify_inclusion(&sample_leaf(1), &proof, 2, root));
    }
}
