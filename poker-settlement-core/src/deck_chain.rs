//! deck 承诺链摘要原语（洗牌/发牌证明链消费侧，设计文档
//! `docs/shuffle-deal-proof-design.md` §5-C3 + 上游 stage0 接口对齐）。
//!
//! hand_binding v1 现值 = `batch_digest`（blake2b witness 域，**不含**
//! deck 承诺链）；ABI v1.3 升域后 hand_binding = Poseidon 折叠
//! `(DOMAIN_v2, batch_digest, deck_chain_digest, reveal_commitment)`
//! （Poseidon 折叠在 `poker-appchain/src/settlement.rs`；本 crate 承载
//! **链摘要** [`deck_chain_digest`]）。deck 锚经 hand_binding v2 间接进入
//! `settle_effect`（效果摘要覆盖 hand_binding 字节）——`settle_effect`
//! 公式本身不变（设计文档 §5-C4）。
//!
//! ## 链语义（zchain 消费侧冻结）
//!
//! - 链元素 = canonical 状态镜像的 32B `deck_commitment`
//!   （`poker_texas_air` `CanonicalStateImage`，镜像内偏移见
//!   `poker_appchain::settlement::STATE_IMAGE_DECK_COMMITMENT_OFFSET`）；
//!   两侧对照（上游真实 `ShuffleChainBuilder` 产出的链 → 本函数重导 →
//!   逐位一致）钉在 `poker-appchain-texasair` 适配器测试；
//! - 上游结算绑定为每手预留 `MAX_DECK_COMMITMENTS = 10` 个承诺槽位
//!   （上游 `hand_binding.rs:45`）；本 crate 取同一上限（10）fail-closed；
//! - zchain 归档 scope 每幅镜像只携带一个 deck 承诺，故结算消费面的链 =
//!   去重后的 `[pre.deck_commitment, post.deck_commitment]`（批内逐环链
//!   由 AIR 行内约束与 STARK 验证负责，见 SHUFFLE_CONSUME.md §1.2）。
//!
//! ## 编码（**已裁决冻结**：上游 poseidon 折叠，与生产者同源）
//!
//! 阶段 0 裁决（2026-09-12，见 SHUFFLE_CONSUME.md §1.2）：上游 stage0 的
//! 真实洗牌链是权威数据源，消费侧算法必须能对上游产出**重导一致**——
//! 因此冻结为上游 `canonical_shuffle_chain::fold_chain` 的逐字节复制：
//!
//! ```text
//! preimage = SHUFFLE_CHAIN_STAGE0_DOMAIN ‖ b"deck-chain" ‖ anchor[0] ‖ … ‖ anchor[len-1]
//! digest   = poseidon_bytes_digest(preimage)
//!          = poseidon_hash_many([len_prefix, chunk_0, …])   // 长度前缀 + 31B 大端分块
//! ```
//!
//! - 域标签 = 上游 `SHUFFLE_CHAIN_STAGE0_DOMAIN`
//!   （`zchain.texas.canonical-shuffle-chain.v1`，`[u8]` 常量与上游逐字节
//!   一致）；折叠标签 `b"deck-chain"` 同源；
//! - 字节折叠 = 上游 `poseidon_over_bytes`：`u64` 长度前缀 felt + 31 字节
//!   大端分块（每块 < 2^248 < 域模数）+ Cairo 原生 `poseidon_hash_many`；
//! - 早期 blake2b-256 提案（域 `zchain.settlement.deck_chain.v1`）
//!   **已删除**：同一链两套摘要算法无法对上游产出重导一致，违背裁决原则
//!   （裁决理由与两侧对照证据见 SHUFFLE_CONSUME.md §1.2/§5）。
//!
//! 空链 / 超长链（> [`DECK_CHAIN_MAX`]）→ `None`（fail-closed：调用方
//! 必须显式处理，不得静默折叠为空链摘要）。
//!
//! ## 哈希选型
//!
//! Poseidon252（`starknet-crypto`，Cairo 原生置换）——**与生产者同源**
//! 是本次裁决的全部要点：摘要可由任何持有链锚的验证者对照上游 receipt
//! 的 `deck_chain_digest` 逐位重导（AIR/Cairo 侧同构，无位打包歧义）。

use starknet_crypto::{poseidon_hash_many, FieldElement};

/// deck 承诺链摘要域标签（**与上游 `SHUFFLE_CHAIN_STAGE0_DOMAIN` 逐字节
/// 一致**——裁决后与生产者共享同一域，不得本地改名）。golden 测试钉扎。
pub const DECK_CHAIN_DIGEST_DOMAIN: &[u8] = b"zchain.texas.canonical-shuffle-chain.v1";

/// deck 链折叠标签（与上游 `fold_chain(b"deck-chain", …)` 逐字节一致）。
pub const DECK_CHAIN_FOLD_LABEL: &[u8] = b"deck-chain";

/// deck 承诺链最大长度（对齐上游 `hand_binding.rs` `MAX_DECK_COMMITMENTS
/// = 10`：初始牌堆 + 每玩家洗牌后牌堆的承诺链槽位）。
pub const DECK_CHAIN_MAX: usize = 10;

/// deck 承诺链摘要：上游同源 poseidon 折叠（编码见模块文档）。
///
/// - 空链 → `None`（无 deck 链的手不得升域到 v2 绑定）；
/// - `len > DECK_CHAIN_MAX` → `None`（超出上游结算绑定槽位预算的链
///   fail-closed 拒绝，不得截断）；
/// - 非空且 ≤ [`DECK_CHAIN_MAX`] → 对上游 `ShuffleChainReceipt::
///   deck_chain_digest` 的逐位重导（同一链锚序列输入）。
#[must_use]
pub fn deck_chain_digest(anchors: &[[u8; 32]]) -> Option<[u8; 32]> {
    if anchors.is_empty() || anchors.len() > DECK_CHAIN_MAX {
        return None;
    }
    let mut material = Vec::with_capacity(
        DECK_CHAIN_DIGEST_DOMAIN.len() + DECK_CHAIN_FOLD_LABEL.len() + anchors.len() * 32,
    );
    material.extend_from_slice(DECK_CHAIN_DIGEST_DOMAIN);
    material.extend_from_slice(DECK_CHAIN_FOLD_LABEL);
    for anchor in anchors {
        material.extend_from_slice(anchor);
    }
    Some(poseidon_bytes_digest(&material))
}

/// 上游 `poseidon_bytes_digest` 的逐字节复制（`poseidon_over_bytes` 门面）：
/// `u64` 长度前缀 felt + 31 字节大端分块 + `poseidon_hash_many`，输出
/// 32 字节大端。分块 ≤ 31 字节 < 2^248 < 域模数，`from_bytes_be` 不可失败。
fn poseidon_bytes_digest(bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(bytes.len() / 31 + 2);
    input.push(FieldElement::from(bytes.len() as u64));
    for chunk in bytes.chunks(31) {
        let mut buf = [0u8; 32];
        buf[32 - chunk.len()..].copy_from_slice(chunk);
        input.push(
            FieldElement::from_bytes_be(&buf)
                .expect("31-byte big-endian chunk is below the field modulus"),
        );
    }
    poseidon_hash_many(&input).to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// golden 向量 1：单元素链（betting 段批，pre.deck == post.deck）。
    /// 十六进制值自上游栈钉扎：与 `poker_texas_air::canonical_shuffle_chain`
    /// 的 `fold_chain(b"deck-chain", [anchor])`（经上游 poseidon 原语）输出
    /// 逐位一致，并由 poker-appchain-texasair 两侧对照测试对真实
    /// `ShuffleChainReceipt.deck_chain_digest` 复核。
    #[test]
    fn golden_single_anchor() {
        let anchors = [[2u8; 32]];
        assert_eq!(
            hex_of(&deck_chain_digest(&anchors).unwrap()),
            "02d643c09cc738ff14b7492d02ed9240d99638dc41da8e624b2166fb0a263a36",
        );
    }

    /// golden 向量 2：双元素链（批内含洗牌段，pre.deck ≠ post.deck）。
    #[test]
    fn golden_two_anchors() {
        let anchors = [[2u8; 32], [3u8; 32]];
        assert_eq!(
            hex_of(&deck_chain_digest(&anchors).unwrap()),
            "030422d4aff9206f9cb01327d07be9d395059a61345528059e3c45609c8a71c2",
        );
    }

    /// golden 向量 3：上限链（10 槽 = 上游 MAX_DECK_COMMITMENTS 预算内）。
    #[test]
    fn golden_max_length_chain() {
        let anchors = [[0xAAu8; 32]; DECK_CHAIN_MAX];
        assert_eq!(
            hex_of(&deck_chain_digest(&anchors).unwrap()),
            "07a1bd0bd5e5562db26a799674fd010558dbbb64a0348b58a3db249217948eb3",
        );
    }

    /// fail-closed：空链与超长链必须显式拒绝（不得静默折叠）。
    #[test]
    fn empty_and_overlong_chains_rejected() {
        assert!(deck_chain_digest(&[]).is_none(), "empty chain must be None");
        let overlong = [[0u8; 32]; DECK_CHAIN_MAX + 1];
        assert!(
            deck_chain_digest(&overlong).is_none(),
            "chain beyond MAX_DECK_COMMITMENTS budget must be None"
        );
    }

    /// 链序敏感 + 域分离：换序/换域必须改变摘要。
    #[test]
    fn order_and_domain_sensitivity() {
        let a = deck_chain_digest(&[[2u8; 32], [3u8; 32]]).unwrap();
        let b = deck_chain_digest(&[[3u8; 32], [2u8; 32]]).unwrap();
        assert_ne!(hex_of(&a), hex_of(&b), "chain order must be binding");
        // 任一锚变化 → 摘要变化（deck 锚断裂可检测的密码学前提）
        let mut tampered = [[2u8; 32], [3u8; 32]];
        tampered[1][0] ^= 0x01;
        assert_ne!(a, deck_chain_digest(&tampered).unwrap());
        // 域标签 = 上游 stage0 域（逐字节）；折叠标签同源
        assert_eq!(DECK_CHAIN_DIGEST_DOMAIN, b"zchain.texas.canonical-shuffle-chain.v1");
        assert_eq!(DECK_CHAIN_FOLD_LABEL, b"deck-chain");
    }

    fn hex_of(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
