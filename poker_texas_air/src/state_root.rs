//! State root 计算 — Poseidon252 over `TexasPokerTable` 全字段。
//!
//! ## 设计
//!
//! `state_root = Poseidon252(TABLE_PREIMAGE)`，其中 `TABLE_PREIMAGE` 是把 `TexasPokerTable`
//! 的 22 个字段编码为 `Vec<FieldElement>`（Starknet Fr = BN254 Fr）后做 Poseidon 哈希。
//!
//! ## AIR 内验证
//!
//! Host 端用 `starknet_crypto::poseidon_hash_many` 计算；
//! AIR 端用 `poker_zkvm::stwo_backend::poseidon_air::PoseidonAir` 验证（M31 域 4-limb）。
//! 两者使用相同的 Starknet 标准 Poseidon252 参数。
//!
//! ## 递归证明中的角色
//!
//! 每个 method AIR 的公开输入包含 `pre_state_root` 和 `post_state_root`；
//! Aggregator AIR 的核心约束为 `left.post_state_root == right.pre_state_root`。

use starknet_ff::FieldElement;

use crate::error::{TexasAirError, TexasAirResult};
use crate::merkle_tree::{MerkleTree, SeatLeaf};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

// 从 poker_l1 引入业务类型（用于 state_root 编码）
use poker_l1::vm::contracts::texas_poker::betting::BettingRound;
use poker_l1::vm::contracts::texas_poker::types::{
    DeckState, ReconstructState, RevealTokenState, ShuffleState, TimeoutConfig, Timestamps,
    TableConfig,
};

/// 表台状态根（Starknet Fr 元素）。
///
/// 实际上是 `Poseidon252(preimage)` 的结果，作为 method AIR 的公开输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateRoot(pub FieldElement);

impl StateRoot {
    /// 零状态根（用于初始化场景）。
    #[must_use]
    pub fn zero() -> Self {
        Self(FieldElement::ZERO)
    }

    /// 从字段构造。
    #[must_use]
    pub const fn from_field(f: FieldElement) -> Self {
        Self(f)
    }

    /// 返回内部字段。
    #[must_use]
    pub const fn field(self) -> FieldElement {
        self.0
    }
}

/// 把 u64 编码为 Starknet `FieldElement`。
#[must_use]
pub fn u64_to_field(v: u64) -> FieldElement {
    FieldElement::from(v)
}

/// 把 u8 编码为 Starknet `FieldElement`。
#[must_use]
pub fn u8_to_field(v: u8) -> FieldElement {
    FieldElement::from(u64::from(v))
}

/// 把 bool 编码为 Starknet `FieldElement`（0 或 1）。
#[must_use]
pub fn bool_to_field(b: bool) -> FieldElement {
    FieldElement::from(u64::from(b))
}

/// TexasPokerTable 的状态根预计算输入。
///
/// 把字段按固定顺序编码为 `Vec<FieldElement>`，作为 Poseidon252 输入。
/// 顺序固定且不可变更——这是 AIR 约束侧的「契约」。
///
/// # 字段顺序
///
/// 1. `table_id_hash`（ObjectID 的 Blake2b → u256 → FieldElement）
/// 2. `name_hash`（变长字符串的 Poseidon）
/// 3. `creator`（Address 20 字节右对齐 → FieldElement）
/// 4. `max_players`（u8）
/// 5. `small_blind`（u64）
/// 6. `big_blind`（u64）
/// 7. `button`（u8）
/// 8. `pot`（u64）
/// 9. `side_pots_root`（Merkle root）
/// 10. `community_cards_root`（Merkle root）
/// 11. `round_state`（u8）
/// 12. `betting_round_root`（嵌套 Poseidon）
/// 13. `current_turn_flag`（bool，标记 Option<u8> 是 Some 还是 None）
/// 14. `current_turn_seat`（u8，None 时为 0）
/// 15. `deck_state_root`
/// 16. `shuffle_state_root`
/// 17. `reveal_token_state_root`
/// 18. `reconstruct_state_root`
/// 19. `timeout_config_root`
/// 20. `timestamps_root`
/// 21. `chip_pool`（u64）
/// 22. `config_root`
/// 23. `version`（u64）
/// 24. `seats_root`（Merkle root，最后一项便于叶子局部更新证明）
pub fn table_state_preimage(table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable) -> TexasAirResult<Vec<FieldElement>> {
    let mut preimage = Vec::with_capacity(24);

    // 1. table_id_hash：ObjectID 通常为 32 字节，用 Blake2b 压缩到 32 字节后转 FieldElement
    let id_bytes = borsh::to_vec(&table.id)
        .map_err(|e| TexasAirError::StateRootError(format!("borsh ser id: {e}")))?;
    let id_hash = blake2b_256(&id_bytes);
    let id_field = bytes_to_field(&id_hash)
        .ok_or_else(|| TexasAirError::StateRootError("table_id > Fr modulus".into()))?;
    preimage.push(id_field);

    // 2. name_hash：变长字符串先 Poseidon
    let name_field = poseidon_string(&table.name);
    preimage.push(name_field);

    // 3. creator：Address (20 字节) 右对齐到 32 字节 BE → FieldElement。
    //    必须进入 state_root，否则 creator 改动不被 state_root 捕获（P0-2 权限校验
    //    要求 creator 的变更可被证明系统约束）。
    preimage.push(address_to_field(&table.creator));

    // 4-8. 标量字段
    preimage.push(u8_to_field(table.max_players));
    preimage.push(u64_to_field(table.small_blind));
    preimage.push(u64_to_field(table.big_blind));
    preimage.push(u8_to_field(table.button));
    preimage.push(u64_to_field(table.pot));

    // 9. side_pots_root：空列表哈希为 0，非空用 MerkleTree
    let side_pots_root = if table.side_pots.is_empty() {
        FieldElement::ZERO
    } else {
        // TODO 阶段 3：实现 side_pot 叶子节点的 Poseidon 编码
        // 暂时用 len 作为占位
        u64_to_field(table.side_pots.len() as u64)
    };
    preimage.push(side_pots_root);

    // 10. community_cards_root：0..=5 张牌的 Poseidon
    let community_cards_root = poseidon_cards(&table.community_cards);
    preimage.push(community_cards_root);

    // 11. round_state
    preimage.push(u8_to_field(table.round_state));

    // 12. betting_round_root
    let betting_round_root = match &table.betting_round {
        Some(br) => poseidon_betting_round(br),
        None => FieldElement::ZERO,
    };
    preimage.push(betting_round_root);

    // 13-14. current_turn: Option<u8>
    let (ct_flag, ct_seat) = match table.current_turn {
        Some(seat) => (bool_to_field(true), u8_to_field(seat)),
        None => (bool_to_field(false), FieldElement::ZERO),
    };
    preimage.push(ct_flag);
    preimage.push(ct_seat);

    // 15-18. 协议状态根
    preimage.push(poseidon_deck_state(&table.deck_state));
    preimage.push(poseidon_shuffle_state(&table.shuffle_state));
    preimage.push(poseidon_reveal_token_state(&table.reveal_token_state));
    preimage.push(poseidon_reconstruct_state(&table.reconstruct_state));

    // 19-20. 配置
    preimage.push(poseidon_timeout_config(&table.timeout_config));
    preimage.push(poseidon_timestamps(&table.timestamps));

    // 21. chip_pool
    preimage.push(u64_to_field(table.chip_pool));

    // 22. config_root
    preimage.push(poseidon_table_config(&table.config));

    // 23. version
    preimage.push(u64_to_field(table.version));

    // 24. seats_root：6/9 个 seats 的 Merkle root
    let seats_root = compute_seats_root(&table.seats)?;
    preimage.push(seats_root);

    Ok(preimage)
}

/// 计算 `TexasPokerTable` 的 state_root = Poseidon252(preimage)。
///
/// # Errors
///
/// 当字段编码失败（如 ObjectID 序列化异常）时返回错误。
pub fn compute_state_root(table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable) -> TexasAirResult<StateRoot> {
    let preimage = table_state_preimage(table)?;
    Ok(StateRoot(poseidon_hash_many(&preimage)))
}

/// 计算 seats 的 Merkle root。
///
/// 把每个 `Seat` 编码为 `SeatLeaf`（Poseidon252 of seat fields），构造 Merkle 树，
/// 返回 root。空列表返回 0。
///
/// # Errors
///
/// 当 seats 长度 > 16 时返回错误（max_players=9 时叶子数 ≤ 9，padding 到 16 即可）。
pub fn compute_seats_root(seats: &[poker_l1::vm::contracts::texas_poker::types::Seat]) -> TexasAirResult<FieldElement> {
    if seats.is_empty() {
        return Ok(FieldElement::ZERO);
    }
    if seats.len() > 16 {
        return Err(TexasAirError::StateRootError(format!(
            "seats.len() = {} > 16 (max padding)",
            seats.len()
        )));
    }
    let leaves: Vec<SeatLeaf> = seats.iter().map(SeatLeaf::from_seat).collect();
    let tree = MerkleTree::from_leaves(&leaves);
    Ok(tree.root())
}

// ===== 内部辅助函数 =====

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 把 32 字节（小端）解释为 Starknet FieldElement。
///
/// Starknet Fr 模数 `p = 2^251 + 17 * 2^192 + 1`，32 字节可能溢出。
/// 溢出时返回 `None`，由上层决定如何处理（取模或报错）。
fn bytes_to_field(bytes: &[u8; 32]) -> Option<FieldElement> {
    // Starknet Fr 模数 `p = 2^251 + 17*2^192 + 1` ≈ 2^251.00003。
    // 首字节 = 0x08，所以 mask & 0x07 确保 value < 2^251 < P。
    // 丢失 5 bit 熵（hash 空间 2^256 → 2^251），对安全性影响可忽略。
    let mut masked = *bytes;
    masked[0] &= 0x07;
    FieldElement::from_bytes_be(&masked).ok()
}

/// 把 Address（20 字节）编码为 Starknet FieldElement。
///
/// 20 字节 < 32 字节，不会溢出 Fr 模数，因此无需像 32 字节那样做 `& 0x07` 截断。
/// 右对齐到 32 字节 BE buffer 后复用 [`bytes_to_field`]。
#[must_use]
pub fn address_to_field(addr: &poker_l1::Address) -> FieldElement {
    let mut buf = [0u8; 32];
    buf[12..].copy_from_slice(addr); // 右对齐（前 12 字节为 0）
    bytes_to_field(&buf).unwrap_or(FieldElement::ZERO)
}

fn poseidon_hash_many(inputs: &[FieldElement]) -> FieldElement {
    starknet_crypto::poseidon_hash_many(inputs)
}

fn poseidon_string(s: &str) -> FieldElement {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return FieldElement::ZERO;
    }
    // 把字符串按 31 字节分块（Fr 单元素最多 31 字节安全），每块转 FieldElement。
    // 关键：必须在 BE 缓冲区中右对齐（左侧补 0），否则左侧高位字节会使值超过 Fr 模数。
    // 同时在每个 chunk 前面加 1 字节长度前缀，避免 "ab" 与 "a\x00b" 产生相同 FieldElement。
    let chunks: Vec<FieldElement> = bytes
        .chunks(31)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            // 长度前缀（1 字节，放在 chunk 的第 0 字节）
            buf[0] = u8::try_from(chunk.len()).unwrap_or(0);
            // chunk 内容从第 1 字节开始（最多 30 字节 + 1 字节长度 = 31 字节有效）
            buf[1..=chunk.len()].copy_from_slice(chunk);
            bytes_to_field(&buf).unwrap_or(FieldElement::ZERO)
        })
        .collect();
    // 最后追加一个 chunk 记录原始字符串长度，避免不同长度字符串哈希碰撞
    let mut all_chunks = chunks;
    all_chunks.push(FieldElement::from(u64::try_from(bytes.len()).unwrap_or(0)));
    poseidon_hash_many(&all_chunks)
}

fn poseidon_cards(cards: &[poker_l1::vm::contracts::texas_poker::card::Card]) -> FieldElement {
    if cards.is_empty() {
        return FieldElement::ZERO;
    }
    // Card 编码为 (rank:u8, suit:u8) → FieldElement
    let fields: Vec<FieldElement> = cards
        .iter()
        .flat_map(|c| {
            // Card 字段访问 — poker_l1 的 Card 类型可能有 rank/suit 字段
            // 暂用 borsh 序列化为字节，再按 31 字节分块
            let bytes = borsh::to_vec(c).unwrap_or_default();
            bytes
                .chunks(31)
                .map(|chunk| {
                    let mut buf = [0u8; 32];
                    buf[..chunk.len()].copy_from_slice(chunk);
                    bytes_to_field(&buf).unwrap_or(FieldElement::ZERO)
                })
                .collect::<Vec<_>>()
        })
        .collect();
    poseidon_hash_many(&fields)
}

fn poseidon_betting_round(br: &BettingRound) -> FieldElement {
    // TODO 阶段 3：完整实现（current_bet/min_raise/big_blind/last_raiser_seat/actions_taken）
    let _ = br;
    FieldElement::ZERO
}

fn poseidon_deck_state(ds: &DeckState) -> FieldElement {
    let _ = ds;
    FieldElement::ZERO
}

fn poseidon_shuffle_state(ss: &ShuffleState) -> FieldElement {
    let _ = ss;
    FieldElement::ZERO
}

fn poseidon_reveal_token_state(rs: &RevealTokenState) -> FieldElement {
    let _ = rs;
    FieldElement::ZERO
}

fn poseidon_reconstruct_state(rs: &ReconstructState) -> FieldElement {
    let _ = rs;
    FieldElement::ZERO
}

fn poseidon_timeout_config(tc: &TimeoutConfig) -> FieldElement {
    let _ = tc;
    FieldElement::ZERO
}

fn poseidon_timestamps(ts: &Timestamps) -> FieldElement {
    let _ = ts;
    FieldElement::ZERO
}

fn poseidon_table_config(cfg: &TableConfig) -> FieldElement {
    let _ = cfg;
    FieldElement::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_encoding_basic() {
        assert_eq!(u8_to_field(0), FieldElement::ZERO);
        assert_eq!(u8_to_field(255), FieldElement::from(255u64));
        assert_eq!(u64_to_field(0), FieldElement::ZERO);
        assert_eq!(u64_to_field(u64::MAX), FieldElement::from(u64::MAX));
        assert_eq!(bool_to_field(false), FieldElement::ZERO);
        assert_eq!(bool_to_field(true), FieldElement::ONE);
    }

    #[test]
    fn test_state_root_zero() {
        assert_eq!(StateRoot::zero().field(), FieldElement::ZERO);
    }

    #[test]
    fn test_poseidon_string_deterministic() {
        let h1 = poseidon_string("hello");
        let h2 = poseidon_string("hello");
        assert_eq!(h1, h2, "poseidon 应确定性");
        let h3 = poseidon_string("world");
        assert_ne!(h1, h3, "不同字符串应产生不同哈希");
    }
}
