//! Mental Poker 客户端 —— 链下生成完整的 crypto proof。
//!
//! 为 `proving_service` 的完整牌局驱动器（[`crate::full_hand::FullHandRunner`]）提供
//! `submit_shuffle_v2` 与 `submit_player_reveal_tokens` 两个 crypto dispatch 所需的
//! 合法密文与零知识证明。
//!
//! # 关键设计
//!
//! - **transcript 必须与合约 verify 端一致**：`poker_l1` 合约（`state_machine.rs` /
//!   `utils.rs`）对所有 crypto 证明验证都用 `MerlinTranscript`（STROBE/Keccak），
//!   而非 `z_poker` 辅助类默认使用的 `FiatShamirTranscript`（面向 Move 合约）。
//!   因此本驱动一律用 `MerlinTranscript::new(label)`，与合约逐字节对齐。
//! - **牌组变换链下精确复现**：合约 `submit_shuffle_v2` 验证 shuffle proof 时用的是
//!   玩家提交的原始 `output_cards`，但存储进 `deck_state.encrypted` 的是
//!   `add_pk_to_c2(output_cards)`（每张 `c2 += player_pk`，`c1` 不变）。后续 reveal
//!   token 的 proof 绑定的是**变换后**的密文，故本驱动维护 `deck_view` 与合约同步。
//! - **所有 card 的 `c1 == G`**（generator）全程不变（初始 deck 是 `(G, plaintext)`，
//!   re_encrypt 仅加 `G·r` 到 c1 与 `pk·r` 到 c2，add_pk_to_c2 只动 c2）。
//!   因此 `reveal_token = c1 · sk = G · sk = pk`。
//! - **aggregated_pk 全程为 None**：玩家经 `join_table` 入座（不设 aggregated_pk），
//!   shuffle proof 绑定的 `pk` 为 identity 点（`add_pk_to_aggregated(None) == None`，
//!   合约 fallback 到 `G1Projective::identity()`）。

use blstrs::G1Projective;
use group::Group;
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};

use poker_protocol::crypto::{DefaultCurve, ElGamalCiphertext, Scalar, curve::CurveScalar};
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::transcript_ext::{
    CryptoTranscript, FiatShamirTranscript, MerlinTranscript,
};

use crate::CryptoDriverError;

/// shuffle proof 的 transcript label —— 必须与合约
/// `utils::new_shuffle_transcript()`（`b"zk_shuffle_proof_v2"`）一致。
const SHUFFLE_PROOF_LABEL: &[u8] = b"zk_shuffle_proof_v2";
/// reveal token proof 的 transcript label —— 必须与合约
/// `state_machine.rs` 中 `MerlinTranscript::new(b"reveal_token_proof_v3")` 一致。
const REVEAL_TOKEN_PROOF_LABEL: &[u8] = b"reveal_token_proof_v3";

/// 一个 shuffle 参与者：持有 (sk, pk=G·sk)。
#[derive(Clone)]
pub struct ShufflePlayer {
    /// 私钥。
    pub sk: Scalar,
    /// 公钥（= generator · sk）。
    pub pk: G1Projective,
}

impl ShufflePlayer {
    /// 用确定性 RNG 生成一个玩家（便于复现）。
    pub fn deterministic(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        Self::random(&mut rng)
    }

    /// 用给定 RNG 生成一个玩家。
    pub fn random(rng: &mut StdRng) -> Self {
        let sk = Scalar::random(rng);
        let pk = G1Projective::generator() * sk;
        Self { sk, pk }
    }
}

/// `submit_shuffle_v2` 一步的产出：提交给合约的密文 + proof。
pub struct ShuffleV2Step {
    /// 玩家洗牌后的输出牌组（proof 覆盖的对象；合约会在此基础上做 `add_pk_to_c2`）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// 生产版本化 shuffle proof（当前生成 Bayer--Groth V2）。
    pub shuffle_proof: ShuffleProof,
}

/// 生成 `submit_shuffle_v2` 所需的 output_cards + shuffle proof。
///
/// 参数：
/// - `input_cards`：当前牌组（= 合约 `deck_state.encrypted`，即上一步变换后的 deck）。
/// - `player_sk`：当前洗牌玩家的私钥（用于 re_encrypt 的随机性不依赖它，但保留接口一致性）。
/// - `player_pk`：当前洗牌玩家的公钥——合约 `add_pk_to_c2` 会把它加到每张 c2。
/// - `aggregated_pk`：shuffle proof 绑定的共享公钥；必须等于桌台 contributor mask 与
///   seat public keys 派生的非 identity aggregate cache。
/// - `seed`：确定性 RNG 种子（便于复现）。
///
/// # Errors
///
/// shuffle prove 失败（如输入含 identity c2 —— 不会发生在 canonical plaintext deck 上）
/// 时返回错误。
///
/// # Panics
///
/// 理论上不 panic（输入保证 52 张非 identity c2）。
pub fn build_shuffle_v2(
    input_cards: &[ElGamalCiphertext],
    _player_sk: &Scalar,
    _player_pk: &G1Projective,
    aggregated_pk: &G1Projective,
    seed: u64,
) -> Result<ShuffleV2Step, CryptoDriverError> {
    let mut rng = StdRng::seed_from_u64(seed);
    let n = input_cards.len();

    // 随机双射 permute（玩家自定义洗牌顺序）
    let mut permute: Vec<usize> = (0..n).collect();
    permute.shuffle(&mut rng);

    // 对每张牌 re_encrypt：output[j] = input[permute[j]].re_encrypt(agg_pk, r_j)
    // re_encrypt: c1' = c1 + G·r, c2' = c2 + pk·r（见 curve.rs::re_encrypt）。
    // 这里 pk = aggregated_pk = identity，故 c2 不变；c1 += G·r。
    // 注意：合约 verify 用的是这里的 output_cards（原始），存储时再 add_pk_to_c2。
    let r_values: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let output_cards: Vec<ElGamalCiphertext> = (0..n)
        .map(|j| input_cards[permute[j]].re_encrypt(aggregated_pk, &r_values[j]))
        .collect();

    // 生产证明必须使用版本化入口；Legacy V1 已被 verifier 永久 fail-closed。
    let mut transcript = FiatShamirTranscript::new(SHUFFLE_PROOF_LABEL);
    let shuffle_proof = ShuffleProof::prove(
        input_cards,
        &output_cards,
        &permute,
        &r_values,
        aggregated_pk,
        &mut rng,
        &mut transcript,
    )
    .map_err(|e| CryptoDriverError::ShuffleProve(e.to_string()))?;

    Ok(ShuffleV2Step {
        output_cards,
        shuffle_proof,
    })
}

/// 链下复现合约 `add_pk_to_c2`：把玩家 pk 加到每张 c2，c1 不变。
///
/// `submit_shuffle_v2` dispatch 后必须对 `deck_view` 调用此函数，使其与合约
/// `deck_state.encrypted` 保持一致，否则后续 reveal token proof 会绑定错误密文。
pub fn apply_add_pk_to_c2(deck: &mut [ElGamalCiphertext], player_pk: &G1Projective) {
    for ct in deck.iter_mut() {
        ct.c2 = ct.c2 + *player_pk;
    }
}

/// `submit_player_reveal_tokens` 一张牌的产出：reveal token + proof。
pub struct RevealTokenStep {
    /// 揭牌令牌（= c1 · sk = G · sk = pk，因 c1 == G）。
    pub reveal_token: G1Projective,
    /// 揭牌 proof（绑定 `encrypted_card` 与玩家 pk）。
    pub proof: RevealTokenProof<DefaultCurve>,
}

/// 为一张牌生成 reveal token + proof。
///
/// 参数：
/// - `player`：提交者（reveal token = c1 · sk）。
/// - `encrypted_card`：**变换后**的牌密文（即 `deck_view[card_index]`，与合约 verify
///   端读取的 `deck_state.encrypted[card_index]` 一致）。
/// - `seed`：确定性 RNG 种子。
pub fn build_reveal_token(
    player: &ShufflePlayer,
    encrypted_card: &ElGamalCiphertext,
    seed: u64,
) -> RevealTokenStep {
    let mut rng = StdRng::seed_from_u64(seed);
    // reveal_token = c1 · sk = G · sk = pk（c1 全程为 G）。
    let reveal_token = encrypted_card.c1 * player.sk;
    let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
    let proof = RevealTokenProof::<DefaultCurve>::prove(
        &player.sk,
        &player.pk,
        encrypted_card,
        &reveal_token,
        &mut rng,
        &mut transcript,
    );
    RevealTokenStep {
        reveal_token,
        proof,
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 shuffle proof 的 prove→verify 自洽（用与合约相同的 MerlinTranscript）。
    /// 这是 crypto_driver 正确性的核心保证：生成的 shuffle_proof 能被合约 verify 接受。
    #[test]
    fn shuffle_v2_proof_verify_roundtrip() {
        let g = G1Projective::generator();
        let deck: Vec<ElGamalCiphertext> = (0..52)
            .map(|i| ElGamalCiphertext {
                c1: g,
                c2: g * Scalar::from_u64(i as u64 + 1),
            })
            .collect();
        let agg_pk = g * Scalar::from_u64(12345);
        let player = ShufflePlayer::deterministic(1);
        let step =
            build_shuffle_v2(&deck, &player.sk, &player.pk, &agg_pk, 42).expect("prove 成功");
        let mut t = FiatShamirTranscript::new(b"zk_shuffle_proof_v2");
        let r = step
            .shuffle_proof
            .verify(&deck, &step.output_cards, &agg_pk, &mut t);
        assert!(r.is_ok(), "verify 应成功: {r:?}");
    }

    /// 验证 `build_shuffle_v2` 在 canonical 初始 deck 上能成功生成 proof。
    #[test]
    fn shuffle_v2_proof_generates_on_canonical_deck() {
        let g = G1Projective::generator();
        let deck: Vec<ElGamalCiphertext> = (0..52)
            .map(|i| ElGamalCiphertext {
                c1: g,
                c2: g * Scalar::from_u64(i as u64 + 1),
            })
            .collect();
        // shuffle proof 的广义 Schnorr 把 aggregated_pk 作为基点，禁止 identity，
        // 故必须用非 identity pk（真实对局里 aggregated_pk = Σ player pk）。
        let agg_pk = g * Scalar::from_u64(999);
        let player = ShufflePlayer::deterministic(1);
        let step =
            build_shuffle_v2(&deck, &player.sk, &player.pk, &agg_pk, 42).expect("prove 成功");
        assert_eq!(step.output_cards.len(), 52);
    }

    /// 验证 `build_reveal_token`：token 应等于玩家 pk（因 c1 == G）。
    #[test]
    fn reveal_token_equals_player_pk_when_c1_is_generator() {
        let player = ShufflePlayer::deterministic(7);
        let g = G1Projective::generator();
        let ct = ElGamalCiphertext {
            c1: g,
            c2: g * Scalar::from_u64(3),
        };
        let step = build_reveal_token(&player, &ct, 99);
        assert_eq!(step.reveal_token, player.pk);
    }

    /// 验证 `apply_add_pk_to_c2`：c2 += pk，c1 不变。
    #[test]
    fn add_pk_to_c2_preserves_c1_adds_pk_to_c2() {
        let g = G1Projective::generator();
        let pk = G1Projective::generator() * Scalar::from_u64(5);
        let mut deck = vec![
            ElGamalCiphertext {
                c1: g,
                c2: g * Scalar::from_u64(2),
            },
            ElGamalCiphertext {
                c1: g,
                c2: g * Scalar::from_u64(3),
            },
        ];
        let original_c1: Vec<_> = deck.iter().map(|c| c.c1).collect();
        let expected_c2: Vec<_> = deck.iter().map(|c| c.c2 + pk).collect();
        apply_add_pk_to_c2(&mut deck, &pk);
        for (i, ct) in deck.iter().enumerate() {
            assert_eq!(ct.c1, original_c1[i], "c1 不应变");
            assert_eq!(ct.c2, expected_c2[i], "c2 应 += pk");
        }
    }
}
