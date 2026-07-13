//! Poker proofs 集成测试（Phase M — M-9/M-13）。
//!
//! 跨模块端到端验证各 proof 类型协同工作，以及字节级 API 可被外部调用。
//!
//! # 测试覆盖
//!
//! - `test_remask_then_leave_roundtrip` — Remask → Leave 恢复原始密文
//! - `test_reconstruct_full_deck` — 完整 ReconstructProof 端到端
//! - `test_all_proofs_byte_level` — 所有 proof 类型的字节级 verify API
//! - `test_reveal_token_proof_roundtrip` — RevealTokenProof 端到端 + 字节级 API
//! - `test_shuffle_proof_roundtrip` — ZKShuffleProof 端到端 + 字节级 API

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use ark_std::{rand::Rng, test_rng};

use poker_zkvm::precompiles::chaum_pedersen::{
    ChaumPedersenDLEQProof, chaum_pedersen_verify_bytes,
};
use poker_zkvm::precompiles::elgamal::{
    ElGamalCiphertext, ElGamalPublicKey, card_to_point, encrypt, keygen_from_secret, reencrypt,
};
use poker_zkvm::precompiles::generalized_schnorr::{
    GeneralizedSchnorrProof, generalized_schnorr_verify_bytes,
};
use poker_zkvm::precompiles::poker_transcript::{PokerTranscript, g1_to_64bytes};
use poker_zkvm::precompiles::reconstruction::{
    ReconstructProof, reconstruct_deck, reconstruct_verify_bytes,
};
use poker_zkvm::precompiles::remask_leave::{
    DleqDirection, PerCardDleqProof, per_card_dleq_verify_bytes,
};
use poker_zkvm::precompiles::reveal_token::{
    REVEAL_TOKEN_PROOF_LABEL, RevealTokenAndProof, reveal_token_verify_bytes,
};
use poker_zkvm::precompiles::shuffle_proof::{
    SHUFFLE_PROOF_LABEL, ZKShuffleProof, shuffle_verify_bytes,
};

// ===== 辅助函数 =====

/// Remask 操作：output.c = input.c (不变)，output.d = input.d + input.c * sk。
///
/// 这是 DLEq 兼容的 remask（c1 不变性，仅修改 d）。
fn remask_cts(cts: &[ElGamalCiphertext], sk: &Fr) -> Vec<ElGamalCiphertext> {
    cts.iter()
        .map(|ct| {
            let mask = G1Projective::from(ct.c) * sk;
            ElGamalCiphertext {
                c: ct.c,
                d: (G1Projective::from(ct.d) + mask).into_affine(),
            }
        })
        .collect()
}

/// Leave 操作：output.c = input.c (不变)，output.d = input.d - input.c * sk。
///
/// Leave 是 Remask 的逆操作：Leave(Rmask(x, sk), sk) == x。
fn leave_cts(cts: &[ElGamalCiphertext], sk: &Fr) -> Vec<ElGamalCiphertext> {
    cts.iter()
        .map(|ct| {
            let mask = G1Projective::from(ct.c) * sk;
            ElGamalCiphertext {
                c: ct.c,
                d: (G1Projective::from(ct.d) - mask).into_affine(),
            }
        })
        .collect()
}

/// 构造 n 张牌的 ElGamal 密文（card_id 1..=n）。
fn make_ciphertexts(n: usize, rng: &mut impl Rng) -> (Fr, G1Affine, Vec<ElGamalCiphertext>) {
    let sk = Fr::rand(rng);
    let pk = keygen_from_secret(&sk);
    let cts: Vec<ElGamalCiphertext> = (0..n)
        .map(|i| {
            let card = card_to_point((i as u8) + 1);
            let r = Fr::rand(rng);
            encrypt(&pk, &card, &r)
        })
        .collect();
    (sk, pk.pk, cts)
}

/// 将 ElGamalCiphertext 列表序列化为字节（每张 128 字节：c[64] || d[64]）。
fn cts_to_bytes(cts: &[ElGamalCiphertext]) -> Vec<u8> {
    cts.iter()
        .flat_map(|ct| {
            let mut v = g1_to_64bytes(&ct.c).to_vec();
            v.extend_from_slice(&g1_to_64bytes(&ct.d));
            v
        })
        .collect()
}

// ===== 测试 1：Remask → Leave 往返 =====

#[test]
fn test_remask_then_leave_roundtrip() {
    let mut rng = test_rng();
    let n = 52;
    let (sk, pk, original_cts) = make_ciphertexts(n, &mut rng);

    // 步骤一：Remask 所有牌
    let remasked_cts = remask_cts(&original_cts, &sk);

    // 验证 Remask 后 c 不变，d 变化
    for i in 0..n {
        assert_eq!(remasked_cts[i].c, original_cts[i].c, "Remask 后 c 应不变");
        assert_ne!(remasked_cts[i].d, original_cts[i].d, "Remask 后 d 应变化");
    }

    // 生成 Remask proof 并验证
    let mut ts_prove = PokerTranscript::new(b"integration_remask");
    let remask_proof = PerCardDleqProof::prove(
        &original_cts,
        &remasked_cts,
        &sk,
        &pk,
        DleqDirection::Remask,
        &mut ts_prove,
        &mut rng,
    )
    .expect("Remask prove should succeed");

    let mut ts_verify = PokerTranscript::new(b"integration_remask");
    assert!(
        remask_proof.verify(&original_cts, &remasked_cts, &pk, &mut ts_verify),
        "Remask proof 验证应通过"
    );

    // 步骤二：Leave 恢复原始密文
    let leave_cts = leave_cts(&remasked_cts, &sk);

    // 验证 Leave 后恢复原始密文
    for i in 0..n {
        assert_eq!(leave_cts[i].c, original_cts[i].c, "Leave 后 c 应不变");
        assert_eq!(leave_cts[i].d, original_cts[i].d, "Leave 后 d 应恢复原始值");
    }

    // 生成 Leave proof 并验证
    let mut ts_prove2 = PokerTranscript::new(b"integration_leave");
    let leave_proof = PerCardDleqProof::prove(
        &remasked_cts,
        &leave_cts,
        &sk,
        &pk,
        DleqDirection::Leave,
        &mut ts_prove2,
        &mut rng,
    )
    .expect("Leave prove should succeed");

    let mut ts_verify2 = PokerTranscript::new(b"integration_leave");
    assert!(
        leave_proof.verify(&remasked_cts, &leave_cts, &pk, &mut ts_verify2),
        "Leave proof 验证应通过"
    );
}

// ===== 测试 2：完整 ReconstructProof 端到端 =====

#[test]
fn test_reconstruct_full_deck() {
    let mut rng = test_rng();

    // 构造 52 张牌的明文点（card_id 1..=52，避免 card 0 = identity）
    let n_cards = 52;
    let n_user_readable = 3;
    let cards: Vec<G1Affine> = (0..n_cards).map(|i| card_to_point((i as u8) + 1)).collect();

    // 用户密钥
    let user_sk = Fr::rand(&mut rng);
    let user_pk = keygen_from_secret(&user_sk).pk;
    let user_pk_struct = ElGamalPublicKey { pk: user_pk };

    // 选前 n_user_readable 张牌作为用户可读牌，用 ElGamal 加密
    let user_readable_cards: Vec<ElGamalCiphertext> = (0..n_user_readable)
        .map(|i| {
            let card = cards[i];
            let r = Fr::rand(&mut rng);
            encrypt(&user_pk_struct, &card, &r)
        })
        .collect();

    // coefficient（非 0、非 1）
    let coefficient = Fr::from(7u64);

    // 调用 reconstruct_deck 生成 output_cards 和 swap_out_cards
    let (s_vec, output_cards, swap_out_cards) = reconstruct_deck(
        &cards,
        &user_readable_cards,
        &user_sk,
        &user_pk,
        &coefficient,
    )
    .expect("reconstruct_deck should succeed");

    assert_eq!(output_cards.len(), n_cards, "output_cards 数量应等于牌数");
    assert_eq!(
        swap_out_cards.len(),
        n_user_readable,
        "swap_out_cards 数量应等于用户可读牌数"
    );

    // 生成 ReconstructProof
    let mut ts_prove = PokerTranscript::new(b"integration_reconstruct");
    let proof = ReconstructProof::prove(
        &cards,
        &user_readable_cards,
        &output_cards,
        &swap_out_cards,
        &user_sk,
        &user_pk,
        &s_vec,
        &mut ts_prove,
        &mut rng,
    )
    .expect("ReconstructProof prove should succeed");

    // 验证 ReconstructProof
    let swap_out_only: Vec<ElGamalCiphertext> = swap_out_cards.iter().map(|(_, ct)| *ct).collect();
    let mut ts_verify = PokerTranscript::new(b"integration_reconstruct");
    assert!(
        proof.verify(
            &cards,
            &output_cards,
            &swap_out_only,
            &user_readable_cards,
            &user_pk,
            &mut ts_verify,
        ),
        "ReconstructProof 验证应通过"
    );

    // 验证序列化 roundtrip
    let proof_bytes = proof.to_bytes();
    let recovered = ReconstructProof::from_bytes(&proof_bytes).expect("from_bytes should succeed");
    let mut ts_verify2 = PokerTranscript::new(b"integration_reconstruct");
    assert!(
        recovered.verify(
            &cards,
            &output_cards,
            &swap_out_only,
            &user_readable_cards,
            &user_pk,
            &mut ts_verify2,
        ),
        "序列化恢复后的 proof 验证应通过"
    );
}

// ===== 测试 3：所有 proof 类型的字节级 verify API =====

#[test]
fn test_all_proofs_byte_level() {
    let mut rng = test_rng();

    // --- 1. ChaumPedersenDLEQProof 字节级验证 ---
    let g1 = G1Projective::generator().into_affine();
    let g2 = (G1Projective::generator() * Fr::from(3u64)).into_affine();
    let s = Fr::rand(&mut rng);
    let p1 = (G1Projective::from(g1) * s).into_affine();
    let p2 = (G1Projective::from(g2) * s).into_affine();

    let mut ts_cp = PokerTranscript::new(b"integration_cp");
    let cp_proof = ChaumPedersenDLEQProof::prove(&g1, &g2, &s, &p1, &p2, &mut ts_cp, &mut rng)
        .expect("CP prove should succeed");
    let cp_bytes = cp_proof.to_bytes();
    assert_eq!(cp_bytes.len(), 98, "ChaumPedersen proof 应为 98 字节");

    let g1_b = g1_to_64bytes(&g1);
    let g2_b = g1_to_64bytes(&g2);
    let p1_b = g1_to_64bytes(&p1);
    let p2_b = g1_to_64bytes(&p2);

    let mut ts_cp_v = PokerTranscript::new(b"integration_cp");
    assert!(
        chaum_pedersen_verify_bytes(&g1_b, &g2_b, &p1_b, &p2_b, &cp_bytes, &mut ts_cp_v),
        "ChaumPedersen 字节级验证应通过"
    );

    // 篡改 proof 字节应失败
    let mut tampered_cp = cp_bytes;
    tampered_cp[66] ^= 0x01;
    let mut ts_cp_t = PokerTranscript::new(b"integration_cp");
    assert!(
        !chaum_pedersen_verify_bytes(&g1_b, &g2_b, &p1_b, &p2_b, &tampered_cp, &mut ts_cp_t),
        "篡改后的 ChaumPedersen proof 应验证失败"
    );

    // --- 2. GeneralizedSchnorrProof 字节级验证 ---
    let base_points: Vec<G1Affine> = (0..3)
        .map(|i| (G1Projective::generator() * Fr::from((i as u64) + 2)).into_affine())
        .collect();
    let secrets: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
    let r_point: G1Projective =
        VariableBaseMSM::msm(&base_points, &secrets).unwrap_or(G1Projective::zero());
    let r_point = r_point.into_affine();

    let mut ts_gs = PokerTranscript::new(b"integration_gs");
    let gs_proof =
        GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts_gs, &mut rng)
            .expect("GS prove should succeed");
    let gs_bytes = gs_proof.to_bytes();

    let base_points_bytes: Vec<u8> = base_points.iter().flat_map(g1_to_64bytes).collect();
    let r_point_bytes = g1_to_64bytes(&r_point);

    let mut ts_gs_v = PokerTranscript::new(b"integration_gs");
    assert!(
        generalized_schnorr_verify_bytes(
            &base_points_bytes,
            &r_point_bytes,
            &gs_bytes,
            &mut ts_gs_v
        ),
        "GeneralizedSchnorr 字节级验证应通过"
    );

    // 篡改 proof 字节应失败
    let mut tampered_gs = gs_bytes;
    if !tampered_gs.is_empty() {
        tampered_gs[0] ^= 0x01;
    }
    let mut ts_gs_t = PokerTranscript::new(b"integration_gs");
    assert!(
        !generalized_schnorr_verify_bytes(
            &base_points_bytes,
            &r_point_bytes,
            &tampered_gs,
            &mut ts_gs_t
        ),
        "篡改后的 GeneralizedSchnorr proof 应验证失败"
    );

    // --- 3. PerCardDleqProof 字节级验证 ---
    let (dleq_sk, dleq_pk, dleq_input_cts) = make_ciphertexts(5, &mut rng);
    let dleq_output_cts = remask_cts(&dleq_input_cts, &dleq_sk);

    let mut ts_dleq = PokerTranscript::new(b"integration_dleq");
    let dleq_proof = PerCardDleqProof::prove(
        &dleq_input_cts,
        &dleq_output_cts,
        &dleq_sk,
        &dleq_pk,
        DleqDirection::Remask,
        &mut ts_dleq,
        &mut rng,
    )
    .expect("DLEq prove should succeed");
    let dleq_bytes = dleq_proof.to_bytes();

    let dleq_input_bytes = cts_to_bytes(&dleq_input_cts);
    let dleq_output_bytes = cts_to_bytes(&dleq_output_cts);
    let dleq_pk_bytes = g1_to_64bytes(&dleq_pk);

    let mut ts_dleq_v = PokerTranscript::new(b"integration_dleq");
    assert!(
        per_card_dleq_verify_bytes(
            &dleq_input_bytes,
            &dleq_output_bytes,
            &dleq_pk_bytes,
            &dleq_bytes,
            &mut ts_dleq_v,
        ),
        "PerCardDleq 字节级验证应通过"
    );

    // 篡改 proof 字节应失败
    let mut tampered_dleq = dleq_bytes;
    if tampered_dleq.len() > 3 {
        tampered_dleq[3] ^= 0x01;
    }
    let mut ts_dleq_t = PokerTranscript::new(b"integration_dleq");
    assert!(
        !per_card_dleq_verify_bytes(
            &dleq_input_bytes,
            &dleq_output_bytes,
            &dleq_pk_bytes,
            &tampered_dleq,
            &mut ts_dleq_t,
        ),
        "篡改后的 PerCardDleq proof 应验证失败"
    );

    // --- 4. ReconstructProof 字节级验证 ---
    let recon_cards: Vec<G1Affine> = (0..6).map(|i| card_to_point((i as u8) + 1)).collect();
    let recon_user_sk = Fr::rand(&mut rng);
    let recon_user_pk = keygen_from_secret(&recon_user_sk).pk;
    let recon_pk_struct = ElGamalPublicKey { pk: recon_user_pk };
    let recon_user_readable: Vec<ElGamalCiphertext> = (0..2)
        .map(|i| {
            let card = recon_cards[i];
            let r = Fr::rand(&mut rng);
            encrypt(&recon_pk_struct, &card, &r)
        })
        .collect();
    let recon_coefficient = Fr::from(7u64);

    let (recon_s_vec, recon_output_cards, recon_swap_out_cards) = reconstruct_deck(
        &recon_cards,
        &recon_user_readable,
        &recon_user_sk,
        &recon_user_pk,
        &recon_coefficient,
    )
    .expect("reconstruct_deck should succeed");

    let mut ts_recon = PokerTranscript::new(b"integration_recon_bytes");
    let recon_proof = ReconstructProof::prove(
        &recon_cards,
        &recon_user_readable,
        &recon_output_cards,
        &recon_swap_out_cards,
        &recon_user_sk,
        &recon_user_pk,
        &recon_s_vec,
        &mut ts_recon,
        &mut rng,
    )
    .expect("Reconstruct prove should succeed");
    let recon_proof_bytes = recon_proof.to_bytes();

    let recon_cards_bytes: Vec<u8> = recon_cards.iter().flat_map(g1_to_64bytes).collect();
    let recon_output_bytes = cts_to_bytes(&recon_output_cards);
    let recon_swap_out_only: Vec<ElGamalCiphertext> =
        recon_swap_out_cards.iter().map(|(_, ct)| *ct).collect();
    let recon_swap_out_bytes = cts_to_bytes(&recon_swap_out_only);
    let recon_user_readable_bytes = cts_to_bytes(&recon_user_readable);
    let recon_pk_bytes = g1_to_64bytes(&recon_user_pk);

    let mut ts_recon_v = PokerTranscript::new(b"integration_recon_bytes");
    assert!(
        reconstruct_verify_bytes(
            &recon_cards_bytes,
            &recon_output_bytes,
            &recon_swap_out_bytes,
            &recon_user_readable_bytes,
            &recon_pk_bytes,
            &recon_proof_bytes,
            &mut ts_recon_v,
        ),
        "Reconstruct 字节级验证应通过"
    );

    // 篡改 proof 字节应失败
    let mut tampered_recon = recon_proof_bytes.clone();
    if !tampered_recon.is_empty() {
        tampered_recon[0] ^= 0x01;
    }
    let mut ts_recon_t = PokerTranscript::new(b"integration_recon_bytes");
    assert!(
        !reconstruct_verify_bytes(
            &recon_cards_bytes,
            &recon_output_bytes,
            &recon_swap_out_bytes,
            &recon_user_readable_bytes,
            &recon_pk_bytes,
            &tampered_recon,
            &mut ts_recon_t,
        ),
        "篡改后的 Reconstruct proof 应验证失败"
    );
}

// ===== 测试 4：RevealTokenProof 端到端 =====

#[test]
fn test_reveal_token_proof_roundtrip() {
    let mut rng = test_rng();
    let (sk, pk, cts) = make_ciphertexts(5, &mut rng);

    // 对每张牌生成 RevealTokenAndProof
    let mut tokens_and_proofs = Vec::new();
    for ct in &cts {
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let rp = RevealTokenAndProof::prove(&sk, &pk, ct, &mut ts, &mut rng)
            .expect("RevealTokenAndProof::prove should succeed");
        tokens_and_proofs.push(rp);
    }

    // 验证每个 proof 并检查解密正确性
    for (ct, rp) in cts.iter().zip(tokens_and_proofs.iter()) {
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            rp.verify(ct, &pk, &mut ts),
            "RevealTokenAndProof verify 应通过"
        );

        // 验证解密：M = c2 - token
        let decrypted =
            (G1Projective::from(ct.d) - G1Projective::from(rp.reveal_token)).into_affine();
        // 原始明文是 card_to_point(i+1)，这里只验证非 identity
        assert!(!decrypted.is_zero(), "解密结果不应为 identity");
    }

    // 字节级 API 验证
    for (ct, rp) in cts.iter().zip(tokens_and_proofs.iter()) {
        let proof_bytes = rp.proof.to_bytes();
        let mut ct_bytes = [0u8; 128];
        ct_bytes[0..64].copy_from_slice(&g1_to_64bytes(&ct.c));
        ct_bytes[64..128].copy_from_slice(&g1_to_64bytes(&ct.d));
        let token_bytes = g1_to_64bytes(&rp.reveal_token);
        let pk_bytes = g1_to_64bytes(&pk);

        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            reveal_token_verify_bytes(&ct_bytes, &token_bytes, &pk_bytes, &proof_bytes, &mut ts),
            "reveal_token_verify_bytes 应通过"
        );
    }

    // 篡改检测：篡改 proof 应失败
    let mut tampered = tokens_and_proofs[0].proof.to_bytes();
    tampered[99] ^= 0x01; // 篡改 response_s
    let mut ct_bytes = [0u8; 128];
    ct_bytes[0..64].copy_from_slice(&g1_to_64bytes(&cts[0].c));
    ct_bytes[64..128].copy_from_slice(&g1_to_64bytes(&cts[0].d));
    let token_bytes = g1_to_64bytes(&tokens_and_proofs[0].reveal_token);
    let pk_bytes = g1_to_64bytes(&pk);
    let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
    assert!(
        !reveal_token_verify_bytes(&ct_bytes, &token_bytes, &pk_bytes, &tampered, &mut ts),
        "篡改后的 RevealTokenProof 应验证失败"
    );

    // 错误 pk 应失败
    let wrong_pk = keygen_from_secret(&(sk + Fr::from(1u64))).pk;
    let wrong_pk_bytes = g1_to_64bytes(&wrong_pk);
    let proof_bytes = tokens_and_proofs[0].proof.to_bytes();
    let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
    assert!(
        !reveal_token_verify_bytes(
            &ct_bytes,
            &token_bytes,
            &wrong_pk_bytes,
            &proof_bytes,
            &mut ts2
        ),
        "错误 pk 的 RevealTokenProof 应验证失败"
    );
}

// ===== 测试 5：ZKShuffleProof 端到端 =====

#[test]
fn test_shuffle_proof_roundtrip() {
    let mut rng = test_rng();
    let n = 8;
    let (_sk, pk, input_cts) = make_ciphertexts(n, &mut rng);

    // 构造随机排列
    let mut permute: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.gen_range(0..=i);
        permute.swap(i, j);
    }

    // 执行 shuffle + re_encrypt
    let pk_obj = ElGamalPublicKey { pk };
    let mut r_values = Vec::with_capacity(n);
    let mut output_cts = Vec::with_capacity(n);
    for &p in permute.iter().take(n) {
        let r_j = Fr::rand(&mut rng);
        r_values.push(r_j);
        output_cts.push(reencrypt(&pk_obj, &input_cts[p], &r_j));
    }

    // 生成 ZKShuffleProof
    let mut ts = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
    let proof = ZKShuffleProof::prove(
        &input_cts,
        &output_cts,
        &permute,
        &r_values,
        &pk,
        &mut ts,
        &mut rng,
    )
    .expect("ZKShuffleProof::prove should succeed");

    // 验证 proof
    let mut ts2 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
    assert!(
        proof.verify(&input_cts, &output_cts, &pk, &mut ts2),
        "ZKShuffleProof verify 应通过"
    );

    // 序列化/反序列化 roundtrip
    let proof_bytes = proof.to_bytes();
    let recovered = ZKShuffleProof::from_bytes(&proof_bytes).expect("from_bytes");
    let mut ts3 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
    assert!(
        recovered.verify(&input_cts, &output_cts, &pk, &mut ts3),
        "序列化后的 ZKShuffleProof 应验证通过"
    );

    // 字节级 API 验证
    let input_bytes = cts_to_bytes(&input_cts);
    let output_bytes = cts_to_bytes(&output_cts);
    let pk_bytes = g1_to_64bytes(&pk);
    let mut ts4 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
    assert!(
        shuffle_verify_bytes(
            &input_bytes,
            &output_bytes,
            &pk_bytes,
            &proof_bytes,
            &mut ts4
        ),
        "shuffle_verify_bytes 应通过"
    );

    // 篡改检测：篡改 proof 应失败
    let mut tampered = proof_bytes.clone();
    tampered[0] ^= 0x01; // 篡改 sum_c1_commit
    let mut ts5 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
    assert!(
        !shuffle_verify_bytes(&input_bytes, &output_bytes, &pk_bytes, &tampered, &mut ts5),
        "篡改后的 ZKShuffleProof 应验证失败"
    );

    // 篡改 output 应失败
    let mut bad_output = output_cts.clone();
    bad_output[0].c =
        (G1Projective::from(bad_output[0].c) + G1Projective::generator()).into_affine();
    let mut ts6 = PokerTranscript::new(SHUFFLE_PROOF_LABEL);
    assert!(
        !proof.verify(&input_cts, &bad_output, &pk, &mut ts6),
        "篡改 output 后 ZKShuffleProof 应验证失败"
    );
}
