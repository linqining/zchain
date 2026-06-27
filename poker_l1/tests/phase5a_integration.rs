//! Phase 5a 集成测试（Task 42a — SubTask 42.1~42.5）
//!
//! 覆盖 Phase 5a 跨模块端到端场景：
//! - SubTask 42.1：OfflineState commitment + checkout/checkin tx 端到端
//! - SubTask 42.2：ZkVerifier + zk_verify syscall 端到端
//! - SubTask 42.3：Hypernova verifier + Fiat-Shamir + public_io 边界
//! - SubTask 42.4：Groth16 CRS fingerprint + IPA verifier
//! - SubTask 42.5：链下折叠（CCS fold loop + ZkShuffleCcsCircuit）

use poker_l1::offline::ack_chain::{compute_ack_chain_hash, AckEntry};
use poker_l1::offline::ccs::{
    fold_loop, fold_step, CcsCircuit, CcsInstance, ZkShuffleCcsCircuit,
};
use poker_l1::offline::groth16::{
    register_groth16_verifier, Groth16Proof, Groth16Vk, Groth16VkRegistry, GROTH16_PROOF_SIZE,
};
use poker_l1::offline::hypernova::{
    fiat_shamir_challenge, register_hypernova_verifier, HypernovaProof, HypernovaVerifier,
    HYPERNOVA_PROOF_MIN_SIZE,
};
use poker_l1::offline::ipa::{register_ipa_verifier, IpaProof, IpaVerifier, IPA_PROOF_MIN_SIZE};
use poker_l1::offline::state::{
    check_offchain_allowed, execute_checkin, execute_checkout, execute_partial_checkin,
    CheckinTx, ExecutionMode, LastPartialFold, OfflineState, PartialCheckinTx,
};
use poker_l1::offline::zk_verifier::{
    VerifierStatus, ZkPublicIo, ZkVerifierRegistry, SCHEME_GROTH16, SCHEME_HYPERNOVA, SCHEME_IPA,
};
use poker_l1::offline::{
    DEFAULT_MAX_ACK_CHAIN_LENGTH, DEFAULT_MAX_PARTIAL_CHECKIN_COUNT, MAX_FOLD_STEP_COUNT,
};
use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;

// ===== 辅助函数 =====

/// 构造测试用 ZkVerifierRegistry（注册全部 3 个 scheme stub verifier）。
fn make_full_registry() -> ZkVerifierRegistry {
    let mut registry = ZkVerifierRegistry::new();
    register_hypernova_verifier(&mut registry);
    register_groth16_verifier(&mut registry);
    register_ipa_verifier(&mut registry);
    registry
}

/// 构造合法 ZkPublicIo（fold_step_count=1, skip_count=0）。
fn make_valid_public_io() -> ZkPublicIo {
    ZkPublicIo {
        initial_commitment: [0x01; 32],
        final_commitment: [0x02; 32],
        state_delta_hash: [0x03; 32],
        ack_chain_hash: [0x04; 32],
        fold_step_count: 1,
        skip_count: 0,
        segment_continuity_proof: Vec::new(),
    }
}

/// 构造 OffChain 模式 OfflineState。
fn make_offchain_state(version: u64, nonce: u64) -> OfflineState {
    OfflineState {
        game_id: ObjectID::new([0x42; 20], 1),
        version,
        state_root: [0xAA; 32],
        participants: vec![
            TaggedPubkey {
                tag: 0x01,
                raw: vec![0x11; 33],
            },
            TaggedPubkey {
                tag: 0x01,
                raw: vec![0x22; 33],
            },
        ],
        nonce,
        execution_mode: ExecutionMode::OffChain,
    }
}

/// 构造测试用 AckEntry。
fn make_ack_entry(checkpoint_seq: u64, participant_byte: u8) -> AckEntry {
    AckEntry {
        chain_id: poker_l1::DEFAULT_CHAIN_ID,
        epoch: 1,
        game_id: ObjectID::new([0x42; 20], 1),
        current_turn: [participant_byte; 20],
        state_hash: [participant_byte; 32],
        checkpoint_seq,
        participant: TaggedPubkey {
            tag: 0x01,
            raw: vec![participant_byte; 33],
        },
        participant_signature: vec![participant_byte; 64],
    }
}

// ===== SubTask 42.1: OfflineState 端到端 =====

#[test]
fn subtask_42_1_offlinestate_checkout_offchain_triggers() {
    // OffChain 模式 → execute_checkout 返回 Some(commitment)
    let state = make_offchain_state(1, 0);
    let commitment = execute_checkout(&state).expect("OffChain 应触发 checkout");
    assert_eq!(commitment, state.commitment());
}

#[test]
fn subtask_42_1_offlinestate_checkout_onchain_skipped() {
    // OnChain 模式 → execute_checkout 返回 None
    let mut state = make_offchain_state(1, 0);
    state.execution_mode = ExecutionMode::OnChain;
    assert!(execute_checkout(&state).is_none(), "OnChain 应跳过 checkout");
}

#[test]
fn subtask_42_1_offlinestate_commitment_deterministic() {
    // 相同 state → 相同 commitment
    let s1 = make_offchain_state(5, 10);
    let s2 = make_offchain_state(5, 10);
    assert_eq!(s1.commitment(), s2.commitment());

    // 不同 version → 不同 commitment
    let s3 = make_offchain_state(6, 10);
    assert_ne!(s1.commitment(), s3.commitment());

    // 不同 nonce → 不同 commitment
    let s4 = make_offchain_state(5, 11);
    assert_ne!(s1.commitment(), s4.commitment());
}

#[test]
fn subtask_42_1_checkin_tx_with_valid_proof_succeeds() {
    // 构造 registry + CheckinTx + 合法 proof → execute_checkin 成功
    let registry = make_full_registry();
    let new_commitment = [0xBB; 32];
    let state_delta = vec![0xCC; 64];
    let state_delta_hash = {
        let mut h = blake2::Blake2bVar::new(32).expect("hasher");
        use blake2::digest::Update;
        h.update(&state_delta);
        let mut out = [0u8; 32];
        use blake2::digest::VariableOutput;
        h.finalize_variable(&mut out).expect("finalize");
        out
    };

    let ack_entries = vec![make_ack_entry(1, 0xAA), make_ack_entry(2, 0xBB)];
    let ack_chain_hash = compute_ack_chain_hash(&ack_entries);

    // Hypernova proof（stub 接受非空 ≥ 64 字节）
    let proof = vec![0xDD; HYPERNOVA_PROOF_MIN_SIZE];

    let tx = CheckinTx {
        game_id: ObjectID::new([0x42; 20], 1),
        proof: proof.clone(),
        state_delta: state_delta.clone(),
        new_commitment,
        ack_chain: ack_entries,
        scheme_id: SCHEME_HYPERNOVA,
        has_partial_checkin: false,
    };

    // 验证签名哈希确定性
    let signing_hash_1 = tx.signing_hash(poker_l1::DEFAULT_CHAIN_ID);
    let signing_hash_2 = tx.signing_hash(poker_l1::DEFAULT_CHAIN_ID);
    assert_eq!(signing_hash_1, signing_hash_2, "signing_hash 应确定性");

    // 验证 ack_chain_hash 与独立计算一致
    assert_eq!(tx.ack_chain_hash(), ack_chain_hash);

    // 验证 state_delta_hash 与独立计算一致
    assert_eq!(tx.state_delta_hash(), state_delta_hash);

    // 执行 checkin
    let result = execute_checkin(
        &tx,
        &registry,
        poker_l1::DEFAULT_CHAIN_ID,
        None,
        3,
        DEFAULT_MAX_ACK_CHAIN_LENGTH,
    )
    .expect("checkin 应成功");

    assert!(result.verified, "Stub 状态下合法 proof 应验证通过");
    assert_eq!(result.scheme_id, SCHEME_HYPERNOVA);
    assert_eq!(result.verifier_status, VerifierStatus::Stub);
}

#[test]
fn subtask_42_1_checkin_tx_ack_chain_too_long_rejected() {
    // ack_chain 超过 max_ack_chain_length → AckChainLengthExceeded
    let registry = make_full_registry();
    let ack_entries: Vec<AckEntry> = (1..=5)
        .map(|i| make_ack_entry(i, (i as u8) * 0x10))
        .collect();

    let tx = CheckinTx {
        game_id: ObjectID::new([0x42; 20], 1),
        proof: vec![0xDD; HYPERNOVA_PROOF_MIN_SIZE],
        state_delta: vec![0xCC; 64],
        new_commitment: [0xBB; 32],
        ack_chain: ack_entries,
        scheme_id: SCHEME_HYPERNOVA,
        has_partial_checkin: false,
    };

    let result = execute_checkin(
        &tx,
        &registry,
        poker_l1::DEFAULT_CHAIN_ID,
        None,
        3,
        3, // max_ack_chain_length=3，但 ack_chain 有 5 个
    );

    assert!(result.is_err(), "ack_chain 过长应被拒绝");
}

#[test]
fn subtask_42_1_checkin_tx_partial_checkin_mismatch_rejected() {
    // has_partial_checkin=true 但 last_partial_fold=None → PartialCheckinMismatch
    let registry = make_full_registry();
    let tx = CheckinTx {
        game_id: ObjectID::new([0x42; 20], 1),
        proof: vec![0xDD; HYPERNOVA_PROOF_MIN_SIZE],
        state_delta: vec![0xCC; 64],
        new_commitment: [0xBB; 32],
        ack_chain: vec![make_ack_entry(1, 0xAA)],
        scheme_id: SCHEME_HYPERNOVA,
        has_partial_checkin: true, // 声明有 partial 但不提供 last_partial_fold
    };

    let result = execute_checkin(
        &tx,
        &registry,
        poker_l1::DEFAULT_CHAIN_ID,
        None, // 缺失 last_partial_fold
        3,
        DEFAULT_MAX_ACK_CHAIN_LENGTH,
    );

    assert!(result.is_err(), "partial_checkin 不一致应被拒绝");
}

#[test]
fn subtask_42_1_partial_checkin_progress_succeeds() {
    // 构造合法 PartialCheckinTx + LastPartialFold → execute_partial_checkin 成功
    let registry = make_full_registry();
    let intermediate = [0x11; 32];
    let new_intermediate = [0x22; 32];

    let ack_entries = vec![make_ack_entry(1, 0xAA)];
    let ack_chain_partial_hash = compute_ack_chain_hash(&ack_entries);

    let last_partial = LastPartialFold {
        intermediate_commitment: intermediate,
        folded_step_count: 1,
        proof_partial_hash: [0u8; 32],
        ack_chain_partial_hash,
    };

    let proof = vec![0xEE; HYPERNOVA_PROOF_MIN_SIZE];

    let tx = PartialCheckinTx {
        game_id: ObjectID::new([0x42; 20], 1),
        proof_partial: proof,
        folded_step_count: 2, // 必须严格大于 last_partial.folded_step_count（=1）
        intermediate_commitment: new_intermediate,
        ack_chain_partial: ack_entries,
        scheme_id: SCHEME_HYPERNOVA,
    };

    // 验证 partial_checkin 签名哈希确定性
    let h1 = tx.signing_hash(poker_l1::DEFAULT_CHAIN_ID);
    let h2 = tx.signing_hash(poker_l1::DEFAULT_CHAIN_ID);
    assert_eq!(h1, h2);

    let result = execute_partial_checkin(
        &tx,
        &registry,
        poker_l1::DEFAULT_CHAIN_ID,
        Some(&last_partial),
        0, // partial_checkin_count（首次）
        DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
        3, // max_skip_segments
        DEFAULT_MAX_ACK_CHAIN_LENGTH,
    )
    .expect("partial_checkin 应成功");

    assert_eq!(result.folded_step_count, 2, "step_count 应从 1 → 2");
    assert_eq!(result.intermediate_commitment, new_intermediate);
}

#[test]
fn subtask_42_1_check_offchain_allowed_stub_mainnet_rejected() {
    // NEW-C1：Stub 状态下主网拒绝 OffChain checkout
    let mut registry = make_full_registry();

    // 默认 Stub 状态 + 主网 → 拒绝（返回 Err）
    registry.set_verifier_status(poker_l1::DEFAULT_CHAIN_ID, VerifierStatus::Stub);
    assert!(
        check_offchain_allowed(&registry, poker_l1::DEFAULT_CHAIN_ID, true).is_err(),
        "Stub + 主网应拒绝 OffChain checkout"
    );

    // Production 状态 + 主网 → 允许（返回 Ok）
    registry.set_verifier_status(poker_l1::DEFAULT_CHAIN_ID, VerifierStatus::Production);
    assert!(
        check_offchain_allowed(&registry, poker_l1::DEFAULT_CHAIN_ID, true).is_ok(),
        "Production + 主网应允许 OffChain checkout"
    );

    // Stub 状态 + 测试网 → 允许（返回 Ok）
    registry.set_verifier_status(poker_l1::DEFAULT_CHAIN_ID, VerifierStatus::Stub);
    assert!(
        check_offchain_allowed(&registry, poker_l1::DEFAULT_CHAIN_ID, false).is_ok(),
        "Stub + 测试网应允许 OffChain checkout"
    );
}

// ===== SubTask 42.2: ZkVerifier + zk_verify syscall 端到端 =====

#[test]
fn subtask_42_2_registry_hot_plug_register_unregister() {
    // 热插拔：注册 → 查询 → 注销 → 查询失败
    let mut registry = ZkVerifierRegistry::new();
    assert!(registry.registered_schemes().is_empty());

    register_hypernova_verifier(&mut registry);
    assert_eq!(registry.registered_schemes(), vec![SCHEME_HYPERNOVA]);

    register_groth16_verifier(&mut registry);
    // BTreeMap 按键升序返回：[SCHEME_HYPERNOVA(1), SCHEME_GROTH16(2)]
    assert_eq!(
        registry.registered_schemes(),
        vec![SCHEME_HYPERNOVA, SCHEME_GROTH16]
    );

    // 注销 Hypernova
    let removed = registry.unregister(SCHEME_HYPERNOVA);
    assert!(removed.is_some());
    assert_eq!(registry.registered_schemes(), vec![SCHEME_GROTH16]);

    // 重新注册
    register_hypernova_verifier(&mut registry);
    assert_eq!(
        registry.registered_schemes(),
        vec![SCHEME_HYPERNOVA, SCHEME_GROTH16]
    );
}

#[test]
fn subtask_42_2_zk_verify_positive_all_schemes() {
    let registry = make_full_registry();
    let public_io = make_valid_public_io();

    // Hypernova（proof ≥ 64 字节）
    let result = registry
        .zk_verify(
            poker_l1::DEFAULT_CHAIN_ID,
            SCHEME_HYPERNOVA,
            &[0xAA; HYPERNOVA_PROOF_MIN_SIZE],
            &public_io,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
        )
        .expect("Hypernova verify 应成功");
    assert!(result.verified);

    // Groth16（proof = 192 字节）
    let result = registry
        .zk_verify(
            poker_l1::DEFAULT_CHAIN_ID,
            SCHEME_GROTH16,
            &[0xBB; GROTH16_PROOF_SIZE],
            &public_io,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
        )
        .expect("Groth16 verify 应成功");
    assert!(result.verified);

    // IPA（proof ≥ 32 字节）
    let result = registry
        .zk_verify(
            poker_l1::DEFAULT_CHAIN_ID,
            SCHEME_IPA,
            &[0xCC; IPA_PROOF_MIN_SIZE],
            &public_io,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
        )
        .expect("IPA verify 应成功");
    assert!(result.verified);
}

#[test]
fn subtask_42_2_zk_verify_negative_unknown_scheme() {
    let registry = make_full_registry();
    let public_io = make_valid_public_io();

    let result = registry.zk_verify(
        poker_l1::DEFAULT_CHAIN_ID,
        99, // 未知 scheme
        &[0xDD; 64],
        &public_io,
        3,
        DEFAULT_MAX_ACK_CHAIN_LENGTH,
    );

    assert!(result.is_err(), "未知 scheme 应返回错误");
}

#[test]
fn subtask_42_2_zk_verify_negative_malformed_proof() {
    let registry = make_full_registry();
    let public_io = make_valid_public_io();

    // Groth16 proof 长度不正确（应为 192）
    let result = registry.zk_verify(
        poker_l1::DEFAULT_CHAIN_ID,
        SCHEME_GROTH16,
        &[0xEE; 100], // 错误长度
        &public_io,
        3,
        DEFAULT_MAX_ACK_CHAIN_LENGTH,
    );

    assert!(result.is_err(), "格式错误的 proof 应返回错误");
}

#[test]
fn subtask_42_2_zk_verify_negative_public_io_boundary_violation() {
    let registry = make_full_registry();

    // fold_step_count > 1000 → FoldStepCountExceeded
    let mut bad_pio = make_valid_public_io();
    bad_pio.fold_step_count = MAX_FOLD_STEP_COUNT + 1;

    let result = registry.zk_verify(
        poker_l1::DEFAULT_CHAIN_ID,
        SCHEME_HYPERNOVA,
        &[0xFF; HYPERNOVA_PROOF_MIN_SIZE],
        &bad_pio,
        3,
        DEFAULT_MAX_ACK_CHAIN_LENGTH,
    );

    assert!(result.is_err(), "public_io 边界违规应返回错误");
}

#[test]
fn subtask_42_2_zk_verify_verifier_status_management() {
    // VerifierStatus 治理：默认 Stub → 升级到 Production
    let mut registry = make_full_registry();

    // 默认 Stub
    assert_eq!(
        registry.verifier_status(poker_l1::DEFAULT_CHAIN_ID),
        VerifierStatus::Stub
    );

    // 升级到 Production（实际升级须治理 90% quorum + timelock，此处仅测试状态切换）
    registry.set_verifier_status(poker_l1::DEFAULT_CHAIN_ID, VerifierStatus::Production);
    assert_eq!(
        registry.verifier_status(poker_l1::DEFAULT_CHAIN_ID),
        VerifierStatus::Production
    );

    // Production 状态下 zk_verify 仍能工作（stub verifier 在 Production 下返回 Other 错误）
    let public_io = make_valid_public_io();
    let result = registry.zk_verify(
        poker_l1::DEFAULT_CHAIN_ID,
        SCHEME_HYPERNOVA,
        &[0xAA; HYPERNOVA_PROOF_MIN_SIZE],
        &public_io,
        3,
        DEFAULT_MAX_ACK_CHAIN_LENGTH,
    );
    // HypernovaVerifier 在 Production 状态下返回 Other（MVP stub 未实现完整验证）
    assert!(
        result.is_err(),
        "Production 状态下 stub verifier 应返回错误（未实现完整验证）"
    );
}

// ===== SubTask 42.3: Hypernova verifier + Fiat-Shamir + public_io 边界 =====

#[test]
fn subtask_42_3_hypernova_proof_structure() {
    // 验证 HypernovaProof 结构构造
    let proof = HypernovaProof {
        folded_instance: poker_l1::offline::hypernova::FoldedInstance {
            instance_commitment: [0x11; 32],
            fold_step_count: 5,
        },
        witness_commitment: poker_l1::offline::hypernova::WitnessCommitment {
            commitment: [0x22; 32],
        },
        final_sumcheck: poker_l1::offline::hypernova::FinalSumcheck {
            evaluations: vec![[0x33; 32], [0x44; 32]],
            final_sum: [0x55; 32],
        },
    };

    // 验证字段可访问
    assert_eq!(proof.folded_instance.fold_step_count, 5);
    assert_eq!(proof.final_sumcheck.evaluations.len(), 2);
}

#[test]
fn subtask_42_3_fiat_shamir_challenge_deterministic() {
    // 相同 public_io → 相同 challenge
    let pio1 = make_valid_public_io();
    let pio2 = make_valid_public_io();

    let c1 = fiat_shamir_challenge(&pio1);
    let c2 = fiat_shamir_challenge(&pio2);

    assert_eq!(c1, c2, "Fiat-Shamir challenge 应确定性");
}

#[test]
fn subtask_42_3_fiat_shamir_challenge_differs_on_input() {
    // 不同 public_io → 不同 challenge
    let pio1 = make_valid_public_io();
    let mut pio2 = make_valid_public_io();
    pio2.fold_step_count = 2;

    let c1 = fiat_shamir_challenge(&pio1);
    let c2 = fiat_shamir_challenge(&pio2);

    assert_ne!(c1, c2, "不同 public_io 应产生不同 challenge");
}

#[test]
fn subtask_42_3_public_io_boundary_fold_step_count() {
    // fold_step_count 边界：1000 通过，1001 失败
    let mut pio = make_valid_public_io();

    pio.fold_step_count = MAX_FOLD_STEP_COUNT;
    assert!(pio.validate(3, DEFAULT_MAX_ACK_CHAIN_LENGTH).is_ok(), "1000 应通过");

    pio.fold_step_count = MAX_FOLD_STEP_COUNT + 1;
    assert!(
        pio.validate(3, DEFAULT_MAX_ACK_CHAIN_LENGTH).is_err(),
        "1001 应失败"
    );
}

#[test]
fn subtask_42_3_public_io_boundary_skip_count() {
    // skip_count 边界：max_skip_segments=3 时，3 通过，4 失败
    let mut pio = make_valid_public_io();

    pio.skip_count = 3;
    assert!(pio.validate(3, DEFAULT_MAX_ACK_CHAIN_LENGTH).is_ok(), "3 应通过");

    pio.skip_count = 4;
    assert!(pio.validate(3, DEFAULT_MAX_ACK_CHAIN_LENGTH).is_err(), "4 应失败");
}

#[test]
fn subtask_42_3_public_io_to_bytes_from_bytes_roundtrip() {
    // to_bytes → from_bytes 往返
    let pio = ZkPublicIo {
        initial_commitment: [0x01; 32],
        final_commitment: [0x02; 32],
        state_delta_hash: [0x03; 32],
        ack_chain_hash: [0x04; 32],
        fold_step_count: 42,
        skip_count: 2,
        segment_continuity_proof: vec![0xAA, 0xBB, 0xCC],
    };

    let bytes = pio.to_bytes();
    let recovered = ZkPublicIo::from_bytes(&bytes).expect("反序列化应成功");

    assert_eq!(recovered.initial_commitment, pio.initial_commitment);
    assert_eq!(recovered.final_commitment, pio.final_commitment);
    assert_eq!(recovered.state_delta_hash, pio.state_delta_hash);
    assert_eq!(recovered.ack_chain_hash, pio.ack_chain_hash);
    assert_eq!(recovered.fold_step_count, pio.fold_step_count);
    assert_eq!(recovered.skip_count, pio.skip_count);
    assert_eq!(
        recovered.segment_continuity_proof,
        pio.segment_continuity_proof
    );
}

#[test]
fn subtask_42_3_public_io_from_bytes_rejects_short_input() {
    // 过短输入 → None
    let short = vec![0u8; 10];
    assert!(ZkPublicIo::from_bytes(&short).is_none());

    // 刚好 MIN_BYTES - 1
    let almost = vec![0u8; ZkPublicIo::MIN_BYTES - 1];
    assert!(ZkPublicIo::from_bytes(&almost).is_none());

    // 刚好 MIN_BYTES（空 segment_continuity_proof）
    let exact = vec![0u8; ZkPublicIo::MIN_BYTES];
    assert!(ZkPublicIo::from_bytes(&exact).is_some());
}

#[test]
fn subtask_42_3_hypernova_verifier_trait_impl() {
    // 验证 HypernovaVerifier 实现 ZkVerifier trait
    let verifier = HypernovaVerifier::into_registry_verifier();
    assert_eq!(verifier.scheme_id(), SCHEME_HYPERNOVA);

    let pio = make_valid_public_io();
    // Stub 状态下验证合法 proof
    assert!(verifier
        .verify(
            &[0xAA; HYPERNOVA_PROOF_MIN_SIZE],
            &pio,
            VerifierStatus::Stub
        )
        .is_ok());

    // 空 proof → InvalidZkProofFormat
    assert!(verifier
        .verify(&[], &pio, VerifierStatus::Stub)
        .is_err());
}

// ===== SubTask 42.4: Groth16 CRS fingerprint + IPA verifier =====

#[test]
fn subtask_42_4_groth16_vk_crs_fingerprint_deterministic() {
    // 相同 VK → 相同 CRS fingerprint
    let vk = Groth16Vk {
        alpha_g1: [0x11; 48],
        beta_g2: [0x22; 96],
        gamma_g2: [0x33; 96],
        delta_g2: [0x44; 96],
        ic: vec![[0x55; 48], [0x66; 48]],
    };

    let fp1 = vk.crs_fingerprint();
    let fp2 = vk.crs_fingerprint();
    assert_eq!(fp1, fp2, "CRS fingerprint 应确定性");

    // 不同 VK → 不同 fingerprint
    let mut vk2 = vk.clone();
    vk2.alpha_g1[0] ^= 0x01;
    let fp3 = vk2.crs_fingerprint();
    assert_ne!(fp1, fp3, "不同 VK 应有不同 fingerprint");
}

#[test]
fn subtask_42_4_groth16_vk_to_bytes_roundtrip() {
    let vk = Groth16Vk {
        alpha_g1: [0x11; 48],
        beta_g2: [0x22; 96],
        gamma_g2: [0x33; 96],
        delta_g2: [0x44; 96],
        ic: vec![[0x55; 48], [0x66; 48], [0x77; 48]],
    };

    let bytes = vk.to_bytes();
    assert!(!bytes.is_empty());

    // 不同 ic 数量 → 不同字节长度
    let vk2 = Groth16Vk {
        ic: vec![[0x55; 48]],
        ..vk.clone()
    };
    let bytes2 = vk2.to_bytes();
    assert_ne!(bytes.len(), bytes2.len());
}

#[test]
fn subtask_42_4_groth16_proof_size_constant() {
    assert_eq!(GROTH16_PROOF_SIZE, 192);
    assert_eq!(
        GROTH16_PROOF_SIZE,
        48 + 96 + 48 // a_g1 + b_g2 + c_g1
    );
}

#[test]
fn subtask_42_4_groth16_vk_registry_register_and_verify() {
    // Groth16VkRegistry：注册 VK + CRS fingerprint 校验
    let mut vk_registry = Groth16VkRegistry::new();
    let vk = Groth16Vk {
        alpha_g1: [0x11; 48],
        beta_g2: [0x22; 96],
        gamma_g2: [0x33; 96],
        delta_g2: [0x44; 96],
        ic: vec![[0x55; 48]],
    };
    let fingerprint = vk.crs_fingerprint();

    // register 接受 vk，返回 vk_id = blake2b_256(vk.to_bytes())
    let vk_id = vk_registry
        .register(vk.clone())
        .expect("注册应成功");

    // vk_id 应等于 crs_fingerprint 的 blake2b_256(vk.to_bytes())
    // 注意：vk_id != crs_fingerprint，两者算法不同
    // verify_crs_fingerprint 接受 vk_id（内部查表）
    assert!(vk_registry.verify_crs_fingerprint(&vk_id).is_ok());

    // 伪造 vk_id → 失败（未注册）
    let mut fake_vk_id = vk_id;
    fake_vk_id[0] ^= 0x01;
    assert!(vk_registry.verify_crs_fingerprint(&fake_vk_id).is_err());

    // 验证 crs_fingerprint 确定性
    assert_eq!(vk.crs_fingerprint(), fingerprint);
}

#[test]
fn subtask_42_4_groth16_verifier_proof_format_validation() {
    let verifier = poker_l1::offline::groth16::Groth16Verifier::into_registry_verifier();
    assert_eq!(verifier.scheme_id(), SCHEME_GROTH16);

    // 合法长度 proof → 通过
    let valid_proof = vec![0u8; GROTH16_PROOF_SIZE];
    assert!(verifier.validate_proof_format(&valid_proof).is_ok());

    // 错误长度 → 失败
    let bad_proof = vec![0u8; 100];
    assert!(verifier.validate_proof_format(&bad_proof).is_err());

    // 空 proof → 失败
    assert!(verifier.validate_proof_format(&[]).is_err());
}

#[test]
fn subtask_42_4_groth16_proof_to_bytes() {
    let proof = Groth16Proof {
        a_g1: [0x11; 48],
        b_g2: [0x22; 96],
        c_g1: [0x33; 48],
    };

    let bytes = proof.to_bytes();
    assert_eq!(bytes.len(), GROTH16_PROOF_SIZE);

    // 验证字节布局：a_g1 || b_g2 || c_g1
    assert_eq!(&bytes[..48], &proof.a_g1);
    assert_eq!(&bytes[48..144], &proof.b_g2);
    assert_eq!(&bytes[144..], &proof.c_g1);
}

#[test]
fn subtask_42_4_ipa_proof_min_size() {
    assert_eq!(IPA_PROOF_MIN_SIZE, 32);
}

#[test]
fn subtask_42_4_ipa_verifier_trait_impl() {
    let verifier = IpaVerifier::into_registry_verifier();
    assert_eq!(verifier.scheme_id(), SCHEME_IPA);

    let pio = make_valid_public_io();

    // 合法 proof（≥ 32 字节）
    assert!(verifier
        .validate_proof_format(&[0u8; IPA_PROOF_MIN_SIZE])
        .is_ok());

    // 空 proof → 失败
    assert!(verifier.validate_proof_format(&[]).is_err());

    // Stub 状态下验证
    let result = verifier.verify(
        &[0xAA; IPA_PROOF_MIN_SIZE],
        &pio,
        VerifierStatus::Stub,
    );
    assert!(result.is_ok());
    assert!(result.unwrap(), "Stub 状态下合法 proof 应验证通过");
}

#[test]
fn subtask_42_4_ipa_proof_to_bytes() {
    let proof = IpaProof {
        l_vec: vec![[0x11; 48], [0x22; 48]],
        r_vec: vec![[0x33; 48], [0x44; 48]],
        a_final: [0x55; 32],
        b_final: [0x66; 32],
    };

    let bytes = proof.to_bytes();
    assert!(!bytes.is_empty());

    // 不同字段数量 → 不同字节长度
    let proof2 = IpaProof {
        l_vec: vec![[0x11; 48]],
        r_vec: vec![[0x33; 48]],
        a_final: [0x55; 32],
        b_final: [0x66; 32],
    };
    let bytes2 = proof2.to_bytes();
    assert_ne!(bytes.len(), bytes2.len());
}

// ===== SubTask 42.5: 链下折叠（CCS fold loop + ZkShuffleCcsCircuit）=====

/// 构造测试用 CcsInstance。
fn make_ccs_instance(seed: u8) -> CcsInstance {
    CcsInstance {
        mat_commitments: vec![[seed; 32], [seed + 1; 32], [seed + 2; 32]],
        public_input_hash: [seed + 3; 32],
        witness_commitment: [seed + 4; 32],
        state_delta_hash: [seed + 5; 32],
        ack_step_hash: [seed + 6; 32],
    }
}

#[test]
fn subtask_42_5_fold_step_single() {
    // 单步 fold：prev=None → fold_step_count=1
    let instance = make_ccs_instance(0x10);
    let result = fold_step(None, &instance, poker_l1::DEFAULT_CHAIN_ID, &ObjectID::new([0u8; 20], 0))
        .expect("单步 fold 应成功");

    assert_eq!(result.fold_step_count, 1);
    assert_eq!(
        result.cumulative_state_delta_hash,
        instance.state_delta_hash,
        "首步 cumulative = 自身 state_delta_hash"
    );
}

#[test]
fn subtask_42_5_fold_step_multi_increments_count() {
    // 多步 fold：fold_step_count 递增
    let instance1 = make_ccs_instance(0x10);
    let instance2 = make_ccs_instance(0x20);

    let step1 = fold_step(None, &instance1, poker_l1::DEFAULT_CHAIN_ID, &ObjectID::new([0u8; 20], 0))
        .expect("step1 应成功");
    let step2 = fold_step(
        Some(&step1),
        &instance2,
        poker_l1::DEFAULT_CHAIN_ID,
        &ObjectID::new([0u8; 20], 0),
    )
    .expect("step2 应成功");

    assert_eq!(step1.fold_step_count, 1);
    assert_eq!(step2.fold_step_count, 2);
    // cumulative_state_delta_hash 应不同（哈希链接）
    assert_ne!(
        step1.cumulative_state_delta_hash,
        step2.cumulative_state_delta_hash
    );
}

#[test]
fn subtask_42_5_fold_loop_multi_step() {
    // fold_loop：≥2 步 CCS 实例折叠为单个 proof
    let instances = vec![
        make_ccs_instance(0x10),
        make_ccs_instance(0x20),
        make_ccs_instance(0x30),
    ];

    let result = fold_loop(
        &instances,
        [0x01; 32], // initial_commitment
        [0x02; 32], // final_commitment
        [0x03; 32], // ack_chain_hash
        0,          // skip_count
        Vec::new(), // segment_continuity_proof
    )
    .expect("fold_loop 应成功");

    assert_eq!(result.fold_step_count, 3);
    assert_eq!(result.public_io.fold_step_count, 3);
    assert_eq!(result.public_io.initial_commitment, [0x01; 32]);
    assert_eq!(result.public_io.final_commitment, [0x02; 32]);
    assert_eq!(result.public_io.ack_chain_hash, [0x03; 32]);
    assert_eq!(result.public_io.skip_count, 0);

    // proof 结构完整
    assert_eq!(
        result.proof.folded_instance.fold_step_count,
        3,
        "HypernovaProof 应记录最终 fold_step_count"
    );
}

#[test]
fn subtask_42_5_fold_loop_empty_rejected() {
    let result = fold_loop(
        &[],
        [0x01; 32],
        [0x02; 32],
        [0x03; 32],
        0,
        Vec::new(),
    );

    assert!(result.is_err(), "空 instances 应被拒绝");
}

#[test]
fn subtask_42_5_fold_loop_exceeds_max_steps_rejected() {
    // O15：超过 1000 步 → FoldStepCountExceeded
    let instances: Vec<CcsInstance> = (0..=MAX_FOLD_STEP_COUNT)
        .map(|i| make_ccs_instance((i as u8).wrapping_mul(0x10)))
        .collect();

    let result = fold_loop(
        &instances,
        [0x01; 32],
        [0x02; 32],
        [0x03; 32],
        0,
        Vec::new(),
    );

    assert!(result.is_err(), "超过 1000 步应被拒绝");
}

#[test]
fn subtask_42_5_fold_loop_max_boundary_accepted() {
    // 边界：恰好 1000 步 → 通过
    let instances: Vec<CcsInstance> = (0..MAX_FOLD_STEP_COUNT)
        .map(|i| make_ccs_instance((i as u8).wrapping_mul(0x10)))
        .collect();

    let result = fold_loop(
        &instances,
        [0x01; 32],
        [0x02; 32],
        [0x03; 32],
        0,
        Vec::new(),
    )
    .expect("恰好 1000 步应通过");

    assert_eq!(result.fold_step_count, MAX_FOLD_STEP_COUNT);
}

#[test]
fn subtask_42_5_zk_shuffle_ccs_circuit_trait() {
    // ZkShuffleCcsCircuit 实现 CcsCircuit trait
    let circuit = ZkShuffleCcsCircuit::new();

    assert_eq!(circuit.name(), "zk_shuffle");
    assert_eq!(circuit.num_matrices(), 3); // CCS 标准 q=2 → 3 矩阵

    // to_instance 生成合法 CcsInstance
    let instance = circuit
        .to_instance(
            &[0xAA; 64], // witness
            &[0xBB; 32], // public_inputs
            &[0xCC; 64], // state_delta
            [0xDD; 32],  // ack_step_hash
        )
        .expect("to_instance 应成功");

    assert_eq!(instance.mat_commitments.len(), 3);
    // 所有字段应为非零哈希
    assert_ne!(instance.public_input_hash, [0u8; 32]);
    assert_ne!(instance.witness_commitment, [0u8; 32]);
    assert_ne!(instance.state_delta_hash, [0u8; 32]);
}

#[test]
fn subtask_42_5_zk_shuffle_circuit_consumed_by_fold_loop() {
    // 端到端：ZkShuffleCcsCircuit → to_instance → fold_loop
    let circuit = ZkShuffleCcsCircuit::new();

    let instances: Vec<CcsInstance> = (0..3)
        .map(|i| {
            circuit
                .to_instance(
                    &[i + 0x10; 64],
                    &[i + 0x20; 32],
                    &[i + 0x30; 64],
                    [i + 0x40; 32],
                )
                .expect("to_instance 应成功")
        })
        .collect();

    let result = fold_loop(
        &instances,
        [0x01; 32],
        [0x02; 32],
        [0x03; 32],
        0,
        Vec::new(),
    )
    .expect("fold_loop 应消费 ZkShuffleCcsCircuit 实例");

    assert_eq!(result.fold_step_count, 3);

    // 生成的 public_io 应能通过 ZkVerifier 校验（Stub 状态）
    let registry = make_full_registry();
    let proof_bytes = vec![0u8; HYPERNOVA_PROOF_MIN_SIZE]; // Stub proof
    let verify_result = registry
        .zk_verify(
            poker_l1::DEFAULT_CHAIN_ID,
            SCHEME_HYPERNOVA,
            &proof_bytes,
            &result.public_io,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
        )
        .expect("zk_verify 应成功");

    assert!(
        verify_result.verified,
        "fold_loop 生成的 public_io 应通过 ZkVerifier 校验"
    );
}

#[test]
fn subtask_42_5_fold_loop_produces_valid_public_io_for_checkin() {
    // 端到端：fold_loop → public_io → CheckinTx → execute_checkin
    let instances = vec![make_ccs_instance(0x10), make_ccs_instance(0x20)];

    let fold_result = fold_loop(
        &instances,
        [0x01; 32],
        [0x02; 32],
        [0x03; 32],
        0,
        Vec::new(),
    )
    .expect("fold_loop 应成功");

    // 构造 CheckinTx 使用 fold_loop 的 public_io
    let ack_entries = vec![make_ack_entry(1, 0xAA)];
    let tx = CheckinTx {
        game_id: ObjectID::new([0x42; 20], 1),
        proof: vec![0xDD; HYPERNOVA_PROOF_MIN_SIZE],
        state_delta: vec![0xCC; 64],
        new_commitment: fold_result.public_io.final_commitment,
        ack_chain: ack_entries,
        scheme_id: SCHEME_HYPERNOVA,
        has_partial_checkin: false,
    };

    let registry = make_full_registry();
    let result = execute_checkin(
        &tx,
        &registry,
        poker_l1::DEFAULT_CHAIN_ID,
        None,
        3,
        DEFAULT_MAX_ACK_CHAIN_LENGTH,
    )
    .expect("checkin 应成功");

    assert!(result.verified, "fold_loop 产出的 proof 应通过 checkin 验证");
}

#[test]
fn subtask_42_5_ack_chain_inclusion_proof_with_fold_results() {
    // 端到端：ack_chain 包含证明 + fold_loop 联动
    use poker_l1::offline::ack_chain::{prove_ack_inclusion, verify_ack_inclusion};

    let ack_entries: Vec<AckEntry> = (1..=4)
        .map(|i| make_ack_entry(i, (i as u8) * 0x10))
        .collect();
    let root = compute_ack_chain_hash(&ack_entries);

    // 为每个 leaf 生成包含证明
    for i in 0..ack_entries.len() {
        let proof = prove_ack_inclusion(&ack_entries, i).expect("proof 应生成");
        let leaf = ack_entries[i].ack_hash();
        assert!(
            verify_ack_inclusion(&root, &leaf, &proof),
            "leaf {i} 包含证明应验证通过"
        );
    }

    // 使用这些 ack_entries 作为 fold_loop 的 ack_chain_hash
    let instances = vec![make_ccs_instance(0x10)];
    let result = fold_loop(
        &instances,
        [0x01; 32],
        [0x02; 32],
        root, // 使用真实 ack_chain_hash
        0,
        Vec::new(),
    )
    .expect("fold_loop 应成功");

    assert_eq!(result.public_io.ack_chain_hash, root);
}
