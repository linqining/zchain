//! 适配器回归：手写约束 canonical AIR 验证器必须接受真实证明、拒绝被篡改的归档。
//!
//! 负例 1（垃圾 STARK 字节）与正例复用**真实 prover**（`prove_canonical_tagged_batch`）
//! 产出的归档——只有公开 scope 完全一致的归档才能让"拒绝"归因于 STARK 字节本身；
//! 其余负例用手工构造的合法 borsh 归档（绑定检查先于 STARK 验证，足以触发）。
//!
//! v2（scope v2 / plan-appchain §5.2）：引擎对**含 `hand_proof` 的记录**直接
//! 调用 `validate_settlement`（appchain 侧 scope v2 镜像可解析 canonical
//! 归档，镜像 pot 逐字节绑定已入纯函数校验），"清除 hand_proof 副本"补偿
//! 已移除。正例的终态镜像 pot（500）与结算 `pot` 一致，gross_pot 绑定可过。

use poker_appchain::error::AppchainError;
use poker_appchain::fee::FeePolicy;
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{EcdsaSig, OwnerKey, spend_digest};
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::pipeline::{Priority, ProofJob, SettlementProver};
use poker_appchain::settlement::{
    HandProofBinding, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
    flat_settlement_plan, parse_archive_scope, settle_effect, settle_spend_scope,
};
use poker_appchain_texasair::TexasAirEngine;
use poker_texas_air::canonical_rake_opening::{CanonicalBlindOpening, CanonicalRakeOpening};
use poker_texas_air::texas_canonical::{
    CANONICAL_ABI_VERSION, CanonicalActionPayload, CanonicalPhase,
    CanonicalProtocolCompletionOpening, CanonicalRoundAdvanceOpening, CanonicalSeat,
    CanonicalStateImage, CanonicalTransitionKind, CanonicalTransitionWitness, MAX_CANONICAL_SEATS,
    NO_CANONICAL_SEAT,
};
use poker_texas_air::texas_canonical_air::{
    ArchivedCanonicalTaggedProof, prove_canonical_tagged_batch,
};
use std::sync::Arc;

// ===== 手工归档（负例专用：绑定检查在 STARK 验证之前，无需真实证明） =====

fn stub_archive_bytes(commitment: [u8; 32], proof: Vec<u8>) -> Vec<u8> {
    let archive = ArchivedCanonicalTaggedProof {
        log_size: 10,
        num_columns: 0,
        table_id: 1,
        first_hand_id: 1,
        last_hand_id: 1,
        first_call_seq: 0,
        last_call_seq: 1,
        transition_count: 2,
        first_transition_kind: 0,
        last_transition_kind: 0,
        reveal_timeout_cascade_count: 0,
        reveal_timeout_cascade_schedule: [u8::MAX; MAX_CANONICAL_SEATS],
        batch_digest: [1; 32],
        pre_state_commitment: [2; 32],
        post_state_commitment: commitment,
        pre_state_root: [0; 32],
        post_state_root: [0; 32],
        pre_lifecycle_root: [0; 32],
        post_lifecycle_root: [0; 32],
        pre_overlay_root: [0; 32],
        post_overlay_root: [0; 32],
        pre_settlement_commitment: [0; 32],
        post_settlement_commitment: [0; 32],
        pre_custody_commitment: [0; 32],
        post_custody_commitment: [0; 32],
        pre_state_image_bytes: Vec::new(),
        post_state_image_bytes: Vec::new(),
        range_claimed_sum: [0; 4],
        rake_opening: None,
        blind_opening: None,
        rules_hash: None,
        state_object_key: [0; 32],
        state_opening_epoch: 0,
        stark_proof_bytes: proof,
    };
    borsh::to_vec(&archive).unwrap()
}

fn stub_job_with(commitment: [u8; 32], proof: Vec<u8>) -> ProofJob {
    let record = SettlementRecord {
        table_id: 1,
        hand_binding: [7; 32],
        policy_commitment: FeePolicy::Zero.commitment_bytes(),
        pot: 1,
        inputs: Vec::new(),
        payouts: Vec::new(),
        rake: RakeSplitRecord {
            total: 0,
            treasury_out: None,
            operator_out: None,
        },
        plan: flat_settlement_plan(1, 0b01, {
            let mut awards = [0u64; 9];
            awards[0] = 1;
            awards
        }),
        hand_proof: Some(HandProofBinding {
            archive_bytes: stub_archive_bytes(commitment, proof),
            post_state_commitment: commitment,
            pre_state_root: [0; 32],
            post_state_root: [0; 32],
        }),
    };
    ProofJob {
        op_index: 0,
        table_id: 1,
        record: Arc::new(record),
        policy: FeePolicy::Zero,
        priority: Priority::Play,
    }
}

// ===== 真实证明（照搬 poker_texas_air tests::create_table 的最小构造） =====

/// 最小 canonical CreateTable witness（与 poker_texas_air 同文件测试夹具一致）。
///
/// v2：`pot`/`chip_pool` 置 500（满足 custody 恒等式 pot + Σseats == chip_pool），
/// 使终态镜像的 `pot` 字段与结算记录的 `pot` 一致——gross_pot 状态镜像绑定
/// （P0-2）的正例路径。
fn canonical_create_table_witness(table_id: u64) -> CanonicalTransitionWitness {
    let pre = CanonicalStateImage {
        abi_version: CANONICAL_ABI_VERSION,
        table_id,
        hand_id: 1,
        call_seq: 0,
        phase: CanonicalPhase::Waiting,
        phase_subtag: 0,
        street: 0,
        current_turn: NO_CANONICAL_SEAT,
        deadline_ms: 0,
        shuffle_timeout_ms: 10_000,
        reveal_timeout_ms: 10_000,
        betting_timeout_ms: 30_000,
        reconstruct_timeout_ms: 10_000,
        showdown_display_ms: 3_000,
        current_bet: 0,
        min_raise: 0,
        chip_pool: 500,
        pot: 500,
        button: 0,
        max_players: 2,
        acted_mask: 0,
        leave_after_hand_mask: 0,
        protocol_pending_mask: 0,
        board_cards_commitment: [1; 32],
        deck_commitment: [2; 32],
        reveal_commitment: [3; 32],
        reconstruction_commitment: [4; 32],
        run_it_twice_commitment: [5; 32],
        rules_commitment: [6; 32],
        governance_commitment: [7; 32],
        settlement_commitment: [8; 32],
        custody_commitment: [9; 32],
        lifecycle_root: [10; 32],
        overlay_root: [11; 32],
        state_root: [12; 32],
        seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
    };
    let mut post = pre.clone();
    post.call_seq = pre.call_seq + 1;
    let mut witness = CanonicalTransitionWitness {
        pre,
        post,
        kind: CanonicalTransitionKind::CreateTable,
        actor: [1; 32],
        action: CanonicalActionPayload {
            seat: NO_CANONICAL_SEAT,
            amount: 0,
            auxiliary: 0,
            flag: false,
            proof_commitment: [0; 32],
        },
        round_advance: CanonicalRoundAdvanceOpening::default(),
        protocol_completion: CanonicalProtocolCompletionOpening::default(),
        rake_opening: CanonicalRakeOpening::ZERO,
        blind_opening: CanonicalBlindOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    witness.seal();
    witness
}

/// 真实 stwo prove（release 下秒级）。
fn proven_archive(table_id: u64) -> ArchivedCanonicalTaggedProof {
    let witness = canonical_create_table_witness(table_id);
    prove_canonical_tagged_batch(&[witness]).expect("canonical proof")
}

/// 结算关系合法（单输入单输出、Zero 费率、P 层签名有效、plan 投影一致）
/// + 真实归档绑定的 job。资产类参数化（REAL 供 P0-3 出证策略回归）。
fn settled_job_with_bytes(
    table_id: u64,
    declared: [u8; 32],
    archive_bytes: Vec<u8>,
    asset_class: AssetClass,
) -> ProofJob {
    let player = OwnerKey::from_seed(&[11; 32]).expect("seed key");
    let note = Note::new(
        asset_class,
        500,
        player.public_bytes(),
        [1; 32],
        Some(table_id),
    )
    .expect("note");
    let mut record = SettlementRecord {
        table_id,
        hand_binding: [7; 32],
        policy_commitment: FeePolicy::Zero.commitment_bytes(),
        pot: 500,
        inputs: vec![SettleInput {
            note: note.clone(),
            // settle_effect 只读 spend.commitment：先填真实承诺再算效果摘要
            spend: SpendAuth {
                commitment: note.commitment_bytes(),
                nullifier: [0; 32],
                sig: EcdsaSig { bytes: [0; 64] },
            },
        }],
        payouts: vec![NoteSpec {
            asset_class,
            amount: 500,
            owner: player.public_bytes(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        }],
        rake: RakeSplitRecord {
            total: 0,
            treasury_out: None,
            operator_out: None,
        },
        plan: flat_settlement_plan(500, 0b01, {
            let mut awards = [0u64; 9];
            awards[0] = 500;
            awards
        }),
        hand_proof: None,
    };
    // S1：授权对完整结算效果签名（记录完整后构造）
    let scope = settle_spend_scope(&record.hand_binding);
    let effect = settle_effect(&record);
    let nullifier = felt_to_bytes32(&note.nullifier(&[11; 32]));
    let digest = spend_digest(&note.commitment_bytes(), &nullifier, &scope, &effect);
    record.inputs[0].spend = SpendAuth {
        commitment: note.commitment_bytes(),
        nullifier,
        sig: player.sign(&digest),
    };
    record.hand_proof = Some(HandProofBinding {
        archive_bytes,
        post_state_commitment: declared,
        // 声明根由调用方按真实归档填充（stub 归档为全零）
        pre_state_root: [0; 32],
        post_state_root: [0; 32],
    });
    ProofJob {
        op_index: 0,
        table_id,
        record: Arc::new(record),
        policy: FeePolicy::Zero,
        priority: Priority::Play,
    }
}

fn settled_job(table_id: u64, archive: &ArchivedCanonicalTaggedProof) -> ProofJob {
    settled_job_class(table_id, archive, AssetClass::Play)
}

/// 指定资产类的真实归档绑定 job（签名按该类完整重算）。
fn settled_job_class(
    table_id: u64,
    archive: &ArchivedCanonicalTaggedProof,
    asset_class: AssetClass,
) -> ProofJob {
    let archive_bytes = borsh::to_vec(archive).expect("archive encoding");
    let mut job = settled_job_with_bytes(
        table_id,
        archive.post_state_commitment,
        archive_bytes,
        asset_class,
    );
    // v2：声明前后状态根 = 真实归档根（validate_settlement 第 11 条判据）
    let record = Arc::make_mut(&mut job.record);
    let hp = record.hand_proof.as_mut().unwrap();
    hp.pre_state_root = archive.pre_state_root;
    hp.post_state_root = archive.post_state_root;
    job
}

/// REAL 类结算 job（P0-3 出证策略回归用；其余构造同 settled_job；
/// op_index 取 5 使水位推进断言可观测——0 与初始水位不可区分）。
fn settled_real_job(table_id: u64, archive: &ArchivedCanonicalTaggedProof) -> ProofJob {
    let mut job = settled_job_class(table_id, archive, AssetClass::Real);
    job.priority = Priority::Real;
    job.op_index = 5;
    job
}

// ===== 负例 =====

#[test]
fn tampered_stark_proof_rejected() {
    let engine = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    // 公开 scope 完全一致（真实证明）但 STARK 证明字节为垃圾 → 验证器必须拒绝
    let mut archive = proven_archive(1);
    archive.stark_proof_bytes = vec![0u8; 64];
    let err = engine.prove(&settled_job(1, &archive)).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::AdmissionRejected("archive stark verify failed")
    ));
}

#[test]
fn commitment_mismatch_rejected() {
    let engine = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let mut j = stub_job_with([3; 32], vec![0u8; 64]);
    let r = Arc::make_mut(&mut j.record);
    r.hand_proof.as_mut().unwrap().post_state_commitment = [4; 32];
    assert!(matches!(
        engine.prove(&j).unwrap_err(),
        AppchainError::AdmissionRejected("archive state commitment mismatch")
    ));
}

#[test]
fn table_mismatch_rejected() {
    let engine = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let mut j = stub_job_with([3; 32], vec![0u8; 64]);
    let r = Arc::make_mut(&mut j.record);
    r.table_id = 2;
    assert!(matches!(
        engine.prove(&j).unwrap_err(),
        AppchainError::AdmissionRejected("archive table mismatch")
    ));
}

#[test]
fn missing_hand_proof_rejected() {
    let engine = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let mut j = stub_job_with([3; 32], vec![0u8; 64]);
    Arc::make_mut(&mut j.record).hand_proof = None;
    assert!(matches!(
        engine.prove(&j).unwrap_err(),
        AppchainError::AdmissionRejected("hand proof required")
    ));
}

#[test]
fn valid_attestation_verifies_and_tamper_fails() {
    // attestation 的 verify 路径独立可复验；篡改 payload 或公钥必失败
    let attestor = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let engine = TexasAirEngine::new(attestor.clone());
    // 构造 bundle 验证 verify 的密码学路径：消息与 prove 所用不同 → 签名无效
    let bundle = poker_appchain::pipeline::ProofBundle {
        binding_hex: hex::encode([7; 32]),
        op_index: 0,
        engine: "texas-air-v2",
        attestor_public: engine.attestor_public(),
        payload: {
            // v2.1 payload：终态承诺(32) + 终态状态根(32) + 首状态根(32) +
            // 计划摘要(32) + 签名(64) = 192B
            let mut p = vec![3u8; 128];
            use ed25519_dalek::Signer as _;
            let msg = [9u8; 32];
            p.extend_from_slice(&attestor.sign(&msg).to_bytes());
            p
        },
    };
    assert!(matches!(
        engine.verify(&bundle).unwrap_err(),
        AppchainError::BadSignature
    ));
    // 旧 v2 布局（128B 载荷）不再接受（attestation v2.1 跨版本不互通）
    let mut legacy = bundle.clone();
    legacy.payload.truncate(128);
    assert!(matches!(
        engine.verify(&legacy).unwrap_err(),
        AppchainError::AdmissionRejected("bad payload")
    ));
}

// ===== attestation v2.1：消息/payload 扩展（P0-3 四要素） =====

#[test]
fn attestation_binds_pre_state_root_and_plan_digest() {
    let engine = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let bundle = engine
        .prove(&settled_job(1, &proven_archive(1)))
        .expect("canonical proof must be admitted");
    assert_eq!(bundle.payload.len(), 192, "v2.1 payload is 192B");
    engine.verify(&bundle).expect("attestation verify");
    // 深度篡改 pre_state_root 区（payload[64..96]）→ 消息变化 → 签名失败
    let mut flip_pre = bundle.clone();
    flip_pre.payload[70] ^= 1;
    assert!(matches!(
        engine.verify(&flip_pre).unwrap_err(),
        AppchainError::BadSignature
    ));
    // 深度篡改 plan_digest 区（payload[96..128]）→ 同拒
    let mut flip_plan = bundle.clone();
    flip_plan.payload[100] ^= 1;
    assert!(matches!(
        engine.verify(&flip_plan).unwrap_err(),
        AppchainError::BadSignature
    ));
}

// ===== P0-3：verifier key 钉扎 + REAL 出证策略 =====

#[test]
fn verifier_key_pin_enforced_on_verify() {
    let attestor = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let engine = TexasAirEngine::new(attestor);
    let bundle = engine
        .prove(&settled_job(1, &proven_archive(1)))
        .expect("canonical proof must be admitted");
    // 未钉扎：verify 通过
    engine.verify(&bundle).expect("no pin configured");
    // 钉扎 key == 签名者：通过
    let pinned = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[1; 32]))
        .with_verifier_key(bundle.attestor_public);
    pinned.verify(&bundle).expect("pinned to signer");
    // 钉扎 key != 签名者：VerifierKeyMismatch（签名本身有效也拒）
    let stranger = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[2; 32]))
        .with_verifier_key([0xAA; 32]);
    assert!(matches!(
        stranger.verify(&bundle).unwrap_err(),
        AppchainError::VerifierKeyMismatch
    ));
}

/// StarkRequired + 钉扎正确：REAL 结算全路径（**真实 stwo prove**）出批、
/// 水位推进——"REAL 已证明"必须真实经过 stwo 验证路径。
#[test]
fn real_settlement_stark_required_end_to_end_with_real_stwo() {
    let attestor = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let pinned_key = attestor.verifying_key().to_bytes();
    let engine: Arc<dyn poker_appchain::pipeline::SettlementProver> =
        Arc::new(TexasAirEngine::new(attestor).with_verifier_key(pinned_key));
    let metrics = Arc::new(poker_appchain::metrics::MetricsRegistry::new());
    let pipeline = poker_appchain::pipeline::ProofPipeline::with_real_policy(
        poker_appchain::pipeline::PipelineConfig {
            workers: 1,
            batch_size: 1,
            queue_bound: 8,
            high_watermark: 8,
            batch_interval_ms: 1_000,
        },
        engine,
        Arc::clone(&metrics),
        poker_appchain::real_policy::RealSettlementPolicy::stark_required(pinned_key),
    );
    let seq = Arc::new(std::sync::Mutex::new(
        poker_appchain::sequencer::Sequencer::new(
            poker_appchain::keys::SequencerKey::from_seed(&[5u8; 32]),
            poker_appchain::sequencer::SequencerConfig::default(),
            Arc::new(poker_appchain::metrics::MetricsRegistry::new()),
        ),
    ));
    pipeline.set_on_batch_proven({
        let seq = Arc::clone(&seq);
        Arc::new(move |through| seq.lock().unwrap().mark_proven_through(through))
    });
    pipeline
        .submit(settled_real_job(1, &proven_archive(1)))
        .expect("REAL job admitted under StarkRequired with pinned key");
    for _ in 0..2_000 {
        if pipeline.completed_count() >= 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(pipeline.completed_count(), 1, "prove = real stwo path");
    let batch = pipeline
        .try_build_batch()
        .unwrap()
        .expect("REAL batch proven");
    assert_eq!(batch.through_op, 5);
    assert_eq!(
        seq.lock().unwrap().proven_watermark(),
        5,
        "watermark advanced via batch callback"
    );
    assert_eq!(metrics.counter("real_settlement_rejected_total"), 0);
}

/// REAL 经 texas-air 但 mode=Disabled → 提交即拒（不进队列、不出证）。
#[test]
fn real_settlement_mode_disabled_rejected() {
    let attestor = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let pinned_key = attestor.verifying_key().to_bytes();
    let engine: Arc<dyn poker_appchain::pipeline::SettlementProver> =
        Arc::new(TexasAirEngine::new(attestor));
    let metrics = Arc::new(poker_appchain::metrics::MetricsRegistry::new());
    let pipeline = poker_appchain::pipeline::ProofPipeline::with_real_policy(
        poker_appchain::pipeline::PipelineConfig {
            workers: 1,
            batch_size: 1,
            queue_bound: 8,
            high_watermark: 8,
            batch_interval_ms: 1_000,
        },
        engine,
        Arc::clone(&metrics),
        poker_appchain::real_policy::RealSettlementPolicy {
            mode: poker_appchain::real_policy::RealMode::Disabled,
            verifier_key: Some(pinned_key),
        },
    );
    let err = pipeline
        .submit(settled_real_job(1, &proven_archive(1)))
        .unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::RealRequiresStarkProof
    ));
    assert_eq!(metrics.counter("real_settlement_rejected_total"), 1);
    assert_eq!(pipeline.inflight_count(), 0, "rejected job must not queue");
}

/// REAL 经 texas-air 但 attestor 与钉扎 key 不匹配：prove（真实 stwo）成功、
/// 批次门拒出——op 不标记已证明、水位不动、completion 保留、告警计数。
#[test]
fn real_settlement_verifier_key_mismatch_blocks_batch_and_watermark() {
    let attestor = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    // 钉扎到"错误"的 key（≠ 引擎 attestor）
    let engine: Arc<dyn poker_appchain::pipeline::SettlementProver> =
        Arc::new(TexasAirEngine::new(attestor));
    let metrics = Arc::new(poker_appchain::metrics::MetricsRegistry::new());
    let pipeline = poker_appchain::pipeline::ProofPipeline::with_real_policy(
        poker_appchain::pipeline::PipelineConfig {
            workers: 1,
            batch_size: 1,
            queue_bound: 8,
            high_watermark: 8,
            batch_interval_ms: 1_000,
        },
        engine,
        Arc::clone(&metrics),
        poker_appchain::real_policy::RealSettlementPolicy::stark_required([0xAA; 32]),
    );
    let seq = Arc::new(std::sync::Mutex::new(
        poker_appchain::sequencer::Sequencer::new(
            poker_appchain::keys::SequencerKey::from_seed(&[6u8; 32]),
            poker_appchain::sequencer::SequencerConfig::default(),
            Arc::new(poker_appchain::metrics::MetricsRegistry::new()),
        ),
    ));
    pipeline.set_on_batch_proven({
        let seq = Arc::clone(&seq);
        Arc::new(move |through| seq.lock().unwrap().mark_proven_through(through))
    });
    pipeline
        .submit(settled_real_job(1, &proven_archive(1)))
        .expect("admission prerequisites met (mode/key/hand_proof)");
    for _ in 0..2_000 {
        if pipeline.completed_count() >= 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(
        pipeline.completed_count(),
        1,
        "prove ran the real stwo path"
    );
    let err = pipeline.try_build_batch().unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::VerifierKeyMismatch
    ));
    assert_eq!(
        pipeline.pending_completion_count(),
        1,
        "completion retained (never marked proven)"
    );
    assert_eq!(
        seq.lock().unwrap().proven_watermark(),
        0,
        "watermark must not advance past a pin-mismatched REAL op"
    );
    assert_eq!(metrics.counter("real_settlement_rejected_total"), 1);
}

// ===== scope v2 镜像一致性（appchain 侧 borsh 镜像 ↔ 真实 canonical 归档） =====

#[test]
fn archive_scope_v2_mirror_matches_canonical_archive() {
    let archive = proven_archive(1);
    let bytes = borsh::to_vec(&archive).expect("archive encoding");
    let scope = parse_archive_scope(&bytes).expect("scope v2 must parse canonical archives");
    assert_eq!(scope.log_size, archive.log_size);
    assert_eq!(scope.num_columns, archive.num_columns);
    assert_eq!(scope.table_id, archive.table_id);
    assert_eq!(scope.first_hand_id, archive.first_hand_id);
    assert_eq!(scope.last_hand_id, archive.last_hand_id);
    assert_eq!(scope.first_call_seq, archive.first_call_seq);
    assert_eq!(scope.last_call_seq, archive.last_call_seq);
    assert_eq!(scope.transition_count, archive.transition_count);
    assert_eq!(scope.first_transition_kind, archive.first_transition_kind);
    assert_eq!(scope.last_transition_kind, archive.last_transition_kind);
    assert_eq!(
        scope.reveal_timeout_cascade_count,
        archive.reveal_timeout_cascade_count
    );
    assert_eq!(
        scope.reveal_timeout_cascade_schedule,
        archive.reveal_timeout_cascade_schedule
    );
    assert_eq!(scope.batch_digest, archive.batch_digest);
    assert_eq!(scope.pre_state_commitment, archive.pre_state_commitment);
    assert_eq!(scope.post_state_commitment, archive.post_state_commitment);
    assert_eq!(scope.pre_state_root, archive.pre_state_root);
    assert_eq!(scope.post_state_root, archive.post_state_root);
    assert_eq!(scope.pre_lifecycle_root, archive.pre_lifecycle_root);
    assert_eq!(scope.post_lifecycle_root, archive.post_lifecycle_root);
    assert_eq!(scope.pre_overlay_root, archive.pre_overlay_root);
    assert_eq!(scope.post_overlay_root, archive.post_overlay_root);
    assert_eq!(
        scope.pre_settlement_commitment,
        archive.pre_settlement_commitment
    );
    assert_eq!(
        scope.post_settlement_commitment,
        archive.post_settlement_commitment
    );
    assert_eq!(scope.pre_custody_commitment, archive.pre_custody_commitment);
    assert_eq!(
        scope.post_custody_commitment,
        archive.post_custody_commitment
    );
    assert_eq!(scope.pre_state_image_bytes, archive.pre_state_image_bytes);
    assert_eq!(scope.post_state_image_bytes, archive.post_state_image_bytes);
    assert_eq!(scope.range_claimed_sum, archive.range_claimed_sum);
    assert!(scope.rake_opening.is_none());
    assert!(scope.blind_opening.is_none());
    // 镜像 pot 偏移（P0-2 绑定用） == 真实终态镜像的 pot 字段（ witness pot=500）
    assert_eq!(
        archive.post_state_image_bytes.len(),
        poker_appchain::settlement::CANONICAL_STATE_IMAGE_BORSH_BYTES
    );
    assert_eq!(
        u64::from_le_bytes(
            scope.post_state_image_bytes[poker_appchain::settlement::STATE_IMAGE_POT_OFFSET..][..8]
                .try_into()
                .unwrap()
        ),
        500
    );
    assert_eq!(
        u64::from_le_bytes(
            scope.post_state_image_bytes
                [poker_appchain::settlement::STATE_IMAGE_CHIP_POOL_OFFSET..][..8]
                .try_into()
                .unwrap()
        ),
        500
    );
}

// ===== 正例：真实 prove → 引擎 admit + attest → 独立 verify → 深度篡改必拒 =====

#[test]
fn canonical_stark_proof_end_to_end_admits_and_deep_tamper_rejected() {
    let engine = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));

    // 1. 真实 stwo prove（单 CreateTable 转移，终态镜像 pot=500）
    let archive = proven_archive(1);
    // 2. 引擎 admit：绑定检查 + verify_canonical_tagged_proof（stwo 全约束）
    //    + **含 hand_proof 的完整**结算关系校验（scope v2/状态根/镜像 pot）+
    //    attestation 签发
    let bundle = engine
        .prove(&settled_job(1, &archive))
        .expect("canonical proof must be admitted");
    // 3. verify 独立复验 attestation；篡改 payload 必失败
    engine.verify(&bundle).expect("attestation verify");
    let mut bad_payload = bundle.clone();
    bad_payload.payload[0] ^= 1;
    assert!(matches!(
        engine.verify(&bad_payload).unwrap_err(),
        AppchainError::BadSignature
    ));
    // payload 长度防线（v1 的 96B 载荷不再接受）
    let mut short = bundle.clone();
    short.payload.truncate(96);
    assert!(matches!(
        engine.verify(&short).unwrap_err(),
        AppchainError::AdmissionRejected("bad payload")
    ));

    // 4. 深度篡改 A：LogUp range 关系的公开 claimed sum（混入 Fiat--Shamir
    //    挑战流，其余全部一致）→ 只有真实 stwo 验证器能拒
    let mut tampered_sum = archive.clone();
    tampered_sum.range_claimed_sum[0] ^= 1;
    let err = engine.prove(&settled_job(1, &tampered_sum)).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::AdmissionRejected("archive stark verify failed")
    ));

    // 5. 深度篡改 B：post 端点 state-image 字节拼接（borsh 可解码、声明承诺
    //    不变）→ 归档端点绑定检查必须拒绝
    let mut tampered_image = archive;
    let last = tampered_image.post_state_image_bytes.len() - 1;
    tampered_image.post_state_image_bytes[last] ^= 1;
    let err = engine.prove(&settled_job(1, &tampered_image)).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::AdmissionRejected("archive stark verify failed")
    ));
}
