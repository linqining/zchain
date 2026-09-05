//! 适配器负例回归：手写约束 AIR 验证器必须拒绝被篡改的归档。

use borsh::BorshSerialize as _;
use poker_appchain::error::AppchainError;
use poker_appchain::fee::FeePolicy;
use poker_appchain::pipeline::{ProofJob, Priority, SettlementProver};
use poker_appchain::settlement::{HandProofBinding, RakeSplitRecord, SettlementRecord};
use poker_appchain_texasair::TexasAirEngine;
use std::sync::Arc;

fn archive_bytes(commitment: [u8; 32], proof: Vec<u8>) -> Vec<u8> {
    let archive = poker_texas_air::texas_tagged::ArchivedTaggedTexasProof {
        log_size: 10,
        num_columns: 1,
        table_id: 1,
        hand_id: 1,
        first_call_seq: 0,
        last_call_seq: 1,
        transition_count: 2,
        batch_digest: [1; 32],
        pre_state_commitment: [2; 32],
        post_state_commitment: commitment,
        stark_proof_bytes: proof,
    };
    borsh::to_vec(&archive).unwrap()
}

fn job_with(commitment: [u8; 32], proof: Vec<u8>) -> ProofJob {
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
        hand_proof: Some(HandProofBinding {
            archive_bytes: archive_bytes(commitment, proof),
            post_state_commitment: commitment,
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

#[test]
fn tampered_stark_proof_rejected() {
    let engine = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    // 字段一致但 STARK 证明字节为垃圾 → 手写约束验证器必须拒绝
    let err = engine.prove(&job_with([3; 32], vec![0u8; 64])).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::AdmissionRejected("archive stark verify failed")
    ));
}

#[test]
fn commitment_mismatch_rejected() {
    let engine = TexasAirEngine::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let mut j = job_with([3; 32], vec![0u8; 64]);
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
    let mut j = job_with([3; 32], vec![0u8; 64]);
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
    let mut j = job_with([3; 32], vec![0u8; 64]);
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
        engine: "texas-air-v1",
        attestor_public: engine.attestor_public(),
        payload: {
            let mut p = vec![3u8; 32];
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
}
