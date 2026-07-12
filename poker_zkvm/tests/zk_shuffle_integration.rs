//! ZkShuffle 集成测试（Phase J — J-10）。
//!
//! 端到端验证 ZkShuffle CCS 电路 + DLEq proof + combined proof 格式。

use ark_bn254::{Fr as BnFr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Zero;
use ark_std::{UniformRand, test_rng};

use poker_zkvm::ccs::Fr;
use poker_zkvm::field::ZkvmField;
use poker_zkvm::precompiles::dleq::{
    DleqProof, batch_dleq_prove, batch_dleq_verify, batch_dleq_verify_bytes, generator_bytes,
};
use poker_zkvm::precompiles::elgamal::{
    ElGamalCiphertext, ElGamalPublicKey, g1_to_u256, u256_to_g1,
};
use poker_zkvm::precompiles::zk_shuffle::{
    HostCiphertext, ShufflePublicInput, ShuffleWitness, ZkShuffleCcsCircuit,
};

const BLINDING_COUNT: usize = 8;

// ===== 辅助函数 =====

fn host_ct_from_affine(ct: &ElGamalCiphertext) -> HostCiphertext {
    let (c_x, c_y) = g1_to_u256(&ct.c);
    let (d_x, d_y) = g1_to_u256(&ct.d);
    HostCiphertext { c_x, c_y, d_x, d_y }
}

fn affine_from_host_ct(ct: &HostCiphertext, which: u8) -> G1Affine {
    let (x, y) = if which == 0 {
        (ct.c_x, ct.c_y)
    } else {
        (ct.d_x, ct.d_y)
    };
    u256_to_g1(&x, &y).unwrap_or(G1Affine::identity())
}

fn build_dummy_data(deck_size: usize) -> (ShuffleWitness, ShufflePublicInput) {
    let n = deck_size;
    let mut rng = test_rng();
    let g = G1Projective::generator();

    let sk = BnFr::rand(&mut rng);
    let pk_proj = g * sk;
    let pk_affine = pk_proj.into_affine();

    let (pk_x_u256, pk_y_u256) = g1_to_u256(&pk_affine);
    let pk = {
        let mut pk_arr = [Fr::zero(); 8];
        for k in 0..4 {
            pk_arr[k] = Fr::from_u64(pk_x_u256[k]);
            pk_arr[k + 4] = Fr::from_u64(pk_y_u256[k]);
        }
        pk_arr
    };

    let mut input_cts = Vec::with_capacity(n);
    let mut output_cts = Vec::with_capacity(n);

    for i in 0..n {
        let card_point = (g * BnFr::from(i as u64)).into_affine();
        let r = BnFr::rand(&mut rng);
        let ct = poker_zkvm::precompiles::elgamal::encrypt(
            &ElGamalPublicKey { pk: pk_affine },
            &card_point,
            &r,
        );
        input_cts.push(host_ct_from_affine(&ct));

        let r2 = BnFr::rand(&mut rng);
        let ct2 = poker_zkvm::precompiles::elgamal::reencrypt(
            &ElGamalPublicKey { pk: pk_affine },
            &ct,
            &r2,
        );
        output_cts.push(host_ct_from_affine(&ct2));
    }

    let permutation: Vec<u8> = (0..n as u8).collect();
    let randomizers: Vec<Fr> = (0..n).map(|_| Fr::from_u64(1)).collect();
    let lambda_bnfrs: Vec<BnFr> = (0..n).map(|_| BnFr::rand(&mut rng)).collect();
    let lambda_challenges: Vec<Fr> = lambda_bnfrs.iter().map(|f| Fr::from_fr(*f)).collect();
    let blinding: Vec<Fr> = (0..BLINDING_COUNT).map(|_| Fr::from_u64(1)).collect();

    let mut delta_c_proj = G1Projective::zero();
    let mut delta_d_proj = G1Projective::zero();
    for i in 0..n {
        let sigma_i = permutation[i] as usize;
        let ct_in = ElGamalCiphertext {
            c: affine_from_host_ct(&input_cts[i], 0),
            d: affine_from_host_ct(&input_cts[i], 1),
        };
        let ct_out = ElGamalCiphertext {
            c: affine_from_host_ct(&output_cts[sigma_i], 0),
            d: affine_from_host_ct(&output_cts[sigma_i], 1),
        };
        let dc = G1Projective::from(ct_out.c) - G1Projective::from(ct_in.c);
        let dd = G1Projective::from(ct_out.d) - G1Projective::from(ct_in.d);
        delta_c_proj += dc * lambda_bnfrs[i];
        delta_d_proj += dd * lambda_bnfrs[i];
    }

    let delta_c_affine = delta_c_proj.into_affine();
    let delta_d_affine = delta_d_proj.into_affine();

    let (dc_x, dc_y) = g1_to_u256(&delta_c_affine);
    let (dd_x, dd_y) = g1_to_u256(&delta_d_affine);

    let mut delta_c = [Fr::zero(); 8];
    let mut delta_d = [Fr::zero(); 8];
    for k in 0..4 {
        delta_c[k] = Fr::from_u64(dc_x[k]);
        delta_c[k + 4] = Fr::from_u64(dc_y[k]);
        delta_d[k] = Fr::from_u64(dd_x[k]);
        delta_d[k + 4] = Fr::from_u64(dd_y[k]);
    }

    let public = ShufflePublicInput {
        pk,
        input_commitment: Fr::zero(),
        output_commitment: Fr::zero(),
        delta_c,
        delta_d,
    };

    let witness = ShuffleWitness {
        input_cts,
        output_cts,
        permutation,
        randomizers,
        lambda_challenges,
        blinding,
    };

    (witness, public)
}

// ===== 测试 =====

#[test]
fn test_shuffle_light_mode_valid() {
    let circuit = ZkShuffleCcsCircuit::with_deck_size(4, false);
    let (witness, public) = build_dummy_data(4);
    let (ccs, witness_vec) = circuit
        .build_circuit(&witness, &public)
        .expect("build_circuit");
    assert!(
        ccs.satisfied_by(&witness_vec).expect("satisfied_by"),
        "Light mode CCS 应满足"
    );
}

#[test]
fn test_shuffle_full_mode_valid() {
    let circuit = ZkShuffleCcsCircuit::with_deck_size(4, true);
    let (witness, public) = build_dummy_data(4);
    let (ccs, witness_vec) = circuit
        .build_circuit(&witness, &public)
        .expect("build_circuit");
    assert!(
        ccs.satisfied_by(&witness_vec).expect("satisfied_by"),
        "Full mode CCS 应满足"
    );
}

#[test]
fn test_shuffle_invalid_permutation() {
    let circuit = ZkShuffleCcsCircuit::with_deck_size(4, false);
    let (mut witness, public) = build_dummy_data(4);
    witness.permutation[0] = 99;
    let result = circuit.build_circuit(&witness, &public);
    assert!(result.is_err(), "排列越界应返回 Err");
}

#[test]
fn test_shuffle_ciphertext_tamper_fails() {
    let circuit = ZkShuffleCcsCircuit::with_deck_size(4, false);
    let (mut witness, public) = build_dummy_data(4);
    witness.output_cts[0].c_x[0] = witness.output_cts[0].c_x[0].wrapping_add(1);
    let (ccs, witness_vec) = circuit
        .build_circuit(&witness, &public)
        .expect("build_circuit");
    assert!(
        !ccs.satisfied_by(&witness_vec).expect("satisfied_by"),
        "篡改密文坐标后 CCS 应不满足"
    );
}

#[test]
fn test_shuffle_dleq_valid() {
    let mut rng = test_rng();
    let g = G1Projective::generator().into_affine();
    let sk = BnFr::rand(&mut rng);
    let pk = (G1Projective::generator() * sk).into_affine();
    let r = BnFr::rand(&mut rng);
    let delta_c = (G1Projective::generator() * r).into_affine();
    let delta_d = (G1Projective::from(pk) * r).into_affine();

    let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
    assert!(
        batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &proof),
        "合法 DLEq proof 应验证通过"
    );
}

#[test]
fn test_shuffle_dleq_invalid() {
    let mut rng = test_rng();
    let g = G1Projective::generator().into_affine();
    let sk = BnFr::rand(&mut rng);
    let pk = (G1Projective::generator() * sk).into_affine();
    let r = BnFr::rand(&mut rng);
    let delta_c = (G1Projective::generator() * r).into_affine();
    let delta_d = (G1Projective::from(pk) * r).into_affine();

    let mut proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
    proof.z += BnFr::from(1u64);
    assert!(
        !batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &proof),
        "篡改 DLEq proof 应验证失败"
    );
}

#[test]
fn test_shuffle_dleq_wrong_delta_c() {
    let mut rng = test_rng();
    let g = G1Projective::generator().into_affine();
    let sk = BnFr::rand(&mut rng);
    let pk = (G1Projective::generator() * sk).into_affine();
    let r = BnFr::rand(&mut rng);
    let delta_c = (G1Projective::generator() * r).into_affine();
    let delta_d = (G1Projective::from(pk) * r).into_affine();

    let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
    let wrong_dc = (G1Projective::generator() * BnFr::from(12345u64)).into_affine();
    assert!(
        !batch_dleq_verify(&g, &pk, &wrong_dc, &delta_d, &proof),
        "错误 ΔC 应使 DLEq 验证失败"
    );
}

#[test]
fn test_shuffle_dleq_serialization() {
    let mut rng = test_rng();
    let g = G1Projective::generator().into_affine();
    let sk = BnFr::rand(&mut rng);
    let pk = (G1Projective::generator() * sk).into_affine();
    let r = BnFr::rand(&mut rng);
    let delta_c = (G1Projective::generator() * r).into_affine();
    let delta_d = (G1Projective::from(pk) * r).into_affine();

    let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
    let bytes = proof.to_bytes();
    assert_eq!(bytes.len(), 97);
    let recovered = DleqProof::from_bytes(&bytes).expect("from_bytes");
    assert_eq!(recovered.a, proof.a);
    assert_eq!(recovered.b, proof.b);
    assert_eq!(recovered.z, proof.z);
    assert!(batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &recovered));
}

#[test]
fn test_shuffle_public_input_roundtrip() {
    let (_, public) = build_dummy_data(4);
    let vec = public.to_vec();
    assert_eq!(vec.len(), 26);
    let recovered = ShufflePublicInput::from_vec(&vec).expect("from_vec");
    assert_eq!(recovered.pk, public.pk);
    assert_eq!(recovered.input_commitment, public.input_commitment);
    assert_eq!(recovered.output_commitment, public.output_commitment);
    assert_eq!(recovered.delta_c, public.delta_c);
    assert_eq!(recovered.delta_d, public.delta_d);
}

#[test]
fn test_shuffle_combined_proof_format() {
    let mut rng = test_rng();

    // 生成 DLEq proof
    let g = G1Projective::generator().into_affine();
    let sk = BnFr::rand(&mut rng);
    let pk = (G1Projective::generator() * sk).into_affine();
    let r = BnFr::rand(&mut rng);
    let delta_c = (G1Projective::generator() * r).into_affine();
    let delta_d = (G1Projective::from(pk) * r).into_affine();
    let dleq_proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
    let dleq_bytes = dleq_proof.to_bytes();

    // 构建 combined proof
    let ccs_proof = vec![0xAB; 32];
    let mut combined = Vec::new();
    combined.extend_from_slice(b"ZKSF");
    combined.extend_from_slice(&1u32.to_be_bytes());
    combined.extend_from_slice(&(ccs_proof.len() as u32).to_be_bytes());
    combined.extend_from_slice(&ccs_proof);
    combined.extend_from_slice(&(dleq_bytes.len() as u32).to_be_bytes());
    combined.extend_from_slice(&dleq_bytes);

    // 验证格式
    assert!(combined.len() >= 4 + 4 + 4 + 4 + 97);
    assert_eq!(&combined[0..4], b"ZKSF");
    let version = u32::from_be_bytes(combined[4..8].try_into().unwrap());
    assert_eq!(version, 1);
    let ccs_len = u32::from_be_bytes(combined[8..12].try_into().unwrap()) as usize;
    assert_eq!(ccs_len, 32);

    // 验证 byte-oriented DLEq 验证
    let g_bytes = generator_bytes();
    let pk_bytes = {
        let (x, y) = g1_to_u256(&pk);
        let mut bytes = [0u8; 64];
        for k in 0..4 {
            bytes[k * 8..k * 8 + 8].copy_from_slice(&x[k].to_le_bytes());
            bytes[32 + k * 8..32 + k * 8 + 8].copy_from_slice(&y[k].to_le_bytes());
        }
        bytes
    };
    let dc_bytes = {
        let (x, y) = g1_to_u256(&delta_c);
        let mut bytes = [0u8; 64];
        for k in 0..4 {
            bytes[k * 8..k * 8 + 8].copy_from_slice(&x[k].to_le_bytes());
            bytes[32 + k * 8..32 + k * 8 + 8].copy_from_slice(&y[k].to_le_bytes());
        }
        bytes
    };
    let dd_bytes = {
        let (x, y) = g1_to_u256(&delta_d);
        let mut bytes = [0u8; 64];
        for k in 0..4 {
            bytes[k * 8..k * 8 + 8].copy_from_slice(&x[k].to_le_bytes());
            bytes[32 + k * 8..32 + k * 8 + 8].copy_from_slice(&y[k].to_le_bytes());
        }
        bytes
    };

    assert!(
        batch_dleq_verify_bytes(&g_bytes, &pk_bytes, &dc_bytes, &dd_bytes, &dleq_bytes),
        "byte-oriented DLEq 验证应通过"
    );
}
