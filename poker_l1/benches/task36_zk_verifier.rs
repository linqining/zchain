//! Task 36.3 + 36.4: ZK verifier 基准测试。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md Task 36：
//! - SubTask 36.3: Hypernova fold step 延迟
//!   测量真实 CCS fold_step 单步延迟 + 多步 fold_loop + Fiat-Shamir challenge 派生
//! - SubTask 36.4: Groth16 / IPA verifier 延迟
//!   测量 Groth16 stub verify + CRS fingerprint 计算/校验 + VK 注册
//!   测量 IPA stub verify + 端到端 zk_verify syscall（含 public_io 边界校验）
//!
//! ## Phase 11 迁移说明
//!
//! fold_step / fold_loop 已从 stub（blake2b 哈希链）迁移到真实 Hypernova 折叠
//! （委托 `poker_zkvm::fold::fold_step::fold` / `poker_zkvm::fold::fold_loop::fold_loop`）。
//! Groth16 / IPA verifier 仍为 Stub 状态（仅校验 proof 格式），将在后续 Phase 升级。
//! 这些基准用于：
//! 1. 量化真实 Hypernova fold 的单步/多步延迟
//! 2. 建立 Stub → Production verifier 升级前的性能基线
//! 3. 量化 fold_step_count 规模对 fold_loop 延迟的影响（O15 上限 1000）

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use poker_l1::offline::ccs::{fold_loop_real, fold_step_real};
use poker_l1::offline::groth16::{
    Groth16Proof, Groth16Verifier, Groth16Vk, Groth16VkRegistry, register_groth16_verifier,
};
use poker_l1::offline::hypernova::{
    HYPERNOVA_PROOF_MIN_SIZE, HypernovaVerifier, fiat_shamir_challenge, register_hypernova_verifier,
};
use poker_l1::offline::ipa::{IPA_PROOF_MIN_SIZE, IpaVerifier, register_ipa_verifier};
use poker_l1::offline::zk_verifier::{
    SCHEME_GROTH16, SCHEME_HYPERNOVA, SCHEME_IPA, VerifierStatus, ZkPublicIo, ZkVerifier,
    ZkVerifierRegistry,
};
use poker_l1::{ChainId, DEFAULT_CHAIN_ID};
use poker_zkvm::ccs::{Ccs, Fr as ZkvmFr, SparseMatrix};
use poker_zkvm::field::ZkvmField;
use poker_zkvm::fold::ccccs::Ccccs;
use poker_zkvm::pcs::ipa::{IpaCommitment, IpaPcs};
use poker_zkvm::pcs::{MultilinearPoly, Pcs};
use poker_zkvm::precompiles::elgamal;
use poker_zkvm::transcript::Transcript;

// ===== 测试数据准备 =====

/// 构造 Fr。
fn zkvm_f(v: u32) -> ZkvmFr {
    ZkvmFr::from_u32_with_wrap(v)
}

/// 构造负 Fr。
fn zkvm_neg_f(v: u32) -> ZkvmFr {
    ZkvmFr::zero().sub(&zkvm_f(v))
}

/// 构造 stub commitment（G1 生成元）。
fn stub_commitment() -> IpaCommitment {
    IpaCommitment(elgamal::generator())
}

/// 使用 IPA 计算实际 witness commitment。
fn commit_witness(pcs: &IpaPcs, z: &[ZkvmFr]) -> IpaCommitment {
    let poly = MultilinearPoly::from_evals(z.to_vec()).expect("MultilinearPoly 构造应成功");
    pcs.commit(&poly).expect("pcs.commit 应成功")
}

/// 构造线性 CCS — x - y = 0（1 row, 4 vars, 2 matrices）。
fn make_linear_ccs() -> Ccs {
    let mut m0 = SparseMatrix::new(1, 4);
    m0.add_entry(0, 1, zkvm_f(1)).unwrap();
    let mut m1 = SparseMatrix::new(1, 4);
    m1.add_entry(0, 2, zkvm_f(1)).unwrap();

    Ccs::new(
        4,
        vec![m0, m1],
        vec![vec![0], vec![1]],
        vec![zkvm_f(1), zkvm_neg_f(1)],
    )
    .expect("linear Ccs 构造应成功")
}

/// 构造 IPA PCS（max_n_vars = 4，支持最多 16 个变量的 witness）。
fn make_ipa_pcs() -> IpaPcs {
    IpaPcs::new(4).expect("IpaPcs 构造应成功")
}

/// 构造 ZK public_io（用于 verifier 基准）。
fn make_public_io(fold_step_count: u32) -> ZkPublicIo {
    ZkPublicIo {
        initial_commitment: [0x01; 32],
        final_commitment: [0x02; 32],
        state_delta_hash: [0x03; 32],
        ack_chain_hash: [0x04; 32],
        fold_step_count,
        skip_count: 0,
        segment_continuity_proof: Vec::new(),
    }
}

/// 构造 Groth16 VK（用于 CRS fingerprint 基准）。
fn make_groth16_vk() -> Groth16Vk {
    Groth16Vk {
        alpha_g1: [0x01; 48],
        beta_g2: [0x02; 96],
        gamma_g2: [0x03; 96],
        delta_g2: [0x04; 96],
        ic: vec![[0x05; 48], [0x06; 48], [0x07; 48]],
    }
}

/// 构造 Groth16 proof 字节（A + B + C = 192 字节）。
fn make_groth16_proof() -> Vec<u8> {
    Groth16Proof {
        a_g1: [0xAA; 48],
        b_g2: [0xBB; 96],
        c_g1: [0xCC; 48],
    }
    .to_bytes()
}

/// 构造 Hypernova proof 字节（>= MIN_SIZE = 64）。
fn make_hypernova_proof() -> Vec<u8> {
    vec![0xAA; HYPERNOVA_PROOF_MIN_SIZE]
}

/// 构造 IPA proof 字节（>= MIN_SIZE = 32）。
fn make_ipa_proof() -> Vec<u8> {
    vec![0xBB; IPA_PROOF_MIN_SIZE]
}

// ===== SubTask 36.3: Hypernova fold step 延迟 =====

/// 测量单步 fold_step_real 延迟（真实 Hypernova fold）。
fn bench_fold_step_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("task36_3_fold_step_single");
    group.sample_size(100);

    let ccs = make_linear_ccs();
    let z_l = vec![zkvm_f(1), zkvm_f(5), zkvm_f(5), zkvm_f(0)];
    let z_c = vec![zkvm_f(1), zkvm_f(3), zkvm_f(3), zkvm_f(0)];
    let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
    let ccccs = ccs
        .to_cccs(&z_c, vec![], stub_commitment())
        .expect("to_cccs");

    group.bench_function("single_fold", |b| {
        b.iter(|| {
            let mut transcript = Transcript::new();
            let result = fold_step_real(
                black_box(&lcccs),
                black_box(&stub_commitment()),
                black_box(&ccccs),
                black_box(&mut transcript),
            )
            .expect("fold_step_real");
            black_box(result);
        });
    });

    group.finish();
}

/// 测量多步 fold_loop_real 延迟（真实 Hypernova fold_loop，不同步数）。
///
/// 测试规模：10 / 100 / 1000 步（O15 上限边界）。
fn bench_fold_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("task36_3_fold_loop");
    group.sample_size(20);

    let ccs = make_linear_ccs();
    let pcs = make_ipa_pcs();
    let ccs_commitment = ccs.ccs_commitment();

    for &steps in &[10usize, 100, 1000] {
        let z_l = vec![zkvm_f(1), zkvm_f(5), zkvm_f(5), zkvm_f(0)];
        let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
        let initial_cmt = commit_witness(&pcs, &z_l);

        let ccccs_instances: Vec<Ccccs> = (0..steps)
            .map(|i| {
                let z_c = vec![
                    zkvm_f(1),
                    zkvm_f((i % 100) as u32 + 1),
                    zkvm_f((i % 100) as u32 + 1),
                    zkvm_f(0),
                ];
                let cmt = commit_witness(&pcs, &z_c);
                ccs.to_cccs(&z_c, vec![], cmt).expect("to_cccs")
            })
            .collect();

        group.throughput(Throughput::Elements(steps as u64));

        group.bench_with_input(
            BenchmarkId::new("fold_loop_real", format!("steps_{}", steps)),
            &ccccs_instances,
            |b, ccccs_instances| {
                b.iter(|| {
                    let mut transcript = Transcript::new();
                    let result = fold_loop_real(
                        black_box(&ccs),
                        black_box(lcccs.clone()),
                        black_box(initial_cmt.clone()),
                        black_box(ccccs_instances),
                        black_box(&pcs),
                        black_box(&mut transcript),
                        black_box(ccs_commitment),
                        black_box([0u8; 32]),
                        black_box(vec![vec![]]),
                    )
                    .expect("fold_loop_real");
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

/// 测量 Fiat-Shamir challenge 派生延迟。
fn bench_fiat_shamir_challenge(c: &mut Criterion) {
    let public_io = make_public_io(10);

    c.bench_function("task36_3_fiat_shamir_challenge", |b| {
        b.iter(|| {
            let challenge = fiat_shamir_challenge(black_box(&public_io));
            black_box(challenge);
        });
    });
}

// ===== SubTask 36.4: Groth16 / IPA verifier 延迟 =====

/// 测量 Groth16 verifier stub 延迟（含 proof 格式校验）。
fn bench_groth16_verify(c: &mut Criterion) {
    let verifier = Groth16Verifier::new();
    let public_io = make_public_io(1);
    let proof = make_groth16_proof();

    c.bench_function("task36_4_groth16_verify_stub", |b| {
        b.iter(|| {
            let result = verifier
                .verify(
                    black_box(&proof),
                    black_box(&public_io),
                    black_box(VerifierStatus::Stub),
                )
                .expect("groth16 stub verify");
            black_box(result);
        });
    });

    // proof 格式校验（不含 verify）
    c.bench_function("task36_4_groth16_validate_format", |b| {
        b.iter(|| {
            verifier
                .validate_proof_format(black_box(&proof))
                .expect("format ok");
        });
    });
}

/// 测量 Groth16 CRS fingerprint 计算与校验延迟（SEC-M10）。
fn bench_groth16_crs_fingerprint(c: &mut Criterion) {
    let vk = make_groth16_vk();
    let mut registry = Groth16VkRegistry::new();
    let vk_id = registry.register(vk.clone()).expect("register vk");

    // CRS fingerprint 计算（blake2b_256 哈希）
    c.bench_function("task36_4_groth16_crs_fingerprint_compute", |b| {
        b.iter(|| {
            let fp = black_box(&vk).crs_fingerprint();
            black_box(fp);
        });
    });

    // CRS fingerprint 校验（注册表查找 + 比对）
    c.bench_function("task36_4_groth16_crs_fingerprint_verify", |b| {
        b.iter(|| {
            registry
                .verify_crs_fingerprint(black_box(&vk_id))
                .expect("fingerprint match");
        });
    });

    // VK 注册（含 blake2b 哈希计算 + BTreeMap 插入）
    c.bench_function("task36_4_groth16_vk_register", |b| {
        b.iter(|| {
            let mut reg = Groth16VkRegistry::new();
            let id = reg.register(black_box(vk.clone())).expect("register");
            black_box(id);
        });
    });
}

/// 测量 IPA verifier stub 延迟（含 proof 格式校验）。
fn bench_ipa_verify(c: &mut Criterion) {
    let verifier = IpaVerifier::new();
    let public_io = make_public_io(1);
    let proof = make_ipa_proof();

    c.bench_function("task36_4_ipa_verify_stub", |b| {
        b.iter(|| {
            let result = verifier
                .verify(
                    black_box(&proof),
                    black_box(&public_io),
                    black_box(VerifierStatus::Stub),
                )
                .expect("ipa stub verify");
            black_box(result);
        });
    });

    c.bench_function("task36_4_ipa_validate_format", |b| {
        b.iter(|| {
            verifier
                .validate_proof_format(black_box(&proof))
                .expect("format ok");
        });
    });
}

/// 测量端到端 zk_verify syscall 延迟（含 public_io 校验 + verifier 查找 + proof 验证）。
///
/// 覆盖三种 scheme 的完整 zk_verify 路径：
/// - Hypernova: 查找 verifier → 校验 public_io → 校验格式 → Stub 返回 true
/// - Groth16:   查找 verifier → 校验 public_io → 校验格式 → Stub 返回 true
/// - IPA:       查找 verifier → 校验 public_io → 校验格式 → Stub 返回 true
fn bench_zk_verify_syscall(c: &mut Criterion) {
    let mut group = c.benchmark_group("task36_4_zk_verify_syscall");
    group.sample_size(50);

    let mut registry = ZkVerifierRegistry::new();
    register_hypernova_verifier(&mut registry);
    register_groth16_verifier(&mut registry);
    register_ipa_verifier(&mut registry);

    let public_io = make_public_io(5);
    let hypernova_proof = make_hypernova_proof();
    let groth16_proof = make_groth16_proof();
    let ipa_proof = make_ipa_proof();

    let chain_id: ChainId = DEFAULT_CHAIN_ID;
    let max_skip = 3u32;
    let max_ack = 1000u32;

    group.bench_function("hypernova", |b| {
        b.iter(|| {
            let result = registry
                .zk_verify(
                    black_box(chain_id),
                    black_box(SCHEME_HYPERNOVA),
                    black_box(&hypernova_proof),
                    black_box(&public_io),
                    black_box(max_skip),
                    black_box(max_ack),
                )
                .expect("zk_verify hypernova");
            black_box(result);
        });
    });

    group.bench_function("groth16", |b| {
        b.iter(|| {
            let result = registry
                .zk_verify(
                    black_box(chain_id),
                    black_box(SCHEME_GROTH16),
                    black_box(&groth16_proof),
                    black_box(&public_io),
                    black_box(max_skip),
                    black_box(max_ack),
                )
                .expect("zk_verify groth16");
            black_box(result);
        });
    });

    group.bench_function("ipa", |b| {
        b.iter(|| {
            let result = registry
                .zk_verify(
                    black_box(chain_id),
                    black_box(SCHEME_IPA),
                    black_box(&ipa_proof),
                    black_box(&public_io),
                    black_box(max_skip),
                    black_box(max_ack),
                )
                .expect("zk_verify ipa");
            black_box(result);
        });
    });

    group.finish();
}

/// 测量 Hypernova verifier stub 延迟（对照 IPA / Groth16）。
fn bench_hypernova_verify(c: &mut Criterion) {
    let verifier = HypernovaVerifier::new();
    let public_io = make_public_io(5);
    let proof = make_hypernova_proof();

    c.bench_function("task36_4_hypernova_verify_stub", |b| {
        b.iter(|| {
            let result = verifier
                .verify(
                    black_box(&proof),
                    black_box(&public_io),
                    black_box(VerifierStatus::Stub),
                )
                .expect("hypernova stub verify");
            black_box(result);
        });
    });

    c.bench_function("task36_4_hypernova_validate_format", |b| {
        b.iter(|| {
            verifier
                .validate_proof_format(black_box(&proof))
                .expect("format ok");
        });
    });
}

criterion_group!(
    benches,
    // SubTask 36.3: Hypernova fold step
    bench_fold_step_single,
    bench_fold_loop,
    bench_fiat_shamir_challenge,
    bench_hypernova_verify,
    // SubTask 36.4: Groth16 / IPA verifier
    bench_groth16_verify,
    bench_groth16_crs_fingerprint,
    bench_ipa_verify,
    bench_zk_verify_syscall,
);
criterion_main!(benches);
