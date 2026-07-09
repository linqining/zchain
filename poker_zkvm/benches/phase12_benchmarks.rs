//! Phase 12 性能基准 — prover 时间 / proof 大小 / verifier 时间 vs trace 步数。
//!
//! 基准维度：
//! - **prover_time**：`prove()` 端到端时间（ELF 校验 + 执行 + CCS 编译 + Hypernova 折叠 + 序列化）
//! - **proof_size**：序列化后的 proof 字节数
//! - **verifier_time**：`verify_production()` 验证时间
//!
//! 步数梯度：100 / 500 / 1000 步
//! - MVP 限制：batch_size=3（唯一满足 num_vars=4=2^2 且 num_rows=2=2^1 的值）
//! - 100 步 → 34 batches，500 步 → 167 batches，1000 步 → 334 batches（均 ≤ MAX_FOLD_STEP_COUNT=1000）

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use poker_zkvm::prover::{prove, MAX_PROOF_TOTAL_SIZE, MAX_ZKVM_PROOF_SIZE, ProverConfig};
use poker_zkvm::test_helpers::build_nop_elf;
use poker_zkvm::verifier::verify_production;

/// 基准步数列表
const STEP_COUNTS: &[usize] = &[100, 500, 1000];

/// MVP 限制下唯一合法的 batch_size（num_vars=4=2^2 且 num_rows=2=2^1）
const BATCH_SIZE: usize = 3;

/// 端到端 prover 基准：prove() 全流程时间
fn bench_prover_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("prover_time");
    group.sample_size(10); // prove 较慢，减少采样数

    for &steps in STEP_COUNTS {
        let batch_size = BATCH_SIZE;
        let elf = build_nop_elf(steps);
        let config = ProverConfig {
            batch_size,
            ..Default::default()
        };

        group.throughput(Throughput::Elements(steps as u64));
        group.bench_with_input(
            BenchmarkId::new("prove", format!("steps_{}", steps)),
            &steps,
            |b, _| {
                b.iter(|| {
                    let (proof_bytes, public_io) =
                        prove(black_box(&elf), black_box(&[]), black_box(&config))
                            .expect("prove 应成功");
                    black_box((proof_bytes, public_io));
                });
            },
        );
    }
    group.finish();
}

/// proof 大小基准：序列化后的字节数
fn bench_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size");

    for &steps in STEP_COUNTS {
        let batch_size = BATCH_SIZE;
        let elf = build_nop_elf(steps);
        let config = ProverConfig {
            batch_size,
            ..Default::default()
        };

        let (proof_bytes, _) = prove(&elf, &[], &config).expect("prove 应成功");
        let size = proof_bytes.len();

        group.bench_function(format!("steps_{}", steps), |b| {
            b.iter(|| {
                assert!(size <= MAX_ZKVM_PROOF_SIZE, "proof 过大");
                assert!(size <= MAX_PROOF_TOTAL_SIZE, "proof 超 M2-002 上限");
                black_box(size);
            });
        });

        // 输出 proof 大小信息
        println!(
            "  proof_size(steps={}) = {} bytes (limit={}, batch_size={})",
            steps, size, MAX_ZKVM_PROOF_SIZE, batch_size
        );
    }
    group.finish();
}

/// verifier 时间基准：verify_production() 验证时间
fn bench_verifier_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier_time");
    group.sample_size(10);

    for &steps in STEP_COUNTS {
        let batch_size = BATCH_SIZE;
        let elf = build_nop_elf(steps);
        let config = ProverConfig {
            batch_size,
            ..Default::default()
        };

        // 预生成 proof
        let (proof_bytes, public_io) = prove(&elf, &[], &config).expect("prove 应成功");

        group.throughput(Throughput::Elements(steps as u64));
        group.bench_with_input(
            BenchmarkId::new("verify", format!("steps_{}", steps)),
            &steps,
            |b, _| {
                b.iter(|| {
                    let ccs_whitelist = poker_zkvm::prover::default_ccs_whitelist();
                    let ok = verify_production(
                        black_box(&proof_bytes),
                        black_box(&public_io),
                        black_box(&ccs_whitelist),
                    )
                        .expect("verify 应成功");
                    assert!(ok);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_prover_time, bench_proof_size, bench_verifier_time);
criterion_main!(benches);
