//! Phase 5.4 — 并行证明配置性能基准。
//!
//! **目标**：测量不同并行配置下的实际最低证明延迟，验证 Phase 5.1/5.2/5.3 的并行化收益。
//!
//! ## 基准维度
//!
//! 1. **`prove_e2e`** — 端到端 `prove()` 时间（ELF 校验 + 执行 + CCS 编译 + Hypernova 折叠 + 序列化）
//!    - 扫描 `rayon_threads`: 1 / 2 / 4 / 8
//!    - 基线：`parallel_ccs_compile = false`（顺序路径）
//!    - 使用真实 texas_poker 合约 ELF（`build_texas_poker_full_hand_elf`）
//! 2. **`ccs_compile`** — 隔离 CCS 编译时间（parallel vs sequential）
//!    - 使用小 batch_size=10 强制多 batch，放大并行收益
//! 3. **`verify`** — `verify_production()` 验证时间
//!
//! ## 运行方式
//!
//! ```bash
//! # 完整基准（约 10-30 分钟）
//! cargo bench -p poker_zkvm --features test-helpers --bench prove_bench
//!
//! # 仅运行 prove_e2e 组（快速，约 3-5 分钟）
//! cargo bench -p poker_zkvm --features test-helpers --bench prove_bench -- prove_e2e
//!
//! # 仅运行特定线程数
//! cargo bench -p poker_zkvm --features test-helpers --bench prove_bench -- \
//!   "prove_e2e/parallel/threads_4"
//! ```
//!
//! ## 输出解读
//!
//! Criterion 会输出每个配置的：
//! - **mean** — 平均时间（ms）
//! - **median** — 中位数时间
//! - **change** — 相对基线的变化百分比（负数 = 加速）
//!
//! 最低 mean 的配置即为该硬件上的"实际最低证明延迟"配置。

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use poker_zkvm::constraints::compile_trace_to_ccs_with_config;
use poker_zkvm::field::ZkvmField;
use poker_zkvm::isa::executor::{ZkvmExecutionConfig, execute_elf_with_config};
use poker_zkvm::prover::{
    MAX_PROOF_TOTAL_SIZE, ProverConfig, default_ccs_registry, prove,
};
use poker_zkvm::syscalls::StubHostState;
use poker_zkvm::test_helpers::{build_texas_poker_full_hand_elf, make_full_hand_input};
use poker_zkvm::verifier::verify_production;

/// 待扫描的 rayon 线程数列表。
///
/// 1 = 单线程（最慢基线）；2/4/8 = 多线程并行。
/// 8 通常覆盖主流 8C/16T 桌面 CPU；更高线程数收益递减（CCS 编译为 CPU 密集型）。
const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8];

/// P1 牌型：A,K,Q,J,10 — straight A-high（category=5，最强非 flush 牌型）
const P1_HAND: [u8; 5] = [14, 13, 12, 11, 10];

/// P2 牌型：2,2,3,4,5 — 一对 2（category=1，弱牌）
const P2_HAND: [u8; 5] = [2, 2, 3, 4, 5];

// ===========================================================================
// 基准 1：prove_e2e — 端到端 prove() 时间
// ===========================================================================

/// 端到端 prove() 基准 — 使用真实 texas_poker 合约 ELF + 生产 batch_size=256。
///
/// 扫描 4 种线程配置 + 1 个顺序基线，共 5 个测试点。
/// 每个测试点采样 10 次（prove 较慢，减少采样以控制总时长）。
fn bench_prove_e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove_e2e");
    group.sample_size(10); // prove 单次 ~1-10s，10 采样足够统计置信区间

    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input(P1_HAND, P2_HAND);

    // --- 基线：顺序路径（parallel_ccs_compile = false, rayon_threads = None）---
    let config_seq = ProverConfig {
        batch_size: 256,
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        parallel_ccs_compile: false,
        rayon_threads: None,
        ..Default::default()
    };
    group.bench_function("sequential_baseline", |b| {
        b.iter(|| {
            let (proof, io) = prove(black_box(&elf), black_box(&input), black_box(&config_seq))
                .expect("prove 应成功");
            black_box((proof, io));
        });
    });

    // --- 并行路径：扫描 rayon_threads ---
    for &n in THREAD_COUNTS {
        let config = ProverConfig {
            batch_size: 256,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            parallel_ccs_compile: true,
            rayon_threads: Some(n),
            ..Default::default()
        };
        group.bench_with_input(
            BenchmarkId::new("parallel", format!("threads_{}", n)),
            &n,
            |b, _| {
                b.iter(|| {
                    let (proof, io) =
                        prove(black_box(&elf), black_box(&input), black_box(&config))
                            .expect("prove 应成功");
                    black_box((proof, io));
                });
            },
        );
    }

    group.finish();
}

// ===========================================================================
// 基准 2：ccs_compile — 隔离 CCS 编译时间
// ===========================================================================

/// 隔离 CCS 编译时间基准 — 使用小 batch_size=10 强制多 batch，放大并行收益。
///
/// texas_poker full hand trace ~250 步 / batch_size=10 = 25 batches，
/// 足以体现 rayon 并行加速比。
fn bench_ccs_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("ccs_compile");
    group.sample_size(20); // CCS 编译较快，可增加采样

    // 构造 trace：执行 texas_poker ELF 一次，复用其 trace
    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input(P1_HAND, P2_HAND);
    // 直接执行 ELF 获取 trace（不经过 prove 全流程，避免 CCS/fold 开销干扰）
    let exec_config = ZkvmExecutionConfig {
        input: input.clone(),
        randomness_seed: poker_zkvm::ccs::Fr::zero().into_fr(),
        initial_commitment: poker_zkvm::ccs::Fr::zero().into_fr(),
        final_commitment: poker_zkvm::ccs::Fr::zero().into_fr(),
        host_state: Box::new(StubHostState),
    };
    let exec_result = execute_elf_with_config(&elf, exec_config).expect("执行应成功");
    let trace = exec_result.trace;

    // --- 顺序路径 ---
    group.bench_function("sequential", |b| {
        b.iter(|| {
            let instances = compile_trace_to_ccs_with_config(
                black_box(&trace),
                black_box(10),
                black_box(false),
            )
            .expect("CCS 编译应成功");
            black_box(instances);
        });
    });

    // --- 并行路径：扫描线程数 ---
    for &n in THREAD_COUNTS {
        // 使用 rayon::ThreadPoolBuilder 限定线程池作用域
        group.bench_with_input(
            BenchmarkId::new("parallel", format!("threads_{}", n)),
            &n,
            |b, &n| {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build()
                    .expect("rayon 线程池构造应成功");
                b.iter(|| {
                    let instances = pool.install(|| {
                        compile_trace_to_ccs_with_config(
                            black_box(&trace),
                            black_box(10),
                            black_box(true),
                        )
                        .expect("CCS 编译应成功")
                    });
                    black_box(instances);
                });
            },
        );
    }

    group.finish();
}

// ===========================================================================
// 基准 3：verify — verify_production() 验证时间
// ===========================================================================

/// verify_production() 基准 — 验证 proof 字节合法性。
///
/// verify 是链上节点的关键路径，其延迟决定 checkin 交易的确认时间。
fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    group.sample_size(20);

    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input(P1_HAND, P2_HAND);
    let config = ProverConfig {
        batch_size: 256,
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        ..Default::default()
    };
    let (proof_bytes, public_io) = prove(&elf, &input, &config).expect("prove 应成功");
    let ccs_registry = default_ccs_registry();

    group.bench_function("verify_production", |b| {
        b.iter(|| {
            let valid = verify_production(
                black_box(&proof_bytes),
                black_box(&public_io),
                black_box(&ccs_registry),
            )
            .expect("verify 应成功");
            black_box(valid);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_prove_e2e, bench_ccs_compile, bench_verify);
criterion_main!(benches);
