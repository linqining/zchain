//! 原生基准：verify_case N 次取分位；另测 canonical verify 特有的 scope 重建承诺开销。
//! 用法：bench_native <case_path> <n_iters>

use std::time::Instant;

fn percentile(sorted: &mut [f64], p: f64) -> f64 {
    // 最近秩分位（与 poker-appchain-texasair/perf_baseline 相同口径）。
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: bench_native <case_path> <n_iters>");
        std::process::exit(2);
    }
    let case_path = &args[1];
    let n_iters: usize = args[2].parse().expect("n_iters");

    let bytes = std::fs::read(case_path).expect("read case");
    let case: stwo_wasm_probe::ProbeCase =
        bincode::deserialize(&bytes).expect("deserialize case");
    println!(
        "case: log_size={} n_scope={} n_trace={} n_interaction_base_cols={} proof_bytes={}",
        case.log_size,
        case.n_scope,
        case.n_trace,
        case.n_interaction_base_cols,
        case.stark_proof.len()
    );

    // 正确性先验：一次完整验证必须通过。
    stwo_wasm_probe::verify_case(&case).expect("verify must pass on genuine case");

    // 预热 3 次。
    for _ in 0..3 {
        let _ = stwo_wasm_probe::verify_case(&case);
    }

    let mut samples: Vec<f64> = Vec::with_capacity(n_iters);
    for i in 0..n_iters {
        let t = Instant::now();
        let r = stwo_wasm_probe::verify_case(&case);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        assert!(r.is_ok(), "verify failed at iter {i}: {:?}", r.err());
        samples.push(ms);
    }
    let mut sorted = samples.clone();
    let p50 = percentile(&mut sorted, 0.50);
    let p95 = percentile(&mut sorted, 0.95);
    println!("native_verify_ms: n={} min={:.3} p50={:.3} p95={:.3} max={:.3}",
        n_iters,
        samples.iter().cloned().fold(f64::INFINITY, f64::min),
        p50, p95,
        samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max));
    println!("native_verify_samples_ms: {:?}", samples);

    // canonical verify 特有：SimdBackend scope 重建承诺（twiddles 冷 + 树构建/承诺）。
    let (twiddles_ms, commit_ms) = stwo_wasm_probe::prover_path::scope_recommit_timings(
        case.log_size,
        case.n_scope,
        case.hasher,
    )
    .expect("scope recommit");
    println!("native_scope_recommit_ms: twiddles_cold={twiddles_ms:.3} tree_build_commit={commit_ms:.3}");
}
