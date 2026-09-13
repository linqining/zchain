//! 原生出证：生成探针 demo 用例（bincode ProbeCase）。
//! 用法：gen_proof <log_size> <n_scope> <n_trace> <poseidon|blake2s> <out_path>

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!("usage: gen_proof <log_size> <n_scope> <n_trace> <poseidon|blake2s> <out_path>");
        return ExitCode::FAILURE;
    }
    let log_size: u32 = args[1].parse().expect("log_size");
    let n_scope: usize = args[2].parse().expect("n_scope");
    let n_trace: usize = args[3].parse().expect("n_trace");
    let hasher = match args[4].as_str() {
        "poseidon" => stwo_wasm_probe::HASHER_POSEIDON252,
        "blake2s" => stwo_wasm_probe::HASHER_BLAKE2S,
        other => panic!("unknown hasher: {other}"),
    };
    let out_path = &args[5];

    let t0 = std::time::Instant::now();
    let (case, committed_log_sizes) =
        match stwo_wasm_probe::prover_path::prove_case(log_size, n_scope, n_trace, hasher) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("prove_case failed: {e}");
                return ExitCode::FAILURE;
            }
        };
    let prove_ms = t0.elapsed().as_secs_f64() * 1e3;

    for (i, sizes) in committed_log_sizes.iter().enumerate() {
        println!(
            "tree{i}: n_cols={} uniform_log_size={}",
            sizes.len(),
            sizes.first().copied().unwrap_or(0)
        );
    }
    println!(
        "proof_bytes={} n_interaction_base_cols={} range_claimed={:?}",
        case.stark_proof.len(),
        case.n_interaction_base_cols,
        case.range_claimed
    );
    println!("prove_ms={prove_ms:.1}");

    match std::fs::write(out_path, bincode::serialize(&case).expect("serialize case")) {
        Ok(()) => {
            println!("wrote {out_path}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("write failed: {e}");
            ExitCode::FAILURE
        }
    }
}
