//! poker-zkvm-demo：在 zkvm 中完成完整一手牌并记录性能日志。
//!
//! # 流程概览
//!
//! 1. **Phase D — 链上 RPC 创建桌子**（可选，`--local-only` 跳过）
//!    - `create_table → join_table ×2 → start_hand`
//!    - 提取 52 张加密牌序（链上 BLS12-381 数据作"牌序权威源"）
//! 2. **Phase C — sigma 协议本地编排**（host 端，BLS12-381，复用 poker_protocol）
//!    - `ZKShuffleProof` prove + verify + 测时
//!    - `RevealTokenAndProof` prove + verify + 测时
//!    - `ReconstructProof` prove + verify + 测时
//! 3. **Phase B — RV32I zkvm 牌型评估+比较**（BN254 Hypernova proof）
//!    - `build_poker_hand_eval_v2_elf ×2`（P1, P2）
//!    - `build_poker_hand_compare_elf`
//!    - 每步 `prove` + `verify_production` + 测时 + proof_size
//! 4. **Phase E — 性能日志**（tracing 双写 stderr + 文件，末尾追加 JSON 摘要）
//!
//! # 关键语义
//!
//! - **sigma_stage**：host 端 sigma 协议（Fiat-Shamir + Schnorr-like），不经过 RV32I/Hypernova
//! - **rv32i_stage**：真实 zkvm proof（`prover::prove` → `verifier::verify_production`，Hypernova 折叠）
//! - 两段分别测时、分别报告，避免性能评估混淆
//!
//! # 曲线说明
//!
//! - **BLS12-381**：业务逻辑层（链上 + poker_protocol sigma 协议）
//! - **BN254**：zkvm 电路层（RV32I 牌型评估+比较的 Hypernova proof）
//!
//! # 用法
//!
//! ```text
//! # 本地模式（无链上 RPC，快速验证 zkvm 性能）
//! zchain poker-zkvm-demo --local-only --log-file /tmp/zkvm_poker_perf_local.log
//!
//! # 链上模式（真实 RPC 数据源）
//! zchain poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_poker_perf_onchain.log
//! ```

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use tracing::info;

use poker_protocol::crypto::curve::{Curve, CurveScalar, ElGamalCiphertextGeneric};
use poker_protocol::crypto::types::{DefaultCurve, ElGamalCiphertext};
use poker_protocol::zk_shuffle::leave_proof::{leave_ciphertext, LeaveProof};
use poker_protocol::zk_shuffle::remask_proof::{remask_ciphertext, RemaskProof};
use poker_protocol::zk_shuffle::reconstruction::{reconstruct_deck, ReconstructProof};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};

use poker_l1::vm::contracts::texas_poker::utils::generate_plaintext_cards;

use poker_zkvm::prover::{
    MAX_PROOF_TOTAL_SIZE, ProverConfig as ZkvmProverConfig, default_ccs_registry,
    prove as zkvm_prove,
};
use poker_zkvm::prover::partial::{
    PartialProveState, prove_final_fold, prove_partial_fold, prove_partial_start,
};
use poker_zkvm::test_helpers::{
    build_poker_hand_compare_elf, build_poker_hand_eval_v2_elf,
    build_texas_poker_full_hand_elf, make_full_hand_input,
};
use poker_zkvm::verifier::verify_production as zkvm_verify_production;

/// 性能摘要（JSON 序列化写入日志末尾）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct PerfSummary {
    /// ISO 8601 时间戳。
    pub timestamp: String,
    /// 运行模式（"local" 或 "onchain"）。
    pub mode: String,
    /// RPC 端点（onchain 模式）。
    pub rpc_endpoint: Option<String>,
    /// 曲线适配说明。
    pub curve_adaptation: String,
    /// 链上 table_id（onchain 模式）。
    pub onchain_table_id: Option<String>,
    /// 链上 tx 数量（onchain 模式）。
    pub onchain_tx_count: Option<u32>,
    /// 链上最终 block 高度（onchain 模式）。
    pub onchain_final_block: Option<u64>,
    /// sigma 协议阶段耗时。
    pub sigma_stage: SigmaStageTimings,
    /// RV32I zkvm 阶段耗时。
    pub rv32i_stage: Rv32iStageTimings,
    /// LCCCS 分阶段提交耗时（`--partial-prove-demo` 启用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_prove_stage: Option<PartialProveStageTimings>,
    /// Phase 5.5 — 并行配置扫描结果（`--parallel-sweep` 启用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_sweep: Option<ParallelSweepResult>,
    /// Phase 5.5 — 全局并行线程配置（`--parallel-threads <n>` 启用；None = 使用默认全局线程池）。
    pub parallel_threads: Option<usize>,
    /// 总耗时（毫秒）。
    pub total_time_ms: f64,
    /// 赢家（1=P1, 2=P2, 0=平局）。
    pub winner: u8,
}

/// sigma 协议阶段耗时（毫秒）。
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct SigmaStageTimings {
    /// ZKShuffleProof prove 耗时。
    pub shuffle_prove_ms: f64,
    /// ZKShuffleProof verify 耗时。
    pub shuffle_verify_ms: f64,
    /// RevealTokenAndProof prove 耗时。
    pub reveal_prove_ms: f64,
    /// RevealTokenAndProof verify 耗时。
    pub reveal_verify_ms: f64,
    /// ReconstructProof prove 耗时。
    pub reconstruct_prove_ms: f64,
    /// ReconstructProof verify 耗时。
    pub reconstruct_verify_ms: f64,
    /// RemaskProof prove 耗时。
    pub remask_prove_ms: f64,
    /// RemaskProof verify 耗时。
    pub remask_verify_ms: f64,
    /// LeaveProof prove 耗时。
    pub leave_prove_ms: f64,
    /// LeaveProof verify 耗时。
    pub leave_verify_ms: f64,
}

/// RV32I zkvm 阶段耗时（毫秒）+ proof 大小。
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Rv32iStageTimings {
    /// P1 牌型评估 prove 耗时。
    pub eval_p1_prove_ms: f64,
    /// P1 牌型评估 verify 耗时。
    pub eval_p1_verify_ms: f64,
    /// P1 proof 字节数。
    pub eval_p1_proof_size_bytes: usize,
    /// P2 牌型评估 prove 耗时。
    pub eval_p2_prove_ms: f64,
    /// P2 牌型评估 verify 耗时。
    pub eval_p2_verify_ms: f64,
    /// P2 proof 字节数。
    pub eval_p2_proof_size_bytes: usize,
    /// 牌型比较 prove 耗时。
    pub compare_prove_ms: f64,
    /// 牌型比较 verify 耗时。
    pub compare_verify_ms: f64,
    /// 比较 proof 字节数。
    pub compare_proof_size_bytes: usize,
}

/// LCCCS 分阶段提交耗时（Phase 4.2 — `--partial-prove-demo` 启用）。
///
/// 对比直接 `prove()` 与三阶段（start + N × fold + final_fold）的性能与等价性。
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct PartialProveStageTimings {
    /// `prove_partial_start` 耗时（ELF 执行 + CCS 编译 + 初始 LCCCS 锚定）。
    pub start_ms: f64,
    /// 单步 `prove_partial_fold` 平均耗时（毫秒）。
    pub fold_avg_ms: f64,
    /// `prove_partial_fold` 总耗时（毫秒，所有 fold 步累加）。
    pub fold_total_ms: f64,
    /// `prove_final_fold` 耗时（剩余 fold + PCS opening + 序列化）。
    pub final_fold_ms: f64,
    /// 分阶段三段总耗时（start + fold_total + final_fold）。
    pub three_stage_total_ms: f64,
    /// 直接 `prove()` 耗时（对照组）。
    pub direct_prove_ms: f64,
    /// 三阶段路径与直接 prove 的 proof 字节完全一致（true=等价性通过）。
    pub proof_equivalent: bool,
    /// fold 步数（ccccs_queue 总长度）。
    pub fold_step_count: u32,
    /// 初始 LCCCS 锚定承诺（32B hex）。
    pub initial_lcccs_anchor_hex: String,
    /// 最终 proof 字节数。
    pub final_proof_size_bytes: usize,
    /// verify_production 耗时（毫秒）。
    pub verify_ms: f64,
}

/// Phase 5.5 — 并行配置扫描单项结果。
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ParallelSweepEntry {
    /// 标签：`"sequential_baseline"` 或 `"threads_N"`。
    pub label: String,
    /// rayon 线程数（0 = sequential baseline；N>=1 = parallel with N threads）。
    pub threads: usize,
    /// 是否启用并行 CCS 编译。
    pub parallel_ccs_compile: bool,
    /// `prove()` 耗时（毫秒）。
    pub prove_ms: f64,
    /// `verify_production()` 耗时（毫秒）。
    pub verify_ms: f64,
    /// proof 字节数。
    pub proof_size_bytes: usize,
}

/// Phase 5.5 — 并行配置扫描结果（`--parallel-sweep` 启用）。
///
/// 使用 `build_texas_poker_full_hand_elf` 扫描 sequential baseline + rayon_threads 1/2/4/8，
/// 找出实际最低证明延迟配置。所有配置产出的 proof 字节应完全一致（Fiat-Shamir 确定性），
/// 仅 prove 耗时因并行度不同而变化。
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ParallelSweepResult {
    /// 扫描配置列表（按 threads 升序）。
    pub entries: Vec<ParallelSweepEntry>,
    /// 最低 prove 耗时配置的 label。
    pub best_label: String,
    /// 最低 prove 耗时（毫秒）。
    pub best_prove_ms: f64,
    /// 最佳配置的 verify 耗时（毫秒）。
    pub best_verify_ms: f64,
    /// 最佳配置的 proof 字节数。
    pub best_proof_size_bytes: usize,
    /// 相对 sequential baseline 的加速比（`sequential_ms / best_prove_ms`）。
    pub speedup_vs_sequential: f64,
    /// 扫描总耗时（毫秒）。
    pub sweep_total_ms: f64,
}

/// 全局 PerfSummary 单例（供各阶段累加耗时）。
static PERF_SUMMARY: OnceLock<std::sync::Mutex<PerfSummary>> = OnceLock::new();

/// 获取全局 PerfSummary（首次调用初始化）。
pub fn perf_summary() -> &'static std::sync::Mutex<PerfSummary> {
    PERF_SUMMARY.get_or_init(|| {
        std::sync::Mutex::new(PerfSummary {
            timestamp: chrono_now_iso8601(),
            mode: "local".to_string(),
            rpc_endpoint: None,
            curve_adaptation: "BLS12-381 (business) + BN254 (zkvm circuit)".to_string(),
            onchain_table_id: None,
            onchain_tx_count: None,
            onchain_final_block: None,
            sigma_stage: SigmaStageTimings::default(),
            rv32i_stage: Rv32iStageTimings::default(),
            partial_prove_stage: None,
            parallel_sweep: None,
            parallel_threads: None,
            total_time_ms: 0.0,
            winner: 0,
        })
    })
}

/// 生成 ISO 8601 时间戳（不引入 chrono 依赖，用 std 时间）。
fn chrono_now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // 简化 ISO 8601 转换（UTC）
    let days_from_epoch = secs / 86400;
    let secs_of_day = secs % 86400;
    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;

    // 从 epoch (1970-01-01) 推算年月日（Howard Hinnant 算法）
    let z = days_from_epoch as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// poker-zkvm-demo 子命令入口。
pub fn run(args: &[String]) -> Result<(), String> {
    let mut rpc_listen = "127.0.0.1:8545".to_string();
    let mut local_only = false;
    let mut log_file: Option<PathBuf> = None;
    let mut deck_size: usize = 52;
    let mut partial_demo = false;
    // Phase 5.5 — 并行配置参数
    let mut parallel_threads: Option<usize> = None;
    let mut parallel_sweep = false;
    let mut sweep_runs: usize = 1; // 每个配置重复 prove 次数（取中位数）
    let mut sweep_elf_full = false; // false = eval ELF（快速，~1-2s/prove），true = full_hand ELF（实际合约，~4min/prove）
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" => {
                i += 1;
                rpc_listen = args.get(i).ok_or("--rpc 缺少参数")?.clone();
            }
            "--local-only" => {
                local_only = true;
            }
            "--log-file" => {
                i += 1;
                log_file = Some(PathBuf::from(
                    args.get(i).ok_or("--log-file 缺少参数")?,
                ));
            }
            "--deck-size" => {
                i += 1;
                let v = args.get(i).ok_or("--deck-size 缺少参数")?;
                deck_size = v
                    .parse::<usize>()
                    .map_err(|e| format!("--deck-size 解析失败：{e}"))?;
                if deck_size == 0 || deck_size > 52 {
                    return Err("--deck-size 须在 1..=52 范围内".to_string());
                }
            }
            "--partial-prove-demo" => {
                partial_demo = true;
            }
            "--parallel-threads" => {
                i += 1;
                let v = args.get(i).ok_or("--parallel-threads 缺少参数")?;
                let n = v
                    .parse::<usize>()
                    .map_err(|e| format!("--parallel-threads 解析失败：{e}"))?;
                if n == 0 {
                    return Err("--parallel-threads 须 >= 1".to_string());
                }
                parallel_threads = Some(n);
            }
            "--parallel-sweep" => {
                parallel_sweep = true;
            }
            "--sweep-runs" => {
                i += 1;
                let v = args.get(i).ok_or("--sweep-runs 缺少参数")?;
                sweep_runs = v
                    .parse::<usize>()
                    .map_err(|e| format!("--sweep-runs 解析失败：{e}"))?;
                if sweep_runs == 0 {
                    return Err("--sweep-runs 须 >= 1".to_string());
                }
            }
            "--sweep-elf" => {
                i += 1;
                let v = args.get(i).ok_or("--sweep-elf 缺少参数")?;
                sweep_elf_full = match v.as_str() {
                    "full" => true,  // build_texas_poker_full_hand_elf（~220 instrs，~4min/prove）
                    "eval" => false, // build_poker_hand_eval_v2_elf（~80 instrs，~1-2s/prove）
                    _ => return Err(format!("--sweep-elf 须为 full 或 eval，实际：{v}")),
                };
            }
            "--help" | "-h" => {
                eprintln!("用法: zchain poker-zkvm-demo [options]");
                eprintln!();
                eprintln!("选项：");
                eprintln!("  --rpc <host:port>      链上 RPC 端点（默认 127.0.0.1:8545）");
                eprintln!("  --local-only           跳过链上 RPC，仅本地 sigma + RV32I");
                eprintln!("  --log-file <path>      性能日志路径（默认 /tmp/zkvm_poker_perf_<timestamp>.log）");
                eprintln!("  --deck-size <n>        牌组大小（默认 52，调试可减为 4）");
                eprintln!("  --partial-prove-demo   额外演示 LCCCS 分阶段提交（Phase 4.2）");
                eprintln!();
                eprintln!("  Phase 5.5 — 并行证明配置：");
                eprintln!("  --parallel-threads <n> 全局 rayon 线程数（应用于 sigma/rv32i/partial 各阶段）");
                eprintln!("  --parallel-sweep       扫描 sequential + threads 1/2/4/8，找出最低 prove 延迟");
                eprintln!("  --sweep-runs <n>       每个配置 prove 重复次数（默认 1，取中位数；推荐 3-5）");
                eprintln!("  --sweep-elf <full|eval> 扫描使用的 ELF（默认 eval 快速；full = 完整 texas_poker 合约）");
                eprintln!();
                eprintln!("示例：");
                eprintln!("  zchain poker-zkvm-demo --local-only");
                eprintln!("  zchain poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/perf.log");
                eprintln!("  zchain poker-zkvm-demo --local-only --partial-prove-demo");
                eprintln!("  zchain poker-zkvm-demo --local-only --parallel-threads 4");
                eprintln!("  zchain poker-zkvm-demo --local-only --parallel-sweep --sweep-runs 3");
                return Ok(());
            }
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }

    let log_path = log_file.unwrap_or_else(|| {
        PathBuf::from(format!("/tmp/zkvm_poker_perf_{}.log", chrono_now_iso8601().replace(':', "-")))
    });

    // 初始化 tracing 双写（stderr + 文件）
    let _guard = init_tracing_with_file(&log_path)?;

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  zchain poker-zkvm-demo — zkvm 完整一手牌 + 性能日志    ║");
    info!("╚══════════════════════════════════════════════════════════╝");
    info!("mode         : {}", if local_only { "local" } else { "onchain" });
    if !local_only {
        info!("rpc_endpoint : {rpc_listen}");
    }
    info!("log_file     : {}", log_path.display());
    info!("deck_size    : {deck_size}");
    info!("curve_adaptation: BLS12-381 (business) + BN254 (zkvm circuit)");
    if let Some(n) = parallel_threads {
        info!("parallel_threads: {n} (应用于所有 prove 阶段)");
    }
    if parallel_sweep {
        info!("parallel_sweep: ENABLED (扫描 sequential + threads 1/2/4/8, runs={sweep_runs}, elf={})", if sweep_elf_full { "full" } else { "eval" });
    }
    info!("");

    // 更新 PerfSummary 模式字段
    {
        let mut s = perf_summary().lock().map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
        s.mode = if local_only { "local".to_string() } else { "onchain".to_string() };
        if !local_only {
            s.rpc_endpoint = Some(rpc_listen.clone());
        }
        s.parallel_threads = parallel_threads;
    }

    let total_start = std::time::Instant::now();
    let winner = run_full_hand(
        local_only,
        &rpc_listen,
        deck_size,
        partial_demo,
        parallel_threads,
        parallel_sweep,
        sweep_runs,
        sweep_elf_full,
    )?;

    let total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    // 更新 PerfSummary 总字段
    {
        let mut s = perf_summary().lock().map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
        s.total_time_ms = total_ms;
        s.winner = winner;
    }

    info!("");
    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  ✓ zkvm 完整一手牌完成                                   ║");
    info!("║    总耗时: {total_ms:.2} ms                                ");
    info!("║    赢家: P{winner}                                          ");
    info!("║    日志: {}                          ", log_path.display());
    info!("╚══════════════════════════════════════════════════════════╝");

    // 所有 tracing 写入完成后，最后追加 JSON 摘要（避免被后续 tracing 写入覆盖）
    write_perf_summary(&log_path)?;

    Ok(())
}

/// 初始化 tracing 双写（stderr + 文件）。
///
/// 使用 `tracing_subscriber::fmt::layer().with_writer(Mutex<File>)` 实现，
/// 不引入 tracing-appender 额外依赖（与 plan Decision 5 一致）。
fn init_tracing_with_file(log_path: &std::path::Path) -> Result<Option<FileGuard>, String> {
    use std::fs::OpenOptions;
    use std::sync::Mutex;
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

    // 先用 .truncate(true) 单独打开一次以清空文件（避免 .append + .truncate 组合在某些平台上行为不一致）
    // 然后用 .append(true) 重新打开，确保后续所有写入走 O_APPEND 到文件末尾
    std::fs::File::create(log_path)
        .map_err(|e| format!("清空日志文件 {} 失败：{e}", log_path.display()))?;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true) // O_APPEND：所有写入走文件末尾，避免与 write_perf_summary 的 append 写入互相覆盖
        .open(log_path)
        .map_err(|e| format!("打开日志文件 {} 失败：{e}", log_path.display()))?;

    let file_writer = Mutex::new(file);

    // 注意：tracing_subscriber 默认初始化会被 main.rs 调用，这里我们重新初始化
    // 用 try_init 避免重复初始化 panic
    let result = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_writer)
                .with_ansi(false), // 文件不含 ANSI 颜色码
        )
        .try_init();

    if result.is_err() {
        // 已经初始化过，仅警告
        eprintln!("tracing 已初始化，跳过重复初始化（日志仅输出到 stderr）");
        return Ok(None);
    }

    Ok(Some(FileGuard {
        _path: log_path.to_path_buf(),
    }))
}

/// 文件守卫（保留路径用于后续 JSON 摘要写入）。
struct FileGuard {
    _path: PathBuf,
}

/// 执行完整一手牌流程，返回赢家（1/2/0）。
fn run_full_hand(
    local_only: bool,
    rpc_listen: &str,
    deck_size: usize,
    partial_demo: bool,
    parallel_threads: Option<usize>,
    parallel_sweep: bool,
    sweep_runs: usize,
    sweep_elf_full: bool,
) -> Result<u8, String> {
    // Phase D: 链上 RPC 创建桌子（可选）
    let card_seq: Vec<u8> = if local_only {
        info!("━━━ Phase D: 跳过链上 RPC（--local-only）━━━");
        (0..deck_size as u8).collect()
    } else {
        info!("━━━ Phase D: 链上 RPC 创建桌子 ━━━━━━━━━━━━━━━━━━━━━━━━━══");
        create_onchain_table_and_extract_cards(rpc_listen, deck_size)?
    };
    info!("");

    // Phase C: sigma 协议本地编排（host 端，BLS12-381）
    info!("━━━ Phase C: sigma 协议本地编排（BLS12-381） ━━━━━━━━━━━━━━");
    let cards_bytes = run_shuffle_protocol(&card_seq)?;
    let p1_cards: [u8; 5] = cards_bytes[0..5]
        .try_into()
        .map_err(|_| "P1 牌序切片转 [u8; 5] 失败".to_string())?;
    let p2_cards: [u8; 5] = cards_bytes[5..10]
        .try_into()
        .map_err(|_| "P2 牌序切片转 [u8; 5] 失败".to_string())?;
    info!("");

    // Phase B: RV32I zkvm 牌型评估+比较（BN254 Hypernova proof）
    info!("━━━ Phase B: RV32I zkvm 牌型评估+比较（BN254） ━━━━━━━══━━━");
    let winner = run_rv32i_eval_and_compare(&p1_cards, &p2_cards, parallel_threads)?;
    info!("");

    // Phase 4.2: LCCCS 分阶段提交演示（可选）
    if partial_demo {
        info!("━━━ Phase 4.2: LCCCS 分阶段提交演示 ━━━━━━━━━━━━━━━━━━━━━━━━");
        run_lcccs_partial_prove_demo(parallel_threads)?;
        info!("");
    }

    // Phase 5.5: 并行证明配置扫描（可选）— 测试实际最低证明延迟
    if parallel_sweep {
        let elf_label = if sweep_elf_full { "texas_poker full hand" } else { "poker_hand_eval_v2" };
        info!("━━━ Phase 5.5: 并行证明配置扫描（{elf_label} ELF） ━━━");
        run_parallel_sweep(sweep_runs, sweep_elf_full)?;
        info!("");
    }

    Ok(winner)
}

/// Phase 5.5 — 构造 `ZkvmProverConfig`，根据 `parallel_threads` 注入并行配置。
///
/// - `None` → 使用默认全局 rayon 线程池（`RAYON_NUM_THREADS` 或 CPU 核数）
/// - `Some(n)` → 构造作用域受限的 rayon 线程池（`prove()` 内通过 `ThreadPoolBuilder::install()` 安装）
fn make_prover_config(parallel_threads: Option<usize>) -> ZkvmProverConfig {
    let mut config = ZkvmProverConfig::default();
    if let Some(n) = parallel_threads {
        config.parallel_ccs_compile = true;
        config.rayon_threads = Some(n);
    }
    config
}

// ===== Phase D: 链上 RPC 集成 =====

/// 通过 RPC 创建链上桌子并提取牌序。
///
/// 流程：create_table → join_table ×2 → start_hand → 校验 phase==3
/// 返回 `(0..deck_size).collect::<Vec<u8>>()` 作为牌序索引（链上 set_initial_encrypted_deck 按 0..51 顺序写入）。
fn create_onchain_table_and_extract_cards(
    rpc_listen: &str,
    deck_size: usize,
) -> Result<Vec<u8>, String> {
    use crate::poker_rpc_demo::{
        build_signed_tx, query_chain_id, query_table_state, submit_tx_via_rpc,
        verify_table_state, wait_for_block_with_tx, PLAYER1, PLAYER2,
    };
    use group::Group;
    use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
    use poker_l1::vm::contracts::texas_poker::dispatch::{selectors, CreateTableArgs, JoinTableArgs};
    use poker_l1::vm::precompile::reserved::texas_poker_contract_id;
    use poker_protocol::crypto::types::ECPoint;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    info!("  [chain] RPC endpoint: {rpc_listen}");
    info!(
        "  [chain] 目标合约: texas_poker (ObjectID = {:?})",
        texas_poker_contract_id()
    );

    // 1. 生成 secp256k1 密钥对（签名所有 tx）
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let compressed = public_key.serialize();
    let tagged_pubkey =
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, compressed.to_vec())
            .map_err(|e| format!("构造 tagged_pubkey 失败：{e}"))?;
    info!(
        "  [chain] signer tagged_pubkey raw={}B",
        tagged_pubkey.raw.len()
    );

    // 2. 查询 chain_id（节点默认 = DEFAULT_CHAIN_ID）
    let chain_id = query_chain_id(rpc_listen).unwrap_or(poker_l1::DEFAULT_CHAIN_ID);
    info!("  [chain] chain_id=0x{chain_id:08X}");

    // 3. 查询初始桌台状态（应不存在）
    if let Some(existing) = query_table_state(rpc_listen)? {
        return Err(format!("桌台对象已存在（预期应不存在）：{existing:?}"));
    }
    info!("  [chain] ✓ 桌台对象尚不存在");

    // 4. Step 1: create_table
    let create_args = CreateTableArgs {
        name: "zkvm_demo_table".to_string(),
        max_players: 2,
        small_blind: 5,
        big_blind: 10,
    };
    let create_args_bytes = borsh::to_vec(&create_args).map_err(|e| format!("borsh: {e}"))?;
    let tx1 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::create_table(),
        create_args_bytes,
        0,
        0,
    );
    let tx1_hash = tx1.tx_hash();
    info!("  [chain] create_table tx_hash={}", hex::encode(tx1_hash));
    submit_tx_via_rpc(rpc_listen, &tx1)?;
    wait_for_block_with_tx(rpc_listen, tx1_hash)?;
    verify_table_state(rpc_listen, "create_table 后", |t| {
        t.name == "zkvm_demo_table"
            && t.max_players == 2
            && t.small_blind == 5
            && t.big_blind == 10
    })?;

    // 5. Step 2a: join_table P1
    let join1_args = JoinTableArgs {
        player: PLAYER1,
        buy_in: 1000,
        pk: ECPoint(blstrs::G1Projective::identity()),
    };
    let join1_bytes = borsh::to_vec(&join1_args).map_err(|e| format!("borsh: {e}"))?;
    let tx2 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::join_table(),
        join1_bytes,
        0,
        0,
    );
    let tx2_hash = tx2.tx_hash();
    info!(
        "  [chain] join_table P1 tx_hash={}",
        hex::encode(tx2_hash)
    );
    submit_tx_via_rpc(rpc_listen, &tx2)?;
    wait_for_block_with_tx(rpc_listen, tx2_hash)?;
    verify_table_state(rpc_listen, "join_table P1 后", |t| {
        t.seats[0].player == PLAYER1 && t.seats[0].stack == 1000 && t.seats[0].is_occupied()
    })?;

    // 6. Step 2b: join_table P2
    let join2_args = JoinTableArgs {
        player: PLAYER2,
        buy_in: 1000,
        pk: ECPoint(blstrs::G1Projective::generator()),
    };
    let join2_bytes = borsh::to_vec(&join2_args).map_err(|e| format!("borsh: {e}"))?;
    let tx3 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::join_table(),
        join2_bytes,
        0,
        0,
    );
    let tx3_hash = tx3.tx_hash();
    info!(
        "  [chain] join_table P2 tx_hash={}",
        hex::encode(tx3_hash)
    );
    submit_tx_via_rpc(rpc_listen, &tx3)?;
    wait_for_block_with_tx(rpc_listen, tx3_hash)?;
    verify_table_state(rpc_listen, "join_table P2 后", |t| {
        t.seats[1].player == PLAYER2 && t.seats[1].stack == 1000
    })?;

    // 7. Step 3: start_hand
    let tx4 = build_signed_tx(
        &secp,
        &secret_key,
        &tagged_pubkey,
        chain_id,
        selectors::start_hand(),
        vec![],
        0,
        0,
    );
    let tx4_hash = tx4.tx_hash();
    info!(
        "  [chain] start_hand tx_hash={}",
        hex::encode(tx4_hash)
    );
    submit_tx_via_rpc(rpc_listen, &tx4)?;
    wait_for_block_with_tx(rpc_listen, tx4_hash)?;
    verify_table_state(rpc_listen, "start_hand 后", |t| {
        t.shuffle_state.phase == 3 // SHUFFLE_PHASE_BEFORE_PREFLOP
            && t.deck_state.encrypted.len() == 52
    })?;

    // 8. 提取牌序（链上 set_initial_encrypted_deck 按 0..51 顺序写入）
    let card_seq: Vec<u8> = (0..deck_size.min(52) as u8).collect();
    info!(
        "  [chain] ✓ 提取牌序索引: {} 张（0..{}）",
        card_seq.len(),
        card_seq.len()
    );

    // 9. 更新 PerfSummary 链上字段
    {
        let mut s = perf_summary()
            .lock()
            .map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
        s.onchain_table_id = Some(hex::encode(texas_poker_contract_id().to_bytes()));
        s.onchain_tx_count = Some(4); // create + join×2 + start_hand
    }

    Ok(card_seq)
}

// ===== Phase C: sigma 协议本地编排 =====

/// 执行 sigma 协议（5 个 proof：Shuffle + RevealToken + Reconstruct + Remask + Leave）。
///
/// 本地用 `generate_plaintext_cards()` 重建 52 张 BLS12-381 明文牌点（与链上等价），
/// 然后依次执行 5 个 sigma proof 的 prove + verify + 测时，最后解密查表得到 P1/P2 牌序。
///
/// # 参数
/// - `card_seq` — 链上牌序索引（本地模式为 0..52）
///
/// # 返回
/// - `Ok(Vec<u8>)` — P1 (5 字节) + P2 (5 字节) 的 rank 数组（rank ∈ 2..=14）
fn run_shuffle_protocol(card_seq: &[u8]) -> Result<Vec<u8>, String> {
    type C = DefaultCurve;
    type Pt = <C as Curve>::Point;
    type Sc = <C as Curve>::Scalar;

    // 1. 准备 52 张明文牌点（与链上 generate_plaintext_cards() 等价）
    let plaintext_cards: Vec<Pt> = generate_plaintext_cards();
    let n_cards = plaintext_cards.len();
    info!("  [sigma] plaintext_cards 数量: {n_cards}（card_seq.len={}）", card_seq.len());

    // 2. 玩家密钥（BLS12-381）
    let mut rng = OsRng;
    let player2_sk = Sc::from_u64(1u64);
    let player2_pk = C::base_g() * player2_sk;

    // 3. 构造 input_cts（52 张）— 标准 ElGamal 加密
    //    Enc(m, pk, r) = (G*r, m + pk*r)，解密 Dec(c, sk) = c.c2 - c.c1*sk = m
    //    注：链上 set_initial_encrypted_deck 使用 r=1 的简化形式（c1=G, c2=m+pk），
    //    本地 demo 用随机 r 模拟真实洗牌前的初始牌组
    let input_r_values: Vec<Sc> = (0..n_cards).map(|_| Sc::random(&mut rng)).collect();
    let input_cts: Vec<ElGamalCiphertext> = (0..n_cards)
        .map(|i| ElGamalCiphertext::encrypt(&plaintext_cards[i], &player2_pk, &input_r_values[i]))
        .collect();

    // === 4. ZKShuffleProof ===
    let shuffle_start = Instant::now();
    let mut permute: Vec<usize> = (0..n_cards).collect();
    permute.shuffle(&mut rng);
    let r_values: Vec<Sc> = (0..n_cards).map(|_| Sc::random(&mut rng)).collect();
    // output_cts[i] = reencrypt(input_cts[permute[i]], r_values[i])
    //   output.c1 = input.c1 + base_g() * r
    //   output.c2 = input.c2 + pk * r
    let output_cts: Vec<ElGamalCiphertext> = (0..n_cards)
        .map(|i| {
            let src = &input_cts[permute[i]];
            let r = r_values[i];
            ElGamalCiphertext {
                c1: src.c1 + C::base_g() * r,
                c2: src.c2 + player2_pk * r,
            }
        })
        .collect();
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_shuffle");
    let shuffle_proof = ZKShuffleProof::<C>::prove(
        &input_cts,
        &output_cts,
        &permute,
        &r_values,
        &player2_pk,
        &mut rng,
        &mut t,
    )
    .map_err(|e| format!("ZKShuffleProof prove 失败：{e:?}"))?;
    let shuffle_prove_ms = shuffle_start.elapsed().as_secs_f64() * 1000.0;

    let verify_start = Instant::now();
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_shuffle");
    let shuffle_result = shuffle_proof.verify(&input_cts, &output_cts, &player2_pk, &mut t);
    let shuffle_verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    info!(
        "  [sigma] ZKShuffleProof:        prove={:>7.2}ms verify={:>6.2}ms ok={}",
        shuffle_prove_ms,
        shuffle_verify_ms,
        shuffle_result.is_ok()
    );
    shuffle_result.map_err(|e| format!("ZKShuffleProof verify 失败：{e:?}"))?;

    // === 5. RevealTokenProof（取 output_cts[0]）===
    let reveal_start = Instant::now();
    let target_ct = &output_cts[0];
    let reveal_token = target_ct.c1 * player2_sk;
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_reveal");
    let reveal_proof = RevealTokenProof::<C>::prove(
        &player2_sk,
        &player2_pk,
        target_ct,
        &reveal_token,
        &mut rng,
        &mut t,
    );
    let reveal_prove_ms = reveal_start.elapsed().as_secs_f64() * 1000.0;

    let verify_start = Instant::now();
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_reveal");
    let reveal_result = reveal_proof.verify(target_ct, &reveal_token, &player2_pk, &mut t);
    let reveal_verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    info!(
        "  [sigma] RevealTokenProof:      prove={:>7.2}ms verify={:>6.2}ms ok={}",
        reveal_prove_ms,
        reveal_verify_ms,
        reveal_result.is_ok()
    );
    reveal_result.map_err(|e| format!("RevealTokenProof verify 失败：{e:?}"))?;

    // === 6. ReconstructProof（取 output_cts[0..2] 作 user_readable）===
    let reconstruct_start = Instant::now();
    let user_readable: Vec<ElGamalCiphertext> = output_cts[0..2].to_vec();
    let coefficient = Sc::from_u64(7u64); // ≠ 0 且 ≠ 1
    let cards_ref: Vec<Pt> = plaintext_cards.clone();
    let (s_vec, recon_output, swap_out) = reconstruct_deck::<C>(
        &cards_ref,
        &user_readable,
        &player2_sk,
        &player2_pk,
        &coefficient,
    )
    .map_err(|e| format!("reconstruct_deck 失败：{e:?}"))?;
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_reconstruct");
    let recon_proof = ReconstructProof::<C>::prove(
        cards_ref.clone(),
        user_readable.clone(),
        recon_output.clone(),
        swap_out.clone(),
        &player2_sk,
        &player2_pk,
        s_vec,
        &mut t,
    )
    .map_err(|e| format!("ReconstructProof prove 失败：{e:?}"))?;
    let recon_prove_ms = reconstruct_start.elapsed().as_secs_f64() * 1000.0;

    let verify_start = Instant::now();
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_reconstruct");
    // ReconstructProof::verify 的 swap_out_cards 参数为 &[ElGamalCiphertextGeneric<C>]（不含 usize 索引）
    let swap_out_cts: Vec<ElGamalCiphertext> =
        swap_out.iter().map(|(_, ct)| ct.clone()).collect();
    let recon_result = recon_proof.verify(
        &cards_ref,
        &recon_output,
        &swap_out_cts,
        &user_readable,
        &player2_pk,
        &mut t,
    );
    let recon_verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    info!(
        "  [sigma] ReconstructProof:      prove={:>7.2}ms verify={:>6.2}ms ok={}",
        recon_prove_ms,
        recon_verify_ms,
        recon_result.is_ok()
    );
    recon_result.map_err(|e| format!("ReconstructProof verify 失败：{e:?}"))?;

    // === 7. RemaskProof（取 output_cts[0..5]）===
    let remask_start = Instant::now();
    let remask_input: Vec<ElGamalCiphertext> = output_cts[0..5].to_vec();
    let mut remask_output: Vec<ElGamalCiphertext> = Vec::with_capacity(5);
    for ct in &remask_input {
        remask_output.push(
            remask_ciphertext::<C>(ct, &player2_sk, &player2_pk, &mut rng)
                .map_err(|e| format!("remask_ciphertext 失败：{e:?}"))?,
        );
    }
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_remask");
    let remask_proof = RemaskProof::<C>::prove(
        &remask_input,
        &remask_output,
        &player2_sk,
        &player2_pk,
        &mut t,
    );
    let remask_prove_ms = remask_start.elapsed().as_secs_f64() * 1000.0;

    let verify_start = Instant::now();
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_remask");
    let remask_ok = remask_proof.verify(&remask_input, &remask_output, &player2_pk, &mut t);
    let remask_verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    info!(
        "  [sigma] RemaskProof:           prove={:>7.2}ms verify={:>6.2}ms ok={}",
        remask_prove_ms, remask_verify_ms, remask_ok
    );
    if !remask_ok {
        return Err("RemaskProof verify 失败".to_string());
    }

    // === 8. LeaveProof（取 remask_output 作 leave_input）===
    let leave_start = Instant::now();
    let leave_input = remask_output.clone();
    let mut leave_output: Vec<ElGamalCiphertext> = Vec::with_capacity(5);
    for ct in &leave_input {
        leave_output.push(
            leave_ciphertext::<C>(ct, &player2_sk, &player2_pk, &mut rng)
                .map_err(|e| format!("leave_ciphertext 失败：{e:?}"))?,
        );
    }
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_leave");
    let leave_proof = LeaveProof::<C>::prove(
        &leave_input,
        &leave_output,
        &player2_sk,
        &player2_pk,
        &mut t,
    );
    let leave_prove_ms = leave_start.elapsed().as_secs_f64() * 1000.0;

    let verify_start = Instant::now();
    let mut t = MerlinTranscript::new(b"zk_shuffle_demo_leave");
    let leave_ok = leave_proof.verify(&leave_input, &leave_output, &player2_pk, &mut t);
    let leave_verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
    info!(
        "  [sigma] LeaveProof:            prove={:>7.2}ms verify={:>6.2}ms ok={}",
        leave_prove_ms, leave_verify_ms, leave_ok
    );
    if !leave_ok {
        return Err("LeaveProof verify 失败".to_string());
    }

    // === 9. 解密查表（取 output_cts[0..5] 为 P1，output_cts[5..10] 为 P2）===
    // pt = ct.c2 - ct.c1 * player2_sk
    // 与 52 个 plaintext_cards 比对找到索引 i → rank = (i % 13) + 2
    let p1_cards: [u8; 5] = decrypt_to_ranks::<C>(&output_cts[0..5], &player2_sk, &plaintext_cards);
    let p2_cards: [u8; 5] =
        decrypt_to_ranks::<C>(&output_cts[5..10], &player2_sk, &plaintext_cards);
    info!("  [sigma] P1 牌序 (rank): {p1_cards:?}");
    info!("  [sigma] P2 牌序 (rank): {p2_cards:?}");

    // === 10. 累加 SigmaStageTimings ===
    {
        let mut s = perf_summary()
            .lock()
            .map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
        s.sigma_stage = SigmaStageTimings {
            shuffle_prove_ms,
            shuffle_verify_ms,
            reveal_prove_ms,
            reveal_verify_ms,
            reconstruct_prove_ms: recon_prove_ms,
            reconstruct_verify_ms: recon_verify_ms,
            remask_prove_ms,
            remask_verify_ms,
            leave_prove_ms,
            leave_verify_ms,
        };
    }

    Ok([p1_cards.as_slice(), p2_cards.as_slice()].concat())
}

/// 辅助：sigma 解密 → 查表 → rank 数组。
///
/// 对每张密文 `ct`，计算明文点 `pt = ct.c2 - ct.c1 * sk`，
/// 与 52 个已知 `hash_to_g1("texas_poker/card/{i}")` 明文点比对，
/// 找到索引 `i` → `rank = (i % 13) + 2`（2..=14 对应 2..A）。
fn decrypt_to_ranks<C: Curve>(
    cts: &[ElGamalCiphertextGeneric<C>],
    sk: &C::Scalar,
    table: &[C::Point],
) -> [u8; 5] {
    assert_eq!(cts.len(), 5, "decrypt_to_ranks 须接收 5 张密文");
    let mut ranks = [0u8; 5];
    for (idx, ct) in cts.iter().enumerate() {
        let pt = ct.c2 - ct.c1 * *sk;
        let mut found = false;
        for (i, known) in table.iter().enumerate() {
            if pt == *known {
                ranks[idx] = (i % 13) as u8 + 2;
                found = true;
                break;
            }
        }
        if !found {
            panic!("解密出的明文点不在 52 张已知牌中（idx={idx}）");
        }
    }
    ranks
}

// ===== Phase B: RV32I zkvm 牌型评估+比较 =====

/// 执行 RV32I 牌型评估+比较，返回赢家（1/2/0）。
///
/// 流程：
/// 1. P1 评估：`build_poker_hand_eval_v2_elf` + `prove(p1)` + `verify_production` + 测时
/// 2. P2 评估：同上
/// 3. 比较：`build_poker_hand_compare_elf` + 输入 `[s1.le, s2.le]` 8 字节 + prove + verify + 测时
/// 4. 累加 `Rv32iStageTimings` 9 个字段
fn run_rv32i_eval_and_compare(
    p1: &[u8; 5],
    p2: &[u8; 5],
    parallel_threads: Option<usize>,
) -> Result<u8, String> {
    let config = make_prover_config(parallel_threads);
    let registry = default_ccs_registry();
    let elf_eval = build_poker_hand_eval_v2_elf();

    // === P1 评估 ===
    let p1_prove_start = Instant::now();
    let (p1_proof, p1_io) = zkvm_prove(&elf_eval, p1, &config)
        .map_err(|e| format!("P1 eval prove 失败：{e:?}"))?;
    let p1_prove_ms = p1_prove_start.elapsed().as_secs_f64() * 1000.0;

    let p1_verify_start = Instant::now();
    let p1_ok = zkvm_verify_production(&p1_proof, &p1_io, &registry)
        .map_err(|e| format!("P1 eval verify 失败：{e:?}"))?;
    let p1_verify_ms = p1_verify_start.elapsed().as_secs_f64() * 1000.0;
    let p1_size = p1_proof.len();
    let s1 = u32::from_le_bytes([
        p1_io.output[0],
        p1_io.output[1],
        p1_io.output[2],
        p1_io.output[3],
    ]);
    info!(
        "  [rv32i] P1 eval:     prove={:>7.2}ms verify={:>6.2}ms size={:>6}B score=0x{s1:04X}",
        p1_prove_ms, p1_verify_ms, p1_size
    );
    if !p1_ok {
        return Err("P1 eval verify 失败".to_string());
    }

    // === P2 评估 ===
    let p2_prove_start = Instant::now();
    let (p2_proof, p2_io) = zkvm_prove(&elf_eval, p2, &config)
        .map_err(|e| format!("P2 eval prove 失败：{e:?}"))?;
    let p2_prove_ms = p2_prove_start.elapsed().as_secs_f64() * 1000.0;

    let p2_verify_start = Instant::now();
    let p2_ok = zkvm_verify_production(&p2_proof, &p2_io, &registry)
        .map_err(|e| format!("P2 eval verify 失败：{e:?}"))?;
    let p2_verify_ms = p2_verify_start.elapsed().as_secs_f64() * 1000.0;
    let p2_size = p2_proof.len();
    let s2 = u32::from_le_bytes([
        p2_io.output[0],
        p2_io.output[1],
        p2_io.output[2],
        p2_io.output[3],
    ]);
    info!(
        "  [rv32i] P2 eval:     prove={:>7.2}ms verify={:>6.2}ms size={:>6}B score=0x{s2:04X}",
        p2_prove_ms, p2_verify_ms, p2_size
    );
    if !p2_ok {
        return Err("P2 eval verify 失败".to_string());
    }

    // === 比较 ===
    let cmp_input: Vec<u8> = s1
        .to_le_bytes()
        .iter()
        .chain(s2.to_le_bytes().iter())
        .copied()
        .collect();
    let elf_cmp = build_poker_hand_compare_elf();
    let cmp_prove_start = Instant::now();
    let (cmp_proof, cmp_io) = zkvm_prove(&elf_cmp, &cmp_input, &config)
        .map_err(|e| format!("compare prove 失败：{e:?}"))?;
    let cmp_prove_ms = cmp_prove_start.elapsed().as_secs_f64() * 1000.0;

    let cmp_verify_start = Instant::now();
    let cmp_ok = zkvm_verify_production(&cmp_proof, &cmp_io, &registry)
        .map_err(|e| format!("compare verify 失败：{e:?}"))?;
    let cmp_verify_ms = cmp_verify_start.elapsed().as_secs_f64() * 1000.0;
    let cmp_size = cmp_proof.len();
    let winner = cmp_io.output[0];
    info!(
        "  [rv32i] compare:     prove={:>7.2}ms verify={:>6.2}ms size={:>6}B winner=P{winner}",
        cmp_prove_ms, cmp_verify_ms, cmp_size
    );
    if !cmp_ok {
        return Err("compare verify 失败".to_string());
    }

    // === 累加 Rv32iStageTimings ===
    {
        let mut s = perf_summary()
            .lock()
            .map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
        s.rv32i_stage = Rv32iStageTimings {
            eval_p1_prove_ms: p1_prove_ms,
            eval_p1_verify_ms: p1_verify_ms,
            eval_p1_proof_size_bytes: p1_size,
            eval_p2_prove_ms: p2_prove_ms,
            eval_p2_verify_ms: p2_verify_ms,
            eval_p2_proof_size_bytes: p2_size,
            compare_prove_ms: cmp_prove_ms,
            compare_verify_ms: cmp_verify_ms,
            compare_proof_size_bytes: cmp_size,
        };
    }

    Ok(winner)
}

// ===== Phase 4.2: LCCCS 分阶段提交演示 =====

/// 演示 LCCCS 分阶段提交流程。
///
/// 使用 `build_poker_hand_eval_v2_elf`（~80 trace 步）演示分阶段 proof 生成。
/// 选择 eval ELF 而非 full_hand ELF 的原因：
///   - partial demo 的目的是演示 **LCCCS 分阶段提交机制**（start → final_fold）
///   - full_hand ELF（220 步）CCS 约束数量大，单次 prove >4min，不适合快速演示
///   - eval ELF 轻量（~80 步），配合默认 batch_size=256 走单实例路径
///   - 完整一手牌流程已在 Phase B（RV32I eval + compare）中展示
///
/// 1. **对照组**：直接 `prove()` 生成完整 proof
/// 2. **两阶段路径**（单实例路径，0 fold 步）：
///    - `prove_partial_start` — ELF 执行 + CCS 编译 + 初始 LCCCS 锚定
///    - `prove_final_fold` — 单实例 sumcheck + PCS opening + 最终 proof 上链
/// 3. **等价性校验**：两阶段路径产出的 proof 字节应与直接 prove() 完全一致
/// 4. **verify_production 验证**：最终 proof 应通过完整 verifier
///
/// 注：多 fold 步的 checkpoint 演示需 release build（debug 下 BN254 标量乘法 ~10x 慢），
/// 已由 `test_final_fold_with_multiple_partial_folds` 单元测试覆盖。
///
/// 演示输入：[14, 13, 12, 11, 10]（A-K-Q-J-10 straight），
/// 期望输出：[5, 14, 0, 0]（category=5=straight, max_rank=14）。
fn run_lcccs_partial_prove_demo(parallel_threads: Option<usize>) -> Result<(), String> {
    use poker_zkvm::prover::MAX_PROOF_TOTAL_SIZE;

    let elf = build_poker_hand_eval_v2_elf();
    // 输入：5 张牌 rank = [A, K, Q, J, 10] → straight (category=5, max=14)
    let input: Vec<u8> = vec![14, 13, 12, 11, 10];
    let config = {
        let mut cfg = ZkvmProverConfig {
            // batch_size=256（默认）→ 80 步 padding 到 256 → 1 batch → 单实例路径（0 fold 步）
            // 选择默认值的原因：
            //   - debug build 下 BN254 标量乘法 ~10x 慢，多 fold 步演示需 release build
            //   - 单实例路径仍完整展示 start（初始 LCCCS 锚定）→ final_fold（最终 proof 上链）
            //   - 证明耗时与 Phase B 的 RV32I eval prove 相当（~9.5s）
            //   - 多 fold 步路径由单元测试 test_final_fold_with_multiple_partial_folds 覆盖
            batch_size: 256,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            ..Default::default()
        };
        if let Some(n) = parallel_threads {
            cfg.parallel_ccs_compile = true;
            cfg.rayon_threads = Some(n);
        }
        cfg
    };
    let registry = default_ccs_registry();

    info!("  [partial] ELF: poker_hand_eval_v2 (~80 instrs, 5B input, 4B output)");
    info!("  [partial] 输入: [A,K,Q,J,10] → 期望 straight (category=5, max=14)");
    info!("  [partial] batch_size={} → 单实例路径（0 fold 步）分阶段提交演示", config.batch_size);

    // === 对照组：直接 prove ===
    let direct_start = Instant::now();
    let (direct_proof, direct_io) = zkvm_prove(&elf, &input, &config)
        .map_err(|e| format!("[partial] 直接 prove 失败：{e:?}"))?;
    let direct_ms = direct_start.elapsed().as_secs_f64() * 1000.0;
    info!(
        "  [partial] 对照组 prove:     {:>7.2}ms size={:>6}B",
        direct_ms,
        direct_proof.len()
    );

    // === 三阶段路径 ===

    // 阶段 1: prove_partial_start
    let start_t = Instant::now();
    let mut state: PartialProveState = prove_partial_start(&elf, &input, &config)
        .map_err(|e| format!("[partial] prove_partial_start 失败：{e:?}"))?;
    let start_ms = start_t.elapsed().as_secs_f64() * 1000.0;

    let fold_step_count = state.ccccs_queue.len() as u32;
    let initial_lcccs_anchor = state.ccs_commitment; // 锚定用 ccs_commitment 作为初始 LCCCS 锚的标识
    info!(
        "  [partial] start:            {:>7.2}ms fold_steps={} ccccs_queue={}",
        start_ms,
        fold_step_count,
        state.ccccs_queue.len()
    );
    info!(
        "  [partial]   initial_lcccs_anchor = {}",
        hex::encode(initial_lcccs_anchor)
    );

    // 阶段 2: prove_partial_fold（每步独立提交，模拟链上 checkpoint）
    let fold_total_start = Instant::now();
    let mut fold_count = 0u32;
    while !state.ccccs_queue.is_empty() {
        let step_t = Instant::now();
        let progress = prove_partial_fold(&mut state, 1)
            .map_err(|e| format!("[partial] prove_partial_fold 失败：{e:?}"))?;
        let step_ms = step_t.elapsed().as_secs_f64() * 1000.0;
        fold_count += 1;
        info!(
            "  [partial]   fold step {}/{}: {:>7.2}ms remaining={} intermediate_commitment={}",
            fold_count,
            fold_step_count,
            step_ms,
            progress.remaining_steps,
            hex::encode(progress.intermediate_commitment)
        );
    }
    let fold_total_ms = fold_total_start.elapsed().as_secs_f64() * 1000.0;
    let fold_avg_ms = if fold_count > 0 {
        fold_total_ms / fold_count as f64
    } else {
        0.0
    };
    info!(
        "  [partial] fold total:       {:>7.2}ms ({} steps, avg {:.2}ms/step)",
        fold_total_ms, fold_count, fold_avg_ms
    );

    // 阶段 3: prove_final_fold
    let final_t = Instant::now();
    let (partial_proof, partial_io) = prove_final_fold(state)
        .map_err(|e| format!("[partial] prove_final_fold 失败：{e:?}"))?;
    let final_fold_ms = final_t.elapsed().as_secs_f64() * 1000.0;
    info!(
        "  [partial] final_fold:       {:>7.2}ms size={:>6}B",
        final_fold_ms,
        partial_proof.len()
    );

    let three_stage_total = start_ms + fold_total_ms + final_fold_ms;
    info!(
        "  [partial] 三阶段总耗时:      {:>7.2}ms (start {:.2} + fold {:.2} + final {:.2})",
        three_stage_total, start_ms, fold_total_ms, final_fold_ms
    );

    // === 等价性校验 ===
    let proof_equivalent = direct_proof == partial_proof;
    let io_equivalent = direct_io == partial_io;
    info!(
        "  [partial] proof 等价性: {} (direct {}B == partial {}B)",
        if proof_equivalent { "✓ 通过" } else { "✗ 失败" },
        direct_proof.len(),
        partial_proof.len()
    );
    info!(
        "  [partial] public_io 等价性: {}",
        if io_equivalent { "✓ 通过" } else { "✗ 失败" }
    );
    if !proof_equivalent {
        return Err("[partial] 三阶段路径 proof 与直接 prove() 不一致".to_string());
    }
    if !io_equivalent {
        return Err("[partial] 三阶段路径 public_io 与直接 prove() 不一致".to_string());
    }

    // === verify_production 验证 ===
    let verify_t = Instant::now();
    let valid = zkvm_verify_production(&partial_proof, &partial_io, &registry)
        .map_err(|e| format!("[partial] verify_production 失败：{e:?}"))?;
    let verify_ms = verify_t.elapsed().as_secs_f64() * 1000.0;
    info!(
        "  [partial] verify_production: {:>7.2}ms valid={}",
        verify_ms, valid
    );
    if !valid {
        return Err("[partial] verify_production 验证失败".to_string());
    }

    // === 校验输出（eval ELF 输出 [category, max_rank, 0, 0]）===
    let expected_output: [u8; 4] = [5, 14, 0, 0]; // category=5=straight, max=14
    info!(
        "  [partial] output: {:?} (期望 {:?} = straight A-high)",
        partial_io.output, expected_output
    );
    if partial_io.output != expected_output {
        return Err(format!(
            "[partial] 期望输出 {:?} (straight A-high)，实际 {:?}",
            expected_output, partial_io.output
        ));
    }

    // === 累加 PartialProveStageTimings ===
    {
        let mut s = perf_summary()
            .lock()
            .map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
        s.partial_prove_stage = Some(PartialProveStageTimings {
            start_ms,
            fold_avg_ms,
            fold_total_ms,
            final_fold_ms,
            three_stage_total_ms: three_stage_total,
            direct_prove_ms: direct_ms,
            proof_equivalent,
            fold_step_count,
            initial_lcccs_anchor_hex: hex::encode(initial_lcccs_anchor),
            final_proof_size_bytes: partial_proof.len(),
            verify_ms,
        });
    }

    info!("  [partial] ✓ LCCCS 分阶段提交演示完成（与直接 prove 等价）");

    Ok(())
}

// ===== Phase 5.5: 并行证明配置扫描 =====

/// 待扫描的 rayon 线程数列表。
///
/// 1 = 单线程（最慢基线）；2/4/8 = 多线程并行。
/// 8 通常覆盖主流 8C/16T 桌面 CPU；更高线程数收益递减（CCS 编译为 CPU 密集型）。
const PARALLEL_SWEEP_THREAD_COUNTS: &[usize] = &[1, 2, 4, 8];

/// Phase 5.5 — 并行证明配置扫描（`--parallel-sweep` 启用）。
///
/// **目标**：测量不同并行配置下的实际最低证明延迟，验证 Phase 5.1/5.2/5.3 的并行化收益。
///
/// **流程**：
/// 1. 构造 texas_poker 完整一手牌 ELF（`build_texas_poker_full_hand_elf`，~220 条指令）
/// 2. **Sequential baseline**：`parallel_ccs_compile=false`，跑 `sweep_runs` 次 prove，取中位数
/// 3. **Parallel threads=1/2/4/8**：`parallel_ccs_compile=true` + `rayon_threads=Some(n)`，各跑 `sweep_runs` 次，取中位数
/// 4. **等价性校验**：所有配置产出的 proof 字节应完全一致（Fiat-Shamir 确定性）
/// 5. **verify_production**：每个配置的 proof 都要通过完整 verifier
/// 6. **报告最低延迟配置**：`best_label` / `best_prove_ms` / `speedup_vs_sequential`
///
/// **输入布局**：62 字节 = 52B deck（0..51 排列）+ 5B P1（[14,13,12,11,10] straight A-high）+ 5B P2（[2,2,3,4,5] 一对 2）
///
/// **为什么用 full_hand ELF 而非 eval ELF**：
///   - eval ELF 仅 ~80 trace 步 → 1 batch → CCS 编译并行收益不显著
///   - full_hand ELF ~250 trace 步 / batch_size=10 = 25 batches → 并行收益显著
///   - 使用 batch_size=10 强制多 batch，放大并行加速比
///
/// **Fiat-Shamir 确定性证明**：
///   - `compile_batch_to_ccs` 为纯函数，输入相同 → 输出相同（无论是否并行）
///   - rayon `into_par_iter().collect()` 保留顺序，CCS 实例顺序不变
///   - 故 `prove()` 输出的 proof 字节在所有配置下应完全一致
fn run_parallel_sweep(sweep_runs: usize, sweep_elf_full: bool) -> Result<(), String> {
    let elf = if sweep_elf_full {
        build_texas_poker_full_hand_elf()
    } else {
        build_poker_hand_eval_v2_elf()
    };

    // 输入布局依 ELF 而定：
    // - full_hand ELF：62B = 52B deck + 5B P1 + 5B P2
    // - eval ELF：5B = P1 5 张牌 rank（仅评估 P1，无比较）
    // 扫描主要测试 prove 延迟，故两种 ELF 都用 P1=[A,K,Q,J,10]（straight A-high）
    let p1: [u8; 5] = [14, 13, 12, 11, 10];
    let input: Vec<u8> = if sweep_elf_full {
        let p2: [u8; 5] = [2, 2, 3, 4, 5];
        make_full_hand_input(p1, p2)
    } else {
        p1.to_vec()
    };
    let registry = default_ccs_registry();

    let elf_label = if sweep_elf_full { "build_texas_poker_full_hand_elf (~220 instrs, 62B input)" } else { "build_poker_hand_eval_v2_elf (~80 instrs, 5B input)" };
    info!("  [sweep] ELF: {elf_label}");
    info!("  [sweep] 输入: P1=[A,K,Q,J,10] straight{}", if sweep_elf_full { " + P2=[2,2,3,4,5] pair" } else { "" });
    info!("  [sweep] batch_size=256（生产配置）：1 batch + 0 fold → 实际最低 prove 延迟");
    info!("  [sweep] 配置: sequential_baseline + threads 1/2/4/8, 每配置 {sweep_runs} runs（取中位数）");
    info!("");

    // 使用 batch_size=256（生产配置）测量实际最低 prove 延迟
    // - eval ELF ~80 步 / batch_size=256 → 1 batch + 0 fold → ~9s/prove（最快）
    // - 多 batch 配置（batch_size<80）虽可并行 CCS 编译，但 fold 步极慢（每步 5+ min），不实用
    // - 生产配置下 parallel_ccs_compile 对 1 batch 无加速，但不引入回归（验证正确性）
    // - 实际并行收益场景：长 trace（>256 步）天然产生多 batch，CCS 编译可并行加速
    const SWEEP_BATCH_SIZE: usize = 256;

    let sweep_start = Instant::now();
    let mut entries: Vec<ParallelSweepEntry> = Vec::new();
    // 用于等价性校验：保存 sequential baseline 的 proof 字节
    let reference_proof: Vec<u8>;

    // === Sequential baseline ===
    let config_seq = ZkvmProverConfig {
        batch_size: SWEEP_BATCH_SIZE,
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        parallel_ccs_compile: false,
        rayon_threads: None,
        ..Default::default()
    };
    info!("  [sweep] ━━ sequential_baseline (parallel_ccs_compile=false) ━━");
    let (seq_prove_ms, seq_verify_ms, seq_proof_size) =
        run_sweep_single_config(&elf, &input, &config_seq, &registry, sweep_runs, "sequential")?;
    info!(
        "  [sweep]   → prove_median={:>8.2}ms verify_median={:>6.2}ms size={:>6}B",
        seq_prove_ms, seq_verify_ms, seq_proof_size
    );
    reference_proof = run_single_prove_for_equiv_check(&elf, &input, &config_seq)?;
    entries.push(ParallelSweepEntry {
        label: "sequential_baseline".to_string(),
        threads: 0,
        parallel_ccs_compile: false,
        prove_ms: seq_prove_ms,
        verify_ms: seq_verify_ms,
        proof_size_bytes: seq_proof_size,
    });

    let sequential_ms = seq_prove_ms;

    // === Parallel configs: threads 1/2/4/8 ===
    for &n in PARALLEL_SWEEP_THREAD_COUNTS {
        let config = ZkvmProverConfig {
            batch_size: SWEEP_BATCH_SIZE,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            parallel_ccs_compile: true,
            rayon_threads: Some(n),
            ..Default::default()
        };
        info!("  [sweep] ━━ threads_{n} (parallel_ccs_compile=true, rayon_threads={n}) ━━");
        let (prove_ms, verify_ms, proof_size) =
            run_sweep_single_config(&elf, &input, &config, &registry, sweep_runs, &format!("threads_{n}"))?;
        info!(
            "  [sweep]   → prove_median={:>8.2}ms verify_median={:>6.2}ms size={:>6}B",
            prove_ms, verify_ms, proof_size
        );

        // 等价性校验：proof 字节应与 sequential baseline 完全一致
        let parallel_proof = run_single_prove_for_equiv_check(&elf, &input, &config)?;
        if parallel_proof != reference_proof {
            return Err(format!(
                "[sweep] threads={n} proof 字节与 sequential_baseline 不一致（Fiat-Shamir 确定性失效）"
            ));
        }
        info!("  [sweep]   ✓ proof 等价性校验通过（与 sequential_baseline 一致）");

        entries.push(ParallelSweepEntry {
            label: format!("threads_{}", n),
            threads: n,
            parallel_ccs_compile: true,
            prove_ms,
            verify_ms,
            proof_size_bytes: proof_size,
        });
    }

    let sweep_total_ms = sweep_start.elapsed().as_secs_f64() * 1000.0;

    // 找出最低 prove 耗时配置
    let best_idx = entries
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| a.prove_ms.partial_cmp(&b.prove_ms).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)
        .ok_or("[sweep] entries 为空")?;
    let best_label = entries[best_idx].label.clone();
    let best_prove_ms = entries[best_idx].prove_ms;
    let best_verify_ms = entries[best_idx].verify_ms;
    let best_proof_size_bytes = entries[best_idx].proof_size_bytes;
    let speedup = if best_prove_ms > 0.0 {
        sequential_ms / best_prove_ms
    } else {
        0.0
    };

    info!("");
    info!("  [sweep] ━━━━━━ 扫描结果汇总 ━━━━━━");
    for e in &entries {
        let marker = if e.label == best_label { "★ BEST" } else { "       " };
        info!(
            "  [sweep] {marker} {:<22} prove={:>8.2}ms verify={:>6.2}ms size={:>6}B",
            e.label, e.prove_ms, e.verify_ms, e.proof_size_bytes
        );
    }
    info!("");
    info!(
        "  [sweep] ✓ 最佳配置: {} (prove={:.2}ms, verify={:.2}ms, size={}B)",
        best_label, best_prove_ms, best_verify_ms, best_proof_size_bytes
    );
    info!(
        "  [sweep] ✓ 加速比: {:.2}x vs sequential_baseline ({:.2}ms → {:.2}ms)",
        speedup, sequential_ms, best_prove_ms
    );
    info!("  [sweep] 扫描总耗时: {:.2}ms ({} 配置 × {} runs = {} 次 prove)", sweep_total_ms, entries.len(), sweep_runs, entries.len() * sweep_runs);

    // 更新 PerfSummary
    {
        let mut s = perf_summary().lock().map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
        s.parallel_sweep = Some(ParallelSweepResult {
            entries,
            best_label,
            best_prove_ms,
            best_verify_ms,
            best_proof_size_bytes,
            speedup_vs_sequential: speedup,
            sweep_total_ms,
        });
    }

    info!("  [sweep] ✓ 并行证明配置扫描完成");

    Ok(())
}

/// 对单个 ProverConfig 跑 `runs` 次 prove + verify，返回 prove/verify 中位数 + proof size。
///
/// 中位数比单次测量更稳定，避免 OS 调度抖动导致的离群值。
fn run_sweep_single_config(
    elf: &[u8],
    input: &[u8],
    config: &ZkvmProverConfig,
    registry: &[poker_zkvm::ccs::Ccs],
    runs: usize,
    label: &str,
) -> Result<(f64, f64, usize), String> {
    let mut prove_times: Vec<f64> = Vec::with_capacity(runs);
    let mut verify_times: Vec<f64> = Vec::with_capacity(runs);
    let mut last_proof_size: usize = 0;

    for run_idx in 0..runs {
        let prove_start = Instant::now();
        let (proof, io) = zkvm_prove(elf, input, config)
            .map_err(|e| format!("[sweep] {label} run {run_idx} prove 失败：{e:?}"))?;
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;

        let verify_start = Instant::now();
        let valid = zkvm_verify_production(&proof, &io, registry)
            .map_err(|e| format!("[sweep] {label} run {run_idx} verify 失败：{e:?}"))?;
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

        if !valid {
            return Err(format!("[sweep] {label} run {run_idx} verify 返回 false"));
        }

        if runs > 1 {
            info!(
                "  [sweep]   run {}/{}: prove={:>8.2}ms verify={:>6.2}ms size={:>6}B",
                run_idx + 1,
                runs,
                prove_ms,
                verify_ms,
                proof.len()
            );
        }

        prove_times.push(prove_ms);
        verify_times.push(verify_ms);
        last_proof_size = proof.len();
    }

    // 取中位数
    prove_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    verify_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let prove_median = prove_times[prove_times.len() / 2];
    let verify_median = verify_times[verify_times.len() / 2];

    Ok((prove_median, verify_median, last_proof_size))
}

/// 单次 prove（用于等价性校验，不测时）。
fn run_single_prove_for_equiv_check(
    elf: &[u8],
    input: &[u8],
    config: &ZkvmProverConfig,
) -> Result<Vec<u8>, String> {
    let (proof, _io) = zkvm_prove(elf, input, config)
        .map_err(|e| format!("[sweep] 等价性校验 prove 失败：{e:?}"))?;
    Ok(proof)
}

// ===== Phase E: 性能日志 =====

/// 写入 JSON 摘要到日志末尾。
fn write_perf_summary(log_path: &std::path::Path) -> Result<(), String> {
    use std::io::Write;
    let s = perf_summary().lock().map_err(|e| format!("PerfSummary 锁中毒：{e}"))?;
    let json = serde_json::to_string_pretty(&*s).map_err(|e| format!("JSON 序列化失败：{e}"))?;

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(log_path)
        .map_err(|e| format!("打开日志文件追加失败：{e}"))?;
    writeln!(file, "\n--- PERF_SUMMARY_JSON ---").map_err(|e| format!("写入失败：{e}"))?;
    writeln!(file, "{json}").map_err(|e| format!("写入失败：{e}"))?;
    Ok(())
}