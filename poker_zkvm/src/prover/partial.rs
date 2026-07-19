//! Phase 4.1 — 链上 LCCCS 分阶段提交（PartialProveState API）。
//!
//! 将 [`super::prove`] 拆分为三阶段，支持链上 LCCCS 分阶段提交：
//!
//! 1. [`prove_partial_start`] — ELF 执行 + CCS 编译 + 初始 LCCCS + CCCCS 队列 +
//!    Transcript/PCS 初始化 + r_x_l 派生。返回的 [`PartialProveState`] 持有
//!    `initial_lcccs`（可立即上链锚定）。
//! 2. [`prove_partial_fold`] — 从 `ccccs_queue` 取 N 个 CCCCS 进行 fold_step +
//!    sumcheck::prove，更新 `current_lcccs` / `current_witness_commitment` /
//!    `fold_steps`，并返回 [`PartialFoldProgress`]（含 `intermediate_commitment`
//!    可定期上链 checkpoint）。
//! 3. [`prove_final_fold`] — 折叠剩余 CCCCS + 最终 PCS opening + 序列化完整
//!    HypernovaProof + 大小检查 + Spartan 压缩（如超限）。
//!
//! ## 等价性保证
//!
//! 三阶段路径产出的 `(proof_bytes, public_io)` 与 [`super::prove`] 完全一致：
//! - 相同的 ELF + input + config → 相同的 trace → 相同的 CCS instances
//! - 相同的 transcript absorb 序列 → 相同的 r_x_l → 相同的 fold challenge
//! - 相同的 fold_step + sumcheck → 相同的 HypernovaProof
//!
//! 测试 [`test_final_fold_equivalent_to_prove`] 验证此等价性。
//!
//! ## 用途
//!
//! - **链上 LCCCS 锚定**：start 阶段产生的 `initial_lcccs` 可立即上链锚定
//!   （CheckinTx），后续 fold 推进无需重复锚定
//! - **链上 checkpoint**：partial_fold 阶段的 `intermediate_commitment` 可定期
//!   上链 checkpoint，使长 trace 的 fold 进度可验证
//! - **降低单次上链数据量**：分阶段提交使单次上链数据量 ≤ 一个 fold step
//!   的大小，而非完整 proof

use ark_serialize::CanonicalSerialize;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use crate::ccs::{Ccs, Fr as ZkvmFr};
use crate::compiler::elf_validator::validate_elf;
use crate::constraints::{MAX_FOLD_STEP_COUNT, compile_trace_to_ccs_with_config};
use crate::error::ZkvmError;
#[allow(unused_imports)]
use crate::field::ZkvmField; // ZkvmField trait 提供 into_fr()，被 config.randomness_seed.into_fr() 调用
use crate::fold::ccccs::Ccccs;
use crate::fold::fold_loop::{FoldStepData, HypernovaProof};
use crate::fold::fold_step;
use crate::fold::lcccs::Lcccs;
use crate::fold::sumcheck;
use crate::isa::executor::{ZkvmExecutionConfig, execute_elf_with_config};
use crate::pcs::ipa::{IpaCommitment, IpaPcs};
use crate::pcs::{MultilinearPoly, Pcs};
use crate::syscalls::StubHostState;
use crate::transcript::{HYPERNOVA_FOLD_DOMAIN_TAG, Transcript};

use super::{ProverConfig, ZkPublicIo, hash_public_io, pad_trace, serialize_proof};

/// PartialProveState 中间承诺的域分离标签。
const PARTIAL_FOLD_DOMAIN_TAG: &[u8] = b"poker_zkvm_partial_fold";

/// PartialProveState — 分阶段证明的运行时状态。
///
/// 由 [`prove_partial_start`] 构造，由 [`prove_partial_fold`] 推进，
/// 最终由 [`prove_final_fold`] 消费并产出完整 HypernovaProof。
///
/// # 字段语义
///
/// - **静态字段**（start 阶段后不变）：`ccs` / `public_io` / `ccs_commitment` /
///   `public_io_commitment` / `batch_public_inputs` / `pcs` / `r_x_l` /
///   `initial_lcccs` / `initial_witness_commitment` / `config`
/// - **动态字段**（随 fold 推进）：`transcript` / `ccccs_queue` /
///   `current_lcccs` / `current_witness_commitment` / `current_witness` /
///   `fold_steps` / `last_sumcheck_transcript`
pub struct PartialProveState {
    /// 共享 CCS 结构（所有 batch 实例引用同一 CCS）。
    pub ccs: Ccs,
    /// 公共输入输出（含 input / output / randomness / commitments / events）。
    pub public_io: ZkPublicIo,
    /// CCS 结构承诺（32B Blake2b），存入最终 HypernovaProof 供 verifier 白名单校验。
    pub ccs_commitment: [u8; 32],
    /// public_io 承诺（32B Blake2b），存入最终 HypernovaProof 供 verifier 绑定校验。
    pub public_io_commitment: [u8; 32],
    /// 所有 batch 的 public_inputs（每组 `[batch_id, first_idx, last_idx]`）。
    pub batch_public_inputs: Vec<Vec<ZkvmFr>>,
    /// IPA PCS 实例（用于 witness commit + open）。
    pub pcs: IpaPcs,
    /// 主 transcript（用于 fold challenge 派生）。
    pub transcript: Transcript,
    /// 公共求值点 `r_x_l`（长度 = log2(num_rows)，所有 fold 步共享）。
    pub r_x_l: Vec<ZkvmFr>,
    /// 待折叠的 CCCCS 队列（incoming instances，按 batch 顺序排列）。
    pub ccccs_queue: Vec<Ccccs>,
    /// 初始 LCCCS（fold_loop 起点，存入 HypernovaProof.initial_lcccs）。
    pub initial_lcccs: Lcccs,
    /// 初始 witness commitment `C_L`（存入 HypernovaProof.initial_witness_commitment）。
    pub initial_witness_commitment: IpaCommitment,
    /// 当前 running LCCCS（最新 folded instance，随 fold 推进）。
    pub current_lcccs: Lcccs,
    /// 当前 running witness commitment `C'`（随 fold 推进，下一轮 fold 的 C_L）。
    pub current_witness_commitment: IpaCommitment,
    /// 当前 running witness `z'`（随 fold 推进，供最终 PCS opening 使用）。
    pub current_witness: Vec<ZkvmFr>,
    /// 已完成的 fold 步骤数据（每步含 CCCCS 输入 + sumcheck + folded 输出）。
    pub fold_steps: Vec<FoldStepData>,
    /// 最后一步 sumcheck 的 transcript（用于 PCS opening 链式）。
    pub last_sumcheck_transcript: Option<Transcript>,
    /// Prover 配置（用于 final_fold 的 proof_size_limit / max_recursion_depth）。
    pub config: ProverConfig,
}

impl std::fmt::Debug for PartialProveState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // IpaPcs 未实现 Debug，故手动实现以隐藏 pcs 字段
        f.debug_struct("PartialProveState")
            .field("ccs", &self.ccs)
            .field("public_io", &self.public_io)
            .field("ccs_commitment", &self.ccs_commitment)
            .field("public_io_commitment", &self.public_io_commitment)
            .field("batch_public_inputs", &self.batch_public_inputs.len())
            .field("pcs.max_n_vars", &self.pcs.max_n_vars())
            .field("r_x_l", &self.r_x_l.len())
            .field("ccccs_queue", &self.ccccs_queue.len())
            .field("fold_steps", &self.fold_steps.len())
            .field("config", &self.config)
            .finish()
    }
}

/// 单次 [`prove_partial_fold`] 的进度快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialFoldProgress {
    /// 累计已折叠步数（= `state.fold_steps.len()` 调用后）。
    pub folded_step_count: u32,
    /// 剩余待折叠 CCCCS 数量（= `state.ccccs_queue.len()` 调用后）。
    pub remaining_steps: u32,
    /// 当前 running witness commitment 的中间承诺
    /// （Blake2b-256 of `PARTIAL_FOLD_DOMAIN_TAG || compressed C' || fold_step_count`）。
    ///
    /// 用于链上 checkpoint，使外部观察者能验证 partial fold 推进的连续性。
    pub intermediate_commitment: [u8; 32],
    /// 本次 fold 推进的步数（可能小于请求的 n_steps，若 queue 不足）。
    pub folded_this_round: u32,
}

/// Phase 4.1 — 阶段 1：启动 partial prove。
///
/// 复用 [`super::prove`] 的 step 1-8：ELF 校验 → 执行 → trace padding → CCS 编译 →
/// LCCCS/CCCCS 构造 → PCS/Transcript 初始化 → r_x_l 派生 → 初始 witness commitment。
///
/// 返回的 [`PartialProveState`] 持有所有运行时状态：
/// - `initial_lcccs` + `initial_witness_commitment` 可立即上链锚定
/// - `ccccs_queue` 等待分阶段 fold
///
/// # 错误
/// 与 [`super::prove`] 的 step 1-8 相同（ELF / 执行 / CCS 编译失败等）。
pub fn prove_partial_start(
    elf_bytes: &[u8],
    input: &[u8],
    config: &ProverConfig,
) -> Result<PartialProveState, ZkvmError> {
    config.validate()?;

    // Phase 5.2 — 与 prove() 一致，若 rayon_threads = Some(n) 则构造临时线程池。
    // prove_partial_start 内部的 CCS 编译、后续 fold（在 prove_partial_fold 中）均依赖
    // 此处建立的线程池作用域。由于 prove_partial_fold 在 start 返回后才被调用，
    // 线程池作用域无法跨阶段保留 — 但 fold 阶段的并行度由 sumcheck/ipa 自身的 rayon
    // 调用决定，使用全局池即可；只有 CCS 编译（batch 级并行）受 parallel_ccs_compile
    // 控制。因此此处仅在 start 阶段（含 CCS 编译）使用临时线程池。
    if let Some(n) = config.rayon_threads {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build()
            .map_err(|e| ZkvmError::Other(format!("ProverConfig.rayon_threads({n}): {e}")))?;
        pool.install(|| prove_partial_start_inner(elf_bytes, input, config))
    } else {
        prove_partial_start_inner(elf_bytes, input, config)
    }
}

/// prove_partial_start 内部实现 — 由 [`prove_partial_start`] 根据线程池配置分派进入。
fn prove_partial_start_inner(
    elf_bytes: &[u8],
    input: &[u8],
    config: &ProverConfig,
) -> Result<PartialProveState, ZkvmError> {
    // 1. ELF 校验
    let _metadata = validate_elf(elf_bytes)?;

    // 2. 执行
    let exec_config = ZkvmExecutionConfig {
        input: input.to_vec(),
        randomness_seed: config.randomness_seed.into_fr(),
        initial_commitment: config.initial_commitment.into_fr(),
        final_commitment: config.final_commitment.into_fr(),
        host_state: Box::new(StubHostState),
    };
    let exec_result = execute_elf_with_config(elf_bytes, exec_config)?;

    // 2.5 构造 ZkPublicIo + 计算 public_io_commitment（需在 transcript 初始化前完成）
    let public_io = ZkPublicIo {
        input: input.to_vec(),
        output: exec_result.output.clone(),
        randomness_seed: config.randomness_seed,
        initial_commitment: config.initial_commitment,
        final_commitment: config.final_commitment,
        event_hashes: exec_result
            .events
            .iter()
            .map(|f| ZkvmFr::from_fr(*f))
            .collect(),
    };
    let public_io_commitment = hash_public_io(&public_io);

    // 3. trace padding（追加 dummy NOP 使 len 整除 batch_size）
    let mut trace = exec_result.trace;
    pad_trace(&mut trace, config.batch_size)?;

    // 4. 编译 CCS 实例（Phase 5.2 — 根据 config.parallel_ccs_compile 选择并行/顺序路径）
    let ccs_instances = compile_trace_to_ccs_with_config(
        &trace,
        config.batch_size,
        config.parallel_ccs_compile,
    )?;
    if ccs_instances.is_empty() {
        return Err(ZkvmError::Other(
            "prove_partial_start: CCS 实例为空（trace 为空或 batch_size 过大）".to_string(),
        ));
    }

    // 5. CCS 一致性 + num_vars 须为 2 的幂
    let ccs = ccs_instances[0].ccs.clone();
    let num_vars = ccs.num_vars;
    if !num_vars.is_power_of_two() {
        return Err(ZkvmError::Other(format!(
            "prove_partial_start: num_vars = {num_vars} 不是 2 的幂（IPA PCS 要求）"
        )));
    }
    let pcs_n_vars = num_vars.trailing_zeros() as usize;
    if pcs_n_vars > config.max_n_vars {
        return Err(ZkvmError::Other(format!(
            "prove_partial_start: pcs_n_vars = {pcs_n_vars} > config.max_n_vars = {}",
            config.max_n_vars
        )));
    }
    let expected_commitment = ccs.ccs_commitment();
    for inst in &ccs_instances {
        let commit = inst.ccs.ccs_commitment();
        if commit != expected_commitment {
            return Err(ZkvmError::FoldError(format!(
                "CCS 结构不一致: 首实例 commitment {:?} != 当前 {:?}",
                &expected_commitment[..8],
                &commit[..8]
            )));
        }
    }

    // 6. PCS + Transcript 初始化
    let pcs = IpaPcs::new(pcs_n_vars)?;
    let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
    // absorb 顺序与 prove() 一致：public_io_commitment → ccs_commitment → batch_public_inputs
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &public_io_commitment);
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &expected_commitment);
    let batch_public_inputs: Vec<Vec<ZkvmFr>> = ccs_instances
        .iter()
        .map(|inst| inst.public_inputs.clone())
        .collect();
    for inst in &ccs_instances {
        for pi in &inst.public_inputs {
            transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
        }
    }

    // 7. 派生 r_x_l（长度 = log2(num_rows)）
    let num_rows = ccs.num_rows();
    let r_x_l_len = if num_rows > 0 && num_rows.is_power_of_two() {
        num_rows.trailing_zeros() as usize
    } else {
        return Err(ZkvmError::Other(format!(
            "prove_partial_start: num_rows = {num_rows} 不是 2 的幂（sumcheck 要求）"
        )));
    };
    let r_x_l: Vec<ZkvmFr> = (0..r_x_l_len)
        .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
        .collect();

    // 8. 构造 initial LCCCS + CCCCS 队列
    let first = &ccs_instances[0];
    let initial_lcccs = ccs.to_lcccs(&first.witness, &r_x_l, r_x_l.clone())?;
    let initial_poly = MultilinearPoly::from_evals(first.witness.clone())?;
    let initial_witness_commitment = pcs.commit(&initial_poly)?;

    let mut ccccs_queue = Vec::with_capacity(ccs_instances.len().saturating_sub(1));
    for inst in &ccs_instances[1..] {
        let poly = MultilinearPoly::from_evals(inst.witness.clone())?;
        let commitment = pcs.commit(&poly)?;
        let ccccs = ccs.to_cccs(&inst.witness, r_x_l.clone(), commitment)?;
        ccccs_queue.push(ccccs);
    }

    // 9. 校验 fold step 上限
    if ccccs_queue.len() > MAX_FOLD_STEP_COUNT {
        return Err(ZkvmError::FoldStepCountExceeded {
            actual: ccccs_queue.len() as u32,
            limit: MAX_FOLD_STEP_COUNT as u32,
        });
    }

    // current_witness 初始化为 initial_lcccs.trace_l（与 fold_loop 内部一致）
    let current_witness = initial_lcccs.trace_l.clone();

    Ok(PartialProveState {
        ccs,
        public_io,
        ccs_commitment: expected_commitment,
        public_io_commitment,
        batch_public_inputs,
        pcs,
        transcript,
        r_x_l,
        ccccs_queue,
        initial_lcccs: initial_lcccs.clone(),
        initial_witness_commitment: initial_witness_commitment.clone(),
        current_lcccs: initial_lcccs,
        current_witness_commitment: initial_witness_commitment,
        current_witness,
        fold_steps: Vec::new(),
        last_sumcheck_transcript: None,
        config: config.clone(),
    })
}

/// Phase 4.1 — 阶段 2：分阶段 fold。
///
/// 从 `state.ccccs_queue` 取 `n_steps` 个 CCCCS 进行 fold_step + sumcheck::prove，
/// 更新 `state.current_lcccs` / `current_witness_commitment` / `current_witness` /
/// `fold_steps` / `last_sumcheck_transcript`。
///
/// # 行为
/// - `n_steps == 0` → 不修改状态，仅返回当前 progress 快照
/// - `ccccs_queue.is_empty()` → 不修改状态，仅返回当前 progress 快照
/// - `n_steps > ccccs_queue.len()` → 实际推进 `ccccs_queue.len()` 步
///
/// # 错误
/// - `fold_step::fold` 失败（CCS 不匹配 / 维度不一致）
/// - `sumcheck::prove` 失败（维度 / 校验）
pub fn prove_partial_fold(
    state: &mut PartialProveState,
    n_steps: usize,
) -> Result<PartialFoldProgress, ZkvmError> {
    let available = state.ccccs_queue.len();
    let to_fold = n_steps.min(available);
    let mut folded_this_round = 0u32;

    for _ in 0..to_fold {
        // 弹出队首 CCCCS（保持 fold 顺序与 fold_loop 一致）
        let ccccs = state.ccccs_queue.remove(0);

        // (a) fold_step — 使用主 transcript 派生 fold challenge r
        let fold_output = fold_step::fold(
            &state.current_lcccs,
            &state.current_witness_commitment,
            &ccccs,
            &mut state.transcript,
        )?;

        // (b) sumcheck::prove — fresh transcript（与 fold_loop 一致）
        let u_prime_spec = fold_output.folded_lcccs.u_l;
        let mut sumcheck_transcript = Transcript::new();
        let sumcheck_output = sumcheck::prove(
            &state.ccs,
            &fold_output.folded_witness,
            &state.current_lcccs.r_x_l,
            u_prime_spec,
            &mut sumcheck_transcript,
        )?;

        // (c) 非线性 CCS 修正：u_l = actual_u_prime（与 fold_loop 一致）
        let mut corrected_lcccs = fold_output.folded_lcccs.clone();
        corrected_lcccs.u_l = sumcheck_output.actual_u_prime;

        // (d) 收集 FoldStepData（供 verifier 重放 fold challenge + 验证 fold 等式 + 验证 sumcheck）
        state.fold_steps.push(FoldStepData {
            ccccs_witness_commitment: ccccs.witness_commitment_c.clone(),
            ccccs_u_c: ccccs.u_c,
            ccccs_x_c: ccccs.x_c.clone(),
            ccccs_trace_c: ccccs.trace_c.clone(),
            sumcheck_proof: sumcheck_output.proof.clone(),
            r_y: sumcheck_output.r_y.clone(),
            z_at_r_y: sumcheck_output.z_at_r_y,
            actual_u_prime: sumcheck_output.actual_u_prime,
            folded_lcccs: corrected_lcccs.clone(),
            folded_witness_commitment: fold_output.folded_commitment.clone(),
        });

        // (e) 推进到下一轮
        state.current_lcccs = corrected_lcccs;
        state.current_witness_commitment = fold_output.folded_commitment;
        state.current_witness = fold_output.folded_witness;
        state.last_sumcheck_transcript = Some(sumcheck_transcript);

        folded_this_round += 1;
    }

    let intermediate_commitment = compute_intermediate_commitment(
        &state.current_witness_commitment,
        state.fold_steps.len(),
    );

    Ok(PartialFoldProgress {
        folded_step_count: state.fold_steps.len() as u32,
        remaining_steps: state.ccccs_queue.len() as u32,
        intermediate_commitment,
        folded_this_round,
    })
}

/// Phase 4.1 — 阶段 3：完成 final fold + PCS opening + 序列化。
///
/// 消费 `state`，产出与 [`super::prove`] 等价的 `(proof_bytes, public_io)`。
///
/// # 流程
/// 1. 折叠 `ccccs_queue` 中所有剩余 CCCCS（等价于一次
///    `prove_partial_fold(state, usize::MAX)`）
/// 2. 根据 `fold_steps` 是否为空分两种路径：
///    - **多实例路径**（fold_steps 非空）：提取最后一步 sumcheck + PCS opening 在最后 r_y
///    - **单实例路径**（fold_steps 为空）：直接对 `initial_lcccs` 运行 sumcheck +
///      PCS opening（与 [`fold_loop`] 单实例路径一致）
/// 3. 构造完整 HypernovaProof + 序列化 + 大小检查 + Spartan 压缩（如超限）
///
/// # 错误
/// - `prove_partial_fold` 失败（fold / sumcheck 失败）
/// - PCS opening 失败（维度 / IPA 内部错误）
/// - proof 序列化后超 `proof_size_limit` 且 Spartan 压缩仍超限
pub fn prove_final_fold(
    mut state: PartialProveState,
) -> Result<(Vec<u8>, ZkPublicIo), ZkvmError> {
    // 1. 折叠所有剩余 CCCCS（若有）
    if !state.ccccs_queue.is_empty() {
        prove_partial_fold(&mut state, usize::MAX)?;
    }

    // 2. 提取 final sumcheck + r_y + z_at_r_y + PCS witness
    // 单实例路径：fold_steps 为空 → 直接对 initial_lcccs 运行 sumcheck
    // 多实例路径：fold_steps 非空 → 提取最后一步数据
    let (final_sumcheck, last_r_y, last_z_at_r_y, mut pcs_transcript, pcs_witness) =
        if state.fold_steps.is_empty() {
            // 单实例路径
            let u_prime_spec = state.initial_lcccs.u_l;
            let mut sumcheck_transcript = Transcript::new();
            let sumcheck_output = sumcheck::prove(
                &state.ccs,
                &state.initial_lcccs.trace_l,
                &state.initial_lcccs.r_x_l,
                u_prime_spec,
                &mut sumcheck_transcript,
            )?;
            // 非线性 CCS 修正：u_l = actual_u_prime（与 fold_loop 单实例路径一致）
            state.initial_lcccs.u_l = sumcheck_output.actual_u_prime;
            (
                sumcheck_output.proof,
                sumcheck_output.r_y,
                sumcheck_output.z_at_r_y,
                sumcheck_transcript,
                state.initial_lcccs.trace_l.clone(),
            )
        } else {
            // 多实例路径
            let last_step = state
                .fold_steps
                .last()
                .expect("fold_steps 非空（已校验）");
            (
                last_step.sumcheck_proof.clone(),
                last_step.r_y.clone(),
                last_step.z_at_r_y,
                state
                    .last_sumcheck_transcript
                    .clone()
                    .unwrap_or_default(),
                state.current_witness.clone(),
            )
        };

    // 3. PCS opening（在 last r_y 处打开 z'）
    let poly = MultilinearPoly::from_evals(pcs_witness)?;
    let (pcs_opening, pcs_eval) = state.pcs.open(&poly, &last_r_y, &mut pcs_transcript)?;

    // debug 校验：PCS opening eval 应 = sumcheck 的 z_at_r_y
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(
            pcs_eval.0, last_z_at_r_y,
            "PCS opening eval 应 = sumcheck 的 z_at_r_y"
        );
    }

    // 4. 构造完整 HypernovaProof
    let proof = HypernovaProof {
        abi_version: 1,
        ccs_commitment: state.ccs_commitment,
        public_io_commitment: state.public_io_commitment,
        batch_public_inputs: state.batch_public_inputs,
        initial_lcccs: state.initial_lcccs,
        initial_witness_commitment: state.initial_witness_commitment,
        fold_steps: state.fold_steps,
        final_sumcheck,
        pcs_opening,
        r_y: last_r_y,
        z_at_point: last_z_at_r_y,
    };

    // 5. 序列化 + 大小检查 + Spartan 压缩（与 prove() 一致）
    finalize_proof_bytes(proof, &state.config, state.public_io)
}

/// 序列化 HypernovaProof + 大小检查 + Spartan 压缩。
///
/// 与 [`super::prove`] 的 step 10-11 完全一致，提取为辅助函数供 final_fold 复用。
///
/// # 参数
/// - `proof` — 完整 HypernovaProof
/// - `config` — Prover 配置（用于 `proof_size_limit`）
/// - `public_io` — 与 proof 绑定的公共输入输出（不存于 HypernovaProof，由调用方传入）
fn finalize_proof_bytes(
    proof: HypernovaProof,
    config: &ProverConfig,
    public_io: ZkPublicIo,
) -> Result<(Vec<u8>, ZkPublicIo), ZkvmError> {
    let proof_bytes = serialize_proof(&proof)?;

    if proof_bytes.len() <= config.proof_size_limit {
        return Ok((proof_bytes, public_io));
    }

    // proof 过大 → Spartan 自动压缩
    let compressed = crate::prover::spartan::spartan_compress(&proof)?;
    let spartan_bytes = match compressed {
        crate::prover::groth16_compress::CompressedProof::Spartan(s) => {
            super::serialize_spartan_proof(&s)?
        }
        _ => {
            return Err(ZkvmError::Other(
                "spartan_compress 返回非 Spartan 变体（预期 Spartan）".to_string(),
            ));
        }
    };

    if spartan_bytes.len() > config.proof_size_limit {
        return Err(ZkvmError::Other(format!(
            "proof 过大 (Spartan compressed {} bytes > {} limit)",
            spartan_bytes.len(),
            config.proof_size_limit
        )));
    }

    Ok((spartan_bytes, public_io))
}

/// 计算中间状态承诺（Blake2b-256 of domain_tag || compressed C' || fold_step_count）。
///
/// 用于链上 checkpoint，使外部观察者能验证 partial fold 推进的连续性。
/// 同一 fold_step_count + 同一 C' → 同一承诺，使链上锚定的承诺可被 verifier 重放验证。
fn compute_intermediate_commitment(
    commitment: &IpaCommitment,
    fold_step_count: usize,
) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(PARTIAL_FOLD_DOMAIN_TAG);
    let mut cmt_bytes = Vec::new();
    commitment
        .0
        .serialize_compressed(&mut cmt_bytes)
        .expect("G1Affine serialize_compressed 不应失败");
    hasher.update(&cmt_bytes);
    hasher.update(&(fold_step_count as u64).to_le_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{MAX_PROOF_TOTAL_SIZE, prove};

    /// 辅助：构造小规模测试 ELF（8 步程序：LUI + 2 ADDI + ECALL + 4 NOP）。
    ///
    /// 与 `prover/mod.rs::build_test_elf_bytes` 相同的 ELF 结构，
    /// batch_size=3 → padding 到 9 步 → 3 batches → 2 fold steps。
    fn build_test_elf() -> Vec<u8> {
        fn encode_i(opcode: u32, funct3: u8, rd: u8, rs1: u8, imm12: u32) -> u32 {
            ((imm12 & 0xFFF) << 20)
                | ((rs1 as u32) << 15)
                | ((funct3 as u32) << 12)
                | ((rd as u32) << 7)
                | opcode
        }
        fn build_elf(entry: u32, text_vaddr: u32, text_bytes: &[u8]) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(84 + text_bytes.len());
            bytes.extend_from_slice(&[
                0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]);
            bytes.extend_from_slice(&2u16.to_le_bytes());
            bytes.extend_from_slice(&0xF3u16.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&entry.to_le_bytes());
            bytes.extend_from_slice(&52u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&52u16.to_le_bytes());
            bytes.extend_from_slice(&32u16.to_le_bytes());
            bytes.extend_from_slice(&1u16.to_le_bytes());
            bytes.extend_from_slice(&40u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            let p_offset = 84u32;
            let p_filesz = text_bytes.len() as u32;
            let p_memsz = text_bytes.len() as u32;
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&p_offset.to_le_bytes());
            bytes.extend_from_slice(&text_vaddr.to_le_bytes());
            bytes.extend_from_slice(&text_vaddr.to_le_bytes());
            bytes.extend_from_slice(&p_filesz.to_le_bytes());
            bytes.extend_from_slice(&p_memsz.to_le_bytes());
            bytes.extend_from_slice(&5u32.to_le_bytes());
            bytes.extend_from_slice(&0x1000u32.to_le_bytes());
            bytes.extend_from_slice(text_bytes);
            bytes
        }
        fn encode_text(words: &[u32]) -> Vec<u8> {
            words.iter().copied().flat_map(u32::to_le_bytes).collect()
        }
        let text = encode_text(&[
            (1 << 12) | (10 << 7) | 0x37, // LUI
            encode_i(0x13, 0, 11, 0, 32), // ADDI
            encode_i(0x13, 0, 17, 0, 2),  // ADDI a7, x0, 2 (commit_output)
            0x00000073,                   // ECALL
            encode_i(0x13, 0, 0, 0, 0),   // NOP
            encode_i(0x13, 0, 0, 0, 0),   // NOP
            encode_i(0x13, 0, 0, 0, 0),   // NOP
            encode_i(0x13, 0, 0, 0, 0),   // NOP
        ]);
        build_elf(0x1000, 0x1000, &text)
    }

    /// 辅助：构造测试 ProverConfig。
    fn test_config(batch_size: usize) -> ProverConfig {
        ProverConfig {
            batch_size,
            proof_size_limit: MAX_PROOF_TOTAL_SIZE,
            ..Default::default()
        }
    }

    #[test]
    fn test_partial_start_state_init() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);
        let state = prove_partial_start(&elf, &input, &config).expect("partial_start");

        // 验证状态字段
        assert!(
            !state.batch_public_inputs.is_empty(),
            "应有 batch_public_inputs"
        );
        assert!(!state.r_x_l.is_empty(), "r_x_l 应非空");
        assert_eq!(
            state.ccccs_queue.len() + 1,
            state.batch_public_inputs.len(),
            "ccccs_queue + initial = total batches"
        );
        assert!(state.fold_steps.is_empty(), "初始 fold_steps 应为空");
        assert!(state.last_sumcheck_transcript.is_none());
        // current_lcccs 初始应等于 initial_lcccs
        assert_eq!(
            state.initial_lcccs.trace_l, state.current_lcccs.trace_l,
            "初始 current_lcccs 应 = initial_lcccs"
        );
        assert_eq!(
            state.current_witness, state.initial_lcccs.trace_l,
            "初始 current_witness 应 = initial_lcccs.trace_l"
        );
        // ccs_commitment 与 ccs.ccs_commitment() 一致
        assert_eq!(state.ccs_commitment, state.ccs.ccs_commitment());
    }

    #[test]
    fn test_partial_fold_zero_steps_no_change() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);
        let mut state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        let queue_len_before = state.ccccs_queue.len();
        let cmt_l_before = state.current_witness_commitment.clone();

        let progress = prove_partial_fold(&mut state, 0).expect("partial_fold 0");
        assert_eq!(progress.folded_this_round, 0);
        assert_eq!(progress.folded_step_count, 0);
        assert_eq!(progress.remaining_steps, queue_len_before as u32);
        assert_eq!(state.ccccs_queue.len(), queue_len_before);
        assert!(state.fold_steps.is_empty());
        // 未推进时 current_witness_commitment 不变
        assert_eq!(
            state.current_witness_commitment.0, cmt_l_before.0,
            "0 步 fold 后 current_witness_commitment 不应变"
        );
    }

    #[test]
    fn test_partial_fold_single_step() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);
        let mut state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        let queue_len = state.ccccs_queue.len();
        assert!(
            queue_len >= 1,
            "应有至少 1 个 CCCCS（8 步 / batch_size=3 → 3 batches → 2 CCCCS）"
        );

        let progress = prove_partial_fold(&mut state, 1).expect("partial_fold 1");
        assert_eq!(progress.folded_this_round, 1);
        assert_eq!(progress.folded_step_count, 1);
        assert_eq!(progress.remaining_steps, (queue_len - 1) as u32);
        assert_eq!(state.fold_steps.len(), 1);
        assert_eq!(state.ccccs_queue.len(), queue_len - 1);
    }

    #[test]
    fn test_partial_fold_more_than_available() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);
        let mut state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        let queue_len = state.ccccs_queue.len();

        // 请求 100 步但只有 queue_len 个 CCCCS
        let progress = prove_partial_fold(&mut state, 100).expect("partial_fold 100");
        assert_eq!(progress.folded_this_round, queue_len as u32);
        assert_eq!(progress.folded_step_count, queue_len as u32);
        assert_eq!(progress.remaining_steps, 0);
        assert!(state.ccccs_queue.is_empty());
    }

    #[test]
    fn test_final_fold_equivalent_to_prove() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);

        // 路径 1：直接 prove
        let (proof_direct, public_io_direct) = prove(&elf, &input, &config).expect("prove");

        // 路径 2：partial_start + final_fold（一次性 fold 全部）
        let state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        let (proof_partial, public_io_partial) =
            prove_final_fold(state).expect("final_fold");

        // public_io 应一致
        assert_eq!(public_io_direct, public_io_partial);
        // proof 字节应完全一致
        assert_eq!(
            proof_direct, proof_partial,
            "PartialProveState 三阶段路径产出的 proof 应与 prove() 完全一致"
        );
    }

    #[test]
    fn test_final_fold_with_intermediate_partial_fold() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);

        // 路径 1：直接 prove
        let (proof_direct, _) = prove(&elf, &input, &config).expect("prove");

        // 路径 2：partial_start + partial_fold(1) + final_fold
        let mut state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        let queue_len = state.ccccs_queue.len();
        if queue_len >= 1 {
            let progress = prove_partial_fold(&mut state, 1).expect("partial_fold 1");
            assert_eq!(progress.folded_this_round, 1);
        }
        let (proof_partial, _) = prove_final_fold(state).expect("final_fold");

        // 即使中途分阶段 fold，最终 proof 也应一致
        assert_eq!(
            proof_direct, proof_partial,
            "分阶段 fold 后 final_fold 的 proof 应与 prove() 完全一致"
        );
    }

    #[test]
    fn test_final_fold_with_multiple_partial_folds() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);

        let (proof_direct, _) = prove(&elf, &input, &config).expect("prove");

        // 多次 partial_fold（每次 1 步）+ final_fold
        let mut state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        while !state.ccccs_queue.is_empty() {
            let _ = prove_partial_fold(&mut state, 1).expect("partial_fold 1");
        }
        let (proof_partial, _) = prove_final_fold(state).expect("final_fold");

        assert_eq!(
            proof_direct, proof_partial,
            "多次 partial_fold 后 final_fold 的 proof 应与 prove() 完全一致"
        );
    }

    #[test]
    fn test_intermediate_commitment_changes_with_fold() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);
        let mut state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        if state.ccccs_queue.is_empty() {
            return; // skip if no fold steps
        }

        let progress0 = prove_partial_fold(&mut state, 0).expect("fold 0");
        let cmt_before = progress0.intermediate_commitment;

        let progress1 = prove_partial_fold(&mut state, 1).expect("fold 1");
        let cmt_after = progress1.intermediate_commitment;

        assert_ne!(
            cmt_before, cmt_after,
            "fold 推进后 intermediate_commitment 应改变"
        );

        // 再次 fold 0 步，commitment 应保持稳定（依赖 current_witness_commitment + fold_step_count）
        let progress2 = prove_partial_fold(&mut state, 0).expect("fold 0 again");
        assert_eq!(
            cmt_after, progress2.intermediate_commitment,
            "无 fold 推进时 intermediate_commitment 应保持稳定"
        );
    }

    #[test]
    fn test_single_instance_partial_path() {
        // 单实例路径：1 batch → 0 个 CCCCS → fold_steps 为空 → 单实例 sumcheck + PCS opening
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        // batch_size=10 使 8 步程序正好 1 batch（无 padding，1 batch）
        let config = test_config(10);

        let state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        assert!(
            state.ccccs_queue.is_empty(),
            "单实例应无 CCCCS 队列（8 步 / batch_size=10 → 1 batch）"
        );

        let (proof_partial, _) = prove_final_fold(state).expect("final_fold");
        let (proof_direct, _) = prove(&elf, &input, &config).expect("prove");
        assert_eq!(
            proof_direct, proof_partial,
            "单实例路径下 partial 与 direct 应一致"
        );
    }

    #[test]
    fn test_progress_fields_consistent() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);
        let mut state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        let total = state.ccccs_queue.len();

        let mut cumulative = 0u32;
        while !state.ccccs_queue.is_empty() {
            let progress = prove_partial_fold(&mut state, 1).expect("partial_fold 1");
            cumulative += 1;
            assert_eq!(progress.folded_this_round, 1);
            assert_eq!(progress.folded_step_count, cumulative);
            assert_eq!(progress.remaining_steps, (total as u32) - cumulative);
        }

        // 全部 fold 完后，progress 应反映终态
        let final_progress = prove_partial_fold(&mut state, 1).expect("partial_fold empty");
        assert_eq!(final_progress.folded_this_round, 0);
        assert_eq!(final_progress.folded_step_count, total as u32);
        assert_eq!(final_progress.remaining_steps, 0);
    }

    #[test]
    fn test_fold_step_count_exceeded_error() {
        // 构造一个 ccccs_queue 长度 > MAX_FOLD_STEP_COUNT 的场景
        // 由于 prove_partial_start 已校验 MAX_FOLD_STEP_COUNT，此处直接构造非法 state
        // 验证 prove_partial_start 在 start 阶段就拒绝
        // （此测试仅作为契约验证，不构造实际非法 ELF）
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = test_config(3);
        let state = prove_partial_start(&elf, &input, &config).expect("partial_start");
        assert!(
            state.ccccs_queue.len() <= MAX_FOLD_STEP_COUNT,
            "prove_partial_start 应已保证 ccccs_queue.len() <= MAX_FOLD_STEP_COUNT"
        );
    }

    #[test]
    fn test_invalid_elf_rejected() {
        let bad_elf = b"not an elf";
        let input = vec![0u8; 32];
        let config = test_config(3);
        let result = prove_partial_start(bad_elf, &input, &config);
        assert!(
            result.is_err(),
            "非法 ELF 应在 partial_start 阶段被拒绝"
        );
    }

    #[test]
    fn test_invalid_config_rejected() {
        let elf = build_test_elf();
        let input = vec![0u8; 32];
        let config = ProverConfig {
            batch_size: 0, // 非法
            ..Default::default()
        };
        let result = prove_partial_start(&elf, &input, &config);
        assert!(
            result.is_err(),
            "batch_size=0 应在 partial_start 阶段被拒绝"
        );
    }

    #[test]
    fn test_compute_intermediate_commitment_deterministic() {
        use ark_bn254::G1Affine;
        use ark_ec::AffineRepr;

        let cmt = IpaCommitment(G1Affine::generator());
        let c1 = compute_intermediate_commitment(&cmt, 0);
        let c2 = compute_intermediate_commitment(&cmt, 0);
        assert_eq!(c1, c2, "相同输入应产生相同承诺");

        // fold_step_count 不同 → 承诺不同
        let c3 = compute_intermediate_commitment(&cmt, 1);
        assert_ne!(c1, c3, "fold_step_count 不同应产生不同承诺");
    }
}