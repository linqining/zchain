//! Prover 入口 — 单方法 prove + 聚合 prove。
//!
//! ## API
//!
//! - [`prove_create_table`] — 生成 `create_table` 方法的 L1 Stwo proof
//! - [`prove_method`] — 泛型 prove，支持任意 method AIR（阶段 2-4）
//! - [`aggregate_proofs`] — 二叉树聚合多个 L1 proof 到单 proof（阶段 2 实现）

use stwo::core::channel::Poseidon252Channel;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, ProvingError};
use stwo::prover::backend::simd::SimdBackend;
use stwo::core::vcs_lifted::poseidon252_merkle::{Poseidon252MerkleChannel, Poseidon252MerkleHasher};
use stwo::core::proof::StarkProof;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, TraceLocationAllocator};

use crate::airs::lifecycle::create_table::CreateTableAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::trace_gen::create_table_trace::CreateTableTrace;
use crate::trace_gen::MethodTrace;

/// `create_table` 方法的 L1 proof 类型。
#[derive(Debug, Clone)]
pub struct CreateTableProof {
    /// Stwo 内部 proof。
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
    /// AIR 公开输入（用于 verify）。
    pub air: CreateTableAir,
    /// trace log_size。
    pub log_size: u32,
}

/// 泛型 method proof（适用于任意 method AIR）。
///
/// 阶段 2-4 引入：替代为每个方法定义专用 Proof 类型。
#[derive(Debug, Clone)]
pub struct MethodProof<A: FrameworkEval + Clone + Sync> {
    /// Stwo 内部 proof。
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
    /// AIR 公开输入（用于 verify）。
    pub air: A,
    /// trace log_size。
    pub log_size: u32,
    /// trace 列数（用于 verifier 重建 commitment）。
    pub num_columns: usize,
}

/// 生成 `create_table` 方法的 L1 proof。
///
/// # 参数
/// - `trace`: 由 [`gen_create_table_trace`] 生成的 trace
///
/// # 返回
/// `CreateTableProof`，可由 [`verify_create_table`] 验证。
///
/// # Errors
///
/// - `TexasAirError::StwoProverError` — Stwo prover 内部错误（如约束不满足）
pub fn prove_create_table(trace: &CreateTableTrace) -> TexasAirResult<CreateTableProof> {
    let log_size = trace.trace.log_size;

    // 1. PCS 配置 + twiddles 预计算
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let big_domain = CanonicCoset::new(log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 2. Channel + CommitmentSchemeProver
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);

    // 3. 提交空 preprocessed trace（tree 0）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 4. 提交 original trace（tree 1）
    {
        let columns = trace.trace.to_evaluations();
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(columns);
        tree_builder.commit(&mut channel);
    }

    // 5. 构建 AIR component
    let air = trace.air.clone();
    let mut allocator = TraceLocationAllocator::default();
    let component =
        FrameworkComponent::new(&mut allocator, air, stwo::core::fields::qm31::SecureField::from(0u32));

    // 6. 生成证明
    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;

    Ok(CreateTableProof {
        stark_proof,
        air: trace.air.clone(),
        log_size,
    })
}

/// 泛型 method prove — 生成任意 method AIR 的 L1 proof。
///
/// 阶段 2-4 通用 prove 入口。所有 17 个新方法（lifecycle/actions/crypto）
/// 通过此函数生成 proof，无需为每个方法定义专用 prove 函数。
///
/// # 参数
/// - `trace`: 已构造的 `MethodTrace`（trace 数据）
/// - `air`: AIR 公开输入实例
/// - `num_columns`: trace 列数
///
/// # 返回
/// `MethodProof<A>`，可由 [`crate::verifier::verify_method`] 验证。
///
/// # Errors
///
/// - `TexasAirError::StwoProverError` — Stwo prover 内部错误（约束不满足）
pub fn prove_method<A>(trace: &MethodTrace, air: A, num_columns: usize) -> TexasAirResult<MethodProof<A>>
where
    A: FrameworkEval + Clone + Sync,
{
    let log_size = trace.log_size;

    // 1. PCS 配置 + twiddles
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let big_domain = CanonicCoset::new(log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 2. Channel + CommitmentSchemeProver
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);

    // 3. 提交空 preprocessed trace（tree 0）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 4. 提交 original trace（tree 1）
    {
        let columns = trace.to_evaluations();
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(columns);
        tree_builder.commit(&mut channel);
    }

    // 5. 构建 AIR component
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        air.clone(),
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 6. 生成证明
    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;

    Ok(MethodProof {
        stark_proof,
        air,
        log_size,
        num_columns,
    })
}

/// 聚合多个 L1 proof 到单 proof。
///
/// 委托给 [`crate::aggregator_prover::prove_aggregator`]。
///
/// # Errors
///
/// - `TexasAirError::RecursionError` — 子节点链式连续性破坏
/// - `TexasAirError::StwoProverError` — Stwo prover 内部错误
pub fn aggregate_proofs(
    children: Vec<crate::aggregator_air::ChildDescriptor>,
) -> TexasAirResult<crate::aggregator_prover::AggregatorProof> {
    crate::aggregator_prover::prove_aggregator(children)
}

