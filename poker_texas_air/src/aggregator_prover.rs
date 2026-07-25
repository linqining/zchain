//! Aggregator Prover — 生成二叉树聚合的 Stwo proof。
//!
//! ## 流程
//!
//! 1. 调用 [`build_binary_tree`] 构造二叉树聚合层级
//! 2. 把每层的聚合行（`AggregatorRow`）写入 trace
//! 3. 调用 Stwo prover 生成 proof
//! 4. 返回 `AggregatorProof`（含 stark_proof + AggregatorAir 公开输入）
//!
//! ## 简化策略
//!
//! 阶段 4 PoC：把所有聚合层展平为单 trace（一行 = 一个聚合节点）。
//! 完整版（阶段 5）每层独立 prove，递归聚合到单 proof。

use stwo::core::channel::Poseidon252Channel;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, ProvingError};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::aggregator_air::{
    build_binary_tree, AggregatorAir, AggregatorRow, ChildDescriptor, cols,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::trace_gen::MethodTrace;

/// Aggregator proof（含 StarkProof + AIR 公开输入）。
#[derive(Debug, Clone)]
pub struct AggregatorProof {
    /// Stwo 内部 proof。
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
    /// AIR 公开输入。
    pub air: AggregatorAir,
    /// trace log_size。
    pub log_size: u32,
    /// 聚合的子节点数。
    pub num_children: usize,
    /// 聚合层级数。
    pub num_levels: usize,
}

/// 把多个 method proof 摘要（`ChildDescriptor`）聚合到单 proof。
///
/// # 参数
/// - `children`: 已按 `call_seq` 升序排列的子节点描述符
///
/// # 返回
/// `AggregatorProof`，可由 [`crate::aggregator_verifier::verify_aggregator`] 验证。
///
/// # Errors
///
/// - `TexasAirError::RecursionError` — 子节点链式连续性破坏 / call_seq 不连续
/// - `TexasAirError::StwoProverError` — Stwo prover 内部错误（约束不满足）
pub fn prove_aggregator(children: Vec<ChildDescriptor>) -> TexasAirResult<AggregatorProof> {
    // 1. 构造二叉树聚合
    let num_children = children.len();
    let (root, levels) = build_binary_tree(children)?;

    if levels.is_empty() {
        return Err(TexasAirError::RecursionError(
            "prove_aggregator: 单子节点无需聚合（levels 为空）".into(),
        ));
    }

    // 2. 把所有聚合行展平到单 trace
    let mut all_rows: Vec<AggregatorRow> = Vec::new();
    for level in &levels {
        all_rows.extend(level.iter().cloned());
    }

    // 3. 选择 log_size（≥10，Stwo SIMD 对齐）
    let num_rows = all_rows.len();
    let mut log_size: u32 = 10; // 最小 1024
    while (1usize << log_size) < num_rows {
        log_size += 1;
    }

    // 4. 构造 trace
    let mut trace = MethodTrace::new(log_size, cols::NUM_COLUMNS);
    for (i, row) in all_rows.iter().enumerate() {
        trace.write_row(i, &row.to_vec())?;
    }
    // padding 行（剩余）
    let padding_row = AggregatorRow::padding();
    for i in num_rows..(1usize << log_size) {
        trace.write_row(i, &padding_row.to_vec())?;
    }

    // 5. 构造 AIR 公开输入
    //    注意：阶段 4 PoC 只用顶层（root）的 left/right 描述符作为 AIR 公开输入
    //    完整版应每层一个 AIR 实例，递归聚合
    let top_level = levels.last().expect("levels 非空");
    let top_row = top_level
        .first()
        .ok_or_else(|| TexasAirError::RecursionError("顶层无聚合行".into()))?;

    // 从顶层行还原 left/right ChildDescriptor（用于 AIR 公开输入）
    let left_desc = ChildDescriptor {
        pre_state_root: top_row.left_pre_state_root,
        post_state_root: top_row.left_post_state_root,
        call_seq: top_row.left_call_seq.0,
        method_kind: crate::method_kind::MethodKind::from_u8(top_row.left_method_kind.0 as u8)
            .unwrap_or(crate::method_kind::MethodKind::CreateTable),
    };
    let right_desc = ChildDescriptor {
        pre_state_root: top_row.right_pre_state_root,
        post_state_root: top_row.right_post_state_root,
        call_seq: top_row.right_call_seq.0,
        method_kind: crate::method_kind::MethodKind::from_u8(top_row.right_method_kind.0 as u8)
            .unwrap_or(crate::method_kind::MethodKind::CreateTable),
    };

    let air = AggregatorAir {
        log_size,
        left: left_desc,
        right: right_desc,
        agg_pre_state_root: root.pre_state_root,
        agg_post_state_root: root.post_state_root,
    };

    // 6. PCS 配置 + twiddles
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let big_domain = CanonicCoset::new(log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 7. Channel + CommitmentSchemeProver
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);

    // 8. 提交空 preprocessed trace（tree 0）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 9. 提交 original trace（tree 1）
    {
        let columns = trace.to_evaluations();
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(columns);
        tree_builder.commit(&mut channel);
    }

    // 10. 构建 AIR component
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        air.clone(),
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 11. 生成 proof
    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;

    Ok(AggregatorProof {
        stark_proof,
        air,
        log_size,
        num_children,
        num_levels: levels.len(),
    })
}
