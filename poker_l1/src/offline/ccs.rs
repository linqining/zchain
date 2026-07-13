//! CCS 电路 trait + Hypernova fold step + 多步折叠循环（Task 26 — SubTask 26.1 / 26.2 / 26.3 / 26.4）。
//!
//! 严格遵循 spec.md L659–663（FROZEN 2026-06-27）：
//! - **SubTask 26.1**：CCS 电路 trait 定义
//! - **SubTask 26.2**：Hypernova fold step 实现
//! - **SubTask 26.3**：多步折叠循环（fold_step_count 上限 1000，O15）
//! - **SubTask 26.4**：集成 `poker_protocol::zk_shuffle` 作为 CCS 电路
//!
//! ## CCS（Customizable Constraint System）
//!
//! spec.md L661-663：每步生成一个 CCS 电路实例，使用 Hypernova 折叠为单个最终证明 π，
//! 附状态增量 Δ。π 的 public_io 包含 ack_chain_hash + skip_count + segment_continuity_proof。
//!
//! ## MVP 实现
//!
//! 当前实现 CCS trait + fold step 接口骨架，具体折叠算法在 Production 阶段实现。

use crate::Hash;
use crate::error::PokerL1Error;

use super::hypernova::{FinalSumcheck, FoldedInstance, HypernovaProof, WitnessCommitment};
use super::zk_verifier::ZkPublicIo;

// ===== Phase 11 Re-export：新 Fr-based 类型（迁移目标）=====
pub use poker_zkvm::ccs::{Ccs as NewCcs, CcsInstance as NewCcsInstance, Fr as ZkvmFr};
pub use poker_zkvm::fold::ccccs::Ccccs;
pub use poker_zkvm::fold::fold_loop::HypernovaProof as ZkvmHypernovaProof;
pub use poker_zkvm::fold::fold_step::FoldStepOutput;
pub use poker_zkvm::fold::lcccs::Lcccs;
pub use poker_zkvm::pcs::ipa::{IpaCommitment, IpaPcs};
pub use poker_zkvm::precompiles::CcsCircuit as NewCcsCircuit;
pub use poker_zkvm::transcript::Transcript as ZkvmTranscript;

/// CCS 电路实例（SubTask 26.1）。
///
/// 每步链下执行生成一个 CCS 实例，包含：
/// - 约束矩阵（mats）
/// - 公共输入（public_inputs）
/// - 见证（witness）
/// - 状态增量（state_delta）
///
/// # 已废弃（Phase 11 迁移）
///
/// 此 struct 基于 `Hash` 类型，已被 `poker_zkvm::ccs::CcsInstance`（Fr-based 新类型）取代。
/// Phase 11 BREAKING 迁移：旧 `fold_step` / `fold_loop` 已返回 Err，
/// 调用方必须迁移到 `poker_zkvm::fold::fold_step::fold` / `poker_zkvm::fold::fold_loop::fold_loop`。
#[deprecated(
    since = "0.3.0",
    note = "Use `poker_zkvm::ccs::CcsInstance` (Fr-based) instead. Phase 11 BREAKING migration."
)]
#[derive(Debug, Clone)]
pub struct CcsInstance {
    /// 约束矩阵哈希列表（每个矩阵的 commitment）。
    pub mat_commitments: Vec<Hash>,
    /// 公共输入哈希。
    pub public_input_hash: Hash,
    /// 见证 commitment（witness 不上链，仅 commitment）。
    pub witness_commitment: Hash,
    /// 状态增量哈希（Δ_i 的哈希，用于 public_io.state_delta_hash 聚合）。
    pub state_delta_hash: Hash,
    /// 该步对应的 ack 集合哈希（用于 ack_chain_hash 聚合）。
    pub ack_step_hash: Hash,
}

/// CCS 电路 trait（SubTask 26.1）。
///
/// 每种具体电路（如 `poker_protocol::zk_shuffle`）实现此 trait，
/// 提供约束矩阵 / 公共输入 / 见证接口。
///
/// # 已废弃（Phase 10 迁移）
///
/// 此 trait 基于 `Hash` 类型，已被 `poker_zkvm::precompiles::CcsCircuit`（Fr-based 新签名）取代。
/// Phase 11 将完成完整迁移：poker_l1 通过 `pub use poker_zkvm::precompiles::CcsCircuit;` re-export，
/// 旧调用方迁移到新类型。新代码应使用 `poker_zkvm::precompiles::CcsCircuit`。
#[deprecated(
    since = "0.2.0",
    note = "Use `poker_zkvm::precompiles::CcsCircuit` (Fr-based) instead. Phase 11 将完成迁移。"
)]
#[allow(deprecated)]
pub trait CcsCircuit: Send + Sync {
    /// 电路名称（用于日志 / 调试）。
    fn name(&self) -> &str;

    /// 约束矩阵数量。
    fn num_matrices(&self) -> usize;

    /// 生成 CCS 实例（SubTask 26.1）。
    ///
    /// 输入：见证 + 公共输入 + 状态增量。
    /// 输出：CCS 实例（含 commitments）。
    #[allow(deprecated)]
    fn to_instance(
        &self,
        witness: &[u8],
        public_inputs: &[u8],
        state_delta: &[u8],
        ack_step_hash: Hash,
    ) -> Result<CcsInstance, PokerL1Error>;
}

/// Hypernova fold step 结果（SubTask 26.2）。
///
/// # 已废弃（Phase 11 迁移）
///
/// 被 `poker_zkvm::fold::fold_step::FoldStepOutput` 取代（含真实 folded LCCCS + witness + commitment）。
#[deprecated(
    since = "0.3.0",
    note = "Use `poker_zkvm::fold::fold_step::FoldStepOutput` instead. Phase 11 BREAKING migration."
)]
#[derive(Debug, Clone)]
pub struct FoldStepResult {
    /// 折叠后的 folded instance。
    pub folded_instance: FoldedInstance,
    /// 折叠后的 witness commitment。
    pub witness_commitment: WitnessCommitment,
    /// 该步的 sumcheck（中间结果）。
    pub sumcheck: FinalSumcheck,
    /// 累计状态增量哈希。
    pub cumulative_state_delta_hash: Hash,
    /// 累计 ack_chain_hash。
    pub cumulative_ack_chain_hash: Hash,
    /// 已折叠步数。
    pub fold_step_count: u32,
}

/// 执行单步 Hypernova fold（SubTask 26.2）。
///
/// # 已废弃（Phase 11 迁移）
///
/// 此函数为 MVP stub，使用 blake2b 哈希链冒充折叠，**Phase 11 已移除该逻辑**。
/// 调用此函数将返回 `Err`。请使用 [`fold_step_real`] 或 `poker_zkvm::fold::fold_step::fold`。
#[deprecated(
    since = "0.3.0",
    note = "Use `fold_step_real` or `poker_zkvm::fold::fold_step::fold` instead. Phase 11 BREAKING migration."
)]
#[allow(deprecated)]
pub fn fold_step(
    _prev: Option<&FoldStepResult>,
    _instance: &CcsInstance,
    _chain_id: crate::ChainId,
    _game_id: &crate::object_model::ObjectID,
) -> Result<FoldStepResult, PokerL1Error> {
    Err(PokerL1Error::Other(
        "Phase 11 BREAKING: fold_step stub removed. Use poker_zkvm::fold::fold_step::fold instead."
            .to_string(),
    ))
}

/// 多步折叠循环结果（SubTask 26.3）。
///
/// # 已废弃（Phase 11 迁移）
///
/// 被 `poker_zkvm::fold::fold_loop::HypernovaProof` 取代（含完整 fold_steps + final_sumcheck + PCS opening）。
#[deprecated(
    since = "0.3.0",
    note = "Use `poker_zkvm::fold::fold_loop::HypernovaProof` instead. Phase 11 BREAKING migration."
)]
#[derive(Debug, Clone)]
pub struct FoldLoopResult {
    /// 最终 Hypernova proof。
    pub proof: HypernovaProof,
    /// 最终 public_io（用于 zk_verify）。
    pub public_io: ZkPublicIo,
    /// 总折叠步数。
    pub fold_step_count: u32,
}

/// 执行多步折叠循环（SubTask 26.3）。
///
/// 将多个 CCS 实例折叠为单个最终 proof π。
///
/// # 参数
/// - `instances`：CCS 实例列表（按折叠顺序）
/// - `initial_commitment`：折叠起点状态承诺
/// - `final_commitment`：折叠终点状态承诺
/// - `ack_chain_hash`：所有 checkpoint ack 的聚合哈希（由 ack_chain 模块计算）
/// - `skip_count`：被跳过的 checkpoint 段数
/// - `segment_continuity_proof`：段间连续性证明
///
/// # 上限
/// `instances.len()` <= 1000（O15 修复 — fold_step_count 上限 1000）。
///
/// # 已废弃（Phase 11 迁移）
///
/// 此函数为 MVP stub，使用 blake2b 哈希链冒充折叠，**Phase 11 已移除该逻辑**。
/// 调用此函数将返回 `Err`。请使用 [`fold_loop_real`] 或 `poker_zkvm::fold::fold_loop::fold_loop`。
#[deprecated(
    since = "0.3.0",
    note = "Use `fold_loop_real` or `poker_zkvm::fold::fold_loop::fold_loop` instead. Phase 11 BREAKING migration."
)]
#[allow(deprecated)]
pub fn fold_loop(
    _instances: &[CcsInstance],
    _initial_commitment: Hash,
    _final_commitment: Hash,
    _ack_chain_hash: Hash,
    _skip_count: u32,
    _segment_continuity_proof: Vec<u8>,
) -> Result<FoldLoopResult, PokerL1Error> {
    Err(PokerL1Error::Other(
        "Phase 11 BREAKING: fold_loop stub removed. Use poker_zkvm::fold::fold_loop::fold_loop instead.".to_string(),
    ))
}

/// ZkShuffle CCS 电路适配器（SubTask 26.4）。
///
/// 将 `poker_protocol::zk_shuffle` 电路适配为 CCS 实例。
/// MVP 阶段：仅提供 trait 实现，实际电路转换在 Production 阶段实现。
///
/// # 已废弃（Phase 10 迁移）
///
/// 此类型已迁移到 `poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit`（Fr-based 新签名）。
/// Phase 11 将通过 `pub use` re-export 新类型，旧调用方迁移到新类型。
/// 新代码应使用 `poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit`。
#[deprecated(
    since = "0.2.0",
    note = "Use `poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit` (Fr-based) instead. Phase 11 将完成迁移。"
)]
pub struct ZkShuffleCcsCircuit {
    /// 电路名称。
    name: String,
    /// 约束矩阵数量。
    num_mats: usize,
}

#[allow(deprecated)] // Phase 11 将完成 Fr-based 迁移
impl ZkShuffleCcsCircuit {
    /// 创建 ZkShuffle CCS 电路。
    pub fn new() -> Self {
        Self {
            name: "zk_shuffle".to_string(),
            num_mats: 3, // CCS 标准要求 q=2 → 3 个矩阵（A, B, C）
        }
    }
}

#[allow(deprecated)] // Phase 11 将完成 Fr-based 迁移
impl Default for ZkShuffleCcsCircuit {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(deprecated)] // Phase 11 将完成 Fr-based 迁移
impl CcsCircuit for ZkShuffleCcsCircuit {
    fn name(&self) -> &str {
        &self.name
    }

    fn num_matrices(&self) -> usize {
        self.num_mats
    }

    fn to_instance(
        &self,
        witness: &[u8],
        public_inputs: &[u8],
        state_delta: &[u8],
        ack_step_hash: Hash,
    ) -> Result<CcsInstance, PokerL1Error> {
        // MVP：直接对输入做哈希作为 commitments
        let hash_data = |data: &[u8]| -> Hash {
            let mut hasher = blake2::Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
            use blake2::digest::Update;
            hasher.update(data);
            let mut out = [0u8; 32];
            use blake2::digest::VariableOutput;
            hasher
                .finalize_variable(&mut out)
                .expect("Blake2bVar finalize 不应失败");
            out
        };

        let mat_commitments = (0..self.num_mats)
            .map(|i| {
                let mut input = witness.to_vec();
                input.push(i as u8);
                hash_data(&input)
            })
            .collect();

        Ok(CcsInstance {
            mat_commitments,
            public_input_hash: hash_data(public_inputs),
            witness_commitment: hash_data(witness),
            state_delta_hash: hash_data(state_delta),
            ack_step_hash,
        })
    }
}

// ===== Phase 11: LegacyCcsInstanceAdapter（编译兼容，运行时 Err）=====

/// 旧 hash-based CcsInstance 的编译兼容适配器（Phase 11 过渡）。
///
/// **v1.2 诚实声明**：仅用于过渡期编译兼容，`to_ccs_instance()` 运行时返回 `Err`。
/// hash 是单向的，无法恢复真实 CCS 矩阵 / witness / public_inputs。
/// 旧调用方在 Production 下会失败，必须重构以提供真实矩阵。
///
/// # 迁移指南
///
/// 旧代码：
/// ```ignore
/// let instance: CcsInstance = circuit.to_instance(witness, pub_inputs, state_delta, ack_hash)?;
/// ```
///
/// 新代码：
/// ```ignore
/// use poker_zkvm::precompiles::CcsCircuit;
/// let instance = circuit.to_ccs_instance(&witness_fr, &public_inputs_fr)?;
/// ```
#[deprecated(
    since = "0.3.0",
    note = "Migrate to poker_zkvm::ccs::CcsInstance with real matrices"
)]
#[allow(deprecated)]
pub struct LegacyCcsInstanceAdapter {
    /// 旧 hash-based 实例（仅保留用于 `name()` / `num_matrices()` 查询）。
    pub legacy: CcsInstance,
}

#[allow(deprecated)]
impl LegacyCcsInstanceAdapter {
    /// 从旧 hash-based CcsInstance 构造适配器。
    pub const fn new(legacy: CcsInstance) -> Self {
        Self { legacy }
    }
}

#[allow(deprecated)]
impl NewCcsCircuit for LegacyCcsInstanceAdapter {
    fn name(&self) -> &str {
        "legacy_hash_based_adapter"
    }

    fn num_matrices(&self) -> usize {
        self.legacy.mat_commitments.len()
    }

    fn to_ccs_instance(
        &self,
        _witness: &[ZkvmFr],
        _public_inputs: &[ZkvmFr],
    ) -> Result<NewCcsInstance, poker_zkvm::error::ZkvmError> {
        Err(poker_zkvm::error::ZkvmError::Other(
            "legacy hash-based instance cannot be really folded — hash is one-way, cannot recover matrices".to_string(),
        ))
    }
}

// ===== Phase 11: 真实 Hypernova fold thin wrapper =====

/// 真实 Hypernova 单步折叠（委托到 `poker_zkvm::fold::fold_step::fold`）。
///
/// 这是 Phase 11 迁移后的推荐入口，替代旧 `fold_step` stub。
///
/// # 参数
/// - `lcccs` — LCCCS_L 实例（running instance）
/// - `witness_commitment_l` — LCCCS_L 的 witness commitment `C_L`
/// - `ccccs` — CCCCS_C 实例（incoming instance）
/// - `transcript` — Fiat-Shamir transcript
pub fn fold_step_real(
    lcccs: &Lcccs,
    witness_commitment_l: &IpaCommitment,
    ccccs: &Ccccs,
    transcript: &mut ZkvmTranscript,
) -> Result<FoldStepOutput, PokerL1Error> {
    poker_zkvm::fold::fold_step::fold(lcccs, witness_commitment_l, ccccs, transcript)
        .map_err(super::hypernova::map_zkvm_error)
}

/// 真实 Hypernova 多步折叠循环（委托到 `poker_zkvm::fold::fold_loop::fold_loop`）。
///
/// 这是 Phase 11 迁移后的推荐入口，替代旧 `fold_loop` stub。
#[allow(clippy::too_many_arguments)]
pub fn fold_loop_real(
    ccs: &NewCcs,
    initial_lcccs: Lcccs,
    initial_commitment: IpaCommitment,
    ccccs_instances: &[Ccccs],
    pcs: &IpaPcs,
    transcript: &mut ZkvmTranscript,
    ccs_commitment: [u8; 32],
    public_io_commitment: [u8; 32],
    batch_public_inputs: Vec<Vec<ZkvmFr>>,
) -> Result<ZkvmHypernovaProof, PokerL1Error> {
    poker_zkvm::fold::fold_loop::fold_loop(
        ccs,
        initial_lcccs,
        initial_commitment,
        ccccs_instances,
        pcs,
        transcript,
        ccs_commitment,
        public_io_commitment,
        batch_public_inputs,
    )
    .map_err(super::hypernova::map_zkvm_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_deprecated_fold_step_returns_error() {
        let instance = CcsInstance {
            mat_commitments: vec![[0; 32]],
            public_input_hash: [0; 32],
            witness_commitment: [0; 32],
            state_delta_hash: [0; 32],
            ack_step_hash: [0; 32],
        };
        let result = fold_step(
            None,
            &instance,
            crate::DEFAULT_CHAIN_ID,
            &crate::object_model::ObjectID::new([0u8; 20], 0),
        );
        assert!(matches!(result, Err(PokerL1Error::Other(_))));
    }

    #[test]
    #[allow(deprecated)]
    fn test_deprecated_fold_loop_returns_error() {
        let result = fold_loop(&[], [0; 32], [0; 32], [0; 32], 0, Vec::new());
        assert!(matches!(result, Err(PokerL1Error::Other(_))));
    }

    #[test]
    #[allow(deprecated)]
    fn test_deprecated_zk_shuffle_circuit_still_compiles() {
        let circuit = ZkShuffleCcsCircuit::new();
        assert_eq!(circuit.name(), "zk_shuffle");
        assert_eq!(circuit.num_matrices(), 3);
    }

    #[test]
    #[allow(deprecated)]
    fn test_legacy_adapter_returns_error() {
        let legacy = CcsInstance {
            mat_commitments: vec![[0; 32], [1; 32], [2; 32]],
            public_input_hash: [3; 32],
            witness_commitment: [4; 32],
            state_delta_hash: [5; 32],
            ack_step_hash: [6; 32],
        };
        let adapter = LegacyCcsInstanceAdapter::new(legacy);
        assert_eq!(adapter.name(), "legacy_hash_based_adapter");
        assert_eq!(adapter.num_matrices(), 3);
        let result = adapter.to_ccs_instance(&[], &[]);
        assert!(result.is_err());
    }
}
