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

use crate::error::PokerL1Error;
use crate::Hash;

use super::hypernova::{FinalSumcheck, FoldedInstance, HypernovaProof, WitnessCommitment};
use super::zk_verifier::ZkPublicIo;
use super::MAX_FOLD_STEP_COUNT;

/// CCS 电路实例（SubTask 26.1）。
///
/// 每步链下执行生成一个 CCS 实例，包含：
/// - 约束矩阵（mats）
/// - 公共输入（public_inputs）
/// - 见证（witness）
/// - 状态增量（state_delta）
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
pub trait CcsCircuit: Send + Sync {
    /// 电路名称（用于日志 / 调试）。
    fn name(&self) -> &str;

    /// 约束矩阵数量。
    fn num_matrices(&self) -> usize;

    /// 生成 CCS 实例（SubTask 26.1）。
    ///
    /// 输入：见证 + 公共输入 + 状态增量。
    /// 输出：CCS 实例（含 commitments）。
    fn to_instance(
        &self,
        witness: &[u8],
        public_inputs: &[u8],
        state_delta: &[u8],
        ack_step_hash: Hash,
    ) -> Result<CcsInstance, PokerL1Error>;
}

/// Hypernova fold step 结果（SubTask 26.2）。
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
/// MVP 阶段：仅生成占位结构，不实际折叠。
/// Production 阶段须实现完整的 Hypernova 折叠算法。
pub fn fold_step(
    prev: Option<&FoldStepResult>,
    instance: &CcsInstance,
    chain_id: crate::ChainId,
    game_id: &crate::object_model::ObjectID,
) -> Result<FoldStepResult, PokerL1Error> {
    let _ = (chain_id, game_id);

    let fold_step_count = prev.map(|p| p.fold_step_count + 1).unwrap_or(1);

    // O15 上限校验
    if fold_step_count > MAX_FOLD_STEP_COUNT {
        return Err(PokerL1Error::FoldStepCountExceeded {
            actual: fold_step_count,
            limit: MAX_FOLD_STEP_COUNT,
        });
    }

    // MVP：直接使用 instance 的 commitments 作为 folded 结果
    let folded_instance = FoldedInstance {
        instance_commitment: instance.mat_commitments[0],
        fold_step_count,
    };
    let witness_commitment = WitnessCommitment {
        commitment: instance.witness_commitment,
    };
    let sumcheck = FinalSumcheck {
        evaluations: vec![instance.public_input_hash],
        final_sum: instance.state_delta_hash,
    };

    // 累计 state_delta_hash：简单哈希链接
    let cumulative_state_delta_hash = prev.map_or(instance.state_delta_hash, |p| {
        let mut hasher = blake2::Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        use blake2::digest::Update;
        hasher.update(&p.cumulative_state_delta_hash);
        hasher.update(&instance.state_delta_hash);
        let mut out = [0u8; 32];
        use blake2::digest::VariableOutput;
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    });

    // 累计 ack_chain_hash：简单哈希链接
    let cumulative_ack_chain_hash = prev.map_or(instance.ack_step_hash, |p| {
        let mut hasher = blake2::Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        use blake2::digest::Update;
        hasher.update(&p.cumulative_ack_chain_hash);
        hasher.update(&instance.ack_step_hash);
        let mut out = [0u8; 32];
        use blake2::digest::VariableOutput;
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    });

    Ok(FoldStepResult {
        folded_instance,
        witness_commitment,
        sumcheck,
        cumulative_state_delta_hash,
        cumulative_ack_chain_hash,
        fold_step_count,
    })
}

/// 多步折叠循环结果（SubTask 26.3）。
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
pub fn fold_loop(
    instances: &[CcsInstance],
    initial_commitment: Hash,
    final_commitment: Hash,
    ack_chain_hash: Hash,
    skip_count: u32,
    segment_continuity_proof: Vec<u8>,
) -> Result<FoldLoopResult, PokerL1Error> {
    if instances.is_empty() {
        return Err(PokerL1Error::Other(
            "fold_loop: instances 不能为空".to_string(),
        ));
    }
    if instances.len() as u32 > MAX_FOLD_STEP_COUNT {
        return Err(PokerL1Error::FoldStepCountExceeded {
            actual: instances.len() as u32,
            limit: MAX_FOLD_STEP_COUNT,
        });
    }

    let mut prev: Option<FoldStepResult> = None;
    for instance in instances {
        let step_result = fold_step(prev.as_ref(), instance, crate::DEFAULT_CHAIN_ID, &crate::object_model::ObjectID::new([0u8; 20], 0))?;
        prev = Some(step_result);
    }

    let final_step = prev.expect("fold_loop: 至少有一个 step result");

    let proof = HypernovaProof {
        folded_instance: final_step.folded_instance,
        witness_commitment: final_step.witness_commitment,
        final_sumcheck: final_step.sumcheck,
    };

    let public_io = ZkPublicIo {
        initial_commitment,
        final_commitment,
        state_delta_hash: final_step.cumulative_state_delta_hash,
        ack_chain_hash,
        skip_count,
        segment_continuity_proof,
        fold_step_count: final_step.fold_step_count,
    };

    Ok(FoldLoopResult {
        proof,
        public_io,
        fold_step_count: final_step.fold_step_count,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ccs_instance(step: u8) -> CcsInstance {
        CcsInstance {
            mat_commitments: vec![[step; 32]],
            public_input_hash: [step; 32],
            witness_commitment: [step; 32],
            state_delta_hash: [step; 32],
            ack_step_hash: [step; 32],
        }
    }

    #[test]
    fn test_fold_step_first() {
        let instance = make_ccs_instance(1);
        let result = fold_step(None, &instance, crate::DEFAULT_CHAIN_ID, &crate::object_model::ObjectID::new([0u8; 20], 0))
            .expect("首次 fold 应成功");
        assert_eq!(result.fold_step_count, 1);
        assert_eq!(result.cumulative_state_delta_hash, instance.state_delta_hash);
        assert_eq!(result.cumulative_ack_chain_hash, instance.ack_step_hash);
    }

    #[test]
    fn test_fold_step_cumulative() {
        let i1 = make_ccs_instance(1);
        let r1 = fold_step(None, &i1, crate::DEFAULT_CHAIN_ID, &crate::object_model::ObjectID::new([0u8; 20], 0)).unwrap();

        let i2 = make_ccs_instance(2);
        let r2 = fold_step(Some(&r1), &i2, crate::DEFAULT_CHAIN_ID, &crate::object_model::ObjectID::new([0u8; 20], 0)).unwrap();

        assert_eq!(r2.fold_step_count, 2);
        // cumulative 应不同于任一单独 hash
        assert_ne!(r2.cumulative_state_delta_hash, i1.state_delta_hash);
        assert_ne!(r2.cumulative_state_delta_hash, i2.state_delta_hash);
    }

    #[test]
    fn test_fold_step_exceeds_limit() {
        // 构造 prev.fold_step_count = MAX_FOLD_STEP_COUNT，下一步应失败
        let prev = FoldStepResult {
            folded_instance: FoldedInstance {
                instance_commitment: [0; 32],
                fold_step_count: MAX_FOLD_STEP_COUNT,
            },
            witness_commitment: WitnessCommitment {
                commitment: [0; 32],
            },
            sumcheck: FinalSumcheck {
                evaluations: vec![],
                final_sum: [0; 32],
            },
            cumulative_state_delta_hash: [0; 32],
            cumulative_ack_chain_hash: [0; 32],
            fold_step_count: MAX_FOLD_STEP_COUNT,
        };

        let instance = make_ccs_instance(1);
        let result = fold_step(Some(&prev), &instance, crate::DEFAULT_CHAIN_ID, &crate::object_model::ObjectID::new([0u8; 20], 0));
        assert!(matches!(result, Err(PokerL1Error::FoldStepCountExceeded { .. })));
    }

    #[test]
    fn test_fold_loop_empty_instances() {
        let result = fold_loop(&[], [0; 32], [0; 32], [0; 32], 0, Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_fold_loop_exceeds_limit() {
        let instances: Vec<CcsInstance> = (0..=MAX_FOLD_STEP_COUNT)
            .map(|i| make_ccs_instance(i as u8))
            .collect();
        let result = fold_loop(&instances, [0; 32], [0; 32], [0; 32], 0, Vec::new());
        assert!(matches!(result, Err(PokerL1Error::FoldStepCountExceeded { .. })));
    }

    #[test]
    fn test_fold_loop_two_steps() {
        let instances = vec![make_ccs_instance(1), make_ccs_instance(2)];
        let ack_chain_hash = [0xAB; 32];
        let result = fold_loop(
            &instances,
            [0x01; 32],
            [0x02; 32],
            ack_chain_hash,
            0,
            Vec::new(),
        )
        .expect("fold_loop 应成功");

        assert_eq!(result.fold_step_count, 2);
        assert_eq!(result.public_io.fold_step_count, 2);
        assert_eq!(result.public_io.initial_commitment, [0x01; 32]);
        assert_eq!(result.public_io.final_commitment, [0x02; 32]);
        assert_eq!(result.public_io.ack_chain_hash, ack_chain_hash);
        assert_eq!(result.public_io.skip_count, 0);
    }

    #[test]
    fn test_fold_loop_max_steps_boundary() {
        // MAX_FOLD_STEP_COUNT 步应通过（边界）
        let instances: Vec<CcsInstance> = (0..MAX_FOLD_STEP_COUNT)
            .map(|i| make_ccs_instance((i % 256) as u8))
            .collect();
        let result = fold_loop(
            &instances,
            [0x01; 32],
            [0x02; 32],
            [0xAB; 32],
            0,
            Vec::new(),
        )
        .expect("fold_loop 应成功");
        assert_eq!(result.fold_step_count, MAX_FOLD_STEP_COUNT);
    }

    #[test]
    #[allow(deprecated)]
    fn test_zk_shuffle_circuit_name() {
        let circuit = ZkShuffleCcsCircuit::new();
        assert_eq!(circuit.name(), "zk_shuffle");
        assert_eq!(circuit.num_matrices(), 3);
    }

    #[test]
    #[allow(deprecated)]
    fn test_zk_shuffle_to_instance() {
        let circuit = ZkShuffleCcsCircuit::new();
        let instance = circuit
            .to_instance(&[0x01, 0x02], &[0x03, 0x04], &[0x05, 0x06], [0x07; 32])
            .expect("to_instance 应成功");

        assert_eq!(instance.mat_commitments.len(), 3);
        // 不同 witness 应产生不同 commitments
        let instance2 = circuit
            .to_instance(&[0xFF, 0x02], &[0x03, 0x04], &[0x05, 0x06], [0x07; 32])
            .unwrap();
        assert_ne!(instance.witness_commitment, instance2.witness_commitment);
    }

    #[test]
    fn test_fold_loop_public_io_validation() {
        let instances = vec![make_ccs_instance(1)];
        let result = fold_loop(
            &instances,
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            0,
            Vec::new(),
        )
        .expect("fold_loop 应成功");

        // public_io 应通过校验
        result
            .public_io
            .validate(3, 1000)
            .expect("public_io 应通过校验");
    }
}
