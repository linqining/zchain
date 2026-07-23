//! # RecursivePublicInputs — L2 proof 的公开输入
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md` §8.3。
//!
//! L2 proof 的 public inputs 必须包含 L1 proof 的所有公开承诺，否则 prover 可以伪造。
//! 这些 public inputs 通过 channel mix 到 L2 proof 的 Fiat-Shamir 中，确保 soundness。

use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::line::LinePoly;
use starknet_ff::FieldElement as FieldElement252;

/// L2 proof 的公开输入。
///
/// 包含 L1 proof 的所有公开承诺，作为 L2 verifier 的输入。
/// 任何字段被篡改都会导致 L2 proof 验证失败（因为 channel mix）。
#[derive(Debug, Clone)]
pub struct RecursivePublicInputs {
    /// L1 proof 的 Merkle roots（所有 trees 的 commitments）。
    ///
    /// 包括 preprocessed trace root（通常为空）、original trace root、
    /// interaction trace root、composition commitment root。
    pub l1_commitments: Vec<FieldElement252>,

    /// L1 proof 的 OODS（Out-Of-Domain Sampling）point。
    ///
    /// 由 L1 verifier 在 commit phase 通过 `CirclePoint::get_random_point(channel)` 抽取。
    pub oods_point: CirclePoint<SecureField>,

    /// L1 proof 的 composition polynomial 在 OODS point 处的 claimed evaluation。
    ///
    /// 来自 L1 proof 的 `sampled_values`，由 L1 prover 提供并经 L1 verifier 验证。
    pub composition_oods_eval: SecureField,

    /// L1 FRI first layer 的 Merkle root。
    pub fri_first_layer_commitment: FieldElement252,

    /// L1 FRI last layer polynomial。
    ///
    /// 作为 L1 FRI 的最终 layer，verifier 直接检查 `query_eval == last_layer_poly.eval_at_point(x)`。
    pub fri_last_layer_poly: LinePoly,

    /// L1 composition polynomial 的 max log degree bound。
    pub max_log_degree_bound: u32,

    /// L1 proof 的 PcsConfig（包含 FriConfig + log_blowup_factor 等）。
    pub config: PcsConfig,

    /// L1 proof 的 query positions（用于 Merkle Path 验证）。
    pub query_positions: Vec<usize>,

    /// L1 trace 的 log size（用于 Merkle Path 验证）。
    pub log_size: u32,

    /// L1 FRI 的 query point x 坐标（从 L1 transcript 提取，非硬编码）。
    ///
    /// v5.2 soundness fix：此前 `gen_fri_verifier_trace` 硬编码 `query_x = 1`，
    /// 允许恶意 prover 选择在 x=1 处通过但其他点失败的伪造多项式。
    /// 此字段存储从 L1 proof 的 Fiat-Shamir transcript 重新推导的真实 query point。
    pub fri_query_x: SecureField,

    /// L1 FRI last layer 在 `fri_query_x` 处的 claimed evaluation。
    ///
    /// 与 `fri_query_x` 一起作为 L2 公开输入，经 channel mix 绑定到 L2 proof。
    /// L2 FRI Verifier AIR 约束 `query_eval_in_trace == fri_query_eval`。
    pub fri_query_eval: SecureField,
}

impl RecursivePublicInputs {
    /// 创建新的 RecursivePublicInputs。
    #[must_use]
    pub const fn new(
        l1_commitments: Vec<FieldElement252>,
        oods_point: CirclePoint<SecureField>,
        composition_oods_eval: SecureField,
        fri_first_layer_commitment: FieldElement252,
        fri_last_layer_poly: LinePoly,
        max_log_degree_bound: u32,
        config: PcsConfig,
        query_positions: Vec<usize>,
        log_size: u32,
        fri_query_x: SecureField,
        fri_query_eval: SecureField,
    ) -> Self {
        Self {
            l1_commitments,
            oods_point,
            composition_oods_eval,
            fri_first_layer_commitment,
            fri_last_layer_poly,
            max_log_degree_bound,
            config,
            query_positions,
            log_size,
            fri_query_x,
            fri_query_eval,
        }
    }

    /// 获取 L1 FRI config。
    #[must_use]
    pub const fn fri_config(&self) -> FriConfig {
        self.config.fri_config
    }
}

impl Default for RecursivePublicInputs {
    fn default() -> Self {
        Self::new(
            Vec::new(),
            CirclePoint::zero(),
            SecureField::from(0u32),
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::from(0u32)]),
            0,
            PcsConfig::default(),
            Vec::new(),
            0,
            SecureField::from(0u32),
            SecureField::from(0u32),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_recursive_public_inputs_new() {
        let inputs = RecursivePublicInputs::new(
            Vec::new(),
            CirclePoint::zero(),
            SecureField::zero(),
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            10,
            PcsConfig::default(),
            Vec::new(),
            10,
            SecureField::zero(),
            SecureField::zero(),
        );
        assert_eq!(inputs.l1_commitments.len(), 0);
        assert_eq!(inputs.max_log_degree_bound, 10);
        assert_eq!(inputs.log_size, 10);
        assert_eq!(inputs.fri_query_x, SecureField::zero());
        assert_eq!(inputs.fri_query_eval, SecureField::zero());
        assert_eq!(
            inputs.fri_config().log_blowup_factor,
            PcsConfig::default().fri_config.log_blowup_factor
        );
    }
}