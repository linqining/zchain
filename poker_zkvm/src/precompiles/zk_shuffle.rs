//! ZkShuffle CCS 电路迁移（Phase 10 — Task 10.5）。
//!
//! 从 `poker_l1/src/offline/ccs.rs` 迁移 `ZkShuffleCcsCircuit` 类型定义到 poker_zkvm。
//! 新签名基于 `Fr` + `CcsInstance`（非旧 hash-based）。
//!
//! # MVP 策略（D6，已批准）
//!
//! 本步骤仅迁移类型定义与 trait 实现，**保持 stub 行为**：
//! - `to_ccs_instance` 返回 `Err(Other("Phase 11 pending"))`
//! - 真实 ZkShuffle 电路实现（基于 `poker_protocol::zk_shuffle`）留待 Phase 11
//!
//! # Phase 11 迁移说明
//!
//! Phase 11 将完成完整迁移：
//! - `poker_l1/src/offline/ccs.rs` 旧 `CcsCircuit` trait + `ZkShuffleCcsCircuit` 标记 `#[deprecated]`
//! - poker_l1 通过 `pub use poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit;` re-export
//! - 旧调用方迁移到新类型，断言改为真实折叠语义

use crate::ccs::{Ccs, CcsInstance, Fr};
use crate::error::ZkvmError;
use crate::precompiles::{CcsCircuit, PrecompileCircuit};

/// ZkShuffle CCS 电路（迁移自 poker_l1，Fr-based 新签名）。
///
/// MVP 阶段为 stub — `to_ccs_instance` 返回 `Err(Other("Phase 11 pending"))`。
/// 真实 ZkShuffle 电路（基于 `poker_protocol::zk_shuffle`）留待 Phase 11 实现。
#[derive(Debug, Clone)]
pub struct ZkShuffleCcsCircuit {
    /// 电路名称。
    name: &'static str,
    /// 约束矩阵数量（CCS 标准要求 q=2 → 3 个矩阵 A/B/C）。
    num_mats: usize,
}

impl ZkShuffleCcsCircuit {
    /// 创建 ZkShuffle CCS 电路（stub）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "zk_shuffle",
            num_mats: 3,
        }
    }

    /// 返回约束矩阵数量。
    #[must_use]
    pub fn num_matrices(&self) -> usize {
        self.num_mats
    }
}

impl Default for ZkShuffleCcsCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl PrecompileCircuit for ZkShuffleCcsCircuit {
    fn name(&self) -> &str {
        self.name
    }

    fn num_variables(&self) -> usize {
        // ZkShuffle witness 变量数 — Phase 11 根据 poker_protocol::zk_shuffle 实际电路确定
        // MVP stub 返回 0（to_ccs_instance 会返回 Err）
        0
    }

    fn build_ccs(&self) -> Ccs {
        // MVP stub：返回空 CCS（0 矩阵 / 0 subset / 0 行）
        // 真实电路结构留待 Phase 11
        Ccs::new(0, Vec::new(), Vec::new(), Vec::new())
            .expect("ZkShuffleCcsCircuit stub CCS 构造应成功")
    }

    fn assign_witness(&self, _inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        // MVP stub：返回错误，真实 witness 赋值留待 Phase 11
        Err(ZkvmError::Other(
            "ZkShuffleCcsCircuit::assign_witness: Phase 11 pending（真实电路未实现）".to_string(),
        ))
    }

    fn gas_cost(&self) -> u64 {
        // ZkShuffle gas — Phase 11 根据实际电路规模确定
        // MVP stub 返回 0（不实际执行）
        0
    }
}

impl CcsCircuit for ZkShuffleCcsCircuit {
    fn name(&self) -> &str {
        self.name
    }

    fn num_matrices(&self) -> usize {
        self.num_mats
    }

    fn to_ccs_instance(
        &self,
        _witness: &[Fr],
        _public_inputs: &[Fr],
    ) -> Result<CcsInstance, ZkvmError> {
        // MVP stub：返回错误，真实 CCS 实例生成留待 Phase 11
        Err(ZkvmError::Other(
            "ZkShuffleCcsCircuit::to_ccs_instance: Phase 11 pending（真实电路未实现）".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::ZkvmField;
    use crate::precompiles::PrecompileRegistry;

    #[test]
    fn test_zk_shuffle_circuit_name_and_num_matrices() {
        let circuit = ZkShuffleCcsCircuit::new();
        // name() 在 PrecompileCircuit 和 CcsCircuit 都有定义，需通过 trait 引用消歧
        let pre: &dyn PrecompileCircuit = &circuit;
        assert_eq!(pre.name(), "zk_shuffle");
        let ccs: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs.num_matrices(), 3);
        assert_eq!(pre.gas_cost(), 0);
    }

    #[test]
    fn test_zk_shuffle_circuit_assign_witness_stub_returns_error() {
        let circuit = ZkShuffleCcsCircuit::new();
        let result = circuit.assign_witness(&[Fr::one()]);
        assert!(result.is_err(), "MVP stub 应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg.contains("Phase 11 pending")),
            "错误信息应包含 'Phase 11 pending'，实际: {err:?}"
        );
    }

    #[test]
    fn test_zk_shuffle_circuit_to_ccs_instance_stub_returns_error() {
        let circuit = ZkShuffleCcsCircuit::new();
        let witness = vec![Fr::one()];
        let public_inputs = vec![Fr::one()];
        let result = circuit.to_ccs_instance(&witness, &public_inputs);
        assert!(result.is_err(), "MVP stub 应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg.contains("Phase 11 pending")),
            "错误信息应包含 'Phase 11 pending'，实际: {err:?}"
        );
    }

    #[test]
    fn test_zk_shuffle_circuit_registry_integration() {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(ZkShuffleCcsCircuit::new()));
        assert_eq!(registry.len(), 1);
        let circuit = registry.get("zk_shuffle").expect("应找到 zk_shuffle");
        assert_eq!(circuit.name(), "zk_shuffle");
        assert_eq!(circuit.gas_cost(), 0);
        // assign_witness 应返回 Err
        assert!(circuit.assign_witness(&[Fr::one()]).is_err());
    }

    #[test]
    fn test_zk_shuffle_circuit_default() {
        let circuit = ZkShuffleCcsCircuit::default();
        let pre: &dyn PrecompileCircuit = &circuit;
        assert_eq!(pre.name(), "zk_shuffle");
        let ccs: &dyn CcsCircuit = &circuit;
        assert_eq!(ccs.num_matrices(), 3);
    }
}
