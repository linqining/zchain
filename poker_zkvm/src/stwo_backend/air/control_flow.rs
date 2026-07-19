//! # Control Flow AIR 组件 — 跳转与分支
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"Phase 2.2"：
//! - JAL / JALR（跳转）
//! - BEQ / BNE / BLT / BGE / BLTU / BGEU（条件分支）
//! - PC 连续性约束（对应 [`crate::constraints`] Group B）
//!
//! ## 当前状态（Phase 1.1）
//!
//! 仅提供类型定义与 trait 实现。约束评估留待 Phase 2.2。

use crate::error::ZkvmError;

use super::super::trace::StwoTraceTable;
use super::StwoAirComponent;

/// Control Flow AIR 组件（跳转与分支）。
///
/// 复用 [`crate::constraints::compute_taken`] 计算 branch taken flag。
#[derive(Clone, Debug, Default)]
pub struct ControlFlowAirComponent {
    /// trace 行数（须为 2 的幂）。
    pub num_rows: usize,
}

impl ControlFlowAirComponent {
    /// 创建新 Control Flow AIR 组件。
    pub fn new(num_rows: usize) -> Self {
        Self { num_rows }
    }
}

impl StwoAirComponent for ControlFlowAirComponent {
    fn name(&self) -> &'static str {
        "control_flow"
    }

    fn num_columns(&self) -> usize {
        // 控制流组件列布局（Phase 2.2 定义）：
        // [pc, next_pc, taken, branch_cond, imm, ...]
        // 当前 Phase 1.1 骨架返回 0
        0
    }

    fn num_rows(&self) -> usize {
        self.num_rows
    }

    fn evaluate_transition(&self, _trace: &StwoTraceTable) -> Result<Vec<super::super::field::M31>, ZkvmError> {
        // TODO(Phase 2.2): 实现跳转与分支约束
        // 复用 compute_taken (constraints/mod.rs:231)
        Err(ZkvmError::Other(
            "ControlFlowAirComponent::evaluate_transition 尚未实现 — Phase 2.2".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_flow_air_component_construction() {
        let comp = ControlFlowAirComponent::new(1024);
        assert_eq!(comp.name(), "control_flow");
        assert_eq!(comp.num_rows(), 1024);
    }

    #[test]
    fn test_control_flow_air_component_default() {
        let comp = ControlFlowAirComponent::default();
        assert_eq!(comp.num_rows, 0);
    }

    #[test]
    fn test_control_flow_air_component_evaluate_returns_unimplemented() {
        let comp = ControlFlowAirComponent::new(1024);
        let trace = StwoTraceTable::new(0, comp.num_rows());
        assert!(comp.evaluate_transition(&trace).is_err());
    }
}
