//! # Memory AIR 组件 — 内存访问一致性
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"Phase 2.3"：
//! - LB / LH / LW / LBU / LHU（加载）
//! - SB / SH / SW（存储）
//! - Offline memory checker（LogUp lookup 协议验证内存一致性）
//!
//! ## 当前状态（Phase 1.1）
//!
//! 仅提供类型定义与 trait 实现。约束评估留待 Phase 2.3。

use crate::error::ZkvmError;

use super::super::trace::StwoTraceTable;
use super::StwoAirComponent;

/// Memory AIR 组件（内存访问一致性）。
///
/// 参考 Nexus zkVM 3.0 §3.2 "Offline memory checker"：
/// - 初始写入集合 + 最终读取集合
/// - LogUp lookup 协议验证 read/write 一致性
/// - 地址范围检查（M31 原生 31-bit，需多 limb 表示 32-bit 地址）
#[derive(Clone, Debug, Default)]
pub struct MemoryAirComponent {
    /// trace 行数（须为 2 的幂）。
    pub num_rows: usize,
}

impl MemoryAirComponent {
    /// 创建新 Memory AIR 组件。
    pub fn new(num_rows: usize) -> Self {
        Self { num_rows }
    }
}

impl StwoAirComponent for MemoryAirComponent {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn num_columns(&self) -> usize {
        // 内存组件列布局（Phase 2.3 定义）：
        // [addr_low, addr_high, value_low, value_high, is_load, is_store, op_size, ...]
        // 当前 Phase 1.1 骨架返回 0
        0
    }

    fn num_rows(&self) -> usize {
        self.num_rows
    }

    fn evaluate_transition(&self, _trace: &StwoTraceTable) -> Result<Vec<super::super::field::M31>, ZkvmError> {
        // TODO(Phase 2.3): 实现 offline memory checker
        Err(ZkvmError::Other(
            "MemoryAirComponent::evaluate_transition 尚未实现 — Phase 2.3".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_air_component_construction() {
        let comp = MemoryAirComponent::new(1024);
        assert_eq!(comp.name(), "memory");
        assert_eq!(comp.num_rows(), 1024);
    }

    #[test]
    fn test_memory_air_component_default() {
        let comp = MemoryAirComponent::default();
        assert_eq!(comp.num_rows, 0);
    }

    #[test]
    fn test_memory_air_component_evaluate_returns_unimplemented() {
        let comp = MemoryAirComponent::new(1024);
        let trace = StwoTraceTable::new(0, comp.num_rows());
        assert!(comp.evaluate_transition(&trace).is_err());
    }
}