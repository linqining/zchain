//! # Syscall AIR 组件 — ECALL 指令与 host 函数
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"Phase 2.4"：
//! - ECALL 指令约束
//! - syscall 编号分派
//! - host 函数调用接口（precompile 注入点）
//!
//! ## precompile 注入机制
//!
//! zk_shuffle 等椭圆曲线 precompile **不进入主 AIR**，由独立证明通道处理：
//! - 主 AIR 仅证明"syscall 被调用 + 输出被使用"
//! - precompile 自身通过 `PrecompileCircuit::build_ccs()` 独立证明
//! - 通过 LogUp 协议连接主 AIR 与 precompile 证明
//!
//! ## 当前状态（Phase 1.1）
//!
//! 仅提供类型定义与 trait 实现。约束评估留待 Phase 2.4。

use crate::error::ZkvmError;

use super::super::trace::StwoTraceTable;
use super::StwoAirComponent;

/// Syscall AIR 组件（ECALL 指令与 host 函数）。
#[derive(Clone, Debug, Default)]
pub struct SyscallAirComponent {
    /// trace 行数（须为 2 的幂）。
    pub num_rows: usize,
}

impl SyscallAirComponent {
    /// 创建新 Syscall AIR 组件。
    pub fn new(num_rows: usize) -> Self {
        Self { num_rows }
    }
}

impl StwoAirComponent for SyscallAirComponent {
    fn name(&self) -> &'static str {
        "syscall"
    }

    fn num_columns(&self) -> usize {
        // Syscall 组件列布局（Phase 2.4 定义）：
        // [syscall_id, arg0, arg1, ..., ret0, ret1, ..., ...]
        // 当前 Phase 1.1 骨架返回 0
        0
    }

    fn num_rows(&self) -> usize {
        self.num_rows
    }

    fn evaluate_transition(&self, _trace: &StwoTraceTable) -> Result<Vec<super::super::field::M31>, ZkvmError> {
        // TODO(Phase 2.4): 实现 ECALL 约束 + precompile 注入接口
        Err(ZkvmError::Other(
            "SyscallAirComponent::evaluate_transition 尚未实现 — Phase 2.4".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_air_component_construction() {
        let comp = SyscallAirComponent::new(1024);
        assert_eq!(comp.name(), "syscall");
        assert_eq!(comp.num_rows(), 1024);
    }

    #[test]
    fn test_syscall_air_component_default() {
        let comp = SyscallAirComponent::default();
        assert_eq!(comp.num_rows, 0);
    }

    #[test]
    fn test_syscall_air_component_evaluate_returns_unimplemented() {
        let comp = SyscallAirComponent::new(1024);
        let trace = StwoTraceTable::new(0, comp.num_rows());
        assert!(comp.evaluate_transition(&trace).is_err());
    }
}