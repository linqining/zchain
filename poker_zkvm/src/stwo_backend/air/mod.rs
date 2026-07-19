//! # Stwo AIR 组件 — 模块声明
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"Phase 2"：
//! - [`cpu`] — CPU 组件（RV32I 指令，对应 [`crate::constraints`] Group A-F）
//! - [`memory`] — 内存组件（LB/LH/LW/LBU/LHU/SB/SH/SW）
//! - [`control_flow`] — 控制流组件（JAL/JALR/BEQ/BNE/...）
//! - [`syscall`] — Syscall 组件（ECALL + host 函数）
//! - [`opcode_table`] — Opcode Table 组件（Phase 2.3.2 Group C：opcode range check via LogUp）
//!
//! ## 设计参考
//!
//! - [Stwo AIR Development Guide](https://zksecurity.github.io/stwo-book/air-development/)
//! - [Stwo Components](https://zksecurity.github.io/stwo-book/air-development/components/)
//! - Nexus zkVM 3.0 AIR arithmetization
//!
//! ## 当前状态（Phase 2.3.2）
//!
//! - `cpu`：CpuAirEval 实现 Group A（idx 连续性）+ Group B（PC 连续性）+ Group C（opcode LogUp claim）
//! - `opcode_table`：OpcodeTableEval 实现 Group C 的 table 侧（yield -count_j）
//! - `memory`/`control_flow`/`syscall`：骨架，留待 Phase 2.4+

pub mod control_flow;
pub mod cpu;
pub mod memory;
pub mod opcode_table;
pub mod syscall;

use crate::error::ZkvmError;

use super::field::M31;
use super::trace::StwoTraceTable;

/// Stwo AIR 组件 trait（统一接口，对应 Stwo `Component` + `ComponentProver`）。
///
/// Phase 1.2 将基于 `stwo::air::Component` 实现完整的 AIR 组件。
/// Phase 1.1 骨架阶段仅定义接口，所有方法返回 [`ZkvmError::Other`]。
pub trait StwoAirComponent: std::fmt::Debug + Send + Sync {
    /// 组件名称（如 "cpu", "memory", "control_flow", "syscall"）。
    fn name(&self) -> &'static str;

    /// 该组件的 trace 列数。
    fn num_columns(&self) -> usize;

    /// 该组件的 trace 行数（须为 2 的幂）。
    fn num_rows(&self) -> usize;

    /// 评估 transition 约束（行间约束）。
    ///
    /// # 当前状态
    /// Phase 1.2 将基于 Stwo `Component::evaluate_transition` 实现。
    fn evaluate_transition(&self, _trace: &StwoTraceTable) -> Result<Vec<M31>, ZkvmError> {
        Err(ZkvmError::Other(format!(
            "StwoAirComponent[{}]: evaluate_transition 尚未实现 — Phase 1.2",
            self.name()
        )))
    }

    /// 评估 boundary 约束（首行/末行）。
    ///
    /// # 当前状态
    /// Phase 1.2 将基于 Stwo `Component::evaluate_boundary` 实现。
    fn evaluate_boundary(&self, _trace: &StwoTraceTable) -> Result<Vec<M31>, ZkvmError> {
        Err(ZkvmError::Other(format!(
            "StwoAirComponent[{}]: evaluate_boundary 尚未实现 — Phase 1.2",
            self.name()
        )))
    }
}