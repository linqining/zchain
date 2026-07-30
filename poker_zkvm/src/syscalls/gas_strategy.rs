//! ZkvmGasStrategy — poker_zkvm 链下 ZK VM gas 策略（Phase 4）。
//!
//! **无 gas 费**：所有 [`instruction_gas`](GasStrategy::instruction_gas) 返回 0，
//! [`instruction_meter_enabled`](GasStrategy::instruction_meter_enabled) 返回 `false`。
//! 仅 step_limit（执行步数上限）约束执行。
//!
//! # 范围说明
//!
//! Phase 4 仅形式化，**不接入 zkvm executor**。现有 `instruction_gas()` / `syscall_gas()`
//! 在 `poker_zkvm/src/syscalls/gas.rs` 保持原状（被约束系统使用）。
//! 本实现作为跨 VM 一致性测试的 zkvm 侧样本。

use vm_common::gas_strategy::{GasStrategy, InsnCategory};
use vm_common::syscall_id::SyscallId;

/// poker_zkvm 链下 ZK VM gas 策略（全 0）。
///
/// zkvm 无 gas 费：所有指令与 syscall 均不计费，仅由 step_limit 约束执行步数。
///
/// # 示例
///
/// ```ignore
/// use poker_zkvm::syscalls::gas_strategy::ZkvmGasStrategy;
/// use vm_common::gas_strategy::{GasStrategy, InsnCategory};
///
/// let strategy = ZkvmGasStrategy::new();
/// assert_eq!(strategy.instruction_gas(InsnCategory::Arithmetic), 0);
/// assert_eq!(strategy.name(), "zkvm");
/// assert!(!strategy.instruction_meter_enabled());
/// ```
pub struct ZkvmGasStrategy;

impl ZkvmGasStrategy {
    /// 创建新策略。
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ZkvmGasStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl GasStrategy for ZkvmGasStrategy {
    fn instruction_gas(&self, _category: InsnCategory) -> u64 {
        0
    }

    fn syscall_gas(&self, _id: SyscallId, _args_len: u32) -> u64 {
        0
    }

    fn instruction_meter_enabled(&self) -> bool {
        false
    }

    fn default_tx_gas_limit(&self) -> u64 {
        0
    }

    fn default_block_gas_limit(&self) -> u64 {
        0
    }

    fn name(&self) -> &'static str {
        "zkvm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkvm_strategy_name() {
        assert_eq!(ZkvmGasStrategy::new().name(), "zkvm");
    }

    #[test]
    fn test_zkvm_no_gas() {
        let s = ZkvmGasStrategy::new();
        // 所有指令类别都应为 0
        assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), 0);
        assert_eq!(s.instruction_gas(InsnCategory::Mul), 0);
        assert_eq!(s.instruction_gas(InsnCategory::Div), 0);
        assert_eq!(s.instruction_gas(InsnCategory::Memory), 0);
        assert_eq!(s.instruction_gas(InsnCategory::ControlFlow), 0);
        assert_eq!(s.instruction_gas(InsnCategory::Shift), 0);
        assert_eq!(s.instruction_gas(InsnCategory::UpperImm), 0);
        assert_eq!(s.instruction_gas(InsnCategory::System), 0);
        assert_eq!(s.instruction_gas(InsnCategory::Other), 0);
    }

    #[test]
    fn test_zkvm_meter_disabled() {
        assert!(!ZkvmGasStrategy::new().instruction_meter_enabled());
    }

    #[test]
    fn test_zkvm_zero_limits() {
        let s = ZkvmGasStrategy::new();
        assert_eq!(s.default_tx_gas_limit(), 0);
        assert_eq!(s.default_block_gas_limit(), 0);
    }

    #[test]
    fn test_zkvm_syscall_gas_zero() {
        let s = ZkvmGasStrategy::new();
        // 所有 syscall 应返回 0
        assert_eq!(s.syscall_gas(SyscallId::Sha256, 100), 0);
        assert_eq!(s.syscall_gas(SyscallId::EcdsaVerify, 0), 0);
        assert_eq!(s.syscall_gas(SyscallId::ObjectRead, 100), 0);
    }

    #[test]
    fn test_zkvm_trait_object() {
        let s: Box<dyn GasStrategy> = Box::new(ZkvmGasStrategy::new());
        assert_eq!(s.name(), "zkvm");
        assert!(!s.instruction_meter_enabled());
    }
}
