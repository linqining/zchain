//! ZkvmHostState trait + StubHostState 默认实现（Phase 4 — Task 4.2.10）。
//!
//! spec.md L662-669：`zkvm_read_state` 的 host 实现从 host 侧读取对应 slot 的链上状态。
//! `PokerL1Context` 无 state slot 字段，因此定义 [`ZkvmHostState`] trait 抽象状态读取。
//!
//! # 设计说明
//!
//! - [`ZkvmHostState`] trait — 节点层可注入自定义实现（如读取 `PokerL1Context` 的状态槽）
//! - [`StubHostState`] — 默认 stub 实现，无状态源时返回 `Other` 错误
//! - Phase 5+ 电路侧校验 Merkle 证明（slot 值在 `state_slot_root` 下）

use crate::error::ZkvmError;

/// Host 状态读取 trait（`read_state` syscall 用，spec L662-669）。
///
/// 节点层在构造 `SyscallContext` 时注入实现：
/// - Stub 场景：使用 [`StubHostState`]（返回错误）
/// - 生产场景：实现此 trait 读取 `PokerL1Context` 的状态槽
///
/// # Merkle 绑定
///
/// Phase 4 仅实现 host 侧读取（slot 白名单 + 值返回）。
/// Merkle 证明验证是 Phase 5+ 电路侧职责：
/// - prover 须提供 Merkle 证明证明 slot 值在 `public_io.state_slot_root` 下
/// - 电路校验 Merkle 证明
/// - 跨 batch 一致性约束 `state_slot_root` 在所有 CCS 实例中相同
pub trait ZkvmHostState: std::fmt::Debug + Send + Sync {
    /// 读取指定 slot 的状态值。
    ///
    /// # 参数
    /// - `slot` — slot ID（已在调用方校验白名单）
    ///
    /// # Errors
    /// - `ZkvmError::Other` — stub 实现或状态不可用
    /// - `ZkvmError::OutOfMemory` — slot 值过大
    fn read_slot(&self, slot: u32) -> Result<Vec<u8>, ZkvmError>;
}

/// 默认 stub 实现（无状态源时返回 `Other` 错误）。
///
/// 用于测试和 Phase 4 开发阶段。
/// 生产环境应注入自定义 [`ZkvmHostState`] 实现。
#[derive(Debug, Clone, Default)]
pub struct StubHostState;

impl ZkvmHostState for StubHostState {
    fn read_slot(&self, slot: u32) -> Result<Vec<u8>, ZkvmError> {
        Err(ZkvmError::Other(format!(
            "read_state: stub host state, slot {slot} not available"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_host_state_returns_error() {
        let stub = StubHostState;
        let result = stub.read_slot(0x01);
        assert!(result.is_err(), "StubHostState 应返回错误");
        assert!(
            matches!(result, Err(ZkvmError::Other(_))),
            "应返回 Other 错误"
        );
    }

    #[test]
    fn test_stub_host_state_default() {
        let stub = StubHostState;
        let result = stub.read_slot(0x05);
        assert!(result.is_err());
    }

    #[test]
    fn test_stub_host_state_clone() {
        let stub1 = StubHostState;
        let stub2 = stub1.clone();
        // 两者行为一致
        assert!(stub1.read_slot(0x01).is_err());
        assert!(stub2.read_slot(0x01).is_err());
    }

    #[test]
    fn test_stub_host_state_debug() {
        let stub = StubHostState;
        let debug_str = format!("{stub:?}");
        assert!(debug_str.contains("StubHostState"));
    }

    #[test]
    fn test_zkvm_host_state_trait_object() {
        // 验证 trait object 可用（Box<dyn ZkvmHostState>）
        let state: Box<dyn ZkvmHostState> = Box::new(StubHostState);
        let result = state.read_slot(0x01);
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_host_state_implementation() {
        /// 自定义测试实现 — 返回固定值。
        #[derive(Debug)]
        struct TestHostState {
            value: Vec<u8>,
        }

        impl ZkvmHostState for TestHostState {
            fn read_slot(&self, _slot: u32) -> Result<Vec<u8>, ZkvmError> {
                Ok(self.value.clone())
            }
        }

        let state = TestHostState {
            value: vec![0xAB, 0xCD],
        };
        let result = state.read_slot(0x01).unwrap();
        assert_eq!(result, vec![0xAB, 0xCD]);
    }
}
