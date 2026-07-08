//! ZKVM 错误类型（Phase 0 — SubTask 0.1.4）。
//!
//! 严格遵循 spec.md L15（v1.4 FROZEN）— 18 个错误变体覆盖所有 ZKVM 失败场景。
//! 所有错误均为不可恢复（`ZkvmError`），通过 `Result<T, ZkvmError>` 传播。

use std::fmt;

/// ZKVM 统一错误类型（18 variants，spec L15）。
///
/// 覆盖：
/// - 指令执行错误（`UnsupportedInstruction` / `UnalignedAccess` / `UninitializedRead`）
/// - 资源超限错误（`TraceTooLong` / `TraceHostMemoryExceeded` / `OutOfMemory` /
///   `FoldStepCountExceeded` / `RecursionDepthExceeded`）
/// - 证明验证错误（`InvalidZkProofFormat` / `SumcheckVerificationFailed` /
///   `CrossLanguageClaimFailed` / `TranscriptMismatch` / `PcsVerificationFailed` /
///   `FoldError` / `ProofKindMismatch`）
/// - ABI / 槽位错误（`AbiVersionMismatch` / `InvalidSlot`）
/// - 通用错误（`Other`）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkvmError {
    /// 不支持的指令（含非法 opcode 或禁用指令如浮点 / atomics / compressed）。
    UnsupportedInstruction(String),

    /// Trace 步数超限（`MAX_ZKVM_TRACE_STEPS = 1_048_576`）。
    TraceTooLong {
        /// 实际步数
        actual: usize,
        /// 上限
        limit: usize,
    },

    /// Trace host 内存超限（`MAX_TRACE_HOST_MEMORY = 512MB`）。
    TraceHostMemoryExceeded {
        /// 实际内存（字节）
        actual: usize,
        /// 上限（字节）
        limit: usize,
    },

    /// 内存不足（分配失败）。
    OutOfMemory,

    /// 未对齐访问（非 4-byte 对齐的内存读写）。
    UnalignedAccess {
        /// 触发地址
        addr: u32,
    },

    /// ZK proof 格式非法（长度 / 结构 / ABI 版本不符）。
    InvalidZkProofFormat(String),

    /// Sumcheck 验证失败（最终求和不等式不成立）。
    SumcheckVerificationFailed,

    /// Cross-language claim 失败（`Σ_j γ^j·v'[j] ≠ (Σ_j γ^j·M_j)·z'(r_y)`）。
    CrossLanguageClaimFailed,

    /// Transcript 不匹配（Fiat-Shamir challenge 重算不一致）。
    TranscriptMismatch,

    /// PCS 验证失败（IPA commitment 校验不通过）。
    PcsVerificationFailed,

    /// ABI 版本不匹配（`ZKVM_ABI_VERSION = 1`）。
    AbiVersionMismatch {
        /// 期望版本
        expected: u32,
        /// 实际版本
        actual: u32,
    },

    /// 无效槽位（`zkvm_read_state` 访问非白名单 slot）。
    InvalidSlot(u32),

    /// 递归深度超限（`MAX_RECURSION_DEPTH = 16`）。
    RecursionDepthExceeded {
        /// 实际深度
        actual: u32,
        /// 上限
        limit: u32,
    },

    /// 折叠步数超限（`MAX_FOLD_STEP_COUNT = 1000`）。
    FoldStepCountExceeded {
        /// 实际步数
        actual: u32,
        /// 上限
        limit: u32,
    },

    /// 折叠错误（LCCCS + CCCCS 折叠过程中数学不一致）。
    FoldError(String),

    /// proof_kind 与 scheme_id 不匹配（`ZkShuffle → 4` / `Zkvm → 1`）。
    ProofKindMismatch,

    /// 未初始化读取（访问未写入的内存地址）。
    UninitializedRead {
        /// 触发地址
        addr: u32,
    },

    /// 通用错误（未分类的内部错误）。
    Other(String),
}

impl fmt::Display for ZkvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedInstruction(desc) => {
                write!(f, "unsupported instruction: {desc}")
            }
            Self::TraceTooLong { actual, limit } => {
                write!(f, "trace too long: {actual} > {limit}")
            }
            Self::TraceHostMemoryExceeded { actual, limit } => {
                write!(
                    f,
                    "trace host memory exceeded: {actual} bytes > {limit} bytes"
                )
            }
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::UnalignedAccess { addr } => {
                write!(f, "unaligned access at 0x{addr:08x}")
            }
            Self::InvalidZkProofFormat(desc) => {
                write!(f, "invalid zk proof format: {desc}")
            }
            Self::SumcheckVerificationFailed => write!(f, "sumcheck verification failed"),
            Self::CrossLanguageClaimFailed => write!(f, "cross-language claim failed"),
            Self::TranscriptMismatch => write!(f, "transcript mismatch"),
            Self::PcsVerificationFailed => write!(f, "pcs verification failed"),
            Self::AbiVersionMismatch { expected, actual } => {
                write!(f, "abi version mismatch: expected {expected}, got {actual}")
            }
            Self::InvalidSlot(slot) => write!(f, "invalid slot: {slot}"),
            Self::RecursionDepthExceeded { actual, limit } => {
                write!(f, "recursion depth exceeded: {actual} > {limit}")
            }
            Self::FoldStepCountExceeded { actual, limit } => {
                write!(f, "fold step count exceeded: {actual} > {limit}")
            }
            Self::FoldError(desc) => write!(f, "fold error: {desc}"),
            Self::ProofKindMismatch => write!(f, "proof_kind mismatch"),
            Self::UninitializedRead { addr } => {
                write!(f, "uninitialized read at 0x{addr:08x}")
            }
            Self::Other(desc) => write!(f, "{desc}"),
        }
    }
}

impl std::error::Error for ZkvmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助：断言错误 variant 的 Display 输出非空且包含关键词。
    fn assert_display_contains(err: &ZkvmError, keyword: &str) {
        let s = err.to_string();
        assert!(!s.is_empty(), "Display 输出不应为空: {err:?}");
        assert!(
            s.contains(keyword),
            "Display 输出应包含 '{keyword}'，实际: '{s}'"
        );
    }

    #[test]
    fn test_unsupported_instruction_display() {
        let err = ZkvmError::UnsupportedInstruction("fence.i".to_string());
        assert_display_contains(&err, "unsupported instruction");
        assert_display_contains(&err, "fence.i");
    }

    #[test]
    fn test_trace_too_long_display() {
        let err = ZkvmError::TraceTooLong {
            actual: 2_000_000,
            limit: 1_048_576,
        };
        assert_display_contains(&err, "trace too long");
        assert_display_contains(&err, "2000000");
        assert_display_contains(&err, "1048576");
    }

    #[test]
    fn test_trace_host_memory_exceeded_display() {
        let err = ZkvmError::TraceHostMemoryExceeded {
            actual: 600_000_000,
            limit: 512_000_000,
        };
        assert_display_contains(&err, "trace host memory exceeded");
    }

    #[test]
    fn test_out_of_memory_display() {
        let err = ZkvmError::OutOfMemory;
        assert_display_contains(&err, "out of memory");
    }

    #[test]
    fn test_unaligned_access_display() {
        let err = ZkvmError::UnalignedAccess { addr: 0x1001 };
        assert_display_contains(&err, "unaligned access");
        assert_display_contains(&err, "0x00001001");
    }

    #[test]
    fn test_invalid_zk_proof_format_display() {
        let err = ZkvmError::InvalidZkProofFormat("proof too short".to_string());
        assert_display_contains(&err, "invalid zk proof format");
        assert_display_contains(&err, "proof too short");
    }

    #[test]
    fn test_sumcheck_verification_failed_display() {
        let err = ZkvmError::SumcheckVerificationFailed;
        assert_display_contains(&err, "sumcheck verification failed");
    }

    #[test]
    fn test_cross_language_claim_failed_display() {
        let err = ZkvmError::CrossLanguageClaimFailed;
        assert_display_contains(&err, "cross-language claim failed");
    }

    #[test]
    fn test_transcript_mismatch_display() {
        let err = ZkvmError::TranscriptMismatch;
        assert_display_contains(&err, "transcript mismatch");
    }

    #[test]
    fn test_pcs_verification_failed_display() {
        let err = ZkvmError::PcsVerificationFailed;
        assert_display_contains(&err, "pcs verification failed");
    }

    #[test]
    fn test_abi_version_mismatch_display() {
        let err = ZkvmError::AbiVersionMismatch {
            expected: 1,
            actual: 2,
        };
        assert_display_contains(&err, "abi version mismatch");
        assert_display_contains(&err, "expected 1");
        assert_display_contains(&err, "got 2");
    }

    #[test]
    fn test_invalid_slot_display() {
        let err = ZkvmError::InvalidSlot(42);
        assert_display_contains(&err, "invalid slot");
        assert_display_contains(&err, "42");
    }

    #[test]
    fn test_recursion_depth_exceeded_display() {
        let err = ZkvmError::RecursionDepthExceeded {
            actual: 17,
            limit: 16,
        };
        assert_display_contains(&err, "recursion depth exceeded");
    }

    #[test]
    fn test_fold_step_count_exceeded_display() {
        let err = ZkvmError::FoldStepCountExceeded {
            actual: 1001,
            limit: 1000,
        };
        assert_display_contains(&err, "fold step count exceeded");
    }

    #[test]
    fn test_fold_error_display() {
        let err = ZkvmError::FoldError("u' mismatch".to_string());
        assert_display_contains(&err, "fold error");
        assert_display_contains(&err, "u' mismatch");
    }

    #[test]
    fn test_proof_kind_mismatch_display() {
        let err = ZkvmError::ProofKindMismatch;
        assert_display_contains(&err, "proof_kind mismatch");
    }

    #[test]
    fn test_uninitialized_read_display() {
        let err = ZkvmError::UninitializedRead { addr: 0x2000 };
        assert_display_contains(&err, "uninitialized read");
        assert_display_contains(&err, "0x00002000");
    }

    #[test]
    fn test_other_display() {
        let err = ZkvmError::Other("internal bug".to_string());
        assert_display_contains(&err, "internal bug");
    }

    /// 确认所有 18 个 variant 都能构造并 Display（无 panic）。
    #[test]
    fn test_all_variants_constructible() {
        let _errs: Vec<ZkvmError> = vec![
            ZkvmError::UnsupportedInstruction("test".to_string()),
            ZkvmError::TraceTooLong {
                actual: 1,
                limit: 0,
            },
            ZkvmError::TraceHostMemoryExceeded {
                actual: 1,
                limit: 0,
            },
            ZkvmError::OutOfMemory,
            ZkvmError::UnalignedAccess { addr: 1 },
            ZkvmError::InvalidZkProofFormat("test".to_string()),
            ZkvmError::SumcheckVerificationFailed,
            ZkvmError::CrossLanguageClaimFailed,
            ZkvmError::TranscriptMismatch,
            ZkvmError::PcsVerificationFailed,
            ZkvmError::AbiVersionMismatch {
                expected: 1,
                actual: 2,
            },
            ZkvmError::InvalidSlot(1),
            ZkvmError::RecursionDepthExceeded {
                actual: 1,
                limit: 0,
            },
            ZkvmError::FoldStepCountExceeded {
                actual: 1,
                limit: 0,
            },
            ZkvmError::FoldError("test".to_string()),
            ZkvmError::ProofKindMismatch,
            ZkvmError::UninitializedRead { addr: 1 },
            ZkvmError::Other("test".to_string()),
        ];
        // 全部能 to_string()
        for err in &_errs {
            assert!(!err.to_string().is_empty());
        }
        // 确认正好 18 个
        assert_eq!(_errs.len(), 18, "应有 18 个 ZkvmError variants");
    }

    /// 确认 ZkvmError 实现 std::error::Error trait。
    #[test]
    fn test_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<ZkvmError>();
    }

    /// 确认 Clone + PartialEq + Eq 派生可用。
    #[test]
    fn test_clone_eq() {
        let err1 = ZkvmError::InvalidSlot(5);
        let err2 = err1.clone();
        assert_eq!(err1, err2);
        assert_ne!(err1, ZkvmError::InvalidSlot(6));
    }
}
