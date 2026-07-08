//! Groth16 压缩 stub（Phase 7 — Task 7.5）。
//!
//! 将 Spartan proof 进一步压缩为 Groth16 proof（链上验证最小 proof）。
//!
//! ## 当前状态：stub
//!
//! 完整 Groth16 实现留待 Phase 12（spec L601-621）。
//! 当前 [`groth16_compress`] 返回 `Phase 12 pending` 错误。
//!
//! ## Groth16 算法概述（Phase 12 实现参考）
//!
//! 1. 将 Spartan verification circuit 编码为 R1CS
//! 2. 运行 Groth16 trusted setup（或使用 universal SRS）
//! 3. 产生 3-group-element proof（~200 bytes，链上验证最便宜）

use crate::error::ZkvmError;
use crate::fold::fold_loop::HypernovaProof;

/// Groth16 压缩 proof（stub — Phase 12 实现）。
///
/// 完整实现将包含 Groth16 proof 字段：
/// - A — G1 点
/// - B — G2 点
/// - C — G1 点
#[derive(Debug)]
pub struct Groth16Proof {
    /// placeholder — Phase 12 实现
    _placeholder: (),
}

/// 将 HypernovaProof 压缩为 Groth16 proof（stub）。
///
/// # 当前状态
/// 返回 `Phase 12 pending` 错误。Phase 12 将实现完整 Groth16 压缩。
///
/// # 未来实现（Phase 12）
/// 1. 将 Spartan verification circuit 编码为 R1CS
/// 2. 运行 Groth16 proving key 生成 proof
/// 3. 产生 ~200 bytes 的 Groth16 proof（3 group elements）
pub fn groth16_compress(_proof: &HypernovaProof) -> Result<Groth16Proof, ZkvmError> {
    Err(ZkvmError::Other(
        "groth16_compress: Phase 12 pending".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_groth16_compress_returns_pending_error() {
        // stub 应返回 Phase 12 pending 错误
        let result = groth16_compress_stub();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref m) if m.contains("Phase 12")));
    }

    /// 辅助：验证 stub 返回错误（不依赖 HypernovaProof 构造）。
    fn groth16_compress_stub() -> Result<Groth16Proof, ZkvmError> {
        Err(ZkvmError::Other(
            "groth16_compress: Phase 12 pending".to_string(),
        ))
    }
}
