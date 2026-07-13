//! 多项式承诺方案（PCS）抽象与实现（Phase 1.5 — Task 1.5.1 / 1.5.2）。
//!
//! 严格遵循 spec.md L36-43（v1.4 FROZEN）：
//! - `Pcs` trait — `commit` / `open` / `verify` 抽象
//! - `ipa` 子模块 — IPA over BN254（NUMS generators + challenge 绑定）
//!
//! # 安全特性
//!
//! - NUMS generators：`hash_to_curve(b"poker_zkvm_ipa_gen" || i)` 防 backdoor
//! - point 绑定：open 开始前 absorb `PCS_OPEN_TAG || commitment || point` 防 proof 复用
//! - challenge 绑定：每轮 challenge 从 transcript 派生，绑定 round_commitment

pub mod ipa;

use crate::error::ZkvmError;
use crate::field::{Bn254ScalarField, ZkvmField};
use crate::transcript::Transcript;

/// 多线性多项式（evaluations on boolean hypercube）。
///
/// `evals[i]` 是多项式在点 `binary(i)` 处的求值，
/// 其中 `binary(i)` 将 `i` 的二进制位映射为 `{0,1}^m` 的坐标。
///
/// `evals.len()` 必须是 2 的幂（`2^num_vars`）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultilinearPoly {
    /// 超立方体上的求值（长度 = 2^num_vars）。
    pub evals: Vec<Bn254ScalarField>,
    /// 变量个数（`evals.len() == 2^num_vars`）。
    pub num_vars: usize,
}

impl MultilinearPoly {
    /// 从求值向量构造多线性多项式。
    ///
    /// # 错误
    /// - `evals.len()` 不是 2 的幂
    pub fn from_evals(evals: Vec<Bn254ScalarField>) -> Result<Self, ZkvmError> {
        let n = evals.len();
        if n == 0 {
            return Err(ZkvmError::Other(
                "MultilinearPoly evals 不能为空".to_string(),
            ));
        }
        if !n.is_power_of_two() {
            return Err(ZkvmError::Other(format!(
                "MultilinearPoly evals.len()={n} 不是 2 的幂"
            )));
        }
        let num_vars = n.trailing_zeros() as usize;
        Ok(Self { evals, num_vars })
    }

    /// 从 u32 求值构造（便捷方法）。
    pub fn from_u32_evals(evals: &[u32]) -> Result<Self, ZkvmError> {
        let evals: Vec<Bn254ScalarField> = evals
            .iter()
            .map(|&v| Bn254ScalarField::from_u32_with_wrap(v))
            .collect();
        Self::from_evals(evals)
    }

    /// 求值向量长度（= 2^num_vars）。
    pub fn len(&self) -> usize {
        self.evals.len()
    }

    /// 是否为空（始终 false，构造时保证非空）。
    pub fn is_empty(&self) -> bool {
        self.evals.is_empty()
    }
}

/// PCS trait — 多项式承诺方案抽象（spec L36）。
///
/// 每个 PCS 实现（如 IPA）须实现此 trait。
pub trait Pcs: Send + Sync {
    /// 承诺类型（如 G1 仿射点）。
    type Commitment: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync;

    /// 证明类型。
    type Proof: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync;

    /// 求值类型。
    type Eval: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync;

    /// 承诺多项式。
    fn commit(&self, poly: &MultilinearPoly) -> Result<Self::Commitment, ZkvmError>;

    /// 打开多项式在指定点的求值，生成证明。
    fn open(
        &self,
        poly: &MultilinearPoly,
        point: &[Bn254ScalarField],
        transcript: &mut Transcript,
    ) -> Result<(Self::Proof, Self::Eval), ZkvmError>;

    /// 验证证明。
    fn verify(
        &self,
        commitment: &Self::Commitment,
        point: &[Bn254ScalarField],
        eval: &Self::Eval,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<bool, ZkvmError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multilinear_poly_from_evals() {
        let poly = MultilinearPoly::from_u32_evals(&[1, 2, 3, 4]).unwrap();
        assert_eq!(poly.num_vars, 2);
        assert_eq!(poly.len(), 4);
    }

    #[test]
    fn test_multilinear_poly_rejects_non_power_of_two() {
        assert!(MultilinearPoly::from_u32_evals(&[1, 2, 3]).is_err());
        assert!(MultilinearPoly::from_u32_evals(&[1, 2, 3, 4, 5]).is_err());
    }

    #[test]
    fn test_multilinear_poly_rejects_empty() {
        assert!(MultilinearPoly::from_u32_evals(&[]).is_err());
    }
}
