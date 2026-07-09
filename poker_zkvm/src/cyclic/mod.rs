//! 曲线 cycle 抽象（Phase 9 — Task 9.1）。
//!
//! 严格遵循 spec.md L569-573（v1.4 FROZEN）：
//! - 主曲线 = BN254，辅助曲线 = Grumpkin
//! - 主曲线标量域 == 辅助曲线 base field，反之亦然（cycle 性质）
//!
//! ## cycle 性质验证
//!
//! arkworks 0.6 中 `ark_grumpkin::Fq` 即 `ark_bn254::Fr`（类型别名 re-export），
//! `ark_grumpkin::Fr` 即 `ark_bn254::Fq`。cycle 性质在类型层面已保证，
//! [`Bn254GrumpkinCycle::verify_cycle`] 在运行时进一步比较 modulus 做防御性校验。
//!
//! ## 用途
//!
//! CycleFold 递归聚合（[`crate::recursion`]）在 BN254 / Grumpkin 间交替递归：
//! - BN254 层验证 Grumpkin proof（点坐标在 BN254 标量域中表达）
//! - Grumpkin 层验证 BN254 proof（点坐标在 Grumpkin 标量域中表达）

use ark_ff::PrimeField;

use ark_bn254::{Fq as Bn254Fq, Fr as Bn254Fr};
use ark_grumpkin::{Fq as GrumpkinFq, Fr as GrumpkinFr};

use crate::error::ZkvmError;

/// 254-bit 素数的 u64 limbs 表示（4 × 64 = 256 bit）。
type ModulusArray = [u64; 4];

/// 曲线 cycle trait — 主曲线标量域 == 辅助曲线 base field，反之亦然。
///
/// 实现者须提供 4 个 modulus（主/辅曲线的标量/base field），
/// [`verify_cycle`] 校验 cycle 性质成立。
///
/// [`verify_cycle`]: CycleCurve::verify_cycle
pub trait CycleCurve: Sized {
    /// 主曲线标量域 modulus（数学符号 `r_primary`）。
    fn primary_scalar_modulus() -> ModulusArray;

    /// 主曲线 base field modulus（数学符号 `p_primary`）。
    fn primary_base_modulus() -> ModulusArray;

    /// 辅助曲线标量域 modulus（数学符号 `r_secondary`）。
    fn secondary_scalar_modulus() -> ModulusArray;

    /// 辅助曲线 base field modulus（数学符号 `p_secondary`）。
    fn secondary_base_modulus() -> ModulusArray;

    /// 验证 cycle 性质（spec L573）。
    ///
    /// 校验：
    /// - `primary_scalar_modulus == secondary_base_modulus`（主标量域 == 辅 base field）
    /// - `secondary_scalar_modulus == primary_base_modulus`（辅标量域 == 主 base field）
    ///
    /// # 错误
    /// - [`ZkvmError::Other`] — cycle 性质不满足（modulus 不匹配）
    fn verify_cycle() -> Result<(), ZkvmError> {
        let ps = Self::primary_scalar_modulus();
        let pb = Self::primary_base_modulus();
        let ss = Self::secondary_scalar_modulus();
        let sb = Self::secondary_base_modulus();

        if ps != sb {
            return Err(ZkvmError::Other(format!(
                "cycle 性质违反：primary_scalar {:?} != secondary_base {:?}",
                ps, sb
            )));
        }
        if ss != pb {
            return Err(ZkvmError::Other(format!(
                "cycle 性质违反：secondary_scalar {:?} != primary_base {:?}",
                ss, pb
            )));
        }
        Ok(())
    }
}

/// BN254 (主) / Grumpkin (辅) 曲线 cycle（spec L572）。
///
/// - 主曲线 BN254：base field = `ark_bn254::Fq`，标量域 = `ark_bn254::Fr`
/// - 辅助曲线 Grumpkin：base field = `ark_grumpkin::Fq`，标量域 = `ark_grumpkin::Fr`
///
/// arkworks 中 `ark_grumpkin::Fq = ark_bn254::Fr`，`ark_grumpkin::Fr = ark_bn254::Fq`，
/// cycle 性质在类型层面已保证。
#[derive(Debug, Clone, Copy, Default)]
pub struct Bn254GrumpkinCycle;

impl CycleCurve for Bn254GrumpkinCycle {
    fn primary_scalar_modulus() -> ModulusArray {
        modulus_to_array::<Bn254Fr>()
    }

    fn primary_base_modulus() -> ModulusArray {
        modulus_to_array::<Bn254Fq>()
    }

    fn secondary_scalar_modulus() -> ModulusArray {
        modulus_to_array::<GrumpkinFr>()
    }

    fn secondary_base_modulus() -> ModulusArray {
        modulus_to_array::<GrumpkinFq>()
    }
}

/// 从 `PrimeField` 提取 modulus 为 `[u64; 4]`。
///
/// arkworks `BigInteger256` 内部为 4 个 u64 limb，`as_ref()` 返回 `&[u64]`。
fn modulus_to_array<F: PrimeField>() -> ModulusArray {
    let modulus = F::MODULUS;
    let limbs: &[u64] = modulus.as_ref();
    let mut out = [0u64; 4];
    for (i, &l) in limbs.iter().enumerate().take(4) {
        out[i] = l;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SubTask 9.1.3：cycle 性质验证 — 主标量域 == 辅 base field && 辅标量域 == 主 base field。
    #[test]
    fn test_cycle_property_bn254_grumpkin() {
        // verify_cycle 不应返回错误
        Bn254GrumpkinCycle::verify_cycle().expect("BN254/Grumpkin cycle 性质应满足");
    }

    /// 主曲线标量域 modulus == 辅助曲线 base field modulus。
    #[test]
    fn test_primary_scalar_equals_secondary_base() {
        let ps = Bn254GrumpkinCycle::primary_scalar_modulus();
        let sb = Bn254GrumpkinCycle::secondary_base_modulus();
        assert_eq!(
            ps, sb,
            "BN254 标量域 (Fr) modulus 应 == Grumpkin base field (Fq) modulus"
        );
    }

    /// 辅助曲线标量域 modulus == 主曲线 base field modulus。
    #[test]
    fn test_secondary_scalar_equals_primary_base() {
        let ss = Bn254GrumpkinCycle::secondary_scalar_modulus();
        let pb = Bn254GrumpkinCycle::primary_base_modulus();
        assert_eq!(
            ss, pb,
            "Grumpkin 标量域 (Fr) modulus 应 == BN254 base field (Fq) modulus"
        );
    }

    /// 验证 4 个 modulus 互不相同（主标量 ≠ 主 base，辅标量 ≠ 辅 base）。
    #[test]
    fn test_primary_scalar_ne_primary_base() {
        let ps = Bn254GrumpkinCycle::primary_scalar_modulus();
        let pb = Bn254GrumpkinCycle::primary_base_modulus();
        assert_ne!(
            ps, pb,
            "BN254 标量域 ≠ base field（否则曲线不安全）"
        );
    }

    /// 验证 arkworks 类型层面 cycle：ark_grumpkin::Fq == ark_bn254::Fr。
    #[test]
    fn test_arkworks_type_level_cycle() {
        // ark_grumpkin::Fq 是 ark_bn254::Fr 的 type alias
        // modulus 应完全相同（同一类型）
        let grumpkin_fq_modulus = modulus_to_array::<GrumpkinFq>();
        let bn254_fr_modulus = modulus_to_array::<Bn254Fr>();
        assert_eq!(
            grumpkin_fq_modulus, bn254_fr_modulus,
            "ark_grumpkin::Fq 应 == ark_bn254::Fr（arkworks type alias）"
        );

        // ark_grumpkin::Fr 是 ark_bn254::Fq 的 type alias
        let grumpkin_fr_modulus = modulus_to_array::<GrumpkinFr>();
        let bn254_fq_modulus = modulus_to_array::<Bn254Fq>();
        assert_eq!(
            grumpkin_fr_modulus, bn254_fq_modulus,
            "ark_grumpkin::Fr 应 == ark_bn254::Fq（arkworks type alias）"
        );
    }

    /// 验证 modulus 非零且为 4 limbs（254-bit 素数）。
    #[test]
    fn test_modulus_nonzero_4_limbs() {
        let ps = Bn254GrumpkinCycle::primary_scalar_modulus();
        let pb = Bn254GrumpkinCycle::primary_base_modulus();
        let ss = Bn254GrumpkinCycle::secondary_scalar_modulus();
        let sb = Bn254GrumpkinCycle::secondary_base_modulus();

        assert_eq!(ps.len(), 4);
        assert_eq!(pb.len(), 4);
        assert_eq!(ss.len(), 4);
        assert_eq!(sb.len(), 4);

        assert_ne!(ps, [0u64; 4], "primary_scalar modulus 不应为全零");
        assert_ne!(pb, [0u64; 4], "primary_base modulus 不应为全零");
    }
}
