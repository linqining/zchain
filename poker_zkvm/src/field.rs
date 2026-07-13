//! ZKVM 域元素抽象（Phase 1 — Task 1.1）。
//!
//! 严格遵循 spec.md L21-23（v1.4 FROZEN）：
//! - `ZkvmField` trait — 统一域元素接口
//! - `Bn254ScalarField` — 基于 `ark_bn254::Fr` 的 newtype
//! - `from_u32_with_wrap(v)` — mod p 包装（u32 < p，无实际 wrap）
//! - `to_u32()` — `rem_euclid(2^32)` 抽取低 32 位，防负 bigint 截断
//! - canonical 编码：32 bytes LE（transcript 使用）

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, One, PrimeField, Zero};

use crate::error::ZkvmError;

/// ZKVM 域元素 trait（spec L21）。
///
/// 抽象 BN254 标量域上的算术运算，供 transcript / PCS / sumcheck / fold 使用。
///
/// # u32 语义说明
///
/// - `from_u32_with_wrap(v)` — 将 u32 值转为域元素（u32 < p，无 wrap）
/// - `to_u32()` — 取域元素低 32 位（`rem_euclid(2^32)`），用于 VM 寄存器值映射
///
/// VM 中 u32 加法溢出时，域元素中 `a + b` 不溢出（因 p > 2^254），
/// 而是得到 `wrapped_result + overflow_bit * 2^32`。
/// overflow_bit 约束在 Phase 5 CCS 中实现。
pub trait ZkvmField:
    Clone + Copy + PartialEq + Eq + std::fmt::Debug + Send + Sync + std::fmt::Display
{
    /// 从 u32 构造域元素（mod p 包装，u32 < p 无实际 wrap）。
    fn from_u32_with_wrap(v: u32) -> Self;

    /// 从 u64 构造域元素（mod p 包装）。
    fn from_u64(v: u64) -> Self;

    /// 取低 32 位（`rem_euclid(2^32)`），防负 bigint 截断。
    fn to_u32(&self) -> u32;

    /// 域元素加法。
    fn add(&self, other: &Self) -> Self;

    /// 域元素减法。
    fn sub(&self, other: &Self) -> Self;

    /// 域元素乘法。
    fn mul(&self, other: &Self) -> Self;

    /// 域元素取负。
    fn neg(&self) -> Self;

    /// 乘法逆元（零返回 None）。
    fn inverse(&self) -> Option<Self>;

    /// 加法单位元。
    fn zero() -> Self;

    /// 乘法单位元。
    fn one() -> Self;

    /// 判零。
    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }

    /// 序列化为 32 bytes LE（canonical 编码，transcript 使用）。
    fn to_canonical_bytes(&self) -> [u8; 32];

    /// 从 32 bytes LE 反序列化。
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ZkvmError>;

    /// 平方（默认实现用 mul，可优化覆盖）。
    fn square(&self) -> Self {
        self.mul(self)
    }

    /// 倍数（默认实现用 add，可优化覆盖）。
    fn double(&self) -> Self {
        self.add(self)
    }
}

/// BN254 标量域元素（`ark_bn254::Fr` 的 newtype）。
///
/// BN254 的 Fr 模数 p ≈ 2^254，远大于 2^32，
/// 因此 u32 值可直接表示为域元素无需 wrap。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Bn254ScalarField(Fr);

impl Bn254ScalarField {
    /// 从 `ark_bn254::Fr` 构造（内部使用）。
    pub const fn from_fr(fr: Fr) -> Self {
        Self(fr)
    }

    /// 转回 `ark_bn254::Fr`（内部使用）。
    pub const fn as_fr(&self) -> &Fr {
        &self.0
    }

    /// 消费为 `ark_bn254::Fr`。
    pub fn into_fr(self) -> Fr {
        self.0
    }
}

impl std::fmt::Debug for Bn254ScalarField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bn254ScalarField({:?})", self.0)
    }
}

impl std::fmt::Display for Bn254ScalarField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_canonical_bytes();
        // 显示前 8 bytes 的 hex（足够区分）
        write!(f, "0x")?;
        for b in bytes.iter().take(8) {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")
    }
}

impl ZkvmField for Bn254ScalarField {
    fn from_u32_with_wrap(v: u32) -> Self {
        Self(Fr::from(v))
    }

    fn from_u64(v: u64) -> Self {
        Self(Fr::from(v))
    }

    fn to_u32(&self) -> u32 {
        // 取低 32 位（LE 的前 4 bytes）
        let bytes = self.to_canonical_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    fn sub(&self, other: &Self) -> Self {
        Self(self.0 - other.0)
    }

    fn mul(&self, other: &Self) -> Self {
        Self(self.0 * other.0)
    }

    fn neg(&self) -> Self {
        Self(-self.0)
    }

    fn inverse(&self) -> Option<Self> {
        if self.0.is_zero() {
            None
        } else {
            Some(Self(self.0.inverse().unwrap()))
        }
    }

    fn zero() -> Self {
        Self(Fr::zero())
    }

    fn one() -> Self {
        Self(Fr::one())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn to_canonical_bytes(&self) -> [u8; 32] {
        // arkworks Fr 的 LE 字节表示
        let bigint = self.0.into_bigint();
        let vec = bigint.to_bytes_le();
        // BigInteger256::to_bytes_le 返回 [u8; 32]
        let mut arr = [0u8; 32];
        let len = vec.len().min(32);
        arr[..len].copy_from_slice(&vec[..len]);
        arr
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ZkvmError> {
        if bytes.len() != 32 {
            return Err(ZkvmError::InvalidZkProofFormat(format!(
                "canonical bytes 长度应为 32，实际 {}",
                bytes.len()
            )));
        }
        // 从 LE bytes 解析
        let fr = Fr::from_le_bytes_mod_order(bytes);
        Ok(Self(fr))
    }

    fn square(&self) -> Self {
        Self(self.0.square())
    }

    fn double(&self) -> Self {
        Self(self.0.double())
    }
}

impl From<u32> for Bn254ScalarField {
    fn from(v: u32) -> Self {
        Self::from_u32_with_wrap(v)
    }
}

impl From<u64> for Bn254ScalarField {
    fn from(v: u64) -> Self {
        Self::from_u64(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 基础算术测试 =====

    #[test]
    fn test_zero_one() {
        let z = Bn254ScalarField::zero();
        let o = Bn254ScalarField::one();
        assert!(z.is_zero());
        assert!(!o.is_zero());
        assert_ne!(z, o);
        // 0 + 1 = 1
        assert_eq!(z.add(&o), o);
        // 0 * 1 = 0
        assert_eq!(z.mul(&o), z);
        // 1 * 1 = 1
        assert_eq!(o.mul(&o), o);
    }

    #[test]
    fn test_add_mod_p() {
        let a = Bn254ScalarField::from_u32_with_wrap(5);
        let b = Bn254ScalarField::from_u32_with_wrap(3);
        let c = a.add(&b);
        assert_eq!(c.to_u32(), 8);
        // 交换律
        assert_eq!(a.add(&b), b.add(&a));
    }

    #[test]
    fn test_mul_mod_p() {
        let a = Bn254ScalarField::from_u32_with_wrap(6);
        let b = Bn254ScalarField::from_u32_with_wrap(7);
        let c = a.mul(&b);
        assert_eq!(c.to_u32(), 42);
        // 交换律
        assert_eq!(a.mul(&b), b.mul(&a));
    }

    #[test]
    fn test_sub() {
        let a = Bn254ScalarField::from_u32_with_wrap(10);
        let b = Bn254ScalarField::from_u32_with_wrap(3);
        assert_eq!(a.sub(&b).to_u32(), 7);
        // a - a = 0
        assert!(a.sub(&a).is_zero());
    }

    #[test]
    fn test_neg() {
        let a = Bn254ScalarField::from_u32_with_wrap(5);
        let neg_a = a.neg();
        // a + (-a) = 0
        assert!(a.add(&neg_a).is_zero());
    }

    #[test]
    fn test_inverse() {
        let a = Bn254ScalarField::from_u32_with_wrap(7);
        let inv = a.inverse().expect("7 有逆元");
        // a * a^-1 = 1
        assert_eq!(a.mul(&inv), Bn254ScalarField::one());

        // 0 无逆元
        assert!(Bn254ScalarField::zero().inverse().is_none());
    }

    #[test]
    fn test_square_and_double() {
        let a = Bn254ScalarField::from_u32_with_wrap(3);
        // 3^2 = 9
        assert_eq!(a.square().to_u32(), 9);
        // 3 + 3 = 6
        assert_eq!(a.double().to_u32(), 6);
    }

    // ===== u32 ↔ 域元素转换测试 =====

    #[test]
    fn test_from_u32_with_wrap() {
        let v = 42u32;
        let f = Bn254ScalarField::from_u32_with_wrap(v);
        assert_eq!(f.to_u32(), v);

        // 最大 u32
        let max = u32::MAX;
        let f_max = Bn254ScalarField::from_u32_with_wrap(max);
        assert_eq!(f_max.to_u32(), max);
    }

    #[test]
    fn test_to_u32_rem_euclid() {
        // 域元素值 < 2^32 时，to_u32 直接返回低 32 位
        let f = Bn254ScalarField::from_u32_with_wrap(0xDEADBEEF);
        assert_eq!(f.to_u32(), 0xDEADBEEF);

        // 域元素值 >= 2^32 时，to_u32 取低 32 位
        // 构造一个大值：2^32 + 5
        let two_pow_32 = Bn254ScalarField::from_u64(1u64 << 32);
        let five = Bn254ScalarField::from_u32_with_wrap(5);
        let big = two_pow_32.add(&five);
        // 低 32 位 = 5
        assert_eq!(big.to_u32(), 5);
    }

    #[test]
    fn test_from_u64() {
        let v = 0x1_0000_0005u64; // 2^32 + 5
        let f = Bn254ScalarField::from_u64(v);
        // 低 32 位 = 5
        assert_eq!(f.to_u32(), 5);
    }

    /// u32 加法溢出场景 + overflow_bit 约束验证（spec L23-24）。
    ///
    /// VM 中 `0xFFFFFFFF + 1` 在 u32 下 wrap 到 0，overflow_bit = 1。
    /// 域元素中 `from_u32(0xFFFFFFFF) + from_u32(1) = 2^32`（不 wrap）。
    /// 关系：`field_add - from_u32(wrapped_result) = overflow_bit * 2^32`
    #[test]
    fn test_u32_overflow_bit_constraint() {
        let a = Bn254ScalarField::from_u32_with_wrap(0xFFFFFFFF);
        let b = Bn254ScalarField::from_u32_with_wrap(1);

        // 域元素加法（不 wrap）
        let field_sum = a.add(&b);

        // u32 wrapping 加法
        let wrapped = 0xFFFFFFFFu32.wrapping_add(1); // = 0
        let field_wrapped = Bn254ScalarField::from_u32_with_wrap(wrapped);

        // overflow_bit = 1, 2^32 = from_u64(1 << 32)
        let two_pow_32 = Bn254ScalarField::from_u64(1u64 << 32);
        let overflow_bit = Bn254ScalarField::one();

        // 验证：field_sum = field_wrapped + overflow_bit * 2^32
        let expected = field_wrapped.add(&two_pow_32.mul(&overflow_bit));
        assert_eq!(
            field_sum, expected,
            "overflow_bit 约束：field(a+b) = field(wrapped) + overflow_bit * 2^32"
        );

        // field_sum 的 to_u32 应该等于 wrapped 结果（低 32 位）
        assert_eq!(field_sum.to_u32(), wrapped); // = 0
    }

    /// 无溢出场景：overflow_bit = 0
    #[test]
    fn test_u32_no_overflow() {
        let a = Bn254ScalarField::from_u32_with_wrap(100);
        let b = Bn254ScalarField::from_u32_with_wrap(200);
        let field_sum = a.add(&b);

        let wrapped = 100u32.wrapping_add(200); // = 300, 无溢出
        let field_wrapped = Bn254ScalarField::from_u32_with_wrap(wrapped);

        // overflow_bit = 0
        assert_eq!(field_sum, field_wrapped);
        assert_eq!(field_sum.to_u32(), 300);
    }

    // ===== canonical bytes 测试 =====

    #[test]
    fn test_canonical_bytes_roundtrip() {
        let vals: Vec<u32> = vec![0, 1, 42, 255, 0xDEADBEEF, u32::MAX];
        for v in vals {
            let f = Bn254ScalarField::from_u32_with_wrap(v);
            let bytes = f.to_canonical_bytes();
            assert_eq!(bytes.len(), 32, "canonical bytes 应为 32 字节");
            let f2 = Bn254ScalarField::from_canonical_bytes(&bytes).expect("roundtrip 应成功");
            assert_eq!(f, f2, "u32={v} 的 roundtrip 不一致");
        }
    }

    #[test]
    fn test_canonical_bytes_le_encoding() {
        // u32 值 1 的 LE 编码：bytes[0]=1, 其余=0
        let one = Bn254ScalarField::one();
        let bytes = one.to_canonical_bytes();
        assert_eq!(bytes[0], 1, "LE 编码下 byte[0] 应为最低位");
        for &b in bytes.iter().skip(1) {
            assert_eq!(b, 0, "LE 编码下高位字节应为 0");
        }
    }

    #[test]
    fn test_canonical_bytes_wrong_length() {
        let short = [0u8; 16];
        let result = Bn254ScalarField::from_canonical_bytes(&short);
        assert!(result.is_err(), "16 字节应返回错误");

        let long = [0u8; 64];
        let result = Bn254ScalarField::from_canonical_bytes(&long);
        assert!(result.is_err(), "64 字节应返回错误");
    }

    #[test]
    fn test_canonical_bytes_zero() {
        let zero = Bn254ScalarField::zero();
        let bytes = zero.to_canonical_bytes();
        // 零的 LE 编码：全 0
        for b in &bytes {
            assert_eq!(*b, 0);
        }
    }

    // ===== Display 测试 =====

    #[test]
    fn test_display() {
        let f = Bn254ScalarField::from_u32_with_wrap(1);
        let s = format!("{f}");
        assert!(s.starts_with("0x"), "Display 应以 0x 开头");
        assert!(s.contains("01"), "u32=1 的 Display 应包含 01");
    }

    // ===== From 转换测试 =====

    #[test]
    fn test_from_u32_trait() {
        let f: Bn254ScalarField = 42u32.into();
        assert_eq!(f.to_u32(), 42);
    }

    #[test]
    fn test_from_u64_trait() {
        let f: Bn254ScalarField = (1u64 << 32).into();
        assert_eq!(f.to_u32(), 0, "2^32 的低 32 位 = 0");
    }

    // ===== proptest 属性测试 =====

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// u32 → field → u32 roundtrip 保持一致
            #[test]
            fn prop_u32_roundtrip(v: u32) {
                let f = Bn254ScalarField::from_u32_with_wrap(v);
                prop_assert_eq!(f.to_u32(), v);
            }

            /// canonical bytes roundtrip
            #[test]
            fn prop_canonical_roundtrip(v: u32) {
                let f = Bn254ScalarField::from_u32_with_wrap(v);
                let bytes = f.to_canonical_bytes();
                let f2 = Bn254ScalarField::from_canonical_bytes(&bytes)
                    .expect("roundtrip 不应失败");
                prop_assert_eq!(f, f2);
            }

            /// 加法交换律：a + b = b + a
            #[test]
            fn prop_add_commutative(a: u32, b: u32) {
                let fa = Bn254ScalarField::from_u32_with_wrap(a);
                let fb = Bn254ScalarField::from_u32_with_wrap(b);
                prop_assert_eq!(fa.add(&fb), fb.add(&fa));
            }

            /// 乘法交换律：a * b = b * a
            #[test]
            fn prop_mul_commutative(a: u32, b: u32) {
                let fa = Bn254ScalarField::from_u32_with_wrap(a);
                let fb = Bn254ScalarField::from_u32_with_wrap(b);
                prop_assert_eq!(fa.mul(&fb), fb.mul(&fa));
            }

            /// 加法结合律：(a + b) + c = a + (b + c)
            #[test]
            fn prop_add_associative(a: u32, b: u32, c: u32) {
                let fa = Bn254ScalarField::from_u32_with_wrap(a);
                let fb = Bn254ScalarField::from_u32_with_wrap(b);
                let fc = Bn254ScalarField::from_u32_with_wrap(c);
                let left = fa.add(&fb).add(&fc);
                let right = fa.add(&fb.add(&fc));
                prop_assert_eq!(left, right);
            }

            /// 乘法分配律：a * (b + c) = a*b + a*c
            #[test]
            fn prop_mul_distributive(a: u32, b: u32, c: u32) {
                let fa = Bn254ScalarField::from_u32_with_wrap(a);
                let fb = Bn254ScalarField::from_u32_with_wrap(b);
                let fc = Bn254ScalarField::from_u32_with_wrap(c);
                let left = fa.mul(&fb.add(&fc));
                let right = fa.mul(&fb).add(&fa.mul(&fc));
                prop_assert_eq!(left, right);
            }

            /// 非零元素有逆元，且 a * a^-1 = 1
            #[test]
            fn prop_inverse(v: u32) {
                let f = Bn254ScalarField::from_u32_with_wrap(v);
                if !f.is_zero() {
                    let inv = f.inverse().expect("非零应有逆元");
                    prop_assert_eq!(f.mul(&inv), Bn254ScalarField::one());
                }
            }
        }
    }
}
