//! poker_protocol 依赖切换（zgame monorepo → 独立 `linqining/poker_protocol`
//! 仓库 v1.0.0，Stark 唯一世界）的 API 兼容层。
//!
//! 新版将 `StarkPoint`/`StarkScalar` 的 blstrs 风格固有门面拆成了
//! `CurvePoint`/`CurveScalar` trait（`poker-protocol-core`），且不再提供
//! `crypto::stark_curve` 模块与 `generator`/`to_compressed`/`double`/`is_zero`
//! 命名。本模块以类型别名 + 扩展 trait 复原旧门面，调用点语法零改动：
//!
//! | 旧（zgame 固有）            | 新（本层桥接实现）                     |
//! |-----------------------------|----------------------------------------|
//! | `StarkPoint::generator()`   | `<StarkCurve as Curve>::base_g()`      |
//! | `p.to_compressed()`         | `CurvePoint::compress`（同字节 32B felt）|
//! | `p.double()`                | `p + p`                                 |
//! | `p.is_zero()`               | `p == identity`                         |
//!
//! `identity`/`is_identity`/`from_compressed`/`zero`/`one`/`invert`/
//! `from_u64`/`from_bytes_mod_order` 等与 trait 同名同签名，直接
//! re-export trait 即可按原语法解析。

pub use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar, StarkCurve};

/// 牌局主曲线的点/标量类型（= `poker-protocol-core` 的 `StarkPoint`/`StarkScalar`）。
pub type StarkPoint = <StarkCurve as Curve>::Point;
pub type StarkScalar = <StarkCurve as Curve>::Scalar;

/// zgame 版点固有门面的等价扩展（仅 Stark 点实现）。
pub trait StarkPointExt: CurvePoint {
    /// 生成元 = `Curve::base_g()`（同一 starknet-curve `GENERATOR`）。
    fn generator() -> Self;
    /// zgame 命名 `to_compressed` → 新 `CurvePoint::compress`（32B felt，同编码）。
    fn to_compressed(&self) -> <Self as CurvePoint>::Compressed;
    fn double(&self) -> Self;
    fn is_zero(&self) -> bool;
}

impl StarkPointExt for StarkPoint {
    fn generator() -> Self {
        <StarkCurve as Curve>::base_g()
    }

    fn to_compressed(&self) -> <Self as CurvePoint>::Compressed {
        CurvePoint::compress(self)
    }

    fn double(&self) -> Self {
        *self + *self
    }

    fn is_zero(&self) -> bool {
        *self == CurvePoint::identity()
    }
}

/// zgame 版标量固有门面的等价扩展。
pub trait StarkScalarExt: CurveScalar {
    /// zgame 版 `is_zero() -> Choice`；`bool::from(x.is_zero())` 语法经
    /// `From<bool> for bool` 恒等转换保持可用。
    fn is_zero(&self) -> bool {
        CurveScalar::as_bytes(self) == vec![0u8; 32]
    }
}

impl StarkScalarExt for StarkScalar {}
