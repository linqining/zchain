//! 步骤1 最小依赖工程：只引用 stwo 的核心（验证器路径）类型，触发完整依赖图编译。
pub fn touch() -> u32 {
    use stwo::core::fields::m31::M31;
    M31::from(1u32).0
}
