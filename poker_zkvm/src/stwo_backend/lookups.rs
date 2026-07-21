//! # Stwo Logup Lookup Relations（Phase 3）
//!
//! 定义 CPU AIR 与 Memory/Register AIR 之间共享的 lookup relation。
//!
//! ## 机制
//!
//! 使用 Stwo 的 `relation!` 宏定义 N 元 lookup relation：
//! - CPU AIR 发送 **claim**（multiplicity = +1）
//! - Memory/Register AIR 发送 **yield**（multiplicity = -1）
//! - Σ(claims) + Σ(yields) = 0 即证明一致性
//!
//! ## Relations
//!
//! - [`MemoryLookup`] — 9 元组：(addr×4, val×4, is_store×1)
//! - [`RegisterLookup`] — 6 元组：(reg_idx×1, val×4, is_write×1)（Phase 3 后续）
//!
//! ## 参考
//!
//! - `stwo-constraint-framework-2.3.0/src/logup.rs` — `LookupElements<N>`
//! - `stwo-constraint-framework-2.3.0/src/lib.rs` L305-335 — `relation!` 宏

// relation! 宏生成的 struct/impl 缺少 doc 注释，此处统一豁免 missing_docs
#![allow(missing_docs)]

use stwo_constraint_framework::relation;

/// Memory lookup relation（9 元组）。
///
/// 用于 CPU AIR 与 Memory AIR 之间的 Load/Store 一致性验证。
///
/// ## 值布局
///
/// ```text
/// values[0..4] = MemAddr (4×8-bit limb, little-endian)
/// values[4..8] = MemVal  (4×8-bit limb, little-endian)
/// values[8]    = IsStore (1=Store, 0=Load)
/// ```
///
/// ## 交互
///
/// - **CPU AIR 发送 claim**（每条 Load/Store 指令，multiplicity = +1）：
///   - Load: values = (mem_addr, loaded_value, 0)
///   - Store: values = (mem_addr, stored_value, 1)
///
/// - **Memory AIR 发送 yield**（每行，multiplicity = -1）：
///   - values = (MemAddr, MemValCur, MemIsStore)
///
/// - **一致性条件**：Σ(CPU claims) = Σ(Memory yields)，即 logup sum = 0
relation!(MemoryLookup, 9);

/// Register lookup relation（6 元组）。
///
/// 用于 CPU AIR 与 Register AIR 之间的寄存器访问一致性验证。
///
/// ## 值布局
///
/// ```text
/// values[0]    = RegIdx (寄存器索引 0-31)
/// values[1..5] = RegVal (4×8-bit limb, little-endian)
/// values[5]    = IsWrite (1=写, 0=读)
/// ```
///
/// ## 交互
///
/// - **CPU AIR 发送 claim**（每条指令的每个寄存器访问）：
///   - rs1 读: values = (op_b, value_b, 0), multiplicity = +1
///   - rs2 读: values = (op_c, value_c, 0), multiplicity = +1
///   - rd 写:  values = (op_a, value_a_eff, 1), multiplicity = +1
///
/// - **Register AIR 发送 yield**（每行，multiplicity = -1）：
///   - values = (RegIdx, RegValCur, RegIsWrite)
#[allow(dead_code)]
relation!(RegisterLookup, 6);

/// ECALL dispatch lookup relation（1 元组，v3）。
///
/// 用于 CPU AIR 与 Precompile AIR（Tier 2+）之间的 syscall 一致性验证。
///
/// ## v3 变更
///
/// 从 25 元组缩减为 1 元组（仅 SyscallId）。原 25 元组中的 Args/Outputs 6×4=24 列
/// 已在 v3 列布局中移除（参见 column_layout_v2.rs）。
///
/// ## 值布局（1 元组）
///
/// ```text
/// values[0] = SyscallId (1 列 M31，直接表示 0-127)
/// ```
///
/// ## 交互
///
/// - **CPU AIR 发送 claim**（每条 ECALL 指令，multiplicity = +1）：
///   - values = (syscall_id,)
///   - 非 ECALL 行 multiplicity = 0（不贡献 sum）
///
/// - **Precompile AIR 发送 yield**（Tier 2+，multiplicity = -1）：
///   - 例如 Poseidon AIR 在 IsLastRound=1 行发送：values = (POSEIDON,)
///
/// - **一致性条件**：Σ(CPU claims) + Σ(Precompile yields) == 0
///
/// ## Phase 4 Tier 1 状态
///
/// - Tier 1：定义 relation + CPU AIR 发送 claim 函数（gated by `Option<EcallLookup>`）
/// - Tier 1 不启用 yield 方（无 Precompile AIR），测试时 multiplicity = 0
/// - Tier 2+：实施 Precompile AIR（Poseidon/Sha256/MerkleVerify）后启用 yield
///
/// ## Soundness 影响
///
/// v3 仅保留 SyscallId 作为 lookup 关键字。这意味着 logup 只能证明"CPU 看到的
/// SyscallId 集合 == Precompile AIR 看到的 SyscallId 集合"，无法保证 Args/Outputs
/// 一致性。如需恢复 Args/Outputs 一致性，需恢复 ECALL Args/Outputs 列（24 列）。
#[allow(dead_code)]
relation!(EcallLookup, 1);

/// Poseidon hash lookup relation（9 元组）。
///
/// 用于 CPU AIR 与 Poseidon AIR 之间的 Poseidon hash 计算一致性验证。
///
/// ## 值布局（9 元组，全部 M31）
///
/// ```text
/// values[0]       = SyscallId      (1 列 M31，= 0x03 for Poseidon)
/// values[1..4]    = Input[0..3]    (3 列 M31，sponge state input)
/// values[4..7]    = Output[0..3]   (3 列 M31，sponge state output)
/// values[7]       = IsLastRound    (1 列 M31，= 1 表示该 hash 的最后一轮)
/// values[8]       = IsPadding      (1 列 M31，= 1 表示 padding 行)
/// ```
///
/// ## 交互
///
/// - **CPU AIR 发送 claim**（每条 Poseidon ECALL 指令，multiplicity = +1）：
///   - values = (POSEIDON=0x03, Input[0..3], Output[0..3], 1, 0)
///   - CPU 从 ECALL 行的 Args/Outputs 重组为 M31 形式
///   - 非 Poseidon ECALL 行 multiplicity = 0
///
/// - **Poseidon AIR 发送 yield**（每 IsLastRound=1 行，multiplicity = -1）：
///   - values = (0x03, Input[0..3], Output[0..3], 1, 0)
///   - padding 行 multiplicity = 0
///
/// - **一致性条件**：Σ(CPU claims) + Σ(Poseidon yields) == 0
///
/// ## Soundness 说明
///
/// - Poseidon AIR 的 16 条约束确保 State 转换正确（sponge permutation）
/// - logup 确保 CPU 知道的 (Input, Output) 与 Poseidon AIR 计算的 (Input, Output) 一致
/// - Input 来源（内存读取）由 Memory AIR 验证（后续步骤）
#[allow(dead_code)]
relation!(PoseidonLookup, 9);

/// Sha256 hash lookup relation（9 元组）。
///
/// 用于 CPU AIR 与 Sha256 AIR 之间的 SHA-256 hash 计算一致性验证。
///
/// ## 值布局（9 元组，全部 M31）
///
/// ```text
/// values[0]       = SyscallId      (1 列 M31，= 0x04 for Sha256)
/// values[1..4]    = Input[0..3]    (3 列 M31，input hash 摘要前 3 个 M31)
/// values[4..7]    = Output[0..3]   (3 列 M31，output hash 摘要前 3 个 M31)
/// values[7]       = IsLastBlock    (1 列 M31，= 1 表示该 hash 的最后一块）
/// values[8]       = IsPadding      (1 列 M31，= 1 表示 padding 行）
/// ```
///
/// ## 交互
///
/// - **CPU AIR 发送 claim**（每条 Sha256 ECALL 指令，multiplicity = +1）：
///   - values = (SHA256=0x04, Input[0..3], Output[0..3], 1, 0)
///   - 非 Sha256 ECALL 行 multiplicity = 0
///
/// - **Sha256 AIR 发送 yield**（每 IsLastBlock=1 行，multiplicity = -1）：
///   - values = (0x04, Input[0..3], Output[0..3], 1, 0)
///   - padding 行 multiplicity = 0
///
/// - **一致性条件**：Σ(CPU claims) + Σ(Sha256 yields) == 0
///
/// ## Soundness 说明
///
/// - Sha256 AIR 的约束确保 compression function 计算正确（64 轮 state transition）
/// - logup 确保 CPU 知道的 (Input, Output) 与 Sha256 AIR 计算的 (Input, Output) 一致
/// - Input 来源（内存读取）由 Memory AIR 验证
///
/// ## 设计文档
///
/// 详见 `.trae/documents/stwo_phase4_tier2_sha256_air_design.md`
#[allow(dead_code)]
relation!(Sha256Lookup, 9);

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::fields::qm31::SecureField;
    use stwo_constraint_framework::Relation;

    #[test]
    fn test_memory_lookup_dummy() {
        // 验证 MemoryLookup 可以创建 dummy 实例
        let _lookup = MemoryLookup::dummy();
    }

    #[test]
    fn test_register_lookup_dummy() {
        let _lookup = RegisterLookup::dummy();
    }

    #[test]
    fn test_memory_lookup_size() {
        // MemoryLookup 是 9 元组
        let lookup = MemoryLookup::dummy();
        assert_eq!(
            <MemoryLookup as Relation<BaseField, SecureField>>::get_size(&lookup),
            9
        );
    }

    #[test]
    fn test_register_lookup_size() {
        let lookup = RegisterLookup::dummy();
        assert_eq!(
            <RegisterLookup as Relation<BaseField, SecureField>>::get_size(&lookup),
            6
        );
    }

    #[test]
    fn test_ecall_lookup_dummy() {
        // 验证 EcallLookup 可以创建 dummy 实例
        let _lookup = EcallLookup::dummy();
    }

    #[test]
    fn test_ecall_lookup_size() {
        // EcallLookup v3 是 1 元组（仅 SyscallId）
        let lookup = EcallLookup::dummy();
        assert_eq!(
            <EcallLookup as Relation<BaseField, SecureField>>::get_size(&lookup),
            1
        );
    }

    #[test]
    fn test_poseidon_lookup_dummy() {
        // 验证 PoseidonLookup 可以创建 dummy 实例
        let _lookup = PoseidonLookup::dummy();
    }

    #[test]
    fn test_poseidon_lookup_size() {
        // PoseidonLookup 是 9 元组（SyscallId + Input×3 + Output×3 + IsLast + IsPadding）
        let lookup = PoseidonLookup::dummy();
        assert_eq!(
            <PoseidonLookup as Relation<BaseField, SecureField>>::get_size(&lookup),
            9
        );
    }

    #[test]
    fn test_sha256_lookup_dummy() {
        // 验证 Sha256Lookup 可以创建 dummy 实例
        let _lookup = Sha256Lookup::dummy();
    }

    #[test]
    fn test_sha256_lookup_size() {
        // Sha256Lookup 是 9 元组（SyscallId + Input×3 + Output×3 + IsLastBlock + IsPadding）
        let lookup = Sha256Lookup::dummy();
        assert_eq!(
            <Sha256Lookup as Relation<BaseField, SecureField>>::get_size(&lookup),
            9
        );
    }
}