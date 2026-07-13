//! Syscall 子电路（Phase 5 — Task 5.5）。
//!
//! 严格遵循 spec.md L287-298 / tasks.md L149-152（v1.4 FROZEN）：
//! - ECALL 子电路 — 解码 `a7`，根据 syscall_id 选择对应预编译子电路
//! - 每个 syscall 调用产生独立 CCS 实例（与指令实例合并折叠）
//! - 加密 syscall（Poseidon/SHA-256/ECDSA）委托 Phase 10 预编译电路
//!
//! ## MVP 策略
//!
//! - [`SyscallAbiCircuit`] — 约束 `a7 == expected_syscall_id`（ABI 一致性）
//! - [`dispatch_syscall`] — 分派器：加密 syscall 附加预编译 CCS 实例
//! - 非加密 syscall（read_input/commit_output/...）仅产生 ABI 实例，
//!   I/O 一致性由 Step 10 内存电路保证

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::precompiles::PrecompileRegistry;
use crate::syscalls::SyscallId;

// ===========================================================================
// SyscallAbiCircuit — ABI 一致性约束
// ===========================================================================

/// Syscall ABI 一致性电路。
///
/// 约束 `a7 == expected_syscall_id`，确保 ECALL 调用了正确的 syscall。
///
/// witness: `z = [1, a7_val, expected_id]`（长度 3）
///
/// 约束（1 行）：`a7_val - expected_id = 0`
pub struct SyscallAbiCircuit {
    /// 预期 syscall_id。
    syscall_id: SyscallId,
}

impl SyscallAbiCircuit {
    /// 创建 ABI 电路（指定预期 syscall_id）。
    #[must_use]
    pub fn new(syscall_id: SyscallId) -> Self {
        Self { syscall_id }
    }

    /// 构建 CCS 约束结构。
    #[must_use]
    pub fn build_ccs() -> Ccs {
        let num_vars = 3;
        let num_rows = 1;
        let neg_one = Fr::zero().sub(&Fr::one());

        // Row 0: a7_val - expected_id = 0
        let mut m_a7 = SparseMatrix::new(num_rows, num_vars);
        m_a7.add_entry(0, 1, Fr::one()).expect("M_a7");

        let mut m_expected_neg = SparseMatrix::new(num_rows, num_vars);
        m_expected_neg
            .add_entry(0, 2, neg_one)
            .expect("M_expected_neg");

        Ccs::new(
            num_vars,
            vec![m_a7, m_expected_neg],
            vec![vec![0], vec![1]],
            vec![Fr::one(), Fr::one()],
        )
        .expect("SyscallAbiCircuit CCS 构造应成功")
    }

    /// 赋值 witness。
    ///
    /// # 参数
    /// - `a7_val` — 实际 a7 寄存器值（须 == syscall_id as u32）
    #[must_use]
    pub fn assign_witness(&self, a7_val: u32) -> Vec<Fr> {
        vec![
            Fr::one(),
            Fr::from_u32_with_wrap(a7_val),
            Fr::from_u32_with_wrap(self.syscall_id as u32),
        ]
    }

    /// 构建完整 CCS 实例。
    ///
    /// # 错误
    /// - `a7_val != syscall_id as u32` 返回 `ZkvmError::Other`（ABI 不匹配）
    pub fn to_instance(&self, a7_val: u32) -> Result<CcsInstance, ZkvmError> {
        if a7_val != self.syscall_id as u32 {
            return Err(ZkvmError::Other(format!(
                "SyscallAbiCircuit: a7={a7_val:#x} != expected syscall_id={:#x}",
                self.syscall_id as u32
            )));
        }
        let ccs = Self::build_ccs();
        let witness = self.assign_witness(a7_val);
        let public_inputs = vec![
            Fr::from_u32_with_wrap(self.syscall_id as u32),
            Fr::from_u32_with_wrap(a7_val),
        ];
        CcsInstance::new(ccs, witness, public_inputs)
    }

    /// 返回 syscall_id。
    #[must_use]
    pub fn syscall_id(&self) -> SyscallId {
        self.syscall_id
    }
}

// ===========================================================================
// dispatch_syscall — ECALL 分派器
// ===========================================================================

/// ECALL 分派器 — 根据 syscall_id 生成 CCS 实例列表。
///
/// 对于每个 ECALL 指令，产生：
/// 1. 始终产生 [`SyscallAbiCircuit`] 实例（ABI 一致性）
/// 2. 对于加密 syscall（Poseidon/SHA-256/ECDSA），附加预编译 CCS 实例
///
/// # 参数
/// - `syscall_id` — 预期 syscall_id
/// - `a7_val` — 实际 a7 寄存器值
/// - `registry` — 预编译电路注册表
/// - `precompile_inputs` — 预编译电路输入（域元素切片，仅加密 syscall 使用）
///
/// # 返回
/// - `Ok(Vec<CcsInstance>)` — CCS 实例列表（1 或 2 个）
/// - `Err(ZkvmError)` — ABI 不匹配 / 预编译电路未注册 / witness 赋值失败
///
/// # 错误
/// - `ZkvmError::Other` — a7 != syscall_id 或预编译电路缺失
pub fn dispatch_syscall(
    syscall_id: SyscallId,
    a7_val: u32,
    registry: &PrecompileRegistry,
    precompile_inputs: &[Fr],
) -> Result<Vec<CcsInstance>, ZkvmError> {
    // 1. 始终产生 ABI 一致性实例
    let abi_instance = SyscallAbiCircuit::new(syscall_id).to_instance(a7_val)?;
    let mut instances = vec![abi_instance];

    // 2. 加密 syscall 附加预编译实例
    let precompile_name = match syscall_id {
        SyscallId::Poseidon => Some("poseidon"),
        SyscallId::Sha256 => Some("sha256"),
        SyscallId::EcdsaVerify => Some("ecdsa_verify"),
        _ => None,
    };

    if let Some(name) = precompile_name {
        let circuit = registry.get(name).ok_or_else(|| {
            ZkvmError::Other(format!("dispatch_syscall: 预编译电路 '{name}' 未注册"))
        })?;
        let ccs = circuit.build_ccs();
        let witness = circuit.assign_witness(precompile_inputs)?;
        let public_inputs = vec![Fr::from_u32_with_wrap(syscall_id as u32)];
        instances.push(CcsInstance::new(ccs, witness, public_inputs)?);
    }

    Ok(instances)
}

/// 判断 syscall_id 是否为加密 syscall（有对应预编译电路）。
#[must_use]
pub fn is_cryptographic_syscall(syscall_id: SyscallId) -> bool {
    matches!(
        syscall_id,
        SyscallId::Poseidon | SyscallId::Sha256 | SyscallId::EcdsaVerify
    )
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::ecdsa::EcdsaVerifyCircuit;
    use crate::precompiles::poseidon::PoseidonCircuit;
    use crate::precompiles::sha256::Sha256Circuit;

    // ===== SyscallAbiCircuit 测试 =====

    #[test]
    fn test_abi_build_ccs() {
        let ccs = SyscallAbiCircuit::build_ccs();
        assert_eq!(ccs.num_vars, 3);
        assert_eq!(ccs.num_rows(), 1);
        assert_eq!(ccs.num_matrices(), 2);
    }

    #[test]
    fn test_abi_matching_id() {
        let circuit = SyscallAbiCircuit::new(SyscallId::Poseidon);
        let ccs = SyscallAbiCircuit::build_ccs();
        let witness = circuit.assign_witness(0x03);
        assert!(ccs.satisfied_by(&witness).expect("应满足"));
    }

    #[test]
    fn test_abi_mismatched_id_soundness() {
        let circuit = SyscallAbiCircuit::new(SyscallId::Poseidon);
        let ccs = SyscallAbiCircuit::build_ccs();
        // a7=0x04 (Sha256) 但声称 Poseidon (0x03)
        let witness = circuit.assign_witness(0x04);
        assert!(!ccs.satisfied_by(&witness).expect("应返回 false"));
    }

    #[test]
    fn test_abi_to_instance_success() {
        let circuit = SyscallAbiCircuit::new(SyscallId::ReadInput);
        let inst = circuit.to_instance(0x01).expect("应成功");
        assert!(inst.is_satisfied().expect("应满足"));
        assert_eq!(inst.public_inputs[0], Fr::from_u32_with_wrap(0x01));
    }

    #[test]
    fn test_abi_to_instance_mismatch_errors() {
        let circuit = SyscallAbiCircuit::new(SyscallId::ReadInput);
        let err = circuit.to_instance(0x05).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("a7")));
    }

    #[test]
    fn test_abi_all_syscall_ids() {
        // 测试所有 10 个 syscall_id 的 ABI 电路
        let ids = [
            SyscallId::ReadInput,
            SyscallId::CommitOutput,
            SyscallId::Poseidon,
            SyscallId::Sha256,
            SyscallId::EcdsaVerify,
            SyscallId::EmitEvent,
            SyscallId::Log,
            SyscallId::Panic,
            SyscallId::GetRandomness,
            SyscallId::ReadState,
        ];
        for id in ids {
            let circuit = SyscallAbiCircuit::new(id);
            let inst = circuit.to_instance(id as u32).expect("应成功");
            assert!(inst.is_satisfied().expect("应满足"));
        }
    }

    // ===== is_cryptographic_syscall 测试 =====

    #[test]
    fn test_is_cryptographic() {
        assert!(is_cryptographic_syscall(SyscallId::Poseidon));
        assert!(is_cryptographic_syscall(SyscallId::Sha256));
        assert!(is_cryptographic_syscall(SyscallId::EcdsaVerify));
        assert!(!is_cryptographic_syscall(SyscallId::ReadInput));
        assert!(!is_cryptographic_syscall(SyscallId::CommitOutput));
        assert!(!is_cryptographic_syscall(SyscallId::EmitEvent));
        assert!(!is_cryptographic_syscall(SyscallId::Log));
        assert!(!is_cryptographic_syscall(SyscallId::Panic));
        assert!(!is_cryptographic_syscall(SyscallId::GetRandomness));
        assert!(!is_cryptographic_syscall(SyscallId::ReadState));
    }

    // ===== dispatch_syscall 测试 =====

    /// 构建含 3 个预编译电路的注册表。
    fn make_registry() -> PrecompileRegistry {
        let mut registry = PrecompileRegistry::new();
        registry.register(Box::new(PoseidonCircuit::new()));
        registry.register(Box::new(Sha256Circuit::new()));
        registry.register(Box::new(EcdsaVerifyCircuit::new()));
        registry
    }

    #[test]
    fn test_dispatch_non_cryptographic_single_instance() {
        let registry = make_registry();
        // read_input: 非加密，仅 ABI 实例
        let instances =
            dispatch_syscall(SyscallId::ReadInput, 0x01, &registry, &[]).expect("应成功");
        assert_eq!(instances.len(), 1);
        assert!(instances[0].is_satisfied().expect("ABI 应满足"));
    }

    #[test]
    fn test_dispatch_commit_output_single_instance() {
        let registry = make_registry();
        let instances =
            dispatch_syscall(SyscallId::CommitOutput, 0x02, &registry, &[]).expect("应成功");
        assert_eq!(instances.len(), 1);
        assert!(instances[0].is_satisfied().expect("应满足"));
    }

    #[test]
    fn test_dispatch_poseidon_two_instances() {
        let registry = make_registry();
        // Poseidon: ABI + 预编译 = 2 个实例
        let inputs = [Fr::from_u32_with_wrap(42)];
        let instances =
            dispatch_syscall(SyscallId::Poseidon, 0x03, &registry, &inputs).expect("应成功");
        assert_eq!(instances.len(), 2);
        // ABI 实例
        assert!(instances[0].is_satisfied().expect("ABI 应满足"));
        // 预编译实例
        assert!(instances[1].is_satisfied().expect("预编译应满足"));
    }

    #[test]
    fn test_dispatch_sha256_two_instances() {
        let registry = make_registry();
        // SHA-256 MVP 需要 3 个输入: [x, y, z]（Ch 函数）
        let inputs = [
            Fr::from_u32_with_wrap(0xAB),
            Fr::from_u32_with_wrap(0xCD),
            Fr::from_u32_with_wrap(0xEF),
        ];
        let instances =
            dispatch_syscall(SyscallId::Sha256, 0x04, &registry, &inputs).expect("应成功");
        assert_eq!(instances.len(), 2);
        assert!(instances[0].is_satisfied().expect("ABI 应满足"));
        assert!(instances[1].is_satisfied().expect("预编译应满足"));
    }

    #[test]
    fn test_dispatch_ecdsa_two_instances() {
        let registry = make_registry();
        // ECDSA 预编译 MVP 需要 3 个输入: [bit, R, P]
        let inputs = [
            Fr::one(),                  // bit=1
            Fr::from_u32_with_wrap(42), // R
            Fr::from_u32_with_wrap(99), // P
        ];
        let instances =
            dispatch_syscall(SyscallId::EcdsaVerify, 0x05, &registry, &inputs).expect("应成功");
        assert_eq!(instances.len(), 2);
        assert!(instances[0].is_satisfied().expect("ABI 应满足"));
        assert!(instances[1].is_satisfied().expect("预编译应满足"));
    }

    #[test]
    fn test_dispatch_abi_mismatch_errors() {
        let registry = make_registry();
        let err = dispatch_syscall(SyscallId::Poseidon, 0x04, &registry, &[]).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("a7")));
    }

    #[test]
    fn test_dispatch_missing_precompile_errors() {
        // 空注册表 → 加密 syscall 分派失败
        let empty_registry = PrecompileRegistry::new();
        let inputs = [Fr::from_u32_with_wrap(42)];
        let err =
            dispatch_syscall(SyscallId::Poseidon, 0x03, &empty_registry, &inputs).unwrap_err();
        assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("未注册")));
    }

    #[test]
    fn test_dispatch_all_non_crypto_single_instance() {
        let registry = make_registry();
        let non_crypto_ids = [
            SyscallId::ReadInput,
            SyscallId::CommitOutput,
            SyscallId::EmitEvent,
            SyscallId::Log,
            SyscallId::Panic,
            SyscallId::GetRandomness,
            SyscallId::ReadState,
        ];
        for id in non_crypto_ids {
            let instances = dispatch_syscall(id, id as u32, &registry, &[]).expect("应成功");
            assert_eq!(
                instances.len(),
                1,
                "非加密 syscall {:?} 应仅产生 1 个实例",
                id
            );
            assert!(instances[0].is_satisfied().expect("应满足"));
        }
    }

    #[test]
    fn test_dispatch_all_crypto_two_instances() {
        let registry = make_registry();
        // Poseidon 需要 1 个输入 [x]
        let inputs_poseidon = [Fr::from_u32_with_wrap(42)];
        let instances = dispatch_syscall(SyscallId::Poseidon, 0x03, &registry, &inputs_poseidon)
            .expect("应成功");
        assert_eq!(instances.len(), 2, "Poseidon 应产生 2 个实例");

        // SHA-256 需要 3 个输入 [x, y, z]
        let inputs_sha = [
            Fr::from_u32_with_wrap(0xAB),
            Fr::from_u32_with_wrap(0xCD),
            Fr::from_u32_with_wrap(0xEF),
        ];
        let instances =
            dispatch_syscall(SyscallId::Sha256, 0x04, &registry, &inputs_sha).expect("应成功");
        assert_eq!(instances.len(), 2, "SHA-256 应产生 2 个实例");

        // ECDSA 需要 3 个输入 [bit, R, P]
        let inputs_ecdsa = [
            Fr::one(),
            Fr::from_u32_with_wrap(42),
            Fr::from_u32_with_wrap(99),
        ];
        let instances = dispatch_syscall(SyscallId::EcdsaVerify, 0x05, &registry, &inputs_ecdsa)
            .expect("应成功");
        assert_eq!(instances.len(), 2, "ECDSA 应产生 2 个实例");
    }

    #[test]
    fn test_abi_witness_layout() {
        let circuit = SyscallAbiCircuit::new(SyscallId::Sha256);
        let witness = circuit.assign_witness(0x04);
        // z = [1, a7, expected_id]
        assert_eq!(witness[0], Fr::one());
        assert_eq!(witness[1], Fr::from_u32_with_wrap(0x04));
        assert_eq!(witness[2], Fr::from_u32_with_wrap(0x04));
    }

    #[test]
    fn test_abi_public_inputs() {
        let circuit = SyscallAbiCircuit::new(SyscallId::EmitEvent);
        let inst = circuit.to_instance(0x06).expect("应成功");
        // public_inputs = [syscall_id, a7_val]
        assert_eq!(inst.public_inputs[0], Fr::from_u32_with_wrap(0x06));
        assert_eq!(inst.public_inputs[1], Fr::from_u32_with_wrap(0x06));
    }
}
