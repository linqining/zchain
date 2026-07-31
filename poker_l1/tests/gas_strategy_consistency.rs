//! Phase 4.6 — 跨 VM GasStrategy 一致性测试。
//!
//! 验证 BpfGasStrategy（poker_l1）与 ZkvmGasStrategy（poker_zkvm）的核心差异：
//! - BPF 有 gas，zkvm 无 gas
//! - 两者可作为 trait object 共存
//!
//! # 设计
//!
//! 本测试放在 poker_l1 crate（同时依赖 poker_zkvm 与自身），可访问两个策略。
//! 不测试具体 gas 值的等价性（BPF 与 zkvm 设计上不同），仅测试形式化差异。

use poker_l1::vm::gas_strategy::BpfGasStrategy;
use poker_zkvm::syscalls::gas_strategy::ZkvmGasStrategy;
use vm_common::gas_strategy::{GasStrategy, InsnCategory};

/// 验证 BPF 启用指令计量、zkvm 禁用指令计量。
#[test]
fn test_bpf_vs_zkvm_meter_difference() {
    let bpf = BpfGasStrategy::new();
    let zkvm = ZkvmGasStrategy::new();

    assert!(bpf.instruction_meter_enabled(), "BPF 应启用指令计量");
    assert!(!zkvm.instruction_meter_enabled(), "zkvm 应禁用指令计量");
}

/// 验证 zkvm 所有指令类别 gas = 0，BPF 所有指令类别 gas > 0。
#[test]
fn test_bpf_vs_zkvm_gas_difference() {
    let bpf = BpfGasStrategy::new();
    let zkvm = ZkvmGasStrategy::new();

    let all_categories = [
        InsnCategory::Arithmetic,
        InsnCategory::Memory,
        InsnCategory::ControlFlow,
        InsnCategory::Shift,
        InsnCategory::Mul,
        InsnCategory::Div,
        InsnCategory::UpperImm,
        InsnCategory::System,
        InsnCategory::Other,
    ];

    for cat in all_categories {
        assert_eq!(zkvm.instruction_gas(cat), 0, "zkvm {:?} 应为 0", cat);
        assert!(bpf.instruction_gas(cat) > 0, "BPF {:?} 应 > 0", cat);
    }
}

/// 验证策略名称差异。
#[test]
fn test_strategy_names() {
    assert_eq!(BpfGasStrategy::new().name(), "bpf");
    assert_eq!(ZkvmGasStrategy::new().name(), "zkvm");
    assert_ne!(BpfGasStrategy::new().name(), ZkvmGasStrategy::new().name());
}

/// 验证 BPF 的 gas 上限为正值，且 block > tx。
#[test]
fn test_bpf_limits_positive() {
    let bpf = BpfGasStrategy::new();
    assert_eq!(bpf.default_tx_gas_limit(), 10_000_000);
    assert_eq!(bpf.default_block_gas_limit(), 50_000_000);
    assert!(bpf.default_block_gas_limit() > bpf.default_tx_gas_limit());
}

/// 验证 zkvm 的 gas 上限为 0（无 gas 费）。
#[test]
fn test_zkvm_limits_zero() {
    let zkvm = ZkvmGasStrategy::new();
    assert_eq!(zkvm.default_tx_gas_limit(), 0);
    assert_eq!(zkvm.default_block_gas_limit(), 0);
}

/// 验证 BPF 对已知 syscall 计费，zkvm 全部为 0。
#[test]
fn test_bpf_vs_zkvm_syscall_gas() {
    let bpf = BpfGasStrategy::new();
    let zkvm = ZkvmGasStrategy::new();

    // BPF 对 ObjectRead 计费（10 + 1*100 = 110），zkvm 为 0
    assert_eq!(
        bpf.syscall_gas(vm_common::syscall_id::SyscallId::ObjectRead, 100),
        110
    );
    assert_eq!(
        zkvm.syscall_gas(vm_common::syscall_id::SyscallId::ObjectRead, 100),
        0
    );

    // BPF 对 VerifySignature 固定 500，zkvm 为 0
    assert_eq!(
        bpf.syscall_gas(vm_common::syscall_id::SyscallId::VerifySignature, 0),
        500
    );
    assert_eq!(
        zkvm.syscall_gas(vm_common::syscall_id::SyscallId::VerifySignature, 0),
        0
    );
}

/// 验证两个策略可作为 trait object 共存于集合。
#[test]
fn test_trait_object_collection() {
    let strategies: Vec<Box<dyn GasStrategy>> = vec![
        Box::new(BpfGasStrategy::new()),
        Box::new(ZkvmGasStrategy::new()),
    ];
    assert_eq!(strategies.len(), 2);
    assert_eq!(strategies[0].name(), "bpf");
    assert_eq!(strategies[1].name(), "zkvm");

    // 通过 trait object 调用方法
    for s in &strategies {
        let _gas = s.instruction_gas(InsnCategory::Arithmetic);
        let _name = s.name();
    }
}

/// 验证 Default trait 可用。
#[test]
fn test_default_trait() {
    let bpf: BpfGasStrategy = Default::default();
    let zkvm: ZkvmGasStrategy = Default::default();
    assert_eq!(bpf.name(), "bpf");
    assert_eq!(zkvm.name(), "zkvm");
}
