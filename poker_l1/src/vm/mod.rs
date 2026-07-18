//! rBPF VM 模块（Phase 3 — Task 14 / 15 / 17）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **Task 14**：集成 `solana_rbpf` runtime（含 gas 计费表 + IMPL-SEC-4 沙箱）
//! - **Task 15**：核心 syscalls（object_read/write/create + emit_event + log/panic +
//!   verify_signature + get_block_height/timestamp + verify_failure_proof）
//! - **Task 17**：合约升级机制（UpgradeCap + timelock + SEC-L7 共识层强制）
//!
//! # 安全说明
//!
//! 本模块 `allow(unsafe_code)` 仅因 `solana_rbpf` 的 syscall 注册机制需要
//! 裸指针交互（`*mut EbpfVm<C>`）。所有 unsafe 操作封装在 `syscalls` 模块内，
//! 附安全不变式注释。其他子模块（gas_table / context / loader / upgrade）不含 unsafe。

#![allow(unsafe_code)]

pub mod context;
pub mod contract;
pub mod contracts;
pub mod crypto_blstrs;
pub mod gas_strategy;
pub mod gas_table;
pub mod loader;
pub mod precompile;
pub mod syscalls;
pub mod upgrade;

pub use context::{ContractCallResult, PokerL1Context, TxContext};
pub use contract::{ContractObject, ContractRegistry, UpgradeCap, UpgradeState};
pub use gas_table::*;
pub use loader::{LoadedContract, RbpfLoaderConfig, execute_contract, load_contract_bytecode};
pub use precompile::{DispatchResult, Precompile, PrecompileRegistry, PrecompileStatus, PrecompileVersion};
pub use syscalls::register_poker_l1_syscalls;
pub use upgrade::{
    UpgradeConfig, UpgradeError, cancel_upgrade, commit_upgrade, dispute_emergency_upgrade,
    dispute_upgrade, emergency_upgrade, initiate_upgrade, process_pending_upgrades,
};
