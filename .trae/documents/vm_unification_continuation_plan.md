# VM 统一架构 — 续作执行计划

## 背景与当前状态

本计划接续 `/Users/mac/projects/zchain/.trae/documents/vm_unification_execution_plan_v2.md`（v2，已审批通过）的执行。上次会话完成 Phase 1 后上下文丢失，本计划从 Phase 2 半成品状态接续。

### 已确认状态（探索结论）

| 项目 | 状态 | 证据 |
|---|---|---|
| Phase 0 测试基线 | ✅ 完成 | poker_l1 vm 测试 + poker_zkvm 1069 测试全绿 |
| Phase 1（vm-common 骨架 + gas/syscall_id 迁移） | ✅ 完成 | `cargo check -p vm-common` 通过；`Cargo.toml` 已注册 workspace |
| Phase 2 启动 | ⚠️ 半成品 | `vm-common/src/precompile.rs` 已存在但**截断**于 L219（`name: "gameturn` 未闭合）|
| Phase 2 adapter | ❌ 未创建 | `poker_zkvm/src/precompiles/adapter.rs` 不存在 |
| Phase 2 模块注册 | ❌ 未完成 | `vm-common/src/lib.rs` 仅有 `pub mod gas; pub mod syscall_id;`，缺 `pub mod precompile;` |
| poker_l1 `Precompile` trait | ✅ 未动 | `poker_l1/src/vm/precompile.rs`（22664 字节）保持原始状态 |
| 17 个业务合约 | ✅ 未动 | `poker_l1/src/vm/contracts/`（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs 外）零修改 |
| Phase 3-5 | ❌ 未开始 | — |

### 关键代码事实（Phase 1 完成后重新探索确认）

- **`vm-common/src/gas.rs`**（273 行）：含所有共享 gas 常量与纯函数（`object_read_gas`/`zk_verify_gas` 等），单一事实源已建立
- **`vm-common/src/syscall_id.rs`**（含 35 个变体）：统一 `SyscallId` 枚举，分段 ID 空间（0x01-0x0F zkvm / 0x40-0x7F poker_l1 / 0x80-0xFF BLS）
- **`poker_l1/src/vm/precompile.rs`**（698 行，22664 字节）：完整 `Precompile` trait + `PrecompileRegistry`，`call()` 签名依赖 `ObjectID`/`Address`/`TaggedPubkey`/`ObjectDb`/`PokerL1Error`/`BlockHeight`/`ChainId`，迁移到 vm-common 会导致 god-crate
- **`poker_zkvm/src/precompiles/mod.rs`**：`PrecompileCircuit` trait（CCS 电路级：`build_ccs`/`assign_witness`/`gas_cost`），9 个具体电路实现
- **`poker_l1/src/crypto_precompiles/bls.rs`**（关键发现）：poker_l1 的 BLS syscall **已经**通过此模块间接调用 blstrs，不是直接 `blstrs::` — Phase 3 抽象层已部分存在
- **`poker_l1/src/vm/context.rs:105`**：`PokerL1Context::new(tx, gas_limit)` — gas_limit 是 `u64`，指令级 gas 通过 `consume(1)` 计量
- **`poker_zkvm/src/isa/executor.rs:173`**：`execute_elf_with_limits_and_config(elf, config, step_limit, mem_limit)` — **无 gas 概念**，只有 step_limit/mem_limit — zkvm "no gas" 现状已成立

---

## 关键设计决策（Phase 2 偏离说明）

**v2 计划 Phase 2 原定方案 2.1A**（关联类型抽象 `Precompile<Db, Err>`）会要求 17 个业务合约修改 `impl Precompile` 签名，破坏"零修改"硬约束。

**实际采用方案**（已在 `vm-common/src/precompile.rs` 顶部文档化）：
- vm-common 仅定义 `PrecompileMetadata` 最小元数据 trait（`id_bytes`/`name`/`version`/`supports_selector`/`is_gas_free`）
- poker_l1 `Precompile` trait 保持原状零修改
- poker_zkvm `PrecompileCircuitAdapter` 实现 `PrecompileMetadata`（单向桥接）
- 完整跨 VM `call()` 统一推迟到有具体业务需求时再实现

**理由**：用户硬约束"业务合约零修改"高于"完整 trait 统一"。元数据接口足以满足跨 VM 注册表管理需求。

---

## 执行原则（沿用 v2）

1. 每阶段独立可回退，每阶段完成立即跑测试
2. 业务合约零修改（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs）
3. Hypernova/CCS/constraints/prover/recursion 零修改
4. GameTurn/CheckpointAnchor gas-free lane 零修改
5. `poker_zkvm::#![deny(unsafe_code)]` 不破坏
6. vm-common 严格 `#![deny(unsafe_code)]`，不依赖 solana_rbpf/arkworks

---

## Phase 2：PrecompileMetadata trait + zkvm Adapter 桥接（续作）

**目标**：完成 vm-common 的 PrecompileMetadata trait 定义，为 zkvm PrecompileCircuit 实现 adapter，建立单向桥接。

**预计工作量**：1-2 天（半成品续作）

### Step 2.1：修复截断的 `vm-common/src/precompile.rs`

**文件**：`/Users/mac/projects/zchain/vm-common/src/precompile.rs`

**问题**：当前文件在 L219 截断（`name: "gameturn` 字符串字面量未闭合），导致 `cargo build -p vm-common` 失败。

**动作**：先 Read 完整文件，再 Write 完整内容（保留已有正确部分，补全截断的 `test_precompile_metadata_gas_free_override` 测试与 `test_precompile_metadata_gas_free_default` 等剩余测试）。

**最终内容应包含**：
- `PrecompileStatus` 枚举（Stub/Production）+ `allows_mainnet()`
- `PrecompileVersion` 结构体（u64 避免 BlockHeight 依赖）+ `Default`
- `PrecompileMetadata` trait（5 个方法，3 个有默认实现）
- `PRECOMPILE_PREFIX = 0xFF` 常量
- `precompile_id_from_name(&str) -> [u8; 32]` 函数（稳定哈希，0xFF 前缀）
- 6 个单元测试：
  1. `test_precompile_status_allows_mainnet`
  2. `test_precompile_version_default`
  3. `test_precompile_id_from_name_stable`（同名同 ID，异名异 ID，前缀验证）
  4. `test_precompile_id_from_name_uniqueness`（5 个名称无碰撞）
  5. `test_precompile_metadata_trait`（默认值验证）
  6. `test_precompile_metadata_gas_free_override`（GameTurn 场景 is_gas_free=true）

### Step 2.2：注册 precompile 模块到 vm-common/src/lib.rs

**文件**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`

**修改**：在 `pub mod gas;` 与 `pub mod syscall_id;` 之后添加 `pub mod precompile;`

### Step 2.3：创建 zkvm PrecompileCircuitAdapter

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/adapter.rs`

**内容**（约 200 行）：

```rust
//! PrecompileCircuitAdapter — 将 zkvm PrecompileCircuit 适配为
//! vm_common::precompile::PrecompileMetadata 元数据接口。
//!
//! 单向桥接：zkvm 电路 → 链上 PrecompileMetadata。
//! 不实现完整 call() — 链上调用 zkvm 电路仍走 zkvm 自己的 host 执行路径。

use vm_common::precompile::{PrecompileMetadata, precompile_id_from_name};

use crate::ccs::{Ccs, Fr};
use crate::error::ZkvmError;
use crate::precompiles::PrecompileCircuit;

/// 包装 zkvm PrecompileCircuit，实现 PrecompileMetadata。
///
/// 用法：
/// ```ignore
/// let poseidon = PoseidonCircuit::new_mvp();
/// let adapter = PrecompileCircuitAdapter::new(poseidon);
/// let _metadata: &dyn PrecompileMetadata = &adapter;
/// ```
#[derive(Debug)]
pub struct PrecompileCircuitAdapter<T: PrecompileCircuit> {
    circuit: T,
    id_bytes: [u8; 32],
}

impl<T: PrecompileCircuit> PrecompileCircuitAdapter<T> {
    /// 创建 adapter（从 circuit.name() 生成稳定 ID）。
    #[must_use]
    pub fn new(circuit: T) -> Self {
        let name = circuit.name();
        Self {
            circuit,
            id_bytes: precompile_id_from_name(name),
        }
    }

    /// 访问内部电路（用于 host 执行路径调用 build_ccs/assign_witness）。
    pub fn circuit(&self) -> &T {
        &self.circuit
    }

    /// 执行电路（host 路径，不走 PrecompileMetadata 接口）。
    ///
    /// 步骤：
    /// 1. 调用 `assign_witness(inputs)` 得到 witness
    /// 2. 调用 `build_ccs()` 得到 Ccs
    /// 3. 验证 `ccs.satisfied_by(&witness)`
    /// 4. 返回 (Ccs, witness) 供 prover 使用
    pub fn execute(&self, inputs: &[Fr]) -> Result<(Ccs, Vec<Fr>), ZkvmError> {
        let witness = self.circuit.assign_witness(inputs)?;
        let ccs = self.circuit.build_ccs()?;
        if !ccs.satisfied_by(&witness)? {
            return Err(ZkvmError::Other(format!(
                "PrecompileCircuitAdapter: CCS not satisfied for circuit '{}'",
                self.circuit.name()
            )));
        }
        Ok((ccs, witness))
    }
}

impl<T: PrecompileCircuit + Send + Sync> PrecompileMetadata for PrecompileCircuitAdapter<T> {
    fn id_bytes(&self) -> [u8; 32] {
        self.id_bytes
    }
    fn name(&self) -> &str {
        self.circuit.name()
    }
    fn version(&self) -> u32 {
        1
    }
    fn is_gas_free(&self) -> bool {
        false // zkvm 电路按 tx gas 计费，GameTurn 走 poker_l1 GamePrecompile
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::poseidon::PoseidonCircuit;
    use crate::precompiles::sha256::Sha256Circuit;

    #[test]
    fn test_adapter_implements_metadata() {
        let adapter = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        let _: &dyn PrecompileMetadata = &adapter;
        assert_eq!(adapter.name(), "poseidon");
        assert_eq!(adapter.id_bytes()[0], 0xFF);
        assert_eq!(adapter.version(), 1);
        assert!(!adapter.is_gas_free());
    }

    #[test]
    fn test_adapter_id_stable_per_name() {
        let a1 = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        let a2 = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        assert_eq!(a1.id_bytes(), a2.id_bytes());

        let b = PrecompileCircuitAdapter::new(Sha256Circuit::new_mvp());
        assert_ne!(a1.id_bytes(), b.id_bytes());
    }

    #[test]
    fn test_adapter_execute_valid_witness() {
        // 用 Poseidon MVP 电路验证 execute() 返回满足的 CCS
        let adapter = PrecompileCircuitAdapter::new(PoseidonCircuit::new_mvp());
        // Poseidon MVP 接收 2 个 Fr 输入
        let inputs = vec![Fr::one(), Fr::one()];
        let (ccs, witness) = adapter.execute(&inputs).expect("execute 应成功");
        assert!(ccs.satisfied_by(&witness).expect("CCS 应满足"));
    }
}
```

### Step 2.4：注册 adapter 模块到 precompiles/mod.rs

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs`

**修改**：在模块声明区添加 `pub mod adapter;`（建议置于 `pub mod zk_shuffle;` 之后，`use` 之前）

### Step 2.5：回归测试

```bash
cargo build -p vm-common                    # 编译通过
cargo test -p vm-common                     # vm-common 全绿（precompile 模块测试）
cargo test -p poker_zkvm --features test-helpers  # adapter 模块测试 + 全部回归
cargo test -p poker_l1                      # 链上零退化（Precompile trait 未动）
git diff poker_l1/src/vm/contracts/         # 除 mod.rs/types.rs/dispatch.rs/game_precompile.rs 外应为空
git diff poker_zkvm/src/precompiles/        # 仅 mod.rs 与新增 adapter.rs 有变化
```

### Phase 2 验收

- [ ] `vm-common/src/precompile.rs` 完整无截断，6 个测试全绿
- [ ] `vm-common/src/lib.rs` 含 `pub mod precompile;`
- [ ] `poker_zkvm/src/precompiles/adapter.rs` 存在，3 个测试全绿
- [ ] `poker_zkvm/src/precompiles/mod.rs` 含 `pub mod adapter;`
- [ ] 17 个业务合约零修改（git diff 验证）
- [ ] poker_l1 `Precompile` trait 零修改
- [ ] `cargo test --workspace` 全绿

---

## Phase 3：CryptoProvider trait 抽象 + 双实现

**目标**：统一密码学原语接口。利用 poker_l1 已有的 `crypto_precompiles/bls.rs` 抽象层，减少迁移工作量。

**预计工作量**：2-3 天（少于 v2 估算的 3-5 天，因 bls.rs 抽象已存在）

### Step 3.1：定义 CryptoProvider trait

**新建**：`/Users/mac/projects/zchain/vm-common/src/crypto.rs`

**trait 设计**（使用关联类型抽象曲线点）：

```rust
pub trait CryptoProvider: Send + Sync {
    // 哈希（纯函数，无关联类型依赖）
    fn sha256(&self, input: &[u8]) -> [u8; 32];
    fn keccak256(&self, input: &[u8]) -> [u8; 32];
    fn blake2b_256(&self, input: &[u8]) -> [u8; 32];

    // 签名验证（固定返回 bool）
    fn ecdsa_verify_secp256k1(
        &self,
        msg_hash: &[u8; 32],
        signature: &[u8; 65],  // r||s||v
        pubkey: &[u8; 33],     // compressed
    ) -> bool;

    fn ed25519_verify(
        &self,
        msg: &[u8],
        signature: &[u8; 64],
        pubkey: &[u8; 32],
    ) -> bool;

    // BLS12-381（字节级接口，避免暴露曲线点类型）
    fn bls12_381_g1_add(&self, a: &[u8; 48], b: &[u8; 48]) -> Option<[u8; 48]>;
    fn bls12_381_g1_mul(&self, a: &[u8; 48], scalar: &[u8; 32]) -> Option<[u8; 48]>;
    fn bls12_381_g1_neg(&self, a: &[u8; 48]) -> Option<[u8; 48]>;
    fn bls12_381_g2_add(&self, a: &[u8; 96], b: &[u8; 96]) -> Option<[u8; 96]>;
    fn bls12_381_g2_mul(&self, a: &[u8; 96], scalar: &[u8; 32]) -> Option<[u8; 96]>;
    fn bls12_381_g2_neg(&self, a: &[u8; 96]) -> Option<[u8; 96]>;
    fn bls12_381_pairing_check(&self, pairs: &[([u8; 48], [u8; 96])]) -> bool;
    fn bls12_381_hash_to_g1(&self, msg: &[u8], dst: &[u8]) -> Option<[u8; 48]>;
    fn bls12_381_hash_to_g2(&self, msg: &[u8], dst: &[u8]) -> Option<[u8; 96]>;
    fn bls12_381_aggregate_g1(&self, points: &[[u8; 48]]) -> Option<[u8; 48]>;
    fn bls12_381_aggregate_g2(&self, points: &[[u8; 96]]) -> Option<[u8; 96]>;

    // BN254（zkvm 电路用，ark-bn254 实现）
    fn bn254_pairing_check(&self, pairs: &[([u8; 32], [u8; 64])]) -> bool;

    /// Provider 名称（"blstrs" / "arkworks"）。
    fn name(&self) -> &'static str;
}
```

**关键设计**：使用字节级接口（`[u8; 48]` for G1, `[u8; 96]` for G2 compressed）避免关联类型，让 trait object 可用。

### Step 3.2：注册 crypto 模块到 vm-common/src/lib.rs

**修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`，添加 `pub mod crypto;`

### Step 3.3：BlstrsCryptoProvider 实现

**新建**：`/Users/mac/projects/zchain/poker_l1/src/vm/crypto_blstrs.rs`

**实现**：
- `BlstrsCryptoProvider` 结构体（无字段，纯函数式）
- 哈希函数：调用 `sha2::Sha256`、`blake2::Blake2b256` 等
- ECDSA：调用 `secp256k1::Secp256k1`
- Ed25519：调用 `ed25519_dalek`
- BLS12-381：**复用现有 `crypto_precompiles/bls.rs` 的实现**（不重复造轮子）
- BN254：返回 `false` 或 panic（poker_l1 不用 BN254）—— 或返回 `bool` 错误标识

**注意**：`crypto_precompiles/bls.rs` 中已有 G1/G2 add/mul/neg/pairing 等函数，直接转发调用。

### Step 3.4：ArkworksCryptoProvider 实现

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/crypto_arkworks.rs`

**实现**：
- `ArkworksCryptoProvider` 结构体
- 哈希函数：与 BlstrsCryptoProvider 使用相同 `sha2`/`blake2` crate（结果必然一致）
- ECDSA：使用 `secp256k1` crate（与 poker_l1 一致）
- Ed25519：使用 `ed25519_dalek`（与 poker_l1 一致）
- BLS12-381：返回 `None`/`false`（zkvm 不用 BLS12-381，用 BN254）
- BN254：调用 `ark_bn254::Bn254::pairing`

### Step 3.5：注册 crypto_blstrs 到 poker_l1/vm/mod.rs

**修改**：`/Users/mac/projects/zchain/poker_l1/src/vm/mod.rs`，添加 `pub mod crypto_blstrs;`

**修改**：`/Users/mac/projects/zchain/poker_zkvm/src/lib.rs`，添加 `pub mod crypto_arkworks;`

### Step 3.6：一致性测试

**新建**：`/Users/mac/projects/zchain/vm-common/tests/crypto_consistency.rs`

由于 `vm-common` 不依赖 blstrs/arkworks，此测试文件需要在 `poker_l1` 或独立测试 crate 中。**决策**：放在 `poker_l1/tests/crypto_consistency.rs`（poker_l1 依赖 blstrs 和 poker_zkvm，可同时访问两个 provider）。

**测试**：
- `test_sha256_consistency`：同一输入跑两个 provider，断言字节相等
- `test_keccak256_consistency`（如适用）
- `test_blake2b_consistency`
- `test_ecdsa_consistency`：同一签名/公钥/消息，断言 verify 结果一致
- `test_ed25519_consistency`
- BLS12-381 vs BN254 不做等价（不同曲线）

### Step 3.7：回归测试

```bash
cargo test -p vm-common                    # crypto trait 测试
cargo test -p poker_l1                      # BlstrsCryptoProvider + 全回归
cargo test -p poker_zkvm --features test-helpers  # ArkworksCryptoProvider + 全回归
cargo test -p poker_l1 --test crypto_consistency  # 跨实现一致性
```

### Phase 3 验收

- [ ] `vm-common/src/crypto.rs` 定义 `CryptoProvider` trait
- [ ] `poker_l1/src/vm/crypto_blstrs.rs` 实现 `BlstrsCryptoProvider`（复用 bls.rs）
- [ ] `poker_zkvm/src/crypto_arkworks.rs` 实现 `ArkworksCryptoProvider`
- [ ] 一致性测试：sha256/ecdsa/ed25519 两个 provider 结果一致
- [ ] 现有 syscall 调用路径零退化（poker_l1 BLS syscall 仍走 bls.rs）
- [ ] `cargo test --workspace` 全绿

**Phase 3 范围说明**：本阶段**不**改造现有 syscalls 的调用路径（即不改 `poker_l1/src/vm/syscalls.rs` 与 `poker_zkvm/src/syscalls/host.rs` 内部实现）。仅建立 trait + 两个 provider 实现 + 一致性测试。让 syscalls 改走 provider 是未来增量工作，避免一次性大改引入风险。

---

## Phase 4：GasStrategy trait + 双实现

**目标**：形式化 gas 计费策略接口，明确 zkvm 指令级 gas = 0、链上 = 1 的差异。当前 zkvm `execute_elf_with_limits_and_config` 已无 gas 概念（仅 step_limit），本阶段主要建立 trait 与未来接入点。

**预计工作量**：1-2 天

### Step 4.1：定义 GasStrategy trait

**新建**：`/Users/mac/projects/zchain/vm-common/src/gas_strategy.rs`

```rust
//! Gas 计费策略 trait — 跨 VM gas 差异的形式化接口。

use crate::syscall_id::SyscallId;

/// 指令分类（用于 gas 计费抽象）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnCategory {
    Arithmetic,
    Memory,
    ControlFlow,
    Shift,
    Mul,
    Div,
    UpperImm,
    System,
    Other,
}

/// Gas 计费策略。
///
/// - `BpfGasStrategy`（poker_l1）：指令级 + syscall 级 gas 全启用
/// - `ZkvmGasStrategy`（poker_zkvm）：指令级 gas = 0（无 gas 费），仅 step_limit
pub trait GasStrategy: Send + Sync {
    /// 指令级 gas（每条指令）。
    fn instruction_gas(&self, category: InsnCategory) -> u64;

    /// syscall 级 gas（按 SyscallId + 参数）。
    fn syscall_gas(&self, id: SyscallId, args_len: u32) -> u64;

    /// 是否启用指令级 gas 计量。
    fn instruction_meter_enabled(&self) -> bool;

    /// 默认 tx gas 上限。
    fn default_tx_gas_limit(&self) -> u64;

    /// 默认 block gas 上限。
    fn default_block_gas_limit(&self) -> u64;

    /// 策略名称（"bpf" / "zkvm"）。
    fn name(&self) -> &'static str;
}
```

### Step 4.2：注册 gas_strategy 模块

**修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`，添加 `pub mod gas_strategy;`

### Step 4.3：BpfGasStrategy 实现

**新建**：`/Users/mac/projects/zchain/poker_l1/src/vm/gas_strategy.rs`

```rust
use vm_common::gas_strategy::{GasStrategy, InsnCategory};
use vm_common::gas;
use vm_common::syscall_id::SyscallId;

/// poker_l1 链上 BPF gas 策略。
///
/// 完整计费：指令级 1 gas/条 + syscall 级按 gas_table 计费。
pub struct BpfGasStrategy;

impl GasStrategy for BpfGasStrategy {
    fn instruction_gas(&self, category: InsnCategory) -> u64 {
        match category {
            InsnCategory::Arithmetic | InsnCategory::UpperImm | InsnCategory::Other => 1,
            InsnCategory::Memory => gas::GAS_MEMORY_BASE,
            InsnCategory::ControlFlow | InsnCategory::System => gas::GAS_BRANCH,
            InsnCategory::Shift => 2,
            InsnCategory::Mul => 20,
            InsnCategory::Div => 20,
        }
    }
    fn syscall_gas(&self, id: SyscallId, args_len: u32) -> u64 {
        // 委托给 vm_common::gas 中的 syscall_gas 函数
        // （需要 SyscallGasArgs，简化版按 args_len 估算）
        match id {
            SyscallId::ObjectRead => gas::object_read_gas(args_len as u64),
            SyscallId::ObjectWrite => gas::object_write_gas(args_len as u64),
            SyscallId::ObjectCreate => gas::object_create_gas(args_len as u64),
            SyscallId::EmitEvent => gas::emit_event_gas(args_len as u64),
            SyscallId::VerifySignature => gas::GAS_SECP256K1_VERIFY,
            SyscallId::ZkVerify => gas::zk_verify_gas(0),
            // ... 其余按 vm_common::gas 常量返回
            _ => 0,
        }
    }
    fn instruction_meter_enabled(&self) -> bool { true }
    fn default_tx_gas_limit(&self) -> u64 { gas::TX_GAS_LIMIT }
    fn default_block_gas_limit(&self) -> u64 { gas::BLOCK_GAS_LIMIT }
    fn name(&self) -> &'static str { "bpf" }
}
```

### Step 4.4：ZkvmGasStrategy 实现

**新建**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas_strategy.rs`

```rust
use vm_common::gas_strategy::{GasStrategy, InsnCategory};
use vm_common::syscall_id::SyscallId;

/// poker_zkvm 链下 ZK VM gas 策略。
///
/// **无 gas 费**：所有 instruction_gas 返回 0，instruction_meter_enabled = false。
/// 仅 step_limit（执行步数上限）约束执行。
pub struct ZkvmGasStrategy;

impl GasStrategy for ZkvmGasStrategy {
    fn instruction_gas(&self, _category: InsnCategory) -> u64 { 0 }
    fn syscall_gas(&self, _id: SyscallId, _args_len: u32) -> u64 { 0 }
    fn instruction_meter_enabled(&self) -> bool { false }
    fn default_tx_gas_limit(&self) -> u64 { 0 }
    fn default_block_gas_limit(&self) -> u64 { 0 }
    fn name(&self) -> &'static str { "zkvm" }
}
```

### Step 4.5：注册 gas_strategy 模块

**修改**：`/Users/mac/projects/zchain/poker_l1/src/vm/mod.rs`，添加 `pub mod gas_strategy;`

**修改**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs`，添加 `pub mod gas_strategy;`

### Step 4.6：vm-common 跨实现测试

**新建**：`/Users/mac/projects/zchain/vm-common/tests/gas_strategy.rs`

```rust
#[test]
fn test_bpf_strategy() {
    let s = BpfGasStrategy;
    assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), 1);
    assert!(s.instruction_meter_enabled());
    assert_eq!(s.default_tx_gas_limit(), 10_000_000);
}

#[test]
fn test_zkvm_strategy_no_gas() {
    let s = ZkvmGasStrategy;
    assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), 0);
    assert_eq!(s.instruction_gas(InsnCategory::Mul), 0);
    assert!(!s.instruction_meter_enabled());
    assert_eq!(s.default_tx_gas_limit(), 0);
}
```

**注意**：由于 vm-common 不依赖 poker_l1/poker_zkvm，跨实现测试需放在 `poker_l1/tests/gas_strategy_consistency.rs`（依赖两者）。

### Step 4.7：回归测试

```bash
cargo test -p vm-common                    # GasStrategy trait 测试
cargo test -p poker_l1                      # BpfGasStrategy + GameTurn gas-free 路径未变
cargo test -p poker_zkvm --features test-helpers  # ZkvmGasStrategy + 全回归
```

### Phase 4 验收

- [ ] `vm-common/src/gas_strategy.rs` 定义 trait + InsnCategory
- [ ] `poker_l1/src/vm/gas_strategy.rs` 实现 `BpfGasStrategy`
- [ ] `poker_zkvm/src/syscalls/gas_strategy.rs` 实现 `ZkvmGasStrategy`（全 0）
- [ ] zkvm 指令级 gas = 0（验证 `ZkvmGasStrategy::instruction_gas(any) == 0`）
- [ ] poker_l1 GameTurn gas-free lane 路径零修改
- [ ] `cargo test --workspace` 全绿

**Phase 4 范围说明**：本阶段**不**改造 `PokerL1Context::new` 或 `execute_elf_with_limits_and_config` 签名以接收 `&dyn GasStrategy`。仅建立 trait + 两个实现 + 跨实现测试。让现有 executor 改用 GasStrategy trait 是未来增量工作，避免一次性大改破坏 GameTurn gas-free 硬约束。这样 Phase 4 是非侵入式的形式化层。

---

## Phase 5：ABI 文档与治理收尾

**目标**：固化统一 ABI 文档，更新 spec.md 非 FROZEN 部分与 project_memory.md。

**预计工作量**：0.5-1 天

### Step 5.1：ABI 文档完善

**修改**：`/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`
- 为每个 `SyscallId` 变体添加 doc-comment（含 ID 值、用途、所属 VM）
- 运行 `cargo doc -p vm-common --no-deps` 生成文档验证

### Step 5.2：架构文档

**新建**：`/Users/mac/projects/zchain/vm-common/ARCHITECTURE.md`

内容：
- vm-common 架构图（5 大模块：gas/syscall_id/precompile/crypto/gas_strategy）
- 依赖边界图（vm-common 不依赖 solana_rbpf/arkworks）
- Phase 1-5 实施摘要
- 与 poker_l1/poker_zkvm 的关系图
- 关键设计决策（PrecompileMetadata 单向桥接、CryptoProvider 字节级接口、GasStrategy 形式化层）

### Step 5.3：更新 project_memory.md

**修改**：`/Users/mac/.trae-cn/memory/projects/-Users-mac-projects-zchain/project_memory.md`

新增条目（Engineering Conventions 节）：
- `vm-common` crate 是跨 VM 共享横切关注点的单一事实源（gas/syscall_id/precompile/crypto/gas_strategy）
- `vm-common` 严格 `#![deny(unsafe_code)]`，不依赖 solana_rbpf 或 arkworks
- `PrecompileMetadata` 是跨 VM 预编译元数据接口（字节级 ID），完整 `call()` 统一推迟
- `CryptoProvider` trait 使用字节级接口（`[u8; 48]` G1 / `[u8; 96]` G2）避免关联类型
- 业务 BLS 用 blstrs（poker_l1），zkvm 电路用 ark-bn254（poker_zkvm），双库共存
- `GasStrategy` trait 形式化跨 VM gas 差异；zkvm 指令级 gas = 0
- 业务合约（17 个）+ Hypernova/CCS/constraints/prover 全程零修改

### Step 5.4：最终端到端验证

```bash
cargo build --workspace                    # 编译通过
cargo test --workspace                     # 全绿
cargo tree -p vm-common                    # 应只有 thiserror，无 solana_rbpf/arkworks
rg "GAS_ZKVM_ECDSA_VERIFY" --type rust     # 应只在 vm-common/src/gas.rs 定义
git diff poker_l1/src/vm/contracts/        # 应为空（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs）
git diff poker_zkvm/src/constraints/       # 应为空
git diff poker_zkvm/src/hypernova/         # 应为空
```

### Phase 5 验收

- [ ] ABI 文档完整（每个 SyscallId 变体有 doc-comment）
- [ ] `vm-common/ARCHITECTURE.md` 创建
- [ ] `project_memory.md` 增加 7 条新工程约定
- [ ] 端到端 `cargo test --workspace` 全绿
- [ ] git diff 验证零修改区域确实未动

---

## 关键文件清单

### Phase 2 修复与新建（4 个）
- **修复**：`/Users/mac/projects/zchain/vm-common/src/precompile.rs`（截断→完整）
- **修改**：`/Users/mac/projects/zchain/vm-common/src/lib.rs`（加 `pub mod precompile;`）
- **新建**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/adapter.rs`（PrecompileCircuitAdapter）
- **修改**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs`（加 `pub mod adapter;`）

### Phase 3 新建（3 个 + 1 个测试）
- `/Users/mac/projects/zchain/vm-common/src/crypto.rs`（CryptoProvider trait）
- `/Users/mac/projects/zchain/poker_l1/src/vm/crypto_blstrs.rs`（BlstrsCryptoProvider）
- `/Users/mac/projects/zchain/poker_zkvm/src/crypto_arkworks.rs`（ArkworksCryptoProvider）
- `/Users/mac/projects/zchain/poker_l1/tests/crypto_consistency.rs`（一致性测试）

### Phase 4 新建（3 个 + 1 个测试）
- `/Users/mac/projects/zchain/vm-common/src/gas_strategy.rs`（GasStrategy trait）
- `/Users/mac/projects/zchain/poker_l1/src/vm/gas_strategy.rs`（BpfGasStrategy）
- `/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas_strategy.rs`（ZkvmGasStrategy）
- `/Users/mac/projects/zchain/poker_l1/tests/gas_strategy_consistency.rs`（跨实现测试）

### Phase 5 文档（2 个 + 1 个修改）
- `/Users/mac/projects/zchain/vm-common/ARCHITECTURE.md`（新建）
- `/Users/mac/.trae-cn/memory/projects/-Users-mac-projects-zchain/project_memory.md`（追加）
- `/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`（doc-comment 完善）

### 修改文件汇总（4 个 Cargo.toml/mod.rs）
- `/Users/mac/projects/zchain/vm-common/src/lib.rs`（加 3 个 `pub mod`）
- `/Users/mac/projects/zchain/poker_l1/src/vm/mod.rs`（加 2 个 `pub mod`）
- `/Users/mac/projects/zchain/poker_zkvm/src/lib.rs`（加 1 个 `pub mod`）
- `/Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs`（加 1 个 `pub mod`）
- `/Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs`（加 1 个 `pub mod`）

### 零修改区域（硬约束）
- `poker_l1/src/vm/contracts/*.rs`（除 mod.rs/types.rs/dispatch.rs/game_precompile.rs）
- `poker_l1/src/vm/precompile.rs`（完整 Precompile trait 保持原状）
- `poker_l1/src/vm/syscalls.rs`（BLS syscall 调用路径不改）
- `poker_l1/src/vm/context.rs`（PokerL1Context 签名不改）
- `poker_l1/src/executor.rs`（GameTurn gas-free lane）
- `poker_zkvm/src/constraints/*`
- `poker_zkvm/src/hypernova/*`
- `poker_zkvm/src/fold/*`
- `poker_zkvm/src/prover/*`
- `poker_zkvm/src/recursion/*`
- `poker_zkvm/src/isa/*`（RV32I 引擎）
- `poker_zkvm/src/precompiles/*.rs`（9 个电路实现，仅 mod.rs 加 adapter 模块声明）
- `poker_zkvm/src/syscalls/host.rs`（host syscall 实现不改）

---

## 与 v2 计划的差异

| 项 | v2 计划 | 本续作计划 | 理由 |
|---|---|---|---|
| Phase 2 Precompile trait 迁移 | 方案 2.1A（关联类型） | PrecompileMetadata 最小元数据 trait | 2.1A 会破坏 17 业务合约零修改硬约束 |
| Phase 3 工作量 | 3-5 天 | 2-3 天 | poker_l1 已有 `crypto_precompiles/bls.rs` 抽象层可复用 |
| Phase 3 syscall 改造 | 改 syscalls.rs 走 CryptoProvider | **不改**，仅建立 trait + 双实现 + 一致性测试 | 避免一次性大改引入风险，syscall 改造推迟到增量工作 |
| Phase 4 executor 接入 | 改 PokerL1Context::new 与 execute_elf_with_limits_and_config 签名 | **不改**，仅建立 trait + 双实现 + 跨实现测试 | 避免破坏 GameTurn gas-free 硬约束，executor 接入推迟到增量工作 |
| Phase 4 工作量 | 2-3 天 | 1-2 天 | 不接入 executor，仅形式化层 |

**核心理念**：本续作计划是"非侵入式形式化层"——建立 5 大 trait/常量/枚举的单一事实源，但**不强制改造现有调用路径**。让现有 syscalls/executors 改用新 trait 是未来增量工作，每步可独立验证可回退。这降低了引入回归的风险，同时已建立统一 ABI 与未来演进基础。

---

## 风险与缓解

| 风险 | 等级 | 缓解 |
|---|---|---|
| precompile.rs 截断修复后测试不通过 | 低 | 保留已有正确部分，仅补全截断的 1 个测试 |
| PrecompileCircuitAdapter::execute() 与现有 host 执行结果不一致 | 中 | adapter 测试覆盖 Poseidon MVP 电路，对比 CCS satisfied_by |
| CryptoProvider 字节级接口性能损失（序列化开销） | 低 | Phase 3 不改造现有 syscall 调用路径，无运行时影响 |
| GasStrategy trait 建立但未接入 executor 成为 dead code | 中 | 文档明确"形式化层，未来接入"，并在 ARCHITECTURE.md 标注演进路径 |
| BLS12-381 与 BN254 双库共存导致依赖膨胀 | 低 | 已共存（poker_l1 blstrs + poker_zkvm ark-bn254），不增加新依赖 |
| Phase 5 project_memory.md 修改覆盖既有内容 | 低 | 使用 Edit 工具追加，不重写整个文件 |

---

## 总结

本续作计划从 Phase 2 半成品状态接续，5 阶段总计 5-9 天工作量。核心策略是**非侵入式形式化层**：

1. **Phase 2**（1-2 天）：修复截断的 precompile.rs，创建 zkvm adapter，建立 PrecompileMetadata 单向桥接
2. **Phase 3**（2-3 天）：建立 CryptoProvider trait + 双实现 + 一致性测试，**不改现有 syscall 调用路径**
3. **Phase 4**（1-2 天）：建立 GasStrategy trait + 双实现（zkvm 全 0）+ 跨实现测试，**不改 executor 签名**
4. **Phase 5**（0.5-1 天）：ABI 文档 + ARCHITECTURE.md + project_memory.md 更新

业务合约、约束系统、Hypernova/prover/recursion、GameTurn gas-free lane 全程零修改。每阶段独立可回退，每阶段完成立即跑测试。
