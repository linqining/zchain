# VM 统一架构方案（方案 B：抽象共用层）

## Context（背景与动机）

zchain 当前存在两套独立 VM：

| 维度 | `poker_l1/src/vm/`（链上） | `poker_zkvm/`（链下 ZK） |
|---|---|---|
| ISA | BPF/SBF（64-bit，11 寄存器） | RV32I（32-bit，32 寄存器） |
| 引擎 | `solana_rbpf 0.8`（外部库） | 自研 `isa/executor.rs` |
| Gas | 指令级 `consume(1)` + syscall 级 `gas_table.rs` | 仅 syscall 级 `syscalls/gas.rs` |
| Syscall | 23 个（object_*、emit_event、verify_signature、bls12_381_*、zk_verify 等） | 15 个（read_input、commit_output、sha256、poseidon、ecdsa_verify 等） |
| Precompile | `Precompile` trait（运行时合约，方法 `id/version/call/supports_selector`） | `PrecompileCircuit` trait（CCS 电路，方法 `build_ccs/assign_witness/gas_cost`） |
| 状态 | `PokerL1Context`（有状态，object_cache） | `ZkvmHostState` trait（无状态，host 函数） |
| 约束系统 | 无 | `constraints/mod.rs` 49 矩阵 93 subsets，**与 RV32I 35 类指令强耦合** |
| 安全基线 | `solana_rbpf::RequisiteVerifier`（IMPL-SEC-4 (1) 强制） | `#![deny(unsafe_code)]` |
| 底层 crypto | blstrs（BLS12-381） | ark-bn254（arkworks） |

**核心矛盾**：用户希望"共用一个 VM 执行引擎（如 solana_rbpf）"，但 zkvm 约束系统与 RV32I 强绑定（49 CCS 矩阵 × 35 指令类别），换 ISA 等于重写约 7K LoC 约束代码 + 5K LoC Hypernova 折叠代码 + 1.5K LoC trace 系统。64-bit BPF 在 254-bit Fr 域上约束代价还会膨胀 3-5 倍（性能下降 5-10 倍）。

**已选方案**：B（抽象共用层）—— 承认"约束系统与 ISA 强绑定"是物理事实，不强求统一引擎，而是抽出真正可复用的横切关注点（precompile/gas/syscall_id/crypto/gas_strategy）放到新的 `vm-common` crate，让两套 VM 共用周边生态。这与项目记忆中"先保守重构再激进优化"、"简单方案胜过复杂方案"、"分阶段实施"完美兼容。

**预期收益**：
- 17 个业务合约零修改（约 9.5K LoC 保留）
- 9 个 precompile 电路零修改（约 13K LoC 保留）
- 约束系统零修改（约 7K LoC 保留）
- Hypernova + CCS + IPA + Groth16 stack 零修改
- spec FROZEN 状态不破坏
- 业务合约与 ZK 电路通过统一 `Precompile` trait 可互调

**未来演进**：阶段 1-2 完成后，若仍需真正统一引擎，可在 `vm-common` 基础上降级方案 C 的工作量（ABI 与 precompile 已统一）。

---

## 总体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                      vm-common (新 crate)                        │
│  ┌──────────┬──────────┬──────────┬──────────┬───────────────┐  │
│  │   gas    │ syscall  │ precompile│ crypto   │ gas_strategy  │  │
│  │ constants│  _id     │  trait +  │ Provider │  trait        │  │
│  │ (single  │ (unified │ Registry +│  trait   │ (Bpf/Zkvm)    │  │
│  │  source) │  enum)   │ timelock  │          │               │  │
│  └──────────┴──────────┴──────────┴──────────┴───────────────┘  │
└─────────────────────────────────────────────────────────────────┘
           ▲                                    ▲
           │                                    │
           │ 依赖                                │ 依赖
           │                                    │
┌──────────┴─────────────────┐  ┌──────────────┴────────────────┐
│   poker_l1/src/vm/         │  │   poker_zkvm/                  │
│  ┌─────────────────────┐   │  │  ┌─────────────────────────┐  │
│  │ solana_rbpf engine  │   │  │  │ RV32I engine (保留)      │  │
│  │ + BpfGasStrategy    │   │  │  │ + ZkvmGasStrategy        │  │
│  │ + 23 syscalls       │   │  │  │ + 15 syscalls            │  │
│  │ + blstrs BLS12-381  │   │  │  │ + ark-bn254 约束电路     │  │
│  │   CryptoProvider    │   │  │  │   CryptoProvider         │  │
│  └─────────────────────┘   │  │  └─────────────────────────┘  │
│  ┌─────────────────────┐   │  │  ┌─────────────────────────┐  │
│  │ 业务合约 17 个      │   │  │  │ PrecompileCircuit 9 个   │  │
│  │ (impl Precompile)   │   │  │  │ + Adapter → Precompile   │  │
│  └─────────────────────┘   │  │  └─────────────────────────┘  │
└───────────────────────────┘  └───────────────────────────────┘
```

---

## 阶段 0：测试基线（1 周）

**目标**：固化现有行为，确保后续重构有可对比基线。

### 步骤
1. 跑通 `cargo test -p poker_l1`（vm 模块全部测试）
2. 跑通 `cargo test -p poker_zkvm`（isa + syscalls + precompiles 测试）
3. 跑通 `cargo test --workspace`
4. 用 `insta` snapshot 测试固化 23 + 15 个 syscall 的 ABI 契约：
   - 新建 `poker_l1/tests/syscall_abi_snapshot.rs`：对每个 syscall 用固定输入跑一遍，记录输出
   - 新建 `poker_zkvm/tests/syscall_abi_snapshot.rs`：同上
5. 输出基线测试报告（通过测试数、覆盖率、关键路径列表）

### 验收
- 所有现有测试通过
- snapshot 文件已提交，作为后续阶段回归基线

---

## 阶段 1：`vm-common` crate 骨架（2-3 周）

**目标**：新建共享 crate，迁移 gas 常量与 syscall_id，建立单一事实源。

### 步骤

#### 1.1 新建 crate
- 创建 `/Users/mac/projects/zchain/vm-common/Cargo.toml`：
  ```toml
  [package]
  name = "vm-common"
  version = "0.1.0"
  edition = "2024"

  [dependencies]
  thiserror = { workspace = true }
  serde = { workspace = true }
  # 注意：vm-common 不依赖 solana_rbpf 也不依赖 arkworks
  # 所有外部依赖通过 trait 抽象，避免成为 god-crate
  ```
- 创建 `/Users/mac/projects/zchain/vm-common/src/lib.rs`：声明子模块
- 修改 `/Users/mac/projects/zchain/Cargo.toml`：workspace members 加 `"vm-common"`

#### 1.2 迁移 gas 常量
- 新建 `vm-common/src/gas.rs`
- 从 `poker_l1/src/vm/gas_table.rs` 迁移**非 BPF 专有**的常量（如 `GAS_BLS12_381_G1_ADD`、`GAS_OBJECT_READ_BASE`、`GAS_ZKVM_*` re-export）
- 从 `poker_zkvm/src/syscalls/gas.rs` 迁移 syscall 级常量（`GAS_ZKVM_ECDSA_VERIFY`、`GAS_ZKVM_POSEIDON` 等）
- 保留各自 crate 内的 **ISA 专有**常量（BPF 指令级 gas 留在 poker_l1；RV32I 指令级 gas 留在 poker_zkvm）
- 修改 `poker_l1/src/vm/gas_table.rs:117` 的 re-export：改为 `pub use vm_common::gas::*;`
- 修改 `poker_zkvm/src/syscalls/gas.rs`：常量改为 `pub use vm_common::gas::*;` 的 re-export

#### 1.3 统一 SyscallId 枚举
- 新建 `vm-common/src/syscall_id.rs`
- 定义统一 `SyscallId` 枚举，分段：
  - `0x00-0x3F`：链上链下共用（sha256=0x04、poseidon、ecdsa_verify、keccak256、ed25519_verify、emit_event、log、panic 等 8 个重叠）
  - `0x40-0x5F`：poker_l1 专属（object_read=0x40、object_write、object_create、get_block_height、get_timestamp、verify_signature、verify_failure_proof、zk_verify 等）
  - `0x60-0x7F`：poker_zkvm 专属（read_input=0x60、commit_output、merkle_verify、modexp、bn254_pairing、bn254_ops、bit_ops、chaum_pedersen、dleq、elgamal 等）
  - `0x80-0xFF`：BLS12-381 系列（poker_l1 现有 12 个 bls12_381_* 保留原 ID 段）
- 提供 `SyscallId::from_u32(id) -> Option<Self>` 与 `as_u32(&self) -> u32`
- poker_l1 与 poker_zkvm 各自保留现有的 syscall 注册机制（不强制改 ID），但新加 syscall 必须用统一枚举

#### 1.4 依赖接入
- 修改 `poker_l1/Cargo.toml`：加 `vm-common = { path = "../vm-common" }`
- 修改 `poker_zkvm/Cargo.toml`：加 `vm-common = { path = "../vm-common" }`
- 修改 `poker_l1/src/offline/ccs.rs:25-33`：部分 re-export 改为从 `vm_common` 直接引

### 验收
- `cargo build --workspace` 通过
- `cargo test --workspace` 全绿（snapshot 测试通过）
- `gas_table.rs` 与 `poker_zkvm/syscalls/gas.rs` 中已无重复常量定义
- `vm-common` crate 不依赖 `solana_rbpf` 或 `arkworks`（验证 `cargo tree -p vm-common`）

---

## 阶段 2：Precompile trait 上移 + 单向 adapter 桥接（2-3 周）

**目标**：统一 precompile 接口，让 zkvm 电路可作为链上 precompile 调用，业务合约零修改。

### 步骤

#### 2.1 迁移 Precompile trait
- 新建 `vm-common/src/precompile.rs`
- 从 `poker_l1/src/vm/precompile.rs` 迁移以下到 `vm-common`：
  - `Precompile` trait（方法：`id()`、`version()`、`call()`、`supports_selector()`、`is_gas_free()`）
  - `PrecompileRegistry`（含热插拔注册、版本管理、治理 timelock=7200 blocks）
  - `DispatchResult`、`ExecutionEnvironment`、`PrecompileStatus`、`PrecompileVersion` 等类型
  - 保留 `0xFF` 前缀的 reserved ObjectID namespace 常量
- 修改 `poker_l1/src/vm/precompile.rs`：内容改为 `pub use vm_common::precompile::*;` alias（保持外部 API 兼容）
- 17 个业务合约（`poker_l1/src/vm/contracts/*.rs`）**零修改**（仍通过 `use crate::vm::precompile::Precompile` 引入）

#### 2.2 zkvm PrecompileCircuit adapter
- 在 `poker_zkvm/src/precompiles/mod.rs` 新增 `PrecompileCircuitAdapter<T: PrecompileCircuit>` 包装器
- 为 9 个 `PrecompileCircuit` 实现自动生成 `vm_common::precompile::Precompile`：
  ```rust
  impl<T: PrecompileCircuit> Precompile for PrecompileCircuitAdapter<T> {
      fn id(&self) -> ObjectID { /* 从 PrecompileCircuit::id() 映射 */ }
      fn version(&self) -> u32 { /* 从 PrecompileCircuit::version() 映射 */ }
      fn call(&self, caller, pubkey, selector, args, env, object_db) -> Result<DispatchResult> {
          // 1. 在 host 侧执行 PrecompileCircuit::host_execute(args) 得到结果
          // 2. 同时调用 build_ccs + assign_witness 生成 CCS 实例（供证明）
          // 3. 返回 DispatchResult { return_data, created_objects, ccs_instance, ... }
      }
      fn supports_selector(&self, s: &[u8; 32]) -> bool { /* 转发 */ }
      fn is_gas_free(&self) -> bool { false /* zkvm precompile 不是 gas-free */ }
  }
  ```
- **单向桥接**：zkvm 电路 → 链上 Precompile 接口可调用；不强制链上业务合约实现 CCS 接口

#### 2.3 共享 PrecompileRegistry
- zkvm 启动时通过 `PrecompileCircuitAdapter::new(circuit)` 包装 9 个电路并注册到 `PrecompileRegistry`
- poker_l1 启动时直接注册 17 个业务合约到同一 `PrecompileRegistry`
- 治理升级流程（`poker_l1/src/vm/upgrade.rs`）保持不变，复用 `vm-common` 的 timelock 机制

#### 2.4 测试
- 业务合约测试全绿（无修改）
- 新增 `vm-common/tests/precompile_adapter.rs`：测试 `PrecompileCircuitAdapter` 的 `call()` 返回正确结果且生成有效 CCS 实例
- 新增 `vm-common/tests/registry_unified.rs`：测试同一 registry 可同时容纳链上业务合约与 zkvm 电路

### 验收
- `cargo test --workspace` 全绿
- 17 个业务合约无修改（`git diff poker_l1/src/vm/contracts/` 应为空）
- zkvm 9 个电路通过 adapter 可作为 `Precompile` 调用

---

## 阶段 3：CryptoProvider 抽象（2-3 周）

**目标**：统一密码学原语接口，按用户决策**业务相关 BLS 用 bls12-381（blstrs），zkvm 电路约束用 ark-bn254（arkworks）**，不强行收敛底层库。

### 步骤

#### 3.1 定义 CryptoProvider trait
- 新建 `vm-common/src/crypto.rs`
- 定义 `CryptoProvider` trait（关联类型 + 方法）：
  ```rust
  pub trait CryptoProvider: Send + Sync {
      type G1; // blstrs::G1Projective 或 ark_bn254::G1Projective
      type G2;
      type Scalar; // blstrs::Scalar 或 ark_bn254::Fr

      // 哈希
      fn sha256(data: &[u8]) -> [u8; 32];
      fn keccak256(data: &[u8]) -> [u8; 32];
      fn poseidon(inputs: &[Self::Scalar]) -> Self::Scalar;
      fn blake2b_256(data: &[u8]) -> [u8; 32];

      // 签名验证
      fn ecdsa_verify_secp256k1(msg_hash: &[u8; 32], sig: &[u8; 64], pubkey: &[u8; 33]) -> bool;
      fn ed25519_verify(msg: &[u8], sig: &[u8; 64], pubkey: &[u8; 32]) -> bool;

      // BLS12-381（业务相关，poker_l1 用 blstrs，zkvm 电路内用 ark-bn254 的等价实现）
      fn bls12_381_g1_add(a: &Self::G1, b: &Self::G1) -> Self::G1;
      fn bls12_381_g1_mul(p: &Self::G1, s: &Self::Scalar) -> Self::G1;
      fn bls12_381_pairing_check(g1: &[Self::G1], g2: &[Self::G2]) -> bool;
      // ... 其余 BLS12-381 操作

      // BN254（zkvm 电路约束专用，poker_l1 不实现）
      fn bn254_pairing_check(g1: &[Self::G1], g2: &[Self::G2]) -> bool;
      // ...
  }
  ```

#### 3.2 双实现 + feature flag
- `vm-common` 不提供默认实现，仅定义 trait
- 在 `poker_l1/src/vm/crypto_blstrs.rs` 新建 `BlstrsCryptoProvider` 实现 `CryptoProvider`（G1 = blstrs::G1Projective）
- 在 `poker_zkvm/src/crypto_arkworks.rs` 新建 `ArkworksCryptoProvider` 实现 `CryptoProvider`（G1 = ark_bn254::G1Projective）
- poker_l1 的 `syscalls.rs` 中 12 个 bls12_381_* syscall 改走 `BlstrsCryptoProvider`（替换直接 `blstrs::G1Projective` 调用）
- poker_zkvm 的 `syscalls/host.rs` 中 sha256/poseidon/ecdsa_verify 改走 `ArkworksCryptoProvider`

#### 3.3 验证一致性
- 新增 `vm-common/tests/crypto_consistency.rs`：对同一输入跑 `BlstrsCryptoProvider::sha256` 与 `ArkworksCryptoProvider::sha256`，断言结果一致
- BLS12-381 与 BN254 是不同曲线，不做等价断言；但确保业务 BLS 操作（链上 validator 聚合签名）仍用 bls12-381（blstrs），zkvm 电路内 BLS 验证用 ark-bn254 的等价群操作

#### 3.4 测试
- poker_l1 现有 BLS syscall 测试全绿
- poker_zkvm 现有 sha256/poseidon/ecdsa 测试全绿
- 新增 cross-impl 一致性测试通过

### 验收
- `cargo test --workspace` 全绿
- poker_l1 的 `syscalls.rs` 中无直接 `blstrs::` 调用（全部走 `BlstrsCryptoProvider`）
- poker_zkvm 的 `host.rs` 中无直接 `ark_bn254::` 调用（全部走 `ArkworksCryptoProvider`）
- 业务相关的 BLS12-381 操作仍用 blstrs（不强行收敛为 ark-bn254）

---

## 阶段 4：GasStrategy trait（1-2 周）

**目标**：gas 计费策略差异化，zkvm 指令级 gas 返回 0，链上保持完整计费。

### 步骤

#### 4.1 定义 GasStrategy trait
- 新建 `vm-common/src/gas_strategy.rs`
- 定义 trait：
  ```rust
  pub trait GasStrategy: Send + Sync {
      /// 指令级 gas（BPF 指令 / RV32I 指令）
      fn instruction_gas(&self, insn_category: InsnCategory) -> u64;

      /// syscall 级 gas
      fn syscall_gas(&self, id: SyscallId, args_len: usize) -> u64;

      /// 是否启用指令级 gas 计费
      fn instruction_meter_enabled(&self) -> bool;

      /// 默认 gas limit
      fn default_tx_gas_limit(&self) -> u64;
      fn default_block_gas_limit(&self) -> u64;
  }

  pub enum InsnCategory {
      Arithmetic,
      Memory,
      ControlFlow,
      Syscall,
      Other,
  }
  ```

#### 4.2 双实现
- 在 `poker_l1/src/vm/gas_strategy.rs` 实现 `BpfGasStrategy`：
  - `instruction_gas` 返回 1（每条 BPF 指令 consume(1)）
  - `instruction_meter_enabled` = true
  - `syscall_gas` 调用 `vm_common::gas` 常量
  - `default_tx_gas_limit` = `TX_GAS_LIMIT`（10M）
- 在 `poker_zkvm/src/syscalls/gas_strategy.rs` 实现 `ZkvmGasStrategy`：
  - `instruction_gas` 返回 0（**zkvm 无 gas**）
  - `instruction_meter_enabled` = false
  - `syscall_gas` 调用 `vm_common::gas` 常量
  - `default_tx_gas_limit` = 0 或 `u64::MAX`（zkvm 不限制）

#### 4.3 GameTurn gas-free 保持不变
- **重要**：`poker_l1/src/executor.rs:186-302` 的 GameTurn/CheckpointAnchor lane 逻辑完全不动
- gas-free 由 `TxLane::GameTurn` + `Precompile::is_gas_free()` 双重判断，与 `GasStrategy` 无关
- `GasStrategy` 仅作用于"走 rBPF 执行的合约"，不影响"直接派发的 precompile"

#### 4.4 接入
- `poker_l1/src/vm/context.rs` 的 `PokerL1Context::new` 改为接收 `&dyn GasStrategy`（或泛型）
- `poker_zkvm/src/isa/executor.rs` 的 `execute_elf_with_limits_and_config` 改为接收 `&dyn GasStrategy`
- 现有 gas_table.rs 中 ISA 专有的 BPF 指令级常量（如 `GAS_INSN_*`）保留在 poker_l1 本地，由 `BpfGasStrategy` 内部使用

#### 4.5 测试
- poker_l1 现有 gas 计费测试全绿（`test_execute_out_of_gas` 等）
- poker_zkvm 现有 syscall gas 测试全绿
- 新增 `vm-common/tests/gas_strategy.rs`：验证 `ZkvmGasStrategy::instruction_gas(any) == 0`

### 验收
- `cargo test --workspace` 全绿
- zkvm 指令级 gas = 0（验证 `ZkvmGasStrategy::instruction_gas(InsnCategory::Arithmetic) == 0`）
- 链上 GameTurn gas-free 路径未变（执行 `cargo test -p poker_l1 test_gameturn_gas_free`）

---

## 阶段 5：ABI 文档与治理收尾（1 周）

**目标**：固化统一 ABI 文档，更新 spec.md 非 FROZEN 部分。

### 步骤

1. 在 `vm-common/src/syscall_id.rs` 中为每个 `SyscallId` 变体添加 doc-comment，记录 ABI 契约（输入寄存器/内存布局、输出布局、gas 计费规则）
2. 生成 `cargo doc -p vm-common --open`，输出 ABI 文档
3. 更新 `/Users/mac/projects/zchain/poker_zkvm/docs/38-3-zkvm-syscall-reference.md`：引用 `vm-common::syscall_id` 作为单一事实源
4. 更新 spec.md（**非 FROZEN 部分**）：记录 vm-common 架构、阶段实施摘要、未来演进路径
5. 输出最终架构图（mermaid），存入 `vm-common/ARCHITECTURE.md`
6. 更新 `/Users/mac/.trae-cn/memory/projects/-Users-mac-projects-zchain/project_memory.md`：增加 vm-common 相关工程约定

### 验收
- ABI 文档完整生成
- spec.md 非 FROZEN 部分更新
- project_memory.md 增加新约定

---

## 关键文件清单

### 新建
- `/Users/mac/projects/zchain/vm-common/Cargo.toml`
- `/Users/mac/projects/zchain/vm-common/src/lib.rs`
- `/Users/mac/projects/zchain/vm-common/src/gas.rs`（gas 常量单一事实源）
- `/Users/mac/projects/zchain/vm-common/src/syscall_id.rs`（统一 SyscallId 枚举）
- `/Users/mac/projects/zchain/vm-common/src/precompile.rs`（Precompile trait + Registry）
- `/Users/mac/projects/zchain/vm-common/src/crypto.rs`（CryptoProvider trait）
- `/Users/mac/projects/zchain/vm-common/src/gas_strategy.rs`（GasStrategy trait）
- `/Users/mac/projects/zchain/vm-common/ARCHITECTURE.md`
- `/Users/mac/projects/zchain/poker_l1/src/vm/crypto_blstrs.rs`（BlstrsCryptoProvider 实现）
- `/Users/mac/projects/zchain/poker_l1/src/vm/gas_strategy.rs`（BpfGasStrategy 实现）
- `/Users/mac/projects/zchain/poker_zkvm/src/crypto_arkworks.rs`（ArkworksCryptoProvider 实现）
- `/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas_strategy.rs`（ZkvmGasStrategy 实现）
- `/Users/mac/projects/zchain/poker_l1/tests/syscall_abi_snapshot.rs`
- `/Users/mac/projects/zchain/poker_zkvm/tests/syscall_abi_snapshot.rs`
- `/Users/mac/projects/zchain/vm-common/tests/precompile_adapter.rs`
- `/Users/mac/projects/zchain/vm-common/tests/registry_unified.rs`
- `/Users/mac/projects/zchain/vm-common/tests/crypto_consistency.rs`
- `/Users/mac/projects/zchain/vm-common/tests/gas_strategy.rs`

### 修改
- `/Users/mac/projects/zchain/Cargo.toml`（workspace members 加 vm-common）
- `/Users/mac/projects/zchain/poker_l1/Cargo.toml`（加 vm-common 依赖）
- `/Users/mac/projects/zchain/poker_zkvm/Cargo.toml`（加 vm-common 依赖）
- `/Users/mac/projects/zchain/poker_l1/src/vm/gas_table.rs`（常量迁移到 vm-common，本地保留 re-export alias）
- `/Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs`（trait 迁移到 vm-common，本地保留 `pub use` alias）
- `/Users/mac/projects/zchain/poker_l1/src/vm/syscalls.rs`（BLS 调用改走 BlstrsCryptoProvider）
- `/Users/mac/projects/zchain/poker_l1/src/vm/context.rs`（new 接收 &dyn GasStrategy）
- `/Users/mac/projects/zchain/poker_l1/src/offline/ccs.rs`（部分 re-export 改为从 vm-common 直接引）
- `/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas.rs`（常量迁移到 vm-common，本地保留 re-export）
- `/Users/mac/projects/zchain/poker_zkvm/src/syscalls/host.rs`（密码学调用改走 ArkworksCryptoProvider）
- `/Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs`（新增 PrecompileCircuitAdapter）
- `/Users/mac/projects/zchain/poker_zkvm/src/isa/executor.rs`（execute_elf_with_limits_and_config 接收 &dyn GasStrategy）
- `/Users/mac/projects/zchain/poker_zkvm/docs/38-3-zkvm-syscall-reference.md`（引用 vm-common ABI）

### 复用（零修改）
- `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/*.rs`（17 个业务合约，约 9.5K LoC）
- `/Users/mac/projects/zchain/poker_l1/src/vm/loader.rs`（solana_rbpf 加载逻辑）
- `/Users/mac/projects/zchain/poker_l1/src/vm/upgrade.rs`（治理升级流程）
- `/Users/mac/projects/zchain/poker_l1/src/executor.rs`（GameTurn gas-free lane 逻辑）
- `/Users/mac/projects/zchain/poker_zkvm/src/constraints/*.rs`（约束系统，约 7K LoC）
- `/Users/mac/projects/zchain/poker_zkvm/src/hypernova/*`（Hypernova 证明系统）
- `/Users/mac/projects/zchain/poker_zkvm/src/fold/*`（折叠系统）
- `/Users/mac/projects/zchain/poker_zkvm/src/prover/*`（prover 系统）
- `/Users/mac/projects/zchain/poker_zkvm/src/recursion/*`（递归系统）
- `/Users/mac/projects/zchain/poker_zkvm/src/isa/*`（RV32I 引擎与约束耦合，不动）
- `/Users/mac/projects/zchain/poker_zkvm/src/precompiles/*.rs`（9 个电路实现，仅加 adapter wrapper）

### 不删除
- `solana_rbpf` 依赖保留在 poker_l1
- `arkworks` 依赖保留在 poker_zkvm
- `poker_l1/src/vm/gas_table.rs` 保留（含 BPF 专有常量 + re-export alias）
- `poker_zkvm/src/syscalls/gas.rs` 保留（含 RV32I 专有常量 + re-export alias）

---

## 关键设计决策

1. **`vm-common` 不依赖 `solana_rbpf` 也不依赖 `arkworks`**：所有外部依赖通过 trait 抽象，避免成为 god-crate。验证手段：`cargo tree -p vm-common` 应只有 `thiserror`、`serde` 等基础库
2. **`vm-common` 不含任何 ISA 语义**：仅含横切关注点（gas/syscall_id/precompile/crypto/gas_strategy）
3. **保留 poker_l1 的 `solana_rbpf` 依赖与 `#![allow(unsafe_code)]`**：不破坏 IMPL-SEC-4 (1) 安全基线
4. **保留 poker_zkvm 的 `#![deny(unsafe_code)]`**：不破坏现有安全保证
5. **`PrecompileCircuitAdapter` 是单向桥接**：zkvm 电路可作为链上 precompile 调用，但不强制链上业务合约实现 CCS 接口（避免 17 个业务合约被迫补 CCS 实现）
6. **BLS 双库共存**：业务相关 BLS 用 bls12-381（blstrs），zkvm 电路约束用 ark-bn254（arkworks）。不强行收敛，因 BLS12-381 与 BN254 是不同曲线，强行收敛会破坏现有 validator 聚合签名
7. **GameTurn gas-free 完全不变**：`executor.rs` 的 lane 逻辑零修改，`GasStrategy` 仅作用于走 rBPF 执行的合约
8. **每阶段独立可回退**：任何阶段失败可回退到上一阶段而不影响其他模块

---

## 验证方案（端到端）

### 阶段 0 验证
```bash
cargo test --workspace
cargo test -p poker_l1 --test syscall_abi_snapshot
cargo test -p poker_zkvm --test syscall_abi_snapshot
```

### 阶段 1 验证
```bash
cargo build --workspace
cargo test --workspace
cargo tree -p vm-common  # 应无 solana_rbpf / arkworks
# 验证 gas 常量单一事实源
rg "GAS_ZKVM_ECDSA_VERIFY" --type rust  # 应只在 vm-common/src/gas.rs 定义
```

### 阶段 2 验证
```bash
cargo test -p vm-common --test precompile_adapter
cargo test -p vm-common --test registry_unified
cargo test -p poker_l1 vm::contracts  # 业务合约零修改应全绿
git diff poker_l1/src/vm/contracts/  # 应为空
```

### 阶段 3 验证
```bash
cargo test -p vm-common --test crypto_consistency
cargo test -p poker_l1 vm::syscalls  # BLS syscall 测试全绿
cargo test -p poker_zkvm syscalls   # sha256/poseidon/ecdsa 测试全绿
# 验证无直接库调用
rg "blstrs::" poker_l1/src/vm/syscalls.rs  # 应无匹配（走 BlstrsCryptoProvider）
rg "ark_bn254::" poker_zkvm/src/syscalls/host.rs  # 应无匹配
```

### 阶段 4 验证
```bash
cargo test -p vm-common --test gas_strategy
cargo test -p poker_l1 test_execute_out_of_gas  # 链上 gas 仍生效
cargo test -p poker_l1 test_gameturn_gas_free   # GameTurn 仍 gas-free
# zkvm 指令级 gas = 0
cargo test -p poker_zkvm -- gas_strategy  # ZkvmGasStrategy::instruction_gas 返回 0
```

### 阶段 5 验证
```bash
cargo doc -p vm-common --no-deps --open  # ABI 文档生成
cargo test --workspace  # 最终全量回归
```

### 性能回归（每阶段都跑）
```bash
cargo bench -p poker_l1 --bench task36_zk_verifier
cargo bench -p poker_zkvm --bench phase12_benchmarks
```
性能不应有显著退化（< 5%），因仅是间接调用替换。

---

## 风险与缓解

| 风险 | 等级 | 缓解措施 |
|---|---|---|
| `vm-common` 抽象边界设计不当成为 god-crate | 中 | 阶段 1 严格限制依赖（禁 solana_rbpf/arkworks），用 `cargo tree` 验证 |
| PrecompileCircuitAdapter 桥接语义不一致 | 中 | 阶段 2 新增 cross-impl 测试，对比 host_execute 与 build_ccs+assign_witness 结果 |
| CryptoProvider 双实现行为差异 | 中 | 阶段 3 cross-impl 一致性测试（sha256/keccak 等纯哈希必须一致；BLS/BN254 不同曲线不做等价） |
| GasStrategy 接入导致现有 gas 测试退化 | 低 | 阶段 4 完整回归 `test_execute_out_of_gas` 等，BpfGasStrategy 与原行为 1:1 |
| 业务合约 ABI 被意外破坏 | 低 | 阶段 0 snapshot 测试 + 阶段 2 `git diff poker_l1/src/vm/contracts/` 必须为空 |
| spec FROZEN 状态被破坏 | 低 | 本方案不触碰约束系统、Hypernova、IPA、Groth16；仅修改非 FROZEN 的 gas/syscall/precompile 接口层 |
| `poker_zkvm::#![deny(unsafe_code)]` 被破坏 | 低 | vm-common 不引入 unsafe；adapter 在 zkvm 内部实现，不引入 solana_rbpf |

---

## 未来演进路径

完成阶段 1-2 后，若仍需真正统一引擎（方案 A 或 C），可基于 `vm-common` 降级工作量：
- ABI 已统一（syscall_id 与 precompile trait 共用）
- gas 策略已抽象（GasStrategy trait 可加第三种 `Rv32iGasStrategy`）
- crypto 接口已统一（CryptoProvider trait）

此时方案 C（poker_l1 改用 RV32I）工作量从"大"降为"中"——仅需重写 `poker_l1/src/vm/{loader,syscalls,context}.rs`，ABI 与 precompile 已统一。这就是"保守重构为激进优化铺路"的体现。

---

## 总结

本方案（方案 B）通过抽出 `vm-common` 共享 crate，在不重写约束系统的前提下，统一了 precompile/gas/syscall_id/crypto/gas_strategy 五大横切关注点。与项目记忆所有约束 100% 兼容，业务合约零修改，分 5 阶段可独立测试与发布，总工作量 1.5-3 人月。是当前最务实的 VM 统一路径。
