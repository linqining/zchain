# 合约开发文档（Rust → BPF + Gas 计费表 + UpgradeCap）

> SubTask 37.2：poker_l1 合约开发文档
>
> 实现来源：`poker_l1/src/vm/gas_table.rs`、`poker_l1/src/vm/contract.rs`、`poker_l1/src/vm/loader.rs`、`poker_l1/src/vm/context.rs`、`poker_l1/src/vm/syscalls.rs`、`poker_l1/src/vm/upgrade.rs`、`poker_l1/src/transaction/mod.rs`
>
> 规范依据：`spec.md`（FROZEN 2026-06-27）+ IMPL-SEC-4 沙箱规范 + SEC-L7 timelock 升级 + SEC2-M11 紧急升级

---

## 1. 概述

poker_l1 合约模型基于 rBPF VM（`solana_rbpf`），合约源码以 Rust 编写，编译为 BPF 字节码（ELF 格式 `.so`），作为 Object 存储在链上 ObjectStore 中。合约执行采用解释器模式（JIT 暂未启用），通过 syscall 与宿主环境交互（读写 Object、发射事件、调用密码学预编译等）。

核心设计目标：

- **合约即 Object**：合约字节码作为 `ContractObject` 存储，通过 `contract_id` 索引，与普通 Object 共享 ObjectStore
- **可升级**：每个合约部署时创建 `UpgradeCap` 升级权对象，持有者可发起 timelock 升级或紧急升级
- **gas 计费**：指令级 + syscall 级双层计费，Public 通道按 `tx.gas.budget` 计费，GameTurn 通道免 gas
- **沙箱隔离**：内存分区（rodata/stack/heap/input），syscall 指针强制校验 heap region，单 Object ≤ 64KB

## 2. 合约对象模型

### 2.1 ContractObject 结构

合约对象存储在 `ObjectStore` 中，通过 `contract_id` 索引。一个 `contract_id` 可拥有多个版本，旧版本在升级后变为不可调用。

> 源码：`poker_l1/src/vm/contract.rs`

```rust
pub struct ContractObject {
    pub contract_id: ObjectID,       // 合约 ID（全局唯一，升级后不变）
    pub version: u32,                // 版本号（从 1 开始，每次升级 +1）
    pub bytecode: Vec<u8>,           // BPF 字节码（ELF 格式，≤ MAX_OBJECT_SIZE=64KB）
    pub deployer: Address,           // 部署者地址
    pub deployed_at_height: u64,     // 部署时的 block height
    pub is_active: bool,             // 是否为当前活跃版本
}
```

字段说明：

- `contract_id`：`ObjectID` 类型，全局唯一，由 `(creator_address, creation_nonce)` 派生，升级后保持不变
- `version`：从 1 开始，每次升级 +1
- `bytecode`：ELF 格式 BPF 字节码，序列化后须 ≤ `MAX_OBJECT_SIZE = 64KB`（IMPL-SEC-4：(7)）
- `is_active`：仅当前活跃版本为 `true`，旧版本在 `activate_version` 后置为 `false` 并移入 `history`

### 2.2 UpgradeCap 升级权

部署合约时同步创建并 transfer 给部署者，持有者可发起升级、取消升级、紧急升级。

```rust
pub struct UpgradeCap {
    pub contract_id: ObjectID,       // 关联的合约 ID
    pub holder: Address,             // 持有者地址
    pub created_at_height: u64,      // 创建时的 block height
}
```

`check_holder(caller)` 校验调用者是否为持有者，非持有者返回 `NotAuthorized`。

### 2.3 ContractRegistry 注册表

链上合约注册表，管理所有已部署合约的多版本字节码 + UpgradeCap + 升级状态。

> 源码：`poker_l1/src/vm/contract.rs`

```rust
pub struct ContractRegistry {
    contracts: BTreeMap<ObjectID, ContractObject>,          // 当前活跃合约
    history: BTreeMap<ObjectID, Vec<ContractObject>>,       // 历史版本
    upgrade_caps: BTreeMap<ObjectID, UpgradeCap>,           // 升级权
    upgrade_states: BTreeMap<ObjectID, UpgradeState>,       // 升级状态
}
```

关键方法：

- `deploy(bytecode, deployer, deploy_height)`：部署新合约，创建 `ContractObject`（version=1）+ `UpgradeCap`，返回 `(contract_id, cap_id)`
- `get_contract(contract_id)`：获取当前活跃版本
- `is_version_callable(contract_id, version)`：检查指定版本是否可调用（仅当前活跃版本可调用）
- `activate_version(contract_id, new_version, new_bytecode, deployer, height)`：内部方法，旧版本失活移入 `history`，激活新版本

## 3. Rust → BPF 编译流程

### 3.1 合约入口函数签名

合约入口为标准 rBPF entrypoint，接收输入数据指针与长度，返回 exit code：

```rust
#[no_mangle]
pub extern "C" fn entrypoint(input: *const u8, input_len: u64) -> u64 {
    // input 映射到 MM_INPUT_START 区域（≤ 64KB）
    // 返回 0 表示成功，非 0 表示错误码
    0
}
```

### 3.2 编译工具链

使用 Rust nightly + `bpfel-unknown-unknown` target 编译为 BPF 字节码：

```bash
# 安装 nightly + bpf target
rustup toolchain install nightly
rustup target add bpfel-unknown-unknown --toolchain nightly

# 编译合约（release 模式，生成 ELF .so 文件）
cargo +nightly build --release --target bpfel-unknown-unknown

# 产物路径：target/bpfel-unknown-unknown/release/<contract_name>.so
```

### 3.3 ELF 验证（IMPL-SEC-4：(1)）

加载时强制执行 `RequisiteVerifier` 验证，拒绝非法字节码：

> 源码：`poker_l1/src/vm/loader.rs` → `load_contract_bytecode`

```rust
let executable = Executable::<PokerL1Context>::from_elf(bytecode, loader)
    .map_err(|e| PokerL1Error::InvalidBytecode(format!("ELF load failed: {e}")))?;

executable.verify::<RequisiteVerifier>()
    .map_err(|e| PokerL1Error::InvalidBytecode(format!("Verifier rejected: {e}")))?;
```

验证失败（非法指令、未终止程序、未知 syscall 等）返回 `InvalidBytecode`，拒绝加载。

### 3.4 字节码大小限制

`bytecode.len()` 序列化后须 ≤ `MAX_OBJECT_SIZE = 64KB`（IMPL-SEC-4：(7)）。超长字节码在 `object_write` / `object_create` / `initiate_upgrade` / `emergency_upgrade` 阶段被拒绝，返回 `ObjectTooLarge`。

## 4. VM 执行环境

### 4.1 PokerL1Context 详解

> 源码：`poker_l1/src/vm/context.rs`

`PokerL1Context` 实现 `solana_rbpf::vm::ContextObject` trait，承载：

- `remaining` / `initial_gas`：gas 计费字段
- `tx: TxContext`：交易上下文（caller、chain_id、nonce、block_height、block_timestamp、is_gameturn）
- `object_cache: BTreeMap<ObjectID, Vec<u8>>`：对象读写缓存
- `events: Vec<ContractEvent>`：本次执行产生的事件
- `created_objects: Vec<ObjectID>`：本次执行创建的对象
- `zk_verifier: Option<ZkVerifierRegistry>`：ZK verifier 注册表（`zk_verify` syscall 使用）

Gas 计费模型：

- 指令级 gas：VM 每执行一条指令调用 `consume(1)`，到 0 抛 `ExceededMaxInstructions`，loader 转换为 `OutOfGas`
- syscall 级 gas：syscall 内部调用 `consume_gas(amount)` 对昂贵操作额外计费
- **GameTurn 通道免 gas**：`is_gameturn=true` 时 `gas_limit=u64::MAX`，`gas_used()` 返回 0
- IMPL-SEC-4：(5) 执行前扣费，余额不足立即 trap

### 4.2 内存布局

> 源码：`poker_l1/src/vm/loader.rs` + `poker_l1/src/vm/gas_table.rs`

| Region | 虚拟地址           | 大小上限                          | 来源                         |
|--------|--------------------|-----------------------------------|------------------------------|
| rodata | `MM_PROGRAM_START` | 来自 ELF                          | `executable.get_ro_region()` |
| stack  | `MM_STACK_START`   | `MAX_STACK_SIZE = 64KB`           | `Config::stack_size()`       |
| heap   | `MM_HEAP_START`    | `MAX_HEAP_SIZE = 1MB`             | `AlignedMemory::zero_filled` |
| input  | `MM_INPUT_START`   | `MAX_INPUT_SIZE = 64KB`           | 调用方传入                   |

### 4.3 调用深度与配置

> 源码：`poker_l1/src/vm/loader.rs`

```rust
const STACK_FRAME_SIZE: usize = 4096;                                  // 单帧 4KB
const MAX_CALL_DEPTH: usize = MAX_STACK_SIZE / STACK_FRAME_SIZE;       // = 16

fn poker_l1_config() -> Config {
    Config {
        enable_instruction_meter: true,   // 启用指令级 gas 计费
        max_call_depth: MAX_CALL_DEPTH,   // 限制栈 ≤ 64KB（IMPL-SEC-4：(3)）
        ..Config::default()
    }
}
```

- `MAX_CALL_DEPTH = 16`（`64KB / 4KB`）
- `enable_instruction_meter = true`：每条指令调用 `consume(1)`
- 当前仅支持解释器模式（`use_jit = false`），JIT 在后续版本通过 `solana_rbpf/jit` feature 启用

### 4.4 GameTurn 通道免 gas

```rust
// PokerL1Context::new(tx, gas_limit)
// GameTurn 通道：gas_limit = u64::MAX
pub const fn gas_used(&self) -> u64 {
    if self.initial_gas == u64::MAX {
        0  // GameTurn 通道免 gas
    } else {
        self.initial_gas.saturating_sub(self.remaining)
    }
}
```

gas 计费仅适用 Public 通道 tx 与合约调用；GameTurn 通道游戏操作 tx 免 gas（由买入锁仓作为反滥用保障）。

## 5. 完整 Gas 计费表

> 源码：`poker_l1/src/vm/gas_table.rs`（FROZEN 2026-06-27）

### 5.1 BPF 指令 gas

| 指令类别     | 常量                    | Gas | 计费公式                       |
|--------------|-------------------------|-----|--------------------------------|
| 算术指令     | `GAS_ARITHMETIC`        | 1   | 固定 1                         |
| 分支指令     | `GAS_BRANCH`            | 2   | 固定 2                         |
| 内存指令基础 | `GAS_MEMORY_BASE`       | 3   | `memory_gas(b) = 3 + 2 * b`    |
| 内存指令每字节 | `GAS_MEMORY_PER_BYTE` | 2   | （`b` = bytes_accessed）       |

### 5.2 Object 操作 gas

| Syscall         | 基础 gas                    | 每字节 gas | 公式                           |
|-----------------|-----------------------------|------------|--------------------------------|
| `object_read`   | `GAS_OBJECT_READ_BASE = 10` | 1          | `10 + 1 * bytes_returned`      |
| `object_write`  | `GAS_OBJECT_WRITE_BASE = 20`| 1          | `20 + 1 * data_len`            |
| `object_create` | `GAS_OBJECT_CREATE_BASE = 20`| 1        | `20 + 1 * data_len`            |

### 5.3 事件与日志 gas

| Syscall       | 基础 gas | 每字节 gas | 限制                  | 公式                          |
|---------------|----------|------------|-----------------------|-------------------------------|
| `emit_event`  | 10       | 1          | payload ≤ 16KB        | `10 + 1 * payload_len`        |
| `log`         | 10       | -          | -                     | 固定 10                       |
| `panic`       | 10       | -          | -                     | 固定 10（trap VM）            |

### 5.4 区块信息 gas

| Syscall             | Gas |
|---------------------|-----|
| `get_block_height`  | 1   |
| `get_timestamp`     | 1   |

### 5.5 签名验证 gas

| Syscall             | Gas                          | 说明                                   |
|---------------------|------------------------------|----------------------------------------|
| `verify_signature`  | `GAS_SECP256K1_VERIFY = 500` | R3-M3 修正，按 tagged pubkey 路由 secp256k1/ed25519 |

### 5.6 BLS12-381 预编译 gas

> 源码：`poker_l1/src/vm/gas_table.rs` + `poker_l1/src/vm/syscalls.rs`（含子群检查）

| Syscall                       | Gas                              | 说明                                  |
|-------------------------------|----------------------------------|---------------------------------------|
| `bls12_381_g1_add`            | `GAS_BLS_G1_ADD = 500`           | G1 点加法（含子群检查）               |
| `bls12_381_g1_mul`            | `GAS_BLS_G1_MUL = 500`           | G1 标量乘法（含子群检查）             |
| `bls12_381_g1_neg`            | `GAS_BLS_G1_NEG = 500`           | G1 取负（含子群检查）                 |
| `bls12_381_g2_add`            | `GAS_BLS_G2_ADD = 500`           | G2 点加法（含子群检查）               |
| `bls12_381_g2_mul`            | `GAS_BLS_G2_MUL = 500`           | G2 标量乘法（含子群检查）             |
| `bls12_381_g2_neg`            | `GAS_BLS_G2_NEG = 500`           | G2 取负（含子群检查）                 |
| `bls12_381_pairing_check`     | `GAS_BLS_PAIRING = 5000`         | 双线性配对检查（worst-case）          |
| `bls12_381_miller_loop`       | `GAS_BLS_MILLER_LOOP = 2000`     | Miller loop + final exp              |
| `bls12_381_final_exp`         | `GAS_BLS_FINAL_EXP = 1000`       | Final exponentiation（identity）     |
| `bls12_381_hash_to_g1`        | `1000 + 10 * msg_len`            | RFC 9380 hash to G1                  |
| `bls12_381_hash_to_g2`        | `1000 + 10 * msg_len`            | RFC 9380 hash to G2                  |

注：`pairing = 2 × miller_loop + 1 × final_exp = 2*2000 + 1000 = 5000`。

### 5.7 ZK 验证 gas

> 源码：`poker_l1/src/vm/gas_table.rs` → `zk_verify_gas(scheme_id)`

| scheme_id | Scheme    | Gas                              |
|-----------|-----------|----------------------------------|
| 1         | Hypernova | `GAS_HYPERNOVA_VERIFY = 50000`   |
| 2         | Groth16   | `GAS_GROTH16_VERIFY = 20000`     |
| 3         | IPA       | `GAS_IPA_VERIFY = 15000`         |
| 其他      | fallback  | `GAS_ZK_VERIFY = 50000`          |

### 5.8 失败证明 gas

| Syscall                   | Gas                              | 说明                                            |
|---------------------------|----------------------------------|-------------------------------------------------|
| `verify_failure_proof`    | `GAS_VERIFY_FAILURE_PROOF = 80000` | SEC-H9 修复：256-bit SMT 非包含证明 + 多签验证 |

成本估算：256 层路径 × 200 + 3 × secp256k1(500) + 1500 + 3 × 500 = 55700，预留 30% 安全边际上取整至 80000。

### 5.9 Gas 限额与大小限制

| 常量                       | 值        | 说明                                       |
|----------------------------|-----------|--------------------------------------------|
| `BLOCK_GAS_LIMIT`          | 50,000,000| block gas limit（M8）                      |
| `TX_GAS_LIMIT`             | 10,000,000| tx gas limit（M8）                         |
| `MAX_OBJECT_SIZE`          | 64 KB     | 单个 Object 序列化后最大字节数（IMPL-SEC-4：(7)） |
| `MAX_HEAP_SIZE`            | 1 MB      | 合约 heap 最大字节数（IMPL-SEC-4：(3)）    |
| `MAX_STACK_SIZE`           | 64 KB     | 合约栈最大字节数（IMPL-SEC-4：(3)）        |
| `MAX_INPUT_SIZE`           | 64 KB     | BPF 输入数据最大字节数                     |
| `MAX_EVENT_PAYLOAD_SIZE`   | 16 KB     | `emit_event` payload 最大字节数            |
| `MAX_BLS_HASH_MSG_SIZE`    | 65536     | BLS12-381 hash_to_curve 消息最大字节数     |
| `MAX_ZK_PROOF_BYTES`       | 256 KB    | `zk_verify` proof 最大字节数（防 DoS）     |
| `MAX_ZK_PUBLIC_IO_BYTES`   | 64 KB     | `zk_verify` public_io 最大字节数           |

## 6. Syscall API 参考

> 源码：`poker_l1/src/vm/syscalls.rs`

poker_l1 注册全部 22 个 syscall 到 rBPF syscall table（10 核心 + 1 zk_verify + 11 BLS 预编译）。所有 syscall 指针须位于 heap region（IMPL-SEC-4：(4)），执行前扣费（IMPL-SEC-4：(5)）。

### 6.1 核心 Syscall

| Syscall name              | 签名（参数顺序）                                              | 返回值           | Gas                              |
|---------------------------|---------------------------------------------------------------|------------------|----------------------------------|
| `object_read`             | `(id_ptr, id_len, out_ptr, out_capacity, _)`                  | 实际读取字节数   | `10 + 1 * bytes_returned`        |
| `object_write`            | `(id_ptr, id_len, data_ptr, data_len, _)`                     | 0                | `20 + 1 * data_len`              |
| `object_create`           | `(data_ptr, data_len, out_id_ptr, out_id_len, _)`             | 0                | `20 + 1 * data_len`              |
| `emit_event`              | `(payload_ptr, payload_len, _, _, _)`                         | 0                | `10 + 1 * payload_len`           |
| `log`                     | `(msg_ptr, msg_len, _, _, _)`                                 | 0                | 10                               |
| `panic`                   | `(msg_ptr, msg_len, _, _, _)`                                 | 始终 Err（trap） | 10                               |
| `verify_signature`        | `(pubkey_ptr, pubkey_len, sig_ptr, sig_len, msg_hash_ptr)`    | 0=通过 / 1=失败 | 500                              |
| `get_block_height`        | `(_, _, _, _, _)`                                             | 当前 block height | 1                                |
| `get_timestamp`           | `(_, _, _, _, _)`                                             | 当前 timestamp(ms) | 1                                |
| `verify_failure_proof`    | `(proof_ptr, proof_len, _, _, _)`                             | 0=有效 / 1=无效 | 80000                            |
| `zk_verify`               | `(scheme_id, proof_ptr, proof_len, public_io_ptr, public_io_len)` | 0=通过 / 1=失败 | 按 scheme 分派（50000/20000/15000）|

### 6.2 BLS12-381 预编译 Syscall

| Syscall name                  | 签名                                                          | Gas                              |
|-------------------------------|---------------------------------------------------------------|----------------------------------|
| `bls12_381_g1_add`            | `(a_ptr, b_ptr, out_ptr, _, _)`                               | 500                              |
| `bls12_381_g1_mul`            | `(point_ptr, scalar_ptr, out_ptr, _, _)`                      | 500                              |
| `bls12_381_g1_neg`            | `(point_ptr, out_ptr, _, _, _)`                               | 500                              |
| `bls12_381_g2_add`            | `(a_ptr, b_ptr, out_ptr, _, _)`                               | 500                              |
| `bls12_381_g2_mul`            | `(point_ptr, scalar_ptr, out_ptr, _, _)`                      | 500                              |
| `bls12_381_g2_neg`            | `(point_ptr, out_ptr, _, _, _)`                               | 500                              |
| `bls12_381_pairing_check`     | `(a_g1_ptr, b_g2_ptr, c_g1_ptr, d_g2_ptr, _)`                 | 5000                             |
| `bls12_381_hash_to_g1`        | `(msg_ptr, msg_len, out_ptr, _, _)`                           | `1000 + 10 * msg_len`            |
| `bls12_381_hash_to_g2`        | `(msg_ptr, msg_len, out_ptr, _, _)`                           | `1000 + 10 * msg_len`            |
| `bls12_381_miller_loop`       | `(a_g1_ptr, b_g2_ptr, out_ptr, _, _)`                         | 2000                             |
| `bls12_381_final_exp`         | `(gt_ptr, out_ptr, _, _, _)`                                  | 1000                             |

### 6.3 关键 Syscall 输入布局

**`verify_failure_proof`** 输入布局（`poker_l1/src/vm/syscalls.rs`）：

| 偏移 | 长度 | 字段                  |
|------|------|-----------------------|
| 0    | 32   | expected SMT root     |
| 32   | 32   | key hash              |
| 64   | 变长 | BCS-encoded MerklePath |

**`zk_verify`** 参数说明：

- `scheme_id`：低 32 位有效（1=Hypernova, 2=Groth16, 3=IPA）
- `max_skip_segments = 3`（默认，SubTask 27.11）
- `max_ack_chain_length = DEFAULT_MAX_ACK_CHAIN_LENGTH`（默认 1000）
- proof ≤ 256KB，public_io ≤ 64KB（防 DoS）
- `ctx.zk_verifier` 未注入时返回 `ZkVerifierNotRegistered`

**`object_create`** ObjectID 生成规则：

```rust
let creation_nonce = ctx.tx.block_height.wrapping_shl(20)
    .wrapping_add(ctx.created_objects.len() as u64);
let object_id = ObjectID::new(ctx.tx.caller, creation_nonce);
```

## 7. UpgradeCap 升级机制

> 源码：`poker_l1/src/vm/upgrade.rs`

### 7.1 UpgradeConfig 配置

```rust
pub struct UpgradeConfig {
    pub upgrade_delay_blocks: u64,           // Timelock 延迟（默认 2000 blocks，SEC-L7 (1)）
    pub emergency_audit_period_blocks: u64,  // 紧急升级审计期（默认 1000 blocks，SEC2-M11 (3)）
    pub emergency_quorum_threshold: u32,     // 紧急升级 quorum（默认 90%，SEC-L7 (5)）
}
```

治理可将 `upgrade_delay_blocks` 设为 `u64::MAX` 实质冻结该合约升级（SEC-L7 (4)）。

### 7.2 UpgradeState 状态机

```text
  deploy ──► Idle ──initiate──► Pending ──commit(timelock到期)──► Idle
               ▲                    │
               │                    ├──cancel(holder)──► Idle
               │                    └──dispute(任意)──► Frozen
               │
               └──emergency──► EmergencyAudit ──audit到期──► Idle
                                  │
                                  └──dispute_emergency──► EmergencyAudit{disputed=true}
```

状态枚举定义（`poker_l1/src/vm/contract.rs`）：

```rust
pub enum UpgradeState {
    Idle,                                            // 无待生效升级
    Pending { new_version, pending_bytecode, activate_at_height, submitted_by },  // Timelock 期
    EmergencyAudit { new_version, audit_ends_at_height, disputed },  // 紧急升级审计期
    Frozen,                                          // 治理冻结
}
```

### 7.3 升级 API

| 函数                          | 调用者              | 状态转换                          | 关键校验                                       |
|-------------------------------|---------------------|-----------------------------------|------------------------------------------------|
| `initiate_upgrade`            | UpgradeCap 持有者   | Idle → Pending                    | 字节码 ≤ 64KB；非 Frozen；非重复 initiate      |
| `cancel_upgrade`              | UpgradeCap 持有者   | Pending → Idle                    | 须为 Pending 状态                              |
| `dispute_upgrade`             | 任意参与者          | Pending → Frozen                  | 须为 Pending 状态（防恶意升级）                |
| `commit_upgrade`              | 任意（自动）        | Pending → Idle（激活新版本）      | timelock 到期（`current_height >= activate_at_height`） |
| `emergency_upgrade`           | UpgradeCap 持有者   | Idle → EmergencyAudit（立即生效） | 90% quorum + 非空 critical_vulnerability_proof |
| `dispute_emergency_upgrade`   | 任意参与者          | EmergencyAudit{disputed=true}     | 审计期内（`current_height < audit_ends_at_height`） |
| `process_pending_upgrades`    | 系统（区块产出时）  | Pending(timelock到期) → Idle      | 遍历所有 Pending，到期自动激活                 |

### 7.4 紧急升级流程（SEC-L7 (5) + SEC2-M11）

紧急升级绕过 timelock，但须满足：

1. **90% validator quorum** 通过专项提案（`validator_quorum_percent >= emergency_quorum_threshold`）
2. **含 `critical_vulnerability_proof`**（非空，SEC2-M11 (1)）
3. **生效后进入 1000 blocks 安全审计期**（SEC2-M11 (3)），期间任意参与者可 `dispute_emergency_upgrade` 触发治理复审
4. 重复 dispute 返回 `EmergencyUpgradeDisputed`；审计期过后不可 dispute

```rust
pub fn emergency_upgrade(
    registry: &mut ContractRegistry,
    config: &UpgradeConfig,
    contract_id: &ObjectID,
    caller: Address,
    new_bytecode: Vec<u8>,
    current_height: u64,
    critical_vulnerability_proof: &[u8],   // 须非空
    validator_quorum_percent: u32,          // 须 >= 90
) -> PokerL1Result<u32>
```

### 7.5 Frozen 状态

`dispute_upgrade` 后状态变为 `Frozen`，所有升级操作（`initiate` / `cancel` / `dispute` / `emergency`）均返回 `NotAuthorized`，须治理介入解冻。

## 8. 交易结构

> 源码：`poker_l1/src/transaction/mod.rs`

### 8.1 Transaction 字段

```rust
pub struct Transaction {
    // 对象模型
    pub inputs: Vec<ObjectID>,                 // 引用的输入对象（≤ 256）
    pub outputs: Vec<Object>,                  // 新创建的输出对象（≤ 256）
    pub contract_call: Option<ContractCall>,   // 合约调用（可选）

    // 签名
    pub tagged_pubkey: TaggedPubkey,           // 签名者 tagged pubkey
    pub signature: Vec<u8>,                    // secp256k1=65B r||s||v；ed25519=64B R||S

    // Gas 与路由
    pub gas: Gas,                              // { budget ≤ 10M, price }
    pub lane_hint: TxLane,                     // Public / GameTurn / CheckpointAnchor / ForceSync
    pub route_hint: RouteHint,                 // AnyValidator / AssignedValidator

    // 重放保护
    pub chain_id: ChainId,                     // SEC-L4：签名域首字段，防跨链重放
    pub nonce: u64,                            // M10：Public / ForceSync 通道重放保护
    pub gameturn_nonce: Option<u64>,           // NEW-M9：per-game per-player 计数器
    pub is_fallback: bool,                     // SEC-H7：默认 false，fallback tx 标记 true
}
```

### 8.2 ContractCall 载荷

```rust
pub struct ContractCall {
    pub contract_id: ObjectID,          // 目标合约对象 ID
    pub method_selector: [u8; 32],      // blake2b_256(method_name)[0..32]
    pub args: Vec<u8>,                  // BCS 编码参数（≤ 64KB）
}
```

### 8.3 TxLane 通道分类

| 通道               | 路由                | Gas 计费 | 说明                                   |
|--------------------|---------------------|----------|----------------------------------------|
| `Public`           | AnyValidator        | 正常计费 | 通用交易（转账、合约部署/调用、bridge）|
| `GameTurn`         | AssignedValidator   | 免 gas   | 游戏轮次（call/check/raise/bet/fold）  |
| `CheckpointAnchor` | AssignedValidator   | 免 gas   | 链下执行 checkpoint（system tx）       |
| `ForceSync`        | AnyValidator        | 正常计费 | 强制同步 / 逃生通道类交易              |

### 8.4 签名哈希计算

> 源码：`poker_l1/src/transaction/mod.rs` → `signing_hash`

签名域分隔前缀 `TX_SIG_DOMAIN = 0x54`（'T' for Transaction）。签名对象 = `blake2b_256(0x54 || chain_id || nonce || gameturn_nonce || is_fallback || lane_hint || route_hint || gas || inputs || outputs || contract_call)`。

注意：`tagged_pubkey` 与 `signature` 不参与签名哈希（它们是签名产物）。

```rust
pub fn signing_hash(&self) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[TX_SIG_DOMAIN]);                    // 0x54
    h.update(&self.chain_id.to_le_bytes());        // SEC-L4：chain_id 首字段
    h.update(&self.nonce.to_le_bytes());
    match self.gameturn_nonce {                    // 0x00=None / 0x01=Some
        Some(v) => { h.update(&[0x01]); h.update(&v.to_le_bytes()); }
        None => h.update(&[0x00]),
    }
    h.update(&[self.is_fallback as u8]);
    h.update(&[self.lane_hint as u8]);
    h.update(&[self.route_hint as u8]);
    h.update(&self.gas.budget.to_le_bytes());
    h.update(&self.gas.price.to_le_bytes());
    for input in &self.inputs { h.update(&input.to_bytes()); }
    for output in &self.outputs { h.update(&output.content_hash()); }
    match &self.contract_call {
        Some(cc) => {
            h.update(&[0x01]);
            h.update(&cc.contract_id.to_bytes());
            h.update(&cc.method_selector);
            h.update(&(cc.args.len() as u64).to_le_bytes());
            h.update(&cc.args);
        }
        None => h.update(&[0x00]),
    }
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}
```

### 8.5 交易大小限制

> 源码：`poker_l1/src/transaction/mod.rs` → `validate_tx_limits`

| 字段           | 上限     | 说明                          |
|----------------|----------|-------------------------------|
| `inputs`       | 256      | 输入对象数量                  |
| `outputs`      | 256      | 输出对象数量                  |
| `signature`    | 65 字节  | secp256k1 = 65B               |
| `contract_call.args` | 64 KB | BCS 编码参数                 |

## 9. 合约开发示例

### 9.1 简单计数器合约（Rust）

```rust
// src/lib.rs
#![no_std]

/// ObjectID 字节长度（poker_l1 固定 28 字节）
const OBJECT_ID_LEN: u64 = 28;

/// Syscall 函数签名（与宿主注册名一致）
extern "C" {
    fn object_read(id_ptr: u64, id_len: u64, out_ptr: u64, out_capacity: u64, _arg5: u64) -> u64;
    fn object_write(id_ptr: u64, id_len: u64, data_ptr: u64, data_len: u64, _arg5: u64) -> u64;
    fn emit_event(payload_ptr: u64, payload_len: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> u64;
}

#[no_mangle]
pub extern "C" fn entrypoint(input: *const u8, input_len: u64) -> u64 {
    // input 布局：[0..28) = counter ObjectID，[28..36) = u64 increment
    // 1. 读取当前计数器值（8 字节）
    let mut id_buf = [0u8; 28];
    unsafe { core::ptr::copy_nonoverlapping(input, id_buf.as_mut_ptr(), 28); }

    let mut value_buf = [0u8; 8];
    let _read = unsafe {
        object_read(id_buf.as_ptr() as u64, OBJECT_ID_LEN, value_buf.as_mut_ptr() as u64, 8, 0)
    };

    // 2. 解析 increment（input[28..36)）
    let mut inc_buf = [0u8; 8];
    unsafe { core::ptr::copy_nonoverlapping(input.add(28), inc_buf.as_mut_ptr(), 8); }
    let current = u64::from_le_bytes(value_buf);
    let inc = u64::from_le_bytes(inc_buf);
    let new_value = current.wrapping_add(inc);

    // 3. 写回 Object
    let new_bytes = new_value.to_le_bytes();
    unsafe {
        object_write(id_buf.as_ptr() as u64, OBJECT_ID_LEN, new_bytes.as_ptr() as u64, 8, 0);
    }

    // 4. 发射事件
    let event_msg = b"counter incremented";
    unsafe {
        emit_event(event_msg.as_ptr() as u64, event_msg.len() as u64, 0, 0, 0);
    }

    0  // exit code 0 = 成功
}
```

### 9.2 编译命令

```bash
# 1. 创建合约项目
cargo new --lib counter_contract
cd counter_contract

# 2. 配置 Cargo.toml
cat > Cargo.toml <<'EOF'
[package]
name = "counter_contract"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[profile.release]
opt-level = "z"
lto = true
panic = "abort"
EOF

# 3. 编译为 BPF 字节码
rustup target add bpfel-unknown-unknown --toolchain nightly
cargo +nightly build --release --target bpfel-unknown-unknown

# 4. 产物
ls -la target/bpfel-unknown-unknown/release/counter_contract.so
# 大小须 ≤ 64KB（MAX_OBJECT_SIZE）
```

### 9.3 部署交易构造

```rust
use poker_l1::object_model::{Object, ObjectID, Ownership};
use poker_l1::transaction::{ContractCall, Gas, RouteHint, Transaction, TxLane};
use poker_l1::signature::{TaggedPubkey, SignatureScheme};

// 1. 读取编译产物
let bytecode = std::fs::read("counter_contract.so")?;
assert!(bytecode.len() <= 64 * 1024, "bytecode 须 ≤ 64KB");

// 2. 构造合约对象（Object 类型 = "Contract"）
let contract_object = Object::new(
    ObjectID::new(deployer_address, deploy_height),
    Ownership::Owned(deployer_address),
    "Contract",
    bytecode,
    None,
);

// 3. 构造部署 tx（Public 通道，正常计费）
let tx_request = TxRequest {
    inputs: vec![],
    outputs: vec![contract_object],
    contract_call: None,           // 部署阶段不调用合约
    gas: Gas::new(1_000_000, 1),   // budget=1M gas, price=1
    lane_hint: TxLane::Public,
    route_hint: RouteHint::AnyValidator,
    chain_id: poker_l1::DEFAULT_CHAIN_ID,
    nonce: 42,
    gameturn_nonce: None,
    is_fallback: false,
};

// 4. 计算签名哈希并签名（SEC-L4：chain_id 为首字段）
let signing_hash = tx_request.signing_hash();
let signature = sign_secp256k1(&private_key, &signing_hash);  // 65 字节

// 5. 组装完整 Transaction
let tagged_pubkey = TaggedPubkey {
    tag: encode_tag(SignatureScheme::Secp256k1, 1),
    raw: public_key_serialized,
};
let tx = tx_request.into_transaction(tagged_pubkey, signature);

// 6. 校验 tx 字段限制
poker_l1::transaction::validate_tx_limits(&tx)?;
```

### 9.4 调用合约交易构造

```rust
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

// 1. 计算 method_selector = blake2b_256("increment")[0..32]
let mut selector = [0u8; 32];
let mut h = Blake2bVar::new(32).unwrap();
h.update(b"increment");
h.finalize_variable(&mut selector).unwrap();

// 2. BCS 编码参数（counter_id + increment）
let mut args = Vec::new();
args.extend_from_slice(&counter_object_id.to_bytes());  // 28 字节
args.extend_from_slice(&100u64.to_le_bytes());          // increment = 100

// 3. 构造 ContractCall
let contract_call = ContractCall {
    contract_id: deployed_contract_id,
    method_selector: selector,
    args,  // ≤ 64KB
};

// 4. 构造调用 tx
let tx_request = TxRequest {
    inputs: vec![counter_object_id],
    outputs: vec![],
    contract_call: Some(contract_call),
    gas: Gas::new(500_000, 1),
    lane_hint: TxLane::Public,
    route_hint: RouteHint::AnyValidator,
    chain_id: poker_l1::DEFAULT_CHAIN_ID,
    nonce: 43,
    gameturn_nonce: None,
    is_fallback: false,
};
```

### 9.5 Gas 估算示例

以 9.4 的调用为例，预估 gas 消耗：

| 操作                          | Gas                                       |
|-------------------------------|-------------------------------------------|
| `object_read(8 bytes)`        | `10 + 1*8 = 18`                           |
| `object_write(8 bytes)`       | `20 + 1*8 = 28`                           |
| `emit_event(20 bytes)`        | `10 + 1*20 = 30`                          |
| BPF 指令（约 100 条算术）     | `100 * 1 = 100`                           |
| BPF 指令（约 20 条内存）      | `20 * (3 + 2*8) = 380`                    |
| BPF 指令（约 10 条分支）      | `10 * 2 = 20`                             |
| **合计**                      | **≈ 576 gas**                             |

设置 `gas.budget = 500_000` 留足安全边际。

---

## 附录：源文件索引

| 模块              | 源文件路径                                   | 说明                                      |
|-------------------|----------------------------------------------|-------------------------------------------|
| gas_table         | `poker_l1/src/vm/gas_table.rs`               | Gas 计费表常量与计算函数                  |
| contract          | `poker_l1/src/vm/contract.rs`                | ContractObject / UpgradeCap / Registry    |
| loader            | `poker_l1/src/vm/loader.rs`                  | rBPF VM 加载器与执行环境                  |
| context           | `poker_l1/src/vm/context.rs`                 | PokerL1Context + gas 计费                 |
| syscalls          | `poker_l1/src/vm/syscalls.rs`                | 22 个 syscall 实现与注册                  |
| upgrade           | `poker_l1/src/vm/upgrade.rs`                 | SEC-L7 timelock 升级机制                  |
| transaction       | `poker_l1/src/transaction/mod.rs`            | Transaction 结构与签名哈希                |
