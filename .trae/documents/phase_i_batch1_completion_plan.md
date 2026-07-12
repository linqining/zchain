# Phase I Batch 1 — 完成计划（修复 modexp + 实现 keccak256 + 注册集成）

## Summary

完成已批准的 Phase I Batch 1 剩余工作：修复 modexp.rs 的 2 个编译错误，实现 keccak256.rs（MVP 单轮 + Full 24 轮 + host 实现 + 测试），并完成 I-4 注册集成（SyscallId 0x0B-0x0D + gas 常量 + PrecompileRegistry 注册）。完成后构建恢复绿色，预编译覆盖率从 4/8 提升到 7/8。

**依据**：`phase_i_batch1_implementation_plan.md`（用户已批准）。本文件聚焦剩余未完成子任务（I-2 修复、I-3、I-4），不再重复已完成的 I-1。

## Current State Analysis

### 实际代码状态（已通过 `cargo check` 验证）

| 子任务 | 文件 | 状态 |
|--------|------|------|
| I-1 merkle_verify | `precompiles/merkle_verify.rs` | ✅ 完成，11 测试通过 |
| I-2 modexp | `precompiles/modexp.rs` | ❌ 2 编译错误 + 1 警告，阻断构建 |
| I-3 keccak256 | `precompiles/keccak256.rs` | ❌ 仅 1 行 doc 注释 stub |
| I-4 注册 | `syscalls/mod.rs` / `gas.rs` / `precompiles/mod.rs` | ❌ 未开始 |

### modexp.rs 当前编译错误（`cargo check` 输出）

```
error[E0382]: use of moved value: `builder.witness`
  --> poker_zkvm/src/precompiles/modexp.rs:100:18
   |
99 |     let ccs = builder.build()?;    // builder 被 move（build 消费 self）
100|     Ok((ccs, builder.witness))    // ERROR: use of moved value
   |

error[E0382]: use of moved value: `builder.witness`
  --> poker_zkvm/src/precompiles/modexp.rs:146:18   // run_full 同样问题

warning: unused import: `host_pow_mod`
  --> poker_zkvm/src/precompiles/modexp.rs:27:38
```

### 已验证的基础设施（无需重新探索）

- `NonNativeBuilder::build(self)` 消费 self（`non_native.rs:L847`），返回 `Result<Ccs, ZkvmError>`
- `NonNativeBuilder.witness: Vec<Fr>` 是 `pub` 字段（`non_native.rs:L298`），可在 build 前 clone
- `host_pow_mod` 已迁移到 `non_native.rs:L241` 作为 `pub(crate)`
- `bit_ops::bit_decompose(builder, val_col, num_bits)` 支持 64-bit（`num_bits` 参数化）
- `CcsBuilder` API：`alloc_var` / `alloc_row` / `add_linear` / `add_multiplication` / `add_bit_check` / `build`
- `sha256.rs` 的 `FullBuilder` 模式（CCS + witness 同步构建）作为 keccak256 Full 模式模板
- `SyscallId` 枚举（`syscalls/mod.rs:L62-83`）：10 个变体 0x01-0x0A，`#[repr(u32)]`
- `syscall_gas`（`gas.rs:L86`）：match SyscallId → u64
- `test_phase10_registry_full`（`precompiles/mod.rs:L341`）：当前仅注册 4 个预编译

## Proposed Changes

### Step 1: 修复 modexp.rs 编译错误（I-2 完成）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/modexp.rs`

**修复 1 — `builder.witness` 移动错误**（Line 99-100 和 Line 145-146）：

在 `run_mvp` 和 `run_full` 中，将 `Ok((ccs, builder.witness))` 改为先 clone witness：

```rust
// run_mvp (Line 99-100):
let witness = builder.witness.clone();
let ccs = builder.build()?;
Ok((ccs, witness))

// run_full (Line 145-146): 同样修改
let witness = builder.witness.clone();
let ccs = builder.build()?;
Ok((ccs, witness))
```

**修复 2 — `host_pow_mod` 未使用导入**（Line 27）：

将 `host_pow_mod` 从模块级导入移到 test 模块内：

```rust
// Line 27（模块级）改为：
use crate::precompiles::non_native::{NonNativeBuilder, NonNativeElement};

// tests 模块内（Line 316 附近）添加：
use crate::precompiles::non_native::host_pow_mod;
```

**验证**：
```bash
cargo test -p poker_zkvm --lib precompiles::modexp
```
预期 10 个测试全部通过（MVP 2 + Full 5 + host_pow_mod 1 + gas 1 + error 1）。

### Step 2: 实现 keccak256.rs（I-3）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/keccak256.rs`

#### 2.1 结构体

```rust
#[derive(Debug, Clone)]
pub struct Keccak256Circuit {
    full_mode: bool,
}
```

#### 2.2 Keccak-f[1600] 算法常量

- **rho 旋转常量** `RHO_OFFSETS: [[u32; 5]; 5]`（25 个值，A[0][0]=0）
- **iota 轮常量** `RC: [u64; 24]`（每轮一个 64-bit 常量）

#### 2.3 MVP 模式（单轮置换）

**输入**：25 个 64-bit lane 值（作为 Fr，低 64 位有效）
**输出**：25 个 lane 值（单轮置换后）

**单轮 5 步**（每步用 `bit_ops` 在 bit 域操作）：
1. **theta**：`C[x] = A[x,0] XOR ... XOR A[x,4]`；`D[x] = C[x-1] XOR rot(C[x+1], 1)`；`A[x,y] ^= D[x]`
2. **rho**：`A[x,y] = rot(A[x,y], RHO[x,y])`（旋转，0 约束，纯 witness 重排）
3. **pi**：`A[y, 2x+3y] = A[x,y]`（置换，0 约束，纯 witness 重排）
4. **chi**：`A'[x,y] = A[x,y] XOR ((NOT A[x+1,y]) AND A[x+2,y])`
5. **iota**：`A'[0,0] ^= RC[round]`

**实现策略**：
- 每个 lane（64-bit）用 `bit_decompose(builder, lane_var, 64)` 分解为 64 个 bit 变量
- theta/rho/pi/chi/iota 全在 bit 域操作（复用 `bit_xor` / `bit_and` / `bit_not` / `bit_rotr`）
- 最后 `bit_recompose` 回 64-bit lane 变量

**约束数估算**：单轮 ~8000 行（25 lanes × 64 bits × ~5 ops）

#### 2.4 Full 模式（24 轮 + padding）

**输入**：32 字节输入（256-bit），padding 到 136 字节（rate=1088 bits）
**输出**：32 字节哈希

**流程**：
1. Padding：`input || 0x01 || ... || 0x80`（Keccak padding，rate=1088 bits = 136 bytes）
2. Absorb：单块吸收（input ≤ 136 bytes 时仅 1 块）
3. 24 轮 Keccak-f[1600] 置换
4. Squeeze：取 state[0..4] 的前 32 字节（256-bit 哈希）

**约束数**：~24 × 8000 ≈ 192,000（与 SHA-256 Full 同量级）

#### 2.5 Host 端实现（测试模块内）

```rust
fn host_keccak_f1600(state: &mut [[u64; 5]; 5])  // 24 轮置换（u64 原生运算）
fn host_keccak256(input: &[u8]) -> [u8; 32]       // 完整哈希
```

#### 2.6 测试（4 个）

1. `test_keccak_mvp_single_round` — 单轮置换正确性（对比 host_keccak_f1600 单轮）
2. `test_keccak_full_empty_input` — `keccak256("")` = `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
3. `test_keccak_full_abc` — `keccak256("abc")` = `0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6beb`
4. `test_keccak_full_tampered_input` — 篡改输入后哈希不匹配

**gas**：
- MVP：`GAS_ZKVM_KECCAK256_PER_ROUND = 10_000`
- Full：`GAS_ZKVM_KECCAK256_PER_BYTE * input_len`（默认 32 字节时 64 gas）

### Step 3: 注册 + Syscall 集成（I-4）

#### 3.1 修改 `precompiles/mod.rs`

在 `test_phase10_registry_full` 测试中注册 3 个新预编译（总数 7）：

```rust
// L341-346 当前：
registry.register(Box::new(poseidon::PoseidonCircuit::new()));
registry.register(Box::new(sha256::Sha256Circuit::new()));
registry.register(Box::new(ecdsa::EcdsaVerifyCircuit::new()));
registry.register(Box::new(zk_shuffle::ZkShuffleCcsCircuit::new()));

// 新增：
registry.register(Box::new(keccak256::Keccak256Circuit::new()));
registry.register(Box::new(modexp::ModexpCircuit::new()));
registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));
```

同样更新其他注册 4 个预编译的测试（L406-409）。

#### 3.2 修改 `syscalls/mod.rs`

**SyscallId 枚举新增 3 个变体**（L82 后）：

```rust
pub enum SyscallId {
    // ... 既有 0x01-0x0A ...
    /// `zkvm_keccak256(ptr, len, out_ptr)` — Keccak-256 哈希。
    Keccak256 = 0x0B,
    /// `zkvm_modexp(base_ptr, exp_ptr, mod_ptr, out_ptr, num_bits)` — 大数模幂。
    Modexp = 0x0C,
    /// `zkvm_merkle_verify(leaf_ptr, root_ptr, path_ptr, depth)` — Merkle 路径验证。
    MerkleVerify = 0x0D,
}
```

**`from_u32()` 新增 3 个分支**（L101 后）：

```rust
0x0B => Ok(Self::Keccak256),
0x0C => Ok(Self::Modexp),
0x0D => Ok(Self::MerkleVerify),
```

**`all()` 返回 `[Self; 13]`**（原 10 + 3 新）：

```rust
pub fn all() -> [Self; 13] {
    [
        Self::ReadInput, Self::CommitOutput, Self::Poseidon, Self::Sha256,
        Self::EcdsaVerify, Self::EmitEvent, Self::Log, Self::Panic,
        Self::GetRandomness, Self::ReadState,
        Self::Keccak256, Self::Modexp, Self::MerkleVerify,
    ]
}
```

**更新文档注释表格**（L9-20）新增 3 行。

**更新 `SyscallRegistry`**：
- `syscalls` 字段类型从 `[Option<...>; 10]` 改为 `[Option<...>; 13]`
- `Debug` 实现的 match 添加 11/12/13 分支

**更新测试**：
- `test_from_u32_invalid_ids`：从 invalid_ids 中移除 0x0B/0x0C/0x0D
- `test_syscall_id_as_u32`：新增 3 个断言
- `test_all_returns_ten_syscalls` → `test_all_returns_thirteen_syscalls`：len=13
- `test_syscall_registry_default`：len=13
- `test_syscall_registry_dispatch_invalid_id`：0x0B 不再是非法

#### 3.3 修改 `syscalls/gas.rs`

**新增 gas 常量**（L53 后）：

```rust
/// `keccak256` 每字节 gas。
pub const GAS_ZKVM_KECCAK256_PER_BYTE: u64 = 2;
/// `keccak256` 每轮 gas（MVP 单轮）。
pub const GAS_ZKVM_KECCAK256_PER_ROUND: u64 = 10_000;
/// `modexp` 基础 gas。
pub const GAS_ZKVM_MODEXP_BASE: u64 = 50_000;
/// `modexp` 每位指数 gas。
pub const GAS_ZKVM_MODEXP_PER_BIT: u64 = 600;
/// `merkle_verify` 每层 gas。
pub const GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL: u64 = 100;
```

**`SyscallGasArgs` 新增字段**：

```rust
pub struct SyscallGasArgs {
    pub input_len: u32,
    pub num_slots: u32,
    pub num_bits: u32,   // modexp 用
    pub depth: u32,      // merkle_verify 用
}
```

**`syscall_gas()` 新增 3 个分支**：

```rust
SyscallId::Keccak256 => GAS_ZKVM_KECCAK256_PER_BYTE * args.input_len as u64,
SyscallId::Modexp => GAS_ZKVM_MODEXP_BASE + GAS_ZKVM_MODEXP_PER_BIT * args.num_bits as u64,
SyscallId::MerkleVerify => GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL * args.depth as u64,
```

**更新测试**：
- `test_gas_constants_values`：新增 5 个常量断言
- `test_all_syscalls_have_gas`：args 添加 `num_bits: 8, depth: 3`

### Step 4: 验证

```bash
# 1. 单个预编译测试
cargo test -p poker_zkvm --lib precompiles::merkle_verify
cargo test -p poker_zkvm --lib precompiles::modexp
cargo test -p poker_zkvm --lib precompiles::keccak256

# 2. 全部预编译测试
cargo test -p poker_zkvm --lib precompiles

# 3. syscall gas + mod 测试
cargo test -p poker_zkvm --lib syscalls::gas
cargo test -p poker_zkvm --lib syscalls::mod

# 4. clippy（无警告）
cargo clippy -p poker_zkvm --lib -- -D warnings

# 5. 全量回归（不含 ignored）
cargo test -p poker_zkvm --lib
```

## Assumptions & Decisions

| 决策点 | 选择 | 理由 |
|--------|------|------|
| modexp witness 提取 | build 前 `builder.witness.clone()` | `NonNativeBuilder::build(self)` 消费 self，需先提取 |
| host_pow_mod 导入位置 | 移到 test 模块 | 仅测试使用，避免模块级未使用警告 |
| keccak256 依赖 | 自实现，不加 sha3 crate | 保持依赖最小化（approved plan 决策） |
| keccak256 MVP | 单轮 Keccak-f[1600] 置换 | 验证约束结构，Full 模式 24 轮 |
| keccak256 lane 表示 | 64-bit bit_decompose | 复用 bit_ops，与 SHA-256 32-bit 模式对齐 |
| SyscallId 扩展 | 新增 0x0B-0x0D | Stage 4 计划明确要求 |
| SyscallGasArgs 扩展 | 新增 `num_bits` + `depth` | modexp/merkle 需要参数化 gas |
| Full 模式测试 | keccak256 Full 标记 `#[ignore]` | 避免 CI 超时（192K 约束）；手动 release 运行 |

## Implementation Order

1. **Step 1**: 修复 modexp.rs 编译错误（2 处 moved value + 1 处 unused import）
2. **Step 1 验证**: `cargo test -p poker_zkvm --lib precompiles::modexp` 全绿
3. **Step 2**: 实现 keccak256.rs（常量表 + MVP + Full + host + 4 测试）
4. **Step 2 验证**: `cargo test -p poker_zkvm --lib precompiles::keccak256` 全绿
5. **Step 3.1**: 修改 `precompiles/mod.rs`（注册 3 个新预编译到测试）
6. **Step 3.2**: 修改 `syscalls/mod.rs`（SyscallId 0x0B-0x0D + from_u32 + all + 测试更新）
7. **Step 3.3**: 修改 `syscalls/gas.rs`（5 个 gas 常量 + SyscallGasArgs 扩展 + syscall_gas 分支 + 测试更新）
8. **Step 4 验证**: 按验证步骤 1-5 依次执行

## Out of Scope

- bn254 pairing（hint-based）— 留待 Phase I Batch 2
- ed25519 — 留待后续批次（需 curve25519-dalek 依赖）
- bls12-381 pairing — 留待后续批次
- 现有 4 个预编译（poseidon/sha256/ecdsa/zk_shuffle）— 不修改
- 既有 10 个 SyscallId — 仅新增，不修改既有
- 既有 gas 常量 — 仅新增，不修改既有
- keccak256 Full 模式 256-byte 以上多块吸收 — 仅支持单块（input ≤ 136 bytes）
