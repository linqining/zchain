# Phase I Batch 1 完成计划 v2（调试 keccak256 + I-4 注册集成）

## Summary

完成 Phase I Batch 1 的剩余工作：解决 `test_host_keccak256_abc` 测试失败问题，然后执行 I-4（SyscallId 0x0B-0x0D + gas 常量 + PrecompileRegistry 注册），最后全量验证。

**依据**：用户已批准的 `phase_i_batch1_finalization_plan.md`。本计划聚焦于未完成的 Step 1（keccak256 调试）和 Steps 2-5（I-4 注册集成 + 验证）。

## Current State Analysis

### Step 1 状态：keccak256.rs

已完成 3 个修复：
1. ✅ `bit_not` 约束修复（L229）：`bit + not_bit - 1 = 0`
2. ✅ `[[Vec::new(); 5]; 5]` 编译错误修复（5 处）：`Default::default()` + 类型标注
3. ✅ Rho 旋转方向修复：host `rotate_left`，circuit `bit_rotr(64 - offset)`

**当前测试状态**（`cargo test -p poker_zkvm --lib precompiles::keccak256`）：
- ✅ `test_keccak_mvp_single_round`
- ✅ `test_keccak_mvp_tampered_output`
- ✅ `test_host_keccak256_empty` — keccak256("") 正确
- ✅ `test_keccak_gas_cost`
- ✅ `test_keccak_wrong_input_length`
- ❓ `test_host_keccak256_abc` — 上一轮运行失败（最后 2 字节不匹配），需重新验证
- ⏸️ `test_keccak_full_empty_input` — `#[ignore]`
- ⏸️ `test_keccak_full_abc` — `#[ignore]`

### 静态分析结论

对 `host_keccak_round`（L599-639）逐行审查结果：
- **Theta**（L600-615）：`D[x] = C[x-1] XOR rot(C[x+1], 1)` → `c[(x+4)%5] ^ c[(x+1)%5].rotate_right(63)` ✅（`rotate_right(63)` = `rotate_left(1)`）
- **Rho+Pi**（L617-626）：`A'[y][(2x+3y)%5] = ROTL(A[x][y], RHO[x][y])` ✅
- **Chi**（L628-635）：`A'[x][y] = A[x][y] XOR ((NOT A[x+1][y]) AND A[x+2][y])` ✅
- **Iota**（L637-638）：`state[0][0] ^= RC[round_idx]` ✅
- **RHO_OFFSETS**（L34-40）：25 个值与 FIPS 202 Section 3.2.2 逐值对比 ✅
- **RC**（L43-68）：24 个轮常量与 FIPS 202 逐值对比 ✅
- **Padding**（L653-662）：Keccak pad10*1（0x01 || 0x00* || 0x80）✅
- **Absorb**（L665-678）：`lane_idx = x + 5*y`，`x = lane_idx % 5`，`y = lane_idx / 5` ✅
- **Squeeze**（L681-688）：取 `state[0..4][0]` 前 4 个 lane 的 LE bytes ✅

**结论**：代码静态分析完全正确。上一轮失败可能是：(a) 修复后未重新编译运行；(b) 有极其微妙的 bug 无法通过阅读发现。需先运行测试确认。

### I-4 待修改文件

| 文件 | 修改内容 |
|------|----------|
| `syscalls/mod.rs` | SyscallId 新增 0x0B-0x0D，`from_u32`/`all()`/数组大小 10→13/Debug/测试更新 |
| `syscalls/gas.rs` | 5 个 gas 常量 + `SyscallGasArgs` 扩展 + `syscall_gas` 3 分支 + 测试更新 |
| `precompiles/mod.rs` | 3 个测试中注册 3 个新预编译（总数 4→7）|

## Proposed Changes

### Step 1: 验证并调试 keccak256("abc")

#### 1.1 运行测试确认当前状态

```bash
cargo test -p poker_zkvm --lib precompiles::keccak256::tests::test_host_keccak256_abc -- --nocapture
```

- **如果通过**：跳到 Step 2
- **如果失败**：继续 1.2

#### 1.2 使用 Python 验证正确值

```bash
python3 -c "
from Crypto.Hash import keccak
k = keccak.new(digest_bits=256)
k.update(b'abc')
print(k.hexdigest())
"
```

预期输出：`4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6beb`

如果 pycryptodome 不可用，使用 pip 安装：`pip3 install pycryptodome`

#### 1.3 添加调试测试（如果仍失败）

在 `keccak256.rs` 的 `tests` 模块中添加一个 `#[ignore]` 调试测试，打印每轮置换后的状态：

```rust
#[test]
#[ignore = "调试用，打印中间状态"]
fn test_debug_keccak_round_states() {
    // keccak256("abc") 的初始状态
    let mut padded = vec![0u8; 136];
    padded[0] = 0x61; padded[1] = 0x62; padded[2] = 0x63; padded[3] = 0x01; padded[135] = 0x80;
    let mut state = [[0u64; 5]; 5];
    for lane_idx in 0..RATE_LANES {
        let offset = lane_idx * 8;
        let lane = u64::from_le_bytes(padded[offset..offset+8].try_into().unwrap());
        state[lane_idx % 5][lane_idx / 5] ^= lane;
    }
    println!("Initial state:");
    for y in 0..5 { for x in 0..5 { print!("{:016x} ", state[x][y]); } println!(); }
    for round in 0..24 {
        host_keccak_round(&mut state, round);
        println!("After round {}:", round);
        for y in 0..5 { for x in 0..5 { print!("{:016x} ", state[x][y]); } println!(); }
    }
    // 打印最终 hash
    let mut result = [0u8; 32];
    for lane_idx in 0..4 {
        let bytes = state[lane_idx % 5][lane_idx / 5].to_le_bytes();
        result[lane_idx*8..(lane_idx+1)*8].copy_from_slice(&bytes);
    }
    println!("Hash: {}", hex::encode(&result));
    // 期望: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6beb
}
```

同时用 Python 生成对应的中间状态：

```python
from Crypto.Hash import keccak
# 手动实现 Keccak-f[1600] 打印中间状态
# ...（如果需要）
```

#### 1.4 修复 bug

根据调试结果定位并修复 bug。可能的方向：
- 检查 `RHO_OFFSETS` 索引是否被转置（`[x][y]` vs `[y][x]`）
- 检查 Pi 步的 `(2*x + 3*y) % 5` 是否有整数溢出（不会，但需确认）
- 检查 `rotate_left` 在某些 u64 值下是否有意外行为（不应该有）
- 对比 NIST Keccak 参考实现的中间状态

### Step 2: 修改 `syscalls/mod.rs`（I-4）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs`

#### 2.1 SyscallId 枚举新增 3 个变体（L82 后）

```rust
    /// `zkvm_keccak256(ptr, len, out_ptr)` — Keccak-256 哈希。
    Keccak256 = 0x0B,
    /// `zkvm_modexp(base_ptr, exp_ptr, mod_ptr, out_ptr, num_bits)` — 大数模幂。
    Modexp = 0x0C,
    /// `zkvm_merkle_verify(leaf_ptr, root_ptr, path_ptr, depth)` — Merkle 路径验证。
    MerkleVerify = 0x0D,
```

#### 2.2 `from_u32()` 新增 3 个分支（L101 后）

```rust
            0x0B => Ok(Self::Keccak256),
            0x0C => Ok(Self::Modexp),
            0x0D => Ok(Self::MerkleVerify),
```

#### 2.3 `all()` 返回 `[Self; 13]`（L108-120）

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

#### 2.4 文档注释表格更新（L9-20）

新增 3 行：
```
//! | 0x0B | `keccak256` | (ptr, len, out_ptr) | Keccak-256 哈希 |
//! | 0x0C | `modexp` | (base_ptr, exp_ptr, mod_ptr, out_ptr, num_bits) | 大数模幂 |
//! | 0x0D | `merkle_verify` | (leaf_ptr, root_ptr, path_ptr, depth) | Merkle 路径验证 |
```

模块注释 "10 个 syscall ID 枚举" → "13 个 syscall ID 枚举"。

#### 2.5 `SyscallRegistry.syscalls` 数组 10 → 13（L289）

```rust
    syscalls: [Option<Box<dyn Syscall>>; 13],
```

注释 "10 个 syscall" → "13 个 syscall"。

#### 2.6 `Debug` impl 新增 11/12/13 分支（L298-310）

```rust
                11 => "Keccak256",
                12 => "Modexp",
                13 => "MerkleVerify",
```

#### 2.7 测试更新

- `test_from_u32_all_valid_ids`：新增 3 个断言 `(0x0B, Keccak256)`, `(0x0C, Modexp)`, `(0x0D, MerkleVerify)`
- `test_from_u32_invalid_ids`：`[0x00, 0x0B, 0x0C, 0xFF, 0x100, u32::MAX]` → `[0x00, 0x0E, 0xFF, 0x100, u32::MAX]`
- `test_syscall_id_as_u32`：新增 3 个断言
- `test_all_returns_ten_syscalls` → `test_all_returns_thirteen_syscalls`：`len() == 13`
- `test_syscall_registry_dispatch_invalid_id`：0x0B 现在是合法 ID（但未注册），保留断言但更新注释

### Step 3: 修改 `syscalls/gas.rs`（I-4）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas.rs`

#### 3.1 新增 5 个 gas 常量（L53 后）

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

#### 3.2 `SyscallGasArgs` 新增字段（L62-67）

```rust
pub struct SyscallGasArgs {
    pub input_len: u32,
    pub num_slots: u32,
    /// modexp 指数位数。
    pub num_bits: u32,
    /// merkle_verify 树深度。
    pub depth: u32,
}
```

更新字段文档注释。

#### 3.3 `syscall_gas()` 新增 3 个分支（L102 前）

```rust
        SyscallId::Keccak256 => GAS_ZKVM_KECCAK256_PER_BYTE * args.input_len as u64,
        SyscallId::Modexp => {
            GAS_ZKVM_MODEXP_BASE + GAS_ZKVM_MODEXP_PER_BIT * args.num_bits as u64
        }
        SyscallId::MerkleVerify => GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL * args.depth as u64,
```

#### 3.4 测试更新

- `test_gas_constants_values`：新增 5 个常量断言
- `test_all_syscalls_have_gas`：`SyscallGasArgs` 添加 `num_bits: 8, depth: 3`
- 新增 `test_keccak256_gas_calculation`：`PER_BYTE * input_len`
- 新增 `test_modexp_gas_calculation`：`BASE + PER_BIT * num_bits`
- 新增 `test_merkle_verify_gas_calculation`：`PER_LEVEL * depth`

### Step 4: 修改 `precompiles/mod.rs`（I-4）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs`

#### 4.1 `test_phase10_registry_full`（L341-369）

新增 3 个注册 + 3 个验证：

```rust
registry.register(Box::new(keccak256::Keccak256Circuit::new()));
registry.register(Box::new(modexp::ModexpCircuit::new()));
registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));
```

`assert_eq!(registry.len(), 4)` → `7`。

新增验证：
```rust
// Keccak256 (MVP)
let keccak = registry.get("keccak256").expect("应找到 keccak256");
assert_eq!(keccak.gas_cost(), 10_000);

// Modexp
let modexp = registry.get("modexp").expect("应找到 modexp");

// MerkleVerify
let merkle = registry.get("merkle_verify").expect("应找到 merkle_verify");
```

#### 4.2 `test_phase10_all_implement_both_traits`（L373-393）

新增 3 个 trait 检查：
```rust
let keccak = keccak256::Keccak256Circuit::new();
let _: &dyn PrecompileCircuit = &keccak;
let _: &dyn CcsCircuit = &keccak;

let modexp = modexp::ModexpCircuit::new();
let _: &dyn PrecompileCircuit = &modexp;
let _: &dyn CcsCircuit = &modexp;

let merkle = merkle_verify::MerkleVerifyCircuit::new();
let _: &dyn PrecompileCircuit = &merkle;
let _: &dyn CcsCircuit = &merkle;
```

#### 4.3 `test_phase10_gas_costs_reasonable`（L397-419）

注册 3 个新预编译，新增 3 个 gas 范围检查：
```rust
("keccak256", 5_000, 15_000),       // MVP ~10k
("modexp", 50_000, 200_000),        // base 50k + per_bit
("merkle_verify", 50, 5_000),       // per_level * depth
```

### Step 5: 全量验证

```bash
# 1. keccak256 测试（含调试）
cargo test -p poker_zkvm --lib precompiles::keccak256 -- --nocapture

# 2. modexp 测试
cargo test -p poker_zkvm --lib precompiles::modexp

# 3. merkle_verify 测试
cargo test -p poker_zkvm --lib precompiles::merkle_verify

# 4. 全部预编译测试
cargo test -p poker_zkvm --lib precompiles

# 5. syscall gas + mod 测试
cargo test -p poker_zkvm --lib syscalls::gas
cargo test -p poker_zkvm --lib syscalls::mod

# 6. clippy（无警告）
cargo clippy -p poker_zkvm --lib -- -D warnings

# 7. 全量回归（不含 ignored）
cargo test -p poker_zkvm --lib

# 8. ignored 测试（release 模式，手动运行）
cargo test -p poker_zkvm --release --lib precompiles::keccak256 -- --ignored
```

## Assumptions & Decisions

| 决策点 | 选择 | 理由 |
|--------|------|------|
| keccak256 调试方法 | 先运行测试确认，再按需调试 | 静态分析未发现 bug，可能上次运行后修复已生效 |
| 调试工具 | Python pycryptodome `Crypto.Hash.keccak` | 不需添加 Rust 依赖，可直接验证 |
| SyscallId 扩展 | 新增 0x0B-0x0D | Stage 4 计划明确要求 |
| SyscallGasArgs 扩展 | 新增 `num_bits` + `depth` | modexp/merkle 需要参数化 gas |
| `all()` 数组大小 | 10 → 13 | 新增 3 个变体 |
| `syscalls` 数组大小 | 10 → 13 | `dispatch` 用 `id as usize - 1` 索引 |
| 预编译注册 | 仅在测试中注册 | `PrecompileRegistry` 是测试用基础设施 |
| `test_syscall_registry_dispatch_invalid_id` | 保留 0x0B 断言，更新注释 | 0x0B 现为合法但未注册，仍返回错误 |

## Implementation Order

1. **Step 1.1**: 运行 `test_host_keccak256_abc` 确认状态
2. **Step 1.2-1.4**: 如果失败，用 Python 验证 → 添加调试测试 → 修复 bug
3. **Step 2**: 修改 `syscalls/mod.rs`（SyscallId + from_u32 + all + 数组 + Debug + 测试）
4. **Step 3**: 修改 `syscalls/gas.rs`（常量 + SyscallGasArgs + syscall_gas + 测试）
5. **Step 4**: 修改 `precompiles/mod.rs`（3 个测试注册新预编译）
6. **Step 5**: 按验证步骤 1-8 依次执行

## Out of Scope

- bn254 pairing — 留待 Phase I Batch 2
- ed25519 — 留待后续批次
- bls12-381 pairing — 留待后续批次
- keccak256 Full 模式多块吸收 — 仅支持单块（input ≤ 136 bytes）
- `host::create_full_registry()` — 不修改，新 ID 为预编译非 syscall
- 新预编译的 host_execute 实现 — 仅注册电路，不实现 syscall dispatch
