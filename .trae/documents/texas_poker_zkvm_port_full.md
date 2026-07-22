# Texas Poker → ZKVM 移植完整方案（Phase 1-5）

> **目标**：将 `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker`（11 个文件，7,961 行 Rust）改写为可在 `poker_zkvm` 中以 RV32I ELF 运行的 guest 程序，并运行测试验证。
>
> **方案**：Rust no_std 编译为 `riscv32i-unknown-none-elf` target → 用 `goblin` 解析为 RV32I 指令 → 在 poker_zkvm 上执行。
>
> **用户已批准范围**：完整 Phase 1-5；guest_sdk 与 guests/texas_poker 采用**独立 workspace**（不加入 zchain workspace.members）。

---

## 当前状态分析

### 已就绪（Phase 1 前置）

- **guest_sdk crate 完整存在**：`poker_zkvm/guest_sdk/` 含 9 个 src 文件（lib.rs + syscalls.rs + allocator.rs + entry.rs + bls.rs + hash.rs + io.rs + game.rs + prelude.rs），21 个 syscall 常量与 host `SyscallId` 完全对齐
- **guests/texas_poker 骨架存在**：Cargo.toml + `.cargo/config.toml`（target=riscv32i-unknown-none-elf）+ src/main.rs（`zkvm_main` 返回 `Ok(alloc::vec![0x42])`）
- **nightly-2026-04-15 + riscv32i-unknown-none-elf target 已安装**

### 当前阻塞（Phase 1.1）

`cargo +nightly-2026-04-15 build --release` 失败：

```
error: current package believes it's in a workspace when it's not:
current:   /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker/Cargo.toml
workspace: /Users/mac/projects/zchain/Cargo.toml
```

**根因**：`zchain/Cargo.toml` 的 `workspace.members = ["poker_l1", "poker_zkvm", "vm-common"]` 未包含 `poker_zkvm/guest_sdk` 与 `poker_zkvm/guests/texas_poker`，cargo 沿目录树向上找到 zchain workspace 但二者未声明归属。

### host 端能力盘点

- **已实现 21 个 host syscall**（`create_full_registry` 注册）：0x01-0x0A（10 个基础）+ 0x10-0x15（6 个 BLS12-381）+ 0x20-0x21（2 个 GameState mock）+ 0x30-0x32（3 个 Game-specific）
- **未实现 5 个 syscall**（slot 为 None）：0x0B KECCAK256 / 0x0C MODEXP / 0x0D MERKLE_VERIFY / 0x0E ED25519_VERIFY / 0x0F BN254_PAIRING
- **ReadInputSyscall 实际 ABI**（`host.rs:86-117`）：a0=ptr（写入目标，0 时回退 HEAP_START）、a1=len，返回 a0=write_addr、a1=actual_len。**guest 用 4 字节 LE 长度前缀约定无需改 host**
- **elf_validator 11 项校验**（`compiler/elf_validator.rs:46-100`）：ELF32+LE+EM_RISCV、无 PT_DYNAMIC、无 DT_NEEDED、段地址 checked_add 防 wrap、段不重叠、总内存 ≤16MB、entry 在 text 内、text ≤8MB、RV32I 指令子集（拒绝 compressed/fence.i/CSR/浮点/atomics）
- **execute_elf_with_limits_and_config**（`isa/executor.rs:173`）：validate → load_elf → 执行循环 → 返回 `ExecuteResult { trace, output, events, logs }`

### 源码依赖分析（texas_poker 11 文件）

| 文件 | 行数 | 类型 | 关键依赖 | 移植难度 |
|------|------|------|---------|---------|
| constants.rs | 145 | 纯常量 | 无 | 低 |
| card.rs | 219 | 纯逻辑 | borsh/serde（仅 derive） | 低 |
| hand_evaluator.rs | 635 | 纯逻辑 | 无 | 低 |
| betting.rs | 296 | 纯逻辑 | 无 | 低 |
| side_pot.rs | 535 | 纯逻辑 | 无 | 低 |
| events.rs | 710 | 数据结构 | borsh/serde + crate::object_model::ObjectID + crate::Address | 中 |
| types.rs | 794 | 数据结构 | borsh/serde + blstrs + poker_protocol::crypto::types + crate::object_model + crate::Address | 高 |
| utils.rs | 718 | crypto 适配 | blstrs + sha3 + poker_protocol::zk_shuffle::transcript_ext + poker_protocol::crypto::types | 高 |
| state_machine.rs | 2,814 | 业务逻辑 | poker_protocol::zk_shuffle::* (DLEqProof/ReconstructProof/RevealTokenProof/ZKShuffleProof) + blstrs + utils + types | 极高 |
| dispatch.rs | 1,046 | 路由 | blake2::Blake2bVar + poker_protocol::zk_shuffle::* + crate::vm::contracts::dispatch + crate::signature | 极高 |
| mod.rs | 49 | 模块声明 | 无 | 低 |

### guest_sdk 类型设计完备性评估

`bls.rs` 现有：G1Point(48B) / Scalar(32B BE) / ElGamalCiphertext(96B)，含 hash_to_curve / add / mul / eq / hash_to_scalar。

**缺口**（Phase 3 需补全）：
- Scalar 标量运算：add/sub/mul/neg/inv/from_u64（host 缺相应 syscall → 见 D2 决策）
- G1Point 辅助：identity/generator/sub（generator/identity 需常量预置或新增 syscall）
- 独立基点 H：`hash_to_g1("texas_poker_independent_base_H")` 可用现有 hash_to_curve 实现

---

## 假设与决策

### D1: 独立 workspace（用户批准）

在 `poker_zkvm/guest_sdk/Cargo.toml` 与 `poker_zkvm/guests/texas_poker/Cargo.toml` 末尾各加**空 `[workspace]` 表**，使两个 crate 独立于 zchain workspace，避免 no_std + riscv32i target 与 workspace 其他 std crate 的 target/feature 污染。

### D2: host 端 syscall 缺口补全策略

**Phase 3 必需新增 1 个 host syscall**：

| 新 syscall | ID | 用途 | 来源 |
|-----------|----|----|----|
| `sha3_256` | 0x16 | utils.rs::hash_to_scalar 用 SHA3-256 (M-P18) | 新增到 SyscallId + host 实现 |

> 备选方案：用现有 `bls_hash_to_scalar` (0x15) 直接替代。但 0x15 的实现若非 M-P18 算法会破坏 utils.rs 兼容性。Phase 3 起始时先**校验 host 端 bls_hash_to_scalar 实现是否==M-P18**，若是则复用，若否则新增 0x16 SHA3-256。

**Phase 4 必需新增 3 个 Mental Poker proof verify syscall**：

| 新 syscall | ID | 用途 |
|-----------|----|----|
| `verify_dleq_proof` | 0x33 | DLEqProof（Leave/Remask）验证 |
| `verify_reconstruct_proof` | 0x34 | ReconstructProof 验证 |
| `verify_reveal_token_proof` | 0x35 | RevealTokenProof 验证 |

> ZKShuffleProof 已有 0x32 SHUFFLE_VERIFY。新增 3 个 syscall 复用 host 端 `poker_protocol::zk_shuffle::*` 验证逻辑（host 是 std，可自由依赖）。

**Phase 4 必需新增 1 个 hash syscall**：

| 新 syscall | ID | 用途 |
|-----------|----|----|
| `blake2b_256` | 0x17 | dispatch.rs::compute_method_selector（32B blake2b 变长输出） |

### D3: borsh/serde 处理

texas_poker 大量使用 `#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]`。**guest 内不需要跨进程序列化**（数据通过 syscall 字节流传递）。

策略：
- **borsh**：在 guest crate 加 `borsh = { version = "1", default-features = false, features = ["derive"] }` 依赖（borsh 0.11+ 支持 no_std + alloc）。需在 guest Cargo.toml 显式启用。
- **serde**：guest 内**不使用 serde**。移除 derive，事件序列化用 borsh 替代（events.rs 中 `#[derive(Serialize, Deserialize)]` 可删，仅保留 borsh）。

### D4: poker_protocol 依赖移除

guest **不依赖 `poker_protocol` crate**（它依赖 blstrs/halo2curves/rayon/merlin/curve25519-dalek，全部非 no_std 或不适合 ZKVM）。

策略：
- `poker_protocol::crypto::types::{ECPoint, ECScalar, ElGamalCiphertext}` → 替换为 `guest_sdk::bls::{G1Point, Scalar, ElGamalCiphertext}`
- `poker_protocol::zk_shuffle::*Proof` → 替换为 `Vec<u8>` 字节流（guest 仅把 proof 透传给 host syscall 验证，不解析内部结构）
- `poker_protocol::zk_shuffle::transcript_ext::MerlinTranscript` → 完全移除，proof 由 host 端构造 transcript（host 持有原始字节 + proof）

### D5: crate::object_model::ObjectID / crate::Address / crate::signature 处理

guest 不依赖 zchain 节点 native 类型：

- `crate::Address = [u8; 20]` → 在 guest crate 内 `type Address = [u8; 20];`
- `crate::object_model::ObjectID` → 在 guest crate 内 `type ObjectID = [u8; 32];`（与 zchain 一致）
- `crate::signature::TaggedPubkey` / `crate::vm::contracts::dispatch::{DispatchContext, DispatchResult}` → dispatch.rs 重写，guest 内 dispatch 逻辑大幅简化（详见 Phase 4）

### D6: 输入/输出格式约定

- **输入**：`[4 字节 LE 长度 N][N 字节 method_call 二进制]`。method_call 二进制为 borsh 序列化的 `(method_selector: [u8;32], args_bytes: Vec<u8>)`。
- **输出**：`zkvm_main` 返回 `Ok(Vec<u8>)`，由 `commit_output` 写出。失败时 `panic_msg` 终止。
- 输入 buffer 64KB（`MAX_INPUT_SIZE`，与 host 一致）。

### D7: 测试策略

- **Phase 1**：poker_zkvm 集成测试 `tests/texas_poker_guest_phase1.rs`，加载编译后的 ELF，validate + execute，断言 `output == [0x42]`
- **Phase 2**：guest crate 内单元测试 `#[cfg(test)]`，用 `std-test` feature 在 host std 模式编译纯逻辑（避开 riscv32i target 不支持 cargo test 的限制）
- **Phase 3-4**：guest crate 单元测试 + poker_zkvm 集成测试（输入构造 + 输出断言）
- **Phase 5**：性能基准对比 `build_texas_poker_full_hand_elf`（217 条手写指令）

---

## Phase 1: SDK 链路修复 + 最小可执行验证

### 1.1 修复 workspace 冲突（D1）

**文件改动**：
- `poker_zkvm/guest_sdk/Cargo.toml`：末尾追加空 `[workspace]` 表
- `poker_zkvm/guests/texas_poker/Cargo.toml`：末尾追加空 `[workspace]` 表

```toml
# 在文件末尾追加（两个文件都加）
[workspace]
```

### 1.2 编译 guest 为 RV32I ELF

```bash
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker
cargo +nightly-2026-04-15 build --release
```

预期产物：`target/riscv32i-unknown-none-elf/release/texas_poker_guest`

### 1.3 编写 Phase 1 集成测试

**新增文件**：`poker_zkvm/tests/texas_poker_guest_phase1.rs`

```rust
#![cfg(feature = "test-helpers")]
use poker_zkvm::compiler::elf_validator::validate_elf;
use poker_zkvm::isa::executor::execute_elf;
use std::path::PathBuf;

fn guest_elf_path() -> PathBuf {
    // poker_zkvm/guests/texas_poker/target/riscv32i-unknown-none-elf/release/texas_poker_guest
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("guests/texas_poker/target/riscv32i-unknown-none-elf/release/texas_poker_guest");
    p
}

#[test]
fn test_phase1_guest_elf_compiles() {
    let elf_path = guest_elf_path();
    assert!(elf_path.exists(), "guest ELF 未找到：先在 guests/texas_poker 执行 cargo build --release");
}

#[test]
fn test_phase1_validate_elf_passes() {
    let elf = std::fs::read(guest_elf_path()).expect("read elf");
    let metadata = validate_elf(&elf).expect("ELF 校验应通过 11 项检查");
    assert!(metadata.entry > 0);
    assert!(metadata.text.is_some());
}

#[test]
fn test_phase1_execute_returns_0x42() {
    let elf = std::fs::read(guest_elf_path()).expect("read elf");
    let input = vec![0u8; 4]; // 4 字节 LE 长度 0（空输入）
    let result = execute_elf(&elf, &input).expect("execute");
    assert_eq!(result.output, vec![0x42]);
}
```

### 1.4 验证步骤

```bash
# 1. 编译 guest
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
# 2. 跑集成测试
cd /Users/mac/projects/zchain && cargo test -p poker_zkvm --features test-helpers --test texas_poker_guest_phase1 -- --nocapture
```

**Phase 1 完成判据**：
- guest ELF 编译成功
- `validate_elf` 通过 11 项校验
- `execute_elf` 返回 `output == [0x42]`

---

## Phase 2: 纯逻辑移植（5 文件，~1,830 行）

### 2.1 新增 guest crate 模块

**文件**：`guests/texas_poker/src/main.rs` 增加模块声明；新建对应文件。

```
guests/texas_poker/src/
├── main.rs           (扩展)
├── constants.rs      (从 poker_l1 复制，无改动)
├── card.rs           (复制 + 删 serde derive)
├── hand_evaluator.rs (复制，无改动)
├── betting.rs        (复制，无改动)
└── side_pot.rs       (复制，无改动)
```

### 2.2 文件移植清单

| 源文件 | 目标文件 | 改动 |
|--------|---------|------|
| `poker_l1/.../texas_poker/constants.rs` | `guests/texas_poker/src/constants.rs` | 直接复制，无依赖 |
| `poker_l1/.../texas_poker/card.rs` | `guests/texas_poker/src/card.rs` | 删 `use serde::{Deserialize, Serialize}` 和 derive；保留 borsh derive（需 D3 在 guest Cargo.toml 加 borsh 依赖） |
| `poker_l1/.../texas_poker/hand_evaluator.rs` | `guests/texas_poker/src/hand_evaluator.rs` | 直接复制 |
| `poker_l1/.../texas_poker/betting.rs` | `guests/texas_poker/src/betting.rs` | 直接复制 |
| `poker_l1/.../texas_poker/side_pot.rs` | `guests/texas_poker/src/side_pot.rs` | 直接复制 |

### 2.3 guest Cargo.toml 加 borsh 依赖

```toml
[dependencies]
zkvm_guest_sdk = { path = "../../guest_sdk" }
borsh = { version = "1", default-features = false, features = ["derive"] }
```

### 2.4 单元测试（std-test feature）

guest crate 加 `[features] std-test = []`，在 `src/lib.rs` 或 `src/main.rs` 加 `#[cfg(feature = "std-test")] extern crate std;`，纯逻辑测试在 `std-test` feature 下编译为 host std 单元测试。

测试用例至少：
- `card::Card::is_valid` 边界（2/14/15、suit 0/3/4）
- `hand_evaluator::evaluate_best_5_of_7` 10 种牌型各一例
- `betting::BettingRound` 状态转换
- `side_pot` 边池 M-A3 empty eligible 合并

### 2.5 验证步骤

```bash
# 1. riscv32i 编译
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
# 2. host std 单元测试
cargo +nightly-2026-04-15 test --features std-test
```

---

## Phase 3: crypto utils + types + events 移植（3 文件，~2,222 行）

### 3.1 host 端：先校验 bls_hash_to_scalar (0x15) 是否 == M-P18

读取 `poker_zkvm/src/syscalls/bls12381.rs` 中 `Bls12381HashToScalarSyscall` 实现：
- **若算法 == SHA3-256 + 清高 2 位**：guest 直接用 `bls_hash_to_scalar` syscall，无需新增 SHA3-256 syscall
- **若算法 != M-P18**：按 D2 新增 `sha3_256` syscall (0x16)，在 host.rs 新增 `Sha3_256Syscall` 用 `sha3::Sha3_256`

### 3.2 guest_sdk 类型补全（`bls.rs`）

补全 Scalar 标量运算 + G1Point 辅助方法。**所有运算经 syscall**（不在 guest 内做模运算）：

- 新增 host syscall（D2 决策）：`bls_scalar_add/sub/mul` (0x18-0x1A)、`bls_g1_sub` (0x1B)、`bls_g1_generator/identity` (0x1C 单 syscall 返回 96B)
- 或：合并为 `bls_scalar_op(op: u8, a, b, out)` 单 syscall（节省 ID 空间）

guest_sdk bls.rs 扩展：
```rust
impl Scalar {
    pub fn add(&self, other: &Self) -> Self { /* syscall */ }
    pub fn sub(&self, other: &Self) -> Self { /* syscall */ }
    pub fn mul(&self, other: &Self) -> Self { /* syscall */ }
    pub fn from_u64(x: u64) -> Self { /* 在 guest 内构造大端字节，无 syscall */ }
    pub fn one() -> Self { /* 常量 [0,...,0,1] */ }
}
impl G1Point {
    pub fn generator() -> Self { /* syscall 0x1C 或常量预置 */ }
    pub fn identity() -> Self { /* 常量 [0;48] */ }
    pub fn sub(&self, other: &Self) -> Self { /* syscall 0x1B */ }
}
```

### 3.3 utils.rs 移植

**目标**：`guests/texas_poker/src/utils.rs`

策略：
- 删 `blstrs`、`ff`、`group`、`subtle`、`sha3`、`poker_protocol::*` 依赖
- 所有 G1/Scalar 操作改用 `guest_sdk::bls::{G1Point, Scalar}`
- `hash_to_scalar` → `Scalar::hash_to_scalar(data)`（syscall 0x15 或 0x16，按 3.1 决策）
- `hash_to_g1` → `G1Point::hash_to_curve(msg)`（syscall 0x10）
- `g1_add/sub/mul/eq/is_identity` → `G1Point::add/sub/mul/eq` + `G1Point::identity()` 字节比较
- `parse_g1` / `serialize_g1` → `G1Point::from_bytes` / `G1Point::as_bytes`（无 syscall）
- `verify_or_skip` → 完全删除（guest 内**永远不跳过** verify，所有 verify 经 syscall）
- `MerlinTranscript` 工厂函数 → 删除（proof 验证完全交给 host，guest 只传 proof 字节给 syscall）
- `verify_pk_ownership` (80B Schnorr) → 新增 host syscall `verify_schnorr_pk` (0x1D)，或 Phase 5 实现

### 3.4 types.rs 移植

**目标**：`guests/texas_poker/src/types.rs`

策略：
- 删 `borsh`/`serde` derive 中的 serde，保留 borsh
- 删 `blstrs::G1Projective` / `poker_protocol::crypto::types::{ECPoint, ECScalar, ElGamalCiphertext}` 导入
- 替换为 `guest_sdk::bls::{G1Point, Scalar, ElGamalCiphertext}`
- `crate::object_model::ObjectID` → `crate::ObjectID`（D5，guest crate 内 `type ObjectID = [u8; 32]`）
- `crate::Address` → guest crate 内 `type Address = [u8; 20]`
- 所有 phase 常量从 `super::constants::*` 导入（Phase 2 已就位）

### 3.5 events.rs 移植

**目标**：`guests/texas_poker/src/events.rs`

策略：
- 删 serde derive，保留 borsh
- 删 `crate::object_model::ObjectID` / `crate::Address`，用 guest crate 本地类型别名
- 事件枚举 `TexasPokerEvent` 保持不变（仅 derive 调整）

### 3.6 验证步骤

```bash
# 1. riscv32i 编译
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
# 2. host std 单元测试（types/utils 加 ser/de round-trip 测试）
cargo +nightly-2026-04-15 test --features std-test
# 3. 集成测试：调用 utils 函数，验证 syscall 链路
cd /Users/mac/projects/zchain && cargo test -p poker_zkvm --features test-helpers --test texas_poker_guest_phase1
```

---

## Phase 4: state_machine + dispatch 移植（2 文件，~3,860 行）

### 4.1 host 端：新增 Mental Poker proof verify syscall（D2）

**文件改动**：
- `poker_zkvm/src/syscalls/mod.rs`：SyscallId 枚举新增 4 个变体（0x33 DLEQ / 0x34 RECONSTRUCT / 0x35 REVEAL_TOKEN / 0x17 BLAKE2B_256）+ from_u32 / sparse_index / TOTAL_COUNT 调整（26 → 30）
- `poker_zkvm/src/syscalls/host.rs`：新增 4 个 host syscall 实现
  - `Blake2b256Syscall` (0x17)：用 `blake2::Blake2bVar`，与 dispatch.rs 算法一致
  - `VerifyDleqProofSyscall` (0x33)：调用 `poker_protocol::zk_shuffle::dleq_proof::DLEqProof::verify`
  - `VerifyReconstructProofSyscall` (0x34)：调用 `ReconstructProof::verify`
  - `VerifyRevealTokenProofSyscall` (0x35)：调用 `RevealTokenProof::verify`
- `poker_zkvm/src/syscalls/host.rs::create_full_registry`：注册 4 个新 syscall
- `poker_zkvm/src/syscalls/gas.rs`：4 个新 syscall 的 gas 估算

**guest_sdk 同步**：
- `guest_sdk/src/syscalls.rs`：id 模块新增 4 个常量
- `guest_sdk/src/syscalls.rs`：新增 4 个高层封装函数 `blake2b_256` / `verify_dleq_proof` / `verify_reconstruct_proof` / `verify_reveal_token_proof`
- `guest_sdk/src/hash.rs`：新增 `blake2b_256` 便捷函数

### 4.2 state_machine.rs 移植

**目标**：`guests/texas_poker/src/state_machine.rs`

策略（核心：所有 poker_protocol::zk_shuffle::*Proof 替换为 `Vec<u8>` 字节流，所有 verify 经 syscall）：

- 删 `poker_protocol::zk_shuffle::*Proof` 导入，proof 类型全部替换为 `Vec<u8>` 或 `&[u8]`
- 删 `poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript}` 导入
- 删 `blstrs::G1Projective` / `group::Group` 导入，改用 `guest_sdk::bls::{G1Point, Scalar, ElGamalCiphertext}`
- `utils::g1_add/g1_mul/g1_sub/g1_equal/g1_is_identity/hash_to_scalar/scalar_from_u64/g1_generator/g1_identity` → 调用 Phase 3 移植后的 utils（或直接调 guest_sdk::bls 方法）
- proof 验证：原 `proof.verify(transcript)` → `guest_sdk::syscalls::verify_dleq_proof(proof_bytes, ...)` 等
- `PokerL1Error` / `PokerL1Result` → guest crate 内自定义简单 error enum（或直接用 `&'static str`），保留 `Result<T, &'static str>` 风格
- 2,814 行函数体本身**尽量保持逐行对应**，只做类型替换

### 4.3 dispatch.rs 移植

**目标**：`guests/texas_poker/src/dispatch.rs`

策略（核心：dispatch 简化为 guest 内入口分发）：

- 删 `blake2::Blake2bVar` 直接使用，改用 `guest_sdk::hash::blake2b_256`（Phase 4.1 新增）
- 删 `crate::vm::contracts::dispatch::{DispatchContext, DispatchResult}` 依赖，guest 内 `DispatchResult` 简化为 `struct { events: Vec<TexasPokerEvent> }`
- 删 `crate::signature::TaggedPubkey` / `crate::object_model::ObjectID` / `crate::Address` / `crate::BlockHeight` / `crate::ChainId`，全部用 guest crate 本地别名或简化类型
- `compute_method_selector` 算法不变（blake2b_256），底层换 syscall
- 17 个 method handler 函数体保留，仅替换依赖类型

### 4.4 main.rs 接入 dispatch

```rust
#![no_std]
#![no_main]
extern crate alloc;
use alloc::vec::Vec;
zkvm_guest_sdk::entry_point!();

mod constants;
mod card;
mod hand_evaluator;
mod betting;
mod side_pot;
mod events;
mod types;
mod utils;
mod state_machine;
mod dispatch;

#[no_mangle]
pub extern "Rust" fn zkvm_main(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    // 输入: [32B method_selector][borsh args_bytes]
    if input.len() < 32 {
        return Err("input too short");
    }
    let selector: &[u8; 32] = input[..32].try_into().map_err(|_| "bad selector")?;
    let args = &input[32..];
    let result = dispatch::route(selector, args)?;
    borsh::to_vec(&result.events).map_err(|_| "borsh serialize failed")
}
```

### 4.5 验证步骤

```bash
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
# 集成测试：构造一个 method call（如 create_table），执行 ELF，断言 output
cd /Users/mac/projects/zchain && cargo test -p poker_zkvm --features test-helpers --test texas_poker_guest_phase4
```

---

## Phase 5: 完整 Mental Poker E2E + 性能基准

### 5.1 完整一手牌 E2E 测试

**新增文件**：`poker_zkvm/tests/texas_poker_guest_e2e.rs`

测试场景（参照现有 `texas_poker_full_hand_bench.rs` 流程）：
1. `create_table` → `join_table` × 2 → `start_hand`
2. `join_and_shuffle` × 2（含 shuffle proof 验证）
3. `post_blinds` → 下注轮（fold/check/call/raise）
4. reveal phase × 4（preflop/flop/turn/river）
5. showdown → `settle_hand`
6. 断言：winner 正确、events 数量正确、output 序列化正确

### 5.2 性能基准

**新增文件**：`poker_zkvm/benches/texas_poker_guest_full_hand.rs`

测量项：
- ELF 字节数（与 `build_texas_poker_full_hand_elf` 217 条手写指令对比）
- trace 步数
- `execute_elf` 时间
- `trace_to_native` + `trace_to_memory_trace` 转换时间
- `prove_cpu_trace` / `prove_cpu_memory_trace` 时间
- `verify_cpu_proof` / `verify_cpu_memory_proof` 时间
- proof 字节数

输出格式参照 `PerfReport`（CSV + 表格）。

### 5.3 与现有 MVP 对比报告

在 `texas_poker_guest_full_hand.rs` 末尾打印对比：
- 现有 `build_texas_poker_full_hand_elf`（217 条手写指令）vs 新 guest ELF
- trace 步数比、prove 时间比、proof 大小比

### 5.4 验证步骤

```bash
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
cd /Users/mac/projects/zchain
# E2E 测试
cargo test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture --ignored
# 性能基准
cargo bench -p poker_zkvm --features test-helpers --bench texas_poker_guest_full_hand
```

**Phase 5 完成判据**：
- E2E 测试通过（winner 正确、events 完整）
- 性能基准产出完整报告
- 与 MVP 对比可读

---

## 风险与缓解

### R1: riscv32i-unknown-none-elf 不支持某些 Rust 特性

- **风险**：std::format! / println! 不可用，浮点不可用，atomic 操作需配置
- **缓解**：guest 内禁用 std::format（用 guest_sdk::syscalls::log 替代）、禁用浮点（texas_poker 纯整数逻辑）、riscv32i target 默认无 atomic（BumpAlloc 用 AtomicU32 可能需改 `target_feature = "disable-atomics"` 或换 non-atomic 实现）

### R2: borsh no_std + alloc 在 riscv32i 上可能 panic

- **风险**：borsh 依赖某些 std trait
- **缓解**：Phase 2 先验证 borsh 1.x 在 riscv32i target 下能编译；若失败则手动实现关键 struct 的 to_bytes/from_bytes（避免 borsh）

### R3: state_machine.rs 2,814 行移植引入回归

- **风险**：逐行类型替换易出错
- **缓解**：每个函数移植后立即在 std-test feature 下跑单元测试，对比 poker_l1 原版输出

### R4: host 端新增 syscall 引入 bug

- **风险**：D2 新增的 7 个 host syscall（SHA3-256/Blake2b256/DLEq/Reconstruct/RevealToken + 可能的 Scalar 算术）实现错误
- **缓解**：每个新 syscall 在 `host.rs` 的 `#[cfg(test)] mod tests` 中加单元测试，覆盖正常/异常/边界

### R5: 性能 — guest ELF 可能远大于 217 条手写指令

- **风险**：Rust no_std release 编译产物可能数十 KB（远大于 MVP 的 ~1KB），prove 时间显著增加
- **缓解**：启用 LTO=fat + codegen-units=1 + strip=symbols + opt-level=3 + overflow-checks=false（已在 Cargo.toml 配置）；若 prove 时间过长，Phase 5 评估是否拆分为多个 guest（每个 method 一个 ELF）

---

## 跨阶段一致性检查清单

每个 Phase 完成后，确认：
- [ ] guest crate `cargo +nightly-2026-04-15 build --release` 成功
- [ ] `validate_elf` 通过 11 项校验
- [ ] `execute_elf` 在合理步数内完成（不超 step_limit）
- [ ] std-test feature 下单元测试全绿
- [ ] poker_zkvm 集成测试全绿
- [ ] SyscallId 常量（host + guest_sdk）一一对应
- [ ] 文档（mod.rs 顶部注释）反映当前 Phase 状态

---

## 实施顺序总结

```
Phase 1: workspace 修复 + ELF 编译 + [0x42] 验证（最小可运行）
   ↓
Phase 2: 5 个纯逻辑文件移植 + 单元测试
   ↓
Phase 3: host 校验 bls_hash_to_scalar + guest_sdk 类型补全 + utils/types/events 移植
   ↓
Phase 4: host 新增 4 syscall（Blake2b256 + 3 proof verify）+ state_machine + dispatch 移植
   ↓
Phase 5: E2E 完整一手牌 + 性能基准 + 对比报告
```

**预估工作量**：Phase 1 (1h) / Phase 2 (4h) / Phase 3 (8h) / Phase 4 (16h) / Phase 5 (6h)，合计 ~35h。
