# poker_zkvm — Hypernova + CCS 零知识虚拟机

基于 Hypernova 折叠协议与 CCS（Customizable Constraint System）的零知识虚拟机，用于 zchain OffChain 模式的状态转换验证。

严格遵循 `build-hypernova-zkvm` spec v1.4（FROZEN）。

## 架构概览

```
┌─────────────────────────────────────────────────────────┐
│  Layer 0  field / transcript / error                     │
│           BN254 标量域 + Fiat-Shamir transcript           │
├─────────────────────────────────────────────────────────┤
│  Layer 1  pcs — IPA over BN254（NUMS generators）         │
├─────────────────────────────────────────────────────────┤
│  Layer 2  compiler / isa / trace / syscalls              │
│           ELF 校验 → RV32I 执行 → Trace → 10 个 Syscall   │
├─────────────────────────────────────────────────────────┤
│  Layer 3  ccs / lookup / constraints                     │
│           CCS 约束系统 + LogUp lookup + Trace→CCS 编译    │
├─────────────────────────────────────────────────────────┤
│  Layer 3.5  fold — Hypernova 折叠                         │
│           LCCCS + CCCCS + fold_step + sumcheck + fold_loop│
├─────────────────────────────────────────────────────────┤
│  Layer 4  hypernova / cyclic                             │
│           折叠协议 + 曲线 cycle（BN254 / Grumpkin）       │
├─────────────────────────────────────────────────────────┤
│  Layer 5  precompiles / prover / verifier                │
│           4 预编译电路 + 端到端 prove/verify              │
├─────────────────────────────────────────────────────────┤
│  Layer 6  cyclegfold / recursion                         │
│           CycleFold 递归聚合 + BN254/Grumpkin 镜像电路    │
└─────────────────────────────────────────────────────────┘
```

## 快速上手

### 构建

```bash
# 编译 crate
cargo build -p poker_zkvm

# 启用测试辅助（含 test_helpers 模块 + 共享 ELF 构建器）
cargo build -p poker_zkvm --features test-helpers
```

### 基本用法 — Prove + Verify

```rust
use poker_zkvm::prover::{prove, ProverConfig};
use poker_zkvm::verifier::verify_production;

let elf_bytes: &[u8] = /* RV32I ELF32 二进制 */;
let input: &[u8] = /* 程序输入 */;
let config = ProverConfig::default(); // batch_size=3 (MVP)

// 1. 生成证明
let (proof_bytes, public_io) = prove(elf_bytes, input, &config)
    .expect("prove 失败");

// 2. 验证证明
let ccs_registry = poker_zkvm::prover::default_ccs_registry();
let ok = verify_production(&proof_bytes, &public_io, &ccs_registry)
    .expect("verify 错误");
assert!(ok);
```

### 运行示例

```bash
# Fibonacci 电路（计算第 N 个 Fibonacci 数）
cargo run -p poker_zkvm --example fibonacci -- 100

# SHA-256 哈希链（迭代 N 次）
cargo run -p poker_zkvm --example sha256_chain -- 10

# 扑克牌型评估（5 张牌面值求和）
cargo run -p poker_zkvm --example poker_hand_eval
```

### 测试

```bash
# 全部测试（含 E2E + soundness）
cargo test -p poker_zkvm --features test-helpers

# 仅 E2E 测试
cargo test -p poker_zkvm --features test-helpers --test e2e_fibonacci
cargo test -p poker_zkvm --features test-helpers --test e2e_sha256_chain
cargo test -p poker_zkvm --features test-helpers --test e2e_poker_hand_eval

# Soundness 负向测试
cargo test -p poker_zkvm --features test-helpers --test soundness_tests

# Clippy
cargo clippy -p poker_zkvm --features test-helpers --all-targets -- -D warnings
```

### 性能基准

```bash
cargo bench -p poker_zkvm --features test-helpers --bench phase12_benchmarks -- --quick
```

基准结果（MVP batch_size=3）：

| 步数 | Prover 时间 | Proof 大小 | Verifier 时间 |
|------|------------|-----------|--------------|
| 100  | 3.4 ms     | 1562 B    | 519 µs       |
| 500  | 12.6 ms    | 1562 B    | 513 µs       |
| 1000 | 24.3 ms    | 1562 B    | 505 µs       |

Prover 时间随步数线性增长；Proof 大小和 Verifier 时间均为常数（Hypernova succinctness）。

## 核心 API

### Prover

```rust
pub fn prove(
    elf_bytes: &[u8],
    input: &[u8],
    config: &ProverConfig,
) -> Result<(Vec<u8>, ZkPublicIo), ZkvmError>;
```

Pipeline：`validate_elf` → `execute_elf` → `compile_trace_to_ccs` → `fold_loop` → `serialize_proof`

### Verifier

```rust
pub fn verify_production(
    proof_bytes: &[u8],
    public_io: &ZkPublicIo,
    ccs_registry: &[crate::ccs::Ccs],
) -> Result<bool, ZkvmError>;
```

Pipeline：`deserialize_proof` → 重建 `IpaPcs` → `sumcheck::verify` → `pcs.verify`

### ProverConfig

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `batch_size` | `usize` | `3` | 每 batch 步数（MVP: `batch_size+1` 须为 2 的幂） |
| `max_n_vars` | `usize` | `20` | IPA PCS 最大变量数（N = 2^max_n_vars ≤ 2^24） |
| `proof_size_limit` | `usize` | `65536` | Proof 字节数上限（64KB） |
| `max_recursion_depth` | `u32` | `16` | CycleFold 递归深度上限 |

## Feature Flags

| Feature | 默认 | 说明 |
|---------|------|------|
| `test-helpers` | 关 | 启用 `test_helpers` 模块（RV32I 编码器 + ELF32 构建器），供集成测试和基准测试使用 |

## 安全约定

- 全 crate `#![deny(unsafe_code)]`
- 全 crate `#![deny(missing_docs)]`
- 所有变长字段反序列化使用 `checked_add` / `checked_mul` 防 32-bit wrap
- 所有外部输入（ELF / proof / public_io）须经过校验后才使用
- Proof 反序列化先校验总长度 ≤ 64KB，再单项子分配防 OOM DoS（v1.3 M2-002）

## 关键限制（MVP）

- **batch_size = 3**：唯一满足 `batch_size+1` 为 2 的幂（IPA PCS）且 `batch_size-1` 为 2 的幂（sumcheck）的值
- **RV32I 子集**：仅支持基础整数指令（无 M/A/F/D/C 扩展）
- **Transparent setup**：MVP 阶段使用透明 IPA PCS（无 trusted setup）
- **riscv32i target 未安装时**：通过内存字节构造 ELF（见 `test_helpers` 模块）

## 文档

- [ZKVM 架构文档](docs/38-1-zkvm-architecture.md) — 6 层架构 + 折叠协议 + CycleFold 递归
- [编译器使用指南](docs/38-2-zkvm-compiler-guide.md) — cargo-zkvm CLI + ELF 校验规则
- [Syscall 参考](docs/38-3-zkvm-syscall-reference.md) — 10 个 syscall 的 ID / ABI / gas
- [迁移指南](docs/38-4-zkvm-migration-guide.md) — 从 hash-based CcsInstance 迁移到 Fr-based 类型
- [未选方案记录](docs/alternatives.md) — 各阶段设计决策与未选方案

## 依赖

| 依赖 | 用途 |
|------|------|
| `ark-bn254` | BN254 曲线（Fr 标量域 + G1/G2 群） |
| `ark-grumpkin` | Grumpkin 曲线（cycle mirror） |
| `ark-poly` | 多项式运算 |
| `ark-crypto-primitives` | Poseidon 哈希 |
| `sha2` | SHA-256 实现 |
| `secp256k1` | ECDSA 验证 |
| `blake2` | Transcript 哈希 |
| `goblin` | ELF 解析 |
| `rayon` | 并行计算 |

## License

MIT OR Apache-2.0
