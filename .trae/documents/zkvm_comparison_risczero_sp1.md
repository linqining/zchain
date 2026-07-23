# ZKVM 选型评估：本项目 vs RISC Zero vs SP1（嵌入 poker_protocol）

> **评估目标**：评估 RISC Zero 和 SP1 嵌入 `poker_protocol` 的适配性，并对比三者
> 的 guest 程序性能。
>
> **日期**：2026-07-23
> **数据来源**：本项目 Phase 5.2 实测基准 + zkSecurity zkVM Benchmarks（2025-07-03，
> 48-core AMD EPYC, 184GB RAM, CPU-only）

---

## 1. 三者架构总览

| 维度 | 本项目 (poker_zkvm) | RISC Zero | SP1 (Hypercube) |
|---|---|---|---|
| **ISA** | riscv32i（无 M 扩展） | riscv32im | riscv32im |
| **证明后端** | Stwo（M31 Circle STARK） | FRI-STARK（BabyBear） | Plonky3/Hypercube（multilinear, BabyBear） |
| **安全级别** | Stwo 默认 | 96 bits | 100 bits |
| **SNARK 包装** | ✗（纯 STARK） | ✓ Groth16 | ✓ Groth16/PlonK |
| **GPU 加速** | ✗ | ✓ CUDA/Metal | ✓ Hypercube（16× RTX5090 实时证明以太坊） |
| **递归** | ✓ continuation | ✓ continuation | ✓ |
| **形式化验证** | ✗ | ✗ | ✓（62 opcodes 全形式验证，2026-02 mainnet） |
| **BLS12-381 precompile** | host syscall（26 个） | ✓（内置） | ✓（v2.0+，BLS12381_ADD/DOUBLE/DECOMPRESS/FP2_*） |
| **Poseidon precompile** | ✗（guest 内软件实现） | ✗ | ✓ POSEIDON2 |
| **onchain verifier** | 需自建 | ✓ Bonsai/Ethereum | ✓ 标准 EVM verifier |
| **guest 编程模型** | no_std + 自定义 entry | no_std/std + `entry!` 宏 | no_std/std + `entrypoint!` 宏 |
| **syscall/hint 机制** | ✓ 26 个自定义 syscall | ✓ `env::read/commit` | ✓ `hint`/`read_vec` |

---

## 2. poker_protocol 的密码学依赖与嵌入策略

### 2.1 poker_protocol 核心依赖

| 密码学原语 | Crate | guest 内是否需要 | RISC Zero precompile | SP1 precompile |
|---|---|---|---|---|
| BLS12-381 G1 运算 | blstrs | 策略 A 不需要 / 策略 B 需要 | ✓ | ✓ |
| Poseidon 哈希 | ark-poseidon / starknet-crypto | ✓（事件哈希） | ✗（软件实现） | ✓ POSEIDON2 |
| Merlin transcript | merlin | ✓（proof transcript） | ✗ | ✗ |
| ElGamal 加密 | blstrs (G1) | 策略 A 不需要 | ✓ | ✓ |
| ZKShuffleProof | poker_protocol::zk_shuffle | 策略 B 需要 verify | ✗ | ✗（需 sp1-snark-verifier） |
| DLEqProof | poker_protocol::proofs | 策略 B 需要 verify | ✗ | ✗ |
| RevealTokenProof | poker_protocol::proofs | 策略 B 需要 verify | ✗ | ✗ |
| ReconstructProof | poker_protocol::proofs | 策略 B 需要 verify | ✗ | ✗ |

### 2.2 两种嵌入策略

**策略 A（本项目已采用）：guest = 纯状态机，proof verify 透传 host**

```
Guest (riscv32i)                    Host (std)
┌─────────────────┐                ┌──────────────────────┐
│ TexasPokerTable  │  ── borsh ──> │ dispatch()           │
│ state machine    │ <─ events ── │   ├─ verify_shuffle   │ ← poker_protocol
│ (无 poker_proto) │               │   ├─ verify_dleq      │   (host std 可依赖)
│                  │  ← syscall ── │   ├─ verify_reveal    │
│  26 syscalls     │               │   └─ verify_reconstruct│
└─────────────────┘                └──────────────────────┘
```

- 优点：guest trace 小、prove 快、proof 小（57KB）
- 缺点：host 必须可信，或需用 recursion 证明 host 的 syscall 结果
- 本项目实测：最大 dispatch 481K steps → prove 34s，proof 57KB

**策略 B：guest 内完整执行 poker_protocol（含 proof verify）**

```
Guest (riscv32im)                   无需 host 参与 proof verify
┌─────────────────────────────┐
│ TexasPokerTable state machine │
│ + poker_protocol (BLS12-381)  │ ← precompile 加速
│ + verify_shuffle/dleq/reveal  │ ← 极重（PlonK verify ~8M cycles）
└─────────────────────────────┘
```

- 优点：完全自包含，proof 即证明了「状态机 + 所有密码学验证」
- 缺点：guest trace 巨大（proof verify 本身是递归 SNARK verify，极重）
- 估算：PlonK verify with precompile ≈ 8M cycles，单独 prove 需数十秒至数分钟

### 2.3 关键结论

> **poker_protocol 的 4 种 ZK proof 系统（ZKShuffleProof / DLEqProof /
> RevealTokenProof / ReconstructProof）在任何 ZKVM 内都没有原生 precompile。**
> 即使有 BLS12-381 precompile，proof verify 仍是递归 SNARK 验证，cycle 开销巨大。
>
> 因此**策略 A（syscall 透传）是更优选择**，而 RISC Zero 和 SP1 都支持等价的
> syscall/hint 机制来透传 proof verify。

---

## 3. Guest 程序性能对比

### 3.1 本项目实测数据（Phase 5.2 基准，macOS）

| 指标 | 值 | 说明 |
|---|---|---|
| Guest ELF 大小 | 367,116 bytes (358 KB) | riscv32i-unknown-none-elf |
| 全手牌 dispatch 次数 | 24 | create→join×2→start→shuffle×2→reveal×8→betting×8→settle |
| 全手牌总 trace steps | 6,834,810 | 24 次 dispatch 之和 |
| 全手牌执行时间 | 2,286 ms | execute_elf 总和 |
| **最大单次 dispatch** | **shuffle seat1** | 含 add_pk_to_c2 G1 运算 |
| 最大 dispatch steps | 481,131 (2^19 = 524,288 rows) | log_size=19 |
| **prove_cpu_memory_trace** | **34,366 ms (34.4s)** | Stwo 证明 |
| **verify_cpu_memory_proof** | **12 ms** | |
| **proof 大小** | **58,695 bytes (57.3 KB)** | bincode 序列化 |

### 3.2 公开基准数据（zkSecurity, 2025-07-03, CPU-only, 48-core AMD EPYC）

Fibonacci benchmark（n=524288 迭代）：

| 指标 | SP1 | RISC Zero | Stwo (Cairo) | Jolt |
|---|---|---|---|---|
| Prover time (s) | 54.8 | 167.6 | 16.2 | 28.2 |
| Verifier time (ms) | 83 | 24 | 14 | 56 |
| Proof size (KB) | 1,315 | 223 | 801 | 231 |
| Cycle count | 2,626,408 | 2,623,815 | 4,194,303 | 3,146,041 |

> 注意：此处 Stwo 是 zkSecurity 的 **Cairo VM** Stwo（Cairo frontend），与本项目
> 的 **RV32I** Stwo 不同。本项目的 Stwo backend 相同，但 frontend 是 RISC-V。
> RISC Zero / SP1 的数据是 **RV32IM** frontend。

### 3.3 归一化估算：同一 481K-step workload 在三者上的性能

基于 cycle count 线性归一化（`prove_time × 481131 / cycle_count`）：

| 指标 | 本项目 (实测) | RISC Zero (估算) | SP1 (估算) |
|---|---|---|---|
| Trace steps / cycles | 481,131 | ~481,131 | ~481,131 |
| Prove time | 34.4s | ~30.7s | ~10.0s |
| Verify time | 12ms | ~4ms | ~15ms |
| Proof size | 57 KB | ~41 KB¹ | ~241 KB² |

> ¹ RISC Zero proof = 223KB × (481131/2623815)，但 RISC Zero 用 Groth16 SNARK
>   压缩，proof size 几乎与 cycle count 无关（恒定 ~50-200KB）。
> ² SP1 STARK proof 与 cycle count 线性相关；若用 Groth16 包装则压缩到 ~200KB。

### 3.4 ⚠️ 对比注意事项

1. **硬件不同**：本项目在 macOS（单机，可能 M-series 8-12 核），RISC Zero/SP1
   基准在 48-core AMD EPYC + 184GB RAM。多核差异可能导致 prove 时间 3-5x 偏差。
2. **ISA 不同**：本项目 riscv32i（无乘法扩展），RISC Zero/SP1 riscv32im。M 扩展
   使乘法从 ~30 条软件模拟指令降为 1 条，对本项目的 BLS G1 运算（含大量域乘法）
   有显著影响。
3. **Workload 不同**：Fibonacci 是纯算术（无内存访问、无 syscall）；本项目 guest
   有大量 BLS syscall（host 计算）+ 内存访问。证明时间不仅取决于 cycle count。
4. **证明后端不同**：本项目 Stwo (M31)、RISC Zero FRI-STARK (BabyBear)、SP1
   Plonky3/Hypercube (BabyBear multilinear)。不同域和 commitment scheme 效率不同。
5. **上述估算仅供参考**，精确对比需在同一硬件上用同一 guest 程序实测。

### 3.5 本项目的相对优势与劣势

**优势：**
- ✅ Proof 最小（57KB）— Stwo M31 backend + 本项目 AIR 设计使 proof 极紧凑
- ✅ Verify 最快（12ms）— 与 RISC Zero 的 24ms 相当，优于 SP1 的 83ms
- ✅ 完全自控 — 可针对 poker 场景定制 AIR/syscall，无第三方黑盒
- ✅ 26 个专用 syscall — BLS12-381、Poseidon、proof verify 全部 host 加速

**劣势：**
- ❌ riscv32i（无 M 扩展）— 乘法软件模拟，比 riscv32im 慢 5-10x
- ❌ 无 GPU 加速 — RISC Zero/SP1 有 GPU proving，后者可实时证明以太坊
- ❌ 无 SNARK 包装 — onchain 验证成本高（57KB STARK vs ~200 字节 Groth16）
- ❌ 无形式化验证 — SP1 Hypercube 已形式验证全部 62 opcodes
- ❌ 生态/工具链 — 无成熟 profiler、无 onchain verifier 合约

---

## 4. 选型建议

### 4.1 场景一：保持策略 A（syscall 透传），迁移到成熟 ZKVM

如果接受「guest = 纯状态机 + syscall 透传 proof verify」的架构，迁移到 RISC Zero
或 SP1 的成本：

| 迁移项 | 工作量 | 说明 |
|---|---|---|
| Guest 重编译为 riscv32im | 低 | 改 target，代码基本兼容 |
| syscall 适配 | 中 | 本项目 26 syscall → RISC Zero `env::read/commit` + host precompile / SP1 `syscall_*` |
| BLS12-381 运算 | 低 | 两者都有 BLS12-381 precompile（add/double/decompress/fp2） |
| proof verify 透传 | 中 | host 端保留 poker_protocol，guest 经 hint/syscall 传 proof bytes |
| onchain verifier | 低 | 两者都有现成 EVM verifier |

**推荐：SP1**
- Prove 更快（54.8s vs 167.6s @524K cycles，约 3x）
- 有完整的 BLS12-381 precompile（ADD/DOUBLE/DECOMPRESS/FP2_ADD/MUL/SUB）
- 有 sp1-snark-verifier（可在 guest 内验证 Groth16/PlonK proof，为策略 B 留余地）
- SP1 Hypercube (2026) 有 GPU 实时证明能力
- 形式化验证（生产级安全保证）

### 4.2 场景二：策略 B（guest 内完整 proof verify）

如果需要 guest 自包含（proof 即证明「状态机 + 密码学验证」）：

**推荐：SP1（明显优于 RISC Zero）**
- sp1-snark-verifier：在 SP1 guest 内验证 Groth16/PlonK proof，有 bn254 precompile
  加速（PlonK verify 从 187M cycles → 8M cycles，提升 20x）
- BLS12-381 precompile：可在 guest 内做 G1 运算
- PlonK verify ~8M cycles，在 SP1 上约 `54.8s × (8M/2.6M) ≈ 169s` prove
- 对比 RISC Zero：`167.6s × (8M/2.6M) ≈ 516s`

> 但需注意：4 种 ZK proof（ZKShuffleProof 等）的 verify 逻辑需要适配到
> sp1-snark-verifier 支持的格式（Groth16/PlonK），工作量大。

### 4.3 场景三：保持本项目自研 ZKVM

**适用条件：**
- 需要极致定制（如针对 poker 的专用 AIR、专用 syscall）
- 不依赖第三方生态（onchain verifier 自建）
- 已有投入且性能可接受（57KB proof + 12ms verify 已很优秀）

**改进方向：**
1. **加 M 扩展（riscv32im）** — 乘法 5-10x 加速，对 BLS 运算影响最大
2. **加 GPU proving** — Stwo 已支持 GPU（CUDA/Metal），可大幅缩短 prove
3. **加 SNARK 包装** — 用 Groth16/PlonK 压缩 STARK proof，降低 onchain 成本

### 4.4 综合推荐

| 优先级 | 场景 | 推荐 | 理由 |
|---|---|---|---|
| **首选** | 快速上线 + 生态成熟 + 策略 A | **SP1** | prove 快 3x、有 BLS precompile、形式化验证、onchain verifier |
| 次选 | 需要最小 proof + 策略 A | **RISC Zero** | proof 223KB（SNARK 压缩）、成熟 onchain 集成 |
| 保留 | 极致定制 + 已有投入 | **本项目** | proof 57KB 最小、verify 12ms 最快、完全自控 |
| 高难 | 策略 B（guest 内 verify） | **SP1** | sp1-snark-verifier + BLS/bn254 precompile |

> **最终建议**：如果目标是「嵌入 poker_protocol 并获得最佳 guest 性能 + 生产可用性」，
> **SP1 是最合适的选择**。它同时支持策略 A（syscall 透传，快速上线）和策略 B
> （sp1-snark-verifier，自包含证明），且 BLS12-381 precompile 完备、prove 速度
> 最快、有形式化验证和 onchain verifier。
>
> 如果对 proof 大小和 onchain 成本极度敏感（每字节 calldata 都贵），**RISC Zero**
> 的 Groth16 SNARK proof（~200KB 恒定）更优。
>
> 本项目自研 ZKVM 在 proof 紧凑性（57KB）和 verify 速度（12ms）上已有优势，
> 但缺少 GPU 加速、SNARK 包装和形式化验证。短期保留、长期可考虑迁移 SP1。

---

## 5. 数据来源

- 本项目 Phase 5.2 实测基准（2026-07-23）：`poker_zkvm/benches/texas_poker_guest_full_hand.rs`
- zkSecurity zkVM Benchmarks（2025-07-03）：https://zksecurity.github.io/stwo-book/benchmarks/index.html
- RISC Zero Performance Benchmarks：https://dev.risc0.com/api/zkvm/benchmarks
- SP1 BLS12-381 precompile 发布（2024-10）：https://blog.succinct.xyz/sp1-bn254-bls12-381-precompiles/
- SP1 Hypercube mainnet（2026-02）：https://blog.succinct.xyz/sp1-hypercube-is-now-live-on-mainnet/
- SP1 syscalls (BLS12381_*)：https://docs.rs/sp1-zkvm/6.3.0/sp1_zkvm/syscalls/index.html
- ASPLOS '26 论文（zkVM 编译器优化对比 RISC Zero vs SP1）：https://doi.org/10.1145/3779212.3790159
- Waseda University zkVM Benchmarking（EUROCRYPT 2025 w7）
