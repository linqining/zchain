# ZKVM 架构文档

> 文档编号：38-1  
> 对应 spec：`build-hypernova-zkvm` spec v1.4（FROZEN）  
> 模块：`poker_zkvm`

## 1. 总体架构

poker_zkvm 是一台基于 Hypernova 折叠协议的零知识虚拟机（ZKVM），执行 RV32I 指令集并生成 succinct proof 证明执行正确性。用于 zchain OffChain 模式的状态转换验证。

### 1.1 设计目标

- **Succinctness**：Proof 大小和 Verifier 时间与 trace 步数无关（常数级）
- **无 trusted setup**：使用透明 IPA PCS（NUMS generators），无 SRS
- **安全性**：全 crate `deny(unsafe_code)`，所有外部输入经校验后使用
- **抗 OOM DoS**：Proof 反序列化先校验总长度，再单项子分配（v1.3 M2-002）

### 1.2 六层架构

```
Layer 0   Foundation          field / transcript / error
Layer 1   Crypto Primitives   pcs (IPA over BN254)
Layer 2   Frontend & Exec     compiler / isa / trace / syscalls
Layer 3   Constraint System   ccs / lookup / constraints
Layer 3.5 Hypernova Fold      fold (LCCCS + CCCCS + fold_step + sumcheck + fold_loop)
Layer 4   Protocol            hypernova / cyclic
Layer 5   Prover/Verifier     precompiles / prover / verifier
Layer 6   Recursion           cyclegfold / recursion
```

## 2. Layer 0 — Foundation

### 2.1 field — 域类型

- `ZkvmField` trait：统一域元素接口（`add` / `sub` / `mul` / `inv` / `from_u32_with_wrap` / `to_canonical_bytes` / `from_canonical_bytes`）
- `Bn254ScalarField`：BN254 标量域 Fr（`ark_bn254::Fr` 的 newtype wrapper）
- Canonical 编码：32 字节 little-endian

### 2.2 transcript — Fiat-Shamir

- 基于 BLAKE2b 的 Fiat-Shamir transcript
- 域分离常量：`HYPERNOVA_FOLD` / `SUMCHECK` / `LOOKUP` / `MEM_CHECK` / `PCS_OPEN`
- Length-prefixing 防歧义（`"ab"+"c"` vs `"a"+"bc"` 产生不同 challenge）
- 严格按 spec 顺序 absorb

### 2.3 error — 错误类型

18 种 `ZkvmError` 变体，覆盖：ELF 校验 / 执行 / 约束 / 折叠 / 序列化 / PCS / Slot 等。

## 3. Layer 1 — PCS

### 3.1 IPA over BN254

- **IPA（Inner Product Argument）**：transparent PCS，无需 trusted setup
- **NUMS generators**：确定性派生（nothing-up-my-sleeve），基于哈希到曲线
- **Commitment**：33 字节 compressed G1 point
- **Opening**：证明 `C = commit(poly)` 且 `poly(r) = v`
- **复杂度**：Prover O(N log N)，Verifier O(log N)，Proof size O(log N)

关键约束：`num_vars`（多项式变量数）须为 2 的幂。

## 4. Layer 2 — Frontend & Execution

### 4.1 compiler — ELF 编译器

- `validate_elf`：11 项校验（magic / class / endianness / machine / dynamic / segment / overlap / entry / text_size / RV32I 子集 / 总内存 ≤ 16MB）
- `compile_crate`：调用 `cargo build --target riscv32i-unknown-none-elf --release`
- `CompilerConfig`：固定 target / opt-level=3 / panic=abort

### 4.2 isa — 指令集

- **RV32I 子集**：6 种指令类型（R / I / S / B / U / J）
- 支持指令：ADDI / ADD / SUB / SW / LW / LB / BNE / BEQ / LUI / ECALL / JAL 等
- 不支持：M（乘除）/ A（原子）/ F/D（浮点）/ C（压缩）

### 4.3 trace — 执行轨迹

- `Step`：单步执行记录（PC / 指令 / 寄存器快照 / 内存访问日志）
- `Trace`：Step 序列 + host 内存使用统计
- `MAX_ZKVM_TRACE_STEPS = 1,048,576`（2^20）
- `MAX_TRACE_HOST_MEMORY = 512MB`

### 4.4 syscalls — 10 个系统调用

| ID | Syscall | 功能 |
|----|---------|------|
| 0x01 | ReadInput | 从 host input buffer 读取 |
| 0x02 | CommitOutput | 写入 host output buffer + halt |
| 0x03 | Poseidon | Poseidon 哈希 |
| 0x04 | Sha256 | SHA-256 哈希 |
| 0x05 | EcdsaVerify | ECDSA 签名验证 |
| 0x06 | EmitEvent | 事件进 public_io（绑定 step_index） |
| 0x07 | Log | 写入 host 日志 |
| 0x08 | Panic | 终止执行 |
| 0x09 | GetRandomness | 从 host seed 派生确定性随机数 |
| 0x0A | ReadState | 读取白名单 slot（0x01-0x05） |

详见 [Syscall 参考](38-3-zkvm-syscall-reference.md)。

## 5. Layer 3 — Constraint System

### 5.1 CCS — Customizable Constraint System

CCS 是一种通用的约束系统，支持多线性多项式约束：

```
对每个行 r ∈ {0, ..., num_rows-1}:
  Σ_i c_i · Π_{j∈S_i} (M_j · z)[r] = 0
```

其中：
- `z`：见证向量（长度 `num_vars`）
- `M_1, ..., M_t`：稀疏矩阵（COO 格式）
- `S_1, ..., S_q`：矩阵索引子集
- `c_1, ..., c_q`：系数

### 5.2 LogUp Lookup 协议

- 用于预编译电路（Poseidon / SHA-256 / ECDSA / ZkShuffle）的 lookup 约束
- `LogUpProof::create(table, witness, multiplicity)` → `(proof, commitments)`
- `proof.verify(&commitments)` → `bool`
- 基于 logarithmic derivative 的 lookup 约束

### 5.3 constraints — Trace→CCS 编译

- `compile_trace_to_ccs(trace, batch_size)` → `Vec<CcsInstance>`
- 将执行轨迹按 `batch_size` 分批，每批编译为一个 CCS 实例
- 涵盖：算术指令子电路 / 内存访问子电路 / 控制流子电路 / Syscall 子电路

## 6. Layer 3.5 — Hypernova Fold

### 6.1 LCCCS — Linearized CCCS

Relaxed CCS 实例，允许 `u_l ≠ 0`：

```
Σ_i c_i · Π_{j∈S_i} v_l[j] = u_l
```

字段：`ccs_ref` / `u_l` / `x_l` / `trace_l` / `r_x_l` / `v_l`

### 6.2 CCCCS — Committed CCCS

不存储 `v_C`，在 `satisfied` 时通过内层 sumcheck 求值重新计算。

字段：`u_c` / `x_c` / `trace_c` / `witness_commitment_c`

### 6.3 fold_step — 单步折叠

输入：`(LCCCS, CCCCS)` → 输出：`folded LCCCS + sumcheck 子证明`

1. 派生 fold challenge `r`（transcript absorb `ccs_commitment` + `lcccs_witness_commitment` + `ccccs_witness_commitment`）
2. 计算 `u'` / `x'` / `trace'` / `v'[j]` / `z'` / `C'`
3. 生成 sumcheck 子证明（外层 + 内层 batched）

### 6.4 sumcheck — 外层 + 内层

- **外层 sumcheck**：`G(r_x_L) = u'`（v1.3 C2-003 claimed sum = u' 标量）
- **内层 batched sumcheck**：单 `r_y` challenge（v1.3 C2-001 combined_point = r_y）
- 公式（显式括号，v1.3 Min3-005）：
  ```
  G(X) = eq(X, r_x_L) · Σ_i [c_i · Π_{j∈S_i} (v_L[j](X) + r·v_C[j](X))]
  ```

### 6.5 fold_loop — 多步折叠

```
prove():
  instances = compile_trace_to_ccs(trace, batch_size)
  folded = instances[0].to_lcccs()
  for ccccs in instances[1..]:
    (folded, sumcheck_proof) = fold_step(folded, ccccs)
  → HypernovaProof { folded_instance, witness_commitment, final_sumcheck, pcs_opening, r_y, z_at_point }
```

## 7. Layer 4 — Protocol

### 7.1 hypernova — 折叠协议入口

- `verify_hypernova`：验证单个 Hypernova proof 的 sumcheck + PCS opening
- `HypernovaProof` 结构（见 fold_loop.rs）

### 7.2 cyclic — 曲线 Cycle

BN254 / Grumpkin 曲线 cycle：
- BN254 的标量域 = Grumpkin 的 base field
- Grumpkin 的标量域 = BN254 的 base field
- `CycleCurve` trait 抽象曲线 cycle 操作

## 8. Layer 5 — Precompiles / Prover / Verifier

### 8.1 precompiles — 4 个预编译电路

| 电路 | 功能 | 约束来源 |
|------|------|---------|
| Poseidon S-box | Poseidon 哈希的 S-box 层 | 查找表 + 约束 |
| SHA-256 Ch | SHA-256 的 Ch 函数 | 位级约束 |
| ECDSA double-and-add | ECDSA 验证的单步 | 条件分支约束 |
| ZkShuffle stub | ZkShuffle 验证 | stub（Phase 12+ 替换） |

### 8.2 prover — 端到端证明

```rust
prove(elf_bytes, input, config) → (proof_bytes, ZkPublicIo)
```

Pipeline：
1. `validate_elf` — ELF 校验
2. `execute_elf` — 执行产生 Trace
3. `compile_trace_to_ccs` — Trace → CCS 实例（按 batch_size 分批）
4. `fold_loop` — 多步折叠产生 HypernovaProof
5. `serialize_proof` — 序列化为字节（含 magic / version / abi_version）

### 8.3 verifier — 端到端验证

```rust
verify_production(proof_bytes, public_io) → bool
```

Pipeline：
1. `deserialize_proof` — 反序列化 + 总长度优先校验 + 单项子分配
2. 重建 `IpaPcs`（基于 `ccs_ref.num_vars`）
3. `sumcheck::verify` — 外层 G(r_x_L) == u'
4. `pcs.verify` — PCS opening z'(r_y)

## 9. Layer 6 — Recursion

### 9.1 cyclegfold — CycleFold 聚合

- 将多个 Hypernova proof 通过二叉树结构递归聚合
- BN254 proof → Grumpkin 递归电路验证 → Grumpkin proof
- Grumpkin proof → BN254 递归电路验证 → BN254 proof
- 交替使用两条曲线，实现跨曲线递归

### 9.2 recursion — 递归 Verifier 电路

- `circuit_bn254.rs`：C_BN254 电路，约束 Grumpkin Hypernova proof
- `circuit_grumpkin.rs`：C_Grumpkin 镜像电路，约束 BN254 Hypernova proof
- MVP 阶段：递归 verifier 委托 `verify_hypernova` 原生验证
- `MAX_RECURSION_DEPTH = 16`

## 10. Proof 格式

### 10.1 序列化布局

```
magic(4B "HYPN") || version(1B) || abi_version(1B)
|| CCS_len(4B LE) || CCS_bytes
|| u_l(32B Fr)
|| x_l / trace_l / r_x_l / v_l
|| witness_commitment(33B compressed)
|| final_sumcheck
|| pcs_opening
|| r_y
|| z_at_point(32B Fr)
```

### 10.2 安全参数

| 参数 | 值 | 说明 |
|------|-----|------|
| `MAX_ZKVM_PROOF_SIZE` | 64 KB | Proof 总大小上限 |
| `MAX_PUBLIC_IO_SIZE` | 8 KB | public_io 上限 |
| `MAX_FOLDED_INSTANCE_SIZE` | 8 KB | folded instance 上限 |
| `MAX_SUMCHECK_PROOF_SIZE` | 16 KB | sumcheck 子证明上限 |
| `MAX_PCS_OPENING_SIZE` | 8 KB | PCS opening 上限 |
| `MAX_EVENT_HASHES_COUNT` | 256 | 事件哈希数量上限 |

### 10.3 反序列化安全（v1.3 M2-002）

1. 先校验 `proof_bytes.len() ≤ MAX_PROOF_TOTAL_SIZE`（不分配缓冲区）
2. 再校验各单项 `≤ MAX_*_SIZE`（子分配）
3. 防 verifier OOM DoS

## 11. 安全属性

### 11.1 Fiat-Shamir 绑定

- Fold 阶段 absorb `ccs_commitment` + `lcccs_witness_commitment` + `ccccs_witness_commitment`
- 绑定矩阵内容与 witness，防 challenge 派生后替换

### 11.2 Transparent 风险声明（MVP）

MVP 阶段 transparent setup 下以下字段会泄漏：
- witness commitment
- sumcheck 各轮求值多项式
- PCS opening 的 `z'(r_y)` 求值

**敏感数据不得在 MVP 阶段进入 ZKVM 计算。**

### 11.3 治理切换

- `verifier_status`：`Stub` → `Production`（90% quorum + timelock）
- `production_switch_height`：一次性写入字段，grace 期起算点
- Grace 期后所有 CheckinTx 须使用新签名（含 `proof_kind` 字段）
