# poker_zkvm Phase 5 + Phase 10 执行计划

> **change-id**：`build-hypernova-zkvm`
> **spec 版本**：v1.4 FROZEN
> **前置状态**：Phase 0-4 已完成（319 测试通过）
> **详细设计文档**：`/Users/mac/projects/zchain/.trae/documents/poker-zkvm-phase10-then-phase5-plan.md`（583 行，已批准，含 7 个设计决策 D1-D7 与 14 步详细实施）

---

## 一、当前状态确认（Phase 1 探索结果）

### 1.1 代码库现状（全部为 stub，未实现）

| 文件 | 状态 | 说明 |
|------|------|------|
| [ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs) | 8 行 stub | 待重写为 CCS 核心数据结构 |
| [constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) | 8 行 stub | 仅 `pub mod memory;`，待重写为约束编译器 |
| [constraints/memory.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/memory.rs) | 6 行 stub | 待实现 byte-level permutation |
| [lookup/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/lookup/mod.rs) | 6 行 stub | 待实现 LogUp 协议 |
| [hypernova/{fold,proof,sumcheck,verifier}.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/hypernova/mod.rs) | 6-10 行 stub | **不在本计划范围**（Phase 7-9） |
| `precompiles/` 目录 | **不存在** | 待创建，lib.rs 需补 `pub mod precompiles;` |
| [lib.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/lib.rs) | 未声明 precompiles | Step 2 需添加模块声明 |
| [docs/alternatives.md](file:///Users/mac/projects/zchain/poker_zkvm/docs/alternatives.md) | 20KB（Phase 0-4） | 待追加 Phase 5 + Phase 10 章节 |

### 1.2 spec / tasks / checklist 现状

- **spec.md L268-312**：Trace → CCS 约束编译器（batching、a la carte 子电路、byte-level permutation、LogUp）
- **spec.md L637-669**：ZKVM Syscall 电路实现（Poseidon ~200/round、SHA-256 ~25,000/block、ECDSA ~110,000）
- **tasks.md L121-159**：Phase 5 Task 5.1-5.6 — **全部 `[ ]` 未完成**
- **tasks.md L292-311**：Phase 10 Task 10.1-10.5 — **全部 `[ ]` 未完成**
- **checklist.md L117-148 / L281-293**：Phase 5 + Phase 10 检查项 — **全部未勾选**

### 1.3 已就绪的基础设施（Phase 0-4 产出）

- `Fr` = `ark_bn254::Fr`（[field.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/field.rs)），含 `ZkvmField` trait（zero/one/add/sub/mul/inverse/to_canonical_bytes）
- `ZkvmError`（[error.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/error.rs)）— 18 variants，含 `FoldStepCountExceeded` / `UninitializedRead` / `InvalidSlot` / `Other(String)`
- `syscalls/poseidon.rs` — Phase 4 host 实现（alpha=5, rate=2, capacity=1, 8 full + 56 partial rounds），Phase 10 电路须复用此配置
- `pcs/ipa.rs` — IPA over BN254（18 测试），Phase 6 Hypernova 将消费
- `trace/` + `isa/` — RV32I 全指令执行引擎，Phase 5 编译器将消费 `Trace` 结构

---

## 二、执行计划（14 步，依赖已批准的详细设计文档）

本计划严格遵循已批准的 `poker-zkvm-phase10-then-phase5-plan.md`（583 行），执行顺序：

```
Step 1: CCS 基础数据结构（ccs/mod.rs）           ← 基础，无依赖
Step 2: precompiles 模块骨架 + CcsCircuit trait   ← 依赖 Step 1
Step 3: Poseidon 预编译电路                       ← 依赖 Step 1+2
Step 4: SHA-256 预编译电路                        ← 依赖 Step 1+2
Step 5: ECDSA 预编译电路                          ← 依赖 Step 1+2
Step 6: ZkShuffleCcsCircuit 迁移                  ← 依赖 Step 2
Step 7: Phase 10 集成测试 + 文档                  ← 依赖 Step 3-6
─── Phase 10 完成 ───
Step 8: compile_trace_to_ccs + batching           ← 依赖 Step 1
Step 9: 算术指令子电路                            ← 依赖 Step 1+8
Step 10: 内存访问子电路                           ← 依赖 Step 1+8
Step 11: 控制流子电路                             ← 依赖 Step 1+8
Step 12: Syscall 子电路                           ← 依赖 Step 7（Phase 10）+ Step 8
Step 13: LogUp lookup 协议                        ← 依赖 Step 1
Step 14: Phase 5 集成测试 + 文档                  ← 依赖 Step 8-13
─── Phase 5 完成 ───
```

### Step 1：CCS 基础数据结构（Task 5.0 / 6.1.1 / 6.1.4 准备）

**文件**：重写 [poker_zkvm/src/ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs)

**实现**：
1. `SparseEntry { row: usize, col: usize, value: Fr }`
2. `SparseMatrix { num_rows, num_cols, entries: Vec<SparseEntry> }` — `new()` / `add_entry()` / `get()` / `evaluate(z: &[Fr]) -> Result<Vec<Fr>, ZkvmError>`
3. `Ccs { num_vars, num_matrices, matrices: Vec<SparseMatrix>, subsets: Vec<Vec<usize>>, coeffs: Vec<Fr> }` — `satisfied_by(z: &[Fr]) -> Result<bool, ZkvmError>` 校验 `Σ_i c_i · Π_{j∈S_i} ⟨M_j, z⟩ = 0`
4. `CcsInstance { ccs: Ccs, witness: Vec<Fr>, public_inputs: Vec<Fr> }`

**测试**（7-10）：sparse_matrix_add_get / evaluate / ccs_satisfied_by_simple / ccs_satisfied_by_violated / ccs_instance_new_type / sparse_matrix_empty / ccs_multiple_matrices

### Step 2：precompiles 模块骨架 + CcsCircuit trait（Task 10.1）

**文件**：
- 新建 `poker_zkvm/src/precompiles/mod.rs`
- 修改 [poker_zkvm/src/lib.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/lib.rs)（添加 `pub mod precompiles;`）

**实现**：
1. `PrecompileCircuit` trait — `name()` / `num_variables()` / `build_ccs() -> Ccs` / `assign_witness(&[Fr]) -> Result<Vec<Fr>, ZkvmError>` / `gas_cost() -> u64`
2. `PrecompileRegistry` — `new()` / `register()` / `get()`
3. `CcsCircuit` trait（新签名，基于 Fr + CcsInstance 新类型，非旧 hash-based）

**测试**（3-5）：registry_register_get / registry_empty / ccs_circuit_trait_dispatch

### Step 3：Poseidon 预编译电路（Task 10.2）

**文件**：新建 `poker_zkvm/src/precompiles/poseidon.rs`

**实现**：`PoseidonCircuit` struct，复用 [syscalls/poseidon.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/syscalls/poseidon.rs) 配置（alpha=5, rate=2, capacity=1, 8+56 rounds）。`build_ccs()` 生成 S-box（x^5 = 4 约束）+ MDS 矩阵约束。`assign_witness()` 与 host `poseidon_hash_bytes` 输出一致。

**测试**（6-8）：build_ccs / satisfied_by / soundness / consistency_with_host / empty_input / large_input

### Step 4：SHA-256 预编译电路（Task 10.3）

**文件**：新建 `poker_zkvm/src/precompiles/sha256.rs`

**实现**：`Sha256Circuit`（block_size=64, output_size=32）。message schedule（64 words 线性反馈 + rotl）+ compression round（ch/maj + 加法 + rotl + 32-bit overflow_bit）。与 `sha2::Sha256::digest` 一致。

**测试**（6-8）：build_ccs / satisfied_by / soundness / consistency_with_sha2 / empty_input（e3b0c442...）/ known_vectors（"abc", "hello world"）

### Step 5：ECDSA 预编译电路（Task 10.4）

**文件**：新建 `poker_zkvm/src/precompiles/ecdsa.rs`

**实现**：`EcdsaVerifyCircuit`（secp256k1 参数）。标量乘 shift-add × 256 + 点加法/倍点 + 哈希 + 最终比较。总约束 ≈ 110,000（spec L659）。MVP 先实现约束骨架 + 关键路径。

**测试**（6-8）：build_ccs / satisfied_by_valid / soundness_tampered_msg / soundness_tampered_sig / soundness_tampered_pubkey / consistency_with_host

### Step 6：ZkShuffleCcsCircuit 迁移（Task 10.5）

**文件**：
- 新建 `poker_zkvm/src/precompiles/zk_shuffle.rs`
- 修改 [poker_l1/src/offline/ccs.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/ccs.rs)（re-export + `#[deprecated]`）

**实现**：迁移 `ZkShuffleCcsCircuit` 类型定义，保持 stub 行为（`to_ccs_instance` 返回 `Err(Other("Phase 11 pending"))`）。poker_l1 通过 `pub use` re-export，旧定义标记 deprecated。

**测试**（3-4）：migration / deprecated_in_poker_l1 / re_export

### Step 7：Phase 10 集成测试 + 文档

**文件**：
- 修改 `poker_zkvm/src/precompiles/mod.rs`（集成测试）
- 修改 [poker_zkvm/docs/alternatives.md](file:///Users/mac/projects/zchain/poker_zkvm/docs/alternatives.md)（Phase 10 章节）

**测试**（3-5）：registry_full（4 个预编译电路）/ all_implement_trait / gas_costs_reasonable

### Step 8：compile_trace_to_ccs + batching（Task 5.1）

**文件**：重写 [poker_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)

**实现**：`compile_trace_to_ccs(trace, batch_size) -> Result<Vec<CcsInstance>, ZkvmError>`。每 K=1024 步生成 1 个 CCS 实例。校验 `instances.len() ≤ 1000`。连续性约束（batch 内 + batch 间）。

**测试**（4-6）：small_trace / batch_boundary / fold_step_limit / empty_trace

### Step 9：算术指令子电路（Task 5.2）

**文件**：新建 `poker_zkvm/src/constraints/algebra.rs`

**实现**：ADD/ADDI（overflow_bit）/ SUB/SLT/SLTU / SLL/SRL/SRA（shift bit-decompose）/ AND/OR/XOR / RV32M DIV/DIVU/REM/REMU（除零语义）。

**测试**（15-20）：每条指令正例 + 边界（除零 / MIN/-1 / overflow）

### Step 10：内存访问子电路（Task 5.3）

**文件**：重写 [poker_zkvm/src/constraints/memory.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/memory.rs)

**实现**：LW/SW/LB/SB/LH/SH/LBU/LHU。byte-level permutation（key = `(byte_addr, byte_val, step_index)`）。混合尺寸重叠（LW 4B 后 LB 1B）。地址 range check（checked_add）。未初始化读取检测。

**测试**（10-15）：read_after_write / uninitialized_read / mixed_size_overlap / aliasing_attack_negative

### Step 11：控制流子电路（Task 5.4）

**文件**：新建 `poker_zkvm/src/constraints/control_flow.rs`

**实现**：JAL/JALR（pc 更新）/ BEQ/BNE/BLT/BGE/BLTU/BGEU（条件求值）/ LUI/AUIPC。

**测试**（8-12）：jump_target / branch_evaluation

### Step 12：Syscall 子电路（Task 5.5）

**文件**：新建 `poker_zkvm/src/constraints/syscall_circuit.rs`

**实现**：ECALL 子电路 — 解码 `a7`，分派到 Phase 10 预编译电路（通过 `PrecompileRegistry`）。每个 syscall 产生独立 CCS 实例。

**测试**（9-12）：poseidon / sha256 / ecdsa / read_input / commit_output / emit_event / get_randomness / read_state / log_panic

### Step 13：LogUp lookup 协议（Task 5.6）

**文件**：重写 [poker_zkvm/src/lookup/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/lookup/mod.rs)

**实现**：`LookupTable` / `LogUpProof`（严格 absorb 顺序：C_T → C_f → C_m → β）。校验 `Σ_i m_i/(β - t_i) == Σ_j 1/(β - f_j)`。内置表：u8/u16/u32 range、AND/OR/XOR 真值表。

**测试**（8-10）：positive（含 m_i=0）/ soundness_negative（β 派生时机错误 / multiplicity 伪造）

### Step 14：Phase 5 集成测试 + 文档

**文件**：
- 修改 [poker_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)（集成测试）
- 修改 [poker_zkvm/docs/alternatives.md](file:///Users/mac/projects/zchain/poker_zkvm/docs/alternatives.md)（Phase 5 章节）

**测试**（2-4）：full_pipeline（含算术/内存/控制流/syscall） / all_subcircuits_satisfied_by

---

## 三、设计决策（引用已批准文档 D1-D7）

| ID | 决策 | 推荐 | 未选择 |
|----|------|------|--------|
| D1 | CCS 数据结构位置 | `ccs/mod.rs` | 新建 `fold/` 目录 / 放 `constraints/` |
| D2 | SparseMatrix 表示 | COO `Vec<(row,col,value)>` | 稠密 `Vec<Vec<Fr>>` / `HashMap` |
| D3 | CcsCircuit trait 迁移 | 迁入 `precompiles/mod.rs` | 保留 poker_l1 |
| D4 | 预编译电路实现 | `PrecompileCircuit` trait + CCS 生成器 | halo2 Circuit / arkworks R1CS |
| D5 | Poseidon 参数 | 复用 syscalls/poseidon.rs 配置 | 独立配置 |
| D6 | ZkShuffle 迁移 | 保持 stub（真实电路 Phase 11） | 完整迁移 |
| D7 | LogUp 位置 | `lookup/mod.rs` | `constraints/lookup.rs` |

详细理由见 `poker-zkvm-phase10-then-phase5-plan.md` 第 60-141 行。

---

## 四、验证步骤

### 每个 Step 完成后

1. **`cargo test -p poker_zkvm`** — 全部测试通过（含新增 + 既有 319 测试）
2. **`cargo clippy -p poker_zkvm --all-targets -- -D warnings`** — 零警告
3. **`cargo build -p poker_zkvm --bin cargo-zkvm`** — 二进制构建成功
4. **`#![deny(unsafe_code)]` + `#![deny(missing_docs)]`** — 全部新增 public item 有 `///` 文档

### 最终验证（Step 14 完成后）

- **总测试数** ≈ 319（既有）+ 90-130（新增）= 409-449
- **clippy 零警告**
- **alternatives.md** 含 Phase 10 + Phase 5 章节
- **tasks.md** Phase 5 + Phase 10 全部 `[x]` 勾选
- **checklist.md** Phase 5 + Phase 10 全部勾选

---

## 五、假设与约束

1. **spec v1.4 FROZEN** — 严格遵循 spec.md L268-312 + L637-669
2. **TDD 严格模式** — 每个 Step 按 RED → GREEN → REFACTOR，测试通过后才进入下一步
3. **不修改 Phase 0-4 既有代码** — 除 lib.rs 添加 `pub mod precompiles;` 外，不改动既有模块
4. **poker_l1 修改最小化** — 仅 Step 6 添加 re-export + deprecated 标记
5. **Phase 6+ 不在本计划范围** — Hypernova 折叠留待后续 Phase
6. **CCS 数据结构为 Phase 6 预留** — `to_lcccs()` / `to_cccs()` 方法签名定义但返回 `Err(Other("Phase 6 pending"))`
7. **多个方案时选择推荐的，未选择方案放 alternatives.md** — 遵循用户既定工作流

---

## 六、文件改动清单

**新建**（8 文件）：
- `poker_zkvm/src/precompiles/{mod,poseidon,sha256,ecdsa,zk_shuffle}.rs`（5 文件）
- `poker_zkvm/src/constraints/{algebra,control_flow,syscall_circuit}.rs`（3 文件）

**重写**（4 文件）：
- `poker_zkvm/src/ccs/mod.rs`
- `poker_zkvm/src/constraints/mod.rs`
- `poker_zkvm/src/constraints/memory.rs`
- `poker_zkvm/src/lookup/mod.rs`

**修改**（3 文件）：
- `poker_zkvm/src/lib.rs`（添加 `pub mod precompiles;`）
- `poker_l1/src/offline/ccs.rs`（re-export + deprecated）
- `poker_zkvm/docs/alternatives.md`（Phase 5 + Phase 10 章节）
