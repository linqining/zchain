# poker_zkvm Phase 10 → Phase 5 实施计划

> **change-id**：`build-hypernova-zkvm`
> **spec 版本**：v1.4 FROZEN
> **前置状态**：Phase 0-4 已完成（319 测试通过）
> **用户决策**：先做 Phase 10（预编译电路），再回 Phase 5（约束编译器）— 因 Task 5.5（Syscall 子电路）依赖 Phase 10

---

## 一、当前状态分析

### 1.1 已完成（Phase 0-4）

| Phase | 模块 | 测试数 | 状态 |
|-------|------|--------|------|
| 0 | crate 骨架 + error.rs | - | ✅ |
| 1 | field.rs + transcript.rs | - | ✅ |
| 1.5 | pcs/ipa.rs（IPA over BN254） | 18 | ✅ |
| 2 | compiler/ + elf_validator + cargo-zkvm | 29 bin | ✅ |
| 3 | isa/ + trace/（RV32I 全指令） | - | ✅ |
| 4 | syscalls/（10 个 syscall + gas + poseidon） | - | ✅ |
| **合计** | | **319** | ✅ |

### 1.2 待实现（本计划范围）

| Phase | 任务 | 模块 | 依赖 |
|-------|------|------|------|
| **5.0** | CCS 基础数据结构 | `ccs/mod.rs` | 无（Phase 1 字段已就绪） |
| **10** | 预编译电路 | `precompiles/` | Phase 5.0 CCS 结构 |
| **5** | Trace → CCS 约束编译器 | `constraints/` + `lookup/` | Phase 5.0 + Phase 10（仅 Task 5.5） |

### 1.3 关键依赖链

```
Phase 1 (字段) ─┬─→ Phase 5.0 (CCS 数据结构) ─┬─→ Phase 10 (预编译电路) ─→ Phase 5.5 (Syscall 子电路)
                │                              ├─→ Phase 5.1 (compile_trace_to_ccs)
                │                              ├─→ Phase 5.2 (算术子电路)
                │                              ├─→ Phase 5.3 (内存子电路)
                │                              ├─→ Phase 5.4 (控制流子电路)
                │                              └─→ Phase 5.6 (LogUp lookup)
                └─→ Phase 1.5 (PCS) ─→ Phase 6 (Hypernova 折叠) [后续 Phase]
```

### 1.4 现有 stub 模块

- `poker_zkvm/src/ccs/mod.rs` — 8 行注释 stub
- `poker_zkvm/src/lookup/mod.rs` — 6 行注释 stub
- `poker_zkvm/src/constraints/mod.rs` — 8 行注释 stub（仅 `pub mod memory;`）
- `poker_zkvm/src/constraints/memory.rs` — 6 行注释 stub
- `poker_zkvm/src/hypernova/{fold,proof,sumcheck,verifier}.rs` — 各 6-10 行注释 stub
- `poker_zkvm/src/{prover,verifier,cyclegfold,recursion}.rs` — 单文件 stub
- **`poker_zkvm/src/precompiles/` 目录不存在**（lib.rs 未声明 `pub mod precompiles;`）

### 1.5 lib.rs 模块声明现状

当前 lib.rs 声明了 `ccs` / `lookup` / `constraints` / `hypernova` 等模块，但**未声明 `precompiles`**（spec L72 要求 `precompiles` 子模块）。本计划须补声明。

---

## 二、设计决策（推荐方案 + 未选择方案）

### D1：CCS 数据结构位置 — `ccs/mod.rs`（推荐）

**推荐**：CCS 核心数据结构（`SparseMatrix` / `Ccs` / `CcsInstance`）放在 `poker_zkvm/src/ccs/mod.rs`。

**理由**：
- lib.rs 已声明 `pub mod ccs;`，stub 已存在
- tasks.md Task 6.1 引用 `fold/ccs.rs`，但现有目录结构用 `hypernova/` 而非 `fold/`；为最小改动，CCS 基础结构放 `ccs/mod.rs`，Hypernova 折叠相关结构（Lcccs/Ccccs）放 `hypernova/fold.rs`
- `constraints/` 模块专注 trace→CCS 编译逻辑，不承载 CCS 数据结构定义

**未选择 A**：新建 `fold/` 目录（tasks.md 字面路径）— 改动大，需改 lib.rs 模块树
**未选择 B**：放 `constraints/mod.rs` — 职责混淆（constraints 是编译器，ccs 是数据结构）

### D2：SparseMatrix 表示 — `Vec<(row, col, value)>` + 维度信息（推荐）

**推荐**：`SparseMatrix { num_rows: usize, num_cols: usize, entries: Vec<SparseEntry> }`，其中 `SparseEntry { row: usize, col: usize, value: Fr }`。

**理由**：
- CCS 矩阵通常极稀疏（每行少量非零项），COO 格式最简
- 不依赖外部稀疏矩阵库
- 序列化简单（length-prefix + entries）
- 可后续按需转为 CSR/CSC 优化 MSM

**未选择 A**：稠密 `Vec<Vec<Fr>>` — 内存爆炸（CCS 矩阵维度 = witness 长度，可达数千）
**未选择 B**：`HashMap<(usize, usize), Fr>` — 非确定性迭代顺序（BTreeMap 更稳但开销大）

### D3：CcsCircuit trait 迁移 — 从 poker_l1 迁入 `precompiles/mod.rs`（推荐）

**推荐**：将 `poker_l1/src/offline/ccs.rs:CcsCircuit` trait 迁入 `poker_zkvm/src/precompiles/mod.rs`，poker_l1 通过 `pub use poker_zkvm::precompiles::CcsCircuit;` re-export（spec L817, L834 要求）。

**理由**：
- spec 明确要求迁移
- 新 trait 签名基于新 CCS 类型（非旧 hash-based）
- 旧 trait 标记 `#[deprecated]`，`LegacyCcsInstanceAdapter` 返回 Err（Phase 11 工作，本计划仅做迁移准备）

### D4：预编译电路实现方式 — CCS 矩阵生成器（推荐）

**推荐**：每个预编译电路是一个 struct，实现 `PrecompileCircuit` trait：
```rust
pub trait PrecompileCircuit: Send + Sync {
    fn name(&self) -> &str;
    fn num_variables(&self) -> usize;
    fn build_ccs(&self) -> Ccs;  // 生成 CCS 矩阵结构
    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError>;
}
```

**理由**：
- 预编译电路本质是固定 CCS 结构 + witness 映射
- 不需要完整电路框架（halo2/arkworks Circuit trait）— Phase 9 递归 verifier 才需要
- 可独立测试：`build_ccs()` + `assign_witness()` + `Ccs::satisfied_by(witness)` 闭环

**未选择 A**：使用 halo2 Circuit trait — 过度工程，Phase 10 不需要递归验证
**未选择 B**：使用 arkworks R1CS — 与 CCS 范式不直接匹配，需转换层

### D5：Poseidon 电路参数 — 复用 syscalls/poseidon.rs 配置（推荐）

**推荐**：Phase 10 Poseidon 电路复用 Phase 4 `syscalls/poseidon.rs` 的参数（alpha=5, rate=2, capacity=1, 8 full + 56 partial rounds），通过 `poseidon_config()` 获取相同配置，确保 host 实现与电路实现一致。

**理由**：
- spec L645 要求电路与 host 输出一致
- 复用配置避免参数不一致 bug

### D6：ZkShuffleCcsCircuit 迁移策略 — 保留为 adapter stub（推荐）

**推荐**：Task 10.5 将 `ZkShuffleCcsCircuit` 从 poker_l1 迁到 `poker_zkvm/src/precompiles/zk_shuffle.rs`，但**保持 stub 实现**（hash-based to_instance），真实 ZkShuffle 电路实现留待 Phase 11（poker_l1 集成时）。

**理由**：
- ZkShuffle 真实电路依赖 `poker_protocol::zk_shuffle`，跨 crate 集成复杂
- 本计划专注预编译电路基础（Poseidon/SHA-256/ECDSA），ZkShuffle 迁移仅做位置搬迁
- spec Task 10.5 仅要求"迁移类型定义与 trait 实现"，不要求真实电路

### D7：LogUp lookup 协议位置 — `lookup/mod.rs`（推荐）

**推荐**：LogUp 协议实现在 `poker_zkvm/src/lookup/mod.rs`（lib.rs 已声明），不在 `constraints/lookup.rs`（tasks.md Task 5.6 路径）。

**理由**：
- lib.rs 已有 `pub mod lookup;` stub
- LogUp 是独立协议，可被多个子电路复用（range check / AND-OR-XOR 真值表 / SHA-256 优化）
- 避免模块嵌套过深

---

## 三、实施步骤

### Step 1：CCS 基础数据结构（Phase 5.0 + Phase 6.1.1/6.1.4）

**目标**：定义 CCS 核心数据结构，为 Phase 10 预编译电路和 Phase 5 约束编译器提供基础。

**文件**：`poker_zkvm/src/ccs/mod.rs`（重写 stub）

**实现内容**：

1. **`SparseEntry` struct** — `{ row: usize, col: usize, value: Fr }`
2. **`SparseMatrix` struct** — `{ num_rows: usize, num_cols: usize, entries: Vec<SparseEntry> }`
   - `new(rows, cols)` / `add_entry(row, col, value)` / `get(row, col) -> Option<Fr>`
   - `evaluate(z: &[Fr]) -> Result<Vec<Fr>, ZkvmError>` — 计算 `M·z`（返回每行内积）
3. **`CcsMatrices` struct** — `{ matrices: Vec<SparseMatrix>, subsets: Vec<Vec<usize>>, coeffs: Vec<Fr> }`
   - 对应 Task 5.1.1
4. **`Ccs` struct** — `{ num_vars: usize, num_matrices: usize, matrices: Vec<SparseMatrix>, subsets: Vec<Vec<usize>>, coeffs: Vec<Fr> }`
   - 对应 Task 6.1.1
   - `satisfied_by(z: &[Fr]) -> Result<bool, ZkvmError>` — 校验 `Σ_i c_i · Π_{j∈S_i} ⟨M_j, z⟩ = 0`
   - `to_lcccs(z: &[Fr], r_x: Fr) -> Lcccs`（占位，Phase 6 实现）
   - `to_cccs(z: &[Fr]) -> Ccccs`（占位，Phase 6 实现）
5. **`CcsInstance` new type** — `{ ccs: Ccs, witness: Vec<Fr>, public_inputs: Vec<Fr> }`
   - 对应 Task 6.1.4（新类型，含矩阵结构与域元素 witness，非 hash-based）

**测试**（TDD RED→GREEN）：
- `test_sparse_matrix_add_and_get` — 添加/查询 entry
- `test_sparse_matrix_evaluate` — M·z 计算正确
- `test_ccs_satisfied_by_simple` — 简单 CCS（1 矩阵，1 subset）satisfied_by 返回 true
- `test_ccs_satisfied_by_violated` — 篡改 witness 后返回 false
- `test_ccs_instance_new_type` — CcsInstance 构造与字段访问
- `test_sparse_matrix_empty` — 空矩阵边界
- `test_ccs_multiple_matrices` — 多矩阵多 subset 场景

**预计测试数**：7-10

---

### Step 2：precompiles 模块骨架 + CcsCircuit trait 迁移（Phase 10.1 + 10.5 准备）

**目标**：创建 precompiles 模块，迁移 CcsCircuit trait，为预编译电路提供注册表。

**文件**：
- 新建 `poker_zkvm/src/precompiles/mod.rs`
- 修改 `poker_zkvm/src/lib.rs`（添加 `pub mod precompiles;`）

**实现内容**：

1. **`PrecompileCircuit` trait**（新 trait，D4 推荐）：
   ```rust
   pub trait PrecompileCircuit: std::fmt::Debug + Send + Sync {
       fn name(&self) -> &str;
       fn num_variables(&self) -> usize;
       fn build_ccs(&self) -> Ccs;
       fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError>;
       fn gas_cost(&self) -> u64;
   }
   ```
2. **`PrecompileRegistry`** — 注册表（HashMap<String, Box<dyn PrecompileCircuit>>）
   - `new()` / `register(circuit)` / `get(name) -> Option<&dyn PrecompileCircuit>`
3. **`CcsCircuit` trait**（从 poker_l1 迁移，但签名基于新 CCS 类型）：
   ```rust
   pub trait CcsCircuit: Send + Sync {
       fn name(&self) -> &str;
       fn num_matrices(&self) -> usize;
       fn to_ccs_instance(&self, witness: &[Fr], public_inputs: &[Fr]) -> Result<CcsInstance, ZkvmError>;
   }
   ```
   - **注意**：poker_l1 旧 `CcsCircuit` trait 的 `to_instance` 签名基于 `Hash` 类型，新签名基于 `Fr` + `CcsInstance` 新类型。本步骤仅定义新 trait，poker_l1 迁移留待 Phase 11。

**测试**：
- `test_precompile_registry_register_and_get`
- `test_precompile_registry_empty`
- `test_ccs_circuit_trait_object_dispatch`

**预计测试数**：3-5

---

### Step 3：Poseidon 预编译电路（Phase 10.2）

**目标**：实现 Poseidon 哈希的 CCS 约束电路，与 host 实现（syscalls/poseidon.rs）输出一致。

**文件**：新建 `poker_zkvm/src/precompiles/poseidon.rs`

**实现内容**：

1. **`PoseidonCircuit` struct** — 含 rate/capacity/full_rounds/partial_rounds 配置（复用 syscalls/poseidon.rs 常量）
2. **`PrecompileCircuit` trait 实现**：
   - `build_ccs()` — 生成 Poseidon permutation 的 CCS 矩阵
     - 每个 S-box（x^5）用 4 个约束表达（x2=x*x, x4=x2*x2, x5=x4*x）
     - MDS matrix 乘法用线性约束表达
     - full round + partial round 分离
   - `assign_witness(inputs)` — 将输入字节转为 Fr，填充 state，执行 permutation，输出 witness 向量
3. **一致性验证**：`build_ccs()` + `assign_witness(inputs)` + `Ccs::satisfied_by(witness)` 闭环
4. **与 host 一致性**：`assign_witness(inputs)` 产生的 output 与 `syscalls::poseidon::poseidon_hash_bytes(inputs)` 一致

**测试**：
- `test_poseidon_circuit_build_ccs` — CCS 结构合理（矩阵数/subset 数/coeff 数）
- `test_poseidon_circuit_satisfied_by` — 合法 witness 通过 satisfied_by
- `test_poseidon_circuit_soundness` — 篡改 witness 后 satisfied_by 失败
- `test_poseidon_circuit_consistency_with_host` — 电路输出 == host `poseidon_hash_bytes` 输出
- `test_poseidon_circuit_empty_input` — 空输入边界
- `test_poseidon_circuit_large_input` — 多 block 输入（rate=2，超过 2 个 Fr 需多 block）

**预计测试数**：6-8

**未选择方案**：
- 完整 Poseidon 电路（含 56 partial rounds 全部约束）— 约束数 ~200/round × 64 rounds = 12800 约束，实现量大；MVP 阶段先实现单 round 验证结构，多 round 用重复结构生成
- lookup 优化 Poseidon（部分 S-box 通过查表）— 依赖 LogUp（Phase 5.6），本步骤先用纯约束

---

### Step 4：SHA-256 预编译电路（Phase 10.3）

**目标**：实现 SHA-256 哈希的 CCS 约束电路，与 `sha2` crate 输出一致。

**文件**：新建 `poker_zkvm/src/precompiles/sha256.rs`

**实现内容**：

1. **`Sha256Circuit` struct** — 含 block_size=64 / output_size=32 配置
2. **`PrecompileCircuit` trait 实现**：
   - `build_ccs()` — 生成 SHA-256 round 的 CCS 矩阵
     - message schedule（64 words）：线性反馈 `w[i] = w[i-3] ⊕ w[i-8] ⊕ w[i-14] ⊕ w[i-16]` + rotl
     - compression round：选择函数 `ch` / 多数函数 `maj` + 加法 + rotl
     - 32-bit 加法约束（mod 2^32，需 overflow_bit 处理）
   - `assign_witness(inputs)` — 填充 message schedule，执行 compression，输出 witness
3. **一致性验证**：与 `sha2::Sha256` 输出一致

**测试**：
- `test_sha256_circuit_build_ccs`
- `test_sha256_circuit_satisfied_by`
- `test_sha256_circuit_soundness`
- `test_sha256_circuit_consistency_with_sha2_crate` — 与 `sha2::Sha256::digest` 一致
- `test_sha256_circuit_empty_input` — 空输入（SHA-256("") = e3b0c442...）
- `test_sha256_circuit_known_vectors` — NIST 测试向量（"abc", "hello world"）

**预计测试数**：6-8

**未选择方案**：
- lookup 优化 SHA-256（~25,000 → ~5,000 约束）— 依赖 LogUp，本步骤先用纯约束
- 完整 64 round 实现 — MVP 阶段可先实现单 block（512-bit），多 block 用 Merkle-Damgård 迭代扩展

---

### Step 5：ECDSA 预编译电路（Phase 10.4）

**目标**：实现 secp256k1 ECDSA 验签的 CCS 约束电路。

**文件**：新建 `poker_zkvm/src/precompiles/ecdsa.rs`

**实现内容**：

1. **`EcdsaVerifyCircuit` struct** — 含 secp256k1 参数（p, n, Gx, Gy）
2. **`PrecompileCircuit` trait 实现**：
   - `build_ccs()` — 生成 ECDSA verify 的 CCS 矩阵
     - secp256k1 标量乘：`__mulsi3` shift-add × 256 次（每次 ~192 约束）
     - 点加法 / 倍点约束
     - 哈希约束（SHA-256 电路复用或内联）
     - 最终比较约束
     - **总约束数 ≈ 110,000**（spec L659）
   - `assign_witness(inputs)` — 输入 (msg, sig, pubkey)，输出 witness
3. **返回值**：a0=1/0（bool，与 host `ecdsa_verify` 一致）

**测试**：
- `test_ecdsa_circuit_build_ccs`
- `test_ecdsa_circuit_satisfied_by_valid_sig` — 合法签名通过
- `test_ecdsa_circuit_soundness_tampered_msg` — 篡改 msg 失败
- `test_ecdsa_circuit_soundness_tampered_sig` — 篡改 sig 失败
- `test_ecdsa_circuit_soundness_tampered_pubkey` — 篡改 pubkey 失败
- `test_ecdsa_circuit_consistency_with_host` — 与 `syscalls::host::EcdsaVerify` 输出一致

**预计测试数**：6-8

**未选择方案**：
- 完整 110,000 约束实现 — 极大实现量；MVP 阶段先实现约束结构骨架 + 关键路径（点加法 + 标量乘框架），具体约束数允许与 spec 估算有偏差
- 使用 halo2-ecc 库 — 引入新依赖，与 CCS 范式不匹配

---

### Step 6：ZkShuffleCcsCircuit 迁移（Phase 10.5）

**目标**：将 `ZkShuffleCcsCircuit` 从 poker_l1 迁到 poker_zkvm，保持 stub 实现。

**文件**：
- 新建 `poker_zkvm/src/precompiles/zk_shuffle.rs`
- 修改 `poker_l1/src/offline/ccs.rs`（添加 `pub use poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit;` re-export，旧定义标记 `#[deprecated]`）

**实现内容**：

1. **`ZkShuffleCcsCircuit` struct** — 迁移自 poker_l1，保持 stub 行为（hash-based to_instance）
2. **实现 `CcsCircuit` trait**（新签名）— stub 返回 `Err(Other("ZkShuffle real circuit pending Phase 11"))`
3. **poker_l1 re-export** — 通过 `pub use` 引用迁移后类型
4. **旧 poker_l1 `ZkShuffleCcsCircuit` 标记 `#[deprecated]`** — Phase 11 完成真实迁移

**测试**：
- `test_zk_shuffle_circuit_migration` — 新位置类型可构造
- `test_zk_shuffle_circuit_deprecated_in_poker_l1` — poker_l1 旧类型标记 deprecated
- `test_zk_shuffle_circuit_re_export` — poker_l1 re-export 路径可访问

**预计测试数**：3-4

**注意**：本步骤不修改 poker_l1 测试（避免破坏现有测试），仅添加 re-export 和 deprecated 标记。Phase 11 完成完整迁移。

---

### Step 7：Phase 10 集成测试 + alternatives.md 更新

**目标**：验证 Phase 10 全部预编译电路集成，更新文档。

**文件**：
- 修改 `poker_zkvm/src/precompiles/mod.rs`（集成测试）
- 修改 `poker_zkvm/docs/alternatives.md`（Phase 10 章节）

**测试**：
- `test_precompile_registry_full` — 注册全部 4 个预编译电路（Poseidon/SHA-256/ECDSA/ZkShuffle）
- `test_all_precompiles_implement_trait` — 全部实现 PrecompileCircuit trait
- `test_poseidon_sha256_ecdsa_gas_costs` — gas 计费常量合理

**文档**：
- alternatives.md 添加 Phase 10 章节（推荐方案 + 未选择方案 + 实现期发现）

**预计测试数**：3-5

---

### Step 8：Phase 5 Task 5.1 — compile_trace_to_ccs 主入口 + batching

**目标**：实现 trace → CCS 实例编译器主入口，含 batching 策略。

**文件**：重写 `poker_zkvm/src/constraints/mod.rs`

**实现内容**：

1. **`compile_trace_to_ccs(trace: &Trace, batch_size: usize) -> Result<Vec<CcsInstance>, ZkvmError>`**
   - 每 K = `ZKVM_BATCH_SIZE`（默认 1024）步生成 1 个 CCS 实例
   - 校验 `instances.len() ≤ MAX_FOLD_STEP_COUNT = 1000`，超出返回 `FoldStepCountExceeded`
2. **连续性约束**（Task 5.1.4）— step i 输出寄存器 == step i+1 输入寄存器（batch 内）
3. **batch 间连续性约束**（Task 5.1.5）— 前一 batch 末步输出 == 后一 batch 首步输入

**测试**：
- `test_compile_trace_to_ccs_small` — 小 trace（10 步，batch_size=4）→ 3 个 CCS 实例
- `test_compile_trace_to_ccs_batch_boundary` — batch 边界连续性约束
- `test_compile_trace_to_ccs_fold_step_limit` — 超过 1000 个实例返回 FoldStepCountExceeded
- `test_compile_trace_to_ccs_empty_trace` — 空 trace 边界

**预计测试数**：4-6

---

### Step 9：Phase 5 Task 5.2 — 算术指令子电路

**目标**：实现算术指令的 CCS 约束子电路。

**文件**：新建 `poker_zkvm/src/constraints/algebra.rs`

**实现内容**：

1. ADD / ADDI（含 overflow_bit 约束）
2. SUB / SLT / SLTU
3. SLL / SRL / SRA（shift amount bit-decompose 为 5 bit）
4. AND / OR / XOR（lookup 优化留待 Task 5.6，先用纯约束）
5. RV32M DIV / DIVU / REM / REMU（除零语义）

**测试**：每条指令正例 + 边界（除零 / MIN/-1 / overflow）

**预计测试数**：15-20

---

### Step 10：Phase 5 Task 5.3 — 内存访问与一致性电路

**目标**：实现内存访问子电路 + byte-level permutation。

**文件**：重写 `poker_zkvm/src/constraints/memory.rs`

**实现内容**：

1. LW/SW/LB/SB/LH/SH/LBU/LHU 子电路
2. byte-level permutation（key = `(byte_addr, byte_val, step_index)`）
3. 混合尺寸重叠访问处理（LW 写 4B 后 LB 读 1B）
4. 地址 range check（checked_add 防 wrap）
5. 未初始化读取检测（返回 `UninitializedRead`）

**测试**：read-after-write / 未初始化读取 / 混合尺寸重叠 / aliasing 攻击负例

**预计测试数**：10-15

---

### Step 11：Phase 5 Task 5.4 — 控制流指令子电路

**目标**：实现控制流指令的 CCS 约束子电路。

**文件**：新建 `poker_zkvm/src/constraints/control_flow.rs`

**实现内容**：

1. JAL / JALR（pc 更新约束）
2. BEQ / BNE / BLT / BGE / BLTU / BGEU（条件求值）
3. LUI / AUIPC

**测试**：跳转目标计算 / 条件分支判定

**预计测试数**：8-12

---

### Step 12：Phase 5 Task 5.5 — Syscall 子电路

**目标**：实现 ECALL 子电路，分派到 Phase 10 预编译电路。

**文件**：新建 `poker_zkvm/src/constraints/syscall_circuit.rs`

**实现内容**：

1. ECALL 子电路 — 解码 `a7`，根据 syscall_id 选择对应预编译子电路
2. 每个 syscall 调用产生独立 CCS 实例（与指令实例合并折叠）
3. **复用 Phase 10 预编译电路**：Poseidon/SHA-256/ECDSA 通过 `PrecompileRegistry` 查找

**测试**：
- `test_syscall_circuit_poseidon` — Poseidon syscall 生成 CCS 实例
- `test_syscall_circuit_sha256` — SHA-256 syscall
- `test_syscall_circuit_ecdsa` — ECDSA syscall
- `test_syscall_circuit_read_input` — read_input（简单 buffer copy）
- `test_syscall_circuit_commit_output` — commit_output
- `test_syscall_circuit_emit_event` — emit_event（绑定 step_index）
- `test_syscall_circuit_get_randomness` — get_randomness（deterministic）
- `test_syscall_circuit_read_state` — read_state（slot 白名单）
- `test_syscall_circuit_log_panic` — log / panic

**预计测试数**：9-12

---

### Step 13：Phase 5 Task 5.6 — LogUp lookup 协议

**目标**：实现 LogUp lookup 协议。

**文件**：重写 `poker_zkvm/src/lookup/mod.rs`

**实现内容**：

1. `LookupTable { entries: Vec<Fr>, f: fn(Fr) -> Fr }`
2. `LogUpProof` — 严格 absorb 顺序：C_T → C_f → C_m → absorb → β
3. 校验等式 `Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)`
4. lookup 实例作为附加 CCS 实例（NIRVANA 风格）
5. 内置 lookup 表：u8 / u16 / u32 range、AND / OR / XOR 真值表

**测试**：
- 正例（含 `m_i = 0` 边界）
- soundness 负例（β 派生时机错误 / multiplicity 伪造）

**预计测试数**：8-10

---

### Step 14：Phase 5 集成测试 + alternatives.md 更新

**目标**：验证 Phase 5 全部约束编译器集成，更新文档。

**文件**：
- 修改 `poker_zkvm/src/constraints/mod.rs`（集成测试）
- 修改 `poker_zkvm/docs/alternatives.md`（Phase 5 章节）

**测试**：
- `test_compile_trace_to_ccs_full_pipeline` — 完整 trace（含算术/内存/控制流/syscall）→ CCS 实例
- `test_phase5_all_subcircuits_satisfied_by` — 全部子电路 satisfied_by 通过

**文档**：
- alternatives.md 添加 Phase 5 章节

**预计测试数**：2-4

---

## 四、验证步骤

每个 Step 完成后须通过：

1. **`cargo test -p poker_zkvm`** — 全部测试通过（含新增 + 既有 319 测试）
2. **`cargo clippy -p poker_zkvm --all-targets -- -D warnings`** — 零警告
3. **`cargo build -p poker_zkvm --bin cargo-zkvm`** — 二进制构建成功
4. **`#![deny(unsafe_code)]` + `#![deny(missing_docs)]`** — 全部新增 public item 有 `///` 文档

最终验证（Step 14 完成后）：
- **总测试数** ≈ 319（既有）+ 90-130（新增）= 409-449
- **clippy 零警告**
- **alternatives.md** 含 Phase 10 + Phase 5 章节

---

## 五、假设与约束

1. **spec v1.4 FROZEN** — 严格遵循 spec.md L268-312（Phase 5）+ L637-669（syscall 电路）+ tasks.md L121-159（Phase 5 tasks）+ L292-311（Phase 10 tasks）
2. **TDD 严格模式** — 每个 Step 按 RED → GREEN → REFACTOR，测试通过后才进入下一步
3. **不修改 Phase 0-4 既有代码** — 除 lib.rs 添加 `pub mod precompiles;` 外，不改动既有模块
4. **poker_l1 修改最小化** — 仅 Step 6 添加 re-export + deprecated 标记，不破坏现有测试
5. **Phase 6+ 不在本计划范围** — Hypernova 折叠（Lcccs/Ccccs/fold/sumcheck）留待后续 Phase
6. **Phase 5.5（Proof 序列化 + Witness 生成）不在本计划范围** — 依赖 Phase 6 HypernovaProof 结构，留待 Phase 6 后
7. **CCS 数据结构为 Phase 6 预留** — `to_lcccs()` / `to_cccs()` 方法签名定义但返回 `Err(Other("Phase 6 pending"))`

---

## 六、未选择方案汇总（跨步骤）

| ID | 方案 | 未选择理由 |
|----|------|-----------|
| A-CCS-LOC | 新建 `fold/` 目录 | 改动大，lib.rs 已有 `ccs` stub |
| A-SPARSE | 稠密矩阵 `Vec<Vec<Fr>>` | 内存爆炸 |
| A-CIRCUIT | halo2 Circuit trait | 过度工程，Phase 10 不需递归验证 |
| A-R1CS | arkworks R1CS | 与 CCS 范式不匹配 |
| A-LOOKUP-OPT | lookup 优化 Poseidon/SHA-256 | 依赖 LogUp，先纯约束 |
| A-FULL-ECDSA | 完整 110,000 约束 ECDSA | 实现量极大，MVP 先骨架 |
| A-PHASE6-FOLD | 本计划含 Phase 6 折叠 | 范围过大，留待后续 |

---

## 七、执行顺序总结

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

**预计总测试数**：90-130 新增（Step 1: 7-10, Step 2: 3-5, Step 3: 6-8, Step 4: 6-8, Step 5: 6-8, Step 6: 3-4, Step 7: 3-5, Step 8: 4-6, Step 9: 15-20, Step 10: 10-15, Step 11: 8-12, Step 12: 9-12, Step 13: 8-10, Step 14: 2-4）

**预计总文件改动**：
- 新建：`precompiles/{mod,poseidon,sha256,ecdsa,zk_shuffle}.rs`（5 文件）+ `constraints/{algebra,control_flow,syscall_circuit}.rs`（3 文件）
- 重写：`ccs/mod.rs` + `constraints/mod.rs` + `constraints/memory.rs` + `lookup/mod.rs`（4 文件）
- 修改：`lib.rs` + `poker_l1/src/offline/ccs.rs` + `docs/alternatives.md`（3 文件）
