# poker\_zkvm 审核问题修复计划

## Context

审核发现 poker\_zkvm 存在 4 个 CRITICAL 级别问题（C-1 至 C-4）和 7 个 HIGH 级别问题（H-1 至 H-7），核心矛盾是：

1. **C-1 健全性漏洞**：`compile_batch_to_ccs` 仅约束 `step_index` 单调递增，未接入指令语义子电路，zkVM 实际未证明程序执行
2. **C-2/C-3/C-4 压缩失效**：CycleFold 伪压缩 + Spartan/Groth16 stub + 基准 500 步 panic，proof 无法满足 64KB 上链限制
3. **H-1 预编译残缺**：4 个预编译中 3 个残缺、1 个纯 stub
4. **H-2 batch\_size=3 限制**：导致 fold step 数爆炸，proof 线性增长

本计划分 3 个 Stage 实施，总工期 5-7 周。Stage 1 修复 proof 大小问题（绕过压缩需求），Stage 2 修复健全性漏洞（最关键），Stage 3 补全预编译与真实压缩。

## Stage 1：Proof 大小修复（\~3-5 天）

**目标**：解除 `batch_size=3` 限制，使 1000 步 proof < 64KB，修复 C-4 基准 panic，使 C-2/C-3 非阻断。

### 核心改动

**1.1 CCS padding 到 2 的幂** — [src/constraints/mod.rs:132-192](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L132-L192)

当前 `compile_batch_to_ccs` 中 `num_vars = k+1`、`num_rows = k-1`，要求两者均为 2 的幂。改为：

* 计算 `padded_num_vars = (num_vars).next_power_of_two()`

* 计算 `padded_num_rows = (num_rows).next_power_of_two()`

* 矩阵扩展到 `padded_num_rows × padded_num_vars`，新增列/行填 0（dummy 约束 `0 = 0`）

* witness 用 0 填充到 `padded_num_vars`

**1.2 单实例 proof 路径** — [src/prover/mod.rs:724-879](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L724-L879)

当前 `prove()` 要求 `ccs_instances.len() >= 2`。新增分支：若仅 1 个 CCS 实例，跳过 `fold_loop`，直接构造单实例 proof：

* LCCCS 从该实例构造

* 无 fold\_steps

* PCS opening 直接对该实例 witness 承诺

* 序列化格式保持兼容（fold\_steps 为空）

需调整 `verify_production`（[src/verifier.rs:138-259](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs#L138-L259)）处理空 fold\_steps 情况（当前 L269-271 会拒绝空 fold\_steps，需放宽：单实例 proof 允许空 fold\_steps，但 PCS opening 仍需验证）。

**1.3 恢复 batch\_size 默认值** — [src/prover/mod.rs:78-93](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L78-L93)

`ProverConfig::default().batch_size` 从 3 改为 `crate::constraints::ZKVM_BATCH_SIZE`（1024）。移除 `batch_size+1 须为 2 的幂` 的 MVP 限制（由 1.1 padding 解决）。

**1.4 统一 proof size 常量** — [src/prover/mod.rs:44-58](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L44-L58)

* `MAX_ZKVM_PROOF_SIZE = 64KB`（保留，spec 上链限制）

* `MAX_PROOF_TOTAL_SIZE`：从 512KB 改为对齐 v1.3 治理参数 `8KB+8KB+16KB+8KB=40KB`，留余量至 64KB

* 修正注释，消除三者矛盾

**1.5 基准测试修复** — [benches/phase12\_benchmarks.rs](file:///Users/mac/projects/zchain/poker_zkvm/benches/phase12_benchmarks.rs)

* `BATCH_SIZE` 从 3 改为 1024

* 移除 `expect("prove 应成功")`，改为正确处理错误

* 更新 README 基准表（[README.md:108-113](file:///Users/mac/projects/zchain/poker_zkvm/README.md#L108-L113)）

### Stage 1 验证

```bash
cargo test -p poker_zkvm --features test-helpers --lib
cargo test -p poker_zkvm --features test-helpers --test e2e_fibonacci
cargo test -p poker_zkvm --features test-helpers --test e2e_sha256_chain
cargo test -p poker_zkvm --features test-helpers --test e2e_poker_hand_eval
cargo bench -p poker_zkvm --features test-helpers --bench phase12_benchmarks -- --quick
```

通过标准：

* 全部测试通过

* 基准 100/500/1000 步均完成，无 panic

* 1000 步 proof < 64KB

***

## Stage 2：完整 RV32I 指令语义约束（\~2-3 周）

**目标**：修复 C-1 健全性漏洞，将 37 条 RV32I base 指令的语义约束接入 `compile_batch_to_ccs`。

### 设计：CCS 行拼接 + 统一 witness 布局

**witness 布局扩展**（替换当前 `[1, idx_0..idx_{K-1}]`）：

```
z = [1,
     idx_0, pc_0, opcode_0, rs1_val_0, rs2_val_0, rd_val_0, imm_0, flag_0,  // step 0
     idx_1, pc_1, opcode_1, rs1_val_1, rs2_val_1, rd_val_1, imm_1, flag_1,  // step 1
     ...
     idx_{K-1}, pc_{K-1}, ...]                                               // step K-1
```

每步 8 个变量 × K 步 + 1 常数 = `8K + 1`。Padding 到 2 的幂（Stage 1.1 已实现）。

**约束矩阵行拼接**：

* 前 `K-1` 行：step\_index 连续性（保留现有约束）

* 接下来 `K` 组行：每步的指令语义约束（按 instruction 类型分派）

* 最后 `K` 组行：PC 递增约束（`pc_{i+1} = pc_i + 4` 或跳转目标）

* 内存访问约束：通过 LogUp lookup（read-after-write 一致性）

### 实现步骤

**2.1 重构** **`compile_batch_to_ccs`** — [src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)

新增 `compile_step_to_constraints(step: &Step) -> StepConstraints`，返回该步的：

* witness 赋值（8 个变量）

* 约束矩阵行（按指令类型分派）

* LogUp lookup 条目（内存访问、range check）

`compile_batch_to_ccs` 聚合所有 step 的约束，行拼接成统一 CCS。

**2.2 指令语义约束实现** — 扩展 [src/constraints/algebra.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/algebra.rs), [control\_flow.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/control_flow.rs), [memory.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/memory.rs)

每条指令实现 `fn constrain(step: &Step) -> (Vec<ConstraintRow>, Vec<LookupEntry>)`：

| 指令组       | 指令                                           | 约束要点                                                         |
| --------- | -------------------------------------------- | ------------------------------------------------------------ |
| 算术 R-type | ADD/SUB/AND/OR/XOR/SLT/SLTU/SLL/SRL/SRA      | 复用现有 AddCircuit/SubCircuit 模式；移位需 bit 分解 + LogUp range check |
| 算术 I-type | ADDI/SLTI/SLTIU/XORI/ORI/ANDI/SLLI/SRLI/SRAI | 同上，imm 替换 rs2                                                |
| Load      | LB/LH/LW/LBU/LHU                             | 内存读约束 + LogUp lookup（addr+step → value）+ 符号扩展                |
| Store     | SB/SH/SW                                     | 内存写约束 + LogUp lookup + 字节展开                                  |
| Branch    | BEQ/BNE/BLT/BGE/BLTU/BGEU                    | 比较约束 + PC 条件跳转                                               |
| Jump      | JAL/JALR                                     | PC 跳转约束 + rd = pc+4                                          |
| Upper     | LUI/AUIPC                                    | imm 高位约束                                                     |
| System    | ECALL/EBREAK/FENCE                           | syscall\_id 约束 + halt 标志                                     |

**2.3 LogUp lookup 集成** — [src/constraints/lookup.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs) + [src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)

将 `LogUpProof` 接入 batch CCS：

* u8 range table（0-255）：所有 byte 值 range check

* u5 range table（0-31）：移位量 range check

* 内存访问表：(addr, step, value) 三元组，read multiplicity = write multiplicity

* 指令 opcode table：合法 opcode range check

**2.4 PC 与寄存器连续性约束** — 新增于 [src/constraints/control\_flow.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/control_flow.rs)

* 顺序执行：`pc_{i+1} = pc_i + 4`

* 跳转执行：`pc_{i+1} = pc_i + imm`（JAL/B-type 条件成立时）

* 寄存器一致性：`rd_val_i` 写入后，后续步骤读取 `rs1_val_j = rd_val_i`（需 LogUp register file lookup 或直接约束）

**2.5 测试** — 新增 `tests/instruction_semantics_tests.rs`

每条指令至少 2 个测试：

* 正例：正确执行 → CCS satisfied

* 负例：篡改 result/pc/registers → CCS not satisfied

集成测试：fibonacci/sha256\_chain/poker\_hand\_eval 的 trace 经 `compile_batch_to_ccs` 后 CCS 实例全部 satisfied。

### Stage 2 验证

```bash
cargo test -p poker_zkvm --features test-helpers --test instruction_semantics_tests
cargo test -p poker_zkvm --features test-helpers --test soundness_tests
# 新增 soundness 测试：篡改 trace 寄存器值 → verify_production 拒绝
cargo test -p poker_zkvm --features test-helpers --test e2e_fibonacci
```

通过标准：

* 37 条 RV32I 指令均有正负测试

* 篡改任意 step 的 register/pc/memory → CCS not satisfied → proof 验证失败

* 所有 E2E 测试通过

***

## Stage 3：预编译补全 + 真实压缩（\~2-3 周）

**目标**：修复 H-1（预编译残缺）和 C-2（CycleFold 伪压缩）。

### 3a. Poseidon 完整 permutation（\~3 天）

[src/precompiles/poseidon.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/poseidon.rs)

* 扩展现有 S-box `x^5` 约束为完整 permutation：3 轮 × 64 cells

* 实现 `assign_witness`：从 input 计算 3 轮完整 witness

* gas\_cost 从 200 调整为实际值

* 测试：已知 Poseidon test vectors

### 3b. SHA-256 完整 compression（\~5 天）

[src/precompiles/sha256.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/sha256.rs)

* 扩展 Ch 函数为完整 64-round compression

* 实现 Maj、Σ0、Σ1 函数约束

* 消息调度（message schedule）约束

* 测试：NIST SHA-256 test vectors

### 3c. ECDSA 完整验签（\~5 天）

[src/precompiles/ecdsa.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/ecdsa.rs)

* 扩展 single double-and-add 为 256-step 完整标量乘

* 实现 ECDSA verify equation：`r = x-coordinate(k·G) mod n`

* bit decomposition 约束 + LogUp range check

* 测试：已知 ECDSA 签名验证用例

### 3d. ZkShuffle 集成 poker\_protocol（\~5 天）

[src/precompiles/zk\_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs)

* 替换 stub 为 `poker_protocol::zk_shuffle` 真实电路

* 实现 `assign_witness`：从 shuffle witness 计算 CCS witness

* 实现 `to_ccs_instance`：生成可折叠的 CCS 实例

* 测试：ZkShuffle 已知 test vector

### 3e. 真实 CycleFold 压缩（\~7 天）

[src/recursion/mod.rs:253-280](file:///Users/mac/projects/zchain/poker_zkvm/src/recursion/mod.rs#L253-L280)

替换 `aggregated_proof = left.proof().clone()` 为真实 IPA 递归聚合：

**方案选择**：IPA recursive aggregation（非 SNARK 电路，复用现有 IPA PCS）

* 将 `verify_hypernova(left)` + `verify_hypernova(right)` 编码为 CCS 实例

* fold 这两个 CCS 实例 → 单个 folded LCCCS

* PCS opening 证明 folded witness 满足 "验证了 left 和 right"

* 聚合后 proof 大小 ≈ 单个 Hypernova proof（不再随 K 增长）

**未选方案**：Spartan sumcheck-based SNARK（需全新实现 sumcheck protocol over R1CS，工作量更大）；Groth16（需 trusted setup，违反 transparent 原则）。

### Stage 3 验证

```bash
cargo test -p poker_zkvm --features test-helpers --lib precompiles
cargo test -p poker_zkvm --features test-helpers --test e2e_poker_hand_eval
cargo test -p poker_zkvm --features test-helpers --lib recursion
# 新增测试：K=8 proof 聚合后大小 < 单个 proof
```

通过标准：

* 4 个预编译全部通过已知 test vector

* ZkShuffle `to_ccs_instance` 不再返回 stub 错误

* CycleFold 聚合 K=8 后 proof 大小 < 单个 sub-proof

***

## 文件影响汇总

### Stage 1（修改 6 文件）

* `src/constraints/mod.rs` — padding 逻辑

* `src/prover/mod.rs` — 单实例 proof + batch\_size 默认值 + 常量统一

* `src/verifier.rs` — 空 fold\_steps 处理

* `benches/phase12_benchmarks.rs` — batch\_size 修复

* `README.md` — 基准表更新

* `src/lib.rs` — 无需改

### Stage 2（修改 5 文件，新增 1 文件）

* `src/constraints/mod.rs` — 重构 `compile_batch_to_ccs`

* `src/constraints/algebra.rs` — 补全 10 条算术指令约束

* `src/constraints/control_flow.rs` — 补全 10 条控制流指令约束

* `src/constraints/memory.rs` — 补全 Load/Store 约束

* `src/constraints/syscall_circuit.rs` — ECALL 完整语义

* `tests/instruction_semantics_tests.rs` — 新增

### Stage 3（修改 5 文件）

* `src/precompiles/poseidon.rs` — 完整 permutation

* `src/precompiles/sha256.rs` — 完整 compression

* `src/precompiles/ecdsa.rs` — 完整验签

* `src/precompiles/zk_shuffle.rs` — 集成 poker\_protocol

* `src/recursion/mod.rs` — 真实 IPA 递归聚合

***

## 跨 Stage 约束

1. **Stage 1 必须先于 Stage 2**：Stage 2 的指令约束会产生更多 witness 变量，需要 Stage 1 的 padding 机制保证 num\_vars 为 2 的幂。

2. **Stage 2 必须先于 Stage 3e**：CycleFold 真实压缩需要折叠 "验证 Hypernova proof" 的 CCS 实例，该 CCS 实例依赖完整的指令语义约束（否则压缩的只是 step\_index 连续性）。

3. **Stage 3a-3d 相互独立**：4 个预编译可并行开发。

4. **测试驱动**：每个 Stage 完成后必须全部测试通过 + clippy clean + 基准可运行，才能进入下一 Stage。

***

## 风险与缓解

| 风险                                                      | 影响         | 缓解                                        |
| ------------------------------------------------------- | ---------- | ----------------------------------------- |
| Stage 2 witness 膨胀导致 num\_vars 超过 MAX\_N\_VARS=24（2^24） | prove() 失败 | 每步 8 变量 × 1024 步 = 8192 ≈ 2^13，远低于上限      |
| Stage 2 LogUp lookup 表过大                                | proof 增长   | u8 range table 仅 256 项，内存表按需构造            |
| Stage 3e IPA 递归聚合复杂度高                                   | 延期         | 可降级为 "K 个 proof 串联验证"（无压缩但有 soundness 保证） |
| Stage 3d ZkShuffle 依赖 poker\_protocol API 变化            | 集成失败       | 先固定 poker\_protocol 版本，再迁移                |

***

## 最终验证

全部 3 个 Stage 完成后：

```bash
# 1. 全量测试
cargo test -p poker_zkvm --features test-helpers
# 2. Clippy
cargo clippy -p poker_zkvm --features test-helpers --all-targets -- -D warnings
# 3. 基准（100/500/1000 步均 < 64KB）
cargo bench -p poker_zkvm --features test-helpers --bench phase12_benchmarks -- --quick
# 4. Soundness（篡改 trace 任意字段 → 拒绝）
cargo test -p poker_zkvm --features test-helpers --test soundness_tests
# 5. 预编译（4 个均非 stub）
cargo test -p poker_zkvm --features test-helpers --lib precompiles
```

修复完成的标志：

* C-1：`compile_batch_to_ccs` 接入全部 37 条 RV32I 指令语义约束

* C-2：CycleFold 聚合 K=8 后 proof < 单个 sub-proof

* C-3：Spartan/Groth16 保留 stub（由 Stage 1 的 padding + Stage 3e 的 IPA 递归绕过）

* C-4：基准 100/500/1000 步无 panic，proof < 64KB

* H-1：4 个预编译全部通过已知 test vector

* H-2：batch\_size=1024 可用

* H-5：proof size 常量统一且对齐 v1.3 治理参数

