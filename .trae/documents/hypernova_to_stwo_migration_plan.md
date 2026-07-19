# Hypernova → Stwo 迁移实施计划

> **⚠️ DEPRECATED（2026-07-20）**：本文档为 v1 fold 改写路线，已被 [hypernova_to_stwo_migration_plan_v2.md](hypernova_to_stwo_migration_plan_v2.md) 取代。
> v2 路线完全放弃 Hypernova 兼容，采用原生 M31 trace + Stwo 原生 AIR + 递归证明。
> 本文档保留作为历史参考，不再作为实施依据。

> **目标**：将 poker\_zkvm 证明系统从 Hypernova（CCS + IPA on BN254）全量替换为 Stwo（Circle STARK + AIR + FRI on M31）
> **预期收益**：\~1000× prove 加速（与 Nexus zkVM 3.0 对齐）
> **总工期**：14-20 周（3.5-5 个月）
> **决策依据**：用户明确选择全量替换、直接用 poker ELF、官方 crate 依赖、先搭骨架

***

## Context（背景与动机）

### 问题

当前 poker\_zkvm 使用 Hypernova + CCS + IPA PCS on BN254，实测性能远不达预期：

* 0-fold 路径（batch\_size=256，80 步）：8.67s

* 1-fold 路径（batch\_size=41，80 步）：128.08s

* 单 fold 步增量：119s（sumcheck::prove 占 \~95%）

瓶颈根因：BN254 254-bit Fr 域运算极其昂贵，每步 fold 需 40 轮 × O(N) Fr 运算（N=2^20=1M）。

### 解决方案

转向 Stwo（Circle STARK + AIR + FRI on M31）：

* M31 31-bit field 原生 CPU 32-bit word 支持（\~8-16× 加速）

* 无 fold 步开销（单次 STARK prove）

* FRI 高度并行（\~2-4× 加速）

* Nexus zkVM 3.0 已验证 \~1000× 加速

### 关键架构洞察（已确认）

**precompile 不参与主证明**：

* grep 确认 `prover/`、`constraints/`、`fold/` 中无 `PrecompileCircuit::build_ccs` 调用

* `prove()` 流程（[prover/mod.rs:966](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L966)）仅包含：ELF → trace → CCS → fold → proof

* zk\_shuffle 由 `poker_protocol::zk_shuffle` 独立证明（[state\_machine.rs:31-35](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/state_machine.rs#L31-L35)）

* `proof_kind` 双通道分派（[zk\_verifier.rs:33-42](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs#L33-L42)）：scheme\_id=1 → Zkvm，scheme\_id=4 → ZkShuffle

→ **Stwo 主 AIR 不含 BN254 G1 约束，加速比预期 \~1000×**

***

## 当前架构与迁移边界

### 保持不变（VM 核心，与证明系统无关）

| 模块             | 路径                                                                                                       | 说明                           |
| -------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------- |
| ELF 校验         | [compiler/elf\_validator.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/compiler/elf_validator.rs) | validate\_elf()              |
| ELF 执行         | [isa/executor.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/executor.rs)                      | execute\_elf\_with\_config() |
| Trace 生成       | [trace/](file:///Users/mac/projects/zchain/poker_zkvm/src/trace)                                         | Step, Trace 结构               |
| 指令集            | [isa/](file:///Users/mac/projects/zchain/poker_zkvm/src/isa)                                             | RV32I Instruction enum       |
| Syscalls       | [syscalls/](file:///Users/mac/projects/zchain/poker_zkvm/src/syscalls)                                   | host 函数                      |
| ZkPublicIo     | [prover/mod.rs:154](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L154)                 | 公共输入输出                       |
| CheckinTx      | [poker\_l1/src/tx/checkin.rs](file:///Users/mac/projects/zchain/poker_l1/src/tx/checkin.rs)              | 链上交易结构                       |
| proof\_kind 分派 | [zk\_verifier.rs:33-77](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs#L33-L77)   | scheme\_id 路由                |

### 需要重写（证明系统特定）

| 模块             | 路径                                                                                                 | 迁移方式                                              |
| -------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| CCS 编译         | [constraints/mod.rs:416](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L416) | compile\_trace\_to\_ccs → compile\_trace\_to\_air |
| CCS 结构         | [ccs/](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs)                                       | 删除，替换为 AIR                                        |
| Hypernova fold | [fold/](file:///Users/mac/projects/zchain/poker_zkvm/src/fold)                                     | 删除（Stwo 无 fold）                                   |
| IPA PCS        | [pcs/ipa.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/pcs/ipa.rs)                          | 删除，替换为 FRI                                        |
| Recursion      | [recursion/](file:///Users/mac/projects/zchain/poker_zkvm/src/recursion)                           | 删除（Stwo 有自己的递归）                                   |
| Prover         | [prover/mod.rs:966](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L966)           | prove() 重写                                        |
| Verifier       | [verifier.rs:70](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs#L70)                 | verify\_production() 重写                           |
| Transcript     | [transcript.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/transcript.rs)                    | 替换为 Stwo transcript                               |
| Field          | [field.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/field.rs)                              | BN254 Fr → M31                                    |

### 可复用的约束逻辑（witness 赋值）

| 函数                     | 路径                                                                                                 | 复用方式                        |
| ---------------------- | -------------------------------------------------------------------------------------------------- | --------------------------- |
| compile\_step\_witness | [constraints/mod.rs:371](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L371) | witness 行生成逻辑，域转换 BN254→M31 |
| instruction\_category  | [constraints/mod.rs:118](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L118) | selector 分类逻辑               |
| assign\_selectors      | [constraints/mod.rs:170](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L170) | one-hot selector 赋值         |
| extract\_insn\_fields  | [constraints/mod.rs:179](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L179) | 指令字段提取                      |
| compute\_taken         | [constraints/mod.rs:231](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L231) | 分支 taken flag               |

***

## Stwo 依赖配置

### Cargo.toml 添加依赖

```toml
[dependencies]
stwo = { version = "2.3", features = ["parallel"] }
stwo-air-utils = "2.3"
stwo-air-utils-derive = "2.3"
stwo-constraint-framework = "2.3"
```

### 关键 API（参考 [Stwo AIR Development](https://zksecurity.github.io/stwo-book/air-development/)）

* `Component` — 每个 AIR 组件独立，通过 LogUp 连接

* `Trace` — witness 数据，作为多线性多项式承诺

* `Claim` — 组件的公共声明

* `Transition constraints` — 行间约束（对应 CCS 的 M\_j 矩阵）

* `Boundary constraints` — 边界约束（首行/末行）

* `Lookup` — LogUp lookup 协议（对应 CCS 的 lookup）

***

## 分阶段实施计划

### Phase 1: Stwo 集成骨架 + POC（3-4 周）

**目标**：建立 Stwo 后端框架，用 poker ELF 做最小 POC 验证 M31 field 实际性能

#### 1.1 Cargo 依赖配置与模块骨架（1 周）

* [ ] poker\_zkvm/Cargo.toml 添加 stwo 依赖

* [ ] 新建 `poker_zkvm/src/stwo_backend/` 模块

  * `mod.rs` — 模块声明

  * `prover.rs` — StwoProver 结构（替代 HypernovaProver）

  * `verifier.rs` — StwoVerifier 结构

  * `air/` — AIR 组件目录

    * `mod.rs`

    * `cpu.rs` — CPU 组件（RV32I 指令）

    * `memory.rs` — 内存组件

    * `control_flow.rs` — 控制流组件

    * `syscall.rs` — Syscall 组件

  * `trace.rs` — trace 转换（poker\_zkvm Trace → Stwo Trace）

  * `field.rs` — BN254 Fr ↔ M31 转换工具

* [ ] 定义 `StwoProverConfig`（替代 ProverConfig）

* [ ] 定义 proof 序列化格式（STWO magic，替代 HYPN）

#### 1.2 最小 AIR 组件：CPU step（1 周）

* [ ] 实现 `CpuAirComponent`（仅 step\_index 连续性约束）

  * 参考 [constraints/mod.rs:540](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L540) Group A 约束

  * 单组件验证：trace → AIR → prove → verify

* [ ] 实现 trace 转换：poker\_zkvm `Trace` → Stwo `TraceTable`

  * 复用 `compile_step_witness`（[constraints/mod.rs:371](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L371)）

  * 域转换：BN254 Fr → M31（32-bit limb）

#### 1.3 POC 验证：poker ELF 端到端（1-2 周）

* [ ] 用 `build_texas_poker_full_hand_elf`（[test\_helpers.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/test_helpers.rs)）生成 ELF

* [ ] 执行 ELF → trace

* [ ] 仅用 CPU step AIR 证明（其他约束暂缺，验证 M31 field 性能）

* [ ] **性能基准**：测量 prove 延迟，对比 Hypernova 8.67s（0-fold）

* [ ] **决策点**：≥100× 加速 → 进入 Phase 2；否则评估方案

**Phase 1 交付物**：

* `stwo_backend/` 模块骨架

* 最小 CPU AIR 组件

* POC 性能基准报告

* 决策：是否继续全量迁移

***

### Phase 2: CPU AIR 完整重写（4-6 周，可并行子任务）

**目标**：完整重写 constraints/ 为 Stwo AIR components，支持所有 RV32I 指令

#### 2.1 CPU 组件：算术指令约束（1.5 周）

* [ ] 参考 [constraints/algebra.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/algebra.rs)

* [ ] 实现 AIR transition constraints：

  * LUI / AUIPC（立即数加载）

  * ADDI / SLTI / SLTIU（立即数算术）

  * ADD / SUB / SLT / SLTU（寄存器算术）

  * XOR / OR / AND（位运算）

  * SLL / SRL / SRA（移位）

* [ ] selector gating：复用 `assign_selectors`（[constraints/mod.rs:170](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L170)）

* [ ] carry 约束（Group F，[constraints/mod.rs:545](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L545)）

#### 2.2 CPU 组件：控制流约束（1 周，可与 2.1 并行）

* [ ] 参考 [constraints/control\_flow.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/control_flow.rs)

* [ ] JAL / JALR（跳转）

* [ ] BEQ / BNE / BLT / BGE / BLTU / BGEU（条件分支）

* [ ] PC 连续性约束（Group B，[constraints/mod.rs:541](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L541)）

* [ ] `compute_taken` 复用（[constraints/mod.rs:231](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L231)）

#### 2.3 内存组件（1.5 周，可与 2.1/2.2 并行）

* [ ] 参考 [constraints/memory.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/memory.rs)

* [ ] 实现 `MemoryAirComponent`：

  * LB / LH / LW / LBU / LHU（加载）

  * SB / SH / SW（存储）

* [ ] **Offline memory checker**（参考 Nexus zkVM 3.0 §3.2）

  * LogUp lookup 协议验证内存一致性

  * 初始写入 + 最终读取集合

* [ ] 地址范围检查（M31 原生 31-bit，需多 limb 表示 32-bit 地址）

#### 2.4 Syscall 组件（1 周，依赖 2.3）

* [ ] 参考 [constraints/syscall\_circuit.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/syscall_circuit.rs)

* [ ] 实现 `SyscallAirComponent`：

  * ECALL 指令约束

  * syscall 编号分派

  * host 函数调用接口（precompile 注入点）

* [ ] **precompile 注入接口**：通过 LogUp 连接主 AIR 与 precompile AIR

  * zk\_shuffle 等保持独立证明（不进入主 AIR）

  * 主 AIR 仅证明"syscall 被调用 + 输出被使用"

#### 2.5 LogUp lookup 协议集成（0.5 周）

* [ ] 参考 [constraints/lookup.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs)

* [ ] 实现 Stwo LogUp（[Static Lookups](https://zksecurity.github.io/stwo-book/air-development/static-lookups/)）

* [ ] selector 二值性约束（Group D，[constraints/mod.rs:543](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L543)）

* [ ] selector one-hot 约束（Group C，[constraints/mod.rs:542](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L542)）

#### 2.6 Phase 2 集成测试（0.5 周）

* [ ] 所有 RV32I 指令的 AIR 约束闭环测试

* [ ] 用 poker ELF 完整执行 trace 验证

* [ ] 性能基准：完整 CPU AIR prove 延迟

**Phase 2 交付物**：

* 完整 CPU/Memory/ControlFlow/Syscall AIR 组件

* LogUp lookup 协议

* 所有 RV32I 指令约束闭环测试通过

***

### Phase 3: 纯算术 precompile 迁移（2-3 周，可并行）

**目标**：将纯算术 precompile 迁移为 Stwo AIR components

#### 3.1 Poseidon AIR component（1 周）

* [ ] 参考 [precompiles/poseidon.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/poseidon.rs)

* [ ] Poseidon 64 轮 permutation → AIR transition constraints

* [ ] S-box x^5 约束（M31 原生支持）

* [ ] MDS matrix 约束（线性，M31 原生）

* [ ] 业务逻辑复用：`assign_witness` → `trace`

#### 3.2 SHA-256 / Keccak-256 AIR component（1 周，可与 3.1 并行）

* [ ] 参考 [precompiles/sha256.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/sha256.rs), [keccak256.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/keccak256.rs)

* [ ] 32-bit 加法 + 位运算 → M31（2 limb）

* [ ] LogUp lookup 用于 S-box 查找表

#### 3.3 Merkle verify AIR component（0.5 周，可与 3.1/3.2 并行）

* [ ] 参考 [precompiles/merkle\_verify.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/merkle_verify.rs)

* [ ] 路径验证约束（复用 hash AIR component）

#### 3.4 precompile 注册表适配（0.5 周）

* [ ] 修改 [precompiles/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs) `PrecompileCircuit` trait

  * `build_ccs()` → `build_air()`

  * `assign_witness()` → `trace()`

* [ ] 修改 [precompiles/adapter.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/adapter.rs)

  * `execute()` 调用 `build_air() + trace()`

* [ ] 保留椭圆曲线 precompile（bn254\_pairing, ecdsa, ed25519 等）**不变**

  * 它们保持独立证明，不进入主 AIR

  * `PrecompileCircuit` trait 保留 `build_ccs()` 作为独立证明接口

**Phase 3 交付物**：

* Poseidon/SHA-256/Keccak/Merkle AIR components

* 适配后的 PrecompileCircuit trait（双接口：build\_air + build\_ccs）

***

### Phase 4: Verifier 重写 + poker\_l1 集成（3-4 周）

#### 4.1 Stwo verifier 实现（1.5 周）

* [ ] 新建 `poker_zkvm/src/stwo_backend/verifier.rs`

* [ ] 实现 `verify_stwo(proof_bytes, public_io) -> Result<bool>`

  * 反序列化 STWO proof

  * public\_io 绑定校验（复用 `hash_public_io`）

  * Stwo verifier 验证 proof

* [ ] proof 序列化格式：

  * magic: `b"STWO"`

  * version: 1

  * public\_io\_commitment (32B)

  * Stwo proof bytes

#### 4.2 poker\_zkvm prove() 重写（1 周）

* [ ] 修改 [prover/mod.rs:966](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs#L966) `prove()`

  * 替换 step 4-7：compile\_trace\_to\_ccs + IpaPcs + fold\_loop → compile\_trace\_to\_air + Stwo prove

  * 保留 step 1-3：ELF 校验 + 执行 + trace padding

  * 序列化为 STWO 格式

* [ ] 保留 `prove_partial_start/fold/final` 接口（Stwo 无 fold，但接口兼容）

  * `prove_partial_start` → 执行 ELF + 生成 AIR trace

  * `prove_partial_fold` → no-op（Stwo 单次 prove）

  * `prove_final_fold` → Stwo prove

#### 4.3 poker\_l1 集成（1 周）

* [ ] 修改 [offline/state.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs) `execute_checkin`

  * scheme\_id=1 走 Stwo verifier（替代 Hypernova verifier）

  * proof\_kind=Zkvm 保持不变（底层从 Hypernova 改为 Stwo）

* [ ] 修改 [offline/zk\_verifier.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs)

  * ZkVerifierRegistry 注册 StwoVerifier

  * VerifierStatus: Stub → Production 治理切换

* [ ] CheckinTx/PartialCheckinTx 结构**不变**

  * proof 字段格式从 HYPN 改为 STWO

  * signing\_hash 计算不变（proof\_kind 前缀保留）

#### 4.4 集成测试（0.5 周）

* [ ] poker\_l1 单元测试：execute\_checkin with Stwo proof

* [ ] 端到端测试：ELF → Stwo prove → poker\_l1 verify

**Phase 4 交付物**：

* Stwo verifier 完整实现

* poker\_zkvm prove() 重写

* poker\_l1 集成完成

* 集成测试通过

***

### Phase 5: 删除 Hypernova + E2E 测试（2-3 周）

#### 5.1 删除 Hypernova 相关模块（0.5 周）

* [ ] 删除 `poker_zkvm/src/fold/`（4,776 行）

* [ ] 删除 `poker_zkvm/src/pcs/`（950 行）

* [ ] 删除 `poker_zkvm/src/recursion/`（2,985 行）

* [ ] 删除 `poker_zkvm/src/ccs/`（924 行）

* [ ] 删除 `poker_zkvm/src/constraints/` 中的 CCS 生成代码（保留 witness 赋值逻辑）

* [ ] 删除 `poker_zkvm/src/transcript.rs`（590 行）

* [ ] 删除 `poker_zkvm/src/field.rs` BN254 部分（525 行）

* [ ] 删除 `poker_zkvm/src/prover/partial.rs` Hypernova 部分

* [ ] 删除 `poker_zkvm/src/prover/spartan.rs`, `groth16_compress.rs`

* [ ] 更新 `poker_zkvm/src/lib.rs` 模块声明

* [ ] 更新 Cargo.toml 删除 arkworks 依赖（保留 elliptic curve 依赖用于 precompile）

#### 5.2 E2E 测试：完整一手牌流程（1.5 周）

* [ ] 修改 [poker\_l1/tests/phase12\_e2e\_lcccs.rs](file:///Users/mac/projects/zchain/poker_l1/tests/phase12_e2e_lcccs.rs)

  * 替换 Hypernova prove 为 Stwo prove

  * 适配 STWO proof 格式

  * 验证 ack\_chain 逻辑（保持不变）

* [ ] 完整一手牌流程：

  * 初始 LCCCS 注册到链上

  * 多次 partial checkin（Stwo proof）

  * 最终 final checkin

  * 链上验证通过

* [ ] zk\_shuffle 独立证明路径验证（scheme\_id=4 不受影响）

#### 5.3 性能基准（1 周）

* [ ] Stwo prove 延迟测量

  * 简单程序（10/80/256 步）

  * poker ELF（完整一手牌）

* [ ] 对比 Hypernova 基准

  * 0-fold 路径：8.67s → 目标 <100ms（\~100× 加速）

  * 1-fold 路径：128.08s → 目标 <200ms（\~600× 加速）

* [ ] proof size 测量

  * Stwo \~42KB vs Hypernova \~7KB

  * 评估是否需要 STARK-to-SNARK wrapping

* [ ] 链上验证 gas 测量

  * Stwo verifier gas 成本

  * 对比 Hypernova verifier gas

**Phase 5 交付物**：

* Hypernova 代码完全删除

* E2E 测试通过（完整一手牌流程）

* 性能基准报告（验证 \~1000× 加速）

***

## 关键设计决策

### 1. proof 序列化格式

```text
STWO proof format:
  magic: b"STWO" (4B)
  version: u8 (1B)
  public_io_commitment: [u8; 32] (32B)
  ccs_commitment: [u8; 32] (32B) — 保留用于兼容性
  stwo_proof_len: u32 LE (4B)
  stwo_proof: Vec<u8>
```

### 2. scheme\_id 语义

* `SCHEME_HYPERNOVA = 1` → 重命名为 `SCHEME_STWO`（保持数值不变，兼容已部署合约）

* `SCHEME_ZKSHUFFLE = 4` → 不变

* `ProofKind::Zkvm` → 不变（底层从 Hypernova 改为 Stwo）

### 3. precompile 双接口

```rust
pub trait PrecompileCircuit: Debug + Send + Sync {
    fn name(&self) -> &str;
    fn num_variables(&self) -> usize;
    
    // 新接口：Stwo AIR component（纯算术 precompile）
    fn build_air(&self) -> Result<AirComponent, ZkvmError>;
    fn trace(&self, inputs: &[M31]) -> Result<TraceTable, ZkvmError>;
    
    // 旧接口：独立 CCS 证明（椭圆曲线 precompile，保持不变）
    fn build_ccs(&self) -> Result<Ccs, ZkvmError>;
    fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError>;
    
    fn gas_cost(&self) -> u64;
}
```

### 4. M31 field 转换策略

* BN254 Fr (254-bit) → M31 (31-bit)：9 limb × 32-bit

* witness 赋值时转换：`Fr::from_u32_with_wrap(x)` → `M31::from(x & 0x7FFFFFFF)`

* 32-bit 地址/立即数：2 limb M31（high + low）

* 范围检查：M31 原生 31-bit，需多 limb 拼接

***

## 风险与缓解

| 风险                         | 影响 | 缓解措施                                       |
| -------------------------- | -- | ------------------------------------------ |
| Stwo AIR API 变更            | 中  | 锁定 stwo = "2.3"，跟随上游更新                     |
| M31 field 范围不足             | 中  | 32-bit 值用 2 limb 表示，范围检查约束                 |
| proof size 增大（42KB vs 7KB） | 中  | 评估 STARK-to-SNARK wrapping（如 plonky2 wrap） |
| 链上验证 gas 增加                | 中  | Stwo verifier 优化 + 递归聚合                    |
| precompile 注入接口复杂度         | 低  | LogUp 协议成熟，参考 Nexus zkVM 3.0               |
| Phase 1 POC 性能不达标          | 高  | 决策点：≥100× 加速继续，否则评估其他方案                    |

***

## 验证方法

### 单元测试（每阶段）

* Phase 1: CPU step AIR 约束闭环（prove + verify）

* Phase 2: 所有 RV32I 指令 AIR 约束闭环

* Phase 3: Poseidon/SHA-256/Keccak/Merkle AIR 约束闭环

* Phase 4: poker\_zkvm prove/verify 端到端

* Phase 5: poker\_l1 execute\_checkin 端到端

### 集成测试

* `cargo test -p poker_zkvm` — 所有 ZKVM 测试通过

* `cargo test -p poker_l1` — 所有 L1 测试通过

* `cargo test -p poker_l1 --test phase12_e2e_lcccs` — E2E 测试通过

### 性能基准

* `cargo bench -p poker_zkvm` — prove/verify 基准

* 对比 Hypernova 基准（8.67s / 128.08s）

* 目标：\~1000× 加速（prove <10ms for 80-step program）

### 兼容性验证

* CheckinTx/PartialCheckinTx 结构不变

* proof\_kind 双通道分派正常

* scheme\_id=4 (ZkShuffle) 独立证明不受影响

* 链上 verifier 治理切换正常（Stub → Production）

***

## 工作量汇总

| Phase  | 工作内容               | 工期          | 可并行            |
| ------ | ------------------ | ----------- | -------------- |
| 1      | Stwo 集成骨架 + POC    | 3-4 周       | -              |
| 2      | CPU AIR 完整重写       | 4-6 周       | 2.1/2.2/2.3 并行 |
| 3      | 纯算术 precompile 迁移  | 2-3 周       | 3.1/3.2/3.3 并行 |
| 4      | Verifier 重写 + 集成   | 3-4 周       | -              |
| 5      | 删除 Hypernova + E2E | 2-3 周       | -              |
| **总计** | -                  | **14-20 周** | -              |

***

## 参考资源

### Stwo 官方

* [Stwo GitHub](https://github.com/starkware-libs/stwo)

* [Stwo AIR Development Guide](https://zksecurity.github.io/stwo-book/air-development/)

* [Stwo Components](https://zksecurity.github.io/stwo-book/air-development/components/)

* [Stwo Lookups](https://zksecurity.github.io/stwo-book/air-development/static-lookups/)

### Nexus zkVM 3.0 参考

* [Nexus zkVM 3.0 Specification](https://specification.nexus.xyz/) — AIR 设计参考

* [Nexus 架构文档](https://docs.nexus.xyz/zkvm/overview/architecture)

### 项目本地评估报告

* [Stwo 迁移评估](file:///Users/mac/projects/zchain/.trae/documents/stwo_migration_assessment.md)

* [Precompile 兼容性评估](file:///Users/mac/projects/zchain/.trae/documents/precompile_stwo_compatibility_assessment.md)

* [硬件评估](file:///Users/mac/projects/zchain/.trae/documents/zkvm_parallelism_hardware_assessment.md)

***

## 实施前置条件与里程碑决策点

### Phase 1 决策门（关键）

* **POC 性能门槛**：≥100× 加速（相对 Hypernova 0-fold 路径 8.67s）→ 进入 Phase 2

* 若 <100× 加速，需评估替代方案（如保留 Hypernova 作为 fallback、改用 plonky3 等）

* 此决策门是整个迁移项目最关键的风险控制点

### 用户决策（已确认，不可变）

1. **迁移策略**：全量替换（删除 Hypernova，仅保留 Stwo）
2. **POC 范围**：直接用 poker ELF（不先用简单 RV32I 程序）
3. **Stwo 依赖**：官方 crate 依赖（stwo ^2.3.0）
4. **首阶段优先**：先搭建 Stwo 集成骨架

### 跨阶段约束

* CheckinTx/PartialCheckinTx 结构不变（向后兼容）

* proof\_kind 双通道分派保留（scheme\_id=1 Zkvm / scheme\_id=4 ZkShuffle）

* 椭圆曲线 precompile 保持独立证明，不进入主 AIR

* 链上 verifier 治理切换机制（Stub → Production）保留

