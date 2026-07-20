# Hypernova → Stwo 迁移实施计划 v2（递归证明路线）

> **版本**：v2.1（2026-07-20，Phase 4 Tier 2 重新计划）
> **取代**：[hypernova_to_stwo_migration_plan.md](file:///Users/mac/projects/zchain/.trae/documents/hypernova_to_stwo_migration_plan.md)（v1，fold 改写路线，已 deprecated）
> **目标**：将 poker_zkvm 证明系统**完全**替换为 Stwo（Circle STARK + AIR + FRI on M31），**放弃 Hypernova 兼容**，trace 原生在 M31 中生成，最终支持递归证明
> **预期收益**：~1000× prove 加速（与 Nexus zkVM 3.0 对齐）
> **总工期**：16-22 周（4-5.5 个月）
> **决策依据**：用户明确要求切换到递归证明，完全不用考虑 Hypernova 兼容，全部改成 Stwo 实现
>
> **v2.1 修订（2026-07-20）**：Phase 4 Tier 2 Poseidon AIR 卡在 `ConstraintsNotSatisfied`，根因为 `ExtendToEvalDomain` 模式与 logup 集成存在边界 case。重新制定 Tier 2 计划：所有 AIR 约束度数 ≤ 2（强制 SubDomain 模式），Poseidon AIR 采用中间列降度方案。详见 [stwo_phase4_tier2_replan.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_tier2_replan.md)

***

## 决策背景（v1 → v2 的架构转向）

### v1 路线的问题（fold 改写）

v1 计划保留 Hypernova 的 `compile_step_witness` → `Vec<Fr>`（BN254 254-bit）witness 结构，通过 `fr_to_m31_single` 域转换硬塞进 Stwo AIR。这导致：

1. **非 native 算术复杂性**：BN254 Fr 的 u32 值被拆成 `low (30 bit) + high (2 bit)`，ADD/SUB 需要 limb decomposition + carry_low + 跨 limb 进位约束
2. **soundness 隐患**：M31 模数 P = 2^31 - 1，30-bit limb 掩码是 workaround，非标准做法
3. **不是 Stwo 的标准用法**：Stwo Circle STARK 设计假设 trace 原生在 M31 生成，域转换破坏性能优势
4. **Hypernova fallback 已无价值**：Hypernova sumcheck prove 19s/step（实测），实际不可用，保留 fallback 的成本高于收益

### v2 路线（递归证明 + 原生 M31）

参考 Nexus zkVM 0.3.6（已完全放弃 Nova/Hypernova/CycleFold）：

1. **trace 原生在 M31 中生成**：emulator 执行 RISC-V 时，32-bit 值拆成 4×8-bit limb，每个 limb 直接 `M31::from(u8)`
2. **完全删除 Hypernova 代码**：`ccs/`、`hypernova/`、`fold/`、`recursion/`（旧）、`pcs/ipa.rs` 全部删除
3. **Stwo 原生 AIR**：用 `FrameworkEval` + `EvalAtRow` + `relation!` 宏 + `LogupTraceGenerator`
4. **递归证明作为 Phase 5**：自建 Stwo Verifier AIR（编码 FRI/Merkle/OODS 验证逻辑）

### 关键调研结论

| 调研项 | 结论 | 影响 |
|--------|------|------|
| Nexus zkVM 0.3.6 trace 生成 | `u32::to_le_bytes()` → 4×8-bit limb → M31，无域转换 | Phase 1 采用相同方案 |
| Nexus zkVM 0.3.6 递归 | **无** zkVM 内递归，递归发生在 Nexus Network 聚合层 | 递归证明不是必需，但用户要求 |
| Stwo 2.3 原生递归 API | **不存在**，需自建 Verifier AIR | Phase 5 工作量大（几千行 AIR） |
| Stwo AIR/Component API | `FrameworkEval`（3 方法）+ `EvalAtRow` + `LogupTraceGenerator` | Phase 2-4 使用此 API |
| poker_zkvm 旧代码 | ~7,761 行需删除（`ccs/` + `hypernova/` + `fold/` + `recursion/`） | Phase 1 清理 |

***

## 架构设计

### 整体架构（v2）

```
┌─────────────────────────────────────────────────────────────────┐
│  poker_l1 (链上验证)                                              │
│  - CheckinTx / PartialCheckinTx (scheme_id 分派)                 │
│  - zk_verifier.rs (scheme_id=1 → Stwo Verifier)                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  poker_zkvm (Stwo 递归证明)                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Phase 5: Recursion Layer (Stwo Verifier AIR)            │   │
│  │  - FRI Verifier AIR                                      │   │
│  │  - Merkle Path Verifier AIR                              │   │
│  │  - OODS Check AIR                                        │   │
│  │  - Composition Eval AIR                                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Phase 1-4: Single-Layer Stwo Proof                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │   │
│  │  │ CPU AIR     │  │ Memory AIR  │  │ Precompile  │      │   │
│  │  │ (Phase 2)   │  │ (Phase 3)   │  │ AIR         │      │   │
│  │  │             │  │             │  │ (Phase 4)   │      │   │
│  │  │ - ADD/SUB   │  │ - RAM       │  │ - Poseidon  │      │   │
│  │  │ - JAL/Branch│  │ - Register  │  │ - Sha256    │      │   │
│  │  │ - LUI/AUIPC │  │ - Timestamp │  │ - Keccak    │      │   │
│  │  │ - SLT/SLTU  │  │             │  │ - Merkle    │      │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘      │   │
│  │           LogUp Lookup (opcode range, memory)            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Phase 1: Native M31 Trace (4×8-bit limb)                │   │
│  │  - emulator → Vec<Vec<M31>> (列主序)                      │   │
│  │  - u32 → to_le_bytes() → 4×M31                            │   │
│  │  - padding (IsPadding 列)                                 │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stwo 2.3 (Circle STARK + FRI on M31)                           │
│  - FrameworkEval / EvalAtRow / relation! 宏                     │
│  - LogupTraceGenerator                                          │
│  - CommitmentSchemeProver<SimdBackend, Blake2sMerkleChannel>    │
│  - StarkProof<Blake2sMerkleHasher>                              │
└─────────────────────────────────────────────────────────────────┘
```

### 列布局设计（参考 Nexus zkVM 0.3.6）

采用 **4×8-bit limb** 表达 32-bit 值（而非 v1 的 2×30-bit limb）：

| 值类型 | 表达方式 | 列数 | 理由 |
|--------|---------|------|------|
| 32-bit PC / 寄存器值 / 立即数 | 4×8-bit limb | 4 | 每个 limb < 256 < M31，无溢出 |
| 16-bit 边界进位 | CarryFlag | 2 | 4 limb 只需 2 个 carry（byte1→2, byte3→外） |
| 16-bit 边界借位 | BorrowFlag | 2 | SUB 用 |
| 指令 indicator | IsAdd/IsSub/IsJal/... | 每指令 1 列 | 参考 Nexus，简化约束度数 |
| padding 标记 | IsPadding | 1 | 末尾填充行标记 |
| 辅助变量 | Helper1-4 | 4×4 | 多 limb 运算中间值 |

### 关键约束设计

**ADD 约束（4×8-bit limb，2×16-bit half）**：
```rust
// is_add * (a_low + carry[0] * 2^16 - b_low - c_low) == 0
// is_add * (a_high + carry[1] * 2^16 - b_high - c_high - carry[0]) == 0
// 其中 a_low = a[0] + a[1] * 256, a_high = a[2] + a[3] * 256
```
约束度数 = 1（is_add）× 1（多项式）= 1，符合 `LOG_CONSTRAINT_DEGREE = 2` 预算。

**JAL 约束**：
```rust
// is_jal * (next_pc - pc - imm) == 0
// is_jal * (rd_val - pc + 4) == 0
```

**taken 二值性（universal）**：
```rust
// taken * (taken - 1) == 0
// (1 - is_branch) * taken == 0   // non-branch 行 taken 必须为 0
```

### 递归证明设计（Phase 5）

由于 Stwo 2.3 不提供原生递归 API，采用 **circuit-based recursion**：

```
L1 proof = 单层 Stwo proof（Phase 1-4 产出，~42KB）
   │
   ▼
L2 proof = Stwo Verifier AIR 证明 "L1 proof 通过 verify"
   │  - FRI Verifier AIR（查询打开、最后一层检查）
   │  - Merkle Path Verifier AIR（Blake2s 哈希链）
   │  - OODS Check AIR（composition polynomial 评估对比）
   │  - Composition Eval AIR
   ▼
L2 proof (~10-20KB，可在链上验证)
```

**工作量评估**：Phase 5 约 3000-5000 行 AIR 代码 + 对应 trace 生成器，是整个迁移中最复杂的阶段。

***

## 6 阶段实施计划

### Phase 1：Trace 重写 + 旧代码清理（2-3 周）

**目标**：emulator 原生输出 `Vec<Vec<M31>>`，删除所有 Hypernova 相关代码。

**任务**：
1. **删除旧代码**（~7,761 行）：
   - `poker_zkvm/src/ccs/`（565 行）
   - `poker_zkvm/src/hypernova/`（全目录）
   - `poker_zkvm/src/fold/`（4,776 行）
   - `poker_zkvm/src/recursion/`（2,985 行，旧 CycleFold）
   - `poker_zkvm/src/pcs/ipa.rs`
   - `poker_zkvm/src/cyclic/` + `cyclegold.rs`
   - `poker_zkvm/src/stwo_backend/field.rs`（域转换工具，不再需要）

2. **重写 trace 生成**：
   - 新建 `poker_zkvm/src/stwo_backend/trace_native.rs`
   - 定义 `NativeTrace` 结构：`Vec<Vec<M31>>`（列主序）
   - 实现 `u32_to_m31_limbs(v: u32) -> [M31; 4]`：`v.to_le_bytes()` → 4 个 M31
   - 实现 `TraceBuilder`：填充列、padding、finalize

3. **重写列布局**：
   - 替换 `poker_zkvm/src/stwo_backend/column_layout.rs`
   - 采用 4×8-bit limb 布局（参考 Nexus `column.rs`）
   - 定义 `Column` enum + `#[size = N]` 派生（或手动实现）
   - 列数预计 60-80 列（参考 Nexus ~150 列，poker_zkvm 指令集更小）

4. **更新 `lib.rs`**：移除 `ccs`、`hypernova`、`fold`、`recursion` 模块声明

**完成标准**：
- [x] 所有旧代码删除，`cargo build` 无 Hypernova 依赖（保留 BN254 Fr 用于 Poseidon，详见 Phase 1 设计文档 9.1）
- [x] `NativeTrace` 可从 emulator 输出生成
- [x] `u32_to_m31_limbs` roundtrip 测试通过
- [x] padding 机制测试通过
- [x] 列布局常量测试通过

**实施状态**：✅ 已完成（2026-07-20）
- 详见 [stwo_phase1_native_trace_design.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase1_native_trace_design.md) §9.1 实施记录
- poker_zkvm 单元测试 342/342 通过；poker_l1 单元测试 1501/1501 通过；workspace 全部集成测试通过
- 后续 Phase 2 起步：CPU AIR 重写（Stwo FrameworkEval + EvalAtRow + relation! macro）

**测试**：
- `test_u32_to_m31_limbs_roundtrip`：u32 → 4×M31 → u32
- `test_trace_builder_padding`：padding 行正确标记
- `test_column_layout_indices`：列索引互不相同

---

### Phase 2：CPU AIR 重写（3-4 周）

**目标**：用 Stwo 原生 AIR 表达所有 CPU 指令约束（ADD/SUB/SLT/SLTU/LUI/AUIPC/JAL/JALR/Branch/逻辑/移位）。

**任务**：
1. **定义 CPU AIR**：
   - 新建 `poker_zkvm/src/stwo_backend/air/cpu_v2.rs`
   - 实现 `FrameworkEval` trait（3 方法：`log_size`、`max_constraint_log_degree_bound`、`evaluate`）
   - `max_constraint_log_degree_bound = log_size + 2`（约束度数上界）

2. **指令约束实现**（参考 Nexus `chips/instructions/`）：
   - **算术指令**（ADD/ADDI/SUB/SUBI）：4×8-bit limb 进位链 + CarryFlag
   - **比较指令**（SLT/SLTU）：BorrowFlag + 符号位
   - **逻辑指令**（XOR/OR/AND）：逐 limb 运算
   - **移位指令**（SLL/SRL/SRA）：ShiftBit + Exp 辅助列
   - **控制流**（JAL/JALR/BEQ-BGEU）：next_pc 约束 + taken 二值性
   - **LUI/AUIPC**：立即数加载
   - **M 扩展**（MUL/MULH/DIV/REM）：参考 Nexus M extension chips

3. **opcode range lookup**：
   - 用 `relation!` 宏定义 `OpcodeLookupElements`
   - `LogupTraceGenerator` 生成 interaction trace
   - CPU 侧 claim（+1），OpcodeTable 侧 yield（-count）

4. **preprocessed columns**：
   - `is_last_row`：最后一行标记
   - `is_padding`：padding 行标记
   - 各种 `is_*` indicator（如果由 verifier 预计算）

**完成标准**：
- [ ] 所有 35 个指令类别约束实现
- [ ] 单指令 AIR 测试通过（每指令至少 1 正例 + 1 负例）
- [ ] LogUp lookup 测试通过
- [ ] `cargo test -p poker_zkvm --lib stwo_backend::air` 全绿

**测试**：
- `test_add_constraint_positive`：正确 ADD 通过
- `test_add_constraint_negative_carry`：错误 carry 被拒
- `test_jal_constraint_positive`：正确 JAL 通过
- `test_taken_binary_constraint`：taken ∈ {0, 1}
- `test_opcode_lookup`：opcode 在 [0, 34] 范围内

---

### Phase 3：内存 & Syscall AIR（2-3 周）

**目标**：内存访问一致性约束 + syscall 约束。

**任务**：
1. **内存 AIR**（参考 Nexus `memory_check/`）：
   - `RamBaseAddr` + `Ram1-4ValCur/Prev`（4×8-bit limb）
   - `Ram1-4TsPrev`（timestamp）
   - 内存连续性约束：当前访问的 `TsPrev` == 上次访问的 `TsCur`
   - 内存值约束：`ValPrev` == 上次写入的 `ValCur`

2. **寄存器 AIR**：
   - `Reg1-3Address` + `Reg1-3ValPrev` + `Reg1-3TsPrev`
   - 寄存器一致性约束（类似内存）

3. **程序内存 AIR**：
   - `ProgCtrPrev` + `ProgCtrCur` + `FinalPrgMemoryCtr`
   - 程序计数器连续性

4. **Syscall AIR**：
   - `poker_zkvm/src/stwo_backend/air/syscall_v2.rs`
   - ECALL/EBREAK 约束
   - 自定义 syscall（poseidon/sha256/keccak/merkle）接口

**完成标准**：
- [x] 内存一致性测试通过（`test_prove_verify_multi_lw_sw_sequence` Store 后 Load 同地址）
- [ ] 寄存器一致性测试通过（**Phase 3.6 待补**：`RegisterLookup` 已定义，`register_air.rs` 待实现）
- [ ] Syscall 约束测试通过（**Phase 3.7 待补**：`syscall_air.rs` 骨架待实现）
- [x] 多组件 AIR 联合 prove 测试通过（5 个 CPU+Memory 多组件测试全部通过）
- [x] `cargo test -p poker_zkvm` 全绿（392 测试通过）

**测试**：
- `test_memory_consistency`：连续内存访问
- `test_register_consistency`：寄存器读写一致
- `test_syscall_ecall`：ECALL 约束

**实施状态**：Phase 3.1-3.5 已完成（2026-07-20）
- 详见 [stwo_phase3_memory_syscall_design.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase3_memory_syscall_design.md) §10 实施记录
- 已完成：Memory AIR（25 列 + 33 条约束）+ CPU Load/Store 约束 + logup claim + 多组件 prover/verifier + 5 个多组件集成测试
- 关键 bug 修复：`memory_air.rs` 中 `offset=-1` 改为 `offset=-2`（SubDomain 模式下 prev-row 读取）
- 待完成：Phase 3.6（Register AIR + 边缘 case 测试）+ Phase 3.7（Syscall AIR 骨架）
- poker_zkvm 测试 392/392 通过

---

### Phase 4：Precompile 迁移到 AIR（10-14 周，分 4 个 Tier）

**目标**：填补 CPU AIR 的 ECALL soundness 缺口，实现 precompile AIR 组件，通过 LogUp 连接主 AIR。

**详细设计**：详见 [stwo_phase4_precompile_air_design.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_precompile_air_design.md)

**进度**：
- ✅ **Tier 1 ECALL Dispatch 已完成**（2026-07-20）：25 列 + C57-C82 约束 + EcallLookup + 9 测试，poker_zkvm 401/401 通过
- 🔄 **Tier 2 进行中**（v2.1 重新计划，2026-07-20）：
  - Poseidon AIR（M31-native）：Step 4.2.1-4.2.3 已完成；Step 4.2.4 卡在 `ConstraintsNotSatisfied`，根因为 `ExtendToEvalDomain` 模式。**v2.1 重新计划**：采用中间列降度方案（21 → 30 列，约束度 6 → 2），强制 SubDomain 模式。详见 [stwo_phase4_tier2_replan.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_tier2_replan.md)
  - Sha256 AIR：待做（同样采用中间列降度）
  - MerkleVerify AIR：待做（依赖 Poseidon AIR）
- ⬜ Tier 3：ECDSA/Keccak256/Modexp AIR（用户确认 in scope）
- ⬜ Tier 4：BLS12-381 Building-block AIRs（选项 B 已确认）

**任务**：
1. **Tier 1（必做）：ECALL dispatch 约束** ✅ **已完成 2026-07-20**
   - 扩展 `column_layout_v2.rs`：新增 25 列（COL_SYSCALL_ID=101 等），NUM_COLUMNS 101→126
   - 扩展 `cpu_air.rs`：C57 IS_ECALL binality + C58-C82 25 条 zero gating + EcallLookup claim（gated by Option<EcallLookup>）
   - 扩展 `lookups.rs`：`relation!(EcallLookup, 25);`
   - 扩展 `trace_native.rs`：自动适应 126 列（vec! 宏用 NUM_COLUMNS 常量）
   - 4 个集成测试 + 5 个单元测试，全部通过
   - **关闭"非 ECALL 行伪造 ECALL 数据"soundness 缺口**

2. **Tier 2（必做）：纯算术 precompile AIR**
   - **Poseidon AIR**（**M31-native 已确认**）：
     - 新建 `poker_zkvm/src/stwo_backend/air/precompile/poseidon.rs`
     - 30 轮 permutation AIR（MDS matrix + round constants + S-box x^5）
     - LogUp 连接主 AIR（hash input/output 在 ECALL 行，round-by-round 在 precompile trace）
   - **Sha256 AIR**：compression function + message schedule（参考 Nexus zkVM）
   - **MerkleVerify AIR**：依赖 Poseidon AIR，递归验证 Merkle path

3. **Tier 3（**用户确认 in scope**）：非 native EC precompile**
   - **ECDSA verify AIR**（secp256k1 over M31，资金路径安全核心）
   - **Keccak256 AIR + host impl**（当前 host 未实现，需从零构建）
   - **Modexp AIR + host impl**（当前 host 未实现）

4. **Tier 4（**选项 B 已确认：Building-block AIRs**）：BLS12-381**
   - 实施 SP1 模式：12 个 BLS12-381 building-block AIRs
     - Fp384 ADD/SUB/MUL（384-bit mod 算术，~12×32-bit limb）
     - Fp2 ADD/SUB/MUL（Karatsuba）
     - Weierstrass ADD/DOUBLE（与 ECDSA secp256k1 共享模块）
     - G1/G2 DECOMPRESS（witnessed sqrt）
   - pairing 由 guest 用 building blocks 组合（无单独 PAIRING syscall，参考 SP1 ~13M cycles/pairing）
   - **soundness 完整**：所有 BLS12-381 ops 在 AIR 内验证

5. **zk_shuffle 保持独立**（Hard Constraint）：
   - zk_shuffle 不进入 Stwo 主 AIR
   - `proof_kind` 双通道分派保持不变
   - 仅 scheme_id=1（Zkvm）走新 Stwo 证明

**关键设计决策（✅ 用户已全部确认 2026-07-20）**：
- Poseidon 字段：**M31-native**
- BLS12-381 处理：**选项 B — Building-block AIRs（SP1 模式）**
- Keccak/Modexp/ECDSA：**全部实现 in scope**
- Ed25519/Bn254Pairing：Descope（不在 syscall 范围）
- 事件哈希迁移：**接受 M31 迁移**（与 Poseidon 决策一致）

**完成标准**：
- [x] Tier 1：4 个 ECALL 集成测试 + 5 单元测试通过（已完成 2026-07-20）
- [ ] Tier 2：3 个 precompile AIR（Poseidon + Sha256 + MerkleVerify）实现并通过测试
- [ ] Tier 2：3/4/5 组件 prover 测试通过
- [ ] Tier 2：precompile 正确性验证（AIR 输出 vs host 函数一致）
- [ ] Tier 2：zk_shuffle 独立性验证（无 Poseidon AIR 引用 zk_shuffle 代码）
- [ ] Tier 3：ECDSA verify AIR + Keccak256 AIR + Modexp AIR 测试通过
- [ ] Tier 4：12 个 BLS12-381 building-block AIRs 测试通过
- [ ] workspace 全部测试通过

**测试**：
- `test_prove_verify_roundtrip_ecall` ✅（Tier 1 已实施）
- `test_ecall_zero_gating_soundness` ✅（Tier 1 已实施）
- `test_ecall_binality_soundness` ✅（Tier 1 已实施）
- `test_ecall_zero_gating_padding_row_all_zeros` ✅（Tier 1 已实施）
- `test_ecall_constraint_poseidon`：ECALL Poseidon syscall 通过（Tier 2）
- `test_poseidon_air_correctness`：AIR 输出 vs host 一致（Tier 2）
- `test_sha256_air_correctness`：SHA-256 正确性（Tier 2）
- `test_merkle_verify_air_depth_8`：8 层 Merkle 树验证（Tier 2）
- `test_ecdsa_verify_air`：ECDSA verify 正确性（Tier 3）
- `test_keccak256_air`：Keccak-f[1600] permutation 正确性（Tier 3）
- `test_modexp_air`：Modexp 正确性（Tier 3）
- `test_bls12381_fp_mul_air` / `test_bls12381_fp2_mul_air` / `test_bls12381_weierstrass_add_air` / `test_bls12381_g1_decompress_air`：BLS12-381 building-block AIR 测试（Tier 4）
- `test_zk_shuffle_independence`：zk_shuffle 仍走独立证明

---

### Phase 5：递归证明层（4-6 周，最复杂）

**目标**：自建 Stwo Verifier AIR，实现 L1 proof → L2 proof 的递归聚合。

**背景**：Stwo 2.3 不提供原生递归 API。采用 StarkWare 官方 "circuit-based recursion" 路线（参考 stwo-cairo）。

**详细设计**：详见 [stwo_phase5_verifier_air_design.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase5_verifier_air_design.md)

**实施状态**：✅ Phase 5.1 模块脚手架完成（2026-07-20）
- 创建 `poker_zkvm/src/stwo_backend/recursive/` 目录（8 个文件）
- OODS Check AIR v5.0 完整实现（9 列 + 5 约束）
- FRI Verifier AIR v5.0 骨架（19 列 + 6 约束，Horner step 待 v5.1）
- Merkle Path AIR 骨架（52 列 + 3 binality 约束，Poseidon252 hash 待补）
- Composition Eval AIR v5.0 stub
- Recursion Prover/Verifier 骨架
- 18/18 测试通过，poker_zkvm 485/485 通过
- 关键决策：L1 VCS 使用 Poseidon252MerkleChannel（递归路径）以简化 Merkle Path Verifier AIR

**任务**：
1. **FRI Verifier AIR**（~1500 行）：
   - 新建 `poker_zkvm/src/stwo_backend/recursive/fri_verifier_air.rs` ✅ 骨架
   - FRI 查询打开验证（Merkle path + leaf value）
   - FRI 最后一层多项式检查（Horner method）✅ v5.0 骨架
   - degree bound 验证

2. **Merkle Path Verifier AIR**（~800 行，**改用 Poseidon252 hash**）：
   - 新建 `poker_zkvm/src/stwo_backend/recursive/merkle_path_air.rs` ✅ 骨架
   - **Poseidon252** 哈希链验证（避免 Blake2s 的 ~10000 约束/hash）
   - 多个 Merkle path 批量验证

3. **OODS Check AIR**（~600 行）：
   - 新建 `poker_zkvm/src/stwo_backend/recursive/oods_check_air.rs` ✅ v5.0 完整
   - Out-of-Domain Sample 评估对比 ✅ v5.0 简化版
   - composition polynomial 评估（v5.1）

4. **Composition Eval AIR**（~600 行）：
   - 新建 `poker_zkvm/src/stwo_backend/recursive/composition_eval_air.rs` ✅ v5.0 stub
   - constraint quotient 评估
   - mask point 评估

5. **Recursion Prover**：
   - 新建 `poker_zkvm/src/stwo_backend/recursive/recursion_prover.rs` ✅ 骨架
   - 输入：L1 `StarkProof<Blake2sMerkleHasher>`
   - 输出：L2 `StarkProof<Blake2sMerkleHasher>`（更小）
   - L2 proof 可在链上验证

6. **Recursion Verifier**：
   - 新建 `poker_zkvm/src/stwo_backend/recursive/recursion_verifier.rs` ✅ 骨架
   - 验证 L2 proof

**完成标准**：
- [x] 4 个 Verifier AIR 模块创建（v5.0 骨架/stub）— 2026-07-20
- [ ] 4 个 Verifier AIR 完整实现并通过测试（v5.1）
- [ ] L1 → L2 递归证明测试通过
- [ ] L2 proof size < 20KB（目标 10-15KB）
- [ ] L2 verify 时间 < 100ms

**测试**：
- `test_fri_verifier_air`：FRI 验证逻辑 ✅ v5.0 骨架测试通过
- `test_merkle_path_verifier_air`：Merkle 路径验证 ✅ v5.0 骨架测试通过
- `test_oods_check_air`：OODS 检查 ✅ v5.0 完整测试通过
- `test_recursive_prover_e2e`：L1 → L2 端到端（待 v5.1）
- `test_recursive_proof_size`：proof size < 20KB（待 v5.1）

**风险**：
- 工作量大（3000-5000 行 AIR）
- Stwo Verifier AIR 无现成参考（stwo-cairo 是 Cairo-specific）
- 分多个子阶段：5.1 脚手架 ✅ / 5.2 OODS 完整 ✅ / 5.3 FRI 完整 / 5.4 Merkle 完整 / 5.5 Recursion Prover / 5.6 E2E

---

### Phase 6：E2E 测试 + 性能基准 + 链上集成（2-3 周）

**目标**：完整一手牌流程 E2E 测试，性能基准对比，链上 verifier 接入。

**任务**：
1. **E2E 测试**：
   - 完整一手牌流程（shuffle/deal/bet/reveal）
   - CheckinTx 生成 → Stwo prove → 链上 verify
   - PartialCheckinTx（递归证明路径）

2. **性能基准**：
   - prove 时间对比（Hypernova 19s/step vs Stwo 目标 < 100ms/step）
   - proof size 对比
   - verify 时间对比
   - 不同 trace 长度（1K/10K/100K/1M steps）基准

3. **链上 verifier 接入**：
   - 更新 `poker_l1/src/offline/zk_verifier.rs`
   - scheme_id=1 → Stwo Verifier（Phase 5 的 L2 verifier）
   - scheme_id=4 → ZkShuffle（不变）

4. **CheckinTx 兼容性**：
   - 确保新 Stwo proof 兼容现有 CheckinTx 结构
   - `proof_kind` 字段保持不变
   - `signing_hash` 包含 1-byte proof_kind 前缀

**完成标准**：
- [ ] 完整一手牌 E2E 测试通过
- [ ] prove 加速 ≥ 100×（目标 1000×）
- [ ] L2 proof size < 20KB
- [ ] 链上 verify 时间 < 200ms
- [ ] CheckinTx 兼容性测试通过

**测试**：
- `test_e2e_full_hand`：完整一手牌流程
- `test_perf_prove`：prove 性能基准
- `test_perf_verify`：verify 性能基准
- `test_checkin_tx_compatibility`：CheckinTx 兼容性

***

## 代码清理清单

### 删除（~7,761 行旧代码）

| 路径 | 行数 | 说明 |
|------|------|------|
| `poker_zkvm/src/ccs/` | 565 | CCS 结构 |
| `poker_zkvm/src/hypernova/` | ~1,200 | Hypernova fold/sumcheck/verifier |
| `poker_zkvm/src/fold/` | 4,776 | Hypernova fold loop |
| `poker_zkvm/src/recursion/` | 2,985 | 旧 CycleFold 电路 |
| `poker_zkvm/src/pcs/ipa.rs` | ~200 | IPA PCS |
| `poker_zkvm/src/cyclic/` + `cyclegold.rs` | 206 | CycleFold 辅助 |
| `poker_zkvm/src/stwo_backend/field.rs` | 134 | 域转换工具（不再需要） |
| `poker_zkvm/src/stwo_backend/column_layout.rs` | ~400 | 旧 2×30-bit limb 布局 |
| `poker_zkvm/src/stwo_backend/air/cpu.rs` | ~1300 | 旧 CPU AIR（fold 改写版本） |
| `poker_zkvm/src/constraints/` | ~1,200 | 旧 CCS 约束编译 |

### 保留（与证明系统无关）

| 路径 | 说明 |
|------|------|
| `poker_zkvm/src/isa/` | RISC-V 指令集定义 |
| `poker_zkvm/src/compiler/` | ELF 校验 |
| `poker_zkvm/src/syscalls/` | host 函数定义 |
| `poker_zkvm/src/trace/` | Step/Trace 数据结构（需适配） |
| `poker_zkvm/src/error.rs` | 错误类型 |
| `poker_zkvm/src/lib.rs` | 模块组织（需更新） |

### 新建

| 路径 | 说明 |
|------|------|
| `poker_zkvm/src/stwo_backend/trace_native.rs` | 原生 M31 trace 生成 |
| `poker_zkvm/src/stwo_backend/column_layout_v2.rs` | 4×8-bit limb 列布局 |
| `poker_zkvm/src/stwo_backend/air/cpu_v2.rs` | 新 CPU AIR |
| `poker_zkvm/src/stwo_backend/air/memory_v2.rs` | 内存 AIR |
| `poker_zkvm/src/stwo_backend/air/syscall_v2.rs` | Syscall AIR |
| `poker_zkvm/src/stwo_backend/air/precompile/` | Precompile AIR 目录 |
| `poker_zkvm/src/stwo_backend/air/recursive/` | 递归证明 AIR 目录 |
| `poker_zkvm/src/stwo_backend/recursive_prover.rs` | 递归 prover |
| `poker_zkvm/src/stwo_backend/recursive_verifier.rs` | 递归 verifier |

***

## Hard Constraints（v2）

- **完全放弃 Hypernova 兼容**：不再保留 Hypernova fallback，`ccs/`、`hypernova/`、`fold/`、`recursion/` 全部删除
- **trace 原生在 M31 中生成**：不再使用 `fr_to_m31_single` 域转换
- **4×8-bit limb 表达 32-bit 值**：参考 Nexus zkVM 0.3.6，每个 limb < 256 < M31
- **Stwo 原生 AIR**：用 `FrameworkEval` + `EvalAtRow` + `relation!` 宏
- **zk_shuffle 保持独立证明**：不进入 Stwo 主 AIR，`proof_kind` 双通道分派不变
- **每阶段测试通过作为下一阶段前提**
- **递归证明采用 circuit-based recursion**：自建 Stwo Verifier AIR（Phase 5）
- **CheckinTx/PartialCheckinTx 结构兼容**：`signing_hash` 包含 1-byte proof_kind 前缀
- **scheme_id=1 → Stwo Verifier，scheme_id=4 → ZkShuffle**（不变）
- **保守重构优先**：先完成 Phase 1-4（单层 Stwo proof），再做 Phase 5（递归证明）
- **Phase 6 完成后才算迁移完成**：E2E + 性能基准 + 链上集成
- **v2.1 新增（2026-07-20）**：所有 AIR 组件的 `max_constraint_log_degree_bound` 必须为 `log_size + 1`（约束度 ≤ 2），强制使用 SubDomain 评估模式。理由：ExtendToEvalDomain 模式在 Stwo 2.3 中与 logup interaction 集成存在边界 case（Poseidon AIR 卡点根因）。度数 > 2 的约束必须通过中间列分解。
- **v2.1 新增（2026-07-20）**：所有 AIR 组件统一使用 `PcsConfig::default()`，禁止 `set_store_polynomials_coefficients` 和 `lifting_log_size = Some(...)`。
- **v2.1 新增（2026-07-20）**：`StarkProof.commitments.len() == 4`（Tree 0/1/2 + composition poly tree），测试断言应为 4。

***

## 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| Phase 5 递归证明工作量超预期 | 高 | 工期 +4-6 周 | 分 5.1/5.2/5.3/5.4 子阶段，每子阶段独立可测 |
| Stwo Verifier AIR 无现成参考 | 高 | Phase 5 阻塞 | 参考 stwo-cairo 实现，但需适配 RV32I |
| 4×8-bit limb 列数过多 | 中 | prove 时间增加 | 参考 prover2 混合 limb（PC/Clk 用 2×16-bit） |
| precompile AIR 复杂度 | 中 | Phase 4 延期 | 优先 Poseidon（zk_shuffle 用），其他可后置 |
| 链上 verify 时间超标 | 中 | Phase 6 阻塞 | 用递归证明压缩 proof size |
| CheckinTx 兼容性问题 | 低 | Phase 6 阻塞 | proof_kind 字段保持不变，提前测试 |

***

## 与 v1 计划的差异

| 维度 | v1（fold 改写） | v2（递归证明） |
|------|----------------|----------------|
| Hypernova 兼容 | 保留 fallback | **完全放弃** |
| trace 生成 | BN254 Fr → M31 域转换 | **原生 M31**（4×8-bit limb） |
| limb 方案 | 2×30-bit | **4×8-bit**（参考 Nexus） |
| 域转换工具 | `fr_to_m31_single` | **删除**（不需要） |
| AIR 约束 | Group A/B/C/E/F（v1 设计） | **Stwo 原生**（FrameworkEval） |
| 递归证明 | 无 | **Phase 5 自建 Verifier AIR** |
| 旧代码处理 | 保留作为 fallback | **全部删除** |
| 总工期 | 14-20 周 | **16-22 周**（+2 周递归证明） |
| 预期加速 | ~1000× | **~1000×**（相同） |

***

## 决策记录

| 日期 | 决策 | 理由 |
|------|------|------|
| 2026-07-20 | 采用 v2 路线（递归证明 + 原生 M31） | 用户明确要求，v1 域转换方案有 soundness 隐患 |
| 2026-07-20 | 采用 4×8-bit limb（参考 Nexus） | 标准 Stwo 用法，无域转换，soundness 清晰 |
| 2026-07-20 | 递归证明作为 Phase 5（非必需） | 单层 Stwo proof 已可用，递归用于链上验证 |
| 2026-07-20 | 完全删除 Hypernova 代码 | fallback 已无价值（19s/step 不可用），保留增加复杂性 |
| 2026-07-20 | zk_shuffle 保持独立 | Hard Constraint，proof_kind 双通道不变 |
| 2026-07-20 | Phase 4 Poseidon 字段：M31-native | Stwo 主 AIR 在 M31 上，BN254 Fr 需非 native 算术，性能损失 10× |
| 2026-07-20 | Phase 4 Tier 3 范围：ECDSA + Keccak256 + Modexp 全部 in scope | 用户确认，资金路径安全核心 + 工期可控 |
| 2026-07-20 | Phase 4 BLS12-381：选项 B（Building-block AIRs，SP1 模式） | soundness 完整，行业最佳实践，与 ECDSA 共享 Weierstrass 模块 |
| 2026-07-20 | Phase 4 Tier 1 ECALL Dispatch 完成实施 | 25 列 + C57-C82 + EcallLookup + 9 测试，poker_zkvm 401/401 通过 |
| 2026-07-20 | **v2.1**：所有 AIR 约束度数 ≤ 2（强制 SubDomain 模式） | 根因分析：PoseidonAir `constraint_log_degree = 3 > log_blowup_factor = 1` 触发 `ExtendToEvalDomain` 模式，与 logup interaction 集成存在边界 case。详见 [stwo_phase4_tier2_replan.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_tier2_replan.md) §2 |
| 2026-07-20 | **v2.1**：Poseidon AIR 采用中间列降度方案（Option B） | S-box `x^5 = x * (x^2)^2` 分解为 3 个 degree ≤ 2 约束（SboxSq1/SboxSq2/SboxOut），新增 9 列（21→30 列），约束度 6→2，强制 SubDomain 模式。详见 [stwo_phase4_tier2_replan.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_tier2_replan.md) §3 |
| 2026-07-20 | **v2.1**：所有 AIR 统一使用 `PcsConfig::default()` | 禁止 `set_store_polynomials_coefficients` 和 `lifting_log_size = Some(...)`，消除 ExtendToEvalDomain 配置复杂性 |
| 2026-07-20 | **v2.1**：`StarkProof.commitments.len() == 4`（Hard Constraint） | Stwo 返回 4 个 commitments（Tree 0 + Tree 1 + Tree 2 + composition poly tree），即使 Tree 0 为空也有 commitment。原测试断言 `== 3` 错误 |
| 2026-07-20 | **Phase 5 v5.0 MVP 完成**：Recursion Prover/Verifier roundtrip | `prove_recursive` + `verify_recursive` + `mix_public_inputs_into_channel`（PcsConfig::mix_into + max_log_degree_bound + composition_oods_eval + oods_point）。3 个 roundtrip 测试通过（prove_succeeds/roundtrip/mismatched_inputs），poker_zkvm 504/504。v5.0 简化：ComputedOodsEval = ClaimedOodsEval，v5.1 由 Composition Eval AIR 计算真值 |
| 2026-07-20 | **无 logup AIR 不调用 `finalize_logup()`**（Hard Constraint） | `FormalLogupAtRow` 初始 `is_finalized=true`，只有 `write_logup_frac`（通过 `add_to_relation`）重置为 false。OodsCheckAir/FriVerifierAir/MerklePathAir/CompositionEvalAir 无 logup，调用 `finalize_logup()` 会 panic |

***

## 下一步

### 已完成
- ✅ Phase 1: BN254 Fr 保留用于 Poseidon 哈希
- ✅ Phase 3.5: 多组件 prover + LogupTraceGenerator（CPU + Memory）
- ✅ Phase 4 Tier 1: ECALL dispatch 约束（25 列 + C57-C82）
- ✅ Phase 4 Tier 2: Poseidon AIR v2.1（中间列降度）+ Sha256 AIR Step 5.1（骨架）
- ✅ Phase 5 v5.0 MVP: OODS Check AIR + FRI Verifier AIR（骨架）+ Merkle Path AIR（骨架）+ Recursion Prover/Verifier roundtrip

### 待完成
- ⏳ Phase 4 Tier 2: Sha256 AIR Step 5.2（完整 compression 约束）+ Step 5.3（多块+4组件集成）
- ⏳ Phase 4 Tier 3: ECDSA verify AIR + Keccak256 AIR + Modexp AIR
- ⏳ Phase 4 Tier 4: BLS12-381 Building-block AIRs（12 个 syscalls）
- ⏳ Phase 5 v5.1: Composition Eval AIR（完整 L1 约束 evaluation）+ FRI commit/decommit + Merkle Poseidon hash
- ⏳ Phase 6: E2E 测试 + 性能基准 + 链上集成
