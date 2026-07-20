# Stwo Phase 4 设计文档：Precompile AIR 组件

> **版本**：1.4（2026-07-20，v2.1 Poseidon AIR 中间列降度重设计）
> **所属迁移计划**：[hypernova_to_stwo_migration_plan_v2.md](file:///Users/mac/projects/zchain/hypernova_to_stwo_migration_plan_v2.md)（v2.1）
> **工期**：10-14 周（4 个 Tier 全部 in scope）
> **前置条件**：Phase 3.5 已完成（多组件 prover + LogupTraceGenerator 集成可用）
> **后续阶段**：Phase 5（递归证明层）
>
> **用户确认决策（2026-07-20）**：
> - Poseidon 字段：**M31-native**（选项 A）
> - Tier 3 范围：**全部实现**（ECDSA verify AIR + Keccak256 AIR + host + Modexp AIR + host）
> - BLS12-381 处理：**选项 B — Building-block AIRs（SP1 模式）**（12 syscalls，pairing 由 guest 组合）
> - 事件哈希迁移：**接受 M31 迁移**（与 Poseidon 决策一致）
> - **Tier 1 ECALL Dispatch 已完成**（2026-07-20）：25 列 + C57-C82 约束 + EcallLookup + 9 测试，poker_zkvm 401/401 通过
>
> **v1.4 修订（2026-07-20）**：§4.1 Poseidon AIR 原设计（21 列 + 18 约束，约束度 6）在 Step 4.2.4 实施时卡在 Stwo prover `ConstraintsNotSatisfied`。根因为 `max_constraint_log_degree_bound = log_size + 3` 触发 `ExtendToEvalDomain` 评估模式，该模式与 logup interaction 集成存在边界 case。**v2.1 重新设计**：新增 §4.1.7 中间列降度方案（30 列 + 27 约束，约束度 ≤ 2，强制 SubDomain 模式）。§4.1.3-4.1.6 原设计保留作为历史参考，标注为"已被 §4.1.7 取代"。详见 [stwo_phase4_tier2_replan.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_tier2_replan.md)

***

## 1. 目标与范围

### 1.1 目标

1. **填补 CPU AIR 的 ECALL soundness 缺口**：当前 CPU AIR 完全没有约束 ECALL 指令，syscall 结果完全信任 host，恶意 prover 可写入任意值
2. **实现 Poseidon AIR 组件**：通过 logup 与 CPU AIR 交互，证明 Poseidon hash 计算正确
3. **实现 Sha256 AIR 组件**：同上
4. **实现 MerkleVerify AIR 组件**：依赖 Poseidon AIR，递归验证 Merkle path
5. **决定 BLS12-381 处理策略**：全 AIR vs trusted host + logup commitment（详见 §6）
6. **决定 Poseidon 字段**：M31-native vs BN254-non-native（详见 §5）

### 1.2 范围

**包含**：
- `poker_zkvm/src/stwo_backend/air/ecall.rs`（新建）：ECALL 调度约束
- `poker_zkvm/src/stwo_backend/air/precompile/`（新建目录）：
  - `poseidon.rs`：Poseidon permutation AIR
  - `sha256.rs`：SHA-256 compression AIR
  - `merkle_verify.rs`：Merkle path verification AIR
- `poker_zkvm/src/stwo_backend/lookups.rs`（扩展）：新增 `PoseidonLookup`、`Sha256Lookup`、`MerkleLookup` relations
- `poker_zkvm/src/stwo_backend/cpu_air.rs`（扩展）：新增 ECALL 约束 + per-syscall logup claim
- `poker_zkvm/src/stwo_backend/trace_native.rs`（扩展）：新增 ECALL trace + precompile trace 生成
- `poker_zkvm/src/stwo_backend/prover.rs`（扩展）：支持多 precompile 组件同时 prove

**不包含**：
- 递归证明 — Phase 5
- BLS12-381 全 AIR（暂列为 Tier 4，可能 descope，详见 §6）
- zk_shuffle AIR（Hard Constraint：保持独立）

### 1.3 Soundness 缺口分析

当前 CPU AIR 有 55 条约束（C1-C55），覆盖算术/控制流/Load-Store/Memory logup。但 **ECALL 完全未约束**：

| 缺口 | 严重性 | Phase 4 解决方案 |
|------|--------|-----------------|
| ECALL 指令无约束（IS_ECALL 列已设但未读） | **CRITICAL** | §3 ECALL dispatch 约束 |
| Poseidon hash 输出未验证（host 计算） | **CRITICAL** | §4.1 Poseidon AIR + logup |
| Sha256 输出未验证 | HIGH | §4.2 Sha256 AIR + logup |
| Merkle path 验证未实现 | MEDIUM | §4.3 MerkleVerify AIR + logup |
| ECDSA verify 未验证 | HIGH | Tier 3（可选） |
| BLS12-381 ops 未验证 | MEDIUM | Tier 4（§6 决策） |

***

## 2. Phase 3.5 多组件架构回顾（Phase 4 基础）

Phase 3.5 已建立的多组件 + logup 架构：

```text
Tree 0 (preprocessed): 空
Tree 1 (original):     CPU trace (101 cols) + Memory trace (25 cols) = 126 cols
Tree 2 (interaction):  CPU logup (4 cols) + Memory logup (4 cols) = 8 cols
```

**Phase 4 扩展**：

```text
Tree 0 (preprocessed): 空
Tree 1 (original):     CPU trace (101 cols) + Memory trace (25 cols)
                      + Poseidon trace (TBD cols) + Sha256 trace (TBD cols)
                      + MerkleVerify trace (TBD cols)
Tree 2 (interaction):  CPU logup (multi-batch) + Memory logup
                      + Poseidon logup + Sha256 logup + MerkleVerify logup
```

**关键模式**：
- CPU AIR 在 ECALL 行发送 `claim`（multiplicity = +1，values = syscall_id + inputs + outputs）
- Precompile AIR 在每行发送 `yield`（multiplicity = -1，values = 同样的元组）
- 一致性：`Σ(CPU claims) + Σ(Precompile yields) == 0`

***

## 3. ECALL Dispatch 约束（Tier 1，必做）

### 3.1 设计

**新增列**（CPU trace，扩展 `column_layout_v2.rs`）：

| 列索引 | 名称 | 说明 |
|--------|------|------|
| 101 | SyscallId | 1 列 M31（直接表示 syscall_id 0-127，无需 limb 分解） |
| 102-105 | SyscallArg0 | 4×8-bit limb（如 input_ptr） |
| 106-109 | SyscallArg1 | 4×8-bit limb（如 input_len） |
| 110-113 | SyscallArg2 | 4×8-bit limb（如 output_ptr） |
| 114-117 | SyscallArg3 | 4×8-bit limb（reserved） |
| 118-121 | SyscallOutput0 | 4×8-bit limb（output[0]） |
| 122-125 | SyscallOutput1 | 4×8-bit limb（output[1]，Poseidon Fr 高位） |

总列数：101 → 126（新增 25 列 = 1 SyscallId + 24 Args/Outputs）

**设计决策**：SyscallId 用 1 列 M31 而非 4×8-bit limb，因为 syscall_id < 128 < M31_MAX，无需 limb 分解。这简化了约束（无需 SyscallId limb binality）且减少 3 列。

**新增约束（C57-C82，26 条）**：

1. **C57：IS_ECALL binality**：`IS_ECALL * (IS_ECALL - 1) == 0`
   - 显式约束 IS_ECALL ∈ {0, 1}，增强 soundness（虽然 Indicator one-hot C14 隐含）
   - 度数 = 2，符合 LOG_CONSTRAINT_DEGREE = 2 预算
2. **C58-C82：ECALL 列 zero gating（25 条）**：`(1 - IS_ECALL) * col[i] == 0`，对 25 列每列一条
   - 非 ECALL 行（IS_ECALL=0）：(1-0)*col = col = 0，强制列为 0
   - ECALL 行（IS_ECALL=1）：(1-1)*col = 0，自动成立，不约束列值
   - 度数 = 2，符合预算
   - **关闭"非 ECALL 行伪造 ECALL 数据"soundness 缺口**

**logup claim 发送**（Tier 2+ 启用，Tier 1 实现但 gated by `Option<EcallLookup>`）：

```rust
// ECALL 行发送 claim，元组 = (syscall_id, arg0, arg1, arg2, arg3, output0, output1)
// multiplicity = IS_ECALL
let mut ecall_claim_values: Vec<E::F> = Vec::with_capacity(25);
ecall_claim_values.push(col(COL_SYSCALL_ID));              // 1 列 SyscallId
ecall_claim_values.extend_from_slice(&[                    // 4 列 Arg0
    col(COL_SYSCALL_ARG0_BASE),
    col(COL_SYSCALL_ARG0_BASE + 1),
    col(COL_SYSCALL_ARG0_BASE + 2),
    col(COL_SYSCALL_ARG0_BASE + 3),
]);
// ... Arg1, Arg2, Arg3, Output0, Output1（各 4 列）
let multiplicity_ef: E::EF = is_ecall.clone().into();
eval.add_to_relation(RelationEntry::new(
    &self.ecall_lookup,
    multiplicity_ef,
    &ecall_claim_values,
));
eval.finalize_logup();
```

**Tier 1 限制**：
- Tier 1 无 Precompile AIR 发送 yield，因此启用 ecall_lookup 时 logup sum != 0
- Tier 1 测试应使用 `new_with_lookup`（不启用 ecall_lookup）避免验证失败
- Tier 2 实施 Precompile AIR 后，启用 ecall_lookup 测试完整 claim + yield 平衡

### 3.2 实现（✅ Tier 1 已完成 2026-07-20）

**Step 4.1.1** ✅：扩展 `column_layout_v2.rs` 新增 25 列常量
- `COL_SYSCALL_ID = 101`（1 列 M31）
- `COL_SYSCALL_ARG0_BASE = 102` 到 `COL_SYSCALL_OUTPUT1_BASE = 122`
- `ECALL_DISPATCH_NUM_COLUMNS = 25`
- `NUM_COLUMNS = 101 → 126`

**Step 4.1.2** ✅：扩展 `trace_native.rs`
- `vec![M31::from(0u32); NUM_COLUMNS]` 自动适应 126 列
- ECALL 行的 25 列暂填 0（Tier 2 实施 Precompile AIR 时填充真实 syscall 数据）
- padding 行 25 列默认为 0（符合 zero gating 要求）

**Step 4.1.3** ✅：扩展 `cpu_air.rs` 新增 C57-C82 约束 + EcallLookup claim
- 新增 `ecall_lookup: Option<EcallLookup>` 字段
- 新增 `new_with_ecall_lookup` 构造函数
- C57: IS_ECALL binality
- C58-C82: 25 条 zero gating
- logup claim（gated by `Option<EcallLookup>`）

**Step 4.1.4** ✅：扩展 `lookups.rs` 新增 `relation!(EcallLookup, 25);`

**Step 4.1.5** ✅：测试（4 个集成测试 + 5 个单元测试）
- `test_prove_verify_roundtrip_ecall`：ECALL 行 prove/verify 通过
- `test_ecall_zero_gating_soundness`：篡改非 ECALL 行 SyscallId 被拒绝
- `test_ecall_binality_soundness`：篡改 IS_ECALL 为非 binary 被拒绝
- `test_ecall_zero_gating_padding_row_all_zeros`：padding 行 25 列全为 0
- poker_zkvm 测试 401/401 通过

### 3.3 测试（✅ Tier 1 已完成）

**Tier 1 实施的测试**：
- ✅ `test_prove_verify_roundtrip_ecall`：ECALL 行 prove/verify 通过
- ✅ `test_ecall_zero_gating_soundness`：篡改非 ECALL 行 SyscallId 被拒绝
- ✅ `test_ecall_binality_soundness`：篡改 IS_ECALL 为非 binary 被拒绝
- ✅ `test_ecall_zero_gating_padding_row_all_zeros`：padding 行 25 列全为 0

**Tier 2+ 待补测试**（需 Precompile AIR）：
- ⬜ `test_ecall_constraint_poseidon`：ECALL Poseidon syscall 完整 roundtrip
- ⬜ `test_ecall_constraint_sha256`：ECALL Sha256 syscall 完整 roundtrip
- ⬜ `test_ecall_logup_balance`：CPU claim + Precompile yield sum = 0
- ⬜ `test_ecall_soundness_malicious_output`：篡改 output 被 logup 拒绝

***

## 4. Precompile AIR 组件（Tier 2，必做）

### 4.1 Poseidon AIR

> **⚠️ v2.1 重设计说明**：§4.1.1 字段决策仍然有效（M31-native）。§4.1.3-4.1.6 原列布局与约束设计（21 列 + 18 约束，约束度 6）**已被 §4.1.7 中间列降度方案取代**，保留作历史参考。Step 4.2.4 实施时原设计触发 Stwo `ExtendToEvalDomain` 模式，与 logup 集成存在边界 case，prover 报 `ConstraintsNotSatisfied`。详见 [stwo_phase4_tier2_replan.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_tier2_replan.md) §2 根因分析。

#### 4.1.1 字段决策（CRITICAL — 需用户确认，详见 §5）

**推荐**：M31-native Poseidon（替代 BN254 Fr Poseidon）

理由：
- Stwo 主 AIR 在 M31 上运行，BN254 Fr Poseidon 需非 native 算术（9×32-bit limb）
- M31 Poseidon 在 zkVM 生态有成熟参考（Plonky3、RISC Zero BabyBear Poseidon）
- 现有 BN254 Fr 事件哈希仅在 `SyscallContext.events: Vec<ark_bn254::Fr>` 中存储，可在 Phase 4 中迁移到 `Vec<M31>` 或 `Vec<[M31; 4]>`（4×8-bit limb 表示 32-bit hash 输出）
- BLS12-381 hash_to_scalar 用 SHA3-256 而非 Poseidon，不受影响

**未选方案**：BN254-non-native Poseidon（保留 BN254 Fr），缺点：
- 需 9×32-bit limb 模拟 BN254 Fr（254-bit），约束膨胀 3-5×
- ADD/MUL 在 BN254 Fr 上需循环进位约束，复杂度高
- 丧失 Stwo 在 M31 上的性能优势

#### 4.1.2 M31 Poseidon 参数

参考 Plonky3 `poseidon-air` 配置：

```rust
const POSEIDON_M31_WIDTH: usize = 3;       // t = 3 (state width)
const POSEIDON_M31_RATE: usize = 2;        // rate = 2
const POSEIDON_M31_CAPACITY: usize = 1;    // capacity = 1
const POSEIDON_M31_ALPHA: u64 = 5;         // S-box: x^5
const POSEIDON_M31_FULL_ROUNDS: usize = 8; // 8 full rounds
const POSEIDON_M31_PARTIAL_ROUNDS: usize = 22; // 22 partial rounds（M31 上更少，参考 Plonky3）
// 总轮数 = 8 + 22 = 30（vs BN254 的 64 轮）
```

**参数推导**：使用 `ark-crypto-primitives::poseidon::find_poseidon_ark_and_mds::<M31>(31, 2, 8, 22, 0)` 在 M31 上重新计算 MDS 矩阵和 round constants，编译期缓存。

**注意**：alpha=5 在 M31 上有效，因为 `gcd(5, M31-1) = gcd(5, 2^31-2) = 1`（5 ∤ 2^31-2）。

#### 4.1.3 Poseidon AIR 列布局

> **⚠️ v2.1 已废弃**：原 21 列布局触发 `ExtendToEvalDomain` 模式。请参考 §4.1.7 新 30 列布局（约束度 ≤ 2，强制 SubDomain 模式）。以下原布局保留作历史参考。

每行表示 **一个 round**（不是一次完整 hash），共 30 行/round × N 次 hash：

| 范围 | 列名 | 说明 |
|------|------|------|
| 0-2 | State[0..3] | 当前轮 state（3 个 M31 元素） |
| 3-5 | StateNext[0..3] | 下一轮 state（避免 prev-row 读取） |
| 6 | IsFullRound | 1=full round，0=partial round |
| 7 | IsPartialRound | 1=partial round，0=full round |
| 8 | IsFirstRound | 1=该 hash 的第 0 轮 |
| 9 | IsLastRound | 1=该 hash 的最后一轮 |
| 10 | RoundCounter | 当前轮序号（0-29） |
| 11-13 | Input[0..3] | 该 hash 的输入（仅 IsFirstRound=1 时有意义） |
| 14-16 | Output[0..3] | 该 hash 的输出（仅 IsLastRound=1 时有意义） |
| 17 | IsPadding | padding 行标记 |
| 18-20 | RoundConstant[0..3] | 当前轮 round constants（preprocessed?） |

总列数：21 列（每 hash 30 行 × 21 列 = 630 元素，vs BN254 Fr 一次 hash = ~6000 元素）

#### 4.1.4 Poseidon AIR 约束

> **⚠️ v2.1 已废弃**：原约束（degree 5-6）触发 `ExtendToEvalDomain` 模式。请参考 §4.1.7 新约束（所有 degree ≤ 2）。以下原约束保留作历史参考。

**P1-P3：State binality** — 每个 state 元素 ∈ M31（无约束，trace 生成保证）

**P4-P6：State 转换 — Full round**（`IsFullRound * constraint`）：

```text
对于 state[i] (i=0,1,2):
  sbox_i = state[i]^5
  new_state_i = sum_j(MDS[i][j] * sbox_j) + round_constant[i]

约束（degree 5）：
  IsFullRound * (StateNext[i] - sum_j(MDS[i][j] * State[j]^5) - RoundConstant[i]) == 0
```

**P7：State 转换 — Partial round**（`IsPartialRound * constraint`）：

```text
仅 state[0] 应用 S-box，state[1]、state[2] 不变：
  sbox_0 = state[0]^5
  new_state[i] = sum_j(MDS[i][j] * (i==0 ? sbox_0 : state[j])) + round_constant[i]

约束（degree 5）：
  IsPartialRound * (StateNext[i] - sum_j(MDS[i][j] * (j==0 ? State[0]^5 : State[j])) - RoundConstant[i]) == 0
```

**P8-P10：First round 接 input**：

```text
约束：IsFirstRound * (State[i] - Input[i]) == 0
```

**P11-P13：Last round 输出**：

```text
约束：IsLastRound * (StateNext[i] - Output[i]) == 0
```

**P14：Round counter 递增**：

```text
约束：IsPadding * (RoundCounter_next - RoundCounter - 1) == 0  // 中间轮
约束：(1 - IsPadding) * (RoundCounter - 0) == 0  // padding 行 RoundCounter=0
```

**P15：IsPadding binality**

**P16：IsFullRound + IsPartialRound + IsPadding = 1**（one-hot）

#### 4.1.5 Logup 交互

CPU AIR 在 ECALL Poseidon 行发送 claim：
```text
values = (SyscallId=POSEIDON, input_bytes_hash, output_Fr_low, output_Fr_high)
multiplicity = +1
```

Poseidon AIR 在 IsLastRound=1 行发送 yield：
```text
values = (POSEIDON, Input[0..3], Output[0], Output[1])
multiplicity = -1
```

**新增 relation**：`relation!(PoseidonLookup, 9);`（9 元组）

#### 4.1.6 测试

> **⚠️ v2.1 已更新**：测试断言 `commitments.len() == 4`（原断言 `== 3` 错误，Stwo 返回 4 个 commitments）。详见 §4.1.7.5。

- `test_poseidon_air_single_hash`：单次 Poseidon hash（30 行）
- `test_poseidon_air_multi_hash`：多次 hash（N×30 行）
- `test_poseidon_air_correctness`：AIR 输出 vs `poseidon_hash` host 函数一致
- `test_poseidon_air_logup_consistency`：CPU claim + Poseidon yield sum = 0
- `test_poseidon_soundness_tampered_output`：篡改 output 被拒绝

#### 4.1.7 中间列降度方案（v2.1 重设计，**当前有效**）

> **取代**：§4.1.3 列布局 + §4.1.4 约束 + §4.1.5 Logup 中的列引用部分
> **完整文档**：[stwo_phase4_tier2_replan.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_tier2_replan.md)
> **触发原因**：Step 4.2.4 实施原设计（21 列 + 18 约束，约束度 6）时 Stwo prover 报 `ConstraintsNotSatisfied`，根因为 `max_constraint_log_degree_bound = log_size + 3` 触发 `EvaluationMode::ExtendToEvalDomain`，该模式与 logup interaction 集成存在边界 case（MemoryAir 用 SubDomain 模式工作正常）。

##### 4.1.7.1 核心思想

将 S-box `x^5` 的高度约束（degree 5）分解为多个 degree ≤ 2 的约束，引入中间列存储中间值：

```text
S-box 分解：x^5 = x * (x^2)^2

SboxInput[j]  = State[j] + RoundConstant[j]                    (inline, 无需新列)
SboxSq1[j]    = SboxInput[j]^2                                  (新列, degree 2 约束)
SboxSq2[j]    = SboxSq1[j]^2                                    (新列, degree 2 约束)
SboxOut[j]    = SboxSq2[j] * SboxInput[j] = SboxInput[j]^5      (新列, degree 2 约束)
```

每个 state 元素新增 3 个中间列（SboxSq1、SboxSq2、SboxOut），3 个 state 元素共 9 个新列。

##### 4.1.7.2 新列布局（30 列，原 21 + 新增 9）

| 范围 | 列名 | 说明 | 新增? |
|------|------|------|-------|
| 0-2 | State[0..3] | 当前轮 state | 否 |
| 3-5 | StateNext[0..3] | 下一轮 state | 否 |
| 6 | IsFullRound | 1=full round | 否 |
| 7 | IsPartialRound | 1=partial round | 否 |
| 8 | IsFirstRound | 1=该 hash 的第 0 轮 | 否 |
| 9 | IsLastRound | 1=该 hash 的最后一轮 | 否 |
| 10 | RoundCounter | 当前轮序号 | 否 |
| 11-13 | Input[0..3] | sponge state input | 否 |
| 14-16 | Output[0..3] | sponge state output | 否 |
| 17 | IsPadding | padding 行标记 | 否 |
| 18-20 | RoundConstant[0..3] | 当前轮 round constants | 否 |
| **21-23** | **SboxSq1[0..3]** | **SboxInput^2** | **是** |
| **24-26** | **SboxSq2[0..3]** | **SboxSq1^2 = SboxInput^4** | **是** |
| **27-29** | **SboxOut[0..3]** | **SboxSq2 * SboxInput = SboxInput^5** | **是** |

总列数：**30 列**（vs 原 21 列，+9 列）

##### 4.1.7.3 新约束清单（所有约束 degree ≤ 2）

| # | 约束 | 度 | gating | 说明 |
|---|------|----|--------|------|
| P1-P5 | 各 flag binality（IsFull/IsPartial/IsFirst/IsLast/IsPadding） | 2 | - | |
| P6 | One-hot (Full + Partial + Padding = 1) | 1 | - | |
| P7-P9 | First round: State[i] = Input[i] | 2 | IsFirstRound | |
| P10-P12 | Last round: StateNext[i] = Output[i] | 2 | IsLastRound | |
| **P13-P15** | **SboxSq1[j] = (State[j] + RC[j])^2** | **2** | **无（unconditional）** | 新增 |
| **P16-P18** | **SboxSq2[j] = SboxSq1[j]^2** | **2** | **无（unconditional）** | 新增 |
| **P19-P21** | **SboxOut[j] = SboxSq2[j] * (State[j] + RC[j])** | **2** | **无（unconditional）** | 新增 |
| **P22-P24** | **Full round: StateNext[i] = sum_j(MDS[i][j] * SboxOut[j])** | **2** | **IsFullRound** | 原 P13-P15 重写 |
| **P25-P27** | **Partial round: StateNext[i] = sum_j(MDS[i][j] * term[j])**，其中 term[0]=SboxOut[0], term[j>0]=State[j]+RC[j] | **2** | **IsPartialRound** | 原 P16-P18 重写 |

总约束数：**27 条**（vs 原 18 条，+9 条）
最大约束度：**2**（vs 原 6）
`max_constraint_log_degree_bound`：**`log_size + 1`**（vs 原 `log_size + 3`）
EvaluationMode：**SubDomain**（vs 原 ExtendToEvalDomain）

##### 4.1.7.4 Padding 行的正确性

新约束 P13-P21 是 **unconditional**（无 gating），需在 padding 行也满足：
- Padding 行：State = 0, RC = 0, SboxSq1 = 0, SboxSq2 = 0, SboxOut = 0
- P13: `0 - (0 + 0)^2 = 0` ✓
- P16: `0 - 0^2 = 0` ✓
- P19: `0 - 0 * (0 + 0) = 0` ✓

Trace 生成器需在 padding 行将 SboxSq1/SboxSq2/SboxOut 填 0（`PoseidonTrace::new` 已初始化为 0）。

##### 4.1.7.5 PcsConfig 一致性（与 MemoryAir 相同）

重设计后 PoseidonAir 使用与 MemoryAir **完全相同**的 PcsConfig：

```rust
let config = PcsConfig::default();  // log_blowup_factor = 1, lifting_log_size = None
let blowup_log = config.fri_config.log_blowup_factor;
let big_domain = CanonicCoset::new(log_size + blowup_log);  // log_size + 1
let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());
// 无需 set_store_polynomials_coefficients
// 无需 lifting_log_size = Some(...)
```

这消除了所有 ExtendToEvalDomain 模式相关的配置复杂性。

##### 4.1.7.6 Logup 交互（与原 §4.1.5 一致，无变化）

CPU AIR 在 ECALL Poseidon 行发送 claim（multiplicity = +1，values = (SyscallId, input, output)），Poseidon AIR 在 IsLastRound=1 行发送 yield（multiplicity = -1）。一致性：`Σ(CPU claims) + Σ(Poseidon yields) == 0`。

**`claimed_sum` 机制**（v2.1 二次修正，2026-07-20）：
- ⚠️ **原 v2.1 文档错误**：曾记为 `claimed_sum = sum(numerators)`，实际 Stwo 源码
  (`stwo-constraint-framework-2.3.0/src/prover/logup.rs:203`) 证明
  `claimed_sum = sum(num/denom)`（`finalize_col` 计算 `value = numerator * denom_inv`，
  `finalize_last` 对 last column 求和）。
- 空 trace：`claimed_sum = 0`（所有 num=0，确定值，可断言 `== 0`）
- 单 hash：`claimed_sum = -1/denom_last_row`（denom 含随机 PoseidonLookup，**非确定值**）
- N hash：`claimed_sum = Σ_i(-1/denom_i)`（**非确定值**）
- **测试断言策略**：非空 trace 仅断言 `claimed_sum != 0` + verify roundtrip 成功
- CPU/Poseidon soundness check `claimed_sum_cpu + claimed_sum_poseidon == 0` 仍成立
  （对应行 denom 相同，num 互为相反数）

##### 4.1.7.7 `StarkProof.commitments.len() == 4`（Hard Constraint）

Stwo 返回 **4 个 commitments**（Tree 0 + Tree 1 + Tree 2 + composition poly tree），即使 Tree 0 为空也有 commitment。原 v1 测试断言 `== 3` **错误**，v2.1 修正为 `== 4`。

##### 4.1.7.8 实施步骤

详见 [stwo_phase4_tier2_replan.md](file:///Users/mac/projects/zchain/.trae/documents/stwo_phase4_tier2_replan.md) §4：

- **Step 4.2.4-rev1.1**：更新 `poseidon_air.rs`（新增 9 列常量 + `max_constraint_log_degree_bound = log_size + 1` + 重写 evaluate）
- **Step 4.2.4-rev1.2**：更新 `trace_native.rs`（自动支持 30 列 + 填充 SboxSq1/SboxSq2/SboxOut）
- **Step 4.2.4-rev1.3**：更新 `prover.rs`（简化 PcsConfig + 修复 commitments.len() 断言）
- **Step 4.2.4-rev1.4**：更新手动检查测试（P13-P27）
- **Step 4.2.5**：单元测试 + prover 测试（关键：单 hash prove 通过验证 SubDomain 模式有效）
- **Step 4.2.6**：3 组件集成测试（CPU + Memory + Poseidon）

##### 4.1.7.9 备选方案（Fallback）

若 Option B（中间列降度）仍无法通过 Stwo prover：

- **Option C：Trusted Host + Logup Commitment**（1-2 天，soundness 弱化）
  - Poseidon hash 由 host 计算，AIR 仅约束 (Input, Output) 的 logup yield
  - 适用场景：开发/测试阶段，或资金路径不依赖 Poseidon 的非核心场景
  - 后续升级：Option B 调试通过后替换

- **Option D：AssertEvaluator 精确定位**（1 天，诊断工具）
  - 在实施 Option B 前，可先用 `AssertEvaluator` 精确定位原设计的失败约束
  - 价值：确认根因是否为 ExtendToEvalDomain 模式（若是，Option B 必然有效；若否，需重新诊断）

**推荐顺序**：先 Option D（1 天诊断）→ 若确认根因 → Option B（2-3 天修复）→ 若 Option B 失败 → Option C（1-2 天降级）

### 4.2 Sha256 AIR

#### 4.2.1 设计

参考 Nexus zkVM `sha256/` 模块：

- **64 轮 compression function**，每轮：message schedule + working variables update
- **8 个 working variables**（a, b, c, d, e, f, g, h），每个 32-bit = 4×8-bit limb
- **64 个 round constants**（K[0..63]）+ 8 initial hash values（H0[0..7]）
- **message schedule**：W[t] = M[t] for t<16；W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16] for t≥16

#### 4.2.2 列布局（每行 = 1 轮，64 行/compression）

| 范围 | 列名 | 说明 |
|------|------|------|
| 0-3 | W[0..4] | 当前轮 message schedule word（4×8-bit limb） |
| 4-35 | A-H (8 words × 4 limbs) | 8 个 working variables |
| 36 | IsPadding | padding 标记 |
| 37 | IsFirstBlock | 多块 hash 时第 0 块标记 |
| 38 | IsLastBlock | 多块 hash 时最后一块标记 |
| 39 | RoundCounter | 0-63 |
| 40-43 | W_next[0..4] | 下一轮 W（避免 prev-row 读取） |
| 44-75 | A_next-H_next | 下一轮 working variables |

总列数：76 列（64 行/compression × 76 列 = 4864 元素/compression）

#### 4.2.3 约束（degree ≤ 2，借助辅助列）

- Working variable update（每轮 8 个约束，degree 2 with辅助列 σ0/σ1/Ch/Maj）
- Message schedule update（degree 2 with辅助列 σ0/σ1）
- Round counter 递增
- First block 接 H0，last block 输出 H_final

**新增 relation**：`relation!(Sha256Lookup, 9);`（input_hash + output_hash + is_multi_block）

#### 4.2.4 测试

- `test_sha256_air_single_block`：单块（512-bit）输入
- `test_sha256_air_multi_block`：多块输入
- `test_sha256_air_correctness`：AIR 输出 vs `sha2::Sha256` 一致
- `test_sha256_soundness_tampered`：篡改输出被拒绝

### 4.3 MerkleVerify AIR

#### 4.3.1 设计

依赖 Poseidon AIR（用 `poseidon_compress` 作为 hash 函数）。

**迭代 depth 次**：
```text
for i in 0..depth:
    if indices[i] == 0:
        parent[i] = Poseidon(child[i], sibling[i])
    else:
        parent[i] = Poseidon(sibling[i], child[i])
final: parent[depth-1] == root
```

#### 4.3.2 列布局（每行 = 1 个 Merkle 层）

| 范围 | 列名 | 说明 |
|------|------|------|
| 0-3 | Child | 当前层 child node（4×8-bit limb） |
| 4-7 | Sibling | 当前层 sibling node |
| 8 | IndexBit | 0=child 是左，1=child 是右 |
| 9-12 | Parent | 下一层 parent（4×8-bit limb） |
| 13 | IsFirstLayer | leaf 层标记 |
| 14 | IsLastLayer | root 层标记 |
| 15 | IsPadding | padding 标记 |
| 16 | LayerCounter | 0..depth-1 |

总列数：17 列

#### 4.3.3 约束

- **IndexBit binality**
- **Parent = Poseidon(Child, Sibling)** when IndexBit=0（通过 PoseidonLookup claim）
- **Parent = Poseidon(Sibling, Child)** when IndexBit=1（通过 PoseidonLookup claim）
- **First layer Child == leaf**
- **Last layer Parent == root**
- **Layer counter 递增**

**新增 relation**：`relation!(MerkleLookup, 13);`（leaf + root + depth + path + indices）

#### 4.3.4 测试

- `test_merkle_verify_air_depth_4`：4 层 Merkle 树
- `test_merkle_verify_air_depth_8`：8 层 Merkle 树
- `test_merkle_verify_soundness_wrong_root`：篡改 root 被拒绝

***

## 5. Poseidon 字段决策（CRITICAL DESIGN GATE）

### 5.1 选项 A：M31-native Poseidon（**推荐**）

**优点**：
- 与 Stwo 主 AIR 字段一致，无需非 native 算术
- 30 轮（vs BN254 的 64 轮），约束数减少 ~50%
- 性能：M31 上的 ADD/MUL 是 native，比 BN254 Fr 模拟快 10-20×
- 生态参考：Plonky3、RISC Zero BabyBear Poseidon 均在 small field 上实现

**缺点**：
- **现有 BN254 Fr 事件哈希失效**：`SyscallContext.events: Vec<ark_bn254::Fr>` 中已存的事件哈希需要重新计算或迁移
- M31 上 Poseidon 安全性需重新分析（31-bit field，state width 3，rate 2 → 128-bit security 需验证）
- BLS12-381 hash_to_scalar 用 SHA3-256 不受影响，但若后续需要 BN254 Fr Poseidon（如 zk_shuffle 内部用），需保留 BN254 版本

**迁移影响**：
- `SyscallContext.events: Vec<ark_bn254::Fr>` → `Vec<[M31; 4]>` 或 `Vec<M31>`（4×8-bit limb 表示 32-bit hash）
- `poseidon_hash_bytes` 返回类型 `Fr` → `[M31; 4]` 或 `M31`
- 现有调用方（emit_event、get_randomness）需更新

### 5.2 选项 B：BN254-non-native Poseidon（保留 BN254 Fr）

**优点**：
- 现有 BN254 Fr 事件哈希保留，无需迁移
- 与 zk_shuffle 内部 Poseidon 兼容（zk_shuffle 用 BN254 Fr Poseidon）
- BLS12-381 用 BN254 Fr 更自然

**缺点**：
- M31 模拟 BN254 Fr 需 9×32-bit limb（254-bit / 28-bit per limb）
- ADD/MUL 在 BN254 Fr 上需循环进位约束，约束膨胀 3-5×
- 丧失 Stwo 在 M31 上的性能优势
- Poseidon hash 单次 hash 约束数 ~6000（vs M31 的 ~150）

### 5.3 决策：选项 A（M31-native Poseidon）✅ **用户已确认**

**理由**：
1. 用户偏好简单方案，M31-native 更简单（无非 native 算术）
2. 性能优势显著（10-20× speedup on Poseidon hash）
3. 现有 BN254 Fr 事件哈希迁移工作量可控（仅 SyscallContext.events 一个字段）
4. zk_shuffle Hard Constraint 保持独立，不强制 BN254 兼容

**用户确认（2026-07-20）**：接受事件哈希从 BN254 Fr 迁移到 M31。

**迁移影响（实施时需处理）**：
- `SyscallContext.events: Vec<ark_bn254::Fr>` → `Vec<[M31; 4]>`（4×8-bit limb 表示 32-bit hash 输出）
- `poseidon_hash_bytes` 返回类型 `Fr` → `[M31; 4]` 或 `M31`
- 现有调用方（emit_event、get_randomness）需更新
- `poseidon_compress` 返回类型 `Fr` → `[M31; 4]`，MerkleVerify AIR 直接使用 M31 输出

***

## 6. BLS12-381 处理策略（Tier 4 决策，**基于对比研究**）

### 6.1 现状

6 个 BLS12-381 syscall 在 `poker_zkvm/src/syscalls/bls12381.rs`：
- `hash_to_curve`（120K gas）
- `scalar_mul`（60K gas）
- `g1_add`（40K gas）
- `g1_mul`（90K gas）
- `pairing`（120K gas）
- `hash_to_scalar`（15K gas，用 SHA3-256 + reduce）

### 6.2 行业调研结论（2026-07-20）

**关键发现**：**没有任何主流 zkVM 实现 BLS12-381 pairing 的完整 AIR**。

| 项目 | BLS12-381 处理方式 | 备注 |
|------|-------------------|------|
| **Nexus zkVM** | **未实现**（仅 Keccak AIR，无 BLS precompile） | 用户参考的项目，BLS 在 guest 中跑 |
| **RISC Zero** | Guest 调用 `bls12_381` Rust crate + bigint2 加速 Fp ops | bigint2 是独立 STARK 加速器，每个 Fp384 mul ~552 cycles |
| **Plonky3** | **未实现**（无 BLS crate） | 仅 BN254 Fr 作为 foreign-field wrapper |
| **Stwo** | **未实现**（仅 blake/poseidon/plonk 示例） | 无 BLS 示例 |
| **SP1** | **Building-block AIRs**（最完整）：BLS12381_FP_ADD/SUB/MUL、FP2_*、ADD/DOUBLE/DECOMPRESS；**无 PAIRING syscall**，pairing 由 guest 用 building blocks 组合计算 | 12 个 BLS syscalls，pairing 约 13M cycles |
| **Jolt** | **未实现** | 仅 secp256k1/p256/grumpkin |

**Pairing AIR 成本估算**（基于 SP1 数据）：
- 单次 BLS12-381 pairing ≈ 15,389 次 Fp 乘法（学术参考）
- 完整 pairing AIR：10M-30M 约束
- 对比：Keccak AIR ~50K 约束，SHA-256 ~10K 约束
- **pairing AIR 比 hash AIR 大 1000×**，这是无项目实现它的根本原因

**行业标准模式**：Building-block AIRs + Guest 组合
1. 提供 Fp384/Fp2 算术 AIR（add/sub/mul）
2. 提供 G1 EC 算术 AIR（add/double/decompress，参数化 Weierstrass）
3. Guest 运行 `bls12_381` Rust crate，field arithmetic 调用 syscall
4. Pairing 由 guest 用 building blocks 组合计算（Miller loop + final exp）

### 6.3 选项 A：Full Pairing AIR（**不推荐**，行业无人实现）

**问题**：
- 10M-30M 约束/pairing，远超 Keccak/SHA-256 的 1000×
- 工期 6-8 周，且性能可能下降 100× 以上
- 无开源参考实现

### 6.4 选项 B：Building-block AIRs + Guest 组合（**SP1 模式，推荐**）

**设计**（参考 SP1 `WeierstrassAddAssignChip`）：
- 实现 12 个 BLS12-381 building-block AIR：
  - `BLS12381_FP_ADD` / `FP_SUB` / `FP_MUL`（384-bit mod 算术，~12×32-bit limb）
  - `BLS12381_FP2_ADD` / `FP2_SUB` / `FP2_MUL`（Fp2 via 3 muls + 2 adds, Karatsuba）
  - `BLS12381_ADD` / `DOUBLE`（参数化 Weierstrass AIR，与 ECDSA 共享）
  - `BLS12381_DECOMPRESS`（point decompression：1 sqrt + 1 inversion，witnessed）
- Guest 运行 `bls12_381` Rust crate（或 `blstrs`），patch field arithmetic 调用 syscall
- Pairing 由 guest 用 building blocks 组合（无单独 PAIRING syscall）

**关键设计点**（SP1 blog 启发）：
- **inversions/sqrt 用 witnessed 方式**：AIR 检查 `x · x_inv = 1`，无需 extended-Euclid
- 同一 Weierstrass AIR 可参数化处理 secp256k1/secp256r1/BN254 G1/BLS12-381 G1（与 Tier 3 ECDSA AIR 共享）

**优点**：
- 每个 Fp mul 都被证明（soundness 完整）
- building blocks 可复用（Fp2 = 3 Fp muls，Fp6 = Fp2 组合，Fp12 = Fp6 组合）
- 与 Tier 3 ECDSA AIR 共享 Weierstrass 模块

**缺点**：
- 12 个 BLS syscalls + 6 个 host impl，工作量 4-6 周
- pairing 仍需 ~13M cycles（guest 计算），prove 时间较长

**工期**：4-6 周
- Step 4.4.1：Fp384 add/sub/mul AIR（1 周）
- Step 4.4.2：Fp2 add/sub/mul AIR（1 周）
- Step 4.4.3：Weierstrass add/double AIR（与 Tier 3 ECDSA 共享，0.5 周）
- Step 4.4.4：BLS12-381 DECOMPRESS AIR（0.5 周）
- Step 4.4.5：Guest patch + e2e 测试（1-2 周）

### 6.5 选项 C：Trusted Host + Logup Commitment（**最快但 soundness 最弱**）

**设计**：
- BLS12-381 syscall 仍由 host 执行（`blstrs` crate）
- CPU AIR 在 ECALL BLS 行发送 `commitment` claim：
  ```text
  values = (syscall_id, input_args, output_args)
  multiplicity = +1
  ```
- 新增 `BlsLookup` relation 但 **不实现 Bls AIR 组件**
- Verifier 信任 commitment，但通过 logup 保证 ECALL input/output 绑定

**优点**：1 周工期，最简单
**缺点**：恶意 prover 可伪造 BLS 输出（soundness tradeoff）

**适用场景**：BLS12-381 仅用于非资金核心路径（texas_poker 合约内部）

### 6.6 选项 D：Hybrid 分阶段（**推荐折中**）

**Phase 4（当前）**：
- 选项 C：Trusted host + logup commitment（1 周）
- 完成 E2E 测试，验证 BLS12-381 syscall 在 poker game 中可用

**Phase 6+（可选）**：
- 若 BLS12-381 用于资金路径或需要更强 soundness，升级到选项 B
- 评估 SP1 cycle 数据：~13M cycles/pairing，是否可接受

### 6.7 用户确认（2026-07-20）

**BLS12-381 处理策略：选项 B — Building-block AIRs（SP1 模式）✅**

用户决策理由：
- **soundness 完整**：所有 BLS12-381 操作在 AIR 内验证，无 trusted host 缺口
- **行业最佳实践**：SP1 已验证的 Pattern E（Building-block + Guest 组合 pairing）
- **与 Tier 3 ECDSA AIR 共享 Weierstrass 模块**：参数化曲线算术 AIR 可复用
- **接受 4-6 周工期**：Phase 4 整体工期可控

选项对比回顾：
- **A** Full Pairing AIR：不推荐（行业无人实现，工期 6-8 周，~50,000 行/pairing）
- **B** Building-block AIRs（SP1 模式）：✅ **已选**（soundness 完整，工期 4-6 周，12 syscalls）
- **C** Trusted host + commitment：被否决（soundness 最弱，恶意 prover 可伪造 BLS 输出）
- **D** Hybrid 分阶段：被否决（先 C 后 B 的两阶段路径不必要，直接实施 B 更简洁）

**实施范围**（Tier 4，详见 §7）：
1. `BLS12381_FP_ADD` / `FP_SUB` / `FP_MUL`：384-bit mod 算术 AIR（~12×32-bit limb）
2. `BLS12381_FP2_ADD` / `FP2_SUB` / `FP2_MUL`：Fp2 via Karatsuba（3 muls + 2 adds）
3. `BLS12381_ADD` / `DOUBLE`：参数化 Weierstrass AIR（与 ECDSA secp256k1 共享模块）
4. `BLS12381_G1_DECOMPRESS` / `G2_DECOMPRESS`：点解压 AIR（witnessed sqrt）
5. **无单独 PAIRING syscall**：pairing 由 guest 用 building blocks 组合（参考 SP1，~13M cycles/pairing）

***

## 7. 实施步骤

### Tier 1：ECALL Dispatch（1-2 周）

#### Step 4.1.1：扩展 column_layout_v2.rs（0.5 天）
- 新增 `COL_SYSCALL_ID_BASE = 101` 等 25 个列常量
- 更新 `NUM_COLUMNS = 101 → 126`

#### Step 4.1.2：扩展 trace_native.rs（1 天）
- `step_to_m31_row` 中 Ecall 指令填充 SyscallId/Args/Output 列
- 非 ECALL 行所有新增列置 0

#### Step 4.1.3：扩展 cpu_air.rs（1-2 天）
- 新增 C56-C75 约束（20 条）
- 新增 EcallLookup claim 发送
- 更新 `max_constraint_log_degree_bound`

#### Step 4.1.4：扩展 lookups.rs（0.5 天）
- `relation!(EcallLookup, 25);`

#### Step 4.1.5：测试（1 天）
- 4 个测试：poseidon/sha256/no_ecall/soundness

### Tier 2：Poseidon AIR（2-3 周）

#### Step 4.2.1：M31 Poseidon 参数生成（1 天）
- 用 `ark-crypto-primitives` 在 M31 上生成 MDS + round constants
- 编译期缓存（`OnceLock`）

#### Step 4.2.2：新建 poseidon_air.rs（3-5 天）
- 实现 `PoseidonAir` FrameworkEval
- 21 列 + 16 条约束
- 单元测试（无 logup，仅约束验证）

#### Step 4.2.3：扩展 trace_native.rs（2 天）
- `trace_to_poseidon_trace`：从 emulator trace 提取 Poseidon 调用，生成 30 行/hash
- 输入/输出与 CPU ECALL 行对应

#### Step 4.2.4：扩展 prover.rs（2 天）
- `prove_cpu_memory_poseidon_trace`：3 组件 prover
- `gen_poseidon_interaction_trace`：Poseidon logup yield
- soundness check：`claimed_sum_cpu + claimed_sum_mem + claimed_sum_poseidon == 0`

#### Step 4.2.5：测试（2 天）
- 5 个测试：single_hash/multi_hash/correctness/logup_consistency/soundness

### Tier 2：Sha256 AIR（2-3 周）

类似 Poseidon AIR 流程，参考 Nexus zkVM sha256 实现。

### Tier 2：MerkleVerify AIR（1 周）

依赖 Poseidon AIR 完成。每行一个 Merkle 层，通过 PoseidonLookup claim 证明每层 hash。

### Tier 3：ECDSA verify AIR（2-3 周，**用户确认 in scope**）

secp256k1 over M31（非 native）。参考 Nexus zkVM ecdsa 实现。

**关键设计**：
- secp256k1 是 256-bit field，M31 模拟需 9×32-bit limb
- ECDSA verify = 公钥点恢复 + signature hash + scalar compare
- 参考 Nexus zkVM `ecdsa/` 模块（secp256k1 AIR ~3000 行）
- 工期细分：
  - Step 4.3.1：secp256k1 field arithmetic AIR（1 周）
  - Step 4.3.2：EC point operations AIR（add, scalar_mul）（1 周）
  - Step 4.3.3：ECDSA verify 顶层 AIR（0.5 周）
  - Step 4.3.4：测试（0.5 周）

### Tier 3：Keccak256 AIR + host impl（2-3 周，**用户确认 in scope**）

当前 `poker_zkvm/src/syscalls/` 中 Keccak256 syscall ID 已声明（0x0B）但无 host 实现。Phase 4 需：
- 新建 `poker_zkvm/src/syscalls/keccak256.rs`：host 实现（用 `tiny-keccak` crate）
- 新建 `poker_zkvm/src/stwo_backend/air/precompile/keccak256.rs`：Keccak-f[1600] permutation AIR

**Keccak AIR 设计**（参考 RISC Zero Keccak AIR）：
- 24 轮 permutation，每轮 5 sub-operations（theta/rho/pi/chi/iota）
- 状态 5×5×64-bit lane = 1600 bits = 200 bytes
- 每轮 ~50 列 × ~24 行
- 工期细分：
  - Step 4.3.5：host impl `Keccak256Syscall`（0.5 周）
  - Step 4.3.6：Keccak-f[1600] AIR（1.5 周）
  - Step 4.3.7：测试（0.5 周）

### Tier 3：Modexp AIR + host impl（2-3 周，**用户确认 in scope**）

当前 `poker_zkvm/src/syscalls/` 中 Modexp syscall ID 已声明（0x0C）但无 host 实现。Phase 4 需：
- 新建 `poker_zkvm/src/syscalls/modexp.rs`：host 实现（用 `num-bigint` crate）
- 新建 `poker_zkvm/src/stwo_backend/air/precompile/modexp.rs`：Modexp AIR

**Modexp AIR 设计**：
- 大整数模幂：`base^exp mod modulus`，所有操作数 variable-length（最多 2048-bit）
- 算法：square-and-multiply，每 bit 一次 square + conditional multiply
- AIR：每 bit 一行，~30 列（base/modulus/result × 9×32-bit limb + IsExpBit + counter）
- 工期细分：
  - Step 4.3.8：host impl `ModexpSyscall`（0.5 周）
  - Step 4.3.9：modular multiplication AIR（1 周）
  - Step 4.3.10：Modexp 顶层 AIR（0.5 周）
  - Step 4.3.11：测试（0.5 周）

### Tier 4：BLS12-381 Building-block AIRs（**选项 B 已确认**，4-6 周）

用户决策（2026-07-20）：实施 SP1 模式的 Building-block AIRs，实现 12 个 BLS12-381 syscalls 的完整 AIR，pairing 由 guest 用 building blocks 组合（无单独 PAIRING syscall）。

**实施清单**（详见 §6.7）：
- 3 个 Fp384 算术 AIR（ADD/SUB/MUL，~12×32-bit limb）
- 3 个 Fp2 算术 AIR（ADD/SUB/MUL，Karatsuba）
- 2 个 Weierstrass 曲线算术 AIR（ADD/DOUBLE，与 ECDSA secp256k1 共享模块）
- 2 个点解压 AIR（G1_DECOMPRESS/G2_DECOMPRESS，witnessed sqrt）

工期细分：
- Step 4.4.1：Fp384 field arithmetic AIR（1 周）
- Step 4.4.2：Fp2 arithmetic AIR（Karatsuba）（0.5 周）
- Step 4.4.3：参数化 Weierstrass AIR（与 ECDSA 共享）（1 周）
- Step 4.4.4：点解压 AIR（0.5 周）
- Step 4.4.5：guest pairing 组合 + cycle 基准（1 周）
- Step 4.4.6：测试（1 周）

***

## 8. 完成标准

### Tier 1（必做）✅ **已完成 2026-07-20**
- [x] `column_layout_v2.rs` 新增 25 列常量（`COL_SYSCALL_ID=101` 等，NUM_COLUMNS 101→126）
- [x] `cpu_air.rs` 新增 C57-C82 约束（C57 IS_ECALL binality + C58-C82 25 条 zero gating）+ EcallLookup claim
- [x] `EcallLookup` relation 定义（`relation!(EcallLookup, 25);`）
- [x] 4 个 ECALL 集成测试通过（roundtrip + zero_gating_soundness + binality_soundness + padding_all_zeros）
- [x] workspace 测试通过（poker_zkvm 401/401）

### Tier 2（必做）
- [ ] `poseidon_air.rs` 实现 + 测试（M31-native，已确认；**v2.1 中间列降度方案：30 列 + 27 约束，约束度 ≤ 2**）
- [ ] `sha256_air.rs` 实现 + 测试（同样采用中间列降度，约束度 ≤ 2）
- [ ] `merkle_verify_air.rs` 实现 + 测试
- [ ] 3 组件 prover（CPU + Memory + Poseidon）测试通过
- [ ] 4 组件 prover（CPU + Memory + Poseidon + Sha256）测试通过
- [ ] 5 组件 prover（CPU + Memory + Poseidon + Sha256 + MerkleVerify）测试通过
- [ ] precompile 正确性验证（AIR 输出 vs host 函数）
- [ ] zk_shuffle 独立性验证（无 Poseidon AIR 引用 zk_shuffle 代码）
- [ ] 事件哈希迁移：SyscallContext.events 类型从 `Vec<ark_bn254::Fr>` 改为 `Vec<[M31; 4]>`
- [ ] **v2.1 验证**：所有 AIR `max_constraint_log_degree_bound = log_size + 1`（SubDomain 模式）
- [ ] **v2.1 验证**：所有 AIR 使用 `PcsConfig::default()`，无 `set_store_polynomials_coefficients` / `lifting_log_size = Some(...)`
- [ ] **v2.1 验证**：`StarkProof.commitments.len() == 4`（所有 prover 测试断言）

### Tier 3（**用户确认 in scope**）
- [ ] `ecdsa_verify_air.rs` 实现 + 测试（secp256k1 over M31，资金路径安全核心）
- [ ] `keccak256.rs` host impl + `keccak256_air.rs` 实现 + 测试
- [ ] `modexp.rs` host impl + `modexp_air.rs` 实现 + 测试
- [ ] 6/7/8 组件 prover（依次加入 ECDSA/Keccak/Modexp）测试通过

### Tier 4（**选项 B 已确认：Building-block AIRs**）
- [ ] `bls_fp384_air.rs`：3 个 Fp384 算术 AIR（ADD/SUB/MUL）+ 测试
- [ ] `bls_fp2_air.rs`：3 个 Fp2 算术 AIR（ADD/SUB/MUL，Karatsuba）+ 测试
- [ ] `weierstrass_air.rs`：参数化曲线算术 AIR（与 ECDSA secp256k1 共享）+ 测试
- [ ] `bls_decompress_air.rs`：G1/G2 点解压 AIR + 测试
- [ ] guest pairing 组合测试 + cycle 基准（目标 ~13M cycles/pairing）
- [ ] 9+ 组件 prover（CPU + Memory + Poseidon + Sha256 + Merkle + ECDSA + Keccak + Modexp + BLS building blocks）测试通过

***

## 9. 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| M31 Poseidon 安全性不足（31-bit field） | LOW | 重新选参数 | 参考 Plonky3 参数，第三方安全分析 |
| Poseidon AIR 列数过多（30 列，v2.1 中间列降度） | LOW | prove 时间增加 | 拆分为多 batch，复用列；MemoryAir 25 列已验证可用 |
| **v2.1 风险**：中间列降度方案仍无法通过 Stwo prover | LOW | 工期 +1-2 周 | Fallback Option C（Trusted Host + Logup Commitment），Option D（AssertEvaluator 诊断） |
| Sha256 AIR 复杂度（76 列 × 64 行） | MEDIUM | 工期 +1 周 | 参考 Nexus zkVM 优化设计；同样采用中间列降度避免 ExtendToEvalDomain |
| ECALL 列扩展影响 CpuAir 现有约束 | LOW | 回归测试 | 新增列不影响现有约束（仅添加 IS_ECALL gating） |
| BLS12-381 commitment soundness 不足 | MEDIUM | 资金风险 | 仅用于非资金核心路径，资金路径用 ECDSA |
| 多组件 prover 性能下降 | MEDIUM | prove 时间增加 | 5+ 组件时考虑子集 prove + 递归聚合（Phase 5） |
| Tier 3 工期超预期（ECDSA/Keccak/Modexp 都需实现） | HIGH | Phase 4 工期 +4-6 周 | 优先 ECDSA（资金路径），Keccak/Modexp 可并行/后置 |
| Keccak/Modexp host impl 与 AIR 一致性验证 | MEDIUM | soundness bug | 测试：host impl 输出 = AIR 输出，多组随机输入对比 |
| 事件哈希迁移引发回归 | LOW | 测试失败 | 增量迁移，保留 BN254 Fr 兼容 path 直到测试全绿 |
| **v2.1 风险**：其他 precompile AIR（Sha256/Keccak/ECDSA）也触发 ExtendToEvalDomain 模式 | MEDIUM | 工期 +2-3 周 | Hard Constraint：所有 AIR 约束度 ≤ 2，强制 SubDomain 模式；实施前先评估约束度 |

***

## 10. 关键设计决策（用户确认状态）

| # | 决策 | 用户确认 | 最终选择 | 影响 |
|---|------|---------|---------|------|
| 1 | Poseidon 字段 | ✅ 已确认 (2026-07-20) | **M31-native** | Phase 4 工期 ±2 周，性能 ±10× |
| 2 | BLS12-381 处理 | ✅ 已确认 (2026-07-20) | **选项 B — Building-block AIRs（SP1 模式）**：12 syscalls，pairing 由 guest 组合；与 ECDSA 共享 Weierstrass 模块 | Phase 4 工期 +4-6 周（Tier 4） |
| 3 | Keccak256 AIR + host | ✅ 已确认 in scope | **实现**（参考 Nexus Keccak AIR，M31 8-limb + lookup tables） | Phase 4 工期 +2-3 周 |
| 4 | Modexp AIR + host | ✅ 已确认 in scope | **实现**（参考 SP1 `U256XU2048_MUL`，witnessed partial products + carry chain） | Phase 4 工期 +2-3 周 |
| 5 | ECDSA verify AIR | ✅ 已确认 in scope | **实现**（参考 SP1 `WeierstrassAddAssignChip`，inversions 用 witnessed） | Phase 4 工期 +2-3 周 |
| 6 | 事件哈希迁移 | ✅ 已确认 | **接受 M31 迁移** | 与决策 1 一致 |
| 7 | Ed25519 / Bn254Pairing | 未涉及 | **Descope**（不在 syscall 范围） | N/A |
| 8 | Tier 1 ECALL Dispatch | ✅ 已完成 (2026-07-20) | 25 列 + C57-C82 约束 + EcallLookup + 4 集成测试 + 5 单元测试，poker_zkvm 401/401 通过 | 关闭"非 ECALL 行伪造 ECALL 数据"soundness 缺口 |
| 9 | **v2.1**：Poseidon AIR 中间列降度方案 | ✅ 已确认 (2026-07-20) | **Option B — S-box x^5 分解为 3 个 degree ≤ 2 约束（SboxSq1/SboxSq2/SboxOut），30 列 + 27 约束**，强制 SubDomain 模式 | Tier 2 Poseidon 工期 -1.5 周（5-7 周 → 3.5-5.5 周） |
| 10 | **v2.1**：所有 AIR 约束度数 ≤ 2（Hard Constraint） | ✅ 已确认 (2026-07-20) | `max_constraint_log_degree_bound = log_size + 1`，强制 SubDomain 评估模式 | 避免所有 AIR 触发 ExtendToEvalDomain 边界 case |
| 11 | **v2.1**：所有 AIR 统一 `PcsConfig::default()` | ✅ 已确认 (2026-07-20) | 禁止 `set_store_polynomials_coefficients` 和 `lifting_log_size = Some(...)` | 消除配置复杂性 |
| 12 | **v2.1**：`StarkProof.commitments.len() == 4` | ✅ 已确认 (2026-07-20) | Stwo 返回 4 个 commitments（Tree 0/1/2 + composition poly tree） | 修正 v1 测试断言错误 |

***

## 11. 类似项目 Precompile 处理方法对比（调研报告，2026-07-20）

### 11.1 调研范围

6 个主流 zkVM / zk 证明系统（2026-07-20 GitHub main 分支）：
- **Nexus zkVM** — Stwo + M31
- **RISC Zero** — BabyBear + 自研 HAL + Zirgen DSL
- **Plonky3** — 独立 AIR 库套件（BabyBear/M31/Goldilocks）
- **Stwo** — M31 Circle STARK 库
- **SP1** — Plonky3 fork（`slop-*`）+ BabyBear
- **Jolt** — lookup-based，BN254 scalar field

### 11.2 Primitive-by-Primitive 对比

| Primitive | Nexus zkVM | RISC Zero | Plonky3 | Stwo | SP1 | Jolt |
|-----------|-----------|-----------|---------|------|-----|------|
| **SHA-256** | CPU AIR 内 | Full AIR (~72 cycles/block) | hash crate（无 AIR） | 无示例 | **Full AIR** | Lookup 分解 |
| **Keccak-256** | **Full AIR**（Xor/BitNotAnd/BitRotate lookup tables，8 limb/lane M31） | 独立加速器电路（200 cycles/perm） | **Full AIR**（16-bit limb × 4/lane，纯算术约束） | 无示例（Nexus 在其上构建） | **Full AIR**（fork Plonky3） | Lookup 分解 |
| **ECDSA secp256k1** | 未实现 | bigint2 blobs + k256 guest | 未实现 | 未实现 | **Full AIR**（Weierstrass 参数化） | Lookup 分解 |
| **BLS12-381 G1 ops** | 未实现 | bigint2 blobs | 未实现 | 未实现 | **Full AIR**（12 syscalls） | 未实现 |
| **BLS12-381 pairing** | **未实现** | **Guest 跑 bls12_381 crate**（bigint2 加速 Fp ops） | 未实现 | 未实现 | **未实现**（用 building blocks 组合） | 未实现 |
| **Modexp** | 未实现 | bigint2 modmul_4096 + RSA | 未实现 | 未实现 | **Full AIR**（U256×U2048_MUL） | bigint inline |
| **Poseidon2** | 未实现 | Full AIR（recursion circuit） | **Full AIR** | **Full AIR**（M31 canonical） | **Full AIR** | 未实现 |
| **Blake3** | 未实现 | 未实现 | **Full AIR** | **Full AIR**（xor lookup tables） | 未实现 | Lookup 分解 |
| **BN254 pairing** | 未实现 | 未实现 | 未实现 | 未实现 | **未实现**（用 building blocks） | 未实现 |

### 11.3 5 种设计模式

| 模式 | 描述 | 代表项目 | 适用场景 |
|------|------|----------|---------|
| **A. Native field Full AIR** | primitive 字段 = AIR 字段，直接约束 | Stwo Poseidon2、Plonky3 Poseidon2 | Poseidon/M31 等原生匹配 |
| **B. Limb decomposition + Lookup tables** | 大 word 拆 limb，bitwise ops 用 lookup | Nexus Keccak、Stwo Blake、SP1 Keccak | Keccak/SHA-256 在 M31/BabyBear |
| **B3. Verify-don't-execute** | witness 提供 inverse/sqrt，AIR 检查 x·x_inv=1 | SP1 Weierstrass | EC ops（inv/sqrt 廉价） |
| **C. 独立加速器电路 + 递归聚合** | 独立 STARK + recursion circuit 合并 | RISC Zero Keccak/bigint2 | 高频重操作（BigInt VM） |
| **D. Lookup-table 分解** | 复杂指令拆 micro-ops + lookup | Jolt | 所有指令统一 lookup |
| **E. Building-block AIRs + Guest 组合** | 提供 Fp/EC building blocks，guest 组合高层 op | SP1 BLS12-381 pairing | pairing 等超复杂原语 |

### 11.4 关键启示（应用于 Phase 4）

1. **Poseidon M31-native 是最佳实践**（Pattern A）— Stwo/Plonky3/SP1/RISC Zero 都这么做
2. **Keccak/SHA-256 用 Pattern B**（limb decomposition + lookup tables）— Nexus Keccak 是 M31 上最佳参考
3. **ECDSA 用 Pattern B3**（参数化 Weierstrass + witnessed inverse）— SP1 是最佳参考
4. **Modexp 用 SP1 的 `U256XU2048_MUL`** Pattern
5. **BLS12-381 pairing 不做完整 AIR**（Pattern E）— 行业共识
6. **多组件框架是标准**（Stwo-style multi-component + Logup）— Phase 3.5 已建立

### 11.5 SP1 性能基准（参考）

SP1 BLS12-381 precompile cycle 数（with precompile vs without）：

| 操作 | Without precompile | With precompile |
|------|-------------------:|----------------:|
| Fp mul | 402 | 552 |
| Fp inversion | 1,826,741 | 1,599 |
| Fp2 mul | 12,782 | 842 |
| Fp12 mul | 272,757 | 12,515 |
| Fp12 inversion | 2,273,149 | 32,516 |
| G1 scalar mul | 19,569,843 | 2,931,398 |
| G2 scalar mul | 77,193,504 | 1,719,549 |
| Ethereum sync committee (512 BLS sigs) | 6,732,566,139 | 49,387,331 |

**启示**：BLS12-381 precompile 显著加速（100×+），但 pairing 仍需 ~13M cycles。Phase 4 选项 B/D 均可接受。

### 11.6 调研来源

- **Nexus zkVM**: https://github.com/nexus-xyz/nexus-zkvm (precompiles/, prover/src/chips/, prover/src/extensions/keccak/)
- **RISC Zero**: https://github.com/risc0/risc0 (risc0/circuit/{keccak,rv32im}, risc0/bigint2/)
- **Plonky3**: https://github.com/Plonky3/Plonky3 (keccak-air, poseidon2-air, blake3-air, bn254)
- **Stwo**: https://github.com/starkware-libs/stwo (crates/prover/src/examples/{blake,poseidon,plonk})
- **SP1**: https://github.com/succinctlabs/sp1 (crates/core/machine/src/syscall/precompiles/)
- **Jolt**: https://github.com/a16z/jolt (crates/jolt-lookup-tables, jolt-inlines/{sha2,keccak256,secp256k1})
- **SP1 blog**: https://blog.succinct.xyz/succinctshipsprecompiles/ (October 2024 BLS12-381 precompile benchmarks)
- **EIP-2537**: https://eips.ethereum.org/EIPS/eip-2537 (BLS12-381 precompile gas costs)
- **Banerjee & Chandrakasan**: arXiv:2201.07496 (15,389 Fp muls per BLS12-381 pairing)