# poker_zkvm Phase B/C/D 续接计划（恢复执行）

> **关联文档**：
> - 已批准总计划：`.trae/documents/poker_zkvm_security_remaining_remediation_plan.md`
> - 详细步骤计划：`.trae/documents/poker_zkvm_phase_bcd_implementation_plan.md`
> - 审计报告：`.trae/documents/poker_zkvm_security_audit_vs_risczero.md`
>
> **本计划状态**：决策完整 — 执行者无需再做选择，按步骤实现即可。
> **背景**：上下文丢失后恢复。本计划基于对**当前代码实际状态**的逐文件核对，确认 B.1–B.5 已落地，仅余 B.6/B.7 + Phase C + Phase D。

---

## 1. 摘要（Summary）

延续对 poker_zkvm 的安全审计修复（对比 RISC Zero，共发现 8 个漏洞）。

- **Phase A（V1 分支条件，CRITICAL）**：✅ 已完成，617 测试通过。
- **Phase B（V4 8-bit limb 范围检查，HIGH）**：B.1–B.5 代码已写入并经本次核对**内部一致**；未编译。**剩余**：B.6 两个 soundness 测试 + B.7 编译/测试。
- **Phase C（V5 递归 FRI query point 硬编码，HIGH）**：⏳ 未开始。`trace_gen.rs:616` 仍为 `SecureField::from(1u32)`。
- **Phase D（全量 soundness 测试 + 回归）**：⏳ 未开始。
- **V2 逻辑/移位指令（MEDIUM）**：用户已确认降级为已知 gap（132 列预算不足，不做 bit 分解）。

---

## 2. 当前状态分析（Current State Analysis — 本次实测核对）

### 2.1 Phase B 代码已落地且内部一致 ✅

经逐文件核对，以下代码均已存在且**关键一致性成立**：

| 子任务 | 位置 | 状态 |
|--------|------|------|
| B.1 `CpuAir::new_with_memory_and_range` | [cpu_air.rs:224](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/cpu_air.rs) | ✅ 已写入（memory+range，ecall=None） |
| B.2 `RangeCheckTrace` + `gen_range_check_air_trace` + `range_check_trace_to_evaluations` | [trace_native.rs:1730](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/trace_native.rs) | ✅ 已写入 |
| B.3 `gen_cpu_range_claim_interaction_trace`（24 列） | [prover.rs:438](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs) | ✅ 已写入 |
| B.4 `gen_range_check_air_interaction_trace`（1 列） | [prover.rs:482](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs) | ✅ 已写入 |
| B.5 `CpuMemRangeProof` + `prove_cpu_mem_range_trace` + `verify_cpu_mem_range_proof` | [prover.rs:724-940](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs) | ✅ 已写入 |
| `RangeCheckAir`（4 列，6 约束，logup yield） | [range_check_air.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/range_check_air.rs) | ✅ 已写入 |
| `RangeCheckLookup` relation（1 元组） | lookups.rs:216 | ✅ 已写入 |

### 2.2 关键一致性已核对（决定 soundness 正确性）

1. **24 limb 列三处一致**（已逐行核对，三处列表完全相同）：
   - CPU AIR evaluate `RANGE_CHECK_COLS`：[cpu_air.rs:1251](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/cpu_air.rs)
   - Prover `gen_cpu_range_claim_interaction_trace` `RANGE_CHECK_COLS`：[prover.rs:448](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs)
   - Trace 生成器 `RANGE_CHECK_LIMB_COLS`：[trace_native.rs:1758](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/trace_native.rs)
   - 列表均为：PC(0-3) + PcNext(4-7) + ValueAEff(10-13) + ValueB(14-17) + ValueC(18-21) + MemAddr(74-77) = 24 limb ✓

2. **交互列顺序与组件顺序一致**：
   - CPU AIR evaluate：先 memory claim（1 次 `add_to_relation`，cpu_air.rs:1180）→ 后 24 range claim（cpu_air.rs:1265）→ 单次 `finalize_logup`（cpu_air.rs:1284）
   - Prover Tree 2 拼接顺序：`cpu_mem_interaction(4) + cpu_range_interaction(96) + mem_yield(4) + rc_yield(4)` = 108 base cols（prover.rs:847-850）
   - components 传入 `prove()` 顺序：`[&cpu, &mem, &range]`（prover.rs:864-865）
   - 三者顺序匹配 ✓

3. **Soundness 条件**：`claimed_sum_cpu (=mem_claim+range_claim) + claimed_sum_mem + claimed_sum_range == 0`，prover 端 assert（prover.rs:830）+ verifier 端 check（prover.rs:931）✓

### 2.3 未编译 ⚠️

Phase B 全部代码（B.1–B.5）自写入后**未编译过**。诊断曾报 `unused` 警告应为 stale（函数已被 `prove_cpu_mem_range_trace` 调用）。B.7 首次编译可能暴露少量类型/API 问题，预计均为局部修复。

### 2.4 Phase C 现状（实测）

- [trace_gen.rs:616](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/recursive/trace_gen.rs)：`let query_x_qm31 = SecureField::from(1u32);`（硬编码，未修复）
- [public_inputs.rs:20](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/recursive/public_inputs.rs)：`RecursivePublicInputs` 有 `query_positions: Vec<usize>`（line 52）但**无** `fri_query_x`/`fri_query_eval` 字段
- 注释明确标注 v5.1 placeholder，待 v5.2 修复（trace_gen.rs:576-592）

---

## 3. 提议变更（Proposed Changes）

### Phase B 剩余：B.6 Soundness 测试 + B.7 编译验证

#### B.6 新增 2 个 range_check soundness 测试

**文件**：[prover.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs) 的 `#[cfg(test)] mod tests`（test 模块起于 line 1277）

**复用现有 helper**：`make_step_indexed`（line 2577）、`trace_to_native`、`trace_to_memory_trace`、`zero_registers`。仿照现有 tamper 模式（如 `test_mul_soundness_tamper_result` line 1760、`test_beq_soundness_tamper_taken_false` line 1993）。

**测试 1 — `test_range_check_soundness_tamper_limb`**（核心 soundness）：
```rust
#[test]
fn test_range_check_soundness_tamper_limb() {
    // 1. 构造合法 ADD 单步 trace（post_registers[1]=5, x2=3, x3=2）
    // 2. trace_to_native → cpu_trace；trace_to_memory_trace → mem_trace
    // 3. 合法 trace：prove_cpu_mem_range_trace 应 Ok（正向验证）
    // 4. 篡改：cpu_trace.cols[COL_PC_BASE][0] = M31::from(256u32)（PC limb[0] 超出 [0,255]）
    // 5. 预期：prove_cpu_mem_range_trace Err 或 panic（soundness assert 失败：
    //    claim side 多了 256 的 +1，yield side 无 256 的对应项 → sum != 0）
    //    用 std::panic::catch_unwind 或 assert!(result.is_err()) 视实际行为
}
```
> **预期失败模式**：prover 端 soundness assert（prover.rs:830 `total_sum != 0`）panic。因 assert 是 panic 非 Err，测试用 `std::panic::catch_unwind` 捕获并断言 `is_err()`；若篡改后 trace 也触发约束失败，则 `is_err()` 同样成立。

**测试 2 — `test_range_check_soundness_roundtrip`**（正向 roundtrip，替代复杂的 multiplicity 篡改）：
```rust
#[test]
fn test_range_check_soundness_roundtrip() {
    // 合法 ADD + LW 多步 trace → prove_cpu_mem_range_trace Ok
    // → verify_cpu_mem_range_proof Ok（正向覆盖 3 组件 roundtrip）
    // 保证 V4 修复不破坏合法 trace 的可证可验性
}
```
> **决策**：测试 2 采用正向 roundtrip（参考 plan 的"简化备选"）。篡改 multiplicity 需在 prove 内部 hook，实现复杂且收益低于测试 1；测试 1 已覆盖"limb 超范围"核心 soundness，测试 2 覆盖"合法 trace 可证"。两项合计满足 V4 验证需求。

**测试位置**：插入 test 模块末尾（line 3019 `test_ecall_binality_soundness` 之后）。

#### B.7 编译 + 测试 + 一致性核对

**步骤**：
1. 编译：`cargo +nightly-2026-04-15 build -p poker_zkvm`
2. range_check 测试：`cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "range_check"`
3. **编译期核对清单**（若失败按此诊断）：
   - `combine(&[limb_val])` 1 元组签名匹配 `RangeCheckLookup`（relation! 宏 1 元组）
   - `PackedSecureField::from(PackedBaseField)` 转换可用（见 gen_cpu_interaction_trace 已用同模式）
   - `M31::from_u32_unchecked(0x7FFFFFFF - count[v])`（trace_native.rs 负数表示）类型正确
   - `multiplicity_ef: E::EF = multiplicity.into()`（range_check_air.rs:184）类型转换
4. 全量回归：`cargo +nightly-2026-04-15 test -p poker_zkvm --lib`

**预期**：619 测试通过（617 + 2 range），0 回归。

---

### Phase C：V5 递归 FRI query point 修复（HIGH）

> **最高风险**：`extract_fri_query_from_l1` 依赖 Stwo `FriVerifier` API。详见已批准计划 `poker_zkvm_phase_bcd_implementation_plan.md` C.1–C.6，此处仅列要点与决策。

#### C.1 扩展 `RecursivePublicInputs`（[public_inputs.rs:20](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/recursive/public_inputs.rs)）

`log_size` 字段后新增 2 字段：`pub fri_query_x: SecureField`、`pub fri_query_eval: SecureField`。同步更新 `new()` 签名、`Default`、及全部构造调用点（用 `rg "RecursivePublicInputs\|RecursivePublicInputs::new\|RecursivePublicInputs::default"` 定位，预计 ~10 处：recursion_prover.rs / trace_gen.rs / recursion_verifier.rs / e2e_test.rs / public_inputs.rs 单测）。

#### C.2 新增 `extract_fri_query_from_l1`

重放 L1 channel（commit preprocessed → commit trace → draw random_coeff → read composition commitment → draw OODS point）→ 构造 `FriVerifier`（从 `proof.fri` + config）→ `sample_query_positions(channel)` → 用 `CanonicCoset::new(log_size + blowup_log).circle_domain()` 将 position 转 CirclePoint → 取 x → `query_eval = last_layer_poly.eval_at_point(query_x)`。

**实现风险与降级**：若 `FriVerifier::new` 构造签名受阻，退化为重放 channel 到 OODS point 后手动按 `pcs/verifier.rs:verify_values` 逻辑 draw query positions，再用 domain API 转 CirclePoint。两方案均需重放 channel。

**API 查阅源**：`~/.cargo/registry/src/index.crates.io-*/stwo-2.3.0/src/core/fri.rs`（`FriVerifier::new` + `sample_query_positions`）、`.../pcs/verifier.rs`（`verify_values` 重放逻辑）。

#### C.3 修复 [trace_gen.rs:616](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/recursive/trace_gen.rs)

```rust
// 旧：let query_x_qm31 = SecureField::from(1u32);
// 新：
let query_x_qm31 = public_inputs.fri_query_x;
let query_eval_qm31 = public_inputs.fri_query_eval;
// 删除原 query_eval 计算行（改用公开输入）
```
更新文档注释 v5.1 placeholder → v5.2 已修复（lines 576-592）。

#### C.4 Prover 一致性检查（recursion_prover.rs `prove_recursive_with_fri` Step 1 后）

调用 `extract_fri_query_from_l1` 提取真实 `(query_x, query_eval)`，与 `public_inputs.fri_query_x/fri_query_eval` 比对，不等返回新 `RecursionProvingError::FriQueryMismatch`。

#### C.5 Channel mix 扩展

`mix_public_inputs_into_channel`（recursion_prover.rs:372）+ verifier 端对应函数新增 `channel.mix_felts(&[inputs.fri_query_x, inputs.fri_query_eval]);`。

#### C.6 Soundness 测试

`test_recursive_fri_soundness_tamper_query_x`：合法 L1 proof → 提取真实值 → 构造 inputs → 篡改 `fri_query_x = SecureField::from(2u32)` → 预期 `prove_recursive_with_fri` Err（`FriQueryMismatch`）。

**降级**：若 C.2 提取受阻无法独立测试，至少保证 C.1/C.3/C.5 编译通过 + 现有 recursive 测试不回归（query_x 用真实提取值或测试中固定值，确保 roundtrip 不破）。

---

### Phase D：全量回归

```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "recursive"
```

**预期最终**：~620 测试（617 + 2 range + 1 FRI），0 失败，0 回归。

---

## 4. 假设与决策（Assumptions & Decisions）

1. **执行顺序**：B.6 → B.7（编译+测试）→ Phase C → Phase D。每阶段完成运行测试确认无回归。
2. **B.6 测试 2 用正向 roundtrip**：篡改 multiplicity 需 hook prove 内部，复杂度高、收益低；测试 1（limb 超范围）已覆盖核心 soundness，测试 2 覆盖合法可证性。
3. **Phase B 3 组件不含 ecall**：`new_with_memory_and_range` 设 `ecall_lookup=None`，匹配现有 `prove_cpu_memory_trace` 无 ecall 模式（已核对 cpu_air.rs evaluate 中 ecall 分支被 None 跳过，不产生无 yield 的 ecall interaction 列）。
4. **Phase C 风险预案**：若 `FriVerifier` API 障碍，先完成 Phase B+D（HIGH range check + 测试）并提交，再单独处理 Phase C。Phase B 与 C 触及不同文件，可独立。
5. **V2 逻辑/移位指令保持降级**：用户已确认，不在本计划范围。
6. **不修改已完成且通过测试的 Phase A 实现**。
7. **每 Phase 完成后提交 git**（仅当用户要求时执行；不主动 commit）。

---

## 5. 验证步骤（Verification Steps）

### Phase B 验证
```bash
cargo +nightly-2026-04-15 build -p poker_zkvm
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "range_check"
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
```
预期：619 通过（+2 range），0 回归。**关键核对**：`gen_range_check_air_trace` 对合法 ADD/LW trace 的 multiplicity 计数使 soundness assert 通过。

### Phase C 验证
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "recursive" "fri_soundness"
```
预期：620 通过（+1 FRI），0 回归。

### Phase D 全量回归
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
```
预期：~620 通过，0 失败，0 回归。

---

## 6. 实施优先级与执行清单

| 顺序 | Phase | 内容 | 预计测试 | 阻塞? |
|------|-------|------|----------|-------|
| 1 | B.6 | range_check 2 soundness 测试 | +2 | 否 |
| 2 | B.7 | 编译 + range_check 测试 + 全量回归 | 0 | 否（可能需局部修类型/API） |
| 3 | C.1–C.6 | 递归 FRI query point 修复 | +1 | C.2 有 Stwo API 风险 |
| 4 | D | 全量回归 + e2e | 0 | 否 |

**执行者从顺序 1 开始**。若 B.7 编译遇阻，优先修复使 range_check 测试通过；若 Phase C 的 C.2 API 障碍短期内无法解决，先完成 B.6+B.7+D（HIGH range check + 回归）并报告，再单独攻坚 Phase C。
