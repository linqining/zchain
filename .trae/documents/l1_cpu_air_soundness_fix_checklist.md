# L1 CPU AIR Soundness 修复 — 审查清单

> 每个 Phase 完成后逐项核对

## Phase 1 审查 ✅

### 列布局
- [x] COL_SIGN_A_BITS_BASE = 134，范围 134-141
- [x] COL_SIGN_B_BITS_BASE = 142，范围 142-149
- [x] NUM_COLUMNS = 150
- [x] 列无重叠测试通过（test_column_ranges_no_overlap，含 134-149）

### A2 约束（Memory AIR）
- [x] M20-M23：`(1-IsStore)*(1-IsPadding)*(ValCur[i]-ValPrev[i])=0`，i=0..3
- [x] 度数 = 2（gating deg1 × diff deg1）
- [x] 非 Load 行（IsStore=1 或 IsPadding=1）gating=0，约束自动满足
- [x] 首次访问 Load：ValPrev=0（M15-M18）+ A2 → ValCur=0（零初始化内存模型）

### A3 约束（CPU AIR）
- [x] ValueB[3] = Σ SignABits[i]·2^i 位分解（gated by g_sign_a_bind）
- [x] SignABits binality（gated by g_sign_a_bind，度 3）
- [x] sign_a = SignABits[7]（gated by g_sign_a_bind）
- [x] ValueC[3] = Σ SignBBits[i]·2^i 位分解（gated by g_sign_b_bind）
- [x] SignBBits binality（gated by g_sign_b_bind，度 3）
- [x] sign_b = SignBBits[7]（gated by g_sign_b_bind）
- [x] g_sign_a_bind = is_slt_group + is_signed_branch + is_mulh + is_mulhsu + is_div + is_rem
- [x] g_sign_b_bind = is_slt_group + is_signed_branch + is_mulh + is_div + is_rem（不含 MULHSU）
- [x] 所有约束度数 ≤ 3

### trace 填充
- [x] trace_native.rs 对 SLT/SLTI/BLT/BGE/MULH/MULHSU/DIV/REM 行填充 SignABits
- [x] 对 MULH/MULHSU/DIV/REM 行填充 SignBBits（SLT/SLTI/BLT/BGE 也用 sign_b）
- [x] 非使用行 SignABits/SignBBits = 0（row 预初始化为 0）

### 测试
- [x] 正例：prove/verify 通过（641 测试全量通过）
- [x] 反例 A3 sign_a 篡改 → prove 失败（test_a3_sign_a_binding_soundness）
- [x] 反例 A3 SignABits 位分解篡改 → prove 失败（test_a3_sign_a_bits_decomposition_soundness）
- [x] 反例 A3 SignBBits 位分解篡改 → prove 失败（test_a3_sign_b_bits_decomposition_soundness）
- [x] 反例 A2 Memory Load ValCur 篡改（logup 平衡）→ prove 失败（test_a2_load_valcur_valprev_soundness）

## 度数预算（全局）
- [x] 无约束度数 > 3（A3 binality 度 3，A2 度 2，均在预算内）
- [x] max_constraint_log_degree_bound = log_size + 1 保持（CPU AIR + Memory AIR）

## Phase 2 审查 ✅

### A8 RangeCheck 覆盖扩展
- [x] RANGE_CHECK_COL_INDICES 定义为 55 列（column_layout_v2.rs，统一常量）
- [x] 覆盖：PC(4)+PcNext(4)+ValueAEff(4)+ValueB(4)+ValueC(4)+MemAddr(4) = 24 原有列
- [x] 新增覆盖：MulCarryLo(7)+MulHigh(4)+AbsA(4)+AbsB(4)+DivQuot(4)+DivRem(4)+MulLow(4) = 31 列
- [x] cpu_air.rs 使用 RANGE_CHECK_COL_INDICES 发送 55 个 range claim
- [x] trace_native.rs gen_range_check_air_trace 统计 55 列的 limb 值出现次数
- [x] prover.rs gen_cpu_full_interaction_trace 生成 56 SecureField 列（1 memory + 55 range）
- [x] prover.rs gen_cpu_range_only_interaction_trace 生成 55 SecureField 列（55 range）
- [x] verify_cpu_mem_range_proof interaction_log_sizes 动态计算（(1+55)×4+4+4 = 232 base cols）

### A7 carry/limb 范围
- [x] ADD/ADDI/SUB carry（col 8-9）由 binality 约束（binary 0/1）✓
- [x] PC carry（col 79-80）由 binality 约束 ✓
- [x] 操作数 limb（ValueAEff/ValueB/ValueC）由 A8 RangeCheck 覆盖 ✓
- [x] M 扩展 carry_lo/abs/quot/rem/low/high 由 A8 RangeCheck 覆盖 ✓

### 测试
- [x] 正向 roundtrip：3 组件 prove/verify 通过（SW+LW，test_range_check_soundness_roundtrip）
- [x] 正向 roundtrip：3 组件 prove/verify 通过（MUL，test_a8_range_check_mul_roundtrip）
- [x] 反例 A8：篡改 MulLow[0]=256 → prove 失败（test_a8_range_check_tamper_mul_low，logup 不平衡）
- [x] cargo test 全量通过（295 stwo_backend tests passed; 0 failed）

## 完成标准
- [ ] A1-A8 全部有 AIR 约束（非信任 trace generator）— Phase 1-2 完成 A2+A3+A7+A8，A1/A6 待后续 Phase
- [x] 所有 Phase 1-2 反例测试通过
- [x] cargo test 全量通过
