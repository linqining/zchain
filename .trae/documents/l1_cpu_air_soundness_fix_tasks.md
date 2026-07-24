# L1 CPU AIR Soundness 修复 — 任务清单

> 对应 spec：`l1_cpu_air_soundness_fix_design.md`
> 状态：规范已冻结，按 Phase 顺序实施

## Phase 1：A2 + A3（独立，先行）✅

- [x] T1.1 column_layout_v2.rs：新增 COL_SIGN_A_BITS_BASE(134) / COL_SIGN_B_BITS_BASE(142)，NUM_COLUMNS=150，更新列无重叠测试
- [x] T1.2 memory_air.rs：新增 M20-M23（Load 行 ValCur=ValPrev 约束）
- [x] T1.3 cpu_air.rs：新增 A3 约束块（ValueB[3]/ValueC[3] 位分解 + binality + sign_a/sign_b 绑定）
- [x] T1.4 trace_native.rs：填充 SignABits/SignBBits（ValueB[3]/ValueC[3] 的 8-bit 分解）
- [x] T1.5 反例测试：篡改 sign_a → prove 失败；Memory Load ValCur≠ValPrev → prove 失败（4 个反例测试）
- [x] T1.6 正例回归：现有 prove/verify 全量通过（641 passed; 0 failed）
- [x] T1.7 修正 3 个依赖「Load 未初始化内存期望非零值」的测试（零初始化内存模型，加前驱 Store）

## Phase 2：A7 + A8（RangeCheck 全覆盖）✅

- [x] T2.1 column_layout_v2.rs：定义 RANGE_CHECK_COL_INDICES 常量（55 列，统一管理）
- [x] T2.2 cpu_air.rs：使用 RANGE_CHECK_COL_INDICES 扩展 RangeCheck 约束覆盖（24→55 列）
- [x] T2.3 trace_native.rs：RANGE_CHECK_LIMB_COLS 统一使用 RANGE_CHECK_COL_INDICES（gen_range_check_air_trace 统计 55 列）
- [x] T2.4 prover.rs：gen_cpu_full_interaction_trace / gen_cpu_range_only_interaction_trace 统一使用 RANGE_CHECK_COL_INDICES
- [x] T2.5 prover.rs：修复 verify_cpu_mem_range_proof 中硬编码的 interaction_log_sizes（108→动态计算 232）
- [x] T2.6 正向 roundtrip：3 组件 prove/verify 通过（SW+LW + MUL 指令）
- [x] T2.7 A8 soundness 反例测试：篡改 MulLow[0]=256 → prove 失败（logup 不平衡）

## Phase 3：A6（指令字解码，大工程）✅

- [x] T3.1 column_layout_v2.rs：新增 InstrWord(4) + ImmField(4) + 解码位分解列（32 列，col 150-181，NUM_COLUMNS=182）
- [x] T3.2 cpu_air.rs：新增 opcode/funct3/funct7 → indicator 解码约束（位分解 + binality + 解码约束）
- [x] T3.3 trace_native.rs：填充 InstrWord/ImmField（step_to_m31_row + fill_a6_instr_columns 公共函数）
- [x] T3.4 反例测试：indicator 与 opcode/funct3/funct7 不匹配 → prove 失败（3 个反例 + 1 个正例回归）

## Phase 4：A1 + A4 + A5（依赖 A6）✅

- [x] T4.1 cpu_air.rs：新增 HelperA = rs1/pc + ImmField 加法约束（A1，复用 ImmField）
  - Load/Store/JALR：HelperA = ValueB + ImmField（16-bit carry 加法）
  - JAL/AUIPC/Branch taken：HelperA = Pc + ImmField（16-bit carry 加法）
  - LUI：HelperA = ImmField（直接 limb 等式）
  - JALR 低 16 位：binality(x) 隐式推导 bit0（无需额外 bit0 witness）
- [x] T4.2 cpu_air.rs：新增 JALR & !1 约束（A4）
  - HelperA[0] = 2 * HelperA_half（偶数约束，HelperA_half ∈ [0,127] RangeCheck）
  - column_layout_v2.rs：新增 COL_HELPER_A_CARRY_BASE(182) + COL_HELPER_A_HALF(184)，NUM_COLUMNS=185
  - trace_native.rs：新增 fill_a1_a4_helper_columns + compute_carry_16bit 函数
  - prover.rs：RANGE_CHECK_COLS 从 63→64 列，interaction_log_sizes 动态计算 268
- [x] T4.3 A5 由 Phase 2 RangeCheck 覆盖（carry_lo 81-87 已在 RANGE_CHECK_COL_INDICES）
- [x] T4.4 反例测试：HelperA 伪造 → prove 失败（7 个测试：4 反例 + 3 正例）
  - test_a1_jalr_helper_a_forgery_soundness（JALR HelperA 伪造，A1 捕获）
  - test_a4_jalr_helper_a_half_forgery_soundness（HelperA_half 伪造，A4 捕获）
  - test_a4_jalr_odd_helper_a_soundness（HelperA[0] 奇数，A4 捕获）
  - test_a1_jal_helper_a_forgery_soundness（JAL HelperA 伪造，A1 捕获）
  - test_a1_a4_jalr_roundtrip（JALR 正例）
  - test_a1_jal_roundtrip（JAL 正例）
  - test_a1_lui_roundtrip（LUI 正例）

## 全局验证

- [x] T9.1 cargo test 全量通过（654 passed; 0 failed）
- [x] T9.2 列无重叠 + NUM_COLUMNS 一致（185 列 v3.9）
- [x] T9.3 max_constraint_log_degree_bound = log_size + 1（CPU AIR + Memory AIR 均保持）
- [x] T9.4 Phase 1-4 反例测试证明 soundness（A1/A2/A3/A4/A6/A8 共 12+ 反例测试）
