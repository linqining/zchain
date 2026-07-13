# Prover 性能优化计划

## Context

Spartan CCS 注册表迁移已完成（全部测试通过）。当前 prover 性能极慢：
- `e2e_fibonacci` N=100 测试运行 49+ 分钟 CPU 时间仍未完成
- 根因 1：e2e 测试使用 `batch_size: 3`（生产默认 256），fibonacci N=100 → 609 步 / 3 = 203 batches → 202 fold steps
- 根因 2：`rayon` 在 `poker_zkvm/Cargo.toml` 中声明但 `src/` 下零使用
- 根因 3：sumcheck 热循环全顺序执行

## 实际实现与计划差异

### Phase 1 差异

**计划**：`default_ccs_registry()` 调用 `generate_test_proof_with_config(ProverConfig::default())` 生成 batch_size=256 的完整 proof，然后反序列化提取 CCS。

**实际**：发现 batch_size=256 的 HYPN proof 超过 512KB（`MAX_PROOF_TOTAL_SIZE`），触发 Spartan 压缩 → SPRT magic → `deserialize_proof` 失败。

**修复**：新增 `generate_ccs_for_config(config)` 函数，直接执行 ELF → pad trace → compile CCS（跳过 fold_loop/serialize），避免序列化问题。`default_ccs_registry()` 改用此函数。

### Phase 2 差异

**计划**：8 项并行化（2a-2h）。

**实际**：实现 7 项（2a-2e + inner h_sum + 2g-2h）。跳过 2f（c_table 并行化），因为 c_table 是 scatter 操作（不同 entry 可能写入同一 col），有写冲突，不是 embarrassingly parallel。

## Phase 1: batch_size 提升 ✅

### 改动文件
- `poker_zkvm/src/prover/mod.rs` — 新增 `build_test_elf_bytes()` / `generate_test_proof_with_config()` / `generate_ccs_for_config()`；重构 `default_ccs_registry()` 返回 batch_size=3 + batch_size=256 两种 CCS
- `poker_zkvm/tests/e2e_fibonacci.rs` — batch_size 3→256
- `poker_zkvm/tests/e2e_sha256_chain.rs` — batch_size 3→256
- `poker_zkvm/tests/e2e_poker_hand_eval.rs` — batch_size 3→256
- `poker_zkvm/tests/common/mod.rs` — 注释更新

### 验证结果
- lib 测试：1069 通过（含 5 个之前失败的 Spartan verifier 测试）
- soundness tests：13 通过（0.59s）
- e2e_fibonacci：7 通过（303s，含 N=50 和 N=100）
- e2e_sha256_chain：5 通过（51s）
- e2e_poker_hand_eval：5 通过（51s）
- poker_l1：49 通过
- clippy：0 warnings
- fmt：无 diff

### 性能提升
- e2e_fibonacci N=100：49+ 分钟（未完成）→ ~5 分钟（含全部 7 个测试）

## Phase 2: rayon 并行化 ✅

### 改动文件
- `poker_zkvm/src/fold/sumcheck.rs` — 6 项并行化
  - `bind_var`（阈值 1024）
  - `compute_eq_table`（阈值 1024）
  - `compute_vjp_tables`（阈值 4，按矩阵数）
  - `actual_u_prime` 计算（阈值 1024）
  - 外层 sumcheck 行循环（阈值 1024）
  - 内层 sumcheck h_sum 循环（阈值 1024）
- `poker_zkvm/src/pcs/ipa.rs` — 2 项并行化
  - `inner_product`（阈值 1024）
  - `open()` 向量折叠 a/b_curr/g（阈值 1024）

### 设计原则
- 所有并行化使用阈值检查（`PARALLEL_THRESHOLD = 1024`），小数据走顺序路径
- 仅并行化独立元素级计算（map/reduce/collect），不触碰 transcript 操作
- Fr 有限域加法满足交换律+结合律，reduce 顺序无关

### 跳过的项
- 2f `c_table` 并行化 — scatter 操作有写冲突，不是 embarrassingly parallel

### 验证结果
- 编译通过
- clippy：0 warnings
- fmt：无 diff
- 测试待运行
