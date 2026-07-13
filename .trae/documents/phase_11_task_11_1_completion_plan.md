# Phase 11 Task 11.1 完成计划 — Stub Fold 迁移收尾

## 摘要

Phase 11 Task 11.1 将 `poker_l1` 的 stub fold 实现（blake2b 哈希链模拟）替换为真实 Hypernova 折叠的薄包装，委托到 `poker_zkvm::fold::fold_step::fold` 与 `poker_zkvm::fold::fold_loop::fold_loop`。

前序工作已完成 Steps 1-5、8：
- `poker_l1/src/offline/hypernova.rs` — `map_zkvm_error` 改为 `pub(crate)`
- `poker_l1/src/offline/ccs.rs` — 添加 re-export、标记 deprecated、添加 `LegacyCcsInstanceAdapter`、添加 `fold_step_real`/`fold_loop_real` 包装、替换 8 个旧单元测试为 4 个 deprecated 验证测试
- 已验证：`cargo build -p poker_l1` 成功，`cargo test -p poker_l1 --lib offline::ccs` 通过 4/4

本计划完成剩余 Steps 6（验证）、7（基准迁移）、9（完整验证）。

## 当前状态分析

### Step 6（phase5a_integration.rs）— 编辑已应用，待验证

`/Users/mac/projects/zchain/poker_l1/tests/phase5a_integration.rs` 的 SubTask 42.5（L814-1137）已重写，使用真实 Hypernova fold API：
- 导入 `fold_step_real`、`fold_loop_real` 及 `poker_zkvm` 类型
- 添加测试辅助函数：`zkvm_f`、`zkvm_neg_f`、`stub_commitment`、`commit_witness`、`make_linear_ccs`、`make_ipa_pcs`
- 8 个迁移测试：
  1. `subtask_42_5_fold_step_single` — 线性 CCS 单步 fold
  2. `subtask_42_5_fold_step_multi_increments_count` — 链式两步 fold
  3. `subtask_42_5_fold_loop_multi_step` — 3 个 CCCCS 实例 fold_loop
  4. `subtask_42_5_fold_loop_empty_rejected` — 空 CCCCS 列表（单实例路径）
  5. `subtask_42_5_fold_loop_exceeds_max_steps_rejected` — O15 上限拒绝
  6. `subtask_42_5_zk_shuffle_ccs_circuit_trait` — `PrecompileCircuit` trait 验证
  7. `subtask_42_5_fold_loop_produces_valid_public_io_for_checkin` — `generate_test_proof` 端到端
  8. `subtask_42_5_ack_chain_inclusion_proof_with_fold_results` — ack_chain 包含证明

**API 验证结果**（已通过 Grep/Read 确认所有 API 表面存在且签名匹配）：
- `Ccs::new(num_vars, matrices, subsets, coeffs)` — `poker_zkvm/src/ccs/mod.rs:234` ✓
- `Ccs::to_lcccs(&self, z, r_x_l, x_l)` — `poker_zkvm/src/fold/ccs.rs:62` ✓
- `Ccs::to_cccs(&self, z, x_c, witness_commitment_c)` — `poker_zkvm/src/fold/ccs.rs:95` ✓
- `Ccs::ccs_commitment(&self)` — `poker_zkvm/src/fold/ccs.rs:168` ✓
- `Lcccs::satisfied(&self)` — `poker_zkvm/src/fold/lcccs.rs:119` ✓
- `PrecompileCircuit` trait（`name`/`num_variables`/`gas_cost`）— `poker_zkvm/src/precompiles/mod.rs:62-80` ✓
- `ZkShuffleCcsCircuit::new()` Light 模式，`gas_cost() = 1_780_000` — `poker_zkvm/src/precompiles/zk_shuffle.rs:68, 418-424` ✓
- `ZkvmField::to_canonical_bytes()` — `poker_zkvm/src/field.rs:66` ✓
- `poker_zkvm::prover::generate_test_proof() -> (Vec<u8>, ZkPublicIo)` — `poker_zkvm/src/prover/mod.rs:952` ✓
- `ZkPublicIo` 字段 `initial_commitment: ZkvmFr`、`final_commitment: ZkvmFr`、`input: Vec<u8>`、`output: Vec<u8>` — `poker_zkvm/src/prover/mod.rs:129-139` ✓

### Step 7（task36_zk_verifier.rs）— 未迁移

`/Users/mac/projects/zchain/poker_l1/benches/task36_zk_verifier.rs` 仍使用旧 deprecated API：
- L20: `use poker_l1::offline::ccs::{fold_loop, fold_step, CcsInstance};`
- L39-47: `make_ccs_instance` 返回旧 `CcsInstance`
- L50-52: `make_ccs_instances` 返回 `Vec<CcsInstance>`
- L106-147: `bench_fold_step_single` 调用旧 `fold_step`（现已返回 Err — 运行时 panic！）
- L152-185: `bench_fold_loop` 调用旧 `fold_loop`（现已返回 Err — 运行时 panic！）

其他基准（Groth16/IPA/zk_verify syscall/fiat_shamir）不依赖 fold，无需迁移。

## 提议变更

### 变更 1：验证 phase5a_integration.rs 编译与测试（Step 6）

**文件**：`/Users/mac/projects/zchain/poker_l1/tests/phase5a_integration.rs`（已编辑，仅验证）

**操作**：
1. `cargo build -p poker_l1 --tests` — 验证编译
2. `cargo test -p poker_l1 --test phase5a_integration` — 验证测试通过
3. 若编译错误或测试失败，定位并修复（优先怀疑点：`to_lcccs` 的 `r_x_l` 参数为空数组时是否被接受；线性 CCS satisfied 检查；`generate_test_proof` 与 `execute_checkin` 的 public_io 映射）

**预期结果**：8 个 SubTask 42.5 测试全部通过。

### 变更 2：迁移 task36_zk_verifier.rs 基准（Step 7）

**文件**：`/Users/mac/projects/zchain/poker_l1/benches/task36_zk_verifier.rs`

**操作**：
1. **替换导入**（L20）：
   ```rust
   // 旧
   use poker_l1::offline::ccs::{fold_loop, fold_step, CcsInstance};
   // 新
   use poker_l1::offline::ccs::{fold_loop_real, fold_step_real};
   use poker_zkvm::ccs::{Ccs, Fr as ZkvmFr, SparseMatrix};
   use poker_zkvm::fold::ccccs::Ccccs;
   use poker_zkvm::fold::lcccs::Lcccs;
   use poker_zkvm::field::ZkvmField;
   use poker_zkvm::pcs::ipa::{IpaCommitment, IpaPcs};
   use poker_zkvm::pcs::{MultilinearPoly, Pcs};
   use poker_zkvm::transcript::Transcript;
   use ark_bn254::G1Affine;
   use ark_ec::AffineRepr;
   ```

2. **替换辅助函数**（L39-52）— 用线性 CCS 辅助函数替换 `make_ccs_instance`/`make_ccs_instances`：
   ```rust
   fn zkvm_f(v: u32) -> ZkvmFr { ZkvmFr::from_u32_with_wrap(v) }
   fn zkvm_neg_f(v: u32) -> ZkvmFr { ZkvmFr::zero().sub(&zkvm_f(v)) }
   fn stub_commitment() -> IpaCommitment { IpaCommitment(G1Affine::generator()) }
   fn commit_witness(pcs: &IpaPcs, z: &[ZkvmFr]) -> IpaCommitment {
       let poly = MultilinearPoly::from_evals(z.to_vec()).expect("poly");
       pcs.commit(&poly).expect("commit")
   }
   fn make_linear_ccs() -> Ccs {
       let mut m0 = SparseMatrix::new(1, 4);
       m0.add_entry(0, 1, zkvm_f(1)).unwrap();
       let mut m1 = SparseMatrix::new(1, 4);
       m1.add_entry(0, 2, zkvm_f(1)).unwrap();
       Ccs::new(4, vec![m0, m1], vec![vec![0], vec![1]], vec![zkvm_f(1), zkvm_neg_f(1)])
           .expect("linear Ccs")
   }
   fn make_ipa_pcs() -> IpaPcs { IpaPcs::new(4).expect("IpaPcs") }
   ```

3. **迁移 `bench_fold_step_single`**（L106-147）— 用 `fold_step_real` 替换：
   ```rust
   fn bench_fold_step_single(c: &mut Criterion) {
       let mut group = c.benchmark_group("task36_3_fold_step_single");
       group.sample_size(100);

       let ccs = make_linear_ccs();
       let z_l = vec![zkvm_f(1), zkvm_f(5), zkvm_f(5), zkvm_f(0)];
       let z_c = vec![zkvm_f(1), zkvm_f(3), zkvm_f(3), zkvm_f(0)];
       let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
       let ccccs = ccs.to_cccs(&z_c, vec![], stub_commitment()).expect("to_cccs");

       group.bench_function("single_fold", |b| {
           b.iter(|| {
               let mut transcript = Transcript::new();
               let result = fold_step_real(
                   black_box(&lcccs),
                   black_box(&stub_commitment()),
                   black_box(&ccccs),
                   black_box(&mut transcript),
               ).expect("fold_step_real");
               black_box(result);
           });
       });

       group.finish();
   }
   ```
   - 移除 "首次 fold" vs "累计 fold" 区分（旧 stub 用 prev 参数区分，真实 fold 无此概念）
   - 单一基准名 `single_fold`

4. **迁移 `bench_fold_loop`**（L152-185）— 用 `fold_loop_real` 替换：
   ```rust
   fn bench_fold_loop(c: &mut Criterion) {
       let mut group = c.benchmark_group("task36_3_fold_loop");
       group.sample_size(20);

       let ccs = make_linear_ccs();
       let pcs = make_ipa_pcs();
       let ccs_commitment = ccs.ccs_commitment();

       for &steps in &[10usize, 100, 1000] {
           let z_l = vec![zkvm_f(1), zkvm_f(5), zkvm_f(5), zkvm_f(0)];
           let lcccs = ccs.to_lcccs(&z_l, &[], vec![]).expect("to_lcccs");
           let initial_cmt = commit_witness(&pcs, &z_l);

           let ccccs_instances: Vec<Ccccs> = (0..steps)
               .map(|i| {
                   let z_c = vec![zkvm_f(1), zkvm_f((i % 100) as u32 + 1), zkvm_f((i % 100) as u32 + 1), zkvm_f(0)];
                   let cmt = commit_witness(&pcs, &z_c);
                   ccs.to_cccs(&z_c, vec![], cmt).expect("to_cccs")
               })
               .collect();

           group.throughput(Throughput::Elements(steps as u64));

           group.bench_with_input(
               BenchmarkId::new("fold_loop_real", format!("steps_{}", steps)),
               &ccccs_instances,
               |b, ccccs_instances| {
                   b.iter(|| {
                       let mut transcript = Transcript::new();
                       let result = fold_loop_real(
                           black_box(&ccs),
                           black_box(lcccs.clone()),
                           black_box(initial_cmt.clone()),
                           black_box(ccccs_instances),
                           black_box(&pcs),
                           black_box(&mut transcript),
                           black_box(ccs_commitment),
                           black_box([0u8; 32]),
                           black_box(vec![vec![]]),
                       ).expect("fold_loop_real");
                       black_box(result);
                   });
               },
           );
       }

       group.finish();
   }
   ```

5. **更新文件头注释**（L1-17）— 移除 "MVP stub" / "blake2b 哈希链" 描述，改为 "真实 Hypernova fold"。

6. **移除未使用导入** — `Hash`、`ChainId` 若不再使用则移除（`make_game_id` 仍可能保留用于其他基准；需检查）。

**保留不变**：`bench_fiat_shamir_challenge`、`bench_groth16_verify`、`bench_groth16_crs_fingerprint`、`bench_ipa_verify`、`bench_zk_verify_syscall`、`bench_hypernova_verify` — 这些不依赖 fold。

### 变更 3：完整验证套件（Step 9）

**操作**（按顺序）：

1. **poker_l1 编译验证**：
   ```bash
   cargo build -p poker_l1
   cargo build -p poker_l1 --tests
   cargo build -p poker_l1 --benches
   ```
   - 预期：成功，仅 deprecated 警告（已知）

2. **poker_l1 Clippy**：
   ```bash
   cargo clippy -p poker_l1 --all-targets -- -D warnings
   ```
   - 预期：0 警告（已在前序工作修复 12 个 clippy 错误）

3. **poker_l1 格式化检查**：
   ```bash
   cargo fmt -p poker_l1 --check
   ```
   - 预期：0 diff

4. **poker_l1 单元测试**：
   ```bash
   cargo test -p poker_l1 --lib
   ```
   - 预期：全部通过

5. **poker_l1 集成测试**：
   ```bash
   cargo test -p poker_l1 --test phase5a_integration
   ```
   - 预期：全部通过（含 8 个迁移后的 SubTask 42.5 测试）

6. **poker_zkvm 回归验证**（确保 re-export 未引入循环依赖或破坏）：
   ```bash
   cargo build -p poker_zkvm
   cargo test -p poker_zkvm --lib
   ```
   - 预期：全部通过

7. **基准编译验证**（不运行，仅编译）：
   ```bash
   cargo build -p poker_l1 --benches
   ```
   - 预期：成功

## 假设与决策

### 假设
1. 前序工作（Steps 1-5、8）的编辑已正确应用且未被回滚
2. `poker_zkvm` crate 的 API 在本会话期间未发生变化
3. `phase5a_integration.rs` 的 SubTask 42.5 编辑已应用（通过 Read 确认 L814-1137 内容）

### 决策
1. **基准 `bench_fold_step_single` 简化为单一基准**：旧 stub 用 `prev` 参数区分 "首次" vs "累计"，真实 fold 无此概念。合并为单一 `single_fold` 基准。
2. **基准规模保持 10/100/1000 步**：与 O15 上限（1000）保持一致，便于对比 stub vs 真实 fold 性能。
3. **基准使用线性 CCS**：与集成测试相同的 `make_linear_ccs` 辅助函数，确保基准可运行且语义清晰。真实 ZkShuffleCcsCircuit 基准留待 Production 阶段。
4. **不迁移 `bench_fiat_shamir_challenge` 等 verifier 基准**：这些基准不依赖 fold，仍使用 stub verifier（正确行为，Production verifier 升级在后续 Phase）。
5. **`MAX_FOLD_STEP_COUNT` 导入保留**：`phase5a_integration.rs` 仍使用 `MAX_FOLD_STEP_COUNT`（L449, L552, L555, L1008-1032）。

## 验证步骤

执行顺序（严格按序）：

1. **Step 6 验证** — `cargo build -p poker_l1 --tests && cargo test -p poker_l1 --test phase5a_integration`
2. **Step 7 迁移** — 编辑 `task36_zk_verifier.rs`，然后 `cargo build -p poker_l1 --benches`
3. **Step 9 完整验证**：
   - `cargo build -p poker_l1 --all-targets`
   - `cargo clippy -p poker_l1 --all-targets -- -D warnings`
   - `cargo fmt -p poker_l1 --check`
   - `cargo test -p poker_l1 --lib`
   - `cargo test -p poker_l1 --test phase5a_integration`
   - `cargo build -p poker_zkvm && cargo test -p poker_zkvm --lib`

## 任务清单

- [ ] Step 6.1: 运行 `cargo build -p poker_l1 --tests`，修复编译错误（若有）
- [ ] Step 6.2: 运行 `cargo test -p poker_l1 --test phase5a_integration`，修复测试失败（若有）
- [ ] Step 7.1: 迁移 `task36_zk_verifier.rs` 导入与辅助函数
- [ ] Step 7.2: 迁移 `bench_fold_step_single` 为 `fold_step_real`
- [ ] Step 7.3: 迁移 `bench_fold_loop` 为 `fold_loop_real`
- [ ] Step 7.4: 更新文件头注释，移除未使用导入
- [ ] Step 7.5: `cargo build -p poker_l1 --benches` 验证编译
- [ ] Step 9.1: `cargo build -p poker_l1 --all-targets`
- [ ] Step 9.2: `cargo clippy -p poker_l1 --all-targets -- -D warnings`
- [ ] Step 9.3: `cargo fmt -p poker_l1 --check`
- [ ] Step 9.4: `cargo test -p poker_l1 --lib`
- [ ] Step 9.5: `cargo test -p poker_l1 --test phase5a_integration`
- [ ] Step 9.6: `cargo build -p poker_zkvm && cargo test -p poker_zkvm --lib`
