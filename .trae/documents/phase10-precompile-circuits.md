# Phase 10 — 预编译电路（Precompile Circuits）实施计划

## Context

Phase 10 实现预编译电路层，为 ZKVM syscall（Poseidon / SHA-256 / ECDSA）提供 CCS 约束结构生成器，并将 `ZkShuffleCcsCircuit` 从 poker_l1 迁移到 poker_zkvm。

**当前状态**（探索后确认）：
- 51 个 precompile 测试全部通过，`cargo build` 干净
- Task 10.1（registry + traits）✅ 完整实现
- Task 10.2/10.3/10.4 为 **MVP 实现**（D1 已批准）— 仅核心约束结构：
  - Poseidon: S-box `x^5` 单 round（7 矩阵 / 6 subsets / 3 行 / 5 变量）
  - SHA-256: Ch 函数单 op（7 矩阵 / 6 subsets / 2 行 / 6 变量）
  - ECDSA: double-and-add 单步（7 矩阵 / 7 subsets / 3 行 / 6 变量）
- Task 10.5 为 **stub**（D6 已批准）— 类型定义迁移完成，`to_ccs_instance` 返回 `Err("Phase 11 pending")`

**关键发现 — SubTask 10.5.2/10.5.3 阻塞**：
- 旧 `poker_l1::CcsCircuit` trait 签名：`to_instance(witness: &[u8], public_inputs: &[u8], state_delta: &[u8], ack_step_hash: Hash) -> Result<CcsInstance, PokerL1Error>`
- 新 `poker_zkvm::precompiles::CcsCircuit` trait 签名：`to_ccs_instance(witness: &[Fr], public_inputs: &[Fr]) -> Result<CcsInstance, ZkvmError>`
- 签名不兼容 → re-export 会导致 poker_l1 编译失败（`phase5a_integration.rs` + `task36_zk_verifier.rs` bench 调用旧 `to_instance`）
- **结论**：10.5.2/10.5.3 须 Phase 11 BREAKING 迁移，非 Phase 10 范围（与 D6 一致）

**用户决策**：保留 MVP 电路，对齐文档，完整算法实现延至 Phase 12+。

## 实施步骤

### Step 1 — 更新 tasks.md Phase 10（L292-311）

将 Phase 10 任务项标记为实际状态：
- Task 10.1: `[x]`（完整实现）
- Task 10.2: `[x]` + 标注 "(MVP: S-box x^5 单 round)"
  - 10.2.1 (完整 permutation + MDS): `[ ]` + "**延至 Phase 12+**"
  - 10.2.2 (约束数 ~200/round): `[ ]` + "**延至 Phase 12+**（MVP ~6 constraints/S-box）"
  - 10.2.3 (host 一致性): `[ ]` + "**延至 Phase 12+**（MVP 仅 ark_bn254::Fr x^5）"
- Task 10.3: `[x]` + 标注 "(MVP: Ch 函数单 op)"
  - 10.3.1 (完整 round + schedule): `[ ]` + "**延至 Phase 12+**"
  - 10.3.2 (~25k/block + lookup): `[ ]` + "**延至 Phase 12+**"
  - 10.3.3 (sha2 一致性): `[x]`（host sha2 已验证）
- Task 10.4: `[x]` + 标注 "(MVP: double-and-add 单步)"
  - 10.4.1 (完整 curve ops): `[ ]` + "**延至 Phase 12+**"
  - 10.4.2 (verify equation): `[ ]` + "**延至 Phase 12+**"
  - 10.4.3 (~110k 约束): `[ ]` + "**延至 Phase 12+**（MVP 单步）"
  - 10.4.4 (msg/sig/pubkey 篡改): `[ ]` + "**延至 Phase 12+**（MVP 已测 R_new/bit_P/bit 非二进制）"
- Task 10.5: `[x]` + 标注 "(stub，D6 批准)"
  - 10.5.1 (类型 + trait stub): `[x]`
  - 10.5.2 (re-export): `[ ]` + "**延至 Phase 11**（trait 签名不兼容，须 BREAKING 迁移）"
  - 10.5.3 (测试路径更新): `[ ]` + "**延至 Phase 11**"

### Step 2 — 更新 checklist.md Phase 10（L281-293）

同步标记：
- `[x]` 预编译电路注册表实现
- `[ ]` Poseidon ~200/round — **延至 Phase 12+**
- `[ ]` Poseidon host 一致性 — **延至 Phase 12+**
- `[ ]` SHA-256 ~25k/block + lookup — **延至 Phase 12+**
- `[x]` SHA-256 sha2 一致性
- `[ ]` ECDSA ~110k 约束 — **延至 Phase 12+**
- `[ ]` ECDSA 正例签名 — **延至 Phase 12+**
- `[ ]` ECDSA msg/sig/pubkey soundness — **延至 Phase 12+**
- `[x]` ZkShuffleCcsCircuit 迁移到 poker_zkvm（stub）
- `[ ]` poker_l1 re-export — **延至 Phase 11**
- `[ ]` 测试路径更新 — **延至 Phase 11**

### Step 3 — 修正 alternatives.md 小误（L318）

`alternatives.md` L318 描述 Poseidon witness 为 "x/x2/x3/x4/x5"，实际代码为 `[1, x, x2, x4, x5]`（无 x3，有常数 1）。修正为准确描述。

### Step 4 — 创建 Phase 10 文档

创建 `/Users/mac/projects/zchain/.trae/documents/phase10-precompile-circuits.md`：
- 实现摘要（4 个电路 + registry）
- MVP 策略与延后说明
- 测试覆盖（51 tests 明细）
- 验证清单
- 与 Phase 11/12+ 的衔接

### Step 5 — 验证

- `cargo test --lib precompiles`（poker_zkvm）— 确认 51 tests 通过
- `cargo build`（poker_zkvm）— 确认编译干净
- `cargo build`（poker_l1）— 确认旧 deprecated 类型仍可编译（`#[allow(deprecated)]` 测试通过）

## 关键文件

| 文件 | 操作 |
|------|------|
| `.trae/specs/build-hypernova-zkvm/tasks.md` L292-311 | 编辑 — 标记实际状态 |
| `.trae/specs/build-hypernova-zkvm/checklist.md` L281-293 | 编辑 — 标记实际状态 |
| `poker_zkvm/docs/alternatives.md` L318 | 编辑 — 修正 witness 描述 |
| `.trae/documents/phase10-precompile-circuits.md` | 创建 — Phase 10 文档 |

## 不变项（无需修改）

- `poker_zkvm/src/precompiles/mod.rs` — Task 10.1 完整，9 tests
- `poker_zkvm/src/precompiles/poseidon.rs` — MVP，12 tests
- `poker_zkvm/src/precompiles/sha256.rs` — MVP，15 tests
- `poker_zkvm/src/precompiles/ecdsa.rs` — MVP，14 tests
- `poker_zkvm/src/precompiles/zk_shuffle.rs` — stub，5 tests
- `poker_l1/src/offline/ccs.rs` — 旧类型已标 `#[deprecated]`，Phase 11 处理 re-export

## 验证方法

```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo test --lib precompiles 2>&1 | tail -5
cd /Users/mac/projects/zchain/poker_zkvm && cargo build 2>&1 | tail -3
cd /Users/mac/projects/zchain/poker_l1 && cargo build 2>&1 | tail -3
```

## 与后续 Phase 衔接

- **Phase 11**：poker_l1 BREAKING 迁移 — re-export `CcsCircuit` trait + `ZkShuffleCcsCircuit`，旧调用方迁移到 Fr-based 新类型，`LegacyCcsInstanceAdapter` 诚实失败
- **Phase 12+**：完整预编译电路实现 — Poseidon 64-round permutation + MDS、SHA-256 64-round compression + lookup、ECDSA 256-step scalar mult + verify equation（~110k 约束）

## 完成摘要

### 已完成（Phase 10 范围内）

| 项 | 状态 | 说明 |
|----|------|------|
| Task 10.1 — 预编译电路注册表 | ✅ 完整 | `PrecompileCircuit` trait + `PrecompileRegistry` + `CcsCircuit` trait + 9 integration tests |
| Task 10.2 — Poseidon MVP | ✅ MVP | S-box `x^5` 单 round（7 矩阵 / 6 subsets / 3 行 / 5 变量），12 tests |
| Task 10.3 — SHA-256 MVP | ✅ MVP | Ch 函数单 op（7 矩阵 / 6 subsets / 2 行 / 6 变量），15 tests |
| Task 10.4 — ECDSA MVP | ✅ MVP | double-and-add 单步（7 矩阵 / 7 subsets / 3 行 / 6 变量），14 tests |
| Task 10.5 — ZkShuffle stub | ✅ stub | 类型定义迁移（D6 批准），5 tests |

### 延后项

| 项 | 延至 | 原因 |
|----|------|------|
| 10.2.1-10.2.3 完整 permutation + MDS + host 一致性 | Phase 12+ | MVP 验证 CCS 闭环即可，完整电路在 Hypernova 集成时实现 |
| 10.3.1-10.3.2 完整 64-round compression + lookup | Phase 12+ | lookup 优化为研究级，需 LogUp 协议 |
| 10.4.1-10.4.4 完整 256-step 标量乘 + verify equation | Phase 12+ | ~110k 约束规模大，跨域（BN254 Fr vs secp256k1 scalar） |
| 10.5.2 poker_l1 re-export | Phase 11 | 新旧 `CcsCircuit` trait 签名不兼容（u8-based vs Fr-based），须 BREAKING 迁移 |
| 10.5.3 测试路径更新 | Phase 11 | 同 10.5.2，`phase5a_integration.rs` + `task36_zk_verifier.rs` bench 须迁移 |

### 测试覆盖（51 tests 全部通过）

- `precompiles/mod.rs` — 9 tests（registry + trait dispatch + Phase 10 integration）
- `precompiles/poseidon.rs` — 12 tests（CCS 结构 / soundness / ark_bn254::Fr 一致性 / 边界）
- `precompiles/sha256.rs` — 15 tests（CCS 结构 / soundness / bitwise Ch 一致性 / sha2 known vectors）
- `precompiles/ecdsa.rs` — 14 tests（CCS 结构 / soundness / secp256k1 一致性 / 边界）
- `precompiles/zk_shuffle.rs` — 5 tests（stub 行为 / registry / default）

### 验证结果

- `cargo test --lib precompiles`（poker_zkvm）：51 passed; 0 failed ✅
- `cargo build`（poker_zkvm）：Finished, 0 errors ✅
- `cargo build`（poker_l1）：Finished, 9 deprecation warnings（旧类型 `#[deprecated]` 预期）✅

### 文档更新

- `tasks.md` Phase 10（L292-311）— 标记实际状态（MVP 完成 + 延后说明）
- `checklist.md` Phase 10（L281-293）— 同步标记
- `alternatives.md` L318-320 — 修正 witness 变量描述 / 约束数 / 一致性声明
- `phase10-precompile-circuits.md` — 本文档（计划 + 完成摘要）
