# 预编译电路默认切换为完整模式实施计划

> **Phase**：Phase 10 收尾（SubTask 10.2.x / 10.3.x / 10.4.x 完成）
> **依赖**：所有预编译完整模式 `run_full()` / `build_full_ccs()` 已实现
> **spec 参考**：`.trae/specs/build-hypernova-zkvm/tasks.md` L295-307

## 摘要

将 9 个预编译电路的 `new()` 默认从 MVP 模式切换为完整模式，新增 `new_mvp()` 保留 MVP 入口。修复 ECDSA / Ed25519 / BN254 Pairing 三个电路的完整模式 trait 方法（当前为 stub）。更新所有受影响的测试。

## 当前状态分析

### 各预编译电路完整模式 trait 方法接入状态

| 电路            | `run_full()` 实现      | `num_variables()`     | `build_ccs()`           | `assign_witness()`           | 切换难度    |
| ------------- | -------------------- | --------------------- | ----------------------- | ---------------------------- | ------- |
| Poseidon      | ✅ `build_full_ccs()` | ✅ 硬编码 439             | ✅ 调用 `build_full_ccs()` | ✅ 调用 `assign_full_witness()` | 低       |
| SHA-256       | ✅ `run_full()`       | ⚠️ 调用 `run_full()`（慢） | ⚠️ 调用 `run_full()`      | ⚠️ 调用 `run_full()`           | 中（需硬编码） |
| ECDSA         | ✅ `run_full()`       | ❌ 返回 0                | ❌ 返回空 CCS               | ❌ 返回 Err                     | 高（需修复）  |
| Keccak256     | ✅ `run_full()`       | ⚠️ 调用 `run_full()`（慢） | ⚠️ 调用 `run_full()`      | ⚠️ 调用 `run_full()`           | 中（需硬编码） |
| Modexp        | ✅ `run_full()`       | ✅ 调用 `run_full()`     | ✅ 调用 `run_full()`       | ✅ 调用 `run_full()`            | 低       |
| MerkleVerify  | ✅ `run_full()`       | ✅ 公式计算                | ✅ 调用 `run_full()`       | ✅ 调用 `run_full()`            | 低       |
| Ed25519       | ✅ `run_full()`       | ❌ 返回 0                | ❌ 返回空 CCS               | ❌ 返回 Err                     | 高（需修复）  |
| BN254 Pairing | ✅ `run_full()`       | ❌ 返回 0                | ❌ 返回空 CCS               | ❌ 待查                         | 高（需修复）  |
| ZkShuffle     | ✅ `build_circuit()`  | ✅ 公式估算                | ✅ 调用 `build_circuit()`  | ✅ 调用 `build_circuit()`       | 低       |

### 完整模式参数与 gas 对照

| 电路            | `new()` 当前模式  | `new()` 目标模式       | MVP gas     | Full gas     |
| ------------- | ------------- | ------------------ | ----------- | ------------ |
| Poseidon      | MVP (5 vars)  | Full (439 vars)    | 200         | 12\_800      |
| SHA-256       | MVP (6 vars)  | Full (\~170K vars) | 25\_000     | 25\_000      |
| ECDSA         | MVP (6 vars)  | Full (256-bit)     | 100\_000    | 19\_375\_600 |
| Keccak256     | MVP           | Full (24-round)    | 10\_000     | 240\_000     |
| Modexp        | MVP (0 bits)  | Full (32-bit)      | 50\_000     | 69\_200      |
| MerkleVerify  | MVP (depth=1) | Full (depth=1)     | 100         | 100          |
| Ed25519       | MVP (6 vars)  | Full (252-bit)     | 50\_000     | 2\_066\_000  |
| BN254 Pairing | MVP (4 vars)  | Full               | 30\_000     | 80\_000      |
| ZkShuffle     | Light         | Full (双向)          | 1\_780\_000 | 3\_540\_000  |

### 受影响的测试文件

1. `poker_zkvm/src/precompiles/mod.rs` — `test_phase10_registry_full`、`test_phase10_all_implement_both_traits`、`test_phase10_gas_costs_reasonable`、`test_phase10_real_circuits_ccs_closed_loop`
2. `poker_zkvm/src/constraints/syscall_circuit.rs` — `make_registry()` 及 3 个 dispatch 测试
3. 各预编译模块内 `#[cfg(test)] mod tests` — MVP 测试使用 `new()`

## 提议变更

### Task 1：Poseidon — 切换 `new()` 为完整模式

**文件**：`poker_zkvm/src/precompiles/poseidon.rs`

**变更**：

1. `new()`：`full_mode: false` → `full_mode: true`
2. 新增 `new_mvp()` 方法：返回 `full_mode: false`（原 `new()` 逻辑）
3. 更新文档注释：`new()` 说明改为"完整 64 轮 permutation 模式"
4. MVP 测试（`test_poseidon_mvp_*`）：`PoseidonCircuit::new()` → `PoseidonCircuit::new_mvp()`

### Task 2：SHA-256 — 切换 `new()` 为完整模式 + 硬编码变量数

**文件**：`poker_zkvm/src/precompiles/sha256.rs`

**变更**：

1. `new()`：`full_mode: false` → `full_mode: true`
2. 新增 `new_mvp()` 方法
3. 新增 `FULL_MODE_NUM_VARS: usize` 常量（值通过运行 `run_full()` 一次获取并硬编码，避免每次调用 `num_variables()` 都构建 CCS）
4. `num_variables()` 完整模式分支：`self.run_full(&dummy).unwrap().0.num_vars` → `FULL_MODE_NUM_VARS`
5. MVP 测试：`Sha256Circuit::new()` → `Sha256Circuit::new_mvp()`

### Task 3：ECDSA — 修复完整模式 trait 方法 + 切换 `new()`

**文件**：`poker_zkvm/src/precompiles/ecdsa.rs`

**变更**：

1. `new()`：`full_mode: false, scalar_num_bits: 0` → `full_mode: true, scalar_num_bits: 256`
2. 新增 `new_mvp()` 方法
3. 修复 `num_variables()` 完整模式分支：

   ```rust
   if self.full_mode {
       let dummy = vec![Fr::zero(); 24];
       self.run_full(&dummy).expect("dummy run_full should succeed").0.num_vars
   } else { 6 }
   ```
4. 修复 `build_ccs()` 完整模式分支：

   ```rust
   if self.full_mode {
       let dummy = vec![Fr::zero(); 24];
       self.run_full(&dummy).expect("dummy run_full should succeed").0
   } else { /* 现有 MVP 代码 */ }
   ```
5. 修复 `assign_witness()` 完整模式分支：

   ```rust
   if self.full_mode {
       Ok(self.run_full(inputs)?.1)
   } else { /* 现有 MVP 代码 */ }
   ```
6. MVP 测试：`EcdsaVerifyCircuit::new()` → `EcdsaVerifyCircuit::new_mvp()`

### Task 4：Keccak256 — 切换 `new()` 为完整模式 + 硬编码变量数

**文件**：`poker_zkvm/src/precompiles/keccak256.rs`

**变更**：

1. `new()`：`full_mode: false` → `full_mode: true`
2. 新增 `new_mvp()` 方法
3. 新增 `FULL_MODE_NUM_VARS: usize` 常量（硬编码，避免每次调用 `num_variables()` 都构建 24 轮 CCS）
4. `num_variables()` 完整模式分支：返回 `FULL_MODE_NUM_VARS` 而非调用 `run_full()`
5. MVP 测试：`Keccak256Circuit::new()` → `Keccak256Circuit::new_mvp()`

### Task 5：Modexp — 切换 `new()` 为完整模式

**文件**：`poker_zkvm/src/precompiles/modexp.rs`

**变更**：

1. `new()`：`num_bits: 0, full_mode: false` → `num_bits: 32, full_mode: true`（32-bit 为合理默认）
2. 新增 `new_mvp()` 方法：返回 `num_bits: 0, full_mode: false`
3. MVP 测试：`ModexpCircuit::new()` → `ModexpCircuit::new_mvp()`

### Task 6：MerkleVerify — 切换 `new()` 为完整模式

**文件**：`poker_zkvm/src/precompiles/merkle_verify.rs`

**变更**：

1. `new()`：`depth: 1, full_mode: false` → `depth: 1, full_mode: true`（depth=1 保持，但启用完整路径验证逻辑）
2. 新增 `new_mvp()` 方法
3. MVP 测试：`MerkleVerifyCircuit::new()` → `MerkleVerifyCircuit::new_mvp()`

### Task 7：Ed25519 — 修复完整模式 trait 方法 + 切换 `new()`

**文件**：`poker_zkvm/src/precompiles/ed25519.rs`

**变更**：

1. `new()`：`full_mode: false, scalar_num_bits: 0` → `full_mode: true, scalar_num_bits: 252`
2. 新增 `new_mvp()` 方法
3. 修复 `num_variables()` 完整模式分支（同 ECDSA 模式，调用 `run_full()`）
4. 修复 `build_ccs()` 完整模式分支
5. 修复 `assign_witness()` 完整模式分支
6. MVP 测试：`Ed25519VerifyCircuit::new()` → `Ed25519VerifyCircuit::new_mvp()`

### Task 8：BN254 Pairing — 修复完整模式 trait 方法 + 切换 `new()`

**文件**：`poker_zkvm/src/precompiles/bn254_pairing.rs`

**变更**：

1. `new()`：`full_mode: false` → `full_mode: true`
2. 新增 `new_mvp()` 方法
3. 修复 `num_variables()` 完整模式分支（调用 `run_full()`）
4. 修复 `build_ccs()` 完整模式分支
5. 修复 `assign_witness()` 完整模式分支
6. MVP 测试：`Bn254PairingCircuit::new()` → `Bn254PairingCircuit::new_mvp()`

### Task 9：ZkShuffle — 切换 `new()` 为完整模式

**文件**：`poker_zkvm/src/precompiles/zk_shuffle.rs`

**变更**：

1. `new()`：`full_mode: false` → `full_mode: true`（从 Light 切换到 Full 双向 on-curve）
2. `new_light()` 保留（等同原 `new()` 逻辑）
3. `Default` impl 跟随 `new()` 变更
4. 更新文档注释
5. Light 模式测试：`ZkShuffleCcsCircuit::new()` → `ZkShuffleCcsCircuit::new_light()`
6. 集成测试 `tests/zk_shuffle_integration.rs`：`with_deck_size(4, false)` 保持不变（显式 Light）

### Task 10：更新 `precompiles/mod.rs` 测试

**文件**：`poker_zkvm/src/precompiles/mod.rs`

**变更**：

#### 10.1 `test_phase10_registry_full`

* 所有 `register(Box::new(XxxCircuit::new()))` → `register(Box::new(XxxCircuit::new_mvp()))`

* **理由**：此测试验证注册表机制（名称查找、gas、变量数），非电路数学正确性。MVP 模式快速且输入简单。

* 断言保持 MVP 值不变（`num_variables()==5/6/4`、`gas_cost()==200/25000/100000/...`）

#### 10.2 新增 `test_phase10_registry_full_mode_smoke`

* 所有 `register(Box::new(XxxCircuit::new()))` 使用完整模式

* 仅断言 `name()` 和 `gas_cost()`（不调用 `num_variables()` / `build_ccs()`，避免慢测试）

* 验证完整模式电路可注册且 gas 正确

#### 10.3 `test_phase10_all_implement_both_traits`

* `XxxCircuit::new()` 保持（完整模式）— 仅创建结构体检查 trait dispatch，不调用方法，无性能问题

#### 10.4 `test_phase10_gas_costs_reasonable`

* `register(Box::new(XxxCircuit::new()))` → `register(Box::new(XxxCircuit::new_mvp()))`

* 保持 MVP gas 范围断言不变

#### 10.5 `test_phase10_real_circuits_ccs_closed_loop`

* `XxxCircuit::new()` → `XxxCircuit::new_mvp()`

* **理由**：此测试使用 MVP 格式输入（Poseidon 1 输入、SHA-256 3 输入、ECDSA 3 输入），完整模式需要不同输入格式。保持 MVP 输入最快。

### Task 11：更新 `syscall_circuit.rs` 测试

**文件**：`poker_zkvm/src/constraints/syscall_circuit.rs`

**变更**：

1. `make_registry()`：`PoseidonCircuit::new()` / `Sha256Circuit::new()` / `EcdsaVerifyCircuit::new()` → 各自 `new_mvp()`
2. **理由**（用户确认）：dispatch 测试验证分派逻辑而非电路数学，MVP 输入格式简单且快速
3. 所有 dispatch 测试（`test_dispatch_poseidon_two_instances` 等）输入保持 MVP 格式不变

### Task 12：更新 tasks.md

**文件**：`.trae/specs/build-hypernova-zkvm/tasks.md`

**变更**：

* SubTask 10.2.1 / 10.2.2 / 10.2.3：`[ ]` → `[x]`，移除"延至 Phase 12+"

* SubTask 10.3.1 / 10.3.2：`[ ]` → `[x]`，移除"延至 Phase 12+"

* SubTask 10.4.1 / 10.4.2 / 10.4.3 / 10.4.4：`[ ]` → `[x]`，移除"延至 Phase 12+"

### Task 13：全量验证

1. `cargo build -p poker_zkvm` — 编译通过
2. `cargo test -p poker_zkvm` — 全部测试通过
3. `cargo clippy -p poker_zkvm -- -D warnings` — 0 warnings
4. `cargo fmt --all --check` — 0 diffs
5. `cargo build -p poker_l1` — 编译通过（验证无跨 crate 影响）
6. `cargo test -p poker_l1` — 全部测试通过（回归）

## 假设与决策

### 决策 1：dispatch 测试使用 `new_mvp()`（用户确认）

* **选择**：`syscall_circuit.rs` 的 `make_registry()` 使用 `new_mvp()`

* **理由**：dispatch 测试验证分派逻辑，非电路数学；MVP 输入格式简单且快速

### 决策 2：registry 测试使用 `new_mvp()` + 新增 full-mode smoke 测试

* **选择**：`test_phase10_registry_full` 等使用 `new_mvp()`，新增 `test_phase10_registry_full_mode_smoke` 仅检查 `name()` + `gas_cost()`

* **理由**：完整模式 `num_variables()` / `build_ccs()` 对 ECDSA（256-bit）/ Ed25519（252-bit）/ SHA-256（\~170K vars）很慢；MVP 模式验证注册表机制足够

### 决策 3：ECDSA / Ed25519 / BN254 完整模式 trait 方法修复

* **选择**：修复 `num_variables()` / `build_ccs()` / `assign_witness()` 调用 `run_full()`

* **理由**：当前 stub 返回 0 / 空 CCS / Err，切换默认后需要可用的 trait 方法

### 决策 4：SHA-256 / Keccak256 硬编码 `FULL_MODE_NUM_VARS`

* **选择**：新增常量硬编码完整模式变量数，`num_variables()` 直接返回

* **理由**：避免每次调用 `num_variables()` 都构建 \~170K / \~192K 变量的 CCS

### 决策 5：Modexp 默认 32-bit

* **选择**：`new()` → `num_bits: 32, full_mode: true`

* **理由**：32-bit 是合理的默认指数位数（覆盖大多数模幂场景），不会过大

### 决策 6：ZkShuffle `new()` 切换为 Full（双向 on-curve）

* **选择**：`new()` → `full_mode: true`

* **理由**：用户要求切换默认为完整模式；`new_light()` 保留 Light 入口

## 验证步骤

1. **编译验证**：`cargo build -p poker_zkvm && cargo build -p poker_l1`
2. **单元测试**：`cargo test -p poker_zkvm`
3. **回归测试**：`cargo test -p poker_l1`
4. **Clippy**：`cargo clippy -p poker_zkvm -- -D warnings && cargo clippy -p poker_l1 -- -D warnings`
5. **Fmt**：`cargo fmt --all --check`

## 实施顺序

1. Task 1-2：Poseidon + SHA-256（完整模式 trait 已接入，仅需切换默认 + 硬编码）
2. Task 3：ECDSA（修复 trait stub + 切换默认）
3. Task 4-6：Keccak256 + Modexp + MerkleVerify
4. Task 7-8：Ed25519 + BN254 Pairing（修复 trait stub + 切换默认）
5. Task 9：ZkShuffle
6. Task 10-11：更新 mod.rs + syscall\_circuit.rs 测试
7. Task 12：更新 tasks.md
8. Task 13：全量验证

