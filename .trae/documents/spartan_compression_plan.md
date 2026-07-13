# 预编译电路完整模式默认切换 — 收尾计划

> **Phase**：Phase 10 收尾（Tasks 10-13）
> **依赖**：Tasks 1-9 已完成（9 个预编译电路 `new()` 均已切换为完整模式，`new_mvp()` / `new_light()` 已新增）
> **参考**：`precompile_full_mode_default_plan.md`（已批准主计划）

## 摘要

完成预编译电路完整模式默认切换的最后 4 个任务：更新 `precompiles/mod.rs` 剩余 2 个测试、更新 `syscall_circuit.rs` 的 `make_registry()`、更新 `tasks.md` 子任务标记、全量验证。Tasks 1-9 已完成，仅剩收尾工作。

## 当前状态分析

### 已完成（Tasks 1-9）

通过 grep 验证所有 9 个预编译电路：

| 电路            | `new()` 模式        | `new_mvp()` / `new_light()` | 状态  |
| ------------- | ----------------- | --------------------------- | --- |
| Poseidon      | `full_mode: true` | `new_mvp()` ✅               | 已完成 |
| SHA-256       | `full_mode: true` | `new_mvp()` ✅               | 已完成 |
| ECDSA         | `full_mode: true` | `new_mvp()` ✅               | 已完成 |
| Keccak256     | `full_mode: true` | `new_mvp()` ✅               | 已完成 |
| Modexp        | `full_mode: true` | `new_mvp()` ✅               | 已完成 |
| MerkleVerify  | `full_mode: true` | `new_mvp()` ✅               | 已完成 |
| Ed25519       | `full_mode: true` | `new_mvp()` ✅               | 已完成 |
| BN254 Pairing | `full_mode: true` | `new_mvp()` ✅               | 已完成 |
| ZkShuffle     | `full_mode: true` | `new_light()` ✅             | 已完成 |

### 剩余工作

**Task 10（`precompiles/mod.rs`）— 部分完成**：

* ✅ `test_phase10_registry_full`（L352-406）：已使用 `new_mvp()` / `new_light()`

* ✅ `test_phase10_all_implement_both_traits`（L409-455）：保留 `new()`（仅 trait dispatch 检查，不调用方法）

* ✅ `test_phase10_gas_costs_reasonable`（L458-493）：已使用 `new_mvp()` / `new_light()`

* ❌ `test_phase10_real_circuits_ccs_closed_loop`（L496-529）：仍使用 `new()`，需改为 `new_mvp()`

* ❌ `test_phase10_registry_full_mode_smoke`：尚未新增

**Task 11（`syscall_circuit.rs`）— 未开始**：

* L265-271 `make_registry()`：`PoseidonCircuit::new()` / `Sha256Circuit::new()` / `EcdsaVerifyCircuit::new()` 仍为完整模式，需改为 `new_mvp()`

**Task 12（`tasks.md`）— 未开始**：

* L296-298 SubTask 10.2.1 / 10.2.2 / 10.2.3：`[ ]` → `[x]`，移除"延至 Phase 12+"

* L300-301 SubTask 10.3.1 / 10.3.2：`[ ]` → `[x]`，移除"延至 Phase 12+"

* L304-307 SubTask 10.4.1 / 10.4.2 / 10.4.3 / 10.4.4：`[ ]` → `[x]`，移除"延至 Phase 12+"

**Task 13（全量验证）— 未开始**

## 提议变更

### Task 10：完成 `precompiles/mod.rs` 测试更新

**文件**：`poker_zkvm/src/precompiles/mod.rs`

#### 10.5 `test_phase10_real_circuits_ccs_closed_loop`（L496-529）

**变更**：

* L499：`poseidon::PoseidonCircuit::new()` → `poseidon::PoseidonCircuit::new_mvp()`

* L507：`sha256::Sha256Circuit::new()` → `sha256::Sha256Circuit::new_mvp()`

* L519：`ecdsa::EcdsaVerifyCircuit::new()` → `ecdsa::EcdsaVerifyCircuit::new_mvp()`

**理由**：此测试使用 MVP 格式输入（Poseidon 1 输入、SHA-256 3 输入、ECDSA 3 输入），完整模式需要不同输入格式（ECDSA 完整模式需要 24 个输入）。保持 MVP 输入最快，验证 CCS 闭环机制本身。

#### 10.2 新增 `test_phase10_registry_full_mode_smoke`

**变更**：在 `test_phase10_gas_costs_reasonable` 之后（L493 后）新增测试：

```rust
/// 验证完整模式电路可注册且 gas 正确（不调用 num_variables / build_ccs，避免慢测试）。
#[test]
fn test_phase10_registry_full_mode_smoke() {
    let mut registry = PrecompileRegistry::new();
    registry.register(Box::new(poseidon::PoseidonCircuit::new()));
    registry.register(Box::new(sha256::Sha256Circuit::new()));
    registry.register(Box::new(ecdsa::EcdsaVerifyCircuit::new()));
    registry.register(Box::new(zk_shuffle::ZkShuffleCcsCircuit::new()));
    registry.register(Box::new(keccak256::Keccak256Circuit::new()));
    registry.register(Box::new(modexp::ModexpCircuit::new()));
    registry.register(Box::new(merkle_verify::MerkleVerifyCircuit::new()));
    registry.register(Box::new(ed25519::Ed25519VerifyCircuit::new()));
    registry.register(Box::new(bn254_pairing::Bn254PairingCircuit::new()));

    assert_eq!(registry.len(), 9, "应有 9 个预编译电路");

    // 仅验证 name() + gas_cost()（完整模式 gas 值）
    assert_eq!(registry.get("poseidon").unwrap().gas_cost(), 12_800);
    assert_eq!(registry.get("sha256").unwrap().gas_cost(), 25_000);
    assert_eq!(registry.get("ecdsa_verify").unwrap().gas_cost(), 19_375_600);
    assert_eq!(registry.get("zk_shuffle").unwrap().gas_cost(), 3_540_000);
    assert_eq!(registry.get("keccak256").unwrap().gas_cost(), 240_000);
    assert_eq!(registry.get("modexp").unwrap().gas_cost(), 69_200);
    assert_eq!(registry.get("merkle_verify").unwrap().gas_cost(), 100);
    assert_eq!(registry.get("ed25519").unwrap().gas_cost(), 2_066_000);
    assert_eq!(registry.get("bn254_pairing").unwrap().gas_cost(), 80_000);
}
```

**理由**：完整模式 `num_variables()` / `build_ccs()` 对 ECDSA（256-bit）/ Ed25519（252-bit）/ SHA-256（\~170K vars）很慢；仅检查 `name()` + `gas_cost()` 足以验证注册机制，且 gas 值反映了完整模式定价。

### Task 11：更新 `syscall_circuit.rs` 测试

**文件**：`poker_zkvm/src/constraints/syscall_circuit.rs`

**变更**（L265-271 `make_registry()`）：

```rust
fn make_registry() -> PrecompileRegistry {
    let mut registry = PrecompileRegistry::new();
    registry.register(Box::new(PoseidonCircuit::new_mvp()));
    registry.register(Box::new(Sha256Circuit::new_mvp()));
    registry.register(Box::new(EcdsaVerifyCircuit::new_mvp()));
    registry
}
```

**理由**（用户已确认）：dispatch 测试验证分派逻辑（ABI 一致性 + 实例数量），非电路数学正确性。MVP 输入格式简单（Poseidon 1 输入、SHA-256 3 输入、ECDSA 3 输入）且快速。所有 dispatch 测试输入保持 MVP 格式不变。

### Task 12：更新 `tasks.md`

**文件**：`.trae/specs/build-hypernova-zkvm/tasks.md`

**变更**：

* L296 SubTask 10.2.1：`[ ]` → `[x]`，移除"— **延至 Phase 12+**（MVP 仅 S-box 单 round）"

* L297 SubTask 10.2.2：`[ ]` → `[x]`，移除"— **延至 Phase 12+**（MVP \~6 constraints/S-box）"

* L298 SubTask 10.2.3：`[ ]` → `[x]`，移除"— **延至 Phase 12+**（MVP 仅验证 ark\_bn254::Fr `x^5` 一致）"

* L300 SubTask 10.3.1：`[ ]` → `[x]`，移除"— **延至 Phase 12+**（MVP 仅 Ch 函数）"

* L301 SubTask 10.3.2：`[ ]` → `[x]`，移除"— **延至 Phase 12+**（MVP 单 Ch op）"

* L304 SubTask 10.4.1：`[ ]` → `[x]`，移除"— **延至 Phase 12+**（MVP 仅单步）"

* L305 SubTask 10.4.2：`[ ]` → `[x]`，移除"— **延至 Phase 12+**"

* L306 SubTask 10.4.3：`[ ]` → `[x]`，移除"— **延至 Phase 12+**（MVP 单步）"

* L307 SubTask 10.4.4：`[ ]` → `[x]`，移除"— **延至 Phase 12+**（MVP 已测篡改 R\_new / bit\_P / bit 非二进制 soundness）"

### Task 13：全量验证

1. `cargo build -p poker_zkvm` — 编译通过
2. `cargo test -p poker_zkvm` — 全部测试通过
3. `cargo clippy -p poker_zkvm -- -D warnings` — 0 warnings
4. `cargo fmt --all --check` — 0 diffs
5. `cargo build -p poker_l1` — 编译通过（验证无跨 crate 影响）
6. `cargo test -p poker_l1` — 全部测试通过（回归）

## 假设与决策

### 决策 1：`test_phase10_real_circuits_ccs_closed_loop` 使用 `new_mvp()`

* **选择**：`new()` → `new_mvp()`

* **理由**：此测试使用 MVP 格式输入（Poseidon 1 输入、SHA-256 3 输入、ECDSA 3 输入），完整模式需要不同输入格式（ECDSA 完整模式需要 24 个输入）。保持 MVP 输入最快，验证 CCS 闭环机制本身。

### 决策 2：`test_phase10_all_implement_both_traits` 保留 `new()`

* **选择**：保留 `new()`（完整模式）

* **理由**：此测试仅创建结构体检查 trait dispatch（`&dyn PrecompileCircuit` / `&dyn CcsCircuit`），不调用任何方法，无性能问题。同时验证完整模式电路实现双 trait。

### 决策 3：新增 `test_phase10_registry_full_mode_smoke` 仅检查 `name()` + `gas_cost()`

* **选择**：仅注册 + 检查 gas，不调用 `num_variables()` / `build_ccs()`

* **理由**：完整模式 `num_variables()` / `build_ccs()` 对 ECDSA（256-bit scalar mul）/ Ed25519（252-bit scalar mul）/ SHA-256（\~170K vars）/ Keccak256（\~350K vars）很慢。gas 值已反映完整模式定价，足以验证注册正确性。

### 决策 4：dispatch 测试使用 `new_mvp()`（用户已确认）

* **选择**：`syscall_circuit.rs` 的 `make_registry()` 使用 `new_mvp()`

* **理由**：dispatch 测试验证分派逻辑（ABI 一致性 + 实例数量），非电路数学；MVP 输入格式简单且快速。

## 验证步骤

1. **编译验证**：`cargo build -p poker_zkvm && cargo build -p poker_l1`
2. **单元测试**：`cargo test -p poker_zkvm`
3. **回归测试**：`cargo test -p poker_l1`
4. **Clippy**：`cargo clippy -p poker_zkvm -- -D warnings && cargo clippy -p poker_l1 -- -D warnings`
5. **Fmt**：`cargo fmt --all --check`

## 实施顺序

1. Task 10.5：更新 `test_phase10_real_circuits_ccs_closed_loop`（3 处 `new()` → `new_mvp()`）
2. Task 10.2：新增 `test_phase10_registry_full_mode_smoke` 测试
3. Task 11：更新 `syscall_circuit.rs` `make_registry()`（3 处 `new()` → `new_mvp()`）
4. Task 12：更新 `tasks.md`（9 个 SubTask `[ ]` → `[x]`，移除"延至 Phase 12+"）
5. Task 13：全量验证（build / test / clippy / fmt）

