# Plan: Complete Spartan CCS Registry Migration

## Summary

完成 Spartan CCS 注册表迁移的收尾工作。前序会话已完成核心改动（`spartan.rs` 去除内嵌 CCS、`prover/mod.rs` 新增 `default_ccs_registry()`、`verifier.rs` 实现 HYPN/SPRT magic 分派 + `verify_spartan`），但仍有 2 个源文件和 1 个文档文件引用旧 API `default_ccs_whitelist()` / `ccs_whitelist`，导致编译失败。本计划修复这些遗留引用并运行完整验证。

## Current State Analysis

### 已完成（前序会话）
- `poker_zkvm/src/prover/spartan.rs` — `SpartanCompressedProof` 已去除 `ccs` 字段 ✅
- `poker_zkvm/src/prover/mod.rs` — `default_ccs_registry()` 已新增（L1310），`serialize/deserialize_spartan_proof` 已更新，`default_ccs_whitelist` 保留为 deprecated 别名（L1322，返回 `Vec<[u8;32]>`） ✅
- `poker_zkvm/src/verifier.rs` — `verify_production` 签名改为 `ccs_registry: &[Ccs]`，HYPN/SPRT magic 分派已实现，`verify_spartan` 已新增，5 个 Spartan 测试已添加 ✅
- `poker_zkvm/tests/e2e_*.rs`（3 个文件）— 已迁移到 `default_ccs_registry` ✅
- `poker_zkvm/benches/phase12_benchmarks.rs` — 已迁移 ✅

### 未完成（本计划修复）
1. **`poker_zkvm/tests/soundness_tests.rs`** — 4 个测试体仍调用 `default_ccs_whitelist()`（返回 `Vec<[u8;32]>`）并传给 `verify_production`（期望 `&[Ccs]`）→ **类型不匹配，编译失败**
   - L66-67: `test_soundness_tampered_proof_magic_fails`
   - L80-81: `test_soundness_tampered_proof_byte_flip_fails`
   - L277-278: `test_soundness_tampered_proof_payload_fails`
   - L288-289: `test_soundness_tampered_proof_z_at_point_fails`
   - 注：L21 import 已更新为 `default_ccs_registry`，但函数体未同步

2. **`poker_l1/src/offline/hypernova.rs`** L224-225 — 仍调用 `default_ccs_whitelist()` 并传 `&ccs_whitelist` → **编译失败**
   - `poker_l1/Cargo.toml` 已启用 `features = ["test-helpers"]`，`default_ccs_registry()` 可访问 ✅

3. **`poker_zkvm/README.md`** L63-64, L136 — 文档示例仍展示旧 API

### 现有 deprecated 别名状态
`default_ccs_whitelist()`（L1322）保留为 deprecated 别名，返回 `Vec<[u8;32]>`，内部调用 `default_ccs_registry()` 后映射 commitments。迁移完成后无内部调用方，但作为公开 API 保留供潜在外部消费者。**不删除**（符合前序已批准计划的决定）。

## Proposed Changes

### 1. `poker_zkvm/tests/soundness_tests.rs` — 批量替换 4 处

对 4 个测试函数中的 8 行执行 `replace_all`：
- `default_ccs_whitelist()` → `default_ccs_registry()`
- `let ccs_whitelist =` → `let ccs_registry =`
- `&ccs_whitelist` → `&ccs_registry`

涉及行：L66-67, L80-81, L277-278, L288-289

### 2. `poker_l1/src/offline/hypernova.rs` L224-225

```rust
// 旧
let ccs_whitelist = poker_zkvm::prover::default_ccs_whitelist();
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io, &ccs_whitelist) {

// 新
let ccs_registry = poker_zkvm::prover::default_ccs_registry();
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io, &ccs_registry) {
```

### 3. `poker_zkvm/README.md` L63-64, L136

L63-64（快速上手示例）：
```rust
// 旧
let ccs_whitelist = poker_zkvm::prover::default_ccs_whitelist();
let ok = verify_production(&proof_bytes, &public_io, &ccs_whitelist)

// 新
let ccs_registry = poker_zkvm::prover::default_ccs_registry();
let ok = verify_production(&proof_bytes, &public_io, &ccs_registry)
```

L136（Verifier API 签名文档）：
```rust
// 旧
ccs_whitelist: &[[u8; 32]],

// 新
ccs_registry: &[crate::ccs::Ccs],
```

### 4. tasks.md

Phase 12 Task 7.2（Spartan 压缩）已标记 `[x]`。CCS 注册表迁移是 Spartan 实现的收尾修复，无需新增独立 task。在 SubTask 7.2.4 后追加一行说明 CCS 注册表方案已落地即可。

## Assumptions & Decisions

1. **保留 `default_ccs_whitelist` deprecated 别名** — 遵循前序已批准计划，不删除。迁移后无内部调用方，但保留供外部兼容。
2. **不修改 `verifier.rs`** — 前序会话已完成，24 个测试通过，无需改动。
3. **不修改 `prover/mod.rs`** — `default_ccs_registry` 和 deprecated 别名均已就位，无需改动。
4. **poker_l1 `test-helpers` feature 已启用** — `Cargo.toml` L11/L36 已配置，`default_ccs_registry()` 可直接访问。

## Verification Steps

1. `cargo build -p poker_zkvm --features test-helpers` — 编译通过
2. `cargo build -p poker_l1` — 编译通过
3. `cargo test -p poker_zkvm --features test-helpers` — 全部测试通过（lib + 4 个 integration test 文件）
4. `cargo test -p poker_l1` — 全部测试通过
5. `cargo clippy -p poker_zkvm --features test-helpers --all-targets -- -D warnings` — 0 warnings
6. `cargo clippy -p poker_l1 --all-targets -- -D warnings` — 0 warnings
7. `cargo fmt --all -- --check` — 0 diffs
