# poker_l1 全面测试补充计划

## Context

用户要求：参考 poker_zkvm 的工程标准，为 poker_l1 补充全面的测试，跑通 e2e 测试，存在问题的功能需要修复。

**当前基线**（已验证）：
- poker_l1 lib 测试 1287 个全部通过，integration 测试 49 个全部通过（共 1336）
- 65 个源文件全部有内联 `#[cfg(test)] mod tests` 块
- **缺失**：无 `tests/soundness_tests.rs`、无 `tests/formal_properties.rs`、无 `tests/common/mod.rs`、无 proptest 使用、proptest 未加入 poker_l1 dev-dependencies

**poker_zkvm 测试标准**（已确认）：
- `tests/soundness_tests.rs` — 专用负向/安全测试（字节篡改、截断、magic 不匹配、超限 payload、非白名单 slot、witness 篡改）
- `tests/formal_properties.rs` — proptest 属性测试
- `tests/common/mod.rs` — 共享测试基础设施
- 内联 `proptest!` 块用于数学不变量

**功能状态**：所有模块均为真实实现（非 stub）。IPA/Groth16 Production verifier 为设计性 stub（实现在 poker_zkvm 中）。`execute_checkin` 终局游戏 `proof_partial_hash` 清理为已记录的设计缺口（非 bug）。

## 实施步骤

### 步骤 1：添加 proptest dev-dependency

文件：`/Users/mac/projects/zchain/poker_l1/Cargo.toml`

在 `[dev-dependencies]` 末尾添加：
```toml
proptest = { workspace = true }
```
workspace 已定义 `proptest = "1"`（Cargo.toml L54）。

### 步骤 2：创建 `poker_l1/tests/common/mod.rs`

提取 phase1-7 测试文件中重复的辅助函数。标记 `#![allow(dead_code)]`（与 poker_zkvm `tests/common/mod.rs:9` 一致）。

包含的辅助函数：
- `make_tagged_pubkey_secp(byte: u8) -> TaggedPubkey` — secp256k1 v1 tagged pubkey
- `make_tagged_pubkey_ed25519(byte: u8) -> TaggedPubkey` — ed25519 v1 tagged pubkey
- `dummy_commit_cert() -> DagCommitCertificate` — 最小合法 commit cert
- `make_block(height: u64, prev_hash: [u8; 32]) -> Block`
- `make_dag_vertex(epoch: u64, round: u64) -> DagVertex`
- `make_tx(...) -> Transaction` — 最小 tx（65 字节零签名）
- `blake2b_256(data: &[u8]) -> [u8; 32]` — 工具哈希
- `make_real_secp_keypair() -> (SecretKey, PublicKey, TaggedPubkey)` — 真实 secp256k1 密钥对
- `make_real_ed25519_keypair() -> (SigningKey, VerifyingKey, TaggedPubkey)` — 真实 ed25519 密钥对

导入模式：测试文件中 `mod common;` + `use common::*;`（与 poker_zkvm soundness_tests.rs:11 一致）。

### 步骤 3：创建 `poker_l1/tests/soundness_tests.rs`

20 个负向/安全测试，每个断言特定 `PokerL1Error` 变体被返回。

**交易校验（4 个）**：
1. `test_soundness_tx_inputs_at_limit_passes` — 256 inputs（恰好 MAX_INPUTS）返回 Ok
2. `test_soundness_tx_outputs_at_limit_passes` — 256 outputs（恰好 MAX_OUTPUTS）返回 Ok
3. `test_soundness_tx_outputs_above_limit_fails` — 257 outputs 返回 `InputTooLong { actual: 257, limit: 256 }`
4. `test_soundness_tx_sig_above_limit_fails` — 66 字节签名返回 `InputTooLong { actual: 66, limit: 65 }`

**签名验证（4 个）**：
5. `test_soundness_sig_tampered_secp_bytes_fails` — 翻转合法 secp 签名首字节 → `InvalidSignature`
6. `test_soundness_sig_ed25519_non_canonical_s_fails` — S 设为 L → `InvalidSignatureCanonical`
7. `test_soundness_sig_ed25519_wrong_pubkey_length_fails` — ed25519 tag + raw.len()=31 → `InvalidPubkeyLength { tag, actual: 31, expected: 32 }`
8. `test_soundness_sig_cross_scheme_routing_fails` — ed25519 tagged pubkey + 65 字节 secp 签名 → 路由到 ed25519 verify → `InvalidSignatureLength { actual: 65, expected: 64 }`

**SMT（4 个）**：
9. `test_soundness_smt_tampered_sibling_fails` — 翻转 `path.siblings[0]` 字节 → `verify` 返回 false
10. `test_soundness_smt_truncated_path_fails` — path.siblings.len()=100（非 256）→ `verify` 返回 false
11. `test_soundness_smt_wrong_key_fails` — prove(key_A)，用 key_B 调 verify → 返回 false
12. `test_soundness_smt_empty_nonempty_mismatch_fails` — `is_empty_leaf=true` + `value=Some(...)` → `verify` 返回 false

**Bridge（3 个）**：
13. `test_soundness_bridge_not_protocol_caller_fails` — `is_protocol_caller=false` → `BridgeVerifyNotAuthorized`
14. `test_soundness_bridge_replay_nonce_fails` — 消费 nonce 后重放 → `BridgeNonceConsumed(nonce)`
15. `test_soundness_bridge_wrong_dest_chain_fails` — `dest_chain_id != network_chain_id` → `BridgeSignatureInvalid(...)`

**Block 时间共识（3 个）**：
16. `test_soundness_block_height_not_increasing_fails` — curr.height == prev.height → `BlockHeightNotIncreasing`
17. `test_soundness_block_timestamp_backwards_fails` — curr.ts < prev.ts → `BlockTimestampMovedBackwards`
18. `test_soundness_block_timestamp_interval_exceeded_fails` — interval > max_interval_ms → `BlockTimestampIntervalExceeded`

**网络大小限制（2 个）**：
19. `test_soundness_tx_too_large_fails` — 构造 128KB+ args 的 tx → `TxTooLarge`（调用 `network::validate_tx_size`）
20. `test_soundness_vertex_too_large_fails` — 构造超限 vertex → `VertexTooLarge`（调用 `network::validate_vertex_size`）

### 步骤 4：创建 `poker_l1/tests/formal_properties.rs`

12 个 proptest 属性，每个 64-256 cases：

**SMT（4 个）**：
1. `prop_smt_insert_prove_verify_roundtrip` — 任意 key/value：upsert → prove → verify == true
2. `prop_smt_insertion_order_independence` — 任意 (key,value) 列表：正向/反向/乱序构建得到相同 root
3. `prop_smt_delete_restores_empty_root` — 任意 key/value：insert+delete 后 root == empty_root
4. `prop_smt_tampered_value_fails` — 任意 key/value/tampered：verify(root, key, Some(tampered), path) == false

**签名（2 个）**：
5. `prop_sig_secp_sign_verify_roundtrip` — 任意 msg_hash：真实密钥对 sign → verify == Ok
6. `prop_sig_ed25519_sign_verify_roundtrip` — 任意 message：真实密钥对 sign → verify == Ok

**地址派生（2 个）**：
7. `prop_address_derivation_deterministic` — 同一 tagged pubkey 两次 derive_address 得到相同 [u8;20]
8. `prop_address_different_schemes_differ` — 同 raw 字节 + secp tag vs ed25519 tag → 不同地址

**序列化往返（2 个）**：
9. `prop_transaction_bcs_roundtrip` — 任意 nonce/is_fallback：to_bcs → from_bcs == 原值
10. `prop_tagged_pubkey_encode_decode_roundtrip` — 任意 scheme/byte：to_bytes → from_bytes == 原值

**哈希确定性（2 个）**：
11. `prop_ack_chain_hash_deterministic` — 同一 AckEntry 两次 ack_hash() 得到相同 Hash
12. `prop_blake2b_domain_separation` — 任意 key/value：leaf_hash != internal_hash（域前缀 0x00 vs 0x01）

### 步骤 5：补齐内联测试缺口

**缺口 1** — `/Users/mac/projects/zchain/poker_l1/src/transaction/mod.rs`：
在现有 `validate_tx_limits_rejects_too_many_inputs` 测试后添加 `validate_tx_limits_rejects_too_many_outputs`：
- 构造 `tx.outputs = vec![dummy_object(); 300]`
- 断言 `InputTooLong { actual: 300, limit: 256 }`

**缺口 2** — `/Users/mac/projects/zchain/poker_l1/src/signature/ed25519_scheme.rs`：
在 `verify_wrong_sig_length` 测试后添加 `verify_rejects_wrong_pubkey_length`：
- 构造 `TaggedPubkey { tag: encode_tag(Ed25519, 1), raw: vec![0u8; 31] }`
- 传入合法 64 字节签名
- 断言 `InvalidPubkeyLength { tag, actual: 31, expected: 32 }`

### 步骤 6：运行全部测试验证

```bash
cargo test -p poker_l1
cargo clippy -p poker_l1 --all-targets -- -D warnings
cargo fmt -p poker_l1 --check
```

预期：1336 现有 + ~20 soundness + ~12 proptest + 2 内联 = ~1370 测试全部通过。

### 步骤 7：终局游戏 proof_partial_hash 清理 — 不实现

**理由**：
- `execute_checkin` 签名接收 `last_partial_fold: Option<&LastPartialFold>`（不可变引用）并返回 `ZkVerifyResult` — 不修改链上状态
- 清理 `last_partial_fold` 是调用方（block 执行层）的职责
- 在 `execute_checkin` 内实现清理需要改变签名以返回状态变更命令，属于设计级变更，超出测试补充范围
- IPA/Groth16 Production stub 为设计性延迟（实现在 poker_zkvm）

## 关键文件清单

- `/Users/mac/projects/zchain/poker_l1/Cargo.toml` — 添加 proptest dev-dependency
- `/Users/mac/projects/zchain/poker_l1/tests/common/mod.rs` — 新建共享测试辅助（从 phase1_integration.rs:30-113 提取）
- `/Users/mac/projects/zchain/poker_l1/tests/soundness_tests.rs` — 新建 20 个负向安全测试
- `/Users/mac/projects/zchain/poker_l1/tests/formal_properties.rs` — 新建 12 个 proptest 属性
- `/Users/mac/projects/zchain/poker_l1/src/transaction/mod.rs` — 添加 too-many-outputs 测试（L503 后）
- `/Users/mac/projects/zchain/poker_l1/src/signature/ed25519_scheme.rs` — 添加 InvalidPubkeyLength 测试（L174 后）

## 复用的现有函数

- `poker_l1::object_model::smt::SparseMerkleTree::{new, upsert, remove, prove, verify}` — smt.rs
- `poker_l1::signature::unified::verify_signature` — unified.rs
- `poker_l1::signature::tagged_pubkey::{encode_tag, SignatureScheme}` — tagged_pubkey.rs
- `poker_l1::account::derive_address` — account/mod.rs
- `poker_l1::transaction::validate_tx_limits` — transaction/mod.rs
- `poker_l1::network::{validate_tx_size, validate_block_size, validate_vertex_size}` — network/mod.rs
- `poker_l1::bridge::bridge_verify` — bridge/mod.rs
- `poker_l1::block::time_consensus::validate_time_consensus` — time_consensus.rs
- `poker_l1::offline::ack_chain::AckEntry::ack_hash` — ack_chain.rs

## 验证方式

1. `cargo test -p poker_l1 --lib` — 1287 + 2 内联 = 1289 lib 测试通过
2. `cargo test -p poker_l1 --test soundness_tests` — 20 soundness 测试通过
3. `cargo test -p poker_l1 --test formal_properties` — 12 proptest 通过
4. `cargo test -p poker_l1 --tests` — 全部 integration + soundness + formal_properties 通过
5. `cargo clippy -p poker_l1 --all-targets -- -D warnings` — 0 warning
6. `cargo fmt -p poker_l1 --check` — 无 diff
