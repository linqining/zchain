# poker_l1 测试补充 — 延续执行计划

## Context

承接上一轮会话的工作。用户原始请求："参考 poker_zkvm 的工程标准，poker_l1 需要补充全面的测试，并且跑通 e2e 测试，存在问题的功能需要修复"。

**已完成的工作**（已验证存在）：
- `/Users/mac/projects/zchain/poker_l1/Cargo.toml` — 已添加 `proptest = { workspace = true }` (L35)
- `/Users/mac/projects/zchain/poker_l1/tests/common/mod.rs` — 已创建 9 个共享辅助函数
- `/Users/mac/projects/zchain/poker_l1/tests/soundness_tests.rs` — 已创建 20 个负向安全测试
- `/Users/mac/projects/zchain/.trae/documents/poker_l1_comprehensive_tests_plan.md` — 原始完整计划文档

**剩余工作**：
1. 编译验证 soundness_tests.rs（未编译过）
2. 创建 tests/formal_properties.rs（12 个 proptest 属性）
3. 补齐 2 个内联测试缺口
4. 运行全部测试 + clippy + fmt 验证
5. 修复发现的问题（如有）

## 当前状态分析

### 测试基线
- poker_l1 lib 测试 1287 个 + integration 49 个 = 1336 全部通过（上一轮基线）
- 65 个源文件均有内联 `#[cfg(test)] mod tests` 块
- tests/ 目录现有文件：phase1-7_integration.rs、phase5a/b/c_integration.rs、phase6_game_flow.rs、phase7_helpers.rs、bridge_helpers.rs、common/mod.rs、soundness_tests.rs

### 关键 API 签名（已通过 Explore 验证）

**SMT**（src/object_model/smt.rs + mod.rs L19-22 公开 re-export）：
- `SparseMerkleTree::new() -> Self`
- `root() -> Hash`
- `upsert(key: [u8;32], value: &[u8])`
- `remove(key: [u8;32]) -> bool`
- `prove(&key) -> MerklePath`
- `verify(root: &Hash, key: &[u8;32], value: Option<&[u8]>, path: &MerklePath) -> bool`
- 公开函数：`leaf_hash(key, value) -> Hash`（前缀 0x00）、`internal_hash(left, right) -> Hash`（前缀 0x01）、`empty_leaf_hash() -> Hash`、`empty_hashes() -> &'static [Hash]`、`TREE_DEPTH = 256`

**TaggedPubkey**（src/signature/tagged_pubkey.rs）：
- `TaggedPubkey::new(scheme: SignatureScheme, version: u8, raw: Vec<u8>) -> Result<Self, PokerL1Error>`
- `to_bytes(&self) -> Vec<u8>`、`from_bytes(bytes: &[u8]) -> Result<Self, PokerL1Error>`
- `encode_tag(scheme, version) -> u8`、`SignatureScheme::{Secp256k1, Ed25519}`

**Address 派生**（src/account/mod.rs L95-L110）：
- `derive_address(tp: &TaggedPubkey) -> Address`（取 `blake2b_256(tp.to_bytes())[0..20]`）
- `Address` = `[u8; 20]`、`Hash` = `[u8; 32]`

**Transaction**（src/transaction/mod.rs L100-L136）：
- `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]` — 支持 BCS 往返
- 字段：inputs/outputs/contract_call/tagged_pubkey/signature/gas/lane_hint/route_hint/chain_id/nonce/gameturn_nonce/is_fallback

**AckEntry**（src/offline/ack_chain.rs L43-L60, L67）：
- `pub fn ack_hash(&self) -> Hash`

**签名验证**：
- `poker_l1::signature::unified::verify_signature(&TaggedPubkey, &[u8], &[u8;32]) -> PokerL1Result<()>`
- secp256k1 签名：`secp256k1::Secp256k1::sign_ecdsa_recoverable(&Message, &SecretKey) -> RecoverableSignature`，`.serialize_compact() -> (RecoveryId, [u8;64])`
- ed25519 签名：`ed25519_dalek::Signer::sign(&SigningKey, msg) -> Signature`，`.to_bytes() -> [u8;64]`

### 内联测试缺口位置
- src/transaction/mod.rs L497-L503：现有 `validate_tx_limits_rejects_too_many_inputs` 测试，紧随其后应添加 `validate_tx_limits_rejects_too_many_outputs`
- src/signature/ed25519_scheme.rs L168-L174：现有 `verify_wrong_sig_length` 测试，紧随其后应添加 `verify_rejects_wrong_pubkey_length`

## 实施步骤

### 步骤 A：编译验证 soundness_tests.rs

```bash
cargo test -p poker_l1 --test soundness_tests --no-run
```

**预期问题**：
- soundness_tests.rs 中的 `make_block`、`make_dag_vertex`、`SigningKey`、`Address`、`RouteHint`、`Transaction`、`BridgeValidatorSig` 等导入可能未使用（dead_code）
- 由于 `tests/common/mod.rs` 已标记 `#![allow(dead_code)]`，common 内部的死代码不会报警；但 soundness_tests.rs 内的 unused imports 仍会触发 warning

**修复策略**：
- 仅移除 soundness_tests.rs 中实际未使用的 `use` 项
- 不修改 common/mod.rs（已 allow(dead_code)）
- 若编译失败因 API 签名不匹配，按实际签名调整

### 步骤 B：创建 tests/formal_properties.rs

文件：`/Users/mac/projects/zchain/poker_l1/tests/formal_properties.rs`

参考 poker_zkvm `tests/formal_properties.rs` 的 `proptest!` 块模式。

**12 个 proptest 属性**：

#### SMT（4 个）
1. `prop_smt_insert_prove_verify_roundtrip`
   - 策略：`key: [u8;32]`（任意 32 字节）、`value: Vec<u8>`（0..256 字节）
   - 不变量：`upsert(key, &value)` → `prove(&key)` → `verify(root, key, Some(&value), path) == true`

2. `prop_smt_insertion_order_independence`
   - 策略：`entries: Vec<([u8;32], Vec<u8>)>`（1..32 项，key 唯一）
   - 不变量：正向构建 root == 反向构建 root == 排序后构建 root

3. `prop_smt_delete_restores_empty_root`
   - 策略：`key: [u8;32]`、`value: Vec<u8>`
   - 不变量：`new()` 的 root == `upsert(key, &value); remove(key);` 后的 root

4. `prop_smt_tampered_value_fails`
   - 策略：`key: [u8;32]`、`value: Vec<u8>`、`tampered_byte: u8`
   - 不变量：`upsert(key, &value); prove(&key); ` 然后构造 `tampered_value`（首字节 ^ tampered_byte），`verify(root, key, Some(&tampered_value), path) == false`

#### 签名（2 个）
5. `prop_sig_secp_sign_verify_roundtrip`
   - 策略：`msg_hash: [u8;32]`（任意 32 字节）
   - 不变量：生成真实 secp256k1 密钥对 → `sign_ecdsa_recoverable` → 拼装 65B (r||s||v) → `verify_signature(&tagged, &sig, &msg_hash) == Ok(())`

6. `prop_sig_ed25519_sign_verify_roundtrip`
   - 策略：`msg: Vec<u8>`（1..256 字节）
   - 不变量：生成真实 ed25519 密钥对 → `sign(&msg)` → `verify_signature(&tagged, &sig, &blake2b_256(&msg)) == Ok(())`
   - 注：`verify_signature` 接收 `msg_hash: &[u8;32]`，需先对任意长度 msg 做哈希

#### 地址派生（2 个）
7. `prop_address_derivation_deterministic`
   - 策略：`byte: u8`（构造 raw=vec![byte;33] 的 secp tagged pubkey）
   - 不变量：`derive_address(&tp) == derive_address(&tp)`（同一输入两次派生得到相同 Address）

8. `prop_address_different_schemes_differ`
   - 策略：`byte: u8`
   - 不变量：secp tagged pubkey (raw=vec![byte;33]) 派生的 address != ed25519 tagged pubkey (raw=vec![byte;32]) 派生的 address

#### 序列化往返（2 个）
9. `prop_transaction_bcs_roundtrip`
   - 策略：`nonce: u64`、`is_fallback: bool`
   - 不变量：构造 `Transaction`（用 `make_tx` 基础上加 nonce/is_fallback）→ `bcs::to_bytes(&tx)` → `bcs::from_bytes::<Transaction>(&bytes)` == 原值

10. `prop_tagged_pubkey_encode_decode_roundtrip`
    - 策略：`scheme_byte: u8`（0 或 1）、`version: u8`（1..=15）、`fill_byte: u8`
    - 不变量：构造 `TaggedPubkey` → `to_bytes()` → `from_bytes()` == 原值

#### 哈希确定性（2 个）
11. `prop_ack_chain_hash_deterministic`
    - 策略：`epoch: u64`、`current_turn: u64`、`checkpoint_seq: u64`
    - 不变量：构造相同 `AckEntry` 两次调用 `ack_hash()` 得到相同 `Hash`

12. `prop_blake2b_domain_separation`
    - 策略：`key: [u8;32]`、`value: Vec<u8>`（非空）
    - 不变量：`leaf_hash(&key, &value) != internal_hash(&leaf_hash(&key, &value), &leaf_hash(&key, &value))`（域前缀 0x00 vs 0x01 必产生不同哈希）

**导入模式**：
```rust
//! poker_l1 形式化属性测试 — proptest 不变量验证。
//!
//! 参考 poker_zkvm tests/formal_properties.rs 模式。

mod common;

use common::{make_real_ed25519_keypair, make_real_secp_keypair, make_tx};
use poker_l1::object_model::{SparseMerkleTree, leaf_hash, internal_hash};
use poker_l1::offline::ack_chain::AckEntry;
use poker_l1::signature::unified::verify_signature;
use poker_l1::signature::{SignatureScheme, TaggedPubkey};
use poker_l1::signature::tagged_pubkey::encode_tag;
use poker_l1::account::derive_address;
use poker_l1::transaction::{Transaction, TxLane};
use poker_l1::{Address, ChainId, DEFAULT_CHAIN_ID, Hash};

use proptest::prelude::*;
use ed25519_dalek::Signer;
use secp256k1::Message;
```

**AckEntry 构造**（参考 src/offline/ack_chain.rs L43-L60 字段）：
```rust
fn make_ack_entry(epoch: u64, current_turn: u64, checkpoint_seq: u64) -> AckEntry {
    AckEntry {
        chain_id: DEFAULT_CHAIN_ID,
        epoch,
        game_id: [0xAB; 32],
        current_turn,
        state_hash: [0xCD; 32],
        checkpoint_seq,
        ack_domain_tag: 0x01,
        participant_tagged_pubkey: common::make_tagged_pubkey_secp(0x42),
        participant_signature: vec![0u8; 65],
    }
}
```

**proptest case 数**：默认 256 cases（与 poker_zkvm 一致），复杂属性（如 insertion_order）使用 64 cases。

### 步骤 C：补齐 2 个内联测试缺口

#### 缺口 1：src/transaction/mod.rs

在 L503（`validate_tx_limits_rejects_too_many_inputs` 测试之后）添加：

```rust
#[test]
fn validate_tx_limits_rejects_too_many_outputs() {
    let tp = crate::signature::TaggedPubkey {
        tag: crate::signature::tagged_pubkey::encode_tag(
            crate::signature::SignatureScheme::Secp256k1,
            crate::signature::CURRENT_VERSION,
        ),
        raw: vec![0x02; 33],
    };
    let dummy_obj = crate::object_model::Object::new(
        crate::object_model::ObjectID::new([0u8; 20], 0),
        crate::object_model::Ownership::Shared,
        "T",
        vec![],
        None,
    );
    let mut tx = crate::transaction::Transaction::new(tp, crate::DEFAULT_CHAIN_ID);
    tx.outputs = vec![dummy_obj; 257];
    let err = crate::transaction::validate_tx_limits(&tx).unwrap_err();
    assert!(
        matches!(err, crate::error::PokerL1Error::InputTooLong { actual: 257, limit: 256 }),
        "257 outputs 应返回 InputTooLong {{ actual: 257, limit: 256 }}, got: {err:?}"
    );
}
```

**注**：需先读取 src/transaction/mod.rs L490-L510 确认现有测试的实际构造方式（Transaction::new 签名、dummy_obj 构造），按现有模式对齐。

#### 缺口 2：src/signature/ed25519_scheme.rs

在 L174（`verify_wrong_sig_length` 测试之后）添加：

```rust
#[test]
fn verify_rejects_wrong_pubkey_length() {
    use crate::signature::tagged_pubkey::encode_tag;
    use ed25519_dalek::{Signer, SigningKey};

    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let msg = [0x42u8; 32];
    let sig = sk.sign(&msg);
    let sig_bytes = sig.to_bytes().to_vec();

    // raw.len()=31（应为 32）的 ed25519 tagged pubkey
    let wrong_tp = TaggedPubkey {
        tag: encode_tag(SignatureScheme::Ed25519, 1),
        raw: vec![0u8; 31],
    };

    let err = verify(&wrong_tp, &sig_bytes, &msg).unwrap_err();
    assert!(
        matches!(err, PokerL1Error::InvalidPubkeyLength { actual: 31, expected: 32, .. }),
        "raw.len()=31 应返回 InvalidPubkeyLength, got: {err:?}"
    );
}
```

**注**：需先读取 src/signature/ed25519_scheme.rs L150-L180 确认现有测试的导入与构造模式。

### 步骤 D：运行全部测试 + clippy + fmt

```bash
# 1. 仅编译 soundness + formal_properties（快速失败）
cargo test -p poker_l1 --test soundness_tests --no-run
cargo test -p poker_l1 --test formal_properties --no-run

# 2. 运行新增测试
cargo test -p poker_l1 --test soundness_tests
cargo test -p poker_l1 --test formal_properties

# 3. 运行 lib 单元测试（含 2 个新增内联测试）
cargo test -p poker_l1 --lib

# 4. 运行全部 integration（e2e）测试
cargo test -p poker_l1 --tests

# 5. clippy + fmt
cargo clippy -p poker_l1 --all-targets -- -D warnings
cargo fmt -p poker_l1 --check
```

**预期总测试数**：1336 现有 + 20 soundness + 12 proptest + 2 内联 = ~1370 全部通过。

### 步骤 E：修复发现的问题

**可能的故障点**：
1. soundness_tests.rs 中 `dummy_commit_cert()` 返回类型不匹配（DagCommitCertificate 字段缺失）
2. soundness_tests.rs 中 `BridgeDeposit` / `BridgeVerifyTx` 字段不匹配
3. soundness_tests.rs 中 `BlockHeader` 字段缺失（除 height/timestamp_ms/prev_hash 外）
4. formal_properties.rs 中 `AckEntry` 字段缺失或类型不匹配
5. formal_properties.rs 中 `Object::new` 签名不匹配
6. proptest 中 `Vec<u8>` 策略需限制大小（避免 OOM）
7. clippy 警告：unused imports、too_many_arguments、large_enum_variant 等

**修复原则**：
- 优先按实际 API 签名调整测试代码（不修改源代码）
- 若源代码确实存在 bug（如 API 不一致、panic、逻辑错误），按 poker_zkvm 工程标准修复
- 修复后必须重跑相关测试确认通过
- 不实现 `execute_checkin` 终局游戏 `proof_partial_hash` 清理（设计性延迟，超出测试补充范围）

## 关键文件清单

- `/Users/mac/projects/zchain/poker_l1/tests/soundness_tests.rs` — 验证编译，按需修复 unused imports
- `/Users/mac/projects/zchain/poker_l1/tests/formal_properties.rs` — 新建 12 个 proptest 属性
- `/Users/mac/projects/zchain/poker_l1/src/transaction/mod.rs` — 添加 too-many-outputs 测试（L503 后）
- `/Users/mac/projects/zchain/poker_l1/src/signature/ed25519_scheme.rs` — 添加 InvalidPubkeyLength 测试（L174 后）

## 假设与决策

1. **不修改 common/mod.rs**：已标记 `#![allow(dead_code)]`，部分函数未在所有测试文件中使用是预期行为
2. **不修改源代码除内联测试外**：仅当测试发现真实 bug 时才修复源代码
3. **proptest case 数**：默认 256（与 poker_zkvm 一致），复杂属性降为 64
4. **Vec<u8> 策略大小限制**：1..256 字节（避免 BCS 序列化超限与 OOM）
5. **不实现终局游戏 proof_partial_hash 清理**：设计性延迟，需改变 `execute_checkin` 签名，超出测试补充范围
6. **e2e 测试定义**：poker_l1 的 phase1-7_integration.rs 已是 e2e 测试，不需额外创建 e2e_*.rs 文件
7. ** IPA/Groth16 Production stub**：设计性延迟（实现在 poker_zkvm），不视为 bug

## 验证方式

1. `cargo test -p poker_l1 --lib` — 1287 + 2 内联 = 1289 lib 测试通过
2. `cargo test -p poker_l1 --test soundness_tests` — 20 soundness 测试通过
3. `cargo test -p poker_l1 --test formal_properties` — 12 proptest 通过
4. `cargo test -p poker_l1 --tests` — 全部 integration + soundness + formal_properties 通过
5. `cargo clippy -p poker_l1 --all-targets -- -D warnings` — 0 warning
6. `cargo fmt -p poker_l1 --check` — 无 diff

## 不在范围内

- 创建独立 `e2e_*.rs` 测试文件（phase1-7_integration.rs 已覆盖）
- 实现 IPA/Groth16 Production verifier（在 poker_zkvm 中）
- 修复 `execute_checkin` 终局游戏 `proof_partial_hash` 清理（设计性延迟）
- 添加 bench（已有 task36_*_bench.rs）
- 修改 spec.md / tasks.md / checklist.md（除非测试发现 spec 与实现不一致）
