# Texas Poker 迁移 B.2-B.4 + 端到端验证执行计划

> **状态**：✅ 用户已批准（前次会话）+ 本次"继续"指令确认推进
> **前置**：A.1-A.5 已完成并验证（ObjectBackend + Snapshot + executor 泛型化 + build_block_from_vertex 接线 + Track A 验证）
> **范围**：完成用户 3-part 目标的剩余 3 个任务（B.2 / B.3 / B.4）+ 端到端验证
> **执行风格**：直接删除式替换（用户已确认 aggressive approach）

---

## 0. Progress Tracker（实时进度 — 2026-07-18 更新）

| 步骤 | 文件 | 状态 | 备注 |
|------|------|------|------|
| A.1-A.5 | object_backend.rs / object_db_snapshot.rs / executor.rs / node/mod.rs / main.rs | ✅ 已完成 | 前置工作已验证 |
| B.3 Step 1 | `texas_poker/utils.rs`（695 行） | ✅ 已完成 | 适配层（G1/Scalar 自由函数 + verify_or_skip + verify_pk_ownership + Transcript 工厂 + ElGamal 包装） |
| B.2 Step 3 | `texas_poker/types.rs`（786 行） | ✅ 已完成 | typed 化（ElGamalCiphertext 重导出 + Seat.pk/RevealTokenData.token/DecryptedCard/DeckState 等字段改 typed）+ Borsh derive + 测试改 borsh |
| B.2 Step 4 | `texas_poker/dispatch.rs`（885 行） | ⏳ 进行中 | 8 个 Args 结构 typed 化 + decode_args 改 borsh + derive Borsh |
| B.3 Step 2-6 | `texas_poker/state_machine.rs`（2814 行） | ❌ 待执行 | imports 替换 + 7 verify 集成点 + 30+ parse/serialize 调用点 + 工具函数简化 |
| B.2 Step 5 | `texas_poker/events.rs` + `side_pot.rs` | ❌ 待执行 | derive Borsh + bcs → borsh |
| B.2 Step 1-2 | 删除 `crypto/` 13 文件 + 修改 `mod.rs` | ❌ 待执行 | rm -rf crypto/ + 移除 `pub mod crypto;` + 新增 `pub mod utils;` |
| B.2+B.3 验证 | `cargo build -p poker_l1` + `cargo test -p poker_l1 --lib vm::contracts::texas_poker` | ❌ 待执行 | 阶段性编译 + 测试验证 |
| B.4.1 | 核心类型 derive Borsh（约 15 文件） | ❌ 待执行 | object_model/ + storage/ + block/ + consensus/ + transaction/ |
| B.4.2-3 | bcs → borsh 全局替换（35 文件）+ 测试更新 | ❌ 待执行 | rg "bcs::" 全替换 + 测试 roundtrip 改 borsh |
| 端到端验证 | `cargo build --workspace` + `cargo test --workspace` + `cargo clippy --workspace` + bcs 残留扫描 | ❌ 待执行 | 最终验证 |

**下一步行动**：执行 B.2 Step 4（dispatch.rs typed 化）。

---

## 1. Summary（任务总览）

本计划承接 A.4-A.5 已完成的 Tx 执行引擎接线工作，完成 3-part 目标的剩余部分：

1. **Task 1 替换**（B.2-B.3）：删除 `texas_poker/crypto/` 13 文件；`types.rs` + `dispatch.rs` Args 字段从 `Vec<u8>` 改为 typed `poker_protocol` 类型；`state_machine.rs` 改 `use poker_protocol::*`，新建 `utils.rs` 适配缺失函数；7 个 ZK verify 集成点改造。
2. **Task 2 迁移**（B.4）：全量 `bcs → borsh` 迁移（合约层 + Object 持久化层，破坏 on-disk 格式）。
3. **端到端验证**：`cargo build --workspace` + `cargo test --workspace` + `cargo clippy --workspace`。

---

## 2. Current State Analysis（当前状态分析 — 已验证）

### 2.1 texas_poker/crypto/ 目录（B.2 目标）

位置：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/crypto/`

**13 文件**（待全部删除）：
- `mod.rs`、`bls_elgamal.rs`、`bls_scalar.rs`、`chaum_pedersen.rs`、`leave_proof.rs`、`reconstruct_proof.rs`、`remask_proof.rs`、`reveal_token_proof.rs`、`schnorr_proof.rs`、`serialization.rs`、`shuffle_proof.rs`、`transcript.rs`、`zk_verifier.rs`

**与 poker_protocol 的功能重叠**：
- `bls_scalar.rs` → `poker_protocol::crypto::curve::{Bls12381Curve, Curve, CurveScalar}` + `poker_protocol::crypto::types::hash_to_scalar`
- `bls_elgamal.rs` → `poker_protocol::crypto::curve::ElGamalCiphertextGeneric<Bls12381Curve>` 的方法
- `shuffle_proof.rs` → `poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof<Bls12381Curve>`
- `remask_proof.rs` / `leave_proof.rs` → `poker_protocol::zk_shuffle::dleq_proof::DLEqProof<Bls12381Curve, {Remask,Leave}Kind>`
- `reveal_token_proof.rs` → `poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof<Bls12381Curve>`
- `reconstruct_proof.rs` → `poker_protocol::zk_shuffle::reconstruction::ReconstructProof<Bls12381Curve>`
- `schnorr_proof.rs` / `chaum_pedersen.rs` → `poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<Bls12381Curve>` + `reconstruction::chaum_pedersen::ChaumPedersenDLEQProof<Bls12381Curve>`
- `transcript.rs` → `poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript}`
- `serialization.rs` → borsh 已 impl 在 `poker_protocol::borsh_impls`（10 类型 roundtrip 通过）
- `zk_verifier.rs` → 部分适配层（`verify_or_skip` + `verify_pk_ownership`）需保留在新建的 `utils.rs`

### 2.2 state_machine.rs crypto 引用点（B.3 目标）

位置：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/state_machine.rs`（2814 行）

**imports（line 32-38）**：
```rust
use super::crypto::bls_elgamal as elgamal;
use super::crypto::bls_scalar::{
    self, g1_add, g1_equal, g1_generator, g1_is_identity, g1_sub, generate_plaintext_cards,
    hash_to_scalar, parse_g1, parse_scalar, scalar_from_u64, serialize_g1,
};
use super::crypto::serialization as ser;
use super::crypto::zk_verifier;
```

**verify_or_skip 调用点（7 处）**：
- line 1109：`skip_shuffle()` → `verify_pk_ownership`
- line 1145：`skip_remask()` → `super::crypto::remask_proof::verify`
- line 1153：`skip_shuffle()` → `super::crypto::shuffle_proof::verify`
- line 1243：`skip_shuffle()` → `super::crypto::shuffle_proof::verify`
- line 1343：`skip_reveal()` → `super::crypto::reveal_token_proof::verify`
- line 1490：`skip_reconstruct()` → `super::crypto::reconstruct_proof::verify`
- line 1560：`skip_remask()` → `super::crypto::leave_proof::verify`

**ser::deserialize_* 调用点（5 处）**：line 1118-1121、1232-1233

**parse_g1/serialize_g1 调用点**：约 30 处（line 55/56/67/201/203/205/214/220/238/241/264/282/918/920/923/950/951/1097/1131/1152/1242/1255/1307 等）

**工具函数（line 53-68）**：`bytes_ct_to_g1` / `g1_ct_to_bytes` / `pk_to_g1`（typed 化后大部分删除）

### 2.3 types.rs Vec<u8> 字段（B.2 目标）

位置：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs`（884 行）

**需 typed 化字段**：
| 结构体 | 字段 | 当前类型 | 新类型 |
|--------|------|----------|--------|
| `ElGamalCiphertext`（本地） | `c1`/`c2` | `Vec<u8>` | 删除本地类型，`pub use poker_protocol::crypto::types::ElGamalCiphertext;` |
| `Seat` | `pk` | `Vec<u8>` | `G1Projective` |
| `RevealTokenData` | `token` | `Vec<u8>` | `G1Projective` |
| `ReconstructState` | `coefficient` | `Vec<u8>` | `Option<Scalar>`（None = 未设置） |
| `DecryptedCard` | `ciphertext_bytes` | `Vec<u8>` | `Option<ElGamalCiphertext>`（None = 已完全解密） |
| `DecryptedCard` | `plaintext_bytes` | `Vec<u8>` | `Option<G1Projective>`（None = 仅部分解密） |
| `DeckState` | `aggregated_pk` | `Vec<u8>` | `Option<G1Projective>`（None = 未初始化） |
| `DeckState` | `plaintext` | `Vec<Vec<u8>>` | `Vec<G1Projective>` |

**保留字段**：`Seat.hand: Vec<Card>`（Card 是本地类型，非密码学点）

### 2.4 dispatch.rs Args 结构（B.2 目标）

位置：`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/dispatch.rs`（约 900 行）

**8 个 Args 结构需 typed 化**：
| 结构体 | 字段 | 当前类型 | 新类型 |
|--------|------|----------|--------|
| `JoinAndShuffleArgs` | `pk` | `Vec<u8>` | `G1Projective` |
| `JoinAndShuffleArgs` | `pk_ownership_proof` | `Vec<u8>` | 保留 `Vec<u8>`（80 字节 Schnorr 自定义格式） |
| `JoinAndShuffleArgs` | `mask_cards` | `Vec<u8>` | `Vec<ElGamalCiphertext>` |
| `JoinAndShuffleArgs` | `output_cards` | `Vec<u8>` | `Vec<ElGamalCiphertext>` |
| `JoinAndShuffleArgs` | `remask_proof` | `Vec<u8>` | `DLEqProof<DefaultCurve, RemaskKind>` |
| `JoinAndShuffleArgs` | `shuffle_proof` | `Vec<u8>` | `ZKShuffleProof<DefaultCurve>` |
| `LeaveWithProofArgs` | `output_cards` | `Vec<u8>` | `Vec<ElGamalCiphertext>` |
| `LeaveWithProofArgs` | `leave_proof` | `Vec<u8>` | `DLEqProof<DefaultCurve, LeaveKind>` |
| `JoinTableArgs` | `pk` | `Vec<u8>` | `G1Projective` |
| `SubmitShuffleV2Args` | `output_cards` | `Vec<u8>` | `Vec<ElGamalCiphertext>` |
| `SubmitShuffleV2Args` | `shuffle_proof` | `Vec<u8>` | `ZKShuffleProof<DefaultCurve>` |
| `SubmitRevealTokensArgs` | `reveal_tokens` | `Vec<Vec<u8>>` | `Vec<G1Projective>` |
| `SubmitRevealTokensArgs` | `proofs` | `Vec<Vec<u8>>` | `Vec<RevealTokenProof<DefaultCurve>>` |
| `SubmitReconstructDeckArgs` | `output_cards` | `Vec<u8>` | `Vec<ElGamalCiphertext>` |
| `SubmitReconstructDeckArgs` | `swap_cards` | `Vec<u8>` | `Vec<ElGamalCiphertext>` |
| `SubmitReconstructDeckArgs` | `user_readable_cards` | `Vec<u8>` | `Vec<ElGamalCiphertext>` |
| `SubmitReconstructDeckArgs` | `proof` | `Vec<u8>` | `ReconstructProof<DefaultCurve>` |

**Args 结构 derive 调整**：所有结构添加 `#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]`，保留 `serde::Serialize, Deserialize`（RPC 兼容）。

### 2.5 bcs 调用点分布（B.4 目标）

`rg "bcs::" --type rust` 确认 **35 个文件**含 bcs 调用：

| 区域 | 主要文件 | bcs 调用数 |
|------|----------|----------|
| Object 持久化 | `storage/object_db.rs`, `object_model/{id,object,ownership,store}.rs` | ~10 |
| Block/Vertex 持久化 | `storage/{block_store,dag_vertex_store}.rs`, `block/mod.rs`, `block/time_consensus.rs` | ~10 |
| Account | `account/mod.rs` | ~3 |
| 合约 dispatch | `vm/contracts/dispatch.rs`（19 处）, `vm/contracts/{game,texas_poker}_precompile.rs`, `vm/contracts/texas_poker/dispatch.rs` | ~25 |
| Texas poker 内部 | `vm/contracts/texas_poker/{events,side_pot,types}.rs` | ~5 |
| 共识 | `consensus/{mod,bullshark,routing,slashing,validator_set,vertex_production,game_assignment}.rs` | ~15 |
| 交易/签名 | `transaction/mod.rs`, `signature/tagged_pubkey.rs` | ~5 |
| VM syscalls | `vm/syscalls.rs` | ~3 |
| 同步/main | `sync/mod.rs`, `src/main.rs`, `network/mod.rs` | ~5 |
| error | `error.rs` | 2（类型引用） |

### 2.6 poker_protocol 已就绪 API

- **`/Users/mac/projects/zgame/poker_protocol/src/crypto/types.rs`**：`DefaultCurve = Bls12381Curve`、`EcPoint = G1Projective`、`Scalar = BlsScalar`、`ElGamalCiphertext = ElGamalCiphertextGeneric<DefaultCurve>`、`hash_to_scalar(digest) -> Scalar`（infallible）
- **`/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/shuffle_proof.rs:160`**：`ZKShuffleProof::verify(&self, input_cts, output_cts, pk, transcript) -> Result<(), VerificationError>`
- **`/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/dleq_proof.rs:244`**：`DLEqProof<C, K>::verify(&self, input_cts, output_cts, player_pk, transcript) -> bool`
- **`/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/reveal_token_proof.rs:107`**：`RevealTokenProof::verify(&self, encrypted_card, reveal_token, expected_pk, transcript) -> Result<(), RevealProofError>`
- **`/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/reconstruction/mod.rs:303`**：`ReconstructProof::verify(&self, cards, output_cards, swap_out_cards, user_readable_cards, user_pk, transcript) -> Result<(), VerificationError>`
- **`/Users/mac/projects/zgame/poker_protocol/src/zk_shuffle/transcript_ext.rs`**：`CryptoTranscript` trait + `MerlinTranscript` impl
- **`/Users/mac/projects/zgame/poker_protocol/src/borsh_impls.rs`**：10 类型 BorshSerialize/Deserialize 已 impl

### 2.7 已完成工作（无需重做）

| 文件 | 状态 |
|------|------|
| `/Users/mac/projects/zchain/Cargo.toml` | ✅ `poker_protocol = { path = "../zgame/poker_protocol", features = ["borsh"] }` + `borsh = "1.5"` |
| `/Users/mac/projects/zchain/poker_l1/Cargo.toml` | ✅ `poker_protocol = { workspace = true }` + `borsh = { workspace = true }` |
| `/Users/mac/projects/zgame/poker_protocol/src/borsh_impls.rs` | ✅ 10 类型 Borsh impl + 180 tests pass |
| `/Users/mac/projects/zchain/poker_l1/src/storage/object_backend.rs` | ✅ ObjectBackend trait |
| `/Users/mac/projects/zchain/poker_l1/src/storage/object_db_snapshot.rs` | ✅ ObjectDbSnapshot + 6 tests |
| `/Users/mac/projects/zchain/poker_l1/src/executor.rs` | ✅ `execute_block`/`execute_tx` 泛型化 `<B: ObjectBackend>` |
| `/Users/mac/projects/zchain/poker_l1/src/node/mod.rs` | ✅ `execute_block_on_state` + `precompile_registry()` |
| `/Users/mac/projects/zchain/src/main.rs` | ✅ `build_block_from_vertex` 接线 + `run_validator_loop` 调用 |

---

## 3. Proposed Changes（变更方案）

### B.2 — 删除 crypto/ 13 文件 + types.rs + dispatch.rs typed 化

#### B.2 Step 1：删除 crypto/ 目录

```bash
rm -rf /Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/crypto/
```

#### B.2 Step 2：修改 `texas_poker/mod.rs`

- 移除 `pub mod crypto;`（line 38）
- 新增 `pub mod utils;`（B.3 创建）
- 更新模块文档（line 19 `crypto` 描述改为 `utils`）

#### B.2 Step 3：修改 `types.rs`

**Step 3.1**：导入替换
```rust
// 删除：use serde::{Deserialize, Serialize};
// 新增：
use serde::{Deserialize, Serialize};
use borsh::{BorshSerialize, BorshDeserialize};
use blstrs::{G1Projective, Scalar as BlsScalar};
use poker_protocol::crypto::types::{ElGamalCiphertext as PpElGamalCiphertext, EcPoint as PpG1Projective, Scalar as PpScalar};
// 重导出 ElGamalCiphertext 供外部使用
pub use poker_protocol::crypto::types::ElGamalCiphertext;
```

**Step 3.2**：删除本地 `ElGamalCiphertext` 结构体（line 50-138）+ `G1_COMPRESSED_SIZE` 常量（line 41）+ 所有 `impl ElGamalCiphertext` 方法。

**Step 3.3**：typed 化各结构体字段（见 2.3 表格）。所有结构体 derive 添加 `BorshSerialize, BorshDeserialize`。

**Step 3.4**：调整默认值构造：
- `Seat::empty()` 的 `pk: vec![]` → `pk: G1Projective::identity()`
- `ReconstructState::default()` 的 `coefficient: vec![]` → `coefficient: None`
- `DecryptedCard` 的 `ciphertext_bytes: vec![]` → `ciphertext_bytes: None`，`plaintext_bytes: vec![]` → `plaintext_bytes: None`
- `DeckState::default()` 的 `aggregated_pk: vec![]` → `aggregated_pk: None`，`plaintext: vec![]` → `plaintext: vec![]`（保持空 Vec）

**Step 3.5**：更新 BCS roundtrip 测试（line 785+）：改 `bcs::to_bytes` → `borsh::to_vec`，`bcs::from_bytes` → `borsh::from_slice`。

#### B.2 Step 4：修改 `dispatch.rs`

**Step 4.1**：导入新增
```rust
use borsh::{BorshSerialize, BorshDeserialize};
use poker_protocol::crypto::types::{DefaultCurve, ElGamalCiphertext, EcPoint as G1Projective, Scalar as BlsScalar};
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, RemaskKind, LeaveKind};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::reconstruction::ReconstructProof;
```

**Step 4.2**：8 个 Args 结构字段 typed 化（见 2.4 表格），derive 添加 `BorshSerialize, BorshDeserialize`。

**Step 4.3**：`decode_args` 函数（line 379-382）：
```rust
fn decode_args<T: borsh::BorshDeserialize>(args: &[u8], method: &str) -> PokerL1Result<T> {
    borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("{method} args borsh: {e}")))
}
```

**Step 4.4**：dispatch 子函数改造（约 17 个）—— 移除手动 `ser::deserialize_*` 调用，直接使用 typed Args 字段。

#### B.2 Step 5：修改 `events.rs` + `side_pot.rs`

- 添加 `#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]` 到所有事件/边池结构
- `bcs::` → `borsh::` 调用替换（如存在）

---

### B.3 — state_machine.rs 改 use poker_protocol::* + utils.rs

#### B.3 Step 1：新建 `utils.rs`

```rust
//! poker_protocol 适配层 —— 吸收 crypto/ 与 poker_protocol 的 API 差异。
//!
//! 提供的函数：
//! - `verify_or_skip`：dev chain ZK skip 回退（保留原 zk_verifier 语义）
//! - `verify_pk_ownership`：80 字节 Schnorr proof of knowledge（自定义格式，保留）
//! - Transcript 工厂：`new_shuffle_transcript` 等（包装 MerlinTranscript::new）
//! - bytes↔G1 转换工具（parse_g1/serialize_g1 等，供 RPC 边界使用）
//! - G1/Scalar 自由函数包装（g1_add/g1_sub/g1_mul 等，最小化 state_machine.rs 改动）

use blstrs::{G1Projective, Scalar as BlsScalar};
use ff::Field;
use group::{Curve, GroupEncoding};
use sha3::{Digest, Sha3_256};
use subtle::CtOption;

use poker_protocol::crypto::curve::{Bls12381Curve, Curve, CurvePoint, CurveScalar};
use poker_protocol::crypto::types::DefaultCurve;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};

use crate::crypto_precompiles::bls::BLS_G1_DST;
use crate::error::{PokerL1Error, PokerL1Result};

// ========== 常量 ==========

pub const G1_COMPRESSED_SIZE: usize = 48;
pub const SCALAR_SIZE: usize = 32;
pub const N_CARDS: usize = 52;

// ========== Transcript 工厂 ==========

pub fn new_shuffle_transcript() -> MerlinTranscript {
    MerlinTranscript::new(b"zk_shuffle_proof_v1")
}
pub fn new_remask_transcript() -> MerlinTranscript {
    MerlinTranscript::new(b"zk_remask_proof_v1")
}
pub fn new_leave_transcript() -> MerlinTranscript {
    MerlinTranscript::new(b"zk_leave_proof_v1")
}
pub fn new_reconstruct_transcript() -> MerlinTranscript {
    MerlinTranscript::new(b"zk_reconstruct_proof_v1")
}
pub fn new_mask_shuffle_transcript() -> MerlinTranscript {
    MerlinTranscript::new(b"zk_mask_shuffle_proof_v1")
}

// ========== ZK skip 回退 ==========

pub fn verify_or_skip<F>(should_skip: bool, verify_fn: F) -> PokerL1Result<bool>
where
    F: FnOnce() -> PokerL1Result<bool>,
{
    if should_skip {
        return Ok(true);
    }
    verify_fn()
}

// ========== G1/Scalar 自由函数（blstrs 包装，与原 bls_scalar.rs API 一致） ==========

pub fn parse_g1(bytes: &[u8]) -> PokerL1Result<G1Projective> { /* ... */ }
pub fn serialize_g1(point: &G1Projective) -> [u8; 48] { point.to_compressed() }
pub fn parse_scalar(bytes: &[u8]) -> PokerL1Result<BlsScalar> { /* ... */ }
pub fn serialize_scalar(s: &BlsScalar) -> [u8; 32] { s.to_bytes_be() }
pub fn g1_generator() -> G1Projective { G1Projective::generator() }
pub fn g1_identity() -> G1Projective { G1Projective::identity() }
pub fn g1_equal(a: &G1Projective, b: &G1Projective) -> bool { a == b }
pub fn g1_is_identity(p: &G1Projective) -> bool { p.is_identity().into() }
pub fn g1_add(a: &G1Projective, b: &G1Projective) -> G1Projective { a + b }
pub fn g1_sub(a: &G1Projective, b: &G1Projective) -> G1Projective { a - b }
pub fn g1_mul(s: &BlsScalar, p: &G1Projective) -> G1Projective { p * s }
pub fn scalar_from_u64(x: u64) -> BlsScalar { BlsScalar::from(x) }
pub fn scalar_zero() -> BlsScalar { BlsScalar::ZERO }
pub fn scalar_one() -> BlsScalar { BlsScalar::ONE }
pub fn hash_to_scalar(data: &[u8]) -> PokerL1Result<BlsScalar> { /* SHA3-256 + 清高 2 位 */ }
pub fn hash_to_g1(msg: &[u8]) -> G1Projective { G1Projective::hash_to_curve(msg, BLS_G1_DST, &[]) }
pub fn generate_plaintext_cards() -> Vec<G1Projective> { /* 0..52 hash_to_g1 */ }
pub fn verify_dleq(g, pk, commitment, s, c) -> bool { /* s*G == commitment + c*pk */ }

// ========== PK 所有权证明（80 字节 Schnorr，自定义格式保留） ==========

pub fn verify_pk_ownership(pk: &G1Projective, proof_bytes: &[u8]) -> bool {
    // 保留原 zk_verifier::verify_pk_ownership 实现
    // 80 字节 = 48 commitment + 32 response
    // challenge = hash_to_scalar(G || pk || commitment)
    // verify_dleq(g, pk, commitment, response, challenge)
}

// ========== ElGamal 操作（包装 ElGamalCiphertextGeneric 方法） ==========

use poker_protocol::crypto::types::ElGamalCiphertext;

pub fn encrypt(plaintext: &G1Projective, pk: &G1Projective, r: &BlsScalar) -> ElGamalCiphertext {
    ElGamalCiphertext::encrypt(plaintext, pk, r)
}
pub fn re_encrypt(ct: &ElGamalCiphertext, pk: &G1Projective, r: &BlsScalar) -> ElGamalCiphertext { /* ... */ }
pub fn decrypt(ct: &ElGamalCiphertext, sk: &BlsScalar) -> G1Projective { /* ... */ }
pub fn gen_reveal_token(ct: &ElGamalCiphertext, sk: &BlsScalar) -> G1Projective { /* ... */ }
pub fn remask(ct: &ElGamalCiphertext, sk: &BlsScalar) -> PokerL1Result<ElGamalCiphertext> { /* ... */ }
pub fn add_pk_to_c2(ct: &ElGamalCiphertext, player_pk: &G1Projective) -> ElGamalCiphertext { /* ... */ }
```

**utils.rs 设计要点**：
1. 保留所有原 `crypto/bls_scalar.rs` 自由函数 API（`parse_g1`/`serialize_g1`/`g1_add` 等），最小化 state_machine.rs 改动
2. `verify_pk_ownership` 保留 80 字节 Schnorr 自定义格式（poker_protocol 的 `GeneralizedSchnorrProof` 是不同格式，不替换）
3. `verify_or_skip` 从原 `zk_verifier.rs` 移植
4. Transcript 工厂改为返回 `MerlinTranscript`（poker_protocol 类型）
5. ElGamal 操作包装 `ElGamalCiphertextGeneric` 方法（内部 `c1 = r·G, c2 = M + r·pk` 等不变）

#### B.3 Step 2：替换 state_machine.rs imports（line 27-48）

```rust
// 删除：use super::crypto::bls_elgamal as elgamal;
// 删除：use super::crypto::bls_scalar::{...};
// 删除：use super::crypto::serialization as ser;
// 删除：use super::crypto::zk_verifier;

// 新增：
use poker_protocol::crypto::types::{
    DefaultCurve, ElGamalCiphertext, EcPoint as G1Projective, Scalar as BlsScalar,
};
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, RemaskKind, LeaveKind};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::reconstruction::ReconstructProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};
use super::utils;  // 适配层（g1_add/g1_sub/parse_g1/verify_pk_ownership/verify_or_skip 等）

// 显式导入自由函数（与原 API 一致）
use super::utils::{
    g1_add, g1_equal, g1_generator, g1_is_identity, g1_sub, generate_plaintext_cards,
    hash_to_scalar, parse_g1, parse_scalar, scalar_from_u64, serialize_g1,
};
```

#### B.3 Step 3：工具函数简化（line 53-68）

typed 化后，`bytes_ct_to_g1` / `g1_ct_to_bytes` / `pk_to_g1` 大部分不再需要（字段已是 G1Projective）。仅保留少量 RPC 边界转换函数。

#### B.3 Step 4：7 个 ZK verify 集成点改造

**改造映射**：

| 集成点 | 当前调用 | 新调用 |
|--------|----------|--------|
| line 1109 `verify_pk_ownership` | `zk_verifier::verify_pk_ownership(&pk_pt, &_pk_ownership_proof)` | `utils::verify_pk_ownership(&pk_pt, &_pk_ownership_proof)` |
| line 1118-1121 `ser::deserialize_*` | `ser::deserialize_ciphertexts(&mask_cards)?` 等 | 删除（Args 已 typed，字段直接是 `Vec<ElGamalCiphertext>` / `DLEqProof<DefaultCurve, RemaskKind>` 等） |
| line 1145 `verify_or_skip` + remask_proof | `super::crypto::remask_proof::verify(&remask_proof, &input_cts, &mask_cts, &pk_pt, &mut t)` | `DLEqProof::<DefaultCurve, RemaskKind>::verify(&remask_proof, &input_cts, &mask_cts, &pk_pt, &mut t)` |
| line 1153 `verify_or_skip` + shuffle_proof | `super::crypto::shuffle_proof::verify(&shuffle_proof, &mask_cts, &output_cts, &new_agg_pk_pt, &mut t)` | `ZKShuffleProof::verify(&shuffle_proof, &mask_cts, &output_cts, &new_agg_pk_pt, &mut t).map_err(|e| PokerL1Error::Serialization(format!("shuffle proof: {e}")))?; Ok(true)` |
| line 1243 `verify_or_skip` + shuffle_proof | 同上 | 同上 |
| line 1343 `verify_or_skip` + reveal_token | `super::crypto::reveal_token_proof::verify(&proof, &encrypted_card, &reveal_token, &expected_pk)` | `RevealTokenProof::verify(&proof, &encrypted_card, &reveal_token, &expected_pk, &mut MerlinTranscript::new(b"reveal_token_proof_v3")).map_err(...)?; Ok(true)` |
| line 1490 `verify_or_skip` + reconstruct | `super::crypto::reconstruct_proof::verify(&proof, cards, output_cards, swap_out_cards, user_readable_cards, user_pk, &mut t)` | `ReconstructProof::verify(&proof, cards, output_cards, swap_out_cards, user_readable_cards, user_pk, &mut t).map_err(...)?; Ok(true)` |
| line 1560 `verify_or_skip` + leave_proof | `super::crypto::leave_proof::verify(&leave_proof, &input_cts, &output_cts, &player_pk, &mut t)` | `DLEqProof::<DefaultCurve, LeaveKind>::verify(&leave_proof, &input_cts, &output_cts, &player_pk, &mut t)` |

**返回值适配**：
- `DLEqProof::verify` 返回 `bool` → 直接返回 `Ok(bool)`
- `ZKShuffleProof::verify` / `RevealTokenProof::verify` / `ReconstructProof::verify` 返回 `Result<(), _>` → `.map_err(...)?; Ok(true)` 转 `PokerL1Result<bool>`

#### B.3 Step 5：parse_g1/serialize_g1 调用点适配

typed 化后大部分 `parse_g1`/`serialize_g1` 调用可删除（字段已是 G1Projective）。保留少数 RPC 边界转换。具体：
- `parse_g1(&ct.c1)`（line 55-56）→ 删除（c1 已是 G1Projective）
- `parse_g1(pk_bytes)`（line 67）→ 删除（pk 已是 G1Projective）
- `serialize_g1(new_pk).to_vec()`（line 201）→ 删除（new_pk 已是 G1Projective）
- `serialize_g1(&g), serialize_g1(m)`（line 238）→ 改 `ElGamalCiphertext::new(g, *m)`
- `serialize_g1(m).to_vec()`（line 241）→ 改 `*m`（plaintext 字段已是 Vec<G1Projective>）
- 以此类推，约 30 处需要逐个改造

#### B.3 Step 6：transcript 适配

所有 `zk_verifier::new_*_transcript()` → `utils::new_*_transcript()`（返回 `MerlinTranscript`，impl `CryptoTranscript`）。

---

### B.4 — 全量 borsh 迁移

#### B.4.1：核心类型 derive 添加

为以下类型添加 `#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]`：

| 文件 | 类型 |
|------|------|
| `object_model/id.rs` | `ObjectID` |
| `object_model/object.rs` | `Object` |
| `object_model/ownership.rs` | `Ownership` |
| `account/mod.rs` | `Account` |
| `block/mod.rs` | `Block`, `BlockHeader` |
| `block/time_consensus.rs` | 时间共识相关结构 |
| `transaction/mod.rs` | `Transaction`, `TxRequest`, `Gas`, `ContractCall`, `RouteHint`, `TxLane` |
| `signature/tagged_pubkey.rs` | `TaggedPubkey` |
| `consensus/mod.rs` | `DagVertex`, `DagCommitCertificate`, `ValidatorEntry`, `ValidatorSet` 等 |
| `consensus/{bullshark,routing,slashing,validator_set,vertex_production,game_assignment}.rs` | 各自结构体 |
| `vm/contracts/texas_poker/types.rs` | 所有结构体（B.2 已涉及） |
| `vm/contracts/texas_poker/dispatch.rs` | 8 个 Args 结构（B.2 已涉及） |
| `vm/contracts/texas_poker/{events,side_pot}.rs` | 事件 + 边池结构 |
| `vm/contracts/dispatch.rs` | `GameContract` |
| `vm/syscalls.rs` | `MerklePath` 等 |
| `storage/{object_db,block_store,dag_vertex_store,mod}.rs` | 存储相关结构 |

**orphan rule 处理**：
- 本地 newtype（`Address = [u8; 20]`, `Hash = [u8; 32]`）直接 derive
- 外部类型（`G1Projective`, `BlsScalar`）已在 `poker_protocol::borsh_impls` 中 impl（B.1 完成）
- `secp256k1::SecretKey`、`PublicKey` 等外部类型：用 newtype 包装或自定义 impl

#### B.4.2：bcs → borsh 调用替换（35 文件）

全局替换规则：
- `bcs::to_bytes(&x)` → `borsh::to_vec(&x)`
- `bcs::from_bytes::<T>(b)` → `borsh::from_slice::<T>(b)`
- `bcs::from_bytes(b)`（省略类型）→ `borsh::from_slice(b)`

**错误类型适配**：
- `bcs::Error` → `borsh::io::Error`
- 所有 `.map_err(|e| PokerL1Error::Serialization(format!("...: {e}")))` 处保持不变（`format!` 兼容任何 Display）

**关键文件改造示例**：

`vm/contracts/dispatch.rs`（19 处 bcs 调用）：
```rust
// 旧：let input: CreateTableInput = bcs::from_bytes(args)
//     .map_err(|e| PokerL1Error::Serialization(format!("hand_started: {e}")))?;
// 新：let input: CreateTableInput = borsh::from_slice(args)
//     .map_err(|e| PokerL1Error::Serialization(format!("hand_started: {e}")))?;

// 旧：let return_value = bcs::to_bytes(&result)
//     .map_err(|e| PokerL1Error::Serialization(format!("...: {e}")))?;
// 新：let return_value = borsh::to_vec(&result)
//     .map_err(|e| PokerL1Error::Serialization(format!("...: {e}")))?;
```

`storage/object_db.rs`（5 处 bcs 调用）：相同模式。

`error.rs`（2 处 `bcs::Error` 类型引用）：
```rust
// 旧：impl From<bcs::Error> for PokerL1Error { ... }
// 新：impl From<borsh::io::Error> for PokerL1Error { ... }
```

#### B.4.3：测试更新

所有测试中 `bcs::to_bytes(&x).unwrap()` → `borsh::to_vec(&x).unwrap()`，`bcs::from_bytes(&b).unwrap()` → `borsh::from_slice(&b).unwrap()`。

#### B.4.4：依赖清理

- `/Users/mac/projects/zchain/Cargo.toml`：保留 `bcs` 依赖（兼容期，避免破坏尚未迁移的第三方代码路径）
- 最终移除 `bcs` 留待下一期

---

## 4. Assumptions & Decisions（假设与决策）

### 决策

1. **B.2 ElGamalCiphertext 处理**：**删除本地类型，全局改用 `poker_protocol::crypto::types::ElGamalCiphertext`**（= `ElGamalCiphertextGeneric<Bls12381Curve>`，字段 `c1/c2: G1Projective`）。`types.rs` 顶部 `pub use poker_protocol::crypto::types::ElGamalCiphertext;` 重导出。

2. **B.2 Args typed 化**：**8 个 Args 结构全部 typed 化**（pk/ciphertexts/proofs 用 poker_protocol 类型）。理由：B.4 已破坏 wire format 改 borsh，同时 typed 化可消除 state_machine.rs 中所有 `ser::deserialize_*` 调用，最简化 B.3 改造。

3. **B.2 Option 表示"未设置"**：`ReconstructState.coefficient`、`DeckState.aggregated_pk`、`DecryptedCard.ciphertext_bytes`/`plaintext_bytes` 用 `Option<T>` 替代空 `Vec<u8>` 表示"未设置"。`G1Projective::identity()` 不用于"未设置"（语义混淆）。

4. **B.3 utils.rs 保留自由函数 API**：**保留 `parse_g1`/`serialize_g1`/`g1_add`/`g1_sub` 等自由函数**（blstrs 包装），最小化 state_machine.rs 改动。理由：原代码用自由函数风格，全改 trait 方法调用（`C::base_g()`、`p.compress()` 等）会大幅增加 B.3 改动量。

5. **B.3 verify_pk_ownership 保留 80 字节自定义格式**：**不替换为 `GeneralizedSchnorrProof`**。理由：80 字节格式（commitment 48 + response 32）是合约 wire format 的一部分，poker_protocol 的 `GeneralizedSchnorrProof` 是不同格式（commitment + Vec<responses>），替换会破坏客户端兼容。

6. **B.3 verify_or_skip 保留语义**：**保留 dev chain ZK skip 回退**。`utils::verify_or_skip(should_skip, verify_fn)` 与原 `zk_verifier::verify_or_skip` 签名一致。

7. **B.4 bcs 依赖保留**：**本期不移除 `bcs` Cargo 依赖**。理由：避免破坏尚未迁移的第三方代码路径；最终移除留待下一期。

8. **B.4 on-disk 格式破坏**：用户已确认全量迁移，部署时需清空 `~/.zchain/data` 等数据目录。

### 假设

1. **poker_protocol verify API 签名兼容** —— B.3 改造时若发现签名差异（如 transcript 参数类型），在 utils.rs 中适配。Phase 1 已确认所有 4 个 proof 类型的 verify 签名。
2. **borsh 1.5 API**：`borsh::to_vec(&T) -> Result<Vec<u8>, borsh::io::Error>` + `borsh::from_slice(&[u8]) -> Result<T, borsh::io::Error>`，derive 宏 `BorshSerialize, BorshDeserialize`。
3. **poker_protocol borsh_impls 已覆盖所有 proof 类型** —— Phase 1 已确认 10 类型 impl（含 ZKShuffleProof/DLEqProof/RevealTokenProof/ReconstructProof/ElGamalCiphertext 等）。
4. **typed Args 不破坏 PrecompileRegistry 调用约定** —— `Precompile::call(args: &[u8])` 仍接收字节，Args 在 dispatch.rs 内部 `borsh::from_slice` 反序列化为 typed 结构。
5. **state_machine.rs 2814 行改造量大** —— B.3 采用"逐集成点改造 + 每步编译验证"策略，保留 `verify_or_skip` 回退降低回归风险。

---

## 5. Verification Steps（验证步骤）

### 阶段验证

| 阶段 | 命令 | 期望 |
|------|------|------|
| B.2 完成 | `cargo build -p poker_l1 2>&1 \| tail -30` | 0 error（state_machine.rs 此时引用 crypto/ 失败，预期错误，需 B.3 同步进行） |
| B.2 + B.3 完成 | `cargo build -p poker_l1 2>&1 \| tail -50` | 0 error |
| B.2 + B.3 测试 | `cargo test -p poker_l1 --lib vm::contracts::texas_poker 2>&1 \| tail -30` | texas_poker 测试全过 |
| B.4 完成 | `cargo build --workspace 2>&1 \| tail -50` | 0 error |
| B.4 测试 | `cargo test --workspace 2>&1 \| tail -50` | 全部测试通过 |
| 最终 clippy | `cargo clippy --workspace -- -D warnings 2>&1 \| tail -30` | 0 warning |

### 端到端验证

```bash
# 1. 清空旧数据目录（on-disk 格式破坏）
rm -rf ~/.zchain/data  # 路径按实际 node 配置调整

# 2. 全量构建
cd /Users/mac/projects/zchain
cargo build --workspace 2>&1 | tee /tmp/build.log
# 期望：Compiling ... Finished

# 3. 全量测试
cargo test --workspace 2>&1 | tee /tmp/test.log
# 期望：test result: ok. N passed; 0 failed

# 4. Clippy
cargo clippy --workspace -- -D warnings 2>&1 | tee /tmp/clippy.log
# 期望：Finished

# 5. 二次扫描 bcs 残留
rg "bcs::" --type rust | tee /tmp/bcs_residual.log
# 期望：0 行（或仅 error.rs 的 From<borsh::io::Error> impl）
```

### 关键回归点

- **poker_protocol roundtrip**：`borsh_impls.rs` 的 10 类型 roundtrip 测试全过
- **texas_poker 单元测试**：`poker_l1/src/vm/contracts/texas_poker/state_machine.rs` 的 19 个 `#[test]` 全过
- **executor 单元测试**：`poker_l1/src/executor.rs` 的 28 个测试全过
- **ObjectDbSnapshot 测试**：`object_db_snapshot.rs` 的 6 个测试全过
- **texas_poker BCS roundtrip 测试**（line 785+）：改 borsh 后 roundtrip 仍通过
- **build_block_from_vertex**：产块后 state_root 应反映 tx 执行结果（非 prev_state_root）

---

## 6. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| poker_protocol verify API 签名不兼容 | B.3 阻塞 | Phase 1 已确认所有 4 个 proof verify 签名；utils.rs 适配 Result → PokerL1Result<bool> |
| typed Args 破坏客户端兼容 | 客户端需同步更新 | 用户已确认全量迁移；文档明确 wire format 变更 |
| borsh derive 对外部类型失败 | B.4 阻塞 | G1Projective/Scalar 已在 B.1 impl；本地 newtype 直接 derive；secp256k1 类型用 newtype 包装 |
| typed 字段破坏现有序列化测试 | B.2 测试失败 | 逐个测试更新；保留 serde 兼容 |
| state_machine.rs 2814 行改造量大 | B.3 回归风险 | 逐集成点改造 + 每步 `cargo build -p poker_l1` 验证；保留 `verify_or_skip` 回退 |
| bcs → borsh 全局替换遗漏 | B.4 编译失败 | `rg "bcs::" --type rust` 二次扫描确认零残留 |
| on-disk 格式破坏导致旧数据无法读取 | 部署阻塞 | 文档明确要求清空数据目录 |
| `error.rs` 的 `From<bcs::Error>` impl 失效 | 编译失败 | 改为 `From<borsh::io::Error>` |
| `G1Projective`/`Scalar` orphan rule | 无法在 poker_l1 derive Borsh | 已在 poker_protocol::borsh_impls impl；poker_l1 直接使用 |

---

## 7. 执行顺序

```
B.2（删除 crypto/ + types.rs typed 化 + dispatch.rs Args typed 化）
  │
  │  ⚠️ B.2 删除 crypto/ 后 state_machine.rs 立即编译失败
  │  ⇒ B.2 + B.3 必须作为原子单元执行（同步进行）
  ▼
B.3（新建 utils.rs + state_machine.rs 改 use poker_protocol::* + 7 集成点改造）
  │
  ▼
B.2 + B.3 阶段验证（cargo build -p poker_l1 + cargo test -p poker_l1 --lib vm::contracts::texas_poker）
  │
  ▼
B.4（全量 borsh 迁移：35 文件 bcs → borsh + derive Borsh）
  │
  ▼
端到端验证（cargo build --workspace + cargo test --workspace + cargo clippy --workspace）
```

**B.2 + B.3 原子执行理由**：
- B.2 删除 crypto/ 后 state_machine.rs 的 `use super::crypto::*` 立即编译失败
- B.3 的 utils.rs 必须在 crypto/ 删除后立即就位，否则无法编译
- 因此 B.2 + B.3 作为不可分割的原子单元执行，中间不分开编译

**B.4 串行执行理由**：
- B.4 依赖 B.2（texas_poker types 需先 typed 化才能 derive Borsh）
- B.4 是机械性替换，可在 B.2-B.3 验证通过后独立进行

---

## 8. 文件变更清单

### 新建文件（1）
1. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/utils.rs` — poker_protocol 适配层（~300 行）

### 删除文件（13）
`/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/crypto/` 整个目录：
- mod.rs, bls_elgamal.rs, bls_scalar.rs, chaum_pedersen.rs, leave_proof.rs, reconstruct_proof.rs, remask_proof.rs, reveal_token_proof.rs, schnorr_proof.rs, serialization.rs, shuffle_proof.rs, transcript.rs, zk_verifier.rs

### 修改文件（关键）

**B.2-B.3 阶段**：
1. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/mod.rs` — 移除 `pub mod crypto;`，新增 `pub mod utils;`
2. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/types.rs` — Vec<u8> → typed + derive Borsh + 删除本地 ElGamalCiphertext
3. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/dispatch.rs` — 8 个 Args typed 化 + decode_args 改 borsh + derive Borsh
4. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/state_machine.rs` — use poker_protocol::* + 7 verify 集成点 + 30+ parse_g1/serialize_g1 调用点改造
5. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/events.rs` — derive Borsh + bcs → borsh
6. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/side_pot.rs` — derive Borsh + bcs → borsh

**B.4 阶段**（35 文件 bcs → borsh + derive Borsh）：
7. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/dispatch.rs` — 19 处 bcs → borsh + GameContract derive
8. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/{game,texas_poker}_precompile.rs` — bcs → borsh
9. `/Users/mac/projects/zchain/poker_l1/src/object_model/{id,object,ownership,store}.rs` — derive Borsh + bcs → borsh
10. `/Users/mac/projects/zchain/poker_l1/src/storage/{object_db,block_store,dag_vertex_store,mod}.rs` — bcs → borsh
11. `/Users/mac/projects/zchain/poker_l1/src/{block,account,consensus,sync,signature,transaction,network}/*.rs` — derive Borsh + bcs → borsh
12. `/Users/mac/projects/zchain/poker_l1/src/vm/syscalls.rs` — bcs → borsh + MerklePath derive
13. `/Users/mac/projects/zchain/poker_l1/src/error.rs` — `From<bcs::Error>` → `From<borsh::io::Error>`
14. `/Users/mac/projects/zchain/src/main.rs` — bcs → borsh（3 处）

---

## 9. 实施检查清单（TodoWrite）

- [ ] **b2-types**: B.2 types.rs typed 化（删除本地 ElGamalCiphertext + 8 个结构体字段改 typed + derive Borsh）
- [ ] **b2-dispatch**: B.2 dispatch.rs 8 个 Args 结构 typed 化 + decode_args 改 borsh + derive Borsh
- [ ] **b2-events-sidepot**: B.2 events.rs + side_pot.rs derive Borsh + bcs → borsh
- [ ] **b3-utils**: B.3 新建 utils.rs（适配层：~300 行）
- [ ] **b3-state-machine**: B.3 state_machine.rs 改 use poker_protocol::* + 7 verify 集成点 + 30+ parse/serialize 调用点
- [ ] **b2-b3-verify**: B.2+B.3 阶段验证（cargo build -p poker_l1 + cargo test -p poker_l1 --lib vm::contracts::texas_poker）
- [ ] **b2-delete-crypto**: B.2 删除 crypto/ 13 文件 + 修改 mod.rs
- [ ] **b4-derive**: B.4.1 核心类型 derive Borsh 添加（约 15 文件）
- [ ] **b4-replace**: B.4.2 bcs → borsh 全局替换（35 文件）
- [ ] **b4-tests**: B.4.3 测试更新
- [ ] **verify-final**: 端到端验证（cargo build --workspace + cargo test --workspace + cargo clippy --workspace + bcs 残留扫描）

---

## 10. 备注

### 关于 B.2 + B.3 原子执行

由于删除 `crypto/` 后 `state_machine.rs` 立即无法编译，B.2 + B.3 必须作为原子单元执行。推荐执行顺序：

1. **先创建 utils.rs**（B.3 Step 1）—— 不破坏现有编译
2. **改造 types.rs**（B.2 Step 3）—— 加 `pub use poker_protocol::crypto::types::ElGamalCiphertext;` + typed 化字段
3. **改造 dispatch.rs**（B.2 Step 4）—— Args typed 化
4. **改造 state_machine.rs**（B.3 Step 2-6）—— imports + 7 集成点 + 30+ 调用点
5. **改造 events.rs + side_pot.rs**（B.2 Step 5）
6. **删除 crypto/ 目录**（B.2 Step 1）+ 修改 mod.rs（B.2 Step 2）
7. **`cargo build -p poker_l1`** 验证编译通过
8. **`cargo test -p poker_l1 --lib vm::contracts::texas_poker`** 验证测试通过

### 关于 typed 字段的 Default 实现

`G1Projective` 已实现 `Default`（返回 identity）。`Option<T>` 默认 `None`。`Vec<T>` 默认 `vec![]`。所有 typed 字段的 `Default` 实现自然满足。

### 关于 poker_protocol 的 ElGamalCiphertext API

`poker_protocol::crypto::types::ElGamalCiphertext`（= `ElGamalCiphertextGeneric<Bls12381Curve>`）提供的方法：
- `encrypt(plaintext, pk, r) -> Self`
- `decrypt(sk) -> Option<EcPoint>`（注意：返回 Option，原 crypto/ 返回 G1Projective）
- `re_encrypt(pk, r) -> Self`
- `is_valid() -> bool`
- `new_placeholder_card() -> Self`（c1 = c2 = identity）

注意 `decrypt` 返回 `Option`，与原 `crypto::bls_elgamal::decrypt` 不同（原版直接返回 G1Projective）。在 state_machine.rs 中调用 decrypt 时需处理 Option。

### 关于 pk_ownership_proof 字段

`JoinAndShuffleArgs.pk_ownership_proof: Vec<u8>` 保留为 `Vec<u8>`（80 字节 Schnorr 自定义格式），不