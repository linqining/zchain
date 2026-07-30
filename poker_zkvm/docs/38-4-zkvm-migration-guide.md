# ZKVM 迁移指南 — 从 hash-based CcsInstance 到 Fr-based 新类型

> 文档编号：38-4
> 对应 spec：spec.md L810-852（v1.4 FROZEN，v1.2 诚实 BREAKING 声明）
> 对应任务：Phase 11 Task 11.1 / SubTask 10.5.2 / SubTask 10.5.3（部分延至 Phase 11b）

## 1. 概述

zchain 的 OffChain 模式原先使用 `poker_l1::offline::ccs::CcsInstance`（hash-based）作为 CCS 实例类型，仅以 blake2b 哈希链冒充折叠。Phase 6 在 `poker_zkvm` 实现了真实的 Hypernova 折叠算法，需要携带完整矩阵结构与域元素 witness 的新类型 `poker_zkvm::ccs::CcsInstance`（Fr-based）。

**这是一个 BREAKING 变更**：旧类型无法透明兼容新折叠算法，所有既有调用方必须迁移到新类型。本指南说明迁移背景、新旧类型差异、迁移步骤与失败语义。

## 2. 迁移背景

### 2.1 为什么需要迁移

旧 `poker_l1::offline::ccs::CcsInstance` 仅存储 4 个 `Hash` 字段：

```rust
// poker_l1/src/offline/ccs.rs:33-44（已标记 #[deprecated]）
pub struct CcsInstance {
    pub mat_commitments: Vec<Hash>,       // 矩阵承诺列表
    pub public_input_hash: Hash,          // 公共输入哈希
    pub witness_commitment: Hash,         // witness 承诺
    pub state_delta_hash: Hash,           // 状态增量哈希
    pub ack_step_hash: Hash,              // ack 步骤哈希
}
```

哈希是单向的，**无法从哈希恢复原始矩阵内容**。真实 Hypernova 折叠需要在 fold step 中读取矩阵 `M_j`、witness `z` 与公共输入 `x`，进行矩阵-向量乘积与多线性扩展求值，因此必须采用携带完整数据的新类型。

### 2.2 新类型定义

新 `poker_zkvm::ccs::CcsInstance` 直接存储约束结构与域元素：

```rust
// poker_zkvm/src/ccs/mod.rs:462-470
pub struct CcsInstance {
    pub ccs: Ccs,                  // 约束结构（矩阵 M_j / 子集 S_i / 系数 c_i）
    pub witness: Vec<Fr>,          // 见证向量 z（长度 = ccs.num_vars）
    pub public_inputs: Vec<Fr>,    // 公共输入（BN254 标量域元素）
}
```

其中 `Ccs` 包含稀疏矩阵列表、子集列表与系数列表，是 fold 算法的直接输入。

### 2.3 trait 签名变更

`CcsCircuit` trait 同步迁移，方法签名从 `&[u8]` 改为 `&[Fr]`：

| 项目 | 旧签名（poker_l1，已 deprecated） | 新签名（poker_zkvm） |
|------|-----------------------------------|----------------------|
| 生成实例方法 | `to_instance(&self, witness: &[u8], public_inputs: &[u8], state_delta: &[u8], ack_step_hash: Hash) -> Result<CcsInstance, PokerL1Error>` | `to_ccs_instance(&self, witness: &[Fr], public_inputs: &[Fr]) -> Result<CcsInstance, ZkvmError>` |
| 返回类型 | `poker_l1::offline::ccs::CcsInstance`（hash-based） | `poker_zkvm::ccs::CcsInstance`（Fr-based） |
| 错误类型 | `PokerL1Error` | `ZkvmError` |

## 3. 当前迁移状态

### 3.1 已完成（Phase 10 / Phase 11a）

| 项目 | 状态 | 位置 |
|------|------|------|
| 新 `CcsInstance` 类型 | 完成 | [poker_zkvm/src/ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs) |
| 新 `CcsCircuit` trait | 完成 | [poker_zkvm/src/precompiles/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs) |
| `ZkShuffleCcsCircuit` stub 迁移 | 完成（stub） | [poker_zkvm/src/precompiles/zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs) |
| 旧类型 `#[deprecated]` 标记 | 完成 | [poker_l1/src/offline/ccs.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/ccs.rs) |
| `CheckinTx.proof_kind` 字段 + signing_hash 1-byte 前缀 | 完成 | `poker_l1/src/state.rs` |
| `execute_checkin` 分派 `zk_verify_with_context` | 完成 | `poker_l1/src/state.rs` |

### 3.2 延期至 Phase 11b（HARD BREAKING 迁移）

以下 SubTask 因新旧 `CcsCircuit` trait 签名不兼容（`to_instance` u8-based vs `to_ccs_instance` Fr-based），须单独进行 HARD BREAKING 迁移：

| SubTask | 描述 | 延期理由 |
|---------|------|----------|
| 10.5.2 | `poker_l1` 替换为 `pub use poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit;` | 新旧 trait 签名不兼容 |
| 10.5.3 | 更新 `phase5a_integration.rs` + `task36_zk_verifier.rs` bench 引用路径 | 同上 |
| 11.1.1 | 旧 `CcsInstance` 标记 `#[deprecated]` | 已部分完成 |
| 11.1.2 | `LegacyCcsInstanceAdapter` | 仅用于过渡期编译兼容 |
| 11.1.3 | `fold_step` 内部调用 `poker_zkvm::fold::fold_step` | 外部 trait 签名变更 |
| 11.1.4 | `fold_loop` 内部调用 `poker_zkvm::fold::fold_loop` | 同 11.1.3 |
| 11.1.5 | 移除 blake2b 哈希链冒充逻辑 | 依赖 11.1.3/11.1.4 |
| 11.1.6 | `CcsCircuit` trait 迁入 `poker_zkvm::precompiles`，`poker_l1` re-export | 依赖 11.1.2 |
| 11.1.7 | 更新既有单元测试断言为真实折叠语义 | 依赖 11.1.3/11.1.4 |

Phase 11a 已完成 Task 11.2（`CheckinTx` / `PartialCheckinTx` proof_kind 序列化 + scheme_id 映射），与 Task 11.1 解耦。

## 4. 迁移步骤

### 4.1 调用方迁移路径

旧调用方迁移到新类型的典型步骤：

1. **替换 import**：将 `use poker_l1::offline::ccs::{CcsCircuit, CcsInstance, ZkShuffleCcsCircuit};` 改为 `use poker_zkvm::precompiles::{CcsCircuit, CcsInstance, zk_shuffle::ZkShuffleCcsCircuit};`

2. **witness / public_inputs 编码变更**：从 `&[u8]` 改为 `&[Fr]`。BN254 标量域 `Fr` 可通过 `Fr::from_canonical_bytes(&bytes[0..32])` 或 `Fr::from_u32_with_wrap(n)` 构造。

3. **方法名变更**：`to_instance(...)` 改为 `to_ccs_instance(...)`，参数从 4 个减为 2 个（去掉 `state_delta` 与 `ack_step_hash`，二者在新类型中不再作为 CcsInstance 字段，改为 `ZkPublicIo` 的公共 IO 字段）。

4. **错误类型变更**：`PokerL1Error` 改为 `ZkvmError`。若调用方仍返回 `PokerL1Error`，使用 `PokerL1Error::from(ZkvmError::...)` 或显式映射。

5. **断言变更**：旧测试断言基于 blake2b 哈希链相等性，须改为真实折叠语义断言（如 `folded_instance.u_l == Fr::zero()`、`is_satisfied() == true`）。

### 4.2 迁移示例

#### 4.2.1 旧代码（已 deprecated）

```rust
use poker_l1::offline::ccs::{CcsCircuit, ZkShuffleCcsCircuit};
use poker_l1::Hash;

#[allow(deprecated)]
fn old_caller() {
    let circuit = ZkShuffleCcsCircuit::new();
    let witness: Vec<u8> = vec![1, 2, 3, 4];
    let public_inputs: Vec<u8> = vec![5, 6, 7, 8];
    let state_delta: Vec<u8> = vec![9, 10];
    let ack_step_hash: Hash = [0u8; 32];

    let instance = circuit
        .to_instance(&witness, &public_inputs, &state_delta, ack_step_hash)
        .expect("旧 API 调用成功");
    // instance.mat_commitments: Vec<Hash>（哈希承诺，不可恢复矩阵）
}
```

#### 4.2.2 新代码

```rust
use poker_zkvm::ccs::Fr;
use poker_zkvm::precompiles::{CcsCircuit, zk_shuffle::ZkShuffleCcsCircuit};

fn new_caller() -> Result<(), Box<dyn std::error::Error>> {
    let circuit = ZkShuffleCcsCircuit::new();
    let witness: Vec<Fr> = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
    let public_inputs: Vec<Fr> = vec![Fr::from_u32_with_wrap(5)];

    // 注：ZkShuffleCcsCircuit 当前为 stub，to_ccs_instance 返回 Err("Phase 11 pending")
    // Phase 11b 完成迁移后，此处将返回携带真实矩阵的 CcsInstance
    let instance = circuit.to_ccs_instance(&witness, &public_inputs)?;
    // instance.ccs: Ccs（稀疏矩阵 + 子集 + 系数）
    // instance.witness: Vec<Fr>（域元素 witness）
    // instance.public_inputs: Vec<Fr>（域元素公共输入）
    Ok(())
}
```

### 4.3 ZkPublicIo 字段映射

旧 `CcsInstance` 中的 `state_delta_hash` 与 `ack_step_hash` 在新设计中移入 `ZkPublicIo`，作为 proof 的公共 IO 字段：

| 旧字段 | 新位置 |
|--------|--------|
| `mat_commitments` | `CcsInstance.ccs.ccs_commitment()`（Blake2b 矩阵哈希） |
| `public_input_hash` | `CcsInstance.public_inputs`（域元素直接存储） |
| `witness_commitment` | `FoldedInstance.witness_commitment`（IPA G1 点承诺） |
| `state_delta_hash` | `ZkPublicIo.state_delta_hash` |
| `ack_step_hash` | `ZkPublicIo.ack_chain_hash`（聚合后） |

## 5. LegacyCcsInstanceAdapter 失败语义

Phase 11b 将引入 `LegacyCcsInstanceAdapter`，用于过渡期**编译兼容**。该适配器将旧 hash-based `CcsInstance` 包装为新类型，但 `to_ccs_instance` 等方法始终返回错误：

```rust
// Phase 11b 将实现（语义说明）
impl LegacyCcsInstanceAdapter {
    pub fn to_ccs_instance(&self, ...) -> Result<CcsInstance, ZkvmError> {
        Err(ZkvmError::Other(
            "legacy hash-based instance cannot be really folded \
             — hash is one-way, cannot recover matrices"
        ))
    }
}
```

**关键语义**：

- `LegacyCcsInstanceAdapter` 仅用于**编译兼容**，不参与真实证明生成
- 旧调用方在 Production 状态下会失败，必须重构以提供真实矩阵
- grace 期内（`PRODUCTION_GRACE_BLOCKS = 7200`）旧调用方仍可工作；grace 期结束后强制走新类型

## 6. fold_step / fold_loop 迁移

旧 `poker_l1::offline::ccs::fold_step` 与 `fold_loop` 使用 blake2b 哈希链冒充折叠，Phase 11b 将内部实现替换为调用 `poker_zkvm::fold::fold_step` / `poker_zkvm::fold::fold_loop`：

```rust
// Phase 11b 迁移后
pub fn fold_step(
    lcccs: &poker_zkvm::fold::Lcccs,
    ccccs: &poker_zkvm::fold::Ccccs,
) -> Result<FoldStepResult, PokerL1Error> {
    // 内部委托给 poker_zkvm::fold::fold_step（真实 Hypernova 实现）
    let folded = poker_zkvm::fold::fold_step(lcccs, ccccs)
        .map_err(PokerL1Error::from)?;
    Ok(FoldStepResult { /* 映射字段 */ })
}
```

**BREAKING 影响**：外部 trait 签名变更，参数类型从旧 hash-based 改为新含矩阵类型，既有调用方必须迁移，无法透明兼容。

## 7. CheckinTx signing_hash 兼容性

Phase 11a 已完成 `CheckinTx` / `PartialCheckinTx` 的 `proof_kind` 字段与 1-byte 前缀序列化：

- `proof_kind` 作为 1-byte 前缀进入 `signing_hash` 输入，位于 `chain_id` 之后
- `ProofKind::ZkShuffle → 0x04`，`ProofKind::Zkvm → 0x01`
- **BREAKING**：破坏旧签名，升级时所有在途 `CheckinTx` 须在 `PRODUCTION_GRACE_BLOCKS` 内重提交或失效

### 7.1 grace 期签名形式分派（v1.4 Min3-004）

grace 期内 verifier 按 `scheme_id` 反推期望的签名形式：

| scheme_id | 期望签名形式 | 不一致错误 |
|-----------|--------------|------------|
| 4（ZkShuffle） | 旧签名（无 `proof_kind` 字段） | `SignatureFormMismatch` |
| 1（Hypernova） | 新签名（含 `proof_kind` 字段） | `SignatureFormMismatch` |

grace 期后所有 `CheckinTx` 必须使用新签名（含 `proof_kind` 字段）。`scheme_id=4` 走既有 ZkShuffle Production verifier（非 stub、非 Hypernova），`scheme_id=1` 走 Hypernova Production verifier。

### 7.2 proof_kind 与 scheme_id 一致性

`execute_checkin` 在分派 verifier 前校验 `proof_kind` 与 `scheme_id` 一致性：

| proof_kind | 期望 scheme_id | 不一致错误 |
|------------|----------------|------------|
| `ZkShuffle` (0x04) | 4 | `ProofKindMismatch` |
| `Zkvm` (0x01) | 1 | `ProofKindMismatch` |

## 8. 常见问题

### 8.1 为什么不能透明兼容

哈希是单向的，无法从 `mat_commitments: Vec<Hash>` 恢复矩阵 `M_j` 的原始稀疏条目。真实 Hypernova 折叠需要矩阵 `M_j` 与 witness `z` 进行 `M_j · z` 计算，因此必须采用携带完整数据的新类型。`LegacyCcsInstanceAdapter` 仅保证编译通过，运行时返回错误。

### 8.2 grace 期内可以混用新旧签名吗

不能。v1.4 Min3-004 修复后，grace 期内 verifier 按 `scheme_id` 严格反推期望签名形式，签名形式与 `scheme_id` 不一致返回 `SignatureFormMismatch`。这与 v1.2 残留的"同时接受带/不带 proof_kind 签名"表述直接矛盾，v1.4 已删除该错误表述。

### 8.3 ZkShuffleCcsCircuit 何时完成真实迁移

Phase 11b 完成。当前 stub 在 [poker_zkvm/src/precompiles/zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs) 中 `to_ccs_instance` 返回 `Err(Other("Phase 11 pending（真实电路未实现）"))`。Phase 11b 将基于 `poker_protocol::zk_shuffle` 实现真实电路。

### 8.4 如何判断我的代码是否需要迁移

- 使用 `poker_l1::offline::ccs::CcsCircuit` / `CcsInstance` / `ZkShuffleCcsCircuit` → 需要迁移
- 调用 `fold_step` / `fold_loop`（poker_l1 版本）→ 需要迁移
- 仅使用 `CheckinTx` / `PartialCheckinTx` 外部接口 → 已由 Phase 11a 完成，无需进一步迁移
- 仅使用 `poker_zkvm::prove` / `verify_production` → 无需迁移

### 8.5 错误类型如何映射

| 旧错误 | 新错误 |
|--------|--------|
| `PokerL1Error::InvalidCcsInstance` | `ZkvmError::InvalidZkProofFormat` |
| `PokerL1Error::FoldStepFailed` | `ZkvmError::FoldStepFailed`（或 `Other`） |
| `PokerL1Error::Other(msg)` | `ZkvmError::Other(msg)` |

## 9. 检查清单

迁移前请确认：

- [ ] 所有 `use poker_l1::offline::ccs::{...}` 已替换为 `use poker_zkvm::precompiles::{...}`
- [ ] witness 与 public_inputs 编码从 `&[u8]` 改为 `&[Fr]`
- [ ] `to_instance(...)` 调用改为 `to_ccs_instance(...)`
- [ ] 错误处理从 `PokerL1Error` 改为 `ZkvmError`（或显式映射）
- [ ] 测试断言从哈希相等性改为真实折叠语义
- [ ] 不再依赖 `LegacyCcsInstanceAdapter`（仅编译兼容，运行时失败）
- [ ] `CheckinTx` 已设置 `proof_kind` 字段
- [ ] `signing_hash` 包含 1-byte `proof_kind` 前缀
- [ ] grace 期内签名形式与 `scheme_id` 一致

## 10. 参考

- spec.md L810-852（v1.4 FROZEN，v1.2 诚实 BREAKING 声明）
- [poker_zkvm/src/ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs) — 新 `CcsInstance` 定义
- [poker_zkvm/src/precompiles/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs) — 新 `CcsCircuit` trait
- [poker_zkvm/src/precompiles/zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs) — ZkShuffle stub
- [poker_l1/src/offline/ccs.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/ccs.rs) — 旧类型（已 deprecated）
- [poker_zkvm/docs/alternatives.md](file:///Users/mac/projects/zchain/poker_zkvm/docs/alternatives.md) — Phase 10 设计决策（D3 CcsCircuit 迁移）
- tasks.md Phase 11 Task 11.1 — 迁移任务清单
