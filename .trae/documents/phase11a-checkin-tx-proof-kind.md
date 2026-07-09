# Phase 11a — Task 11.2：CheckinTx `proof_kind` 接线

> **change-id**：`build-hypernova-zkvm`
> **spec**：v1.4 FROZEN — tasks.md L324-332（Task 11.2 SubTask 11.2.1-11.2.8）
> **范围**：仅 Task 11.2（CheckinTx `proof_kind` 序列化 + `execute_checkin` 接线到已实现的 `verify_with_context`）
> **不含**：Task 11.1（CCS/fold 硬迁移）— 留作 Phase 11b 独立推进

## 1. 当前状态分析（Phase 1 探索结论）

### 1.1 Verifier 侧已全部实现（**无需修改**）

| 文件 | 已有内容 | 位置 |
|---|---|---|
| [zk_verifier.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs) | `ProofKind` enum + `from_scheme_id()` + `expects_new_signature()` | L29-65 |
| 同上 | `ZkVerifyContext`（current_height / production_switch_height / grace_blocks / last_partial_proof_hash / uses_new_signature）+ `in_grace_period()` / `grace_period_ended()` | L67-108 |
| 同上 | `ZkVerifierRegistry::zk_verify_with_context()` | L425-456 |
| [hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs) | `HypernovaVerifier::verify_with_context` — ProofKindMismatch + SignatureFormMismatch + grace 期分派 | L218-260 |
| 同上 | `ZkShuffleVerifier::verify_with_context` — grace 期 stub 路径 + M2-003 proof_hash 不可变 + grace_period_ended 强制新签名 | L324-380 |
| 同上 | grace 期单元测试（7 个：matching_proof_hash / forced_production / proof_hash_mismatch 等） | L614-775 |
| [error.rs](file:///Users/mac/projects/zchain/poker_l1/src/error.rs) | `ProofKindMismatch { declared, actual }` / `PartialFoldHashImmutable` / `SignatureFormMismatch { scheme_id }` | L636 / L642 / L645 |

### 1.2 state.rs 缺失项（**本次实现目标**）

| 位置 | 现状 | 缺失 |
|---|---|---|
| [state.rs L110-125](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L110-L125) `CheckinTx` | 无 `proof_kind` 字段 | 需新增 `proof_kind: ProofKind` |
| [state.rs L158-174](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L158-L174) `CheckinTx::signing_hash` | 无 `proof_kind` 前缀 | 需在 chain_id 后插入 `[self.proof_kind.to_byte()]` |
| [state.rs L181-194](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L181-L194) `PartialCheckinTx` | 无 `proof_kind` 字段 | 需新增 `proof_kind: ProofKind` |
| [state.rs L216-229](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L216-L229) `PartialCheckinTx::signing_hash` | 无 `proof_kind` 前缀 | 需在 chain_id 后插入 `[self.proof_kind.to_byte()]` |
| [state.rs L273-334](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L273-L334) `execute_checkin` | 调用 `registry.zk_verify()`（L326） | 改为 `zk_verify_with_context`，新增 `ctx: &ZkVerifyContext` 参数 + ProofKind/scheme_id 一致性校验 |
| [state.rs L350-436](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L350-L436) `execute_partial_checkin` | 调用 `registry.zk_verify()`（L414） | 改为 `zk_verify_with_context`，新增 `ctx: &ZkVerifyContext` 参数 + ProofKind/scheme_id 一致性校验 |
| [zk_verifier.rs L44-65](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs#L44-L65) `impl ProofKind` | 无 `to_byte()` | 需新增（供 signing_hash 序列化） |

### 1.3 调用方影响范围

`CheckinTx` / `PartialCheckinTx` 构造点（须补 `proof_kind` 字段）：

| 文件 | CheckinTx 构造点 | PartialCheckinTx 构造点 |
|---|---|---|
| [state.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs) tests 模块 | L553 / L570 / L589 / L631 / L659 / L683 / L707（7 处） | L737 / L754 / L791 / L817（4 处） |
| [phase5a_integration.rs](file:///Users/mac/projects/zchain/poker_l1/tests/phase5a_integration.rs) | 需检查 | 需检查 |
| [hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs) tests | grace 期测试直接调用 `verify_with_context`，不构造 CheckinTx — 无需改 | — |

`execute_checkin` / `execute_partial_checkin` 调用点（须补 `ctx` 参数）：
- `state.rs` tests 模块内多处
- `phase5a_integration.rs` 内多处

## 2. 实施步骤

### Step 1 — 新增 `ProofKind::to_byte()`（zk_verifier.rs）

在 [zk_verifier.rs L44-65](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs#L44-L65) 的 `impl ProofKind` 块末尾追加：

```rust
/// 转为 1-byte 表示（用于 signing_hash 序列化）。
///
/// - `ZkShuffle` → 4（`SCHEME_ZKSHUFFLE`）
/// - `Zkvm` → 1（`SCHEME_HYPERNOVA`）
#[must_use]
pub const fn to_byte(self) -> u8 {
    match self {
        Self::ZkShuffle => SCHEME_ZKSHUFFLE as u8,
        Self::Zkvm => SCHEME_HYPERNOVA as u8,
    }
}
```

### Step 2 — `CheckinTx` 新增 `proof_kind` 字段 + `signing_hash` 前缀（state.rs）

**2a.** [state.rs L110-125](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L110-L125) `CheckinTx` 结构体在 `scheme_id` 字段后新增：

```rust
    /// scheme_id（Hypernova / Groth16 / IPA）。
    pub scheme_id: u32,
    /// proof_kind（v1.2 — 与 scheme_id 双向映射，进入 signing_hash）。
    pub proof_kind: super::zk_verifier::ProofKind,
    /// 是否基于 partial_checkin 衔接（SEC2-M8）。
    pub has_partial_checkin: bool,
```

**2b.** [state.rs L158-174](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L158-L174) `signing_hash` 在 `chain_id` 后插入 1-byte `proof_kind` 前缀（spec.md L327 SubTask 11.2.3 BREAKING）：

```rust
    pub fn signing_hash(&self, chain_id: crate::ChainId) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&[self.proof_kind.to_byte()]); // v1.2 BREAKING — proof_kind 前缀
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.proof_hash());
        hasher.update(&self.state_delta_hash());
        hasher.update(&self.new_commitment);
        hasher.update(&self.ack_chain_hash());
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
```

同步更新 `signing_hash` 的 doc 注释，加入 `proof_kind` 字段说明。

### Step 3 — `PartialCheckinTx` 新增 `proof_kind` 字段 + `signing_hash` 前缀（state.rs）

**3a.** [state.rs L181-194](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L181-L194) `PartialCheckinTx` 在 `scheme_id` 字段后新增 `proof_kind: ProofKind`（同 Step 2a）。

**3b.** [state.rs L216-229](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L216-L229) `signing_hash` 在 `chain_id` 后插入 `[self.proof_kind.to_byte()]`（同 Step 2b）。

### Step 4 — `execute_checkin` 接线 `zk_verify_with_context`（state.rs）

[state.rs L273-334](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L273-L334)：

**4a.** 函数签名新增 `ctx: &super::zk_verifier::ZkVerifyContext<'_>` 参数（放在 `max_ack_chain_length` 之后）。

**4b.** 在 ack_chain 长度校验之后、构造 public_io 之前，新增 ProofKind/scheme_id 一致性校验（SubTask 11.2.4）：

```rust
    // SubTask 11.2.4：proof_kind 与 scheme_id 一致性校验
    let expected_kind = super::zk_verifier::ProofKind::from_scheme_id(tx.scheme_id)
        .ok_or(PokerL1Error::ProofKindMismatch {
            declared: tx.proof_kind.to_byte(),
            actual: tx.scheme_id as u8,
        })?;
    if expected_kind != tx.proof_kind {
        return Err(PokerL1Error::ProofKindMismatch {
            declared: tx.proof_kind.to_byte(),
            actual: tx.scheme_id as u8,
        });
    }
```

**4c.** [state.rs L326-333](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L326-L333) 将 `registry.zk_verify(...)` 替换为 `registry.zk_verify_with_context(..., ctx)`：

```rust
    registry.zk_verify_with_context(
        chain_id,
        tx.scheme_id,
        &tx.proof,
        &public_io,
        max_skip_segments,
        max_ack_chain_length,
        ctx,
    )
```

### Step 5 — `execute_partial_checkin` 接线 `zk_verify_with_context`（state.rs）

[state.rs L350-436](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L350-L436)：

**5a.** 函数签名新增 `ctx: &super::zk_verifier::ZkVerifyContext<'_>` 参数（放在 `max_ack_chain_length` 之后；`#[allow(clippy::too_many_arguments)]` 已存在，参数变为 9 个）。

**5b.** 在 SEC-H1 提交次数上限校验之前，新增 ProofKind/scheme_id 一致性校验（同 Step 4b）。

**5c.** [state.rs L414-421](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs#L414-L421) 将 `registry.zk_verify(...)` 替换为 `registry.zk_verify_with_context(..., ctx)`。

### Step 6 — 更新既有测试（state.rs + phase5a_integration.rs）

**6a.** state.rs tests 模块 11 处 `CheckinTx { ... }` / `PartialCheckinTx { ... }` 构造点补 `proof_kind: ProofKind::Zkvm`（scheme_id=1 → Hypernova → Zkvm）。

**6b.** state.rs tests 模块所有 `execute_checkin(...)` / `execute_partial_checkin(...)` 调用补 `ctx` 参数。构造默认 `ZkVerifyContext` helper：

```rust
fn make_default_ctx() -> super::zk_verifier::ZkVerifyContext<'static> {
    super::zk_verifier::ZkVerifyContext {
        current_height: 0,
        production_switch_height: 0, // 切换前
        grace_blocks: 7200,
        last_partial_proof_hash: None,
        uses_new_signature: true, // Zkvm 期望新签名
    }
}
```

**6c.** phase5a_integration.rs 内 `CheckinTx` / `PartialCheckinTx` 构造 + `execute_checkin` / `execute_partial_checkin` 调用同步补字段与 ctx 参数（grep 定位具体行）。

**6d.** state.rs 头部 `use` 引入 `ProofKind` + `ZkVerifyContext`（若尚未引入）。

### Step 7 — 集成测试（SubTask 11.2.7）

在 state.rs tests 模块新增：

- `test_execute_checkin_zkvm_proof_kind_consistency` — scheme_id=1 + proof_kind=Zkvm + 合法 proof → 通过
- `test_execute_checkin_zkshuffle_proof_kind_consistency` — scheme_id=4 + proof_kind=ZkShuffle + grace 期 ctx + 匹配 last_partial_proof_hash → 通过 stub 路径

### Step 8 — soundness 负例测试（SubTask 11.2.8）

在 state.rs tests 模块新增：

- `test_execute_checkin_proof_kind_mismatch` — scheme_id=1 + proof_kind=ZkShuffle → 返回 `ProofKindMismatch`
- `test_execute_checkin_unknown_scheme_id` — scheme_id=99 → 返回 `ProofKindMismatch`（`from_scheme_id` 返回 None）
- `test_checkin_tx_signing_hash_includes_proof_kind` — 同一 tx 仅 `proof_kind` 不同 → `signing_hash` 不相等（验证 BREAKING 前缀生效）

## 3. 假设与决策

| # | 决策 | 理由 |
|---|---|---|
| D1 | 仅做 Task 11.2，Task 11.1 留作 Phase 11b | 用户确认；11.1 HARD BREAKING 需重写 phase5a_integration.rs + bench，独立于 11.2 |
| D2 | `proof_kind` 字段位置：紧随 `scheme_id` 之后 | 语义聚合；spec.md L327 未指定字段顺序但与 scheme_id 邻近最自然 |
| D3 | `signing_hash` 中 `proof_kind` 前缀位置：chain_id 之后 | spec.md L327：「proof_kind 作为 1-byte 前缀进入 signing_hash 输入」；chain_id 后、game_id 前为最稳定位置 |
| D4 | `execute_checkin` / `execute_partial_checkin` 的 ProofKind/scheme_id 一致性校验在函数内做（不依赖 verifier 内部） | 提前失败 + 错误信息更精确（`declared`/`actual`）；verifier 内部校验为兜底 |
| D5 | `to_byte()` 返回 `SCHEME_* as u8`（4 / 1） | 与 `from_scheme_id` 互逆；与 scheme_id 数值一致便于调试 |
| D6 | 不修改 `zk_verify_with_context` / `HypernovaVerifier::verify_with_context` / `ZkShuffleVerifier::verify_with_context` | Phase 8 已实现并通过测试；本次仅接线 |
| D7 | 默认 ctx helper `uses_new_signature = true` | 既有测试 scheme_id=1（Zkvm）期望新签名；切换前 production_switch_height=0 → 不触发 grace 期逻辑 |

## 4. 验证步骤

1. `cargo build -p poker_l1` — 编译通过，无 warning
2. `cargo test -p poker_l1 --lib offline::state` — state.rs 全部测试通过（含新增 5 个）
3. `cargo test -p poker_l1 --lib offline::hypernova` — 既有 grace 期测试不回归
4. `cargo test -p poker_l1 --test phase5a_integration` — 集成测试通过
5. `cargo clippy -p poker_l1 -- -D warnings` — 无 warning
6. 更新 [tasks.md](file:///Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/tasks.md) L324-332 Task 11.2 SubTask 标记 `[x]`；[checklist.md](file:///Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/checklist.md) Phase 11 Task 11.2 对应项同步

## 5. 关键文件清单

| 文件 | 修改类型 | 说明 |
|---|---|---|
| [poker_l1/src/offline/zk_verifier.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs) | 新增方法 | `ProofKind::to_byte()`（L44-65 块内） |
| [poker_l1/src/offline/state.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs) | 修改 | CheckinTx / PartialCheckinTx 字段 + signing_hash + execute_* 接线 + 测试更新 + 新增 5 测试 |
| [poker_l1/tests/phase5a_integration.rs](file:///Users/mac/projects/zchain/poker_l1/tests/phase5a_integration.rs) | 修改 | CheckinTx / PartialCheckinTx 构造 + execute_* 调用补字段/ctx |
| [.trae/specs/build-hypernova-zkvm/tasks.md](file:///Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/tasks.md) | 文档 | L324-332 Task 11.2 标记完成 |
| [.trae/specs/build-hypernova-zkvm/checklist.md](file:///Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/checklist.md) | 文档 | Phase 11 Task 11.2 对应项同步 |

## 6. 延后项（Phase 11b — Task 11.1）

- SubTask 11.1.1-11.1.8：CCS/fold 迁移到 `poker_zkvm::fold::CcsInstance`（Fr-based）
- `LegacyCcsInstanceAdapter` 实现（仅编译兼容，返回 `Err`）
- `fold_step` / `fold_loop` 内部调用 `poker_zkvm::fold::*`
- 移除 blake2b 哈希链冒充逻辑
- `CcsCircuit` trait 迁入 `poker_zkvm::precompiles`，`poker_l1` re-export
- 重写 `phase5a_integration.rs` + `benches/task36_zk_verifier.rs` 调用方
- 迁移示例文档
