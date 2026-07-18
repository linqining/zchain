# 预编译合约 Gas 策略重构：移除 executor 中冗余的 is\_gameturn 判定

## Summary

当前 [executor.rs](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs) L182 的 `let is_gameturn = matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor)` 同时承担了**两类职责**：(A) Gas/费用/nonce 策略；(B) 共识路由语义。其中 (A) 类职责应改由 `Precompile` trait 的 `is_gas_free()` 属性决定，而非 tx lane。

当前设计存在**安全漏洞**：用户构造 `lane_hint = GameTurn` 但 `contract_call` 指向普通 rBPF 合约时，executor 会跳过余额/nonce 预检、给予 `gas_limit = u64::MAX`、不扣费不推进 nonce —— 即对任意合约发起**免费无限 gas DoS** 且可绕过 account nonce 重放保护。

本次重构：(1) 为 `Precompile` trait 增加 `is_gas_free()` 属性；(2) executor 的 gas 策略改由 precompile 属性决定；(3) gas-free lane 与非 gas-free 目标组合**直接拒绝**；(4) 移除 `TxContext.is_gameturn` 字段（无 syscall 读取，安全删除）；(5) `TxLane::GameTurn` 在共识/路由层保留不变（仍有必要校验：轮次、assigned\_validator、tx 排序、独立 merkle root）。

## Current State Analysis

### executor.rs 中 `is_gameturn` 的 5 处用途

| 位置                                                                               | 用途                                                  | 重构后处理                                                            |
| -------------------------------------------------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------- |
| [L182-183](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L182-L183) | 派生 `is_gameturn` 标志                                 | 改名 `is_gas_free_lane`，仅表示"tx 声称走免 gas 通道"                        |
| [L185-199](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L185-L199) | 跳过账户/nonce/余额预检                                     | 改由 precompile `is_gas_free()` 决定                                 |
| [L243-244](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L243-L244) | GameTurn 无 contract\_call 时 fail-closed             | 保留语义：gas-free lane 必须有 contract\_call 指向 gas-free precompile     |
| [L253-259](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L253-L259) | 跳过 `apply_public_tx`（不扣费/不推进 nonce）                 | 改由 precompile `is_gas_free()` 决定                                 |
| [L301-314](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L301-L314) | `gas_limit = u64::MAX` + 设置 `TxContext.is_gameturn` | gas-free precompile 走 registry.execute 不经此路径；移除 `is_gameturn` 字段 |

### TxLane::GameTurn 在共识层的必要校验（**不动**）

| 文件                                                                                                                        | 函数                               | 校验内容                             |
| ------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | -------------------------------- |
| [routing.rs L314-323](file:///Users/mac/projects/zchain/poker_l1/src/consensus/routing.rs#L314-L323)                      | `validate_lane_route`            | GameTurn 必须配 `AssignedValidator` |
| [routing.rs L337-354](file:///Users/mac/projects/zchain/poker_l1/src/consensus/routing.rs#L337-L354)                      | `validate_assigned_validator`    | 必须提交给游戏 assigned\_validator      |
| [routing.rs L373-395](file:///Users/mac/projects/zchain/poker_l1/src/consensus/routing.rs#L373-L395)                      | `validate_turn_order`            | 必须是当前轮次玩家                        |
| [routing.rs L417+](file:///Users/mac/projects/zchain/poker_l1/src/consensus/routing.rs#L417)                              | `validate_game_turn_phase_aware` | 阶段感知提交校验                         |
| [vertex\_production.rs L343-364](file:///Users/mac/projects/zchain/poker_l1/src/consensus/vertex_production.rs#L343-L364) | `sort_vertex_txs_s9`             | GameTurn tx 排序优先                 |
| [bullshark.rs L298-302](file:///Users/mac/projects/zchain/poker_l1/src/consensus/bullshark.rs#L298-L302)                  | block 产出                         | 拆分 public/gameturn tx\_root      |

→ **结论**：`TxLane::GameTurn` 在共识层有独立必要校验，不能移除。但 executor 不应再用它决定 gas 策略。

### TxContext.is\_gameturn 字段读取情况

经穷举搜索：该字段仅在 [context.rs L59](file:///Users/mac/projects/zchain/poker_l1/src/vm/context.rs#L59) 声明、[executor.rs L314](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L314) 写入，**无任何 syscall 或条件分支读取**。可安全移除。

### Precompile trait 当前缺失

[precompile.rs L42-77](file:///Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs#L42-L77) 的 `Precompile` trait 仅有 `id()` / `version()` / `call()` / `supports_selector()`，**无 gas 策略属性**。

## Proposed Changes

### 改动 1：`Precompile` trait 增加 `is_gas_free()` 方法

**文件**：[poker\_l1/src/vm/precompile.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs)

在 `Precompile` trait 中增加默认实现为 `false` 的方法：

```rust
pub trait Precompile: Send + Sync {
    fn id(&self) -> ObjectID;
    fn version(&self) -> u32;
    fn call(&self, ...) -> PokerL1Result<DispatchResult>;
    fn supports_selector(&self, _selector: &[u8; 32]) -> bool { true }

    /// 该预编译合约是否免 gas。
    ///
    /// 免 gas 预编译合约（如 GamePrecompile）的调用不消耗 gas、不扣费、
    /// 不推进 account nonce。反滥用由游戏买入锁仓 + gameturn_nonce + 轮次约束保障。
    ///
    /// 默认 false：普通预编译合约（如签名验证、哈希等）仍按 tx gas 策略计费。
    fn is_gas_free(&self) -> bool { false }
}
```

### 改动 2：`GamePrecompile` 覆写 `is_gas_free() = true`

**文件**：[poker\_l1/src/vm/contracts/game\_precompile.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/game_precompile.rs)

在 `impl Precompile for GamePrecompile` 中增加：

```rust
fn is_gas_free(&self) -> bool { true }
```

### 改动 3：`PrecompileRegistry` 增加 `is_gas_free()` 查询方法

**文件**：[poker\_l1/src/vm/precompile.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs)

```rust
impl PrecompileRegistry {
    /// 查询某 ObjectID 对应的预编译合约是否免 gas。
    ///
    /// 未注册的 ObjectID 返回 false。
    pub fn is_gas_free(&self, id: ObjectID) -> bool {
        self.precompiles.get(&id).is_some_and(|p| p.is_gas_free())
    }
}
```

### 改动 4：重构 executor.rs 的 gas/fee/nonce 策略

**文件**：[poker\_l1/src/executor.rs](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs)

#### 4a. 重写 `execute_tx_inner` 的路由与策略判定（L181-245）

新逻辑（伪代码）：

```rust
let caller = derive_address(&tx.tagged_pubkey);
let is_gas_free_lane = matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor);

// 解析目标合约的 gas-free 属性
let target_is_gas_free = match (&tx.contract_call, &env.precompile_registry) {
    (Some(call), Some(registry)) if registry.is_precompile(call.contract_id) => {
        registry.is_gas_free(call.contract_id)
    }
    _ => false, // 无 contract_call 或非预编译合约 → 不是 gas-free 目标
};

// ===== 安全校验：gas-free lane 必须配 gas-free 预编译合约 =====
if is_gas_free_lane {
    match (&tx.contract_call, &env.precompile_registry) {
        (Some(call), Some(registry)) if registry.is_precompile(call.contract_id) && registry.is_gas_free(call.contract_id) => {
            // OK：gas-free lane + gas-free precompile
        }
        _ => {
            // gas-free lane 但目标不是 gas-free precompile → 拒绝（防免费 gas 滥用）
            return Err(PokerL1Error::Other(format!(
                "gas-free lane {:?} requires gas-free precompile contract, got {:?}",
                tx.lane_hint,
                tx.contract_call.as_ref().map(|c| c.contract_id)
            )));
        }
    }
}

// ===== 账户预检：仅非 gas-free tx 需要 =====
if !target_is_gas_free {
    let account = account_store.get(&caller).ok_or_else(|| ...)?;
    validate_public_tx(account, tx, env.chain_id)?;
    if account.balance < tx.gas.budget { return Err(InsufficientBalance); }
}

// ===== 执行 =====
// (预编译路径保持现状：registry.execute)
// (rBPF 路径：execute_contract_call —— 但 gas_limit 不再用 is_gameturn，见 4b)

// ===== 结算：仅非 gas-free tx 扣费/推进 nonce =====
if !target_is_gas_free {
    apply_public_tx(account, tx, gas_used)?;
    fee_charged = gas_used;
}
```

#### 4b. 移除 `execute_contract_call` 中的 `is_gameturn` 判定

**位置**：[executor.rs L300-315](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L300-L315)

原代码：

```rust
let is_gameturn = matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor);
let gas_limit = if is_gameturn { u64::MAX } else { tx.gas.budget.min(TX_GAS_LIMIT) };
let tx_ctx = TxContext { ..., is_gameturn };
```

重构后：

```rust
// gas-free precompile 已在上方走 registry.execute 分支，不会进入此函数。
// 进入此函数的 tx 一律按 Public 计费：gas_limit = tx.gas.budget.min(TX_GAS_LIMIT)
let gas_limit = tx.gas.budget.min(TX_GAS_LIMIT);
let tx_ctx = TxContext {
    caller: *caller,
    caller_pubkey: tx.tagged_pubkey.clone(),
    chain_id: env.chain_id,
    nonce: tx.nonce,
    block_height: env.block_height,
    block_timestamp: env.block_timestamp,
    // is_gameturn 字段已移除
};
```

#### 4c. 移除 `else if is_gameturn` fail-closed 分支

**位置**：[executor.rs L243-244](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L243-L244)

原代码在 contract\_call 为 None 且 is\_gameturn 时返回 "not yet implemented"。重构后此分支被 4a 的安全校验覆盖：gas-free lane 无 contract\_call 时直接被拒绝，无需单独 fail-closed。

### 改动 5：移除 `TxContext.is_gameturn` 字段

**文件**：[poker\_l1/src/vm/context.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/context.rs) L58-59

删除字段声明及其文档注释。同步删除 executor.rs L314 的字段赋值。

### 改动 6：`execute_block` 中的 block gas limit 判定

**位置**：[executor.rs L439-453](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L439-L453)

原代码用 `matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor)` 判断是否跳过 block gas 累计。此判定在 block 级别仍正确（gas-free lane 的 tx 不消耗 block gas），**保留不变**。但需更新注释说明：判定基于 lane 而非 precompile，因为 block 产出时已保证 lane-contract 一致性（executor 层已拒绝不一致的 tx）。

## Assumptions & Decisions

1. **gas-free 判定权威源**：precompile 的 `is_gas_free()` 是 gas 策略的单一权威源。`TxLane::GameTurn` 仅在共识路由层有意义。
2. **lane-contract 一致性**：gas-free lane（GameTurn/CheckpointAnchor）必须配 gas-free precompile；不一致直接拒绝（用户选择）。
3. **非 gas-free lane 调 gas-free precompile**：允许（如 Public lane 调 GamePrecompile 做只读查询），但**按 Public 计费**（扣 gas、推进 nonce）。理由：lane 语义由路由层强制，executor 不拦截；但 gas 策略跟随 lane 而非合约。
4. **`TxContext.is_gameturn`** **移除安全**：经穷举搜索无 syscall 读取，仅声明 + 赋值，删除无行为影响。
5. **共识层不动**：`TxLane::GameTurn` 在 routing.rs / vertex\_production.rs / bullshark.rs 的校验逻辑保留，本重构不涉及。

## 测试计划

### 新增测试（executor::tests）

1. **`test_gas_free_lane_with_gas_free_precompile_succeeds`**：lane=GameTurn + contract\_call 指向注册的 GamePrecompile → 执行成功，gas\_used=0，不扣费不推进 nonce。
2. **`test_gas_free_lane_with_non_gas_free_contract_rejected`**（**核心安全测试**）：lane=GameTurn + contract\_call 指向普通 rBPF 合约 → 拒绝执行，错误含 "gas-free lane requires gas-free precompile"。state\_root 不变，账户不变。
3. **`test_gas_free_lane_with_unregistered_contract_rejected`**：lane=GameTurn + contract\_call 指向未注册 ObjectID → 拒绝执行。
4. **`test_gas_free_lane_without_contract_call_rejected`**：lane=GameTurn + contract\_call=None → 拒绝执行（替代原 fail-closed 测试）。
5. **`test_public_lane_with_gas_free_precompile_charges_gas`**：lane=Public + contract\_call 指向 GamePrecompile → 执行成功但**扣 gas、推进 nonce**（验证 lane-contract 组合的非对称策略）。
6. **`test_checkpoint_anchor_lane_with_gas_free_precompile_succeeds`**：lane=CheckpointAnchor + gas-free precompile → 免 gas 执行。

### 修改现有测试

* **`test_execute_tx_gameturn_without_contract_fail_closed`**：重命名为 `test_execute_tx_gameturn_without_contract_call_rejected`，错误信息断言改为 "gas-free lane"。

* **`test_execute_tx_gameturn_contract_call_gas_free`**：需注入 PrecompileRegistry + GamePrecompile，否则现在会被拒绝。

### 新增测试（precompile::tests）

1. **`test_precompile_is_gas_free_default_false`**：TestPrecompile（未覆写）`is_gas_free()` 返回 false。
2. **`test_registry_is_gas_free_query`**：注册 gas-free precompile 后 `registry.is_gas_free(id)` 返回 true；未注册返回 false。

### 回归测试

* 运行 `cargo test` 全套，确保 1365 个现有测试无回归。

* 特别关注 `execute_block_gas_limit_skips_public_not_gameturn` 测试（block gas 累计逻辑未变）。

## 验证步骤

1. `cargo check -p poker_l1` 编译通过。
2. `cargo test -p poker_l1 --lib executor::tests` 全部通过。
3. `cargo test -p poker_l1 --lib vm::precompile::tests` 全部通过。
4. `cargo test -p poker_l1 --lib vm::contracts::game_precompile::tests` 全部通过。
5. `cargo test -p poker_l1` 全套通过（含集成测试）。
6. `cargo clippy -p poker_l1 --lib` 无新增 warning（特别是 `is_gameturn` 相关的死代码警告应消失）。
7. 手动验证：构造 lane=GameTurn + 普通 rBPF 合约的 tx，确认被拒绝（安全漏洞已修复）。
8. 共识层回归：`cargo test -p poker_l1 --lib consensus::` 全套通过，确认 `TxLane::GameTurn` 的轮次/排序/merkle root 校验未受影响。

