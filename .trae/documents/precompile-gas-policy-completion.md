# 预编译合约 Gas 策略重构：收尾完成计划

## Summary

本计划是 [precompile-gas-policy-refactor.md](file:///Users/mac/projects/zchain/.trae/documents/precompile-gas-policy-refactor.md)（已批准并基本实现）的收尾。原计划的 6 项代码改动 + 6 个 executor 新增测试 + 3 个修改测试**已全部完成并通过**，仅剩 2 个 precompile::tests 单元测试和完整验证步骤待执行。

## Current State（已验证）

### ✅ 代码改动（6/6 完成）

| 改动                                                 | 文件                                                                                                                       | 状态 |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -- |
| 1. `Precompile::is_gas_free()` trait 方法（默认 false）  | [precompile.rs L78-96](file:///Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs#L78-L96)                          | ✅  |
| 2. `GamePrecompile::is_gas_free() = true` 覆写       | [game\_precompile.rs L113-122](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/game_precompile.rs#L113-L122) | ✅  |
| 3. `PrecompileRegistry::is_gas_free(id)` 查询方法      | [precompile.rs L263-272](file:///Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs#L263-L272)                      | ✅  |
| 4. executor.rs lane-contract 一致性校验 + gas 策略跟随 lane | [executor.rs L188-215](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs#L188-L215)                             | ✅  |
| 5. `TxContext.is_gameturn` 字段移除                    | [context.rs L45-60](file:///Users/mac/projects/zchain/poker_l1/src/vm/context.rs#L45-L60)                                | ✅  |
| 6. `execute_block` 注释更新（block gas 判定基于 lane）       | [executor.rs](file:///Users/mac/projects/zchain/poker_l1/src/executor.rs)                                                | ✅  |

### ✅ 测试改动（9/9 完成）

* **6 个新增 executor 测试**（全部通过）：

  * `test_gas_free_lane_with_gas_free_precompile_succeeds`

  * `test_gas_free_lane_with_non_gas_free_contract_rejected`（核心安全测试）

  * `test_gas_free_lane_with_unregistered_contract_rejected`

  * `test_public_lane_with_gas_free_precompile_charges_nonce`

  * `test_checkpoint_anchor_lane_with_gas_free_precompile_succeeds`

  * `test_gas_free_lane_without_registry_rejected`

* **3 个修改的现有测试**（全部通过）：

  * `test_execute_tx_gameturn_without_contract_call_rejected`（重命名 + 断言更新）

  * `test_execute_tx_gameturn_contract_call_gas_free`（注入 GasFreeTestPrecompile）

  * `test_execute_block_gas_limit_skips_public_not_gameturn`（使用 gas\_free\_id）

### ✅ 已验证

* `cargo check -p poker_l1`：编译通过（仅 pre-existing doc warnings，无 refactoring 相关错误）

* `cargo test -p poker_l1 --lib executor::tests`：**28 passed; 0 failed**

* `cargo test -p poker_l1 --lib vm::precompile::tests`：**11 passed; 0 failed**

## Remaining Work（待完成）

### 任务 1：新增 2 个 precompile::tests

**文件**：[poker\_l1/src/vm/precompile.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs)（在 `mod tests` 末尾追加，L613 `}` 之前）

#### 测试 1：`test_precompile_is_gas_free_default_false`

验证 `Precompile` trait 的 `is_gas_free()` 默认实现返回 `false`（未覆写的 `TestPrecompile` 应返回 false）。

```rust
#[test]
fn test_precompile_is_gas_free_default_false() {
    // 未覆写 is_gas_free() 的 TestPrecompile 应返回 false（默认实现）。
    let precompile = make_test_precompile(ObjectID::new([0xFF; 20], 1), 1);
    assert!(
        !precompile.is_gas_free(),
        "Precompile::is_gas_free() 默认应返回 false"
    );
}
```

#### 测试 2：`test_registry_is_gas_free_query`

验证 `PrecompileRegistry::is_gas_free(id)` 查询方法：注册 gas-free precompile 后返回 true；未注册的 ObjectID 返回 false。

需要一个覆写 `is_gas_free() = true` 的测试 precompile（与 executor.rs 中的 `GasFreeTestPrecompile` 类似）：

```rust
/// 测试用 gas-free 预编译合约（覆写 is_gas_free() = true）。
struct GasFreeTestPrecompile {
    id: ObjectID,
}

impl GasFreeTestPrecompile {
    fn new(id: ObjectID) -> Arc<dyn Precompile> {
        Arc::new(Self { id })
    }
}

impl Precompile for GasFreeTestPrecompile {
    fn id(&self) -> ObjectID {
        self.id
    }

    fn version(&self) -> u32 {
        1
    }

    fn call(
        &self,
        _caller: &Address,
        _caller_pubkey: &TaggedPubkey,
        _method_selector: &[u8; 32],
        _args: &[u8],
        _env: &ExecutionEnvironment,
        _object_db: &mut ObjectDb,
    ) -> PokerL1Result<DispatchResult> {
        Ok(DispatchResult::empty())
    }

    fn is_gas_free(&self) -> bool {
        true
    }
}

#[test]
fn test_registry_is_gas_free_query() {
    let mut registry = PrecompileRegistry::new();
    let gas_free_id = ObjectID::new([0xFE; 20], 1);
    let non_gas_free_id = ObjectID::new([0xFD; 20], 2);

    // 注册 gas-free precompile
    registry.register(GasFreeTestPrecompile::new(gas_free_id));
    // 注册普通（非 gas-free）precompile
    registry.register(make_test_precompile(non_gas_free_id, 1));

    // gas-free precompile 查询返回 true
    assert!(
        registry.is_gas_free(gas_free_id),
        "已注册的 gas-free precompile 应返回 true"
    );
    // 普通 precompile 查询返回 false
    assert!(
        !registry.is_gas_free(non_gas_free_id),
        "已注册的非 gas-free precompile 应返回 false"
    );
    // 未注册的 ObjectID 查询返回 false
    assert!(
        !registry.is_gas_free(ObjectID::new([0x00; 20], 999)),
        "未注册的 ObjectID 应返回 false"
    );
}
```

### 任务 2：运行完整验证

按原计划验证步骤执行：

```bash
# 1. 编译检查
cargo check -p poker_l1

# 2. executor 测试（已通过，重新确认无回归）
cargo test -p poker_l1 --lib executor::tests

# 3. precompile 测试（新增 2 个测试后）
cargo test -p poker_l1 --lib vm::precompile::tests

# 4. game_precompile 测试
cargo test -p poker_l1 --lib vm::contracts::game_precompile::tests

# 5. 共识层回归（确认 TxLane::GameTurn 校验未受影响）
cargo test -p poker_l1 --lib consensus::

# 6. 全套测试（含集成测试）
cargo test -p poker_l1

# 7. clippy 检查（确认无 is_gameturn 相关死代码警告）
cargo clippy -p poker_l1 --lib
```

## Assumptions & Decisions

1. **沿用原计划的所有决策**：本收尾计划不改变原计划的任何设计决策（gas 策略跟随 lane、lane-contract 一致性强制、TxContext.is\_gameturn 移除等）。
2. **测试代码风格**：与现有 precompile::tests 中的 `TestPrecompile` / `make_test_precompile` 风格保持一致。
3. **GasFreeTestPrecompile 复用**：precompile.rs 中新增的 `GasFreeTestPrecompile` 与 executor.rs 中的同名 struct 独立（不同模块，无冲突），保持模块内聚。

## Verification Steps

1. 在 [precompile.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/precompile.rs) `mod tests` 中追加 `GasFreeTestPrecompile` struct + 2 个测试函数。
2. `cargo check -p poker_l1` 编译通过。
3. `cargo test -p poker_l1 --lib vm::precompile::tests` 全部通过（11 → 13 个测试）。
4. `cargo test -p poker_l1` 全套通过（无回归）。
5. `cargo clippy -p poker_l1 --lib` 无新增 warning。
6. `cargo test -p poker_l1 --lib consensus::` 全套通过（共识层回归）。

