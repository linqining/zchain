# Texas Poker ZKVM 移植 — Phase 2 执行计划

> **上下文**：本计划基于已批准的完整方案 `.trae/documents/texas_poker_zkvm_port_full.md`（含 D1-D7 决策、Phase 1-5 全景）。Phase 1 已完成并验证通过，本文件聚焦 **Phase 2 的精确执行步骤**，使执行者无需再做任何选择。
>
> **用户原话**："将项目 `poker_l1/src/vm/contracts/texas_poker` 改写成 zkvm 可运行的形式，并运行测试"。
> **已批准范围**：完整 Phase 1-5；本计划执行 Phase 2，完成后继续 Phase 3-5（按完整方案推进）。

***

## 当前状态（已核对）

### Phase 1 已完成 ✅

| 项                                 | 文件                                                                                                                                 | 状态            |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| 空 `[workspace]` 表                 | [guest\_sdk/Cargo.toml](file:///Users/mac/projects/zchain/poker_zkvm/guest_sdk/Cargo.toml)                                         | ✅ 末尾已追加       |
| 空 `[workspace]` 表                 | [guests/texas\_poker/Cargo.toml](file:///Users/mac/projects/zchain/poker_zkvm/guests/texas_poker/Cargo.toml)                       | ✅ 末尾已追加       |
| `#[macro_use] extern crate alloc` | [guest\_sdk/src/lib.rs](file:///Users/mac/projects/zchain/poker_zkvm/guest_sdk/src/lib.rs)                                         | ✅             |
| `static mut HEAP_NEXT` bump alloc | [guest\_sdk/src/allocator.rs](file:///Users/mac/projects/zchain/poker_zkvm/guest_sdk/src/allocator.rs)                             | ✅ 无 atomic    |
| `use alloc::vec::Vec`             | [guest\_sdk/src/io.rs](file:///Users/mac/projects/zchain/poker_zkvm/guest_sdk/src/io.rs)                                           | ✅             |
| Phase 1 骨架                        | [guests/texas\_poker/src/main.rs](file:///Users/mac/projects/zchain/poker_zkvm/guests/texas_poker/src/main.rs)                     | ✅ 返回 `[0x42]` |
| Phase 1 集成测试                      | [poker\_zkvm/tests/texas\_poker\_guest\_phase1.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/texas_poker_guest_phase1.rs) | ✅ 5 个测试       |

**Phase 1 验证结果**（来自前序对话）：

* guest ELF 编译成功（1600 字节）

* `validate_elf` 通过 11 项校验

* `execute_elf` 返回 `output == [0x42]`

* trace 步数实测 \~49215（上限 200000）

### Phase 2 待执行（本计划目标）

`guests/texas_poker/src/` 目前只有 `main.rs`。需创建 5 个纯逻辑文件并配置双模式编译（riscv32i release + std-test 单元测试）。

***

## 已读源文件分析（5 个，\~1,830 行）

### 1. constants.rs（145 行）— 无依赖

* 纯常量定义，无 `use`、无 derive、无 std 依赖

* 自带 3 个单元测试（`test_round_state_constants` / `test_shuffle_phase_constants` / `test_player_limits`）

* **改动**：零改动，直接复制

### 2. card.rs（219 行）— borsh + serde

* `use borsh::{BorshDeserialize, BorshSerialize};`（保留）

* `use serde::{Deserialize, Serialize};`（删除）

* `Card` 和 `PlayingCard` 各一处 `#[derive(... Serialize, Deserialize, BorshSerialize, BorshDeserialize)]`（删 Serialize, Deserialize）

* `impl std::fmt::Display for Card` + `std::fmt::Formatter` + `std::fmt::Result`（改 `core::fmt::`）

* `format!` 宏可用（guest\_sdk lib.rs 已 `#[macro_use] extern crate alloc`）

* 自带 4 个单元测试

* **改动**：删 serde use + derive；`std::fmt` → `core::fmt`

### 3. hand\_evaluator.rs（635 行）— serde + std::collections::HashSet + std::fmt + std::cmp

* `use serde::{Deserialize, Serialize};`（删除）

* `HandRank` derive `#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]`（删 Serialize, Deserialize，保留 Hash）

* `impl std::fmt::Display for HandRank` + `std::fmt::Formatter` + `std::fmt::Result`（改 `core::fmt::`）

* `impl Ord for HandRank { fn cmp(&self, other: &Self) -> std::cmp::Ordering }`（改 `core::cmp::Ordering`）

* `impl PartialOrd for HandRank { fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> }`（改 `core::cmp::Ordering`）

* `assert_no_duplicates` 中 `use std::collections::HashSet;` — **替换为 O(n²) 双重循环**（输入固定 7 张牌，无需 BTreeSet，避免额外依赖）

* `vec![]` / `Vec<u8>` 需 `use alloc::vec::Vec;`（或依赖 lib.rs 宏导出，但类型导入仍需显式）

* `compare` / `compare_kickers` / `best_hand` / `evaluate_five_impl` / `find_winners` 等函数体逻辑不变

* 自带 12 个单元测试，测试内 `use crate::vm::contracts::texas_poker::card::*;`（改为 `use super::super::card::*;` 即 `use crate::card::*;`）

* **改动**：删 serde；`std::fmt`→`core::fmt`；`std::cmp`→`core::cmp`；HashSet→双重循环；加 `use alloc::vec::Vec;`

### 4. betting.rs（296 行）— borsh + serde + thiserror

* `use borsh::{BorshDeserialize, BorshSerialize};`（保留）

* `use serde::{Deserialize, Serialize};`（删除）

* `BettingRound` derive `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]`（删 Serialize, Deserialize）

* `BettingError` derive `#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]` + `#[error("...")]` 属性 — **替换**：

  * 删 `thiserror::Error` derive 和 `#[error(...)]` 属性

  * 保留 `#[derive(Debug, Clone, PartialEq, Eq)]`

  * 错误类型在 guest 内只需 `Debug + Clone + PartialEq + Eq`（Error trait 非必需，Result\<T, BettingError> 不要求 Error bound）

* `vec![]` / `Vec` 需 `use alloc::vec::Vec;`

* 自带 10 个单元测试，`use super::*;` 即可

* **改动**：删 serde；删 thiserror derive + error 属性；加 `use alloc::vec::Vec;`

### 5. side\_pot.rs（535 行）— borsh + serde + thiserror

* `use serde::{Deserialize, Serialize};`（删除）

* `use borsh::{BorshSerialize, BorshDeserialize};`（保留）

* `use super::constants::MAX_TOTAL_BET;`（保留，依赖 Phase 2 constants.rs）

* `SidePot` derive `#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]`（删 Serialize, Deserialize）

* `SidePotError` derive `#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]` + `#[error("...")]`（同 betting.rs 处理：删 thiserror + error 属性）

* `SidePotResult` derive `#[derive(Debug, Clone, PartialEq, Eq)]`（无变化）

* `vec![]` / `Vec` / `checked_add` / `sort_unstable` / `.contains()` 都可用（需 `use alloc::vec::Vec;`）

* `calculate_side_pots` / `distribute_pots` / `sum_bets` / `collect_all_in_bets` 函数体逻辑不变

* 自带 \~13 个单元测试，`use super::*;` 即可

* **改动**：删 serde；删 thiserror derive + error 属性；加 `use alloc::vec::Vec;`

***

## thiserror 替换细节（betting.rs + side\_pot.rs 共同问题）

`thiserror` 1.x 在 no\_std 下需特殊配置且 riscv32i target 兼容性存疑。**最简可靠方案**：删除 `thiserror::Error` derive 和 `#[error("...")]` 属性，保留 `#[derive(Debug, Clone, PartialEq, Eq)]`。

**理由**：

* guest 内 `Result<T, BettingError>` 不要求 `E: std::error::Error`，只需 `Debug`

* 单元测试用 `assert_eq!(result, Err(BettingError::InvalidRaiseAmount))` 比较，只需 `PartialEq`

* 若 std-test feature 下某些测试需要 Display，可后续手动 `impl core::fmt::Display`，但当前测试用例均不依赖 Display

***

## HashSet 替换细节（hand\_evaluator.rs::assert\_no\_duplicates）

原实现：

```rust
fn assert_no_duplicates(cards: &[Card]) {
    use std::collections::HashSet;
    let set: HashSet<_> = cards.iter().map(|c| (c.suit, c.rank)).collect();
    assert_eq!(set.len(), cards.len(), "牌组中存在重复牌");
}
```

**替换为 O(n²) 双重循环**（输入固定 7 张牌，性能可忽略）：

```rust
fn assert_no_duplicates(cards: &[Card]) {
    for i in 0..cards.len() {
        for j in (i + 1)..cards.len() {
            assert_ne!(
                (cards[i].suit, cards[i].rank),
                (cards[j].suit, cards[j].rank),
                "牌组中存在重复牌"
            );
        }
    }
}
```

避免引入 `alloc::collections::BTreeSet` 或其他 no\_std 集合依赖，逻辑等价且确定性更强（无排序歧义）。

***

## 双模式编译方案（riscv32i release + std-test 单元测试）

### 关键技术点

guest crate 是 `[[bin]]`（`name = "texas_poker_guest"`）。riscv32i target 不支持 `cargo test`（无 std + 无 test harness），故用 `std-test` feature 在 host std 模式编译纯逻辑单元测试。

### main.rs 改造（双模式门控）

```rust
//! Texas Poker ZKVM Guest。
//!
//! 双模式编译：
//! - 默认（riscv32i-unknown-none-elf）：no_std + no_main，编译为 RV32I ELF
//! - std-test feature：std + 有 main，跑 host 单元测试

#![cfg_attr(not(feature = "std-test"), no_std)]
#![cfg_attr(not(feature = "std-test"), no_main)]

// std-test 模式引入 std（供测试用）
#[cfg(feature = "std-test")]
extern crate std;

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

// 仅 riscv32i 模式注册 _start + panic_handler
#[cfg(not(feature = "std-test"))]
zkvm_guest_sdk::entry_point!();

mod constants;
mod card;
mod hand_evaluator;
mod betting;
mod side_pot;

/// guest 主逻辑入口（riscv32i 模式由 entry_point 调用）。
#[no_mangle]
pub extern "Rust" fn zkvm_main(_input: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Phase 2: 仍返回 [0x42]，dispatch 接入在 Phase 4
    Ok(alloc::vec![0x42])
}

// std-test 模式需要一个 main（cargo test 对 bin crate 需要 main）
#[cfg(feature = "std-test")]
fn main() {}
```

### Cargo.toml 改造

```toml
[dependencies]
zkvm_guest_sdk = { path = "../../guest_sdk" }
borsh = { version = "1", default-features = false, features = ["derive"] }

[features]
default = []
# std-test：用 host std 编译纯逻辑单元测试（避开 riscv32i 不支持 cargo test）
std-test = []
```

***

## 执行步骤（按顺序）

### 步骤 1：修改 Cargo.toml 加依赖 + std-test feature

**文件**：[guests/texas\_poker/Cargo.toml](file:///Users/mac/projects/zchain/poker_zkvm/guests/texas_poker/Cargo.toml)

在 `[dependencies]` 下加 `borsh`，新增 `[features]` 段。

### 步骤 2：创建 constants.rs（零改动复制）

**文件**：`guests/texas_poker/src/constants.rs`
**源**：[poker\_l1/.../texas\_poker/constants.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/constants.rs)
**改动**：无（直接复制 145 行，含 3 个单元测试）

### 步骤 3：创建 card.rs

**文件**：`guests/texas_poker/src/card.rs`
**源**：[poker\_l1/.../texas\_poker/card.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/card.rs)
**改动**：

* 删 `use serde::{Deserialize, Serialize};`

* `Card` derive 删 `Serialize, Deserialize`

* `PlayingCard` derive 删 `Serialize, Deserialize`

* `impl std::fmt::Display` → `impl core::fmt::Display`

* `std::fmt::Formatter` → `core::fmt::Formatter`

* `std::fmt::Result` → `core::fmt::Result`

### 步骤 4：创建 hand\_evaluator.rs

**文件**：`guests/texas_poker/src/hand_evaluator.rs`
**源**：[poker\_l1/.../texas\_poker/hand\_evaluator.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/hand_evaluator.rs)
**改动**：

* 删 `use serde::{Deserialize, Serialize};`

* 加 `use alloc::vec::Vec;`

* `HandRank` derive 删 `Serialize, Deserialize`（保留 `Hash`）

* `impl std::fmt::Display` → `impl core::fmt::Display`，`Formatter`/`Result` 同改

* `impl Ord` 的 `std::cmp::Ordering` → `core::cmp::Ordering`

* `impl PartialOrd` 的 `Option<std::cmp::Ordering>` → `Option<core::cmp::Ordering>`

* `assert_no_duplicates` 用 O(n²) 双重循环替换 HashSet

* 测试内 `use crate::vm::contracts::texas_poker::card::*;` → `use crate::card::*;`

### 步骤 5：创建 betting.rs

**文件**：`guests/texas_poker/src/betting.rs`
**源**：[poker\_l1/.../texas\_poker/betting.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/betting.rs)
**改动**：

* 删 `use serde::{Deserialize, Serialize};`

* 加 `use alloc::vec::Vec;`

* `BettingRound` derive 删 `Serialize, Deserialize`

* `BettingError` derive 删 `thiserror::Error`，删所有 `#[error("...")]` 属性，保留 `#[derive(Debug, Clone, PartialEq, Eq)]`

### 步骤 6：创建 side\_pot.rs

**文件**：`guests/texas_poker/src/side_pot.rs`
**源**：[poker\_l1/.../texas\_poker/side\_pot.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker/side_pot.rs)
**改动**：

* 删 `use serde::{Deserialize, Serialize};`

* 加 `use alloc::vec::Vec;`

* `SidePot` derive 删 `Serialize, Deserialize`

* `SidePotError` derive 删 `thiserror::Error`，删所有 `#[error("...")]` 属性，保留 `#[derive(Debug, Clone, PartialEq, Eq)]`

### 步骤 7：改造 main.rs（双模式门控 + mod 声明）

**文件**：[guests/texas\_poker/src/main.rs](file:///Users/mac/projects/zchain/poker_zkvm/guests/texas_poker/src/main.rs)
**改动**：按"双模式编译方案"中的代码替换全文

### 步骤 8：验证 — riscv32i 编译

```bash
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
```

**预期**：编译成功，产物 `target/riscv32i-unknown-none-elf/release/texas_poker_guest`

### 步骤 9：验证 — host std 单元测试

```bash
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 test --features std-test
```

**预期**：constants(3) + card(4) + hand\_evaluator(12) + betting(10) + side\_pot(\~13) ≈ 42 个测试全绿

### 步骤 10：验证 — Phase 1 集成测试回归

```bash
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
cd /Users/mac/projects/zchain && cargo test -p poker_zkvm --features test-helpers --test texas_poker_guest_phase1 -- --nocapture
```

**预期**：Phase 1 的 5 个测试仍全绿（ELF 仍通过 validate\_elf 11 项校验 + execute\_elf 返回 \[0x42]）

***

## Phase 2 完成判据

* [ ] `cargo +nightly-2026-04-15 build --release` 成功（riscv32i ELF）

* [ ] `cargo +nightly-2026-04-15 test --features std-test` 全绿（\~42 个单元测试）

* [ ] Phase 1 集成测试回归全绿（5 个测试）

* [ ] `validate_elf` 仍通过 11 项校验（ELF 增大但未超限）

* [ ] `execute_elf` 仍返回 `[0x42]`（main.rs 逻辑未变）

***

## Phase 3-5 后续（按完整方案推进，此处仅索引）

* **Phase 3**：host 校验 `bls_hash_to_scalar`(0x15) 是否==M-P18 → guest\_sdk bls.rs 类型补全 → utils/types/events 移植

* **Phase 4**：host 新增 4 syscall（Blake2b256 + 3 proof verify）→ state\_machine(2814行) + dispatch(1046行) 移植 → main.rs 接入 dispatch

* **Phase 5**：E2E 完整一手牌测试 + 性能基准 + 与 MVP(217 条手写指令) 对比报告

详见 [.trae/documents/texas\_poker\_zkvm\_port\_full.md](file:///Users/mac/projects/zchain/.trae/documents/texas_poker_zkvm_port_full.md)。

***

## 风险与缓解（Phase 2 特定）

### R2-1: borsh 1.x 在 riscv32i target 编译失败

* **缓解**：若 build 失败，尝试 `borsh = { version = "1", default-features = false, features = ["derive", "bytes"] }`；若仍失败，手动实现关键 struct 的 `to_bytes`/`from_bytes`（card.rs 的 Card/PlayingCard、betting.rs 的 BettingRound、side\_pot.rs 的 SidePot）

### R2-2: std-test feature 双模式门控冲突

* **缓解**：若 `cargo test --features std-test` 报 no\_std/no\_main 冲突，检查 main.rs 的 `cfg_attr` 门控是否正确；必要时把纯逻辑抽到 `lib.rs`，bin 仅在 riscv32i 模式编译

### R2-3: thiserror 删除后某些测试依赖 Error trait

* **缓解**：已确认 5 个源文件的测试用例均用 `assert_eq!(result, Err(...))` 比较，不依赖 Display/Error；若个别测试用 `unwrap()` + Debug 打印，`Debug` derive 已保留

