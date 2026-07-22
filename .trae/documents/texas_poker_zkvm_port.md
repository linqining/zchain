# Texas Poker → ZKVM 移植方案

## Context

**问题**：`poker_l1/src/vm/contracts/texas_poker/`（7,961 行 Rust，11 个文件）是 L1 节点的 native precompile，依赖 `blstrs`/`poker_protocol`/`halo2curves` 等无法编译为 RV32I 的 crate。现有 zkvm MVP（`poker_zkvm/src/test_helpers.rs:559`）是 217 条手写 RV32I 汇编，仅做手牌评估，不可持续。

**目标**：用 Rust no\_std 编译 texas\_poker 为 `riscv32i-unknown-none-elf` ELF，用 goblin 解析后在 poker\_zkvm 中运行。不手写汇编。

**关键事实**（已验证）：

* poker\_zkvm 已有 21 个 syscall 完全覆盖 texas\_poker 密码学需求（BLS 0x10-0x15、GameState 0x20-0x21、Card 0x30-0x32）

* `bls_hash_to_scalar` (0x15) 与 `texas_poker/utils.rs::hash_to_scalar` 算法一致

* `HEAP_START = 0x1000_0000`，`STACK_TOP = 0x8000_0000`，最大内存 16MB

* elf\_validator 校验：ELF32 + LE + EM\_RISCV + 无 PT\_DYNAMIC + 无 DT\_NEEDED + 拒绝 compressed 指令

* poker\_zkvm 自己已用 `extern crate alloc`（lib.rs:48），alloc 可用

* `poker_protocol`（在 `/Users/mac/projects/zgame/poker_protocol`）不是 no\_std，依赖 blstrs/rayon/merlin，不能直接编译

**功能分层**：

* 纯逻辑（\~1,830 行）：card.rs, betting.rs, side\_pot.rs, hand\_evaluator.rs, constants.rs

* 密码学（718 行）：utils.rs → syscall 替换

* 混合（\~5,364 行）：types.rs, state\_machine.rs, dispatch.rs, events.rs → 重构 import + proof 类型改 opaque bytes

## 推荐方案：guest\_sdk + guest crate 两层架构

### 目录结构

```
poker_zkvm/
├── guest_sdk/                         # 新增：no_std syscall SDK
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                     # #![no_std] + extern crate alloc
│       ├── syscalls.rs                # 21 个 raw ecall 包装（unsafe inline asm）
│       ├── allocator.rs               # BumpAlloc + #[global_allocator]
│       ├── entry.rs                   # _start trampoline + #[panic_handler]
│       ├── prelude.rs                 # Vec/String/entry! re-export
│       ├── io.rs                      # read_input/commit_output 便捷 API
│       ├── bls.rs                     # G1Point([u8;48]) / Scalar([u8;32])
│       ├── hash.rs                    # poseidon/sha256/keccak256
│       └── game.rs                    # card_encode/decode/shuffle_verify
└── guests/
    └── texas_poker/                   # 新增：texas_poker guest crate
        ├── Cargo.toml
        ├── .cargo/config.toml          # target = riscv32i-unknown-none-elf
        └── src/
            ├── lib.rs                  # #![no_std] + #![no_main]
            ├── main.rs                 # zkvm_main entry
            ├── codec.rs                # 简化 borsh 替代
            ├── types_bridge.rs        # 本地化 Address/ObjectID/DispatchContext
            └── texas_poker/            # 移植自 poker_l1
                ├── constants.rs        # 照抄
                ├── card.rs             # 照抄，去 serde/borsh
                ├── betting.rs          # 照抄，去 serde/borsh
                ├── side_pot.rs         # 照抄，去 thiserror
                ├── hand_evaluator.rs   # 照抄
                ├── events.rs           # 替换 ObjectID/Address
                ├── types.rs            # ECPoint→G1Point, ECScalar→Scalar
                ├── utils.rs            # 重写：blstrs → guest_sdk::bls
                ├── state_machine.rs    # proof 类型改 opaque bytes
                └── dispatch.rs         # 替换 import
```

### 关键设计

**1. syscall 包装**（`guest_sdk/src/syscalls.rs`）

使用 `core::arch::asm!` 内联 `ecall` 指令，ABI 严格对齐 host `SyscallId` 枚举：

```rust
unsafe fn syscall3(num: u32, a0: u32, a1: u32, a2: u32) -> u32 {
    let ret: u32;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0 => ret,
        in("a1") a1, in("a2") a2, in("a7") num,
        options(nostack, preserves_flags),
    );
    ret
}
```

**2. Bump Allocator**（`guest_sdk/src/allocator.rs`）

* 起始 `HEAP_START = 0x1000_0000`，大小 8MB

* 无 free/dealloc（guest 短生命周期，无内存复用需求）

* `#[global_allocator]` 注册

**3. Entry Point**（`guest_sdk/src/entry.rs`）

* `_start` 函数：读 4 字节长度前缀 → 读 N 字节输入 → 调 `zkvm_main` → `commit_output`

* `#[panic_handler]`：路由到 `panic` syscall，不格式化 location（节省代码体积）

**4. Host 侧改动**（`poker_zkvm/src/syscalls/host.rs`）

* `ReadInputSyscall::host_execute` 调整：a0 返回 actual\_len（当前返回 ptr，guest 无法读取 actual\_len）

**5. types\_bridge.rs** — 本地化 poker\_l1 类型

* `Address = [u8; 20]`、`ObjectID`（28 字节定长）、`DispatchContext`、`DispatchResult`

* 与 host 序列化字节级兼容

**6. proof 类型改 opaque bytes**

* `ZKShuffleProof(pub Vec<u8>)`、`DLEqProof(pub Vec<u8>)` 等

* guest 内不做 verify 数学，通过 `shuffle_verify` syscall (0x32) 或 `verify_or_skip(zk_skip=true)` 跳过

## 分阶段实施

### Phase 1：SDK 骨架可编译（1-2 天）

* 创建 `guest_sdk/` + 最小 `texas_poker_guest`（`zkvm_main` 返回 `[0x42]`）

* 修改 host `ReadInputSyscall` 返回值

* 验证：ELF 通过 `validate_elf` 11 项校验，`execute_elf` 返回 `[0x42]`

### Phase 2：纯逻辑移植（2-3 天）

* 复制 card/betting/side\_pot/hand\_evaluator/constants 到 guest

* 移除 serde/borsh/thiserror derive

* 验证：guest crate 编译为 ELF 通过，host 单元测试（std-test feature）行为与原版一致

### Phase 3：crypto utils + types（3-4 天）

* 实现 `guest_sdk/bls.rs`（G1Point/Scalar，5 个核心方法）

* 重写 `utils.rs`：blstrs → syscall

* 移植 types.rs/events.rs

* 验证：guest 调用 `hash_to_g1(b"test")` → 与 host `G1Projective::hash_to_curve` 比对

### Phase 4：state\_machine + dispatch（4-5 天）

* 移植 state\_machine.rs（2,814 行）+ dispatch.rs（1,046 行）

* proof 类型改 opaque bytes

* 实现 codec.rs（最小 borsh 替代）

* 验证：完整一手牌流程 `create_table → join → start_hand → fold/call → settle`（zk\_skip=true）

### Phase 5：完整 Mental Poker + 性能（5-7 天）

* 补全 syscall 0x16-0x19（scalar\_add/sub/inv、g1\_neg、g1\_generator）

* 取消 zk\_skip，启用真实 verify

* 性能基准：对比手写汇编 vs Rust 编译 ELF

## 关键文件

| 文件                                                | 作用                                        |
| ------------------------------------------------- | ----------------------------------------- |
| `poker_zkvm/src/syscalls/host.rs`                 | 修改 ReadInputSyscall 返回值约定                 |
| `poker_zkvm/src/compiler/elf_validator.rs`        | Phase 1 验证基准（11 项校验）                      |
| `poker_zkvm/src/compiler/mod.rs`                  | `compile_crate` 已就绪                       |
| `poker_l1/src/vm/contracts/texas_poker/utils.rs`  | 重写为 syscall 的核心模板                         |
| `poker_zkvm/tests/texas_poker_full_hand_bench.rs` | E2E 测试模板                                  |
| `Cargo.toml`（workspace）                           | 增加 guest\_sdk、guests/texas\_poker members |

## 验证方法

### Phase 1 验证

```bash
rustup +nightly-2026-04-15 target add riscv32i-unknown-none-elf
cd poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
# ELF 通过 validate_elf
cargo run -p poker_zkvm --example run_minimal_guest
# 预期：output = [0x42]
```

### Phase 4 E2E 验证

```bash
cargo test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
# 预期：完整一手牌流程 prove + verify 通过
```

### 性能对比（Phase 5）

```bash
cargo test -p poker_zkvm --features test-helpers --test texas_poker_full_hand_bench -- --nocapture --ignored
# 对比手写汇编 vs Rust 编译的 trace 步数 / prove 时间 / proof 大小
```

## 风险与缓解

| 风险                                 | 缓解                                                    |
| ---------------------------------- | ----------------------------------------------------- |
| 默认 linker script 不满足 validate\_elf | Phase 1 优先验证；提供自定义 `linker.ld`                        |
| Rust emitted compressed 指令         | `-C target-feature=-c` 禁用；validate\_elf 捕获            |
| 代码体积超 8MB                          | `lto=fat` + `codegen-units=1` + `strip` + 删 `format!` |
| BLS syscall 缺口（scalar\_add 等）      | Phase 4 用 zk\_skip=true；Phase 5 补 syscall             |
| trace 步数超 1M                       | opt-level=3 + 关 overflow-checks；分阶段监控                 |

