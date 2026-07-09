# ZKVM Syscall 参考

> 文档编号：38-3  
> 对应模块：`poker_zkvm::syscalls`  
> 对应 spec：spec.md L196-277（v1.4 FROZEN）

## 1. 概述

ZKVM 提供 10 个系统调用（syscall），通过 `ECALL` 指令触发。每个 syscall 有唯一的数字 ID，通过寄存器 `a7` (x17) 传参。

### 1.1 ABI 版本

```rust
pub const ZKVM_ABI_VERSION: u32 = 1;
```

写入 proof header，链上 verifier 校验。未来 ABI 升级须 bump 版本号 + 链上 verifier 兼容性矩阵。

### 1.2 寄存器约定

| 寄存器 | 别名 | 用途 |
|--------|------|------|
| x10 | a0 | 第一个参数 / 返回值 |
| x11 | a1 | 第二个参数 / 返回值 |
| x12 | a2 | 第三个参数 |
| x13 | a3 | 第四个参数 |
| x17 | a7 | Syscall ID |

### 1.3 调用方式

```rust
// 设置 a7 = syscall ID
addi(17, 0, SYSCALL_ID);

// 设置参数（a0, a1, a2, ...）
addi(10, 0, param1);  // a0
addi(11, 0, param2);  // a1

// 触发 syscall
ecall();
```

## 2. Syscall 列表

### 2.1 ReadInput (0x01)

从 host input buffer 读取数据到 VM 内存。

**ABI**：
- `a0` = ptr（写入目标地址；若 `a0=0` 则用 `HEAP_START` 向后兼容）
- `a1` = len（期望读取长度）
- 返回：`a0` = ptr（实际写入地址），`a1` = actual_len（实际读取长度）

**Gas**：`GAS_ZKVM_READ_INPUT_BASE = 10`（固定）

**示例**：
```rust
addi(10, 0, 0x2000),  // a0 = 0x2000 (写入地址)
addi(11, 0, 32),      // a1 = 32 (读取 32 字节)
addi(17, 0, 1),       // a7 = 1 (read_input)
ecall(),               // → VM 内存 [0x2000, 0x2020) 写入 input
```

### 2.2 CommitOutput (0x02)

写入 host output buffer 并终止执行（halt）。

**ABI**：
- `a0` = ptr（读取源地址）
- `a1` = len（输出长度）
- 无返回值（执行终止）

**Gas**：`GAS_ZKVM_COMMIT_OUTPUT_BASE = 10`（固定）

**示例**：
```rust
sw(1, 0, 0),           // SW x1, 0(x0) — store result to addr 0
addi(10, 0, 0),       // a0 = 0 (output ptr)
addi(11, 0, 4),       // a1 = 4 (output len)
addi(17, 0, 2),       // a7 = 2 (commit_output)
ecall(),               // → halt, output = [0..4)
```

### 2.3 Poseidon (0x03)

计算 Poseidon 哈希（BN254 标量域）。

**ABI**：
- `a0` = ptr（输入地址）
- `a1` = len（输入长度，字节）
- `a2` = out_ptr（输出地址，写入 32 字节哈希）
- 无返回值（结果写入 out_ptr）

**Gas**：`GAS_ZKVM_POSEIDON_BASE + GAS_ZKVM_POSEIDON_PER_BLOCK * ceil(len / 32)`
- Base: 100
- Per 32-byte block: 50

**示例**：
```rust
addi(10, 20, 0),   // a0 = input_ptr
addi(11, 0, 32),   // a1 = 32 (input len)
addi(12, 20, 0),   // a2 = output_ptr
addi(17, 0, 3),    // a7 = 3 (poseidon)
ecall(),            // → 32B Poseidon 哈希写入 output_ptr
// Gas = 100 + 50 * 1 = 150
```

### 2.4 Sha256 (0x04)

计算 SHA-256 哈希。

**ABI**：
- `a0` = ptr（输入地址）
- `a1` = len（输入长度，字节）
- `a2` = out_ptr（输出地址，写入 32 字节哈希）
- 无返回值（结果写入 out_ptr）

**Gas**：`GAS_ZKVM_SHA256_PER_BYTE * len`
- Per byte: 1

**示例**：
```rust
addi(10, 20, 0),   // a0 = input_ptr
addi(11, 0, 32),   // a1 = 32 (input len)
addi(12, 20, 0),   // a2 = output_ptr (in-place)
addi(17, 0, 4),    // a7 = 4 (sha256)
ecall(),            // → 32B SHA-256 哈希写入 output_ptr
// Gas = 1 * 32 = 32
```

### 2.5 EcdsaVerify (0x05)

验证 secp256k1 ECDSA 签名。

**ABI**：
- `a0` = msg_ptr（消息地址）
- `a1` = msg_len（消息长度）
- `a2` = sig_ptr（签名地址，64 字节：r || s）
- `a3` = pubkey_ptr（公钥地址，33 字节 compressed）
- 返回：`a0` = 1（验证通过）或 0（验证失败）

**Gas**：`GAS_ZKVM_ECDSA_VERIFY = 100,000`（固定）

**示例**：
```rust
addi(10, 0, 0x2000),   // a0 = msg_ptr
addi(11, 0, 32),        // a1 = msg_len
addi(12, 0, 0x2100),   // a2 = sig_ptr
addi(13, 0, 0x2160),   // a3 = pubkey_ptr
addi(17, 0, 5),         // a7 = 5 (ecdsa_verify)
ecall(),                 // → a0 = 1 or 0
```

### 2.6 EmitEvent (0x06)

发射事件到 public_io（绑定 step_index）。

**ABI**：
- `a0` = ptr（事件数据地址）
- `a1` = len（事件数据长度）
- 无返回值（事件哈希追加到 public_io.events）

**Gas**：`GAS_ZKVM_EMIT_EVENT_BASE + GAS_ZKVM_EMIT_EVENT_PER_BYTE * len`
- Base: 10
- Per byte: 1

**说明**：事件哈希 = `BLAKE2b(step_index || event_data)`，绑定执行位置防重放。

### 2.7 Log (0x07)

写入 host 日志（不进入 public_io）。

**ABI**：
- `a0` = ptr（日志消息地址）
- `a1` = len（日志消息长度）
- 无返回值

**Gas**：`GAS_ZKVM_LOG_BASE + GAS_ZKVM_LOG_PER_BYTE * len`
- Base: 10
- Per byte: 1

### 2.8 Panic (0x08)

终止执行并返回错误。

**ABI**：
- `a0` = ptr（错误消息地址）
- `a1` = len（错误消息长度）
- 无返回值（执行终止，返回 `ZkvmError::Other("zkvm_panic: ...")`）

**Gas**：`GAS_ZKVM_PANIC = 10`（固定）

### 2.9 GetRandomness (0x09)

从 host seed 派生确定性随机数。

**ABI**：
- `a0` = out_ptr（输出地址，写入 32 字节 Fr）
- 无返回值（随机数写入 out_ptr）

**Gas**：`GAS_ZKVM_GET_RANDOMNESS = 100`（固定）

**说明**：随机数 = `BLAKE2b(randomness_seed || counter)`，每次调用 counter 递增。确定性派生 — prover 和 verifier 产生相同序列。

### 2.10 ReadState (0x0A)

读取 host 链上状态（仅允许白名单 slot）。

**ABI**：
- `a0` = slot（状态 slot ID，须在白名单内）
- `a1` = out_ptr（输出地址）
- 无返回值（状态数据写入 out_ptr）

**Gas**：`GAS_ZKVM_READ_STATE_PER_SLOT * num_slots`
- Per slot: 50

**白名单**：仅 slot 0x01-0x05 允许访问。

## 3. Slot 白名单

| Slot | 常量 | 值 | 说明 |
|------|------|-----|------|
| `SLOT_GAME_STATE` | 0x01 | 游戏状态 |
| `SLOT_PLAYER_HANDS` | 0x02 | 玩家手牌 |
| `SLOT_POT_AMOUNT` | 0x03 | 底池金额 |
| `SLOT_CURRENT_TURN` | 0x04 | 当前轮次 |
| `SLOT_ACK_CHAIN` | 0x05 | 确认链 |

非白名单 slot 返回 `ZkvmError::InvalidSlot(slot)`。

```rust
pub fn is_whitelisted_slot(slot: u32) -> bool {
    matches!(slot, 0x01..=0x05)
}
```

## 4. Gas 计费总表

| Syscall | ID | Gas 公式 | 示例 Gas |
|---------|-----|---------|---------|
| ReadInput | 0x01 | 10（固定） | 10 |
| CommitOutput | 0x02 | 10（固定） | 10 |
| Poseidon | 0x03 | 100 + 50 * ceil(len/32) | len=32 → 150 |
| Sha256 | 0x04 | 1 * len | len=32 → 32 |
| EcdsaVerify | 0x05 | 100,000（固定） | 100,000 |
| EmitEvent | 0x06 | 10 + 1 * len | len=32 → 42 |
| Log | 0x07 | 10 + 1 * len | len=32 → 42 |
| Panic | 0x08 | 10（固定） | 10 |
| GetRandomness | 0x09 | 100（固定） | 100 |
| ReadState | 0x0A | 50 * num_slots | 1 slot → 50 |

**注意**：Gas 计费是 on-chain 概念，host 执行不实际扣 gas。`syscall_gas` 函数供 executor / prover 估算 syscall gas 开销。

## 5. Rust API

### 5.1 SyscallId 枚举

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SyscallId {
    ReadInput = 0x01,
    CommitOutput = 0x02,
    Poseidon = 0x03,
    Sha256 = 0x04,
    EcdsaVerify = 0x05,
    EmitEvent = 0x06,
    Log = 0x07,
    Panic = 0x08,
    GetRandomness = 0x09,
    ReadState = 0x0A,
}
```

### 5.2 SyscallId 方法

```rust
// 从 u32 构造（非法 ID 返回 Err）
let id = SyscallId::from_u32(0x04)?; // Sha256

// 获取全部 10 个 syscall ID
for id in SyscallId::all() {
    println!("{id:?} = 0x{:02X}", id as u32);
}
```

### 5.3 SyscallContext

`SyscallContext` 持有 syscall 执行所需的所有状态：

| 字段 | 类型 | 说明 |
|------|------|------|
| `input` | `Vec<u8>` | 程序输入（ReadInput 读取） |
| `output` | `Vec<u8>` | 程序输出（CommitOutput 写入） |
| `events` | `Vec<Fr>` | 事件哈希列表（EmitEvent 追加） |
| `logs` | `Vec<Vec<u8>>` | 日志消息列表（Log 追加） |
| `halted` | `bool` | halt 标志（CommitOutput / Panic 设置） |
| `step_index` | `u64` | 当前步索引（EmitEvent 绑定） |
| `randomness_seed` | `Fr` | 随机数种子 |
| `initial_commitment` | `Fr` | 初始承诺 |
| `final_commitment` | `Fr` | 终止承诺 |
| `host_state` | `Box<dyn ZkvmHostState>` | Host 状态读取实现 |

### 5.4 SyscallRegistry

```rust
// 创建完整注册表（注册全部 10 个 syscall）
let registry = SyscallRegistry::new();

// 分派 syscall
registry.dispatch(syscall_id, &mut ctx, &mut state)?;
```

### 5.5 ZkvmHostState trait

```rust
pub trait ZkvmHostState: Send + Sync {
    /// 读取指定 slot 的链上状态
    fn read_slot(&self, slot: u32) -> Result<Vec<u8>, ZkvmError>;
}
```

`StubHostState` 是测试用空实现（所有 slot 返回 `Err`）。生产环境须提供真实实现。

### 5.6 syscall_gas 函数

```rust
use poker_zkvm::syscalls::{SyscallId, gas::{syscall_gas, SyscallGasArgs}};

let args = SyscallGasArgs {
    input_len: 32,
    num_slots: 1,
};
let gas = syscall_gas(SyscallId::Sha256, &args);
assert_eq!(gas, 32);
```

## 6. Syscall trait

每个 syscall 实现 `Syscall` trait：

```rust
pub trait Syscall: Send + Sync {
    /// Syscall ID
    fn id(&self) -> SyscallId;

    /// Host 端执行
    fn host_execute(
        &self,
        ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError>;

    /// Gas 开销
    fn gas_cost(&self, state: &VmState) -> u64;
}
```

10 个实现：`ReadInputSyscall` / `CommitOutputSyscall` / `PoseidonSyscall` / `Sha256Syscall` / `EcdsaVerifySyscall` / `EmitEventSyscall` / `LogSyscall` / `PanicSyscall` / `GetRandomnessSyscall` / `ReadStateSyscall`。
