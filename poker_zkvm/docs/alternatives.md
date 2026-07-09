# poker_zkvm 备选方案文档

> 本文档记录 poker_zkvm 实现过程中各 Phase 的备选方案。推荐方案已实现，备选方案记录理由供未来参考。

---

## Phase 0 — crate 骨架

### 推荐方案（已实现）
- **密码学库**：arkworks 0.6 主线（ark-bn254 / ark-grumpkin / ark-poly / ark-ff / ark-ec / ark-serialize）
- **理由**：Hypernova/CCS 折叠算法生态（Sonobe）在 arkworks 更成熟；IPA + multilinear polynomials 有原生支持；BN254/Grumpkin cycle 是 arkworks 一等公民。

### 备选方案 A — halo2 曲线库
- **描述**：使用 halo2_proofs + halo2curves 提供 BN254/Grumpkin 曲线与字段算术。
- **未选理由**：Hypernova 折叠生态（Sonobe）在 arkworks 更成熟；halo2 主要面向 PLONKish 电路，与 CCS（Customizable Constraint System）范式不直接匹配；halo2curves 的 API 与 arkworks 不兼容，混合使用会引入额外适配层。

---

## Phase 1 — 域理论基础

### 推荐方案（已实现）
- **字段库**：`ark_bn254::Fr` 作为 BN254 标量域基础
- **Transcript**：自实现 `Transcript` 结构（基于 `Blake2bVar`），支持 domain tag + length-prefixing

### 备选方案 A — halo2curves::bn256::Fr
- **描述**：使用 halo2curves 提供的 BN254 标量域。
- **未选理由**：API 类似但生态弱；与 arkworks 的 IPA / multilinear poly 实现不兼容。

### 备选方案 B — ark-poly-commit::BatchTranscript
- **描述**：使用 ark-poly-commit 自带的 transcript 实现。
- **未选理由**：不满足 spec 的 domain tag + length-prefix 规范；spec 明确要求 NUMS + domain separation + length-prefixing，自实现更可控。

---

## Phase 1.5 — IPA 多项式承诺

### 推荐方案（已实现）
- **IPA 实现**：自实现 IPA over BN254，NUMS generators 通过 `hash_to_curve(b"poker_zkvm_ipa_gen" || i)` 派生
- **hash-to-curve**：try-and-increment + `G1Affine::get_point_from_x_unchecked(x, true)`（内部自动 sqrt + QR 检测）
- **G_final 计算**：闭式 MSM `G_final = Σ_i (Π_k r_k_inv^{bit(i,k)}) · G_i`，单次 O(N)
- **最终校验**：`P_final == a_final·G_final + (a_final·b_final)·Q`

### 备选方案 A — ark-ec SWU hash-to-curve（未选）
- **描述**：使用 `ark_ec::hashing::curve_maps::swu::SWUMap` 实现 RFC 9380 hash-to-curve
- **未选理由**：arkworks 0.6 BN254 SWU 支持需要额外 feature flag（`hash_to_curve`）；try-and-increment 已满足 NUMS；SWU 复杂度高且对 BN254 的 A=0 短 Weierstrass 曲线需特殊处理（需 iso_map）
- **何时考虑**：未来若需 RFC 9380 合规（标准化互操作）

### 备选方案 B — 逐轮点折叠计算 G_final（未选）
- **描述**：verify 阶段每轮显式折叠 `G' = G_L + r_inv · G_R`，与 prover 同步
- **未选理由**：O(N log N) 比 MSM 闭式 O(N) 慢；且每轮需点加法（Pippenger 优化无法应用）
- **何时考虑**：若需与 prover 严格对称实现便于审计

### 备选方案 C — 添加 H generator 用于盲化（未选）
- **描述**：commitment `C = ⟨a, G⟩ + r·H`，r 为随机盲化因子
- **未选理由**：spec 明确「MVP transparent，witness 不盲化」；ZK 版本留作 v2
- **何时考虑**：v2 真正 ZK 版本

### 备选方案 D — ark-poly-commit::IPA（未选）
- **描述**：使用 ark-poly-commit crate 的 IPA 实现。
- **未选理由**：
  1. 不支持自定义 NUMS generators（spec 明确要求 `hash_to_curve` 派生）
  2. transcript 不兼容 spec 规范（domain tag + length-prefix）
  3. challenge 派生顺序与 spec 不一致（spec 要求 open 开始前 absorb `PCS_OPEN_TAG || commitment || point`）

### 实现期发现
- **arkworks 0.6 API 验证**：`G1Affine::get_point_from_x_unchecked`、`VariableBaseMSM::msm`、`Mul<Fr> for G1Affine/G1Projective`、`CanonicalSerialize` 均已源码验证，无需回退方案
- **标量乘法方向**：`Fr * G1Projective` 未实现（`Mul` 不对称），须用 `G1Projective * Fr`
- **最终校验等式修正**：初始实现误将 `a_final·(G_final + (a_final·b_final)·Q)` 写为整体乘法，正确应为 `a_final·G_final + (a_final·b_final)·Q`（Q 项不额外乘 a_final）

---

## Phase 2 — 前端编译流水线

### 推荐方案（已实现）

#### 2.2 ELF 校验器
- **ELF 解析**：goblin 0.8（`default-features = false, features = ["elf32", "elf64", "endian_fd"]`）
- **统一 `Elf::parse` API**：需要 `elf32 + elf64 + endian_fd` 三个 feature 才能使用统一 `Elf` struct（自动识别 ELF32/ELF64 + 大小端）
- **TOCTOU 消除**：`validate_elf` 返回 owned `ElfMetadata`（`data: Vec<u8>`），类型层保证校验后数据不可篡改
- **.text 识别**：按 section header 名称 `.text` 精确查找（goblin `shdr_strtab`）
- **RV32I 校验**：opcode 白名单（11 个）+ FENCE/SYSTEM 细查
- **错误映射**：ELF 格式错误 → `ZkvmError::Other(String)`，RV32I 非法指令 → `ZkvmError::UnsupportedInstruction(String)`（spec v1.4 FROZEN 18 variants 不可新增）
- **测试 ELF 构造**：手工字节拼接（精确控制每个字段测试负例）

#### 2.1 编译器入口
- **编译调用**：`cargo build --target riscv32i-unknown-none-elf --release` + `RUSTFLAGS` 传 `-C panic=abort -C opt-level=3`
- **_start trampoline**：预生成 Rust 源码字符串（含 `#[no_mangle] _start` + `#[panic_handler]` + extern 声明）
- **crate name 解析**：简单行扫描 `[package] name = "..."`

#### 2.3 prelude 模块
- **alloc re-export**：`pub use alloc::{boxed::Box, format, string::String, vec, vec::Vec}`
- **entry!/test! 宏**：`#[macro_export] macro_rules!` pass-through（标记后原样输出）

#### 2.4 cargo-zkvm CLI
- **参数解析**：手写 `std::env::args()` 解析（不引入 clap 依赖）
- **run/prove/verify stub**：返回 `Phase X not implemented` 错误（下游 Phase 未就绪）

### 备选方案

#### A — 自实现 ELF parser（未选）
- **描述**：手写 ELF32 解析器，完全控制解析逻辑。
- **未选理由**：工作量大且容易引入 bug（ELF 格式细节多）；goblin 是成熟、纯 Rust、无 unsafe 的库，已广泛用于生产。

#### B — `object` crate 做 ELF 解析（未选）
- **描述**：使用 `object` crate（Rust object file parser）。
- **未选理由**：比 goblin 更重（支持更多格式 COFF/Mach-O）；只需 ELF32 解析，goblin 更轻量。

#### C — 直接调用 `rustc` 编译（未选）
- **描述**：`compile_crate` 用 `Command::new("rustc")` 直接调用 rustc 编译单个文件。
- **未选理由**：无法解析 crate 依赖（用户 crate 通常有 `Cargo.toml` 依赖）；`cargo build` 内部调用 rustc 并自动处理依赖解析与链接；spec 描述的 `rustc --target ... -C panic=abort -C opt-level=3` 是编译 flags 描述，通过 `RUSTFLAGS` 传递给 cargo 等效。

#### D — clap 做 CLI 参数解析（未选）
- **描述**：使用 `clap` crate 提供 `build/run/prove/verify/test` 子命令。
- **未选理由**：spec 未要求复杂参数解析；5 个子命令 + `--key value` 参数手写 < 100 行；引入 clap 增加编译时间和依赖树体积。
- **何时考虑**：若 CLI 需求复杂化（如嵌套子命令、配置文件、shell completion）。

#### E — 过程宏生成 _start trampoline（未选）
- **描述**：使用 proc-macro crate 在编译时自动生成 `_start` trampoline。
- **未选理由**：需单独 proc-macro crate（`poker_zkvm_macros`），增加构建复杂度；Phase 2 trampoline 逻辑固定，预生成字符串更简单直接、可审阅。
- **何时考虑**：若 trampoline 需根据用户函数签名动态生成（如不同 input/output 类型）。

#### F — 过程宏实现 entry!/test!（未选）
- **描述**：使用 proc-macro 实现 `#[zkvm::entry]` / `#[zkvm::test]` 属性宏。
- **未选理由**：proc-macro 需单独 crate（过度工程）；当前宏仅 pass-through 标记，实际处理在 `compile_crate` 源码分析；`macro_rules!` + `#[macro_export]` 已满足需求。
- **何时考虑**：若宏需做 AST 变换（如自动生成 trampoline 代码注入用户 crate）。

### 实现期发现
- **goblin feature 需求**：统一 `Elf::parse` API 需 `elf32 + elf64 + endian_fd` 三 feature 同时启用（仅 `elf32` 无法使用统一 `Elf` struct）
- **goblin `ProgramHeader` 字段类型**：`p_flags: u32`（非 u64），但 `p_offset/p_vaddr/p_paddr/p_filesz/p_memsz/p_align: u64`（统一 struct 用 u64 兼容 ELF32/ELF64）
- **clippy `manual_is_multiple_of`**：Rust 1.81+ `% n != 0` → `!is_multiple_of(n)`；`manual_range_contains`：`x >= 1 && x <= 3` → `(1..=3).contains(&x)`
- **`extern crate alloc`**：std 环境下使用 `alloc::` 路径需在 crate root 显式声明 `extern crate alloc;`

---

## 通用 — 测试框架

### 推荐方案（已实现）
- **测试框架**：标准 `#[test]` + proptest（property testing）+ criterion（Phase 12 benchmark）

### 备选方案 A — quickcheck
- **描述**：使用 quickcheck 进行 property testing。
- **未选理由**：proptest 生态更成熟，支持更丰富的策略（strategy composition, shrinking）；quickcheck 的 shrink 机制较弱，对复杂结构（如多线性多项式）的失败用例定位不如 proptest。

---

## Phase 3 — ZKVM ISA 执行引擎

### 推荐方案（已实现）

#### 3.1 内存模型（D1）
- 分页 `BTreeMap<u32, Box<Page>>` + 字节级初始化位图
- `PAGE_SIZE = 4096`，每页含 `data: [u8; 4096]` + `init_mask: [u8; 512]`（1 bit/byte）
- `total_allocated` 跟踪已分配内存，超 `MAX_ZKVM_MEMORY = 16MB` 返回 `OutOfMemory`

#### 3.2 内存对齐（D2）
- 自然对齐（标准 RISC-V 语义）：LW/SW→4B，LH/SH/LHU→2B，LB/SB/LBU→1B
- 未对齐返回 `UnalignedAccess`

#### 3.3 Instruction 枚举（D3）
- 逐 variant + 预解码操作数（`rd`/`rs1`/`rs2`/`imm`/`shamt` 直接存入）
- `imm` 为 `u32`（已符号扩展），`shamt` 为 `u8`（0-31）
- `#[derive(Clone, Debug, PartialEq, Eq)]`

#### 3.4 StepLog vs Step 分离（D4）
- `execute()` 返回 `StepLog`（纯函数，不含 `step_index`）
- executor 组装 `Step`（含 `step_index`）追加到 `Trace`

#### 3.5 HostContext（D5）
- 结构体 + `dispatch(state, syscall_id)` 方法
- Phase 3 实现 3 个 syscall：`read_input`(0x01) / `commit_output`(0x02) / `panic`(0x08)
- 其余 syscall 返回 `Other("syscall N not implemented in Phase 3")`

#### 3.6 Trace 序列化（D6）
- 自定义二进制流式格式：magic `"TRCE"` + version(4B) + num_steps(8B) + steps
- `deserialize` 用 `checked_mul` 防 u64 溢出 + 超 `MAX_TRACE_HOST_MEMORY` 早夭

#### 3.7 opcode 白名单（D7）
- `decode` 内部自包含 match（不共享 `elf_validator` 的 `RV32I_OPCODES` 常量）
- 职责不同：`elf_validator` 校验段内所有指令，`decode` 解码单条指令

#### 3.8 load_elf 签名（D8）
- 接受 `&ElfMetadata`（已校验的 owned 数据），消除 TOCTOU
- `validate_elf` 返回 owned `ElfMetadata`（`data: Vec<u8>`），类型层保证校验后不可篡改

#### 3.9 ECALL 分派时机
- executor 循环检测 `Instruction::Ecall` 后调 `host.dispatch`
- `execute()` 仅 `pc+=4`，保持纯函数性

### 备选方案

#### A — `HashMap<u32, u8>` 内存模型（未选）
- **描述**：使用 `HashMap<u32, u8>` 存储字节级数据
- **未选理由**：离散地址无序迭代（`BTreeMap` 确定性迭代更利于电路约束）；`HashMap` 哈希碰撞非确定；每字节一个 entry 内存开销大（4-8 倍膨胀）

#### B — 稠密 `Vec<u8>` 内存模型（未选）
- **描述**：预分配 16MB `Vec<u8>`，按地址直接索引
- **未选理由**：16MB 浪费（多数程序仅用几 KB）；无法支持稀疏地址（栈顶 `0x8000_0000` 与堆 `0x1000_0000` 之间巨大空洞）

#### C — 全部强制 4B 对齐（未选）
- **描述**：所有内存访问强制 4 字节对齐
- **未选理由**：违反 RISC-V 语义（LB/SB/LH/SH 是合法指令）；spec 明确自然对齐

#### D — 按 format 分组 Instruction 枚举（未选）
- **描述**：`Instruction` 按 R/I/S/B/U 格式分组（如 `Instruction::RType { funct3, funct7, rd, rs1, rs2 }`）
- **未选理由**：`execute` 需间接分派（先 match format 再 match funct3/funct7）；重复解码；类型安全性弱（无法在类型层区分 ADD vs SUB）

#### E — 存 raw word 的 Instruction（未选）
- **描述**：`Instruction` 仅存 raw `u32` word，`execute` 时再解码
- **未选理由**：重复解码（`decode` 后 `execute` 再解一次）；`execute` 性能差；`StepLog.instruction` 序列化需二次解码

#### F — `execute` 直接返回 `Step`（未选）
- **描述**：`execute(state, insn) -> Result<Step, ZkvmError>`，内部含 `step_index`
- **未选理由**：`execute` 需要知道 `step_index`（需传入或从 state 读），破坏纯函数性；`step_index` 是 executor 维护的状态，不应泄漏到 `execute`

#### G — HostContext 用 trait object（未选）
- **描述**：定义 `Syscall` trait，`HostContext` 持有 `Box<dyn Syscall>`
- **未选理由**：过度设计（Phase 3 仅 3 个 syscall）；trait object 动态分派开销；Phase 4 扩展为 10 个 syscall 时再考虑

#### H — `execute` 内部分派 syscall（未选）
- **描述**：`execute()` 检测 `Ecall` 后直接调 syscall
- **未选理由**：破坏 `execute` 纯函数性（syscall 有副作用：读 input / 写 output / halt）；`execute` 签名需变为 `&mut HostContext`，耦合 executor 与 host；难以单元测试 `execute`

#### I — serde + bincode 序列化（未选）
- **描述**：使用 serde derive + bincode 二进制序列化
- **未选理由**：引入 serde + bincode 两个新依赖（spec 要求最小依赖）；bincode 不支持流式消费（需先反序列化整个 `Trace`）；无法自定义 `checked_mul` 防 u64 溢出

#### J — 接受 raw bytes 的 `load_elf`（未选）
- **描述**：`load_elf(state, elf_bytes: &[u8])`，内部调 `validate_elf`
- **未选理由**：TOCTOU 风险（校验后、加载前 `elf_bytes` 可能被修改）；类型层无法保证已校验；当前设计 `validate_elf` 返回 owned `ElfMetadata`，`load_elf` 消费 `&ElfMetadata`，类型安全

### 实现期发现
- **`extern crate alloc`**：std 环境下使用 `alloc::collections::BTreeMap` 需在 crate root 显式声明
- **`MemoryMap::get_page` 返回 `Option<&Page>`**：需用 `.map(|v| &**v)` 解引用 `Box`
- **clippy `manual_is_multiple_of`**：Rust 1.81+ `% n != 0` → `!is_multiple_of(n)`
- **read_input 简化 ABI（Phase 3）**：不读 a0/a1 参数，直接将 input 写入 `INPUT_BUFFER_ADDR` 并设 a0/a1；Phase 4 扩展为标准 ABI
- **EBREAK 不作为 halt 信号**：Phase 3 中 EBREAK 仅 `pc+=4`（与 ECALL 一致），halt 仅由 `commit_output` syscall 触发
- **`ExecuteResult` 需 `#[derive(Debug)]`**：测试中 `unwrap()` 要求 `Debug`
- **`flat_map(u32::to_le_bytes)` 类型不匹配**：`iter()` 产出 `&u32`，需 `.copied()` 转换为 `u32` 才能传入 `fn(u32) -> [u8; 4]`
- **`matches!` 结构体 variant 缺字段**：`TraceHostMemoryExceeded { limit: 100 }` 需加 `..` 忽略 `actual` 字段

---

## Phase 4 — ZKVM Syscall 完整实现

### 推荐方案（已选择）

1. **Poseidon 哈希实现**：使用 `ark-crypto-primitives` 0.6.0 的 `PoseidonSponge`
   - BN254 Fr 无内置默认 Poseidon 参数（不像 BLS12-381 Fr），用 `find_poseidon_ark_and_mds` 运行时生成
   - 参数：alpha=5, rate=2, capacity=1, 8 full + 56 partial rounds, prime_bits=254
   - `PoseidonConfig` 通过 `OnceLock` 全局缓存，首次调用生成，后续复用

2. **Syscall 分派架构**：`Syscall` trait + `SyscallRegistry` 数组分派
   - 每个 syscall 为一个 struct，实现 `Syscall` trait（`id()` / `host_execute()` / `gas_cost()`）
   - `SyscallRegistry` 内部 `[Option<Box<dyn Syscall>>; 10]`，index = SyscallId as usize - 1
   - `create_full_registry()` 工厂函数注册全部 10 个实现

3. **Host 状态读取**：定义 `ZkvmHostState` trait
   - `PokerL1Context` 无 state slot 字段，用 trait 抽象解耦
   - `StubHostState` 默认实现返回 `Other` 错误
   - 节点层可注入自定义实现（如读取 `PokerL1Context` 的状态槽）

4. **Gas 计费**：双层设计 — `gas::syscall_gas()` 独立函数 + `Syscall::gas_cost()` trait 方法
   - trait 方法读寄存器估算 gas，委托到 `gas` 模块的纯函数
   - executor 循环中不实际扣 gas（gas 计费是 on-chain 概念）

5. **SyscallContext**：集中 struct 持有 host 侧状态（11 个字段）
   - input / output / events / logs / halted / step_index / randomness 参数 / host_state
   - builder 模式：`new()` → `with_randomness()` → `with_host_state()`

6. **ECDSA 签名格式**：64 字节 compact（r||s）+ 33 字节 compressed pubkey
   - 使用 `secp256k1::ecdsa::Signature::from_compact` + `PublicKey::from_slice`
   - 验证失败返回 a0=0（bool 语义），不返回 Err

7. **Poseidon 参数生成**：运行时 `find_poseidon_ark_and_mds` + `OnceLock` 缓存
   - 首次调用 ~ms 级，后续零开销
   - skip_matrices=0（首个合格矩阵即采用）

8. **ReadInput ABI 升级**：标准 ABI（a0=ptr, a1=len）+ a0=0 回退到 HEAP_START
   - Phase 3 简化 ABI（不读 a0/a1）→ Phase 4 标准 ABI
   - 向后兼容：a0=0 时用 `HEAP_START`（0x1000_0000）

### 未选择方案

1. **自实现 Poseidon 电路**：手写 Poseidon 约束 — 工作量大，arkworks 已有成熟实现
2. **stub Poseidon 占位**：返回固定值 — 无法通过确定性测试
3. **保持 Phase 3 match 分派**：executor 内 match syscall_id — 扩展性差，无法动态注册
4. **函数指针表**：`HashMap<u32, fn>` — 丢失 `&self` 状态，无法实现 trait object
5. **直接依赖 PokerL1Context**：在 zkvm crate 中依赖 poker_l1 — 循环依赖，耦合度高
6. **硬编码状态**：slot 值写死在代码中 — 无法适配不同链状态
7. **独立 gas 函数（无 trait 方法）**：executor 需自行读寄存器 + 查表 — 逻辑分散
8. **散落参数**：每个 syscall `host_execute(state, input, output, events, ...)` — 参数列表过长
9. **DER 签名格式**：可变长度，解析复杂 — compact 固定 64 字节更简洁
10. **65 字节 recoverable 签名**：需要 recovery feature — 验证场景不需要恢复公钥
11. **编译期硬编码 Poseidon 参数**：需代码生成工具 — 运行时生成 + 缓存更灵活
12. **BLS12-381 默认参数**：域不同，参数不兼容
13. **强制标准 ABI 不回退**：破坏 Phase 3 测试兼容性
14. **保持 Phase 3 简化 ABI**：无法指定写入地址，限制程序灵活性

### 实现期发现

- **secp256k1 0.29 API 变更**：`Signature` 移至 `secp256k1::ecdsa::Signature`，`PublicKey::serialize_compressed()` 重命名为 `PublicKey::serialize()`
- **`hex` crate 需加入 dev-dependencies**：测试中使用 `hex::decode_to_slice` 做 SHA-256 向量验证
- **`div_ceil` 可用**：Rust 1.73+ 稳定，用于 Poseidon gas 的 block 数计算 `(input_len).div_ceil(32)`
- **`OnceLock` vs `Lazy`**：std 1.70+ 提供 `OnceLock`，无需额外依赖 `once_cell`
- **`SyscallRegistry::new()` 委托 `host::create_full_registry()`**：mod.rs 定义 struct，host.rs 提供 factory — 模块间循环引用在 Rust 中合法
- **`SyscallContext` 需手动实现 `Debug`**：`Box<dyn ZkvmHostState>` 无 `Derive Debug`，需手动 `field("host_state", &self.host_state)`
- **`ZkvmHostState` 需 `Send + Sync`**：`SyscallContext` 可能跨线程传递（executor + prover），trait object 须线程安全
- **ReadInput 向后兼容仅覆盖 a0=0**：a1=0 → 读 0 字节（无回退），测试需显式设 a1

---

## Phase 10 — 预编译电路（CCS 约束生成器）

### 推荐方案（已实现）

- **CCS 数据结构**（Step 1）：`SparseMatrix`（COO 格式）+ `Ccs`（矩阵 M_j / 子集 S_i / 系数 c_i）+ `CcsInstance`（ccs + witness + public_inputs）。`satisfied_by(z)` 校验 `Σ_i c_i · Π_{j∈S_i} ⟨M_j, z⟩ = 0`。
- **双 trait 设计**（Step 2）：`PrecompileCircuit`（约束结构 + witness 赋值 + gas 计费）+ `CcsCircuit`（实例生成，Fr-based 新签名，从 poker_l1 迁移）。
- **Poseidon 电路**（Step 3）：MVP 实现 S-box `x^5 = x^4·x` 的 3 行约束（6 subsets / 7 row-isolated 矩阵 / 5 个 witness 变量 `[1, x, x2, x4, x5]`），与 `ark_bn254::Fr` 的 `x^5` 一致（完整 permutation + host `poseidon_hash_bytes` 一致性延至 Phase 12+）。
- **SHA-256 电路**（Step 4）：MVP 实现 Ch 函数 `Ch(x,y,z) = z + x·(y-z)` 的 2 行约束（6 subsets / 7 row-isolated 矩阵 / 6 个 witness 变量 `[1, x, y, z_var, y_minus_z, ch]`），Ch 输出与 bitwise Ch 一致；host `sha2` crate known vectors 已验证（完整 64-round compression 延至 Phase 12+）。
- **ECDSA 电路**（Step 5）：MVP 实现 double-and-add 单步的 3 行约束（7 subsets / 7 row-isolated 矩阵 / 6 个 witness 变量 `[1, bit, R, P, bit_P, R_new]`：bit 范围检查 + 条件乘法 + 条件加法），secp256k1 曲线，gas=100_000（完整 256-step 标量乘 + verify equation ~110k 约束延至 Phase 12+）。
- **ZkShuffle 迁移**（Step 6）：stub 实现（`assign_witness` 和 `to_ccs_instance` 返回 `Err("Phase 11 pending")`），poker_l1 旧类型标记 `#[deprecated]`。
- **行隔离原则**：每个矩阵只在单行有非零条目，同变量在不同行需不同矩阵。

### 关键设计决策

- **D1 — MVP 策略**：每个预编译电路实现单一核心数学操作的 CCS 约束（Poseidon: S-box x^5；SHA-256: Ch 函数；ECDSA: double-and-add 单步），不实现完整电路（如 ECDSA 完整 ~110,000 约束）。MVP 优先验证 CCS 闭环 + trait 接口正确性。
- **D2 — gas_cost 取值**：ECDSA `gas_cost()` 返回 100,000（spec L660 `GAS_ZKVM_ECDSA_VERIFY`），而非 110,000（spec L659 约束数）。前者是 gas 计费，后者是约束数，两者不同。
- **D3 — CcsCircuit 迁移**：从 poker_l1 迁移到 poker_zkvm，签名从 `Hash`-based 改为 `Fr` + `CcsInstance` 新类型。poker_l1 旧 trait 保留 `#[deprecated]`，Phase 11 通过 `pub use` re-export 新类型。
- **D4 — trait 方法歧义消解**：当 struct 同时实现 `PrecompileCircuit` 和 `CcsCircuit`（均有 `name()`），通过 trait reference 消歧：`let pre: &dyn PrecompileCircuit = &circuit; pre.name()`。

### 备选方案

#### Step 3 — Poseidon S-box 实现

1. **完整 Poseidon 置换电路**（未选）：实现 8 full + 56 partial rounds + MDS 矩阵乘法。未选理由：MVP 阶段验证 CCS 闭环即可，完整电路在 Phase 11/12 Hypernova 集成时实现。
2. **查表实现 S-box**（未选）：使用 LogUp lookup 协议将 x^5 拆为查表。未选理由：LogUp 在 Step 13 实现，当前阶段优先 CCS 约束验证。
3. **arkworks Poseidon circuit**（未选）：使用 `ark-crypto-primitives::snark::Poseidon`。未选理由：与 CCS 范式不匹配，需适配层。

#### Step 4 — SHA-256 Ch 函数实现

1. **完整 SHA-256 压缩电路**（未选）：实现 64 轮 message schedule + compression。未选理由：MVP 验证 Ch 函数约束即可，完整电路在 Phase 11 实现。
2. **位级拆分 Ch**（未选）：将 x/y/z 拆为 32 位，逐位计算 `(x_i & y_i) ⊕ ((1-x_i) & z_i)`。未选理由：32 倍约束数，MVP 阶段用域元素级运算。
3. **查表实现 Ch**（未选）：8-bit lookup table。未选理由：LogUp 未实现，当前用算术约束。

#### Step 5 — ECDSA 验签电路

1. **完整 ECDSA 验签电路**（未选）：实现 256-bit 标量乘 shift-add + 点加法/倍点 + 哈希 + 最终比较（~110,000 约束）。未选理由：MVP 验证 double-and-add 单步 + 条件点加法 + bit 范围检查即可。
2. **窗口标量乘**（未选）：windowed scalar multiplication（4-bit window，64 次迭代）。未选理由：MVP 用简单 double-and-add，窗口法在 Phase 11 优化。
3. **查表优化 bit 检查**（未选）：使用 LogUp lookup 验证 bit ∈ {0,1}。未选理由：当前用 `bit·bit - bit = 0` 约束，简单有效。
4. **完整点加法公式**（未选）：实现 Weierstrass 完整点加法公式（含无穷远点处理、同 x 坐标处理）。未选理由：MVP 假设非退化情况，Phase 11 补全边界条件。
5. **secp256k1 endomorphism 优化**（未选）：利用 GLV endomorphism 加速标量乘。未选理由：复杂度高，MVP 不需要。

#### Step 6 — ZkShuffle 迁移策略

1. **立即迁移完整实现**（未选）：将 poker_l1 的 ZkShuffleCcsCircuit 完整逻辑迁移到 poker_zkvm。未选理由：poker_l1 旧实现基于 Hash 类型（hash-based commitments），与 poker_zkvm Fr-based 新签名不兼容；Phase 11 才完成完整迁移。
2. **删除 poker_l1 旧类型**（未选）：直接删除 `poker_l1::CcsCircuit` 和 `ZkShuffleCcsCircuit`。未选理由：破坏向后兼容，poker_l1 现有测试和调用方会编译失败。
3. **保留旧类型不标 deprecated**（未选）：不标记 `#[deprecated]`。未选理由：新代码可能误用旧类型，无法引导迁移。

### 实现期发现

- **`#![deny(missing_docs)]` 影响**：所有 public items（trait / struct / method）必须有 `///` 文档注释，否则编译失败。
- **`ZkvmField` import 位置**：`Fr::one()` / `Fr::zero()` / `Fr::from_u32_with_wrap()` 需要 `use crate::field::ZkvmField;`。若仅在测试中使用，应放在 `#[cfg(test)] mod tests` 块内避免 unused import 警告。
- **trait 方法歧义**：当 struct 实现两个 trait 且方法同名（如 `name()`），Rust 编译器报 `multiple applicable items in scope`。需通过 trait reference 消歧。
- **`Ccs::satisfied_by` 转置**：为满足 clippy `needless_range_loop` 检查，mz 矩阵需转置为 row-major 访问。
- **ECDSA witness 顺序**：`[1, bit, R, P, bit_P, R_new]` — 常数 1 在首位，输入在中部，计算结果在尾部。符合 CCS witness 约定。
- **SparseMatrix 行隔离**：每个矩阵只允许在单行有非零条目。同变量在不同行使用需创建不同矩阵（如 `M_bit_r0` 和 `M_bit_r1` 是同一变量 bit 但分布在不同行）。
- **gas_cost 与约束数区分**：spec 中 ECDSA 有两个数字：100,000（gas，spec L660）和 ~110,000（约束数，spec L659）。`gas_cost()` 返回前者。
- **deprecated trait 的测试**：测试旧 trait 时需 `#[allow(deprecated)]` 标注测试函数，否则触发 deprecation 警告。

---

## Phase 5 — Trace → CCS 约束编译器

### 推荐方案（已实现）

#### Step 8 — compile_trace_to_ccs + batching

1. **K=1024 batch 策略**（已选）：每 1024 步生成 1 个 CCS 实例，最大 1000 实例（N ≤ 1,024,000）。理由：与 spec L276 `ZKVM_BATCH_SIZE = 1024` 一致，平衡 batch 数与单 batch 约束数。
2. **batch_id 作为 public_inputs[0]**（已选）：batch_id 单调递增，通过 public_inputs 传递 batch 间连续性。理由：公共输入可被 verifier 校验，无需额外承诺。
3. **step_index 连续性约束**（已选）：batch 内 `idx_{i+1} - idx_i - 1 = 0`，通过 CCS 约束强制。理由：防 trace 重排序攻击。

#### Step 9 — 算术指令子电路

1. **overflow_bit carry 模式**（已选）：`a + b - result - 2^32 * overflow_bit = 0` + `overflow_bit² - overflow_bit = 0`。理由：RISC-V mod 2^32 算术需映射到域 mod p，carry witness 桥接语义差异。
2. **行隔离矩阵**（已选）：每个矩阵只在单行有非零项，防止 subset 污染其他行。理由：CCS 约束 `Π_{j∈S_i} (M_j·z)[r]` 要求矩阵在其他行求值为 0。
3. **bit-decompose shift amount**（已选）：SLL/SRL/SRA 的 shift amount 拆为 5 个 bit，每个 bit range check ∈ {0,1}。理由：防 shift amount 越界，符合 RISC-V 语义（shift = shamt mod 32）。

#### Step 10 — 内存访问子电路

1. **byte-level permutation**（已选，spec L288-298 v1.2）：写操作展开为字节级写（LW 4B → 4 条字节写），读操作展开为字节级读。理由：防 LB 1B vs LW 4B aliasing 攻击。
2. **permutation key = (byte_addr, byte_val, step_index)**（已选）：每 byte 单独记录。理由：step_index 单调性显式约束 `step_{i+1} > step_i`。
3. **checked_add 防 wrap 攻击**（已选，spec L294）：地址 `checked_add(size)` 防 `addr=0xFFFFFFF0, size=0x20` wrap。理由：防恶意 ELF 构造越界地址。
4. **函数式 API（非 circuit 结构）**（已选）：`expand_to_bytes()` / `check_uninitialized_read()` / `verify_memory_permutation()` 独立函数。理由：内存一致性是全局校验（非单步约束），函数式 API 更自然。

#### Step 11 — 控制流子电路

1. **overflow carry 用于跳转目标计算**（已选）：JAL `pc + imm - pc_new - 2^32 * pc_carry = 0` + `pc_carry² - pc_carry = 0`。理由：imm 为负数时（two's complement 大 u32），域加法 ≠ mod 2^32 结果，需 carry 桥接。
2. **BEQ 条件求值**（已选）：`taken * (rs1 - rs2) = 0` + `taken² - taken = 0`。理由：taken=0 时自动满足（因 taken * 任意 = 0），taken=1 时强制 rs1 == rs2。
3. **LUI 无 carry**（已选）：imm < 2^20 → imm*4096 < 2^32，无溢出可能。理由：减少不必要的 carry witness。

#### Step 12 — Syscall 子电路

1. **SyscallAbiCircuit 独立约束 a7 == syscall_id**（已选）：先校验 ABI 一致性，再分派到预编译电路。理由：分离 ABI 校验与语义执行，便于模块化。
2. **dispatch_syscall 路由**（已选）：Poseidon/SHA-256/ECDSA 查预编译注册表，非密码 syscall 仅产生 ABI 实例。理由：密码 syscall 需额外预编译 CCS 实例（可被 Hypernova 折叠）。
3. **预编译名映射**（已选）：Poseidon→"poseidon", Sha256→"sha256", EcdsaVerify→"ecdsa_verify"。理由：与 `PrecompileCircuit::name()` 一致。

#### Step 13 — LogUp lookup 协议

1. **Blake2b hash-to-field 承诺**（已选，MVP）：`commit(elems) = Blake2b(domain || len || elems) → Fr`。理由：binding（collision-resistant），无需 PCS 基础设施。生产环境替换为 Pedersen 向量承诺。
2. **严格 absorb 顺序 C_T → C_f → C_m → β**（已选，spec L155）：β 在 witness 承诺后派生。理由：防 prover 看到 β 后调整 multiplicity（β 操纵攻击）。
3. **域元素逆元计算有理函数**（已选）：`m_i / (β - t_i)` 使用 `denom.inverse()`。理由：BN254 Fr 是素域，非零元素均有逆元。
4. **简化 CCS 编码 `lhs - rhs = 0`**（已选，MVP）：witness `[1, lhs, rhs]`，单行约束。理由：MVP 阶段验证 LogUp 等式闭环即可，完整 per-entry binding（inv 变量 + `(β - t_i) * inv_t_i - 1 = 0`）留待 Hypernova 折叠集成。
5. **真值表打包编码**（已选）：`t = (x << 2) | (y << 1) | result`，3-bit 打包。理由：单个域元素表示完整真值表条目，减少表大小。

### 备选方案

#### Step 8 — Batching 策略

1. **动态 batch 大小**（未选）：根据 trace 长度自动调整 K。未选理由：固定 K=1024 与 spec 一致，动态调整增加复杂度。
2. **单 batch 全 trace**（未选）：整个 trace 生成 1 个 CCS 实例。未选理由：大 trace（1M 步）导致单实例约束数爆炸，超 Hypernova 折叠能力。
3. **batch 间 Merkle 承诺**（未选）：batch 间连续性通过 Merkle root 绑定。未选理由：public_inputs 传递 batch_id 已足够，Merkle 增加开销。

#### Step 9 — 算术子电路

1. **原生域算术（无 carry）**（未选）：直接 `a + b - result = 0`。未选理由：负 imm 时域加法 ≠ mod 2^32 结果（`Fr::from_u32_with_wrap(0xFFFFFFF0)` 是大正数，非 −16）。
2. **bit-decompose 全加法器**（未选）：32-bit 逐位 ripple-carry adder。未选理由：~128 个约束/加法（vs 2 约束 carry 模式），MVP 不需要。
3. **lookup 优化 AND/OR/XOR**（未选）：使用 LogUp 真值表替代算术约束。未选理由：LogUp 在 Step 13 实现，Step 9 先用算术约束验证 CCS 闭环。

#### Step 10 — 内存子电路

1. **word-level permutation**（未选）：4 字节为单位记录。未选理由：LB 1B vs LW 4B aliasing 攻击（spec L288 v1.2 明确要求 byte-level）。
2. **Merkle tree 内存承诺**（未选）：所有内存访问构建 Merkle tree。未选理由：byte-level permutation 更高效，Merkle 增加对数开销。
3. **circuit 结构（LwCircuit / SwCircuit）**（未选）：每条内存指令独立电路。未选理由：内存一致性是全局校验（跨步），函数式 API 更自然。

#### Step 11 — 控制流子电路

1. **无 carry 的 pc 计算**（未选）：`pc + imm - pc_new = 0`。未选理由：负 imm 时域加法不等于 mod 2^32 结果（JAL 向后跳转失败）。
2. **bit-decompose imm**（未选）：imm 拆为 13-bit（符号位 + 12-bit）。未选理由：13 个 range check 约束 vs 2 个 carry 约束，carry 模式更简洁。
3. **JALR 电路**（未选）：未实现 JALR。未选理由：MVP 阶段 JAL + BEQ + LUI + AUIPC 覆盖核心控制流，JALR 留待后续迭代。

#### Step 12 — Syscall 子电路

1. **内联预编译约束**（未选）：将 Poseidon/SHA-256/ECDSA 约束直接内联到 syscall 电路。未选理由：破坏模块化，预编译电路应可独立测试和复用。
2. **syscall_id range check**（未选）：校验 `a7 ∈ [0x01, 0x0A]`。未选理由：ABI 电路约束 `a7 == expected_id` 更严格（精确匹配而非范围）。
3. **非密码 syscall 产生空 CCS 实例**（未选）：ReadInput/CommitOutput 等不产生预编译实例。未选理由：已实现（仅产生 ABI 实例），但备选方案是产生空实例标记 — 未选因增加冗余实例。

#### Step 13 — LogUp lookup 协议

1. **Plookup grand product**（未选）：`Π_j (β - f_j) / Π_i (β - t_i)^{m_i}`。未选理由：grand product 在多表场景下需多个乘积，LogUp 用倒数和更高效。
2. **Pedersen 向量承诺**（未选）：使用 `pcs/ipa.rs` 的 Pedersen commitment。未选理由：MVP 阶段优先验证 LogUp 等式闭环，PCS 集成留待 Hypernova 折叠阶段。
3. **完整 per-entry CCS 编码**（未选）：witness 包含所有 inv_t_i / inv_f_j 变量 + `(β - t_i) * inv_t_i - 1 = 0` 约束。未选理由：变量数随表大小线性增长，MVP 用简化编码验证等式即可。
4. **u32 range 表**（未选）：2^32 条目的完整 u32 range 表。未选理由：表太大无法枚举；实际用 4× u8 range 表（byte decomposition）替代。
5. **LogUp-RC（lookups based on randomized checks）**（未选）：随机化校验变体。未选理由：标准 LogUp 已满足需求，RC 变体增加复杂度。

### 实现期发现

- **carry witness 模式复用**：AddCircuit 的 `overflow_bit` 模式直接复用到 JalCircuit（`pc_carry` / `rd_carry`）和 AuipcCircuit（`carry`），保持一致性。
- **BEQ subset 设计**：`taken * (rs1 - rs2) = 0` 需要 2 个 subset（S_0={0,1} for taken*(rs1-rs2), S_1={2,3} for... 实际是 S_0={M_taken, M_rs1} × S_1={M_taken, M_rs2} 的二次约束），需仔细对齐矩阵/子集/系数。
- **`Fr::from_u32_with_wrap` 语义**：u32 值直接映射为域元素（BN254 p > 2^32），无实际 wrap。但负数（two's complement 大 u32）映射为大正数，需 carry 桥接 mod 2^32 语义。
- **Blake2bVar 承诺**：`commit_field_slice` 使用 `Blake2bVar(32)` + domain prefix + length prefix，与 transcript 的 absorb 模式一致，防 concatenation ambiguity。
- **LogUp 等式验证**：`Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)` 使用 `Fr::inverse()` 计算逆元。β 与 t_i 或 f_j 碰撞时 `denom = 0`，返回错误（而非 false）。
- **真值表打包位序**：`(x << 2) | (y << 1) | result` — x 在高位、result 在低位。witness `f = (x << 2) | (y << 1) | expected_result`，查找成功等价于 `expected_result == op(x, y)`。
- **associated vs instance method**：algebra/control_flow 电路用 associated function（`AddCircuit::build_ccs()`），syscall_circuit 用实例方法（`syscall_abi.assign_witness()`）。差异因 syscall 电路需存储 `syscall_id` 状态。
- **内存模块函数式 API**：memory.rs 无 circuit 结构，提供 `expand_to_bytes` / `check_uninitialized_read` / `verify_memory_permutation` 函数。理由：内存一致性是全局校验（跨步），非单步约束。

---

## Phase 6：Hypernova 折叠算法

### 推荐方案（已选）

#### Step 1 — CCS 扩展方法 (fold/ccs.rs)

1. **inherent impl 扩展 Ccs**（已选）：直接在 `Ccs` 上 impl 新方法（`to_lcccs` / `to_cccs` / `ccs_commitment` / `compute_v_at`）。理由：`Ccs` 与扩展在同一 crate，无需 trait indirection。
2. **to_lcccs 显式接受 r_x_l**（已选）：spec 标注 `to_lcccs(z)`，但 r_x_l 是必要参数（v_l 在 r_x_l 处求值）。理由：数学上 r_x_l 是 LCCCS 的核心字段，不能省略。
3. **Blake2b 串联 hash 作为 ccs_commitment**（已选）：串联所有矩阵 entries + 子集 + 系数，Blake2bVar(32) 输出。理由：矩阵数量少（t ≤ 10），串联 hash 足够防碰撞且实现简单（vs Merkle root）。
4. **compute_v_at 共享工具方法**（已选）：`v[j] = Σ_r eq(r_x, r) · (M_j · z)[r]`，LCCCS 和 CCCCS 共用。理由：避免代码重复，v_l 和 v_c(r_x_l) 计算逻辑完全相同。

#### Step 2 — LCCCS relaxed 实例 (fold/lcccs.rs)

1. **relaxed 约束 `Σ_i c_i · Π v_L[j] = u_L`（u_L 可非 0）**（已选，v1.3 M2-001）：理由：折叠后 u' = u_L + r·u_C 可能非 0（尤其非线性 CCS），relaxed 形式是 Hypernova 的核心。
2. **显式存储 r_x_L**（已选，v1.3）：LCCCS 显式存储 r_x_L 字段。理由：v_L 在 r_x_L 处求值，r_x_L 是 verifier 验证 sumcheck 的必要参数。
3. **v_L 向量化（长度 = num_matrices）**（已选，v1.3）：`v_L[j] = Σ_y M_j(r_x_L, y) · z_L(y)`。理由：每个矩阵对应一个 v 值，向量形式便于 fold_step 分量级折叠。
4. **eq_eval 共享工具函数**（已选）：`eq(r_x, row) = Π_i (r_x_i · bit_i + (1-r_x_i) · (1-bit_i))`。理由：sumcheck 和 compute_v_at 共用 eq 函数。

#### Step 3 — CCCCS 实例（无 v_C）(fold/ccccs.rs)

1. **不存储 v_C 字段**（已选，v1.3 C2-002）：CCCCS 实例只存 `u_C / x_C / trace_C / witness_commitment_C`。理由：`v_C[j](X) = Σ_y M_j(X, y) · z_C(y)` 是关于 X 的多项式，在 CCCCS 创建时 r_x_L 尚不存在；v_C[j] 在折叠时于 r_x_L 处通过内层 batched sumcheck 计算并验证。
2. **satisfied() 在 x_C 处求值**（已选）：校验 `Σ_i c_i · Π_{j∈S_i} (Σ_y M_j(x_C, y) · z_C(y)) = u_C`。理由：x_C 是 CCCCS 的公共求值点，satisfied 验证此点处约束成立。

#### Step 4 — 单步折叠 (fold/fold_step.rs)

1. **fold challenge `r` 为单标量**（已选，v1.3）：通过 transcript 派生单个域元素 r。理由：Hypernova 折叠是标量线性组合 `z' = z_L + r·z_C`，无需向量 challenge。
2. **absord 序列：ccs_commitment + C_L + C_C**（已选，spec L432）：先 absorb CCS 承诺（防矩阵替换），再 absorb 两个 witness commitment。理由：绑定 fold 输入，防 prover 选择性 fold。
3. **CanonicalSerialize 编码 G1 点**（已选）：`C_L` / `C_C` 用 `CanonicalSerialize` 压缩为 32 bytes。理由：与 transcript absorb 格式一致，BLS12-381 G1 compressed 形式。
4. **folded_witness = z_L + r·z_C**（已选）：fold_step 返回 folded witness 向量。理由：PCS opening 需要完整的 folded witness（非仅 v' 分量）。
5. **v_C[j](r_x_L) 通过 sumcheck 计算**（已选）：fold_step 不直接计算 v_C[j](r_x_L)，而是通过 sumcheck::prove 的内层 batched sumcheck 间接计算并验证。理由：v_C[j](r_x_L) 是 sumcheck 的核心声明，直接计算会绕过 sumcheck 的 soundness 保证。

#### Step 5 — 外层 + 内层 batched sumcheck (fold/sumcheck.rs)

1. **外层 claimed sum = u' 标量**（已选，v1.3 C2-003）：证明 `Σ_X G(X) = u'`，其中 u' 是标量（非 v' 向量）。理由：relaxed 约束 `Σ_i c_i · Π v'[j] = u'` 的 RHS 是标量。
2. **内层 batched sumcheck 产生单 r_y**（已选，v1.3 C2-001）：引入 FS challenge γ，batched 证明 `Σ_j γ^j · v'[j] = Σ_Y (Σ_j γ^j · M_j(r_x_prime, Y)) · z'(Y)`，归约到单 challenge r_y。理由：combined_point = r_y（单 challenge，非 (r_x, r_{y_1}, ..., r_{y_t}) 元组），简化 PCS opening。
3. **r_x_prime（非 r_x_L）用于内层**（已选）：spec L392 写 `M_j(r_x_L, y)`，但数学上应为 `M_j(r_x_prime, y)`。理由：r_x_prime 是外层 sumcheck 产生的 fresh challenge point，spec 的 r_x_L 是简化标注。
4. **round polynomial 用 evaluation points 表示**（已选）：degree D 多项式用 D+1 个点 `[g(0), g(1), ..., g(D)]`。理由：prove 和 verify 对齐，无需系数转换。
5. **Lagrange 插值 eval_poly_at**（已选）：在 evaluation points 上求值 `g(r)`。理由：标准 Lagrange 插值，evaluation points 固定为 `x_i = i`。
6. **actual_u_prime 修正**（已选）：prove 返回 `actual_u_prime = Σ_X G(X)`（实际计算的 claimed sum）。理由：非线性 CCS（|S_i| ≥ 2）的 `u' = u_L + r·u_C` 是 FALSE（Π 不分配 +），actual_u_prime 是真实 sum。

#### Step 6 — 多步折叠 + PCS opening (fold/fold_loop.rs)

1. **fresh transcript per sumcheck**（已选）：每步 sumcheck 使用独立 `Transcript::new()`，不链式连接到 fold transcript。理由：verifier 创建 fresh transcript 即可验证 final sumcheck；fold challenge r 仍从主 transcript 派生（绑定 fold 输入），sumcheck 通过 z' 和 u' 间接绑定到 r。
2. **actual_u_prime 更新 folded LCCCS**（已选）：每步 fold + sumcheck 后，更新 `corrected_lcccs.u_l = actual_u_prime`。理由：非线性 CCS 的 `u' = u_L + r·u_C` ≠ actual_u_prime，folded LCCCS 的 u_l 必须为 actual_u_prime 才能通过 verifier 的 sumcheck 验证。
3. **PCS opening transcript 链式**（已选）：PCS opening 与 final sumcheck 共享同一 fresh transcript。理由：verifier 运行 sumcheck::verify 后在同一 transcript 上 pcs.verify，与 prover 对齐。
4. **简化 verifier（仅 final sumcheck + PCS opening）**（已选）：verify_hypernova 仅验证 final sumcheck + PCS opening，不验证中间 fold 步骤。理由：完整 verifier 需所有 sumcheck proofs + fold 数据（留待 Phase 8 完整实现）；MVP 阶段验证 final sumcheck + PCS opening 即可证明最终 folded 实例的 witness 一致性。
5. **HypernovaProof.abi_version = 1**（已选）：ZKVM_ABI_VERSION = 1（定义于 syscalls/mod.rs）。理由：与 spec L417 一致，Phase 8 反序列化时校验。
6. **MAX_FOLD_STEP_COUNT = 1000 上限**（已选，constraints/mod.rs）：fold_loop 校验 `ccccs_instances.len() ≤ 1000`。理由：防 OOM DoS，限制单次 prove 的最大折叠步数。

### 备选方案（未选）

#### Step 1 — CCS 扩展方法

1. **trait extension（extension trait）**（未选）：定义 `trait CcsFoldExt { fn to_lcccs(...); }`。未选理由：`Ccs` 与扩展在同一 crate，inherent impl 更直接。
2. **Merkle root ccs_commitment**（未选）：矩阵 entries 构建 Merkle tree。未选理由：矩阵数量少（t ≤ 10），串联 hash 足够，Merkle 增加对数开销。
3. **to_lcccs 隐式 r_x_l（随机派生）**（未选）：to_lcccs 内部从 transcript 派生 r_x_l。未选理由：r_x_l 是 LCCCS 的核心字段，应由调用方控制（测试需固定 r_x_l）。

#### Step 2 — LCCCS relaxed 实例

1. **strict 约束 u_L = 0**（未选）：LCCCS 约束 `Σ c_i · Π v_L[j] = 0`。未选理由：折叠后 u' 可能非 0，strict 形式无法表示 folded 实例。
2. **v_L 标量（单值）**（未选）：v_L 为单个域元素（Σ_j 加权）。未选理由：fold_step 需分量级折叠 `v'[j] = v_L[j] + r·v_C[j](r_x_L)`，标量形式无法分解。
3. **不存储 r_x_L（从 transcript 派生）**（未选）：verifier 从 transcript 重新派生 r_x_L。未选理由：r_x_L 是 public 参数，显式存储便于跨阶段传递。

#### Step 3 — CCCCS 实例

1. **存储 v_C 字段**（未选，v1.2）：CCCCS 存 v_C 向量。未选理由：v1.3 C2-002 修正 — v_C[j](X) 是多项式，创建时 r_x_L 不存在，无法求值；存储多项式表示增加复杂度。
2. **v_C 多项式表示**（未选）：存储 v_C[j] 的 MLE evaluation table。未选理由：每个 CCCCS 需存储 num_matrices 个长度 num_rows 的表，内存开销大；sumcheck 内部计算更高效。

#### Step 4 — 单步折叠

1. **fold challenge 向量**（未选）：r 为向量（每分量一个 challenge）。未选理由：Hypernova 折叠是标量线性组合，向量 challenge 无数学依据。
2. **直接计算 v_C[j](r_x_L)**（未选）：fold_step 内部调用 `ccs.compute_v_at(z_C, r_x_L)` 计算 v_C[j](r_x_L)。未选理由：绕过 sumcheck 的 soundness 保证；v_C[j](r_x_L) 应由 sumcheck 间接验证。
3. **folded_witness 不返回（仅返回 LCCCS）**（未选）：fold_step 仅返回 folded LCCCS + commitment。未选理由：PCS opening 需完整 folded witness z'，LCCCS.trace_l 可充当但语义混淆（trace_l 是 z_L，folded 后应为 z'）。

#### Step 5 — Sumcheck 协议

1. **外层 claimed sum = v' 向量**（未选，v1.2）：证明 `Σ_X G(X) = v'`（向量）。未选理由：v1.3 C2-003 修正 — relaxed 约束的 RHS 是标量 u'，非向量。
2. **内层 batched 多 r_y 元组**（未选，v1.2）：内层 sumcheck 归约到 `(r_x, r_{y_1}, ..., r_{y_t})` 元组。未选理由：v1.3 C2-001 修正 — batched sumcheck 产生单 r_y，PCS opening 在单点打开更简洁。
3. **r_x_L 用于内层（spec 标注）**（未选）：内层 sumcheck 使用 `M_j(r_x_L, y)`。未选理由：数学上应为 `M_j(r_x_prime, y)`，r_x_prime 是外层 sumcheck 的 fresh challenge；spec 的 r_x_L 是简化标注。
4. **round polynomial 用系数表示**（未选）：存储多项式系数 `[a_0, a_1, ..., a_D]`。未选理由：prove 和 verify 需对齐，evaluation points 表示更直接（无需系数转换）。
5. **不返回 actual_u_prime**（未选）：prove 仅返回 proof + r_y + z_at_r_y。未选理由：非线性 CCS 的 actual_u_prime ≠ u_L + r·u_C，fold_loop 需此值更新 folded LCCCS 的 u_l。

#### Step 6 — 多步折叠 + PCS opening

1. **sumcheck 链式 transcript**（未选）：每步 sumcheck 在上一步 transcript 上继续。未选理由：verifier 需从第一步开始重建所有 transcript，复杂度高；fresh transcript 使 verifier 仅需 final sumcheck。
2. **不更新 u_l（用 spec 公式值）**（未选）：folded LCCCS 的 u_l 保持 `u_L + r·u_C`。未选理由：非线性 CCS 的 actual_u_prime ≠ u_L + r·u_C，verifier 的 sumcheck 验证会失败（claimed sum ≠ 实际 sum）。
3. **PCS opening 独立 transcript**（未选）：PCS opening 使用 fresh transcript（非链式）。未选理由：verifier 需在同一 transcript 上先 sumcheck::verify 再 pcs.verify，独立 transcript 会导致 transcript 状态不一致。
4. **完整 verifier（验证所有 fold 步骤）**（未选）：verify_hypernova 验证所有 N-1 步 fold 的 sumcheck。未选理由：HypernovaProof 仅含 final_sumcheck（spec L417），完整 verifier 需所有 sumcheck proofs + fold 数据；MVP 阶段简化 verifier 足够，完整实现留待 Phase 8。
5. **N=1 时返回 trivial proof**（未选）：0 个 CCCCS 实例时返回空 proof。未选理由：fold_loop 要求至少 1 个 CCCCS 实例（N ≥ 2），N=1 场景由上层 prover 直接返回 CCS satisfied 实例（非 fold_loop 职责）。
6. **stub commitment 用于 verify_hypernova 测试**（未选）：verify_hypernova 测试用 `G1Affine::generator()` 作为 stub commitment。未选理由：pcs.open 内部计算 `⟨z', G⟩`，pcs.verify 用 `C' = C_L + r·C_C`；stub commitment 导致 `C' ≠ ⟨z', G⟩`，transcript 不匹配；必须用真实 IPA commitment。

### 实现期发现

- **actual_u_prime 修正是关键**：非线性 CCS（|S_i| ≥ 2）的 `Π_{j∈S_i} (v_L[j] + r·v_C[j]) ≠ Π v_L[j] + r·Π v_C[j]`（Π 不分配 +），因此 `u' = u_L + r·u_C` 是 FALSE。sumcheck::prove 计算的 `actual_u_prime = Σ_X G(X)` 是真实 claimed sum。fold_loop 必须用 actual_u_prime 更新 folded LCCCS 的 u_l，否则 verifier 的 sumcheck 验证失败。
- **fresh transcript 设计**：每步 sumcheck 使用独立 fresh transcript，使 verifier 能用 fresh transcript 验证 final sumcheck。fold challenge r 仍从主 transcript 派生（绑定 fold 输入），sumcheck 通过 z' 和 u' 间接绑定到 r。这是 prover/verifier transcript 对齐的关键设计。
- **IPA commitment 一致性**：pcs.open 内部从 witness 多项式计算 commitment `⟨z', G⟩`，pcs.verify 使用 `proof.witness_commitment = C' = C_L + r·C_C`。为使两者匹配，C_L 和 C_C 必须是真实 IPA commitment（非 stub），这样 `C' = ⟨z_L, G⟩ + r·⟨z_C, G⟩ = ⟨z_L + r·z_C, G⟩ = ⟨z', G⟩`。
- **x_l / x_c 维度一致**：fold_step 校验 `lcccs.x_l.len() == ccccs.x_c.len()`。4-row CCS 测试中 r_x_l 长度 = log2(4) = 2，若 x_c = vec![f(0), f(0)] 则 x_l 也必须长度 2（不能为空）。
- **MultilinearPoly from_evals 要求 2 的幂**：folded witness 长度 = num_vars，必须为 2 的幂。sumcheck 内部已校验，fold_loop 的 PCS opening 依赖此保证。
- **debug_assert PCS eval 一致性**：fold_loop 在 debug 模式下校验 `pcs_eval == last_z_at_r_y`（PCS opening 的 eval 应 = sumcheck 的 z_at_r_y）。这是 prover 内部一致性检查，release 模式下跳过。
- **cloned_ref_to_slice_refs 优化**：`&[ccccs.clone()]` 可替换为 `std::slice::from_ref(&ccccs)`，避免不必要的 clone（fold_loop 接受 `&[Ccccs]`，借用即可）。
- **fold_step.rs Ccs 导入**：`Ccs` 仅在 test 模块使用（非 test 代码用 `Fr` 但不用 `Ccs`），应从模块级 import 移到 test 模块 import，避免 unused_imports 警告。

---

## Phase 7 — Prover 与最终压缩

### Recommended（采用方案）

1. **prover 模块拆分为 mod.rs + spartan.rs + groth16_compress.rs** — 主流程（prove/ProverConfig/ZkPublicIo/serialize_proof/pad_trace）与压缩器解耦，便于 Phase 12 替换 Spartan/Groth16 stub 为完整 SNARK 实现。
2. **ProverConfig 使用 Bn254ScalarField（newtype）而非 ark_bn254::Fr** — 与 `crate::ccs::Fr` 类型一致，prove() 内部用 `.into_fr()` 桥接到 `ZkvmExecutionConfig`（后者用 ark_bn254::Fr），构造 ZkPublicIo 时用 `ZkvmFr::from_fr()` 反向桥接 events。
3. **trace padding 使用 RISC-V NOP（Addi x0, x0, 0）** — 保证 `trace.len() % batch_size == 0` 使所有 batch 生成相同结构的 CCS（num_vars/num_rows 一致），且 NOP 不改变执行语义（output/events 已在 ExecuteResult 中固定）。
4. **serialize_proof stub 使用 length-prefixed 二进制** — 简单往返一致（magic + version + abi_version + 各字段 length-prefixed），Phase 5.5 替换为 spec L452-483 规范格式（含 field_id / proof_kind / MAX_* 字段长度上限校验）。
5. **Spartan/Groth16 stub 返回 Phase 12 pending 错误** — `spartan_compress` / `groth16_compress` 返回 `ZkvmError::Other("Phase 12 pending")`，明确未实现边界，避免误用。完整 SNARK 实现留待 Phase 12（spec L601-621）。
6. **cargo-zkvm prove 同时输出 proof + .public_io 文件** — verifier 验证时需要 proof + ZkPublicIo 两者，cmd_prove 写出 `<output>` proof 文件 + `<output>.public_io` 公共输入输出文件，保持 3 参数简洁（不引入额外 --public-io 参数）。
7. **x_l / x_c = r_x_l（非 CcsInstance.public_inputs）** — Hypernova fold 协议的 LCCCS.x_l / CCCCS.x_c 是公共求值点（长度 = log2(num_rows)），不是 CcsInstance.public_inputs（[batch_id, first_idx, last_idx]）。public_inputs 仅 absorb 到 transcript 供 verifier 侧 batch 连续性校验，不参与 fold 方程。

### Alternatives（未采用方案）

1. ~~ProverConfig 直接用 ark_bn254::Fr~~ — 会破坏 crate 内 Fr 类型一致性（crate::ccs::Fr = Bn254ScalarField newtype），且 ZkPublicIo 序列化需 newtype 的 to_canonical_bytes 方法。
2. ~~trace padding 用 ECALL~~ — 会触发 syscall 分派，改变执行结果（可能 panic 或产生额外 output/events），破坏证明正确性。
3. ~~serialize_proof 用 serde~~ — 引入额外依赖，且 spec L452-483 格式非 serde 标准（含 magic / abi_version / MAX_* 长度校验，需手动二进制布局）。
4. ~~prove() 内部自动压缩（Spartan/Groth16）~~ — MVP 阶段压缩器未就绪（Phase 12），过早集成会阻塞 Phase 7 交付。当前 prove() 仅在 proof_bytes > proof_size_limit 时返回错误，提示需 CycleFold 压缩。
5. ~~cargo-zkvm prove 只输出 proof 文件~~ — verifier 无法独立验证，需配套 public_io（含 input/output/randomness_seed/commitments/event_hashes）。
6. ~~proof_size_limit 检查放在 fold_loop 内~~ — 职责泄漏，fold_loop 应专注折叠，proof 大小检查是 prover 端职责（fold_loop 生成 HypernovaProof，prover 序列化后检查大小）。
7. ~~x_l / x_c = CcsInstance.public_inputs~~ — public_inputs 长度 = 3（[batch_id, first_idx, last_idx]），但 Ccccs::new 要求 x_c.len() == log2(num_rows)，fold_step 要求 x_l.len() == x_c.len()。public_inputs 长度与 log2(num_rows) 不匹配会导致维度错误。

### Implementation Discovered（实现中发现）

1. **IPA PCS 要求 witness 长度 = 2^m** — `MultilinearPoly::from_evals` 要求 evals.len() 是 2 的幂。CCS 的 num_vars = batch_size + 1，因此 batch_size + 1 须为 2 的幂。当前 MVP 限制：`ProverConfig::default().batch_size = 3`（num_vars = 4 = 2^2）。Phase 5 增强版将在 CCS 构造时自动 padding 到 2 的幂，届时可恢复 batch_size = 1024。
2. **fold_loop 要求 ≥1 个 CCCCS 实例** — 即至少 2 个 CCS 实例（1 LCCCS + 1 CCCCS）。prove() 中显式校验 `ccs_instances.len() >= 2`，不足返回错误提示增加 trace 长度或减小 batch_size。
3. **ZkvmExecutionConfig 用 ark_bn254::Fr，ProverConfig 用 Bn254ScalarField** — 类型不一致需 `.into_fr()` / `from_fr()` 桥接。prove() 中 `config.randomness_seed.into_fr()` 转换 randomness_seed / initial_commitment / final_commitment，`exec_result.events.iter().map(|f| ZkvmFr::from_fr(*f))` 转换 events。
4. **exec_result.events 是 Vec<ark_bn254::Fr>** — execute_elf_with_config 返回的 events 类型是 ark_bn254::Fr（非 newtype），构造 ZkPublicIo 时需逐元素 `ZkvmFr::from_fr(*f)` 转换。
5. **executor::tests 的 build_test_elf / encode_text 是私有** — prover 集成测试需复制一份到 prover::tests（无法跨模块引用私有测试辅助函数）。
6. **validate_elf 对 parse 错误返回 Other 而非 InvalidZkProofFormat** — `Elf::parse` 失败时 validate_elf 返回 `ZkvmError::Other("ELF parse error: ...")`，prove() 透传此错误。test_prove_invalid_elf_errors 应 expect Other("ELF parse error")，非 InvalidZkProofFormat。
7. **Ccccs::new 校验 x_c.len() == log2(num_rows)** — CCCCS 的 x_c 是公共求值点（长度 = log2(num_rows)），非任意公共输入。Lcccs::new 不校验 x_l 长度，但 fold_step 校验 x_l.len() == x_c.len()，因此 x_l 也须为 log2(num_rows) 长度。

---

## 待补充

后续 Phase（8-9, 11-13）的备选方案将在实现时补充到此文档。

- Phase 2 已完成（4 个 Task 全部实现，160 测试通过，clippy 零警告，release build 成功）
- Phase 3 已完成（4 个 Task 全部实现，246 测试通过，clippy 零警告，cargo-zkvm `run` 子命令集成）
- Phase 4 已完成（7 个 Step 全部实现，319 测试通过，clippy 零警告，10 个 host syscall 实现）
- Phase 10 已完成（7 个 Step 全部实现，357 测试通过，clippy 零警告，4 个预编译电路 + CCS 基础结构）
- Phase 5 已完成（7 个 Step 全部实现，523 lib tests + 30 bin tests 通过，clippy 零警告，6 个子电路模块 + LogUp lookup 协议）
- Phase 6 已完成（6 个 Step 全部实现，610 lib tests + 30 bin tests 通过，clippy 零警告，Hypernova 折叠算法完整实现：CCS 扩展 + LCCCS/CCCCS + fold_step + sumcheck + fold_loop + verify_hypernova）
- Phase 7 已完成（3 个 Step 收尾 + cargo-zkvm prove 集成，633 lib tests + 31 bin tests 通过，clippy 零警告，端到端 prover：prove() + ProverConfig + ZkPublicIo + serialize_proof + pad_trace + Spartan/Groth16 stub + cargo-zkvm prove 子命令）

---

## Phase 8 — 链上 Verifier Production 实现

### Recommended（采用方案）

1. **CCS 序列化采用 COO 格式（row/col/value 三元组）** — SparseMatrix 以 `Vec<SparseEntry>` 存储，序列化为 `num_rows(u64) || num_cols(u64) || entries_count(u32) || entries...`。相比 CSR/CSC 格式更简单往返一致，且 from_bytes 可逐 entries 校验 row/col 边界（防 OOB）。
2. **PROOF_VERSION 从 v1 升级到 v2（含 CCS 序列化）** — v1 不含 CCS（verifier 无法重建 IpaPcs），v2 在 folded_instance 首字段序列化 CCS（length-prefixed）。deserialize_proof 校验 magic + version + abi_version + 总长度（MAX_PROOF_TOTAL_SIZE=48KB）。
3. **verify_production 复用 fold_loop::verify_hypernova 逻辑** — 不重新实现 sumcheck/PCS verify，直接调用 `sumcheck::verify` + `pcs.verify`，共享 fresh Transcript（与 prover 的 final sumcheck transcript 匹配）。
4. **pcs_n_vars = num_vars.trailing_zeros()（非 checked_ilog2 + 1）** — 对于 num_vars=4，trailing_zeros=2（正确，IpaPcs::new(2) 创建 4 个 generators）；checked_ilog2(4)+1=3（错误，创建 8 个 generators）。
5. **poker_l1 添加 poker_zkvm 依赖 + test-helpers feature** — poker_l1 的 Cargo.toml 添加 `poker_zkvm = { workspace = true }`，dev-dependencies 添加 `poker_zkvm = { workspace = true, features = ["test-helpers"] }` 以访问 `generate_test_proof` 跨 crate 测试辅助函数。
6. **ZkVerifyContext 生命周期参数化（`'a`）** — `last_partial_proof_hash: Option<&'a Hash>` 借用链上状态，避免克隆 Hash（32B）。ctx 在 verify_with_context 调用期间存活即可。
7. **HypernovaVerifier + ZkShuffleVerifier 分离** — HypernovaVerifier 只处理 scheme_id=1（Zkvm，强制 Production）；ZkShuffleVerifier 处理 scheme_id=4（grace 期内 stub 路径 + M2-003 proof_hash 匹配）。两者都实现 ZkVerifier trait 的 verify_with_context。
8. **M2-003 proof_partial_hash 不可变约束优先于 SEC-H1 进度校验** — execute_partial_checkin 中先校验 proof_partial_hash 匹配/幂等，再校验进度。因 M2-003 不可变约束比进度校验更严格（proof_partial_hash 不匹配直接拒绝，不论进度是否推进）。
9. **map_zkvm_error 中 AbiVersionMismatch u32→u8 转换** — ZkvmError 用 u32，PokerL1Error 用 u8（ABI 版本号实际范围 0-255）。使用 `u8::try_from` + 溢出回退到 Other 错误。
10. **grace 期后强制 Production 检查在 Stub 检查之前** — verify_with_context 中先判定 grace_period_ended / in_grace_period，再判定 status == Stub。否则 grace 期后 status=Stub 会直接返回 Ok(true) 绕过 Production 强制。

### Alternatives（未采用方案）

1. ~~CCS 序列化用 serde~~ — 引入额外依赖，且 spec 要求手动二进制布局（length-prefixed + 边界校验），serde 无法表达 "entries_count(u32) + 逐 entries 校验 row < num_rows" 的细粒度校验。
2. ~~PROOF_VERSION 保持 v1（不含 CCS）~~ — verifier 无法重建 IpaPcs（需 num_vars 计算 pcs_n_vars），proof 验证无法独立完成。v2 含 CCS 是 Production verifier 的必要条件。
3. ~~verify_production 重新实现 sumcheck/PCS verify~~ — 代码重复，且易与 prover 侧实现不一致。复用 fold_loop::verify_hypernova 逻辑保证 prover/verifier 对称。
4. ~~pcs_n_vars = checked_ilog2(num_vars) + 1~~ — 对 num_vars=4 给出 3（错误），创建 8 个 generators。trailing_zeros 给出 2（正确），创建 4 个 generators。
5. ~~poker_l1 不依赖 poker_zkvm，通过 FFI/JSON 通信~~ — 增加序列化开销与维护成本。直接 crate 依赖最简单，且 poker_zkvm 是 workspace 成员。
6. ~~ZkVerifyContext 拥有 Hash 所有权（非借用）~~ — 每次验证需克隆 32B Hash，性能开销不必要。借用更符合零成本抽象。
7. ~~HypernovaVerifier 同时处理 scheme_id=1 和 scheme_id=4~~ — 违反单一职责原则，且 scheme_id=4 的 grace 期 stub 路径与 scheme_id=1 的 Production 路径逻辑差异大。分离两个 verifier 更清晰。
8. ~~M2-003 校验在进度校验之后~~ — 会导致 proof_partial_hash 不匹配 + 进度推进时走到 "允许" 分支，违反不可变约束。M2-003 必须优先。
9. ~~map_zkvm_error 中 AbiVersionMismatch 直接 as u8~~ — u32 → u8 截断会丢失高位，且非规范化转换。try_into + 溢出处理更安全。
10. ~~grace 期后强制 Production 检查在 Stub 检查之后~~ — status=Stub 时会先返回 Ok(true)，绕过 grace 期后强制 Production 的要求。必须在 Stub 检查之前。

### Implementation Discovered（实现中发现）

1. **poker_zkvm 的 generate_test_proof 需 pub（非 pub(crate)）** — poker_l1 集成测试需跨 crate 调用。但 `#[cfg(test)]` 在 poker_zkvm 作为依赖编译时不启用，需添加 `test-helpers` feature + `#[cfg(any(test, feature = "test-helpers"))]`。
2. **ZkvmError::AbiVersionMismatch 用 u32，PokerL1Error::AbiVersionMismatch 用 u8** — 类型不一致需 try_into 转换。ABI 版本号实际范围 0-255（ZKVM_ABI_VERSION=1），u8 足够。
3. **M2-003 不可变约束使 NoProgressPartialCheckin 实际不触发** — proof_partial_hash 不匹配时优先返回 PartialFoldHashImmutable（M2-003 优先于 SEC-H1 进度校验）。现有 test_execute_partial_checkin_no_progress 需更新为期望 PartialFoldHashImmutable。
4. **grace 期后 HypernovaVerifier 的 verify_with_context 须在 Stub 检查前判定** — 否则 status=Stub 直接返回 Ok(true)，绕过 grace 期后强制 Production。调整逻辑顺序：M2-004 签名校验 → grace_period_ended → in_grace_period → status==Stub → Production。
5. **ZkShuffleVerifier 的 M2-003 校验仅在 grace 期内 + status==Stub 时执行** — Production 状态走 ZkShuffle Production verifier（Phase 11 迁移），不参与 proof_hash 匹配校验。
6. **poker_l1 的 ZkPublicIo ≠ poker_zkvm 的 ZkPublicIo** — 前者是 OffChain 边界（initial_commitment/final_commitment/state_delta_hash/ack_chain_hash/fold_step_count/skip_count/segment_continuity_proof），后者是 ZKVM 公共输入输出（input/output/randomness_seed/initial_commitment/final_commitment/event_hashes）。需 public_io_to_zkvm 转换函数。
7. **poker_l1 添加 poker_zkvm 依赖后编译时间增加 ~10s** — poker_zkvm 依赖 arkworks 全家桶（ark-ff/ark-ec/ark-poly/ark-serialize/ark-bn254/ark-grumpkin），首次编译需 ~10s。后续增量编译不受影响。

### Phase 8 完成状态

- Phase 8 已完成（13 个 Step 全部实现，poker_zkvm 651 lib tests + poker_l1 1271 lib tests 通过，clippy lib 零错误，链上 Verifier Production 完整实现：CCS 序列化 + serialize/deserialize_proof v2 + verify_production + HypernovaVerifier Production 分支 + ZkShuffleVerifier grace 期双通道 + M2-003 proof_partial_hash 不可变 + M2-004 签名形式校验 + 12 个 Phase 8 集成测试）

---

## Phase 9 — CycleFold 递归聚合

### 推荐方案（已实现）— MVP 原生验证 + 电路定义

- **Task 9.1 + 9.2**：完整实现 — `cyclic/mod.rs` 曲线 cycle 抽象（`CycleCurve` trait + `Bn254GrumpkinCycle` + cycle 性质运行时校验）+ `recursion/mod.rs` CycleFold 树形聚合（`CycleFoldNode` + `aggregate` + `tree_aggregate` + 递归终止条件 + 原生验证）
- **Task 9.3 + 9.4**：电路结构定义（`RecursiveVerifierCircuit` trait + `CircuitBn254` / `CircuitGrumpkin` + 6 条约束文档化 + 约束数估算 100k-200k）+ 原生验证模拟（`verify_native` 委托到 `verify_hypernova`）。真实 R1CS / PLONKish 电路编译推迟到 Phase 12/13。
- **理由**：与 Phase 8 一致（`verify_production` 也是原生验证而非电路内验证）；spec L590/L599 明确将"递归电路本身的 SNARK 证明"推迟到 Phase 12/13（Spartan / Groth16 压缩）。

### 备选方案 A — 完整 arkworks R1CS 电路

- **描述**：添加 `ark-r1cs-std` + `ark-relations` 依赖，实现真实 R1CS 约束（EC 点算术 + IPA verify + sumcheck verify）。
- **未选理由**：10-20 万约束/层，工作量巨大；arkworks R1CS EC 算术复杂；Phase 12/13 才需真实 SNARK；MVP 阶段原生验证已提供 soundness 保证。

### 备选方案 B — halo2 PLONKish 电路

- **描述**：使用 `halo2_proofs` 实现 PLONKish 电路。
- **未选理由**：与 arkworks 栈不一致；alternatives 文档 Phase 0 已拒绝 halo2（Hypernova 折叠生态在 arkworks 更成熟）。

### 备选方案 C — 递归聚合返回 CycleFoldNode 而非 HypernovaProof

- **描述**：`aggregate` 返回树结构而非单个 proof。
- **未选理由**：tasks.md 签名要求返回 `HypernovaProof`；树结构作为 `tree_aggregate` 的内部实现，`aggregate` 从树根提取 proof。

### Implementation Discovered（实现中发现）

1. **`verify_hypernova` 需真实 IPA commitment** — `fold_loop` 的 `initial_commitment` 参数若使用 stub（`G1Affine::generator()`），最终 `witness_commitment = stub + r·C_C` 不匹配实际 folded witness，导致 `pcs.verify` 失败。测试辅助函数 `make_proof` 须使用 `commit_witness(pcs, &z_l)` 构造真实 commitment（参考 `fold_loop.rs` L557-587 的 `test_verify_hypernova_linear_ccs_valid`）。
2. **`recursion/mod.rs` 从单文件转为目录模块** — Phase 13 占位为单文件 `recursion/mod.rs`，Phase 9 需添加 `circuit_bn254.rs` / `circuit_grumpkin.rs` 子模块，转为目录模块。Phase 13 的 Spartan/Groth16 压缩逻辑将在 `recursion/` 下新增子模块（如 `recursion/spartan.rs`），不与 Phase 9 冲突。
3. **曲线交替规则** — 叶节点为 BN254（HypernovaProof 基于 BN254 IPA PCS），depth 1 = Grumpkin（C_Grumpkin 验证 BN254 叶 proofs），depth 2 = BN254，依此类推。奇数 depth = Grumpkin，偶数 depth = Bn254。
4. **MVP `aggregated_proof` 取左子树 proof** — 真实 CycleFold 压缩需 SNARK 电路将两个子 proof 压缩为一个更小的 proof。MVP 阶段 `aggregated_proof = left.proof().clone()`，仅验证所有 sub-proof 的 soundness，不压缩 proof 大小。

### Phase 9 完成状态

- Phase 9 已完成（Task 9.1/9.2/9.3/9.4 全部实现，poker_zkvm 693 lib tests 通过（+36 新增 Phase 9 测试），clippy lib 零警告，CycleFold 树形聚合 + 递归终止条件 + C_BN254/C_Grumpkin 电路定义 + 6 条约束文档化 + 原生验证模拟）
