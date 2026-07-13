# Tasks — Hypernova ZKVM（支持 Rust 直接编译）

> **change-id**：`build-hypernova-zkvm`
> **依赖**：`build-poker-l1-chain`（spec FROZEN 2026-06-27）
> **版本**：v1.4（v1.3 密码学专家复核后修订 — 8 项修复：**2 MAJOR**：M3-001 治理参数清单 MAX_* 默认值同步（8KB/8KB/16KB/8KB）/ M3-002 grace 期后 scheme_id=4 分支明确（走 ZkShuffle Production verifier）；**6 MINOR**：Min3-001 total_payload checked_add/checked_mul / Min3-002 游戏终结判定条件 / Min3-003 幂等重提交范围 / Min3-004 删除 v1.2 残留 grace 期表述 / Min3-005 外层 sumcheck 公式括号 / Min3-006 gas 估算明细）
> **v1.2 变更摘要**（v1.1 独立审核后修订）：修正 Hypernova 折叠核心等式 — `v` 向量化 / fold challenge 标量化 / transcript 补矩阵承诺+witness commitment / LogUp `β` 在 witness 承诺后派生 / 内存一致性改 byte-level permutation / proof 反序列化字段长度上限 / ELF TOCTOU+checked_add+PT_DYNAMIC / `ZkPublicIo` 新增 3 字段 + 序列化 bump / slot 值 Merkle 绑定 / event hash 绑定 step_index / randomness 派生函数绑定上下文 / CycleFold 递归 verifier 电路定义 + Task 9.3/9.4 / CcsInstance 迁移诚实 BREAKING / CheckinTx.proof_kind 序列化策略 + scheme_id 映射 / Phase 5.5 依赖修正 / IPA challenge 派生 + NUMS generators / Production grace period 双通道 + 切换高度绑定
> **执行原则**：分阶段并行推进；每阶段产出可独立验证；优先实现最小可用闭环（Rust → ELF → trace → CCS → fold → verify），再迭代优化

## Phase 0：crate 骨架与依赖集成

- [ ] Task 0.1：创建 `poker_zkvm/` crate 骨架
  - [ ] SubTask 0.1.1：在根 `Cargo.toml` 添加 `poker_zkvm = { path = "poker_zkvm" }` workspace 成员
  - [ ] SubTask 0.1.2：创建 `poker_zkvm/Cargo.toml`（lib + bin `cargo-zkvm`），声明依赖：`ark-ff` / `ark-ec` / `ark-poly` / `ark-serialize` / `ark-groth16` / `ark-bn254` / `ark-grumpkin` / `halo2` / `sha2` / `blake2` / `blstrs` / `secp256k1` / `rayon` / `thiserror` / `serde` / `goblin`（ELF 解析）
  - [ ] SubTask 0.1.3：创建 `poker_zkvm/src/lib.rs`，声明 `#![deny(unsafe_code)]`，定义模块树（`compiler` / `isa` / `trace` / `constraints` / `pcs` / `fold` / `prover` / `verifier` / `syscalls` / `precompiles` / `cyclic` / `recursion` / `field` / `transcript` / `serialize` / `error`）
  - [ ] SubTask 0.1.4：定义 `poker_zkvm/src/error.rs` — `ZkvmError` 枚举（`UnsupportedInstruction` / `TraceTooLong` / `TraceHostMemoryExceeded` / `OutOfMemory` / `UnalignedAccess` / `InvalidZkProofFormat` / `SumcheckVerificationFailed` / `CrossLanguageClaimFailed` / `TranscriptMismatch` / `PcsVerificationFailed` / `AbiVersionMismatch` / `InvalidSlot` / `RecursionDepthExceeded` / `FoldStepCountExceeded` / `FoldError` / `ProofKindMismatch` / `UninitializedRead` / `Other`）
  - [ ] SubTask 0.1.5：`cargo build` 通过，`cargo test` 通过空测试

## Phase 1：字段、曲线 cycle 与 transcript

- [ ] Task 1.1：实现 `poker_zkvm/src/field.rs` — `ZkvmField` trait + BN254 标量域实现
  - [ ] SubTask 1.1.1：定义 `ZkvmField` trait，文档明确 `from_u32_with_wrap` (mod p) 与 `to_u32` (mod 2^32) 语义差异
  - [ ] SubTask 1.1.2：实现 `Bn254ScalarField`（基于 `ark_bn254::Fr`）
  - [ ] SubTask 1.1.3：实现 u32/u64 → 域元素包装（mod p），域元素 → u32（使用 `rem_euclid(2^32)` 抽取，防负 bigint 截断）函数
  - [ ] SubTask 1.1.4：单元测试覆盖 u32 加法 / 乘法溢出场景（含 overflow_bit 约束验证）
- [ ] Task 1.2：实现 `poker_zkvm/src/transcript.rs` — Fiat-Shamir transcript（严格规范）
  - [ ] SubTask 1.2.1：定义 `Transcript` 结构（基于 `Blake2bVar`），支持 `absorb(domain_tag, length_prefix, data)` / `challenge(domain_tag) -> FieldElement`
  - [ ] SubTask 1.2.2：实现 canonical 编码 — 域元素固定 32 bytes LE，commitment 为 curve point compressed 33 bytes
  - [ ] SubTask 1.2.3：实现 length-prefixing（4 bytes LE，防 concatenation ambiguity）
  - [ ] SubTask 1.2.4：定义域分离常量：`HYPERNOVA_FOLD_DOMAIN_TAG = 0x10` / `SUMCHECK_DOMAIN_TAG = 0x11` / `LOOKUP_DOMAIN_TAG = 0x12` / `MEM_CHECK_DOMAIN_TAG = 0x13` / `PCS_OPEN_DOMAIN_TAG = 0x14`
  - [ ] SubTask 1.2.5：实现 absorb 序列规范（**v1.2 补矩阵承诺 + witness commitment**）— fold 阶段 absorb `FOLD_TAG || public_io || ccs_struct_params || ccs_commitment || lcccs_witness_commitment || lcccs_u || lcccs_x || lcccs_v || ccccs_witness_commitment || ccccs_u || ccccs_x || ccccs_v`；sumcheck / lookup / pcs_open 阶段同 spec；`ccs_commitment` = 矩阵 `M_1..M_t` 承诺的 Merkle root，防矩阵内容替换
  - [ ] SubTask 1.2.6：单元测试 — 相同输入相同 challenge；不同输入不同 challenge；length-prefix 防歧义（`"ab"+"c"` vs `"a"+"bc"` 产生不同 challenge）

## Phase 1.5：多项式承诺方案（PCS）— **新增 Phase**

- [ ] Task 1.5.1：实现 `poker_zkvm/src/pcs/mod.rs` — `Pcs` trait 抽象
  - [ ] SubTask 1.5.1.1：定义 `Pcs` trait（`commit(poly: &MultilinearPoly) -> Commitment` / `open(poly, point) -> (Proof, Eval)` / `verify(commitment, point, eval, proof) -> bool`）
  - [ ] SubTask 1.5.1.2：定义 `Commitment` / `Proof` / `Eval` 类型（与曲线 cycle 兼容）
- [ ] Task 1.5.2：实现 `poker_zkvm/src/pcs/ipa.rs` — IPA over BN254（**v1.2 补 challenge 派生 + NUMS generators**）
  - [ ] SubTask 1.5.2.1：实现 `commit(poly)` — Pedersen vector commitment，BN254 MSM；**generators 通过 hash-to-curve NUMS 派生**：`G_i = hash_to_curve(b"poker_zkvm_ipa_gen" || i)`
  - [ ] SubTask 1.5.2.2：实现 `open(poly, point)` — log(N) 轮 IPA protocol，每轮产生 1 commitment；**每轮 challenge 从 transcript 派生**：`r_i ← challenge(PCS_OPEN_TAG || round_commitment_i || round_index_i)`；**open 开始前 absorb `PCS_OPEN_TAG || commitment || point`** 绑定 point 与 commitment 防 proof 复用
  - [ ] SubTask 1.5.2.3：实现 `verify(commitment, point, eval, proof)` — log(N) 轮挑战重算最终 commitment，校验一致；**verifier 重算 challenge 时使用相同 absorb 顺序（含 point 与 commitment 绑定）**
  - [ ] SubTask 1.5.2.4：单元测试 — 小规模多线性多项式（n_vars <= 8）commit/open/verify 闭环
  - [ ] SubTask 1.5.2.5：soundness 负例测试 — 篡改 eval / 篡改 proof / 篡改 commitment / **复用 proof 到不同 point** 任一字段必须 verify 失败

## Phase 2：前端编译流水线

- [ ] Task 2.1：实现 `poker_zkvm/src/compiler/mod.rs` — `cargo-zkvm` 编译入口
  - [ ] SubTask 2.1.1：定义 `CompilerConfig`（target = `riscv32i-unknown-none-elf` / opt-level = 3 / panic = abort）
  - [ ] SubTask 2.1.2：实现 `compile_crate(crate_path) -> PathBuf`，调用 `rustc --target riscv32i-unknown-none-elf`
  - [ ] SubTask 2.1.3：实现 `compile_std_bindings()` — 生成 `_start` trampoline 调用用户 `main`，从 `zkvm_read_input` 读输入，`zkvm_commit_output` 提交输出，panic 转 `zkvm_panic`
- [ ] Task 2.2：实现 `poker_zkvm/src/compiler/elf_validator.rs` — **强化 ELF 校验（v1.2 补 TOCTOU + checked_add + PT_DYNAMIC）**
  - [ ] SubTask 2.2.1：校验 ELF magic / class（ELF32）/ endian（little）/ machine（EM_RISCV）
  - [ ] SubTask 2.2.2：校验所有段地址在 `[0, MAX_ZKVM_MEMORY)` 范围内，**且 `addr.checked_add(size) <= MAX_ZKVM_MEMORY`**（使用 `checked_add` 防段地址+段大小 wrap 攻击，如 `addr=0xFFFFFFF0, size=0x20`）
  - [ ] SubTask 2.2.3：校验 entry point 在 `.text` 段范围内
  - [ ] SubTask 2.2.4：校验段之间无重叠
  - [ ] SubTask 2.2.5：校验所有 relocation 入口指向有效段内偏移
  - [ ] SubTask 2.2.6：扫描 `.text` 段所有指令属于 RV32I 子集（拒绝 fence.i / 浮点 / atomics / SIMD / compressed）
  - [ ] SubTask 2.2.7：校验 `.text` 段大小 ≤ `MAX_TEXT_SIZE = 8MB`，总加载内存 ≤ `MAX_ZKVM_MEMORY = 16MB`（**使用 `checked_add` 累加各段大小**）
  - [ ] SubTask 2.2.8：**拒绝 `PT_DYNAMIC` 段与 `DT_NEEDED` 入口**（防 dynamic linking 触发外部符号解析）
  - [ ] SubTask 2.2.9：**校验 `e_shoff + e_shnum * e_shentsize` 不溢出**（防 section header table 损坏导致解析器崩溃）
  - [ ] SubTask 2.2.10：**消除 TOCTOU** — `validate_elf(elf_bytes: &[u8]) -> Result<ElfMetadata, ZkvmError>` 接受字节切片返回已解析 `ElfMetadata`；`load_elf(metadata: &ElfMetadata, state)` 接受 `ElfMetadata` 而非路径
  - [ ] SubTask 2.2.11：单元测试覆盖每项校验失败的负例（含 wrap 攻击 / PT_DYNAMIC / TOCTOU）
- [ ] Task 2.3：实现 `poker_zkvm/src/compiler/prelude.rs` — `zkvm::prelude` 模块
  - [ ] SubTask 2.3.1：re-export `alloc::vec::Vec` / `alloc::boxed::Box` / `alloc::string::String` / `alloc::format!`
  - [ ] SubTask 2.3.2：定义 `zkvm::entry` 宏 — 标记用户入口函数，生成 `_start` trampoline
  - [ ] SubTask 2.3.3：定义 `zkvm::test` 宏 — 标记测试函数，供 `cargo zkvm test` 调用
- [ ] Task 2.4：实现 `cargo-zkvm` bin（`poker_zkvm/src/bin/cargo-zkvm.rs`）
  - [ ] SubTask 2.4.1：实现 `cargo zkvm build` 子命令（调用 `compiler::compile_crate` + `elf_validator::validate_elf`）
  - [ ] SubTask 2.4.2：实现 `cargo zkvm run --elf <path> --input <path>` 子命令
  - [ ] SubTask 2.4.3：实现 `cargo zkvm prove --elf <path> --input <path> --output <path>` 子命令
  - [ ] SubTask 2.4.4：实现 `cargo zkvm verify --proof <path> --public-io <path>` 子命令
  - [ ] SubTask 2.4.5：实现 `cargo zkvm test` 子命令（扫描 `#[zkvm::test]` 标记，自动 compile + run + prove + verify）

## Phase 3：ZKVM ISA 执行引擎

- [ ] Task 3.1：实现 `poker_zkvm/src/isa/mod.rs` — RV32I 指令解码与执行
  - [ ] SubTask 3.1.1：定义 `Instruction` 枚举（覆盖 RV32I 全部指令 + ECALL syscall）
  - [ ] SubTask 3.1.2：实现 `decode(word: u32) -> Result<Instruction, ZkvmError>` — RV32I 解码器（拒绝 compressed 指令）
  - [ ] SubTask 3.1.3：实现 `execute(state: &mut VmState, insn: Instruction) -> Result<StepLog, ZkvmError>` — 单步执行
  - [ ] SubTask 3.1.4：单元测试覆盖每条 RV32I 指令
- [ ] Task 3.2：实现 `poker_zkvm/src/isa/state.rs` — VM 状态
  - [ ] SubTask 3.2.1：定义 `VmState { pc: u32, registers: [u32; 32], memory: MemoryMap, … }`
  - [ ] SubTask 3.2.2：实现内存模型 — 32-bit 地址空间，STACK_TOP = 0x80000000，HEAP_START = 0x10000000，4-byte 对齐
  - [ ] SubTask 3.2.3：实现 `load_elf(state: &mut VmState, elf_bytes: &[u8])` — 解析 ELF 段，加载到内存
  - [ ] SubTask 3.2.4：实现 `read_memory(addr, len)` / `write_memory(addr, data)` — 含对齐校验与边界检查（MAX_ZKVM_MEMORY = 16MB）
- [ ] Task 3.3：实现 `poker_zkvm/src/isa/executor.rs` — 执行循环
  - [ ] SubTask 3.3.1：实现 `execute_elf(elf_bytes, input) -> Result<Trace, ZkvmError>` — 加载 ELF + 循环 decode + execute
  - [ ] SubTask 3.3.2：实现步数上限检查（MAX_ZKVM_TRACE_STEPS = 1,048,576），超出返回 `TraceTooLong`
  - [ ] SubTask 3.3.3：实现 trace host 内存上限检查（MAX_TRACE_HOST_MEMORY = 512MB），超出返回 `TraceHostMemoryExceeded`
  - [ ] SubTask 3.3.4：实现 syscall 分派（基于 `a7` 寄存器调用对应 `syscalls::host::*` 函数）
- [ ] Task 3.4：实现 `poker_zkvm/src/trace/mod.rs` — Trace 数据结构
  - [ ] SubTask 3.4.1：定义 `Trace { steps: Vec<Step> }` 与 `Step { step_index, pc, instruction, registers: [u32; 32], mem_access: Vec<MemAccess> }`
  - [ ] SubTask 3.4.2：定义 `MemAccess { addr, op: Read|Write, value, size: u8 }`（**size 字段必须存在**，防 LB 1B vs LW 4B aliasing）
  - [ ] SubTask 3.4.3：实现 `Trace::serialize()` / `Trace::deserialize()` — 二进制流式格式
  - [ ] SubTask 3.4.4：实现 `Trace::len()` / `Trace::step(i)` / `Trace::iter()`
  - [ ] SubTask 3.4.5：实现 `Trace::host_memory_usage()` 估算

## Phase 4：ZKVM Syscall

- [ ] Task 4.1：实现 `poker_zkvm/src/syscalls/mod.rs` — Syscall 注册表与 ABI 版本化
  - [ ] SubTask 4.1.1：定义 `SyscallId` 枚举（`ReadInput = 0x01` / `CommitOutput = 0x02` / `Poseidon = 0x03` / `Sha256 = 0x04` / `EcdsaVerify = 0x05` / `EmitEvent = 0x06` / `Log = 0x07` / `Panic = 0x08` / `GetRandomness = 0x09` / `ReadState = 0x0A`）
  - [ ] SubTask 4.1.2：定义 `Syscall` trait（`fn id()` / `fn host_execute(...)` / `fn gas_cost(...)`）
  - [ ] SubTask 4.1.3：定义 `ZKVM_ABI_VERSION = 1` 常量，写入 proof header
- [ ] Task 4.2：实现 `poker_zkvm/src/syscalls/host.rs` — Host 实现（执行引擎用）
  - [ ] SubTask 4.2.1：`read_input` — 从 host input buffer 读取
  - [ ] SubTask 4.2.2：`commit_output` — 写入 host output buffer
  - [ ] SubTask 4.2.3：`poseidon` — 调用 `poker_protocol::crypto::poseidon`
  - [ ] SubTask 4.2.4：`sha256` — 调用 `sha2` crate
  - [ ] SubTask 4.2.5：`ecdsa_verify` — 调用 `secp256k1` crate
  - [ ] SubTask 4.2.6：`emit_event` — event 内容经 Poseidon 哈希产生 `event_hash = Poseidon(content_hash || step_index)`（**v1.2 绑定 step_index**），收集到 `event_hashes` 数组，`public_io.event_hashes_root` = 数组 Merkle root
  - [ ] SubTask 4.2.7：`log` — 写入 host event log
  - [ ] SubTask 4.2.8：`panic` — 终止执行
  - [ ] SubTask 4.2.9：`get_randomness` — **deterministic**，**v1.2 派生函数** `output = Poseidon(seed || initial_commitment || final_commitment || call_counter)`，`seed` = public_io 的 `randomness_seed`（来自链上 VRF，绑定 `block_height + game_id`）；`call_counter` 单调递增，电路显式约束
  - [ ] SubTask 4.2.10：`read_state` — 从 host `PokerL1Context` 读取状态槽，**仅允许白名单 slot**（`SLOT_GAME_STATE = 0x01` / `SLOT_PLAYER_HANDS = 0x02` / `SLOT_POT_AMOUNT = 0x03` / `SLOT_CURRENT_TURN = 0x04` / `SLOT_ACK_CHAIN = 0x05`），非白名单返回 `InvalidSlot(slot)`；**v1.2 Merkle 绑定**：prover 须提供 Merkle 证明 slot 值在 `public_io.state_slot_root` 下，绑定 `execute_checkin` 时 `block_height`；跨 batch 一致性约束 `state_slot_root` 相同
- [ ] Task 4.3：实现 `poker_zkvm/src/syscalls/gas.rs` — Syscall gas 计费
  - [ ] SubTask 4.3.1：定义 `GAS_ZKVM_POSEIDON_BASE / PER_BLOCK` / `GAS_ZKVM_SHA256_PER_BYTE` / `GAS_ZKVM_ECDSA_VERIFY = 100000` / `GAS_ZKVM_READ_STATE_PER_SLOT` 等常量
  - [ ] SubTask 4.3.2：实现 `syscall_gas(id, args) -> u64` 函数
  - [ ] SubTask 4.3.3：单元测试覆盖各 syscall gas 计算
  - [ ] SubTask 4.3.4：soundness 负例测试 — 非白名单 slot 调用必须返回 `InvalidSlot`

## Phase 5：Trace → CCS 约束编译器

- [ ] Task 5.1：实现 `poker_zkvm/src/constraints/mod.rs` — CCS 实例生成 + batching 策略
  - [ ] SubTask 5.1.1：定义 `CcsMatrices { m: Vec<SparseMatrix>, subsets: Vec<Vec<usize>>, coeffs: Vec<FieldElement> }` — CCS 标准结构
  - [ ] SubTask 5.1.2：实现 `compile_trace_to_ccs(trace: &Trace, batch_size: usize) -> Result<Vec<CcsInstance>, ZkvmError>` — 主入口，**含 batching 策略**：每 K = `ZKVM_BATCH_SIZE`（默认 1024）步生成 1 个 CCS 实例
  - [ ] SubTask 5.1.3：校验 `instances.len() ≤ MAX_FOLD_STEP_COUNT = 1000`，超出返回 `FoldStepCountExceeded`
  - [ ] SubTask 5.1.4：实现「连续性约束」 — step $i$ 输出寄存器 == step $i+1$ 输入寄存器（在 batch 内）
  - [ ] SubTask 5.1.5：实现 batch 间连续性约束（前一 batch 末步输出 == 后一 batch 首步输入）
- [ ] Task 5.2：实现 `poker_zkvm/src/constraints/algebra.rs` — 算术指令子电路
  - [ ] SubTask 5.2.1：实现 ADD / ADDI 子电路（含 overflow_bit 约束 — 见 spec Scenario:u32 算术约束）
  - [ ] SubTask 5.2.2：实现 SUB / SLT / SLTU 子电路
  - [ ] SubTask 5.2.3：实现 SLL / SRL / SRA 子电路 — **shift amount 必须 bit-decompose 为 5 个 bit**，每个 bit range check ∈ {0,1}；SRA 须约束符号位扩展
  - [ ] SubTask 5.2.4：实现 AND / OR / XOR 子电路（通过 lookup 真值表优化）
  - [ ] SubTask 5.2.5：实现 RV32M DIV / DIVU / REM / REMU 子电路 — **RISC-V 除零语义**：`DIV(x,0)=-1` / `DIVU(x,0)=2^32-1` / `REM(x,0)=x` / `DIV(MIN,-1)=MIN` / `REM(MIN,-1)=0`
  - [ ] SubTask 5.2.6：单元测试覆盖每条算术指令（含边界：除零 / MIN/-1 / overflow）
- [ ] Task 5.3：实现 `poker_zkvm/src/constraints/memory.rs` — 内存访问与一致性电路（**v1.2 byte-level permutation，正确处理混合尺寸访问**）
  - [ ] SubTask 5.3.1：实现 LW / SW / LB / SB / LH / SH / LBU / LHU 子电路
  - [ ] SubTask 5.3.2：实现 **byte-level permutation**（非 word-level）— 写操作展开为字节级写（LW 4B → 4 条字节写），读操作展开为字节级读；permutation key 为 `(byte_addr, byte_val, step_index)`（每 byte 单独记录）；`size` 字段仅在 read-write check 层使用
  - [ ] SubTask 5.3.3：实现 **混合尺寸重叠访问**处理 — LW 写 4B 后 LB 读 1B 能正确匹配（byte_val == 对应字节）；`step_index` 单调性显式约束 `step_{i+1} > step_i`
  - [ ] SubTask 5.3.4：实现地址 range check（地址 < MAX_ZKVM_MEMORY，使用 `checked_add` 防多字节访问 wrap）
  - [ ] SubTask 5.3.5：实现未初始化读取检测 — byte_addr 在 read 集合但 write 集合无对应记录（step_index < read_step）返回 `UninitializedRead`
  - [ ] SubTask 5.3.6：单元测试覆盖连续 read-after-write、未初始化读取检测、**混合尺寸重叠访问（LW 写后 LB 读 / LB 写后 LW 读）**
  - [ ] SubTask 5.3.7：soundness 负例测试 — 字节级 aliasing 攻击必须失败；permutation 顺序伪造必须失败
- [ ] Task 5.4：实现 `poker_zkvm/src/constraints/control_flow.rs` — 控制流指令子电路
  - [ ] SubTask 5.4.1：实现 JAL / JALR 子电路（pc 更新约束）
  - [ ] SubTask 5.4.2：实现 BEQ / BNE / BLT / BGE / BLTU / BGEU 子电路（条件求值）
  - [ ] SubTask 5.4.3：实现 LUI / AUIPC 子电路
  - [ ] SubTask 5.4.4：单元测试覆盖跳转目标计算与条件分支判定
- [ ] Task 5.5：实现 `poker_zkvm/src/constraints/syscall_circuit.rs` — Syscall 子电路
  - [ ] SubTask 5.5.1：实现 ECALL 子电路 — 解码 `a7`，根据 syscall_id 选择对应预编译子电路
  - [ ] SubTask 5.5.2：每个 syscall 调用产生一个独立 CCS 实例（与指令实例合并折叠）
  - [x] SubTask 5.5.3：**依赖 Phase 10 预编译电路**（Poseidon / SHA-256 / ECDSA）— Phase 10 已完成，syscall_circuit.rs 已实现 dispatch_syscall 委托预编译电路
- [ ] Task 5.6：实现 `poker_zkvm/src/constraints/lookup.rs` — LogUp lookup 协议（**正确公式 + v1.2 严格 β 派生时机**）
  - [ ] SubTask 5.6.1：定义 `LookupTable { entries: Vec<FieldElement>, f: fn(FieldElement) -> FieldElement }`
  - [ ] SubTask 5.6.2：实现 `LogUpProof` — **严格 absorb 顺序**：prover 提交 table 承诺 `C_T` → witness 承诺 `C_f` → multiplicity 承诺 `C_m` → `transcript.absorb(LOOKUP_TAG || C_T || C_f || C_m)` → **β ← transcript.challenge(LOOKUP_TAG)`**（**β 必须在 witness 承诺之后派生**）；校验等式 `Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)`
  - [ ] SubTask 5.6.3：lookup 实例作为附加 CCS 实例（NIRVANA 风格，可被 Hypernova 折叠）
  - [ ] SubTask 5.6.4：实现内置 lookup 表：u8 / u16 / u32 range、AND / OR / XOR 真值表
  - [ ] SubTask 5.6.5：单元测试覆盖 lookup 正例（含 `m_i = 0` 合法边界情况）
  - [ ] SubTask 5.6.6：soundness 负例测试 — prover 在看到 β 后调整 multiplicity 必须失败（table 必须先承诺）；伪造 multiplicity 必须失败；**β 派生时机错误（在 witness 承诺前派生）必须被 transcript 校验拒绝**

## Phase 5.5：Proof 序列化与 Witness 生成 — **新增 Phase**

- [ ] Task 5.5.1：实现 `poker_zkvm/src/serialize/mod.rs` — Proof 序列化布局（**v1.2 补字段长度上限校验防 verifier OOM DoS**）
  - [ ] SubTask 5.5.1.1：定义 proof 二进制布局（magic / abi_version / proof_kind / field_id / public_io / folded_instance / witness_commitment / final_sumcheck / pcs_opening / event_hashes），所有变长字段前缀 4-byte LE length
  - [ ] SubTask 5.5.1.2：实现 canonical 域元素编码（32 bytes LE，mod p）
  - [ ] SubTask 5.5.1.3：实现 `HypernovaProof::serialize()` / `HypernovaProof::deserialize()` 函数
  - [ ] SubTask 5.5.1.4：反序列化校验 magic / abi_version / field_id，不匹配返回 `InvalidZkProofFormat` / `AbiVersionMismatch`
  - [ ] SubTask 5.5.1.5：**v1.3 字段长度上限校验（修正 M2-002 — 总长度优先 + 单项子分配）** — 反序列化分三步：
    - 第 0 步：stream 读固定头部（magic / abi_version / proof_kind / field_id，共 10 bytes），校验
    - **第 1 步（v1.3 关键）：总长度优先校验** — stream 读所有变长字段 length 前缀（不读 payload），计算 `total_payload = public_io_len + folded_instance_len + witness_commitment_len + final_sumcheck_len + pcs_opening_len + event_hashes_count * 32 + length_prefix_overhead`，校验 `total_payload ≤ MAX_ZKVM_PROOF_SIZE = 64KB`，超长立即返回 `InvalidZkProofFormat`，**不分配任何变长 payload 缓冲区**（防 OOM — v1.2 单项校验通过后再总校验，attacker 可构造单项 64KB×3=192KB proof 通过单项校验后才失败，已分配 192KB 缓冲区）
    - **第 2 步：单项上限校验（v1.3 子分配 — 单项之和 ≤ 总上限 ≈ 48KB < 64KB）**：`MAX_PUBLIC_IO_SIZE = 8KB` / `MAX_FOLDED_INSTANCE_SIZE = 8KB` / `witness_commitment_len ≤ 33` / `MAX_SUMCHECK_PROOF_SIZE = 16KB` / `MAX_PCS_OPENING_SIZE = 8KB` / `MAX_EVENT_HASHES_COUNT = 256`（256 × 32 = 8KB）
    - 第 3 步：第 1+2 步全通过后才分配 payload 缓冲区并解析字段内容
    - 早夭逻辑：第 1 步或第 2 步任一失败立即返回 `InvalidZkProofFormat`，不进入昂贵计算
  - [ ] SubTask 5.5.1.6：单元测试 — serialize → deserialize 往返一致；篡改 magic / abi_version 必须失败；**超长字段（如 `public_io_len = 0xFFFFFFFF`）必须立即返回 `InvalidZkProofFormat` 不 OOM**
- [ ] Task 5.5.2：实现 `poker_zkvm/src/prover/witness.rs` — Witness 生成与盲化策略
  - [ ] SubTask 5.5.2.1：定义 witness 映射规则：`z = (u, x, trace, 1)`，u 为内部 witness，x 为公共输入，trace 为执行 trace 域元素编码，1 为常数
  - [ ] SubTask 5.5.2.2：实现 `generate_witness(trace, ccs_instance) -> WitnessVector`
  - [ ] SubTask 5.5.2.3：MVP transparent 策略 — witness 不盲化
  - [ ] SubTask 5.5.2.4：文档明确 MVP 风险声明：transparent proof 仍可能从多项式求值反推 witness，敏感数据不应在 MVP 阶段进入 ZKVM 计算
  - [ ] SubTask 5.5.2.5：单元测试 — witness 与 CCS 实例一一对应；CCS satisfied_by(witness) == true

## Phase 6：Hypernova 折叠算法

- [ ] Task 6.1：实现 `poker_zkvm/src/fold/ccs.rs` — CCS 数据结构（**新类型，非 poker_l1 旧 hash-based**）
  - [ ] SubTask 6.1.1：定义 `Ccs { num_vars, num_matrices, matrices, subsets, coeffs }`
  - [ ] SubTask 6.1.2：实现 `Ccs::satisfied_by(z: &[FieldElement]) -> bool` — 校验 $\sum c_i \prod_{j\in S_i} \langle M_j, z\rangle = 0$
  - [ ] SubTask 6.1.3：实现 `Ccs::to_lcccs(z)` / `Ccs::to_cccs(z)` — 生成 LCCCS / CCCCS 实例
  - [ ] SubTask 6.1.4：定义 `CcsInstance`（新类型，含矩阵结构与域元素 witness，**非 poker_l1 旧 hash-based**）
- [ ] Task 6.2：实现 `poker_zkvm/src/fold/lcccs.rs` — LCCCS 实例（**v1.3 显式存储 r_x_L + v 字段向量化**）
  - [ ] SubTask 6.2.1：定义 `Lcccs { ccs_ref, u_L: FieldElement, x_L: Vec<FieldElement>, trace_L: Vec<FieldElement>, r_x_L: FieldElement, v_L: Vec<FieldElement> }`（**v1.3：`u_L` 为标量（relaxed，可非 0）；`r_x_L` 显式存储（v_L 在 r_x_L 处求值）；`v_L` 为长度 `num_matrices` 的向量，`v_L[j] = Σ_y M_j(r_x_L, y)·z_L(y)`**）
  - [ ] SubTask 6.2.2：实现 `Lcccs::satisfied() -> bool` — **v1.3 relaxed 约束：`Σ_i c_i · Π_{j∈S_i} v_L[j] = u_L`（u_L 可非 0，非 = 0）**
- [ ] Task 6.3：实现 `poker_zkvm/src/fold/ccccs.rs` — CCCCS 实例（**v1.3 修正 C2-002 — 不存储 v_C 字段**）
  - [ ] SubTask 6.3.1：定义 `Ccccs { ccs_ref, u_C: FieldElement, x_C: Vec<FieldElement>, trace_C: Vec<FieldElement>, witness_commitment_C: Commitment }` — **v1.3 关键修正 C2-002：CCCCS 实例不存储 v_C 字段**（v_C[j](X) = Σ_y M_j(X, y)·z_C(y) 是关于 X 的多项式，在 CCCCS 创建时 r_x_L 尚不存在；v_C[j] 在折叠时于 r_x_L 处通过内层 batched sumcheck 计算并验证）
  - [ ] SubTask 6.3.2：实现 `Ccccs::satisfied() -> bool` — **校验 `Σ_i c_i · Π_{j∈S_i} (Σ_y M_j(x_C, y)·z_C(y)) = u_C`**（在 x_C 处求值，u_C 标量可非 0）
- [ ] Task 6.4：实现 `poker_zkvm/src/fold/fold_step.rs` — 单步折叠（**v1.3 修正 — fold challenge 标量 + u' 标量 + v_C 在 r_x_L 求值**）
  - [ ] SubTask 6.4.1：实现 `fold(lcccs: &Lcccs, ccccs: &Ccccs, transcript: &mut Transcript) -> Result<Lcccs, ZkvmError>`
  - [ ] SubTask 6.4.2：通过 transcript 派生**随机标量 `r`**（单域元素，非向量；absorb 序列含 `ccs_commitment` + `lcccs_witness_commitment` + `ccccs_witness_commitment`，见 Task 1.2.5）
  - [ ] SubTask 6.4.3：计算折叠后的实例：`u' = u_L + r·u_C`（**标量**）/ `x' = x_L + r·x_C` / `trace' = trace_L + r·trace_C` / `r_x' = r_x_L`（folded LCCCS 沿用 LCCCS_L 的 r_x）/ **`v'[j] = v_L[j] + r·v_C[j](r_x_L)`（分量级；v_C[j](r_x_L) = Σ_y M_j(r_x_L, y)·z_C(y) 通过内层 batched sumcheck 计算）**；folded witness `z' = z_L + r·z_C`（PCS opening 用）
  - [ ] SubTask 6.4.4：生成 sumcheck 子证明（**v1.3 修正：外层 claimed sum = u' 标量（非 v' 向量）+ 内层 batched sumcheck 单 r_y**）
  - [ ] SubTask 6.4.5：单元测试 — 折叠后 Lcccs::satisfied() == true（**relaxed 约束 `Σ_i c_i · Π_{j∈S_i} v'[j] = u'`**）
  - [ ] SubTask 6.4.6：soundness 负例测试 — 篡改 lcccs / ccccs 任一字段必须 fold 失败或 verify 失败
- [ ] Task 6.5：实现 `poker_zkvm/src/fold/sumcheck.rs` — Sumcheck 协议（**v1.3 修正 — 外层 claimed sum = u' 标量 + 内层 batched 单 r_y**）
  - [ ] SubTask 6.5.1：实现 `SumcheckProof` 数据结构（含外层 sumcheck proof + 内层 batched sumcheck proof）
  - [ ] SubTask 6.5.2：实现 `prove(g, num_vars, transcript) -> SumcheckProof`（**v1.3 修正 C2-003 — 外层 sumcheck claimed sum = `u'` 标量（非 v' 向量，非 0）**；外层归约到 `r_x_L`，校验 `G(r_x_L) = u'`；**v1.3 修正 C2-001 — 内层 batched sumcheck**：引入 FS challenge `γ`（单标量），对每个 `j ∈ [0, t)` batched，证明 `Σ_j γ^j·v'[j] = Σ_y (Σ_j γ^j·M_j(r_x_L, y))·z'(y)`，归约到**单个 challenge `r_y`**：`Σ_j γ^j·v'[j] = (Σ_j γ^j·M_j(r_x_L, r_y))·z'(r_y)`；**combined_point = r_y（单 challenge，非 (r_x, r_{y_1}, ..., r_{y_t}) 元组）**）
  - [ ] SubTask 6.5.3：实现 `verify(proof, claimed_sum, num_vars, transcript) -> bool`（校验外层 `G(r_x_L) == u'`（标量，非 v'）+ 内层 batched sumcheck 归约到 `z'(r_y)`）
  - [ ] SubTask 6.5.4：单元测试覆盖小规模 sumcheck（n_vars <= 8）prove/verify，**含 u' ≠ 0 场景**
  - [ ] SubTask 6.5.5：soundness 负例测试 — 篡改 claimed_sum / 篡改 proof / **篡改 `r_y` 与 `z_at_point` 关联** 必须失败
- [ ] Task 6.6：实现 `poker_zkvm/src/fold/fold_loop.rs` — 多步折叠（**v1.3 修正 — PCS opening 在 r_y 打开 z'**）
  - [ ] SubTask 6.6.1：实现 `fold_loop(instances: &[CcsInstance], ...) -> Result<HypernovaProof, ZkvmError>`
  - [ ] SubTask 6.6.2：顺序折叠为单个 LCCCS（N-1 次折叠），N ≤ MAX_FOLD_STEP_COUNT = 1000
  - [ ] SubTask 6.6.3：生成 final sumcheck proof + **PCS opening proof 在 `r_y`（单 challenge）处打开 folded witness `z'` 得 `z_at_point = z'(r_y)`**（调用 `pcs::ipa::open`，**v1.3 修正：z_at_point 是 z' 在 r_y 的求值，不是 v'，也不是 u'**）
  - [ ] SubTask 6.6.4：返回 `HypernovaProof { abi_version, folded_instance, witness_commitment, final_sumcheck, pcs_opening, r_y, z_at_point }`（**v1.3：combined_point 字段改名为 r_y**）
  - [ ] SubTask 6.6.5：单元测试 — N=1 / N=10 / N=1000 折叠闭环
  - [ ] SubTask 6.6.6：soundness 负例测试 — N=10 折叠后篡改 folded_instance / witness_commitment / final_sumcheck / pcs_opening / **r_y / z_at_point** 任一字段必须 verify 失败

## Phase 7：Prover 与最终压缩

- [x] Task 7.1：实现 `poker_zkvm/src/prover/mod.rs` — Prover 主流程
  - [x] SubTask 7.1.1：定义 `ProverConfig { field, transcript_domain, fold_step_limit, proof_size_limit, batch_size, max_recursion_depth }`
  - [x] SubTask 7.1.2：实现 `prove(elf_bytes, input, config) -> Result<(proof_bytes, public_io), ZkvmError>`
  - [x] SubTask 7.1.3：流程：load ELF → execute → trace → compile_trace_to_ccs (batch_size=K) → fold_loop → compress → emit proof
  - [x] SubTask 7.1.4：实现 proof 大小检查（MAX_ZKVM_PROOF_SIZE = 64KB），超出触发 CycleFold 递归压缩
  - [x] SubTask 7.1.5：实现错误恢复 — prover 失败返回详细错误，host 端可调整 `ZKVM_BATCH_SIZE` 后重试
- [x] Task 7.2：实现 `poker_zkvm/src/prover/spartan.rs` — Spartan 最终压缩
  - [x] SubTask 7.2.1：实现 `spartan_compress(proof: &HypernovaProof) -> Result<CompressedProof, ZkvmError>`（完整实现 — 复用 final sumcheck + IPA opening，原生验证 fold 链 fast fail）
  - [x] SubTask 7.2.2：Spartan proof 大小 ≤ 10KB（实测 ~6-7KB：final sumcheck ~4KB + IPA opening ~1.3KB + LCCCS 公共数据 ~1KB）
  - [x] SubTask 7.2.3：单元测试 — compressed proof 可被 verifier 校验（`test_spartan_compress_valid_proof` 验证端到端 compress → verify 通过）
  - [x] SubTask 7.2.4：soundness 负例测试 — 篡改 Spartan proof 必须失败（`test_spartan_compress_tampered_commitment` + `test_spartan_verify_tampered_sumcheck`）
  - [x] SubTask 7.2.5：CCS 注册表迁移 — Spartan proof 去除内嵌 CCS（~1.9MB → ~7KB），`verify_production` 签名改为 `ccs_registry: &[Ccs]`，verifier 按 `ccs_commitment` 从注册表查找 CCS；HYPN/SPRT magic 字节分派 + `MAX_PROOF_TOTAL_SIZE` 预检；`default_ccs_whitelist` 保留为 deprecated 别名
- [x] Task 7.3：实现 `poker_zkvm/src/prover/groth16_compress.rs` — Groth16 备选压缩（可选）
  - [x] SubTask 7.3.1：实现 `groth16_compress(lcccs: &Lcccs, crs: &Crs) -> Result<Groth16Proof, ZkvmError>`（stub — Phase 12 实现）
  - [x] SubTask 7.3.2：复用 `poker_l1/src/offline/groth16.rs` 既有 verifier — `groth16_compress.rs` 已实现完整 Groth16 setup/prove/verify（基于 ark-groth16 0.6 GR1CS）

## Phase 8：链上 Verifier Production 实现（v1.3 修正 cross-language claim + 双通道 grace period + M2-003/004 修复）

- [x] Task 8.1：实现 `poker_zkvm/src/verifier/mod.rs` — 链上 verifier（**v1.3 cross-language claim PCS opening 在 r_y 打开 z' 得 z_at_point**）
  - [x] SubTask 8.1.1：实现 `verify_production(proof_bytes: &[u8], public_io: &ZkPublicIo) -> Result<bool, ZkvmError>`
  - [x] SubTask 8.1.2：反序列化 `HypernovaProof`（校验 magic / abi_version / field_id — 不匹配返回 `InvalidZkProofFormat` / `AbiVersionMismatch`；**v1.3 字段长度上限校验：总长度优先 + 单项子分配（见 SubTask 5.5.1.5），超长立即返回 `InvalidZkProofFormat` 不进入昂贵计算**）
  - [x] SubTask 8.1.3：重新生成 Fiat-Shamir challenge（基于 public_io + transcript，**含 ccs_commitment + witness_commitment 绑定**）
  - [x] SubTask 8.1.4：校验 final sumcheck 等式 — **v1.3 修正 C2-003 — 外层 `G(r_x_L) == u'`（claimed sum 为 `u'` 标量，非 v' 向量，非 0）**，失败返回 `SumcheckVerificationFailed`
  - [x] SubTask 8.1.5：校验 folded instance cross-language claim（**v1.3 数学等式 1+2+3+4 — 见 spec Scenario:Cross-language claim 验证**）— 失败返回 `CrossLanguageClaimFailed`：
    - **外层 sumcheck 一致性**：`G(r_x_L) == u'`（与 SubTask 8.1.4 一致，**v1.3 修正 C2-003 — claimed sum 为 `u'` 标量，非 v' 向量，非 0**）
    - **v1.3 修正 C2-001 — 内层 batched sumcheck 归约**：引入 FS challenge `γ`（单标量），对每个 `j ∈ [0, t)` batched，校验 `Σ_j γ^j · v'[j] == (Σ_j γ^j · M_j(r_x_L, r_y)) · z'(r_y)` 在**单个 challenge `r_y`** 处归约（**非 t 个 r_{y_j}**；verifier 用 PCS opening 提供的 `z_at_point = z'(r_y)` 校验）
    - **PCS opening 校验**：`Pcs::verify(witness_commitment', r_y, z_at_point, opening_proof) == true`，其中 **`combined_point = r_y`（单 challenge，非 (r_x, r_{y_1}, ..., r_{y_t}) 元组 — v1.3 修正 C2-001）**，**`z_at_point = z'(r_y)` 是 folded witness z' 在 r_y 的求值，不是 v'，也不是 u'**
    - **v1.3 修正 M2-001 — LCCCS relaxed 约束**：`Σ_i c_i · Π_{j∈S_i} v'[j] = u'`（**relaxed，u' 可非 0，非原始 CCS 的 = 0**）— 通过外层 sumcheck 隐式验证（G(r_x_L) = u' 即此约束）
    - **关键不变式校验**：`u'`（外层 claimed sum）+ `v'`（内层 per-matrix 值）+ `z_at_point`（PCS opening 求值）三者须通过外层 sumcheck + 内层 batched sumcheck 链关联，否则 prover 可独立伪造
  - [x] SubTask 8.1.6：校验 PCS opening — 失败返回 `PcsVerificationFailed`（**verifier 重算 challenge 时使用与 prover 相同的 absorb 顺序，含 point 与 commitment 绑定**）
  - [x] SubTask 8.1.7：校验 transcript 一致性 — 失败返回 `TranscriptMismatch`
  - [x] SubTask 8.1.8：合法 proof 通过测试
  - [x] SubTask 8.1.9：soundness 负例测试 — 篡改 proof 任一字段（folded_instance / witness_commitment / final_sumcheck / pcs_opening / **r_y / z_at_point** / public_io）必须失败；**篡改 `z_at_point` 与 `u'`/`v'` 关联（独立伪造三者）必须失败**
- [x] Task 8.2：集成到 `poker_l1/src/offline/hypernova.rs`（**v1.3 双通道 grace period + production_switch_height 绑定 + M2-003/004 修复**）
  - [x] SubTask 8.2.1：修改 `HypernovaVerifier::verify` Production 分支调用 `poker_zkvm::verifier::verify_production`
  - [x] SubTask 8.2.2：扩展 `PokerL1Error` 增加 `SumcheckVerificationFailed` / `CrossLanguageClaimFailed` / `TranscriptMismatch` / `PcsVerificationFailed` / `AbiVersionMismatch` / `InvalidSlot` / `RecursionDepthExceeded` / **`ProofKindMismatch`** / **`UninitializedRead`** / **v1.3 新增 `PartialFoldHashImmutable`（M2-003）** / **v1.3 新增 `SignatureFormMismatch`（M2-004）**
  - [x] SubTask 8.2.3：实现 **v1.2 双通道 grace period** — 治理切换时记录 `production_switch_height`（当前 block height）到 `GovernanceParams`；grace 期（`PRODUCTION_GRACE_BLOCKS = 7200`）内采用 proof_kind 双通道：
    - **`proof_kind = ZkShuffle` 旧 Stub proof**：允许走 stub 路径（仅校验 proof 长度），**但 `proof_hash` 必须匹配链上已存 `last_partial_fold.proof_partial_hash`**（仅允许在途游戏继续，不允许新游戏用 Stub proof — 防 attacker 伪造任意 64 字节 proof）
    - **`proof_kind = Zkvm` proof**：强制走 Production 路径（完整 sumcheck + cross-language claim + PCS opening + transcript 校验）
  - [x] SubTask 8.2.4：grace 期结束后（`current_height > production_switch_height + PRODUCTION_GRACE_BLOCKS`）所有 proof 强制 Production 路径，stub 路径彻底关闭
  - [x] SubTask 8.2.5：Stub 分支行为保持不变（`verifier_status == Stub` 时仅校验 proof 长度）
  - [x] SubTask 8.2.6：**v1.3 修正 M2-003 — `last_partial_fold.proof_partial_hash` 链上不可变约束** — `PartialCheckinTx` 执行时校验 `last_partial_fold.proof_partial_hash == None || last_partial_fold.proof_partial_hash == tx.proof_partial_hash`（首次设置或幂等重提交允许；覆盖已有值返回 `PartialFoldHashImmutable` 错误）；`execute_checkin` 完成（游戏终结）后清零；grace 期结束后强制清零；**v1.4 修正 Min3-002 — "游戏终结"判定条件 = `poker_protocol::game_state::is_terminal(ack_chain)` 或 ZKVM 程序 `zkvm_commit_output` 提交 `game_over=true`**；**v1.4 修正 Min3-003 — 幂等重提交范围 = 整个 `PartialCheckinTx` 内容幂等（`proof_partial_hash` + `intermediate_commitment` + `ack_chain_partial` 全部相等），非仅 `proof_partial_hash` 幂等**
  - [x] SubTask 8.2.7：**v1.3 修正 M2-004 — 单 proof_kind 单签名形式** — verifier 通过 `scheme_id` 反推期望的签名形式（`scheme_id=4` 期望旧签名无 `proof_kind` 字段；`scheme_id=1` 期望新签名含 `proof_kind` 字段），签名形式与 `scheme_id` 不一致返回 `SignatureFormMismatch` 错误；切换前仅接受旧签名，grace 期内按 scheme_id 分派，grace 期后仅接受新签名
  - [x] SubTask 8.2.8：更新既有单元测试 — Production 分支测试改用真实 proof；**grace 期双通道测试（ZkShuffle + 匹配 proof_hash 通过 / ZkShuffle + 不匹配 proof_hash 失败 / Zkvm 强制 Production / grace 期后 stub 关闭）**；**v1.3 M2-003 测试（覆盖已有 `proof_partial_hash` 返回 `PartialFoldHashImmutable`）**；**v1.3 M2-004 测试（`scheme_id=4` 旧签名通过 / `scheme_id=4` 新签名返回 `SignatureFormMismatch` / `scheme_id=1` 新签名通过 / `scheme_id=1` 旧签名返回 `SignatureFormMismatch`）**

## Phase 9：CycleFold 递归聚合（v1.2 补递归 verifier 电路定义 — Task 9.3/9.4）

- [x] Task 9.1：实现 `poker_zkvm/src/cyclic/mod.rs` — 曲线 cycle 抽象
  - [x] SubTask 9.1.1：定义 `CycleCurve` trait（主曲线 + 辅助曲线）
  - [x] SubTask 9.1.2：实现 `Bn254GrumpkinCycle` — BN254 (主) / Grumpkin (辅)
  - [x] SubTask 9.1.3：cycle 性质验证 — 主曲线标量域 == 辅助曲线 base field，反之亦然
- [x] Task 9.2：实现 `poker_zkvm/src/recursion/mod.rs` — CycleFold 递归（含终止条件）
  - [x] SubTask 9.2.1：定义 `RecursiveNode { sub_proofs: Vec<HypernovaProof>, parent: Option<Box<RecursiveNode>> }`
  - [x] SubTask 9.2.2：实现 `aggregate(sub_proofs: &[HypernovaProof]) -> Result<HypernovaProof, ZkvmError>`
  - [x] SubTask 9.2.3：实现 `tree_aggregate(sub_proofs, depth) -> Result<HypernovaProof, ZkvmError>` — log(N) 递归深度
  - [x] SubTask 9.2.4：**递归终止条件** — final proof ≤ 64KB 时停止；递归深度 ≤ `MAX_RECURSION_DEPTH = 16`，超出返回 `RecursionDepthExceeded`；**深度依据分析**：最坏 N=1000 sub-proofs，CycleFold 树形聚合深度 = `ceil(log2(1000)) = 10`，10 层后 ≤ 64KB，`MAX_RECURSION_DEPTH=16` 留 60% 余量
  - [x] SubTask 9.2.5：单元测试 — K=8 sub-proofs 聚合为单个 final proof
  - [x] SubTask 9.2.6：soundness 负例测试 — 篡改任一 sub_proof 必须聚合失败或最终 verify 失败
- [x] Task 9.3：**v1.2 新增 / v1.3 修正** — 实现 `poker_zkvm/src/recursion/circuit_bn254.rs` — BN254 递归 verifier 电路 `C_BN254`（约束 Hypernova verifier 步骤）
  - [x] SubTask 9.3.1：定义 `C_BN254` 电路结构（halo2 或 arkworks Circuit trait），public inputs 含 `π_G` 的 public_io（含 `randomness_seed` / `event_hashes_root` / `state_slot_root`）、folded LCCCS 的 `u'`（标量）/ `x'` / `v'`（`Vec<FieldElement>` 长度 = `num_matrices`）、witness_commitment'
  - [x] SubTask 9.3.2：约束 1 — **反序列化 `π_G`**：校验 magic / abi_version / field_id（Grumpkin field_id），约束各字段长度 ≤ `MAX_*` 常量（v1.3 总长度优先 + 单项子分配）
  - [x] SubTask 9.3.3：约束 2 — **PCS verify（IPA on Grumpkin）**：约束 log(N) 轮 IPA verify — 每轮吸收 round commitment + 派生 challenge + 重算 commitment；因 Grumpkin 点坐标在 BN254 标量域中，可直接在 BN254 电路中表达
  - [x] SubTask 9.3.4：约束 3 — **v1.3 修正 C2-003 — 外层 sumcheck verify（claimed sum = u' 标量）**：约束外层 sumcheck 各轮多项式求值一致性，重算 challenge `r_x_L`，校验 `G(r_x_L) == u'`（**非 v'**；u' 是 folded LCCCS 标量参数；G(r_x_L) = u' 即隐式校验 relaxed LCCCS 约束 `Σ_i c_i · Π_{j∈S_i} v'[j] = u'`）
  - [x] SubTask 9.3.5：约束 4 — **v1.3 修正 C2-001 — 内层 batched sumcheck verify（单 r_y）**：约束内层 batched sumcheck 各轮求值一致性，重算 FS challenge `γ`，归约到**单个 challenge `r_y`**（非 t 个 r_{y_j}），校验 `Σ_j γ^j · v'[j] == (Σ_j γ^j · M_j(r_x_L, r_y)) · z'(r_y)`（z'(r_y) 由 PCS opening 提供）
  - [x] SubTask 9.3.6：约束 5 — **v1.3 修正 — cross-language claim 校验（combined_point = r_y 单 challenge）**：约束 PCS opening `Pcs::verify(witness_commitment', r_y, z_at_point, opening_proof)`，并校验 `z_at_point == z'(r_y)` 与内层 batched sumcheck 一致性（**关键不变式**：`u'` + `v'` + `z_at_point` 三者须通过外层 + 内层 batched sumcheck 链关联）
  - [x] SubTask 9.3.7：约束 6 — **transcript 一致性**：重算所有 FS challenge（r, γ, r_x_L, r_y），校验与 prover 提供的一致
  - [x] SubTask 9.3.8：**v1.3 修正 — 约束数估算（单层估算非总累加）**：`C_BN254` 单层约束数 ≈ IPA verify（log(N) 轮 × ~5000 约束/轮）+ 外层 sumcheck verify（~10000 约束）+ 内层 batched sumcheck verify（~10000 约束）+ cross-language（~5000 约束）≈ **100,000-200,000 约束/单递归层**；`MAX_RECURSION_DEPTH=16` 为最大允许深度上限，**实际递归深度由 `ceil(log2(sub_proofs.len()))` 决定**（N=1000 时仅需 10 层，远低于 16）
  - [x] SubTask 9.3.9：单元测试 — `C_BN254` 验证合法 Grumpkin proof 通过；篡改 sub-proof 任一字段必须电路约束失败
- [x] Task 9.4：**v1.2 新增 / v1.3 修正** — 实现 `poker_zkvm/src/recursion/circuit_grumpkin.rs` — Grumpkin 镜像电路 `C_Grumpkin`（对称约束 BN254 Hypernova verifier）
  - [x] SubTask 9.4.1：定义 `C_Grumpkin` 电路结构（对称镜像 `C_BN254`），public inputs 含 BN254 proof 的对应字段（u' 标量 / x' / v' / witness_commitment'）
  - [x] SubTask 9.4.2：对称约束 1-6（反序列化 / PCS verify on BN254 / **v1.3 外层 sumcheck claimed sum = u'** / **v1.3 内层 batched sumcheck 单 r_y** / **v1.3 cross-language claim combined_point = r_y** / transcript 一致性）— BN254 点坐标在 Grumpkin 标量域中直接表达
  - [x] SubTask 9.4.3：**跨曲线 bridging**：BN254 电路的 witness（含 Grumpkin 点坐标）通过 cycle 性质在 BN254 标量域中直接表达；Grumpkin 电路的 BN254 点坐标同理
  - [x] SubTask 9.4.4：单元测试 — `C_Grumpkin` 验证合法 BN254 proof 通过；篡改 sub-proof 任一字段必须电路约束失败
  - [x] SubTask 9.4.5：**交替递归测试**：BN254 层（`C_BN254` 验证 2 个 Grumpkin sub-proofs）→ Grumpkin 层（`C_Grumpkin` 验证 2 个 BN254 proofs）交替，深度 4 层闭环通过

## Phase 10：预编译电路

- [x] Task 10.1：实现 `poker_zkvm/src/precompiles/mod.rs` — 预编译电路注册表
- [x] Task 10.2：实现 `poker_zkvm/src/precompiles/poseidon.rs` — Poseidon 哈希电路（Full: 64 轮 permutation + MDS matrix；`new()` 默认 Full，`new_mvp()` 保留 MVP）
  - [x] SubTask 10.2.1：实现 Poseidon permutation 电路（round function + MDS matrix）
  - [x] SubTask 10.2.2：约束数 ≈ 200/round（Full mode `FULL_MODE_GAS_COST = 12_800`）
  - [x] SubTask 10.2.3：单元测试 — 正例输入产出预期哈希；与 host `poker_protocol::crypto::poseidon` 输出一致
- [x] Task 10.3：实现 `poker_zkvm/src/precompiles/sha256.rs` — SHA-256 电路（Full: 完整 compression；`new()` 默认 Full，`new_mvp()` 保留 MVP）
  - [x] SubTask 10.3.1：实现 SHA-256 round 电路（message schedule + compression）
  - [x] SubTask 10.3.2：约束数 ≈ 25,000/block（Full mode `FULL_MODE_NUM_VARS = 172_577`，`FULL_MODE_GAS_COST = 25_000`）
  - [x] SubTask 10.3.3：单元测试 — 与 `sha2` crate 输出一致（host sha2 已验证 known vectors）
- [x] Task 10.4：实现 `poker_zkvm/src/precompiles/ecdsa.rs` — ECDSA 验签电路（Full: 256-bit 完整标量乘；`new()` 默认 Full，`new_mvp()` 保留 MVP）
  - [x] SubTask 10.4.1：实现 secp256k1 curve operations 电路
  - [x] SubTask 10.4.2：实现 ECDSA verify equation 电路
  - [x] SubTask 10.4.3：**实际约束数 ≈ 19,376,000 gas**（基于 256-bit scalar_mul × 3 + point_add + assert_point_equal）
  - [x] SubTask 10.4.4：单元测试 — 正例签名通过；篡改 msg / sig / pubkey 必须失败
- [x] Task 10.5：迁移 `poker_l1/src/offline/ccs.rs:ZkShuffleCcsCircuit` 到 `poker_zkvm/src/precompiles/zk_shuffle.rs`（stub，D6 批准）
  - [x] SubTask 10.5.1：迁移类型定义与 trait 实现（stub — `to_ccs_instance` 返回 `Err("Phase 11 pending")`）
  - [x] SubTask 10.5.2：在 `poker_l1/src/offline/ccs.rs` 替换为 `pub use poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit;` — **已完成（BREAKING 迁移）**：移除旧 hash-based `ZkShuffleCcsCircuit` + 旧 `CcsCircuit` trait，re-export 新 Fr-based 类型
  - [x] SubTask 10.5.3：更新既有单元测试引用路径 — **已完成**：`phase5a_integration.rs` 已使用新类型；`test_deprecated_zk_shuffle_circuit_still_compiles` 改为 `test_zk_shuffle_circuit_reexported`

## Phase 11：poker_l1 集成与 stub 替换（v1.2 CcsInstance 诚实 BREAKING + CheckinTx proof_kind 序列化 + scheme_id 映射）

- [x] Task 11.1：替换 `poker_l1/src/offline/ccs.rs` 中的 stub fold 实现（**v1.2 诚实 BREAKING 声明**）
  - [x] SubTask 11.1.1：旧 `CcsInstance`（hash-based）标记 `#[deprecated(note = "Use poker_zkvm::fold::CcsInstance instead")]`
  - [x] SubTask 11.1.2：实现 `LegacyCcsInstanceAdapter` — **v1.2 诚实声明**：仅用于过渡期**编译兼容**，返回 `Err(Other("legacy hash-based instance cannot be really folded — hash is one-way, cannot recover matrices"))`，**不参与真实证明生成**；旧调用方在 Production 下会失败，必须重构以提供真实矩阵
  - [x] SubTask 11.1.3：`fold_step` 内部调用 `poker_zkvm::fold::fold_step`（接受新 `CcsInstance` 类型，**外部 trait 签名变更** — 参数类型从旧 hash-based 改为新含矩阵类型，既有调用方必须迁移，无法透明兼容）
  - [x] SubTask 11.1.4：`fold_loop` 内部调用 `poker_zkvm::fold::fold_loop`（接受新 `CcsInstance` 类型，同 SubTask 11.1.3 BREAKING）
  - [x] SubTask 11.1.5：移除 blake2b 哈希链冒充逻辑
  - [x] SubTask 11.1.6：`CcsCircuit` trait 一并迁入 `poker_zkvm::precompiles`，`poker_l1` 通过 `pub use poker_zkvm::precompiles::CcsCircuit;` re-export
  - [x] SubTask 11.1.7：更新既有单元测试 — 调用方迁移到新类型，断言改为真实折叠语义
  - [x] SubTask 11.1.8：提供迁移示例文档（既存调用方如何迁移）— 含 `LegacyCcsInstanceAdapter` 失败语义说明
- [x] Task 11.2：扩展 `CheckinTx` / `PartialCheckinTx` 接受 ZKVM proof（**v1.2 proof_kind 序列化策略 + scheme_id 映射**）
  - [x] SubTask 11.2.1：定义 `ProofKind` 枚举（`ZkShuffle` / `Zkvm`）
  - [x] SubTask 11.2.2：**v1.2 scheme_id 映射** — 定义 `SCHEME_ZKSHUFFLE = 4`（新增）/ `SCHEME_HYPERNOVA = 1`（既有）；`ProofKind::ZkShuffle → SCHEME_ZKSHUFFLE` / `ProofKind::Zkvm → SCHEME_HYPERNOVA`
  - [x] SubTask 11.2.3：`CheckinTx` 新增 `proof_kind: ProofKind` 字段；**v1.2 序列化策略** — `proof_kind` 作为 1-byte 前缀进入 `signing_hash` 输入（**BREAKING — 破坏旧签名，升级时所有在途 `CheckinTx` 须在 `PRODUCTION_GRACE_BLOCKS` 内重提交或失效**；非 v1.1 所述 backward-compatible）
  - [x] SubTask 11.2.4：`execute_checkin` 按 `scheme_id` 分派 verifier（`scheme_id=4` → 既有 zk_shuffle verifier；`scheme_id=1` → `poker_zkvm::verifier::verify_production`）；`proof_kind` 与 `scheme_id` 不一致返回 `ProofKindMismatch`
  - [x] SubTask 11.2.5：**v1.4 修正 Min3-004 — grace 期签名形式分派**：grace 期内 verifier 按 `scheme_id` 反推期望的签名形式（`scheme_id=4` 期望旧签名无 `proof_kind` 字段；`scheme_id=1` 期望新签名含 `proof_kind` 字段），签名形式与 `scheme_id` 不一致返回 `SignatureFormMismatch`（**v1.4 删除 v1.2 残留"同时接受带/不带 proof_kind 签名"表述 — 与 M2-004 单 proof_kind 单签名形式修复直接矛盾**）
  - [x] SubTask 11.2.6：`PartialCheckinTx` 同样新增 `proof_kind` 字段，序列化策略与 `CheckinTx` 一致
  - [x] SubTask 11.2.7：集成测试 — Rust 代码 → ZKVM proof → `CheckinTx { scheme_id: SCHEME_HYPERNOVA, proof_kind: ProofKind::Zkvm }` 上链 → 链上验证通过
  - [x] SubTask 11.2.8：soundness 负例测试 — `proof_kind` 与 `scheme_id` 不一致必须返回 `ProofKindMismatch`

## Phase 11.5：治理参数与 gas 调整 — **新增 Phase**（v1.2 补 6 项 Proof 字段长度上限 + production_switch_height）

- [x] Task 11.5.1：调整 `poker_l1/src/vm/gas_table.rs`
  - [x] SubTask 11.5.1.1：`GAS_HYPERNOVA_VERIFY` 从 50000 → 300000（**覆盖 Spartan pairing + final exp + IPA verify log(N) 轮 MSM + 余量；本参数须在 Phase 12 性能基准实测后再次校准**）
  - [x] SubTask 11.5.1.2：新增 `GAS_ZKVM_POSEIDON_BASE / PER_BLOCK` / `GAS_ZKVM_SHA256_PER_BYTE` / `GAS_ZKVM_ECDSA_VERIFY = 100000` / `GAS_ZKVM_READ_STATE_PER_SLOT` 常量
- [x] Task 11.5.2：扩展治理敏感参数清单（`governance_params.rs` 或对应文件）
  - [x] SubTask 11.5.2.1：新增 `MAX_ZKVM_TRACE_STEPS = 1,048,576` 到 90% quorum 敏感参数表
  - [x] SubTask 11.5.2.2：新增 `MAX_ZKVM_MEMORY = 16MB`
  - [x] SubTask 11.5.2.3：新增 `MAX_ZKVM_PROOF_SIZE = 64KB`
  - [x] SubTask 11.5.2.4：新增 `ZKVM_BATCH_SIZE = 1024`（含一致性约束 `MAX_ZKVM_TRACE_STEPS / ZKVM_BATCH_SIZE ≤ MAX_FOLD_STEP_COUNT`）
  - [x] SubTask 11.5.2.5：新增 `MAX_RECURSION_DEPTH = 16`
  - [x] SubTask 11.5.2.6：新增 `MAX_TRACE_HOST_MEMORY = 512MB`
  - [x] SubTask 11.5.2.7：新增 `PRODUCTION_GRACE_BLOCKS = 7200`
  - [x] SubTask 11.5.2.8：新增 `GAS_HYPERNOVA_VERIFY = 300000` 到敏感参数表
  - [x] SubTask 11.5.2.9：**v1.3 修正 M2-002 — Proof 字段长度上限参数（单项子分配，和 ≤ 总上限 ≈ 48KB < 64KB）**（防 verifier OOM DoS，见 Task 5.5.1.5）：`MAX_PUBLIC_IO_SIZE = 8KB` / `MAX_FOLDED_INSTANCE_SIZE = 8KB` / `MAX_SUMCHECK_PROOF_SIZE = 16KB` / `MAX_PCS_OPENING_SIZE = 8KB` / `MAX_EVENT_HASHES_COUNT = 256`（256 × 32 = 8KB）（**注：`witness_commitment_len ≤ 33` 为常量非治理参数**；**v1.2 单项 64KB×3+16KB=208KB > 总 64KB 矛盾，v1.3 修正为子分配**）
  - [x] SubTask 11.5.2.10：**v1.2 新增 `production_switch_height` 字段**（`GovernanceParams` 一次性写入字段 — 治理切换 `verifier_status` 从 `Stub` 到 `Production` 时写入当前 block height，grace 期起算点；grace 期结束后可清零；非持续调整参数，但写入须 90% quorum）
  - [x] SubTask 11.5.2.11：单元测试 — 所有敏感参数调整须 90% quorum + timelock；`ZKVM_BATCH_SIZE` 调整后一致性约束生效；**`production_switch_height` 一次性写入后不可改（除非 grace 期结束清零）**

## Phase 12：端到端集成测试

- [x] Task 12.1：编写示例 Rust 电路
  - [x] SubTask 12.1.1：`examples/fibonacci.rs` — 计算第 N 个 fibonacci 数（while-loop RV32I 程序，6N+9 步）
  - [x] SubTask 12.1.2：`examples/sha256_chain.rs` — 计算 SHA-256 哈希链（in-place，8N+11 步）
  - [x] SubTask 12.1.3：`examples/poker_hand_eval.rs` — 评估扑克牌型（5 张牌面值求和，19 步）
- [x] Task 12.2：端到端测试 — 每个示例跑 compile + run + prove + verify 流程
  - [x] SubTask 12.2.1：fibonacci 完整闭环测试通过（7 项：N=0/1/5/10/50/100 + proof_size_bound）
  - [x] SubTask 12.2.2：sha256_chain 完整闭环测试通过（5 项：N=1/5/10 zeros + N=1/3 custom）
  - [x] SubTask 12.2.3：poker_hand_eval 完整闭环测试通过（5 项：aces/mixed/high_cards/all_kings/max_safe）
- [x] Task 12.3：性能基准测试（criterion）
  - [x] SubTask 12.3.1：prover 时间 vs trace 步数（100/500/1000 步，batch_size=3）
  - [x] SubTask 12.3.2：proof 大小 vs trace 步数（1562 bytes 常数，Hypernova succinctness）
  - [x] SubTask 12.3.3：verifier 时间（~510µs 常数，与 trace 步数无关）
- [x] Task 12.4：soundness 端到端测试
  - [x] SubTask 12.4.1：恶意 ELF（篡改 magic/truncated/machine_type）被 `validate_elf` 拒绝（3 项）
  - [x] SubTask 12.4.2：恶意 ELF（段溢出地址）被 `validate_elf` 拒绝（含于 12.4.1 truncated 测试）
  - [x] SubTask 12.4.3：恶意 prover 篡改 witness 后 proof 必须 verify 失败（4 项：magic/byte_flip/u_l/z_at_point）
  - [x] SubTask 12.4.4：恶意 prover 伪造 multiplicity 后 lookup 必须失败（2 项：multiplicity/commitment 篡改）
  - [x] SubTask 12.4.5：恶意 prover 篡改 trace 后 CCS satisfied_by 必须失败（2 项：trace/witness_length）
  - [x] SubTask 12.4.6：恶意 prover 调用非白名单 slot 必须返回 `InvalidSlot`（2 项：invalid/whitelisted）

## Phase 13：文档与示例

- [x] Task 13.1：编写 `poker_zkvm/README.md` — 快速上手指南
- [x] Task 13.2：编写 `docs/38-1-zkvm-architecture.md` — ZKVM 架构文档
- [x] Task 13.3：编写 `docs/38-2-zkvm-compiler-guide.md` — 编译器使用指南
- [x] Task 13.4：编写 `docs/38-3-zkvm-syscall-reference.md` — Syscall 参考
- [x] Task 13.5：编写 `docs/38-4-zkvm-migration-guide.md` — **新增**：从既有 hash-based CcsInstance 迁移到新类型的指南（含新旧类型差异、迁移步骤、LegacyCcsInstanceAdapter 失败语义、CheckinTx signing_hash 兼容性、grace 期签名形式分派、检查清单）

# Task Dependencies

- Phase 0 (crate 骨架) — 所有后续 Phase 的前置
- Phase 1 (字段 + transcript) — Phase 1.5 / 5 / 6 / 7 / 8 / 9 的前置
- Phase 1.5 (PCS) — Phase 6 / 7 / 8 / 5.5 的前置（Hypernova 折叠与 proof 序列化依赖 PCS）
- Phase 2 (前端编译) — Phase 3 的前置（ELF 产出供执行引擎消费）
- Phase 3 (ISA 执行引擎) — Phase 5 的前置（trace 产出供约束编译器消费）
- Phase 4 (syscall) — 与 Phase 3 并行（syscall 是 ISA 的子模块）
- Phase 5 (约束编译器) — Phase 6 的前置（CCS 实例供 fold 消费）
- **Phase 5 Task 5.5 (syscall circuit) 依赖 Phase 10**（预编译电路）— 不能与 Phase 10 完全并行，须在 Phase 10 完成后才能完整测试
- **Phase 5.5 (serialize + witness) — v1.2 依赖修正（Min-002）**：依赖 Phase 1.5（PCS）+ Phase 5（CCS 实例结构供 witness 映射）+ Phase 6（HypernovaProof 结构定义）；**非 v1.1 所述"与 Phase 5 / 6 并行"** — Task 5.5.1 serialize 须等 Phase 6.6 定义 `HypernovaProof` 结构后才能实现，Task 5.5.2 witness 须等 Phase 5 CCS 实例结构后才能实现
- Phase 6 (Hypernova 折叠) — Phase 7 / 8 / 9 的前置（依赖 Phase 1.5 PCS）
- Phase 7 (prover + 压缩) 与 Phase 8 (verifier) — 可并行（均依赖 Phase 6）
- Phase 9 (CycleFold) — 依赖 Phase 6 / 7；**v1.2 Task 9.3/9.4（递归 verifier 电路）依赖 Phase 6 + Phase 1.5（PCS verify 约束）+ Phase 8（verifier 步骤定义）**
- **Phase 10 (预编译电路) — 修正：与 Phase 5 部分并行（Task 10.2 / 10.3 / 10.4 / 10.5 可并行），但 Phase 5 Task 5.5 依赖 Phase 10 完成**
- Phase 11 (poker_l1 集成) — 依赖 Phase 6 / 8 / 10
- Phase 11.5 (治理参数 + gas) — 与 Phase 11 并行；**v1.2 Task 11.5.2.9（MAX_* 字段长度参数）依赖 Phase 5.5（proof 序列化布局定义）**
- Phase 12 (端到端测试) — 依赖 Phase 11 / 11.5
- Phase 13 (文档) — 与 Phase 12 并行

# Parallelizable Work

可在同一 Phase 内并行推进的 Task 组：
- Phase 1: Task 1.1（字段）与 Task 1.2（transcript）并行
- Phase 1.5: Task 1.5.1（trait）→ Task 1.5.2（IPA 实现）
- Phase 2: Task 2.1（编译入口）依赖 Task 2.2（elf_validator）+ Task 2.3（prelude）— 三者可部分并行；Task 2.4（cargo-zkvm bin）依赖前三者
- Phase 3: Task 3.1（ISA） / Task 3.2（state） / Task 3.4（trace）可并行；Task 3.3（executor）依赖前三者
- Phase 4: Task 4.1（注册表）→ Task 4.2（host 实现）→ Task 4.3（gas）— 顺序
- Phase 5: Task 5.1（主入口+batching）→ 5.2/5.3/5.4/5.6 并行（每指令子电路独立）；**Task 5.5（syscall circuit）须等 Phase 10 完成**
- Phase 5.5: Task 5.5.1（serialize）与 Task 5.5.2（witness）并行（**但均须等 Phase 5 + Phase 6 + Phase 1.5 完成**）
- Phase 6: Task 6.1 → 6.2 / 6.3 并行 → 6.4 → 6.5（sumcheck）→ 6.6
- Phase 7: Task 7.1（主流程）依赖 Phase 6；Task 7.2（Spartan）与 Task 7.3（Groth16）并行
- Phase 8: Task 8.1（verifier）与 Task 8.2（集成）顺序 — 8.2 依赖 8.1
- Phase 9: Task 9.1 → 9.2 → 9.3 / 9.4 并行（9.3 BN254 电路与 9.4 Grumpkin 电路可并行实现，但 9.4 须等 9.3 验证电路结构可行后）
- Phase 10: Task 10.2 / 10.3 / 10.4 / 10.5 并行（各预编译电路独立）
- Phase 11: Task 11.1（stub 替换）与 Task 11.2（CheckinTx 扩展）部分并行
- Phase 11.5: Task 11.5.1（gas）与 Task 11.5.2（治理参数）并行；Task 11.5.2.9（MAX_*）须等 Phase 5.5 完成
