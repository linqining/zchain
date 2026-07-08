# Checklist — Hypernova ZKVM（支持 Rust 直接编译）

> **change-id**：`build-hypernova-zkvm`
> **版本**：v1.4（v1.3 密码学专家复核后修订 — 8 项修复：**2 MAJOR**：M3-001 治理参数清单 MAX_* 默认值同步（8KB/8KB/16KB/8KB）/ M3-002 grace 期后 scheme_id=4 分支明确（走 ZkShuffle Production verifier）；**6 MINOR**：Min3-001 total_payload checked_add/checked_mul / Min3-002 游戏终结判定条件 / Min3-003 幂等重提交范围 / Min3-004 删除 v1.2 残留 grace 期表述 / Min3-005 外层 sumcheck 公式括号 / Min3-006 gas 估算明细）
> **v1.2 变更摘要**（v1.1 独立审核后修订）：修正 Hypernova 折叠核心等式 — `v` 向量化 / fold challenge 标量化 / transcript 补矩阵承诺+witness commitment / LogUp `β` 在 witness 承诺后派生 / 内存一致性改 byte-level permutation / proof 反序列化字段长度上限 / ELF TOCTOU+checked_add+PT_DYNAMIC / `ZkPublicIo` 新增 3 字段 + 序列化 bump / slot 值 Merkle 绑定 / event hash 绑定 step_index / randomness 派生函数绑定上下文 / CycleFold 递归 verifier 电路定义 + Task 9.3/9.4 / CcsInstance 迁移诚实 BREAKING / CheckinTx.proof_kind 序列化策略 + scheme_id 映射 / Phase 5.5 依赖修正 / IPA challenge 派生 + NUMS generators / Production grace period 双通道 + 切换高度绑定
> 用于在实现完成后系统性验证所有 spec 要求已满足。每个 checkpoint 须通过代码审查 / 单元测试 / 集成测试 / 文档检查确认。

## Phase 0：crate 骨架

- [ ] `poker_zkvm` crate 已加入根 `Cargo.toml` workspace members
- [ ] `poker_zkvm/Cargo.toml` 声明完整依赖（arkworks / halo2 / sha2 / blake2 / blstrs / secp256k1 / rayon / goblin 等）
- [ ] `poker_zkvm/src/lib.rs` 含 `#![deny(unsafe_code)]` 声明
- [ ] `poker_zkvm/src/lib.rs` 定义全部子模块（compiler / isa / trace / constraints / pcs / fold / prover / verifier / syscalls / precompiles / cyclic / recursion / field / transcript / serialize / error）
- [ ] `poker_zkvm/src/error.rs` 定义 `ZkvmError` 含全部错误变体（UnsupportedInstruction / TraceTooLong / TraceHostMemoryExceeded / OutOfMemory / UnalignedAccess / InvalidZkProofFormat / SumcheckVerificationFailed / CrossLanguageClaimFailed / TranscriptMismatch / PcsVerificationFailed / AbiVersionMismatch / InvalidSlot / RecursionDepthExceeded / FoldStepCountExceeded / FoldError / **`ProofKindMismatch`** / **`UninitializedRead`** / Other）
- [ ] `cargo build` 通过，无 warning
- [ ] `cargo test` 通过（即使为空测试）

## Phase 1：字段、曲线 cycle 与 transcript

- [ ] `ZkvmField` trait 已定义，含 `name` / `modulus` / `from_u64` / `from_u32_with_wrap` / `to_u32_bits` / `to_u32` 方法
- [ ] trait 文档明确 `from_u32_with_wrap` (mod p) 与 `to_u32` (mod 2^32) 语义差异
- [ ] `Bn254ScalarField` 实现 `ZkvmField`，基于 `ark_bn254::Fr`
- [ ] u32 → 域元素包装（mod p）已实现并测试
- [ ] 域元素 → u32（mod $2^{32}$）抽取已实现并测试
- [ ] u32 加法溢出场景测试通过（含 overflow_bit 约束）
- [ ] u32 乘法溢出场景测试通过
- [ ] `Transcript` 结构已实现，支持 `absorb(domain_tag, length_prefix, data)` / `challenge(domain_tag) -> FieldElement`
- [ ] canonical 编码实现 — 域元素固定 32 bytes LE，commitment 为 curve point compressed 33 bytes
- [ ] length-prefixing 实现（4 bytes LE，防 concatenation ambiguity）
- [ ] 域分离常量已定义：`HYPERNOVA_FOLD_DOMAIN_TAG = 0x10` / `SUMCHECK_DOMAIN_TAG = 0x11` / `LOOKUP_DOMAIN_TAG = 0x12` / `MEM_CHECK_DOMAIN_TAG = 0x13` / `PCS_OPEN_DOMAIN_TAG = 0x14`
- [ ] absorb 序列规范实现（fold / sumcheck / lookup / pcs_open 阶段均含 `ccs_struct_params` 防 weak CCS 重放）
- [ ] **v1.2 fold 阶段 absorb 含 `ccs_commitment`（M_1..M_t 承诺的 Merkle root，绑定矩阵内容）+ `lcccs_witness_commitment` + `ccccs_witness_commitment`**（绑定 witness 防 challenge 派生后替换）
- [ ] Transcript 单元测试通过 — 相同输入相同 challenge；不同输入不同 challenge；length-prefix 防歧义测试（`"ab"+"c"` vs `"a"+"bc"` 产生不同 challenge）

## Phase 1.5：多项式承诺方案（PCS）— **新增**（v1.2 补 NUMS generators + challenge 派生 + point/commitment 绑定）

- [ ] `Pcs` trait 已定义，含 `commit` / `open` / `verify` 方法
- [ ] `Commitment` / `Proof` / `Eval` 类型已定义（与曲线 cycle 兼容）
- [ ] IPA over BN254 实现完成
- [ ] `commit(poly)` 基于 Pedersen vector commitment + BN254 MSM 实现完成
- [ ] **v1.2 NUMS generators** — generators 通过 `hash_to_curve(b"poker_zkvm_ipa_gen" || i)` 派生（非可信 setup）
- [ ] `open(poly, point)` log(N) 轮 IPA protocol 实现完成
- [ ] **v1.2 open 开始前 absorb `PCS_OPEN_TAG || commitment || point`**（绑定 point 与 commitment 防 proof 复用）
- [ ] **v1.2 每轮 challenge 从 transcript 派生** — `r_i ← challenge(PCS_OPEN_TAG || round_commitment_i || round_index_i)`
- [ ] `verify(commitment, point, eval, proof)` log(N) 轮挑战重算实现完成
- [ ] **v1.2 verifier 重算 challenge 时使用与 prover 相同的 absorb 顺序**（含 point 与 commitment 绑定）
- [ ] 小规模多线性多项式（n_vars <= 8）commit/open/verify 闭环测试通过
- [ ] **soundness 负例测试** — 篡改 eval / 篡改 proof / 篡改 commitment 任一字段必须 verify 失败
- [ ] **v1.2 soundness 负例测试** — 复用 proof 到不同 point 必须 verify 失败（防 proof 重放攻击）

## Phase 2：前端编译流水线

- [ ] `CompilerConfig` 已定义（target = `riscv32i-unknown-none-elf` / opt-level = 3 / panic = abort）
- [ ] `compile_crate` 函数能调用 `rustc --target riscv32i-unknown-none-elf` 编译用户 crate
- [ ] ELF 输出到 `target/riscv32i-unknown-none-elf/release/<crate_name>.elf`
- [ ] `_start` trampoline 已生成 — 调用 `zkvm_read_input` 读输入，调用用户 `main`，`zkvm_commit_output` 提交输出
- [ ] panic 自动转 `zkvm_panic` syscall
- [ ] **ELF 强化校验全部通过**（v1.2 补 TOCTOU + checked_add + PT_DYNAMIC）：
  - [ ] 校验 ELF magic / class（ELF32）/ endian（little）/ machine（EM_RISCV）
  - [ ] 校验所有段地址在 `[0, MAX_ZKVM_MEMORY)` 范围内（**v1.2 使用 `addr.checked_add(size) <= MAX_ZKVM_MEMORY`** 防 `addr=0xFFFFFFF0, size=0x20` wrap 攻击）
  - [ ] 校验 entry point 在 `.text` 段范围内
  - [ ] 校验段之间无重叠
  - [ ] 校验所有 relocation 入口指向有效段内偏移
  - [ ] 扫描 `.text` 段所有指令属于 RV32I 子集（拒绝 fence.i / 浮点 / atomics / SIMD / compressed）
  - [ ] 校验 `.text` 段大小 ≤ `MAX_TEXT_SIZE = 8MB`，总加载内存 ≤ `MAX_ZKVM_MEMORY = 16MB`（**v1.2 使用 `checked_add` 累加各段大小**）
  - [ ] **v1.2 拒绝 `PT_DYNAMIC` 段与 `DT_NEEDED` 入口**（防 dynamic linking 触发外部符号解析）
  - [ ] **v1.2 校验 `e_shoff + e_shnum * e_shentsize` 不溢出**（防 section header table 损坏导致解析器崩溃）
  - [ ] **v1.2 消除 TOCTOU** — `validate_elf(elf_bytes) -> ElfMetadata` 接受字节切片返回已解析 `ElfMetadata`；`load_elf(metadata, state)` 接受 `ElfMetadata` 而非路径
- [ ] 每项 ELF 校验失败的负例测试覆盖（**含 wrap 攻击 / PT_DYNAMIC / TOCTOU**）
- [ ] `zkvm::prelude` 模块 re-export `Vec` / `Box` / `String` / `format!`
- [ ] `zkvm::entry` 宏已定义
- [ ] `zkvm::test` 宏已定义
- [ ] `cargo-zkvm` bin 含 `build` / `run` / `prove` / `verify` / `test` 五个子命令
- [ ] 端到端测试 — 用 `examples/hello_world`（简单 main 函数）跑通 `cargo zkvm build`

## Phase 3：ZKVM ISA 执行引擎

- [ ] `Instruction` 枚举覆盖全部 RV32I 指令 + ECALL
- [ ] `decode(word: u32)` 函数能正确解码全部 RV32I 指令（拒绝 compressed 指令）
- [ ] `execute(state, insn)` 函数能正确执行每条 RV32I 指令
- [ ] RV32I 全部指令单元测试通过
- [ ] `VmState` 含 `pc` / `registers[32]` / `memory: MemoryMap`
- [ ] 内存模型 — 32-bit 地址空间，STACK_TOP = 0x80000000，HEAP_START = 0x10000000
- [ ] 4-byte word 对齐访问强制（未对齐返回 `UnalignedAccess`）
- [ ] 内存上限 MAX_ZKVM_MEMORY = 16MB 强制（超出返回 `OutOfMemory`）
- [ ] `load_elf` 能解析 ELF 段加载到内存
- [ ] `execute_elf` 完整执行循环实现
- [ ] 步数上限 MAX_ZKVM_TRACE_STEPS = 1,048,576 强制（超出返回 `TraceTooLong`）
- [ ] **trace host 内存上限 MAX_TRACE_HOST_MEMORY = 512MB 强制（超出返回 `TraceHostMemoryExceeded`）**
- [ ] syscall 分派基于 `a7` 寄存器
- [ ] `Trace` 数据结构含 `steps: Vec<Step>`
- [ ] `Step` 含 `step_index` / `pc` / `instruction` / `registers` / `mem_access`
- [ ] **`MemAccess` 含 `addr` / `op` / `value` / `size`（size 字段防 LB 1B vs LW 4B aliasing）**
- [ ] Trace 二进制序列化 / 反序列化实现并测试
- [ ] `Trace::host_memory_usage()` 估算实现

## Phase 4：Syscall

- [ ] `SyscallId` 枚举覆盖全部 10 个 syscall（0x01-0x0A）
- [ ] `Syscall` trait 含 `id` / `host_execute` / `gas_cost` 方法
- [ ] `ZKVM_ABI_VERSION = 1` 常量已定义，写入 proof header
- [ ] `read_input` host 实现从 host input buffer 读取
- [ ] `commit_output` host 实现写入 host output buffer
- [ ] `poseidon` host 实现调用 `poker_protocol::crypto::poseidon`
- [ ] `sha256` host 实现调用 `sha2` crate
- [ ] `ecdsa_verify` host 实现调用 `secp256k1` crate
- [ ] `emit_event` host 实现 — event 内容经 Poseidon 哈希产生 `event_hash = Poseidon(content_hash || step_index)`（**v1.2 绑定 step_index**），收集到 `event_hashes` 数组，`public_io.event_hashes_root` = 数组 Merkle root
- [ ] `log` host 实现写入 host event log
- [ ] `panic` host 实现终止执行
- [ ] **`get_randomness` host 实现 deterministic**（**v1.2 派生函数绑定上下文**）— `output = Poseidon(seed || initial_commitment || final_commitment || call_counter)`，`seed` = public_io 的 `randomness_seed`（来自链上 VRF，绑定 `block_height + game_id`）；`call_counter` 单调递增，电路显式约束
- [ ] **`read_state` host 实现含 slot 白名单校验 + v1.2 Merkle 绑定** — 仅允许 `SLOT_GAME_STATE = 0x01` / `SLOT_PLAYER_HANDS = 0x02` / `SLOT_POT_AMOUNT = 0x03` / `SLOT_CURRENT_TURN = 0x04` / `SLOT_ACK_CHAIN = 0x05`，非白名单返回 `InvalidSlot(slot)`；**v1.2 prover 须提供 Merkle 证明 slot 值在 `public_io.state_slot_root` 下**，绑定 `execute_checkin` 时 `block_height`；跨 batch 一致性约束 `state_slot_root` 相同
- [ ] 每个 syscall 的 gas 计费常量已定义
- [ ] `syscall_gas(id, args) -> u64` 函数实现
- [ ] gas 计费单元测试覆盖各 syscall
- [ ] **soundness 负例测试** — 非白名单 slot 调用必须返回 `InvalidSlot`；**v1.2 伪造 slot 值（无 Merkle 证明）必须失败；跨 batch `state_slot_root` 不一致必须失败**

## Phase 5：Trace → CCS 约束编译器

- [ ] `CcsMatrices` 数据结构含 `m` / `subsets` / `coeffs`
- [ ] `compile_trace_to_ccs(trace, batch_size)` 主入口函数实现
- [ ] **batching 策略实现** — 每 K = `ZKVM_BATCH_SIZE`（默认 1024）步生成 1 个 CCS 实例
- [ ] **instances.len() ≤ MAX_FOLD_STEP_COUNT = 1000 校验**（超出返回 `FoldStepCountExceeded`）
- [ ] 「连续性约束」已实现 — step $i$ 输出寄存器 == step $i+1$ 输入寄存器（在 batch 内）
- [ ] batch 间连续性约束已实现
- [ ] ADD / ADDI 子电路实现（**含 overflow_bit 约束**）
- [ ] SUB / SLT / SLTU 子电路实现
- [ ] **SLL / SRL / SRA 子电路实现 — shift amount 必须 bit-decompose 为 5 个 bit，每个 bit range check ∈ {0,1}；SRA 须约束符号位扩展**
- [ ] AND / OR / XOR 子电路实现（通过 lookup 优化）
- [ ] **RV32M DIV / DIVU / REM / REMU 子电路实现 — RISC-V 除零语义**：`DIV(x,0)=-1` / `DIVU(x,0)=2^32-1` / `REM(x,0)=x` / `DIV(MIN,-1)=MIN` / `REM(MIN,-1)=0`
- [ ] 算术指令单元测试覆盖（含边界：除零 / MIN/-1 / overflow）
- [ ] LW / SW / LB / SB / LH / SH / LBU / LHU 子电路实现
- [ ] **v1.2 byte-level permutation（非 word-level）** — 写操作展开为字节级写（LW 4B → 4 条字节写），读操作展开为字节级读；permutation key 为 `(byte_addr, byte_val, step_index)`（每 byte 单独记录）；`size` 字段仅在 read-write check 层使用
- [ ] **v1.2 混合尺寸重叠访问处理** — LW 写 4B 后 LB 读 1B 能正确匹配（byte_val == 对应字节）；`step_index` 单调性显式约束 `step_{i+1} > step_i`
- [ ] 地址 range check 实现（**v1.2 使用 `checked_add` 防多字节访问 wrap**）
- [ ] read-after-write 测试通过
- [ ] **v1.2 未初始化读取检测** — byte_addr 在 read 集合但 write 集合无对应记录（step_index < read_step）返回 `UninitializedRead`
- [ ] **soundness 负例测试 — 字节级 aliasing 攻击必须失败；permutation 顺序伪造必须失败；混合尺寸重叠访问（LW 写后 LB 读 / LB 写后 LW 读）正确匹配**
- [ ] JAL / JALR 子电路实现
- [ ] BEQ / BNE / BLT / BGE / BLTU / BGEU 子电路实现
- [ ] LUI / AUIPC 子电路实现
- [ ] ECALL 子电路实现
- [ ] **LogUp lookup 协议实现 — 正确公式 `Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)`**
- [ ] **v1.2 严格 β 派生时机** — prover 提交 table 承诺 `C_T` → witness 承诺 `C_f` → multiplicity 承诺 `C_m` → `transcript.absorb(LOOKUP_TAG || C_T || C_f || C_m)` → **β ← challenge**（**β 必须在 witness 承诺之后派生**，防 prover 在看到 β 后调整 multiplicity）
- [ ] **table 承诺 `C_T` 必须先于 witness 提交（防 multiplicity 伪造攻击）**
- [ ] lookup 实例作为附加 CCS 实例（NIRVANA 风格，可折叠）
- [ ] 内置 lookup 表：u8 / u16 / u32 range、AND / OR / XOR 真值表
- [ ] lookup 正例测试通过
- [ ] **soundness 负例测试 — prover 在看到 β 后调整 multiplicity 必须失败；伪造 multiplicity 必须失败；v1.2 β 派生时机错误（在 witness 承诺前派生）必须被 transcript 校验拒绝**

## Phase 5.5：Proof 序列化与 Witness 生成 — **新增**（v1.3 修正 M2-002 — 总长度优先 + 单项子分配防 verifier OOM DoS）

- [ ] Proof 二进制布局实现（magic / abi_version / proof_kind / field_id / public_io / folded_instance / witness_commitment / final_sumcheck / pcs_opening / event_hashes / **v1.3 r_y / z_at_point**）
- [ ] 所有变长字段前缀 4-byte LE length
- [ ] canonical 域元素编码实现（32 bytes LE，mod p）
- [ ] `HypernovaProof::serialize()` / `HypernovaProof::deserialize()` 函数实现
- [ ] 反序列化校验 magic / abi_version / field_id，不匹配返回 `InvalidZkProofFormat` / `AbiVersionMismatch`
- [ ] **v1.3 反序列化字段长度上限校验（修正 M2-002 — 总长度优先 + 单项子分配，和 ≤ 总上限 ≈ 48KB < 64KB）** — 三步法：
  - [ ] 第 0 步：stream 读固定头部（magic / abi_version / proof_kind / field_id，共 10 bytes），校验
  - [ ] **第 1 步（关键）：总长度优先校验** — stream 读所有变长字段 length 前缀（不读 payload），计算 `total_payload = public_io_len + folded_instance_len + witness_commitment_len + final_sumcheck_len + pcs_opening_len + event_hashes_count * 32 + length_prefix_overhead`，校验 `total_payload ≤ MAX_ZKVM_PROOF_SIZE = 64KB`，超长立即返回 `InvalidZkProofFormat`，**不分配任何变长 payload 缓冲区**（防 OOM — v1.2 单项校验通过后再总校验，attacker 可构造单项 64KB×3=192KB proof 通过单项校验后才失败，已分配 192KB 缓冲区）
  - [ ] **第 2 步：单项上限校验（v1.3 子分配）**：
    - [ ] `public_io_len ≤ MAX_PUBLIC_IO_SIZE = 8KB`
    - [ ] `folded_instance_len ≤ MAX_FOLDED_INSTANCE_SIZE = 8KB`（含 `v': Vec<FieldElement>` 向量，长度 ≤ `num_matrices * 32 bytes`；典型 `num_matrices ≤ 10` 即 320B，8KB 余量充足）
    - [ ] `witness_commitment_len ≤ 33`（单个 compressed curve point）
    - [ ] `final_sumcheck_len ≤ MAX_SUMCHECK_PROOF_SIZE = 16KB`（外层 + 内层 batched sumcheck ~4KB，16KB 余量充足）
    - [ ] `pcs_opening_len ≤ MAX_PCS_OPENING_SIZE = 8KB`（log(N) 轮 IPA，~1.3KB，8KB 余量充足）
    - [ ] `event_hashes_count ≤ MAX_EVENT_HASHES_COUNT = 256`（256 × 32 = 8KB）
  - [ ] 第 3 步：第 1+2 步全通过后才分配 payload 缓冲区并解析字段内容
- [ ] **v1.3 早夭逻辑** — 第 1 步或第 2 步任一失败立即返回 `InvalidZkProofFormat`，不分配大缓冲区，不进入昂贵计算
- [ ] serialize → deserialize 往返一致测试通过
- [ ] **soundness 负例测试 — 篡改 magic / abi_version 必须失败**
- [ ] **v1.3 soundness 负例测试 — 超长字段（如 `public_io_len = 0xFFFFFFFF`）必须立即返回 `InvalidZkProofFormat` 不 OOM**
- [ ] **v1.3 soundness 负例测试 — 单项 8KB 通过但总和 48KB+ > 64KB 的恶意 proof 必须在第 1 步总长度优先校验失败（不分配缓冲区）**
- [ ] Witness 映射规则定义 — `z = (u, x, trace, 1)`
- [ ] `generate_witness(trace, ccs_instance) -> WitnessVector` 函数实现
- [ ] MVP transparent 策略实现 — witness 不盲化
- [ ] **v1.3 MVP 风险声明枚举具体泄漏字段** — witness commitment（Pedersen 无盲化）/ sumcheck 各轮求值多项式 / PCS opening 的 `z'(r_y)` 求值；具体敏感数据（玩家手牌明文 / VRF seed / ECDSA 私钥 / 游戏中需对对手保密的状态）不得在 MVP 阶段进入 ZKVM 计算
- [ ] witness 与 CCS 实例一一对应测试通过
- [ ] `Ccs::satisfied_by(witness) == true` 测试通过

## Phase 6：Hypernova 折叠算法（v1.3 修正核心等式 — C2-001/002/003 + M2-001）

- [ ] `Ccs` 数据结构含 `num_vars` / `num_matrices` / `matrices` / `subsets` / `coeffs`
- [ ] `Ccs::satisfied_by(z)` 函数实现并测试
- [ ] `Ccs::to_lccls(z)` / `Ccs::to_cccs(z)` 函数实现
- [ ] **`CcsInstance` 新类型定义（含矩阵结构与域元素 witness，非 poker_l1 旧 hash-based）**
- [ ] **v1.3 `Lcccs` 结构** — `{ ccs_ref, u_L: FieldElement, x_L: Vec<FieldElement>, trace_L: Vec<FieldElement>, r_x_L: FieldElement, v_L: Vec<FieldElement> }`（`u_L` 为标量，relaxed 可非 0；`r_x_L` 显式存储；`v_L[j] = Σ_y M_j(r_x_L, y)·z_L(y)`，长度 = `num_matrices`）
- [ ] **v1.3 `Ccccs` 结构（修正 C2-002 — 不存储 v_C 字段）** — `{ ccs_ref, u_C: FieldElement, x_C: Vec<FieldElement>, trace_C: Vec<FieldElement>, witness_commitment_C: Commitment }`（v_C[j](X) 是多项式，折叠时在 r_x_L 处通过内层 batched sumcheck 计算）
- [ ] `Lcccs::satisfied()` 函数实现并测试 — **v1.3 relaxed 约束 `Σ_i c_i · Π_{j∈S_i} v_L[j] = u_L`（u_L 可非 0，非 = 0）**
- [ ] `Ccccs::satisfied()` 函数实现并测试
- [ ] `fold(lcccs, ccccs, transcript)` 函数实现
- [ ] **v1.3 Fiat-Shamir 派生随机标量 `r`（单域元素，非向量）**（absorb 序列含 `ccs_commitment` + `lcccs_witness_commitment` + `ccccs_witness_commitment`，见 Phase 1.2）
- [ ] **v1.3 折叠后实例** — `u' = u_L + r·u_C`（**标量**）/ `x' = x_L + r·x_C` / `trace' = trace_L + r·trace_C` / `r_x' = r_x_L`（沿用 LCCCS_L 的 r_x）/ **`v'[j] = v_L[j] + r·v_C[j](r_x_L)`（分量级；v_C[j](r_x_L) 通过内层 batched sumcheck 计算）**；folded witness `z' = z_L + r·z_C`
- [ ] 折叠成本 = O(变量数) MSM
- [ ] 折叠后 `Lcccs::satisfied() == true` 单元测试通过 — **v1.3 relaxed 约束 `Σ_i c_i · Π_{j∈S_i} v'[j] = u'`**
- [ ] **soundness 负例测试 — 篡改 lcccs / ccccs 任一字段必须 fold 失败或 verify 失败**
- [ ] `SumcheckProof` 数据结构实现（**v1.3 含外层 sumcheck proof + 内层 batched sumcheck proof**）
- [ ] `prove(g, num_vars, transcript)` 函数实现 — **v1.3 修正 C2-003 — 外层 sumcheck claimed sum = `u'`（标量，非 v' 向量，非 0）**；外层归约到 `r_x_L`，校验 `G(r_x_L) = u'`；**v1.3 修正 C2-001 — 内层 batched sumcheck**：引入 FS challenge `γ`（单标量），对每个 `j ∈ [0, t)` batched，证明 `Σ_j γ^j·v'[j] = Σ_y (Σ_j γ^j·M_j(r_x_L, y))·z'(y)`，归约到**单个 challenge `r_y`**：`Σ_j γ^j·v'[j] = (Σ_j γ^j·M_j(r_x_L, r_y))·z'(r_y)`；**combined_point = r_y（单 challenge，非 (r_x, r_{y_1}, ..., r_{y_t}) 元组）**
- [ ] `verify(proof, claimed_sum, num_vars, transcript)` 函数实现 — **v1.3 校验外层 `G(r_x_L) == u'`（标量，非 v'）+ 内层 batched sumcheck 归约到 `z'(r_y)`**
- [ ] 小规模 sumcheck（n_vars <= 8）prove/verify 测试通过，**含 u' ≠ 0 场景**
- [ ] **soundness 负例测试 — 篡改 claimed_sum / 篡改 proof / 篡改 `r_y` 与 `z_at_point` 关联 必须失败**
- [ ] `fold_loop(instances, ...)` 函数实现
- [ ] N=1 折叠闭环测试通过
- [ ] N=10 折叠闭环测试通过
- [ ] N=1000 折叠闭环测试通过
- [ ] **v1.3 返回 `HypernovaProof { abi_version, folded_instance, witness_commitment, final_sumcheck, pcs_opening, r_y, z_at_point }`**（**combined_point 字段改名为 r_y**）— PCS opening proof 在 `r_y`（单 challenge）处打开 folded witness `z'` 得 `z_at_point = z'(r_y)`（**不是 v'，也不是 u'**）
- [ ] **soundness 负例测试 — N=10 折叠后篡改 folded_instance / witness_commitment / final_sumcheck / pcs_opening / r_y / z_at_point 任一字段必须 verify 失败**

## Phase 7：Prover 与最终压缩

- [ ] `ProverConfig` 已定义（含 `batch_size` / `max_recursion_depth`）
- [ ] `prove(elf_bytes, input, config)` 主流程实现
- [ ] 流程：load ELF → execute → trace → compile_trace_to_ccs (batch_size=K) → fold_loop → compress → emit proof
- [ ] proof 大小检查 MAX_ZKVM_PROOF_SIZE = 64KB 强制
- [ ] 超出时触发 CycleFold 递归压缩
- [ ] **错误恢复实现** — prover 失败返回详细错误，host 端可调整 `ZKVM_BATCH_SIZE` 后重试
- [ ] Spartan 压缩实现 — proof ≤ 10KB
- [ ] Spartan compressed proof 可被 verifier 校验
- [ ] **soundness 负例测试 — 篡改 Spartan proof 必须失败**
- [ ] Groth16 备选压缩实现（可选）
- [ ] Groth16 复用 `poker_l1/src/offline/groth16.rs` 既有 verifier

## Phase 8：链上 Verifier Production（v1.3 cross-language claim 修正 + 双通道 grace period + M2-003/004 修复）

- [ ] `verify_production(proof_bytes, public_io)` 函数实现
- [ ] 反序列化 `HypernovaProof` 实现（校验 magic / abi_version / field_id；**v1.3 字段长度上限校验：总长度优先 + 单项子分配（见 Phase 5.5），超长立即返回 `InvalidZkProofFormat` 不进入昂贵计算**）
- [ ] 重新生成 Fiat-Shamir challenge 实现（**v1.2 含 `ccs_commitment` + `witness_commitment` 绑定**）
- [ ] final sumcheck 等式校验 — **v1.3 修正 C2-003 — 外层 `G(r_x_L) == u'`（claimed sum 为 `u'` 标量，非 v' 向量，非 0）**，失败返回 `SumcheckVerificationFailed`
- [ ] **v1.3 folded instance cross-language claim 校验 — 数学等式 1+2+3+4**：
  - [ ] **外层 sumcheck 一致性**：`G(r_x_L) == u'`（**v1.3 修正 C2-003 — claimed sum 为 `u'` 标量，非 v' 向量，非 0**）
  - [ ] **v1.3 修正 C2-001 — 内层 batched sumcheck 归约（单 r_y）**：引入 FS challenge `γ`（单标量），对每个 `j ∈ [0, t)` batched，校验 `Σ_j γ^j · v'[j] == (Σ_j γ^j · M_j(r_x_L, r_y)) · z'(r_y)` 在**单个 challenge `r_y`** 处归约（**非 t 个 r_{y_j}**；verifier 用 PCS opening 提供的 `z_at_point = z'(r_y)` 校验）
  - [ ] **PCS opening 校验**：`Pcs::verify(witness_commitment', r_y, z_at_point, opening_proof) == true`，其中 **`combined_point = r_y`（单 challenge，非 (r_x, r_{y_1}, ..., r_{y_t}) 元组 — v1.3 修正 C2-001）**，**`z_at_point = z'(r_y)` 是 folded witness z' 在 r_y 的求值，不是 v'，也不是 u'**
  - [ ] **v1.3 修正 M2-001 — LCCCS relaxed 约束**：`Σ_i c_i · Π_{j∈S_i} v'[j] = u'`（**relaxed，u' 可非 0，非原始 CCS 的 = 0**）— 通过外层 sumcheck 隐式验证（G(r_x_L) = u' 即此约束）
  - [ ] **关键不变式校验**：`u'`（外层 claimed sum）+ `v'`（内层 per-matrix 值）+ `z_at_point`（PCS opening 求值）三者须通过外层 sumcheck + 内层 batched sumcheck 链关联（防 prover 独立伪造）
- [ ] 失败返回 `CrossLanguageClaimFailed`
- [ ] PCS opening 校验 — 失败返回 `PcsVerificationFailed`（**v1.2 verifier 重算 challenge 时使用与 prover 相同的 absorb 顺序，含 point 与 commitment 绑定**）
- [ ] transcript 一致性校验 — 失败返回 `TranscriptMismatch`
- [ ] 合法 proof 通过测试
- [ ] **soundness 负例测试** — 篡改 folded_instance / witness_commitment / final_sumcheck / pcs_opening / **r_y / z_at_point** / public_io 任一字段必须失败；**篡改 `z_at_point` 与 `u'`/`v'` 关联（独立伪造三者）必须失败**
- [ ] `poker_l1/src/offline/hypernova.rs` Production 分支调用 `poker_zkvm::verifier::verify_production`
- [ ] `PokerL1Error` 扩展 `SumcheckVerificationFailed` / `CrossLanguageClaimFailed` / `TranscriptMismatch` / `PcsVerificationFailed` / `AbiVersionMismatch` / `InvalidSlot` / `RecursionDepthExceeded` / **`ProofKindMismatch`** / **`UninitializedRead`** / **v1.3 新增 `PartialFoldHashImmutable`（M2-003）** / **v1.3 新增 `SignatureFormMismatch`（M2-004）**
- [ ] **v1.2 双通道 grace period 实现** — 治理切换时记录 `production_switch_height`（当前 block height）到 `GovernanceParams`；grace 期（`PRODUCTION_GRACE_BLOCKS = 7200`）内：
  - [ ] `proof_kind = ZkShuffle` 旧 Stub proof：允许走 stub 路径（仅校验 proof 长度），**但 `proof_hash` 必须匹配链上已存 `last_partial_fold.proof_partial_hash`**（仅允许在途游戏继续，不允许新游戏用 Stub proof）
  - [ ] `proof_kind = Zkvm` proof：强制走 Production 路径（完整 sumcheck + cross-language claim + PCS opening + transcript 校验）
- [ ] **v1.3 修正 M2-003 — `last_partial_fold.proof_partial_hash` 链上不可变约束** — `PartialCheckinTx` 执行时校验 `last_partial_fold.proof_partial_hash == None || last_partial_fold.proof_partial_hash == tx.proof_partial_hash`（首次设置或幂等重提交允许；覆盖已有值返回 `PartialFoldHashImmutable` 错误）；`execute_checkin` 完成（游戏终结）后清零；grace 期结束后强制清零；**v1.4 修正 Min3-002 — "游戏终结"判定 = `is_terminal(ack_chain)` 或 `game_over=true`**；**v1.4 修正 Min3-003 — 幂等范围 = 整个 PartialCheckinTx 内容幂等（proof_partial_hash + intermediate_commitment + ack_chain_partial 全部相等）**
- [ ] **v1.3 修正 M2-004 — 单 proof_kind 单签名形式** — verifier 通过 `scheme_id` 反推期望的签名形式（`scheme_id=4` 期望旧签名无 `proof_kind` 字段；`scheme_id=1` 期望新签名含 `proof_kind` 字段），签名形式与 `scheme_id` 不一致返回 `SignatureFormMismatch` 错误；切换前仅接受旧签名，grace 期内按 scheme_id 分派，grace 期后仅接受新签名
- [ ] **grace 期结束后**（`current_height > production_switch_height + PRODUCTION_GRACE_BLOCKS`）所有 proof 强制 Production 路径，stub 路径彻底关闭
- [ ] Stub 分支行为保持不变（`verifier_status == Stub` 时仅校验 proof 长度）
- [ ] 既有单元测试更新 — Production 分支测试改用真实 proof
- [ ] **v1.2 grace 期双通道测试** — ZkShuffle + 匹配 proof_hash 通过 / ZkShuffle + 不匹配 proof_hash 失败 / Zkvm 强制 Production / grace 期后 stub 关闭
- [ ] **v1.3 M2-003 测试** — 覆盖已有 `proof_partial_hash` 返回 `PartialFoldHashImmutable`；幂等重提交通过；execute_checkin 完成后清零
- [ ] **v1.3 M2-004 测试** — `scheme_id=4` 旧签名通过 / `scheme_id=4` 新签名返回 `SignatureFormMismatch` / `scheme_id=1` 新签名通过 / `scheme_id=1` 旧签名返回 `SignatureFormMismatch`

## Phase 9：CycleFold 递归聚合（v1.2 补递归 verifier 电路定义）

- [ ] `CycleCurve` trait 已定义
- [ ] `Bn254GrumpkinCycle` 实现主曲线 BN254 + 辅助曲线 Grumpkin
- [ ] Cycle 性质验证 — 主曲线标量域 == 辅助曲线 base field
- [ ] `RecursiveNode` 数据结构定义
- [ ] `aggregate(sub_proofs)` 函数实现
- [ ] `tree_aggregate(sub_proofs, depth)` 函数实现 — log(N) 递归深度
- [ ] **递归终止条件实现** — final proof ≤ 64KB 时停止；递归深度 ≤ `MAX_RECURSION_DEPTH = 16`，超出返回 `RecursionDepthExceeded`；**v1.2 深度依据分析**：最坏 N=1000 sub-proofs，`ceil(log2(1000)) = 10`，10 层后 ≤ 64KB，`MAX_RECURSION_DEPTH=16` 留 60% 余量
- [ ] K=8 sub-proofs 聚合为单个 final proof 测试通过
- [ ] **soundness 负例测试 — 篡改任一 sub_proof 必须聚合失败或最终 verify 失败**
- [ ] **v1.2 Task 9.3 / v1.3 修正 — BN254 递归 verifier 电路 `C_BN254`**：
  - [ ] `C_BN254` 电路结构定义（halo2 或 arkworks Circuit trait），public inputs 含 `π_G` 的 public_io（含 `randomness_seed` / `event_hashes_root` / `state_slot_root`）、folded LCCCS 的 `u'`（标量）/ `x'` / `v'`（`Vec<FieldElement>` 长度 = `num_matrices`）、witness_commitment'
  - [ ] 约束 1：反序列化 `π_G`（校验 magic / abi_version / field_id，各字段长度 ≤ `MAX_*` 常量；**v1.3 总长度优先 + 单项子分配**）
  - [ ] 约束 2：PCS verify（IPA on Grumpkin）— log(N) 轮 IPA verify 约束
  - [ ] **v1.3 修正 C2-003 — 约束 3：外层 sumcheck verify** — 重算 challenge `r_x_L`，校验 `G(r_x_L) == u'`（**非 v'**；u' 是 folded LCCCS 标量参数；G(r_x_L) = u' 即隐式校验 relaxed LCCCS 约束 `Σ_i c_i · Π_{j∈S_i} v'[j] = u'`）
  - [ ] **v1.3 修正 C2-001 — 约束 4：内层 batched sumcheck verify（单 r_y）** — 重算 FS challenge `γ`，归约到**单个 challenge `r_y`**，校验 `Σ_j γ^j · v'[j] == (Σ_j γ^j · M_j(r_x_L, r_y)) · z'(r_y)`（z'(r_y) 由 PCS opening 提供）
  - [ ] **v1.3 修正 — 约束 5：cross-language claim** — PCS opening `Pcs::verify(witness_commitment', r_y, z_at_point, opening_proof)` + `z_at_point == z'(r_y)` 与内层 batched sumcheck 一致性（**关键不变式**：`u'` + `v'` + `z_at_point` 三者须通过外层 + 内层 batched sumcheck 链关联）
  - [ ] 约束 6：transcript 一致性 — 重算所有 FS challenge（r, γ, r_x_L, r_y）
  - [ ] **v1.3 修正 — 约束数估算（单层估算非总累加）**：`C_BN254` 单层约束数 ≈ IPA verify（log(N) 轮 × ~5000 约束/轮）+ 外层 sumcheck verify（~10000 约束）+ 内层 batched sumcheck verify（~10000 约束）+ cross-language（~5000 约束）≈ **100,000-200,000 约束/单递归层**；`MAX_RECURSION_DEPTH=16` 为最大允许深度上限，**实际递归深度由 `ceil(log2(sub_proofs.len()))` 决定**（N=1000 时仅需 10 层，远低于 16）
  - [ ] 单元测试 — `C_BN254` 验证合法 Grumpkin proof 通过；篡改 sub-proof 任一字段必须电路约束失败
- [ ] **v1.2 Task 9.4 / v1.3 修正 — Grumpkin 镜像电路 `C_Grumpkin`**：
  - [ ] `C_Grumpkin` 电路结构定义（对称镜像 `C_BN254`），public inputs 含 BN254 proof 的对应字段（u' 标量 / x' / v' / witness_commitment'）
  - [ ] 对称约束 1-6（反序列化 / PCS verify on BN254 / **v1.3 外层 sumcheck claimed sum = u'** / **v1.3 内层 batched sumcheck 单 r_y** / **v1.3 cross-language claim combined_point = r_y** / transcript 一致性）
  - [ ] **跨曲线 bridging** — BN254 电路的 witness（含 Grumpkin 点坐标）通过 cycle 性质在 BN254 标量域中直接表达；反之同理
  - [ ] 单元测试 — `C_Grumpkin` 验证合法 BN254 proof 通过；篡改 sub-proof 任一字段必须电路约束失败
  - [ ] **交替递归测试** — BN254 层（`C_BN254` 验证 2 个 Grumpkin sub-proofs）→ Grumpkin 层（`C_Grumpkin` 验证 2 个 BN254 proofs）交替，深度 4 层闭环通过

## Phase 10：预编译电路

- [ ] 预编译电路注册表实现
- [ ] Poseidon 哈希电路实现 — 约束数 ≈ 200/round
- [ ] Poseidon 电路输出与 host `poker_protocol::crypto::poseidon` 一致测试通过
- [ ] SHA-256 电路实现 — 约束数 ≈ 25,000/block，通过 lookup 优化
- [ ] SHA-256 电路输出与 `sha2` crate 一致测试通过
- [ ] ECDSA 验签电路实现 — **实际约束数 ≈ 110,000**（基于 `__mulsi3` shift-add × 256 次标量乘 + 哈希 + 最终比较）
- [ ] ECDSA 正例签名通过测试
- [ ] **ECDSA soundness 负例测试 — 篡改 msg / sig / pubkey 必须失败**
- [ ] `ZkShuffleCcsCircuit` 已从 `poker_l1/src/offline/ccs.rs` 迁移到 `poker_zkvm/src/precompiles/zk_shuffle.rs`
- [ ] `poker_l1` 通过 `pub use` re-export 引用迁移后的 `ZkShuffleCcsCircuit`
- [ ] 既有单元测试引用路径已更新

## Phase 11：poker_l1 集成（v1.2 CcsInstance 诚实 BREAKING + CheckinTx proof_kind 序列化 + scheme_id 映射）

- [ ] **旧 `CcsInstance`（hash-based）标记 `#[deprecated(note = "Use poker_zkvm::fold::CcsInstance instead")]`**
- [ ] **v1.2 `LegacyCcsInstanceAdapter` 诚实 BREAKING 实现** — 仅用于过渡期**编译兼容**，返回 `Err(Other("legacy hash-based instance cannot be really folded — hash is one-way, cannot recover matrices"))`，**不参与真实证明生成**；旧调用方在 Production 下会失败
- [ ] `poker_l1/src/offline/ccs.rs` 中 `fold_step` 内部调用 `poker_zkvm::fold::fold_step`（接受新 `CcsInstance` 类型，**外部 trait 签名变更**，既有调用方必须迁移，无法透明兼容）
- [ ] `poker_l1/src/offline/ccs.rs` 中 `fold_loop` 内部调用 `poker_zkvm::fold::fold_loop`（同 BREAKING）
- [ ] blake2b 哈希链冒充逻辑已移除
- [ ] `CcsCircuit` trait 一并迁入 `poker_zkvm::precompiles`，`poker_l1` 通过 `pub use poker_zkvm::precompiles::CcsCircuit;` re-export
- [ ] 既有单元测试断言改为真实折叠语义
- [ ] **迁移示例文档已提供**（既存调用方如何迁移）— 含 `LegacyCcsInstanceAdapter` 失败语义说明
- [ ] `ProofKind` 枚举已定义（`ZkShuffle` / `Zkvm`）
- [ ] **v1.2 scheme_id 映射** — `SCHEME_ZKSHUFFLE = 4`（新增）/ `SCHEME_HYPERNOVA = 1`（既有）；`ProofKind::ZkShuffle → SCHEME_ZKSHUFFLE` / `ProofKind::Zkvm → SCHEME_HYPERNOVA`
- [ ] **v1.2 `CheckinTx` 新增 `proof_kind: ProofKind` 字段** — `proof_kind` 作为 1-byte 前缀进入 `signing_hash` 输入（**BREAKING — 破坏旧签名，升级时所有在途 `CheckinTx` 须在 `PRODUCTION_GRACE_BLOCKS` 内重提交或失效**；非 backward-compatible）
- [ ] `execute_checkin` 按 `scheme_id` 分派 verifier（`scheme_id=4` → zk_shuffle verifier；`scheme_id=1` → `poker_zkvm::verifier::verify_production`）；`proof_kind` 与 `scheme_id` 不一致返回 `ProofKindMismatch`
- [ ] **v1.4 修正 Min3-004 — grace 期签名形式分派** — verifier 按 `scheme_id` 反推期望的签名形式（`scheme_id=4` 期望旧签名无 `proof_kind` 字段；`scheme_id=1` 期望新签名含 `proof_kind` 字段），不一致返回 `SignatureFormMismatch`（**删除 v1.2 残留"同时接受带/不带 proof_kind 签名"表述**）
- [ ] `PartialCheckinTx` 同样新增 `proof_kind` 字段，序列化策略与 `CheckinTx` 一致
- [ ] 集成测试 — Rust 代码 → ZKVM proof → `CheckinTx { scheme_id: SCHEME_HYPERNOVA, proof_kind: ProofKind::Zkvm }` 上链 → 链上验证通过
- [ ] **v1.2 soundness 负例测试** — `proof_kind` 与 `scheme_id` 不一致必须返回 `ProofKindMismatch`

## Phase 11.5：治理参数与 gas 调整 — **新增**（v1.2 补 6 项 Proof 字段长度上限 + production_switch_height）

- [ ] `poker_l1/src/vm/gas_table.rs` 中 `GAS_HYPERNOVA_VERIFY` 从 50000 → 300000（**v1.2 覆盖 Spartan pairing + final exp + IPA verify log(N) 轮 MSM + 余量；Phase 12 实测校准**）
- [ ] 新增 `GAS_ZKVM_POSEIDON_BASE / PER_BLOCK` 常量
- [ ] 新增 `GAS_ZKVM_SHA256_PER_BYTE` 常量
- [ ] 新增 `GAS_ZKVM_ECDSA_VERIFY = 100000` 常量
- [ ] 新增 `GAS_ZKVM_READ_STATE_PER_SLOT` 常量
- [ ] **治理敏感参数清单扩展**（`governance_params.rs` 或对应文件）：
  - [ ] `MAX_ZKVM_TRACE_STEPS = 1,048,576` 已加入 90% quorum 敏感参数表
  - [ ] `MAX_ZKVM_MEMORY = 16MB` 已加入
  - [ ] `MAX_ZKVM_PROOF_SIZE = 64KB` 已加入
  - [ ] `ZKVM_BATCH_SIZE = 1024` 已加入（含一致性约束 `MAX_ZKVM_TRACE_STEPS / ZKVM_BATCH_SIZE ≤ MAX_FOLD_STEP_COUNT`）
  - [ ] `MAX_RECURSION_DEPTH = 16` 已加入
  - [ ] `MAX_TRACE_HOST_MEMORY = 512MB` 已加入
  - [ ] `PRODUCTION_GRACE_BLOCKS = 7200` 已加入
  - [ ] `GAS_HYPERNOVA_VERIFY = 300000` 已加入
  - [ ] **v1.3 修正 M2-002 — Proof 字段长度上限参数（单项子分配，和 ≤ 总上限 ≈ 48KB < 64KB）**（防 verifier OOM DoS）：`MAX_PUBLIC_IO_SIZE = 8KB` / `MAX_FOLDED_INSTANCE_SIZE = 8KB` / `MAX_SUMCHECK_PROOF_SIZE = 16KB` / `MAX_PCS_OPENING_SIZE = 8KB` / `MAX_EVENT_HASHES_COUNT = 256`（256 × 32 = 8KB）
  - [ ] **v1.2 新增 `production_switch_height` 字段** — `GovernanceParams` 一次性写入字段（治理切换 `verifier_status` 从 `Stub` 到 `Production` 时写入当前 block height，grace 期起算点；grace 期结束后可清零；非持续调整参数，但写入须 90% quorum）
- [ ] 单元测试 — 所有敏感参数调整须 90% quorum + timelock
- [ ] 单元测试 — `ZKVM_BATCH_SIZE` 调整后一致性约束 `MAX_ZKVM_TRACE_STEPS / ZKVM_BATCH_SIZE ≤ MAX_FOLD_STEP_COUNT` 生效
- [ ] **v1.2 单元测试 — `production_switch_height` 一次性写入后不可改（除非 grace 期结束清零）**

## Phase 12：端到端集成测试

- [ ] `examples/fibonacci/` 示例已创建
- [ ] `examples/sha256_chain/` 示例已创建
- [ ] `examples/poker_hand_eval/` 示例已创建
- [ ] fibonacci (N=100) 完整闭环测试通过（compile + run + prove + verify）
- [ ] sha256_chain (10 次哈希) 完整闭环测试通过
- [ ] poker_hand_eval (5 张牌评估) 完整闭环测试通过
- [ ] criterion 性能基准测试 — prover 时间 vs trace 步数（100 / 1000 / 10000 步）
- [ ] criterion 性能基准测试 — proof 大小 vs trace 步数
- [ ] criterion 性能基准测试 — verifier 时间（应与 trace 步数无关，~ ms 级）
- [ ] **soundness 端到端测试**：
  - [ ] 恶意 ELF（含未支持指令）被 `validate_elf` 拒绝
  - [ ] 恶意 ELF（含段溢出地址）被 `validate_elf` 拒绝
  - [ ] 恶意 prover 篡改 witness 后 proof 必须 verify 失败
  - [ ] 恶意 prover 伪造 multiplicity 后 lookup 必须失败
  - [ ] 恶意 prover 篡改 trace 后 CCS satisfied_by 必须失败
  - [ ] 恶意 prover 调用非白名单 slot 必须返回 `InvalidSlot`

## Phase 13：文档

- [ ] `poker_zkvm/README.md` 快速上手指南已编写
- [ ] `docs/38-1-zkvm-architecture.md` 架构文档已编写
- [ ] `docs/38-2-zkvm-compiler-guide.md` 编译器使用指南已编写
- [ ] `docs/38-3-zkvm-syscall-reference.md` Syscall 参考已编写
- [ ] **`docs/38-4-zkvm-migration-guide.md` 从既有 hash-based CcsInstance 迁移到新类型的指南已编写**

## 安全与合规检查

- [ ] `poker_zkvm` crate 全模块 `deny(unsafe_code)` 生效
- [ ] 任何 unsafe 块（仅限 FFI 调用 arkworks / halo2）附安全不变式注释
- [ ] MAX_ZKVM_TRACE_STEPS = 1,048,576 强制
- [ ] MAX_ZKVM_MEMORY = 16MB 强制
- [ ] MAX_ZKVM_PROOF_SIZE = 64KB 强制
- [ ] MAX_TRACE_HOST_MEMORY = 512MB 强制
- [ ] MAX_RECURSION_DEPTH = 16 强制
- [ ] ZKVM_BATCH_SIZE = 1024 强制（含 instances.len() ≤ MAX_FOLD_STEP_COUNT 一致性约束）
- [ ] **v1.3 修正 M2-002 — Proof 字段长度上限强制（总长度优先 + 单项子分配）** — `MAX_PUBLIC_IO_SIZE = 8KB` / `MAX_FOLDED_INSTANCE_SIZE = 8KB` / `MAX_SUMCHECK_PROOF_SIZE = 16KB` / `MAX_PCS_OPENING_SIZE = 8KB` / `MAX_EVENT_HASHES_COUNT = 256`（256 × 32 = 8KB）；**反序列化先校验总长度 ≤ 64KB 不分配缓冲区，再校验单项上限**（防 verifier OOM DoS；v1.2 单项 64KB×3+16KB=208KB > 总 64KB 矛盾，v1.3 修正）
- [ ] 上链 proof ≤ 10KB（通过 Spartan / Groth16 压缩）
- [ ] **GAS_HYPERNOVA_VERIFY = 300000**（**v1.3 修正 M2-005 — Spartan 递归压缩 IPA verify，链上仅 ~160k；v1.4 修正 Min3-006 — 补 proof 反序列化等附加项后 ~170-180k × 1.5 ≈ 255-270k < 300k，余量较紧，Phase 12 实测后若超 280k 须上调；IPA verify ~1000k 由 prover off-chain 承担**）
- [ ] Fiat-Shamir transcript 严格按 spec 顺序 absorb
- [ ] **v1.2 fold 阶段 absorb 含 `ccs_commitment` + `lcccs_witness_commitment` + `ccccs_witness_commitment`**（绑定矩阵内容与 witness 防 challenge 派生后替换）
- [ ] length-prefixing 防歧义（`"ab"+"c"` vs `"a"+"bc"` 产生不同 challenge）
- [ ] canonical 编码（域元素 32 bytes LE，commitment 33 bytes compressed）
- [ ] ccs_struct_params 绑定（防 weak CCS 结构重放）
- [ ] 域分离常量已应用（HYPERNOVA_FOLD / SUMCHECK / LOOKUP / MEM_CHECK / PCS_OPEN）
- [ ] proof 不包含 witness 明文
- [ ] **v1.3 MVP transparent 风险声明枚举具体泄漏字段** — witness commitment / sumcheck 各轮求值多项式 / PCS opening 的 `z'(r_y)` 求值会泄漏；具体敏感数据不得在 MVP 阶段进入 ZKVM 计算
- [ ] `verifier_status` 治理切换保持既有 NEW-C1 流程（90% quorum + timelock）
- [ ] **v1.2 Production grace period 双通道实现** — 治理切换时记录 `production_switch_height` 到 `GovernanceParams`；切换后 `PRODUCTION_GRACE_BLOCKS = 7200` 内 `proof_kind=ZkShuffle` 须 `proof_hash` 匹配链上 `last_partial_fold.proof_partial_hash` 才走 stub，`proof_kind=Zkvm` 强制 Production；grace 期后 stub 关闭
- [ ] **v1.3 修正 M2-003 — `last_partial_fold.proof_partial_hash` 链上不可变约束** — `PartialCheckinTx` 执行时校验 `last_partial_fold.proof_partial_hash == None || == tx.proof_partial_hash`（首次设置或幂等允许；覆盖已有值返回 `PartialFoldHashImmutable`）；execute_checkin 完成后清零（**v1.4 Min3-002 — 游戏终结判定 = `is_terminal(ack_chain)` 或 `game_over=true`**）；grace 期结束强制清零；**v1.4 Min3-003 — 幂等范围 = 整个 PartialCheckinTx 内容幂等**
- [ ] **v1.3 修正 M2-004 — 单 proof_kind 单签名形式** — verifier 按 `scheme_id` 反推期望签名形式（`scheme_id=4` 期望旧签名无 proof_kind 字段；`scheme_id=1` 期望新签名含 proof_kind 字段），不一致返回 `SignatureFormMismatch`；切换前仅接受旧签名，grace 期内按 scheme_id 分派，grace 期后仅接受新签名
- [ ] Stub + 主网 chain_id 拒绝 OffChain checkout 行为不变
- [ ] **ABI 版本化** — proof header 含 `ZKVM_ABI_VERSION = 1`，链上 verifier 校验
- [ ] **v1.2 `ZkPublicIo` 字段完整** — 含 `randomness_seed` / `event_hashes_root` / `state_slot_root` 三个新字段；`ZK_PUBLIC_IO_VERSION = 2`；反序列化对旧 version 1 提供 fallback（缺省字段填零 hash），但 Production verifier 强制 version 2
- [ ] **`zkvm_read_state` slot 白名单强制 + v1.2 Merkle 绑定** — 仅允许 `SLOT_GAME_STATE` / `SLOT_PLAYER_HANDS` / `SLOT_POT_AMOUNT` / `SLOT_CURRENT_TURN` / `SLOT_ACK_CHAIN`；prover 须提供 Merkle 证明 slot 值在 `public_io.state_slot_root` 下；跨 batch 一致性约束 `state_slot_root` 相同
- [ ] **v1.2 `zkvm_get_randomness` deterministic 派生函数绑定上下文** — `output = Poseidon(seed || initial_commitment || final_commitment || call_counter)`，防 prover grinding
- [ ] **v1.2 `zkvm_emit_event` event_hash 绑定 step_index** — `event_hash = Poseidon(content_hash || step_index)`，`event_hashes_root` = 数组 Merkle root，进 `public_io`
- [ ] **ELF 强化校验全部生效** — 段地址（**v1.2 checked_add**）/ entry point / relocation / 指令子集 / 段大小 / **v1.2 拒绝 PT_DYNAMIC + DT_NEEDED / 校验 e_shoff 不溢出 / TOCTOU 消除**
- [ ] **LogUp 公式正确 + v1.2 β 派生时机严格** — `Σ m_i/(β - t_i) == Σ 1/(β - f_j)`，table 先于 witness 承诺，**β 必须在 witness 承诺之后派生**
- [ ] **v1.2 内存 byte-level permutation** — key 为 `(byte_addr, byte_val, step_index)`，每 byte 单独记录；混合尺寸重叠访问正确匹配；未初始化读取返回 `UninitializedRead`
- [ ] **u32 算术约束完整** — overflow_bit / shift bit decomposition / 除零语义
- [ ] **v1.2 CcsInstance 类型迁移诚实 BREAKING** — 旧 hash-based 标记 `#[deprecated]`；`LegacyCcsInstanceAdapter` 返回 `Err` 仅编译兼容；新类型含矩阵结构与域元素 witness；`fold_step`/`fold_loop` 外部 trait 签名变更，既有调用方必须迁移
- [ ] **v1.2 CheckinTx 新增 proof_kind 字段 BREAKING 序列化** — `proof_kind` 作为 1-byte 前缀进入 `signing_hash` 输入（破坏旧签名）；`scheme_id` 映射：`ZkShuffle → SCHEME_ZKSHUFFLE=4` / `Zkvm → SCHEME_HYPERNOVA=1`；`proof_kind` 与 `scheme_id` 不一致返回 `ProofKindMismatch`
- [ ] **v1.3 Hypernova 核心等式修正（C2-001/002/003 + M2-001）** — `Lcccs.v_L` 向量化（`Vec<FieldElement>`，长度 = `num_matrices`，在 `r_x_L` 处求值）；`u_L` 为标量（relaxed 可非 0）；**CCCCS 不存储 v_C**（v_C[j](X) 是多项式，折叠时在 r_x_L 处通过内层 batched sumcheck 计算）；fold challenge `r` 标量化；**外层 sumcheck claimed sum = `u'` 标量**（非 v' 向量，非 0）；**内层 batched sumcheck 单 `r_y`**（非 t 个 r_{y_j}）；`combined_point = r_y`（单 challenge）；PCS opening 在 `r_y` 处打开 folded witness `z'` 得 `z_at_point = z'(r_y)`（不是 v'，也不是 u'）；**LCCCS relaxed 约束 `Σ_i c_i · Π_{j∈S_i} v'[j] = u'`**（非 = 0）；verifier 校验 `u'` + `v'` + `z_at_point` 三者通过外层 sumcheck + 内层 batched sumcheck 链关联
- [ ] **v1.2 IPA NUMS generators + challenge 派生** — generators 通过 `hash_to_curve` 派生（非可信 setup）；`open` 前 absorb `PCS_OPEN_TAG || commitment || point`（绑定防 proof 复用）；每轮 challenge 从 transcript 派生
- [ ] **v1.2 CycleFold 递归 verifier 电路定义** — `C_BN254` / `C_Grumpkin` 电路约束 Hypernova verifier 步骤（反序列化 / PCS verify / 外层 sumcheck / 内层 sumcheck 链 / cross-language claim / transcript 一致性）；约束数 ≈ 100,000-200,000/层
- [ ] **治理参数清单完整** — v1.2 共 14 项 ZKVM 参数（8 项 v1.1 + 5 项 MAX_* + production_switch_height）全部加入 90% quorum 敏感参数表（**v1.3 修正 M2-002 — 5 项 MAX_* 子分配为 8KB/8KB/16KB/8KB/256，和 ≤ 64KB**；**v1.4 修正 M3-001 — 治理参数清单默认值与反序列化子分配同步（8KB/8KB/16KB/8KB），消除 v1.2 残留 64KB/64KB/64KB/16KB 矛盾**）

## Soundness 负例测试汇总

- [ ] Phase 1.5 PCS — 篡改 eval / proof / commitment 必须 verify 失败
- [ ] **v1.2 Phase 1.5 PCS — 复用 proof 到不同 point 必须 verify 失败**（防 proof 重放攻击）
- [ ] Phase 4 syscall — 非白名单 slot 调用必须返回 `InvalidSlot`
- [ ] **v1.2 Phase 4 syscall — 伪造 slot 值（无 Merkle 证明）必须失败；跨 batch `state_slot_root` 不一致必须失败**
- [ ] **v1.2 Phase 5 memory — 字节级 aliasing 攻击必须失败；permutation 顺序伪造必须失败；混合尺寸重叠访问正确匹配**
- [ ] **v1.2 Phase 5 memory — 未初始化读取必须返回 `UninitializedRead`**
- [ ] Phase 5 lookup — prover 在看到 β 后调整 multiplicity 必须失败；伪造 multiplicity 必须失败
- [ ] **v1.2 Phase 5 lookup — β 派生时机错误（在 witness 承诺前派生）必须被 transcript 校验拒绝**
- [ ] Phase 5.5 serialize — 篡改 magic / abi_version 必须失败
- [ ] **v1.2 Phase 5.5 serialize — 超长字段（如 `public_io_len = 0xFFFFFFFF`）必须立即返回 `InvalidZkProofFormat` 不 OOM**
- [ ] **v1.3 Phase 5.5 serialize — 单项 8KB 通过但总和 > 64KB 的恶意 proof 必须在第 1 步总长度优先校验失败（不分配缓冲区）**
- [ ] Phase 6 fold_step — 篡改 lcccs / ccccs 任一字段必须 fold 失败或 verify 失败
- [ ] Phase 6 sumcheck — 篡改 claimed_sum / proof 必须失败
- [ ] **v1.3 Phase 6 sumcheck — 篡改 `r_y` 与 `z_at_point` 关联必须失败**
- [ ] Phase 6 fold_loop — 篡改 folded_instance / witness_commitment / final_sumcheck / pcs_opening 任一字段必须 verify 失败
- [ ] **v1.3 Phase 6 fold_loop — 篡改 r_y / z_at_point 必须 verify 失败**
- [ ] Phase 7 Spartan — 篡改 Spartan proof 必须失败
- [ ] Phase 8 verifier — 篡改 proof 任一字段必须失败
- [ ] **v1.3 Phase 8 verifier — 篡改 `z_at_point` 与 `u'`/`v'` 关联（独立伪造三者）必须失败**
- [ ] **v1.2 Phase 8 grace period — ZkShuffle + 不匹配 proof_hash 必须失败；grace 期后 stub 必须关闭**
- [ ] **v1.3 Phase 8 M2-003 — 覆盖已有 `proof_partial_hash` 必须返回 `PartialFoldHashImmutable`**
- [ ] **v1.3 Phase 8 M2-004 — `scheme_id` 与签名形式不匹配必须返回 `SignatureFormMismatch`**
- [ ] **v1.4 Phase 8 Min3-001 — `total_payload` 求和 wrap 攻击（构造 `event_hashes_count` 使 `*32` 溢出）必须被 `checked_mul` 拦截**
- [ ] **v1.4 Phase 8 Min3-002 — 非终态游戏 `execute_checkin` 不得清零 `proof_partial_hash`；终态游戏（`is_terminal` 或 `game_over=true`）必须清零**
- [ ] **v1.4 Phase 8 Min3-003 — 幂等 `proof_partial_hash` 但 `intermediate_commitment`/`ack_chain_partial` 不同必须返回 `PartialFoldHashImmutable`**
- [ ] **v1.4 Phase 8 M3-002 — grace 期后 `scheme_id=4` 必须走 ZkShuffle Production verifier（非 stub），旧签名必须失败**
- [ ] Phase 9 CycleFold — 篡改任一 sub_proof 必须聚合失败或最终 verify 失败
- [ ] **v1.2 Phase 9 `C_BN254` — 篡改 Grumpkin sub-proof 任一字段必须电路约束失败**
- [ ] **v1.2 Phase 9 `C_Grumpkin` — 篡改 BN254 sub-proof 任一字段必须电路约束失败**
- [ ] Phase 10 ECDSA — 篡改 msg / sig / pubkey 必须失败
- [ ] **v1.2 Phase 11 CheckinTx — `proof_kind` 与 `scheme_id` 不一致必须返回 `ProofKindMismatch`**
- [ ] Phase 12 端到端 — 恶意 ELF / 篡改 witness / 伪造 multiplicity / 篡改 trace / 非白名单 slot 均被拒绝
- [ ] **v1.2 Phase 12 端到端 — 恶意 ELF wrap 攻击 / PT_DYNAMIC 注入 / TOCTOU 攻击 均被 `validate_elf` 拒绝**
