# Hypernova ZKVM（支持 Rust 直接编译）Spec

> **change-id**：`build-hypernova-zkvm`
> **依赖**：`build-poker-l1-chain`（spec.md FROZEN 2026-06-27）— 本 spec 为 v2 backlog 增量
> **参考实现**：`poker_l1/src/offline/hypernova.rs`（stub）/ `poker_l1/src/offline/ccs.rs`（stub）/ `poker_l1/src/vm/`（既有 rBPF VM）
> **版本**：v1.4（v1.3 密码学专家复核后修订 — 8 项修复：**2 MAJOR**：M3-001 治理参数清单 MAX_* 默认值与反序列化子分配矛盾（64KB/64KB/64KB/16KB → 8KB/8KB/16KB/8KB 同步）/ M3-002 grace 期后 scheme_id=4 分支歧义 → 明确走 ZkShuffle Production verifier（非 stub）；**6 MINOR**：Min3-001 M2-002 total_payload 求和显式 checked_add/checked_mul 防 32-bit wrap / Min3-002 M2-003 "游戏终结"判定条件明确（ack_chain 终态或 game_over 标记）/ Min3-003 M2-003 幂等重提交范围明确（整个 PartialCheckinTx 内容幂等，非仅 proof_partial_hash）/ Min3-004 tasks/checklist 残留 v1.2 "同时接受带/不带 proof_kind 签名"表述删除 / Min3-005 外层 sumcheck 公式 G(X) 显式括号消除运算符优先级歧义 / Min3-006 M2-005 gas 估算补 proof 反序列化等附加项明细（~170-180k × 1.5 ≈ 255-270k < 300k））
> **v1.3 变更摘要**（v1.2 密码学专家复核后修订）：修正 Hypernova 折叠核心等式 — C2-001 内层 batched sumcheck 产生单 `r_y`（非 t+1 维元组）/ C2-002 CCCCS 实例不存储 `v_C`（多项式，折叠时在 r_x_L 求值）/ C2-003 外层 sumcheck claimed sum = `u'` 标量（非 v' 向量）/ M2-001 LCCCS relaxed 约束 = `u'`（非 = 0）/ M2-002 proof 字段长度上限矛盾 → 总长度优先 + 单项子分配 / M2-003 grace period `last_partial_fold` 链上不可变约束（新增 `PartialFoldHashImmutable`）/ M2-004 grace period 签名 malleability → 单 proof_kind 单签名形式（新增 `SignatureFormMismatch`）/ M2-005 gas 成本分析澄清 → Spartan 压缩 IPA verify 链上仅 ~160k
> **v1.2 变更摘要**（v1.1 独立审核后修订）：修正 Hypernova 折叠核心等式 — cross-language claim PCS opening 改为打开 witness 多项式 / `Lcccs.v` 向量化为 `Vec<FieldElement>` / fold challenge `r` 标量化 / transcript 补吸收矩阵承诺与 witness commitment / LogUp `β` 在 witness 承诺后派生 / 内存一致性改 byte-level permutation / proof 反序列化字段长度上限校验 / ELF TOCTOU + checked_add + PT_DYNAMIC 拒绝 / `ZkPublicIo` 新增 `randomness_seed` + `event_hashes_root` + `state_slot_root` / slot 值 Merkle 绑定 / event hash 绑定 step_index / randomness 派生函数绑定 initial/final_commitment + call_counter / CycleFold 递归 verifier 电路定义 / CcsInstance 迁移诚实 BREAKING 声明 / CheckinTx.proof_kind 序列化策略 / gas 计费补 IPA verify 成本 + Phase 12 实测校准 / Phase 5.5 依赖修正 / IPA challenge 派生与 NUMS generators / Production grace period 改为 proof_kind 双通道 + 切换高度绑定

## Why

当前 zchain 的 OffChain 模式仅支持 `poker_protocol::zk_shuffle` 一类专用电路，无法让开发者用普通 Rust 代码编写扑克规则、AI 对手、随机性协议等链下逻辑并自动生成 ZK 证明。现有 `HypernovaVerifier` 与 `fold_step`/`fold_loop` 均为 stub（blake2b 哈希链冒充折叠），既无真实折叠算法，也无任何前端能将 Rust 编译为可证电路。

为实现「编写 Rust → 编译 → 链下执行 → 生成 Hypernova proof → 链上验证」的完整闭环，需引入一个新的 ZKVM 子系统，复用既有 `ZkVerifierRegistry` / `ZkPublicIo` / `verifier_status` 治理框架，独立于 `poker_l1/src/vm/` 的 rBPF 合约 VM（rBPF 用于链上合约，ZKVM 用于链下可证计算）。

## What Changes

* **新增** 独立 crate `poker_zkvm/`（workspace 新成员），实现基于 Hypernova + CCS 的零知识虚拟机
* **新增** Rust 前端编译流水线：Rust 源 → RV32I ELF（复用 rustc + LLVM RISC-V backend，禁用浮点 / atomics / 不支持特性）→ ZKVM 加载
* **新增** ZKVM ISA 执行引擎：解释 RV32I + 自定义 syscall 指令，产生 execution trace（PC / 寄存器 / 内存每步快照）
* **新增** Trace → CCS 约束编译器：将每 K 步指令的语义翻译为 1 个 CCS 实例（K = `ZKVM_BATCH_SIZE` 默认 1024，确保 N_CCS ≤ `MAX_FOLD_STEP_COUNT = 1000`）；CCS 矩阵 $M_1..M_t$ 表达「a la carte」每指令子电路
* **新增** 多项式承诺方案（PCS）模块：IPA over BN254（与 CycleFold cycle 兼容），含 commit/open/verify 协议
* **新增** 内存一致性电路（read-write check 模式，RAM as permutation，permutation key 含 `(addr, val, size, step_index)` 防 aliasing 攻击）
* **新增** Range check / 哈希等 lookup 协议（LogUp，公式 `Σ m_i/(β - t_i) == Σ 1/(β - f_i)`，table 先于 witness 承诺）
* **新增** Hypernova 真实折叠算法实现：LCCCS + CCCCS 折叠 + 外层 sumcheck + 内层 batched sumcheck + cross-language claim + Fiat-Shamir transcript（length-prefixing + canonical 编码 + CCS 结构参数 + **矩阵承诺 + witness commitment 绑定**，防 weak CCS 结构重放）
* **新增** 链上 verifier Production 实现：替换 `HypernovaVerifier::verify` 中的 `Err(Other)` 分支，校验 final sumcheck 等式 + folded instance cross-language claim。**关键数学定义（v1.3 对照原论文修正）**：
  - `Lcccs.v` 为 `Vec<FieldElement>`（每矩阵一个分量，长度 = `num_matrices`，在 `r_x_L` 处求值）
  - **`Ccccs` 不存储 `v_C` 字段**（v_C[j] 是多项式，折叠时在 r_x_L 处通过内层 sumcheck 计算）
  - fold challenge `r` 为**单标量**（FS 派生一个域元素），非向量
  - 折叠后 `v'_j = v_{L,j} + r·v_C[j](r_x_L)`（分量级，v_C[j](r_x_L) 通过内层 sumcheck 计算）
  - **sumcheck claimed sum 为 `u'`（标量，非 v' 向量）**，非 0
  - cross-language claim：PCS 在 **`combined_point = r_y`（单个 challenge，非元组）** 处打开 folded witness `z'` 得 `z'(r_y)`，verifier 校验 `Σ_j γ^j·v'[j] == (Σ_j γ^j·M_j(r_x_L, r_y))·z'(r_y)`；**不是** 直接打开得 `v'` 或 `u'`
  - **LCCCS 约束（relaxed）**：`Σ_i c_i · Π_{j∈S_i} v'[j] = u'`（u' 可非 0，非原始 CCS 的 = 0）
* **新增** CycleFold 递归聚合（BN254 / Grumpkin cycle）支持超长计算分段聚合，含递归终止条件（proof > 64KB 触发再聚合，直到 ≤ 64KB；最多 `MAX_RECURSION_DEPTH = 16` 层，超出 fail）
* **新增** Spartan / Groth16 最终压缩器（复用 `poker_l1/src/offline/groth16.rs`）；**BREAKING** 调整 `GAS_HYPERNOVA_VERIFY` 从 50000 → 300000（Spartan ≥ 2 pairing × 45k + final exp 60-80k + **IPA verify log(N) 轮 MSM ≈ 20 轮 × ~50k gas** + 50% 余量；本参数须在 Phase 12 性能基准实测后再次校准）
* **新增** ZKVM syscall 表（与 rBPF VM syscalls 解耦）：`zkvm_read_input` / `zkvm_commit_output` / `zkvm_poseidon` / `zkvm_sha256` / `zkvm_ecdsa_verify` / `zkvm_emit_event` / `zkvm_log` / `zkvm_panic` / `zkvm_get_randomness`（deterministic，从 host seed 派生） / `zkvm_read_state`（slot 白名单 + gas 按 slot 计费）
* **新增** 工具链：`cargo-zkvm` 子命令（编译 + 生成 proof + 验证），ELF 加载器（含强化校验：段地址 / entry point / relocation），trace 格式定义（含 host 内存上限 `MAX_TRACE_HOST_MEMORY = 512MB`）
* **新增** Proof 序列化布局规范（length-prefix + canonical field encoding + ABI 版本号 `ZKVM_ABI_VERSION = 1`）
* **新增** Witness 生成与盲化策略（trace → witness 向量映射；MVP transparent，witness 不盲化；ZK 版本留作 v2，明确风险声明）
* **复用** `poker_l1/src/offline/zk_verifier.rs` 的 `ZkVerifierRegistry` / `ZkPublicIo` / `VerifierStatus` 治理接口（**注意**：`ZkPublicIo` 需扩展字段，见下 BREAKING）
* **复用** `poker_l1/src/offline/groth16.rs` 既有 Groth16 verifier
* **BREAKING** `poker_l1/src/offline/zk_verifier.rs::ZkPublicIo` 结构扩展：新增 3 个字段 — `randomness_seed: Hash`（VRF 派生 seed，供 `zkvm_get_randomness`）/ `event_hashes_root: Hash`（所有 `event_hash` 的 Merkle root）/ `state_slot_root: Hash`（链上 state root 承诺，供 `zkvm_read_state` slot 值 Merkle 绑定）。序列化布局 bump 版本号 `ZK_PUBLIC_IO_VERSION = 2`；反序列化对旧格式（version 1，仅 7 字段）提供 fallback（缺省字段填零 hash），但 Production verifier 强制要求 version 2
* **BREAKING** `poker_l1/src/offline/ccs.rs` 中 `CcsInstance` 类型签名变更：原 hash-based `mat_commitments: Vec<Hash>` → 新结构含矩阵结构与域元素 witness。新建 `poker_zkvm::fold::CcsInstance`，`poker_l1` 旧 `CcsInstance` 标记 `#[deprecated]`。**诚实声明**：`LegacyCcsInstanceAdapter` 仅用于过渡期**编译兼容**（返回 `Err(Other("legacy hash-based instance cannot be really folded — hash is one-way, cannot recover matrices"))`），**不参与真实证明生成**；旧调用方在 Production 下会失败，必须重构以提供真实矩阵。`CcsCircuit` trait 一并迁入 `poker_zkvm`，`poker_l1` 通过 `pub use` re-export
* **BREAKING** `fold_step` / `fold_loop` 内部替换为真实 Hypernova 实现；**外部 trait 签名变更** — 参数类型从旧 hash-based `CcsInstance` 改为 `poker_zkvm::fold::CcsInstance`（含矩阵结构与域元素 witness）。既有调用方必须迁移到新类型，无法透明兼容
* **BREAKING** `GAS_HYPERNOVA_VERIFY` 从 50000 → 300000（覆盖 Spartan pairing + IPA verify + 余量；Phase 12 实测校准），加入 90% quorum 敏感参数表
* **BREAKING** `ZkShuffleCcsCircuit` stub 从 `poker_l1/src/offline/ccs.rs` 移除，迁入 `poker_zkvm::precompiles::zk_shuffle`；`CcsCircuit` trait 一并迁入 `poker_zkvm`，`poker_l1` 通过 `pub use poker_zkvm::precompiles::CcsCircuit;` re-export
* **BREAKING** `CheckinTx` 新增 `proof_kind: ProofKind` 字段（`ZkShuffle` / `Zkvm`）区分专用电路 proof vs ZKVM proof。**序列化策略**：`proof_kind` 作为 1-byte 前缀进入 `signing_hash` 输入（破坏旧签名 — 升级时所有在途 `CheckinTx` 须在 `PRODUCTION_GRACE_BLOCKS` 内重提交或失效）。`proof_kind` 与 `scheme_id` 映射：`ZkShuffle → SCHEME_ZKSHUFFLE`（新增 scheme_id=4）/ `Zkvm → SCHEME_HYPERNOVA`（既有 scheme_id=1）。grace 期内同时接受带/不带 `proof_kind` 的签名，但 verifier 强制按 `scheme_id` 分派，`proof_kind` 仅作辅助校验（与 `scheme_id` 不一致返回 `ProofKindMismatch`）
* **新增** Production verifier 升级 grace period：`verifier_status` 从 `Stub` → `Production` 切换后，**采用 proof_kind 双通道 + 切换高度绑定**：(1) 治理切换时记录 `production_switch_height` 到 `GovernanceParams`；(2) grace 期（`PRODUCTION_GRACE_BLOCKS = 7200`）内，仅允许 `proof_kind = ZkShuffle` 的旧 Stub proof 走 stub 路径，且 `proof_hash` 必须匹配链上已存 `last_partial_fold.proof_partial_hash`（仅允许在途游戏继续，不允许新游戏用 Stub proof）；(3) `proof_kind = Zkvm` 强制走 Production 路径；(4) grace 期结束后所有 proof 强制 Production 路径
* **非目标**（本 spec 不覆盖）：JIT 编译 ZKVM 字节码、GPU 加速 prover、与 rBPF VM 互操作、BLS12-381 / BW6-761 cycle 支持（v2）、真正 ZK（witness 盲化，v2）

## Impact

- **Affected specs**：
  - `build-poker-l1-chain/spec.md` Task 22（ZkVerifier trait）/ Task 23（Hypernova Proof）/ Task 26（CCS + fold step）/ Task 21（OfflineState checkin 路径）
  - `build-poker-l1-chain/spec.md` L497-525（可插拔 ZK 证明验证模块）/ L659-669（链下折叠证明）
  - 既有 90% quorum 敏感参数清单 — 新增 `GAS_HYPERNOVA_VERIFY` / `MAX_ZKVM_TRACE_STEPS` / `MAX_ZKVM_MEMORY` / `MAX_ZKVM_PROOF_SIZE` / `ZKVM_BATCH_SIZE` / `MAX_RECURSION_DEPTH` / `PRODUCTION_GRACE_BLOCKS`
- **Affected code**：
  - 新增 `poker_zkvm/` 整个 crate（compiler / isa / trace / constraints / pcs / fold / prover / verifier / syscalls / precompiles / cyclic / recursion / field / transcript / serialize / error）
  - 修改 `poker_l1/src/offline/zk_verifier.rs` — `ZkPublicIo` 新增 `randomness_seed` / `event_hashes_root` / `state_slot_root` 字段；序列化布局 bump `ZK_PUBLIC_IO_VERSION = 2`；`to_bytes`/`from_bytes`/`validate` 同步扩展
  - 修改 `poker_l1/src/offline/ccs.rs` — `fold_step`/`fold_loop` 调用真实 Hypernova 实现；旧 `CcsInstance` 标记 `#[deprecated]`；`LegacyCcsInstanceAdapter` 仅编译兼容返回 `Err`；`ZkShuffleCcsCircuit` + `CcsCircuit` trait 迁出
  - 修改 `poker_l1/src/offline/hypernova.rs` — `HypernovaVerifier::verify` Production 分支调用 `poker_zkvm::verifier::verify_production`；新增 grace period 双通道逻辑（proof_kind 分派 + `production_switch_height` 绑定）
  - 修改 `poker_l1/src/offline/state.rs` — `CheckinTx` 新增 `proof_kind: ProofKind` 字段进入 `signing_hash`；`execute_checkin` 按 `scheme_id` + `proof_kind` 分派 verifier；新增 `ProofKindMismatch` 错误
  - 修改 `poker_l1/src/vm/gas_table.rs` — `GAS_HYPERNOVA_VERIFY` 改为 300000；新增 ZKVM 相关 gas 常量
  - 修改 `poker_l1/src/offline/governance_params.rs`（若存在）— 新增 6 项 ZKVM 治理参数 + `production_switch_height` 字段到敏感参数表
  - 修改根 `Cargo.toml` — 增加 `poker_zkvm` workspace 成员
- **依赖关系**：本 spec 完成后，OffChain 模式从「仅支持 zk_shuffle 专用电路」扩展到「支持任意 Rust 代码生成 Hypernova proof」

## ADDED Requirements

### Requirement: ZKVM 独立 crate 与 workspace 集成

系统 SHALL 新增 `poker_zkvm` crate 作为 workspace 成员，独立于 `poker_l1` 的 rBPF VM。`poker_zkvm` SHALL 提供 `compiler` / `isa` / `trace` / `constraints` / `pcs` / `fold` / `prover` / `verifier` / `syscalls` / `precompiles` / `cyclic` / `recursion` / `field` / `transcript` / `serialize` / `error` 子模块，并通过 `pub use` 暴露稳定 API。

#### Scenario: crate 加入 workspace

- **WHEN** 开发者在根 `Cargo.toml` 添加 `poker_zkvm = { path = "poker_zkvm" }` 到 workspace members
- **THEN** `cargo build` 编译 `poker_zkvm` crate，无外部 C 依赖（仅依赖 Rust crate 生态：arkworks / halo2 / rayon 等）
- **AND** `poker_l1` 通过 `poker_zkvm = { path = "../poker_zkvm" }` 依赖引用 ZKVM 接口

#### Scenario: `deny(unsafe_code)`

- **WHEN** 编译 `poker_zkvm` crate
- **THEN** `#![deny(unsafe_code)]` 生效，仅在 FFI 调用 arkworks / halo2 时通过 `safe` wrapper 隔离
- **AND** 任何 unsafe 块需附安全不变式注释

### Requirement: 字段选择与算术包装（含完整约束规范）

系统 SHALL 选择 Hypernova 工作域并定义 Rust 整数类型到域元素的算术包装规则。**MVP 固定 BN254 + Grumpkin cycle**（不提供 BLS12-381 备选，BLS12-381 + BW6-761 cycle 留作 v2）。

#### Scenario: 域选择

- **WHEN** 初始化 ZKVM
- **THEN** 工作域 = BN254 标量域 $F_r$（$r = 21888242871839275222246405745257275088548364400416034343698204186575808495617$）
- **AND** 辅助曲线 = Grumpkin（cycle 性质：BN254 标量域 == Grumpkin base field，反之亦然）
- **AND** 域选择通过 `ZkvmField` trait 抽象，但 MVP 阶段仅实现 BN254（不允运行时切换）

#### Scenario: `ZkvmField` trait 语义明确

- **WHEN** 调用 `from_u32_with_wrap(v: u32)`
- **THEN** 返回 `FieldElement::from(v)`（mod p，wrap 语义 = mod p）
- **WHEN** 调用 `to_u32(fe: FieldElement) -> u32`
- **THEN** 返回 `fe.to_bigint().rem_euclid(2^32) as u32`（mod $2^{32}$ 抽取，使用 `rem_euclid` 确保非负 — Rust `%` 对负 bigint 是截断而非取模，会返回负值）
- **AND** trait 文档明确说明两种 wrap 语义差异

#### Scenario: u32 算术约束（完整规范）

- **WHEN** Rust 代码执行 `a + b`（u32）
- **THEN** ZKVM 执行引擎按 RISC-V 语义计算（mod $2^{32}$），结果存入寄存器
- **AND** 电路约束：
  1. `result_field = a_field + b_field mod p`
  2. `result_u32 = result_field mod 2^{32}`
  3. range check `result_u32 < 2^{32}`（通过 LogUp u32 表）
  4. `overflow_bit = (a + b >= 2^{32}) ? 1 : 0`（通过比较电路：若 `a_field + b_field - result_field != 0` 则 `overflow = 1` 且 `result_field + 2^32 == a_field + b_field`）

#### Scenario: 移位指令约束（shift amount bit decomposition）

- **WHEN** 执行 SLL / SRL / SRA（shift amount = `rs2 & 0x1F`）
- **THEN** shift amount 必须 bit-decompose 为 5 个 bit（s_4, s_3, s_2, s_1, s_0），每个 bit range check ∈ {0, 1}
- **AND** 通过 selector 多项式选择 shift amount ∈ {0, 1, 2, ..., 31} 对应的输出值
- **AND** SRA（算术右移）须约束符号位扩展：若 `rs1[31] == 1`，高位填充 1；否则填充 0

#### Scenario: 除法与除零语义（RV32M 启用时）

- **WHEN** 执行 DIV / DIVU / REM / REMU（仅 RV32M 启用时）
- **THEN** RISC-V 除零语义：
  - `DIV(x, 0) = -1`（即 `0xFFFFFFFF`）
  - `DIVU(x, 0) = 2^32 - 1`
  - `REM(x, 0) = x`
  - `DIV(MIN_INT, -1) = MIN_INT`（即 `0x80000000`）
  - `REM(MIN_INT, -1) = 0`
- **AND** 电路须显式约束这些边界情况（不能直接用域除法）
- **AND** 默认禁用 RV32M 时，编译器自动链接 `__mulsi3` / `__divsi3` / `__modsi3` 软件库

#### Scenario: 乘法软件库约束预算

- **WHEN** 链接 `__mulsi3`（shift-add 实现，32 轮迭代）
- **THEN** 单次 u32 乘法约束数 ≈ 32 × 6 = 192（每轮 1 shift + 1 add + 1 cond_add + 1 range check + 1 bit + 1 carry）
- **AND** ECDSA 验签电路须重算约束预算：secp256k1 标量乘 ≈ 256 次 mul + 256 次 add ≈ 256 × (192 + 6) ≈ 50,688 约束/次标量乘
- **AND** 完整 ECDSA 验签 ≈ 2 次标量乘 + 哈希 + 最终比较 ≈ 110,000 约束（不是 100k；以重算值为准）

### Requirement: Rust 前端编译流水线

系统 SHALL 提供 `cargo-zkvm` 工具，将用户 Rust 代码编译为 RV32I ELF 文件供 ZKVM 执行。编译 SHALL 复用 rustc + LLVM RISC-V backend，禁用浮点 / atomics / SIMD / inline asm。

#### Scenario: 标准编译

- **GIVEN** 用户在 `my_circuit/src/main.rs` 编写 `fn main() { ... }` 入口
- **WHEN** 执行 `cargo zkvm build`
- **THEN** 工具调用 `rustc --target riscv32i-unknown-none-elf -- -C panic=abort -C opt-level=3` 编译
- **AND** 输出 ELF 文件到 `target/riscv32i-unknown-none-elf/release/my_circuit.elf`
- **AND** 校验 ELF 不含未支持指令（如 `fence.i` / 浮点 load/store）— 违反返回 `UnsupportedInstruction`

#### Scenario: ELF 强化校验（消除 TOCTOU + 防 wrap 攻击）

- **WHEN** `validate_elf(elf_bytes: &[u8]) -> Result<ElfMetadata, ZkvmError>` 被调用（**接受字节切片而非路径**，消除 TOCTOU — validate 后立即返回已解析的 `ElfMetadata`，`load_elf` 接受 `ElfMetadata` 而非路径，避免文件被中间修改）
- **THEN** 校验以下全部条件，任一失败返回具体错误：
  1. 所有 `.text` / `.rodata` / `.data` / `.bss` 段地址在 `[0, MAX_ZKVM_MEMORY)` 范围内，**且 `addr.checked_add(size) <= MAX_ZKVM_MEMORY`（使用 `checked_add` 防段地址 + 段大小 wrap 攻击 — 如 `addr=0xFFFFFFF0, size=0x20` 会 wrap 到 0x10 绕过上限）**
  2. entry point 在 `.text` 段范围内
  3. 段之间无重叠
  4. 所有 relocation 入口指向有效段内偏移
  5. ELF magic / class（ELF32）/ endian（little）/ machine（EM_RISCV）正确
  6. `.text` 段所有指令属于 RV32I 子集（拒绝 fence.i / 浮点 / atomics / SIMD / compressed 指令）
  7. `.text` 段大小 ≤ `MAX_TEXT_SIZE = 8MB`
  8. 总加载内存 ≤ `MAX_ZKVM_MEMORY = 16MB`（使用 `checked_add` 累加各段大小）
  9. **拒绝 `PT_DYNAMIC` 段与 `DT_NEEDED` 入口**（防 dynamic linking 触发外部符号解析）
  10. **校验 `e_shoff + e_shnum * e_shentsize` 不溢出**（防 section header table 损坏导致解析器崩溃）
- **AND** 拒绝 0xFFFFFFFF 等溢出地址（防整数溢出攻击）
- **AND** `ElfMetadata` 含已解析的段布局（segment_addrs / entry_point / text_bytes 等），`load_elf(metadata: &ElfMetadata, state: &mut VmState)` 直接使用，不再读文件

#### Scenario: 入口函数签名

- **WHEN** 用户定义 `#[zkvm::entry] fn main(input: &[u8]) -> Result<Vec<u8>, zkvm::Error>`
- **THEN** 工具生成 `_start` trampoline，从 `zkvm_read_input` syscall 读取 input，调用 `main`，通过 `zkvm_commit_output` 提交返回值
- **AND** panic 自动转 `zkvm_panic` syscall

#### Scenario: no_std 兼容

- **WHEN** 用户代码使用 `#![no_std]`
- **THEN** 工具提供 `zkvm::prelude` 包含 `alloc` / `Vec` / `Box` / `format!`（基于 `alloc` crate）
- **AND** 标准库 `std::fs` / `std::net` 等系统调用不可用，编译时报错

### Requirement: ZKVM ISA 执行引擎

系统 SHALL 实现 RV32I 解释器（含自定义 syscall 指令），执行 ELF 文件并产生 execution trace。trace 格式 SHALL 被后续约束编译器消费。

#### Scenario: 指令集支持

- **WHEN** ZKVM 加载 ELF 文件
- **THEN** 支持 RV32I 全部指令（详见 spec v1.0 列表）
- **AND** 拒绝 RV32M 以外的扩展指令（M 扩展作为可选 support，默认禁用 — 用软件库实现乘除法以简化电路）
- **AND** 不支持浮点 / atomics / SIMD / compressed 指令

#### Scenario: 自定义 syscall 指令

- **WHEN** 执行到 `ECALL` 指令
- **THEN** 根据 `a7` 寄存器值分派到 ZKVM syscall：
  - `0x01` = `zkvm_read_input(ptr, len)`
  - `0x02` = `zkvm_commit_output(ptr, len)`
  - `0x03` = `zkvm_poseidon(ptr, len, out_ptr)`
  - `0x04` = `zkvm_sha256(ptr, len, out_ptr)`
  - `0x05` = `zkvm_ecdsa_verify(msg_ptr, msg_len, sig_ptr, pubkey_ptr) -> bool`
  - `0x06` = `zkvm_emit_event(ptr, len)` — event 内容进入 public_io
  - `0x07` = `zkvm_log(ptr, len)`
  - `0x08` = `zkvm_panic(ptr, len)` — 终止执行
  - `0x09` = `zkvm_get_randomness(out_ptr)` — 从 host seed 派生（deterministic）
  - `0x0A` = `zkvm_read_state(slot, out_ptr)` — 仅允许白名单 slot
- **AND** syscall 返回值写入 `a0` 寄存器
- **AND** 每个 syscall 调用记录到 trace（含 syscall_id + 参数 hash + 返回值 hash）

#### Scenario: syscall ABI 版本化

- **WHEN** ZKVM 启动
- **THEN** 加载 ABI 版本号 `ZKVM_ABI_VERSION = 1`，写入 proof header
- **AND** 链上 verifier 校验 proof header 中的 ABI 版本，不匹配返回 `AbiVersionMismatch`
- **AND** 未来 ABI 升级须 bump 版本号 + 链上 verifier 兼容性矩阵

#### Scenario: `zkvm_get_randomness` 确定性语义（绑定执行上下文 + 防重放）

- **WHEN** 调用 `zkvm_get_randomness(out_ptr)`
- **THEN** host 实现使用派生函数 `output = Poseidon(seed || initial_commitment || final_commitment || call_counter)`，其中：
  - `seed` = public_io 的 `randomness_seed` 字段（来自链上 VRF 输出，per-execution 唯一，绑定 `block_height + game_id`）
  - `initial_commitment` / `final_commitment` = public_io 中既有字段（绑定本次执行，防跨执行重放）
  - `call_counter` = 本次执行中 `zkvm_get_randomness` 的调用序号（从 0 开始单调递增，电路须显式约束 `call_counter_{i+1} = call_counter_i + 1`）
- **AND** prover 与 verifier 使用相同派生函数与输入，确保 randomness deterministic
- **AND** 防御 prover grinding：seed 来自链上 VRF 输出（既有 `poker_protocol::vrf`），跨执行变化（VRF 输出绑定 `block_height + game_id`）
- **AND** 同一 batch 内多次调用返回不同值（因 `call_counter` 递增）

#### Scenario: `zkvm_read_state` slot 白名单 + Merkle 绑定（防 prover 伪造 slot 值）

- **WHEN** 调用 `zkvm_read_state(slot, out_ptr)`
- **THEN** 校验 `slot` ∈ `ZKVM_READABLE_SLOTS` 白名单：
  - `SLOT_GAME_STATE = 0x01`
  - `SLOT_PLAYER_HANDS = 0x02`
  - `SLOT_POT_AMOUNT = 0x03`
  - `SLOT_CURRENT_TURN = 0x04`
  - `SLOT_ACK_CHAIN = 0x05`
- **AND** 非白名单 slot 返回 `InvalidSlot(slot)`
- **AND** **slot 值绑定到 `state_slot_root`**：prover 必须提供 Merkle 证明证明 slot 值在 public_io 的 `state_slot_root`（链上 state root 承诺）下；电路校验 Merkle 证明
- **AND** `state_slot_root` 绑定到 `execute_checkin` 时的 `block_height`（链上 state root 取该高度快照，写入 public_io）
- **AND** **跨 batch 一致性**：所有 batch 必须使用同一 `state_slot_root`（即同一高度快照）— 电路约束 `state_slot_root` 在所有 CCS 实例中相同
- **AND** gas = `GAS_ZKVM_READ_STATE_PER_SLOT * num_slots`

#### Scenario: `zkvm_emit_event` 进 public_io（绑定 step_index 防重排）

- **WHEN** 调用 `zkvm_emit_event(ptr, len)`
- **THEN** event 内容（ptr 指向的内存）经 Poseidon 哈希后产生 `event_hash = Poseidon(content_hash || step_index)`，其中 `step_index` 是本次调用的执行步序号
- **AND** 所有 `event_hash` 收集到 proof 的 `event_hashes` 数组（保留顺序）
- **AND** `public_io.event_hashes_root` = `event_hashes` 数组的 Merkle root（每个叶子 = `event_hash`，含 `step_index` 绑定）
- **AND** 链上 verifier 校验 `event_hashes` 数组的 Merkle root == `public_io.event_hashes_root`
- **AND** verifier 校验 `event_hashes` 数组中 `step_index` 严格单调递增（防 event 重排攻击）
- **AND** event 明文不进 proof（仅 hash），但 event hash 暴露给链上（非 ZK，与 MVP 决策一致）

#### Scenario: Trace 生成

- **WHEN** 执行每条指令
- **THEN** trace 记录 `(step_index, pc, instruction, registers[32], memory_access_log)`
- **AND** trace 总步数 ≤ `MAX_ZKVM_TRACE_STEPS = 2^20 = 1,048,576`
- **AND** trace host 内存占用 ≤ `MAX_TRACE_HOST_MEMORY = 512MB`（按 1M 步 × 32 寄存器 × 4B + mem access 估算 ≈ 128-256MB，留 2x 余量），超出返回 `TraceHostMemoryExceeded`
- **AND** trace 序列化为可流式消费的二进制格式

#### Scenario: 内存模型

- **WHEN** ZKVM 初始化内存
- **THEN** 内存为 32-bit 地址空间，初始分配 `STACK_TOP = 0x80000000` 向下生长，`HEAP_START = 0x10000000` 向上生长
- **AND** 内存按 4-byte word 对齐访问（未对齐访问返回 `UnalignedAccess`）
- **AND** 内存大小上限 = `MAX_ZKVM_MEMORY = 16MB`

### Requirement: Trace → CCS 约束编译器（含 batching 策略）

系统 SHALL 实现 trace-to-CCS 编译器，将 execution trace 中每 K 步翻译为 1 个 CCS 实例。

#### Scenario: Batching 策略（解决 trace 步 vs CCS 实例单位不一致）

- **GIVEN** trace 长度 N 步
- **WHEN** 调用 `compile_trace_to_ccs(trace, batch_size = K)`
- **THEN** 返回 ⌈N/K⌉ 个 CCS 实例（K = `ZKVM_BATCH_SIZE` 默认 1024）
- **AND** 实例数 ≤ `MAX_FOLD_STEP_COUNT = 1000`（即 N ≤ 1000 × 1024 = 1,024,000 ≈ MAX_ZKVM_TRACE_STEPS，单位一致）
- **AND** 每个 CCS 实例内部含 K 步执行的合并约束（连续性约束连接步与步）
- **AND** batch_size 可治理调整（90% quorum 敏感参数）

#### Scenario: 每步指令子电路（a la carte）

- **WHEN** 编译单步
- **THEN** 根据指令 opcode 选择对应子电路
- **AND** 子电路仅约束本步指令的语义（不约束其他指令）— 实现 Hypernova「a la carte」成本模型
- **AND** 指令译码通过 selector 多项式表达（每个 opcode 对应一个 selector bit）

#### Scenario: 内存一致性电路（byte-level permutation，正确处理混合尺寸访问）

- **GIVEN** trace 中的内存访问序列 `[(step_i, addr, op, val, size), ...]`（`size ∈ {1, 2, 4}` 字节）
- **WHEN** 编译内存约束
- **THEN** 采用 **byte-level permutation**（非 word-level）：所有写操作展开为字节级写（LW 4 字节 → 4 条字节写记录），所有读操作展开为字节级读（LB 1 字节 → 1 条字节读记录）
- **AND** permutation argument key 为 `(byte_addr, byte_val, step_index)`（**每个 byte 单独一条记录**），证明 read 集合 == write 集合
- **AND** **解决混合尺寸重叠访问**：若 LW 写 4 字节到地址 A（产生 4 条字节写），随后 LB 读地址 A 的 1 字节（产生 1 条字节读，val = 4 字节中对应字节），permutation argument 能正确匹配（LB 读的 byte_val == LW 写的对应字节值）
- **AND** `size` 字段仅在 read-write check 层使用（验证单条内存指令的 size 与 val 一致性），不进入 permutation key
- **AND** `step_index` 单调性显式约束：电路约束 `step_{i+1} > step_i`（防止 permutation 顺序伪造）
- **AND** 未初始化读取检测：若某 byte_addr 在 read 集合中出现但在 write 集合中无对应记录（step_index < read_step），返回 `UninitializedRead`
- **AND** 内存访问 batch 到全局内存向量中

#### Scenario: Range check / Lookup 协议（LogUp 正确公式 + 严格 absorb 顺序）

- **WHEN** 子电路需要 range check 或哈希函数查表
- **THEN** 通过 LogUp 协议表达，公式为：
  - prover 提交 lookup table `T = {t_1, ..., t_m}` 的承诺 `C_T`
  - prover 提交 witness lookup 值 `f_1, ..., f_n` 与对应 multiplicity `m_1, ..., m_n` 的承诺 `C_f` / `C_m`
  - **严格 absorb 顺序**：`transcript.absorb(LOOKUP_TAG || C_T || C_f || C_m)`，然后 `β ← transcript.challenge(LOOKUP_TAG)`（**β 必须在 witness 承诺之后派生** — 若 β 在 witness 承诺前派生，prover 看到 β 后可任意构造 `f_j` 与 `m_i` 使等式成立，LogUp 完全不 soundness）
  - 校验等式：`Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)`（在域上求和）
- **AND** **`m_i = 0` 是合法值**（表项未被使用），等式两边对应项为 0
- **AND** **`f_j` 不在表中时**：等式左侧无对应 `t_i` 使 `β - t_i` 匹配，sumcheck 反证会失败（通过 witness commitment 绑定后由 sumcheck 反证）
- **AND** table 承诺 `C_T` 必须先于 witness 提交（防 multiplicity 伪造攻击 — 否则 prover 可在看到 β 后调整 multiplicity）
- **AND** lookup 实例作为附加 CCS 实例（NIRVANA 风格，可被 Hypernova 折叠）
- **AND** lookup 表包括：u8 / u16 / u32 range、AND / OR / XOR 真值表、sha256 round table（可选）

### Requirement: 多项式承诺方案（PCS）模块

系统 SHALL 实现多项式承诺方案（PCS），用于对 witness / trace 的多线性扩展进行承诺。

#### Scenario: PCS 选型

- **WHEN** 初始化 PCS
- **THEN** 默认使用 IPA（Inner Product Argument）over BN254
- **AND** IPA 与 CycleFold 的 BN254/Grumpkin cycle 兼容（可在 cycle 上递归）
- **AND** 备选 KZG over BN254（需 trusted setup，留作 v2）
- **AND** PCS 通过 `Pcs` trait 抽象，含 `commit(poly) -> Commitment` / `open(poly, point) -> (Proof, Eval)` / `verify(commitment, point, eval, proof) -> bool`

#### Scenario: IPA commit / open / verify（含 challenge 派生 + NUMS generators）

- **WHEN** 调用 `commit(poly: &MultilinearPoly)`
- **THEN** 返回 `Commitment`（基于 Pedersen vector commitment，BN254 上的 MSM）
- **AND** Pedersen commitment 的 generators 通过 **hash-to-curve NUMS**（Nothing-Up-My-Sleeve）派生：`G_i = hash_to_curve(b"poker_zkvm_ipa_gen" || i)`，确保无离散对数关系
- **WHEN** 调用 `open(poly, point)`
- **THEN** 返回 `(Proof, Eval)`，Proof 含 log(N) 轮 commitment
- **AND** **每轮 challenge 从 transcript 派生**：`r_i ← transcript.challenge(PCS_OPEN_DOMAIN_TAG || round_commitment_i || round_index_i)`，absorb 顺序严格固定
- **AND** **challenge 必须绑定 `point` 与原 `commitment`**：open 开始前 `transcript.absorb(PCS_OPEN_DOMAIN_TAG || commitment || point)`，防 proof 复用到不同 point/commitment
- **WHEN** 调用 `verify(commitment, point, eval, proof)`
- **THEN** 通过 log(N) 轮挑战重算最终 commitment，校验与原 commitment 一致
- **AND** verifier 重算 challenge 时使用相同 absorb 顺序（含 `point` 与 `commitment` 绑定）

#### Scenario: PCS 与 Hypernova fold 集成

- **WHEN** Hypernova fold 步骤需要 witness 承诺
- **THEN** prover 通过 `Pcs::commit` 生成 `witness_commitment`
- **AND** final sumcheck 完成后通过 `Pcs::open` 在 challenge 点 opening
- **AND** verifier 通过 `Pcs::verify` 校验 opening

### Requirement: Hypernova 真实折叠算法（v1.3 修正核心等式 — 对照原论文）

系统 SHALL 实现完整 Hypernova 折叠算法（替换 `poker_l1/src/offline/ccs.rs` 中的 stub）。**v1.3 关键修正**（对照 Hypernova 原论文 eprint 2023/573 + Sonobe/Skyline 公开实现，修复 v1.2 的 3 个 CRITICAL 错误）：CCCCCS 实例**不存储 v_C 字段**（v_C[j] 是多项式，折叠时在 r_x 处通过内层 sumcheck 计算）；外层 sumcheck claimed sum = **u'（标量）**（非 v' 向量）；内层 batched sumcheck 产生**单个 r_y**（combined_point = r_y，非 t+1 维元组）；LCCCS 约束 `Σ_i c_i · Π_{j∈S_i} v'_j = u'`（relaxed，u' 可非 0，非 = 0）。

#### Scenario: LCCCS 数据结构（v 字段向量化，存储 r_x 处求值）

- **GIVEN** CCS 结构含 `num_matrices = t` 个矩阵 `M_1..M_t`
- **THEN** LCCCS 实例结构为 `(ccs_ref, u_L: FieldElement, x_L: Vec<FieldElement>, trace_L, r_x_L: FieldElement, v_L: Vec<FieldElement>)`，其中：
  - `u_L` 为标量（relaxed LCCCS 的 u 参数，可非 0）
  - `r_x_L` 为创建该 LCCCS 时的外层 sumcheck challenge（**显式存储**，因 v_L 在 r_x_L 处求值）
  - `v_L` 是长度为 `t` 的向量，`v_L[j] = Σ_y M_j(r_x_L, y) · z_L(y)`（在 `r_x_L` 处求值的标量）
- **AND** **LCCCS 满足性（relaxed）**：`Σ_i c_i · Π_{j∈S_i} v_L[j] = u_L`（u_L 可非 0；非原始 CCS 的 = 0）

#### Scenario: CCCCS 数据结构（v1.3 不存储 v_C — 关键修正）

- **GIVEN** CCS 结构含 `num_matrices = t` 个矩阵
- **THEN** CCCCS 实例结构为 `(ccs_ref, u_C: FieldElement, x_C: Vec<FieldElement>, trace_C, witness_commitment_C: Commitment)`
- **AND** **CCCCS 实例不存储 v_C 字段**（v1.3 修正 C2-002）— 原因：`v_C[j](X) = Σ_y M_j(X, y) · z_C(y)` 是关于 X 的多项式，在 CCCCS 创建时 `r_x`（来自配对的 LCCCS）尚不存在；v_C[j] 在折叠时于 `r_x` 处求值，通过内层 sumcheck 计算并验证，**不是 CCCCS 实例的存储字段**
- **AND** **CCCCS 满足性**：`Σ_i c_i · Π_{j∈S_i} (Σ_y M_j(x_C, y) · z_C(y)) = u_C`（在 `x_C` 处求值，u_C 标量可非 0）

#### Scenario: LCCCS + CCCCS 折叠（v1.3 修正 — fold challenge 标量 + u' 标量 claimed sum）

- **GIVEN** 一个 LCCCS 实例 `(ccs_ref, u_L, x_L, trace_L, r_x_L, v_L)` 与一个 CCCCS 实例 `(ccs_ref, u_C, x_C, trace_C, witness_commitment_C)`
- **WHEN** 调用 `fold(lcccs, ccccs, transcript) -> Lcccs`
- **THEN** prover 通过 Fiat-Shamir 派生**随机标量 `r`**（单域元素，非向量）
- **AND** 计算折叠后的 LCCCS 实例 `(ccs_ref, u', x', trace', r_x_L, v')`，其中：
  - `u' = u_L + r · u_C`（标量 + 标量乘，**u' 为标量**）
  - `x' = x_L + r · x_C`（向量 + 标量乘）
  - `trace' = trace_L + r · trace_C`（向量 + 标量乘）
  - `r_x' = r_x_L`（folded LCCCS 沿用 LCCCS_L 的 r_x，因 v_L 已在 r_x_L 处求值）
  - **`v'[j] = v_L[j] + r · v_C[j](r_x_L)`（分量级）** — 其中 `v_C[j](r_x_L) = Σ_y M_j(r_x_L, y) · z_C(y)` 是 CCCCS witness 多项式在 `r_x_L` 处的求值，**通过内层 sumcheck 计算并验证**（非 CCCCS 实例字段）
- **AND** **folded witness** `z' = z_L + r · z_C`（prover 显式构造用于 PCS opening；witness_commitment' = witness_commitment_L + r · witness_commitment_C）
- **AND** **folded LCCCS 满足性（relaxed，v1.3 修正 M2-001）**：`Σ_i c_i · Π_{j∈S_i} v'[j] = u'`（u' 可非 0；非 = 0）
- **AND** 折叠成本 = O(变量数) MSM（最优）

#### Scenario: Sumcheck 验证（v1.3 修正 — 外层 claimed sum = u' 标量 + 内层 batched 单 r_y）

- **WHEN** 完成所有折叠后，prover 生成 final sumcheck 证明
- **THEN** **外层 sumcheck（v1.3 修正 C2-003 — claimed sum 为 u' 标量，非 v' 向量）**：
  - 证明 `Σ_X G(X) = u'`（**claimed sum 是 u' 标量**，非 v' 向量；非 = 0）
  - 其中 **`G(X) = eq(X, r_x_L) · Σ_i [c_i · Π_{j∈S_i} (v_L[j](X) + r · v_C[j](X))]`（v1.4 修正 Min3-005 — 显式括号消除运算符优先级歧义：`eq(X, r_x_L)` 在 Σ_i 和 Π_{j∈S_i} 之外作为整体求和的乘法因子，非在 Π 内 — 否则会产生 `eq^|S_i|` 项使 `Σ_X G(X) ≠ u'`）**
  - `v_L[j](X) = Σ_y M_j(X, y) · z_L(y)`（线性化多项式）
  - `v_C[j](X) = Σ_y M_j(X, y) · z_C(y)`
  - 归约到 `G(r_x_L) = u'`，即 `Σ_i c_i · Π_{j∈S_i} v'[j] = u'`（folded LCCCS 满足性）
- **AND** **内层 batched sumcheck（v1.3 修正 C2-001 — 产生单个 r_y，非 t 个 r_{y_j}）**：
  - 引入 FS challenge `γ`（单标量），对每个 `j ∈ [0, t)` batched
  - 证明 `Σ_j γ^j · v'[j] = Σ_y (Σ_j γ^j · M_j(r_x_L, y)) · z'(y)` 其中 `z' = z_L + r · z_C`
  - 归约到**单个 challenge `r_y`**：`Σ_j γ^j · v'[j] = (Σ_j γ^j · M_j(r_x_L, r_y)) · z'(r_y)`
- **AND** **combined_point = `r_y`（单个 challenge，非 (r_x, r_{y_1}, ..., r_{y_t}) 元组）** — witness 多项式 z' 在 Y 域定义，仅在 r_y 处求值
- **AND** 通过 Fiat-Shamir transcript 派生所有 challenge（r, γ, r_x_L 来自外层，r_y 来自内层 batched），确保非交互性

#### Scenario: Cross-language claim 验证（v1.3 修正 — PCS 在 r_y 处打开 z' + verifier 校验等式）

- **WHEN** verifier 接收 folded LCCCS 实例 + final sumcheck proof + PCS opening proof
- **THEN** 校验以下等式（**v1.3 数学定义明确**）：
  1. **外层 sumcheck**：`Σ_X G(X) = u'` 且 `G(r_x_L) == u'`（**claimed sum 为 u' 标量**，非 0；final eval 一致性）
  2. **内层 batched sumcheck**：`Σ_j γ^j · v'[j] == (Σ_j γ^j · M_j(r_x_L, r_y)) · z'(r_y)` 在 challenge `r_y` 处归约（**verifier 用 PCS opening 提供的 `z'(r_y)` 校验**）
  3. **PCS opening 校验**：`Pcs::verify(witness_commitment', r_y, z_at_point, opening_proof) == true`，其中：
     - `combined_point = r_y`（**单个 challenge**，非 t+1 维元组 — v1.3 修正 C2-001）
     - `z_at_point = z'(r_y)` — folded witness `z' = z_L + r · z_C` 在 `r_y` 处的求值
     - **`z_at_point` 不是 `u'`，也不是 `v'`** — 是 witness 多项式 z' 在 r_y 的求值
  4. **LCCCS 约束（relaxed，v1.3 修正 M2-001）**：`Σ_i c_i · Π_{j∈S_i} v'[j] = u'`（**relaxed，u' 可非 0**；非原始 CCS 的 = 0）— 通过外层 sumcheck 隐式验证（G(r_x_L) = u' 即此约束）
- **AND** 任一等式失败返回 `CrossLanguageClaimFailed`
- **AND** **关键不变式**：`u'`（外层 claimed sum）+ `v'`（内层 per-matrix 值）+ `z_at_point`（PCS opening 求值）三者通过外层 sumcheck + 内层 batched sumcheck 链关联，verifier 必须校验此关联，否则 prover 可独立伪造

#### Scenario: 多步折叠循环

- **GIVEN** N 个 CCS 实例（N ≤ `MAX_FOLD_STEP_COUNT = 1000`）
- **WHEN** 调用 `fold_loop(instances, ...) -> HypernovaProof`
- **THEN** 顺序折叠为单个 LCCCS 实例（N-1 次折叠）
- **AND** 生成 final sumcheck proof + PCS opening proof
- **AND** 返回 `HypernovaProof { abi_version, folded_instance, witness_commitment, final_sumcheck, pcs_opening, r_y, z_at_point }`（v1.3：combined_point 改为 r_y 单 challenge）
- **AND** 折叠过程中保留 witness commitment 链以供 verifier 校验

### Requirement: Fiat-Shamir transcript 严格规范

系统 SHALL 实现严格规范的 Fiat-Shamir transcript，防止 concatenation ambiguity / weak CCS 结构重放攻击。

#### Scenario: absorb 顺序与编码（v1.2 补矩阵承诺 + witness commitment 绑定）

- **WHEN** prover 生成 challenge
- **THEN** transcript 严格按 spec 顺序 absorb 数据：
  1. `domain_tag`（1 byte）
  2. `length_prefix`（4 bytes LE，编码数据长度）
  3. `data`（canonical 编码 — 域元素固定 32 bytes LE，commitment 为 curve point compressed 33 bytes）
- **AND** absorb 序列固定（**v1.2 补矩阵承诺与 witness commitment**，防 weak CCS 结构重放与 witness 替换）：
  - fold 阶段：`FOLD_TAG || public_io || ccs_struct_params || ccs_commitment || lcccs_witness_commitment || lcccs_u || lcccs_x || lcccs_v || ccccs_witness_commitment || ccccs_u || ccccs_x || ccccs_v`，其中：
    - `ccs_commitment` = 所有矩阵 `M_1..M_t` 承诺的 Merkle root（或串联 hash），**绑定矩阵内容**防 attacker 替换矩阵（v1.1 仅绑定 `ccs_struct_params` 尺寸，不足以防内容替换）
    - `lcccs_witness_commitment` / `ccccs_witness_commitment` = LCCCS/CCCCS 的 witness 多项式承诺，**绑定 witness**防 prover 在 challenge 派生后替换 witness
  - sumcheck 阶段：`SUMCHECK_TAG || prev_challenge || claimed_sum || poly_round_i`
  - lookup 阶段：`LOOKUP_TAG || table_commitment || witness_commitment || multiplicity_commitment`（**然后** 派生 `β`，见 LogUp Scenario）
  - pcs_open 阶段：`PCS_OPEN_TAG || commitment || point || round_commitment_i || round_index_i`（见 IPA Scenario）
- **AND** `ccs_struct_params` 含 `num_vars` / `num_matrices` / `num_subsets` / `num_coeffs`，与 `ccs_commitment` 共同防止弱 CCS 结构重放
- **AND** verifier 重算 challenge 须与 prover 一致，任一不一致返回 `TranscriptMismatch`

#### Scenario: 域分离常量

- **WHEN** transcript 初始化
- **THEN** 域分离常量已定义：`HYPERNOVA_FOLD_DOMAIN_TAG = 0x10` / `SUMCHECK_DOMAIN_TAG = 0x11` / `LOOKUP_DOMAIN_TAG = 0x12` / `MEM_CHECK_DOMAIN_TAG = 0x13` / `PCS_OPEN_DOMAIN_TAG = 0x14`

### Requirement: Proof 序列化布局规范（v1.3 修正字段长度上限矛盾 M2-002）

系统 SHALL 定义 proof 二进制序列化布局，含 ABI 版本号与变长字段 length-prefix。**v1.3 关键修正（M2-002）**：v1.2 各变长字段单项上限 64KB×3 + 16KB = 208KB > 总上限 `MAX_ZKVM_PROOF_SIZE = 64KB`，存在矛盾 — attacker 可构造单项都通过但总和超 64KB 的 proof，单项校验通过后才在总校验失败，已分配大缓冲区造成 OOM。v1.3 修复：(1) 总长度优先校验（反序列化开始时 stream 读所有 length 字段求和，超 64KB 立即 fail，不分配任何大缓冲区）；(2) 单项上限合理子分配，**单项之和 ≤ 总上限**。

#### Scenario: Proof 二进制布局

- **WHEN** prover 序列化 `HypernovaProof`
- **THEN** 输出二进制布局：
  ```
  [4 bytes]  magic = "ZKVM"
  [1 byte]   abi_version = 1
  [1 byte]   proof_kind = 0x01 (Hypernova) / 0x02 (Groth16) / 0x03 (Spartan)
  [4 bytes]  field_id = 0x01 (BN254)
  [4 bytes]  public_io_len (LE)
  [N bytes]  public_io
  [4 bytes]  folded_instance_len
  [M bytes]  folded_instance (canonical field encoding)
  [4 bytes]  witness_commitment_len
  [K bytes]  witness_commitment (compressed curve point)
  [4 bytes]  final_sumcheck_len
  [L bytes]  final_sumcheck
  [4 bytes]  pcs_opening_len
  [P bytes]  pcs_opening
  [4 bytes]  event_hashes_count
  [..]       event_hashes (each 32 bytes)
  ```
- **AND** 所有域元素使用 canonical encoding（32 bytes LE，mod p）
- **AND** 所有变长字段前缀 4-byte LE length

#### Scenario: 反序列化字段长度上限校验（v1.3 修正 M2-002 — 总长度优先 + 单项子分配）

- **WHEN** verifier 反序列化 `HypernovaProof`
- **THEN** **第 0 步：stream 读固定头部**（magic / abi_version / proof_kind / field_id，共 10 bytes），校验 magic / abi_version / field_id，不匹配返回 `InvalidZkProofFormat` / `AbiVersionMismatch`
- **AND** **第 1 步：总长度优先校验（v1.3 关键修正 M2-002；v1.4 修正 Min3-001 — 显式 checked_add/checked_mul 防 wrap）** — stream 读所有变长字段的 length 前缀（不读 payload），计算 `total_payload = public_io_len + folded_instance_len + witness_commitment_len + final_sumcheck_len + pcs_opening_len + event_hashes_count * 32 + length_prefix_overhead`，**所有加法与乘法必须使用 `checked_add` / `checked_mul`**（防 32-bit 平台 `event_hashes_count * 32` 或多项 length 累加 wrap 导致 `total_payload` 计算偏小绕过 64KB 上限 — 与 ELF 校验 L156 `checked_add` 同等严谨度），校验 `total_payload ≤ MAX_ZKVM_PROOF_SIZE = 64KB`，超长立即返回 `InvalidZkProofFormat`，**不分配任何变长 payload 缓冲区**（防 OOM — v1.2 单项校验通过后再总校验，attacker 可构造单项 64KB×3 = 192KB proof 通过单项校验后才在总校验失败，已分配 192KB 缓冲区）
- **AND** **第 2 步：单项上限校验（v1.3 子分配 — 单项之和 ≤ 总上限）** — 各变长字段 length ≤ 对应 `MAX_*` 常量，子分配如下（**总和 ≈ 48KB < 64KB**，留 25% 余量给 length 前缀与固定头部）：
  - `public_io_len ≤ MAX_PUBLIC_IO_SIZE = 8KB`
  - `folded_instance_len ≤ MAX_FOLDED_INSTANCE_SIZE = 8KB`（含 `v': Vec<FieldElement>` 向量，长度 ≤ `num_matrices * 32 bytes`；典型 `num_matrices ≤ 10` 即 320B，8KB 余量充足）
  - `witness_commitment_len ≤ 33`（单个 compressed curve point，固定）
  - `final_sumcheck_len ≤ MAX_SUMCHECK_PROOF_SIZE = 16KB`（外层 sumcheck ~10 轮 + 内层 batched sumcheck ~10 轮，每轮 ~200B 即 ~4KB，16KB 余量充足）
  - `pcs_opening_len ≤ MAX_PCS_OPENING_SIZE = 8KB`（log(N) 轮 IPA，N=2^20 即 20 轮 × 64B = 1.3KB，8KB 余量充足）
  - `event_hashes_count ≤ MAX_EVENT_HASHES_COUNT = 256`（即 256 × 32 = 8KB）
- **AND** **第 3 步：逐字段分配并解析** — 第 1+2 步全通过后才分配 payload 缓冲区并解析字段内容
- **AND** **早夭逻辑**：第 1 步（总长度）或第 2 步（单项上限）任一失败立即返回 `InvalidZkProofFormat`，不分配大缓冲区，不进入 sumcheck/PCS 计算

### Requirement: Witness 生成与盲化策略

系统 SHALL 定义 trace → witness 向量映射规则与盲化策略。

#### Scenario: Witness 映射

- **WHEN** prover 生成 witness
- **THEN** witness 向量 `z = (u, x, trace, 1)`，其中 `u` 为内部 witness，`x` 为公共输入，`trace` 为执行 trace 的域元素编码，`1` 为常数 1
- **AND** witness 与 CCS 实例一一对应

#### Scenario: MVP transparent 风险声明（v1.2 枚举具体泄漏字段）

- **WHEN** MVP 阶段生成 proof
- **THEN** witness 不盲化（transparent SNARK）
- **AND** **风险声明（v1.2 枚举具体泄漏字段）**：transparent 模式下以下字段会泄漏：
  - **witness commitment**（Pedersen 无盲化，对小域可暴力枚举）
  - **sumcheck 各轮求值多项式**（直接暴露 witness 在 challenge 点的线性组合）
  - **PCS opening 的 `z'(r_y)` 求值**（暴露 folded witness 在 `r_y` 点的求值）
- **AND** 具体而言，以下敏感数据**不得**在 MVP 阶段进入 ZKVM 计算：
  - 玩家手牌（明文）
  - VRF seed / 私钥派生数据
  - ECDSA 私钥 / 签名随机数 k
  - 任何游戏中需对对手保密的状态
- **AND** 真正 ZK 版本（witness 盲化）留作 v2，需引入随机盲化向量 + Hypernova-PCS with ZK

### Requirement: 链上 Verifier Production 实现

系统 SHALL 实现 `HypernovaVerifier::verify` 的 Production 分支，替换当前 `Err(Other)` 返回。

#### Scenario: Production 验证流程

- **GIVEN** proof 字节流 + `ZkPublicIo` public_io
- **WHEN** `verifier_status == Production` 且调用 `verify(proof, public_io, Production)`
- **THEN** 反序列化 `HypernovaProof`（校验 magic / abi_version / field_id）
- **AND** 重新生成 Fiat-Shamir challenge（基于 public_io + transcript）
- **AND** 校验 final sumcheck 等式在 challenge 处求值匹配
- **AND** 校验 folded instance 的 cross-language claim（含 PCS opening 校验）
- **AND** 校验 transcript 一致性
- **AND** 任一失败返回 `InvalidZkProofFormat` / `SumcheckVerificationFailed` / `CrossLanguageClaimFailed` / `TranscriptMismatch` / `PcsVerificationFailed` / `AbiVersionMismatch`
- **AND** 全部通过返回 `Ok(true)`

#### Scenario: 与既有 Stub 兼容 + Production grace period（v1.2 双通道 + 切换高度绑定）

- **WHEN** `verifier_status == Stub`
- **THEN** 保持当前 stub 行为（仅校验 proof 长度）
- **AND** 主网 `chain_id` 拒绝 OffChain checkout（既有 NEW-C1 行为不变）
- **WHEN** `verifier_status` 从 `Stub` 切换为 `Production`（治理通过）
- **THEN** 治理切换时记录 `production_switch_height`（当前 block height）到 `GovernanceParams`
- **AND** **grace 期（`PRODUCTION_GRACE_BLOCKS = 7200`）内采用 proof_kind 双通道**：
  - `proof_kind = ZkShuffle` 的旧 Stub proof：允许走 stub 路径（仅校验 proof 长度），**但 `proof_hash` 必须匹配链上已存 `last_partial_fold.proof_partial_hash`**（仅允许在途游戏继续，不允许新游戏用 Stub proof — 防 attacker 伪造任意 64 字节 proof 通过校验）
  - `proof_kind = Zkvm` 的 proof：强制走 Production 路径（完整 sumcheck + cross-language claim + PCS opening + transcript 校验）
- **AND** **v1.3 修正 M2-003 — `last_partial_fold.proof_partial_hash` 链上不可变约束**：grace 期内 `last_partial_fold.proof_partial_hash` 一旦写入链上状态即视为冻结，**后续 PartialCheckinTx 仅允许追加新 `intermediate_commitment`，不允许覆盖已存的 `proof_partial_hash` 字段**（否则 attacker 可通过恶意 PartialCheckinTx 替换 `proof_partial_hash` 匹配伪造 proof，绕过 M2-003 防御）；具体实现：
  - `PartialCheckinTx` 执行时校验 `last_partial_fold.proof_partial_hash == None || last_partial_fold.proof_partial_hash == tx.proof_partial_hash`（首次设置或幂等重提交允许；覆盖已有值返回 `PartialFoldHashImmutable` 错误）
  - **v1.4 修正 Min3-003 — 幂等重提交范围明确**：幂等重提交允许 `proof_partial_hash` 重复，**同时 `tx.intermediate_commitment` 与 `tx.ack_chain_partial` 也必须与链上已存值相等**（即整个 `PartialCheckinTx` 内容幂等，而非仅 `proof_partial_hash` 幂等而其他字段可覆盖 — 否则 attacker 可借幂等 `proof_partial_hash` 通道覆盖 `intermediate_commitment`/`ack_chain_partial`）；非幂等的其他字段返回 `PartialFoldHashImmutable` 错误
  - **v1.4 修正 Min3-002 — "游戏终结"判定条件明确**：`execute_checkin` 完成（游戏终结）后清零 `last_partial_fold.proof_partial_hash`；**"游戏终结"判定条件 = `ack_chain` 达到游戏规则定义的终态**（如扑克游戏的 `showdown` / `fold_all` 终态标记，由 `poker_protocol::game_state::is_terminal(ack_chain)` 判定，或 `execute_checkin` 调用的 ZKVM 程序通过 `zkvm_commit_output` 显式提交 `game_over = true` 标记）；判定后立即清零 `last_partial_fold.proof_partial_hash`，杜绝 grace 期结束后终态游戏仍残留 `proof_partial_hash`
  - grace 期结束后 `last_partial_fold.proof_partial_hash` 强制清零（所有 stub 路径关闭）
- **AND** grace 期结束后（`current_height > production_switch_height + PRODUCTION_GRACE_BLOCKS`），所有 proof 强制 Production 路径，stub 路径彻底关闭
- **AND** **防伪造机制**：grace 期内 attacker 即使提交 `proof_kind = ZkShuffle` 的伪造 proof，因 `proof_hash` 必须匹配链上已存 `last_partial_fold.proof_partial_hash`（仅具体在途游戏有，且 v1.3 链上不可变），无法伪造新游戏的 CheckinTx

### Requirement: CycleFold 递归聚合（v1.2 补递归 verifier 电路定义）

系统 SHALL 实现 CycleFold 递归，支持超长计算分段聚合。CycleFold SHALL 在 BN254 / Grumpkin 曲线 cycle 上实例化。**v1.2 关键补全**：明确递归 verifier 电路本身的约束定义（v1.1 仅定义输入输出与终止条件，未定义递归电路，导致 CycleFold 无法落地）。

#### Scenario: 分段聚合

- **GIVEN** 总计算步数 N > MAX_FOLD_STEP_COUNT × ZKVM_BATCH_SIZE
- **WHEN** prover 分段
- **THEN** 每段独立 fold_loop 生成 sub-proof
- **AND** 通过 CycleFold 递归聚合 K 个 sub-proof 为单个 final proof
- **AND** final proof 大小 = O(log K)

#### Scenario: 递归终止条件（含深度依据分析）

- **WHEN** 递归聚合后 final proof 仍 > `MAX_ZKVM_PROOF_SIZE = 64KB`
- **THEN** 继续递归压缩，直到 proof ≤ 64KB
- **AND** 递归深度 ≤ `MAX_RECURSION_DEPTH = 16`，超出返回 `RecursionDepthExceeded`
- **AND** **深度依据分析**：最坏 N=1000 sub-proofs，CycleFold 树形聚合深度 = `ceil(log2(1000)) = 10`；每层 proof 大小衰减系数 ≈ 0.5（CycleFold 输出 O(log K) 但常数 ~50），10 层后 ≤ 64KB；`MAX_RECURSION_DEPTH=16` 留 60% 余量
- **AND** 最终通过 Spartan / Groth16 压缩到 ≤ 10KB 上链

#### Scenario: 曲线 cycle 选择

- **WHEN** 初始化 CycleFold
- **THEN** 主曲线 = BN254，辅助曲线 = Grumpkin
- **AND** 主曲线标量域 == 辅助曲线 base field，反之亦然（cycle 性质验证通过单元测试）

#### Scenario: CycleFold 递归 verifier 电路定义（v1.2 新增 — 核心补全）

- **GIVEN** 一个 Grumpkin 上的 Hypernova proof `π_G`（待聚合的 sub-proof）
- **WHEN** 构造 BN254 上的递归 verifier 电路 `C_BN254`
- **THEN** `C_BN254` SHALL 约束以下 Hypernova verifier 步骤（在 BN254 算术下表达）：
  1. **反序列化 `π_G`**：校验 magic / abi_version / field_id（Grumpkin field_id）
  2. **PCS verify（IPA on Grumpkin）**：约束 log(N) 轮 IPA verify — 每轮吸收 round commitment + 派生 challenge + 重算 commitment；因 Grumpkin 点坐标在 BN254 标量域中，可直接在 BN254 电路中表达
  3. **外层 sumcheck verify（v1.3 修正 — claimed sum = u' 标量）**：约束外层 sumcheck 各轮多项式求值一致性，重算 challenge `r_x_L`，校验 `G(r_x_L) == u'`（**非 v'**；u' 是 folded LCCCS 标量参数；G(r_x_L) = u' 即隐式校验 relaxed LCCCS 约束 `Σ_i c_i · Π_{j∈S_i} v'[j] = u'`）
  4. **内层 batched sumcheck verify（v1.3 修正 — 单 r_y，非 t 个 r_{y_j}）**：约束内层 batched sumcheck 各轮求值一致性，重算 FS challenge `γ`，归约到**单个 challenge `r_y`**，校验 `Σ_j γ^j · v'[j] == (Σ_j γ^j · M_j(r_x_L, r_y)) · z'(r_y)`（z'(r_y) 由 PCS opening 提供）
  5. **cross-language claim 校验（v1.3 修正 — combined_point = r_y 单 challenge）**：约束 PCS opening `Pcs::verify(witness_commitment', r_y, z_at_point, opening_proof)`，并校验 `z_at_point == z'(r_y)` 与内层 batched sumcheck 一致性
  6. **transcript 一致性**：重算所有 FS challenge（r, γ, r_x_L, r_y），校验与 prover 提供的一致
- **AND** `C_BN254` 的 public inputs 包含：`π_G` 的 public_io（含 `randomness_seed` / `event_hashes_root` / `state_slot_root`）、folded LCCCS 的 `u'`（标量）/ `x'` / `v'`（`Vec<FieldElement>`，长度 = `num_matrices`）、witness_commitment'
- **AND** **Grumpkin 镜像电路 `C_Grumpkin`**：对称地，在 Grumpkin 上约束 BN254 的 Hypernova verifier（当递归层在 BN254 与 Grumpkin 间交替时使用）
- **AND** **跨曲线 bridging**：BN254 电路的 witness（含 Grumpkin 点坐标）通过 cycle 性质在 BN254 标量域中直接表达；Grumpkin 电路的 BN254 点坐标同理
- **AND** **递归电路约束数估算（v1.3 修正 — 单层估算非总累加）**：`C_BN254` 单层约束数 ≈ IPA verify（log(N) 轮 × ~5000 约束/轮）+ 外层 sumcheck verify（~10000 约束）+ 内层 batched sumcheck verify（~10000 约束）+ cross-language（~5000 约束）≈ **100,000-200,000 约束/单递归层**；`MAX_RECURSION_DEPTH=16` 为最大允许深度上限，**实际递归深度由 `ceil(log2(sub_proofs.len()))` 决定**（N=1000 时仅需 10 层，远低于 16），单层 100k-200k 约束在 BN254 电路可接受范围内
- **AND** 递归电路本身的证明通过 Spartan / Groth16 压缩后上链

#### Scenario: 递归聚合流程（含 verifier 电路调用）

- **WHEN** prover 执行 `tree_aggregate(sub_proofs, depth)`
- **THEN** 树形聚合：叶节点为 sub-proofs，内部节点为递归 verifier 电路实例
- **AND** 每层递归：在 BN254 上构造 `C_BN254` 电路，证明"我验证了 2 个 Grumpkin sub-proofs"，生成 BN254 proof
- **AND** 下一层：在 Grumpkin 上构造 `C_Grumpkin` 电路，证明"我验证了 2 个 BN254 proofs"，生成 Grumpkin proof
- **AND** 交替递归直到 final proof ≤ 64KB 或 depth > 16
- **AND** final proof 通过 Spartan / Groth16 压缩到 ≤ 10KB 上链

### Requirement: 最终压缩（Spartan / Groth16）与 gas 预算

系统 SHALL 提供 Spartan 或 Groth16 最终压缩器，将 Hypernova 最终 LCCCS 实例压成单次上链 proof。**`GAS_HYPERNOVA_VERIFY` 调整为 300000**。

#### Scenario: Spartan 压缩（v1.3 修正 M2-005 — 澄清 IPA verify 由 Spartan 递归压缩）

- **WHEN** prover 完成 Hypernova 折叠后
- **THEN** 调用 Spartan SNARK 证明 folded LCCCS 实例成立（Spartan proof **内部已包含 IPA verify 的正确性证明** — prover 在生成 Spartan proof 时把 IPA verify 作为 witness 约束进 Spartan 电路，链上 verifier 验证 Spartan proof 即隐式验证 IPA verify 通过）
- **AND** 输出 proof 字节大小 ≤ 10KB
- **AND** 链上 verifier 校验 Spartan proof（**不直接执行 IPA verify** — IPA verify 是 prover 端 off-chain 计算，~1000k gas 成本由 prover 承担，非链上）
- **AND** **v1.3 修正 M2-005 — Spartan verifier 链上成本分解（澄清 IPA verify 已被 Spartan 递归压缩）**：
  - Spartan pairing：≥ 2 次 × 45k gas = 90k gas
  - final exponentiation：≈ 60-80k gas（参考 EIP-1108）
  - **IPA verify**：**链上 0 gas**（已由 Spartan proof 递归证明；若不使用 Spartan 直接上链 IPA verify 则需 ~1000k gas，但本 spec 采用 Spartan 压缩路径）
- **AND** **总链上 gas 估算（v1.4 修正 Min3-006 — 补估算项明细）**：
  - Spartan pairing：≥ 2 次 × 45k gas = 90k gas
  - final exponentiation：≈ 60-80k gas（取中值 70k）
  - proof 反序列化 + 公共输入校验 + Spartan 内部 MSM：≈ 10-20k gas（v1.4 补充 — 之前漏算）
  - 小计：≈ 170-180k gas
  - 余量 50%（覆盖 Spartan verifier 电路规模变动、ECDSA verify 等附加约束）：× 1.5
  - **总估算 ≈ 255-270k gas** — `GAS_HYPERNOVA_VERIFY = 300000` 留 ~10-15% 余量，**合理**（v1.2 误把 off-chain IPA verify 成本 1000k 加进链上估算得 1740k，与 GAS=300000 矛盾；v1.3 澄清 Spartan 压缩 IPA verify 后链上仅 ~160k；v1.4 补 proof 反序列化等附加项后仍 < 300k，GAS=300k 充足但余量较紧，**Phase 12 实测后若超 280k 须上调**）
- **AND** **若实测 IPA verify off-chain 成本过高**（prover 端无法承受），需改用 KZG PCS（trusted setup，v2）或递归压缩 IPA verify — **本参数须在 Phase 12 性能基准实测后再次校准**

#### Scenario: Groth16 备选

- **WHEN** 治理选择 Groth16 作为最终压缩器
- **THEN** 复用 `poker_l1/src/offline/groth16.rs` 既有 `Groth16Verifier`
- **AND** 须通过 trusted setup MPC 生成 CRS

#### Scenario: `GAS_HYPERNOVA_VERIFY` 调整

- **WHEN** 修改 `poker_l1/src/vm/gas_table.rs`
- **THEN** `GAS_HYPERNOVA_VERIFY` 从 50000 → 300000
- **AND** 加入 90% quorum 敏感参数清单
- **AND** 治理升级须遵循既有 NEW-C1 流程（90% quorum + `parameter_delay_blocks` timelock）

### Requirement: ZKVM Syscall 实现

系统 SHALL 实现完整 ZKVM syscall 表，每个 syscall 既有 host 实现（执行引擎用）也有电路实现（约束编译器用）。

#### Scenario: Poseidon 哈希

- **WHEN** 调用 `zkvm_poseidon(ptr, len, out_ptr)`
- **THEN** host 实现使用 `poker_protocol::crypto::poseidon`
- **AND** 电路实现使用 Poseidon 预编译电路（~ 200 constraints/round）
- **AND** gas = `GAS_ZKVM_POSEIDON_BASE + GAS_ZKVM_POSEIDON_PER_BLOCK * num_blocks`

#### Scenario: SHA-256

- **WHEN** 调用 `zkvm_sha256(ptr, len, out_ptr)`
- **THEN** host 实现使用 `sha2` crate
- **AND** 电路实现使用 SHA-256 预编译电路（~ 25,000 constraints/block，通过 lookup 优化）
- **AND** gas 按字节计费

#### Scenario: ECDSA 验证（约束预算重算）

- **WHEN** 调用 `zkvm_ecdsa_verify(msg_ptr, msg_len, sig_ptr, pubkey_ptr) -> bool`
- **THEN** host 实现使用 `secp256k1` crate
- **AND** 电路实现使用 ECDSA 预编译电路（**实际约束数 ≈ 110,000**，基于 `__mulsi3` shift-add 软件库 × 256 次标量乘 + 哈希 + 最终比较；非 spec v1.0 的 100k）
- **AND** gas = `GAS_ZKVM_ECDSA_VERIFY = 100000`（与既有 `GAS_SECP256K1_VERIFY` 对齐）

#### Scenario: 状态读取（v1.2 Merkle 绑定防 prover 伪造）

- **WHEN** 调用 `zkvm_read_state(slot, out_ptr)`
- **THEN** host 实现从 `PokerL1Context` 读取对应 slot 的链上状态
- **AND** **电路实现（v1.2 Merkle 绑定）**：prover 必须提供 Merkle 证明证明 slot 值在 `public_io.state_slot_root`（链上 state root 承诺，绑定 `execute_checkin` 时的 `block_height`）下；电路校验 Merkle 证明
- **AND** **跨 batch 一致性**：所有 batch 必须使用同一 `state_slot_root`（即同一高度快照）— 电路约束 `state_slot_root` 在所有 CCS 实例中相同
- **AND** slot 必须在白名单内（见 ISA Scenario）
- **AND** gas = `GAS_ZKVM_READ_STATE_PER_SLOT * num_slots`

### Requirement: 安全约束与抗 DoS

系统 SHALL 强制多项安全约束，防止恶意 proof 拖垮 prover / verifier。

#### Scenario: Trace 步数上限

- **WHEN** ZKVM 执行用户代码
- **THEN** 总步数 ≤ `MAX_ZKVM_TRACE_STEPS = 2^20 = 1,048,576`
- **AND** 超出立即 trap，返回 `TraceTooLong`
- **AND** 此参数列入 90% quorum 敏感参数清单

#### Scenario: 内存大小上限

- **WHEN** ZKVM 分配内存
- **THEN** 总内存 ≤ `MAX_ZKVM_MEMORY = 16MB`
- **AND** 超出返回 `OutOfMemory`
- **AND** 此参数列入 90% quorum 敏感参数清单

#### Scenario: Proof 大小上限与递归压缩

- **WHEN** prover 生成 final proof
- **THEN** proof 字节大小 ≤ `MAX_ZKVM_PROOF_SIZE = 64KB`
- **AND** 超出 prover 自动触发 CycleFold 递归压缩
- **AND** 递归深度 ≤ `MAX_RECURSION_DEPTH = 16`
- **AND** 上链 proof ≤ 10KB（通过 Spartan / Groth16 压缩）
- **AND** `MAX_ZKVM_PROOF_SIZE` / `MAX_RECURSION_DEPTH` 列入 90% quorum 敏感参数清单

#### Scenario: Trace host 内存上限

- **WHEN** prover 累积 trace
- **THEN** trace host 内存占用 ≤ `MAX_TRACE_HOST_MEMORY = 512MB`
- **AND** 超出返回 `TraceHostMemoryExceeded`
- **AND** 此参数列入 90% quorum 敏感参数清单

#### Scenario: Batching 参数治理

- **WHEN** 治理调整 `ZKVM_BATCH_SIZE`（默认 1024）
- **THEN** 须 90% quorum + `parameter_delay_blocks` timelock
- **AND** 此参数列入 90% quorum 敏感参数清单
- **AND** 调整后须保证 `MAX_ZKVM_TRACE_STEPS / ZKVM_BATCH_SIZE ≤ MAX_FOLD_STEP_COUNT`

#### Scenario: 见证不可泄露（MVP 风险声明）

- **WHEN** prover 生成 proof
- **THEN** proof 不包含 witness 明文，仅包含 commitment
- **AND** **MVP 风险声明**：transparent SNARK 仍可能从多项式求值反推 witness，敏感数据不应在 MVP 阶段进入 ZKVM 计算
- **AND** 真正 ZK 版本（witness 盲化）留作 v2

### Requirement: 工具链与开发体验

系统 SHALL 提供 `cargo-zkvm` 命令行工具，覆盖编译 / 执行 / 证明 / 验证完整流程。

#### Scenario: 编译命令

- **WHEN** 执行 `cargo zkvm build`
- **THEN** 编译当前 crate 为 RV32I ELF
- **AND** 输出到 `target/riscv32i-unknown-none-elf/release/<crate_name>.elf`
- **AND** 校验 ELF 无未支持指令（含强化校验项）

#### Scenario: 执行命令

- **WHEN** 执行 `cargo zkvm run --elf <path> --input <input.bin>`
- **THEN** ZKVM 解释执行 ELF，输出返回值
- **AND** 同时生成 trace 文件到 `target/zkvm/trace.bin`

#### Scenario: 证明命令

- **WHEN** 执行 `cargo zkvm prove --elf <path> --input <input.bin> --output <proof.bin>`
- **THEN** 调用 prover 生成 Hypernova proof
- **AND** proof 写入 `proof.bin`
- **AND** 同时生成 `public_io.bin`

#### Scenario: 验证命令

- **WHEN** 执行 `cargo zkvm verify --proof <proof.bin> --public-io <public_io.bin>`
- **THEN** 调用链上 verifier Production 实现校验 proof
- **AND** 通过返回 `verified = true`，失败返回错误详情

#### Scenario: 测试命令

- **WHEN** 执行 `cargo zkvm test`
- **THEN** 运行当前 crate 所有 `#[zkvm::test]` 标记的测试函数
- **AND** 每个测试函数自动 compile + run + prove + verify
- **AND** 失败时输出失败 step 的 trace 反汇编

### Requirement: 与 poker_l1 集成（含 CheckinTx 扩展）

系统 SHALL 与 `poker_l1` 既有 OffChain 模式集成，支持 ZKVM 生成的 proof 通过 `CheckinTx` 上链。

#### Scenario: `CheckinTx` 新增 `proof_kind` 字段（v1.2 序列化策略 + scheme_id 映射）

- **WHEN** 修改 `poker_l1/src/offline/state.rs::CheckinTx`
- **THEN** 新增 `proof_kind: ProofKind` 字段（`ProofKind::ZkShuffle` / `ProofKind::Zkvm`）
- **AND** **序列化策略（v1.2 明确）**：`proof_kind` 作为 1-byte 前缀进入 `signing_hash` 输入（破坏旧签名 — 升级时所有在途 `CheckinTx` 须在 `PRODUCTION_GRACE_BLOCKS` 内重提交或失效）
- **AND** **`proof_kind` 与 `scheme_id` 映射（v1.2 明确）**：
  - `ProofKind::ZkShuffle` → `SCHEME_ZKSHUFFLE`（新增 scheme_id=4）
  - `ProofKind::Zkvm` → `SCHEME_HYPERNOVA`（既有 scheme_id=1）
- **AND** `execute_checkin` 按 `scheme_id` 分派到对应 verifier（`scheme_id=4` → 既有 zk_shuffle verifier；`scheme_id=1` → `poker_zkvm::verifier::verify_production`）；`proof_kind` 与 `scheme_id` 不一致返回 `ProofKindMismatch`
- **AND** **v1.3 修正 M2-004 — 签名 malleability 修复（单 proof_kind 单签名形式）**：v1.2 同时接受带/不带 `proof_kind` 的签名会导致同一 proof 有两种合法签名形式，attacker 可对已签名 CheckinTx 重写 `proof_kind` 字段产生新的合法签名（ECDSA 签名 malleability 攻击向量）。v1.3 修复策略：
  - **切换前**（`verifier_status == Stub`）：仅接受旧签名（无 `proof_kind` 字段，`signing_hash` 不含 `proof_kind` 前缀）
  - **grace 期内**：`proof_kind = ZkShuffle` 旧 proof 走 stub 路径时**仅接受旧签名**（无 `proof_kind` 字段）；`proof_kind = Zkvm` 新 proof 走 Production 路径时**仅接受新签名**（含 `proof_kind` 字段）；**verifier 通过 `scheme_id` 反推期望的签名形式**（`scheme_id=4` 期望旧签名；`scheme_id=1` 期望新签名），签名形式与 `scheme_id` 不一致返回 `SignatureFormMismatch` 错误
  - **grace 期后**：仅接受新签名（含 `proof_kind` 字段）；旧签名 CheckinTx 失效，须重新签名提交。**v1.4 修正 M3-002 — grace 期后 scheme_id=4 分支明确**：grace 期后所有 `CheckinTx`（不论 `scheme_id`）必须使用新签名（含 `proof_kind` 字段）；`scheme_id=4`（ZkShuffle）走既有 ZkShuffle Production verifier（**非 stub、非 Hypernova** — 即 zk_shuffle 专用电路的完整 Production 验证路径），`scheme_id=1`（Zkvm）走 Hypernova Production verifier（`poker_zkvm::verifier::verify_production`）；stub 路径彻底关闭，ZkShuffle 在途游戏须用 ZkShuffle Production verifier 收尾
  - **不变式**：单个 `CheckinTx` 同一时刻仅有一种合法签名形式（由 `scheme_id` 决定），杜绝签名 malleability

#### Scenario: CheckinTx 接受 ZKVM proof

- **WHEN** 操作方在 OffChain 模式下使用 ZKVM 执行链下逻辑
- **THEN** 生成的 proof 通过 `CheckinTx { proof, state_delta, new_commitment, ack_chain, scheme_id: SCHEME_HYPERNOVA, proof_kind: ProofKind::Zkvm, has_partial_checkin: false }` 提交
- **AND** 链上 `execute_checkin` 调用 `HypernovaVerifier::verify` Production 分支
- **AND** 通过后应用 Δ 更新 Game 对象

#### Scenario: PartialCheckin 支持 ZKVM

- **WHEN** ZKVM 执行长计算需中断恢复
- **THEN** 通过 `PartialCheckinTx { proof_partial, folded_step_count, intermediate_commitment, ack_chain_partial, scheme_id: SCHEME_HYPERNOVA, proof_kind: ProofKind::Zkvm }` 提交中间锚点
- **AND** 链上 verifier 校验 partial proof

#### Scenario: verifier_status 治理切换（v1.2 双通道 grace period）

- **WHEN** 治理将 `verifier_status` 从 `Stub` 升级为 `Production`
- **THEN** 既有 NEW-C1 流程触发：90% quorum + `parameter_delay_blocks` timelock
- **AND** timelock 内可由 90% quorum 反对提案撤销
- **AND** 升级后记录 `production_switch_height`（当前 block height）到 `GovernanceParams`
- **AND** 启动 `PRODUCTION_GRACE_BLOCKS = 7200` grace period，期间采用 proof_kind 双通道（见 Production grace period Scenario）
- **AND** grace period 结束后 ZKVM proof 可在主网使用，stub 路径彻底关闭

#### Scenario: 错误恢复与重试

- **WHEN** prover 中途失败（OOM / trace 过长 / fold 失败）
- **THEN** prover 返回详细错误（`OutOfMemory` / `TraceTooLong` / `TraceHostMemoryExceeded` / `FoldError`）
- **AND** host 端可调整 `ZKVM_BATCH_SIZE` 后重试（若 trace 过长但 ≤ MAX_ZKVM_TRACE_STEPS）
- **AND** prover 不保存中间状态（无 checkpoint），失败须从头重跑

## MODIFIED Requirements

### Requirement: Hypernova fold step / fold loop（修改 `poker_l1/src/offline/ccs.rs`）

**原 spec**：`fold_step` 与 `fold_loop` 使用 blake2b 哈希链累计作为占位实现，Production 阶段须实现完整 CCS 折叠算法。

**修改后（v1.2 诚实 BREAKING 声明）**：
- `poker_l1/src/offline/ccs.rs::CcsInstance`（原 hash-based）标记 `#[deprecated(note = "Use poker_zkvm::fold::CcsInstance instead")]`
- 新建 `poker_zkvm::fold::CcsInstance`（含矩阵结构与域元素 witness）
- **`LegacyCcsInstanceAdapter` 仅用于过渡期编译兼容**：返回 `Err(Other("legacy hash-based instance cannot be really folded — hash is one-way, cannot recover matrices"))`，**不参与真实证明生成**；旧调用方在 Production 下会失败，必须重构以提供真实矩阵
- `fold_step` / `fold_loop` 接受 `poker_zkvm::fold::CcsInstance`，内部调用 `poker_zkvm::fold::fold_step` / `poker_zkvm::fold::fold_loop`
- **外部 trait 签名变更**（参数类型从旧 hash-based 改为新含矩阵类型），既有调用方必须迁移到新类型，无法透明兼容
- 移除 blake2b 哈希链冒充逻辑
- `CcsCircuit` trait 一并迁入 `poker_zkvm`，`poker_l1` 通过 `pub use poker_zkvm::precompiles::CcsCircuit;` re-export

### Requirement: HypernovaVerifier Production 分支（修改 `poker_l1/src/offline/hypernova.rs`）

**原 spec**：Production 分支返回 `Err(Other("Hypernova Production verifier 尚未实现"))`。

**修改后（v1.2 双通道 grace period）**：
- Production 分支调用 `poker_zkvm::verifier::verify_production(proof, public_io)`
- 校验 final sumcheck + cross-language claim + PCS opening + Fiat-Shamir transcript
- 返回错误类型扩展为 `InvalidZkProofFormat` / `SumcheckVerificationFailed` / `CrossLanguageClaimFailed` / `TranscriptMismatch` / `PcsVerificationFailed` / `AbiVersionMismatch` / `ProofKindMismatch` / **v1.3 新增 `PartialFoldHashImmutable`（M2-003）** / **v1.3 新增 `SignatureFormMismatch`（M2-004）**
- **grace period 双通道逻辑**：切换后 `PRODUCTION_GRACE_BLOCKS` 内，`proof_kind = ZkShuffle` 旧 Stub proof 须 `proof_hash` 匹配链上已存 `last_partial_fold.proof_partial_hash` 才走 stub 路径；`proof_kind = Zkvm` 强制 Production 路径
- 治理切换时记录 `production_switch_height` 到 `GovernanceParams`

### Requirement: ZkShuffleCcsCircuit 迁移（含 CcsCircuit trait）

**原 spec**：`poker_l1/src/offline/ccs.rs:240-308` 定义 `ZkShuffleCcsCircuit` 作为 CCS 电路适配器 stub。

**修改后**：`ZkShuffleCcsCircuit` 与 `CcsCircuit` trait 迁移到 `poker_zkvm::precompiles`（`ZkShuffleCcsCircuit` 在 `precompiles::zk_shuffle`，`CcsCircuit` trait 在 `precompiles::mod`）。`poker_l1` 通过 `pub use poker_zkvm::precompiles::CcsCircuit;` + `pub use poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit;` re-export 引用。

### Requirement: `GAS_HYPERNOVA_VERIFY` 调整（v1.2 补 IPA verify 成本）

**原 spec**：`GAS_HYPERNOVA_VERIFY = 50000`（`poker_l1/src/vm/gas_table.rs:95`）。

**修改后**：`GAS_HYPERNOVA_VERIFY = 300000`（暂定，覆盖 Spartan pairing + final exp + **IPA verify** + 余量；**本参数须在 Phase 12 性能基准实测后再次校准**），加入 90% quorum 敏感参数清单。若实测 IPA verify 成本过高（> 500k gas），需改用 KZG PCS（trusted setup，v2）或递归压缩 IPA verify。

## REMOVED Requirements

### Requirement: blake2b 哈希链冒充折叠

**Reason**：blake2b 哈希链不是 ZK 折叠算法，仅用于 MVP 占位。真实 Hypernova 实现完成后该占位代码移除。
**Migration**：`fold_step` / `fold_loop` 内部实现替换为 `poker_zkvm::fold` 调用，外部接口签名变更（接受新 `CcsInstance` 类型），调用方须迁移。

### Requirement: `ZkShuffleCcsCircuit` 在 `poker_l1` 中的 stub 位置

**Reason**：`ZkShuffleCcsCircuit` 应作为 ZKVM 预编译电路，逻辑上属于 `poker_zkvm` crate。
**Migration**：迁移到 `poker_zkvm::precompiles::zk_shuffle`，`poker_l1` 通过 re-export 引用。

### Requirement: BLS12-381 / BW6-761 cycle 备选

**Reason**：v1.0 spec 提及 BLS12-381 可作 BN254 替代，但 BLS12-381 与 Grumpkin 非 cycle，CycleFold 无法实现。MVP 固定 BN254 + Grumpkin。
**Migration**：BLS12-381 + BW6-761 cycle 留作 v2，本 spec 不覆盖。

## Known Limitations（非 MVP 范围，后续迭代）

* **GPU 加速 prover**：MVP 阶段 prover 单线程实现（可选用 rayon 多线程）；GPU 加速留作 v2
* **JIT 编译 ZKVM 字节码**：MVP 仅解释执行 RV32I；JIT 留作 v2
* **真正 ZK（witness 盲化）**：MVP 仅实现 succinctness（proof 简洁性），witness 可能通过多项式求值反推；ZK 版本留作 v2，需引入随机盲化向量 + Hypernova-PCS with ZK
* **与 rBPF VM 互操作**：ZKVM 与 rBPF 合约 VM 独立，不互操作
* **BLS12-381 + BW6-761 cycle**：MVP 阶段仅支持 BN254 + Grumpkin；BLS12-381 留作 v2
* **浮点支持**：RV32I 不含浮点指令；浮点运算通过软件库实现，电路不优化
* **多线程支持**：RV32I 不含 atomics；并发执行通过 host 端调度实现（不进入电路）
* **Prover checkpoint / 中断恢复**：MVP 阶段 prover 失败须从头重跑；checkpoint 留作 v2

## 治理参数清单（90% quorum 敏感参数）

新增以下参数到既有 `governance_params.rs` 敏感参数表：

| 参数名 | 默认值 | 说明 |
|--------|--------|------|
| `GAS_HYPERNOVA_VERIFY` | 300000 | 链上 Hypernova verifier gas（暂定，覆盖 Spartan pairing + IPA verify + 余量；**Phase 12 实测校准**） |
| `MAX_ZKVM_TRACE_STEPS` | 1,048,576 | ZKVM trace 步数上限 |
| `MAX_ZKVM_MEMORY` | 16MB | ZKVM 内存上限 |
| `MAX_ZKVM_PROOF_SIZE` | 64KB | Proof 大小上限（触发 CycleFold） |
| `MAX_PUBLIC_IO_SIZE` | 8KB | Proof 中 public_io 字段长度上限（v1.4 修正 M3-001 — 与反序列化第 2 步单项子分配一致，防 verifier OOM） |
| `MAX_FOLDED_INSTANCE_SIZE` | 8KB | Proof 中 folded_instance 字段长度上限（v1.4 修正 M3-001） |
| `MAX_SUMCHECK_PROOF_SIZE` | 16KB | Proof 中 final_sumcheck 字段长度上限（v1.4 修正 M3-001） |
| `MAX_PCS_OPENING_SIZE` | 8KB | Proof 中 pcs_opening 字段长度上限（v1.4 修正 M3-001） |
| `MAX_EVENT_HASHES_COUNT` | 256 | Proof 中 event_hashes 数组长度上限（256 × 32 = 8KB） |
| `ZKVM_BATCH_SIZE` | 1024 | Trace → CCS 实例的 batching 大小 |
| `MAX_RECURSION_DEPTH` | 16 | CycleFold 递归深度上限（依据：log2(1000)≈10，留 60% 余量） |
| `MAX_TRACE_HOST_MEMORY` | 512MB | Prover host 端 trace 内存上限 |
| `PRODUCTION_GRACE_BLOCKS` | 7200 | Stub → Production 切换后旧 proof 兼容期 |
| `production_switch_height` | （动态） | `verifier_status` 从 Stub 切换为 Production 时的 block height（grace period 起算点），治理切换时写入 |

所有参数调整须遵循既有 NEW-C1 流程：90% quorum + `parameter_delay_blocks` timelock + timelock 内可由 90% quorum 反对提案撤销。`production_switch_height` 为一次性写入字段（切换时设置，grace 期结束后可清零），非持续调整参数。
