# poker\_zkvm 实现计划（从基础开始 · TDD 严格模式）

> **change-id**：`build-hypernova-zkvm`
> **spec 版本**：v1.4（FROZEN — 8 项 v1.3 复核修复全部完成）
> **执行原则**：从基础开始实现，TDD 严格（RED → GREEN → REFACTOR），每 Phase 测试通过后才进入下一 Phase；多个方案时选择推荐方案，未选方案记录到 `poker_zkvm/docs/alternatives.md`

***

## 一、当前状态分析

### 1.1 已完成

* **spec.md / tasks.md / checklist.md 全部 v1.4 完成**（2 MAJOR + 6 MINOR 修复已落地，跨文件一致性已校验）

* **密码学专家复核 v1.3** 已完成（0 CRITICAL + 2 MAJOR + 6 MINOR → 全部修复升级到 v1.4）

* **架构决策已确认**（用户已选）：

  * 密码学库：**arkworks 0.6 主线**（ark-bn254 / ark-grumpkin / ark-poly / ark-ff）

  * 实现节奏：**连续实现**（仅方案选择或测试失败时暂停）

  * 测试框架：**标准** **`#[test]`** **+ proptest**（property testing）+ criterion（Phase 12 benchmark）

  * TDD 模式：**严格 RED → GREEN → REFACTOR**

  * 备选方案：**`poker_zkvm/docs/alternatives.md`** 记录

### 1.2 现有代码基线（参考实现）

* `poker_l1/src/offline/hypernova.rs` — Hypernova verifier **stub**（hash-based FoldedInstance/WitnessCommitment/FinalSumcheck，Production 分支返回 `Err(Other)`）

* `poker_l1/src/offline/zk_verifier.rs` — `ZkVerifier` trait / `ZkVerifierRegistry` / `VerifierStatus`（Stub/Production 治理开关）

* `poker_l1/src/offline/ccs.rs` — CCS **stub**（hash-based，待迁移到域元素类型）

* `poker_l1/src/offline/mod.rs` — `#![deny(unsafe_code)]` 约定

* workspace `Cargo.toml` — 当前 `members = ["poker_l1"]`，需添加 `poker_zkvm`

### 1.3 关键数学定义（v1.4 最终态，实现须严格对照）

* **LCCCS**：`(ccs_ref, u_L: FieldElement, x_L, trace_L, r_x_L: FieldElement, v_L: Vec<FieldElement>)` — relaxed 约束 `Σ_i c_i·Π_{j∈S_i} v'[j] = u'`（u' 可 ≠ 0）

* **CCCSS**：`(ccs_ref, u_C, x_C, trace_C, witness_commitment_C)` — **不存储 v\_C**（多项式，折叠时在 r\_x\_L 求值）

* **Fold**：`u' = u_L + r·u_C`（标量）；`v'[j] = v_L[j] + r·v_C[j](r_x_L)`；`z' = z_L + r·z_C`

* **外层 sumcheck**：claimed sum = **u'（标量，非 v' 向量）**；`G(X) = eq(X, r_x_L) · Σ_i [c_i · Π_{j∈S_i} (v_L[j](X) + r·v_C[j](X))]`（v1.4 显式括号）

* **内层 batched sumcheck**：challenge γ → **单 r\_y**（非 t 不同 r\_{y\_j}）；`Σ_j γ^j·v'[j] == (Σ_j γ^j·M_j(r_x_L, r_y))·z'(r_y)`

* **combined\_point = r\_y**（单 challenge）；PCS 在 r\_y 打开 z'

***

## 二、模块依赖图（6 层，自底向上实现）

```text
Layer 0 — Foundation（Phase 0-1）
  error.rs ──► field.rs ──► transcript.rs
       │
       ▼
Layer 1 — Crypto Primitives（Phase 1.5）
  pcs/mod.rs ──► pcs/ipa.rs
       │
       ▼
Layer 2 — Frontend & Execution（Phase 2-4）
  compiler/elf_validator.rs ──► isa/ ──► trace/ ──► syscalls/
       │
       ▼
Layer 3 — Constraint System（Phase 5-6）
  ccs/ ──► lookup/logup.rs ──► constraints/memory.rs
       │
       ▼
Layer 4 — Hypernova Protocol（Phase 7-9）
  hypernova/fold.rs ──► hypernova/sumcheck.rs ──► hypernova/proof.rs ──► hypernova/verifier.rs
       │
       ▼
Layer 5 — Prover & Verifier（Phase 10-11）
  prover.rs ──► verifier.rs
       │
       ▼
Layer 6 — Recursion & Compression（Phase 12-13）
  cyclegfold.rs ──► spartan.rs
```

**实现顺序**：严格按 Layer 0 → 1 → 2 → 3 → 4 → 5 → 6，每个 Layer 内按子依赖顺序。下层测试全部通过后才进入上层。

***

## 三、详细实施计划

### Phase 0：crate 骨架（Layer 0 起步）

**目标**：创建 `poker_zkvm` crate 骨架，加入 workspace，`cargo build` + 空 `cargo test` 通过。

**文件清单**：

1. **修改** **`/Users/mac/projects/zchain/Cargo.toml`**（workspace root）

   * `members = ["poker_l1", "poker_zkvm"]`

   * `[workspace.dependencies]` 新增 arkworks 0.6 系列：

     ```toml
     ark-ff = { version = "0.6", features = ["std"] }
     ark-ec = { version = "0.6", features = ["std"] }
     ark-poly = { version = "0.6", features = ["std"] }
     ark-serialize = { version = "0.6", features = ["std"] }
     ark-bn254 = "0.6"
     ark-grumpkin = "0.6"
     ark-groth16 = { version = "0.6", default-features = false }
     rayon = "1"
     goblin = "0.8"
     proptest = "1"
     ```

2. **创建** **`/Users/mac/projects/zchain/poker_zkvm/Cargo.toml`**

   * `[package]` name = "poker\_zkvm", edition = "2024"

   * `[lib]` path = "src/lib.rs"

   * `[dependencies]`：arkworks 系列 + sha2 + blake2 + thiserror + serde + rayon + goblin

   * `[dev-dependencies]`：proptest + criterion

   * `[[bench]]` name = "phase12\_benchmarks", harness = false（Phase 12 才填）

3. **创建** **`/Users/mac/projects/zchain/poker_zkvm/src/lib.rs`**

   * `#![deny(unsafe_code)]`

   * `#![deny(missing_docs)]`（文档严格）

   * 模块声明（16 模块，按 Layer 顺序）：

     ```rust
     pub mod error;        // Layer 0
     pub mod field;        // Layer 0
     pub mod transcript;   // Layer 0
     pub mod pcs;          // Layer 1
     pub mod compiler;     // Layer 2
     pub mod isa;          // Layer 2
     pub mod trace;        // Layer 2
     pub mod syscalls;     // Layer 2
     pub mod ccs;          // Layer 3
     pub mod lookup;       // Layer 3
     pub mod constraints;  // Layer 3
     pub mod hypernova;    // Layer 4
     pub mod prover;       // Layer 5
     pub mod verifier;     // Layer 5
     pub mod cyclegfold;   // Layer 6
     pub mod recursion;    // Layer 6
     ```

   * 每个 Phase 才填实际内容，Phase 0 先 `pub mod xxx;` 占位（模块内 `//! TODO: Phase N 实现`）

4. **创建** **`/Users/mac/projects/zchain/poker_zkvm/src/error.rs`**

   * `ZkvmError` 枚举（18 variants，对照 spec L15）：
     `UnsupportedInstruction` / `TraceTooLong` / `TraceHostMemoryExceeded` / `OutOfMemory` / `UnalignedAccess` / `InvalidZkProofFormat` / `SumcheckVerificationFailed` / `CrossLanguageClaimFailed` / `TranscriptMismatch` / `PcsVerificationFailed` / `AbiVersionMismatch` / `InvalidSlot` / `RecursionDepthExceeded` / `FoldStepCountExceeded` / `FoldError` / `ProofKindMismatch` / `UninitializedRead` / `Other`

   * `impl std::fmt::Display + std::error::Error for ZkvmError`

   * `#[derive(Debug, Clone, PartialEq, Eq)]`

   * 单元测试：每个 variant 能 `to_string()` + `from(Other)` 转换

**验证**：

* `cargo build -p poker_zkvm` 通过

* `cargo test -p poker_zkvm` 通过（error.rs 单元测试）

* `cargo clippy -p poker_zkvm -- -D warnings` 无警告

**推荐方案**：arkworks 0.6（已确认）
**备选方案**（记录到 alternatives.md）：halo2 曲线库 — Hypernova 折叠生态（Sonobe）在 arkworks 更成熟

***

### Phase 1：域理论基础（Layer 0 完成）

**目标**：实现 `ZkvmField` trait + BN254 标量域 + Fiat-Shamir transcript。

#### Task 1.1：`src/field.rs`

**TDD 流程**：

1. RED：先写测试 — `test_field_add_mod_p` / `test_field_mul_mod_p` / `test_from_u32_with_wrap` / `test_to_u32_rem_euclid` / `test_overflow_bit_constraint` / proptest `prop_field_roundtrip`
2. GREEN：实现最小代码使测试通过
3. REFACTOR：提取通用 trait

**实现内容**：

* `pub trait ZkvmField: Clone + Copy + PartialEq + Eq + std::fmt::Debug + Send + Sync`

  * `fn from_u32_with_wrap(v: u32) -> Self` — mod p 包装（spec L21）

  * `fn to_u32(&self) -> u32` — `rem_euclid(2^32)` 抽取，防负 bigint 截断（spec L23）

  * `fn from_u64(v: u64) -> Self`

  * `fn add(&self, other: &Self) -> Self`

  * `fn mul(&self, other: &Self) -> Self`

  * `fn inverse(&self) -> Option<Self>`

  * `fn zero() -> Self`

  * `fn one() -> Self`

  * `fn from_be_bytes(bytes: &[u8]) -> Self`

  * `fn to_be_bytes(&self) -> [u8; 32]` — 固定 32 bytes LE（transcript canonical 编码）

* `pub struct Bn254ScalarField(ark_bn254::Fr);` — newtype 包装

* impl `ZkvmField` for `Bn254ScalarField`

* **关键测试**：u32 加法溢出场景（如 `0xFFFFFFFF + 1` wrap 到 0）+ overflow\_bit 约束验证

**推荐方案**：ark-bn254::Fr 作为基础字段
**备选方案**：halo2curves::bn256::Fr — API 类似但生态弱

#### Task 1.2：`src/transcript.rs`

**TDD 流程**：

1. RED：测试 — `test_transcript_deterministic` / `test_transcript_different_input` / `test_length_prefix_disambiguation`（`"ab"+"c"` vs `"a"+"bc"` 产生不同 challenge）
2. GREEN：基于 `Blake2bVar` 实现
3. REFACTOR：提取 domain tag 常量

**实现内容**：

* `pub struct Transcript { hasher_state: ..., absorbed: Vec<u8> }`

* `fn absorb(&mut self, domain_tag: u8, data: &[u8])` — 规范：`domain_tag || len_le(data) || data`（spec L28 length-prefixing 4 bytes LE）

* `fn absorb_field(&mut self, domain_tag: u8, elem: &impl ZkvmField)` — canonical 32 bytes LE

* `fn challenge(&mut self, domain_tag: u8) -> Bn254ScalarField` — 派生新 challenge，更新内部状态

* **域分离常量**（spec L29）：

  * `HYPERNOVA_FOLD_DOMAIN_TAG = 0x10`

  * `SUMCHECK_DOMAIN_TAG = 0x11`

  * `LOOKUP_DOMAIN_TAG = 0x12`

  * `MEM_CHECK_DOMAIN_TAG = 0x13`

  * `PCS_OPEN_DOMAIN_TAG = 0x14`

* **absorb 序列**（spec L30，v1.2 补矩阵承诺 + witness commitment）：

  * fold 阶段：`FOLD_TAG || public_io || ccs_struct_params || ccs_commitment || lcccs_witness_commitment || lcccs_u || lcccs_x || lcccs_v || ccccs_witness_commitment || ccccs_u || ccccs_x || ccccs_v`

  * `ccs_commitment` = 矩阵 M\_1..M\_t 承诺的 Merkle root，防矩阵内容替换

**推荐方案**：自实现 Transcript trait（spec 明确要求 NUMS + domain separation + length-prefixing）
**备选方案**：ark-poly-commit::BatchTranscript — 不满足 spec 的 domain tag + length-prefix 规范

**验证**：

* `cargo test -p poker_zkvm field::` 全通过

* `cargo test -p poker_zkvm transcript::` 全通过

* proptest：1000 个随机输入 roundtrip 一致

***

### Phase 1.5：IPA 多项式承诺（Layer 1）

**目标**：实现 BN254 上的 IPA（Inner Product Argument），含 NUMS generators + challenge 绑定。

#### Task 1.5.1：`src/pcs/mod.rs` — Pcs trait

* `pub trait Pcs: Send + Sync`

  * `fn commit(&self, poly: &MultilinearPoly) -> Result<Commitment, ZkvmError>`

  * `fn open(&self, poly: &MultilinearPoly, point: &[FieldElement], transcript: &mut Transcript) -> Result<(Proof, FieldElement), ZkvmError>`

  * `fn verify(&self, commitment: &Commitment, point: &[FieldElement], eval: &FieldElement, proof: &Proof, transcript: &mut Transcript) -> Result<bool, ZkvmError>`

* 类型定义：`Commitment` / `Proof` / `Eval` / `MultilinearPoly`

#### Task 1.5.2：`src/pcs/ipa.rs` — IPA over BN254

**TDD 流程**：

1. RED：测试 — `test_ipa_commit_open_verify_completeness` / `test_ipa_soundness_tampered_eval` / `test_ipa_soundness_tampered_proof` / `test_ipa_soundness_tampered_commitment` / `test_ipa_soundness_reuse_proof_different_point`（spec L43）
2. GREEN：实现 IPA
3. REFACTOR：提取 MSM 工具

**实现内容**（spec L38-43）：

* `pub struct IpaPcs { generators: Vec<ark_bn254::G1Affine> }`

* **NUMS generators 派生**：`G_i = hash_to_curve(b"poker_zkvm_ipa_gen" || i)`（spec L39）

  * hash\_to\_curve：使用 ark-ec 的 `hash_to_curve`（需要 SWU map，BN254 支持）

  * generators 预计算缓存（最多 2^20 个，按需扩展）

* `commit(poly)`：Pedersen vector commitment `C = Σ_i a_i · G_i`，BN254 MSM

* `open(poly, point, transcript)`：

  * **open 开始前 absorb**：`PCS_OPEN_TAG || commitment || point`（spec L40，绑定 point 与 commitment 防 proof 复用）

  * log(N) 轮 IPA protocol，每轮产生 1 commitment

  * **每轮 challenge**：`r_i ← challenge(PCS_OPEN_TAG || round_commitment_i || round_index_i)`（spec L40）

* `verify(commitment, point, eval, proof, transcript)`：

  * 重算 challenge 时使用相同 absorb 顺序（含 point 与 commitment 绑定）

  * log(N) 轮挑战重算最终 commitment，校验一致

**推荐方案**：自实现 IPA（spec 明确要求 NUMS generators，ark-poly-commit 不满足）
**备选方案**：ark-poly-commit::IPA — 不支持自定义 NUMS generators，且 transcript 不兼容 spec 规范

**验证**：

* 小规模多线性多项式（n\_vars <= 8）commit/open/verify 闭环

* soundness 负例全部 verify 失败

* proptest：100 个随机多项式 completeness

***

### Phase 2：前端编译流水线 — ELF 校验器（Layer 2 起步）

**目标**：实现强化 ELF 校验器（TOCTOU 消除 + checked\_add + PT\_DYNAMIC 拒绝）。

#### Task 2.2：`src/compiler/elf_validator.rs`

**TDD 流程**：

1. RED：测试覆盖每项校验失败的负例（spec L62）：

   * `test_reject_bad_magic` / `test_reject_wrong_class` / `test_reject_wrong_endian` / `test_reject_wrong_machine`

   * `test_reject_segment_addr_overflow`（wrap 攻击 `addr=0xFFFFFFF0, size=0x20`）

   * `test_reject_entry_outside_text` / `test_reject_overlapping_segments`

   * `test_reject_invalid_relocation` / `test_reject_non_rv32i_instruction`（fence.i / 浮点 / atomics / SIMD / compressed）

   * `test_reject_text_too_large` / `test_reject_total_memory_too_large`

   * `test_reject_pt_dynamic` / `test_reject_dt_needed`

   * `test_reject_section_header_overflow`（`e_shoff + e_shnum * e_shentsize` 溢出）

   * `test_toctou_elimination`（validate\_elf 接受 bytes 返回 ElfMetadata，load\_elf 接受 ElfMetadata）
2. GREEN：基于 goblin 实现
3. REFACTOR：提取校验函数

**实现内容**（spec L52-62）：

* `pub fn validate_elf(elf_bytes: &[u8]) -> Result<ElfMetadata, ZkvmError>`

  * 校验 ELF magic / class（ELF32）/ endian（little）/ machine（EM\_RISCV）

  * 校验所有段地址在 `[0, MAX_ZKVM_MEMORY)` 范围内，**且** **`addr.checked_add(size) <= MAX_ZKVM_MEMORY`**（spec L53，checked\_add 防 wrap）

  * 校验 entry point 在 `.text` 段范围内

  * 校验段之间无重叠

  * 校验所有 relocation 入口指向有效段内偏移

  * 扫描 `.text` 段所有指令属于 RV32I 子集（拒绝 fence.i / 浮点 / atomics / SIMD / compressed）

  * 校验 `.text` 段大小 ≤ `MAX_TEXT_SIZE = 8MB`，总加载内存 ≤ `MAX_ZKVM_MEMORY = 16MB`（**使用** **`checked_add`** **累加各段大小**）

  * **拒绝** **`PT_DYNAMIC`** **段与** **`DT_NEEDED`** **入口**（spec L59）

  * **校验** **`e_shoff + e_shnum * e_shentsize`** **不溢出**（spec L60，防 section header table 损坏）

  * **消除 TOCTOU**（spec L61）：接受字节切片返回已解析 `ElfMetadata`，`load_elf` 接受 `ElfMetadata` 而非路径

* `pub struct ElfMetadata { segments: Vec<Segment>, entry_point: u32, text_bytes: Vec<u8>, ... }`

* `pub fn load_elf(metadata: &ElfMetadata, state: &mut VmState) -> Result<(), ZkvmError>`（Phase 3 实现 VmState 后填充）

**推荐方案**：goblin 0.8 解析（成熟、纯 Rust、无 unsafe）
**备选方案**：自实现 ELF parser — 更可控但工作量大，且容易引入 bug

**验证**：

* 合法 RV32I ELF 接受

* 各类恶意 ELF 全部拒绝

* proptest：随机篡改字节后校验拒绝（非崩溃）

***

### Phase 3-13：方向性指引（每 Phase 详细实施前再细化）

| Phase | Layer | 关键文件                                         | 核心目标                 | 测试策略                             |
| ----- | ----- | -------------------------------------------- | -------------------- | -------------------------------- |
| 3     | 2     | `isa/` `trace/`                              | RV32I 解码+执行+Trace 生成 | 每条指令单元测试 + proptest              |
| 4     | 2     | `syscalls/`                                  | 8 个 syscall 实现       | 每 syscall 单元测试                   |
| 5     | 3     | `ccs/`                                       | CCS 矩阵+约束编译          | 小电路折叠闭环                          |
| 6     | 3     | `lookup/` `constraints/memory.rs`            | LogUp + 内存一致性        | RAM as permutation 负例            |
| 7     | 4     | `hypernova/fold.rs`                          | LCCCS+CCCSS 折叠       | 单步折叠等式验证                         |
| 8     | 4     | `hypernova/sumcheck.rs`                      | 外层+内层 sumcheck       | 等式 `Σ G(X) == u'`                |
| 9     | 4     | `hypernova/proof.rs` `hypernova/verifier.rs` | Proof 结构+verifier    | 三步反序列化 + soundness               |
| 10    | 5     | `prover.rs`                                  | 端到端 prover           | 小程序端到端 proof                     |
| 11    | 5     | `verifier.rs`                                | 端到端 verifier         | 集成到 poker\_l1 ZkVerifierRegistry |
| 12    | 6     | `cyclegfold.rs`                              | CycleFold 递归聚合       | 超长计算分段聚合                         |
| 13    | 6     | `recursion/spartan.rs`                       | Spartan 压缩           | 链上 \~160k gas 验证                 |

**每 Phase 进入前**：先读对应 spec 区段 → 写 TDD 测试 → 实现 → 测试通过 → 进入下一 Phase。

***

## 四、备选方案文档策略

**文件**：`/Users/mac/projects/zchain/poker_zkvm/docs/alternatives.md`

**记录规则**：

* 每个 Phase 实现时，若存在多个可行方案，记录到 alternatives.md

* 格式：

  ```markdown
  ## Phase X — <模块名>

  ### 推荐方案（已实现）
  <方案描述 + 理由>

  ### 备选方案 A
  <方案描述 + 未选理由>

  ### 备选方案 B
  <方案描述 + 未选理由>
  ```

* Phase 0-2 已知备选：

  1. 密码学库：arkworks 0.6（选）vs halo2（未选 — Sonobe 折叠生态弱）
  2. IPA 实现：自实现（选，spec 要求 NUMS）vs ark-poly-commit（未选 — 不支持 NUMS）
  3. ELF 解析：goblin 0.8（选）vs 自实现（未选 — 工作量大）
  4. Transcript：自实现（选，spec 规范）vs ark-poly-commit::BatchTranscript（未选 — 不兼容）
  5. 字段库：ark-bn254::Fr（选）vs halo2curves::bn256::Fr（未选 — 生态弱）
  6. 测试框架：proptest（选）vs quickcheck（未选 — proptest 生态更成熟）

***

## 五、TDD 严格工作流

**每个 SubTask 严格遵循**：

1. **RED（先写测试）**

   * 写失败测试，明确预期行为

   * `cargo test -p poker_zkvm <module>::test_<name>` 必须 FAIL（编译失败或断言失败）

2. **GREEN（最小实现）**

   * 写最小代码使测试通过

   * 不引入额外抽象，不过度设计

   * `cargo test -p poker_zkvm <module>::test_<name>` 必须 PASS

3. **REFACTOR（重构）**

   * 提取通用逻辑，改善命名

   * 测试必须仍然 PASS

   * `cargo clippy -p poker_zkvm -- -D warnings` 无警告

**Phase 完成标准**：

* 该 Phase 所有 SubTask 测试通过

* `cargo test -p poker_zkvm` 全部通过

* `cargo build -p poker_zkvm --release` 通过

* 记录备选方案到 alternatives.md（如有）

***

## 六、关键风险与缓解

| 风险                  | 影响            | 缓解措施                                              |
| ------------------- | ------------- | ------------------------------------------------- |
| arkworks 0.6 API 变更 | 编译失败          | 锁定 `Cargo.lock`，CI 定期跑 `cargo update --dry-run`   |
| IPA 性能瓶颈            | prover 慢      | Phase 12 benchmark，必要时用 MSM 预计算 + rayon 并行        |
| CycleFold 复杂度高      | Phase 12 延期   | 先跑通主路径（Phase 0-11），CycleFold 独立 Phase 12          |
| Hypernova 数学错误      | proof 不 sound | 严格对照 spec v1.4 最终数学定义 + 测试向量验证 + Phase 11 密码学专家复核 |
| rBPF VM 集成冲突        | Phase 3 卡住    | 复用 poker\_l1 既有 solana\_rbpf 经验，ZKVM 独立于 rBPF     |
| 32-bit wrap 漏洞      | OOM DoS       | 全部使用 `checked_add` / `checked_mul`，clippy lint 强制 |

***

## 七、验证步骤

### 每 Phase 完成时

```bash
cargo build -p poker_zkvm
cargo test -p poker_zkvm
cargo clippy -p poker_zkvm -- -D warnings
```

### 关键 Phase（1.5 / 5 / 8 / 10）

```bash
cargo test -p poker_zkvm --release
cargo test -p poker_zkvm -- --ignored  # 包含 proptest 大规模
```

### Phase 12（benchmark）

```bash
cargo bench -p poker_zkvm --bench phase12_benchmarks
```

### 集成验证（Phase 11）

```bash
cargo test -p poker_l1 --test hypernova_integration
cargo build -p zchain  # 确认 workspace 整体编译
```

***

## 八、立即执行计划

**用户已批准后立即开始**：

1. **Phase 0**（crate 骨架）— 预计 1-2 小时

   * 修改 workspace Cargo.toml

   * 创建 poker\_zkvm/Cargo.toml

   * 创建 src/lib.rs + src/error.rs

   * 验证：`cargo build` + `cargo test` 通过

2. **Phase 1**（域理论基础）— 预计 3-4 小时

   * TDD 实现 field.rs

   * TDD 实现 transcript.rs

   * 验证：所有单元测试 + proptest 通过

3. **Phase 1.5**（IPA PCS）— 预计 6-8 小时

   * TDD 实现 pcs/mod.rs + pcs/ipa.rs

   * 验证：completeness + soundness 测试通过

4. **Phase 2**（ELF 校验器）— 预计 4-6 小时

   * TDD 实现 compiler/elf\_validator.rs

   * 验证：所有负例测试通过

**每 Phase 完成后报告**：

* 测试结果（通过数 / 失败数）

* 关键决策（如有方案选择）

* 下一 Phase 计划

**遇到以下情况暂停询问用户**：

* 方案选择（spec 未明确）

* 测试持续失败（无法通过 GREEN）

* 性能问题（需要重新设计）

* 依赖冲突（arkworks 版本不兼容）

