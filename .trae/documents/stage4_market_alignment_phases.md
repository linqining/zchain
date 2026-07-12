# Stage 4 — 市场对标补齐分阶段实施计划

## Context

第二轮市场对照审计（对照 RISC Zero/SP1/Jolt/zkWASM/Cairo/Nexus 3.0）识别出 poker_zkvm 的 4 项 P0 关键缺口、5 项 P1 显著缺口。本计划将这些缺口拆分为 7 个顺序阶段，遵循"安全优先、保守重构、分阶段验证"原则。

**关键可行性发现**（来自探索）：
- LogUp 协议在 `constraints/lookup.rs:L247-L371` 已有完整实现，memory permutation 可直接复用
- `HypernovaVerifierCircuit` 已实现 `ConstraintSynthesizer<Fq>`（`hypernova_verifier_circuit.rs:L102-L150`），Groth16 API 已完整可用
- ECDSA `new_full_with_bits(n)` 可调 num_bits，但 256-bit 约 19M 约束
- zk_shuffle 真实电路位置不明，poker_l1 Production verifier 也是"Phase 11 尚未迁移"

**用户决策**：
- M 扩展（P0-4）延后到后期阶段
- zk_shuffle（P0-3）先探索 spike 再决策
- Phase 1-3 顺序执行（不并行）

---

## 阶段总览

| 阶段 | 缺口 | 风险 | 依赖 | 预计交付 |
|------|------|------|------|----------|
| Phase F | P0-1 Groth16 真实压缩 | 低 | 无 | ~200B 压缩 proof |
| Phase G | P0-2 LogUp 内存一致性 | 低 | 无 | O(n log n) 内存证明 |
| Phase H | P1-5 ECDSA 256-bit 标量 | 中 | 无 | 真实签名验证 |
| Phase I | P1-1 预编译补齐（6 项） | 低 | 无 | 8/8 预编译覆盖 |
| Phase J | P0-3 zk_shuffle 真实电路 | 高 | Phase I | 真实 ZkShuffle 电路 |
| Phase K | P0-4 RV32IM M 扩展 | 高 | 无 | 8 条乘除指令 |
| Phase L | P1-2/P1-3/P1-4 收尾 | 中 | Phase F-K | gas 对齐 + 形式化 |

排序理由：F/G 是 soundness 基础且基础设施已就绪，最优先；H/I 是功能补齐，独立低风险；J 风险最高（依赖不明），需探索 spike；K 是大工程延后；L 是收敛阶段。

---

## Phase F: Groth16 真实 SNARK 压缩 (P0-1)

**目标**：将 `groth16_compress` 从 Native 验证升级为真实 Groth16 SNARK proof 生成。

**动机**：当前 `groth16_compress` 返回 `CompressedProof::Native`，仅做约束满足性检查，证明大小未实际压缩。市场主流 zkVM（SP1/RISC Zero）均压缩到 <1KB。`HypernovaVerifierCircuit` 已实现 `ConstraintSynthesizer<Fq>`，`groth16_setup/prove/verify` API 已完整可用，只需接入。

**子步骤**：
1. **F-1**：在 `groth16_compress` 中，Native 验证通过后调用 `groth16_setup(circuit.clone())` 生成 PK/VK
2. **F-2**：调用 `groth16_prove(&pk, circuit)` 生成 `Groth16Proof`，返回 `CompressedProof::Groth16`
3. **F-3**：新增 `groth16_compress_verify(vk, public_inputs, compressed)` 端到端验证入口
4. **F-4**：集成到 `tree_aggregate_recursive`（recursion/mod.rs:L286-291），替换 `CompressedProof::Native`
5. **F-5**：测试 + 回归

**关键文件**：
- `poker_zkvm/src/prover/groth16_compress.rs`（L135-164 改造）
- `poker_zkvm/src/recursion/mod.rs`（L286-291 集成）

**可复用代码**：
- `groth16_setup` — `groth16_compress.rs:L57-65`
- `groth16_prove` — `groth16_compress.rs:L72-80`
- `groth16_verify` — `groth16_compress.rs:L88-96`
- `HypernovaVerifierCircuit::generate_constraints` — `hypernova_verifier_circuit.rs:L102-L150`
- `extract_fold_chain` — `hypernova_verifier_circuit.rs:L165-L234`

**测试策略**：
- 扩展 `test_groth16_compress_valid_proof`，断言返回 `CompressedProof::Groth16` 变体
- 新增端到端测试：`groth16_compress` → `groth16_compress_verify` 闭环
- 篡改 commitment 失败测试
- 证明大小对比（Native vs Groth16）

**风险与缓解**：
- **风险**：Fq 域约束系统与 BN254 Groth16 的兼容性。`HypernovaVerifierCircuit` 用 `Fq`（BN254 基域），Groth16 用 `Fr`（BN254 标量域）。
- **缓解**：先用小规模 fold chain（1-2 步）验证端到端。若不兼容，需引入 cycle-of-curves 双电路方案（BN254 + Grumpkin）。
- **风险**：trusted setup 用 `test_rng()`（L60），生产需 ceremony。
- **缓解**：文档标注，开发阶段用 test_rng，生产前需 ceremony。

**交付物**：`CompressedProof::Groth16` 产出 ~200B proof；端到端 verify 通过。

---

## Phase G: LogUp 内存一致性 (P0-2)

**目标**：将 `verify_memory_permutation` 从 O(n²) 集合比较升级为 LogUp permutation argument。

**动机**：当前 `verify_memory_permutation`（memory.rs:L126-160）对每个 read 遍历所有 writes，复杂度 O(n²)，且无法转为电路内约束。市场主流 zkVM（Nexus 3.0/Cairo/SP1）均用 permutation/LogUp。`lookup.rs:L247-L371` 已有完整 `LogUpProof::create/verify/verify_equation`，可直接复用。

**子步骤**：
1. **G-1**：新增 `memory.rs::build_logup_proof(reads, writes)` — 将 `ByteAccess` 映射为 LogUp 的 table/witness/multiplicity
   - permutation key = `(byte_addr, byte_val, step_index)` 编码为单 Fr 元素
   - writes 作为 table `t_i`，multiplicity `m_i` = write 出现次数
   - reads 作为 witness `f_j`
2. **G-2**：保留 `check_uninitialized_read` 作为前置检查（LogUp 不直接验证时序）
3. **G-3**：`verify_memory_permutation` 改为调用 `LogUpProof::create` + `verify`，替代 L145-157 的 O(n²) 循环
4. **G-4**：将 LogUp proof 转为 `CcsInstance`（复用 `lookup.rs:L382-L430` 的 `to_ccs_instance`），供 Hypernova 折叠
5. **G-5**：测试 + 回归

**关键文件**：
- `poker_zkvm/src/constraints/memory.rs`（L126-160 改造）
- `poker_zkvm/src/constraints/lookup.rs`（复用 L247-L430）

**可复用代码**：
- `LogUpProof::create` — `lookup.rs:L247-L281`
- `LogUpProof::verify` — `lookup.rs:L293-L318`
- `LogUpProof::verify_equation` — `lookup.rs:L327-L371`
- `LogUpProof::to_ccs_instance` — `lookup.rs:L382-L430`
- `expand_to_bytes` — `memory.rs:L49-L80`
- `Transcript` — 复用现有 transcript 模块

**测试策略**：
- 复用现有 `test_permutation_mixed_size_*` 系列测试，断言 LogUp 路径与 O(n²) 路径结果一致
- 新增大规模内存访问性能测试（1000+ access），验证 O(n log n) 提升
- 篡改 byte_val 失败测试
- permutation 顺序伪造失败测试
- LogUp proof 可被 `fold_loop` 消费测试

**风险与缓解**：
- **风险**：step_index 时序约束在 LogUp 中需额外处理（multiplicity 不区分先后）。
- **缓解**：将 step_index 编入 permutation key 的 Fr 编码，确保 read 的 key 必须匹配某 write 的 key；时序通过前置 `check_uninitialized_read` 保证。
- **风险**：LogUp 等式计算涉及逆元，β 与 t_i 碰撞时 denom=0。
- **缓解**：复用 `lookup.rs` 已有的碰撞检测（L291-L292）。

**交付物**：`verify_memory_permutation` 返回 `LogUpProof`；CCS 实例可被 fold_loop 消费；O(n²) → O(n log n)。

---

## Phase H: ECDSA Full 256-bit 标量支持 (P1-5)

**目标**：将 ECDSA Full 模式从 8-bit 小标量升级到真实 256-bit 标量。

**动机**：当前 `make_full_mode_test_inputs()` 用 s=3/z=2/r=1 小标量，因 `scalar_mul` 的 8-bit recompose 约束要求 `scalar.limbs[0] < 2^num_bits`。真实 ECDSA 签名的 r/s 为 256-bit，无法通过此约束。市场 zkVM（SP1/RISC Zero）均支持任意 256-bit 标量。

**子步骤**：
1. **H-1**：评估两种方案：
   - 方案 A：直接提升 `num_bits` 到 256（约束数 ~19M，prover 时间长）
   - 方案 B：分段标量分解（windowed scalar mul，每段 64-bit，4 段折叠）
   - 推荐方案 B，约束数可降至 ~6M
2. **H-2**：实现选择的方案（若方案 B，新增 `scalar_mul_windowed` 函数）
3. **H-3**：更新 `make_full_mode_test_inputs()` 使用真实 secp256k1 测试向量（RFC 6979）
4. **H-4**：更新 `gas_cost()` 反映 256-bit 真实成本
5. **H-5**：测试 + 回归

**关键文件**：
- `poker_zkvm/src/precompiles/ecdsa.rs`（L74 构造函数 + 测试模块）
- `poker_zkvm/src/precompiles/secp256k1_ops.rs`（L256-L381 scalar_mul，可能新增 windowed 版本）

**可复用代码**：
- `EcdsaVerifyCircuit::new_full_with_bits(n)` — `ecdsa.rs:L74`
- `scalar_mul` — `secp256k1_ops.rs:L256-L381`
- `NonNativeBuilder` — `non_native.rs`

**测试策略**：
- 使用 RFC 6979 测试向量（真实 secp256k1 签名）
- 篡改 r/s/px/py 失败测试
- gas cost 基准测试
- 与 8-bit 模式向后兼容测试

**风险与缓解**：
- **风险**：256-bit 约束数大（19M），prover 时间可能过长（分钟级）。
- **缓解**：先 benchmark 64-bit 增量，确认线性增长后推进到 256-bit；必要时引入分段折叠。

**交付物**：Full 模式支持任意 256-bit secp256k1 签名验证。

---

## Phase I: 预编译补齐 (P1-1)

**目标**：将预编译覆盖率从 3/8 提升到 8/8，补齐市场标准预编译。

**动机**：当前仅 poseidon/sha256/ecdsa 三个真实预编译。市场主流 zkVM 提供 7-8 个预编译（keccak256/ed25519/bn254/bls12-381/modexp/merkle_verify）。预编译缺失导致对应运算 cycle 开销膨胀 10-100 倍。

**子步骤**（每个预编译独立）：
1. **I-1: keccak256** — 新增 `precompiles/keccak256.rs`，参考 SHA-256 的 CCS 模式（`sha256.rs`），实现 Keccak-f[1600] 轮函数。Ethereum 兼容必需。
2. **I-2: merkle_verify** — 新增 `precompiles/merkle_verify.rs`，复用 Poseidon 哈希 + 路径验证约束。
3. **I-3: ed25519** — 新增 `precompiles/ed25519.rs`，复用 curve25519-dalek（若依赖可用）或自实现 Ed25519 验签约束。
4. **I-4: bn254 pairing** — 新增 `precompiles/bn254_pairing.rs`，复用 ark-bn254 pairing。用于递归 SNARK 验证。
5. **I-5: modexp** — 新增 `precompiles/modexp.rs`，基于 NonNativeBuilder 实现大数模幂。
6. **I-6: bls12-381 pairing** — 新增 `precompiles/bls12_381_pairing.rs`（可选，若项目已有 BLS12-381 依赖）。
7. **I-7**: 注册到 `PrecompileRegistry` + `syscalls/mod.rs` + `syscalls/gas.rs`

**关键文件**：
- `poker_zkvm/src/precompiles/`（新增 5-6 个模块）
- `poker_zkvm/src/precompiles/mod.rs`（注册）
- `poker_zkvm/src/syscalls/mod.rs`（新增 syscall 入口）
- `poker_zkvm/src/syscalls/gas.rs`（新增 gas 常量）

**可复用代码**：
- `PrecompileCircuit` trait — `precompiles/mod.rs:L35-L65`
- `NonNativeBuilder` — `non_native.rs`
- SHA-256 的 CCS 构建模式 — `sha256.rs:L109-L214`
- Poseidon 的轮函数约束模式 — `poseidon.rs:L94-L204`

**测试策略**：
- 每个预编译 `build_ccs` + `assign_witness` + `satisfied_by` 闭环
- keccak256：使用 NIST SHA-3 测试向量
- merkle_verify：使用已知 Merkle tree 路径
- ed25519：使用 RFC 8032 测试向量
- bn254 pairing：使用 ark-bn254 测试向量
- modexp：使用大数运算测试向量

**风险与缓解**：
- **风险**：bn254 pairing 约束数极大（~100M+），可能不实际。
- **缓解**：可作为 hint-based 预编译（信任 host 计算，仅验证承诺），而非完整电路约束。
- **风险**：ed25519 依赖 curve25519-dalek 可能引入 unsafe。
- **缓解**：检查依赖的 unsafe 策略，必要时自实现 Ed25519 验签约束。

**交付物**：8/8 预编译覆盖；每个预编译有完整测试。

---

## Phase J: zk_shuffle 真实电路 (P0-3)

**目标**：将 `ZkShuffleCcsCircuit` 从 stub 升级为真实 CCS 电路。

**动机**：当前 `zk_shuffle.rs` 全方法返回 "Phase 11 pending"。ZkShuffle 是项目核心业务（扑克牌洗牌），stub 状态阻塞核心 ZK 功能。`poker_l1/src/offline/hypernova.rs:L318-L322` 的 `ZkShuffleVerifier` Production 路径也返回未迁移错误。

**子步骤**：
1. **J-1: 探索 spike**（1-2 天）：
   - 定位 `poker_protocol::zk_shuffle` 的真实电路实现
   - 搜索 poker_l1/poker_protocol 中的 ZkShuffle 相关代码
   - 确认是否为外部 crate 依赖
   - 评估真实电路的 witness 结构、约束数量、公共输入
2. **J-2: 决策点**：
   - 若找到真实电路 → 迁移路径（J-3a）
   - 若未找到 → 降级为基于 shuffle 语义重新实现（J-3b）
3. **J-3a: 迁移路径**：
   - 实现 `ZkShuffleCcsCircuit::build_ccs` / `assign_witness` / `to_ccs_instance`
   - 迁移为 Fr-based CCS
   - 处理类型转换（poker_l1 Fr vs poker_zkvm Fr）
4. **J-3b: 重新实现路径**：
   - 基于 shuffle 语义实现约束（Permutation + Card range check）
   - 参考 ZkShuffle 论文设计 CCS 电路
5. **J-4**: 在 `poker_l1/src/offline/hypernova.rs:L318` 接入真实 verifier，替换 "Phase 11 尚未迁移" 错误
6. **J-5**: 测试 + 回归

**关键文件**：
- `poker_zkvm/src/precompiles/zk_shuffle.rs`（全文件改造）
- `poker_l1/src/offline/hypernova.rs`（L318-L322 接入）
- `poker_l1/src/offline/zk_verifier.rs`（SCHEME_ZKSHUFFLE = 4）

**测试策略**：
- 真实 ZkShuffle proof 通过验证
- 篡改 proof 失败测试
- 与 poker_l1 集成测试
- grace 期前后签名形式测试

**风险与缓解**：
- **风险**：真实电路位置不明是最大风险。
- **缓解**：J-1 探索 spike 先行，若无法定位则降级为 J-3b 重新实现。
- **风险**：ZkShuffle 电路可能极复杂（约束数百万级）。
- **缓解**：评估是否可拆分为多个子电路折叠。

**交付物**：`to_ccs_instance` 返回真实 `CcsInstance`；`ZkShuffleVerifier` Production 路径可用。

---

## Phase K: RV32IM M 扩展 (P0-4)

**目标**：在 RV32I 基础上增加 M 扩展的 8 条指令：MUL/MULH/MULHSU/MULHU/DIV/DIVU/REM/REMU。

**动机**：当前仅支持 RV32I 子集，不支持乘除法。任何乘除运算需软件展开为加法/移位循环，cycle 开销膨胀 10-100 倍。市场主流 zkVM（RISC Zero/SP1/Nexus）均支持 RV32IM。M 扩展是智能合约场景的硬需求。

**子步骤**：
1. **K-1**：在 `Instruction` 枚举新增 8 个 variant（R-type，opcode=0x33，funct7=0x01）
2. **K-2**：`decode` 函数扩展 opcode 0x33 的 (funct3, funct7=0x01) 分支
3. **K-3**：`execute` 函数实现 8 条指令语义（RV32M 规范：DIVU by 0 = 2^32-1，DIV overflow = -2^31）
4. **K-4**：`algebra.rs` 新增 MUL 子电路（witness 含 hi/lo 分解 + overflow 约束）和 DIV 子电路（witness 含商/余数 + 除数非零约束）
5. **K-5**：测试 + 回归

**关键文件**：
- `poker_zkvm/src/isa/mod.rs`（枚举 + decode + execute）
- `poker_zkvm/src/constraints/algebra.rs`（新增 MUL/DIV 子电路）

**可复用代码**：
- 现有 R-type 指令的 decode/execute 模式
- `CcsBuilder` 约束构建模式

**测试策略**：
- decode/execute 往返测试（编码→解码→执行）
- 边界用例：MUL 溢出、DIV by zero、DIV overflow、REM 符号
- CCS `satisfied_by` 闭环测试
- 含 MUL/DIV 的程序端到端 proof 生成

**风险与缓解**：
- **风险**：DIV 的非零除数约束需引入辅助 witness。
- **缓解**：参考市场 zkVM 的除法约束模式（商 q、余数 r、约束 `a = q*b + r` + `0 <= r < |b|`）。
- **风险**：M 扩展影响 ELF 编译器（riscv32i → riscv32im）。
- **缓解**：更新 `compile_crate` 目标，验证现有 ELF 兼容性。

**交付物**：8 条 M 指令完整 decode/execute/constraint 闭环。

---

## Phase L: Gas 模型 + STARK fallback + 形式化验证 (P1-2, P1-3, P1-4)

**目标**：对齐市场 gas 模型；评估 STARK fallback；引入形式化验证。

**子步骤**（可独立）：
1. **L-1: Gas 模型对齐**（P1-3）：
   - 调研 SP1/RISC Zero 的 gas 模型（per-instruction + per-syscall + per-memory-access）
   - 更新 `syscalls/gas.rs` 常量，新增 per-instruction gas 表
   - 文档化 gas 估算公式
2. **L-2: STARK fallback 评估**（P1-2）：
   - 评估 Plonky3/FRI 作为 Hypernova 备选后端的可行性
   - 评估 CCS 后端可替换性（CCS 泛化 R1CS/Plonkish/AIR）
   - 产出评估文档，不一定要实现
3. **L-3: 形式化验证**（P1-4）：
   - 对核心数学不变量编写 `proptest` 属性测试：
     - fold 等式 `C' = C_L + r·C_C`
     - LogUp 等式 `Σ m_i/(β-t_i) == Σ 1/(β-f_j)`
     - CCS `satisfied_by` 一致性
   - 评估引入 Lean4/Coq 形式化证明的可行性
   - 产出属性测试套件 + 评估文档

**关键文件**：
- `poker_zkvm/src/syscalls/gas.rs`（扩展）
- `poker_zkvm/tests/formal_properties.rs`（新增）
- `.trae/specs/build-hypernova-zkvm/stark_fallback_evaluation.md`（评估文档）

**测试策略**：
- Gas 估算与市场 zkVM 偏差 < 20%
- `proptest` 覆盖 1000+ 随机实例
- 属性测试全绿

**风险与缓解**：
- **风险**：STARK fallback 工作量大（需实现 FRI）。
- **缓解**：L-2 仅评估不实现，实现留待下一周期。
- **风险**：形式化验证学习曲线陡。
- **缓解**：先用 `proptest` 覆盖，逐步引入证明助手。

**交付物**：gas 模型文档化；STARK fallback 评估文档；属性测试套件。

---

## 跨文件一致性计划

每阶段完成后同步更新三份文档（`/Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/`）：

| 文档 | 更新时机 | 更新内容 |
|------|----------|----------|
| `spec.md` | 阶段开始前 | 新增 Phase 编号、设计决策（D 编号）、BREAKING 声明 |
| `tasks.md` | 阶段开始时 | 新增 Task/SubTask 条目（checkbox） |
| `checklist.md` | 阶段完成时 | 新增 checkpoint，逐项勾选验证结果 |

文档更新在代码 PR 前完成，确保 spec 先行。

---

## 验证策略

**每阶段端到端验证**：构建最小 Rust 程序 → 编译为 ELF → 执行 trace → CCS → fold → compress → verify 全链路。

**阶段验证点**：
- Phase F：`CompressedProof::Groth16` verify 通过，证明大小 < 1KB
- Phase G：大规模内存访问的 LogUp proof 可折叠，O(n²) → O(n log n)
- Phase H：真实 secp256k1 签名验证通过
- Phase I：8/8 预编译 `satisfied_by` 闭环
- Phase J：ZkShuffle proof 通过 Production verifier
- Phase K：含 MUL/DIV 的程序生成有效 proof
- Phase L：gas 估算偏差 < 20%，proptest 全绿

**回归测试**：每阶段完成后运行全量 `cargo test`。关键回归用例：
- 现有 `test_groth16_compress_*` 不得破坏
- 现有 `test_permutation_*` 不得破坏
- 现有 `test_decode_*` 不得破坏
- poker_zkvm lib + poker_l1 lib + e2e + soundness 全量测试

---

## 执行顺序与依赖

```
Phase F (Groth16 压缩) ──┐
                         ├──> Phase J (zk_shuffle) ──┐
Phase G (LogUp 内存) ────┤                            │
                         │                            ├──> Phase L (收尾)
Phase H (ECDSA 256-bit) ─┤                            │
                         │                            │
Phase I (预编译补齐) ────┘                            │
                                                      │
Phase K (M 扩展) ─────────────────────────────────────┘
```

- Phase F/G/H/I 顺序执行，互相独立
- Phase J 依赖 Phase I 的 CCS 模式参考
- Phase K 独立，可任何时候执行（延后到后期）
- Phase L 依赖前置阶段稳定

---

## 关键风险总结

| 风险 | 阶段 | 缓解 |
|------|------|------|
| Fq/Fr 域兼容性 | Phase F | 小规模 fold chain 验证，必要时引入 cycle-of-curves |
| 256-bit ECDSA 约束数大 | Phase H | 分段标量分解，benchmark 增量 |
| zk_shuffle 真实电路位置不明 | Phase J | 探索 spike 先行，降级为重新实现 |
| M 扩展影响编译器 | Phase K | 更新 riscv32im 目标，验证 ELF 兼容性 |
| bn254 pairing 约束数极大 | Phase I | hint-based 预编译 fallback |
