# Phase 7：Prover 与最终压缩

## Context

Phase 6 完成了 Hypernova 折叠算法（CCS 扩展 + LCCCS/CCCCS + fold_step + sumcheck + fold_loop + verify_hypernova，610 lib tests + 30 bin tests 通过）。Phase 7 构建 Prover 主流程，将 ELF → 执行 → trace → CCS 实例 → Hypernova 折叠 → 压缩 → 上链 proof 的端到端管线串联起来。

Phase 7 的核心挑战：
1. **CCS 结构一致性**：`compile_trace_to_ccs` 按 batch_size 分批，每批生成独立 CCS 结构（num_vars/num_rows 依赖 batch 实际大小）。fold_loop 要求所有实例共享同一 CCS。需 padding 使所有 batch 等长。
2. **proof 序列化**：Phase 5.5（serialize）尚未实现，prover 需返回 `proof_bytes`。采用简单二进制编码作为 stub，Phase 5.5 替换为 spec 规范格式。
3. **Spartan/Groth16 压缩**：完整 SNARK 实现超出 MVP 范围。stub 返回 Phase pending 错误。

## 实现步骤

### Step 1 — 常量 + ProverConfig + ZkPublicIo（prover/mod.rs）

将 `prover.rs`（单文件占位）转为 `prover/mod.rs`（目录模块）。

**文件**：`poker_zkvm/src/prover/mod.rs`

1. 定义常量：
   - `MAX_ZKVM_PROOF_SIZE: usize = 64 * 1024`（64KB，spec L692）
   - `MAX_RECURSION_DEPTH: u32 = 16`（spec L565/L694）

2. 定义 `ProverConfig`：
   ```rust
   pub struct ProverConfig {
       pub batch_size: usize,          // 默认 ZKVM_BATCH_SIZE = 1024
       pub max_n_vars: usize,          // IPA PCS 上限，默认 20（2^20 = 1M）
       pub proof_size_limit: usize,    // 默认 MAX_ZKVM_PROOF_SIZE
       pub max_recursion_depth: u32,   // 默认 MAX_RECURSION_DEPTH
       pub randomness_seed: Fr,        // VRF 派生 seed
       pub initial_commitment: Fr,     // host 承诺
       pub final_commitment: Fr,       // host 承诺
   }
   ```
   - `Default` 实现：使用默认值
   - `validate()` 方法：校验 batch_size > 0、max_n_vars ≤ 24 等

3. 定义 `ZkPublicIo`（poker_zkvm 本地版本，spec L59 要求扩展字段）：
   ```rust
   pub struct ZkPublicIo {
       pub input: Vec<u8>,
       pub output: Vec<u8>,
       pub randomness_seed: Fr,
       pub initial_commitment: Fr,
       pub final_commitment: Fr,
       pub event_hashes: Vec<Fr>,
   }
   ```
   - `to_bytes()` / `from_bytes()` 简单二进制编码

4. 测试：config validation、ZkPublicIo 序列化往返

### Step 2 — prove() 主流程（prover/mod.rs）

**核心函数**：
```rust
pub fn prove(
    elf_bytes: &[u8],
    input: &[u8],
    config: &ProverConfig,
) -> Result<(Vec<u8>, ZkPublicIo), ZkvmError>
```

**流程**：
1. `validate_elf(elf_bytes)` → ElfMetadata（复用 `compiler/elf_validator.rs`）
2. `execute_elf_with_config(elf_bytes, config)` → ExecuteResult（复用 `isa/executor.rs`）
   - 构造 `ZkvmExecutionConfig`：input、randomness_seed、initial_commitment、final_commitment
3. **trace padding**：若 `trace.len() % batch_size != 0`，追加 dummy Step（step_index 递增、NOP 指令）使长度整除 batch_size
   - 复用 `trace::Step` 结构（step_index、pc、instruction=NOP、registers=[0;32]、mem_access=vec![]）
   - padding 不影响执行结果（output/events 已在 ExecuteResult 中固定）
4. `compile_trace_to_ccs(&trace, config.batch_size)` → Vec<CcsInstance>（复用 `constraints/mod.rs`）
5. **CCS 一致性校验**：遍历所有 CcsInstance，校验 `ccs.ccs_commitment()` 相同（复用 `fold/ccs.rs`）
6. 创建 `IpaPcs::new(config.max_n_vars)`（复用 `pcs/ipa.rs`）
7. 创建 `Transcript::new()`，absorb CCS commitment + public inputs
8. 派生 `r_x_l`：`transcript.challenge(FOLD_DOMAIN)` → 长度 = log2(num_rows) 的 challenge
9. **转换 CcsInstance → LCCCS/CCCCS**：
   - 第一个 CcsInstance → `ccs.to_lcccs(&witness, &r_x_l, public_inputs)` → LCCCS
   - IPA commit witness → `IpaPcs::commit(MultilinearPoly::from_evals(witness))` → IpaCommitment
   - 剩余 CcsInstance → `ccs.to_cccs(&witness, x_c, commitment)` → CCCCS
   - x_c = r_x_l（同一求值点，简化 MVP）
10. `fold_loop(&ccs, lcccs, initial_commitment, &ccccs_instances, &pcs, &mut transcript)` → HypernovaProof（复用 `fold/fold_loop.rs`）
11. **序列化 proof**：`serialize_proof(&proof)` → proof_bytes（简单二进制编码，stub）
12. **proof 大小检查**：`proof_bytes.len() ≤ config.proof_size_limit`，超出返回 `Other("proof too large, trigger CycleFold")` （CycleFold 留待 Phase 12）
13. 构造 `ZkPublicIo`：input、output、randomness_seed、commitments、event_hashes
14. 返回 `(proof_bytes, public_io)`

**关键复用**：
- `compiler/elf_validator.rs::validate_elf` — ELF 校验
- `isa/executor.rs::execute_elf_with_config` — ELF 执行
- `constraints/mod.rs::compile_trace_to_ccs` — trace → CCS 实例
- `fold/ccs.rs::Ccs::to_lcccs` / `to_cccs` / `ccs_commitment` — 实例转换
- `pcs/ipa.rs::IpaPcs::new` / `commit` — IPA 承诺
- `fold/fold_loop.rs::fold_loop` — Hypernova 折叠
- `transcript.rs::Transcript` — Fiat-Shamir

**测试**：
- prove 成功（minimal ELF → proof_bytes + public_io）
- prove 失败：无效 ELF、空 input、trace 过长
- CCS 一致性校验（不同 CCS → 错误）
- proof 大小检查

### Step 3 — proof 序列化 stub（prover/mod.rs）

**函数**：
```rust
fn serialize_proof(proof: &HypernovaProof) -> Result<Vec<u8>, ZkvmError>
fn deserialize_proof(bytes: &[u8]) -> Result<HypernovaProof, ZkvmError>
```

简单二进制编码（非 spec 规范格式，Phase 5.5 替换）：
- magic (4B) + abi_version (1B) + field 标记
- folded_instance 各字段（length-prefixed）
- witness_commitment（compressed point 33B）
- final_sumcheck 各字段
- pcs_opening 各字段
- r_y / z_at_point

**测试**：序列化往返一致性

### Step 4 — Spartan 压缩 stub（prover/spartan.rs）

**文件**：`poker_zkvm/src/prover/spartan.rs`

```rust
pub struct SpartanProof { /* stub — Phase 12 实现 */ }

pub fn spartan_compress(
    proof: &HypernovaProof,
) -> Result<SpartanProof, ZkvmError> {
    Err(ZkvmError::Other("spartan_compress: Phase 12 pending".to_string()))
}
```

**测试**：stub 返回错误

### Step 5 — Groth16 压缩 stub（prover/groth16_compress.rs）

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`

```rust
pub struct Groth16Proof { /* stub — Phase 12 实现 */ }

pub fn groth16_compress(
    proof: &HypernovaProof,
) -> Result<Groth16Proof, ZkvmError> {
    Err(ZkvmError::Other("groth16_compress: Phase 12 pending".to_string()))
}
```

**测试**：stub 返回错误

### Step 6 — 集成 cargo-zkvm prove 子命令

**文件**：`poker_zkvm/src/bin/cargo-zkvm.rs`

替换 `cmd_prove` stub：
- 读取 ELF 文件 + input 文件
- 构造 `ProverConfig::default()`
- 调用 `poker_zkvm::prover::prove(elf_bytes, &input, &config)`
- 写 proof_bytes 到 --output 文件
- 写 public_io 到 --public-io 文件

**测试**：prove 子命令成功/失败路径

### Step 7 — 文档 + 最终验证

- 更新 `poker_zkvm/docs/alternatives.md` Phase 7 章节
- `cargo test -p poker_zkvm` 全量通过
- `cargo clippy -p poker_zkvm --all-targets` 零警告
- `cargo build --workspace` 成功

## 关键设计决策

1. **trace padding**：追加 dummy NOP Step 使 `trace.len() % batch_size == 0`。padding 不影响执行结果（output/events 已固定），仅保证 CCS 结构一致。
2. **x_c = r_x_l**：MVP 简化 — CCCCS 的 x_c 使用与 LCCCS 相同的 r_x_l。完整实现应由 transcript 为每个 CCCCS 派生独立 x_c。
3. **proof 序列化 stub**：简单二进制编码，非 spec L452-483 规范格式。Phase 5.5 实现正式序列化后替换。
4. **Spartan/Groth16 stub**：返回 Phase pending 错误。完整 SNARK 实现留待 Phase 12。
5. **ZkPublicIo 本地定义**：poker_zkvm 独立于 poker_l1，本地定义 ZkPublicIo。Phase 11 集成时与 poker_l1 版本对齐。

## 验证方法

1. `cargo test -p poker_zkvm --lib prover` — prover 模块单元测试
2. `cargo test -p poker_zkvm --bin cargo-zkvm` — cargo-zkvm 集成测试
3. `cargo test -p poker_zkvm` — 全量测试无回归
4. `cargo clippy -p poker_zkvm --all-targets` — 零警告
5. `cargo build --workspace` — workspace 构建成功

## 涉及文件

- `poker_zkvm/src/prover/mod.rs`（新建，替换 prover.rs）
- `poker_zkvm/src/prover/spartan.rs`（新建）
- `poker_zkvm/src/prover/groth16_compress.rs`（新建）
- `poker_zkvm/src/prover.rs`（删除）
- `poker_zkvm/src/bin/cargo-zkvm.rs`（修改 cmd_prove）
- `poker_zkvm/docs/alternatives.md`（追加 Phase 7 章节）
