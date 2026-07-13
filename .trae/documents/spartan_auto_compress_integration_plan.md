# Spartan 自动压缩集成到 prove() 主流程 — 实现 Plan

## Context

**问题**：当前 `poker_zkvm/src/prover/mod.rs:886-892` 的 `prove()` 在生成的 HypernovaProof 序列化后超过 `MAX_ZKVM_PROOF_SIZE = 64KB` 时**直接返回错误**，不进行压缩。这导致已知失败测试 `bin/cargo-zkvm.rs:459 test_prove_writes_proof_and_public_io_files`（多 batch 程序生成 ~2.4MB proof > 64KB）。

**已完成**：`poker_zkvm/src/prover/spartan.rs::spartan_compress` + `spartan_verify` 已完整实现（Phase 7.2），实测 Spartan proof ~6-7KB，远低于 64KB 上链限制。但未集成到 `prove()` 主流程。

**目标**：将 Spartan 压缩自动集成到 `prove()`，proof > 64KB 时自动调用 `spartan_compress` 并序列化为 Spartan proof bytes；扩展 `verify_production` 按 magic 字节分派 HYPN/SPRT 验证路径。修复失败测试 + 新增覆盖测试。

**用户决策**：Spartan proof 内嵌完整 CCS 结构（与 HYPN 一致），`verify_production` 签名不变（`ccs_whitelist: &[[u8; 32]]`）。Spartan verify 从内嵌 CCS 提取矩阵做 sumcheck，无需调用方提供 CCS 注册表。

## 关键设计

### Magic 字节分派
- 现有 HYPN: `PROOF_MAGIC = b"HYPN"` (4B) + `PROOF_VERSION = 3` (1B)
- 新增 SPRT: `SPARTAN_PROOF_MAGIC = b"SPRT"` (4B) + `SPARTAN_PROOF_VERSION = 1` (1B)
- `verify_production` 入口读取前 4 字节分派

### Spartan proof 序列化布局
```
magic(4B "SPRT") || version(1B=1) || abi_version(1B)
|| ccs_commitment(32B)                  // 校验用（与 ccs.ccs_commitment() 一致）
|| public_io_commitment(32B)
|| ccs(Ccs::to_bytes 变长)              // 完整 CCS 结构（用户决策）
|| final_witness_commitment(33B compressed G1Affine, u32 LE length prefix)
|| final_u_l(32B Fr)
|| final_r_x_l(u32 LE length + 32B/entry)
|| final_sumcheck(serialize_sumcheck 复用)
|| pcs_opening(serialize_ipa_proof 复用)
|| r_y(u32 LE length + 32B/entry)
|| z_at_r_y(32B Fr)
|| fold_step_count(8B LE u64)
```
- 上限 `SPARTAN_MAX_PROOF_TOTAL_SIZE = 64KB`（与 HYPN 一致，允许 CCS 内嵌 + Spartan 核心 ~7KB）
- 反序列化时**总长度优先**校验 + 单项子分配校验，防 OOM DoS

### SpartanCompressedProof 结构扩展
`spartan.rs::SpartanCompressedProof` 新增 `pub ccs: Ccs` 字段：
- `spartan_compress` 时从 `proof.initial_lcccs.ccs_ref.clone()` 提取（HypernovaProof 已含完整 CCS）
- 序列化时通过 `ccs.to_bytes()` 写入
- 反序列化时通过 `Ccs::from_bytes()` 解析
- 反序列化后校验 `ccs.ccs_commitment() == proof.ccs_commitment` 一致性（防篡改）

## 文件修改清单

### 1. `poker_zkvm/src/prover/spartan.rs`
- **SpartanCompressedProof 结构** (L41-62)：新增 `pub ccs: Ccs` 字段
- **spartan_compress** (L81-130)：在构造 SpartanCompressedProof 时填入 `ccs: proof.initial_lcccs.ccs_ref.clone()`
- **现有 4 个测试**：更新 `make_valid_proof()` 已返回 ccs，无需修改；测试 match arm 中需构造 ccs 字段（直接用 `proof.initial_lcccs.ccs_ref.clone()`）
- **新增测试** `test_spartan_proof_serialization_roundtrip`：序列化/反序列化往返一致性 + ccs_commitment 一致性校验

### 2. `poker_zkvm/src/prover/mod.rs`
- **常量** (L252-272 附近)：新增
  ```rust
  pub const SPARTAN_PROOF_MAGIC: &[u8; 4] = b"SPRT";
  pub const SPARTAN_PROOF_VERSION: u8 = 1;
  pub const SPARTAN_MAX_PROOF_TOTAL_SIZE: usize = 64 * 1024;
  ```
- **新增函数** `serialize_spartan_proof(proof: &SpartanCompressedProof) -> Result<Vec<u8>, ZkvmError>` (复用 serialize_commitment / serialize_fr_slice / serialize_sumcheck / serialize_ipa_proof；CCS 用 `proof.ccs.to_bytes()` + u32 LE length prefix)
- **新增函数** `deserialize_spartan_proof(bytes: &[u8]) -> Result<SpartanCompressedProof, ZkvmError>` (总长度优先校验 + magic/version 校验 + ccs_commitment 一致性校验)
- **prove() 修改** (L882-894):
  ```rust
  let proof_bytes = serialize_proof(&proof)?;
  if proof_bytes.len() <= config.proof_size_limit {
      return Ok((proof_bytes, public_io));
  }
  // proof 过大 → Spartan 自动压缩
  let compressed = spartan_compress(&proof)?;
  let spartan_bytes = match compressed {
      CompressedProof::Spartan(s) => serialize_spartan_proof(&s)?,
      _ => return Err(ZkvmError::Other("非 Spartan 变体".to_string())),
  };
  if spartan_bytes.len() > config.proof_size_limit {
      return Err(ZkvmError::Other(format!(
          "proof 过大 (Spartan compressed {} bytes > {} limit)",
          spartan_bytes.len(), config.proof_size_limit
      )));
  }
  Ok((spartan_bytes, public_io))
  ```
- **新增测试** `test_prove_auto_compresses_to_spartan`：构造多 batch 程序（proof > 64KB），验证 `prove()` 返回前 4 字节为 `b"SPRT"` + 大小 ≤ 64KB

### 3. `poker_zkvm/src/verifier.rs`
- **verify_production** (L65-163)：重构为分派入口
  ```rust
  pub fn verify_production(
      proof_bytes: &[u8],
      public_io: &ZkPublicIo,
      ccs_whitelist: &[[u8; 32]],
  ) -> Result<bool, ZkvmError> {
      if proof_bytes.len() < 5 {
          return Err(ZkvmError::InvalidZkProofFormat("proof 过短".to_string()));
      }
      match &proof_bytes[0..4] {
          b"HYPN" => verify_hypernova(proof_bytes, public_io, ccs_whitelist),
          b"SPRT" => verify_spartan(proof_bytes, public_io, ccs_whitelist),
          _ => Err(ZkvmError::InvalidZkProofFormat(format!(
              "未知 magic: {:?}", &proof_bytes[0..4]
          ))),
      }
  }
  ```
- **新增私有函数** `verify_hypernova`：现有 L70-318 逻辑移入（仅函数名变更，签名不变）
- **新增私有函数** `verify_spartan(proof_bytes, public_io, ccs_whitelist)`:
  ```rust
  fn verify_spartan(...) -> Result<bool, ZkvmError> {
      let proof = deserialize_spartan_proof(proof_bytes)?;
      // CCS 白名单校验
      if !ccs_whitelist.contains(&proof.ccs_commitment) {
          return Err(ZkvmError::Other("CCS 不在白名单".to_string()));
      }
      // CCS 内嵌一致性校验（防篡改）
      if proof.ccs.ccs_commitment() != proof.ccs_commitment {
          return Err(ZkvmError::InvalidZkProofFormat(
              "内嵌 CCS commitment 与 ccs_commitment 不一致".to_string()
          ));
      }
      // public_io 绑定
      if hash_public_io(public_io) != proof.public_io_commitment {
          return Err(ZkvmError::Other("public_io 不匹配".to_string()));
      }
      // IpaPcs 创建
      let pcs_n_vars = proof.ccs.num_vars.trailing_zeros() as usize;
      let pcs = IpaPcs::new(pcs_n_vars)?;
      // Spartan 验证
      spartan_verify(&proof, &proof.ccs, &pcs)
  }
  ```
- **新增测试**：
  - `test_verify_production_spartan_branch`：prove → verify_production 往返通过
  - `test_verify_production_spartan_tampered`：篡改 `final_u_l` → 验证失败
  - `test_verify_production_magic_dispatch`：HYPN 和 SPRT 各走对应分支
  - `test_verify_production_spartan_tampered_ccs`：篡改内嵌 CCS → ccs_commitment 不一致错误

### 4. `poker_zkvm/src/bin/cargo-zkvm.rs`
- **test_prove_writes_proof_and_public_io_files** (L459-537)：自动通过（prove 自动压缩后返回成功 + msg 含 "bytes proof"）。无需修改测试代码，仅验证通过。

### 5. `.trae/specs/build-hypernova-zkvm/tasks.md`
- **SubTask 7.1.4**：补充说明"proof > 64KB 时自动调用 spartan_compress 序列化为 Spartan proof bytes（Phase 7 集成完成）"
- **新增 SubTask 7.4**（如需要）："prove() 自动压缩集成 + verify_production magic 分派"
- 完成后标记相关 subtask `[x]`

## 关键复用

- `Ccs::to_bytes()` / `Ccs::from_bytes()` (`poker_zkvm/src/ccs/mod.rs:411, 433`)
- `serialize_commitment` / `serialize_fr_slice` / `serialize_sumcheck` / `serialize_ipa_proof` (`prover/mod.rs:292-390`)
- `deserialize_commitment` / `deserialize_fr_slice` / `deserialize_sumcheck` / `deserialize_ipa_proof` (`prover/mod.rs:462-584`)
- `hash_public_io` (`prover/mod.rs:281`)
- `spartan_compress` / `spartan_verify` (`spartan.rs:81, 146`)
- `IpaPcs::new(pcs_n_vars)` (`pcs/ipa.rs:184`)

## 验证步骤

1. **单元测试**:
   ```bash
   cargo test -p poker_zkvm --lib prover::spartan
   cargo test -p poker_zkvm --lib prover::tests::test_prove_auto_compresses_to_spartan
   cargo test -p poker_zkvm --lib verifier::tests::test_verify_production_spartan
   cargo test -p poker_zkvm --bin cargo-zkvm test_prove_writes_proof_and_public_io_files
   ```

2. **完整测试套件**:
   ```bash
   cargo test -p poker_zkvm
   cargo test -p poker_l1
   ```

3. **质量检查**:
   ```bash
   cargo clippy -p poker_zkvm --all-targets -- -D warnings
   cargo fmt --check -p poker_zkvm
   cargo clippy -p poker_l1 --all-targets -- -D warnings
   ```

4. **端到端验证**:
   - `cargo run --bin cargo-zkvm -- prove --elf <test.elf> --input <test.bin> --output <test.proof>` 输出 "Prove successful" + proof 大小
   - 验证 proof bytes 前 4 字节为 `b"SPRT"`（自动压缩路径）

## 风险与回退

- **Spartan proof 内嵌 CCS 后大小**：测试 CCS 小（~236B），生产 CCS 可能 ~10-30KB。Spartan proof 总大小 = CCS + Spartan 核心（~7KB）。若生产 CCS 过大导致 Spartan proof > 64KB，需后续考虑：
  - (a) CCS Merkle 化 + 仅内嵌 Merkle root + 路径证明
  - (b) 改为方案 A/B（外部 CCS 注册表）
  - 当前先按用户决策内嵌完整 CCS，若生产场景超限再优化

- **CCS 序列化兼容性**：CCS 结构变更会破坏 Spartan proof 反序列化。需保证 `Ccs::to_bytes` / `from_bytes` 版本稳定（当前无版本字段，依赖 `SPARTAN_PROOF_VERSION = 1` 整体版本控制）

- **向后兼容**：HYPN 路径完全不变（仅移入 `verify_hypernova` 函数），旧 proof 仍可验证。prove() 仍优先尝试 HYPN 路径，仅超限时才转 Spartan。

- **测试 fixture 影响**：现有 `default_ccs_whitelist()` 返回 `Vec<[u8;32]>`（不变）；测试中 prove → verify 往返测试需兼容两种 magic（HYPN 单实例路径 + SPRT 多 batch 路径）
