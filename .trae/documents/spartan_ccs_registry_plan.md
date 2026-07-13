# Spartan 压缩集成 — CCS 注册表方案（修正内嵌 CCS 超限问题）

## Context

**问题**：上一轮实现将完整 CCS 结构内嵌到 SpartanCompressedProof，但生产级 CCS 为 1.9MB（49 矩阵 × ~800 条目 × 48B/条目），导致 Spartan proof 1.9MB > 64KB 上链限制。已知失败测试 `cargo-zkvm.rs:459 test_prove_writes_proof_and_public_io_files` 仍失败。

**用户决策**：改用外部 CCS 注册表方案 — `verify_production` 签名从 `ccs_whitelist: &[[u8; 32]]` 改为 `ccs_registry: &[Ccs]`。Spartan proof 不含 CCS，verifier 从注册表按 `ccs_commitment` 查找 CCS 结构。

**目标**：
1. Spartan proof 移除内嵌 CCS，降至 ~7KB（远低于 64KB）
2. `verify_production` 支持 HYPN/SPRT magic 字节分派
3. 修复失败测试 + 新增 Spartan 路径覆盖测试
4. 更新所有调用方（poker_zkvm 测试/bench + poker_l1）

## 当前状态

已完成（上一轮）：
- `spartan.rs` SpartanCompressedProof 含 `ccs: Ccs` 字段（**需移除**）
- `prover/mod.rs` serialize_spartan_proof/deserialize_spartan_proof 含 CCS 序列化（**需移除**）
- `prover/mod.rs` prove() 自动压缩逻辑已实现（保留，仅调整错误消息）
- `prover/mod.rs` 常量 SPARTAN_PROOF_MAGIC/VERSION/MAX_SIZE 已定义（保留）

未完成：
- `verifier.rs` magic 字节分派（需实现）
- 所有测试更新（需实现）
- poker_l1 调用方更新（需实现）

## 文件修改清单

### 1. `poker_zkvm/src/prover/spartan.rs` — 移除 ccs 字段

**SpartanCompressedProof 结构（L39-68）**：移除 `pub ccs: Ccs` 字段。保留 `ccs_commitment: [u8; 32]`（verifier 用它从注册表查找 CCS）。

**spartan_compress（L87-137）**：移除 `ccs: proof.initial_lcccs.ccs_ref.clone()` 行。

**spartan_verify（L153-185）**：签名不变（仍接收 `ccs: &Ccs` 参数），逻辑不变。

**测试（L272-386）**：4 个现有测试无需修改（它们调用 `spartan_verify(spartan, &ccs, &pcs)`，ccs 来自测试 fixture 而非 proof 结构）。

### 2. `poker_zkvm/src/prover/mod.rs` — 序列化/注册表/测试辅助

**serialize_spartan_proof（L742-784）**：移除 CCS 序列化块（L754-757 的 `ccs_bytes` 逻辑）。

**deserialize_spartan_proof（L796-930）**：移除 CCS 反序列化 + CCS 一致性校验（L857-868）。反序列化后 SpartanCompressedProof 不含 ccs 字段。

**default_ccs_whitelist() → default_ccs_registry()（L1331-1335）**：
```rust
pub fn default_ccs_registry() -> Vec<Ccs> {
    let (proof_bytes, _) = generate_test_proof();
    let proof = deserialize_proof(&proof_bytes).expect("deserialize generate_test_proof 应成功");
    vec![proof.initial_lcccs.ccs_ref]
}
```
保留 `default_ccs_whitelist` 作为 deprecated 别名（返回 `Vec<[u8;32]>`），向后兼容：
```rust
#[deprecated(note = "使用 default_ccs_registry() 返回完整 CCS 结构")]
pub fn default_ccs_whitelist() -> Vec<[u8; 32]> {
    default_ccs_registry().iter().map(|c| c.ccs_commitment()).collect()
}
```

**prove() 错误消息（L1124-1129）**：更新为 "proof 过大 (Spartan compressed {} bytes > {} limit)" — 移除 "CCS 可能过大需 CycleFold" 提示（CCS 已不内嵌，超限仅可能因 fold_step 过多）。

**新增测试 `test_prove_auto_compresses_to_spartan`**：构造多 batch 程序（proof > 64KB），验证 `prove()` 返回前 4 字节为 `b"SPRT"` + 大小 ≤ 64KB。

### 3. `poker_zkvm/src/verifier.rs` — magic 分派 + CCS 注册表

**verify_production（L65-69）**：重构为分派入口
```rust
pub fn verify_production(
    proof_bytes: &[u8],
    public_io: &ZkPublicIo,
    ccs_registry: &[Ccs],
) -> Result<bool, ZkvmError> {
    if proof_bytes.len() < 4 {
        return Err(ZkvmError::InvalidZkProofFormat("proof 过短（< 4 字节 magic）".to_string()));
    }
    match &proof_bytes[0..4] {
        b"HYPN" => verify_hypernova(proof_bytes, public_io, ccs_registry),
        b"SPRT" => verify_spartan(proof_bytes, public_io, ccs_registry),
        _ => Err(ZkvmError::InvalidZkProofFormat(format!(
            "未知 magic: {:?}", &proof_bytes[0..4]
        ))),
    }
}
```

**新增私有函数 verify_hypernova**：现有 L70-318 逻辑移入，签名 `fn verify_hypernova(proof_bytes, public_io, ccs_registry: &[Ccs]) -> Result<bool, ZkvmError>`。修改点：
- L74 CCS 白名单校验：从 `ccs_whitelist.contains(&proof.ccs_commitment)` 改为 `ccs_registry.iter().any(|c| c.ccs_commitment() == proof.ccs_commitment)`
- 其余逻辑不变（proof.initial_lcccs.ccs_ref 仍提供完整 CCS）

**新增私有函数 verify_spartan**：
```rust
fn verify_spartan(
    proof_bytes: &[u8],
    public_io: &ZkPublicIo,
    ccs_registry: &[Ccs],
) -> Result<bool, ZkvmError> {
    let proof = deserialize_spartan_proof(proof_bytes)?;
    
    // CCS 注册表查找
    let ccs = ccs_registry.iter()
        .find(|c| c.ccs_commitment() == proof.ccs_commitment)
        .ok_or_else(|| ZkvmError::Other(format!(
            "CCS 不在注册表: commitment {:?}..",
            &proof.ccs_commitment[..8]
        )))?;
    
    // public_io 绑定校验
    if hash_public_io(public_io) != proof.public_io_commitment {
        return Err(ZkvmError::Other("public_io 不匹配".to_string()));
    }
    
    // IpaPcs 创建
    let pcs_n_vars = ccs.num_vars.trailing_zeros() as usize;
    if !ccs.num_vars.is_power_of_two() {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "ccs.num_vars {} 非 2 的幂", ccs.num_vars
        )));
    }
    let pcs = IpaPcs::new(pcs_n_vars)?;
    
    // Spartan 验证（sumcheck + PCS opening）
    crate::prover::spartan::spartan_verify(&proof, ccs, &pcs)
}
```

**测试更新（L321-685）**：
- `extract_ccs_whitelist` → `extract_ccs_registry`：返回 `Vec<Ccs>`（从 proof_bytes 反序列化取 `initial_lcccs.ccs_ref`）
- 所有 `let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);` → `let ccs_registry = extract_ccs_registry(&proof_bytes);`
- 所有 `verify_production(&x, &y, &ccs_whitelist)` → `verify_production(&x, &y, &ccs_registry)`
- `test_verify_production_rejects_unregistered_ccs`：`let empty_registry: Vec<Ccs> = vec![];`
- `test_verify_production_oversized_proof_fails`：`verify_production(&oversized, &public_io, &[])` 不变（空 slice 兼容）

**新增测试**：
- `test_verify_production_spartan_branch`：prove（多 batch）→ verify_production 往返通过
- `test_verify_production_spartan_tampered`：篡改 Spartan proof 的 final_u_l → 验证失败
- `test_verify_production_magic_dispatch`：HYPN 和 SPRT 各走对应分支
- `test_verify_production_spartan_rejects_unregistered_ccs`：Spartan proof 的 ccs_commitment 不在注册表 → 拒绝
- `test_verify_production_spartan_rejects_mismatched_public_io`：Spartan proof 的 public_io 不匹配 → 拒绝

### 4. `poker_zkvm/benches/phase12_benchmarks.rs`

L110-114：`default_ccs_whitelist()` → `default_ccs_registry()`，变量名 `ccs_whitelist` → `ccs_registry`。

### 5. `poker_zkvm/tests/e2e_sha256_chain.rs`

L12：import `default_ccs_registry` 替换 `default_ccs_whitelist`
L49-50：`let ccs_registry = default_ccs_registry();` + `verify_production(&proof_bytes, &public_io, &ccs_registry)`

### 6. `poker_zkvm/tests/e2e_poker_hand_eval.rs`

L13：import `default_ccs_registry` 替换 `default_ccs_whitelist`
L39-40：同上模式

### 7. `poker_zkvm/tests/e2e_fibonacci.rs`

L12：import `default_ccs_registry` 替换 `default_ccs_whitelist`
L35-36：同上模式

### 8. `poker_zkvm/tests/soundness_tests.rs`

L21：import `default_ccs_registry` 替换 `default_ccs_whitelist`
L66-67, L80-81, L277-278, L288-289：`let ccs_registry = default_ccs_registry();` + `verify_production(&x, &y, &ccs_registry)`

### 9. `poker_l1/src/offline/hypernova.rs`

L224-225：
```rust
let ccs_registry = poker_zkvm::prover::default_ccs_registry();
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io, &ccs_registry) {
```

### 10. `.trae/specs/build-hypernova-zkvm/tasks.md`

标记相关 SubTask 完成：
- SubTask 7.1.4：prove() 自动压缩集成
- 新增 SubTask 7.4（如需要）：verify_production magic 分派 + CCS 注册表

## 实现顺序

1. **spartan.rs**：移除 ccs 字段（最小改动，不影响现有测试）
2. **prover/mod.rs**：移除 CCS 序列化 + 改 default_ccs_registry + 保留 deprecated 别名
3. **verifier.rs**：magic 分派 + verify_hypernova/verify_spartan + 更新所有测试
4. **测试文件 + bench**：批量更新 import 和调用
5. **poker_l1**：更新调用方
6. **验证**：cargo test/clippy/fmt 全通过
7. **tasks.md**：标记完成

## 关键复用

- `Ccs::ccs_commitment()` — 注册表查找 key
- `deserialize_spartan_proof` / `serialize_spartan_proof` — Spartan proof 序列化（移除 CCS 后）
- `spartan_verify(proof, ccs, pcs)` — Spartan 验证核心逻辑（签名不变）
- `hash_public_io` — public_io 绑定
- `IpaPcs::new(pcs_n_vars)` — PCS 创建

## 验证步骤

1. **单元测试**：
```bash
cargo test -p poker_zkvm --lib prover::spartan
cargo test -p poker_zkvm --lib prover::tests::test_prove_auto_compresses_to_spartan
cargo test -p poker_zkvm --lib verifier::tests
cargo test -p poker_zkvm --bin cargo-zkvm test_prove_writes_proof_and_public_io_files
```

2. **集成测试**：
```bash
cargo test -p poker_zkvm --test e2e_sha256_chain
cargo test -p poker_zkvm --test e2e_poker_hand_eval
cargo test -p poker_zkvm --test e2e_fibonacci
cargo test -p poker_zkvm --test soundness_tests
```

3. **poker_l1**：
```bash
cargo test -p poker_l1 --lib offline::hypernova
```

4. **质量检查**：
```bash
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo fmt --check -p poker_zkvm
cargo clippy -p poker_l1 --all-targets -- -D warnings
cargo fmt --check -p poker_l1
```

5. **完整测试套件**：
```bash
cargo test -p poker_zkvm
cargo test -p poker_l1
```

## 风险与回退

- **API 破坏**：`verify_production` 签名变更影响所有调用方。通过保留 `default_ccs_whitelist` deprecated 别名缓解过渡。所有调用方在本 phase 内同步更新。
- **CCS 注册表完整性**：`default_ccs_registry()` 当前仅返回 1 个 CCS（测试 fixture）。生产部署需扩展为覆盖所有合法 batch_size 的 CCS 集合。本 phase 不处理此问题，留待生产部署配置。
- **HYPN 路径兼容性**：HYPN proof 仍内嵌完整 CCS（在 `initial_lcccs.ccs_ref` 中），verifier 额外校验其 commitment 在注册表中（防御深度）。旧 HYPN proof 不受影响。
- **Spartan proof 大小**：移除 CCS 后 ~7KB，远低于 64KB。即使 fold_step_count 较大（影响 final_sumcheck 大小），仍远低于上限。
