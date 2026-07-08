# Phase 8 实施计划：链上 Verifier Production 实现

## 概述

Phase 8 实现端到端链上 Verifier Production，包含 2 个 Task：
- **Task 8.1**：实现 `poker_zkvm::verifier::verify_production(proof_bytes, public_io)`
- **Task 8.2**：集成到 `poker_l1::offline::hypernova::HypernovaVerifier`，含 v1.3 双通道 grace period + M2-003/004 修复

遵循 spec v1.4（FROZEN）与 tasks.md Phase 8 定义（SubTask 8.1.1-8.1.9 + 8.2.1-8.2.8）。

## 当前状态分析

### poker_zkvm 侧
- [poker_zkvm/src/verifier.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs) — 6 行 stub，需完整实现
- [poker_zkvm/src/prover/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs) L264-355 — `serialize_proof` 已实现，但**未序列化 `folded_instance.ccs_ref`**（CCS 矩阵），verifier 无法重建 sumcheck 验证上下文
- [poker_zkvm/src/fold/fold_loop.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/fold/fold_loop.rs) L48-63 — `HypernovaProof` 结构定义完整；L213-240 — `verify_hypernova`（简化版，仅 sumcheck + PCS，不含反序列化）
- [poker_zkvm/src/fold/lcccs.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/fold/lcccs.rs) L38-52 — `Lcccs` 含 `ccs_ref: Ccs`（owned，含完整矩阵）
- [poker_zkvm/src/ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs) L127-136 — `Ccs { num_vars, matrices: Vec<SparseMatrix>, subsets: Vec<Vec<usize>>, coeffs: Vec<Fr> }`，无 to_bytes/from_bytes
- [poker_zkvm/src/fold/sumcheck.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/fold/sumcheck.rs) L528-535 — `verify(proof, ccs, r_x_l, u_prime, z_at_r_y, transcript)` 需 `&Ccs`
- [poker_zkvm/src/pcs/ipa.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/pcs/ipa.rs) L368-375 — `IpaPcs::verify(commitment, point, eval, proof, transcript)`
- [poker_zkvm/src/error.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/error.rs) — ZkvmError 18 个变体齐全（SumcheckVerificationFailed / CrossLanguageClaimFailed / TranscriptMismatch / PcsVerificationFailed / AbiVersionMismatch / InvalidZkProofFormat / ProofKindMismatch 等）

### poker_l1 侧
- [poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs) L140-158 — `HypernovaVerifier::verify` Production 分支返回 `Err(Other("尚未实现"))`，需替换为 `verify_production` 调用
- [poker_l1/src/error.rs](file:///Users/mac/projects/zchain/poker_l1/src/error.rs) — `PokerL1Error` 缺失 verifier 错误变体（SumcheckVerificationFailed / CrossLanguageClaimFailed / TranscriptMismatch / PcsVerificationFailed / AbiVersionMismatch / ProofKindMismatch / PartialFoldHashImmutable / SignatureFormMismatch 等）
- [poker_l1/src/governance/mod.rs](file:///Users/mac/projects/zchain/poker_l1/src/governance/mod.rs) L316-399 — `GovernanceParams` 无 `production_switch_height` 字段
- [poker_l1/src/offline/state.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs) L237-246 — `LastPartialFold` 已含 `proof_partial_hash: Hash` 字段，但 `execute_partial_checkin` 未校验不可变性（M2-003）
- [poker_l1/src/offline/zk_verifier.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs) L56-71 — `ZkPublicIo`（poker_l1 版本，含 initial/final commitment 等）

### 关键约束（来自 project_memory）
- **x_l / x_c = r_x_l**（长度 = log2(num_rows)），非 CcsInstance.public_inputs
- **fold_loop 使用 fresh Transcript** for each sumcheck step；PCS opening chains from sumcheck transcript
- **Hypernova outer sumcheck claimed sum = u' 标量**（非 v' 向量，非 0）
- **LCCCS relaxed 约束**：`Σ_i c_i · Π_{j∈S_i} v'[j] = u'`（u' 可非 0）
- **IPA batch_size=3**（num_vars=4=2^2，MVP 限制）
- **proof_partial_hash 链上不可变**（M2-003）
- **单 proof_kind 单签名形式**（M2-004：scheme_id=4→旧签名，scheme_id=1→新签名）

## 实施步骤

### Step 1：CCS 序列化（ccs/mod.rs）

**文件**：[poker_zkvm/src/ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs)

为 `SparseEntry` / `SparseMatrix` / `Ccs` 添加 `to_bytes()` / `from_bytes()` 方法：
- `SparseEntry::to_bytes()`：`row(u64 LE) || col(u64 LE) || value(32B canonical)`
- `SparseMatrix::to_bytes()`：`num_rows(u64 LE) || num_cols(u64 LE) || entries_count(u32 LE) || entries...`
- `Ccs::to_bytes()`：`num_vars(u64 LE) || matrices_count(u32 LE) || matrices... || subsets_count(u32 LE) || subsets... || coeffs_count(u32 LE) || coeffs...`
- 每个 `from_bytes()` 反向解析，校验维度一致性，超长返回 `InvalidZkProofFormat`

**测试**：5 个 — 往返一致性 / 空矩阵 / 大矩阵 / 畸形输入 / 维度校验

### Step 2：更新 serialize_proof 含 CCS

**文件**：[poker_zkvm/src/prover/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs) L264-355

在 `serialize_proof` 中 `folded_instance` 序列化段添加 `ccs_ref.to_bytes()`（位置：u_l 之前，作为 Lcccs 第一字段）。新增 `PROOF_VERSION` 升至 2（向后兼容性：v1 proof 反序列化失败时返回 `InvalidZkProofFormat("version mismatch")`）。

同步更新 `fold_loop.rs::verify_hypernova` 中 proof 结构假设。

### Step 3：实现 deserialize_proof

**文件**：[poker_zkvm/src/prover/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs)

新增 `pub fn deserialize_proof(bytes: &[u8]) -> Result<HypernovaProof, ZkvmError>`：
- 校验 magic / version / abi_version（不匹配返回 `InvalidZkProofFormat` / `AbiVersionMismatch`）
- **总长度优先校验**：若 `bytes.len() > MAX_PROOF_TOTAL_SIZE`（48KB，对应 MAX_* 之和），立即返回 `InvalidZkProofFormat` 不进入昂贵解析
- **单项子分配校验**（v1.3 M2-002）：解析时校验每个字段长度 ≤ 治理上限（MAX_PUBLIC_IO_SIZE / MAX_FOLDED_INSTANCE_SIZE / MAX_SUMCHECK_PROOF_SIZE / MAX_PCS_OPENING_SIZE）
- 反序列化 Lcccs（含 ccs_ref） / witness_commitment / final_sumcheck / pcs_opening / r_y / z_at_point
- 反序列化后调用 `Lcccs::new` 校验维度一致性

**测试**：3 个 — 往返一致性 / magic 错误 / 总长度超限

### Step 4：实现 verify_production

**文件**：[poker_zkvm/src/verifier.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs)（重写）

实现 `pub fn verify_production(proof_bytes: &[u8], public_io: &ZkPublicIo) -> Result<bool, ZkvmError>`：

1. `deserialize_proof(proof_bytes)` — 反序列化 + 字段长度校验
2. 重建 `IpaPcs::new(ccs_ref.num_vars.trailing_zeros())` — PCS verifier
3. 重建 Fiat-Shamir transcript：
   - `Transcript::new()`
   - absorb `public_io` 哈希（blake2b）
   - absorb `ccs_commitment`（blake2b of ccs_ref.to_bytes()）
   - absorb `witness_commitment`（compressed bytes）
4. 调用 `sumcheck::verify(&proof.final_sumcheck, &ccs_ref, &r_x_l, u_prime, z_at_point, &mut transcript)`
   - **u_prime = proof.folded_instance.u_l**（folded LCCCS 的 u_l 即外层 sumcheck claimed sum u'）
   - **z_at_point = proof.z_at_point**
   - 失败返回 `SumcheckVerificationFailed`
5. 调用 `pcs.verify(&witness_commitment, &r_y, &z_at_point, &pcs_opening, &mut transcript)`
   - 失败返回 `PcsVerificationFailed`
6. 校验 transcript 一致性（challenge 派生顺序）— 失败返回 `TranscriptMismatch`
7. 返回 `Ok(true)`

**关键设计**：
- 不重新实现 sumcheck / PCS verify 逻辑，复用 fold_loop.rs 中已验证的实现
- public_io 校验：proof 中的 `x_l`（= r_x_l）与 public_io 派生 challenge 一致性由 sumcheck::verify 内部 transcript 铐定
- cross-language claim 由 sumcheck::verify（外层 G(r_x_L) == u'）+ PCS opening（z'(r_y)）联合保证

### Step 5：verify_production 测试（10 个）

**文件**：[poker_zkvm/src/verifier.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs)（测试模块）

构造合法 proof：使用 `prover::prove()` 生成真实 proof（复用 Phase 7 测试 fixtures）。

1. `test_verify_production_valid_proof_passes` — 合法 proof 通过
2. `test_verify_production_tampered_magic_fails` — 篡改 magic 返回 `InvalidZkProofFormat`
3. `test_verify_production_tampered_abi_version_fails` — 篡改 abi_version 返回 `AbiVersionMismatch`
4. `test_verify_production_tampered_folded_instance_fails` — 篡改 u_l 返回 `SumcheckVerificationFailed`
5. `test_verify_production_tampered_witness_commitment_fails` — 篡改 commitment 返回 `PcsVerificationFailed`
6. `test_verify_production_tampered_sumcheck_fails` — 篡改 round_polys 返回 `SumcheckVerificationFailed`
7. `test_verify_production_tampered_pcs_opening_fails` — 篡改 pcs_opening 返回 `PcsVerificationFailed`
8. `test_verify_production_tampered_r_y_fails` — 篡改 r_y 返回 `PcsVerificationFailed` 或 `SumcheckVerificationFailed`
9. `test_verify_production_tampered_z_at_point_fails` — 篡改 z_at_point 返回 `SumcheckVerificationFailed`（u'/v'/z_at_point 链断裂）
10. `test_verify_production_oversized_proof_fails` — > 48KB 返回 `InvalidZkProofFormat`

### Step 6：扩展 PokerL1Error

**文件**：[poker_l1/src/error.rs](file:///Users/mac/projects/zchain/poker_l1/src/error.rs)

新增 11 个 verifier 错误变体（SubTask 8.2.2）：
- `SumcheckVerificationFailed`
- `CrossLanguageClaimFailed`
- `TranscriptMismatch`
- `PcsVerificationFailed`
- `AbiVersionMismatch { expected: u8, actual: u8 }`
- `InvalidSlot`
- `RecursionDepthExceeded { actual: u32, limit: u32 }`
- `ProofKindMismatch { declared: u8, actual: u8 }`
- `UninitializedRead { slot: u32 }`
- `PartialFoldHashImmutable`（M2-003）
- `SignatureFormMismatch { scheme_id: u32 }`（M2-004）

### Step 7：GovernanceParams production_switch_height

**文件**：[poker_l1/src/governance/mod.rs](file:///Users/mac/projects/zchain/poker_l1/src/governance/mod.rs)

- `GovernanceParams` 新增 `production_switch_height: u64` 字段（默认 0，表示未切换）
- `ParamName` 新增 `ProductionSwitchHeight` 变体（敏感参数 90% quorum）
- `default_values()` 设置 `production_switch_height: 0`
- **一次性写入语义**：治理切换 `verifier_status` 从 Stub 到 Production 时写入当前 block height；写入后不可改（除非 grace 期结束清零）
- 新增常量 `pub const PRODUCTION_GRACE_BLOCKS: u64 = 7200;`

**测试**：3 个 — 默认值 / 一次性写入 / 清零

### Step 8：HypernovaVerifier Production 分支

**文件**：[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs) L140-158

修改 `HypernovaVerifier::verify` Production 分支：
- 调用 `poker_zkvm::verifier::verify_production(proof, &public_io_to_zkvm(public_io))`
- 新增 `public_io_to_zkvm` 转换函数：poker_l1 `ZkPublicIo` → poker_zkvm `ZkPublicIo`
- 错误映射：`ZkvmError::SumcheckVerificationFailed` → `PokerL1Error::SumcheckVerificationFailed`，依此类推

### Step 9：Grace period 双通道逻辑

**文件**：[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs)

修改 `HypernovaVerifier::verify` 签名，新增参数 `current_height: u64` / `production_switch_height: u64` / `last_partial_fold: Option<&LastPartialFold>`：

- `Stub` 状态：仅校验 proof 长度（行为不变）
- `Production` 状态 + grace 期内（`current_height ≤ production_switch_height + PRODUCTION_GRACE_BLOCKS`）：
  - `proof_kind = ZkShuffle`（scheme_id=4）：允许 stub 路径，**但 `proof_hash` 必须匹配链上 `last_partial_fold.proof_partial_hash`**（仅允许在途游戏继续）
  - `proof_kind = Zkvm`（scheme_id=1）：强制走 Production 路径
- `Production` 状态 + grace 期后：所有 proof 强制 Production 路径，stub 关闭

**注意**：`ZkVerifier::verify` trait 签名变更需更新所有调用方（`ZkVerifierRegistry::zk_verify`）。新增参数通过 `ZkVerifyContext` 结构封装，避免签名爆炸。

### Step 10：M2-003 proof_partial_hash 不可变

**文件**：[poker_l1/src/offline/state.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/state.rs) L344-407

修改 `execute_partial_checkin`：
- 校验 `last_partial_fold.proof_partial_hash == None || == tx.proof_partial_hash()`（首次或幂等重提交允许）
- 覆盖已有值返回 `PokerL1Error::PartialFoldHashImmutable`
- **幂等重提交范围**（v1.4 Min3-003）：整个 `PartialCheckinTx` 内容幂等（`proof_partial_hash` + `intermediate_commitment` + `ack_chain_partial` 全部相等）
- `execute_checkin` 完成后清零 `last_partial_fold`
- **游戏终结判定**（v1.4 Min3-002）：`is_terminal(ack_chain)` 或 ZKVM `game_over=true`

### Step 11：M2-004 单 proof_kind 单签名形式

**文件**：[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs)

verifier 通过 `scheme_id` 反推期望签名形式：
- `scheme_id=4`（ZkShuffle）：期望旧签名（无 `proof_kind` 字段）
- `scheme_id=1`（Zkvm）：期望新签名（含 `proof_kind` 字段）
- 签名形式与 `scheme_id` 不一致返回 `SignatureFormMismatch { scheme_id }`
- 切换前仅接受旧签名；grace 期内按 scheme_id 分派；grace 期后仅接受新签名

### Step 12：poker_l1 集成测试（10 个）

**文件**：[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs)（测试模块）

1. `test_production_valid_proof_passes` — 合法 Zkvm proof Production 验证通过
2. `test_production_invalid_proof_fails` — 篡改 proof 返回对应错误
3. `test_grace_zkshuffle_with_matching_proof_hash_passes` — grace 期 ZkShuffle + 匹配 proof_hash 通过
4. `test_grace_zkshuffle_with_mismatched_proof_hash_fails` — grace 期 ZkShuffle + 不匹配 proof_hash 失败
5. `test_grace_zkvm_forced_production` — grace 期 Zkvm 强制 Production
6. `test_post_grace_stub_closed` — grace 期后 stub 关闭
7. `test_m2_003_partial_fold_hash_immutable` — 覆盖已有 proof_partial_hash 返回 `PartialFoldHashImmutable`
8. `test_m2_003_idempotent_resubmit` — 幂等重提交通过
9. `test_m2_004_scheme4_old_signature_passes` — scheme_id=4 旧签名通过
10. `test_m2_004_scheme1_old_signature_fails` — scheme_id=1 旧签名返回 `SignatureFormMismatch`

### Step 13：文档更新 + 最终验证

**文件**：
- [poker_zkvm/docs/alternatives.md](file:///Users/mac/projects/zchain/poker_zkvm/docs/alternatives.md) — 新增 Phase 8 段落（推荐方案 / 未选方案 / 实现发现）
- [.trae/specs/build-hypernova-zkvm/tasks.md](file:///Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/tasks.md) — Phase 8 所有 SubTask 勾选 `[x]`

**最终验证**：
- `cargo test -p poker_zkvm` — 全部通过
- `cargo test -p poker_l1` — 全部通过
- `cargo clippy --workspace -- -D warnings` — 零警告
- `cargo build --release --workspace` — 构建成功

## 假设与决策

### 假设
1. `prover::prove()` 生成的 proof 通过 `serialize_proof` 序列化后可被 `deserialize_proof` 正确恢复
2. `sumcheck::verify` 与 `IpaPcs::verify` 的实现已正确（Phase 6 已验证）
3. poker_l1 `ZkPublicIo` → poker_zkvm `ZkPublicIo` 转换：`initial/final_commitment`（Hash→Fr）、`state_delta_hash`、`ack_chain_hash`、`event_hashes`（poker_l1 无此字段，用空 Vec）

### 决策
1. **CCS 序列化格式**：自定义二进制（非 serde），与 `serialize_proof` 风格一致（长度前缀 + 内容）
2. **PROOF_VERSION 升级**：v1 → v2（含 CCS），不向后兼容（v1 proof 反序列化失败）
3. **ZkVerifyContext 封装**：避免 `verify` 签名爆炸（current_height / production_switch_height / last_partial_fold 打包）
4. **错误映射**：`ZkvmError` → `PokerL1Error` 一对一映射（无信息丢失）
5. **未选方案**：
   - (a) CCS 不序列化，verifier 侧硬编码 CCS — 拒绝：proof 与 CCS 绑定，硬编码限制灵活性
   - (b) proof 中存 CCS hash 而非完整 CCS — 拒绝：verifier 无法重建 sumcheck 上下文
   - (c) ZkVerifier::verify 新增 5 个参数 — 拒绝：签名爆炸，改用 ZkVerifyContext
   - (d) grace 期 proof_kind 双签名形式接受 — 拒绝：与 M2-004 单 proof_kind 单签名形式矛盾

## 验证步骤

1. **单元测试**：每个 Step 完成后运行对应模块测试
2. **集成测试**：Step 5 / Step 12 完成后运行端到端测试
3. **回归测试**：Step 13 运行 `cargo test --workspace` 确保无回归
4. **Clippy**：`cargo clippy --workspace -- -D warnings` 零警告
5. **构建**：`cargo build --release --workspace` 成功
