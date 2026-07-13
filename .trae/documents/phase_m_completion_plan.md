# Phase M 完成计划：集成测试 + 最终验证

## 总结

用户请求："poker protocol下其他协议如remaskproof reconstructproof等也一并实现，其中verify方法应该是放在precompile里"。

经过探索确认，**M-5 到 M-8 已全部完成**：

* `remask_leave.rs` — PerCardDleqProof (Remask/Leave) 实现完成，10 个测试通过

* `reconstruction.rs` — ReconstructionDLEQProof + SwapOutCardProof + ReconstructProof 实现完成，8 个测试通过

* `chaum_pedersen.rs` — ChaumPedersenDLEQProof 实现完成，7 个测试通过

* `generalized_schnorr.rs` — GeneralizedSchnorrProof 实现完成，10 个测试通过

* `poker_transcript.rs` + `elgamal.rs` — 基础设施完成

* 所有模块已在 `mod.rs` 中声明

**唯一剩余工作**：M-9 — 创建集成测试文件 + 运行最终回归验证（clippy + fmt + 全量测试）。

## 当前状态分析

### 已完成的文件

| 文件                                   | 行数     | 状态   | 测试数 |
| ------------------------------------ | ------ | ---- | --- |
| `precompiles/remask_leave.rs`        | \~645  | ✅ 完成 | 10  |
| `precompiles/reconstruction.rs`      | \~1287 | ✅ 完成 | 8   |
| `precompiles/chaum_pedersen.rs`      | \~333  | ✅ 完成 | 7   |
| `precompiles/generalized_schnorr.rs` | \~400+ | ✅ 完成 | 10  |
| `precompiles/poker_transcript.rs`    | -      | ✅ 完成 | 12  |
| `precompiles/elgamal.rs`             | -      | ✅ 完成 | 8   |

### 缺失的文件

* `poker_zkvm/tests/poker_proofs_integration.rs` — **不存在，需要创建**

### 已验证的测试状态

```
cargo test -p poker_zkvm --lib precompiles::reconstruction
→ 8 passed, 0 failed, 0 ignored (0.07s)
```

全量 lib 测试有 1049+ 个测试（不含 reconstruction 的 8 个）。

## 提议变更

### 步骤 1：创建集成测试文件

**文件**：`/Users/mac/projects/zchain/poker_zkvm/tests/poker_proofs_integration.rs`（新建）

**目的**：跨模块端到端集成测试，验证各 proof 类型协同工作，以及字节级 API 可被外部调用。

**包含 3 个集成测试**：

1. **`test_remask_then_leave_roundtrip`**

   * 生成 52 张牌的 ElGamal 密文

   * 对每张牌执行 Remask 操作，生成 PerCardDleqProof (Remask 方向)

   * 验证所有 Remask proof

   * 对 remask 后的密文执行 Leave 操作，生成 PerCardDleqProof (Leave 方向)

   * 验证所有 Leave proof

   * 断言 Leave 后的密文恢复到原始密文（d2 = input.d - output.d 关系）

2. **`test_reconstruct_full_deck`**

   * 生成 52 张牌的 G1Affine 点

   * 选 2 张作为 user\_readable\_cards，用 ElGamal 加密

   * 调用 `reconstruct_deck` 生成 output\_cards 和 swap\_out\_cards

   * 调用 `ReconstructProof::prove` 生成完整重建证明

   * 调用 `ReconstructProof::verify` 验证

   * 断言验证通过

3. **`test_all_proofs_byte_level`**

   * 对每种 proof 类型（ChaumPedersen、GeneralizedSchnorr、PerCardDleq、Reconstruct）

   * 生成 proof 并序列化为字节

   * 调用字节级 verify 函数（`chaum_pedersen_verify_bytes`、`generalized_schnorr_verify_bytes`、`reconstruct_verify_bytes`）

   * 断言字节级验证通过

   * 篡改 proof 字节，断言字节级验证失败

**依赖的 pub API**（已在各模块中暴露）：

* `remask_leave::{PerCardDleqProof, DleqDirection, remask_cts}`

* `reconstruction::{ReconstructProof, ReconstructionDLEQProof, SwapOutCardProof, reconstruct_deck, derive_from_output_cards, reconstruct_verify_bytes}`

* `chaum_pedersen::{ChaumPedersenDLEQProof, chaum_pedersen_verify_bytes}`

* `generalized_schnorr::{GeneralizedSchnorrProof, generalized_schnorr_verify_bytes}`

* `poker_transcript::PokerTranscript`

* `elgamal::{ElGamalCiphertext, ElGamalPublicKey, ElGamalSecretKey, encrypt, decrypt, keygen}`

### 步骤 2：运行最终回归验证

按顺序执行以下命令，确保无回归：

```bash
# 1. 全量 lib 测试
cargo test -p poker_zkvm --lib

# 2. 集成测试
cargo test -p poker_zkvm --test poker_proofs_integration

# 3. Clippy 检查（含测试和 test-helpers feature）
cargo clippy -p poker_zkvm --tests --features test-helpers -- -D warnings

# 4. 格式检查
cargo fmt -p poker_zkvm -- --check
```

**预期结果**：

* lib 测试：1057+ passed (1049 既有 + 8 reconstruction)，0 failed

* 集成测试：3 passed, 0 failed

* Clippy：0 warnings

* Fmt：无 diff

### 步骤 3：修复发现的问题（如有）

如果在步骤 2 中发现：

* 编译错误 → 修复集成测试代码

* Clippy 警告 → 修复警告

* Fmt diff → 运行 `cargo fmt -p poker_zkvm` 自动格式化

* 测试失败 → 分析失败原因并修复

## 假设与决策

1. **集成测试路径**：`poker_zkvm/tests/poker_proofs_integration.rs`（遵循既有 `zk_shuffle_integration.rs` 的命名模式）

2. **不修改既有文件**：M-5 到 M-8 的实现已通过测试，不触碰既有代码，只新增集成测试文件

3. **不注册 PrecompileRegistry**：用户明确说"仅 precompiles 实现"，不涉及 `syscall_circuit.rs` 中的 PrecompileRegistry 注册（该注册属于 poker\_l1 集成范畴）

4. **字节级 API 已就绪**：`chaum_pedersen_verify_bytes`、`generalized_schnorr_verify_bytes`、`reconstruct_verify_bytes` 已在各模块中实现，集成测试直接调用

5. **RNG 使用**：集成测试中使用 `ark_std::test_rng()`（确定性），遵循既有测试模式

## 验证步骤

完成后，向用户报告：

1. 集成测试文件创建成功，3 个测试全部通过
2. 全量 lib 测试无回归（1057+ passed）
3. Clippy 0 warnings
4. Fmt 无 diff
5. Phase M 全部完成（M-5-fix 到 M-9）

