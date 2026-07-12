# Phase J 续作计划 v2 — ZkShuffle 真实电路收尾（J-3~J-10）

> **状态**：Plan Mode Phase 4（待用户批准）
> **前置**：[phase_j_resume_plan.md](file:///Users/mac/projects/zchain/.trae/documents/phase_j_resume_plan.md)（已批准，J-1/J-2 完成，J-3~J-7 编译修复完成但 2 测试失败）
> **当前进度**：J-1（bn254_ops.rs）✅、J-2（elgamal.rs）✅、J-3~J-7 编译修复 ✅（6/8 测试通过），**阻塞于 ΔC/ΔD 线性组合数学问题**

---

## 1. Summary

本计划承接已批准的 Phase J 续作计划，解决 zk_shuffle.rs 的 ΔC/ΔD 数学阻塞，然后顺序完成 J-7（mod.rs 测试更新）、J-8（dleq.rs）、J-9（poker_l1 verifier）、J-10（集成测试），最终交付完整 ZkShuffle 电路 + DLEq proof + poker_l1 Production verifier + 集成测试。

**核心修复**：从 CCS 电路中移除 ΔC/ΔD 线性组合约束。原因：CCS 的 field-element-wise 线性组合（`sub_mod`/`mul_mod`/`add_mod`）计算的是坐标级域乘法 `Σ λ_i · (P_i.x)`，数学上**不等于** G1 标量乘法 `(Σ λ_i · P_i).x`。DLEq proof（J-8）在外部处理 ΔC = g^R / ΔD = pk^R 的离散对数等价证明。

---

## 2. Current State Analysis

### 2.1 已完成

- **[bn254_ops.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/bn254_ops.rs)**（J-1 ✅）：`assert_g1_on_curve` + BN254_P 常量，18 测试通过
- **[elgamal.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/elgamal.rs)**（J-2 ✅）：Host 类型 + 运算 + 转换，8 测试通过
- **[zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs)**（J-3~J-7 编译修复 ✅）：927 行，编译通过，6/8 测试通过

### 2.2 当前阻塞 — ΔC/ΔD 数学问题

**现象**：`test_zk_shuffle_build_circuit_light` 和 `test_zk_shuffle_build_circuit_full` 在 `ccs.satisfied_by(&witness_vec)` 处失败。

**根因**：[zk_shuffle.rs L263-329](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs#L263-L329) 的 ΔC/ΔD 计算使用 CCS 非原生域算术（`sub_mod`/`mul_mod`/`add_mod`），计算的是坐标级域运算：
```
CCS 计算: ΔC.x = Σ λ_i · (c'_{σ(i)}.x - c_i.x) mod p   (域乘法)
```

但 [zk_shuffle.rs L731-750](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs#L731-L750) 的 dummy 数据使用 G1 标量乘法：
```
Dummy 计算: ΔC = Σ λ_i · (c'_{σ(i)} - c_i)             (G1 MSM)
```

两者数学上**不等价**：G1 点加法的 x 坐标公式 `x₃ = (y₂-y₁)/(x₂-x₁))² - x₁ - x₂` 不是域加法，G1 标量乘法的 x 坐标不是域乘法。因此 CCS 约束与 dummy witness 不匹配，`satisfied_by` 失败。

### 2.3 待实现

- **mod.rs 测试断言过期**：[mod.rs L374-377](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L374-L377) 断言 `num_variables() == 0`、`gas_cost() == 0`；[mod.rs L456](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L456) 断言 `("zk_shuffle", 0, 1)`
- **[poker_l1 hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs#L318-L322)**：ZkShuffleVerifier Production 路径返回 `Err("尚未迁移")`
- **dleq.rs**：尚未创建
- **集成测试**：尚未创建

---

## 3. Proposed Changes

### J-fix：移除 CCS 中的 ΔC/ΔD 线性组合（解除阻塞）

**文件**：[zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs)

#### 3.1.1 移除 ΔC/ΔD public input 变量分配（L192-218）

删除以下 4 个 `alloc_element` 调用（`delta_c_pub_x/y`、`delta_d_pub_x/y`），共 27 行。ΔC/ΔD 仍保留在 `ShufflePublicInput` 结构中（供 DLEq 使用），但不再分配为 CCS 变量。

#### 3.1.2 移除 ΔC/ΔD 计算循环 + assert_equal（L263-329）

删除整个 "===== 3. ΔC/ΔD 计算 =====" 和 "===== 4. 绑定 ΔC/ΔD 到 public input =====" 段落，共 67 行。包括：
- `zero_elem`、`delta_c_acc_x/y`、`delta_d_acc_x/y` 初始化
- `for i in 0..n` 循环中的 `sub_mod`/`mul_mod`/`add_mod` 计算
- `lambda_elem` 分配（L283-284）
- 4 个 `assert_equal` 绑定

#### 3.1.3 移除 `fr_to_u256_limbs` 辅助函数（L385-398）

该函数仅用于 ΔC/ΔD 计算中的 λ_i 转换，移除后无引用。

#### 3.1.4 更新 `test_zk_shuffle_delta_c_mismatch` 测试（L872-885）

移除 ΔC/ΔD 约束后，篡改 ΔC 不再影响 CCS 满足性。将此测试改为**密文篡改测试**：篡改 output 密文的 c.x 坐标，验证 CCS 不满足（on-curve 检查失败）。

**原测试**（L872-885）：
```rust
#[test]
fn test_zk_shuffle_delta_c_mismatch() {
    let circuit = ZkShuffleCcsCircuit::with_deck_size(4, false);
    let (witness, mut public) = build_dummy_data(4);
    public.delta_c[0] = public.delta_c[0].add(&Fr::one());
    let (ccs, witness_vec) = circuit.build_circuit(&witness, &public).expect("build_circuit");
    assert!(!ccs.satisfied_by(&witness_vec).expect("satisfied_by"), "ΔC 不匹配时 CCS 应不满足");
}
```

**改为**：
```rust
#[test]
fn test_zk_shuffle_ciphertext_tamper_fails() {
    let circuit = ZkShuffleCcsCircuit::with_deck_size(4, false);
    let (mut witness, public) = build_dummy_data(4);
    // 篡改 output 密文[0] 的 c.x 坐标（破坏 on-curve）
    witness.output_cts[0].c_x[0] = witness.output_cts[0].c_x[0].wrapping_add(1);
    let (ccs, witness_vec) = circuit.build_circuit(&witness, &public).expect("build_circuit");
    assert!(
        !ccs.satisfied_by(&witness_vec).expect("satisfied_by"),
        "篡改密文坐标后 CCS 应不满足（on-curve 检查失败）"
    );
}
```

#### 3.1.5 更新模块文档注释（L1-23）

移除文档中 "ΔC/ΔD 计算" 相关行（L7、L21），更新约束计数表。

#### 3.1.6 简化 dummy 数据中的 ΔC/ΔD 计算（L728-765）

dummy 数据中的 ΔC/ΔD G1 MSM 计算仍保留（供 DLEq proof 使用），但添加注释说明这些值不参与 CCS 约束，仅作为 public input 传递给 DLEq。

#### 3.1.7 验证

```bash
cargo test -p poker_zkvm --lib precompiles::zk_shuffle
```

**预期**：8/8 测试通过（含改名的 `test_zk_shuffle_ciphertext_tamper_fails`）。

---

### J-7：更新 mod.rs 测试断言

**文件**：[mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs)

#### 3.2.1 更新 `test_phase10_registry_full`（L374-377）

```rust
// 原：
let zk_shuffle = registry.get("zk_shuffle").expect("应找到 zk_shuffle");
assert_eq!(zk_shuffle.num_variables(), 0);
assert_eq!(zk_shuffle.gas_cost(), 0);

// 改为：
let zk_shuffle = registry.get("zk_shuffle").expect("应找到 zk_shuffle");
// num_variables: 26 + deck_size*52 + 8 = 2738（估算，实际由 build_circuit 决定）
assert!(zk_shuffle.num_variables() > 1000, "zk_shuffle 应有大量变量");
assert_eq!(zk_shuffle.gas_cost(), 1_780_000);  // Light mode
```

#### 3.2.2 更新 `test_phase10_gas_costs_reasonable`（L456）

```rust
// 原：("zk_shuffle", 0, 1),
// 改为：("zk_shuffle", 1_000_000, 5_000_000),
```

#### 3.2.3 验证

```bash
cargo test -p poker_zkvm --lib precompiles::tests
cargo clippy -p poker_zkvm --lib -- -D warnings
```

---

### J-8：新建 dleq.rs — Schnorr 批量 DLEq proof

**文件**：`poker_zkvm/src/precompiles/dleq.rs`（新建）

**内容**：Schnorr 批量 DLEq proof，证明 ΔC = g^R 和 ΔD = pk^R 共享同一离散对数 R。

**协议**：
1. Prover 选随机 w，计算 A = g^w, B = pk^w
2. Challenge c = H(g, pk, ΔC, ΔD, A, B)（Fiat-Shamir，Blake2bVar）
3. Response z = w + c · R
4. Verifier 校验：g^z == A · ΔC^c AND pk^z == B · ΔD^c（用 MSM 实现）

**序列化**：97 字节（A.x: 32B + B.x: 32B + z: 32B + flags: 1B）

**API**：
- `DleqProof { a: G1Affine, b: G1Affine, z: Fr }`
- `batch_dleq_prove(g, pk, delta_c, delta_d, r_combined, rng) -> DleqProof`
- `batch_dleq_verify(g, pk, delta_c, delta_d, proof) -> bool`
- `DleqProof::to_bytes() -> [u8; 97]`
- `DleqProof::from_bytes(&[u8]) -> Option<Self>`

**测试**（4 个）：
- `test_dleq_prove_verify_roundtrip`：合法 proof 验证通过
- `test_dleq_verify_invalid_proof`：篡改 z 验证失败
- `test_dleq_verify_wrong_delta_c`：错误 ΔC 验证失败
- `test_dleq_serialization_roundtrip`：97 字节序列化 roundtrip

**mod.rs 更新**：在 `pub mod ed25519;` 之后添加 `pub mod dleq;`（保持字母序）。

**依赖**：`blake2` crate（已在 Cargo.toml 中，供其他模块使用）。需验证 `Blake2bVar` 是否可用；若不可用，改用 `ark_ff::to_bytes` + `Sha256` 作为 FS challenge。

**验证**：
```bash
cargo test -p poker_zkvm --lib precompiles::dleq
cargo clippy -p poker_zkvm --lib -- -D warnings
```

---

### J-9：修改 poker_l1 ZkShuffleVerifier Production 路径

**文件**：[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs)

#### 3.4.1 修改 `verify()` 方法（L306-323）

将 Production 路径从 `Err("尚未迁移")` 改为委托到新方法 `verify_production()`。

#### 3.4.2 新增 `verify_production()` 方法

解析 combined proof 格式并验证：
```
| magic(4) | version(4) | ccs_len(4) | ccs_proof(N) | dleq_len(4) | dleq_proof(97) |
```

验证步骤：
1. 校验 magic = `b"ZKSF"` + version = 1
2. 解析 ccs_proof 和 dleq_proof
3. 委托 HypernovaVerifier 验证 CCS proof（scheme_id=1 路径）
4. 从 public_io 提取 (g, pk, ΔC, ΔD)
5. 调用 `poker_zkvm::precompiles::dleq::batch_dleq_verify` 验证 DLEq proof

#### 3.4.3 新增 `parse_shuffle_public_io()` 辅助函数

从 `ZkPublicIo` 提取 (g, pk, ΔC, ΔD)，格式：`pk(64B) + delta_c(64B) + delta_d(64B) = 192B`。

#### 3.4.4 新增 `parse_g1_affine()` 辅助函数

从 64 字节解析 G1Affine（x||y 各 32B little-endian），含 on-curve 校验。

#### 3.4.5 新增测试

- `test_zkshuffle_verify_production_invalid_magic`：magic 不匹配
- `test_zkshuffle_verify_production_short_proof`：长度不足

**验证**：
```bash
cargo test -p poker_l1 --lib offline::hypernova
cargo clippy -p poker_l1 --lib -- -D warnings
```

---

### J-10：集成测试

**文件**：`poker_zkvm/tests/zk_shuffle_integration.rs`（新建）

**测试矩阵**（10 个测试）：

| 测试 | 描述 |
|------|------|
| `test_shuffle_light_mode_valid` | deck_size=4 合法 shuffle，Light mode，CCS satisfied |
| `test_shuffle_full_mode_valid` | deck_size=4 合法 shuffle，Full mode，CCS satisfied |
| `test_shuffle_invalid_permutation` | 排列越界，返回 Err |
| `test_shuffle_ciphertext_tamper_fails` | 篡改 output 密文，CCS 不 satisfied |
| `test_shuffle_dleq_valid` | 合法 DLEq proof 验证通过 |
| `test_shuffle_dleq_invalid` | 篡改 DLEq proof 验证失败 |
| `test_shuffle_dleq_wrong_delta_c` | 错误 ΔC，DLEq 验证失败 |
| `test_shuffle_dleq_serialization` | DLEq 序列化 roundtrip |
| `test_shuffle_public_input_roundtrip` | ShufflePublicInput to_vec/from_vec |
| `test_shuffle_combined_proof_format` | combined proof 格式校验（magic/version/长度） |

**辅助**：复用 `build_dummy_data(deck_size)` + `elgamal` 模块的 host 运算。

**验证**：
```bash
cargo test -p poker_zkvm --test zk_shuffle_integration
```

---

## 4. Assumptions & Decisions

### 4.1 核心决策：移除 CCS 中的 ΔC/ΔD 线性组合

**原因**：CCS（over BN254 Fr）的非原生域算术计算坐标级域乘法，无法验证 G1 MSM。这是 BN254 G1 群运算的固有特性（点加法 x 坐标公式涉及除法，非线性）。

**影响**：CCS 仅验证 pk on-curve + 密文 on-curve + ZK blinding。ΔC/ΔD 的 re-encryption 关系由 DLEq proof（J-8）在外部验证。

**已知局限**：当前架构无排列论证（permutation argument）。DLEq 证明 ΔC = g^R / ΔD = pk^R，但不证明输出是输入的置换。完整的 shuffle soundness 需要 LogUp 排列论证，留待后续阶段（Phase J-ext 或 Phase K）。

### 4.2 延续前置计划决策

- 双证明系统：CCS/Hypernova proof + Schnorr DLEq proof
- Light/Full 双模式
- card_id · G 牌面编码
- Combined proof 格式：`magic(4) | version(4) | ccs_len(4) | ccs_proof(N) | dleq_len(4) | dleq_proof(97)`
- public_io 格式：`pk(64B) + delta_c(64B) + delta_d(64B) = 192B`

### 4.3 风险与缓解

- **DLEq 序列化符号歧义**：从 x 坐标恢复 y 有两个平方根。**缓解**：验证时用 proof 中的 A/B 点直接验证（A/B 在 proof 中以 x-only + flags 存储，反序列化时选正根；若验证失败，可能是符号问题，但 DLEq 验证等式 `g^z == A · ΔC^c` 会自动校验 A 的正确性）。
- **CCS proof 委托**：ZkShuffle 的 CCS proof 用 HypernovaVerifier 验证（CCS 结构相同，仅 witness/public_input 不同）。若 HypernovaVerifier 的 public_io 格式不匹配，需在 J-9 中适配。
- **blake2 依赖**：需确认 `blake2` crate 的 `Blake2bVar` 在 poker_zkvm 中可用。

---

## 5. Verification Steps

### 5.1 J-fix（移除 ΔC/ΔD）
```bash
cargo test -p poker_zkvm --lib precompiles::zk_shuffle
```
预期：8/8 测试通过。

### 5.2 J-7（mod.rs 测试更新）
```bash
cargo test -p poker_zkvm --lib precompiles::tests
cargo clippy -p poker_zkvm --lib -- -D warnings
```

### 5.3 J-8（dleq.rs）
```bash
cargo test -p poker_zkvm --lib precompiles::dleq
cargo clippy -p poker_zkvm --lib -- -D warnings
```

### 5.4 J-9（poker_l1 verifier）
```bash
cargo test -p poker_l1 --lib offline::hypernova
cargo clippy -p poker_l1 --lib -- -D warnings
```

### 5.5 J-10（集成测试）
```bash
cargo test -p poker_zkvm --test zk_shuffle_integration
```

### 5.6 全量回归
```bash
cargo test -p poker_zkvm --lib
cargo test -p poker_l1 --lib
cargo clippy -p poker_zkvm -- -D warnings
cargo clippy -p poker_l1 -- -D warnings
cargo fmt --all -- --check
```

---

## 6. 实施顺序

```
J-fix（移除 ΔC/ΔD → 解除 8/8 测试阻塞）
    │
    ↓
J-7（mod.rs 测试断言更新）
    │
    ↓
J-8（dleq.rs + 链接到 mod.rs）
    │
    ↓
J-9（poker_l1 ZkShuffleVerifier Production 路径）
    │
    ↓
J-10（集成测试）
    │
    ↓
全量回归 + clippy + fmt
```

**每步完成标准**：
- 对应单元测试通过
- 无新 clippy 警告
- 不破坏既有测试（除非该步骤明确要求更新断言）

---

## 7. 已知局限与后续工作

### 7.1 排列论证（Permutation Argument）

当前 CCS 不包含排列论证。完整 shuffle soundness 需要：
- **LogUp 排列论证**：证明输出密文 multiset = 输入密文 multiset（重加密后）
- 或 **Bayer-Groth shuffle argument**：直接证明 shuffle 关系

这需要额外 ~50K-100K 约束，留待后续阶段实现。

### 7.2 ΔC/ΔD 绑定

当前 ΔC/ΔD 作为 DLEq 的公共输入，但不绑定到 CCS witness。完整绑定需要：
- 在 CCS 中包含排列论证（证明 ΔC = Σ λ_i · (c'_{σ(i)} - c_i)）
- 或使用 per-element DLEq（n 个 DLEq proof，每个对应一个密文对）
