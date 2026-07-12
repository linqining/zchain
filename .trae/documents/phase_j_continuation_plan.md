# Phase J 续作计划 — ZkShuffle 真实电路（J-2 完成至 J-10）

> **状态**：Plan Mode Phase 4（待用户批准）
> **前置**：[phase_j_zk_shuffle_plan.md](file:///Users/mac/projects/zchain/.trae/documents/phase_j_zk_shuffle_plan.md)（已批准，J-1 完成）
> **当前进度**：J-1（bn254_ops.rs）已完成并通过 18 个测试；J-2（elgamal.rs）文件已创建（326 行，8 个测试）但**尚未链接到 mod.rs**，测试**尚未运行**

---

## 1. Summary

本计划承接已批准的 Phase J 计划，从 J-2 收尾开始，顺序完成 J-3 至 J-10，最终交付完整 ZkShuffle 真实电路 + poker_l1 Production verifier + 集成测试。

**架构决策（已在前置计划中批准，不再重复）**：
- 完整 ZkShuffle 协议（含 ZK 盲化）
- 双证明系统：CCS/Hypernova proof（poker_zkvm）+ Schnorr DLEq proof（poker_l1 原生验证）
- poker_zkvm + poker_l1 同时修改

---

## 2. Current State Analysis

### 2.1 已完成（J-1）

**[bn254_ops.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/bn254_ops.rs)**（~590 行，已链接到 mod.rs L21）
- 常量：`BN254_P`、`BN254_B`、`BN254_G1_X`、`BN254_G1_Y`
- `Point`（Jacobian x/y/z: NonNativeElement）
- 点运算：`point_double`、`point_add`、`scalar_mul`
- 约束检查：`assert_on_curve`、`assert_g1_on_curve`、`assert_point_equal`
- Host 辅助：`host_g1_on_curve`、`host_jacobian_on_curve`、`host_jacobian_to_affine`、`host_g1_add`
- 辅助：`select_fr`、`select_element`、`select_point`、`identity_point`、`from_affine`
- 9 个单元测试全部通过；bn254_pairing.rs 重构后 9 个测试也通过

### 2.2 进行中（J-2）

**[elgamal.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/elgamal.rs)**（326 行，**未链接到 mod.rs**）
- Host 类型：`ElGamalPublicKey`、`ElGamalSecretKey`、`ElGamalCiphertext`（ark-bn254 G1Affine）
- Host 运算：`generator`、`keygen_from_secret`、`keygen`、`encrypt`、`decrypt`、`reencrypt`
- 牌面编码：`card_to_point`、`precompute_card_points`
- 转换辅助：`g1_to_u256`、`u256_to_g1`、`bytes_le_to_u256`
- CCS 类型：`CcsG1Point`、`CcsCiphertext`
- 8 个单元测试已编写但未运行（文件未链接）

**问题**：[mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs) L20-33 未声明 `pub mod elgamal;`，rust-analyzer 报 "unlinked-file"。

### 2.3 待实现（J-3 至 J-10）

**[zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs)**（174 行 stub）
- `ZkShuffleCcsCircuit::new()` 返回 stub
- `build_ccs()` 返回空 CCS（0 矩阵）
- `assign_witness()` / `to_ccs_instance()` 返回 `Err("Phase 11 pending")`
- `gas_cost()` 返回 0
- 5 个测试断言 stub 行为

**[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs#L306-L323)** ZkShuffleVerifier
- `verify()` Production 路径返回 `Err("ZkShuffle Production verifier 尚未迁移（Phase 11）")`
- `verify_with_context()` grace 期逻辑已正确，仅需 Production 分支委托到新 `verify()`

### 2.4 受影响的现有测试

**[mod.rs L455](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L455)** `test_phase10_gas_costs_reasonable`
- 当前断言 `("zk_shuffle", 0, 1)`（gas = 0）
- J-7 完成后需改为 `("zk_shuffle", 1_000_000, 5_000_000)`（Full ~3.54M / Light ~1.78M）

**[mod.rs L374-376](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L374-L376)** `test_phase10_registry_full`
- 当前断言 `zk_shuffle.num_variables() == 0` 和 `gas_cost() == 0`
- J-7 完成后需更新为真实值

---

## 3. Proposed Changes

### J-2 收尾：链接 elgamal.rs + 运行测试

**文件**：[precompiles/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs)

**修改**：在 L20-33 的模块声明中，于 `pub mod ed25519;`（L24）之前插入：
```rust
pub mod elgamal;
```

**验证**：
```bash
cargo test -p poker_zkvm --lib precompiles::elgamal
cargo clippy -p poker_zkvm --lib -- -D warnings
```
预期 8 个测试通过，无新 clippy 警告。

---

### J-3：zk_shuffle.rs 排列论证核心

**文件**：[zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs)（完全重写）

**数据结构**：
```rust
pub struct ZkShuffleCcsCircuit {
    name: &'static str,
    num_mats: usize,
    deck_size: usize,        // 默认 52
    full_mode: bool,         // true: 双向 on-curve; false: 仅输出 on-curve
}

pub struct ShufflePublicInput {
    pub pk: [Fr; 8],              // ElGamal 公钥 (x, y 各 4 limbs)
    pub input_commitment: Fr,     // H(c_1||d_1||...||c_n||d_n)
    pub output_commitment: Fr,    // H(c'_1||d'_1||...||c'_n||d'_n)
    pub delta_c: [Fr; 8],         // ΔC = Σ λ_i · Δc_i (G1 点 x||y)
    pub delta_d: [Fr; 8],         // ΔD = Σ λ_i · Δd_i (G1 点 x||y)
}

pub struct ShuffleWitness {
    pub input_cts: Vec<CcsCiphertext>,   // n × 16 limbs
    pub output_cts: Vec<CcsCiphertext>,  // n × 16 limbs
    pub permutation: Vec<u8>,             // σ(i)
    pub randomizers: Vec<Fr>,             // r_i
    pub lambda_challenges: Vec<Fr>,       // λ_i (FS)
    pub blinding: Vec<Fr>,                // ZK 盲化 (k=8)
}
```

**排列论证（LogUp）**：
- 将每个 `(c, d)` 编码为单个 Fr：`enc_i = H_to_Fr(c_x, c_y, d_x, d_y)`（使用现有 `commit_field_slice` 或 Poseidon）
- 输入 table T = {enc_1, ..., enc_n}，multiplicity 全 1
- 输出 witness W = {enc'_{σ(1)}, ..., enc'_{σ(n)}}（按 σ 重排）
- 调用 `LogUpProof::create(table, witness, multiplicity)` 生成证明
- 在 CCS witness 中追加 LogUp 的辅助变量

**构造函数**：
- `new()` / `new_light()` → Light mode（deck_size=52, full_mode=false）
- `new_full()` → Full mode（deck_size=52, full_mode=true）
- `with_deck_size(deck_size, full_mode)` → 自定义

---

### J-4：范围检查与 on-curve 验证

**牌面范围检查**：
- 每张牌的 card_id ∈ [0, 51]
- 从 output_cts 的 d 分量解密得到 card_id（host-side 预计算）
- 在 CCS 中对 card_id 使用 `NonNativeBuilder::assert_lt(card_id_elem, &52_u256)`

**G1 on-curve 检查**：
- Full mode：input 和 output 所有密文的 c/d 都检查（4 × 52 = 208 次）
- Light mode：仅 output 检查（2 × 52 = 104 次）
- 调用 `bn254_ops::assert_g1_on_curve(builder, &x, &y)`

---

### J-5：批量 ΔC/ΔD 计算

**CCS 约束**（每张牌）：
1. `Δc_i = c'_{σ(i)} - c_i`（`sub_mod` in BN254 Fp，传 `&BN254_P`）
2. `Δd_i = d'_{σ(i)} - d_i`（`sub_mod`）
3. `λ_i · Δc_i`（`mul_mod`）
4. `λ_i · Δd_i`（`mul_mod`）
5. 累加 `ΔC += λ_i · Δc_i`（`add_mod`）
6. 累加 `ΔD += λ_i · Δd_i`（`add_mod`）

**最终绑定**：
- `assert_equal(ΔC_ccs, ΔC_public_elem)` — 将 CCS 计算的 ΔC 与 public input 绑定
- `assert_equal(ΔD_ccs, ΔD_public_elem)`

---

### J-6：ZK 盲化

**方法**：
- witness 末尾追加 k=8 个随机 Fr 变量 `b_1, ..., b_8`
- 分配 8 个 `builder.alloc(random_fr)` 变量
- 将 `b_i` 混入 `output_commitment = H(..., b_1, ..., b_8)`
- 确保 witness 不为零空间

---

### J-7：完整 ZkShuffleCcsCircuit trait 实现

**PrecompileCircuit trait**：
```rust
fn name(&self) -> &str { "zk_shuffle" }
fn num_variables(&self) -> usize { /* 根据 deck_size 计算 */ }
fn build_ccs(&self) -> Ccs { /* 调用 build_shuffle_ccs() */ }
fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> { /* ... */ }
fn gas_cost(&self) -> u64 {
    if self.full_mode { 3_540_000 } else { 1_780_000 }
}
```

**CcsCircuit trait**：
```rust
fn to_ccs_instance(&self, witness: &[Fr], public_inputs: &[Fr]) -> Result<CcsInstance, ZkvmError> {
    // 1. 验证 witness 长度
    // 2. 构建 CCS
    // 3. CcsInstance::new(ccs, witness, public_inputs)
}
```

**更新 mod.rs 测试**：
- `test_phase10_gas_costs_reasonable` L455：`("zk_shuffle", 0, 1)` → `("zk_shuffle", 1_000_000, 5_000_000)`
- `test_phase10_registry_full` L374-376：更新 `num_variables()` 和 `gas_cost()` 断言

**替换 zk_shuffle.rs 的 5 个 stub 测试**：
- `test_zk_shuffle_circuit_name_and_num_matrices` → 保留并更新断言
- `test_zk_shuffle_circuit_assign_witness_stub_returns_error` → 替换为 `test_zk_shuffle_assign_witness_valid`
- `test_zk_shuffle_circuit_to_ccs_instance_stub_returns_error` → 替换为 `test_zk_shuffle_to_ccs_instance_valid`
- `test_zk_shuffle_circuit_registry_integration` → 更新断言
- `test_zk_shuffle_circuit_default` → 保留

---

### J-8：新建 dleq.rs — Schnorr 批量 DLEq proof

**文件**：`poker_zkvm/src/precompiles/dleq.rs`（新建）

**内容**：
```rust
pub struct DleqProof {
    pub a: ark_bn254::G1Affine,  // g^w
    pub b: ark_bn254::G1Affine,  // pk^w
    pub z: ark_ff::Fr,           // w + c · R
}

pub fn batch_dleq_prove(
    g: &G1Affine,
    pk: &G1Affine,
    delta_c: &G1Affine,   // Σ λ_i · Δc_i
    delta_d: &G1Affine,   // Σ λ_i · Δd_i
    r_combined: &Fr,      // Σ λ_i · r_i
    rng: &mut impl Rng,
) -> DleqProof

pub fn batch_dleq_verify(
    g: &G1Affine,
    pk: &G1Affine,
    delta_c: &G1Affine,
    delta_d: &G1Affine,
    proof: &DleqProof,
) -> bool
// 验证: g^z == A · ΔC^c AND pk^z == B · ΔD^c
```

**序列化**：`to_bytes()` → `[u8; 97]`（A: 32B compressed + B: 32B compressed + z: 32B + 1B flag）
`from_bytes()` → `Option<DleqProof>`

**修改 mod.rs**：添加 `pub mod dleq;`

**测试**：
- `test_dleq_prove_verify_roundtrip` — 合法 proof 验证通过
- `test_dleq_verify_invalid_proof` — 篡改 z 验证失败
- `test_dleq_verify_wrong_delta_c` — 错误 ΔC 验证失败
- `test_dleq_serialization_roundtrip` — 序列化/反序列化一致

---

### J-9：修改 poker_l1 ZkShuffleVerifier Production 路径

**文件**：[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs#L306-L323)

**修改 `verify()` 方法**：
```rust
fn verify(&self, proof: &[u8], public_io: &ZkPublicIo, status: VerifierStatus) -> Result<bool, PokerL1Error> {
    if status == VerifierStatus::Stub {
        self.validate_proof_format(proof)?;
        return Ok(true);
    }
    // Production 路径
    self.verify_production(proof, public_io)
}

fn verify_production(&self, proof: &[u8], public_io: &ZkPublicIo) -> Result<bool, PokerL1Error> {
    // 1. 解析 combined proof: magic(4) | version(4) | ccs_len(4) | ccs_proof(N) | dleq_len(4) | dleq_proof(M)
    // 2. 校验 magic == b"ZKSF" && version == 1
    // 3. 从 public_io 提取 ΔC, ΔD, pk
    // 4. 验证 CCS/Hypernova proof（委托 HypernovaVerifier，若 scheme_id=1 路径已存在）
    //    注：ZkShuffle 的 CCS proof 用 Hypernova 验证（scheme_id=4 但内部 CCS 同 scheme_id=1）
    // 5. 验证 Schnorr DLEq proof（调用 poker_zkvm::precompiles::dleq::batch_dleq_verify）
    // 6. 两者都通过才返回 true
}
```

**修改 `validate_proof_format()`**：
- 校验 magic + version + 长度字段
- 最小长度 = 4 + 4 + 4 + HYPERNOVA_PROOF_MIN_SIZE + 4 + 97

**保持 `verify_with_context()` 不变**：grace 期逻辑已正确。

**poker_l1 依赖**：在 poker_l1 的 Cargo.toml 中确认 `poker_zkvm` 依赖（已存在，J-8 的 dleq 模块可直接访问）。

**测试**：
- `test_zkshuffle_verify_production_valid` — 合法 combined proof 验证通过
- `test_zkshuffle_verify_production_invalid_magic` — 错误 magic 验证失败
- `test_zkshuffle_verify_production_invalid_dleq` — DLEq 部分篡改验证失败
- `test_zkshuffle_verify_production_short_proof` — 长度不足验证失败

---

### J-10：集成测试

**文件**：`poker_zkvm/tests/zk_shuffle_integration.rs`（新建）

**测试矩阵**：
| 测试 | 描述 |
|------|------|
| `test_shuffle_light_mode_valid` | 52 张牌合法 shuffle，Light mode，CCS satisfied |
| `test_shuffle_full_mode_valid` | 52 张牌合法 shuffle，Full mode，CCS satisfied |
| `test_shuffle_invalid_permutation` | 排列不合法（重复牌），CCS 不 satisfied |
| `test_shuffle_invalid_on_curve` | 输出点不在曲线上，CCS 不 satisfied |
| `test_shuffle_range_check_fail` | card_id > 51，CCS 不 satisfied |
| `test_shuffle_delta_c_mismatch` | ΔC 计算错误，CCS 不 satisfied |
| `test_shuffle_dleq_valid` | 合法 DLEq proof，verify 返回 true |
| `test_shuffle_dleq_invalid` | 非法 DLEq proof，verify 返回 false |
| `test_shuffle_combined_proof_format` | combined proof 格式校验 |
| `test_shuffle_end_to_end` | 端到端：prover 生成 → poker_l1 verifier 验证 |

**测试辅助**：
- 使用 `test-helpers` feature 共享 ELF 构建代码模式
- 在 zk_shuffle.rs 中添加 `#[cfg(any(test, feature = "test-helpers"))]` 门控的辅助函数：
  - `build_test_shuffle_witness(deck_size, seed) -> ShuffleWitness`
  - `build_test_public_input(witness: &ShuffleWitness) -> ShufflePublicInput`

---

## 4. Assumptions & Decisions

### 4.1 延续前置计划决策
所有架构决策（Schnorr DLEq、双证明系统、Light/Full 双模式、LogUp 排列、card_id·G 牌面编码）延续前置计划，不重新决策。

### 4.2 新增假设
1. **LogUp 编码**：`enc_i = H_to_Fr(c_x, c_y, d_x, d_y)` 使用 `commit_field_slice`（已有）或简单线性组合 `c_x + c_y·basis + d_x·basis² + d_y·basis³`（避免 Poseidon 依赖）。**决定**：先用线性组合（简单 + 足够安全，因为 LogUp 本身提供排列保证），若需要抗碰撞再升级 Poseidon。
2. **Hypernova 验证委托**：ZkShuffle 的 CCS proof 用现有 `HypernovaVerifier`（scheme_id=1 路径）验证。ZkShuffle 的 CCS 与普通 Zkvm CCS 结构相同，仅 witness/public_input 不同。
3. **gas 计费**：Full mode 3,540,000（~1.77M 约束 × 2），Light mode 1,780,000（~890K × 2）。

### 4.3 风险与缓解
- **约束数过大**：Full mode ~1.77M 约束，Hypernova 折叠可处理（Phase F 已验证百万级约束 + Groth16 压缩到 ~200B）
- **ark-ec 0.6 API**：J-1 已解决 `ProjectiveCurve → CurveGroup + PrimeGroup` 适配，J-2/J-8 沿用
- **mod.rs 测试更新**：J-7 完成后需同步更新 `test_phase10_gas_costs_reasonable` 和 `test_phase10_registry_full`

---

## 5. Verification Steps

### 5.1 每个子阶段
```bash
# J-2 收尾
cargo test -p poker_zkvm --lib precompiles::elgamal
cargo clippy -p poker_zkvm --lib -- -D warnings

# J-3 至 J-7
cargo test -p poker_zkvm --lib precompiles::zk_shuffle
cargo clippy -p poker_zkvm --lib -- -D warnings

# J-8
cargo test -p poker_zkvm --lib precompiles::dleq
cargo clippy -p poker_zkvm --lib -- -D warnings

# J-9
cargo test -p poker_l1 --lib offline::hypernova
cargo clippy -p poker_l1 --lib -- -D warnings

# mod.rs 集成测试
cargo test -p poker_zkvm --lib precompiles::tests
```

### 5.2 全量回归
```bash
cargo test -p poker_zkvm --lib
cargo test -p poker_l1 --lib
cargo clippy -p poker_zkvm -- -D warnings
cargo clippy -p poker_l1 -- -D warnings
cargo fmt --all -- --check
```

### 5.3 集成测试（J-10）
```bash
cargo test -p poker_zkvm --test zk_shuffle_integration --features test-helpers
```

### 5.4 端到端验证
1. Prover 生成合法 shuffle 的 combined proof（CCS + DLEq）
2. `ZkShuffleVerifier::verify_production()` 返回 `Ok(true)`
3. 篡改 proof 任意字节，验证返回 `Err` 或 `Ok(false)`

---

## 6. 实施顺序

```
J-2 收尾（链接 elgamal + 测试）
    │
    ↓
J-3（排列论证核心）→ J-4（范围+on-curve）→ J-5（ΔC/ΔD）→ J-6（盲化）→ J-7（完整 trait + mod.rs 测试更新）
    │
    ↓
J-8（dleq.rs）→ J-9（poker_l1 verifier）→ J-10（集成测试）
```

**每步完成标准**：
- 对应单元测试通过
- 无新 clippy 警告
- 不破坏既有测试（除非该步骤明确要求更新断言）
