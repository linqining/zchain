# Phase J — ZkShuffle 真实电路实现计划

> **状态**：Plan Mode Phase 4（待用户批准）
> **范围**：完整 ZkShuffle 协议（含 ZK 盲化），poker_zkvm + poker_l1 同时修改
> **依赖**：Phase I（已完成）、Phase F（Groth16 压缩，已完成）、Phase H（256-bit ECDSA，已完成）

---

## 1. Summary

将 `ZkShuffleCcsCircuit` 从 stub 替换为真实 Mental Poker ZkShuffle 电路，基于：
- **ElGamal 交换加密**（BN254 G1 群）：密文 `(c, d) = (g^r, m · pk^r)`
- **排列论证**（LogUp）：证明输出牌组是输入牌组的一个置换
- **G1 on-curve 检查**：验证所有密文点是合法 BN254 G1 点
- **批量 DLEq（Schnorr）**：证明重加密使用了正确的随机数 r
- **ZK 盲化**：witness 末尾追加随机 blinding 变量

采用**双证明系统**：
1. **CCS/Hypernova proof**（poker_zkvm）：排列 + 范围 + on-curve + ΔC/ΔD 线性组合 + 盲化
2. **Schnorr DLEq proof**（poker_l1 原生验证）：证明 `g^R = ΔC` 且 `pk^R = ΔD`

不使用 Groth16 DLEq（避免 trusted setup 复杂度），改用 Schnorr DLEq（~97B，原生验证，无 trusted setup）。

---

## 2. Current State Analysis

### 2.1 现有 stub（需替换）

**[poker_zkvm/src/precompiles/zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs)**（174 行）
- `ZkShuffleCcsCircuit::new()` 返回 stub，`build_ccs()` 返回空 CCS
- `assign_witness()` / `to_ccs_instance()` 返回 `Err("Phase 11 pending")`
- `gas_cost()` 返回 0
- 5 个测试断言 stub 行为（需替换为真实电路测试）

**[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs#L280-L404)**（ZkShuffleVerifier）
- `verify()` Production 路径返回 `Err("ZkShuffle Production verifier 尚未迁移（Phase 11）")`
- `verify_with_context()` grace 期内走 stub 路径（仅校验长度 + proof_hash 匹配）
- `validate_proof_format()` 仅检查非空 + `>= HYPERNOVA_PROOF_MIN_SIZE`

### 2.2 可复用基础设施

| 组件 | 文件 | 复用方式 |
|------|------|----------|
| 非原生域算术 | [non_native.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/non_native.rs) | `NonNativeBuilder` 通用，传 `&BN254_P` 即可做 BN254 Fp 算术 |
| BN254 常量 | [bn254_pairing.rs:38-46](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/bn254_pairing.rs#L38-L46) | `BN254_P` / `BN254_B` 已定义，提取到 `bn254_ops.rs` |
| G1 on-curve 检查 | [bn254_pairing.rs:65](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/bn254_pairing.rs#L65) | `assert_g1_on_curve` 提取到 `bn254_ops.rs` |
| secp256k1 点运算模式 | [secp256k1_ops.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/secp256k1_ops.rs) | 作为 `bn254_ops.rs` 的模板（BN254 a=0, b=3 同 secp256k1 a=0, b=7） |
| CCS 构建器 | [ccs_builder.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/ccs_builder.rs) | `CcsBuilder` API 直接使用 |
| LogUp 排列论证 | [lookup.rs:247-340](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs#L247-L340) | `LogUpProof::create/verify/verify_equation` |
| PrecompileCircuit trait | [mod.rs:52-70](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L52-L70) | 实现 `build_ccs` + `assign_witness` + `gas_cost` |
| CcsCircuit trait | [mod.rs:136-156](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L136-L156) | 实现 `to_ccs_instance` |
| ProofKind / scheme_id | [zk_verifier.rs:19-74](file:///Users/mac/projects/zchain/poker_l1/src/offline/zk_verifier.rs#L19-L74) | `SCHEME_ZKSHUFFLE = 4` → `ProofKind::ZkShuffle` |
| ark-bn254 依赖 | [Cargo.toml:17-28](file:///Users/mac/projects/zchain/poker_zkvm/Cargo.toml#L17-L28) | `ark-bn254` / `ark-ec` / `ark-groth16` 已在 workspace |

### 2.3 约束预算

| 组件 | 单次约束数 | 数量 | 小计 |
|------|-----------|------|------|
| assert_g1_on_curve（输出牌） | ~8,400 | 52 × 2 = 104 | ~873,600 |
| assert_g1_on_curve（输入牌） | ~8,400 | 52 × 2 = 104 | ~873,600 |
| 牌面范围检查（0-51） | ~270 | 52 | ~14,040 |
| LogUp 排列 witness | ~2 | 52 × 2 | ~208 |
| ΔC/ΔD 线性组合 | ~4 | 52 × 16 limbs | ~3,328 |
| ZK 盲化 | ~64 | 8 | ~512 |
| **总计（Full mode）** | | | **~1.77M** |
| **总计（Light mode，仅输出 on-curve）** | | | **~890K** |

> Hypernova 折叠可处理百万级约束，经 Phase F Groth16 压缩后 proof ~200B。

---

## 3. Proposed Changes

### J-1: 新建 `poker_zkvm/src/precompiles/bn254_ops.rs`

**目标**：BN254 G1 点运算 CCS 电路（镜像 secp256k1_ops.rs 结构，BN254 参数 a=0, b=3）。

**内容**：
- 从 `bn254_pairing.rs` 提取 `BN254_P` / `BN254_B` 常量到此文件，`bn254_pairing.rs` 改为 `use crate::precompiles::bn254_ops::{BN254_P, BN254_B, assert_g1_on_curve}`
- `Point` 结构（复用 `NonNativeElement` for x/y/z Jacobian 坐标）
- `identity_point()` → (1:1:0)
- `from_affine(x, y)` → (x:y:1)
- `point_double(p)` — BN254 倍点公式（a=0，同 secp256k1 但 b=3）
- `point_add(p, q)` — BN254 点加（EFD add-1998-cmo-2，H = U1-U2 符号修正）
- `scalar_mul(p, scalar, num_bits)` — Double-and-add
- `assert_on_curve(p)` — 提取自 bn254_pairing.rs
- `assert_point_equal(a, b)` — 逐 limb 相等检查

**约束计数**：同 secp256k1_ops（point_double ~8,400 / point_add ~16,800 / scalar_mul(256) ~6.5M）

**修改 `bn254_pairing.rs`**：删除重复的 `BN254_P` / `BN254_B` / `assert_g1_on_curve`，改为从 `bn254_ops` 导入。

**修改 `precompiles/mod.rs`**：添加 `pub mod bn254_ops;`。

---

### J-2: 新建 `poker_zkvm/src/precompiles/elgamal.rs`

**目标**：ElGamal 类型定义 + host-side 运算（使用 ark-bn254）。

**内容**：
```rust
// Host-side 类型（ark-bn254）
pub struct ElGamalPublicKey { pk: ark_bn254::G1Affine }
pub struct ElGamalSecretKey { sk: ark_ff::Fq }  // BN254 标量域
pub struct ElGamalCiphertext { c: ark_bn254::G1Affine, d: ark_bn254::G1Affine }

// host 运算
pub fn keygen(rng) -> (PublicKey, SecretKey)
pub fn encrypt(pk: &PublicKey, msg: &G1Affine, r: &Fr) -> Ciphertext
pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> G1Affine
pub fn reencrypt(pk: &PublicKey, ct: &Ciphertext, r: &Fr) -> Ciphertext
pub fn batch_dleq_prove(pk, cts_in, cts_out, permutation, rs) -> DleqProof
pub fn batch_dleq_verify(pk, cts_in, cts_out, proof) -> bool

// CCS-side 表示
pub struct CcsCiphertext { c: NonNativeElement_x2, d: NonNativeElement_x2 }  // 16 limbs
```

**关键设计**：
- 牌面 m 映射为 G1 点：`m_point = card_id * G`（card_id ∈ 0..52）
- 重加密：`(c', d') = (c · g^r', d · pk^r')`
- 批量 DLEq（Schnorr）：
  1. Δc_i = c'_{σ(i)} - c_i = g^{r_i}
  2. Δd_i = d'_{σ(i)} - d_i = pk^{r_i}
  3. FS challenge λ_i = H(c_ts, Δc_1, Δd_1, ..., Δc_n, Δd_n, i)
  4. R = Σ λ_i · r_i
  5. ΔC = Σ λ_i · Δc_i = g^R
  6. ΔD = Σ λ_i · Δd_i = pk^R
  7. Schnorr proof: (A=g^w, B=pk^w, z=w+c·R) where c=H(g, pk, ΔC, ΔD, A, B)

**修改 `precompiles/mod.rs`**：添加 `pub mod elgamal;`。

---

### J-3: 修改 `poker_zkvm/src/precompiles/zk_shuffle.rs` — 排列论证

**目标**：替换 stub，实现 LogUp 排列论证核心。

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
    pub delta_c: [Fr; 8],         // ΔC = Σ λ_i · Δc_i (G1 点)
    pub delta_d: [Fr; 8],         // ΔD = Σ λ_i · Δd_i (G1 点)
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

**排列论证**：
- 将每个 `(c, d)` 编码为单个 Fr：`enc_i = H_to_Fr(c_x, c_y, d_x, d_y)`
- LogUp table T = {enc_1, ..., enc_n}（input）
- LogUp witness W = {enc'_{σ(1)}, ..., enc'_{σ(n)}}（output，按 σ 重排）
- LogUp multiplicity m_i = 1（每张牌出现一次）
- 验证 `Σ m_i / (β - t_i) == Σ 1 / (β - f_j)` 即可证明 multiset 相等

---

### J-4: 修改 `zk_shuffle.rs` — 范围检查与 on-curve 验证

**牌面范围检查**：
- 每张牌的 card_id ∈ [0, 51]
- 使用 `NonNativeBuilder::assert_lt(card_id_elem, &52_u256)`

**G1 on-curve 检查**：
- Full mode：input 和 output 所有密文的 c/d 都检查
- Light mode：仅 output 检查（input 由上一轮 proof 保证）
- 调用 `bn254_ops::assert_g1_on_curve(builder, &x, &y)`

---

### J-5: 修改 `zk_shuffle.rs` — 批量 ΔC/ΔD 计算

**目标**：在 CCS 中计算 `ΔC = Σ λ_i · (c'_{σ(i)} - c_i)` 和 `ΔD = Σ λ_i · (d'_{σ(i)} - d_i)`。

**CCS 约束**（每张牌）：
1. `Δc_i = c'_{σ(i)} - c_i`（`sub_mod` in BN254 Fp）
2. `λ_i · Δc_i`（`mul_mod` in BN254 Fp）
3. 累加 `ΔC += λ_i · Δc_i`（`add_mod`）

**约束计数**：每张牌 2 × (sub_mod + mul_mod + add_mod) ≈ 2 × (30 + 1400 + 30) = ~2,920，52 张 ≈ 151,840

**最终 `assert_equal(ΔC_ccs, ΔC_public)`**：将 CCS 计算的 ΔC/ΔD 与 public input 中的 ΔC/ΔD 绑定。

---

### J-6: 修改 `zk_shuffle.rs` — ZK 盲化

**方法**：witness 末尾追加 k=8 个随机 Fr 变量，参与最终 commitment。
- 分配 8 个随机变量 `b_1, ..., b_8`
- 将 `b_i` 混入 `output_commitment = H(..., b_1, ..., b_8)`
- 确保 witness 不为零空间，防止 prover 作弊

---

### J-7: 重写 `zk_shuffle.rs` — ZkShuffleCcsCircuit 完整实现

**实现 PrecompileCircuit trait**：
```rust
fn name(&self) -> &str { "zk_shuffle" }
fn num_variables(&self) -> usize { /* 根据 deck_size 计算总变量数 */ }
fn build_ccs(&self) -> Ccs { /* 调用内部 build_shuffle_ccs(deck_size, full_mode) */ }
fn assign_witness(&self, inputs: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
    // inputs = [pk(8), input_cts(n*16), output_cts(n*16), perm(n), rs(n), lambdas(n), blinding(8)]
    // 调用 build_shuffle_witness() 计算 witness
}
fn gas_cost(&self) -> u64 {
    // Full mode: ~1.77M constraints → gas = 1_770_000 * 2 = 3_540_000
    // Light mode: ~890K → gas = 1_780_000
    if self.full_mode { 3_540_000 } else { 1_780_000 }
}
```

**实现 CcsCircuit trait**：
```rust
fn to_ccs_instance(&self, witness: &[Fr], public_inputs: &[Fr]) -> Result<CcsInstance, ZkvmError> {
    // 1. 验证 witness 长度
    // 2. 验证 ccs.satisfied_by(witness)
    // 3. 提取 public_inputs 到 CcsInstance
}
```

**新增 `new_full()` / `new_light()` 构造函数**：
- `new()` / `new_light()` → Light mode（默认，仅 output on-curve）
- `new_full()` → Full mode（双向 on-curve）

---

### J-8: 新建 `poker_zkvm/src/precompiles/dleq.rs`

**目标**：Schnorr 批量 DLEq proof 生成与验证（host-side，使用 ark-bn254）。

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

**序列化**：`DleqProof` → `[u8; 97]`（A: 32B compressed + B: 32B compressed + z: 32B + 1B flag）
**验证开销**：4 次 G1 标量乘 + 2 次等式检查（native，<1ms）

---

### J-9: 修改 `poker_l1/src/offline/hypernova.rs`

**目标**：ZkShuffleVerifier Production 路径实现。

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
    // 4. 验证 CCS/Hypernova proof（委托 HypernovaVerifier）
    // 5. 验证 Schnorr DLEq proof（调用 dleq::batch_dleq_verify）
    // 6. 两者都通过才返回 true
}
```

**修改 `validate_proof_format()`**：
- 校验 magic + version + 长度字段
- 最小长度 = 4 + 4 + 4 + HYPERNOVA_PROOF_MIN_SIZE + 4 + 97

**保持 `verify_with_context()` 不变**：grace 期逻辑已正确，仅需 Production 分支委托到新的 `verify()`。

---

### J-10: 新建 `poker_zkvm/tests/zk_shuffle_integration.rs`

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

**测试辅助**：使用 `test-helpers` feature 共享 ELF 构建代码模式（参考 project_memory 中 test_helpers 约定）。

---

## 4. Assumptions & Decisions

### 4.1 架构决策

| 决策 | 选择 | 理由 |
|------|------|------|
| DLEq 验证方式 | Schnorr（非 Groth16） | 避免 trusted setup；~97B proof；native 验证 <1ms |
| DLEq 验证位置 | poker_l1 原生（非 CCS 内） | CCS 内 256-bit scalar_mul ~6.5M 约束，不可接受 |
| ΔC/ΔD 绑定方式 | CCS 计算 + public input 绑定 | CCS 证明 ΔC/ΔD 由真实密文计算；DLEq 证明 ΔC=g^R, ΔD=pk^R |
| on-curve 检查范围 | 双模式（Light/Full） | Light 仅检查 output（~890K），Full 双向检查（~1.77M） |
| 牌面编码 | card_id · G（G1 点） | ElGamal 明文空间 = G1 群；card_id ∈ [0, 51] |
| 排列编码 | LogUp over H(c_x, c_y, d_x, d_y) | 复用现有 LogUpProof API；O(n) verifier |
| ZK 盲化 | witness 末尾 8 个随机 Fr | 标准技术；混入 output_commitment |

### 4.2 假设

1. **deck_size = 52**（标准扑克），可配置但测试固定 52
2. **BN254 标量域** = `ark_ff::Fr`（与 CCS Fr 一致），**BN254 基域** = `ark_ff::Fq`（非原生，需 NonNativeBuilder）
3. **ElGamal 明文** = G1 点 `m · G`，card_id ∈ [0, 51] → 52 个预计算点
4. **FS challenge** λ_i 使用 `Transcript`（poker_zkvm 现有 Fiat-Shamir 实现）
5. **grace 期逻辑不变**：J-9 仅修改 Production 路径，stub/grace 期路径保持
6. **ProofKind::ZkShuffle 仍用旧签名**（无 proof_kind 字段），grace 期后强制新签名（由 verify_with_context 处理，不改动）

### 4.3 未选择方案（记录）

- **Groth16 DLEq**：需 trusted setup + R1CS 构建复杂度，且 ark-groth16 集成增加依赖面。Schnorr 达到同等安全级别且更简单。
- **CCS 内 DLEq**：256-bit scalar_mul 在 CCS 中 ~6.5M 约束，不可接受。
- **poker_protocol 复用**：J-1 spike 确认 `poker_protocol` crate 不存在，走全新实现路径。

---

## 5. Verification Steps

### 5.1 单元测试（每个子阶段）

- **J-1**：`cargo test -p poker_zkvm --lib bn254_ops` — 点运算正确性（double/add/scalar_mul/on_curve）
- **J-2**：`cargo test -p poker_zkvm --lib elgamal` — 加密/解密/重加密 round-trip
- **J-3~J-7**：`cargo test -p poker_zkvm --lib zk_shuffle` — CCS build + satisfied_by + 拒绝非法 witness
- **J-8**：`cargo test -p poker_zkvm --lib dleq` — DLEq prove/verify round-trip + 拒绝非法 proof
- **J-9**：`cargo test -p poker_l1 --lib offline::hypernova` — ZkShuffleVerifier Production 路径

### 5.2 集成测试（J-10）

```bash
cargo test -p poker_zkvm --test zk_shuffle_integration --features test-helpers
cargo test -p poker_l1 --lib offline::hypernova --features test-helpers
```

### 5.3 clippy + 格式

```bash
cargo clippy -p poker_zkvm -- -D warnings
cargo clippy -p poker_l1 -- -D warnings
cargo fmt --all -- --check
```

### 5.4 端到端验证

1. Prover 生成合法 shuffle 的 combined proof（CCS + DLEq）
2. `ZkShuffleVerifier::verify_production()` 返回 `Ok(true)`
3. 篡改 proof 任意字节，验证返回 `Err` 或 `Ok(false)`

---

## 6. 实施顺序与依赖

```
J-1 (bn254_ops) ──┐
                  ├─→ J-3 (排列) ──→ J-4 (范围+on-curve) ──→ J-5 (ΔC/ΔD) ──→ J-6 (盲化) ──→ J-7 (完整实现)
J-2 (elgamal)  ───┘                                                                         │
                                                                                            ↓
J-8 (dleq)  ────────────────────────────────────────────────────────────→ J-9 (poker_l1) ──→ J-10 (集成测试)
```

- J-1 和 J-2 可并行
- J-3 到 J-7 顺序执行（同一文件递增改造）
- J-8 依赖 J-2（DLEq 使用 ElGamal 类型）
- J-9 依赖 J-7 + J-8
- J-10 依赖全部完成
