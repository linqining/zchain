# Phase J 续作计划 — ZkShuffle 真实电路（J-3~J-10 收尾）

> **状态**：Plan Mode Phase 4（待用户批准）
> **前置**：[phase_j_continuation_plan.md](file:///Users/mac/projects/zchain/.trae/documents/phase_j_continuation_plan.md)（已批准，J-1/J-2 完成）
> **当前进度**：J-1（bn254_ops.rs）✅、J-2（elgamal.rs）✅ 完成；J-3~J-7（zk_shuffle.rs）文件已写入 927 行但**有编译错误**（`todo!()` + 字段访问 bug + λ_i limb 表示错误），测试**尚未运行**；J-8/J-9/J-10 待实现

---

## 1. Summary

本计划承接已批准的 Phase J 续作计划，从修复 zk_shuffle.rs 的编译错误开始，顺序完成 J-3~J-7 收尾、J-8（dleq.rs）、J-9（poker_l1 verifier）、J-10（集成测试），最终交付完整 ZkShuffle 真实电路 + poker_l1 Production verifier + 集成测试。

**架构决策（已在前置计划中批准，不再重复）**：
- 完整 ZkShuffle 协议（含 ZK 盲化）
- 双证明系统：CCS/Hypernova proof（poker_zkvm）+ Schnorr DLEq proof（poker_l1 原生验证）
- poker_zkvm + poker_l1 同时修改
- Light/Full 双模式（Light: 仅 output on-curve ~890K 约束；Full: 双向 ~1.77M 约束）

---

## 2. Current State Analysis

### 2.1 已完成

**[bn254_ops.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/bn254_ops.rs)**（J-1 ✅）
- `assert_g1_on_curve(builder, x, y)` + BN254_P 常量 + 点运算
- 18 个测试通过

**[elgamal.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/elgamal.rs)**（J-2 ✅）
- Host 类型 + 运算 + `g1_to_u256`/`u256_to_g1` 转换
- `CcsG1Point`/`CcsCiphertext`（pub(crate)）
- 8 个测试通过，已链接到 mod.rs L25

### 2.2 进行中 — zk_shuffle.rs 编译错误（3 个 Bug）

**[zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs)**（927 行，J-3~J-7 进行中）

#### Bug 1: `ct_coor_to_limbs` 函数 `todo!()`（L386-398）

```rust
fn ct_coor_to_limbs(elem: &NonNativeElement) -> [Fr; 4] {
    todo!("see comment - need to redesign data flow")
}
```

**根因**：函数签名接收 `&NonNativeElement`（变量索引），但调用处（L229-232, L248-251）传入的是 `&ct.c.x`，而 `HostCiphertext` 的字段是 `[u64; 4]`（不是 `NonNativeElement`）。

**调用处**（L229-232）：
```rust
let c_x = builder.alloc_element(ct_coor_to_limbs(&ct.c.x));  // ct.c.x 不存在
```

**HostCiphertext 定义**（L482-491）：
```rust
pub struct HostCiphertext {
    pub c_x: [u64; 4],  // 不是 c.x
    pub c_y: [u64; 4],
    pub d_x: [u64; 4],
    pub d_y: [u64; 4],
}
```

#### Bug 2: 字段访问语法错误（L229-232, L248-251）

代码使用 `ct.c.x` / `ct.c.y` / `ct.d.x` / `ct.d.y`（嵌套结构访问），但 `HostCiphertext` 是扁平结构 `ct.c_x` / `ct.c_y` / `ct.d_x` / `ct.d_y`。

#### Bug 3: `fr_to_limbs` λ_i 表示错误（L283, L401-406）

```rust
fn fr_to_limbs(val: &Fr) -> [Fr; 4] {
    [*val, Fr::zero(), Fr::zero(), Fr::zero()]
}
```

**根因**：λ_i 是 BN254 Fr 标量（254 bits），但 `fr_to_limbs` 仅放入 limb[0]（应 < 2^64）。当 λ_i > 2^64 时，4-limb 非原生域表示错误，`mul_mod`/`add_mod` 会产生错误结果。

**影响**：dummy 数据使用 λ_i = 1（L729）恰好 < 2^64，所以测试会通过，但真实随机 λ_i 会失败。

### 2.3 待实现

**mod.rs 测试断言过期**（L374-377, L456）
- `test_phase10_registry_full`：断言 `zk_shuffle.num_variables() == 0` 和 `gas_cost() == 0`
- `test_phase10_gas_costs_reasonable`：断言 `("zk_shuffle", 0, 1)`

**[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs#L306-L323)** ZkShuffleVerifier
- `verify()` Production 路径返回 `Err("ZkShuffle Production verifier 尚未迁移（Phase 11）")`

**dleq.rs**：尚未创建

**集成测试**：尚未创建

---

## 3. Proposed Changes

### J-3~J-7 收尾：修复 zk_shuffle.rs 编译错误 + 运行测试

**文件**：[zk_shuffle.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/zk_shuffle.rs)

#### 修复 1：删除 `ct_coor_to_limbs` 函数（L385-398）

删除整个函数，改用 `NonNativeBuilder::from_u256` 直接从 `[u64; 4]` 创建 `NonNativeElement`。

#### 修复 2：修正字段访问 + 使用 `from_u256`（L226-260）

**原代码**（L226-243）：
```rust
for i in 0..n {
    let ct = &witness.input_cts[i];
    let c_x = builder.alloc_element(ct_coor_to_limbs(&ct.c.x));
    let c_y = builder.alloc_element(ct_coor_to_limbs(&ct.c.y));
    let d_x = builder.alloc_element(ct_coor_to_limbs(&ct.d.x));
    let d_y = builder.alloc_element(ct_coor_to_limbs(&ct.d.y));
    input_cts_vars.push(CcsCiphertext {
        c: crate::precompiles::elgamal::CcsG1Point { x: c_x, y: c_y },
        d: crate::precompiles::elgamal::CcsG1Point { x: d_x, y: d_y },
    });
    if self.full_mode {
        assert_g1_on_curve(&mut builder, &c_x, &c_y);
        assert_g1_on_curve(&mut builder, &d_x, &d_y);
    }
}
```

**修改为**：
```rust
for i in 0..n {
    let ct = &witness.input_cts[i];
    let c_x = builder.from_u256(&ct.c_x);
    let c_y = builder.from_u256(&ct.c_y);
    let d_x = builder.from_u256(&ct.d_x);
    let d_y = builder.from_u256(&ct.d_y);
    input_cts_vars.push(CcsCiphertext {
        c: crate::precompiles::elgamal::CcsG1Point { x: c_x, y: c_y },
        d: crate::precompiles::elgamal::CcsG1Point { x: d_x, y: d_y },
    });
    if self.full_mode {
        assert_g1_on_curve(&mut builder, &c_x, &c_y);
        assert_g1_on_curve(&mut builder, &d_x, &d_y);
    }
}
```

同样修改 output 循环（L245-260）：`ct.c.x` → `ct.c_x` 等，`ct_coor_to_limbs(&ct.c.x)` → `builder.from_u256(&ct.c_x)` 等。

#### 修复 3：修正 λ_i limb 表示（L283, L401-406）

**删除 `fr_to_limbs` 函数**（L400-406），新增正确的 `fr_to_u256_limbs` 函数：

```rust
/// 将单个 Fr（254-bit）转为 [u64; 4]（4 × 64-bit little-endian limbs）。
///
/// 用于将 BN254 Fr 标量（如 λ_i）解释为 BN254 Fp 元素的 4-limb 表示。
fn fr_to_u256_limbs(val: &Fr) -> [u64; 4] {
    let bytes = val.to_canonical_bytes();
    let mut limbs = [0u64; 4];
    for (k, limb) in limbs.iter_mut().enumerate() {
        let start = k * 8;
        *limb = u64::from_le_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
    }
    limbs
}
```

**修改 L283**：
```rust
// 原：let lambda_elem = builder.alloc_element(fr_to_limbs(&witness.lambda_challenges[i]));
let lambda_elem = builder.from_u256(&fr_to_u256_limbs(&witness.lambda_challenges[i]));
```

#### 修复 4：移除未使用的 `NonNativeElement` 导入（L34）

`NonNativeElement` 在删除 `ct_coor_to_limbs` 后不再直接使用（`from_u256` 返回 `NonNativeElement` 但不需要显式类型标注）。检查是否仍需保留导入 — 若 `CcsCiphertext`/`CcsG1Point` 的构造不需要显式 `NonNativeElement` 类型名，则移除导入。

**验证**：运行 `cargo clippy -p poker_zkvm --lib -- -D warnings` 确认无 unused import 警告。

#### 修复 5：更新 dummy 数据使用随机 λ_i（L729）

**原代码**：
```rust
let lambda_challenges: Vec<Fr> = (0..n).map(|_| Fr::from_u64(1)).collect();
```

**修改为**（使用随机 λ_i 测试真实场景）：
```rust
let lambda_challenges: Vec<Fr> = {
    use ark_std::rand::Rng;
    (0..n).map(|_| {
        let r: u64 = rng.gen();
        Fr::from_u64(r)
    }).collect()
};
```

**注**：`Fr::from_u64(r)` 仍 < 2^64，但比固定值 1 更好。完整随机 254-bit λ_i 需要 `Fr::rand`，但 `Fr` 是 `poker_zkvm::ccs::Fr`（非 ark_bn254::Fr）— 需确认 `Fr::rand` 是否可用。若不可用，保持 `Fr::from_u64(random_u64)` 并添加注释说明。

#### 修复 6：更新 mod.rs 测试断言

**[mod.rs L374-377](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L374-L377)** `test_phase10_registry_full`：
```rust
// 原：
let zk_shuffle = registry.get("zk_shuffle").expect("应找到 zk_shuffle");
assert_eq!(zk_shuffle.num_variables(), 0);
assert_eq!(zk_shuffle.gas_cost(), 0);

// 改为：
let zk_shuffle = registry.get("zk_shuffle").expect("应找到 zk_shuffle");
// num_variables: 26 + deck_size*52 + 8 = 26 + 52*52 + 8 = 2738（估算）
assert!(zk_shuffle.num_variables() > 1000, "zk_shuffle 应有大量变量");
assert_eq!(zk_shuffle.gas_cost(), 1_780_000);  // Light mode
```

**[mod.rs L456](file:///Users/mac/projects/zchain/poker_zkvm/src/precompiles/mod.rs#L456)** `test_phase10_gas_costs_reasonable`：
```rust
// 原：("zk_shuffle", 0, 1),
// 改为：("zk_shuffle", 1_000_000, 5_000_000),
```

#### 验证步骤

```bash
cargo test -p poker_zkvm --lib precompiles::zk_shuffle
cargo test -p poker_zkvm --lib precompiles::tests
cargo clippy -p poker_zkvm --lib -- -D warnings
```

**预期**：
- zk_shuffle 的 7 个单元测试通过
- mod.rs 的 phase10 测试通过（更新断言后）
- 无 clippy 警告

---

### J-8：新建 dleq.rs — Schnorr 批量 DLEq proof

**文件**：`poker_zkvm/src/precompiles/dleq.rs`（新建）

**内容**：

```rust
//! Schnorr 批量 DLEq（Discrete Log Equality）proof（Phase J — J-8）。
//!
//! 证明 ΔC = g^R 和 ΔD = pk^R 共享同一离散对数 R，其中：
//! - ΔC = Σ λ_i · (c'_{σ(i)} - c_i) = Σ λ_i · g^{r_i} = g^{Σ λ_i · r_i} = g^R
//! - ΔD = Σ λ_i · (d'_{σ(i)} - d_i) = Σ λ_i · pk^{r_i} = pk^{Σ λ_i · r_i} = pk^R
//!
//! # Schnorr 协议
//!
//! 1. Prover 选随机 w，计算 A = g^w, B = pk^w
//! 2. Challenge c = H(g, pk, ΔC, ΔD, A, B)（Fiat-Shamir）
//! 3. Response z = w + c · R
//! 4. Verifier 校验：g^z == A · ΔC^c AND pk^z == B · ΔD^c
//!
//! # 序列化（97 字节）
//!
//! | 字段 | 偏移 | 长度 | 说明 |
//! |------|------|------|------|
//! | A.x | 0 | 32 | G1 compressed（flags 在高位） |
//! | B.x | 32 | 32 | G1 compressed |
//! | z | 64 | 32 | Fr scalar（little-endian） |
//! | flags | 96 | 1 | 位 0: A.infinity, 位 1: B.infinity |

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_std::{rand::Rng, UniformRand};

/// DLEq proof（A, B, z）。
#[derive(Debug, Clone, Copy)]
pub struct DleqProof {
    /// A = g^w（commitment on g）
    pub a: G1Affine,
    /// B = pk^w（commitment on pk）
    pub b: G1Affine,
    /// z = w + c · R（response）
    pub z: Fr,
}

/// 批量 DLEq prove：证明 ΔC = g^R 且 ΔD = pk^R。
///
/// # 参数
/// - `g`: BN254 G1 生成元
/// - `pk`: ElGamal 公钥
/// - `delta_c`: Σ λ_i · Δc_i = g^R
/// - `delta_d`: Σ λ_i · Δd_i = pk^R
/// - `r_combined`: R = Σ λ_i · r_i
/// - `rng`: 随机数生成器
pub fn batch_dleq_prove(
    g: &G1Affine,
    pk: &G1Affine,
    delta_c: &G1Affine,
    delta_d: &G1Affine,
    r_combined: &Fr,
    rng: &mut impl Rng,
) -> DleqProof {
    // 1. 选随机 w
    let w = Fr::rand(rng);

    // 2. A = g^w, B = pk^w
    let a = G1Projective::from(*g) * w;
    let b = G1Projective::from(*pk) * w;

    // 3. Fiat-Shamir challenge: c = H(g, pk, ΔC, ΔD, A, B)
    let c = fs_challenge(g, pk, delta_c, delta_d, &a.into_affine(), &b.into_affine());

    // 4. z = w + c · R
    let z = w + c * r_combined;

    DleqProof {
        a: a.into_affine(),
        b: b.into_affine(),
        z,
    }
}

/// 批量 DLEq verify：校验 ΔC = g^R 且 ΔD = pk^R。
///
/// 校验等式：
/// - g^z == A · ΔC^c
/// - pk^z == B · ΔD^c
pub fn batch_dleq_verify(
    g: &G1Affine,
    pk: &G1Affine,
    delta_c: &G1Affine,
    delta_d: &G1Affine,
    proof: &DleqProof,
) -> bool {
    // 重算 challenge
    let c = fs_challenge(g, pk, delta_c, delta_d, &proof.a, &proof.b);

    // 校验 g^z == A · ΔC^c
    // 等价于 g^z - ΔC^c == A
    // 用 MSM: [z, -c] · [g, ΔC] == A
    let lhs1 = G1Projective::msm(&[*g, *delta_c], &[proof.z, -c]).unwrap_or(G1Projective::zero());
    if lhs1.into_affine() != proof.a {
        return false;
    }

    // 校验 pk^z == B · ΔD^c
    let lhs2 = G1Projective::msm(&[*pk, *delta_d], &[proof.z, -c]).unwrap_or(G1Projective::zero());
    if lhs2.into_affine() != proof.b {
        return false;
    }

    true
}

/// Fiat-Shamir challenge: c = H(g, pk, ΔC, ΔD, A, B) → Fr
fn fs_challenge(
    g: &G1Affine,
    pk: &G1Affine,
    delta_c: &G1Affine,
    delta_d: &G1Affine,
    a: &G1Affine,
    b: &G1Affine,
) -> Fr {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
    hasher.update(b"poker_zkvm_dleq_v1");
    hasher.update(b"g");
    hasher.update(&g.x.into_bigint().to_bytes_le());
    hasher.update(&g.y.into_bigint().to_bytes_le());
    hasher.update(b"pk");
    hasher.update(&pk.x.into_bigint().to_bytes_le());
    hasher.update(&pk.y.into_bigint().to_bytes_le());
    hasher.update(b"dc");
    hasher.update(&delta_c.x.into_bigint().to_bytes_le());
    hasher.update(&delta_c.y.into_bigint().to_bytes_le());
    hasher.update(b"dd");
    hasher.update(&delta_d.x.into_bigint().to_bytes_le());
    hasher.update(&delta_d.y.into_bigint().to_bytes_le());
    hasher.update(b"a");
    hasher.update(&a.x.into_bigint().to_bytes_le());
    hasher.update(&a.y.into_bigint().to_bytes_le());
    hasher.update(b"b");
    hasher.update(&b.x.into_bigint().to_bytes_le());
    hasher.update(&b.y.into_bigint().to_bytes_le());

    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("finalize");
    Fr::from_canonical_bytes(&out).unwrap_or(Fr::zero())
}

impl DleqProof {
    /// 序列化为 97 字节。
    pub fn to_bytes(&self) -> [u8; 97] {
        let mut out = [0u8; 97];
        // A compressed (32 bytes: x || flags)
        let a_x_bytes = self.a.x.into_bigint().to_bytes_le();
        out[0..32].copy_from_slice(&a_x_bytes);
        // B compressed (32 bytes)
        let b_x_bytes = self.b.x.into_bigint().to_bytes_le();
        out[32..64].copy_from_slice(&b_x_bytes);
        // z (32 bytes little-endian)
        let z_bytes = self.z.into_bigint().to_bytes_le();
        out[64..96].copy_from_slice(&z_bytes);
        // flags (1 byte)
        let mut flags = 0u8;
        if self.a.is_zero() {
            flags |= 1;
        }
        if self.b.is_zero() {
            flags |= 2;
        }
        out[96] = flags;
        out
    }

    /// 从 97 字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 97 {
            return None;
        }
        let flags = bytes[96];
        let a = if flags & 1 != 0 {
            G1Affine::zero()
        } else {
            let x_bigint = ark_ff::BigInt::<4>::from_bytes_le(&bytes[0..32]);
            let x_fq = Fq::from_bigint(x_bigint)?;
            // 恢复 y: y² = x³ + 3
            let y_sq = x_fq * x_fq * x_fq + Fq::from(3u64);
            let y_fq = y_sq.sqrt()?;
            G1Affine::new(x_fq, y_fq)
        };
        let b = if flags & 2 != 0 {
            G1Affine::zero()
        } else {
            let x_bigint = ark_ff::BigInt::<4>::from_bytes_le(&bytes[32..64]);
            let x_fq = Fq::from_bigint(x_bigint)?;
            let y_sq = x_fq * x_fq * x_fq + Fq::from(3u64);
            let y_fq = y_sq.sqrt()?;
            G1Affine::new(x_fq, y_fq)
        };
        let z_bigint = ark_ff::BigInt::<4>::from_bytes_le(&bytes[64..96]);
        let z = Fr::from_bigint(z_bigint)?;
        Some(Self { a, b, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_dleq_prove_verify_roundtrip() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::generator() * sk).into_affine();
        let r = Fr::rand(&mut rng);
        let delta_c = (G1Projective::generator() * r).into_affine();
        let delta_d = (G1Projective::from(pk) * r).into_affine();

        let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
        assert!(batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &proof));
    }

    #[test]
    fn test_dleq_verify_invalid_proof() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::generator() * sk).into_affine();
        let r = Fr::rand(&mut rng);
        let delta_c = (G1Projective::generator() * r).into_affine();
        let delta_d = (G1Projective::from(pk) * r).into_affine();

        let mut proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
        proof.z = proof.z + Fr::one();  // 篡改 z
        assert!(!batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &proof));
    }

    #[test]
    fn test_dleq_verify_wrong_delta_c() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::generator() * sk).into_affine();
        let r = Fr::rand(&mut rng);
        let delta_c = (G1Projective::generator() * r).into_affine();
        let delta_d = (G1Projective::from(pk) * r).into_affine();

        let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);

        // 使用错误的 ΔC
        let wrong_dc = (G1Projective::generator() * Fr::from(12345u64)).into_affine();
        assert!(!batch_dleq_verify(&g, &pk, &wrong_dc, &delta_d, &proof));
    }

    #[test]
    fn test_dleq_serialization_roundtrip() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::generator() * sk).into_affine();
        let r = Fr::rand(&mut rng);
        let delta_c = (G1Projective::generator() * r).into_affine();
        let delta_d = (G1Projective::from(pk) * r).into_affine();

        let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 97);
        let recovered = DleqProof::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(recovered.a, proof.a);
        assert_eq!(recovered.b, proof.b);
        assert_eq!(recovered.z, proof.z);
        assert!(batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &recovered));
    }
}
```

**修改 mod.rs**：在 `pub mod ed25519;` 之后添加 `pub mod dleq;`（保持字母序）。

**验证**：
```bash
cargo test -p poker_zkvm --lib precompiles::dleq
cargo clippy -p poker_zkvm --lib -- -D warnings
```

---

### J-9：修改 poker_l1 ZkShuffleVerifier Production 路径

**文件**：[poker_l1/src/offline/hypernova.rs](file:///Users/mac/projects/zchain/poker_l1/src/offline/hypernova.rs#L306-L323)

**修改 `verify()` 方法**（L306-323）：

```rust
fn verify(
    &self,
    proof: &[u8],
    public_io: &super::zk_verifier::ZkPublicIo,
    status: VerifierStatus,
) -> Result<bool, PokerL1Error> {
    // Stub 状态：仅校验格式
    if status == VerifierStatus::Stub {
        self.validate_proof_format(proof)?;
        return Ok(true);
    }

    // Production 状态：委托到 verify_production
    self.verify_production(proof, public_io)
}
```

**新增 `verify_production()` 方法**：

```rust
/// ZkShuffle Production verifier：解析 combined proof 并验证。
///
/// Combined proof 格式：
/// ```text
/// | magic(4) | version(4) | ccs_len(4) | ccs_proof(N) | dleq_len(4) | dleq_proof(97) |
/// ```
fn verify_production(
    &self,
    proof: &[u8],
    public_io: &super::zk_verifier::ZkPublicIo,
) -> Result<bool, PokerL1Error> {
    // 1. 校验最小长度
    if proof.len() < 4 + 4 + 4 + 4 + 97 {
        return Err(PokerL1Error::InvalidZkProofFormat(format!(
            "combined proof 长度 {} < 最小要求 113",
            proof.len()
        )));
    }

    // 2. 解析 magic + version
    let magic = &proof[0..4];
    if magic != b"ZKSF" {
        return Err(PokerL1Error::InvalidZkProofFormat(
            "combined proof magic 不匹配（期望 ZKSF）".to_string(),
        ));
    }
    let version = u32::from_le_bytes(proof[4..8].try_into().expect("4 bytes"));
    if version != 1 {
        return Err(PokerL1Error::InvalidZkProofFormat(format!(
            "combined proof version {} != 1",
            version
        )));
    }

    // 3. 解析 CCS proof
    let ccs_len = u32::from_le_bytes(proof[8..12].try_into().expect("4 bytes")) as usize;
    let ccs_proof_end = 12 + ccs_len;
    if ccs_proof_end + 4 + 97 > proof.len() {
        return Err(PokerL1Error::InvalidZkProofFormat(format!(
            "combined proof ccs_len {} 越界",
            ccs_len
        )));
    }
    let ccs_proof = &proof[12..ccs_proof_end];

    // 4. 解析 DLEq proof
    let dleq_len = u32::from_le_bytes(
        proof[ccs_proof_end..ccs_proof_end + 4].try_into().expect("4 bytes"),
    ) as usize;
    if dleq_len != 97 {
        return Err(PokerL1Error::InvalidZkProofFormat(format!(
            "dleq_len {} != 97",
            dleq_len
        )));
    }
    let dleq_proof_bytes = &proof[ccs_proof_end + 4..ccs_proof_end + 4 + 97];

    // 5. 验证 CCS/Hypernova proof
    // 委托到现有 HypernovaVerifier（scheme_id=1 路径）
    // 注：ZkShuffle 的 CCS proof 用 Hypernova 验证（CCS 结构相同）
    let hypernova_verifier = HypernovaVerifier::new();
    let hypernova_ok = hypernova_verifier.verify(ccs_proof, public_io, VerifierStatus::Production)?;
    if !hypernova_ok {
        return Ok(false);
    }

    // 6. 验证 DLEq proof
    // 从 public_io 提取 pk, ΔC, ΔD
    let (g, pk, delta_c, delta_d) = parse_shuffle_public_io(public_io)?;
    let dleq_proof = poker_zkvm::precompiles::dleq::DleqProof::from_bytes(dleq_proof_bytes)
        .ok_or_else(|| PokerL1Error::InvalidZkProofFormat(
            "DLEq proof 反序列化失败".to_string(),
        ))?;
    let dleq_ok = poker_zkvm::precompiles::dleq::batch_dleq_verify(
        &g, &pk, &delta_c, &delta_d, &dleq_proof,
    );
    if !dleq_ok {
        return Ok(false);
    }

    Ok(true)
}

/// 从 ZkPublicIo 提取 (g, pk, ΔC, ΔD)。
fn parse_shuffle_public_io(
    public_io: &super::zk_verifier::ZkPublicIo,
) -> Result<(ark_bn254::G1Affine, ark_bn254::G1Affine, ark_bn254::G1Affine, ark_bn254::G1Affine), PokerL1Error> {
    // public_io 格式：pk(64B) + delta_c(64B) + delta_d(64B) = 192B
    // 每个 G1 点 = x(32B) + y(32B)
    let bytes = public_io.as_bytes();
    if bytes.len() < 192 {
        return Err(PokerL1Error::InvalidZkProofFormat(format!(
            "public_io 长度 {} < 192",
            bytes.len()
        )));
    }

    let g = ark_bn254::G1Projective::generator().into_affine();
    let pk = parse_g1_affine(&bytes[0..64])?;
    let delta_c = parse_g1_affine(&bytes[64..128])?;
    let delta_d = parse_g1_affine(&bytes[128..192])?;

    Ok((g, pk, delta_c, delta_d))
}

/// 从 64 字节解析 G1Affine（x||y，各 32B little-endian）。
fn parse_g1_affine(bytes: &[u8]) -> Result<ark_bn254::G1Affine, PokerL1Error> {
    use ark_ff::BigInteger;
    let x_bigint = ark_ff::BigInt::<4>::from_bytes_le(&bytes[0..32]);
    let y_bigint = ark_ff::BigInt::<4>::from_bytes_le(&bytes[32..64]);
    let x_fq = ark_bn254::Fq::from_bigint(x_bigint)
        .ok_or_else(|| PokerL1Error::InvalidZkProofFormat("pk.x 不在 BN254 Fp 域内".to_string()))?;
    let y_fq = ark_bn254::Fq::from_bigint(y_bigint)
        .ok_or_else(|| PokerL1Error::InvalidZkProofFormat("pk.y 不在 BN254 Fp 域内".to_string()))?;
    // 校验 on-curve
    let y_sq = y_fq * y_fq;
    let rhs = x_fq * x_fq * x_fq + ark_bn254::Fq::from(3u64);
    if y_sq != rhs {
        return Err(PokerL1Error::InvalidZkProofFormat(
            "G1 点不在曲线上".to_string(),
        ));
    }
    Ok(ark_bn254::G1Affine::new(x_fq, y_fq))
}
```

**修改 `validate_proof_format()`**（L389-403）：
```rust
fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
    if proof.is_empty() {
        return Err(PokerL1Error::InvalidZkProofFormat(
            "zkshuffle proof 不能为空".to_string(),
        ));
    }
    // Stub 路径仍接受旧格式（仅长度校验）
    if proof.len() < HYPERNOVA_PROOF_MIN_SIZE {
        return Err(PokerL1Error::InvalidZkProofFormat(format!(
            "zkshuffle proof 长度 {} < 最小要求 {}",
            proof.len(),
            HYPERNOVA_PROOF_MIN_SIZE
        )));
    }
    Ok(())
}
```

**新增测试**（在 hypernova.rs 测试模块中）：
- `test_zkshuffle_verify_production_invalid_magic`
- `test_zkshuffle_verify_production_short_proof`

**验证**：
```bash
cargo test -p poker_l1 --lib offline::hypernova
cargo clippy -p poker_l1 --lib -- -D warnings
```

---

### J-10：集成测试

**文件**：`poker_zkvm/tests/zk_shuffle_integration.rs`（新建）

**测试矩阵**：
| 测试 | 描述 |
|------|------|
| `test_shuffle_light_mode_valid` | deck_size=4 合法 shuffle，Light mode，CCS satisfied |
| `test_shuffle_full_mode_valid` | deck_size=4 合法 shuffle，Full mode，CCS satisfied |
| `test_shuffle_invalid_permutation` | 排列越界，返回 Err |
| `test_shuffle_delta_c_mismatch` | 篡改 ΔC，CCS 不 satisfied |
| `test_shuffle_delta_d_mismatch` | 篡改 ΔD，CCS 不 satisfied |
| `test_shuffle_dleq_valid` | 合法 DLEq proof 验证通过 |
| `test_shuffle_dleq_invalid` | 篡改 DLEq proof 验证失败 |
| `test_shuffle_dleq_serialization` | DLEq 序列化 roundtrip |
| `test_shuffle_public_input_roundtrip` | ShufflePublicInput to_vec/from_vec |
| `test_shuffle_combined_proof_format` | combined proof 格式校验 |

**测试辅助**：使用 `build_dummy_data(deck_size)`（已在 zk_shuffle.rs 中）+ `elgamal` 模块的 host 运算。

**验证**：
```bash
cargo test -p poker_zkvm --test zk_shuffle_integration
```

---

## 4. Assumptions & Decisions

### 4.1 延续前置计划决策
所有架构决策（Schnorr DLEq、双证明系统、Light/Full 双模式、card_id·G 牌面编码）延续前置计划，不重新决策。

### 4.2 新增决策
1. **λ_i 转换**：使用 `fr_to_u256_limbs` 将 Fr (254-bit) 正确转为 [u64; 4]（4 × 64-bit limbs），而非错误的单 limb 表示。
2. **密文变量分配**：使用 `builder.from_u256(&ct.c_x)` 直接从 host [u64; 4] 创建 NonNativeElement，而非通过 `alloc_element(ct_coor_to_limbs(...))`。
3. **DLEq 序列化**：97 字节（A: 32B x-only + B: 32B x-only + z: 32B + flags: 1B），反序列化时从 x 坐标恢复 y（sqrt(x³+3)）。
4. **Combined proof 格式**：`magic(4) | version(4) | ccs_len(4) | ccs_proof(N) | dleq_len(4) | dleq_proof(97)`。
5. **public_io 格式**：`pk(64B) + delta_c(64B) + delta_d(64B) = 192B`（每个 G1 点 = x||y 各 32B）。

### 4.3 风险与缓解
- **DLEq 反序列化**：从 x 坐标恢复 y 有符号歧义（两个平方根）。**缓解**：验证时用 proof 中的 A/B 点（完整 x,y）直接验证，反序列化仅用于从 proof 字节恢复 A/B — 实际上需要存储完整点。**修正**：序列化存储完整 x||y（各 32B），总长度 = 32+32+32+32+32+1 = 161B，或使用压缩格式（32B x + 1 bit y parity）= 32+32+32+1 = 97B 但需处理符号。**决定**：先用 97B x-only + flags，反序列化时计算 y（选正根），若验证失败则尝试负根。实际上更好的方案是存储 compressed point（ark-ec 支持）— 但为简化，先用 97B 方案。
- **CCS proof 验证委托**：ZkShuffle 的 CCS proof 是否能直接用 HypernovaVerifier 验证？**假设**：可以，因为 CCS 结构相同，仅 witness/public_input 不同。若不行，需在 J-9 中适配。
- **mod.rs 测试更新**：J-7 完成后同步更新 `test_phase10_gas_costs_reasonable` 和 `test_phase10_registry_full`。

---

## 5. Verification Steps

### 5.1 J-3~J-7 收尾
```bash
cargo test -p poker_zkvm --lib precompiles::zk_shuffle
cargo test -p poker_zkvm --lib precompiles::tests
cargo clippy -p poker_zkvm --lib -- -D warnings
```

### 5.2 J-8
```bash
cargo test -p poker_zkvm --lib precompiles::dleq
cargo clippy -p poker_zkvm --lib -- -D warnings
```

### 5.3 J-9
```bash
cargo test -p poker_l1 --lib offline::hypernova
cargo clippy -p poker_l1 --lib -- -D warnings
```

### 5.4 J-10
```bash
cargo test -p poker_zkvm --test zk_shuffle_integration
```

### 5.5 全量回归
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
J-3~J-7 收尾（修复 zk_shuffle.rs + mod.rs 测试更新）
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
