# poker\_zkvm Phase 1.5.2 — IPA over BN254 实现计划

> **范围**：Task 1.5.2（IPA 实现）+ Task 1.5.3（Phase 1.5 全量验证）
> **依赖**：Phase 1.5.1 已完成（`pcs/mod.rs` 的 `Pcs` trait + `MultilinearPoly`）
> **遵循**：TDD 严格模式（RED → GREEN → REFACTOR），spec.md L326-337（v1.4 FROZEN），tasks.md SubTask 1.5.2.1-1.5.2.5
> **用户要求**：从基础开始实现，测试通过后才进入下一步；多个方案时选择推荐的，备选放入 `docs/alternatives.md`

***

## 一、当前状态分析

### 已完成

* [x] Phase 0：crate 骨架（`lib.rs` 16 模块、`error.rs` 18 variants、workspace 集成）

* [x] Phase 1：`field.rs`（`ZkvmField` trait + `Bn254ScalarField`，26 测试）+ `transcript.rs`（Blake2bVar，23 测试）

* [x] Phase 1.5.1：`pcs/mod.rs`（`MultilinearPoly` + `Pcs` trait，3 测试）

### 待实现

* [ ] **Phase 1.5.2**：`pcs/ipa.rs` — IPA over BN254（本计划核心）

* [ ] **Phase 1.5.3**：全量验证（`cargo test -p poker_zkvm` + clippy + release build）

### 现有 API 约束（来自 Phase 1.5.1）

`Pcs` trait 签名（[pcs/mod.rs:75-105](file:///Users/mac/projects/zchain/poker_zkvm/src/pcs/mod.rs#L75-L105)）：

```rust
pub trait Pcs: Send + Sync {
    type Commitment: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync;
    type Proof: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync;
    type Eval: Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync;
    fn commit(&self, poly: &MultilinearPoly) -> Result<Self::Commitment, ZkvmError>;
    fn open(&self, poly: &MultilinearPoly, point: &[Bn254ScalarField], transcript: &mut Transcript) -> Result<(Self::Proof, Self::Eval), ZkvmError>;
    fn verify(&self, commitment: &Self::Commitment, point: &[Bn254ScalarField], eval: &Self::Eval, proof: &Self::Proof, transcript: &mut Transcript) -> Result<bool, ZkvmError>;
}
```

`Bn254ScalarField` API（[field.rs:82-104](file:///Users/mac/projects/zchain/poker_zkvm/src/field.rs#L82-L104)）：

* `Bn254ScalarField(Fr)` newtype，提供 `from_fr` / `as_fr` / `into_fr` 转换

* 实现 `ZkvmField` trait（`add`/`mul`/`neg`/`inverse`/`zero`/`one`/`to_canonical_bytes` 等）

`Transcript` API（[transcript.rs:69-177](file:///Users/mac/projects/zchain/poker_zkvm/src/transcript.rs#L69-L177)）：

* `absorb(domain_tag: u8, data: &[u8])` — length-prefixing

* `absorb_field(domain_tag: u8, elem: &Bn254ScalarField)` — 32 bytes LE

* `challenge(domain_tag: u8) -> Bn254ScalarField` — 内部 counter 区分同 tag 多次调用

* 常量 `PCS_OPEN_DOMAIN_TAG = 0x14`

***

## 二、IPA 协议设计（基于 Bulletproofs 标准构造）

### 数学定义

**BN254 G1 曲线**：`y² = x³ + 3` over `Fq`（基域），标量域 `Fr`（== `Bn254ScalarField`）

**Setup（NUMS）**：

* `G_i = hash_to_curve(b"poker_zkvm_ipa_gen" || i_le)`，`i = 0..N-1`，`N = 2^max_n_vars`

* `Q = hash_to_curve(b"poker_zkvm_ipa_q" || 0_le)` — 独立 generator 用于内积承诺

* 所有 generator 满足 NUMS（无 DL 关系），通过 try-and-increment 派生

**Commit(poly)**：

* `C = ⟨a, G⟩ = Σ_i a_i · G_i`（Pedersen vector commitment，无盲化 — MVP transparent）

**Open(poly, point, transcript)**：

1. **预绑定**（spec L334）：`transcript.absorb(PCS_OPEN_TAG, commitment_bytes)` + `transcript.absorb_field(PCS_OPEN_TAG, point[j])` 对每个 `j`
2. **计算查询向量** `b[i] = eq(binary(i), point) = Π_{j=0..m-1} (bit_j(i) · point[j] + (1-bit_j(i)) · (1-point[j]))`
3. **计算求值** `v = ⟨a, b⟩ = Σ_i a_i · b_i`
4. **构造 P**：`P = C + v · Q`（将内积 v 绑入承诺）
5. **log(N) 轮折叠**（`k = 0..m-1`）：

   * 切分 `a = (a_L, a_R)`，`b = (b_L, b_R)`，`G = (G_L, G_R)`（各半）

   * `L_k = ⟨a_R, G_L⟩ + ⟨a_R, b_L⟩ · Q`

   * `R_k = ⟨a_L, G_R⟩ + ⟨a_L, b_R⟩ · Q`

   * `transcript.absorb(PCS_OPEN_TAG, L_k_bytes)` + `transcript.absorb(PCS_OPEN_TAG, R_k_bytes)` + `transcript.absorb(PCS_OPEN_TAG, k_le_bytes)`

   * `r_k = transcript.challenge(PCS_OPEN_TAG)`

   * `r_k_inv = r_k.inverse()`（挑战为 0 概率 ≈ 2^-254，出错返回 `Other`）

   * 折叠：`a' = a_L + r_k · a_R`，`b' = b_L + r_k_inv · b_R`，`G' = G_L + r_k_inv · G_R`

   * `P' = P + r_k · L_k + r_k_inv · R_k`
6. **最终**：`a`、`b`、`G` 各退化为单元素 `a_final`、`b_final`、`G_final`
7. **返回**：`IpaProof { l_vec, r_vec, a_final }` + `IpaEval(v)`

**Verify(commitment, point, eval, proof, transcript)**：

1. **预绑定**（与 open 相同 absorb 顺序）
2. **计算查询向量** `b`（verifier 独立计算）
3. **构造 P**：`P = C + eval.value · Q`
4. **log(N) 轮重算 challenge 与折叠**（与 open 相同 absorb 顺序）：

   * 吸收 `L_k`/`R_k`/`k` → 派生 `r_k`、`r_k_inv`

   * 折叠 `b' = b_L + r_k_inv · b_R`

   * 折叠 `P' = P + r_k · L_k + r_k_inv · R_k`
5. **闭式计算 G\_final**（避免逐轮点折叠的 O(N log N) 开销）：

   * `G_final = Σ_i (Π_{k=0..m-1} r_k_inv^{bit_{m-1-k}(i)}) · G_i` — 单次 MSM，O(N)
6. **最终校验**：`P_final == a_final · G_final + (a_final * b_final) · Q`

   * 等价于 `P_final == a_final · (G_final + b_final · Q)`

   * 若成立返回 `true`，否则 `false`

### 安全性论证

* **binding**：`G_i` 与 `Q` 满足 NUMS（无 DL 关系），prover 无法找到不同 `a'` 使 `⟨a', G⟩ == ⟨a, G⟩`

* **challenge 绑定**：`point` 与 `commitment` 在 open 前吸收到 transcript，challenge 依赖二者，防 proof 复用

* **soundness**：prover 伪造 `a_final'` 使等式成立等价于求解 DLP（`a_final' · (G_final + b_final · Q) == P_final`），不可行

***

## 三、实现步骤（TDD 严格模式）

### Step 1：RED — 编写失败测试（先写测试）

修改文件：[poker\_zkvm/src/pcs/ipa.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/pcs/ipa.rs)

编写以下 16 个单元测试（在 `#[cfg(test)] mod tests` 内），全部应编译失败（因 IPA 尚未实现）：

| #  | 测试名                                              | 验证内容                                         |
| -- | ------------------------------------------------ | -------------------------------------------- |
| 1  | `test_hash_to_curve_deterministic`               | 相同输入产生相同 G1 点                                |
| 2  | `test_hash_to_curve_on_curve`                    | 点满足 `y² = x³ + 3`                            |
| 3  | `test_hash_to_curve_different_index`             | 不同 `i` 产生不同点                                 |
| 4  | `test_compute_query_vector_correctness`          | `b[i] = eq(binary(i), point)` 小例验证           |
| 5  | `test_inner_product_correctness`                 | `⟨a, b⟩` 计算正确                                |
| 6  | `test_ipa_commit_simple`                         | commit 返回非 identity 点                        |
| 7  | `test_ipa_commit_deterministic`                  | 相同 poly 产生相同 commitment                      |
| 8  | `test_ipa_open_verify_completeness`              | 完整闭环：commit→open→verify 返回 true（num\_vars=3） |
| 9  | `test_ipa_completeness_multiple_vars`            | num\_vars ∈ {0,1,2,4,8} 全部 completeness 通过   |
| 10 | `test_ipa_soundness_tampered_eval`               | 篡改 eval.value → verify 返回 false              |
| 11 | `test_ipa_soundness_tampered_a_final`            | 篡改 proof.a\_final → verify 返回 false          |
| 12 | `test_ipa_soundness_tampered_commitment`         | 篡改 commitment → verify 返回 false              |
| 13 | `test_ipa_soundness_tampered_l_vec`              | 篡改 proof.l\_vec\[0] → verify 返回 false        |
| 14 | `test_ipa_soundness_reuse_proof_different_point` | 同 proof 用不同 point → verify 返回 false          |
| 15 | `test_ipa_rejects_poly_too_large`                | `poly.num_vars > max_n_vars` 返回 `Err`        |
| 16 | `test_ipa_rejects_point_length_mismatch`         | `point.len() != poly.num_vars` 返回 `Err`      |

**proptest**（2 个）：

* `prop_ipa_completeness` — 随机 poly（num\_vars ≤ 6）+ 随机 point，commit/open/verify 返回 true

* `prop_ipa_soundness_eval` — 随机篡改 eval 使 verify 返回 false

### Step 2：GREEN — 实现 IPA 使所有测试通过

修改文件：[poker\_zkvm/src/pcs/ipa.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/pcs/ipa.rs)

实现内容（按依赖顺序）：

#### 2.1 导入与常量

```rust
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{AdditiveGroup, Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::error::ZkvmError;
use crate::field::{Bn254ScalarField, ZkvmField};
use crate::pcs::{MultilinearPoly, Pcs};
use crate::transcript::{Transcript, PCS_OPEN_DOMAIN_TAG};
```

#### 2.2 类型定义

```rust
/// IPA 承诺（G1 仿射点）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaCommitment(pub G1Affine);

/// IPA 证明（log(N) 轮的 L/R 点 + 最终标量 a_final）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaProof {
    pub l_vec: Vec<G1Affine>,
    pub r_vec: Vec<G1Affine>,
    pub a_final: Bn254ScalarField,
}

/// IPA 求值（多线性多项式在 point 处的值）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaEval(pub Bn254ScalarField);
```

#### 2.3 `hash_to_curve` — NUMS 派生

```rust
/// NUMS hash-to-curve：try-and-increment（BN254 G1: y² = x³ + 3）。
///
/// 算法：`x = Fq::from_le_bytes_mod_order(Blake2b(domain || index_le || counter_le))`，
/// 检查 `x³+3` 是否为二次剩余，是则取 `y = sqrt(x³+3)` 构造点。
fn hash_to_curve(domain: &[u8], index: u32) -> G1Affine { ... }
```

#### 2.4 辅助函数

* `field_to_fr(f: &Bn254ScalarField) -> Fr` — 解包 newtype

* `point_to_bytes(p: &G1Affine) -> Vec<u8>` — `CanonicalSerialize::serialize_compressed`

* `compute_query_vector(point: &[Bn254ScalarField]) -> Vec<Bn254ScalarField>` — `b[i] = Π_j (bit·r + (1-bit)·(1-r))`

* `inner_product(a: &[Bn254ScalarField], b: &[Bn254ScalarField]) -> Bn254ScalarField`

* `msm(scalars: &[Fr], bases: &[G1Affine]) -> G1Projective` — 使用 `VariableBaseMSM::msm`，回退到手动循环

* `compute_g_final(g: &[G1Affine], challenges_inv: &[Bn254ScalarField]) -> G1Projective` — 闭式 MSM

#### 2.5 `IpaPcs` 结构

```rust
/// IPA over BN254 PCS 实现。
pub struct IpaPcs {
    generators: Vec<G1Affine>,   // G_0..G_{N-1}，N = 2^max_n_vars
    q_generator: G1Affine,       // 独立 NUMS generator 用于内积承诺
    max_n_vars: usize,
}

impl IpaPcs {
    /// 构造：预计算 generators。
    pub fn new(max_n_vars: usize) -> Result<Self, ZkvmError> { ... }
    pub fn max_n_vars(&self) -> usize { self.max_n_vars }
}
```

#### 2.6 `Pcs` trait 实现

* `commit`：校验 `poly.num_vars <= max_n_vars`，MSM 计算 `C = ⟨a, G⟩`

* `open`：预绑定 → 计算 b → 计算 v → log(N) 轮折叠 → 返回 proof + eval

* `verify`：预绑定 → 重算 b → 重算 challenges → 闭式算 G\_final → 校验 `P_final == a_final·G_final + (a_final·b_final)·Q`

### Step 3：REFACTOR — 提取公共逻辑

* 将 `compute_query_vector` / `inner_product` / `msm` 提取为模块级函数（已在 2.4 完成）

* 若 `VariableBaseMSM::msm` API 不可用，回退到手动循环并记录在 alternatives.md

* 添加 doc comment（中文，解释数学与安全特性）

### Step 4：Phase 1.5.3 — 全量验证

* `cargo test -p poker_zkvm pcs::` — IPA + PCS trait 测试全通过

* `cargo test -p poker_zkvm` — 整个 crate 所有测试通过（field + transcript + pcs）

* `cargo clippy -p poker_zkvm -- -D warnings` — 无 warning

* `cargo build -p poker_zkvm --release` — release 构建通过

* `cargo build --workspace` — workspace 整体编译通过

***

## 四、关键设计决策（已确定）

| #  | 决策                   | 选择                                                   | 理由                                                      |
| -- | -------------------- | ---------------------------------------------------- | ------------------------------------------------------- |
| 1  | hash-to-curve 方法     | **try-and-increment**                                | 简单、NUMS 性质保持；ark-ec SWU 需要额外 feature flag 且 BN254 支持不完整 |
| 2  | Q generator 派生       | **`hash_to_curve(b"poker_zkvm_ipa_q", 0)`**          | 独立 domain tag 与 G\_i 明确分离                               |
| 3  | commitment 编码        | **compressed 33 bytes**                              | 节省 proof 体积；arkworks `CanonicalSerialize` 原生支持          |
| 4  | G\_final 计算          | **闭式 MSM**（O(N)）                                     | 比逐轮点折叠 O(N log N) 快；verifier 已是 O(N) 无可避免               |
| 5  | MSM 实现               | **`VariableBaseMSM::msm`**，手动循环回退                    | 生产性能；回退保 TDD 可继续                                        |
| 6  | round\_index 吸收      | **显式 absorb** **`k.to_le_bytes()`**                  | spec L333 字面要求，虽然 Transcript 内部 counter 已区分             |
| 7  | max\_n\_vars 上限      | **24**（N=16M）                                        | 防 OOM；超过返回 `Other` 错误                                   |
| 8  | 预计算 generators       | **eager（构造时）**                                       | 简单；测试用小 N；生产可改 lazy                                     |
| 9  | point 编码到 transcript | **每个分量** **`absorb_field`（32 bytes LE）**             | 与 Phase 1 transcript 设计一致                               |
| 10 | num\_vars=0 处理       | **支持**（0 轮 IPA，proof 为空 vec + a\_final=a\[0]，b=\[1]） | 边界完备性                                                   |

***

## 五、备选方案（实现时追加到 `docs/alternatives.md`）

### A. ark-ec SWU hash-to-curve（未选）

* **描述**：使用 `ark_ec::hashing::curve_maps::swu::SWUMap` 实现 RFC 9380 hash-to-curve

* **未选理由**：arkworks 0.6 BN254 SWU 支持需要额外 feature flag（`hash_to_curve`）；try-and-increment 已满足 NUMS；SWU 复杂度高且对 BN254 的 A=0 短 Weierstrass 曲线需特殊处理（需 iso\_map）

* **何时考虑**：未来若需 RFC 9380 合规（标准化互操作）

### B. 逐轮点折叠计算 G\_final（未选）

* **描述**：verify 阶段每轮显式折叠 `G' = G_L + r_inv · G_R`，与 prover 同步

* **未选理由**：O(N log N) 比 MSM 闭式 O(N) 慢；且每轮需点加法（Pippenger 优化无法应用）

* **何时考虑**：若需与 prover 严格对称实现便于审计

### C. 添加 H generator 用于盲化（未选）

* **描述**：commitment `C = ⟨a, G⟩ + r·H`，r 为随机盲化因子

* **未选理由**：spec L39 明确「MVP transparent，witness 不盲化」（spec L39）；ZK 版本留作 v2

* **何时考虑**：v2 真正 ZK 版本

### D. ark-poly-commit::IPA（未选，已在 alternatives.md 记录）

* **未选理由**：不支持自定义 NUMS generators；transcript 不兼容 spec

***

## 六、假设与前置条件

1. **arkworks 0.6 API 假设**（实现时验证）：

   * `G1Projective::new(x: Fq, y: Fq, z: Fq)` — 构造点

   * `Fq::from_le_bytes_mod_order(&[u8]) -> Fq` — hash → 基域元素

   * `Fq::sqrt() -> Option<Fq>` — 二次剩余检测（需 `Field` trait in scope）

   * `G1Projective * Fr` — 标量乘（`std::ops::Mul`）

   * `G1Projective + G1Projective` — 点加（`std::ops::Add`）

   * `G1Projective::into_affine() -> G1Affine` / `G1Affine::into_group() -> G1Projective`

   * `CanonicalSerialize::serialize_compressed(&mut Vec<u8>)` for `G1Affine`

   * `VariableBaseMSM::msm(&[G1Affine], &[Fr]) -> Result<G1Projective, _>`

2. **若 API 不可用的回退**：

   * `G1Projective::new` 不存在 → 用 `ark_ec::short_weierstrass::Projective::<Config>::new(x, y, z)`

   * `Fq::sqrt` 不可用 → 手动 Tonelli-Shanks（`Fq` 实现 `SquareRootField`）

   * `VariableBaseMSM::msm` 签名不符 → 手动循环 `Σ s_i · G_i`

   * 上述回退记录在 `docs/alternatives.md` 的"实现期发现"小节

3. **Transcript 兼容性**：`Transcript::absorb`/`challenge`/`absorb_field` 已在 Phase 1 实现，API 稳定

4. **错误处理**：所有失败路径返回 `ZkvmError`（使用既有 variants：`InvalidZkProofFormat`、`PcsVerificationFailed`、`Other`）

***

## 七、验证步骤（Definition of Done）

### Phase 1.5.2 完成标准

* [ ] `pcs/ipa.rs` 实现完整（IpaPcs + IpaCommitment + IpaProof + IpaEval + Pcs impl）

* [ ] 16 单元测试 + 2 proptest 全部通过

* [ ] soundness 负例 5 项全部 verify 返回 false

* [ ] completeness 覆盖 num\_vars ∈ {0,1,2,3,4,8}

### Phase 1.5.3 完成标准

* [ ] `cargo test -p poker_zkvm` 全通过（field 26 + transcript 23 + pcs 3 + ipa 18 = 70 测试）

* [ ] `cargo clippy -p poker_zkvm -- -D warnings` 无 warning

* [ ] `cargo build -p poker_zkvm --release` 通过

* [ ] `cargo build --workspace` 通过（poker\_l1 不受影响）

### 后续衔接

* Phase 1.5 完成后进入 **Phase 2**：ELF 校验器（`compiler/elf_validator.rs`）

* IPA 模块将在 Phase 4（Hypernova fold）被 `cross-language claim` 调用

***

## 八、风险与缓解

| 风险                               | 概率 | 缓解                                             |
| -------------------------------- | -- | ---------------------------------------------- |
| arkworks 0.6 API 与假设不符           | 中  | Step 2 实现时先写最小 smoke test 验证 API；回退方案已在假设 2 列出 |
| `Fq::sqrt` 性能差                   | 低  | 测试用小 N；生产预计算缓存                                 |
| IPA 协议实现有 bug 导致 completeness 失败 | 中  | TDD 严格模式 — RED 测试先写，GREEN 阶段逐个测试通过             |
| Transcript absorb 顺序与 spec 不一致   | 低  | 严格按 spec L333-334 顺序；verify 阶段重放完全相同顺序         |
| soundness 测试误通过（verify 返回 true）  | 中  | 每个篡改字段单独测试；proptest 随机篡改验证                     |

***

## 九、执行顺序（TaskCreate 跟踪）

1. **Task A**：RED — 在 `pcs/ipa.rs` 编写 16 单元测试 + 2 proptest（编译失败）
2. **Task B**：GREEN-A — 实现 `hash_to_curve` + 辅助函数（使测试 1-5 通过）
3. **Task C**：GREEN-B — 实现 `IpaPcs::new` + `commit`（使测试 6-7 通过）
4. **Task D**：GREEN-C — 实现 `open` + `verify`（使测试 8-9 通过）
5. **Task E**：GREEN-D — 验证 soundness 测试 10-14 通过（应自动通过，无需额外代码）
6. **Task F**：GREEN-E — 验证边界测试 15-16 通过
7. **Task G**：REFACTOR — 提取公共逻辑、补 doc comment、追加 alternatives.md
8. **Task H**：Phase 1.5.3 — `cargo test` + `clippy` + `release build` + workspace build 全通过

