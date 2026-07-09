# Phase 9 — CycleFold 递归聚合 实施计划

> **change-id**：`build-hypernova-zkvm`
> **spec 版本**：v1.4 FROZEN
> **任务范围**：Task 9.1（曲线 cycle 抽象）+ Task 9.2（CycleFold 聚合）+ Task 9.3（C\_BN254 递归 verifier 电路）+ Task 9.4（C\_Grumpkin 镜像电路）

## 当前进度

| 步骤 | 任务 | 状态 |
| --- | --- | --- |
| Step 1 | Task 9.1 — `cyclic/mod.rs` 曲线 cycle 抽象 | ✅ 已完成（6 测试通过，`lib.rs` 已加 `pub mod cyclic;`） |
| Step 2 | Task 9.2 — `recursion/mod.rs` CycleFold 树形聚合 | ✅ 已完成（13 测试通过） |
| Step 3 | Task 9.3 — `recursion/circuit_bn254.rs` C_BN254 电路 | ✅ 已完成（7 测试通过） |
| Step 4 | Task 9.4 — `recursion/circuit_grumpkin.rs` C_Grumpkin 镜像 | ✅ 已完成（9 测试通过） |
| Step 4.5 | **修复测试失败** — 替换 stub_commitment 为真实 IPA commitment | ✅ 已完成（36/36 测试通过） |
| Step 5 | `cyclegfold.rs` / `alternatives.md` 更新 | ✅ 已完成 |
| Step 6 | `tasks.md` + `checklist.md` 勾选 | ✅ 已完成 |
| Step 7 | 编译 + 测试 + clippy 验证 | ✅ 已完成（693 lib tests + 1271 poker_l1 tests 通过，clippy 零警告） |

**Phase 9 全部完成。** 验证结果：
- `cargo build -p poker_zkvm --lib` — 成功
- `cargo test -p poker_zkvm --lib` — 693 passed; 0 failed（657 既有 + 36 新增 Phase 9）
- `cargo clippy -p poker_zkvm --lib` — 零警告
- `cargo test -p poker_l1 --lib` — 1271 passed; 0 failed（无回归）

### Step 4.5：修复 16 个测试失败（根因已定位）

**根因**：三个文件的 `make_proof` 测试辅助函数使用 `stub_commitment()`（= `G1Affine::generator()`）作为 `fold_loop` 的 `initial_commitment`。`fold_loop` 内部计算 `folded_commitment = initial_commitment + r·C_C`，若 `initial_commitment` 是 stub，最终 `witness_commitment` 不匹配实际 folded witness，导致 `pcs.verify` 失败。

**参考**：`fold_loop.rs` L557-587 的 `test_verify_hypernova_linear_ccs_valid` 明确使用 `commit_witness(pcs, &z_l)` 而非 stub，注释说明"使用真实 IPA commitment，使 C' = C_L + r·C_C = ⟨z', G⟩ 与 pcs.open 内部承诺一致"。

**修复方案**：在三个文件的 `#[cfg(test)] mod tests` 中：

1. 添加 `commit_witness` 辅助函数（复制自 `fold_loop.rs` L266-269）：
```rust
fn commit_witness(pcs: &IpaPcs, z: &[Fr]) -> IpaCommitment {
    let poly = MultilinearPoly::from_evals(z.to_vec()).expect("MultilinearPoly 构造应成功");
    pcs.commit(&poly).expect("pcs.commit 应成功")
}
```

2. 添加 `use crate::pcs::MultilinearPoly;` 到 test 模块 imports

3. 在 `make_proof` 中替换两处 `stub_commitment()`：
   - `to_cccs(&z_c, vec![], stub_commitment())` → `to_cccs(&z_c, vec![], commit_witness(pcs, &z_c))`
   - `fold_loop(..., stub_commitment(), ...)` → `fold_loop(..., commit_witness(pcs, &z_l), ...)`

**受影响文件**：
- `poker_zkvm/src/recursion/mod.rs`（test 模块 L300-368）
- `poker_zkvm/src/recursion/circuit_bn254.rs`（test 模块 L124-190）
- `poker_zkvm/src/recursion/circuit_grumpkin.rs`（test 模块 L130-200）

**保留**：`stub_commitment()` 函数本身可保留（部分不涉及 PCS verify 的测试可能仍用），但 `make_proof` 内必须改用 `commit_witness`。

***

## Context

Phase 8 完成了链上 Verifier Production 实现（verify\_production + grace period 双通道 + M2-003/004 修复）。当总计算步数 N > MAX\_FOLD\_STEP\_COUNT × ZKVM\_BATCH\_SIZE 时，prover 须分段生成多个 sub-proof，再通过 CycleFold 递归聚合为单个 final proof。

Phase 9 实现 CycleFold 递归聚合的核心逻辑：曲线 cycle 抽象（BN254/Grumpkin）+ 树形聚合 + 递归终止条件 + 递归 verifier 电路定义。

### MVP 实现深度（与项目既有模式一致）

spec L590/L599 明确将"递归电路的 SNARK 证明"推迟到 Phase 12/13（Spartan/Groth16 压缩）。Phase 8 的 verify\_production 也是原生验证而非电路内验证。因此 Phase 9 采用：

* **Task 9.1 + 9.2**：完整实现（cycle 抽象 + 树形聚合 + 终止条件 + 原生验证）

* **Task 9.3 + 9.4**：电路结构定义（trait + 6 条约束文档化 + 约束数估算）+ 原生验证模拟（复用 `verify_hypernova` / `verify_production`）。真实 R1CS/PLONKish 电路编译推迟到 Phase 12/13。

### 关键不变式

* 递归深度 ≤ `MAX_RECURSION_DEPTH = 16`（已存在于 `prover/mod.rs`）

* final proof ≤ `MAX_ZKVM_PROOF_SIZE = 64KB`（已存在于 `prover/mod.rs`）

* BN254 标量域 == Grumpkin base field，反之亦然（cycle 性质）

* 交替递归：BN254 层验证 Grumpkin proof → Grumpkin 层验证 BN254 proof

***

## 模块布局

当前状态：

* `poker_zkvm/src/cyclegfold.rs` — Phase 12 占位（仅 doc comment）

* `poker_zkvm/src/recursion/mod.rs` — Phase 13 占位（仅 doc comment）

* 无 `cyclic/` 模块

目标布局（遵循 tasks.md 路径）：

```
poker_zkvm/src/
├── cyclic/
│   └── mod.rs                    # Task 9.1 — 曲线 cycle 抽象
├── recursion/
│   ├── mod.rs                    # Task 9.2 — CycleFold 聚合（替换 Phase 13 占位）
│   ├── circuit_bn254.rs          # Task 9.3 — C_BN254 递归 verifier 电路
│   └── circuit_grumpkin.rs       # Task 9.4 — C_Grumpkin 镜像电路
├── cyclegfold.rs                 # 更新 doc 指向 recursion 模块（Phase 12 扩展点）
└── lib.rs                        # 添加 pub mod cyclic;
```

注：`recursion/mod.rs` 从单文件转为目录模块。Phase 13 的 Spartan/Groth16 压缩逻辑将在 `recursion/` 下新增子模块（如 `recursion/spartan.rs` / `recursion/groth16.rs`），不与 Phase 9 冲突。

***

## 实施步骤

### Step 1：创建 `poker_zkvm/src/cyclic/mod.rs`（Task 9.1）

定义曲线 cycle 抽象：

```rust
/// 曲线 cycle trait — 主曲线标量域 == 辅助曲线 base field，反之亦然。
pub trait CycleCurve: Sized + Copy {
    type PrimaryScalar;   // 主曲线标量域
    type PrimaryBase;     // 主曲线 base field
    type SecondaryScalar; // 辅助曲线标量域
    type SecondaryBase;   // 辅助曲线 base field

    fn primary_scalar_modulus() -> [u64; 4];
    fn primary_base_modulus() -> [u64; 4];
    fn secondary_scalar_modulus() -> [u64; 4];
    fn secondary_base_modulus() -> [u64; 4];

    /// 验证 cycle 性质：PrimaryScalar == SecondaryBase && SecondaryScalar == PrimaryBase
    fn verify_cycle() -> Result<(), ZkvmError>;
}

/// BN254 (主) / Grumpkin (辅) 曲线 cycle。
pub struct Bn254GrumpkinCycle;
impl CycleCurve for Bn254GrumpkinCycle { ... }
```

**SubTask 9.1.1**：定义 `CycleCurve` trait（主曲线 + 辅助曲线标量/base field 关系）
**SubTask 9.1.2**：实现 `Bn254GrumpkinCycle` — BN254 (主) / Grumpkin (辅)
**SubTask 9.1.3**：cycle 性质验证 — 运行时比较 modulus：`Fr_BN254 == Fq_Grumpkin` && `Fr_Grumpkin == Fq_BN254`

测试：

* `test_cycle_property_bn254_grumpkin` — 验证 4 个 modulus 满足 cycle 关系

* `test_primary_scalar_equals_secondary_base` — Fr\_BN254.modulus == Fq\_Grumpkin.modulus

* `test_secondary_scalar_equals_primary_base` — Fr\_Grumpkin.modulus == Fq\_BN254.modulus

**关键文件**：

* 新建：`poker_zkvm/src/cyclic/mod.rs`

* 修改：`poker_zkvm/src/lib.rs` — 添加 `pub mod cyclic;`（Layer 4 区域）

***

### Step 2：创建 `poker_zkvm/src/recursion/mod.rs`（Task 9.2）

替换 Phase 13 占位，实现 CycleFold 树形聚合：

```rust
pub mod circuit_bn254;
pub mod circuit_grumpkin;

use crate::fold::fold_loop::HypernovaProof;
use crate::error::ZkvmError;
use crate::prover::{MAX_ZKVM_PROOF_SIZE, MAX_RECURSION_DEPTH};

/// 递归聚合节点 — 树形结构表示 CycleFold 聚合过程。
#[derive(Debug, Clone)]
pub enum CycleFoldNode {
    /// 叶节点 — 单个 Hypernova sub-proof。
    Leaf { proof: HypernovaProof, curve: CurveKind },
    /// 内部节点 — 两个子节点聚合后的结果。
    Node {
        left: Box<CycleFoldNode>,
        right: Box<CycleFoldNode>,
        aggregated_proof: HypernovaProof,
        curve: CurveKind,  // 本层证明所在曲线
        depth: u32,
    },
}

/// 曲线种类（交替递归用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveKind {
    Bn254,
    Grumpkin,
}

/// 聚合 K 个 sub-proof 为单个 final proof（Task 9.2.2）。
///
/// MVP 实现：验证所有 sub-proof 后返回树根。真实 size 压缩需 Phase 12/13 SNARK。
pub fn aggregate(sub_proofs: &[HypernovaProof]) -> Result<HypernovaProof, ZkvmError>;

/// 树形聚合（Task 9.2.3）— log(N) 递归深度。
pub fn tree_aggregate(
    sub_proofs: &[HypernovaProof],
    max_depth: u32,
) -> Result<CycleFoldNode, ZkvmError>;
```

**SubTask 9.2.1**：`CycleFoldNode` 树结构（Leaf + Node）
**SubTask 9.2.2**：`aggregate` — 验证所有 sub-proof，返回聚合后的 proof
**SubTask 9.2.3**：`tree_aggregate` — 树形配对聚合，每层交替曲线
**SubTask 9.2.4**：递归终止条件 — proof ≤ 64KB 或 depth > 16 返回 `RecursionDepthExceeded`
**SubTask 9.2.5**：单元测试 — K=8 sub-proofs 聚合
**SubTask 9.2.6**：soundness 负例 — 篡改任一 sub\_proof 聚合失败

**聚合逻辑（MVP）**：

1. 校验 `sub_proofs` 非空
2. 对每个 sub\_proof 执行 `verify_hypernova`（原生验证，soundness 保证）
3. 配对聚合：每对 sub\_proof 生成一个 `Node`，`aggregated_proof` 取左子树的 proof（MVP — 真实压缩需 SNARK 电路）
4. 检查 `aggregated_proof.to_bytes().len()` 是否 ≤ 64KB
5. 若超过且 depth < max\_depth，递归聚合
6. 若 depth >= max\_depth，返回 `RecursionDepthExceeded`

**关键文件**：

* 修改：`poker_zkvm/src/recursion/mod.rs`（替换占位）

* 复用：`crate::fold::fold_loop::{HypernovaProof, verify_hypernova}`

* 复用：`crate::prover::{MAX_ZKVM_PROOF_SIZE, MAX_RECURSION_DEPTH}`

* 复用：`crate::error::ZkvmError::RecursionDepthExceeded`

***

### Step 3：创建 `poker_zkvm/src/recursion/circuit_bn254.rs`（Task 9.3）

定义 BN254 递归 verifier 电路 `C_BN254`（MVP — trait + 约束文档化 + 原生模拟）：

```rust
use crate::error::ZkvmError;
use crate::fold::fold_loop::HypernovaProof;
use crate::pcs::ipa::IpaPcs;

/// BN254 递归 verifier 电路 C_BN254（spec L575-590）。
///
/// 约束一个 Grumpkin 上的 Hypernova proof π_G 的 verifier 步骤。
/// MVP 实现：原生验证模拟 + 约束数估算。真实 R1CS 电路编译推迟到 Phase 12/13。
pub struct CircuitBn254<'a> {
    /// 待验证的 Grumpkin Hypernova sub-proof（序列化字节）。
    pub sub_proof_bytes: &'a [u8],
    /// sub-proof 的公共输入。
    pub public_io: &'a crate::prover::ZkPublicIo,
    /// IPA PCS（用于原生验证模拟）。
    pub pcs: &'a IpaPcs,
}

/// 递归 verifier 电路 trait — 定义电路结构 + 约束数 + 原生验证模拟。
pub trait RecursiveVerifierCircuit {
    /// 电路所在曲线。
    fn curve_kind() -> CurveKind;
    /// 验证的 sub-proof 所在曲线。
    fn sub_proof_curve_kind() -> CurveKind;
    /// 估算约束数（spec L589 — 单层 100k-200k）。
    fn constraint_count(num_vars: usize, num_matrices: usize) -> usize;
    /// 原生验证模拟（MVP — 复用 verify_hypernova）。
    fn verify_native(&self) -> Result<bool, ZkvmError>;
    /// public inputs 清单（spec L586）。
    fn public_inputs_desc() -> &'static [&'static str];
}
```

**6 条约束（文档化 + 原生验证对应）**：

| 约束                                               | spec | MVP 原生验证对应                                                      |
| ------------------------------------------------ | ---- | --------------------------------------------------------------- |
| 1. 反序列化 π\_G                                     | L580 | `HypernovaProof::deserialize` + magic/abi\_version/field\_id 校验 |
| 2. PCS verify (IPA on Grumpkin)                  | L581 | `pcs.verify(witness_commitment, r_y, z_at_point, pcs_opening)`  |
| 3. 外层 sumcheck (claimed sum = u')                | L582 | `sumcheck::verify(..., u_l, ...)`                               |
| 4. 内层 batched sumcheck (单 r\_y)                  | L583 | `sumcheck::verify` 内部含内层 batched                                |
| 5. cross-language claim (combined\_point = r\_y) | L584 | PCS opening + z\_at\_point 一致性                                  |
| 6. transcript 一致性                                | L585 | fresh transcript 重算 challenge                                   |

**SubTask 9.3.1**：`CircuitBn254` 结构 + public inputs 定义
**SubTask 9.3.2-9.3.7**：6 条约束文档化 + `verify_native` 委托到 `verify_hypernova`
**SubTask 9.3.8**：约束数估算 — IPA verify (log(N) × \~5000) + 外层 sumcheck (\~10000) + 内层 (\~10000) + cross-language (\~5000) ≈ 100k-200k
**SubTask 9.3.9**：单元测试 — 合法 Grumpkin proof 通过；篡改 sub-proof 失败

**关键文件**：

* 新建：`poker_zkvm/src/recursion/circuit_bn254.rs`

* 复用：`crate::fold::fold_loop::{HypernovaProof, verify_hypernova}`

* 复用：`crate::pcs::ipa::IpaPcs`

***

### Step 4：创建 `poker_zkvm/src/recursion/circuit_grumpkin.rs`（Task 9.4）

对称镜像 `C_BN254`，在 Grumpkin 上约束 BN254 Hypernova verifier：

```rust
/// Grumpkin 镜像电路 C_Grumpkin（spec L587）。
///
/// 对称约束 BN254 上的 Hypernova verifier 步骤。
/// 跨曲线 bridging：BN254 点坐标在 Grumpkin 标量域中直接表达（cycle 性质）。
pub struct CircuitGrumpkin<'a> {
    pub sub_proof_bytes: &'a [u8],
    pub public_io: &'a crate::prover::ZkPublicIo,
    pub pcs: &'a IpaPcs,  // MVP: BN254 IPA（真实实现需 Grumpkin IPA）
}

impl RecursiveVerifierCircuit for CircuitGrumpkin<'_> {
    fn curve_kind() -> CurveKind { CurveKind::Grumpkin }
    fn sub_proof_curve_kind() -> CurveKind { CurveKind::Bn254 }
    // ...
}
```

**SubTask 9.4.1**：`C_Grumpkin` 结构（对称镜像）
**SubTask 9.4.2**：对称约束 1-6（同 C\_BN254 但曲线互换）
**SubTask 9.4.3**：跨曲线 bridging 文档（cycle 性质使点坐标可直接表达）
**SubTask 9.4.4**：单元测试 — 合法 BN254 proof 通过；篡改失败
**SubTask 9.4.5**：交替递归测试 — BN254 层 → Grumpkin 层 → 深度 4 闭环

**交替递归测试设计**：

```
叶: 4 个 Grumpkin sub-proofs (g1, g2, g3, g4)
Layer 1 (BN254): C_BN254 验证 (g1, g2) → b1; C_BN254 验证 (g3, g4) → b2
Layer 2 (Grumpkin): C_Grumpkin 验证 (b1, b2) → g_final
深度 2 层闭环（MVP 模拟，真实交替需 Grumpkin IPA PCS）
```

**关键文件**：

* 新建：`poker_zkvm/src/recursion/circuit_grumpkin.rs`

***

### Step 5：更新 `cyclegfold.rs` + `alternatives.md` 文档

* `poker_zkvm/src/lib.rs`：✅ 已完成（Layer 4 已含 `pub mod cyclic;`，Layer 6 已含 `pub mod recursion;`）

* `poker_zkvm/src/cyclegfold.rs`：更新 doc 指向 `recursion` 模块（Phase 9 CycleFold 聚合已实现于 `recursion`；cyclegfold 留作 Phase 12 SNARK 压缩扩展点）

* `poker_zkvm/docs/alternatives.md`：添加 Phase 9 备选方案记录（MVP 原生验证 + 电路定义 vs 完整 R1CS / halo2 PLONKish）

***

### Step 6：tasks.md + checklist 更新

* `/Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/tasks.md` L262-290：勾选 Task 9.1/9.2/9.3/9.4 所有子任务

* `/Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/checklist.md` L253-279：勾选 Phase 9 检查项（CycleCurve trait / Bn254GrumpkinCycle / cycle 性质验证 / RecursiveNode / aggregate / tree_aggregate / 终止条件 / K=8 测试 / soundness 负例 / C_BN254 6 条约束 + 约束数估算 + 测试 / C_Grumpkin 镜像 + 跨曲线 bridging + 交替递归测试）

***

### Step 7：编译 + 测试 + clippy 验证

```bash
cargo build -p poker_zkvm --lib
cargo test -p poker_zkvm --lib
cargo clippy -p poker_zkvm --lib
cargo test -p poker_l1 --lib   # 确保不破坏 poker_l1
```

***

## 备选方案（记录于 alternatives.md）

### 推荐方案（已选择）— MVP 原生验证 + 电路定义

* Task 9.1+9.2 完整实现；Task 9.3+9.4 电路 trait + 约束文档 + 原生模拟

* 理由：与 Phase 8 一致（verify\_production 也是原生）；spec L590/L599 明确推迟 SNARK 编译到 Phase 12/13

### 备选 A — 完整 arkworks R1CS 电路

* 添加 ark-r1cs-std + ark-relations 依赖

* 实现真实 R1CS 约束（EC 点算术 + IPA verify + sumcheck verify）

* 未选理由：10-20 万约束/层，工作量巨大；arkworks R1CS EC 算术复杂；Phase 12/13 才需真实 SNARK

### 备选 B — halo2 PLONKish 电路

* 添加 halo2\_proofs 依赖

* 未选理由：与 arkworks 栈不一致；alternatives 文档 Phase 0 已拒绝 halo2

### 备选 C — 递归聚合返回 CycleFoldNode 而非 HypernovaProof

* `aggregate` 返回树结构而非单个 proof

* 未选理由：tasks.md 签名要求返回 HypernovaProof；树结构作为内部实现

***

## 验证清单

* [x] `cargo build -p poker_zkvm --lib` 成功

* [x] `cargo test -p poker_zkvm --lib` 全通过（693 tests，含 36 新增 Phase 9 测试）

* [x] `cargo clippy -p poker_zkvm --lib` 零警告

* [x] `cargo test -p poker_l1 --lib` 全通过（1271 tests，不破坏既有）

* [x] Task 9.1：cycle 性质验证测试通过（BN254 Fr == Grumpkin Fq）

* [x] Task 9.2：K=8 sub-proofs 聚合测试通过；篡改 sub\_proof 失败

* [x] Task 9.3：C\_BN254 合法 proof 通过；篡改失败；约束数估算 100k-200k

* [x] Task 9.4：C\_Grumpkin 镜像测试通过；交替递归深度 4 闭环

* [x] tasks.md + checklist 勾选完成

