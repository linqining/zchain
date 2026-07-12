# Phase L 收尾计划：形式化验证 proptest 套件 + 验证收尾

## Summary

Phase L 前 3 个 Task（L-0 Phase K 验证 / L-1 Per-Instruction Gas 模型 / L-2 STARK Fallback 评估文档）已完成。本计划聚焦剩余 2 个 Task：

- **L-3**：新建 `poker_zkvm/tests/formal_properties.rs`，包含 4 类 proptest 属性测试，覆盖核心数学不变量（CCS satisfied_by、LogUp 等式、域算术、SparseMatrix 运算）。
- **L-4**：全量验证收尾（clippy + lib 测试 + formal_properties 测试 + doc 测试）。

完成本计划后，Phase L 收敛，Stage 4（Phase F-L）全部结束。

## Current State Analysis

### 已完成（L-0/L-1/L-2）

- **L-0 Phase K 验证**：[isa/mod.rs:952](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/mod.rs#L952) 已用 `checked_div(b).unwrap_or(u32::MAX)`；[algebra.rs:625](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/algebra.rs#L625) 已移除 `pow64.clone()`。
- **L-1 Per-Instruction Gas**：[syscalls/gas.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas.rs) L83-L117 新增 9 个 `GAS_INSN_*` 常量；L190-L249 新增 `instruction_gas()`；L251-L266 新增 `total_step_gas()`；L479-L705 新增 13 个测试。
- **L-2 STARK Fallback 评估文档**：[stark_fallback_evaluation.md](file:///Users/mac/projects/zchain/.trae/specs/build-hypernova-zkvm/stark_fallback_evaluation.md) 已创建（216 行，8 章节）。

### 未完成（L-3/L-4）

- **L-3**：`poker_zkvm/tests/formal_properties.rs` **不存在**（已通过 Glob 验证 `tests/` 目录仅有 e2e_fibonacci/e2e_sha256_chain/e2e_poker_hand_eval/soundness_tests）。
- **L-4**：未执行最终验证。

### API 可见性验证（已确认全部 public）

| API | 位置 | 签名 |
|-----|------|------|
| `AddCircuit::to_instance` | [algebra.rs:133](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/algebra.rs#L133) | `pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError>` |
| `MulCircuit::to_instance` | [algebra.rs:461](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/algebra.rs#L461) | `pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError>` |
| `MulhCircuit::to_instance` | [algebra.rs:662](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/algebra.rs#L662) | `pub fn to_instance(a: u32, b: u32) -> Result<CcsInstance, ZkvmError>` |
| `Ccs::satisfied_by` | [ccs/mod.rs:304](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs#L304) | `pub fn satisfied_by(&self, z: &[Fr]) -> Result<bool, ZkvmError>` |
| `CcsInstance` 字段 | [ccs/mod.rs:533-539](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs#L533) | `pub ccs: Ccs, pub witness: Vec<Fr>, pub public_inputs: Vec<Fr>` |
| `SparseMatrix::new` | [ccs/mod.rs:84](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs#L84) | `pub fn new(num_rows: usize, num_cols: usize) -> Self` |
| `SparseMatrix::add_entry` | [ccs/mod.rs:101](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs#L101) | `pub fn add_entry(&mut self, row, col, value: Fr) -> Result<(), ZkvmError>` |
| `SparseMatrix::evaluate` | [ccs/mod.rs:134](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs#L134) | `pub fn evaluate(&self, z: &[Fr]) -> Result<Vec<Fr>, ZkvmError>` |
| `LogUpProof::create` | [lookup.rs:247](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs#L247) | `pub fn create(table: Vec<Fr>, witness: Vec<Fr>, multiplicity: Vec<Fr>) -> Result<(Self, LogUpCommitments), ZkvmError>` |
| `LogUpProof::verify` | [lookup.rs:293](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs#L293) | `pub fn verify(&self, commits: &LogUpCommitments) -> Result<bool, ZkvmError>` |
| `LogUpProof::verify_equation` | [lookup.rs:327](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs#L327) | `pub fn verify_equation(&self) -> Result<bool, ZkvmError>` |
| `Fr` | [ccs/mod.rs:25](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs#L25) | `pub type Fr = Bn254ScalarField` |
| `ZkvmField` trait | [field.rs:31-61](file:///Users/mac/projects/zchain/poker_zkvm/src/field.rs#L31) | `from_u32_with_wrap`/`from_u64`/`add`/`sub`/`mul`/`neg`/`inverse`/`zero`/`one`/`is_zero` |

### 关键依赖确认

- `proptest = { workspace = true }` 在 [Cargo.toml:38](file:///Users/mac/projects/zchain/poker_zkvm/Cargo.toml#L38)（dev-dependencies）
- `Bn254ScalarField` 实现 `#[derive(Clone, Copy, ...)]`（field.rs），可直接复制
- `Fr` 实现 `PartialEq`/`Eq`（通过 `Bn254ScalarField` derive）

---

## Proposed Changes

### Task L-3：创建 `poker_zkvm/tests/formal_properties.rs`

**文件**：新建 `/Users/mac/projects/zchain/poker_zkvm/tests/formal_properties.rs`

**结构**：4 类 proptest，共 12 个属性测试。

#### L-3.1：CCS satisfied_by 一致性（4 个测试）

```rust
proptest! {
    /// 属性：满足 CCS 约束的 witness 必须通过 satisfied_by 检查（AddCircuit）
    #[test]
    fn prop_ccs_satisfied_by_consistent(a: u32, b: u32) {
        let instance = AddCircuit::to_instance(a, b).expect("to_instance");
        prop_assert!(instance.ccs.satisfied_by(&instance.witness).expect("satisfied_by"));
    }

    /// 属性：篡改 witness 后 satisfied_by 必须失败（idx > 0）
    #[test]
    fn prop_ccs_satisfied_by_tampered(a: u32, b: u32, tamper_idx: u8) {
        let instance = AddCircuit::to_instance(a, b).expect("to_instance");
        let mut witness = instance.witness.clone();
        let idx = (tamper_idx as usize) % witness.len();
        if idx == 0 { return Ok(()); } // 跳过常量位
        witness[idx] = witness[idx].add(&Fr::one());
        let result = instance.ccs.satisfied_by(&witness).expect("satisfied_by");
        prop_assert!(!result, "篡改 witness[{}] 后应失败", idx);
    }

    /// 属性：MUL 子电路对任意 a,b 满足约束
    #[test]
    fn prop_mul_circuit_satisfied(a: u32, b: u32) {
        let instance = MulCircuit::to_instance(a, b).expect("to_instance");
        prop_assert!(instance.ccs.satisfied_by(&instance.witness).expect("satisfied_by"));
    }

    /// 属性：MULH 子电路对任意 a,b 满足约束
    #[test]
    fn prop_mulh_circuit_satisfied(a: u32, b: u32) {
        let instance = MulhCircuit::to_instance(a, b).expect("to_instance");
        prop_assert!(instance.ccs.satisfied_by(&instance.witness).expect("satisfied_by"));
    }
}
```

#### L-3.2：LogUp 等式一致性（1 个测试）

**关键修正**：原计划中 `LogUpProof::create` 签名为 `Vec<Fr>`（非 `&Vec<Fr>`），且 `table.len() == multiplicity.len()` 是硬约束。

```rust
proptest! {
    /// 属性：LogUp create → verify 闭环对合法 table/witness 成功
    #[test]
    fn prop_logup_create_verify_consistent(
        mult in prop::collection::vec(0u32..5, 1..10)
    ) {
        // table 长度 = mult 长度（硬约束）
        let table: Vec<u32> = (0..mult.len() as u32).collect();
        let table_fr: Vec<Fr> = table.iter().map(|&v| Fr::from_u32_with_wrap(v)).collect();
        let mult_fr: Vec<Fr> = mult.iter().map(|&v| Fr::from_u32_with_wrap(v)).collect();
        // witness = 按 multiplicity 展开 table
        let mut witness_fr = Vec::new();
        for (t, &m) in table.iter().zip(mult.iter()) {
            for _ in 0..m {
                witness_fr.push(Fr::from_u32_with_wrap(*t));
            }
        }
        // 若 witness 为空（所有 m=0），跳过（verify_equation 会因 β 无碰撞而通过）
        if witness_fr.is_empty() { return Ok(()); }
        let (proof, commits) = LogUpProof::create(table_fr, witness_fr, mult_fr).expect("create");
        prop_assert!(proof.verify(&commits).expect("verify"));
        prop_assert!(proof.verify_equation().expect("verify_equation"));
    }
}
```

#### L-3.3：域算术属性（7 个测试）

```rust
proptest! {
    /// 属性：a + b = b + a（交换律，64-bit）
    #[test]
    fn prop_field_add_commutative_u64(a: u64, b: u64) {
        let fa = Fr::from_u64(a);
        let fb = Fr::from_u64(b);
        prop_assert_eq!(fa.add(&fb), fb.add(&fa));
    }

    /// 属性：a * b = b * a（交换律，64-bit）
    #[test]
    fn prop_field_mul_commutative_u64(a: u64, b: u64) {
        let fa = Fr::from_u64(a);
        let fb = Fr::from_u64(b);
        prop_assert_eq!(fa.mul(&fb), fb.mul(&fa));
    }

    /// 属性：(a + b) + c = a + (b + c)（结合律）
    #[test]
    fn prop_field_add_associative(a: u32, b: u32, c: u32) {
        let fa = Fr::from_u32_with_wrap(a);
        let fb = Fr::from_u32_with_wrap(b);
        let fc = Fr::from_u32_with_wrap(c);
        prop_assert_eq!(fa.add(&fb).add(&fc), fa.add(&fb.add(&fc)));
    }

    /// 属性：a * (b + c) = a*b + a*c（分配律）
    #[test]
    fn prop_field_distributive(a: u32, b: u32, c: u32) {
        let fa = Fr::from_u32_with_wrap(a);
        let fb = Fr::from_u32_with_wrap(b);
        let fc = Fr::from_u32_with_wrap(c);
        prop_assert_eq!(fa.mul(&fb.add(&fc)), fa.mul(&fb).add(&fa.mul(&fc)));
    }

    /// 属性：a - a = 0
    #[test]
    fn prop_field_sub_self(a: u64) {
        let fa = Fr::from_u64(a);
        prop_assert!(fa.sub(&fa).is_zero());
    }

    /// 属性：a * 0 = 0
    #[test]
    fn prop_field_mul_zero(a: u64) {
        let fa = Fr::from_u64(a);
        prop_assert!(fa.mul(&Fr::zero()).is_zero());
    }

    /// 属性：a * 1 = a
    #[test]
    fn prop_field_mul_one(a: u64) {
        let fa = Fr::from_u64(a);
        prop_assert_eq!(fa.mul(&Fr::one()), fa);
    }
}
```

#### L-3.4：SparseMatrix 运算属性（1 个测试）

```rust
proptest! {
    /// 属性：SparseMatrix evaluate 在 row-isolated（单 entry）下仅 row 处非零
    #[test]
    fn prop_sparse_matrix_row_isolated_evaluate(
        row in 0u32..10,
        col in 0u32..5,
        val in 0u64..1000,
        z_len in 5usize..10
    ) {
        let mut m = SparseMatrix::new(10, z_len);
        m.add_entry(row as usize, col as usize, Fr::from_u64(val)).expect("add_entry");
        let z: Vec<Fr> = (0..z_len).map(|i| Fr::from_u32_with_wrap(i as u32)).collect();
        let result = m.evaluate(&z).expect("evaluate");
        prop_assert_eq!(result.len(), 10);
        for (i, &v) in result.iter().enumerate() {
            if i == row as usize {
                prop_assert_eq!(v, Fr::from_u64(val).mul(&z[col as usize]));
            } else {
                prop_assert!(v.is_zero(), "row {} 应为 0", i);
            }
        }
    }
}
```

#### 文件头部 imports

```rust
//! Phase L — 形式化验证属性测试套件（Task L-3）。
//!
//! 覆盖核心数学不变量：
//! - CCS satisfied_by 一致性（AddCircuit/MulCircuit/MulhCircuit + 篡改测试）
//! - LogUp 等式一致性（create → verify 闭环）
//! - 域算术属性（交换律/结合律/分配律/单位元/零元）
//! - SparseMatrix 运算属性（row-isolated evaluate）

use proptest::prelude::*;

use poker_zkvm::ccs::{CcsInstance, Fr, SparseMatrix};
use poker_zkvm::constraints::algebra::{AddCircuit, MulCircuit, MulhCircuit};
use poker_zkvm::constraints::lookup::{LogUpProof};
use poker_zkvm::field::ZkvmField;
```

#### 关键决策

1. **`tamper_idx == 0` 跳过**：`witness[0]` 是常量 `1`，篡改为 `2` 后 `overflow_bit² - overflow_bit = 4 - 2 = 2 ≠ 0`（实际会失败），但 AddCircuit 的 Row 0 `a + b - result - 2^32*overflow_bit` 中 `overflow_bit` 若原为 0 篡改为 1，会让等式变成 `a+b-result-2^32 = -2^32 ≠ 0`（失败）。但为稳健起见，仍跳过 idx=0 避免边界争议。

2. **LogUp witness 为空时跳过**：当所有 `m_i = 0` 时 witness 为空，`verify_equation` 的 RHS=0，LHS 也为 0（所有 m_i=0），等式成立但语义无意义，跳过。

3. **不测试 fold 等式**：需构造可折叠随机 CCS 实例，基础设施不足，留待后续。

---

### Task L-4：验证与收尾

**步骤**（按顺序执行）：

1. **clippy 检查**（lib + tests）：
   ```bash
   cargo clippy -p poker_zkvm --lib --tests -- -D warnings
   ```
   - 预期：0 warning
   - 若有 warning，修复后重跑

2. **lib 单元测试**：
   ```bash
   cargo test -p poker_zkvm --lib
   ```
   - 预期：全部通过（含 L-1 新增 13 个 gas 测试）

3. **formal_properties 集成测试**：
   ```bash
   cargo test -p poker_zkvm --test formal_properties
   ```
   - 预期：12 个 proptest 全绿（默认 256 cases each）

4. **doc 测试**：
   ```bash
   cargo test -p poker_zkvm --doc
   ```
   - 预期：全部通过

5. **跨文件一致性检查**（仅检查，不修改）：
   - 确认 `stark_fallback_evaluation.md` 完整（8 章节）
   - 确认 `gas.rs` 含 9 个 `GAS_INSN_*` 常量 + `instruction_gas` + `total_step_gas`
   - 确认 `formal_properties.rs` 含 12 个 proptest

**验证标准**：
- clippy 0 warning
- lib 测试全通过
- formal_properties 12 个 proptest 全绿
- doc 测试全通过

---

## Assumptions & Decisions

### 假设

1. Phase K clippy 修复已正确落地（已通过 Read 验证）
2. L-1 Gas 模型代码已稳定（已通过 Grep 验证 9 常量 + 2 函数存在）
3. L-2 STARK 评估文档已完整（已通过 Read 验证 8 章节存在）
4. proptest workspace 依赖可用（已通过 Cargo.toml 验证）
5. `AddCircuit`/`MulCircuit`/`MulhCircuit` 的 `to_instance` 对任意 u32 输入均返回 `Ok`（已通过代码审查验证 witness 构造逻辑）

### 关键决策

1. **proptest 默认 cases 数**：不设置 `proptest! { #![proptest_config(ProptestConfig { cases: 256, ... })] }`，使用默认 256 cases，平衡覆盖度与运行时间。
2. **不新增 `Instruction` proptest**：`Instruction` 枚举无 `Arbitrary` 实现，自定义 strategy 工作量大，gas 模型已有 13 个单元测试覆盖。
3. **LogUp 测试构造方式**：用 `table = [0, 1, 2, ...]` + 随机 `mult` + 展开 witness，确保 `table.len() == mult.len()` 硬约束满足。

---

## 执行顺序

```
L-3 (创建 formal_properties.rs) ──> L-4 (验证收尾)
```

L-3 完成后立即执行 L-4 的 4 步验证。若任何步骤失败，修复后重跑该步骤。
