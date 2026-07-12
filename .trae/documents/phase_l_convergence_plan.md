# Phase L：Gas 模型对齐 + STARK fallback 评估 + 形式化验证

## Summary

Stage 4 收尾阶段。在 Phase F-K 完成的基础上，对齐市场 gas 模型（补齐 per-instruction gas 表）、评估 STARK fallback 可行性（仅文档，不实现）、并引入形式化验证属性测试套件（proptest 覆盖核心数学不变量）。本阶段不引入新功能电路，聚焦于收敛、文档化和属性验证。

**前置**：Phase K 最终验证（clippy + 全量回归）。

## Current State Analysis

### Gas 模型现状
- [syscalls/gas.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/syscalls/gas.rs)：已有 15 个 syscall gas 常量 + `syscall_gas()` 函数（L124-L151），覆盖全部 15 个 SyscallId
- [syscalls/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/syscalls/mod.rs)：`SyscallId` 枚举 15 个 variant（0x01-0x0F），完整
- [constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)：`instruction_category()` 已分类 35 个类别（L112-L161），`NUM_CATEGORIES=35`，M 扩展归入 category 31
- [poker_l1/src/vm/gas_table.rs](file:///Users/mac/projects/zchain/poker_l1/src/vm/gas_table.rs)：L1 侧 BPF 指令 gas 模型参考（算术=1, 内存=3+2*bytes, 分支=2）
- **缺口**：poker_zkvm **无 per-instruction gas**（ISA executor 不计费），仅 syscall 计费

### STARK/fallback 现状
- 无 plonky3/fri/stark 依赖（Cargo.toml 未引入）
- CCS 定义在 [ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs)，由 `SparseMatrix` + `subsets` + `coeffs` 组成，理论上泛化 R1CS/Plonkish/AIR
- 无 `stark_fallback_evaluation.md` 文件

### 形式化验证现状
- proptest 已在 Cargo.toml（workspace 依赖）
- 现有 proptest 覆盖（3 文件）：
  - [field.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/field.rs#L457)：u32 roundtrip / canonical bytes / 加法交换律 / 乘法交换律
  - [transcript.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/transcript.rs#L520)：transcript 一致性
  - [pcs/ipa.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/pcs/ipa.rs#L708)：IPA commit/open 一致性
- **缺口**：CCS `satisfied_by`、fold 等式、LogUp 等式、prover/verifier 端到端属性无 proptest
- 无 `tests/formal_properties.rs`

### 关键数学不变量位置
- **CCS satisfied_by**：[ccs/mod.rs:L304-L324](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs#L304) — `satisfied_by()` + row-isolated 快速路径
- **Fold 等式**：[fold/fold_loop.rs:L137](file:///Users/mac/projects/zchain/poker_zkvm/src/fold/fold_loop.rs#L137) — `fold_loop()` 调用 `fold_step::fold()` + `sumcheck::prove()`
- **LogUp 等式**：[constraints/lookup.rs:L327-L371](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs#L327) — `LogUpProof::verify_equation()` 校验 `Σ m_i/(β-t_i) == Σ 1/(β-f_j)`

---

## Proposed Changes

### Task L-0：Phase K 最终验证（前置）

**目标**：确认 Phase K 的 clippy 修复（`checked_div`/`checked_rem`）和全量回归通过。

**步骤**：
1. `cargo clippy -p poker_zkvm --lib -- -D warnings` — 验证无 `manual_checked_ops` 警告
2. `cargo test -p poker_zkvm` — 全量回归
3. 若通过，Phase K 关闭，进入 Phase L

**验证标准**：clippy 0 warning + 全量测试通过。

---

### Task L-1：Per-Instruction Gas 模型对齐

**目标**：在 poker_zkvm 中新增 per-instruction gas 表和 `instruction_gas()` 函数，对齐 SP1/RISC Zero 的 per-instruction + per-syscall + per-memory-access 三层 gas 模型。

**文件**：`poker_zkvm/src/syscalls/gas.rs`（扩展）

#### L-1.1：新增 per-instruction gas 常量

参考 L1 BPF gas 表（`poker_l1/src/vm/gas_table.rs`）+ SP1/RISC Zero 公开文档：

```rust
// ===== Per-Instruction Gas（对齐 L1 BPF + SP1 模型）=====

/// 算术指令 gas（ADD/SUB/AND/OR/XOR/SLT/SLTU + I-type 变体）。
/// 对齐 L1 GAS_ARITHMETIC=1 + SP1 per-insn base。
pub const GAS_INSN_ARITHMETIC: u64 = 1;

/// 内存加载指令基础 gas（LB/LH/LW/LBU/LHU）。
/// 对齐 L1 GAS_MEMORY_BASE=3。
pub const GAS_INSN_MEMORY_BASE: u64 = 3;

/// 内存加载指令每字节附加 gas。
/// 对齐 L1 GAS_MEMORY_PER_BYTE=2（IMPL-SEC-4 修复）。
pub const GAS_INSN_MEMORY_PER_BYTE: u64 = 2;

/// 分支指令 gas（BEQ/BNE/BLT/BGE/BLTU/BGEU/JAL/JALR）。
/// 对齐 L1 GAS_BRANCH=2。
pub const GAS_INSN_BRANCH: u64 = 2;

/// 移位指令 gas（SLL/SRL/SRA/SLLI/SRLI/SRAI）。
/// 移位约束复杂度高于算术，设为 2。
pub const GAS_INSN_SHIFT: u64 = 2;

/// M 扩展乘法指令 gas（MUL/MULH/MULHSU/MULHU）。
/// 乘法约束（64-bit 乘积分解）远重于算术，对齐 modexp PER_BIT 量级。
pub const GAS_INSN_MUL: u64 = 20;

/// M 扩展除法指令 gas（DIV/DIVU/REM/REMU）。
/// MVP trust witness 模式下约束轻，但语义复杂；完整约束后应提升。
pub const GAS_INSN_DIV: u64 = 20;

/// LUI/AUIPC gas（高位立即数，等同算术）。
pub const GAS_INSN_UPPER_IMM: u64 = 1;

/// FENCE/ECALL/EBREAK gas。
pub const GAS_INSN_SYSTEM: u64 = 2;
```

#### L-1.2：新增 `instruction_gas()` 函数

```rust
/// 计算单条指令的 gas 开销（不含 syscall gas）。
///
/// # 模型
///
/// | 类别 | 指令 | Gas |
/// |------|------|-----|
/// | 算术 | ADD/SUB/AND/OR/XOR/SLT/SLTU + I-type | `GAS_INSN_ARITHMETIC` |
/// | 内存 | LB/LH/LW/LBU/LHU | `GAS_INSN_MEMORY_BASE + GAS_INSN_MEMORY_PER_BYTE * bytes` |
/// | Store | SB/SH/SW | `GAS_INSN_MEMORY_BASE + GAS_INSN_MEMORY_PER_BYTE * bytes` |
/// | 分支 | BEQ/BNE/BLT/BGE/BLTU/BGEU/JAL/JALR | `GAS_INSN_BRANCH` |
/// | 移位 | SLL/SRL/SRA/SLLI/SRLI/SRAI | `GAS_INSN_SHIFT` |
/// | 乘法 | MUL/MULH/MULHSU/MULHU | `GAS_INSN_MUL` |
/// | 除法 | DIV/DIVU/REM/REMU | `GAS_INSN_DIV` |
/// | 高位立即数 | LUI/AUIPC | `GAS_INSN_UPPER_IMM` |
/// | 系统 | FENCE/ECALL/EBREAK | `GAS_INSN_SYSTEM` |
///
/// # 参数
/// - `insn` — 解码后的指令
/// - `mem_bytes` — 内存访问字节数（1/2/4），非内存指令传 0
#[must_use]
pub fn instruction_gas(insn: &Instruction, mem_bytes: u32) -> u64 {
    match insn {
        Instruction::Lb { .. } | Instruction::Lh { .. } | Instruction::Lw { .. }
        | Instruction::Lbu { .. } | Instruction::Lhu { .. }
        | Instruction::Sb { .. } | Instruction::Sh { .. } | Instruction::Sw { .. } => {
            GAS_INSN_MEMORY_BASE + GAS_INSN_MEMORY_PER_BYTE * mem_bytes as u64
        }
        Instruction::Beq { .. } | Instruction::Bne { .. }
        | Instruction::Blt { .. } | Instruction::Bge { .. }
        | Instruction::Bltu { .. } | Instruction::Bgeu { .. }
        | Instruction::Jal { .. } | Instruction::Jalr { .. } => GAS_INSN_BRANCH,
        Instruction::Sll { .. } | Instruction::Srl { .. } | Instruction::Sra { .. }
        | Instruction::Slli { .. } | Instruction::Srli { .. } | Instruction::Srai { .. } => GAS_INSN_SHIFT,
        Instruction::Mul { .. } | Instruction::Mulh { .. }
        | Instruction::Mulhsu { .. } | Instruction::Mulhu { .. } => GAS_INSN_MUL,
        Instruction::Div { .. } | Instruction::Divu { .. }
        | Instruction::Rem { .. } | Instruction::Remu { .. } => GAS_INSN_DIV,
        Instruction::Lui { .. } | Instruction::Auipc { .. } => GAS_INSN_UPPER_IMM,
        Instruction::Fence | Instruction::Ecall | Instruction::Ebreak => GAS_INSN_SYSTEM,
        // 其余算术（ADD/SUB/AND/OR/XOR/SLT/SLTU + I-type 变体）
        _ => GAS_INSN_ARITHMETIC,
    }
}
```

#### L-1.3：新增 `total_step_gas()` 辅助函数

```rust
/// 计算单步执行的 gas（指令 gas + syscall gas，若为 ECALL）。
///
/// ECALL 指令本身的 gas + 对应 syscall 的 gas。
#[must_use]
pub fn total_step_gas(insn: &Instruction, mem_bytes: u32, syscall_id: Option<SyscallId>, syscall_args: &SyscallGasArgs) -> u64 {
    let insn_gas = instruction_gas(insn, mem_bytes);
    let sys_gas = syscall_id.map(|id| syscall_gas(id, syscall_args)).unwrap_or(0);
    insn_gas + sys_gas
}
```

#### L-1.4：测试

在 `gas.rs` 的 `#[cfg(test)] mod tests` 中新增：
- `test_instruction_gas_arithmetic` — ADD/SUB/AND/OR/XOR 返回 1
- `test_instruction_gas_memory` — LW 返回 3+2*4=11, LB 返回 3+2*1=5
- `test_instruction_gas_branch` — BEQ/JAL 返回 2
- `test_instruction_gas_shift` — SLL/SLLI 返回 2
- `test_instruction_gas_mul` — MUL/MULH 返回 20
- `test_instruction_gas_div` — DIV/REMU 返回 20
- `test_instruction_gas_upper_imm` — LUI/AUIPC 返回 1
- `test_instruction_gas_system` — FENCE/ECALL/EBREAK 返回 2
- `test_total_step_gas_ecall` — ECALL + Poseidon syscall 总 gas = 2 + 150 = 152
- `test_gas_model_documentation` — 断言 gas 估算公式在 doc comment 中（简单 sanity check）

---

### Task L-2：STARK Fallback 评估文档

**目标**：评估 Plonky3/FRI 作为 Hypernova 备选后端的可行性，产出评估文档（不实现代码）。

**文件**：新建 `.trae/specs/build-hypernova-zkvm/stark_fallback_evaluation.md`

#### 文档结构

```markdown
# STARK Fallback 评估

## 1. 动机
- Hypernova + IPA 当前为唯一后端，无 fallback
- 评估 STARK（FRI-based）作为备选后端的可行性

## 2. 当前架构
- CCS（Customizable Constraint System）泛化 R1CS/Plonkish/AIR
- Hypernova 折叠 + IPA over BN254 PCS
- Groth16 最终压缩

## 3. STARK 后端评估
### 3.1 Plonky3/FRI
- 优势：透明 setup（无 trusted setup）、post-quantum、reursive-friendly
- 劣势：proof size 大（100KB-1MB vs Hypernova ~2KB）、verifier time O(n log n) vs O(1)
- 兼容性：FRI PCS 可替换 IPA PCS，但需重新实现 sumcheck + cross-language claim

### 3.2 CCS 后端可替换性
- CCS 的 `SparseMatrix` + `subsets` + `coeffs` 结构泛化 R1CS/Plonkish/AIR
- 替换 PCS（IPA → FRI）需修改：commit/open/verify 三个函数
- 折叠算法（Hypernova）依赖 PCS opening，替换 PCS 不影响折叠逻辑
- 风险：FRI 的 opening 语义与 IPA 不同（多项式 vs 多线性扩展）

## 4. 对比矩阵
| 维度 | Hypernova+IPA | STARK+FRI |
|------|---------------|-----------|
| Proof size | ~2KB | 100KB-1MB |
| Prover time | O(N) | O(N log N) |
| Verifier time | O(1) ~510µs | O(log N) |
| Trusted setup | 否（IPA 透明） | 否 |
| Post-quantum | 否（BN254） | 是 |
| 递归友好 | 是（CycleFold） | 是（FRI 递归） |

## 5. 建议
- **短期**：保持 Hypernova+IPA 为唯一后端（proof size 优势显著）
- **中期**：评估 FRI 作为特定场景备选（post-quantum 需求）
- **长期**：CCS 后端抽象层（trait-based PCS），支持 IPA/FRI 切换

## 6. 未选择方案
- 方案 B（实现 FRI）：工作量 ~2-3 周，proof size 膨胀 50-500x，不推荐短期投入
- 方案 C（Plonky3 集成）：依赖外部 crate，引入 unsafe 风险
```

---

### Task L-3：形式化验证属性测试套件

**目标**：对核心数学不变量编写 proptest 属性测试，覆盖 CCS/Fold/LogUp 三个关键不变量。

**文件**：新建 `poker_zkvm/tests/formal_properties.rs`

#### L-3.1：CCS satisfied_by 一致性

```rust
proptest! {
    /// 属性：满足 CCS 约束的 witness 必须通过 satisfied_by 检查
    #[test]
    fn prop_ccs_satisfied_by_consistent(a: u32, b: u32) {
        let instance = AddCircuit::to_instance(a, b).expect("to_instance");
        let ccs = instance.ccs;
        let witness = instance.witness;
        prop_assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));
    }

    /// 属性：篡改 witness 后 satisfied_by 必须失败
    #[test]
    fn prop_ccs_satisfied_by_tampered(a: u32, b: u32, tamper_idx: u8) {
        let instance = AddCircuit::to_instance(a, b).expect("to_instance");
        let mut witness = instance.witness.clone();
        let idx = (tamper_idx as usize) % witness.len();
        witness[idx] = witness[idx].add(&Fr::one()); // 篡改
        let result = instance.ccs.satisfied_by(&witness).expect("satisfied_by");
        // 篡改后应失败（除非原值为 0 且篡改恰好仍满足，概率极低）
        // 注意：idx=0（常量 1）篡改会让 witness[0]=2，约束仍可能满足
        // 因此仅对 idx > 0 断言失败
        if idx > 0 {
            prop_assert!(!result, "篡改 witness[{}] 后应失败", idx);
        }
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

#### L-3.2：LogUp 等式一致性

```rust
proptest! {
    /// 属性：LogUp create → verify 闭环对合法 table/witness 成功
    #[test]
    fn prop_logup_create_verify_consistent(
        table in prop::collection::vec(0u32..100, 1..10),
        witness_mult in prop::collection::vec(0u32..5, 1..10)
    ) {
        // 构造 table + multiplicity + witness 使得 Σ m_i*t_i = Σ f_j
        let table_fr: Vec<Fr> = table.iter().map(|&v| Fr::from_u32_with_wrap(v)).collect();
        let mult_fr: Vec<Fr> = witness_mult.iter().map(|&v| Fr::from_u32_with_wrap(v)).collect();
        // witness = 展开 table by multiplicity
        let mut witness_fr = Vec::new();
        for (t, &m) in table.iter().zip(witness_mult.iter()) {
            for _ in 0..m {
                witness_fr.push(Fr::from_u32_with_wrap(*t));
            }
        }
        if let Ok((proof, commits)) = LogUpProof::create(&table_fr, &witness_fr, &mult_fr) {
            prop_assert!(proof.verify(&commits).expect("verify"));
            prop_assert!(proof.verify_equation().expect("verify_equation"));
        }
    }
}
```

#### L-3.3：域算术属性（扩展现有）

```rust
proptest! {
    /// 属性：a + b = b + a（交换律，扩展到 64-bit）
    #[test]
    fn prop_field_add_commutative_u64(a: u64, b: u64) {
        let fa = Fr::from_u64(a);
        let fb = Fr::from_u64(b);
        prop_assert_eq!(fa.add(&fb), fb.add(&fa));
    }

    /// 属性：a * b = b * a（交换律，扩展到 64-bit）
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
        prop_assert_eq!(
            fa.mul(&fb.add(&fc)),
            fa.mul(&fb).add(&fa.mul(&fc))
        );
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

#### L-3.4：CCS 矩阵运算属性

```rust
proptest! {
    /// 属性：SparseMatrix evaluate 在 row-isolated 下 O(1) 正确
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
        // row-isolated: 仅 row 处非零
        for (i, &v) in result.iter().enumerate() {
            if i == row as usize {
                prop_assert_eq!(v, Fr::from_u64(val).mul(&z[col as usize]));
            } else {
                prop_assert!(v.is_zero());
            }
        }
    }
}
```

#### L-3.5：形式化验证评估文档

在 `stark_fallback_evaluation.md` 末尾追加"形式化验证评估"章节：

```markdown
## 7. 形式化验证评估

### 7.1 现状
- proptest 覆盖：field / transcript / IPA / CCS satisfied_by / LogUp 等式（Phase L 新增）
- 覆盖范围：核心数学不变量的随机属性测试，1000+ 随机实例

### 7.2 Lean4/Coq 可行性评估
- **优势**：数学等式的机器检查证明（fold 等式、LogUp 等式）
- **劣势**：学习曲线陡、与 Rust 代码绑定需提取（extraction）、维护成本高
- **建议**：短期以 proptest 为主，长期对 fold 等式和 LogUp 等式引入 Lean4 证明

### 7.3 推荐下一步
1. 扩展 proptest 到 fold 等式（需构造可折叠的随机 CCS 实例）
2. 对 Hypernova fold 等式编写 Lean4 形式化证明（独立项目）
3. 评估 TLA+ 对 executor 状态机的规格化验证
```

---

### Task L-4：验证与收尾

**步骤**：
1. `cargo clippy -p poker_zkvm --lib -- -D warnings` — 无 warning
2. `cargo test -p poker_zkvm` — 全量回归通过
3. `cargo test -p poker_zkvm --test formal_properties` — 新增属性测试通过
4. `cargo test -p poker_zkvm --doc` — doc test 通过
5. 检查 `stark_fallback_evaluation.md` 完整性

**验证标准**：
- clippy 0 warning
- 全量测试通过（含新增 instruction_gas 测试 + formal_properties）
- STARK 评估文档完整
- proptest 默认 256 cases 全绿

---

## Assumptions & Decisions

### 关键决策

1. **Gas 表放置位置**：选择 `syscalls/gas.rs`（非新文件）
   - 理由：所有 gas 逻辑集中一处，与现有 `syscall_gas()` 一致
   - 未选择：新建 `syscalls/instruction_gas.rs`（分离但增加文件数）

2. **Gas 模型参考**：以 L1 BPF gas 表（arithmetic=1, memory=3+2*bytes, branch=2）为基线
   - 理由：保持与 poker_l1 体系一致，避免两套 gas 模型
   - M 扩展（MUL/DIV）新增 gas=20，反映约束复杂度

3. **STARK fallback 不实现**：仅产出评估文档
   - 理由：stage4 计划明确"L-2 仅评估不实现"，FRI 实现工作量 ~2-3 周
   - 未选择：实现 FRI（proof size 膨胀 50-500x，短期无收益）

4. **proptest 放置位置**：`tests/formal_properties.rs`（集成测试文件）
   - 理由：stage4 计划指定，跨模块属性测试集中可见
   - 未选择：散布在各模块 `#[cfg(test)] mod proptests`（碎片化）

5. **proptest 范围**：聚焦 CCS satisfied_by + LogUp 等式 + 域算术
   - 理由：这三个是核心数学不变量，且可独立测试
   - 未选择：fold 等式 proptest（需构造可折叠随机 CCS 实例，基础设施不足，留待后续）

### 假设

- Phase K clippy 修复已正确落地（已通过 Read 验证代码存在）
- proptest workspace 依赖可用（Cargo.toml 已配置）
- `Instruction` 枚举的 `Clone`/`Debug` trait 可用于 proptest（已有 `#[derive(Clone, Debug, PartialEq, Eq)]`）

---

## 跨文件一致性

完成后同步更新：
- [ ] `.trae/specs/build-hypernova-zkvm/spec.md` — 新增 Phase L 设计决策
- [ ] `.trae/specs/build-hypernova-zkvm/tasks.md` — 新增 Task L.1/L.2/L.3 条目
- [ ] `.trae/specs/build-hypernova-zkvm/checklist.md` — 新增 Phase L checkpoint
- [ ] `.trae/specs/build-hypernova-zkvm/stark_fallback_evaluation.md` — 新建评估文档

---

## 执行顺序

```
L-0 (Phase K 验证) ──> L-1 (Gas 模型) ──┐
                                        ├──> L-4 (验证收尾)
L-2 (STARK 评估文档) ────────────────────┤
                                        │
L-3 (proptest 套件) ─────────────────────┘
```

- L-0 前置（必须先通过）
- L-1/L-2/L-3 可并行（互相独立）
- L-4 最后收尾
