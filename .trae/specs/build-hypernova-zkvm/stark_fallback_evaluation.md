# STARK Fallback 评估

> **阶段**：Phase L — Task L-2（仅评估，不实现）
> **版本**：v1.0
> **日期**：2026-07-12
> **参考**：stage4_market_alignment_phases.md Phase L

## 1. 动机

当前 poker_zkvm 采用 Hypernova + IPA over BN254 作为唯一证明后端，无 fallback 机制。本评估文档分析 STARK（FRI-based）作为备选后端的可行性，为长期架构决策提供依据。

**评估范围**：
- Plonky3/FRI 作为备选 PCS（多项式承诺方案）
- CCS 后端可替换性
- 与现有 Hypernova 折叠算法的兼容性

**不评估**：
- 具体 FRI 实现细节（留待实际实现时）
- 非 FRI-based STARK（如 Brakedown、Orion）

## 2. 当前架构

poker_zkvm 当前证明栈：

```
Rust 源码 → RV32I/RV32IM ELF → ISA 执行 → Trace
                                              ↓
                                    CCS 约束编译器
                                              ↓
                                    Hypernova 折叠
                                     (LCCCS + CCCCS)
                                              ↓
                                    IPA over BN254
                                     (commit/open/verify)
                                              ↓
                                    Groth16 最终压缩
                                     (~200B proof)
```

**核心组件**：
- **CCS（Customizable Constraint System）**：`SparseMatrix` + `subsets` + `coeffs`，泛化 R1CS/Plonkish/AIR
  - 实现：`poker_zkvm/src/ccs/mod.rs`
- **Hypernova 折叠**：LCCCS + CCCCS + 外层 sumcheck + 内层 batched sumcheck + cross-language claim
  - 实现：`poker_zkvm/src/fold/fold_loop.rs`、`poker_zkvm/src/hypernova/`
- **IPA over BN254**：透明 setup（无 trusted ceremony），commit/open/verify
  - 实现：`poker_zkvm/src/pcs/ipa.rs`
- **Groth16 压缩**：将 Hypernova proof 压缩为 ~200B SNARK proof
  - 实现：`poker_zkvm/src/prover/groth16_compress.rs`

## 3. STARK 后端评估

### 3.1 Plonky3/FRI

**FRI（Fast Reed-Solomon Interactive Oracle Proof of Proximity）** 是 STARK 证明系统的核心组件，用于验证多项式在某域上的低度扩展。

**优势**：
- **透明 setup**：无需 trusted ceremony，与 IPA 一样透明
- **Post-quantum 安全**：基于 Reed-Solomon 编码，不依赖椭圆曲线离散对数（ECDLP），抗量子攻击
- **递归友好**：FRI verification 可表达为电路，支持递归聚合（Plonky3 的设计目标之一）
- **算术友好**：可在小域（如 Goldilocks `p = 2^64 - 2^32 + 1`）上工作，prover 效率高

**劣势**：
- **Proof size 大**：典型 STARK proof 为 100KB-1MB，远大于 Hypernova+Groth16 的 ~2KB
- **Verifier time**：O(log N) 轮交互（虽为非交互式 Fiat-Shamir），每轮需 Merkle 验证，比 IPA 的 O(1) ~510µs 慢
- **域不兼容**：FRI 通常在小域（Goldilocks/BabyBear）上工作，与 BN254 标量域（~2^254）不同，跨域需额外处理
- **实现复杂度**：FRI + DEEP composition + 消防员（firewall）等组件实现量大

**兼容性分析**：
- FRI PCS 可替换 IPA PCS，但需重新实现 `commit`/`open`/`verify` 三个函数
- Hypernova 折叠算法依赖 PCS opening（cross-language claim），替换 PCS 不影响折叠逻辑本身
- **风险**：FRI 的 opening 语义与 IPA 不同 — IPA 打开多线性多项式在单点求值，FRI 验证多项式在低度扩展上的求值，语义映射需仔细设计

### 3.2 CCS 后端可替换性

CCS 的设计目标是泛化多种约束系统：

| 约束系统 | CCS 表示 |
|----------|----------|
| R1CS | 3 矩阵 (A, B, C)，1 subset {A, B}，coeff +1；1 subset {C}，coeff -1 |
| Plonkish | 多个 gate 矩阵 + copy constraints（permutation） |
| AIR | 多个 transition 约束矩阵 + boundary constraints |

**替换 PCS 的影响范围**：
- **不变**：CCS 结构、Hypernova 折叠算法、sumcheck 协议、trace 编译器
- **需修改**：`IpaPcs` → `FriPcs`（或 trait 抽象）、commit/open/verify 实现、cross-language claim 的 PCS opening 部分
- **需新增**：FRI 参数（rate、coset、security parameter）、Merkle tree（用于 FRI commitment）

**工作量估算**：
- PCS trait 抽象：~1-2 天
- FRI 实现（commit/open/verify）：~1-2 周
- cross-language claim 适配：~2-3 天
- 测试 + 集成：~3-5 天
- **总计**：~2-3 周

## 4. 对比矩阵

| 维度 | Hypernova+IPA+Groth16 | STARK+FRI |
|------|----------------------|-----------|
| **Proof size** | ~2KB（Groth16 压缩后 ~200B） | 100KB-1MB |
| **Prover time** | O(N) 折叠 + O(N) IPA commit | O(N log N) FRI |
| **Verifier time** | O(1) ~510µs（Hypernova） / O(1) ~ms（Groth16） | O(log² N) ~ms |
| **Trusted setup** | 否（IPA 透明）/ Groth16 需 ceremony | 否 |
| **Post-quantum** | 否（BN254 ECDLP） | 是 |
| **递归友好** | 是（CycleFold BN254/Grumpkin） | 是（FRI 递归） |
| **域** | BN254 标量域（~2^254） | Goldilocks/BabyBear（~2^64） |
| **实现成熟度** | 已实现 + 测试 | 未实现 |
| **市场采用** | RISC Zero（部分）/ 自研 | Plonky3/RISC Zero/StarkWare |

## 5. 建议

### 短期（当前-6 个月）
**保持 Hypernova+IPA+Groth16 为唯一后端**。

理由：
- Proof size 优势显著（~200B vs 100KB+），链上验证 gas 开销低
- 已实现且经过测试，无引入新 bug 的风险
- BN254 与 poker_l1 既有 Groth16 verifier 兼容
- Post-quantum 在当前业务场景非硬需求（扑克游戏不涉及长期机密）

### 中期（6-12 个月）
**评估 FRI 作为特定场景备选**。

触发条件：
- 出现明确的 post-quantum 需求（如治理决定支持抗量子签名）
- Plonky3 生态成熟，有可复用的高质量 Rust 实现
- 链上 gas 模型调整，大 proof 的验证成本可接受

实施路径：
1. 引入 PCS trait 抽象层（`Pcs` trait），支持 IPA/FRI 切换
2. 实现 `FriPcs`（基于 Plonky3 或自实现）
3. 适配 cross-language claim 的 FRI opening
4. 基准测试：FRI vs IPA 的 prover/verifier/proof size 对比

### 长期（12+ 个月）
**CCS 后端抽象层（trait-based PCS）**。

- `Pcs` trait 统一 IPA/FRI/其他 PCS
- 治理参数允许切换后端（类似 `verifier_status` 的 `Stub`/`Production` 切换）
- 支持混合模式：Hypernova 折叠用 IPA，最终压缩用 FRI（或反之）

## 6. 未选择方案

### 方案 B：立即实现 FRI
- **工作量**：~2-3 周
- **proof size 膨胀**：50-500x（从 ~200B 到 100KB+）
- **短期收益**：无（当前无 post-quantum 硬需求）
- **风险**：引入新实现 bug、域不兼容、cross-language claim 适配复杂
- **结论**：不推荐短期投入

### 方案 C：Plonky3 直接集成
- **依赖**：引入 `plonky3` crate
- **风险**：外部 crate 可能引入 `unsafe`（违反 `#![deny(unsafe_code)]`）
- **域问题**：Plonky3 默认 Goldilocks 域，与 BN254 不兼容
- **结论**：需先评估 Plonky3 的 unsafe 策略和跨域方案

### 方案 D：Brakedown/Orion
- **特点**：线性时间 prover，但 proof size 更大
- **成熟度**：学术阶段，无生产级实现
- **结论**：暂不评估

## 7. 形式化验证评估

### 7.1 现状
proptest 属性测试覆盖（Phase L 新增）：
- **域算术**：交换律、结合律、分配律、单位元、零元（`tests/formal_properties.rs`）
- **CCS satisfied_by**：合法 witness 通过 + 篡改 witness 失败（`tests/formal_properties.rs`）
- **LogUp 等式**：create → verify 闭环（`tests/formal_properties.rs`）
- **SparseMatrix**：row-isolated evaluate 正确性（`tests/formal_properties.rs`）
- **已有**：field.rs / transcript.rs / pcs/ipa.rs 的 proptest（Phase 1-1.5）

覆盖范围：核心数学不变量的随机属性测试，proptest 默认 256 cases。

### 7.2 Lean4/Coq 可行性评估

**优势**：
- 数学等式的机器检查证明（fold 等式 `C' = C_L + r·C_C`、LogUp 等式 `Σ m_i/(β-t_i) == Σ 1/(β-f_j)`）
- 不变量证明不依赖测试覆盖率，提供更强保证
- Lean4 社区活跃，有数学库支持

**劣势**：
- **学习曲线陡**：团队需学习依赖类型理论 + Lean4 tactics
- **与 Rust 代码绑定**：Lean4 证明验证的是数学规格，非 Rust 实现本身；需 extraction 或手动对应
- **维护成本高**：代码变更时需同步更新证明
- **无现成框架**：poker_zkvm 的 CCS/Hypernova 无现成 Lean4 规格

**建议**：
- **短期**：以 proptest 为主，覆盖核心不变量的随机属性
- **中期**：对 Hypernova fold 等式编写 Lean4 形式化证明（独立项目，不阻塞主线开发）
- **长期**：评估 Lean4 规格提取工具（如 Aeneas），实现 Rust → Lean4 的半自动规格映射

### 7.3 推荐下一步

1. **扩展 proptest 到 fold 等式**（Phase L+1）
   - 构造可折叠的随机 CCS 实例
   - 验证 `fold_step` 后 `C' = C_L + r·C_C` 在域上成立
   - 依赖：需实现随机 CCS 实例生成器

2. **Hypernova fold 等式 Lean4 证明**（独立项目）
   - 规格：LCCCS + CCCCS → folded LCCCS 的数学定义
   - 证明：folded instance 满足 relaxed CCS 约束
   - 参考：Hypernova 原论文的 correctness proof

3. **TLA+ executor 状态机规格化**（评估）
   - 对 ISA executor 的状态转移编写 TLA+ 规格
   - 验证 safety（无非法状态转移）和 liveness（终止性）
   - 适用场景：复杂控制流（分支、跳转、syscall 分派）

## 8. 结论

| 子项 | 决策 | 理由 |
|------|------|------|
| STARK fallback 实现 | 不实现（短期） | proof size 膨胀 50-500x，短期无 post-quantum 硬需求 |
| PCS trait 抽象 | 中期规划 | 为未来 FRI 集成预留接口 |
| 形式化验证 | proptest 为主 | 覆盖核心不变量，Lean4 留作长期投资 |
| Fold 等式 proptest | Phase L+1 | 需随机 CCS 实例生成器基础设施 |
