# Rust → Lean 证明方案详细清单（闭合手工镜像信任缺口）

> 承接 `lean-verify-texas-poker-state-machine.md`（2026-07-28 完成状态）的**已知限制 #3**：
> "Rust 源码未在 Lean 中嵌入（无 Rust frontend）：精化论证基于手工镜像"。
> 以及 `PokerLean/Audit/TrustBoundary.lean:61-68` 诚实声明的缺口：
> `rustAirEquivalence = false`、`vmEndToEndRefinement = false`。
> 本文详细列举把**真实 Rust 代码**与 **Lean 模型**连接起来的全部可行方案、
> 各自的信任基座、适用范围、工作量与风险，并给出分阶段落地路线。

## 0. 现状基线（所有方案的出发点）

### 已有资产

| 资产 | 位置 | 规模 | 状态 |
|---|---|---|---|
| Lean 状态机模型 + 定理 | `poker_lean/PokerLean/State/`（14 文件） | 5,746 LOC | 无 sorry，仅标准三公理 |
| 手写 AIR soundness（21 selector） | `poker_lean/PokerLean/{Contract,AIR,Proofs}/` | ~143k LOC 总计 | 无 sorry |
| 精化论证（映射表 + panic-freedom） | `State/Refinement.lean` | 597 LOC | 文档化 + 部分桥接引理 |
| 机器可查信任边界 | `Audit/TrustBoundary.lean` | — | `ClaimScope` 布尔声明 |
| Rust 合约 | `poker_l1/src/vm/contracts/texas_poker/` | 19,001 LOC | 被验证对象 |
| Rust AIR 电路 | `poker-appchain-texasair/` | — | 方案 D 对象 |

### 缺口本质

当前所有 Lean 定理的形如 `Lean 谓词 A → Lean 谓词 B`（模型内蕴含），
而 **"真实 Rust 代码满足 Lean 谓词"这一步完全没有机器检查**：
`Refinement.lean` 只有 Rust file:line 锚定的映射表和 checked_add/sub 的
panic-freedom 论证。Rust 侧任何改动都会使 Lean 镜像**静默陈旧**
（风险表"类型镜像再次陈旧"）。

Rust 合约分层（决定方案可行性）：

```
19,001 LOC 总量
├── 纯算法层（无密码学、无 IO）           ~1,641 LOC   ← 方案 A1 目标
│   ├── constants.rs  190   （纯常量）
│   ├── card.rs       497   （纯位运算/枚举）
│   ├── betting.rs    242   （纯算术，仅 import constants + borsh/serde derive）
│   ├── side_pot.rs   141   （纯算术 + 迭代器链 side_pot.rs:20）
│   └── hand_evaluator.rs 571（纯算术/位运算）
├── 编解码层                              ~523 LOC    ← 方案 A2 目标
│   └── state_codec.rs（borsh 序列化；连接 texasPokerTableToPreimage axiom）
├── 状态机/结算层（含密码学 gating）       ~7,700 LOC  ← 方案 A3 目标
│   ├── state_machine.rs 5,868
│   ├── settlement.rs      932
│   └── types.rs         3,716（结构定义 + 部分 impl）
├── 密码学交互层（poker_protocol 调用）    ~2,500 LOC  ← 永远不透明处理
│   └── ElGamal / DLEqProof / RevealTokenProof / CurvePoint
└── dispatch/事件/证明任务/测试           ~6,600 LOC  ← 按需
```

---

## 方案 0 —— 手工镜像 + 映射表审计（现状基线）

- **机制**：人工把 Rust 语义翻译成 Lean 全函数；`Refinement.lean §1` 列出
  每个字段的 Rust file:line 对应；`§2` 列出 panic 义务并用 `rust_checked_add/sub`
  建模逐一 discharge；`§5` 论证 `total_chips ≤ U64_MAX` 不需要成立。
- **信任基座**：人工审查（最弱）。
- **优点**：已经完成；Lean 侧代码干净（有 simp 引理、可读），是后续一切方案的
  **规范侧资产**——任何自动提取方案最终都要证明"提取代码 ≡ 这个干净模型"。
- **缺陷**：无机器检查；Rust 演进会静默破坏对应关系；无法把
  `TrustBoundary.ClaimScope` 的任何 `false` 翻成 `true`。
- **结论**：作为基线保留，不单独前进。

---

## 方案 A —— Charon + Aeneas 自动提取（主推路线，分 4 批）

### 原理与工具链

```
cargo (nightly) ──rustc driver──▶ MIR ──Charon──▶ LLBC ──Aeneas──▶ Lean 4 纯函数
```

- **Charon**：挂载 rustc driver，把编译后的 MIR 降为带类型的
  LLBC（Low-Level Borrow Calculus）。
- **Aeneas**：利用 Rust borrow checker 的保证，把每个（可通过的）Rust 函数翻译为
  Lean 4 **纯函数**：可变状态变为状态传递参数，panic 变为 `Result` 错误返回，
  循环变为递归。同时自动生成每个函数的 `panic_free` 证明义务。
- **2026 状态**：活跃维护；Runtime Verification 已用该管线验证 Zcash 共识
  算术/解析（生产级密码学 Rust），并以 AI prover 辅助消化证明义务
  （arXiv 2026-07 "A Rust-to-Lean Verification Pipeline with AI Provers"）。
  这与 `.trae/specs/build-hypernova-zkvm/stark_fallback_evaluation.md:189`
  "长期：评估 Lean4 规格提取工具（如 Aeneas）"的规划一致。

### 信任基座变化

人工审查 → **{ rustc/MIR, Charon, Aeneas 翻译, Lean kernel }**。
前三者是新增信任根，但都是被广泛复用的确定性工具（且 Charon/Aeneas 开源可审计），
远弱于"人没看错 19k LOC"。

### 关键产出模式（每批相同）

```lean
-- Extracted/Betting.lean（Aeneas 生成，不手改）
def rust_process_call (r : BettingRound) (sb : Nat) : Result Nat := ...

-- Bridge/Betting.lean（手写）
theorem rust_process_call_eq_model (r sb) (h : preconditions):
    rust_process_call r sb = ok (TexasPoker.process_call r sb) := ...
-- 于是全部 State/ 已有定理经等价定理直接传导到真实 Rust 语义
```

**注意**：不在提取代码上直接证 chip 守恒等深性质（提取代码冗长、无 simp 引理，
证明成本高）；而是证"提取 ≡ 干净模型"的逐函数等价，让 5,746 LOC 已有定理
零成本传导。这是 RV Zcash 案例验证过的标准模式。

### 分批落地

#### A1 —— 纯算法层（~1,641 LOC，最高性价比，第一个做）

- **对象**：`constants.rs` / `card.rs` / `betting.rs` / `side_pot.rs` / `hand_evaluator.rs`。
- **前置重构（Rust 侧，语义等价的纯重构）**：
  1. `side_pot.rs:20` 等迭代器链（`(0..16).filter(..).collect()`、`sort_unstable`）
     重写为带下标的 for 循环——Charon 对闭包/`Iterator` trait 支持有限，
     官方建议就是改成显式循环；
  2. `betting.rs:1-2` 的 `borsh/serde` derive 属于 IO 层，提取时剥离
     （常量层不需要序列化）；
  3. 确认无 `dyn`/函数指针/`unsafe`（初查未见）。
- **产出**：`PokerLean/Extracted/{Constants,Card,Betting,SidePot,HandEvaluator}.lean`
  + `PokerLean/Bridge/*.lean` 等价定理集。
- **闭合的缺口**：已知限制 #3 在**核心算法域**（side pot 守恒、hand evaluator
  全序、betting 规则）被机器检查闭合——这三块恰是资金安全最敏感的纯逻辑。
- **工作量估计**：Rust 重构 1-2 天；Charon/Aeneas 跑通 2-4 天（工具链适配）；
  等价证明 1-2 周（`evaluate_best` 的 21 组合枚举在提取代码上仍是最难点）。

#### A2 —— 编解码层（`state_codec.rs` 523 LOC）

- **对象**：borsh 编解码 + `texasPokerTableToPreimage`。
- **价值**：把自定义信任根 `PokerLean.texasPokerTableToPreimage` 从 axiom
  降为定理（提取的 Rust 编码 ≡ Lean 编码函数），直接削减
  `remainingCustomTrustRoots`（`TrustBoundary.lean:85-86`）。
- **风险**：borsh 依赖外部 crate 序列化框架，需把 `to_bytes` 路径中
  本合约自己的字段编码逻辑提取出来（字段级 encode 是手写算术，可提取；
  框架 trait 层不透明）。
- **工作量**：~1 周。

#### A3 —— 状态机/结算层（`state_machine.rs` 核心 apply_*/advance_* 子集）

- **对象**：`apply_fold/check/call/raise`、`advance_round/shuffle/reveal`、
  `collect_ante/rake`、`end_without_showdown`、`reset_for_next_hand`
  （与 `State/Transitions.lean`、`State/Theorems.lean` 已覆盖的函数一一对应）。
- **前置**：`types.rs` 64 字段结构提取（Aeneas 支持，结构体直接映射）；
  密码学字段（`ECPoint`/`DLEqProof`/`CurvePoint`）作为**不透明类型参数**——
  Aeneas 对外部 crate 代码用 `assume`，但状态机函数只对它们做判等/透传，
  不需要内部结构（与现有 `State/Types.lean` 的不透明占位策略一致）。
- **工作量**：3-6 周（等价定理数量 = State/ 中已证函数数量，逐个传导）。
- **产出**：`vmEndToEndRefinement` 可以诚实升级为
  "核心状态转移函数级精化（密码学不透明）"。

#### A4 —— 全量 dispatch + selector 21/22（视需要）

- 现有 21 selector 模型 + Rust fail-closed 的 21/22；只在产品需要时补。

### 工具链适配注意

1. 仓库 Rust 锁 `nightly-2026-04-15`（`rust-toolchain.toml`，Stwo 需要）。
   Charon 对 rustc 版本敏感：建议**单独的提取 CI job** 用 Charon 支持的
   nightly 版本编译同一份源码（rust-toolchain override），不影响主构建。
2. Lean 锁 4.13.0 + Mathlib v4.13.0（`poker_lean/lean-toolchain`）。
   Aeneas 生成的代码 + Aeneas 库需与 4.13 兼容；若 Aeneas 现行版要求更新
   Lean，优先固定 Aeneas 旧版而非升级 Mathlib（风险表第 4 条）。
   最坏情况：Aeneas 输出与 Mathlib 不同库、只依赖核心 `Result` 定义，
   版本压力很小。
3. 提取产物**不手改**、放独立 `PokerLean/Extracted/`，`Bridge/` 承载全部手写
   等价证明，`PokerLean.lean` 顶层 import 分开管理。

---

## 方案 B —— 深嵌入 LLBC/MIR 解释器（Aeneas 的兜底替代）

- **机制**：在 Lean 中为 LLBC（或 MIR 子集）写**深嵌入解释器**
  （指令集 + 语义关系/可执行解释器），证明"解释器执行 ⊨ Lean 模型"，
  即编译器正确性风格（类似 CompCert 汇编语义 vs C 语义）。
- **适用**：仅当 Charon 对本合约某构造（如 `reconstruction_v3` vendored 模块、
  泛型曲线代码）提取失败、且该构造无法重构时，**局部**为该子集自写解释器。
- **代价**：等于自写 mini-Aeneas（指令语义 + 内存模型 + 类型布局），
  工程量 1-2 月起，且引入自写语义的正确性问题——**不如重构 Rust 代码**。
- **结论**：不主动采用；仅记录为 Aeneas 硬失败时的逃生通道。

---

## 方案 C —— Lean 可执行规范 + Rust 差分对拍（非证明，立即落地）

- **机制**：`State/` 模型全是 Lean 全函数，**本身可执行**
  （`lake env lean --run` / 编译 C 后端二进制）。Rust 侧用 proptest 生成
  随机输入（合法状态 + 动作序列），同时喂给真实 Rust 合约函数与 Lean 模型
  `#eval`，断言输出逐字段一致。
- **覆盖**：betting / side_pot / hand_evaluator / apply_* 状态转移。
- **价值**：
  1. **防镜像陈旧**——Rust 任何语义改动立刻在对拍中爆出（风险表第 3 条的
     直接缓解），这是方案 A 落地前唯一的经济护栏；
  2. 为方案 A 的等价定理提供反例 hunter（对拍失败 = 等价定理有洞）。
- **限制**：不是证明；密码学路径无法对拍（Lean 侧本就不透明）。
- **工作量**：2-4 天（Lean CLI runner + Rust proptest harness + CI job）。
- **结论**：**立即做**，与 A1 并行。

---

## 方案 D —— AIR 等价闭合（`rustAirEquivalence`，信任削减最大的一步）

### 与方案 A 的关系

方案 A 证明"Rust 合约代码 ≡ Lean 合约模型"；方案 D 证明
"**Rust AIR 电路约束 ≡ 手写 Lean AIR 谓词**"。后者对象小得多
（约束求值是纯算术函数，无密码学、无 64 字段状态），而信任收益更大，
因为它接上的是**已经在生产的 ZK 证明系统**。

### 信任链（闭合后）

```
ZK 证明（Stwo，证明真实执行满足 Rust AIR）        ← 生产路径已有
  + Rust AIR 求值 ≡ Lean AirAcceptable          ← 方案 D（机器检查）
  + Lean AirAcceptable → Lean Contract 语义      ← 已有 21 selector 无 sorry
  ⇒ 真实执行 ⟹ 合约业务语义                       ── 端到端（密码学 proof 系统 soundness 除外）
```

### 具体步骤

1. 定位 `poker-appchain-texasair/` 中每个方法 M 的约束求值函数
   （`BoundAir` 的列布局 + 约束多项式求值——纯整数算术）。
2. Charon/Aeneas 提取这些函数 → `PokerLean/Extracted/Air/*.lean`。
3. 证符号行等价：`∀ row, rust_air_eval_M row = (AirAcceptable_M row : Prop 的可判定求值)`。
4. 建模 `expected_trace_row → BoundAir → transcript` 公开输入绑定
   （这是 `TrustBoundary.lean:38-40` 点名的缺口），至少文档化 + 部分形式化。
5. 翻转 `ClaimScope.rustAirEquivalence := true`（逐 selector 翻，从
   fold/check/call/raise/bet 五个资金敏感方法开始）。

### 工作量与风险

- 单方法 AIR 约束 ~50-200 行纯算术，提取容易；难在第 4 步（transcript/布局
  涉及 Stwo 内部结构，需在 Lean 里定义物理列布局镜像并证求值一致）。
- 估计：首方法 2-3 周（含布局镜像模式建立），后续每方法 2-5 天，五个核心
  方法 ~5-6 周。

---

## 方案 E —— 其他证明器中转（列出以完整性，不推荐）

| 路径 | 说明 | 为何不选 |
|---|---|---|
| Verus（SMT） | Rust 原地验证，非线性算术弱 | 非 Lean；已有 5,746 LOC Lean 资产无法复用 |
| Creusot（Why3） | Rust → WhyML，Pearlite 逻辑 | 非 Lean；桥接 Why3→Lean 无工具 |
| Kani（模型检查） | 有界穷举 | 不是证明；可作方案 C 的补充对拍 |
| coq-of-rust → Coq | MIR → Coq Gallina | Coq→Lean 无成熟翻译器；纯绕路 |
| Eurydice（Rust→C） | 同组工具，产出可读 C | 用于交叉审计对照，非 Lean 证明 |

唯一例外：Kani 可作为方案 C 的加强版（符号执行 vs 随机对拍），低成本补充。

---

## 方案 F —— 信任边界的机器化沉淀（贯穿所有方案的度量）

每个方案落地一块，同步更新 `Audit/TrustBoundary.lean`：

- `ClaimScope` 对应布尔逐个翻 `true`（附引用等价定理名）；
- `remainingCustomTrustRoots` 随 A2 收缩（去掉 `texasPokerTableToPreimage`）；
- `SoundnessAudit.lean` 的 `#print axioms` 清单随之缩短；
- selector 21/22 若补做，`allVmSelectorsCovered` 可翻 `true`。

这保证"能声称什么"永远是机器可查的，防止证明资产与宣传口径漂移。

---

## 方案对比总表

| 方案 | 机制 | 机器检查 | 覆盖 | 工作量 | 信任基座变化 | 建议 |
|---|---|---|---|---|---|---|
| 0 手工镜像 | 人工翻译+映射表 | ✗ | 全部（弱） | 已完成 | 人工审查 | 保留基线 |
| A Charon+Aeneas | MIR→LLBC→Lean 纯函数 | ✓ | A1 纯算法→A3 状态机 | A1 2-3 周；A3 3-6 周 | +rustc/Charon/Aeneas | **主推** |
| B LLBC 解释器 | 深嵌入自写语义 | ✓ | Charon 失败子集 | 1-2 月+ | +自写语义 | 仅兜底 |
| C 差分对拍 | Lean 可执行规范 vs proptest | ✗（测试） | 纯算法+转移 | 2-4 天 | 无（置信） | **立即做** |
| D AIR 等价 | 提取电路求值≡Lean AIR | ✓ | 5 核心→21 selector | 首法 2-3 周，后 2-5 天/法 | +提取工具 | **第二优先** |
| E 其他证明器 | Verus/Creusot/Kani/Coq | 部分 | — | — | — | 不采用 |
| F 信任边界沉淀 | ClaimScope 翻位 | ✓ | 元层面 | 持续 | 无 | 贯穿执行 |

## 推荐执行顺序

```
立即（并行）：C 差分对拍护栏（2-4 天）
第一阶段：  A1 纯算法提取 + 等价（2-3 周）── 闭合核心算法域的已知限制 #3
第二阶段：  D AIR 等价·五核心方法（5-6 周）── 翻转 rustAirEquivalence（最大信任削减）
第三阶段：  A2 编解码（1 周）+ A3 状态机子集（3-6 周）
贯穿：      F TrustBoundary 逐项翻位
兜底：      B 仅当 Charon 硬失败且不可重构
```

优先级论证：A1 性价比最高（1,641 LOC 纯代码、无密码学、RV Zcash 案例同构）；
D 排第二而非 A3，因为它把"真实执行"（经 ZK 系统）接入信任链，比
"更多合约函数的等价"对最终端到端声明的贡献更大；A3 工作量最大放最后。

## 验证方法（每阶段通用）

```bash
# Lean 侧
cd /Users/mac/projects/zchain/poker_lean
lake build                                    # 全量（含 Extracted/Bridge）
grep -rn "sorry\|admit\|sorryAx" PokerLean/Extracted/ PokerLean/Bridge/  # 应无（Aeneas 的 assume 需单独审计清单）
lake env lean PokerLean/Audit/TrustBoundary.lean  # ClaimScope + #print axioms

# Rust 侧（方案 A 前置重构不得改变行为）
cd /Users/mac/projects/zchain/poker_l1
cargo test -p poker-l1 texas_poker            # 现有单测全绿
# 方案 C 对拍
cargo test -p poker-l1 differential -- --nocapture
```

## 不在范围内（沿袭原文档边界）

- Mental Poker 密码学协议内部正确性（VRF/ElGamal/Chaum-Pedersen/ZK proof system）
  ——方案 A 中永远不透明处理，其 soundness 由 ZK 验证与 fail-closed gating 承担
- Stwo/多项式承诺/FFT 等 ZK 后端 soundness（信任根，不重证）
- `poker_protocol` crate 内部（vendored reconstruction_v3 除外，可按 A3 处理）

---

## ✅ 方案 C 实施记录（2026-09-24）

### 交付物

| 文件 | 作用 |
|---|---|
| `poker_l1/src/vm/contracts/texas_poker/tests/differential.rs` | Rust 侧生成器：xorshift64* 固定种子，12,000 用例（B×3000 / SP×2000 / EB×5000 / EBP×1000 / W×1000）写入 `$ZCHAIN_DIFF_DIR`（默认 `/tmp/zchain_diff`） |
| `poker_l1/src/vm/contracts/texas_poker/tests/mod.rs` + `mod.rs` 接线 | `#[cfg(test)] mod tests;` |
| `poker_lean/Differential/Main.lean` | Lean 侧 runner：读同一份向量，`State/` 模型求值，逐行比对，非零退出码 |
| `poker_lean/lakefile.lean` | 新增 `lean_exe differential`（原生编译，避免解释器栈溢出） |
| `scripts/lean_diff_check.sh` | 一键对拍：`cargo test` 生成 → `differential` 比对 |

### 运行方式

```bash
scripts/lean_diff_check.sh          # 退出码 0 = 全一致
```

### 首轮结果：抓到 2 个真实镜像 bug（这正是本护栏的目的）

**B（betting）与 SP（side pot）2 域 5,000 例全部一致**——镜像保真 ✓。
**EB/EBP/W 域 3,847 例不一致**，根因两个，均在 `State/HandEvaluator.lean`：

1. **`build_groups` 缺少排序**（重大）：Lean 版按点数升序产出分组，而
   `evaluate_five` 判定链假设 `groups[0]` 是最大计数组。Rust
   （`hand_evaluator.rs:170-180`）先按 `(count, rank)` 字典序降序排序再判定。
   后果：**漏判所有跨花色对子**（如 ♥4+♠4 不算 pair）、TWO_PAIR/ONE_PAIR 的
   kicker 顺序反向。修复：新增 `pair_ge`/`sort_groups_desc`/`pad_groups`
   （镜像 Rust 的 sort + `(0,0)` 填充），重写 `build_groups`。
2. **`evaluate_best` <5 张填充花色不循环**：Lean 用 `Card.new 0 0` 全同花色
   填充，Rust（`hand_evaluator.rs:117-123`）花色 0,1,2,3 循环（避免伪同花）。
   后果：≤3 张真实同花色牌会被 Lean 误判为 FLUSH。修复：
   `(List.range (5-n)).map (fun i => Card.new (i % 4) 0)`。

### 修复后状态

- 差分对拍：**12,000/12,000 PASS**（5 域全绿）
- `lake build` 全量通过：Phase 4 全部既有定理（全序性 / best-is-maximum /
  决定性）在修正后的 `evaluate_five` 上仍然成立（定理均关于函数结构性质，
  不依赖分组内部顺序）
- sorry 审计保持 0

### 影响评估

被修复的两处 bug 属于"模型算错牌"，若未来把 Phase 4 定理用于任何下游论证
（如按 HandRank 分池正确性），旧模型会给出错误结论。**这说明在无 Rust
frontend 的手工镜像模式下，差分对拍是必要护栏**——方案 A（Aeneas 提取）
落地后此脚本继续作为 CI 回归使用。

---

## ✅ 方案 A1 实施记录（2026-09-24，进行中）

### 已达成

1. **工具链**（`tools_external/aeneas/`）：Aeneas nightly-2026.09.23 官方 tarball
   （含 aeneas + charon + charon-driver 二进制）+ `rustup nightly-2026-09-17`
   （charon 锁定的 rustc）。Aeneas Lean 库依赖 **Mathlib v4.31.0**（云缓存拉取），
   与 `poker_lean`（4.13）版本隔离。
2. **Rust 侧提取友好重构**（`poker-settlement-core/src/side_pot.rs`，36 单测 +
   12,000 对拍全绿，语义零变化）：
   - `sort_unstable` + `(0..n).filter().map().collect()` → 显式循环 +
     本地 `insert_sorted_u64`（与 Lean `insert_sorted` 同构）——消除
     `core::slice::sort` 深层泛型（首次提取因它在 charon 转换 pass 卡 50+ 分钟）
   - `total()` 的 `iter().map().sum()` → 显式下标循环——消除 core::iter
     Map/Sum 适配器（生成器与库的 Iterator 结构版本偏斜，map/sum 字段冲突）
   - `last_mut().expect("pots 非空")` → `pop()`+`push()` 回写——绕开生成器对
     `Option.expect` 错误解构的 bug（同时中文 panic 消息触发转义 bug，改 ASCII）
3. **提取管线打通**：
   ```
   charon cargo --preset=aeneas --start-from crate::side_pot（~1 分钟）
     → LLBC（1.2 MB，13 个条目）
   aeneas -backend lean -split-files → 4 个 Lean 文件（~1000 行）
   ```
   产物在 `poker_lean_extracted/PokerSettlementCore/`（独立 Lake 项目，
   Lean 4.31 + Aeneas 库路径依赖 + Mathlib v4.31 云缓存），**编译通过**。
   提取的 `calculate_side_pots` 忠实镜像 Rust 控制流（长度检查 → sum_bets try
   分支 → loop0 水位收集 → loop1 分层 → 外层兜底）。
4. **Model/ 移植**：`poker_lean_extracted/PokerLeanExtracted/Model/`——4.13 项目
   手写模型的 Mathlib-free 纯定义副本（Constants/Card/Betting/SidePot/
   HandEvaluator，含对拍修复），供 Bridge 定理引用。
5. **Bridge 首批等价定理**（`Bridge/SidePot.lean`，无 sorry，`#print axioms`
   仅标准三公理）：
   - `side_pot_new_ok` / `side_pot_new_to_model`：提取 `SidePot::new` ≡ ok 构造
     ≡ 模型构造（rfl 级）
   - `seat_bit_equiv`：提取 `seat_bit j = ok (2^j)`（j < 16），经
     `UScalar.shiftLeft` / `BitVec.shiftLeft` / `Nat.one_shiftLeft` 链证明

### 关键经验（后续提取的 playbook）

- `--start-from crate::<模块>` 才能限定范围；`--include` 不会缩小默认起点。
- 提取前先消 std 深水区：`sort_unstable`、迭代器链、`expect`——显式循环 +
  Vec push/pop 是 Aeneas 最友好形态（这也让 Bridge 证明更容易）。
- `--extract-opaque-bodies` 会让 Aeneas 在某 std 枚举 discriminant 上崩溃
  （OCaml `Z.to_int` 溢出），不要用。
- Aeneas 2026 的 `Result` 是 `@[irreducible] ITree RustEffect`：纯值 `ok` 可
  `rfl`，但 `<$>`/bind 需 ITree 引理（`itree_ret_bind` 等）；标量运算用库的
  `simp only [HShiftLeft.hShiftLeft, UScalar.shiftLeft_UScalar, ...]` 链。
- 工具链版本偏斜真实存在（二进制 vs 库）：遇到"结构缺字段/解构错"先怀疑
  版本，其次用 Rust 重构绕开。

### 下一步（按优先级）

1. `insert_sorted_u64 ≡ insert_sorted`、`is_eligible` 等价（小步快跑）
2. Vec ↔ List 表示转换引理集 → `sum_bets` / `slice_layer` / `push_or_merge`
   / `calculate_side_pots` 全函数等价（Bridge 主定理）
3. 提取 `poker_l1` 纯算法层（betting / card / hand_evaluator / constants），
   同一管线
4. 提取侧差分对拍（`-all-computable` + 同一套 12,000 向量跑提取代码）


