# PokerLean — Texas Poker AIR Soundness 形式化验证

## 项目目标

使用 Lean 4 定理证明器分析 `poker_texas_air` 的 AIR 电路约束，并以最终建立
“真实 Rust AIR 接受 ⇒ `poker_l1` 合约语义成立”的实现级 soundness 为目标。
当前版本尚未闭合 Rust AIR、公开输入接线与 VM 实现之间的精化桥。

### Soundness 的形式化定义

对每个方法 M：

```lean
∀ (row : CommonRow) (ext : MethodColumns_M),
  AirAcceptable_M row ext →
  ContractSemantics_M (extractPre row ext) (extractPost row ext)
```

**含义**：任何满足 AIR 电路约束的 trace 行，其对应的状态转换
也一定满足合约的业务语义约束。

> **当前边界**：仓库中的 theorem 只对手写 Lean `AirAcceptable` 与
> `ContractSemantics` 谓词建立上述蕴含；尚未证明这些谓词与真实 Rust 实现等价。
> 机器可检查的范围声明与公理审计见 `PokerLean/Audit/TrustBoundary.lean`。

call/raise/bet 的当前 `Contract*` 谓词是 **mid-round 局部语义**：
筹码从 stack 移入 `seat.bet`，pot 不变，round 不变。VM 后续的
`advance_turn` 可能收池、推进 round 或 settlement；这些 end-of-round 分支
尚未形式化为 Rust↔Lean 完整精化。即使在 mid-round，raise/bet 对其他玩家
`acted_this_round` 的重置等字段也仍未在这些 Contract 中完整建模。

对应的手写 Lean AIR 已同步 verifier-trusted pre-state 金额、Nat 级 checked-u64
规则、actor `all_in` 更新、short all-in/conditional min-raise 和 `post_current_turn`；bet 仅允许
FLOP/TURN/RIVER。但这只是 logical spec 同步：Rust physical column layout 及
`expected_trace_row → BoundAir → transcript` 的 refinement 尚未证明。Lean bet 的
post `current_bet`/`min_raise` 目前是 canonical post table 的逻辑重建字段，不是 Rust
`BetRow` 的独立 physical columns。

## 快速开始

### 前置要求

- [elan](https://github.com/leanprover/elan) (Lean 版本管理器)
- Lean 4.13.0
- Lake (Lean 构建工具)

### 安装

```bash
# 安装 elan
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

# 安装指定版本 Lean
elan install leanprover/lean4:v4.13.0

# 克隆项目
cd poker_lean
```

### 构建验证

```bash
# 更新依赖（mathlib）
lake update

# 构建项目
lake build

# 或者检查特定文件
lake env lean PokerLean.lean
```

### 在 VS Code 中使用

1. 安装 `lean4` 扩展
2. 打开 `poker_lean` 文件夹
3. 等待 Lean 服务器启动
4. 打开任意 `.lean` 文件，查看类型检查和证明状态

## 项目结构

```
poker_lean/
├── lakefile.lean              # Lake 项目配置
├── lean-toolchain             # Lean 工具链版本
├── PokerLean.lean             # 主入口（所有模块导入）
├── Common/                    # 基础类型层
│   ├── M31.lean              # M31 有限域定义与性质
│   ├── U64Encoding.lean      # u64 ↔ 4×M31 limb 编解码
│   └── CommonColumns.lean    # 37 通用列布局与约束
├── Contract/                  # 合约语义层
│   ├── Types.lean            # 核心数据结构
│   ├── Constants.lean        # 常量定义
│   ├── CreateTable.lean      # create_table 语义谓词
│   └── Fold.lean             # fold 语义谓词
├── AIR/                       # AIR 电路约束层
│   ├── AirBase.lean          # AIR 接受谓词基础
│   ├── CreateTableAir.lean   # create_table AIR 约束
│   └── FoldAir.lean          # fold AIR 约束
├── Proofs/                    # Soundness 证明层
│   ├── CreateTableSoundness.lean  # create_table 证明
│   └── FoldSoundness.lean    # fold 证明（含反例）
└── Audit/                     # 审计与信任边界
    ├── TrustBoundary.lean    # 可执行范围声明 + 21 theorem 公理审计
    └── SoundnessAudit.lean   # 当前审计结论（模型内，不夸大为实现级）
```

## 架构设计

### 三层模型

1. **Contract 层**：合约的业务语义，用 Lean 归纳谓词定义
2. **AIR 层**：电路的约束条件，基于 M31 域和列布局
3. **Proof 层**：从 AIR 约束推导出合约语义的证明

### 状态提取函数

每个方法 AIR 都有对应的状态提取函数：

```lean
extractPreTableFromAir  : CommonRow → MethodColumns → TexasPokerTable
extractPostTableFromAir : CommonRow → MethodColumns → TexasPokerTable
extractParamsFromAir    : MethodColumns → MethodParams
```

这些函数将电路列投影为合约语义的状态对象，是连接两层的桥梁。

### 证明方法

**正例（soundness 成立）**：
- 假设 AIR 约束成立
- 逐条证明合约语义的每个合取支
- 使用 limb 解码引理、算术推理等

**反例（soundness 不成立）**：
- 构造一个满足 AIR 约束的行
- 证明它不满足合约语义的某个条件
- 得出存在性结论

## 当前已完成

- M31、u64 limb 编解码、Contract/AIR/State 的手写 Lean 模型。
- selector 0--20 的 21 个模型内 theorem wrapper；它们均能通过 Lean 类型检查。
  当前 Rust/VM selector 21 `request_leave_after_hand` 与 22 `fold_with_proof`
  没有 Lean 模型或定理，生产证明路径也对二者 fail-closed。
- call/raise/bet 的 verifier-trusted 金额、checked-u64 局部规则、下一行动座位与
  actor `all_in`、same-round pot/round 不变语义已在手写 Lean 模型中同步；bet 排除 PREFLOP。
- State 层若干不变量、筹码守恒和座位级 Rust 算术镜像证明。
- `TrustBoundary.lean` 中的机器可检查范围声明与 `#print axioms` 审计。
- 删除了数学上不可能的“任意长度 Poseidon 输入精确单射”公理。

## 当前覆盖评级

| 层次 | 状态 | 可声称内容 |
|------|------|------------|
| Lean 模型内蕴含 | ✅ 已建立 | `Lean AirAcceptable → Lean Contract` |
| 当前全部 VM selector | ❌ 未覆盖 | Lean 仅有 0--20；21/22 无模型内定理 |
| Lean theorem 的公理依赖 | ✅ 已审计 | 剩余自定义信任根为哈希函数与状态编码函数 |
| Rust AIR ↔ Lean AIR | ❌ 未建立 | 不能把 theorem 直接套到 `FrameworkEval::evaluate` |
| VM 完整转移 ↔ Lean Contract | ❌ 未建立 | caller、轮次推进、结算等未完成精化 |
| public input / state-root / trace | ❌ 未建立 | 不能声称 witness 已绑定到公开状态 |
| Host receipt / Aggregator / 密码学子证明的 Lean 模型 | ❌ 未建立 | Rust P05-H-core 已有 O(N) host 验证与 anchor 校验；H-source 尚未接共识来源，P05-R 仍 fail-closed；均未在 Lean 精化 |

详细结论见 `PokerLean/Audit/SoundnessAudit.lean`。

## 后续工作

1. 把真实 Rust AIR 的每个 `add_constraint` 机械化或生成到 Lean，并证明逐项等价。
2. 建立 trace 列、公开输入、state-root preimage 与 Lean 状态提取之间的编码定理。
3. 修正 Contract，使其覆盖 VM 的 caller/creator 授权、`advance_turn`、收池和结算。
4. 将 State 层的座位级镜像扩展为完整桌台级 refinement。
5. 单独形式化 Aggregator 与外部密码学 proof verifier；完成后再升级实现级结论。

## 相关代码库

- **poker_texas_air**：`../poker_texas_air/` — Rust 实现的 AIR 电路
- **poker_l1**：`../poker_l1/` — Move/Rust 合约实现
- **poker_protocol**：密码学协议库

## License

与主项目一致。
