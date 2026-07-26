# PokerLean — Texas Poker AIR Soundness 形式化验证

## 项目目标

使用 Lean 4 定理证明器，形式化验证 `poker_texas_air` 的 AIR 电路约束
对于 `poker_l1` 合约语义是 **sound**（充分的、可靠的）。

### Soundness 的形式化定义

对每个方法 M：

```lean
∀ (row : CommonRow) (ext : MethodColumns_M),
  AirAcceptable_M row ext →
  ContractSemantics_M (extractPre row ext) (extractPost row ext)
```

**含义**：任何满足 AIR 电路约束的 trace 行，其对应的状态转换
也一定满足合约的业务语义约束。

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
└── Audit/                     # 审计报告
    └── SoundnessAudit.lean   # 21 方法整体审计
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

## 已完成的工作

### 1. 基础类型形式化
- ✅ M31 有限域（加法、乘法、binality）
- ✅ u64 ↔ 4×M31 limb 编解码
- ✅ 37 通用列布局与约束
- ✅ MethodKind 枚举（21 个方法）

### 2. 合约数据结构
- ✅ Seat（含 folded, all_in, is_waiting 等布尔字段）
- ✅ SeatStatus 派生枚举
- ✅ RoundState 枚举
- ✅ BettingRoundState
- ✅ TexasPokerTable 完整结构

### 3. create_table 方法
- ✅ 合约语义谓词 `ContractCreateTable`
- ✅ AIR 约束 `CreateTableAirAcceptable`
- ✅ Soundness 定理（弱版本，含额外假设）
- ✅ 存在性定理

### 4. fold 方法
- ✅ 合约语义谓词 `ContractFold`
- ✅ AIR 约束 `FoldAirAcceptable`
- ✅ **Not-soundness 反例**（证明当前 AIR 不 sound）
- ✅ 弱 soundness 定理模板

### 5. 全方法审计
- ✅ 21 个方法的约束缺口清单
- ✅ 4 个共性问题（state root, version, table_id, limb 验证）
- ✅ 分方法风险评级
- ✅ 完善路径建议

## 关键发现

### 当前 AIR 实现的 Soundness 评级：❌ 严重不足

| 级别 | 方法数 | 说明 |
|------|--------|------|
| ✅ 良好 | 0 | 完全满足 soundness |
| ⚠️ 中等 | 1 | create_table（结构约束较完善） |
| ❌ 严重 | 20 | 约束严重缺失 |

### 四大核心风险

1. **State Root 未验证**（极高风险）
   - 所有方法都没有 Poseidon252 哈希验证
   - pre/post state 的内容完全不受约束

2. **前置守卫缺失**（高风险）
   - 大多数动作没有 round_state gating
   - 没有 current_turn 检查
   - 没有 seat 状态检查

3. **资金守恒未验证**（高风险）
   - bet/call/raise 没有 stack-bet-pot 算术关系
   - 攻击者可以凭空创造筹码

4. **输入一致性模型**（中风险）
   - 大量 `input == expected` 模式
   - 将验证责任推给 host
   - 与 ZK 信任模型冲突

详细审计见 `Audit/SoundnessAudit.lean`。

## 后续工作

### 短期（高优先级）
1. 为 create_table 补齐 state root 验证的形式化
2. 为 fold/raise/check/call 补齐合约语义和 AIR 约束
3. 实现通用的 state root Poseidon252 验证框架

### 中期
4. 完成所有 8 个动作类方法的 soundness 分析
5. 完成生命周期类方法的 soundness 分析
6. 实现资金守恒的通用证明框架

### 长期
7. 密码学协议类方法的形式化（Mental Poker）
8. 完整的 21 个方法 soundness 证明
9. 与实际 Rust AIR 实现的一致性验证

## 相关代码库

- **poker_texas_air**：`../poker_texas_air/` — Rust 实现的 AIR 电路
- **poker_l1**：`../poker_l1/` — Move/Rust 合约实现
- **poker_protocol**：密码学协议库

## License

与主项目一致。
