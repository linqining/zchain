# poker_l1 三层信任模型文档

> 本文档系统阐述 zchain poker_l1 的三层信任架构，作为安全审计、架构设计与运维参考。
>
> 严格对齐 `poker_l1` 源码实现：
> - `poker_l1/src/transaction.rs` — `TxLane`（Public / GameTurn / CheckpointAnchor / ForceSync）
> - `poker_l1/src/consensus/routing.rs` — `validate_assigned_validator` / `validate_turn_order` / `validate_game_turn_phase_aware`
> - `poker_l1/src/consensus/vertex_production.rs` — `validate_fallback_tx` / `TimeoutProof` / `sort_vertex_txs_s9` / `sort_commit_txs_r4m4`
> - `poker_l1/src/consensus/slashing.rs` — `SlashingReason` / `SlashingConfig`
> - `poker_l1/src/offline/state.rs` — `ExecutionMode` / `OfflineState` / `CheckoutTx` / `CheckinTx`
> - `poker_l1/src/offline/zk_verifier.rs` — `VerifierStatus` / ZK proof 验证
> - `poker_l1/src/block/time_consensus.rs` — `TimeConsensusConfig` / `checkpoint_interval_blocks`

---

## 1. 概述

### 1.1 三层信任模型

zchain poker_l1 采用**渐进式信任最小化**架构，按 tx 通道与执行模式划分为三层：

```
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Public 通道（全共识网络信任）                   │
│ 信任假设：≥2/3 validator 诚实（BFT）                     │
│ 安全性：最高（全网共识）                                  │
│ 性能：~1000 tx/s，~3s finality                          │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Game tx 通道（单点 + 多副本见证信任）            │
│ 信任假设：assigned_validator 诚实 OR ≥4 witness 诚实     │
│ 安全性：中（单点 + fallback）                            │
│ 性能：~1000 tx/s，~3s finality（路由优化）              │
├─────────────────────────────────────────────────────────┤
│ Layer 3: OffChain（密码学信任）                          │
│ 信任假设：无（仅依赖 ZK soundness）                      │
│ 安全性：密码学保证（无信任假设）                          │
│ 性能：~100,000+ tx/s，~ms 延迟（链下）                  │
└─────────────────────────────────────────────────────────┘
```

### 1.2 设计目标

| 目标 | 实现方式 |
| --- | --- |
| 渐进信任最小化 | Layer 1 → Layer 2 → Layer 3，信任假设递减 |
| 性能递增 | Layer 1 ~1000 tx/s → Layer 3 ~100,000+ tx/s |
| 安全性互补 | BFT 共识 / 单点 + fallback / 密码学 |
| 协同设计 | 三层共用 DAG 共识 + slashing 基础设施 |
| 跨层逃生 | 上层失职可降级到下层逃生 |

### 1.3 核心概念

- **TxLane**：tx 通道枚举（Public / GameTurn / CheckpointAnchor / ForceSync）
- **ExecutionMode**：执行模式枚举（OnChain / OffChain）
- **assigned_validator**：per-Game per-epoch 单点打包 validator
- **witness**：多副本见证 validator（fallback 时签名 TimeoutProof）
- **commitment**：链下状态承诺（blake2b_256）
- **ZK proof**：链下计算正确性的密码学证明（Hypernova / Groth16 / IPA）

---

## 2. Layer 1：Public 通道（全共识网络信任）

### 2.1 信任假设

| 假设 | 说明 |
| --- | --- |
| BFT 假设 | ≥2/3 validator 诚实（按 stake 加权） |
| 数据可用性 | 所有 tx 链上完整存储 |
| 状态验证 | 全节点重放验证 |

### 2.2 信任对象

- **全网 validator 集合**（N-of-N）
- 任意 validator 可打包，无需 assigned_validator 配合

### 2.3 典型 tx

| tx 类型 | 说明 | 源码位置 |
| --- | --- | --- |
| 普通转账 | 账户间资金转移 | `transaction.rs` |
| 合约调用 | 通用智能合约调用 | `transaction.rs` |
| **fallback tx** | 玩家被审查时逃生 | `vertex_production.rs::validate_fallback_tx` |
| **CheckinTx** | OffChain 结算（走 Public 计费） | `offline/state.rs::CheckinTx` |
| force_checkpoint 逃生 tx | OffChain 操作方失职逃生 | `consensus/routing.rs` |
| Slash evidence tx | slashing 证据提交 | `consensus/slashing.rs` |

### 2.4 安全保证

| 保证 | 说明 |
| --- | --- |
| 共识 finality | ≥2/3 validator 签名后不可逆 |
| 审查防护 | 任意 validator 可打包（无需 assigned_validator 配合） |
| 状态完整性 | 全节点重放验证 |
| 数据可用性 | 链上完整存储 |

### 2.5 性能特征

| 指标 | 值 |
| --- | --- |
| 吞吐量 | ~1000 tx/s（DAG 共识上限） |
| 延迟 | ~3s（block finality） |
| gas 计费 | 正常计费（无免 gas 特权） |
| 路由 | 任意 validator 可接收 |

### 2.6 适用场景

- 高价值交易（需强共识）
- 跨游戏交易（与 Game 无关）
- fallback 逃生（assigned_validator 失职）
- OffChain 结算（CheckinTx 需全共识验证 ZK proof）
- slashing 证据提交

---

## 3. Layer 2：Game tx 通道（单点 + 多副本见证信任）

### 3.1 信任假设

| 假设 | 说明 |
| --- | --- |
| 正常情况 | 信任 assigned_validator 单点（每 epoch 一个） |
| fallback 情况 | 信任 ≥4 个独立 witness（required_witness_count） |
| 隐含 BFT | 仍依赖 Layer 1 的 validator 集合（witness 来自 validator 池） |

**关键**：信任假设是 OR 关系——即使 assigned_validator 作恶，只要 ≥4 witness 诚实，玩家仍可逃生。

### 3.2 信任对象

- **assigned_validator**（正常打包）
- **≥4 witness**（fallback 时签名 TimeoutProof）

### 3.3 典型 tx

| tx 类型 | 说明 | 源码位置 |
| --- | --- | --- |
| **GameTurn tx（Betting）** | fold / check / call / raise | `routing.rs::validate_turn_order` |
| **GameTurn tx（MultiPlayerSubmit）** | Shuffle / RevealToken / Reconstruct / LeaveProof | `routing.rs::validate_game_turn_phase_aware` |
| **CheckpointAnchorTx** | OffChain 模式定期 checkpoint | `offline/state.rs` / `network/mod.rs:448` |

### 3.4 安全保证

| 保证 | 说明 | 源码位置 |
| --- | --- | --- |
| 单点打包 | assigned_validator 负责校验轮转约束 + 打包 | `routing.rs::validate_assigned_validator` |
| 多副本见证 | TimeoutProof 需 ≥4 witness 独立签名（R3-H4 / R4-H6） | `vertex_production.rs::validate_witness_count` |
| fallback 逃生 | assigned_validator 失职时玩家可走 Layer 1 fallback tx | `vertex_production.rs::validate_fallback_tx` |
| slashing 威慑 | downtime 10% slashing + equivocation 100% slashing | `slashing.rs::SlashingReason` |
| SEC-H6 防护 | 跨 commit force_advance 防护 | `vertex_production.rs::check_sech6_cross_commit_force_advance` |
| S9 / R4-M4 排序 | GameTurn tx 优先执行 | `vertex_production.rs::sort_vertex_txs_s9` / `sort_commit_txs_r4m4` |

### 3.5 性能特征

| 指标 | 值 |
| --- | --- |
| 吞吐量 | ~1000 tx/s（与 Layer 1 共享 DAG） |
| 延迟 | ~3s（block finality）+ 路由优化（单跳到 assigned_validator） |
| gas 计费 | **免 gas**（spec 硬约束） |
| 路由 | 仅 assigned_validator 可打包 |

### 3.6 路由优化

虽然吞吐量与 Layer 1 相同（共享 DAG），但**端到端延迟更低**：

| 路径 | 流程 | 延迟 |
| --- | --- | --- |
| Layer 1 | 客户端 → 任意 validator → gossip → assigned_validator → vertex | ~3s + gossip（30-100ms） |
| Layer 2 | 客户端 → assigned_validator（直接）→ vertex | ~3s |

省掉 gossip 传播跳数，且 S9 / R4-M4 排序保证 GameTurn tx 优先执行。

### 3.7 适用场景

- 游戏内实时交互（玩家在线）
- 单手牌高价值（需即时共识）
- OffChain 期间的 checkpoint_anchor（链下状态定期上链）

---

## 4. Layer 3：OffChain（密码学信任）

### 4.1 信任假设

| 假设 | 说明 |
| --- | --- |
| **无信任假设** | 仅依赖 ZK proof soundness（Hypernova / Groth16 / IPA） |
| 活性假设 | 操作方定期提交 checkpoint_anchor（否则触发 fallback） |
| 数据可用性假设 | 操作方公开链下数据（否则 force_checkpoint 逃生） |

**关键**：操作方仅负责活性（提交 checkpoint），**不负责正确性**。操作方作恶只能导致活性问题（可通过 force_checkpoint 逃生），不能导致安全性问题（state 转换错误）。

### 4.2 信任对象

- **无**（密码学保证，不信任任何单点）
- 操作方仅负责活性

### 4.3 典型 tx

| tx 类型 | 说明 | 源码位置 |
| --- | --- | --- |
| **CheckoutTx** | 开局后将链上状态快照为 commitment | `offline/state.rs::CheckoutTx` |
| **CheckinTx** | 结算时提交 (π, Δ, new_commitment, ack_chain) | `offline/state.rs::CheckinTx` |
| **PartialCheckin** | 分段结算（SEC2-M8） | `offline/state.rs` |
| **CheckpointAnchorTx** | 链下 checkpoint 定期上链（走 Layer 2 路由） | `network/mod.rs:448` |

### 4.4 安全保证

| 保证 | 说明 | 源码位置 |
| --- | --- | --- |
| ZK proof 验证 | 链上 verifier 验证 π，proof 不可伪造 | `offline/zk_verifier.rs` |
| commitment 绑定 | state_root = blake2b_256(...)，状态篡改即被检测 | `offline/state.rs::OfflineState::commitment` |
| ack_chain 完整性 | Merkle root 防止 checkpoint 伪造 | `offline/state.rs::CheckinTx::ack_chain_hash` |
| partial_checkin 进度 | SEC-H1 强制进度（no progress → 拒绝） | `error.rs::NoProgressPartialCheckin` |
| VerifierStatus gate | Stub + mainnet 拒绝 OffChain checkout（NEW-C1） | `offline/state.rs::check_offchain_allowed` |

### 4.5 性能特征

| 指标 | 值 |
| --- | --- |
| 吞吐量 | ~100,000+ tx/s（链下执行） |
| 延迟 | ~ms（链下）+ proof 生成（秒~分钟）+ checkin 上链 |
| gas 计费 | CheckpointAnchor 免 gas（Layer 2）；CheckinTx 走 Layer 1 计费 |
| 路由 | 链下执行，仅结算上链 |

### 4.6 ZK 证明系统

源码：`poker_l1/src/offline/zk_verifier.rs` / `poker_l1/src/offline/ccs.rs`

| scheme_id | 方案 | 适用场景 |
| --- | --- | --- |
| 0 | Hypernova | 递归折叠，多步结算 |
| 1 | Groth16 | 单次证明，验证快 |
| 2 | IPA | 无 trusted setup |

### 4.7 适用场景

- 多手牌批量结算
- 隐私敏感场景（commitment 隐藏状态）
- 高频交易（<1s 响应）
- 离线玩家（异步游戏）
- 跨链互操作（ZK proof 可跨链验证）

---

## 5. 三层对比矩阵

### 5.1 信任与安全对比

| 维度 | Layer 1: Public | Layer 2: Game tx | Layer 3: OffChain |
| --- | --- | --- | --- |
| **信任假设** | ≥2/3 validator 诚实 | assigned_validator OR ≥4 witness | 无（密码学） |
| **信任对象数** | 全网（N） | 1 + 4（fallback） | 0 |
| **安全性来源** | BFT 共识 | BFT + fallback | ZK soundness |
| **审查防护** | 任意 validator 可打包 | witness fallback tx | force_checkpoint |
| **slashing** | downtime + equivocation | downtime + equivocation | 仅操作方 downtime |
| **数据可用性** | 链上完整 | 链上完整 | 链上 commitment + 链下完整 |
| **状态验证** | 全节点重放 | 全节点重放 | ZK proof 验证 |
| **隐私** | 全公开 | 全公开 | commitment 隐藏 |

### 5.2 性能对比

| 维度 | Layer 1: Public | Layer 2: Game tx | Layer 3: OffChain |
| --- | --- | --- | --- |
| **吞吐量** | ~1000 tx/s | ~1000 tx/s | ~100,000+ tx/s |
| **延迟** | ~3s | ~3s（路由优化） | ~ms（链下） |
| **gas** | 正常计费 | 免 gas | CheckpointAnchor 免 / Checkin 计费 |
| **finality** | block finality | block finality | checkin finality |
| **离线玩家** | 不支持 | 不支持 | 支持 |

### 5.3 tx 通道映射

| TxLane | ExecutionMode | Layer | 说明 |
| --- | --- | --- | --- |
| Public | OnChain / OffChain | Layer 1 | 通用 tx + fallback + checkin |
| GameTurn | OnChain | Layer 2 | 游戏内交互（免 gas） |
| CheckpointAnchor | OffChain | Layer 2 | 链下 checkpoint（免 gas，走 assigned_validator） |
| ForceSync | OnChain / OffChain | Layer 1 | 强制同步 tx |

---

## 6. 递减假设与递增性能

### 6.1 信任假设递减

```
Layer 1: 信任全网 N 个 validator（≥2/3 诚实）
           ↓ 缩小信任集合
Layer 2: 信任 1 个 assigned_validator + 4 个 witness（≥4/5 诚实）
           ↓ 消除信任假设
Layer 3: 信任 0 个实体（仅密码学）
```

### 6.2 性能递增

```
Layer 1: ~1000 tx/s，~3s 延迟
           ↓ 路由优化（不提升吞吐，降低延迟）
Layer 2: ~1000 tx/s，~3s 延迟（路由优化）
           ↓ 突破共识瓶颈
Layer 3: ~100,000+ tx/s，~ms 延迟
```

### 6.3 安全性权衡

```
Layer 1: BFT 安全（≥2/3 诚实）—— 最高
           ↓ 单点风险（fallback 缓解）
Layer 2: BFT + fallback（≥4/5 诚实）—— 中
           ↓ 密码学保证（无信任假设）
Layer 3: ZK soundness —— 密码学最高
```

**关键洞察**：Layer 3 的安全性**理论上最高**（无信任假设），但**实践中依赖 ZK 电路实现正确性**，因此与 Layer 1/2 互补而非替代。

### 6.4 权衡总结

| 层级 | 信任假设 | 性能 | 安全性 | 适用场景 |
| --- | --- | --- | --- | --- |
| Layer 1 | 最高（全网） | 最低 | BFT 最高 | 高价值、跨游戏 |
| Layer 2 | 中（单点 + fallback） | 中（路由优化） | BFT + fallback | 游戏内实时 |
| Layer 3 | 最低（无） | 最高 | 密码学最高 | 批量结算、隐私 |

---

## 7. 三层协同设计

zchain 的三层不是独立孤岛，而是**协同设计**，共用基础设施。

### 7.1 共用基础设施

| 基础设施 | Layer 1 | Layer 2 | Layer 3 |
| --- | --- | --- | --- |
| DAG 共识 | ✅ | ✅ | ✅（仅 checkin） |
| validator 集合 | ✅ | ✅ | ✅ |
| slashing 机制 | ✅ | ✅ | ✅（操作方） |
| SEC-H6 防护 | ✅ | ✅ | ✅ |
| assigned_validator 路由 | - | ✅ | ✅（CheckpointAnchor） |
| witness fallback | ✅（fallback tx） | ✅ | ✅（force_checkpoint） |
| ZK verifier registry | - | - | ✅ |

### 7.2 跨层逃生路径

```
Layer 3 操作方失职
    → force_checkpoint（走 Layer 1 Public 通道）
    → 社区启动新操作方
    → 链下数据公开后继续执行

Layer 2 assigned_validator 失职
    → TimeoutProof witness ≥4
    → fallback tx（走 Layer 1 Public 通道）
    → 任意 validator 打包

Layer 1 validator 集体作恶
    → 无法逃生（BFT 假设破坏）
    → 仅能通过社会共识分叉
```

### 7.3 tx 跨层流转

OffChain 模式的完整生命周期跨三层：

```
游戏开局（Layer 1 创建 Game）
    ↓
CheckoutTx（Layer 1 触发，存 commitment）
    ↓
链下执行（Layer 3）
    ↓
CheckpointAnchorTx（Layer 2 路由，免 gas）
    ↓
链下继续执行（Layer 3）
    ↓
CheckinTx（Layer 1 Public 通道计费）
    ↓
ZK proof 验证（Layer 1 verifier）
    ↓
应用 Δ，解锁 checkout（Layer 1 状态更新）
```

### 7.4 通道选择逻辑

源码：`poker_l1/src/transaction.rs` / `poker_l1/src/offline/state.rs`

```
tx 类型 → TxLane 通道 → Layer
─────────────────────────────────
普通转账 → Public → Layer 1
fallback tx → Public → Layer 1
CheckinTx → Public → Layer 1
force_checkpoint → Public → Layer 1
GameTurn（OnChain）→ GameTurn → Layer 2
CheckpointAnchor（OffChain）→ CheckpointAnchor → Layer 2
```

---

## 8. 与传统分层架构对比

### 8.1 与 L1/L2/L3 对比

| 维度 | 传统 L1/L2/L3 | zchain 三层信任 |
| --- | --- | --- |
| Layer 1 | 结算层（以太坊） | Public 通道（全共识） |
| Layer 2 | Rollup（Arbitrum/Optimism） | Game tx 通道（链原生） |
| Layer 3 | 应用链（Xai/Ronin） | OffChain（ZK 结算） |
| 跨层通信 | 跨链桥 / rollup bridge | 链原生 tx 通道 |
| 安全继承 | L2 继承 L1 安全 | Layer 2/3 共用 Layer 1 validator |
| 信任假设 | L2 信任 sequencer | Layer 2 信任 assigned_validator + witness |

### 8.2 zchain 创新点

| 创新点 | 说明 |
| --- | --- |
| Layer 2 链原生 | 传统 L2 是独立 rollup，zchain Layer 2 是链原生通道（无独立链） |
| Layer 3 ZK 结算 | 传统 L3 是应用链，zchain Layer 3 是 ZK 结算（无独立链） |
| 三层共用 validator | 传统三层是独立 validator set，zchain 三层共用全局 validator 池 |
| 跨层逃生 | 传统跨层逃生需跨链桥，zchain 跨层逃生走链原生 tx |
| 渐进信任最小化 | 传统三层是独立信任模型，zchain 三层是渐进式信任最小化 |

---

## 9. 安全分析

### 9.1 单层攻击与跨层防护

| 攻击 | 目标层 | 跨层防护 |
| --- | --- | --- |
| assigned_validator 审查 | Layer 2 | Layer 1 fallback tx（任意 validator 打包） |
| assigned_validator equivocation | Layer 2 | Layer 1 slashing（链上证据） |
| OffChain 操作方活性失效 | Layer 3 | Layer 1 force_checkpoint（社区启动新操作方） |
| OffChain 状态篡改 | Layer 3 | Layer 1 ZK proof 验证（密码学保证） |
| validator 集体作恶 | Layer 1 | 无跨层防护（社会共识分叉） |

### 9.2 信任假设破坏后果

| 假设破坏 | 影响层 | 后果 |
| --- | --- | --- |
| <2/3 validator 诚实 | Layer 1 + Layer 2 | BFT 安全性破坏，全链不可信 |
| <4 witness 诚实 | Layer 2 | fallback 失效，assigned_validator 单点风险 |
| ZK soundness 破坏 | Layer 3 | 链下状态转换可伪造 |
| 操作方活性失效 | Layer 3 | 链下执行停滞，需 force_checkpoint |

### 9.3 最小信任配置

| 场景 | 最小信任配置 |
| --- | --- |
| 仅 Layer 1 | 信任 ≥2/3 validator |
| Layer 1 + Layer 2 | 信任 ≥2/3 validator AND (assigned_validator OR ≥4 witness) |
| Layer 1 + Layer 2 + Layer 3 | 信任 ≥2/3 validator AND (assigned_validator OR ≥4 witness) AND ZK soundness |

---

## 10. 源码索引

### 10.1 通道与模式定义

| 类型 | 源码位置 | 说明 |
| --- | --- | --- |
| `TxLane` | `poker_l1/src/transaction.rs` | tx 通道枚举 |
| `ExecutionMode` | `poker_l1/src/offline/state.rs:52` | 执行模式枚举（OnChain / OffChain） |
| `OfflineState` | `poker_l1/src/offline/state.rs:36` | 链下状态承诺 |
| `CheckoutTx` | `poker_l1/src/offline/state.rs:96` | checkout tx |
| `CheckinTx` | `poker_l1/src/offline/state.rs:110` | checkin 结算 tx |

### 10.2 Layer 1 校验函数

| 函数 | 源码位置 | 说明 |
| --- | --- | --- |
| `validate_fallback_tx` | `poker_l1/src/consensus/vertex_production.rs` | fallback tx 校验 |
| `validate_witness_independence` | `poker_l1/src/consensus/vertex_production.rs` | witness 独立性 |
| `validate_witness_count` | `poker_l1/src/consensus/vertex_production.rs` | witness 数量 |
| `check_offchain_allowed` | `poker_l1/src/offline/state.rs` | OffChain 主网 gate |

### 10.3 Layer 2 校验函数

| 函数 | 源码位置 | 说明 |
| --- | --- | --- |
| `validate_assigned_validator` | `poker_l1/src/consensus/routing.rs` | 校验 assigned_validator 身份 |
| `validate_turn_order` | `poker_l1/src/consensus/routing.rs` | 校验下注阶段轮转 |
| `validate_game_turn_phase_aware` | `poker_l1/src/consensus/routing.rs` | 校验多玩家阶段提交者 |
| `sort_vertex_txs_s9` | `poker_l1/src/consensus/vertex_production.rs` | S9 vertex 内排序 |
| `sort_commit_txs_r4m4` | `poker_l1/src/consensus/vertex_production.rs` | R4-M4 commit 内排序 |

### 10.4 Layer 3 校验函数

| 函数 | 源码位置 | 说明 |
| --- | --- | --- |
| `OfflineState::commitment` | `poker_l1/src/offline/state.rs:62` | 计算状态承诺 |
| `CheckinTx::state_delta_hash` | `poker_l1/src/offline/state.rs:129` | 计算状态增量哈希 |
| `CheckinTx::proof_hash` | `poker_l1/src/offline/state.rs:139` | 计算 proof 哈希 |
| `CheckinTx::ack_chain_hash` | `poker_l1/src/offline/state.rs:150` | 计算 ack_chain Merkle root |
| `VerifierStatus` | `poker_l1/src/offline/zk_verifier.rs:31` | ZK verifier 状态 |

### 10.5 跨层基础设施

| 类型 | 源码位置 | 说明 |
| --- | --- | --- |
| `SlashingReason` | `poker_l1/src/consensus/slashing.rs` | slashing 类型（共用） |
| `SlashingConfig` | `poker_l1/src/consensus/slashing.rs` | slashing 配置（共用） |
| `TimeConsensusConfig` | `poker_l1/src/block/time_consensus.rs` | 时间共识配置（共用） |
| `DagVertex` | `poker_l1/src/consensus/mod.rs` | DAG vertex（共用） |
| `DagCommitCertificate` | `poker_l1/src/consensus/mod.rs` | commit certificate（共用） |

---

## 11. 运维检查清单

### 11.1 Layer 1 检查

- [ ] validator 集合规模 ≥ 5（SEC-C2）
- [ ] validator stake 分散（无单点 ≥1/3 stake）
- [ ] Public 通道 fallback tx 正常工作
- [ ] slashing 证据提交通道正常
- [ ] force_checkpoint 逃生通道正常

### 11.2 Layer 2 检查

- [ ] assigned_validator 分配正确（hash(G.id, epoch) % |V|）
- [ ] `turn_timeout_blocks` 配置合理（默认 30）
- [ ] `checkpoint_multi_replica_count` 配置合理（默认 5）
- [ ] TimeoutProof.witness 独立性校验生效
- [ ] TimeoutProof.witness 数量校验生效（≥4）
- [ ] SEC-H6 跨 commit force_advance 防护生效
- [ ] S9 / R4-M4 排序规则正确
- [ ] assigned_validator downtime 监控

### 11.3 Layer 3 检查

- [ ] `checkpoint_interval_blocks` 配置合理（默认 100）
- [ ] VerifierStatus 主网为 Production（非 Stub）
- [ ] ZK proof 验证 gas 配置合理
- [ ] CheckoutTx / CheckinTx 流程正常
- [ ] partial_checkin 分段结算正常（SEC2-M8）
- [ ] force_checkpoint 逃生流程文档化
- [ ] 操作方活性监控（checkpoint_anchor 定期提交）

### 11.4 跨层检查

- [ ] 跨层逃生路径测试通过
- [ ] slashing 机制跨层一致
- [ ] validator 集合跨层共享
- [ ] DAG 共识跨层一致

---

## 12. 参考

- [37-1-node-deployment.md](37-1-node-deployment.md) — 节点部署文档
- [37-3-offline-proof-development.md](37-3-offline-proof-development.md) — 链下证明开发文档
- [37-6-dag-consensus-ops.md](37-6-dag-consensus-ops.md) — DAG 共识运维文档
- [37-8-game-phase-protocol.md](37-8-game-phase-protocol.md) — 游戏阶段协议文档
- [37-9-assigned-validator-security.md](37-9-assigned-validator-security.md) — assigned_validator 作恶场景与防护
- spec：`.trae/specs/build-poker-l1-chain/spec.md` SubTask 7（tx 通道） / SubTask 12（assigned_validator） / SubTask 21（OffChain） / SubTask 27（审查防护）
- spec：`.trae/specs/extend-game-multiplayer-phases/spec.md` Phase 1-5（多玩家阶段）
