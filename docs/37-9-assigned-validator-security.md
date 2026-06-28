# poker_l1 assigned_validator 作恶场景与防护机制文档

> 本文档系统分析 zchain poker_l1 中 assigned_validator 的作恶面与多层防护机制，作为安全审计与运维参考。
>
> 严格对齐 `poker_l1` 源码实现：
> - `poker_l1/src/consensus/routing.rs` — `validate_assigned_validator` / `validate_turn_order` / `validate_game_turn_phase_aware` / `GameStatus`
> - `poker_l1/src/consensus/vertex_production.rs` — `validate_fallback_tx` / `TimeoutProof` / `check_sech6_cross_commit_force_advance` / `build_game_sub_block` / `sort_vertex_txs_s9` / `sort_commit_txs_r4m4`
> - `poker_l1/src/consensus/slashing.rs` — `SlashingReason` / `SlashingConfig` / `is_downtime_auto_slashable` / `is_downtime_governance_kickout`
> - `poker_l1/src/consensus/phase_timeout.rs` — `handle_submit_phase_timeout` / `KickResult`
> - `poker_l1/src/consensus/texas_holdem_turn_rule.rs` — `TexasHoldemTurnRule::advance_phase`
> - `poker_l1/src/block/time_consensus.rs` — `TimeConsensusConfig` / `is_submit_phase_timed_out`
> - `poker_l1/src/consensus/mod.rs` — `DagVertex::vertex_hash` / `DagCommitCertificate::signing_hash`

---

## 1. 概述

### 1.1 assigned_validator 角色

assigned_validator 是 zchain 中负责某个 Game 的 tx 打包与校验的**单点 validator**。spec SubTask 12.1 定义分配规则：

```
assigned_validator = validators[hash(G.id, current_epoch) % |V|]
```

每个 Game 在每个 epoch 内有且仅有一个 assigned_validator，负责：
- 接收该 Game 的 GameTurn / CheckpointAnchor 通道 tx
- 校验 tx 轮转约束（current_turn_player / pending_submitters）
- 把合法 tx 打包到自己产出的 vertex 中
- 推进游戏阶段状态机（advance_phase）

### 1.2 权力集中带来的风险

assigned_validator 权力集中，可能实施的作恶面广：
- **审查**：拒绝打包合法 tx
- **伪造**：伪造玩家签名或 timeout_proof
- **抢跑**：跨 commit force_advance 抢跑
- **Equivocation**：双签 vertex / commit certificate
- **状态篡改**：篡改游戏状态字段
- **超时滥用**：恶意触发超时惩罚
- **跨阶段作恶**：滥用阶段切换

### 1.3 防护设计原则

| 原则 | 实现方式 |
| --- | --- |
| 不信任单点 | assigned_validator 的所有行为都可被其他 validator 见证或拒绝 |
| 多副本见证 | TimeoutProof 需 ≥4 个独立 witness，防女巫 |
| 经济激励对齐 | downtime 自动 slashing 10%，equivocation 全额 slashing |
| 逃生通道 | fallback tx 让玩家在 assigned_validator 失职时仍能推进游戏 |
| 客观时间 | 所有超时以 `block.height` 为权威（SEC-M5），防 timestamp 操纵 |

### 1.4 行业对比与设计渊源

assigned_validator 设计综合了多家公链之长，下表对比相似设计：

| 链 | 单点打包 | 多副本见证 fallback | Slashing | per-Game/分片分配 | 去中心化 |
| --- | --- | --- | --- | --- | --- |
| **zchain** | ✅ assigned_validator | ✅ witness ≥4 | ✅ downtime + equivocation | ✅ per-Game | ✅ |
| Near | ✅ chunk producer | ✅ fisherman | ✅ | ✅ per-shard | ✅ |
| Arbitrum AnyTrust | ✅ sequencer | ✅ DAC 2/3 | ❌ | ❌ | 半 |
| Avalanche L1s | ❌ validator set | ❌ | ✅ | ✅ per-L1 | ✅ |
| Cosmos ICS | ❌ validator set | ❌ | ✅ | ✅ per-chain | ✅ |
| Algorand | ✅ VRF leader | ❌ | ❌ | ✅ per-round | ✅ |
| Tendermint | ✅ round-robin | ❌ | ✅ | ❌ 全链 | ✅ |
| Cardano | ✅ slot leader | ❌ | ❌ | ❌ 全链 | ✅ |
| Arbitrum Rollup | ✅ sequencer | ✅ force inclusion | ❌ | ❌ | ❌ |
| Ronin | ❌ DPoS | ❌ | ❌ | ❌ 单链 | 半 |

#### 1.4.1 最接近的设计

**Near Protocol — Chunk Producer**（相似度 ⭐⭐⭐⭐⭐）

| 特征 | Near | zchain |
| --- | --- | --- |
| 分配方式 | VRF 选 chunk producer（每 shard 每 height） | `hash(G.id, epoch) % \|V\|` |
| 负责对象 | 单个 shard 的 chunk 打包 | 单个 Game 的 GameTurn tx 打包 |
| 任期 | 1 height（~1s） | 1 epoch（~1000 blocks） |
| Fallback | 其他 validator 见证缺失 → next chunk producer | TimeoutProof witness ≥4 → fallback tx |
| Slashing | chunk producer 不出块 → 自动 slashing | SEC-M1 自动 slashing 2100 blocks |
| 多副本见证 | fisherman 检查状态转换 | required_witness_count=4 |

参考：[Near Nightshade Paper](https://near.org/papers/nightshade)

**Arbitrum AnyTrust — Sequencer + DAC**（相似度 ⭐⭐⭐⭐）

| 特征 | Arbitrum AnyTrust | zchain |
| --- | --- | --- |
| 单点打包 | 单一 sequencer | assigned_validator |
| Fallback 机制 | Data Availability Committee（DAC，N-of-M） | TimeoutProof witness（M-of-N） |
| DAC 阈值 | 2/3（典型 6-of-8） | 4-of-5（required_witness_count） |
| Sequencer 失效 | DAC 公开数据 → 社区启动新 sequencer | witness 提交 TimeoutProof → fallback tx |
| 信任假设 | 至少 1 个 DAC 诚实 | 至少 4 个 witness 诚实 |
| Slashing | DAC 保证金 | validator stake slashing |

参考：[Arbitrum AnyTrust Whitepaper](https://arbitrumfoundation.s3.amazonaws.com/anytrust.pdf)

#### 1.4.2 应用专属 Validator Set

**Avalanche Subnets / L1s**（相似度 ⭐⭐⭐）

| 特征 | Avalanche L1s | zchain |
| --- | --- | --- |
| 分配方式 | 应用自定义 validator subset | 全局 validator 池按 hash 分配 |
| 隔离性 | 完全隔离（每个 L1 独立 validator） | 软隔离（Game 共享 validator 但路由分流） |
| 资源开销 | 每 L1 需 N 个 validator | 全局 validator 共享 |
| Slashing | L1 自定义规则 | 全局 slashing |

**Cosmos Interchain Security（ICS）**（相似度 ⭐⭐⭐）

| 特征 | Cosmos ICS | zchain |
| --- | --- | --- |
| 分配方式 | provider chain validator 子集分配到 consumer chain | 全局 validator 按 hash 分配到 Game |
| 安全性 | 由 provider chain stake 保护 | 由全局 validator stake 保护 |
| Slashing | provider chain 统一 slashing | 全局 slashing |
| 隔离性 | consumer chain 独立状态 | Game 独立状态 |
| 隔离粒度 | 粗粒度（链级别） | 细粒度（Game 级别） |

参考：[Cosmos ICS](https://cosmos.github.io/interchain-security/)

#### 1.4.3 Leader Rotation 模式

**Algorand — VRF Leader**（相似度 ⭐⭐⭐）

| 特征 | Algorand | zchain |
| --- | --- | --- |
| 分配方式 | VRF 每 round 选 leader | hash(G.id, epoch) 每 epoch 选 |
| 隐私性 | VRF 输出直到 leader 主动揭示才知道 | 公开（链上分配） |
| 任期 | 1 round（~4s） | 1 epoch |
| Fallback | next round 自动选新 leader | witness fallback tx |
| 抗审查 | VRF 随机性 | epoch 重分配 |

参考：[Algorand Pure PoS](https://algorand.com/technology/pure-proof-of-stake)

**Cardano — Slot Leader**（相似度 ⭐⭐⭐）

| 特征 | Cardano | zchain |
| --- | --- | --- |
| 分配方式 | VRF（每 epoch 选 slot leader） | hash（每 epoch 选 assigned_validator） |
| 任期 | 1 slot（~20s） | 1 epoch |
| 任期长度 | ~5 days | ~1000 blocks |
| 预测性 | 可提前计算（VRF eval） | 可提前计算（hash + epoch） |
| Slashing | 无（PoS 无 slashing） | downtime + equivocation slashing |

参考：[Cardano Ouroboros](https://cardano.org/ouroboros/)

**Cosmos Tendermint — Round-Robin Leader**（相似度 ⭐⭐⭐）

| 特征 | Tendermint | zchain |
| --- | --- | --- |
| 分配方式 | 轮转 + 优先级（按 voting power） | hash 分配 |
| 任期 | 1 round | 1 epoch |
| Fallback | next round 自动换 leader | witness fallback tx |
| 单点风险 | 高（每 round 单 leader） | 高（每 epoch 单 assigned_validator） |
| Slashing | downtime slashing | downtime slashing |
| 打包范围 | 全链一个 leader | per-Game 一个 leader |

参考：[Tendermint BFT](https://docs.tendermint.com/)

#### 1.4.4 Sequencer 模式（中心化打包）

**Arbitrum Rollup / Optimism / Starknet**（相似度 ⭐⭐）

| 特征 | L2 Rollup Sequencer | zchain |
| --- | --- | --- |
| 单点打包 | 单一 sequencer | assigned_validator |
| 去中心化 | 当前中心化（计划去中心化） | 已去中心化（validator 池分配） |
| Fallback | force inclusion（L1 7-day 挑战期） | witness fallback tx（30 blocks） |
| Slashing | 无（中心化 sequencer） | 全局 slashing |
| 响应延迟 | ~250ms | ~3s（block time） |

#### 1.4.5 游戏专用链

**Ronin（Axie Infinity）**（相似度 ⭐⭐）

| 特征 | Ronin | zchain |
| --- | --- | --- |
| 设计目标 | 游戏专用 L1 | 游戏专用 L1 |
| Validator 数量 | 少量（9 个 DPoS） | 全局 validator 池 |
| 分配方式 | DPoS 轮转 | hash(G.id, epoch) |
| Fallback | 无（DPoS 整体验证） | witness fallback tx |
| Slashing | DPoS 投票踢出 | 全局 slashing |
| Game 隔离 | 全链一个 Game | per-Game 独立状态 |

**Xai / Oasys / B3.fun**（相似度 ⭐⭐）

| 特征 | Xai / Oasys / B3 | zchain |
| --- | --- | --- |
| 架构 | L3 / 游戏专用 L1 / L2 | L1 |
| Validator | 继承 L1/L2 validator | 独立 validator 池 |
| Game 隔离 | 每 Game 独立链 | 单链多 Game |
| 状态管理 | 每 Game 独立状态机 | per-Game GameStatus |

#### 1.4.6 zchain 设计的独特性

zchain 的 assigned_validator 设计**综合了多家之长**：

| 来源 | 借鉴的设计 |
| --- | --- |
| Near | VRF-like 分配（hash 替代 VRF）+ 单点打包 + fisherman witness |
| Arbitrum AnyTrust | 单点 sequencer + 多副本 fallback committee（M-of-N） |
| Cosmos | downtime + equivocation 双重 slashing + 全局共享安全 |
| Algorand | 可预测的 leader 分配（hash + epoch 可提前计算） |
| **zchain 原创** | 见下表 |

**zchain 原创设计**：

| 原创点 | 说明 |
| --- | --- |
| per-Game 细粒度分配 | 其他链都是 per-shard（Near）或 per-chain（Cosmos ICS），zchain 在单链内支持百万级 Game 的独立 assigned_validator 分配 |
| 免 gas GameTurn 通道 | 其他链都是统一计费，zchain 对 GameTurn tx 免 gas |
| 多玩家并行提交阶段协议 | 其他链无游戏阶段概念，zchain 定义了 Betting / MultiPlayerSubmit(Shuffle/RevealToken/Reconstruct/LeaveProof) 状态机 |
| 跨 commit force_advance 防护（SEC-H6） | 其他链无此机制，zchain 防止 assigned_validator 抢跑触发 fallback |
| 链原生 per-Game 单点打包 | 其他链要么 per-shard 要么 per-chain，zchain 是少数把"per-Game 单点打包 + 多副本见证 fallback"做到链原生级别 |

**核心创新**：zchain 是少数把"per-Game 单点打包 + 多副本见证 fallback"做到**链原生级别**的设计，在单链内支持百万级 Game 的独立 assigned_validator 分配，这是其架构独特性。

**三层信任模型**：assigned_validator 模式属于 zchain 三层信任架构的 Layer 2（Game tx 通道），与 Layer 1（Public 通道，全共识网络信任）和 Layer 3（OffChain，密码学信任）协同设计。详细分析见独立文档 [37-10-trust-layer-model.md](37-10-trust-layer-model.md)。

| Layer | 通道 | 信任假设 | 性能 |
| --- | --- | --- | --- |
| Layer 1 | Public | ≥2/3 validator 诚实（BFT） | ~1000 tx/s，~3s |
| **Layer 2** | **Game tx** | **assigned_validator OR ≥4 witness** | **~1000 tx/s，~3s（路由优化）** |
| Layer 3 | OffChain | 无（ZK soundness） | ~100,000+ tx/s，~ms |

---

## 2. 审查类作恶（Censorship）

### 2.1 拒绝打包合法 GameTurn tx

**场景**：assigned_validator 收到合法玩家 GameTurn tx 但故意丢弃或不打包，导致游戏卡死。

**防护机制（7 层纵深防御）**：

| 层级 | 机制 | 默认值 | 源码位置 |
| --- | --- | --- | --- |
| L1 | `turn_timeout_blocks` 超时后玩家可触发 fallback tx | 30 blocks | `time_consensus.rs` |
| L2 | fallback tx 走 Public 通道，任意非 assigned_validator 可接收 | - | `vertex_production.rs::validate_fallback_tx` |
| L3 | TimeoutProof.witness **独立性**（R3-H4）：witness 须为非 assigned_validator | - | `validate_witness_independence` |
| L4 | TimeoutProof.witness **数量**（R4-H6）：≥ `required_witness_count` | 4 | `validate_witness_count` |
| L5 | non_inclusion_proof：sparse Merkle 证明未打包 | - | `TimeoutProof.non_inclusion_proof` |
| L6 | SEC-M1 自动 slashing：连续 `downtime_threshold_blocks + 2*epoch_length_blocks` 未提交 vertex | 2100 blocks | `is_downtime_auto_slashable` |
| L7 | 治理踢出：连续 `downtime_threshold_blocks` 未提交 vertex | 100 blocks | `is_downtime_governance_kickout` |

**关键设计**：fallback tx 不依赖 assigned_validator 配合，由其他 validator 见证即可执行，彻底打破审查。

### 2.2 拒绝推进多玩家阶段

**场景**：在 Shuffle / RevealToken / Reconstruct 阶段，assigned_validator 故意不调用 `advance_phase()`，让游戏卡在多玩家阶段。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| 阶段独立超时 | `shuffle_timeout_blocks=100` / `reveal_token_timeout_blocks=50` / `reconstruct_timeout_blocks=100` | `time_consensus.rs::TimeConsensusConfig` |
| `is_submit_phase_timed_out()` | 任意 validator 可检测超时 | `time_consensus.rs` |
| `handle_submit_phase_timeout()` | kick `pending_submitters` 中所有未提交者 + 退款 | `phase_timeout.rs` |
| 剩余 < 2 人自动 finalize | 触发 `end_without_showdown`，防止游戏僵死 | `phase_timeout.rs` |
| block.height 单调性 | SEC-M5：超时判定以 `block.height` 为权威 | `time_consensus.rs` |

### 2.3 选择性打包（front-running）

**场景**：assigned_validator 优先打包自己关联玩家的 tx，对其他玩家延迟打包。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| S9 排序 | vertex 内 GameTurn + CheckpointAnchor 全部先于 Public / ForceSync | `sort_vertex_txs_s9` |
| R4-M4 排序 | commit 内所有 vertex 的 GameTurn tx 全部先于 ForceSync | `sort_commit_txs_r4m4` |
| build_game_sub_block 排序键固定 | Betting: `(current_turn 优先, arrival)`；MultiPlayerSubmit: `(phase_kind, arrival)` | `vertex_production.rs` |
| vertex_hash 不可篡改 | tx 顺序参与 `vertex_hash` 计算，签名后不可改变 | `DagVertex::vertex_hash` |

**局限**：assigned_validator 仍可在**打包前**选择哪些 tx 进入 vertex（即 mempool 层面的审查），但这通过 fallback tx 机制（2.1）缓解。

---

## 3. 伪造类作恶（Forgery）

### 3.1 伪造玩家 GameTurn tx

**场景**：assigned_validator 伪造玩家签名提交 GameTurn tx（如代玩家 fold）。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| 玩家签名验证 | tx 必须由玩家 secp256k1/Ed25519 签名，assigned_validator 无法伪造 | `transaction.rs` |
| `gameturn_nonce`（NEW-M9） | per-game per-player 计数器，防重放 | `GameStatus.player_nonce` |
| `validate_turn_order` | 校验 `actor == game.current_turn_player` | `routing.rs` |
| `validate_game_turn_phase_aware` | 多玩家阶段校验 `actor ∈ pending_submitters` | `routing.rs` |
| account nonce | per-account 计数器，连续递增防跳号 | `block/validator.rs` |

**结论**：assigned_validator **无法**伪造玩家 tx（除非窃取玩家私钥）。

### 3.2 伪造 TimeoutProof 触发 fallback

**场景**：assigned_validator 自签伪造 TimeoutProof，谎称自己超时，触发 fallback tx 操纵游戏。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| witness 独立性（R3-H4） | `validate_witness_independence` 强制 witness_pubkeys **不含 assigned_validator** | `vertex_production.rs` |
| witness 数量（R4-H6） | ≥ `required_witness_count`（默认 4，配置 `checkpoint_multi_replica_count=5` 的 2/3） | `validate_witness_count` |
| non_inclusion_proof | sparse Merkle 证明 assigned_validator 在窗口内未装入同 gameturn_nonce 的 tx | `TimeoutProof.non_inclusion_proof` |
| 多副本独立性（R3-H4） | witness 须来自不同物理 validator，防女巫 | `validate_fallback_tx` |

**结论**：assigned_validator **无法**自签伪造 TimeoutProof，必须由 ≥4 个其他 validator 见证。

### 3.3 伪造 fallback tx 抢跑

**场景**：assigned_validator 伪造 fallback tx，绕过正常 GameTurn 通道校验。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| SEC-H7 | fallback tx 必须走 Public 通道且 `is_fallback = true` | `vertex_production.rs` |
| InvalidFallbackFlag | GameTurn 通道 tx 设置 `is_fallback = true` → 拒绝 | `validate_game_turn_tx` |
| nonce 一致性 | `validate_fallback_tx` 校验 `timeout_proof.original_tx.gameturn_nonce == fallback_tx.gameturn_nonce` | `vertex_production.rs` |
| Public 通道计费 | fallback tx 走 Public 通道正常计费（R3-H5），assigned_validator 需付出 gas 成本 | `validate_fallback_tx` |

---

## 4. 抢跑类作恶（Front-running）

### 4.1 跨 commit force_advance 抢跑

**场景**：assigned_validator 在前一 commit 已装入 GameTurn tx（`last_action_height` 应已更新），但当前 commit 仍触发 `force_advance` 谎称超时。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| SEC-H6 | `check_sech6_cross_commit_force_advance` 校验前一 commit 内是否有该 Game 的 GameTurn tx | `vertex_production.rs` |
| Phase 6 扩展 | 覆盖 `MultiPlayerSubmit` 阶段（4 种 SubmitPhaseKind） | `vertex_production.rs` |
| 拒绝规则 | 若前一 commit 有 GameTurn tx → force_advance 判定为 false，**拒绝** | `vertex_production.rs` |
| 审计字段 | 错误信息含 `game_phase` 便于审计 | `vertex_production.rs` |

### 4.2 vertex 内排序抢跑

**场景**：assigned_validator 操纵 vertex 内 tx 顺序让自己关联玩家先执行。

**防护机制**：

| 机制 | 说明 |
| --- | --- |
| 排序规则固定 | S9 / R4-M4 / build_game_sub_block 排序规则在 spec 中固定 |
| vertex_hash 不可篡改 | vertex_hash 含 tx_hashes 顺序，签名后不可篡改 |
| 其他 validator 可验证 | 其他 validator 可重放排序算法验证 |

---

## 5. Equivocation 类作恶（双签）

### 5.1 Vertex Equivocation

**场景**：assigned_validator 在同一 `(epoch, round)` 签发两个不同 vertex，造成 DAG 分叉。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| SlashingReason::VertexEquivocation | 优先级 1（最高），100% slashing（NEW-M15） | `slashing.rs` |
| VertexEquivocationEvidence | 两个冲突 vertex 的签名证据 | `slashing.rs` |
| SEC-C1 签名绑定 | 签名对象含 `chain_id / epoch / round / author_pubkey`，防跨链/跨 epoch 重用 | `DagVertex::signing_hash` |
| 链上证据可验证 | 任何 validator 可提交证据触发 slashing | `slashing.rs` |

### 5.2 Commit Certificate Equivocation

**场景**：assigned_validator 在同一 `(epoch, commit_round)` 签发两个不同 commit certificate。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| SlashingReason::CommitCertEquivocation | 优先级 2，100% slashing | `slashing.rs` |
| SEC2-C1 签名绑定 | `chain_id / epoch / commit_round / prev_commit_hash / state_root / public_tx_root / gameturn_tx_root` | `DagCommitCertificate::signing_hash` |
| prev_commit_hash hash chain | 形成 hash chain，防 long-range attack | `DagCommitCertificate` |
| state_root 绑定 | 防 commit certificate 被重用到不同 block 内容 | `DagCommitCertificate` |

---

## 6. 状态篡改类作恶

### 6.1 篡改游戏状态

**场景**：assigned_validator 篡改 `current_turn_player` / `phase` / `pending_submitters` 等字段。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| tx-driven 状态转换 | 所有状态变更必须由 tx 驱动，assigned_validator 无法直接改 state | `routing.rs` |
| state_root 绑定 | commit certificate 含 `state_root`（SEC2-C1），篡改即被检测 | `DagCommitCertificate` |
| 玩家可校验 | 玩家通过 state_root 验证自己状态 | `DagCommitCertificate` |
| `validate_game_turn_phase_aware` | 校验 actor 在 pending_submitters / active_participants 中 | `routing.rs` |

### 6.2 篡改 last_action_height

**场景**：assigned_validator 不更新 `last_action_height`，让游戏看起来超时，触发 force_advance。

**防护机制**：

| 机制 | 说明 |
| --- | --- |
| tx-driven 更新 | `last_action_height` 由 GameTurn tx 进 vertex 隐式更新，无需 assigned_validator 主动操作 |
| SEC-H6 | 跨 commit force_advance 防护（前 commit 有 GameTurn tx → 拒绝 force_advance） |
| S10 | `block.height` 严格单调递增，assigned_validator 无法操纵 |

---

## 7. 超时滥用类作恶

### 7.1 恶意触发超时惩罚

**场景**：assigned_validator 故意不打包某些玩家的 tx，等超时后 kick 玩家获利。

**防护机制**：

| 机制 | 说明 | 默认值 |
| --- | --- | --- |
| `turn_timeout_blocks` | 给玩家充足时间 | 30 blocks（~90s @ 3s/block） |
| fallback tx | 玩家可在 30 blocks 后向其他 validator 提交 | - |
| SEC-M1 | assigned_validator 长期不作为 → 自动 slashing | 2100 blocks |
| block.height 单调 | 攻击者无法加速时间 | - |

### 7.2 多玩家阶段恶意 kick

**场景**：assigned_validator 在 Shuffle 阶段故意不推进，等 100 blocks 后 kick 所有 pending 玩家。

**防护机制**：

| 机制 | 说明 |
| --- | --- |
| 超时配置合理 | Shuffle=100 / RevealToken=50 / Reconstruct=100 |
| 玩家可主动提交 | fallback tx 机制覆盖所有 GameTurn tx |
| downtime slashing | assigned_validator 长期不作为 → SEC-M1 自动 slashing |
| kick 后退款 | 玩家 `total_bet` 全额退款，资金安全 |

---

## 8. 跨阶段作恶

### 8.1 阶段切换滥用

**场景**：assigned_validator 恶意调用 `advance_phase()` 影响游戏。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| PhaseTransitionError::PendingSubmittersNotEmpty | `advance_phase` 要求 `pending_submitters.is_empty()` 才能推进 | `texas_holdem_turn_rule.rs` |
| 状态机转换规则固定 | Shuffle → RevealToken → Betting / Reconstruct → Betting 等，spec 约束 | `texas_holdem_turn_rule.rs` |
| Betting 阶段拒绝切换 | Betting 阶段调用 advance_phase 返回 Err(InvalidPhaseTransition) | `texas_holdem_turn_rule.rs` |

### 8.2 LeaveProof 滥用

**场景**：assigned_validator 伪造玩家 LeaveProof 强制玩家离开。

**防护机制**：

| 机制 | 说明 | 源码位置 |
| --- | --- | --- |
| 玩家签名 | LeaveProof.verify 校验玩家 BLS 签名 | `texas_poker_move/sources/leave_proof.move` |
| validate_game_turn_phase_aware LeaveProof 分支 | 校验 `actor ∈ active_participants` | `routing.rs` |
| assigned_validator 无法伪造 | BLS 签名需要玩家私钥 | - |

---

## 9. 防护层次矩阵

| 作恶类别 | L1 协议层 | L2 共识层 | L3 经济层 | L4 治理层 |
| --- | --- | --- | --- | --- |
| 审查（Censorship） | fallback tx | TimeoutProof witness | downtime slashing | 治理踢出 |
| 伪造（Forgery） | 签名验证 | nonce 校验 | - | - |
| 抢跑（Front-running） | SEC-H6 跨 commit 防护 | S9/R4-M4 排序 | - | - |
| Equivocation | SEC-C1/SEC2-C1 签名绑定 | vertex_hash / cert_hash | 100% slashing | - |
| 状态篡改 | tx-driven 状态 | state_root 绑定 | - | 玩家审计 |
| 超时滥用 | 合理超时配置 | block.height 单调 | downtime slashing | - |
| 跨阶段作恶 | advance_phase 约束 | 状态机固定 | - | - |

---

## 10. Slashing 优先级与罚没比例

源码：`poker_l1/src/consensus/slashing.rs`

### 10.1 SlashingReason 优先级（SEC2-H2）

| 优先级 | SlashingReason | 罚没比例 | 触发条件 |
| --- | --- | --- | --- |
| 1 | VertexEquivocation | 100%（NEW-M15） | 同一 (epoch, round, author) 双签 vertex |
| 2 | CommitCertEquivocation | 100%（NEW-M15） | 同一 (epoch, commit_round) 双签 commit certificate |
| 3 | CheckpointRefusal | 100% | 拒收 checkpoint |
| 4 | Downtime | 10%（DEFAULT_DOWNTIME_SLASH_PERCENTAGE） | 连续停机 |
| 5 | RefuseAck | 100% | 拒绝 ACK |

### 10.2 自动 vs 治理 slashing

| 类型 | 触发条件 | 默认阈值 | 是否需要治理介入 |
| --- | --- | --- | --- |
| 自动 slashing（SEC-M1） | 连续 `downtime_threshold_blocks + 2*epoch_length_blocks` 未提交 vertex | 2100 blocks | 否（治理仅用于争议申辩） |
| 治理踢出 | 连续 `downtime_threshold_blocks` 未提交 vertex | 100 blocks | 是 |
| Equivocation | 链上证据提交即触发 | - | 否（证据自验证） |

---

## 11. 关键常量速查

源码：`poker_l1/src/block/time_consensus.rs` / `poker_l1/src/consensus/slashing.rs` / `poker_l1/src/consensus/vertex_production.rs`

### 11.1 超时相关

| 常量 | 默认值 | 说明 |
| --- | --- | --- |
| `turn_timeout_blocks` | 30 | GameTurn 玩家行动超时 |
| `shuffle_timeout_blocks` | 100 | Shuffle 阶段超时 |
| `reveal_token_timeout_blocks` | 50 | RevealToken 阶段超时 |
| `reconstruct_timeout_blocks` | 100 | Reconstruct 阶段超时 |
| `hand_max_duration_blocks` | 300 | 单手牌最大持续 block 数 |
| `game_validator_timeout_blocks` | 50 | assigned_validator 超时阈值 |

### 11.2 Slashing 相关

| 常量 | 默认值 | 说明 |
| --- | --- | --- |
| `DEFAULT_SLASH_PERCENTAGE` | 100 | equivocation 类罚没比例 |
| `DEFAULT_DOWNTIME_SLASH_PERCENTAGE` | 10 | 停机罚没比例 |
| `DEFAULT_DOWNTIME_THRESHOLD_BLOCKS` | 100 | 治理踢出阈值 |
| `DEFAULT_DEFENSE_WINDOW_BLOCKS` | 200 | 申辩窗口 |

### 11.3 多副本见证相关

| 常量 | 默认值 | 说明 |
| --- | --- | --- |
| `DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT` | 5 | 多副本配置 |
| `required_witness_count(5)` | 4 | TimeoutProof 最少 witness 数 |

---

## 12. 源码索引

### 12.1 校验函数

| 函数 | 源码位置 | 防护场景 |
| --- | --- | --- |
| `validate_assigned_validator` | `poker_l1/src/consensus/routing.rs` | 校验接收 validator 身份 |
| `validate_turn_order` | `poker_l1/src/consensus/routing.rs` | 校验下注阶段轮转约束 |
| `validate_game_turn_phase_aware` | `poker_l1/src/consensus/routing.rs` | 校验多玩家阶段提交者 |
| `validate_game_turn_tx` | `poker_l1/src/consensus/vertex_production.rs` | 综合校验 GameTurn tx |
| `validate_fallback_tx` | `poker_l1/src/consensus/vertex_production.rs` | 校验 fallback tx |
| `validate_witness_independence` | `poker_l1/src/consensus/vertex_production.rs` | 校验 witness 独立性 |
| `validate_witness_count` | `poker_l1/src/consensus/vertex_production.rs` | 校验 witness 数量 |
| `check_sech6_cross_commit_force_advance` | `poker_l1/src/consensus/vertex_production.rs` | SEC-H6 跨 commit 防护 |
| `is_submit_phase_timed_out` | `poker_l1/src/block/time_consensus.rs` | 多玩家阶段超时判定 |
| `handle_submit_phase_timeout` | `poker_l1/src/consensus/phase_timeout.rs` | 超时惩罚执行 |

### 12.2 Slashing 函数

| 函数 | 源码位置 | 说明 |
| --- | --- | --- |
| `is_downtime_governance_kickout` | `poker_l1/src/consensus/slashing.rs` | 治理踢出判定 |
| `is_downtime_auto_slashable` | `poker_l1/src/consensus/slashing.rs` | SEC-M1 自动 slashing 判定 |
| `apply_slashing` | `poker_l1/src/consensus/slashing.rs` | 单个 slashing 执行 |
| `apply_multi_slashing` | `poker_l1/src/consensus/slashing.rs` | 多重 slashing 执行（SEC2-H2） |
| `compute_slash_amount` | `poker_l1/src/consensus/slashing.rs` | 计算罚没金额 |

### 12.3 签名绑定函数

| 函数 | 源码位置 | 防护场景 |
| --- | --- | --- |
| `DagVertex::vertex_hash` | `poker_l1/src/consensus/mod.rs` | vertex 内容哈希（含 tx 顺序） |
| `DagVertex::signing_hash` | `poker_l1/src/consensus/mod.rs` | SEC-C1 签名对象哈希 |
| `DagCommitCertificate::signing_hash` | `poker_l1/src/consensus/mod.rs` | SEC2-C1 签名对象哈希 |
| `DagCommitCertificate::cert_hash` | `poker_l1/src/consensus/mod.rs` | commit certificate 哈希（含签名） |

### 12.4 排序函数

| 函数 | 源码位置 | 防护场景 |
| --- | --- | --- |
| `sort_vertex_txs_s9` | `poker_l1/src/consensus/vertex_production.rs` | S9 vertex 内排序 |
| `sort_commit_txs_r4m4` | `poker_l1/src/consensus/vertex_production.rs` | R4-M4 commit 内排序 |
| `build_game_sub_block` | `poker_l1/src/consensus/vertex_production.rs` | game sub-block 排序 |

---

## 13. 安全审计检查清单

### 13.1 审查类防护检查

- [ ] `turn_timeout_blocks` 配置合理（默认 30）
- [ ] `checkpoint_multi_replica_count` 配置合理（默认 5）
- [ ] fallback tx 通道（Public）正常工作
- [ ] TimeoutProof.witness 独立性校验生效
- [ ] TimeoutProof.witness 数量校验生效（≥4）
- [ ] SEC-M1 自动 slashing 阈值监控
- [ ] 治理踢出流程文档化

### 13.2 伪造类防护检查

- [ ] 玩家签名验证生效
- [ ] `gameturn_nonce` 计数器正确递增
- [ ] `validate_turn_order` / `validate_game_turn_phase_aware` 校验生效
- [ ] fallback tx 的 SEC-H7 校验生效（is_fallback 标记）
- [ ] fallback tx 的 nonce 一致性校验生效

### 13.3 抢跑类防护检查

- [ ] SEC-H6 跨 commit force_advance 防护生效
- [ ] Phase 6 扩展覆盖 MultiPlayerSubmit 阶段
- [ ] S9 排序规则正确
- [ ] R4-M4 排序规则正确
- [ ] build_game_sub_block 排序键正确

### 13.4 Equivocation 类防护检查

- [ ] VertexEquivocation slashing 生效
- [ ] CommitCertEquivocation slashing 生效
- [ ] SEC-C1 签名绑定字段完整（chain_id / epoch / round / author_pubkey）
- [ ] SEC2-C1 签名绑定字段完整（chain_id / epoch / commit_round / prev_commit_hash / state_root / public_tx_root / gameturn_tx_root）

### 13.5 超时类防护检查

- [ ] `shuffle_timeout_blocks` / `reveal_token_timeout_blocks` / `reconstruct_timeout_blocks` 配置合理
- [ ] `is_submit_phase_timed_out()` 函数正确判定超时
- [ ] `handle_submit_phase_timeout()` 正确执行 kick + 退款
- [ ] 剩余 < 2 人时正确触发 finalize
- [ ] block.height 单调性保证

### 13.6 跨阶段防护检查

- [ ] `advance_phase` 要求 `pending_submitters.is_empty()`
- [ ] 状态机转换规则固定（Shuffle → RevealToken → Betting 等）
- [ ] Betting 阶段调用 advance_phase 返回 Err
- [ ] LeaveProof 需要玩家 BLS 签名

---

## 14. 参考

- [texas_poker_move/sources/leave_proof.move](../../zgame/texas_poker_move/sources/leave_proof.move) — LeaveProof 验证逻辑
- [texas_poker_move/sources/table.move](../../zgame/texas_poker_move/sources/table.move) — Move 合约多玩家阶段实现
- [37-6-dag-consensus-ops.md](37-6-dag-consensus-ops.md) — DAG 共识运维文档
- [37-8-game-phase-protocol.md](37-8-game-phase-protocol.md) — 游戏阶段协议文档
- spec：`.trae/specs/build-poker-l1-chain/spec.md` SubTask 7.3 / 7.4 / 7.5 / 8.4 / 8.6 / 8.9 / 11.3 / 13.2-13.5
- spec：`.trae/specs/extend-game-multiplayer-phases/spec.md` Phase 4 / Phase 5
