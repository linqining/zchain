# poker_l1 治理操作文档（SubTask 37.5）

> 覆盖范围：参数调整（ParameterChange）+ validator 集更新（ValidatorSetUpdate）+ 密钥轮换（KeyRotation）+ timelock 撤销（TimelockRevocation）
>
> 源文件：
> - `poker_l1/src/governance/mod.rs` — 治理核心（DEFAULT_* 常量、validate_param 边界、quorum 函数、ProposalKind、ProposalStatus）
> - `poker_l1/src/consensus/validator_set.rs` — validator 集更新、VRF、bonding/unbonding
> - `poker_l1/src/consensus/slashing.rs` — slashing 配置

---

## 1. 概述

poker_l1 采用 **链上提案投票 + timelock 延迟执行** 的治理模型。所有 validator 可对提案投票，达到 quorum 后提案通过；参数调整类提案须额外经历 timelock 延迟，期间可被撤销提案（TimelockRevocation）紧急叫停。

治理模型支持四类操作：

| 操作 | ProposalKind | 是否需要 timelock | 默认 quorum |
|------|-------------|-------------------|-------------|
| 参数调整 | `ParameterChange` | 是（`parameter_delay_blocks`） | 普通参数 2/3，敏感参数 90% |
| Validator 集更新 | `ValidatorSetUpdate` | 否（epoch 边界生效） | 始终 90% |
| 密钥轮换 | `KeyRotation` | 否（`key_rotation_delay_blocks` 内嵌于 effective_height） | 始终 90% |
| Timelock 撤销 | `TimelockRevocation` | 否（通过即立即撤销原提案） | 始终 90%（SEC-H8） |

核心常量（定义于 `governance/mod.rs`）：

- `DEFAULT_VOTING_PERIOD_BLOCKS = 1000`：投票期默认 1000 block
- `DEFAULT_PARAMETER_DELAY_BLOCKS = 2000`：参数 timelock 默认 2000 block（R3-M4：由 500 提升至 2000）
- `DEFAULT_EPOCH_LENGTH_BLOCKS = 1000`：epoch 长度默认 1000 block

安全约束一览：

- **SEC-H4**：敏感参数 90% quorum 补全 9 项
- **SEC-C2**：`validator_set_size` 90% quorum + 下限 5
- **SEC-H8**：timelock 撤销须 ≥90% 赞成，立即生效
- **SEC2-M6**：quorum 分母 = 当前 epoch validator 集大小（含离线）；参与率下限 2/3 / 90%
- **SEC-M2**：单次缩减比例 ≤ 20%
- **SEC-M4**：`verifier_status` per-chain_id 命名空间隔离
- **SEC2-H4**：密钥轮换 timelock（`key_rotation_delay_blocks`）

---

## 2. 提案类型（ProposalKind）

`ProposalKind` 枚举定义于 `governance/mod.rs`，共四种变体：

### 2.1 ParameterChange（参数调整）

```rust
pub enum ProposalKind {
    ParameterChange {
        param: ParamName,       // 目标参数名
        new_value: u64,         // 提议新值
        target_chain_id: ChainId, // SEC-M4：verifier_status per-chain_id
    },
    // ...
}
```

- 提交时由 `validate_param()` 校验参数边界，越界返回 `ParamOutOfBounds`。
- `verifier_status` 提案须校验 `target_chain_id == network_chain_id`（SEC-M4），否则返回 `ProposalChainIdMismatch`。
- 通过后进入 `Timelock` 状态，等待 `parameter_delay_blocks` 结束后执行。

### 2.2 ValidatorSetUpdate（validator 集更新）

```rust
pub enum ProposalKind {
    ValidatorSetUpdate {
        additions: Vec<ValidatorAddition>, // 加入的 validator（pubkey + stake）
        removals: Vec<TaggedPubkey>,       // 踢出的 validator pubkey
        effective_epoch: Epoch,            // 生效 epoch
    },
    // ...
}
```

- 始终 90% quorum（`finalize_voting` 中 `is_sensitive = true`）。
- 提交时校验 SEC-C2（新集大小 ≥ 5）与 SEC-M2（单次缩减 ≤ 20%）。
- 通过后直接进入 `Passed` 状态（无 timelock），在 epoch 边界由 consensus 模块应用。

### 2.3 KeyRotation（密钥轮换）

```rust
pub enum ProposalKind {
    KeyRotation {
        old_pubkey: TaggedPubkey,    // 旧 pubkey
        new_pubkey: TaggedPubkey,    // 新 pubkey
        effective_height: BlockHeight, // timelock 结束 height
    },
    // ...
}
```

- 始终 90% quorum。
- `effective_height = submit_height + voting_period_blocks + key_rotation_delay_blocks`，timelock 内嵌于生效 height（SEC2-H4）。
- 通过后进入 `Passed` 状态，用于 validator 私钥泄露后的紧急轮换。

### 2.4 TimelockRevocation（timelock 撤销）

```rust
pub enum ProposalKind {
    TimelockRevocation {
        original_proposal_id: u64, // 被撤销的原提案 ID
    },
    // ...
}
```

- 始终 90% quorum（SEC-H8）。
- 创建时校验原提案处于 `Timelock` 状态，否则返回 `ProposalNotInTimelock`。
- 通过后立即将原提案标记为 `Revoked`，原提案不可再执行。

---

## 3. 提案生命周期（ProposalStatus）

`ProposalStatus` 状态机定义于 `governance/mod.rs`：

```
┌─────────────────────────────────────────────────────────────────────┐
│                         提案状态转移图                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌────────┐  voting_end + 通过(普通参数)  ┌──────────┐              │
│  │        │ ───────────────────────────► │          │              │
│  │        │                              │ Timelock │ ── revoke ──► │
│  │        │  voting_end + 通过(集更新/   │          │              │
│  │ Voting │  密钥轮换/撤销)              └────┬─────┘   ┌────────┐ │
│  │        │ ───────────────────────────► ┌────┘         │        │ │
│  │        │                Passed        │              │ Revoked│ │
│  └────┬───┘                              ▼              └────────┘ │
│       │                              ┌────────┐                     │
│       │  voting_end + 未通过          │        │                     │
│       │ ───────────────────────────► │Executed│                     │
│       │                Rejected       │        │                     │
│       ▼                              └────────┘                     │
│   ┌────────┐                                                        │
│   │Rejected│                                                        │
│   └────────┘                                                        │
└─────────────────────────────────────────────────────────────────────┘
```

状态流转规则：

| 当前状态 | 触发条件 | 目标状态 | 说明 |
|---------|---------|---------|------|
| `Voting` | `voting_end` + 赞成达 quorum（ParameterChange） | `Timelock` | 设置 `timelock_end_height` |
| `Voting` | `voting_end` + 赞成达 quorum（ValidatorSetUpdate / KeyRotation） | `Passed` | 无 timelock，epoch 边界生效 |
| `Voting` | `voting_end` + 赞成达 quorum（TimelockRevocation） | `Passed` + 原提案 → `Revoked` | 立即撤销原提案 |
| `Voting` | `voting_end` + 赞成不足或参与率不足 | `Rejected` | 参与率下限：普通 2/3，敏感 90% |
| `Timelock` | `execute_proposal` + `timelock_end` 已过 | `Executed` | 参数正式生效 |
| `Timelock` | TimelockRevocation 提案通过 | `Revoked` | SEC-H8 紧急撤销 |
| `Passed` | `execute_proposal` | `Executed` | validator 集更新 / 密钥轮换执行 |

关键 block 阈值：

- `voting_period_blocks`：投票期，默认 1000 block
- `parameter_delay_blocks`：参数 timelock，默认 2000 block
- 投票期结束 height = `submit_height + voting_period_blocks`
- Timelock 结束 height = `voting_end_height + parameter_delay_blocks`

---

## 4. Quorum 机制

Quorum 计算定义于 `governance/mod.rs`，遵循 SEC2-M6 规则：**分母 = 当前 epoch validator 集大小（含离线 validator）**。

### 4.1 三种 quorum 函数

```rust
/// 普通参数 2/3 quorum（向上取整）
pub const fn required_yes_votes_normal(validator_count: usize) -> usize {
    if validator_count == 0 { return 0; }
    (validator_count * 2).div_ceil(3)  // ceil(n * 2 / 3)
}

/// 敏感参数 90% quorum（向上取整）
pub const fn required_yes_votes_sensitive(validator_count: usize) -> usize {
    if validator_count == 0 { return 0; }
    (validator_count * 9).div_ceil(10)  // ceil(n * 9 / 10)
}

/// 撤销提案 90% quorum（SEC-H8）
pub const fn required_revocation_votes(validator_count: usize) -> usize {
    required_yes_votes_sensitive(validator_count)  // 复用 90%
}
```

### 4.2 通过判定逻辑（`finalize_voting`）

提案通过须同时满足两个条件：

1. **参与率下限**：`total_votes (yes + no) ≥ required_participation`
   - 普通参数：`required_yes_votes_normal(n) = ceil(n * 2/3)`
   - 敏感参数 / ValidatorSetUpdate / KeyRotation / TimelockRevocation：`required_yes_votes_sensitive(n) = ceil(n * 9/10)`
2. **赞成票下限**：`yes_votes ≥ required_yes`
   - 普通参数：`ceil(n * 2/3)`
   - 敏感参数：`ceil(n * 9/10)`

任一条件不满足 → `Rejected`。

### 4.3 quorum 示例

| validator 数 n | 普通 2/3 (ceil) | 敏感 90% (ceil) |
|---------------|----------------|-----------------|
| 5 | 4 | 5 |
| 7 | 5 | 7 |
| 10 | 7 | 9 |
| 21 | 14 | 19 |
| 100 | 67 | 90 |

### 4.4 DDoS 检测（SEC2-M6）

`detect_voting_ddos()` 检测投票期离线率：若 `offline_rate > 30%`，返回 `true` 表示应延长投票期。

```rust
pub fn detect_voting_ddos(&self, proposal_id: u64, validator_count: usize) -> bool {
    let offline = validator_count.saturating_sub(proposal.total_votes());
    validator_count > 0 && offline * 100 / validator_count > 30
}
```

---

## 5. 完整参数清单（41 个可治理参数）

下表列出全部 41 个可治理参数（`ParamName` 枚举），每项含默认值、边界、是否敏感（90% quorum）及说明。

> 敏感参数标记为 **是**（需 90% quorum），普通参数标记为 **否**（需 2/3 quorum）。

| # | 参数名 | 默认值 | 边界 [min, max] | 敏感 | 说明 |
|---|--------|--------|-----------------|------|------|
| 1 | TurnTimeoutBlocks | 30 | [3, 1000] | 是 (SEC-H4) | turn 超时 block 数 |
| 2 | HandMaxDurationBlocks | 120 | [turn_timeout×4, 100000] | 否 | 单手牌最大持续 block 数 |
| 3 | DisputeWindowBlocks | 500 | [10, 10000] | 否 | dispute 窗口 block 数 |
| 4 | DaWindowBlocks | 500 | [10, 10000] | 否 | DA 窗口 block 数 |
| 5 | RecoveryWindowBlocks | 100 | [10, 10000] | 否 | recovery 窗口 block 数 |
| 6 | CheckpointIntervalBlocks | 5 | [1, 1000] | 否 | checkpoint 间隔 block 数 |
| 7 | GameValidatorTimeoutBlocks | 15 | [1, floor(turn_timeout/2)] | 否 | game validator 超时 block 数 |
| 8 | AckDeadlineBlocks | 3 | [1, 100] | 否 | ACK 截止 block 数 |
| 9 | MaxSkipSegments | 3 | [1, 10] | 是 (SEC-H4) | 最大跳过 segment 数 |
| 10 | MaliciousRefuseThreshold | 3 | [1, 100] | 是 (SEC-H4) | 恶意拒收阈值 |
| 11 | MaxIntervalMs | 2000 | [500, 60000] | 否 | 最大间隔（毫秒） |
| 12 | MaxActiveGamesPerPlayer | 10 | [1, 1000] | 否 | 每玩家最大活跃 game 数 |
| 13 | EpochLengthBlocks | 1000 | [100, 10000] | 是 (R3-H1) | epoch 长度 block 数 |
| 14 | MaxVertexSize | 256KB | [64KB, 4MB] | 否 | vertex 最大字节数 |
| 15 | BlockGasLimit | 100_000_000 | [10M, 200M] | 是 (R3-H1) | block gas 上限 |
| 16 | TxPruneAfterBlocks | 1000 | [100, 100000] | 否 | tx 裁剪延迟 block 数 |
| 17 | VertexPruneAfterBlocks | 10000 | [100, 100000] | 否 | vertex 裁剪延迟 block 数 |
| 18 | ArchiveNodeMinCount | 3 | [1, 100] | 否 | archive node 最小数量 |
| 19 | CheckpointMultiReplicaCount | 5 | [3, 15] | 是 (SEC-H4) | checkpoint 多副本数 |
| 20 | DelegatedEscapeMaxExpiryBlocks | 100 | [10, 1000] | 否 | delegated escape 最大过期 block 数 |
| 21 | DefenseWindowBlocks | 500 | [10, 1000] | 是 (R3-H1) | 防御窗口 block 数 |
| 22 | ParameterDelayBlocks | 2000 | [100, 10000] | 是 (R3-H1) | 参数 timelock block 数 |
| 23 | BondingPeriodBlocks | 1000 | [epoch_length, 10×epoch_length] | 是 (SEC-H4) | bonding 期 block 数 |
| 24 | SlashPercentage | 100 | [1, 100] | 是 (R3-H1) | equivocation slashing 百分比 (%) |
| 25 | DowntimeSlashPercentage | 10 | [1, 100] | 是 (R3-H1) | 停机 slashing 百分比 (%) |
| 26 | VerifierStatus | Stub (0) | (0=Stub, 1=Production) | 是 (R3-H1/NEW-C1) | ZK verifier 状态（per-chain_id） |
| 27 | DowntimeThresholdBlocks | 100 | [10, 10000] | 否 | 停机阈值 block 数 |
| 28 | VotingPeriodBlocks | 1000 | [10, 10000] | 否 | 投票期 block 数 |
| 29 | MaxDesignatedOperatorCheckExemptions | 3 | [0, 10] | 否 | designated operator 检查豁免上限 |
| 30 | UnderInvestigationThreshold | 3 | [1, 100] | 否 | 审查调查嫌疑阈值 |
| 31 | MaxRequestAckPerTurnTimeout | 3 | [1, 100] | 是 (SEC-H4) | 每 turn 超时最大 request ACK 数 |
| 32 | MaxClockDriftMs | 500 | [0, 60000] | 否 | 最大时钟偏移（毫秒） |
| 33 | ForfeitDepositRatio | 50 | [10, 200] | 否 | 弃权保证金比例 (%) |
| 34 | ChallengeDepositRatio | 50 | [1, 100] | 否 | 挑战保证金比例 (%) (SEC-C4) |
| 35 | ChallengeRewardRatio | 100 | [10, 100] | 否 | 挑战奖励比例 (%) (SEC-C4) |
| 36 | DesignatedOperatorBondAmount | 10000 | [1, 10^9] | 否 | designated operator bond 金额 |
| 37 | UnbondingPeriodBlocks | 2000 | [epoch_length, 10×epoch_length] | 是 (SEC-H4) | unbonding 期 block 数 |
| 38 | KeyRotationDelayBlocks | 1000 | [100, 10000] | 是 (SEC-H4) | 密钥轮换 timelock block 数 |
| 39 | ArchiveRetentionBlocks | 100000 | [1000, 1000000] | 是 (SEC-H4) | archive 保留 block 数 |
| 40 | ValidatorSetSize | 10 | [5, 1000] | 是 (SEC-C2) | validator 集大小上限 |
| 41 | MaxPartialCheckinCount | 3 | [1, 10] | 否 | 最大 partial checkin 数 (SEC-H1) |

### 5.1 依赖参数边界

部分参数的边界依赖其他参数的当前值（`validate_param` 中动态计算）：

| 参数 | 下界依赖 | 上界依赖 |
|------|---------|---------|
| HandMaxDurationBlocks | `turn_timeout_blocks × 4` | 固定 100000 |
| GameValidatorTimeoutBlocks | 固定 1 | `floor(turn_timeout_blocks / 2)` (R5-H2) |
| BondingPeriodBlocks | `epoch_length_blocks` | `10 × epoch_length_blocks` |
| UnbondingPeriodBlocks | `epoch_length_blocks` | `10 × epoch_length_blocks` |

> 修改 `turn_timeout_blocks` 或 `epoch_length_blocks` 后，依赖参数的边界会动态变化，后续提案须通过新边界校验。

---

## 6. 敏感参数分类

敏感参数（`is_sensitive() == true`）需 90% quorum 通过。共 17 个敏感 `ParamName`，加上始终 90% 的 `ValidatorSetUpdate` 提案类型，合计 18 项需 90% quorum 的治理项。

### 6.1 R3-H1 修正（7 项敏感参数 + ValidatorSetUpdate）

| 参数 | 默认值 | 边界 | 说明 |
|------|--------|------|------|
| BlockGasLimit | 100M | [10M, 200M] | block gas 上限，影响吞吐与 DoS 防御 |
| EpochLengthBlocks | 1000 | [100, 10000] | epoch 长度，影响共识节奏 |
| SlashPercentage | 100 | [1, 100] | equivocation 全额罚没比例 |
| DowntimeSlashPercentage | 10 | [1, 100] | 停机罚没比例 |
| VerifierStatus | Stub | (0,1) | ZK verifier 状态（NEW-C1） |
| ParameterDelayBlocks | 2000 | [100, 10000] | 参数 timelock，防止闪电治理 |
| DefenseWindowBlocks | 500 | [10, 1000] | 审查防御窗口 |

> **ValidatorSetUpdate** 提案类型始终 90% quorum（`finalize_voting` 中硬编码 `is_sensitive = true`），归入 R3-H1 范畴。

### 6.2 SEC-H4 补全（9 项）

| 参数 | 默认值 | 边界 | 说明 |
|------|--------|------|------|
| BondingPeriodBlocks | 1000 | [epoch, 10×epoch] | bonding 锁定期 |
| UnbondingPeriodBlocks | 2000 | [epoch, 10×epoch] | unbonding 锁定期（可被 slashing） |
| KeyRotationDelayBlocks | 1000 | [100, 10000] | 密钥轮换 timelock |
| CheckpointMultiReplicaCount | 5 | [3, 15] | checkpoint 多副本数 |
| ArchiveRetentionBlocks | 100000 | [1000, 1M] | archive 保留期 |
| MaxSkipSegments | 3 | [1, 10] | 最大跳过 segment 数 |
| TurnTimeoutBlocks | 30 | [3, 1000] | turn 超时 |
| MaliciousRefuseThreshold | 3 | [1, 100] | 恶意拒收阈值 |
| MaxRequestAckPerTurnTimeout | 3 | [1, 100] | 每 turn 超时最大 request ACK 数 |

### 6.3 SEC-C2（1 项）

| 参数 | 默认值 | 边界 | 说明 |
|------|--------|------|------|
| ValidatorSetSize | 10 | [5, 1000] | validator 集大小，下限 5 保障 OffChain 安全 |

### 6.4 始终 90% quorum 的提案类型

| 提案类型 | 原因 |
|---------|------|
| `ValidatorSetUpdate` | validator 集变更影响共识安全 |
| `KeyRotation` | 密钥轮换影响身份与签名 |
| `TimelockRevocation` | SEC-H8：撤销已通过提案须极高共识 |

---

## 7. Validator 集更新流程

Validator 集更新由 `ValidatorSetUpdate` 提案驱动，定义于 `governance/mod.rs` 与 `consensus/validator_set.rs`。

### 7.1 提案提交

```rust
// governance/mod.rs — create_validator_set_update_proposal
let new_size = prev_size + additions.len() - removals.len();

// SEC-C2：新 validator 集大小 >= 5
if new_size < 5 {
    return Err(PokerL1Error::ValidatorSetReductionTooSmall { new_size });
}

// SEC-M2：单次缩减比例 <= 20%
if !removals.is_empty() {
    let max_removals = prev_size * 20 / 100;
    if removals.len() > max_removals.max(1) {
        return Err(PokerL1Error::SingleReductionRatioExceeded { .. });
    }
}
```

约束常量（`consensus/validator_set.rs`）：

- `MIN_VALIDATOR_SET_SIZE = 5`（SEC-C2）
- `MAX_SINGLE_REDUCTION_RATIO = 20`（SEC-M2，单次缩减 ≤ 20%）

### 7.2 新 validator 加入流程

```
提交提案 (90% quorum)
    │
    ▼
投票通过 → Passed
    │
    ▼ (epoch 边界生效)
Bonding 状态 (bonding_period_blocks = 1000)
    │  可同步，不参与共识
    │  可被 slashing (can_be_slashed = true)
    ▼ (bonding_until_height 到达)
Active 状态 (参与共识出块)
```

- 新 validator 初始状态为 `Bonding`（`ValidatorEntry::new`）。
- `bonding_until_height` 到达后，由 `process_bonding_expiry()` 转为 `Active`。
- Bonding 期可被 slashing（`can_be_slashed()` 包含 `Bonding` 状态）。

### 7.3 validator 退出流程

```
Active 状态
    │
    ▼ start_unbonding(unbonding_until_height)
Unbonding 状态 (unbonding_period_blocks = 2000)
    │  不参与共识，但可被 slashing (can_be_slashed = true)
    │  须提交 vrf_key_destroy_proof (SEC2-M10)
    ▼ (unbonding_until_height 到达 + vrf_key_destroyed = true)
Retired 状态 (vrf_retired = true)
    │  质押可提取，不可再被 slashing
    ▼
```

关键校验（`finalize_unbonding`）：

- `unbonding_until_height` 须已到达，否则返回错误。
- `vrf_key_destroyed` 须为 `true`（SEC2-M10），否则 unbonding 期延长。
- 完成后 `vrf_retired = true`，validator 永久退出。

### 7.4 VRF key 销毁（SEC2-M10）

```rust
// consensus/validator_set.rs
pub fn mark_vrf_key_destroyed(&mut self, pubkey: &TaggedPubkey) -> PokerL1Result<()> {
    let v = self.find_validator_mut(pubkey)
        .ok_or_else(|| PokerL1Error::ValidatorNotInSet(pubkey.clone()))?;
    v.vrf_key_destroyed = true;
    Ok(())
}
```

退出 validator 须提交 `vrf_key_destroy_proof`，标记 `vrf_key_destroyed = true`。否则 unbonding 期无法结束，质押不可提取。

### 7.5 单次缩减比例限制（SEC-M2）

```rust
// consensus/validator_set.rs
pub fn validate_reduction_ratio(&self, removed_count: usize) -> PokerL1Result<()> {
    let prev_size = self.validators.len() as u32;
    let ratio = removed_count as u32 * 100 / prev_size;
    if ratio > MAX_SINGLE_REDUCTION_RATIO {
        return Err(...);
    }
    Ok(())
}
```

- 单次踢出比例 ≤ 20%（`MAX_SINGLE_REDUCTION_RATIO = 20`）。
- 防止恶意治理一次性清空 validator 集。
- 示例：10 个 validator 中最多踢出 2 个（20%）。

---

## 8. 密钥轮换（KeyRotation）

密钥轮换用于 validator 私钥泄露后的紧急身份迁移，定义于 `governance/mod.rs`。

### 8.1 提案参数

```rust
pub fn create_key_rotation_proposal(
    &mut self,
    old_pubkey: TaggedPubkey,
    new_pubkey: TaggedPubkey,
    proposer: TaggedPubkey,
    current_height: BlockHeight,
) -> PokerL1Result<u64> {
    let effective_height = current_height
        + self.params.voting_period_blocks
        + self.params.key_rotation_delay_blocks;  // timelock 内嵌
    // ...
}
```

### 8.2 timelock 机制

- `key_rotation_delay_blocks` 默认 1000（敏感参数，90% quorum 可治理）。
- timelock 内嵌于 `effective_height`：`effective = submit + voting_period + key_rotation_delay`。
- timelock 期间旧密钥仍可用于提交 slashing 证据（SEC2-H4），防止轮换前遗留证据失效。
- 投票通过后进入 `Passed` 状态（非 `Timelock`），到 `effective_height` 后执行。

### 8.3 安全说明

- 密钥轮换始终 90% quorum。
- 轮换不改变 validator 的质押与 VRF key，仅替换签名 pubkey。
- 适用于：私钥泄露、密钥迁移、安全事件应急响应。

---

## 9. Timelock 撤销（TimelockRevocation）

已通过但未执行的参数调整提案可被撤销，定义于 `governance/mod.rs`，遵循 SEC-H8。

### 9.1 撤销条件

- 原提案须处于 `Timelock` 状态（已通过投票、timelock 未结束）。
- 撤销提案无独立 timelock，通过后立即生效。

```rust
pub fn create_revocation_proposal(
    &mut self,
    original_proposal_id: u64,
    proposer: TaggedPubkey,
    current_height: BlockHeight,
) -> PokerL1Result<u64> {
    let original = self.proposals.get(&original_proposal_id)
        .ok_or_else(|| ...)?;
    if original.status != ProposalStatus::Timelock {
        return Err(PokerL1Error::ProposalNotInTimelock(original.status));
    }
    // 创建撤销提案（无 timelock）
    // ...
}
```

### 9.2 撤销执行

撤销提案通过 90% quorum 后，`finalize_voting` 立即将原提案标记为 `Revoked`：

```rust
ProposalKind::TimelockRevocation { original_proposal_id } => {
    proposal.status = ProposalStatus::Passed;
    if let Some(orig) = self.proposals.get_mut(&orig_id) {
        orig.status = ProposalStatus::Revoked;  // 原提案被撤销
    }
    Ok(ProposalStatus::Passed)
}
```

被撤销的原提案不可再执行（`execute_proposal` 对 `Revoked` 状态返回 `ProposalNotInTimelock` 错误）。

### 9.3 使用场景

- **闪电治理防御**：参数调整通过后发现存在风险，紧急撤销。
- **安全应急**：发现提案被恶意推动，90% validator 联合撤销。
- **参数回滚**：timelock 内重新评估后决定不执行。

---

## 10. 操作示例

以下 Rust 代码示例展示治理提案的创建、投票与执行完整流程。

### 10.1 参数调整提案（普通参数，2/3 quorum）

```rust
use poker_l1::governance::{GovernanceState, ParamName, ProposalStatus};

let mut state = GovernanceState::new();
let proposer = make_pubkey(0x01);
let pubkeys = make_pubkeys(10); // 10 个 validator

// 1. 创建提案：修改 ack_deadline_blocks = 10（非敏感，2/3 quorum）
let proposal_id = state.create_parameter_proposal(
    ParamName::AckDeadlineBlocks,
    10,
    poker_l1::DEFAULT_CHAIN_ID,
    proposer,
    100,  // current_height
    poker_l1::DEFAULT_CHAIN_ID,
)?;

// 2. 投票：7 个赞成（ceil(10 * 2/3) = 7，达到 quorum）
for pk in &pubkeys[0..7] {
    state.vote(proposal_id, pk.clone(), true, 100)?;
}

// 3. 结束投票（voting_end_height = 100 + 1000 = 1100）
let status = state.finalize_voting(proposal_id, 10, 1100)?;
assert_eq!(status, ProposalStatus::Timelock);

// 4. timelock 结束后执行（timelock_end = 1100 + 2000 = 3100）
state.execute_proposal(proposal_id, 3100)?;
assert_eq!(state.params.ack_deadline_blocks, 10);
```

### 10.2 敏感参数提案（90% quorum）

```rust
// 修改 slash_percentage = 50（敏感，需 90% quorum）
let proposal_id = state.create_parameter_proposal(
    ParamName::SlashPercentage,
    50,
    poker_l1::DEFAULT_CHAIN_ID,
    proposer,
    100,
    poker_l1::DEFAULT_CHAIN_ID,
)?;

// 仅 7 票赞成 < 9（ceil(10 * 9/10) = 9）→ 拒绝
for pk in &pubkeys[0..7] {
    state.vote(proposal_id, pk.clone(), true, 100)?;
}
let status = state.finalize_voting(proposal_id, 10, 1100)?;
assert_eq!(status, ProposalStatus::Rejected);

// 需 9 票赞成才能通过
let proposal_id2 = state.create_parameter_proposal(
    ParamName::SlashPercentage, 50, /* ... */
)?;
for pk in &pubkeys[0..9] {
    state.vote(proposal_id2, pk.clone(), true, 100)?;
}
let status = state.finalize_voting(proposal_id2, 10, 1100)?;
assert_eq!(status, ProposalStatus::Timelock); // 通过，进入 timelock
```

### 10.3 Validator 集更新提案（始终 90% quorum）

```rust
use poker_l1::governance::{GovernanceState, ValidatorAddition};

let mut state = GovernanceState::new();
let proposer = make_pubkey(0x01);

// 当前 validator 集（10 个 Active validator）
let current_set = make_validator_set(10);

// 加入 1 个新 validator
let addition = ValidatorAddition {
    pubkey: make_pubkey(0x20),
    stake: 1_000_000,
};

let proposal_id = state.create_validator_set_update_proposal(
    &current_set,
    vec![addition],
    vec![],     // 不踢出
    2,          // effective_epoch = 2
    proposer,
    100,
)?;

// 投票需 90%（ceil(10 * 9/10) = 9 票）
for pk in &pubkeys[0..9] {
    state.vote(proposal_id, pk.clone(), true, 100)?;
}

// 通过后直接 Passed（无 timelock）
let status = state.finalize_voting(proposal_id, 10, 1100)?;
assert_eq!(status, ProposalStatus::Passed);

// epoch 边界由 consensus 模块应用：新 validator 进入 Bonding 期
```

### 10.4 Timelock 撤销提案（SEC-H8）

```rust
// 1. 原提案：修改 ack_deadline_blocks，2/3 quorum 通过
let original_id = state.create_parameter_proposal(
    ParamName::AckDeadlineBlocks, 10, /* ... */
)?;
for pk in &pubkeys[0..7] {
    state.vote(original_id, pk.clone(), true, 100)?;
}
state.finalize_voting(original_id, 10, 1100)?; // → Timelock

// 2. timelock 内创建撤销提案
let revocation_id = state.create_revocation_proposal(
    original_id,
    proposer,
    1200,  // timelock 内
)?;

// 3. 撤销需 90% quorum（ceil(10 * 9/10) = 9 票）
for pk in &pubkeys[0..9] {
    state.vote(revocation_id, pk.clone(), true, 1200)?;
}

// 4. 结束撤销投票 → 通过，原提案立即被撤销
let status = state.finalize_voting(revocation_id, 10, 1200 + 1000)?;
assert_eq!(status, ProposalStatus::Passed);
assert_eq!(state.proposals[&original_id].status, ProposalStatus::Revoked);

// 5. 执行原提案 → 失败（已撤销）
let result = state.execute_proposal(original_id, 5000);
assert!(result.is_err());
```

### 10.5 密钥轮换提案

```rust
let old_pk = make_pubkey(0x01);
let new_pk = make_pubkey(0x02);

let proposal_id = state.create_key_rotation_proposal(
    old_pk,
    new_pk,
    make_pubkey(0x03),  // proposer
    100,                // current_height
)?;

// 始终 90% quorum
for pk in &pubkeys[0..9] {
    state.vote(proposal_id, pk.clone(), true, 100)?;
}

// 通过后 Passed（timelock 内嵌于 effective_height）
let status = state.finalize_voting(proposal_id, 10, 1100)?;
assert_eq!(status, ProposalStatus::Passed);

// effective_height = 100 + 1000 + 1000 = 2100 后执行
state.execute_proposal(proposal_id, 2100)?;
assert_eq!(state.proposals[&proposal_id].status, ProposalStatus::Executed);
```

### 10.6 VerifierStatus 治理（per-chain_id，SEC-M4）

```rust
// mainnet 默认 Stub，拒绝 OffChain checkout
assert_eq!(state.verifier_status(poker_l1::DEFAULT_CHAIN_ID), VerifierStatus::Stub);
assert!(!state.is_offchain_checkout_allowed(poker_l1::DEFAULT_CHAIN_ID));

// 创建提案：升级为 Production（敏感，90% quorum）
// SEC-M4：target_chain_id 须 == network_chain_id
let proposal_id = state.create_parameter_proposal(
    ParamName::VerifierStatus,
    1,  // 1 = Production
    poker_l1::DEFAULT_CHAIN_ID,
    proposer,
    100,
    poker_l1::DEFAULT_CHAIN_ID,  // 须一致
)?;

for pk in &pubkeys[0..9] {
    state.vote(proposal_id, pk.clone(), true, 100)?;
}
state.finalize_voting(proposal_id, 10, 1100)?;

// timelock 结束后执行
state.execute_proposal(proposal_id, 1100 + 2000)?;
assert_eq!(state.verifier_status(poker_l1::DEFAULT_CHAIN_ID), VerifierStatus::Production);
assert!(state.is_offchain_checkout_allowed(poker_l1::DEFAULT_CHAIN_ID));
```

---

## 附录 A：Slashing 与治理的交互

Slashing 配置（`consensus/slashing.rs`）受以下治理参数驱动：

| Slashing 原因 | 优先级 | slash_percentage | 可治理参数 |
|--------------|--------|-----------------|-----------|
| VertexEquivocation | 1 | 100% | SlashPercentage（敏感） |
| CommitCertEquivocation | 2 | 100% | SlashPercentage（敏感） |
| RefuseCheckpoint | 3 | 100% | SlashPercentage（敏感） |
| Downtime | 4 | 10% | DowntimeSlashPercentage（敏感） |
| RefuseAck | 5 | 100% | SlashPercentage（敏感） |

关键规则（SEC2-H2）：

- 扣除基数 = **剩余质押**（非原始质押），多重 slashing 依次从剩余中扣除。
- 停机自动 slashing 阈值 = `downtime_threshold_blocks + 2 × epoch_length_blocks`（SEC-M1）。
- Retired 状态 validator 不可再被 slashing。

---

## 附录 B：关键常量速查

| 常量 | 值 | 定义位置 | 说明 |
|------|-----|---------|------|
| `DEFAULT_VOTING_PERIOD_BLOCKS` | 1000 | governance/mod.rs | 投票期 |
| `DEFAULT_PARAMETER_DELAY_BLOCKS` | 2000 | governance/mod.rs | 参数 timelock |
| `DEFAULT_EPOCH_LENGTH_BLOCKS` | 1000 | governance/mod.rs | epoch 长度 |
| `DEFAULT_BONDING_PERIOD_BLOCKS` | 1000 | governance/mod.rs | bonding 期（= 1 epoch） |
| `DEFAULT_UNBONDING_PERIOD_BLOCKS` | 2000 | governance/mod.rs | unbonding 期（= 2 epoch） |
| `DEFAULT_KEY_ROTATION_DELAY_BLOCKS` | 1000 | governance/mod.rs | 密钥轮换 timelock |
| `DEFAULT_SLASH_PERCENTAGE` | 100 | governance/mod.rs | equivocation 罚没比例 |
| `DEFAULT_DOWNTIME_SLASH_PERCENTAGE` | 10 | governance/mod.rs | 停机罚没比例 |
| `DEFAULT_VALIDATOR_SET_SIZE` | 10 | governance/mod.rs | validator 集大小 |
| `DEFAULT_DEFENSE_WINDOW_BLOCKS` | 500 | governance/mod.rs | 防御窗口 |
| `MIN_VALIDATOR_SET_SIZE` | 5 | consensus/validator_set.rs | validator 集下限（SEC-C2） |
| `MAX_SINGLE_REDUCTION_RATIO` | 20 | consensus/validator_set.rs | 单次缩减上限 %（SEC-M2） |

---

*本文档基于 spec.md（FROZEN 2026-06-27）与 `poker_l1` 源码生成，覆盖 SubTask 37.5：治理操作文档。*
