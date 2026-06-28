# poker_l1 节点部署文档（SubTask 37.1）

> 本文档覆盖 SubTask 37.1：节点部署文档（含 genesis 配置：validator 集、初始参数、epoch 配置）。
> 所有参数值严格对齐 `spec.md`（FROZEN 2026-06-27）与 `poker_l1` 源码常量定义。

---

## 1. 概述

`poker_l1` 是面向链下博弈场景的高性能 L1 区块链，采用 DAG vertex + Bullshark commit certificate 共识模型，配合 GameTurn sub-block 机制承载链下执行结果上链。网络由四种节点角色协同运作：

| 节点角色 | 共识参与 | 裁剪策略 | 典型用途 |
| --- | --- | --- | --- |
| **Validator** | 参与 DAG vertex 产出 + Bullshark 投票 + game sub-block 产出 | 同 Full（Layer 1-3 裁剪） | 出块节点，需质押 + VRF key |
| **Full**（默认） | 仅验证，不参与共识 | Layer 1-3 裁剪 | RPC 服务、tx 提交、状态查询 |
| **Archive** | 仅验证 | 永不裁剪 | 提供 `request_historical_data` RPC，链上历史回溯 |
| **Light** | 仅订阅 block header + state root | 仅 header | 轻客户端、跨链桥验证 |

### 1.1 网络架构要点

- **DAG vertex 传播**：基于 gossipsub，validator 把 tx 批量打包为 vertex（上限 `MAX_VERTEX_SIZE=256KB`），引用 ≥2/3 validator 的上一轮 vertex hash，附 secp256k1 签名。
- **Compact Block Relay**：validator 先广播 compact vertex（vertex header + tx short IDs，`SHORT_ID_LEN=8` 字节），接收方从本地 tx 缓存匹配，缺失部分再请求完整 tx。
- **无 mempool 设计**（O1 移除）：tx 直接装入下一个 vertex，内存中仅保留 `MEMPOOL_BUFFER_WINDOW_MS=100ms` 缓冲窗口。
- **chain_id 重放保护**（SEC-L4）：所有 tx 与 vertex 签名对象绑定 `chain_id`，跨链重放无效。

### 1.2 源码索引

| 模块 | 源文件 |
| --- | --- |
| 顶层常量 / chain_id | `poker_l1/src/lib.rs` |
| NodeRole / NodeConfig | `poker_l1/src/node/mod.rs` |
| TimeConsensusConfig | `poker_l1/src/block/time_consensus.rs` |
| ValidatorEntry / VRF | `poker_l1/src/consensus/validator_set.rs` |
| GovernanceParams / DEFAULT_* | `poker_l1/src/governance/mod.rs` |
| 网络约束 / Compact Block Relay | `poker_l1/src/network/mod.rs` |
| MAX_VERTEX_SIZE | `poker_l1/src/consensus/mod.rs` |

---

## 2. genesis 配置

genesis 配置定义网络启动初始状态，包含三部分：validator 集初始化、初始治理参数、epoch 与 chain_id 配置。

### 2.1 chain_id 配置

`chain_id` 是网络的唯一标识，用于跨链重放保护（M10 / SEC-L4）。源码定义于 `poker_l1/src/lib.rs`：

```rust
pub const DEFAULT_CHAIN_ID: ChainId = 0x706F_6B31;
```

| 网络 | chain_id | 说明 |
| --- | --- | --- |
| testnet | `0x706F_6B31`（"pok1"） | `DEFAULT_CHAIN_ID`，开发与测试网络 |
| mainnet | 由 genesis 文件指定 | 生产网络，须与 testnet 不同 |

> **SEC-L4 约束**：所有 tx、vertex 签名对象、VRF input 均绑定 `chain_id`，跨链重放视为无效。

### 2.2 validator 集初始化

genesis validator 集须满足 **SEC-C2**：OffChain 模式下 `|V| >= 5`（`MIN_VALIDATOR_SET_SIZE=5`）。每个 validator 由 `ValidatorEntry` 描述（源码：`poker_l1/src/consensus/validator_set.rs`）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `pubkey` | `TaggedPubkey` | secp256k1 tagged pubkey（用于 vertex / commit certificate 签名） |
| `vrf_pubkey` | `[u8; 33]` | VRF pubkey（IMPL-SEC-2：compressed secp256k1，**33 字节**） |
| `stake` | `u64` | 质押金额 |
| `status` | `ValidatorStatus` | 初始为 `Bonding`，到 `bonding_until_height` 后转 `Active` |
| `bonding_until_height` | `BlockHeight` | Bonding 期结束 height |
| `unbonding_until_height` | `BlockHeight` | Unbonding 期结束 height（初始 0） |
| `last_vertex_height` | `BlockHeight` | 最后一次产出 vertex 的 height（初始 0） |
| `under_investigation_count` | `u32` | 审查嫌疑计数（每 epoch 衰减 1） |
| `vrf_key_destroyed` | `bool` | VRF 私钥是否已销毁（SEC2-M10） |
| `vrf_retired` | `bool` | VRF pubkey 是否已 retired |

#### VRF 常量

| 常量 | 值 | 说明 |
| --- | --- | --- |
| `VRF_PUBKEY_SIZE` | 33 字节 | compressed secp256k1 |
| `VRF_PROOF_SIZE` | 97 字节 | `gamma_33B \|\| c_32B \|\| s_32B`（ECVRF-secp256k1 + SHA-256） |
| `VRF_OUTPUT_SIZE` | 32 字节 | SHA-256 random output |
| `MIN_VALIDATOR_SET_SIZE` | 5 | SEC-C2 主网最小 validator 规模 |

#### ValidatorStatus 状态机

```
Bonding ──(bonding_until_height 到达)──> Active
Active  ──(start_unbonding)────────────> Unbonding
Unbonding ──(unbonding_until_height 到达 + vrf_key_destroyed)──> Retired
Active/Bonding/Unbonding ──(slashing)──> Slashed
```

### 2.3 初始参数（GovernanceParams）

初始参数从 `poker_l1/src/governance/mod.rs` 的 `DEFAULT_*` 常量读取，写入 `GovernanceParams::default_values()`。下表列出关键初始参数及其默认值与边界：

#### 2.3.1 共识与超时参数

| 参数 | 默认值 | 边界 | 敏感 | 说明 |
| --- | --- | --- | --- | --- |
| `epoch_length_blocks` | `1000` (`DEFAULT_EPOCH_LENGTH_BLOCKS`) | [100, 10000] | 是 | 每 1000 block 重分配 validator 集 |
| `epoch_transition_window_blocks` | `10` (`DEFAULT_EPOCH_TRANSITION_WINDOW_BLOCKS`) | [1, 100] | 否 | epoch 边界前过渡窗口 |
| `turn_timeout_blocks` | `30` (`DEFAULT_TURN_TIMEOUT_BLOCKS`) | [3, 1000] | 是 | GameTurn 玩家行动超时 |
| `hand_max_duration_blocks` | `120` (`DEFAULT_HAND_MAX_DURATION_BLOCKS`) | [turn_timeout*4, 100000] | 否 | 单手牌最大持续 block 数 |
| `game_validator_timeout_blocks` | `15` (`DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS`) | [1, floor(turn_timeout/2)] | 否 | assigned_validator 超时阈值 |
| `da_window_blocks` | `500` (`DEFAULT_DA_WINDOW_BLOCKS`) | [10, 10000] | 否 | 数据可用性窗口 |
| `dispute_window_blocks` | `500` (`DEFAULT_DISPUTE_WINDOW_BLOCKS`) | [10, 10000] | 否 | 争议窗口 |
| `recovery_window_blocks` | `100` (`DEFAULT_RECOVERY_WINDOW_BLOCKS`) | [10, 10000] | 否 | 恢复窗口 |
| `checkpoint_interval_blocks` | `5` (`DEFAULT_CHECKPOINT_INTERVAL_BLOCKS`) | [1, 1000] | 否 | checkpoint 提交间隔 |
| `ack_deadline_blocks` | `3` (`DEFAULT_ACK_DEADLINE_BLOCKS`) | [1, 100] | 否 | ack 截止 block 数 |
| `max_skip_segments` | `3` (`DEFAULT_MAX_SKIP_SEGMENTS`) | [1, 10] | 是 | 最大跳过 segment 数 |

#### 2.3.2 治理流程参数

| 参数 | 默认值 | 边界 | 敏感 | 说明 |
| --- | --- | --- | --- | --- |
| `voting_period_blocks` | `1000` (`DEFAULT_VOTING_PERIOD_BLOCKS`) | [10, 10000] | 否 | 投票期 |
| `parameter_delay_blocks` | `2000` (`DEFAULT_PARAMETER_DELAY_BLOCKS`) | [100, 10000] | 是 | 参数调整 timelock（R3-M4 提升） |
| `bonding_period_blocks` | `1000` (`DEFAULT_BONDING_PERIOD_BLOCKS`) | [epoch_length, 10*epoch_length] | 是 | 新 validator 锁定期（= 1 epoch） |
| `unbonding_period_blocks` | `2000` (`DEFAULT_UNBONDING_PERIOD_BLOCKS`) | [epoch_length, 10*epoch_length] | 是 | 退出锁定期（= 2 × epoch，可被 slashing） |
| `key_rotation_delay_blocks` | `1000` (`DEFAULT_KEY_ROTATION_DELAY_BLOCKS`) | [100, 10000] | 是 | 密钥轮换 timelock |

#### 2.3.3 Slashing 与惩罚参数

| 参数 | 默认值 | 边界 | 敏感 | 说明 |
| --- | --- | --- | --- | --- |
| `slash_percentage` | `100` (`DEFAULT_SLASH_PERCENTAGE`) | [1, 100] | 是 | 恶意行为 slash 比例（NEW-M15：100%） |
| `downtime_slash_percentage` | `10` (`DEFAULT_DOWNTIME_SLASH_PERCENTAGE`) | [1, 100] | 是 | 停机 slash 比例（NEW-L2：10%） |
| `downtime_threshold_blocks` | `100` (`DEFAULT_DOWNTIME_THRESHOLD_BLOCKS`) | [10, 10000] | 否 | 停机判定阈值 |
| `under_investigation_threshold` | `3` (`DEFAULT_UNDER_INVESTIGATION_THRESHOLD`) | [1, 100] | 否 | 审查嫌疑阈值 |
| `malicious_refuse_threshold` | `3` (`DEFAULT_MALICIOUS_REFUSE_THRESHOLD`) | [1, 100] | 是 | 恶意拒绝阈值 |

#### 2.3.4 网络与容量参数

| 参数 | 默认值 | 边界 | 敏感 | 说明 |
| --- | --- | --- | --- | --- |
| `block_gas_limit` | `100_000_000` (`DEFAULT_BLOCK_GAS_LIMIT`) | [10M, 200M] | 是 | 单 block gas 上限（100M gas） |
| `max_vertex_size` | `256KB` (`DEFAULT_MAX_VERTEX_SIZE`) | [64KB, 4MB] | 否 | vertex 大小上限 |
| `max_active_games_per_player` | `10` (`DEFAULT_MAX_ACTIVE_GAMES_PER_PLAYER`) | [1, 1000] | 否 | 单玩家最大活跃 game 数 |
| `tx_prune_after_blocks` | `1000` (`DEFAULT_TX_PRUNE_AFTER_BLOCKS`) | [100, 100000] | 否 | tx 裁剪延迟 |
| `vertex_prune_after_blocks` | `10_000` (`DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS`) | [100, 100000] | 否 | vertex 裁剪延迟 |
| `archive_retention_blocks` | `100_000` (`DEFAULT_ARCHIVE_RETENTION_BLOCKS`) | [1000, 1000000] | 是 | archive 节点保留窗口 |
| `max_interval_ms` | `2000` (`DEFAULT_MAX_INTERVAL_MS`) | [500, 60000] | 否 | timestamp_ms 最大间隔（软引用） |
| `max_clock_drift_ms` | `500` (`DEFAULT_MAX_CLOCK_DRIFT_MS`) | [0, 60000] | 否 | 链下时钟漂移容忍（软引用） |

#### 2.3.5 副本与 checkpoint 参数

| 参数 | 默认值 | 边界 | 敏感 | 说明 |
| --- | --- | --- | --- | --- |
| `checkpoint_multi_replica_count` | `5` (`DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT`) | [3, 15] | 是 | checkpoint 多副本数 |
| `archive_node_min_count` | `3` (`DEFAULT_ARCHIVE_NODE_MIN_COUNT`) | [1, 100] | 否 | archive 节点最小数量 |
| `validator_set_size` | `10` (`DEFAULT_VALIDATOR_SET_SIZE`) | [5, 1000] | 是 | validator 集目标规模（SEC-C2） |
| `designated_operator_bond_amount` | `10_000` (`DEFAULT_DESIGNATED_OPERATOR_BOND_AMOUNT`) | [1, 10^9] | 否 | designated operator 质押金额 |
| `forfeit_deposit_ratio` | `50` (`DEFAULT_FORFEIT_DEPOSIT_RATIO`) | [10, 200] | 否 | 弃权保证金比例（%） |
| `challenge_deposit_ratio` | `50` (`DEFAULT_CHALLENGE_DEPOSIT_RATIO`) | [1, 100] | 否 | 挑战保证金比例（SEC-C4） |
| `challenge_reward_ratio` | `100` (`DEFAULT_CHALLENGE_REWARD_RATIO`) | [10, 100] | 否 | 挑战奖励比例（SEC-C4） |
| `max_partial_checkin_count` | `3` (`DEFAULT_MAX_PARTIAL_CHECKIN_COUNT`) | [1, 10] | 否 | 部分签到上限（SEC-H1） |
| `defense_window_blocks` | `500` (`DEFAULT_DEFENSE_WINDOW_BLOCKS`) | [10, 1000] | 是 | 辩护窗口 |
| `delegated_escape_max_expiry_blocks` | `100` (`DEFAULT_DELEGATED_ESCAPE_MAX_EXPIRY_BLOCKS`) | [10, 1000] | 否 | 委托逃生最大过期 block |

### 2.4 epoch 配置

epoch 是 validator 集重分配的基本周期，由 `epoch_length_blocks` 与 `epoch_transition_window_blocks` 共同决定：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `epoch_length_blocks` | `1000` | 每 1000 block 触发一次 epoch 边界，重分配 validator 集 |
| `epoch_transition_window_blocks` | `10` | epoch 边界前 10 block 内，OffChain Game 操作方须提交 `checkpoint_anchor` |

epoch 推进规则（`poker_l1/src/block/time_consensus.rs`）：
- `is_epoch_boundary(h)`：`h % epoch_length_blocks == 0` 时为 epoch 边界
- `epoch_of(h)`：`h / epoch_length_blocks`（向下取整）
- `in_epoch_transition_window(h)`：距下一 epoch 边界 `<= epoch_transition_window_blocks` 时为过渡窗口

### 2.5 genesis 配置示例

#### 2.5.1 JSON 示例

```json
{
  "chain_id": 1886345265,
  "genesis_chain_randomness": "0000000000000000000000000000000000000000000000000000000000000000",
  "validator_set": {
    "epoch": 1,
    "validators": [
      {
        "pubkey": { "tag": "0x01", "raw": "02..." },
        "vrf_pubkey": "02...(33 bytes)",
        "stake": 1000000,
        "status": "Active",
        "bonding_until_height": 0,
        "unbonding_until_height": 0,
        "last_vertex_height": 0,
        "under_investigation_count": 0,
        "vrf_key_destroyed": false,
        "vrf_retired": false
      }
    ]
  },
  "governance_params": {
    "epoch_length_blocks": 1000,
    "epoch_transition_window_blocks": 10,
    "turn_timeout_blocks": 30,
    "bonding_period_blocks": 1000,
    "unbonding_period_blocks": 2000,
    "slash_percentage": 100,
    "downtime_slash_percentage": 10,
    "block_gas_limit": 100000000,
    "validator_set_size": 10,
    "archive_node_min_count": 3
  },
  "time_consensus": {
    "max_interval_ms": 30000,
    "max_clock_drift_ms": 5000,
    "turn_timeout_blocks": 30,
    "hand_max_duration_blocks": 300,
    "dispute_window_blocks": 200,
    "da_window_blocks": 500,
    "checkpoint_interval_blocks": 100,
    "game_validator_timeout_blocks": 50,
    "epoch_length_blocks": 1000,
    "epoch_transition_window_blocks": 10
  }
}
```

> 注：genesis validator 初始 `status` 可设为 `Active` 以跳过 bonding 期；新加入 validator 须经历 `bonding_period_blocks=1000` 锁定期。

---

## 3. 节点角色与配置

### 3.1 节点角色详解

源码：`poker_l1/src/node/mod.rs`，`NodeRole` 枚举定义四种角色。

#### 3.1.1 Validator

```rust
pub enum NodeRole {
    Validator,
    Full,       // #[default]
    Archive,
    Light,
}
```

- **职责**：参与 DAG vertex 产出 + Bullshark 投票 + game sub-block 产出
- **密钥要求**：须持有 `ValidatorKey`（secp256k1 私钥 32 字节 + tagged pubkey）
- **裁剪行为**：同 Full，执行 Layer 1-3 裁剪
- **质押要求**：须质押并注册 VRF pubkey，经历 `bonding_period_blocks=1000` 后转为 `Active`
- **tx 缓冲**：`submit_tx` 时将 tx 装入 `pending_tx` 缓冲，等待打包入下一个 vertex

#### 3.1.2 Full（默认）

- **职责**：仅验证，不参与共识
- **裁剪行为**：Layer 1-3 裁剪（`should_prune() = true`）
- **密钥要求**：无需 validator 密钥
- **tx 缓冲**：不缓冲 tx（`pending_tx` 始终为空）

#### 3.1.3 Archive

- **职责**：仅验证，永不裁剪
- **特殊 RPC**：提供 `request_historical_data` RPC（`serves_historical_data() = true`）
- **最小数量**：网络须维持 `DEFAULT_ARCHIVE_NODE_MIN_COUNT=3` 个 archive 节点
- **保留窗口**：`archive_retention_blocks=100_000`

#### 3.1.4 Light

- **职责**：仅订阅 block header + state root commitment
- **裁剪行为**：仅保留 header（`should_prune() = false`，但存储极简）
- **验证机制**：secp256k1 多签验证 + 2/3 quorum（`verify_block_header_quorum`）

### 3.2 NodeConfig 字段

源码：`poker_l1/src/node/mod.rs`，`NodeConfig` 结构：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `role` | `NodeRole` | `Full` | 节点角色 |
| `chain_id` | `ChainId` | `DEFAULT_CHAIN_ID` (0x706F_6B31) | 网络 chain_id |
| `data_dir` | `PathBuf` | — | 数据目录（RocksDB 路径） |
| `rpc_listen` | `String` | `"127.0.0.1:8545"` | RPC 监听地址 |
| `p2p_listen` | `String` | `"127.0.0.1:9000"` | P2P 监听地址 |
| `validator_key` | `Option<ValidatorKey>` | `None` | Validator 密钥（仅 Validator 角色需要） |

#### ValidatorKey 结构

```rust
pub struct ValidatorKey {
    pub secret_key_bytes: [u8; 32],   // secp256k1 私钥（32 字节）
    pub tagged_pubkey: TaggedPubkey,  // 对应的 tagged pubkey
}
```

> **安全约束**：私钥仅在 validator 节点内存中持有，**不持久化到磁盘**。

### 3.3 节点配置 TOML 示例

#### Validator 节点

```toml
# validator.toml
role = "Validator"
chain_id = 1886345265  # 0x706F_6B31
data_dir = "/var/lib/poker_l1/validator"
rpc_listen = "127.0.0.1:8545"
p2p_listen = "0.0.0.0:9000"

[validator_key]
# 私钥通过环境变量或 KMS 注入，不写入配置文件
# secret_key_bytes = "..."  # 禁止明文存储
```

#### Full 节点

```toml
# full.toml
role = "Full"
chain_id = 1886345265
data_dir = "/var/lib/poker_l1/full"
rpc_listen = "0.0.0.0:8545"
p2p_listen = "0.0.0.0:9000"
```

#### Archive 节点

```toml
# archive.toml
role = "Archive"
chain_id = 1886345265
data_dir = "/var/lib/poker_l1/archive"  # 须大容量磁盘
rpc_listen = "0.0.0.0:8545"
p2p_listen = "0.0.0.0:9000"
```

#### Light 节点

```toml
# light.toml
role = "Light"
chain_id = 1886345265
data_dir = "/var/lib/poker_l1/light"
rpc_listen = "127.0.0.1:8545"
p2p_listen = "0.0.0.0:9000"
```

---

## 4. 部署步骤

### 4.1 环境准备

#### 4.1.1 系统依赖

```bash
# macOS
brew install rocksdb cmake

# Ubuntu/Debian
apt-get update && apt-get install -y \
    librocksdb-dev \
    cmake \
    build-essential \
    pkg-config
```

#### 4.1.2 Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
rustup component add clippy rustfmt
```

#### 4.1.3 编译 poker_l1

```bash
cd /Users/mac/projects/zchain
cargo build --release -p poker_l1
# 二进制产物：target/release/poker_l1_node（或对应 binary）
```

### 4.2 genesis 文件生成

#### 4.2.1 生成 validator 密钥对

使用 CLI keygen 工具生成 secp256k1 tagged pubkey（源码：`node::keygen_secp256k1`）：

```bash
poker_l1_cli keygen --scheme secp256k1
# 输出：
# scheme: secp256k1
# secret_key_bytes: <32 bytes hex>
# tagged_pubkey: tag=0x01 raw=<33 bytes compressed>
# address: <20 bytes>
```

> **VRF key 生成**：validator 还须生成 ECVRF-secp256k1 密钥对（`vrf_pubkey` 33 字节），具体工具由 IMPL-SEC-2 专项提供。

#### 4.2.2 构造 genesis 文件

参照 [2.5.1 JSON 示例](#251-json-示例) 构造 `genesis.json`，须满足：
- validator 集大小 `|V| >= 5`（SEC-C2）
- 每个 validator 含 `pubkey` + `vrf_pubkey` + `stake`
- `chain_id` 与目标网络一致
- `governance_params` 与 `time_consensus` 取默认值或按需调整（须在边界内）

### 4.3 节点启动

#### 4.3.1 启动 Validator 节点

```bash
poker_l1_node \
    --config validator.toml \
    --genesis genesis.json \
    --validator-secret-key-from-env POKER_L1_VALIDATOR_SK
# POKER_L1_VALIDATOR_SK 环境变量传入 32 字节 secp256k1 私钥 hex
```

#### 4.3.2 启动 Full 节点

```bash
poker_l1_node \
    --config full.toml \
    --genesis genesis.json
```

#### 4.3.3 启动 Archive 节点

```bash
poker_l1_node \
    --config archive.toml \
    --genesis genesis.json
# 须保证磁盘容量 >= archive_retention_blocks * 平均 block 大小
```

#### 4.3.4 启动 Light 节点

```bash
poker_l1_node \
    --config light.toml \
    --genesis genesis.json
```

### 4.4 验证节点加入流程

新 validator 加入网络须经历以下流程（源码：`consensus/validator_set.rs`）：

1. **生成密钥**：secp256k1 signing key + ECVRF-secp256k1 key
2. **提交加入提案**：通过治理 `ValidatorSetUpdate` 提案（需 90% quorum，SubTask 33.5）
3. **提案通过**：在 `effective_epoch` 边界生效，validator 以 `Bonding` 状态加入
4. **Bonding 期**：经历 `bonding_period_blocks=1000` block 锁定期
   - 期间可同步链状态，但 `can_participate_consensus() = false`
   - 期间可被 slashing（`can_be_slashed() = true`）
5. **转为 Active**：到达 `bonding_until_height` 后，`process_bonding_expiry` 将状态转为 `Active`
6. **注册 VRF key**：Active 后须提交 epoch VRF proof 参与 epoch_randomness 生成

```
提案通过 ──> Bonding (1000 block) ──> Active ──> 参与 DAG 共识 + VRF
```

### 4.5 验证节点退出流程

1. **发起退出**：`start_unbonding(pubkey, unbonding_until_height)`，状态转为 `Unbonding`
2. **Unbonding 期**：经历 `unbonding_period_blocks=2000` block（= 2 × epoch）
   - 期间不参与共识，但可被 slashing（R5-H7）
3. **销毁 VRF key**：须提交 `vrf_key_destroy_proof`，`vrf_key_destroyed = true`（SEC2-M10）
4. **完成退出**：`finalize_unbonding`，状态转为 `Retired`，`vrf_retired = true`

> **SEC-M2 约束**：单次 validator 集缩减比例 `<= 20%`（`MAX_SINGLE_REDUCTION_RATIO=20`）。

---

## 5. 时间共识参数

### 5.1 TimeConsensusConfig 详解

源码：`poker_l1/src/block/time_consensus.rs`，`TimeConsensusConfig` 集中所有时间共识可治理参数。注意：该 struct 的默认值与 `GovernanceParams` 中的对应常量可能存在差异（见下表注释），运行时以 `GovernanceParams` 为权威。

| 字段 | TimeConsensusConfig 默认 | GovernanceParams 默认 | 说明 |
| --- | --- | --- | --- |
| `max_interval_ms` | `30_000` | `2000` (`DEFAULT_MAX_INTERVAL_MS`) | DAG commit 间隔软参考（30 秒） |
| `max_clock_drift_ms` | `5_000` | `500` (`DEFAULT_MAX_CLOCK_DRIFT_MS`) | 链下参与者时钟漂移容忍（5 秒） |
| `turn_timeout_blocks` | `30` | `30` | GameTurn 玩家行动超时 |
| `hand_max_duration_blocks` | `300` | `120` (`DEFAULT_HAND_MAX_DURATION_BLOCKS`) | 单手牌最大持续 block 数 |
| `dispute_window_blocks` | `200` | `500` (`DEFAULT_DISPUTE_WINDOW_BLOCKS`) | 争议窗口 |
| `da_window_blocks` | `500` | `500` | 数据可用性窗口 |
| `checkpoint_interval_blocks` | `100` | `5` (`DEFAULT_CHECKPOINT_INTERVAL_BLOCKS`) | checkpoint 提交间隔 |
| `game_validator_timeout_blocks` | `50` | `15` (`DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS`) | assigned_validator 超时阈值 |
| `epoch_length_blocks` | `1000` | `1000` | epoch 长度 |
| `epoch_transition_window_blocks` | `10` | `10` | epoch 过渡窗口 |

> **运行时权威**：`GovernanceParams` 为治理可调整的权威值；`TimeConsensusConfig::new()` 为 struct 内置默认，部署时须以 genesis 中 `governance_params` 为准同步初始化。

### 5.2 SEC-M5 安全约束（关键）

**所有超时判定以 `block.height` 为权威，禁止以 `timestamp_ms` 触发安全决策。**

源码 `time_consensus.rs` 顶部明确：
- `block.height = prev.height + 1`（严格单调递增，**权威**）
- `timestamp_ms >= prev.timestamp_ms`（单调不减，**软引用**）
- `timestamp_ms <= prev.timestamp_ms + max_interval_ms`（最大间隔，**软引用**）

**禁止行为**：
1. 以 `timestamp_ms` 触发 `force_advance` / `force_checkpoint` 等逃生 tx 的硬截止判定
2. 以 `timestamp_ms` 作为 slashing / 超时判定的依据
3. 任何以 `timestamp_ms` 为依据的安全决策均视为实现错误

**`max_clock_drift_ms`**（R7-M3）：仅供链下参与者作软参考时钟漂移容忍度，**不用于 validator 共识硬校验**。

### 5.3 超时判定函数

| 函数 | 判定逻辑 | 触发动作 |
| --- | --- | --- |
| `is_turn_timeout` | `current > last_action + turn_timeout_blocks` | 任意参与者触发 fallback |
| `is_validator_timeout` | `current > last_vertex + game_validator_timeout_blocks` | 触发 `assigned_validator_failure_proof` |
| `is_hand_timeout` | `current > hand_start + hand_max_duration_blocks` | 触发 `force_advance` / `request_revert` |
| `is_da_window_passed` | `current > block_height + da_window_blocks` | vertex 视为 DA 已确认 |
| `is_dispute_window_passed` | `current > block_height + dispute_window_blocks` | 链下执行结果视为 final |
| `should_submit_checkpoint` | `current >= last_checkpoint + checkpoint_interval_blocks` | 应提交新 checkpoint_anchor |
| `is_epoch_boundary` | `current % epoch_length_blocks == 0` | 触发 validator 重分配 |
| `is_submit_phase_timed_out` | `current > phase_started_height + <phase>_timeout_blocks` | kick pending_submitters 中玩家 + 退款（spec Phase 4） |

### 5.4 多玩家提交阶段超时配置（spec Phase 4 Task 7）

> **来源**：`extend-game-multiplayer-phases` spec（FROZEN）— Phase 4 引入多玩家并行提交阶段（Shuffle / RevealToken / Reconstruct / LeaveProof），每个阶段独立配置超时阈值。

`TimeConsensusConfig` 在原有 10 个字段基础上新增 3 个多玩家阶段超时字段（源码：`poker_l1/src/block/time_consensus.rs`）：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `shuffle_timeout_blocks` | `100` | Shuffle 阶段超时阈值（block 数） |
| `reveal_token_timeout_blocks` | `50` | RevealToken 阶段超时阈值（block 数，最短，防玩家故意拖延揭牌） |
| `reconstruct_timeout_blocks` | `100` | Reconstruct 阶段超时阈值（block 数） |

> **LeaveProof 不超时**：`SubmitPhaseKind::LeaveProof` 为被动行为（玩家可随时提交离场证明），无超时阈值，`is_submit_phase_timed_out()` 对此阶段始终返回 `None`。

#### 5.4.1 超时判定规则

`is_submit_phase_timed_out(game, current_height, config) -> Option<SubmitPhaseKind>`：

| 当前 `game.phase` | 使用阈值 | 判定逻辑 |
| --- | --- | --- |
| `Betting { .. }` | 不适用 | 返回 `None`（下注阶段走 `is_turn_timeout`） |
| `MultiPlayerSubmit { kind: Shuffle }` | `shuffle_timeout_blocks` (100) | `current > phase_started_height + 100` → `Some(Shuffle)` |
| `MultiPlayerSubmit { kind: RevealToken }` | `reveal_token_timeout_blocks` (50) | `current > phase_started_height + 50` → `Some(RevealToken)` |
| `MultiPlayerSubmit { kind: Reconstruct }` | `reconstruct_timeout_blocks` (100) | `current > phase_started_height + 100` → `Some(Reconstruct)` |
| `MultiPlayerSubmit { kind: LeaveProof }` | 不适用 | 返回 `None`（LeaveProof 永不超时） |

**边界判定**（严格大于 `>`）：
- `current == phase_started_height + timeout_blocks` → **未超时**（边界值不触发）
- `current == phase_started_height + timeout_blocks + 1` → **已超时**
- overflow（`checked_add` 失败）→ 返回 `None`（保守不超时，避免误 kick）

#### 5.4.2 超时惩罚执行（handle_submit_phase_timeout）

超时触发后由 `handle_submit_phase_timeout()`（源码：`poker_l1/src/consensus/phase_timeout.rs`）执行：

1. 遍历 `game.pending_submitters`，对每个未提交玩家执行 kick
2. 从 `active_participants` / `pending_submitters` / `completed_submitters` 同时移除该玩家
3. 退款 `total_bet`（由调用方通过 `refund_calc: F` 闭包计算）
4. 若剩余 `active_participants < 2` → 触发 `end_without_showdown` 直接结算

返回 `Vec<KickResult>`，每项含 `{ player: Address, refund_amount: u64 }`。

#### 5.4.3 genesis 配置示例（多玩家阶段超时）

在 genesis `time_consensus` 段新增三个字段：

```json
{
  "time_consensus": {
    "max_interval_ms": 30000,
    "max_clock_drift_ms": 5000,
    "turn_timeout_blocks": 30,
    "hand_max_duration_blocks": 300,
    "dispute_window_blocks": 200,
    "da_window_blocks": 500,
    "checkpoint_interval_blocks": 100,
    "game_validator_timeout_blocks": 50,
    "epoch_length_blocks": 1000,
    "epoch_transition_window_blocks": 10,
    "shuffle_timeout_blocks": 100,
    "reveal_token_timeout_blocks": 50,
    "reconstruct_timeout_blocks": 100
  }
}
```

> **默认值兼容**：未显式配置时，`TimeConsensusConfig::default()` / `TimeConsensusConfig::new()` 自动填入上述默认值，既有 genesis 文件无需修改即可向后兼容。

#### 5.4.4 部署建议

| 场景 | 建议配置 | 理由 |
| --- | --- | --- |
| 主网（mainnet） | 保持默认值 | 100 block Shuffle 超时足够覆盖网络分区恢复；50 block RevealToken 防玩家故意拖延 |
| 测试网（testnet） | 可降至默认值的 50%（Shuffle=50 / RevealToken=25 / Reconstruct=50） | 加速测试用例流转 |
| 高延迟网络 | 可提升至默认值的 200%（Shuffle=200 / RevealToken=100 / Reconstruct=200） | 防诚实玩家因网络延迟被误 kick |

> **SEC-M5 约束**：所有超时判定以 `block.height` 为权威，禁止以 `timestamp_ms` 触发。`shuffle_timeout_blocks` 等参数均以 block 高度计量，不受 proposer 任意选 `timestamp_ms` 影响。

---

## 6. 网络约束

源码：`poker_l1/src/network/mod.rs` 与 `poker_l1/src/consensus/mod.rs`。

### 6.1 大小上限

| 约束 | 常量 | 值 | 源码位置 |
| --- | --- | --- | --- |
| Block 序列化最大 | `MAX_BLOCK_SIZE` | 4MB (4 * 1024 * 1024) | `network/mod.rs` |
| tx 序列化最大 | `MAX_TX_SIZE` | 128KB (128 * 1024) | `network/mod.rs` |
| vertex 序列化最大 | `MAX_VERTEX_SIZE` | 256KB (256 * 1024) | `consensus/mod.rs` |

校验函数：
- `validate_tx_size(tx)`：超出返回 `TxTooLarge`
- `validate_block_size(block)`：超出返回 `BlockTooLarge`
- `validate_vertex_size(vertex)`：超出返回 `VertexTooLarge`

### 6.2 无 mempool 设计

poker_l1 **不维护 mempool**（O1 移除），tx 直接装入下一个 vertex：

| 配置 | 值 | 说明 |
| --- | --- | --- |
| `MEMPOOL_BUFFER_WINDOW_MS` | 100ms | tx 缓冲窗口，超时则丢弃 |

`TxBuf` 实现 FIFO 缓冲：
- `push(tx)`：加入缓冲，记录时间戳
- `drain_for_vertex()`：取出所有 tx 装入 vertex，丢弃超时 tx（返回超时 tx 哈希列表）
- `should_drain()`：非破坏性检查最早 tx 是否超时

### 6.3 Compact Block Relay

为降低网络带宽，validator 先广播 compact vertex（仅含 tx short IDs），接收方从本地 tx 缓存匹配。

| 配置 | 值 | 说明 |
| --- | --- | --- |
| `SHORT_ID_LEN` | 8 字节（64 bit） | short ID 长度（SEC2-L3） |
| `SHORT_ID_MAP_LIMIT` | 100_000 | short ID → tx_hash 映射表大小上限 |

**short ID 计算**：`short_id = blake2b_256(0x53 || tx_hash)[0..8]`

**冲突处理**（SEC2-L3）：
- 多个 tx 映射到同一 short ID → 标记冲突，从映射表移除，转入 `conflicts` 集合
- 冲突的 short ID 不可用于 compact block relay，须请求完整 vertex fallback
- 冲突概率 < 2^-32（8 字节空间，birthday bound ≈ 2^32 tx 才有 50% 冲突）

### 6.4 BroadcastConfig（多副本广播）

源码：`network/mod.rs`，`BroadcastConfig` 用于 Public tx + force_* tx 多副本广播（SubTask 30.8）：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `replica_count` | 3 | 目标副本数量 |
| `min_accept` | 1 | 至少一个副本接受即视为成功 |

`multi_replica_broadcast` 函数：
- 接受副本数 `< min_accept` → 返回 `MultiReplicaBroadcastFailed`
- checkpoint_anchor 多副本广播作为审查检测证据（副本 validator 仅见证不装入 vertex）

### 6.5 gossipsub 主题

| GossipTopic | 用途 |
| --- | --- |
| `DagVertex` | 完整 DAG vertex 传播 |
| `Transaction` | 完整 tx 传播 |
| `CompactVertex` | Compact vertex 传播（SubTask 30.5） |
| `CheckpointAnchor` | checkpoint_anchor 多副本广播（SubTask 30.8） |

---

## 7. 安全注意事项

### 7.1 chain_id 重放保护（SEC-L4）

- 所有 tx 含 `chain_id` 字段，签名对象绑定 `chain_id`，跨链重放无效
- DAG vertex 的 `signing_hash` 含 `chain_id`（SEC-C1）：`blake2b_256(chain_id || epoch || round || author_pubkey || vertex_hash || parent_hashes)`
- VRF input 绑定 `chain_id`（SEC2-C2）：`VRF input = hash(chain_id || epoch || prev_epoch_randomness)`
- 部署时须确保 mainnet `chain_id` 与 testnet `0x706F_6B31` 不同

### 7.2 VRF key 销毁（SEC2-M10）

validator 退出时**必须销毁 VRF 私钥**并提交 `vrf_key_destroy_proof`：

- `vrf_key_destroyed` 字段标记是否已销毁
- `finalize_unbonding` 校验 `vrf_key_destroyed == true`，否则拒绝完成退出
- 退出后 `vrf_retired = true`，该 VRF pubkey 不再可用
- 未销毁 VRF key 退出 → unbonding 期延长

### 7.3 validator 最小规模（SEC-C2）

- **OffChain 模式强制约束**：`|V| >= 5`（`MIN_VALIDATOR_SET_SIZE=5`）
- `validate_size_for_offchain()` 校验：validator 集大小 `< 5` → 返回 `ValidatorSetTooSmallForOffChain`
- genesis validator 集**必须** >= 5 个
- validator 集更新提案须保证新集合 >= 5（`create_validator_set_update_proposal` 校验）

### 7.4 单次缩减比例（SEC-M2）

- 单次 validator 集缩减比例 `<= 20%`（`MAX_SINGLE_REDUCTION_RATIO=20`）
- `validate_reduction_ratio(removed_count)` 校验：`removed_count * 100 / prev_size > 20` → 拒绝
- 示例：10 个 validator 单次最多移除 2 个（20%）
- 防止恶意提案一次性踢出大量 validator 导致共识瘫痪

### 7.5 validator 密钥安全

- **私钥不持久化**：`ValidatorKey.secret_key_bytes` 仅在内存中持有，不写入磁盘
- **私钥注入**：通过环境变量或 KMS（如 AWS KMS / HSM）注入
- **密钥轮换**：通过 `KeyRotation` 提案（90% quorum），timelock = `key_rotation_delay_blocks=1000`，期间旧密钥仍可用于 slashing 证据（SEC2-H4）
- **全零私钥拒绝**：`ValidatorKey::from_secret_bytes([0u8; 32])` 返回错误（不在曲线阶范围内）

### 7.6 timestamp_ms 软引用约束（SEC-M5）

- block 提议者可在 `[prev.timestamp_ms, prev.timestamp_ms + max_interval_ms]` 合法范围内任意选 `timestamp_ms`
- **安全约束**：
  1. 链下参与者触发 `force_advance` / `force_checkpoint` 等逃生 tx 的硬截止判定**一律以 `block.height` 为权威**，禁止以 `timestamp_ms` 作为触发条件
  2. `timestamp_ms` 仅可用于"显示用"与"非安全相关的软参考"
  3. 任何以 `timestamp_ms` 为依据的安全决策均视为实现错误
- `max_clock_drift_ms` 仅供链下参与者作软参考，不参与 validator 共识硬校验（R7-M3）

### 7.7 archive 节点最小数量

- 网络须维持 `DEFAULT_ARCHIVE_NODE_MIN_COUNT=3` 个 archive 节点
- archive 节点提供 `request_historical_data` RPC，是链上历史回溯的唯一来源
- 部署时建议 >= 3 个 archive 节点分布在不同地理区域与运营商

### 7.8 verifier_status per-chain_id（SEC-M4）

- `verifier_status` 按 `chain_id` 命名空间隔离（`BTreeMap<ChainId, VerifierStatus>`）
- mainnet `chain_id` 初始为 `Stub`，拒绝 OffChain checkout
- 升级为 `Production` 须通过 90% quorum 治理提案 + timelock
- testnet/devnet 不受限制（`is_offchain_checkout_allowed` 始终返回 `true`）

---

## 附录：参数源码索引速查

| 参数组 | 源文件 | 关键常量 / 结构 |
| --- | --- | --- |
| chain_id | `poker_l1/src/lib.rs` | `DEFAULT_CHAIN_ID = 0x706F_6B31` |
| NodeRole / NodeConfig | `poker_l1/src/node/mod.rs` | `NodeRole::{Validator, Full, Archive, Light}`，`NodeConfig` |
| ValidatorKey | `poker_l1/src/node/mod.rs` | `ValidatorKey`（secp256k1，32B 私钥 + tagged pubkey） |
| TimeConsensusConfig | `poker_l1/src/block/time_consensus.rs` | `TimeConsensusConfig`（13 个字段，含 `shuffle_timeout_blocks` / `reveal_token_timeout_blocks` / `reconstruct_timeout_blocks`） |
| 多玩家阶段超时惩罚 | `poker_l1/src/consensus/phase_timeout.rs` | `handle_submit_phase_timeout()` / `KickResult`（spec Phase 4 Task 8） |
| ValidatorEntry / ValidatorStatus | `poker_l1/src/consensus/validator_set.rs` | `ValidatorEntry`，`ValidatorStatus`，`MIN_VALIDATOR_SET_SIZE=5` |
| VRF 常量 | `poker_l1/src/consensus/validator_set.rs` | `VRF_PUBKEY_SIZE=33`，`VRF_PROOF_SIZE=97`，`VRF_OUTPUT_SIZE=32` |
| MAX_SINGLE_REDUCTION_RATIO | `poker_l1/src/consensus/validator_set.rs` | `MAX_SINGLE_REDUCTION_RATIO=20` |
| MAX_VERTEX_SIZE | `poker_l1/src/consensus/mod.rs` | `MAX_VERTEX_SIZE=256*1024` |
| DEFAULT_* 治理常量 | `poker_l1/src/governance/mod.rs` | 41 个 `DEFAULT_*` 常量，`GovernanceParams` |
| 网络大小上限 | `poker_l1/src/network/mod.rs` | `MAX_BLOCK_SIZE=4MB`，`MAX_TX_SIZE=128KB` |
| Compact Block Relay | `poker_l1/src/network/mod.rs` | `SHORT_ID_LEN=8`，`MEMPOOL_BUFFER_WINDOW_MS=100` |
| BroadcastConfig | `poker_l1/src/network/mod.rs` | `replica_count=3`，`min_accept=1` |
