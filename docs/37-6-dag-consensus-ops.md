# poker_l1 DAG 共识运维文档（SubTask 37.6）

> 覆盖范围：DAG vertex 同步、Bullshark commit 流程、validator 加入/退出、slashing 运维、故障排查、监控指标、性能基准
>
> 源文件：
> - `poker_l1/src/consensus/mod.rs` — `DagVertex` / `DagCommitCertificate` / 签名域常量 / `MAX_VERTEX_SIZE`
> - `poker_l1/src/consensus/bullshark.rs` — `Dag` / `detect_commit_leader` / `bullshark_linear_order` / `project_block_from_commit` / `assemble_commit_certificate`
> - `poker_l1/src/consensus/vertex_production.rs` — `VertexBuilder` / `required_parent_count` / `required_witness_count` / S9 + R4-M4 排序
> - `poker_l1/src/consensus/validator_set.rs` — `ValidatorEntry` / `ValidatorStatus` / VRF / bonding/unbonding
> - `poker_l1/src/consensus/slashing.rs` — `SlashingConfig` / `SlashingReason` / `InvestigationState`
> - `poker_l1/src/consensus/game_assignment.rs` — `GameAssignmentConfig` / epoch 过渡 / `client_route_validator`
> - `poker_l1/src/consensus/routing.rs` — `GameStatus` / `TurnRule` / 路由校验
> - `poker_l1/src/vm/contracts/force_checkpoint.rs` — `ForceCheckpointTx` / 多副本见证 / 非包含证明
> - `poker_l1/src/network/mod.rs` — `GossipTopic` / Compact Block Relay / `TxBuf` / 多副本广播
> - `poker_l1/src/storage/pruning.rs` — `PruningConfig` / `PrunedVertex` / `NodeRole`
> - `poker_l1/src/node/mod.rs` — `compute_assigned_validator_local`

---

## 1. 概述

poker_l1 采用 **Narwhal-Bullshark** DAG 共识：Narwhal 负责数据可用性（DAG vertex 传播），Bullshark 负责排序（commit certificate + linear order）。该架构将"数据传播"与"共识排序"解耦，使 validator 可并行出 vertex，吞吐由网络带宽决定，最终性由 2/3 quorum 决定。

### 1.1 架构特点

| 特点 | 说明 | 实现位置 |
|------|------|----------|
| 无 mempool | tx 直接装入下一个 vertex，100ms 缓冲窗口 | `network/mod.rs` `TxBuf` |
| Compact Block Relay | vertex 先以 short ID 广播，缺失 tx 再请求 | `network/mod.rs` `CompactVertex` |
| 多 validator 并行出 vertex | 每个 validator 每轮独立产 vertex，引用 ≥2/3 上一轮 vertex | `vertex_production.rs` |
| 双通道分类 | GameTurn + CheckpointAnchor 走 assigned_validator；Public + ForceSync 任意 validator | `routing.rs` |
| GameTurn 免 gas | 游戏操作 tx 免 gas，仅校验轮转约束 + 买入锁仓 | `vertex_production.rs` `validate_gameturn_gas_free` |

### 1.2 DAG 结构示意

```
              Round R+2        Round R+1        Round R
              ┌────────┐       ┌────────┐       ┌────────┐
              │ V(D,R2)│ ────► │ V(C,R1)│ ────► │ V(A,R )│
              └────────┘       └────────┘       └────────┘
                  │                │  │              │
                  ▼                ▼  ▼              ▼
              ┌────────┐       ┌────────┐       ┌────────┐
              │ V(E,R2)│ ────► │ V(D,R1)│ ────► │ V(B,R )│
              └────────┘       └────────┘       └────────┘
                                   │
                                   ▼
                              [leader V(C,R1)]
                              被 ≥2/3 R+2 引用
                              → 形成 commit
```

每轮每个 validator 出一个 vertex，引用上一轮 ≥2/3 validator 的 vertex hash。当某 vertex（leader）被下一轮 ≥2/3 validator 间接引用时，形成 commit certificate，触发 Bullshark 线性排序与 block 投影。

---

## 2. DAG Vertex 结构与传播

### 2.1 DagVertex 结构

定义于 `consensus/mod.rs`：

```rust
pub struct DagVertex {
    pub epoch: Epoch,                  // 当前 epoch（SEC-C1：绑定 epoch 防 equivocation 证据歧义）
    pub round: Round,                  // DAG round（全局递增，跨 epoch 不重置）
    pub author_pubkey: TaggedPubkey,   // 作者 validator 的 tagged pubkey
    pub tx_list: Vec<Transaction>,     // 交易列表（tx 批量）
    pub parent_hashes: Vec<Hash>,      // 引用的上一轮 vertex hash（≥2/3 validator 的 vertex hash）
    pub author_sig: Vec<u8>,           // 作者 validator 的 secp256k1 签名
}
```

### 2.2 签名域分隔常量

| 常量 | 值 | 用途 | 定义位置 |
|------|----|------|----------|
| `VERTEX_SIG_DOMAIN` | `0x56` ('V') | vertex 内容哈希前缀 | `consensus/mod.rs` |
| `COMMIT_CERT_SIG_DOMAIN` | `0x43` ('C') | commit certificate 签名哈希前缀 | `consensus/mod.rs` |
| `SHORT_ID_DOMAIN` | `0x53` ('S') | Compact Block Relay short ID 前缀 | `network/mod.rs` |
| `VRF_INPUT_DOMAIN` | `0x56` ('V') | VRF input 哈希前缀 | `consensus/validator_set.rs` |
| `VRF_OUTPUT_DOMAIN` | `0x52` ('R') | VRF output 哈希前缀 | `consensus/validator_set.rs` |

### 2.3 关键大小上限

| 常量 | 值 | 说明 |
|------|----|------|
| `MAX_VERTEX_SIZE` | 256 KB | vertex 序列化后上限，超出分多个 vertex |
| `MAX_TX_SIZE` | 128 KB | 单个 tx 序列化后上限 |
| `MAX_BLOCK_SIZE` | 4 MB | block 序列化后上限 |

vertex_hash 计算（不含 `author_sig`，签名不参与自身内容哈希）：

```
vertex_hash = blake2b_256(0x56 || epoch || round || author_pubkey || tx_hashes || parent_hashes)
```

signing_hash（SEC-C1：绑定 `chain_id` 防跨链重放）：

```
signing_hash = blake2b_256(chain_id || epoch || round || author_pubkey || vertex_hash || parent_hashes)
```

### 2.4 Vertex 传播：GossipTopic

`network/mod.rs` 定义四个 gossip topic：

| GossipTopic | 用途 | 消息类型 |
|-------------|------|----------|
| `DagVertex` | 完整 vertex 传播 | `NetworkMessage::DagVertex` |
| `Transaction` | 完整 tx 传播 | `NetworkMessage::Transaction` |
| `CompactVertex` | Compact Block Relay（先广播 short ID） | `NetworkMessage::CompactVertex` |
| `CheckpointAnchor` | checkpoint_anchor 多副本广播（审查检测证据） | `NetworkMessage::Transaction` |

### 2.5 Compact Block Relay

为降低带宽，validator 打包 vertex 后先广播 `CompactVertex`（vertex header + tx short IDs），接收方从本地已收 tx 集合匹配，仅请求缺失的 tx。

| 常量 | 值 | 说明 |
|------|----|------|
| `SHORT_ID_LEN` | 8 字节（64 bit） | short ID 长度，冲突概率 < 2^-32 |
| `SHORT_ID_MAP_LIMIT` | 100,000 | short ID → tx_hash 映射表上限（防内存膨胀） |
| `SHORT_ID_DOMAIN` | `0x53` ('S') | short ID 域分隔前缀 |

```
short_id = blake2b_256(0x53 || tx_hash)[0..8]
```

**冲突处理（SEC2-L3）**：当多个 tx 映射到同一 short ID 时，将该 short ID 移入 `conflicts` 集合，后续匹配返回 `ShortIdCollision`，调用方须请求完整 vertex fallback。冲突的 short ID 永久不可用于 compact block relay。

### 2.6 无 mempool 设计

poker_l1 移除传统 mempool，validator 收到 tx 后直接装入下一个 vertex，内存中仅保留 `TxBuf` 短暂缓冲。

| 常量 | 值 | 说明 |
|------|----|------|
| `MEMPOOL_BUFFER_WINDOW_MS` | 100 ms | tx 在缓冲中超过此窗口 → 丢弃并记录超时哈希 |

`TxBuf` 工作流：

1. `push(tx)`：加入 FIFO 队列，记录 arrival 时间
2. `should_drain()`：检查最早 tx 是否超过 100ms 窗口
3. `drain_for_vertex()`：取出所有 tx，超时的 tx 记录哈希后丢弃

### 2.7 多副本广播配置

`BroadcastConfig` 用于 Public tx + force_* tx 的多副本广播：

```rust
pub struct BroadcastConfig {
    pub replica_count: usize,  // 目标副本数量（默认 3）
    pub min_accept: usize,     // 至少一个副本接受即视为成功（默认 1）
}
```

checkpoint_anchor 多副本广播作为审查检测证据：副本 validator 仅见证不装入 vertex，签发 `MultiReplicaReceipt` 作为 `force_checkpoint` 的 evidence。

---

## 3. Bullshark 共识流程

### 3.1 DagCommitCertificate 结构

定义于 `consensus/mod.rs`：

```rust
pub struct DagCommitCertificate {
    pub epoch: Epoch,                       // 当前 epoch（SEC2-C1）
    pub commit_round: CommitRound,          // Bullshark commit 轮次
    pub prev_commit_hash: Hash,             // 前一个 commit 的 hash（形成 hash chain 防 long-range attack）
    pub vertex_hash_list: Vec<Hash>,        // commit 涵盖的 vertex hash 列表
    pub round_attendance_bitmap: Vec<u8>,   // 本轮出勤 bitmap
    pub state_root: Hash,                   // 本 block 的 state_root
    pub public_tx_root: Hash,               // Public 通道 tx Merkle root（NEW-M14）
    pub gameturn_tx_root: Hash,             // GameTurn + CheckpointAnchor 通道 tx Merkle root
    pub signature_list: Vec<Vec<u8>>,       // validator secp256k1 签名列表
    pub signer_bitmap: Vec<u8>,             // 签名者 bitmap
}
```

signing_hash（SEC2-C1）：

```
signing_hash = blake2b_256(0x43 || chain_id || epoch || commit_round || prev_commit_hash
                          || vertex_hash_list || round_attendance_bitmap
                          || state_root || public_tx_root || gameturn_tx_root)
```

绑定 `prev_commit_hash` 形成 hash chain 防 long-range attack；绑定 `state_root` / `public_tx_root` / `gameturn_tx_root` 防 commit certificate 被重用到不同 block 内容。

### 3.2 Commit 流程

```
┌─────────────────────────────────────────────────────────────┐
│  Round R:  leader vertex V(L,R) 产出                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Round R+1: ≥2/3 validator 引用 V(L,R) 作为 parent            │
│  → detect_commit_leader() 返回 CommitLeader                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  bullshark_linear_order(): 收集 leader 祖先 → 按              │
│  (round, author_pubkey_bytes, vertex_hash) 线性排序            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  assemble_commit_certificate(): 收集 ≥2/3 签名 →              │
│  构造 signer_bitmap + signature_list                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  project_block_from_commit():                                 │
│  1. 线性排序 vertex                                            │
│  2. 聚合 tx_list → R4-M4 排序（GameTurn 优先，ForceSync 后置） │
│  3. 拆分 public_txs / gameturn_txs                            │
│  4. 计算 public_tx_root / gameturn_tx_root                    │
│  5. 构造 BlockHeader（含 dag_commit_certificate）              │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 核心函数

| 函数 | 位置 | 作用 |
|------|------|------|
| `detect_commit_leader` | `bullshark.rs` | 检测某轮 vertex 是否获得 ≥2/3 validator 引用 |
| `bullshark_linear_order` | `bullshark.rs` | 对 commit 内 vertex 按 (round, author) 线性排序 |
| `project_block_from_commit` | `bullshark.rs` | 从 commit 投影产出 block（tx 聚合 + R4-M4 排序） |
| `assemble_commit_certificate` | `bullshark.rs` | 组装 commit certificate（构造 signer_bitmap） |
| `validate_commit_certificate_quorum` | `bullshark.rs` | 校验签名数 ≥ 2/3 quorum |
| `validate_commit_certificate_fields` | `bullshark.rs` | 校验 epoch / prev_commit_hash / roots 一致性 |
| `detect_commit_cert_equivocation` | `bullshark.rs` | 检测同 (epoch, commit_round) 双签 commit certificate |

### 3.4 Quorum 阈值

定义于 `vertex_production.rs`：

```rust
pub const fn required_parent_count(validator_count: usize) -> usize {
    (validator_count * 2).div_ceil(3)  // ceil(n * 2 / 3)
}

pub const fn required_quorum(validator_count: usize) -> usize {
    required_parent_count(validator_count)  // 与 parent 阈值相同
}
```

**示例**：

| validator 数 |V| | required_parent_count | required_quorum |
|---------------|----------------------|-----------------|
| 5 | 4 | 4 |
| 6 | 4 | 4 |
| 7 | 5 | 5 |
| 9 | 6 | 6 |
| 10 | 7 | 7 |
| 20 | 14 | 14 |

`detect_commit_leader` 去重逻辑：同一 validator 多个 vertex 引用 leader 只算一次（按 `author_pubkey.to_bytes()` 去重），防止通过多产 vertex 伪造 quorum。

### 3.5 Block 最终性

commit certificate 含 ≥2/3 validator 的 secp256k1 多签 → block 视为 finalized。轻客户端只需验证 commit certificate 的 2/3 quorum 即可信任 block header，无需下载完整 DAG。

---

## 4. Vertex 生产规则

### 4.1 VertexBuilder

定义于 `vertex_production.rs`：

```rust
pub struct VertexBuilder {
    pub epoch: Epoch,
    pub round: Round,
    pub author_pubkey: TaggedPubkey,
    pub tx_list: Vec<Transaction>,       // 按 arrival 顺序
    pub parent_hashes: Vec<crate::Hash>, // 须 ≥2/3 validator 的上一轮 vertex hash
}
```

`VertexBuilder` 不做签名，仅组装数据。调用方在外层完成签名后填入 `author_sig`：

```rust
let mut builder = VertexBuilder::new(epoch, round, author_pubkey);
builder.push_tx(tx1);
builder.push_tx(tx2);
builder.validate_size()?;            // 校验 ≤ 256KB
builder.validate_parents(n_validators)?;  // 校验 parent_hashes ≥ 2/3
let vertex = builder.with_parents(parents).build(author_sig);
```

### 4.2 Parent 引用规则

`required_parent_count(n) = ceil(n * 2 / 3)`：vertex 须引用 ≥2/3 validator 上一轮的 vertex hash。`validate_parents()` 在 parent 数量不足时返回 `InsufficientParents { actual, required }`。

### 4.3 Checkpoint 多副本见证阈值

`required_witness_count(n) = max(3, floor(n * 2 / 3))`（R4-H6 修正）：

| checkpoint_multi_replica_count | required_witness_count | 说明 |
|--------------------------------|------------------------|------|
| 1 | 3 | 下限保护 |
| 3 | 3 | max(3, 2) = 3 |
| 4 | 3 | max(3, 2) = 3 |
| 5 | 3 | max(3, 3) = 3（默认 3-of-5） |
| 6 | 4 | max(3, 4) = 4 |
| 9 | 6 | max(3, 6) = 6 |

默认 `DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT = 5`，对应 3-of-5 多签（NEW-M3）。

### 4.4 Vertex 内排序（S9）

`sort_vertex_txs_s9()` 按 lane 优先级 stable partition：

1. **GameTurn + CheckpointAnchor**（先执行）
2. **Public**（中间）
3. **ForceSync**（后置）

同通道内保持 arrival 顺序。

### 4.5 Commit 级排序（R4-M4）

`sort_commit_txs_r4m4()` 聚合 commit 内所有 vertex 的 tx 后按 S9 规则排序，等价于跨 vertex 的 GameTurn 全先于 ForceSync：

```rust
pub fn sort_commit_txs_r4m4(commit_vertex_txs: Vec<Vec<Transaction>>) -> Vec<Transaction> {
    let mut aggregated: Vec<Transaction> = Vec::new();
    for vertex_txs in commit_vertex_txs {
        aggregated.extend(vertex_txs);
    }
    sort_vertex_txs_s9(aggregated)
}
```

### 4.6 SEC-H6 跨 commit 抢跑防护

`check_sech6_cross_commit_force_advance()` 校验：force_advance 所在 commit 的前一个 commit 内若有该 Game 的 GameTurn tx，则 `last_action_height` 视为已更新，force_advance 判定为 false 被拒绝。

### 4.7 validate_size

`VertexBuilder::validate_size()` 估算 vertex 序列化后大小，超过 `MAX_VERTEX_SIZE`（256KB）返回 `VertexTooLarge`。生产中应序列化后精确校验，超出分多个 vertex。

---

## 5. Game 分配与路由

### 5.1 链上权威分配

`ValidatorSet::assigned_validator_for_game()` 使用 `hash(game_id || epoch || epoch_randomness) % |V_active|`（绑定 `epoch_randomness`，更强安全性）：

```rust
pub fn assigned_validator_for_game(&self, game_id: &ObjectID) -> PokerL1Result<TaggedPubkey> {
    let active: Vec<&ValidatorEntry> = self.validators.iter()
        .filter(|v| v.can_participate_consensus())
        .collect();
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&game_id.to_bytes());
    h.update(&self.epoch.to_le_bytes());
    h.update(&self.epoch_randomness);
    // 取前 8 字节作为 u64 索引 % active.len()
    // ...
}
```

### 5.2 客户端本地计算

`compute_assigned_validator_local()` 定义于 `node/mod.rs`，使用 `hash(0x41 || game_id || epoch) % |V|`（**不含 `epoch_randomness`**），客户端本地零延迟路由：

```rust
pub fn compute_assigned_validator_local<'a>(
    game_id: &ObjectID,
    epoch: Epoch,
    validator_set: &'a [TaggedPubkey],
) -> Option<&'a TaggedPubkey> {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[0x41]); // 'A' for Assignment
    h.update(&game_id.to_bytes());
    h.update(&epoch.to_le_bytes());
    // 取前 8 字节作为 u64 索引 % validator_set.len()
    // ...
}
```

客户端本地路由仅作为预路由提示，最终由 validator 通过 `validate_client_route_consistency()` 校验权威性。

### 5.3 Epoch 切换与重分配

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `epoch_length_blocks` | 1000 | epoch 长度（block 数） |
| `epoch_transition_window_blocks` | 10 | epoch 边界前过渡窗口 |

`compute_current_epoch(height, epoch_length) = height / epoch_length`（R4-H2：链上权威判定）。

`is_in_epoch_transition_window()` 判定当前 height 是否在 epoch 边界前 `epoch_transition_window_blocks` 个 block 内。

### 5.4 GameAssignmentConfig

```rust
pub struct GameAssignmentConfig {
    pub game_validator_timeout_blocks: BlockHeight,    // 默认 2（R4-L8 修正）
    pub epoch_length_blocks: BlockHeight,              // 默认 1000
    pub epoch_transition_window_blocks: BlockHeight,   // 默认 10
    pub forfeit_bond_percentage: u32,                  // 默认 50（SEC2-H3：最低 50%）
}
```

- **R4-L8**：`game_validator_timeout_blocks` 由 3 降至 2，原值与 `turn_timeout_blocks` 同值致竞争条件，降为 2 给 fallback tx 留处理窗口
- **SEC2-H3**：操作方未提交过渡锚点 → forfeit 保证金按比例扣除（最低 50%）
- **NEW-M10**：epoch 边界前过渡窗口内须提交 `checkpoint_anchor`，未提交 → 任意参与者触发 `force_advance` 或 `request_revert`

### 5.5 活跃 Game 上限

`DEFAULT_MAX_ACTIVE_GAMES_PER_PLAYER = 10`（S8 修复）。`validate_active_games_limit()` 在 join 时校验，超出返回 `TooManyActiveGames`。

---

## 6. Slashing 机制

### 6.1 SlashingConfig

定义于 `slashing.rs`：

```rust
pub struct SlashingConfig {
    pub slash_percentage: u32,                // equivocation 默认 100%（NEW-M15）
    pub downtime_threshold_blocks: BlockHeight, // 默认 100
    pub downtime_slash_percentage: u32,        // 默认 10%（NEW-L2）
    pub defense_window_blocks: BlockHeight,    // 默认 50（NEW-H1）
    pub epoch_length_blocks: BlockHeight,      // 默认 1000
}
```

### 6.2 自动 slashing 阈值

```rust
pub const fn auto_slash_threshold(&self) -> BlockHeight {
    self.downtime_threshold_blocks + 2 * self.epoch_length_blocks
}
// 默认 = 100 + 2 * 1000 = 2100 blocks
```

| 判定函数 | 阈值 | 触发动作 |
|----------|------|----------|
| `is_downtime_governance_kickout` | `downtime_threshold_blocks` (100) | 治理踢出（需人工介入） |
| `is_downtime_auto_slashable` | `auto_slash_threshold` (2100) | 自动 slashing 10%（无需治理） |

### 6.3 SlashingReason 优先级（SEC2-H2）

| 优先级 | SlashingReason | 默认 slash_percentage | 说明 |
|--------|----------------|----------------------|------|
| 1 | `VertexEquivocation` | 100% | 同一 (epoch, round, author) 双签 vertex |
| 2 | `CommitCertEquivocation` | 100% | 同一 (epoch, commit_round) 双签 commit certificate |
| 3 | `RefuseCheckpoint` | 100% | 拒收 checkpoint（审查证据） |
| 4 | `Downtime` | 10% | 停机（NEW-L2） |
| 5 | `RefuseAck` | 100% | 拒绝 ACK |

### 6.4 多重 slashing（SEC2-H2）

`apply_multi_slashing()` 按优先级排序后依次执行：

- **扣除基数 = 剩余质押**（非原始质押），每项 slashing 基于当时剩余质押计算
- `slash_amount = remaining_stake * slash_percentage / 100`
- 质押耗尽 → 全额扣除 + 转欠款记录
- 受害者补偿按优先级分配

### 6.5 NEW-H1 调查流程

`force_checkpoint` 触发 assigned_validator 进入 `InvestigationState`：

| 字段 | 说明 |
|------|------|
| `triggered_at_height` | 调查触发 block height |
| `defense_deadline` | 防御窗口结束 height = triggered_at + 50 |
| `defense_submitted` | 是否已提交申辩 |
| `defense_valid` | 申辩是否有效 |
| `resolved` | 是否已 resolve |

流程：

1. `force_checkpoint` 提交 → `under_investigation_count` +1
2. `defense_window_blocks` (50) 内可提交"未收到证明"申辩
3. 申辩有效 → 豁免 slashing，仅记录审查嫌疑
4. 申辩无效或无申辩 → 治理 slashing
5. `under_investigation_count` 达 `DEFAULT_INVESTIGATION_THRESHOLD` (3) → 即使申辩也触发 slashing
6. 每 epoch 衰减 1（最低 0），防止历史指控永久累积

### 6.6 NEW-L2 停机惩罚

- 停机 validator 罚没 `downtime_slash_percentage`（10%）保证金
- 失去出块资格
- 申辩须提供 gossipsub 订阅日志 + libp2p 连接日志 + ≥2/3 validator 网络可达性佐证（SEC-H5）

---

## 7. Validator 加入/退出流程

### 7.1 ValidatorEntry 结构

定义于 `validator_set.rs`：

```rust
pub struct ValidatorEntry {
    pub pubkey: TaggedPubkey,                // secp256k1 tagged pubkey
    pub vrf_pubkey: [u8; 33],                // VRF pubkey（compressed secp256k1，33B）
    pub stake: u64,                          // 质押金额
    pub status: ValidatorStatus,             // 当前状态
    pub bonding_until_height: BlockHeight,   // Bonding 期结束 height
    pub unbonding_until_height: BlockHeight, // Unbonding 期结束 height
    pub last_vertex_height: BlockHeight,     // 最后一次产出 vertex 的 block height（停机判定）
    pub under_investigation_count: u32,      // 审查嫌疑计数（每 epoch 衰减 1）
    pub vrf_key_destroyed: bool,             // VRF 私钥是否已销毁（SEC2-M10）
    pub vrf_retired: bool,                   // VRF pubkey 是否已 retired（SEC2-M10）
}
```

### 7.2 ValidatorStatus 状态机

```
                    ┌──────────────────┐
                    │  ValidatorSetUpdate │
                    │  提案 (90% quorum)  │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │     Bonding       │  bonding_period_blocks=1000
                    │  (锁定期，可同步   │  (NEW-L3 = 1 epoch)
                    │   不参与共识)      │
                    └────────┬─────────┘
                             │ bonding_until_height 到达
                             ▼
              ┌──────────────────────────────┐
              │           Active              │  参与共识出块
              │   (参与共识，可被 slashing)    │
              └──────────────┬───────────────┘
                             │ start_unbonding()
                             ▼
                    ┌──────────────────┐
                    │    Unbonding      │  unbonding_period_blocks=2000
                    │  (不参与共识，     │  (R5-H7 = 2 × epoch_length)
                    │   可被 slashing)  │
                    └────────┬─────────┘
                             │ unbonding_until_height 到达
                             │ + vrf_key_destroyed=true
                             ▼
                    ┌──────────────────┐
                    │     Retired       │  vrf_retired=true
                    │  (不可被 slashing) │
                    └──────────────────┘

       任意状态 ──► Slashed（equivocation 类，R5-H7：unbonding 期内仍可 slashing）
```

### 7.3 ValidatorStatus 状态表

| 状态 | can_participate_consensus | can_be_slashed | 说明 |
|------|---------------------------|-----------------|------|
| `Bonding` | false | true | NEW-L3 锁定期，可同步不参与共识 |
| `Active` | true | true | 参与共识出块 |
| `Unbonding` | false | true | R5-H7 退出锁定期，不参与共识但可被 slashing |
| `Slashed` | false | false | 已被 slashing |
| `Retired` | false | false | 已退出，vrf_pubkey 标记 retired |

### 7.4 加入流程

1. **提交 ValidatorSetUpdate 提案**（90% quorum）
   - 校验 SEC-C2：新集大小 ≥ `MIN_VALIDATOR_SET_SIZE` (5)
   - 校验 SEC-M2：单次缩减比例 ≤ `MAX_SINGLE_REDUCTION_RATIO` (20%)
2. **Bonding 期**（`bonding_period_blocks` = 1000 = 1 epoch，NEW-L3）
   - 初始状态为 `Bonding`
   - 可同步不参与共识
   - `bonding_until_height` 到达后转为 `Active`
3. **Active**：参与共识出块

### 7.5 退出流程

1. **start_unbonding()**：`Active` → `Unbonding`
   - 仅 `Active` 状态可发起退出
   - 设置 `unbonding_until_height = current_height + unbonding_period_blocks` (2000)
2. **Unbonding 期**（R5-H7 = 2 × epoch_length）
   - 不参与共识但**可被 slashing**（unbonding 期内 equivocation 仍可罚没）
3. **mark_vrf_key_destroyed()**：销毁 VRF 私钥（SEC2-M10）
   - 退出 validator 须提交 `vrf_key_destroy_proof`
4. **finalize_unbonding()**：`Unbonding` → `Retired`
   - 须满足：`unbonding_until_height` 到达 + `vrf_key_destroyed = true`
   - 设置 `vrf_retired = true`
   - 不可再被 slashing

### 7.6 关键安全约束

| 约束 | 值 | 说明 |
|------|----|------|
| `MIN_VALIDATOR_SET_SIZE` | 5 | SEC-C2：OffChain 模式 \|V\| ≥ 5 |
| `MAX_SINGLE_REDUCTION_RATIO` | 20% | SEC-M2：单次缩减 ≤ 20% |
| `bonding_period_blocks` | 1000 | NEW-L3：新 validator 锁定期 = 1 epoch |
| `unbonding_period_blocks` | 2000 | R5-H7：退出锁定期 = 2 × epoch_length |
| R5-H7 | — | unbonding 期内 equivocation 仍可 slashing |

### 7.7 VRF key 管理

- `vrf_pubkey`：33 字节（compressed secp256k1，IMPL-SEC-2）
- `VrfProof`：97 字节（gamma_33 || c_32 || s_32，ECVRF-secp256k1 + SHA-256）
- 退出时须 `mark_vrf_key_destroyed()` → `vrf_key_destroyed = true`
- `finalize_unbonding()` 后 `vrf_retired = true`，pubkey 永久不可复用

---

## 8. 审查检测与防护

### 8.1 多副本见证机制

`force_checkpoint` 逃生机制用于 assigned_validator 审查截断防护：

| 常量 | 值 | 说明 |
|------|----|------|
| `DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT` | 5 | NEW-M3：3-of-5 多副本见证 |
| `DEFAULT_REPLICA_WITNESS_THRESHOLD` | 3 | 3-of-N 见证签名阈值 |
| `DEFAULT_FORCE_CHECKPOINT_DEPOSIT_RATIO_BPS` | 1000 (10%) | SEC2-M3：预锁保证金比例 |
| `MAX_FORCE_CHECKPOINT_PER_BLOCK` | 5 | SEC2-M3：全局每 block 上限 |
| `DEFAULT_INVESTIGATION_THRESHOLD` | 3 | NEW-H1：累积调查阈值 |
| `DEFAULT_INVESTIGATION_RETENTION_EPOCHS` | 10 | NEW-H1：调查标记保留 epoch 数 |
| `VERIFY_FAILURE_PROOF_GAS` | 80000 | SEC-H9：verify_failure_proof gas 上限 |
| `DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS` | 10000 | SubTask 27.5g：证据裁剪窗口 |

### 8.2 force_checkpoint 逃生流程

```
┌─────────────────────────────────────────────────────────────┐
│  assigned_validator 拒收 checkpoint_anchor                   │
│  （game_validator_timeout_blocks=2 内未装入 vertex）          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  副本 validator 收到 checkpoint_anchor → 签发                │
│  MultiReplicaReceipt（≥3 个见证签名，3-of-5）                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  任意参与者提交 force_checkpoint tx（走 Public 通道，         │
│  正常计费 gas，预锁 10% buy_in 保证金）                       │
│  含 AssignedValidatorFailureProof:                            │
│    - 原始 checkpoint_anchor 内容                              │
│    - multi_replica_receipts（≥3 见证签名）                    │
│    - RoundRangeNonInclusionProof（round 范围非包含证明）      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  validator 先 cheap check（数量 + validator 集归属）          │
│  再完整验证（签名 + 非包含证明）                               │
│  → 接受 force_checkpoint，更新 last_action_height             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  NEW-H1: under_investigation_count +1                        │
│  defense_window_blocks=50 内 assigned_validator 可申辩        │
│    - 申辩有效 → 豁免 slashing，仅记录审查嫌疑                 │
│    - 申辩无效/无申辩 → 治理 slashing                          │
│    - 累积达 3 次 → 即使申辩也触发 slashing                    │
└─────────────────────────────────────────────────────────────┘
```

### 8.3 RoundRangeNonInclusionProof

证明 assigned_validator 在 `[round_start, round_end]` 范围内未装入 checkpoint_anchor tx：

- **epoch 字段**（SEC-C1）：round 跨 epoch 全局递增，须显式绑定 epoch
- **vertex_list**：列出 assigned_validator 在范围内所有 vertex（round + author + vertex_hash + tx_merkle_root）
- **round_attendance_bitmap**：R4-M7 从 commit certificate 派生，标记每个 round 是否产出 vertex
- **non_inclusion_proofs**：对每个 vertex 提供 256 层 sparse Merkle 非包含证明（R5-H4），证明 tx_hash 不在 tx_merkle_tree 中
- **裁剪约束**：证据须在 `vertex_prune_after_blocks` (10000) 内提交

### 8.4 SEC-H5 申辩要求

assigned_validator 申辩须提供：

1. gossipsub 订阅日志
2. libp2p 连接日志
3. ≥2/3 validator 网络可达性佐证

申辩成功豁免 slashing；无申辩或申辩无效 → 治理 slashing。

---

## 9. 故障排查

### 9.1 vertex 同步失败

| 症状 | 可能原因 | 诊断方法 |
|------|----------|----------|
| `InsufficientParents { actual, required }` | parent_hashes < 2/3 validator | 检查 `required_parent_count(\|V\|)`，确认上一轮 vertex 是否齐全 |
| `VertexTooLarge { actual, limit }` | vertex 序列化 > 256KB | 检查 `MAX_VERTEX_SIZE`，拆分为多个 vertex |
| `DagVertexNotFound` | leader vertex 不在本地 DAG | 触发 sync protocol 请求缺失 vertex |
| `ShortIdCollision` | Compact Block Relay short ID 冲突 | 请求完整 vertex fallback，冲突 short ID 永久禁用 |

### 9.2 Commit certificate 失败

| 症状 | 可能原因 | 诊断方法 |
|------|----------|----------|
| `InsufficientQuorum { actual, required }` | 签名数 < 2/3 | 检查 `signer_count()` 与 `required_quorum(\|V\|)`，确认 validator 在线率 |
| `CommitCertificateMismatch` | epoch / prev_commit_hash / roots 不一致 | 检查 `validate_commit_certificate_fields()` 各字段，确认链式 hash chain 未断 |
| commit 长时间不产生 | 无 vertex 被 ≥2/3 引用 | 检查 `detect_commit_leader` 是否有 leader vertex，确认网络分区 |

### 9.3 Validator 停机

| 症状 | 可能原因 | 诊断方法 |
|------|----------|----------|
| `last_vertex_height` 长期不更新 | validator 离线 | 监控 `last_vertex_height`，超 `downtime_threshold_blocks` (100) → 治理踢出 |
| 自动 slashing 未触发 | `auto_slash_threshold` 计算错误 | 确认 `downtime_threshold + 2*epoch_length = 2100`，检查 `is_downtime_auto_slashable()` |
| 停机 validator 仍出块 | 状态未正确转为非 Active | 检查 `can_participate_consensus()`，停机类 slashing 不立即改 status |

### 9.4 GameTurn 超时

| 症状 | 可能原因 | 诊断方法 |
|------|----------|----------|
| GameTurn tx 长时间未确认 | assigned_validator 审查或离线 | 检查 `game_validator_timeout_blocks` (2)，超时后走 fallback tx |
| fallback tx 被拒 | timeout_proof 无效 | 检查 `validate_fallback_tx()`：witness 数量 ≥ 3、witness 独立性、gameturn_nonce 一致 |
| `NotYourTurn` | 非当前轮次玩家提交 | 检查 `validate_turn_order()` 与 `TurnRule::current_turn()` |

### 9.5 Checkpoint 审查

| 症状 | 可能原因 | 诊断方法 |
|------|----------|----------|
| `ForceCheckpointEvidenceFailed` | evidence 验证失败 | 检查 `AssignedValidatorFailureProof::verify()`：witness 数量、签名有效性、非包含证明 |
| `InvalidAssignedValidatorFailureProof` | 非包含证明格式错误 | 检查 `merkle_path.len() == 256`、`expected_root` 匹配、round_range 跨度 ≤ `max_round_span` |
| `under_investigation_count` 异常增长 | 误判或网络问题 | 检查 `defense_window_blocks` (50) 内申辩，每 epoch 衰减 1 |

### 9.6 Epoch 切换问题

| 症状 | 可能原因 | 诊断方法 |
|------|----------|----------|
| assigned_validator 突然变化 | epoch 切换重分配 | 检查 `compute_current_epoch()`，确认 `epoch_length_blocks` (1000) |
| `force_advance` 被拒 | 过渡窗口内无证据 | 检查 `is_in_epoch_transition_window()`，窗口内 force_advance 须附"未提交过渡锚点"证据 |
| checkpoint_anchor 提交失败 | 不在过渡窗口内 | 检查 `EpochTransitionState::submit_anchor()`，须在 `[window_start, window_end]` 内 |

### 9.7 Slashing 争议

| 症状 | 可能原因 | 诊断方法 |
|------|----------|----------|
| 误判 equivocation | 同一 vertex 重复提交 | 检查 `VertexEquivocationEvidence::validate()`：`vertex_hash_1 != vertex_hash_2` |
| 申辩窗口过期 | 超过 `defense_window_blocks` (50) | 检查 `InvestigationState::is_window_expired()`，过期后不可申辩 |
| 优先级处理错误 | 多重 slashing 顺序错 | 检查 `apply_multi_slashing()` 按 `priority()` 排序：vertex > commit > checkpoint > downtime > ack |

---

## 10. 监控指标

### 10.1 关键运维指标

| 指标 | 阈值/正常范围 | 告警条件 | 数据来源 |
|------|---------------|----------|----------|
| vertex 产出速率 | rounds/block | 单 validator 连续 100 block 未产出 → 停机 | `last_vertex_height` |
| commit certificate 频率 | 每 N block 1 个 | 长时间无 commit → 网络分区或 quorum 不足 | `commit_round` 增长 |
| validator 在线率 | ≥ 2/3 | 在线率 < 2/3 → 共识停滞 | `active_count()` / `validators.len()` |
| GameTurn 延迟 | ≤ `game_validator_timeout_blocks` (2) | 超时 → 触发 fallback | `last_action_height` |
| slashing 事件计数 | 0 | > 0 → 安全事件 | `SlashingResult` 计数 |
| archive node 数量 | ≥ `DEFAULT_ARCHIVE_NODE_MIN_COUNT` (3) | < 3 → 禁止裁剪 | `is_archive_node_sufficient()` |
| DAG vertex 裁剪 | `vertex_prune_after_blocks` (10000) 后裁剪 | 裁剪失败 → 存储压力 | `check_vertex_pruning_eligibility()` |
| tx 裁剪 | `tx_prune_after_blocks` (1000) 后裁剪 | 裁剪失败 → 存储压力 | `check_tx_pruning_eligibility()` |

### 10.2 节点角色分层

`NodeRole` 定义于 `storage/pruning.rs`：

| 角色 | 裁剪行为 | 历史数据 RPC | 数据保留 |
|------|----------|--------------|----------|
| `Archive` | 永不裁剪 | 提供 `request_historical_data` | 全数据 |
| `Full` | Layer 1-3 裁剪（tx / vertex / ZK proof） | 不提供 | 最近 10000 block 详情 + 永久保留项 |
| `Light` | 无完整数据可裁剪 | 不提供 | 仅 block header + state root commitment |

### 10.3 永久保留项（SEC-M8）

以下项写入 archive node 永不裁剪：

- `BlockHeader` — block header
- `ValidatorSetChange` — validator 集变更（含 slashing 证据 + 罚没金额）
- `GovernanceParamChange` — 治理参数变更
- `GameFinalSettlement` — Game 最终结算 + 台费分配
- `SlashingEvidence` — slashing 证据
- `ForceCheckpointEvidence` — force_checkpoint evidence 全量
- `ChallengeDeltaEvidence` — challenge_delta 争议证据
- `RequestRevertEvidence` — request_revert 回退证据
- `ZkProofHashChain` — ZK proof hash 链
- `PartialCheckinAnchor` — partial_checkin 锚点
- `RotateValidatorKeyRecord` — 密钥轮换记录
- `UpgradeCapRecord` — 升级 tx 记录
- `VerifierStatusSwitch` — verifier_status 切换
- `UnderInvestigationRecord` — 审查嫌疑累积记录
- `BridgeOperation` — 桥操作凭证

---

## 11. 性能基准

### 11.1 Task 36 基准测试

| bench 名称 | 测试内容 | 关键指标 |
|------------|----------|----------|
| `task36_dag_consensus` | DAG TPS（5/10/20 validator）+ 共识延迟 | `detect_commit_leader` + `bullshark_linear_order` + `project_block_from_commit` 延迟 |
| `task36_bls_syscall` | BLS12-381 预编译 | 各预编译延迟（G1/G2 add、pairing、hash_to_curve） |
| `task36_zk_verifier` | ZK verifier | `fold_step` / `fold_loop` / `zk_verify` 延迟 |

### 11.2 运行基准测试

```bash
# DAG 共识基准（含 5/10/20 validator TPS + 共识延迟）
cargo bench --bench task36_dag_consensus

# BLS12-381 预编译基准
cargo bench --bench task36_bls_syscall

# ZK verifier 基准
cargo bench --bench task36_zk_verifier

# 运行全部 Task 36 基准
cargo bench --bench task36_dag_consensus --bench task36_bls_syscall --bench task36_zk_verifier
```

### 11.3 性能预期参考

| 场景 | 预期吞吐/延迟 | 影响因素 |
|------|---------------|----------|
| DAG TPS（5 validator） | 高 | 网络带宽、vertex 大小 |
| DAG TPS（20 validator） | 中 | quorum 计算开销、parent 引用数 |
| `detect_commit_leader` | 低延迟 | DAG 规模、祖先遍历深度 |
| `bullshark_linear_order` | 低延迟 | commit 内 vertex 数量 |
| `project_block_from_commit` | 中延迟 | tx 数量、R4-M4 排序开销 |
| BLS12-381 pairing | 中延迟 | 硬件加速、预编译实现 |
| `zk_verify` | 高延迟 | fold 次数、circuit 规模 |

### 11.4 裁剪对性能的影响

| 裁剪层级 | 触发条件 | 性能影响 |
|----------|----------|----------|
| Layer 1（tx） | `tx_prune_after_blocks` (1000) + Game 结算 + dispute 过期 | 降低存储，加速 sync |
| Layer 2（vertex） | `vertex_prune_after_blocks` (10000) | 降低 DAG 遍历开销，丢失 tx_list 详情 |
| Layer 3（ZK proof） | Game 结算 + dispute 过期 + archive node ≥ 3 | 链上仅保留 proof_hash，proof 移至 Walrus DA 层 |

裁剪后 `PrunedVertex` 仅保留 `(round, epoch, author_pubkey, vertex_hash, tx_count, parent_count, author_sig)`，slashing 证据仍可用（`author_sig` 保留）。

---

## 12. 运维检查清单

### 12.1 日常检查

- [ ] validator 在线率 ≥ 2/3（`active_count()` / `validators.len()`）
- [ ] commit certificate 频率正常（`commit_round` 持续增长）
- [ ] 无 validator 触发 `downtime_threshold_blocks` (100) 停机阈值
- [ ] `under_investigation_count` 无异常增长
- [ ] archive node 数量 ≥ 3（`is_archive_node_sufficient()`）

### 12.2 Epoch 切换检查

- [ ] epoch 边界前 `epoch_transition_window_blocks` (10) 内提交 `checkpoint_anchor`
- [ ] 新 epoch 的 VRF proof 已提交（`submit_epoch_vrf_proof`）
- [ ] `epoch_randomness` 已更新（或 fallback 已触发）
- [ ] 所有活跃 Game 的 assigned_validator 已重分配校验

### 12.3 安全事件响应

- [ ] equivocation 证据已提交（`VertexEquivocationEvidence` / `CommitCertEquivocationEvidence`）
- [ ] `apply_slashing()` 按正确 `SlashingReason` 执行
- [ ] `force_checkpoint` 证据完整（`AssignedValidatorFailureProof` 验证通过）
- [ ] `InvestigationState` 申辩窗口未过期（`defense_window_blocks` = 50）
- [ ] slashing 事件已记录到 `PermanentRetentionItem::SlashingEvidence`

### 12.4 存储与裁剪

- [ ] Full node 裁剪窗口配置正确（`tx_prune_after_blocks` = 1000, `vertex_prune_after_blocks` = 10000）
- [ ] archive node 数量充足（≥ 3）后才允许裁剪
- [ ] 永久保留项未误裁剪（`PermanentRetentionItem` 全部保留）
- [ ] Walrus blob 未过期（`ArchivedZkProof.blob_expired` = false）

---

## 附录 A：关键常量速查

| 常量 | 值 | 定义位置 |
|------|----|----------|
| `MAX_VERTEX_SIZE` | 256 KB | `consensus/mod.rs` |
| `MAX_TX_SIZE` | 128 KB | `network/mod.rs` |
| `MAX_BLOCK_SIZE` | 4 MB | `network/mod.rs` |
| `SHORT_ID_LEN` | 8 字节 | `network/mod.rs` |
| `SHORT_ID_MAP_LIMIT` | 100,000 | `network/mod.rs` |
| `MEMPOOL_BUFFER_WINDOW_MS` | 100 ms | `network/mod.rs` |
| `VERTEX_SIG_DOMAIN` | 0x56 ('V') | `consensus/mod.rs` |
| `COMMIT_CERT_SIG_DOMAIN` | 0x43 ('C') | `consensus/mod.rs` |
| `SHORT_ID_DOMAIN` | 0x53 ('S') | `network/mod.rs` |
| `MIN_VALIDATOR_SET_SIZE` | 5 | `consensus/validator_set.rs` |
| `MAX_SINGLE_REDUCTION_RATIO` | 20 (%) | `consensus/validator_set.rs` |
| `VRF_PROOF_SIZE` | 97 字节 | `consensus/validator_set.rs` |
| `VRF_PUBKEY_SIZE` | 33 字节 | `consensus/validator_set.rs` |
| `DEFAULT_SLASH_PERCENTAGE` | 100 (%) | `consensus/slashing.rs` |
| `DEFAULT_DOWNTIME_THRESHOLD_BLOCKS` | 100 | `consensus/slashing.rs` |
| `DEFAULT_DOWNTIME_SLASH_PERCENTAGE` | 10 (%) | `consensus/slashing.rs` |
| `DEFAULT_DEFENSE_WINDOW_BLOCKS` | 50 | `consensus/slashing.rs` |
| `auto_slash_threshold` (默认) | 2100 | `consensus/slashing.rs` |
| `DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS` | 2 | `consensus/game_assignment.rs` |
| `DEFAULT_FORFEIT_BOND_PERCENTAGE` | 50 (%) | `consensus/game_assignment.rs` |
| `DEFAULT_MAX_ACTIVE_GAMES_PER_PLAYER` | 10 | `consensus/routing.rs` |
| `DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT` | 5 | `consensus/vertex_production.rs` |
| `DEFAULT_FORCE_CHECKPOINT_DEPOSIT_RATIO_BPS` | 1000 (10%) | `vm/contracts/force_checkpoint.rs` |
| `MAX_FORCE_CHECKPOINT_PER_BLOCK` | 5 | `vm/contracts/force_checkpoint.rs` |
| `DEFAULT_INVESTIGATION_THRESHOLD` | 3 | `vm/contracts/force_checkpoint.rs` |
| `DEFAULT_REPLICA_WITNESS_THRESHOLD` | 3 | `vm/contracts/force_checkpoint.rs` |
| `VERIFY_FAILURE_PROOF_GAS` | 80000 | `vm/contracts/force_checkpoint.rs` |
| `DEFAULT_TX_PRUNE_AFTER_BLOCKS` | 1000 | `storage/pruning.rs` |
| `DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS` | 10000 | `storage/pruning.rs` |
| `DEFAULT_ARCHIVE_NODE_MIN_COUNT` | 3 | `storage/pruning.rs` |

---

## 附录 B：Quorum 计算速查

| validator 数 |V| | required_parent_count | required_quorum | required_witness_count(5) |
|---------------|----------------------|-----------------|---------------------------|
| 5 | 4 | 4 | 3 |
| 6 | 4 | 4 | 3 |
| 7 | 5 | 5 | 3 |
| 8 | 6 | 6 | 3 |
| 9 | 6 | 6 | 3 |
| 10 | 7 | 7 | 3 |
| 15 | 10 | 10 | 3 |
| 20 | 14 | 14 | 3 |

公式：

- `required_parent_count(n) = ceil(n * 2 / 3)`
- `required_quorum(n) = required_parent_count(n)`
- `required_witness_count(n) = max(3, floor(n * 2 / 3))`

---

*文档版本：SubTask 37.6 — DAG 共识运维文档（FROZEN 2026-06-27 spec 对齐）*
