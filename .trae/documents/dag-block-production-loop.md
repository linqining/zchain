# DAG 产块循环实现计划

## Context

当前 `zchain node` 子命令只起 RPC server，没有 DAG 产块循环。spec 明确要求："block 不需要单独 production，而是 DAG commit 的投影"。`poker_l1` 库已实现完整的 Bullshark 共识原语（`Dag` 状态机、`detect_commit_leader`、`project_block_from_commit`、`assemble_commit_certificate`），但 `main.rs` 没有调用它们。本次补齐 validator 后台产块循环 + tokio TCP 轻量 P2P 广播，使 validator 能周期性产出 vertex → 检测 commit → 投影 block → 持久化 + 广播。

## 设计决策

* **单 validator 自闭环**：`required_quorum(1) = 1`，每轮新 vertex 引用上轮 vertex → 自动满足 commit quorum

* **tokio TCP 轻量 P2P**：实现 `NetworkTransport` trait，4 字节 length-prefix + BCS 序列化消息，不引入 libp2p（避免 musl 静态编译问题）

* **1 秒出块周期**（可通过 `--block-interval-ms` 覆盖）

* **代码在** **`src/main.rs`**：产块循环是二进制编排逻辑，避免给 `poker_l1` 添加线程/定时器依赖

## 实现步骤

### 1. P2P TCP 传输层（main.rs 新增 `TcpTransport`）

实现 `poker_l1::network::NetworkTransport` trait：

```rust
struct TcpTransport {
    peers: Arc<Mutex<Vec<TcpStream>>>,  // 已连接 peers
}
```

* `gossip_broadcast(topic, msg)`：BCS 序列化 → 4 字节 length prefix → 发送给所有 peers

* `send_to(peer, msg)`：点对点发送

* P2P server 线程：accept 新连接，接收消息并处理（Block → put\_block, DagVertex → put\_vertex, Transaction → submit\_tx）

* CLI 参数：`--peer <addr>`（可重复，启动时主动连接）

### 2. validator 产块循环（main.rs 新增 `run_validator_loop`）

在 `run_node` 中，validator 角色 spawn 后台线程：

```
loop {
    if shutdown.load() { break; }
    sleep(block_interval);  // 默认 1s

    // 1. drain_pending_tx → tx_list
    // 2. VertexBuilder(epoch, round, author_pubkey)
    //    parent_hashes = last_vertex_hash.map(|h| vec![h]).unwrap_or_default()
    //    创世轮（round 1）跳过 validate_parents
    // 3. build unsigned vertex → vertex.signing_hash(chain_id) → secp256k1 签名
    // 4. dag.lock().insert(vertex.clone()) + node.put_vertex(&vertex)
    // 5. transport.gossip_broadcast(DagVertex, &vertex)

    // 6. 若 last_vertex_hash 存在 → 检测 commit：
    //    detect_commit_leader(&dag, &last_vertex_hash, validator_count=1)
    //    若 Some(leader):
    //      a. compute_commit_roots(&dag, &leader) → (public_tx_root, gameturn_tx_root)
    //      b. cert_signing_hash → secp256k1 签名 cert
    //      c. assemble_commit_certificate(epoch, commit_round, prev_commit_hash,
    //         vertex_hash_list, attendance, state_root=[0;32], roots, sigs=[(0,sig)], 1)
    //      d. project_block_from_commit(&dag, &leader, cert, state_root, prev_block_hash, height, timestamp)
    //      e. node.put_block(&block) + transport.gossip_broadcast(Block)
    //      f. commit_round += 1; prev_commit_hash = cert.cert_hash(chain_id)

    // 7. last_vertex_hash = vertex_hash; round += 1
}
```

### 3. cert roots 一致性（`compute_commit_roots` 辅助函数）

`project_block_from_commit` 内部计算 `public_tx_root`/`gameturn_tx_root`，但 `assemble_commit_certificate` 需要这些 roots 作为参数。为保证一致：

```rust
fn compute_commit_roots(dag: &Dag, leader: &CommitLeader) -> PokerL1Result<(Hash, Hash)> {
    let ordered = bullshark_linear_order(dag, &leader.referencing_hashes)?;
    let mut vertex_txs: Vec<Vec<Transaction>> = Vec::new();
    for h in &ordered {
        if let Some(v) = dag.get(h) { vertex_txs.push(v.tx_list.to_vec()); }
    }
    let sorted = sort_commit_txs_r4m4(vertex_txs);
    let (mut pub_txs, mut gt_txs) = (vec![], vec![]);
    for tx in sorted {
        match tx.lane_hint {
            TxLane::GameTurn | TxLane::CheckpointAnchor => gt_txs.push(tx),
            _ => pub_txs.push(tx),
        }
    }
    Ok((compute_tx_merkle_root(&pub_txs), compute_tx_merkle_root(&gt_txs)))
}
```

复用 [bullshark.rs:207-235](file:///Users/mac/projects/zchain/poker_l1/src/consensus/bullshark.rs#L207-L235) `bullshark_linear_order`、[vertex\_production.rs:375-384](file:///Users/mac/projects/zchain/poker_l1/src/consensus/vertex_production.rs#L375-L384) `sort_commit_txs_r4m4`、[block/mod.rs](file:///Users/mac/projects/zchain/poker_l1/src/block/mod.rs) `compute_tx_merkle_root`。

### 4. main.rs 集成修改

修改 `run_node`（[main.rs:145-364](file:///Users/mac/projects/zchain/src/main.rs#L145-L364)）：

* 新增 CLI 参数：`--block-interval-ms <ms>`（默认 1000）、`--peer <addr>`（可重复）

* validator 角色：创建 `Arc<Mutex<Dag>>` + `Arc<TcpTransport>`

* spawn 3 个后台线程：

  * P2P accept loop（接收 peer 连接 + 消息）

  * validator loop（产块循环，仅 validator）

  * signal handler（已有，保持不变）

* RPC server 循环保持不变

### 5. full node 接收逻辑

full node 不产块，但通过 P2P 接收：

* 收到 `NetworkMessage::ResponseBlocks(blocks)` → 逐个 `node.put_block(&block)`

* 收到 `NetworkMessage::DagVertex(vertex)` → `node.put_vertex(&vertex)`

* 收到 `NetworkMessage::Transaction(tx)` → `node.submit_tx(tx)`

## 关键文件

| 文件                                                           | 改动                                                                                            |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| [src/main.rs](file:///Users/mac/projects/zchain/src/main.rs) | 新增 `TcpTransport`、`run_validator_loop`、`compute_commit_roots`、修改 `run_node`                   |
| [Cargo.toml](file:///Users/mac/projects/zchain/Cargo.toml)   | 无新依赖（tokio/secp256k1/bcs 已有）                                                                  |
| `poker_l1/src/consensus/bullshark.rs`                        | 不修改，复用 `Dag`/`detect_commit_leader`/`project_block_from_commit`/`assemble_commit_certificate` |
| `poker_l1/src/network/mod.rs`                                | 不修改，复用 `NetworkTransport` trait / `NetworkMessage` / `GossipTopic`                            |

## 复用的现有函数

* [vertex\_production.rs:96-191](file:///Users/mac/projects/zchain/poker_l1/src/consensus/vertex_production.rs#L96-L191) `VertexBuilder::new/push_tx/with_parents/build`

* [consensus/mod.rs:171-185](file:///Users/mac/projects/zchain/poker_l1/src/consensus/mod.rs#L171-L185) `DagVertex::signing_hash(chain_id)`

* [consensus/mod.rs:239-256](file:///Users/mac/projects/zchain/poker_l1/src/consensus/mod.rs#L239-L256) `DagCommitCertificate::signing_hash(chain_id)` / `cert_hash(chain_id)`

* [bullshark.rs:51-67](file:///Users/mac/projects/zchain/poker_l1/src/consensus/bullshark.rs#L51-L67) `Dag::insert/get/round_vertices/max_round`

* [bullshark.rs:123-175](file:///Users/mac/projects/zchain/poker_l1/src/consensus/bullshark.rs#L123-L175) `detect_commit_leader`

* [bullshark.rs:418-461](file:///Users/mac/projects/zchain/poker_l1/src/consensus/bullshark.rs#L418-L461) `assemble_commit_certificate`

* [bullshark.rs:261-315](file:///Users/mac/projects/zchain/poker_l1/src/consensus/bullshark.rs#L261-L315) `project_block_from_commit`

* [node/mod.rs:471-477](file:///Users/mac/projects/zchain/poker_l1/src/node/mod.rs#L471-L477) `Node::drain_pending_tx`

* [node/mod.rs:360-362](file:///Users/mac/projects/zchain/poker_l1/src/node/mod.rs#L360-L362) `Node::put_block`

## 验证

1. **编译**：`cargo zigbuild --release --target x86_64-unknown-linux-musl`
2. **生成 validator 密钥**：`zchain keygen --scheme secp256k1` → 保存 secret\_key\_hex
3. **启动 validator**：

   ```
   zchain node --role validator --validator-key-file /path/to/key \
     --data-dir /tmp/val1 --rpc-listen 127.0.0.1:8545 --p2p-listen 127.0.0.1:9000
   ```
4. **提交 tx**：通过 `submit_tx` RPC 提交一笔签名交易
5. **等待 2 秒**（2 轮 vertex 后出第一个 block）
6. **查询验证**：`get_block` height=1 → 确认含提交的 tx + `dag_commit_certificate`
7. **P2P 同步测试**（可选）：启动 full node `--peer 127.0.0.1:9000` → 通过 P2P 接收 block

## 已知限制

* 单 validator 自闭环（无真实 BFT 多签共识）

* `state_root` 暂用 `[0u8;32]`（无状态机执行层）

* P2P 明文 TCP（生产环境需加 Noise/tls 加密）

* peer discovery 手动（`--peer` 参数），无自动发现

* 创世轮 vertex 无 parent（跳过 `validate_parents`，符合 Bullshark 创世轮语义）

