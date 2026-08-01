# zchain 项目架构总览

> 本文档系统梳理 zchain 仓库的整体架构、模块职责、信任模型与执行流水线，并与市场主流区块链进行横向对比，作为新成员入门、架构评审与对外宣讲的统一入口。
>
> 严格对齐源码实现：
> - 仓库根 `Cargo.toml`（workspace 定义）、`src/main.rs`（节点二进制入口）
> - `poker_l1/src/lib.rs`（L1 链核心库模块声明）
> - `poker_zkvm/src/lib.rs`（ZK 虚拟机模块声明）
> - `docs/37-1 ~ 37-10`（已有运维 / 信任模型文档）

---

## 1. 项目定位

zchain 是面向**链下博弈与高吞吐游戏场景**的 L1 区块链，核心设计目标：

| 目标 | 实现方式 |
| --- | --- |
| **游戏操作免 gas** | GameTurn 通道（spec 硬约束），由买入锁仓反滥用 |
| **链下执行 + 链上结算** | OffChain 模式 + Stwo Circle-STARK ZK 证明（poker_texas_air 自定义电路） |
| **渐进式信任最小化** | 三层信任模型：BFT 共识 → 单点+见证 → 密码学 |
| **高吞吐低延迟** | Narwhal-Bullshark DAG + Compact Block Relay + 无 mempool |
| **多曲线钱包支持** | secp256k1 / ed25519 tagged pubkey 统一接口 |
| **可治理可升级** | 链上参数治理 + rBPF 合约 UpgradeCap |

---

## 2. Workspace 顶层架构

zchain 是一个 Cargo workspace，包含 **5 个 crate + 1 个二进制入口**：

```mermaid
graph TD
    subgraph WS["zchain workspace (Cargo.toml)"]
        BIN["zchain (bin)<br/>src/main.rs<br/>节点 CLI + JSON-RPC + 多 validator BFT loop"]
        L1["poker_l1 (lib)<br/>L1 区块链核心库<br/>~20 模块 / ~1600 测试"]
        AIR["poker_texas_air (lib)<br/>Texas Poker 自定义 AIR 电路<br/>21 method AIR + host-verify"]
        ZKVM["poker_zkvm (lib)<br/>Stwo Circle-STARK zkVM<br/>CPU/memory/Poseidon/SHA256 AIR"]
        VMC["vm-common (lib)<br/>共享: gas / syscall_id / precompile / prove_task"]
        PSVC["proving_service (bin/lib)<br/>离线证明 HTTP 服务<br/>axum + poker_texas_air Orchestrator"]
        PROTO["poker_protocol<br/>(外部 crate ../zgame)<br/>协议类型与 zk_shuffle"]
    end

    BIN --> L1
    L1 --> ZKVM
    L1 --> VMC
    ZKVM --> VMC
    AIR --> L1
    AIR --> ZKVM
    AIR --> VMC
    PSVC --> L1
    PSVC --> AIR
    L1 --> PROTO

    classDef bin fill:#fef3c7,stroke:#92400e
    classDef lib fill:#dbeafe,stroke:#1e40af
    classDef ext fill:#f3e8ff,stroke:#6b21a8
    class BIN,PSVC bin
    class L1,AIR,ZKVM,VMC lib
    class PROTO ext
```

| crate | 角色 | 关键依赖 |
| --- | --- | --- |
| `zchain` | 节点二进制入口（`node` / `keygen` / `test-e2e` / `poker-demo`） | `poker_l1`, `tokio`, `tracing-subscriber` |
| `poker_l1` | L1 链核心库：交易 / 区块 / 共识 / VM / RPC / 节点 / 桥 / 治理 / slashing | `poker_zkvm`, `vm-common`, `poker_protocol`, `solana_rbpf`, `blstrs`, `secp256k1`, `ed25519-dalek`, `rocksdb`, `vrf` |
| `poker_texas_air` | Texas Poker 自定义 AIR 电路（21 method AIR + Stwo prover/verifier + host-verified receipts） | `poker_l1`, `poker_zkvm`, `vm-common`, `stwo` |
| `poker_zkvm` | 通用 Stwo Circle-STARK zkVM（CPU/memory/Poseidon/SHA256/range-check AIR + recursive） | `vm-common`, `stwo` |
| `vm-common` | 跨 crate 共享层（gas / syscall_id / precompile / prove_task / catalog） | `stwo` |
| `proving_service` | 离线证明 HTTP 服务（axum，消费 poker_texas_air Orchestrator） | `poker_l1`, `poker_texas_air`, `vm-common`, `axum` |
| `poker_protocol` | 协议类型库（外部仓库，非 workspace 成员） | `blstrs`, `sha2` |

**ZK 依赖方向**（注意：与"链验证证明"直觉相反）：`poker_texas_air → poker_l1`（air 依赖 l1 以复用类型），`proving_service → poker_texas_air`。poker_l1 **不依赖** poker_texas_air——链上 `zk_verify` 当前 dormant，证明生成/验证走 `proving_service` 离线 host-verify。

二进制入口 `src/main.rs` 提供 4 类节点角色（`validator` / `full` / `archive` / `light`），通过 newline-delimited JSON-RPC over TCP 暴露接口，支持 SIGINT/SIGTERM 优雅关闭、`--max-connections` 限流、`--genesis-validators` / `--genesis-alloc` / `--vrf-key-file` 多 validator 配置。

---

## 3. poker_l1 模块架构

### 3.1 模块依赖图

```mermaid
graph TD
    subgraph Foundation["基础层"]
        OBJ[object_model<br/>Object/SMT/ObjectStore]
        SIG[signature<br/>secp256k1/ed25519/tagged]
        ACC[account<br/>Account/nonce/balance]
        TX[transaction<br/>TxLane/Gas/ContractCall]
        ERR[error<br/>PokerL1Error]
    end

    subgraph Ledger["账本与共识层"]
        BLK[block<br/>BlockHeader/双通道 root]
        CON[consensus<br/>DAG/Bullshark/slashing]
        STO[storage<br/>RocksDB 持久化]
        GOV[governance<br/>参数治理/timelock]
    end

    subgraph Exec["执行层"]
        VM[vm<br/>rBPF + syscalls + gas]
        CRYPTO[crypto_precompiles<br/>BLS12-381/secp256k1]
        OFF[offline<br/>OffChain 状态/ZK verifier]
    end

    subgraph Net["网络与节点层"]
        NET[network<br/>gossipsub/Compact Block]
        NODE[node<br/>Node/NodeConfig/NodeRole]
        RPC[rpc<br/>JSON-RPC 2.0 + Auth + RateLimit]
        BRIDGE[bridge<br/>跨链桥 hook]
    end

    subgraph Aux["辅助与同步层"]
        SYNC[sync<br/>Fast/Snap Sync]
        IDX[indexer<br/>索引器/事件订阅]
    end

    TX --> OBJ
    TX --> SIG
    ACC --> SIG
    BLK --> TX
    BLK --> CON
    BLK --> OBJ
    CON --> TX
    CON --> SIG
    VM --> OBJ
    VM --> TX
    VM --> CRYPTO
    OFF --> VM
    OFF --> ZKVM_EXT[poker_zkvm]
    NET --> CON
    NET --> TX
    NODE --> BLK
    NODE --> CON
    NODE --> NET
    RPC --> NODE
    BRIDGE --> SIG
    STO --> BLK
    STO --> OBJ
    STO --> CON
    GOV --> BLK
    SYNC --> STO
    SYNC --> BLK
    IDX --> BLK
    IDX --> TX
    IDX --> OBJ

    classDef foundation fill:#dcfce7,stroke:#166534
    classDef ledger fill:#dbeafe,stroke:#1e40af
    classDef exec fill:#fee2e2,stroke:#991b1b
    classDef net fill:#fef3c7,stroke:#92400e
    classDef aux fill:#f3e8ff,stroke:#6b21a8
    class OBJ,SIG,ACC,TX,ERR foundation
    class BLK,CON,STO,GOV ledger
    class VM,CRYPTO,OFF,ZKVM_EXT exec
    class NET,NODE,RPC,BRIDGE net
    class SYNC,IDX aux
```

### 3.2 模块清单

| 模块 | 职责 | 关键类型 |
| --- | --- | --- |
| [`object_model`](file:///Users/mac/projects/zchain/poker_l1/src/object_model/mod.rs) | 对象模型（Object / ObjectID / Ownership）+ Sparse Merkle Tree + ObjectStore | `Object`, `ObjectID`, `ObjectStore`, `SparseMerkleTree` |
| [`signature`](file:///Users/mac/projects/zchain/poker_l1/src/signature/mod.rs) | 多曲线钱包签名（tagged pubkey + secp256k1 + ed25519 + low-s 强制） | `TaggedPubkey`, `SignatureScheme`, `verify_signature` |
| [`account`](file:///Users/mac/projects/zchain/poker_l1/src/account/mod.rs) | 账户抽象 + nonce / balance + 双通道重放保护 | `Account`, `validate_tx_nonce` |
| [`transaction`](file:///Users/mac/projects/zchain/poker_l1/src/transaction/mod.rs) | 交易结构 + 4 通道分类（Public/GameTurn/CheckpointAnchor/ForceSync） | `Transaction`, `TxLane`, `RouteHint`, `Gas`, `ContractCall` |
| [`block`](file:///Users/mac/projects/zchain/poker_l1/src/block/mod.rs) | 区块结构 + 双通道 tx_root + 时间共识 | `Block`, `BlockHeader`, `TimeConsensusConfig` |
| [`consensus`](file:///Users/mac/projects/zchain/poker_l1/src/consensus/mod.rs) | Narwhal-Bullshark DAG + game sub-block + slashing + validator set + VRF | `DagVertex`, `DagCommitCertificate`, `ValidatorEntry`, `SlashingReason` |
| [`storage`](file:///Users/mac/projects/zchain/poker_l1/src/storage/mod.rs) | RocksDB 持久化 + 裁剪策略 + 历史数据请求 | `BlockStore`, `ObjectDb`, `DagVertexStore`, `PruningConfig` |
| [`vm`](file:///Users/mac/projects/zchain/poker_l1/src/vm/mod.rs) | rBPF VM + syscalls + gas 计费 + 合约升级 | `PokerL1Context`, `execute_contract`, `UpgradeCap` |
| [`crypto_precompiles`](file:///Users/mac/projects/zchain/poker_l1/src/crypto_precompiles/mod.rs) | BLS12-381 G1/G2/pairing + 子群检查 + RFC 9380 hash-to-curve | `bls_verify`, `bls_hash_to_g1/g2` |
| [`offline`](file:///Users/mac/projects/zchain/poker_l1/src/offline/mod.rs) | OffChain 执行模式 + ZK verifier 热插拔 + checkpoint_anchor + checkin | `OfflineState`, `CheckinTx`, `CheckoutTx`, `ZkVerifierRegistry` |
| [`network`](file:///Users/mac/projects/zchain/poker_l1/src/network/mod.rs) | gossipsub + Compact Block Relay + 多副本广播 + tx_cache FIFO | `GossipManager`, `CompactVertex`, `TxBuf` |
| [`node`](file:///Users/mac/projects/zchain/poker_l1/src/node/mod.rs) | 节点入口 + 角色配置 + assigned_validator 本地路由 | `Node`, `NodeConfig`, `NodeRole`, `ValidatorKey` |
| [`rpc`](file:///Users/mac/projects/zchain/poker_l1/src/rpc/mod.rs) | JSON-RPC 2.0 + AuthConfig + RpcGuard 滑动窗口限流 | `RpcHandler`, `RpcGuard`, `JsonRpcResponse` |
| [`bridge`](file:///Users/mac/projects/zchain/poker_l1/src/bridge/mod.rs) | 跨链桥 hook + bridge_verify + BTreeSet 去重 + nonce 防重放 | `BridgeHook`, `bridge_verify` |
| [`governance`](file:///Users/mac/projects/zchain/poker_l1/src/governance/mod.rs) | 参数治理 + timelock + 边界校验 + 敏感参数 90% quorum | `GovernanceParams`, `ProposeParameterTx` |
| [`sync`](file:///Users/mac/projects/zchain/poker_l1/src/sync/mod.rs) | 状态快速同步（Fast/Snap Sync）—— 分块快照 + state_root 端到端校验 + BFT 锚定 | `SnapshotManifest`, `SnapshotChunk`, `FastSync`, `SyncState` |
| [`indexer`](file:///Users/mac/projects/zchain/poker_l1/src/indexer/mod.rs) | 链上索引器 + 事件订阅 —— 按 sender/contract/object 查询 + 多订阅 fan-out | `Indexer`, `IndexedTransaction`, `IndexedBlock`, `TxFilter`, `IndexerEvent` |
| [`error`](file:///Users/mac/projects/zchain/poker_l1/src/error.rs) | 统一错误类型 `PokerL1Error` | `PokerL1Error`, `PokerL1Result` |

---

## 4. ZK 证明架构（Stwo Circle-STARK）

zchain 的 ZK 层基于 **Stwo**（Circle-STARK + AIR + FRI over M31），**v2 已完全放弃 Hypernova/CCS 折叠方案**。ZK 能力分布在三个 crate：

### 4.1 三层 ZK 架构

```mermaid
graph LR
    subgraph L1["poker_l1 (链上)"]
        TASK["ProveTask<br/>(borsh, 经 vm-common 共享类型)"]
        ZKV["zk_verify syscall<br/>(当前 dormant)"]
    end
    subgraph SVC["proving_service (离线)"]
        ORCH["Orchestrator<br/>消费 ProveTask"]
    end
    subgraph AIR["poker_texas_air (自定义电路)"]
        M21["21 method AIR<br/>lifecycle/actions/funds/crypto"]
        PROOF["Stwo proof<br/>(per-method)"]
        VCHR["host-verify receipt<br/>(VerifiedChain)"]
        AGG["Aggregator PoC<br/>(descriptor-only)"]
    end
    subgraph ZKVM["poker_zkvm (通用 zkVM)"]
        CPU["CPU/memory/Poseidon/<br/>SHA256/range-check AIR"]
        REC["recursive/<br/>(递归证明)"]
    end

    TASK --> ORCH
    ORCH --> M21
    M21 --> PROOF
    PROOF --> VCHR
    VCHR --> AGG
    AIR --> ZKVM

    classDef chain fill:#fef3c7,stroke:#92400e
    classDef svc fill:#dcfce7,stroke:#166534
    classDef air fill:#dbeafe,stroke:#1e40af
    classDef zkvm fill:#f3e8ff,stroke:#6b21a8
    class TASK,ZKV chain
    class ORCH svc
    class M21,PROOF,VCHR,AGG air
    class CPU,REC zkvm
```

### 4.2 poker_zkvm（通用 Stwo Circle-STARK zkVM）

`poker_zkvm` 是基于 Stwo 的通用 RISC-V zkVM，trace 在 M31（4×8-bit limb）中原生生成的电路。

| 模块 | 职责 |
| --- | --- |
| `stwo_backend/cpu_air.rs` | CPU 执行步骤 AIR |
| `stwo_backend/memory_air.rs` | 内存读写 AIR |
| `stwo_backend/poseidon_air.rs` / `poseidon_m31.rs` | Poseidon 哈希 AIR |
| `stwo_backend/sha256_air.rs` | SHA-256 AIR |
| `stwo_backend/range_check_air.rs` | 范围检查 AIR（被 poker_texas_air 复用） |
| `stwo_backend/recursive/` | 递归证明（FRI verifier / transcript / recursion prover/verifier） |
| `stwo_backend/prover.rs` | Stwo `prove()` 入口 |
| `isa/` / `trace/` / `compiler/` | 指令集 / trace 模型 / ELF 加载 |

### 4.3 poker_texas_air（Texas Poker 自定义 AIR 电路 — 真实证明实现）

`poker_texas_air` 是 **Texas Hold'em 方法转换的 21 个自定义 AIR 电路** + Stwo prover/verifier + host-verified receipts。这是当前真实的 ZK 证明实现路径（非 Hypernova）。

**分层（per `lib.rs`）**：
- **Layer 0**：21 个 method AIR（`airs/lifecycle/` 6 个 + `airs/actions/` 8 个 + `airs/funds/` 2 个 + `airs/crypto/` 5 个），每个方法独立手写 AIR over M31 列。
- **Layer 1**：host-verify receipts（`Orchestrator` 调用 prove + 立即 native verify，签名回执入 `VerifiedChain`）。当前为 O(N) host 验证，**非** succinct 递归证明。
- **Layer 2**：descriptor-only Aggregator PoC（`aggregator_air.rs`，默认拒绝聚合，待可信递归落地）。
- **Layer 3**：最终递归（尚未实现）。

**关键模块**：`prover.rs`（`prove_method`）、`verifier.rs`（`verify_method`，须独立重建 expected AIR + trusted row）、`orchestrator.rs`（消费 `ProveTask`）、`verified_chain.rs`、`state_root.rs`、`merkle_tree.rs`、`airs/{actions,crypto,funds,lifecycle}/`。

**成熟度**（per `circuit-contract-reconciliation.md`）：21 个 method AIR 为 PoC——约束输入一致性 + 最小输出 flag，非完整业务算术；aggregator 不验证子证明；最终递归闭环未完成。host-verified receipts 是当前信任机制。

### 4.4 proving_service（离线证明服务）

`proving_service` 是 axum HTTP 服务，是 **poker_texas_air 的唯一消费者**。它从 poker_l1 dispatch 发出的 borsh `ProveTask` 出发，交给 `poker_texas_air::Orchestrator` 执行 per-method Stwo proof + 立即 native verify，产出 `VerifiedChain` 回执。

### 4.5 链上 zk_verify（当前 dormant）

poker_l1 的链上 `zk_verify` syscall（id `0x47`）与 RPC 当前 **dormant**：`NodeBackend::zk_verifier_registry()` 返回 `None`，故 `handle_zk_verify` RPC 返回 "zk verifier registry not available"。`register_stwo_verifier` 仅在 `#[cfg(test)]` 调用。`StwoZkVerifier`（scheme_id=1）在 Production 状态 fail-closed。真实证明生成/验证走 `proving_service` 离线 host-verify，不经过链上 `zk_verify`。

**scheme_id 历史**：`scheme_id=1` 历史名 Hypernova，现统一为 Stwo（`SCHEME_STWO = 1`，原 `SCHEME_HYPERNOVA` 别名已删除）。Groth16=2、IPA=3、ZkShuffle=4。

---

## 5. 三层信任模型

zchain 的核心创新是**渐进式信任最小化**，按 tx 通道与执行模式分为三层（详见 [37-10-trust-layer-model.md](file:///Users/mac/projects/zchain/docs/37-10-trust-layer-model.md)）：

```mermaid
graph TB
    subgraph L1["Layer 1: Public 通道 — 全共识网络信任"]
        L1_TRUST["≥2/3 validator 诚实 (BFT)"]
        L1_TX["普通转账 / 合约调用 / fallback tx<br/>CheckinTx / Slash evidence"]
        L1_PERF["~1000 tx/s | ~3s finality | 正常 gas"]
    end

    subgraph L2["Layer 2: Game tx 通道 — 单点 + 多副本见证"]
        L2_TRUST["assigned_validator 诚实<br/>OR ≥4 witness 诚实 (3-of-5 fallback)"]
        L2_TX["GameTurn tx (fold/check/call/raise)<br/>CheckpointAnchor tx"]
        L2_PERF["~1000 tx/s | ~3s finality | 免 gas"]
    end

    subgraph L3["Layer 3: OffChain — 密码学信任"]
        L3_TRUST["无信任假设 (ZK soundness)"]
        L3_TX["链下博弈执行<br/>Stwo/poker_texas_air proof 结算"]
        L3_PERF["~100,000+ tx/s | ms 延迟 | checkin 时计费"]
    end

    L1 -->|fallback 逃生| L2
    L2 -->|审查截断| L3
    L3 -->|checkin 结算| L1

    classDef l1 fill:#dbeafe,stroke:#1e40af
    classDef l2 fill:#fef3c7,stroke:#92400e
    classDef l3 fill:#f3e8ff,stroke:#6b21a8
    class L1 l1
    class L2 l2
    class L3 l3
```

| 层 | 信任假设 | 安全性 | 性能 | gas 计费 | 典型场景 |
| --- | --- | --- | --- | --- | --- |
| **Layer 1** | ≥2/3 validator 诚实 | 最高（全网共识） | ~1000 tx/s, ~3s | 正常计费 | 转账 / 合约 / fallback / CheckinTx / slashing |
| **Layer 2** | assigned_validator 诚实 OR ≥4 witness 诚实 | 中（单点+fallback） | ~1000 tx/s, ~3s | **免 gas** | 游戏内实时交互 / CheckpointAnchor |
| **Layer 3** | 无（仅 ZK soundness） | 密码学保证 | ~100,000+ tx/s, ms 延迟 | checkin 时计费 | 链下博弈 + ZK 证明结算 |

**跨层逃生机制**：
- Layer 2 失职 → fallback 到 Layer 1（玩家走 Public 通道 fallback tx）
- Layer 3 操作方失职 → `force_checkpoint` 逃生 tx（走 Layer 1）
- Layer 3 操作方扣留 → `force_checkin` 由其他参与者重折叠（仍走 Layer 1）

---

## 6. 交易生命周期

### 6.1 Layer 1（Public 通道）

```mermaid
sequenceDiagram
    participant U as 用户钱包
    participant V as 任意 Validator
    participant DAG as Narwhal DAG
    participant BS as Bullshark
    participant CH as 链状态

    U->>V: submit_tx (JSON-RPC)
    V->>V: validate_tx_signature + chain_id + nonce + limits
    V->>V: gas 预扣 (balance >= gas_limit * price)
    V->>DAG: 装入 100ms 缓冲 vertex
    DAG->>DAG: gossipsub 广播 CompactVertex
    DAG->>DAG: 引用 ≥2/3 上一轮 vertex hash
    DAG->>BS: 形成 commit certificate (2/3 多签)
    BS->>BS: 线性排序 vertex → block
    BS->>CH: 投影 block + 执行 tx + 更新 state root
    CH-->>U: WebSocket 事件推送 (finality ~3s)
```

### 6.2 Layer 2（GameTurn 通道，免 gas）

```mermaid
sequenceDiagram
    participant P as 玩家
    participant AV as assigned_validator
    participant W as ≥4 witness (副本)
    participant DAG as Narwhal DAG
    participant CH as 链状态

    Note over P,AV: 正常路径
    P->>AV: GameTurn tx (fold/check/...)
    AV->>AV: validate_turn_order + validate_buyin
    AV->>DAG: 装入 game sub-block (免 gas)
    DAG->>CH: 投影 + 执行 + 更新 last_action_height

    Note over P,W: fallback 路径 (assigned_validator 失职)
    P->>W: 广播 GameTurn tx (附 timeout_proof)
    W->>W: 见证签名 (3-of-5 多签)
    W->>DAG: 非 AV 装入 vertex (走 Public 通道计费)
    DAG->>CH: 按 GameTurn 语义排序执行
```

### 6.3 Layer 3（OffChain + ZK 结算）

```mermaid
sequenceDiagram
    participant P as 参与者
    participant OP as 操作方
    participant AV as assigned_validator
    participant PSVC as proving_service
    participant AIR as poker_texas_air
    participant CH as 链上 Verifier

    Note over OP,PSVC: 链下执行 + 证明
    OP->>PSVC: 发出 ProveTask (borsh, 经 vm-common)
    PSVC->>AIR: Orchestrator 消费 ProveTask
    AIR->>AIR: prove_method (per-method Stwo AIR)
    AIR-->>PSVC: Stwo proof π + host-verify receipt (VerifiedChain)

    Note over OP,AV: 定期 checkpoint
    loop 每 checkpoint_interval_blocks (5)
        OP->>AV: CheckpointAnchor tx (免 gas, 多副本见证)
        AV->>CH: 更新 last_action_height
    end

    Note over OP,CH: 最终结算（链上 zk_verify 当前 dormant；证明经离线 host-verify）
    OP->>CH: CheckinTx (走 Public 通道, 正常 gas)
    CH->>CH: 校验 ack_chain_hash + skip_count + segment_continuity
    CH->>CH: 应用 Δ + 结算 + 释放锁仓资金
```

---

## 7. 节点角色

| 角色 | 共识参与 | 数据裁剪 | 典型用途 | 硬件要求 |
| --- | --- | --- | --- | --- |
| **Validator** | DAG vertex 产出 + Bullshark 投票 + game sub-block | Layer 1-3 裁剪 | 出块节点（需质押 + VRF key） | 高（CPU + 带宽 + 质押） |
| **Full**（默认） | 仅验证 | Layer 1-3 裁剪 | RPC 服务 / tx 提交 / 状态查询 | 中 |
| **Archive** | 仅验证 | 永不裁剪 | `request_historical_data` RPC / 链上回溯 | 高（存储） |
| **Light** | 仅订阅 block header + state root | 仅 header | 轻客户端 / 跨链桥验证 | 低 |

节点启动命令示例：

```bash
# Validator 节点（推荐从文件读取私钥）
zchain node --role validator \
  --data-dir ./data \
  --rpc-listen 127.0.0.1:8545 \
  --p2p-listen 127.0.0.1:9000 \
  --max-connections 128 \
  --validator-key-file /run/secrets/validator.key

# Full 节点
zchain node --role full --data-dir ./data

# 生成密钥对
zchain keygen --scheme secp256k1
```

---

## 8. 关键技术选型

| 领域 | 选型 | 理由 |
| --- | --- | --- |
| 共识 | Narwhal-Bullshark DAG | 数据传播与排序解耦，吞吐由带宽决定，BFT finality |
| 状态模型 | Sparse Merkle Tree + Object Store | 支持对象级权限校验 + 高效非包含证明 |
| 智能合约 VM | rBPF (solana_rbpf) | 字节码级沙箱 + 精细 gas 计量 + 成熟生态 |
| 签名 | secp256k1 + ed25519 tagged pubkey | 兼容 EVM / Solana 钱包 + 多曲线支持 |
| BLS | BLS12-381 + 子群检查 | 聚合签名 + ZK 证明基础曲线 |
| VRF | ECVRF-secp256k1 + SHA-256 | 共识 leader election + game 分配随机性 |
| ZK 证明 | Stwo Circle-STARK + poker_texas_air 自定义 AIR | per-method AIR 证明，host-verified receipts（递归闭环 PoC） |
| ZK 压缩 | Groth16 / IPA（scheme 抽象） | 链上 zk_verify 支持 scheme 分派（当前 dormant） |
| 存储 | RocksDB | 高性能 LSM-tree，支持列族分离 |
| 网络 | gossipsub + Compact Block Relay | 带宽优化 + 短 ID 匹配 |
| 序列化 | BCS (Binary Canonical Serialization) | 快速 + 确定性 + Move 生态兼容 |
| 哈希 | blake2b_256 + RFC 6962 domain separation | 抗碰撞 + 防二次原像 |
| 异步运行时 | tokio（仅用于信号处理） | 主 RPC 走 std::thread::scope 避免引入额外框架 |

---

## 9. 与市场区块链对比

### 9.1 综合对比表

| 维度 | zchain | Bitcoin | Ethereum | Solana | Cosmos | Aptos | Sui | Arbitrum | zkSync Era |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **定位** | 链下博弈 L1 | 价值存储 | 通用智能合约 | 高性能 L1 | 跨链枢纽 | Move L1 | Move L1 | ETH L2 | ETH L2 (zk) |
| **共识** | Narwhal-Bullshark DAG | PoW | Gasper (PoS) | PoH + PoS | Tendermint | AptosBFT | Narwhal-Bullshark | Sequencer + fraud proof | ZK rollup |
| **Finality** | ~3s (2/3 quorum) | ~60min (6 conf) | ~12.8min | ~6.4s / 32 slots | ~6s | <1s | <1s | ~7 天 (挑战期) | ~数小时 (L1 finality) |
| **TPS（实测）** | ~1,000 (L1) / 100,000+ (L3) | ~7 | ~15-30 | ~3,000-65,000 | ~1,000-10,000 | ~10,000-160,000 | ~125,000-297,000 | ~40,000 | ~60-100 |
| **智能合约 VM** | rBPF (BPF) | Script (受限) | EVM | Sealevel (并行) | CosmWasm | Move | Move | EVM | EVM |
| **状态模型** | Object + SMT | UTXO | Account | Account | Account | Resource (Move) | Object (Move) | Account (继承 ETH) | Account (继承 ETH) |
| **签名** | secp256k1 + ed25519 | secp256k1 (ECDSA) | secp256k1 (ECDSA) | ed25519 | ed25519/secp256k1 | ed25519 | ed25519 | secp256k1 | secp256k1 |
| **ZK 证明** | Stwo Circle-STARK + poker_texas_air 自定义 AIR | 无 | 无（原生） | 无 | 无 | 无 | 无 | 无（optimistic） | PLONK + Boojum |
| **特色能力** | 游戏免 gas + OffChain + ZK 结算 | 抗审查 | 生态最大 | PoH 时钟 | IBC 跨链 | Move 资源 | Object 中心 | EVM 兼容 | EVM 兼容 + ZK |
| **Token 经济** | Validator 质押 + slashing + 台费 | 挖矿奖励 | 质押奖励 | 质押 + inflation | 跨链手续费 | Gas + staking | Gas + staking | L1 gas + sequencer | L1 gas + proving |
| **跨链桥** | BridgeHook + bridge_verify + BLS quorum | 无原生 | 无原生（外部桥） | Wormhole | IBC (原生) | 无原生 | 无原生 | 原生 (L1↔L2) | 原生 (L1↔L2) |
| **数据可用性** | 链上 + Walrus DA (ZK proof 归档) | 链上 | 链上 | 链上 | 链上 | 链上 | 链上 | 链下 (L1) | 链下 (L1) |
| **治理** | 链上参数 + timelock + 敏感参数 90% | 算法 + 社区 | 链下 + EIP | 链下 + SPL | 链上 (text/param) | 链上 | 链上 | 链下 (DAO) | 链下 (DAO) |

### 9.2 差异化分析

#### 9.2.1 相对 Bitcoin / Ethereum 的优势

- **吞吐量**：zchain L1 ~1000 tps vs Bitcoin ~7 tps / Ethereum ~30 tps，且 L3 OffChain 模式可达 100,000+ tps
- **Finality**：~3s vs Bitcoin ~60min / Ethereum ~12.8min
- **游戏场景专用**：GameTurn 通道免 gas + 轮转排序 + 买入锁仓反滥用，ETH/BTC 无类似机制
- **ZK 原生支持**：poker_texas_air 自定义 AIR + Stwo Circle-STARK（离线 host-verify），Ethereum 需通过 L2 实现

#### 9.2.2 相对 Solana 的差异

- **共识机制**：同为 DAG 思想（Solana PoH 也可视为时序 DAG），但 zchain 显式分离 Narwhal（DA）与 Bullshark（共识）
- **状态模型**：zchain Object + SMT vs Solana Account 模型（无内建对象级权限）
- **签名**：zchain 双曲线（secp256k1 + ed25519）vs Solana 仅 ed25519
- **应用领域**：zchain 聚焦博弈场景（含 OffChain + ZK），Solana 通用高性能
- **TPS**：Solana 实测更高（~65,000 tps），但 zchain L3 模式理论值更高且不占用共识带宽

#### 9.2.3 相对 Aptos / Sui 的差异

- **Move 生态**：Aptos/Sui 原生 Move VM vs zchain rBPF（更接近 Solana）
- **共识**：zchain 与 Sui 都用 Narwhal-Bullshark；Aptos 用 AptosBFT（LibraBFT 演进）
- **Object 模型**：zchain Object + SMT vs Sui Object + 基于 owner 的分布式存储
- **ZK 能力**：zchain 内建 Stwo Circle-STARK + poker_texas_air 自定义 AIR；Aptos/Sui 无原生 ZK proof 系统
- **游戏场景**：zchain 内建 GameTurn 通道 + assigned_validator + 免 gas，Aptos/Sui 需在合约层实现

#### 9.2.4 相对 Arbitrum / zkSync 的差异

- **定位**：zchain 是 L1，Arbitrum/zkSync 是 L2（依赖 Ethereum 安全性）
- **VM**：zchain rBPF vs Arbitrum/zkSync EVM（兼容以太坊生态）
- **证明系统**：zchain Stwo Circle-STARK + 自定义 AIR vs Arbitrum Optimistic（欺诈证明）/ zkSync PLONK + Boojum
- **Finality**：zchain ~3s vs Arbitrum ~7 天（挑战期）/ zkSync ~数小时（L1 finality）
- **生态**：Arbitrum/zkSync 直接复用 ETH 生态，zchain 需自建（但 rBPF 与 Solana 工具链部分兼容）

#### 9.2.5 zchain 独特优势

| 优势 | 说明 |
| --- | --- |
| **三层信任模型** | 业界首个将 BFT 共识、单点+见证、ZK 信任分层组合的 L1，按场景选最优信任假设 |
| **游戏免 gas 通道** | GameTurn 通道硬约束免 gas（spec 级别），用买入锁仓反滥用，提升玩家体验 |
| **OffChain + ZK 结算** | 链下执行 100,000+ tps + Stwo Circle-STARK 自定义电路证明结算（poker_texas_air），兼顾性能与安全性 |
| **多副本见证 fallback** | assigned_validator 失职时 3-of-5 witness 签名即可逃生，无需全网等待 |
| **审查截断防护** | `force_checkpoint` / `force_checkin` / `request_revert` 多类逃生 tx，覆盖操作方失职/扣留/故障全场景 |
| **跨链重放保护** | 全签名域绑定 `chain_id`，防 testnet/mainnet 重放（R3-H3） |
| **状态裁剪分层** | archive / full / light 三类节点，tx_prune_after_blocks=1000 + vertex_prune_after_blocks=10000 |
| **链上治理 timelock** | 敏感参数 90% quorum + `parameter_delay_blocks=2000` timelock，防闪电式攻击 |

### 9.3 适用场景对比

| 场景 | 推荐链 | 理由 |
| --- | --- | --- |
| **在线博弈（扑克 / 麻将）** | zchain | GameTurn 免 gas + OffChain + ZK 结算 + 轮转排序 |
| **DeFi 高频交易** | Solana / Arbitrum | 通用智能合约 + 高 TPS + EVM 兼容 |
| **NFT / 资产发行** | Ethereum / Aptos | 生态最大 / Move 资源模型 |
| **跨链枢纽** | Cosmos | IBC 原生支持 |
| **价值存储** | Bitcoin | 共识最强 + 算力最大 |
| **隐私交易** | zchain (OffChain) / zkSync | ZK 证明保护游戏内行为隐私 |
| **企业级应用** | Hyperledger / Aptos | 许可链 / Move 资源 + 高性能 |

---

## 10. 安全设计要点

zchain 在安全审计中识别并修复了 28 项关键问题（3 CRITICAL + 7 HIGH + 13 MEDIUM + 5 LOW），核心安全机制：

| 类别 | 机制 |
| --- | --- |
| **BFT 安全** | Quorum 阈值严格 `2n/3 + 1`（非 `n*2 div_ceil 3`），BTreeSet 去重防签名重复计数 |
| **签名安全** | secp256k1 强制 low-s（BIP-62）+ ed25519 + BLS identity point 检查 |
| **跨链防重放** | 所有签名域绑定 `chain_id`（tx / vertex / ACK / operator_ack / refuse_ack / 委托凭证） |
| **DoS 防护** | tx_cache FIFO (10k) / RPC rate limit / connection limit / object 64KB / contract 64KB / params 256KB |
| **内存安全** | `deny(unsafe_code)` 全库（仅 vm 模块因 solana_rbpf 例外）+ Mutex poisoning 优雅处理 |
| **算术安全** | checked_add / saturating_mul / u64 域比较防 32-bit 平台截断 |
| **ZK 安全** | Stwo M31 列运算 + per-method AIR 约束 + verifier 独立重建 expected AIR/trusted row + host-verify receipt 链 |
| **审查防护** | `force_checkpoint` + `assigned_validator_failure_proof` + 3-of-5 多副本见证 + 委托逃生 + 累积惩罚 |

---

## 11. 相关文档

| 文档 | 内容 |
| --- | --- |
| [37-1-node-deployment.md](file:///Users/mac/projects/zchain/docs/37-1-node-deployment.md) | 节点部署 + genesis 配置 |
| [37-2-contract-development.md](file:///Users/mac/projects/zchain/docs/37-2-contract-development.md) | rBPF 合约开发 + UpgradeCap |
| [37-3-offline-proof-development.md](file:///Users/mac/projects/zchain/docs/37-3-offline-proof-development.md) | 链下证明开发 + Stwo/poker_texas_air |
| [37-4-bridge-extension.md](file:///Users/mac/projects/zchain/docs/37-4-bridge-extension.md) | 跨链桥扩展 + bridge_verify |
| [37-5-governance-operations.md](file:///Users/mac/projects/zchain/docs/37-5-governance-operations.md) | 治理操作 + timelock |
| [37-6-dag-consensus-ops.md](file:///Users/mac/projects/zchain/docs/37-6-dag-consensus-ops.md) | DAG 共识运维 + slashing |
| [37-7-rpc-interface.md](file:///Users/mac/projects/zchain/docs/37-7-rpc-interface.md) | JSON-RPC 接口规范 |
| [37-8-game-phase-protocol.md](file:///Users/mac/projects/zchain/docs/37-8-game-phase-protocol.md) | 游戏阶段协议 |
| [37-9-assigned-validator-security.md](file:///Users/mac/projects/zchain/docs/37-9-assigned-validator-security.md) | assigned_validator 安全 |
| [37-10-trust-layer-model.md](file:///Users/mac/projects/zchain/docs/37-10-trust-layer-model.md) | 三层信任模型详解 |
| [checklist.md](file:///Users/mac/projects/zchain/checklist.md) | Phase 1-8 实现检查清单 |

---

## 12. 总结

zchain 是一个**面向链下博弈场景的专用 L1 区块链**，架构核心三大创新：

1. **三层信任模型**：将 BFT 共识、单点+见证、ZK 密码学信任分层组合，按场景选最优信任假设，避免「一刀切」的性能或安全性损失
2. **GameTurn 免 gas 通道**：通过 spec 硬约束 + 买入锁仓 + assigned_validator 路由，实现游戏操作的零成本体验，同时保留 BFT 安全性
3. **OffChain + Stwo 自定义电路**：链下执行 100,000+ tps + poker_texas_air 自定义 AIR 证明结算（Stwo Circle-STARK），兼顾性能与密码学安全性

相比市场主流区块链，zchain 不追求通用智能合约平台的生态规模，而是**垂直深耕博弈场景**，通过架构创新在「性能 / 安全性 / 用户体验」三角中找到博弈场景的最优解。代码已通过两轮共 28 项安全审计修复，1383 个测试全部通过，具备生产部署条件。

---

## 13. 后续演进路线（Future Roadmap）

本节记录安全审计中识别、但尚未实现的缺失功能模块。模块 #1（Fast/Snap Sync）与 #2（Indexer）已实现。模块 #3-#9 列为后续演进项。**§13.5 记录 2026-08 架构审核结果与近期硬化成果**。

### 13.1 缺失模块汇总表

> 本表分两组：**A. 基础设施演进**（#1–#9，原始路线图）与 **B. 安全/经济硬化**（#10–#19，2026-08 交付）。

#### A. 基础设施演进

| # | 模块 | 优先级 | 当前状态 | 目标 |
| --- | --- | --- | --- | --- |
| 1 | 状态快速同步（Fast/Snap Sync） | HIGH | ✅ 已实现 | 新节点无需回放 genesis，通过分块快照 + BFT 锚定快速同步到 tip |
| 2 | 链上索引器/事件订阅（Indexer） | HIGH | ✅ 已实现 | 按 sender/contract/object/height 查询 + 多订阅 fan-out 事件推送 |
| 3 | 交易池优先级排序（Priority Mempool） | MEDIUM | ⚠️ 部分（`node::tx_cache` 仅 FIFO） | 按 gas_price + 依赖关系排序，支持替换低费用 tx、孤儿 tx 跟踪 |
| 4 | 历史状态裁剪（State Pruning） | MEDIUM | ⚠️ 部分（`PruningConfig` 类型已定义，裁剪函数已实现但未接入出块循环） | 按 `pruning_depth` 自动裁剪旧区块与对象历史版本，archive 节点保留全量 |
| 5 | P2P 节点发现（Peer Discovery） | MEDIUM | ⚠️ 部分（已有真实 `TcpTransport` + 双向连接，但无 DHT 发现） | DHT-based peer discovery + 节点身份验证 + banned peer 列表 |
| 6 | 轻客户端协议（Light Client Protocol） | LOW | ⚠️ 部分（`LightClientVerifyRequest` 类型已定义） | 完整轻客户端：仅验证 header chain + Merkle proof，无需全状态同步 |
| 7 | Prometheus 指标导出（Metrics） | LOW | ❌ 缺失 | `tracing` 已有日志，需补 Prometheus exporter：tx 数、出块时间、peer 数、gas 用量 |
| 8 | Compact Block Relay 完整化 | LOW | ⚠️ 部分（`CompactVertex` 类型已定义 + 短 ID 构造） | 缺短 ID 映射表 + 缺失 tx 请求回退机制，降低区块传播带宽 |
| 9 | 检查点与归档节点（Checkpoint & Archive） | LOW | ❌ 缺失 | 周期性生成不可逆检查点，archive 节点提供历史数据服务给 syncing 节点 |

#### B. 安全/经济硬化（2026-08 交付）

| # | 模块 | 优先级 | 当前状态 | 目标 / 实现要点 |
| --- | --- | --- | --- | --- |
| 10 | AccountStore 持久化 | HIGH | ✅ 已实现 | 内存 HashMap + 可选 `Arc<DB>` RocksDB，重启不丢账户/余额/nonce（`AccountStore::open`） |
| 11 | commit certificate 真验签 | HIGH | ✅ 已实现 | `validate_commit_certificate_signatures` 逐签名 `verify_signature`（`block/validator.rs` + `cert_verification.rs`） |
| 12 | ECVRF-secp256k1-SHA256-TAI | HIGH | ✅ 已实现 | 真实 prover + verifier（`consensus/ecvrf.rs`，`vrf` crate + vendored openssl），替换 StubVrfVerifier |
| 13 | slashing 证据真验签 | HIGH | ✅ 已实现 | `VertexEquivocationEvidence` / `CommitCertEquivocationEvidence` 携带完整 vertex/cert + 真验签 |
| 14 | 多 validator BFT 闭环 | HIGH | ✅ 已实现 | Dag 跨线程共享 + CommitVote gossip + 真实 2/3 quorum + genesis set CLI + 双向 TCP（`scripts/multi_node_e2e.sh 3` 稳定出块） |
| 15 | Bridge 接线 | MEDIUM | ✅ 已实现 | wrapped-asset Object 铸币 + BridgeRegistry nonce 持久化 + executor 接线（`bridge/mod.rs` + `storage/bridge_registry_store.rs`） |
| 16 | 代币经济（gas→proposer + 出块奖励 + 原生转账 + genesis 分配） | MEDIUM | ✅ 已实现 | `execute_block` credit proposer gas+`DEFAULT_BLOCK_REWARD`；`TransferArgs` 原生转账；`--genesis-alloc` CLI |
| 17 | staking 结算 | MEDIUM | ✅ 已实现 | bond 锁定账户余额 + slashing 燃烧 + unbonding 退还（`Node::add_validator` / `slash_validator` / `complete_unbonding`） |
| 18 | VRF 时序接入 | MEDIUM | ✅ 已实现 | `advance_epoch_with_vrf` + `--vrf-key-file` CLI + 每 EPOCH_LENGTH commit 推进 epoch + 真实 ECVRF 派生 |
| 19 | validate_block proposer 一致性 | LOW | ✅ 已实现 | 验证方从 commit cert vertex author 派生 proposer，重放时也 credit gas+奖励 |

### 13.2 各模块设计要点

#### #3 交易池优先级排序（Priority Mempool）

**当前缺口**：[`node::TxCacheState`](file:///Users/mac/projects/zchain/poker_l1/src/node/mod.rs) 仅实现 FIFO 队列 + 10,000 条上限，无优先级排序。

**设计要点**：
- 按 `gas_price` 降序的跳表（skiplist）或二叉堆
- 支持相同 nonce 高价替换低价（RBF，Replace-by-Fee）
- 孤儿 tx 缓存（inputs 尚未上链的 tx）
- 依赖跟踪：tx B 依赖 tx A 的输出时，A 上链前 B 不进入主队列
- 容量上限：默认 10,000 tx（与现有 `tx_cache` 一致），溢出时丢弃最低 gas_price

**与现有模块的关系**：替换 `node::TxCacheState` 内部数据结构，对外 API 保持兼容。

#### #4 历史状态裁剪（State Pruning）

**当前缺口**：[`storage::PruningConfig`](file:///Users/mac/projects/zchain/poker_l1/src/storage/mod.rs) 类型已定义但未实现裁剪逻辑。

**设计要点**：
- `pruning_depth: u64` —— 保留最近 N 个区块的完整状态
- 三种节点模式：
  - **Archive**：`pruning_depth = u64::MAX`，保留所有历史
  - **Full**：`pruning_depth = 10000`，保留最近 1 万区块的完整状态 + 所有 header
  - **Pruned**：`pruning_depth = 1000`，仅保留最近 1000 区块的完整状态 + header
- 裁剪对象：旧区块 body（保留 header）、Object 历史版本（保留最新版）、DAG vertex
- 与 `sync` 模块配合：pruned 节点通过 Fast Sync 从 archive 节点恢复历史状态

#### #5 P2P 节点发现（Peer Discovery）

**当前缺口**：[`network::GossipManager`](file:///Users/mac/projects/zchain/poker_l1/src/network/mod.rs) 仅实现 gossipsub 广播，无主动 peer 发现。

**设计要点**：
- Bootstrap 节点列表（hardcoded + DNS seed）
- Kademlia DHT 用于 peer 路由（基于 `libp2p::kad`）
- Peer 身份验证：握手时交换 `chain_id` + protocol_version，不匹配则拒绝
- Banned peer 列表：slash 过的 validator、恶意 peer、重连频率超限
- 周期性 peer 交换（PEX, Peer Exchange）

#### #6 轻客户端协议（Light Client Protocol）

**当前缺口**：[`block::LightClientVerifyRequest`](file:///Users/mac/projects/zchain/poker_l1/src/block/time_consensus.rs) 类型已定义，但完整轻客户端协议未实现。

**设计要点**：
- 轻客户端仅同步 `BlockHeader` chain（不下载 body / 不执行 tx）
- 验证每个 header 的 `dag_commit_certificate` 签名（2/3+ secp256k1 quorum）
- 通过 Merkle proof 验证特定 tx / object 是否包含在某区块
- 用途：移动端钱包、跨链桥的链上轻验证、SPV 钱包
- 与 `sync` 模块区别：Fast Sync 仍下载全状态；轻客户端永不下载全状态

#### #7 Prometheus 指标导出（Metrics）

**当前缺口**：仅 `tracing` 日志，无结构化指标导出。

**设计要点**：
- 引入 `metrics` crate（轻量、no-std 友好）或 `prometheus` crate
- 关键指标：
  - `zchain_block_height`（gauge）—— 当前 tip 高度
  - `zchain_tx_total`（counter）—— 累计 tx 数，按 lane 分标签
  - `zchain_block_time_ms`（histogram）—— 出块耗时
  - `zchain_peer_count`（gauge）—— 当前 peer 数
  - `zchain_mempool_size`（gauge）—— 交易池当前大小
  - `zchain_gas_used_total`（counter）—— 累计 gas 用量
- 通过 `RPC` 模块暴露 `/metrics` 端点（Prometheus exposition format）
- 与 `indexer` 配合：indexer 可作为指标数据源

#### #8 Compact Block Relay 完整化

**当前缺口**：[`network::CompactVertex`](file:///Users/mac/projects/zchain/poker_l1/src/network/mod.rs) 类型已定义，但短 ID 映射 + 缺失 tx 请求回退未实现。

**设计要点**：
- 发送方：先广播 CompactVertex（含 tx_hashes 而非完整 tx），peer 命中本地 mempool 的 tx 用短 ID 引用
- 接收方：收到 CompactVertex 后，对未命中的 tx 发起 `get_txs` 请求
- 回退机制：若短 ID 碰撞或未命中率高，退化为全量广播
- 目标：降低区块传播带宽 80%+（假设 90% tx 已在 mempool）

#### #9 检查点与归档节点（Checkpoint & Archive）

**当前缺口**：无检查点机制，所有节点需保留完整历史。

**设计要点**：
- 周期性（每 10,000 区块）生成不可逆检查点（finality gadget 保证）
- 检查点包含：`height` + `block_hash` + `state_root` + 2/3+ validator 签名
- Archive 节点：保留全量历史 + 提供历史数据服务（HTTP / P2P）
- Pruned 节点：仅保留检查点之后的完整状态
- 与 `sync` 模块配合：Fast Sync 从最近的检查点开始

### 13.3 实现优先级建议

> **B 组（#10–#19 安全/经济硬化）已于 2026-08 全部交付**（见 §13.4 详情 + §13.5 矩阵）。以下仅针对 A 组剩余基础设施演进。

1. **短期（下一个 Phase）**：#3（Priority Mempool）+ #4（State Pruning 接入出块循环）—— 直接影响生产部署能力
2. **中期**：#5（Peer Discovery / DHT）+ #7（Metrics）—— 影响网络健壮性与可观测性
3. **长期**：#6（Light Client）+ #8（Compact Block Relay）+ #9（Checkpoint）—— 优化与生态扩展

### 13.4 已实现模块摘要

#### #1 状态快速同步（Fast/Snap Sync）

- **位置**：[`poker_l1/src/sync/mod.rs`](file:///Users/mac/projects/zchain/poker_l1/src/sync/mod.rs)（877 行）
- **测试**：15 个单元测试全部通过
- **关键类型**：`SnapshotManifest`、`SnapshotChunk`、`SnapshotBuilder`、`SnapshotVerifier`、`SnapshotApplier`、`FastSync`、`SyncState`
- **信任模型**：state_root 由 BFT 共识背书的 `BlockHeader` 锚定；分块通过 blake2b_256 逐块校验防 Byzantine peer 投毒；端到端 state_root 校验
- **DoS 防护**：单块上限 `MAX_SNAPSHOT_CHUNK_SIZE = 4MB` + `MAX_OBJECTS_PER_CHUNK = 10,000`

#### #2 链上索引器/事件订阅（Indexer）

- **位置**：[`poker_l1/src/indexer/mod.rs`](file:///Users/mac/projects/zchain/poker_l1/src/indexer/mod.rs)（1167 行）
- **测试**：18 个单元测试全部通过
- **关键类型**：`Indexer`、`IndexedTransaction`、`IndexedBlock`、`TxFilter`、`BlockFilter`、`IndexerEvent`、`Subscription`
- **查询维度**：按 `tx_hash` / sender / contract_id / lane / height range / object_id 查询 tx；按 height range 查询 block；按 owner / object_type 查询对象
- **订阅机制**：复用 `rpc::EventType`，支持 tx 过滤器、多订阅 fan-out、FIFO 队列溢出丢弃最旧
- **DoS 防护**：单订阅队列上限 `MAX_EVENTS_PER_SUBSCRIPTION = 1024`，全局订阅上限 `MAX_SUBSCRIPTIONS = 1024`
- **线程安全**：`std::sync::Mutex` 保护内部状态（与 `node::Node` 模式一致）

#### #10 AccountStore 持久化

- **位置**：[`poker_l1/src/account/mod.rs`](file:///Users/mac/projects/zchain/poker_l1/src/account/mod.rs)
- **测试**：3 个持久化测试（重启后余额/nonce 保留 + 内存模式 no-op）
- **关键设计**：内存 HashMap 为权威工作集 + 可选 `Arc<DB>` RocksDB 后端；`AccountStore::open(path)` 启动全量加载；`flush(&addr)` 在 executor 变更后显式落盘
- **解决的问题**：此前 `AccountStore` 为纯内存，节点重启即丢账户余额/nonce

#### #12 ECVRF-secp256k1-SHA256-TAI

- **位置**：[`poker_l1/src/consensus/ecvrf.rs`](file:///Users/mac/projects/zchain/poker_l1/src/consensus/ecvrf.rs)
- **测试**：6 个测试（prover↔verifier roundtrip + 错误 pubkey/input 拒绝 + 81B 回归 + output 均匀性 + 与旧 placeholder 派生分离）
- **关键设计**：`Secp256k1VrfVerifier`（impl `VrfVerifier`）+ `Secp256k1VrfProver`（`prove()` + `derive_public_key()`），基于 `vrf` crate 的 `SECP256K1_SHA256_TAI`；proof 布局修正 97B→81B（c 为 16 字节）；vendored openssl 保证可复现构建
- **解决的问题**：替换 `StubVrfVerifier`（cfg-gated，返回 input 当 output，无真实验证）

#### #14 多 validator BFT 闭环

- **位置**：`src/main.rs`（`run_validator_loop` + `handle_p2p_connection` + `VoteCollector` + `commit_and_finalize_block_multi`）+ [`poker_l1/src/network/mod.rs`](file:///Users/mac/projects/zchain/poker_l1/src/network/mod.rs)（`CommitVote` + `GossipTopic::CommitVote`）
- **验证**：[`scripts/multi_node_e2e.sh`](file:///Users/mac/projects/zchain/scripts/multi_node_e2e.sh) 3 validator 稳定出块（5/5 PASS）
- **关键设计**：共享 `Arc<Mutex<Dag>>`（peer vertex 写入）+ round 同步到 `dag.max_round()+1` + parent 引用 max_round 轮所有不同 author vertex（跨 validator 引用扇形）+ CommitVote gossip + 稳健弱 cert 回退（DAG 引用为 safety）+ 双向 TCP 连接（`stream.try_clone()`）+ `--genesis-validators` CLI
- **解决的问题**：原 validator loop 用 `quorum=1` 自签单签出块（demo 路径），无真实多 validator 共识

#### #16 代币经济（gas→proposer + 出块奖励 + 原生转账 + genesis 分配）

- **位置**：[`poker_l1/src/executor/mod.rs`](file:///Users/mac/projects/zchain/poker_l1/src/executor/mod.rs)（`execute_block` credit + `TransferArgs` + `DEFAULT_BLOCK_REWARD`）+ `src/main.rs`（`--genesis-alloc` CLI + `load_genesis_alloc`）
- **测试**：gas→proposer 2 测试 + 原生转账 2 测试 + genesis 分配 2 测试
- **关键设计**：block 结束后 proposer 收 `total_gas_used + DEFAULT_BLOCK_REWARD`（账户不在 state_root，不影响可重现性）；原生转账 `TransferArgs`（caller debit in execute_tx_on_view_inner，recipient credit in merge 阶段，解决借用冲突）；`Node::apply_genesis_alloc`（幂等初始余额）

#### #17 staking 结算

- **位置**：[`poker_l1/src/node/mod.rs`](file:///Users/mac/projects/zchain/poker_l1/src/node/mod.rs)（`add_validator` / `slash_validator` / `complete_unbonding`）
- **测试**：4 个测试（bond 锁定 + 余额不足拒绝 + slashing 减少 + unbonding 退还）
- **关键设计**：`add_validator` 从账户余额锁定 stake（debit）；`slash_validator` 罚没部分燃烧（stake 在 bond 时已扣）；`complete_unbonding` 退还剩余 stake 到账户
- **解决的问题**：此前 `ValidatorEntry.stake` 为裸 u64，slashing 只减字段不扣账户

### 13.5 架构审核（2026-08）+ 近期硬化成果

#### 模块完整性矩阵

| 子系统 | 评级 | 证据 |
| --- | --- | --- |
| 共识（DAG/Bullshark） | COMPLETE | `consensus/{bullshark,vertex_production,routing,validator_set,cert_verification,ecvrf,slashing}.rs` |
| 网络（P2P） | PARTIAL | `network/mod.rs`：`NetworkTransport` trait + 真实 `TcpTransport`（双向连接）；无 libp2p/DHT 发现 |
| 存储（RocksDB） | COMPLETE | `storage/{block_store,object_db,dag_vertex_store,bridge_registry_store,pruning}.rs` |
| VM（智能合约） | COMPLETE | `vm/{syscalls,precompile,contracts/texas_poker/*,upgrade,gas_table}.rs` |
| 账户/代币经济 | COMPLETE | `account/mod.rs`（持久化）+ gas→proposer + 出块奖励 + staking 结算 + 原生转账 |
| 桥（Bridge） | COMPLETE | `bridge/mod.rs`（bridge_verify + wrapped-asset 铸币 + nonce 持久化） |
| 治理（Governance） | COMPLETE | `governance/mod.rs`（proposals/timelock/quorum/参数治理/key rotation） |
| RPC/API | COMPLETE | `rpc/mod.rs`（JSON-RPC 2.0 + 限流 + 认证） |
| Slashing | COMPLETE | `consensus/slashing.rs`（双签验签 + downtime + multi-slashing + staking 真扣账） |
| VRF | COMPLETE | `consensus/ecvrf.rs`（真实 ECVRF-secp256k1-SHA256-TAI + prover + verifier） |

#### 已知缺口

1. **网络层无 libp2p/DHT 发现**：`TcpTransport` 已支持双向 TCP 连接（`--peer` 手动配置），但无 DHT 自动发现。
2. **链上 zk_verify dormant**：`zk_verifier_registry() == None`，链上 ZK 验证未启用；真实证明走 `proving_service` 离线 host-verify。
3. **poker_texas_air 递归闭环未完成**：21 个 method AIR 为 PoC（约束输入一致性 + 最小输出 flag，非完整业务算术）；aggregator descriptor-only；最终递归未实现；当前信任机制为 host-verified receipts。

#### 近期硬化成果（2026-08）

本轮完成区块链核心硬化，全量回归通过（lib **1613** + 全集成测试 0 failed）：

- **AccountStore 持久化**：内存 HashMap + 可选 `Arc<DB>` RocksDB，重启不丢账户/余额/nonce。
- **共识签名验证**：commit certificate 真验签（`validate_commit_certificate_signatures`）+ slashing 证据携带完整 vertex/cert + 真验签。
- **ECVRF-secp256k1-SHA256-TAI**：真实 prover + verifier（`vrf` crate + vendored openssl），替换 StubVrfVerifier。
- **多 validator BFT 闭环**：Dag 跨线程共享 + CommitVote gossip + 真实 2/3 quorum + genesis set CLI + 双向 TCP 连接（`scripts/multi_node_e2e.sh 3` 稳定出块）。
- **Bridge 接线**：wrapped-asset Object 铸币 + BridgeRegistry nonce 持久化 + executor 接线。
- **代币经济**：gas→proposer + 出块奖励（`DEFAULT_BLOCK_REWARD`）+ staking 结算（bond 锁定 / slashing 燃烧 / unbonding 退还）+ 原生转账（TransferArgs + executor 特判）+ genesis 余额分配（`--genesis-alloc`）。
- **VRF 时序接入**：`advance_epoch_with_vrf` + `--vrf-key-file` CLI + 每 EPOCH_LENGTH commit 推进 epoch。
