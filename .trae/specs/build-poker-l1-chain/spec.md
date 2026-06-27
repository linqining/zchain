# Poker L1 区块链 Spec

## Why

当前 zgame 将扑克逻辑放在 Sui L1 上，受 Sui 共识、Gas、对象模型约束，无法实现"按玩家轮次排序交易""买入后离线折叠证明"等扑克原生特性。基于 `poker_protocol` 自建一条 L1，可把扑克语义下沉到共识层与对象层，让交易排序、并发颗粒度、密码学原语、链下证明全部为扑克量身定制，从而获得更高并发、更低延迟、更强隐私与可验证性。

## What Changes

* **新增** `poker_l1/` 工作空间成员：一条独立 L1 区块链节点实现（Rust）

* **新增** 双模式排序共识：

  * **结算层公共排序**：对所有通用交易采用 Sui/Solana 式排序（按 gas price / 到达顺序 / FIFO）

  * **游戏轮转排序**：对作用于活跃 Game 对象的交易施加轮转约束（按 `current_turn` 排序）

  * 两条通道共存于同一 DAG vertex，vertex 内 GameTurn tx 优先于 force\_sync tx 处理

* **新增** Narwhal-Bullshark DAG 共识：数据平面（Narwhal-style DAG vertex 传播）+ 共识平面（Bullshark 排序）；无 mempool、无 leader 瓶颈、validator 失败不丢 tx

* **新增** 游戏分配与分布式 Game Sub-Block：per-game assigned\_validator + epoch 自动重分配 + DAG 自动失败转移

* **新增** 时间共识与超时：block header 含权威 `timestamp_ms`（单调不减 + 最大间隔约束）与 `height`（严格单调递增）；所有超时截止以 block height 为准

* **新增** 游戏交易免 Gas + 台费结算：GameTurn 通道游戏操作免 gas，结算时收台费；每玩家活跃 Game 数量上限反垃圾

* **新增** Sui 风格对象模型：每一局为独立对象，结算后冻结为 Immutable

* **新增** 账户抽象与交易安全：tagged pubkey 地址派生 + account nonce + chain\_id 重放保护

* **新增** rBPF 合约 VM：Rust 编译为 BPF，含 gas 计费表 + 合约升级机制（UpgradeCap）

* **新增** 多曲线钱包签名：secp256k1 + ed25519，tagged pubkey 统一路由

* **新增** BLS12-381 原生预编译：G1/G2/Pairing/Hash-to-curve，强制子群检查 + worst-case gas 计费

* **新增** 可插拔 ZK 证明验证模块：Hypernova / Groth16 / IPA

* **新增** 游戏执行模式：合约可选 OnChain（默认）/ OffChain（可选）

* **新增** 链下执行通信协议：checkpoint anchor + 多方签名 ack，解决 force\_advance 判定与合谋防护

* **新增** 链下执行 + ZK 折叠 + 强制同步：6 类争议场景，challenge\_delta 语义澄清

* **新增** 状态裁剪与存储管理：结算后历史版本可裁剪，保留 state root commitment

* **新增** 治理与参数管理：validator 超多数投票链上参数调整

* **新增** 网络层约束：DAG vertex 容量上限 + block/tx 大小上限 + Compact Block Relay

* **新增** 跨链桥模块（预留）：含安全约束（burn-on-source + nonce 防重放）

* **复用** `poker_protocol::crypto::Bls12381Curve` (blstrs) 作为 BLS12-381 预编译底座（仅用于 ZK 证明验证，非共识签名）

* **复用** `poker_protocol::zk_shuffle` 中的证明系统作为链下折叠的输入电路之一

* **BREAKING** 不再依赖 Sui RPC / Move 合约作为真理之源；poker\_l1 自身成为真理之源

* **BREAKING** 不再使用 PoA + leader rotation 单 leader 出块模型；改为 Narwhal-Bullshark DAG 共识

* **BREAKING** validator 共识签名不再使用 BLS12-381；改为 secp256k1（通用、硬件钱包支持）；DagCommitCertificate 采用 signer\_bitmap + signature\_list 多签；BLS12-381 仅保留用于 ZK 证明验证预编译

## Impact

* Affected specs: 无既有 L1 spec，本 spec 为新建

* Affected code:

  * 新增 `poker_l1/` 整个 crate（consensus/dag / object\_model / vm / crypto\_precompiles / account / offline / network / bridge / governance / node）

  * 只读依赖 `poker_protocol/` 的 crypto 与 zk\_shuffle 模块

  * 根 `Cargo.toml` 增加 workspace 成员

  * 后期（非本 spec 范围）`texas/src/relayer/` 可接入 poker\_l1 节点替换 sui\_query

## ADDED Requirements

### Requirement: Narwhal-Bullshark DAG 共识 (Narwhal-Bullshark DAG Consensus)（S1 重构）

The system SHALL use a Narwhal-Bullshark style DAG consensus: a data plane where each validator broadcasts signed vertices containing tx batches, AND a consensus plane (Bullshark) that orders committed DAG vertices into a linear chain. There SHALL be no mempool and no single-leader block production bottleneck. Each validator SHALL independently produce vertices; validator failure SHALL NOT cause tx loss (DAG redundancy). Slashing SHALL penalize vertex equivocation and downtime.

#### Scenario: Validator 集与 PoA 准入

* **WHEN** 链启动

* **THEN** validator 集 V = {v0, v1, ..., vn}（genesis 定义，可通过治理更新，**SEC-C2 修复 — 治理提案校验 `new_validator_set_size >= 5`，拒绝将 validator 集缩减至 < 5 的提案**（原 R5-L7 的 >= 3 在 3-of-3 合谋即可控制共识，已提升至 5）；**SEC-M2 修复 — 单次缩减比例 <= 20%**）；每个 validator 有 secp256k1 签名密钥（通用、硬件钱包支持）+ 质押保证金；非 validator 节点可作 full node 同步但不参与共识；**NEW-L3 修复**：新 validator 需经历 `bonding_period_blocks`（默认 = 1 epoch = `epoch_length_blocks`）锁定期，期间可同步链状态但不参与共识出块；**R5-H7 修正 — validator 退出 unbonding 期**：`unbonding_period_blocks`（默认 = 2 × `epoch_length_blocks`）退出锁定期，期间不参与共识但质押仍可被 slashing，防 equivocation 后立即退出逃避 slashing；unbonding 期结束无 slashing 证据 → 质押可提取；**R5-L5 修正 — validator 密钥轮换**：`rotate_validator_key` tx（旧密钥签名 `hash(chain_id || old_pubkey || new_pubkey || block_height)` + 新密钥确认），有 `key_rotation_delay_blocks` timelock，期间旧密钥仍可用于 slashing 证据；**SEC2-H4 修复 — rotate_validator_key timelock 期间密钥使用约束**：(1) 旧密钥仅可用于 slashing 证据验证，不可用于签名新 vertex；(2) validator 提交 rotate_validator_key tx 后，gossipsub 认证立即拒绝旧密钥签名的 vertex（validator 须用新密钥签名 vertex，但新密钥在 timelock 期间不参与 consensus quorum 计算）；(3) timelock 期间 validator 处于过渡状态，可签名 vertex 但不计入 2/3 quorum（防旧密钥泄露作恶 + 新密钥未充分确认）；(4) timelock 结束后新密钥正式加入 quorum 计算；(5) 新增密钥泄露申辩 path：validator 可提交 `key_compromise_proof`（含密钥泄露证据 + 新密钥签名）触发紧急密钥轮换，绕过 timelock（须 90% validator quorum 确认）；**SEC-M1 修复 — 停机自动 slashing 路径**：连续 `downtime_threshold_blocks + 2 * epoch_length_blocks` 未提交任何 vertex → 自动 slashing `downtime_slash_percentage`（无需治理介入），治理仅用于争议申辩（validator 申辩网络故障）

#### Scenario: DAG 数据平面（Narwhal-style）

* **WHEN** validator 收到客户端 tx 或其他 validator 的 vertex

* **THEN** validator 把 tx 批量打包为 vertex（含 tx list + 引用 ≥2/3 validator 的上一轮 vertex hash + 自身 secp256k1 签名）；**R4-H7 修正 — vertex 签名对象**：`hash(chain_id || epoch || round || author_pubkey || vertex_hash || parent_hashes)`（**SEC-C1 修复 — 增加 `epoch` 与 `author_pubkey` 字段**：绑定 chain_id 防跨链重放；绑定 epoch 防 epoch 边界 equivocation 证据歧义（round 跨 epoch 全局递增，无 epoch 字段则无法判定 vertex 属于哪个 epoch 的 validator 集）；绑定 author_pubkey 使 slashing 证据归属判定不依赖 ECDSA recovery 反推，支持多 key 钱包与 signer_bitmap 绑定）；通过 gossipsub 广播给所有 validator（**R4-L3 修正 — gossipsub Sybil 攻击防护**：validator-only topic 仅接受已认证 peer 加入 — 每个连接需完成 libp2p identify 握手并出示 validator secp256k1 公钥签名（签名对象 `hash(chain_id || peer_id || timestamp)`），节点校验 pubkey 在当前 ValidatorSet 中方可加入并发布；非 validator 全节点可订阅只读但不能发布；防 Sybil 节点灌入垃圾 vertex）（**R5-M1 修正 — epoch 边界 gossipsub grace period**：±`epoch_transition_window_blocks` 内 gossipsub 认证同时接受旧集与新集 validator pubkey，防节点未同步 epoch 边界 block 时拒绝新 validator）（**SEC2-M2 修复 — gossipsub grace period 共识层约束**：(1) gossipsub grace period 仅允许网络层认证容忍（防拒绝新 validator 的 vertex），不改变共识层 vertex 有效性；(2) grace period 内，退出 validator（不在新 epoch validator 集中）签名的 vertex 被共识层拒绝（不计入 commit certificate 的 2/3 quorum）；(3) grace period 内，退出 validator 若进行 equivocation，仍按 vertex equivocation slashing 处理（unbonding 期间质押可被 slashing）；(4) grace period 内，退出 validator 的 vertex 若被误引用进 commit，节点须在 finality 前剔除（commit certificate 验证须校验所有签名 validator 在该 epoch 的 validator 集中））；vertex 上限 `max_vertex_size`（默认 256KB），超出分多个 vertex；无需 mempool，tx 在 vertex 中即被冗余传播

#### Scenario: Bullshark 共识平面

* **WHEN** DAG 中存在足够多的 vertex 形成 commit certificate（某轮 vertex 获得 ≥2/3 validator 引用）

* **THEN** Bullshark 算法对 DAG 中的 vertex 进行线性排序，产出 block 序列；block 不需要单独 production，而是 DAG commit 的投影；**NEW-M14 修复**：block header 含 `height`、`timestamp_ms`、`prev_hash`、`state_root`、`public_tx_root`（Public 通道 tx 的 Merkle root）、`gameturn_tx_root`（GameTurn + CheckpointAnchor 通道 tx 的 Merkle root）、`dag_commit_certificate`，拆分为两个独立 tx_root 以支持双通道独立验证与轻客户端按通道过滤查询（原单一 `tx_root` 字段已废弃）；**SEC2-C1 修复 — DagCommitCertificate 签名域明确**：commit certificate 签名对象 = `hash(chain_id || epoch || commit_round || prev_commit_hash || vertex_hash_list || round_attendance_bitmap || state_root || public_tx_root || gameturn_tx_root)`；绑定 `epoch` 防 epoch 边界 equivocation 证据歧义；绑定 `prev_commit_hash` 形成 hash chain 防 long-range attack（旧 validator 私钥泄露后无法伪造历史 commit）；绑定 `state_root` / `public_tx_root` / `gameturn_tx_root` 防 commit certificate 被重用到不同 block 内容

#### Scenario: Validator 失败不丢 tx（DAG 冗余）

* **WHEN** validator vi 离线

* **THEN** 客户端发往 vi 的 tx 早已广播给多个 validator（客户端默认多副本提交），其他 validator 在自己的 vertex 中包含该 tx；DAG commit 仍能上链该 tx；零延迟接管、零 tx 丢失

#### Scenario: Block 最终性

* **WHEN** DAG 中某轮 vertex 获得 ≥2/3 validator 引用形成 commit certificate

* **THEN** 该 commit certificate 中的所有 vertex 及其引用的祖先 vertex 被视为 finalized；轻客户端只需验证 commit certificate 的 2/3 secp256k1 多签（signer\_bitmap + signature\_list）即可信任该范围内的 block header

#### Scenario: Slashing — Vertex 等价 equivocation

* **WHEN** validator 在同一 DAG round 对两个冲突 vertex 签名（相同 round + 不同内容）

* **THEN** 任何节点可提交双签证据（两个 vertex + 两个签名）；**SEC-C1 修复 — 链上校验两个 vertex 的 `(epoch, round, author_pubkey)` 完全一致**（防跨 epoch equivocation 判定歧义：round 跨 epoch 全局递增，无 epoch 字段则 validator 可申辩"第一个 vertex 是上一 epoch grace period 内的合法签名"）；验证通过后该 validator 被踢出 validator 集并罚没保证金；**NEW-M15 修复**：`slash_amount = stake * slash_percentage / 100`，`slash_percentage` 默认 100%（全额罚没，可治理 ∈ [1, 100]）

#### Scenario: Slashing — Commit Certificate equivocation

* **WHEN** validator 在同一 `(epoch, commit_round)` 对两个冲突 commit certificate 签名

* **THEN** 任何节点可提交双签证据（两个 commit certificate + 两个签名）；链上校验两个 commit certificate 的 `(epoch, commit_round)` 完全一致；验证通过后该 validator 被踢出 validator 集并罚没保证金（`slash_percentage` 默认 100%，与 vertex equivocation 同语义）

#### Scenario: Slashing — 停机

* **WHEN** validator 连续 `downtime_threshold_blocks`（默认 100）未提交任何 vertex

* **THEN** 治理可提议踢出该 validator；**NEW-L2 修复 + R4-L1/R5-H1 修正**：停机 validator 罚没 `downtime_slash_percentage`（默认 10%，由 5% 提升至 10% — 原 5% 比例可能不足以威慑为协助审查而故意停机的 validator）保证金 + 失去出块资格

#### Scenario: 多重 slashing 处理规则

* **WHEN** validator 同时被指控多项违规（equivocation + 停机 + 拒收 checkpoint + 恶意 refuse_ack）

* **THEN** **SEC2-H2 修复**：(1) 扣除基数始终为 validator 被踢出时的剩余质押（非原始质押）；(2) 处理优先级：vertex equivocation（最高）> commit certificate equivocation > 拒收 checkpoint > 停机 > 恶意 refuse_ack 累计（最低）；(3) 每项 slashing 扣除 = 剩余质押 * 该项 slash_percentage / 100；(4) 质押耗尽后剩余 slashing 转为欠款记录，validator 重新加入时须补缴；(5) 受害者补偿按 slashing 优先级分配，高优先级受害者先获补偿

#### Scenario: 无 mempool 设计

* **WHEN** 客户端提交 tx

* **THEN** tx 直接发给一个或多个 validator（Public tx 广播给多 validator 副本；GameTurn tx 发给 assigned\_validator）；validator 把 tx 装入自己的 vertex；无 gossiped pending tx pool，消除 mempool DoS 攻击面

#### Scenario: 审查缓解（DAG 抗审查）

* **WHEN** 某个 validator 拒绝把某玩家的 GameTurn tx 装入 vertex

* **THEN** 客户端可同时提交给多个 validator（Public tx）或提交 `force_advance` 给任意 validator（force\_\* 类 tx 任何 validator 必须接受并装入 vertex）；审查证据（tx + 提交时间证明 + 多 validator 副本签名）可作为治理踢出该 validator 的依据

### Requirement: 游戏分配与分布式 Game Sub-Block (Game Assignment & Distributed Game Sub-Blocks)

The system SHALL assign each Game to a dedicated validator (assigned\_validator) at creation time via deterministic hash. The assigned validator SHALL sequence GameTurn txs for its games and produce signed game sub-blocks embedded in its DAG vertices. Game assignment SHALL be re-evaluated at each epoch boundary for load balancing. Clients SHALL route GameTurn txs to assigned\_validator, Public txs to any validator, and force\_\* txs to any validator (escape hatch).

#### Scenario: Game 创建时分配 validator

* **WHEN** Game G 创建（合约 `create_game` 调用）

* **THEN** G.assigned\_validator = validator\_set\[hash(G.id, current\_epoch) % |validator\_set|]；写入 Game 对象；客户端可本地计算 `hash(G.id, epoch) % |V|` 确认归属，无需额外 RPC

#### Scenario: GameTurn tx 直发 assigned\_validator

* **WHEN** 客户端提交作用于 Game G 的 GameTurn tx（call/check/raise/bet/fold）

* **THEN** tx 路由到 G.assigned\_validator；该 validator 校验轮转约束（`current_turn`）+ 买入锁仓状态后装入自己的 vertex；非 assigned\_validator 收到则转发或返回 `NotAssignedValidator`

#### Scenario: checkpoint\_anchor tx 走 CheckpointAnchor 通道

* **WHEN** OffChain 模式下操作方提交 checkpoint\_anchor

* **THEN** checkpoint\_anchor **走 CheckpointAnchor 通道（路由到 assigned\_validator，与 GameTurn 同路由但独立 lane 不参与 turn ordering），通过 gossipsub 广播提交（与 DAG vertex 传播同一 topic，确保所有 validator 包括 assigned\_validator 必然收到 — 防栽赃）**，免 gas（system tx 类别），客户端多副本广播默认 `checkpoint_multi_replica_count`**=5（R4-H1 修正 — 由 3 提升至 5 以增加合谋难度；NEW-M3 修复）** 个作为审查检测证据（副本 validator 仅见证不装入 vertex）；tx 更新 `last_action_height = block.height`（R5-L2 修正 — checkpoint\_anchor 去重：相同 (game\_id, checkpoint\_seq) 仅首次包含入 vertex 时生效，后续返回 `DuplicateCheckpoint`）；任何 validator 拒收 → 由 `force_checkpoint` 逃生 tx 触发 + 治理 slashing 证据

#### Scenario: force\_\* / checkin / request\_da tx 路由任意 validator

* **WHEN** 客户端提交 `force_advance` / `force_checkin` / `force_revert` / `request_revert` / `request_da` / `force_settle` / `checkin` / `challenge_delta` / `request_ack` / `refuse_ack` / `checkpoint_skip` / `force_checkpoint` / `partial_checkin` / `revoke_delegated_escape` / `rotate_validator_key` tx

* **THEN** tx 路由到任意 validator（客户端广播给多 validator 副本以提高确定性）；任何 validator 必须接受并装入 vertex（不得审查 escape hatch）；这些 tx 走 Public 通道排序，正常计费（`request_ack` / `refuse_ack` / `checkpoint_skip` 免 gas，与 checkpoint\_anchor 同属 system tx 类别）；**SEC-L4 修复 — 签名域统一加 chain\_id**：所有 force\_\* / request\_\* / checkin / partial\_checkin / challenge\_delta / checkpoint\_anchor / checkpoint\_skip / force\_checkpoint / rotate\_validator\_key / refuse\_ack / request\_ack tx 的签名消息对象必须显式包含 `chain_id` 字段作为首字段（即 `hash(chain_id || ...tx-specific-fields...)`），与 vertex 签名（C1）、ACK 签名（C3）、operator\_ack 签名域保持一致；防跨链重放攻击（testnet/devnet/mainnet 同名 tx 跨链重放）；validator 校验签名前先校验 `chain_id == network_chain_id`，不匹配返回 `WrongChainId`

#### Scenario: Public tx 路由任意 validator

* **WHEN** 客户端提交 Public tx（转账、合约部署、合约调用、bridge 操作等）

* **THEN** tx 路由到任意 validator（客户端广播给多 validator 副本）；validator 装入 vertex 后通过 DAG 传播

#### Scenario: Game sub-block 嵌入 DAG vertex

* **WHEN** assigned\_validator 产出一个 DAG vertex

* **THEN** vertex 中该 validator 负责的所有 game 的 GameTurn tx 被分组为多个 game sub-block（每个 game 一个 sub-block），sub-block 内部按 `(current_turn, arrival)` 排序；vertex 自带 validator secp256k1 签名，sub-block 无需额外签名（vertex 签名覆盖）

#### Scenario: Sub-block 内部排序（S9 修复 + R4-M4 修正）

* **WHEN** 同一 vertex 内，玩家 A 提交了作用于 Game G 的合法 GameTurn tx，同时对手 B 提交了作用于 G 的 `force_advance` tx（force\_advance 走 Public 通道但可同 vertex 传播）

* **THEN** assigned\_validator 在 vertex 内先执行 G 的 GameTurn tx（更新 `last_action_height` 为当前预期 block height），再判定 force\_advance；因 `last_action_height` 已更新，force\_advance 判定 `block.height > last_action_height + turn_timeout_blocks` 为 false，force\_advance 被拒绝；**R4-M4 修正 — 跨 vertex commit 级 S9 排序**：同一 Bullshark commit certificate 涵盖的所有 vertex（可能跨多个 round）的 GameTurn tx 先于所有 ForceSync/force\_advance tx 执行，即 commit 级别的 S9 规则，防攻击者将 force\_advance 提交到与 GameTurn tx 不同 vertex 利用 Bullshark 排序不确定性使 force\_advance 先执行；**SEC-H6 修复 — 跨 commit force_advance 抢跑防护**：跨 commit（不同 block）的 force_advance 判定需额外校验 — force_advance 所在 commit 的前一个 commit 内是否有该 Game 的 GameTurn tx，若有则 `last_action_height` 视为已更新（即使 GameTurn tx 所在 vertex 与 force\_advance 所在 vertex 不同 commit），force_advance 判定为 false 被拒绝；vertex 内同时含 GameTurn 和 force\_advance 时遵循 commit 级 S9 规则（GameTurn 先执行），不遵循 vertex 内顺序

#### Scenario: Epoch 自动重分配

* **WHEN** 链推进到 epoch 边界（每 `epoch_length_blocks` 默认 1000 block 一个 epoch）

* **THEN** 所有活跃 Game 的 assigned\_validator 重新计算 `hash(G.id, new_epoch) % |V|`；新 epoch 内 tx 路由到新 assigned\_validator；旧 assigned\_validator 不再接受该 game 的 tx；客户端本地计算即可路由，无需 RPC

#### Scenario: OffChain epoch 过渡协议（NEW-M10 修复 + R3-M5/R4-H2 修正）

* **WHEN** OffChain 模式 Game 接近 epoch 边界

* **THEN** (a) 操作方在 epoch 边界前 `epoch_transition_window_blocks`（默认 10）内必须提交一次 `checkpoint_anchor`（带 ack）作为过渡锚点，新 assigned\_validator 从此锚点继续；(b) 未提交过渡锚点 → 任意参与者触发 `force_advance` 或 `request_revert`；(c) `last_partial_fold` 状态保留，新 assigned\_validator 接受后续 `partial_checkin` / `checkin` 校验 `intermediate_commitment` 连续性（proof 验证为无状态密码学操作，assigned\_validator 切换不影响）；(d) **R4-H2 修正 + R3-M5 修正**：过渡期间 `force_checkpoint` 的 `assigned_validator_failure_proof` 仅可指控一个 assigned\_validator（旧或新），由**链上 tx 提交时的 `current_epoch` 权威决定**（非客户端本地判断 — 客户端通过轻客户端获取权威 `current_epoch`，避免时钟偏差或 epoch 边界同步延迟导致指控错误的 assigned\_validator）；(e) **SEC2-H3 修复 — epoch 边界 force_advance 抢跑防护**：操作方未在 `epoch_transition_window_blocks` 内提交过渡锚点 → 自动触发 forfeit 警告，forfeit 保证金按 `(epoch_transition_window_blocks - 已过 blocks) / epoch_transition_window_blocks` 比例扣除（最低 50%）；epoch 边界 ±`epoch_transition_window_blocks` 内，force_advance 判定需额外校验：force_advance 提交方须证明操作方在 `epoch_transition_window_blocks` 内未提交过渡锚点（通过 epoch 边界前 N blocks 的 checkpoint_anchor 非包含证明）；新 assigned_validator 在 epoch 边界后 `epoch_transition_window_blocks` 内不得接受 force_advance（除非附带操作方未提交过渡锚点的证据），给新 validator 状态同步窗口

#### Scenario: Assigned validator 失败自动接管

* **WHEN** assigned\_validator 在 `game_validator_timeout_blocks`（**默认 2（R4-L8 修正 — 原 3 与 turn\_timeout\_blocks 同值致竞争条件，降为 2 给 fallback tx 留处理窗口；R5-H2 修正 — 边界约束 `game_validator_timeout_blocks ∈ [1, floor(turn_timeout_blocks / 2)]`，否则治理可设为 > turn\_timeout\_blocks 使 fallback 机制失效）**）内未提交含该 game 的 GameTurn tx 的 vertex

* **THEN** DAG 冗余保证：客户端此前已把 tx 广播给多 validator 副本，其他 validator 可在 vertex 中包含该 tx；force\_\* tx 任何 validator 可触发；下个 epoch 自动重分配；无需客户端重试逻辑

#### Scenario: 客户端路由发现

* **WHEN** 客户端需确定一个 game 的 assigned\_validator

* **THEN** 客户端本地计算 `hash(game_id, current_epoch) % |validator_set|`；validator\_set 在 genesis 定义、epoch 切换时通过轻客户端同步；零延迟路由，无需 RPC

#### Scenario: 跨 Game 并行

* **WHEN** 两个 Game G1、G2 分别分配给不同 validator v1、v2

* **THEN** G1、G2 的 GameTurn tx 在不同 validator 的 vertex 中并行处理；DAG 共识保证两者 commit 顺序确定但处理并行；单 validator 不再处理所有 game

#### Scenario: MVP 不支持 tournament 原生跨 validator 协调

* **WHEN** tournament 模式需多 table 协调

* **THEN** MVP 阶段 tournament 在合约层用多个独立 Game 表达，不跨 validator 协调；v2 可考虑 tournament 整体绑定一个 assigned\_validator

### Requirement: 双模式排序共识 (Dual-Mode Sequencing)

The system SHALL operate a settlement layer with Sui/Solana-style public ordering for general transactions, AND a turn-ordered lane for transactions affecting active Game objects. Both lanes coexist within DAG vertices. GameTurn txs SHALL be processed before force\_sync txs within the same vertex for the same Game.

#### Scenario: 通用交易按公共排序结算

* **WHEN** 用户提交一笔通用交易（转账、合约部署、合约调用、checkin 结算等，不触碰活跃 Game 对象）

* **THEN** tx 路由到任意 validator，装入 Public 通道；DAG 共识按 (gas\_price, arrival) 排序

#### Scenario: 游戏交易按轮转排序

* **WHEN** Game G 的 `current_turn = Player P`，且 P 提交了作用于 G 的写交易 Tx

* **THEN** assigned\_validator 把 Tx 排入 G 的 game sub-block，按 `current_turn` 顺序排在所有作用于 G 的其他玩家写交易之前

#### Scenario: 非当前轮次写交易被拒绝

* **WHEN** Player Q（Q ≠ current\_turn）提交了作用于活跃 Game G 的状态变更交易

* **THEN** assigned\_validator 拒绝该交易进入 vertex（返回 `NotYourTurn` 错误），read-only 交易允许

#### Scenario: 跨 Game 交易并行

* **WHEN** 两个交易分别作用于不同的 Game 对象 G1、G2

* **THEN** 两者可在不同 validator 的 vertex 中并行排序与执行，互不阻塞

#### Scenario: 双通道共存于同一 vertex

* **WHEN** 一个 vertex 既含 Public 通道交易又含游戏通道交易

* **THEN** 两条通道在 vertex 内独立排序、并行执行，block 头分别记录两通道的 tx 根与状态根

### Requirement: 时间共识与超时 (Time Consensus & Timeouts)

The system SHALL establish on-chain time via block header timestamps with monotonicity and max-interval constraints AND block height as an objective monotonic counter. All force-sync deadlines SHALL be measured in block height. Timestamp validation SHALL NOT depend on validator local clocks (avoids consensus fork).

#### Scenario: 区块时间戳单调不减 + 最大间隔约束（S10 修复 + R5-L4 修正）

* **WHEN** DAG 共识 commit 一个 block

* **THEN** block header 含 `timestamp_ms`；验证规则：`timestamp_ms >= prev.timestamp_ms`（单调不减）且 `timestamp_ms <= prev.timestamp_ms + max_interval_ms`（最大间隔，防止设未来时间戳）；validator 不使用本地时钟校验（避免共识分叉）；**R5-L4 修正 — `timestamp_ms` 为软引用**：所有硬性截止判定以 `block.height` 为权威，block 提议者可在合法范围内选任意 `timestamp_ms` 值不影响安全判定；**R7-M3 修正 — `max_clock_drift_ms` 用途明确**：该参数仅供链下参与者（light client / 链下操作方）作软参考时钟漂移容忍度使用（如链下判断 checkpoint_anchor 是否"近期"提交以决定是否触发 force\_advance 的辅助参考），**不用于 validator 共识硬校验**（共识硬截止一律以 `block.height` 为权威），设为 0 表示链下参与者不得依赖 timestamp 软参考；**SEC-M5 修复 — timestamp\_ms 合谋风险警示**：block 提议者（DAG 中获得 commit 的 validator）可在 `[prev.timestamp_ms, prev.timestamp_ms + max_interval_ms]` 合法范围内任意选 `timestamp_ms` 值，存在被合谋 validator 用于操纵链下参与者辅助参考时钟的风险（如故意压低 timestamp\_ms 使链下操作方误判 checkpoint\_anchor "未近期提交"提前触发 force\_advance）；**安全约束**：(1) 链下参与者触发 `force_advance` / `force_checkpoint` 等逃生 tx 的**硬截止判定一律以 `block.height` 为权威**，禁止以 `timestamp_ms` 作为触发条件；(2) `timestamp_ms` 仅可用于"显示用"（区块浏览器展示、日志时间戳）与"非安全相关的软参考"（如链下操作方 UI 倒计时提示）；(3) 任何以 `timestamp_ms` 为依据的安全决策均视为实现错误

#### Scenario: 区块高度作为客观单调计数器

* **WHEN** 链推进一个 block

* **THEN** `block.height = prev.height + 1`，严格单调递增，无法操纵或回退

#### Scenario: 超时以 block height 计量

* **WHEN** 设置 turn 超时 / hand 超时 / 挑战窗口

* **THEN** 参数表达为 `turn_timeout_blocks` / `hand_max_duration_blocks` / `dispute_window_blocks` / `da_window_blocks` / `checkpoint_interval_blocks` / `game_validator_timeout_blocks`；`force_advance` / `force_settle` / 挑战窗口到期均以 `block.height > last_action_height + timeout_blocks` 判定

#### Scenario: 链下参与者同步时间

* **WHEN** OffChain 模式下参与者需判断超时是否到期

* **THEN** 参与者运行轻客户端订阅 block header，获取权威 `block.height` 与 `timestamp_ms`；以 `block.height` 判定硬截止，以 `timestamp_ms` 作为软参考

#### Scenario: 链下时钟漂移不影响争议判定

* **WHEN** 链下参与者本地时钟与链上 `timestamp_ms` 偏差较大

* **THEN** 所有硬性截止仍以 `block.height` 为准，链下时钟漂移不影响争议判定

#### Scenario: 超时参数吸收网络延迟（M3 修复）

* **WHEN** 链下参与者因区块传播延迟（可能数秒）未及时收到最新 block

* **THEN** `turn_timeout_blocks` 应 >= 3 以吸收典型区块传播延迟；spec 推荐默认值 `turn_timeout_blocks = 10`，用户可在合约中配置更大的值以增加容错；`ack_deadline_blocks` 推荐 >= 3（吸收 ACK 链下传递 + 链上确认延迟）；`max_skip_segments` 推荐 3（平衡容错与最终 checkin 风险）

### Requirement: 游戏交易免 Gas + 台费结算 (Gas-Free Game Transactions + Rake Settlement)

The system SHALL NOT charge gas for game actions on the GameTurn lane. A rake SHALL be collected at hand settlement, with rake logic defined by the contract. Anti-spam SHALL be enforced via buy-in stake lock AND per-player active Game limit.

#### Scenario: 游戏操作免 gas

* **WHEN** 玩家在 GameTurn 通道提交 call / check / raise / bet / fold 等游戏操作 tx

* **THEN** assigned\_validator 与其他 validator 跳过 gas 计费，仅校验轮转约束（`current_turn`）与买入锁仓状态

#### Scenario: 台费在结算时扣除

* **WHEN** Game 调用合约 `settle` 函数结束一局

* **THEN** 合约按配置的台费规则（比例 / 封顶 / 收款方）从底池扣除台费，剩余部分分配给胜者；台费收款方由合约配置（可配置为 validator 奖励池以覆盖免 gas 成本）

#### Scenario: 底池为零时不收台费（M1 修复）

* **WHEN** settle 时底池为 0（所有人 preflop fold 到大盲）

* **THEN** 合约跳过台费扣除（台费 = min(rake\_rate × pot, rake\_cap) = 0），不产生负数

#### Scenario: 买入锁仓反垃圾

* **WHEN** 玩家未买入或买入锁仓已释放

* **THEN** 玩家的 GameTurn 通道写交易被拒绝（返回 `NotStaked` 错误）

#### Scenario: 每玩家活跃 Game 数量上限（S8 修复）

* **WHEN** 玩家尝试 join 第 N+1 个活跃 Game（N = `max_active_games_per_player`，默认 10）

* **THEN** join 被拒绝（返回 `TooManyActiveGames` 错误）；活跃 Game 定义为 owner != Immutable 且玩家仍在座

#### Scenario: 非游戏交易正常计费

* **WHEN** 用户提交 Public 通道交易（转账、合约部署、checkin 结算、bridge 操作等）

* **THEN** 按标准 gas 模型计费，与普通 L1 一致

### Requirement: 对象模型 (Object-Centric State)

The system SHALL model each Hand as a first-class object with unique ID, version, owner, and typed data, minimizing concurrency granularity to per-object.

#### Scenario: Game 对象创建

* **WHEN** 牌桌开始新一手牌

* **THEN** 链上创建一个新 Game 对象，`ID = (table_id, hand_id)`，`version = 0`，`owner = Shared`，`assigned_validator = validator_set[hash(G.id, epoch) % |V|]`

#### Scenario: ObjectID 全局唯一性（NEW-L4 修复）

* **WHEN** 任何对象创建（Game / Account / Contract / UpgradeCap 等）

* **THEN** **`ObjectID = (creator_address: [u8;20], creation_nonce: u64)` 二元组**，全局唯一性由创建账户 nonce 单调递增 + 不同 creator address 保证；`ObjectStore` 创建时校验 `ObjectID` 不存在，冲突返回 `ObjectIDCollision`；同一 creator 的 `creation_nonce` 单调递增不复用，不同 creator address 不碰撞

#### Scenario: 对象版本递增

* **WHEN** 任何修改 Game 对象的 tx 执行成功

* **THEN** 该对象 `version += 1`，旧版本保留为不可变历史

#### Scenario: 结算后冻结

* **WHEN** Game 结算完成

* **THEN** Game 对象 `owner` 变为 `Immutable`，后续 tx 仅可读不可写

### Requirement: 账户抽象与交易安全 (Account Abstraction & Tx Security)（S7/M9/M10 修复）

The system SHALL define an account model with address derived from tagged pubkey, account nonce for replay protection, and chain\_id for cross-chain replay protection. Each account SHALL have a balance for Public lane gas payment.

#### Scenario: Tagged Pubkey 与地址派生（S7 修复）

* **WHEN** 用户生成密钥对

* **THEN** pubkey 编码为 tagged format：1 字节 scheme tag（0x00 = secp256k1 compressed 33B，0x01 = ed25519 32B）+ raw pubkey bytes；地址 = `blake2b_256(tagged_pubkey)` 取前 20 字节；不同曲线的 tagged pubkey 不会产生地址碰撞

#### Scenario: secp256k1 recoverable 签名编码

* **WHEN** 用户用 secp256k1 签名

* **THEN** signature = `r (32B) || s (32B) || v (1B, recovery id)`，v ∈ {0, 1}；验证时从 v 恢复 pubkey 再比对

#### Scenario: 账户模型（M9 修复）

* **WHEN** 账户创建（首次收到 tx 或通过 faucet）

* **THEN** Account = `{ address, tagged_pubkey, nonce: u64, balance: u64 }`；一个账户绑定一个 pubkey（MVP 不支持多 key 账户）；balance 用于支付 Public 通道 gas

#### Scenario: 交易重放保护（M10 修复 + NEW-M9 修复）

* **WHEN** 用户提交 tx

* **THEN** tx 含 `chain_id`（网络 magic，防跨链重放）与 `nonce`（防同链重放）；validator 校验 `tx.nonce == account.nonce`，通过后 `account.nonce += 1`；nonce 不匹配的 tx 被拒绝（返回 `InvalidNonce`）；**NEW-M9 修复 — GameTurn 通道 tx 可使用 `gameturn_nonce`（per-game per-player 计数器，`Option<u64>` 字段）替代 account nonce** — validator 校验 `gameturn_nonce == game.player_nonce[player]` 后 `+= 1`；GameTurn tx 不阻塞 account nonce 链（account nonce 仅由 Public / ForceSync tx 推进）；fallback 接受的 GameTurn tx（NEW-H2）同样使用 `gameturn_nonce`，避免 Public tx nonce 阻塞 GameTurn 出牌；**SEC-L3 修复 — `gameturn_nonce` 存储结构明确**：`Game.player_nonce: BTreeMap<PlayerAddress, u64>`（per-game per-player 计数器），玩家首次 join 时初始化为 0，每个 GameTurn tx（含 fallback tx）执行成功后 `+= 1`；冷启动（map 中无该 player 记录）按 0 处理；该字段随 Game 对象持久化与裁剪；**SEC-H7 修复 — fallback tx 格式标识**：tx 格式增加 `is_fallback: bool` 字段（默认 false），fallback tx 在 tx 中显式标记 `is_fallback = true`，validator 据此路由到 `gameturn_nonce` 验证路径（不走 account nonce 校验，但走 Public 通道计费 gas）；正常 GameTurn tx 不得设置 `is_fallback = true`（validator 拒绝 — 防 assigned_validator 误将正常 tx 路由到 fallback 路径绕过轮转排序独占权）

### Requirement: Rust 合约部署 (rBPF VM + Gas Table + Upgrade)（M4/M8 修复）

The system SHALL execute smart contracts compiled from Rust to BPF bytecode via the `solana_rbpf` VM. A gas cost table SHALL be defined for instructions and syscalls. Contract upgrade SHALL be supported via UpgradeCap.

#### Scenario: 合约部署

* **WHEN** 用户提交一个 `.so` BPF 合约字节码

* **THEN** 节点验证字节码格式，注册合约对象，返回 `contract_id`；同时创建一个 `UpgradeCap` 对象并 transfer 给部署者

#### Scenario: 合约调用

* **WHEN** tx 调用合约 C 的方法 M

* **THEN** VM 加载 C 的字节码，实例化 rBPF runtime，执行 entrypoint，按 gas 计费表计费

#### Scenario: Gas 计费表（M8 修复 + NEW-M16 修复 + R3-M3 修正）

* **WHEN** VM 执行合约

* **THEN** gas 计费规则：BPF 算术指令 = 1 gas，内存指令 = 3 gas，分支指令 = 2 gas；syscall 计费：`object_read` = 10 gas，`object_write` = 20 gas，**`secp256k1_verify` = 500 gas（R3-M3 修正 — 原未列出，用于 tx / vertex / receipt / operator\_ack / ACK 签名验证）**，`bls12_381_g1_mul` = 500 gas，`bls12_381_pairing_check` = 5000 gas，`hypernova_verify` = 50000 gas，`groth16_verify` = 20000 gas，`ipa_verify` = 15000 gas，**`verify_failure_proof` = 80000 gas（NEW-M16 修复 — 验证 `assigned_validator_failure_proof` 含多签验证 + Merkle 非包含证明 + round 完备性校验，按 worst-case 计费；**SEC-H9 修复 — gas 重算至 80000**：原 5000 gas 估算基于"标准 Merkle tree (~1000 gas)"是错误的 — `assigned_validator_failure_proof` 采用 **256-bit sparse Merkle tree**（R5-H4 修正，以 tx\_hash 为 key，深度 256），非包含证明 worst-case 需 256 层路径 × 每层哈希 ~200 gas (blake2b 256-bit) ≈ 51200 gas；加上 3×secp256k1\_verify(500) = 1500 gas + round 完备性校验 ~1500 gas + multi-replica receipt 签名验证 3×500 = 1500 gas ≈ 55700 gas；预留 ~30% 安全边际上取整至 80000 gas；原 5000 gas 会导致诚实验证方 OutOfGas 拒绝合法 force\_checkpoint，使逃生通道失效）**；block gas limit = 50,000,000，tx gas limit = 10,000,000；**`force_checkpoint` tx 提交方需预付含 `verify_failure_proof` gas，evidence 验证失败 gas 不退（反 spam）**

#### Scenario: 合约升级（M4 修复 + R4-L4 修正）

* **WHEN** UpgradeCap 持有者提交新版本字节码 + UpgradeCap 作为 input

* **THEN** 节点验证 UpgradeCap 所有权，注册新版本字节码，`contract_id` 不变但 `version += 1`；旧版本变为不可调用；台费规则、forfeit 规则等可迭代；**R4-L4 修正 — UpgradeCap 多签/timelock 建议（文档化）**：强烈建议采用 governance multisig ≥2/3 quorum 或 timelock（延迟 `parameter_delay_blocks` 默认 2000 个 block 生效，期间可审查 + 紧急撤销）；**SEC-L7 修复 — timelock 共识层强制**：原"不在共识层强制"为安全漏洞 — 单点密钥丢失或单方恶意升级可瞬间替换全合约逻辑窃取资金；现升级为共识层强制：(1) 升级 tx 提交后进入 `upgrade_delay_blocks`（默认 = `parameter_delay_blocks` = 2000）timelock，期间新版本字节码仅注册不可调用，timelock 到期后自动生效；(2) timelock 期间任何持有 UpgradeCap 的主体可提交 `cancel_upgrade` tx 撤销升级；(3) timelock 期间任意参与者可提交 `dispute_upgrade` tx 触发治理投票冻结升级（防恶意升级）；(4) 治理可投票将特定合约的 `upgrade_delay_blocks` 设为 `u64::MAX` 实质冻结升级；(5) 紧急升级（修复关键漏洞）须 90% validator quorum 通过专项提案绕过 timelock；(6) `UpgradeCap` 持有者主体记录在合约部署 tx 中，链上可查；**SEC2-M11 修复 — 紧急升级范围限制与审查**：(1) 紧急升级提案须包含 `critical_vulnerability_proof`（关键漏洞证据，如漏洞复现 tx + 影响评估），validator 校验证据合理性后方可投票；(2) 紧急升级仅允许修复性升级（不可改变资金所有权），禁止功能性升级绕过 timelock；(3) 紧急升级生效后须立即触发安全审计期（默认 1000 blocks），期间任意参与者可提交 `dispute_emergency_upgrade` tx 触发治理复审；(4) 紧急升级的合约字节码须开源 + 第三方审计报告（链上提交审计 hash）；(5) 紧急升级生效后，受影响资金须锁定 1000 blocks（防瞬间提现）

#### Scenario: Syscall 可用

* **WHEN** 合约调用 `object_read` / `object_write` / `bls12_381_g1_mul` 等 syscall

* **THEN** runtime 路由到对应宿主函数并返回结果

### Requirement: BLS12-381 原生预编译（S6 修复）

The system SHALL provide native BLS12-381 G1/G2/pairing operations as VM syscalls, implemented atop `poker_protocol::crypto::Bls12381Curve` (blstrs). All G1/G2 inputs SHALL pass subgroup check before any operation. Gas SHALL be billed at worst-case rate.

#### Scenario: G1 标量乘法（含子群检查）

* **WHEN** 合约调用 `bls12_381_g1_mul(point, scalar)`

* **THEN** runtime 先对 point 做子群检查（`G1.is_in_subgroup()`），失败返回 `InvalidSubgroup` 错误；通过后返回 G1 点 = point \* scalar，常数时间实现；gas = 500（含子群检查开销）

#### Scenario: 双线性配对（含子群检查）

* **WHEN** 合约调用 `bls12_381_pairing_check(a_g1, b_g2, c_g1, d_g2)`

* **THEN** runtime 对所有 4 个输入做子群检查（G2 子群检查开销约 1ms），失败返回 `InvalidSubgroup`；通过后返回 `e(a,b) == e(c,d)` 布尔结果；gas = 5000（按 worst-case，非 typical-case 计费）

#### Scenario: Hash-to-curve（按字节计费）

* **WHEN** 合约调用 `bls12_381_hash_to_g2(msg, dst)`

* **THEN** 返回 G2 点，遵循 RFC 9380；gas = 1000 + 10 \* msg.len()（按消息字节线性计费）；msg 最大长度 65536 字节，超出返回 `InputTooLong`；**SEC2-L2 修复 — BLS12-381 hash_to_g2 DST 明确**：DST = `POKER_L1_BLS12381G2_XMD:SHA-256_SSWU_RO_`（固定值，不可配置）；DST 须在 genesis 中硬编码，治理不可更改；合约调用 hash_to_g2 时，runtime 自动附加固定 DST，不允许合约自定义 DST（防 DST 操纵）

#### Scenario: 子群检查防止 DoS

* **WHEN** 恶意合约提交非子群 G2 元素调用 pairing

* **THEN** 子群检查在 pairing 之前执行并拒绝，避免非子群元素导致 pairing 时间增加数倍

### Requirement: 多曲线钱包签名 (Multi-Curve Wallet Signatures)

The system SHALL natively support secp256k1 and ed25519 signature schemes, exposed via a unified verification interface using tagged pubkey routing.

#### Scenario: secp256k1 签名验证（NEW-L1 修复 + R3-C2 修正）

* **WHEN** 用户用 secp256k1 私钥对 tx 哈希签名并提交（tag = 0x00）

* **THEN** 节点从 tagged pubkey 提取 33B compressed pubkey，用 secp256k1 ECDSA recoverable 验证签名（含 v recovery id）；**NEW-L1 修复 — 强制 low-s（BIP-62）**：校验 `s <= n/2`（n 为曲线阶数），**`s > n/2` 返回 `InvalidSignatureLowS`（拒绝，不规范化转换 — R3-C2 修正：规范化会接受 high-s 变体，无法消除延展性；同一私钥对同一消息的 high-s 与 low-s 签名视为不同签名，延展性消除）**；应用于所有 secp256k1 签名路径（tx / vertex / receipt / operator\_ack / ACK）；**SEC-L2 修复 — low-s 检查时机明确**：low-s 校验必须在签名解析后、pubkey 恢复前执行（即解析 `r || s || v` 后立即校验 `s <= n/2`），失败立即返回 `InvalidSignatureLowS` 不进入 ECDSA 验证流程 — 避免 attacker 用 high-s 签名浪费 validator 完整 ECDSA 验证计算资源（DoS 缓解）；通过后接受 tx

#### Scenario: ed25519 签名验证

* **WHEN** 用户用 ed25519 私钥对 tx 哈希签名并提交（tag = 0x01）

* **THEN** 节点从 tagged pubkey 提取 32B pubkey，用 ed25519 验证签名，通过后接受 tx；**SEC2-L1 修复 — ed25519 签名规范化**：(1) 校验 R 的编码为 canonical（y 坐标 < 2^255 - 19）；(2) 校验 S 的编码为 canonical（S < L，L 为子群阶数）；(3) 非规范化编码返回 `InvalidSignatureCanonical`；(4) 应用于所有 ed25519 签名路径（tx / ACK / operator_ack / multi-replica receipt）

#### Scenario: 统一路由

* **WHEN** 任意签名方案的账户发起 tx

* **THEN** `verify_signature(tagged_pubkey, sig, msg_hash) -> bool` 读取 tag 字节路由到对应曲线验证器；未知 tag 返回 `UnknownScheme` 错误；**SEC-M9 修复 — tag 版本化机制**：tag 字节采用 `(scheme_id: 4 bits || version_id: 4 bits)` 编码（单字节高 4 位为方案 ID、低 4 位为版本号），当前定义：`0x00` = secp256k1 v1、`0x01` = ed25519 v1；预留 `0x10`-`0xF0` 高位段供未来方案（BLS12-381、后量子签名等）；版本号允许同方案多版本共存（如 secp256k1 v2 支持抗量子硬化），旧版本 tag 在治理明确废弃前保持兼容；`SignatureScheme` 枚举与 `UnknownScheme` 错误处理保持向后兼容（未知 tag 仍返回 `UnknownScheme`）；新 tag 引入须经治理提案 + 90% quorum 通过（防 2/3 合谋引入弱签名方案绕过安全模型）

### Requirement: 可插拔 ZK 证明验证模块 (Pluggable ZK Proof Verifiers)

The system SHALL provide on-chain verifier syscalls for Hypernova, Groth16, and IPA, each registered as a distinct VM syscall.

#### Scenario: Hypernova 验证

* **WHEN** 合约调用 `hypernova_verify(proof, public_io)`

* **THEN** verifier 检查折叠实例一致性 + final sumcheck（Fiat-Shamir challenge），返回布尔结果

#### Scenario: Groth16 验证（R4-L2 修正）

* **WHEN** 合约调用 `groth16_verify(vk, proof, public_inputs)`

* **THEN** verifier 执行配对检查，复用 BLS12-381 预编译（含子群检查），返回布尔结果；**R4-L2 修正 — Groth16 trusted setup MPC（文档化提醒）**：链下 MPC ceremony 生成 CRS，`verifying_key` 通过治理提案上链注册到 `ZkVerifierRegistry`，`proving_key` 链下分发，toxic waste 由参与方销毁；该流程不在共识层强制，但 spec 文档化提醒采用 Groth16 电路的合约方必须自行组织可信 setup；**SEC-M10 修复 — Groth16 CRS fingerprint 链上验证**：`ZkVerifierRegistry` 注册 `verifying_key` 时须同时存储 `crs_fingerprint = blake2b_256(vk.alpha_g1 || vk.beta_g2 || vk.gamma_g2 || vk.delta_g2 || vk.ic)`，作为 vk 完整性指纹；合约调用 `groth16_verify(vk_id, proof, public_inputs)` 时，verifier 先校验 `blake2b_256(stored_vk) == crs_fingerprint`，不匹配返回 `CrsFingerprintMismatch`（防 vk 被恶意替换为攻击者控制的 weak vk 实施 key substitution attack — 攻击者用自己的 setup 生成 vk 与 proof，使任意 public_inputs 都能"通过"验证）；`crs_fingerprint` 注册后不可更改，更新 vk 须经治理 90% quorum 通过注册新 `vk_id`（保留旧 vk_id 兼容历史 proof）

#### Scenario: IPA 验证

* **WHEN** 合约调用 `ipa_verify(commitment, proof, opening_point)`

* **THEN** verifier 执行内积论证检查（Pedersen 承诺 + 折叠递归），返回布尔结果

#### Scenario: 模块可插拔

* **WHEN** 节点升级新增一个 ZK 验证器

* **THEN** 通过 syscall 注册表挂载，无需重新编译已部署合约

#### Scenario: Hypernova public\_io 边界（O15 修复）

* **WHEN** 链下 prover 生成最终折叠证明 π

* **THEN** π 的 public\_io 包含：initial\_commitment、final\_commitment、state\_delta\_hash、ack\_chain\_hash（所有 checkpoint ack 的聚合哈希）、fold\_step\_count（折叠步数，上限 1000）；verifier 校验 public\_io 完整性

### Requirement: 游戏执行模式 (Game Execution Modes)

The system SHALL support two execution modes per Game, selected via contract parameter `execution_mode ∈ {OnChain, OffChain}`. OnChain is the default trustless mode; OffChain is an opt-in performance mode.

#### Scenario: 合约声明执行模式

* **WHEN** 牌桌合约初始化新一手牌（HandStarted）

* **THEN** 合约读取 `execution_mode` 参数：`OnChain` 时后续步骤直接走链上 GameTurn 通道；`OffChain` 时触发 checkout 到链下

#### Scenario: OnChain 模式（默认，信任最小化）

* **WHEN** `execution_mode = OnChain`

* **THEN** 所有游戏步骤作为 GameTurn 通道 tx 在链上执行，每步状态变更上链，无 checkout / checkin，无 ZK 证明；玩家无需信任任何链下执行方

#### Scenario: OffChain 模式（可选，性能优先）

* **WHEN** `execution_mode = OffChain` 且新一手牌已开局

* **THEN** Game 对象状态被快照为 `OfflineState` commitment 存入链上，owner 标记为 `ChannelOwner`，后续游戏步骤在链下执行

#### Scenario: 玩家不信任可选链下

* **WHEN** 部分玩家不信任链下结算

* **THEN** 牌桌合约可被部署为 `execution_mode = OnChain`，所有玩家走全链上 GameTurn 通道

### Requirement: 链下执行通信协议 (Off-Chain Communication Protocol)（S2/S3/S4 修复）

The system SHALL define an off-chain communication protocol for OffChain mode: periodic checkpoint anchors with multi-party signed acks, plus censorship-resistance mechanisms (ack\_deadline, checkpoint\_skip). This protocol provides observable on-chain signals for force\_advance judgment, enables force\_checkin feasibility, prevents collusion, and resists censorship truncation by assigned\_validator or malicious participants.

#### Scenario: Checkpoint Anchor（S2 修复 + 审查截断防护 + NEW-M3/R4-H1 修正）

* **WHEN** OffChain 模式下链下执行推进

* **THEN** 操作方（当前轮次玩家或 designated operator）每 `checkpoint_interval_blocks`（默认 5）提交一次轻量 `checkpoint_anchor` tx，内容为 `(game_id, current_turn, state_hash, ack_signatures, opt_out_ack_proof?)`；该 tx **走 CheckpointAnchor 通道（路由到 assigned\_validator，与 GameTurn 同路由但独立 lane 不参与 turn ordering），通过 gossipsub 广播提交（与 DAG vertex 传播同一 topic，确保所有 validator 包括 assigned\_validator 必然收到 — 防栽赃）**，**SEC-H5 修复 — gossipsub 传播保证明确化**：gossipsub 采用 mesh + gossip 混合传播，mesh 大小 = `checkpoint_multi_replica_count + 1`（确保 assigned\_validator 必在 mesh 中），消息 TTL >= `game_validator_timeout_blocks`（防消息因 TTL 过期丢失）；免 gas（system tx 类别），客户端多副本广播默认 `checkpoint_multi_replica_count`**=5（R4-H1 修正 — 同步 spec.md 中所有"默认 3"为"默认 5"；NEW-M3 修复 — 由 3 提升至 5 以增加合谋难度）** 个作为审查检测证据（副本 validator 仅见证不装入 vertex）；tx 更新链上 `last_action_height = block.height`（**R5-L2 修正 — checkpoint\_anchor 去重：相同 (game\_id, checkpoint\_seq) 仅首次包含入 vertex 时生效，后续返回 `DuplicateCheckpoint`**）；操作方提交后无需观察 on-chain confirmation（被动检测模式，ack\_chain 与 on-chain confirmation 解耦）；assigned\_validator 拒收 → 由 `force_checkpoint` 逃生 tx 触发 + 治理 slashing 证据；该设计防止 assigned\_validator 单点审查导致 force\_advance 误触发

#### Scenario: 多方签名 ACK 防合谋（S4 修复 + NEW-H3/R3-H3/R4-H3 修正 + NEW-M11 修复）

* **WHEN** 操作方生成 checkpoint\_anchor

* **THEN** checkpoint\_anchor 必须包含所有活跃参与者（**NEW-M11 修复 — 活跃参与者定义：当前手牌未 fold 且未 sit-out 的在座玩家；fold tx 上链作为证据，ACK 集合随 fold 事件动态收缩**）的 tagged pubkey 签名 ack（secp256k1/ed25519 钱包密钥）；**NEW-H3 修复 + R3-H3/R4-H3 修正 — ACK 签名域分离**：ACK 签名消息为 `hash(chain_id || epoch || game_id || current_turn || state_hash || checkpoint_seq || ack_domain_tag)`（**SEC-C3 修复 — 增加 `epoch` 字段**：防跨 epoch 重放 — 同一 game 在不同 epoch 由不同 assigned\_validator 处理，无 epoch 字段则 ACK 可在 state\_hash 巧合下跨 epoch 重放；**增加 `ack_domain_tag` 常量字节（0x02）**：与 refuse\_ack（0x03）、operator\_ack（0x04）等做显式 domain separation，防未来协议升级引入跨域重放；**绑定 chain\_id 防跨链重放** — testnet/mainnet game\_id 碰撞时 ACK 不可重放；**绑定 game\_id 防跨 Game 重放**；**绑定 checkpoint\_seq 防跨 checkpoint 重放**；domain-separated）；缺少任一活跃参与者 ack 的 checkpoint\_anchor 被任何接收 validator 拒绝（返回 `MissingAck` 错误）；合谋需要所有活跃参与者串通，单方无法伪造状态；`opt_out_ack_proof` 字段用于 ack\_deadline 逾期默认 ACK 场景；**SEC2-M9 修复 — ack 签名者身份校验**：(1) validator 校验每个 ack 签名者的 tagged pubkey 必须在 `Game.active_participants` 集合中，不匹配返回 `AckSignerNotParticipant`；(2) `ack_signatures` 须覆盖全部 `active_participants`，缺失返回 `MissingAck`；(3) ack 签名者去重：同一 participant 的多个 ack 仅首个有效；(4) `Game.active_participants` 集合在 fold/sit-out 事件时链上更新，validator 校验 ack 集合 == 当前 `active_participants`

#### Scenario: force\_checkpoint 逃生 tx（审查截断防护 — assigned\_validator 审查 checkpoint\_anchor + NEW-H1/NEW-C2/R3-M6 修正）

* **WHEN** assigned\_validator 拒收 checkpoint\_anchor 或操作方机器故障但已广播 checkpoint

* **THEN** 任何节点可提交 `force_checkpoint` tx（任意 validator，escape hatch 类，**走 Public 通道正常计费 gas** — 避免免 gas spam 风险）：`(game_id, current_turn, state_hash, ack_signatures, opt_out_ack_proof?, assigned_validator_failure_proof)`；**NEW-C2 修复**：链上验证 evidence 后接受，更新 `last_action_height = block.height`（**R3-H6 修正：request\_ack 不再更新此字段，仅 force\_checkpoint / checkpoint\_anchor / GameTurn / force\_sync 更新**）；**NEW-H1 修复 + R3-M6 修正 — 审查调查 + 累积惩罚**：触发 assigned\_validator `under_investigation = true` + `defense_window_blocks`（默认 50）防御窗口（而非自动 slashing），窗口内 validator 可提交"未收到证明"申辩（**R3-M6：申辩需 ≥2/3 validator gossipsub 日志佐证，自述无效**）；**SEC-H5 修复 — 申辩机制强化**：assigned\_validator 申辩时须提供其 gossipsub 订阅日志 + libp2p 连接日志，证明其在 round\_range 期间网络可达但未收到该 checkpoint\_anchor；≥2/3 validator 佐证其网络可达性 + 日志有效性方可申辩成功（防 gossipsub 网络分区下栽赃 — 原设计"assigned\_validator 作为 gossipsub 订阅者必然收到"假设在网络分区下不成立）；申辩有效 → 豁免仅记录嫌疑，无申辩或申辩无效 → 治理 slashing；**累积惩罚**：`under_investigation_count` 仅当申辩无效或无申辩时 +1（R4-H5 修正 — 原"无论申辩是否成功 +1"可被恶意参与者 griefing 诚实 validator），每 epoch 衰减 1（最低为 0，R4-H5），达阈值（默认 3）后即使申辩也触发 slashing，标记保留 N epoch 供模式分析；支持 `opt_out_ack_proof` 字段（与 checkpoint\_anchor 等价语义）；**R5-H4 修正**：`assigned_validator_failure_proof` 中的 `tx_merkle_tree` 采用 sparse Merkle tree（以 tx\_hash 为 key，256-bit depth）而非标准 Merkle tree；非包含证明格式为 `(tx_hash, sparse_merkle_path)`，叶子值 = empty\_placeholder 表示 tx 不存在；worst-case proof size = 8KB；**SEC2-M3 修复 — force_checkpoint evidence spam DoS 防护**：(1) `force_checkpoint` tx 提交方须额外预锁 `force_checkpoint_deposit`（默认 = buy_in_amount * 10%），evidence 验证失败时没收（除 gas 不退外，增加经济惩罚）；(2) 每 Game 在 `turn_timeout_blocks` 内最多接受 1 个 force_checkpoint tx（防同 Game spam）；(3) validator 在验证 evidence 前先进行 cheap check（ACK 完整性、state_hash 格式、round 范围合理性），cheap check 失败立即拒绝（不消耗 80000 gas）；(4) 全局 force_checkpoint 频率限制：每 block 最多 N 个 force_checkpoint tx（默认 5），超出排队下一 block

#### Scenario: assigned\_validator\_failure\_proof 验证（含 C1 栽赃防护 + C6 非包含证明 + NEW-M3/R3-C1/R4-H6 修正）

* **WHEN** 链上验证 `force_checkpoint` 的 `assigned_validator_failure_proof`

* **THEN** evidence 含 `(原始 checkpoint\_anchor tx 内容 + gossipsub 广播证据 + multi-replica receipt signatures（**≥3 个副本 validator 接收见证签名，3-of-N 多签阈值，N=checkpoint\_multi\_replica\_count=5（NEW-M3 修复 — 由 2-of-3 提升至 3-of-5 以提高合谋门槛；阈值公式 `required_witness_count = max(3, floor(checkpoint_multi_replica_count * 2 / 3))`（R3-C1 修正 — N=5→3，N=7→4，修正原 `ceil(N*2/3)+1` 对 N=5 得 5 的数学错误），治理可调但下限 ≥3；R4-H6 修正 — fallback timeout\_proof 同此阈值，原 2-of-N 过低，2-of-5 合谋即可伪造）**）+ assigned\_validator 应出 vertex 但未出的 round 范围 + 非包含证明)`；链上验证：(1) 原始 checkpoint\_anchor 内容合法（ACK 完整、state\_hash 格式正确）；(2) **≥3 个副本 validator 见证签名有效（multi-replica receipt signatures，防止单一或两个副本合谋伪造）**；(3) **栽赃防护（SEC-H5 修正 — 弱化"必然收到"假设）**：≥3 副本见证证明 tx 已进入 gossip 网络，assigned\_validator 作为 gossipsub 订阅者**在 mesh 覆盖范围内应收到**（gossipsub mesh 大小 = `checkpoint_multi_replica_count + 1` 确保 assigned\_validator 必在 mesh 中）；**但网络分区下 assigned\_validator 可能未收到**，因此 assigned\_validator 可在 `defense_window_blocks` 内提交申辩（见 force\_checkpoint 逃生 tx Scenario 的 SEC-H5 修复），申辩需提供 gossipsub 订阅日志 + libp2p 连接日志 + ≥2/3 validator 网络可达性佐证；申辩成功则豁免 slashing（操作方无法"只发给副本跳过 assigned\_validator"仅在 mesh 覆盖范围内成立）；(4) assigned\_validator 在 `game_validator_timeout_blocks` 内未装入 vertex（通过 DAG round 范围 + 非包含证明）；任一失败 → 拒绝 force\_checkpoint + **NEW-M16：evidence 验证失败 gas 不退**

#### Scenario: round 范围非包含证明（C6 修复 + R4-M7/R5-H4 修正）

* **WHEN** 构造 `assigned_validator_failure_proof` 的非包含证明

* **THEN** 格式 `(epoch, round_range [R, R+k], assigned_validator_pubkey, vertex_list, non_inclusion_proofs)`；**SEC-C1 修复 — 增加 `epoch` 字段**：round 跨 epoch 全局递增，须显式绑定 epoch 以判定 round\_range 所属 validator 集；链上校验 `epoch` 与 `round_range` 一致性（round\_range 必须完全位于该 epoch 内，跨 epoch 的 round\_range 拒绝）；**R7-M7 修正 — block height 与 DAG round 映射**：1 个 DAG round 对应 1 个 block height（Bullshark 每轮 commit 投影产出 1 个 block），因此 `k = game_validator_timeout_blocks`（round 范围跨度 = block height 跨度）；(1) `vertex_list` 列出 assigned\_validator 在 [R, R+k] 内所有 vertex（round + author + vertex\_hash + tx\_merkle\_root）；(2) 完备性证明：通过 DAG commit certificate 结构验证 vertex\_list 覆盖所有 round（缺失即不完整）；**R4-M7 修正 — round 缺席见证生成机制**：每轮 Bullshark commit 形成时，commit certificate 中附带 `round_attendance_bitmap`（第 i 位标记 validator vi 该轮是否产出 vertex）；缺席见证无需独立签名 tx — 直接从 commit certificate 的 bitmap 派生（commit certificate 已含 ≥2/3 validator secp256k1 多签，bitmap 为 signed payload 一部分）；assigned\_validator bit=0 即 round 缺席证据；(3) `non_inclusion_proofs`：对每个 vertex 提供 Merkle 非包含证明（checkpoint\_anchor tx\_hash 不在 `tx_merkle_tree` 中，**R5-H4 — sparse Merkle tree 格式**）；(4) 裁剪约束：证据须在 `vertex_prune_after_blocks`（**默认 10000（NEW-M13 修复）**）内提交

#### Scenario: 委托逃生机制（含 C3 撤销注册表 + NEW-M1/NEW-M2/R4-H7 修正）

* **WHEN** 操作方离线，watchtower/参与者凭 `delegated_escape_authorization` 代为提交 `force_checkpoint`

* **THEN** 操作方预先签署 `delegated_escape_authorization` 凭证（`game_id` + 委托方 `tagged_pubkey` + `expiry_height` + `credential_nonce` + 操作方签名；**R4-H7 修正 — 签名对象 = `hash(chain_id || game_id || tagged_pubkey || expiry_height || credential_nonce)` 绑定 chain\_id 防跨链重放**）；链上 Game 对象维护 `delegated_escape_nonce: u64`（初始 0）；链上验证委托凭证有效性（签名 + **NEW-M2 修复 — `expiry_height` 为绝对 block height（非相对偏移），校验 `block.height <= expiry_height` 且 `expiry_height - tx.block_height <= delegated_escape_max_expiry_blocks`（默认 100，限制凭证最大有效窗口防长期未撤销滥用）** + game\_id 匹配 + `credential_nonce > Game.delegated_escape_nonce`）+ 代提交方签名后接受 `force_checkpoint`；**NEW-M1 修复 — 凭证一次性消费**：接受后链上执行 `Game.delegated_escape_nonce = credential_nonce`（消费该 nonce，防止同一凭证被多 watchtower 重复提交 force\_checkpoint spam）；**撤销机制**：定义 `revoke_delegated_escape` tx（任意 validator，正常计费 gas）：操作方签名 → `Game.delegated_escape_nonce += 1` → 所有旧 nonce 凭证失效；新凭证使用 `credential_nonce = Game.delegated_escape_nonce + 1`；**SEC2-L4 修复 — credential_nonce 消费时机**：(1) `credential_nonce` 仅在 force_checkpoint 被接受（evidence 验证通过）时消费；(2) force_checkpoint 被拒绝（evidence 无效）时，`credential_nonce` 不消费，watchtower 可重新提交（但须支付 gas）；(3) 同一 `credential_nonce` 的 force_checkpoint 提交频率限制：每 `turn_timeout_blocks` 最多 1 次（防 spam）；(4) `credential_nonce` 消费时机：force_checkpoint tx finality 后（非装入 vertex 时），防 vertex reorg 导致 nonce 误消费

#### Scenario: 多副本检测协议（NEW-M3 修复 + R4-M8/R5-L3/R5-M2 修正）

* **WHEN** 副本 validator 收到 checkpoint\_anchor 但发现 assigned\_validator 在 `game_validator_timeout_blocks` 内未装入 vertex

* **THEN** 副本 validator 签发"审查见证证据"（checkpoint\_anchor 内容哈希 + 接收时所在 block height + round 范围 + 副本 validator secp256k1 签名；**R4-H7 修正 — 签名对象 = `hash(chain_id || game_id || content_hash || block_height || round_range)` 绑定 chain\_id**）；**需 ≥3 个副本 validator 的见证签名方可构成有效 `assigned_validator_failure_proof`**（NEW-M3：由 2-of-N 提升至 3-of-N，防止单一或两个副本合谋伪造）；该见证证据可附在 `force_checkpoint` 的 `assigned_validator_failure_proof` 中，亦可独立提交治理 slashing 提案；副本 validator 不得直接把 checkpoint\_anchor 装入自己的 vertex；副本 validator 签发虚假见证证据 → 治理 slashing（罚没保证金，全额 `slash_percentage = 100%`）；**R4-M8 修正 — 副本 validator 确定性选择**：`replica_set = top_N(hash(game_id, epoch, round) % |V|, validator_set, N=checkpoint_multi_replica_count)`，取哈希值排序前 N 个 validator，非客户端自由选择 — 防恶意客户端选择合谋副本 validator 签发虚假见证证据陷害诚实 assigned\_validator（**R5-L3 修正 — replica\_set 计算使用 checkpoint\_seq 而非 DAG round，每 checkpoint\_anchor 提交时计算一次，稳定 ~5 blocks 无需每 block 重算**）；**SEC-M11 修复 — replica\_set 引入 VRF 随机源**：原 `hash(game_id, epoch, checkpoint_seq) % |V|` 为纯确定性哈希，attacker 可在游戏开始前预测整个游戏周期内所有 checkpoint 的 replica\_set（仅需 game_id + epoch + checkpoint\_seq），提前 corrupt 对应 validator；现引入 VRF 随机源：(1) 每 epoch 第一个 block 的 proposer 须提交 VRF proof `(random_output, vrf_proof)`（使用 VRF 算法如 ECVRF-secp256k1，私钥与 validator 签名密钥分离 — 专门的 `vrf_pubkey` 字段），链上验证 VRF proof 后将 `random_output` 写入 `epoch_randomness` 字段（永久保留）；(2) `replica_set = top_N(hash(game_id || epoch || checkpoint_seq || epoch_randomness) % |V|, validator_set, N)`，引入不可预测的 `epoch_randomness` 使 attacker 无法在 epoch 开始前预测 replica\_set；(3) VRF proof 验证失败的 block 被 validator 拒绝（视为恶意 proposer）；(4) 若 epoch 第一个 block proposer 离线（DAG 冗余下仍能 commit），使用 genesis `chain_randomness` 作为 fallback（确定性但不依赖单点）；(5) validator 集更新时 `vrf_pubkey` 同步更新，旧 VRF 输出保留用于历史证据验证（**SEC-C2 修复 — 小 validator 集安全降级强制约束**：原 R5-M2 修正"|V| < 5 时阈值降为 max(2, floor((|V|-1)*2/3))"在 |V|=3 时退化为 2-of-2 全合谋、|V|=4 时退化为 2-of-3，可伪造 assigned\_validator\_failure\_proof 陷害诚实 validator；现强制约束：(1) 主网 `chain_id` 下 |V| < 5 时 OffChain 模式 Game 创建被拒绝（返回 `ValidatorSetTooSmallForOffChain`），仅允许 OnChain 模式；(2) |V| >= 5 时方可启用 OffChain 模式；(3) testnet/devnet 不受此约束以便小规模测试；与下方 Validator 集更新 Scenario 的 `new_validator_set_size >= 5` 强制下限对齐）；**SEC2-C2 修复 — VRF input 绑定 epoch**：`VRF input = hash(chain_id || epoch || prev_epoch_randomness)`，绑定 `epoch` 防跨 epoch 重用 VRF output；绑定 `prev_epoch_randomness` 形成 randomness hash chain（每 epoch randomness 依赖上一 epoch randomness），增加不可预测性；链上验证 VRF proof 时校验 VRF input 包含当前 `epoch`，不匹配返回 `VrfInputMismatch`；**SEC2-M10 修复 — VRF 私钥销毁与 retired 标记**：(1) validator 退出时须提交 `vrf_key_destroy_proof`（VRF 私钥销毁证据），未提交则 unbonding 期延长；(2) 链上验证 VRF proof 时，校验 VRF output == 链上记录的 `epoch_randomness`，不匹配返回 `VrfOutputMismatch`；(3) VRF proof 仅用于验证 `epoch_randomness` 的正确性，replica_set 计算始终使用链上记录的 `epoch_randomness`（而非 VRF proof 中的 random_output）；(4) 退出 validator 的 `vrf_pubkey` 标记为 retired，后续 VRF proof 验证拒绝 retired vrf_pubkey；**SEC2-M12 修复 — epoch_randomness fallback 不可预测性**：(1) fallback 触发条件：epoch 第一个 block 的 proposer 在 `epoch_transition_window_blocks` 内未提交 VRF proof；(2) fallback 时 `epoch_randomness = hash(prev_epoch_randomness || genesis_chain_randomness)`，引入 `prev_epoch_randomness` 增加不可预测性；(3) fallback 连续触发上限：连续 3 个 epoch 触发 fallback → 治理调查 proposer DDoS 攻击；(4) DAG 冗余下，若原始 proposer 离线，接替的 validator 须提交 VRF proof（使用接替 validator 的 vrf_pubkey），而非立即 fallback；(5) 仅当接替 validator 也未提交 VRF proof 时，方触发 fallback

#### Scenario: request\_ack 触发 ack\_deadline（审查截断防护 — 参与者恶意拒 ACK + NEW-M7/R3-H6/R4-M2/R5-L6 修正）

* **WHEN** 操作方完成链下折叠并请求某参与者 P 的 ACK，但 P 在合理时间内未响应（链下 ACK 未到达）

* **THEN** 操作方提交 `request_ack` tx（任意 validator，免 gas），内容为 `(game_id, current_turn, state_hash, target_participant=P)`；链上设定 `ack_deadline = block.height + ack_deadline_blocks`（默认 3），写入 Game 对象的 `pending_ack_requests` 字段；**R3-H6 修正 — `request_ack` 不更新 `last_action_height`**（ACK 收集动作非游戏推进，更新会被操作方对不同 P 轮流提交滥用拖延 force\_advance）；**NEW-M7 修复 — 频率限制防 spam**：每个 Game 对每个参与者 P 同时只允许 1 个 active `pending_ack_request`（即同一 `(game_id, target_participant)` 在 `ack_deadline` 未过期前不得提交新的 `request_ack`，违反返回 `PendingAckExists`）；**R4-M2 修正 — 同一 Game 在 `turn_timeout_blocks` 内最多提交 `min(活跃参与者数, max_request_ack_per_turn_timeout)` 次 request\_ack**（默认 = 活跃参与者数，上限 10）无论针对哪个 P（违反返回 `RequestAckTooFrequent`，原 1 次过度限制正常 ACK 收集，多人游戏需多个参与者 ACK 无法在 1 个 turn\_timeout\_blocks 内完成）；**R5-L6 修正 — pending\_ack\_request 重置**：P 提交 ACK 或 refuse\_ack 后立即清除 (game\_id, P) 的 pending request，无需等 ack\_deadline 过期即可重新 request\_ack

#### Scenario: refuse\_ack 显式拒绝（带证据 + R4-H7 修正）

* **WHEN** 参与者 P 认为操作方提交的 state\_hash 错误或存在欺诈

* **THEN** P 在 `ack_deadline` 内提交 `refuse_ack` tx（任意 validator，免 gas），内容为 `(game_id, request_id, reason, evidence)`；**R4-H7 修正 — refuse\_ack 签名对象 = `hash(chain_id || game_id || request_id || reason)` 绑定 chain\_id 防跨链重放**；evidence 必须包含可验证的证明（如错误状态片段、签名失效证据）；链上记录拒绝但 **不立即判定**，进入 dispute 流程；若 P 拒绝但 evidence 验证失败 → P forfeit 该局保证金

#### Scenario: ack\_deadline 逾期 opt-out 默认 ACK（审查截断防护）

* **WHEN** `block.height > ack_deadline` 且 P 既未链下提供 ACK 也未链上提交 `refuse_ack`

* **THEN** 视为 P 默认 ACK（opt-out）；操作方可提交带 `opt_out_ack_proof` 字段的 checkpoint\_anchor（或 force\_checkpoint，若 checkpoint\_anchor 被审查），该字段包含 `request_ack` tx 所在 block height + 逾期证明；链上验证 `block.height > ack_deadline` 后接受该 checkpoint\_anchor / force\_checkpoint；该机制防止参与者恶意拖延导致操作方 force\_advance 误触发；**SEC2-H1 修复 — opt_out_ack_proof 滥用防护**：(1) `ack_deadline_blocks` 下限提升至 10（约 20 秒，覆盖典型网络抖动 + DDoS 切换时间），列入 90% quorum 敏感参数；(2) 操作方提交 `request_ack` 后须等待至少 `ack_grace_period_blocks`（默认 3）方可提交带 `opt_out_ack_proof` 的 checkpoint_anchor，给参与者额外响应窗口；(3) 批量 request_ack 检测：若操作方在同一 `turn_timeout_blocks` 内对所有活跃参与者提交 `request_ack`，触发批量 opt-out 审查警报，任意参与者可提交 `force_checkpoint` 强制要求操作方提供完整 ACK（非 opt-out）

#### Scenario: 治理 slashing 恶意 refuse\_ack

* **WHEN** 参与者多次提交 `refuse_ack` 但 evidence 验证失败

* **THEN** 累计 `malicious_refuse_count`，达到阈值（`malicious_refuse_threshold` 默认 3）后触发治理 slashing 流程；保证金罚没并分配给被恶意拒绝的操作方

#### Scenario: force\_advance 判定基于 checkpoint（S2 修复 + NEW-C2/R5-L1 修正）

* **WHEN** OffChain 模式下判断轮次超时

* **THEN** 判定基于 `block.height > last_action_height + turn_timeout_blocks`（**NEW-C2 修复 — 字段名统一为 `last_action_height`，原 `last_checkpoint_*` 别名已废弃合并**）；若操作方在 checkpoint\_interval 内提交了 anchor，则 `last_action_height` 已更新，不触发 force\_advance；若未提交，则超时判定成立；force\_advance 可由任意 validator 接受（escape hatch）；**R5-L1 修正 — force\_advance 自然频率限制**：每 turn\_timeout\_blocks 最多 1 次（每次触发后 last\_action\_height 更新，下一次需再等 turn\_timeout\_blocks 个 block），无需额外频率限制

#### Scenario: force\_checkin 可行性条件（S3 修复 + H4 修复 + NEW-M4/R3-M1/R3-M7/R5-M4 修正）

* **WHEN** 操作方扣留最终证明 π 或机器故障

* **THEN** force\_checkin 覆盖两种场景 — (1) 操作方已通过 checkpoint\_anchor 广播中间 state\_hash 但拒绝提交最终 checkin（恶意扣留）；(2) 操作方机器故障导致无法提交 checkin（机器故障）；两种场景下其他参与者均可基于已广播 checkpoint state 自行计算 `(π', Δ')`；机器故障场景下参与者可汇集签名动作日志从最后 ACKed checkpoint 重新折叠；force\_checkin 成功 → 游戏正常结算；纯扣留（无 checkpoint 广播）走 `request_revert`；**H4 修复 — forfeit 边界判定基于 `last_checkpoint_age = block.height - Game.last_action_height`（纯 timer 驱动，不要求故障证据；NEW-C2 修复：字段名统一为 `last_action_height`）**：`<= turn_timeout_blocks` → 恶意扣留 → forfeit；`> turn_timeout_blocks` → 机器故障 → 不 forfeit（参与者可重折叠）；与 `request_revert` 的 reason 字段语义兼容；**NEW-M4 修复 + R3-M1/R3-M7 修正 — 指定操作方场景**：若操作方为 designated operator（非当前轮次玩家），forfeit 边界加倍为 `last_checkpoint_age <= turn_timeout_blocks * 2`；force_advance 时**无条件豁免当前轮次玩家**（改为 check 而非 fold，**R3-M1 修正 — 不需"证明短暂网络抖动"，与纯 timer 驱动一致；豁免对象是当前轮次玩家而非 designated operator**）；**R3-M7 修正 — check 豁免次数上限**：Game 维护 `designated_operator_check_exemptions` 计数器，达上限（默认 2）后恢复 fold 语义，防恶意 designated operator 循环停发无限拖延（**SEC-H2 修复 — 重置条件加 state\_hash 变化校验**：`designated_operator_check_exemptions` 仅当 designated operator 提交的 checkpoint\_anchor 的 `state_hash` 与上一次不同（即有实际进度）时重置为 0；防 designated operator 提交无进度 checkpoint\_anchor（state\_hash 不变，仅 checkpoint\_seq +1）循环重置豁免权无限拖延；原 R5-M4 修正"成功提交 checkpoint\_anchor 时重置"被恶意 designated operator 滥用；**SEC-H2 修复 — 无进度检测**：连续 2 次 checkpoint\_anchor 的 state\_hash 相同 → 视为无进度，exemptions 不重置 + 记录 `no_progress_count`，达阈值（默认 2）触发 `force_revert`**）；反规避：停发 checkpoint\_anchor 超 turn\_timeout\_blocks 先触发 force\_advance（fold 损失筹码）

#### Scenario: 操作方故障恢复流程（3 阶段时间窗口，不要求故障证据）

* **WHEN** 操作方机器故障或恶意扣留

* **THEN** 纯 timer 驱动的恢复流程 — 阶段 1 `turn_timeout_blocks`（操作方可恢复，force\_advance 可触发，无 forfeit）；阶段 2 `da_window_blocks` + `recovery_window_blocks`（request\_da + 参与者重折叠 force\_checkin，窗口内无 forfeit）；阶段 3 forfeit + force\_revert（窗口过期 + 无 force\_checkin + 操作方未恢复 → forfeit 保证金 + 回退到最后 ACKed checkpoint）；**不要求故障证据**（任何证据可伪造，时间窗口不可伪造）；与 `request_revert` reason 字段语义兼容：阶段 1-2 内 `technical_interrupt` 无 forfeit；阶段 3 内 `technical_interrupt` 仍无 forfeit（reason 优先于阶段判定）；恶意滥用由参与者在阶段 3 提交 `force_revert`（reason=`malicious_withholding`）触发 forfeit

#### Scenario: 动作日志可选保存（H5 修复 — operator ack 签名 + 冲突裁决 + NEW-H5/R3-H3 修正）

* **WHEN** 链下执行每一步时，参与者可选保存签名动作日志

* **THEN** **日志格式为 `(game_id, step_index, action, state_hash_before, state_hash_after, participant_tagged_pubkey, participant_signature, operator_tagged_pubkey, operator_ack_signature)`** — 其中 `operator_ack_signature` 为操作方对 `hash(chain_id || game_id || step_index || action || state_hash_before || state_hash_after || participant_tagged_pubkey)` 的签名（**NEW-H5 修复：绑定 game\_id 防跨 Game 重放与栽赃 + R3-H3 修正：增加 chain\_id 防跨链重放**，确认该动作为规范执行）；保存日志的参与者在操作方故障后可汇集日志 → 校验 `participant_signature` 与 `operator_ack_signature` 有效 → 仅保留双签有效日志 → 从最后 ACKed checkpoint 重新执行 → 重新折叠为 π' → 提交 force\_checkin；缺少 `operator_ack_signature` 的日志仅作参考（操作方可事后否认）；未保存日志的参与者放弃重折叠权，只能依赖 request\_revert；动作日志非链上数据，不占链空间；操作方亦应保存完整执行轨迹；**H5 冲突裁决**：同一 `(game_id, step_index)` 的冲突日志条目（不同 action 或 state\_hash\_after）且两者均带有效 `operator_ack_signature` → 操作方 equivocation（双签）→ 链上验证冲突证据（含 game\_id 一致性校验，**NEW-H5**）后操作方 forfeit 保证金（与 vertex equivocation slashing 同语义）；仅一方有 operator ack → 以带 ack 条目为准；两方均无 → 无法裁决走 request\_revert；**反规避**：操作方无法对 A/B 签不同日志制造混乱（双签直接 forfeit），无法事后否认已签动作（非否认性），无法跨 Game 栽赃（game\_id 绑定）；参与者伪造 operator\_ack\_signature → 签名验证失败 → 伪造方 forfeit

#### Scenario: 链下参与者同步 checkpoint

* **WHEN** 链下参与者需判断是否超时

* **THEN** 参与者通过轻客户端订阅 block header + checkpoint\_anchor tx；若 `block.height > last_action_height + turn_timeout_blocks`，可提交 force\_advance（路由到任意 validator）

### Requirement: 链下执行 + ZK 折叠 + 强制同步 (Off-Chain Execution + ZK Folding + Force Sync)

The system SHALL allow OffChain mode Game state to be checked out, support off-chain execution with continuous folding proofs, and verify folded proofs on-chain. Force-sync mechanisms SHALL handle disputes with concrete tx types and resolution rules. challenge\_delta SHALL re-derive Δ from π (no witness needed).

#### Scenario: 链下折叠证明

* **WHEN** 链下执行 N 步游戏逻辑

* **THEN** 每步生成一个 CCS 电路实例，使用 Hypernova 折叠为单个最终证明 π，附状态增量 Δ；π 的 public\_io 包含 ack\_chain\_hash（所有正常 checkpoint ack 聚合）+ skip\_count（被跳过的 checkpoint 段数）+ segment\_continuity\_proof（段间连续性证明）

#### Scenario: 链上同步验证

* **WHEN** 玩家提交 `(π, Δ, new_commitment, ack_chain)` 作为 checkin 结算交易

* **THEN** 该交易走 Public 通道排序（路由到任意 validator）；链上 verifier 验证 π（含 ack\_chain\_hash 校验 + skip\_count 上限校验 + segment\_continuity\_proof 验证），通过后应用 Δ 更新 Game 对象

#### Scenario: checkpoint\_skip 机制（审查截断容错 — 中间 checkpoint 失败 + R4-M6/R5-H6 修正）

* **WHEN** 某 checkpoint 因审查 / ack\_deadline 逾期 / refuse\_ack dispute 等原因未能正常上链

* **THEN** 操作方提交 `checkpoint_skip` tx（任意 validator，免 gas，与 checkpoint\_anchor 同属 system tx 类别），内容为 `(game_id, skip_segment_start, skip_segment_end, last_known_state_hash, continuity_proof)`；**R4-M6 修正 — continuity\_proof 格式**：`continuity_proof = (start_state_proof, end_state_proof)`，`start_state_proof` 为 ≥2/3 参与者 ACK 签名聚合证据（签名对象 `hash(chain_id || game_id || checkpoint_seq || state_hash)`），证明 skip 段起点状态已被确认；`end_state_proof` 待下一 checkpoint 提交时隐式补全；链上校验 start\_state\_proof 签名有效性 + 签名者 ≥2/3 活跃参与者 + state\_hash == last\_acked\_checkpoint.state\_hash；失败 → checkpoint\_skip 被拒绝，操作方必须提交 request\_revert；该 tx 仅更新 `last_action_height = block.height` 与 `skip_count += 1`，**不推进 ack\_chain\_hash**；连续 skip 上限 `max_skip_segments`（默认 3），超出则操作方必须提交 `request_revert` 回退到最后已知 commitment；**R5-H6 修正 — end\_state\_proof 终态验证（verify\_segment\_chain() 算法）**：(1) 连续 skip 段间 end\_state == 下段 start\_state；(2) skip 结束回退时 end\_state == last\_acked\_checkpoint.state\_hash；(3) skip 后 checkin 时 end\_state == π.initial\_commitment；(4) 任一断裂 → 拒绝 + forfeit；**SEC-M6 修复 — skip 段 ack 一致性显式校验**：原设计仅校验 skip 段起点 ≥2/3 ACK，但未明确 skip 期间 ACK 集合的连续性 — 攻击者可在 skip 段中静默移除参与者（如拒绝 fold/sit-out 玩家继续签名），使下一 checkpoint ACK 集合人为缩减至 < 2/3 即可伪造；现强制：(1) skip 段提交时 `start_state_proof` 须包含**完整活跃参与者集合**（与上一正常 checkpoint 的 ack\_set 完全一致，不允许在 skip 段中变更 ack\_set）；(2) 若 skip 段期间有玩家 fold（链上 fold tx 已确认），ack\_set 收缩须在 `start_state_proof` 中显式记录 fold 证据 + 缩减后的 ack\_set；validator 校验 ack\_set 收缩合法（仅 fold/sit-out 触发）+ 收缩后仍 ≥2/3 活跃玩家；(3) skip 后下一 checkpoint 的 ack\_set 须 == skip tx 中记录的 ack\_set（含合法收缩），不匹配返回 `AckSetMismatch`；(4) 连续 skip 段间 ack\_set 不可静默变化

#### Scenario: skip\_count 与 ack\_chain\_hash 的关系

* **WHEN** 链上 verifier 验证最终 π

* **THEN** ack\_chain\_hash 仅包含正常 checkpoint 的 ack 聚合（跳过段不参与）；skip\_count 必须 <= `max_skip_segments`；segment\_continuity\_proof 必须证明"跳过段起点状态 == 上一正常 checkpoint 终点状态"且"跳过段终点状态 == 下一正常 checkpoint 起点状态"；任一校验失败 → checkin 被拒绝，操作方进入 forfeit 流程

#### Scenario: 轮次超时强制推进

* **WHEN** 当前轮次玩家在 `turn_timeout_blocks` 内未提交 GameTurn tx（OnChain）或未提交 checkpoint\_anchor（OffChain）

* **THEN** 任何参与者可提交 `force_advance` tx（路由到任意 validator）；超时玩家按 fold 处理（弃牌失去本轮投入），除非当前轮次无人下注且该玩家在大盲位（按 check 处理）（M6 修复）；更新 `current_turn` 与 `last_action_height`

#### Scenario: force\_advance 的 fold/check 规则（M6 修复）

* **WHEN** force\_advance 触发

* **THEN** 默认超时 = fold（玩家弃牌，失去本轮已投入筹码）；例外：当前下注轮无人加注（current\_bet == 0 且无 raise）且超时玩家是大盲位，则超时 = check（过牌，不丢失筹码）；规则由协议层定义，合约可覆盖；**SEC2-L5 修复 — fold/check 规则边界修正**：(1) preflop 阶段，当前下注轮无人 raise（即 `current_bet == big_blind_amount` 且 `raise_count == 0`）且超时玩家是大盲位，则超时 = check；(2) postflop 阶段，当前下注轮无人下注（`current_bet == 0` 且 `bet_count == 0`），则任何超时玩家 = check（不仅限大盲位）；(3) 规则由协议层定义，合约可覆盖

#### Scenario: 证明扣留强制 checkin

* **WHEN** OffChain 模式下操作方已提交 checkpoint\_anchor 但扣留最终 π

* **THEN** 任何参与者可提交 `force_checkin` tx（任意 validator），基于已广播的 checkpoint state 自行计算 `(π', Δ')` 提交；若操作方连 checkpoint 也扣留，走 `request_revert` 回退到最后已知 commitment；扣留方按 forfeit 规则处置

#### Scenario: challenge\_delta 语义澄清（S5 修复 + NEW-H4 修复 + R4-L7 修正）

* **WHEN** 提交的 π 验证通过，但 Δ 与 π 的 public\_io 推导出的状态增量不一致

* **THEN** 任何参与者可在 `dispute_window_blocks` 内提交 `challenge_delta` tx（任意 validator）；**R4-L7 修正 — 挑战方保证金机制**：challenge\_delta 提交方须预锁挑战保证金 = `buy_in_amount * challenge_deposit_ratio / 100`（**SEC-C4 修复 — `challenge_deposit_ratio` 默认值由 10 提升至 50**（与 forfeit\_deposit\_ratio 同量级），提高恶意挑战成本，防 griefing 攻击方通过恶意挑战迫使操作方游戏回退；可治理 ∈ [1, 100]）；链上从 π 的 public\_io 重新派生 `state_delta_hash`（不需 witness，因 public\_io 已包含 `state_delta_hash`），对比 hash(提交的 Δ) 与 `state_delta_hash`；若 hash(提交的 Δ) == `state_delta_hash` → Δ 与 π 一致，挑战失败，挑战方 forfeit 保证金（恶意挑战惩罚，保证金没收分配给被挑战方作补偿）；若不一致 → 提交方 forfeit 保证金，**NEW-H4 修复 — `state_delta_hash` 不可逆性**：`state_delta_hash` 为 hash，链上无法从中逆推正确 Δ'（challenge 仅能比对 hash 不一致，不能恢复 Δ 用于继续执行），因此**触发 `request_revert` 回退到最后 ACKed checkpoint\_state 重新结算**（reason=`malicious_withholding`），而非"应用正确 Δ 继续"；挑战成立 → 挑战方保证金退还 + 从操作方 forfeit 保证金分得奖励（**SEC-C4 修复 — `challenge_reward_ratio` 默认值由 50 提升至 100**，激励挑战方发现 Δ 不一致，因发现需链下重新执行计算成本高；可治理 ∈ [10, 100]）；**SEC-C4 修复 — forfeit 保证金分配规则明确**：挑战成立后操作方 forfeit 保证金分配 = `挑战方得 challenge_reward_ratio %（默认 100%），剩余按 buy_in 比例分配给其他受害者玩家`；**SEC-C4 修复 — 多玩家 game 经济安全**：forfeit 保证金应覆盖桌面总 buy-in（所有玩家 buy-in 之和），而非仅操作方 buy-in（见下方 forfeit 保证金机制 Scenario 的 SEC-C4 修正）；防恶意挑战方无成本骚扰；**SEC2-L6 修复 — 时间窗口边界统一**：`dispute_window` 边界判定：`block.height <= checkin_block.height + dispute_window_blocks`（包含边界，挑战方在边界 block 内可挑战）；所有时间窗口（`turn_timeout_blocks` / `ack_deadline_blocks` / `da_window_blocks` / `recovery_window_blocks` 等）统一采用 `<=` 边界判定（包含边界），spec 全局统一

#### Scenario: request\_revert / force\_revert tx（NEW-H4 修复 — reason 枚举）

* **WHEN** 操作方故障、恶意扣留证明、或数据不可用

* **THEN** 任何参与者可提交 `request_revert` / `force_revert` tx（任意 validator），内容为 `(game_id, last_acked_checkpoint, reason)`；`reason` 枚举：`technical_interrupt` / `malicious_withholding` / `data_unavailable`；**`reason=technical_interrupt` → 回退到最后 ACKed checkpoint\_state，操作方不 forfeit**（技术中断豁免）；`reason=malicious_withholding` 或 `data_unavailable` → 回退 + 按 forfeit 规则处置；与故障恢复流程兼容：阶段 1-2 内 `technical_interrupt` 无 forfeit；阶段 3 内 `technical_interrupt` 仍无 forfeit（reason 优先于阶段判定）；恶意滥用由参与者在阶段 3 提交 `force_revert`（reason=`malicious_withholding`）触发 forfeit；**R7-M6 修正 — 防操作方抢跑 technical\_interrupt 避免 forfeit**：阶段 3 内操作方本人提交 `force_revert` / `request_revert`（reason=`technical_interrupt`）**被拒绝**（返回 `OperatorCannotClaimTechnicalInterrupt`）— 阶段 3 的 `technical_interrupt` 豁免仅限非操作方参与者提交（操作方在阶段 3 已超 `da_window_blocks + recovery_window_blocks`，不构成"技术中断"），操作方在阶段 3 只能由其他参与者提交 `force_revert`（reason=`malicious_withholding`）触发 forfeit，防恶意操作方反复扣留证明后抢先提交 technical\_interrupt 无成本 griefing

#### Scenario: partial\_checkin 折叠中断恢复（NEW-M5/NEW-M6/NEW-C2/R3-M2/R3-H3/R4-M1/R4-M5/R5-M5/R5-M6 修正）

* **WHEN** 链下折叠中断，操作方需提交 π\_partial 锚点供恢复后继续

* **THEN** 定义 `partial_checkin` tx（任意 validator，escape hatch 类，正常计费 gas）：`(game_id, π_partial, folded_step_count=N, intermediate_commitment, ack_chain_partial)`；链上 verifier 验证 π\_partial（与最终 π 相同的 public\_io 边界格式，`fold_step_count = N`，`final_commitment = intermediate_commitment`）；验证通过后链上记录 `last_partial_fold = (intermediate_commitment, N, π_partial_hash, ack_chain_partial_hash)`，**不应用 Δ（不结算）**，仅作"已折叠到第 N 步"锚点；操作方恢复后从该锚点继续折叠；**NEW-C2 修复**：不推进 `last_action_height`（partial\_checkin 非操作方活动，仅锚点）；不触发 forfeit；**SEC-H1 修复 — 提交次数上限**：每 Game 最多提交 `max_partial_checkin_count`（默认 3，可治理 ∈ [1, 10]）次 partial\_checkin，超出则操作方必须提交完整 checkin 或触发 `request_revert`（防操作方反复提交 partial\_checkin 但 folded\_step\_count 不递增无限拖延）；**SEC-H1 修复 — 进度校验**：每次 partial\_checkin 的 `folded_step_count` 必须严格大于上一次记录的 `N`（防操作方提交无进度锚点拖延），违反返回 `NoProgressPartialCheckin`；可多次提交（每次覆盖 `last_partial_fold`）；**R5-M6 修正 — partial\_checkin tx 签名域**：`hash(chain_id || game_id || π_partial_hash || folded_step_count || intermediate_commitment || ack_chain_partial_hash)`，操作方签名，绑定 chain\_id 防跨链重放；**R5-M5 修正 — ack\_chain\_partial\_hash = MerkleRoot(ack_chain[0..N])**，使用与 ack\_chain\_hash 完全相同的 RFC 6962 构造，确保 partial\_checkin 与完整 checkin 算法一致性

#### Scenario: ack\_chain\_hash 算法（NEW-M5 修复 + R3-M2/R3-H3/R4-M1/R4-M5 修正）

* **WHEN** 构造 π 的 public\_io 中的 `ack_chain_hash` 或 `ack_chain_partial_hash`

* **THEN** **`ack_chain_hash = MerkleRoot(ack_1 || ack_2 || ... || ack_n)`**，其中 `ack_i = hash(chain_id || epoch || game_id || current_turn || state_hash || checkpoint_seq || ack_domain_tag || participant_tagged_pubkey || participant_signature)`（**SEC-C3 修复：增加 `epoch` 与 `ack_domain_tag`（0x02），与 ACK 签名域一致**；**R3-H3/R4-H3 修正：增加 chain\_id 绑定防跨链重放**；Merkle 根结构保证顺序 + 防篡改）；**R3-M2/R4-M5 修正 — RFC 6962 风格 domain separation 防二次原像攻击**：叶子节点哈希为 `H(0x00 || ack_i)`，内部节点哈希为 `H(0x01 || left_child || right_child)`（区分叶子与内部节点）；**R4-M1 修正 — 边界情况**：空树 → `H(0x00 || b"")`（**SEC-L5 修复 — 明确 empty 叶子值 = 空字节串 `b""`**），单叶子 → `H(0x00 || ack_1)`，不平衡树 → RFC 6962 filled subtree 补齐 `H(0x00 || b"")`；skip 段不参与 ack\_chain；**SEC2-M4 修复 — ack_chain 长度上限**：(1) `ack_chain` 最大长度 = `max_ack_chain_length`（默认 1000，可治理 ∈ [100, 10000]）；(2) 超过 `max_ack_chain_length` 时，操作方须提交 checkin 结算（强制结算）或 request_revert；(3) `ack_chain_hash` 构造采用增量 Merkle 树（每追加一个 ack 仅 O(log n) 计算），防全量重构成本；(4) `checkpoint_interval_blocks` 下限提升至 3（防操作方每 block 提交 checkpoint_anchor 增加 ack_chain 长度）

#### Scenario: partial\_checkin 与完整 checkin 衔接（NEW-M6 修复）

* **WHEN** 操作方恢复后提交完整 checkin tx

* **THEN** 完整 checkin tx 签名域（**R5-M6 修正**）：`hash(chain_id || game_id || π_hash || state_delta_hash || new_commitment || ack_chain_hash)`，操作方签名；链上校验 π\_final 的 `initial_commitment` == 已记录的 `intermediate_commitment` 且 `fold_step_count = M - N`（本次折叠步数）；**NEW-M6 修复 — ack\_chain 前缀校验**：完整 checkin 时链上校验完整 `ack_chain[0..N]` 的哈希 == `last_partial_fold` 中记录的 `ack_chain_partial_hash`，防止操作方切换 ack\_chain 上下文；校验通过 → 应用 Δ 结算 + 清除 `last_partial_fold`；无 partial\_checkin 记录时向后兼容（`fold_step_count` 为总步数）；**SEC2-M8 修复 — partial_checkin 与完整 checkin race condition**：(1) 完整 checkin tx 须显式声明 `has_partial_checkin: bool` 字段；(2) `has_partial_checkin = true` 时，validator 校验 `last_partial_fold` 存在且 `ack_chain[0..N]` 哈希匹配；(3) `has_partial_checkin = false` 时，validator 校验 `last_partial_fold` 不存在（防操作方先提交 partial_checkin 再用 `has_partial_checkin = false` 绕过校验）；(4) 完整 checkin 装入 vertex 后，partial_checkin tx 被拒绝（返回 `GameAlreadyCheckedIn`）；(5) partial_checkin 与完整 checkin 同 commit 内时，partial_checkin 先执行（commit 级 S9 规则），完整 checkin 后执行并校验

#### Scenario: GameTurn fallback 接受（NEW-H2 修复 + R3-H4/R3-H5/R4-H6 修正）

* **WHEN** assigned\_validator 在 `game_validator_timeout_blocks`（默认 2）内未装入 GameTurn tx

* **THEN** 客户端可向任意非 assigned\_validator 提交该 tx（附 `assigned_validator_timeout_proof` — 含原始 tx + 提交时间戳 + **多副本广播证据（R3-H4 修正 — 需 ≥3 个副本 validator secp256k1 签名见证，使用与 force\_checkpoint 相同的阈值公式 `required_witness_count = max(3, floor(checkpoint_multi_replica_count * 2 / 3))`（3-of-5）（R4-H6 修正 — 原 2-of-N 阈值过低，fallback 允许非 assigned\_validator 接受 GameTurn tx 绕过轮转排序独占权，2-of-5 合谋即可伪造 timeout\_proof）** + round 范围非包含证明，复用 C6 格式）；非 assigned\_validator 验证 timeout\_proof 后接受装入自己的 vertex；fallback tx 走 Public 通道正常计费 gas（区别于正常 GameTurn 免 gas）；**R3-H5 修正 — fallback tx 执行排序仍按 GameTurn 通道语义**（current\_turn 排序），S9 规则同样适用，防 Public 通道与 GameTurn 通道并行执行导致轮转约束校验顺序不确定；fallback tx 使用 `gameturn_nonce`（NEW-M9）；更新 `last_action_height`；**SEC-H7 修复 — fallback tx nonce 竞态处理**：(1) fallback tx 装入 vertex 时，validator 须校验 assigned\_validator 在 `game_validator_timeout_blocks` 内确实未装入同 `gameturn_nonce` 的 GameTurn tx（通过 DAG round 范围非包含证明，复用 C6 sparse Merkle 格式，与 assigned\_validator\_failure\_proof 同源）；(2) 若 fallback tx 与原 GameTurn tx 同 `gameturn_nonce` 都进入 commit（如网络延迟导致原 tx 在 timeout 后到达 assigned\_validator），以 Bullshark 排序中先执行的 tx 为准（先执行的成功推进 `gameturn_nonce`，后执行的因 nonce 不匹配被拒绝并返回 `DuplicateGameTurnNonce`）；(3) 后执行的 fallback tx 已付 gas，可通过 `refund_tx` 退回 gas（refund tx 免 gas，由 validator 自动构造）；(4) 若先执行的是 fallback tx，原 GameTurn tx 后到则同样被拒绝（fallback tx 优先执行后 `gameturn_nonce` 已推进，原 tx nonce 不匹配）

#### Scenario: forfeit 保证金机制（R4-L6 修复 + R5-H3 修正）

* **WHEN** Game 创建时操作方预锁 forfeit 保证金，或触发 forfeit 时分配

* **THEN** **R4-L6 修正**：Game 创建时操作方预锁 forfeit 保证金 = `total_table_buy_in * forfeit_deposit_ratio / 100`（**SEC-C4 修复 — 保证金基数由"操作方 buy\_in\_amount"改为"桌面总 buy-in（所有玩家 buy-in 之和）"**：原设计在多玩家 game 中操作方 forfeit 100% buy-in 远小于总底池，操作方有强烈动机伪造 Δ 窃取底池；现保证金覆盖桌面总 buy-in，确保操作方 forfeit 足以补偿所有受害者；`forfeit_deposit_ratio` 默认 100 即等额桌面总 buy-in，可治理 ∈ [10, 200]）；保证金存入 `Game.forfeit_deposit` 字段；触发 forfeit 时全额扣除分配给受害参与者（按 buy-in 比例）；forfeit 保证金独立于 slashing 保证金；Game 结算后未触发 forfeit 则退还操作方；**R5-H3 修正 — designated operator forfeit 保证金**：若操作方为 designated operator（非玩家，无 buy\_in\_amount），forfeit 保证金 = `designated_operator_bond_amount`（可治理，**SEC-L8 修复 — 默认 = 桌面所有玩家 buy-in 的中位数 median(buy\_in)，避免异常值拉高平均**）；Game 对象增加 `designated_operator_bond` 字段；任命 tx 为 `(game_id, operator_pubkey, bond_amount, expiry_height)` 签名 `hash(chain_id || game_id || operator_pubkey || bond_amount || expiry_height)`；**SEC2-M7 修复 — designated_operator bond_amount 强制校验**：(1) 任命 tx 中的 `bond_amount` 须 == 当前治理参数 `designated_operator_bond_amount`，操作方不得自行设置（validator 校验不匹配返回 `InvalidBondAmount`）；(2) `designated_operator_bond_amount` 须 >= 桌面总 buy-in（与 `forfeit_deposit_ratio = 100` 对齐），validator 校验 `bond_amount >= total_table_buy_in`，不满足返回 `InsufficientOperatorBond`；(3) 任命 tx 须由所有参与玩家签名确认（防操作方单方面设置低 bond），签名对象 = `hash(chain_id || game_id || operator_pubkey || bond_amount || expiry_height || player_tagged_pubkeys)`

#### Scenario: 数据不可用强制发布

* **WHEN** 操作方未在 `da_window_blocks` 内发布链下状态到链上或 DA 层

* **THEN** 任何参与者可提交 `request_da` tx（任意 validator）；逾期未发布触发 `force_revert` 回退到最后已知 commitment

#### Scenario: 整局超时兜底结算

* **WHEN** 一局超过 `hand_max_duration_blocks` 仍未结算

* **THEN** 任何参与者可提交 `force_settle` tx（任意 validator），强制按最后已知 commitment 结算，未行动方 forfeit

#### Scenario: 挑战窗口与惩罚保证金

* **WHEN** 一局 OffChain 模式结算完成

* **THEN** 进入 `dispute_window_blocks` 挑战窗口；窗口内无有效挑战则结算最终化；挑战成立则败方 forfeit 保证金

### Requirement: 状态裁剪与存储管理 (State Pruning & Storage)（M2 修复 + NEW-M13/R5-M7 修正）

The system SHALL define a pruning strategy: settled Game objects' historical versions SHALL be prunable after dispute window expiry, while state root commitments SHALL be retained permanently for light client verification. DAG vertex content SHALL be prunable after `vertex_prune_after_blocks`. ZK proofs SHALL be archived to Walrus DA layer after Game settlement + dispute expiry.

#### Scenario: 结算后历史版本裁剪

* **WHEN** Game 对象结算（owner = Immutable）且 `dispute_window_blocks` 已过

* **THEN** 节点可裁剪该 Game 对象的中间版本数据（仅保留最终版本 + 所有版本的状态根承诺）；裁剪不影响 state root 验证

#### Scenario: 历史 tx 内容压缩（M2 扩展）

* **WHEN** block 距 finality 过 `tx_prune_after_blocks`（默认 1000）+ block 内所有 Game 结算 + dispute 过期

* **THEN** 节点可丢弃完整 tx 内容，仅保留 `(tx_hash, tx_type, merkle_proof)`；block header 的 `tx_merkle_root` 永久保留以支持存在性证明

#### Scenario: DAG vertex 压缩（NEW-M13 修复）

* **WHEN** vertex 所在 round 距 finality 过 `vertex_prune_after_blocks`（**默认 10000（NEW-M13 修复 — 由 1000 统一提升至 10000，与 round 范围非包含证明证据保留期一致）**）

* **THEN** 节点丢弃 `tx_list` + `parent_hashes` 详情，保留 `(round, author, vertex_hash, tx_count, parent_count, author_sig)`；Bullshark 共识仍正常运行

#### Scenario: ZK proof 归档到 Walrus DA 层（R5-M7 修正）

* **WHEN** checkin 的 (π, Δ, ack_chain) 所在 Game 结算 + `dispute_window_blocks` 过期

* **THEN** π 移到 Walrus DA 层，链上仅保留 `(proof_hash, verification_result, walrus_blob_id)`；**R5-M7 修正 — Walrus DA 集成规范**：(1) 付费由 Game 创建时预扣 `da_storage_fee` 从 `forfeit_deposit` / `buy_in` 扣除；(2) `proof_hash = blake2b(π || Δ || ack_chain)` 链上存储，检索 blob 后重新计算 hash 验证完整性；(3) `da_storage_fee` 覆盖 `dispute_window_blocks` + `archive_retention_blocks`，blob 过期时 archive node 续费；(4) blob 不可用时 `request_historical_data` 返回 `HistoricalDataUnavailable`，不影响链上最终性；archive node 数量 < `archive_node_min_count`（默认 3）时不得裁剪；**SEC-M7 修复 — Walrus blob 多副本续费 + 失败处理**：(1) 每个 ZK proof blob 在 Walrus 上传时强制 `replica_count >= 3`（Walrus shard 多副本冗余，单点失效不影响检索）；(2) 续费责任由所有 archive node 共担（任一 archive node 续费成功即可，避免单 archive node 故障导致 blob 过期）；(3) 续费资金来源：Game 创建时预扣的 `da_storage_fee` 优先，预扣资金耗尽后由 chain treasury 兜底（治理预算），treasury 资金不足时触发"blob 过期警告期"（默认 1000 block）提示社区抢救；(4) 续费失败处理：blob 确认过期（Walrus API 返回 not found）→ 链上状态标记 `proof_blob_expired = true`，`request_historical_data` 返回 `HistoricalDataUnavailable`，但 `proof_hash` 与 `verification_result` 仍永久保留（链上 finality 不受影响，仅历史数据可检索性受损）；(5) 治理可触发"blob 重上传"提案：由任一 archive node 从本地存档重新上传至 Walrus（须附 `proof_hash` 完整性校验）

#### Scenario: State root commitment 永久保留

* **WHEN** 节点裁剪历史版本

* **THEN** 每个 block 的 state root（Sparse Merkle Root）永久保留；轻客户端可验证任意历史 block 的 state root 而不需要完整对象数据

#### Scenario: 节点角色分层

* **WHEN** 节点配置为不同角色

* **THEN** (a) archive node（永不裁剪，提供 `request_historical_data` RPC）；(b) full node（Layer 1-3 裁剪）；(c) light node（仅 block header + state root commitment 订阅）；archive node 响应延迟 < 5s；**SEC-M3 修复 — archive node 经济激励**：原"archive node 数量不足时 full node 自动升级为 archive mode"为义务无激励，会导致 full node 消极配合或拒绝升级（存档成本高、无回报）；现改为：(1) 治理预算从 chain treasury 拨付 `archive_reward_per_block`（默认 0，可治理 > 0）按 archive node 数量平分，每个 epoch 结算一次；(2) archive node 须质押 `archive_bond_amount`（默认 = 1 validator 质押金额的 10%），SLA 违约（响应延迟 > 5s 持续 > 1000 block）扣除部分 bond；(3) `request_historical_data` RPC 由请求方支付微 gas（按返回数据量计费），收入归响应的 archive node；(4) 治理可指定 `mandatory_archive_validators`（强制 validator 节点兼 archive 职责，作为兜底）；(5) archive node 数量 < `archive_node_min_count`（默认 3）时，治理触发"招募期"提高 `archive_reward_per_block` 激励自愿升级，而非强制 full node；**SEC2-M5 修复 — archive node 勾结检测与惩罚**：(1) archive node 须定期提交存储证明（proof of storage，类似 Filecoin 的 PoSt），证明其仍持有完整历史数据；(2) 存储证明频率：每 epoch 提交一次，随机抽样 N 个历史 block 的 state root + tx_hash 进行验证；(3) 存储证明失败 → 扣除 `archive_bond_amount` 的 50%，连续 2 次失败 → 全额扣除 + 移出 archive node 列表；(4) 参与者可提交 archive node 拒服务证据（request_historical_data 请求 + archive node 拒绝响应日志 + 多副本请求见证），治理 slashing archive node；(5) archive node 数量 < `archive_node_min_count` 时，强制 `mandatory_archive_validators` 兜底

#### Scenario: Compact Block Relay 协同

* **WHEN** tx 内容被裁剪

* **THEN** short ID 映射表随 tx 内容一起裁剪；archive node 维护完整映射；新节点 fast sync 跳过历史 short ID

#### Scenario: 永久保留项

* **WHEN** 任何裁剪操作

* **THEN** 永久保留：block header / ValidatorSet 变更记录（含 slashing 证据 + 罚没金额）/ 治理参数变更记录（参数名 / 旧值 / 新值 / 生效 height）/ Game 最终结算版本 + 台费分配 / slashing 证据（vertex equivocation / 停机 / 恶意 refuse\_ack 累计）；**SEC-M8 修复 — 永久保留项清单补全**：原清单遗漏多项安全审计与争议解决所需证据，补全：(1) `force_checkpoint` evidence 全量（含 `assigned_validator_failure_proof` + multi-replica receipt signatures + 申辩记录 + 申辩佐证 validator gossipsub 日志 hash）；(2) `challenge_delta` 争议证据（含挑战方提交的 state_delta_hash + 旧 commitment + challenge_deposit 扣除记录 + challenge_reward 发放记录）；(3) `request_revert` 回退证据（含回退前 commitment + 回退后 commitment + 触发原因）；(4) ZK proof 的 `proof_hash` + `verification_result` + `walrus_blob_id`（即使 blob 过期也保留 hash 链）；(5) `partial_checkin` 锚点记录（`last_partial_fold` 完整字段，防后续 checkin 衔接断裂）；(6) `rotate_validator_key` tx 完整记录（含旧/新 pubkey + timelock 期 + slashing 证据窗口）；(7) `UpgradeCap` 升级 tx 记录（含新字节码 hash + timelock 期 + cancel/dispute 记录）；(8) `verifier_status` 切换记录（含 chain_id + 旧/新状态 + 治理提案 hash + 投票记录）；(9) validator `under_investigation_count` 累积记录（含每次调查的 evidence hash + 申辩结果 + 衰减历史）；(10) 桥操作 `burn_on_source` + `mint_on_target` 凭证（含 nonce + recipient + source_tx_hash）；所有永久保留项写入 archive node 但 full node 可仅保留最近 N=10000 block 的详情以节省存储

#### Scenario: 全节点可选归档模式

* **WHEN** 节点配置为 archive mode

* **THEN** 该节点保留所有历史版本不裁剪，供数据查询与同步使用；非 archive 节点可从 archive 节点按需请求历史数据

#### Scenario: 轻客户端 validator 集同步（R4-L5 修正 + R5-H5/R5-M8 修正）

* **WHEN** 轻客户端从 trusted checkpoint 同步到最新状态

* **THEN** **R4-L5 修正**：从 trusted checkpoint 获取 `validator_set_hash` → 请求后续 `ValidatorSetUpdate` tx 链 → 逐个验证签名 + quorum → 推导当前 ValidatorSet → 验证最新 commit certificate；允许轻客户端从任意 trusted checkpoint 同步到最新状态无需下载全链历史；**R5-H5 修正 — ValidatorSetUpdate tx 格式**：`(epoch, prev_validator_set_hash, new_validator_set, new_validator_set_hash, signer_bitmap, signature_list)`，签名域 `hash(chain_id || epoch || prev_validator_set_hash || new_validator_set_hash)`，threshold = 2/3 of `prev_validator_set`；**hash chain**：每个 tx 的 `prev_validator_set_hash` 必须等于上一个 tx 的 `new_validator_set_hash`，防中间 tx 被隐瞒；**R5-M8 修正 — 轻客户端状态验证**：`state_root` 为 Sparse Merkle Tree root（对象 keyed by ObjectID）；全节点提供 `get_state_proof(object_id)` RPC 返回 `(object_data, sparse_merkle_path)`；轻客户端用 state\_root 校验 path 验证对象真实性，支持链下参与者 trustless 验证 Game 状态

### Requirement: 治理与参数管理 (Governance & Parameter Management)（M11 修复 + NEW-M8/NEW-M12/NEW-C1/R3-H1/R3-M4/R4-H4/R4-M3/R5-H8/R5-L5/R5-L7 修正）

The system SHALL support on-chain parameter adjustment via validator supermajority (2/3) vote, with timelock delay before生效, parameter boundary validation, and 90% supermajority for sensitive parameters. Governable parameters SHALL include timeout parameters, vertex/DAG parameters, slashing parameters, `verifier_status`, and validator set membership.

#### Scenario: 参数调整提案

* **WHEN** validator 提交参数调整提案（parameter\_name, new\_value）

* **THEN** 提案进入投票期（`voting_period_blocks`，默认 ∈ [10, 10000]）；其他 validator 可投赞成/反对票；提案 new\_value 必须在参数边界内（见下文"参数边界校验"Scenario），越界提案投票期即拒绝

#### Scenario: 参数调整执行（NEW-M8 修复 + R3-M4/R3-H1 修正）

* **WHEN** 投票期结束

* **THEN** **普通参数**赞成票 >= 2/3 validator 集 → 通过；**R3-H1 修正 — 敏感参数 90% quorum（补全 8 项）**：以下参数需 90% validator 赞成（非 2/3）：`block_gas_limit` / `epoch_length_blocks` / `validator_set 更新` / `slash_percentage` / `downtime_slash_percentage` / `verifier_status`（否则 2/3 合谋可降级为 Stub 使操作方伪造 π）/ `parameter_delay_blocks`（否则可降至 0 使 timelock 失效）/ `defense_window_blocks`（否则可降至 0 使被指控 validator 无申辩时间）；**SEC-H4 修复 — 敏感参数 90% quorum 补全 9 项**：以下参数因同等安全影响亦需 90% quorum：`bonding_period_blocks`（否则 2/3 合谋降至 epoch_length_blocks 缩短 Sybil 攻击准备时间）/ `unbonding_period_blocks`（否则 2/3 合谋降至 epoch_length_blocks 使 validator equivocation 后快速退出提取质押，slashing 证据提交窗口过短）/ `key_rotation_delay_blocks`（否则 2/3 合谋降至 100 使旧密钥 slashing 证据窗口过短）/ `checkpoint_multi_replica_count`（否则 2/3 合谋降至 3 使合谋门槛退化为 3-of-3）/ `archive_retention_blocks`（否则 2/3 合谋降至 1000 使 Walrus blob 快速过期历史 ZK proof 丢失）/ `max_skip_segments`（否则 2/3 合谋升至 10 削弱 ack_chain 完整性）/ `turn_timeout_blocks`（否则 2/3 合谋降至 3 使链下参与者因区块传播延迟误判超时 force_advance 误触发）/ `malicious_refuse_threshold`（否则 2/3 合谋升至 100 使恶意 refuse_ack 几乎永不触发 slashing）/ `max_request_ack_per_turn_timeout`（否则 2/3 合谋降至 1 阻断多人游戏 ACK 收集）；**SEC-C2 修复 — `validator_set_size` 亦列入 90% quorum 敏感参数**（防 2/3 合谋缩减 validator 集至 < 5）；**NEW-M8 修复 + R3-M4 修正 — timelock**：提案通过后**不立即生效**，进入 `parameter_delay_blocks`（**默认 2000（R3-M4 修正 — 由 500 提升至 2000，按 block interval ≤ 2s 计约 67 分钟，给参与者充足时间发现恶意提案并退出）**）timelock 延迟期方可生效（防闪电式参数调整攻击），**SEC-H8 修复 — timelock 撤销机制明确**：timelock 内可由 **≥ 90% validator 赞成**（高于原通过 quorum，防原通过方 2/3 合谋阻止撤销）的反对提案撤销，撤销提案**无 timelock 立即生效**（防原提案在 timelock 内生效）；撤销提案仅可在原提案 timelock 期间提交，timelock 结束后无法撤销（已生效参数需重新发起反向提案）；**SEC2-M6 修复 — 治理投票 quorum 分母明确**：(1) quorum 分母 = 当前 epoch 的权威 validator 集大小（全部 validator，包括离线）；(2) 投票参与率下限 = 2/3（即至少 2/3 validator 参与投票方可计票，防 DDoS 降低分母）；(3) 敏感参数（90% quorum）的投票参与率下限 = 90%；(4) 投票期结束未达参与率下限 → 提案自动否决（防 DDoS 阻断治理）；(5) 新增 DDoS 检测：若投票期内 validator 离线率突增 > 30%，治理可延长投票期

#### Scenario: 参数边界校验（R4-H4/R5-H2/R5-M3 修正）

* **WHEN** 提交参数调整提案

* **THEN** 越界提案投票期即拒绝：`turn_timeout_blocks ∈ [3, 1000]`、`max_interval_ms ∈ [500, 60000]`、`block_gas_limit ∈ [10M, 200M]`、`epoch_length_blocks ∈ [100, 10000]`、`slash_percentage ∈ [1, 100]`、`downtime_slash_percentage ∈ [1, 100]`、`parameter_delay_blocks ∈ [100, 10000]`、`defense_window_blocks ∈ [10, 1000]`、`checkpoint_multi_replica_count ∈ [3, 15]`、`delegated_escape_max_expiry_blocks ∈ [10, 1000]`、`game_validator_timeout_blocks ∈ [1, floor(turn_timeout_blocks / 2)]`（R5-H2）、`ack_deadline_blocks ∈ [1, 100]`、`max_skip_segments ∈ [1, 10]`、`max_active_games_per_player ∈ [1, 1000]`、`bonding_period_blocks ∈ [epoch_length_blocks, 10*epoch_length_blocks]`、`downtime_threshold_blocks ∈ [10, 10000]`、`voting_period_blocks ∈ [10, 10000]`、`under_investigation_threshold ∈ [1, 100]`、`max_designated_operator_check_exemptions ∈ [0, 10]`、`hand_max_duration_blocks ∈ [turn_timeout_blocks*4, 100000]`、`archive_node_min_count ∈ [1, 100]`、`recovery_window_blocks ∈ [10, 10000]`、`checkpoint_interval_blocks ∈ [1, 1000]`、`da_window_blocks ∈ [10, 10000]`、`dispute_window_blocks ∈ [10, 10000]`、`tx_prune_after_blocks ∈ [100, 100000]`、`epoch_transition_window_blocks ∈ [1, 100]`（R5-M3 修正 — 否则 slash\_percentage 可降至 0 使 equivocation 无经济惩罚）、`unbonding_period_blocks ∈ [epoch_length_blocks, 10*epoch_length_blocks]`（R7-H2 修正 — 防治理降为 0 绕过 R5-H7 slashing 防护）、`malicious_refuse_threshold ∈ [1, 100]`（R7-M1 — 防设为 0 griefing 或极大值使恶意 refuse\_ack 永不触发）、`max_request_ack_per_turn_timeout ∈ [1, 100]`（R7-M1 — 防设为 0 阻断 ACK 收集或极大值使频率限制失效）、`max_vertex_size ∈ [64KB, 4MB]`（R7-M1 — 防极小值致 vertex 无法容纳正常 tx 或极大值致网络 DoS）、`designated_operator_bond_amount ∈ [1, 10^9]`（R7-M1 — 必须为正，防 designated operator 无保证金约束）、`key_rotation_delay_blocks ∈ [100, 10000]`（R7-M2 — 防密钥轮换 timelock 失效使旧密钥 slashing 证据失效）、`max_clock_drift_ms ∈ [0, 60000]`（R7-M3 — 链下参与者软参考用，非共识硬校验）、`forfeit_deposit_ratio ∈ [10, 200]`（R7-M4）、`challenge_deposit_ratio ∈ [1, 100]`（R7-M4）、`challenge_reward_ratio ∈ [10, 100]`（R7-M4）、`archive_retention_blocks ∈ [1000, 1000000]`（R7-M5 — 防 Walrus blob 过期致历史 ZK proof 丢失）、`validator_set_size ∈ [5, 1000]`（**SEC-C2 修复 — 强制主网 validator 集下限 5，与 OffChain 模式 |V|>=5 约束对齐，列入 90% quorum 敏感参数**）、`max_partial_checkin_count ∈ [1, 10]`（**SEC-H1 修复 — partial_checkin 提交次数上限，默认 3，防操作方无限拖延**）

#### Scenario: 可治理参数完整列表（NEW-M12/R4-M3/R5-H8 修正）

* **WHEN** 治理调整任意参数

* **THEN** 可治理参数完整列表：`turn_timeout_blocks` / `hand_max_duration_blocks` / `dispute_window_blocks` / `da_window_blocks` / `recovery_window_blocks` / `checkpoint_interval_blocks` / `game_validator_timeout_blocks` / `ack_deadline_blocks` / `max_skip_segments` / `malicious_refuse_threshold` / `max_interval_ms` / `max_active_games_per_player` / `epoch_length_blocks` / `max_vertex_size` / `block_gas_limit` / `tx_prune_after_blocks` / `vertex_prune_after_blocks` / `archive_node_min_count` / `checkpoint_multi_replica_count` / `delegated_escape_max_expiry_blocks` / `defense_window_blocks` / `parameter_delay_blocks` / `epoch_transition_window_blocks` / `bonding_period_blocks` / `slash_percentage` / `downtime_slash_percentage` / `verifier_status`（敏感参数 90% quorum）/ `downtime_threshold_blocks` / `voting_period_blocks` / `max_designated_operator_check_exemptions` / `under_investigation_threshold`（R4-M3 修正 — 原 4 个参数缺失可治理列表）/ `max_request_ack_per_turn_timeout` / `max_clock_drift_ms` / `forfeit_deposit_ratio` / `challenge_deposit_ratio` / `challenge_reward_ratio` / `designated_operator_bond_amount` / `unbonding_period_blocks` / `key_rotation_delay_blocks` / `archive_retention_blocks`（R5-H8 修正 — 补全遗漏可治理参数；R7-M2/M5 修正 — 补全 key\_rotation\_delay\_blocks 与 archive\_retention\_blocks）

#### Scenario: verifier\_status 治理切换（NEW-C1 修复）

* **WHEN** 治理切换 `verifier_status`

* **THEN** `verifier_status` flag（`Stub` / `Production`）由治理设置，初始为 `Stub`；合约层在 `execution_mode = OffChain` 时校验 `verifier_status`，`Stub` 状态下主网 `chain_id` 拒绝 OffChain checkout（返回 `OffChainDisabledOnMainnet`）；治理将 `verifier_status` 升级为 `Production` 后方可主网启用 OffChain 模式；testnet/devnet 不受限制；`verifier_status` 为敏感参数，需 90% validator 赞成（防 2/3 合谋降级为 Stub 使操作方伪造 π）；**SEC-M4 修复 — verifier\_status 命名空间隔离**：`verifier_status` 为 per-`chain_id` 状态（每个网络独立），存储为 `BTreeMap<chain_id, VerifierStatus>` 而非全局单一 flag；防"在 testnet 将 verifier\_status 升级为 Production 后通过 fork 复用到 mainnet"或"mainnet 治理误降级 testnet 状态"等命名空间混淆；治理提案须明确目标 `chain_id`，validator 校验提案 `chain_id == network_chain_id` 一致方可生效；testnet/devnet 的 `verifier_status` 由各自网络治理独立设置（testnet 治理 quorum 阈值可低于 mainnet 的 90%）；mainnet 链上硬编码 mainnet `chain_id` 的初始 `verifier_status = Stub`，首次升级为 Production 须经 mainnet 治理 90% quorum + `parameter_delay_blocks` timelock 双重保护

#### Scenario: Validator 集更新（R5-L5/R5-L7 修正）

* **WHEN** 治理提案加入/踢出 validator

* **THEN** 提案通过后 validator 集在下一个 epoch 边界更新；新 validator 需质押保证金 + 经历 `bonding_period_blocks`（默认 = 1 epoch）锁定期；**SEC-C2 修复 — validator 集下限提升至 5**：治理提案校验 `new_validator_set_size >= 5`（原 R5-L7 的 >= 3 在 3-of-3 合谋即可控制共识，且与 SEC-C2 的 OffChain 模式 |V|>=5 强制约束对齐），拒绝将 validator 集缩减至 < 5 的提案；**SEC-M2 修复 — 单次缩减比例限制**：治理提案校验 `removed_count / prev_validator_set_size <= 0.2`（单次最多踢出 20% validator），防一次踢出过多诚实 validator 导致共识被瞬时控制；**R5-L5 修正 — validator 密钥轮换**：`rotate_validator_key` tx（旧密钥签名 `hash(chain_id || old_pubkey || new_pubkey || block_height)` + 新密钥确认），有 `key_rotation_delay_blocks` timelock，期间旧密钥仍可用于 slashing 证据；**SEC2-H5 修复 — epoch 边界 commit certificate grace period**：(1) commit certificate 验证使用 epoch 权威 validator 集，由 commit certificate 中的 epoch 字段决定（与 SEC-C1 修复一致）；(2) epoch N 的 commit certificate 必须由 epoch N 的 validator 集 2/3 签名；(3) epoch N+1 的 commit certificate 必须由 epoch N+1 的 validator 集 2/3 签名；(4) 不存在跨 epoch 的 commit certificate grace period（与 gossipsub grace period 不同 — gossipsub 是网络层容忍，共识层是硬性约束）；(5) epoch 边界 block 的 commit certificate 须同时包含旧集与新集的 2/3 签名（过渡 commit），防任一集单方面控制

### Requirement: 网络层约束 (Network Constraints)（M12 修复）

The system SHALL define DAG vertex size limits, block size limits, tx size limits, and compact block relay for propagation efficiency. No mempool SHALL be used.

#### Scenario: DAG vertex 容量上限

* **WHEN** validator 打包一个 vertex

* **THEN** vertex 序列化后 <= `max_vertex_size`（默认 256KB）；超出分多个 vertex；vertex 内 tx 数量无硬上限，受 vertex 大小约束

#### Scenario: Block 与 tx 大小上限

* **WHEN** DAG 共识 commit 一个 block

* **THEN** block 序列化后 <= 4MB；单个 tx 序列化后 <= 128KB；超出限制的 tx 被拒绝（返回 `TxTooLarge`）

#### Scenario: Compact Block Relay

* **WHEN** DAG vertex 在 P2P 网络中传播

* **THEN** validator 先广播 compact vertex（vertex header + tx short IDs）；接收 validator 从本地已收 tx 集合匹配，仅请求缺失的 tx；减少带宽消耗；**SEC2-L3 修复 — short ID 冲突处理**：(1) short ID 长度 = 8 字节（64 bit），冲突概率 < 2^-32；(2) 接收 validator 匹配 short ID 时，若多个 tx 匹配同一 short ID，请求完整 tx hash 消歧；(3) validator 维护 short ID → tx hash 映射表，映射表大小有上限（防内存膨胀）；(4) short ID 冲突时，validator 请求完整 vertex（fallback），不依赖 short ID 匹配

#### Scenario: 无 mempool

* **WHEN** validator 收到 tx

* **THEN** tx 直接装入下一个 vertex；不维护 gossiped pending tx pool；validator 内存中仅保留待装入 vertex 的 tx 短暂缓冲（默认 100ms 内必装 vertex）；消除 mempool DoS 攻击面（O1 移除）

### Requirement: 跨链桥模块 (Cross-Chain Bridge Module, Reserved)（M7 修复）

The system SHALL reserve a cross-chain bridge module interface with security constraints: protocol-layer verification, burn-on-source requirement, and nonce replay protection.

#### Scenario: 桥接口预留

* **WHEN** 后续需要接入一条外部链

* **THEN** 实现者可通过 `BridgeHook` trait + `bridge_verify` syscall 注册新桥；`bridge_verify` 必须由协议层在 deposit 流程中调用，不允许任意合约直接调用伪造"已验证"信号

#### Scenario: 资产锁定与铸造（含安全约束）

* **WHEN** 桥接资产从外部链进入 poker\_l1

* **THEN** 桥模块锁定外部链资产凭证（由桥验证器签名背书）；**SEC-H3 修复 — 签名绑定字段补全 `recipient` 与 `source_tx_hash`**：签名绑定 `(nonce, source_chain_id, dest_chain_id, asset, amount, recipient, source_tx_hash)`（**`recipient` 字段绑定 poker\_l1 上的接收地址（tagged pubkey 派生地址），防签名被 frontrun 重放到错误接收者** — 原设计缺失 recipient，攻击者可观察合法桥 deposit 签名后抢先提交 bridge\_verify 将资产铸造到攻击者地址；**`source_tx_hash` 用于跨链追踪**）；防重放由 `nonce` + `dest_chain_id` 保证；在 poker\_l1 上铸造对应 wrapped 对象给 `recipient`；反向操作需 burn wrapped 对象 + burn proof；**SEC2-M1 修复 — bridge_verify 抢跑防护**：(1) `bridge_verify` tx 须由 recipient 本人签名提交（绑定 recipient tagged pubkey），防第三方抢跑；(2) 若桥协议允许任意第三方提交（去中心化 relayer），则 gas 奖励按 first-come-first-served 分配，但 spec 须明确奖励来源（如桥手续费的一部分）；(3) recipient 可指定 `preferred_relayer` 字段，优先 relayer 提交时获额外奖励，其他 relayer 仅获基础 gas 退款

## MODIFIED Requirements

### Requirement: 真理之源

原有 zgame 项目以 Sui L1 + Move 合约为真理之源。poker\_l1 上线后，poker\_l1 自身成为真理之源；Sui 适配层降级为可选镜像。

## REMOVED Requirements

### Requirement: 依赖 Sui RPC 进行状态同步

**Reason**: poker\_l1 原生提供 RPC 与状态查询，不再依赖 Sui fullnode
**Migration**: `texas/src/relayer/sui_query` 后续替换为 `poker_l1_query`；本 spec 不强制迁移时间表

### Requirement: PoA + Leader Rotation 单 leader 出块（原 S1 方案）

**Reason**: 单 leader 出块存在 SPOF 与审查瓶颈；Narwhal-Bullshark DAG 共识提供更高并行性、更强抗审查、零延迟失败转移
**Migration**: 无需迁移（本 spec 首次发布即采用 DAG 共识）

### Requirement: Mempool 与 Mempool 驱逐策略（原 O1 方案）

**Reason**: DAG 数据平面天然冗余传播 tx，无需 gossiped pending tx pool；移除 mempool 消除 DoS 攻击面
**Migration**: 无需迁移（本 spec 首次发布即无 mempool）

## Known Limitations（非 MVP 范围，后续迭代）

* **MEV 风险（M5）**：Public 通道按 (gas\_price, arrival) 排序存在 MEV 风险（三明治攻击、validator 重排）；MVP 不实现加密 mempool / threshold encryption，作为已知风险接受；未来可通过 PBS 或加密 mempool 缓解

* **创世状态（O3）**：初始 token 分发、初始 validator 集、初始合约部署在部署阶段定义，非本 spec 范围

* **权限模型（O7）**：MVP 允许任何账户部署合约与创建 Game；未来可增加白名单或治理审批

* **事件体系（O5）**：MVP 仅定义 `emit_event(payload)` 原语；完整事件 schema 与索引留待后续

* **错误码表（O6）**：spec 中提到的错误码（NotYourTurn / NotStaked / TooManyActiveGames / InvalidNonce / InvalidSubgroup / UnknownScheme / MissingAck / InputTooLong / NotAssignedValidator / TxTooLarge）在实现阶段统一编排

* **Tournament 跨 validator 协调**：MVP 阶段 tournament 在合约层用多个独立 Game 表达，不跨 validator 协调；v2 可考虑 tournament 整体绑定一个 assigned\_validator

* **DAG 同步与状态同步**：新节点加入时需从 archive 节点同步历史 DAG vertex 与 state；快速同步协议留待实现阶段

## Phasing

本 spec 覆盖完整愿景。tasks.md 按 MVP-first 分阶段：

* **Phase 1–2**: 链骨架 + 对象模型 + 账户抽象 + 多曲线签名 + Narwhal-Bullshark DAG 共识 + 游戏分配 + 双模式排序 + 时间共识（可独立验证的最小可用链）

* **Phase 3–4**: rBPF VM（含 gas 表 + 合约升级）+ BLS12-381 预编译（含子群检查）

* **Phase 5**: 链下执行通信协议 + ZK 证明验证模块 + 强制同步与争议解决 + 状态裁剪

* **Phase 6–7**: 网络节点 + 治理 + 跨链桥接口预留 + 端到端集成测试

