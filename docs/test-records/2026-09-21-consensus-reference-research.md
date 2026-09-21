# 共识参考实现调研与偏差分析（2026-09-21）

目的：在继续修改多 validator 共识之前，先对照 Narwhal/Bullshark（Sui 上一代）与
Mysticeti（Sui 现役）的**真实源码**，搞清楚整套 DAG BFT 算法的每个环节，再逐点
审视 zchain 当前实现的结构性偏差。此前多轮"打补丁式"修复（L2 成熟度门、L4 意图
稳定门、L5 投票钉扎、波冻结、空产出配速、straggler 跳跃……）每个都在治某个症
状，但相互耦合、顾此失彼——本文档回答"参考实现里这些机制为什么根本不需要存在"。

## 1. zchain 当前实现完整地图（源码级）

### 1.1 Vertex 生产（src/main.rs validator loop，~L3555-3960）

- **轮次推进：纯定时器驱动**。每周期 `wait_for_pending_tx(block_interval=1s)` 超时
  或 tx 唤醒；多 validator 空产出再加 3s 配速（`EMPTY_VERTEX_PACE`，L3728）。
- **round 取值**：`round = 自身 last_vertex.round + 1`；落后前沿 >2 轮时跳到
  `max_r - 1`（straggler 跳跃，L3811）。
- **parents**：`ref_round`（= 自身 last 所在轮）的**全部**不同 author vertex（含
  自己）；`validate_parents` 要求 ≥ quorum（4 节点 = 3），不足则整轮回排 tx +
  请求补洞（L3855-3887）。
- 广播：先 tx 后 compact vertex；2s 周期全窗口（64 个）重播未提交自家 vertex。

### 1.2 Commit 检测与出块（L3962-4470）

1. **候选收集**：全部未提交 vertex 按 (round, author, hash) 规范序
   （`canonical_commit_candidates`），过滤：round ≤ max_r-2（L2 成熟度门）+
   引用 quorum 预检。
2. **detect_commit_leader**（bullshark.rs L175）：统计引用某 vertex 的
   **不同 author 数**（扫描 leader_round+1 起**所有后续轮次**，L192），≥2/3 即
   CommitLeader。`referencing_hashes` = 这些引用者的集合。
3. **波闭合检查**（L4106）：leader_round+1 轮的作者集必须完整（缺席者要么为 0，
   要么该波龄 ≥ COMMIT_ABSENCE_ROUNDS=4 才视为终态）。
4. **引用叶缺口扫描**（L4145）：find_missing_parent_vertices 定位缺失引用叶。
5. **投影**（canonical_commit_projection L2754 → attempt_commit_projection）：
   referencing_hashes 的祖先闭包（不降入 committed），fail-closed 报缺。
6. **L4 意图稳定门**（L4251）：连续两个生产周期 (height, leader, 投影) 相同才签票。
7. **L5 CommitVote 投票面**（L4339）：对
   `cert_signing_hash = H(投影+leader+epoch+tip 四元组)` 签名，gossip 广播；
   同 (epoch, commit_round) 钉扎 5s 防双票。票在 P2P accept 线程验证入池
   （L2294），validator loop 每周期 peek。
8. **凑齐 2/3 票** → **仅 commit leader 装配块**并广播（L4430）；leader 5s 超时
   则 follower 兜底装配。其余节点经 gossip 块验证（cert 多签+重放+state_root）
   接受。
9. 块头携带 `dag_commit_certificate`（cert_signing_hash + 2/3 签名列表）。

### 1.3 关键观察（待对照参考实现验证的疑点）

- **O1 引用集无界**：detect_commit_leader 从 leader_round+1 起扫**所有**轮次的
  引用。迟到节点看到的引用集更大 → 投影更大 → cert_signing_hash 不同 → 各节点
  对不同 cert 签票（实测 WAITING-VOTES votes=2/3 反复出现）。
- **O2 无固定 leader**：每轮没有预定的 leader，靠"首个过 quorum 预检的规范序候
  选"事后发现。任何视角差异（成熟度边界、波闭合时机、缺口）→ 各节点选中不同
  候选 → 投票分散。
- **O3 第二投票面**：CommitVote 是独立于 DAG 的 gossip 面，自带丢票/双票/钉扎/
  兜底装配等一整类故障模式。
- **O4 定时器驱动轮次**：frontier 无界竞跑 commit（实测 frontier 819 vs cert
  264），于是需要成熟度门压投影、需要空产出配速对齐、需要 straggler 跳跃。
- **O5 leader-only 装配**：块产出被装配者可用性 gate，需要 5s 兜底。

## 2. 参考实现调研结论

### 2.1 Mysticeti（MystenLabs/mysticeti，Sui 现役；crate `mysticeti-core`）

- **A 轮次推进 = threshold clock（凑票驱动，非定时器）**：收到 round r 的 2f+1
  权益区块即进入 r+1（threshold_clock.rs:58-72）；出块门控 `clock_round >
  last_proposed`（core.rs:232-235）；round r 块的 includes 必须含 r-1 轮 quorum
  （types.rs:371-374）。定时器（leader_timeout=2s）只是活性兜底：超时
  `force_new_block` 绕过"等 leader 块"的门控（net_sync.rs:423-428）。
- **B Leader = 每波一个（wave_length=3），轮数种子确定性抽样**；生产配置
  `enable_pipelining=true` 时 3 个 committer 偏移 0/1/2 并行，**等效每轮都是
  某个 committer 的 leader 轮**（universal_committer.rs:163-165）。
- **C 精确 commit 规则（3 轮一波）**：round L 的 leader 块 X；round L+1 的块
  因果历史上"支持"X 即**票**（is_vote，base_committer.rs:113-125）；round L+2
  的块 includes 含 2f+1 票即为 X 的 **certificate**（:158-178）；**决策轮出现
  2f+1 个 certificate → 直接提交**（:323-343）；跳过 = 投票轮 2f+1 块不含
  leader 任何块（enough_leader_blame，:228-248）；间接提交经后续已提交 anchor
  的因果历史（:294-318）。顶层从 `highest_known_round - 2` 向低遍历，输出最长
  已决定前缀（universal_committer.rs:38-45,76-81）。
- **D 投票完全隐含在 DAG 里**：**没有 CommitVote 网络消息**；certificate 不是
  落地对象，各节点从本地 DAG 重算；commit 结果仅本地 WAL（core.rs:485-490）。
- **E 出块/输出 = 每节点本地确定性推导**：Linearizer 以每个 leader 为锚对其
  因果历史 BFS 去重产出 CommittedSubDag（linearizer.rs:130-148），轮内排序
  "任意确定性算法均可"（:67-70）。**没有 leader 装配**。
- **F 活性三件套**：blame 跳过 + leader_timeout 2s 强制出块 + 缺块双路 sync
  （对等推送流 SubscribeOwnFrom + 250ms 采样回拉缺失，批量 50/请求）。
  **没有"冻结波/缺席窗口"概念**。
- **G 默认参数**：wave_length=3、leader_timeout=2s、retain 500 轮、
  pipelining=true。
- **H 安全性根**：不禁止同轮双签（拜占庭可出多个块）；includes **顺序**决定
  每个 (author,round) 只"支持"第一个块（first-support 消歧）；quorum 交集保
  证至多一块被 certify（遇双 certify 直接 panic，base_committer.rs:213-215）。

**对 zchain 最刺眼的三条**：(1) 我们的 CommitVote 是独立网络消息面——参考实现
里票就是 DAG 边；(2) 我们的 commit 由 validator loop 事后扫描发起——参考实现
是收块后本地 `try_commit` 纯函数推导；(3) 我们 detect_commit_leader 扫
leader_round+1 起**所有**轮的引用——参考实现的票**只在 L+1 轮**、cert
**只在 L+2 轮**，天然有界、天然冻结。

### 2.2 Narwhal/Bullshark（源码研读结论，MystenLabs/narwhal，archived main）

要点（与 Mysticeti 相互印证，行号为该仓库 main 分支）：

- **A 轮次推进 = 双驱动**：凑齐上一轮 2f+1 certificates 是**必要条件**
  （primary/aggregators.rs:90-96，凑满后 weight 不清零、后续 certificate 继续
  追加为额外 parents——Bullshark commit 判定所需）；`max_header_delay=100ms`
  超时或 payload 攒够是充分触发（proposer.rs:235-239）。
- **B Leader**：每个偶数轮恰一个，按轮数种子 stake 加权**确定性抽样**
  （config/lib.rs:564-577），非轮转；纯函数全网一致。
- **C commit 规则**（仓库实现是论文 2209.05633 的简化版）：leader ℓ_r 被
  commit ⟺ round r+1 中 **f+1 stake 的 certificate 的 parents 直接包含 ℓ_r**
  （单层边；bullshark.rs:66-82）。跳过 = 无 f+1 支持即不提交，内容由后续
  leader 的 causal history 兜底；回溯提交用 order_leaders 的"路径可达"
  （utils.rs:20-37）而非全量历史。
- **D 投票两层**：header→certificate 的真实签名投票（2f+1 单播给作者聚合为
  BLS 聚合签名）；共识投票 = DAG 边，无独立共识消息。
- **E 输出 = 本地确定性推导**：DFS 前序展开 leader causal history，跳过已
  提交，sort_by_key(round)，全局递增 consensus_index。
- **F 等价防护**：投票者不二签（vote_digest_store）+ 聚合器拒绝重复投票者
  + header 强制 parents 全来自上一轮且 2f+1。
- **G 参数**：max_header_delay=100ms、gc_depth=50、sync_retry_delay=5s。

**对本设计的额外启发**：(1) 诚实 proposer 在 leader 轮会**先等 leader 的
certificate 再出下一轮**（PartiallySynchronous 分支，proposer.rs:139-153）——
未等待就产出等于投永久非支持票 → zchain 生产侧 leader 等待的依据；
(2) 凑 quorum 后继续追加 parents——引用集是"至少 quorum"而非恰好的全量。

## 4. 实施记录与实测（2026-09-21）

按 §3.3 方案实施，另含三个实测暴露问题的追修：

1. **wave-3 固定 leader 扫描**（bullshark.rs `evaluate_leader_wave` /
   `round_leader_index` + main.rs 扫描重写）：删除 L2/L4/GAP-LEAVES/
   canonical 候选序；6 个新单元测试。
2. **genesis epoch = 1**（node/mod.rs）：消除每次冷启动的 0→1 中途翻转
  （实测 node_2 在翻转窗口视角分叉、卡死在高度 4）。8 个测试夹具同步。
3. **tip 同代快照**：fold 与 tip 四元组同代读取——cycle 中途到达的块不再
   产生「旧投影 × 新 tip」杂交语句（实测 h4 票数 1/2 分裂卡死）。
4. **未决轮间接裁决**（ABSORB/SKIP-INDIRECT）：2/2 分票的未决轮由更晚
   可提交波的闭包裁决（Mysticeti 间接规则本地等价），扫描不再永久阻塞。
5. **生产侧 leader 等待 800ms**（仅前沿处）：减少伪 blame。
6. **多提交排水**（每周期最多 8 pick，投影增量排除）+ **投票微等待 800ms**
   （当周期收齐即装配）+ 空产出配速 1s + 块间隔 500ms：frontier-commit
   lag 从 ~22 轮压到 ~3 轮。

### 4.1 本地 4 节点实测（4 分片桥真实负载，WAL 3029 手结算）

| 阶段 | 配置 | 吞吐 | 备注 |
|------|------|------|------|
| 旧实现（canonical 扫描 + L2/L4/L5） | interval 1s | ~240/h | frontier 819 vs cert 264；60s/笔 |
| wave-3 + genesis 修复 | interval 1s, pace 3s | ~240/h | 死锁解除、四节点一致，但 lag~15 轮 |
| + 多提交排水 | interval 1s, pace 1s | ~860/h | lag~22 轮（生产反超消费） |
| + pace 2s | interval 1s | ~732/h | lag~14，消费也被拖慢 |
| + 投票微等待 | interval 500ms, pace 1s | **~4305/h** | lag≈3 轮；4.5s/笔/分片 |

4305/h ⟹ 2773 手全量重锚 ≈ 39 分钟。测试套件：poker_l1 1921 通过 +
zchain 17 通过（含 6 个新增 wave 单测）。

### 4.2 遗留事项

- D6（threshold clock 式凑票推进轮次）未对齐：当前仍为定时器驱动 +
  validate_parents 准入校验，实测足够。
- CommitVote 平面保留为出块证据（D4 方案 B）；cert 签名子集因装配者而异，
  本地推导块字节仍不同——若未来要全节点本地装配，需先定块字节规范化
  （如 cert 签名按 signer 序截断前 quorum 个）。
- 插桩（[wave]/WAITING-VOTES/ABSORB）为 INFO 级，量产后可降 debug。

## 3. 逐点偏差分析与重构方案

### 3.1 偏差总表

| # | 决策点 | 参考（Mysticeti） | zchain 现状 | 后果 |
|---|--------|-------------------|-------------|------|
| D1 | 票的来源 | 仅 round L+1 的 vertex（有界、天然冻结） | leader 后**所有**轮次的引用（无界、随视角增长） | 投影随视角变化 → cert_signing_hash 各节点不同 → 投票分散（WAITING-VOTES votes=2/3） |
| D2 | leader | 每轮/每波**预定**（轮数确定性函数） | "首个过 quorum 预检的规范序候选"事后发现 | 任何视角差 → 各节点选不同候选 → 票各奔东西 |
| D3 | commit 触发 | 收块后本地纯函数推导（try_commit） | validator loop 周期扫描 + L4 意图稳定门（连两周期） + L5 钉扎 | commit 慢 + 补丁机群 |
| D4 | cert 证据 | DAG 图案本身（无可选子集） | CommitVote 消息面（丢票/双票/兜底装配一整类故障） | 保留但语义改变：从"凑共识"降级为"出块证据"，自然收敛 |
| D5 | 出块 | 每节点本地确定性推导 | leader-only 装配 + 5s 兜底 | 保留（cert 签名子集因装配者而异，本地推导块字节不同；leader-only 是既定解） |
| D6 | 轮次推进 | threshold clock（凑 2f+1 进轮），定时器仅兜底 | 纯定时器 + 3s 配速 + straggler 跳跃 | frontier 竞跑；有界波后竞跑无害，暂保留 |
| D7 | 活性 | blame 跳过 + leader 超时强制出块 + 双路 sync | 波冻结（COMMIT_ABSENCE_ROUNDS）+ 缺席窗口 | 被 blame/轮龄判定取代 |

### 3.2 安全性论证（为什么可以砍掉 L2/L4/波冻结）

- **准入层拒绝等价**（node/mod.rs L2061-2074：同 (epoch, round) 不同内容 →
  VertexEquivocation）→ 每个 (author, round) 至多一个 vertex → 本地视图恒为
  全局 DAG 的子集（无需 first-support 消歧，比 Mysticeti 更强的前提）。
- **commit 与 skip 互斥（quorum 交集）**：同轮的"支持者集"与"非支持者集"对
  每 author 互斥，两个 quorum 在 4 节点必交（3+3>4）→ 全局 DAG 中不可能同时
  存在 quorum 支持与 quorum 指责 → 任何两个节点的（皆为全局子集的）局部视图
  也不可能一个 commit 一个 skip。
- **投影确定性**：波 = (L, L+1, L+2) 三轮定死；票只数 L+1、cert 只数 L+2；
  投影 = leader 祖先闭包（parents 不可变）→ 语句 = (DAG, committed) 的纯函数
  → 各节点必然算出同一 cert_signing_hash，L4 意图门失去存在必要。
- **轮界推进自愈**：leader vertex ∈ committed → 该轮跳过；投影 Empty → 该轮
  已消化 → 游标前进。commit 严格按轮序，序列全局一致。

### 3.3 实施方案（wave-3 固定 leader 本地推导）

1. `bullshark.rs` 新增：
   - `round_leader_pubkey(sorted, r) = sorted[r % n]`（轮转，pipelining 等效
     每轮皆有 leader）。
   - `evaluate_leader_wave(dag, leader_hash, r, vc) -> WaveOutcome`：
     - votes = round r+1 中 parents 含 leader 的 vertex（按 author 去重）
     - certs = round r+2 中 parents ∩ votes 按 author 数 ≥ quorum 的 vertex
     - `Commit{votes, certs}` / `Skip`（r+1 非 supporter ≥ quorum，或 leader
       缺失且轮龄 ≥ COMMIT_ABSENCE_ROUNDS）/ `Undecided`
   - 保留 `detect_commit_leader`（单 validator 路径与既有测试用）。
2. `main.rs` validator loop 的 commit 段重写：
   - 删除：canonical 候选扫描、L2 成熟度门、L4 意图稳定门、波冻结作者检查、
     GAP-LEAVES 预检。
   - 新增：`scan_from` 游标，按轮序 `for r in scan_from..=max_r`：leader ∈
     committed → r++；投影 Empty → r++；Skip → r++；Commit → 走既有
     cert 签名→投票→leader 装配流程（L5 钉扎保留为保险）；Undecided →
     break（含 leader 缺失时对 r..r+2 窗口发补洞请求）。
   - 投影根从"引用集闭包"改为"leader 祖先闭包"（attempt_commit_projection
     以 [leader_hash] 为根）。
3. 生产/轮次推进/重播/补洞机制全部不动（D6 留待后续对齐 threshold clock）。
4. 块格式不变；put_block 不重推投影 → 旧链块仍有效。

## 3. 逐点偏差分析与重构方案

（待填写。）
