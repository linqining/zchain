# SHUFFLE_CONSUME — 洗牌/发牌证明链·消费侧语义与边界（zchain）

> 状态：2026-09-13 实现记录（路线 A+B 消费半边，设计文档
> `docs/shuffle-deal-proof-design.md` §5-C2/C3 的落地）。
> 权威设计以该文档为准；本文记录消费侧语义、与上游（poker_texas_air）
> 的接口对齐状态、迁移策略与排队清单。
>
> 纪律：零新依赖；fail-closed；**不假实现**——凡依赖上游未定格式的部分
> 一律显式开关（默认关）+ 本文写明，禁止用假数据冒充验证。

---

## 0. 一句话

结算侧现在会**消费** deck 承诺链：`hand_binding` 升域为
`zchain.settlement.binding.v2` 域的 Poseidon 折叠
（batch_digest + deck 链摘要 + reveal 承诺），声明 v2 绑定的结算记录被
强制走全链 fail-closed 校验（首/末转移 kind、`blind_opening`、deck/reveal
锚）；旧格式在迁移窗内接受并计数，窗关闭后拒绝；BG/DLEq 验证回执
（verifier receipt）已对齐上游 stage0 冻结的 `engine_receipt_digest`
语义（§1.5），密码学验证仍归引擎（引擎接线前 receipt 门开启即显式拒绝，
绝不静默放行）。**阶段 0 收口（2026-09-13）**：deck 链摘要算法已裁决
冻结为上游 poseidon 折叠同源（§1.2）、真实 stage0 归档钉扎正例落地
（§5）、REAL×协议行 fail-closed（11b-f）落地。

## 1. 消费语义（ABI v1.3）

### 1.1 hand_binding 升域（设计文档 §5-C3）

```text
hand_binding_v2 = felt32(poseidon_hash_many(
    domain_felt(b"zchain.settlement.binding.v2"),
    hi/lo(scope.batch_digest),            // 既有 STARK 批摘要
    hi/lo(deck_chain_digest),             // 上游同源 poseidon 折叠，见 1.2（已裁决）
    hi/lo(post.reveal_commitment),        // 发牌揭示账本锚
))
```

- 位置：`poker-appchain/src/settlement.rs::hand_binding_v2`；
  链摘要原语 `poker-settlement-core/src/deck_chain.rs::deck_chain_digest`
  （本 crate 新增的唯一原语，golden ×3 钉扎，独立预计算）。
- 域标签冻结：`zchain.settlement.binding.v2`（与 v1 花费 scope 域
  `poker-appchain.settlement.binding.v1` 不同名不同层，测试钉扎）。
- 与上游 `hand_binding.rs`（`poker_dual_hand_binding_v1` Poseidon 布局，
  含 players/settlement_digest 全量字段）的关系：**zchain 折影子集**——
  只折叠消费侧可从归档 scope 重导的三个量。全量对齐 vs 子集折叠是设计
  文档 §6-Q3 的开放决策点（见 §4 开放问题）；子集选择使 v2 绑定可由
  **任何验证者从归档公开字段重导**（无信任生产者输入），这是消费侧
  fail-closed 的前提。
- **deck 锚进入结算效果的路径**：`settle_effect` 公式不变（设计文档
  §5-C4 明确"不变"），但效果摘要覆盖 `record.hand_binding` 字节——
  v2 绑定内含 deck 链摘要，故 deck 锚**经 hand_binding 间接进
  settle_effect 与签名覆盖**。无结构体形状变更（`HandProofBinding`/
  `SettlementRecord` 布局零改动，borsh 兼容）。

### 1.2 deck 承诺链（消费侧定义）

- 链元素 = canonical 状态镜像 32B `deck_commitment`（`CanonicalStateImage`
  v5 定宽 borsh，镜像内偏移 `STATE_IMAGE_DECK_COMMITMENT_OFFSET = 122`；
  同区 `board_cards@90 / reveal@154 / reconstruction@186`）。
- 消费侧链 = 去重 consecutive 的 `[pre.deck_commitment,
  post.deck_commitment]`：相等（betting 段批）→ 单元素链；不等（批内
  含洗牌段）→ 双元素链。归档 scope 每幅镜像只携带一个 deck 承诺，
  **批内逐环链**（多次洗牌的中间承诺）由 AIR 行内约束
  （`proof_commitment == post.deck_commitment`）与 STARK 验证负责，
  不在结算消费面重复。
- 上限 `DECK_CHAIN_MAX = 10`，对齐上游 `hand_binding.rs`
  `MAX_DECK_COMMITMENTS = 10` 槽位预算；超长/空链 → `None`
  （fail-closed，不静默折叠）。
- **链摘要编码（已裁决冻结，2026-09-13）**：**上游 poseidon 折叠，与
  生产者同源**——
  `poseidon_bytes_digest(b"zchain.texas.canonical-shuffle-chain.v1"
  ‖ b"deck-chain" ‖ anchor[0] ‖ …)`（即上游
  `canonical_shuffle_chain::ShuffleChainReceipt.deck_chain_digest` 的
  逐字节复制；字节折叠 = 上游 `poseidon_over_bytes`：u64 长度前缀 felt
  + 31B 大端分块 + Cairo 原生 `poseidon_hash_many`）。
  - **裁决理由**：上游 stage0 的真实链是权威数据源，消费侧算法必须能对
    上游产出重导一致；早期消费侧 blake2b-256 提案
    （`zchain.settlement.deck_chain.v1`）与上游 poseidon 折叠对同一链
    必然不同值，双算法并存需要额外映射面且无验证者可达的公共参照——
    故删除 blake2b 版、消费侧冻结为上游同源（`poker-settlement-core/
    src/deck_chain.rs`，`DECK_CHAIN_DIGEST_DOMAIN`/`DECK_CHAIN_FOLD_LABEL`
    与上游逐字节一致）。
  - **两侧对照证据**：上游真实 `ShuffleChainBuilder` 产出链 → 消费侧
    `deck_chain_digest` 重导 → 与上游 receipt **逐位一致**
    （`poker-appchain-texasair/tests/shuffle_stage0_consume.rs`；
    golden `073c5e280d7d548111384f60c97f1b492af20b5d1ef4c242497b55605265e66a`，
    确定性种子可重现）。
  - 层次说明：上游 receipt 的链 = 逐洗牌行 post.deck（可含中间承诺）；
    结算消费面的链 = scope 端点去重 `[pre, post]`（批内逐环链由 AIR
    行内约束负责，见上文）——同一算法、不同输入层。

### 1.3 全链强制（11b，仅 v2 格式记录）

对 `classify_hand_binding == HandBindingV2` 的记录，在既有 11 条校验
（table/终态承诺/状态根/非空批/镜像 pot@74 逐字节/rake opening 重导出）
之上追加：

| # | 校验 | 拒绝消息（即清单） |
|---|---|---|
| a | 首 kind ∈ {JoinTable(1), StartHand(3), SubmitShuffle(7)} | `full-chain archive first transition kind is not a chain-entry kind` |
| b | 末 kind ∈ {AdvanceRound(19), EndWithoutShowdown(21), RevealTimeoutAward(27), RevealTimeoutRakedAward(28)} | `full-chain archive last transition kind is not settlement-terminal` |
| c | `blind_opening.is_some()` 且 `ante_mode ≤ 2` 且非全零 | `full-chain archive is missing the blind opening` / `blind opening has unsupported ante mode` / `blind opening is vacuous (all-zero blinds and ante)` |
| d | pre/post 镜像 `deck_commitment` 非零 | `archive pre-state deck commitment is zero (S1 anchor missing)` / `archive post-state deck commitment is zero` |
| e | 终态 `reveal_commitment` 非零 | `archive terminal reveal commitment is zero (deal not covered)` |
| f | **REAL 类 × 含协议行归档 → 拒绝**（无开关；`archive_has_protocol_rows`：首/末 kind ∈ {7,8,9} 或 deck/reveal/reconstruction 承诺批内轮转） | `REAL settlement archive contains protocol rows; route A native shuffle-chain verification is required (fail-closed)` |

- 11b-f（阶段 0 负面发现的消费侧强制，2026-09-13 落地）：上游实测
  （SHUFFLE_STAGE0.md §3.4-2）——canonical AIR 对**非末段** shuffle 行
  deck 承诺篡改照常出证（只冻结锚、不重算密文哈希）。含协议行的 REAL
  结算必须经路线 A 原生校验；该结果在结算纯函数层不可自证 ⇒ 直接拒绝
  该批（设计文档路线 A 正当性的链侧执行）。PLAY 类不受此条约束；引擎
  receipt 归责接线后升级为"要求回执集验证"。既有 v1/v2 流量零影响
  （既有归档均无协议行）。

- 首 kind 集为设计文档 §5-C2 字面集（"按阶段 0 结论定集"——单批/两段
  实测出来前冻结不放宽；`CreateTable(0)` 暂不在集内）。
- 末 kind 集说明：canonical AIR 无独立 showdown 结算行（v1 证明段以
  `AdvanceRound` 收池收尾），超时终局 21/27/28；`AutoFold(20)`/
  `ResetOnly(22)` 等零注码/非收池行被排除（结算记录要求 pot > 0）。

### 1.4 hand_binding 三态分类与迁移策略（11a）

`classify_hand_binding`（v2 优先）：

| 分类 | 判定 | 迁移窗（默认） | 窗关闭后 |
|---|---|---|---|
| `HandBindingV2` | `== hand_binding_v2(scope)` | 接受 + 全链强制（1.3） | 同左 |
| `LegacyBatchDigest` | `== scope.batch_digest`（v1 e2e 形态） | 接受 + 计数①`legacy_binding_accept_count` | 拒绝 |
| `Unbound` | 皆非（v1 语义遗留） | 接受 + 计数②`unbound_binding_accept_count` | 拒绝 |

- 开关：`set_full_chain_enforcement(true)` 关闭迁移窗（进程级原子量，
  默认 false——既有 v1 流量零回退；生产翻转点 = 生产者接线完成 +
  全量结清 v1 存量，见 §3 排队清单）。
- **诚实边界**：迁移窗内"换锚归档"（deck 断链拼装）只会把分类降级为
  Unbound 从而走旧语义接受——这是双轨迁移的固有缝隙（v1 语义本就允许
  绑定与归档无关系，无新增弱点）；窗关闭后该攻击被拒（负例 G6）。
  v2 声明即承诺：分类为 V2 而全链校验失败**直接拒绝**，不降级。

### 1.5 路线 B：verifier receipt（占位校验结构，默认关）

- 已冻结（本仓库侧）：语句面
  `crypto_statement_digest(kind, inputs) = blake2b-256(
  b"zchain.settlement.crypto_statement.v1" ‖ kind ‖ inputs…)`，
  kind ∈ {`bg.shuffle.v2`（pre.deck→post.deck）, `dleq.reveal.v1`
  （post.deck→reveal 承诺）}；`expected_crypto_statements(scope)` 给出
  scope 级粗粒度期望语句集；`verify_receipt_set` 做覆盖记账（每语句恰
  一张回执 / 无未知 / 无重复 / receipt 非零）。
- **上游 stage0 已冻结（2026-09-12，§6-4 接口承诺兑现）**：
  `CryptoVerifierReceipt.receipt_digest` = 上游
  `ShuffleChainReceipt.engine_receipt_digest` =
  `poseidon_bytes_digest(DOMAIN ‖ b"receipt" ‖ batch_digest ‖
  deck/reveal/reconstruct 三链摘要 ‖ 逐行 statement digest)`（域同
  §1.2 裁决域）；上游逐行 statement digest =
  `poseidon_bytes_digest(DOMAIN ‖ kind ‖ seat ‖ pre ‖ post)`（kind ∈
  {`shuffle`,`reveal`,`reconstruct`}）。
- **未实现（诚实降级点）**：
  1. 逐行 statement 级对账（消费侧语句面仍为 scope 级粗粒度；上游逐行
     digest 需归档携带协议行明细——sidecar vs 扩归档 = 设计文档
     §6-Q2，未决）；引擎侧 BG/DLEq 验证编排（poker-appchain-texasair
     C1）仍未接线；
  2. BG V2 / reveal token DLEq 的**密码学方程验证**在引擎侧
     （poker-appchain-texasair C1 编排），本模块零密码学验证；
  3. 逐张/逐玩家细粒度语句（52 张 reveal token、n 玩家洗牌链）需归档
     携带协议行明细（sidecar vs 扩归档 = 设计文档 §6-Q2），未定。
- 互锁：`set_crypto_receipt_enforcement(true)`（默认 false）后，v2
  记录**显式拒绝**（`crypto receipt enforcement is enabled but engine
  receipt integration is pending upstream stage0`）——防止"忘了接
  receipt 就静默放行"；该门只作用于声明 deck 链的 v2 记录，迁移期
  v1 流量不受影响。**开启即承诺引擎已接线，此前开启 = 全链 v2 停摆
  （fail-closed，宁可停不可假）。**

## 2. 与上游接口的对齐状态

| 接口 | 状态 | 依据 |
|---|---|---|
| canonical 镜像 `deck/reveal/reconstruction/board` 承诺字段与偏移（90/122/154/186） | **已消费**（按上游 `CanonicalStateImage` v5 字段序推导，与既有锚 `chip_pool@66/pot@74` 互证；布局回归钉在 `shuffle_chain_consume.rs`） | 上游 `texas_canonical.rs:125-171` |
| `CanonicalTransitionKind` 判别值（1/3/7/8/9/19/20/21/27/28） | **已消费**（`#[repr(u8)]` 冻结判别值） | 上游 `texas_canonical.rs:318-386` |
| `blind_opening` 批级公开投影（恰在批含末个 SubmitReveal 时出现） | **已消费**（存在性 + 形状） | 上游 rules-opening 通道 / 本仓 ABI.md |
| v2 绑定折叠布局 | **zchain 子集定义已冻结**；与上游 `hand_binding.rs` 全量对齐待 §6-Q3 | 本文档 §1.1 |
| `deck_commitment` 32B 的规范派生函数（52 密文 → 32B） | **stage0 提案并消费侧冻结沿用**：`poseidon_points_commitment(⌊c1₀,c2₀,…⌋)` + 初始牌堆 = `canonical_base_deck`（r=i+1，§4.4）；与 poker_l1 `(G,m)` 种子分裂的跨仓对齐仍开放（§6-Q3）；消费侧只依赖镜像字段字节，不重算密文哈希 | SHUFFLE_STAGE0.md §6-3/§4.4 |
| verifier receipt ABI（receipt_digest 构造） | **上游 stage0 已冻结**（`engine_receipt_digest`，本文档 §1.5）；引擎侧接线未完成（门默认关） | SHUFFLE_STAGE0.md §6-4 |
| 生产者接线（canonical 协议行 witness 归档实时产出） | **测试级已就绪**（stage0 `ShuffleChainBuilder` + 两侧对照/夹具导出）；实时链级仍未接线（hooks.rs 回退遗留路径，BLOCKERS B6） | SHUFFLE_STAGE0.md §1.2/§7-1 |
| 全链首 kind 集定集（单批 vs 两段续链） | **阶段 0 已实测**：shuffle→reveal→下注→结算链单批成立（A1，起点 = hand-start 投影 SubmitShuffle(7)）；reconstruct 为三批级联。现集 {1,3,7} 覆盖；`CreateTable(0)` 维持不入集（保守冻结不放宽） | SHUFFLE_STAGE0.md §0/§4.1/§4.2 |
| 真实归档 → `parse_archive_scope` 逐字段钉扎 | **已落地**（§3-2 排队项收口）：`stage0_full_chain.*` 夹具（13 行单批全链，log 8，pot@74=400、deck@122/reveal@154 锚、blind opening 50/100）| `poker-appchain-texasair/tests/shuffle_stage0_consume.rs` + `poker-appchain/tests/shuffle_chain_real_archive.rs` |
| 座位 bet 布局 ↔ `blind_opening` 面额解耦的跨镜像强校验 | **暂缓**（blind_opening 不携带座位指派；强校验需上游冻结座位指派口径） | 负例矩阵"盲注面额脱钩"的消费侧可判定部分仅 1.3-c |

## 3. 排队清单（2026-09-13 洗牌链接线收口：1/2 钉扎半边/3/5 已落地）

1. ✅ **sequencer/ops 准入扩展**（已落地）：`SequencerConfig` additive
   字段 `full_chain_enforcement` / `crypto_receipt_enforcement`
   （默认 false = 现状，逐行注明），经
   `SequencerConfig::apply_settlement_gates()` 在**进程启动路径**刻入
   settlement 进程级原子量；replay/build_index/watcher 重放面禁止调用
   （重放确定性，`validate_settlement` 在重放 apply 路径上执行）。
2. **引擎侧（poker-appchain-texasair，C1）**——钉扎半边已落地：
   - ✅ 真实归档 → `parse_archive_scope` 的 deck/reveal/reconstruction
     偏移逐字段钉扎（真实 stage0 夹具 `tests/fixtures/stage0_full_chain.*`，
     `tests/shuffle_stage0_consume.rs` 导出 + `poker-appchain/tests/
     shuffle_chain_real_archive.rs` 独立消费）；
   - ✅ deck 链摘要两侧对照（真实 receipt vs 消费侧重导逐位一致）；
   - ⬜ attestation v2.2（payload 追加 `shuffle_chain_digest` 与
     `engine_receipt_digest`，域不变形状区分）；
   - ⬜ BG/DLEq 原生验证编排 + `CryptoVerifierReceipt` 填充（上游
     receipt ABI 已冻结，剩余为引擎编排 + §6-Q2 材料传输形态）。
3. ✅ **ABI.md 增补**（已落地，v1.3 §15）：状态镜像内偏移表
   90/122/154/186；hand_binding v2 域与折叠布局；deck 链摘要冻结
   算法；11b a–f（含 REAL×协议行 fail-closed）；迁移窗/receipt 门
   语义；`build.py SITE["ABI_VERSION"]` 同步 v1.3（网站三件套全过）。
4. **指标面**（⬜ 未动）：`legacy/unbound_binding_accept_count` 进
   `metrics.rs` 聚合导出（现为进程内计数器，纯函数层不持 MetricsRegistry
   引用）。
5. ✅ **生产者接线对齐**（阶段 0 出口已消化）：单批合并对
   shuffle→reveal→下注→结算链成立（A1）；`FULL_CHAIN_FIRST_KINDS`
   定集复核——现集 {1,3,7} 覆盖 A1 起点与 A0 形态，`CreateTable(0)`
   维持不入集；reconstruct 三批级联的段间接续（pre_state_commitment
   环接/第二锚）留 C1 集成时评估。

## 4. 开放问题（沿设计文档 §6，消费侧补充）

- **Q3 承诺口径**：v2 绑定的子集折叠与上游 `hand_binding.rs` 全量布局
  的最终关系（本实现选子集：可重导、无生产者信任输入）。
- **Q2 证明材料传输形态**：细粒度语句面（逐张 reveal token）依赖
  sidecar/扩归档决策，当前语句集为 scope 级粗粒度。
- **座位级盲注解耦**：`blind_opening` 无座位指派字段，镜像座位 bet 区
  （偏移 474 起、每座 134B）的逐座位对账需上游冻结指派口径后实现。
- **v2 owner 侧**：canonical AIR 未纳入 v2 owner（v2 结算证明覆盖为水位
  级）——deck 链消费 v1 结算先行；`note_v2::validate_settlement_v2`
  不消费 deck 链（待 v2 owner 线，含 §6-Q5 owner↔加密公钥合一评审）。

## 5. 测试证据（--release，nightly-2026-04-15；2026-09-13 洗牌链接线后更新）

- `poker-settlement-core`：36 通过（31 基线 + 5 新：golden ×3、
  fail-closed 边界、序敏感性），0 失败；**golden 向量为独立预计算**
  （python3 hashlib），零既有 golden 更新（加法式，`plan.digest`/
  `payout_root` 域与值不变）。
- `poker-appchain`（364 基线 + 新增，全绿）：
  - `tests/shuffle_chain_consume.rs`（常开矩阵）：布局钉扎 ×1、
    正例 ×2（PLAY——REAL×协议行转 11b-f）、负例 N1–N12（精确拒绝消息
    断言；N12 = REAL×协议行 fail-closed）、REAL 边界 ×3（无协议行
    REAL 正例 / PLAY 控制面 / Legacy 窗内边界）、迁移计数 ×2、
    语句面 + receipt 覆盖记账矩阵 ×2；
  - `tests/shuffle_chain_gate.rs`（门控矩阵 G1–G8 + `SequencerConfig::
    apply_settlement_gates` 运营面接线回归，单用例顺序执行 + Drop 守卫
    复原）；
  - **新 `tests/shuffle_chain_real_archive.rs`**：真实 stage0 归档夹具
    （`tests/fixtures/stage0_full_chain.*`，上游真实 BG/DLEq 出证导出）
    的消费侧钉扎——scope 逐字段、v2 绑定正例（PLAY）、11b-f 负例
    （REAL，精确消息）、deck 锚篡改分类降级；
  - **新 `tests/archive_index_v2.rs`**：v2 WAL（TE-M2/M3/M6 op 真实产链
    9 帧）→ build_index → load_index 等价 + `v2` 子对象逐字段核对；
    MigrateNote/SettleV2 行装载契约；unknown kind 仍拒；
  - `settlement.rs` 内嵌单测：域分离、语句 golden ×2、链去重；
  - v1.2 既有测试零回退（迁移窗默认关下行为不变；v2 全链正例的资产类
    从 REAL 调整为 PLAY 并注明——11b-f 使 REAL×协议行成为 fail-closed
    拒绝语义，边界另有 REAL 正例覆盖）。
- `poker-appchain-texasair`：**新 `tests/shuffle_stage0_consume.rs`**
  （交付 1/2 主证据）：上游真实 `ShuffleChainBuilder`（4×BG V2 prove +
  8×DLEq prove，Stark 曲线 + Poseidon 生产域）单批全链 13 行出证 →
  STARK verify → 路线 A 原生验证 → ① 消费侧 `deck_chain_digest` 对上游
  receipt **逐位一致**（golden 钉扎）② 真实归档 scope 钉扎 ③ 消费侧
  PLAY 正例 + REAL 11b-f 负例 ④ 夹具导出。
- `poker-settlement-core`：36 通过（deck_chain goldens 更新为上游同源
  poseidon 折叠——算法裁决所致，非 golden 漂移；fail-closed 边界与
  序敏感性语义保留）。

## 6. 诚实降级点汇总（2026-09-13 更新）

1. receipt 密码学验证不在本层，`verify_receipt_set` 只保证覆盖记账；
   门开启状态下（运营方显式开启）v2 记录 fail-closed 拒绝——引擎侧 C1
   编排 + §6-Q2 材料传输形态为剩余排期项。
2. 迁移窗内 Unbound 接受语义（§1.4 诚实边界）。
3. 首/末 kind 集经阶段 0 实测复核后维持保守冻结（§3-5）；reconstruct
   三批级联的段间接续未做结算面第二锚（跨批拼装的 deck 链断点检查留
   C1 集成）。
4. ~~镜像偏移缺真实归档钉扎~~ **已收口**（stage0 夹具双重钉扎，§5）。
5. ~~`post.reveal_commitment` 非零未经真实归档验证~~ **已收口**（真实
   全链批 AdvanceRound 终态 reveal 承诺非零，夹具钉住）。注意其反面
   同样真实：`EndWithoutShowdown` 终局会把 reveal/reconstruction 承诺
   **清零**（上游 stage0 夹具语义）——11b-e 的"终态非零"判据因此只对
   AdvanceRound 收尾的结算段批成立；以 EndWithoutShowdown/超时终局收尾
   的批若直接作结算绑定会被 11b-e 拒（fail-closed 保守方向，如实记录；
   放宽属后续 ABI 决策点）。
6. **11b-f 的 REAL 灰度边界**：11b-f 挂在 v2 分类之后——Legacy/Unbound
   绑定的 REAL×协议行归档在迁移窗内仍走旧语义接受（§1.4 既有边界，
   非新增弱点；窗关闭后拒绝）。
