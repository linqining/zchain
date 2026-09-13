# 洗牌/发牌证明链 设计立项文档

> 状态：2026-09-13 设计立项稿（外部评审建议 3 的第①段出口——**只做设计，
> 不含实现**）。第②段（上游 AIR 扩展 + 本仓库适配器/测试）依本档排期。
> 排期来源：`docs/roadmap-schedule.md` §4（建议 3 升格为正式排期项）。
> 参考基准：本仓库 `docs/plan-appchain-v1.md`、`poker-appchain/docs/BLOCKERS.md`、
> `poker-appchain/docs/ABI.md`（v1.2.4）；全量上游仓库
> `/Users/mac/projects/poker_texas_air`（本仓库 `poker-appchain-texasair` 以
> path 依赖直接引用，见其 `Cargo.toml:19`）。
>
> 诚实纪律：§1 全部现状结论附文件+行号/符号证据；工作量与证明开销均为
> **估算**（标注"估算"）；不确定处进 §6 开放问题，不编造。

---

## 0. 摘要

现状一手证明自 hand-start（下注入场）状态镜像起，洗牌/发牌（shuffle/deal）
不在一手证明链内——"可验证公平"叙事只覆盖下注与结算端，不覆盖"拿到牌前
牌序未被操纵"。

本档结论（概要）：

1. **上游已有的比预想多**：canonical AIR（29 选择子）的转移空间**已经包含**
   `SubmitShuffle(7)/SubmitReveal(8)/SubmitReconstruct(9)` 及其完成行；
   状态镜像已含 `deck_commitment/reveal_commitment/reconstruction_commitment`
   三个承诺字段；RevealComplete（发牌→下注桥）的组合约束已于 2026-09-11
   在上游 AIR 贯通。真正的缺口不是"状态机行没进 AIR"，而是**密码学方程
   （BG 洗牌证明、逐张 reveal token DLEq、重构 V3）刻意留在 AIR 之外**
   （上游 Plan D 决策），以及 **zchain 侧没有消费这些行的证明链与结算衔接**。
2. **推荐路线（混合）**：以 canonical AIR 既有的 shuffle/reveal 行为骨架做
   **证明链续接**（hand-start 镜像前移至 shuffle 段输出），密码学方程由上游
   sigma/BG 套件在**验证引擎与客户端双端原生验证**并经
   **verifier receipt 绑定**归责；不把 Stark 曲线 EC 运算塞进 circle-STARK
   （成本/风险不可接受，且与上游 Plan D 分工冲突）。
3. **链侧改动是加法式**：`TexasArchiveScope` 前缀消费对上游归档追加字段
   天然兼容；需要新做的是结算校验对首/末转移 kind、`blind_opening`、
   `deck_commitment` 链的 fail-closed 强制，以及 hand_binding 语义升级
   （ABI v1.3，见 §5）。

---

## 1. 现状测绘（全部带证据）

### 1.1 上游洗牌/发牌相关密码学证明原语

| 原语 | 位置 | 状态 |
|---|---|---|
| **Bayer–Groth 洗牌证明 V2** | `poker-protocol-bg/src/proof.rs:88`（`BayerGrothShuffleProof<C>`）、`:6`（`PROTOCOL_ID = b"poker/bayer-groth-shuffle/v2"`）、`:211`（`prove`）、`:363`（`verify`）；Pedersen 承诺键 hash_to_curve 派生 `:16-34` | **生产强制**（`docs/SOUNDNESS.md:47-49`："BG V2 is mandatory"） |
| Legacy 洗牌证明 V1 | `poker-protocol-proofs/src/shuffle_proof.rs:1-8`（`ZKShuffleProof`；模块文档自述 mixed-witness 攻击，`VersionedShuffleProof::verify` 无条件拒绝） | 仅解码/迁移/攻击回归用，**verify 恒拒** |
| 版本化封装 | `poker_protocol/src/zk_shuffle/mod.rs:42`（`ShuffleProof = VersionedShuffleProof<DefaultCurve>`） | `DefaultCurve = StarkCurve`（`poker_protocol/src/lib.rs:1-5`，2026-09-05 起唯一生产曲线；`poker-protocol-core/src/lib.rs:4`） |
| 发牌（reveal token）DLEq | `poker-protocol-proofs/src/reveal_token_proof.rs:28`（`RevealTokenProof`）、`dleq_proof.rs:120`（`DLEqProof`，Remask/Leave 两 kind）、`remask_proof.rs:16`、`leave_proof.rs:17`、`pk_ownership.rs:18` | sigma 套件，Stark 曲线 + Poseidon 域（`transcript_domains.rs`，2026-09 Poseidon epoch） |
| 重构（reconstruct）V3 | `poker-protocol-proofs/src/reconstruction/v3.rs:116`（`ReconstructProofV3`）、`v3.rs:178`（`canonical_base_deck`）、`cross_key.rs:32`（`CrossKeyNegationProof`）、`slot_or.rs:44`（`SlotContributionOrProof`）、`chaum_pedersen.rs:19`、`ordered_encryption.rs:29` | V3 为 Lean 形式化修复版（`docs/SOUNDNESS.md:19-27`；V2 被 Lean 反例证伪后移除） |
| 预编译 ABI | `poker-protocol-abi/src/lib.rs:7-13`（`ZKSH`/`ZKRC`/`ZKR3` magic + ABI 版本）、`:260`（`ShuffleVerifyRequest`）、`:408`（`ReconstructionVerifyRequest`）、`:560`（`ReconstructionV3VerifyRequest`）、`:123-129`（`ShuffleProofSystem::BayerGrothV2=2`）、`:146-154`（`BayerGrothOrderedV2`/`BayerGrothSlotOrV3`） | `RISTRETTO_AIR_DECK_SIZE = 52`（`:26`）；`CurveId::StarkCurve = 6`（`:54-58`）；`TranscriptId::Poseidon252 = 3`（`:92-94`） |
| 明文牌与初始牌堆 | `poker_l1/src/contracts/texas_poker/core/utils.rs:285-297`（`generate_plaintext_cards` = `hash_to_g1("texas_poker/card/{i}")` 确定性派生）、`:305-310`（`plaintext_cards_commitment` = `poseidon_points_commitment`） | 协议常量，shuffle 前的规范初始牌堆由此锚定 |

**关键词核查（按任务要求）**：`grep -ri "menton"` 在上游全仓 **0 命中**——
不存在 Menton–Reed 原语；洗牌证明系统只有 Bayer–Groth（V2 生产 + V1 已废弃）
与历史 Ristretto/AIR 路线（`ShuffleProofSystem::RistrettoAirV1/V2`，
`poker-protocol-abi/src/lib.rs:126-128`，属 BLS/Ristretto 时代遗产）。

### 1.2 canonical AIR：29 选择子、状态镜像、牌序进入点

- **29 个转移选择子**：`KIND_COUNT = 29`
  （`poker_texas_air/src/texas_canonical_air.rs:43`；文件共 14,569 行）。
  `CanonicalTransitionKind`（`src/texas_canonical.rs:318-386`）含协议行
  **`SubmitShuffle = 7`、`SubmitReveal = 8`、`SubmitReconstruct = 9`**、
  `FoldWithProof = 18`、`AdvanceRound = 19` 及 reveal/reconstruct 超时级联
  `23..=28`。
- **协议行携带密码学证明承诺**：`carries_crypto_proof()`
  （`src/texas_canonical.rs:437-445`）= 上述 4 类；载体为
  `CanonicalActionPayload.proof_commitment: [u8; 32]`（`:454`）。
  绑定语义（AIR 约束）：SubmitShuffle/SubmitReconstruct 行
  `action.proof_commitment == post.deck_commitment`
  （`src/texas_canonical.rs:1473/1505/1533/1636/1937`）、SubmitReveal 行
  `== post.reveal_commitment`（`:1750`）、重构提交行
  `== post.reconstruction_commitment`（`:1827`）。即 **AIR 冻结了"密码学证明
  的结果锚"（新牌堆/揭示承诺），但不重放密码学方程本身**。
- **状态镜像（牌序进入点）**：`CanonicalStateImage`
  （`src/texas_canonical.rs:125-171`）定宽 borsh ABI（1,680 字节，本仓库
  `poker-appchain/docs/ABI.md:206-207` 镜像记录），与牌序相关字段：
  - `deck_commitment: [u8; 32]`（`:159`）——**牌序（加密形态）进入状态镜像
    的唯一入口**；
  - `reveal_commitment`（`:160`）、`reconstruction_commitment`（`:161`）、
    `board_cards_commitment`（`:158`）、`protocol_pending_mask`（`:157`）、
    `shuffle/reveal/reconstruct_timeout_ms`（`:138-141`）。
  - 加密形态：52 张牌为 ElGamal 密文（`CipherDeck::Active(Box<[ElGamalCiphertext; 52]>)`，
    `poker_l1/src/contracts/texas_poker/core/types.rs:1916-1921`；Stark 曲线
    32B 压缩点），**不进镜像字节**——镜像只进 32B 承诺；面额盲化不适用
    （牌不是筹码），筹码侧盲注面额见 §1.5。
  - 镜像 custody 恒等式逐行受 AIR 约束：`pot + Σ(stack + pending_addon + bet)
    == chip_pool`（`src/texas_canonical.rs:285-298`）。
  - 镜像承诺函数：`CanonicalStateImage::commitment()` = blake3 链摘要，
    域 `zchain.texas.canonical-state.v3`（`src/texas_canonical.rs:302-311`）。
- **协议完成行（shuffle→reveal→betting 的规范化语义）已在 AIR**：
  - ShuffleComplete：枚举 `CanonicalProtocolCompletionKind`（
    `src/texas_canonical.rs:540-543`），opening 携带
    `pre/post_deck_commitment`（`:602-603`）与 pending/completed mask
    （`:585-586`），validate 见 `validate_shuffle_completion_opening`
    （`:967-1012`）；上游 `docs/STATUS.md:85-87` 记录 2026-09-05 全落地。
  - RevealComplete（**发牌→下注桥**）：2026-09-11 贯通（`docs/STATUS.md:88-121`）
    ——组合约束覆盖 UTG/SB/BB 位置扫描、逐座位盲注资金移动、deadline 重挂；
    盲注/ante 经 `CanonicalBlindOpening`（small/big blind、ante_mode、
    ante_amount）由 rules-opening 通道鉴权，批次归档公开字段即本仓库镜像的
    `blind_opening`（`poker-appchain/src/settlement.rs:394`；ABI.md:198，
    解析侧注记"恰在批含末个 SubmitReveal 时出现"见 settlement.rs:393）。
    批级出证入口
    `prove_canonical_reveal_completion_batch`（`texas_canonical_air.rs:9037`）。
  - 准入已翻转：`crypto_admitted`/`validate_direct_batch` 对
    SubmitShuffle/SubmitReveal/SubmitReconstruct 放行（`docs/STATUS.md:117-125`）。
- **上游已知断点**：整手四段拆分文档 `canonical_full_hand_proof_perf_sweep`
  （`texas_canonical_air.rs:14244-14259`）写于 2026-09-10，其中
  "Revealing→Betting 桥是 TODO #22 已知缺口"一句相对 STATUS.md 2026-09-11
  的 RevealComplete 贯通**可能已过时**——合并现状需实测（§6-Q1）。

### 1.3 上游方法 AIR 与 precompile binding 模式（密码学方程的现行出口）

方法级 AIR（19 active，`src/method_kind.rs:32-79`；C 档 4 个：
`SubmitShuffleV2=17`、`SubmitPlayerRevealTokens=18`、`SubmitReconstructDeck=19`、
`FoldWithProof=22`）**不在 STARK 内验密码学**，而是：

- 以 `SubmitShuffleV2Air` 为例（`src/airs/crypto/submit_shuffle_v2.rs`）：
  AIR 约束 canonical request digest 与 **verifier-issued receipt digest**
  两列（`REQUEST_DIGEST_BASE/RECEIPT_DIGEST_BASE`，`:52-56`）；
  `validate_public_inputs`（`:289-335`）要求 verifier 签发的
  `PrecompileAirBinding`、重解码 request、校验 call_context
  （table/hand/call/seat/state replay scope）。设计意图原文：host-native
  Bayer–Groth verifier 在 binding 的唯一构造路径执行一次，AIR 不接受 prover
  提供的裸 `success = true`（`:19-23`、`:175-178`）。
- 上游 P 层（链上侧）同构：DAPV sigma 聚合由 `PokerDualSettlement` 经
  Starknet EC_OP builtin 链上验证（`dual::hand_batch_stark`），
  BG V2 强制，四层防拼接绑定含"hand-binding 前缀进每个内层 FS transcript +
  ρ 与 STARK 公共输入跨层对账"（`docs/SOUNDNESS.md:29-57`）。
- **信任结论**（上游自己的口径）：曲线密码学等式"刻意留在 AIR 外"
  （`docs/STATUS.md:45-51` fail-closed gap #1）；G 层"host 是可用性依赖
  而非正确性依赖"的成立前提是 **P 层链上验证独立兜底**（`docs/SOUNDNESS.md:77-81`）。
  zchain v1 没有链上 EC_OP 兜底（settlement 在 appchain 内部闭环），因此
  zchain 若原样引入协议行，密码学方程的验证者 = 我们的验证引擎——
  这是本设计必须显式处理的信任边界（§2、§3、§6-Q4）。

### 1.4 上游 hand_binding 与 deck 承诺链（结算侧已预留的挂钩）

`src/hand_binding.rs:24-34`（Poseidon 域 `poker_dual_hand_binding_v1`，`:41`）：

```text
hand_binding = poseidon_hash_many(
    DOMAIN_TAG, table_id, hand_id, num_players,
    players[0..n], num_decks, deck_commitments[0..num_decks],
    reveal_commitment, state_root_pre, state_root_post, settlement_digest)
```

- `MAX_DECK_COMMITMENTS = 10`（`:45`）——**初始牌堆 + 每玩家洗牌后牌堆**
  的承诺链槽位已在上游结算绑定中预留。
- 另有一个 64-bit 承诺：`deck_commitment()` = blake2b-256 前 8 字节，
  域 `zchain.texas_poker.deck_ciphertexts.v1`，输入为有序密文 borsh
  （`src/deck_commitment.rs:12,20-36`），供 orchestrator/precompile-dual
  绑定用（`src/orchestrator.rs:1917-1918,2027`）。
- **口径注记**：canonical 镜像的 32B `deck_commitment`、上述 u64 前缀、
  hand_binding 内的 felt 承诺，三处计算函数不同；canonical 32B 值由宿主侧
  witness 构造进入镜像（测试夹具中为占位常量，如
  `src/canonical_state_hash.rs:123` 的 `deck_commitment: [2; 32]`），其"从密文
  计算的规范函数"上游未见单一权威定义——需在实现前统一（§6-Q3）。

### 1.5 本仓库（zchain）现状：证明起点、镜像、hand_binding、custody

- **一手证明起点**：canonical batch 现取"下注街→收池"段。E2E
  `poker-appchain-texasair/tests/e2e_full_hand.rs:10-21`：批内
  `Raise(13)/Fold(10)/Call(12)/AdvanceRound(19)` 5 行；注释明示
  Create/Join/StartHand 与 SubmitShuffle/SubmitReveal 属**相邻 batch 段**，
  盲注以 hand-start 镜像座位 `bet` 字段进入证明范围，终局 pot 的 custody
  恒等式（`pot + Σ(stack+bet) == chip_pool`）逐行由 AIR 约束，盲注面额
  因此被证明覆盖。`docs/plan-appchain-v1.md:208-209` 同口径：
  "当前一手证明自 hand-start 镜像起，盲注面额已被 custody 恒等式覆盖；
  Revealing→Betting 洗牌/发牌续链属上游路线"。
- **hand_binding 现值**：`hand_binding = archive.batch_digest`
  （`tests/e2e_full_hand.rs:633`）；`batch_digest` = blake2b-256 over
  borsh(witnesses)，域 `zchain.texas.canonical-tagged-batch.v2`
  （`poker_texas_air/src/texas_canonical_air.rs:490-500`）。**不含**
  deck 承诺链（与上游 `hand_binding.rs` 的 Poseidon 布局不同源）。
- **结算校验现状**：`poker-appchain/src/settlement.rs`
  - `TexasArchiveScope`（`:334-395`）= 上游归档公开字段序的前缀镜像
    （scope v2），已含 `first/last_transition_kind`（`:352-354`）、
    `pre/post_state_image_bytes`（`:386-388`）、`rake_opening`（`:392`）、
    `blind_opening`（`:394`）；`parse_archive_scope` 用前缀消费（`:406-411`），
    上游尾部追加字段天然不破坏解码。
  - `validate_settlement`（`:518-…`）对 scope 的强制：table 一致（`:694`）、
    终态承诺一致（`:697`）、前后状态根一致（`:701-705`）、
    `transition_count != 0`（`:706`）、**镜像 pot@74 逐字节绑定**（`:709-716`）、
    rake opening 重导出（`:724-…`）。**未强制**：首/末转移 kind、
    `blind_opening` 存在性、`deck_commitment` 链——即当前即使归档里出现
    shuffle/reveal 行也不会被拒，但也没有被使用（§5-C2 是补口）。
- **引擎与归责**：`poker-appchain-texasair/src/lib.rs` `TexasAirEngine`
  prove = 归档解析 → 绑定检查 → `verify_canonical_tagged_proof` 完整 STARK
  验证 → `validate_settlement` → attestor 签名 attestation v2.1
  （`:33` 引擎文档、`:82-83` payload 192B：binding/post 承诺/pre·post
  状态根/plan digest）；verifier key 钉扎 + `real_policy`（默认
  `StarkRequired`，ABI.md §8）。**引擎当前不验证任何密码学方程**
  （无 BG/DLEq 调用）。
- **上游密码学栈在本仓库的可用性**：适配器 path 依赖
  `../../poker_texas_air`（`poker-appchain-texasair/Cargo.toml:19`），
  BG V2/σ 套件可直接调用；另有 vendor 份 `poker_l1/src/vm/contracts/
  texas_poker/reconstruction_v3/`（BLOCKERS B8 关闭记录，
  `poker-appchain/docs/BLOCKERS.md:168-176`）。
- **生产者缺口**：canonical witness 归档（含协议行）目前仅在测试夹具构造，
  实时链产出的是 legacy ProveTask 链（`BLOCKERS.md` B6 残余边界①，
  `:272-274`）。
- **行数预算约束**：canonical trace 域下限 `MIN_LOG_SIZE = 8`（256 行）
  使单证明成本与行数解耦（B3/DR-1，`BLOCKERS.md:158-166`）——协议行
  （每人 1 行 SubmitShuffle + 每座位 1 行 SubmitReveal + 2 完成行 +
  可能的超时行）行数增量可控，但 log 8→9 跳档是 DR-1 已记录的重访条件。
- **v2 wallet 方向**：`poker-appchain/src/owner_v2.rs` `OwnerRef`/
  `SignatureScheme`（`LegacySecp256k1=0`、`StarkCurve=1`、
  `StarknetAccountBinding`，`:163-174`；域 `zchain.owner_v2.*`，`:67-73`）。
  上游 mental poker 的注册加密公钥为 Stark 曲线 ECPoint——owner_v2 的
  StarkCurve owner 与之**同域**，有"owner key 即牌堆加密公钥"的自然绑定
  机会（§6-Q5，涉密钥复用安全评审，本档不预设结论）。

### 1.6 信任边界小结

```text
                       上游（Plan D 世界）                 zchain v1（本设计对象）
密码学方程验证者    host native verifier + 链上 EC_OP   （引入后）zchain 验证引擎 + 客户端
                    （PokerDualSettlement, hand_batch_stark）
状态机转移证明者    canonical AIR（stwo）               canonical AIR（同一栈，path 依赖）
结算事实源          hand_binding（Poseidon, deck 链）   hand_binding = batch_digest（blake2b）
兜底独立性          P 层链上验证独立于 host             无链上兜底 → 引擎即信任锚（须 fail-closed
                                                        + 双端可复验 + 归责收据，见 §3/§4）
```

---

## 2. 缺口定义

### 2.1 目标命题（要证明什么）

记某手牌 h 的玩家有序集 P = (p_1..p_n)（座位序），`deck_commit_i` 为第 i 次
洗牌后的加密牌堆承诺。一手牌的完整公平命题 **S** 由五段构成：

```text
S1 初始牌堆绑定：
   deck_commit_0 锚定进一手证明的起始状态镜像（deck_commitment 字段），
   且 deck_commit_0 的密文 = 规范初始牌堆（canonical plaintext cards
   经参与者加密公钥的加密组合）。

S2 洗牌正确性：
   对每个玩家 p_i 的 SubmitShuffle 行：deck_commit_i 对应的密文序列
   = permute·re-encrypt(deck_commit_{i-1}; pk_i, ρ_i)，
   即 Bayer–Groth V2 关系（poker-protocol-bg/proof.rs:236 的谓词），
   且 AIR 内 deck_commitment 链逐环相扣（既有约束）。

S3 发牌正确性：
   每张发出的牌（hole/board）= S2 终态密文在**全部**参与者 reveal token
   （部分解密份额，RevealTokenProof/DLEq）作用下的正确开启；
   hole 牌只对持有者可读（owner-readable），board 对所有人可读；
   揭示次序/目标（RevealTarget/assignment）与 canonical reveal ledger 一致。

S4 发牌→下注桥：
   RevealComplete 后的下注入场镜像（UTG/SB/BB 座位、盲注实投面额、
   deadline）与 S3 终态镜像连续——上游 RevealComplete 组合已覆盖，
   zchain 需接入而非重造。

S5 牌值→结算衔接：
   摊牌/结算使用的明文牌值可追溯到 S3 的揭示链（reveal_commitment →
   board_cards_commitment / owner_readable_hole_cards），结算侧
   hand_binding 覆盖完整 deck 承诺链。
```

### 2.2 现状对照（差距逐项）

| 命题段 | AIR 状态机层 | 密码学方程层 | zchain 消费侧 |
|---|---|---|---|
| S1 | 镜像有 `deck_commitment` 字段；S1 的"规范初始牌堆"派生未冻结进 AIR | 无方程需求（承诺相等性） | 未消费（批起点不含该帧） |
| S2 | SubmitShuffle 行 + `proof_commitment == post.deck_commitment` 已约束（§1.2） | **缺口**：BG V2 在 AIR 外（host/链上） | 未接入；引擎不验 BG |
| S3 | SubmitReveal 行 + RevealComplete 组合已贯通（§1.2） | **缺口**：逐张 DLEq 在 AIR 外 | 未接入 |
| S4 | RevealComplete → betting 入场已组合（盲注 opening 通道） | 无方程需求 | 未接入（当前批起点 = 其后段） |
| S5 | 终态镜像 pot/custody 已绑定（zchain 已消费 @74） | 无 | hand_binding 无 deck 链（**缺口**） |

一句话：**状态机层证明上游已基本备齐，zchain 缺"接入 + 消费"；密码学方程层
两侧都依赖 host-native 验证，zchain 缺"引擎验证 + 归责 + 客户端复验"。**

---

## 3. 候选技术路线（≥2 条）

> 共同前置：S1–S4 的状态机行全部走既有 canonical AIR（29 选择子不动——
> 协议转移已是其中 4+ 类；扩展面为零，这是上游架构给的红利）。
> 三条路线的差异只在**密码学方程层放哪、怎么归责**。

### 路线 A：canonical 续链 + 引擎/客户端双端原生验证（承诺锚模式）

洗牌/发牌密码学方程由验证引擎在 STARK 验证通过后**原生验证**
（直接调用上游 `poker-protocol-proofs`/`poker-protocol-bg`：52 张 BG V2
verify + 每张 reveal token DLEq verify），绑定输入为归档镜像的
`deck_commitment` 链与 AIR 已冻结的 `proof_commitment` 锚；客户端
（wallet-core wasm）同码路径复验。trust 假设 = 引擎代码正确且客户端可
独立复验（开源可审计，非密码学自证）。

- **工作量**：M（估算）。上游原语齐备、path 依赖现成；主要工作在 zchain
  适配器验证编排 + witness 生产者接线（canonical 归档生产者本身未接线，
  `BLOCKERS.md:272-274`，这部分是既有债，算入而不重复计）。
- **证明开销**：STARK 侧 0 增量（不进 trace）；原生侧 BG verify 52 张
  ≈ 十几次 52 点 MSM + Poseidon transcript（估算：单次 verify 数十 ms 级、
  逐手全链 < 1s 级，Apple M3 Pro 参照 777ms p95 证明基线外挂）——
  **数字必须实测后写进基准档**。
- **风险**：引擎单点（v1 无链上兜底）；镜像 deck_commitment 与真实密文的
  对应关系依赖 witness 生产者诚实（AIR 只冻结镜像，不重算密文哈希）。
- **耦合面**：29 选择子 0 改动；镜像链 0 改动；zchain 引擎 1 处编排 +
  attestation 扩展。

### 路线 B：verifier receipt digest 绑定（上游 precompile 模式移植）

在路线 A 之上，把"谁在何时验证了哪条密码学语句"做成**可归责收据**：
移植上游方法 AIR 的 `PrecompileAirBinding` 模式（§1.3）——验证引擎对
每条 BG/DLEq 语句产出域绑定 receipt digest（statement digest + call_context
+ 引擎 key），digest 进 attestation（v2.2）并随 proof registry 归档公开；
客户端与第三方 watcher 可用同一 digest 重放验证。STARK 侧可选（非必须）
把 receipt digest 作为公开列（上游 `SubmitShuffleV2Air` 形态）或仅入
attestation（zchain 现有归责框架形态，改动更小）。

- **工作量**：M–L（估算）。receipt ABI 需冻结（对齐 `poker-protocol-abi`
  纪律）；两种绑定深度（进 AIR 公开列 vs 进 attestation）建议先 attestation。
- **证明开销**：STARK 进列方案 +每协议行 2×DIGEST_LIMBS 列（上游
  `submit_shuffle_v2.rs:52-56` 形态，行数不变）；attestation 方案 0。
- **风险**：最低；与上游方法 AIR 演化保持同构。
- **耦合面**：若选进 AIR 公开列，canonical AIR 公开绑定面 +
  `TexasArchiveScope` 镜像同步扩；attestation 方案仅动本仓库。

### 路线 C：密码学方程进 circle-STARK（洗牌写进 AIR 选择子/组件）

把 S2/S3 关系写进 stwo 组件 AIR：Stark 曲线点运算在 M31/Q31 上多 limb
模拟（非原生域算术），52 张 × n 玩家密文链 → EC 加法/标量乘协处理器 +
Poseidon252 重放。这是唯一的"无见证单证明"形态。

- **工作量**：XL+（估算）。上游 Poseidon252-v2 五组件（STATUS.md:126-136）
  提供了组件化范本，但 EC 运算协处理器是全新组件族。
- **证明开销**：估算为数量级恶化——单次 256-bit 域 EC 点加 ≈ 数百约束，
  52 张 × 9 玩家洗牌链的方程数量 → 数十万至百万级约束行（粗估，
  未实测；上游把同类关系留 AIR 外正是 Plan D 成本决策）。
- **风险**：最高；与上游 Plan D 分工正面冲突（STATUS.md:47-51 刻意留外），
  上游演进（curve/协议改版）需持续跟平。
- **耦合面**：canonical AIR 组件编排、归档 ABI、验证器全部动。

### 路线对照

| 维度 | A 承诺锚+原生验证 | B + receipt 归责 | C 全进 AIR |
|---|---|---|---|
| 信任升级 | 代码可审计 + 客户端可复验 | + 引擎不可抵赖（签名收据） | 密码学自证（无见证） |
| 工作量（估算） | M | M–L | XL+ |
| STARK 开销（估算） | 0 | 0（attestation 档） | 数量级恶化 |
| 与上游一致性 | 高（Plan D 同口径） | 高（方法 AIR 同构） | 冲突 |
| 独立兜底 | 无链上兜底 | 收据可第三方审计 | 自足 |

---

## 4. 推荐路线 + 理由 + 分阶段里程碑

**推荐：A 为主干，B 叠加（attestation 档先行），C 不做**（随上游/Phase 2
重估）。理由：

1. **叙事缺口立关**：A 把一手证明链扩到 发牌→下注→结算 全程（roadmap
   §4 出口判据），用已存在的 AIR 行 + 已存在的密码学套件，改动集中在
   zchain 侧，XL 缺口降为 M。
2. **信任模型诚实**：v1 无链上兜底是事实；A+B 给出"引擎验证 + 签名收据 +
   客户端同码复验 + watcher 审计"的归责链，并在对外文案中如实标注
   （延续 plan-appchain §6 的禁用词纪律，不写"trustless"）。
3. **与上游对齐**：C 逆 Plan D 而行，维护成本不可控；待 Phase 2 Cairo
   verifier PoC（roadmap §3）落地后再评估"链上验 STARK/递归收口"。
4. **B 留升级缝**：receipt 进 AIR 公开列（上游 `SubmitShuffleV2Air` 形态）
   保留为后续选项，不预先支付 trace 成本。

### 分阶段里程碑（每阶段有出口判据）

**阶段 0：现状复核与单批合并实测（S，估算 0.5–1 周）**
- 复跑上游 `canonical_full_hand_proof_perf_sweep` 最新形态 + 以
  `prove_canonical_reveal_completion_batch` 通道实测
  `JoinTable→StartHand→SubmitShuffle×n→ShuffleComplete→SubmitReveal→
  RevealComplete→Bet…→AdvanceRound` 能否单 batch 出证；不能则确定双段
  续链点（pre/post_state_commitment 环接）。
- **出口**：差距重估记录（本档附录或 BLOCKERS 新条目）：单批/两段结论、
  行数（log 8/9 跳档判定）、协议行 prove/verify 增量实测数字。

**阶段 1：证明链前移 + hand_binding 升级（M，估算 2–4 周）**
- zchain e2e/适配器把 batch 起点前移到 shuffle 段（含 StartHand 与
  `deck_commit_0` 进入镜像）；结算侧强制首/末转移 kind 与 `blind_opening`
  存在性（§5-C2）；hand_binding 升级为覆盖 deck 承诺链
  （§5-C3，ABI v1.3）。
- **出口**：e2e 一手全链（洗牌→发牌→下注→结算→REAL 提现 finality）出证
  通过；篡改负例矩阵全拒：改 `deck_commitment` 任一环、换/删 reveal token、
  盲注面额与 `blind_opening` 脱钩、跨手拼装 deck 链、
  缺协议行的降级批冒充全链批。

**阶段 2：密码学方程双端验证 + receipt 归责（M–L，估算 3–5 周）**
- 引擎 verify 路径加 BG V2 + DLEq 原生验证（feature 门控，REAL 必开）；
  receipt digest（statement + call_context + engine key）冻结 ABI 并入
  attestation v2.2 + proof registry；wallet-core wasm 同码复验；
  watcher 加洗牌链对账（承诺链连续 + receipt 集完整）。
- **出口**：独立 verifier（不依赖 host witness）对完整洗牌/发牌链复验通过；
  引擎侧被绕过（attestation 缺 receipt/ 错 statement digest）的负例全拒；
  原生验证延迟实测落档 `docs/plan-appchain-perf.md`（门槛在实测后定，
  初稿预期 < 1s p95 附加——估算）。

**阶段 3（远期，不承诺排期）：密码学自证或链上兜底**
- 触发条件：Phase 2 递归桥 PoC 有成本结论（roadmap §3），或上游把
  STATUS gap #1 收口。届时重估路线 C / Starknet EC_OP 接入。

---

## 5. 对链侧（zchain）的改动清单

- **C1 `poker-appchain-texasair`**（适配器）：
  - verify 编排扩展：STARK 通过后追加密码学原生验证（输入 =
    归档镜像 `deck_commitment` 链 + 协议行 `proof_commitment` + 客户端
    提交的 BG/DLEq 证明材料——**材料目前不在 canonical 归档内**，需要
    伴随证明包（sidecar）或扩展归档，形态是 §6-Q2 的决策点）。
  - attestation v2.2：payload 追加 `shuffle_chain_digest` 与 receipt 集
    摘要（沿用 v2→v2.1 的"域不变、形状区分"纪律，ABI.md §8.3）。
- **C2 `poker-appchain::settlement`**（结算校验，纯函数，fail-closed 清单
  增项）：
  - 首 kind ∈ {JoinTable, StartHand, SubmitShuffle}（按阶段 0 结论定集）、
    末 kind ∈ 结算语义集；全链批必须 `blind_opening.is_some()`；
  - 镜像偏移断言扩到 `deck_commitment`（对 `pre_state_image_bytes` 起点帧）；
  - ABI 版本：v1.3（**加法式**：新校验只收紧不放宽；`TexasArchiveScope`
    前缀消费零改动，镜像一致性测试扩字段）。
- **C3 hand_binding 语义升级**（ABI v1.3，**语义变化须升域**）：
  现值 `batch_digest`（blake2b witness 域）升级为 Poseidon 折叠
  `hand_binding = poseidon(DOMAIN_v2, batch_digest, deck_chain_digest,
  reveal_commitment)`（域 `zchain.settlement.binding.v2`）——与上游
  `hand_binding.rs` 布局对齐程度（含 players/settlement_digest 全量对齐
  还是 zchain 折影子集）是 §6-Q3 决策点；旧值兼容期按 ABI v2 迁移纪律
  （plan-appchain §6.12.1b 的双轨先例）。
- **C4 与 settlement 的衔接**：`settle_effect`/`HandProofBinding` 不变
  （结构已含 pre/post 状态根）；payout 投影、rake 口径（B9）全部不动。
  wallet 签名预览（§6.12 结构化预览）追加"洗牌链摘要"字段。
- **C5 生产者接线**（既有债，本立项的硬前置）：canonical 协议行 witness
  归档的实时生产者（`BLOCKERS.md:272-274`）——texas 游戏层在
  shuffle/reveal 阶段产出 canonical transition witness（含 BG/DLEq 材料）
  并接 `ProofPipeline`。**这是阶段 1 最大的不确定工作量**（估算：占阶段 1
  一半以上；上游 `proving-tool`/`hand-bench` 是参照实现）。
- **C6 owner_v2 联动（不阻塞）**：若 §6-Q5 决策为"owner key 即加密公钥"，
  `AccountBindingRegistry` 需在入座（JoinTable）时登记 seat 加密公钥并
  进 lifecycle root；实现随 v2 wallet 线，不进本链首阶段。

---

## 6. 开放问题清单（需上游/业务决策）

- **Q1（上游）单批合并现状**：RevealComplete 组合（2026-09-11）之后，
  四段拆分是否已收敛为单 batch？`perf_sweep` 注释与 STATUS.md 时序矛盾，
  需上游确认或阶段 0 实测定论。
- **Q2（上游/双仓）密码学证明材料的传输形态**：BG/DLEq 材料不进 canonical
  归档；选择 (a) sidecar 伴随证明包（`poker-protocol-abi` 的
  `RistrettoAirV2SubmissionPackage`/`ZR4A` 是现成容器先例）、(b) 扩归档
  尾缀字段、(c) 引擎从链下提交层拉取。影响 C1/C5 设计。
- **Q3（双仓）承诺口径统一**：canonical 镜像 32B `deck_commitment` 的
  规范派生函数（从 52 密文到 32B 的唯一权威）、`deck_commitment.rs` 的
  u64 前缀、上游 hand_binding 的 felt 承诺——三者关系需一份冻结规格；
  zchain hand_binding v2 与上游 `hand_binding.rs` 全量对齐还是子集折叠。
- **Q4（业务）v1 密钥托管的信任表述**：v1 客户端密钥托管于运营方
  （`BLOCKERS.md:277-278`），洗牌/发牌私钥同理——此时 S2/S3 证明的对手
  模型不含"运营方独力作弊"（它自己有全部私钥）。对外叙事必须限定为
  "协议执行可验证"而非"运营方无法操纵牌序"；玩家亲自参与 shuffle/reveal
  （密钥自托管）前，命题强度不变。文案口径需产品/法务确认。
- **Q5（业务+安全）owner_v2 StarkCurve owner 与牌堆加密公钥合一**：
  绑定自然但引入密钥复用（ spend 授权 vs 加密身份同钥）；如合一，
  需域分离规格与安全评审；如不合一，seat 加密公钥的登记/轮换通道
  要新设计。
- **Q6（上游）`blind_opening` 与 `rake_opening` 的批次共存语义**：
  两 opening 的计费基数衔接（B9 contested-only 残余边界，
  `BLOCKERS.md:106-108`）在"全链批"形态下是否出现新组合（首段含
  reveal 完成行 + 末段 raked 终局的跨批归档），需在阶段 1 的负例矩阵里
  显式覆盖。
- **Q7（上游）`RISTRETTO_AIR_DECK_SIZE`/`ZR4A` 容器等 Ristretto 时代
  遗产**在新 Stark 曲线世界是否维持兼容义务（影响 Q2 容器选型）。
- **Q8（双仓）协议行 trace 行数与 log 跳档**：全链批行数（含 9 座位
  超时级联最坏情形）是否触发 `MIN_LOG_SIZE` 8→9；若触发，单手证明
  成本跳档与 3s 门槛（M4-ACC-1）的余量重算（DR-1 重访条件）。

---

## 7. 立项记录

```text
立项：洗牌/发牌证明链（外部评审建议 3 第①段出口；一手证明链覆盖
      发牌→下注→结算全程；状态机层走既有 canonical AIR 29 选择子协议行，
      密码学方程层走 sigma/BG 双端原生验证 + receipt 归责）。
推荐路线：A（canonical 续链 + 引擎/客户端双端原生验证）为主干，
      B（verifier receipt digest 归责，attestation v2.2 档先行）叠加；
      C（密码学方程进 circle-STARK）不做，随 Phase 2 递归桥 PoC 重估。
首阶段出口：阶段 0 差距重估记录落档——单批/两段合并结论（含
      prove_canonical_reveal_completion_batch 通道实测）、全链批行数与
      log 8/9 跳档判定、协议行 prove/verify 增量实测数字。
日期：2026-09-13
```
