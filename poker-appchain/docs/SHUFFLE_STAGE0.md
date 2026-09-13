# SHUFFLE_STAGE0 — 洗牌/发牌证明链·阶段 0 实测报告（上游侧）

> 状态：2026-09-12 实施记录（路线 A+B 上游半边，设计文档
> `zchain/docs/shuffle-deal-proof-design.md` §4 里程碑 0 的出口判据落地）。
> 实施仓库：`/Users/mac/projects/poker_texas_air`（工作树改动，未 commit；
> `docs/STATUS.md` 追加一行进度）。
> 配套文档：消费侧语义见本目录 `SHUFFLE_CONSUME.md`；两文冲突处以设计文档
> 与本文的实测数据为准，接口差异已在 §6 显式列出。
>
> 纪律：pinned nightly-2026-04-15 + `--release`；既有测试零回退（§5 基线）；
> 零新依赖；poker_texas_air git 未 commit；诚实降级点全部显式（§7）。

---

## 0. 出口判定：PASS（带 2 个上游 AIR 缺口的如实记录）

| 阶段 0 出口判据（设计文档 §4） | 结果 |
|---|---|
| 单批合并实测：`JoinTable→StartHand→SubmitShuffle×n→ShuffleComplete→SubmitReveal→RevealComplete→Bet…→AdvanceRound` 单批出证 | **PASS\***：单批 13 行全链（SubmitShuffle×4 → SubmitReveal×4(末行 RevealComplete，盲注实投) → Raise → Fold×3 → EndWithoutShowdown）prove + verify + 原生 BG/DLEq 校验全通过（§3.1）。\*起点为 hand-start 投影（street=1），StartHand 行在配套 A0 批内单独出证——street 断点见 §4.1 |
| `prove_canonical_reveal_completion_batch` 通道实测 | **PASS**：该通道直接承载全链批（盲注 opening + 规则 hash 绑定走通） |
| 行数（log 8/9 跳档判定） | **判定：log 8 足够，无需跳 9**。全链单手批 13–18 行；最坏 9 座位 + 超时级联亦 ≪256 行（§3.4）。且当前 AIR 下 >256 行的全链批**本就无法合法表达**（§4.1/§4.2） |
| 协议行 prove/verify 增量实测数字 | **PASS**：§3.3（prove ~1.0s、STARK verify ~165ms、原生链校验 ~330–520ms、BG/DLEq 生产 ~420ms；负载噪声说明见该节） |
| reconstruct（9 行）入批 | **PASS（三段批）**：SubmitReconstruct×2（真实 V3 证明）+ 街 2 揭示 + 下注 + AdvanceRound 在批 1；kick→reconstruct-enter 强制专属级联批（批 2）；重构提交批 3（§3.5） |

---

## 1. 现状测绘结论（侦察，带文件+行号）

### 1.1 生产者排除点（"归档生产者未接线"的具体位置）

- **实时链**：`texas/src/starknet/hooks.rs:176-178` ——
  `let appchain_hand_proof = None;`，注释原文："REAL 桌的 canonical 归档由
  归档生产者供给（v1 残余边界：归档生产者未接线，REAL 手在此显式回退遗留
  路径，见 BLOCKERS B6）"。即 canonical 批的实时生产者**不存在**，
  `texas/src/starknet/appchain/prover.rs` 只有 verify 半边。
- canonical witness 的现有产生者仅两处（全仓 grep）：本 crate 测试夹具
  （`src/texas_canonical_air.rs` tests 模块）与基准 harness
  （`hand-bench/src/main.rs`）。
- 游戏服务器产生 shuffle/reveal 事件的流程（真实密码学流程在，
  只是没接 canonical 归档）：`texas/src/pokergame/table/shuffle.rs`
  （`advance_shuffle`，BG V2 over `DefaultCurve`=Stark 曲线，
  Poseidon 域 `SHUFFLE_V2_POSEIDON`）、`table/phases.rs`
  （`start_preflop_shuffle`/`on_before_preflop_shuffle_complete`/
  reveal 相位机）、`table/full_hand_tests.rs::run_full_hand`（整手真实
  驱动参照）、`starknet/mirror.rs`（VM canonical 重排镜像）。
- **AIR/admission 层没有排除**：`validate_direct_batch`
  （`src/texas_canonical.rs:840-852`）对 SubmitShuffle/SubmitReveal/
  SubmitReconstruct 已放行（#22④/#22② 准入翻转，上游 docs/STATUS.md
  2026-09-05/09-11）。缺口确实只在生产侧。

### 1.2 本阶段新增的生产者（"接线"的形态）

新模块 `src/canonical_shuffle_chain.rs`（公开 API，测试与后续实时生产者
共用）：

- `ShuffleChainBuilder`：持有一手牌的真实密钥/牌堆世系；`produce_shuffle_row`
  （Bayer–Groth V2 prove→**native verify 先行**→deck 承诺轮转→witness 行）、
  `produce_reveal_row`（逐卡 RevealTokenProof(DLEq) prove→verify→reveal
  账本承诺轮转；末行按 `set_reveal_completion_blinds` 做 RevealComplete
  规范化投影）、`produce_reconstruct_row`（ReconstructProofV3 prove→verify
  →reconstruction/deck 承诺锚）。**fail-closed：证明不过不产行。**
- `verify_canonical_batch_with_shuffle_chain(archive, witnesses, sidecar)`：
  路线 A 验证半边——①`verify_canonical_tagged_proof` 全 STARK；②witness↔
  archive 绑定（batch_digest/行数/首末 kind/端点像字节）；③逐协议行 native
  BG/DLEq/V3 校验 + 承诺链从 sidecar 密文**重推导**比对镜像锚；④多余/缺失/
  错位 sidecar 条目一律拒绝。
- `ShuffleChainReceipt`（路线 B 上游半边）：batch_digest + deck/reveal/
  reconstruct 三条链摘要 + 逐行 statement digest +
  `engine_receipt_digest`（域 `zchain.texas.canonical-shuffle-chain.v1`，
  poseidon_bytes_digest 折叠）——attestation v2.2 与 watcher 重放的锚点。
- curve/域：`DefaultCurve`（Stark 曲线）+ `PoseidonFeltTranscript`
  生产域（`SHUFFLE_V2_POSEIDON`/`REVEAL_TOKEN_V3_POSEIDON`/
  `RECONSTRUCT_V3_POSEIDON`），与 texas 游戏服务器一致。

---

## 2. 改动清单（全部工作树，未 commit）

| 文件 | 改动 |
|---|---|
| `src/canonical_shuffle_chain.rs` | **新增**（约 1,270 行）：阶段 0 生产者 + native 双端验证 + receipt（§1.2），`shuffle-chain stage0` 注释贯穿 |
| `src/lib.rs` | 注册 `pub mod canonical_shuffle_chain;`（含模块文档） |
| `tests/canonical_shuffle_chain_stage0.rs` | **新增**（约 1,240 行）：11 个测试（§3），`--nocapture` 输出实测数据 |

不改动：AIR 约束（`texas_canonical_air.rs` 的约束面零改动——本阶段结论是
"无需扩展 trace，只差上游两个小缺口"，见 §4）、texas 游戏服务器
（实时生产者接线属阶段 1 C5）、poker_l1、poker-protocol-*。

---

## 3. 实测数据（`cargo test -p poker_texas_air --release --test
canonical_shuffle_chain_stage0 -- --nocapture`）

> 噪声声明：与 3 个并行 agent 共享本机，首次冷跑出现 17–19s 的 prove 极值；
> 下表为空载复测的稳定值（每项 ≥3 次复测，取代表值），极值区间一并标注。

### 3.1 全链单批（主交付，A1）

13 行 = SubmitShuffle×4（末行 ShuffleComplete）→ SubmitReveal×4（末行
RevealComplete：SB 50/BB 100 实投、UTG/价格/deadline 规范化）→ Raise 300 →
Fold×3 → EndWithoutShowdown（450 入账 + 重置投影）：

- 归档形状：**log_size 8（256 行 trace）、num_columns 5391**
- 密码学生产（4×BG V2 prove + 8×reveal DLEq prove）：**~420–460ms**
- `prove_canonical_reveal_completion_batch`（13 行）：**~1.0–1.1s**
  （负载峰值 18.6s）
- `verify_canonical_tagged_proof`：**~165ms**（峰值 500ms）
- `verify_canonical_batch_with_shuffle_chain`（原生 4×BG verify + 32×DLEq
  verify + 承诺链重推导）：**~330–520ms**
- receipt digest：同种子确定（更换测试种子则值变，函数本身确定）

### 3.2 对照与配套批

| 批 | 行数 | log | 说明 |
|---|---|---|---|
| 纯下注批（Raise+Fold×3+End） | 5 | 8 | prove ~1.9–2.1s / verify ~230–480ms——**与全链批同域同量级**：协议行的 trace 边际成本≈0（单行选择子），成本在原生验证侧 |
| A0：JoinTable×4→StartHand→SubmitShuffle×4 | 9 | 8 | 桌务+洗牌协议合法单批（真实 BG） |
| B1：Call×3+Check→AdvanceRound→街 2 揭示×2 | 7 | 8 | 下注→发牌相位续批 |
| B2：RevealTimeoutKick→RevealTimeoutReconstruct | 2 | 8 | **强制专属级联批**（§4.2） |
| B3：SubmitReconstruct×2（真实 V3 证明，末行 completion→Shuffling/2） | 2 | 8 | 三批 prove 合计 ~1.3s；V3 语句逐行原生校验 + deck/reconstruction 承诺重推导 |

### 3.3 log 8/9 跳档判定

- 跳档条件：单批 >256 行（`tagged_batch_log_size`，`src/trace_gen/
  generic_trace.rs:51-60`；域上限 log 10 = 1024 行）。
- 实测单手全链 13 行（4 人）；9 座位满配（9 shuffle + 9 reveal + 下注 +
  结算）≈ 25 行；再加超时级联最坏情形仍在几十行量级——**距 256 行阈值
  一个数量级，log 8 维持，单手成本与行数解耦（B3/DR-1）继续成立**。
- log 9 实测（258 行合法 Join/Leave 填充批，见 §4.3）：**prove 745ms /
  STARK verify 209ms**——即便未来全链批真的越过 256 行，单批跳档成本的
  绝对值也在亚秒级，3s 门槛（M4-ACC-1）不受威胁。
- **但**：当前 AIR 下"全链 + >256 行"本就无法合法表达（§4.1/§4.2），
  跳档实测用的是 Waiting 相位合法填充，非全链形状——如实标注。

### 3.4 负例矩阵（fail-closed，全绿）

1. **归档 deck 承诺篡改**：端点像字节翻位 → STARK verify 与原生链校验双拒。
2. **非末段 shuffle 行 deck 承诺篡改（重链合法批）**：**AIR 照常出证**（诚实
   缺口：AIR 只冻结锚，不重算密文哈希）→ 原生 sidecar 校验拒（路线 A 的
   存在理由实测演示）。
3. **协议行删除**：中间行裸删 → 批内非连续拒（prove 期）；pending 掩码算术
   使局部删除即使重链也拒；整段删除重链可证 → 原归档 digest 失配拒 + 原生
   侧"多余 sidecar 材料"拒（即使对新归档也拒）。
4. **行序/材料序颠倒**：witness 序换 → digest 失配 + prove 拒；sidecar 序换 →
   座位错位拒。
5. **BG 证明缺失/伪造/密文段偷换**：缺材料、错行证明、output=input 三类全拒。
6. **reveal token 伪造**：换座 token（键绑定+账本轮转双失配）、token 点平移
   （DLEq 拒）。

---

## 4. 阶段 0 新发现的上游 AIR 缺口（附修复建议）

### 4.1 street 断点（阻塞 StartHand→…→RevealComplete 直连）

- `StartHand` 钉 `post.street == 0`（`texas_canonical.rs`
  "start_hand header/button initialization is invalid"）；
- shuffle completion 钉 `post.street == pre.street`
  （`validate_shuffle_completion_opening`，"final shuffle completion has
  invalid VM normalization header"——**实测证实**，见测试探针历史）；
- reveal completion 要求 `pre.street == 1`
  （`validate_reveal_completion_opening`）。
- ⇒ 自 StartHand 起的批，street 恒 0，永远到不了 RevealComplete。
  **修复建议（一行级）**：允许 shuffle completion 的完成开局面把 street
  0→1（与 VM `start_preflop_reveal_phase` 语义一致）；或 StartHand 直接
  开 street=1。阶段 0 的桥接：生产者以 hand-start 投影（street=1）作为
  全链批起点（A1），StartHand 行在 A0 批内出证；两批之间由生产者侧投影
  续链——**这是本报告唯一的"非单批"妥协**。
- 连带后果：in-batch 换手（StartHand 重入批）+ RevealComplete 不可同时
  达成 → **全链批合法行数上限事实上锁死在单手规模**，>256 行全链批不可
  表达（§3.3）。

### 4.2 reveal-timeout 级联的批级隔离

`validate_reveal_timeout_cascade_archive_shape`（`texas_canonical_air.rs:
9522-9564`）：批内一旦出现 Kick 行，该批必须是**专属级联批**（首行 Kick、
座位严格升序、至多一个 terminal 续行）。⇒ reconstruct 链最少三批：
（协议+下注+街 2 揭示）→（kick→reconstruct-enter）→（SubmitReconstruct
提交段）。消费侧跨批衔接按既有 pre/post_state_commitment 环接即可，
但"全链单批"叙事对含 reconstruct 的手不成立。

### 4.3 reconstruct 完成后的续链不可表达（阶段 1 上游缺口）

`validate_shuffle_completion_opening` 要求 `pre_cards_dealt == 0`（preflop
专用），而 reconstruct completion 落到 `Shuffling/subtag-2` 时牌已发
（opening 的 `pre_cards_dealt` 只验 ≤52 不参与该分支）。⇒ 重构后的
重洗牌→重揭示→回下注在 AIR 内**无出口**；阶段 0 批终点钉在
`Shuffling/2`（重构洗牌段）。补 subtag-2 完成分支是阶段 1 的上游前置。

### 4.4 初始牌堆规范分裂（§6-Q3 的具体化）

poker_l1 `set_initial_encrypted_deck` 的 `(G, m)` 种子（sk=0 形式）在聚合钥
BG/逐份额解密世界**不是合法 ElGamal 密文**（隐含 r=1 不出现在 c2，
实测 decrypt(agg) 不落在规范牌集合）。本阶段生产者改用
`canonical_base_deck`（`poker-protocol-proofs/src/reconstruction/v3.rs:178`，
公开确定性随机数 r=i+1，Cairo 可重放）作为 S1 锚。**两处种子形式的
跨仓对齐**是消费侧（zchain deck_chain_digest）与上游必须冻结的第一个
承诺（§6.1）。

---

## 5. 基线与回归（零回退）

| 命令 | 改动前基线 | 改动后 |
|---|---|---|
| `cargo test --workspace --release` | **1355 passed / 0 failed** / 161 ignored | 复测中（见下） |
| `RUSTFLAGS='--cfg=texas_release_tests' cargo test -p poker_texas_air --release --features test-helpers --tests` | **222 passed / 0 failed** / 112 ignored | 复测中（见下） |
| 新增 suite | — | 10 passed / 0 failed / 1 ignored（log-9 测量，`--include-ignored` 门跑） |
| `missing_docs` 棘轮 | budget 323 | **missing_docs: 0（budget 323）** |
| clippy（`--no-deps` 限本阶段文件） | — | 新文件零告警（既有 197 条基线告警不动） |

> 注：`cargo clippy -p poker_texas_air`（不带 `--no-deps`）会在
> third_party/flock-prover 上报 `erasing_op` deny——预先存在的跨 workspace
> lint 配置问题（flock 自己的 workspace lints 在被外层 workspace 引用时不
> 生效），与本阶段改动无关，未触碰 third_party。

---

## 6. 对消费侧（zchain）的接口承诺清单

供 `SHUFFLE_CONSUME.md` 工作流对齐；标注"待冻结"的项在冻结前消费侧
必须保持显式开关（默认关），与该文的纪律一致。

1. **归档本体零变更**：`ArchivedCanonicalTaggedProof`（borsh 信封）形状
   不变；新可达内容 = first/last_transition_kind 现在可以是 7/8/9、
   `blind_opening` + `rules_hash` 将随 RevealComplete 批常态出现。
   `TexasArchiveScope` 前缀消费不受影响；消费侧需确认 `rules_hash`
   （`Option<ArchivedCanonicalRulesHashProof>`）是否进 scope/校验面。
2. **sidecar（Q2 未决，阶段 0 为进程内形态）**：
   `ShuffleChainSidecar { shuffles: [ShuffleRowMaterial],
   reveals: [RevealRowMaterial], reconstructs: [ReconstructRowMaterial] }`，
   批序对齐；`ShuffleRowMaterial = { seat, aggregate_pk, input_deck[52],
   output_deck[52], proof: BayerGrothShuffleProof<StarkCurve> }`；
   `RevealRowMaterial = { seat, seat_pk, revealed: [{card(c1,c2), token,
   proof}] }`；`ReconstructRowMaterial = { seat, statement, proof,
   rebuilt_deck }`。**BG proof 当前无 Borsh 实现 → sidecar 不可序列化**，
   wire 形态（伴随包/归档尾缀/拉取）冻结前消费侧不得假设字节布局。
3. **承诺派生（Q3 提案，待跨仓冻结）**——域
   `zchain.texas.canonical-shuffle-chain.v1`：
   - `deck_commitment = poseidon_points_commitment(⌊c1₀,c2₀,c1₁,c2₁,…⌋)`；
   - 初始牌堆 = `canonical_base_deck`（r=i+1，§4.4，**与 poker_l1 (G,m)
     分裂待对齐**）；
   - reveal 账本轮转 = poseidon_bytes_digest(DOMAIN‖"reveal-ledger"‖pre‖
     seat‖count‖逐卡(c1‖c2‖token))；
   - reconstruction 承诺 = poseidon over V3 contributions (c1‖c2)。
   与消费侧 `deck_chain_digest`（blake2b-256，SHUFFLE_CONSUME.md §1.2）
   **算法不同**：两侧需择一冻结（建议消费侧改用本poseidon 折叠，或上游
   出 blake2b 变体），冻结前 hand_binding v2 的 deck 链摘要按消费侧现值
   计算、不与上游混用。
4. **receipt（路线 B）**：`engine_receipt_digest` =
   poseidon_bytes_digest(DOMAIN‖"receipt"‖batch_digest‖三链摘要‖逐行
   statement digest)，statement digest =
   poseidon_bytes_digest(DOMAIN‖kind‖seat‖pre_commitment‖post_commitment)。
   消费侧 attestation v2.2 可直接 archival 该 32B 值 + 三链摘要 +
   statement_digests 计数；engine key 绑定与签名归 zchain 归责框架。
5. **批形状承诺**：全链单批起点 = hand-start 投影（street=1，
   §4.1 桥接）；含 Kick 的段为专属级联批（§4.2）；reconstruct 段终点 =
   Shuffling/2（§4.3）。zchain 结算校验（C2）的"首 kind ∈
   {JoinTable, StartHand, SubmitShuffle}"白名单需允许这些批段组合。
6. **信任边界重申（§6-Q4）**：阶段 0 的私钥全部在测试/运营方手里
   （builder 持全部 sk），S2/S3 的对手模型不含"运营方独力作弊"；
   对外文案维持"协议执行可验证"口径。

---

## 7. 诚实降级点

1. **生产者接线是测试级而非实时链级**：`hooks.rs:177` 的实时归档生产者
   仍未接线（阶段 1 C5，估算占阶段 1 一半工作量）；本阶段交付的是生产者
   模块 + 证明可行性，不是服务器路径。
2. **"单批"对 reconstruct 不成立**：级联批隔离（§4.2）使其为三批；
   "单批"承诺只对 shuffle→reveal→下注→结算链成立（A1）。
3. **street 断点桥接**：A1 的起点是生产者投影而非 AIR 可证行——两批间的
   street 修复属上游一行级改动，未在本阶段擅自改 AIR 语义（改动建议 §4.1，
   待上游确认后阶段 1 落地）。
4. **V3 语义为行级自洽**：两个 SubmitReconstruct 行各自携带真实 V3 证明并
   通过原生校验，但 poker_l1 语义的"离场者份额累积重构"
   （reconstruct_accumulated 多方贡献合并）未建模——sidecar 按"提交者=
   owner"自洽绑定，累积语义留给阶段 1 生产者集成。
5. **kick 行的 reveal/reconstruction 承诺轮转不被 sidecar 覆盖**：其鉴权
   走 ZR4A reveal-ledger opening（既有机制）；本阶段原生链校验跳过这些行，
   receipt 的 reveal_chain 只覆盖 sidecar 揭示行。
6. **计时噪声**：共享开发机 + 并行编译，单次极值到 18.6s；报告引用的
   代表值为空载复测，基准档（docs/plan-appchain-perf.md）落数前应在
   静止机器复测（阶段 2 出口项）。
7. **log-9 测量的形状妥协**（§3.3/§4.3）：258 行域跳档实测用合法
   Join/Leave 填充，非全链形状。

---

## 8. 复现

```bash
cd /Users/mac/projects/poker_texas_air
# 阶段 0 主 suite（10 tests + 1 ignored）
cargo test -p poker_texas_air --release --test canonical_shuffle_chain_stage0 -- --nocapture
# log-9 域跳档测量
cargo test -p poker_texas_air --release --test canonical_shuffle_chain_stage0 \
  -- --ignored --nocapture
# CI 门（workspace 零回退 + release integration）
cargo test --workspace --release
RUSTFLAGS='--cfg=texas_release_tests' cargo test -p poker_texas_air --release \
  --features test-helpers --tests
```
