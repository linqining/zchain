# 排期表：后续阶段工作分解（2026-09-13）

> 对应盘点"组三（后续阶段）"的执行排期。原则：不互相阻塞——各条目只要
> 其自身依赖满足即可启动；标注 **[进行中]** 的条目本轮已开工。工作量档位
> （S/M/L/XL）是相对估算，非承诺工期；每条含入口/出口判据，出口判据即验收。
>
> **2026-09-13 二次盘点（全量实现核对 + e2e 复验）**：对照本表逐项核对
> 代码实现并补齐缺口——本轮新增交付：阈值 BLS（t-of-n）、DA v2
> （object_type 签名域 + Merkle 分块挑战-应答）、withdrawal_root 进
> checkpoint（additive）、bond/slash 对账恒等（链式摘要 + 两侧 reconcile）、
> 合规运营化框架（版本化 geo_policy + 准入门 + 审计账 + 指标）。全部
> workspace crate + extension + wallet-app + 场景演练复验绿（详见交付
> 报告）。原文状态行下方以 **[2026-09-13 核对]** 注记修正。
>
> **常规测试入口（2026-09-13 立档）**：`bash scripts/e2e_acceptance.sh`
> （full/quick）——workspace release 套件 + 节点 e2e + 4 场景演练（串行
> 强制）+ extension 浏览器 E2E + 独立 workspace + fuzz + 1000 手审计
> 留痕；结果时间戳落档 `docs/test-records/`，立档日全量记录见
> `docs/e2e-acceptance-2026-09-13.md`。
>
> **套件口径（如实标注）**：官方测试口径为逐 crate（`scripts/ci_local.sh`
> 与 CI workflow：poker_l1/poker-appchain/poker-settlement-core/poker-wallet
> 各自 `--release`），不含 `third_party/` vendored 包自身的测试目标——
> 上游 crates.io 1.2.2 打包剥离了 path 型 dev-dependency
> （`stwo-cairo-dev-utils` 等），vendored prover 的 `cargo test` 无法编译；
> 该 import 只承载 Poseidon252 witness closure（见
> `third_party/stwo-cairo/README.md`），其测试属上游 CI 范畴。临时
> `cargo test --workspace` 需 `--exclude stwo-cairo-prover`。
>
> **2026-09-13 三次核验（复验 + 回归修复）**：对照本表复验二次盘点五项
> 交付（实现+测试均在树：`dkg.rs`/`da.rs` v2/`poker-appchain/checkpoint.rs`
> withdrawal_root/`slash.rs`+`bond.rs` 对账/`compliance.rs` 准入接线），
> 全量 release 套件 3714/0（54 目标，`--exclude stwo-cairo-prover`）+
> extension 154/154 + zwallet 19/19。复验同时发现阈值/聚合 7 节点演练的
> kill-2 场景回归（恰 quorum 存活时引用轮闭合检查 × 掉线作者死锁），已修复
> 并回写 §2 两行；修复后受影响目标复验 poker_l1 lib 1896 / poker-appchain
> 390 / zchain 17 全绿，两演练 PASS（阈值 PASS=9 FAIL=0 第 1 次尝试、聚合
> PASS=5 FAIL=0）。上游洗牌链阶段 0 状态过时表述已修正（§4 行）。

## 1. 钱包产品线（§6.12）

| 条目 | 依赖 | 量 | 状态 / 出口判据 |
|---|---|---|---|
| Extension 0.2（testnet、多账户、REAL/PLAY 隔离、proof portal、备份恢复、网络切换） | 无 | M | **✅ 完成**（实际交付越过：0.4.0-alpha）。多账户隔离/切换确认/fail-closed 恢复全测试 + run_02 真浏览器 36/36；遗留（如实登记）：provider proof 方法、SeenReceipt 验签、REAL 提现。**[2026-09-13 核对]** |
| Extension 0.3 收尾（提现预览、relay/ForceInclude 状态、SNIP-12 会话密钥授权 UI） | ForceInclude ✅（已上线协议对象）；WC 生产 relay 见前置 B5 | M | **◐ 大部分交付**：提现预览（finality 展示态、canSubmit 恒 false）、receipt 状态机 signed→seen→included（超 deadline 提示 ForceInclude）、SNIP-12 会话密钥授权 UI + wasm 摘要互操作（run_03 30/30）。缺口：WC 生产 relay（B5 外部依赖，dormant 如实登记）、SeenReceipt 验签、included 链上核对通道。**[2026-09-13 核对]** |
| Extension 0.4（account binding registry UI、会话密钥撤销/单笔每日限额、capability matrix） | ABI v2 alpha ✅（下条） | L | **◐ 交付（本地/展示面）**：授权簿/会话密钥列表（scope/限额/撤销）、单笔/每日限额校验（JS + wasm 双层）、capability matrix 三协议行（6 测试）。缺口：链侧 admission 登记、会话密钥直接出 SpendAuth 签名路径。**[2026-09-13 核对]** |
| Extension 1.0（第三方安全审查、可复现构建、硬件钱包可读签名） | 外部审查排期（前置 B4） | L+外部 | **◐ 立项并交付工程面**：`scripts/extension_reproducible_build.sh`（锁定 vendor wasm/glue SHA-256 + 两阶段独立组装 + SOURCE_DATE_EPOCH 归一 + 逐字节比对，REPRODUCIBLE PASS）。缺口：wasm 源码级工具链容器重建、签名发布/SBOM、外部审查。**[2026-09-13 核对]** |
| 独立钱包应用 MVP（Tauri 桌面壳，复用 wallet-core） | 无 | M | **✅ 完成**（Tauri v2 + zwallet 核心接线层；创建/导入、PLAY note 列表、逐字段签名确认、备份恢复 fail-closed、应用锁/自动锁——集成测试 19/19 绿）。缺口：tauri build 打包、链上连通（demo faucet 如实标注）。**[2026-09-13 核对]** |
| ABI v2 alpha（OwnerRef / SignatureEnvelope / MigrateNote 定义与校验关系） | 无 | M | **✅ 完成**（owner_v2.rs/note_v2.rs：三 scheme 判别值冻结 + 三 scheme 验签正负例 + SNIP-12 互操作冻结向量 + 逐字段篡改矩阵；v1 判别值 0..=6 零变更）。**[2026-09-13 核对]** |
| ABI v2 正式版（v2 Note 准入 + MigrateNote 接入链 + 迁移交易进 proof/checkpoint） | ABI v2 alpha ✅；治理确认迁移参数 | L | **✅ 完成（代码/测试层）**：MigrateNote=7/SettleV2=8 进准入（submit_migrate 专道）、迁移帧进帧链并被水位覆盖、v2 账本承诺进状态根、checkpoint 全量覆盖、双 verifier 并行结算 + 混合结算、端到端迁移 + WAL 重放等价（tests/note_v2.rs）。缺口（如实）：AIR/STARK 侧 v2 关系仅 witness 形状就绪；治理迁移参数待定。**[2026-09-13 核对]** |

## 2. 共识与协议（v1.5）

> 外部评审建议 1（可信度：高）已采纳：**DA 选型是 v1.5 叙事的前置条件**
> （方案唯一结构性缺位——checkpoint 只落运营方自有存储，逃生舱依赖的
> "最后 finalized checkpoint"会随 sequencer 扣数据一起不可用）。DA 行
> 据此升格为两段：选型决策（前置）+ 层实现。

| 条目 | 依赖 | 量 | 状态 / 出口判据 |
|---|---|---|---|
| **DA 选型决策（建议 1，前置）** | 无 | M | **✅ 完成**（`docs/da-selection.md`，2026-09-13）。决策：分层方案——L1 双 provider 对象存储 + da.rs 演进（签名域加 object_type、回执加挑战-应答）+ Starknet Vault 根锚定；L2 全量归档自托管；Celestia 触发式备选；EigenDA/Avail 本期不引入。关键结论：DA 关键层（checkpoint+根）MB/天量级且与手数解耦，全量数据不承载逃生舱。待办已识别：da.rs"凭证成立≠数据可取"缺口、checkpoint v1 缺 withdrawal_root、batch_roots 无界增长 |
| ForceInclude 强化（receipt 持久化、forced 集进 vertex 载荷） | 无 | M | **✅ 完成**：receipt sidecar 重启可答、forced 集进 vertex 载荷（additive BCS）；审查演练 PASS=8 FAIL=0 |
| Checkpoint + 聚合 QC 原型（HotStuff-2/Jolteon 前置层） | 无 | XL | **✅ 完成 + kill-2 收敛修复（2026-09-13）**：blstrs 零新依赖、2f+1 聚合配对验证；commit 投票语句发散（恰 quorum 存活时 leader 推断窗口错位 → cert hash 分裂）已修复为 canonical leader 候选序——**聚合演练 PASS=5 FAIL=0（kill-2 后链 28→32、QC 推进至 32）**；恰 quorum 存活的第二处死锁（引用轮闭合检查 × 掉线作者）由前沿缺席分类修复（见阈值 BLS 行 [三次核验回归+修复]）；HotStuff 流水线差距文档化 |
| 阈值 BLS 聚合签名（真 t-of-n） | 聚合 QC ✅ | L | **✅ 完成（2026-09-13）**：`consensus/dkg.rs` deal-sum DKG（Feldman 承诺、群私钥从不以明文存在、坏 dealer 定位）+ 份额签名 + Lagrange 重构接 `bls_aggregate_g1_weighted` 预留点 + **单配对验证（阈值 747µs vs 聚合 4764µs = 6.4×）**；CheckpointQc 双形态 additive（Aggregate 零回退）；`--qc-threshold-t` + `zchain dkg` 子命令；17 新测试；**7 节点演练 kill-2 后存活恰 5=t 仍产阈值 QC（mode=threshold）+ 重启恢复 fail-closed（PASS=9 FAIL=0，第 1 次尝试）**；边界：DKG 无投诉轮、HotStuff chain-QC 流水线另行。**[三次核验回归+修复]** 二次盘点复验发现 kill-2 场景 3 次尝试全败（引用轮闭合检查把掉线 validator 的 vertex 当 gossip 在途无限等待 + 候选 round-asc 序最老者整体弃权 → commit 冻死）；修复为前沿缺席分类（`bullshark::author_has_vertex_since` + `COMMIT_ABSENCE_ROUNDS`，DAG 内容纯函数、finality 口径不变），修复后第 1 次尝试 PASS=9 FAIL=0，聚合演练同轮 PASS=5 FAIL=0 |
| DA 层原型 | DA 选型 ✅；checkpoint QC ✅ | L | **✅ 原型完成**：DaRequest/DaReceipt（独立域防重放）/DaCertificate 2f+1 聚合，M8-ACC-8 停机注入场景通过；**[2026-09-13 二次盘点]** DaReceiptV2/DaCertificateV2（object_type 进签名域防跨对象重放）+ Merkle 分块挑战-应答原语（blob_chunk_digests/chunk_merkle_root/verify_chunk_inclusion/challenge_chunk_index，负例矩阵 8 测试）——原语与证书装配层交付，gossip 轮次/擦除码/采样留后续（da.rs 模块注释口径） |
| bond/slash 真实罚没 | bond 记账 ✅ | M | **✅ 完成**：SlashLedger 从 stake 扣减、归零停出块（active_count 5→4 实测）、evidence 幂等；与 appchain BondLedger 对账接线留待 |
| 抗审查演练 | ForceInclude 强化 ✅ | M | **✅ 完成**：scenario_censorship_drill PASS=8 FAIL=0（三态 + forced 进块 + 重启后 receipt 可答） |

## 3. 证明与退出（Phase 2）

> 外部评审建议 2（可信度：中高）已采纳：**Cairo verifier 提前 PoC**。
> 核对修正：Stwo 验证已随 Starknet v0.13.6 进主网、Herodotus Integrity
> 已上线——但它们验的是 **Cairo 程序执行证明**，本项目是自定义 AIR 的
> stwo 证明，中间差一层**递归桥**（把 AIR verifier 检查写成 Cairo 程序
> 再出证）。PoC 的真正价值正是暴露这层成本，故拆出独立 PoC 行。

| 条目 | 依赖 | 量 | 状态 / 出口判据 |
|---|---|---|---|
| stwo-wasm（浏览器完整 STARK 验证） | **✅ 完成（路径 A 已拍板并交付，2026-09-13）**。vendored stwo（16 cfg 门→feature 门，diff 存档，native 逐字节不变）；**canonical 真证明 wasm 完整验证跑通**：p50 1699–1735ms（超 500ms 门槛 3.5×，wasm/native≈9.2×——Poseidon felt252 软件大数主导；按"explorer 低频性能不敏感"口径如实标注交付）；负例 9/9 拒；扩展 portal STARK 卡片（版本/耗时/超预算标注）+ E2E run_04 12/12、run_02/03 零回退、node 142/142。E3/M4-ACC-5 闭环（超预算如实记录）；优化方向（simd/wasm 内存布局/上游 feature 门 PR）见 `docs/stwo-wasm-path-a.md` §遗留 |
| **Cairo verifier PoC——递归桥成本实测（建议 2）** | 无强依赖 | M（PoC）→XL（正式） | **✅ 完成（CONDITIONAL，2026-09-13，`docs/cairo-bridge-poc.md`）**。全链路真实跑通：canonical 形状最小验证子集用官方 verifier_core v1.2.2 写成 Cairo 程序，cairo-vm → stwo-cairo 出证 → 双通道验证通过（Rust mirror 与官方 Cairo 重算逐位一致，poseidon 计数 38 精确闭合）。**实测**：hades 9.06 steps/M31 乘 18.03/QM31 乘 148.23/fri_fold 145.28/channel draw≈511；15,098 步验证程序出证 8–24s（Blake2s）/570–642s（Poseidon252）。**外推**：完整 canonical AIR 递归桥 ≈2.18×10⁸ steps/证明（出证 ≈7 分钟）；直接合约验 AIR = 24.7B L2 gas → **NO-GO**；递归桥链上验最终证明 ≈10M–100M L2 gas。**Phase 2 结论**：单次"证明上链即验"否决；无信任退出 CONDITIONAL GO（前置：FRI 降 q→≈72M 步 + OOD scope 树 + 聚合 economics） |
| Starknet Vault verifier（正式接入） | 递归桥 PoC 结论 | XL | 立项项。出口：canonical 批次证明上链可验证 |
| withdrawal root + permissionless claim（逻辑层） | Vault verifier（链上面后置） | L | **✅ 逻辑层完成**：RFC 6962 风格域分离 + ClaimLedger 四步校验 + 6 类拒绝路径 + 重载等价；M7-ACC-5 语义测试钉住 |
| 储备证明（STARK） | Vault verifier；报表输入 ✅（M7 数据结构已预对齐） | XL | 立项项。出口：第三方独立验证偿付能力 |
| stwo 递归证明聚合（outer_aggregate 的递归形态） | stwo 递归 API 上游；递归桥 PoC | L | 当前聚合根（v1.2.3）为承诺折叠，递归形态随上游排期 |

## 4. 上游与跨仓库路线（建议 3 升格为正式排期项）

> 外部评审建议 3（可信度：高）已采纳：洗牌/发牌证明链空档属实（一手
> 证明自 hand-start 镜像起，方案与 BLOCKERS 均记录），核心卖点只覆盖
> 结算端，与对外"可验证公平"叙事有落差——从"上游跟踪"升格排期。

| 条目 | 依赖 | 量 | 状态 / 出口判据 |
|---|---|---|---|
| **洗牌/发牌证明链（建议 3）** | poker_texas_air canonical AIR | XL | **①设计 ✅ + 上游阶段 0 ✅（PASS）+ ②消费侧链面已落地**：设计文档（2026-09-13）；**阶段 0 于 2026-09-12 在上游实测出口判定 PASS**（单批 13 行全链 prove/verify + 原生 BG/DLEq 校验、log 8 判定维持无需跳 9、reconstruct 三段批入批；实测报告 `poker-appchain/docs/SHUFFLE_STAGE0.md`，上游 STATUS.md 2026-09-12 行）+ **C1–C6 链侧改动已实现**（工作区）——settlement.rs ABI v1.3：hand_binding 升域 `hand_binding_v2 = poseidon(batch_digest + deck_chain_digest + reveal_commitment)`、validate_settlement 按 classify_hand_binding 分派全链强制（首/末 kind、blind_opening、deck/reveal 承诺）、路线 B receipt 门（默认关 fail-closed，上游阶段 0 已 PASS，接线开启待阶段 1）、tests/shuffle_chain_consume/gate。缺口：阶段 1（wire 格式冻结 + hooks 实时接线，XL）；引擎侧 BG/DLEq 验证接进 appchain 消费路径（上游原生校验已存在，消费侧接线属阶段 1）。**[2026-09-13 核对：原文"消费侧未接 deck 链""待路线拍板"均已过时]** |
| Revealing→Betting 下注续链 | 与洗牌链一并设计 | — | 并入上行 |
| S-two GPU 后端 / wasm 兼容性跟踪 | `docs/gpu-prover-probe.md`、stwo-wasm 探针触发条件 | S | 持续 |

## 4b. 密钥管理与合规（外部评审建议 4）

> 来源说明：被引会话材料中建议 4 原文截断；按其核对结论重建——评价
> 指向 **密钥管理基础设施与合规运营化**，核对明确"HSM/KMS 批评应加重
> 而非删减"（appchain 侧 sequencer/attestor 密钥目前从环境变量种子
> **确定性派生**；仅 poker_l1 部署文档 37-1 提过 KMS/HSM 注入，appchain
> 侧没有）。

| 条目 | 依赖 | 量 | 状态 / 出口判据 |
|---|---|---|---|
| **KeyProvider 可插拔密钥注入（建议 4 核心）** | v2 正式版工作流 ✅（已释放） | M | **✅ 完成**：`key_provider.rs`——`KeyProvider` trait + Env/File/Remote(KMS 端点接缝) 三实现 + `from_config` 工厂（无默认回退、全零种子拒、Unix 权限过宽拒、https 降级如实标注）+ `SequencerKey::from_provider`；集成测试 21 项（含 grep 级"无固定种子回退"检查 + mock KMS + 生产装配端到端）；轮换工具 `seq_key_rotate --provider` 同源取钥。**[2026-09-13 核对：原文"排入当前开发"已过时]** |
| 密钥轮换与 KeyProvider 整合 | 轮换工具 ✅（rotation.rs） | S | **✅ 完成**：`bin/seq_key_rotate.rs` `--provider` 路径走 `from_config → SequencerKey::from_provider`（生产同源取钥通道，无默认种子回退）。**[2026-09-13 核对]** |
| 合规运营化框架（地区开关、限额、审计留痕） | 法务评审（前置 D 组） | M | **仓库内实现已出现**（`poker-appchain/src/compliance.rs`：GeoPolicy 版本化/市场开关/KYC 制动位/限额/自排除，2026-09-13 会话期间并入工作树，来源非本轮启动工作流，测试绿已纳入回归）；真实限额数值与市场名单仍待 C-M1 法务评审 |

## 5. 已明确不做/维持边界（防排期腐化）

- fold-win（raked-sole-survivor）计费语义：维持 fail-closed，放开与否是
  运营方业务决策，需先立业务评审再动 B9 语义，不在工程排期内。
- 客户端密钥自托管全面替代托管模式、跨链桥：不在 v1/v1.5 范围。（代币经济已按用户指令移出本边界，见 §6。）

## 6. 代币经济（TE v1：原生代币与稳定币现金桌）

> 来源：`docs/plan-token-economy-v1.md`（TE-v1）+ `docs/plan-token-economy-compliance-v1.md`
> （TEC-v1），2026-09-13 经用户指令正式入排期（原"已明确不做"边界随之撤销）。
> 执行口径（用户指令）：**收费方式以枚举先行**（三仓枚举同步：判别值冻结），
> **具体结算规则留在合约**（poker_l1 texas_poker settlement）。

| 条目 | 依赖 | 量 | 状态 / 出口判据 |
|---|---|---|---|
| **TE-E0 收费枚举三仓同步** | 无 | S–M | **✅ 完成**：判别值 2 三仓冻结一致（settlement-core 常量 / appchain borsh 变体 / 上游 rake_mode）；poker_texas_air mode 2 完整 STARK prove/verify 实测 ~1.2s；合约侧销毁处置已由 TE-M4 定稿（rake_disposal 单一判定点） |
| TE-M1 AssetId 推广 | NoteV2 alpha ✅ | L | **✅ 完成（263 全绿）**：AssetId{domain,token} + 同域跨 token 攻击面 fail-closed（v1 模型无法表达的负例）+ v1 路径零回退 |
| TE-M2 REAL 多币种 | TE-M1 ✅ | L | **✅ 完成（305 全绿）**：DepositV2=9/WithdrawRequestV2=10 + per-token 独立托管恒等式 + 轧差拒绝结构性强制（合并口径平衡账本仍拒） |
| TE-M3 GTS 游戏币标准 | TE-M1 ✅ | XL | **✅ 完成（331 全绿）**：RegisterGameToken=11/IssueGameToken=12/BurnGameToken=13 + 价带双向 + 供给恒等对账导出 |
| TE-M4 GAME 桌（FixedRakeBurn 结算规则合约实现） | TE-E0 ✅；TE-M3 ✅；poker_l1 ✅ | M | **✅ 完成（poker_l1 2421/appchain 340 全绿）**：rake_disposal 单一判定点 + mode1/mode2 plan 逐字节相等对照 + GAME 桌一手 e2e（outstanding 收缩闭环） |
| TE-M5 UI/explorer 呈现 | TE-M2/M3 ✅ | M | **✅ 完成**：网关资产摘要（REAL 三 token + GAME 对账）+ 扩展资产分栏 + 网站资产标识小节（三扫描过） |
| TE-M6 Free 模式（判别值 14/15/16） | TE-M3 ✅ | M | **✅ 完成（364 全绿）**：FaucetMint/BuyGasCredits/BindGasPolicy + INV-TE-8/9 + credit 与 CustodyLedger 物理隔离（非平凡基线逐位不变断言） |
| 合规框架落地（TEC-v1：geo_policy 版本化、KYC 门挂 Deposit/IssueGameToken） | 法务评审（前置 D 组） | L | **◐ 工程面完成（2026-09-13，见 §4b 合规运营化框架行）**：geo_policy 版本化 + KYC 制动位挂 Deposit/DepositV2/IssueGameToken/FaucetMint/BuyGasCredits（TEC-v1 §10-5 同口径）+ RG 自排除/限额/fiat_only/token 白名单 + 审计账 + 指标。缺口：法务评审（前置 D 组，市场名单/限额数值）、watcher 侧钱包筛查接线、购买页 EU 撤回弃权流程（运营/前端面） |
