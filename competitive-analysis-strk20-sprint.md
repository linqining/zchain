# STRK20 Private Sprint 竞品全景分析（2026-09-07）

> 数据来源：registry.json 全部 202 个仓库的 README.md + strk20.json 批量抓取（缓存于本次调研），
> 33 个重点项目深读，102 个 demo_url 存活检测。本项目 = poker_texas_air (RFP-03)。

## 0. 一页结论

**评审规则**（hackathon README）：30% STRK20 集成深度 + 30% 主网可用产品 + 25% 创新 + 15% 文档。
**硬性门槛**：3 笔触及 pool 的**主网**交易 hash + 公开 demo URL + 3 分钟视频，截止 **9 月 7 日 23:59 UTC**。

本项目技术上是 RFP-03 赛道（乃至全场）密码学最强的项目，但 strk20.json 的
`transactions: []`、`demo_url: ""`、`demo_video: ""` 三项全空 = **按当前状态不满足评分门槛**。
主网部署脚本与成本（~115.5 STRK，建议 ≥130）已备好，差额全在执行与展示层。

## 1. 全景统计

| 指标 | 数值 |
|---|---|
| registry 总项目数 | 202 |
| 有 strk20.json | 174 (86%) |
| strk20.json 有 ≥1 笔 tx | 92 |
| tx 达到 3 笔门槛 | 84 |
| tx ≥10 笔（头部量级） | 12（最多 44 笔，aperture） |
| 列出合约地址 | 85 |
| 有 demo_url | 102 |
| 有 demo_video | 61 |
| README 有真实截图/图片 | 34/191 (18%) |
| demo 存活 | 40 个非 vercel URL 中 38 个 200；vercel.app 被本沙箱屏蔽无法核验，抽验大多存活；确认死链：welttowelt/mosby-pass (404)、cenwadike/open-beanie (拒绝连接) |

分类分布（registry category）：Payments 最多，其次 DeFi / Infra / Consumer / Tooling / Gaming。

## 2. 同赛道与游戏类项目优点（深读 10 个）

### dpinones/private-poker —— RFP-03 同题竞品（最重要）
- **定位**：heads-up 单挑扑克，底牌被表达为字面上的加密 STRK20 CARD notes（卡牌即隐私票据）。
- **优点**：把 STRK20 note 机制复用为"只有 viewing key 持有人能发现自己底牌"的载体，思路极巧；
  协议分层文档清晰（PLAN/DEALER_ARCHITECTURE/CARD_NOTE_PROTOCOL/STRK20_DEPENDENCIES）；
  工程纪律强（format/lint/typecheck/test/cairo:check 检查链、`phase0:status` 机器可查状态门、
  SDK pin + 离线复现验证）；**诚实披露**"trustless mental poker 明确推迟到 V2"。
- **完成度**：Phase 0——无可玩 demo、无链上交易、无 strk20.json。可信 dealer 是 V1 前提。
- **对本项目的含义**：赛道内没有"可玩 + 已部署"的既成标杆；对方把 mental poker 推迟，
  本项目的无信任发牌就是差异化制高点，但要拿出可玩证据才能兑现。

### DevTest-me/hidden-starknet (HIDDEN)
- **定位**：主网 live 的 1v1 押注游戏合集（RPS/囚徒困境/Bluff 暗牌下注/刺客目标）。
- **优点**：把"移动隐私"（合约 commit-reveal）与"资金隐私"（STRK20 pool）职责分得很清；
  "What's actually private, and what isn't" 三段论是隐私叙事范本；主网端到端全生命周期
  （create→join→commit→reveal→resolve→payout 走 privacy_invoke）；超时判负、取消退款、
  localStorage 恢复等**产品完成度细节**；strk20.json 3 tx + 1 合约 + Vercel demo + YouTube 视频齐全；
  README 顶部居中 logo + 徽章 + 一句话 slogan。
- **借鉴**：它的 Bluff 是场上最接近"暗牌扑克"的可玩产品；"两个机制各管一种隐私"的写法值得抄。

### nickthelegend/molfi-fun
- **定位**：隐私预测市场（价格区间下注，结算前密封）。
- **优点**：strk20.json 全场最强之一（27 tx + 3 合约 + 自托管 mp4 + 自有域名）；
  坦诚披露 2026-09-06 才修复的旧合约明文 band 泄露，且红色警告 banner 由部署的 ABI 驱动自动撤回；
  88 个 Cairo 测试；TS 定价内核与 Cairo 版向量互锁；**permissionless settlement 验证页**——
  任何陌生人可重算结算核对派付；专属 /privacy 页逐 route 声明隐私主张。
- **借鉴**：泄露修复史 = 工程能力 + 诚实的双重展示，全场最佳叙事；"可验证性做成可演示页面"。

### broody/stake-wars
- **定位**：质押即领土战争（委托 STRK 作为 FORCE 攻防 Sector）。
- **优点**：把可复用的 STRK20 集成（Whisper 密封竞拍库：Cairo + headless TS SDK）做成独立库
  再被产品消费——"一次提交、两个仓库、边界清晰"；React Three Fiber 3D 前端；Sepolia 部署；
  demo 视频与 URL 均挂自有域名 assets.stakewars.gg / stakewars.gg，观感最专业。

### BlackAporia/game-shield
- **定位**：游戏赏金中枢（STRK20 注资、审核、多赢家分池、无许可退款），**已部署主网**。
- **优点**："Design decision: from commit-reveal to public payout"——完整的抢跑分析→根因→
  简化修复→tradeoff 披露的安全权衡故事；snforge 全路径覆盖；status checklist 全勾；
  YouTube + Vercel 的最低成本全套组合。

### Calcutatator/STRKWORLD
- **定位**：2D 共享城市，每栋楼是一个真实隐私协议（Bank/Exchange/Post Office/Bridge/Vault）。
- **优点**：游戏层从不触碰私钥/prover/viewing key，玩家选择编译为窄类型 intent 过 privacy gate；
  Phaser + Colyseus 的**隐私最小多人**（结构上看不到地址）；每栋楼 "v1 status + live boundary"
  双列状态表；"金融楼无批准隐私路径即锁门"把隐私要求变成游戏机制。弱点：strk20.json 全空。

### joaoolucas/nightfall (Portage.fun)
- **定位**：cozy 风放置类生物收集 RPG。
- **优点**：README 顶部 3 张游戏截图 + live demo 置顶（游戏类最好）；"What stays private" 对照表；
  `validate:submission` 脚本自动校验提交证据（强制 3+ 条 SN_MAIN 交易）；诚实声明
  commit-reveal 孵化"不能称 provably fair"。

### manoahLinks/Cipher21_starknet
- **定位**：Starknet 机密 21 点（纯设计文档，零代码）。
- **优点**：**全场写作质量最高**：完整 TOC、FHEVM↔Starknet 能力对比表、隐私可见性表、
  mermaid 端到端时序图、"两个 leak 说清楚"（withdraw 腿公开→固定面额化解；open note 金额明文→
  可见但不可归因）、论证"庄家知牌靴在 21 点无害、在扑克致命"。M0-M5 每个里程碑以部署地址收尾。

### SunsetLabs-Game/stableroll
- **定位**：跨链隐私工资单（Starknet 注资→Starknet/EVM/Solana 领取）。
- **优点**：**验证文化全场最强**：`docs/verification-guide.md` 把 README 每条主张映射到源码字段/
  测试/命令；`npm run verify:eligibility` 机器校验 strk20.json 的 3 条主网交易；架构图由 typed spec
  生成、CI 防漂移；demo 视频用 **Remotion 代码化渲染**（93 秒，托管 GitHub Release）；
  "What actually works today" 逐组件 Done/Partial 状态表。

### kevlau1/redpocket
- **定位**：链上红包（份额直接落进 shielded 余额）。
- **优点**：三 leg 集成（Shield/Create/Claim）清晰；Merkle 票据 + 域分隔 poseidon root，
  密码永不上链；**"区块浏览器视角"隐私表**（明说 `0xed26…` 领了 0.1179 STRK 可见，密码/剩余票据/
  资金去向不可见）；helper 预部署主网用户零部署；"Limits worth knowing" 直链官方合规文档。

### iamsdpweb3/starkbet21（反面参考）
- 私有 21 点，V0 公开牌 + 构造器种子牌靴，隐私"come later"；无 strk20.json、无 demo。
  唯一亮点：Devnet 0.9 `pending`→`pre_confirmed` 的 RPC 兼容代理。

## 3. 展示标杆项目优点（深读 22 个）

### 第一梯队：证据 + 叙事双满分
| 项目 | 定位 | 核心优点 |
|---|---|---|
| **zkasuran/veilcast** | 私密预测市场 + agent mandate | "For judges" 十行对答表作 README 第一章；`node agent/cli.mjs verify` 一条命令链上重推导全部声明（exit 5=虚假声明/exit 2=诚实不足）；322 测试；把"hub 只读前 10 hash"的规则细读写进 README 并前置计分交易；"The failure \| The rule" 踩坑表 |
| **kamalbuilds/neobank** (sealed.cash) | 私密账户 | strk20.json 的 `notes` 逐笔 tx 注解（评委核对零成本）；"Blocked, not shipped \| Why" 表；章节直接叫 "Status, for a judge opening the demo"；自定义域名 + 同域 demo.mp4 |
| **Jennycruzy/facet** (usefacet.xyz) | shadow account 分身 | "证据账本"式 README（每个声明注明 tx/块高/file:line）；"Honest positioning" 章主动界定窄主张；prover SIGILL 诊断 + ghcr 预构建镜像回馈生态；连 reverted tx 都如实记录 |
| **shariqazeem/sage** (sagepays.xyz) | AI agent 私密支付 | 主网 tx 表写成"故事分镜"（编号步骤+人话+Voyager 链接）；"Proven, not promised" 指标表每数字带出处；自建 `/proof/<tx>` 收据页；11 个资金守卫逐个做 mutation testing |
| **sands786/veyra** | 团队私密财务 | 全场最视觉化：品牌 banner + "The 90-second path" 时间戳表替评委规划动线；双片 Film library（30s teaser + 90s 4K60 judge cut，缩略图直链 mp4）；strk20.json 独有 `onchain_evidence` 生命周期结构 |
| **Immadominion/tip** (usetip.xyz) | Flutter 原生私密钱包 | 从零 Dart 实现协议栈，密码学对照 Cairo 参考值、传输栈逐字节复现 RFC worked examples；tx hash 排版成"阶段名+hash"代码块；诚实长文解释为何未上主网 |
| **OoJae/aperture-strk20** | DAO 密封投票+金库 | 44 笔主网 tx（全场最多）；**RUBRIC_MAP.md** 直接对评分标准建索引；"Things that surprise people" pool 十一个坑清单（生态贡献）；永久锁死的 14 STRK 写进正文附诊断文档；README 当公开修改日志 |
| **drained69/Sotto** | 私密财富工作台 | 四档能力状态表（Live/Mainnet configured/Configuration-dependent/Not active）；Troubleshooting 当评委 FAQ 写；"Who controls what" 责任归属表；fail-closed 配置（缺配置就隐藏不 mock） |
| **Blockchain-Oracle/strk20-run** (strk20.run) | 九合一私密超级 App | "Mainnet record" 表每一行从链上读回；给交易起叙事名（"The hidden buy 买家从未被点名"）；**"What we refuse to claim"** 章用 `claims-lint` 注释标记；池 class hash pin 死不匹配即停机 |
| **Vickrey-Protocol/vickrey** | 密封二价拍卖 | strk20.json 天花板：`$comment` 逐字段解释、`pending` 对象为每个未填字段写解锁条件、三次彩排按 run 存档；自曝 /api/reveals 未授权读取漏洞当日修复；活池 calldata 对照 + 故意放畸形样本让检查"能失败" |
| **neromtoobad/doom** | 私密预测市场 | **"对着真实部署站点录"的 watch 页**；匿名集数量从市场事件日志实测（空市场直说"仅凭金额可识别"）；实测手续费经济学（1 STRK 注赢也亏 74.9%）并自曝早期版本显示相反数字；`yarn verify` 贴 PASS 输出 |

### 第二梯队：单项能力突出
- **PoulavBhowmick03/erebus**：AI agent 藏 note salt 信道谈判；11 笔主网 tx（本批最多）；
  浏览器内模拟 agent 流程（基础设施项目免钱包可"玩"）；用实测回击质疑（wire v3 对活体交易
  分类器 balanced accuracy 0.5000=瞎猜）；docs/runs 日期化运行档案。
- **bongbongcrypto/stealth-checkout**：**demo-arcade 演示场**（投币街机卖点数，mock 钱包两分钟
  全流程零安装）——隐私支付 demo 摩擦最优解；区分"机制测试交易"与"第 8 笔真正的端到端支付"；
  以三条 findings 开头（6 STRK 平板费、delta 确认、QR 流水泄露）。
- **Cyano88/kudiroll**：**为评委专设只读 /demo 路由**（样例数据+禁写+免钱包）；JUDGE_WALKTHROUGH.md
  两分钟走查；提交后持续追加 dated evidence log。
- **dmetagame/cutout**：docs/DEMO_RUNBOOK.md（Judge demo 专用）；冻结模型版本化（同一输入同一
  决策 ID）；每次发版声明"没动什么"。
- **Tutulii/private-payroll**：技术纵深最深（Noir 电路+Garaga verifier 主网+证明三态拆分+
  XChaCha 加密账本+MCP 网关）；能力-证据状态表每行附 evidence 文件；`verify:completion`
  故意会失败的发布门禁。**反面教训**：demo_video 空缺、无免钱包入口——工程满分评委却接触不到。
- **nftkingiii/Morrow**：Evidence 是产品第四个 tab 而非文档；自托管 demo mp4 与应用同域；
  "At present, Morrow has no deployment, live demo, video" 一句话说穿现状。
- **gstohl/quietline**：6+ 张 mermaid 图（全场语义最专业）；开场加粗钉死边界（localnet-only）；
  Release ladder P0→P7 画出现状位置；strk20.json transactions:[] 与 README 声明完全一致。
- **leojay-net/SLPM-V2**：8 张大型 ASCII 图讲密码学管线；"STRK20 Integration" 独立成章解释选型
  （自建 prover 的基础设施成本）；npm alias 隔离 starknet.js 大版本冲突的解法写进 README。
- **kfastov/strk20-indexer**：Infra 范本——demo 页面展示每步实测耗时 + 可展开验证细节；
  本地 note 发现不交 viewing key；"Trust and current limits" 六条信任边界。
- **welttowelt/booty-bank**：meme 钩子（"BORROW AGAINST YOUR BBL"）+ 严肃工程对冲；
  "能点的全能点、不能点的全有标签"（真实链上 swap 与假银行控件同屏但身份清楚）。
- **solutionkanu12/iwa**：一鱼两吃（STRK20 主网 + Zama FHE Sepolia）双旗舰；STATUS.md 实时状态页。

## 4. 标杆共性（展示套路总结）

1. **README 章节模板**：slogan 一句话 → demo/视频链接 → 隐私 vs 公开两列表 → 架构图 →
   主网证据表 → Status/Known limitations → 复现脚本 → 文档地图。前 10 行决定评委去留。
2. **"Private vs Public" 对照表是标配**，且从"什么私密"升级到"什么仍然公开、什么故意公开"
   （"A claim a judge can falsify with one explorer query is worth less than a narrower one that holds"）。
3. **主网 tx 叙事表是最强证据形态**：编号步骤 + 人话描述 + explorer 链接；进阶：/proof/<tx> 收据页、
   strk20.json notes 逐笔注解、onchain_evidence 生命周期。
4. **评委动线被产品化**：For judges 表 / 90-second path / RUBRIC_MAP / JUDGE_WALKTHROUGH /
   DEMO_RUNBOOK——本质都是替评委规划 30-90 秒动线。
5. **免钱包入口三板斧**：只读 /demo 路由（样例数据+禁写）、mock 钱包演示场、浏览器模拟剧本。
6. **demo 视频自托管同域 mp4 是上升流派**（Morrow/erebus/doom/veyra/sage），90 秒-3 分钟黄金时长；
   "对着真实部署站点录"保证视频与产品零脱节。
7. **"不要信我，验证我"产品化**：一条命令 verify + 非零退出码 + PASS 输出贴进 README。
8. **踩坑文档 = 生态贡献 = 成熟度信号**（pool 平板费、note 成熟期、版本冲突、SIGILL…）。
9. **诚实是共同竞争策略**：Blocked 表 / "What we refuse to claim" / 永久锁死资金写进正文 /
   自曝漏洞——精确的失败披露是最稀缺的差异化。

## 5. 本项目 vs 竞品

### 技术维度（本项目优势，且多为全场独有）
| 维度 | 本项目 | 场上最强对手 |
|---|---|---|
| 发牌信任模型 | **无信任 mental poker**：ElGamal 加密 + 玩家联合洗牌 + 每步 sigma proof | dpinones 明确推迟 V2（用可信 dealer）；Cipher21 论证"成本太大"只做 commit-reveal 设计；HIDDEN 用 commit-reveal 只隐藏单步移动；starkbet21 公开牌 |
| 链上验证 | P 层 secp256k1 sigma proofs 经 **EC_OP builtin 链上验证**（PokerDualSettlement） | 多数项目合约仅做业务逻辑；aperture/molfi/doom 的 privacy_invoke 路线无游戏级链上证明 |
| STARK | Stwo circle-STARK 批量证明 + wasm **浏览器可验证** | 场上普遍依赖官方 prover 或无 STARK |
| 形式化验证 | **Lean 4 + Mathlib**，机器检查出 V2 重构不健全性反例并修复为 V3 | 全场无第二家有 Lean 形式化 |
| STRK20 集成 | Vault 1:1 筹码 + 双 anonymizer（买筹/私密领奖 open note）+ SNIP-36 settlement + canonical STRK | 与头部一致（privacy_invoke 路线） |
| 工程配套 | fuzz、hand-bench（一手 29s/1.5MB 证明）、proving-tool CLI、5 合约 Sepolia 全部署 + 详注 strk20.json | 相当于头部水平 |

### 技术维度的相对弱点（评委可挑战点）
- G 层 STARK 目前 host-verified（operator attestation），链上 G verifier 是 Phase 2——需按 RFP
  "eventually" 条款主动框定（README 已做，但要写进评委动线）。
- 主网零交易、零部署：对比 aperture 44 tx / molfi 27 tx / erebus 11 tx。
- "host 是可用性依赖不是正确性依赖"的论证目前埋在 README 中部，评委 30 秒内看不到。

### 展示维度（本项目缺口，对照标杆逐项）
| 展示项 | 标杆做法 | 本项目现状 |
|---|---|---|
| strk20.json transactions | 头部 11-44 笔，最少 3 笔主网 | **空 []** —— 不满足评分硬门槛 |
| demo_video | 90s-3min，自托管/YouTube | **空** |
| demo_url | 品牌域名或评委专用路径 | **空**（客户端未部署公网） |
| registry.json 元数据 | name/one_liner/category/inspired_by | 未填 → 列在 "Other"，不在 Gaming 类 |
| README 截图/图 | 34 家有截图；mermaid/ASCII 图普遍 | 仅 3 个徽章，**零产品截图、零架构图** |
| 隐私/公开对照表 | 几乎标配 | 无（trust model 有，但非对照表形态） |
| 评委动线 | For judges / 90s path / walkthrough | 无 |
| 链上证据表 | tx 叙事表 + explorer 链接 | README 内无任何 0x 地址（addr=False） |
| Known limitations | 独立章节 | 分散在 trust model 段落 |
| verify 命令 | veilcast/doom/cutout 式 | 无（有 hand-verify 但未包装成评委可跑命令） |

## 6. 展示补充清单（按优先级）

### P0 —— 硬性门槛（9/7 23:59 UTC 前，今天）
1. **主网部署**：跑 `poker_contracts/scripts/deploy_mainnet.sh`（成本已估算 ≥130 STRK），
   完成后把 5 个合约地址 + declare/deploy tx 写进 strk20.json contracts。
2. **3 笔主网 pool 交易**：shield→buy-in→对局→settle→私密 claim 任选真实链路，
   每笔都要触及 pool 且带自列合约事件（veilcast 提示：hub 只读前 10 个 hash，合格的排前面）。
3. **3 分钟 demo 视频**：对进 deploy 好的站点录"建桌→发牌验证明文不可见→摊牌→链上结算→
   私密领奖"主线；上传 YouTube（或同域 mp4）。对着真实部署录（doom 式）。
4. **demo_url**：部署 client（Vercel/GitHub Pages/自有域名）。因评委可能没有 Ready wallet + STRK，
   参考 kudiroll/stealth-checkout 做双入口：真实模式 + **免钱包观摩模式**
   （预置一手正在进行的牌局，实时展示 sigma proofs 到达与校验）。
5. **registry.json 补元数据**：`name: poker_texas_air`、`one_liner`、`category: Gaming`、
   `inspired_by: RFP-03`。

### P1 —— README 改造（15% 文档分 + 30% 主网产品的呈现）
6. **顶部三行**：slogan（"cheating is mathematically impossible" 已很好）+ demo 链接 + 视频链接 +
   1-3 张**产品截图**（牌桌面/证明校验面板/结算 tx）。
7. **"For judges" 表**（veilcast 式十行）：RFP 对应、mental poker 差异化、链上 P 验证、
   Lean 形式化、部署地址、demo/视频、如何验证。
8. **隐私/公开对照表**：三层拆分——mental poker 隐藏什么（牌、洗牌过程）、STRK20 隐藏什么
   （筹码流、赢家领取）、什么仍然公开（deposit/withdraw 边、timing、桌面状态）。
   本项目独有卖点：**竞品只藏资金流，牌本身公开或依赖可信 dealer；本项目连游戏状态都加密**。
9. **架构图**：mermaid 画一手牌端到端时序（deal→shuffle proofs→reveal→dual settlement→claim）
   + 双证明分层图（P 链上 / G host+browser / Phase 2 链上）。
10. **状态表**：四档粒度（Live on sepolia / Host-verified / Browser-verifiable / Phase 2 on-chain），
    把"host 是可用性依赖不是正确性依赖"放进第一屏。
11. **Known limitations**：channel-open linkability、G 层临时信任根、operator 可用性、证明体积/时延。
12. **README 写入部署地址表**：Sepolia 5 合约 + 关键 tx，链接 Starkscan。

### P2 —— 加分项（对齐头部）
13. **verify 脚本**：一条命令从链上读回 settlement/claim 事件核对声明（参考 doom `yarn verify`）。
14. **踩坑叙事**：Lean 4 机器检查发现 V2 重构不健全性→修复 V3，写成 "The failure | The rule" 表——
    全场独有的故事，比任何功能都稀缺。
15. **dated evidence log**：提交截止后到 9/11 宣布前持续追加验证记录（kudiroll 式）。
16. **差异化一句话进 one_liner**：如 "The only poker on Starknet with no trusted dealer —
    cards are encrypted, shuffles are proven, and settlement is verified on-chain."

## 7. 附：全部 202 项目速览表

见本次调研生成的 `/tmp/strk20_repos/catalog.txt`（每行：序号/仓库名/分类/RFP/demo/视频/合约数/一句话简介）。
