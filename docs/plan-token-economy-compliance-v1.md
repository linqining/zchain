# ZChain 代币经济合规框架 v1（TEC-v1）

| 项 | 值 |
|---|---|
| 状态 | 草案（设计冻结前评审稿） |
| 日期 | 2026-09-13 |
| 关联 | `docs/plan-token-economy-v1.md`（TE-v1，技术设计）、`docs/plan-appchain-v1.md` §6 |
| 里程碑前缀 | C-M1..C-M4 |

> **免责声明**：本文是工程侧的合规设计输入，不是法律意见。所有司法辖区
> 结论均基于 2026-09 可公开查证的法律、判例与监管动态（文中附来源）；
> 每个目标市场的上线决定必须由该辖区持牌律师出具书面意见。法规引用
> 以原文为准，本文仅作设计映射。

---

## 0. 监管定位总框架：三个产品，三套监管盒子

TE-v1 的三域资产模型恰好对应三套互不重叠的监管盒子——这是设计的
出发点，也是最重要的结构性结论：

| 产品 | 法律定性 | 监管盒子 | 核心义务 |
|---|---|---|---|
| **REAL 桌**（原生代币/USDT/USDC 现金桌） | 真金远程博彩（real-money gaming） | 赌博法（逐市场牌照制，无跨境通行证） | 牌照、AML、RG（负责任博彩）、游戏认证、博彩税 |
| **GAME 币**（单向游戏币） | 游戏内虚拟货币 / 社交博彩筹码 | 消费者保护法 + 支付法（预付工具）+ 少数辖区赌博法 | 定价透明、撤回权处理、年龄门、个别辖区禁入 |
| **Free 模式桌**（免费游戏币 + gas 服务费，TE-v1 §3.8） | 付费娱乐服务 / 街机-订阅模型（付费玩游戏，奖品无价值） | 消费者保护法 + 支付法（预付服务额度） | 定价透明、撤回权处理、年龄门；敌意辖区仍禁入 |
| **USDT/USDC/原生代币**（我们不发行） | 支付与储备资产 | 稳定币法 / 加密资产服务法（MiCA、GENIUS 等） | 储备托管资质、Travel Rule、钱包筛查、制裁合规 |

**关键定性判断**（后文逐项论证）：

1. GAME 币的"单向 + 不可兑换 + 不可桥"设计在大多数辖区**恰好落在
   赌博法定义之外**（无"可变现奖品"）且落在加密资产法之外（闭环
   非流通）——这是设计带来的合规红利，不是巧合。
2. 但存在**结构性敌意辖区**（华盛顿州、比利时、中国大陆）：那里
   "付费获得筹码参与Chance游戏"本身即构成赌博，与可否赎回无关，
   只能地理封锁，无法靠产品设计消解。
3. REAL 桌没有任何"设计绕行"空间：加密资产在主要辖区均被认定为
   "money or money's worth"，现金桌 = 博彩，唯一合规路径是逐市场
   牌照。
4. **Free 模式（币免费 + 固定 gas 服务费，TE-v1 §3.8）是三种模式中
   赌博法画像最干净的**：对局付费是对服务的固定对价（与胜负无关），
   奖品（免费不稀缺的币）无价值 → 赌博三要件缺"奖品"。这正是
   ClubWPT 订阅制扑克在 49 个州合法运营的同族结构，且我们不发真实
   奖品，比它更保守（§2.1）。

---

## 1. 辖区矩阵（2026-09 口径）

动作含义：`放行` = 可运营；`牌照` = 取得该辖区牌照后可运营；
`法币` = 只能走法币通道；`封禁` = geo-block，不提供服务不投放广告。

| 辖区 | REAL 现金桌 | GAME 币 | 稳定币/通道 | 动作 |
|---|---|---|---|---|
| 中国大陆 | 禁（在线赌博入刑；2021 起虚拟货币交易全面禁止） | 品类禁（德扑类棋牌 2018 起清理下架，"游戏币兑筹码下注"被认定变相赌博） | 禁 | **全产品封禁**（含广告投放） |
| 美国联邦 | 无跨州授权 | 闭环非兑换币 ≠ CVC（FinCEN 口径），非证券（无升值预期） | GENIUS 法案 2027-01 前后生效，仅允许 permitted payment stablecoin（USDC 合规；USDT 属外国发行人待认定） | REAL 走 B2B；GAME 全国放行**除敌意州** |
| 华盛顿州等 | 未授权 | **非法赌博**（*Kater v. Churchill Downs*, 9th Cir. 2018：虚拟筹码延长游戏 = "thing of value"；2025 州检察长仍在大规模执法） | — | **GAME 封禁**（参照同行做法屏蔽 WA 用户） |
| 美国 6 个合法州（NV/DE/NJ/PA/MI/WV，MSIGA 共享流动性） | 州牌照 + 21 岁 + 州内地理围栏；州持牌商现仅法币入金 | 同联邦 | 州持牌场景法币为主 | Phase 3 经持牌运营商 B2B 进入 |
| 英国 | 需 UKGC 牌照；加密资产 = "money's worth" 即属牌照活动；**2026-02 UKGC 正在评审允许持牌商收加密支付** | 无 money's worth 奖品即豁免（非博彩） | 持牌商支付通道需报备 | REAL = 牌照目标市场；GAME 放行 |
| 德国 | GGL 持牌商**禁止加密货币交易**（仅欧元；€1 下注上限 / €1,000 月充值上限 / LUGAS） | 消费者法适用 | — | REAL 仅法币方案或放弃；GAME 放行（消费者合规见 §4） |
| 马耳他 | MGA 牌照（B2C Type 1-4；欧盟声誉最优） | 放行 | 受监管加密在牌照框架内可接受 | REAL Phase 2 基地 |
| 荷兰 | 远程赌博法（2021）牌照可做线上扑克 | KSA 对奖品价值测试严格（loot box 前科） | — | REAL = 牌照市场；GAME 谨慎评估 |
| 比利时 | 牌照制 | **社交博彩类游戏 + loot box 被认定无牌即刑事违法** | — | **GAME 封禁**（不做比利时用户与广告） |
| 澳大利亚 | IGA 禁止线上赌场/扑克（**2026-08 修正案进一步收紧**） | 豁免（判例口径：不可变现即非赌博服务；监管关注持续） | — | REAL 封禁；GAME 放行但保留收紧预案 |
| 日本 | 赌博禁止（例外极少） | 自家事业型预付支付手段：未使用余额 > ¥1,000 万需向财务局**申报**（非注册） | — | REAL 封禁；GAME 申报制合规放行 |
| 库拉索 | LOK 新制（2024-12 起 CGA 直接发牌）；**2026-06 加密规则生效**：禁 mixer/受制裁钱包、加密默认高风险、偏好受监管法币稳定币、匿名钱包 EDD、23 国禁入名单，2027-06 全面达标 | 放行 | 上述加密规则 | REAL Phase 1 备选基地 |
| 马恩岛 | OGRA（£36,750/年、5 年期，历史最友好加密博彩辖区） | 放行 | 牌照框架内 | REAL Phase 1 首选基地 |
| 安茹安 | 低价快速（首年 €18-42K、0% 博彩税） | 放行 | crypto-ready | 仅作早期过渡，声誉弱 |

矩阵维护纪律：这是**版本化的运营参数**（对应 §5 的 GEO 准入表），
每季度法务复核 + 事件触发即时更新（如 WA/比利时执法动态、UKGC
加密支付评审结论）。

**Free 模式（TE-v1 §3.8）对矩阵的修正**：上表 GAME 币列按"付费购买"
口径评估；Free 模式（币免费、每手固定 gas 服务费、无真实奖品）画像
更干净——美国联邦层面确定性更高（无有价值奖品即非赌博；纯娱乐社交
赌场在纽约等严格州仍合法的口径同理）；**WA 仍封禁**（RCW 9.46.240
将传输赌博信息定为重罪，连订阅制 ClubWPT 都排除华盛顿）；比利时/
中国大陆维持封禁；英国/澳大利亚豁免逻辑不变（无 money's worth
奖品）。注意 2025 年多州打击的是**可赎回双币 sweepstakes** 模式
（MT/CT/CA/NV/NJ/NY），与 Free 模式（无真实奖品）不同，但证明
"付费 + Chance 游戏"品类立法活跃，季度扫描必须覆盖该品类。

---

## 2. GAME 币的法律定性防御矩阵

GAME 币要同时躲开四个盒子：赌博法、证券法、支付法（e-money/预付）、
加密资产法（MiCA/VASP）。TE-v1 的每条设计都对应至少一个辖区的
定性测试：

| TE-v1 设计 | 定性测试 | 结论 | 依据 |
|---|---|---|---|
| 不可赎回（无 WithdrawRequest 路径） | 赌博法"prize of money or money's worth"（UK GA 2005）；IGA（澳）"prize of monetary value" | 无可变现奖品 → 非赌博 | UKGC 虚拟货币指南；澳大利亚社交博彩豁免判例口径 |
| 不可兑换/不可桥（封闭操作集 + AIR 不可证明） | MiCA "crypto-asset"（DLT 上可转移的价值数字化表示） | **闭环论**：仅在发行方生态内消费、不可与法币/加密互兑、无二级市场 → 论证落在 MiCA 范围外的"有限网络"口径（镜像 EMD 豁免逻辑）；口径未由 ESMA 最终明确，按中等不确定性处理 | ESMA MiCA 中心；Drew Napier 区块链游戏框架分析 |
| 同上 | 证券法 Howey 测试（美）/ MiCA 白皮书义务 | 无升值预期（比率冻结、无转售市场、消费用途）→ 非投资合同 | 行业通行分析 |
| 同上 | FinCEN 可转换虚拟货币（CVC）/ 货币传输 | 闭环预付工具，非 CVC，出售自家游戏币不构成货币传输 | FinCEN 2019 CVC 指南口径 |
| 同上 | EMD2 电子货币（EU） | 不可赎回 + 仅限发行方游戏内使用 → 不满足"可按面值赎回"要件，且符合有限网络方向 | 电子货币指令要件分析 |
| 发行价带 + 比率冻结 | 消费者保护（EU CPC 网络对游戏内货币的原则、Directive 2019/770） | 定价透明（购买页明示单价与不可退换）+ 禁止误导 | CPC 2025 虚拟货币原则 |
| PLAY 免费层永久保留（TE-v1 §3.6） | WA *Kater* 判例的"付费才能继续玩 = 筹码有价值"逻辑 | 免费筹码充足供给削弱"extend play"价值论——保留 PLAY 是对美式集体诉讼的关键缓解 | *Kater v. Churchill Downs* 争议焦点 |

**敌意辖区单独说明**（不可设计消解，只能封禁）：

- **华盛顿州**：判例明确"虚拟筹码延长游戏特权"即构成 "thing of
  value"，付费社交博彩 = 非法赌博；2025 年州检察长对 16 款社交
  赌场 App 提起关停诉讼。动作：GAME 购买与广告对 WA IP 全面封锁，
  服务条款明确排除。
- **比利时**：博彩委员会将社交赌场类游戏与 loot box 一并认定为
  无牌即刑事违法。动作：封禁。
- **中国大陆**：单向虚拟货币模型本身与《关于加强网络游戏虚拟货币
  管理工作的通知》（文化部、商务部）一致（虚拟货币仅限兑换发行方
  自家游戏服务、不得兑付法币、禁止用于博彩），但**德扑品类在
  "游戏币兑换筹码下注"模式下被认定变相赌博**（腾讯《天天德州》
  2018 年退市即为标志事件），叠加虚拟货币交易禁令 → 全产品封禁。

**附带义务**（不封禁辖区的轻合规）：

- **日本**：GAME 币 = 自家事业型预付支付手段，未使用余额基准日
  超过 ¥1,000 万须向当地财务局申报（备案制，成本低）。
- **EU 消费者法**：游戏币 = 数字内容（Directive 2019/770）；14 天
  撤回权可在"明示同意 + 立即履行"下由用户放弃——**购买流程必须
  实现该弃权勾选**；价格展示用本地货币；未使用余额的退换政策按
  CPC 原则书面上墙。
- **年龄门**：GAME 侧 18+（美区 21+ 依州法），REAL 侧按牌照市场
  18/21+。

### 2.1 Free 模式（免购买 + gas 服务费）的定性防御

Free 模式 = 币免费（faucet 限量但不稀缺）+ 每手固定 gas 服务费 +
奖品只有免费币。对照赌博三要件：

| 要件 | Free 模式 | 分析 |
|---|---|---|
| consideration（对价） | 存在（gas 服务费） | **固定费额、与胜负/底池无关**（TE-v1 §3.8.2 刻意不按底池比例）→ 服务对价，非 wager |
| chance（机会） | 存在 | — |
| prize（奖品） | **缺失** | 币由 faucet 免费持续供给、无任何兑付出口 → 赢币无边际价值。对照 *Kater* 的"延长游戏"理论：付费才能续玩才有价值，免费可续玩则无 |

- **先例**：ClubWPT 订阅制（月费换会员资格 + 每日发放不可兑现锦标
  赛点数 + sweepstakes 真实奖品）在 49 个州合法运营，仅排除华盛顿
  （RCW 9.46.240，WSGC sweepstakes FAQ）。Free 模式不发任何真实
  奖品，结构上比它更保守。
- **gas credit 定性**：预付服务额度（prepaid service credits）——
  单一用途（只可被对局消耗）、不可赎回 → 沿用 §2 GAME 币防御矩阵：
  非证券（无升值预期）、非 e-money（不可赎回）、闭环；日本按自家
  事业型预付支付手段申报口径处理；EU 购买流程实现 14 天撤回弃权。
- **faucet 纪律是合规要件**（TE-v1 §3.8.1）：faucet 供给收紧到
  "付费才能持续玩"的程度，Free 模式即退化为 Paid 模式的监管画像
  （WA 判例正是如此认定）——faucet 参数变更视为合规敏感变更，进
  法务复核清单。
- **营销纪律**：gas 费必须以"服务费/对局费"呈现，禁止"buy-in /
  底池 / 奖金"话术；奖品表述禁止暗示币有任何价值。

---

## 3. REAL 桌牌照策略（三阶段）

### Phase 1（离岸基地 + 允许名单市场）

- 基地候选：**马恩岛 OGRA**（首选：5 年期、加密友好历史最长、
  一张牌照覆盖扑克/赌场/电竞）或**库拉索 LOK**（次选：CGA 直接
  发牌，但 2026-06 加密新规带来 mixer/钱包筛查/EDD 等合规工程，
  2027-06 全面达标时限）。
- 允许名单 = 基地牌照可覆盖 + 当地法不禁止离岸服务 + 不在牌照
  23 国禁入名单的市场；明确排除：中国大陆、美国（直接 2C）、
  澳大利亚、德国（加密禁令）、英国（无 UKGC 牌不得提供）、
  荷兰/比利时。
- 牌照自带义务进运营基线：AML/CFT 政策、指定合规官、年度审计、
  RNG/游戏公平认证（本链可证明结算是认证亮点）、RG 工具、
  博彩税申报。

### Phase 2（欧洲 point-of-consumption）

- 欧盟博彩无通行证：每个成员国按消费地原则单独发牌。以马耳他
  MGA 为合规基地（B2C + 后续 B2B），逐国申请（优先顺序按商业
  评估：常见为荷兰、意大利、西班牙、丹麦等）。
- **德国特例**：GGL 持牌商不得经手加密货币（仅欧元，且有限额与
  LUGAS）→ 德国市场若进入，只能是"法币出入金 + 链上 REAL-USDT
  记账内部化"不可行——**德国走纯法币镜像产品或放弃**，技术侧
  无需为此改造（德国用户 geo 到法币通道即可，REAL 域 code 白名单
  按市场配置，§5 GEO 表已预留）。
- **英国观察窗**：UKGC 2026-02 起评审持牌商加密支付路径——若
  落地为"受监管稳定币 + 持牌商许可"，英国成为 REAL 域旗舰市场
  （UKGC 牌照 + 加密入金）；评审结论前不进英国 REAL。

### Phase 3（美国 B2B）

- 直接 2C 不做。路径：与 MSIGA 成员州（NV/DE/NJ/PA/MI，WV 待启动）
  持牌运营商 B2B 合作——本链作为可证明结算基础设施供给持牌方，
  玩家入金走持牌方法币通道，链上资产由持牌方作为对手方映射。
- 稳定币侧预留：GENIUS 法案生效（不晚于 2027-01-18）后美国市场
  仅允许 permitted payment stablecoin（USDC 方向合规；USDT 属外国
  发行人、待财政部可比性认定）。**美国市场的 anchor 白名单 =
  USDC-only 起步**。

---

## 4. 稳定币与储备托管合规

1. **发行与持有分离**：我们只持有和使用 USDT/USDC，不发行 →
   不触发 GENIUS/MiCA EMT 发行人义务。但以下行为会触发**服务方**
   义务，需按市场处理：
   - 为玩家托管稳定币（vault 储备）→ EU 视角属 CASP"保管钱包"
     服务：EU 市场需自有 CASP 牌照或持牌托管伙伴；离岸牌照市场
     （马恩岛/库拉索）由牌照 AML 框架覆盖。
   - 玩家以 USDT 换 GAME 币 → 形似"加密换加密"兑换服务。缓解：
     **GAME 币购买通道按市场分列**——EU 走法币 PSP（卡/SEPA），
     anchor 记账仍可为 USDT/USDC（内部记账），链上不出现
     "币币兑换"语义（TE-v1 的单向发行 op 本来就不是 exchange，
     叙事与实现一致）；离岸牌照市场可直接收稳定币。
2. **GENIUS 法案时间线**（美区）：签署 2025-07-18；生效为
   2027-01-18 与最终规则发布后 120 天的较早者；生效后 DASP 不得
   向美国用户提供非合规外国稳定币 → 美区 anchor 白名单从 USDT
   中移除、仅留 USDC（或后续取得认定的发行人）。
3. **钱包与通道卫生**（对齐库拉索 2026 新规与牌照惯例，写入
   vault watcher 准入）：
   - 入金地址筛查（Chainalysis/TRM 类）：受制裁地址、mixer 来源
     → 拒绝 + 冻结流程；
   - 匿名/自托管钱包大额入金 → EDD（来源说明）；
   - Travel Rule：对触发市场的转账按 FATF R.16 配套（通常由持牌
    出入金伙伴承担传输方义务，平台侧提供数据）。
4. **储备隔离**：每币种独立对账（TE-v1 INV-TE-2）之上，储备账户
   与运营资金分离、目标破产隔离——对齐 UKGC 玩家资金分级与 MGA
   玩家资金规则的口径（即使尚不适用，按该标准建设可在牌照申请时
   直接呈报）。

---

## 5. AML/KYC 与地理围栏的协议落点

合规控制不留在运营手册里，全部映射到准入控制（与 TE-v1 的 fail-closed
纪律同构）：

| 控制项 | 协议落点 | 强制层 |
|---|---|---|
| KYC 门 | REAL `Deposit` 与 GAME `IssueGameToken` 的准入校验（operator 侧 KYC 状态 + 等级，无状态拒收） | 准入（validation），计 metric |
| GEO 允许名单 | 版本化 `geo_policy`：市场 → {REAL 开关, GAME 开关, anchor 白名单, 法币-only 标志}；入金/发行/开桌前校验 | 准入 + 配置版本号进软确认帧（审计） |
| 年龄门 | KYC 元数据（18+/21+），与 GEO 表联动 | 准入 |
| 钱包筛查 | watcher 入金前置：制裁/混合器命中 → 不确认（不产生 deposit_id） | 托管侧 fail-closed |
| EDD/SOF | 高额入金/异常流水的运营流程，挂 KYC 等级 | 运营 + 审计日志 |
| STR/SAR | 牌照辖区按当地时限上报 | 运营 |
| RG（限额/自排除/冷却） | REAL 侧牌照强制：自排除名单进 `geo_policy` 个体黑名单；限额在运营层执行 | 准入 + 运营 |
| gas credit 准入 | Free 桌每手结算前校验额度，不足拒绝 | 计量账非负恒等（INV-TE-8）导出审计 |

新增工程项（进 TE-M2/TE-M3 范围，作为合规增补）：

- **TE-M2+**：`Deposit` 准入链加 KYC/GEO 校验位与 `geo_policy`
  版本引用；
- **TE-M3+**：`IssueGameToken` 同上；GAME 购买页实现 EU 14 天撤回
  弃权勾选（前端 + 购买凭证存档）；
- 指标：`kyc_gate_rejected_total`、`geo_policy_rejected_total{market}`。

---

## 6. 负责任博彩与消费者保护基线

- **REAL 侧**（牌照市场强制）：充值限额、亏损限额、时段提醒、
  自排除（且进共享排除名单如 GAMSTOP 类）、明确概率与费率披露
  （rake 展示已有链上可审计数据优势）。
- **GAME 侧**：18+ 年龄门、购买限额（默认月上限 + 自助下调）、
  不向自我判定博彩风险用户推送促销（EU UCPD 口径）、PLAY 免费层
  永久保留（§2 防御矩阵中 WA 判例缓解）。
- **营销红线**（沿 plan §6.9 禁用词纪律 + 辖区广告法）：禁入市场
  零投放；GAME 不得使用"投资/升值/回收"话术；REAL 必须带牌照
  编号与 RG 信息；影响者营销按 UK ASA/CPC 规则披露。

## 7. 税务与数据保护（要点）

- 博彩税：按牌照辖区申报（马恩岛 GGR 分档、马耳他按游戏类型、
  库拉索净收益税等）；GAME 币销售在 EU 属数字服务增值税范畴
  （B2C 按消费者所在国税率）——EU 市场进入前完成 VAT 注册。
- 玩家侧：英国等辖区赌博赢利不征个税；美国市场由持牌 B2B 伙伴
  承担 W-2G 类申报；平台为持牌方提供结算数据导出（archive_index
  已具备按窗导出能力）。
- GDPR：EU 用户数据 DPA 体系、数据最小化（KYC 数据与链上身份
  分离存储）；不进中国 → 无 PIPL 义务面。

## 8. 风险登记册（不可设计消解项）

| 风险 | 等级 | 缓解 |
|---|---|---|
| MiCA 对闭环游戏币口径未最终明确（ESMA 无 gaming token 专项指南） | 中 | 保持无二级市场/无互兑/无桥三不原则；EU 只走法币购买通道；预留 CASP 伙伴方案 |
| 美式集体诉讼潮流（社交博彩损害理论） | 中 | WA 等敌意州封禁；PLAY 免费层；购买限额；仲裁条款与明确警示 |
| 比利时刑事口径扩散（荷/西等跟进社交博彩定性） | 中 | 季度法务扫描；封禁列表可 48h 内生效（geo_policy 热更新路径） |
| UKGC 加密支付评审结论不确定 | 低 | 英国 REAL 推迟到结论落地；技术无需变更 |
| GENIUS/稳定币规则演进（外国发行人认定） | 中 | anchor 白名单按市场配置已预留；USDC-only 美区起步 |
| 中国周边市场误伤（华语流量含大陆用户穿透） | 高 | 严厉 IP/支付/KYC 三重围栏，华语广告投放排除大陆定向 |
| Free 模式费制定性被挑战（运营侧引入底池比例费或稀缺化 faucet） | 中 | 固定费额与 faucet 充足供给是协议冻结参数；任何 loosening 走法务复核（§2.1） |

## 9. 分阶段合规路线图

| 阶段 | 动作 | 出口判据 |
|---|---|---|
| C-M1 | 聘任牌照辖区律师（马恩岛/马耳他 + 目标市场清单）；确定 Phase 1 基地并递交申请；geo_policy v1（封禁：中国大陆、美 direct、澳、德 REAL、UK REAL、比、WA 州） | 牌照受理函 + geo_policy 上线 |
| C-M2 | AML/KYC 供应商接入（含钱包筛查）；GEO/KYC 准入控制进 op 校验；GAME 购买弃权流程；日本 PPI 申报评估 | 准入控制负例测试全绿 |
| C-M3 | REAL 域小流量开跑（允许名单市场）：RG 工具、审计、牌照报告管道 | 牌照首年合规审计通过 |
| C-M4 | Phase 2 欧盟逐国牌照 / Phase 3 美国 B2B 谈判（按商业优先级择一先走） | 首个欧盟国家牌照或美国持牌 B2B 签约 |

## 10. 对 TE-v1 的修订增补

1. TE-M2 增补：`geo_policy` 准入参数 + KYC 校验位 + anchor 白名单
   按市场分列（法币-only 市场的通道标记）。
2. TE-M3 增补：GAME 购买页 EU 撤回弃权流程；GAME 月购买限额默认值；
   `IssueGameToken` 准入链。
3. TE-v1 §7 风险表新增：MiCA 闭环口径、WA/比利时封禁清单引用本文。
4. 决策点新增 **TE-D5**：EU 市场 GAME 币购买通道走法币 PSP（推荐，
   规避币币兑换叙事）还是稳定币直购 + CASP 伙伴。
5. 新增 TE-M6（Free 模式）的合规增补：gas 购买页"服务费"话术与
   EU 撤回弃权流程；faucet 参数进法务复核清单；`BuyGasCredits`
   准入链挂 KYC/GEO（与 `IssueGameToken` 同口径）。

---

## 附：主要来源

- 华盛顿州：[WSGC 虚拟赌场立场](https://wsgc.wa.gov/regarding-virtual-casinos)、[Justia: Kater v. Churchill Downs (9th Cir. 2018)](https://law.justia.com/cases/federal/appellate-courts/ca9/16-35010/16-35010-2018-03-28.html)、[KOMO: 2025 州检察长执法](https://komonews.com/news/local/state-ag-seeks-to-end-social-casino-apps-despite-previous-gambling-guidance-washington-state-gambling-commission-playtika-bingo-blitz-big-fish-casino-currency)
- 英国：[UKGC 数字与虚拟货币指南](https://www.gamblingcommission.gov.uk/authorities/codes-of-practice/guide/page/digital-and-virtual-currencies)、[CoinDesk: UKGC 探索加密支付（2026-02）](https://www.coindesk.com/policy/2026/02/27/uk-s-gambling-watchdog-explores-allowing-gamblers-to-pay-bets-with-crypto)
- 澳大利亚：[ICLG 澳洲博彩法 2026](https://iclg.com/practice-areas/gambling-laws-and-regulations/australia/)、[Guardian: 社交赌场豁免](https://www.theguardian.com/australia-news/2022/nov/17/social-casino-apps-the-games-exempt-from-australias-gambling-laws-because-no-one-can-win)
- 欧盟：[ESMA MiCA 中心](https://www.esma.europa.eu/esmas-activities/digital-finance-and-innovation/markets-crypto-assets-regulation-mica)、[Drew Napier: 区块链游戏监管框架（闭环豁免）](https://www.drewnapier.com/DrewNapier/media/DrewNapier/The-Regulatory-Frameworks-for-Blockchain-Gaming.pdf)、[EGDF 游戏内货币](https://www.egdf.eu/documentation/7-balanced-protection-of-vulnerable-players/consumer-protection/in-game-currencies-2023/)、[ZwillGen: CPC 虚拟货币原则](https://www.zwillgen.com/gaming/cpcn-announces-virtual-currency-consumer-protection-guidelines/)、[BEUC 报告](https://www.beuc.eu/sites/default/files/publications/BEUC-X-2024-061_Monetising_play_Regulating_in_game_and_in_app_premium_currencies.pdf)
- 比利时/荷兰：[LY Xiao (2025): 比利时社交博彩与 loot box 违法性研究](https://www.researchgate.net/publication/389336055_Widespread_Illegal_Advertising_of_Loot_Boxes_and_Social_Casino_Games_in_Belgium_Empowered_by_the_EU_Digital_Services_Act_to_Assess_Compliance_Using_Meta_s_Ad_Repository)、[ICLG 荷兰 2026](https://iclg.com/practice-areas/gambling-laws-and-regulations/netherlands/)
- 德国：[GamblingMaps: GGL 持牌与加密禁令](https://gamblingmaps.org/map/regulations/germany)
- 美国：[GENIUS 法案全文（S.1582）](https://www.congress.gov/bill/119th-congress/senate-bill/1582/text)、[财政部拟议规则公告](https://home.treasury.gov/news/press-releases/sb0605)、[Yale JREG: 外国发行人待遇](https://www.yalejreg.com/nc/how-the-genius-act-regulates-foreign-issuersand-how-it-compares-to-europe-and-the-uk-by-benedikt-bartylla/)、[LegalUSPokerSites: MSIGA 2026](https://www.legaluspokersites.com/blogs/msiga-online-poker-states-2026/)
- 离岸牌照：[iGB: 库拉索加密规则（2026-06 生效）](https://igamingbusiness.com/legal-compliance/cga-curacao-crypto-gambling-regulations-mid-2027-deadline/)、[ICLG 马恩岛 2026](https://iclg.com/practice-areas/gambling-laws-and-regulations/isle-of-man/)、[Global Law Experts: 库拉索 2026](https://globallawexperts.com/obtaining-a-curacao-gambling-license-in-2026-license-types-costs-and-requirements/)
- 中国：[文化部、商务部虚拟货币通知原文](https://zwgk.mct.gov.cn/zfxxgkml/zcfg/gfxwj/202012/t20201204_906151.html)、[文化部 2016 事中事后监管通知](https://www.cac.gov.cn/2016-12/06/c_1120060575.htm)、[界面：天天德州退市](https://www.jiemian.com/article/2465929.html)
- 日本：[资金决济法英译本](https://www.japaneselawtranslation.go.jp/en/laws/view/3078/en)、[KS Lawyers: 预付型支付手段申报](https://kslawyers.jp/insights_news/column/post-1288)
- 美国（Free 模式先例）：[ClubWPT 奖品资格与 sweepstakes 规则](https://www.clubwpt.com/prize-eligibility/)、[WSGC sweepstakes FAQ（RCW 9.46.240）](https://wsgc.wa.gov/sweepstakes-faq)
