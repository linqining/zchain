# PRD：ZChain Wallet · 方向 B「账簿 / Ledger」钱包界面

**版本**：v1.0（固化设计稿 v0.2） · **日期**：2026-09-19 · **状态**：草稿待评审 · **作者**：[待填写]
**产品类型**：B2C（自托管加密钱包 + dapp 签名端）；因涉及托管资产与未审计事实，额外覆盖 B2B 级的安全边界、能力矩阵与发布门禁
**设计稿**：`design/zchain-wallet-ui-b-ledger.html`（19 屏 · 380×600 · Chrome popup · DS-0…DS-13）
**逻辑层实现**：`extension/common/ui_ledger.js`（方向 B 纯函数层，已接线至 `extension/popup/popup.js:44`）

---

## 0. 阅读指引与文档口径

本文不是从零发起的新需求，而是**对已存在的设计稿（v0.2）与其已落地的纯逻辑层做需求固化**：把散落在稿的 HTML 注释、DS-0…DS-13 说明，以及 `ui_ledger.js` / `transfer_preview.js` / `withdraw_preview.js` / `receipts.js` / `service_worker.js` 源码注释中的隐含约束，收敛成可评审、可测试、可交接的一份 PRD。

每条需求标注来源，后文不重复解释：

| 标记 | 含义 |
|---|---|
| `[稿]` | 直接来自设计稿的可见内容或注释 |
| `[码]` | 来自已提交代码的可验证事实，附 `文件:行号` |
| `[档]` | 来自 `docs/` 规格文档 |
| `[审]` | 本文按 `[码]` 口径复算稿面数字后新发现的问题或结论 |
| `[判]` | 作者基于以上者作出的产品判断，需评审确认 |

**贯穿全文的判定标准**：这套钱包的资产数字有一部分**不是可自由动用的钱**，且其中一部分**当前没有任何数据源**。所有功能描述服从同一条纪律——`[稿 DS-13]`「不许为了好看删掉的文案」：界面无法从上游诚实取得的数据，必须显示 `—` + 未接入说明，禁止前端推算、补齐或美化。

**一句话结论**：设计稿在**交互结构与限制说明**上高度忠实于实现（42 项关键数字中 25 项可精确回溯到代码常量或 RPC 字段），但在**法币折算、二维码、金额精度、时间文案、会话 scope 枚举**五处与 0.6.1 的交付现实冲突，其中 5 项属发布门禁级（R-01 / R-15 / R-17 / R-19 / R-32）。完整清单见 §13。

---

## 1. 背景与目标

### 1.1 背景

**问题现状。** 钱包 0.6.1 已支持三层账户（ZChain 隐私层 note 库 / EVM / Starknet），并具备竞品没有的真实能力：一手牌的 STARK 结算证明可在浏览器内用 `stwo` wasm 完整复验，实测 p50 ≈ 1.70–1.80s `[码 docs/stwo-wasm-path-a.md:5]`。但界面上这个能力被摊平在二级页——finality 状态只有提现页一个 dot 行、回执列表一枚 chip `[稿 DS-0]`。用户看得见余额，看不见"这笔余额现在能用到什么程度"。

**同时存在的结构成本。** 方向 A（毡布绿 v0.1，`design/zchain-wallet-ui.html`）用底部 4 tab（首页 + 三条链），于是"首页"和三链页在讲同一件事，且 zc/evm/stk 是三套独立模板，直接造成 `popup.js` 里 EVM 与 Starknet 的复制粘贴 `[稿 DS-0]`。

**不做会怎样。** 三个后果：其一，唯一不可复制的差异化资产（结算可证）在界面上不可见，与竞品的"牌桌"叙事无法区分；其二，三套链模板持续分叉，每次改动付三份成本；其三——最严重——REAL 域是托管映射、提现通道未开放、PLAY 是无价值测试筹码，这些限制若缩成一行灰字，用户会按"可自由动用的钱"理解资产，产生真实的资金误判与合规风险。

**做了能怎样。** 方向 B 把叙事从"上桌"换成"对账"：纸白底、细线账格、方形印章、等宽数字右对齐 `[稿 DS-0]`；finality 阶梯提升为一等公民组件（凭证条 `.rail`），出现在一切资产变动位置；导航收成 3 tab（总账/账簿/证明），链降级为筛选器，一个模板 × 三个数据面 `[稿 DS-0]`。后者已在代码落地为 `SCREENS` 注册表的 `shared: true` `[码 ui_ledger.js:39-58]`。

**为什么是现在。** 纯逻辑层已落地并被测试覆盖（`common/ui_ledger.js` + `tests/ui_ledger.test.js` 19 例），`popup.js` 已 import 该模块，`gasPriceGwei`、`info.nonce` 等字段已在真界面渲染 `[码 popup.js:1411]`。此时固化 PRD 成本最低：视觉与交互尚有决策空间，数据口径已经钉住，不必回改上游。

### 1.2 目标用户

| 用户角色 | 特征描述 | 核心诉求 | 使用场景 |
|---|---|---|---|
| 德扑桌玩家（主） | 已装扩展，在 devnet/testnet 上桌，持 PLAY 筹码 + 少量 REAL 映射资产；懂钱包不懂密码学 | 上桌时零摩擦签名、不反复输口令；下桌后想知道"我赢的这钱是不是真的" | 一局结束 → 看结算 → 想提现 → 被通道未开放拦住 |
| 多链资产管理型 | 三层并用，EVM 侧持原生币与 ERC-20；关心 gas 与 nonce | 一眼看清三层各有多少、哪层被锁、哪笔还挂着 | 每天开 popup 数次，每次停留 < 60s |
| dapp 开发者 / 验证者 | 自建桌台或合约，经 SNIP-12 会话密钥请求签名；需向用户自证没出老千 | 让签名请求的每个字段都能对上一条已归档证明 | 用 Proof Portal 输入 hand binding 复验一手牌 |
| 审计 / 合规视角（次，不可忽略） | 不直接用钱包，读界面截图与文案 | 界面是否如实标注托管性质、未审计事实、未实现能力 | 抽查"是否存在暗示安全保证的徽章 / 话术" |
| 低视力 / 强光环境用户 | 户外或明亮桌面，对浅底高对比有刚需 | 纸白账簿底正是为此而生 `[稿 DS-0]` | 白天桌面 · 需一键切夜场底 |

> 角色 1/2 来自稿已确立的目标人群 `[稿]`；角色 3 来自 SNIP-12 与 Portal 两个已实现能力 `[码]`；角色 4/5 为本文补充 `[判]`，因方向 B 的核心卖点（可证 / 双底色）直接服务这两类人。

### 1.3 业务目标与成功指标

设计稿与仓库中**没有任何 DAU / 转化 / 留存基线**。按红线「不编造数据」只给框架与可取数口径，缺数字处标 `[待补充]`。

| 目标 | 衡量指标 | 目标值 | 监测方式 |
|---|---|---|---|
| 让「结算可证」可被感知 | 单次会话访问「证明」tab 或 Portal 的用户占比 | 上线 4 周后 ≥ `[待补充]`% | `screen_view(proofs)` / `portal_verify_start` |
| 复验真被做完（不只看入口） | 发起验证 → 验证成功完成率 | ≥ `[待补充]`% | `portal_verify_result` + `portal_verify_step` 分步错误码 |
| 消除口令疲劳 | GAME 域签名经会话密钥完成、未触发口令输入的占比 | ≥ `[待补充]`% | `sign_request_resolved.via` |
| 不产生资产误解 | 用户在 REAL 资产上尝试提现提交的行为次数 | **恒为 0**（入口 fail-closed） | `withdraw_submit_attempt_blocked`（>0 即说明禁用态表达失败） |
| 消除界面事故 | 横向溢出 / 中文折断 / 对比度不达标项 | 各 0 | 自检脚本（需随仓库提交，见 R-21） |
| 减少重复实现 | EVM/Starknet 独立仪表盘分支数 | 2 组 → 1 组 `shared` | 代码结构核对 |
| 首屏可信时长 | popup 打开 → 三层余额渲染 p95 | ≤ `[待补充]`ms（现状未压测） | Performance API |
| 证明获取时延 | Portal 步骤 1–2（取明细 + 下载证明）p95 | ≤ `[待补充]`ms；网关侧限流 10 req/s、burst 20 `[码]` | `portal_verify_step` 分步 ms |

### 1.4 范围界定

**覆盖**：19 屏 + 3 张收款 sheet + 2 个模态 + toast 的完整功能/数据/交互规格；凭证条与回执投递两套状态机的规则；贪心选币 / 转账预览 / 提现预览 / SNIP-12 会话密钥 / Proof Portal 的业务规则；**过渡动画规范（§7，稿此处空白，本文补齐）**；**每个可见数字的数据来源与可信度分级（§6.2）**。

**不覆盖**：视觉细节（色值/字号/圆角，DS-1…DS-5 已钉，只引用不重述）；密码学算法选型与 keystore 格式（作为**已继承的产品约束**引用，不重新决策）；服务端/网关/合约实现方案；移动端界面（`wallet-app/mobile/` 为静态演示，仅口径冲突处提及）；法币行情源接入方案（只登记"价格源未接入"这一事实及其界面后果）。

---

## 2. 需求概述

把三层账户收敛成一本可审计的账簿：链作筛选器、finality 作一等组件、限制说明作视觉锚点。

---

## 3. 信息架构与导航模型

### 3.1 导航骨架 `[稿 DS-9]` `[码 ui_ledger.js:39-58]`

**底部 3 tab**：`总账(home)` / `账簿(acct)` / `证明(proofs)`。设置不在 tab 上，移到票据抬头右上角齿轮。

**链 = 筛选器，不是目的地。** 账簿顶部三值切换器 `ZChain | EVM | Starknet`，带计数徽标。切换只换数据面不换结构，由 `CHAIN` 映射表驱动 kind/net/addr 三处文案 `[稿:1721-1725]`；代码侧 `CHAINS=['zc','evm','stk']`，`chainOf()` 对未知值回落 `null`（不猜）`[码:63-67]`。

**三条主线互不串线** `[稿:818-824]`：

```
总账 ─→ 账簿(链切换) ─→ 转账 / 提现 / 收款
                         └→ 会话密钥 ─→ 撤销(模态)
证明 ─→ 回执列表 ─→ 凭证详情 ─→ Portal 复验
抬头齿轮 ─→ 设置 ─→ 备份 / 恢复 / 危险区
```

### 3.2 屏幕注册表：19 屏（稿）↔ 18 条（码）

稿声明「19 屏可点击 · 18 对照 + 1 新增」`[稿:490,961]`；`extension/README.md:148` 声明「18 屏注册表」`[码]`。两者口径不同但都成立，**必须由本文统一**，否则 e2e 与埋点的屏幕 id 会分叉 `[判]`：

| # | 稿 id | 稿分组 | 代码 id | 代码 tab | shared | parent | 说明 |
|---|---|---|---|---|---|---|---|
| 01 | welcome | 引导 | welcome | – | – | – | |
| 02 | success | 引导 | success | – | – | home | |
| 03 | import | 引导 | import | – | – | welcome | |
| 04 | lock | 引导 | lock | – | – | home | |
| 05 | home | 账户 | home | home | – | – | 总账 tab |
| 06 | zc-dash | 账簿 | **`acct`**(zc) | acct | ✔ | – | **稿平铺 3 屏，码收敛 1 条** |
| 07 | evm-dash | 账簿 | **`acct`**(evm) | acct | ✔ | – | |
| 08 | stk-dash | 账簿 | **`acct`**(stk) | acct | ✔ | – | |
| 09 | zc-send | ZChain | zc-send | acct | – | `@acct` | |
| 10 | zc-withdraw | ZChain | zc-withdraw | acct | – | `@acct` | |
| 11 | zc-confirm | ZChain | zc-confirm | **home** | – | `@acct` | 唯一 tab 归总账的子页 |
| 12 | zc-sessions | ZChain | zc-sessions | acct | – | `@acct` | |
| 13 | zc-portal | ZChain | zc-portal | **proofs** | – | `@acct` | 稿从账簿 ZChain acts 进入 |
| 14 | zc-receipts | ZChain | zc-receipts | acct | – | `@acct` | |
| 15 | evm-send | EVM | **`send`**(evm) | acct | ✔ | `@acct` | 稿 grp「EVM」→ 码 grp「链层」；稿为专属屏，码为通用 |
| 16 | evm-history | EVM | **`history`**(evm) | acct | ✔ | `@acct` | 同上 |
| 17 | evm-manage | EVM | **`manage`**(evm) | acct | ✔ | `@acct` | 同上 |
| 18 | proofs | 证明 | proofs | proofs | – | – | 稿 v0.2 新增 |
| 19 | settings | 系统 | settings | – | – | home | |
| – | （稿仅 toast 示意） | – | **`contract`**(链层) | acct | ✔ | `@acct` | **代码有第 18 条，稿未画屏** |

**需评审裁决的四处 `[审]`：**

1. 稿把 send/history/manage 画成 EVM 专属三屏，代码做成 `shared`（三链通用）。**采代码口径** `[判]`——这是"链=筛选器"的必然结论，稿只是用 EVM 数据演示一遍。
2. 代码存在 `contract`（合约读写）屏，稿只在 EVM pane 的 `acts` 放了 `data-toast="示意:合约读写面板"` `[稿:1177]`。需求成立但缺设计 → R-02。
3. id 稳定性：e2e 与埋点按 id 寻址 `[码 ui_ledger.js:32]`。**统一用代码侧 id**（`acct`/`send`/`history`/`manage` + `chain` 参数），稿侧 `zc-dash`/`evm-send` 等作别名保留一个版本周期。
4. ⚠ **13 屏内容高度超过 600px**：`design/pixso/README.md` 记录 B 方向导出时需为 13 屏生成 `__full.html`（整屏不滚动变体）`[码 build-pixso-shot-export.mjs]`。即**超过一半的屏幕在 380×600 的 popup 基准内是滚动态**。`[判]` 本文保留 380×600 为基准，但要求首屏（不滚动）必须包含：抬头 + 该屏主行动按钮 + 该屏警示条；滚动区只承载次要明细 → **R-40（布局验收门禁）**。

### 3.3 返回与链上下文保持 `[码 ui_ledger.js:85-107]`

- 子页"返回"目标由注册表 `parent` 决定；`parent:'@acct'` 解析为 `{id:'acct', chain:当前链}`——**从提现页返回时回到你离开时那条链**，不重置为 ZChain。稿侧用 `lastAcct` 变量实现同一语义 `[稿:1727]`。
- 未知屏幕 id → 返回 `{error:'UnknownScreen'}`，**不静默回落首页** `[码:96]`。写进验收：跳错屏必须显式报错。
- `tabOf(id)` 决定子页高亮哪个 tab；`zc-confirm` 归总账（签名请求来自 dapp 上下文，语义是"当前状态"而非"账簿操作"）。

### 3.4 抬头体系 `[稿 DS-9]`

一级屏（home/acct/proofs）用**票据抬头**：两行 + 齿孔线。第一行 = "这是什么单据"（`General Ledger` / `Ledger · Zchain` / `Proofs` + 网络标识 + 齿轮）；第二行 = "谁的账户"（头像 + 账户名 + 地址行 + 复制/锁定）。

子页用**子页栏**：方形返回 + 居中标题 + 右侧域标签（REAL / GAME / Ethereum / SNIP-12 / 倒计时）。`[判]` 域标签在标题栏是有意的：用户从任意入口进入操作流，抬眼就能确认在动哪一域的资产。

---

## 4. 功能详细设计

优先级：**P0** 本版本必须；**P1** 强烈建议同期；**P2** 可延后，但界面须按 fail-closed 显示禁用或 `—`。

### 4.1 引导流

#### F-01 欢迎页 · 一次创建三层（`welcome`）— P0

**功能描述**：首次打开扩展的落地页，讲清"三层账户一次创建"，并提供导入/恢复分流。
**用户故事**：作为新装扩展的用户，我希望一次点击拿到能上桌的完整账户，而不必给三条链各建一次钱包。

**业务规则**

1. 任一层已存在钱包即视为已 onboarded：欢迎页与创建流程不再触发，直接进三链总览 `[码 extension/README.md:144]`。
2. 已存在钱包时再触发一键创建 → `OnboardedAlready`「已存在钱包：请用口令解锁，不会被一键创建覆盖」`[码 ui_ledger.js:328]`。**必须原样展示**，不得静默新建。
3. 「3 账户层 / 2 套 KDF / STARK」为固定能力宣告、非查询结果 `[稿:981-985]`，与 `CAPABILITY_ROWS` 同源（F-19）。
4. 页脚三行元信息（稿版本 / 对齐 Extension 版本 / `Play · DevNet · v1.3`）常驻 `[稿:997]`。
5. ⚠ **`[审]` 术语红线：全界面不得出现 "ZC" / "ZCN" 作为代币名。** 仓库中不存在该资产：`docs/37-7-rpc-interface.md §6.5` 明确 `Account.balance` 是「不可转让 resource credits，**不是 ZCN**」`[档]`，`plan-appchain-v1.md §6.1` 承诺不发原生代币 `[档]`。ZChain 侧资产是 note 账本：REAL 域（NATIVE/USDT/USDC）+ GAME 域（PLAY + GTS，**结构上单向、不可赎回、不可跨链桥** `[档 TE-v1 §3.3/§3.4]`）。稿用 `zc-` 前缀指**层**、不指代币 ✅。另注：`EVM`/`Starknet` 的 ETH 数字来自另外两个独立账户层，**三层之间无任何汇率或兑换通道**。
6. `[审]` GAME 域代币在代码里的标签是 `PLAY(legacy)` `[码 networks.js ASSET_TABLE.gameTokens]`。`[判]` 界面展示 `PLAY` 即可，但导出/备份/日志字段须保留 `legacy` 标记，避免后续新增 GAME 代币时歧义。

**交互流程**：点工具栏图标 → 无 keystore 则渲染本页 → 「一键创建钱包」派生三层 → `success`；「导入或恢复钱包」→ `import`。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 已存在钱包 | 拒绝创建，不覆盖 | `OnboardedAlready`（原文见上） |
| 派生中某一层失败 | **不保留半套账户**，整体回滚欢迎页 | 逐层给出原因，不显示"部分成功" `[判]` |
| 后台 SW 在派生途中被回收 | 视同失败重试；禁止呈现"看起来已创建" | 「创建未完成，请重试」`[判]` |

#### F-02 创建成功 · 口令只显示一次（`success`）— P0

**功能描述**：展示自动生成的解锁口令与三层地址，用门控勾选强制确认已保存后才放行。
**用户故事**：作为刚创建钱包的用户，我希望被明确告知口令不可再取，并有一个"我已保存"的强制关卡，避免随手关掉页面后失去访问权。

**业务规则**

1. 口令**只显示这一次**；钱包不存储口令，丢失仅能通过加密备份恢复 `[稿:1010]`。
2. 口令块可复制（toast「口令已复制到剪贴板」）。⚠ `[审]` `[判]` **建议补警示行**：把口令写入剪贴板会被其他读取剪贴板的扩展拿到。稿当前只有一个可点复制按钮而无风险说明，与 DS-13 的诚实纪律不自洽 → R-08。
3. 「我已将口令保存在安全的地方」未勾选时主按钮 `disabled` `[稿:1018-1019]`。**这是唯一放行条件**，不可用"3 秒后自动启用"替代。
4. 三层地址逐行可复制；ZChain 行用 felt 色（黑桃）图标，EVM/Starknet 用中性图标 `[稿:1014-1016]`。
5. ⚠ `[审]` ZChain 地址值 `zc1qpoker…f7x2` **在实现中不存在**（D-03），本页与 R-19 一并修正。

**异常处理**：未勾选就离开 → 口令不再于任何页面重现，恢复只能走 `import` 的备份路径。

#### F-03 导入 / 恢复（`import`）— P0

**功能描述**：三段式（备份恢复 / 私钥导入 / 自定义口令），三条路径的能力边界逐条如实声明。
**用户故事**：作为换机或重装的用户，我希望用备份文件恢复，并清楚知道这个备份覆盖哪几层。

**业务规则（穷举）**

*Pane A · 备份恢复*

1. 文件 `.zcbk`，由「设置 → 备份导出」生成 `[稿:1033-1034]`。
2. **ZCBK v1 只含 ZChain 层的 REAL/PLAY 双库与 keystore 信封，不含 EVM / Starknet 账户**——那两层须在各自管理页导出私钥 `[稿 DS-13:952]`。此说明以 info 提示条常驻，**不得折叠**。
3. 备份口令 ≥ 8 位，**与钱包解锁口令相互独立** `[稿:1036]`。
4. 解密全程本地完成，备份口令不离开设备 `[稿:1038]`。
5. 篡改或结构非法 → `Tampered`（fail-closed）；版本高于支持范围 → `UnsupportedVersion`（只升不降）`[码:352-353]`。

*Pane B · 私钥导入*

6. 必须先选「目标层」。**支持矩阵为封闭枚举**：Starknet（STARK curve）✔、EVM（secp256k1）✔、**ZChain note 层 ✘ 暂不支持私钥导入** `[稿:1045]`。不支持项必须朱红强调，不得只置灰。
7. ⚠ `[审]` 稿的「目标层」下拉只演示了 `EVM · Ethereum compatible`，且**未说明是否要求该层已存在其他账户**。规则：各层独立导入，某层为空时允许单独导入，结果不影响其他两层 keystore `[判]`（与 F-04「三层会话彼此独立」一致）。
8. ⚠ `[审]` 私钥输入框稿为明文 `class="mono"`，无掩码。`[判]` 需 `type=password` + 可切换可见 + 失焦自动掩码 → R-09。

*Pane C · 自定义口令*

9. 自定义解锁口令 ≥ 10 位、含数字与字母；需二次确认 `[稿:1048]`。
10. 强度条 + 文字（稿示例 `66% / 强度:良好`）。⚠ `[审]` **稿与代码均未定义强度分档算法**。本文补齐（需评审 `[判]`）：<10 位或仅 1 类字符 → `弱`（禁止提交）；≥10 位含 2 类 → `良好`；≥12 位含 3 类 → `强`；进度条分段 33 / 66 / 100。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 备份口令错误 | 拒绝解密，不透露差异 | `BadPassword`「口令错误（fail-closed）」 |
| 备份被改过一个字节 | fail-closed 拒绝整包 | `Tampered`「备份已篡改或结构非法（fail-closed）」 |
| 备份版本更高 | 拒绝，不尝试向前兼容 | `UnsupportedVersion`「备份版本不受支持（只升不降）」 |
| 选 ZChain 层做私钥导入 | 入口不可达 | 「ZChain note 层暂不支持私钥导入」 |
| 两次口令不一致 | 提交禁用 | 字段级错误，不弹 toast `[判]` |
| 非 ZCBK 格式文件 | 拒绝读取 | `BackupRejected`「备份被拒绝」 |

#### F-04 锁定 · 统一解锁（`lock`）— P0

**功能描述**：一个口令尝试解锁全部层，但各层 keystore 彼此独立、结果互不影响。
**用户故事**：作为三层并用的用户，我不想输三遍口令；但我也想清楚知道这次真的解开了几层。

**业务规则**

1. 触发锁定的两个条件：**无操作 15 分钟**，或**后台页面被浏览器回收（即 fail-closed）** `[稿:1065,1616]`。代码常量 `AUTO_LOCK_MS = 15*60*1000` ✅ `[码 service_worker.js:152]`。
2. 三层独立判定：`isUnlocked()` / `evmUnlocked()` / `stkUnlocked()` 各自比对 `lastActivity` `[码:2705-2712]`。**因此存在 2/3 这类中间态**，稿面「已解锁 2 / 3」是合法状态而非笔误 ✅。
3. 会话载体：`mem.session = {id: crypto.randomUUID(), expiresAt: now + AUTO_LOCK_MS}` `[码]`。
4. 「解锁三层」为单按钮动作，一次口令尝试全部三层 `[稿:1068]`。
5. 页脚必须逐层写明算法差异：`ZChain 层 Argon2id + ChaCha20-Poly1305，EVM / Starknet 层 PBKDF2-SHA256(600k) + AES-256-GCM` `[稿:1072]`。`[判]` 这不是技术炫耀——"同一口令喂给两套 KDF"是用户必须知道的边界，DS-13 已列为不许删的文案 `[稿:953]`。
6. ⚠ `[审]` 「忘记口令？使用备份恢复」**文案有误导风险**：备份口令与解锁口令相互独立（F-03 规则 3），只忘**解锁**口令的用户走此路径同样无效。改为「忘记口令？使用备份恢复（需备份口令）」→ R-10。
7. ⚠ `[审]` **稿未覆盖的第二类超时**：代码另有 `PAGE_TIMEOUT_MS = 45_000`（页面请求超时）、`EVM/STK_DRAFT_TTL_MS = 60_000`（草稿 TTL）`[码]`。这些时长与 15 分钟自动锁定是不同层机制，必须在设置或帮助文案中区分，否则用户会把 45s 页超时误读为"被锁了"。完整常量表见 §6.1。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 口令错误 | 全部层保持锁定 | `BadPassword`；不透露哪层算法先失败 `[判]` |
| 仅部分层匹配（历史分次改过口令） | 成功层解锁，失败层保持锁定并逐层列出 | 「2 层已解锁，1 层口令不符」`[判]` |
| 会话超龄 | 拒绝使用旧会话 | `SessionInvalid`「钱包已锁定，请先解锁」 |
| 无 keystore | 跳 `welcome` | `NoKeystore`「还没有钱包：请先创建或导入」 |
| 该层无账户 | 跳过该层 | `NoAccount`「还没有该层账户：请先创建或导入」 |
| 解锁途中 popup 关闭 | 视为取消；内存会话按 TTL 自然过期 | 无提示 `[判]` |

---

### 4.2 账户层

#### F-05 三链总账（`home`）— P0 · 本文最重的一屏

**功能描述**：三层资产聚合视图 + 最弱凭证 + 待办，是"账簿封面"。
**用户故事**：作为每天开 popup 数次的用户，我希望一眼看到三层各有多少、哪层被锁住、现在有没有一笔资产正卡在凭证阶梯的某一格。

**业务规则**

*A. 总额块*

1. 主数字为**法币等值**，稿面 `≈ $22,288.63`，前缀 `≈` 表示折算非承诺 `[稿:1086]`。
2. ⚠ **`[审]` 该数字在 0.6.1 无任何数据源。** 代码事实：`PRICE_SOURCE_CONNECTED = false` `[码 ui_ledger.js:25-26]`，`fiatOf` 恒 null；**已上线的界面行为是** hero 渲染 `—`（绝不是 `$0.00`）+ chip `价格源未接入`，设置页「货币计价」也显示 `未接入` `[码 popup.js]`。`[判]` **本文以代码口径为准**：价格源接入前总额块必须 `—` + `价格源未接入`，禁止出现任何 `$` 数字 → **R-01（发布门禁级）**。
3. ⚠ **跨域禁止轧差** `[码 ui_ledger.js:15,373-388]`：`sumWithinDomain()` 只允许同域相加，**`REAL / GAME 金额永不合计`**。稿面"三链总资产"把 REAL 托管映射与 EVM/Starknet 市场价资产相加，**语义上违背该纪律**——REAL 是托管债权，不是可自由动用的市场价资产。`[判]` 价格源接入后若要合计，三选一：(a) 仅合计非托管资产、REAL 单列不进总额；(b) 标题改「三链资产概览」且逐层不汇总；(c) 合计但逐段标注托管性质。需产品裁决。
4. ⚠ `[审]` **复算不通过**：`10,120.00 + 8,124.69 + 4,043.42 = 22,288.11 ≠ 22,288.63`（差 **$0.52**），证明稿面总额是**手写字面量**而非计算结果。规则：**任何"合计"必须由求和函数产出，禁止硬编码**（账簿第一纪律：合计必须能竖着加平）。
5. 眼睛图标 = 隐藏金额。⚠ `[审]` 稿未定义隐藏态渲染与持久化。补齐 `[判]`：隐藏后**所有**金额位（法币等值、行内金额、限额用量、gas、选币明细）统一渲染 `••••••`；状态存于渲染态 `rt`，不写磁盘（避免重启后仍隐藏导致困惑）。

*B. 账户层列表*

6. 三行分别跳 `acct` 对应链 pane `[稿:1091-1093]`。
7. 每行右列为该层法币等值，行下 `ar-s` 显示该层地址。`[判]` 地址与金额同屏是防误点的必要冗余。
8. 状态徽标按层独立：稿示例 ZChain 已解锁 / EVM 已解锁 / Starknet 已锁定，抬头「已解锁 2 / 3」严格一致 ✅。**规则：徽标必须来自三个独立判定函数，禁止用一个全局 unlocked 布尔驱动四行。**
9. 锁定层的余额仍可见——Starknet pane 明写「当前余额为链上只读数据」`[稿:1208]`。`[判]` 只读展示不需解锁，这是刻意的信任/隐私权衡。
10. ⚠ `[审]` ZChain 行副文案 `PLAY 12,400.00 · NATIVE 10,000.00` 把 GAME 与 REAL 金额并排在**同一行**。虽未相加，但仍把两域混进一个视觉单元。`[判]` 改为两列（`GAME 12,400` / `REAL 10,000`）并沿用 F-06 的 chip 配色，保持"域"的视觉隔离 → R-41。

*C. 最弱凭证卡*

11. 凭证条常驻首页（"一等公民"的具体落点）`[稿:1096-1104]`。
12. 聚合规则：取全部 note 的**最弱一环**，由 `proofLadder()` 返回 `weakest`；未知 proof 一律回落 `'pending'`（不猜、不把 null 当 0）`[码:203-214]`。
13. ✅ **层级判定的真实出处（本 PRD 最重要的数据来源澄清）**：note 侧枚举是 `ProofState {Pending, Soft, Proven{batch_root,batch_index}, Finalized}` 单调推进 `[码 poker-wallet/src/note_store.rs:38-52; sync.rs:202]`；`proven` 与否由**网关水位**决定——`frame_index ≤ watermark → "proven"`，否则 `"soft_accepted"`，watermark = 最后一条 proven-log 的 `op_index` `[码 explorer_gateway/api.rs:159-163]`。`[判]` 所以 `proven` 不是"我看了一会儿"，而是"网关注明的水位覆盖到了这笔操作"。界面必须把"水位"作为可解释对象（DS-13「网关水位原样展示、不推进」）。
14. ⚠ **`[审]` 系统内不存在"确认数"概念。** `[档 docs/37-10-trust-layer-model.md]`：信任分层是 Layer1 ≥2/3 validators、Layer2 assigned_validator OR ≥4 witnesses、Layer3 zero-trust，三者**区块终态均为 ~3s**，epoch 长度 1000 块；全系统**没有 "N confirmations" 这一列**。唯一例外是 EVM pane 用 Etherscan 的 `confirmations > 0` `[码 evm/history.js:17]`。**界面规则：任何非 EVM 层不得出现"需要 N 个确认"字样**；进度信号只有三处——note 的 `ProofState` 阶梯、网关水位、（仅 EVM）链上确认数。
15. `[审]` 措辞统一：卡片标题「最弱凭证」/ 副文案「短板：…」/ 代码字段 `weakest`。三处同义，UI 统一用「最弱凭证」。

*D. 待办卡*

16. 计数徽标「1 项」；条目为 dapp 签名请求，含 origin 与剩余时间。
17. ⚠ **`[审]` `92s 后过期` 违反倒计时格式化契约**：`remainText()` 规定 `<60s → "Ns"`、`60s ≤ x < 1h → "m:ss"`，故 92 秒应渲染 **`1:32`** `[码:166-176]`。稿首页/回执列表写 `92s`、签名页抬头写 `1:52`（=112s）——两个数是不同渲染时刻，可解释；但 `92s` 的**格式**是错的。规则：**所有剩余时间一律走 `remainText()`** → §6.3。
18. ⚠ `[审]` **签名请求的 120 秒 TTL 与草稿 TTL 不是一回事**：`pendingTtlMs = 120_000`（待签名请求 `[码 validation.js:99]`）、`EVM/STK_DRAFT_TTL_MS = 60_000`、`transfer_preview.ttlSec = 300`。首页待办的倒计时必须取**请求 TTL**，不得取草稿 TTL。
19. 待办为空时整卡不渲染（而非渲染空卡）`[判]`：首页是封面，空状态卡把注意力浪费在无事发生上。

**交互流程**：popup 打开且已解锁 → 渲染三层余额 + 最弱凭证 + 待办 → 点层行进 `acct`；点「查看」进 `zc-withdraw`；点待办进 `zc-confirm`；齿轮进 `settings`；锁进 `lock`；tab 切 `acct`/`proofs`。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 无任何 keystore | 不渲染首页，跳 `welcome` | – |
| 某层 RPC 不可达 | 该层 `—`；**不伪造、不沿用上次数值** | `RpcUnreachable`「RPC 不可达（未伪造结果）」 |
| 网关不可达 | 同上 | `GatewayUnreachable`「网关不可达（未伪造结果）」 |
| 网络未配置网关（`zchain-testnet-1.gatewayUrl = null`） | 该域数据全 `—` | `GatewayNotConfigured`「当前网络未配置网关」（**刻意设计**，不得回落 devnet 网关） |
| 网络不在注册表内 | 拒绝并提示 | `NetworkUnsupported`「该网络不在注册表内」 |
| 三层全锁定 | 只显示只读余额与解锁入口 | 「已锁定」 |
| 加载中 | 骨架行，不遮挡已有数据 | – |
| 网关限流（10 req/s、burst 20、429） | 退避重试并如实提示 | 「网关繁忙，稍后重试」`[判]` |

---

### 4.3 账簿（`acct` 单模板 × 三链）

#### F-06 账簿 · ZChain 层 — P0

**功能描述**：ZChain 层主页，GAME/PLAY 与 REAL 托管资产**分列不合算**，四个快捷动作。
**用户故事**：作为桌上玩家，我希望一眼分清"能玩的筹码"和"名义上是我的钱"，并且这两个数不要被偷偷加起来。

**业务规则**

1. **左右双列总额（`.split`）**：左 `GAME 可用筹码 12,400.00 PLAY`（蓝墨 chip），右 `REAL 托管映射 10,000.00 NATIVE`（金墨 chip + 金墨数字）`[稿:1136-1139]`。**两列不得相加** `[码:373-388]`。这也是稿在 home 只报 $10,120.00 的原因（PLAY 不计价）。
2. ⚠ **`[审]` GAME 域聚合口径存在两种含义，稿未区分。** 代码事实：`groupBalances()` 把 wallet-core 的 v1 字段 `play_free/play_locked`（来自 `wallet_get_all_notes`，十进制**字符串**）映射到 GAME 行；而**另一处 GAME 聚合是 `outstanding = Σminted − Σburned`，即"流通供应量核对"，不是用户余额** `[码 assets.js]`。两者数值可能完全不同。`[判]` 本屏的 `12,400.00` 必须是**本账户 note 之和**；若同时展示供应量核对，标题必须写「GAME 域流通量」而不是放在资产行里 → **R-22**。
   另注：为避开 u128 精度丢失，金额全程以**字符串**传递 `[码]`——**所有求和必须走 BigInt，禁止 `Number()`**。
3. ⚠ `[审]` **域编号文档与代码不一致**：`docs/plan-token-economy-v1.md §1.1` 定义三域（`REAL=1, PLAY=2, Game=3`）`[档]`，代码冻结为两域（`DOMAIN={REAL:1,GAME:2}`，legacy PLAY = `token_id 0`，`poker-appchain/src/asset_id.rs:117-121`）`[码]`。**界面口径以代码为准**，文档需同步 → R-23。资产名唯一来源是 `common/networks.js` 的 `ASSET_TABLE`；未知 asset id → `UnknownAsset`（fail-closed，不显示"未知资产 0x…"）`[码 assets.js]`。
4. 托管警示紧贴双列：`托管映射资产 — REAL 域提现通道未开放；GAME 域筹码不上主网。` `[稿:1140]`。金条提示条为 **P0 不可折叠**。
5. 快捷动作 4 格：`收款`(sheet) / `转账` / `提现` / `Portal`。`[审]` Portal 进动作条意味着它是一等操作而非二级详情 ✅ 与 DS-0 自洽。
6. ✅ 资产列表三条：PLAY(GAME) / NATIVE(REAL) / USDT+USDC(未接入)。**第三条整行 `opacity:.5`、金额 `—` 而不是 `0.00`** `[稿:1151]`。代码完全对齐：REAL 域三列封闭枚举，`usdt/usdc` 硬编码 `{connected:false, free:null, locked:null}`，注释"如实标注未接入，刻意不写 0" `[码 assets.js:5-6,134]`。**稿此处是全稿最可信的示范。**
7. `桌上锁定 0.00` 与 `可用 12,400.00` 同列 `[稿:1149]`：区分"账面"与"可花费"。`[码]` `InsufficientFunds` 官方文案「可用余额不足（note 全额消费，不支持部分花费）」说明**可用余额不是一个字段而是一堆 note 的组合结果**，因此"可用"必须由选币器算出。软锁真实来源是 `pendingSpendMap()`（防双花）`[码 receipts.js:78]`。
8. ✅ 会话密钥摘要卡 `单笔 / 日累计 ≤1,000 · 2,150/5,000` + 进度条 43%。`[审]` 复算 `2150*100/5000 = 43` ✅ 与 `sessionUsage()` 的 `Math.min(100, Number((u*100n)/l))`（整数向下取整）精确一致 `[码:293-303]`。**这条是稿面数字有真实算法支撑的正面样板。**
9. ✅ 最新动态 2 条（`included` / `seen`），时间文案「2 分钟前」「刚刚」符合 `relTime()` 契约 `[码:150-163]`。
10. ⚠ **`[审]` 但这两条的金额值无来源**：回执数据结构**没有 `amount` 字段**（存 `{digest, kind, chainId, signedAtMs, deadlineMs, status, seenAtMs, includedAtMs, inputs[], evidence, openedAt, seenTxHash}`）`[码 receipts.js]`。稿面 `-500.00` / `+620.50` 需由 `inputs[].amount` 求和得出（可推导）或由预览快照回填 → **R-24**。
11. ⚠ **`[审]` 「结算 · 8♠ 桌 #128」这类标题也没有来源**：代码 `kindLabel` 仅映射 `transfer | buy_in | settle | withdraw` 四个 kind `[码]`，**没有"开桌"这个 kind**，也没有桌号/局号字段。稿面的桌名（8♠ / 9♣）与局号（#128 / #96 / #127 / `#A3F2`）全部为装饰性示例。`[判]` 若要展示桌标识，需在回执新增 `tableId` 字段并明确类型（F-12 规则 7：`tableAllowlist` 是**非负整数**数组，`#A3F2` 这种 hex 与之冲突）→ R-25。
12. ⚠ `[审]` **链切换器计数 `2 / 1 / 1` 口径未定义**：ZChain 资产行 3 条（含 1 条未接入）显示 2；EVM 2 条（ETH + USDC）显示 1。`[判]` 推断为"**有值条目数**（未接入 / 空值不计）"，需钉死 → D-08。

**交互流程**：home 点 ZChain 行 → `acct`(zc)，或 tab 进 `acct`（沿用 `lastChain`）→ 顶部切换器换链只换数据面，抬头 kind/net/addr 同步 `[稿:1798-1805]`。「收款」→ `ovl-zc-recv`；「转账」→ `zc-send`；「提现」→ `zc-withdraw`；「Portal」→ `zc-portal`；「资产 · 回执」→ `zc-receipts`；「会话密钥 · 管理」→ `zc-sessions`。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 无 note（新账户） | 双列 `0.00`（真零），区别于未接入的 `—` | 空态引导「去水龙头领取」`[判]` |
| 网关水位落后 | 原样展示，**不推进、不猜测** | 凭证条停在网关给出的等级 `[稿 DS-13:954]` |
| note 全被桌台软锁 | 可用为 0，转账禁用 | `NoSpendableNote`「没有可花费的 note」 |
| 金额超 u64（>20 位） | 拒绝 | `AmountOverflow`「金额超出可表示范围」（`U64_MAX = 18446744073709551615`） |

#### F-07 账簿 · EVM 层 — P0

**业务规则（关键差异点）**

1. 总额块 `2.4183 ETH ≈ $8,124.69`，附二维码与外链两个图标按钮 `[稿:1168-1171]`。二维码按钮受 R-17 约束（未接入 → 不画假码）。
2. ⚠ **`[审]` 三处隐含 ETH 单价互不相同**：`8,124.69/2.4183 = $3,359.67`；Starknet pane `4,043.42/1.2034 = $3,360.00`（精确）；send 预览 `840.12/0.25 = $3,360.48`。**规则：一次渲染只允许一个价格快照**（同一 `updatedAt`），全部派生等值由该快照计算，禁止各屏各取各的价 → §13 C-02。
3. ⚠ **`[审]` pane 总余额未计入 ERC-20，且 ERC-20 本身无实现来源。** 稿资产列表有 USDC `320.00 · erc-20 · eth_call 读取`，但 `2.4183 ETH` 与 home 的 `$8,124.69` 都只覆盖原生币。代码事实：**账簿页的 ERC-20 行是静态 `—` 占位**，注释「需在「合约」页按代币地址读取」`[码 popup.js]`。`[判]` 标题从「总余额 · ETH」改为「原生币余额 · ETH」，或补 ERC-20 读取能力后合计并标注来源 → R-04。
4. ✅ 网络卡三行 `chainId 1 校验通过` / `gas 12 gwei` / `nonce 42`**均有真实来源**：`eth_getTransactionCount` `[码 evm/rpc.js:78]`、`eth_gasPrice` `[码:82]`、`gasPriceGwei = formatUnits(gasPrice, 9)`、渲染 `fmtAmount(info.gasPriceGwei)+' gwei'` `[码 popup.js:1411]`；chainId **签名前二次独立验证（不符拒签）** `[码 capability_matrix.js:65]`。
5. ⚠ **`偏低` 这个判断词无算法** `[审]`：12 gwei 的"偏低"没有基准。`[判]` 规则：`偏低/正常/拥挤` = 当前 gasPrice 相对网络参考值的分位区间；**取不到参考值则不显示 chip**，禁止凭静态数写判断词 → R-05。
6. ⚠ **`[审]` 「mainnet 刻意不注册」只适用于 ZChain 层，不适用于 EVM 层。** 代码事实：EVM 网络注册表**包含 Ethereum `0x1`（`https://eth.llamarpc.com`）**、Sepolia、Base、Arbitrum、`evm-devnet 0x7a69@127.0.0.1:8545` `[码 service_worker.js]`；被刻意不注册的是 `zchain-mainnet-1`。稿面能力矩阵写「网络 · mainnet 刻意不注册 → NetworkUnsupported」**会让 EVM 用户误以为主网不可用**，而 F-07 本身就在展示 chainId 1。**必须改写为「ZChain 层 mainnet 刻意不注册」** → **R-26（高优先文案缺陷）**。
7. USDC 行带 `只读` chip `[稿:1188]`：ERC-20 余额经 `eth_call` 只读取得，**不产生任何签名**。`[判]` 信任标注，列 P0 不可移除。
8. 账户管理入口行 `私钥 · 口令 · RPC → 危险区需二次确认`。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 交易状态非 confirmed/failed | 显示 `待确认` | ⚠ **稿面写 `pending`，而 `txStatusChip()` 规定未知态返回 `{text:'待确认', cls:'ch-amb'}`** `[码:265-269]`。采代码口径。 |
| 交易 revert | `已回退` | `txStatusChip('reverted')→'已回退'` `[码]`（稿只演示了 `Failed`） |
| ERC-20 合约无响应 | 该行 `—`，不影响原生币 | 「读取失败」`[判]` |
| `eth_chainId` ≠ 所选网络 | **拒签** | `与预设不符` + `InvalidArgument`「输入不合法」 |
| `eth_estimateGas` 失败 | 回落 `max(estimate, 21000)` | 不隐藏回落 `[判]` |

#### F-08 账簿 · Starknet 层 — P0

**业务规则**

1. **本层锁定的独立呈现**：`bn-amb`「本层已锁定 · 解锁后才能发起 invoke；当前余额为链上只读数据」`[稿:1208]`。`[判]` 三层里唯一演示"锁定态仍可读"的 pane。
2. 动作条 `发送 / 收款 / 水龙头 / 历史`。发送在锁定态触发 toast。⚠ `[审]` 稿未定义"禁用 vs 提示后拦截"。规则：**入口保持可点，点击后在签名边界拦截并跳 `lock`**（禁用不解释原因，可点能给反馈）`[判]`。
3. 网络卡：`chainId ZCDN 校验通过` / `nonce 7` / `UDC 地址 0x41a7…8e02（公式推导）`。`[审]` "公式推导"是诚实标注的正面例子——UDC 地址由网络参数推导而非查询。**规则：凡推导值必须显式标注「公式推导」**，与查询值、估算值三档区分。
4. ⚠ **`[审]` 代币符号错误（发布门禁级）。** 稿面 Starknet 总额标题为「总余额 · ETH」、徽标 `Ξ`、`invoke · transfer -0.5000`、水龙头 toast「示意:水龙头领取 10 ETH」。代码事实：**devnet 的 `tokenSymbol` 是 `DST` / "Dev Stark Token"** `[码 stark/networks.js:22-25]`。`[判]` devnet 上把 DST 显示成 ETH 会让人误判资产性质（DST 无价值、水龙头所铸）。**测试网资产必须显示测试网符号** → **R-19**。
5. 水龙头 `+10.0000`，标 `dev` chip（蓝墨）。`[审]` 用 PLAY 语义色标 devnet 来源筹码，与 DS-6「蓝墨只标测试/娱乐筹码」一致 ✅。金额单位需按 R-19 改为 DST。
6. `invoke · transfer` 行展示 `maxFee 0.00042`——把费用上限摊在第一层列表，符合账簿叙事；代码对应 `chainState.maxFee` `[码 popup.js:1429]` ✅。
7. `[审]` **密钥类字段的掩码纪律**：代码中 `chainState.strkScanKey` 值为**固定 8 星号 `********`**（表示"已配置"，不回显明文；`popup.js:1298` 注释）**规则**：任何密钥字段永不回显明文，只以「已配置 / 未配置」+ 固定长度掩码表达（避免掩码长度泄露 key 长度）。
8. `[审]` 稿面 Starknet 无独立"发送"屏（只有 toast），但代码把 `send` 标为 `shared`。`[判]` Starknet 发送屏需补齐设计（同账簿模板，字段为 `to/calldata/maxFee/chainId`）→ R-02 同源。

---

### 4.4 ZChain 专属流

#### F-09 转账 · 贪心选币（`zc-send`）— P0 · 全应用唯一可提交的资产变动

**功能描述**：GAME 域 PLAY 转账；界面展示贪心选中的支出 note、找零、凭证门槛与可提交判定。
**用户故事**：作为要给另一账户转筹码的玩家，我希望看到"这笔钱由哪几张 note 凑成"，并在签名前就知道它能不能提交。

**业务规则（穷举）**

1. **PLAY 是整数筹码，不支持小数**：`parseAmountInput()` 去 `,_␣`，拒绝任何非零小数位（reason「PLAY 为整数筹码，不支持小数」），但接受 `.00` 形式 `[码 transfer_preview.js:47-58]`；再过 `validateAmount`（`^[0-9]+$`、≤20 位、≤`U64_MAX`、>0、无前导零）。`[审]` 稿面 `500.00` / `12,400.00` 是**显示层补两位的排版约定，不是数据精度**。**规则**：(a) 输入允许 `.00`，其他小数拒绝并说明原因；(b) 所有 note 量为 u64 整数；(c) 展示精度由 §6.3 的"显示精度表"统一补齐，**且 `fmtAmount` 本身不补零**（代码里没有任何函数会产出 `12,400.00`，补零必须由新增展示层完成）→ **R-27（U-01）**。
2. **MAX 填入最大可用** `[稿:1275]`，来源是预览的 `spendableTotal` `[码]`，**不是余额字段**。
3. ✅ **网络费：网关代付，显示 `免费`** `[稿:1289]`。代码精确一致：`fee:{paidBy:'gateway', amount:'0', label:'网关代付'}` `[码 transfer_preview.js]`。`[审]` EVM 层 gas 模型完全不同——**两域费用语义不可混用，不可在同一列表并列比较**。
4. **贪心选币**：按 `BigInt(amount)` 降序取 note 直到覆盖目标，**note 全额消费**（无部分花费），金额相同按 commitment 破平序（确定性）`[码 transfer_preview.js:60]`。稿示例 `300.00 + 200.00 = 500.00`、找零 `0.00（本次无找零）` ✅ 复算通过。
5. **守恒校验**：`Σoutputs === Σinputs`；`canSubmit = reasons.length===0 && covered && conservationOk` `[码:165]`。预览同时产出 `totalIn`、`change`、`outputs[{owner,amount,change?}]`、`finality{worstProof,requiredProof,reached}`、`covered`、`spendableTotal`、`cannotSubmitReasons[]`、`operation`（送去 wallet-core 的那一份，**UI 展示摘要与签名摘要同源**）`[码]`。
6. **支出 note 数硬上限 16**（`LIMITS.maxInputs`/`maxOutputs`，批量签名防护）`[码 validation.js:97-98]`。⚠ **稿未定义超限态** `[审]`。规则：贪心结果 >16 → `canSubmit=false` + 原因「所需 note 数超过单签上限 16，请先合并小额 note」，并在选币卡显示所需张数 → R-06。
7. **GAME 域凭证门槛是网络策略，不是 UI 口径** `[码 transfer_preview.js:24-38]`：设计基准 `GAME_MIN_PROOF='proven'`；**devnet 放宽为 `DEVNET_MIN_PROOF='soft'`**（本地水龙头铸的 stub note 在 wallet-core 里只有 `Soft`，无批次根，不能谎称 proven）；testnet/mainnet 维持 `proven`。⚠ `[审]` 稿面 zc-send 写「满足 GAME 域要求」而当前网络是 `zchain-devnet-1`——devnet 实际要求是 `soft`。**「本网络要求的等级」必须是数据不是文案**，否则换网时说明会撒谎 → R-05b。
8. **门槛在后台复核**：`verifySpendProofs()` 在 `popup:transferConfirm` 独立再验一次，**UI 那份 `canSubmit` 只是展示结论** `[码 extension/README.md:164-166]`。`[判]` 本屏最重要的架构纪律：界面禁用不是安全边界，后台复核才是。
9. ⚠ **`[审]` 收款 owner 的格式在稿中是错的。** 代码要求：**66 位 hex = 33 字节压缩公钥，不带 `0x` 前缀**，全零拒绝 `[码 transfer_preview.js; validation.js]`。稿占位符写 `0x… / zc1q…` `[稿:1280]`——既允许了 `0x` 前缀，又暗示存在 bech32 地址形态。`[判]` 必须改为「33 字节压缩公钥（hex，无 0x 前缀）」并说明为何是公钥 → **R-19（P0）**。
10. 提交成功后回执 `digest`（**64-hex**）应在「证明 → 回执」可跟踪 `[稿:1302]`。⚠ `[审]` toast 写的 `回执 0xc41d…9b` 形态既不是 `shortAddr` 默认口径，也不是 64-hex 的正确缩略。
11. **预览 TTL 300 秒** `[码 transfer_preview.js]`。`[判]` 选币结果超过 5 分钟必须作废重算（note 集合可能已被桌台消费）。稿未展示"预览过期"态 → 并入 R-06。
12. ⚠ `[审]` 预览的 `nonce = nowSec*1000`，SW 会用单调递增的 `nextTransferNonce()` 覆写 `[码]`。**界面不得展示这个 nonce**（它是防重放内部计数，不是链上 nonce），否则用户会把它和 EVM pane 的 `nonce 42` 混为一谈。

**交互流程**：`acct(zc)`「转账」→ 本页 → 输入金额实时重算（张数/找零/短板/canSubmit）→ 输入 owner（扫码入口受 R-17 约束）→ 「确认转账」→ 后台签名提交 → toast → 回执进 `signed`。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 余额不足 | 禁提交，标出缺口 | `InsufficientFunds`「可用余额不足（note 全额消费，不支持部分花费）」 |
| 无法找零平衡 | 禁提交 | `NoChangeAllowed`「选币结果无法平衡：需要找零输出但收款方已满」 |
| note 已被消费 / 不在本库 | 拒绝 | `NoteNotFound`「输入 note 不在本账户库中（可能已被消费）」 |
| note 被桌台软锁 | 拒绝 | `NoteNotSpendable`「输入 note 已锁定，不可花费」 |
| 凭证低于本网络门槛 | 拒绝（后台兜底） | `ProofBelowGate`「凭证层级低于该网络的支出门槛」 |
| 预览摘要与签名内容不一致 | **拒签** | `PreviewMismatch`「预览摘要与签名内容不一致（已拒绝）」 |
| 预览过期 | 要求重新发起 | `DraftExpired`「交易预览已过期，请重新发起」 |
| owner 格式非法 | 字段级拒绝 | `OwnerInvalid`「收款地址格式不合法」 |
| 无待确认交易 | 拒绝提交 | `NoDraft`「没有待确认交易，请重新发起」 |
| 用户取消 | 不产生回执 | `UserRejected`「已取消」 |

#### F-10 REAL 提现预览 · fail-closed（`zc-withdraw`）— P0

**功能描述**：REAL 域提现的**逐字段预览**。**本屏永不产生链上交易。**

**业务规则**

1. **`canSubmit` 恒 false**，且是 wallet-core 展示门（`readiness=vault_offline`）与 finality 判定的**合取**：任何一层不满足都不可能出现可提交态；**UI 只消费本模块输出，不得自行决定** `[码 withdraw_preview.js 红线注释; ACCEPTANCE.md:332]`。
2. ✅ 展示门的真实判据：`real_page_view` 要求 `vault_online && verifier_ready && bft_finality_ready`，当前 `show_claim=false`、`claim_disabled_reason='vault_offline'`、托管提示 `'real_is_custodial_v1_offline'` `[码 poker-wallet/src/display.rs:55-73]`。`[审]` **这直接证实了稿面三条原因中的第 ①③ 条**（通道未开放 / 托管方签名服务待接入）来自同一处策略，不是编造。
3. ✅ 准入最低凭证层级 `WITHDRAW_MIN_PROOF = REAL_MIN_PROOF = 'finalized'`（从严）`[码 withdraw_preview.js:22]`；稿面「所需证明 finalized」完全一致。
4. 金额校验：正十进制整数、≤20 位（超 → `AmountOverflow`）；owner `validateHex(input.owner, 33)` `[码:41-47]`。
5. ✅ 原因必须**逐条列举，不得合并成一句「暂不可用」** `[稿 DS-13:945]`。稿示例三条复算 ✅：① 提现通道未开放（v1 托管模式）② 1 张 note 未达 finalized ③ 托管方签名服务待接入。其中选币 `1,000 + 2,500 + 1,500 = 5,000.00` 精确等于提现金额、找零 `0.00`，故第 ② 条只能源自 note `a208…91ce = soft`，逻辑自洽。
6. **模拟预览的双重声明**：抬头印章 `通道未开放` + 提示条「以下为模拟预览，不会提交任何链上交易」`[稿 DS-13:944]`。**两处都要，不可只留一处。**
7. 禁用按钮笔触 = **虚线**（"不可用"的专用形状语言），配文案「fail-closed：原因消除前，提交入口保持禁用」`[稿:1343]`。
8. ⚠ **`[审]` 三条原因同视觉权重但不同性质。** ①③ 是策略/依赖型（本版本不会开放），② 是数据型（会随水位推进自行满足）。当前呈现会让用户误以为"等一会儿就能提"。`[判]` 策略型原因必须加限定语「本版本不会开放」→ R-07。
9. ⚠ `[审]` 链上 `Proven` 需要 `batch_root + batch_index` `[码 note_store.rs:38-52]`，即"被证明批次覆盖"；稿面 note 只有单个 proof 词，没有批次信息。`[判]` 若要做"可证"，凭证详情应可展开到 `batch_root`（可独立复核的锚点），否则 `proven` 仍是不可验证的断言。
10. `[档]` **真实提现路径确实存在但未实现**：`WithdrawRequest` + 水位 + 批次根的**双重 finality**（PLAY 豁免）`[docs/plan-appchain-v1.md:281]`。`[判]` 界面不得出现任何暗示"即将开放"的时间承诺。

**异常处理**：`BadPassword`、`SessionInvalid`、`InsufficientFunds`、`AmountOverflow`、`OwnerInvalid`；另「网关水位落后 → 不推进 finality，原样展示」。

#### F-11 dapp 签名请求（`zc-confirm`）— P0

**功能描述**：来自 dapp 的签名请求详情，120 秒倒计时，会话密钥免口令签名。

**业务规则**

1. ✅ 倒计时 `120 秒` **有真实来源**：`LIMITS.pendingTtlMs = 120_000`「待签名请求默认超时：超时 → `RequestExpired`」`[码 validation.js:99]`。抬头 chip `1:52` 用 `m:ss` 符合 `remainText()` ✅。
2. 子页栏右侧用 **`i-x`（关闭）而非返回箭头** `[稿:1351]`：签名请求不是导航栈的一页，退出即拒绝。`[判]` 必须在需求里写死。
3. 大额醒目 `-500.00` + 限定语 `PLAY · 8♠ 桌 · GAME 域 · 不动 REAL 资产` `[稿:1357]`。`[审]`「不动 REAL 资产」是**跨域隔离的用户可见承诺**，P0 不可删。
4. 请求内容卡：链 / `table_id #A3F2` / 资产(PLAY GAME) / `rake 2.00%` / 过期 120 秒。
   ⚠ **`[审]` 两处字段形态与实现不符**：① 代码 `table_id` 渲染为**数字**（`tableAllowlist` 亦为"非负整数"数组），稿写成 hex `#A3F2`；② 代码 `rake` 渲染为 `fmtAmount(pv.rake)`——**是金额不是百分比**，稿写成 `2.00%`。二者不能都对。`[判]` 若保留两种展示需两个上游字段（`rake_amount` + `rake_rate`），否则统一 → R-25、R-28。
5. 授权对象卡：收款 owner、`hand_binding 0xc41d8f22…04b79b`、`request_id 3f9e77d0…aa31`、证明说明「结算后可在 Portal 完整验证」。
   ⚠ **`[审]` 标识符命名空间冲突**：`0xc41d8f…` 前缀同时是**买入交易 hash**（`0xc41d…9b`）与 **hand_binding**；`3f9e77d0…` 同时是 request_id 与结算 tx 前缀（`0x3f9e…aa`）。`request_id` 上限 128 字符 `[码 validation.js:93]`，而 `hand_binding` 是 32 字节摘要——**两类标识符没有视觉区分手段**。`[判]` 必须为不同标识符定义不同前缀标签（`tx` / `hb` / `req`），否则用户无法跨屏核对 → R-29。
6. **会话密钥免口令条件**：「在单笔限额（≤ 1,000 PLAY）内，无需输入口令」`[稿:1374]`。⚠ `[审]` **超出 `perTxLimit` 时的回落界面稿未画**，需补：「本笔 > 单笔限额 ≤1,000，需口令确认」。→ 并入 R-06。
7. 原始摘要 `<details>` 折叠（SNIP-12 原文，供专业用户核对，不强迫普通用户读）`[稿:1379]`。⚠ 稿示例为 **68 位 hex（34 字节）**，而 32 字节摘要应为 64 位 → §13 C-06。
8. **盲签拒绝**：能力矩阵红线「盲签拒绝；私钥 / 助记词 / nullifier 不出边界；网关水位原样展示、不推进」`[稿:1644]`。
9. 超时：`RequestExpired`「请求已超时」`[码:343]`，弹窗自行关闭并回执给 dapp。
10. ⚠ `[审]` **origin 的可信度局限**：稿用 `poker.zchain.devnet` 作 origin。`[判]` 此值必须来自后台校验过的请求 origin（未授权 → `OriginNotPermitted` `[码:355]`；长度上限 256 `[码 validation.js:95]`），且界面必须标出"origin 由浏览器提供、同名站点可能仿冒"这一局限。

**交互流程**：dapp 发起 → 扩展提示 → 本页 →「批准签名」走会话密钥路径（限额内免口令）→ toast；「拒绝」→ `UserRejected` → 回 `acct(zc)`；倒计时归零 → 自动按拒绝处理并关闭。

#### F-12 会话密钥 · SNIP-12（`zc-sessions`）— P0

**功能描述**：按 origin 记账的委托签名授权，含"现有会话"与"新建草稿"两段。

**业务规则**

1. 授权簿**按 origin 记账**；撤销只影响该 origin 的委托密钥，**不动主密钥** `[稿:1418]`。
2. 状态词封闭枚举 + 芯片映射 `[码:305-316]`：`active 活跃`(felt) / `exhausted 已耗尽`(amb) / `revoked 已撤销`(bad) / `expired 已过期`(amb) / `not_yet_valid 未生效` / `unknown 未知`。**未知值原样透出，不造名称**。稿面「活跃」「已耗尽」一致 ✅。
3. ✅ 日累计 `2,150 / 5,000` → 43%；`5,000/5,000` → 100% + amber + `已耗尽`（`exhausted: u >= l`）。
4. 无日限 → `{percent:null, limitText:'不限'}`，**UI 不画进度条** `[码:296-298]`。⚠ `[审]` 稿未演示该态，需补设计。
5. ⚠ **`[审]` scope 枚举与实现完全不符（P0）。** 稿：`开桌(OpenTable) / 买入(BuyIn) / 结算(Settlement)` **三项**；代码：`DEFAULT_SESSION_SCOPES = ['play','buyin','bet','settle']` **四项** `[码 sessions.js]`。缺 `play` 与 `bet`，多 `OpenTable`。**授权项对不上意味着 UI 勾的 scope 后台不认。** `[判]` 以代码为准，UI 文案改为 `对局(play) / 买入(buyin) / 下注(bet) / 结算(settle)`，并保留 SNIP-12 原词供核对 → **R-30**。
6. 限额字段 `perTxLimit` / `perDayLimit` 均为**十进制字符串** `[码 sessions.js]` → 展示前必须走 BigInt/字符串路径，禁止浮点。
7. 桌白名单：`tableAllowlist` 为**非负整数数组** `[码 sessions.js]`。⚠ 稿面 `8♠ · 9♣(2 桌)` 是装饰性花色写法，`table_id` 又写成 `#A3F2`。`[判]` 输入必须是整数；展示可给"整数值 + 本地别名"两段（如 `8 (8♠)`），**不得只用装饰性符号作为可提交的值** → R-25。
8. 有效期：**默认 `validitySec = 24*60*60`（1 天），最大 365 天** `[码 sessions.js]`。⚠ 稿面「有效期 7 天」既非默认值也未被标注为可选项。`[判]` 选择器默认显示 1 天，选择 >30 天时给风险确认。剩余展示 `剩 6 天 12 小时` ✅ 与 `validityRemain()` 模板逐字一致 `[码:179-188]`。
9. ⚠ **`[审]` 「日累计」的"日"是 UTC 日，不是本地日。** 代码按 `Math.floor(nowSec / 86_400)` 分窗 `[码 sessions.js]`。`[判]` **界面必须写明"按 UTC 日重置"**，否则用户以为本地零点重置而提前用满限额 → R-31。
10. 数量上限 `MAX_SESSION_BINDINGS = 16` `[码 sessions.js]`。⚠ 稿未定义达上限后的新建行为。规则：满 16 → 「新建草稿」禁用 + 原因「授权数已达上限 16，请先撤销不用的 origin」→ R-11b。
11. ⚠ **`[审]` 授权目前是本地登记，链上未生效。** 代码 `evidence = 'devnet_local_entry'`，注释「链上 admission 注册未接线」`[码 sessions.js]`。稿能力矩阵「SNIP-12 授权面已备，**链上 admission 未开放**」✅ 与之一致。**必须在会话密钥页显式声明**："当前授权为本机登记，链上不校验"。
12. ⚠ **`[审]` 限额执行是客户端记账。** `dailyUsedToday`/`perDayLimit` 来自本地 vault 绑定 `[码 sessions.js]`；清 `chrome.storage` 或重装即可绕过。`[判]` **限额必须由后台/链上侧独立复核，UI 只是镜像**；在此之前不得把限额描述为安全保证 → **R-03（高影响）**。
13. **撤销为粘滞操作**：立即生效、本会话永久失效、该 origin 后续每次签名都需重新输入口令 `[稿 DS-11:876]`。撤销必须走**模态二次确认 + 键入 `REVOKE` 才解禁** `[稿:877-878]`。`[审]` 键入常量字符串是有意高摩擦，与"删除账户仅需口令"形成摩擦分级（§8 D-09）。
14. `[审]` **SW 侧会话与 vault 侧会话是两个概念**：`mem.session`（解锁会话，15 min）与 `SessionBinding`（SNIP-12 授权，1 天/7 天）互不相干。`[判]` 页名"会话密钥"易与"解锁会话"混淆，建议页内加一行区分说明 → R-42。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 该 origin 未获授权 | 拒绝建立会话 | `OriginNotPermitted`「该站点未授权」 |
| 限额耗尽仍请求签名 | **回落口令路径**（非直接拒绝） | 「本会话日累计已耗尽，需输入口令」`[判]` |
| 会话绑定数达 16 | 新建禁用 | 「授权数已达上限 16，请先撤销」 |
| scope 全部取消勾选 | 登记入口禁用 ✅ `[稿:1436]` | 「请至少选择一项授权范围」 |
| 撤销失败 | 保持原态，不显示"已撤销" | 原样透出错误 `[判]` |
| 解锁会话被回收（后台重启） | 视为锁定，需重新解锁 | `SessionInvalid` |
| origin 超长（>256）/ id 超长（>128） | 拒绝登记 | `InvalidArgument` |

#### F-13 Proof Portal（`zc-portal`）— P0

**功能描述**：输入一手牌的 hand binding，本地完整复验其 STARK 结算证明。

**业务规则**

1. **四步顺序闸门** `[稿:1450-1457]` `[码 popup.js:2027-2032]`：

| 步 | 动作 | 真实上游 | 稿面展示 |
|---|---|---|---|
| 1 | 拉取结算明细 | `GET {gateway}/api/v1/settlement/{binding}` `[码 explorer_gateway/api.rs:54-77]`，超时 `DEFAULT_FETCH_TIMEOUT_MS=15_000` | `网关 127.0.0.1:18900 · 200 OK` ✅ 地址与代码一致 |
| 2 | 下载 STARK 证明 | `GET {gateway}/api/v1/proof/{binding}` `[码 api.rs:63]` | `payload 84.2 KB · engine stwo` |
| 3 | **浏览器内完整 STARK 验证** | canonical borsh `ArchivedCanonicalTaggedProof` → `vendor/stwo-verify/stwo_verify_wasm.wasm`，ABI `sv_alloc/sv_free/sv_verify/sv_stats/sv_last_error`，**完整 FRI + Merkle + constraints + 公开 scope 承诺重建** `[码 common/stwo_verify.js]` | `stwo wasm 运行中…` ✅ |
| 4 | **wallet-core 本地复验** | `wallet_verify_settlement_detail`（Rust wasm），逐项具名检查：`inputs_sum_equals_pot`、`payouts_plus_rake_equals_pot`、`rake_matches_plan`、`plan_awards_consistent`、`plan_pots_sum`、`payout_root_recomputed`、`payout_table_id_consistent`；回传 `verifier{name:'wallet-core/verifier', version, abi_version}` `[码 portal.js:289-304]` | `结算关系与 payout_root 比对` ✅ |

   上一步未过不得推进；已过的不可回退（后台顺序闸保证，非仅前端标记）。
2. **最终印章是合取**：`stark.ok && verdict==='verified' → 已验证`，否则 `'partial'` / `'failed'` `[码]`。`[判]` **`partial` 态必须有专属呈现**（不得显示 `已验证`），稿只演示了成功态。
3. **耗时如实展示**：稿 `约 1.7s` / `1.72s` ✅ 忠实——代码实测 **p50 ≈ 1.70–1.80s、p95 ≈ 1.98s，超 500ms 门槛约 3.5×**；已由决策接受「性能不敏感，超 500ms 也可交付，但**必须如实展示真实耗时**」，且 `>500ms` 时须显式标注「超预算（低频场景可接受，性能不敏感）」`[码 docs/stwo-wasm-path-a.md:5,34,152,204]`。
4. ⚠ **`[审]` 最关键的正交性要求**：`verify_settlement()` 成功时返回的 level **恒为 `FinalityLevel::Soft`** `[码 verifier.rs:92-101]`——**本地验算不授予 proven/finalized**。因此 `已验证` 与阶梯上的 `proven/finalized` 是**两个正交结论**：前者＝"这份证明的数学关系成立"，后者＝"这笔资产在共识里到了哪一格"。**Portal 成功页必须同时展示两者，且绝不得用 `已验证` 暗示可提现** → R-15 同族。
5. ⚠ **`[审]` 不得声称链上验证。** 链上 `zk_verify` 目前是 **dormant / Stub（只检查 `len() >= 64`）** `[档 docs/37-7 §6.9]`。`[判]` 界面任何位置不得出现"链上已验证 / on-chain verified"字样；`已验证` 的说明必须限定为"浏览器内 + 本地内核复验" → **R-32（发布门禁级）**。
6. ✅ **复验在本地**：「证明文件与结算明细由网关拉取，复验在 wallet-core(wasm) 本地执行；**不依赖服务端『已验证』结论**」`[稿:1682]` 与代码一致（无本地节点、无 SPV、不信服务端结论）。
7. 结算摘要四行：底池 `1,240.00 PLAY`、`rake 24.80 PLAY(2%)`、我方份额 `+620.50 PLAY`、`payout_root 0x8c3f…d210`。✅ `[审]` 复算 `1240 × 2% = 24.80` 精确成立，2% 与 F-11 同源。⚠ 但 **`+620.50` / `24.80` 含非整数部分，而 PLAY 为整数筹码、note 金额必须 `/^[0-9]+$/`**（F-09 规则 1）。这两个数**无法由当前账本数据模型产出** → 必须由 U-01（§6.2）钉死单位与精度，或改用整数示例。
8. ⚠ `[审]` **`payout_root` 的展示位**：第 4 步确有 `payout_root_recomputed` 检查 `[码 portal.js]`，说明该值在复验中被重算；但是否作为展示字段回传给 UI 未确认。`[判]` **展示位可保留，取不到时必须 `—`，禁止用占位 hash 填充** → R-16。
9. ⚠ `[审]` **payload 体积无上限保护**：稿展示 `84.2 KB`，代码只有 `DEFAULT_FETCH_TIMEOUT_MS=15_000` 限时不限大小 `[码 api.rs]`。规则：下载前读 `Content-Length`，超阈值（建议 5 MB，需评审）时拒绝并说明；同时在步骤 2 展示真实 KB → R-20。
10. ⚠ `[审]` 输入框预填 `0xc41d8f22e9a04b79b`（19 位 hex）——不是合法 32 字节摘要。规则：binding 输入必须校验 64-hex，非法即禁用「验证」按钮 → §13 C-06。
11. `[审]` 状态接口 `GET {gateway}/api/v1/status` `[码 api.rs:56]` 未被稿面任何屏使用。`[判]` 建议 Portal 首屏读取该接口以显示"网关可用 / 水位"，替代靠请求失败才发现不可用 → R-43。

**交互流程**：入口 = `acct(zc)` 动作条 Portal / `proofs` 待复验条目 → 输入或粘贴 hand binding →「验证这一手牌」→ 步骤 1→4 顺序推进（当前步 `run` 态 + 旋转图标）→ 成功：`已验证` + `bn-ok`；失败：`bn-bad` + 错误码原文 + **保留已完成步骤**（便于定位）。

**异常处理**

| 异常场景 | 处理方式 | 用户提示 |
|---|---|---|
| 该 binding 无结算明细 | 停在步骤 1 | `SettlementNotFound`「该 hand binding 无结算明细」 |
| 无已归档证明 | 停在步骤 2 | `ProofNotFound`「无已归档证明产物」 |
| 网关未配置（testnet） | 直接失败，不猜测 | `GatewayNotConfigured` |
| 网关超时（>15s） | 失败可重试 | `GatewayTimeout`「网关超时」 |
| STARK 验签拒绝 | 步骤 3 失败，显示 `rc` | `StarkVerifyRejected`「STARK 证明验证未通过」（`rc -1/-2/-3` → `StarkArchiveInvalid`/`Rejected`/`VerifierError` `[码]`） |
| 结算关系不符 | 步骤 4 失败，**列出具体不通过的检查名** | `WalletCoreError` + 检查名 `[判]` |
| 证明体积超阈值 | 拒绝下载 | 「证明体积 N KB 超出可验证上限」`[判]` |
| 只完成部分步骤 | 印章 `partial`，**不得显示 `已验证`** | 「部分验证完成」`[判]` |

#### F-14 回执状态机（`zc-receipts`）— P0

**功能描述**：本钱包所有签名请求的投递状态跟踪，三段过滤。

**业务规则**

1. **两套状态不得混用**：凭证阶梯 `pending→soft→proven→finalized`（**凭证**状态，锚定在 note）与回执投递 `signed→seen→included`（**投递**状态）语义正交，笔触刻意不同 `[稿:748,1683]` `[码 ui_ledger.js:20,23]`。DS-7 核心论点，P0。
2. ✅ 常量一致：`DEFAULT_INCLUSION_DEADLINE_MS = 10_000`（与协议侧 `poker_l1/src/force_include.rs:61` 同值 `[码 receipts.js:19]`）、`RECEIPT_STATES` 三态单向 `[码:22]`。
3. ⚠ **`[审]` `included` 是本地手工登记，不是链上核对。** 代码 `evidence` 恒为：`seen → 'not_provided' | 'receipt_unverified_signature'`、`included → 'local_manual_entry'`；模块头直说「扩展 0.2 **不实现提交路径**（无 tx 广播、无 receipt 验签）」`[码 receipts.js]`。`[判]` `included` 芯片**必须带可展开的 evidence 说明**，不得让绿色 `included` 读作"链上已确认"。`[稿:1491]`「evidence 按网关返回如实展示，未验签就写未验签」✅ 与代码一致，列 P0 → R-33。
4. **列表容量上限 20，超出丢弃最旧（按 `openedAt`）** `[码 receipts.js:25]`。⚠ 稿未定义超限态。规则：列表底部常驻「本机仅保留最近 20 条回执，更早的不在此处」→ R-11。
5. 分桶：`pend = status !== 'included'`（含 signed **与 seen**）、`done = included`、`stale = pastDeadline` 单独透出且**不改分桶** `[码:247-253]`。⚠ `[审]` 稿面「签名中」段只有 1 条 `signed`，`seen` 条目没进该段——**与代码分桶不符**；段名「签名中/已上链」也与代码语义（未上链/已上链）不一致。规则：段名改 `未上链（signed · seen）` / `已上链（included）`，或明确产品有意只把 signed 视作"签名中"并同步改 `receiptBuckets()`。**必择其一，不可各说各话** → R-12。
6. 超期芯片措辞 `[码 receiptChip():256-262]`：`included→included`(felt)；`seen 超期→'seen 超期'`(bad)；`signed 超期→'signed 超期'`(bad)；未超期 seen 用 `ch-play`、signed 用 `ch-amb`。⚠ `[审]` 稿在 `acct(zc)` 最新动态里把 `seen` 写成**裸 chip（无 ch-play）**，receipts 屏却用 `ch-play`——同状态不同色，违反"一个状态一种笔触"。统一按 `receiptChip()`。
7. **ForceInclude 本版本只展示状态、不实现提交**：按钮禁用 + `title="仅展示协议状态，ForceInclude 提交路径未实现"`，不给可点笔触 `[稿:1489, DS-13:947]`。`[码]` 协议侧对象确实存在（`sort_commit_txs_r4m4_with_force_include`、forced 集已进 vertex 载荷、抗审查演练 PASS=8 FAIL=0 `[档 roadmap-schedule.md:62,67]`）——"存在协议路径"不是空话，但钱包侧无提交通道。
8. ⚠ **`[审]` 已知实现缺口**：`inclusionView()` 在 0.6.1 **从不把 `pastDeadline` 置 true** `[码 receipts.js:177]`，因此稿面的"超期"态在现网不可达、无法端到端验证 → R-13。
9. ⚠ `[审]` **回执无 `amount` 字段**（F-06 规则 10）：稿面每条金额需由 `inputs[].amount` 求和推导；`kind` 仅四值，"开桌"无对应 → R-24、R-25。
10. 软锁：`pendingSpendMap()` 提供 note 本地软锁（防双花）`[码 receipts.js:78]`。`[判]` F-06 的 `桌上锁定` 列应由此驱动，而非独立字段。
11. `[审]` 回执 `digest` 为 64-hex `[码 receipts.js]`。稿面 hash 一律带 `0x` 前缀且长度不一（40 / 64 / 68 hex）→ 需统一（§13 C-06）。

**异常处理**：网关重启后回执由 sidecar 可答；`DuplicateReceipt`「回执已存在」`[码:356]`；`seen` 验签失败 → 写 `receipt_unverified_signature` 并保持层级不变。

---

### 4.5 链层通用屏（`send` / `history` / `manage`，稿以 EVM 演示）

#### F-15 发送 · 交易预览（`send`）— P0

1. 金额 + 法币等值 + gas price 三重信息（`≈ $840.12 · gas price 12 gwei`）`[稿:1514]`。法币等值受 R-01 约束（无价格源 → `—`）。
2. 预览卡：`from` / `to` / `value` / `gas limit` / `预估手续费 0.000252 ETH` / `chainId 1 校验通过`。
   ✅ **`[审]` 这是稿面最漂亮的一处自洽，且有真实算法**：`evmPrepareAndDraft()` 并发 `Promise.all([eth_getTransactionCount, eth_gasPrice, eth_estimateGas])`，gasLimit 下限 `21000n`，**`maxFee = gasPrice × gasLimit`** `[码 service_worker.js]` → `21,000 × 12 gwei = 252,000 gwei = 0.000252 ETH`。**要求写成硬规则：预览中任何派生金额，必须能由同屏已展示的输入项推出**（账簿的"可复核"纪律）。`[码]` 预览返回 `valueWei/valueHuman/nonce/gasPriceGwei/gasLimit/maxFeeWei/maxFeeHuman/balanceHuman` 八字段，稿面字段可全部对上 ✅。
3. ⚠ `[审]` `gas limit 21,000` 是**下限**（`max(estimate, 21000)`）`[码]`，稿写成定值；且把 `EIP-155` 标在 gas limit 行——**EIP-155 是链 ID 签名编码，与 gas limit 无关**。规则：`EIP-155` 挂到 `chainId` 行，gas limit 行标「估算值，下限 21,000」→ R-34。
4. 不可撤销警示：「发送后不可撤销，请核对地址与金额；chainId 不符时交易将被拒绝签名」`[稿:1528]` ✅ 有实现（二次独立 chainId 校验）。
5. MAX 说明「已填入最大可用（**预留 gas**）」`[稿:1512]` —— 与 ZChain 层 MAX（网关代付、无需预留）不同，**费用模型差异必须在文案上体现**。规则：EVM MAX = `balance − maxFee`（用当前 gasPrice × gasLimit 预留）。
6. ⚠ `[审]` 金额展示 `-0.2500`（4 位小数）。代码 `formatUnits(wei, 18)` **截断、不四舍五入、去尾零** `[码 evm/crypto.js:581-588]`，故实际渲染 `0.25`。**展示精度表（U-01）必须与 `formatUnits` 显式调和**：要么新增补零的展示函数，要么接受 `0.25` → R-27。
7. `[判]` **`formatUnits` 截断而非四舍五入是正确选择**（宁可少报不多报），但必须在文档钉为规则，防止后来者"顺手改成 `toFixed()` 四舍五入"导致余额虚高。
8. 交易预览的 `more` 标注 `eth_sendTransaction` `[稿:1520]`。`[判]` 展示 RPC 方法名符合"账簿可复核"叙事，但需确认与实际暴露的方法名一致（`adapters/eip1193.js`）→ 待确认项。

#### F-16 交易记录 · 双边对账（`history`）— P1

1. 「合并 Explorer 数据」开关：本地账本 + Etherscan 兼容 txlist `[稿:1540-1541]`。⚠ **`[审]` 代码事实**：Explorer 侧只取 `account txlist`、`offset=50`，**无 API key 即不请求**，且**没有"合并"开关** `[码 evm/history.js; network_registry.js]`；本地 tx 记录上限 **500 条** `[码]`。`[判]` 稿把内部能力做成了用户可见开关——可保留，但语义必须重定义为「是否使用第三方 Explorer 补充展示」，并**明示启用会把地址发给第三方**（隐私告知义务）→ R-14。
2. **冲突处理规则（P0 纪律）**：「来源用 chip 区分（本地 / explorer）；两者冲突时以链上回执为准，并把差异原样列在详情里，**不做静默合并**」`[稿:1556]`。
3. ✅ 分桶 `all / tx(kind!=='contract') / c(kind==='contract')` 与 `historyBuckets()` 一致（稿：2 条转账 + 2 条合约）`[码:272-279]`。
4. 方向判定 `txDirection()`：`from===self→out`、`to===self→in`、**其余一律 out（保守，不当作收入）** `[码:282-290]`。`[审]` 这条"未知即支出"的保守选择须在文档显式承认，避免被当 bug 修掉。
5. ⚠ `[审]` **示例数据 id 冲突**：`0x51b7…c8` 同时是 ZChain「结算 · 8♠ #128」（+620.50）与 EVM「接收 1.20 ETH」；`0x9a02…ef` 同时是 ZChain「转账 −200.00」与 EVM「swap · 1inch · Failed」；`0x8f3a…c2`（EVM 已发送）与 `0x8f3a91c4…d7e2`（EVM 收款人 / ZChain 收款 owner）前缀相撞。`[判]` 示例数据必须**按链分段命名空间**（evm tx 用 `0xe…`、stk 用 `0x5…`、zc digest 不带 `0x`），否则 QA 交叉核对被误导 → §13 C-05。
6. ✅ `fee $0.85` 在历史行内展示合理（来自落库的 `maxFee` 实付）。
7. `[审]` 稿用 `approve · USDC`、`swap · 1inch` 作为合约类标题。代码无 `approve`/`swap` 解码标签（只有 `kind==='contract'` 分桶）。`[判]` 需补 4byte/selector 解码，或改为中性的「合约调用 · 0x<selector 前 4 字节>」→ R-44。

#### F-17 账户管理 · 危险区（`manage`）— P0

1. 三段分组：**安全**（导出私钥 / 修改口令 / 锁定）· **网络**（RPC 覆盖 / Explorer API 覆盖）· **危险区**（删除账户），段标题用 danger 变体 `[稿:1582-1596]`。
2. 导出私钥：口令确认后展开，**30 秒自动收起** `[稿:1584]`。⚠ `[审]` 代码**未找到 30 秒实现**（D-57）→ 需实现。`[判]` 收起时必须有可见反馈（回到掩码态 + toast）；并警告"剪贴板 / 截屏风险"。
3. ⚠ **`[审]` 修改口令：三层 keystore 各自重派生（两套 KDF）** `[稿:1585]`，但稿与代码均**未定义部分失败时的补偿**。`[判]` 必须二选一：(a) 全部成功才提交，任一失败回滚；(b) 逐层结果明列并要求确认。当前若中途失败会造成三层口令不一致，直接影响 F-04 统一解锁 → **R-35（数据丢失级）**。
4. 锁定 = 「立即清除内存中的会话」`[稿:1586]` ✅ 对应 `mem.session` 失效。
5. 删除账户模态：「该账户的私钥将从本机 keystore **永久移除**。若没有备份，资产无法找回。**此操作与其他两层无关**。」`[稿:1602]`。`[审]` 最后一句是关键的**作用域澄清**，必须保留。危险按钮用**描边朱红**而非实心，以免与主按钮抢权重 `[稿 DS-4]`。
6. 页脚安全声明：「本机 keystore（本层）：PBKDF2-SHA256 600k + AES-256-GCM · 私钥只在后台内存会话，落盘仅密文 · **无云端副本**」`[稿:1597]`。
7. ⚠ `[审]` **删除 ZChain 层的语义与另两层不同**：ZChain 层删除的是 note 库（含 nullifier 索引），删了可能永久无法花费；另两层删的是账户。稿只在 EVM pane 演示删除。`[判]` **ZChain 层的删除必须额外提示 note 库丢失** → 并入 R-35。

---

### 4.6 证明层（方向 B 新增）

#### F-18 证明中心 · 凭证簿（`proofs`）— P0 · v0.2 新增屏

**功能描述**：把方向 A 分散在「回执」与「Portal」两处的事项合并成一条主线：本地凭证簿。

**业务规则**

1. 抬头以 `seal-ok 独立可验` 占据账户头像位 `[稿:1657]`。`[判]` 这一屏的主语是"证明"不是"账户"，用印章占住锚点位置是正确取舍。
2. ⚠ **`[审]` 时间窗口与计数无实现来源**：稿写「最近 24 小时 · 5 份结算证明」，代码写的是 **`最近 ${log.length} 次本地复验`**，**没有时间过滤** `[码 popup.js]`；本地 proof log 上限 **20 条** `[码 proof_archive]`。`[判]` 二者必择一：加 24h 过滤（需新增 `verifiedAt`）或改文案为「最近 5 次本地复验」。且"份结算证明"与"复验次数"不是一回事（同一手牌复验两次是 2 次不是 2 份）→ **R-36**。
3. ✅ 分布「4 份已达 finalized」/「1 份停在 soft」**复算 `4+1=5` 自洽**。
4. ⚠ **`[审]` 「可提现」与 F-10 直接冲突（最高优先修正）。** F-10 规定 `canSubmit` **恒 false**（通道未开放 + `vault_offline`），本屏却把 4 份 finalized 标为「可提现」。**二者不能同时为真。** `[判]` 本屏文案必须改为**「满足提现的凭证条件」**——凭证到位 ≠ 通道开放。**这是全稿最可能被用户读成"我能取钱"的一处** → **R-15**。
5. 阶梯示例 `pending/soft/proven` 完成 + `finalized` 琥珀（cur）= `outcome='wait'` 态 `[码:228-241]` ✅。
6. ⚠ `[审]` 待复验列表第二条「9♣ 桌 #96 · 超期回执 · **可 ForceInclude**」与 F-14 规则 7「不实现提交」矛盾。改为「存在 ForceInclude 协议路径（本版本不可提交）」，且点击跳 Portal 而非跳一个不存在的提交按钮。并入 R-15。
7. ✅ 第一条「8♠ #128 · **seen 未 included**」是诚实标注 seen 与 included 落差的正面例子，保留。
8. 已复验区：`8♠ #127 · verified` + `校验耗时 1.72s(浏览器内 stwo)` ✅（D-54 真实基准）+ `payout_root 0x8c3f…d210`（受 R-16 约束，取不到必须 `—`）。
9. 底部说明（P0 文案）：「阶梯是**凭证**状态（锚定在 note 上）；回执的 signed → seen → included 是**投递**状态」`[稿:1683]`——DS-7 论点在本屏的复述。
10. ✅「验证在本地完成 · 不依赖服务端『已验证』结论」`[稿:1682]` 与代码一致；受 R-32 约束不得暗示链上验证。

---

### 4.7 系统层

#### F-19 设置 · 能力矩阵（`settings`）— P0

**功能描述**：通用偏好、安全与备份、关于，以及**能力矩阵**模态。

**业务规则**

1. **通用段四项**：
   - 自动锁定 `15 min` ✅ `[码 service_worker.js:152]`；说明含「或后台页面被浏览器回收（即 fail-closed）」。
   - 显示测试网：⚠ `[审]` 稿为可切换开关（on），代码侧该项**渲染为只读展示**（`popup.js:1425`）→ 需对齐：要么实现开关（并说明关闭后哪些条目消失），要么改稿为只读 → R-37。
   - 货币计价 `USD`：稿注「仅展示，非托管承诺」✅。⚠ 但在**价格源未接入**的现实下是无效项——代码里设置页该项显示 `未接入` `[码]`。必须显示 `未接入` 而非 `USD`（否则用户以为切换计价单位就能换算法币）→ 并入 R-01。
   - 外观底面（纸白 / 夜场）✅ `setGround()` 实现，持久化在 popup 侧 `[稿:1744-1748]`；代码有纯函数 `nextGround()` `[码 ui_ledger.js:391-393]`。
2. **安全与备份四项**：备份导出 `.zcbk`（仅 ZChain 层 REAL/PLAY 双库 · 备份口令独立）/ 从备份恢复（Argon2id 本地解密）/ 授权簿·会话密钥 / **能力矩阵**。
3. **关于段**：版本 `0.6.1`（✅ `manifest.json version:"0.6.1"`、`minimum_chrome_version:"116"`）、`MV3 · DevNet 形态`、稿 v0.2 对齐此版本、文档与源码。
   ⚠ `[审]` **存在版本漂移**：`service_worker.js` 内 `PROVIDER_VERSION = '0.4.0-alpha'` 与 manifest `0.6.1` 不一致 `[码]`。`[判]` 「关于」页只允许展示 manifest 版本；provider 版本若需展示必须单独标注为"适配器版本" → R-38。
4. **反审计徽章纪律（发布门禁）**：「未通过第三方审计 —『可验证』指密码学与结算证明可被独立复核，**不等于已审计**；本界面不出现任何审计徽章」`[稿:1633]`；品牌合规第 7 条「logo 不与任何『已审计』类徽章组合；本文件不存在此类徽章」`[稿:28]`。`[判]` 此条应作为**发布门禁**（引入徽章 / "audited" / "安全保证"字样即 block），而非普通文案要求。
5. **能力矩阵六条（必须单一数据源）** `[稿:1640-1645]`：

| 层 / 面 | 已具备 | 不具备 / 红线 |
|---|---|---|
| ZChain | GAME 域可签可转 | REAL 仅展示，提现预览 `canSubmit` 恒 false |
| EVM | 转账与合约写入可签名广播（EIP-155 + chainId 校验） | 不签 note spend |
| Starknet | invoke v1 + devnet 水龙头；SNIP-12 授权面已备 | 链上 admission 未开放 |
| 网络 | devnet / testnet 可选 | **ZChain 层 mainnet 刻意不注册 → `NetworkUnsupported`**（⚠ R-26：EVM 层 mainnet 实际已注册） |
| 边界 | — | 盲签拒绝；私钥 / 助记词 / nullifier 不出边界；网关水位原样展示、不推进 |
| 会话 | 三层共用口令 | 会话彼此独立；后台被回收即锁定（fail-closed） |

   ✅ `[审]` 六条与代码 `CAPABILITY_ROWS` 逐条对应，REAL 行实际返回 `{available:true, enabled:false, label:'仅展示', reason:'提现通道未开放（v1 托管模式）'}` `[码 capability_matrix.js]`。**要求：能力矩阵必须由同一份常量渲染，不得在稿、UI、文档各写一份。**
6. `[档]` **合规现状**：`docs/plan-token-economy-compliance-v1.md` **没有回执留存要求**；其控制点是 `Deposit`/`IssueGameToken` 上的 KYC/GEO/age 闸门，以及**版本化 `geo_policy` 哈希进软确认帧以供审计**。`[判]` 本 PRD 界面**不需**为合规增设留存周期 UI；唯一相关的界面义务是水龙头发放纪律（需 GAME 域流通量核对，见 R-22）。
7. `[审]` 界面**不得出现任何"已审计 / 安全保证 / 资金托管承诺"字样**；`[稿 DS-6]` 的 `REAL 金墨` 只允许出现在 REAL 资产与其托管提示上（品牌硬规则 4），也不得被用于任何"担保"语义。

---

### 4.8 浮层与模态

#### F-20 收款 sheet（三链各一）— P0

1. 结构：标题（`收款 · <层> 层`）+ **完整地址（`word-break:break-all` 等宽块）** + 网络/域限定说明 + 复制按钮 `[稿:1232-1261]`。
2. 地址下方一行限定语，**防跨链误转**：ZChain「完整地址 · 点按下方按钮复制」/ EVM「Ethereum · chainId 1」/ Starknet「SN DevNet · ZCDN」`[稿]`。`[判]` 网络标识在收款页为 P0 必需——这是唯一一处"给错地址即永久损失"的场景。
3. ⚠ **`[审]` 三张 sheet 都画了二维码，但 0.6.1 没有二维码编码器，且界面红线明令禁止画假码。** 代码事实：`recvSheet()` **不画 QR**，展示 banner `二维码未接入` `[码 popup.js]`；`extension/README.md:160`「二维码编码器未接入 → 收款只给完整地址 + 复制，**不画假码**」；稿件的 `qr-art` 是**手写的 29 格 SVG 版式数据、不是任何地址的编码**（DS-12 亦注明它是精灵中唯一的非图标例外 `[稿:893]`）。
   **需求判定（P0 · 发布门禁级）**：本屏必须渲染为「完整地址块 + 复制按钮 + 说明『二维码编码未接入』」，**禁止展示任何伪码图形**。理由：用户会拿手机去扫一个不编码任何东西的图案 → **R-17**。
4. `[判]` **待保留约束**：「二维码卡必须保持白底（夜场底色下亦然），保证扫码器可用」`[稿 DS-11:865]` 仅在二维码实现后生效，本文登记为未来约束，当前不得据此画假码。
5. ⚠ **`[审]` 三张 sheet 的完整地址缩略方式各不相同**：ZChain `zc1qpoker9xf7x2wwn2h3a5v8…`（尾省略）、EVM `0x59195049a3…29f97527`（首 12 + 尾 8）、Starknet `0x058ff920c8…8b29853f`。**收款页不应缩略**——用户需能逐字核对完整地址。`[判]` **规则：收款页永不截断地址，必须完整可换行展示 + 复制**；稿在 EVM/Starknet sheet 里做了中间省略属缺陷 → **R-39（P0）**。
6. sheet 内必须用事件代理写法（MV3 `script-src 'self'`，禁内联事件）`[码 popup.js:1908]`。

#### F-21 破坏性操作模态（撤销会话密钥 / 删除账户）— P0

| 操作 | 确认方式 | 摩擦级别 | 理由 |
|---|---|---|---|
| 撤销会话密钥 | 键入常量 `REVOKE` 才解禁 | 高 | 粘滞、永久失效、影响后续每次签名 |
| 删除账户 | 输入口令校验 | 中 | 资产永久灭失，但需口令证明"你是你" |
| 打开能力矩阵 | 无确认 | 无 | 只读 |

`[判]` 摩擦分级依据：撤销是**权限收缩**（误点导致后续摩擦），删除是**资产灭失**（需身份校验）。两者都是模态 + 遮罩，确认按钮在条件满足前禁用。
⚠ `[审]` **缺一个必须存在的模态**：修改口令部分失败时的补偿确认（F-17 规则 3 / R-35）。

#### F-22 toast — P0

稿 JS 实测：自动消失 **1900ms** `[稿:1815]`；每个挂载容器内复用单个 `.tst` 节点 `[稿:1810-1813]`；墨底反色细条，不用圆胶囊 `[稿 DS-11]`。
`[判]` 规范：1.9s 对中文短句偏短 → 常规 **2.4s**；**破坏性结果（撤销 / 删除 / 拒签）4s**；错误类 toast 不得自动消失（需可读到底 + 手动关闭）；同一时刻只允许一条，后来者替换前者（不排队，避免重渲染后积压）。

---

## 5. 核心组件规范

### 5.1 凭证条 `.rail`（Proof Rail）— P0 · 方向 B 最核心组件

**语义**：四个方形节点 = `pending → soft → proven → finalized`。唯一规则：**整条链的等级由最弱的一环决定，并且把最弱那一环标出来** `[稿 DS-7]`。

**状态渲染契约（直接采用 `ladderSteps()`，页面不得各写一套）** `[码 ui_ledger.js:216-241]`：

| `outcome` | 含义 | 已到达节点 | **下一格** | 稿面出现位置 |
|---|---|---|---|---|
| `ok` | 达标 | `done`（绿） | 已到顶则无 | DS-7 例 1；zc-send |
| `wait` | 仍在推进（等证明 / 等 finality） | `done` | **`cur`（琥珀）** | 首页最弱凭证；DS-7 例 2；凭证簿 |
| `blocked` | 被卡住（fail-closed，提交入口禁用） | `done` | **`bad`（朱红）** | 提现预览；DS-7 例 3 |
| `idle` | 无数据 | 全空 | 全空 | 空账户 |

✅ **`[审]` 这张表解决了一处稿面看似矛盾的地方**：DS-7 例 2 与首页都把「proven」画成琥珀，而提现预览把「proven」画成朱红——不是画错，是 `wait` 与 `blocked` 两种 outcome。稿未把这层区分写成规则，代码才是权威。**四格笔触在任何页面必须一致。**

**聚合算法** `proofLadder()` `[码:203-214]`：计数各等级 → `spendable !== false` 计入可花费 → `weakest` = 全集合 rank 最低者 → **未知/缺失 proof 一律回落 `'pending'`**（不猜、不把 null 当 0）→ 空集合 `weakest = null`（渲染 `idle`，**不显示"全部达标"**）。

⚠ **词汇双轨风险** `[审]`：note 侧枚举 `ProofState{Pending, Soft, Proven, Finalized}` `[码 note_store.rs:38-52]` 与 verifier 侧 `FinalityLevel{Local, Soft, Proven, Finalized}`（`.name()` 返回 `"local"`）`[码 verifier.rs:51-72]` **第一格不同名**。UI 的 `PROOF_LADDER[0]='pending'` 对齐 note 侧 ✅（正确选择），但从 verifier 路径回来的值若为 `"local"`，`PROOF_LADDER.includes('local')` 为 false → **静默回落 pending，等级信息丢失** → **R-18**（须统一到单一常量 + §6.4 `proof_ladder_mismatch` 埋点监测）。

### 5.2 印章 `.seal`（方向 B 独有语义）

`本地已验证` / `模拟预览` / `通道未开放` / `已创建` / `已验证` / `verified`。旋转 −4°（角落章 `+6°`）、1.5px 方框、等宽大字距 `[稿 DS-3]`。
`[判]` **用途限定：印章只用于"结论性判定"，普通状态用 chip。** 它取代方向 A 的发光与色彩强调（品牌纪律：不用描边字 / 发光字 `[稿:23]`）。

### 5.3 fail-closed 按钮

禁用态 = `opacity:.42` + `border:1px dashed` + 灰底灰字 `[稿:202]`。**虚线是"不能点"的专用笔触**，让不可用在形状上可读而非只靠透明度 `[稿 DS-4]`。这是提现页"原因消除前提交入口保持禁用"的视觉落点 `[稿:1343]`。

### 5.4 两套状态机的笔触隔离

| 维度 | 凭证阶梯 | 回执投递 |
|---|---|---|
| 词汇 | pending → soft → proven → finalized | signed → seen → included |
| 语义 | 资产能用到什么程度 | 网关见到没有 |
| 渲染 | 方形节点 + 连接线 | 等宽小写**原词不翻译** `[稿 DS-6:718]` |
| 禁止 | 用同一种 chip 表达两者 `[码:224-226]` | 同上 |

`[判]` **原词不翻译是刻意的**：这些词是链上/网关返回的协议词汇，翻译会让用户无法与 explorer / RPC 输出对照，破坏"可复核"。所以 `proven` / `finalized` / `verified` / `signed` 在稿中一律保持英文 ✅。

### 5.5 提示条的五种优先级 `[稿 DS-10]`

| 变体 | 语义 | 强制出现位置 |
|---|---|---|
| `bn-real`（金条） | 托管警示 | 一切 REAL 区块（品牌硬规则 4） |
| `bn-ok`（绿条） | 验证通过 | Portal 成功、验证类结论 |
| `bn-bad`（朱红条） | 不可撤销 / 未审计 | 发送确认页、设置关于段 |
| `bn-info`（蓝条） | 性能与范围如实标注 | Portal 耗时、备份覆盖范围 |
| `bn-amb`（琥珀条） | 层级 / 锁定中间态 | Starknet 本层已锁定 |

`[判]` 用左侧 3px 色条而非整圈描边——扫一眼即可分优先级；托管警示（金）与失败警示（朱红）是两种不同形状的语言，不会互相冒充 `[稿 DS-10]`。

---

## 6. 数据需求

### 6.1 数据模型（界面视角）

```
Wallet
 ├─ KeystoreEnvelope（三层独立；同一解锁口令喂给两套 KDF）
 │   ├─ ZChain 层：Argon2id + ChaCha20-Poly1305
 │   └─ EVM / Starknet 层：PBKDF2-SHA256(600k) + AES-256-GCM
 ├─ AccountLayer（zc|evm|stk；解锁态独立；AUTO_LOCK_MS=900_000；mem.session={uuid,expiresAt}）
 │   ├─ zc：NoteStore（REAL/PLAY 物理分库；ProofState 单调推进）
 │   │    ├─ REAL 域(domain=1)：NATIVE | USDT(未接入) | USDC(未接入)
 │   │    │    Note { commitment(hex32), amount:u64·字符串传递, proof, spendable,
 │   │    │           source_op_index, custody_risk_notice }
 │   │    └─ GAME 域(domain=2)：PLAY(legacy)+GTS；outstanding=Σmint−Σburn（≠用户余额）
 │   ├─ evm：chainState { chainId, nonce, gasPriceGwei, gasLimit, maxFee, assets[ETH+erc20占位] }
 │   └─ stk：chainState { chainId:'ZCDN', nonce, maxFee, tokenSymbol='DST',
 │                         udc(公式推导), strkScanKey(掩码 ********) }
 ├─ Receipt { digest(64hex), kind∈transfer|buy_in|settle|withdraw, chainId, signedAtMs,
 │            deadlineMs=10_000, status∈INCLUSION_LADDER, seenAtMs, includedAtMs,
 │            inputs[{commitment,amount}], evidence, openedAt, seenTxHash }  ← 无 amount；容量 20
 ├─ SessionBinding { origin, delegated, scope[play|buyin|bet|settle], perTxLimit, perDayLimit,
 │                   dailyUsedToday, tableAllowlist(非负整数[]), expiresAt, status(6值),
 │                   evidence:'devnet_local_entry' }  ← 上限 16；日窗 UTC/86400
 ├─ SettlementSummary { pot, rake_amount, share, payout_root(展示待确认), engine:'stwo', verified_ms }
 └─ Preview { amount, owner(33B 压缩公钥 hex66), notes[], change, outputs[], totalIn,
              spendableTotal, weakest, required, reached, covered, reasons[], canSubmit,
              fee{paidBy:'gateway',amount:'0'}, operation(与签名摘要同源) }
```

**模型层三条硬约束（决定全部界面形态）**：① note **全额消费**，无部分花费；② **Σoutputs = Σinputs 守恒**；③ REAL 与 GAME **物理分库**，跨域永不轧差。

**时长常量总表**（⚠ `[审]` 七处 TTL 各不相同，必须在文档钉死以免混用）：

| 常量 | 值 | 用途 | 出处 |
|---|---|---|---|
| `AUTO_LOCK_MS` | 900,000（15 min） | 无操作自动锁定 | `[码 service_worker.js:152]` |
| `LIMITS.pendingTtlMs` | 120,000（2 min） | dapp 签名请求超时 | `[码 validation.js:99]` |
| `EVM_DRAFT_TTL_MS` / `STK_DRAFT_TTL_MS` | 60,000（1 min） | 链层交易草稿 TTL | `[码 service_worker.js]` |
| `transfer_preview.ttlSec` | 300（5 min） | ZChain 选币预览 TTL | `[码 transfer_preview.js]` |
| `DEFAULT_INCLUSION_DEADLINE_MS` | 10,000（10 s） | 回执包含期限（ForceInclude 触发线） | `[码 receipts.js:19]` |
| `PAGE_TIMEOUT_MS` | 45,000 | 页面请求超时 | `[码 service_worker.js]` |
| `DEFAULT_FETCH_TIMEOUT_MS` | 15,000 | Portal 网关取数超时 | `[码 explorer_gateway/api.rs]` |
| toast 驻留 | 1,900（稿）→ 建议 2,400 | 提示消失 | `[稿:1815]` |

**数量上限总表**（⚠ `[审]` 稿面所有列表都远未触及上限，必须补齐超限设计）：

| 上限 | 值 | 超限行为（本文规定） |
|---|---|---|
| 单条交易输入 / 输出 note 数 | 16 `[码 validation.js:97-98]` | `canSubmit=false` + 原因文案 |
| 回执条数 | 20（丢最旧）`[码 receipts.js:25]` | 列表底部常驻说明 |
| 会话绑定数 | 16 `[码 sessions.js]` | 新建禁用 + 原因文案 |
| 本地 tx 记录 | 500 `[码]` | 分页 / 说明保留窗口 |
| proof log | 20 `[码 proof_archive]` | 「最近 N 次」文案（R-36） |
| 金额 | u64（≤20 位十进制）`[码 validation.js:104]` | `AmountOverflow` |
| origin / requestId / sessionId | 256 / 128 / 128 `[码:93-95]` | `InvalidArgument` |
| 区块终态 | ~3 s（三层信任分层共用）`[档 37-10]` | 界面不得写"N 个确认" |
| 网关限流 | 10 req/s、burst 20、256 并发 `[档]` | 429 → 退避重试文案 |

### 6.2 「每一个数字的数据来源」溯源表

标记：✅ 有真实来源且稿面自洽 · ⚠ 有来源但稿面值不一致 · ❌ 稿面值无实现来源（硬编码示例） · 🔒 常量（非查询结果）

#### A. 账户与标识

| id | 稿面值 | 数据来源 | 状态 |
|---|---|---|---|
| D-01 | 「3 账户层 / 2 套 KDF / STARK」 | 产品形态宣告，与 `CAPABILITY_ROWS` 同源 `[码 capability_matrix.js]` | 🔒 |
| D-02 | 账户名「牌手一号」+ 头像「A」 | 本地可改账户标签（重命名入口在 manage） | ⚠ 稿无来源字段 |
| D-03 | `zc1qpoker…f7x2` / `zc1qpoker9xf7x2wwn2h3a5v8…` | **无实现来源。** 全仓库仅出现在两处演示数据：设计稿本身与 `wallet-app/mobile/www/js/data.js:10`。代码侧 owner 是 **33 字节压缩公钥（66 hex，无 0x）** `[码 transfer_preview.js; validation.js]`；**不存在 bech32 `zc1q` 编码器** | ❌ **R-19** |
| D-04 | `0x5919…7527` / `0x59195049a3…29f97527` | EVM 地址派生（keccak + EIP-55 校验和 `[码 evm/crypto.js:6]`）；值为示例 | ✅ 来源真实 |
| D-05 | `0x058f…853f`；`UDC 0x41a7…8e02` | Starknet 账户地址；UDC 由部署公式推导 | ✅ 稿已标「公式推导」 |
| D-06 | 口令 `felt-poker-verifiable-9x2a` | 一键创建的自动生成口令（4 段 / ≤24 字节形态） | ⚠ 需核对生成器规则 |
| D-07 | 已解锁 `2 / 3` | `isUnlocked()`/`evmUnlocked()`/`stkUnlocked()` 独立判定 `[码:2705-2712]` | ✅ |
| D-08 | 链切换器计数 `2 / 1 / 1` | **口径未定义**（ZChain 3 条含未接入 → 2；EVM 2 条 → 1） | ⚠ 推断"有值条目数"，需钉死 |

#### B. 余额与金额

| id | 稿面值 | 数据来源 | 状态 |
|---|---|---|---|
| D-09 | `PLAY 12,400.00` | GAME 域 `spendable=true` note 的 `Σamount`（BigInt，字符串传递） | ✅ 来源真实 / ⚠ R-22 |
| D-10 | `桌上锁定 0.00` | `play_locked` / `real_locked` `[码 assets.js]`；软锁来自 `pendingSpendMap()` `[码 receipts.js:78]` | ✅ |
| D-11 | `NATIVE 10,000.00` | REAL 域 NATIVE 列（v1 只有 NATIVE 有值）`[码 assets.js:5-6,112]` | ✅ |
| D-12 | `USDT / USDC → —` + `未接入` | 硬编码 `{connected:false, free:null, locked:null}` `[码 assets.js:134]` | ✅ **稿与代码完全一致的正面样板** |
| D-13 | `≈ $22,288.63`（三链总资产） | **无价格源**（`PRICE_SOURCE_CONNECTED=false`、`fiatOf` 恒 null；现网渲染 `—` + `价格源未接入`）；且 `10,120+8,124.69+4,043.42=22,288.11`（差 **$0.52** → 手写字面量）；另违反跨域禁轧差 | ❌ **R-01** |
| D-14 | `REAL 托管 $10,120.00` | 无来源；隐含 NATIVE 单价 **$1.012** 无任何出处 | ❌ R-01 |
| D-15 | `EVM ≈ $8,124.69`（2.4183 ETH） | 隐含 ETH 价 **$3,359.67** | ⚠ 三价不一致（C-02） |
| D-16 | `Starknet ≈ $4,043.42`（1.2034） | 隐含 ETH 价 **$3,360.00**（精确） | ⚠ 同上 + **符号应为 DST**（R-19） |
| D-17 | `0.25 ETH ≈ $840.12` | 隐含 ETH 价 **$3,360.48** | ⚠ 同上 |
| D-18 | `ETH 2.4183` / `1.2034` / `10.0000` | `eth_getBalance` / Starknet balance → `formatUnits(wei,18)`，**截断、不四舍五入、去尾零** `[码 evm/crypto.js:581-588]` | ✅ 来源真实 / ⚠ 尾零冲突（R-27） |
| D-19 | `USDC 320.00`（erc-20 · eth_call 读取） | 理论来源 `presentDecoded`+`decimalsByType` `[码 evm/contracts.js:107-126]`；**账簿页当前是静态 `—` 占位** `[码 popup.js]` | ❌ 该页无实现（R-04） |
| D-20 | `-0.2500` / `+1.2000` / `+88.00` / `+620.50` | tx `value` → `formatUnits`。⚠ **回执无 `amount` 字段**；`+88.00`/`+620.50` 含非零小数，无法作为 note 金额存储 | ⚠ R-24 + U-01 |

#### C. 费用与 gas

| id | 稿面值 | 数据来源 | 状态 |
|---|---|---|---|
| D-21 | `gas 12 gwei` | `eth_gasPrice` → `formatUnits(gp,9)` → `gasPriceGwei` → `fmtAmount(x)+' gwei'` `[码 rpc.js:82; popup.js:1411]` | ✅ 值示例 |
| D-22 | `偏低`（gas chip） | **无来源**：未定义基准值 / 分位算法 | ❌ R-05 |
| D-23 | `gas limit 21,000（EIP-155）` | `max(eth_estimateGas, 21000n)` `[码 service_worker.js]`。⚠ EIP-155 是**链 ID 签名编码**，与 gas limit 无关 | ✅ 数值真实 / ⚠ 标注错位 R-34 |
| D-24 | `预估手续费 0.000252 ETH ≈ $0.85` | **`maxFee = gasPrice × gasLimit`**：`21,000 × 12 gwei = 0.000252 ETH`；`× $3,360 = $0.8467 → $0.85` | ✅ **全稿最佳自洽样板（算法可回溯）** |
| D-25 | `maxFee 0.00042`（Starknet） | `chainState.maxFee` `[码 popup.js:1429]` | ✅ 值示例 |
| D-26 | `网络费：网关代付 免费`（ZChain） | `fee:{paidBy:'gateway', amount:'0', label:'网关代付'}` `[码 transfer_preview.js]` | ✅ **精确一致** |
| D-27 | `fee $0.85`（历史记录行） | 同 D-24 落库后的实付值 | ✅ |
| D-28 | `0.000252` 与 `21,000`/`12 gwei` 的关系 | 用户可在同屏自行验算 | ✅ 可复核 |

#### D. 网络与链参数

| id | 稿面值 | 数据来源 | 状态 |
|---|---|---|---|
| D-29 | EVM `nonce 42` | `eth_getTransactionCount(addr, tag)` `[码 evm/rpc.js:78]` | ✅ 值示例 |
| D-30 | Starknet `nonce 7` | 链上 nonce 查询 `[码 stark/*]` | ✅ 值示例 |
| D-31 | `chainId 1 校验通过` | `eth_chainId` 与注册表比对 + **签名前二次独立验证（不符拒签）** `[码 capability_matrix.js:65]` | ✅ |
| D-32 | `chainId ZCDN 校验通过` | Starknet devnet 网络表 `[码 stark/networks.js]` | ✅ |
| D-33 | `zchain-devnet-1` / `Ethereum` / `SN DevNet` | `CHAIN` 映射 `[稿:1721-1725]`；ZChain 仅 devnet（网关 `http://127.0.0.1:18900`）+ testnet（`gatewayUrl:null`）；**`zchain-mainnet-1` 刻意未注册** | 🔒 ✅ |
| D-34 | 「mainnet 刻意不注册」（能力矩阵） | **仅 ZChain 层成立**；EVM 注册表**含 Ethereum `0x1` / Sepolia / Base / Arbitrum / evm-devnet `0x7a69`** `[码 service_worker.js]` | ❌ 表述过宽 **R-26** |
| D-35 | `USDC · erc-20 · eth_call 读取` | 理论来源存在 `[码 evm/contracts.js]`；账簿页未接线 | ❌ R-04 |
| D-36 | `approve · USDC` / `swap · 1inch` 标题 | 代码仅 `kind==='contract'` 分桶，无 selector 解码 | ❌ R-44 |

#### E. 选币与凭证

| id | 稿面值 | 数据来源 | 状态 |
|---|---|---|---|
| D-37 | 转账选币 `300.00 + 200.00 = 500.00`，找零 `0.00` | `selectNotes()` BigInt 降序贪心，commitment 破平 `[码 transfer_preview.js:60]` | ✅ **复算通过** |
| D-38 | 提现选币 `1,000+2,500+1,500 = 5,000.00`，找零 `0.00` | 同上 | ✅ **复算通过** |
| D-39 | 单条输入上限 `16` | `LIMITS.maxInputs/maxOutputs = 16`，超限 `InvalidParams` `[码 validation.js:97]` | 🔒 **稿未展示超限态** |
| D-40 | 「GAME 域要求 proven」 | `GAME_MIN_PROOF='proven'`；**devnet 实为 `soft`** `[码 transfer_preview.js:26-38]` | ⚠ 稿在 devnet 展示 testnet 门槛 |
| D-41 | 「所需证明 finalized」（提现） | `WITHDRAW_MIN_PROOF = REAL_MIN_PROOF = 'finalized'` `[码 withdraw_preview.js:22]` | ✅ |
| D-42 | 最弱凭证 = `soft`（1 张） | `proofLadder().weakest`；等级实由**网关水位**（`frame_index ≤ watermark → proven`，否则 `soft_accepted`）`[码 api.rs:159-163]` | ✅ |
| D-43 | `canSubmit=false`（提现恒 false） | 展示门 ∧ finality 合取；`show_claim` 需 `vault_online && verifier_ready && bft_finality_ready` `[码 display.rs:55-73]` | 🔒 ✅ |
| D-44 | 「模拟预览」/「通道未开放」 | `claim_disabled_reason='vault_offline'`、`custody notice='real_is_custodial_v1_offline'` `[码 display.rs]` | ✅ |
| D-45 | `batch_root` / `batch_index`（隐含于 `Proven`） | `ProofState::Proven{batch_root, batch_index}` `[码 note_store.rs]`；**稿未展示** | ⚠ 可证锚点缺失 |

#### F. 时间

| id | 稿面值 | 数据来源 | 状态 |
|---|---|---|---|
| D-46 | 签名请求 `120 秒` / 抬头 `1:52` | `LIMITS.pendingTtlMs = 120_000` → `remainText()` `[码 validation.js:99]` | ✅ **真实常量，非编造** |
| D-47 | `92s 后过期` | 应经 `remainText()` → **`1:32`** | ⚠ 格式违规 |
| D-48 | 回执超期 `deadline 10s` | `DEFAULT_INCLUSION_DEADLINE_MS=10_000`；协议侧 `force_include.rs:61` 同值 `[码 receipts.js:19]` | ✅ |
| D-49 | 自动锁定 `15 分钟` | `AUTO_LOCK_MS = 15*60*1000` `[码 service_worker.js:152]` | ✅ |
| D-50 | `刚刚` / `2 分钟前` / `1 小时前` / `3 天前` / `5 天前` | `relTime(ts,now)` 分段 `[码 ui_ledger.js:150-163]` | ✅ |
| D-51 | `昨天` | **`relTime()` 无此输出**：24h–30d 走 `N 天前`，≥30d 走 ISO | ⚠ 格式违规 |
| D-52 | `剩 6 天 12 小时` | `validityRemain()` 的 `剩 ${d} 天 ${h} 小时` `[码:179-188]` | ✅ **模板逐字一致** |
| D-53 | `有效期 7 天`（新建默认） | 代码默认 `validitySec = 86_400`（**1 天**），最大 365 天 `[码 sessions.js]` | ⚠ 非默认值且未标注 |
| D-54 | `校验耗时 1.72s` / 「约 1.7s」 | 宿主墙钟；实测 p50 1.70–1.80s、p95 1.98s `[码 stwo-wasm-path-a.md:5,135]` | ✅ **真实基准** |
| D-55 | `500ms 交互预算` | 验收门槛，超约 3.5× 已由决策接受并要求如实标注 `[码 同:6,204]` | 🔒 ✅ |
| D-56 | toast `1900ms` | 稿 JS `setTimeout(…,1900)` `[稿:1815]` | 🔒 |
| D-57 | 导出私钥 `30 秒自动收起` | 稿约定；**代码未找到实现** | ❌ 需实现 |
| D-58 | 「日累计」的重置点 | `Math.floor(nowSec/86_400)` = **UTC 日** `[码 sessions.js]` | ⚠ 界面未说明 R-31 |

#### G. 限额与风控

| id | 稿面值 | 数据来源 | 状态 |
|---|---|---|---|
| D-59 | 单笔 `≤ 1,000 PLAY` | `SessionBinding.perTxLimit`（十进制字符串）`[码 sessions.js]` | ✅ 值示例 |
| D-60 | 日累计 `2,150 / 5,000` → **43%** | `sessionUsage()`：`Math.min(100, Number((u*100n)/l))` = `2150*100/5000 = 43` | ✅ **整数向下取整，与 meter width:43% 精确一致** |
| D-61 | `5,000 / 5,000 已耗尽` → 100% amber | `exhausted: u >= l` `[码:302]` | ✅ |
| D-62 | 无日限 → 不画进度条 + `不限` | `limit==null → {percent:null, limitText:'不限'}` `[码:296-298]` | ✅ 稿未演示该态 |
| D-63 | 桌白名单 `8♠ · 9♣(2 桌)` | `tableAllowlist` = **非负整数数组** `[码 sessions.js]` | ⚠ 装饰性符号不可提交 |
| D-64 | `table_id #A3F2` | 代码 `table_id` 渲染为**数字** `[码]` | ❌ R-25 |
| D-65 | scope 三项 | 代码**四项** `['play','buyin','bet','settle']` `[码 sessions.js]` | ❌ **R-30** |
| D-66 | 会话状态 `活跃` / `已耗尽` | `SESSION_STATUS_CHIP` 6 值枚举 `[码:305-316]` | ✅ |
| D-67 | 会话数 / origin 数 | `MAX_SESSION_BINDINGS=16`；稿未演示满态 | 🔒 |

#### H. 结算与证明

| id | 稿面值 | 数据来源 | 状态 |
|---|---|---|---|
| D-68 | `底池 1,240.00 PLAY` | 网关结算明细 `GET /api/v1/settlement/{binding}` `[码 api.rs:54]` | ✅ 值示例 |
| D-69 | `rake 24.80 PLAY（2%）` | `24.80 = 1240 × 0.02` ✅ 复算通过；`rake_matches_plan` 是复验项之一 `[码 portal.js]`。⚠ 代码 `rake` 渲染为**金额**非百分比 | ⚠ 数学对 / ❌ 形态 R-28 |
| D-70 | `我方份额 +620.50 PLAY` | 结算分配输出 | ⚠ **小数无法作为 note 金额存储**（U-01） |
| D-71 | `payout_root 0x8c3f…d210` | 复验含 `payout_root_recomputed` `[码 portal.js]`；是否回传 UI 展示未确认 | ⚠ R-16 |
| D-72 | `网关 127.0.0.1:18900 · 200 OK` | 本地网关配置；host_permissions 仅 `localhost`/`127.0.0.1` `[码 manifest.json]` | ✅ **端口精确一致** |
| D-73 | `payload 84.2 KB` | 证明文件响应体字节数 / 1024 | ⚠ **未设大小上限** R-20 |
| D-74 | `engine stwo` | 证明引擎标识；`STARK_FIELDS` 含 `engine` `[码 popup.js]` | ✅ |
| D-75 | `最近 24 小时 · 5 份`（4+1） | 代码是 `最近 N 次本地复验`，**无时间过滤**；log 上限 20 `[码]` | ❌ 窗口虚构 R-36 / ✅ 4+1 算术自洽 |
| D-76 | `已验证` 印章 | `stark.ok ∧ verdict==='verified'` 合取 `[码]`；**不授予** proven/finalized（`verify_settlement` 恒返回 `FinalityLevel::Soft`）`[码 verifier.rs:97]` | ✅ 有来源 / ⚠ 语义必须限定 R-15 |
| D-77 | 回执列表容量 | `MAX_RECEIPTS = 20`（丢最旧）`[码 receipts.js:25]` | 🔒 稿未定义超限 |
| D-78 | 备份格式 `ZCBK v1`（REAL/PLAY 双库） | 备份信封版本；`UnsupportedVersion`「只升不降」`[码:353]` | 🔒 ✅ |
| D-79 | KDF 参数 `PBKDF2-SHA256 600k` / `Argon2id` | keystore 实现常量 | 🔒 ✅ |
| D-80 | `0.6.1` / `MV3` / 稿 `v0.2` / `v1.3` | `manifest.json version:"0.6.1"`、`minimum_chrome_version:"116"` `[码]` | 🔒 ✅ |
| D-81 | `PROVIDER_VERSION 0.4.0-alpha`（未在稿面展示） | 与 manifest 漂移 `[码 service_worker.js]` | ⚠ R-38 |

#### I. 设计系统类数字（非产品数据，但需登记来源）

| id | 稿面值 | 来源 | 状态 |
|---|---|---|---|
| D-82 | 对比度表 16.61 / 8.16 / 5.45 / 5.28 … | 声称「本次 node 计算」`[稿 DS-1]` | ⚠ 未随仓库提交可复算脚本 R-21 |
| D-83 | `ink-3` 由 `#6b675c`(4.49) 压深到 `#666256`(4.85) | 自检发现 <4.5 后修正 `[稿:564]` | ✅ 有过程记录 |
| D-84 | 「2,349 个节点逐元素取色 · 0 项不达标」 | 自检口径声明 `[稿:565]` | ⚠ **无法由稿面数字复算**（C-07），需提交脚本 |
| D-85 | 「纵向容量比方向 A 多约 25%」 | 设计比较结论 `[稿 DS-8]` | ⚠ 无可复现测量 |
| D-86 | `380×600` / 圆角 `3·6` / 账格 `26px` / 印章 `−4°` / `1.6 stroke` / `38 枚图标` | 设计 token；38 枚 symbol 可数（`qr-art` 为唯一例外） | 🔒 ✅ **复算通过** |
| D-87 | 「19 屏 = 18 对照 + 1 新增」/ 17 个模板 | `SCREENS` 19 条、`<template>` 17 个，`t-acct` 复用为 3 屏 | ✅ **复算通过** |

#### U-01 · 单位与精度口径（必须先裁决，否则 D-18/D-20/D-69/D-70 全部悬空）

`[审]` 现状是**三套精度并存且互相矛盾**：

| 层 | 存储单位 | 校验 | 稿面渲染 |
|---|---|---|---|
| ZChain note（PLAY/NATIVE） | u64 **整数**，无 decimals 概念 | `/^[0-9]+$/` 拒绝任何小数 `[码 withdraw_preview.js:41]`；「PLAY 为整数筹码，不支持小数」`[码 transfer_preview.js:55]` | 补 2 位小数（`12,400.00`） |
| EVM / Starknet | wei（18 decimals） | `formatUnits(wei,18)` **截断 + 去尾零** `[码 evm/crypto.js:581-588]` | 补 4 位小数（`-0.2500`） |
| 法币等值 | — | **无（价格源未接入）** | 补 2 位小数（`$8,124.69`） |
| `fmtAmount` | — | **保留原始小数位，明确不补齐、不四舍五入** `[码 ui_ledger.js:121-132]` | 与上三行全部冲突 |

**裁决要求**：明确「显示精度 ≠ 存储精度」。建议统一为**展示层固定小数位表**（PLAY/NATIVE 2 位、原生 ETH 4 位、ERC-20 按 `decimals`、法币 2 位），且**禁止把展示小数当作可输入精度**。稿面的 `+620.50`、`+88.00`、`24.80` 作为 note 金额**永远非法**，示例数据需重做 → **R-27**。

### 6.3 格式化口径（全 UI 单一实现）

**规则：以下函数是唯一出口，任何页面不得本地拼装。** `[码 ui_ledger.js]`

| 场景 | 函数 | 契约 | 稿面违规点 `[审]` |
|---|---|---|---|
| 金额分组 | `fmtAmount(v)` | 千分位 + **保留原始小数位**（不补齐、不四舍五入、不造精度）；非十进制原样回落 | 稿把 `0.25` 显示为 `0.2500`、`12400` 显示为 `12,400.00`（补零），与"不补齐"冲突 |
| 收支符号 | `fmtSigned(v,{positive,negative})` | 正值加 `+` | ✅ 一致 |
| 地址/哈希缩略 | `shortAddr(a, head=10, tail=6)` | 首 10 + `…` + 尾 6；短于 `head+tail+1` 原样返回；空值 `—` | **稿存在 ≥4 种缩略**：行内 `0x5919…7527`(6/4)、sheet `0x59195049a3…29f97527`(12/8)、note `77b1…04dd`(4/4)、tx `0xc41d…9b`(6/2)。且 `zc1qpoker…f7x2`(9/4) 无法用该函数表达。**收款页规则另定：永不截断（R-39）** |
| 相对时间 | `relTime(ts,now)` | 刚刚 / N 秒前 / N 分钟前 / N 小时前 / N 天前 / `YYYY-MM-DD` | 稿出现 `昨天`（非法输出） |
| 倒计时 | `remainText(msLeft)` | `已过期`(<0) / `Ns`(<60) / `m:ss`(<1h) / `Nh Mm` | 稿出现 `92s 后过期`（应 `1:32`） |
| 有效期 | `validityRemain(sec)` | `剩 N 天 M 小时` / `剩 N 小时` / `剩 N 分钟` / `已过期` | ✅ 逐字一致 |
| 百分比 | `sessionUsage().percent` | 整数向下取整，封顶 100；无上限 → `null` | ✅ 43% 一致 |
| 凭证阶梯 | `ladderSteps()` | 四态 done/cur/bad/空（见 §5.1） | ⚠ outcome 未在稿中区分 |
| 回执芯片 | `receiptChip()` | 含 `seen 超期`/`signed 超期` 变体 | ⚠ 同状态不同色 |
| 链上交易芯片 | `txStatusChip()` | 成功 / 失败 / 已回退 / **待确认** | ⚠ 稿用 `pending` |
| 错误文案 | `errorText(err)` | `ERROR_TEXT[code]` + `reason`，截断 200 字符，**未知码原样透出 code 不吞**（共 ~35 码） | ⚠ 稿仅覆盖少数码 |
| 哈希不换行 | `.hashline` + 横向滚动 | 哈希/地址/金额**永不折断** `[稿:22]` | ⚠ DS-2 示例 hash 只有 40 hex（应 64） |

`[判]` 缩略规则的推荐落法（需评审确认）：同一字段类型在**全应用内固定一组参数**——地址 `(10,6)`、tx hash `(10,6)`、note commitment `(8,6)`；**同一屏内不同字段若参数不同，必须靠 label 而非靠长度差异让用户区分**。

### 6.4 数据埋点

`[判]` 设计稿与代码均**未实现任何埋点**。以下为本 PRD 新增需求，全部走本地聚合 + 用户可关闭，且**禁止采集私钥、助记词、nullifier、完整地址（只采首尾哈希）、口令痕迹**（能力矩阵红线 `[稿:1644]`）。

| 事件名 | 触发条件 | 关键属性 | 用途 |
|---|---|---|---|
| `popup_open` | popup 渲染完成 | unlockedLayers(0-3), ground(paper/night) | 会话量、双底色使用比 |
| `screen_view` | 屏幕渲染 | screenId, chain, tab | 屏幕热度；验证"链=筛选器"是否真的减少跳转 |
| `chain_switch` | 账簿切换器点击 | fromChain, toChain | 验证筛选器模型 vs 目的地模型 |
| `layer_unlock` | 统一解锁结果 | succeeded[3], failed[3], reason | 2/3 中间态出现率 |
| `amount_gate_hit` | MAX 填入 | layer, available, notesNeeded | 选币压力 |
| `note_select_result` | 预览重算完成 | noteCount, hasChange, weakest, required, canSubmit, blockedReasons[] | **核心：哪种原因最常卡住提交** |
| `note_count_over_limit` | 贪心结果 >16 | noteCount | 验证 R-06 超限设计是否够用 |
| `withdraw_preview_view` | 进入提现预览 | amount, reasons[], canSubmit | 预期恒 false，用于回归监控 |
| `withdraw_submit_attempt_blocked` | 提交按钮被点到（防御性） | reasons[] | 应为 0；>0 说明禁用态表达失败 |
| `sign_request_resolved` | 签名请求关闭 | decision(approve/reject/expire), via(session_key/password), originHash, amount | 免口令命中率 |
| `session_key_exhausted` | 限额耗尽触发 | originHash, kind(perTx/daily) | 限额设置合理性 |
| `session_key_revoke` | 撤销完成 | originHash, confirmTyped(bool) | 粘滞操作的可理解性 |
| `proof_rail_view` | 凭证条渲染 | weakest, required, outcome, position | 一等组件的曝光位分布 |
| `proof_ladder_mismatch` | note proof 不在 `PROOF_LADDER` 内 | rawValue | **监测 R-18 词汇漂移**（静默回落 pending） |
| `portal_verify_start` | 点「验证这一手牌」 | bindingPrefix(8), from | 复验漏斗顶部 |
| `portal_verify_step` | 每步结束 | step(1-4), ok, ms, payloadKB, engine, gatewayStatus | 定位失败步骤；**监控 payloadKB 上限风险 R-20** |
| `portal_verify_result` | 全流程结束 | verdict(verified/partial/failed), totalMs, overBudget, payoutRootPresent | 完成率；监控 R-16 |
| `receipt_state_change` | signed→seen→included 推进 | digestHash, from, to, pastDeadline, evidence | 投递时延；`evidence` 验证 R-33 |
| `receipt_past_deadline_view` | 超期态曝光 | count | ForceInclude 需求强度（现网恒 0，见 R-13） |
| `receipt_capacity_hit` | 回执数达 20 | – | 验证 R-11 说明是否必要 |
| `copy_action` | 任意复制按钮 | fieldKind(password/address/txid), layer | 口令复制占比（评估 R-08） |
| `qr_view_attempt` | 打开收款 sheet | layer, qrRendered(false) | **量化 R-17 影响面** |
| `fiat_unavailable_view` | 总额块渲染为 `—` | – | R-01 修复后验证 |
| `backup_export` / `backup_restore_result` | 备份流 | ok, code, coversLayers(1) | 备份可用性 |
| `danger_action_confirm` | 危险区确认弹窗关闭 | action, confirmed, frictionPassed | 摩擦设计有效性 |
| `rekey_partial_failure` | 修改口令部分层失败 | failedLayers[] | **R-35 的唯一可见信号，必须实现** |
| `error_shown` | 任意错误呈现 | code, screenId | **~35 码命中率**；发现无文案兜底码 |
| `ground_switch` | 纸白/夜场切换 | to | 双底色真实需求度 |
| `settings_change` | 任一设置项变更 | key, from, to | 使用面 |

---

## 7. 过渡动画与动效规范

> ⚠ **`[审]` 设计稿在动效上是空白的**：全文件只有 5 条 `transition`、**0 个 `@keyframes`**、**0 处 `prefers-reduced-motion`**，而浮层、模态、toast、屏幕切换的开合全部是 `display:none ↔ block` 瞬时切换。同一组 5 条 transition 已在 `extension/popup/popup.css` 与 `wallet-app/mobile/www/css/app.css` 逐字落地（三处一致），因此**界面目前的事实是"只有 hover/focus 微反馈，没有任何状态转场"**。本章为补齐内容。
>
> 现存动画清单（唯一来源，`[稿 CSS]` `[码 popup.css:67,77,134,274]`）：
> `body{transition:background .2s,color .2s}`（换底）、`input:focus{border-color .15s,box-shadow .15s}`、`.btn{filter .12s,background .12s}`、`.sw2::after{left .15s,background .15s}`（方形滑块位移 18px）、`.shot .clip{transform .12s,border-color .12s}`（稿的画廊卡片 hover，属外壳不属产品）。

### 7.1 总则（六条硬约束）

**A-1 诚实性优先于顺滑。** 动效不得用于制造"已经好了"的错觉。这条在稿中有对应的产品纪律：「性能如实标注，约 1.7s，不伪装即时」`[稿 DS-10/DS-13]`。
**推论**：① 禁止用 > 实际耗时的装饰性 spinner 掩盖进度；② 禁止在步骤未真的完成时先播放完成动画（尤其 Portal 步骤 3→4 的"已验证"印章，见 F-13 规则 2）；③ 禁止"骨架屏 + 随机延迟"营造的流畅感。

**A-2 禁止 scroll-driven 动画。** 品牌合规第 6 条硬规则：「不做 scroll-driven 动画（整页截图会停在 opacity:0）」`[稿:27]`。这条同时服务于设计资产出图（`#shot=1` 无头截图模式 `[稿:97-98]`）与可访问性。**任何依赖滚动位置的 opacity/transform 动画都是违规。**

**A-3 时长预算。** 交互预算为 **500ms** `[码 docs/stwo-wasm-path-a.md:204]`。**规范**：任何"用户动作 → 界面响应"的动画总时长 ≤ 200ms；超出 200ms 的必须伴随**真实进度信息**（步骤态 / 耗时读数），不得只是等待。

**A-4 必须与"整体重渲染"共存（本应用特有，最关键的一条）。** 0.6.1 是 MV3 popup，`script-src 'self'` → **无内联脚本 / 无内联事件**，一切点击走 `data-*` + 单一事件委托，且**状态变化会整体重渲染屏幕 DOM**，浮层开合与表单草稿需跨渲染保持（`rt.ovl` / `rt.form`）`[码 extension/README.md:167-168]`。`[判]` 这决定了动效的实现策略：
- **不得**依赖元素跨状态持续存在来做 CSS 过渡——重渲染替换节点会打断过渡；
- 进入动画必须通过**渲染后一次性 class**（`data-anim="enter"` + `animation`）实现；
- **首版不依赖 `@starting-style` / View Transitions API**——`minimum_chrome_version` 为 116 `[码 manifest.json]`，`@starting-style` 需 Chrome 117+；若要用必须先提升最低版本，属独立决策；
- 禁用 Web Animations API 的长链编排（每次重渲染都要重建），优先声明式 `@keyframes`；
- 关闭动画期间不得提前销毁遮罩节点（否则 `rt.ovl` 与视觉不一致）。

**A-5 尊重 `prefers-reduced-motion: reduce`。** 现状完全缺失 `[审]`。**规范**：开启减弱动效时，所有 `transition-duration` 与 `animation-duration` 降为 `0.01ms`，但**保留状态变化的可读反馈**（印章、chip 配色、虚线禁用态不变）；旋转/平移动画一律停为静态；**倒计时与凭证阶梯的状态更新不得被隐藏**——它们是信息，不是装饰。

**A-6 禁止动画的语义域（不可动效化的内容）。** 以下四类**永不加动画**，因为它们承担"这是事实"的职责 `[判]`：① 托管警示条与 `通道未开放` / `模拟预览` 印章（闪烁会削弱严肃性）；② 数字的最终值（不做"数字滚动增长"——滚动过程会短暂显示错误金额，违背账簿纪律）；③ 哈希 / 地址（任何动效不得使其位移或折断）；④ 能力矩阵正文。

### 7.2 逐场景动效表

缓动词汇：`std` = `cubic-bezier(.2,0,.38,1)`（进入/常规）；`out` = `cubic-bezier(0,0,.3,1)`（离场）；`seal` = `cubic-bezier(.34,1.3,.64,1)`（轻微过冲，**仅用于印章**，幅度 ≤1.06）。

| # | 场景 | 触发 | 属性 | 时长 | 缓动 | 设计理由 |
|---|---|---|---|---|---|---|
| T-01 | **底色切换** 纸白 ↔ 夜场 | `setGround()` / 设置项 | `background`、`color`（全 token 一次换皮） | 200ms | std | **已有实现** `[稿:68]`。屏幕代码不含硬编码色值，切底色即换皮 `[稿 DS-1]`；200ms 让"同一体系两张皮"被感知为一个动作而非两次刷新 |
| T-02 | **tab 切换 / 屏幕导航** | `data-nav` | 新屏 `opacity 0→1` + `translateY(4px→0)`；旧屏立即隐藏 | 140ms / 0ms | std | 账簿要"翻页感"但不要"滑动感"：横向滑动暗示目的地（链=目的地模型，正是方向 B 要消灭的 `[稿 DS-0]`），淡入只表达"内容已换"。单向不做双向位移以规避重渲染冲突（A-4） |
| T-03 | **链切换（账簿内）** | `data-cs` | 切换器反色块 `background`；数据面淡入；**抬头 kind/net/addr 不动** | 各 120ms | std | 比 T-02 更快——链切换是筛选而非导航，**快 = "这只是过滤条件"**。抬头不动是因为它承载身份，跳动会被读成"账户变了" |
| T-04 | **收款 sheet 上滑** | `data-open` | 遮罩 `opacity 0→1`；面板 `translateY(100%→0)` | 遮罩 160ms / 面板 220ms（错开 40ms） | std | 底部 sheet 必须位移才不突兀；遮罩先起可避免面板压在旧内容上读起来像"贴上去的纸条" |
| T-05 | sheet / modal 关闭 | 遮罩 / `data-close` | 反向 | 160ms | `out` | **离场一律比进入快（约 0.7×）**，减少"等界面"的主观时长 |
| T-06 | **破坏性模态出现** | `data-open`（`mdl-del` / `mdl-cap` / REVOKE） | 遮罩淡入 140ms；卡片 `scale(.96→1)` + 淡入 180ms；随后**焦点落到确认输入框** | 140+180ms | std | 模态比 sheet 更"重"，用 scale 而非 translate 表达"从界面中浮出、必须处理"。**禁用过冲**（`seal` 不用于危险动作）——愉悦感会削弱风险信号 `[判]` |
| T-07 | **模态确认按钮解禁** | 键入 `REVOKE` / 口令匹配 | 虚线禁用态 → 实线可用：`border-style`、`opacity .42→1` | 120ms | std | 让用户"看到门槛被跨过"。虚线→实线是本设计系统的专用语义 `[稿 DS-4]`，动画只是让转换可读 |
| T-08 | **toast 进 / 出** | `data-toast` | `opacity 0→1` + `translateY(6px→0)`；驻留 2400ms（稿 1900ms）；淡出 200ms | 进 140 / 出 200ms | std / out | ⚠ **稿中 toast 完全无动画**（`display:none↔flex`）`[审]`。**必须补**：无淡出的 toast 会"凭空消失"，在窄屏 popup 里极易被误认为界面 bug |
| T-09 | **凭证条状态推进** | note proof 变化 | 节点 `background` 160ms；连接线 `scaleX(0→1)`（`transform-origin:left`）由左向右 | 节点 160ms；线 240ms，**逐格错开 60ms** | std | 阶梯的语义就是**单向推进**，所以动画只能从左向右生长；**回退时不做动画**（直接重绘）——避免用户把"降级"读成正常的来回摆动 `[判]`。若 `outcome` 由 `wait`→`blocked`，节点琥珀变朱红 + **单次** `scale(1→1.06→1)` 300ms 提示，不循环 |
| T-10 | **印章落下** | `已验证` / `已创建` / `本地已验证` 结论成立 | `opacity 0→1` + `rotate(-8°→−4°)` + `scale(1.08→1)` | 260ms（**必须在验证真正返回之后**，不得提前） | `seal` | 方向 B 的状态强调手段是印章 `[稿 DS-3]`。**"盖章"这个物理动作自带"结论不可撤回"的含义**，比绿勾更适合一个审计产品。旋转角从 −8° 收敛到静态的 −4°，让印章像是被手盖上去后停住 |
| T-11 | **倒计时** | 签名请求页 / 待办行 | 每秒**仅替换文本**，不做过渡 | – | – | 秒级跳动本身就是反馈；加动画会与"时间真实流逝"竞争注意力。**归零时**整个请求容器 `opacity 1→0` 300ms 后关闭，让超时可被察觉（A-6④ 例外：这是过程不是结论） |
| T-12 | **限额进度条** | `sessionUsage().percent` 变化 | `width` 过渡 + 颜色（绿→琥珀在 ≥80% 时切换） | 240ms | std | 账簿里"额度用掉多少"是连续量，跳变会让用户怀疑数据是否算错；颜色切换**不做动画**（A-6：语义切换要瞬时确定） |
| T-13 | **勾选 / 开关** | `.cb`、`.sw2` | 复选框反色 `background,color` 120ms；开关滑块 `left` 150ms（18px 位移） | 120 / 150ms | std | 开关 150ms **已有实现** `[稿:319]`。复选框是反色填墨，120ms 让它读作"落章"而非"淡入" |
| T-14 | **按钮按压** | `:active` | `filter: brightness(.92)` | 0ms（即时） | – | **已有实现** `[稿:193]`。**故意不给 active 加过渡**：按下必须瞬时反馈，加过渡会让人怀疑没点到 |
| T-15 | **输入框聚焦** | `:focus` | `border-color` 150ms + `box-shadow` 2px 外环 150ms | 150ms | std | **已有实现** `[稿:72]`。外环同时是键盘导航焦点环，**不得移除**（无障碍必需） |
| T-16 | **表单错误抖动** | `AmountInvalid` / `OwnerInvalid` 等字段级错误 | `translateX(±2px)` 两次，幅度 ≤4px | 240ms | std | 唯一允许的"警告性"动效。⚠ **禁止用于后端拒绝**（`InsufficientFunds` 等）——那是事实陈述不是操作失误，应显示错误条 `[判]` |
| T-17 | **列表项删除** | 删除会话记录 / 回执 | `opacity 1→0` + `height` 收拢 | 200ms | `out` | 收拢而非直接消失，避免"后面的行自己跳上来"被误读为数据被替换 |
| T-18 | **Portal 步骤推进** | 步骤 n 完成 → n+1 开始 | 已完成步图标 `background` 反色 160ms；进行中步图标 `transform: rotate` **无限循环** 1.2s linear | 160ms / 循环 | std / linear | **循环旋转是"仍在运行"的诚实信号**，与 T-19 联动；步骤间不做花哨转场。⚠ 循环动画必须在**请求真正结束时**立即停止，不得播完一整圈 `[判]` |
| T-19 | **长任务进度（>500ms）** | Portal 步骤 3（stwo wasm ~1.7s） | 无进度百分比可给（wasm 同步阻塞），**只给耗时读数**：`运行中… 1.2s` 每 100ms 递增 | 读数更新 100ms | – | 稿明确要求"进度如实展示，不伪装即时" `[稿 DS-10]`。**这是本设计唯一一处无法给百分比的长任务**，因此必须用"已耗时读数"替代进度条——进度条若无真实分母就是撒谎 `[判]` |
| T-20 | **加载骨架** | 余额 / 列表首次取数 | `background` 微幅脉冲（`--pg-2 ↔ --cd-2`），**不加位移** | 1.1s 循环 | – | 不用 shimmer 斜扫：`[稿:23]` 品牌纪律禁发光/渐变强调，shimmer 本质是扫光。脉冲是这套体系里唯一合法的等待语言 |
| T-21 | **hover 反馈** | 行 / 按钮 / 图标按钮 | `background`、`border-color` 变化 | 120ms | std | 已在 CSS 中。**注意触屏无 hover**：所有仅靠 hover 提供的信息必须在常态可见（`[判]` 稿面 `title` 属性的 ForceInclude 说明即违反此条，需改为常显文案） |
| T-22 | **锁定瞬间** | 自动锁定 / 手动锁定 | **不加动画**，直接渲染 `lock` 屏 | 0ms | – | 与 fail-closed 语义一致：安全状态切换不该有过渡期。淡入会制造"还能操作一下"的错觉 `[判]` |

### 7.3 禁止清单（评审时逐条对照）

| 禁止 | 理由 |
|---|---|
| scroll-driven / 滚动位置相关动画 | 品牌硬规则 6；无头出图会停在 `opacity:0` `[稿:27]` |
| 数字滚动增长（count-up） | 中间帧显示错误金额，违背账簿纪律（A-6②） |
| 任何 `text-shadow` / 发光 / 渐变强调 | 品牌硬规则 3；方向 B 强调只用颜色与字重 `[稿:23]` |
| 用动画掩盖 1.7s 验证耗时 | 直接违反 F-13 规则 3 与已达成决策 `[档]` |
| 未验签 / 未实现的能力配"可点"笔触 | `[稿 DS-13:947]`「不给可点笔触」；动画会制造可用性暗示 |
| shimmer 斜扫式骨架屏 | 本质是扫光，违反上一条 |
| 循环动画在请求结束后继续播放 | 会谎报"仍在进行" |
| 把 `已验证` 印章做成入场预置动画 | 结论必须在数据到位后出现（A-1②） |
| 依赖元素持久存在的过渡（重渲染场景） | A-4：节点会被替换，动画不生效 |
| 移除 focus 外环 | 键盘导航必需（T-15） |
| 审计 / 安全类徽章的任何强调动效 | 本界面不存在此类徽章 `[稿:28]` |

### 7.4 性能预算

| 项 | 要求 |
|---|---|
| 动画属性 | 仅 `opacity` / `transform`（合成层）；`width`（T-12 进度条）与 `background`/`border-color`/`color`（状态色）允许，因面积小 |
| 同时运行的动画 | ≤ 3 个元素；重渲染时前一个立即结束，不得排队 |
| 布局抖动 | 动画期间不得触发 `scrollHeight` 变化（避免 380×600 内出现滚动条抖动） |
| 低端机降级 | `prefers-reduced-motion` 为唯一降级开关（A-5），不做设备能力探测 |
| 首屏 | 首屏加载不得有任何入场动画阻塞首帧（稿本身要求：整页截图必须能停在最终态） |

---

## 8. 产品设计理由（决策记录）

> 本章回答"为什么这样设计"。格式：决策 → 理由 → 代价（承认可付出的成本）。

**D-01 为什么把钱包做成"账簿"而不是"牌桌"。**
产品的真实差异点不是牌桌——牌桌是竞品都有的——而是**结算可证** `[稿 DS-0]`。方向 A 卖情绪（上桌），方向 B 卖事实（对账）。界面叙事必须与真实差异点对齐，否则营销说的和用的是两件事。
**代价**：放弃了夜间氛围带来的"好玩"第一印象；纸白底在娱乐场景里显得克制。这正是稿坚持做双底色（纸白 / 夜场一键切换，夜场底逐字复用 media-kit 原色 `[稿 DS-1]`）的原因——**让品牌方不必二选一，只需选体系** `[稿:31]`。

**D-02 为什么把 finality 从二级页提为一等组件。**
"可证"是这个产品唯一不可复制的资产，若它只存在于提现页的一行和回执的一枚 chip，用户永远不会主动去发现，差异化等于不存在 `[稿 DS-0/DS-7]`。凭证条出现在总账、转账预览、提现预览、凭证簿四处，共用 `ladderSteps` 语义 `[码 extension/README.md:156-158]`。
**代价**：首页与凭证簿多占约 90px 纵向空间——在已有 13 屏需要滚动的基准上（R-40）这是昂贵的位置。因此首页凭证条必须保持单行、说明压缩到一句。

**D-03 为什么"链 = 筛选器"而不是"链 = 目的地"。**
底部 4 tab（首页 + 三条链）会让首页和三链页讲同一件事，且链被误认为四个独立的地方；更重要的是三套模板直接造成 `popup.js` 的复制粘贴 `[稿 DS-0]`。改成 3 tab + 一个账簿模板 × 三数据面后，屏幕注册表用 `shared:true` 表达复用 `[码 ui_ledger.js:39-58]`。
**代价**：EVM/Starknet 各自的特异能力（水龙头、合约读写、RPC 覆盖）被压进同一个模板，只能靠 pane 内容差异表达，不能靠导航差异表达；且 `contract` 屏因此一度在稿里退化为一个 toast（R-02）。

**D-04 为什么数字全部右对齐 + 等宽 + 保留原始小数位。**
账簿的对齐纪律是"小数点必须能竖着读" `[稿 DS-0/DS-2]`。右对齐成列后，用户可以把一列数纵向加总并对上合计——**这个动作本身就是"可审计"的日常练习**。`tabular-nums` 让同列数字等宽。
**代价 / 暴露的问题**：稿面合计加不平（§6.2 D-13，差 $0.52），恰好说明这条纪律的价值——它让手写示例数据的错误立刻可见。同时"不补齐小数位"（`fmtAmount` 契约）与稿的补零呈现直接冲突（U-01），**这是审美选择必须让位于可验证性的地方**。

**D-05 为什么用方形 chip 与印章，不用胶囊与发光。**
胶囊 pill 与发光是营销徽章的语言；方形 chip + 等宽大字距是"印刷票据上的分类戳" `[稿 DS-0]`。品牌纪律禁止描边字与发光字 `[稿:23]`，所以状态强调只能换一种手段——印章。
**代价**：印章的 −4° 旋转在小尺寸下可读性低于水平文字，因此稿限定它只出现在大字号结论位，并另设 `ch-xs` 小号 chip 承载普通状态。

**D-06 为什么 REAL 用金墨、PLAY 用蓝墨、且不允许混用。**
`[稿 DS-6]`：REAL 金墨只允许出现在 REAL 资产与其托管提示（media-kit 硬规则 4：金色不用于非 REAL 强调）；PLAY 蓝墨只标测试/娱乐筹码；动作绿只标"已达成"的状态。
**理由的实质**：三种颜色对应三种**资产性质**（托管债权 / 无价值筹码 / 状态达成）。一旦混用，颜色就不再是可信的信息通道，整套"限制说明作视觉锚点"的设计就会失效。**这是为什么 R-19（Starknet 把 DST 显示成 ETH）也是同一族问题**：符号撒谎会让用户按错误的资产性质决策。

**D-07 为什么用虚线表达禁用而不是只降透明度。**
`[稿 DS-4]`：让"不能点"在**形状**上就可读。透明度是弱信号（且与 `opacity:.5` 的"未接入资产行"语义撞车），虚线是独立通道。
**代价**：虚线框在视觉上像"草稿"，可能被读成"未完成"而非"被禁止"——因此 F-10 要求虚线按钮旁必须配 `fail-closed` 文字说明。

**D-08 为什么设置项里放"能力矩阵"这种对用户没用的东西。**
`[稿 DS-13]`：不为好看放宽说明。能力矩阵把"哪些是真能做的、哪些是刻意不做的"一次性摊开，服务的是**信任建立**与**审计可查**两类需求，不是操作效率。
**代价**：占用设置页一个入口与一个模态。但它是全界面对"我们做不到什么"的唯一集中陈述处，收益是长期信任。

**D-09 为什么撤销会话密钥要键入 `REVOKE`，而删除账户只需口令。**
两者风险性质不同 `[判]`：撤销是**权限收缩**（后果是可恢复的、影响体验而非资产，但会造成后续每次签名都要口令），删除是**资产永久灭失**（不可恢复，但需要证明"你是你"）。
所以摩擦来源不同——前者用"键入常量"制造"我在做一个不可逆决定"的意识，后者用"口令"做身份校验。**摩擦不是为了挡人，是为了让正确的信息被读到。**

**D-10 为什么收款用底部 sheet 而破坏性操作用模态。**
`[稿 DS-11]`：收款是**给出去的信息**（低风险、需停留展示），sheet 可留在页面上下文里；破坏性操作是**必须做决定的中断**，模态 + 遮罩强制处理。
**代价**：sheet 不挡全屏，用户可能没注意就切走——所以复制按钮必须在 sheet 首屏可见（稿如此 ✅）。

**D-11 为什么协议状态词不翻译。**
`proven` / `finalized` / `signed` / `verified` 保持等宽原词 `[稿 DS-6:718]`。理由：这些词是网关与链上返回的原始值，用户核对时需要在 explorer / RPC 响应里搜到同一个词；翻译成"已证实/已定稿"会断开这条核对路径，而"可复核"正是产品承诺。
**代价**：普通用户不懂这些英文词。缓解方案是配套的行内说明（`短板：1 张 note 仅 soft`、`凭证阶梯说明`）与 `?` 提示，而不是替换原词。

**D-12 为什么"已解锁 2 / 3"这种中间态要显式暴露。**
三层 keystore 独立、解锁态独立 `[码 service_worker.js:2705-2712]`，2/3 是真实状态。把它藏起来（只显示"已解锁"）会导致用户在 Starknet 上点"发送"才被拦截，产生"为什么突然要口令"的困惑。
**代价**：增加了首页的信息量与用户的认知负担。**但隐藏真实的复杂度不是好设计，是把复杂度推到出错的那一刻。**

**D-13 为什么不做"一键全部解锁"以外的智能解锁（如按当前层解锁）。**
`[判]` 三层共用一个口令是既成产品约束（DS-13 明载"同一口令喂给两套 KDF"）。按层解锁会把口令管理复杂度乘以 3，而收益只是省一次失败提示。统一解锁 + 逐层结果反馈是更诚实也更简单的组合。

**D-14 为什么"1.7 秒"必须写在界面上。**
`docs/stwo-wasm-path-a.md` 的记录显示这是一个被明确接受的决策：**性能不敏感，超 500ms 也可交付，但必须如实展示真实耗时** `[档:34]`。`[判]` 把 1.7s 写成文案（而非优化到 500ms 内）是把"慢"从缺陷转化为"这件事本来就需要真算一遍"的证据——对一个卖"可证"的产品，**慢一点但真的算了，比秒出但你说不出算了什么更有价值**。这也决定了 T-19 用"已耗时读数"而不是假进度条。

**D-15 为什么稿选择"保留全部限制文案 + 用印章突出"而不是精简。**
`[稿 DS-13]`「这套钱包的资产数字有一部分不是可自由动用的钱」。方向 B 不但保留限制说明，还用印章把它做成视觉锚点——「模拟预览」「通道未开放」应该像盖在单据上的红章一样显眼。
`[判]` 这是本文档最重要的产品立场：**在这个产品里，限制说明不是界面噪音，而是核心内容。** 也因此 §13 中所有"稿面比实现更乐观"的问题都属于必须修的高危项。

---

## 9. 非功能需求

| 类别 | 要求 | 验收标准 |
|---|---|---|
| **对比度** | 全部正文/说明组合 ≥ 4.5:1；语义色在两种底色下均达标 `[稿 DS-1]` | 13 组配对最低 5.28:1；最紧一对 `ink-3/pg-2` 已按自检压深至 4.85；剩余 <4.5 的仅禁用按钮与占位符（WCAG 1.4.3 对非活动控件豁免）`[稿:564]`。⚠ 自检脚本需随仓库提交（R-21） |
| **字体** | **零 webfont**（品牌硬规则 1）`[稿:21]` | 只用 `system-ui` 栈 + `ui-monospace`；全文件无 `@font-face` |
| **数字排印** | 哈希/地址/金额一律等宽、`tabular-nums`、**永不换行折断**（横向滚动）`[稿:22]` | 横向溢出 0；`word-break:break-all` 容器内不得出现中文（稿自检口径 `[稿:565]`） |
| **可访问性** | 语义角色与键盘可达 | 开关有 `role="switch"` + `aria-checked` 且随状态更新 `[稿:1617; JS:1853]`；`<svg aria-hidden>`；屏幕有 `aria-label`；focus 外环不得移除（T-15） |
| **减弱动效** | 遵循 `prefers-reduced-motion`（A-5） | 开启后所有时长 ≤0.01ms；阶梯与倒计时仍更新 |
| **容器基线** | 380×600 Chrome popup；Chrome ≥ 116 | `minimum_chrome_version:"116"` `[码 manifest.json]`；13 屏需滚动的首屏完整性按 R-40 验收 |
| **内容安全策略** | MV3 `script-src 'self'`：**无内联脚本 / 无内联事件** `[码 extension/README.md:167]` | 全部交互经 `data-*` + 单一事件委托；动画经 class 而非 JS 驱动（A-4） |
| **权限最小化** | 仅 `storage` + `alarms`；host 权限仅 `localhost` / `127.0.0.1` `[码 manifest.json]` | 不得申请 `tabs` / `<all_urls>`；任何外部数据请求需在能力矩阵中可见 |
| **数据出域** | 私钥 / 助记词 / nullifier / 口令不出边界 `[稿:1644]` | 口令不离开设备（备份本地解密 `[稿:1038]`）；无云端副本（manage 页脚 `[稿:1597]`）；埋点禁采项见 §6.4 |
| **内存与会话** | 私钥只在后台内存会话，落盘仅密文 `[稿:1597]` | 锁定即清除 `mem.session`；`AUTO_LOCK_MS` 到期自动失效；popup 关闭不留明文 |
| **fail-closed 可用性** | 任何不确定一律拒绝，不放行、不猜测 | 未知 proof → `pending`；未知枚举 → 原样透出；`chainOf` 未知 → null；`txDirection` 未知 → out |
| **不可变性承诺** | REAL 提现永不提交；链上验证永不声称 `[稿 DS-13]` | `canSubmit` 恒 false 需有回归测试；`zk_verify` Stub 状态下不得出现"链上已验证"（R-32） |
| **降级** | 单数据源失败不污染其他层 | 某层 `—` 不影响其余两层；能力矩阵常驻可查；「关于」页永远可达 |
| **可测试性** | 全部业务判断为可单测的纯函数 `[码 extension/README.md:161-163]` | `ui_ledger` 19 例 / `transfer_preview` 17 例；本文新增需求（超限态、partial 态）须同步补测试 |
| **国际化** | 本版仅 `zh-CN`；协议词保持英文原词（§8 D-11） | 英文原词不得被翻译；错误码原文可搜；文案集中于 `ERROR_TEXT` 单表 |

---

## 10. 验收标准

| 编号 | 场景 | Given（前提） | When（操作） | Then（预期结果） |
|---|---|---|---|---|
| AC-01 | 无价格源不得显示法币 | `PRICE_SOURCE_CONNECTED=false` | 打开 `home` | 总额块显示 `—` + chip `价格源未接入`；**DOM 中不存在任何 `$` 字符** |
| AC-02 | 跨域金额不轧差 | ZChain 层有 PLAY 与 NATIVE | 查看总账/账簿任何合计位 | 不存在 `PLAY + NATIVE` 的和；两列永不相加 |
| AC-03 | 收款不画假码 | 二维码编码器未接入 | 打开三层任一收款 sheet | 显示完整地址（**不截断**）+ 复制按钮 + `二维码未接入`；**无 `<svg>` 码图元素** |
| AC-04 | 合计必须加得平 | 三层金额任一有值 | 渲染总额 | 合计 === 求和函数结果；误差为 0（非字面量） |
| AC-05 | 单一价格快照 | 价格源已接入 | 同一次渲染跨屏比较 | ETH 在 home/acct/send 的隐含单价完全相同（同一 `updatedAt`） |
| AC-06 | 提现入口恒禁用 | 任意 REAL 余额、任意凭证等级 | 打开 `zc-withdraw` | 提交按钮 `disabled` + 虚线笔触；**不存在任何使其解禁的代码路径** |
| AC-07 | 原因逐条不合并 | `cannotSubmitReasons = []` 非空 | 渲染提现预览 | 原因按条列表展示；不出现"暂不可用"合并句 |
| AC-08 | 策略型原因不得暗示可开放 | 原因含"通道未开放" | 阅读原因列表 | 该行含"本版本不会开放"限定语；不出现"即将开放/敬请期待" |
| AC-09 | 凭证短板聚合 | note 集合含 1 张 soft、其余 proven | 渲染凭证条（首页） | `weakest=soft`；`outcome=wait` 时第三格（proven）为琥珀 cur；线只推进到 soft |
| AC-10 | outcome 区分 wait/blocked | 同一 `weakest=soft`；提现页 `canSubmit=false` | 分别渲染首页与提现页 | 首页第三格 = cur（琥珀）；提现页第三格 = bad（朱红） |
| AC-11 | 未知 proof 不猜测 | note.proof = `"local"` 或 `null` | `proofLadder()` 聚合 | 计入 `pending`；`total` 计数正确；**上报 `proof_ladder_mismatch`**（AC 兼测 R-18） |
| AC-12 | 空集合不显示"全部达标" | note 集合为空 | 渲染凭证条 | 四格全空（idle）；`weakest=null`；无"已达标"文案 |
| AC-13 | 两套状态不混用 | 存在 `included` 回执与 `proven` note | 同屏渲染 | 回执用等宽小写原词 chip；凭证用方形节点；无共用同一组件类的情况 |
| AC-14 | 倒计时格式统一 | 剩余 92 秒 | 渲染任意待办/回执行 | 显示 `1:32`（不是 `92s`）；剩余 45 秒时显示 `45s` |
| AC-15 | 相对时间格式统一 | 事件发生于 30 小时前 | 渲染任意列表行 | 显示 `1 天前`（不是 `昨天`）；>30 天显示 `YYYY-MM-DD` |
| AC-16 | 链上交易未知态 | tx status 非 confirmed/failed/reverted | 渲染历史行 | 芯片文案 `待确认`（不是 `pending`） |
| AC-17 | 超期分桶不改属 | 回执 `pastDeadline=true` 且 status=`seen` | 切换到"未上链"段 | 该条出现在未上链段（分桶不因超期改变），且带 `seen 超期` 红色芯片 |
| AC-18 | 金额精度不可输入 | 转账输入框 | 键入 `500.50` | 拒绝并说明「PLAY 为整数筹码，不支持小数」；`500.00` 允许 |
| AC-19 | note 数超限 fail-closed | 需 17 张 note 才能覆盖金额 | 渲染预览 | `canSubmit=false` + 原因含"上限 16"；按钮禁用 |
| AC-20 | 门槛按网络取值 | 当前网络 `zchain-devnet-1` | 渲染转账预览 | 展示 `required=soft`（devnet 策略），文案不写死 proven |
| AC-21 | 后台独立复核 | 手改前端 `canSubmit=true` | 提交转账 | 后台 `verifySpendProofs` 仍拒绝；证明 UI 非安全边界 |
| AC-22 | 预览与签名摘要同源 | 预览展示 `operation` 摘要 | 批准签名 | 实际签名 payload 摘要与预览展示值一致；不符触发 `PreviewMismatch` 并拒签 |
| AC-23 | 已验证不暗示可提现 | Portal 验证成功（`verified`）且存在 soft note | 查看凭证簿 / 提现页 | 凭证簿不显示"可提现"；提现仍禁用；两处独立呈现 |
| AC-24 | 部分验证不得盖章 | 步骤 3 过、步骤 4 未回 | 观察 Portal | 不显示 `已验证`；显示 `partial` + 已完成步骤保留 |
| AC-25 | 耗时如实显示 | 验证耗时 1720ms | 验证结束 | 显示 `1.72s` + 「超预算」标注；无假进度条 |
| AC-26 | 不声称链上验证 | `zk_verify` 为 Stub | 检查全部界面文案 | 无任何"链上已验证 / on-chain verified"字样 |
| AC-27 | 本地登记性质如实 | 回执 `included`，evidence=`local_manual_entry` | 展开该回执 | 显示"本机手工登记，未经链上核对"；绿色芯片不被误释为链上确认 |
| AC-28 | 未验签不推进层级 | `seen` 回执 `seenVerified=false` | 渲染凭证阶梯 | 层级不变；evidence 文案写明"未验签" |
| AC-29 | session scope 与后台一致 | 用户在 UI 勾选全部 scope | 提交登记 | 提交的 scope 值 ∈ `['play','buyin','bet','settle']`；无 `opentable` |
| AC-30 | 桌白名单整数 | 输入 `8♠` | 提交 | 拒绝或要求整数；提交的值是 `8`；展示为 `8 (8♠)` |
| AC-31 | UTC 日窗口 | 本地时区 UTC+8，`2,150/5,000` | 查看日累计 | 页面显示「按 UTC 日重置」；重置点与 `Math.floor(nowSec/86_400)` 一致 |
| AC-32 | 限额不描述为安全保证 | 会话密钥页 | 阅读全部文案 | 含"授权为本机登记，链上不校验；限额由客户端/后台执行"；无"最多只能花 X"式保证 |
| AC-33 | 撤销粘滞性说明 | 打开撤销模态 | 阅读正文 | 含"立即生效、本会话永久失效、后续每次签名需口令"；`REVOKE` 未键入前按钮禁用 |
| AC-34 | 无审计徽章 | 全 19 屏 + 2 模态 | 搜索界面 | 无 `audited`/`审计通过`/盾牌类徽章；logo 不与徽章组合 `[稿:28]` |
| AC-35 | 未审计声明常驻 | 打开设置关于段 | 阅读 | `未通过第三方审计` +「可验证 ≠ 已审计」说明存在 |
| AC-36 | 能力矩阵单一数据源 | 修改 `CAPABILITY_ROWS` 一行 | 重开设置 | 模态内对应行文案随之变化；稿/码/模态三处无分叉 |
| AC-37 | 备份覆盖范围如实 | 打开 `import` 备份 pane | 阅读 | 明写"只覆盖 ZChain 层；不含 EVM/Starknet"；无"完整备份"字样 |
| AC-38 | 口令只显一次 | 已创建成功后再次进入任何屏 | 查找口令 | 除当次 success 页外无处可回显；仅"改口令"或备份路径 |
| AC-39 | 门控不放行 | 未勾选"我已保存" | 点击主按钮 | 按钮保持禁用；不出现自动解禁；不跳过 |
| AC-40 | 三层解锁独立反馈 | Starknet 口令不符、其余两层匹配 | 点"解锁三层" | 显示"2 层已解锁，1 层口令不符"；首页徽标为 2/3；不因部分成功而静默 |
| AC-41 | 链筛选器记忆链 | 当前在 Starknet pane | 进提现页后点返回 | 回到 `acct` 且仍是 Starknet，不重置为 ZChain |
| AC-42 | 未知屏幕不静默回落 | 导航到 `foo` | 触发 `resolveScreen` | 返回 `{error:'UnknownScreen'}`；**不跳转到 home** |
| AC-43 | 网络不可达不伪造 | 网关宕机 | 打开任意屏 | 相关金额为 `—`；显示 `GatewayUnreachable`；不沿用上次数值 |
| AC-44 | 动效不撒谎 | `prefers-reduced-motion: reduce` | 执行任意导航/sheet/印章 | 无位移/旋转动画；印章、chip 配色、虚线禁用态仍可辨；倒计时与阶梯仍更新 |
| AC-45 | 首屏完整性 | 380×600 不滚动 | 逐屏检查 13 张超高屏 | 抬头、主操作按钮、警示条三者均在首屏内（R-40） |
| AC-46 | 格式化单测 | 构造边界值（0、u64 上限、恰好 60 秒、30 天） | 跑 `ui_ledger` 测试 | 输出与 §6.3 契约完全一致；无本地拼装 |
| AC-47 | 测试网符号正确 | 网络为 SN DevNet | 查看 Starknet pane | 显示 `DST`，不显示 `ETH`/`Ξ`（R-19） |
| AC-48 | 凭证簿计数口径 | proof log 有 5 条、跨 30 小时 | 查看凭证簿 | 文案为"最近 5 次本地复验"或已实现的 24h 过滤；与代码口径一致（R-36） |

---

## 11. 排期建议

`[判]` 按"设计语言已定、数据口径已钉、纯逻辑层已落地"的现状拆分。人日为单人口径，含自测不含 QA。

| 阶段 | 内容 | 预估人日 | 依赖 | 风险点 |
|---|---|---|---|---|
| **P0-0 决策收口** | 评审 §13 全部 12 条一致性缺陷 + 44 条风险，裁决 R-01/04/15/17/19/26/27/30/32/39 的方向（修稿 or 改实现） | 3 | 本文档 | 未收口就开工必然返工；R-27（精度）影响所有示例数据 |
| **P0-1 逻辑层补齐** | `ui_ledger.js`：新增展示精度层（补零）、`ladderSteps` 的 `partial` outcome、`requiredProof` 按网络取值、超限判定（note>16 / 回执>20 / 会话>16）、scope 枚举对齐、UTC 日说明字段 | 5 | P0-0 | 改动面在既有测试内（19 例），需同步扩测 |
| **P0-2 上游缺口** | ① 定价源接入或"未接入"落稿；② 二维码编码器；③ 回执 `amount` 与 `tableId` 字段；④ `pastDeadline` 真实置位；⑤ payout_root 回传 | 12（依赖后端 6） | 网关/账本侧 | **关键路径**。①②不做则 R-01/R-17 只能以"稿降级"方式关闭 |
| **P0-3 界面重做（ZChain 主线）** | `home` / `acct`×3 / `zc-send` / `zc-withdraw` / `zc-confirm` / `zc-sessions` / `proofs`，按 `shared` 模板与单数据源改造 | 18 | P0-1 | 重渲染 + 无内联脚本的动效实现（A-4）易踩坑 |
| **P0-4 界面（链层通用）** | `send` / `history` / `manage` / **`contract`（稿缺，需先补设计）** | 10 | P0-3 | `contract` 无稿；EVM/Starknet 差异被压进模板可能不够用 |
| **P0-5 引导与设置** | `welcome` / `success` / `import` / `lock` / `settings` + 能力矩阵模态 | 6 | P0-1 | 三层独立解锁的部分成功呈现 |
| **P1-6 动效落地** | §7.2 全部 T-01…T-22 + `@keyframes` + `prefers-reduced-motion` 全量 | 5 | P0-3 | 与重渲染共存；最低 Chrome 版本限制新 API |
| **P1-7 埋点** | §6.4 全 29 事件 + 本地聚合 + 可关闭开关 | 5 | P0-3 | 禁采项需审计（口令/地址/nullifier） |
| **QA / E2E** | 扩 `tests/e2e/run_08.mjs`（现 30 步）覆盖 AC-01…AC-48；补纯函数边界单测；自检脚本入库（R-21） | 12 | 全部 | 部分 AC 需真实网关/链环境；现网 `partial`/超期态不可达（AC-24/28） |
| **合计** | – | **76 人日**（不含后端 6） | – | – |

**里程碑建议**：P0-0 收口是硬闸门；P0-1 与 P0-2 可并行；P0-2 若判定为"本版本不做"，则 R-01/R-17/R-19 转为**降级文案任务**（工作量从 12 人日降到约 2 人日，但稿面必须相应重出图）。

### 11.1 需补齐设计的清单（稿面为 `示意` 或完全空白）

| 编号 | 缺什么 | 位置 |
|---|---|---|
| R-02 | `contract`（合约读写）屏 | 代码注册表有、稿只有 toast `[稿:1177]` |
| R-06 | note 数 >16 / 预览过期 / 会话 >16 / 无日限 / 单笔超限回落口令 | 五个未演示态 |
| R-11 | 回执 >20 条的说明态 | `zc-receipts` 底部 |
| R-24 | 回执金额与桌标识 | 所有交易行 |
| R-25 | 整数 `table_id` 的展示形态 | `zc-confirm` / 交易行 |
| R-30 | 四项 scope 的勾选布局（稿只有三项） | `zc-sessions` 新建草稿 |
| R-42 | "会话密钥"与"解锁会话"的区分说明 | `zc-sessions` |
| R-44 | 合约调用的可读标题（无 selector 解码时） | `history` |
| R-27 | 各层展示精度表落地后的全部示例数据重做 | 19 屏 |
| R-36 | 凭证簿计数文案与筛选口径 | `proofs` |
| 缺态 | 各层 `—`（无价格源 / RPC 不可达 / 未配置网关）的完整视觉 | 全界面 |
| 缺态 | Starknet `send` 屏 | 稿未画 |
| 缺态 | 键盘导航焦点可见态 | 全界面 |

---

## 12. 风险与依赖

| 编号 | 风险 | 概率 | 影响 | 缓解措施 |
|---|---|---|---|---|
| R-01 | 法币折算无数据源，稿面全部 `$` 数字不可实现（`PRICE_SOURCE_CONNECTED=false`） | **确定** | 高：首页主数字退化为 `—`，"三链总资产"卖点落空 | 二选一并写进发布条件：接入价格源；或首页改为非金额主数字（如凭证达标度）。**禁止前端推算汇率** |
| R-02 | `contract` 屏无设计但代码已注册 | 高 | 中：EVM/Starknet 合约交互无落点 | 先出稿；本版本可显式禁用入口并注明 |
| R-03 | 会话密钥限额是客户端记账，可被清 storage 绕过 | 高 | **高**：界面把限额呈现为安全保证，实际不是 | 文案降级为"本机自助约束"；推动后台/链上独立复核；加 §6.4 埋点监控 |
| R-04 | ERC-20 余额在账簿页只有静态 `—` 占位 | 高 | 中：稿面 `USDC 320.00` 误导实现者以为已有读取路径 | 改标题为"原生币余额"；把 ERC-20 读取并入 `contract` 需求 |
| R-05 | `gas 偏低` 判断词无基准算法（含 R-05b：门槛按网络取值） | 高 | 中：无依据的判断词损害"可复核"承诺 | 定义分位算法或移除 chip；凭证门槛改为数据字段 |
| R-06 | 五个关键边界态无设计（超限/过期/满态/无限制/超单笔） | 高 | 中：实现者按自己理解补，产生不一致 | 本文先给规则（§4.4），P0-0 评审后补稿 |
| R-07 | 提现三条原因同权重，用户误读"等一下就能提" | 中 | 高：直接导致资产误解与客服量 | 策略型原因加"本版本不会开放"限定语 |
| R-08 | 口令一键复制到剪贴板无风险说明 | 中 | 高：剪贴板可被其他扩展读取 | 补警示行；埋点 `copy_action` 统计口令复制占比 |
| R-09 | 私钥输入框无掩码 | 中 | 中：肩窥 / 截屏泄露 | 改 password + 显隐切换 + 失焦掩码 |
| R-10 | 「忘记口令」引导走备份，但备份口令独立、可能一起忘 | 高 | 中：用户被误导到死路 | 文案补"（需备份口令）"；备份口令缺失时给独立出路 |
| R-11 | 回执 20 / 会话 16 / note 16 / tx 500 / proof log 20 上限均无超限设计 | 高 | 中：用户看到"数据凭空消失" | 每处上限配常驻说明（§6.1 总表） |
| R-12 | 回执分桶与段名与 `receiptBuckets()` 不一致 | 高 | 中：埋点与 e2e 结果不可比 | 二者择一并同步；本文档默认采代码口径 |
| R-13 | `inclusionView()` 从不置 `pastDeadline=true`，超期 UI 不可达 | **确定** | 中：超期态无法验收 | 修实现（比较 `seenAtMs + deadline` 与 `now`）；本版本相应把超期文案降为不可达 |
| R-14 | 「合并 Explorer 数据」开关不存在；启用会把地址发给第三方 | 高 | 中：隐私承诺缺位 + 功能虚标 | 重定义开关语义并补隐私告知；无 API key 时如实显示"不可用" |
| R-15 | 「可提现」/「可 ForceInclude」与 `canSubmit` 恒 false 直接冲突 | **确定** | **最高**：用户可能据此做出资金决策 | 立即改文案为"满足提现的凭证条件"；作为发布门禁 |
| R-16 | `payout_root` 不填充，稿面两处展示该 hash | 高 | 中：核心可验证锚点缺失 | 允许 `—`；推动后端回传（已在 verifier 检查项中，缺的是出口） |
| R-17 | 收款页三处伪二维码，违反"不画假码"红线 | **确定** | **最高**：用户会去扫不编码任何内容的图形 | 发布门禁：移除图形 + `二维码未接入`；实现编码器后另案 |
| R-18 | `ProofState::Pending` 与 `FinalityLevel::Local` 词汇双轨，跨层传递静默降级 | 高 | 高：等级信息丢失且无报错 | 单一常量 + `proof_ladder_mismatch` 埋点 + 边界处显式转换 |
| R-19 | ZChain 地址形态（bech32）与 owner 真实类型（33B 压缩公钥）不符；Starknet devnet 显示 ETH 而非 DST | **确定** | 高：地址类型错可能导致转账失败与资产丢失 | 全界面改用真实类型与真实符号；owner 输入校验同步 |
| R-20 | 证明下载无体积上限（稿示例 84.2 KB），DoS / 渲染卡顿风险 | 中 | 中 | `Content-Length` 阈值 + 埋点 `payloadKB` 监控 |
| R-21 | DS-1/DS-8 的自检声明（2,349 节点 / +25% 容量）无随仓库脚本 | 高 | 低：结论不可复核，与产品"可证"立场矛盾 | 自检脚本入库并纳入 CI；或从稿中删除该量化声明 |
| R-22 | GAME 域"用户余额"与"流通供应量"两种聚合易混用 | 中 | 高：账簿页显示供应量会被读成个人资产 | 明确双列标题；`outstanding` 单列且不进个人合计 |
| R-23 | 域编号文档（三域）与代码（两域）不一致 | **确定** | 中：跨团队协作出错 | 同步文档；界面只信 `DOMAIN` 常量 |
| R-24 | 回执无 `amount` 字段，所有交易行金额无来源 | **确定** | 高：账簿主表靠推导或回填 | 后端加字段或由 `inputs[].amount` 求和，并在文档定义 |
| R-25 | `kind` 无"开桌"、无桌号字段；`table_id` 是整数而稿写 hex | **确定** | 中：桌台上下文展示不出来，玩家无法核对是哪一桌 | 加 `tableId`（整数）+ 可选本地别名；kind 需覆盖开桌或改用装饰标签 |
| R-26 | 能力矩阵"mainnet 刻意不注册"表述过宽（EVM 已注册主网） | **确定** | 高：安全边界描述失实，审计不可信 | 改为"ZChain 层 mainnet"；并逐层列举网络可用性 |
| R-27 | 三套精度并存（整数 u64 / wei 去尾零 / 稿补零），`fmtAmount` 明确不补零 | **确定** | 高：示例数据不可生成；实现者困惑 | U-01 裁决 + 展示层新增补零函数 + 稿面数字重做 |
| R-28 | `rake` 是金额还是百分比未定；稿与代码不同 | 高 | 中：费率信息可能完全丢失 | 加 `rake_rate` 字段或改稿为金额 |
| R-29 | 多类标识符（tx/digest/hand_binding/request_id）无前缀区分且示例值互相冲突 | 高 | 中：跨屏核对不可能 | 前缀标签 + 示例数据按链分段命名空间 |
| R-30 | 会话 scope 三项（稿）vs 四项（码），完全不匹配 | **确定** | **高**：授权项提交即失效或错授 | 采代码枚举，UI 重排；补 e2e 断言 |
| R-31 | 日累计按 UTC 日重置，界面未说明 | **确定** | 中：用户提前用满或误判剩余 | 界面标注"按 UTC 日重置" |
| R-32 | 链上 `zk_verify` 是 Stub；任何"链上已验证"表述都是失实 | **确定** | **最高**：把不可验证的东西说成可验证，直接摧毁产品承诺 | 发布门禁；文案限定为"浏览器内 + 本地内核" |
| R-33 | `included` 实为本机手工登记，绿色芯片易被读成链上确认 | **确定** | 高：状态语义失守 | evidence 必须可展开常显；`included` 配说明 |
| R-34 | EIP-155 标注在 gas limit 行（应属 chainId） | 高 | 低：技术表述错误损害专业可信度 | 移到 chainId 行 |
| R-35 | 修改口令部分失败的补偿行为未定义 | 中 | **高**：三层口令不一致，影响统一解锁；删 ZChain 层含 note 库不可逆 | 先定义回滚策略；埋 `rekey_partial_failure` |
| R-36 | 「最近 24 小时 · 5 份」窗口与"份/次"口径无实现支撑 | **确定** | 中：计数不可信 | 加时间字段或改文案；统一"复验次数"口径 |
| R-37 | 「显示测试网」稿为开关、码为只读 | 高 | 低：功能虚标 | 对齐（实现或降级为只读） |
| R-38 | `PROVIDER_VERSION 0.4.0` 与 manifest `0.6.1` 漂移 | **确定** | 低：版本信息不可信 | 关于页只展示 manifest 版本；适配器版本单列 |
| R-39 | 收款页对完整地址做了中间省略 | 高 | **高**：用户无法逐字核对地址 | 收款页永不截断（本文已定） |
| R-40 | 13/19 屏超出 600px，需滚动才能看到主操作 | **确定** | 高：核心动作可能在首屏外 | 首屏完整性验收（AC-45）；必要时压缩明细区 |
| R-41 | 首页 ZChain 行把 GAME 与 REAL 并排一行 | 中 | 中：跨域视觉隔离被削弱 | 拆两列 + chip 配色 |
| R-42 | "会话密钥"（SNIP-12）与"解锁会话"（15 min）概念易混 | 高 | 中：用户误以为撤销授权=锁定钱包 | 页内加一行区分说明 |
| R-43 | `GET /api/v1/status` 未被使用，网关可用性只能靠失败发现 | 中 | 低：体验差但无错 | Portal 首屏读 status 显示可用性 |
| R-44 | `approve`/`swap` 等合约标题无 selector 解码 | 高 | 低：历史记录可读性差 | 解码或改为中性标题 |

**外部依赖（阻塞项）**

| 依赖 | 影响范围 | 状态 |
|---|---|---|
| 价格源 / 预言机 | R-01，首页与 EVM/Starknet pane 全部 `$` 数字 | 未接入（`fiatOf` 恒 null）`[码]` |
| 二维码编码器 | R-17，3 张收款 sheet | 未接入 `[码 README:160]` |
| 网关回传 `amount` / `tableId` | R-24、R-25 | 未定义字段 `[码 receipts.js]` |
| `payout_root` 出口 | R-16 | verifier 内有重算，UI 未回传 `[码 portal.js]` |
| `pastDeadline` 置位 | R-13 | 实现缺口 `[码 receipts.js:177]` |
| REAL vault 上线 + BFT finality | R-15、F-10 一切"可提现"表述 | 三条件全不满足（`vault_offline`）`[码 display.rs:55-73]` |
| 链上会话 admission 注册 | R-03、F-12 规则 11 | 未接线（`devnet_local_entry`）`[码 sessions.js]` |
| 链上 `zk_verify` 真实实现 | R-32 | dormant / Stub `[档 37-7 §6.9]` |
| testnet 网关 | 网络切到 `zchain-testnet-1` 时 | `gatewayUrl:null`（刻意）`[码]` |

---

## 13. 设计稿一致性问题清单（本文复算结论）

`[审]` 以下每条均由本文按 `[码]` 口径复算或 grep 得出，可独立验证。建议作为 P0-0 决策收口的议程。

| 编号 | 问题 | 复算 / 证据 | 处置 |
|---|---|---|---|
| **C-01** | 首页三链合计加不平 | `10,120.00 + 8,124.69 + 4,043.42 = 22,288.11`，稿写 `22,288.63`，差 `$0.52` | 改由求和函数产出（AC-04）；连带 R-01 |
| **C-02** | 三处隐含 ETH 单价互不相同 | `$3,359.67`（EVM pane）/ `$3,360.00`（Starknet pane，精确）/ `$3,360.48`（send 预览） | 单一价格快照（AC-05）；连带 R-01 |
| **C-03** | NATIVE 隐含单价 `$1.012` 无出处 | `10,120 ÷ 10,000 = 1.012` | 移除或接入价格源 |
| **C-04** | 手续费 `0.000252 ETH` 与 `21,000 × 12 gwei` **完全自洽** | `21000 × 12 = 252,000 gwei`；`0.000252 × 3360 = $0.8467 ≈ $0.85`；代码 `maxFee = gasPrice × gasLimit` | ✅ **正面样板**，列为可复核规则（F-15 规则 2） |
| **C-05** | 示例 hash 跨链跨实体复用 | `0x51b7…c8`（ZChain 结算 / EVM 接收）；`0x9a02…ef`（ZChain 转账 / EVM swap）；`0x8f3a…` 前缀（EVM 已发送 tx / 收款 owner） | 示例数据按链分段命名空间（R-29） |
| **C-06** | hex 长度不符合摘要规格 | SNIP-12 原始摘要 `68` hex（34B，应 64/32B）；DS-2 示例 hash `40` hex（20B）；Portal 预填 `19` hex | 全部改为 64-hex（F-11 规则 7 / F-13 规则 10） |
| **C-07** | `hand_binding` 缩略尾段取自中部 | 样例全串尾 6 位是 `88a2f5`，稿写 `…04b79b`；`04b79b` 实际位于第 13 位 | 缩略必须由 `shortAddr()` 产出（§6.3） |
| **C-08** | 自检节点数 `2,349` 不可复算 | 稿口径「2 底色 × 19 屏 × 3 链数据面」与 2,349 无法整除自洽（2,349 = 81 × 29） | 提交脚本或删除该数字（R-21） |
| **C-09** | `92s 后过期` 违反 `remainText()` | 92 ≥ 60 → 应输出 `1:32` | 统一格式化（AC-14） |
| **C-10** | `昨天` 不是 `relTime()` 的任何输出 | 24h–30d → `N 天前` | 统一格式化（AC-15） |
| **C-11** | DS-7 例 2 与提现页同格不同色 | 前者 cur（琥珀）、后者 bad（朱红） | ✅ 非缺陷：`outcome` 分别为 `wait` / `blocked`（§5.1，AC-10） |
| **C-12** | 选币/限额/证明/凭证数字全部自洽 | `300+200=500` ✅；`1000+2500+1500=5000` ✅；`2150/5000=43%` ✅；`4+1=5` 份 ✅；`1240×2%=24.80` ✅ | ✅ 保留为验收基线（AC-37…） |
| **C-13** | 屏数口径 19（稿）vs 18（README） | `SCREENS` 19 条 / `<template>` 17 个（`t-acct` 复用 3）；代码 `SCREENS` 18 条（`acct` 收敛 + `contract` 无稿） | 统一为代码 id（§3.2） |
| **C-14** | scope / 有效期默认 / 日窗口三点偏离 | 稿 3 项 scope vs 码 4 项；稿"7 天"vs 码默认 1 天；稿未说 UTC 日 | R-30 / D-53 / R-31 |

---

## 14. PRD 质量自检

| 序号 | 检查项 | 判断标准 | 结果 |
|---|---|---|---|
| 1 | 背景不空泛 | 回答了"为什么做"而非只说"需要做" | ✅ §1.1 给出现状 / 三套模板成本 / 资产误判风险三层理由 |
| 2 | 目标可量化 | 至少一个数字型成功指标 | ⚠ **部分通过**：有指标框架与可取数口径，但无基线数字（仓库确实没有）。已按红线标 `[待补充]`，唯"提现提交尝试 = 0"与"界面事故 = 0"为硬数字目标 |
| 3 | 用户画像具体 | 不含"所有用户" | ✅ 5 个角色，含特征 / 诉求 / 场景 |
| 4 | 业务规则穷举 | 无"等""其他情况"等模糊表述 | ✅ 逐屏规则编号；异常表列全；上限/时长给全表；对无法确定处显式标 `[判]` 或"需评审裁决"而非用"等"掩盖 |
| 5 | 异常流程覆盖 | 每个功能至少 2 个异常场景 | ✅ 每屏 ≥3；错误码表 ~35 个有官方文案 `[码 ui_ledger.js:322-358]` |
| 6 | 验收标准可测试 | 使用 Given-When-Then | ✅ AC-01…AC-48 全部 G-W-T 格式 |
| 7 | 数据埋点完整 | 核心操作路径均有埋点 | ✅ 29 事件覆盖创建/解锁/选币/提现/签名/会话/凭证/复验/回执/复制/错误/换肤 |
| 8 | 无技术方案 | 只描述"做什么" | ⚠ **有意偏离**：本文大量引用常量与函数名，但性质是**为既有事实做溯源**（用户明确要求"每个数字的数据来源"），不是为未定事项选技术栈；未指定数据库、语言、框架、算法选型 |
| 9 | 优先级明确 | 标注 P0/P1/P2 | ✅ 全部 F-01…F-22 标注；发布门禁项单列 |
| 10 | 排期有依据 | 考虑开发/测试/联调 | ✅ 9 阶段 76 人日 + 依赖 + 关键路径 + 降级路径 |

**未通过项的处理建议**：
- **第 2 项**：需业务方补三类基线数据——popup 日活跃会话数、REAL 资产用户占比、dapp 签名请求日量。无这三项，§1.3 的目标值无法从"框架"变"承诺"。
- **第 8 项**：若评审认为技术引用过重，可将 §6.2 溯源表整体移入附录，正文只保留"✅ 有来源 / ❌ 无来源"两档标记。本文档结构支持这种裁剪而不损失信息。

**红线复核**（对照本 skill 的反模式表）

| 反模式 | 本文是否触犯 | 说明 |
|---|---|---|
| 需求镀金（一期写 50 个功能点） | 否 | 19 屏是**既有设计与已落地代码的清点**，非新增；§11 明确给出"降级路径"以收缩范围 |
| 伪需求（"用户可能需要"） | 否 | 每条需求带 `[稿]/[码]/[档]/[判]` 来源；`[判]` 集中可审 |
| 交互越界（写按钮颜色字号布局） | 否 | 视觉一律引用 DS-1…DS-12，不重述色值与字号；§7 只描述行为与时序 |
| 技术越界（指定 Redis/MySQL） | 否（见自检第 8 项） | 只描述"数据从哪个已存在接口取"，不指定实现方案；KDF/曲线是既有交付约束 |
| 规则黑洞（"按业务规则处理"） | 否 | 阈值、时长、上限、枚举、回落行为全部给具体值与出处；未定处显式标 `[判]` 并进 §11 缺设计清单 |

---

## 15. 附录

### 15.1 相关文档

| 文档 | 用途 |
|---|---|
| `design/zchain-wallet-ui-b-ledger.html` | 本 PRD 的设计基准（19 屏 + DS-0…DS-13） |
| `design/zchain-wallet-ui.html` | 方向 A（毡布绿 v0.1），1:1 对照稿 |
`design/pixso/pixso-b-ledger.html` + `.screens/` | 运行时 DOM 导出产物（19 屏 × 2 形态 + 14 DS 板）；无额外逐屏溯源注释
| `extension/README.md` | 「UI 结构（方向 B）」与诚实边界条款（第 148–168 行） |
| `extension/ACCEPTANCE.md` | 0.6.1 验收对照；提现预览红线（第 332 行） |
| `docs/stwo-wasm-path-a.md` | 1.7s 验证耗时的实测基准与 500ms 决策口径 |
| `docs/37-10-trust-layer-model.md` | 信任分层与「无 N 个确认」的事实来源 |
| `docs/37-7-rpc-interface.md` | RPC 契约；`Account.balance ≠ ZCN`（§6.5）；`zk_verify` Stub（§6.9） |
| `docs/plan-appchain-v1.md` | 双重 finality 提现路径（§5.3 / 第 281 行）；ForceInclude 定义 |
`docs/plan-token-economy-v1.md` / `-compliance-v1.md` | 资产域定义（注意域编号与代码不一致，R-23）；KYC/GEO 闸门
| `SECURITY_ARCHITECTURE_AUDIT.md` | 安全边界背景（不替代能力矩阵） |

### 15.2 竞品参考

| 维度 | MetaMask / 通用多链钱包 | 方向 B 的做法 | 差异理由 |
|---|---|---|---|
| 多链呈现 | 网络下拉，链 = 目的地，每链一套页 | 链 = 账簿内筛选器，一个模板 × 三数据面 | 消除重复页与重复实现 `[稿 DS-0]` |
| 交易状态 | "确认中 → 完成"，常伴 N 个确认 | 两套显式状态机：凭证阶梯 + 投递阶梯，原词不翻译 | ZChain 无"确认数"概念；"可证"必须单独表达 `[档 37-10]` |
| 资产可信度 | 余额一个数 | 短板等级 + 逐条不可提交原因 + 托管印章 | 限制说明是核心内容（§8 D-15） |
| 法币等值 | 普遍显示 | 无价格源时 `—` + `价格源未接入` | 不编造数据（R-01） |
| 收款 | 二维码普遍 | 当前只给完整地址 + 复制，**不画假码** | `[稿 DS-11]` + 现网无编码器（R-17） |
| 审计表述 | 常见"已审计"徽章 | 明写"未通过第三方审计"，界面零徽章 | 品牌硬规则 7（F-19 规则 4） |

### 15.3 术语表

| 术语 | 定义 |
|---|---|
| **凭证阶梯 / proof ladder** | `pending → soft → proven → finalized`，描述 note 的资产可用等级；由 `PROOF_LADDER` 与 `ProofState` 定义 |
| **投递状态机 / inclusion ladder** | `signed → seen → included`，描述网关是否见到并提交该交易；与阶梯正交 |
| **短板 / weakest** | 参与一次操作的全部 note 中凭证等级最低者；决定该操作的整体等级 |
| **水位 / watermark** | 最后一条已证明日志的 `op_index`；`frame_index ≤ watermark` 才可称 `proven` |
| **轧差 / netting** | 把不同域（REAL ↔ GAME）金额相抵或相加；本产品**禁止** |
| **fail-closed** | 任何不确定（未知枚举、超时、部分失败）一律拒绝放行；界面对应虚线禁用按钮 |
| **粘滞操作 / sticky** | 生效后不可在同会话内恢复；撤销会话密钥属此类 |
| **托管映射 / custodial mapping** | REAL 域资产由运营方托管，非链上可自由动用；`real_is_custodial_v1_offline` |
| **模拟预览 / dry run** | 界面展示计算结果但**不产生任何链上交易**；提现预览是唯一的此类屏 |
| **贪心选币 / greedy select** | 按金额降序取 note 至覆盖目标；note 全额消费、守恒校验、上限 16 |
| **可复核 / independently verifiable** | 密码学与结算证明可被第三方重算，**不等于**已审计 |
| **GTS** | Game Token，GAME 域的可组合资产（结构单向、不可赎回） |
| **UDC** | Starknet Universal Deployer Contract，地址可由公式推导 |

### 15.4 开放问题（评审需给出结论）

1. **首页主数字放什么**？若无价格源，`—` 作为首屏最大字号是否可接受？`[判]` 建议：改为"凭证达标度"（如 `4/5 已 finalized`）作为主数字，与差异化卖点一致。
2. **REAL 与非托管资产能否同屏合计**？若不能，跨域禁轧差如何向用户解释"为什么总数比三层加起来小"？
3. **限额在无链上背书时如何措辞**？"自助约束"是否足以避免安全暗示？（R-03）
4. **note >16、回执 >20 是否需要"合并/清理"操作**？当前设计只能"等它自己好"，长期是否会造成不可用（`[判]` 需要 note 合并功能）。
5. **`contract` 屏的设计归属与优先级**（R-02）。
6. **会话过期后桌台正在进行的对局如何处理**——会话失效是否会卡住结算？稿与代码均未回答。
7. **动效是否接受"首版不用现代 CSS 过渡特性"的限制**（最低 Chrome 116）；是否值得提升最低版本以换取 `@starting-style` / View Transitions？
8. **示例数据是否重做为可由代码生成的 fixture**？当前 12 条一致性缺陷中 6 条源于手写数据（C-01…C-07）。`[判]` 强烈建议：**稿的数字应由一份 fixture JSON 渲染生成**，与实现共用同一份格式化函数——这是让稿本身变成可测资产的唯一方式。
