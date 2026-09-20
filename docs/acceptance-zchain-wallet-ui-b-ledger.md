# 验收报告：ZChain Wallet · 方向 B「账簿 / Ledger」扩展实现

**对照基准**：`docs/prd-zchain-wallet-ui-b-ledger.md` v1.0
**验收对象**：`extension/`（Chrome MV3，manifest v0.6.1）
**日期**：2026-09-19 · **执行**：Qoder（实现 + 自验）

---

## 0. 结论摘要

方向 B 的账簿 UI 与纯逻辑层在本轮之前已**基本实现**（18 屏渲染器齐全、凭证条/回执分桶/会话用量等纯函数已接线并被 e2e 覆盖）。本轮工作不是"从零实现插件"，而是**按 PRD 把 44 条风险中界面侧可闭环的 33 条落地，并把 48 条验收标准中此前无自动断言的 30 条变成可执行断言**。

结果：

| 层次 | 结果 | 说明 |
|---|---|---|
| `npm test`（node --test） | **全部通过，0 失败** | 基线 237 例 → 现 **330 例**（新增 93 例） |
| `pack.sh --verify`（真实 Chrome for Testing 加载） | **V1–V4 PASS** | SW 启动 / popup 渲染 / runtime 消息 / 首屏三层芯片 |
| `run_08.mjs`（方向 B 专属浏览器 e2e） | **32 步全 PASS，0 FAIL** | 覆盖 A 链筛选器 / B 合计边界 / C 转账 / D 展示-签名一致 / E 提现 fail-closed / F 凭证簿 / G Portal 失败面 / H 双底色 / I 能力矩阵 / J 逐屏排版几何扫描 |
| `run_07.mjs`（onboarding e2e） | **14 步全 PASS，0 FAIL** | 含本轮新增 O2c 口令框排版断言 |
| 发布门禁（R-01/15/17/19/32） | **界面侧全部收口** | 见 §2 与 §3；R-01/R-17 属"上游未接入 → 界面降级"，非本层可实现 |

新增/修改文件：

- 新增 `extension/common/telemetry.js`（PRD §6.4 全部 30 个事件 + 禁采结构性排除 + 本地聚合，此前**完全没有实现**）
- 新增 `extension/tests/prd_ledger_acceptance.test.js`（34 例，按 AC/R 编号正向断言）
- 新增 `extension/tests/prd_static_guards.test.js`（37 例，含 **R-21 要求的可复算对比度自检脚本**）
- 新增 `extension/tests/telemetry.test.js`（16 例）
- 修改 `ui_ledger.js` / `receipts.js` / `withdraw_preview.js` / `capability_matrix.js` / `portal.js` / `popup.js` / `popup.css` / `service_worker.js` / `receipts.test.js`

**另发现并修复 6 个 PRD 未记载的真实缺陷**（其中 2 个会造成资金数字算错；另有 2 个是本轮改动自己引入的回归，其一逃过了全部三层证据、由用户肉眼发现），见 §4。同时发现 **PRD 自身有 3 处与代码不符**，见 §5。

---

## 1. 验收方法（三层证据）

单一层次的"通过"不足以交付这个 PRD 所要求的东西——它的关键约束分布在三个不同层面：

1. **纯函数层**（`node --test`）：格式化契约、阶梯聚合、分桶、上限文案、BigInt 求和。这是 PRD §6 的主战场，断言最密集。
2. **静态守卫层**（`prd_static_guards.test.js`，本轮新增）：只在源码/样式表层面才能确认的东西——对比度按 WCAG 1.4.3 **现算**、CSP 内联事件为 0、零 webfont、`$` 法币字面量为 0、盾牌图形为 0、`?? 'ETH'` 式 fail-open 为 0、**跨模块调用名是否真的被 import**。最后一条尤其关键：`node --check` 抓不到未导入的标识符，而它会在线上抛 `ReferenceError` 让整屏空白（本轮我自己就踩了一次，见 §4-D5）。
3. **真实浏览器层**（`pack.sh --verify` + `run_08.mjs`）：Chrome for Testing 真加载解包目录，驱动真实 popup DOM。**本轮唯一发现的自引入回归就是被这层抓出来的**（Starknet pane 渲染抛错 → A4 步 FAIL），说明这层不是仪式。
   但这层原先只断言"元素在不在、文案对不对"，**不量几何**——所以同类自引入缺陷 D6（口令框一字一行）漏过了三层，是用户看出来的。本轮起补入 `A0b`/`J1`/`O2c` 三处布局断言（见 §4-D6）。

一条测试若只跑过其中一层，本报告在状态列里写清楚是哪一层。

---

## 2. §10 验收标准逐项（AC-01 … AC-48）

状态图例：✅ 通过（有自动断言）｜🟦 PRD 前已满足，本轮审计确认｜🟡 部分通过（附缺口）｜⛔ 受阻于外部依赖

| AC | 场景 | 状态 | 证据 |
|---|---|---|---|
| AC-01 | 无价格源不得显示法币 | ✅ | 单测 `AC-01 价格源未接入时 fmtFiat 恒返回「—」`；静态守卫 `AC-01 结构性：popup 源码里不存在法币金额字面量`（本轮把遗留的 `'$0.00'` 死分支改为 `fmtFiat('0')`）；e2e `B1`/`B2` |
| AC-02 | 跨域金额不轧差 | ✅ | 单测 `AC-02 domainTotals 逐域各给一个合计` + `缺域参数即 fail-closed`；e2e `B 段` |
| AC-03 | 收款不画假码 | 🟦 | 静态守卫 `R-17 / AC-03`：sheet 内无 `ic('qr')`、含「二维码未接入」、地址 `word-break:break-all`；`recvSheet` 全程不缩略（R-39） |
| AC-04 | 合计必须加得平 | ✅ | 单测 `AC-04 复算 PRD §13 C-01`（断言 `22,288.11 ≠ 稿面 22,288.63`）+ `sumDecimals 任一非法即整体拒绝` |
| AC-05 | 单一价格快照 | ⛔ | 不适用：无价格源，无任何 `$` 路径。`fmtFiat` 已预留 `connected` 分支与 §13 C-02 注释；接入时必须由该出口乘单一快照 |
| AC-06 | 提现入口恒禁用 | 🟦 | `withdraw_preview.js` 字面 `canSubmit:false` + 单测 03「全 finalized 也恒禁用」；e2e `E 段` |
| AC-07 | 原因逐条不合并 | 🟦 | 逐条渲染（`reasonRows`）；e2e `E 段` |
| AC-08 | 策略型原因不得暗示可开放 | ✅ | **本轮新增**：`withdraw_preview` 产出 `cannotSubmitReasonDetails[{text, kind, qualifier}]`（`policy` → 「本版本不会开放」）；popup `reasonRows` 渲染为芯片；静态守卫 `AC-08 / R-07` |
| AC-09 | 凭证短板聚合 | ✅ | 新增单一出口 `ladderOutcome()`；单测 `AC-09 ladderOutcome…第三格画 cur`；此前 4 处内联推导已收敛 |
| AC-10 | wait / blocked 区分 | ✅ | 单测 `AC-10 同一 weakest=soft…必须画 bad（朱红）而非 cur`（§13 C-11 的正解） |
| AC-11 | 未知 proof 不猜测且上报 | ✅ | 单测 `AC-11…回落 pending 且必须上报 mismatch`；popup `trackLadderMismatch()`；静态守卫 `AC-11` |
| AC-12 | 空集合不显示"全部达标" | ✅ | 单测 `AC-12`（`weakest=null` → `idle` → 四格全空） |
| AC-13 | 两套状态不混用 | ✅ | 单测 `AC-13 词汇完全不相交`；渲染出口分离（方形节点 vs 等宽原词 chip） |
| AC-14 | 倒计时格式统一 | ✅ | 单测 `AC-14`（92s→`1:32`、45s、60s 边界、`1h 1m`、已过期、NaN→`—`）；**本轮修掉一处手工拼秒**（`zc-sessions` 过期行原为 `${…}s`，已改 `remainText`） |
| AC-15 | 相对时间格式统一 | ✅ | 单测 `AC-15`（无「昨天」；>30d → `YYYY-MM-DD`；未来时间戳 → 刚刚） |
| AC-16 | 链上交易未知态 | ✅ | 单测 `AC-16`（`待确认` 而非 `pending`；`已回退`） |
| AC-17 | 超期不改分桶 | ✅ | 单测 `AC-17`（seen 超期仍在未上链段 + `seen 超期` 红芯片） |
| AC-18 | 金额精度不可输入 | 🟦 | `transfer_preview` 单测 01（拒绝 `500.50`、接受 `.00`），文案与 PRD 逐字一致 |
| AC-19 | note 数超限 fail-closed | 🟦 | `transfer_preview` 既有 `超出批量上限 16`；**本轮补齐展示层**：`CAPACITY`/`capacityNotice`/`limitReasonText` + 单测 |
| AC-20 | 门槛按网络取值 | 🟦 | `minProofForNetwork('devnet')='soft'` 既有；新增 `requiredProofText` 使文案随网络变化 |
| AC-21 | 后台独立复核 | 🟦 | `verifySpendProofs` 在签名路径；e2e `D 段` |
| AC-22 | 预览与签名摘要同源 | 🟦 | e2e `C/D 段`（含摘要被换 → `PreviewMismatch` 拒签） |
| AC-23 | 已验证不暗示可提现 | ✅ | 静态守卫 `R-15`（否定式白名单，禁裸"可提现"）；`popup.js:1339` 「未开放（不暗示可提现）」 |
| AC-24 | 部分验证不得盖章 | 🟡 | 代码侧成立：`conclusion==='partial'` → 印章文案 `部分验证` + 保留已完成步骤；**本轮新增** `rt.sealAnim` 使印章只在结论返回那一次落章（T-10/A-1②）。缺口：`partial` 需真实网关返回部分步骤才能端到端复现，本环境未跑通 |
| AC-25 | 耗时如实显示 | ✅ | **本轮改为实测条件化**：`overBudgetNote(totalMs)` 取代常驻"约 1.7–2.0s 超预算"文案；未超预算时如实报"在 500ms 预算内"。单测 `AC-25`。并补 T-19 的 100ms 递增已耗时读数 |
| AC-26 | 不声称链上验证 | ✅ | 静态守卫 `AC-26 / R-32`（禁 `链上已验证` / `on-chain verified`） |
| AC-27 | included 说明本机登记 | ✅ | **本轮新增**：`receiptEvidenceText()` + 回执行常驻「证据：…」渲染；单测 + 静态守卫 `R-24 / AC-27` |
| AC-28 | 未验签不推进层级 | 🟦 | `applySeenReceipt` 既有（evidence 写 `receipt_unverified_signature`）+ receipts 单测 04；本轮补界面常显 |
| AC-29 | scope 与后台一致 | ✅* | **本轮改**：勾选框由 `SESSION_SCOPES`/`FORBIDDEN_SCOPES` 单一常量驱动，提交值只接受常量内的词。⚠ 单测断言的是"UI 与后台同源且不含 withdraw/opentable"；PRD 记的"代码 4 项"实为 **5 项**（含 `transfer`），见 §5 |
| AC-30 | 桌白名单整数 | ✅ | **本轮新增** `normalizeTableId`（`8♠`/`#A3F2`/负数/小数/超安全整数一律 → null）+ receipts 单测 5 例；界面显示「桌号 N（协议 table_id 为非负整数）」 |
| AC-31 | UTC 日窗口 | ✅ | **本轮新增**：会话卡常驻 `DAILY_RESET_TEXT` + 当前 UTC 日序号；`utcDayIndex()` 与 `sessions.js` 的 `floor(now/86400)` 同口径；单测 + 静态守卫 |
| AC-32 | 限额不描述为安全保证 | ✅ | **本轮新增**说明行（"清除浏览器存储即可绕过…链上 admission 未接线前不得据此认为资金受限额保护"）；静态守卫要求出现否定式「不是安全保证」 |
| AC-33 | 撤销粘滞性说明 + REVOKE 键入 | ✅ | **本轮从零实现**：撤销由"直接执行"改为模态；`REVOKE` 未键入前按钮 `disabled`（`gatedInput`/`gatedBtn` + 委托 `input` 监听）；模态含"立即生效 / 永久失效 / 需重新输入口令"三条。静态守卫 `AC-33 / F-21` |
| AC-34 | 无审计徽章 | ✅ | **本轮清除 4 处 shield**（`banner('ok')`、证明 tab、Portal 动作、Portal 按钮、回执行）+ 静态守卫区分肯定/否定式承诺 |
| AC-35 | 未审计声明常驻 | 🟦 | 关于段既有；守卫现要求同时出现「未通过第三方审计」与「不等于已审计」 |
| AC-36 | 能力矩阵单一数据源 | ✅ | **本轮完成**：`CAPABILITY_ROWS` 进 `common/capability_matrix.js`，删除 popup 内第二份 `CAP_RED_LINES`；单测 `R-26` + 静态守卫 `AC-36` |
| AC-37 | 备份覆盖范围如实 | 🟦 | `popup.js:822` banner「只覆盖 ZChain 层…不含 EVM / Starknet」 |
| AC-38 | 口令只显一次 | 🟦 | 仅 `rt.created` 内存态渲染；守卫确认无第二处 |
| AC-39 | 门控不放行 | 🟦 | `data-check` 委托 + `disabled`；本轮为解禁态补 T-07 虚线→实线 |
| AC-40 | 三层解锁独立反馈 | 🟦 | `unlockCount` 三独立判定 + toast「已解锁 N / M 层」 |
| AC-41 | 链筛选器记忆链 | 🟦 | `backTarget('@acct')` 带当前链；e2e `A5` 三链来回后结构一致 |
| AC-42 | 未知屏幕不静默回落 | 🟦 | `resolveScreen` 返回 `{error:'UnknownScreen'}` + toast |
| AC-43 | 网络不可达不伪造 | 🟦 | `—` + `RpcUnreachable/GatewayUnreachable（未伪造结果）`；e2e `G 段` |
| AC-44 | 动效不撒谎 | ✅ | **本轮新增** CSS `@media (prefers-reduced-motion: reduce)`（时长降到 0.01ms，保留印章/芯片/虚线语义）+ JS 侧 `prefersReducedMotion()` 使离场立即完成；静态守卫 `AC-44` |
| AC-45 | 首屏完整性 | 🟡 | **本轮实现缓解**：账簿快捷动作条 `.acts` 改吸底（`position:sticky;bottom:0`，抬头不滚动），主操作不再落在首屏外。缺口：PRD 要求的"19 屏逐张 380×600 截图 + 量高"未做，无逐屏数据 |
| AC-46 | 格式化单测 | ✅ | 34 例边界断言（0 / u64 上限 / 恰好 60s / 30 天 / 前导零 / 非十进制原样回落） |
| AC-47 | 测试网符号正确 | ✅ | **本轮修 fail-open**：`stkUnit()` 三级取 `info → net → '—'`，删除 `?? 'ETH'` 与 `tk:'Ξ'`；水龙头标签随符号；补「DST 是 devnet 测试代币，无价值、不可上主网」。e2e `A4` 复绿 |
| AC-48 | 凭证簿计数口径 | ✅ | **本轮新增** `proofLogSummary()`（`次` vs `份` 区分、无时间戳不报 24h 窗口——见 §4-D3）；静态守卫禁掉字面量「最近 24 小时」 |

小结：**48 条中 30 条本轮拿到或新增了自动断言**，13 条为 PRD 前已满足、本轮逐条审计确认，4 条部分通过（AC-05/24/45 + AC-29 的口径修订），1 条受阻于价格源（AC-05）。

---

## 3. §12 风险逐项（R-01 … R-44）

### 3.1 发布门禁级（5 条）

| R | 结果 | 说明 |
|---|---|---|
| R-01 法币折算无数据源 | ✅ 界面侧收口 | 源码内无法币字面量（守卫）；hero/EVM/Starknet 三处一律 `—` + `价格源未接入`。**上游依赖仍在**（价格源/预言机未接入） |
| R-15 「可提现」误导 | ✅ | 全站无裸"可提现"；提现页原因带「本版本不会开放」限定语；凭证簿不再写"可提现"（守卫强制） |
| R-17 伪二维码 | ✅ | 三张 sheet 只给完整地址 + 复制 + `二维码未接入`（本轮前已满足，守卫固化）。⚠ 编码器和 `chainActs` 里的 `ic('qr')` 按钮图标仍待产品定夺（图标非码图形，但语义易混） |
| R-19 地址形态 / DST 符号 | 🟡 | **符号已修**（AC-47）。**owner 格式**：输入校验（66 hex、无 `0x`）后台早已 fail-closed；界面提示语已含「公钥即 owner（hex33 压缩公钥）」。缺口：稿面 `zc1q…` bech32 形态**仍存在于设计稿**，需重出图 |
| R-32 链上验证表述 | ✅ | 守卫禁词；Portal 文案限定为"网关取数 + 本地 wasm 复验" |

### 3.2 本轮新落地（界面侧可闭环，28 条）

R-03（限额否定式说明）、R-05b（门槛随网络）、R-06（五个边界态文案 + 键入门槛机制）、R-07（原因性质标注）、R-08（口令复制常驻警示 + 4s 不自动消失）、R-09（私钥 `type=password` + 失焦回掩码 + 显隐切换）、R-10（忘记口令 → 「需备份口令」）、R-11（回执/会话/note/tx/proof log 五处上限常驻说明 + `capStore` 改为如实返回丢弃数）、R-13（**PRD 判断有误**，见 §5）、R-14（Explorer 开关改名为「用第三方 Explorer 补充展示」+ 常显隐私告知）、R-18（`PROOF_ALIASES` + `mismatches` 上报，别名命中也算漂移）、R-20（证明体积上限 5 MB → `ProofTooLarge`，含错误码文案）、R-21（**可复算自检脚本入库**：对比度按 WCAG 现算、CSP、webfont、徽章、未导入标识符）、R-24（回执金额由 `inputs[].amount` BigInt 求和推导，任一非法整体 `—`）、R-25（`tableId` 非负整数归一 + 未知 kind 不造「开桌」标题）、R-26（网络行按层分列，`NetworkUnsupported` 文案限定 ZChain 层）、R-27（`DISPLAY_DECIMALS` + `fmtDisplay`，只补齐不截断不四舍五入）、R-29（`ID_PREFIX`/`idText` 具名缩略，tx/hb/req/rc/note/root 六类）、R-30（scope 单一常量驱动）、R-31（UTC 日说明 + 序号）、R-33（evidence 常显）、R-36（计数口径 + `次` vs `份`）、R-38（`provider` 改标「适配器版本」，主版本只认 manifest）、R-39（收款页永不截断，守卫固化）、R-41（首页 GAME/REAL 拆两行 + 域配色芯片）、R-42（「两个"会话"不是一回事」说明条）、R-43（Portal 首屏主动 `GET /api/v1/status`，30s 内复用）、R-44（合约标题：见 §3.3）

另外 **§7 动效整章**、**§6.4 埋点整章**从 0 实现到落地，见 §6、§7。

### 3.3 未闭环（受外部依赖或需上游改动，11 条）

| R | 为什么没关 | 需要什么 |
|---|---|---|
| R-02 | `contract` 屏代码有渲染器但**稿缺设计**；本轮未自创视觉 | 设计补稿 |
| R-04 | 账簿页 ERC-20 仍是静态 `—` 占位（读取未接线） | 把 `eth_call` 余额读取并入 `contract` 屏 |
| R-12 | 采代码口径（段名「未上链 / 已上链」），**设计稿需同步重出** | 稿件更新 |
| R-16 | `payout_root` 网关是否回传 UI 仍未确认；界面已按"取不到即 `—（网关未回传该字段）`" | 后端出口 |
| R-22 | GAME 域「流通供应量」`outstanding` 仍不在任何屏显示（保持只显示个人余额） | 若要做，需新增独立卡并明确标题 |
| R-23 | 域编号文档（三域）与代码（两域）不一致，**本轮只动代码侧口径** | `docs/plan-token-economy-v1.md:516` 同步 |
| R-28 | `rake` 仍只有金额口径（无百分比字段）；界面已不再同时显示两种 | 上游加 `rake_rate` 或确认只要金额 |
| R-35 | **未实现**：修改口令部分失败的补偿模态。后台 `popup:evmRemoveAccount`/`stkRemove` 也不接受口令二次校验 | 需后台加逐层 rekey 结果回执 + 回滚策略；见 §8 偏离说明 |
| R-37 | 「显示测试网」稿为开关、码为只读，本轮未动 | 产品决定实现或降级稿 |
| R-40 | 吸底缓解已做，**逐屏量高验收未做** | 19 屏 × 2 底色截图核对 |
| R-44 | 合约调用无可读标题（无 selector 解码） | 4byte 解码或确认用中性标题 |

---

## 4. 本轮发现的 PRD 未记载缺陷（6 个，均已修）

这几条不在 R-01…R-44 里。D1–D4 是读代码/跑测试时发现的，前两条会**算错钱**；D5、D6 是**我自己本轮引入**的回归——D5 被 e2e 抓到，D6 漏过了我全部三层证据、由用户肉眼发现。

**D1 · u64 金额经 `Number()` 静默丢精度（回执软锁表）**
`receipts.js:65` 把 `inputs[].amount` 转成 `Number`。note 金额上限 `18446744073709551615` 远超 `Number.MAX_SAFE_INTEGER`，转换后末几位直接错，而这个值是双花软锁的占用金额。
→ 改为十进制字符串存储；新增 `pendingSpendSum()`（BigInt）。单测断言 `String(Number(big)+1) !== '18446744073709551616'`，把"为什么必须禁 `Number()`"钉成回归防护。

**D2 · 「可用余额」用浮点减法**
`service_worker.js:2169` `Math.max(0, Number(play_free) - pendingSum)`。这是转账页 MAX 与 `InsufficientFunds` 判定的输入，大额 PLAY 余额下会虚高/虚低。
→ 改走 BigInt 下钳减（`subClampedDecimal`）。

**D3 · 计数文案的"看起来像数据的空值"**
新增 `proofLogSummary` 时发现：无时间戳记录若按 `newest=0` 计算，会输出「24 小时内 0 次」——一个无法由数据支撑的结论。
→ 无带时间戳记录时窗口必须为 `null`，文案只报「最近 N 次本地复验」。单测 `R-36` 覆盖。

**D4 · 空 `data-act` 把只读信息伪装成可用控件**
`docHeader` 在无 `netAct` 时仍渲染 `<button data-act="">`，凭证簿的 `engine stwo` 标签点下去得到「未实现的动作：」。
→ 无动作时渲染静态 `<span>`（§7.3「未实现的能力不给可点笔触」同理）。

**D5 · 我自己的回归（被 e2e 抓到）**
为 Starknet pane 传 `nameKids: chip('dev')`，而 `assetRow` 对它做数组展开 → `TypeError` → 整屏渲染失败、`#stk-address` 消失、A4 FAIL。`node --check` 和 316 个单测全绿，只有真实 Chrome e2e 发现。
→ 改为数组；并在静态守卫里补"跨模块调用名必须已 import"检查（同类 `ReferenceError` 隐患一次拦掉）。修后 e2e 回到 30/30。

**D6 · 口令框「一字一行」塌陷（本轮引入，由用户肉眼发现，我的三层证据全部漏过）**
为 R-08 给 `passBox` 加常驻风险警示时，把 `<p style="width:100%">` 塞进了 `.pass` 这个**不换行的 flex 行**。口令 `<span class="grow">` 的 `flex-basis` 是 0，按弹性布局规则分不到收缩量，却被那个 100% 兄弟挤成 **0 宽**；又因 `.pass` 继承 `word-break:break-all`，0 宽盒子在每个字符后折行 → 24 字符竖排成 24 行。
→ `.pass` 改 `display:grid; grid-template-columns: minmax(0,1fr) auto`，警示行改由 `.pass > .hint-s { grid-column: 1/-1 }` 独占一行（不再靠行内 `width:100%`）。实测口令 span 宽度 `0 → 284px`（盒宽 348px），24 字符 1 行读完。

这条是对本报告验收方法的一次自我修正：浏览器层原先只断言"元素存在 + 文案正确"，**从不量几何**，所以 D6 一路绿灯到用户眼前。已补两处几何断言，并用"只回退 `.pass` 一条规则的副本"验证它们不是空断言：

- `run_07 O2c`：量 `#welcome-generated-password` 的宽度 / 折行数 / 警示是否在其下方。回退副本 `FAIL: {"spanW":0,"hintBelow":false}`，修后 `PASS: {"spanW":284,"lines":1,"hintBelow":true}`。
- `run_08 A0b + J1`：通用塌陷探测器（可见文本叶子若 0 宽、或折行数 ≥ 字符数即判塌陷），A0b 扫引导成功页，J1 扫首页 / 账簿 / 证明 / 设置 / 账户面板。回退副本上 A0b `FAIL: 0宽:welcome-generated-password`、J1 仍 PASS——说明塌陷仅存在于成功页一处，其余屏干净。

---

## 5. PRD 本身需要修订的 3 处（复算结论）

按 PRD 自己的 `[码]` 口径复算，下列陈述与当前代码不符。**界面已按代码实现**，文档需同步：

1. **R-13 判断有误**（§12 标为「确定」级）。PRD 称 `inclusionView()` 在 0.6.1 从不把 `pastDeadline` 置 true、"超期态不可达"。实读 `receipts.js:177-197`：`pastDeadline` 由 `isPastInclusionDeadline(anchorMs ?? signedAtMs, now, deadlineMs)` 计算，`seen` 锚 `seenAtMs`、`signed` 锚 `signedAtMs`、`included` 排除；`tests/receipts.test.js` 111-133 两条路径均断言为 true，并经 `service_worker.js:2086` 透出。→ 该条与"本版本相应把超期文案降为不可达"的让步应删除；AC-17/AC-45 的超期分支已按可达实现并有断言。
2. **R-30 / AC-29 的 scope 项数**。PRD 记代码为 4 项 `['play','buyin','bet','settle']`；实际 `SESSION_SCOPES` 为 **5 项含 `transfer`**（源 `adapters/starknet.js`），`DEFAULT_SESSION_SCOPES` 才是 4 项。界面现已由常量驱动（5 个勾选项）。→ AC-29 的断言应改为「提交的 scope ∈ `SESSION_SCOPES` 且 ∉ `FORBIDDEN_SCOPES`」，而非固定 4 元集。
3. **§11 排期与现状不符**。P0-3/P0-4（界面重做 28 人日）假设方向 B 界面待建，实际 18 屏渲染器、`shared` 模板、凭证条、fail-closed 提交均已落地并由 `run_08` 32 步覆盖。真实缺口是：§6.4 埋点（0 → 已实现）、§7 动效（0 → 已实现）、R-33/R-31/R-42 等文案与门槛（已实现）、以及需要设计补稿的 R-02/R-12/R-19。

另有两处小口径：`docs/plan-token-economy-v1.md` 的三域定义与代码两域不一致（R-23，需改文档）；`extension/package.json` 仍写 `0.6.0-alpha` 而 manifest 是 `0.6.1`（R-38 同源，界面已只认 manifest）。

---

## 6. §6 数据口径落地要点

- **§6.3 单一出口**已强制：`fmtAmount`/`fmtDisplay`/`shortAddr`/`relTime`/`remainText`/`validityRemain`/`receiptChip`/`txStatusChip`/`errorText` 全部经 `ui_ledger`；守卫禁止 popup 内出现 `toLocaleString({useGrouping})`、`expiresAt … }s`、字面量「昨天」。
- **R-27 精度裁决已落地**为「显示精度 ≠ 存储精度」：`DISPLAY_DECIMALS = {play:2, native:2, note:2, eth:4, strk:4, erc20:null, usd:2, gwei:2}`，`fmtDisplay` **只追加零、绝不截断或四舍五入**（`0.25009999` 原样透出）——因为上游 `formatUnits` 已是截断口径，展示层再 round 就是把余额报高。
- **§6.1 时长/上限常量**：`CAPACITY` 表与 `validation.LIMITS`/`receipts.MAX_RECEIPTS`/`sessions.MAX_SESSION_BINDINGS` 同值并有断言。
- **§6.4 埋点**：30 个事件 id + 属性封闭枚举；禁采键名结构性丢弃、长 hex 自动降为 `r<8hex>` 引用、口令痕迹形态直接丢；**默认关闭**，关闭即清空缓冲；`summarize`/`computeMetrics` 只给分子分母，PRD 标 `[待补充]` 的目标值不替产品编造。已在 popup 接线的事件：`popup_open`、`screen_view`、`chain_switch`、`note_select_result`、`note_count_over_limit`、`proof_rail_view`、`proof_ladder_mismatch`、`fiat_unavailable_view`、`portal_verify_start`、`portal_verify_step`(1-4，实测 ms)、`portal_verify_result`、`error_shown`、`copy_action`、`ground_switch`、`settings_change`。设置页新增「本地诊断事件」开关（默认未开启，显示缓冲条数与容量）。

---

## 7. §7 动效规范落地

此前状态：**4 条 transition、0 个 `@keyframes`、0 处 `prefers-reduced-motion`**，浮层/模态/toast/换屏全是 `display:none↔block` 瞬时切换。

本轮实现（`popup.css` +4 变量与 12 个关键帧，`popup.js` 挂点）：

| 场景 | 状态 | 落点 |
|---|---|---|
| T-01 底色切换 | 🟦 既有 200ms | `body{transition:background,color}` |
| T-02 屏幕导航 | ✅ | `.body.anim-enter` 140ms；`go()` 仅在**真的换屏**时置 `rt.enterAnim`（A-4：重渲染不重复播放） |
| T-03 链切换 | ✅ | `.body.anim-filter` 120ms；动画只加在 `.body`，**抬头 `.dh` 不参与**（跳动会被读成"账户变了"） |
| T-04/T-05 sheet 与离场 | ✅ | 遮罩 160ms + 面板 220ms；`leaveOverlay()` 先挂 `.leaving` 再摘 `.on`，离场统一 160ms（A-4：遮罩节点不得提前销毁） |
| T-06 破坏性模态 | ✅ | `scale(.96→1)` 180ms，**刻意不用 seal 过冲缓动** |
| T-07 门槛解禁 | ✅ | `.btn.gated → .ungated` 虚线转实线 120ms |
| T-08 toast | ✅ | 改 `opacity+visibility`（`.tst` 节点跨渲染持久，是唯一能走 transition 的）；140ms 进 / 200ms 出；常规 2400ms、错误 4000ms、`sticky` 选项 |
| T-09 凭证条推进 | ✅ | `.rail.anim-enter` 节点缩放 + `.rline` `scaleX` 从左向右，逐格错开 60ms；回退不动画 |
| T-10 印章落下 | ✅ | `qSeal` −8°→−4° + scale(1.08→1)，**仅由 `rt.sealAnim` 在结论返回那一次触发** |
| T-11 倒计时 | 🟦 | 每秒仅替换文本（`tickCountdowns` 既有） |
| T-12 限额进度条 | ✅ | `.meter i` width 240ms；颜色切换不做动画 |
| T-13 勾选 / 开关 | ✅ | 补 `.cb` 120ms 反色；开关 150ms 既有 |
| T-14 按钮按压 | ✅ 修正 | 原 `.btn{transition:filter .12s}` 使 `:active` 变渐变，与"按下必须瞬时"冲突 → `.btn:active{transition:none}` |
| T-15 输入聚焦 | 🟦 | 既有 150ms + focus 外环 |
| T-16 表单错误抖动 | 🟡 | `qNudge` 与 `.nudge` 已定义，**未接到字段错误路径** |
| T-17 列表项删除 | 🟡 | `.row-out` 已定义，**未接删除动画时序** |
| T-18 Portal 步骤推进 | ✅ | 进行中图标 `.spin`（1.2s linear），请求结束立即摘 class |
| T-19 长任务耗时读数 | ✅ | `验证中… 1.2s` 每 100ms 递增（wasm 同步阻塞无真实分母 → 用耗时读数代替进度条） |
| T-20 骨架脉冲 | 🟡 | `qPulse` + `.skl` 已定义（不用 shimmer 斜扫），加载点仍用「加载中…」文本 |
| T-21 hover | 🟦 | 既有；ForceInclude 说明已由 `title` 改为常显文案 |
| T-22 锁定瞬间 | ✅ | 显式 `.scr[data-locked="1"]{animation:none;transition:none}` 防"还能操作一下"的错觉 |

A-1…A-6 与 §7.3 禁止清单：`scroll-driven`/`IntersectionObserver`/count-up 均为 0（守卫）；托管警示条与数字最终值无动画（A-6 由"不给 `.bn`/`.ar-amt` 加动画类"实现）。**未做**：`.act-pin`→`.acts` 之外的逐屏首屏量测、A-6 的自动化视觉核对。

---

## 8. 一处有意偏离 PRD 的说明（必须被看到）

**F-21 要求"删除账户 = 输入口令校验"，本轮未实现，且刻意不做。**

原因：后台 `popup:evmRemoveAccount` / `popup:stkRemoveAccount` **不接受口令参数**，也不做二次校验（删除只要求该层处于解锁会话）。若在模态里放一个口令框却不校验它，就是**伪造安全控制**——比诚实使用 `DELETE` 键入确认更糟，因为它会让用户以为删除受口令保护。

当前做法：保留 `DELETE` 键入（摩擦仍在），并在模态里如实说明作用域（「私钥将从本机 keystore 永久移除…此操作与其他两层无关」）。要真正满足 F-21，需要后台新增"口令再验证后才允许 remove"的入口，属服务侧改动，已列入 §3.3 R-35 依赖。

同类诚实处理：`withdraw_submit_attempt_blocked` 事件在按钮**真 disabled** 的前提下不可能被捕获（Chrome 不向 disabled 控件派发指针事件）。因此该指标的结构含义就是"恒为 0"——要让它可被观测，必须把 disabled 换成"可点但拒绝"，那恰恰违反 AC-06。本项按 AC-06 优先，未加该埋点。

---

## 9. 如何复现验证

```bash
cd /Users/mac/projects/zchain

# 1) 纯函数 + 静态守卫（无浏览器依赖，约 15s）
npm --prefix extension test

# 2) 只跑 PRD 专项
node --test extension/tests/prd_ledger_acceptance.test.js \
            extension/tests/prd_static_guards.test.js \
            extension/tests/telemetry.test.js

# 3) 打包 + 真实 Chrome 加载验证（V1–V4）
bash extension/scripts/pack.sh --verify

# 4) 方向 B 专属浏览器 e2e（32 步，需本地 devchain 环境）
node extension/tests/e2e/run_08.mjs

# 4b) onboarding e2e（14 步，含口令框排版断言）
node extension/tests/e2e/run_07.mjs

# 5) 装到日常 Chrome：chrome://extensions → 开发者模式 →
#    加载已解压 → extension/dist/unpacked
```

最后一次全量复跑发生在 **D6 修复之后**（`.pass` 改栅格 + 三处几何断言），四层同时验证：

| 命令 | 结果 |
|---|---|
| `npm --prefix extension test` | `tests 330 / pass 330 / fail 0` |
| `bash extension/scripts/pack.sh --verify` | V1–V4 **PASS**（Chrome/153.0.8010.36，解包目录真实加载） |
| `node extension/tests/e2e/run_08.mjs` | `verdict: PASS (32/32)` |
| `node extension/tests/e2e/run_07.mjs` | `verdict: PASS (14/14)` |

---

## 10. 建议的下一步（按价值排序）

1. **补设计稿**：R-02 `contract` 屏、R-12 回执段名、R-19 owner 形态、R-45 无日限态、单笔超限回落口令态 —— 这五处是"界面已按代码实现但稿面无图"，不补稿会持续分叉。
2. **同步 PRD**：§5 的 3 处复算结论（R-13、AC-29 项数、§11 排期现状）改回文档，否则下一轮验收会重复劳动。
3. **R-35 后台改造**：逐层 rekey 结果回执 + 部分失败回滚，然后才能谈 F-21 的口令校验删除。
4. **AC-45 逐屏量高**：19 屏 × 2 底色截图 + 首屏三要素（抬头 / 主操作 / 警示条）核对，把 AC-45 从"缓解"升级为"验收"。
5. **T-16/T-17/T-20 收尾**：关键帧已就位，接上字段错误、列表删除、骨架三处时序（约 0.5 人日）。
6. **价格源与二维码**：这两条决定了首页主数字与收款体验能否从 `—` 毕业；接入时注意 AC-05（单一快照）与 DS-11（白底二维码）两条已登记的约束。
