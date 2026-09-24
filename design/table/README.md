# ZChain 牌桌设计稿 · 账簿 Ledger 方向 v0.1

重设计 `poker_texas_air/client` 的**两套牌桌**：生产桌 `/play`（可玩，socket.io）与
ZK 展示桌 `/game/:gameId`（结算可证叙事）。视觉走钱包已有的**方向 B「纸白账簿」**，
先出静态设计稿，代码落地是下一步。

## 打开

```bash
open design/table/zchain-table-ui.html      # 画廊：9 屏纵向排布 + 纸白/夜场切换
```

单屏精确出图（1280×800，无外壳）：

```bash
cd design/table && ./render.sh              # 全部 9 屏 → png/paper--<id>.png
GROUND=night ./render.sh t3 g1              # 夜场底
ZCHAIN_CFT_CHROME=/path/to/chrome ./render.sh   # 覆盖 Chrome for Testing 路径
```

或直接在浏览器里 `zchain-table-ui.html?g=night#t3`。屏 id：`t1 t2 t3 t4 t5 t6 g1 g2 ds`。

## 为什么是「账簿」而不是「赌场」

现桌是开源 Secret Poker 客户端的紫色渐变换皮（`primaryCta #4f46e5`、`radius 2rem`、
`surfaceGlass`），与自家 brand token 无关；座位靠 `scale(.55)` 绝对定位堆叠，15 秒
计时是一条与真实剩余时间无关的 CSS 无限旋转环，数字非等宽所以筹码对不齐成列。
观感结论：像 demo，不像产品。

而项目自己的设计文档已经判过：**「牌桌是竞品都有的，差异点是结算可证」**。
所以牌桌不该往「更像赌场」走，该往「更像一笔可被复核的账」走 ——
这恰好是钱包方向 B 已经成立的那套体系。

**本稿不新增任何视觉语言**：令牌逐字同源 `design/figma/tokens.json` 与
`design/zchain-wallet-ui-b-ledger.html`，只新增牌桌专有部件（台面 / 座位条目卡 /
注单引线 / 密封牌背 / 彩池合计块 / 操作刻度尺）。

## 毡面语汇 → 账簿语汇

| 牌桌惯例 | 本稿做法 | 用的现成原语 |
|---|---|---|
| 绿毡台面 | 账格纸面 + 细线双线桌沿，零厚度零阴影 | `.tot::before` 的 `rule-paper` 横纹 |
| 木质桌沿 | `1px --rl-2` 外沿 + `1px --rl` 内沿 | `.rl` / `.rl-2` |
| 圆形头像座 | 方形纸卡：头像 + 名 + 等宽余量右对齐 | `.cd` / `.av` |
| 庄家圆扣 | 旋转 4° 的方角印章「庄 BTN」 | `.seal` |
| 筹码堆 | 等宽数字 + 点线引线指向彩池 | `.num` |
| 彩池显示 | 合计块：主池 / 边池 / 已投入 / 待跟 / 台费 | `.tot` + `.lr` |
| 街段文字 | 五节点方角状态轨 | `.rail` / `.rn` / `.rline` |
| 旋转计时环 | 线性细条 + `T-09` 等宽读数 | `.meter` |
| 牌背 | 密封信封：交叉细网 + 锁 + SEALED + 牌序 | 新增，语义接 `EncryptedCard` |
| 赢家高亮 | 落一枚印章 + 彩池划销 + 派彩结转行 | `.seal` + `.pot--cleared` |
| 下注滑杆 | 印刷刻度尺（最小加注 / 半池 / 底池 / 全下有标注） | 新增 |
| 操作按钮 | 一屏只允许一个翡翠实底，其余描边 | `.btn-p/-s/-o` |

## 屏清单

**A · 生产桌 `/play`** — 字段对齐 `types/game.ts` 的 `Table` / `Seat`，未虚构数据

| 屏 | 内容 |
|---|---|
| T1 | 空桌 · 待入座（5 空置位 / 密封公共牌 / 彩池 0 / 票据抬头） |
| T2 | 对局中 · 他人行动（翻牌圈 / 线性计时 / 弃牌划销 / 彩池四行拆解） |
| T3 | 轮到我行动（操作刻度尺 / 加注档位 / 底池赔率 / 四键层级） |
| T4 | 摊牌与派彩（赢家落章 / 彩池划销结转 / 弃牌家底牌不公开） |
| T5 | 买入弹窗（链上入账单据，字段一一对应 `Seat.tsx`） |
| T6 | 本手凭证（流水 / 结算 / 证明三段同页 —— 差异化主屏） |

**B · ZK 展示桌 `/game/:gameId`** — 字段对齐 `GameState` / `CryptoEvent`

| 屏 | 内容 |
|---|---|
| G1 | 展示桌主视图（左：牌局事实 · 右：支撑这些事实的密码学证据） |
| G2 | 证明面板（承诺层 / 证明层 / 防重放 / 链上验证 + 徽章三态含失败态） |

**C · 组件板** — T9 `DS`：令牌与实测对比度、座位状态矩阵、牌面与密封牌背、
彩池写法、操作层级与计时器、印章与标签、街段轨与证明轨。

## 与现实现的三处刻意偏离

1. **座位布局**：现桌 5 座为 `SEAT_LAYOUTS` 的三上两下；本稿改为**对手四座压上桌沿长边、
   玩家本人放大进页脚**。这是牌桌客户端的通行做法，也让玩家本人的底牌 / 余量 / 计时
   第一次有了稳定可读的位置。落地时需同步改 `Play.tsx` 的 `SEAT_LAYOUTS`。
2. **弃牌位不摘除**：现桌已弃牌玩家会从桌上消失，导致数不清还剩几人。本稿保留在账页上
   （划销线 + 虚线框 + `已弃牌` 标签），但不画注单行 —— 弃牌者在台面上没有注。
3. **台费用语义红**：`rakeCollected` 现在藏在角落的胶囊里。玩家有权一眼看到自己交了多少钱。

## 已核对的落地风险

> 2026-09-24：数据缺口分四组（A 客户端渲染 / B 派生计算 / C texas 下发 / D 链上证明层）。
> A/B/C 已在 `poker_texas_air` 落地；**D 组（洗牌证明通道、区块/Gas、合约地址、
> settlement 凭证）移交单独开发**，缺口、字段对照与实施方案见
> [data-gaps-onchain.md](./data-gaps-onchain.md)。

- **`ShuffleProofVisualizer` 的 `proof` 在现桌被硬编码为 `null`**，所以永远显示「暂无数据」。
  G2 需要后端把 `ShuffleProofJson` 真正接上才能落地；且现桌 UI 用的字段名
  （`sum_c1_commit` / `sum_c2_commit` / `nonce`）与服务端结构
  （`zk_consistency` / `triple_dleq` / `product_arg` / `global_challenge_hex` / `nonce_hex`）
  **不一致**。本稿沿用 UI 已写出的字段名，落地时以服务端为准 —— 这不是设计稿能臆造的部分。
- 徽章现桌只有 tx hash + 外链。G2 补了**区块号 / 合约地址 / Gas** 三项，需 RPC 实际返回支撑。
- `sidePots[]` 与 `streets[]` 在 `HandHistoryPanel` 里**声明了却从未渲染**，T6 把它们补上。
- 现桌买入的 `maxBuyin` 硬编码 `5000`，注释说明链上 `limit` 可能为 0 时回退 `bigBlind*100`；
  T5 按 `1,000 – 4,850 / 步进 1,000` 呈现，落地时上限应取服务端真值。
- **本稿不影响 `scripts/dev_poker_air.sh`**：该脚本只构建 zchain 侧 crate 与 `texas` 二进制，
  从不构建 / 类型检查 `client/src`，所以牌桌改动不会被 zchain 侧 CI 捕获，验证需在
  `poker_texas_air/client` 内单独做。

## 建议落地顺序

牌桌不需要重写。四步能拿到本稿约八成观感提升，且不动 socket 与状态层：

1. `styles/theme.ts` 换成 `tokens.json` 的 paper / night 两套（`radius 2rem → 3px`、
   `primaryCta 紫 → felt 绿`、`surfaceGlass → cd 纸白`）
2. `OccupiedSeat` 的旋转计时环 → 线性 `.meter`，并**接真实剩余时间**
3. `NameTag` 胶囊 → `.seat-cd` 条目卡（等宽余量右对齐）
4. `GameStateInfo` 的胶囊组 → `.pot` 合计块（主池 / 边池 / 待跟 / 台费四行）

## 品牌硬规则遵循情况

继承方向 B 的 7 条，逐条未破：零 webfont；哈希 / 地址 / 金额一律等宽且不折断；
零 `text-shadow`（不用描边字、发光字）；`--real` 金只用于托管语义（T6 金库提示条）；
纸白底全部语义色实测 **5.81 – 18.27 : 1**（夜场 8.19 – 16.08 : 1），满足声明的 ≥ 5.2 : 1；
无 scroll-driven 动画；logo 不与「已审计」类徽章组合 —— 本稿所有印章只陈述**结算事实**
（已结算 / 已入金库 / 验证失败），不陈述审计。
