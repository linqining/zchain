# ZChain 站点 · 账簿 Ledger 体系 v0.1

把牌桌稿（`design/table/`）与钱包方向 B（`design/zchain-wallet-ui-b-ledger.html`）已成立的
账簿体系，铺到**营销站 `website/`** 与**牌桌客户端其余页**。本轮交付的是**体系**，不是逐页成品。

## 打开

```bash
open design/site/zchain-site-ui.html      # 体系板：85 类名逐条演练，右上角切纸白/夜场
```

整页出图（板子约 6000px 高，headless 需给足窗口高度）：

```bash
cd design/site
"/tmp/chrome/mac_arm-*/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" \
  --headless --disable-gpu --hide-scrollbars --window-size=1280,6100 \
  --screenshot=png/full-paper.png "file://$PWD/zchain-site-ui.html"
```

> **踩过的坑**：板子用 `<link rel="stylesheet" href="ledger.css">` 相对引用。
> 把 HTML 拷到别处（如 `/tmp`）再截图，会静默截成**无样式**页面且没有任何报错。
> 必须在 `design/site/` 原地渲染。

## 文件

| 文件 | 是什么 |
|---|---|
| `ledger.css` | **唯一样式源**。`website/assets/css/main.css` 的替换件，85 个类名 1:1 沿用 |
| `zchain-site-ui.html` | 体系板 S0–S10，用站点真实原文与真实类名渲染 |
| `png/` | 出图 |

## 为什么可以不改内容

已核对：`build.py` **不产生任何内联 `style=`、也不引用任何 CSS 变量**，它只输出类名。
所以换样式源 ≠ 换结构 —— `build.py`、`templates/base.html`（31 行）、
13 个 `content/*.md` 一行都不用改。

## 夜场不丢：这轮是叠加式的

`ledger.css` 的 night 段 14 个 token **逐字沿用** `media-kit/v0.1/brand.css`，
也就是站点今天的颜色。所以：

- **切到夜场 ≈ 今天的站**（体系相同，底色沿用现品牌基线）
- **纸白是新增的默认**

这是本轮最重要的低风险性质：品牌方不需要在"要不要保留夜场"上纠结。

## 旧 → 账簿 的关键改动

| 构件 | 现站点 | 账簿体系 |
|---|---|---|
| `--radius` / `-lg` | 12px / 18px | 3px / 6px（另补 `--radius-sm: 2px`） |
| `--shadow-pop` | `0 18px 48px rgba(0,0,0,.5)` | `0 1px 0 rgba(20,19,15,.04)` |
| `--glow-felt` | `0 0 24px rgba(55,227,156,.25)` | `none`（变量保留，防未清理引用重新发光） |
| 标题字 | 渐变字 + `background-clip:text` | 纯色 + 字重（硬规则 3：不用描边字、发光字） |
| 卡片 hover | `translateY(-3px)` 浮起 | 仅描边转深 |
| `.hero` | 径向渐变光晕 + 网格纹理 mask | 账格纸纹（26px 一道横线，与钱包 `.tot` 同源） |
| `.felt-oval` | blur 过的虚线毡布椭圆 | 账页：细线双线桌沿，零模糊 |
| `.pcard` ×3 | 摊开的明牌 Q♣ K♥ A♠ | **密封牌背** SEALED + 牌序 #12/#28/#47（纯 CSS，不动 md） |
| `.stat-band` | 四块各自带阴影的卡 | 一格一格账格（1px 分隔线拼表） |
| `.card-play/-real` | 3px **顶边**色条 | 3px **左边**色条（账页页边注，不是横幅） |
| `.st` 状态丸 | 胶囊（且 `--radius-pill` 未定义，实际塌 0） | 方角 2px + 等宽 + 字距 .09em ＝ 钱包/牌桌 `.ch` |
| `.banner` | 渐变底 + 4px 左条 | 纯色 wash + 3px 左条 ＝ 钱包 `.bn` |
| `table` | 斑马纹 + 圆角 + 单元格竖线 | 无斑马、方角、去竖线、表头等宽大写小字 + 2px 实线压底、全表 `tabular-nums` |
| `.docs-side` | 三块圆角卡 | 账簿目录：等宽分组题 + 左 2px 槽，当前项翡翠底 + 左条 |
| `.nav-list` | 圆角胶囊高亮 | 等宽小字 + 竖细线分隔，当前项 2px 底部翡翠线 |
| `.page-head` | 无分隔 | 2px 实线题头线（全站唯一一处粗线） |

顺带修一个现存缺陷：`.st` 引用的 `--radius-pill` 从未在 `:root` 定义过，已在体系里补上。

## 需要你拍板的品牌改判（我没有擅自动）

按本轮决策「纸白为默认」，以下三份品牌文档与现状冲突，**必须同步改，否则体系与品牌文档
会互相打脸**：

1. `website/media-kit/v0.1/brand.css` —— 注释写「青黑毡布 v3」为基线，需改为双底并设 paper 为默认
2. `website/media-kit/v0.1/colors.md` —— 同上，且需补 paper 底 8 个语义色的实测对比度
3. `website/media-kit/v0.1/typography.md` —— 需写明「数字一律等宽」与「不用渐变字/发光字」

实测对比度（对 `--surface #fffdf7`）：`text 18.27` / `muted 8.98` / `muted-2 5.99` /
`felt 6.45` / `play 8.31` / `real 6.63` / `danger 6.56` / `amb 5.81`，
全部满足方向 B 声明的 ≥ 5.2:1。夜场底 8.19 – 16.08:1。

## 逐页铺开顺序（下一轮）

**第一梯队**（体系收益最大、结构最简单）：
`index.md`（hero + 统计带 + 三入口）→ `product.md` → `transparency.md` → `status.md`

**第二梯队**（表格为主，靠 S6 的表格改造直接吃到收益）：
`explorer.md` → `proofs.md` → `roadmap.md`

**第三梯队**（长文，靠 S7 的 docs 布局与 74em 行长）：
`technology.md` → `security.md` → `developers.md` → `docs/*` → `community.md` → `legal.md`

**牌桌客户端其余页**：`/` 首页、`/lobby` 大厅、`/dashboard`、`/whitepaper`、静态页、404 ——
这些是 React + styled-components，不能直接吃 `ledger.css`，需要把令牌注入
`client/src/styles/theme.ts`（现桌 theme 是紫蓝 SaaS 值），再按牌桌稿的同一路径逐组件替换。

## 全站逐页出图（已完成）

```
python3 website/build.py                                   # 41 页 → website/dist
python3 website/tools/site_shoot.py                        # 纸白 41 桌面 + 12 窄屏
GROUND=night TOPLEVEL=1 python3 website/tools/site_shoot.py # 夜场 13 顶层页
python3 design/review/build.py                             # 刷新总评审台
```

`site_shoot.py` **只在 `dist/` 内**把 `ledger.css` 覆盖成 `assets/css/main.css`，
入库的 `website/assets/css/main.css` 一个字节没动（`git status --short website/` 为空可验）。
产物在 `design/site/pages/{desktop,desktop-night,mobile}/<slug>.png`，共 66 张。

## 全站还原度走查（41 页逐页 + 13 页夜场 + 12 页窄屏）

走查方式不是抽查截图，是**先把 41 页的 DOM 全量比对类名，再按比对结果定点看图**。
比对脚本口径：从 `dist/**/*.html` 收集所有 `class="…"`，与 `ledger.css` 的选择器集合求差。

- **90 个类名里 7 个在 CSS 中无定义**：`docs-body` `ul-list` `ol-list` `explorer-live`
  `language-console` `language-json` `language-text`。逐个查祖先链后确认**全部由元素选择器覆盖**
  （`docs-body` 就是 `<body>`，`ul-list`/`ol-list` 都在 `.page-body` 内，
  `language-*` 在 `pre code` 内），所以不是漏样式。
  但 `ul-list`/`ol-list`/`explorer-live` 已补上显式规则，脱离 `.page-body` 也不会退回 UA 默认。
- **`pre` 规则在迁移时丢了**（真回归）。原 `main.css:61` 有 `pre{overflow-x:auto}`，
  我的第一版没有，导致长代码行把整页撑到 **750px 宽**——窄屏全站右半被切。
  已补回账簿版 `pre`（`--code` 底 + 细线 + 2px 圆角 + 等宽 + 横向滚动），
  并给 `code` 分档：桌面 `break-word`（不把 `plan_digest` 拦腰斩断），≤720 切 `anywhere`（防撑破）。
- **`proofs` 页有两处硬写夜场色的内联 `style`**（`background:#0d1710;color:#e9f2ec`），
  纸白底上糊成一条黑杠、占位文字完全不可读。已在 `ledger.css` 里用属性选择器 + `!important` 就地拉回。
  **根治要改 `website/content/proofs.md` 去掉内联样式**，那是内容改动，本轮没动。
- **docs 侧栏带 UA 圆点**。`.docs-side a` 是 `display:block`，但外层 `<ul>` 没人管，
  29 篇文档的目录都挂着小黑点。已补 `.docs-side ul{list-style:none;padding:0}`。
- **首页三张牌上的 `SEALED` 压在相邻牌下**。不是裁切 bug，是牌扇正常叠压——
  但 9.5px/0.12em 的字宽刚好越过可见区，读成 "SEALE"。降到 8.5px/0.1em。
- **出图管线两个静默 bug**（都不影响设计本身，但会让交付物不可信）：
  探针 iframe 不设 `width` 时默认 300px，正文被压窄后 `scrollHeight` 虚高近 2 倍，
  首轮 41 张全带 1000–4600px 尾部空白；窄屏那轮写死 1200px 高，12 张全被裁断。
  现在两处都按目标视口宽度量高，并加了 `trim()` 兜底裁尾。
- **`.wrap` 窄屏左右留白 24px 偏大**（390 视口下正文只剩 342px）。已加 ≤560 → 16px。
- **夜场那轮 13 张是逐字节重复的假图**（最严重的一条，靠比对 md5 才发现）。
  `ledger.css` 的夜场挂在 `html[data-ground="night"]` 上，而站点模板的 `<html lang="zh-CN">`
  没有这个属性 —— 只覆盖 CSS 不写属性，夜场渲染出来就是纸白。
  现在 `site_shoot.py` 会先把 `data-ground` 写进 `dist` 的每个 `<html>`（构建产物，可安全改），
  再出图。**这条也说明：夜场图必须和纸白图比 md5 才算验证过，光看图看不出来。**

### 仍未达（按严重度排）

1. **数字列贴右对齐**——见下。
2. **`.explorer-live` 实时态未演练**：本轮起 HTTP 出图时 `/api/v1/*` 全部 404，
   实时块走的是静态回退分支。骨架屏、加载失败态、水位缺口态都没画过。
3. **720–900 区间的表格横滚体验未验证**：只出了 1280 与 390 两档。
4. **`</li>` 字面量泄漏**：`docs/proofs/verify` 等页的有序列表末尾渲染出裸 `</li>` 文本，
   来自 Markdown 源里的原始 HTML，属内容 bug 不属样式，本轮未改。

## 已知缺口（不藏）

- **数字列贴右对齐做不到**：Markdown 表格不能带类名，目前只能靠 `tabular-nums` 做到
  **等宽对齐**而非**贴右**。要真右对齐需在 `build.py` 的表格渲染里给纯数字列加
  `class="num"`（约 6 行）。我没有擅自改生成器。
- **`.explorer-live` / `[data-explorer]` 实时块**由 JS 注入，本轮只在静态数据下验证；
  实时态的骨架屏与错误态未演练。
- **窄屏做了 900 / 720 / 560 三档**，720 那档是为表格横滚与长标识符断行新加的；
  720–900 区间仍未出图验证。
- **品牌文件未同步**：`media-kit/v0.1/brand.css`、`colors.md`、`typography.md`
  仍以夜场为基线，与本轮"纸白为默认"冲突。见上面「需要你拍板的品牌改判」。
