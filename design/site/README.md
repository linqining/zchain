# ZChain 站点 · 账簿 Ledger 体系 v1.1

把牌桌稿（`design/table/`）与钱包方向 B（`design/zchain-wallet-ui-b-ledger.html`）已成立的
账簿体系，铺到**营销站 `website/`** 与**牌桌客户端其余页**。
v1.0 已并入主样式并出齐全站 41 页逐页图；v1.1 是**移动端增量层**（尚未并入主样式，见末两节）。

## 打开

```bash
open design/site/zchain-site-ui.html         # 桌面体系板 S0–S10，右上角切纸白/夜场
open design/site/zchain-site-mobile-ui.html  # 移动体系板 M0–M6（文档本身就是 390 宽）
open design/review/index.html                # 总评审台：143 张，桌面/夜场/移动/移动夜场/三档抽查
```

体系板整页出图：

```bash
BOARD="design/site/zchain-site-ui.html:board"        python3 website/tools/cdp_shoot.py
BOARD="design/site/zchain-site-mobile-ui.html:mobile-board" python3 website/tools/cdp_shoot.py
GROUND=night BOARD="design/site/zchain-site-mobile-ui.html:mobile-board" python3 website/tools/cdp_shoot.py
```

> **两个踩过的坑**：
> 1. 板子用相对路径 `<link href="../../website/assets/css/main.css">` 引用样式源。
>    把 HTML 拷到别处（如 `/tmp`）再截图，会静默截成**无样式**页面且没有任何报错。
>    必须在 `design/site/` 原地渲染。
> 2. **这台机器上 headless Chrome 已不可用**（含 Chrome for Testing bundle）——
>    在 `gpu_data_manager_impl_private.cc:417` 直接自杀，`--disable-gpu` / `--no-sandbox` /
>    swiftshader / `--headless=old` / `--single-process` 全部无效，连 `about:blank` 都不出图。
>    所有出图走 `website/tools/cdp_shoot.py`：起一个挪出屏幕外的**有头**实例，
>    用 CDP 的 `Emulation.setDeviceMetricsOverride` 定视口后截图。

## 文件

| 文件 | 是什么 |
|---|---|
| `website/assets/css/main.css` | **唯一样式源**（已落地）。94 个站点类名 1:1 覆盖，`design/site/ledger.css` 已删除并入该文件 |
| `ledger-mobile.css` | 移动端**增量层**（未并入），只放 `@media` 与移动专属规则，段号 M1–M6 |
| `zchain-site-ui.html` | 桌面体系板 S0–S10，用站点真实原文与真实类名渲染 |
| `zchain-site-mobile-ui.html` | 移动体系板 M0–M6，390 宽排版，`<link>` 主样式 + 增量层 |
| `pages/` | 全站逐页图，六档（桌面/夜场 × 1280，移动/夜场移动/360/430） |
| `png/` | 体系板出图 |
| `website/tools/cdp_shoot.py` | CDP 出图（桌面 / 移动 / 板子三模式） |
| `website/tools/site_shoot.py` | 被上面复用：`apply_ground()` 写底、`label_tables()` 注 `data-label`、`RAIL_JS` 轨道定位、`apply_mobile_layer()` 叠加 |
| `website/tools/audit_mobile.py` | 41 页移动还原度程序化走查（7 项断言，支持 `SLUGS=` 定点复跑） |

## 落地状态（v1.0）

样式源已经是入库的 `website/assets/css/main.css`，不再是"替换件"。落地时**确实改了内容/生成器**三处，
都是为了让体系完整生效，不是可选优化：

| 改动 | 为什么必须 |
|---|---|
| `build.py` 给"整列都是量"的列挂 `class="num"` | Markdown 表格不能带类名，不挂类就永远做不到贴右对齐。`0x…` 哈希与含省略号的地址由生成器判定后留在左对齐 |
| `content/proofs.md` 去掉两处硬写夜场色的内联 `style=` | 纸白底上糊成黑杠、占位文字不可读。原来靠 CSS `!important` 兜底，现在根治，全站内联 `style=` 归零 |
| `templates/*.html` + `assets/js/ground.js` | 夜场是 `html[data-ground="night"]` 选择器，而模板的 `<html>` 没有这个属性 —— 不加切换控件，夜场在站点上**根本不可达** |
| `build.py` 的 raw HTML 块改为"吃到空行" | 旧口径按"连续以 `<` 开头的行"截断，`<li>` 内部软换行会让行尾 `</li>` 被转义成页面上的字面量（proofs 页可见）|

底面优先级：标记里显式写死的 `data-ground` > `localStorage.zchain-ground` > `prefers-color-scheme`。
首帧由模板内联脚本决定，避免纸白↔夜场闪白。

## 夜场不丢：这轮是叠加式的

夜场段 14 个基色 token **逐字沿用**改版前的站点色（`media-kit/v0.1/brand.css` 已改为由
`main.css` 生成，夜场块未动）。所以：

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

## 品牌改判已落（原「需要拍板」清单）

按「纸白为默认」这条决策，三份品牌文档已同步到 **v0.1.1**（目录名仍叫 `v0.1`，
因为站点正文里"media-kit v0.1"是被引用的可引用版本号，改目录名会打断引用；版本变更
写在文件内部）：

1. `website/media-kit/v0.1/brand.css` —— 由脚本从 `main.css` 重新生成：paper 为默认块，
   night 块逐字保留改版前的 14 个 token。
2. `website/media-kit/v0.1/colors.md` —— 双底两张 token 表 + `-w` 着色令牌
   （纸白用实色、夜场用 alpha）的说明 + 逐组合实测对比度。
3. `website/media-kit/v0.1/typography.md` —— 按实测字号重写，并补「等宽的使用边界」、
   「不用字重当层级」「数字列口径」「标题 balance」四条纪律。

实测对比度（`check_a11y.py` 现在解析 `main.css` 的两套底，不再写死夜场）：
纸白底最低 **5.52**（`danger on danger-w`）、最高 18.27（`text on surface`）；
夜场底最低 **5.29**（`muted-2 on surface-2`，即表头真实配色）、最高 18.00（`text on bg`）。
品牌线 ≥ 5.2:1 两套底各自全通过。
（这两个最低值本身是这轮抓出来的：旧检查器只按夜场底算，掩盖了两处真实违规，
靠把 `--muted-2` 与 `--amb` 各调一档才达标。）

## 逐页铺开顺序（已按此顺序落地）

**第一梯队**（体系收益最大、结构最简单）：
`index.md`（hero + 统计带 + 三入口）→ `product.md` → `transparency.md` → `status.md`

**第二梯队**（表格为主，靠 S6 的表格改造直接吃到收益）：
`explorer.md` → `proofs.md` → `roadmap.md`

**第三梯队**（长文，靠 S7 的 docs 布局与 74em 行长）：
`technology.md` → `security.md` → `developers.md` → `docs/*` → `community.md` → `legal.md`

**牌桌客户端其余页**：`/` 首页、`/lobby` 大厅、`/dashboard`、`/whitepaper`、静态页、404 ——
这些是 React + styled-components，不能直接吃 `main.css`，需要把令牌注入
`client/src/styles/theme.ts`（现桌 theme 是紫蓝 SaaS 值），再按牌桌稿的同一路径逐组件替换。

## 全站逐页出图（已完成）

```
python3 website/build.py                                   # 41 页 → website/dist
DSF=1 python3 website/tools/cdp_shoot.py                   # 纸白 41 页 @1280
GROUND=night TOPLEVEL=1 DSF=1 python3 website/tools/cdp_shoot.py  # 夜场 13 顶层页
MOBILE=1 python3 website/tools/cdp_shoot.py                # 窄屏 @390（叠加移动适配层）
python3 design/review/build.py                             # 刷新总评审台
```

`main.css` 就是入库的唯一样式源，出图工具不再往 `dist/` 里覆盖任何 CSS：
两个 shooter 都会在 `dist/assets/css/main.css` 与入库源不一致时**直接退出**（`dist` 过期）。
只有 `MOBILE=1` 是例外——它把尚未并入主样式的 `ledger-mobile.css` + `data-label` +
横滑轨定位脚本叠进 `dist` 预览，跑前必须是刚 `build.py` 出来的干净产物。

为什么默认走 `cdp_shoot.py` 而不是 `site_shoot.py`：这台机器上 headless Chrome
（含 Chrome for Testing bundle）会在 `gpu_data_manager_impl_private.cc:417` 直接自杀，
`--disable-gpu` / `--no-sandbox` / swiftshader 均无效。`cdp_shoot.py` 起一个挪出屏幕外的
有头实例，用 CDP 的 `Emulation.setDeviceMetricsOverride` 定视口后整页截图，
不需要高度探针。产物在 `design/site/pages/{desktop,desktop-night,mobile}/<slug>.png`。

## 全站还原度走查（41 页逐页 + 13 页夜场 + 12 页窄屏）

走查方式不是抽查截图，是**先把 41 页的 DOM 全量比对类名，再按比对结果定点看图**。
比对脚本口径：从 `dist/**/*.html` 收集所有 `class="…"`，与 `main.css` 的选择器集合求差。

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
  纸白底上糊成一条黑杠、占位文字完全不可读。**已根治**：`website/content/proofs.md`
  去掉内联样式，改挂 `.input` / `.btn` 两个体系类名，主样式里因此不需要任何
  `[style*=…] { … !important }` 的兜底带。
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
  夜场块挂在 `html[data-ground="night"]` 上，而站点模板的 `<html lang="zh-CN">`
  没有这个属性 —— 只覆盖 CSS 不写属性，夜场渲染出来就是纸白。
  现在 `site_shoot.py` 会先把 `data-ground` 写进 `dist` 的每个 `<html>`（构建产物，可安全改），
  再出图。**这条也说明：夜场图必须和纸白图比 md5 才算验证过，光看图看不出来。**

### 仍未达（按严重度排）

1. **`.explorer-live` 实时态未演练**：本轮起 HTTP 出图时 `/api/v1/*` 全部 404，
   实时块走的是静态回退分支。骨架屏、加载失败态、水位缺口态都没画过。
2. **720–900 区间的表格横滚体验未验证**：只出了 1280 与 390 两档
   （移动体系层另有 360 / 430 抽查，仍不覆盖 720–900）。

### 落地后重出图这一轮自己踩出的三个回归（都已修，逐条附证据）

按 md5 确认 41 张桌面 + 13 张夜场全部重出、且纸白/夜场两两不同之后，定点看图查出三条：

1. **`.kv` 被我一律做成了两列 grid**，而站点里 `class="kv"` 只出现在 `proofs.md`
   的两段**说明文字**上（`.k`/`.v` 全站零使用）。grid 把段里每个 `<code>` 变成网格项，
   句子读成"或  `--public`  启动（CORS *）"这种断裂节奏。
   现在 grid 只在 `:has(> .k)` / `:has(> dt)` 时生效，散文回到改版前的等宽段落；
   体系板上的账目行经 CDP 复测仍是两列 grid（`427px 105px` 等），没有被一起改掉。
2. **`.task` 勾选行**：`build.py` 给每个列表项都挂 `.li`，`.li{display:block}` 与
   `.task{display:flex}` 同特异性且排在后面，于是 flex 一直没生效、方框和文字粘在一起
   （roadmap 页）。先把 `.li` 挪到前面让 flex 生效，发现 flex 又会把行内 `<code>`
   拆成弹性项 —— 最终改成**悬挂方框**（`position:absolute` + 24px 缩进），
   并补 `.ul-list > .li.task` 把被 `.ul-list > .li{padding-left:2px}` 吃掉的缩进要回来。
3. **`build.py` 的 raw HTML 块按"连续以 `<` 开头的行"截断**，`<li>` 内部软换行的续行
   因此被当成新段落，行尾 `</li>` 转义成页面上的字面量。改成吃到空行为止
   （CommonMark HTML 块口径），改前全仓扫描确认这种"HTML 行后紧跟非空非 HTML 行"
   只有 1 处，就是出错那处；重建后 diff 只有 `proofs/index.html` 变化。

另外补了一条排版规则：首屏大标题 `text-wrap: balance`。中文没有空格分词，
15 字标题在 1280 下会自然折出「…结算记 / 录。」的孤字行。已同步进 `typography.md` 第 7 条。

## 移动端适配（v1.1 增量层，**尚未并入主样式**）

`design/site` 是响应式**网站**，不是 App flow，所以没有套移动端 App 的范式
（底部 TabBar / 抽屉 / 安全区驱动的导航折叠）。三处按网站的做法在窄屏换掉做法，
其余全部沿用主样式的 token——移动层**不新增任何 token**（颜色、字号阶、圆角、阴影一律
取自主样式 `:root` / `html[data-ground="night"]`；唯一的字面色是 chip 轨 `mask-image` 里的
`#000` 透明度停靠点，只当 alpha 用、不上屏），窄屏改的是既有类名在断点处的取值。

| 决定 | 选了什么 | 为什么不是别的 |
|---|---|---|
| 主导航 | 顶部**横滑 chip 轨**（13 项全可见，渐隐提示可滑） | 390 下主样式只把 `.site-nav` 变全宽，13 个链接折成两行，吸顶头变成一大块。汉堡抽屉要新增一层状态且藏起全站入口，底部 tab 是给 App 的、站点只有 13 个平级页没有"首页/我的"这种分组 |
| 表格页（explorer / status / proofs / roadmap…） | 表转**「凭证行」卡**：每个 `<tr>` 一张账簿小票，字段竖排 k/v | 主样式在 720 下是整表横滚，七列的 explorer 一屏只容得下 2–3 列＝读不了。横滚对"扫一眼这行"的账簿动作是反的 |
| 范围 | 移动体系板 + **全部 41 页** + 360/390/430 三档抽查 | 只出代表作等于没验证——审计脚本 41 页全跑才能抓到 explorer 那张唯一会被 64 位哈希撑破的表 |

### 打开

```bash
open design/site/zchain-site-mobile-ui.html   # 体系板 M0–M6，本身就是 390 宽的文档
```

> 板子必须在 390 下排版。媒体查询按**视口**生效、不按容器，把板子塞进 1280 页面里的
> 390 宽框是假的——那样验的不是真 CSS。所以板子 `<body>` 就是 390 的排版宽度。

```bash
MOBILE=1 python3 website/tools/cdp_shoot.py                       # 41 页 @390
VW=360,430 SLUGS=home,explorer,docs-protocol-abi MOBILE=1 python3 website/tools/cdp_shoot.py   # 多档抽查
GROUND=night TOPLEVEL=1 MOBILE=1 python3 website/tools/cdp_shoot.py               # 夜场 13 页
python3 website/tools/audit_mobile.py                             # 41 页程序化走查
BOARD="design/site/zchain-site-mobile-ui.html:mobile-board" \
  python3 website/tools/cdp_shoot.py                              # 重出体系板
```

产物在 `design/site/pages/{mobile,mobile-night,mobile-360,mobile-430}/`（41 / 13 / 3 / 3 张），
板子在 `design/site/png/mobile-board-{paper,night}.png`。

### 段落

`ledger-mobile.css` 的段号与体系板 M0–M6 一一对应（首轮两边各编各的号，M2/M3/M4 错位，
已按板子口径重排；重排后先比过 2 张出图逐字节相同，并静态确认九段 `@media` 之间
没有选择器重叠，所以纯移动不改层叠）。

| 段 | 断点 | 管什么 |
|---|---|---|
| M1 | ≤720 | 顶部横滑 chip 轨（grid 两行：brand+toggle / nav；`mask-image` 做两端渐隐；`@media (hover:none)` 关掉 hover 唯一反馈） |
| M2 | ≤720 / ≤400 | 首屏与栅格：标题 30px、`.cta-row` 纵向铺满、三入口与 `grid-2/-3` 转单列、`.stat-band` 四格转两格再转单格 |
| M3 | ≤560 | 表格转凭证行卡（`td::before{content:attr(data-label)}`）+ `table:not([data-labeled])` 的整表横滚兜底 |
| M4 | ≤900 | docs 目录转吸顶小节轨，`:has(a.active)` 只留当前分组 |
| M5 | ≤560 | 正文节奏、表单与状态（h2 19px、行高 1.78、`blockquote` 收 UA 缩进、`.kv` 转单列、`.banner-tag` 独占一行） |
| M6 | ≤720 | 页脚单列、链接 40px 命中区、`padding-bottom:max(20px, env(safe-area-inset-bottom))` |

### 移动落地补丁（约 10 行，**不做则凭证行卡不成立**）

凭证行卡要每个 `<td>` 知道自己列的表头文字，**纯 CSS 拿不到兄弟元素文本**，所以必须有
`data-label`。站点表格由 `build.py` 从 Markdown 生成，目前不带这个属性。
本轮出图是在 `dist` 的**私有临时副本**里注入的（延续"只改构建产物、不碰入库文件"），
落地要把这个动作搬进生成器：

1. **`website/build.py` `flush_table()`**（`website/build.py:219`）——`cell()` 现在只认 `class="num"`，
   补一个 `data-label`（只依赖文件里已有的 `re` / `_inline`）：

   ```python
   def cell(tag: str, i: int, text: str) -> str:
       cls = f' class="num"' if i in num else ""
       lab = ""
       if tag == "td" and i < len(thead) and thead[i].strip():
           # 表头渲染成行内 HTML 后摘掉标签＝纯文字；_inline 用 quote=False，
           # 所以进属性只需再处理双引号。
           plain = re.sub(r"<[^>]+>", "", _inline(thead[i]))
           lab = ' data-label="%s"' % plain.replace('"', "&quot;")
       return f"<{tag}{cls}{lab}>" + _inline(text) + f"</{tag}>"
   ```

   并把 `parts = ["<table>", "<thead><tr>"]` 的第一项改成 `'<table data-labeled="1">'`。
   工具侧的等价实现是 `site_shoot.label_tables()`（`_TAG.sub("", …)` + `replace('"', "&quot;")`），
   两处口径必须一致，否则出图与入库站点的凭证卡标签会对不上。
   **没有 `<thead>` 的表不要打 `data-labeled`** ——
   CSS 的 `table:not([data-labeled])` 兜底就是为它们准备的，会退回整表横滚而不是渲染空白行。

   **这段补丁已经照原样验过**：把上面两处改动原样打到 `website/` 的一份临时副本上重建，
   41 页里取到的 `data-label` 与出图时注入的那份**逐页逐字节一致**，并且剥掉这两个属性后
   与入库 `dist` **41/41 逐字节相同**（即除属性外不改动任何页面内容）。
   落地这一步本身没有未知量，不需要再试。

   > 抄这段时注意一个巧合：工具侧 `_TH.findall()` 在 `<thead>` 区域内会先把 `<thead>` 本身
   > 当成一个 `<th>`（`<th[^>]*>` 匹配得到 `thead`），于是第 1 列"表头文字"是
   > `<tr><th>频道` 这种串——它靠后面那次摘标签**恰好**被修掉。
   > 生成器侧走的是 `thead` 这个 markdown 列表，不受这个坑影响；
   > 但如果改用"从渲染后的 HTML 反推标签"的写法，就必须先摘标签再解码，顺序反了就崩。

2. **`ledger-mobile.css` 整段追加**到 `website/assets/css/main.css` **末尾、`@media print` 之前**。
   媒体查询不加权重，同特异性靠后者生效，追加位置错了 M3 就压不住主样式 720 档的整表横滚。

3. **轨道定位 JS 7 行**（`site_shoot.RAIL_JS`）落成 `website/assets/js/rail.js`，
   并在**两个模板各加一行**：`templates/base.html:47` 与 `templates/docs.html:56`
   各自写死了 `<script src="/assets/js/ground.js" defer>`（模板里没有共用的脚本占位符），
   挨着它加即可。
   它把 `.site-nav` 与 `.docs-side ul` 的 `a.active` 横向居中——静态截图看不到滚动位置，
   评审图必须能看出"当前项在轨里"；对真实用户同样有用（深链进 docs 子页时直接定位到当前小节）。
   **两个坑已踩过**：`scrollLeft` 必须设在真正会滚的
   `.site-nav` 上（`.nav-list` 是 `width:max-content` 的被卷内容，设在它身上等于没设）；
   算偏移要用 `getBoundingClientRect()` 差值，不能用 `offsetLeft`
   （`.site-header` 是 `position:sticky`，会当 `offsetParent`，靠后的项会滚过头）。

这三处不落地，`mobile*/` 那批图就**不代表入库站点**。
第 1、2 条**没有未知量**：补丁已照原样在临时副本上跑通并逐字节对账（见上），
第 3 条是纯搬运 + 一行模板接线。

### 移动还原度走查（41 页程序化，不是看图）

`website/tools/audit_mobile.py` 起同样的 CDP 通路，逐页断言 7 项，41 页全跑：
横向溢出 `max(docSW,bodySW)-vw`、触控目标 <40px、凭证卡标签覆盖率、chip 轨可横滑且
`active` 在视野内、字号（**分两层**：正文 ≥12px，`st`/`chip`/`kicker`/`banner-tag`/`breadcrumb`
及任何带 `letter-spacing` 的微标签 ≥9.5px）、真正跑到视口外的元素（排除滚动容器内）、
**状态丸被拉成通栏**（值列里带底色且宽度 ≥ 该列 85% 的短文本子项）。

结果：**390px 审计 41 页，0 页有未达项；55 张表全部带 `data-label`；横向溢出全部 +0**。
支持 `SLUGS=explorer,status` 定点复跑，改一条 CSS 不必等 41 页。

> **第七条断言本身是补出来的，而且第一版是假的**：基准我用了整个 `td` 的内容宽（342px），
> 而值列只有 232px，比例最高 0.72，永远够不到 0.85 阈值——**把修复注掉重跑，它照样全绿**。
> 第二版又踩了一次：探针是 Python 原始字符串，我写成 `split(/\\s+/)`，JS 里变成匹配
> 字面反斜杠，`gridTemplateColumns` 没被切开、退回整 td 基准，还是全绿。
> 两次都是靠**负向测试**（临时删掉那条 CSS 规则，看审计是否报警）抓出来的：
> 修好之后 explorer/status 各报 6 个 100% 拉伸、proofs 干净（它的表里没有丸）。
> **任何"新增的断言"都必须先证明它能报出它要防的那个错，否则它是装饰。**

这一轮抓出来并修掉的（都不是"看图能看出来"的）：

- **explorer 横向溢出 +261px**（真设计缺陷）：卡片模式 `值` 列里 64 位哈希是纯文本、
  不在 `<code>` 内，没有任何可断点。补 `table td{overflow-wrap:anywhere}`。
- **状态丸在凭证卡里被拉成通栏色条**（同一张图上看桌面还原度时抓到）：`.st`/`.chip` 是
  `inline-block`，落进 `td` 的网格后作为网格项默认 `justify-self:stretch`，于是填满整个值列；
  桌面它是贴文字的。补 `table td > .st, table td > .chip { justify-self: start; }`。
  只收这两个类——`.meter` 那类线性量具本来就该铺满值列。
- **体系板 M0 的规格数字和 CSS 对不上**（自己的稿子没对账，这轮逐条回查主样式后修掉三处）：
  写了「正文 15px」而移动层从没改过字号（真实值 15.5px，只把行高从 1.68 抬到 1.78）；
  写了「桌面页标题 40」而主样式是 `clamp(24px,3vw,32px)`（1280 下 32）；
  写了「390（iPhone 15）」而 iPhone 15 的逻辑宽是 393。
  另外把「44 导航 chip / 主操作」拆开——首屏主 CTA 实际是 48px，和导航 chip 不是一档。
  **板子是验收依据，它写错的数会被当成设计意图验收过去**，所以逐条比的是 CSS 而不是记忆。
- **导航链接数写成了 12**（板子 + CSS 注释 + README 三处），实际 13 项。已按 `dist` 里
  `.site-nav` 的真实 `<a>` 计数改正。
- **`ground-toggle` 触控只有 32px**，抬到 40px，体系板 M0 文案同步改。
- **审计时序竞态**：脚本原来只挂 `window.load`，审计从 `readyState==complete` 只等 600ms，
  同一份 CSS 两次跑出不同结果（失败页数反而变多）。现在 load 与 DOMContentLoaded 双挂，
  审计侧轮询最多 5 次 × 400ms。
- **字号判据误报**：把账簿体系故意的 9.5px 微标签层当成违规，才分出上面的两层阈值。
- **出图侧两个坑**：`captureBeyondViewport:true` 会把横向滚动轨算进画幅（explorer 从 390
  变成 651 CSS px 宽），改成量高后二次 `setDeviceMetricsOverride` 拉高视口按视口截图；
  体系板出图默认落到 1280 宽，**媒体查询根本不触发**，出一张"看起来是移动"的桌面压窄图。
- **板子夜场又是逐字节重复**：`BOARD` 模式没传 `?g=`，模板 `<html>` 写死 paper。
  和桌面那轮同一类错误，第二次犯。**结论：任何"切底"产物都必须比 md5，`guard_duplicates()`
  现在已经同时守 desktop↔desktop-night 和 mobile↔mobile-night 两对。**
- **并行会话竞态**：`dist` 是共享构建产物，实测有并行会话在跑 `build.py`，
  刚注入的 `data-label` 会被别人清空，出图和审计一起拿到基线态且**不报错**。
  现在 `staged_dist()` 先把 `dist` 复制进私有临时目录再叠加，一次运行看到的是固定快照；
  审计自己准备被测状态。

### 移动仍未达（按严重度排）

1. **`.explorer-live` 实时态在窄屏未演练**：出图时 `/api/v1/*` 全 404，走的是静态回退分支。
2. **720–900 区间未出图验证**：只有 360/390/430/560/720/900/1280 的断点声明，
   720–900 这一段（表格横滚兜底与 docs 轨的交接带）没有图。
3. **真机手势未验**：横滑轨的橡皮筋滚动、`overscroll-behavior-x:contain` 是否真的
   不抢页面纵向滚动，只在 Chromium 移动端仿真下看过。
4. **`data-label` 落地前 `mobile*/` 不代表入库站点**（见上）。


## 已知缺口（不藏）

- **`.explorer-live` / `[data-explorer]` 实时块**由 JS 注入，本轮只在静态数据下验证；
  实时态的骨架屏与错误态未演练。
- **窄屏做了 900 / 720 / 560 三档**，720 那档是为表格横滚与长标识符断行新加的；
  720–900 区间仍未出图验证。
- **移动体系层尚未并入主样式**：`ledger-mobile.css`（M1 横滑导航 / M3 凭证行卡 /
  M4 docs 吸顶轨）目前只在 `MOBILE=1` 出图时叠进 `dist` 的私有副本预览，M3 依赖的
  `td[data-label]` 与横滑轨定位脚本也还在那条预览路径里注入。落地补丁见
  「移动落地补丁」一节；三处不落地，`mobile*/` 那批图不代表入库站点。
- **令牌漂移**：本次两处对比度微调（`--muted-2`、`--amb`）只同步了站点与
  `media-kit`，`extension/popup/popup.css` 与 `wallet-app/mobile/www/css/app.css`
  仍是旧值，属另外两个产品自己的验收面。
