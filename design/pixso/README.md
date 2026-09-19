# ZChain Wallet · Pixso 导入包

从两套已有设计稿自动抽取生成，剥离了「总览/交互」外壳与切换脚本，
使每一屏都以**固定 380×600 画板**静态可见，供 Pixso `code_to_design` 导入。
品牌 token 全部同源 `website/media-kit/v0.1`，未改动。

两套方向并排对照：

| 方向 | 设计语言 | 底色 | 屏数 | 设计系统板 | 生成器 |
|---|---|---|---|---|---|
| **A 毡布绿** | 夜色牌桌 / 发光翡翠 / 圆角胶囊 | 夜场深色 | 18 | 9 | `build-pixso-import.js`（静态抽模板） |
| **B 账簿 Ledger** | 纸白账格 / 细线 / 等宽数字 / 印章 | 纸白（可切夜场） | 19 | 14 | `build-pixso-shot-export.mjs`（运行时导出） |

> B 为什么换成运行时导出：方向 B 的 `t-acct` 是**一份模板实例化三次**（ZChain / EVM / Starknet
> 三个数据面，靠 `applyChain()` 切换）。静态抽模板会把三块板塌缩成一块，且跳过 `applyChain`
> ——那块板里三链面板同时可见，是坏板。新脚本让原型自己渲染完再取 DOM，因此屏数与
> 原型 `SCREENS` 注册表严格一致（19 屏），并额外产出整屏版。

## 文件

- `pixso-a-felt.html` — 方向 A 整板（18 屏 + 9 设计系统板，网格排布，带编号与屏名）
- `pixso-b-ledger.html` — 方向 B 整板（19 屏 + 14 设计系统板）
- `pixso-a-felt.screens/01-welcome.html … 18-settings.html` — 方向 A 逐屏独立文件，每个正好 380×600
- `pixso-b-ledger.screens/01-welcome.html … 19-settings.html` — 方向 B 逐屏 380×600（popup 首屏）
- `pixso-b-ledger.screens/NN-<id>__full.html` — 方向 B 同屏整屏版（按内容撑高；13 屏内容超出 600px，评审完整内容用它）
- `pixso-b-ledger.screens/ds/01-ds-0.html … 14-ds-13.html` — 方向 B 设计系统板（1240 宽）

## 导入 Pixso（推荐：把 file_key 发我，我来转）

Pixso MCP 的每个写操作都需要 `file_key`，且无法自动定位当前打开的文件。所以：

1. 先完成 Pixso MCP 的 OAuth 授权（Qoder 连接器面板里点「授权 / 连接」，scope `mcp:connect`）——
   未授权时每个调用都会返回 `[Pixso MCP] MCP authentication service is temporarily unavailable`。
2. 在 Pixso 新建一个设计文件（团队/个人均可），打开它。
3. 复制浏览器地址栏 URL（形如 `https://pixso.cn/app/design/<file_key>?...`），发给我。
4. 我用 `code_to_design` 把逐屏文件按 380×600 导入，组织成并排对照的页面：
   - `A · 毡布绿 / Screens`、`A · 毡布绿 / Design System`
   - `B · 账簿 / Screens`、`B · 账簿 / Design System`
   导入后我会逐屏校验字体回退与图标，再收尾。

> 建议先导 1 屏样张验证还原度（字体、SVG 图标、等宽数字对齐），确认后再铺全量。

## 自助导入（不经过我）

- 用浏览器打开 `pixso-a-felt.html` / `pixso-b-ledger.html`，整板复制，在 Pixso 里粘贴或走 HTML 导入。
- 逐屏文件可直接拖入 Pixso 画布。

## 重新生成

设计稿若更新，重跑（方向 A 用静态抽取，方向 B 用运行时导出）：

```bash
node design/pixso/build-pixso-import.js \
  design/zchain-wallet-ui.html \
  design/pixso/pixso-a-felt.html \
  "ZChain Wallet · 方向 A 毡布绿 (Night)"

node design/pixso/build-pixso-shot-export.mjs          # 默认即方向 B / paper / 整屏版一起出
# 夜场底色另出一套：
node design/pixso/build-pixso-shot-export.mjs \
  --ground=night --out=./pixso-b-ledger-night.html \
  --title="ZChain Wallet · 方向 B 账簿 Ledger (Night)"
```

B 的脚本需要 Chrome for Testing（定位方式同 `design/figma/build.mjs`，`ZCHAIN_CFT_CHROME` 可覆盖）。
参数：`--src` `--out` `--title` `--ground=paper|night` `--only=id1,id2` `--no-aggregate` `--no-full`。
