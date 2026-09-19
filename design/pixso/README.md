# ZChain Wallet · Pixso 导入包

由 `design/pixso/build-pixso-import.js` 从两套已有设计稿自动抽取生成，剥离了「总览/交互」外壳与切换脚本，
使每一屏都以**固定 380×600 画板**静态可见，供 Pixso `code_to_design` 导入。
品牌 token 全部同源 `website/media-kit/v0.1`，未改动。

两套方向并排对照：

| 方向 | 设计语言 | 底色 | 屏数 | 设计系统板 |
|---|---|---|---|---|
| **A 毡布绿** | 夜色牌桌 / 发光翡翠 / 圆角胶囊 | 夜场深色 | 18 | 9 |
| **B 账簿 Ledger** | 纸白账格 / 细线 / 等宽数字 / 印章 | 纸白（可切夜场） | 17 | 14 |

## 文件

- `pixso-a-felt.html` — 方向 A 整板（18 屏 + 9 设计系统板，网格排布，带编号与屏名）
- `pixso-b-ledger.html` — 方向 B 整板（17 屏 + 14 设计系统板）
- `pixso-a-felt.screens/01-welcome.html … 18-settings.html` — 方向 A 逐屏独立文件，每个正好 380×600
- `pixso-b-ledger.screens/01-welcome.html … 17-proofs.html` — 方向 B 逐屏独立文件

## 导入 Pixso（推荐：把 file_key 发我，我来转）

Pixso MCP 的每个写操作都需要 `file_key`，且无法自动定位当前打开的文件。所以：

1. 在 Pixso 新建一个设计文件（团队/个人均可），打开它。
2. 复制浏览器地址栏 URL（形如 `https://pixso.cn/app/design/<file_key>?...`），发给我。
3. 我用 `code_to_design` 把逐屏文件按 380×600 导入，组织成并排对照的页面：
   - `A · 毡布绿 / Screens`、`A · 毡布绿 / Design System`
   - `B · 账簿 / Screens`、`B · 账簿 / Design System`
   导入后我会逐屏校验字体回退与图标，再收尾。

> 建议先导 1 屏样张验证还原度（字体、SVG 图标、等宽数字对齐），确认后再铺全量。

## 自助导入（不经过我）

- 用浏览器打开 `pixso-a-felt.html` / `pixso-b-ledger.html`，整板复制，在 Pixso 里粘贴或走 HTML 导入。
- 逐屏文件可直接拖入 Pixso 画布。

## 重新生成

设计稿若更新，重跑：

```bash
node design/pixso/build-pixso-import.js \
  design/zchain-wallet-ui.html \
  design/pixso/pixso-a-felt.html \
  "ZChain Wallet · 方向 A 毡布绿 (Night)"

node design/pixso/build-pixso-import.js \
  design/zchain-wallet-ui-b-ledger.html \
  design/pixso/pixso-b-ledger.html \
  "ZChain Wallet · 方向 B 账簿 Ledger (Paper)" paper
```
