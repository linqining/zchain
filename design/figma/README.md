# ZChain Wallet 移动版 · Figma / Pixso 导入包(方向 B「账簿 Ledger」)

由 `build.mjs` 从 `wallet-app/mobile/www`(设计稿 19 屏的手机尺寸移植,393 逻辑宽)
批量产出,供把设计铺进 Figma / Pixso,并作为原生客户端(Kotlin Compose / SwiftUI)
的视觉规格基线。

## 产物

| 路径 | 内容 |
| --- | --- |
| `png/NN-<id>__paper\|night.png` | 19 屏 × 双底色,内容撑满高度,@3x(1179px 宽) |
| `png/NN-<id>__*_vp.png` | 同屏的手机视口首屏(393×852 @3x) |
| `screens/NN-<id>__*.html` | 逐屏独立 HTML(CSS/图标内联、固定画板)——可编辑导入的原料 |
| `tokens.json` | Tokens Studio 兼容令牌(纸白/夜场两套 + base),含 `$themes` |

屏幕清单与设计稿一致(01-welcome … 19-settings,账簿模板 ×3 链)。
重新生成:`node design/figma/build.mjs`(依赖 Chrome for Testing,定位逻辑同 e2e)。

## 导入 Figma

三条路,按需选:

1. **图片直贴(最快)**:把 `png/` 全选拖进 Figma 画布,按 `NN-` 编号排两列
   (左 paper 右 night)。适合评审/对照,不可编辑。
2. **可编辑图层**:Figma 装 **html.to.design** 插件 → 把 `screens/*.html`
   逐屏导入,转成可编辑图层(字体回退、SVG 图标导入后需人工过一遍)。
3. **设计变量**:Tokens Studio 插件 → Import → 选 `tokens.json` → 生成
   `paper` / `night` 两套变量(含主题切换),原生端颜色对照以它为准。

## 导入 Pixso

- **自助**:逐屏 `screens/*.html` 直接拖入 Pixso 画布;或整板导入后拆画板。
- **走本地 MCP(可写入设计的唯一自动化通道)**:Pixso 桌面端开启
  「MCP 服务」(设置/AI 面板内开关;服务起来后本机 `127.0.0.1:3667/mcp`
  才会监听),然后提供文件 URL 里的 `file_key`,由 `code_to_design`
  逐屏导入并排画板。
  注意:官方远程代理 `@pixso/pixso-stdio-mcp` 只有
  `get_node_dsl` 等**只读**工具,不能反向写入设计,不要指望它导图。

## 原生客户端对照约定

- 画板基准:**393×852 @3x**(iPhone 14/15 Pro);Android 出图同源缩放。
- 颜色/圆角/字阶一律以 `tokens.json` 与 `www/css/app.css` 的 CSS 变量为唯一来源;
  组件类名(`.dh/.rail/.cd/.lr/.ar/.tx/.bn/.seal/…`)即原生组件命名对照表。
- 诚实性纪律(DS-13)逐条保留:REAL 托管警示、fail-closed 禁用态、
  「未接入」而非 0.00、性能如实标注——原生实现不得为好看删减。
