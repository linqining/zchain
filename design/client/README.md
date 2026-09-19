# ZChain 客户端 · 账簿 Ledger 设计稿 C1–C7

牌桌稿（`../table/`）和站点稿（`../site/`）之后的第三块：把 `/play` 之外的**客户端路由**也画成同一套账簿语言。
这一轮的输入是 React 源码，不是想象——每屏的文案都从
`poker_texas_air/client/src/context/localization/locales/zh.json` 与对应 `src/pages/*.tsx` 里取原文。

## 打开

```
open design/review/index.html          # ← 三套稿的总评审台，建议从这里进
open design/client/zchain-client-ui.html
```

`zchain-client-ui.html` 顶部工具条可切**纸白 / 夜场**，并按屏跳转。

## 七屏对应关系

| 屏 | 路由 | 源文件 | 关键 locale 前缀 |
| --- | --- | --- | --- |
| C1 | `/` | `SecretPokerHomePage.tsx` | `homepage_*` |
| C2 | `/lobby` | `SecretPokerLobby.tsx` | `main_page-*` `funds-banner_*` `navbar-*` |
| C3 | `/dashboard` | `Dashboard.tsx` | `dashboard-*` `playerkey-*` |
| C4 | `/whitepaper` | `Whitepaper.tsx` + `whitepaper/WhitepaperZh.tsx` | `whitepaper` |
| C5 | `*` | `NotFoundPage.tsx` | `notfound-*` `static_page-back_btn_txt` |
| C6 | 登录弹窗 | 钱包连接路径 | `login_*` |
| C7 | 领取奖励弹窗 | 私密/公开双路径 | `claim-*` |

`/play` 与 `/game/:gameId` 不在此文件——它们在 `../table/` 的 T1–T6 / G1–G2。

## 出图

```
python3 design/client/render.py                 # 纸白全套 → png/paper--c*.png
GROUND=night python3 design/client/render.py    # 夜场全套 → png/night--c*.png
python3 design/client/render.py c2 c7           # 只出指定屏
```

脚本先量高再截图，两步都走 HTTP。**不能直接用 `file://`**：探针页要读 iframe 的
`contentDocument`，`file://` 下浏览器按跨源处理，读不到高度会**静默**回退成默认值，
你会拿到一堆被裁断的图而没有任何报错。同理，不要把这个 html 拷到 `/tmp` 再截——
它虽然自带样式不依赖外链，但 `render.py` 的路径是按 `design/` 根算的。

## 这轮真正改掉的四件事

1. **图标语言换成牌面。** 大厅原来是四张 196×210 的卡通人物 PNG（king/queen/jack/queen2）。
   改成 A♠ K♠ Q♠ J♠ 的字面 + 花色，零图片、零加载、零版权资产，
   并且和牌桌稿的牌面是同一套符号。
2. **"服务器看不到你的牌"变成看得见的东西。** C1 主视觉右侧是一张
   *服务器视角*的表：你的底牌、他人底牌、公共牌全部是 `■`，最后一行写
   `服务器可见 = ∅ 空集`。原来这里是一句口号加一张插画。
3. **领取奖励弹窗（C7）是整套客户端的重心。** 私密领取要跨 5 个前置条件、
   两种出金路径、一段 12 小时在局锁定。原实现把这些散在 tooltip 和失败报错里。
   这里改成账簿的**条件清单**：一行一个条件，左侧方框勾/未勾，右侧是系统实际读到的值，
   未满足那行直接把修复动作写成正文链接；锁定用线性计量条而不是转圈（它表达的是"还剩多少"）；
   私密 / 公开两条路径用 `--real` 与 `--felt` 两种**语义色**区分归属可见性，
   而不是"推荐 / 普通"的视觉等级——这是玩家的隐私选择，不是消费选择。
4. **把决定权相关的读数提到决策现场。** C6 登录弹窗里 Wallet API 版本与当前网络
   直接决定能不能私密领取，原来要等领币失败才知道；这里做成弹窗内两格读数。
   C3 同理：`在局锁定 2,000` 与 `可领取 1,240` 分行列出，解锁按钮在锁定那一行。

## 需要你拍板的两处（我没有擅自动）

- **社交登录去留。** `zh.json` 里有 `login_google / login_apple / login_facebook / login_twitch`，
  但同一个文件的 `login_oauth-note-1` 写的是「使用 Starknet 钱包登录 — 无需社交账号」。
  这两句互相打脸。C6 按钱包优先路径只画了钱包两条。
  **要么删社交入口，要么改那句文案**——这是产品决定，不是设计决定。
- **`main_page-modal_button_text` = 「领取免费筹码」但弹窗正文是「立即领取 10,000 免费筹码」。**
  10,000 这个数字在 C2/C7 里我没敢沿用：C7 用的是真实金库口径（本桌剩余 1,240）。
  如果 10,000 是有效的注册赠金，它应该出现在 C6 之后、而不是藏在商店式弹窗里。

## 已知未达项

- C1/C3/C4 是**整页长图**，不是一屏；评审时请按滚动顺序看，不要按"首屏"评判。
- C4 白皮书正文是我按白皮书命题**重写的示意文**，不是 `WhitepaperZh.tsx` 的逐段搬运
  （那份正文有几十屏，逐段搬会淹掉设计评审）。表格与公式的样式是真的，内容以源文件为准。
- 未画：`/game-rules`、`StaticPage` 的通用外壳、`maintenance` 页、Cookie 横幅、
  `shop-coming_soon` 弹窗（已在 C2 卡片脚注里以 `COMING SOON` 表达）。
- 窄屏（390）客户端稿未出。客户端是响应式 React，断点与站点不同（源码里是 468/590/900/1024），
  要出窄屏需要先定客户端自己的断点表——建议下一轮连同工程落地一起做。
