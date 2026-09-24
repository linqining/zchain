# 测试记录:poker_texas_air 远程测试实例部署（/opt/texas-test）× bot+真人钱包 2000 手

- 日期：2026-09-22
- 目标：把本地 `/Users/mac/projects/poker_texas_air` 部署到 stark 的**独立测试目录**，
  与生产 `/opt/texas/texas`（systemd `texas.service`，:9001，Starknet 主网）完全区分；
  然后用机器人（seat 2/3 注入 bot）+ 真人钱包（Chrome for Testing + ZChain 扩展，
  登录/买入/动作全部扩展真实签名）打 2000 手，全部结算经结算桥锚定到 4 节点 zchain。

## 1. 部署清单

| 项 | 位置/值 | 状态 |
|---|---|---|
| 测试实例目录 | `/opt/texas-test`（ texas 二进制 + start-test.sh + run/ 运行目录） | ✅ 与 /opt/texas 完全隔离 |
| texas 游戏 | musl 交叉编译（Mac, HEAD 363bb56f），`:1443`（用户开定的直连端口；**不占用生产 9001**） | ✅ |
| appchain 出口 | `run/appchain/sequencer.wal`，sequencer_public `b0e9318e…`，attestor `cd46809b…` | ✅ |
| explorer_gateway | `/opt/zchain-src/target/release/explorer_gateway`，`:18900 --public`（扩展数据面） | ✅ |
| 结算桥 | bridge p0（`b89f05e7…`），state `run/bridge_state.json`，target=2100，poll 8s | ✅ |
| deploy-record | tx `d3334def59f34b7b…`，nonce 761，**included**（新实例合约绑定记录上链） | ✅ |
| 机器人 | bot 循环注入 `0x…b01`(seat2)/`0x…b02`(seat3)，`TEXAS_DEV_BOT_ENABLED=1` | ✅ |
| 真人钱包 | 扩展一键创建钱包 → 水龙头 1000 PLAY → ZChain 登录 → 买入 1000 → 自动打牌 | ✅ |
| 前端 | Mac 上 vite :5173（`GAME_SERVER_URL=http://8.218.68.215:1443`） | ✅ |

**费用语义实证**：4 个桥账户链上 balance=0（上次 3029 锚定后耗尽），
但节点全部默认 `FeePolicy::Free`（源码无 CLI 可改，Free 不检查 legacy balance），
deploy-record 以 nonce 761 成功入块 → 0 余额不阻塞锚定，无需给桥充值/重置链。

## 2. 过程中修复的问题（按时间序）

1. **musl 交叉编译链接失败**：默认 `cc` 不认识 Linux 链接参数 →
   `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc`
   （brew musl-cross）链接通过。产物 29.5MB static-pie，x86_64 验证 OK。
2. **Chrome for Testing bundle 损坏**：所有 helper 子进程启动即
   EXC_BREAKPOINT（290+ 次 "Network service crashed"）→
   `/tmp/chrome` 内旧副本文件缺失（codesign: "code has no resources but
   signature indicates they must be present"，新下载副本同告警属 CfT 正常）。
   重新下载 153.0.8010.36 到持久目录 `~/tools/cft/`（CHROME_BIN 指定）后 0 崩溃。
   教训：CfT 放 /tmp 会被系统清理损伤，且 codesign --deep 对 CfT 报警不能作为判据。
3. **SSH 隧道闪断**：一次性 `ssh -f -N -L` 无保活静默死亡 →
   `~/tools/poker-air-2000/tunnel-watchdog.sh`（nc 探测 + ServerAliveInterval=15
   自动重建 18900/29101/28545）。后续 1443 直连后仅 gateway 18900 与 RPC 28545 仍走隧道。
4. **真人 WS 反复断连 → 手速 43s/手（auto=1~3 超时代打）**——根因两层：
   a. **客户端毒化标志（根治）**：`isUnmountingRef` 用 effect cleanup 置位、
      另一 effect cleanup 读位触发离桌。React 18 StrictMode 挂载即双执行 cleanup，
      伪卸载把标志毒化 → join/socket effect 一旦重跑（lobbyReady/socket 变化）
      就误发 LEAVE_TABLE（useTableJoin）甚至 `navigate('/')`（useGameSocket），
      玩家被弹回首页 404 次、座位反复被服务端移除（DISCONNECT 118+）。
      根治：删除两个文件的 isUnmountingRef 模式，改 `useLocation` 路由守卫
      （仅真实 `/play` → 其他路径迁移才离桌；StrictMode 重挂载不改 pathname），
      页面关闭仍由 pagehide 兜底。修复后：跳回 0 次、DISCONNECT 0、每手 auto=0。
   b. **端口直连（用户放通 1443/9001）**：测试实例迁 1443，浏览器
      WS/REST 直连 `8.218.68.215:1443`，消除隧道抖动这一放大器。
5. **登录 500（假象叠加）**：旧 vite 进程残留占用 5173（其代理目标指向
   已死隧道 29101），新 vite strictPort 绑定失败静默退出 → 登录 POST 全 500。
   按 PID 杀净旧进程重启 vite（代理目标=直连 1443）后登录正常。
   教训：strictPort 失败只写日志不重试，重启脚本必须先按 PID/端口确认杀净。
6. **客户端 dev 模式 WS 地址**：clientConfig 的 socketURI 在 dev 下只能拼
   `hostname:VITE_SERVER_PORT`，无法表达跨机直连 → clientConfig 增加
   dev 亦支持 `VITE_SERVER_URI` 绝对地址（缺省回退旧行为）。
7. **桥目标簿记**：texas 重启清空内存牌桌 history（浏览器 DONE 判据归零），
   桥的锚定计数持久。为使"打满的每一手都被锚定"，桥 target 上调 2100
   （≈重启前已锚 112 + 本轮 2000）。
8. **Chrome 挂死级联 → 手牌活锁（重要，待专项根治）**：
   - Chrome 进程 18:15 挂死（DevTools 端口 fetch failed），mjs 死循环重试不退出
     → 服务器把断连真人超时代打到手末 → 座位移除 → 2 bot 局。
   - **2 bot 局暴露服务端活锁**：betting-authority VM 镜像的 `current_turn`
     与 `table.turn()` 指针失同步（镜像指到空座位 0），bot 依 table 态发的
     check 全被 VM 拒（"cannot check: bet < current_bet"/"not player's turn"），
     超时代打对空座位无从施加 → 手牌永停 PreFlop，桥/浏览器全部无进展。
     根修方向：镜像 turn 推进须与桌子座位移除事件同步（或 bot 决策改读镜像态）。
   - 运行级护栏（本次已加）：
     a. mjs 主循环 CDP 连续失败 ≥8 次即抛出退出 → supervisor 换新浏览器
        （挂死转化为 ~1 分钟内自动重启）；
     b. stark `/opt/texas-test/run-guard.sh`：≥240s 无 "hand complete" 即
        自动 `start-test.sh 2100` 重启测试栈（桥 state/WAL 持久续跑）。

## 3. 运行参数（stark 测试实例 .env，与生产区分的关键项）

```
PORT=1443                    # 生产 9001
TEXAS_ENV=dev                # 生产 starknet 主网
TEXAS_PROVER_MODE=dev        # 本地进程内证明器
TEXAS_APPCHAIN=1             # 结算出口=嵌入式 appchain → zchain
STARKNET_AUTH_STRICT=false   # 生产 true（链上验签）
STARKNET_RAKE_BPS=0          # 生产 500
BETTING_TIMEOUT_SECS=8       # 生产 90
```

## 4. 验收结论（2026-09-22 定稿）

用户在长跑稳定后改判验收口径：**前端部署到 zchain.secretpokers.com + E2E 打 5 手通过即结束**
（见第 5 节）。2000 手长跑在停止时已累计锚定 947（桥 state 计数），期间验证了
多层自愈闭环，远超 1000 手前例的稳定性结论。

### 4.1 三重对账（最终，2026-09-22 08:0x）

| 项 | 结果 |
|---|---|
| 四节点高度一致 | 18545/18546/18547/18548 = **40406** 全一致 ✓ |
| 桥账户 nonce 对账 | 链上 nonce=**1711** = 761(前期) + 1(deploy-record d3334def) + **949**(state 锚定 keys)，精确一致 ✓ |
| 末笔 get_tx | 末笔锚定 binding `1e7f419f…`（nonce=1711）tx `7d964bcf…`：**四节点全部 FOUND** ✓ |

### 4.2 长跑统计（02:32–07:40，约 5.2 小时）

- 锚定数 150 → 947（+797），期间 4 次钱包锁态自愈重启、多次 bust 自动重入座、
  1 次 run-guard 冻结重启 + 浏览器陈旧 table 自愈刷新 + 自动重入座的完整闭环
- 真人钱包（每 attempt 扩展真实签名登录/买入/行动）与 2 bot 全程同桌

## 5. 前端部署：zchain.secretpokers.com（2026-09-22）

| 项 | 值 |
|---|---|
| 域名 | zchain.secretpokers.com → 8.218.68.215（用户已在 DNS 放置） |
| 前端 | client 生产构建（`npm run build`，VITE_SERVER_URI=https://zchain.secretpokers.com/，见 client/.env.production.local，gitignored） |
| 静态目录 | stark:/var/www/zchain-test/dist（tar 管道上传，原子切换 .new→dist） |
| nginx | /etc/nginx/conf.d/zchain-test.conf（独立 server block：/:443 静态、/api/ → 127.0.0.1:1443、/socket.io/ WS 升级 → 1443；80 → 301 https） |
| 证书 | certbot certonly --nginx 独立签发 live/zchain.secretpokers.com（不触碰 strk 证书） |
| 隔离声明 | 生产 /var/www/poker、poker.conf、:9001、strk.secretpokers.com 全程未修改（部署后复测 strk 200 / 生产 API 401 正常） |
| 脚本 | poker_texas_air/scripts/deploy_client_zchain_test.sh（构建+上传+冒烟，--skip-build 可复用产物） |
| 配套 | deploy/zchain-test-nginx.conf、deploy/zchain-test-server.env（注释版模板） |
| 扩展 | extension/manifest.json 增加 https://zchain.secretpokers.com/*（content_scripts ×2 + host_permissions），否则 inpage 不注入、登录无 ZChain 按钮 |

### 5.1 E2E 回归（经域名，5 手口径）✅

- 基线：启动时桥 state 锚定 **889**
- 流程：Chrome for Testing + ZChain 扩展打开 https://zchain.secretpokers.com →
  扩展真实签名登录 → 水龙头 1000 PLAY → Sit Down → 买入签名（审批 origin =
  https://zchain.secretpokers.com ✓ 注入生效）→ 与 2 bot 连打
- 结果：**DONE: 947 anchored ≥ 894**（browser.done sentinel；锚定增量 58 ≫ 5，
  其中真人钱包签名动作 97 个，跨 hand 1790034464/…4520/…4546/…4857/…4881 等），
  每手结算经 appchain→桥→zchain 锚定 ✓
- 恢复路径亦验证：一次 bust 后 mjs 自动重入座（点击 Sit Down → 补水 → 买入签名 →
  服务器确认 seated）

结论：**前端部署 + zchain 结算 E2E 回归通过。**
