# ACCEPTANCE — Extension 0.1–0.4 验收对照（plan-appchain §6.12.7）

Extension 0.1 交付范围 = PLAY、本地 keystore、ZChain provider、开桌/买入/结算
签名、devnet。Extension 0.2 追加 = testnet、多账户、REAL/PLAY 隔离、proof
portal、备份恢复、网络切换（§6.12.4 表行）。Extension 0.3（本轮交付）追加 =
SNIP-12 会话密钥授权（UI + 流程）、REAL 提现预览（展示态）。Extension 0.4
（本轮交付）追加 = 授权簿/registry UI、会话密钥撤销/过期、单笔/每日限额
执行、capability matrix。本文逐条对照钱包验收门槛，如实标注：✅ 已实现并
测试 / ◐ 部分 / ⛔ 未实现（不虚标）。0.2 增量见"Extension 0.2 验收对照"节，
0.3/0.4 增量见文末"Extension 0.3/0.4 验收对照"节。

---

## M6-ACC-6（浏览器插件 origin 绑定 / nonce / 网络隔离 / 权限最小化）

| 门槛 | 状态 | 覆盖位置 |
|---|---|---|
| 伪造 origin（envelope.origin ≠ sender 真实 origin）拒绝 | ✅ node 测试 02 + 浏览器 E2E | `tests/validation.test.js`；`common/validation.js::checkEnvelope`（(a) 项）；后台以浏览器固定的 `sender.origin` 为锚 |
| origin 白名单逐 origin 单独保存/撤销 | ✅ node 测试 03/22 | `originIsGranted/grantOrigin/revokeOrigin`；授权簿在 `chrome.storage.local` |
| nonce 单调防重放（重放/回退/相等） | ✅ node 测试 04/05/06 + E2E 步骤 7（`NonceReplay`） | `checkEnvelope` (c) 项 + wallet-core `(chain,nonce)` 账本二次防重放 |
| 过期信封拒绝 | ✅ node 测试 07 | `checkEnvelope` (d) 项；签名请求自身 expiry 由 wallet-core 再拒 |
| sessionId 绑定（错 token/锁定/会话过期） | ✅ node 测试 08 + E2E 步骤 8（`SessionInvalid`） | `checkEnvelope` (e) 项；SW 休眠重启后旧 token 失效 |
| 网络隔离（chain_id 与当前网络不符拒） | ✅ node 测试 14 | `validateRequest→checkNetworkAbiDomain`；0.1 仅 `zchain-devnet-1` |
| 权限最小化：首连/换网/提现类/批量签名必须显式确认 | ✅ node 测试 21 + E2E 步骤 3（connect 弹窗批准） | `requiresExplicitConfirm`；签名类恒确认；0.1 中换网/提现类直接 `NotSupportedIn01/KindDisabledIn01` |

## WALLET-ACC-3（恶意 dapp 不能诱导签名；取消/超时/重放全过）

| 攻击面 | 状态 | 覆盖 |
|---|---|---|
| 任意 bytes 盲签 | ✅ 不存在该能力：provider 无 signBytes；wallet-core `sign_raw_bytes` 恒拒（43 测试覆盖） |
| 结构外签名请求（未知 method/kind/缺参/坏 hex） | ✅ node 测试 09/10/11/18/20 |
| 金额溢出 / 非安全数值 | ✅ node 测试 12/13（u64 上限 + 安全整数 + 字符串金额）；wallet-core u128 checked 聚合双保险 |
| ABI 版本 / domain 不认识 | ✅ node 测试 15/16 + WASM 冒烟（`UnknownAbiVersion`） |
| 换链重放 | ✅ node 测试 14 |
| 展示-签名调包 | ✅ `previewHash` 非空时必须等于 wallet-core 重算摘要（`PreviewMismatch`，E2E demo 按钮"坏 previewHash"）；空值仅 0.1 允许（dapp SDK 0.2 交付），弹窗结构化预览是唯一确认面 |
| 用户取消 | ✅ E2E 步骤 6（`UserRejected`）+ node 测试 23 |
| 超时 | ✅ node 测试 24/25（45s TTL → `RequestExpired`，sweepExpired 清扫） |
| 重放（页面信封 / 签名 nonce） | ✅ node 测试 04/05 + E2E 步骤 7 |
| 锁定后签名 | ✅ E2E 步骤 8（`SessionInvalid`） |
| REAL 边界（0.1 误签 REAL） | ✅ node 测试 17（`AssetClassDisabledIn01`；对应 WALLET-ACC-6 的 PLAY 侧） |

## WALLET-ACC-4（日志 / crash dump 不含敏感字段）

- ◐ 已实现日志纪律 + 说明，发布工程项未做：
  - background/popup 日志走字段白名单（`logSafe`：requestId/method/code/origin
    级状态）；参数、keystore、口令、预览金额、密钥材料一律不入日志
    （`background/service_worker.js::logSafe`；popup.js 不打印任何请求内容）。
  - 密钥材料只存在于 wallet-core wasm 线性内存（`SecretBytes`/`Zeroizing`，
    zeroize-on-drop）；落盘只有密文信封；`sanitizeNotesForPage` 保证 note
    脱敏输出（无 spend secret/nullifier）——node 测试 26 + WASM 冒烟第 9 步。
  - **crash dump / 分析 SDK / clipboard 的敏感数据扫描属发布工程**
    （WALLET-ACC-8 可复现构建/签名发布的一部分）：0.1 无分析 SDK、无
    clipboard 访问、无远程脚本；扫描流水线标 1.0 交付。

## 其余门槛

| 门槛 | 状态 |
|---|---|
| WALLET-ACC-1（MetaMask/Argent/WalletConnect 兼容矩阵） | ⛔ 0.3+（0.1 刻意不与 EIP-1193 生态互操作，见 README"不冒充"节） |
| WALLET-ACC-2（跨端 digest/signature 字节一致） | ◐ 单实现已保证：逻辑面由 wallet-core 43 测试覆盖；WASM 面由 `tests/wasm_smoke.mjs` 覆盖（同一 ABI）；桌面/移动对比向量挂同一钩子（README），0.2 随移动端补 |
| WALLET-ACC-3a（SNIP-12 会话密钥 admission） | ⛔ 0.3/0.4（wallet-core 已备 `session_admission`/`binding_admission`，provider 未开放） |
| WALLET-ACC-5（备份恢复 fail-closed） | ✅ 0.2 已接：popup 导出/导入（wallet-core ZCBK v1 单实现）；错口令/篡改文件/未来版本 fail-closed（node 用例 + 浏览器 E2E A7-A9）；见文末 0.2 节 |
| WALLET-ACC-6（REAL 显示门 / PLAY 不误显示 REAL） | ✅ 0.2 已接：REAL/PLAY 物理分库视图 + `display.rs` 展示门经 wasm `wallet_display_views` 输出（claim 恒隐藏 + 托管风险提示常显；PLAY 视图无 REAL 字段）；REAL 签名面仍关闭（诚实边界）；见文末 0.2 节 |
| WALLET-ACC-7（外部钱包 capability 矩阵） | ⛔ 0.3/0.4（`zchain_getCapabilities` 已返回本钱包能力矩阵） |
| WALLET-ACC-8（可复现构建/签名包/SBOM/审查） | ⛔ 1.0 |

## 验证记录（真实执行）

- 安全校验层 28/28 通过：`node --test "extension/tests/*.test.js"`
  （等价形式；本机 Node v24.4.1 对 `node --test <目录>/` 这一参数形态存在
  通病——目录被当作模块执行，用最小目录复现确认与本项目无关）。
- `node extension/tests/wasm_smoke.mjs`：通过（真实 Argon2id/secp256k1/
  ChaCha20-Poly1305 路径：create→faucet→preview→sign→persist/lock/unlock→
  错口令拒→nonce 重放拒→脱敏检查）。
- `cargo test -p poker-wallet --release`：43/43 通过（23 lib + 20 acceptance，
  零回归）；`cargo build --release -p poker-wallet` CLI 正常。
- 真实浏览器（Chrome for Testing 153，headless=new + `--load-extension`，
  unpacked 加载）：provider 注入 ✓、`window.ethereum` 不存在 ✓、未授权 origin
  全部 `OriginNotPermitted` ✓、connect→批准→`granted:true` ✓、getNotes 脱敏 ✓、
  signOperation→结构化预览（全部 §6.12.4 字段）→批准→真实签名（digest 64 hex
  + borsh operation）✓、拒绝→`UserRejected` ✓、nonce 重放→`NonceReplay` ✓、
  锁定后→`SessionInvalid` ✓。截图：`/tmp/zchain_e2e_popup.png`、
  `/tmp/zchain_e2e_demo.png`（验证会话产物，不入库）。
- manifest.json：`python3 -c "import json;json.load(open('extension/manifest.json'))"`
  通过；MV3 必填项核查见 README"CSP/权限"行与 manifest 注释字段（name/version/
  manifest_version/background/permissions/content_scripts/action 均在）。

---

## M6-ACC-1（浏览器验证吞吐：连续 10 手证明验证，全部通过且无内存泄漏——长会话）

日期：2026-09-12 · 结果：**✅ PASS**（真实 Chrome for Testing 浏览器内执行，500/500
正确 + GC 后留存堆与 wasm 线性内存均无持续增长趋势）

### 范围口径（如实，不虚标）

- **v1 客户端本地验证的浏览器面** = wallet-core wasm 的结算关系验证面。本测试
  每手执行两个 wasm JSON 入口（与扩展 `common/wallet_core.js` 加载**同一**
  `vendor/wallet-core/wallet_core_wasm*.wasm` 字节）：
  1. `wallet_preview(kind=settle)`：borsh 解码 + 守恒预检 + 预览/摘要面；
  2. `wallet_sign(kind=settle)`：对签名完备后的记录执行 poker-appchain
     `validate_settlement` **全量校验**（守恒 / 费率 / 分账 / P 层 SpendAuth
     ECDSA 签名覆盖 / 手牌证明绑定 / payout 投影），fail-closed，校验不过不出
     签名。poseidon/blake2b/secp256k1 全部在 wasm 内（密码学零 JS）。
- **不在浏览器循环内（0.1 wasm JSON 面未暴露，如实标注）**：软确认链
  `verify_chain`、批次根 `verify_batch_root`/golden 复算、attestation 结构校验
  属 wallet-core native verifier（`poker-wallet/src/verifier.rs`）**同一实现**，
  由 `cargo test -p poker-wallet --release` 的 native 测试覆盖；0.1 的 wasm 面
  没有这些入口（0.2 sync/proof portal 缝接入）。夹具仍随附每手的软确认链
  （sequencer ed25519 签名帧，生成期 `verify_chain` 自检通过）与单手批次根，
  供后续 wasm 面开放后同夹具复用。
- **完整 STARK 验证的 wasm 化（stwo-wasm）不在 v1**：本测试验证的是结算关系
  面（上述 validate_settlement 全量关系 + 真实 ECDSA 验签），不是 stwo 证明的
  浏览器内验证。

### 夹具（真实结算输入，非 mock）

`extension/tests/fixtures/m6acc1/hand_01..10.json` + `manifest.json`，由一次性
生成器 `extension/tests/perf/fixture_gen/`（path 依赖 poker-appchain 公开 API，
复刻 `poker-appchain/tests/common/mod.rs` 的两人桌结算构造）产出，生成期自检：

- 10 份正例：ABI v1.2 `SettlementRecord`（含 `SettlementPlan`）+ FixedRake 5%
  策略，双输入 SpendAuth 为真实 owner ECDSA 签名（覆盖 scope+effect），
  `validate_settlement` 生成期全过；
- 手 10 为**负例**：正例记录 `inputs[1].spend.sig` 末字节翻转（伪造 P 层签名
  注入），生成期断言被拒（"owner signature invalid or missing"）；
- 每份随附软确认链 2 帧（OpenTable→Settle，sequencer 签名，生成期
  `verify_chain` 全过）与单手批次根复算值。

### 执行环境与驱动方式

- Chrome for Testing **153.0.8010.36**（macOS arm64），`--headless=new` +
  CDP（复用 E7 验证记录同一驱动方式）；`--enable-precise-memory-info` +
  `--js-flags=--expose-gc`（泄漏判据需要每轮强制 GC 后采样留存堆）。
- 驱动/复现：`M6ACC1_ROUNDS=50 node extension/tests/perf/run_m6acc1.mjs`
  （本地静态服务 serving `extension/`，页面 `tests/perf/m6acc1.html`，runner
  逐轮取走明细，页面不 retain 报告数据——避免 harness 自身累积污染泄漏判据）。

### 结果（长会话 = 50 轮 × 10 手 = **500 手验证**，2026-09-12）

| 指标 | 值 |
|---|---|
| 正确性 | **500/500**：450 正例全部通过（输出结算操作），50 负例全部 `VerifierRejected`（每轮 1 个伪造签名注入均被拒，即 M6-ACC-3 的浏览器面负例） |
| 每手耗时（preview+sign 两段 wasm 调用） | 中位 **2.4 ms**，均值 2.41 ms，p95 **3.7 ms**，最大 7.4 ms |
| GC 后留存堆（判据序列） | 首 3 轮均值 788,146 B → 末 3 轮均值 826,348 B = **+4.85%**（< 20% 门槛）；末 10 轮极差 5,700 B，在噪声带 max(32KB, 首3均值×2%) 内——无持续增长趋势 |
| wasm 线性内存 | 2,424,832 B 全程恒定（**0%** 增长，无扩张） |
| 总墙钟 | 5.17 s（500 手验证，不含一次性钱包/夹具装载 30.9 ms） |

堆判据全文（结果 JSON `heap.criteria` 字段）：末 3 轮均值 vs 首 3 轮均值增幅
< 20%，且最后 10 轮无持续增长（"持续"= 连续递增 ≥ 5 轮**且**极差超过噪声带
max(32KB, 首 3 轮均值×2%)——带内微小抖动不计为增长）。

### 证据产物

- 结果 JSON：`extension/tests/perf/m6acc1_result.json`（50 轮逐手明细：每手
  preview/sign 分段耗时、判定、负例错误码；逐轮堆/wasm 内存采样）。
- 截图：`extension/tests/perf/m6acc1_screenshot.png`（页面渲染 PASS 摘要）。
- 复现入口：`extension/tests/perf/run_m6acc1.mjs`（runner）、`m6acc1.html` +
  `m6acc1_page.js`（harness）、`fixture_gen/`（夹具生成器）。

### 没测什么（如实）

- 未在扩展 Service Worker/popup 运行时内压测（本测试为同一 wasm 字节的独立
  页面上下文；扩展栈内的 provider/预览/签名通路 E2E 见上文"验证记录"节）。
- 软确认链/批次根/attestation 校验未进浏览器循环（0.1 wasm 面无入口，见范围
  口径）；stwo-wasm 不在 v1。
- `performance.memory` 为 Chrome 专有；非 Chrome 浏览器上 heap 判据不可采样
  （harness 会如实标注 `unavailable`，正确性判据不受影响）。

---

## 连接协议适配器（M6"钱包连接协议"条目，Extension 0.1 追加交付）

三套连接协议适配器（`adapters/`：EIP-1193 兼容 / WalletConnect v2 / Starknet
钱包接口），架构、chain id 映射表、生产 WC 接入步骤与红线清单见
`adapters/README.md`。本节逐项对照 M6 连接协议条目，如实标注。

### 逐项对照

| M6 条目 | 状态 | 覆盖位置 |
|---|---|---|
| Wallet Standard 风格能力发现 | ✅ 逻辑面：三适配器统一以 `zchain_getCapabilities` 为唯一能力源——WC proposal 授权阶段强制探测（授予集 = 请求 ∩ §6.12.4 白名单 ∩ 能力）；`tests/adapters/walletconnect.test.js` 用例 01/02/08 | `adapters/walletconnect.js`；能力矩阵本体 = `background/service_worker.js::capabilities()` |
| WC v2（会话传输） | ✅ 适配核心 + 契约测试：proposal namespace 映射（独立 `zchain:` CAIP namespace）、请求路由、能力探测、会话过期/断开/请求 id 重放拒、validation.js 参数校验透传；SignClient 为注入接口 + 内存 stub（零 npm 进构建） | `adapters/walletconnect.js` + `adapters/wc_signclient_stub.js`；17 用例 |
| EIP-1193（兼容形状） | ✅ 只读子集：`eth_chainId`/`net_version`/`eth_accounts` 白名单 + `zchain_*` 透传（同一 validation.js 拒绝面）+ 事件转发（connect/chainChanged/accountsChanged/disconnect）；`eth_chainId` = 显式映射别名 `0x7a0001`（非 0x1） | `adapters/eip1193.js`；15 用例 |
| Starknet 钱包接口 | ✅ 授权委托面：钱包对象探测（starknet/stargate 形状，fail-closed）+ SNIP-12 `AuthorizeZChainKey` typed data 组装（与 `account_binding.rs` encode_type 逐字一致）+ 注入式 verifier 验签 + 授权登记 | `adapters/starknet.js`；15 用例 |
| 后台注册/开关 | ✅ `initAdapters`（安全默认：EIP-1193 只读硬编码、WC 未注入 SignClient 即 dormant、Starknet 仅显式调用触达）；popup:adapters/setAdapterConfig | `adapters/index.js` + `background/service_worker.js`；4 用例 |

### "不伪装"红线如何被测试钉住（tests/adapters/，共 51 用例）

| 红线 | 钉住方式 |
|---|---|
| EVM 签名 ≠ ZChain 签名（EVM 钱包仅限未来 bridge/登录适配器） | eip1193 用例 05：`eth_sign`/`personal_sign`/`eth_signTypedData(_v3/_v4)`/`eth_sendTransaction`/`eth_sendRawTransaction` 七方法全拒 `4200 + EvmSigningForbidden`，适配器无任何启用开关（未来启用路径 = wallet-core 新增 `evmBridge` capability + 桥接专用方法，见 adapters/README.md） |
| 不伪装 Ethereum 主网/MetaMask | eip1193 用例 01（`eth_chainId = 0x7a0001 ≠ 0x1`，显式映射表）+ index 用例 04（无 `isMetaMask`，`isZChainEip1193Shim`）；映射表外网络拒绝（eip1193 用例 11 负例：未知网络不转发 chainChanged） |
| WC 不伪装 eip155/sn 账户 | walletconnect 用例 03/04：混入 eip155 namespace / 非 zchain chains 整案拒（CAIP-25 5100/5001）；账户形状恒 `zchain:<net>:<pubkey>`（用例 01） |
| WC 能力不足绝不退化盲签 | walletconnect 用例 02（能力缺失不授予）+ 08（`CapabilityMissing(-32051)`，message 明示 no blind signing）+ 05（白名单外方法 proposal 拒）+ 10（请求阶段白名单外 `MethodNotAllowed`，永不过执行） |
| WC 重放/过期/断开 | walletconnect 用例 11/12/13/16（SessionExpired + 主动断开 / 重放与回退 id `ReplayDetected` / `RequestExpired` / `UnknownSession`） |
| Starknet 签名不越权到 note spend | starknet 适配器无任何 spend 签名路由（仅 signMessage typed data）；用例 08：withdraw scope 签名前拒（`ScopeForbidden`）且不触达钱包；scope 全集常量不含 withdraw（用例 09）。对应 §6.12.1 推荐形态"Starknet Account + SNIP-12 授权的 ZChain 会话密钥" |
| Starknet scoped 授权（超 scope/过期） | 用例 10（过期 `Expired` / 未生效 `NotYetValid`，签名前拒）+ 07（篡改签名 `SignatureRejected` 且不登记）+ 06（正例：验签过 → 登记 constraints 镜像，字段与 SNIP-12 message 一一对应） |
| SNIP-12 规范不漂移 | starknet 用例 01：`AUTHORIZE_ENCODE_TYPE` 与 `poker-wallet/src/account_binding.rs::authorize_encode_type()` 逐字比对；用例 02/03：domain 四字段 + message 14 成员 + SNIP-12 值形状（amount 十进制 / bytes 字节数组 / felt252 hex） |

### WALLET-ACC-1 兼容矩阵：本适配层可覆盖与剩余部分

- **本层可覆盖（capability 拒绝路径，逻辑面）**：外部钱包/客户端能力不足时
  的显式拒绝（WC `CapabilityMissing`/CAIP-25 拒绝码族、EIP-1193 `4200`
  白名单外、Starknet `WalletUnsupported`/`WalletNotConnected`）与协议形状
  协商（namespace 映射、链 id 匹配）——即兼容矩阵中每次握手失败时行为是
  确定的、有稳定错误码的。
- **剩余（真机矩阵，未验证、不虚标）**：MetaMask/Rabby 实装对 EIP-1193
  shim 的互操作；Argent X/Braavos 作为 WC peer 及其对 `chainId:
  "zchain-devnet-1"` SNIP-12 domain 的签名接受度；真实 WC relay（
  `@walletconnect/sign-client` 打包入口未交付，缺省 dormant）。均仍标
  WALLET-ACC-1 真机集成面。
- 关联边界（承接 wallet-core README"已知边界"）：`wasm.rs` 尚无 SNIP-12
  摘要/验签 wasm 入口，Starknet 验签暂经注入式 verifier 接口（形状与
  wallet-core 一致；生产实现 = `authorize_message_hash` + `starknet-crypto`
  验签路径）；wasm 入口补齐后零改动替换注入。

### 验证记录（真实执行，2026-09-12）

- `node --test extension/tests/*.test.js extension/tests/adapters/*.test.js`：
  **75/75 通过**（既有 validation 28 不回归 + 新增 adapters 51 =
  eip1193 15 + walletconnect 17 + starknet 15 + index 4）。
  注：本机 Node v24.4.1 对 `node --test <目录>/` 参数形态存在通病（目录被
  当作模块执行，见上文"验证记录"节同款说明），以通配/逐文件形式为准。
- `node --check extension/background/service_worker.js` + 全部 adapters/*.js：
  通过（SW 仍为 MV3 module；接线为 add-only，popup/页面既有消息面未改动）。
- 回归口径：`node --test extension/tests/ 2>&1 | tail -6` 这一目录形态在本机
  Node 24.4.1 上因上述通病不可用；等价命令为
  `node --test extension/tests/*.test.js extension/tests/adapters/*.test.js`。


---

> **部署依赖项**：真机兼容矩阵（WALLET-ACC-1）、发布工程（WALLET-ACC-8）、WC 生产 relay 接入等条目集中登记于 [`../website/RELEASE_PREREQUISITES.md`](../website/RELEASE_PREREQUISITES.md)（B 组：钱包发布工程）。

---

## Extension 0.2 验收对照（plan §6.12.4 表行，2026-09-12 交付）

0.2 范围 = **testnet、多账户、REAL/PLAY 隔离、proof portal、备份恢复、网络
切换**。逐项对照与测试证据如下。

### 逐项对照

| 0.2 交付项 | 状态 | 实现与覆盖 |
|---|---|---|
| 多账户 | ✅ | 账本 `common/accounts.js`（纯函数）+ SW 存储：每账户独立保存 {keystore 密文, origin 授权簿, 网络选择}（§6.12.4 "每个 origin 的权限、网络和账户选择单独保存"）；wasm 会话单槽——锁定/切换当前账户不影响其他账户（其余账户本为密文态）；0.1 单账户无损迁移。UI：popup 账户列表/切换/新建。测试：`tests/accounts.test.js` 8 例 + E2E A10-A14 |
| 网络切换（testnet） | ✅ | `zchain_switchNetwork` 完整语义：注册表内网络（devnet/testnet）结构合法；异网必须弹窗二次确认（popup 内也二步确认）；批准后持久化到**当前账户**；同网幂等 no-op。**红线**：`zchain-mainnet-1` 刻意不注册 → `NetworkUnsupported`（注册表 + validation + 注册表测试三层钉死）；chain_id 参与签名摘要域由 wallet-core `preview_digest` 保证（WALLET-ACC-2 逻辑面测试）。测试：validation 29、networks 01-06、E2E B1-B3 + C9-C10 |
| REAL/PLAY 隔离 | ✅（展示面）| `wallet_get_all_notes`（REAL/PLAY 物理分库视图 + 分栏余额）+ `wallet_display_views`（`display.rs` 单实现：REAL claim 恒隐藏 + 托管风险提示常显、PLAY 视图无 REAL 字段）；popup 物理分栏渲染。**诚实边界**：REAL 仅展示，签名/提现不开放（provider 层 `AssetClassDisabledIn01` 维持，文案不暗示可提现）。测试：wasm_smoke 10-11、E2E A3-A5 |
| 备份恢复（WALLET-ACC-5） | ✅ | wasm `wallet_backup_export/import`（wallet-core ZCBK v1 单实现：Argon2id + ChaCha20-Poly1305 + 声明索引自检）；备份口令独立自包含（导出时 owner/DEK 信封以备份口令重封）；popup 导出 .zcbk 文件下载 + 导入校验 → 新增**锁定**账户。fail-closed：错口令 → BadPassword；篡改字节 → 拒绝；未来版本 → UnsupportedVersion（解密前拒绝）。测试：wasm_smoke 13a-d、Rust backup.rs 既有 3 例、E2E A6-A9 |
| proof portal | ✅（扩展侧）| 独立扩展页 `portal/portal.html`：hand binding → 网关 settlement 明细（payout_root/rake/层级 proven/soft_accepted）→ proof 归档（engine + 字节数）→ wallet-core wasm `wallet_verify_settlement_detail` 本地复验 → verifier 版本/耗时/结论。逻辑模块 `common/portal.js`（纯函数 + 注入 fetch）。**诚实边界**：复验面 = 结算关系（payout_root 复算 + 守恒 + 费率关系），STARK 证明本体不在浏览器内验证（stwo-wasm 非 0.2 交付）；层级是网关水位声明，原样展示不推进；网关不可达/未配置/404 如实报错不伪造结论。测试：`tests/portal.test.js` 8 例、Rust portal_check 6 例（native）、E2E D0-D5（真实 explorer_gateway + 真实证明注册表） |
| ForceInclude 状态展示（0.3 剩余项的展示面） | ✅（仅展示）| `common/receipts.js` 状态机（poker_l1 `force_include` 协议语义：deadline 10_000ms 同源常量）：signed → seen → included；导入 SeenReceipt（§5.3-1 形状，**不验签**——evidence 如实标注 `receipt_unverified_signature`）；超 deadline 提示"可经 L1 ForceInclude 路径"（**仅展示协议状态，不实现提交路径**）。测试：`tests/receipts.test.js` 8 例、E2E C4-C8 |
| 安全层不削弱 | ✅ | origin/nonce/expiry/sessionId/ABI/domain/预览摘要绑定全部保留；既有 79 用例零回退（仅 eip1193 用例 08 与 validation 用例 10 因 0.2 交付 switchNetwork 而更新断言对象——拒绝面语义不变）；新增 validation 29-31（mainnet 红线/REAL 关闭/脱敏透传） |
| 权限清单最小 | ✅ | manifest `permissions` 仍仅 `storage,alarms`；网关访问走 `optional_host_permissions` + portal 页内显式按钮（chrome.permissions.request），默认零主机授权 |

### 版本与诚实声明

- manifest/package/provider 版本：**0.2.0-alpha**（功能面完成后仍为 alpha；
  1.0 门槛 = 第三方安全审查 + 可复现构建/签名发布/SBOM，见 §6.12.4 表）。
- **0.2 未做（不虚标）**：
  - `zchain_verifyProof`/`zchain_watchProof` provider 方法仍未开放（proof
    portal 为扩展页交付；provider 面随 dapp SDK 规划）；
  - SeenReceipt 签名验证（wallet-core wasm 无 secp256k1 recoverable 验签
    入口）——回执 evidence 如实标注未验签；
  - ForceInclude 提交路径（L1 侧 check_censorship 提交）；
  - REAL 提现/入金/claim（Vault 未上线，页面不暗示可提现）；
  - 浏览器内完整 STARK 证明验证（stwo-wasm）。

### 验证记录（真实执行，2026-09-12）

- `node --test extension/tests/*.test.js extension/tests/adapters/*.test.js`：
  **112/112 通过**（既有 79 不回退 + 新增 33：validation 29-31、networks 6、
  accounts 8、receipts 8、portal 8）。目录形式 `node --test extension/tests/`
  在本机 Node v24.4.1 的既有通病不变，仍用通配形式。
- `node extension/tests/wasm_smoke.mjs`：通过（新增步骤：REAL/PLAY 分库视图、
  展示门、结算复验结构负例、备份导出→错口令/篡改 fail-closed→正确口令恢复→
  恢复件解锁同公钥）。
- `cargo test -p poker-wallet --release`：43/43 通过（零回归）；
  `cargo test -p poker-wallet --features wasm --bin wallet_core_wasm`：
  **6/6 通过**（wasm.rs portal_check 纯逻辑 native 测试：payout_root 复算/
  篡改赔付/声明根失配/守恒与费率 fail-closed/结构负例/混合资产类）。
- **真实浏览器 E2E（Extension 0.2 关键流）**：`node extension/tests/e2e/run_02.mjs`
  — **36/36 PASS**（Chrome for Testing 153.0.8010.36，headless=new + CDP +
  unpacked 加载；结果 JSON `tests/e2e/e2e02_result.json`、截图
  `tests/e2e/e2e02_screenshot.png`、逐步骤日志 `tests/e2e/e2e02_progress.log`）：
  - 多账户 + 备份恢复（A0-A14）：创建/水龙头/分库视图/展示门/导出/错口令/
    篡改 fail-closed/导入恢复公钥一致/第二账户/切换隔离/错误口令拒；
  - 网络切换（B1-B3）：popup 换网持久化到账户、testnet 网关未配置如实 null、
    mainnet 红线拒；
  - 页面 provider 流（C1-C10，经 content bridge + 真实 envelope）：连接授权
    （写入当前账户授权簿）、结构化签名预览批准、真实签名、回执状态机
    （signed/SeenReceipt 形状校验/receipt_unverified 标注/人工登记 included）、
    页面换网弹窗二次确认（devnet→testnet，getNetwork 跟随）；
  - 安全回归（E1-E2）：坏 previewHash → PreviewMismatch、锁定后签名 →
    SessionInvalid（不回退）；
  - **proof portal（D0-D5，真实 explorer_gateway --gen-fixture demo WAL +
    真实证明注册表，--public）**：真实结算明细（payout_root/rake/层级
    proven）→ proof 归档元数据（engine=host-validate-v2）→ wallet-core wasm
    复验 **verified**（payout_root 复算一致 + verifier 版本/耗时）；未知
    binding → SettlementNotFound；死端口 → GatewayUnreachable。

### 0.2 已知边界与降级点（如实）

1. **portal 跨源 fetch 的自动化路径**：Chrome 138+ 对 chrome-extension 页面
   访问 127.0.0.1 施加 Local Network Access 限制；E2E 的 D 步骤在
   http://127.0.0.1 同源 harness 页（`tests/e2e/portal_harness.html`）执行
   **同一逻辑模块**（common/portal.js + wallet_core wasm）对真实网关的管线；
   扩展 portal 页的加载与错误面有烟测（D0/D5）。生产用户的等价放行 =
   portal 页"授予网关主机权限"按钮（chrome.permissions.request，可选权限、
   需用户手势；manifest 默认零主机授权）。
2. **E2E 的 SeenReceipt 未验签**：协议验签入口属 wallet-core wasm 0.3 缝
   （secp256k1 recoverable），0.2 只做形状校验并如实标注。
3. **E2E 回执的 included 为人工登记**：0.2 无链上核对通道，evidence 恒为
   `local_manual_entry`（UI 文案明示"非链上证实"）。
4. **连接授权归属**：0.2 起 origin 授权簿按账户隔离；钱包尚无任何账户时
   （首次创建前）的连接批准不落授权簿（无归属对象，fail-closed 方向）。

---

## Extension 0.3/0.4 验收对照（plan §6.12.4 表行，2026-09-12 交付）

0.3（本轮）= **SNIP-12 会话密钥授权（UI + 流程）、REAL 提现预览（展示态）**；
0.4（本轮）= **授权簿/registry UI、会话密钥撤销/过期、单笔/每日限额执行、
capability matrix**。版本号 0.4.0-alpha（1.0 仍不宣称——外审/签名发布/SBOM
属外部门槛，可复现构建本节只交付仓库内工程面）。

### 逐项对照

| 交付项 | 状态 | 实现与覆盖 |
|---|---|---|
| SNIP-12 会话密钥授权（0.3） | ✅（popup UI 面） | popup"会话密钥"页：创建授权（**delegated key 生成走 wallet-core** `wallet_session_key_create`——私钥只活在 wasm 会话，锁定即毁；scope 默认只勾 PLAY 低风险集 `play/buyin/bet/settle`、transfer 可显式勾选、withdraw 永不可选；单笔/每日限额、桌白名单可选、有效期默认 24h 上限 365d）→ 展示 SNIP-12 授权摘要（**摘要由 wallet-core** `wallet_snip12_authorize_digest` 计算，revision 1 poseidon，与 `account_binding.rs` 单实现；typed data 组装复用 adapters/starknet.js，encode_type 与 wallet-core 逐字一致）→ devnet 入口形态登记（扩展侧构造 AuthorizeZChainKey + 保存约束记录，evidence 如实标注 `devnet_local_entry`）→ 撤销页（revoke → JS 粘滞位 + wallet-core `wallet_binding_status` 状态机双重确认 → 后续签名拒）。测试：`tests/sessions.test.js` 11 例 + wasm_smoke 14-18 步 + E2E S3-S7/L6-L7 |
| REAL 提现预览（0.3，展示态） | ✅ | `common/withdraw_preview.js`：金额/收款 owner/finality（所选 note 短板聚合，要求 finalized）/托管风险逐字段预览；**提交按钮恒禁用**——canSubmit 恒 false（wallet-core display.rs 展示门 vault_offline ∧ finality 合取），不开放真实提现提交（与 0.2 的 REAL 展示边界一致）。测试：`tests/withdraw_preview.test.js` 6 例 + E2E W1-W2 |
| WalletConnect 生产 relay（0.3 表项） | ⛔（如实挂起） | 前置 **B5：projectId 外部注册**（@walletconnect/sign-client 打包入口 + relay 凭证）。适配核心 0.1 已备（注入 SignClient 即激活，缺省 dormant 如实展示）；capability matrix 的 WC 行如实报 dormant 并注明 B5 外部依赖。登记于 `website/RELEASE_PREREQUISITES.md` B 组 |
| 授权簿/registry UI（0.4） | ✅ | popup"授权簿"页：按 origin 的权限列出/撤销（§6.12.4 "每个 origin 的权限、网络和账户选择单独保存"，授权簿按账户隔离）；会话密钥列表（scope/单笔每日限额/今日已用/桌白名单/有效期/状态 active-exhausted-revoked-expired-not_yet_valid/登记来源 evidence/撤销/删除）。**撤销 fail-closed**：JS 层（`common/sessions.js` governingBinding：origin+chain 最新 active/exhausted/revoked binding；revoked → 该 origin 签名一律拒，粘滞，删除记录是唯一清除路径且为显式用户动作）+ wallet-core wasm 层（`wallet_session_admit` 独立复检）双层校验。测试：sessions.test.js 04-06/10-11 + E2E R1-R4/L6-L9 |
| 单笔/每日限额执行（0.4） | ✅ | 签名路径（handleSign）：预览后、弹窗前先过 **JS 第一层**（`admitOperation`，判定顺序与 wallet-core `session_admission` 逐条一致：撤销 → 换网 → 时间窗 → scope → 桌白名单 → 单笔限额 → 日限额；金额口径 = 预览 amount_in，BigInt 十进制比较），再过 **wallet-core wasm 第二层**（`wallet_session_admit` = `account_binding::binding_admission` 单实现；拒绝是结构化 verdict `{admitted:false, rejected_reason}`）。签名成功后 `recordSpend` 记账日限聚合（unix 天窗，跨天清零）。每类拒绝有稳定码：SessionRevoked/SessionChainMismatch/SessionNotYetValid/SessionExpired/SessionScopeNotAllowed/SessionTableNotAllowed/SessionOverPerTxLimit/SessionOverDailyLimit。测试：sessions.test.js 07-09 + wasm_smoke 16 步（每类负例）+ E2E L1-L5（限额内成功 + 记账 + 超限弹窗前拒） |
| 执行语义（诚实声明） | ✅ | governing binding 只取 origin+chain 下**最新**登记的 active/exhausted/revoked 记录；expired/not_yet_valid（自然时间窗外）→ 授权不再适用，回到常规签名路径（origin 授权 + 显式确认不变），避免自然过期把 origin 永久锁死；revoked → 恒拒（粘滞），删除记录（显式用户动作）才回常规路径 |
| capability matrix（0.4，WALLET-ACC-7 UI 面） | ✅ | `common/capability_matrix.js`：复用 adapters 的 capability∩白名单逻辑（shared.js 只读白名单与签名全拒表、WC dormant 状态、starknet.js fail-closed 探测），结构化输出三协议行（EIP-1193/WC/Starknet）各自 supported 列表与 denied 列表（每项带拒绝原因：EvmSigningForbidden/CapabilityMissing 盲签红线/ScopeForbidden note spend 红线/B5 dormant）；popup"钱包能力矩阵"卡渲染。测试：`tests/capability_matrix.test.js` 6 例 + E2E C1-C4 |
| 可复现构建（1.0 仓库内工程面，WALLET-ACC-8） | ✅（工程面） | `scripts/extension_reproducible_build.sh`：锁定输入（node 版本、vendor wasm/胶水 SHA-256、源文件树哈希清单）→ 两阶段独立组装 + mtime 归一（SOURCE_DATE_EPOCH，缺省 = HEAD 提交时间）+ 文件排序 + `zip -X` → 逐字节比对 → `REPRODUCIBLE PASS` + 包哈希；不一致时逐成员哈希列出差异文件。产出 `extension/dist-checksums.txt`（清单 + SHA-256 + 环境指纹）供发布附随。**诚实边界**：wasm 按"锁定输入"复核哈希、不在脚本内重建（重建需固定工具链容器）；wasm 源码级可复现重建/签名发布/SBOM 属 1.0 外部交付，见文末"已知边界" |
| wasm.rs 缺口（0.3/0.4 缝） | ✅ | `poker-wallet/src/wasm.rs` 新增 `session_check` 纯模块（非门控，native 可测：`parse_message/parse_binding/status/admit/authorize_digest`，全部为 wallet-core `account_binding`/`key_manager` 公开纯函数之上的 JSON 前端，零密码学实现）+ wasm32 入口：`wallet_session_key_create`（delegated key 生成，OS 随机源 + 私钥不出边界；bindingId 缺省时生成并**掩码为规范 felt**，保证 SNIP-12 摘要构造恒可行）、`wallet_session_key_list`、`wallet_binding_status`、`wallet_session_admit`、`wallet_snip12_authorize_digest`。**核心逻辑零改动**（account_binding.rs/key_manager.rs 只读复用） |

### 验证记录（真实执行，2026-09-12）

- `node --test extension/tests/*.test.js extension/tests/adapters/*.test.js`：
  **135/135 通过**（既有 112 零回退 + 新增 23：sessions 11、withdraw_preview 6、
  capability_matrix 6）。
- `node extension/tests/wasm_smoke.mjs`：通过（真实密码学路径全链 + 新增
  14-18 步：delegated key 生成（公钥级输出、无 secret 泄漏、bindingId 幂等
  upsert）、binding 状态查询（active/revoked/exhausted + 日限余量）、限额
  enforcement（正例 + OverPerTx/TableNotAllowed/ScopeNotAllowed/ChainMismatch/
  Revoked/DailyLimitExhausted 六类负例）、SNIP-12 摘要（确定性 + scope 字段
  敏感 + domain/encode_type 形状）、锁定后会话密钥清空（私钥不持久化边界））。
- `cargo test -p poker-wallet --release`：43/43 通过（零回归）；
  `cargo test -p poker-wallet --features wasm --bin wallet_core_wasm`：
  **11/11 通过**（既有 portal_check 6 + 新增 session_check 5：状态机查询/
  准入正负例（含日限跨天窗）/摘要与 Rust 单实现逐字节一致 + 字段敏感/
  解析 fail-closed）。
- **真实浏览器 E2E**：
  - `node extension/tests/e2e/run_03.mjs`（0.3/0.4 关键流）——**30/30 PASS**
    （Chrome for Testing 153，headless=new + CDP + unpacked 加载；结果 JSON
    `tests/e2e/e2e03_result.json`、截图 `e2e03_screenshot.png`、日志
    `e2e03_progress.log`）：S0-S5（草稿 → delegated key + SNIP-12 摘要 →
    devnet 登记 → registry 投影）、L0-L11（连接 → 限额内签名成功 + 日限
    记账 200 → 单笔超限弹窗前拒 → 撤销（JS+wallet-core 双重确认）→ 撤销后
    签名拒 → 删除后常规路径恢复）、R1-R4（origin 授权簿撤销 → 页面
    OriginNotPermitted → 重连恢复）、C1-C4（矩阵三行 + WC dormant + EIP-1193
    签名全拒）、W1-W2（提现预览恒禁用）、P1（provider 授权方法面
    NotSupportedIn01——popup UI 为唯一入口）。
  - `node extension/tests/e2e/run_02.mjs`（0.2 回归）——**36/36 PASS**
    （0.3/0.4 改动对既有关键流零回退）。
  - `node extension/tests/e2e/run_04.mjs`（0.4 / stwo-wasm path A：portal STARK
    验证流）——**12/12 PASS**（Chrome for Testing 153；fixture 网关 + 真实
    canonical 证明：STARK wasm 完整验证 verified（实测 1790ms，超 500ms 预算
    如实标注）→ 篡改拒绝 StarkVerifyRejected → 非归档 StarkArchiveInvalid →
    ProofNotFound 如实跳过 → GatewayUnreachable/GatewayTimeout 三态 →
    fail-closed 结论规则。fixture settlement 复验步骤照常执行、结果如实记录
    不作通过断言（真实结算链路由 run_02 覆盖）。结果
    `tests/e2e/e2e04_result.json`、截图 `e2e04_screenshot.png`）。
- **可复现构建（真实执行）**：`bash scripts/extension_reproducible_build.sh`
  → `REPRODUCIBLE PASS`（build1 = build2，逐字节一致；SOURCE_DATE_EPOCH =
  HEAD 提交时间 1789216779；node v24.4.1；wasm sha256
  `0f6bce9320735b761fcb5f275269b6cc17fbbc6798fab80ce7540ee4fb4ae7d9`；源树
  74 文件）。如实说明：包内容含本文件，故任何后续文件变更都会改变包哈希
  （本节刻意不记录"终态哈希"——它随文档演进而失效）；PASS/FAIL 判定依赖的
  是**两阶段是否逐字节一致**，与具体哈希值无关，复跑脚本即重新产出并核对。
  最近一次运行的清单 + SHA-256 见 `extension/dist-checksums.txt`（发布附随
  件，每次运行刷新；该产物自身排除在包外，不产生自引用）。

### 版本与诚实声明

- manifest/package/provider 版本：**0.4.0-alpha**。0.3/0.4 功能面完成后仍为
  alpha；**1.0 不宣称**（第三方安全审查、签名发布/SBOM、wasm 工具链固定的
  源码级可复现重建、硬件钱包适配属 1.0 外部交付）。
- **0.3/0.4 未做（不虚标）**：
  - **链侧 admission 登记**：devnet 入口形态 = 扩展侧本地登记约束记录
    （evidence = `devnet_local_entry`）；AuthorizeZChainKey 的链上登记与
    Starknet 钱包签名回填（popup 表单地址为手输入口形态）随 Vault/appchain
    admission 接口交付；
  - **会话密钥自身的签名路径**：delegated key 私钥只活在 wasm 会话（锁定即
    毁、不持久化——诚实边界，wasm_smoke 18 步钉住）；0.3/0.4 交付的是授权
    与**约束执行面**（owner 路径签名受 binding 约束 + 撤销拒），会话密钥
    直接出 SpendAuth 签名的路径随链侧 admission 语义一起交付；
  - provider 方法 `zchain_authorizeSessionKey`/`zchain_revokeSessionKey` 仍
    未开放（NotSupportedIn01；授权由钱包 popup UI 发起，dapp SDK 面后置）；
  - WalletConnect 生产 relay（B5：projectId 外部注册）；
  - 真实提现提交（Vault 未上线；提现预览恒展示态）。

### 0.3/0.4 已知非确定源（可复现构建，如实）

1. `extension/vendor/wallet-core/wallet_core_wasm_bg.wasm` 及胶水：**锁定
   输入**（脚本复核哈希，不在脚本内重建）。从源码重建需要固定
   rustc/wasm-bindgen 0.2.127/LLVM clang 工具链（容器化），属 1.0 外部交付；
   跨工具链版本的 wasm 字节不保证一致。
2. zip 归档元数据已消除（固定 mtime + 排序 + `-X`）；宿主 zip 实现差异
   （如 zip64 策略）理论上可致 FAIL——脚本会逐成员列出差异，如实失败。
   开发期实测踩坑一则（已修复并写入脚本注释）：macOS 大小写不敏感文件系统
   会把 `find -exec TOUCH {} +` 中的函数名解析成 `/usr/bin/touch`（丢掉
   `-t` 参数）→ 两阶段 mtime 相差数秒 → 偶发 FAIL；修复后连续 6 次运行
   全部 PASS。
3. `.DS_Store`、`*.log`、脚本自身产物（dist-checksums.txt、build 目录）一律
   排除在包外。
