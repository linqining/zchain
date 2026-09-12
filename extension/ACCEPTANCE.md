# ACCEPTANCE — Extension 0.1 验收对照（plan-appchain §6.12.7）

Extension 0.1 交付范围 = PLAY、本地 keystore、ZChain provider、开桌/买入/结算
签名、devnet。本文逐条对照钱包验收门槛，如实标注：✅ 已实现并测试 /
◐ 部分 / ⛔ 0.2+（未实现，不虚标）。

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
| WALLET-ACC-5（备份恢复 fail-closed） | ⛔ 0.2（wallet-core `backup` 已实现并有测试；扩展 UI 未接） |
| WALLET-ACC-6（REAL 显示门 / PLAY 不误显示 REAL） | ◐ 0.1 PLAY-only：REAL 在 provider/校验层全链路拒绝（测试 17）；`display.rs` 的 REAL 页面门是 0.2 REAL UI 交付时接入 |
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
