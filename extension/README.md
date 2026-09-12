# ZChain Wallet — Browser Extension 0.1（plan-appchain §6.12.4）

浏览器钱包插件的最小可用版本（Minimum Usable Skeleton）。范围 = **PLAY、本地
keystore、ZChain provider（`window.zchain`）、开桌/买入/结算签名、devnet**。

**密码学零 JS 实现**：摘要（blake2s/poseidon）、签名（secp256k1）、加密
（Argon2id + ChaCha20-Poly1305）全部由 [wallet-core](../poker-wallet)
（lib 名 `wallet_core`，plan §6.12.3 的唯一实现）以 WASM 形式完成。本目录
只有消息校验、状态机与 UI。

## 架构

```text
Web page (dapp)
   │  window.postMessage（页面可伪造，不信任）
   ▼
content/bridge.js ──────────── isolated world；origin 由浏览器固定，
   │  chrome.runtime.sendMessage  附加 sender.origin 不可伪造
   ▼
background/service_worker.js ── 内部 RPC 路由 / 会话与锁屏状态机 /
   │  common/validation.js       待签名请求状态机（批准/拒绝/超时）
   │  （origin 白名单·nonce 单调·expiry·sessionId·
   │    method/参数/金额/网络/ABI/domain 校验）
   ▼
common/wallet_core.js → vendor/wallet-core/wallet_core_wasm*.wasm
   │                             （poker-wallet 编译产物；唯一密码学边界）
   ▼
encrypted vault：chrome.storage.local 只存密文
  （owner key 口令信封 + DEK 信封 + PLAY note 库快照，全部 wallet-core 格式）
```

provider（`content/inpage.js`，MAIN world）暴露版本化 `zchain_*` 接口；
**不冒充 EIP-1193**：不写 `window.ethereum`、不派发 EIP-6963 announce。
EIP-6963 发现仅用于外部 EVM 钱包（MetaMask/Rabby/Argent X/Braavos）共存；
ZChain 使用独立 namespace/名称/icon/capability 矩阵（`zchain_getCapabilities`），
避免被 dapp 误当 MetaMask 连接。

连接协议适配器（`adapters/`，M6"钱包连接协议"）：EIP-1193 兼容形状（只读
eth_* 子集，`eth_sign`/`eth_sendTransaction` 等签名方法默认全拒）、WalletConnect
v2 适配核心（`zchain:` namespace、getCapabilities 能力探测、重放/过期拒；
SignClient 注入式 + 测试 stub，零 npm 进构建）、Starknet 钱包接口（SNIP-12
`AuthorizeZChainKey` 授权委托，对接 wallet-core account_binding）。三适配器
均暴露独立 ZChain 网络身份（`zchain-devnet-1` / EIP-1193 映射别名 `0x7a0001`
/ `zchain:zchain-devnet-1`），不伪装成 Ethereum 主网/Starknet 主网账户——
架构、映射表与红线清单见 `adapters/README.md`。

## 安装（加载 unpacked）

1. （可选，重新构建 WASM，见下文）产物已提交：`vendor/wallet-core/`。
2. 打开 `chrome://extensions` → 开启"开发者模式"→ "加载已解压的扩展程序"
   → 选择本目录（`extension/`）。
3. 验证 dapp 流程：
   ```bash
   python3 -m http.server -d extension/demo 8080   # 仓库根目录执行
   # 访问 http://localhost:8080/，点页面按钮；content_scripts 只匹配
   # http://localhost/* 与 http://127.0.0.1/*（0.1 的示例域边界）
   ```
4. 注意：Google 品牌 Chrome 137+ 命令行 `--load-extension` 已被禁用；用
   chrome://extensions 手动加载，或用 Chrome for Testing / Chromium。

## wallet-core WASM（真实实现，路线 a）

`poker-wallet/src/wasm.rs`（feature `wasm` + `wasm32` target 双重门控，
`required-features = ["wasm"]`，默认构建/43 个测试/CLI 完全不受影响）暴露
JSON-in/JSON-out 入口：`wallet_create / wallet_unlock / wallet_lock /
wallet_persist / wallet_faucet_play / wallet_get_notes / wallet_preview /
wallet_sign / wallet_sign_settle_input / wallet_core_meta`。约定：
金额十进制字符串（JS Number 只有 2^53 安全整数）、key/承诺/摘要 hex、
`SealedEnvelope`/`SettlementRecord`/`FeePolicy` 走 borsh 稳定字节 ABI。

构建与绑定（本仓库已执行，产物在 `extension/vendor/wallet-core/`）：

```bash
# 本机需要支持 wasm32 后端的 clang（Apple clang 没有；Homebrew LLVM 有）
CC_wasm32_unknown_unknown=/usr/local/opt/llvm/bin/clang \
cargo build -p poker-wallet --target wasm32-unknown-unknown \
            --features wasm --release --bin wallet_core_wasm

wasm-bindgen --target web \
  --out-dir extension/vendor/wallet-core \
  target/wasm32-unknown-unknown/release/wallet_core_wasm.wasm
```

依赖说明（`poker-wallet/Cargo.toml` 追加，均不影响 native 构建）：
`wasm-bindgen = "=0.2.127"`（与仓库 wasm-bindgen-cli 版本严格一致）+
wasm32 目标下 `getrandom = { version = "0.2.17", features = ["js"] }`
（OsRng 经浏览器 `crypto.getRandomValues`；keystore salt/nonce、密钥生成
在 WASM 运行时可用）。

跨端一致性钩子（WALLET-ACC-2）：同一 `SigningRequest` 的 digest/signature
bytes 由 wallet-core 单实现保证；验收挂
`cargo test -p poker-wallet --release tests::wallet_acc_2_*`
（poker-wallet/tests/acceptance.rs）+ `extension/tests/wasm_smoke.mjs`
（同一请求经 WASM 的 digest 与 native 同源实现一致，及其 preview/sign 链路）。
0.2 交付移动端时在同一钩子上加桌面/移动向量对比。

## 安全不变量（对照 plan §6.12.4"插件必须支持"）

| 要求 | 状态 |
|---|---|
| EIP-6963 只用于外部 EVM 钱包共存；不冒充 MetaMask | ✅ 已实现（inpage.js 注释+行为；`isZChain`，无 `window.ethereum`） |
| 每 origin 权限/网络/账户单独保存；首连/换网/提现/批量签名二次确认 | ✅ 已实现（validation.js `originIsGranted/grantOrigin` + `requiresExplicitConfirm`；0.1 换网/提现直接拒绝） |
| 签名前结构化预览（chain_id/table_id/asset_class/金额/收款 owner/rake/hand_binding/request_id/proof 状态/过期） | ✅ 已实现（wallet-core `SigningPreview` → popup/popup.js 逐字段渲染 + REAL/PLAY 徽章） |
| 会话密钥授权单独展示 | ⛔ 0.3（SNIP-12 delegated key） |
| 站点消息带 nonce/origin/expiry/sessionId；后台校验来源/replay/ABI/domain/version/取消 | ✅ 已实现（validation.js 28 个 node 测试 + 浏览器 E2E） |
| CSP 禁远程脚本与运行时下载；权限清单最小化 | ✅（`script-src 'self' 'wasm-unsafe-eval'`；`wasm-unsafe-eval` 仅为捆绑 WASM 所需，不允许 eval/远程脚本/运行时下载。permissions 仅 `storage,alarms`（自动锁屏心跳）；无 host 权限，`optional_host_permissions` 备用；content_scripts 限定 localhost 示例域） |
| 断网查看/签署缓存操作，不伪造 finalized/claimable | 部分：签名与查看全本地（无网络依赖）；proof 状态如实显示 note 库内状态，无 finalized 伪造。断网 UI 专门处理 ⛔ 0.2 |
| 只向页面暴露公钥/地址/签名结果/脱敏状态；不暴露 spend secret/助记词/note 明文 | ✅（`sanitizeNotesForPage` + 测试 26；nullifier/spend secret 永不出 wasm/storage） |
| 可复现构建/签名发布/SBOM | ⛔ 1.0（WALLET-ACC-8） |

## 迭代路线（§6.12.4 表）

| 版本 | 交付内容 | 本仓库状态 |
|---|---|---|
| **Extension 0.1** | PLAY、本地 keystore、ZChain provider、开桌/买入/结算签名、devnet | ✅ 本目录（骨架 + 真实安全层 + 真实 wallet-core WASM） |
| Extension 0.2 | testnet、多账户、REAL/PLAY 隔离、proof portal、备份恢复、网络切换 | ⛔ |
| Extension 0.3 | WalletConnect Vault adapter、提现预览、relay/ForceInclude 状态、SNIP-12 会话密钥授权 | ⛔ |
| Extension 0.4 | account binding registry、会话密钥撤销/过期、单笔/每日限额、Stark wallet capability matrix | ⛔ |
| Extension 1.0 | 第三方安全审查、可复现构建、硬件钱包适配（仅可读签名） | ⛔ |

## 测试

```bash
node --test "extension/tests/*.test.js" "extension/tests/adapters/*.test.js"
                                         # 28 个安全校验用例 + 51 个适配器用例
                                         # （node:test，无框架；目录形式
                                         # `node --test extension/tests/` 受本机
                                         # Node 24 通病影响，用通配形式）
node extension/tests/wasm_smoke.mjs       # WASM 冒烟（真实密码学路径）
cargo test -p poker-wallet --release      # 43 个 wallet-core 测试（不回归）
```

`tests/validation.test.js`：伪造 origin、重放/回退 nonce、过期信封、session
绑定/锁定、未知 method、0.1 未交付 method、缺参、金额溢出/非法、换链不符、
ABI/domain 不认识、REAL/提现类边界、权限最小化判定（首连/换网/提现/批量）、
请求状态机（批准/拒绝/超时/去重）、输出脱敏、origin 规范化。
`tests/adapters/`：连接协议适配器——EIP-1193（方法路由/白名单/EVM 签名拒绝/
chainId 映射/事件转发）、WalletConnect v2（proposal 批准与拒绝/能力缺失拒/
会话过期/请求重放/参数校验透传/事件转发）、Starknet（typed data 与
wallet-core 规范逐字一致/签名验证正负例/scoped 授权超 scope 与过期拒）、
注册面（安全默认/开关真实效果/dormant 如实）。
`tests/wasm_smoke.mjs`：wallet-core WASM 的真实 keystore/签名链路冒烟
（错口令 fail-closed、nonce 重放拒、脱敏检查），缺产物时自动跳过。

## 已知边界（如实声明，不虚标）

- `wallet_faucet_play` 是**本地 devnet 水龙头 stub**：无链上 mint、无同步；
  真链接入在 0.2（`sync::ChainSource` 缝）。
- SW（service worker）被浏览器回收即自动锁定（fail-closed）；待签名请求随之
  超时。pending 请求不跨 SW 生命周期持久化（0.2 改进）。
- nonce 账本存 `chrome.storage.session`（浏览器会话内单调；重启重置——重置后
  页面 nonce 计数也重启，不存在重放窗口，因为签名 nonce 由 wallet-core 的
  `(chain, nonce)` 账本二次防重放）。
- 结算 0.1 走整记录补签路径（`Settle`）；逐输入 `sign_settle_input` 的
  operator 收集路径 wasm 已具备、provider 尚未开放（0.2）。
- 无图标资源（MV3 可选）；popup 为最小样式。
