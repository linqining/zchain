# ZChain Wallet — Browser Extension 0.6.0-alpha（plan-appchain §6.12.4）

浏览器钱包插件（0.1 最小可用骨架 → 0.2 迭代 → 0.3/0.4 迭代 → 0.5 迭代 →
0.6 迭代 → **0.6.1 交互迭代**）。
**0.6.1 新增 = MetaMask 式一键 onboarding**：新用户打开插件首屏即
"一键创建钱包"（一次点击同时创建 ZChain / EVM / Starknet 三层账户，自动
生成强口令且只在成功页显示一次，可复制保存；另设"高级：自定义口令创建"
与导入入口）；已有任一层钱包的老用户**永不触发**创建流程，直接进入多链
总览首页（三链卡片 + 统一解锁 + 全部锁定）。
**0.6 新增 = Starknet 账户层（STARK curve 原生支持）**：STARK curve
ECDSA/Pedersen/starknet_keccak 自包含实现（公共向量钉住）、UDC 公式地址
推导、invoke v1 签名广播、余额/合约调用/交易记录/钱包管理全功能（与 EVM
层同规格）。**0.5 新增 = 完整可用的 EVM 兼容多链账户层**：余额查询、合约
调用（读/写）、交易记录查询（本地账本 + 链上 explorer 合并）、钱包管理
（口令加密 keystore、创建/导入/锁定/解锁、私钥导出、修改口令、删除账户、
多账户切换）。
0.2 新增 = testnet、多账户、REAL/PLAY 隔离展示、proof portal、备份恢复、
网络切换；0.3 = SNIP-12 会话密钥授权（UI + 流程）、REAL 提现预览（展示态）；
0.4 = 授权簿/registry UI、会话密钥撤销/过期、单笔/每日限额执行（wasm/JS
双层 fail-closed）、capability matrix。0.1 基线 = PLAY、本地 keystore、
ZChain provider（`window.zchain`）、开桌/买入/结算签名、devnet。
诚实版本策略：0.5 功能面完成后仍为 **alpha**（1.0 门槛 = 第三方安全审查 +
wasm 源码级可复现重建/签名发布/SBOM；仓库内可复现构建工程面已随 0.4 交付，
见 `scripts/extension_reproducible_build.sh`）。

## Extension 0.5：EVM 兼容账户层（本轮交付）

popup 顶栏 **ZChain / EVM 钱包** 双模式切换。EVM 层与既有 ZChain note 钱包
并存，互不影响（各自 keystore、各自会话、统一自动锁屏心跳）。

| 要求 | 实现 |
|---|---|
| **钱包余额查询** | JSON-RPC（`eth_getBalance/getTransactionCount/gasPrice/eth_chainId`），水龙头（dev 链）→ 余额/nonce/gas/chainId 展示 + RPC chainId 不符告警 |
| **合约调用** | 只读：`eth_call`（ERC-20 预设免填 ABI + 自定义 ABI JSON；金额按 decimals 换算）；写：ABI 编码 → 交易预览卡（to/value/data/gas/手续费/chainId 逐字段）→ 确认 → EIP-155 签名 → `eth_sendRawTransaction` |
| **交易记录查询** | 本地账本（pending → confirmed/failed 回执状态机）+ Etherscan 兼容 `txlist` 端点合并（hash 去重、本地回执状态优先）+ 待确认交易自动对账 |
| **钱包管理** | 创建（随机 secp256k1 + PBKDF2-SHA256 600k + AES-256-GCM keystore）、导入私钥（同址重复导入拒绝）、锁定/解锁（错口令 fail-closed）、**私钥导出**（口令确认）、修改口令（重加密）、删除账户、多账户切换、网络/RPC/Explorer 设置 |
| **E2E（浏览器操作）** | `tests/e2e/run_05.mjs`：36 步全 UI 操作（点击/输入/确认）真实浏览器测试 + 本地开发链（`tests/e2e/devchain.mjs`）链上核对 |

密码学边界（如实声明）：EVM 层的 keccak256/secp256k1/RLP/EIP-155 实现于
`common/evm/crypto.js`（自包含零依赖；**与 ZChain 路径的 wallet-core WASM
边界无关**）。正确性由公共测试向量钉住（`tests/evm/crypto.test.js`）：
keccak256 标准向量、secp256k1 G 点已知向量、EIP-55 规范示例、EIP-155 规范
示例交易（signing hash + 规范签名交易的 sender 恢复一致性）；e2e 的开发链
用同一模块独立解码 raw 交易并恢复 sender 与钱包地址核对（交叉验证）。k 的
生成为 RFC 6979 结构的 HMAC-DRBG（哈希函数用 keccak256，非 RFC 规定的
SHA 族——确定性性质与安全论证相同）。keystore 用 WebCrypto 平台原语
（PBKDF2-SHA256 600k 派生 + AES-256-GCM；私钥只在 SW 内存会话，锁定/SW
回收即毁）。私钥/口令永不落 storage、不入日志（WALLET-ACC-4 同纪律）。

网络预设：ZChain EVM DevNet（本地 8545，支持水龙头）/ Ethereum / Sepolia /
Base / Arbitrum One + 每链自定义 RPC 与 Explorer API 覆盖（manifest 已声明
`http://localhost/*`、`http://127.0.0.1/*` host 权限供本地节点使用；公网 RPC
走 CORS 开放的公开端点）。不冒充 EIP-1193 provider 的红线不变（无
`window.ethereum` 注入）。

`common/evm/` 模块（全部纯函数、node --test 直覆盖）：
`crypto.js`（keccak256/secp256k1/RLP/EIP-155/EIP-55/ABI 编解码/数值格式化）、
`keystore.js`（加密 keystore/导入导出/改密码）、`rpc.js`（JSON-RPC 客户端，
稳定错误码 RpcUnreachable/RpcError/RpcBadShape）、`networks.js`（链预设与
覆盖解析）、`contracts.js`（ABI 解析/编码/解码/ERC-20 预设）、`txs.js`
（本地交易账本状态机）、`history.js`（explorer 行归一 + 合并）。

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
  （owner key 口令信封 + DEK 信封 + REAL/PLAY 双库快照，全部 wallet-core 格式）
```

0.2 新增内部模块（全部纯函数、零密码学、node --test 直接覆盖）：

| 模块 | 职责 |
|---|---|
| `common/networks.js` | 网络注册表（devnet/testnet；**mainnet 刻意不注册**——红线）、网关 URL 解析 |
| `common/accounts.js` | 多账户账本（每账户 {keystore 密文, origin 授权簿, 网络}；0.1 迁移） |
| `common/receipts.js` | 交易回执 inclusion 状态机（poker_l1 force_include 协议语义，仅展示面） |
| `common/portal.js` | proof portal 客户端（URL/错误分类/本地复验编排，注入式 fetch） |
| `portal/portal.html|.js` | proof portal 扩展页（验证一手牌 + 网关设置 + 可选主机权限按钮） |
| `tests/e2e/run_02.mjs` | 0.2 关键流真实浏览器 E2E（含真实 explorer gateway） |

0.3/0.4 新增内部模块（同一纪律：纯函数、零密码学、node --test 直接覆盖）：

| 模块 | 职责 |
|---|---|
| `common/sessions.js` | SNIP-12 会话密钥授权簿（登记/撤销粘滞/删除）+ **签名路径限额执行**（与 wallet-core `session_admission` 同序的 JS 第一层：撤销→换网→时间窗→scope→桌白名单→单笔→日限额；wasm 第二层 = `wallet_session_admit`）；授权草稿复用 adapters/starknet.js 规范校验 |
| `common/withdraw_preview.js` | REAL 提现预览（展示态）：金额/收款 owner/finality 短板聚合/托管风险；canSubmit 恒 false（展示门 ∧ finality 合取），不开放真实提交 |
| `common/capability_matrix.js` | 外部钱包能力矩阵（EIP-1193/WC/Starknet 三协议 supported/denied 结构化输出，复用 adapters 白名单常量与 fail-closed 探测） |
| `tests/sessions.test.js` 等 | 0.3/0.4 纯逻辑测试（+23 例） |
| `tests/e2e/run_03.mjs` | 0.3/0.4 关键流真实浏览器 E2E（30 步） |
| `common/stwo_verify.js` + `vendor/stwo-verify/` | 0.4 STARK 本体浏览器端完整验证（stwo wasm 验证器，path A）：加载 vendored wasm、转发归档字节；验证语义零 JS 重实现。产物带 sha256 清单（`vendor/stwo-verify/MANIFEST.json`）；实测延迟 p50≈1.7–1.8s（**超 500ms 预算，portal 如实标注**），见 `docs/stwo-wasm-path-a.md` |
| `tests/stwo_verify.test.js` | STARK 阶段单测（结果分类/fail-closed）+ 真实 wasm 冒烟（正例 verified + 篡改拒绝） |
| `tests/e2e/run_04.mjs` | 0.4 portal STARK 验证流真实浏览器 E2E（fixture 网关 + 真实 canonical 证明；12 步） |
| `scripts/extension_reproducible_build.sh`（仓库 `scripts/`） | 可复现构建（两阶段比对 + dist-checksums.txt，见下文"可复现构建"节） |

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

## 交互（0.6.1 一键 onboarding）

- **新用户**：打开插件 → 欢迎页"一键创建钱包"→ 一次点击创建三链账户 →
  成功页显示自动口令（只显示一次，可复制）与三链地址 → "开始使用"进入多链
  总览。进阶路径：自定义口令创建 / 各链私钥导入（展开项）。
- **老用户**：任一层已有钱包即视为已 onboarded——欢迎页与创建流程不再触发；
  首页直接是三链总览卡片（进入钱包 / 全部锁定）；锁定态出现**统一解锁**
  （一个口令尝试解锁全部层，任一层独立 keystore 互不影响）。
- 覆盖测试：`tests/e2e/run_07.mjs`（13 步浏览器操作）。

## 安装（打包 / 加载 unpacked）

**一键打包**（产出可在 Chrome 安装的扩展包 + 真实加载验证）：

```bash
bash extension/scripts/pack.sh --verify
# → dist/unpacked/                          直接被 Chrome“加载已解压”的目录
# → dist/zchain-wallet-extension-v<版本>.zip manifest 在包根（可直接上传
#   Chrome Web Store 开发者后台，或解压后加载）
# → dist/SHA256SUMS.txt                     zip 与逐文件 SHA-256 清单
#   --verify 会用 Chrome for Testing headless 真实加载 dist/unpacked：
#   service worker 启动 + popup 渲染 + runtime 消息往返 + 三模式按钮
#   （--out DIR 换输出目录；--skip-checks 跳过 node --check 加速）
```

**在 Chrome 安装（三选一）**：

1. `chrome://extensions` → 开启"开发者模式"→ "加载已解压的扩展程序" →
   选择 `extension/dist/unpacked/`（或解压 zip 后的目录）；
2. Chrome Web Store 开发者后台直接上传 `dist/*.zip`；
3. Chrome for Testing / Chromium / 企业策略：`--load-extension=<绝对路径>`。

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
| 每 origin 权限/网络/账户单独保存；首连/换网/提现/批量签名二次确认 | ✅ 已实现（validation.js `originIsGranted/grantOrigin` + `requiresExplicitConfirm`；0.2 起授权簿与网络按账户隔离，换网交付完整语义：注册表内网络 + 弹窗二次确认，提现类仍拒绝） |
| 签名前结构化预览（chain_id/table_id/asset_class/金额/收款 owner/rake/hand_binding/request_id/proof 状态/过期） | ✅ 已实现（wallet-core `SigningPreview` → popup/popup.js 逐字段渲染 + REAL/PLAY 徽章） |
| 会话密钥授权单独展示 | ✅ 0.3/0.4：popup"会话密钥"页（SNIP-12 `AuthorizeZChainKey`：delegated key 生成走 wallet-core、scope 默认 PLAY 低风险集、单笔/每日限额、桌白名单、有效期 → wallet-core 计算的 SNIP-12 摘要确认 → devnet 入口形态登记 → 撤销粘滞）；授权约束在签名路径强制（wasm/JS 双层） |
| 站点消息带 nonce/origin/expiry/sessionId；后台校验来源/replay/ABI/domain/version/取消 | ✅ 已实现（validation.js 28 个 node 测试 + 浏览器 E2E） |
| CSP 禁远程脚本与运行时下载；权限清单最小化 | ✅（`script-src 'self' 'wasm-unsafe-eval'`；`wasm-unsafe-eval` 仅为捆绑 WASM 所需，不允许 eval/远程脚本/运行时下载。permissions 仅 `storage,alarms`（自动锁屏心跳）；无 host 权限，`optional_host_permissions` 备用；content_scripts 限定 localhost 示例域） |
| 断网查看/签署缓存操作，不伪造 finalized/claimable | ✅ 0.2：签名与查看全本地；proof 状态如实显示 note 库内层级；portal 层级（proven/soft_accepted）是网关水位声明，原样展示不推进；网关不可达/未配置/404 有稳定错误码（GatewayUnreachable/GatewayNotConfigured/SettlementNotFound），不伪造验证结论 |
| 只向页面暴露公钥/地址/签名结果/脱敏状态；不暴露 spend secret/助记词/note 明文 | ✅（`sanitizeNotesForPage` + 测试 26；nullifier/spend secret 永不出 wasm/storage；会话密钥 delegated 私钥只活在 wasm 会话，公钥级信息才出边界） |
| 可复现构建/签名发布/SBOM | ◐ 仓库内工程面已交付（两阶段可复现打包 + dist-checksums，见下节）；签名发布/SBOM/wasm 源码级固定工具链重建 ⛔ 1.0（WALLET-ACC-8 外部面） |

## 迭代路线（§6.12.4 表）

| 版本 | 交付内容 | 本仓库状态 |
|---|---|---|
| **Extension 0.1** | PLAY、本地 keystore、ZChain provider、开桌/买入/结算签名、devnet | ✅ 本目录（骨架 + 真实安全层 + 真实 wallet-core WASM） |
| **Extension 0.2** | testnet、多账户、REAL/PLAY 隔离、proof portal、备份恢复、网络切换 | ✅ 本目录（详见 ACCEPTANCE.md"Extension 0.2 验收对照"节） |
| **Extension 0.3** | SNIP-12 会话密钥授权、提现预览 | ✅ 本目录（**popup UI 面**；WalletConnect Vault adapter/relay、ForceInclude 提交路径、SeenReceipt 验签未交付——relay 挂 B5 外部依赖） |
| **Extension 0.4** | account binding registry、会话密钥撤销/过期、单笔/每日限额、Stark wallet capability matrix | ✅ 本目录（撤销/限额在签名路径 wasm/JS 双层 fail-closed；详见 ACCEPTANCE.md"Extension 0.3/0.4 验收对照"节） |
| **Extension 0.5** | EVM 兼容多链账户：余额查询、合约调用（读/写）、交易记录查询、钱包管理（口令 keystore/私钥导出/生成导入）、e2e | ✅ 本目录（`common/evm/*` + popup EVM 视图 + 本地开发链；36 步浏览器 e2e PASS，详见 ACCEPTANCE.md"Extension 0.5 验收对照"节） |
| **Extension 0.6** | **Starknet 账户层（STARK curve）**：余额查询、合约调用（starknet_call/invoke v1 签名）、交易记录、钱包管理（keystore/私钥导出/改密码/删除/多账户） | ✅ 本目录（**0.6.0-alpha**；`common/stark/*` + popup Starknet 视图 + 本地 Starknet 开发链（独立验签）；32 步浏览器 e2e PASS，详见 ACCEPTANCE.md"Extension 0.6 验收对照"节） |
| Extension 1.0 | 第三方安全审查、可复现构建、硬件钱包适配（仅可读签名） | ◐ 可复现构建的**仓库内工程面**已交付（`scripts/extension_reproducible_build.sh`：两阶段打包比对 PASS + dist-checksums.txt）；外审/签名发布/SBOM/硬件钱包 ⛔ |

## 可复现构建（1.0 仓库内工程面）

```bash
bash scripts/extension_reproducible_build.sh
# → REPRODUCIBLE PASS（2026-09-12 实测：build1 与 build2 逐字节一致；
#   包内容含本 README，故哈希随文件演进变化——不在此记录"终态哈希"，
#   以每次运行的 extension/dist-checksums.txt 为准）
# → extension/dist-checksums.txt（文件清单 + SHA-256 + 环境指纹，发布附随）
```

- 锁定输入：node 版本、`vendor/wallet-core` wasm/胶水 SHA-256、源文件树哈希
  清单（71 文件内容哈希）。
- 两阶段构建：`build1/` 与 `build2/` 各从零组装一次，统一 mtime
  （`SOURCE_DATE_EPOCH`，缺省 = git HEAD 提交时间）、统一排序、`zip -X`
  打包后**逐字节比对**；不一致 → 逐成员列出差异文件。
- 诚实边界：wasm 按**锁定输入**复核哈希、不在脚本内重建（源码级可复现重建
  需固定 rustc/wasm-bindgen/LLVM 工具链容器，属 1.0 外部交付）；`.DS_Store`、
  日志、脚本产物排除在包外。已知非确定源清单见 ACCEPTANCE.md。

## 测试

```bash
node --test "extension/tests/*.test.js" "extension/tests/adapters/*.test.js" \
     "extension/tests/evm/*.test.js" "extension/tests/stark/*.test.js"
                                         # 198 用例 = 0.4 的 135 + 0.5 EVM 24
                                         #   + 0.6 STARK curve 12/钱包面 8 等
                                         # （node:test，无框架；目录形式
                                         # `node --test extension/tests/` 受本机
                                         # Node 24 通病影响，用通配形式）
node extension/tests/wasm_smoke.mjs       # WASM 冒烟（真实密码学路径 + 0.2 备份/
                                         # 分库视图/展示门/复验负例 + 0.3/0.4
                                         # 会话密钥/限额/SNIP-12 摘要 14-18 步）
node extension/tests/e2e/run_02.mjs       # 0.2 关键流真实浏览器 E2E（36 步，
                                         # 含真实 explorer_gateway；见 ACCEPTANCE）
node extension/tests/e2e/run_03.mjs       # 0.3/0.4 关键流真实浏览器 E2E（30 步：
                                         # 会话密钥授权/限额执行/授权簿/能力矩阵/
                                         # 提现预览；见 ACCEPTANCE）
node extension/tests/e2e/run_04.mjs       # 0.4 portal STARK 验证流 E2E（12 步）
node extension/tests/e2e/run_05.mjs       # 0.5 EVM 钱包关键流真实浏览器 E2E
                                         # （36 步全 UI 操作：创建/余额/合约读写/
                                         # 转账/记录/导出私钥/改密码；内置本地
                                         # 开发链真实解码 raw 交易核对）
node extension/tests/e2e/run_06.mjs       # 0.6 Starknet 钱包关键流真实浏览器 E2E
                                         # （32 步全 UI 操作：创建/余额/合约读/
                                         # invoke 签名广播/记录/导出私钥/改密码；
                                         # 本地 Starknet 开发链 STARK curve
                                         # 独立验签核对）
cargo test -p poker-wallet --release      # 43 个 wallet-core 测试（不回归）
cargo test -p poker-wallet --features wasm \
    --bin wallet_core_wasm                # 11 个 wasm.rs 纯逻辑测试
                                         #（portal_check 6 + session_check 5）
```
*既有 112 = validation 31 + adapters 51 + networks 6 + accounts 8 + receipts 8
+ portal 8；0.3/0.4 起新增 sessions 11 + withdraw_preview 6 +
capability_matrix 6 = **135**。既有 31 例中的 eip1193 用例 08 与 validation
用例 10 在 0.2 因 switchNetwork 更新过断言对象（拒绝面语义不变）。

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
（错口令 fail-closed、nonce 重放拒、脱敏检查），缺产物时自动跳过；0.2 增补：
REAL/PLAY 分库视图、REAL 展示门（claim 隐藏 + 托管提示）、结算复验结构负例、
备份导出→错口令/篡改 fail-closed→正确口令恢复→恢复件解锁同公钥。
`tests/networks.test.js`：注册表/mainnet 红线/网关 URL 解析（testnet 未配置
如实 null）/explorer 链接。
`tests/accounts.test.js`：多账户账本（创建上限/切换隔离/授权簿与网络按账户
隔离/移除/0.1 单账户迁移/标签清洗）。
`tests/receipts.test.js`：回执状态机（digest 校验/SeenReceipt 形状（不验签，
如实标注）/单向迁移/deadline 判定（含 0=禁用与溢出安全）/ForceInclude 提示
文案（仅展示）/滚动上限）。
`tests/portal.test.js`：portal 客户端（binding 解析/URL 组装/注入 fetch 的
全部错误路径/X-Zchain-Engine 头与 body engine 优先级/verifyLocally 同步异步/
verdictRows 映射）。
`tests/sessions.test.js`：会话密钥授权簿（草稿 scope/限额 fail-closed、
withdraw 永不可选/登记形状/幂等 upsert/上限/撤销粘滞/删除/状态视图）+
签名路径准入（与 wallet-core 同序的每类负例独立断言 + 日限记账跨天开窗 +
governing binding 选择语义）。
`tests/withdraw_preview.test.js`：REAL 提现预览（形状 fail-closed/贪心选币
finality 短板聚合/余额不足/库空/锁定 note 跳过/**canSubmit 恒 false 红线**）。
`tests/capability_matrix.test.js`：能力矩阵（探测 fail-closed/EIP-1193 只读
子集 + 签名全拒清单/WC dormant 如实 + active 白名单/Starknet SNIP-12 授权
委托 + note spend 拒绝红线）。
`tests/e2e/run_02.mjs`：0.2 关键流真实浏览器 E2E（多账户/备份/换网/回执/
portal 正例（真实 explorer_gateway）+ 安全回归），证据见 ACCEPTANCE.md。
`tests/e2e/run_03.mjs`：0.3/0.4 关键流真实浏览器 E2E（会话密钥草稿 → 登记 →
限额内/超限签名 → 撤销 fail-closed → 删除恢复 → 授权簿撤销/恢复 → 能力矩阵 →
提现预览 → provider 边界），证据见 ACCEPTANCE.md。

## 已知边界（如实声明，不虚标）

- `wallet_faucet_play` 是**本地 devnet 水龙头 stub**：无链上 mint、无同步；
  真链接入挂 `sync::ChainSource` 缝（0.2 未接入，不虚标）。
- SW（service worker）被浏览器回收即自动锁定（fail-closed）；待签名请求随之
  超时。pending 请求不跨 SW 生命周期持久化。
- nonce 账本存 `chrome.storage.session`（浏览器会话内单调；重启重置——重置后
  页面 nonce 计数也重启，不存在重放窗口，因为签名 nonce 由 wallet-core 的
  `(chain, nonce)` 账本二次防重放）。
- 结算走整记录补签路径（`Settle`）；逐输入 `sign_settle_input` 的 operator
  收集路径 wasm 已具备、provider 尚未开放（0.3）。
- 无图标资源（MV3 可选）；popup/portal 为最小样式。
- **0.2 新增边界**：
  - wasm 会话单槽：同一时刻至多一个账户解锁；切换账户 = 锁当前 + 目标待解锁
    （其他账户互不影响——各自密文独立保存）。
  - REAL 侧为**纯展示**：分库视图 + 托管风险提示 + finality 层级；REAL 签名/
    提现/入金不开放（页面文案不暗示可提现）；REAL 库当前恒空（不开放铸造）。
  - 备份口令与钱包口令相互独立（导出时信封以备份口令重封）——忘记备份口令
    同样无法恢复（fail-closed，无后门）。
  - 回执 SeenReceipt 不验签（wasm 验签入口 0.3 缝）；included 为人工登记
    （evidence 字段如实标注，UI 明示"非链上证实"）。
  - portal 复验面 = 结算关系（payout_root 复算 + 守恒 + 费率关系）；STARK
    证明本体不在浏览器内验证（stwo-wasm 非 0.2 交付，页面如实标注）。
  - portal 对 127.0.0.1 网关的跨源访问：生产用户经"授予网关主机权限"按钮
    （可选权限）或网关 `--public`（CORS *）放行；两者皆无时如实报
    GatewayUnreachable。
  - `zchain_verifyProof`/`zchain_watchProof` provider 方法仍未开放（portal 为
    扩展页交付）。
- **0.5 新增边界（如实声明）**：
  - EVM 层密码学为 JS 自包含实现（`common/evm/crypto.js`，公共向量钉住），
    不在 wallet-core WASM 边界内；k 生成 = RFC 6979 结构 HMAC-DRBG
    （H=keccak256）。交易为 legacy（EIP-155）类型；EIP-1559/typed tx、
    DApp 浏览器 provider 注入（`window.ethereum`——红线不变）、硬件钱包、
    助记词（BIP-39）派生路径未交付。
  - 交易记录 = 本地账本 + 待确认回执对账 + Etherscan 兼容 txlist 合并；
    未配置 Explorer API 的链只展示本钱包发出过的交易（纯 RPC 无法回溯全量
    链上历史——不虚标）。
  - 公网 RPC 依赖端点 CORS（公开节点通行做法）；manifest 声明了 localhost
    host 权限供本地节点。SW 被回收即 EVM 会话锁定（fail-closed），待确认
    draft 随之失效（60 秒 TTL）。
  - `tests/e2e/devchain.mjs` 为测试/演示用最小 JSON-RPC 链（真实解码 raw
    交易 + sender 恢复），非生产链客户端。
- **0.6 新增边界（如实声明）**：
  - Starknet 层密码学为 JS 自包含实现（`common/stark/curve.js`，公共向量
    钉住：crypto-cpp 公钥/验签正负例、StarkEx Pedersen 向量、starknet.js
    交易哈希向量、地址推导与校验和与官方实现对拍）；k 生成 = RFC 6979
    结构 HMAC-keccak256 DRBG。
  - 交易类型仅 invoke v1（Pedersen 元素链哈希）；v3（Poseidon/BLAKE2s）
    与 SNIP-12 typed-data rev1 哈希仍归 wallet-core 单实现，本层不重复。
  - 账户地址 = UDC 公式（class hash + 盐 + [公钥]）；公网预设 class hash
    为广泛引用的 ArgentX Cairo-1 类（UI 可覆盖）；导入同私钥会因新随机盐
    得到新地址（Starknet 语义：地址由 (class, salt, pubkey) 共同决定）。
  - 私钥生成 < 2^125（生态惯例）；keystore 'stark-1' 形状与 EVM 层相互独立。
  - devnet 水龙头 = dev 链扩展方法 dev_faucet（注册 pubkey + 出资）；链端
    验签依赖注册的 pubkey（真实网络由账户合约内验证）。
- **0.3/0.4 新增边界（如实声明）**：
  - 会话密钥的 **delegated 私钥只活在 wasm 会话**（锁定/切换即毁，不持久化
    ——wasm_smoke 18 步钉住）；0.3/0.4 交付的是授权与**约束执行面**（origin
    的签名请求受 binding 约束 + 撤销拒），会话密钥直接出 SpendAuth 的路径随
    链侧 admission 语义交付。
  - 授权登记为 **devnet 入口形态**（本地约束记录，evidence =
    `devnet_local_entry`）：链侧 admission 登记与 Starknet 钱包签名回填
    （popup 表单地址为手输入口形态）未接；SNIP-12 摘要由 wallet-core 计算
    并在确认页展示，但本地登记不以该签名为准（如实标注）。
  - 会话密钥约束的执行语义：origin+chain 下最新登记的 active/exhausted/
    revoked binding 管辖；**自然过期/未生效 → 回常规路径**（不锁死 origin），
    **撤销 → 恒拒（粘滞）**，删除记录（显式用户动作）是唯一清除路径。
  - 限额金额口径 = 预览 `amount_in`（找零回自身也计入——限额从严方向）；
    日限按 unix 天窗聚合。
  - REAL 提现预览为**纯展示**：canSubmit 恒 false（display.rs 展示门 ∧
    finality 合取），提交路径随 Vault 上线单独交付。
  - WalletConnect 生产 relay 未交付（前置 B5：projectId 外部注册）；能力
    矩阵的 WC 行如实报 dormant。
  - `zchain_authorizeSessionKey`/`zchain_revokeSessionKey` provider 方法
    仍未开放（NotSupportedIn01；授权由钱包 popup UI 发起）。
