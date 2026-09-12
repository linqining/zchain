# extension/adapters/ — 钱包连接协议适配器（M6"钱包连接协议"）

三套连接协议适配器，对接既有 `window.zchain` provider（`content/inpage.js`）
与 wallet-core 能力模型（`poker-wallet`：`vault_adapter.rs` 的
`VaultCapabilities` / `account_binding.rs` 的 SNIP-12 typed data）。

**总纪律**（plan-appchain §6.12.1/§6.12.12，测试逐一钉住，见
`../tests/adapters/`）：

1. **不把外部协议伪装成原生共识账户**。ZChain 网络身份 = 字符串 chain id
   （`zchain-devnet-1`）；所有协议形状（EIP-1193 数字 id、WC CAIP-2、
   Starknet domain）都是**显式映射/独立 namespace**，见下表。
2. **EVM 钱包仅可作"未来 EVM bridge/登录适配器"**（§6.12.1
   `SignerKind::EvmWallet` 注释），不能伪装成 Note owner——EIP-1193 签名
   方法默认全拒且**无开关**。
3. **WC v2 是会话传输，能力需探测**：方法白名单 = §6.12.4 的 `zchain_*`
   全集，授权阶段即做 `getCapabilities` 探测，授予集 = 请求 ∩ 白名单 ∩
   能力；能力不足回 `CapabilityMissing`/`MethodNotAllowed`，**绝不退化成
   blind signing**。
4. **Starknet 接口只用于授权委托/Vault**：SNIP-12 `AuthorizeZChainKey`
   typed data 签名 → wallet-core 形状 verifier 验签 → 授权登记。Starknet
   签名**不产生** ZChain note spend 签名（spend 唯一入口是 wallet-core 的
   secp256k1 结构化 SigningRequest）。
5. **JS 零密码学、构建零 npm 依赖**：摘要/验签唯一入口 wallet-core（WASM
   或同形接口注入）；WC SignClient 为注入接口 + 内存 stub。

## 文件

| 文件 | 职责 |
|---|---|
| `shared.js` | 链 id 映射表、方法白名单、错误码（三条红线的常量锚点） |
| `eip1193.js` | EIP-1193 兼容 provider（只读 eth_* 子集 + zchain_* 透传 + 事件转发） |
| `walletconnect.js` | WC v2 适配核心（proposal namespace 映射 / 请求路由 / 能力探测 / 重放与过期拒） |
| `wc_signclient_stub.js` | 测试用内存 SignClient（模拟 relay：propose→approve、request 往返、过期/断开） |
| `starknet.js` | Starknet 钱包接口（探测 + SNIP-12 `AuthorizeZChainKey` 授权流程） |
| `index.js` | 注册面/可配置开关（`initAdapters`），后台接线入口 |

## 网络/chain id 映射表（"不伪装"的显式锚点）

| ZChain 网络 id（规范身份，处处返回） | EIP-1193 `eth_chainId`（映射别名） | `net_version` | WC CAIP-2 | 备注 |
|---|---|---|---|---|
| `zchain-devnet-1` | `0x7a0001`（7995393） | `"7995393"` | `zchain:zchain-devnet-1` | 0.1 唯一网络 |
| `zchain-testnet-1` | `0x7a0002` | `"7995394"` | `zchain:zchain-testnet-1` | 0.2 预留（交付前不启用） |
| `zchain-mainnet-1` | `0x7a0003` | `"7995395"` | `zchain:zchain-mainnet-1` | 预留 |

- 映射方案：`0x7A0000 + kind 序号`（0x7A = 'z'）。取值在高位**未注册**区间，
  刻意避开 `0x1`（Ethereum 主网）与 chainlist 已注册链；未登记网络一律
  拒绝（fail-closed）。
- WC account 形状：`zchain:zchain-devnet-1:<公钥 hex>`（CAIP-10 风格）。
- Starknet SNIP-12 domain：`{ name: "ZChain", version: "1", chainId:
  "zchain-devnet-1", revision: "1" }`（不复用 `SN_MAIN`/EVM chain id）。

## 1. EIP-1193 兼容适配器（`eip1193.js`）

```js
import { createEip1193Provider } from './adapters/eip1193.js';
const provider = createEip1193Provider({ zchain: window.zchain });
await provider.request({ method: 'eth_chainId' });        // '0x7a0001'
await provider.request({ method: 'eth_accounts' });       // ['<公钥 hex>']（锁定=[]）
await provider.request({ method: 'zchain_signOperation', params: { operation, previewHash } });
provider.on('chainChanged', (hexId) => {});               // '0x7a0001'
provider.on('accountsChanged' | 'connect' | 'disconnect', cb);
provider.removeListener(event, cb);
```

- **方法策略**：白名单 `eth_chainId` / `net_version` / `eth_accounts`（只读子集）
  + `zchain_*` 全集透传（`zchain_getAccounts`/`zchain_signOperation`/…，
  仍过 `common/validation.js` 的方法白名单与结构校验——与页面通道同一拒绝面）。
- **红线拒绝**：`eth_sign` / `personal_sign` / `eth_signTypedData*` /
  `eth_sendTransaction` / `eth_sendRawTransaction` 一律
  `unsupportedMethod(4200)` + `data.zchainCode = 'EvmSigningForbidden'`；
  其它 `eth_*`/`wallet_*` 一律 `MethodNotAllowed`。
  **何时才允许**：未来 EVM bridge 交付时（§6.12.1 EVM 钱包仅限
  bridge/登录适配器）——前置条件：① wallet-core 能力矩阵新增显式
  capability（如 `evmBridge`）；② 只打开**桥接专用**签名入口；③ 本黑名单
  仍然拒绝，bridge 走独立方法名，绝不冒用 `eth_sign` 语义。
- **事件**：`connect`（首个成功请求）/ `chainChanged`（映射别名）/
  `accountsChanged` / `disconnect`(4900)，由注入事件源（默认 = zchain
  provider 自身的 `on/off`，契约：`zchain:chainChanged|zchain:accountsChanged|
  zchain:disconnect`）转发。0.1 的 inpage provider 尚未派发事件（0.2 交付），
  适配器不虚构事件，事件源可由后台/测试注入。
- **身份诚实**：`isZChain`/`isZChainEip1193Shim`，绝不提供
  `isMetaMask`/`isRabby`，不写 `window.ethereum`（与 inpage.js 的
  EIP-6963 边界一致）。
- 错误码：`4200` 不支持的方法（稳定 token 在 `data.zchainCode`）、`4900`
  断连、`-32000` zchain 路由错误（稳定码透传，如 `NetworkMismatch`）。

## 2. WalletConnect v2 适配器（`walletconnect.js` + `wc_signclient_stub.js`）

```js
import { createWalletConnectAdapter } from './adapters/walletconnect.js';
import { createSignClientStub } from './adapters/wc_signclient_stub.js'; // 测试/演练

const adapter = createWalletConnectAdapter({
  signClient,        // WalletConnect SignClient 形状接口（生产 = 真实实例，见下）
  zchain,            // zchain provider 面（inpage 或后台同形门面）
  network: { chainId: 'zchain-devnet-1' },
});
```

- **proposal（session_proposal）**：只接受单一 `zchain:` namespace；
  `chains ⊆ {zchain:zchain-devnet-1}`；`methods ⊆ §6.12.4 zchain_* 白名单`；
  `events ⊆ {chainChanged, accountsChanged}`。随后 `getCapabilities` 探测，
  **授予集 = 请求 ∩ 白名单 ∩ 能力**；探测失败整案拒绝（fail-closed）。
  拒绝码（CAIP-25）：`5100` namespace、`5001` chains、`5000` methods、
  `5002` 无账户（锁定态拒连）、`5900` 能力探测失败（ZChain 扩展码）。
- **session_request**：逐层拒绝面（顺序即实现）——
  未知会话 `UnknownSession(-32055)` → 会话过期 `SessionExpired(-32052)`（并
  主动 disconnect）→ 请求 id 单调（重放/回退 `ReplayDetected(-32053)`）→
  方法白名单 `MethodNotAllowed(-32050)` → 会话授予集（曾请求但能力缺失
  `CapabilityMissing(-32051)`，从未授予 `MethodNotGranted(-32050)`）→ 请求
  expiry（`RequestExpired(-32054)`）→ chainId 匹配 → `validation.js` 参数
  结构校验（稳定码透传，如 `ZC-NetworkMismatch`）→ zchain provider 路由。
  **签名类最终仍过后台 popup 显式确认与 wallet-core 全拒绝面**——WC 只是
  传输，不新增任何绕过路径（见 `background/service_worker.js` 的
  `adapterSign`）。
- **事件**：zchain 事件源 → `emitSessionEvent`（chainChanged/accountsChanged）
  转发给每个活动会话。
- **生产接入步骤（替换 stub，零 npm 进构建的边界内）**：
  1. 在一个独立打包入口（或后续 vendor 产物）安装
     `@walletconnect/sign-client`（配 `projectId` 与 relay）；
  2. SW 启动早期 `init` 并把实例赋到
     `globalThis.__zchainInjectedSignClient`（`background/service_worker.js`
     的注入点）——`initAdapters` 检测到即从 dormant 转激活；
  3. 真实 SignClient 需满足本目录接口契约（wallet 侧）：
     `on('session_proposal'|'session_request'|'session_delete')` /
     `approveSession({id, namespaces})` / `rejectSession({id, reason})` /
     `respondSessionRequest({topic, response})` / `disconnect({topic, reason})` /
     `emitSessionEvent({topic, event, chainId})` / `session: Map`。
  4. 验收钩子：`tests/adapters/walletconnect.test.js` 的 17 个用例即契约
     测试——把 stub 换成真实实例后同套用例应全过（stub 的
     `emitSessionRequestFromDapp` 对应"直接注入传输层事件"的负例驱动）。
  5. **如实标注**：真机 relay 互通（Argent X/Braavos 作为 WC 钱包侧、
     dapp 作为 peer）属 WALLET-ACC-1 真机矩阵，0.1 未验证。

## 3. Starknet 钱包接口适配器（`starknet.js`）

```js
import { detectStarknetWallet, authorizeSessionKeyViaStarknet } from './adapters/starknet.js';
const detected = detectStarknetWallet(window); // 扫 window.starknet / window.stargate
const res = await authorizeSessionKeyViaStarknet(detected.wallet, authorizationRequest, {
  chainId: 'zchain-devnet-1',
  verifySignature,   // wallet-core 形状 verifier：SNIP-12 摘要 + Stark 验签唯一入口
  registerBinding,   // 授权登记（wallet-core BindingRegistry / 后台）
});
```

- **typed data**：按 `poker-wallet/src/account_binding.rs` 的
  `authorize_encode_type()`（成员名字母序、revision 1）组装 JSON；domain =
  `{ name: "ZChain", version: "1", chainId: "zchain-devnet-1", revision:
  "1" }`。测试 `tests/adapters/starknet.test.js` 用例 01 把 encode_type 与
  wallet-core 逐字比对（防漂移）。
- **wallet-core 接入现状（如实）**：`wasm.rs` 目前没有 typed-data 构造/验签
  入口，故本适配器组装 JSON、验签经**注入的 verifier 接口**（形状：
  `verifySignature({typedData, accountAddress, signature}) → {ok, digest}`，
  生产实现 = wallet-core 的 SNIP-12 Poseidon 摘要 + `starknet-crypto` 验签
  路径；测试用 mock）。wasm 入口补齐后零改动替换注入。
- **准入（签名前，fail-closed）**：scope 白名单（`play/buyin/bet/settle/
  transfer`；**`withdraw` 永远拒绝**——会话密钥不得持有提现权限）、时间窗
  （过期 `Expired` / 未生效 `NotYetValid`）、地址 felt 域校验、`hex33` 公钥、
  换链拒（`NetworkMismatch`）、未连接/非钱包拒。用户在钱包侧取消 →
  `UserRejected`；验签不过 → `SignatureRejected` 且不登记。
- **审计**：钱包自身 `getChainId()`（如 `SN_SEPOLIA`）与 ZChain domain
  **如实分开记录**（binding 的 `walletChainId` 字段），不冒充相等；钱包若
  报告 ZChain 托管网络（未来形态）则强制一致。
- **边界注释（红线）**：Starknet 签名只用于授权委托/Vault 登录
  （§6.12.1 推荐形态"Starknet Account + SNIP-12 授权的 ZChain 会话密钥"），
  绝不产生 note spend 签名；Starknet 地址不是 Note owner，登记里只是授权方。

## 后台接线（`background/service_worker.js`）

- `initAdapters({ zchain: adapterCoreProvider(), signClient: globalThis.__zchainInjectedSignClient ?? null, log: logSafe })`：
  默认全启用，但默认态即安全态（EIP-1193 只读子集硬编码无开关；WC 无注入
  即 dormant，不挂任何事件）。
- WC/适配器签名复用 `handleSign` 管线（origin 标记 `adapter:walletconnect`）：
  popup 显式确认 + wallet-core 预览摘要绑定 + 全拒绝面不变。
- 页面侧请求来源（inpage → bridge → SW）照旧过 `checkEnvelope` 的
  origin/nonce/expiry/sessionId 校验——适配层不改变页面信任模型。
- popup 消息：`popup:adapters`（状态自省）、`popup:setAdapterConfig`
  （开关持久化到 `chrome.storage.local.adapterConfig`，下次 SW 启动生效）。

## 红线清单（测试锚点）

| 红线 | 测试（`tests/adapters/`） |
|---|---|
| EVM 签名伪装 ZChain 签名 | eip1193 用例 05（7 个签名/交易方法全拒 `EvmSigningForbidden`，无开关） |
| 伪装 Ethereum 主网/MetaMask | eip1193 用例 01（`eth_chainId ≠ 0x1`，显式映射表）+ index 用例 04（无 `isMetaMask`）+ 04 映射表外网络拒 |
| WC 能力不足退化盲签 | walletconnect 用例 02/08（授予集 ∩ 能力；`CapabilityMissing` 拒且 message 明示 no blind signing） |
| WC 接受 eip155/sn 伪装 | walletconnect 用例 03/04（非 zchain namespace/chains 整案拒） |
| WC 重放/过期 | walletconnect 用例 11/12/13/16（SessionExpired/ReplayDetected/RequestExpired/UnknownSession） |
| Starknet 签名越权到 note spend | starknet 用例 08（withdraw scope 签名前拒、不触达钱包）；适配器无任何 spend 签名路由 |
| Starknet scoped 授权（超 scope/过期） | starknet 用例 08/09/10 |
| 注册面不虚报 | index 用例 01/03（WC dormant 如实、status 不虚报激活） |

## 已知边界（如实声明，不虚标）

- 真机互操作（MetaMask/Argent X/Braavos 实装、真实 WC relay）**未验证**，
  属 WALLET-ACC-1 真机矩阵；0.1 交付的是适配核心 + 契约测试 + 内存 stub。
- EIP-1193 事件源契约在 0.1 由注入方实现（inpage provider 事件面 0.2 交付）。
- WC 生产接入需要打包真实 `@walletconnect/sign-client`（引入 npm 依赖），
  该打包入口本身属后续交付；`requireInjectedSignClient` 保证缺省 dormant。
- SNIP-12 typed data 的**摘要与真机钱包签名兼容性**（Argent X/Braavos 对
  `chainId: "zchain-devnet-1"` domain 的接受度）待真机验证（wallet-core
  README"已知边界"同一结论）。
