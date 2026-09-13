// =============================================================================
// extension/adapters/shared.js — 连接协议适配器共享常量与错误
// （EIP-1193 / WalletConnect v2 / Starknet 钱包接口三适配器共用）
//
// plan-appchain §6.12.1/§6.12.12 红线（本文件是红线的常量锚点，测试逐一钉住）：
// - **不把外部协议伪装成原生共识账户**：ZChain 网络身份是字符串 chain id
//   （`zchain-devnet-1`，与 wallet-core `DEFAULT_CHAIN_ID` 一致）。EIP-1193 的
//   数字 chain id 只是一个**显式映射别名**（见 EIP1193_CHAIN_ID_MAP），刻意
//   避开 0x1（Ethereum 主网）等已注册 EVM 链；`eth_chainId` 永不返回 0x1。
// - EVM 钱包仅可作"未来 EVM bridge/登录适配器"（§6.12.1 SignerKind::EvmWallet
//   注释），**不能伪装成 Note owner**：EIP-1193 签名方法默认全拒。
// - WC v2 是会话传输：方法白名单 = §6.12.4 的 zchain_* 全集，能力经
//   zchain_getCapabilities 探测，缺能力即拒，绝不退化成 blind signing。
// - Starknet 接口仅用于 Vault/登录/SNIP-12 授权委托（AuthorizeZChainKey），
//   不产生 ZChain note spend 签名。
//
// 纪律：本目录零密码学（验签/摘要唯一入口 wallet-core WASM 或同形接口）；
// 零 npm 依赖；无 IO、无浏览器全局（node --test 可直接加载）。
// =============================================================================

/** Extension 0.1 唯一网络（与 common/validation.js NETWORKS_01 一致）。 */
export const ZCHAIN_NETWORK_ID = 'zchain-devnet-1';

/**
 * ZChain 网络 id → EIP-1193 数字 chain id（hex string）映射表。
 *
 * 映射方案（显式、稳定、有文档）：`0x7A0000 + kind 序号`（0x7A = 'z' 的
 * ASCII）。取值落在高位未注册区间，**不是** chainlist 上任何已注册 EVM 链，
 * 更不是 0x1/0x5/0xaa36a7 等——数字 id 只服务于 EIP-1193 形状的客户端，
 * ZChain 的规范网络身份始终是字符串 id（`zchain_getNetwork` /
 * `zchain_getCapabilities` 返回值）。新增网络必须在本表显式登记，
 * 未登记网络一律拒绝（fail-closed）。
 */
export const EIP1193_CHAIN_ID_MAP = {
  'zchain-devnet-1': '0x7a0001', // 7995393
  'zchain-testnet-1': '0x7a0002', // 0.2 起启用（换网交付）
  'zchain-mainnet-1': '0x7a0003', // 预留；0.2 扩展注册表刻意不登记（红线）
};

/** 字符串网络 id → EIP-1193 hex chain id；未知网络返回 null（fail-closed）。 */
export function toEip1193ChainId(networkId) {
  const mapped = EIP1193_CHAIN_ID_MAP[networkId];
  return typeof mapped === 'string' ? mapped : null;
}

/** EIP-1193 hex chain id → 字符串网络 id；未知返回 null。 */
export function fromEip1193ChainId(hexChainId) {
  const entry = Object.entries(EIP1193_CHAIN_ID_MAP).find(([, hex]) => hex === hexChainId);
  return entry ? entry[0] : null;
}

/** EIP-1193 `net_version`（数字 id 的十进制字符串）。 */
export function netVersionFor(networkId) {
  const hex = toEip1193ChainId(networkId);
  if (!hex) return null;
  return String(parseInt(hex, 16));
}

/**
 * WC v2 `zchain:` namespace 的 CAIP-2 形状：`zchain:<networkId>`。
 * 刻意不复用 `eip155:`/`sn:` 前缀——独立 namespace 是"不伪装"红线的第一道。
 */
export function toCaip2ChainId(networkId) {
  return `zchain:${networkId}`;
}

/** `zchain:<networkId>` → networkId；非 zchain namespace 返回 null。 */
export function networkIdFromCaip2(chainId) {
  if (typeof chainId !== 'string' || !chainId.startsWith('zchain:')) return null;
  return chainId.slice('zchain:'.length) || null;
}

/** WC v2 account 形状：`zchain:<networkId>:<公钥 hex>`。 */
export function toCaip10Account(networkId, publicKeyHex) {
  return `${toCaip2ChainId(networkId)}:${publicKeyHex}`;
}

// ---------------------------------------------------------------------------
// EIP-1193 适配器：方法策略（只读子集 + 签名全拒）
// ---------------------------------------------------------------------------

/** 允许的 eth_* 只读子集（白名单；之外一律拒绝）。 */
export const EIP1193_ETH_ALLOWED = new Set(['eth_chainId', 'net_version', 'eth_accounts']);

/**
 * EVM 签名/交易方法黑名单（默认拒绝；即使 dapp 先 probe 也拿不到）。
 * 红线：ZChain 签名绝不能伪装成 EVM 签名——§6.12.1 中 EVM 钱包只是
 * "未来 EVM bridge/登录适配器"。未来若交付 EVM bridge，必须：
 *   1) wallet-core 能力矩阵新增显式 capability（如 `evmBridge`）；
 *   2) 该 capability 打开且仅打开**桥接专用**签名入口；
 *   3) 本表仍然拒绝（bridge 走独立方法，不冒用 eth_sign 语义）。
 */
export const EIP1193_ETH_SIGNING_DENIED = new Set([
  'eth_sign',
  'personal_sign',
  'eth_signTypedData',
  'eth_signTypedData_v3',
  'eth_signTypedData_v4',
  'eth_sendTransaction',
  'eth_sendRawTransaction',
]);

/** EIP-1193 数字错误码（EIP-1474/1193 语义）。 */
export const EIP1193_ERROR_CODES = {
  userRejected: 4001,
  unsupportedMethod: 4200, // 白名单外 eth_* 与被拒签名方法共用；token 在 data.zchainCode
  disconnected: 4900,
  chainDisconnected: 4901,
  internal: -32603,
  zchainRouted: -32000, // zchain_* 透传错误（稳定码在 data.zchainCode）
};

// ---------------------------------------------------------------------------
// WalletConnect v2 适配器：namespace 与错误码
// ---------------------------------------------------------------------------

/** WC 会话可声明的 zchain 事件（镜像 EIP-1193 事件语义）。 */
export const WC_ZCHAIN_EVENTS = ['chainChanged', 'accountsChanged'];

/**
 * zchain namespace 方法白名单 = §6.12.4 的 zchain_* 全集（与
 * common/validation.js METHODS 逐字一致；import 之，避免两处漂移）。
 * ZCHAIN_METHODS 是数组（文档/展示用），ZCHAIN_METHODS_SET 是成员判定用集合。
 */
export { METHODS as ZCHAIN_METHODS } from '../common/validation.js';
import { METHODS } from '../common/validation.js';
export const ZCHAIN_METHODS_SET = new Set(METHODS);

/**
 * WC session_request 失败的错误码（JSON-RPC 自定义区段；稳定契约，测试钉住）。
 * message 一律携带 `ZC-<STABLE_CODE>: <人读原因>`。
 */
export const WC_ERROR_CODES = {
  methodNotAllowed: -32050, // 方法不在 §6.12.4 zchain_* 白名单（永不为盲签开口）
  capabilityMissing: -32051, // getCapabilities 探测缺能力（绝不退化 blind sign）
  sessionExpired: -32052,
  replayDetected: -32053, // 请求 id 重放/回退
  requestExpired: -32054,
  unknownSession: -32055,
  invalidParams: -32056, // validation.js 稳定码在 message
  provider: -32000, // zchain provider 抛错（稳定码在 message）
};

/** WC proposal 拒绝码（CAIP-25 语义）。 */
export const WC_PROPOSAL_REJECT_CODES = {
  unsupportedNamespaceKey: 5100,
  unsupportedMethods: 5000,
  unsupportedChains: 5001,
  unsupportedAccounts: 5002,
  capabilityProbeFailed: 5900, // ZChain 扩展码：能力探测失败即拒绝（fail-closed）
};

/** 把 zchain 稳定错误码折进 WC JSON-RPC error message（测试按 token 断言）。 */
export function wcErrorPayload(code, stableCode, reason) {
  return { code, message: `ZC-${stableCode}: ${reason ?? ''}`.trim() };
}
