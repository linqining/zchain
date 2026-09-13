// =============================================================================
// extension/common/capability_matrix.js — 外部钱包能力矩阵（Extension 0.4）
//
// plan §6.12.4 Extension 0.4"Stark wallet capability matrix"（WALLET-ACC-7）：
// 外部钱包/客户端能力探测结果的**结构化展示**——EIP-1193 / WalletConnect v2 /
// Starknet 钱包接口各自支持的 capability 列表与拒绝原因。
//
// 复用 adapters 的既有逻辑（不二次实现）：
//   - EIP-1193：shared.js 的只读白名单（EIP1193_ETH_ALLOWED）与签名全拒表
//     （EIP1193_ETH_SIGNING_DENIED）；
//   - WalletConnect：adapterHost.status() 的 active/dormant 状态 + shared.js
//     的 zchain 方法白名单（= §6.12.4 全集）；能力缺失绝不退化盲签；
//   - Starknet：starknet.js 的 detectStarknetWallet（fail-closed 形状探测）+
//     SNIP-12 授权委托定位。
//
// 纪律：纯函数、零依赖、无 IO、零密码学；探测结果只陈述事实（dormant 如实
// 报 dormant），不虚报激活状态。
// =============================================================================

import { EIP1193_ETH_ALLOWED, EIP1193_ETH_SIGNING_DENIED, ZCHAIN_METHODS } from '../adapters/shared.js';
import { detectStarknetWallet } from '../adapters/starknet.js';

/**
 * 宿主全局对象上的外部钱包探测（EIP-6963 只用于外部 EVM 钱包共存；本钱包
 * 自身 provider 是 window.zchain，不写 window.ethereum——见 inpage.js）。
 *
 * @param {object} [globalObj] 默认 globalThis（页面中即 window）
 * @returns {{ eip1193: {detected, providers}, starknet: {detected, namespace,
 *            address}|null }}
 */
export function detectExternalWallets(globalObj = globalThis) {
  const eth = globalObj?.ethereum;
  const injected = eth && typeof eth === 'object'
    ? (Array.isArray(eth.providers) ? eth.providers : [eth])
    : [];
  const providers = injected.map((p) => ({
    isMetaMask: p?.isMetaMask === true,
    isRabby: p?.isRabby === true,
    isCoinbaseWallet: p?.isCoinbaseWallet === true,
    requestable: typeof p?.request === 'function',
  }));
  const stark = detectStarknetWallet(globalObj);
  return {
    eip1193: { detected: providers.length > 0, providers },
    starknet: stark
      ? { detected: true, namespace: stark.namespace, address: stark.address ?? null, isConnected: stark.isConnected }
      : { detected: false },
  };
}

/**
 * 构造能力矩阵（结构化行；popup 消费渲染）。
 *
 * @param {object} input
 *   {zchainCaps: 自家 getCapabilities 输出, adapterStatus: adapterHost.status()
 *   输出, detection: detectExternalWallets() 输出}
 * @returns {{ generatedAtMs, own: {methods, networks, currentNetwork,
 *            assetClasses}, rows: Array<{protocol, detected, active, summary,
 *            supported: [{name, detail}], denied: [{name, reason}]}> }}
 */
export function buildCapabilityMatrix({ zchainCaps, adapterStatus, detection }) {
  const status = adapterStatus ?? {};
  const det = detection ?? { eip1193: { detected: false, providers: [] }, starknet: { detected: false } };

  const eipDenied = [...EIP1193_ETH_SIGNING_DENIED].sort().map((m) => ({
    name: m,
    reason: 'EvmSigningForbidden(4200)：ZChain 签名绝不伪装成 EVM 签名（EVM 钱包仅限未来 bridge/登录适配器，走独立方法）',
  }));

  const wcActive = status.walletconnect?.active === true;
  const wcSupported = wcActive
    ? ZCHAIN_METHODS.map((m) => ({ name: m, detail: '会话内可路由（仍过 validation.js 校验与显式确认）' }))
    : [];
  const wcDenied = [
    ...!wcActive
      ? [{
        name: '（全部方法）',
        reason: 'dormant：SignClient 未注入（生产 relay @walletconnect/sign-client 属 B5 外部依赖，未交付）',
      }]
      : [],
    {
      name: '盲签（任意 bytes）',
      reason: 'CapabilityMissing(-32051)：能力探测缺失即拒绝，绝不退化盲签',
    },
    {
      name: '非 zchain namespace（eip155:/sn:）',
      reason: 'CAIP-25 整案拒绝：不伪装 Ethereum/Starknet 账户',
    },
  ];

  const starkDenied = [
    {
      name: 'ZChain note spend 签名',
      reason: 'ScopeForbidden：Starknet 签名只用于 SNIP-12 授权委托/身份探测，绝不产生 note spend 签名（scope 全集不含 withdraw）',
    },
    ...!det.starknet?.detected
      ? [{ name: '授权委托（当前）', reason: '未检测到 Starknet 钱包对象（window.starknet/stargate 形状，fail-closed）' }]
      : [],
  ];

  return {
    generatedAtMs: Date.now(),
    own: {
      providerVersion: zchainCaps?.providerVersion ?? null,
      methods: zchainCaps?.methods ?? [],
      networks: zchainCaps?.networks ?? [],
      currentNetwork: zchainCaps?.currentNetwork ?? null,
      assetClasses: zchainCaps?.assetClasses ?? [],
    },
    rows: [
      {
        protocol: 'EIP-1193（兼容形状）',
        detected: det.eip1193?.detected === true,
        active: status.eip1193?.enabled === true,
        summary: det.eip1193?.detected
          ? `检测到 ${det.eip1193.providers.length} 个注入的 EVM provider（外部钱包共存；本钱包不冒充其中任何一个）`
          : '未检测到 window.ethereum（EIP-1193 shim 仍可为宿主创建，只读子集）',
        supported: [
          ...[...EIP1193_ETH_ALLOWED].sort().map((m) => ({ name: m, detail: '只读子集（硬编码白名单，无开关）' })),
          { name: 'zchain_* 透传', detail: '经同一 validation.js 拒绝面（eth_chainId = 显式映射别名 0x7a0001，非 0x1）' },
          { name: '事件转发', detail: 'connect/chainChanged/accountsChanged/disconnect' },
        ],
        denied: eipDenied,
      },
      {
        protocol: 'WalletConnect v2',
        detected: true,
        active: wcActive,
        summary: wcActive
          ? `SignClient 已注入；会话数 ${status.walletconnect?.sessions ?? 0}`
          : 'dormant：未注入 SignClient，不监听任何会话事件（生产 relay 属 B5 外部依赖）',
        supported: wcSupported,
        denied: wcDenied,
      },
      {
        protocol: 'Starknet 钱包接口',
        detected: det.starknet?.detected === true,
        active: status.starknet?.enabled === true,
        summary: det.starknet?.detected
          ? `检测到 ${det.starknet.namespace} 命名空间钱包对象${det.starknet.address ? `（${String(det.starknet.address).slice(0, 12)}…）` : ''}`
          : '未检测到 Starknet 钱包对象（授权委托流程不可用；SNIP-12 devnet 入口形态仍可登记约束）',
        supported: [
          { name: 'SNIP-12 AuthorizeZChainKey', detail: 'typed data 组装（与 wallet-core encode_type 逐字一致）+ 签名委托 + 授权登记' },
          { name: '身份探测', detail: 'Vault/登录场景的钱包对象形状检查（isConnected/signMessage/getChainId）' },
        ],
        denied: starkDenied,
      },
    ],
  };
}
