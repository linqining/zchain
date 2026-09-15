// =============================================================================
// extension/common/evm/networks.js — EVM 网络注册表（Extension 0.5）
//
// 纯函数、零副作用（node --test 直覆盖）。预设链 + 用户自定义 RPC 覆盖
// （per chainId，storage 由 SW 管）。默认 RPC 均为公开、CORS 开放的端点；
// devnet 指向本机开发链（e2e/本地演示用），支持水龙头。
// =============================================================================

export const EVM_NETWORKS = [
  {
    id: 'evm-devnet',
    name: 'ZChain EVM DevNet（本地）',
    chainIdHex: '0x7a69', // 31337
    kind: 'devnet',
    rpcUrl: 'http://127.0.0.1:8545',
    explorerUrl: null,
    explorerApiUrl: null,
    faucet: true,
  },
  {
    id: 'ethereum',
    name: 'Ethereum',
    chainIdHex: '0x1',
    kind: 'mainnet',
    rpcUrl: 'https://eth.llamarpc.com',
    explorerUrl: 'https://etherscan.io',
    explorerApiUrl: null, // 需要 API key：用户可在设置里填 etherscan v2 端点
    faucet: false,
  },
  {
    id: 'sepolia',
    name: 'Sepolia 测试网',
    chainIdHex: '0xaa36a7',
    kind: 'testnet',
    rpcUrl: 'https://rpc.sepolia.org',
    explorerUrl: 'https://sepolia.etherscan.io',
    explorerApiUrl: null,
    faucet: false,
  },
  {
    id: 'base',
    name: 'Base',
    chainIdHex: '0x2105',
    kind: 'mainnet',
    rpcUrl: 'https://mainnet.base.org',
    explorerUrl: 'https://basescan.org',
    explorerApiUrl: null,
    faucet: false,
  },
  {
    id: 'arbitrum',
    name: 'Arbitrum One',
    chainIdHex: '0xa4b1',
    kind: 'mainnet',
    rpcUrl: 'https://arb1.arbitrum.io/rpc',
    explorerUrl: 'https://arbiscan.io',
    explorerApiUrl: null,
    faucet: false,
  },
];

export const DEFAULT_EVM_NETWORK_ID = 'evm-devnet';

/** id / chainIdHex → 网络；未知 → null（不虚构）。 */
export function resolveEvmNetwork(idOrChainIdHex) {
  const key = String(idOrChainIdHex ?? '').toLowerCase();
  return EVM_NETWORKS.find((n) => n.id === key || n.chainIdHex === key) ?? null;
}

/** 网络生效 RPC：用户覆盖 > 预设。返回 null = 无效。 */
export function effectiveRpcUrl(network, rpcOverrides = {}) {
  if (!network) return null;
  const override = rpcOverrides?.[network.chainIdHex];
  return canonicalHttpUrl(override) ?? canonicalHttpUrl(network.rpcUrl);
}

/** 生效 explorer API（用户覆盖 > 预设；无 → null）。 */
export function effectiveExplorerApi(network, explorerOverrides = {}) {
  if (!network) return null;
  return canonicalHttpUrl(explorerOverrides?.[network.chainIdHex]) ?? canonicalHttpUrl(network.explorerApiUrl);
}

/** http(s) URL 规范化（只留 origin+path，去 query/hash；非法 → null）。 */
export function canonicalHttpUrl(input) {
  if (typeof input !== 'string' || input.trim() === '') return null;
  try {
    const u = new URL(input.trim());
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.origin + (u.pathname === '/' ? '' : u.pathname);
  } catch {
    return null;
  }
}

/** 网络选择视图（popup 消费；无密钥材料）。 */
export function evmNetworkView(network, rpcOverrides = {}, explorerOverrides = {}) {
  if (!network) return null;
  return {
    id: network.id,
    name: network.name,
    chainIdHex: network.chainIdHex,
    kind: network.kind,
    rpcUrl: effectiveRpcUrl(network, rpcOverrides),
    rpcOverridden: Boolean(rpcOverrides?.[network.chainIdHex]),
    explorerUrl: network.explorerUrl,
    explorerApiUrl: effectiveExplorerApi(network, explorerOverrides),
    faucet: network.faucet === true,
  };
}
