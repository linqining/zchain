// =============================================================================
// extension/common/stark/networks.js — Starknet 网络预设（Extension 0.6）
//
// 纯函数。预设：本地开发链（支持水龙头/注册，e2e 与本地演示）+ Sepolia/
// Mainnet（公共 CORS RPC；账户 class hash 可在 UI 覆盖——地址由
// (class, salt, pubkey) 推导，class hash 换档即换地址，如实标注）。
// =============================================================================

export const STARKNET_NETWORKS = [
  {
    id: 'starknet-devnet',
    name: 'ZChain Starknet DevNet（本地）',
    chainIdFelt: '0x5a43444e', // 'ZCDN'
    chainId: 'ZCDN',
    kind: 'devnet',
    rpcUrl: 'http://127.0.0.1:9545',
    explorerUrl: null,
    faucet: true,
    // 开发链固定 class hash（dev 约定；constructor calldata = [pubkey]）
    accountClassHash: '0xc1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55',
    // 开发链内置代币合约（ETH 形状 ERC-20：balanceOf/transfer，u256 金额）
    tokenAddress: '0xc0de0000000000000000000000000000000070b19e6b9',
    tokenName: 'Dev Stark Token',
    tokenSymbol: 'DST',
    tokenDecimals: 18,
  },
  {
    id: 'starknet-sepolia',
    name: 'Starknet Sepolia 测试网',
    chainIdFelt: '0x534e5f5365706f6c6961', // 'SN_SEPOLIA'
    chainId: 'SN_SEPOLIA',
    kind: 'testnet',
    rpcUrl: 'https://starknet-sepolia.public.blastapi.io/rpc',
    explorerUrl: 'https://sepolia.starkscan.co',
    faucet: false,
    // ArgentX Cairo-1 账户 class（广泛引用的预设值；UI 可覆盖）
    accountClassHash: '0x1a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003',
    // Starknet 原生 ETH（ERC-20）
    tokenAddress: '0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
    tokenName: 'Ether',
    tokenSymbol: 'ETH',
    tokenDecimals: 18,
  },
  {
    id: 'starknet-mainnet',
    name: 'Starknet 主网',
    chainIdFelt: '0x534e5f4d41494e', // 'SN_MAIN'
    chainId: 'SN_MAIN',
    kind: 'mainnet',
    rpcUrl: 'https://starknet-mainnet.public.blastapi.io/rpc',
    explorerUrl: 'https://starkscan.co',
    faucet: false,
    accountClassHash: '0x1a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003',
    tokenAddress: '0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
    tokenName: 'Ether',
    tokenSymbol: 'ETH',
    tokenDecimals: 18,
  },
];

export const DEFAULT_STARKNET_NETWORK_ID = 'starknet-devnet';

/** id → 网络；未知 → null。 */
export function resolveStarknetNetwork(id) {
  const key = String(id ?? '').toLowerCase();
  return STARKNET_NETWORKS.find((n) => n.id === key) ?? null;
}

/** 生效 RPC：用户覆盖 > 预设。 */
export function effectiveRpcUrl(network, rpcOverrides = {}) {
  if (!network) return null;
  const override = rpcOverrides?.[network.id];
  return canonicalHttpUrl(override) ?? canonicalHttpUrl(network.rpcUrl);
}

/** http(s) URL 规范化（origin+path；非法 → null）。 */
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

/** 网络视图（popup 消费）。 */
export function starknetNetworkView(network, rpcOverrides = {}) {
  if (!network) return null;
  return {
    id: network.id,
    name: network.name,
    chainId: network.chainId,
    chainIdFelt: network.chainIdFelt,
    kind: network.kind,
    rpcUrl: effectiveRpcUrl(network, rpcOverrides),
    rpcOverridden: Boolean(rpcOverrides?.[network.id]),
    explorerUrl: network.explorerUrl,
    faucet: network.faucet === true,
    accountClassHash: network.accountClassHash,
    tokenAddress: network.tokenAddress,
    tokenSymbol: network.tokenSymbol,
    tokenName: network.tokenName,
    tokenDecimals: network.tokenDecimals,
  };
}
