// =============================================================================
// extension/common/networks.js — ZChain 网络注册表（Extension 0.2）
//
// §6.12.4 "testnet + 网络切换"的单一事实源：
// - 只有在本表显式登记的网络才可使用（fail-closed）；`zchain-mainnet-1`
//   **刻意不登记**——devnet/testnet 不得误连 mainnet 配置（红线），任何
//   主网接入都是 1.0 前审查门槛后的独立交付；
// - chain_id 参与签名摘要域由 wallet-core 保证（operation_signer::preview_digest
//   绑定 chain_id；WALLET-ACC-2 逻辑面测试覆盖），本模块只提供解析与展示配置；
// - 网关/explorer URL 按网络解析；testnet 未部署网关 → gatewayUrl = null
//   （portal 必须如实报"未配置"，不得回落 devnet 网关）。
//
// 纯数据 + 纯函数：零 IO、零密码学、零浏览器全局（node --test 直接覆盖）。
// =============================================================================

/** 网络注册表（新网络必须在此登记，否则一律拒绝）。 */
export const NETWORKS = {
  'zchain-devnet-1': {
    chainId: 'zchain-devnet-1',
    kind: 'devnet',
    label: 'Devnet（本地）',
    abiVersion: 1,
    // 本地 replay 网关默认地址（explorer_gateway --listen 127.0.0.1:18900）。
    defaultGatewayUrl: 'http://127.0.0.1:18900',
    // explorer 链接基址（0.2 与网关同源）。
    explorerBase: 'http://127.0.0.1:18900',
  },
  'zchain-testnet-1': {
    chainId: 'zchain-testnet-1',
    kind: 'testnet',
    label: 'Testnet',
    abiVersion: 1,
    // testnet 公共网关未部署：必须由用户显式设置，绝不静默回落 devnet。
    defaultGatewayUrl: null,
    explorerBase: null,
  },
};

/** Extension 0.2 可用网络 id 列表（顺序即 UI 展示序）。 */
export const NETWORK_IDS = Object.keys(NETWORKS);

/** 默认网络（devnet；与 wallet-core DEFAULT_CHAIN_ID 一致）。 */
export const DEFAULT_NETWORK_ID = 'zchain-devnet-1';

/** 主网红线：0.2 无主网配置。 */
export const MAINNET_CHAIN_ID = 'zchain-mainnet-1';

// ---------------------------------------------------------------------------
// TE-M5：资产 token 名称解析表（网络配置级单一事实源）
// ---------------------------------------------------------------------------

/**
 * AssetId 资产维度展示配置（ABI v2 冻结判别值：domain REAL=1 / GAME=2；
 * 与 poker-appchain `asset_id.rs` 同一数值面，UI 层不做第二种换算）。
 *
 * - `domainNames`：域名（判别值 → 展示名）；
 * - `realTokens`：REAL 域封闭枚举（token_id → 展示名：0=NATIVE / 1=USDT /
 *   2=USDC）。新增币种 = ABI 版本升级——**不在 UI 层造名**，未知 token_id
 *   解析失败（fail-closed）；
 * - `gameTokens`：GAME 域静态名只有遗留 PLAY（token_id 0，v1 休闲筹码
 *   特例）。GTS 注册游戏币（token_id ≥ 1）**没有链上名称字段**（genesis
 *   规格不含 name），注册表随网络从网关 `status.assets` 动态获取、以
 *   `token <id>` 编号如实呈现——刻意不静态登记链下名称，避免与链上注册
 *   表漂移。
 */
export const ASSET_TABLE = {
  domainNames: { 1: 'REAL', 2: 'GAME' },
  realTokens: { 0: 'NATIVE', 1: 'USDT', 2: 'USDC' },
  gameTokens: { 0: 'PLAY(legacy)' },
};

/**
 * 解析网络 id → 网络配置；未登记网络（含 mainnet）返回 null。
 * @param {string} chainId
 * @returns {{chainId: string, kind: string, label: string, abiVersion: number,
 *            defaultGatewayUrl: string|null, explorerBase: string|null} | null}
 */
export function resolveNetwork(chainId) {
  if (typeof chainId !== 'string') return null;
  const net = NETWORKS[chainId];
  return net ? { ...net } : null;
}

/**
 * 网络切换目标合法性（validateRequest 的注册表面）：
 * - 未登记（含 mainnet/任意字符串）→ { ok:false, code:'NetworkUnsupported' }；
 * - 已登记 → { ok:true, network }。
 */
export function checkSwitchTarget(chainId) {
  const net = resolveNetwork(chainId);
  if (!net) {
    return {
      ok: false,
      code: 'NetworkUnsupported',
      reason:
        chainId === MAINNET_CHAIN_ID
          ? 'mainnet is intentionally not configured in extension 0.2 (devnet/testnet only)'
          : `unknown network ${String(chainId)}`,
    };
  }
  return { ok: true, network: net };
}

/**
 * 生效网关 URL 解析：用户设置优先，缺省用网络默认值；两者皆无（testnet
 * 未部署）→ null（调用方必须如实报 GatewayNotConfigured）。
 */
export function effectiveGatewayUrl(chainId, userSettings) {
  const net = resolveNetwork(chainId);
  if (!net) return null;
  const configured = userSettings?.[chainId]?.gatewayUrl;
  if (configured != null) {
    const v = canonicalHttpUrl(configured);
    if (v) return v;
  }
  return net.defaultGatewayUrl;
}

/** http(s) URL 规范化（去路径/去尾斜杠；非法 → null）。 */
export function canonicalHttpUrl(url) {
  if (typeof url !== 'string' || url.length === 0 || url.length > 256) return null;
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    // 只保留 scheme+host+port（网关是源级配置；路径不参与）。
    return u.origin;
  } catch {
    return null;
  }
}

/**
 * explorer 上单手结算的链接（不可用时返回 null——UI 显示"无链接"而非伪造）。
 */
export function settlementExplorerUrl(chainId, userSettings, bindingHex) {
  const net = resolveNetwork(chainId);
  if (!net) return null;
  const base = userSettings?.[chainId]?.explorerBase
    ? canonicalHttpUrl(userSettings[chainId].explorerBase)
    : net.explorerBase;
  if (!base) return null;
  return `${base}/api/v1/settlement/${bindingHex}`;
}
