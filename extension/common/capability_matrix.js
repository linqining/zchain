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
 * 交付面能力矩阵（PRD F-19 规则 5 / §13 R-26 / AC-36）——**单一数据源**。
 *
 * 为什么放这里：设置页模态、欢迎页的能力宣告、以及验收文档必须引用同一份
 * 常量。稿面此前分三处各写一份（稿 / UI / 文档），任何一处放宽都无人发现。
 * PRD 红线：「能力矩阵必须由同一份常量渲染，不得在稿、UI、文档各写一份」。
 *
 * ⚠ R-26 是这一版的**文案缺陷修正**：0.6.1 之前此处的"网络"行写成
 * "mainnet 刻意不注册"，但事实是**只有 ZChain 层**刻意不注册 mainnet；
 * EVM 注册表含 Ethereum `0x1`，Starknet 亦含主网条目。把局部策略说成全局
 * 事实，会让 EVM 用户以为主网不可用（而本屏就在展示 chainId 1）。
 * 因此网络行按层分列，不把三层压成一句。
 */
export const CAPABILITY_ROWS = [
  {
    layer: 'ZChain',
    can: 'GAME 域可签可转（贪心选币 + 凭证门槛 + 找零守恒）',
    cannot: 'REAL 域仅隔离展示；提现预览 canSubmit 恒 false（wallet-core 展示门 ∧ finality）',
  },
  {
    layer: 'EVM',
    can: '原生币转账与合约写入可签名广播（EIP-155 chainId 编码 + 签名前二次校验）',
    cannot: '不签 note spend；账簿页 ERC-20 余额未接线（显示 `—`，不报 0）',
  },
  {
    layer: 'Starknet',
    can: 'invoke v1 + devnet 水龙头（devnet 代币符号 DST，非 ETH）',
    cannot: 'SNIP-12 授权面已备，**链上 admission 未开放**（当前授权为本机登记）',
  },
  {
    layer: '网络 · ZChain 层',
    can: 'devnet / testnet 可选（封闭注册表）',
    cannot: 'mainnet 刻意不注册 → NetworkUnsupported；testnet 未配置网关 → GatewayNotConfigured',
  },
  {
    layer: '网络 · EVM / Starknet 层',
    can: '含各自主网条目（EVM Ethereum 0x1 / Base / Arbitrum；Starknet 主网），按注册表可选',
    cannot: 'RPC 返回 chainId 与预设不符 → 拒签，不静默继续',
  },
  {
    layer: '边界',
    can: '网关水位、回执证据按上游原样展示',
    cannot: '盲签拒绝；私钥 / 助记词 / nullifier 不出边界；水位不推进、不猜测',
  },
  {
    layer: '会话',
    can: '三层共用同一口令解锁（一次输入尝试全部层）',
    cannot: '三层 keystore 与会话彼此独立（存在 2/3 中间态）；后台被回收即锁定（fail-closed）',
  },
];

/** 欢迎页固定能力宣告（与上表同源，非查询结果）：`3 账户层 / 2 套 KDF / STARK`。 */
export const CAPABILITY_SUMMARY = {
  layers: 3,
  kdfs: 2,
  proofSystem: 'STARK',
  text: '3 账户层 / 2 套 KDF / STARK 可验结算',
};

/** 交互预算（PRD D-55：超 500ms 必须如实标注，不伪装即时）。 */
export const INTERACTION_BUDGET_MS = 500;

/** 超过预算时的强制标注文案（F-13 规则 3）。 */
export function overBudgetNote(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= INTERACTION_BUDGET_MS) return null;
  return `超预算（低频场景可接受，性能不敏感）：${(n / 1000).toFixed(2)}s > 0.50s`;
}

/**
 * 外部钱包 / 客户端能力探测矩阵（WALLET-ACC-7）。
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
