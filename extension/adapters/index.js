// =============================================================================
// extension/adapters/index.js — 连接协议适配器注册面（可配置开关）
//
// 职责：
// - 统一装载三适配器（EIP-1193 / WalletConnect v2 / Starknet 钱包接口）；
// - 配置开关持久化（默认全启用，但默认态即为安全态：EIP-1193 只读子集恒定、
//   WC 需外部注入 SignClient 才激活、Starknet 仅在显式调用授权流程时触达
//   钱包对象）；
// - 状态自省（popup / 诊断可查询，不虚报激活状态）。
//
// 红线锚点（见 shared.js）：无论开关如何组合，EVM 签名方法没有启用路径，
// WC 没有注入 SignClient 就没有会话，Starknet 只服务 SNIP-12 授权委托。
// =============================================================================

import { createEip1193Provider } from './eip1193.js';
import { createWalletConnectAdapter, WC_SESSION_TTL_SEC } from './walletconnect.js';
import { ZCHAIN_NETWORK_ID } from './shared.js';

/**
 * 默认配置（安全默认：全部"可用但不越权"）。
 * - eip1193.enabled：允许创建 EIP-1193 shim（eth_* 只读子集是硬编码，无开关）；
 * - walletconnect.enabled + requireInjectedSignClient：未注入 SignClient 时
 *   适配器保持 dormant（不监听任何会话事件）；
 * - starknet.enabled：允许检测/授权流程（只在被显式调用时触达钱包对象）。
 */
export const DEFAULT_ADAPTER_CONFIG = {
  eip1193: { enabled: true },
  walletconnect: { enabled: true, requireInjectedSignClient: true, sessionTtlSec: WC_SESSION_TTL_SEC },
  starknet: { enabled: true },
};

/** 合并部分配置（未知键忽略；值域 fail-closed）。 */
export function resolveAdapterConfig(partial) {
  const d = DEFAULT_ADAPTER_CONFIG;
  const pick = (v, fallback) => (typeof v === 'boolean' ? v : fallback);
  const ttl = (v) => (Number.isSafeInteger(v) && v > 0 ? v : d.walletconnect.sessionTtlSec);
  return {
    eip1193: { enabled: pick(partial?.eip1193?.enabled, d.eip1193.enabled) },
    walletconnect: {
      enabled: pick(partial?.walletconnect?.enabled, d.walletconnect.enabled),
      requireInjectedSignClient: pick(
        partial?.walletconnect?.requireInjectedSignClient,
        d.walletconnect.requireInjectedSignClient,
      ),
      sessionTtlSec: ttl(partial?.walletconnect?.sessionTtlSec),
    },
    starknet: { enabled: pick(partial?.starknet?.enabled, d.starknet.enabled) },
  };
}

/**
 * 初始化适配器宿主。
 *
 * @param {object} opts
 * @param {object} [opts.config]           部分配置（与 DEFAULT_ADAPTER_CONFIG 合并）
 * @param {object} [opts.zchain]           zchain provider 面（inpage 或后台同形门面）
 * @param {object} [opts.signClient]       注入的 SignClient（生产 = @walletconnect/sign-client；
 *                                         缺省 = WC 适配器 dormant，不挂任何事件）
 * @param {string} [opts.networkId]        当前 ZChain 网络 id（默认 zchain-devnet-1）
 * @param {object} [opts.eventSource]      zchain 事件源（EIP-1193 shim 转发用）
 * @param {(event, fields) => void} [opts.log] 字段白名单日志
 */
export function initAdapters({
  config: configPartial = {},
  zchain = null,
  signClient = null,
  networkId = ZCHAIN_NETWORK_ID,
  eventSource = null,
  log = () => {},
} = {}) {
  const config = resolveAdapterConfig(configPartial);
  const network = { chainId: networkId };
  const warnings = [];

  // ---- EIP-1193 shim 工厂（enabled=false 时拒绝创建）----
  const createEip1193 = (overrides = {}) => {
    if (!config.eip1193.enabled) {
      return { ok: false, code: 'AdapterDisabled', reason: 'eip1193 adapter is disabled by config' };
    }
    const provider = createEip1193Provider({
      zchain: overrides.zchain ?? zchain,
      eventSource: overrides.eventSource ?? eventSource,
      networkId: overrides.networkId ?? networkId,
    });
    return { ok: true, provider };
  };

  // ---- WalletConnect v2（需注入 SignClient；否则 dormant）----
  let walletconnect = null;
  if (!config.walletconnect.enabled) {
    warnings.push('walletconnect disabled by config');
  } else if (!signClient) {
    warnings.push('walletconnect dormant: no SignClient injected (production = @walletconnect/sign-client)');
  } else {
    walletconnect = createWalletConnectAdapter({
      signClient,
      zchain,
      network,
      sessionTtlSec: config.walletconnect.sessionTtlSec,
      log,
    });
  }

  return {
    config,
    /** 创建 EIP-1193 兼容 provider（每次调用返回独立实例）。 */
    createEip1193,
    /** WC 适配器句柄（dormant 时为 null，如实暴露）。 */
    walletconnect,
    /** 状态自省（不含任何密钥/参数级信息）。 */
    status() {
      return {
        eip1193: { enabled: config.eip1193.enabled, ethSubset: 'read-only (hard-coded)' },
        walletconnect: {
          enabled: config.walletconnect.enabled,
          active: walletconnect != null,
          sessions: walletconnect ? walletconnect.sessions.size : 0,
        },
        starknet: { enabled: config.starknet.enabled },
        networkId,
        warnings,
      };
    },
  };
}
