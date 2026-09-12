// =============================================================================
// extension/adapters/eip1193.js — EIP-1193 兼容适配器（Extension 0.1）
//
// 定位（如实声明）：这是 zchain provider 之上的 **EIP-1193 请求信封**（事件型
// provider），让只懂 EIP-1193 形状的客户端能以只读方式发现 ZChain 网络并
// 路由 `zchain_*` 方法。它**不是** MetaMask、不写 `window.ethereum`、不派发
// EIP-6963 announce、`eth_chainId` 永不返回 EVM 已注册链（见 shared.js 映射表）。
//
// plan 红线（§6.12.1）如何被本文件钉住：
// - EVM 钱包仅可作"未来 EVM bridge/登录适配器"，不能伪装成 Note owner：
//   `eth_sign`/`personal_sign`/`eth_signTypedData*`/`eth_sendTransaction`/
//   `eth_sendRawTransaction` 一律拒绝（EvmSigningForbidden），无开关、无
//   降级路径；文档（adapters/README.md）写明未来 EVM bridge 的前置条件。
// - 白名单外 eth_* 一律 unsupportedMethod（4200）。
// - zchain_* 透传仍走 common/validation.js 的 METHODS_01 白名单（WALLET-ACC-3
//   的同一拒绝面），签名类最终仍过后台 origin/nonce/expiry/session 校验与
//   popup 显式确认——适配器只是信封，不新增任何绕过路径。
//
// 纪律：零密码学、零依赖、无 IO；事件源注入（见 createEip1193Provider）。
// =============================================================================

import {
  EIP1193_ERROR_CODES,
  EIP1193_ETH_ALLOWED,
  EIP1193_ETH_SIGNING_DENIED,
  fromEip1193ChainId,
  netVersionFor,
  toEip1193ChainId,
} from './shared.js';
import { METHODS_01, validateRequest } from '../common/validation.js';

/** EIP-1193 风格错误（数字 code + 稳定 token 在 data.zchainCode）。 */
export class Eip1193Error extends Error {
  constructor(code, message, data) {
    super(message);
    this.name = 'Eip1193Error';
    this.code = code;
    if (data !== undefined) this.data = data;
  }
}

function unsupported(method, zchainCode, reason) {
  return new Eip1193Error(
    EIP1193_ERROR_CODES.unsupportedMethod,
    `ZChain does not support ${method}: ${reason}`,
    { zchainCode },
  );
}

// ---------------------------------------------------------------------------
// 内部事件总线（最小 EventEmitter；on/removeListener/once 语义）
// ---------------------------------------------------------------------------

class Emitter {
  constructor() {
    this.handlers = new Map();
  }

  on(event, cb) {
    if (!this.handlers.has(event)) this.handlers.set(event, new Set());
    this.handlers.get(event).add(cb);
    return this;
  }

  removeListener(event, cb) {
    this.handlers.get(event)?.delete(cb);
    return this;
  }

  emit(event, payload) {
    const set = this.handlers.get(event);
    if (!set) return;
    for (const cb of [...set]) {
      try {
        cb(payload);
      } catch {
        // 监听器异常不阻断其它监听器（fail-open 仅限 UI 通知路径）。
      }
    }
  }
}

/**
 * 适配器接受的 zchain 事件源契约：`{ on(event, cb), off(event, cb) }`，
 * 事件名与负载：
 *   - `zchain:chainChanged`   payload: string 网络id（`zchain-devnet-1`）
 *   - `zchain:accountsChanged` payload: string[] 账户公钥
 *   - `zchain:disconnect`     payload: { code?, reason? }
 * 0.1 的 inpage provider 尚未派发这些事件（provider 事件面是 0.2 交付）；
 * 本适配器把事件源设计为**注入项**：后台/测试/未来 provider 均可实现同一
 * 契约，注入即生效，不为 0.1 虚构事件。
 */

/**
 * 创建 EIP-1193 兼容 provider。
 *
 * @param {object} opts
 * @param {object} opts.zchain      zchain provider（inpage 形状：getNetwork/
 *                                  getAccounts/signOperation/… 异步方法）
 * @param {object} [opts.eventSource] 上述契约的事件源（可选）
 * @param {string} [opts.networkId] 初始网络 id（默认从 zchain.getNetwork() 取）
 * @returns {object} EIP-1193 形状 provider：request/on/removeListener(+emit 供测试)
 */
export function createEip1193Provider({ zchain, eventSource = null, networkId = null } = {}) {
  if (!zchain || typeof zchain !== 'object') {
    throw new TypeError('createEip1193Provider: zchain provider required');
  }
  const bus = new Emitter();
  let currentNetworkId = networkId; // 惰性：首个请求时从 getNetwork() 填充
  let connected = false;

  function currentHexChainId() {
    const hex = toEip1193ChainId(currentNetworkId);
    if (!hex) {
      throw new Eip1193Error(
        EIP1193_ERROR_CODES.chainDisconnected,
        `ZChain network ${String(currentNetworkId)} has no EIP-1193 alias`,
        { zchainCode: 'NetworkInvalid' },
      );
    }
    return hex;
  }

  function emitConnected() {
    if (connected) return;
    connected = true;
    bus.emit('connect', { chainId: currentHexChainId() });
  }

  async function resolveNetworkId() {
    if (currentNetworkId) return currentNetworkId;
    const net = await zchain.getNetwork();
    currentNetworkId = net?.chainId ?? null;
    return currentNetworkId;
  }

  /** eth_accounts → zchain_getAccounts（锁定返回 []，符合 EIP-1193 语义）。 */
  async function ethAccounts() {
    const res = await zchain.getAccounts();
    return Array.isArray(res?.accounts) ? res.accounts : [];
  }

  /**
   * zchain_* 透传：与 inpage 相同的方法面，仍按 validation.js 的 METHODS_01
   * 白名单 + 结构校验把关（UnknownMethod/NotSupportedIn01/MissingParam/…）。
   */
  async function routeZchain(method, params) {
    const networkIdNow = await resolveNetworkId();
    if (!METHODS_01.has(method)) {
      // 与后台 validateRequest 的两个拒绝面一致（未知 vs 0.1 未交付）。
      const vr = validateRequest(method, {}, { network: { chainId: networkIdNow } });
      throw new Eip1193Error(
        EIP1193_ERROR_CODES.unsupportedMethod,
        `${vr.code}: ${method} ${vr.reason}`,
        { zchainCode: vr.code },
      );
    }
    const vr = validateRequest(method, params ?? {}, { network: { chainId: networkIdNow } });
    if (!vr.ok) {
      throw new Eip1193Error(EIP1193_ERROR_CODES.zchainRouted, `${vr.code}: ${vr.reason}`, {
        zchainCode: vr.code,
      });
    }
    switch (method) {
      case 'zchain_requestAccounts':
        return zchain.requestAccounts();
      case 'zchain_getNetwork':
        return zchain.getNetwork();
      case 'zchain_getCapabilities':
        return zchain.getCapabilities();
      case 'zchain_getAccounts':
        // 与 inpage 响应形状一致（{ accounts, locked }）；eth_accounts 才映射为裸数组。
        return zchain.getAccounts();
      case 'zchain_signOperation':
        return zchain.signOperation(params.operation, params.previewHash);
      case 'zchain_signSettlement':
        return zchain.signSettlement(params.settlement, params.previewHash);
      case 'zchain_getNotes':
        return zchain.getNotes(params.filter);
      case 'zchain_lock':
        return zchain.lock();
      default:
        throw unsupported(method, 'MethodNotAllowed', 'no route in 0.1');
    }
  }

  const provider = {
    // 诚实标志：绝不提供 isMetaMask/isRabby 等 EIP-1193 身份伪装。
    isZChain: true,
    isZChainEip1193Shim: true,
    providerName: 'ZChain Wallet (EIP-1193 shim, read-only eth_*)',

    /** EIP-1193 request 入口。 */
    async request({ method, params } = {}) {
      if (typeof method !== 'string' || method.length === 0) {
        throw new Eip1193Error(
          EIP1193_ERROR_CODES.unsupportedMethod,
          'ZC-BadRequest: method must be a non-empty string',
          { zchainCode: 'BadRequest' },
        );
      }

      // (1) 只读 eth_* 白名单 → ZChain 网络身份（独立数字别名，见映射表）。
      if (EIP1193_ETH_ALLOWED.has(method)) {
        await resolveNetworkId();
        emitConnected();
        switch (method) {
          case 'eth_chainId':
            return currentHexChainId();
          case 'net_version':
            return netVersionFor(currentNetworkId);
          case 'eth_accounts':
            return ethAccounts();
          default:
            throw unsupported(method, 'MethodNotAllowed', 'unreachable');
        }
      }

      // (2) EVM 签名/交易：红线拒绝（无开关）。
      if (EIP1193_ETH_SIGNING_DENIED.has(method)) {
        throw unsupported(
          method,
          'EvmSigningForbidden',
          'ZChain signatures are not EVM signatures (plan §6.12.1); EVM wallets may only serve a future EVM bridge/login adapter',
        );
      }

      // (3) 其它 eth_*/wallet_*：一律不支持（不探测、不猜测）。
      if (method.startsWith('eth_') || method.startsWith('wallet_')) {
        throw unsupported(method, 'MethodNotAllowed', 'outside the read-only eth_* subset');
      }

      // (4) zchain_* 透传（同一 §6.12.4 方法面；后台校验不变）。
      if (method.startsWith('zchain_')) {
        const result = await routeZchain(method, params);
        emitConnected();
        return result;
      }

      throw unsupported(method, 'UnknownMethod', 'not an eth_*/zchain_* method');
    },

    on(event, cb) {
      bus.on(event, cb);
      return provider;
    },

    removeListener(event, cb) {
      bus.removeListener(event, cb);
      return provider;
    },

    /** 测试/宿主注入用（非 EIP-1193 表面）。 */
    emit: (event, payload) => bus.emit(event, payload),
  };

  // ---- 事件转发：zchain 事件源 → EIP-1193 事件（数字别名） ----
  // 事件源缺省 = zchain provider 本身（它实现了 on/off 即可作为事件源）；
  // 也可注入独立事件源（后台/宿主实现同一契约）。
  const source = eventSource ?? (typeof zchain.on === 'function' ? zchain : null);
  if (source && typeof source.on === 'function') {
    const offFns = [];
    const sub = (event, handler) => {
      source.on(event, handler);
      if (typeof source.off === 'function') offFns.push(() => source.off(event, handler));
    };
    sub('zchain:chainChanged', (networkIdNext) => {
      if (typeof networkIdNext !== 'string' || !toEip1193ChainId(networkIdNext)) return; // fail-closed：未知网络不转发
      currentNetworkId = networkIdNext;
      bus.emit('chainChanged', toEip1193ChainId(networkIdNext));
    });
    sub('zchain:accountsChanged', (accounts) => {
      bus.emit('accountsChanged', Array.isArray(accounts) ? accounts : []);
    });
    sub('zchain:disconnect', (payload) => {
      connected = false;
      bus.emit('disconnect', new Eip1193Error(EIP1193_ERROR_CODES.disconnected, `ZChain provider disconnected: ${payload?.reason ?? 'unknown'}`, { zchainCode: payload?.code ?? 'Disconnected' }));
    });
    // 0.1 不提供 off 生命周期（provider 与适配器同生命周期）；offFns 留作 0.2。
    void offFns;
  }

  return provider;
}

// 测试/文档钩子：把 EIP-1193 hex chain id 映射回网络 id（供诊断使用）。
export { fromEip1193ChainId };
