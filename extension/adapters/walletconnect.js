// =============================================================================
// extension/adapters/walletconnect.js — WalletConnect v2 适配核心（Extension 0.1）
//
// 定位（如实声明）：WC v2 只是**会话传输**。本模块是"适配核心"：接受注入的
// SignClient 形状接口（生产 = `@walletconnect/sign-client` 实例；测试 =
// wc_signclient_stub.js 内存实现），完成：
//   1) session proposal 的 namespace 映射——只接受 `zchain:` namespace
//      （chains = ZChain 网络 id、methods = §6.12.4 zchain_* 白名单、events =
//      chainChanged/accountsChanged），`eip155:`/`sn:` 等一律整案拒绝；
//   2) session request → zchain provider 路由：方法白名单 + 会话授权集 +
//      getCapabilities 能力探测 + validation.js 参数结构校验 + 请求 id 单调
//      （重放拒）+ 请求/会话过期拒；
//   3) zchain 事件 → session_event 转发（chainChanged/accountsChanged）。
//
// 红线（plan §6.12.1/§6.12.12，测试逐一钉住）：
// - 能力不足即拒：授权阶段即做 getCapabilities 探测，授予集 = 请求 ∩ 白名单 ∩
//   能力；请求阶段对"曾请求但能力缺失"的方法回 CapabilityMissing，对从未授予
//   的方法回 MethodNotAllowed——**绝不退化成 blind signing**。
// - 不伪装：独立 `zchain:` CAIP namespace、独立网络 id；account 形状
//   `zchain:<networkId>:<公钥>`，不冒充 eip155/sn 账户。
//
// 纪律：零密码学、零 npm 依赖（SignClient 为注入接口）、无浏览器全局。
// =============================================================================

import {
  WC_ERROR_CODES,
  WC_PROPOSAL_REJECT_CODES,
  WC_ZCHAIN_EVENTS,
  ZCHAIN_METHODS_SET,
  networkIdFromCaip2,
  toCaip10Account,
  wcErrorPayload,
} from './shared.js';
import { validateRequest } from '../common/validation.js';

/** 会话默认有效期（秒）：7 天；到期后该会话一切请求拒（SessionExpired）。 */
export const WC_SESSION_TTL_SEC = 7 * 24 * 3600;

/** method → zchain provider 调用（与 inpage provider 的方法面一致）。 */
const ROUTES = {
  zchain_requestAccounts: (p, z) => z.requestAccounts(),
  zchain_getNetwork: (_p, z) => z.getNetwork(),
  zchain_getCapabilities: (_p, z) => z.getCapabilities(),
  zchain_getAccounts: (_p, z) => z.getAccounts(),
  zchain_signOperation: (p, z) => z.signOperation(p.operation, p.previewHash),
  zchain_signSettlement: (p, z) => z.signSettlement(p.settlement, p.previewHash),
  zchain_getNotes: (p, z) => z.getNotes(p.filter),
  zchain_lock: (_p, z) => z.lock(),
};

/**
 * 创建 WC v2 适配器并挂到 signClient 事件上。
 *
 * @param {object} opts
 * @param {object} opts.signClient  SignClient 形状接口（见 wc_signclient_stub.js 头注释）
 * @param {object} opts.zchain      zchain provider 面（getNetwork/getCapabilities/
 *                                  getAccounts/signOperation/…；inpage 或后台同形门面）
 * @param {object} [opts.network]   { chainId }（默认 zchain-devnet-1）
 * @param {() => number} [opts.now] 当前毫秒（测试注入）
 * @param {number} [opts.sessionTtlSec]
 * @param {(event: string, fields: object) => void} [opts.log] 字段白名单日志
 * @returns {{ detach(): void, sessions: Map, grantedMethodsOf(topic): string[] }}
 */
export function createWalletConnectAdapter({
  signClient,
  zchain,
  network = { chainId: 'zchain-devnet-1' },
  now = () => Date.now(),
  sessionTtlSec = WC_SESSION_TTL_SEC,
  log = () => {},
} = {}) {
  if (!signClient || typeof signClient.on !== 'function' || typeof signClient.approveSession !== 'function') {
    throw new TypeError('createWalletConnectAdapter: SignClient-shaped signClient required');
  }
  if (!zchain || typeof zchain !== 'object') {
    throw new TypeError('createWalletConnectAdapter: zchain provider required');
  }

  /** topic → { topic, methods(授予集), requested, chains, accounts, expiry } */
  const sessionRecords = new Map();
  /** topic → 该会话已见最大请求 id（单调；重放/回退拒）。 */
  const lastRequestId = new Map();
  const listeners = new Set();

  const nowSec = () => Math.floor(now() / 1000);

  function failRequest(topic, id, code, stableCode, reason) {
    log('wc_request_rejected', { code: stableCode, kind: 'session_request' });
    signClient.respondSessionRequest({
      topic,
      response: { id, jsonrpc: '2.0', error: wcErrorPayload(code, stableCode, reason) },
    });
  }

  // ---------------------------------------------------------------------------
  // (1) session_proposal：namespace 映射 + 能力探测 → approve / reject
  // ---------------------------------------------------------------------------

  function rejectProposal(id, codeKey, message) {
    log('wc_proposal_rejected', { code: codeKey, kind: 'session_proposal' });
    signClient.rejectSession({ id, reason: { code: WC_PROPOSAL_REJECT_CODES[codeKey], message } });
  }

  async function handleProposal(proposal) {
    const id = proposal?.id;
    if (!Number.isSafeInteger(id)) return;
    const required = proposal.params?.requiredNamespaces ?? proposal.params?.namespaces ?? {};

    // (a) 只接受单一 `zchain:` namespace（不与 eip155/sn 混装——不伪装红线）。
    const keys = Object.keys(required);
    if (keys.length !== 1 || keys[0] !== 'zchain') {
      rejectProposal(id, 'unsupportedNamespaceKey', `only the "zchain" namespace is supported, got [${keys.join(', ')}]`);
      return;
    }
    const ns = required.zchain ?? {};

    // (b) chains：必须全是 zchain: 且等于当前网络。
    const chains = Array.isArray(ns.chains) ? ns.chains : [];
    if (chains.length === 0 || !chains.every((c) => networkIdFromCaip2(c) === network.chainId)) {
      rejectProposal(id, 'unsupportedChains', `zchain namespace supports only [zchain:${network.chainId}]`);
      return;
    }

    // (c) methods：必须都在 §6.12.4 zchain_* 白名单内（eth_* 永不接受）。
    const methods = Array.isArray(ns.methods) ? ns.methods : [];
    const illegal = methods.filter((m) => !ZCHAIN_METHODS_SET.has(m));
    if (methods.length === 0 || illegal.length > 0) {
      rejectProposal(id, 'unsupportedMethods', `methods outside the zchain_* whitelist: [${illegal.join(', ')}]`);
      return;
    }

    // (d) events：只支持 chainChanged/accountsChanged。
    const events = Array.isArray(ns.events) ? ns.events : [];
    if (!events.every((e) => WC_ZCHAIN_EVENTS.includes(e))) {
      rejectProposal(id, 'unsupportedMethods', `unsupported zchain events: [${events.join(', ')}]`);
      return;
    }

    // (e) 能力探测（getCapabilities）：授予集 = 请求 ∩ 白名单 ∩ 能力。
    //     探测失败 → 整案拒绝（fail-closed，绝不盲签）。
    let caps;
    try {
      caps = await zchain.getCapabilities();
    } catch (e) {
      rejectProposal(id, 'capabilityProbeFailed', `getCapabilities failed: ${e?.code ?? e?.message ?? 'error'}`);
      return;
    }
    const capMethods = new Set(Array.isArray(caps?.methods) ? caps.methods : []);
    const granted = methods.filter((m) => capMethods.has(m));

    // (f) 账户：公钥级信息（无密钥材料）；未解锁无账户 → 拒（5002）。
    let accounts = [];
    try {
      const res = await zchain.getAccounts();
      accounts = Array.isArray(res?.accounts) ? res.accounts : [];
    } catch {
      accounts = [];
    }
    if (accounts.length === 0) {
      rejectProposal(id, 'unsupportedAccounts', 'wallet has no unlocked account to expose (unlock first)');
      return;
    }

    const grantedNamespaces = {
      zchain: {
        chains: [`zchain:${network.chainId}`],
        methods: granted,
        events: events.filter((e) => WC_ZCHAIN_EVENTS.includes(e)),
        accounts: accounts.map((pk) => toCaip10Account(network.chainId, pk)),
      },
    };

    const approved = signClient.approveSession({ id, namespaces: grantedNamespaces });
    const topic = approved?.topic;
    sessionRecords.set(topic, {
      topic,
      methods: granted,
      requested: methods,
      chains: [`zchain:${network.chainId}`],
      accounts: grantedNamespaces.zchain.accounts,
      expiry: nowSec() + sessionTtlSec,
    });
    log('wc_session_approved', { kind: 'session_proposal', count: granted.length });
  }

  // ---------------------------------------------------------------------------
  // (2) session_request：白名单/授权/能力/重放/过期 → validation.js → 路由
  // ---------------------------------------------------------------------------

  function handleRequest(event) {
    const id = event?.id;
    const topic = event?.topic;
    const request = event?.params?.request;
    const record = sessionRecords.get(topic);

    // (a) 会话存在性（未知 topic / 已被 disconnect）。
    if (!record || !signClient.session?.has?.(topic)) {
      failRequest(topic, id, WC_ERROR_CODES.unknownSession, 'UnknownSession', `no zchain session ${String(topic)}`);
      return;
    }

    // (b) 会话过期（relay 侧 expiry 或本地 TTL）。
    const sessionExpiry = Math.min(record.expiry, signClient.session.get(topic)?.expiry ?? record.expiry);
    if (nowSec() >= sessionExpiry) {
      failRequest(topic, id, WC_ERROR_CODES.sessionExpired, 'SessionExpired', 'session expired; reconnect required');
      try {
        signClient.disconnect({ topic, reason: { message: 'session expired' } });
      } catch {
        // 已被对端断开：目标状态一致。
      }
      sessionRecords.delete(topic);
      return;
    }

    // (c) 重放/回退：请求 id 必须严格递增（WC id 单调语义的本地强制）。
    const last = lastRequestId.get(topic);
    if (!Number.isSafeInteger(id) || (last != null && id <= last)) {
      failRequest(topic, id, WC_ERROR_CODES.replayDetected, 'ReplayDetected', `request id ${String(id)} replays/regresses ${String(last)}`);
      return;
    }
    lastRequestId.set(topic, id);

    // (d) 方法在 §6.12.4 白名单内？（白名单外永不执行——无盲签开口。）
    const method = request?.method;
    if (typeof method !== 'string' || !ZCHAIN_METHODS_SET.has(method)) {
      failRequest(topic, id, WC_ERROR_CODES.methodNotAllowed, 'MethodNotAllowed', `${String(method)} is not a zchain_* method`);
      return;
    }

    // (e) 方法在会话授予集内？
    if (!record.methods.includes(method)) {
      const code = record.requested.includes(method) ? WC_ERROR_CODES.capabilityMissing : WC_ERROR_CODES.methodNotAllowed;
      const stable = record.requested.includes(method) ? 'CapabilityMissing' : 'MethodNotGranted';
      const reason =
        stable === 'CapabilityMissing'
          ? `${method} was requested but the wallet capability probe (getCapabilities) does not expose it; refusing (no blind signing)`
          : `${method} was not granted in the session namespace`;
      failRequest(topic, id, code, stable, reason);
      return;
    }

    // (f) 请求自带 expiry？（可选；早于当前时间即拒。）
    const reqExpiry = request?.expiry;
    if (reqExpiry != null && (!Number.isSafeInteger(reqExpiry) || nowSec() >= reqExpiry)) {
      failRequest(topic, id, WC_ERROR_CODES.requestExpired, 'RequestExpired', 'request expiry passed');
      return;
    }

    // (g) chainId 参数必须指向当前 zchain 网络。
    const reqChain = event.params?.chainId ?? request?.chainId;
    if (reqChain != null && networkIdFromCaip2(reqChain) !== network.chainId) {
      failRequest(topic, id, WC_ERROR_CODES.methodNotAllowed, 'UnsupportedChain', `chain ${String(reqChain)} != zchain:${network.chainId}`);
      return;
    }

    // (h) 参数结构校验：与页面通道同一 validation.js 拒绝面（缺参/金额/ABI/
    //     domain/网络不符…稳定码透传）。
    const params = request?.params ?? {};
    const vr = validateRequest(method, params, { network, now: now() });
    if (!vr.ok) {
      failRequest(topic, id, WC_ERROR_CODES.invalidParams, vr.code, vr.reason);
      return;
    }

    // (i) 路由到 zchain provider（签名类最终仍过后台 popup 显式确认与
    //     wallet-core 全拒绝面——WC 只是传输，不新增任何能力）。
    const route = ROUTES[method];
    if (!route) {
      failRequest(topic, id, WC_ERROR_CODES.methodNotAllowed, 'NotSupportedIn01', `${method} has no 0.1 route`);
      return;
    }
    Promise.resolve()
      .then(() => route(params, zchain))
      .then((result) => {
        signClient.respondSessionRequest({
          topic,
          response: { id, jsonrpc: '2.0', result: result ?? null },
        });
        log('wc_request_resolved', { method, kind: 'session_request' });
      })
      .catch((e) => {
        failRequest(
          topic,
          id,
          WC_ERROR_CODES.provider,
          e?.code ?? 'ProviderError',
          e?.message ?? 'zchain provider error',
        );
      });
  }

  // ---------------------------------------------------------------------------
  // (3) 会话删除 / zchain 事件转发
  // ---------------------------------------------------------------------------

  function handleDelete({ topic } = {}) {
    sessionRecords.delete(topic);
    lastRequestId.delete(topic);
    for (const cb of listeners) cb({ topic });
  }

  function forwardZchainEvents(eventSource) {
    if (!eventSource || typeof eventSource.on !== 'function') return () => {};
    const offs = [];
    const on = (name, fn) => {
      eventSource.on(name, fn);
      if (typeof eventSource.off === 'function') offs.push(() => eventSource.off(name, fn));
    };
    on('zchain:chainChanged', (networkId) => {
      for (const topic of sessionRecords.keys()) {
        try {
          signClient.emitSessionEvent({ topic, event: { name: 'chainChanged', data: networkId }, chainId: `zchain:${networkId}` });
        } catch {
          // 会话已消失：跳过。
        }
      }
    });
    on('zchain:accountsChanged', (accounts) => {
      for (const topic of sessionRecords.keys()) {
        try {
          signClient.emitSessionEvent({ topic, event: { name: 'accountsChanged', data: Array.isArray(accounts) ? accounts : [] }, chainId: `zchain:${network.chainId}` });
        } catch {
          // 同上。
        }
      }
    });
    return () => offs.forEach((f) => f());
  }

  const detachEventSource = forwardZchainEvents(zchain);

  signClient.on('session_proposal', (p) => {
    handleProposal(p).catch((e) => rejectProposal(p?.id, 'capabilityProbeFailed', `proposal handling failed: ${e?.message ?? e}`));
  });
  signClient.on('session_request', handleRequest);
  signClient.on('session_delete', handleDelete);

  return {
    /** 解除 signClient 事件绑定（测试/停用用）。 */
    detach() {
      signClient.off?.('session_proposal', handleProposal);
      signClient.off?.('session_request', handleRequest);
      signClient.off?.('session_delete', handleDelete);
      detachEventSource();
    },
    /** topic → 会话记录（授予集/过期等；诊断与测试用）。 */
    sessions: sessionRecords,
    grantedMethodsOf: (topic) => sessionRecords.get(topic)?.methods ?? [],
  };
}
