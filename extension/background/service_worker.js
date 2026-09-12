// =============================================================================
// extension/background/service_worker.js — ZChain 钱包后台（Extension 0.1）
//
// 职责（plan-appchain §6.12.4）：
// 1. 内部 RPC 路由：页面消息（经 content bridge）→ 安全校验层 → wallet-core
//    WASM → 结构化响应；popup 消息（解锁/创建/批准/拒绝）→ 同一校验层。
// 2. 会话/锁屏状态机：解锁会话只存在于 SW 内存（SW 被回收即自动锁定——
//    fail-closed）；密文 keystore 落 chrome.storage.local；nonce 账本落
//    chrome.storage.session（浏览器会话内单调）。
// 3. 页面桥接校验：origin 绑定、nonce 防重放、expiry、sessionId、ABI/domain/
//    version、预览摘要绑定、取消/超时状态（全部委托 common/validation.js）。
//
// 日志纪律（WALLET-ACC-4）：只允许 logSafe()——字段白名单（method/requestId/
// code/origin 级状态）；任何参数、keystore、预览金额、口令、密钥材料一律不入
// 日志。见 extension/ACCEPTANCE.md。
// =============================================================================

import {
  checkEnvelope,
  grantOrigin,
  openPendingRequest,
  requiresExplicitConfirm,
  reject as vReject,
  sanitizeNotesForPage,
  sweepExpired,
  transitionRequest,
  validateRequest,
} from '../common/validation.js';
import { callCore, initWalletCore } from '../common/wallet_core.js';
import { initAdapters } from '../adapters/index.js';

// ---------------------------------------------------------------------------
// 状态（SW 内存态 = 可丢失态；丢失即锁定，安全方向单一）
// ---------------------------------------------------------------------------

const AUTO_LOCK_MS = 15 * 60 * 1000;
const PAGE_TIMEOUT_MS = 45_000;

const mem = {
  session: null,             // {id, expiresAt, locked:false} | null（null = 锁定）
  pending: {},               // requestId -> {state, payload, openedAt, expiresAt}
  pageWaiters: new Map(),    // requestId -> {resolve}
  lastActivity: 0,
};

const storage = {
  local: chrome.storage.local,
  session: chrome.storage.session,
};

async function getGrants() {
  const { grants } = await storage.local.get('grants');
  return grants ?? {};
}
async function setGrants(grants) {
  await storage.local.set({ grants });
}
async function getKeystore() {
  const { keystore } = await storage.local.get('keystore');
  return keystore ?? null;
}
async function setKeystore(keystore) {
  await storage.local.set({ keystore });
}
async function getNonceLedger() {
  const { nonceLedger } = await storage.session.get('nonceLedger');
  return nonceLedger ?? {};
}
async function setNonceLedger(nonceLedger) {
  await storage.session.set({ nonceLedger });
}

/** 会话句柄：unlock 后生成；页面消息的 sessionId 必须与之相等。 */
function newSession() {
  const s = {
    id: crypto.randomUUID(),
    // 会话自身有效期与自动锁屏对齐；超过即 SessionInvalid。
    expiresAt: Date.now() + AUTO_LOCK_MS,
    locked: false,
  };
  mem.session = s;
  mem.lastActivity = Date.now();
  return s;
}

function isUnlocked() {
  return mem.session != null && !mem.session.locked && Date.now() < mem.session.expiresAt;
}

// ---------------------------------------------------------------------------
// 日志（WALLET-ACC-4：字段白名单；永不输出 params/keystore/口令/密钥/预览内容）
// ---------------------------------------------------------------------------

function logSafe(event, fields = {}) {
  const allowed = ['requestId', 'method', 'code', 'origin', 'state', 'kind', 'count'];
  const picked = {};
  for (const k of allowed) {
    if (fields[k] !== undefined) picked[k] = fields[k];
  }
  console.info(JSON.stringify({ ts: new Date().toISOString(), event, ...picked }));
}

// ---------------------------------------------------------------------------
// 网络状态（0.1：固定 devnet；换网是 0.2）
// ---------------------------------------------------------------------------

function currentNetwork() {
  return { chainId: 'zchain-devnet-1', kind: 'devnet' };
}

function capabilities() {
  return {
    provider: 'zchain',
    providerVersion: '0.1.0',
    abiVersion: 1,
    networks: [currentNetwork().chainId],
    assetClasses: ['PLAY'],
    methods: [
      'zchain_requestAccounts', 'zchain_getNetwork', 'zchain_getCapabilities',
      'zchain_getAccounts', 'zchain_signOperation', 'zchain_signSettlement',
      'zchain_getNotes', 'zchain_lock',
    ],
    laterIterations: {
      '0.2': ['zchain_switchNetwork(多网络)', 'REAL/PLAY 隔离', 'zchain_verifyProof/watchProof（proof portal）', '备份恢复'],
      '0.3': ['zchain_authorizeSessionKey/revokeSessionKey', 'WalletConnect Vault adapter', '提现预览'],
      '0.4': ['account binding registry', '会话密钥限额/撤销'],
    },
  };
}

// ---------------------------------------------------------------------------
// 页面响应封装（稳定错误码 → provider 错误对象）
// ---------------------------------------------------------------------------

function pageError(code, reason) {
  return { error: { code, reason: reason ?? '' } };
}

// ---------------------------------------------------------------------------
// 签名执行（唯一入口走 wallet-core WASM；本文件零密码学）
// ---------------------------------------------------------------------------

/** 构造 wallet-core 的请求 JSON（页面形状 → core ABI 形状）。 */
function toCoreRequest(operation) {
  return JSON.stringify({
    kind: operation.kind,
    chain_id: operation.chainId,
    domain: operation.domain,
    abi_version: operation.abiVersion,
    nonce: String(operation.nonce),
    expiry: String(operation.expiry),
    asset_class: operation.assetClass,
    inputs: operation.inputs,
    outputs: operation.outputs ?? undefined,
    table_id: operation.tableId != null ? String(operation.tableId) : undefined,
    seat_owner: operation.seatOwner ?? undefined,
    policy_borsh: operation.policyBorsh ?? undefined,
    record_borsh: operation.recordBorsh ?? undefined,
  });
}

async function corePreview(coreReqJson) {
  return callCore('wallet_preview', coreReqJson, String(Math.floor(Date.now() / 1000)));
}

// ---------------------------------------------------------------------------
// 待签名请求生命周期（popup 批准/拒绝 + 超时）
// ---------------------------------------------------------------------------

async function openSignRequest(requestId, origin, method, params, preview) {
  const opened = openPendingRequest(
    mem.pending,
    requestId,
    { origin, method, params: { previewHash: params.previewHash ?? null }, preview },
    Date.now(),
  );
  if (!opened.ok) return opened;
  mem.pending = opened.store;
  updateBadge();
  logSafe('sign_request_opened', { requestId, method, origin });
  return opened;
}

function updateBadge() {
  const remaining = Object.values(mem.pending).filter((r) => r.state === 'pending').length;
  chrome.action.setBadgeText({ text: remaining > 0 ? String(remaining) : '' });
  chrome.action.setBadgeBackgroundColor({ color: '#c0392b' });
}

/** 等待 popup 决定；超时 → expired + RequestExpired。 */
function waitForDecision(requestId) {
  return new Promise((resolve) => {
    const timer = setTimeout(async () => {
      mem.pageWaiters.delete(requestId);
      const swept = sweepExpired(mem.pending, Date.now());
      mem.pending = swept.store;
      resolve({ ok: false, code: 'RequestExpired', reason: 'user did not respond in time' });
    }, PAGE_TIMEOUT_MS);
    mem.pageWaiters.set(requestId, {
      resolve: (tr) => {
        clearTimeout(timer);
        resolve(tr.ok ? tr : { ok: false, code: 'RequestExpired', reason: tr.reason });
      },
    });
  });
}

// ---------------------------------------------------------------------------
// 页面消息管线（content bridge → 这里）
// 返回 {response} 给 bridge 转发回页面。
// ---------------------------------------------------------------------------

async function handlePageMessage(msg, sender) {
  const now = Date.now();
  const senderOrigin = sender.origin ?? '';
  const requestId = msg?.envelope?.requestId;

  // ---- (1) 信封校验：伪造 origin / 重放 / 过期 / session 绑定 ----
  // requireGrant 仅对 zchain_requestAccounts 关闭：未授权 origin 必须能到达
  // 弹窗"显式确认"（批准后写入授权簿）；其余方法一律要求已授权。
  const state = { nonceLedger: await getNonceLedger(), session: mem.session };
  const requireGrant = msg?.method !== 'zchain_requestAccounts';
  const env = checkEnvelope(msg, senderOrigin, state, { now, grants: await getGrants(), requireGrant });
  if (!env.ok) {
    logSafe('page_rejected', { code: env.code, method: msg?.method, requestId });
    return pageError(env.code, env.reason);
  }
  await setNonceLedger(env.nextState.nonceLedger);
  mem.lastActivity = now;

  // ---- (2) 请求结构校验：未知 method / 缺参 / 金额 / 网络 / ABI / domain ----
  const vr = validateRequest(msg.method, msg.params ?? {}, { network: currentNetwork() });
  if (!vr.ok) {
    logSafe('page_rejected', { code: vr.code, method: msg.method, requestId });
    return pageError(vr.code, vr.reason);
  }

  // ---- (3) 路由 ----
  try {
    return await routePageMethod(msg, senderOrigin, requestId);
  } catch (e) {
    const code = e?.code ?? 'InternalError';
    logSafe('page_method_error', { code, method: msg.method, requestId });
    return pageError(code, e?.detail ?? 'internal error');
  }
}

async function routePageMethod(msg, origin, requestId) {
  const method = msg.method;
  const params = msg.params ?? {};

  switch (method) {
    case 'zchain_requestAccounts': {
      // 首连：强制显式确认（popup）；批准后 origin 入授权簿。
      const decision = await openAndAwait({ requestId, origin, method, kind: 'connect' });
      if (!decision.ok) return pageError(decision.code, decision.reason);
      const grants = grantOrigin(origin, await getGrants(), Math.floor(Date.now() / 1000));
      await setGrants(grants);
      const ks = await getKeystore();
      const accounts = ks && isUnlocked() ? [await publicKeyHex()] : [];
      return { accounts, chainId: currentNetwork().chainId, granted: true };
    }
    case 'zchain_getNetwork':
      return { ...currentNetwork(), abiVersion: 1 };
    case 'zchain_getCapabilities':
      return capabilities();
    case 'zchain_getAccounts': {
      if (!isUnlocked()) return { accounts: [], locked: true };
      return { accounts: [await publicKeyHex()], locked: false };
    }
    case 'zchain_getNotes': {
      if (!isUnlocked()) return pageError('SessionInvalid', 'wallet locked');
      const notes = await callCore('wallet_get_notes');
      return { notes: sanitizeNotesForPage(notes.notes) }; // 脱敏输出（无 secret/nullifier）
    }
    case 'zchain_lock': {
      await lockWallet('page_request');
      return { locked: true };
    }
    case 'zchain_signOperation':
    case 'zchain_signSettlement': {
      return await handleSign(msg, origin, requestId);
    }
    default:
      // validateRequest 已过滤；这里兜底。
      return pageError('UnknownMethod', method);
  }
}

/** 签名管线：预览（真实 wallet-core 摘要）→ 显式确认 → 摘要绑定校验 → 签名。 */
async function handleSign(msg, origin, requestId) {
  if (!isUnlocked()) return pageError('SessionInvalid', 'wallet locked');

  const op = msg.params.operation ?? msg.params.settlement;
  // (a) 真实预览：wallet-core 计算结构化预览与确认摘要（不占用 nonce）。
  const previewRes = await corePreview(toCoreRequest(op));
  const preview = previewRes.preview;

  // (b) 显式确认判定（签名类恒为 true；维持纵深防御）。
  if (!requiresExplicitConfirm({ method: msg.method, params: msg.params, origin }, { grants: await getGrants(), network: currentNetwork() })) {
    return pageError('ExplicitConfirmRequired', 'signing requires explicit confirm');
  }

  // (c) 打开待签名请求并等待 popup 决定（批准/拒绝/超时）。
  const opened = await openSignRequest(requestId, origin, msg.method, msg.params, preview);
  if (!opened.ok) return pageError(opened.code, opened.reason);
  const decision = await waitForDecision(requestId);
  if (!decision.ok) {
    logSafe('sign_request_settled', { requestId, state: 'expired' });
    return pageError(decision.code, decision.reason);
  }
  if (decision.request.state !== 'approved') {
    logSafe('sign_request_settled', { requestId, state: decision.request.state });
    return pageError('UserRejected', 'user rejected the request');
  }

  // (d) 预览摘要绑定：页面传入的 previewHash 若非空，必须与 wallet-core
  //     重算一致（展示-签名一致性；不一致 → PreviewMismatch）。空值允许于
  //     0.1（dapp 侧摘要计算随 0.2 dapp SDK 交付），此时弹窗预览是唯一确认面。
  const claimed = String(msg.params.previewHash ?? '').trim().toLowerCase();
  if (claimed !== '' && claimed !== preview.digest.toLowerCase()) {
    logSafe('preview_mismatch', { requestId, method: msg.method });
    return pageError('PreviewMismatch', 'previewHash does not match wallet-computed digest');
  }

  // (e) 签名（owner 路径；占用 (chain, nonce)；全部 wallet-core 拒绝面生效）。
  const signed = await callCore('wallet_sign', toCoreRequest(op), String(Math.floor(Date.now() / 1000)));
  logSafe('operation_signed', { requestId, kind: preview.kind });
  // 持久化 note 库变化（密文）。
  try {
    const ks = await callCore('wallet_persist');
    await setKeystore(ks);
  } catch (e) {
    logSafe('persist_failed', { code: e.code ?? 'Unknown' });
  }
  return {
    digest: signed.digest,
    operationBorsh: signed.operation_borsh,
    preview: signed.preview,
  };
}

async function publicKeyHex() {
  const { publicKey } = await storage.session.get('publicKey');
  return publicKey ?? null;
}

/** 连接类请求：popup 内联确认（不走签名预览页）。 */
async function openAndAwait({ requestId, origin, method, kind }) {
  const opened = openPendingRequest(mem.pending, requestId, { origin, method, kind, preview: null }, Date.now());
  if (!opened.ok) return { ok: false, code: opened.code, reason: opened.reason };
  mem.pending = opened.store;
  chrome.action.setBadgeText({ text: '1' });
  const decisionPromise = new Promise((resolve) => {
    const timer = setTimeout(() => {
      mem.pageWaiters.delete(requestId);
      resolve({ ok: false, code: 'RequestExpired', reason: 'connect request timed out' });
    }, PAGE_TIMEOUT_MS);
    mem.pageWaiters.set(requestId, {
      resolve: (outcome) => {
        clearTimeout(timer);
        resolve(outcome);
      },
    });
  });
  const tr = await decisionPromise;
  updateBadge();
  return tr;
}

// ---------------------------------------------------------------------------
// 锁定（自动/手动/页面请求共用）
// ---------------------------------------------------------------------------

async function lockWallet(reason) {
  try {
    await callCore('wallet_lock');
  } catch {
    // 已锁定/未初始化：目标状态一致，继续清理。
  }
  mem.session = null;
  mem.pending = {};
  mem.pageWaiters.clear();
  await storage.session.remove(['publicKey']);
  chrome.action.setBadgeText({ text: '' });
  logSafe('wallet_locked', { reason });
}

// ---------------------------------------------------------------------------
// popup 内部 RPC
// ---------------------------------------------------------------------------

async function handlePopupMessage(m) {
  switch (m.type) {
    case 'bridge:getSession': {
      // content bridge 专用：只下发会话令牌与公开状态（无密钥/无 note 明文）。
      // 锁定后令牌为 null（页面旧令牌全部失效）；签名类操作另需解锁态。
      return { sessionId: mem.session?.id ?? null, unlocked: isUnlocked(), chainId: currentNetwork().chainId };
    }
    case 'popup:getState': {
      const ks = await getKeystore();
      const grants = await getGrants();
      return {
        hasKeystore: ks != null,
        unlocked: isUnlocked(),
        publicKey: isUnlocked() ? (await storage.session.get('publicKey')).publicKey ?? null : null,
        chainId: currentNetwork().chainId,
        networkKind: currentNetwork().kind,
        grantedOrigins: Object.keys(grants),
        pending: pendingSummaries(),
      };
    }
    case 'popup:create': {
      const res = await callCore('wallet_create', m.password, 'interactive');
      await setKeystore({ version: 1, chain_id: res.keystore.chain_id, owner_envelope: res.keystore.owner_envelope, dek_envelope: res.keystore.dek_envelope, play_store: res.keystore.play_store });
      newSession();
      await storage.session.set({ publicKey: res.public_key });
      logSafe('wallet_created');
      return { publicKey: res.public_key, chainId: res.keystore.chain_id };
    }
    case 'popup:unlock': {
      const ks = await getKeystore();
      if (!ks) return { error: { code: 'NoKeystore', reason: 'create a wallet first' } };
      const res = await callCore('wallet_unlock', JSON.stringify(ks), m.password);
      newSession();
      await storage.session.set({ publicKey: res.public_key });
      logSafe('wallet_unlocked');
      return { publicKey: res.public_key, chainId: res.chain_id, playFree: res.play_free, notes: res.notes };
    }
    case 'popup:lock':
      await lockWallet('popup');
      return { locked: true };
    case 'popup:faucet': {
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const res = await callCore('wallet_faucet_play', String(m.amount));
      const ksNow = await callCore('wallet_persist');
      await setKeystore((await getKeystore()) ? { ...(await getKeystore()), play_store: ksNow.play_store } : ksNow);
      logSafe('devnet_faucet_issued');
      return res;
    }
    case 'popup:getNotes': {
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const notes = await callCore('wallet_get_notes');
      return { notes: sanitizeNotesForPage(notes.notes) };
    }
    case 'popup:listPending':
      return { pending: pendingSummaries() };
    case 'popup:adapters':
      // 适配器状态自省（无密钥/无参数级信息；WC 未注入 SignClient 时如实报 dormant）。
      return { status: adapterHost.status(), config: adapterHost.config };
    case 'popup:setAdapterConfig': {
      // 开关持久化；适配器装载发生在 SW 启动，故改动在下次 SW 启动生效（如实回执）。
      const merged = { ...adapterHost.config, ...(m.config ?? {}) };
      await setAdapterConfig(merged);
      return { saved: true, appliesOn: 'next service worker start', config: merged };
    }
    case 'popup:approve':
    case 'popup:reject': {
      const decision = m.type === 'popup:approve' ? 'approved' : 'rejected';
      const tr = transitionRequest(mem.pending, m.requestId, decision, Date.now());
      if (!tr.ok) return { error: { code: tr.code, reason: tr.reason } };
      mem.pending = tr.store;
      const waiter = mem.pageWaiters.get(m.requestId);
      if (waiter) {
        // 连接类（无 preview）与签名类（handleSign 的 waitForDecision）统一唤醒。
        mem.pageWaiters.delete(m.requestId);
        waiter.resolve({ ok: true, request: tr.request });
      }
      logSafe('popup_decided', { requestId: m.requestId, state: decision });
      return { ok: true };
    }
    default:
      return { error: { code: 'UnknownPopupMessage', reason: m.type ?? '' } };
  }
}

function pendingSummaries() {
  return Object.entries(mem.pending)
    .filter(([, r]) => r.state === 'pending')
    .map(([requestId, r]) => ({
      requestId,
      origin: r.payload.origin,
      method: r.payload.method,
      kind: r.payload.kind ?? 'sign',
      preview: r.payload.preview,
      expiresAt: r.expiresAt,
    }));
}

// ---------------------------------------------------------------------------
// 连接协议适配器（M6"钱包连接协议"；adapters/README.md 有架构说明）
//
// - EIP-1193 shim：只读 eth_* 子集是硬编码（shared.js 白名单，无开关）；
//   provider 实例由页面侧/宿主经 adapters.createEip1193() 创建。
// - WalletConnect v2：**需外部注入 SignClient 才激活**（默认 dormant，不挂
//   任何会话事件）；生产注入点 = globalThis.__zchainInjectedSignClient
//   （真实 @walletconnect/sign-client 实例，见 adapters/README.md 生产接入）。
// - Starknet 接口：仅服务 SNIP-12 授权委托（popup 0.3 接入），注册面在此。
// 所有经适配器到达签名管线的请求仍走 handleSign → popup 显式确认 →
// wallet-core 全拒绝面（WC/适配层不新增任何绕过路径）；页面侧请求来源
// （inpage → bridge）照旧过 origin/nonce/expiry/sessionId 校验。
// ---------------------------------------------------------------------------

async function getAdapterConfig() {
  const { adapterConfig } = await storage.local.get('adapterConfig');
  return adapterConfig ?? {};
}

async function setAdapterConfig(cfg) {
  await storage.local.set({ adapterConfig: cfg });
}

/** WC/适配器签名的弹出确认仍复用签名管线（origin 标记为 adapter 来源）。 */
async function adapterSign(method, params) {
  const requestId = `adapter-${crypto.randomUUID()}`;
  const decision = await handleSign({ method, params }, 'adapter:walletconnect', requestId);
  if (decision?.error) {
    const e = new Error(`${decision.error.code}: ${decision.error.reason}`);
    e.code = decision.error.code;
    throw e;
  }
  return decision;
}

/** 适配器用的 zchain provider 面（与 inpage provider 方法面一致；后台门面）。 */
function adapterCoreProvider() {
  return {
    requestAccounts: async () => {
      // 首连确认走页面 provider（envelope 门控）；后台门面不提供该路由。
      const e = new Error('RouteUnavailable: requestAccounts must go through the page provider');
      e.code = 'RouteUnavailable';
      throw e;
    },
    getNetwork: async () => ({ ...currentNetwork(), abiVersion: 1 }),
    getCapabilities: async () => capabilities(),
    getAccounts: async () => {
      if (!isUnlocked()) return { accounts: [], locked: true };
      return { accounts: [await publicKeyHex()], locked: false };
    },
    signOperation: async (operation, previewHash) => adapterSign('zchain_signOperation', { operation, previewHash }),
    signSettlement: async (settlement, previewHash) => adapterSign('zchain_signSettlement', { settlement, previewHash }),
    getNotes: async (filter) => {
      if (!isUnlocked()) {
        const e = new Error('SessionInvalid: wallet locked');
        e.code = 'SessionInvalid';
        throw e;
      }
      const notes = await callCore('wallet_get_notes');
      let list = sanitizeNotesForPage(notes.notes);
      if (filter && typeof filter === 'object' && typeof filter.spendable === 'boolean') {
        list = list.filter((n) => n.spendable === filter.spendable);
      }
      return list;
    },
    lock: () => lockWallet('adapter'),
  };
}

const adapterHost = initAdapters({
  config: {},
  zchain: adapterCoreProvider(),
  // 生产注入点：把真实 SignClient 赋到 globalThis.__zchainInjectedSignClient
  // （由打包的 WC 入口在 SW 启动早期注入；缺省即 dormant）。
  signClient: globalThis.__zchainInjectedSignClient ?? null,
  log: (event, fields) => logSafe(event, fields),
});

// ---------------------------------------------------------------------------
// 接线
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
  (async () => {
    await initWalletCore();
    // 页面通道：只接受有 tab 的 sender（content script）；origin 由浏览器固定。
    if (sender.tab && sender.origin?.startsWith('http')) {
      // 桥握手（bridge:getSession）走内部处理器：只下发会话令牌，非页面 RPC。
      if (typeof m?.type === 'string' && m.type.startsWith('bridge:')) {
        sendResponse(await handlePopupMessage(m));
        return;
      }
      const response = await handlePageMessage(m, sender);
      sendResponse(response);
      return;
    }
    // 扩展内部通道（popup/options）：仅扩展自身页面（sender.id === 扩展 id）。
    if (sender.id === chrome.runtime.id) {
      sendResponse(await handlePopupMessage(m));
      return;
    }
    sendResponse(pageError('Forbidden', 'unknown sender'));
  })().catch((e) => {
    logSafe('listener_error', { code: e?.code ?? 'InternalError' });
    sendResponse(pageError(e?.code ?? 'InternalError', e?.detail ?? 'internal'));
  });
  return true; // async sendResponse
});

// 自动锁屏心跳（alarms 是 0.1 唯一使用的周期任务）。
chrome.alarms.create('zchain.autolock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== 'zchain.autolock') return;
  // 清扫过期请求（超时 → expired，页面侧收到 RequestExpired）。
  const swept = sweepExpired(mem.pending, Date.now());
  mem.pending = swept.store;
  if (isUnlocked() && Date.now() - mem.lastActivity > AUTO_LOCK_MS) {
    lockWallet('autolock');
  }
});

chrome.runtime.onInstalled.addListener(() => {
  logSafe('installed', { kind: 'extension-0.1' });
});
