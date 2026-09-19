// =============================================================================
// extension/background/service_worker.js — ZChain 钱包后台（Extension 0.4）
//
// 0.2 交付（plan §6.12.4 表行：testnet、多账户、REAL/PLAY 隔离、proof portal、
// 备份恢复、网络切换）：
// 1. 内部 RPC 路由：页面消息（经 content bridge）→ 安全校验层 → wallet-core
//    WASM → 结构化响应；popup 消息（解锁/创建/批准/拒绝/换网/备份/回执）→
//    同一校验层。
// 2. 会话/锁屏状态机：解锁会话只存在于 SW 内存（SW 被回收即自动锁定——
//    fail-closed）；密文 keystore 落 chrome.storage.local；nonce 账本落
//    chrome.storage.session。**wasm 会话是单槽**：同一时刻至多一个账户处于
//    解锁态；锁定/切换当前账户不影响其他账户（它们本来就是密文态，无共享
//    解锁状态可被影响）。
// 3. 多账户账本（common/accounts.js）：每账户独立保存 {keystore 密文，
//    origin 授权簿，网络选择}（§6.12.4 "每个 origin 的权限、网络和账户选择
//    单独保存"）；0.1 单账户首次启动时无损迁移。
// 4. 网络切换（common/networks.js）：zchain_switchNetwork 完整语义——目标
//    必须在注册表内（mainnet 刻意不注册，红线），异网切换必须弹窗二次确认，
//    确认后持久化到**当前账户**；chain_id 参与签名摘要域由 wallet-core 保证
//    （operation_signer::preview_digest 绑定 chain_id）。
// 5. 交易回执（common/receipts.js）：签名成功后登记 inclusion 状态位
//    （signed → seen → included；超协议 deadline 提示 ForceInclude——仅展示
//    协议状态，不实现提交路径）。
// 6. 备份恢复：经 wallet-core backup（ZCBK v1）导出/导入，错口令/篡改文件
//    fail-closed。
//
// 0.3 交付（本轮）：
// 7. SNIP-12 会话密钥授权（popup"会话密钥"页）：delegated key 生成走
//    wallet-core（`wallet_session_key_create`，私钥只活在 wasm 会话）；授权
//    请求草稿与 SNIP-12 规范校验复用 adapters/starknet.js；授权确认页展示
//    wallet-core `wallet_snip12_authorize_digest` 计算的 SNIP-12 摘要；
//    devnet 入口形态 = 扩展侧登记约束记录（链侧 admission 登记未接，evidence
//    如实标注）；撤销粘滞。
// 8. REAL 提现预览（展示态）：common/withdraw_preview.js 逐字段预览 +
//    finality 聚合；canSubmit 恒 false（wallet-core 展示门 + finality 合取），
//    不开放真实提现提交。
//
// 0.4 交付（本轮）：
// 9. 授权簿/registry（popup 授权簿页）：origin 授权的列出/撤销；会话密钥
//    列表（scope/限额/桌白名单/到期/撤销）；撤销后签名路径 fail-closed。
// 10. 单笔/每日限额执行：origin 有 governing binding 时，签名请求先过 JS 层
//     准入（common/sessions.js，与 wallet-core session_admission 同序）再过
//     wallet-core wasm（`wallet_session_admit`）——wasm/JS 双层 fail-closed；
//     签名成功后记账日限聚合（recordSpend）。
// 11. capability matrix（common/capability_matrix.js）：EIP-1193/WC/Starknet
//     能力探测结果的结构化展示。
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
  revokeOrigin as revokeOriginGrant,
  sanitizeNotesForPage,
  sweepExpired,
  transitionRequest,
  validateRequest,
} from '../common/validation.js';
import { callCore, initWalletCore } from '../common/wallet_core.js';
import {
  DEFAULT_NETWORK_ID,
  canonicalHttpUrl,
  effectiveGatewayUrl,
  resolveNetwork,
} from '../common/networks.js';
import {
  activeAccount,
  createAccount,
  emptyLedger,
  migrateLegacySingle,
  selectAccount,
  setAccountGrants,
  setAccountNetwork,
} from '../common/accounts.js';
import {
  applySeenReceipt,
  inclusionView,
  markIncluded,
  openReceipt,
  pendingSpendMap,
} from '../common/receipts.js';
import {
  admitOperation,
  bindingView,
  deleteBinding,
  draftAuthorization,
  emptyBindingStore,
  governingBinding,
  recordSpend,
  revokeBinding,
  upsertBinding,
  validateDraft,
} from '../common/sessions.js';
import { buildAuthorizeTypedData } from '../adapters/starknet.js';
import { buildWithdrawPreview } from '../common/withdraw_preview.js';
import { buildTransferPreview, minProofForNetwork, verifySpendProofs } from '../common/transfer_preview.js';
import { buildCapabilityMatrix, detectExternalWallets } from '../common/capability_matrix.js';
import { initAdapters } from '../adapters/index.js';
// ---------------------------------------------------------------------------
// Extension 0.5：EVM 兼容账户层（余额查询 / 合约调用 / 交易记录 / 钱包管理）
// 密码学与编解码在 common/evm/*（标准向量钉住）；本文件只做状态机与编排。
// ---------------------------------------------------------------------------
import {
  bytesToHex, toChecksumAddress, isAddress, parseUnits, formatUnits, hexToBytes,
  signLegacyTransaction,
} from '../common/evm/crypto.js';
import {
  createKeystore, encryptToKeystore, decryptFromKeystore, changeKeystorePassword,
  parsePrivateKeyHex, addressFromPrivateKey,
} from '../common/evm/keystore.js';
import {
  EVM_NETWORKS, DEFAULT_EVM_NETWORK_ID, resolveEvmNetwork, effectiveRpcUrl,
  effectiveExplorerApi, evmNetworkView,
  canonicalHttpUrl as canonicalEvmUrl,
} from '../common/evm/networks.js';
import { JsonRpcClient, hexQtyToBigInt } from '../common/evm/rpc.js';
import { parseAbi, ABI_PRESETS, readContract, buildWriteIntent, presentDecoded } from '../common/evm/contracts.js';
import { emptyTxStore, addPendingTx, applyReceipt, txListView, pendingHashes } from '../common/evm/txs.js';
import { mergeHistory, fetchExplorerHistory, normalizeExplorerRow } from '../common/evm/history.js';
import { formatUnits as formatEvmUnits } from '../common/evm/crypto.js';
// ---------------------------------------------------------------------------
// Extension 0.6：Starknet 账户层（STARK curve：余额/合约调用/交易记录/钱包管理）
// 密码学与编解码在 common/stark/*（公共向量钉住）；本文件只做状态机与编排。
// ---------------------------------------------------------------------------
import {
  hexToBigInt, bigIntToHex, decodeShortString, starknetSelector,
  toChecksumAddress as starkChecksum, privateKeyToPublicKey,
} from '../common/stark/curve.js';
import {
  createStarkAccount, decryptFromKeystore as decryptStarkKeystore,
  changeKeystorePassword as changeStarkKeystorePassword, parsePrivateKeyHex as parseStarkPrivateKey,
  deriveAccount, generateSalt as generateStarkSalt, encryptToKeystore as encryptStarkKeystore,
} from '../common/stark/account.js';
import {
  STARKNET_NETWORKS, DEFAULT_STARKNET_NETWORK_ID, resolveStarknetNetwork,
  effectiveRpcUrl as effectiveStarkRpcUrl, starknetNetworkView, canonicalHttpUrl as canonicalStarkUrl,
} from '../common/stark/networks.js';
import { StarknetRpc } from '../common/stark/rpc.js';
import { signInvoke, amountToFelts, feltsToAmount, buildInvokeCalldata } from '../common/stark/invoke.js';
import { emptyTxStore as emptyStkTxStore, addPendingTx as addStkPendingTx, applyReceipt as applyStkReceipt,
  txListView as stkTxListView, pendingHashes as stkPendingHashes, mergeHistory as mergeStkHistory } from '../common/stark/txs.js';

// ---------------------------------------------------------------------------
// 状态（SW 内存态 = 可丢失态；丢失即锁定，安全方向单一）
// ---------------------------------------------------------------------------

const AUTO_LOCK_MS = 15 * 60 * 1000;
const PAGE_TIMEOUT_MS = 45_000;
export const PROVIDER_VERSION = '0.4.0-alpha';

/** 钱包侧自发起签名的 nonce：Date.now() 口径 + 内存高水位（严格单调，防 nonce
 *  回退被 wallet-core 拒；跨 SW 生命周期由 wallet-core 账本自己守住）。 */
function nextTransferNonce() {
  return Math.max(Date.now(), (mem.transferNonce ?? 0) + 1);
}

const mem = {
  session: null,             // {id, accountId, expiresAt, locked:false} | null（null = 锁定）
  pending: {},               // requestId -> {state, payload, openedAt, expiresAt}
  pageWaiters: new Map(),    // requestId -> {resolve}
  lastActivity: 0,
  // Extension 0.5：EVM 会话（私钥只在 SW 内存；SW 回收即锁，fail-closed）
  evm: {
    session: null,           // {accountId, privateKey: Uint8Array, address}
    draft: null,             // 待确认交易（prepare → confirm 两步）
  },
  // Extension 0.6：Starknet 会话（同上 fail-closed；私钥为 felt bigint）
  stk: {
    session: null,           // {accountId, privateKey: bigint, address, pubKey}
    draft: null,             // 待确认 invoke（prepare → confirm 两步）
  },
  transferNonce: 0,          // 钱包侧自发起签名的 nonce 高水位（严格单调）
};

const storage = {
  local: chrome.storage.local,
  session: chrome.storage.session,
};

// ---------------------------------------------------------------------------
// 账本存储（多账户；0.1 单账户无损迁移）
// ---------------------------------------------------------------------------

async function getLedger() {
  const { ledger } = await storage.local.get('ledger');
  if (ledger && ledger.accounts) return ledger;
  // 迁移：0.1 的 `keystore`（+全局 `grants`）→ 首账户。
  const legacy = await storage.local.get(['keystore', 'grants', 'publicKey']);
  const migrated = migrateLegacySingle(emptyLedger(), legacy.keystore ? { ...legacy, chainId: undefined } : null, Date.now());
  if (migrated.migrated) {
    await storage.local.set({ ledger: migrated.ledger });
    await storage.local.remove(['keystore']);
    logSafe('ledger_migrated', { kind: 'single-to-multi' });
    return migrated.ledger;
  }
  return emptyLedger();
}

async function setLedger(ledger) {
  await storage.local.set({ ledger });
}

/** 当前选中账户（无 → null）。 */
async function getActiveAccount() {
  return activeAccount(await getLedger());
}

/** 当前解锁会话的账户 id（锁定 → null）。 */
function sessionAccountId() {
  return isUnlocked() ? mem.session.accountId : null;
}

async function getNonceLedger() {
  const { nonceLedger } = await storage.session.get('nonceLedger');
  return nonceLedger ?? {};
}
async function setNonceLedger(nonceLedger) {
  await storage.session.set({ nonceLedger });
}

/** 会话句柄：unlock 后生成；页面消息的 sessionId 必须与之相等。 */
function newSession(accountId) {
  const s = {
    id: crypto.randomUUID(),
    accountId,
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
// 网络状态（0.2：注册表 devnet/testnet；mainnet 刻意不注册——红线）
// 当前网络 = 当前账户的选择；无账户时缺省 devnet。
// ---------------------------------------------------------------------------

function currentNetwork(ledgerAccount) {
  const net = resolveNetwork(ledgerAccount?.networkId ?? DEFAULT_NETWORK_ID);
  return { chainId: net.chainId, kind: net.kind, label: net.label };
}

function capabilities(ledgerAccount) {
  const net = currentNetwork(ledgerAccount);
  return {
    provider: 'zchain',
    providerVersion: PROVIDER_VERSION,
    abiVersion: 1,
    networks: [DEFAULT_NETWORK_ID, 'zchain-testnet-1'],
    currentNetwork: net.chainId,
    assetClasses: ['PLAY'], // REAL：0.2 仅隔离展示，签名面关闭
    methods: [
      'zchain_requestAccounts', 'zchain_getNetwork', 'zchain_getCapabilities',
      'zchain_switchNetwork', 'zchain_getAccounts', 'zchain_signOperation',
      'zchain_signSettlement', 'zchain_getNotes', 'zchain_lock',
    ],
    laterIterations: {
      '0.3（已交付 popup 面）': ['SNIP-12 会话密钥授权（delegated key 生成/授权摘要/devnet 登记入口形态/撤销）', 'REAL 提现预览（展示态）'],
      '0.4（已交付）': ['授权簿/registry UI', '会话密钥撤销/限额 fail-closed 执行（wasm/JS 双层）', 'capability matrix'],
      '未交付（如实）': ['provider 授权方法面（zchain_authorizeSessionKey 随 dapp SDK）', 'WalletConnect 生产 relay（B5 外部依赖：projectId 注册）', '真实提现提交（Vault 未上线）'],
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

// 页面只读方法白名单（routePageMethod 的只读分支：无状态变更、无用户交互）。
// 说明：只读页面探活不得续期自动锁——已授权页面高频轮询廉价只读方法（如
// zchain_getNetwork）不能让明文会话（EVM/Starknet 私钥）无限存活、SW 无限
// 保活；这些方法照常处理，只是不刷新 lastActivity。popup 消息不受影响。
const PAGE_READ_ONLY_METHODS = new Set([
  'zchain_getNetwork',     // 网络/链 ID 查询
  'zchain_getCapabilities',// 能力矩阵查询
  'zchain_getAccounts',    // 会话/账户状态 getter
  'zchain_getNotes',       // note 列表查询（脱敏，无状态变更）
]);

async function handlePageMessage(msg, sender) {
  const now = Date.now();
  const senderOrigin = sender.origin ?? '';
  const requestId = msg?.envelope?.requestId;
  const account = await getActiveAccount();

  // ---- (1) 信封校验：伪造 origin / 重放 / 过期 / session 绑定 ----
  // requireGrant 仅对 zchain_requestAccounts 关闭：未授权 origin 必须能到达
  // 弹窗"显式确认"（批准后写入**当前账户**的授权簿）；其余方法一律要求已授权。
  const state = { nonceLedger: await getNonceLedger(), session: mem.session };
  const requireGrant = msg?.method !== 'zchain_requestAccounts';
  const env = checkEnvelope(msg, senderOrigin, state, { now, grants: account?.grants ?? {}, requireGrant });
  if (!env.ok) {
    logSafe('page_rejected', { code: env.code, method: msg?.method, requestId });
    return pageError(env.code, env.reason);
  }
  await setNonceLedger(env.nextState.nonceLedger);
  // 说明：只读页面探活不得续期自动锁（PAGE_READ_ONLY_METHODS 白名单跳过
  // lastActivity 刷新）；其余页面方法（首连/换网/签名，均伴随用户交互）仍续期。
  if (!PAGE_READ_ONLY_METHODS.has(msg.method)) {
    mem.lastActivity = now;
  }

  // ---- (2) 请求结构校验：未知 method / 缺参 / 金额 / 网络 / ABI / domain ----
  const vr = validateRequest(msg.method, msg.params ?? {}, { network: currentNetwork(account) });
  if (!vr.ok) {
    logSafe('page_rejected', { code: vr.code, method: msg.method, requestId });
    return pageError(vr.code, vr.reason);
  }

  // ---- (3) 路由 ----
  try {
    return await routePageMethod(msg, senderOrigin, requestId, account);
  } catch (e) {
    const code = e?.code ?? 'InternalError';
    logSafe('page_method_error', { code, method: msg.method, requestId });
    return pageError(code, e?.detail ?? 'internal error');
  }
}

async function routePageMethod(msg, origin, requestId, account) {
  const method = msg.method;
  const params = msg.params ?? {};

  switch (method) {
    case 'zchain_requestAccounts': {
      // 首连：强制显式确认（popup）；批准后 origin 入**当前账户**授权簿。
      const decision = await openAndAwait({ requestId, origin, method, kind: 'connect' });
      if (!decision.ok) return pageError(decision.code, decision.reason);
      const accountId = sessionAccountId() ?? account?.id;
      if (accountId) {
        const grants = grantOrigin(origin, account.grants ?? {}, Math.floor(Date.now() / 1000));
        const g = setAccountGrants(await getLedger(), accountId, grants);
        if (g.ok) await setLedger(g.ledger);
      }
      const accounts = account && isUnlocked() ? [await publicKeyHex()] : [];
      return { accounts, chainId: currentNetwork(account).chainId, granted: true };
    }
    case 'zchain_getNetwork':
      return { ...currentNetwork(account), abiVersion: 1 };
    case 'zchain_getCapabilities':
      return capabilities(account);
    case 'zchain_getAccounts': {
      if (!isUnlocked()) return { accounts: [], locked: true };
      return { accounts: [await publicKeyHex()], locked: false };
    }
    case 'zchain_getNotes': {
      if (!isUnlocked()) return pageError('SessionInvalid', 'wallet locked');
      // provider 面（dapp 可见）只出 PLAY note（脱敏）；REAL 侧数据仅在
      // 扩展 UI（popup）经内部通道展示——dapp 与 REAL 操作面无关。
      const notes = await callCore('wallet_get_notes');
      return { notes: sanitizeNotesForPage(notes.notes) }; // 脱敏输出（无 secret/nullifier）
    }
    case 'zchain_switchNetwork': {
      return await handleSwitchNetwork(msg, origin, requestId, account);
    }
    case 'zchain_lock': {
      await lockWallet('page_request');
      return { locked: true };
    }
    case 'zchain_signOperation':
    case 'zchain_signSettlement': {
      return await handleSign(msg, origin, requestId, account);
    }
    default:
      // validateRequest 已过滤；这里兜底。
      return pageError('UnknownMethod', method);
  }
}

/**
 * 换网（0.2 完整语义）：同网幂等 no-op；异网必须弹窗二次确认（显示
 * from → to），批准后持久化到**当前账户**（账户元数据网络隔离）。切换不
 * 改签名材料——chain_id 参与签名摘要域由 wallet-core 保证。
 */
async function handleSwitchNetwork(msg, origin, requestId, account) {
  const target = resolveNetwork(msg.params.chainId);
  const from = currentNetwork(account);
  if (target.chainId === from.chainId) {
    // 幂等：已是目标网络，无状态变化（无需确认）。
    return { ...target, abiVersion: 1, previousChainId: from.chainId, changed: false };
  }
  // 未解锁时禁止换网（换网要写入账户元数据；锁定态无"当前账户会话"概念，
  // 且不允许页面在锁定态推动状态变化）。
  if (!isUnlocked()) return pageError('SessionInvalid', 'wallet locked');
  const decision = await openAndAwait({
    requestId,
    origin,
    method: msg.method,
    kind: 'switch_network',
    preview: { fromChainId: from.chainId, fromKind: from.kind, toChainId: target.chainId, toKind: target.kind },
  });
  if (!decision.ok) return pageError(decision.code, decision.reason);
  const accountId = sessionAccountId();
  const res = setAccountNetwork(await getLedger(), accountId, target.chainId, Date.now());
  if (!res.ok) return pageError(res.code, res.reason);
  await setLedger(res.ledger);
  logSafe('network_switched', { kind: target.kind });
  return { ...target, abiVersion: 1, previousChainId: from.chainId, changed: true };
}

/** 签名管线：预览（真实 wallet-core 摘要）→ 显式确认 → 摘要绑定校验 → 签名。 */
async function handleSign(msg, origin, requestId, account) {
  if (!isUnlocked()) return pageError('SessionInvalid', 'wallet locked');

  const op = msg.params.operation ?? msg.params.settlement;
  // (a) 真实预览：wallet-core 计算结构化预览与确认摘要（不占用 nonce）。
  const previewRes = await corePreview(toCoreRequest(op));
  const preview = previewRes.preview;

  // (b) 显式确认判定（签名类恒为 true；维持纵深防御）。
  if (!requiresExplicitConfirm({ method: msg.method, params: msg.params, origin }, { grants: account.grants ?? {}, network: currentNetwork(account) })) {
    return pageError('ExplicitConfirmRequired', 'signing requires explicit confirm');
  }

  // (b2) 会话密钥约束执行（Extension 0.4）：origin 有 governing binding 时
  //      逐条强制（撤销粘滞 / 换网 / 时间窗 / scope / 桌白名单 / 单笔限额 /
  //      日限额；wasm/JS 双层，见 enforceSessionBinding）。金额口径 =
  //      预览 amount_in（限额从严方向）。拒在弹窗之前（fail fast）。
  const admission = await enforceSessionBinding(origin, preview, account);
  if (!admission.ok) return pageError(admission.code, admission.reason);

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
  //     重算一致（展示-签名一致性；不一致 → PreviewMismatch）。空值允许
  //     （dapp 侧摘要计算随 dapp SDK 交付），此时弹窗预览是唯一确认面。
  const claimed = String(msg.params.previewHash ?? '').trim().toLowerCase();
  if (claimed !== '' && claimed !== preview.digest.toLowerCase()) {
    logSafe('preview_mismatch', { requestId, method: msg.method });
    return pageError('PreviewMismatch', 'previewHash does not match wallet-computed digest');
  }

  // (e) 签名（owner 路径；占用 (chain, nonce)；全部 wallet-core 拒绝面生效）。
  //     chain_id 参与摘要域（wallet-core preview_digest），跨网重放必换摘要。
  const signed = await callCore('wallet_sign', toCoreRequest(op), String(Math.floor(Date.now() / 1000)));
  logSafe('operation_signed', { requestId, kind: preview.kind });
  // 持久化 note 库变化（密文）。
  try {
    await persistActiveKeystore();
  } catch (e) {
    logSafe('persist_failed', { code: e.code ?? 'Unknown' });
  }
  // (f) 回执登记（inclusion 状态位；仅展示协议状态——0.2 无提交路径）。
  await recordReceipt(signed.digest, preview.kind, currentNetwork(account).chainId);
  // (g) 会话密钥日限记账（Extension 0.4；governing binding 存在时把本笔
  //     amount_in 记入当日窗口——否则日限额永不累积）。
  if (admission.enforced) {
    const accountId = sessionAccountId() ?? account.id;
    const store = await getBindingStore(accountId);
    const spend = recordSpend(store, admission.binding.bindingId, String(preview.amount_in ?? '0'), Math.floor(Date.now() / 1000));
    if (spend.ok) await setBindingStore(accountId, spend.store);
    else logSafe('session_spend_record_failed', { code: spend.code });
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

/** 把当前 wasm 会话的密文快照写回账本中该账户的 keystore。 */
async function persistActiveKeystore() {
  const accountId = sessionAccountId();
  const ksNow = await callCore('wallet_persist');
  if (!accountId) return;
  const ledger = await getLedger();
  const account = ledger.accounts[accountId];
  if (!account) return;
  // wallet_persist 返回完整 keystore 形状（含 real_store）。
  const next = {
    ...ledger,
    accounts: { ...ledger.accounts, [accountId]: { ...account, keystore: ksNow } },
  };
  await setLedger(next);
}

// ---------------------------------------------------------------------------
// 交易回执（ForceInclude 展示面；common/receipts.js 状态机）
// ---------------------------------------------------------------------------

async function getReceipts() {
  const { receipts } = await storage.local.get('receipts');
  return receipts ?? {};
}

async function recordReceipt(digest, kind, chainId, inputs = []) {
  const store = await getReceipts();
  const r = openReceipt(store, { digest, kind, chainId, signedAtMs: Date.now(), inputs }, Date.now());
  if (!r.ok) return; // 重复 digest：幂等跳过（回执登记不影响签名结果）。
  await storage.local.set({ receipts: r.store });
}

// ---------------------------------------------------------------------------
// 会话密钥授权簿（Extension 0.3/0.4；common/sessions.js 纯逻辑）
// 存储：storage.local.sessionRegistry = { [accountId]: { [bindingId]: binding } }
// ---------------------------------------------------------------------------

async function getBindingStore(accountId) {
  if (!accountId) return emptyBindingStore();
  const { sessionRegistry } = await storage.local.get('sessionRegistry');
  return sessionRegistry?.[accountId] ?? emptyBindingStore();
}

async function setBindingStore(accountId, store) {
  if (!accountId) return;
  const { sessionRegistry } = await storage.local.get('sessionRegistry');
  await storage.local.set({ sessionRegistry: { ...(sessionRegistry ?? {}), [accountId]: store } });
}

/** 当前账户的授权簿视图（registry UI + E2E 消费；无密钥材料）。 */
async function registryView() {
  const ledger = await getLedger();
  const account = activeAccount(ledger);
  const nowSec = Math.floor(Date.now() / 1000);
  const store = await getBindingStore(account?.id);
  return {
    accountId: account?.id ?? null,
    chainId: currentNetwork(account).chainId,
    origins: Object.entries(account?.grants ?? {})
      .map(([origin, g]) => ({ origin, grantedAt: g?.grantedAt ?? null }))
      .sort((a, b) => (a.origin < b.origin ? -1 : 1)),
    sessionKeys: Object.values(store)
      .map((b) => bindingView(b, nowSec))
      .sort((a, b) => (b.registeredAt ?? 0) - (a.registeredAt ?? 0)),
  };
}

/**
 * 签名路径的会话密钥约束执行（Extension 0.4，wasm/JS 双层 fail-closed）。
 * origin 无 governing binding → 不约束（常规 owner 路径不变）；有 → 先过
 * JS 层（common/sessions.js，与 wallet-core session_admission 同序），再过
 * wallet-core wasm（`wallet_session_admit`，同一约束单实现的第二层）。
 *
 * @returns {{ok:true, enforced:boolean, binding?}} | {{ok:false, code, reason}}
 */
async function enforceSessionBinding(origin, preview, account) {
  const accountId = sessionAccountId() ?? account?.id;
  const nowSec = Math.floor(Date.now() / 1000);
  const chainId = currentNetwork(account).chainId;
  const store = await getBindingStore(accountId);
  const binding = governingBinding(store, origin, chainId, nowSec);
  if (!binding) return { ok: true, enforced: false };

  // (1) JS 第一层（稳定码面向 UI/测试；错误码 = Session* 族）。
  const op = {
    kind: preview.kind,
    tableId: preview.table_id ?? null,
    amountIn: String(preview.amount_in ?? '0'),
  };
  const js = admitOperation(binding, op, { chainId, nowSec });
  if (!js.ok) {
    logSafe('session_binding_rejected', { code: js.code, origin });
    return js;
  }
  // (2) wasm 第二层（wallet-core binding_admission；拒绝/异常一律 fail-closed）。
  const req = {
    scope: js.scope,
    table_id: op.tableId != null && /^[0-9]+$/.test(String(op.tableId)) ? Number(op.tableId) : null,
    amount: js.amount,
    chain_id: chainId,
  };
  let core;
  try {
    core = await callCore('wallet_session_admit', JSON.stringify(binding), JSON.stringify(req), String(nowSec));
  } catch (e) {
    logSafe('session_binding_core_error', { code: e.code ?? 'Unknown' });
    return { ok: false, code: 'SessionRejected', reason: `wallet-core admission unavailable（fail-closed）: ${e.code ?? ''}` };
  }
  if (core?.admitted !== true) {
    logSafe('session_binding_core_rejected', { code: core?.rejected_reason ?? 'Unknown' });
    return { ok: false, code: 'SessionRejected', reason: `wallet-core 准入拒绝：${core?.rejected_reason ?? 'unknown'}` };
  }
  return { ok: true, enforced: true, binding };
}

// ---------------------------------------------------------------------------
// 连接/换网类请求：popup 内联确认（不走签名预览页）。
// ---------------------------------------------------------------------------

async function openAndAwait({ requestId, origin, method, kind, preview = null }) {
  const opened = openPendingRequest(mem.pending, requestId, { origin, method, kind, preview }, Date.now());
  if (!opened.ok) return { ok: false, code: opened.code, reason: opened.reason };
  mem.pending = opened.store;
  updateBadge();
  const decisionPromise = new Promise((resolve) => {
    const timer = setTimeout(() => {
      mem.pageWaiters.delete(requestId);
      resolve({ ok: false, code: 'RequestExpired', reason: 'request timed out' });
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
// 锁定（自动/手动/页面请求共用；只影响当前会话，其他账户不受影响）
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
// Extension 0.5：EVM 兼容账户层
//
// 存储（chrome.storage.local，只存密文/公开量）：
//   evmVault    = { accounts: {id → {id,label,address,keystore,createdAt}},
//                   activeAccountId, networkId }
//   evmSettings = { rpcOverrides: {chainIdHex → url}, explorerOverrides: {...} }
//   evmTxStores = { accountId → tx store（本地交易记录） }
// 内存：mem.evm.session = {accountId, privateKey, address}（锁定即毁）；
//       mem.evm.draft = 待确认交易（prepare → confirm 两步，60 秒过期）。
// 日志纪律同 WALLET-ACC-4：私钥/口令/签名材料一律不入日志。
// ---------------------------------------------------------------------------

const EVM_DRAFT_TTL_MS = 60_000;

async function getEvmVault() {
  const { evmVault } = await storage.local.get('evmVault');
  return evmVault ?? { accounts: {}, activeAccountId: null, networkId: DEFAULT_EVM_NETWORK_ID };
}

async function setEvmVault(vault) {
  await storage.local.set({ evmVault: vault });
}

async function getEvmSettings() {
  const { evmSettings } = await storage.local.get('evmSettings');
  return evmSettings ?? { rpcOverrides: {}, explorerOverrides: {} };
}

async function setEvmSettings(settings) {
  await storage.local.set({ evmSettings: settings });
}

async function getEvmTxStore(accountId) {
  if (!accountId) return emptyTxStore();
  const { evmTxStores } = await storage.local.get('evmTxStores');
  return evmTxStores?.[accountId] ?? emptyTxStore();
}

async function setEvmTxStore(accountId, store) {
  if (!accountId) return;
  const { evmTxStores } = await storage.local.get('evmTxStores');
  await storage.local.set({ evmTxStores: { ...(evmTxStores ?? {}), [accountId]: store } });
}

function evmUnlocked() {
  return mem.evm.session != null;
}

function evmActiveAccount(vault) {
  return vault.accounts[vault.activeAccountId] ?? null;
}

function lockEvm(reason) {
  mem.evm.session = null;
  mem.evm.draft = null;
  logSafe('evm_locked', { reason: reason ?? '' });
}

function evmError(code, reason) {
  return { error: { code, reason: reason ?? '' } };
}

/** 当前生效 EVM 网络 + 客户端（无账户/未配置 → 错误）。 */
function evmRpc(vault, settings) {
  const net = resolveEvmNetwork(vault.networkId ?? DEFAULT_EVM_NETWORK_ID);
  if (!net) return { error: evmError('NetworkUnsupported', String(vault.networkId)) };
  const url = effectiveRpcUrl(net, settings.rpcOverrides);
  if (!url) return { error: evmError('RpcNotConfigured', net.id) };
  return { net, rpc: new JsonRpcClient(url) };
}

/** 待确认交易回执对账（refresh/history 共用）。 */
async function reconcileEvmPending(rpc, accountId) {
  const store = await getEvmTxStore(accountId);
  const hashes = pendingHashes(store);
  let reconciled = 0;
  for (const hash of hashes) {
    try {
      const receipt = await rpc.getTransactionReceipt(hash);
      if (receipt && receipt.blockNumber != null) {
        const applied = applyReceipt(store, hash, receipt, Date.now());
        if (applied.ok) { await setEvmTxStore(accountId, applied.store); reconciled++; }
      }
    } catch { /* 单笔回执查询失败不阻塞其余 */ }
  }
  return reconciled;
}

/** 交易预览草稿（转账与合约写共用）：nonce/gas/余额校验 → mem.evm.draft。 */
async function evmPrepareAndDraft(vault, settings, account, { to, value, data, kind, methodLabel, decodedArgs }) {
  const env = evmRpc(vault, settings);
  if (env.error) return env.error;
  const { net, rpc } = env;
  if (!isAddress(String(to ?? ''))) return evmError('InvalidArgument', '收款/合约地址非法');
  let valueBig;
  try {
    valueBig = BigInt(value ?? '0');
  } catch {
    return evmError('InvalidArgument', '金额非法');
  }
  if (valueBig < 0n) return evmError('InvalidArgument', '金额不能为负');
  try {
    const [nonceHex, gasPriceHex, estimateHex] = await Promise.all([
      rpc.getTransactionCount(account.address),
      rpc.gasPrice(),
      rpc.estimateGas({ from: account.address, to, value: '0x' + valueBig.toString(16), data }),
    ]);
    const nonce = hexQtyToBigInt(nonceHex);
    const gasPrice = hexQtyToBigInt(gasPriceHex);
    let gasLimit = hexQtyToBigInt(estimateHex);
    if (gasLimit < 21000n) gasLimit = 21000n;
    const maxFee = gasPrice * gasLimit;
    const balance = hexQtyToBigInt(await rpc.getBalance(account.address));
    if (balance < valueBig + maxFee) {
      return evmError('InsufficientFunds', `余额不足：需要 ${formatUnits(valueBig + maxFee)}，当前 ${formatUnits(balance)}（含 gas）`);
    }
    mem.evm.draft = {
      from: account.address, to: toChecksumAddress(to), value: valueBig.toString(),
      data, nonce: nonce.toString(), gasPrice: gasPrice.toString(), gasLimit: gasLimit.toString(),
      chainIdHex: net.chainIdHex, kind, methodLabel: methodLabel ?? null, decodedArgs: decodedArgs ?? null,
      createdAt: Date.now(),
    };
    return {
      preview: {
        from: account.address, to: toChecksumAddress(to),
        valueWei: valueBig.toString(), valueHuman: formatUnits(valueBig),
        data: data === '0x' ? null : data,
        nonce: nonce.toString(), gasPriceGwei: formatUnits(gasPrice, 9), gasLimit: gasLimit.toString(),
        maxFeeWei: maxFee.toString(), maxFeeHuman: formatUnits(maxFee),
        chainIdHex: net.chainIdHex, kind, methodLabel: methodLabel ?? null, decodedArgs: decodedArgs ?? null,
        balanceHuman: formatUnits(balance),
      },
    };
  } catch (e) {
    return evmError(e.code === 'RpcError' ? 'EstimateFailed' : (e.code ?? 'RpcError'), e.message);
  }
}

async function handleEvmMessage(m) {
  const vault = await getEvmVault();
  const settings = await getEvmSettings();
  const account = evmActiveAccount(vault);

  switch (m.type) {
    // ---- 状态 ----
    case 'popup:evmGetState': {
      const net = resolveEvmNetwork(vault.networkId ?? DEFAULT_EVM_NETWORK_ID);
      return {
        hasWallet: Object.keys(vault.accounts).length > 0,
        unlocked: evmUnlocked(),
        address: evmUnlocked() ? mem.evm.session.address : (account?.address ?? null),
        activeAccountId: vault.activeAccountId,
        networkId: net?.id ?? null,
        networks: EVM_NETWORKS.map((n) => evmNetworkView(n, settings.rpcOverrides, settings.explorerOverrides)),
        accounts: Object.values(vault.accounts)
          .map((a) => ({
            id: a.id, label: a.label, address: a.address, createdAt: a.createdAt,
            active: a.id === vault.activeAccountId,
            unlocked: evmUnlocked() && mem.evm.session?.accountId === a.id,
          }))
          .sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0)),
        presets: Object.entries(ABI_PRESETS).map(([id, p]) => ({ id, label: p.label })),
      };
    }

    // ---- 钱包管理 ----
    case 'popup:evmCreate': {
      if (typeof m.password !== 'string' || m.password.length < 8) {
        return evmError('InvalidArgument', '口令至少 8 字符');
      }
      const { keystore, address, privateKey } = await createKeystore(m.password);
      const id = crypto.randomUUID();
      const label = (typeof m.label === 'string' && m.label.trim()) || `EVM 账户 ${Object.keys(vault.accounts).length + 1}`;
      vault.accounts[id] = { id, label, address, keystore, createdAt: Date.now() };
      vault.activeAccountId = id;
      await setEvmVault(vault);
      mem.evm.session = { accountId: id, privateKey: hexToBytes(privateKey), address };
      logSafe('evm_wallet_created');
      return { accountId: id, address };
    }
    case 'popup:evmImportKey': {
      if (typeof m.password !== 'string' || m.password.length < 8) {
        return evmError('InvalidArgument', '口令至少 8 字符');
      }
      let priv;
      try {
        priv = parsePrivateKeyHex(m.privateKey);
      } catch (e) {
        return evmError(e.code ?? 'InvalidArgument', e.message);
      }
      const address = addressFromPrivateKey(priv);
      if (Object.values(vault.accounts).some((a) => a.address?.toLowerCase() === address.toLowerCase())) {
        return evmError('AccountExists', '该地址已存在');
      }
      const keystore = await encryptToKeystore(priv, m.password);
      const id = crypto.randomUUID();
      const label = (typeof m.label === 'string' && m.label.trim()) || `导入 ${address.slice(0, 6)}…`;
      vault.accounts[id] = { id, label, address, keystore, createdAt: Date.now() };
      vault.activeAccountId = id;
      await setEvmVault(vault);
      mem.evm.session = { accountId: id, privateKey: priv, address };
      logSafe('evm_wallet_imported');
      return { accountId: id, address };
    }
    case 'popup:evmUnlock': {
      const target = m.accountId ? vault.accounts[m.accountId] : account;
      if (!target) return evmError('NoKeystore', '先创建钱包');
      let priv;
      try {
        priv = await decryptFromKeystore(target.keystore, m.password);
      } catch (e) {
        return evmError(e.code ?? 'BadPassword', e.message);
      }
      vault.activeAccountId = target.id;
      await setEvmVault(vault);
      mem.evm.session = { accountId: target.id, privateKey: priv, address: target.address };
      logSafe('evm_unlocked');
      return { address: target.address };
    }
    case 'popup:evmLock':
      lockEvm('popup');
      return { locked: true };
    case 'popup:evmExportKey': {
      if (!evmUnlocked()) return evmError('SessionInvalid', '先解锁');
      let priv;
      try {
        priv = await decryptFromKeystore(account.keystore, m.password);
      } catch (e) {
        return evmError(e.code ?? 'BadPassword', e.message);
      }
      // 双校验：口令解出的私钥必须对应当前账户地址
      if (addressFromPrivateKey(priv).toLowerCase() !== account.address.toLowerCase()) {
        return evmError('BadKeystore', 'keystore 与账户不一致（fail-closed）');
      }
      logSafe('evm_key_exported');
      return { privateKey: bytesToHex(priv), address: account.address };
    }
    case 'popup:evmChangePassword': {
      if (typeof m.next !== 'string' || m.next.length < 8) {
        return evmError('InvalidArgument', '新口令至少 8 字符');
      }
      if (!account) return evmError('NoKeystore', '先创建钱包');
      let next;
      try {
        next = await changeKeystorePassword(account.keystore, m.current, m.next);
      } catch (e) {
        return evmError(e.code ?? 'BadPassword', e.message);
      }
      vault.accounts[account.id] = { ...account, keystore: next };
      await setEvmVault(vault);
      logSafe('evm_password_changed');
      return { ok: true };
    }
    case 'popup:evmSelectAccount': {
      if (!vault.accounts[m.accountId]) return evmError('NoAccount', '账户不存在');
      lockEvm('evm_account_switch');
      vault.activeAccountId = m.accountId;
      await setEvmVault(vault);
      return { activeAccountId: m.accountId, locked: true };
    }
    case 'popup:evmRemoveAccount': {
      if (!vault.accounts[m.accountId]) return evmError('NoAccount', '账户不存在');
      if (evmUnlocked() && mem.evm.session.accountId === m.accountId) lockEvm('evm_account_remove');
      delete vault.accounts[m.accountId];
      if (vault.activeAccountId === m.accountId) {
        vault.activeAccountId = Object.keys(vault.accounts)[0] ?? null;
      }
      await setEvmVault(vault);
      const { evmTxStores } = await storage.local.get('evmTxStores');
      if (evmTxStores?.[m.accountId]) {
        const next = { ...evmTxStores };
        delete next[m.accountId];
        await storage.local.set({ evmTxStores: next });
      }
      return { ok: true, activeAccountId: vault.activeAccountId };
    }
    case 'popup:evmSetLabel': {
      if (!account) return evmError('NoAccount', '账户不存在');
      const label = String(m.label ?? '').slice(0, 40);
      vault.accounts[account.id] = { ...account, label };
      await setEvmVault(vault);
      return { ok: true };
    }

    // ---- 网络 / RPC 设置 ----
    case 'popup:evmSetNetwork': {
      const net = resolveEvmNetwork(m.networkId);
      if (!net) return evmError('NetworkUnsupported', String(m.networkId));
      vault.networkId = net.id;
      await setEvmVault(vault);
      return { networkId: net.id, chainIdHex: net.chainIdHex };
    }
    case 'popup:evmSetRpc': {
      const net = resolveEvmNetwork(m.chainIdHex);
      if (!net) return evmError('NetworkUnsupported', String(m.chainIdHex));
      if (m.rpcUrl == null || m.rpcUrl === '') {
        delete settings.rpcOverrides[net.chainIdHex];
      } else {
        const canonical = canonicalEvmUrl(m.rpcUrl);
        if (!canonical) return evmError('InvalidArgument', 'RPC URL 必须是 http(s)');
        settings.rpcOverrides[net.chainIdHex] = canonical;
      }
      await setEvmSettings(settings);
      return { saved: true, rpcUrl: effectiveRpcUrl(net, settings.rpcOverrides) };
    }
    case 'popup:evmSetExplorer': {
      const net = resolveEvmNetwork(m.chainIdHex);
      if (!net) return evmError('NetworkUnsupported', String(m.chainIdHex));
      if (m.apiUrl == null || m.apiUrl === '') {
        delete settings.explorerOverrides[net.chainIdHex];
      } else {
        const canonical = canonicalEvmUrl(m.apiUrl);
        if (!canonical) return evmError('InvalidArgument', 'Explorer API URL 必须是 http(s)');
        settings.explorerOverrides[net.chainIdHex] = canonical;
      }
      await setEvmSettings(settings);
      return { saved: true, explorerApiUrl: effectiveExplorerApi(net, settings.explorerOverrides) };
    }

    // ---- 余额 / 链状态 ----
    case 'popup:evmRefresh': {
      if (!account) return evmError('NoAccount', '先创建钱包');
      const env = evmRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      try {
        const [actualHex, balanceHex, nonceHex, gasPriceHex] = await Promise.all([
          rpc.request('eth_chainId'), rpc.getBalance(account.address), rpc.getTransactionCount(account.address), rpc.gasPrice(),
        ]);
        const reconciled = await reconcileEvmPending(rpc, account.id);
        const actual = actualHex?.toLowerCase();
        return {
          chainIdHex: actual ?? null,
          chainIdMismatch: actual != null && actual !== net.chainIdHex,
          balanceWei: hexQtyToBigInt(balanceHex).toString(),
          balanceHuman: formatUnits(hexQtyToBigInt(balanceHex)),
          nonce: hexQtyToBigInt(nonceHex).toString(),
          gasPriceWei: hexQtyToBigInt(gasPriceHex).toString(),
          gasPriceGwei: formatUnits(hexQtyToBigInt(gasPriceHex), 9),
          rpcUrl: effectiveRpcUrl(net, settings.rpcOverrides),
          pendingReconciled: reconciled,
        };
      } catch (e) {
        return evmError(e.code ?? 'RpcError', e.message);
      }
    }

    // ---- 合约调用（只读 eth_call）----
    case 'popup:evmReadContract': {
      if (!account) return evmError('NoAccount', '先创建钱包');
      const env = evmRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      let fn;
      try {
        fn = resolveEvmFunction(m);
      } catch (e) {
        return evmError(e.code ?? 'InvalidArgument', e.message);
      }
      try {
        const res = await readContract({
          contract: m.contract, fn, args: m.args ?? [],
          callImpl: (tx) => rpc.call({ from: account.address, ...tx }),
        });
        // ERC-20 预设：金额类输出按 decimals 换算人类可读值（多一次只读调用）
        const decimalsByType = {};
        if (m.preset === 'erc20' && fn.outputTypes.some((t) => /^uint/.test(t))) {
          try {
            const decCall = await readContract({
              contract: m.contract, fn: parseAbi(ABI_PRESETS.erc20.abi).byName.decimals, args: [],
              callImpl: (tx) => rpc.call({ from: account.address, ...tx }),
            });
            const dec = Number(decCall.values[0]);
            if (Number.isInteger(dec) && dec >= 0 && dec <= 36) decimalsByType.uint256 = dec;
          } catch { /* decimals 不可用则只出 raw */ }
        }
        return {
          method: fn.name,
          signature: fn.signature,
          values: presentDecoded(fn, res.values, { decimalsByType }),
        };
      } catch (e) {
        return evmError(e.code ?? 'RpcError', e.message);
      }
    }

    // ---- 交易（prepare → confirm 两步）----
    case 'popup:evmPrepareTx': {
      if (!evmUnlocked()) return evmError('SessionInvalid', '先解锁');
      const env = evmRpc(vault, settings);
      if (env.error) return env.error;
      let to, value, data, kind, methodLabel, decodedArgs;
      if (m.intent) {
        ({ to, value, data, methodLabel, decodedArgs } = m.intent);
        kind = 'contract';
      } else {
        to = m.to;
        value = String(parseUnits(m.valueEth ?? '0'));
        data = typeof m.dataHex === 'string' && m.dataHex !== '' && m.dataHex !== '0x' ? m.dataHex : '0x';
        kind = data === '0x' ? 'transfer' : 'contract';
        methodLabel = kind === 'contract' ? 'raw calldata' : null;
        decodedArgs = null;
      }
      return evmPrepareAndDraft(vault, settings, account, { to, value, data, kind, methodLabel, decodedArgs });
    }
    case 'popup:evmPrepareContractTx': {
      if (!evmUnlocked()) return evmError('SessionInvalid', '先解锁');
      const env = evmRpc(vault, settings);
      if (env.error) return env.error;
      let fn;
      try {
        fn = resolveEvmFunction(m);
      } catch (e) {
        return evmError(e.code ?? 'InvalidArgument', e.message);
      }
      if (fn.view) return evmError('InvalidArgument', `${fn.name} 是只读方法，请用“读取”`);
      // ERC-20 预设的金额参数：先查 decimals，把人类可读金额换算到最小单位
      let tokenDecimals = null;
      if (m.preset === 'erc20' && fn.inputs.some((i) => /^uint\d*$/.test(i.type) && i.type !== 'uint8')) {
        try {
          const decRes = await readContract({
            contract: m.contract, fn: parseAbi(ABI_PRESETS.erc20.abi).byName.decimals, args: [],
            callImpl: (tx) => env.rpc.call({ from: account.address, ...tx }),
          });
          const dec = Number(decRes.values[0]);
          if (Number.isInteger(dec) && dec >= 0 && dec <= 36) tokenDecimals = dec;
        } catch { /* decimals 拿不到则按最小单位解释（UI 已提示） */ }
      }
      let intent;
      try {
        intent = buildWriteIntent(fn, m.args ?? [], { contract: m.contract, tokenDecimals });
      } catch (e) {
        return evmError(e.code ?? 'InvalidArgument', e.message);
      }
      return evmPrepareAndDraft(vault, settings, account, { ...intent, kind: 'contract' });
    }
    case 'popup:evmConfirmTx': {
      if (!evmUnlocked()) return evmError('SessionInvalid', '先解锁');
      const draft = mem.evm.draft;
      if (!draft) return evmError('NoDraft', '没有待确认交易');
      if (Date.now() - draft.createdAt > EVM_DRAFT_TTL_MS) {
        mem.evm.draft = null;
        return evmError('DraftExpired', '交易预览已过期，请重新发起');
      }
      const env = evmRpc(vault, settings);
      if (env.error) return env.error;
      const { rpc } = env;
      let signed;
      try {
        signed = signLegacyTransaction({
          nonce: draft.nonce, gasPrice: draft.gasPrice, gasLimit: draft.gasLimit,
          to: draft.to, value: draft.value, data: draft.data,
          chainId: BigInt(draft.chainIdHex),
        }, mem.evm.session.privateKey);
      } catch (e) {
        return evmError('SignFailed', e.message);
      }
      let hash;
      try {
        hash = await rpc.sendRawTransaction(signed.raw);
      } catch (e) {
        return evmError(e.code ?? 'RpcError', e.message);
      }
      mem.evm.draft = null;
      const added = addPendingTx(await getEvmTxStore(account.id), {
        hash, chainId: draft.chainIdHex, from: draft.from, to: draft.to,
        value: draft.value, data: draft.data, nonce: draft.nonce, gasPrice: draft.gasPrice,
        gasLimit: draft.gasLimit, kind: draft.kind, methodLabel: draft.methodLabel,
        decodedArgs: draft.decodedArgs,
      }, Date.now());
      if (added.ok) await setEvmTxStore(account.id, added.store);
      logSafe('evm_tx_broadcast');
      return { hash: hash.toLowerCase(), localHash: signed.hash, tx: added.entry ?? null };
    }
    case 'popup:evmRejectTx':
      mem.evm.draft = null;
      return { ok: true };

    // ---- 交易记录 ----
    case 'popup:evmHistory': {
      if (!account) return evmError('NoAccount', '先创建钱包');
      const env = evmRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      const reconciled = await reconcileEvmPending(rpc, account.id);
      const local = txListView(await getEvmTxStore(account.id));
      let explorerRows = [];
      let explorerNote = null;
      const explorerApi = effectiveExplorerApi(net, settings.explorerOverrides);
      if (m.includeExplorer && explorerApi) {
        const res = await fetchExplorerHistory({ apiUrl: explorerApi, address: account.address });
        if (res.ok) explorerRows = res.rows;
        else explorerNote = res.code;
      } else if (m.includeExplorer && !explorerApi) {
        explorerNote = 'ExplorerApiNotConfigured';
      }
      const merged = mergeHistory(local, explorerRows).map((t) => ({
        ...t,
        valueHuman: t.valueHuman ?? formatUnits(t.value ?? '0'),
        explorerUrl: net.explorerUrl ? `${net.explorerUrl}/tx/${t.hash}` : null,
      }));
      return { txs: merged, explorerNote, pendingReconciled: reconciled };
    }

    // ---- devnet 水龙头（仅支持水龙头的链）----
    case 'popup:evmFaucet': {
      if (!account) return evmError('NoAccount', '先创建钱包');
      const env = evmRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      if (!net.faucet) return evmError('FaucetUnsupported', `${net.name} 不提供水龙头`);
      let wei;
      try {
        wei = parseUnits(m.amountEth ?? '1');
      } catch {
        return evmError('InvalidArgument', '金额非法');
      }
      if (wei <= 0n) return evmError('InvalidArgument', '金额必须为正');
      try {
        await rpc.request('dev_faucet', [account.address, '0x' + wei.toString(16)]);
      } catch (e) {
        return evmError(e.code ?? 'RpcError', `水龙头失败：${e.message}`);
      }
      logSafe('evm_faucet_issued');
      return { ok: true, credited: wei.toString() };
    }

    default:
      return evmError('UnknownPopupMessage', m.type ?? '');
  }
}

/** 从消息解析函数条目：preset（erc20）或自定义 ABI JSON + 方法名。 */
function resolveEvmFunction(m) {
  if (m.preset) {
    const preset = ABI_PRESETS[m.preset];
    if (!preset) {
      const e = new Error('未知 ABI 预设');
      e.code = 'InvalidArgument';
      throw e;
    }
    const abi = parseAbi(preset.abi);
    const fn = abi.byName[String(m.method ?? '')];
    if (!fn) {
      const e = new Error(`预设中无方法 ${m.method}`);
      e.code = 'UnknownMethod';
      throw e;
    }
    return fn;
  }
  let abiJson;
  try {
    abiJson = typeof m.abiJson === 'string' ? JSON.parse(m.abiJson) : m.abiJson;
  } catch {
    const e = new Error('ABI JSON 解析失败');
    e.code = 'InvalidArgument';
    throw e;
  }
  const abi = parseAbi(abiJson);
  const fn = abi.byName[String(m.method ?? '')];
  if (!fn) {
    const e = new Error(`ABI 中无方法 ${m.method}`);
    e.code = 'UnknownMethod';
    throw e;
  }
  return fn;
}


// ---------------------------------------------------------------------------
// Extension 0.6：Starknet 账户层
//
// 存储（chrome.storage.local，只存密文/公开量）：
//   stkVault    = { accounts: {id → {id,label,address,pubKey,keystore,createdAt}},
//                   activeAccountId, networkId }
//   stkSettings = { rpcOverrides: {networkId → url}, explorerOverrides: {...} }
//   stkTxStores = { accountId → tx store }
// 内存：mem.stk.session = {accountId, privateKey: bigint, address}（锁定即毁）；
//       mem.stk.draft = 待确认 invoke（60 秒过期）。日志纪律同 WALLET-ACC-4。
// ---------------------------------------------------------------------------

const STK_DRAFT_TTL_MS = 60_000;

async function getStkVault() {
  const { stkVault } = await storage.local.get('stkVault');
  return stkVault ?? { accounts: {}, activeAccountId: null, networkId: DEFAULT_STARKNET_NETWORK_ID };
}

async function setStkVault(vault) {
  await storage.local.set({ stkVault: vault });
}

async function getStkSettings() {
  const { stkSettings } = await storage.local.get('stkSettings');
  return stkSettings ?? { rpcOverrides: {}, explorerOverrides: {} };
}

async function setStkSettings(settings) {
  await storage.local.set({ stkSettings: settings });
}

async function getStkTxStore(accountId) {
  if (!accountId) return emptyStkTxStore();
  const { stkTxStores } = await storage.local.get('stkTxStores');
  return stkTxStores?.[accountId] ?? emptyStkTxStore();
}

async function setStkTxStore(accountId, store) {
  if (!accountId) return;
  const { stkTxStores } = await storage.local.get('stkTxStores');
  await storage.local.set({ stkTxStores: { ...(stkTxStores ?? {}), [accountId]: store } });
}

function stkUnlocked() {
  return mem.stk?.session != null;
}

function stkActiveAccount(vault) {
  return vault.accounts[vault.activeAccountId] ?? null;
}

function lockStk(reason) {
  if (mem.stk) {
    mem.stk.session = null;
    mem.stk.draft = null;
  }
  logSafe('stk_locked', { reason: reason ?? '' });
}

function stkError(code, reason) {
  return { error: { code, reason: reason ?? '' } };
}

/** 一键创建用的强口令（24 位 base62，拒绝采样去偏差，~142 bit 熵；只在成功页显示一次）。 */
function generateStrongPassword() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  while (out.length < 24) {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (out.length >= 24) break;
      if (b >= 248) continue; // 248 = 62 * 4：拒绝采样消除模偏差
      out += alphabet[b % 62];
    }
  }
  return out;
}

function stkRpc(vault, settings) {
  const net = resolveStarknetNetwork(vault.networkId ?? DEFAULT_STARKNET_NETWORK_ID);
  if (!net) return { error: stkError('NetworkUnsupported', String(vault.networkId)) };
  const url = effectiveStarkRpcUrl(net, settings.rpcOverrides);
  if (!url) return { error: stkError('RpcNotConfigured', net.id) };
  return { net, rpc: new StarknetRpc(url) };
}

/** 待确认 invoke 回执对账。 */
async function reconcileStkPending(rpc, accountId) {
  const store = await getStkTxStore(accountId);
  const hashes = stkPendingHashes(store);
  let reconciled = 0;
  for (const hash of hashes) {
    try {
      const receipt = await rpc.getTransactionReceipt(hash);
      if (receipt && (receipt.block_number != null || receipt.execution_status)) {
        const applied = applyStkReceipt(store, hash, receipt, Date.now());
        if (applied.ok) { await setStkTxStore(accountId, applied.store); reconciled++; }
      }
    } catch { /* 单笔失败不阻塞 */ }
  }
  return reconciled;
}

/** ERC-20 形状 balanceOf（u256）→ {rawWei: bigint, human: string}。 */
async function stkTokenBalance(rpc, net, address) {
  const res = await rpc.call({
    contract_address: net.tokenAddress,
    entry_point_selector: bigIntToHex(starknetSelector('balance_of')),
    calldata: [bigIntToHex(hexToBigInt(address))],
  });
  const raw = hexToBigInt(res[0]) | (hexToBigInt(res[1] ?? '0x0') << 128n);
  return { rawWei: raw, human: formatEvmUnits(raw, net.tokenDecimals) };
}

async function handleStkMessage(m) {
  const vault = await getStkVault();
  const settings = await getStkSettings();
  const account = stkActiveAccount(vault);

  switch (m.type) {
    // ---- 状态 ----
    case 'popup:stkGetState': {
      const net = resolveStarknetNetwork(vault.networkId ?? DEFAULT_STARKNET_NETWORK_ID);
      return {
        hasWallet: Object.keys(vault.accounts).length > 0,
        unlocked: stkUnlocked(),
        address: stkUnlocked() ? mem.stk.session.address : (account?.address ?? null),
        activeAccountId: vault.activeAccountId,
        networkId: net?.id ?? null,
        networks: STARKNET_NETWORKS.map((n) => starknetNetworkView(n, settings.rpcOverrides)),
        accounts: Object.values(vault.accounts)
          .map((a) => ({
            id: a.id, label: a.label, address: a.address, pubKey: a.pubKey, createdAt: a.createdAt,
            active: a.id === vault.activeAccountId,
            unlocked: stkUnlocked() && mem.stk.session?.accountId === a.id,
          }))
          .sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0)),
      };
    }

    // ---- 钱包管理 ----
    case 'popup:stkCreate': {
      if (typeof m.password !== 'string' || m.password.length < 8) {
        return stkError('InvalidArgument', '口令至少 8 字符');
      }
      const net = resolveStarknetNetwork(vault.networkId ?? DEFAULT_STARKNET_NETWORK_ID);
      let created;
      try {
        created = await createStarkAccount(m.password, net.accountClassHash);
      } catch (e) {
        return stkError(e.code ?? 'WalletError', e.message);
      }
      const id = crypto.randomUUID();
      const label = (typeof m.label === 'string' && m.label.trim()) || `Starknet 账户 ${Object.keys(vault.accounts).length + 1}`;
      const displayAddress = starkChecksum(created.address);
      vault.accounts[id] = {
        id, label, address: displayAddress, pubKey: created.pubKey,
        keystore: created.keystore, createdAt: Date.now(),
      };
      vault.activeAccountId = id;
      await setStkVault(vault);
      mem.stk.session = {
        accountId: id, privateKey: hexToBigInt(created.privateKey),
        address: displayAddress, pubKey: created.pubKey,
      };
      logSafe('stk_wallet_created');
      return { accountId: id, address: displayAddress, pubKey: created.pubKey };
    }
    case 'popup:stkImportKey': {
      if (typeof m.password !== 'string' || m.password.length < 8) {
        return stkError('InvalidArgument', '口令至少 8 字符');
      }
      const net = resolveStarknetNetwork(vault.networkId ?? DEFAULT_STARKNET_NETWORK_ID);
      let priv;
      try {
        priv = parseStarkPrivateKey(m.privateKey);
      } catch (e) {
        return stkError(e.code ?? 'InvalidArgument', e.message);
      }
      // 随机盐 + 网络 class hash 推导地址；同地址重复导入拒绝
      const salt = generateStarkSalt();
      const { address, pubKey } = deriveAccount({ privKey: priv, salt, classHash: net.accountClassHash });
      const addressHex = bigIntToHex(address);
      if (Object.values(vault.accounts).some((a) => a.address?.toLowerCase() === addressHex.toLowerCase())) {
        return stkError('AccountExists', '该地址已存在');
      }
      const keystore = await encryptStarkKeystore(priv, {
        password: m.password, salt, classHash: hexToBigInt(net.accountClassHash),
      });
      const id = crypto.randomUUID();
      const label = (typeof m.label === 'string' && m.label.trim()) || `导入 ${addressHex.slice(0, 8)}…`;
      const displayAddress = starkChecksum(addressHex);
      vault.accounts[id] = { id, label, address: displayAddress, pubKey: bigIntToHex(pubKey), keystore, createdAt: Date.now() };
      vault.activeAccountId = id;
      await setStkVault(vault);
      mem.stk.session = { accountId: id, privateKey: priv, address: displayAddress, pubKey: bigIntToHex(pubKey) };
      logSafe('stk_wallet_imported');
      return { accountId: id, address: displayAddress };
    }
    case 'popup:stkUnlock': {
      const target = m.accountId ? vault.accounts[m.accountId] : account;
      if (!target) return stkError('NoKeystore', '先创建钱包');
      let priv;
      try {
        priv = await decryptStarkKeystore(target.keystore, m.password);
      } catch (e) {
        return stkError(e.code ?? 'BadPassword', e.message);
      }
      vault.activeAccountId = target.id;
      await setStkVault(vault);
      mem.stk.session = { accountId: target.id, privateKey: priv, address: target.address, pubKey: target.pubKey };
      logSafe('stk_unlocked');
      return { address: target.address };
    }
    case 'popup:stkLock':
      lockStk('popup');
      return { locked: true };
    case 'popup:stkExportKey': {
      if (!stkUnlocked()) return stkError('SessionInvalid', '先解锁');
      let priv;
      try {
        priv = await decryptStarkKeystore(account.keystore, m.password);
      } catch (e) {
        return stkError(e.code ?? 'BadPassword', e.message);
      }
      // 双校验：口令解出的私钥必须对应当前账户公钥
      if (privateKeyToPublicKey(priv) !== hexToBigInt(account.pubKey)) {
        return stkError('BadKeystore', 'keystore 与账户不一致（fail-closed）');
      }
      logSafe('stk_key_exported');
      return { privateKey: bigIntToHex(priv), address: account.address };
    }
    case 'popup:stkChangePassword': {
      if (typeof m.next !== 'string' || m.next.length < 8) {
        return stkError('InvalidArgument', '新口令至少 8 字符');
      }
      if (!account) return stkError('NoKeystore', '先创建钱包');
      let next;
      try {
        next = await changeStarkKeystorePassword(account.keystore, m.current, m.next);
      } catch (e) {
        return stkError(e.code ?? 'BadPassword', e.message);
      }
      vault.accounts[account.id] = { ...account, keystore: next };
      await setStkVault(vault);
      logSafe('stk_password_changed');
      return { ok: true };
    }
    case 'popup:stkSelectAccount': {
      if (!vault.accounts[m.accountId]) return stkError('NoAccount', '账户不存在');
      lockStk('stk_account_switch');
      vault.activeAccountId = m.accountId;
      await setStkVault(vault);
      return { activeAccountId: m.accountId, locked: true };
    }
    case 'popup:stkRemoveAccount': {
      if (!vault.accounts[m.accountId]) return stkError('NoAccount', '账户不存在');
      if (stkUnlocked() && mem.stk.session.accountId === m.accountId) lockStk('stk_account_remove');
      delete vault.accounts[m.accountId];
      if (vault.activeAccountId === m.accountId) {
        vault.activeAccountId = Object.keys(vault.accounts)[0] ?? null;
      }
      await setStkVault(vault);
      const { stkTxStores } = await storage.local.get('stkTxStores');
      if (stkTxStores?.[m.accountId]) {
        const next = { ...stkTxStores };
        delete next[m.accountId];
        await storage.local.set({ stkTxStores: next });
      }
      return { ok: true, activeAccountId: vault.activeAccountId };
    }

    // ---- 网络 / RPC ----
    case 'popup:stkSetNetwork': {
      const net = resolveStarknetNetwork(m.networkId);
      if (!net) return stkError('NetworkUnsupported', String(m.networkId));
      vault.networkId = net.id;
      await setStkVault(vault);
      return { networkId: net.id, chainId: net.chainId };
    }
    case 'popup:stkSetRpc': {
      const net = resolveStarknetNetwork(m.networkId);
      if (!net) return stkError('NetworkUnsupported', String(m.networkId));
      if (m.rpcUrl == null || m.rpcUrl === '') {
        delete settings.rpcOverrides[net.id];
      } else {
        const canonical = canonicalStarkUrl(m.rpcUrl);
        if (!canonical) return stkError('InvalidArgument', 'RPC URL 必须是 http(s)');
        settings.rpcOverrides[net.id] = canonical;
      }
      await setStkSettings(settings);
      return { saved: true, rpcUrl: effectiveStarkRpcUrl(net, settings.rpcOverrides) };
    }
    case 'popup:stkSetExplorer': {
      const net = resolveStarknetNetwork(m.networkId);
      if (!net) return stkError('NetworkUnsupported', String(m.networkId));
      if (m.apiUrl == null || m.apiUrl === '') {
        delete settings.explorerOverrides[net.id];
      } else {
        const canonical = canonicalStarkUrl(m.apiUrl);
        if (!canonical) return stkError('InvalidArgument', 'Explorer API URL 必须是 http(s)');
        settings.explorerOverrides[net.id] = canonical;
      }
      await setStkSettings(settings);
      return { saved: true };
    }

    // ---- 余额 / 链状态 ----
    case 'popup:stkRefresh': {
      if (!account) return stkError('NoAccount', '先创建钱包');
      const env = stkRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      try {
        const [chainIdAscii, nonceHex, balance] = await Promise.all([
          rpc.chainId(), rpc.getNonce(account.address), stkTokenBalance(rpc, net, account.address),
        ]);
        const reconciled = await reconcileStkPending(rpc, account.id);
        return {
          chainId: chainIdAscii,
          chainIdMismatch: chainIdAscii !== net.chainId,
          nonce: hexToBigInt(nonceHex).toString(),
          balanceWei: balance.rawWei.toString(),
          balanceHuman: balance.human,
          tokenSymbol: net.tokenSymbol,
          rpcUrl: effectiveStarkRpcUrl(net, settings.rpcOverrides),
          pendingReconciled: reconciled,
        };
      } catch (e) {
        return stkError(e.code ?? 'RpcError', e.message);
      }
    }

    // ---- 合约只读调用 ----
    case 'popup:stkReadContract': {
      if (!account) return stkError('NoAccount', '先创建钱包');
      const env = stkRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      try {
        let selector, calldata;
        if (m.preset === 'erc20') {
          const fn = String(m.method ?? '');
          const known = { name: 'name', symbol: 'symbol', decimals: 'decimals', totalSupply: 'total_supply', balanceOf: 'balance_of' }[fn];
          const netFn = { name: 'name', symbol: 'symbol', decimals: 'decimals', totalSupply: 'total_supply', balanceOf: 'balance_of' }[fn];
          void known;
          if (!netFn) return stkError('UnknownMethod', `预设中无方法 ${fn}`);
          selector = bigIntToHex(hexToBigInt(selectorFromName(netFn)));
          calldata = fn === 'balanceOf' ? [account.address] : [];
        } else {
          if (!m.selector && !m.functionName) return stkError('InvalidArgument', '需要 selector 或方法名');
          selector = m.selector ?? bigIntToHex(hexToBigInt(selectorFromName(m.functionName)));
          calldata = (m.calldata ?? []).map((c) => bigIntToHex(hexToBigInt(String(c).trim())));
        }
        const result = await rpc.call({
          contract_address: m.contract,
          entry_point_selector: selector,
          calldata,
        });
        return {
          selector,
          calldata,
          values: (result ?? []).map((f) => {
            const dec = decodeShortString(f);
            return /^0x/.test(dec) ? `${dec}（${hexToBigInt(f)}）` : dec;
          }),
          raw: result ?? [],
        };
      } catch (e) {
        return stkError(e.code ?? 'RpcError', e.message);
      }
    }

    // ---- 交易（prepare → confirm 两步）----
    case 'popup:stkPrepareTx': {
      if (!stkUnlocked()) return stkError('SessionInvalid', '先解锁');
      const env = stkRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      // 参数：preset erc20 transfer（人类可读金额）或自定义 selector + felt calldata
      let to, functionName, selector, calldata, methodLabel;
      try {
        if (m.preset === 'erc20') {
          if (m.method !== 'transfer' && m.method !== 'approve') {
            return stkError('UnknownMethod', `预设写方法仅支持 transfer/approve，收到 ${m.method}`);
          }
          // 金额预检（transfer）：amount ≤ 余额（回执前的 fail fast）
          if (m.method === 'transfer') {
            const balance = await stkTokenBalance(rpc, net, account.address);
            const [lo, hi] = amountToFelts(m.amountHuman ?? '0', net.tokenDecimals);
            const amountWei = hexToBigInt(lo) | (hexToBigInt(hi) << 128n);
            if (balance.rawWei < amountWei) {
              return stkError('InsufficientFunds', `余额不足：当前 ${balance.human} ${net.tokenSymbol}，转账 ${m.amountHuman} ${net.tokenSymbol}`);
            }
          }
          const amountArgs = amountToFelts(m.amountHuman ?? '0', net.tokenDecimals);
          to = net.tokenAddress;
          functionName = m.method === 'transfer' ? 'transfer' : 'approve';
          selector = bigIntToHex(hexToBigInt(selectorFromName(functionName)));
          calldata = m.method === 'transfer'
            ? [bigIntToHex(hexToBigInt(m.recipient)), ...amountArgs]
            : [bigIntToHex(hexToBigInt(m.recipient ?? m.spender)), ...amountArgs];
          methodLabel = `${functionName}(recipient, amount_u256)`;
        } else {
          to = m.to;
          selector = m.selector ?? bigIntToHex(hexToBigInt(selectorFromName(m.functionName)));
          calldata = (m.calldata ?? []).map((c) => bigIntToHex(hexToBigInt(String(c).trim())));
          methodLabel = m.functionName ?? 'raw invoke';
        }
      } catch (e) {
        return stkError(e.code ?? 'InvalidArgument', e.message);
      }
      if (hexToBigInt(to) === 0n) return stkError('InvalidArgument', '目标合约地址非法');
      try {
        const [nonceHex] = await Promise.all([rpc.getNonce(account.address)]);
        const nonce = hexToBigInt(nonceHex);
        const chainIdFelt = hexToBigInt(net.chainIdFelt);
        // 预估费用：dev 链走 dev_estimateFee；通用路径按保守 maxFee 由 RPC estimateFee 提供
        let maxFeeWei;
        try {
          const est = await rpc.request('starknet_estimateFee', [{
            invoke_v1: {
              max_fee: '0x0', signature: ['0x0', '0x0'], nonce: bigIntToHex(nonce),
              sender_address: account.address, calldata: buildInvokeCalldata({ to, entryPointSelector: selector, calldata }),
            },
          }, 'latest']);
          const overall = hexToBigInt(est?.overall_fee ?? '0x0');
          maxFeeWei = overall + overall / 10n; // +10% 缓冲
        } catch {
          maxFeeWei = 10n ** 15n; // 估算不可用时的保守上限（0.001 ETH）
        }
        const balance = await stkTokenBalance(rpc, net, account.address);
        if (balance.rawWei < maxFeeWei) {
          return stkError('InsufficientFunds', `余额不足以支付手续费：需要 ~${formatEvmUnits(maxFeeWei, net.tokenDecimals)} ${net.tokenSymbol}`);
        }
        mem.stk.draft = {
          to, selector, calldata, methodLabel: methodLabel ?? null,
          nonce: nonce.toString(), maxFeeWei: maxFeeWei.toString(),
          chainIdFelt: net.chainIdFelt, createdAt: Date.now(),
        };
        return {
          preview: {
            from: account.address, to,
            selector, methodLabel: methodLabel ?? null,
            calldata,
            nonce: nonce.toString(),
            maxFeeWei: maxFeeWei.toString(),
            maxFeeHuman: formatEvmUnits(maxFeeWei, net.tokenDecimals),
            chainId: net.chainId,
          },
        };
      } catch (e) {
        return stkError(e.code === 'RpcError' ? 'EstimateFailed' : (e.code ?? 'RpcError'), e.message);
      }
    }
    case 'popup:stkConfirmTx': {
      if (!stkUnlocked()) return stkError('SessionInvalid', '先解锁');
      const draft = mem.stk.draft;
      if (!draft) return stkError('NoDraft', '没有待确认交易');
      if (Date.now() - draft.createdAt > STK_DRAFT_TTL_MS) {
        mem.stk.draft = null;
        return stkError('DraftExpired', '交易预览已过期，请重新发起');
      }
      const env = stkRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      const nonce = hexToBigInt(draft.nonce);
      const signed = signInvoke({
        senderAddress: account.address,
        to: draft.to,
        entryPointSelector: draft.selector,
        calldata: draft.calldata,
        nonce,
        maxFee: hexToBigInt(draft.maxFeeWei),
        chainIdFelt: hexToBigInt(draft.chainIdFelt),
        privateKey: mem.stk.session.privateKey,
      });
      let addRes;
      try {
        addRes = await rpc.addInvokeTransaction({
          max_fee: signed.invocation.max_fee,
          signature: signed.invocation.signature,
          nonce: signed.invocation.nonce,
          sender_address: signed.invocation.sender_address,
          calldata: signed.invocation.calldata,
        });
      } catch (e) {
        return stkError(e.code ?? 'RpcError', e.message);
      }
      const txHash = addRes?.transaction_hash ?? signed.txHash;
      mem.stk.draft = null;
      const added = addStkPendingTx(await getStkTxStore(account.id), {
        hash: txHash, chainId: net.id, from: account.address, to: draft.to,
        selector: draft.selector, calldataLen: draft.calldata.length,
        kind: 'contract', methodLabel: draft.methodLabel, nonce: draft.nonce,
        maxFee: draft.maxFeeWei,
      }, Date.now());
      if (added.ok) await setStkTxStore(account.id, added.store);
      logSafe('stk_tx_broadcast');
      return { hash: txHash, localHash: signed.txHash, tx: added.entry ?? null };
    }
    case 'popup:stkRejectTx':
      mem.stk.draft = null;
      return { ok: true };

    // ---- 交易记录 ----
    case 'popup:stkHistory': {
      if (!account) return stkError('NoAccount', '先创建钱包');
      const env = stkRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      const reconciled = await reconcileStkPending(rpc, account.id);
      const local = stkTxListView(await getStkTxStore(account.id));
      let explorerRows = [];
      let explorerNote = null;
      const explorerApi = settings.explorerOverrides?.[net.id] ?? null;
      if (m.includeExplorer && explorerApi) {
        const res = await fetchExplorerHistory({ apiUrl: explorerApi, address: account.address });
        if (res.ok) explorerRows = res.rows;
        else explorerNote = res.code;
      } else if (m.includeExplorer && !explorerApi) {
        explorerNote = 'ExplorerApiNotConfigured';
      }
      const merged = mergeStkHistory(local, explorerRows).map((t) => ({
        ...t,
        explorerUrl: net.explorerUrl ? `${net.explorerUrl}/tx/${t.hash}` : null,
      }));
      return { txs: merged, explorerNote, pendingReconciled: reconciled };
    }

    // ---- devnet 水龙头（注册 pubkey + 出资）----
    case 'popup:stkFaucet': {
      if (!account) return stkError('NoAccount', '先创建钱包');
      const env = stkRpc(vault, settings);
      if (env.error) return env.error;
      const { net, rpc } = env;
      if (!net.faucet) return stkError('FaucetUnsupported', `${net.name} 不提供水龙头`);
      const amountHuman = String(m.amountHuman ?? '100');
      let wei;
      try {
        wei = BigInt(0) || (() => {
          const mm = /^(\d+)(?:\.(\d+))?$/.exec(amountHuman);
          if (!mm) throw new Error('x');
          const frac = (mm[2] ?? '').slice(0, net.tokenDecimals).padEnd(net.tokenDecimals, '0');
          return BigInt(mm[1]) * 10n ** BigInt(net.tokenDecimals) + (frac ? BigInt(frac) : 0n);
        })();
      } catch {
        return stkError('InvalidArgument', '金额非法');
      }
      try {
        await rpc.devFaucet(account.address, bigIntToHex(wei), account.pubKey);
      } catch (e) {
        return stkError(e.code ?? 'RpcError', `水龙头失败：${e.message}`);
      }
      logSafe('stk_faucet_issued');
      return { ok: true, credited: wei.toString() };
    }

    default:
      return stkError('UnknownPopupMessage', m.type ?? '');
  }
}

/** 方法名 → selector hex（curve.js starknetSelector 包装）。 */
function selectorFromName(name) {
  return bigIntToHex(starknetSelector(String(name)));
}


// ---------------------------------------------------------------------------
// popup 内部 RPC
// ---------------------------------------------------------------------------

async function handlePopupMessage(m, { page = false } = {}) {
  // 说明：只读页面探活不得续期自动锁——content bridge 的握手（bridge:*
  // 消息）虽走本内部处理器，但同样源自页面（无信封、可被任意页面高频
  // 触发），不得刷新 lastActivity；扩展自身页面（popup/options/portal）
  // 的消息始终续期（用户正在交互）。
  if (!page) mem.lastActivity = Date.now();
  if (typeof m?.type === 'string' && m.type.startsWith('popup:evm')) {
    return handleEvmMessage(m);
  }
  if (typeof m?.type === 'string' && m.type.startsWith('popup:stk')) {
    return handleStkMessage(m);
  }

  // ---------------------------------------------------------------------------
  // Extension 0.6.1：MetaMask 式一键 onboarding
  // ---------------------------------------------------------------------------
  if (m?.type === 'popup:overview') {
    const zLedger = await getLedger();
    const zActive = activeAccount(zLedger);
    const zHas = Object.keys(zLedger.accounts).length > 0;
    const evmV = await getEvmVault();
    const evmHas = Object.keys(evmV.accounts).length > 0;
    const stkV = await getStkVault();
    const stkHas = Object.keys(stkV.accounts).length > 0;
    return {
      onboarded: zHas || evmHas || stkHas,
      autoLockMs: AUTO_LOCK_MS,
      providerVersion: PROVIDER_VERSION,
      layers: {
        zchain: {
          has: zHas, unlocked: isUnlocked(),
          address: isUnlocked() ? (await publicKeyHex()) : (zActive?.publicKey ?? null),
          label: zActive?.label ?? null,
        },
        evm: {
          has: evmHas, unlocked: evmUnlocked(),
          address: evmUnlocked() ? mem.evm.session.address : (evmActiveAccount(evmV)?.address ?? null),
          label: evmActiveAccount(evmV)?.label ?? null,
        },
        stk: {
          has: stkHas, unlocked: stkUnlocked(),
          address: stkUnlocked() ? mem.stk.session.address : (stkActiveAccount(stkV)?.address ?? null),
          label: stkActiveAccount(stkV)?.label ?? null,
        },
      },
    };
  }
  if (m?.type === 'popup:quickCreate') {
    // 仅全新状态允许（任一层已有钱包 → OnboardedAlready，绝不覆盖既有钱包）
    const zLedger0 = await getLedger();
    const evmV0 = await getEvmVault();
    const stkV0 = await getStkVault();
    if (Object.keys(zLedger0.accounts).length > 0 || Object.keys(evmV0.accounts).length > 0 || Object.keys(stkV0.accounts).length > 0) {
      return stkError('OnboardedAlready', '已存在钱包：请用口令解锁，不会被一键创建覆盖');
    }
    // 口令：用户自定义（≥8）或自动生成强口令（成功页只显示一次；不落任何存储）
    const custom = typeof m.password === 'string' && m.password.length >= 8;
    const password = custom ? m.password : generateStrongPassword();
    // (1) ZChain note 钱包
    const zRes = await callCore('wallet_create', password, 'interactive');
    const zId = crypto.randomUUID();
    const zCreated = createAccount(zLedger0, {
      id: zId, label: 'ZChain 主账户', keystore: zRes.keystore,
      publicKey: zRes.public_key, networkId: DEFAULT_NETWORK_ID, now: Date.now(),
    });
    if (!zCreated.ok) return stkError(zCreated.code, zCreated.reason);
    await setLedger(zCreated.ledger);
    newSession(zId);
    await storage.session.set({ publicKey: zRes.public_key });
    // (2) EVM 账户
    const evmCreated = await createKeystore(password);
    const evmId = crypto.randomUUID();
    evmV0.accounts[evmId] = {
      id: evmId, label: 'EVM 主账户', address: evmCreated.address,
      keystore: evmCreated.keystore, createdAt: Date.now(),
    };
    evmV0.activeAccountId = evmId;
    await setEvmVault(evmV0);
    mem.evm.session = { accountId: evmId, privateKey: hexToBytes(evmCreated.privateKey), address: evmCreated.address };
    // (3) Starknet 账户（当前网络 class hash）
    const net = resolveStarknetNetwork(DEFAULT_STARKNET_NETWORK_ID);
    const stkCreated = await createStarkAccount(password, net.accountClassHash);
    const stkId = crypto.randomUUID();
    // 与 popup:stkCreate 同一口径：落盘/会话都存 Starknet 校验和地址（同一层
    // 不因创建路径不同而出现两种地址形态）。
    const stkDisplay = starkChecksum(stkCreated.address);
    stkV0.accounts[stkId] = {
      id: stkId, label: 'Starknet 主账户', address: stkDisplay, pubKey: stkCreated.pubKey,
      keystore: stkCreated.keystore, createdAt: Date.now(),
    };
    stkV0.activeAccountId = stkId;
    await setStkVault(stkV0);
    mem.stk.session = {
      accountId: stkId, privateKey: hexToBigInt(stkCreated.privateKey),
      address: stkDisplay, pubKey: stkCreated.pubKey,
    };
    logSafe('quick_created');
    return {
      generated: !custom, // 自动口令时成功页只显示一次
      password: !custom ? password : undefined,
      layers: {
        zchain: { publicKey: zRes.public_key },
        evm: { address: evmCreated.address },
        stk: { address: stkDisplay },
      },
    };
  }
  if (m?.type === 'popup:quickUnlock') {
    // 统一解锁：同一口令逐一尝试三个层（各自独立 keystore，互不影响）
    const results = { zchain: null, evm: null, stk: null };
    let unlockedCount = 0;
    let total = 0;
    // zchain
    const zLedger = await getLedger();
    const zAccount = activeAccount(zLedger);
    if (zAccount) {
      total += 1;
      try {
        const res = await callCore('wallet_unlock', JSON.stringify(zAccount.keystore), m.password);
        const ledger = await getLedger();
        ledger.accounts[zAccount.id] = { ...zAccount, publicKey: res.public_key };
        const sel = selectAccount(ledger, zAccount.id, Date.now());
        await setLedger(sel.ledger);
        newSession(zAccount.id);
        await storage.session.set({ publicKey: res.public_key });
        results.zchain = true;
        unlockedCount += 1;
      } catch (e) {
        results.zchain = false;
        // 只记错误码不记细节（keystore 内容不入日志）：一层解锁失败而其他层
        // 成功 = 口令正确、该层 keystore 状态异常——留排查锚点。
        logSafe('quick_unlock_layer_failed', { layer: 'zchain', code: e?.code ?? 'Unknown' });
      }
    }
    // evm
    const evmV = await getEvmVault();
    const evmAccount = evmActiveAccount(evmV);
    if (evmAccount) {
      total += 1;
      try {
        const priv = await decryptFromKeystore(evmAccount.keystore, m.password);
        mem.evm.session = { accountId: evmAccount.id, privateKey: priv, address: evmAccount.address };
        results.evm = true;
        unlockedCount += 1;
      } catch { results.evm = false; }
    }
    // stk
    const stkV = await getStkVault();
    const stkAccount = stkActiveAccount(stkV);
    if (stkAccount) {
      total += 1;
      try {
        const priv = await decryptStarkKeystore(stkAccount.keystore, m.password);
        mem.stk.session = { accountId: stkAccount.id, privateKey: priv, address: stkAccount.address, pubKey: stkAccount.pubKey };
        results.stk = true;
        unlockedCount += 1;
      } catch { results.stk = false; }
    }
    logSafe('quick_unlock', { count: unlockedCount });
    return { results, unlockedCount, total };
  }
  if (m?.type === 'popup:lockAll') {
    await lockWallet('lockAll');
    lockEvm('lockAll');
    lockStk('lockAll');
    return { locked: true };
  }
  switch (m.type) {
    case 'bridge:getSession': {
      // content bridge 专用：只下发会话令牌与公开状态（无密钥/无 note 明文）。
      // 锁定后令牌为 null（页面旧令牌全部失效）；签名类操作另需解锁态。
      const account = await getActiveAccount();
      return { sessionId: mem.session?.id ?? null, unlocked: isUnlocked(), chainId: currentNetwork(account).chainId };
    }
    case 'popup:getState': {
      const ledger = await getLedger();
      const account = activeAccount(ledger);
      const net = currentNetwork(account);
      const receipts = await getReceipts();
      return {
        hasKeystore: Object.keys(ledger.accounts).length > 0,
        unlocked: isUnlocked(),
        publicKey: isUnlocked() ? (await storage.session.get('publicKey')).publicKey ?? null : null,
        chainId: net.chainId,
        networkKind: net.kind,
        networkLabel: net.label,
        networks: [DEFAULT_NETWORK_ID, 'zchain-testnet-1'],
        activeAccountId: ledger.activeAccountId,
        accounts: Object.values(ledger.accounts)
          .map((a) => ({
            id: a.id,
            label: a.label,
            publicKey: a.publicKey ?? null,
            networkId: a.networkId,
            createdAt: a.createdAt,
            lastSelectedAt: a.lastSelectedAt,
            originCount: Object.keys(a.grants ?? {}).length,
            active: a.id === ledger.activeAccountId,
            unlocked: isUnlocked() && mem.session?.accountId === a.id,
          }))
          .sort((a, b) => (b.lastSelectedAt ?? 0) - (a.lastSelectedAt ?? 0)),
        grantedOrigins: Object.keys(account?.grants ?? {}),
        receipts: Object.values(receipts)
          .map((r) => ({ ...r, view: inclusionView(r, Date.now()) }))
          .sort((a, b) => (b.signedAtMs ?? 0) - (a.signedAtMs ?? 0)),
        gatewayUrl: effectiveGatewayUrl(net.chainId, await getNetworkSettings()),
        autoLockMs: AUTO_LOCK_MS,
        providerVersion: PROVIDER_VERSION,
      };
    }
    case 'popup:create': {
      // 创建即新增账户并切换（wasm 会话单槽：新账户解锁态替换当前会话——
      // 既有账户保持密文态，随后可经口令解锁切换回来）。
      const ledger0 = await getLedger();
      const res = await callCore('wallet_create', m.password, 'interactive');
      const accountId = crypto.randomUUID();
      const created = createAccount(ledger0, {
        id: accountId,
        label: m.label,
        keystore: res.keystore,
        publicKey: res.public_key,
        networkId: DEFAULT_NETWORK_ID,
        now: Date.now(),
      });
      if (!created.ok) return { error: { code: created.code, reason: created.reason } };
      await setLedger(created.ledger);
      newSession(accountId);
      await storage.session.set({ publicKey: res.public_key });
      logSafe('wallet_created', { kind: 'account' });
      return { accountId, publicKey: res.public_key, chainId: res.keystore.chain_id };
    }
    case 'popup:unlock': {
      const account = m.accountId ? (await getLedger()).accounts[m.accountId] : await getActiveAccount();
      if (!account) return { error: { code: 'NoKeystore', reason: 'create a wallet first' } };
      const res = await callCore('wallet_unlock', JSON.stringify(account.keystore), m.password);
      // 解锁成功后把公钥写回账户元数据（公开信息；0.1 迁移账户补齐）。
      const ledger = await getLedger();
      ledger.accounts[account.id] = { ...account, publicKey: res.public_key };
      const sel = selectAccount(ledger, account.id, Date.now());
      await setLedger(sel.ledger);
      newSession(account.id);
      await storage.session.set({ publicKey: res.public_key });
      logSafe('wallet_unlocked', { kind: 'account' });
      return {
        accountId: account.id,
        publicKey: res.public_key,
        chainId: res.chain_id,
        playFree: res.play_free,
        realFree: res.real_free,
        notes: res.notes,
      };
    }
    case 'popup:lock':
      await lockWallet('popup');
      return { locked: true };
    case 'popup:selectAccount': {
      // 切换账户：先锁定当前会话（wasm 单槽），再推进 activeAccountId。
      // 目标账户保持锁定，需各自口令解锁——源账户状态不受影响。
      await lockWallet('account_switch');
      const sel = selectAccount(await getLedger(), m.accountId, Date.now());
      if (!sel.ok) return { error: { code: sel.code, reason: sel.reason } };
      await setLedger(sel.ledger);
      logSafe('account_selected', { kind: 'switch' });
      return { activeAccountId: sel.ledger.activeAccountId, locked: true };
    }
    case 'popup:faucet': {
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const res = await callCore('wallet_faucet_play', String(m.amount));
      await persistActiveKeystore();
      logSafe('devnet_faucet_issued');
      return res;
    }
    case 'popup:getNotes': {
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      // REAL/PLAY 物理分库视图（0.2）：余额分栏 + 分列 note 列表（脱敏）。
      const all = await callCore('wallet_get_all_notes');
      // 在途支出软锁（防双花）：已签 transfer 回执的输入 note 在 inclusion 前
      // 不可再花。展示与可选余额一并扣减（与 transferPreview 的选币口径同源）。
      const pending = pendingSpendMap(await getReceipts());
      const notes = sanitizeNotesForPage(all.play).map((n) => ({
        ...n,
        spendable: n.spendable !== false && !pending.has(n.commitment),
      }));
      const pendingSum = [...pending.values()].reduce((a, b) => a + (Number(b) || 0), 0);
      const balances = { ...all.balances };
      if (pendingSum > 0 && balances.play_free != null) {
        balances.play_free = String(Math.max(0, Number(balances.play_free) - pendingSum));
      }
      return {
        notes,
        realNotes: sanitizeNotesForPage(all.real),
        balances,
      };
    }
    case 'popup:getDisplayViews': {
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      // 展示门（WALLET-ACC-6）：REAL claim 门 + 托管风险提示，wallet-core
      // display.rs 单实现输出；UI 只消费，不自行决定。
      return await callCore('wallet_display_views');
    }
    case 'popup:switchNetwork': {
      // 钱包侧换网（popup UI 发起；UI 已做两步式确认）。写入**当前账户**的
      // 网络选择（账户元数据网络隔离）。锁定态拒绝（无"当前账户会话"）。
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const res = setAccountNetwork(await getLedger(), sessionAccountId(), m.chainId, Date.now());
      if (!res.ok) return { error: { code: res.code, reason: res.reason } };
      await setLedger(res.ledger);
      logSafe('network_switched', { kind: 'popup' });
      const net = resolveNetwork(res.ledger.accounts[res.ledger.activeAccountId].networkId);
      return { chainId: net.chainId, kind: net.kind };
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
    case 'popup:backupExport': {
      // 加密备份导出（WALLET-ACC-5）：wallet-core ZCBK v1 全库导出；口令错
      // 不可能（导出只加密）；返回 borsh 字节 hex，popup 转文件下载。
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      if (typeof m.password !== 'string' || m.password.length < 8) {
        return { error: { code: 'InvalidArgument', reason: '口令至少 8 字符' } };
      }
      const res = await callCore(
        'wallet_backup_export',
        m.password,
        'interactive',
        String(Math.floor(Date.now() / 1000)),
      );
      logSafe('backup_exported');
      return { backupHex: res.backup_hex, createdUnix: res.created_unix, notes: res.notes };
    }
    case 'popup:backupImport': {
      // 导入恢复（fail-closed）：结构/魔数/版本 → 口令（AEAD）→ 索引自检 →
      // keystore 信封同口令复核。成功 = 新增一个**锁定**账户（不自动解锁、
      // 不替换当前会话），用备份口令解锁后可用。
      const hexStr = typeof m.backupHex === 'string' ? m.backupHex.trim() : '';
      if (hexStr.length === 0) return { error: { code: 'InvalidArgument', reason: '备份文件为空' } };
      let res;
      try {
        res = await callCore('wallet_backup_import', hexStr, m.password ?? '');
      } catch (e) {
        // 稳定错误码直通 UI：BadPassword / Tampered / UnsupportedVersion。
        return { error: { code: e.code ?? 'BackupRejected', reason: e.detail ?? '备份被拒绝' } };
      }
      const ledger0 = await getLedger();
      const created = createAccount(ledger0, {
        id: crypto.randomUUID(),
        label: `恢复 ${new Date().toISOString().slice(0, 10)}`,
        keystore: res.keystore,
        publicKey: res.public_key,
        now: Date.now(),
      });
      if (!created.ok) return { error: { code: created.code, reason: created.reason } };
      await setLedger(created.ledger);
      logSafe('backup_imported');
      return {
        accountId: created.account.id,
        publicKey: res.public_key,
        createdUnix: res.created_unix,
        indexes: res.indexes,
        remainsLocked: true,
      };
    }
    case 'popup:receipts': {
      const receipts = await getReceipts();
      return {
        receipts: Object.values(receipts)
          .map((r) => ({ ...r, view: inclusionView(r, Date.now()) }))
          .sort((a, b) => (b.signedAtMs ?? 0) - (a.signedAtMs ?? 0)),
      };
    }
    case 'popup:receiptSeen': {
      // 导入 SeenReceipt（§5.3-1 形状）：0.2 无验签入口——evidence 如实标注
      // receipt_unverified_signature。
      const store = await getReceipts();
      const r = applySeenReceipt(store, m.digest, m.receipt, Date.now());
      if (!r.ok) return { error: { code: r.code, reason: r.reason } };
      await storage.local.set({ receipts: r.store });
      return { entry: r.entry };
    }
    case 'popup:receiptIncluded': {
      // 人工登记 included（0.2 无链上核对通道；evidence 保持 local_manual_entry）。
      const store = await getReceipts();
      const r = markIncluded(store, m.digest, Date.now());
      if (!r.ok) return { error: { code: r.code, reason: r.reason } };
      await storage.local.set({ receipts: r.store });
      return { entry: r.entry };
    }
    case 'popup:getSettings':
      return { settings: await getNetworkSettings() };
    // -----------------------------------------------------------------------
    // Extension 0.3/0.4：会话密钥授权簿 / 提现预览 / 能力矩阵（popup 内部面）
    // -----------------------------------------------------------------------
    case 'popup:getRegistry':
      return await registryView();
    case 'popup:revokeOrigin': {
      // 撤销 origin 授权（§6.12.4 授权簿管理；当前账户名下）。
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const accountId = sessionAccountId();
      const account = await getActiveAccount();
      const grants = revokeOriginGrant(m.origin, account?.grants ?? {});
      const g = setAccountGrants(await getLedger(), accountId, grants);
      if (!g.ok) return { error: { code: g.code, reason: g.reason } };
      await setLedger(g.ledger);
      logSafe('origin_revoked', { origin: String(m.origin ?? '').slice(0, 40) });
      return { ok: true };
    }
    case 'popup:sessionDraft': {
      // 0.3 授权流程第 1 步：草稿 + delegated key 生成（wallet-core）+
      // SNIP-12 typed data + 摘要。**不登记**——确认后走 popup:sessionRegister。
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const account = await getActiveAccount();
      const chainId = m.chainId ?? currentNetwork(account).chainId;
      const nowSec = Math.floor(Date.now() / 1000);
      const draft = draftAuthorization({ ...m, chainId, nowSec });
      if (!draft.ok) return { error: { code: draft.code, reason: draft.reason } };
      // delegated key 生成（私钥只活在 wasm 会话；返回公钥级摘要）。
      let created;
      try {
        created = await callCore('wallet_session_key_create', JSON.stringify({
          chainId: draft.request.chainId,
          accountAddress: draft.request.accountAddress,
          allowedScopes: draft.request.allowedScopes,
          perTxLimit: draft.request.perTxLimit,
          perDayLimit: draft.request.perDayLimit,
          tableAllowlist: draft.request.tableAllowlist,
          nonce: draft.request.nonce,
          validAfter: draft.request.validAfter,
          validUntil: draft.request.validUntil,
        }));
      } catch (e) {
        return { error: { code: e.code ?? 'WalletCoreError', reason: e.detail ?? 'delegated key generation failed' } };
      }
      const key = created.binding;
      // 字段准入（SNIP-12 规范校验；此刻 delegated key / bindingId 已就绪）。
      const fullRequest = { ...draft.request, delegatedPublicKey: key.delegated_public_key, bindingId: key.binding_id };
      const shape = validateDraft(fullRequest);
      if (!shape.ok) return { error: { code: shape.code, reason: shape.reason } };
      // SNIP-12 typed data（adapters/starknet.js 组装；与 account_binding.rs
      // encode_type 逐字一致）+ 摘要（wallet-core poseidon 单实现）。
      const typed = buildAuthorizeTypedData(fullRequest, { chainId: draft.request.chainId });
      if (!typed.ok) return { error: { code: typed.code, reason: typed.reason } };
      let digestRes;
      try {
        digestRes = await callCore('wallet_snip12_authorize_digest', JSON.stringify({
          chainId: draft.request.chainId,
          accountAddress: draft.request.accountAddress,
          delegatedPublicKey: key.delegated_public_key,
          signatureScheme: 'secp256k1',
          allowedScopes: draft.request.allowedScopes,
          perTxLimit: draft.request.perTxLimit,
          perDayLimit: draft.request.perDayLimit,
          tableAllowlist: draft.request.tableAllowlist,
          bindingId: key.binding_id,
          nonce: draft.request.nonce,
          validAfter: draft.request.validAfter,
          validUntil: draft.request.validUntil,
        }));
      } catch (e) {
        return { error: { code: e.code ?? 'WalletCoreError', reason: e.detail ?? 'snip12 digest failed' } };
      }
      return {
        request: draft.request,
        key,
        typedData: typed.typedData,
        digest: digestRes.digest,
        encodeType: digestRes.encode_type,
        origin: draft.defaults.origin,
      };
    }
    case 'popup:sessionRegister': {
      // 0.3 授权流程第 2 步：登记约束记录（devnet 入口形态 = 本地登记；
      // evidence 如实标注 devnet_local_entry——链侧 admission 登记未接）。
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const accountId = sessionAccountId();
      const account = await getActiveAccount();
      const store = await getBindingStore(accountId);
      const up = upsertBinding(store, { ...m.binding, origin: m.origin ?? m.binding?.origin, evidence: 'devnet_local_entry' });
      if (!up.ok) return { error: { code: up.code, reason: up.reason } };
      await setBindingStore(accountId, up.store);
      logSafe('session_binding_registered', { kind: 'devnet_local_entry' });
      return { binding: bindingView(up.binding, Math.floor(Date.now() / 1000)) };
    }
    case 'popup:sessionRevoke': {
      // 0.3/0.4 撤销（粘滞；撤销后该 origin 的签名一律拒绝——fail-closed）。
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const accountId = sessionAccountId();
      const store = await getBindingStore(accountId);
      const r = revokeBinding(store, m.bindingId, Math.floor(Date.now() / 1000));
      if (!r.ok) return { error: { code: r.code, reason: r.reason } };
      await setBindingStore(accountId, r.store);
      // 双重校验：撤销态经 wallet-core 状态机确认（wasm 状态查询入口）。
      let coreStatus = null;
      try {
        coreStatus = await callCore('wallet_binding_status', JSON.stringify(r.binding), String(Math.floor(Date.now() / 1000)));
      } catch { coreStatus = null; }
      logSafe('session_binding_revoked');
      return { binding: bindingView(r.binding, Math.floor(Date.now() / 1000)), coreStatus };
    }
    case 'popup:sessionDelete': {
      // 删除记录（显式用户动作；撤销粘滞态的唯一清除路径——删除后该 origin
      // 回到常规签名路径，而非恢复授权）。
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const accountId = sessionAccountId();
      const store = await getBindingStore(accountId);
      const d = deleteBinding(store, m.bindingId);
      if (!d.ok) return { error: { code: d.code, reason: d.reason } };
      await setBindingStore(accountId, d.store);
      logSafe('session_binding_deleted');
      return { ok: true };
    }
    case 'popup:withdrawPreview': {
      // 0.3 REAL 提现预览（展示态；canSubmit 恒 false——不开放真实提交）。
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const account = await getActiveAccount();
      const all = await callCore('wallet_get_all_notes');
      const views = await callCore('wallet_display_views');
      const wp = buildWithdrawPreview({
        amount: m.amount,
        owner: m.owner,
        realNotes: sanitizeNotesForPage(all.real),
        displayViews: views,
        chainId: currentNetwork(account).chainId,
        nowSec: Math.floor(Date.now() / 1000),
      });
      if (!wp.ok) return { error: { code: wp.code, reason: wp.reason } };
      return { preview: wp.preview };
    }
    // -----------------------------------------------------------------------
    // 方向 B「转账 · 贪心选币」：钱包侧自发起 PLAY 转账（预览 → 摘要绑定 → 签名）
    //
    // 与页面（dapp）签名管线同源：同一 validateRequest 入口、同一 wallet-core
    // `wallet_preview`/`wallet_sign`、同一摘要绑定红线（展示摘要 ≠ 待签摘要即
    // PreviewMismatch，绝不签）、同一回执登记。差别只在触发者：钱包自发起没有
    // origin/信封，因此也就没有会话密钥限额（owner 路径）。
    // -----------------------------------------------------------------------
    case 'popup:transferPreview': {
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const account = await getActiveAccount();
      const net = currentNetwork(account);
      const all = await callCore('wallet_get_all_notes');
      // 在途支出软锁（防双花）：signed/seen 收据的输入 note 不参与选币——
      // 与 getNotes 展示口径、签名闸三处同源（common/receipts.pendingSpendMap）。
      const pending = pendingSpendMap(await getReceipts());
      const spendablePlay = sanitizeNotesForPage(all.play).filter((n) => !pending.has(n.commitment));
      const res = buildTransferPreview({
        amount: m.amount,
        owner: m.owner,
        selfOwner: await publicKeyHex(),
        playNotes: spendablePlay,
        chainId: net.chainId,
        nowSec: Math.floor(Date.now() / 1000),
        nonce: nextTransferNonce(),
        // 门槛按网络形态取（devnet 的本地 stub note 只有 soft，见模块注释）。
        minProof: minProofForNetwork(net.kind),
      });
      if (!res.ok) return { error: { code: res.code, reason: res.reason } };
      // wallet-core 预览：摘要与签名同源（展示-签名一致性红线的第二处落点）。
      // 本地选币只是"打算怎么做"，core 的 preview/digest 才是"将要签什么"；
      // core 拒绝（余额/守恒/note 不存在）一律并入 cannotSubmitReasons。
      const preview = res.preview;
      try {
        const cp = await corePreview(toCoreRequest(preview.operation));
        const digest = String(cp?.preview?.digest ?? '');
        preview.digest = digest;
        preview.corePreview = cp?.preview ?? null;
        if (!/^[0-9a-f]{64}$/i.test(digest)) {
          preview.canSubmit = false;
          preview.cannotSubmitReasons.push('wallet-core 预览未返回摘要');
        }
      } catch (e) {
        preview.canSubmit = false;
        preview.cannotSubmitReasons.push(`wallet-core 预览拒绝：${e.code ?? 'WalletCoreError'} ${e.detail ?? ''}`.trim());
      }
      logSafe('transfer_previewed');
      return { preview };
    }
    case 'popup:transferConfirm': {
      if (!isUnlocked()) return { error: { code: 'SessionInvalid', reason: 'locked' } };
      const account = await getActiveAccount();
      const net = currentNetwork(account);
      const op = m.operation;
      // (1) 结构/网络/ABI/资产类校验：与页面请求同一函数（不开第二套校验面）。
      const v = validateRequest('zchain_signOperation', { operation: op, previewHash: m.digest ?? '' }, { network: net });
      if (!v.ok) return { error: { code: v.code, reason: v.reason } };
      // (1b) 凭证门槛在**后台**复核：UI 那份 canSubmit 只是展示结论，签名前
      // 按当前库状态重算（绕过 UI 直发 RPC / 预览后状态变化都拒）。
      const allNotes = sanitizeNotesForPage((await callCore('wallet_get_all_notes')).play);
      // 在途支出软锁：signed/seen 收据已占用的输入 note 拒绝再签（防双花）。
      const pending = pendingSpendMap(await getReceipts());
      const inFlight = (op?.inputs ?? []).filter((c) => pending.has(String(c)));
      if (inFlight.length > 0) {
        return {
          error: {
            code: 'NoteNotSpendable',
            reason: `输入 note ${String(inFlight[0]).slice(0, 12)}… 已被在途转账占用（回执未上链，防止双花）`,
          },
        };
      }
      const gate = verifySpendProofs({
        playNotes: allNotes,
        inputs: op?.inputs ?? [],
        minProof: minProofForNetwork(net.kind),
      });
      if (!gate.ok) return { error: { code: gate.code, reason: gate.reason } };
      // (2) 展示-签名一致性：重算预览摘要，与 UI 展示那份比对（不一致拒签）。
      const previewRes = await corePreview(toCoreRequest(op));
      const claimed = String(m.digest ?? '').trim().toLowerCase();
      if (claimed === '' || claimed !== String(previewRes.preview?.digest ?? '').toLowerCase()) {
        logSafe('transfer_preview_mismatch');
        return { error: { code: 'PreviewMismatch', reason: '展示摘要与待签内容不一致，请重新生成预览' } };
      }
      // (3) 签名（wallet-core 全拒绝面：nonce/expiry/note 存在性与守恒）。
      const signed = await callCore('wallet_sign', toCoreRequest(op), String(Math.floor(Date.now() / 1000)));
      try {
        await persistActiveKeystore();
      } catch (e) {
        logSafe('persist_failed', { code: e.code ?? 'Unknown' });
      }
      // (4) 回执登记（signed 状态位；链上提交通道未开放——仅展示协议状态）。
      // 携带输入 note 明细：pendingSpendMap 据此软锁在途支出（防双花）。
      const amountByCommitment = new Map(
        allNotes.map((n) => [n.commitment, Number(n.amount)]),
      );
      await recordReceipt(signed.digest, 'transfer', net.chainId,
        (op?.inputs ?? []).map((c) => ({
          commitment: String(c),
          amount: amountByCommitment.get(String(c)),
        })));
      mem.transferNonce = Math.max(mem.transferNonce ?? 0, Number(op.nonce) ?? 0);
      logSafe('transfer_signed');
      return { digest: signed.digest, preview: signed.preview };
    }
    case 'popup:capabilityMatrix': {
      // 0.4 能力矩阵（外部钱包探测 + adapters capability∩白名单逻辑复用）。
      const account = await getActiveAccount();
      return {
        matrix: buildCapabilityMatrix({
          zchainCaps: capabilities(account),
          adapterStatus: adapterHost.status(),
          detection: detectExternalWallets(),
        }),
      };
    }
    case 'popup:setGateway': {
      // 按网络设置网关 URL（http(s) origin 规范化；空串 = 清除覆盖回默认）。
      const net = resolveNetwork(m.chainId);
      if (!net) return { error: { code: 'NetworkUnsupported', reason: String(m.chainId) } };
      const settings = await getNetworkSettings();
      if (m.gatewayUrl == null || m.gatewayUrl === '') {
        delete settings[net.chainId];
      } else {
        const canonical = canonicalHttpUrl(m.gatewayUrl);
        if (!canonical) return { error: { code: 'InvalidArgument', reason: '网关 URL 必须是 http(s) 源' } };
        settings[net.chainId] = { ...settings[net.chainId], gatewayUrl: canonical };
      }
      await storage.local.set({ networkSettings: settings });
      return { saved: true, gatewayUrl: effectiveGatewayUrl(net.chainId, settings) };
    }
    case 'popup:approve':
    case 'popup:reject': {
      const decision = m.type === 'popup:approve' ? 'approved' : 'rejected';
      const tr = transitionRequest(mem.pending, m.requestId, decision, Date.now());
      if (!tr.ok) return { error: { code: tr.code, reason: tr.reason } };
      mem.pending = tr.store;
      const waiter = mem.pageWaiters.get(m.requestId);
      if (waiter) {
        // 连接/换网类（无签名预览）与签名类（handleSign 的 waitForDecision）统一唤醒。
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

/** 网关设置（per 网络；storage.local）。 */
async function getNetworkSettings() {
  const { networkSettings } = await storage.local.get('networkSettings');
  return networkSettings ?? {};
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
  const decision = await handleSign({ method, params }, 'adapter:walletconnect', requestId, await getActiveAccount());
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
    getNetwork: async () => ({ ...currentNetwork(await getActiveAccount()), abiVersion: 1 }),
    getCapabilities: async () => capabilities(await getActiveAccount()),
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
      // page:true —— 桥握手是页面探活，不得续期自动锁（见 handlePopupMessage）。
      if (typeof m?.type === 'string' && m.type.startsWith('bridge:')) {
        sendResponse(await handlePopupMessage(m, { page: true }));
        return;
      }
      const response = await handlePageMessage(m, sender);
      sendResponse(response);
      return;
    }
    // 扩展内部通道（popup/options/portal 页）：仅扩展自身页面（sender.id === 扩展 id）。
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

// 自动锁屏心跳（alarms 是唯一的周期任务）。
chrome.alarms.create('zchain.autolock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== 'zchain.autolock') return;
  // 清扫过期请求（超时 → expired，页面侧收到 RequestExpired）。
  const swept = sweepExpired(mem.pending, Date.now());
  mem.pending = swept.store;
  if (isUnlocked() && Date.now() - mem.lastActivity > AUTO_LOCK_MS) {
    lockWallet('autolock');
  }
  // EVM / Starknet 会话同一心跳 fail-closed（私钥只活在 SW 内存）。
  if (evmUnlocked() && Date.now() - mem.lastActivity > AUTO_LOCK_MS) {
    lockEvm('autolock');
  }
  if (stkUnlocked() && Date.now() - mem.lastActivity > AUTO_LOCK_MS) {
    lockStk('autolock');
  }
});

chrome.runtime.onInstalled.addListener(() => {
  logSafe('installed', { kind: 'extension-0.2' });
});
