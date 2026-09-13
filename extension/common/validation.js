// =============================================================================
// extension/common/validation.js — ZChain 钱包插件安全校验层（Extension 0.1，
// 0.2 增量：多网络 switchNetwork 判定面 / REAL 分库视图透传）
// plan-appchain §6.12.4："站点消息必须带 request nonce、origin、expiry 和
// session id，后台校验来源、replay、ABI/domain/version 和用户取消状态。"
//
// 设计纪律：
// - **纯函数、零依赖、无 IO、无全局状态**：所有可变状态（nonce 账本、权限表、
//   待签名请求）由调用方持有，本模块只做判定并返回"下一状态"，因此可以在
//   node --test 下脱离浏览器完整测试；
// - 不含任何密码学（密码学唯一入口是 wallet-core 的 WASM 绑定）；
// - 全部判定 fail-closed：任何无法确认合法的输入都拒绝，错误返回稳定码
//   （错误码是 UI/测试契约，文本仅供人读）。
// =============================================================================

/** Operation ABI 版本（与 wallet-core SUPPORTED_ABI_VERSION 一致；唯一）。 */
export const SUPPORTED_ABI_VERSION = 1;

/** 已知域标签（wallet-core operation_signer::parse_domain 只认 "zchain"）。 */
export const SUPPORTED_DOMAINS = ['zchain'];

/**
 * Extension 0.2 网络（多网络/换网交付；注册表本体在 common/networks.js，
 * 这里保留判定面所需的最小集合——chainId 列表供"换链重放"类检查使用）。
 * mainnet **刻意不在表内**：devnet/testnet 不得误连 mainnet 配置（红线）。
 */
export const NETWORKS_02 = [
  { chainId: 'zchain-devnet-1', kind: 'devnet' },
  { chainId: 'zchain-testnet-1', kind: 'testnet' },
];

/** 0.1 的单网络表（保留为常量供测试引用；判定不再使用）。 */
export const NETWORKS_01 = [{ chainId: 'zchain-devnet-1', kind: 'devnet' }];

/** Extension 0.1 资产边界：只允许 PLAY（REAL/隔离与显示门是 0.2 交付）。 */
export const ASSET_CLASSES_01 = ['PLAY'];

/** 页面可见的 provider 方法全集（版本化 zchain_*；不冒充 EIP-1193）。 */
export const METHODS = [
  'zchain_requestAccounts',
  'zchain_getNetwork',
  'zchain_getCapabilities',
  'zchain_switchNetwork',
  'zchain_getAccounts',
  'zchain_signOperation',
  'zchain_signSettlement',
  'zchain_authorizeSessionKey',
  'zchain_revokeSessionKey',
  'zchain_getNotes',
  'zchain_verifyProof',
  'zchain_watchProof',
  'zchain_lock',
];

/** Extension 0.2 实际可用的方法（其余返回 NotSupportedIn01；0.2 起
 *  zchain_switchNetwork 交付——完整语义见 validateRequest 换网分支）。 */
export const METHODS_AVAILABLE = new Set([
  'zchain_requestAccounts',
  'zchain_getNetwork',
  'zchain_getCapabilities',
  'zchain_switchNetwork',
  'zchain_getAccounts',
  'zchain_signOperation',
  'zchain_signSettlement',
  'zchain_getNotes',
  'zchain_lock',
]);

/** 结构化签名请求的种类（0.1 只放行 PLAY 低风险三类；withdraw/key_rotation
 *  属提现类/高风险，按迭代表是 0.2/0.3 交付，provider 与后台双重拒绝）。 */
export const OPERATION_KINDS_01 = ['transfer', 'buy_in', 'settle'];

/** 各方法的必填参数（缺一即拒）。金额一律十进制字符串或安全整数。 */
export const METHOD_PARAMS = {
  zchain_requestAccounts: [],
  zchain_getNetwork: [],
  zchain_getCapabilities: [],
  zchain_switchNetwork: ['chainId'],
  zchain_getAccounts: [],
  zchain_signOperation: ['operation', 'previewHash'],
  zchain_signSettlement: ['settlement', 'previewHash'],
  zchain_authorizeSessionKey: ['request'],
  zchain_revokeSessionKey: ['bindingId'],
  zchain_getNotes: [],
  zchain_verifyProof: ['proof'],
  zchain_watchProof: ['binding'],
  zchain_lock: [],
};

/** 信封字段校验允许的 method 集合之外的辅助上限（防资源滥用）。 */
export const LIMITS = {
  maxMethodLength: 64,
  maxRequestIdLength: 128,
  maxSessionIdLength: 128,
  maxOriginLength: 256,
  /** 单条 signOperation 输入 note 数上限（批量签名防护的一部分）。 */
  maxInputs: 16,
  maxOutputs: 16,
  /** 待签名请求默认超时（毫秒）：超时 → RequestExpired。 */
  pendingTtlMs: 120_000,
};

/** u64 上限（账本金额域；与 wallet-core 的 u64 一致）。 */
export const U64_MAX = 18_446_744_073_709_551_615n;

// ---------------------------------------------------------------------------
// 错误构造（稳定码 + 人读详情；detail 不携带任何密钥材料）
// ---------------------------------------------------------------------------

/** @returns {{ok: false, code: string, reason: string}} */
export function reject(code, reason) {
  return { ok: false, code, reason };
}

const OK = { ok: true };

// ---------------------------------------------------------------------------
// 1. origin 校验：精确 origin 匹配 + 每 origin 独立授权（plan §6.12.4
//    "每个 origin 的权限、网络和账户选择单独保存"）
// ---------------------------------------------------------------------------

/** 粗提 origin（scheme + host + port；路径/query 一律不参与匹配）。 */
export function canonicalOrigin(origin) {
  if (typeof origin !== 'string' || origin.length === 0 || origin.length > LIMITS.maxOriginLength) {
    return null;
  }
  try {
    const u = new URL(origin);
    // 只接受 http(s)；chrome-extension/about/javascript/data/file 一律拒绝。
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    return u.origin;
  } catch {
    return null;
  }
}

/**
 * origin 是否已被显式授权（grants: Record<origin, {grantedAt, accounts[]}>）。
 * 精确匹配：无通配符、无后缀匹配。
 */
export function originIsGranted(origin, grants) {
  const key = canonicalOrigin(origin);
  if (!key || !grants || typeof grants !== 'object') return false;
  return Object.prototype.hasOwnProperty.call(grants, key) && grants[key] != null;
}

/** 记录/更新一个 origin 的授权（返回新对象；不修改入参）。 */
export function grantOrigin(origin, grants, now) {
  const key = canonicalOrigin(origin);
  if (!key) throw new TypeError('bad origin');
  return { ...grants, [key]: { grantedAt: now, accounts: grants?.[key]?.accounts ?? [] } };
}

/** 撤销 origin 授权。 */
export function revokeOrigin(origin, grants) {
  const key = canonicalOrigin(origin);
  if (!key || !grants) return grants ?? {};
  const next = { ...grants };
  delete next[key];
  return next;
}

// ---------------------------------------------------------------------------
// 2. 信封校验（伪造 origin / 重放 nonce / 过期 / session 绑定）
// ---------------------------------------------------------------------------

/**
 * 校验页面消息信封 + 占用 nonce。
 *
 * @param msg           页面消息体 {envelope:{origin,nonce,expiry,sessionId,requestId}, method, params}
 * @param senderOrigin  chrome sender 的真实 origin（content script 侧固定注入，
 *                      页面无法伪造——后台仍与 envelope.origin 比对）
 * @param state         {nonceLedger: Record<origin, number>, session: {id, expiresAt, locked} | null}
 * @param opts          {now: 毫秒, grants: Record<origin, ...>}
 * @returns {ok:true, nextState} | {ok:false, code, reason}
 */
export function checkEnvelope(msg, senderOrigin, state, opts) {
  // requireGrant=false 仅用于 zchain_requestAccounts 首连：尚未授权的 origin
  // 必须能到达"显式确认"步骤（批准后 grantOrigin 入库）。
  const { now, grants, requireGrant = true } = opts;
  if (!isPlainObject(msg)) return reject('BadEnvelope', 'message must be an object');
  const env = msg.envelope;
  if (!isPlainObject(env)) return reject('BadEnvelope', 'envelope required');
  if (typeof msg.method !== 'string' || msg.method.length === 0 || msg.method.length > LIMITS.maxMethodLength) {
    return reject('BadEnvelope', 'method required');
  }

  // (a) envelope.origin 必须存在、可规范化，且与 sender 真实 origin 完全一致
  //     （伪造 origin 拒绝）。
  const claimed = canonicalOrigin(env.origin);
  if (!claimed) return reject('OriginInvalid', 'envelope.origin missing or not http(s)');
  const sender = canonicalOrigin(senderOrigin);
  if (!sender) return reject('OriginInvalid', 'sender origin missing');
  if (claimed !== sender) return reject('OriginMismatch', `envelope.origin ${claimed} != sender ${sender}`);

  // (b) origin 必须已被授权（首连 zchain_requestAccounts 例外：它必须能到达
  //     弹窗显式确认，批准后 grantOrigin 入库）。
  if (requireGrant && !originIsGranted(sender, grants)) return reject('OriginNotPermitted', `${sender} not granted`);

  // (c) nonce：单调递增安全整数（同一 origin 重放/回退/相等一律拒绝）。
  if (!Number.isSafeInteger(env.nonce) || env.nonce < 0) {
    return reject('NonceInvalid', 'nonce must be a non-negative safe integer');
  }
  const ledger = state?.nonceLedger ?? {};
  const last = ledger[sender];
  if (last != null && env.nonce <= last) {
    return reject('NonceReplay', `nonce ${env.nonce} <= last ${last}`);
  }

  // (d) expiry：unix 秒，必须晚于当前时间（毫秒→秒换算后比较，宽松 1s）。
  if (!Number.isSafeInteger(env.expiry)) return reject('EnvelopeExpired', 'expiry must be integer seconds');
  const nowSec = Math.floor(now / 1000);
  if (env.expiry <= nowSec) {
    return reject('EnvelopeExpired', `expiry ${env.expiry} <= now ${nowSec}`);
  }

  // (e) sessionId 绑定：必须与当前解锁会话一致（换会话/锁定后旧消息全拒）。
  const session = state?.session;
  if (!session || session.locked) return reject('SessionInvalid', 'wallet locked');
  if (typeof env.sessionId !== 'string' || env.sessionId.length === 0 || env.sessionId.length > LIMITS.maxSessionIdLength) {
    return reject('SessionInvalid', 'sessionId required');
  }
  if (env.sessionId !== session.id) return reject('SessionInvalid', 'sessionId mismatch');
  if (Number.isSafeInteger(session.expiresAt) && now > session.expiresAt) {
    return reject('SessionInvalid', 'session expired');
  }

  // (f) requestId：存在且有界（用于取消/去重关联，不参与密码学）。
  if (typeof env.requestId !== 'string' || env.requestId.length === 0 || env.requestId.length > LIMITS.maxRequestIdLength) {
    return reject('BadEnvelope', 'requestId required');
  }

  return {
    ok: true,
    origin: sender,
    nextState: { ...state, nonceLedger: { ...ledger, [sender]: env.nonce } },
  };
}

// ---------------------------------------------------------------------------
// 3. 请求结构校验（未知 method / 缺参 / 金额 / 网络 / ABI / domain）
// ---------------------------------------------------------------------------

/**
 * 金额校验：>0、≤u64、无小数/指数/负号；接受十进制字符串（首选）或安全整数。
 * （JS Number 只有 2^53 安全整数，页面接口统一字符串以避免精度损失。）
 */
export function validateAmount(v) {
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v <= 0) return reject('AmountInvalid', 'number must be a positive safe integer');
    return { ok: true, amount: String(v) };
  }
  if (typeof v !== 'string' || v.length === 0 || v.length > 20) return reject('AmountInvalid', 'amount must be a decimal string');
  if (!/^[0-9]+$/.test(v)) return reject('AmountInvalid', 'amount must match ^[0-9]+$');
  if (v.length > 1 && v[0] === '0') return reject('AmountInvalid', 'no leading zeros');
  if (BigInt(v) > U64_MAX) return reject('AmountOverflow', `amount exceeds u64 max`);
  if (BigInt(v) === 0n) return reject('AmountInvalid', 'amount must be > 0');
  return { ok: true, amount: v };
}

/**
 * provider 方法级校验：未知 method 拒、0.1 未交付 method 拒、缺参拒、
 * 网络不符拒、ABI/domain 不认识拒、PLAY 之外拒、签名请求结构逐字段校验。
 *
 * @param method  zchain_* 方法名
 * @param params  方法参数对象
 * @param ctx     {network: {chainId}, now?: ms}
 */
export function validateRequest(method, params, ctx) {
  if (!METHODS.includes(method)) return reject('UnknownMethod', `${method} is not a zchain method`);
  if (!METHODS_AVAILABLE.has(method)) {
    return reject('NotSupportedIn01', `${method} is not available in this wallet version (0.4); session-key authorization ships via the wallet popup UI (0.3/0.4), provider methods follow with the dapp SDK`);
  }

  const required = METHOD_PARAMS[method] ?? [];
  if (!isPlainObject(params)) return reject('InvalidParams', 'params must be an object');
  for (const key of required) {
    if (params[key] === undefined || params[key] === null) {
      return reject('MissingParam', `params.${key} is required`);
    }
  }

  const network = ctx?.network;
  if (!network || typeof network.chainId !== 'string') return reject('NetworkInvalid', 'wallet has no network');

  // 换网（Extension 0.2 完整语义）：
  // - 目标必须是注册表内网络（devnet/testnet）；mainnet 刻意不注册——
  //   "devnet/testnet 不得误连 mainnet 配置"红线在这里与注册表双重钉死；
  // - 目标 == 当前网络 → 幂等 no-op（无需弹窗确认，无状态变化）；
  // - 目标 != 当前网络 → 通过（结构合法），但必须走显式二次确认流
  //   （requiresExplicitConfirm 对 switchNetwork 恒 true；后台负责弹窗）。
  if (method === 'zchain_switchNetwork') {
    const known = NETWORKS_02.some((n) => n.chainId === params.chainId);
    if (!known) {
      return reject(
        'NetworkUnsupported',
        params.chainId === 'zchain-mainnet-1'
          ? 'mainnet is intentionally not configured in extension 0.2 (devnet/testnet only)'
          : `unknown network ${String(params.chainId)}`,
      );
    }
    return OK;
  }

  // 签名类：逐字段校验（金额/ABI/domain/chain/kind/类型）。
  if (method === 'zchain_signOperation') return validateSignOperation(params.operation, ctx);
  if (method === 'zchain_signSettlement') return validateSignSettlement(params.settlement, ctx);

  return OK;
}

/** 结构化签名操作（transfer/buy_in；settle 走 signSettlement）。 */
function validateSignOperation(operation, ctx) {
  if (!isPlainObject(operation)) return reject('InvalidParams', 'operation must be an object');
  const kind = operation.kind;
  if (typeof kind !== 'string') return reject('InvalidParams', 'operation.kind required');
  if (!OPERATION_KINDS_01.includes(kind)) {
    return OPERATION_KINDS_DISABLED.has(kind)
      ? reject('KindDisabledIn01', `operation kind ${kind} ships in 0.2+`)
      : reject('UnknownKind', `unknown operation kind ${kind}`);
  }
  if (operation.assetClass !== 'PLAY') {
    // REAL 是已知资产类，但签名面在 0.2 仍关闭（0.2 交付的是 REAL/PLAY
    // **隔离展示**：分库视图 + 托管风险提示；REAL 提现/签名随 Vault 上线
    // 开放，绝不因展示而放开签名）。其余值非法。
    return operation.assetClass === 'REAL'
      ? reject('AssetClassDisabledIn01', 'REAL signing stays closed in 0.2 (display-only isolation); only PLAY is signable')
      : reject('AssetClassInvalid', `unknown asset class ${String(operation.assetClass)}`);
  }
  const net = checkNetworkAbiDomain(operation, ctx);
  if (!net.ok) return net;

  // inputs：承诺 hex32 数组，1..LIMITS.maxInputs（批量签名防护）。
  const inputs = operation.inputs;
  if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length > LIMITS.maxInputs) {
    return reject('InvalidParams', `inputs must be 1..${LIMITS.maxInputs} commitments`);
  }
  for (const c of inputs) {
    const r = validateHex(c, 32);
    if (!r.ok) return reject('InvalidParams', `inputs[] must be hex32: ${r.reason}`);
  }

  if (kind === 'transfer') {
    const outputs = operation.outputs;
    if (!Array.isArray(outputs) || outputs.length === 0 || outputs.length > LIMITS.maxOutputs) {
      return reject('InvalidParams', `outputs must be 1..${LIMITS.maxOutputs} entries`);
    }
    for (const o of outputs) {
      if (!isPlainObject(o)) return reject('InvalidParams', 'outputs[] must be objects');
      const owner = validateHex(o.owner, 33);
      if (!owner.ok) return reject('InvalidParams', `outputs[].owner must be hex33: ${owner.reason}`);
      const amt = validateAmount(o.amount);
      if (!amt.ok) return amt;
    }
  }

  if (kind === 'buy_in') {
    if (!Number.isSafeInteger(operation.tableId) || operation.tableId <= 0) {
      return reject('InvalidParams', 'operation.tableId must be a positive safe integer');
    }
    const seat = validateHex(operation.seatOwner, 33);
    if (!seat.ok) return reject('InvalidParams', `operation.seatOwner must be hex33: ${seat.reason}`);
  }

  // nonce/expiry：签名请求自身的防重放上下文（wallet-core 再次强校验）。
  if (!Number.isSafeInteger(operation.nonce) || operation.nonce < 0) {
    return reject('InvalidParams', 'operation.nonce must be a non-negative safe integer');
  }
  if (!Number.isSafeInteger(operation.expiry)) return reject('InvalidParams', 'operation.expiry must be integer unix seconds');

  return OK;
}

/** 结算签名（operator 下发 record/policy 的 borsh hex + 预览摘要绑定）。 */
function validateSignSettlement(settlement, ctx) {
  if (!isPlainObject(settlement)) return reject('InvalidParams', 'settlement must be an object');
  const net = checkNetworkAbiDomain(settlement, ctx);
  if (!net.ok) return net;
  for (const key of ['recordBorsh', 'policyBorsh']) {
    const r = validateHex(settlement[key], null, { maxLen: 8192 });
    if (!r.ok) return reject('InvalidParams', `settlement.${key} must be non-empty hex: ${r.reason}`);
  }
  if (!Number.isSafeInteger(settlement.nonce) || settlement.nonce < 0) {
    return reject('InvalidParams', 'settlement.nonce must be a non-negative safe integer');
  }
  if (!Number.isSafeInteger(settlement.expiry)) return reject('InvalidParams', 'settlement.expiry must be integer unix seconds');
  return OK;
}

function checkNetworkAbiDomain(operation, ctx) {
  // chain_id 与当前网络不符拒（换链重放防护）。
  if (operation.chainId !== ctx.network.chainId) {
    return reject('NetworkMismatch', `operation.chainId ${operation.chainId} != current ${ctx.network.chainId}`);
  }
  // ABI 版本不认识拒（wallet-core 只支持 v1；这里先行拒绝并给稳定码）。
  if (operation.abiVersion !== SUPPORTED_ABI_VERSION) {
    return reject('AbiUnsupported', `abiVersion ${String(operation.abiVersion)} != ${SUPPORTED_ABI_VERSION}`);
  }
  // domain 标签不认识拒。
  if (!SUPPORTED_DOMAINS.includes(operation.domain)) {
    return reject('DomainUnsupported', `domain ${String(operation.domain)} not recognized`);
  }
  return OK;
}

/** hex 字符串校验（exactLen 字节 → 2*exactLen 字符；null = 只设上限）。 */
export function validateHex(v, exactLen, opts = {}) {
  const maxLen = opts.maxLen ?? 132;
  if (typeof v !== 'string' || v.length === 0 || v.length > maxLen) return reject('InvalidParams', 'expected non-empty hex string');
  if (!/^[0-9a-fA-F]*$/.test(v)) return reject('InvalidParams', 'expected hex characters');
  if (exactLen != null && v.length !== exactLen * 2) {
    return reject('InvalidParams', `expected ${exactLen * 2} hex chars, got ${v.length}`);
  }
  return OK;
}

// ---------------------------------------------------------------------------
// 4. 权限最小化判定：首次连接 / 换网 / 提现类 / 批量签名 → 必须显式二次确认
//    （plan §6.12.4；0.1 中提现类与换网直接不可用，但判定函数保留，供
//    0.2 在同一测试面下启用）
// ---------------------------------------------------------------------------

/**
 * 该请求是否必须弹窗显式确认（返回 true 时不允许静默签名）。
 *
 * @param req {method, params, origin}
 * @param ctx {grants, network}
 */
export function requiresExplicitConfirm(req, ctx) {
  if (!isPlainObject(req) || typeof req.method !== 'string') return true;
  // (1) 首次连接：origin 未授权（requestAccounts 即连接请求）。
  if (req.method === 'zchain_requestAccounts') return true;
  if (!originIsGranted(req.origin, ctx?.grants)) return true;
  // (2) 换网：任何 switchNetwork。
  if (req.method === 'zchain_switchNetwork') return true;
  // (3) 提现类：withdraw/key_rotation（0.1 已被 validateRequest 拒绝，这里是纵深）。
  const op = req.params?.operation ?? req.params?.settlement;
  const kind = op?.kind;
  if (WITHDRAW_LIKE.has(kind)) return true;
  // (4) 批量签名：任何数组形 params（0.1 的单请求只允许单操作；出现数组即批量）。
  if (Array.isArray(req.params?.batch)) return true;
  if (Array.isArray(op) || (Array.isArray(req.params) && req.params.length > 1)) return true;
  // (5) 签名类一律确认（预览确认页是签名前的强制路径）。
  if (req.method === 'zchain_signOperation' || req.method === 'zchain_signSettlement') return true;
  if (req.method === 'zchain_authorizeSessionKey') return true;
  return false;
}

const WITHDRAW_LIKE = new Set(['withdraw', 'key_rotation']);
const OPERATION_KINDS_DISABLED = new Set(['withdraw', 'key_rotation']);

// ---------------------------------------------------------------------------
// 5. 待签名请求状态机：pending → approved | rejected | expired（取消与超时）
// ---------------------------------------------------------------------------

export const REQUEST_STATES = ['pending', 'approved', 'rejected', 'expired'];

/** 创建待签名请求（幂等键：requestId；已存在非 pending → 拒绝）。 */
export function openPendingRequest(store, requestId, payload, now, ttlMs = LIMITS.pendingTtlMs) {
  if (typeof requestId !== 'string' || requestId.length === 0) return reject('BadEnvelope', 'requestId required');
  const existing = store[requestId];
  if (existing && existing.state !== 'expired') {
    return reject('DuplicateRequestId', `request ${requestId} already ${existing.state}`);
  }
  const next = {
    ...store,
    [requestId]: { state: 'pending', payload, openedAt: now, expiresAt: now + ttlMs },
  };
  return { ok: true, store: next, request: next[requestId] };
}

/** 状态迁移（合法迁移之外一律拒绝：pending → approved/rejected；任意 → expired）。 */
export function transitionRequest(store, requestId, to, now) {
  const req = store[requestId];
  if (!req) return reject('UnknownRequest', `no request ${requestId}`);
  if (!REQUEST_STATES.includes(to)) return reject('InvalidTransition', `bad state ${to}`);
  if (req.state !== 'pending') return reject('InvalidTransition', `request ${requestId} already ${req.state}`);
  if (to === 'approved' || to === 'rejected') {
    if (now > req.expiresAt) return reject('RequestExpired', `request expired at ${req.expiresAt}`);
  }
  const next = { ...store, [requestId]: { ...req, state: to, settledAt: now } };
  return { ok: true, store: next, request: next[requestId] };
}

/** 超时清扫：把所有过期 pending 置为 expired（返回新 store 与被超时的 id 列表）。 */
export function sweepExpired(store, now) {
  const next = { ...store };
  const expired = [];
  for (const [id, req] of Object.entries(next)) {
    if (req.state === 'pending' && now > req.expiresAt) {
      next[id] = { ...req, state: 'expired', settledAt: now };
      expired.push(id);
    }
  }
  return { store: next, expired };
}

// ---------------------------------------------------------------------------
// 6. 输出脱敏（plan §6.12.4 "只向页面暴露公钥、地址、签名结果和脱敏状态"）
// ---------------------------------------------------------------------------

/** note 列表脱敏：剥离 spend secret / nullifier / origin 帧 / 内部索引。
 *  assetClass 仅在库侧显式提供时透传（REAL/PLAY 分库视图；绝不推断）。 */
export function sanitizeNotesForPage(notes) {
  if (!Array.isArray(notes)) return [];
  return notes.map((n) => ({
    commitment: typeof n.commitment === 'string' ? n.commitment : undefined,
    amount: n.amount != null ? String(n.amount) : undefined,
    tableId: n.table_id ?? n.tableId ?? null,
    proof: n.proof,
    spendable: Boolean(n.spendable),
    assetClass: n.asset_class === 'REAL' || n.asset_class === 'PLAY' ? n.asset_class : undefined,
  }));
}

/** 钱包状态脱敏（对页面可见的全部字段；公钥/地址/余额级信息）。 */
export function publicWalletState({ publicKey, chainId, playFree, playLocked }) {
  return { publicKey, chainId, playFree: playFree != null ? String(playFree) : undefined, playLocked: playLocked != null ? String(playLocked) : undefined };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
