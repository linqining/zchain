// =============================================================================
// extension/adapters/starknet.js — Starknet 钱包接口适配器（Extension 0.1）
//
// 定位（如实声明，plan §6.12.1 推荐形态"Starknet Account + SNIP-12 授权的
// ZChain 会话密钥"）：本适配器**只做一件事**——把注入的 Starknet 钱包对象
// （window.starknet / window.stargate 风格：isConnected / account /
// signMessage(typedData) / getChainId）用于：
//   1) Vault/登录场景的身份探测（能力形状检查）；
//   2) SNIP-12 `AuthorizeZChainKey` typed data 组装 + signMessage 委托 +
//      签名验证 + 授权登记（对接 wallet-core account_binding 的字段规范）。
//
// **边界（红线，测试钉住）**：Starknet 签名只用于授权委托/Vault 登录，
// **绝不**产生 ZChain note spend 签名（spend 签名唯一入口是 wallet-core 的
// secp256k1 结构化 SigningRequest）；Starknet 账户地址不是 ZChain Note owner，
// 授权登记里它只是"授权方"（account_address 字段）。
//
// typed data 规范来源：poker-wallet/src/account_binding.rs——
//   - domain：{ name: "ZChain", version: "1", chainId: <zchain 网络 id>,
//     revision: "1" }（SNIP-12 revision 1；不复用 SN_MAIN/EVM chain id）；
//   - AuthorizeZChainKey 成员（名字字母序，与 authorize_encode_type 逐字一致）：
//     account_address:felt252, allowed_scopes:shortstring[], binding_id:felt252,
//     chain_id:shortstring, delegated_public_key:bytes, nonce:felt252,
//     per_day_limit:amount, per_tx_limit:amount, signature_scheme:shortstring,
//     table_allowlist:felt252[], table_allowlist_scope:shortstring,
//     valid_after:amount, valid_until:amount, zchain_chain_id:shortstring。
//   wallet-core 的 wasm 前端（wasm.rs）目前没有 typed-data 构造/验签入口，
//   故本文件按上述规范组装 JSON；**摘要（Poseidon/SNIP-12）与 Stark 验签
//   仍只属于 wallet-core**——通过注入的 verifier 接口完成（零 JS 密码学）。
//
// 纪律：零密码学、零依赖、无 IO、无浏览器全局（globalObj 注入）。
// =============================================================================

/** 会话密钥允许的 scope（wallet-core key_manager::Scope 名；withdraw 禁止）。 */
export const SESSION_SCOPES = ['play', 'buyin', 'bet', 'settle', 'transfer'];

/** 会话密钥永不持有的 scope（key_manager：提现类高风险，仅 owner 路径）。 */
export const FORBIDDEN_SCOPES = ['withdraw'];

/** SNIP-12 revision（wallet-core 固定 revision 1）。 */
export const SNIP12_REVISION = '1';

/** SNIP-12 金额类型（amount = u128）的十进制字符串上限（2^128-1 = 39 位）。 */
const U128_MAX_DIGITS = 39;

/** Stark 域模数 = 2^251 + 17·2^192 + 1（仅用于地址范围输入校验，非密码学）。 */
const FIELD_MODULUS = (1n << 251n) + 17n * (1n << 192n) + 1n;

/** AuthorizeZChainKey 的成员类型表（与 account_binding.rs encode_type 逐字一致）。 */
export const AUTHORIZE_TYPE_MEMBERS = [
  ['account_address', 'felt252'],
  ['allowed_scopes', 'shortstring[]'],
  ['binding_id', 'felt252'],
  ['chain_id', 'shortstring'],
  ['delegated_public_key', 'bytes'],
  ['nonce', 'felt252'],
  ['per_day_limit', 'amount'],
  ['per_tx_limit', 'amount'],
  ['signature_scheme', 'shortstring'],
  ['table_allowlist', 'felt252[]'],
  ['table_allowlist_scope', 'shortstring'],
  ['valid_after', 'amount'],
  ['valid_until', 'amount'],
  ['zchain_chain_id', 'shortstring'],
];

/** 与 wallet-core `authorize_encode_type()` 逐字相等的字符串（测试比对锚点）。 */
export const AUTHORIZE_ENCODE_TYPE =
  'AuthorizeZChainKey(' + AUTHORIZE_TYPE_MEMBERS.map(([n, t]) => `${n}:${t}`).join(',') + ')';

// ---------------------------------------------------------------------------
// 钱包对象探测（window.starknet / window.stargate 风格）
// ---------------------------------------------------------------------------

/** 判定一个候选对象是否形如 Starknet 钱包（fail-closed：缺方法即不算）。 */
function describeWallet(candidate) {
  if (!candidate || typeof candidate !== 'object') return null;
  // 不把自家 provider（window.zchain）误认成 Starknet 钱包。
  if (candidate.isZChain) return null;
  if (typeof candidate.signMessage !== 'function') return null;
  if (typeof candidate.getChainId !== 'function') return null;
  return {
    isConnected: Boolean(candidate.isConnected),
    address: candidate.account?.address ?? (typeof candidate.account === 'string' ? candidate.account : null),
    supportsTypedData: true,
    wallet: candidate,
  };
}

/**
 * 在宿主全局对象上检测注入的 Starknet 钱包。
 * @param {object} [globalObj] 默认 globalThis（页面中即 window）
 * @returns {{ namespace: 'starknet'|'stargate', isConnected, address, supportsTypedData, wallet } | null}
 */
export function detectStarknetWallet(globalObj = globalThis) {
  for (const namespace of ['starknet', 'stargate']) {
    const desc = describeWallet(globalObj?.[namespace]);
    if (desc) return { namespace, ...desc };
  }
  return null;
}

// ---------------------------------------------------------------------------
// SNIP-12 typed data 组装（JSON 形状；摘要计算属于 wallet-core，不在此处）
// ---------------------------------------------------------------------------

/** StarknetDomain（SNIP-12 rev1；chainId 是 ZChain 版本化网络 id 字符串）。 */
export function buildStarknetDomain(chainId) {
  return { name: 'ZChain', version: '1', chainId, revision: SNIP12_REVISION };
}

/** felt252 JSON 值：'0x' hex（SNIP-12 rev1 约定；不留前导零）。 */
function feltHex(bytesHex) {
  return `0x${bytesHex.toLowerCase().replace(/^0x/, '')}`;
}

/** amount JSON 值：十进制字符串（u128；0 表示"不限"）。 */
function amountStr(v) {
  if (v == null) return '0';
  const s = typeof v === 'number' ? String(v) : String(v).trim();
  if (!/^[0-9]+$/.test(s) || s.length > U128_MAX_DIGITS) return null;
  if (s.length > 1 && s[0] === '0') return null;
  return s;
}

/**
 * 构造 `AuthorizeZChainKey` SNIP-12 typed data（wallet-core 规范的 JSON 镜像）。
 *
 * @param {object} req 见 validateAuthorizationRequest 的字段说明
 * @param {object} ctx { chainId: 'zchain-devnet-1' }
 * @returns {{ ok: true, typedData }} | {{ ok: false, code, reason }}
 */
export function buildAuthorizeTypedData(req, ctx) {
  const base = validateAuthorizationRequest(req, ctx);
  if (!base.ok) return base;

  const message = {
    account_address: feltHex(req.accountAddress),
    allowed_scopes: [...base.scopes],
    binding_id: feltHex(req.bindingId),
    chain_id: ctx.chainId,
    // SNIP-12 bytes 类型：按字节数组编码（每字节一个 '0x..' hex 字符串）。
    delegated_public_key: req.delegatedPublicKey.toLowerCase().replace(/^0x/, '').match(/.{2}/g).map((b) => `0x${b}`),
    nonce: feltHex(BigInt(req.nonce).toString(16)),
    per_day_limit: amountStr(req.perDayLimit),
    per_tx_limit: amountStr(req.perTxLimit),
    signature_scheme: req.signatureScheme ?? 'secp256k1',
    table_allowlist: base.tableAllowlist ? base.tableAllowlist.map((t) => feltHex(BigInt(t).toString(16))) : [],
    table_allowlist_scope: base.tableAllowlist ? 'allowlist' : 'all',
    valid_after: amountStr(req.validAfter),
    valid_until: amountStr(req.validUntil),
    zchain_chain_id: ctx.chainId,
  };

  const typedData = {
    types: {
      StarknetDomain: [
        { name: 'name', type: 'shortstring' },
        { name: 'version', type: 'shortstring' },
        { name: 'chainId', type: 'shortstring' },
        { name: 'revision', type: 'shortstring' },
      ],
      AuthorizeZChainKey: AUTHORIZE_TYPE_MEMBERS.map(([name, type]) => ({ name, type })),
      // SNIP-12 rev1：内建类型需在 types 中登记为空表（钱包侧按内建处理）。
      shortstring: [],
      felt252: [],
      bytes: [],
      amount: [],
    },
    primaryType: 'AuthorizeZChainKey',
    domain: buildStarknetDomain(ctx.chainId),
    message,
  };
  return { ok: true, typedData };
}

// ---------------------------------------------------------------------------
// 授权请求校验（签名**之前**的准入面：scope/时间窗/字段形状，fail-closed）
// ---------------------------------------------------------------------------

/**
 * 校验授权请求。
 * 字段：chainId, accountAddress('0x..' felt hex), delegatedPublicKey(hex33),
 * signatureScheme('secp256k1'), allowedScopes(string[]), perTxLimit/perDayLimit
 * (十进制|null), tableAllowlist(number[]|null), bindingId(hex32), nonce(int),
 * validAfter/validUntil(unix 秒 int)。
 */
export function validateAuthorizationRequest(req, ctx) {
  if (!req || typeof req !== 'object') return { ok: false, code: 'InvalidParams', reason: 'authorization request must be an object' };
  const fail = (code, reason) => ({ ok: false, code, reason });

  if (req.chainId !== ctx.chainId) return fail('NetworkMismatch', `chainId ${String(req.chainId)} != ${ctx.chainId}`);

  // Starknet 账户地址：felt 域内的 '0x' hex（仅形状/范围校验，非密码学）。
  const addr = req.accountAddress;
  if (typeof addr !== 'string' || !/^0x[0-9a-fA-F]{1,64}$/.test(addr)) {
    return fail('InvalidParams', 'accountAddress must be a felt hex string');
  }
  if (BigInt(addr) === 0n || BigInt(addr) >= FIELD_MODULUS) {
    return fail('InvalidParams', 'accountAddress must be a canonical felt (< field modulus, non-zero)');
  }

  const pk = req.delegatedPublicKey;
  if (typeof pk !== 'string' || !/^[0-9a-fA-F]{66}$/.test(pk)) {
    return fail('InvalidParams', 'delegatedPublicKey must be hex33 (compressed secp256k1)');
  }

  // scope：白名单内、非空、且不含会话密钥禁用类（withdraw）。
  const scopes = req.allowedScopes;
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return fail('InvalidParams', 'allowedScopes must be a non-empty array');
  }
  if (!scopes.every((s) => SESSION_SCOPES.includes(s))) {
    const unknown = scopes.filter((s) => !SESSION_SCOPES.includes(s));
    if (unknown.some((s) => FORBIDDEN_SCOPES.includes(s))) {
      return fail('ScopeForbidden', `session keys must never hold scope: ${unknown.filter((s) => FORBIDDEN_SCOPES.includes(s)).join(', ')}`);
    }
    return fail('ScopeUnknown', `unknown scopes: ${unknown.join(', ')}`);
  }

  // 限额（amount 形状；null = 不限，编码为 0）。
  if (amountStr(req.perTxLimit) == null) return fail('InvalidParams', 'perTxLimit must be a decimal u128 or null');
  if (amountStr(req.perDayLimit) == null) return fail('InvalidParams', 'perDayLimit must be a decimal u128 or null');

  // 桌白名单：null = 全桌；数组 = 白名单模式（可为空 = 全拒，wallet-core 语义）。
  let tableAllowlist = null;
  if (req.tableAllowlist != null) {
    if (!Array.isArray(req.tableAllowlist) || !req.tableAllowlist.every((t) => Number.isSafeInteger(t) && t >= 0)) {
      return fail('InvalidParams', 'tableAllowlist must be null or an array of non-negative integers');
    }
    tableAllowlist = req.tableAllowlist;
  }

  if (typeof req.bindingId !== 'string' || !/^[0-9a-fA-F]{64}$/.test(req.bindingId)) {
    return fail('InvalidParams', 'bindingId must be hex32');
  }
  const nonce = typeof req.nonce === 'string' ? Number(req.nonce) : req.nonce;
  if (!Number.isSafeInteger(nonce) || nonce < 0) return fail('InvalidParams', 'nonce must be a non-negative safe integer');

  const va = typeof req.validAfter === 'string' ? Number(req.validAfter) : req.validAfter;
  const vu = typeof req.validUntil === 'string' ? Number(req.validUntil) : req.validUntil;
  if (!Number.isSafeInteger(va) || !Number.isSafeInteger(vu)) return fail('InvalidParams', 'validAfter/validUntil must be integer unix seconds');
  if (va >= vu) return fail('InvalidParams', 'validAfter must be < validUntil');
  if (ctx.nowSec != null && vu <= ctx.nowSec) return fail('Expired', `validUntil ${vu} <= now ${ctx.nowSec}`);
  if (ctx.nowSec != null && va > ctx.nowSec) return fail('NotYetValid', `validAfter ${va} > now ${ctx.nowSec}`);

  return { ok: true, scopes: [...scopes], tableAllowlist };
}

// ---------------------------------------------------------------------------
// 签名归一化（Argent X / Braavos 返回 [r, s]（十进制或 hex）或 {r, s}）
// ---------------------------------------------------------------------------

/** 归一化 Stark 签名为 { r, s }（'0x' hex BigInt 字符串）。 */
export function normalizeStarkSignature(signature) {
  const parts = Array.isArray(signature) ? signature : signature && typeof signature === 'object' ? [signature.r, signature.s] : null;
  if (!parts || parts.length !== 2) return null;
  const toHex = (v) => {
    if (typeof v === 'string' && /^0x[0-9a-fA-F]+$/.test(v)) return `0x${BigInt(v).toString(16)}`;
    if (typeof v === 'string' && /^[0-9]+$/.test(v)) return `0x${BigInt(v).toString(16)}`;
    if (typeof v === 'bigint') return `0x${v.toString(16)}`;
    return null;
  };
  const r = toHex(parts[0]);
  const s = toHex(parts[1]);
  if (!r || !s) return null;
  return { r, s };
}

// ---------------------------------------------------------------------------
// 授权主流程：构造 typed data → 钱包签名 → wallet-core 形状 verifier 验签 → 登记
// ---------------------------------------------------------------------------

/**
 * 经 Starknet 钱包完成会话密钥授权（AuthorizeZChainKey）。
 *
 * @param {object} starknetWallet 检测到的钱包对象（isConnected/account/signMessage/getChainId）
 * @param {object} authorizationRequest 见 validateAuthorizationRequest
 * @param {object} deps
 * @param {string} deps.chainId            ZChain 网络 id（typed data domain.chainId）
 * @param {number} [deps.nowSec]           当前 unix 秒（缺省取系统时间）
 * @param {(args: {typedData, accountAddress, signature}) => Promise<{ok: boolean, digest?: string}>} deps.verifySignature
 *        **wallet-core 形状 verifier**（生产 = wallet-core 的 SNIP-12 摘要 +
 *        Stark 验签路径；测试 = mock。本文件绝不自行实现摘要/验签。）
 * @param {(binding: object) => Promise<{ok: boolean}>} deps.registerBinding
 *        授权登记（生产 = wallet-core BindingRegistry / 后台；测试 = 内存表）
 * @returns {Promise<{ok: true, bindingId, digest, walletChainId, binding} | {ok: false, code, reason}>}
 */
export async function authorizeSessionKeyViaStarknet(starknetWallet, authorizationRequest, deps) {
  const { chainId, verifySignature, registerBinding } = deps ?? {};
  const nowSec = deps?.nowSec ?? Math.floor(Date.now() / 1000);

  if (typeof verifySignature !== 'function' || typeof registerBinding !== 'function') {
    return { ok: false, code: 'InvalidArgument', reason: 'verifySignature/registerBinding (wallet-core shaped) are required' };
  }

  // (0) 钱包形状/连接态（fail-closed）。
  const desc = describeWallet(starknetWallet);
  if (!desc) return { ok: false, code: 'WalletUnsupported', reason: 'object does not look like a Starknet wallet (signMessage/getChainId required)' };
  if (!desc.isConnected) return { ok: false, code: 'WalletNotConnected', reason: 'Starknet wallet is not connected' };

  // (1) 请求准入（scope/时间窗/字段形状；签名之前拒绝，不让用户盲签坏请求）。
  const base = validateAuthorizationRequest(authorizationRequest, { chainId, nowSec });
  if (!base.ok) return base;

  // (2) 钱包链身份审计：wallet.getChainId() 返回钱包自己的链 id。若它本身是
  //     ZChain 托管网络 id（未来形态），必须与 domain 一致；否则如实记录、
  //     不冒充相等（Argent X/Braavos 对 ZChain domain.chainId 的真机行为属
  //     WALLET-ACC-1 真机矩阵）。
  let walletChainId = null;
  try {
    walletChainId = (await starknetWallet.getChainId()) ?? null;
  } catch (e) {
    return { ok: false, code: 'WalletChainIdUnavailable', reason: String(e?.message ?? e) };
  }
  if (typeof walletChainId === 'string' && walletChainId.startsWith('zchain:') && walletChainId !== `zchain:${chainId}`) {
    return { ok: false, code: 'NetworkMismatch', reason: `wallet chain ${walletChainId} != zchain:${chainId}` };
  }

  // (3) SNIP-12 typed data（wallet-core account_binding.rs 规范的 JSON 形状）。
  const built = buildAuthorizeTypedData(authorizationRequest, { chainId });
  if (!built.ok) return built;

  // (4) 钱包签名（signMessage 仅此一处使用；只签 typed data，不签任意 bytes）。
  let rawSignature;
  try {
    rawSignature = await starknetWallet.signMessage(built.typedData);
  } catch (e) {
    return { ok: false, code: 'UserRejected', reason: String(e?.message ?? e) };
  }
  const signature = normalizeStarkSignature(rawSignature);
  if (!signature) return { ok: false, code: 'SignatureInvalid', reason: 'wallet returned an unparsable signature' };

  // (5) 验签（wallet-core 形状 verifier：SNIP-12 摘要 + Stark 验签唯一入口）。
  let verified;
  try {
    verified = await verifySignature({ typedData: built.typedData, accountAddress: authorizationRequest.accountAddress, signature });
  } catch (e) {
    return { ok: false, code: 'VerifierRejected', reason: String(e?.message ?? e) };
  }
  if (!verified?.ok) {
    return { ok: false, code: 'SignatureRejected', reason: 'wallet-core rejected the Starknet signature' };
  }

  // (6) 登记授权（字段与 SNIP-12 message 一一对应 = wallet-core
  //     constraints_from_message 的镜像；binding_id 为登记主键）。
  const reqNonce = typeof authorizationRequest.nonce === 'string'
    ? Number(authorizationRequest.nonce)
    : authorizationRequest.nonce;
  const binding = {
    bindingId: authorizationRequest.bindingId.toLowerCase(),
    chainId,
    accountAddress: authorizationRequest.accountAddress.toLowerCase(),
    delegatedPublicKey: authorizationRequest.delegatedPublicKey.toLowerCase(),
    signatureScheme: authorizationRequest.signatureScheme ?? 'secp256k1',
    allowedScopes: base.scopes,
    perTxLimit: authorizationRequest.perTxLimit ?? null,
    perDayLimit: authorizationRequest.perDayLimit ?? null,
    tableAllowlist: base.tableAllowlist,
    nonce: reqNonce,
    validAfter: Number(authorizationRequest.validAfter),
    validUntil: Number(authorizationRequest.validUntil),
    walletChainId,
    digest: verified.digest ?? null,
  };
  const registered = await registerBinding(binding);
  if (!registered?.ok) {
    return { ok: false, code: registered?.code ?? 'BindingRejected', reason: registered?.reason ?? 'binding registration refused' };
  }
  return { ok: true, bindingId: binding.bindingId, digest: verified.digest ?? null, walletChainId, binding };
}
