// =============================================================================
// extension/common/sessions.js — SNIP-12 会话密钥授权簿与限额执行（Extension
// 0.3/0.4）
//
// 职责（plan §6.12.4 表行 Extension 0.3"SNIP-12 会话密钥授权" + 0.4"account
// binding registry、会话密钥撤销/过期、单笔/每日限额"）：
//   1. 授权请求草稿（scope 默认只勾 PLAY 与低风险牌局操作；withdraw 永不可选）
//      与字段准入（复用 adapters/starknet.js 的 SNIP-12 规范校验，不二次实现）；
//   2. 授权簿（registry）：登记 / 撤销（粘滞）/ 删除（显式用户动作）/ 状态视图；
//   3. **签名路径限额与约束执行**：origin 有会话密钥授权时，其签名请求必须
//      通过 binding 准入——判定顺序与 wallet-core `session_admission` 逐条
//      一致（撤销 → 换网 → 时间窗 → scope → 桌白名单 → 单笔限额 → 日限额），
//      fail-closed；本模块是 JS 第一层，wallet-core wasm
//      （`wallet_session_admit`）是第二层，两层独立校验。
//
// 执行语义（如实声明）：
//   - governing binding 选择：当前 origin + 当前 chain 下**最新登记**的、状态
//     属于 active/exhausted/revoked 的 binding。active/exhausted → 逐条强制；
//     revoked → 该 origin 的签名一律拒绝（撤销粘滞；只有用户在授权簿显式
//     删除记录才回到常规路径）；expired/not_yet_valid（自然时间窗外）→ 授权
//     不再适用，回到常规签名路径（origin 授权 + 显式确认不变）。
//   - 准入金额口径：预览的 amount_in（操作消耗总额；找零回自身也计入——
//     限额从严方向）。
//   - 日限额按 unix 天窗聚合（与 wallet-core now/86_400 一致），金额用
//     BigInt 十进制字符串比较（JS Number 只有 2^53 安全整数）。
//
// 纪律：纯函数、零依赖、无 IO、零密码学（delegated key 生成与 SNIP-12 摘要
// 唯一入口是 wallet-core wasm）；存储由调用方（background service worker）
// 持有，本模块只做判定并返回"下一状态"。
// =============================================================================

import {
  FORBIDDEN_SCOPES,
  SESSION_SCOPES,
  validateAuthorizationRequest,
} from '../adapters/starknet.js';

/** scope 名集合（wallet-core key_manager::Scope 名；withdraw 永不授权）。 */
export { FORBIDDEN_SCOPES, SESSION_SCOPES };

/** 创建授权页的默认勾选：PLAY 与低风险牌局操作（transfer 属玩家间转账，
 *  默认不勾但可显式勾选；withdraw 在 key_manager 即为会话密钥禁用类）。 */
export const DEFAULT_SESSION_SCOPES = ['play', 'buyin', 'bet', 'settle'];

/** 单账户授权簿上限（防资源滥用）。 */
export const MAX_SESSION_BINDINGS = 16;

/** 操作 kind → 会话 scope（wallet-core key_manager::Scope 名）。 */
export function operationScope(kind) {
  switch (kind) {
    case 'transfer': return 'transfer';
    case 'buy_in': return 'buyin';
    case 'settle': return 'settle';
    default: return null; // 未知 kind 无法准入（fail-closed；play/bet 类操作
    // 随对应 provider 面开放时在此登记）。
  }
}

/** 桌内操作判定（与 wallet-core scope_is_table_bound 一致）。 */
export function scopeIsTableBound(scope) {
  return scope === 'play' || scope === 'buyin' || scope === 'bet' || scope === 'settle';
}

// ---------------------------------------------------------------------------
// 授权请求草稿（0.3 popup"会话密钥"页）
// ---------------------------------------------------------------------------

/**
 * 构造授权请求草稿（签名/摘要构造之前；delegated key 由 wallet-core 生成，
 * bindingId 缺省时也由 wallet-core 生成——本函数不产生任何密钥材料）。
 *
 * @param {object} input {origin, chainId, accountAddress, allowedScopes?,
 *                        perTxLimit?, perDayLimit?, tableAllowlist?,
 *                        validitySec?, nowSec, nonce?}
 * @returns {{ok:true, request, defaults}} | {{ok:false, code, reason}}
 *   request 形状 = adapters/starknet.js validateAuthorizationRequest 的输入。
 */
export function draftAuthorization(input) {
  const fail = (code, reason) => ({ ok: false, code, reason });
  if (!input || typeof input !== 'object') return fail('InvalidArgument', 'input required');
  const nowSec = Number.isSafeInteger(input.nowSec) ? input.nowSec : Math.floor(Date.now() / 1000);
  const chainId = typeof input.chainId === 'string' ? input.chainId : '';
  if (!chainId) return fail('InvalidArgument', 'chainId required');
  const origin = typeof input.origin === 'string' ? input.origin.trim().toLowerCase() : '';
  if (!origin) return fail('InvalidArgument', 'origin required（授权面向的站点 origin）');

  // scope：默认低风险集；输入必须落在白名单内且不含禁用类。
  const scopes = Array.isArray(input.allowedScopes) && input.allowedScopes.length > 0
    ? input.allowedScopes
    : [...DEFAULT_SESSION_SCOPES];
  const unknown = scopes.filter((s) => !SESSION_SCOPES.includes(s));
  if (unknown.length > 0) {
    if (unknown.some((s) => FORBIDDEN_SCOPES.includes(s))) {
      return fail('ScopeForbidden', `会话密钥永不持有 scope：${unknown.filter((s) => FORBIDDEN_SCOPES.includes(s)).join(', ')}`);
    }
    return fail('ScopeUnknown', `未知 scope：${unknown.join(', ')}`);
  }

  // 限额：十进制正整数字符串或 null（不限）。0 视为未设置。
  const limit = (v) => {
    if (v == null || v === '') return null;
    const s = String(v).trim();
    if (!/^[0-9]+$/.test(s) || s === '0') return { err: '限额必须是十进制正整数或留空（不限）' };
    if (s.length > 20) return { err: '限额超出范围' };
    return { val: s };
  };
  const perTx = limit(input.perTxLimit);
  if (perTx?.err) return fail('InvalidArgument', perTx.err);
  const perDay = limit(input.perDayLimit);
  if (perDay?.err) return fail('InvalidArgument', perDay.err);
  if (perTx?.val && perDay?.val && BigInt(perTx.val) > BigInt(perDay.val)) {
    return fail('InvalidArgument', '单笔限额不得大于每日限额');
  }

  // 桌白名单：空 = 全桌（null）；逗号分隔非负整数。
  let tableAllowlist = null;
  if (typeof input.tableAllowlist === 'string' && input.tableAllowlist.trim() !== '') {
    const parts = input.tableAllowlist.split(',').map((t) => t.trim()).filter((t) => t !== '');
    if (!parts.every((t) => /^[0-9]+$/.test(t) && t.length <= 20)) {
      return fail('InvalidArgument', '桌白名单必须是非负整数（逗号分隔）');
    }
    tableAllowlist = parts.map((t) => Number(t));
  } else if (Array.isArray(input.tableAllowlist)) {
    if (!input.tableAllowlist.every((t) => Number.isSafeInteger(t) && t >= 0)) {
      return fail('InvalidArgument', '桌白名单必须是非负整数数组');
    }
    tableAllowlist = [...input.tableAllowlist];
  }

  const validitySec = Number.isSafeInteger(input.validitySec) && input.validitySec > 0
    ? input.validitySec
    : 24 * 60 * 60; // 默认 24h
  if (validitySec > 365 * 24 * 60 * 60) return fail('InvalidArgument', '有效期不得超过 365 天');

  return {
    ok: true,
    request: {
      chainId,
      accountAddress: input.accountAddress,
      allowedScopes: scopes,
      perTxLimit: perTx?.val ?? null,
      perDayLimit: perDay?.val ?? null,
      tableAllowlist,
      nonce: Number.isSafeInteger(input.nonce) ? input.nonce : nowSec,
      validAfter: nowSec,
      validUntil: nowSec + validitySec,
    },
    defaults: { origin, validitySec },
  };
}

/**
 * 字段准入（delegated key 生成之后、登记之前；直接复用 adapters/starknet.js
 * 的 SNIP-12 规范校验——accountAddress felt 形状、delegatedPublicKey hex33、
 * 时间窗先后、scope 白名单等）。
 */
export function validateDraft(request) {
  return validateAuthorizationRequest(request, {
    chainId: request?.chainId,
    nowSec: Number.isSafeInteger(request?.validAfter) ? request.validAfter : undefined,
  });
}

// ---------------------------------------------------------------------------
// 授权簿（registry；storage 由调用方持有：{ [bindingId]: binding }）
// ---------------------------------------------------------------------------

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** 空 registry。 */
export function emptyBindingStore() {
  return {};
}

/** binding 记录形状校验（登记入口 fail-closed；字段与 SNIP-12 message 镜像）。 */
export function validateBindingRecord(binding) {
  if (!isPlainObject(binding)) return { ok: false, code: 'InvalidArgument', reason: 'binding must be an object' };
  if (typeof binding.bindingId !== 'string' || !/^[0-9a-f]{64}$/.test(binding.bindingId)) {
    return { ok: false, code: 'InvalidArgument', reason: 'bindingId must be 64 lowercase hex' };
  }
  if (typeof binding.chainId !== 'string' || binding.chainId.length === 0) {
    return { ok: false, code: 'InvalidArgument', reason: 'chainId required' };
  }
  if (typeof binding.origin !== 'string' || binding.origin.length === 0) {
    return { ok: false, code: 'InvalidArgument', reason: 'origin required' };
  }
  if (typeof binding.delegatedPublicKey !== 'string' || !/^[0-9a-f]{66}$/.test(binding.delegatedPublicKey)) {
    return { ok: false, code: 'InvalidArgument', reason: 'delegatedPublicKey must be 66 lowercase hex' };
  }
  if (!Array.isArray(binding.allowedScopes) || binding.allowedScopes.length === 0
    || !binding.allowedScopes.every((s) => SESSION_SCOPES.includes(s))) {
    return { ok: false, code: 'InvalidArgument', reason: 'allowedScopes must be a non-empty whitelist subset' };
  }
  for (const k of ['perTxLimit', 'perDayLimit']) {
    const v = binding[k];
    if (v != null && (typeof v !== 'string' || !/^[0-9]+$/.test(v))) {
      return { ok: false, code: 'InvalidArgument', reason: `${k} must be a decimal string or null` };
    }
  }
  if (binding.tableAllowlist != null
    && (!Array.isArray(binding.tableAllowlist) || !binding.tableAllowlist.every((t) => Number.isSafeInteger(t) && t >= 0))) {
    return { ok: false, code: 'InvalidArgument', reason: 'tableAllowlist must be null or non-negative integers' };
  }
  for (const k of ['nonce', 'validAfter', 'validUntil']) {
    if (!Number.isSafeInteger(binding[k]) || binding[k] < 0) {
      return { ok: false, code: 'InvalidArgument', reason: `${k} must be a non-negative integer` };
    }
  }
  if (binding.validAfter >= binding.validUntil) {
    return { ok: false, code: 'InvalidArgument', reason: 'validAfter must be < validUntil' };
  }
  return { ok: true };
}

/**
 * 登记/更新 binding（幂等 upsert，主键 bindingId；同 id 重授权替换为最新）。
 * @returns {{ok:true, store, binding}} | {{ok:false, code, reason}}
 */
export function upsertBinding(store, binding) {
  if (!isPlainObject(store)) return { ok: false, code: 'InvalidArgument', reason: 'bad store' };
  const shape = validateBindingRecord(binding);
  if (!shape.ok) return shape;
  if (store[binding.bindingId] == null && Object.keys(store).length >= MAX_SESSION_BINDINGS) {
    return { ok: false, code: 'BindingLimitReached', reason: `max ${MAX_SESSION_BINDINGS} bindings` };
  }
  const record = {
    origin: binding.origin,
    chainId: binding.chainId,
    accountAddress: binding.accountAddress,
    delegatedPublicKey: binding.delegatedPublicKey,
    signatureScheme: binding.signatureScheme ?? 'secp256k1',
    allowedScopes: [...binding.allowedScopes],
    perTxLimit: binding.perTxLimit ?? null,
    perDayLimit: binding.perDayLimit ?? null,
    tableAllowlist: binding.tableAllowlist == null ? null : [...binding.tableAllowlist],
    nonce: binding.nonce,
    validAfter: binding.validAfter,
    validUntil: binding.validUntil,
    bindingId: binding.bindingId,
    digest: typeof binding.digest === 'string' ? binding.digest : null,
    // 登记来源（诚实字段）：devnet 入口形态 = 本地登记，链侧 admission 登记未接。
    evidence: typeof binding.evidence === 'string' ? binding.evidence : 'devnet_local_entry',
    registeredAt: Number.isSafeInteger(binding.registeredAt) ? binding.registeredAt : Date.now(),
    revoked: false,
    revokedAt: null,
    dailyUsedDay: Number.isSafeInteger(binding.dailyUsedDay) ? binding.dailyUsedDay : 0,
    dailyUsedAmount: typeof binding.dailyUsedAmount === 'string' ? binding.dailyUsedAmount : '0',
  };
  return { ok: true, store: { ...store, [record.bindingId]: record }, binding: record };
}

/** 撤销（粘滞；幂等——重复撤销返回成功，不改变已撤销态）。 */
export function revokeBinding(store, bindingId, nowSec) {
  const b = store?.[bindingId];
  if (!b) return { ok: false, code: 'UnknownBinding', reason: String(bindingId) };
  if (b.revoked) return { ok: true, store, binding: b, alreadyRevoked: true };
  const next = { ...store, [bindingId]: { ...b, revoked: true, revokedAt: nowSec ?? Math.floor(Date.now() / 1000) } };
  return { ok: true, store: next, binding: next[bindingId] };
}

/** 删除记录（显式用户动作；撤销粘滞态的唯一清除路径）。 */
export function deleteBinding(store, bindingId) {
  if (!store?.[bindingId]) return { ok: false, code: 'UnknownBinding', reason: String(bindingId) };
  const next = { ...store };
  delete next[bindingId];
  return { ok: true, store: next };
}

/**
 * binding 展示状态（UI 用；wallet-core 状态机把 not_yet_valid 归并进
 * expired，这里区分开供 registry 页展示，enforcement 语义仍以 wallet-core
 * 准入判定为准）。
 */
export function bindingStatus(binding, nowSec) {
  if (!isPlainObject(binding)) return 'unknown';
  if (binding.revoked) return 'revoked';
  if (typeof nowSec !== 'number') return 'unknown';
  if (nowSec < binding.validAfter) return 'not_yet_valid';
  if (nowSec >= binding.validUntil) return 'expired';
  if (binding.perDayLimit != null) {
    const used = binding.dailyUsedDay === Math.floor(nowSec / 86_400)
      ? BigInt(binding.dailyUsedAmount ?? '0')
      : 0n;
    if (used >= BigInt(binding.perDayLimit)) return 'exhausted';
  }
  return 'active';
}

/** 某 origin + chain 下的 binding（按登记时间倒序）。 */
export function bindingsForOrigin(store, origin, chainId) {
  return Object.values(store ?? {})
    .filter((b) => b.origin === origin && b.chainId === chainId)
    .sort((a, b) => (b.registeredAt ?? 0) - (a.registeredAt ?? 0));
}

/**
 * governing binding：当前 origin + chain 下最新登记的 active/exhausted/revoked
 * binding（见文件头"执行语义"）。无 → null（该 origin 走常规签名路径）。
 */
export function governingBinding(store, origin, chainId, nowSec) {
  const enforcing = bindingsForOrigin(store, origin, chainId)
    .filter((b) => ['active', 'exhausted', 'revoked'].includes(bindingStatus(b, nowSec)));
  return enforcing[0] ?? null;
}

// ---------------------------------------------------------------------------
// 签名路径执行（JS 第一层；wallet-core wasm `wallet_session_admit` 是第二层）
// ---------------------------------------------------------------------------

/**
 * 对一笔待签操作执行 binding 准入（判定顺序与 wallet-core
 * session_admission 逐条一致，fail-closed）。
 *
 * @param binding  governing binding 记录
 * @param op       {kind, tableId?: number|string|null, amountIn: 十进制字符串}
 * @param ctx      {chainId, nowSec}
 * @returns {{ok:true, scope, amount, enforced:true}} |
 *          {{ok:false, code, reason}}
 */
export function admitOperation(binding, op, ctx) {
  const fail = (code, reason) => ({ ok: false, code, reason });
  if (!isPlainObject(binding) || !isPlainObject(op) || !isPlainObject(ctx)) {
    return fail('InvalidArgument', 'binding/op/ctx required');
  }
  const nowSec = ctx.nowSec;
  const amount = typeof op.amountIn === 'string' && /^[0-9]+$/.test(op.amountIn) ? op.amountIn : null;
  if (amount == null) return fail('InvalidArgument', 'amountIn must be a decimal string');

  // (1) 撤销粘滞（最先判：撤销后任何窗口/限额讨论都无效）。
  if (binding.revoked) return fail('SessionRevoked', '会话密钥授权已撤销（粘滞；可在授权簿删除记录后恢复常规路径）');
  // (2) 换网（chain_id 逐字一致）。
  if (binding.chainId !== ctx.chainId) return fail('SessionChainMismatch', `授权 chain ${binding.chainId} != 当前 ${ctx.chainId}`);
  // (3) 时间窗 [valid_after, valid_until)。
  if (nowSec < binding.validAfter) return fail('SessionNotYetValid', `授权生效时间未到（${binding.validAfter}）`);
  if (nowSec >= binding.validUntil) return fail('SessionExpired', '授权已过有效期');
  // (4) scope 白名单。
  const scope = operationScope(op.kind);
  if (scope == null) return fail('SessionScopeNotAllowed', `操作 kind ${String(op.kind)} 无法映射到会话 scope（fail-closed）`);
  if (!binding.allowedScopes.includes(scope)) return fail('SessionScopeNotAllowed', `scope "${scope}" 不在授权集 [${binding.allowedScopes.join(', ')}]`);
  // (5) 桌白名单（只约束桌内操作；白名单模式下缺桌 id 即拒绝）。
  if (binding.tableAllowlist != null) {
    if (scopeIsTableBound(scope)) {
      const table = typeof op.tableId === 'string' && /^[0-9]+$/.test(op.tableId) ? Number(op.tableId) : op.tableId;
      if (!Number.isSafeInteger(table) || !binding.tableAllowlist.includes(table)) {
        return fail('SessionTableNotAllowed', `桌 ${String(op.tableId ?? '（缺失）')} 不在授权白名单`);
      }
    }
  }
  // (6) 单笔限额。
  if (binding.perTxLimit != null && BigInt(amount) > BigInt(binding.perTxLimit)) {
    return fail('SessionOverPerTxLimit', `单笔 ${amount} 超过授权限额 ${binding.perTxLimit}`);
  }
  // (7) 日限额（unix 天窗聚合；跨天窗清零）。
  if (binding.perDayLimit != null) {
    const today = Math.floor(nowSec / 86_400);
    const used = binding.dailyUsedDay === today ? BigInt(binding.dailyUsedAmount ?? '0') : 0n;
    if (used + BigInt(amount) > BigInt(binding.perDayLimit)) {
      return fail('SessionOverDailyLimit', `当日累计 ${used + BigInt(amount)} 将超过授权日限额 ${binding.perDayLimit}`);
    }
  }
  return { ok: true, scope, amount, enforced: true };
}

/**
 * 记账一笔已授权花费（日限聚合；跨天自动开新窗；金额走十进制字符串 BigInt）。
 * @returns {{ok:true, store, binding}} | {{ok:false, code, reason}}
 */
export function recordSpend(store, bindingId, amountIn, nowSec) {
  const b = store?.[bindingId];
  if (!b) return { ok: false, code: 'UnknownBinding', reason: String(bindingId) };
  if (typeof amountIn !== 'string' || !/^[0-9]+$/.test(amountIn)) {
    return { ok: false, code: 'InvalidArgument', reason: 'amount must be a decimal string' };
  }
  const today = Math.floor(nowSec / 86_400);
  const used = b.dailyUsedDay === today ? BigInt(b.dailyUsedAmount ?? '0') : 0n;
  const nextAmount = (used + BigInt(amountIn)).toString();
  const next = { ...store, [bindingId]: { ...b, dailyUsedDay: today, dailyUsedAmount: nextAmount } };
  return { ok: true, store: next, binding: next[bindingId] };
}

/** registry 页行视图（脱敏：无密钥材料；状态/余量按当前时间投影）。 */
export function bindingView(binding, nowSec) {
  const status = bindingStatus(binding, nowSec);
  const day = Math.floor((nowSec ?? 0) / 86_400);
  const usedToday = binding.dailyUsedDay === day ? BigInt(binding.dailyUsedAmount ?? '0') : 0n;
  return {
    bindingId: binding.bindingId,
    origin: binding.origin,
    chainId: binding.chainId,
    accountAddress: binding.accountAddress,
    delegatedPublicKey: binding.delegatedPublicKey,
    allowedScopes: [...(binding.allowedScopes ?? [])],
    perTxLimit: binding.perTxLimit ?? null,
    perDayLimit: binding.perDayLimit ?? null,
    dailyUsedToday: usedToday.toString(),
    tableAllowlist: binding.tableAllowlist == null ? null : [...binding.tableAllowlist],
    validAfter: binding.validAfter,
    validUntil: binding.validUntil,
    status,
    evidence: binding.evidence ?? null,
    digest: binding.digest ?? null,
    registeredAt: binding.registeredAt ?? null,
    revokedAt: binding.revokedAt ?? null,
  };
}
