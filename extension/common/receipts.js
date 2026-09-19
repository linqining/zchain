// =============================================================================
// extension/common/receipts.js — 交易回执 inclusion 状态机（Extension 0.2）
//
// 对应 poker_l1::force_include 的协议语义（§5.3 / M3-ACC-6），**仅展示面**：
// - seen：用户侧拿到 SeenReceipt（validator 见证回执，poker_l1 签发）；
// - included：交易已进块（本地人工登记，扩展 0.2 无链上核对通道）；
// - 超 deadline（协议默认 10_000ms，poker_l1 DEFAULT_INCLUSION_DEADLINE_MS）
//   未 included → UI 提示"可经 L1 ForceInclude 路径强制包含"。
//
// 诚实边界（不虚标）：扩展 0.2 **不实现提交路径**（无 tx 广播、无 receipt
// 验签——SeenReceipt 的 secp256k1 验签在 wallet-core wasm 尚无入口）。状态
// 的来源全部如实标注：signed（本地签发时间）、seen（导入的 receipt，签名
// 未验证）、included（人工登记）。本模块只是纯状态机 + 判定函数。
//
// 纯函数、零依赖、无 IO、零密码学。
// =============================================================================

/** 强制包含期限默认值（毫秒）——与 poker_l1 DEFAULT_INCLUSION_DEADLINE_MS 一致。 */
export const DEFAULT_INCLUSION_DEADLINE_MS = 10_000;

/** 回执状态全集（signed → seen → included；单向）。 */
export const RECEIPT_STATES = ['signed', 'seen', 'included'];

/** 本地保存上限（防资源滥用；旧回执滚动丢弃）。 */
export const MAX_RECEIPTS = 20;

/**
 * 登记一条回执（签名成功后调用；digest 是确认摘要，chainId 参与展示）。
 * @returns {{ok:true, store}} | {ok:false, code, reason}
 */
export function openReceipt(store, { digest, kind, chainId, signedAtMs, deadlineMs, inputs }, now) {
  if (typeof digest !== 'string' || digest.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(digest)) {
    return { ok: false, code: 'InvalidArgument', reason: 'digest must be 64 hex' };
  }
  if (store?.[digest]) return { ok: false, code: 'DuplicateReceipt', reason: digest };
  const next = {
    ...store,
    [digest]: {
      digest: digest.toLowerCase(),
      kind: typeof kind === 'string' ? kind : 'unknown',
      chainId: typeof chainId === 'string' ? chainId : null,
      signedAtMs,
      deadlineMs: Number.isSafeInteger(deadlineMs) && deadlineMs > 0 ? deadlineMs : DEFAULT_INCLUSION_DEADLINE_MS,
      status: 'signed',
      seenAtMs: null,
      includedAtMs: null,
      // transfer 类收据携带输入 note（{commitment, amount}[]）：pendingSpendMap
      // 据此对在途支出做本地软锁（防同一批 note 被反复签名转出）。
      inputs: normalizeReceiptInputs(inputs),
      // 证据来源标注（诚实字段，UI 必须原样展示）：
      evidence: { seen: 'not_provided', included: 'local_manual_entry' },
      openedAt: now,
    },
  };
  return { ok: true, store: capStore(next) };
}

/** 收据输入 note 归一：只留 {commitment, amount}，其余丢弃（防脏字段入库）。 */
function normalizeReceiptInputs(inputs) {
  if (!Array.isArray(inputs)) return [];
  return inputs
    .filter((i) => i && typeof i.commitment === 'string' && i.commitment.length > 0)
    .map((i) => ({
      commitment: i.commitment,
      amount: Number.isFinite(Number(i.amount)) ? Number(i.amount) : null,
    }));
}

/**
 * 在途已花 note 软锁表（防双花，本地口径）：
 * transfer 收据在 signed/seen 状态期间，其输入 note 不得再次成为支出输入——
 * 链上 inclusion 才真正消费 note 并把找零记回本地库；devnet stub 没有
 * inclusion 回路，若不软锁，同一批 note 可被无限次签名转出（双花脚枪）。
 * included = 链上已结算：软锁退出（真实部署由 core 同步接管最终状态）。
 *
 * @returns {Map<string, number>} commitment -> 在途占用金额
 */
export function pendingSpendMap(store) {
  const map = new Map();
  for (const entry of Object.values(store ?? {})) {
    if (!entry || entry.kind !== 'transfer' || entry.status === 'included') continue;
    for (const inp of Array.isArray(entry.inputs) ? entry.inputs : []) {
      if (typeof inp?.commitment !== 'string' || inp.commitment.length === 0) continue;
      if (!map.has(inp.commitment)) {
        map.set(inp.commitment, Number.isFinite(inp.amount) ? inp.amount : 0);
      }
    }
  }
  return map;
}

/**
 * 导入 SeenReceipt（§5.3-1 形状）→ seen。
 * 形状校验（chain_id/tx_hash/seen_at_ms/validator_pubkey/signature 五字段）；
 * **签名不验证**（0.2 无 wasm 验签入口）——evidence 标注 `receipt_unverified`。
 */
export function applySeenReceipt(store, digest, receipt, now) {
  const entry = store?.[digest];
  if (!entry) return { ok: false, code: 'UnknownReceipt', reason: String(digest) };
  if (entry.status === 'included') {
    return { ok: false, code: 'InvalidTransition', reason: 'already included' };
  }
  const r = validateSeenReceiptShape(receipt);
  if (!r.ok) return r;
  const next = {
    ...store,
    [digest]: {
      ...entry,
      status: 'seen',
      seenAtMs: receipt.seen_at_ms,
      seenTxHash: receipt.tx_hash,
      evidence: { ...entry.evidence, seen: 'receipt_unverified_signature' },
      seenAppliedAt: now,
    },
  };
  return { ok: true, store: next, entry: next[digest] };
}

/** SeenReceipt 形状校验（只验形状与界，不验签）。 */
export function validateSeenReceiptShape(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { ok: false, code: 'InvalidArgument', reason: 'receipt must be an object' };
  }
  if (typeof receipt.chain_id !== 'string' || receipt.chain_id.length === 0 || receipt.chain_id.length > 64) {
    return { ok: false, code: 'InvalidArgument', reason: 'chain_id required' };
  }
  if (typeof receipt.tx_hash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(receipt.tx_hash)) {
    return { ok: false, code: 'InvalidArgument', reason: 'tx_hash must be 64 hex' };
  }
  if (!Number.isSafeInteger(receipt.seen_at_ms) || receipt.seen_at_ms < 0) {
    return { ok: false, code: 'InvalidArgument', reason: 'seen_at_ms must be a non-negative safe integer' };
  }
  if (typeof receipt.validator_pubkey !== 'string' || receipt.validator_pubkey.length === 0 || receipt.validator_pubkey.length > 132) {
    return { ok: false, code: 'InvalidArgument', reason: 'validator_pubkey required' };
  }
  if (!Array.isArray(receipt.signature) || receipt.signature.length === 0 || receipt.signature.length > 128) {
    return { ok: false, code: 'InvalidArgument', reason: 'signature must be a byte array' };
  }
  return { ok: true };
}

/**
 * 标记 included（**人工登记**；0.2 无链上核对通道，evidence 保持
 * `local_manual_entry` 标注）。
 */
export function markIncluded(store, digest, now) {
  const entry = store?.[digest];
  if (!entry) return { ok: false, code: 'UnknownReceipt', reason: String(digest) };
  if (entry.status === 'included') return { ok: false, code: 'InvalidTransition', reason: 'already included' };
  const next = {
    ...store,
    [digest]: {
      ...entry,
      status: 'included',
      includedAtMs: now,
      evidence: { ...entry.evidence, included: 'local_manual_entry' },
    },
  };
  return { ok: true, store: next, entry: next[digest] };
}

/**
 * poker_l1 `is_past_inclusion_deadline` 的同语义判定：
 * `deadline_ms > 0 && now > arrived_at + deadline`（deadline 0 = 禁用）。
 */
export function isPastInclusionDeadline(arrivedAtMs, nowMs, deadlineMs = DEFAULT_INCLUSION_DEADLINE_MS) {
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0) return false;
  if (!Number.isSafeInteger(arrivedAtMs)) return false;
  const sum = arrivedAtMs + deadlineMs;
  return sum <= Number.MAX_SAFE_INTEGER && nowMs > sum;
}

/**
 * UI 展示判定：状态位 + 是否超 deadline + 展示提示（超期未 included 时给
 * ForceInclude 提示——**仅协议状态展示，扩展不实现提交路径**）。
 */
export function inclusionView(receipt, now) {
  if (!receipt) return null;
  const anchorMs = receipt.status === 'signed' ? receipt.signedAtMs : receipt.seenAtMs;
  const pastDeadline =
    receipt.status !== 'included' &&
    isPastInclusionDeadline(anchorMs ?? receipt.signedAtMs, now, receipt.deadlineMs);
  let hint = null;
  if (pastDeadline) {
    hint =
      '已超强制包含期限：可经 L1 ForceInclude 路径（SeenReceipt + check_censorship）主张强制包含。本扩展 0.2 仅展示协议状态，不实现提交路径。';
  } else if (receipt.status === 'signed') {
    hint = `等待链上见证实回执（协议 deadline ${receipt.deadlineMs} ms）。`;
  }
  return {
    status: receipt.status,
    pastDeadline,
    deadlineMs: receipt.deadlineMs,
    evidence: receipt.evidence,
    hint,
  };
}

/** 回执滚动上限。 */
function capStore(store) {
  const keys = Object.keys(store);
  if (keys.length <= MAX_RECEIPTS) return store;
  const drop = keys
    .sort((a, b) => (store[a].openedAt ?? 0) - (store[b].openedAt ?? 0))
    .slice(0, keys.length - MAX_RECEIPTS);
  const next = { ...store };
  for (const k of drop) delete next[k];
  return next;
}
