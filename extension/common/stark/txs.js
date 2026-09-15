// =============================================================================
// extension/common/stark/txs.js — Starknet 交易记录本地账本（Extension 0.6）
//
// 与 EVM 层 txs.js 同一状态机形状：pending → succeeded/reverted（回执驱动）；
// 记录不含密钥材料。explorer 合并复用 history 归一思路（dev 链 txlist）。
// =============================================================================

export const MAX_TX_RECORDS = 500;

export function emptyTxStore() {
  return { byHash: {}, order: [] };
}

/** 新增 pending 记录（重复 hash 幂等跳过）。 */
export function addPendingTx(store, tx, nowMs) {
  if (!tx?.hash || typeof tx.hash !== 'string' || !tx.hash.startsWith('0x')) {
    return { ok: false, code: 'InvalidArgument', reason: 'tx hash 非法' };
  }
  if (store.byHash[tx.hash]) return { ok: true, store, entry: store.byHash[tx.hash] };
  const entry = {
    hash: tx.hash,
    chainId: tx.chainId ?? null,
    from: tx.from ?? null,
    to: tx.to ?? null,
    selector: tx.selector ?? null,
    calldataLen: tx.calldataLen ?? 0,
    valueHuman: tx.valueHuman ?? null,
    kind: tx.kind ?? 'contract', // transfer | contract
    methodLabel: tx.methodLabel ?? null,
    nonce: String(tx.nonce ?? ''),
    maxFee: String(tx.maxFee ?? '0'),
    status: 'pending',
    createdAtMs: nowMs,
    confirmedAtMs: null,
    blockNumber: null,
    actualFee: null,
    source: 'local',
  };
  const byHash = { ...store.byHash, [tx.hash]: entry };
  const order = [tx.hash, ...store.order].slice(0, MAX_TX_RECORDS);
  return { ok: true, store: cap({ byHash, order }), entry };
}

/** 回执落地：execution_status SUCCEEDED → succeeded，否则 reverted。 */
export function applyReceipt(store, hash, receipt, nowMs) {
  const entry = store.byHash[hash];
  if (!entry) return { ok: false, code: 'TxNotFound' };
  if (entry.status !== 'pending') return { ok: true, store, entry };
  const status = receipt?.execution_status === 'SUCCEEDED' || receipt?.status === 'ACCEPTED_ON_L2'
    ? 'succeeded'
    : receipt?.execution_status === 'REVERTED' ? 'reverted' : 'succeeded';
  const next = {
    ...entry,
    status,
    confirmedAtMs: nowMs,
    blockNumber: receipt?.block_number != null ? String(receipt.block_number) : entry.blockNumber,
    actualFee: receipt?.actual_fee?.amount != null
      ? String(receipt.actual_fee.amount)
      : (receipt?.actual_fee != null ? String(receipt.actual_fee) : null),
  };
  return { ok: true, store: { ...store, byHash: { ...store.byHash, [hash]: next } }, entry: next };
}

/** 视图（新 → 旧）。 */
export function txListView(store, { limit = 50 } = {}) {
  return store.order
    .map((h) => store.byHash[h])
    .filter(Boolean)
    .slice(0, limit)
    .map((t) => ({ ...t, explorerUrl: t.explorerUrl ?? null }));
}

/** 待确认 hash 列表。 */
export function pendingHashes(store) {
  return store.order.filter((h) => store.byHash[h]?.status === 'pending');
}

/** explorer 行（Etherscan 风格自端点）→ 归一记录；shape 非法 → null。 */
export function normalizeExplorerRow(row) {
  if (!row || typeof row.hash !== 'string' || !row.hash.startsWith('0x')) return null;
  const status = String(row.isError ?? '0') === '1' ? 'reverted'
    : (Number(row.confirmations ?? 0) > 0 ? 'succeeded' : 'pending');
  const ts = Number(row.timeStamp);
  return {
    hash: row.hash,
    from: row.from ?? null,
    to: row.to ?? null,
    selector: row.selector ?? null,
    kind: row.kind ?? 'contract',
    methodLabel: row.methodLabel ?? null,
    valueHuman: row.valueHuman ?? null,
    status,
    blockNumber: row.blockNumber != null ? String(row.blockNumber) : null,
    createdAtMs: Number.isFinite(ts) && ts > 0 ? ts * 1000 : null,
    confirmedAtMs: status !== 'pending' && Number.isFinite(ts) ? ts * 1000 : null,
    source: 'explorer',
  };
}

/** 合并本地记录与 explorer 行（hash 去重，本地状态优先；新 → 旧）。 */
export function mergeHistory(localRecords, explorerRows = []) {
  const byHash = new Map();
  for (const t of localRecords ?? []) byHash.set(t.hash, { ...t, source: t.source ?? 'local' });
  for (const row of explorerRows ?? []) {
    const norm = normalizeExplorerRow(row);
    if (!norm) continue;
    const existing = byHash.get(norm.hash);
    if (!existing) {
      byHash.set(norm.hash, norm);
      continue;
    }
    byHash.set(norm.hash, {
      ...existing,
      createdAtMs: existing.createdAtMs ?? norm.createdAtMs,
      confirmedAtMs: existing.confirmedAtMs ?? norm.confirmedAtMs,
      blockNumber: existing.blockNumber ?? norm.blockNumber,
    });
  }
  return [...byHash.values()].sort((a, b) => (b.createdAtMs ?? 0) - (a.createdAtMs ?? 0));
}

function cap(store) {
  const keep = new Set(store.order);
  const byHash = {};
  for (const [h, e] of Object.entries(store.byHash)) {
    if (keep.has(h)) byHash[h] = e;
  }
  return { byHash, order: store.order.slice(0, MAX_TX_RECORDS) };
}
