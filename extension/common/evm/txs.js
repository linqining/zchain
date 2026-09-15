// =============================================================================
// extension/common/evm/txs.js — 交易记录本地账本（Extension 0.5）
//
// 纯函数状态机（node --test 直覆盖）：pending → confirmed/failed（回执驱动）；
// 本地登记保证"发过的交易可查"，链上回执/探索器数据由 history.js 合并。
// 记录不含任何密钥材料。
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
    value: String(tx.value ?? '0'),
    data: typeof tx.data === 'string' && tx.data !== '0x' ? tx.data : null,
    nonce: String(tx.nonce ?? ''),
    gasPrice: String(tx.gasPrice ?? ''),
    gasLimit: String(tx.gasLimit ?? ''),
    kind: tx.kind ?? 'transfer', // transfer | contract
    methodLabel: tx.methodLabel ?? null,
    decodedArgs: tx.decodedArgs ?? null,
    status: 'pending',
    createdAtMs: nowMs,
    confirmedAtMs: null,
    blockNumber: null,
    gasUsed: null,
    effectiveGasPrice: null,
    logs: 0,
    source: 'local',
  };
  const byHash = { ...store.byHash, [tx.hash]: entry };
  const order = [tx.hash, ...store.order].slice(0, MAX_TX_RECORDS);
  return { ok: true, store: cap({ byHash, order }), entry };
}

/** hex 数量 → 十进制字符串（已是十进制/空值则原样）。 */
function qtyToDecimal(v) {
  if (v == null) return null;
  const s = String(v);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s).toString();
  return s;
}

/** 回执落地：status '0x1' → confirmed，否则 failed。未知 hash → ok:false。 */
export function applyReceipt(store, hash, receipt, nowMs) {
  const entry = store.byHash[hash];
  if (!entry) return { ok: false, code: 'TxNotFound' };
  if (entry.status !== 'pending') return { ok: true, store, entry };
  const statusOk = receipt?.status === '0x1' || receipt?.status === 1;
  const next = {
    ...entry,
    status: statusOk ? 'confirmed' : 'failed',
    confirmedAtMs: nowMs,
    blockNumber: qtyToDecimal(receipt?.blockNumber) ?? entry.blockNumber,
    gasUsed: qtyToDecimal(receipt?.gasUsed),
    effectiveGasPrice: qtyToDecimal(receipt?.effectiveGasPrice),
    logs: Array.isArray(receipt?.logs) ? receipt.logs.length : 0,
  };
  return { ok: true, store: { ...store, byHash: { ...store.byHash, [hash]: next } }, entry: next };
}

/** 视图（新 → 旧；含展示字段）。 */
export function txListView(store, { limit = 50 } = {}) {
  return store.order
    .map((h) => store.byHash[h])
    .filter(Boolean)
    .slice(0, limit)
    .map((t) => ({
      hash: t.hash,
      chainId: t.chainId,
      from: t.from,
      to: t.to,
      value: t.value,
      kind: t.kind,
      methodLabel: t.methodLabel,
      decodedArgs: t.decodedArgs,
      status: t.status,
      nonce: t.nonce,
      blockNumber: t.blockNumber,
      gasUsed: t.gasUsed,
      gasPrice: t.gasPrice,
      createdAtMs: t.createdAtMs,
      confirmedAtMs: t.confirmedAtMs,
      logs: t.logs,
      source: t.source,
      explorerUrl: t.explorerUrl ?? null,
    }));
}

function cap(store) {
  const keep = new Set(store.order);
  const byHash = {};
  for (const [h, e] of Object.entries(store.byHash)) {
    if (keep.has(h)) byHash[h] = e;
  }
  return { byHash, order: store.order.slice(0, MAX_TX_RECORDS) };
}

/** 待确认的 hash 列表（回执轮询用）。 */
export function pendingHashes(store) {
  return store.order.filter((h) => store.byHash[h]?.status === 'pending');
}
