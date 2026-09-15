// =============================================================================
// extension/common/evm/history.js — 交易记录合并视图（Extension 0.5）
//
// 纯函数：本地账本（txs.js）+ 可选 explorer API（Etherscan 兼容
// ?module=account&action=txlist）→ 归一化合并视图（按 hash 去重，本地
// 回执状态优先）。注入式 fetch。
// =============================================================================

import { formatUnits } from './crypto.js';

/**
 * Etherscan 兼容 txlist 一行 → 归一记录。shape 非法返回 null（不虚构）。
 */
export function normalizeExplorerRow(row, { nativeDecimals = 18 } = {}) {
  if (!row || typeof row.hash !== 'string' || !row.hash.startsWith('0x')) return null;
  const err = String(row.isError ?? '0') === '1';
  const status = err ? 'failed' : (Number(row.confirmations ?? 0) > 0 ? 'confirmed' : 'pending');
  const ts = Number(row.timeStamp);
  return {
    hash: row.hash,
    from: row.from ? String(row.from) : null,
    to: row.to ? String(row.to) : null,
    value: String(row.value ?? '0'),
    valueHuman: formatUnits(String(row.value ?? '0'), nativeDecimals),
    kind: row.input && row.input !== '0x' ? 'contract' : 'transfer',
    methodLabel: null,
    status,
    blockNumber: row.blockNumber != null ? String(row.blockNumber) : null,
    gasUsed: row.gasUsed != null ? String(row.gasUsed) : null,
    gasPrice: row.gasPrice != null ? String(row.gasPrice) : null,
    createdAtMs: Number.isFinite(ts) && ts > 0 ? ts * 1000 : null,
    confirmedAtMs: status === 'confirmed' && Number.isFinite(ts) ? ts * 1000 : null,
    source: 'explorer',
  };
}

/**
 * 合并本地记录与 explorer 行：hash 去重（本地优先），按时间新 → 旧。
 * @returns {Array} 归一记录
 */
export function mergeHistory(localRecords, explorerRows = []) {
  const byHash = new Map();
  for (const t of localRecords ?? []) {
    byHash.set(t.hash, { ...t, source: t.source ?? 'local' });
  }
  for (const row of explorerRows ?? []) {
    const norm = normalizeExplorerRow(row);
    if (!norm) continue;
    const existing = byHash.get(norm.hash);
    if (!existing) {
      byHash.set(norm.hash, norm);
      continue;
    }
    // 本地记录补 explorer 的时间戳/区块（状态仍以本地回执为准）
    byHash.set(norm.hash, {
      ...existing,
      createdAtMs: existing.createdAtMs ?? norm.createdAtMs,
      confirmedAtMs: existing.confirmedAtMs ?? norm.confirmedAtMs,
      blockNumber: existing.blockNumber ?? norm.blockNumber,
    });
  }
  return [...byHash.values()].sort(
    (a, b) => (b.createdAtMs ?? 0) - (a.createdAtMs ?? 0),
  );
}

/**
 * 拉取 explorer txlist（Etherscan 兼容）。任何失败 → {ok:false, code}，
 * 不抛异常（历史查询不阻塞钱包其他功能）。
 */
export async function fetchExplorerHistory({ apiUrl, address, fetchImpl = globalThis.fetch.bind(globalThis), timeoutMs = 8000 }) {
  try {
    const url = `${apiUrl}${apiUrl.includes('?') ? '&' : '?'}module=account&action=txlist&address=${encodeURIComponent(address)}&sort=desc&page=1&offset=50`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl(url, { signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) return { ok: false, code: 'ExplorerHttpError', status: res.status };
    const json = await res.json();
    if (json?.status !== '1' || !Array.isArray(json?.result)) {
      // Etherscan 风格：status 0 = 无记录/错误；如实返回空集并带原因
      return { ok: true, rows: [], reason: json?.message ?? 'no result' };
    }
    return { ok: true, rows: json.result };
  } catch (e) {
    return { ok: false, code: e?.name === 'AbortError' ? 'ExplorerTimeout' : 'ExplorerUnreachable' };
  }
}
