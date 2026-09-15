// =============================================================================
// extension/common/evm/rpc.js — JSON-RPC 客户端（Extension 0.5）
//
// 注入式 fetch（可测）；稳定错误码：RpcUnreachable / RpcError / RpcBadShape。
// 只暴露钱包用到的方法面（余额/nonce/gas/call/sendRaw/回执/区块）。
// =============================================================================

// 本文件不依赖 crypto.js：hex quantity 校验就地完成（允许奇数长度）。

export class JsonRpcClient {
  constructor(url, fetchImpl = globalThis.fetch.bind(globalThis)) {
    if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
      const e = new Error('RPC URL 非法');
      e.code = 'InvalidArgument';
      throw e;
    }
    this.url = url;
    this.fetchImpl = fetchImpl;
    this.nextId = 1;
  }

  async request(method, params = []) {
    let res;
    const body = JSON.stringify({ jsonrpc: '2.0', id: this.nextId++, method, params });
    try {
      res = await this.fetchImpl(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
    } catch (e) {
      const cause = e?.cause ? ` (${String(e.cause?.message ?? e.cause).slice(0, 160)})` : '';
      const stack0 = typeof e?.stack === 'string' ? ` [${e.stack.split('\n')[0].slice(0, 120)}]` : '';
      const err = new Error(`RPC 不可达：${this.url}${cause}${stack0}`);
      err.code = 'RpcUnreachable';
      throw err;
    }
    if (!res.ok) {
      const e = new Error(`RPC HTTP ${res.status}`);
      e.code = 'RpcError';
      throw e;
    }
    let json;
    try {
      json = await res.json();
    } catch {
      const e = new Error('RPC 响应不是 JSON');
      e.code = 'RpcBadShape';
      throw e;
    }
    if (json?.error) {
      const e = new Error(`RPC ${method} 失败：${json.error.message ?? JSON.stringify(json.error)}`);
      e.code = 'RpcError';
      e.data = json.error.data;
      throw e;
    }
    if (!('result' in (json ?? {}))) {
      const e = new Error('RPC 响应缺少 result');
      e.code = 'RpcBadShape';
      throw e;
    }
    return json.result;
  }

  // ---- 方法面 ----

  async chainId() {
    const hex = await this.request('eth_chainId');
    if (!/^0x[0-9a-f]+$/i.test(String(hex))) throw badShape('eth_chainId');
    return Number(BigInt(hex));
  }

  async getBalance(address, tag = 'latest') {
    return this.request('eth_getBalance', [address, tag]);
  }

  async getTransactionCount(address, tag = 'latest') {
    return this.request('eth_getTransactionCount', [address, tag]);
  }

  async gasPrice() {
    return this.request('eth_gasPrice');
  }

  async estimateGas(tx) {
    return this.request('eth_estimateGas', [tx]);
  }

  async call(tx, tag = 'latest') {
    return this.request('eth_call', [tx, tag]);
  }

  async sendRawTransaction(rawHex) {
    return this.request('eth_sendRawTransaction', [rawHex]);
  }

  async getTransactionReceipt(hash) {
    return this.request('eth_getTransactionReceipt', [hash]);
  }

  async getTransactionByHash(hash) {
    return this.request('eth_getTransactionByHash', [hash]);
  }
}

function badShape(method) {
  const e = new Error(`RPC ${method} 响应形状非法`);
  e.code = 'RpcBadShape';
  return e;
}

/** 规范化 hex 数量（0x… → BigInt；hex quantity 允许奇数长度）。'0x'/缺省 → 0n。 */
export function hexQtyToBigInt(hex) {
  if (hex == null) return 0n;
  if (typeof hex === 'bigint') return hex;
  if (typeof hex === 'number') return BigInt(Math.trunc(hex));
  const h = String(hex).trim().toLowerCase();
  if (h === '0x') return 0n;
  if (!/^0x[0-9a-f]+$/.test(h)) throw badShape('hex quantity');
  return BigInt(h);
}
