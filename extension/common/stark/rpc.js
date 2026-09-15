// =============================================================================
// extension/common/stark/rpc.js — Starknet JSON-RPC 客户端（Extension 0.6）
//
// 注入式 fetch；方法面 = 钱包所需子集（RPC 0.6 形状）：
//   starknet_chainId / blockNumber / getNonce / call / add_invoke_transaction /
//   getTransactionReceipt / getTransactionByHash，dev 链扩展 dev_faucet。
// 稳定错误码：RpcUnreachable / RpcError / RpcBadShape（与 EVM 层同一纪律）。
// =============================================================================

import { hexToBigInt, bigIntToHex, decodeShortString } from './curve.js';

export class StarknetRpc {
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
      const err = new Error(`RPC 不可达：${this.url}${cause}`);
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

  /** 链 ID（felt）→ 可读字符串（如 'SN_MAIN'）。 */
  async chainId() {
    const hex = await this.request('starknet_chainId');
    return decodeShortString(hex);
  }

  async chainIdHex() {
    return this.request('starknet_chainId');
  }

  async blockNumber() {
    const n = await this.request('starknet_blockNumber');
    return Number(BigInt(n));
  }

  async getNonce(address) {
    return this.request('starknet_getNonce', [address]);
  }

  /** 只读调用：request = {contract_address, entry_point_selector, calldata}。 */
  async call(request, blockId = 'latest') {
    return this.request('starknet_call', [request, blockId]);
  }

  async addInvokeTransaction(invocation) {
    return this.request('starknet_add_invoke_transaction', [{ invoke_v1: invocation }]);
  }

  async getTransactionReceipt(txHash) {
    return this.request('starknet_getTransactionReceipt', [txHash]);
  }

  async getTransactionByHash(txHash) {
    return this.request('starknet_getTransactionByHash', [txHash]);
  }

  /** dev 链水龙头（注册 pubkey + 出资）。 */
  async devFaucet(address, amountHex, pubKey) {
    return this.request('dev_faucet', [address, amountHex, pubKey]);
  }
}

/** felt 数组 → 十进制字符串数组（UI 展示/存储用）。 */
export function feltsToDecimal(felts) {
  return (felts ?? []).map((f) => hexToBigInt(f).toString());
}

/** 十进制/数字字符串数组 → felt hex 数组。 */
export function decimalsToFelts(decimals) {
  return (decimals ?? []).map((d) => bigIntToHex(BigInt(d)));
}
