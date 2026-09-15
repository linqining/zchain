// =============================================================================
// tests/e2e/starkdevchain.mjs — 本地 Starknet JSON-RPC 开发链（Extension 0.6）
//
// node:http 实现的最小 Starknet RPC 0.6 形状链：
//   - starknet_chainId/blockNumber/getNonce/call/add_invoke_transaction/
//     getTransactionReceipt
//   - add_invoke_transaction **独立验签**：重算交易哈希（Pedersen 元素链），
//     STARK curve ECDSA 验证（dev_faucet 注册的 pubkey）+ nonce + 余额/费用
//   - 内置 ERC-20 形状代币（name/symbol/decimals/balance_of/transfer，u256）
//   - dev_faucet（注册 pubkey + 出资）、dev_estimateFee、explorer txlist REST
// CORS/PNA 全开（扩展页/Service Worker fetch 需要）。
// =============================================================================

import { createServer } from 'node:http';
import {
  hexToBigInt, bigIntToHex, pedersenHash, computeHashOnElements, ecVerify,
  encodeShortString, starknetSelector, decodeShortString,
} from '../../common/stark/curve.js';

const TOKEN = {
  address: '0xc0de0000000000000000000000000000000070b19e6b9',
  name: 'Dev Stark Token',
  symbol: 'DST',
  decimals: 18,
};

const CHAIN_ID_FELT = '0x5a43444e'; // 'ZCDN'
const GAS_PRICE = 10n ** 10n; // 1 gwei（felt 粒度）

export async function startStarkDevChain({ port = 0 } = {}) {
  const state = {
    balances: new Map(),  // addr(minimal hex) → BigInt wei（代币最小单位，u256 简化为 251 位内）
    nonces: new Map(),    // addr → BigInt
    pubkeys: new Map(),   // addr → BigInt pubkey（dev_faucet 注册）
    txs: new Map(),       // hash → receipt 形状记录
    blocks: [],
  };

  // 地址键统一规范化为最小 hex（校验和/补零形式一律归一，避免键不一致）
  const norm = (a) => '0x' + hexToBigInt(a).toString(16);

  const selectorTransfer = starknetSelector('transfer');
  const selectorBalanceOf = starknetSelector('balance_of');
  const selectorName = starknetSelector('name');
  const selectorSymbol = starknetSelector('symbol');
  const selectorDecimals = starknetSelector('decimals');

  const balOf = (addr) => state.balances.get(norm(addr)) ?? 0n;
  const feltHex = (v) => bigIntToHex(v);
  const u256Pair = (v) => [feltHex(v & 0xffffffffffffffffffffffffffffffffn), feltHex(v >> 128n)];

  function u256ToBig(loHex, hiHex) {
    return hexToBigInt(loHex) | (hexToBigInt(hiHex ?? '0x0') << 128n);
  }

  /** 对 call（只读）执行代币语义。 */
  function doCall(request) {
    const to = String(request.contract_address ?? '').toLowerCase();
    const selector = hexToBigInt(request.entry_point_selector);
    const calldata = request.calldata ?? [];
    if (to !== TOKEN.address.toLowerCase()) {
      throw { message: `contract not found: ${to}` };
    }
    if (selector === selectorBalanceOf) {
      return u256Pair(balOf(calldata[0]));
    }
    if (selector === selectorName) return [feltHex(encodeShortString(TOKEN.name))];
    if (selector === selectorSymbol) return [feltHex(encodeShortString(TOKEN.symbol))];
    if (selector === selectorDecimals) return [feltHex(BigInt(TOKEN.decimals))];
    throw { message: `entry point not found: ${selector}` };
  }

  /** invoke 语义执行（验签已过）：transfer 转账 + 手续费扣减。 */
  function doInvoke({ sender, to, selector, calldata }) {
    const gasCost = GAS_PRICE * 30000n;
    const bal = balOf(sender);
    if (bal < gasCost) return { ok: false, error: 'insufficient balance for fee' };
    state.balances.set(sender.toLowerCase(), bal - gasCost);
    const logs = [];
    if (norm(to) === norm(TOKEN.address) && selector === selectorTransfer) {
      const recipient = norm(calldata[0]);
      const amount = u256ToBig(calldata[1], calldata[2]);
      const senderBal = balOf(sender);
      if (senderBal < amount) return { ok: false, error: 'ERC20: insufficient balance' };
      state.balances.set(sender.toLowerCase(), senderBal - amount);
      state.balances.set(recipient, balOf(recipient) + amount);
      logs.push({ kind: 'Transfer', from: sender, to: recipient, amount: amount.toString() });
      return { ok: true, logs };
    }
    return { ok: true, logs }; // 未知合约/selector：链级接受（dev 简化）
  }

  const handlers = {
    starknet_chainId: () => CHAIN_ID_FELT,
    starknet_blockNumber: () => '0x' + state.blocks.length.toString(16),
    starknet_getNonce: ([addr]) => '0x' + (state.nonces.get(norm(addr)) ?? 0n).toString(16),
    starknet_call: ([request]) => doCall(request),
    dev_faucet: ([addr, amountHex, pubKey]) => {
      const key = norm(addr);
      state.balances.set(key, balOf(key) + hexToBigInt(amountHex));
      if (pubKey) state.pubkeys.set(key, hexToBigInt(pubKey));
      return true;
    },
    dev_estimateFee: () => {
      const overall = GAS_PRICE * 30000n;
      return { gas_consumed: '0x7530', gas_price: feltHex(GAS_PRICE), overall_fee: feltHex(overall) };
    },
    starknet_estimateFee: () => {
      const overall = GAS_PRICE * 30000n;
      return { gas_consumed: '0x7530', gas_price: feltHex(GAS_PRICE), overall_fee: feltHex(overall) };
    },
    starknet_add_invoke_transaction: ([wrapper]) => {
      const inv = wrapper?.invoke_v1 ?? wrapper;
      const sender = norm(inv.sender_address);
      const registeredPub = state.pubkeys.get(sender);
      if (registeredPub === undefined) throw { message: `unregistered account: ${sender}` };
      const nonce = hexToBigInt(inv.nonce);
      const have = state.nonces.get(sender) ?? 0n;
      if (nonce !== have) throw { message: `nonce mismatch: have ${have}, tx ${nonce}` };
      const [rHex, sHex] = inv.signature ?? [];
      const maxFee = hexToBigInt(inv.max_fee ?? '0x0');
      // 链级独立验签：交易哈希重算（同 cairo-lang 公式）
      const txHash = computeHashOnElements([
        encodeShortString('invoke'), 1n, hexToBigInt(sender), 0n,
        computeHashOnElements((inv.calldata ?? []).map(hexToBigInt)),
        maxFee, hexToBigInt(CHAIN_ID_FELT), nonce,
      ]);
      const ok = ecVerify(registeredPub, txHash, hexToBigInt(rHex), hexToBigInt(sHex));
      if (!ok) throw { message: 'invalid signature' };
      // 执行
      const to = String(inv.calldata?.[0] ?? '');
      const selector = hexToBigInt(inv.calldata?.[1] ?? '0x0');
      const innerCalldata = (inv.calldata ?? []).slice(3);
      const res = doInvoke({ sender, to, selector, calldata: innerCalldata });
      const blockNumber = state.blocks.length + 1;
      state.nonces.set(sender, nonce + 1n);
      const executionStatus = res.ok ? 'SUCCEEDED' : 'REVERTED';
      if (!res.ok) {
        state.balances.set(sender, balOf(sender) + GAS_PRICE * 30000n); // 失败退费（dev 简化）
      }
      const receipt = {
        transaction_hash: feltHex(txHash),
        block_number: blockNumber,
        execution_status: executionStatus,
        finality_status: 'ACCEPTED_ON_L2',
        actual_fee: { amount: '0x' + (GAS_PRICE * 30000n).toString(16), unit: 'WEI' },
        logs: res.logs ?? [],
      };
      state.txs.set(receipt.transaction_hash, {
        hash: receipt.transaction_hash,
        from: sender, to, selector: feltHex(selector),
        nonce: nonce.toString(), maxFee: maxFee.toString(),
        blockNumber, executionStatus, timeStamp: Math.floor(Date.now() / 1000),
        valueHuman: null, kind: 'contract', confirmations: 1,
        isError: executionStatus === 'SUCCEEDED' ? '0' : '1',
      });
      state.blocks.push(blockNumber);
      return { transaction_hash: receipt.transaction_hash };
    },
    starknet_getTransactionReceipt: ([hash]) => {
      const t = state.txs.get(String(hash).toLowerCase());
      if (!t) throw { message: `tx hash not found: ${hash}` };
      return {
        transaction_hash: t.hash, block_number: t.blockNumber,
        execution_status: t.executionStatus, finality_status: 'ACCEPTED_ON_L2',
        actual_fee: { amount: '0x' + (GAS_PRICE * 30000n).toString(16), unit: 'WEI' },
      };
    },
    starknet_getTransactionByHash: ([hash]) => {
      const t = state.txs.get(String(hash).toLowerCase());
      if (!t) throw { message: 'tx hash not found' };
      return { transaction_hash: t.hash, status: 'ACCEPTED_ON_L2', block_number: t.blockNumber };
    },
  };

  const server = createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && url.pathname === '/api' && url.searchParams.get('module') === 'account') {
      const address = String(url.searchParams.get('address') ?? '').toLowerCase();
      const rows = [...state.txs.values()]
        .filter((t) => norm(t.from) === norm(address) || (t.to && norm(t.to) === norm(address)))
        .sort((a, b) => b.blockNumber - a.blockNumber);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: '1', message: 'OK', result: rows }));
      return;
    }

    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      let rpc;
      try { rpc = JSON.parse(body); } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad json' }));
        return;
      }
      const respond = (id, payload) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id, ...payload }));
      };
      const handler = handlers[rpc.method];
      if (!handler) {
        respond(rpc.id, { error: { code: -32601, message: `method not found: ${rpc.method}` } });
        return;
      }
      try {
        const result = handler(rpc.params ?? []);
        respond(rpc.id, { result });
      } catch (e) {
        respond(rpc.id, { error: { code: -32000, message: e.message ?? 'reverted' } });
      }
    });
  });

  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const address = server.address();
  return {
    url: `http://127.0.0.1:${address.port}`,
    port: address.port,
    token: TOKEN,
    state,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// 独立运行自检：node tests/e2e/starkdevchain.mjs
if (process.argv[1] && process.argv[1].endsWith('starkdevchain.mjs')) {
  const chain = await startStarkDevChain({ port: 9545 });
  console.log(`starkdevchain listening on ${chain.url}, token ${TOKEN.address}`);
  process.on('SIGINT', async () => { await chain.close(); process.exit(0); });
}
