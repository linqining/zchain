// =============================================================================
// tests/e2e/devchain.mjs — 本地 EVM 开发链（Extension 0.5 e2e / 本地演示用）
//
// node:http 实现的最小 JSON-RPC 链：真实解码 raw 交易（RLP + EIP-155 sender
// 恢复，复用 extension/common/evm/crypto.js）、账户/nonce/余额状态机、
// 区块与回执、内置演示合约（ERC-20 形状代币 + greet 字符串）、水龙头
// （dev_faucet）、以及 Etherscan 兼容的 explorer txlist REST 端点。
// CORS 全开（扩展页 fetch 需要）。
//
// 用法：
//   import { startDevChain } from './devchain.mjs';
//   const chain = await startDevChain({ port: 0 });
//   chain.url        // http://127.0.0.1:<port>
//   chain.contract   // 演示合约地址
//   await chain.close();
// =============================================================================
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  hexToBytes, bytesToHex, parseAndRecoverTransaction, toChecksumAddress,
  keccak256, utf8ToBytes, encodeTuple, decodeTuple, functionSelector,
} from '../../common/evm/crypto.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

const TOKEN = {
  name: 'Dev Token',
  symbol: 'DVT',
  decimals: 18,
  faucetAmount: 1000n * 10n ** 18n, // faucet() 铸 1000 DVT 给调用者
};

export async function startDevChain({ port = 0, chainIdHex = '0x7a69' } = {}) {
  const state = {
    chainIdHex,
    balances: new Map(),   // addr(lower) → BigInt wei
    nonces: new Map(),     // addr → BigInt
    txs: new Map(),        // hash → {raw, from, to, value, data, nonce, gasPrice, gasLimit, blockNumber, status, gasUsed, logs}
    blocks: [],            // {number, timestamp, txHashes}
    tokenBalances: new Map(), // addr → BigInt
    greeting: 'Hello ZChain',
  };
  const contract = toChecksumAddress('0x' + 'c0de'.padEnd(40, '0'));

  const blockNumberOf = () => '0x' + (state.blocks.length + 1).toString(16);

  function applyContractCall(caller, data) {
    // 返回 {ret hex, logs[], ok, error?}；调用方保证余额扣费已处理
    const sel = data.slice(0, 10).toLowerCase();
    const argsHex = '0x' + data.slice(10);
    const logs = [];
    const transferTopic = bytesToHex(keccak256(utf8ToBytes('Transfer(address,address,uint256)')));
    if (sel === functionSelector('greet()')) {
      return { ret: encodeString(state.greeting), logs, ok: true };
    }
    if (sel === functionSelector('setGreeting(string)')) {
      const [msg] = decodeTuple(['string'], hexToBytes(argsHex));
      state.greeting = String(msg);
      return { ret: '0x', logs, ok: true };
    }
    if (sel === functionSelector('name()')) return { ret: encodeString(TOKEN.name), logs, ok: true };
    if (sel === functionSelector('symbol()')) return { ret: encodeString(TOKEN.symbol), logs, ok: true };
    if (sel === functionSelector('decimals()')) {
      return { ret: '0x' + TOKEN.decimals.toString(16).padStart(64, '0'), logs, ok: true };
    }
    if (sel === functionSelector('totalSupply()')) {
      let total = 0n;
      for (const v of state.tokenBalances.values()) total += v;
      return { ret: '0x' + total.toString(16).padStart(64, '0'), logs, ok: true };
    }
    if (sel === functionSelector('balanceOf(address)')) {
      const [[addr]] = [decodeTuple(['address'], hexToBytes(argsHex))];
      const bal = state.tokenBalances.get(String(addr).toLowerCase()) ?? 0n;
      return { ret: '0x' + bal.toString(16).padStart(64, '0'), logs, ok: true };
    }
    if (sel === functionSelector('faucet()')) {
      const callerLower = caller.toLowerCase();
      const cur = state.tokenBalances.get(callerLower) ?? 0n;
      state.tokenBalances.set(callerLower, cur + TOKEN.faucetAmount);
      logs.push(mkTransferLog(contract, null, caller, TOKEN.faucetAmount, transferTopic));
      return { ret: '0x', logs, ok: true };
    }
    if (sel === functionSelector('transfer(address,uint256)')) {
      const [to, amount] = decodeTuple(['address', 'uint256'], hexToBytes(argsHex));
      const fromLower = caller.toLowerCase();
      const toLower = String(to).toLowerCase();
      const cur = state.tokenBalances.get(fromLower) ?? 0n;
      const amt = BigInt(String(amount));
      if (cur < amt) return { ok: false, error: 'ERC20: insufficient balance', ret: '0x', logs };
      state.tokenBalances.set(fromLower, cur - amt);
      state.tokenBalances.set(toLower, (state.tokenBalances.get(toLower) ?? 0n) + amt);
      logs.push(mkTransferLog(caller, caller, toChecksumAddress(String(to)), amt, transferTopic));
      return { ret: '0x', logs, ok: true };
    }
    return { ok: false, error: `unknown contract selector ${sel}`, ret: '0x', logs };
  }

  function encodeString(s) {
    return bytesToHex(encodeTuple(['string'], [s]));
  }

  function mkTransferLog(emitter, from, to, amount, topic) {
    const pad = (a) => a.toLowerCase().replace(/^0x/, '').padStart(64, '0');
    return {
      address: emitter.toLowerCase(),
      topics: [topic, '0x' + pad(from ?? '0x0'), '0x' + pad(to)],
      data: '0x' + BigInt(amount).toString(16).padStart(64, '0'),
      blockNumber: blockNumberOf(),
    };
  }

  const handlers = {
    eth_chainId: () => state.chainIdHex,
    net_version: () => String(Number(BigInt(state.chainIdHex))),
    eth_blockNumber: () => '0x' + state.blocks.length.toString(16),
    eth_gasPrice: () => '0x3b9aca00', // 1 gwei
    eth_getBalance: ([addr]) => '0x' + (state.balances.get(String(addr).toLowerCase()) ?? 0n).toString(16),
    eth_getTransactionCount: ([addr]) => '0x' + (state.nonces.get(String(addr).toLowerCase()) ?? 0n).toString(16),
    eth_estimateGas: ([tx]) => {
      const base = 21000n;
      const dataLen = tx?.data && tx.data !== '0x' ? BigInt(16 * ((tx.data.length - 2) / 2)) : 0n;
      return '0x' + (base + dataLen).toString(16);
    },
    eth_call: ([tx]) => {
      if (!tx?.to || tx.to.toLowerCase() !== contract.toLowerCase()) return '0x';
      const res = applyContractCall(tx.from ?? '0x' + '00'.repeat(20), tx.data ?? '0x');
      if (!res.ok) throw { message: `execution reverted: ${res.error}` };
      return res.ret;
    },
    dev_faucet: ([addr, weiHex]) => {
      const key = String(addr).toLowerCase();
      state.balances.set(key, (state.balances.get(key) ?? 0n) + BigInt(weiHex));
      return true;
    },
    eth_sendRawTransaction: ([rawHex]) => {
      const tx = parseAndRecoverTransaction(rawHex); // 独立解码路径：RLP + ECDSA 恢复
      const fromLower = tx.from.toLowerCase();
      const nonce = state.nonces.get(fromLower) ?? 0n;
      if (tx.nonce !== nonce) throw { message: `nonce mismatch: have ${nonce}, tx ${tx.nonce}` };
      const gasCost = tx.gasPrice * tx.gasLimit;
      const balance = state.balances.get(fromLower) ?? 0n;
      if (balance < tx.value + gasCost) throw { message: 'insufficient funds for gas * price + value' };
      // 应用
      state.balances.set(fromLower, balance - tx.value - gasCost);
      state.nonces.set(fromLower, nonce + 1n);
      const logs = [];
      let status = '0x1';
      let gasUsed = tx.gasLimit;
      let effectiveTo = tx.to;
      if (tx.to && tx.to.toLowerCase() === contract.toLowerCase()) {
        const res = applyContractCall(tx.from, tx.data);
        if (!res.ok) {
          status = '0x0';
          state.balances.set(fromLower, (state.balances.get(fromLower) ?? 0n) + gasCost); // 失败退 gas
          gasUsed = tx.gasLimit; // 简化：失败仍计全额 gas
        } else {
          gasUsed = 21000n + BigInt(16 * ((tx.data.length - 2) / 2 || 0));
          state.balances.set(fromLower, (state.balances.get(fromLower) ?? 0n) + (tx.gasLimit - gasUsed) * tx.gasPrice);
          logs.push(...res.logs);
        }
      } else if (tx.to) {
        state.balances.set(tx.to.toLowerCase(), (state.balances.get(tx.to.toLowerCase()) ?? 0n) + tx.value);
      }
      const blockNumber = blockNumberOf();
      for (const l of logs) l.blockNumber = blockNumber;
      state.txs.set(tx.hash, {
        hash: tx.hash, raw: rawHex, from: tx.from, to: effectiveTo ?? null,
        value: tx.value.toString(), data: tx.data, nonce: tx.nonce.toString(),
        gasPrice: tx.gasPrice.toString(), gasLimit: tx.gasLimit.toString(),
        blockNumber, status, gasUsed: gasUsed.toString(), logs,
        timeStamp: Math.floor(Date.now() / 1000),
        input: tx.data === '0x' ? '0x' : tx.data,
      });
      state.blocks.push({ number: blockNumber, timestamp: Math.floor(Date.now() / 1000), txHash: tx.hash });
      return tx.hash;
    },
    eth_getTransactionReceipt: ([hash]) => {
      const t = state.txs.get(String(hash).toLowerCase());
      if (!t) return null;
      return {
        transactionHash: t.hash, transactionIndex: '0x0', blockNumber: t.blockNumber,
        from: t.from, to: t.to, cumulativeGasUsed: t.gasUsed, gasUsed: t.gasUsed,
        contractAddress: null, logs: t.logs, logsBloom: '0x' + '00'.repeat(256),
        status: t.status, effectiveGasPrice: t.gasPrice,
      };
    },
    eth_getTransactionByHash: ([hash]) => {
      const t = state.txs.get(String(hash).toLowerCase());
      if (!t) return null;
      return {
        hash: t.hash, nonce: '0x' + BigInt(t.nonce).toString(16),
        blockNumber: t.blockNumber, from: t.from, to: t.to,
        value: '0x' + BigInt(t.value).toString(16), input: t.input,
        gas: '0x' + BigInt(t.gasLimit).toString(16), gasPrice: '0x' + BigInt(t.gasPrice).toString(16),
      };
    },
  };

  const server = createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    // Etherscan 兼容 explorer txlist（GET /api?module=account&action=txlist&address=…）
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && url.pathname === '/api' && url.searchParams.get('module') === 'account') {
      const address = String(url.searchParams.get('address') ?? '').toLowerCase();
      const rows = [...state.txs.values()]
        .filter((t) => t.from.toLowerCase() === address || t.to?.toLowerCase() === address)
        .sort((a, b) => Number(BigInt(b.blockNumber)) - Number(BigInt(a.blockNumber)))
        .map((t) => ({
          blockNumber: String(Number(BigInt(t.blockNumber))),
          timeStamp: String(t.timeStamp),
          hash: t.hash, nonce: t.nonce,
          from: t.from, to: t.to ?? '', value: t.value, gas: t.gasLimit,
          gasPrice: t.gasPrice, gasUsed: t.gasUsed,
          isError: t.status === '0x1' ? '0' : '1',
          input: t.input, confirmations: '1',
        }));
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
        if (result instanceof Promise) {
          result.then((r) => respond(rpc.id, { result })).catch((e) => respond(rpc.id, { error: { code: -32000, message: e.message ?? 'error' } }));
        } else {
          respond(rpc.id, { result });
        }
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
    contract,
    state,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// 独立运行自检：node tests/e2e/devchain.mjs
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const chain = await startDevChain({ port: 8545 });
  console.log(`devchain listening on ${chain.url}, contract ${chain.contract}`);
  process.on('SIGINT', async () => { await chain.close(); process.exit(0); });
}
