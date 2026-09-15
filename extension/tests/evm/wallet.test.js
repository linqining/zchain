// =============================================================================
// tests/evm/wallet.test.js — keystore / 网络 / RPC / 交易记录 / 历史 / 合约
// （Extension 0.5 纯逻辑面；RPC 用注入式 fetch 假节点）
// =============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createKeystore, encryptToKeystore, decryptFromKeystore, changeKeystorePassword,
  parsePrivateKeyHex, addressFromPrivateKey, PBKDF2_ITERATIONS,
} from '../../common/evm/keystore.js';
import {
  EVM_NETWORKS, DEFAULT_EVM_NETWORK_ID, resolveEvmNetwork, effectiveRpcUrl,
  effectiveExplorerApi, canonicalHttpUrl, evmNetworkView,
} from '../../common/evm/networks.js';
import { JsonRpcClient, hexQtyToBigInt } from '../../common/evm/rpc.js';
import {
  emptyTxStore, addPendingTx, applyReceipt, txListView, pendingHashes, MAX_TX_RECORDS,
} from '../../common/evm/txs.js';
import { normalizeExplorerRow, mergeHistory, fetchExplorerHistory } from '../../common/evm/history.js';
import {
  parseAbi, encodeCall, decodeCallOutput, readContract, buildWriteIntent, ABI_PRESETS,
} from '../../common/evm/contracts.js';
import { generatePrivateKeyBytes, bytesToHex, hexToBytes, encodeTuple } from '../../common/evm/crypto.js';

// ---------------------------------------------------------------------------
// keystore
// ---------------------------------------------------------------------------

const FAST = { iterations: 2000 };

test('keystore：创建 → 解密往返（正确口令）', async () => {
  const { keystore, address, privateKey } = await createKeystore('correct horse battery', FAST);
  assert.equal(keystore.version, 1);
  assert.equal(keystore.crypto.kdf, 'pbkdf2-sha256');
  assert.equal(keystore.crypto.cipher, 'aes-256-gcm');
  assert.ok(keystore.address.startsWith('0x'));
  assert.equal(address, keystore.address);
  assert.match(privateKey, /^0x[0-9a-f]{64}$/);
  const priv = await decryptFromKeystore(keystore, 'correct horse battery');
  assert.equal(addressFromPrivateKey(priv), address);
  // 私钥不会出现在 keystore 密文对象里
  assert.equal(JSON.stringify(keystore).includes(privateKey.slice(2)), false);
});

test('keystore：错口令 fail-closed（BadPassword）', async () => {
  const { keystore } = await createKeystore('correct horse battery', FAST);
  await assert.rejects(() => decryptFromKeystore(keystore, 'wrong password'),
    (e) => e.code === 'BadPassword');
  await assert.rejects(() => decryptFromKeystore(keystore, ''));
  // 篡改密文 → BadPassword（GCM 认证失败）
  const tampered = { ...keystore, crypto: { ...keystore.crypto, data: '0x00' + keystore.crypto.data.slice(4) } };
  await assert.rejects(() => decryptFromKeystore(tampered, 'correct horse battery'),
    (e) => e.code === 'BadPassword');
});

test('keystore：结构非法拒绝 + 短口令拒绝 + 改密码', async () => {
  await assert.rejects(() => decryptFromKeystore({ version: 2 }, 'x'),
    (e) => e.code === 'BadKeystore');
  await assert.rejects(() => createKeystore('short', FAST),
    (e) => e.code === 'InvalidArgument');
  const { keystore, address } = await createKeystore('old password here', FAST);
  const next = await changeKeystorePassword(keystore, 'old password here', 'new password here', FAST);
  assert.equal(next.address, address);
  assert.notEqual(next.crypto.salt, keystore.crypto.salt); // 新盐
  await assert.rejects(() => decryptFromKeystore(next, 'old password here'), (e) => e.code === 'BadPassword');
  const priv = await decryptFromKeystore(next, 'new password here');
  assert.equal(addressFromPrivateKey(priv), address);
});

test('keystore：私钥导入解析（形状/范围拒绝面）', async () => {
  const sk = generatePrivateKeyBytes();
  const hex = bytesToHex(sk);
  assert.deepEqual(parsePrivateKeyHex(hex), sk);
  assert.deepEqual(parsePrivateKeyHex(hex.slice(2)), sk); // 允许无 0x
  assert.throws(() => parsePrivateKeyHex('0x1234'), (e) => e.code === 'InvalidArgument');
  assert.throws(() => parsePrivateKeyHex('0x' + '00'.repeat(32)), (e) => e.code === 'InvalidArgument');
  assert.throws(() => parsePrivateKeyHex('0x' + 'ff'.repeat(33)));
  // 地址推导一致性
  assert.equal(addressFromPrivateKey(sk), addressFromPrivateKey(hexToBytes(hex)));
  // 默认迭代参数 ≥ 600k（生产强度）
  assert.ok(PBKDF2_ITERATIONS >= 600_000);
});

test('keystore：encryptToKeystore 直用（导入私钥路径）', async () => {
  const sk = generatePrivateKeyBytes();
  const ks = await encryptToKeystore(sk, 'import password', FAST);
  assert.equal(ks.address, addressFromPrivateKey(sk));
  const out = await decryptFromKeystore(ks, 'import password');
  assert.deepEqual(out, sk);
});

// ---------------------------------------------------------------------------
// networks
// ---------------------------------------------------------------------------

test('networks：注册表/解析/RPC 覆盖/explorer 覆盖', () => {
  assert.ok(EVM_NETWORKS.length >= 5);
  assert.equal(DEFAULT_EVM_NETWORK_ID, 'evm-devnet');
  const dev = resolveEvmNetwork('evm-devnet');
  assert.equal(dev.chainIdHex, '0x7a69');
  assert.equal(dev.faucet, true);
  assert.equal(resolveEvmNetwork('0x1').id, 'ethereum');
  assert.equal(resolveEvmNetwork('0xdead'), null);
  assert.equal(resolveEvmNetwork(undefined), null);
  // RPC 覆盖：非法 URL 忽略回预设
  assert.equal(effectiveRpcUrl(dev, {}), dev.rpcUrl);
  assert.equal(effectiveRpcUrl(dev, { '0x7a69': 'http://127.0.0.1:9999' }), 'http://127.0.0.1:9999');
  assert.equal(effectiveRpcUrl(dev, { '0x7a69': 'not a url' }), dev.rpcUrl);
  assert.equal(effectiveRpcUrl(dev, { '0x7a69': 'ftp://x' }), dev.rpcUrl);
  assert.equal(effectiveRpcUrl(null, {}), null);
  // explorer API 覆盖
  assert.equal(effectiveExplorerApi(dev, { '0x7a69': 'http://127.0.0.1:1/api' }), 'http://127.0.0.1:1/api');
  assert.equal(effectiveExplorerApi(resolveEvmNetwork('ethereum'), {}), null);
  // canonicalHttpUrl：去 query/尾斜杠
  assert.equal(canonicalHttpUrl('http://x:1/api?module=1#f'), 'http://x:1/api');
  assert.equal(canonicalHttpUrl('http://x:1/'), 'http://x:1');
  // 视图
  const view = evmNetworkView(dev, { '0x7a69': 'http://127.0.0.1:9999' });
  assert.equal(view.rpcUrl, 'http://127.0.0.1:9999');
  assert.equal(view.rpcOverridden, true);
  assert.equal(view.faucet, true);
});

// ---------------------------------------------------------------------------
// rpc（注入式 fetch 假节点）
// ---------------------------------------------------------------------------

function fakeFetch(handler) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    const result = handler(body.method, body.params, url);
    return {
      ok: true,
      json: async () => typeof result === 'object' && result?.__error
        ? { jsonrpc: '2.0', id: body.id, error: { message: result.message } }
        : { jsonrpc: '2.0', id: body.id, result },
    };
  };
}

test('rpc：请求/错误码面', async () => {
  const rpc = new JsonRpcClient('http://127.0.0.1:1', fakeFetch((m) => {
    if (m === 'eth_chainId') return '0x7a69';
    if (m === 'eth_getBalance') return '0xde0b6b3a7640000'; // 1 ETH（奇数长度规范 quantity）
    if (m === 'eth_gasPrice') return '0x3b9aca00';
    if (m === 'boom') return { __error: true, message: 'nope' };
    return '0x1';
  }));
  assert.equal(await rpc.chainId(), 31337);
  assert.equal(hexQtyToBigInt(await rpc.getBalance('0x1')), 10n ** 18n);
  assert.equal(hexQtyToBigInt(await rpc.gasPrice()), 1000000000n);
  await assert.rejects(() => rpc.request('boom'), (e) => e.code === 'RpcError');
  // 不可达
  const dead = new JsonRpcClient('http://127.0.0.1:1', async () => { throw new Error('x'); });
  await assert.rejects(() => dead.request('eth_chainId'), (e) => e.code === 'RpcUnreachable');
  // URL 非法
  assert.throws(() => new JsonRpcClient('ftp://x'), (e) => e.code === 'InvalidArgument');
  assert.throws(() => new JsonRpcClient('nope'));
  assert.equal(hexQtyToBigInt('0x'), 0n);
  assert.equal(hexQtyToBigInt(null), 0n);
  assert.equal(hexQtyToBigInt(42), 42n);
});

// ---------------------------------------------------------------------------
// txs
// ---------------------------------------------------------------------------

test('txs：pending → confirmed/failed 状态机 + 上限 + 幂等', () => {
  let store = emptyTxStore();
  const add = addPendingTx(store, {
    hash: '0x' + 'ab'.repeat(32), chainId: '0x7a69', from: '0xA', to: '0xB',
    value: '1000', nonce: 0, kind: 'transfer', methodLabel: null,
  }, 1000);
  assert.ok(add.ok);
  store = add.store;
  // 重复 hash 幂等
  const dup = addPendingTx(store, { hash: '0x' + 'ab'.repeat(32) }, 1001);
  assert.equal(dup.entry.status, 'pending');
  // 回执落地
  const rec = applyReceipt(store, '0x' + 'ab'.repeat(32), { status: '0x1', blockNumber: '0x5', gasUsed: '0x5208' }, 2000);
  assert.equal(rec.entry.status, 'confirmed');
  assert.equal(rec.entry.blockNumber, '5');
  store = rec.store;
  // 已终态不再变化
  const again = applyReceipt(store, '0x' + 'ab'.repeat(32), { status: '0x0' }, 3000);
  assert.equal(again.entry.status, 'confirmed');
  // failed
  let store2 = emptyTxStore();
  store2 = addPendingTx(store2, { hash: '0x' + 'cd'.repeat(32), to: '0xB', value: '1' }, 10).store;
  const fail = applyReceipt(store2, '0x' + 'cd'.repeat(32), { status: '0x0' }, 20);
  assert.equal(fail.entry.status, 'failed');
  // 未知 hash
  assert.equal(applyReceipt(store, '0x' + 'ee'.repeat(32), { status: '0x1' }, 1).ok, false);
  // 非法 hash 拒绝
  assert.equal(addPendingTx(emptyTxStore(), { hash: 'nope' }, 1).ok, false);
  // 列表 + pending 清单
  assert.equal(txListView(store).length, 1);
  assert.deepEqual(pendingHashes(store), []);
  // 上限滚动
  let big = emptyTxStore();
  for (let i = 0; i < MAX_TX_RECORDS + 20; i++) {
    big = addPendingTx(big, { hash: '0x' + i.toString(16).padStart(64, '0'), to: '0xB', value: '1' }, i).store;
  }
  assert.equal(big.order.length, MAX_TX_RECORDS);
  assert.ok(!big.byHash['0x' + '0'.padStart(64, '0')]); // 最旧的被挤出
});

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

test('history：explorer 行归一 + 合并去重（本地优先）', () => {
  const row = normalizeExplorerRow({
    hash: '0x' + '11'.repeat(32), from: '0xA', to: '0xB', value: '1500000000000000000',
    timeStamp: '1700000000', isError: '0', confirmations: '5', blockNumber: '9',
    gasUsed: '21000', input: '0x',
  });
  assert.equal(row.valueHuman, '1.5');
  assert.equal(row.status, 'confirmed');
  assert.equal(row.kind, 'transfer');
  assert.equal(normalizeExplorerRow({ hash: 'nope' }), null);
  assert.equal(normalizeExplorerRow(null), null);

  const local = [{
    hash: '0x' + '11'.repeat(32), status: 'confirmed', from: '0xA', to: '0xB',
    value: '1500000000000000000', kind: 'transfer', source: 'local', createdAtMs: 123,
  }];
  const merged = mergeHistory(local, [
    { hash: '0x' + '22'.repeat(32), value: '1', timeStamp: '1700000100', isError: '1', confirmations: '1', input: '0xdead' },
    local[0] && { hash: local[0].hash, value: '999', timeStamp: '1700000000', isError: '0', confirmations: '9', input: '0x' },
  ].filter(Boolean));
  assert.equal(merged.length, 2);
  assert.equal(merged[0].hash, '0x' + '22'.repeat(32)); // 新 → 旧
  const kept = merged.find((m) => m.hash === local[0].hash);
  assert.equal(kept.value, '1500000000000000000'); // 本地值优先
  assert.equal(kept.source, 'local');
});

test('history：explorer 拉取失败面（不抛异常）', async () => {
  const fail = await fetchExplorerHistory({
    apiUrl: 'http://127.0.0.1:1/api', address: '0xA',
    fetchImpl: async () => { throw new Error('x'); },
  });
  assert.equal(fail.ok, false);
  assert.equal(fail.code, 'ExplorerUnreachable');
  const httpErr = await fetchExplorerHistory({
    apiUrl: 'http://127.0.0.1:1/api', address: '0xA',
    fetchImpl: async () => ({ ok: false, status: 500 }),
  });
  assert.equal(httpErr.ok, false);
  const empty = await fetchExplorerHistory({
    apiUrl: 'http://127.0.0.1:1/api', address: '0xA',
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: '0', message: 'No transactions found' }) }),
  });
  assert.deepEqual(empty.rows, []);
});

// ---------------------------------------------------------------------------
// contracts
// ---------------------------------------------------------------------------

test('contracts：ABI 解析/编码/解码 + view 路由', async () => {
  const abi = parseAbi(ABI_PRESETS.erc20.abi);
  const symbol = abi.byName.symbol;
  assert.equal(symbol.view, true);
  assert.equal(symbol.selector, '0x95d89b41');
  const bal = abi.byName.balanceOf;
  const data = encodeCall(bal, ['0x2b5ad5c4795c026514f8317c7a215e218dccd6cf']);
  assert.ok(data.startsWith('0x70a08231'));
  // 解码 uint256 输出
  const values = decodeCallOutput(bal, '0x' + (10n ** 21n).toString(16).padStart(64, '0'));
  assert.deepEqual(values, [(10n ** 21n).toString()]);
  // string 输出
  const nameFn = abi.byName.name;
  const enc = encodeTuple(['string'], ['Dev Token']);
  const dec = decodeCallOutput(nameFn, '0x' + [...enc].map((b) => b.toString(16).padStart(2, '0')).join(''));
  assert.deepEqual(dec, ['Dev Token']);
  // 非 view 方法走 readContract 拒绝
  await assert.rejects(() => readContract({
    contract: '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed', fn: abi.byName.transfer, args: [],
    callImpl: async () => '0x',
  }), (e) => e.code === 'MethodNotView');
  // view 正常（注入式 callImpl）
  const res = await readContract({
    contract: '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed', fn: abi.byName.symbol, args: [],
    callImpl: async (tx) => {
      assert.equal(tx.to, '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed');
      return '0x' + [...encodeTuple(['string'], ['DVT'])].map((b) => b.toString(16).padStart(2, '0')).join('');
    },
  });
  assert.deepEqual(res.values, ['DVT']);
});

test('contracts：写意图（token 金额换算 + 方法标签）', () => {
  const abi = parseAbi(ABI_PRESETS.erc20.abi);
  const intent = buildWriteIntent(abi.byName.transfer, ['0x2b5ad5c4795c026514f8317c7a215e218dccd6cf', '1.5'], {
    contract: '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed', tokenDecimals: 18,
  });
  assert.ok(intent.data.startsWith('0xa9059cbb'));
  assert.equal(intent.value, '0');
  assert.equal(intent.methodLabel, 'transfer(address,uint256)');
  assert.equal(intent.decodedArgs[1].value, (10n ** 18n * 3n / 2n).toString());
  // 非法地址/参数
  assert.throws(() => buildWriteIntent(abi.byName.transfer, ['nope', '1'], { contract: '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed' }),
    (e) => e.code === 'InvalidArgument');
  assert.throws(() => buildWriteIntent(abi.byName.transfer, ['0x2b5ad5c4795c026514f8317c7a215e218dccd6cf'], { contract: '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed' }),
    (e) => e.code === 'InvalidArgument');
  // view 方法不允许走写路径
  assert.throws(() => buildWriteIntent(abi.byName.symbol, [], { contract: '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed' }));
});
