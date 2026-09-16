// =============================================================================
// tests/stark/wallet.test.js — Starknet 账户层钱包逻辑（Extension 0.6）
// keystore/地址推导/invoke 组装签名/交易账本/网络预设 + 与本地开发链的
// 全链路集成（签名 → 链上独立验签 → 状态变更 → explorer）。
// =============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createStarkAccount, encryptToKeystore, decryptFromKeystore, changeKeystorePassword,
  parsePrivateKeyHex, deriveAccount, generateSalt,
} from '../../common/stark/account.js';
import {
  STARKNET_NETWORKS, DEFAULT_STARKNET_NETWORK_ID, resolveStarknetNetwork,
  effectiveRpcUrl, starknetNetworkView, canonicalHttpUrl,
} from '../../common/stark/networks.js';
import { StarknetRpc } from '../../common/stark/rpc.js';
import {
  signInvoke, amountToFelts, feltsToAmount, buildInvokeCalldata,
} from '../../common/stark/invoke.js';
import {
  emptyTxStore, addPendingTx, applyReceipt, txListView, pendingHashes, mergeHistory,
  normalizeExplorerRow,
} from '../../common/stark/txs.js';
import {
  privateKeyToPublicKey, ecVerify, hexToBigInt, bigIntToHex, starknetSelector,
  padAddress,
} from '../../common/stark/curve.js';
import { startStarkDevChain } from '../e2e/starkdevchain.mjs';

const FAST = { iterations: 2000 };
const DEV_CLASS = '0xc1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55c1a55';

test('stk keystore：创建 → 解密往返 + 地址/公钥一致性', async () => {
  const { keystore, address, pubKey, privateKey } = await createStarkAccount('correct horse battery', DEV_CLASS, FAST);
  assert.equal(keystore.version, 'stark-1');
  assert.ok(address.startsWith('0x'));
  assert.ok(pubKey.startsWith('0x'));
  // 地址 = UDC(class, salt, [pubkey])；从私钥重推导一致
  const re = deriveAccount({ privKey: hexToBigInt(privateKey), salt: hexToBigInt(keystore.accountSalt), classHash: DEV_CLASS });
  assert.equal(padAddress(re.address), padAddress(hexToBigInt(address)));
  assert.equal(re.pubKey, hexToBigInt(pubKey));
  const priv = await decryptFromKeystore(keystore, 'correct horse battery');
  assert.equal(privateKeyToPublicKey(priv), hexToBigInt(pubKey));
  // 私钥不出现在 keystore JSON
  assert.equal(JSON.stringify(keystore).includes(privateKey.slice(2)), false);
});

test('stk keystore：错口令 fail-closed + 篡改拒绝 + 改密码', async () => {
  const { keystore, address } = await createStarkAccount('old password here', DEV_CLASS, FAST);
  await assert.rejects(() => decryptFromKeystore(keystore, 'wrong password!'),
    (e) => e.code === 'BadPassword');
  const tampered = { ...keystore, crypto: { ...keystore.crypto, data: '0x00' + keystore.crypto.data.slice(4) } };
  await assert.rejects(() => decryptFromKeystore(tampered, 'old password here'),
    (e) => e.code === 'BadPassword');
  await assert.rejects(() => decryptFromKeystore({ version: 2 }, 'x'), (e) => e.code === 'BadKeystore');
  const next = await changeKeystorePassword(keystore, 'old password here', 'new password 123', FAST);
  assert.equal(next.address, address);
  await assert.rejects(() => decryptFromKeystore(next, 'old password here'), (e) => e.code === 'BadPassword');
  const priv = await decryptFromKeystore(next, 'new password 123');
  assert.ok(priv > 0n);
});

test('stk 私钥导入解析：形状/范围拒绝面', () => {
  assert.ok(parsePrivateKeyHex('0x123') > 0n);
  assert.throws(() => parsePrivateKeyHex('0xzz'), (e) => e.code === 'InvalidArgument');
  assert.throws(() => parsePrivateKeyHex('0x0'), (e) => e.code === 'InvalidArgument');
  // grindKey 语义（scure-starknet / starknet.js）：私钥 ∈ [1, 2^251)——
  // 2^125 边界及以上（但 < 2^251）必须可导入（标准钱包密钥域）
  assert.equal(parsePrivateKeyHex('0x2' + '0'.repeat(31)), 2n ** 125n);
  assert.ok(parsePrivateKeyHex('0x' + 'f'.repeat(32)) > 2n ** 125n);
  assert.equal(parsePrivateKeyHex('0x7' + 'f'.repeat(62)), 2n ** 251n - 1n); // 最大合法值
  // ≥ 2^251 拒绝
  assert.throws(() => parsePrivateKeyHex('0x8' + '0'.repeat(62)), (e) => e.code === 'InvalidArgument');
  assert.throws(() => parsePrivateKeyHex('0x' + 'f'.repeat(63)), (e) => e.code === 'InvalidArgument');
  assert.throws(() => parsePrivateKeyHex('0x' + 'f'.repeat(64)), (e) => e.code === 'InvalidArgument');
  assert.ok(generateSalt() > 0n);
  // 导入路径 encryptToKeystore → 解密一致
});

test('stk 导入：encryptToKeystore 指定 salt/class → 地址稳定（高位密钥）', async () => {
  // 高位密钥（> 2^125，标准钱包密钥域）导入路径全链路：derive/加密/解密一致
  const priv = parsePrivateKeyHex('0x' + 'f'.repeat(32));
  const salt = 0x42n;
  const ks = await encryptToKeystore(priv, { password: 'import password', salt, classHash: hexToBigInt(DEV_CLASS) });
  const re = deriveAccount({ privKey: priv, salt, classHash: DEV_CLASS });
  assert.equal(padAddress(hexToBigInt(ks.address)), padAddress(re.address));
  const out = await decryptFromKeystore(ks, 'import password');
  assert.equal(out, priv);
});

test('stk 网络：预设/解析/RPC 覆盖', () => {
  assert.ok(STARKNET_NETWORKS.length >= 3);
  assert.equal(DEFAULT_STARKNET_NETWORK_ID, 'starknet-devnet');
  const dev = resolveStarknetNetwork('starknet-devnet');
  assert.equal(dev.chainId, 'ZCDN');
  assert.equal(dev.faucet, true);
  assert.equal(resolveStarknetNetwork('nope'), null);
  assert.equal(effectiveRpcUrl(dev, {}), dev.rpcUrl);
  assert.equal(effectiveRpcUrl(dev, { 'starknet-devnet': 'http://127.0.0.1:9' }), 'http://127.0.0.1:9');
  assert.equal(effectiveRpcUrl(dev, { 'starknet-devnet': 'ftp://x' }), dev.rpcUrl);
  assert.equal(canonicalHttpUrl('http://x:1/api?m=1'), 'http://x:1/api');
  const view = starknetNetworkView(dev, { 'starknet-devnet': 'http://127.0.0.1:9' });
  assert.equal(view.rpcOverridden, true);
  assert.equal(view.tokenSymbol, 'DST');
});

test('stk invoke：金额换算 + calldata 组装', () => {
  const [lo, hi] = amountToFelts('1.5', 18);
  assert.equal(feltsToAmount([lo, hi], 18), '1.5');
  assert.throws(() => amountToFelts('abc', 18), (e) => e.code === 'InvalidArgument');
  const data = buildInvokeCalldata({
    to: '0x1234', functionName: 'transfer',
    calldata: ['0x5678', ...amountToFelts('2', 18)],
  });
  // [to, selector, len, ...args]；len = 3（recipient + u256 对）
  assert.equal(data.length, 3 + 3);
  assert.equal(bigIntToHex(starknetSelector('transfer')), data[1]);
  assert.equal(BigInt(data[2]), 3n);
});

test('stk 交易账本：pending → succeeded/reverted + 上限 + 合并', () => {
  let store = emptyTxStore();
  const hash = '0x' + 'ab'.repeat(32);
  store = addPendingTx(store, { hash, from: '0xA', to: '0xB', kind: 'contract', methodLabel: 'transfer' }, 1).store;
  const rec = applyReceipt(store, hash, { execution_status: 'SUCCEEDED', block_number: 5 }, 2);
  assert.equal(rec.entry.status, 'succeeded');
  assert.equal(rec.entry.blockNumber, '5');
  store = rec.store;
  // reverted
  let store2 = emptyTxStore();
  const h2 = '0x' + 'cd'.repeat(32);
  store2 = addPendingTx(store2, { hash: h2 }, 1).store;
  const fail = applyReceipt(store2, h2, { execution_status: 'REVERTED', block_number: 6 }, 2);
  assert.equal(fail.entry.status, 'reverted');
  // 未知 hash
  assert.equal(applyReceipt(store, '0x' + 'ee'.repeat(32), {}, 3).ok, false);
  // pending 清单
  assert.deepEqual(pendingHashes(store), []);
  // explorer 合并
  const merged = mergeHistory(txListView(store), [
    { hash: '0x' + 'ee'.repeat(32), from: '0xA', to: '0xB', isError: '0', timeStamp: '1700000000', confirmations: '1', kind: 'contract' },
    { hash, from: '0xA', to: '0xB', isError: '0', timeStamp: '1700000000', confirmations: '1' },
  ]);
  assert.equal(merged.length, 2);
  assert.equal(merged.find((m) => m.hash === hash).source, 'local');
  assert.equal(normalizeExplorerRow({ hash: 'x' }), null);
});

// ---------------------------------------------------------------------------
// 与本地开发链的全链路集成（签名 → 独立验签 → 状态 → explorer）
// ---------------------------------------------------------------------------

test('stk 集成：devchain 水龙头/余额/签名转账/回执/explorer', { timeout: 30_000 }, async () => {
  const chain = await startStarkDevChain({ port: 0 });
  try {
    const rpc = new StarknetRpc(chain.url);
    const { keystore, address, pubKey, privateKey } = await createStarkAccount('correct horse battery', DEV_CLASS, FAST);
    const net = resolveStarknetNetwork('starknet-devnet');
    // 水龙头（注册 pubkey + 出资 100）
    await rpc.devFaucet(address, bigIntToHex(100n * 10n ** 18n), pubKey);
    // 余额
    const bal = await rpc.call({
      contract_address: net.tokenAddress,
      entry_point_selector: bigIntToHex(starknetSelector('balance_of')),
      calldata: [address],
    });
    const balWei = hexToBigInt(bal[0]) | (hexToBigInt(bal[1]) << 128n);
    assert.equal(balWei, 100n * 10n ** 18n);
    // 链 ID / nonce
    assert.equal(await rpc.chainId(), 'ZCDN');
    assert.equal(hexToBigInt(await rpc.getNonce(address)), 0n);
    // 签名转账（25 DST → OTHER）并广播
    const OTHER = '0x' + 'beef'.padEnd(62, '0');
    const signed = signInvoke({
      senderAddress: address,
      to: net.tokenAddress,
      functionName: 'transfer',
      calldata: [OTHER, ...amountToFelts('25', 18)],
      nonce: 0n,
      maxFee: hexToBigInt('0x2386f26fc10000'), // 0.01 ETH 上限
      chainIdFelt: hexToBigInt(net.chainIdFelt),
      privateKey,
    });
    assert.equal(signed.txHash.startsWith('0x'), true);
    assert.ok(ecVerify(hexToBigInt(pubKey), hexToBigInt(signed.txHash), hexToBigInt(signed.signature[0]), hexToBigInt(signed.signature[1])));
    const addRes = await rpc.addInvokeTransaction({
      max_fee: signed.invocation.max_fee,
      signature: signed.invocation.signature,
      nonce: signed.invocation.nonce,
      sender_address: signed.invocation.sender_address,
      calldata: signed.invocation.calldata,
    });
    assert.ok(addRes.transaction_hash.startsWith('0x'));
    // 回执 + 余额核对
    const receipt = await rpc.getTransactionReceipt(addRes.transaction_hash);
    assert.equal(receipt.execution_status, 'SUCCEEDED');
    const bal2 = await rpc.call({
      contract_address: net.tokenAddress,
      entry_point_selector: bigIntToHex(starknetSelector('balance_of')),
      calldata: [address],
    });
    const bal2Wei = hexToBigInt(bal2[0]) | (hexToBigInt(bal2[1]) << 128n);
    // 100 − 25 − 手续费（0.0003）≈ 74.9997
    assert.ok(bal2Wei < 75n * 10n ** 18n && bal2Wei > 74n * 10n ** 18n);
    // OTHER 收到 25
    const balOther = await rpc.call({
      contract_address: net.tokenAddress,
      entry_point_selector: bigIntToHex(starknetSelector('balance_of')),
      calldata: [OTHER],
    });
    assert.equal(hexToBigInt(balOther[0]) | (hexToBigInt(balOther[1]) << 128n), 25n * 10n ** 18n);
    // explorer
    const ex = await fetch(`${chain.url}/api?module=account&action=txlist&address=${address}`).then((r) => r.json());
    assert.ok(ex.result.length >= 1);
  } finally {
    await chain.close();
  }
});
