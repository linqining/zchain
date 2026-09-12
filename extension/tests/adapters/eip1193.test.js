// =============================================================================
// extension/tests/adapters/eip1193.test.js — EIP-1193 兼容适配器测试
//
// 覆盖（node:test；mock zchain provider，无密码学、无 IO）：
//   chainId/net_version 映射（非 0x1）· eth_accounts 路由（锁定/解锁）·
//   EVM 签名方法红线拒绝（eth_sign/personal_sign/eth_signTypedData_v4/
//   eth_sendTransaction）· 白名单外 eth_* 拒 · zchain_* 透传（方法白名单 +
//   validation.js 拒绝面）· connect 事件 · 事件转发（chainChanged/
//   accountsChanged/disconnect）· removeListener。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createEip1193Provider, Eip1193Error } from '../../adapters/eip1193.js';
import { EIP1193_CHAIN_ID_MAP } from '../../adapters/shared.js';

// ---------------------------------------------------------------------------
// 夹具：mock zchain provider（inpage 形状）+ 最小事件源
// ---------------------------------------------------------------------------

const PUB = 'ab'.repeat(33);

function makeEmitter() {
  const handlers = new Map();
  return {
    handlers,
    on(event, cb) {
      if (!handlers.has(event)) handlers.set(event, new Set());
      handlers.get(event).add(cb);
    },
    off(event, cb) {
      handlers.get(event)?.delete(cb);
    },
    emit(event, payload) {
      for (const cb of [...(handlers.get(event) ?? [])]) cb(payload);
    },
  };
}

function mockZchain(over = {}) {
  const state = { unlocked: over.unlocked ?? false, events: makeEmitter(), calls: [] };
  const provider = {
    isZChain: true,
    ...state.events,
    getNetwork: async () => {
      state.calls.push('getNetwork');
      return { chainId: 'zchain-devnet-1', kind: 'devnet', abiVersion: 1 };
    },
    getCapabilities: async () => ({
      provider: 'zchain',
      methods: ['zchain_requestAccounts', 'zchain_getNetwork', 'zchain_getCapabilities', 'zchain_getAccounts', 'zchain_signOperation', 'zchain_signSettlement', 'zchain_getNotes', 'zchain_lock'],
    }),
    getAccounts: async () => {
      state.calls.push('getAccounts');
      return state.unlocked ? { accounts: [PUB], locked: false } : { accounts: [], locked: true };
    },
    requestAccounts: async () => {
      state.calls.push('requestAccounts');
      return { accounts: [PUB], chainId: 'zchain-devnet-1', granted: true };
    },
    signOperation: async (operation, previewHash) => {
      state.calls.push(['signOperation', operation, previewHash]);
      return { digest: 'de'.repeat(32), operationBorsh: 'aa', preview: {} };
    },
    signSettlement: async (settlement, previewHash) => {
      state.calls.push(['signSettlement', settlement, previewHash]);
      return { digest: 'de'.repeat(32), operationBorsh: 'bb', preview: {} };
    },
    getNotes: async (filter) => {
      state.calls.push(['getNotes', filter]);
      return [{ commitment: 'cc'.repeat(32), amount: '50', spendable: true }];
    },
    lock: async () => {
      state.unlocked = false;
      return { locked: true };
    },
  };
  return { provider, state };
}

function validOperation(over = {}) {
  return {
    kind: 'transfer',
    assetClass: 'PLAY',
    chainId: 'zchain-devnet-1',
    domain: 'zchain',
    abiVersion: 1,
    nonce: 7,
    expiry: 1_800_000_000,
    inputs: ['ab'.repeat(32)],
    outputs: [{ owner: 'cd'.repeat(33), amount: '50' }],
    ...over,
  };
}

async function requestError(promise) {
  try {
    await promise;
  } catch (e) {
    return e;
  }
  throw new Error('expected the request to reject');
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

test('01 eth_chainId 返回 ZChain 网络的映射别名（0x7a0001，绝非 0x1）', async () => {
  const { provider: z } = mockZchain();
  const p = createEip1193Provider({ zchain: z });
  assert.equal(await p.request({ method: 'eth_chainId' }), '0x7a0001');
  assert.notEqual(await p.request({ method: 'eth_chainId' }), '0x1');
  assert.equal(EIP1193_CHAIN_ID_MAP['zchain-devnet-1'], '0x7a0001'); // 显式映射表
});

test('02 net_version 返回映射数字 id 的十进制字符串', async () => {
  const { provider: z } = mockZchain();
  const p = createEip1193Provider({ zchain: z });
  assert.equal(await p.request({ method: 'net_version' }), String(parseInt('0x7a0001', 16)));
});

test('03 eth_accounts 映射 zchain_getAccounts：锁定 → 空数组', async () => {
  const { provider: z, state } = mockZchain({ unlocked: false });
  const p = createEip1193Provider({ zchain: z });
  assert.deepEqual(await p.request({ method: 'eth_accounts' }), []);
  assert.ok(state.calls.includes('getAccounts'));
});

test('04 eth_accounts：解锁 → 返回公钥账户', async () => {
  const { provider: z } = mockZchain({ unlocked: true });
  const p = createEip1193Provider({ zchain: z });
  assert.deepEqual(await p.request({ method: 'eth_accounts' }), [PUB]);
});

test('05 红线：EVM 签名/交易方法一律 EvmSigningForbidden（无开关）', async () => {
  const { provider: z } = mockZchain({ unlocked: true });
  const p = createEip1193Provider({ zchain: z });
  for (const method of ['eth_sign', 'personal_sign', 'eth_signTypedData', 'eth_signTypedData_v3', 'eth_signTypedData_v4', 'eth_sendTransaction', 'eth_sendRawTransaction']) {
    const e = await requestError(p.request({ method, params: [] }));
    assert.ok(e instanceof Eip1193Error, method);
    assert.equal(e.code, 4200, method);
    assert.equal(e.data.zchainCode, 'EvmSigningForbidden', method);
  }
});

test('06 白名单外 eth_*/wallet_* → unsupportedMethod(4200)', async () => {
  const { provider: z } = mockZchain();
  const p = createEip1193Provider({ zchain: z });
  for (const method of ['eth_blockNumber', 'eth_getBalance', 'wallet_addEthereumChain', 'eth_requestAccounts']) {
    const e = await requestError(p.request({ method }));
    assert.equal(e.code, 4200, method);
    assert.equal(e.data.zchainCode, 'MethodNotAllowed', method);
  }
});

test('07 zchain_signOperation 透传路由：参数原样、结果透传', async () => {
  const { provider: z, state } = mockZchain({ unlocked: true });
  const p = createEip1193Provider({ zchain: z });
  const op = validOperation();
  const res = await p.request({ method: 'zchain_signOperation', params: { operation: op, previewHash: '' } });
  assert.equal(res.digest, 'de'.repeat(32));
  const call = state.calls.find((c) => Array.isArray(c) && c[0] === 'signOperation');
  assert.deepEqual(call[1], op); // operation 原样
  assert.equal(call[2], ''); // previewHash 原样
});

test('08 zchain_* 白名单：未知方法 UnknownMethod、0.1 未交付 NotSupportedIn01、缺参 MissingParam', async () => {
  const { provider: z } = mockZchain({ unlocked: true });
  const p = createEip1193Provider({ zchain: z });
  const e1 = await requestError(p.request({ method: 'zchain_foo' }));
  assert.equal(e1.data.zchainCode, 'UnknownMethod');
  const e2 = await requestError(p.request({ method: 'zchain_switchNetwork', params: { chainId: 'zchain-devnet-1' } }));
  assert.equal(e2.data.zchainCode, 'NotSupportedIn01');
  const e3 = await requestError(p.request({ method: 'zchain_signOperation', params: {} }));
  assert.equal(e3.data.zchainCode, 'MissingParam');
});

test('09 zchain 结构校验透传：换链不符 → NetworkMismatch（validation.js 同一拒绝面）', async () => {
  const { provider: z } = mockZchain({ unlocked: true });
  const p = createEip1193Provider({ zchain: z });
  const e = await requestError(p.request({
    method: 'zchain_signOperation',
    params: { operation: validOperation({ chainId: 'ethereum-mainnet' }), previewHash: '' },
  }));
  assert.equal(e.code, -32000); // zchain 路由错误
  assert.equal(e.data.zchainCode, 'NetworkMismatch');
});

test('10 首次成功请求后派发 connect（携带映射 chainId，且只派发一次）', async () => {
  const { provider: z } = mockZchain();
  const p = createEip1193Provider({ zchain: z });
  const seen = [];
  p.on('connect', (payload) => seen.push(payload));
  await p.request({ method: 'eth_chainId' });
  await p.request({ method: 'net_version' });
  assert.deepEqual(seen, [{ chainId: '0x7a0001' }]);
});

test('11 事件转发：zchain:chainChanged → chainChanged（映射别名）', () => {
  const { provider: z, state } = mockZchain();
  const p = createEip1193Provider({ zchain: z, networkId: 'zchain-devnet-1' });
  const seen = [];
  p.on('chainChanged', (hex) => seen.push(hex));
  state.events.emit('zchain:chainChanged', 'zchain-devnet-1');
  assert.deepEqual(seen, ['0x7a0001']);
  // 未知网络不转发（fail-closed），chainId 保持原值
  state.events.emit('zchain:chainChanged', 'sn:mainnet');
  assert.equal(seen.length, 1);
  assert.equal(p.request({ method: 'eth_chainId' }).constructor, Promise); // 仍可用
});

test('12 事件转发：accountsChanged 数组透传；disconnect → 4900', () => {
  const { provider: z, state } = mockZchain();
  const p = createEip1193Provider({ zchain: z, networkId: 'zchain-devnet-1' });
  const accounts = [];
  const disconnects = [];
  p.on('accountsChanged', (a) => accounts.push(a));
  p.on('disconnect', (e) => disconnects.push(e));
  state.events.emit('zchain:accountsChanged', [PUB]);
  state.events.emit('zchain:disconnect', { code: 'Locked', reason: 'wallet locked' });
  assert.deepEqual(accounts, [[PUB]]);
  assert.equal(disconnects.length, 1);
  assert.equal(disconnects[0].code, 4900);
  assert.equal(disconnects[0].data.zchainCode, 'Locked');
});

test('13 removeListener 停止接收事件', () => {
  const { provider: z, state } = mockZchain();
  const p = createEip1193Provider({ zchain: z, networkId: 'zchain-devnet-1' });
  const seen = [];
  const cb = (a) => seen.push(a);
  p.on('accountsChanged', cb);
  state.events.emit('zchain:accountsChanged', [PUB]);
  p.removeListener('accountsChanged', cb);
  state.events.emit('zchain:accountsChanged', ['ff'.repeat(33)]);
  assert.equal(seen.length, 1);
});

test('14 畸形请求：method 缺失/为空 → BadRequest', async () => {
  const { provider: z } = mockZchain();
  const p = createEip1193Provider({ zchain: z });
  for (const bad of [undefined, null, '', 42]) {
    const e = await requestError(p.request({ method: bad }));
    assert.equal(e.data.zchainCode, 'BadRequest', String(bad));
  }
});

test('15 zchain_getNotes / zchain_lock 透传（getNotes 返回页形状）', async () => {
  const { provider: z, state } = mockZchain({ unlocked: true });
  const p = createEip1193Provider({ zchain: z });
  const notes = await p.request({ method: 'zchain_getNotes', params: { filter: { spendable: true } } });
  assert.equal(notes[0].commitment, 'cc'.repeat(32));
  assert.deepEqual(state.calls.find((c) => Array.isArray(c) && c[0] === 'getNotes')[1], { spendable: true });
  const locked = await p.request({ method: 'zchain_lock' });
  assert.equal(locked.locked, true);
});
