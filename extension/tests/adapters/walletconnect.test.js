// =============================================================================
// extension/tests/adapters/walletconnect.test.js — WalletConnect v2 适配核心测试
//
// 覆盖（node:test；SignClient 用 wc_signclient_stub.js 内存实现，无网络/密码学）：
//   proposal 批准（namespace 映射/授予集=请求∩白名单∩能力）· 非法 namespace
//   拒（eip155 混装）· 非法 chains 拒 · 白名单外 method 拒 · 无账户拒 ·
//   请求路由（签名往返）· 未授予 method 拒 · 能力缺失拒（CapabilityMissing，
//   无盲签退路）· 会话过期拒 + 断开 · 请求 id 重放/回退拒 · 请求过期拒 ·
//   参数结构（validation.js）拒 · 事件转发（session_event）· 断开后拒。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createWalletConnectAdapter, WC_SESSION_TTL_SEC } from '../../adapters/walletconnect.js';
import { createSignClientStub } from '../../adapters/wc_signclient_stub.js';
import { WC_ERROR_CODES, WC_PROPOSAL_REJECT_CODES } from '../../adapters/shared.js';

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

const PUB = 'ab'.repeat(33);
const NOW_MS = 1_757_000_000_000;
const NETWORK = { chainId: 'zchain-devnet-1' };

const FULL_CAP_METHODS = [
  'zchain_requestAccounts', 'zchain_getNetwork', 'zchain_getCapabilities',
  'zchain_getAccounts', 'zchain_signOperation', 'zchain_signSettlement',
  'zchain_getNotes', 'zchain_lock',
];

function makeEmitter() {
  const handlers = new Map();
  return {
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
  const events = makeEmitter();
  const provider = {
    isZChain: true,
    getNetwork: async () => ({ chainId: 'zchain-devnet-1', kind: 'devnet', abiVersion: 1 }),
    getCapabilities: async () => ({ provider: 'zchain', methods: over.capMethods ?? FULL_CAP_METHODS }),
    getAccounts: async () => (over.unlocked === false ? { accounts: [], locked: true } : { accounts: [PUB], locked: false }),
    signOperation: async (operation, previewHash) => {
      over.signCalls?.push({ operation, previewHash });
      return { digest: 'de'.repeat(32), operationBorsh: 'aa', preview: { kind: 'transfer' } };
    },
    getNotes: async () => [{ commitment: 'cc'.repeat(32), amount: '50', spendable: true }],
  };
  return Object.assign(provider, events);
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

/** 建立已批准会话的快捷方式。 */
async function approvedSession({ capMethods, requested, unlocked = true } = {}) {
  const signClient = createSignClientStub({ now: () => NOW_MS });
  const z = mockZchain({ capMethods, unlocked });
  const adapter = createWalletConnectAdapter({
    signClient,
    zchain: z,
    network: NETWORK,
    now: () => NOW_MS,
    log: () => {},
  });
  const session = await signClient.connect({
    requiredNamespaces: {
      zchain: {
        chains: [`zchain:${NETWORK.chainId}`],
        methods: requested ?? ['zchain_getAccounts', 'zchain_signOperation', 'zchain_getNotes', 'zchain_lock'],
        events: ['chainChanged', 'accountsChanged'],
      },
    },
  });
  return { signClient, z, adapter, session };
}

/** 直接向 wallet 侧注入 session_request 并收集适配器的 JSON-RPC 响应。 */
async function rawRequest(signClient, event) {
  const recorded = [];
  const orig = signClient.respondSessionRequest;
  signClient.respondSessionRequest = (call) => {
    recorded.push(call);
    return { acknowledged: true };
  };
  signClient.emitSessionRequestFromDapp(event);
  await new Promise((r) => setTimeout(r, 0));
  signClient.respondSessionRequest = orig;
  return recorded;
}

function reqEvent({ id = 1001, topic, method, params = {}, expiry, chainId }) {
  return {
    id,
    topic,
    params: {
      request: { method, params, ...(expiry != null ? { expiry } : {}) },
      chainId: chainId ?? null,
    },
  };
}

async function rejectionOf(signClient, event) {
  const [resp] = await rawRequest(signClient, event);
  assert.ok(resp?.response?.error, 'expected an error response');
  return resp.response.error;
}

// ---------------------------------------------------------------------------
// proposal：namespace 映射与拒绝面
// ---------------------------------------------------------------------------

test('01 proposal 批准：namespace 映射正确（zchain 链/授予集/事件/CAIP10 账户）', async () => {
  const { signClient, adapter, session } = await approvedSession();
  assert.deepEqual(session.namespaces.zchain.chains, ['zchain:zchain-devnet-1']);
  assert.deepEqual(
    [...session.namespaces.zchain.methods].sort(),
    ['zchain_getAccounts', 'zchain_lock', 'zchain_getNotes', 'zchain_signOperation'].sort(),
  );
  assert.deepEqual(session.namespaces.zchain.events, ['chainChanged', 'accountsChanged']);
  assert.deepEqual(session.namespaces.zchain.accounts, [`zchain:zchain-devnet-1:${PUB}`]);
  assert.ok(signClient.session.has(session.topic));
  assert.deepEqual(
    [...adapter.grantedMethodsOf(session.topic)].sort(),
    ['zchain_getAccounts', 'zchain_lock', 'zchain_getNotes', 'zchain_signOperation'].sort(),
  );
  // 默认会话 TTL = 7 天
  assert.equal(WC_SESSION_TTL_SEC, 7 * 24 * 3600);
  assert.ok(session.expiry > Math.floor(NOW_MS / 1000) + 6 * 24 * 3600);
});

test('02 授予集 = 请求 ∩ 白名单 ∩ 能力：能力缺失的方法不授予', async () => {
  // getCapabilities 缺 zchain_signOperation → 请求了也不授予。
  const { session } = await approvedSession({
    capMethods: FULL_CAP_METHODS.filter((m) => m !== 'zchain_signOperation'),
    requested: ['zchain_getAccounts', 'zchain_signOperation'],
  });
  assert.deepEqual(session.namespaces.zchain.methods, ['zchain_getAccounts']);
});

test('03 proposal 混入 eip155 namespace → 整案拒绝（不伪装红线）', async () => {
  const signClient = createSignClientStub();
  createWalletConnectAdapter({ signClient, zchain: mockZchain(), network: NETWORK, now: () => NOW_MS });
  const err = await signClient
    .connect({
      requiredNamespaces: {
        eip155: { chains: ['eip155:1'], methods: ['eth_sendTransaction'], events: [] },
        zchain: { chains: ['zchain:zchain-devnet-1'], methods: ['zchain_getAccounts'], events: [] },
      },
    })
    .then(() => null, (e) => e);
  assert.equal(err.code, WC_PROPOSAL_REJECT_CODES.unsupportedNamespaceKey);
  assert.match(err.message, /zchain/);
  assert.equal(signClient.getActiveSessions().size, 0);
});

test('04 proposal chains 含非当前 ZChain 网络 → 拒绝（独立网络身份）', async () => {
  const signClient = createSignClientStub();
  createWalletConnectAdapter({ signClient, zchain: mockZchain(), network: NETWORK, now: () => NOW_MS });
  for (const chains of [['zchain:zchain-testnet-1'], ['eip155:1'], ['zchain:zchain-devnet-1', 'zchain:zchain-mainnet-1'], []]) {
    const err = await signClient
      .connect({ requiredNamespaces: { zchain: { chains, methods: ['zchain_getAccounts'], events: [] } } })
      .then(() => null, (e) => e);
    assert.equal(err.code, WC_PROPOSAL_REJECT_CODES.unsupportedChains, chains.join(','));
  }
});

test('05 proposal methods 含 eth_*（白名单外）→ 拒绝（永不为盲签开口）', async () => {
  const signClient = createSignClientStub();
  createWalletConnectAdapter({ signClient, zchain: mockZchain(), network: NETWORK, now: () => NOW_MS });
  for (const methods of [['eth_sendTransaction'], ['zchain_getAccounts', 'personal_sign'], []]) {
    const err = await signClient
      .connect({ requiredNamespaces: { zchain: { chains: ['zchain:zchain-devnet-1'], methods, events: [] } } })
      .then(() => null, (e) => e);
    assert.equal(err.code, WC_PROPOSAL_REJECT_CODES.unsupportedMethods, methods.join(','));
  }
});

test('06 proposal 时钱包无账户（锁定）→ 拒绝（5002）', async () => {
  const signClient = createSignClientStub();
  createWalletConnectAdapter({ signClient, zchain: mockZchain({ unlocked: false }), network: NETWORK, now: () => NOW_MS });
  const err = await signClient
    .connect({ requiredNamespaces: { zchain: { chains: ['zchain:zchain-devnet-1'], methods: ['zchain_getAccounts'], events: [] } } })
    .then(() => null, (e) => e);
  assert.equal(err.code, WC_PROPOSAL_REJECT_CODES.unsupportedAccounts);
});

// ---------------------------------------------------------------------------
// session_request：路由与拒绝面
// ---------------------------------------------------------------------------

test('07 签名请求路由：signOperation 往返（参数原样、结果回 dapp）', async () => {
  const signCalls = [];
  const { signClient, session } = await approvedSession({ requested: ['zchain_signOperation'] });
  void signCalls;
  const op = validOperation();
  const result = await signClient.request({
    topic: session.topic,
    chainId: 'zchain:zchain-devnet-1',
    request: { method: 'zchain_signOperation', params: { operation: op, previewHash: '' } },
  });
  assert.equal(result.digest, 'de'.repeat(32));
});

test('08 请求了但能力缺失的方法 → CapabilityMissing（绝不退化盲签）', async () => {
  const { signClient, session } = await approvedSession({
    capMethods: FULL_CAP_METHODS.filter((m) => m !== 'zchain_signOperation'),
    requested: ['zchain_getAccounts', 'zchain_signOperation'],
  });
  const err = await rejectionOf(
    signClient,
    reqEvent({ topic: session.topic, method: 'zchain_signOperation', params: {} }),
  );
  assert.equal(err.code, WC_ERROR_CODES.capabilityMissing);
  assert.match(err.message, /ZC-CapabilityMissing/);
  assert.match(err.message, /blind signing/);
});

test('09 从未授予的 zchain_* 方法 → MethodNotGranted', async () => {
  const { signClient, session } = await approvedSession({ requested: ['zchain_getAccounts'] });
  const err = await rejectionOf(
    signClient,
    reqEvent({ topic: session.topic, method: 'zchain_lock' }),
  );
  assert.equal(err.code, WC_ERROR_CODES.methodNotAllowed);
  assert.match(err.message, /ZC-MethodNotGranted/);
});

test('10 白名单外方法（eth_sign / 未知）→ MethodNotAllowed（永不过执行）', async () => {
  const { signClient, session } = await approvedSession();
  const cases = [['eth_sign', 1001], ['wallet_switchEthereumChain', 1002], ['not_a_method', 1003]];
  for (const [method, id] of cases) {
    const err = await rejectionOf(signClient, reqEvent({ id, topic: session.topic, method, params: {} }));
    assert.equal(err.code, WC_ERROR_CODES.methodNotAllowed, method);
    assert.match(err.message, /ZC-MethodNotAllowed/, method);
  }
});

test('11 会话过期 → SessionExpired 拒绝 + 会话被断开', async () => {
  const { signClient, session } = await approvedSession();
  signClient.expireSession(session.topic); // 模拟 relay 侧过期
  const err = await rejectionOf(
    signClient,
    reqEvent({ topic: session.topic, method: 'zchain_getAccounts', params: {} }),
  );
  assert.equal(err.code, WC_ERROR_CODES.sessionExpired);
  assert.match(err.message, /ZC-SessionExpired/);
  // 过期会话被主动断开（session_delete 双向可见）。
  assert.equal(signClient.session.has(session.topic), false);
});

test('12 请求 id 重放/回退 → ReplayDetected', async () => {
  const { signClient, session } = await approvedSession();
  const event = reqEvent({ id: 1001, topic: session.topic, method: 'zchain_getAccounts', params: {} });
  const [first] = await rawRequest(signClient, event);
  assert.ok(first.response.result != null); // 首次成功
  // 完全重放（同 id）
  const err1 = await rejectionOf(signClient, event);
  assert.equal(err1.code, WC_ERROR_CODES.replayDetected);
  assert.match(err1.message, /ZC-ReplayDetected/);
  // 回退 id
  const err2 = await rejectionOf(signClient, reqEvent({ id: 900, topic: session.topic, method: 'zchain_getAccounts', params: {} }));
  assert.equal(err2.code, WC_ERROR_CODES.replayDetected);
});

test('13 请求自带 expiry 已过 → RequestExpired', async () => {
  const { signClient, session } = await approvedSession();
  const nowSec = Math.floor(NOW_MS / 1000);
  const err = await rejectionOf(
    signClient,
    reqEvent({ topic: session.topic, method: 'zchain_getAccounts', expiry: nowSec - 1, params: {} }),
  );
  assert.equal(err.code, WC_ERROR_CODES.requestExpired);
  assert.match(err.message, /ZC-RequestExpired/);
});

test('14 参数结构校验：换链不符 → validation.js 稳定码透传（NetworkMismatch）', async () => {
  const { signClient, session } = await approvedSession({ requested: ['zchain_signOperation'] });
  const err = await rejectionOf(
    signClient,
    reqEvent({
      topic: session.topic,
      method: 'zchain_signOperation',
      params: { operation: validOperation({ chainId: 'ethereum-mainnet' }), previewHash: '' },
    }),
  );
  assert.equal(err.code, WC_ERROR_CODES.invalidParams);
  assert.match(err.message, /ZC-NetworkMismatch/);
});

test('15 chainId 参数非 zchain 当前网络 → UnsupportedChain', async () => {
  const { signClient, session } = await approvedSession();
  const err = await rejectionOf(
    signClient,
    reqEvent({ topic: session.topic, method: 'zchain_getAccounts', params: {}, chainId: 'eip155:1' }),
  );
  assert.match(err.message, /ZC-UnsupportedChain/);
});

test('16 断开后的会话请求 → UnknownSession', async () => {
  const { signClient, session } = await approvedSession();
  signClient.disconnect({ topic: session.topic, reason: { message: 'dapp closed' } });
  const err = await rejectionOf(
    signClient,
    reqEvent({ topic: session.topic, method: 'zchain_getAccounts', params: {} }),
  );
  assert.equal(err.code, WC_ERROR_CODES.unknownSession);
  assert.match(err.message, /ZC-UnknownSession/);
});

test('17 事件转发：zchain:chainChanged → session_event（发给每个活动会话）', async () => {
  const { signClient, z, session } = await approvedSession();
  const seen = [];
  signClient.onSessionEvent((e) => seen.push(e));
  z.emit('zchain:chainChanged', 'zchain-devnet-1');
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(seen.length, 1);
  assert.equal(seen[0].topic, session.topic);
  assert.deepEqual(seen[0].event, { name: 'chainChanged', data: 'zchain-devnet-1' });
  assert.equal(seen[0].chainId, 'zchain:zchain-devnet-1');
});
