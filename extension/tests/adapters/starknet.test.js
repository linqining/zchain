// =============================================================================
// extension/tests/adapters/starknet.test.js — Starknet 钱包接口适配器测试
//
// 覆盖（node:test；钱包对象/verifier/registry 全部 mock；验签接口形状与
// wallet-core 一致——真实摘要（SNIP-12 Poseidon）与 Stark 验签仍属 wallet-core，
// 本文件零密码学）：
//   encode_type 与 wallet-core 逐字一致 · typed data 域/成员/值形状完整 ·
//   钱包对象探测（含 zchain provider 误认防护）· 授权全流程正例（验签通过 +
//   登记 constraints 镜像）· 篡改签名拒 · withdraw scope 拒 · 未知 scope 拒 ·
//   过期/未生效拒 · 换链拒 · 钱包未连接/非钱包拒 · signMessage 抛错（用户拒）·
//   签名归一化。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  AUTHORIZE_ENCODE_TYPE,
  SESSION_SCOPES,
  SNIP12_REVISION,
  authorizeSessionKeyViaStarknet,
  buildAuthorizeTypedData,
  detectStarknetWallet,
  normalizeStarkSignature,
  validateAuthorizationRequest,
} from '../../adapters/starknet.js';

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

const CHAIN_ID = 'zchain-devnet-1';
const NOW_SEC = 1_757_000_000;
const ADDR = '0x03fdc1fba1dd7a1a3f4a1e0a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a'; // felt hex 形状示例
const PK33 = '0200000000000000000000000000000000000000000000000000000000000000ab'; // 33B 压缩公钥 hex
const BINDING_ID = 'aa'.repeat(32);

function authRequest(over = {}) {
  return {
    chainId: CHAIN_ID,
    accountAddress: ADDR,
    delegatedPublicKey: PK33,
    signatureScheme: 'secp256k1',
    allowedScopes: ['play', 'buyin', 'settle'],
    perTxLimit: '1000',
    perDayLimit: '5000',
    tableAllowlist: [1, 2],
    bindingId: BINDING_ID,
    nonce: 7,
    validAfter: NOW_SEC - 100,
    validUntil: NOW_SEC + 3600,
    ...over,
  };
}

function mockWallet(over = {}) {
  const state = { signCalls: [], chainId: over.walletChainId ?? 'SN_SEPOLIA' };
  const wallet = {
    isConnected: over.isConnected ?? true,
    account: { address: ADDR },
    getChainId: async () => state.chainId,
    signMessage: async (typedData) => {
      state.signCalls.push(typedData);
      if (over.signError) throw new Error(over.signError);
      const sig = over.signature ?? deterministicSignature(typedData);
      return over.signatureShape === 'object' ? { r: sig[0], s: sig[1] } : sig;
    },
  };
  return { wallet, state };
}

/** 确定性"签名"（测试管线用占位推导，非密码学）：与 mock verifier 配对。 */
function derive(typedData, salt = 0) {
  let h = 0x9e3779b9 ^ salt;
  const s = JSON.stringify(typedData);
  for (let i = 0; i < s.length; i += 1) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) >>> 0;
  }
  return `0x${((h ^ 0x5f3759df) >>> 0).toString(16)}`; // >>> 0：保持无符号 32 位
}
function deterministicSignature(typedData) {
  return [derive(typedData, 1), derive(typedData, 2)];
}

/** wallet-core 形状 verifier 的 mock：只接受 mock 钱包产出的签名。 */
function mockVerifier() {
  return async ({ typedData, signature }) => {
    const [r, s] = deterministicSignature(typedData);
    if (signature.r === r && signature.s === s) {
      return { ok: true, digest: derive(typedData, 3) };
    }
    return { ok: false };
  };
}

function mockRegistry() {
  const bindings = new Map();
  return {
    bindings,
    registerBinding: async (binding) => {
      bindings.set(binding.bindingId, binding);
      return { ok: true };
    },
  };
}

// ---------------------------------------------------------------------------
// typed data 规范（与 wallet-core account_binding.rs 一致性）
// ---------------------------------------------------------------------------

test('01 AuthorizeZChainKey encode_type 与 wallet-core authorize_encode_type 逐字一致', () => {
  assert.equal(
    AUTHORIZE_ENCODE_TYPE,
    'AuthorizeZChainKey(account_address:felt252,allowed_scopes:shortstring[],binding_id:felt252,' +
      'chain_id:shortstring,delegated_public_key:bytes,nonce:felt252,per_day_limit:amount,' +
      'per_tx_limit:amount,signature_scheme:shortstring,table_allowlist:felt252[],' +
      'table_allowlist_scope:shortstring,valid_after:amount,valid_until:amount,' +
      'zchain_chain_id:shortstring)',
  );
});

test('02 typed data：域字段齐全（ZChain/1/zchain-devnet-1/revision=1）', () => {
  const { ok, typedData } = buildAuthorizeTypedData(authRequest(), { chainId: CHAIN_ID });
  assert.equal(ok, true);
  assert.deepEqual(typedData.domain, { name: 'ZChain', version: '1', chainId: CHAIN_ID, revision: SNIP12_REVISION });
  assert.equal(typedData.primaryType, 'AuthorizeZChainKey');
  // StarknetDomain 成员（rev1 含 revision）
  assert.deepEqual(
    typedData.types.StarknetDomain.map((m) => `${m.name}:${m.type}`).join(','),
    'name:shortstring,version:shortstring,chainId:shortstring,revision:shortstring',
  );
  // 内建类型登记（SNIP-12 rev1）
  for (const builtin of ['shortstring', 'felt252', 'bytes', 'amount']) {
    assert.deepEqual(typedData.types[builtin], [], builtin);
  }
});

test('03 typed data：message 14 个成员齐全且值形状符合 SNIP-12（amount 十进制/bytes 字节数组）', () => {
  const { typedData } = buildAuthorizeTypedData(authRequest(), { chainId: CHAIN_ID });
  const msg = typedData.message;
  // 与 encode_type 的成员名单一致（名字母序）
  assert.deepEqual(
    Object.keys(msg).sort(),
    AUTHORIZE_ENCODE_TYPE.slice('AuthorizeZChainKey('.length, -1).split(',').map((m) => m.split(':')[0]).sort(),
  );
  assert.equal(msg.account_address, ADDR.toLowerCase());
  assert.deepEqual(msg.allowed_scopes, ['play', 'buyin', 'settle']);
  assert.equal(msg.binding_id, `0x${BINDING_ID}`);
  assert.equal(msg.chain_id, CHAIN_ID);
  assert.equal(msg.zchain_chain_id, CHAIN_ID);
  // bytes = 每字节一个 '0x..'（33 项）
  assert.equal(msg.delegated_public_key.length, 33);
  assert.ok(msg.delegated_public_key.every((b) => /^0x[0-9a-f]{2}$/.test(b)));
  // amount = 十进制字符串
  assert.equal(msg.per_tx_limit, '1000');
  assert.equal(msg.per_day_limit, '5000');
  assert.equal(msg.valid_after, String(NOW_SEC - 100));
  assert.equal(msg.valid_until, String(NOW_SEC + 3600));
  assert.equal(msg.signature_scheme, 'secp256k1');
  assert.equal(msg.nonce, '0x7');
  assert.deepEqual(msg.table_allowlist, ['0x1', '0x2']);
  assert.equal(msg.table_allowlist_scope, 'allowlist');
});

test('04 typed data：tableAllowlist=null → table_allowlist_scope=all（wallet-core 语义）', () => {
  const { typedData } = buildAuthorizeTypedData(authRequest({ tableAllowlist: null }), { chainId: CHAIN_ID });
  assert.equal(typedData.message.table_allowlist_scope, 'all');
  assert.deepEqual(typedData.message.table_allowlist, []);
});

// ---------------------------------------------------------------------------
// 钱包探测
// ---------------------------------------------------------------------------

test('05 探测：识别 starknet/stargate 形状钱包；缺方法不认；zchain provider 不误认', () => {
  const { wallet } = mockWallet();
  const g = { starknet: wallet };
  const d = detectStarknetWallet(g);
  assert.equal(d.namespace, 'starknet');
  assert.equal(d.isConnected, true);
  assert.equal(d.address, ADDR);
  assert.equal(d.wallet, wallet);
  // stargate 命名空间
  assert.equal(detectStarknetWallet({ starknet: null, stargate: wallet }).namespace, 'stargate');
  // 缺 signMessage → 不认（fail-closed）
  assert.equal(detectStarknetWallet({ starknet: { isConnected: true, account: {}, getChainId() {} } }), null);
  // 自家 provider（isZChain）不误认
  assert.equal(detectStarknetWallet({ starknet: { isZChain: true, signMessage() {}, getChainId() {} } }), null);
  assert.equal(detectStarknetWallet({}), null);
});

// ---------------------------------------------------------------------------
// 授权主流程
// ---------------------------------------------------------------------------

test('06 正例：签名验证通过 + 登记 constraints 镜像（与 SNIP-12 message 字段一一对应）', async () => {
  const { wallet, state } = mockWallet();
  const registry = mockRegistry();
  const req = authRequest();
  const res = await authorizeSessionKeyViaStarknet(wallet, req, {
    chainId: CHAIN_ID,
    nowSec: NOW_SEC,
    verifySignature: mockVerifier(),
    registerBinding: registry.registerBinding,
  });
  assert.equal(res.ok, true);
  assert.equal(res.bindingId, BINDING_ID);
  assert.ok(state.signCalls.length === 1); // 只 signMessage 一次
  assert.equal(state.signCalls[0].primaryType, 'AuthorizeZChainKey');
  // 登记内容 = 请求字段的镜像（constraints_from_message 语义）
  const b = registry.bindings.get(BINDING_ID);
  assert.ok(b, 'binding registered');
  assert.equal(b.chainId, CHAIN_ID);
  assert.equal(b.accountAddress, ADDR.toLowerCase());
  assert.equal(b.delegatedPublicKey, PK33.toLowerCase());
  assert.deepEqual(b.allowedScopes, ['play', 'buyin', 'settle']);
  assert.equal(b.perTxLimit, '1000');
  assert.equal(b.perDayLimit, '5000');
  assert.deepEqual(b.tableAllowlist, [1, 2]);
  assert.equal(b.nonce, 7);
  assert.equal(b.validAfter, NOW_SEC - 100);
  assert.equal(b.validUntil, NOW_SEC + 3600);
  assert.equal(b.walletChainId, 'SN_SEPOLIA'); // 审计字段：钱包自身链 id（如实记录，不冒充相等）
  assert.ok(b.digest);
});

test('07 篡改签名 → 验签拒（SignatureRejected），且不登记', async () => {
  const { wallet } = mockWallet();
  const registry = mockRegistry();
  const sig = deterministicSignature(buildAuthorizeTypedData(authRequest(), { chainId: CHAIN_ID }).typedData);
  const tampered = [sig[0], `0x${(BigInt(sig[1]) + 1n).toString(16)}`];
  const res = await authorizeSessionKeyViaStarknet(
    mockWallet({ signature: tampered }).wallet,
    authRequest(),
    { chainId: CHAIN_ID, nowSec: NOW_SEC, verifySignature: mockVerifier(), registerBinding: registry.registerBinding },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, 'SignatureRejected');
  assert.equal(registry.bindings.size, 0);
  void wallet;
});

test('08 scope 红线：withdraw 进会话密钥 → ScopeForbidden（签名前拒绝，不触达钱包）', async () => {
  const { wallet, state } = mockWallet();
  const registry = mockRegistry();
  const res = await authorizeSessionKeyViaStarknet(wallet, authRequest({ allowedScopes: ['play', 'withdraw'] }), {
    chainId: CHAIN_ID,
    nowSec: NOW_SEC,
    verifySignature: mockVerifier(),
    registerBinding: registry.registerBinding,
  });
  assert.equal(res.code, 'ScopeForbidden');
  assert.equal(state.signCalls.length, 0); // 用户不被诱导盲签坏请求
  assert.equal(registry.bindings.size, 0);
});

test('09 scope：未知 scope 拒（ScopeUnknown）；空数组拒（InvalidParams）', async () => {
  const bad1 = validateAuthorizationRequest(authRequest({ allowedScopes: ['play', 'megaadmin'] }), { chainId: CHAIN_ID, nowSec: NOW_SEC });
  assert.equal(bad1.code, 'ScopeUnknown');
  const bad2 = validateAuthorizationRequest(authRequest({ allowedScopes: [] }), { chainId: CHAIN_ID, nowSec: NOW_SEC });
  assert.equal(bad2.code, 'InvalidParams');
  // 全集常量不含 withdraw
  assert.ok(SESSION_SCOPES.includes('play') && !SESSION_SCOPES.includes('withdraw'));
});

test('10 scoped 授权：已过期（validUntil<now）拒 Expired；未生效（validAfter>now）拒 NotYetValid', async () => {
  const { wallet, state } = mockWallet();
  const deps = { chainId: CHAIN_ID, nowSec: NOW_SEC, verifySignature: mockVerifier(), registerBinding: mockRegistry().registerBinding };
  const expired = await authorizeSessionKeyViaStarknet(wallet, authRequest({ validUntil: NOW_SEC - 1 }), deps);
  assert.equal(expired.code, 'Expired');
  const future = await authorizeSessionKeyViaStarknet(wallet, authRequest({ validAfter: NOW_SEC + 100 }), deps);
  assert.equal(future.code, 'NotYetValid');
  assert.equal(state.signCalls.length, 0);
});

test('11 换链：request.chainId 与目标网络不符 → NetworkMismatch', async () => {
  const res = validateAuthorizationRequest(authRequest({ chainId: 'zchain-testnet-1' }), { chainId: CHAIN_ID, nowSec: NOW_SEC });
  assert.equal(res.code, 'NetworkMismatch');
  // 钱包自身是 zchain 托管网络且与 domain 不一致 → NetworkMismatch（不冒充）
  const { wallet } = mockWallet({ walletChainId: 'zchain:zchain-testnet-1' });
  const res2 = await authorizeSessionKeyViaStarknet(wallet, authRequest(), {
    chainId: CHAIN_ID,
    nowSec: NOW_SEC,
    verifySignature: mockVerifier(),
    registerBinding: mockRegistry().registerBinding,
  });
  assert.equal(res2.code, 'NetworkMismatch');
});

test('12 钱包边界：未连接拒 WalletNotConnected；非钱包对象拒 WalletUnsupported', async () => {
  const { wallet } = mockWallet({ isConnected: false });
  const deps = { chainId: CHAIN_ID, nowSec: NOW_SEC, verifySignature: mockVerifier(), registerBinding: mockRegistry().registerBinding };
  const r1 = await authorizeSessionKeyViaStarknet(wallet, authRequest(), deps);
  assert.equal(r1.code, 'WalletNotConnected');
  const r2 = await authorizeSessionKeyViaStarknet({ isZChain: true }, authRequest(), deps);
  assert.equal(r2.code, 'WalletUnsupported');
  const r3 = await authorizeSessionKeyViaStarknet(null, authRequest(), deps);
  assert.equal(r3.code, 'WalletUnsupported');
});

test('13 用户在钱包侧拒绝签名 → UserRejected；无 verifier/registry 依赖 → InvalidArgument', async () => {
  const { wallet } = mockWallet({ signError: 'user rejected' });
  const res = await authorizeSessionKeyViaStarknet(wallet, authRequest(), {
    chainId: CHAIN_ID,
    nowSec: NOW_SEC,
    verifySignature: mockVerifier(),
    registerBinding: mockRegistry().registerBinding,
  });
  assert.equal(res.code, 'UserRejected');
  const missing = await authorizeSessionKeyViaStarknet(mockWallet().wallet, authRequest(), { chainId: CHAIN_ID });
  assert.equal(missing.code, 'InvalidArgument');
});

test('14 字段形状：坏公钥长度/坏地址/坏 bindingId/validAfter>=validUntil → InvalidParams', () => {
  for (const [over, desc] of [
    [{ delegatedPublicKey: 'abcd' }, 'pk len'],
    [{ accountAddress: '0xzz' }, 'addr shape'],
    [{ bindingId: 'aa' }, 'bindingId len'],
    [{ validAfter: NOW_SEC + 3600, validUntil: NOW_SEC + 3600 }, 'window empty'],
    [{ perTxLimit: '-5' }, 'negative limit'],
    [{ nonce: -1 }, 'negative nonce'],
  ]) {
    const r = validateAuthorizationRequest(authRequest(over), { chainId: CHAIN_ID, nowSec: NOW_SEC });
    assert.equal(r.code, 'InvalidParams', desc);
  }
});

test('15 签名归一化：[十进制 r,s] / {r,s hex} / 垃圾输入', () => {
  const a = normalizeStarkSignature(['12345', '678']);
  assert.equal(a.r, BigInt(12345).toString(16).padStart(0, 'x') && `0x${BigInt('12345').toString(16)}`);
  assert.equal(a.s, `0x${BigInt('678').toString(16)}`);
  const b = normalizeStarkSignature({ r: '0xabc', s: '0xdef' });
  assert.equal(b.r, '0xabc');
  assert.equal(b.s, '0xdef');
  for (const bad of [null, [], ['1'], ['1', '2', '3'], { r: 'xyz', s: '1' }, 'sig']) {
    assert.equal(normalizeStarkSignature(bad), null, JSON.stringify(bad));
  }
});
