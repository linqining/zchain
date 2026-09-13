// =============================================================================
// extension/tests/validation.test.js — 安全校验层测试（node:test，无框架依赖）
//
// 运行：node --test extension/tests/
//
// 覆盖（WALLET-ACC-3 的插件侧判定面；每类拒绝都有正例 + 负例）：
//   伪造 origin / 重放 nonce / 回退 nonce / 过期信封 / session 绑定与锁定 /
//   未知 method / 0.1 未交付 method / 缺参 / 金额溢出与非法 / 换链不符 /
//   ABI 版本不认识 / domain 不认识 / REAL 边界 / 提现类边界 / 权限最小化
//   （首次连接、换网、提现类、批量签名）/ 请求状态机（取消、超时、重复）/
//   输出脱敏 / origin 规范化。
//
// 本文件不测试密码学——密码学只在 wallet-core（wasm_smoke.mjs 走真实路径）。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  checkEnvelope,
  canonicalOrigin,
  grantOrigin,
  originIsGranted,
  openPendingRequest,
  reject,
  requiresExplicitConfirm,
  revokeOrigin,
  sanitizeNotesForPage,
  sweepExpired,
  transitionRequest,
  validateAmount,
  validateHex,
  validateRequest,
} from '../common/validation.js';

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

const ORIGIN = 'https://play.example';
const NOW_MS = 1_757_000_000_000; // 2026-09-04T…Z（毫秒）
const NOW_SEC = Math.floor(NOW_MS / 1000);
const EXP_SEC = NOW_SEC + 600;
const SESSION = { id: 'sess-abc', expiresAt: NOW_MS + 3_600_000, locked: false };
const STATE = { nonceLedger: {}, session: SESSION };
const GRANTS = grantOrigin(ORIGIN, {}, NOW_SEC);
const NETWORK = { chainId: 'zchain-devnet-1' };

function envelope(over = {}) {
  return {
    origin: over.origin ?? ORIGIN,
    nonce: over.nonce ?? 1,
    expiry: over.expiry ?? EXP_SEC,
    sessionId: over.sessionId ?? 'sess-abc',
    requestId: over.requestId ?? 'req-1',
  };
}

function msg(over = {}) {
  return { envelope: envelope(over.env), method: over.method ?? 'zchain_getNetwork', params: over.params ?? {} };
}

function validTransfer(over = {}) {
  return {
    kind: 'transfer',
    assetClass: 'PLAY',
    chainId: NETWORK.chainId,
    domain: 'zchain',
    abiVersion: 1,
    nonce: 7,
    expiry: EXP_SEC,
    inputs: ['ab'.repeat(32)],
    outputs: [{ owner: 'cd'.repeat(33), amount: '50' }],
    ...over,
  };
}

// ---------------------------------------------------------------------------
// 信封：origin / nonce / expiry / session（WALLET-ACC-3 插件侧）
// ---------------------------------------------------------------------------

test('01 正常流：合法信封通过并推进该 origin 的 nonce 账本', () => {
  const r = checkEnvelope(msg(), ORIGIN, STATE, { now: NOW_MS, grants: GRANTS });
  assert.equal(r.ok, true);
  assert.equal(r.nextState.nonceLedger[ORIGIN], 1);
});

test('02 伪造 origin：envelope.origin 与 sender 真实 origin 不符 → 拒绝', () => {
  const forged = msg({ env: { ...envelope(), origin: 'https://evil.example' } });
  const r = checkEnvelope(forged, ORIGIN, STATE, { now: NOW_MS, grants: GRANTS });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'OriginMismatch');
});

test('03 origin 未授权：白名单外站点 → 拒绝（每 origin 单独保存权限）', () => {
  // envelope.origin 与 sender 一致（否则先命中 OriginMismatch），但该 origin
  // 从未被授权 → OriginNotPermitted。
  const r = checkEnvelope(msg({ env: { ...envelope(), origin: 'https://stranger.example' } }), 'https://stranger.example', STATE, { now: NOW_MS, grants: GRANTS });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'OriginNotPermitted');
});

test('04 重放 nonce：同 origin 相同 nonce 二次使用 → NonceReplay', () => {
  const state = { ...STATE, nonceLedger: { [ORIGIN]: 41 } };
  const r = checkEnvelope(msg({ env: { ...envelope(), nonce: 41 } }), ORIGIN, state, { now: NOW_MS, grants: GRANTS });
  assert.equal(r.code, 'NonceReplay');
});

test('05 回退 nonce：更小 nonce → NonceReplay（单调性）', () => {
  const state = { ...STATE, nonceLedger: { [ORIGIN]: 100 } };
  const r = checkEnvelope(msg({ env: { ...envelope(), nonce: 99 } }), ORIGIN, state, { now: NOW_MS, grants: GRANTS });
  assert.equal(r.code, 'NonceReplay');
});

test('06 非 safe integer nonce（含小数/负数/超大）→ NonceInvalid', () => {
  for (const nonce of [1.5, -1, 2 ** 53, Number.MAX_SAFE_INTEGER + 1]) {
    const r = checkEnvelope(msg({ env: { ...envelope(), nonce } }), ORIGIN, STATE, { now: NOW_MS, grants: GRANTS });
    assert.equal(r.code, 'NonceInvalid', `nonce=${nonce}`);
  }
});

test('07 过期信封：expiry <= now → EnvelopeExpired', () => {
  const past = NOW_SEC - 1;
  const r = checkEnvelope(msg({ env: { ...envelope(), expiry: past } }), ORIGIN, STATE, { now: NOW_MS, grants: GRANTS });
  assert.equal(r.code, 'EnvelopeExpired');
});

test('08 session 绑定：错误 sessionId / 已锁定 / 会话过期 → SessionInvalid', () => {
  const wrong = checkEnvelope(msg({ env: { ...envelope(), sessionId: 'sess-other' } }), ORIGIN, STATE, { now: NOW_MS, grants: GRANTS });
  assert.equal(wrong.code, 'SessionInvalid');

  const lockedState = { ...STATE, session: { ...SESSION, locked: true } };
  const locked = checkEnvelope(msg(), ORIGIN, lockedState, { now: NOW_MS, grants: GRANTS });
  assert.equal(locked.code, 'SessionInvalid');

  const expiredState = { ...STATE, session: { ...SESSION, expiresAt: NOW_MS - 1 } };
  const expired = checkEnvelope(msg(), ORIGIN, expiredState, { now: NOW_MS, grants: GRANTS });
  assert.equal(expired.code, 'SessionInvalid');
});

// ---------------------------------------------------------------------------
// 请求结构：method / 参数 / 金额 / 网络 / ABI / domain / 资产边界
// ---------------------------------------------------------------------------

test('09 未知 method → UnknownMethod', () => {
  const r = validateRequest('eth_sendTransaction', {}, { network: NETWORK });
  assert.equal(r.code, 'UnknownMethod');
});

test('10 未交付 method（authorizeSessionKey/revokeSessionKey/verifyProof/watchProof）→ NotSupportedIn01', () => {
  for (const m of ['zchain_authorizeSessionKey', 'zchain_revokeSessionKey', 'zchain_verifyProof', 'zchain_watchProof']) {
    const r = validateRequest(m, {}, { network: NETWORK });
    assert.equal(r.code, 'NotSupportedIn01', m);
  }
});

test('11 缺必填参数 → MissingParam', () => {
  const r = validateRequest('zchain_signOperation', { operation: undefined }, { network: NETWORK });
  assert.equal(r.code, 'MissingParam');
});

test('12 金额溢出：u64+1 → AmountOverflow；非法金额（负数/小数/0/前导零/科学计数）→ AmountInvalid', () => {
  const big = validateRequest('zchain_signOperation', { operation: validTransfer({ outputs: [{ owner: 'cd'.repeat(33), amount: '18446744073709551616' }] }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(big.code, 'AmountOverflow');

  for (const amount of ['-1', '1.5', '0', '01', '1e9', '0x10']) {
    const r = validateRequest('zchain_signOperation', { operation: validTransfer({ outputs: [{ owner: 'cd'.repeat(33), amount }] }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
    assert.equal(r.code, 'AmountInvalid', `amount=${amount}`);
  }
});

test('13 validateAmount 单元：安全整数接受并归一为字符串；u64 边界接受', () => {
  assert.deepEqual(validateAmount(50), { ok: true, amount: '50' });
  assert.equal(validateAmount('18446744073709551615').ok, true); // u64 max
  assert.equal(validateAmount('18446744073709551616').code, 'AmountOverflow');
  assert.equal(validateAmount(2 ** 53).code, 'AmountInvalid'); // 非安全整数
});

test('14 换链不符：operation.chainId != 当前网络 → NetworkMismatch', () => {
  const r = validateRequest('zchain_signOperation', { operation: validTransfer({ chainId: 'zchain-testnet-1' }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(r.code, 'NetworkMismatch');
});

test('15 ABI 版本不认识 → AbiUnsupported', () => {
  const r = validateRequest('zchain_signOperation', { operation: validTransfer({ abiVersion: 2 }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(r.code, 'AbiUnsupported');
});

test('16 domain 不认识（eip155/SN_MAIN 等任意标签）→ DomainUnsupported', () => {
  for (const domain of ['eip155', 'SN_MAIN', 'zchainx', '']) {
    const r = validateRequest('zchain_signOperation', { operation: validTransfer({ domain }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
    assert.equal(r.code, 'DomainUnsupported', `domain=${domain}`);
  }
});

test('17 REAL 在 0.1 拒绝（PLAY 默认；REAL 隔离是 0.2）→ AssetClassDisabledIn01', () => {
  const r = validateRequest('zchain_signOperation', { operation: validTransfer({ assetClass: 'REAL' }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(r.code, 'AssetClassDisabledIn01');
});

test('18 提现类/密钥轮换在 0.1 拒绝 → KindDisabledIn01；未知 kind → UnknownKind', () => {
  const w = validateRequest('zchain_signOperation', { operation: validTransfer({ kind: 'withdraw' }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(w.code, 'KindDisabledIn01');
  const k = validateRequest('zchain_signOperation', { operation: validTransfer({ kind: 'key_rotation' }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(k.code, 'KindDisabledIn01');
  const u = validateRequest('zchain_signOperation', { operation: validTransfer({ kind: 'mint_all' }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(u.code, 'UnknownKind');
});

test('19 正常签名请求全绿：transfer / buy_in / settle（settle 走 signSettlement 形状）', () => {
  const t = validateRequest('zchain_signOperation', { operation: validTransfer(), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(t.ok, true, t.reason);

  const b = validateRequest('zchain_signOperation', { operation: validTransfer({ kind: 'buy_in', tableId: 1, seatOwner: 'cd'.repeat(33), outputs: undefined }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(b.ok, true, b.reason);

  const s = validateRequest(
    'zchain_signSettlement',
    { settlement: { chainId: NETWORK.chainId, domain: 'zchain', abiVersion: 1, assetClass: 'PLAY', nonce: 9, expiry: EXP_SEC, recordBorsh: 'ab'.repeat(64), policyBorsh: 'cd'.repeat(32) }, previewHash: 'f'.repeat(64) },
    { network: NETWORK },
  );
  assert.equal(s.ok, true, s.reason);
});

test('20 结构非法：输入承诺越界/输出越界/坏 hex → InvalidParams', () => {
  const PH = 'f'.repeat(64);
  const emptyInputs = validateRequest('zchain_signOperation', { operation: validTransfer({ inputs: [] }), previewHash: PH }, { network: NETWORK });
  assert.equal(emptyInputs.code, 'InvalidParams');

  const tooMany = validateRequest('zchain_signOperation', { operation: validTransfer({ inputs: Array.from({ length: 17 }, () => 'ab'.repeat(32)) }), previewHash: PH }, { network: NETWORK });
  assert.equal(tooMany.code, 'InvalidParams');

  const badHex = validateRequest('zchain_signOperation', { operation: validTransfer({ inputs: ['zz'] }), previewHash: PH }, { network: NETWORK });
  assert.equal(badHex.code, 'InvalidParams');

  const noTable = validateRequest('zchain_signOperation', { operation: validTransfer({ kind: 'buy_in', tableId: 1, seatOwner: 'cd'.repeat(33) }), previewHash: PH }, { network: NETWORK });
  assert.equal(noTable.ok, true); // buy_in 不要求 outputs
  const badOwner = validateRequest('zchain_signOperation', { operation: validTransfer({ outputs: [{ owner: 'cd', amount: '50' }] }), previewHash: PH }, { network: NETWORK });
  assert.equal(badOwner.code, 'InvalidParams');
});

// ---------------------------------------------------------------------------
// 权限最小化：首次连接 / 换网 / 提现类 / 批量签名 → 必须显式确认
// ---------------------------------------------------------------------------

test('21 权限最小化判定：首次连接、换网、提现类、批量签名、一切签名 → requireExplicitConfirm', () => {
  const grants = {};
  // 首次连接
  assert.equal(requiresExplicitConfirm({ method: 'zchain_requestAccounts', params: {}, origin: ORIGIN }, { grants }), true);
  // 授权后：查询类可静默
  assert.equal(requiresExplicitConfirm({ method: 'zchain_getNetwork', params: {}, origin: ORIGIN }, { grants: GRANTS }), false);
  // 换网
  assert.equal(requiresExplicitConfirm({ method: 'zchain_switchNetwork', params: { chainId: 'x' }, origin: ORIGIN }, { grants: GRANTS }), true);
  // 提现类（即便 0.1 已拒，判定层面仍要求确认——纵深）
  assert.equal(requiresExplicitConfirm({ method: 'zchain_signOperation', params: { operation: { kind: 'withdraw' } }, origin: ORIGIN }, { grants: GRANTS }), true);
  // 批量签名
  assert.equal(requiresExplicitConfirm({ method: 'zchain_signOperation', params: { batch: [validTransfer(), validTransfer()] }, origin: ORIGIN }, { grants: GRANTS }), true);
  // 一切签名
  assert.equal(requiresExplicitConfirm({ method: 'zchain_signOperation', params: { operation: validTransfer() }, origin: ORIGIN }, { grants: GRANTS }), true);
});

test('22 origin 授权簿：grant/revoke 往返 + 非 http(s) origin 规范化拒绝', () => {
  let g = grantOrigin('https://play.example:443/path?q=1', {}, NOW_SEC); // URL 规范化去路径/端口默认
  assert.equal(originIsGranted('https://play.example', g), true);
  assert.equal(canonicalOrigin('javascript:alert(1)'), null);
  assert.equal(canonicalOrigin('chrome-extension://abc/x'), null);
  assert.equal(canonicalOrigin('file:///etc/passwd'), null);
  g = revokeOrigin('https://play.example', g);
  assert.equal(originIsGranted('https://play.example', g), false);
});

// ---------------------------------------------------------------------------
// 请求状态机：取消 / 超时 / 重复（WALLET-ACC-3 "取消、超时和重放测试"）
// ---------------------------------------------------------------------------

test('23 请求状态机：pending → approved；二次迁移拒绝；用户拒绝也合法', () => {
  let store = {};
  const opened = openPendingRequest(store, 'req-1', { kind: 'transfer' }, NOW_MS);
  assert.equal(opened.ok, true);
  store = opened.store;

  const ok = transitionRequest(store, 'req-1', 'approved', NOW_MS + 1);
  assert.equal(ok.ok, true);
  const again = transitionRequest(ok.store, 'req-1', 'rejected', NOW_MS + 2);
  assert.equal(again.code, 'InvalidTransition');

  const opened2 = openPendingRequest(store, 'req-2', {}, NOW_MS);
  const rej = transitionRequest(opened2.store, 'req-2', 'rejected', NOW_MS + 1);
  assert.equal(rej.ok, true);
});

test('24 请求超时：超 TTL 后 approve → RequestExpired；sweepExpired 批量清扫', () => {
  let store = {};
  const opened = openPendingRequest(store, 'req-1', {}, NOW_MS);
  store = opened.store;
  const late = transitionRequest(store, 'req-1', 'approved', NOW_MS + 120_001);
  assert.equal(late.code, 'RequestExpired');

  const opened2 = openPendingRequest(store, 'req-2', {}, NOW_MS);
  const opened3 = openPendingRequest(opened2.store, 'req-3', {}, NOW_MS);
  const swept = sweepExpired(opened3.store, NOW_MS + 120_001);
  assert.deepEqual(swept.expired, ['req-1', 'req-2', 'req-3'].filter((id) => true)); // 三个都过期
  assert.equal(swept.store['req-1'].state, 'expired');

  // 清扫后的 expired 请求不可再 approve（fail-closed）
  const after = transitionRequest(swept.store, 'req-1', 'approved', NOW_MS + 120_002);
  assert.equal(after.code, 'InvalidTransition');
});

test('25 requestId 去重：同 id 复用未结束请求 → DuplicateRequestId；复用已过期请求允许', () => {
  let store = {};
  const o1 = openPendingRequest(store, 'req-1', {}, NOW_MS);
  store = o1.store;
  const dup = openPendingRequest(store, 'req-1', {}, NOW_MS + 1);
  assert.equal(dup.code, 'DuplicateRequestId');
  const swept = sweepExpired(store, NOW_MS + 120_001); // 过 TTL 后清扫
  const reuse = openPendingRequest(swept.store, 'req-1', {}, NOW_MS + 120_002);
  assert.equal(reuse.ok, true);
});

// ---------------------------------------------------------------------------
// 输出脱敏 + hex 工具
// ---------------------------------------------------------------------------

test('26 输出脱敏：sanitizeNotesForPage 剥离 spend secret / nullifier / 内部字段', () => {
  const internal = [
    {
      commitment: 'ab'.repeat(32),
      amount: '300',
      table_id: null,
      proof: 'soft',
      spendable: true,
      spend_secret: 'ff'.repeat(32),
      nullifier: 'ee'.repeat(32),
      origin_frame: { op_index: 0, frame_hash: '11'.repeat(32) },
    },
  ];
  const out = sanitizeNotesForPage(internal);
  assert.equal(out.length, 1);
  const blob = JSON.stringify(out);
  for (const banned of ['spend_secret', 'nullifier', 'origin_frame', 'frame_hash']) {
    assert.ok(!blob.includes(banned), `leaked ${banned}`);
  }
  assert.equal(out[0].commitment, 'ab'.repeat(32));
  assert.equal(out[0].amount, '300');
});

test('27 validateHex：长度精确匹配 + 字符集 + 上限', () => {
  assert.equal(validateHex('ab'.repeat(32), 32).ok, true);
  assert.equal(validateHex('ab'.repeat(31), 32).code, 'InvalidParams');
  assert.equal(validateHex('aB'.repeat(32), 32).ok, true); // 大小写接受
  assert.equal(validateHex('0x' + 'ab'.repeat(32), 32).code, 'InvalidParams'); // 无 0x 前缀
  assert.equal(validateHex('ab'.repeat(33), null, { maxLen: 32 }).code, 'InvalidParams');
  assert.equal(validateHex('', 32).code, 'InvalidParams');
});

test('28 信封畸形：缺 envelope / method 缺失 / requestId 过长 → BadEnvelope', () => {
  const noEnv = checkEnvelope({ method: 'zchain_getNetwork' }, ORIGIN, STATE, { now: NOW_MS, grants: GRANTS });
  assert.equal(noEnv.code, 'BadEnvelope');
  const noMethod = checkEnvelope({ envelope: envelope() }, ORIGIN, STATE, { now: NOW_MS, grants: GRANTS });
  assert.equal(noMethod.code, 'BadEnvelope');
  const longId = checkEnvelope(msg({ env: { ...envelope(), requestId: 'x'.repeat(129) } }), ORIGIN, STATE, { now: NOW_MS, grants: GRANTS });
  assert.equal(longId.code, 'BadEnvelope');
});

// ---------------------------------------------------------------------------
// Extension 0.2：多网络 switchNetwork 判定面（mainnet 红线 + REAL 展示透传）
// ---------------------------------------------------------------------------

test('29 换网（0.2）：目标必须是注册表内网络；mainnet/未知网络 → NetworkUnsupported', () => {
  // testnet：结构合法（0.2 交付真换网；确认流由后台弹窗完成）
  const t = validateRequest('zchain_switchNetwork', { chainId: 'zchain-testnet-1' }, { network: NETWORK });
  assert.equal(t.ok, true, t.reason);
  // 同网切换也结构合法（幂等 no-op 在后台处理）
  const same = validateRequest('zchain_switchNetwork', { chainId: 'zchain-devnet-1' }, { network: NETWORK });
  assert.equal(same.ok, true);
  // mainnet 红线：刻意不注册 → NetworkUnsupported（理由必须明示"刻意"）
  const m = validateRequest('zchain_switchNetwork', { chainId: 'zchain-mainnet-1' }, { network: NETWORK });
  assert.equal(m.code, 'NetworkUnsupported');
  assert.match(m.reason, /intentionally not configured/);
  // 任意未知网络
  const junk = validateRequest('zchain_switchNetwork', { chainId: '0x1' }, { network: NETWORK });
  assert.equal(junk.code, 'NetworkUnsupported');
  // 缺参
  const missing = validateRequest('zchain_switchNetwork', {}, { network: NETWORK });
  assert.equal(missing.code, 'MissingParam');
  // 换网恒需显式确认（权限最小化纵深）
  assert.equal(requiresExplicitConfirm({ method: 'zchain_switchNetwork', params: { chainId: 'zchain-testnet-1' }, origin: ORIGIN }, { grants: GRANTS }), true);
});

test('30 REAL 签名面 0.2 仍关闭（0.2 只交付隔离展示，不暗示可提现）→ AssetClassDisabledIn01', () => {
  const r = validateRequest('zchain_signOperation', { operation: validTransfer({ assetClass: 'REAL' }), previewHash: 'f'.repeat(64) }, { network: NETWORK });
  assert.equal(r.code, 'AssetClassDisabledIn01');
  assert.match(r.reason, /display-only/);
});

test('31 脱敏透传：asset_class 仅在显式提供（REAL/PLAY）时透传，其余一律不推断', () => {
  const out = sanitizeNotesForPage([
    { commitment: 'ab'.repeat(32), amount: '5', table_id: null, proof: 'soft', spendable: true, asset_class: 'REAL', spend_secret: 'ff'.repeat(32) },
    { commitment: 'cd'.repeat(32), amount: '6', table_id: null, proof: 'soft', spendable: true, asset_class: 'PLAY' },
    { commitment: 'ee'.repeat(32), amount: '7', table_id: null, proof: 'soft', spendable: true, asset_class: 'POINTS' },
  ]);
  assert.equal(out[0].assetClass, 'REAL');
  assert.equal(out[1].assetClass, 'PLAY');
  assert.equal(out[2].assetClass, undefined); // 未知类不透传
  assert.ok(!JSON.stringify(out).includes('spend_secret'));
});
