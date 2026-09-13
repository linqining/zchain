// =============================================================================
// extension/tests/portal.test.js — proof portal 客户端逻辑测试（Extension 0.2）
//
// 覆盖：binding 解析（0x/大小写/坏形状）/ URL 组装 / fetchSettlement 与
// fetchProof 的全错误路径（未配置 → GatewayNotConfigured、网络失败 →
// GatewayUnreachable、404 → Settlement/ProofNotFound、429/5xx →
// GatewayHttpError、非 JSON 体）/ X-Zchain-Engine 头与响应体 engine 的优先级 /
// verifyLocally（同步/异步 verifyFn、错误传播、耗时测量）/ verdictRows 映射。
// 注入式 fetch / 零网络真实 IO。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyFetchError,
  fetchProof,
  fetchSettlement,
  parseBinding,
  proofUrl,
  settlementUrl,
  verdictRows,
  verifyLocally,
} from '../common/portal.js';

const GATEWAY = 'http://127.0.0.1:18900';
const BINDING = 'ab'.repeat(32);

function jsonResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
    headers: { get: (name) => headers[name.toLowerCase()] ?? null },
  };
}

const DETAIL = {
  hand_binding: BINDING,
  table_id: 1001,
  pot: 3020,
  payout_root: 'ef'.repeat(32),
  level: 'soft_accepted',
  rake: { total: 151 },
  plan: { gross_pot: 3020, rake: 151, total_awards: 2869, pots: [] },
  inputs: [{ amount: 3020 }],
  payouts: [{ owner: 'cd'.repeat(33), amount: 2869, asset_class: 'PLAY', table_id: 1001, pot_index: 0, runout_index: 0 }],
};

test('01 parseBinding：0x 前缀与大小写归一；坏形状 → BadBinding', () => {
  assert.deepEqual(parseBinding('0x' + BINDING.toUpperCase()), { ok: true, binding: BINDING });
  assert.equal(parseBinding('0x' + 'zz'.repeat(32)).code, 'BadBinding');
  assert.equal(parseBinding('ab'.repeat(31)).code, 'BadBinding');
  assert.equal(parseBinding('').code, 'BadBinding');
  assert.equal(parseBinding(123).code, 'BadBinding');
  assert.equal(parseBinding(null).code, 'BadBinding');
});

test('02 URL 组装：settlement/proof 端点形状（与 explorer gateway 白名单一致）', () => {
  assert.equal(settlementUrl(GATEWAY, BINDING), `${GATEWAY}/api/v1/settlement/${BINDING}`);
  assert.equal(proofUrl(GATEWAY, BINDING), `${GATEWAY}/api/v1/proof/${BINDING}`);
});

test('03 fetchSettlement 正例：返回明细；网关未配置 → GatewayNotConfigured', async () => {
  let calledUrl = '';
  const res = await fetchSettlement(GATEWAY, BINDING, async (url) => {
    calledUrl = url;
    return jsonResponse(200, DETAIL);
  });
  assert.equal(res.ok, true);
  assert.equal(calledUrl, `${GATEWAY}/api/v1/settlement/${BINDING}`);
  assert.equal(res.detail.payout_root, 'ef'.repeat(32));
  assert.equal(res.detail.level, 'soft_accepted');

  const none = await fetchSettlement(null, BINDING, async () => { throw new Error('should not fetch'); });
  assert.equal(none.ok, false);
  assert.equal(none.code, 'GatewayNotConfigured');
});

test('04 fetchSettlement 错误路径：网络失败/404/429/非 JSON/形状不符', async () => {
  const unreachable = await fetchSettlement(GATEWAY, BINDING, async () => { throw new TypeError('Failed to fetch'); });
  assert.equal(unreachable.ok, false);
  assert.equal(unreachable.code, 'GatewayUnreachable');
  assert.match(unreachable.reason, /网关不可达|--public|主机权限/);

  const notFound = await fetchSettlement(GATEWAY, BINDING, async () => jsonResponse(404, { error: 'settlement not found' }));
  assert.equal(notFound.code, 'SettlementNotFound');

  const rateLimited = await fetchSettlement(GATEWAY, BINDING, async () => jsonResponse(429, { error: 'rate limited' }));
  assert.equal(rateLimited.code, 'GatewayHttpError');

  const badJson = await fetchSettlement(GATEWAY, BINDING, async () => ({ ok: true, status: 200, json: async () => { throw new Error('bad json'); }, headers: { get: () => null } }));
  assert.equal(badJson.code, 'GatewayHttpError');

  const wrongShape = await fetchSettlement(GATEWAY, BINDING, async () => jsonResponse(200, { hello: 1 }));
  assert.equal(wrongShape.code, 'GatewayHttpError');
});

test('05 fetchProof 正例：engine 响应头优先，body 兜底；404 → ProofNotFound', async () => {
  const fromHeader = await fetchProof(GATEWAY, BINDING, async () =>
    jsonResponse(200, { binding_hex: BINDING, engine: 'body-engine', payload_b64: 'AAAA', payload_len: 3 }, { 'x-zchain-engine': 'header-engine' }));
  assert.equal(fromHeader.ok, true);
  assert.equal(fromHeader.proof.engine, 'header-engine');
  assert.equal(fromHeader.proof.engineSource, 'header');

  const fromBody = await fetchProof(GATEWAY, BINDING, async () =>
    jsonResponse(200, { binding_hex: BINDING, engine: 'body-engine', payload_b64: 'AAAA', payload_len: 3 }));
  assert.equal(fromBody.proof.engine, 'body-engine');
  assert.equal(fromBody.proof.engineSource, 'body');

  const notFound = await fetchProof(GATEWAY, BINDING, async () => jsonResponse(404, { error: 'proof not found' }));
  assert.equal(notFound.ok, false);
  assert.equal(notFound.code, 'ProofNotFound');

  const noPayload = await fetchProof(GATEWAY, BINDING, async () => jsonResponse(200, { binding_hex: BINDING }));
  assert.equal(noPayload.code, 'GatewayHttpError');

  const unconfigured = await fetchProof(null, BINDING, async () => { throw new Error('nope'); });
  assert.equal(unconfigured.code, 'GatewayNotConfigured');
});

test('06 verifyLocally：同步/异步 verifyFn 均支持；错误传播带稳定码；耗时被测量', async () => {
  const verdict = { verdict: 'verified', checks: [] };
  const syncRes = await verifyLocally(DETAIL, () => verdict);
  assert.equal(syncRes.ok, true);
  assert.equal(syncRes.verdict.verdict, 'verified');
  assert.ok(Number.isInteger(syncRes.elapsedMs));

  const asyncRes = await verifyLocally(DETAIL, async () => verdict);
  assert.equal(asyncRes.ok, true);

  const err = new Error('core rejected');
  err.code = 'VerifierRejected';
  err.detail = 'payout root mismatch';
  const failRes = await verifyLocally(DETAIL, () => { throw err; });
  assert.equal(failRes.ok, false);
  assert.equal(failRes.code, 'VerifierRejected');
  assert.match(failRes.reason, /payout root mismatch/);

  const noVerdict = await verifyLocally(DETAIL, () => null);
  assert.equal(noVerdict.code, 'VerifierError');
});

test('07 classifyFetchError：网络失败/404 族/HTTP 状态的稳定码', () => {
  assert.equal(classifyFetchError(new Error('x'), null, 'settlement').code, 'GatewayUnreachable');
  assert.equal(classifyFetchError(null, 404, 'settlement').code, 'SettlementNotFound');
  assert.equal(classifyFetchError(null, 404, 'proof').code, 'ProofNotFound');
  assert.equal(classifyFetchError(null, 400, 'settlement').code, 'BadBinding');
  assert.equal(classifyFetchError(null, 500, 'proof').code, 'GatewayHttpError');
});

test('08 verdictRows：检查项映射为中文标签；ok 布尔化', () => {
  const rows = verdictRows({
    checks: [
      { check: 'payout_root_recomputed', ok: true, detail: 'computed==declared' },
      { check: 'payouts_plus_rake_equals_pot', ok: false, detail: 'x != y' },
      { check: 'future_unknown_check', ok: true, detail: '' },
    ],
  });
  assert.equal(rows.length, 3);
  assert.match(rows[0].label, /payout_root 本地复算/);
  assert.match(rows[1].label, /守恒/);
  assert.equal(rows[1].ok, false);
  assert.equal(rows[2].label, 'future_unknown_check'); // 未知项原样透传
});
