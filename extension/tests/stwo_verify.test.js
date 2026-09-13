// =============================================================================
// extension/tests/stwo_verify.test.js — portal STARK 验证阶段单测（0.4 / path A）
//
// 覆盖：verifyStarkProof 的全结果分类（rc=0 verified / rc=-1 StarkArchiveInvalid /
// rc=-2 StarkVerifyRejected / rc=-3 与异常与无 rc → StarkVerifierError / 空
// payload / 坏 base64）、耗时如实测量、stats 透传；fetchProof 透传 payloadB64；
// 网关超时 → GatewayTimeout（与 GatewayUnreachable 分开）。
// 注入式 starkVerifyFn / 零真实 wasm 依赖（wasm 集成由 tests/e2e/run_04.mjs 与
// 本文件尾部的 wasm 冒烟用例覆盖，产物缺失时如实 skip）。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { fetchProof, verifyStarkProof } from '../common/portal.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GATEWAY = 'http://127.0.0.1:18900';
const BINDING = 'ab'.repeat(32);

function jsonResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    headers: { get: (name) => headers[name.toLowerCase()] ?? null },
  };
}

const STATS = {
  verified: true, error: null, archive_len: 1185984, table_id: 9101,
  log_size: 8, num_columns: 5392, transition_count: 5,
  batch_digest: '13'.repeat(32),
  internal_elapsed_ms: null,
  verifier: 'stwo-wasm-verify/0.1.0 (stwo 2.3.0 vendored+wasm-poseidon; poker_texas_air canonical AIR)',
};

test('01 verifyStarkProof：rc=0 → verified + stats + 耗时', async () => {
  const res = await verifyStarkProof('AAAA', () => ({ rc: 0, stats: STATS, error: '' }));
  assert.equal(res.ok, true);
  assert.equal(res.stark.verdict, 'verified');
  assert.equal(res.stark.stats.table_id, 9101);
  assert.match(res.stark.stats.verifier, /stwo-wasm-verify/);
  assert.ok(Number.isInteger(res.stark.elapsedMs));
});

test('02 verifyStarkProof：rc=-1 归档非法 / rc=-2 验证拒绝（带 stats）/ rc=-3 验证器错误', async () => {
  const bad = await verifyStarkProof('AAAA', () => ({ rc: -1, stats: null, error: 'archive borsh decode: x' }));
  assert.equal(bad.ok, false);
  assert.equal(bad.code, 'StarkArchiveInvalid');
  assert.match(bad.reason, /borsh/);

  const rejected = await verifyStarkProof('AAAA', () => ({ rc: -2, stats: { ...STATS, verified: false }, error: 'fri failed' }));
  assert.equal(rejected.ok, false);
  assert.equal(rejected.code, 'StarkVerifyRejected');
  assert.match(rejected.reason, /fri failed/);
  assert.equal(rejected.stats.table_id, 9101);

  const internal = await verifyStarkProof('AAAA', () => ({ rc: -3, stats: null, error: 'boom' }));
  assert.equal(internal.code, 'StarkVerifierError');
});

test('03 verifyStarkProof：异常/无 rc/空 payload/坏 base64 → fail-closed 分类', async () => {
  const thrown = await verifyStarkProof('AAAA', async () => { throw new Error('wasm not loaded'); });
  assert.equal(thrown.code, 'StarkVerifierError');
  assert.match(thrown.reason, /wasm not loaded/);
  assert.ok(Number.isInteger(thrown.elapsedMs));

  const noRc = await verifyStarkProof('AAAA', () => ({ hello: 1 }));
  assert.equal(noRc.code, 'StarkVerifierError');

  const empty = await verifyStarkProof('', () => ({ rc: 0, stats: STATS, error: '' }));
  assert.equal(empty.code, 'StarkArchiveInvalid');

  const nonB64 = await verifyStarkProof('!!!not-base64!!!', () => ({ rc: 0, stats: STATS, error: '' }));
  assert.equal(nonB64.code, 'StarkArchiveInvalid');
});

test('04 verifyStarkProof：字节数守恒（base64 解码结果原样交给 starkVerifyFn）', async () => {
  // "AAAA" = bytes [0,0,0]
  let seen = null;
  await verifyStarkProof('AAAA', (bytes) => { seen = bytes; return { rc: 0, stats: STATS, error: '' }; });
  assert.ok(seen instanceof Uint8Array);
  assert.equal(seen.length, 3);
  assert.deepEqual([...seen], [0, 0, 0]);
});

test('05 fetchProof：payloadB64 透传（STARK 阶段输入）', async () => {
  const res = await fetchProof(GATEWAY, BINDING, async () =>
    jsonResponse(200, { binding_hex: BINDING, engine: 'poker_texas_air-canonical', payload_b64: 'QUJD', payload_len: 3 }));
  assert.equal(res.ok, true);
  assert.equal(res.proof.payloadB64, 'QUJD');
  assert.equal(res.proof.engineSource, 'body');
});

test('06 fetchProof：网关超时 → GatewayTimeout（独立于 GatewayUnreachable）', async () => {
  const abortErr = new Error('The operation was aborted');
  abortErr.name = 'AbortError';
  const res = await fetchProof(GATEWAY, BINDING, async () => { throw abortErr; });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'GatewayTimeout');
  assert.match(res.reason, /网关超时/);

  const netFail = await fetchProof(GATEWAY, BINDING, async () => { throw new TypeError('Failed to fetch'); });
  assert.equal(netFail.code, 'GatewayUnreachable');
});

// ===== wasm 集成冒烟（真实产物；缺失时如实 skip，不算 PASS 造假）=====
const VENDOR_WASM = path.join(HERE, '..', 'vendor', 'stwo-verify', 'stwo_verify_wasm.wasm');
const FIXTURE = path.join(HERE, 'fixtures', 'stwo_verify', 'canonical_table9101.bin');

test('07 wasm 冒烟：真实 canonical 归档 verified + 篡改拒绝（产物缺失时 SKIP）', { skip: !existsSync(VENDOR_WASM) || !existsSync(FIXTURE) }, async () => {
  const { initStwoVerifyFromBytes } = await import('../vendor/stwo-verify/stwo_verify_loader.mjs');
  const v = await initStwoVerifyFromBytes(readFileSync(VENDOR_WASM));
  const bytes = readFileSync(FIXTURE);

  const good = v.verifyCanonicalProof(bytes);
  assert.equal(good.rc, 0, `genuine proof must verify, got rc=${good.rc} ${good.error}`);
  assert.equal(good.stats.verified, true);
  assert.equal(good.stats.table_id, 9101);
  assert.match(good.stats.verifier, /stwo 2\.3\.0 vendored\+wasm-poseidon/);

  const tampered = Uint8Array.from(bytes);
  tampered[Math.floor(tampered.length / 2)] ^= 0x01;
  const bad = v.verifyCanonicalProof(tampered);
  assert.notEqual(bad.rc, 0, 'tampered proof must be rejected');
});
