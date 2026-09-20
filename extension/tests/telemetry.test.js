// extension/tests/telemetry.test.js — PRD §6.4 埋点：禁采结构性排除 + 本地聚合
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  TELEMETRY_SCHEMA,
  FORBIDDEN_KEYS,
  MAX_TELEMETRY_EVENTS,
  INTERACTION_BUDGET_MS,
  hashRef,
  isKnownEvent,
  sanitizeEvent,
  createTelemetry,
  summarize,
  computeMetrics,
  portalStepProps,
} from '../common/telemetry.js';

test('01 事件 id 是封闭枚举：未登记事件 → UnknownEvent，不静默记录', () => {
  assert.equal(isKnownEvent('popup_open'), true);
  assert.equal(sanitizeEvent('whatever_i_want', { a: 1 }).ok, false);
  assert.equal(sanitizeEvent('whatever_i_want', { a: 1 }).code, 'UnknownEvent');
  assert.equal(sanitizeEvent(null, {}).code, 'UnknownEvent');
});

test('02 schema 覆盖 PRD §6.4 全部事件（30 个 id，backup 两条分行）', () => {
  const ids = Object.keys(TELEMETRY_SCHEMA);
  assert.ok(ids.length >= 29, `期望 ≥29 事件，实得 ${ids.length}`);
  for (const id of [
    'popup_open', 'screen_view', 'chain_switch', 'layer_unlock', 'amount_gate_hit',
    'note_select_result', 'note_count_over_limit', 'withdraw_preview_view',
    'withdraw_submit_attempt_blocked', 'sign_request_resolved', 'session_key_exhausted',
    'session_key_revoke', 'proof_rail_view', 'proof_ladder_mismatch', 'portal_verify_start',
    'portal_verify_step', 'portal_verify_result', 'receipt_state_change',
    'receipt_past_deadline_view', 'receipt_capacity_hit', 'copy_action',
    'qr_view_attempt', 'fiat_unavailable_view', 'backup_export', 'backup_restore_result',
    'danger_action_confirm', 'rekey_partial_failure', 'error_shown', 'ground_switch',
    'settings_change',
  ]) {
    assert.ok(ids.includes(id), `缺事件 ${id}`);
  }
});

test('03 禁采键名结构性排除：私钥/助记词/nullifier/口令 一律丢弃并如实报告', () => {
  const r = sanitizeEvent('sign_request_resolved', {
    decision: 'approve',
    via: 'session_key',
    originHash: 'poker.zchain.devnet',
    privateKey: 'deadbeef'.repeat(8),
    nullifier: 'abc123',
    password: 'correct horse',
    mnemonic: 'abandon abandon abandon',
    spendSecret: 'x'.repeat(64),
  });
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.props).sort(), ['decision', 'originHash', 'via']);
  for (const k of ['privateKey', 'nullifier', 'password', 'mnemonic', 'spendSecret']) {
    assert.ok(r.dropped.includes(k), `应丢弃 ${k}`);
  }
  // 键名以 Hash 结尾 → 即使调用方误传原值，也在出口处强制降为不可逆引用
  assert.match(r.props.originHash, /^r[0-9a-f]{8}$/);
  assert.ok(!JSON.stringify(r.props).includes('poker.zchain'), 'origin 明文不得出现在事件里');
  assert.equal(FORBIDDEN_KEYS.length >= 10, true);
});

test('04 未登记属性丢弃：不做“顺手多记一个字段”', () => {
  const r = sanitizeEvent('ground_switch', { to: 'night', unexpectedField: 'x' });
  assert.deepEqual(r.props, { to: 'night' });
  assert.deepEqual(r.dropped, ['unexpectedField']);
});

test('05 长 hex 原值降级为哈希引用；origin 不落明文', () => {
  const a = hashRef('0x59195049a3b7c1d2e3f4a5b6c7d8e9f0a1b2c3d4');
  const b = hashRef('0x59195049a3b7c1d2e3f4a5b6c7d8e9f0a1b2c3d4');
  const c = hashRef('0x0000000000000000000000000000000000000001');
  assert.match(a, /^r[0-9a-f]{8}$/);
  assert.equal(a, b, '同一原值必须对上一条（跨事件可关联）');
  assert.notEqual(a, c);
  const r = sanitizeEvent('copy_action', { fieldKind: 'address', layer: 'evm', value: '0x' + 'ab'.repeat(20) });
  assert.ok(!JSON.stringify(r.props).includes('ababab'), '不得出现地址原值片段');
});

test('06 口令痕迹形态直接丢弃（即使键名合法）', () => {
  const r = sanitizeEvent('settings_change', { key: 'password', from: 'felt-poker-verifiable-9x2a', to: 'x' });
  assert.equal(r.props.from, undefined);
  assert.ok(r.dropped.includes('from'));
  assert.equal(r.props.key, 'password', '键名本身合法（记录“改过哪一项”）');
});

test('07 §6.4 明列的前缀字段可保留：bindingPrefix 前 8 位、rawValue 阶梯词汇', () => {
  const r = sanitizeEvent('portal_verify_start', { bindingPrefix: '0xc41d8f22e9a0', from: 'proofs' });
  assert.equal(r.props.bindingPrefix, '0xc41d8f22e9a0'.slice(0, 64));
  const m = sanitizeEvent('proof_ladder_mismatch', { rawValue: 'local' });
  assert.equal(m.props.rawValue, 'local');
});

test('08 类型收敛：int 截断、num 三位小数、bool 严格、列表≤8 项', () => {
  const r = sanitizeEvent('note_select_result', {
    noteCount: '3.9',
    hasChange: 1,
    weakest: 'soft',
    required: 'proven',
    canSubmit: 'true',
    blockedReasons: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'],
  });
  assert.equal(r.props.noteCount, 3);
  assert.equal(r.props.hasChange, true);
  assert.equal(r.props.canSubmit, true);
  assert.equal(r.props.blockedReasons.length, 8);
  const n = sanitizeEvent('portal_verify_step', { step: 2, ok: true, ms: 841.6667 });
  assert.equal(n.props.ms, 842);
});

test('09 默认关闭：未同意不记录，缓冲区不增长', () => {
  const t = createTelemetry({ now: () => 1000 });
  assert.equal(t.isEnabled(), false);
  assert.equal(t.record('popup_open', { unlockedLayers: 2 }).code, 'TelemetryDisabled');
  assert.equal(t.list().length, 0);
});

test('10 关闭即清空：不留“先记着以后再看”的余地', () => {
  const t = createTelemetry({ enabled: true, now: () => 2000 });
  t.record('screen_view', { screenId: 'home' });
  t.record('screen_view', { screenId: 'proofs' });
  assert.equal(t.list().length, 2);
  assert.equal(t.setEnabled(false), false);
  assert.equal(t.list().length, 0);
  assert.equal(t.setEnabled(true), true);
  assert.equal(t.list().length, 0);
});

test('11 环形缓冲：超容量丢最旧（与 MAX_RECEIPTS 同构）', () => {
  const t = createTelemetry({ enabled: true, capacity: 3, now: () => 5 });
  for (const id of ['ground_switch', 'chain_switch', 'copy_action', 'error_shown']) {
    t.record(id, id === 'ground_switch' ? { to: 'night' } : id === 'chain_switch' ? { fromChain: 'zc', toChain: 'evm' } : id === 'copy_action' ? { fieldKind: 'address', layer: 'zc' } : { code: 'BadPassword', screenId: 'lock' });
  }
  const ids = t.list().map((e) => e.id);
  assert.deepEqual(ids, ['chain_switch', 'copy_action', 'error_shown']);
  assert.equal(t.stats().buffered, 3);
  assert.equal(MAX_TELEMETRY_EVENTS, 500);
});

test('12 summarize：次数 / 最近时间 / 数值分布 / 布尔计数', () => {
  const s = summarize([
    { id: 'portal_verify_step', at: 10, props: { step: 1, ok: true, ms: 120 } },
    { id: 'portal_verify_step', at: 20, props: { step: 3, ok: true, ms: 1720 } },
    { id: 'portal_verify_step', at: 15, props: { step: 4, ok: false, ms: 30 } },
  ]);
  assert.equal(s.portal_verify_step.count, 3);
  assert.equal(s.portal_verify_step.lastAt, 20);
  assert.equal(s.portal_verify_step.numeric.ms.sum, 1870);
  assert.equal(s.portal_verify_step.numeric.ms.min, 30);
  assert.equal(s.portal_verify_step.numeric.ms.max, 1720);
  assert.equal(s.portal_verify_step.numeric.ms.avg, 623.333);
  assert.deepEqual(s.portal_verify_step.bool.ok, { true: 2, false: 1 });
});

test('13 computeMetrics：只算分子分母，不编造目标值', () => {
  const m = computeMetrics([
    { id: 'popup_open', props: { unlockedLayers: 3 } },
    { id: 'popup_open', props: { unlockedLayers: 3 } },
    { id: 'screen_view', props: { screenId: 'proofs', tab: 'proofs' } },
    { id: 'portal_verify_start', props: { bindingPrefix: '0xc41d8f' } },
    { id: 'portal_verify_start', props: { bindingPrefix: '0x99aabb' } },
    { id: 'portal_verify_result', props: { verdict: 'verified', totalMs: 1720, overBudget: true } },
    { id: 'portal_verify_result', props: { verdict: 'partial', totalMs: 900, overBudget: true } },
    { id: 'sign_request_resolved', props: { decision: 'approve', via: 'session_key' } },
    { id: 'sign_request_resolved', props: { decision: 'approve', via: 'password' } },
    { id: 'sign_request_resolved', props: { decision: 'reject', via: 'password' } },
    { id: 'proof_ladder_mismatch', props: { rawValue: 'local' } },
    { id: 'withdraw_submit_attempt_blocked', props: { reasons: ['通道未开放'] } },
    { id: 'fiat_unavailable_view', props: {} },
  ]);
  assert.equal(m.proofsVisitRatio, 0.5);
  assert.equal(m.portalCompletion, 0.5);
  assert.equal(m.sessionKeySignRatio, 0.5);
  assert.equal(m.withdrawSubmitAttempts, 1, '>0 即说明禁用态表达失败（§1.3 硬目标应为 0）');
  assert.equal(m.ladderMismatch, 1);
  assert.equal(m.overBudgetResults, 2);
  assert.equal(m.fiatUnavailableViews, 1);
  assert.equal(INTERACTION_BUDGET_MS, 500);
});

test('14 空数据不得变 0 除：比率类指标为 null（不造数）', () => {
  const m = computeMetrics([]);
  assert.equal(m.proofsVisitRatio, null);
  assert.equal(m.portalCompletion, null);
  assert.equal(m.sessionKeySignRatio, null);
  assert.equal(m.withdrawSubmitAttempts, 0);
});

test('15 portalStepProps：payloadBytes → KB 一位小数，缺项不写键', () => {
  const p = portalStepProps({ step: 2, ok: true, ms: 88, payloadBytes: 86221, engine: 'stwo', gatewayStatus: '200' });
  assert.equal(p.payloadKB, 84.2);
  assert.equal(p.engine, 'stwo');
  const q = portalStepProps({ step: 1, ok: false, ms: 5 });
  assert.equal('payloadKB' in q, false);
  assert.equal(q.ok, false);
});

test('16 值长度上限：不把整个 payload 塞进埋点', () => {
  const r = sanitizeEvent('error_shown', { code: 'E'.repeat(500), screenId: 'home' });
  assert.equal(r.props.code.length, 64);
});
