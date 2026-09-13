// =============================================================================
// extension/tests/receipts.test.js — 交易回执 inclusion 状态机测试（0.2）
//
// 对应 poker_l1::force_include 的协议语义（§5.3；deadline 10_000ms）。
// 覆盖：登记（digest 校验/去重/滚动上限）/ SeenReceipt 形状校验（不验签——
// 如实标注）/ 状态迁移（signed → seen → included 单向）/ deadline 判定
// （含 0 = 禁用与溢出安全）/ UI 展示判定（超期 ForceInclude 提示文案、
// evidence 诚实标注）。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_INCLUSION_DEADLINE_MS,
  MAX_RECEIPTS,
  applySeenReceipt,
  inclusionView,
  isPastInclusionDeadline,
  markIncluded,
  openReceipt,
  validateSeenReceiptShape,
} from '../common/receipts.js';

const DIGEST = 'ab'.repeat(32);
const NOW = 1_757_000_000_000;

function validReceipt(over = {}) {
  return {
    chain_id: 'zchain-devnet-1',
    tx_hash: 'cd'.repeat(32),
    seen_at_ms: NOW + 50,
    validator_pubkey: 'ef'.repeat(33),
    signature: [1, 2, 3],
    ...over,
  };
}

function seeded() {
  const r = openReceipt({}, { digest: DIGEST, kind: 'transfer', chainId: 'zchain-devnet-1', signedAtMs: NOW }, NOW);
  assert.equal(r.ok, true);
  return r.store;
}

test('01 常量与协议一致：deadline 10_000ms（poker_l1 DEFAULT_INCLUSION_DEADLINE_MS）', () => {
  assert.equal(DEFAULT_INCLUSION_DEADLINE_MS, 10_000);
});

test('02 登记：digest 64hex 强校验；重复登记拒绝', () => {
  assert.equal(openReceipt({}, { digest: 'zz', kind: 'transfer' }, NOW).code, 'InvalidArgument');
  assert.equal(openReceipt({}, { digest: 'ab'.repeat(31), kind: 'transfer' }, NOW).code, 'InvalidArgument');
  const store = seeded();
  assert.equal(openReceipt(store, { digest: DIGEST, kind: 'transfer' }, NOW).code, 'DuplicateReceipt');
  const e = store[DIGEST];
  assert.equal(e.status, 'signed');
  assert.equal(e.deadlineMs, DEFAULT_INCLUSION_DEADLINE_MS);
  assert.equal(e.evidence.included, 'local_manual_entry');
});

test('03 SeenReceipt 形状校验：五字段缺一即拒；签名仅形状检查（0.2 无验签入口）', () => {
  assert.equal(validateSeenReceiptShape(validReceipt()).ok, true);
  assert.equal(validateSeenReceiptShape(null).code, 'InvalidArgument');
  assert.equal(validateSeenReceiptShape(validReceipt({ chain_id: '' })).code, 'InvalidArgument');
  assert.equal(validateSeenReceiptShape(validReceipt({ tx_hash: 'cd'.repeat(31) })).code, 'InvalidArgument');
  assert.equal(validateSeenReceiptShape(validReceipt({ seen_at_ms: -1 })).code, 'InvalidArgument');
  assert.equal(validateSeenReceiptShape(validReceipt({ seen_at_ms: 1.5 })).code, 'InvalidArgument');
  assert.equal(validateSeenReceiptShape(validReceipt({ validator_pubkey: '' })).code, 'InvalidArgument');
  assert.equal(validateSeenReceiptShape(validReceipt({ signature: 'deadbeef' })).code, 'InvalidArgument');
});

test('04 applySeenReceipt：合法回执 → seen + evidence 如实标注 receipt_unverified_signature', () => {
  const store = seeded();
  const r = applySeenReceipt(store, DIGEST, validReceipt(), NOW + 10);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.entry.status, 'seen');
  assert.equal(r.entry.seenAtMs, NOW + 50);
  assert.equal(r.entry.evidence.seen, 'receipt_unverified_signature');
  // 非法形状拒绝且不迁移
  assert.equal(applySeenReceipt(store, DIGEST, { broken: true }, NOW + 10).ok, false);
  assert.equal(store[DIGEST].status, 'signed');
  // 未知 digest
  assert.equal(applySeenReceipt(store, 'ff'.repeat(32), validReceipt(), NOW + 10).code, 'UnknownReceipt');
});

test('05 状态机单向：included 后不可再 seen；included 后不可再 included', () => {
  const store = seeded();
  const inc = markIncluded(store, DIGEST, NOW + 20);
  assert.equal(inc.ok, true);
  assert.equal(inc.entry.status, 'included');
  assert.equal(inc.entry.includedAtMs, NOW + 20);
  const again = applySeenReceipt(inc.store, DIGEST, validReceipt(), NOW + 30);
  assert.equal(again.code, 'InvalidTransition');
  const third = markIncluded(inc.store, DIGEST, NOW + 30);
  assert.equal(third.code, 'InvalidTransition');
  assert.equal(markIncluded(store, 'ff'.repeat(32), NOW).code, 'UnknownReceipt');
});

test('06 isPastInclusionDeadline：边界（等于不算超）；deadline 0 = 禁用；非安全值拒绝', () => {
  // now == arrived + deadline → 未超（严格大于）
  assert.equal(isPastInclusionDeadline(1_000, 11_000, 10_000), false);
  assert.equal(isPastInclusionDeadline(1_000, 11_001, 10_000), true);
  // deadline 0（禁用强制包含路径）恒 false
  assert.equal(isPastInclusionDeadline(0, Number.MAX_SAFE_INTEGER, 0), false);
  // 非安全整数 arrived → false（fail-neutral，不在展示面制造假警报）
  assert.equal(isPastInclusionDeadline(1.5, 20_000, 10_000), false);
  // 溢出安全
  assert.equal(isPastInclusionDeadline(Number.MAX_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER, 10_000), false);
});

test('07 inclusionView：超期未 included → ForceInclude 提示（仅展示，不实现提交路径）', () => {
  const store = seeded();
  const view = inclusionView(store[DIGEST], NOW + 10_001);
  assert.equal(view.status, 'signed');
  assert.equal(view.pastDeadline, true);
  assert.match(view.hint, /ForceInclude/);
  assert.match(view.hint, /仅展示协议状态，不实现提交路径/);
  // deadline 内：等待见证提示
  const early = inclusionView(store[DIGEST], NOW + 5_000);
  assert.equal(early.pastDeadline, false);
  assert.match(early.hint, /等待链上见证实回执/);
  // included：无超期提示
  const inc = markIncluded(store, DIGEST, NOW + 20_000);
  const v3 = inclusionView(inc.entry, NOW + 20_001);
  assert.equal(v3.status, 'included');
  assert.equal(v3.pastDeadline, false);
  assert.equal(v3.hint, null);
  // seen 态的超期锚点用 seenAtMs
  const seen = applySeenReceipt(store, DIGEST, validReceipt({ seen_at_ms: NOW + 60_000 }), NOW + 60_000);
  const v4 = inclusionView(seen.entry, NOW + 60_000 + 10_001);
  assert.equal(seen.entry.status, 'seen');
  assert.equal(v4.pastDeadline, true);
});

test('08 回执滚动上限：MAX_RECEIPTS 之外最旧回执被丢弃', () => {
  let store = {};
  for (let i = 0; i < MAX_RECEIPTS + 3; i++) {
    const r = openReceipt(store, { digest: (i % 256).toString(16).padStart(2, '0').repeat(32), kind: 'transfer', signedAtMs: NOW + i }, NOW + i);
    store = r.store;
  }
  assert.equal(Object.keys(store).length, MAX_RECEIPTS);
});
