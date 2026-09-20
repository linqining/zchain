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
  RECEIPT_KINDS,
  openReceipt,
  pendingSpendMap,
  pendingSpendSum,
  receiptAmount,
  receiptEvidenceText,
  receiptKindLabel,
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

test('pendingSpendMap: signed/seen 的 transfer 收据输入占用，included 释放', () => {
  const c1 = 'aa'.repeat(32);
  const c2 = 'bb'.repeat(32);
  let store = openReceipt({}, {
    digest: DIGEST, kind: 'transfer', chainId: 'zchain-devnet-1', signedAtMs: NOW,
    inputs: [{ commitment: c1, amount: 300 }, { commitment: c2, amount: 200 }],
  }, NOW).store;
  let m = pendingSpendMap(store);
  assert.equal(m.size, 2);
  // u64 安全契约（R-24）：占用金额是十进制**字符串**，不经 `Number()`。
  assert.equal(m.get(c1), '300');
  assert.equal(m.get(c2), '200');
  assert.equal(pendingSpendSum(m), '500');

  // seen 仍占用
  store = applySeenReceipt(store, DIGEST, validReceipt(), NOW + 50).store;
  assert.equal(pendingSpendMap(store).size, 2);

  // included 释放（真实链上 core 同步接管最终状态）
  store = markIncluded(store, DIGEST, NOW + 100).store;
  assert.equal(pendingSpendMap(store).size, 0);
});

test('pendingSpendMap: 非 transfer 收据 / 脏输入 / 空 store 安全', () => {
  const store = openReceipt({}, {
    digest: DIGEST, kind: 'buy_in', chainId: 'zchain-devnet-1', signedAtMs: NOW,
    inputs: [{ commitment: 'cc'.repeat(32), amount: 1 }],
  }, NOW).store;
  assert.equal(pendingSpendMap(store).size, 0);
  assert.equal(pendingSpendMap(null).size, 0);
  assert.equal(pendingSpendMap({}).size, 0);
  // 脏输入（无 commitment / amount 非数）不进表、不抛
  const dirty = openReceipt({}, {
    digest: 'cd'.repeat(32), kind: 'transfer', signedAtMs: NOW,
    inputs: [{ amount: 5 }, { commitment: 'dd'.repeat(32), amount: 'xyz' }, 'garbage'],
  }, NOW).store;
  const m = pendingSpendMap(dirty);
  assert.equal(m.size, 1);
  // 脏金额按 '0' 记账（仍软锁 commitment —— 锁是防双花，与金额无关）
  assert.equal(m.get('dd'.repeat(32)), '0');
});

test('openReceipt: inputs 归一只留 {commitment, amount}', () => {
  const store = openReceipt({}, {
    digest: DIGEST, kind: 'transfer', signedAtMs: NOW,
    inputs: [{ commitment: 'ee'.repeat(32), amount: '42', secret: 'x', nullifier: 'y' }, 7],
  }, NOW).store;
  assert.deepEqual(store[DIGEST].inputs, [{ commitment: 'ee'.repeat(32), amount: '42' }]);
  // 无 inputs 的旧调用形状：空数组（buy_in 等不受影响）
  const plain = openReceipt({}, { digest: 'ef'.repeat(32), kind: 'buy_in', signedAtMs: NOW }, NOW).store;
  assert.deepEqual(plain['ef'.repeat(32)].inputs, []);
});

test('u64 金额不丢精度：pendingSpendSum / receiptAmount 走 BigInt（R-24）', () => {
  const big = '18446744073709551615'; // U64_MAX：Number 会把它变成 ...600
  const store = openReceipt({}, {
    digest: 'be'.repeat(32), kind: 'transfer', signedAtMs: NOW,
    inputs: [{ commitment: 'aa'.repeat(32), amount: big }, { commitment: 'bb'.repeat(32), amount: '1' }],
  }, NOW).store;
  const r = store['be'.repeat(32)];
  assert.deepEqual(receiptAmount(r), { ok: true, total: '18446744073709551616' });
  assert.equal(pendingSpendSum(pendingSpendMap(store)), '18446744073709551616');
  assert.notEqual(String(Number(big) + 1), '18446744073709551616', '浮点求和会塌成 …52000：这正是禁用 Number() 求和的理由');
});

test('receiptAmount：无输入 / 脏金额一律 fail-closed，不返回半截合计或 0', () => {
  assert.equal(receiptAmount({ inputs: [] }).code, 'NoInputs');
  assert.equal(receiptAmount(null).code, 'NoInputs');
  const r = receiptAmount({ inputs: [{ amount: '100' }, { amount: '1.5' }] });
  assert.equal(r.code, 'AmountInvalid');
  assert.equal(r.bad, '1.5');
  assert.equal('total' in r, false);
});

test('tableId 只接受非负整数（R-25）：hex / 花色写法一律归 null，不猜值', () => {
  const hexFor = (n) => n.toString(16).padStart(2, '0').repeat(32);
  const mk = (tableId, n) => openReceipt({}, { digest: hexFor(n), kind: 'settle', signedAtMs: NOW, tableId }, NOW).store[hexFor(n)];
  assert.equal(mk(8, 1).tableId, 8);
  assert.equal(mk('128', 2).tableId, 128);
  assert.equal(mk(0, 3).tableId, 0, '0 是合法桌号，不得当成缺省');
  const rejected = ['#A3F2', '8♠', -1, 1.5, 'abc', null, undefined, '', '9007199254740993'];
  rejected.forEach((bad, i) => {
    assert.equal(mk(bad, 10 + i).tableId, null, `应拒绝 ${JSON.stringify(bad)}`);
  });
});

test('receiptKindLabel：已知 kind 给标签，未知原样透出、不造「开桌」（R-25）', () => {
  assert.deepEqual(receiptKindLabel('settle'), { text: '结算', known: true, raw: 'settle' });
  assert.deepEqual(receiptKindLabel('buy_in'), { text: '买入', known: true, raw: 'buy_in' });
  assert.equal(RECEIPT_KINDS.length, 4);
  const u = receiptKindLabel('opentable');
  assert.equal(u.known, false);
  assert.match(u.text, /未知操作 · opentable/);
  assert.equal(receiptKindLabel(null).known, false);
});

test('receiptEvidenceText：included 必须说明是本机手工登记（R-33 / AC-27）', () => {
  const t = receiptEvidenceText({ seen: 'not_provided', included: 'local_manual_entry' });
  assert.match(t, /本机手工登记，未经链上核对/);
  assert.match(t, /local_manual_entry/);
  assert.match(receiptEvidenceText({ seen: 'receipt_unverified_signature' }), /验签未通过/);
  assert.match(receiptEvidenceText('not_provided'), /未提供证据/);
  assert.match(receiptEvidenceText({}), /evidence 未提供/);
  // 未知证据词原样透出，不翻译成"看起来没问题"的句子
  assert.match(receiptEvidenceText({ included: 'gateway_signed_entry' }), /gateway_signed_entry/);
});

test('MAX_RECEIPTS 之外的丢弃数如实返回，供界面常驻说明（R-11）', () => {
  let store = {};
  let dropped = 0;
  for (let i = 0; i < 24; i += 1) {
    const r = openReceipt(store, {
      digest: i.toString(16).padStart(2, '0').repeat(32), kind: 'transfer', signedAtMs: NOW + i,
    }, NOW + i);
    store = r.store;
    dropped += r.dropped;
  }
  assert.equal(Object.keys(store).length, MAX_RECEIPTS);
  assert.equal(dropped, 4);
});
