// =============================================================================
// extension/tests/ui_ledger.test.js — 方向 B 账簿 UI 纯逻辑层测试
//
// 覆盖：屏幕注册表完整性（唯一 id / tab 归属 / 共享屏幕）/ 导航解析（含未知
// 屏幕 fail-closed、@acct 返回、链上下文沿用）/ 金额格式化（保留原始精度、
// 非数字原样回落、不造 0）/ 地址缩略 / 时间与倒计时文案 / 凭证阶梯聚合与
// 短板 / 阶梯节点笔触 / 回执与交易分桶 / 会话日限用量 / 错误码文案（未知码
// 不吞）/ 跨域禁轧差 / 底色切换。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  SCREENS, CHAINS, PRICE_SOURCE_CONNECTED, PROOF_LADDER, INCLUSION_LADDER,
  chainOf, screenById, isSharedScreen, resolveScreen, backTarget, tabOf,
  fmtAmount, fmtSigned, shortAddr, relTime, remainText, validityRemain,
  proofRank, proofLadder, ladderSteps, receiptBuckets, receiptChip,
  txStatusChip, historyBuckets, txDirection, sessionUsage, sessionStatusChip,
  errorText, sumWithinDomain, nextGround, screenTitle, CHAIN_LABEL,
} from '../common/ui_ledger.js';

// ---- 注册表 ----

test('01 屏幕注册表：id 唯一、设计稿 18 屏齐全、tab 归属合法', () => {
  const ids = SCREENS.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, 'id 不得重复');
  for (const want of ['welcome', 'success', 'import', 'lock', 'home', 'acct',
    'zc-send', 'zc-withdraw', 'zc-confirm', 'zc-sessions', 'zc-portal', 'zc-receipts',
    'send', 'contract', 'history', 'manage', 'proofs', 'settings']) {
    assert.ok(ids.includes(want), `缺少屏幕 ${want}`);
  }
  for (const s of SCREENS) {
    assert.ok([null, 'home', 'acct', 'proofs'].includes(s.tab), `${s.id} tab 归属非法`);
    assert.ok(typeof s.name === 'string' && s.name.length > 0);
    assert.ok(typeof s.grp === 'string' && s.grp.length > 0);
  }
});

test('02 结构性修正：账簿类屏幕是共享模板（链=筛选器），ZChain 专属面单独成屏', () => {
  assert.equal(screenById('acct').shared, true);
  for (const id of ['send', 'history', 'manage', 'contract']) {
    assert.equal(isSharedScreen(id), true, `${id} 应为链复用屏幕`);
  }
  for (const id of ['zc-send', 'zc-withdraw', 'zc-sessions', 'zc-receipts', 'zc-portal', 'zc-confirm']) {
    assert.equal(isSharedScreen(id), false, `${id} 应为 ZChain 专属`);
  }
  assert.equal(isSharedScreen('home'), false);
});

test('03 chainOf：三值封闭枚举，未知 → null（不猜链）', () => {
  assert.deepEqual(CHAINS, ['zc', 'evm', 'stk']);
  for (const c of CHAINS) assert.equal(chainOf(c), c);
  assert.equal(chainOf('solana'), null);
  assert.equal(chainOf(undefined), null);
  assert.equal(chainOf('ZC'), null);
  assert.equal(CHAIN_LABEL.zc, 'ZChain');
});

test('04 resolveScreen：冒号带链 / 对象形式 / 缺链沿用 lastChain / 未知 fail-closed', () => {
  assert.deepEqual(resolveScreen('acct:evm'), { id: 'acct', chain: 'evm' });
  assert.deepEqual(resolveScreen({ id: 'send', chain: 'stk' }), { id: 'send', chain: 'stk' });
  assert.deepEqual(resolveScreen('acct', { lastChain: 'stk' }), { id: 'acct', chain: 'stk' });
  assert.deepEqual(resolveScreen('send'), { id: 'send', chain: 'zc' });
  assert.deepEqual(resolveScreen('home'), { id: 'home', chain: null });
  const bad = resolveScreen('nope');
  assert.equal(bad.error, 'UnknownScreen');
  assert.equal(bad.target, 'nope');
  assert.equal(resolveScreen('acct:solana').chain, 'zc', '非法链回落默认而不是保留非法值');
});

test('05 backTarget：子页回账簿并沿用当前链；顶级屏幕无返回', () => {
  assert.deepEqual(backTarget('zc-send', { chain: 'zc' }), { id: 'acct', chain: 'zc' });
  assert.deepEqual(backTarget('manage', { chain: 'evm' }), { id: 'acct', chain: 'evm' });
  assert.deepEqual(backTarget('settings'), { id: 'home', chain: null });
  assert.equal(backTarget('home'), null);
  assert.equal(backTarget('unknown'), null);
  assert.equal(tabOf('proofs'), 'proofs');
  assert.equal(tabOf('zc-send'), 'acct');
  assert.equal(tabOf('welcome'), null);
});

// ---- 格式化 ----

test('06 fmtAmount：千分位分组 + 保留原始小数位（不补零、不四舍五入）', () => {
  assert.equal(fmtAmount('12400'), '12,400');
  assert.equal(fmtAmount('1234567.8910'), '1,234,567.8910');
  assert.equal(fmtAmount('0'), '0');
  assert.equal(fmtAmount('007'), '7');
  assert.equal(fmtAmount(2.4183), '2.4183');
  assert.equal(fmtAmount(1000n), '1,000');
  assert.equal(fmtAmount('-500'), '-500');
  assert.equal(fmtAmount('1000000000000000000'), '1,000,000,000,000,000,000');
});

test('07 fmtAmount 不推断：非数字串原样透出（绝不静默变 0/NaN）', () => {
  assert.equal(fmtAmount('—'), '—');
  assert.equal(fmtAmount('12abc'), '12abc');
  assert.equal(fmtAmount(''), '');
  assert.equal(fmtAmount(null), '');
  assert.equal(fmtAmount(undefined), '');
  assert.equal(fmtSigned('500', { positive: true }), '+500');
  assert.equal(fmtSigned('500', { negative: true }), '-500');
  assert.equal(fmtSigned('-500', { negative: true }), '-500');
});

test('08 shortAddr：长地址首尾保留，短值/空值不造省略号', () => {
  assert.equal(shortAddr('0x59195049a3b2c1d4e5f629f97527'), '0x59195049…f97527');
  assert.equal(shortAddr('0x1234'), '0x1234');
  assert.equal(shortAddr(null), '—');
  assert.equal(shortAddr(''), '—');
  assert.equal(shortAddr('abcdef', 2, 2), 'ab…ef');
});

test('09 时间文案：相对时间 / 倒计时 / 有效期（过期与边界都有确定文案）', () => {
  const now = 1_700_000_000_000;
  assert.equal(relTime(now - 5_000, now), '刚刚');
  assert.equal(relTime(now - 45_000, now), '45 秒前');
  assert.equal(relTime(now - 120_000, now), '2 分钟前');
  assert.equal(relTime(now - 3_600_000 * 5, now), '5 小时前');
  assert.equal(relTime(now - 3_600_000 * 30, now), '1 天前');
  assert.equal(relTime(null, now), '—');
  assert.equal(remainText(30_000), '30s');
  assert.equal(remainText(92_000), '1:32');
  assert.equal(remainText(112_000), '1:52');
  assert.equal(remainText(-1), '已过期');
  assert.equal(remainText(3_700_000), '1h 1m');
  const base = 1_700_000;
  assert.equal(validityRemain(base + 6 * 86400 + 12 * 3600, base), '剩 6 天 12 小时');
  assert.equal(validityRemain(base + 180, base), '剩 3 分钟');
  assert.equal(validityRemain(base - 1, base), '已过期');
});

// ---- 凭证阶梯 / 回执 ----

test('10 proofLadder：计数 + 短板取最低层级（混合层级）', () => {
  const l = proofLadder([
    { proof: 'finalized' }, { proof: 'proven' }, { proof: 'soft' }, { proof: 'pending' },
  ]);
  assert.equal(l.weakest, 'pending');
  assert.deepEqual(l.counts, { pending: 1, soft: 1, proven: 1, finalized: 1 });
  assert.deepEqual(l.ladder.map((x) => `${x.proof}:${x.count}`), ['pending:1', 'soft:1', 'proven:1', 'finalized:1']);
  assert.equal(l.total, 4);
});

test('11 proofLadder：未知 proof 记为 pending（不丢弃）、spendable=false 不计可用、空库 weakest=null', () => {
  const l = proofLadder([{ proof: 'wat' }, { proof: 'proven', spendable: false }]);
  assert.equal(l.counts.pending, 1);
  assert.equal(l.spendable, 1);
  assert.equal(proofLadder([]).weakest, null);
  assert.equal(proofRank('finalized'), 3);
  assert.equal(proofRank('bogus'), 0);
  assert.deepEqual(PROOF_LADDER, ['pending', 'soft', 'proven', 'finalized']);
  assert.deepEqual(INCLUSION_LADDER, ['signed', 'seen', 'included']);
});

test('12 ladderSteps：done/cur/bad/空 四态笔触；blocked 卡红、wait 停琥珀、ok 只画 done', () => {
  assert.deepEqual(ladderSteps({ current: 'finalized', outcome: 'ok' }).map((s) => s.state),
    ['done', 'done', 'done', 'done']);
  assert.deepEqual(ladderSteps({ current: 'soft', outcome: 'blocked' }).map((s) => s.state),
    ['done', 'done', 'bad', '']);
  assert.deepEqual(ladderSteps({ current: 'soft', outcome: 'wait' }).map((s) => s.state),
    ['done', 'done', 'cur', '']);
  assert.deepEqual(ladderSteps({ current: 'proven', outcome: 'ok' }).map((s) => s.state),
    ['done', 'done', 'done', '']);
  assert.deepEqual(ladderSteps({}).map((s) => s.state), ['', '', '', '']);
  assert.deepEqual(ladderSteps({ current: 'pending', outcome: 'blocked' }).map((s) => s.state),
    ['done', 'bad', '', '']);
  assert.deepEqual(ladderSteps({ current: 'soft', outcome: 'blocked', required: 'finalized' })
    .filter((s) => s.required).map((s) => s.proof), ['finalized']);
});

test('13 receiptBuckets：pend=未 included，done=included，超期单列且不改分桶', () => {
  const receipts = [
    { digest: 'a', status: 'signed', view: { pastDeadline: false } },
    { digest: 'b', status: 'seen', view: { pastDeadline: true } },
    { digest: 'c', status: 'included', view: { pastDeadline: false } },
  ];
  const b = receiptBuckets(receipts);
  assert.equal(b.all.length, 3);
  assert.deepEqual(b.pend.map((r) => r.digest), ['a', 'b']);
  assert.deepEqual(b.done.map((r) => r.digest), ['c']);
  assert.deepEqual(b.stale.map((r) => r.digest), ['b']);
  assert.deepEqual(receiptBuckets(null).all, []);
});

test('14 receiptChip / txStatusChip：超期与失败的措辞不美化', () => {
  assert.deepEqual(receiptChip({ status: 'included' }), { text: 'included', cls: 'ch-felt' });
  assert.equal(receiptChip({ status: 'seen', view: { pastDeadline: true } }).cls, 'ch-bad');
  assert.equal(receiptChip({ status: 'signed' }).cls, 'ch-amb');
  assert.equal(txStatusChip('confirmed').text, '成功');
  assert.equal(txStatusChip('succeeded').cls, 'ch-felt');
  assert.equal(txStatusChip('reverted').text, '已回退');
  assert.equal(txStatusChip('pending').cls, 'ch-amb');
});

test('15 historyBuckets / txDirection：转账与合约分列，方向按本账户地址判定', () => {
  const txs = [{ kind: 'transfer', hash: '1' }, { kind: 'contract', hash: '2' }];
  const b = historyBuckets(txs);
  assert.equal(b.all.length, 2);
  assert.equal(b.tx.length, 1);
  assert.equal(b.c.length, 1);
  assert.equal(txDirection({ from: '0xAB', to: '0x11' }, '0xab'), 'out');
  assert.equal(txDirection({ from: '0x11', to: '0xAB' }, '0xab'), 'in');
  assert.equal(txDirection({ from: '0x11', to: '0x22' }, '0xab'), 'out');
});

// ---- 会话密钥 ----

test('16 sessionUsage：日限百分比封顶；无日限不画进度条；用尽判定', () => {
  assert.deepEqual(sessionUsage({ perDayLimit: '5000', dailyUsedToday: '2150' }),
    { percent: 43, usedText: '2150', limitText: '5000', exhausted: false });
  assert.equal(sessionUsage({ perDayLimit: '5000', dailyUsedToday: '9000' }).percent, 100);
  assert.equal(sessionUsage({ perDayLimit: '5000', dailyUsedToday: '9000' }).exhausted, true);
  assert.deepEqual(sessionUsage({ perDayLimit: null, dailyUsedToday: '0' }),
    { percent: null, usedText: '0', limitText: '不限' });
  assert.equal(sessionStatusChip('active').cls, 'ch-felt');
  assert.equal(sessionStatusChip('revoked').text, '已撤销');
  assert.equal(sessionStatusChip('weird').text, 'weird', '未知状态原样透出');
});

// ---- 错误码 / 合计边界 / 底色 ----

test('17 errorText：已知码给中文口径，未知码保留原始 code（不吞错）', () => {
  assert.equal(errorText({ code: 'BadPassword' }), '口令错误（fail-closed）');
  assert.equal(errorText({ code: 'InsufficientFunds', reason: '缺 300' }), '可用余额不足（note 全额消费，不支持部分花费）：缺 300');
  assert.equal(errorText({ code: 'BrandNewCode', reason: 'x' }), 'BrandNewCode：x');
  assert.equal(errorText('SessionInvalid'), '钱包已锁定，请先解锁');
  assert.equal(errorText(null), '');
  assert.ok(errorText({ code: 'X', reason: 'y'.repeat(400) }).length <= 220);
});

test('18 合计边界：域内可加（BigInt 不丢精度），跨域必须 DomainRequired，坏值 fail-closed', () => {
  assert.deepEqual(sumWithinDomain(['1', '2', '99999999999999999999'], 'GAME'),
    { ok: true, total: '100000000000000000002', domain: 'GAME' });
  assert.equal(sumWithinDomain(['1', '2']).ok, false);
  assert.equal(sumWithinDomain(['1', '2']).code, 'DomainRequired');
  assert.equal(sumWithinDomain(['1', '-2'], 'REAL').code, 'AmountInvalid');
  assert.equal(sumWithinDomain(['1.5'], 'REAL').code, 'AmountInvalid');
  assert.equal(PRICE_SOURCE_CONNECTED, false, '无价格源：UI 不得出现伪造的法币合计');
});

test('19 nextGround / screenTitle：双底色切换与账簿标题', () => {
  assert.equal(nextGround('paper'), 'night');
  assert.equal(nextGround('night'), 'paper');
  assert.equal(nextGround(undefined), 'night');
  assert.equal(screenTitle('acct', 'evm'), '账簿 · EVM 层');
  assert.equal(screenTitle('acct'), '账簿 · ZChain 层');
  assert.equal(screenTitle('settings'), '设置 · 能力矩阵');
  assert.equal(screenTitle('nope'), 'ZChain Wallet');
});
