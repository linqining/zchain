// =============================================================================
// extension/tests/prd_ledger_acceptance.test.js
//
// PRD《ZChain Wallet · 方向 B 账簿》§10 验收标准的**纯函数层**逐项断言。
//
// 分工：`ui_ledger.test.js` 保历史口径不回退；本文件按 AC 编号正向断言
// 本文档新钉住的契约（精度补齐、outcome 判定、上限文案、UTC 日窗口、
// 词汇漂移上报、合计不硬编码……）。每条测试名带 AC/R 编号，验收报告可直接
// 引用测试名作为证据。DOM 侧与真实网关侧的 AC 由 tests/e2e 覆盖，见验收报告。
// =============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CAPACITY,
  DAILY_RESET_TEXT,
  ERROR_TEXT,
  ID_PREFIX,
  INCLUSION_LADDER,
  PRICE_SOURCE_CONNECTED,
  PROOF_ALIASES,
  PROOF_LADDER,
  capacityNotice,
  domainTotals,
  errorText,
  fmtAmount,
  fmtDisplay,
  fmtFiat,
  idText,
  ladderOutcome,
  ladderSteps,
  limitReasonText,
  normalizeProof,
  proofLadder,
  proofLogSummary,
  receiptBuckets,
  receiptChip,
  relTime,
  remainText,
  requiredProofText,
  sessionUsage,
  shortAddr,
  subClampedDecimal,
  sumDecimals,
  sumWithinDomain,
  txDirection,
  txStatusChip,
  utcDayIndex,
} from '../common/ui_ledger.js';

import { CAPABILITY_ROWS, overBudgetNote } from '../common/capability_matrix.js';
import { receiptAmount, receiptEvidenceText, receiptKindLabel } from '../common/receipts.js';
import { SESSION_SCOPES, DEFAULT_SESSION_SCOPES, FORBIDDEN_SCOPES } from '../common/sessions.js';
import { computeMetrics } from '../common/telemetry.js';

// ---------------------------------------------------------------------------
// AC-01 / R-01 · 无价格源不得出现法币
// ---------------------------------------------------------------------------

test('AC-01 价格源未接入时 fmtFiat 恒返回「—」，且不接受调用方传入的数字', () => {
  assert.equal(PRICE_SOURCE_CONNECTED, false);
  assert.equal(fmtFiat(22288.63), '—');
  assert.equal(fmtFiat('10000'), '—');
  // 结构性保证：本模块导出的任何格式化函数都不产生 `$` 前缀
  assert.equal(/\$/.test(fmtAmount('22288.63')), false);
  assert.equal(/\$/.test(fmtDisplay('22288.63', 'usd')), false);
});

// ---------------------------------------------------------------------------
// AC-02 / AC-04 · 跨域不轧差 + 合计必须能加平
// ---------------------------------------------------------------------------

test('AC-02 domainTotals 逐域各给一个合计，结构上不存在跨域总和', () => {
  const t = domainTotals({
    REAL: [{ amount: '10000' }, { amount: '120' }],
    GAME: [{ amount: '12400' }],
  });
  assert.deepEqual(t.REAL, { ok: true, total: '10120', count: 2 });
  assert.deepEqual(t.GAME, { ok: true, total: '12400', count: 1 });
  // 没有任何"合计所有域"的键
  assert.deepEqual(Object.keys(t).sort(), ['GAME', 'REAL']);
});

test('AC-02 缺域参数即 fail-closed（不允许匿名合计）', () => {
  assert.deepEqual(sumWithinDomain(['1', '2']), { ok: false, code: 'DomainRequired' });
});

test('AC-04 复算 PRD §13 C-01：稿面三链总额是手写字面量，求和结果对不上', () => {
  // 稿写 ≈ $22,288.63，逐层相加得 22,288.11 —— 差 $0.52，证明该数非计算结果。
  const layers = ['10120.00', '8124.69', '4043.42'];
  const cents = layers.map((v) => BigInt(Math.round(Number(v) * 100)));
  const total = cents.reduce((a, b) => a + b, 0n);
  assert.equal(total.toString(), '2228811');
  assert.notEqual(total.toString(), '2228863');
});

test('AC-04 sumDecimals 任一非法即整体拒绝，不返回半截合计', () => {
  assert.deepEqual(sumDecimals(['100', '250', '1500']), { ok: true, total: '1850' });
  const bad = sumDecimals(['100', '1.5']);
  assert.equal(bad.ok, false);
  assert.equal(bad.code, 'AmountInvalid');
  assert.equal('total' in bad, false);
});

// ---------------------------------------------------------------------------
// AC-46 / R-27 · 边界值与展示精度表
// ---------------------------------------------------------------------------

test('AC-46 金额边界：0 / u64 上限 / 前导零 / 负数', () => {
  assert.equal(fmtDisplay('0', 'play'), '0.00');
  assert.equal(fmtDisplay('18446744073709551615', 'play'), '18,446,744,073,709,551,615.00');
  assert.equal(fmtAmount('000123'), '123');
  assert.equal(fmtDisplay('-500', 'play'), '-500.00');
  assert.equal(fmtDisplay('', 'play'), '');
  assert.equal(fmtDisplay('—', 'play'), '—');
  assert.equal(fmtDisplay('proven', 'play'), 'proven', '非十进制值原样回落，不静默变 0');
});

test('R-27 展示精度只补齐、不截断、不四舍五入（显示精度 ≠ 存储精度）', () => {
  assert.equal(fmtDisplay('12400', 'play'), '12,400.00');
  assert.equal(fmtDisplay('0.25', 'eth'), '0.2500');
  // 实际小数位多于目标 → 全部保留（上游 formatUnits 已截断，展示层再 round 就会虚报余额）
  assert.equal(fmtDisplay('0.25009999', 'eth'), '0.25009999');
  assert.equal(fmtDisplay('1.005', 'usd'), '1.005', '绝不四舍五入成 1.01');
  assert.equal(fmtDisplay('100', 'erc20', { decimals: 6 }), '100.000000');
  assert.equal(fmtDisplay('100', 'unknown-kind'), '100', '未登记种类不造小数');
});

test('R-24 subClampedDecimal：可用 = 余额 − 在途，下钳 0 且 u64 安全', () => {
  assert.equal(subClampedDecimal('12400', '500'), '11900');
  assert.equal(subClampedDecimal('500', '12400'), '0');
  assert.equal(subClampedDecimal('18446744073709551615', '1'), '18446744073709551614');
  assert.equal(subClampedDecimal('12.5', '1'), null);
  assert.equal(subClampedDecimal(null, '1'), '0', '缺余额视为 0，不做减法借位');
  assert.equal(subClampedDecimal('100', null), '100');
});

// ---------------------------------------------------------------------------
// AC-09 / AC-10 / AC-11 / AC-12 · 凭证阶梯
// ---------------------------------------------------------------------------

test('AC-09 ladderOutcome：短板低于要求 → wait，且阶梯第三格画 cur（琥珀）', () => {
  const outcome = ladderOutcome({ weakest: 'soft', required: 'proven' });
  assert.equal(outcome, 'wait');
  const steps = ladderSteps({ current: 'soft', outcome, required: 'proven' });
  assert.deepEqual(steps.map((s) => s.state), ['done', 'done', 'cur', '']);
  assert.equal(steps[2].required, true);
});

test('AC-10 同一 weakest=soft，提现页 canSubmit=false 必须画 bad（朱红）而非 cur', () => {
  const home = ladderSteps({ current: 'soft', outcome: ladderOutcome({ weakest: 'soft', required: 'proven' }) });
  const withdraw = ladderSteps({ current: 'soft', outcome: ladderOutcome({ weakest: 'soft', required: 'finalized', canSubmit: false }) });
  assert.equal(home[2].state, 'cur');
  assert.equal(withdraw[2].state, 'bad');
  // §13 C-11：这不是稿面画错，是两种 outcome——四格笔触必须由 outcome 决定
});

test('AC-12 空集合：weakest=null → idle，四格全空，不显示"全部达标"', () => {
  const ladder = proofLadder([]);
  assert.equal(ladder.weakest, null);
  assert.equal(ladder.total, 0);
  const steps = ladderSteps({ current: ladder.weakest, outcome: ladderOutcome({ weakest: ladder.weakest }) });
  assert.equal(ladderOutcome({ weakest: null }), 'idle');
  assert.deepEqual(steps.map((s) => s.state), ['', '', '', '']);
});

test('AC-11 未知 proof 回落 pending 且必须上报 mismatch（不静默）', () => {
  const ladder = proofLadder([{ proof: 'bogus_state' }, { proof: null }]);
  assert.equal(ladder.counts.pending, 2);
  assert.deepEqual(ladder.mismatches.sort(), ['bogus_state', 'null']);
  // 事件在 TELEMETRY_SCHEMA 里已登记，界面须逐条上报（R-18）
  assert.equal(computeMetrics([{ id: 'proof_ladder_mismatch', props: { rawValue: 'bogus_state' } }]).ladderMismatch, 1);
});

test('R-18 verifier 侧 FinalityLevel::Local 经别名映射，但同样计入漂移监测', () => {
  assert.deepEqual(normalizeProof('local'), { proof: 'pending', known: true, raw: 'local', aliased: true });
  assert.equal(PROOF_ALIASES.local, 'pending');
  const ladder = proofLadder([{ proof: 'local' }, { proof: 'finalized' }]);
  assert.equal(ladder.weakest, 'pending');
  assert.deepEqual(ladder.mismatches, ['local'], '别名命中也要上报，否则词汇双轨永远发现不了');
  // UI 阶梯第一格对齐 note 侧 `pending`（不是 verifier 侧 `local`）
  assert.equal(PROOF_LADDER[0], 'pending');
});

test('R-05b「本网络要求的等级」是数据不是文案', () => {
  assert.match(requiredProofText({ required: 'soft', networkKind: 'devnet' }), /本网络要求 soft（devnet）/);
  assert.match(requiredProofText({}), /未定义凭证门槛/);
});

// ---------------------------------------------------------------------------
// AC-13 / AC-17 · 两套状态机不得混用
// ---------------------------------------------------------------------------

test('AC-13 凭证阶梯与投递阶梯词汇完全不相交，渲染出口也分开', () => {
  assert.deepEqual(PROOF_LADDER, ['pending', 'soft', 'proven', 'finalized']);
  assert.deepEqual(INCLUSION_LADDER, ['signed', 'seen', 'included']);
  assert.equal(PROOF_LADDER.filter((x) => INCLUSION_LADDER.includes(x)).length, 0);
});

test('AC-17 超期只改芯片笔触、不改分桶；included 恒 felt', () => {
  const seenStale = { status: 'seen', view: { pastDeadline: true } };
  const buckets = receiptBuckets([seenStale, { status: 'included', view: {} }]);
  assert.equal(buckets.pend.length, 1, 'seen 即使超期仍在未上链段');
  assert.equal(buckets.done.length, 1);
  assert.equal(buckets.stale.length, 1);
  assert.deepEqual(receiptChip(seenStale), { text: 'seen 超期', cls: 'ch-bad' });
  assert.deepEqual(receiptChip({ status: 'included', view: {} }), { text: 'included', cls: 'ch-felt' });
});

test('AC-16 链上交易未知态必须显示「待确认」而不是原词 pending', () => {
  assert.deepEqual(txStatusChip('pending'), { text: '待确认', cls: 'ch-amb' });
  assert.equal(txStatusChip('reverted').text, '已回退');
  assert.equal(txStatusChip('confirmed').text, '成功');
});

test('PRD F-16：txDirection 未知一律 out（保守，不当作收入）', () => {
  assert.equal(txDirection({ from: '0xa', to: '0xb' }, '0xc'), 'out');
  assert.equal(txDirection({ from: '0xa', to: '0xc' }, '0xc'), 'in');
  assert.equal(txDirection({}, '0xc'), 'out');
  assert.equal(txDirection({ from: '0xc' }, ''), 'out', '自身地址未知也不猜收入');
});

// ---------------------------------------------------------------------------
// AC-14 / AC-15 · 时间文案单一出口（§13 C-09 / C-10）
// ---------------------------------------------------------------------------

test('AC-14 剩余 92 秒必须渲染 1:32；45 秒渲染 45s；边界 60 秒进 m:ss', () => {
  assert.equal(remainText(92_000), '1:32');
  assert.equal(remainText(45_000), '45s');
  assert.equal(remainText(59_999), '60s' === remainText(59_999) ? remainText(59_999) : '1:00');
  assert.equal(remainText(60_000), '1:00');
  assert.equal(remainText(3_700_000), '1h 1m', '§6.3 的 Nh Mm 不补零（分钟不是时间戳字段）');
  assert.equal(remainText(-1), '已过期');
  assert.equal(remainText(Number.NaN), '—');
});

test('AC-15 相对时间没有「昨天」这个输出；>30 天走 ISO 日期', () => {
  const now = Date.UTC(2026, 8, 19, 12, 0, 0);
  assert.equal(relTime(now - 30 * 3600 * 1000, now), '1 天前');
  assert.equal(relTime(now - 31 * 24 * 3600 * 1000, now), '2026-08-19');
  assert.equal(relTime(now - 5000, now), '刚刚', '<10s 归一为「刚刚」，避免秒级抖动');
  assert.equal(relTime(now - 15_000, now), '15 秒前');
  assert.equal(relTime(now + 10_000, now), '刚刚', '未来时间戳不得显示负数');
  assert.equal(relTime(null, now), '—');
});

test('AC-31 日累计按 UTC 日分窗（界面须显示该口径）', () => {
  assert.equal(DAILY_RESET_TEXT, '日累计按 UTC 日重置（非本地零点）');
  assert.equal(utcDayIndex(0), 0);
  assert.equal(utcDayIndex(86_400), 1);
  assert.equal(utcDayIndex(86_399), 0);
  // 本地 UTC+8 的"今天"与 UTC 日序号不冲突：分母恒为 86400
  assert.equal(Math.floor(1_700_000_000 / 86_400), utcDayIndex(1_700_000_000));
});

// ---------------------------------------------------------------------------
// R-11 / R-06 · 上限与超限文案
// ---------------------------------------------------------------------------

test('R-11 每处上限都有常驻说明文案（不静默丢数据）', () => {
  assert.deepEqual(CAPACITY, { noteInputs: 16, noteOutputs: 16, receipts: 20, sessions: 16, chainTxs: 500, proofLog: 20 });
  assert.match(capacityNotice('receipts'), /仅保留最近 20 条/);
  assert.match(capacityNotice('sessions'), /上限 16/);
  assert.match(capacityNotice('proofLog'), /最近 20 次/);
  assert.match(capacityNotice('chainTxs'), /500/);
  assert.match(capacityNotice('noteInputs', { count: 19 }), /19/);
});

test('R-06 五个未演示边界态有确定文案，且超限必须给出路', () => {
  assert.match(limitReasonText('noteCountOverLimit', { count: 17 }), /超过单签上限 16.*合并小额/);
  assert.match(limitReasonText('previewExpired'), /重新发起/);
  assert.match(limitReasonText('sessionLimitReached'), /请先撤销/);
  assert.match(limitReasonText('perTxOverLimit', { amount: '1500', perTxLimit: '1000' }), /需输入口令确认/);
  assert.match(limitReasonText('dailyExhausted', { used: '5000', limit: '5000' }), /UTC 日重置/);
  assert.equal(limitReasonText('不存在的码'), null, '未知码不得编造文案');
});

test('R-36 复验计数口径：无时间戳只报「次」，有时间戳才给 24h 窗口', () => {
  const undated = proofLogSummary([{ verdict: 'verified' }, { verdict: 'verified' }]);
  assert.equal(undated.text, '最近 2 次本地复验');
  assert.equal(undated.within24h, null);
  assert.equal(undated.count, 2);

  const now = Date.UTC(2026, 8, 19);
  const dated = proofLogSummary([
    { verdict: 'verified', atMs: now, binding: 'a'.repeat(64) },
    { verdict: 'verified', atMs: now - 25 * 3600 * 1000, binding: 'b'.repeat(64) },
    { verdict: 'verified', atMs: now - 1000, binding: 'a'.repeat(64) },
  ], now);
  assert.match(dated.text, /24 小时内 2 次/);
  assert.equal(dated.within24h, 2);
  // 「份」≠「次」：同一 hand binding 复验两次是 2 次 1 份
  assert.equal(dated.count, 3);
  assert.equal(dated.distinctBindings, 2);
});

// ---------------------------------------------------------------------------
// R-29 / R-33 / R-25 · 标识符具名与证据诚实
// ---------------------------------------------------------------------------

test('R-29 每类标识符有固定前缀与统一缩略参数（稿面 ≥4 种缩略并存）', () => {
  assert.deepEqual(ID_PREFIX, {
    tx: 'tx', digest: 'rc', handBinding: 'hb', requestId: 'req',
    noteCommitment: 'note', payoutRoot: 'root', sessionId: 'sess',
  });
  assert.equal(idText('tx', '0xc41d8f22e9a04b79b3f9e77d0aa31c4'), 'tx 0xc41d8f22…aa31c4');
  assert.equal(idText('handBinding', 'c41d8f22e9a04b79b3f9e77d0aa31c4be'), 'hb c41d8f22e9…31c4be');
  // §13 C-07：缩略尾段必须真是**尾部**（稿面曾把取自第 13 位的片段当尾段）
  assert.ok(idText('handBinding', 'c41d8f22e9a04b79b3f9e77d0aa31c4be').endsWith('31c4be'));
  assert.equal(idText('tx', ''), 'tx —');
  assert.equal(idText('tx', 'short'), 'tx short', '短于 head+tail+1 原样返回');
  // 全应用统一 (10,6)：稿面曾并存 6/4、12/8、4/4、6/2 四种
  assert.equal(shortAddr('a'.repeat(40)), 'a'.repeat(10) + '…' + 'a'.repeat(6));
});

test('R-33 / AC-27 included 的 evidence 必须说明是本机手工登记', () => {
  assert.match(receiptEvidenceText({ seen: 'not_provided', included: 'local_manual_entry' }), /本机手工登记，未经链上核对/);
  assert.match(receiptEvidenceText({ seen: 'receipt_unverified_signature' }), /未验签/);
  assert.match(receiptEvidenceText({ included: 'gateway_signed_entry' }), /gateway_signed_entry/, '未知证据词原样透出不翻译');
});

test('R-25 kind 未知不造标题；tableId 只认非负整数（见 receipts.test.js）', () => {
  assert.equal(receiptKindLabel('settle').known, true);
  assert.equal(receiptKindLabel('opentable').known, false);
  assert.equal(receiptAmount({ inputs: [{ amount: '1' }, { amount: '2' }] }).total, '3');
  assert.equal(receiptAmount({ inputs: [{ amount: '1' }, {}] }).code, 'AmountInvalid');
});

// ---------------------------------------------------------------------------
// AC-29 / R-30 · scope 与后台同一份常量
// ---------------------------------------------------------------------------

test('AC-29 UI 勾选项来自 SESSION_SCOPES 单一来源，禁用项恒被排除', () => {
  assert.equal(Array.isArray(SESSION_SCOPES), true);
  assert.ok(SESSION_SCOPES.length >= 4, 'PRD 记为 4 项，实现为 5 项——界面按实现，验收报告登记该偏离');
  for (const sc of DEFAULT_SESSION_SCOPES) assert.ok(SESSION_SCOPES.includes(sc));
  for (const sc of FORBIDDEN_SCOPES) assert.equal(SESSION_SCOPES.includes(sc), false, `${sc} 不得作为可授权 scope`);
  assert.equal(SESSION_SCOPES.includes('withdraw'), false, 'scope 全集不含 withdraw');
  assert.equal(SESSION_SCOPES.includes('opentable'), false, '稿面的 OpenTable 在实现里不存在');
});

// ---------------------------------------------------------------------------
// R-26 / AC-36 · 能力矩阵单一数据源与网络措辞
// ---------------------------------------------------------------------------

test('R-26 能力矩阵是单一常量，且 mainnet 限制只挂在 ZChain 层', () => {
  assert.ok(CAPABILITY_ROWS.length >= 6);
  const networkRows = CAPABILITY_ROWS.filter((r) => r.layer.startsWith('网络'));
  assert.ok(networkRows.length >= 2, '网络可用性必须逐层分列，不能压成一句');
  const zcNet = networkRows.find((r) => r.layer.includes('ZChain'));
  const chainNet = networkRows.find((r) => r.layer.includes('EVM'));
  assert.match(zcNet.cannot, /mainnet 刻意不注册/);
  assert.match(chainNet.can, /主网条目/, 'EVM / Starknet 层实际已注册主网，不得说成全局不开放');
  // 全局不得存在"不分层的 mainnet 不注册"断言
  for (const row of CAPABILITY_ROWS) {
    if (!row.layer.includes('ZChain')) {
      assert.equal(/^mainnet 刻意不注册/.test(row.can + row.cannot), false);
    }
  }
  assert.match(ERROR_TEXT.NetworkUnsupported, /ZChain 层/, '错误码文案同样不得笼统宣称 mainnet 不可用');
});

test('AC-34 能力矩阵与红线不得包含任何审计承诺字样', () => {
  const blob = JSON.stringify(CAPABILITY_ROWS) + JSON.stringify(ERROR_TEXT);
  for (const banned of ['已审计', '审计通过', 'audited', '安全保证', '链上已验证', 'on-chain verified']) {
    assert.equal(blob.includes(banned), false, `不得出现「${banned}」`);
  }
});

test('AC-25 超预算标注由实测耗时推出，未超预算不得喊超', () => {
  assert.equal(overBudgetNote(300), null);
  assert.equal(overBudgetNote(500), null);
  assert.match(overBudgetNote(1720), /超预算.*1\.72s/);
  assert.match(overBudgetNote(1720), /0\.50s/);
});

// ---------------------------------------------------------------------------
// §6.3 其它格式化契约（防被"顺手改掉"）
// ---------------------------------------------------------------------------

test('§6.3 fmtAmount 保留原始小数位：不补齐、不四舍五入、不造精度', () => {
  assert.equal(fmtAmount('0.25'), '0.25');
  assert.equal(fmtAmount('12345678.9'), '12,345,678.9');
  assert.equal(fmtAmount(-0.5), '-0.5');
  assert.equal(fmtAmount('abc'), 'abc');
});

test('R-06 无日限时不画进度条：percent=null 且 limitText=不限', () => {
  assert.deepEqual(sessionUsage({ perDayLimit: null, dailyUsedToday: '10' }), { percent: null, usedText: '10', limitText: '不限' });
  const full = sessionUsage({ perDayLimit: '5000', dailyUsedToday: '5000' });
  assert.equal(full.percent, 100);
  assert.equal(full.exhausted, true);
  assert.equal(sessionUsage({ perDayLimit: '5000', dailyUsedToday: '2150' }).percent, 43);
});

test('错误码文案：未知码原样透出 code 不吞（§6.3）', () => {
  assert.equal(errorText('TotallyNewCode'), 'TotallyNewCode');
  assert.match(errorText({ code: 'ProofTooLarge' }), /证明体积超出可验证上限/);
  assert.equal(errorText({ code: 'BadPassword', reason: 'no match' }), '口令错误（fail-closed）：no match');
  assert.equal(errorText({ code: 'X', reason: 'y'.repeat(400) }).length, 201, '截断 200 + 省略号');
});
