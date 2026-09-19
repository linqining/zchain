// =============================================================================
// extension/tests/transfer_preview.test.js — 钱包侧 PLAY 转账选币（方向 B）
//
// 覆盖：输入归一（千分位/小数/0/超长）/ owner 与 self owner 形状校验 / 自转
// 拒绝 / 贪心选币（降序、最少张数、同额按 commitment 稳定序）/ 守恒（Σout ==
// Σin）/ 找零输出与"找零无处可去"禁提交 / 凭证短板聚合与 GAME 门槛 / 批量上限 /
// 余额不足如实标注 / operation 形状可直接过 validateSignOperation /
// canSubmit 是全部条件的合取（任一不满足即 false）。
// 零 IO、零密码学（不触达 wallet-core）。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildTransferPreview, parseAmountInput, selectNotes, verifySpendProofs,
  minProofForNetwork, GAME_MIN_PROOF,
} from '../common/transfer_preview.js';
import { validateRequest } from '../common/validation.js';

/** 签名面校验走公开入口（与后台管线同一函数；previewHash 允许空串）。 */
const checkSign = (operation, network) =>
  validateRequest('zchain_signOperation', { operation, previewHash: '' }, { network });

const OWNER = '02' + 'ab'.repeat(32);           // hex33 收款
const SELF = '03' + 'cd'.repeat(32);            // hex33 本账户
const C = (n) => n.toString(16).padStart(2, '0').repeat(32).slice(0, 64);

function note(amount, proof = 'proven', opts = {}) {
  return { commitment: opts.commitment ?? C(amount), amount: String(amount), proof, spendable: opts.spendable !== false };
}

function base(over = {}) {
  return {
    amount: '500',
    owner: OWNER,
    selfOwner: SELF,
    playNotes: [note(300), note(200), note(1_000)],
    chainId: 'zchain-devnet-1',
    nowSec: 1_700_000_000,
    ...over,
  };
}

// ---- 输入归一 ----

test('01 parseAmountInput：千分位/空格可接受，小数与非数字拒绝（不四舍五入）', () => {
  assert.deepEqual(parseAmountInput('1,234'), { ok: true, amount: '1234' });
  assert.deepEqual(parseAmountInput(' 500.00 '), { ok: true, amount: '500' });
  assert.deepEqual(parseAmountInput('007'), { ok: true, amount: '7' });
  assert.equal(parseAmountInput('500.5').code, 'AmountInvalid');
  assert.equal(parseAmountInput('500.5').reason, 'PLAY 为整数筹码，不支持小数');
  assert.equal(parseAmountInput('').code, 'AmountInvalid');
  assert.equal(parseAmountInput('-5').code, 'AmountInvalid');
  assert.equal(parseAmountInput('0').code, 'AmountInvalid');
  assert.equal(parseAmountInput('99999999999999999999999').code, 'AmountInvalid', '超过 20 位先按长度拒');
  assert.equal(parseAmountInput('18446744073709551616').code, 'AmountOverflow', 'u64 max + 1');
});

// ---- 选币 ----

test('02 selectNotes：金额降序贪心，最少张数覆盖，spendable=false 不参与', () => {
  const s = selectNotes([note(100), note(600), note(300, 'proven'), note(999, 'proven', { spendable: false })], '500');
  assert.deepEqual(s.selected.map((n) => n.amount), ['600']);
  assert.equal(s.totalIn, 600n);
  assert.equal(s.covered, true);
  const locked = selectNotes([note(999, 'proven', { spendable: false })], '500');
  assert.equal(locked.selected.length, 0);
  assert.equal(locked.covered, false);
});

test('03 贪心组合：单张不够时继续累加，恰好覆盖不产生找零', () => {
  const p = buildTransferPreview(base({ amount: '500', playNotes: [note(300), note(200), note(50)] }));
  assert.equal(p.ok, true);
  assert.deepEqual(p.preview.inputs.map((n) => n.amount), ['300', '200']);
  assert.equal(p.preview.totalIn, '500');
  assert.equal(p.preview.change, '0');
  assert.equal(p.preview.outputs.length, 1);
  assert.equal(p.preview.canSubmit, true);
});

test('04 守恒：Σoutputs 恒等于 Σinputs（note 全额消费，找零回本账户）', () => {
  const p = buildTransferPreview(base({ amount: '500', playNotes: [note(1_000), note(300)] })).preview;
  const sum = (xs) => xs.reduce((a, x) => a + BigInt(x.amount), 0n);
  assert.equal(sum(p.outputs).toString(), p.totalIn);
  assert.equal(p.totalIn, '1000');
  assert.equal(p.change, '500');
  assert.deepEqual(p.outputs, [{ owner: OWNER.toLowerCase(), amount: '500' }, { owner: SELF.toLowerCase(), amount: '500', change: true }]);
});

test('05 需要找零但本账户 owner 缺失 → 禁提交并给出原因（不静默丢筹码）', () => {
  const r = buildTransferPreview(base({ selfOwner: null, playNotes: [note(1_000)] }));
  assert.equal(r.preview.canSubmit, false);
  assert.ok(r.preview.cannotSubmitReasons.some((x) => x.includes('找零无处可去')));
});

// ---- 凭证门槛 ----

test('06 凭证短板聚合：混合层级取最低，未达 GAME 门槛禁提交', () => {
  const p = buildTransferPreview(base({ playNotes: [note(300, 'finalized'), note(200, 'soft')] }));
  assert.equal(p.preview.finality.worstProof, 'soft');
  assert.equal(p.preview.finality.requiredProof, GAME_MIN_PROOF);
  assert.equal(p.preview.finality.reached, false);
  assert.equal(p.preview.canSubmit, false);
  assert.ok(p.preview.cannotSubmitReasons.some((x) => /凭证短板为 soft/.test(x)));
});

test('07 全 proven 达标 → 可提交；未知 proof 记 pending（从严，不丢弃）', () => {
  assert.equal(buildTransferPreview(base({ playNotes: [note(300), note(200)] })).preview.canSubmit, true);
  const weird = buildTransferPreview(base({ playNotes: [note(300, 'wat'), note(200, 'proven')] }));
  assert.equal(weird.preview.finality.worstProof, 'pending');
  assert.equal(weird.preview.canSubmit, false);
});

// ---- 余额与批量 ----

test('08 余额不足：如实给出需要/可用金额，canSubmit=false', () => {
  const p = buildTransferPreview(base({ amount: '5000', playNotes: [note(300), note(200)] })).preview;
  assert.equal(p.covered, false);
  assert.equal(p.canSubmit, false);
  assert.ok(p.cannotSubmitReasons.some((x) => x.includes('需要 5000') && x.includes('可用 500')));
});

test('09 库为空 / note 无 commitment：原因逐条给出，不伪造可选币结果', () => {
  const empty = buildTransferPreview(base({ playNotes: [] })).preview;
  assert.equal(empty.canSubmit, false);
  assert.ok(empty.cannotSubmitReasons.some((x) => x.includes('没有可花费')));
  const noC = buildTransferPreview(base({ playNotes: [{ amount: '500', proof: 'proven' }] })).preview;
  assert.deepEqual(noC.operation.inputs, []);
});

test('10 批量上限：选币张数超过 maxInputs 时禁提交', () => {
  const many = Array.from({ length: 20 }, () => note(30));
  const p = buildTransferPreview(base({ amount: '600', playNotes: many })).preview;
  assert.ok(p.cannotSubmitReasons.some((x) => /批量上限/.test(x)));
  assert.equal(p.canSubmit, false);
});

// ---- 形状校验与自转 ----

test('11 owner 形状 / 自转 / 非法金额：稳定错误码', () => {
  assert.equal(buildTransferPreview(base({ owner: 'nope' })).code, 'OwnerInvalid');
  assert.equal(buildTransferPreview(base({ owner: '0x' + OWNER })).code, 'OwnerInvalid', '不接受 0x 前缀');
  assert.equal(buildTransferPreview(base({ owner: OWNER.slice(0, 60) })).code, 'OwnerInvalid');
  assert.equal(buildTransferPreview(base({ owner: SELF, selfOwner: SELF })).code, 'SelfTransfer');
  assert.equal(buildTransferPreview(base({ amount: 'abc' })).code, 'AmountInvalid');
});

test('12 预览产出的 operation 直接过签名面校验（展示与签名同源，无第二套形状）', () => {
  const p = buildTransferPreview(base()).preview;
  const v = checkSign(p.operation, { chainId: 'zchain-devnet-1', kind: 'devnet' });
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(p.operation.kind, 'transfer');
  assert.equal(p.operation.assetClass, 'PLAY');
  assert.equal(p.operation.domain, 'zchain');
  assert.equal(p.operation.abiVersion, 1);
  assert.equal(p.operation.expiry, 1_700_000_000 + 300);
});

test('13 REAL 资产类不可能从本模块产出（签名面红线由校验层守住）', () => {
  const v = checkSign(
    { kind: 'transfer', assetClass: 'REAL', chainId: 'zchain-devnet-1', domain: 'zchain', abiVersion: 1, nonce: 1, expiry: 2, inputs: [C(1)], outputs: [{ owner: OWNER, amount: '1' }] },
    { chainId: 'zchain-devnet-1', kind: 'devnet' },
  );
  assert.equal(v.code, 'AssetClassDisabledIn01');
});

test('14 确定性：同输入同 nowSec → 逐字段一致（摘要绑定的前提）', () => {
  const a = buildTransferPreview(base()).preview;
  const b = buildTransferPreview(base()).preview;
  assert.deepEqual(a.operation, b.operation);
  assert.deepEqual(a.inputs, b.inputs);
});

// ---- 网络门槛策略 + 签名前复核（后台边界第二道闸） ----

test('15 门槛是网络策略：devnet 放宽到 soft，其余维持设计要求的 proven', () => {
  assert.equal(minProofForNetwork('devnet'), 'soft');
  assert.equal(minProofForNetwork('testnet'), GAME_MIN_PROOF);
  assert.equal(minProofForNetwork('mainnet'), GAME_MIN_PROOF);
  assert.equal(GAME_MIN_PROOF, 'proven');
  // devnet 上 soft note 可提交；同一份数据在 testnet 口径下不可。
  const devnet = buildTransferPreview(base({ playNotes: [note(500, 'soft')], minProof: minProofForNetwork('devnet') })).preview;
  assert.equal(devnet.canSubmit, true, JSON.stringify(devnet.cannotSubmitReasons));
  const testnet = buildTransferPreview(base({ playNotes: [note(500, 'soft')], minProof: minProofForNetwork('testnet') })).preview;
  assert.equal(testnet.canSubmit, false);
  assert.equal(testnet.finality.requiredProof, 'proven');
});

test('16 verifySpendProofs：库里没有 / 已锁定 / 层级不足 → 全部拒绝', () => {
  const notes = [note(500, 'soft'), note(300, 'proven')];
  const ok = verifySpendProofs({ playNotes: notes, inputs: [notes[0].commitment, notes[1].commitment], minProof: 'soft' });
  assert.equal(ok.ok, true);
  assert.equal(ok.worst, 'soft');
  assert.equal(verifySpendProofs({ playNotes: notes, inputs: [], minProof: 'soft' }).code, 'NoSpendableNote');
  assert.equal(verifySpendProofs({ playNotes: notes, inputs: ['f'.repeat(64)] }).code, 'NoteNotFound');
  assert.equal(verifySpendProofs({ playNotes: [note(500, 'soft', { spendable: false })], inputs: [note(500).commitment] }).code, 'NoteNotSpendable');
  const gate = verifySpendProofs({ playNotes: notes, inputs: [notes[0].commitment], minProof: GAME_MIN_PROOF });
  assert.equal(gate.ok, false);
  assert.equal(gate.code, 'ProofBelowGate');
  assert.equal(gate.worst, 'soft');
});

test('17 复核按 commitment 大小写不敏感匹配，未知层级从严按 pending', () => {
  const n = note(500, 'wat');
  const r = verifySpendProofs({ playNotes: [n], inputs: [n.commitment.toUpperCase()], minProof: 'soft' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'ProofBelowGate');
  assert.equal(r.worst, 'pending');
});
