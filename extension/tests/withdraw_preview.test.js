// =============================================================================
// extension/tests/withdraw_preview.test.js — REAL 提现预览（展示态）测试
// （Extension 0.3）
//
// 覆盖：金额/owner 形状 fail-closed、贪心选币与 finality 聚合（短板决定）、
// 余额不足、REAL 库为空、展示门合取（vault_offline + finality）、
// **canSubmit 恒 false**（display-only 红线——任何就绪组合都不出现可提交态）。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildWithdrawPreview, WITHDRAW_MIN_PROOF } from '../common/withdraw_preview.js';

const OWNER = 'ab'.repeat(33);
const VIEWS_OFFLINE = {
  real: { show_claim: false, claim_disabled_reason: 'vault_offline', custody_risk_notice: 'real_is_custodial' },
};

function note(amount, proof, seedByte = 1) {
  return { commitment: String(seedByte).repeat(64), amount: String(amount), proof, spendable: true };
}

const BASE = {
  amount: '1500',
  owner: OWNER,
  displayViews: VIEWS_OFFLINE,
  chainId: 'zchain-devnet-1',
  nowSec: 1_757_000_000,
};

test('01 形状 fail-closed：坏金额（0/负/非十进制/溢出长度）/ 坏 owner', () => {
  assert.equal(buildWithdrawPreview({ ...BASE, amount: '0' }).code, 'AmountInvalid');
  assert.equal(buildWithdrawPreview({ ...BASE, amount: '-5' }).code, 'AmountInvalid');
  assert.equal(buildWithdrawPreview({ ...BASE, amount: '12.5' }).code, 'AmountInvalid');
  assert.equal(buildWithdrawPreview({ ...BASE, amount: '1'.repeat(21) }).code, 'AmountOverflow');
  assert.equal(buildWithdrawPreview({ ...BASE, owner: 'ab'.repeat(32) }).code, 'OwnerInvalid');
  assert.equal(buildWithdrawPreview({ ...BASE, owner: 'zz'.repeat(33) }).code, 'OwnerInvalid');
  assert.equal(buildWithdrawPreview(null).code, 'InvalidArgument');
});

test('02 贪心选币 + finality 短板聚合：混合层级取最低', () => {
  const r = buildWithdrawPreview({
    ...BASE,
    realNotes: [note(1000, 'finalized', 1), note(800, 'soft', 2)],
  });
  assert.equal(r.ok, true);
  const p = r.preview;
  assert.equal(p.assetClass, 'REAL');
  assert.equal(p.amount, '1500');
  assert.equal(p.owner, OWNER);
  assert.equal(p.inputs.length, 2); // 1000 + 800 覆盖 1500
  assert.equal(p.finality.worstProof, 'soft'); // 短板决定
  assert.equal(p.finality.requiredProof, WITHDRAW_MIN_PROOF);
  assert.equal(p.finality.reached, false);
  assert.equal(p.canSubmit, false); // display-only 红线
  assert.ok(p.cannotSubmitReasons.some((x) => x.includes('vault_offline')));
  assert.ok(p.cannotSubmitReasons.some((x) => x.includes('finality')));
  assert.equal(p.custodyRisk, 'real_is_custodial');
  assert.equal(p.displayOnly, true);
});

test('03 全 finalized 也恒禁用（展示门合取；绝不出现可提交态）', () => {
  const r = buildWithdrawPreview({
    ...BASE,
    realNotes: [note(2000, 'finalized', 3)],
  });
  const p = r.preview;
  assert.equal(p.finality.worstProof, 'finalized');
  assert.equal(p.finality.reached, true);
  // finality 已达，但展示门（vault_offline）未就绪 → 仍禁用
  assert.equal(p.canSubmit, false);
  assert.ok(p.cannotSubmitReasons.some((x) => x.includes('vault_offline')));
  assert.ok(!p.cannotSubmitReasons.some((x) => x.includes('finality')));
});

test('04 余额不足 / REAL 库为空：如实标注', () => {
  const short = buildWithdrawPreview({ ...BASE, realNotes: [note(100, 'finalized', 1)] });
  assert.equal(short.ok, true);
  assert.equal(short.preview.finality.reached, false); // 余额不足 = 未覆盖
  assert.ok(short.preview.cannotSubmitReasons.some((x) => x.includes('不足以覆盖')));
  const empty = buildWithdrawPreview({ ...BASE, realNotes: [] });
  assert.equal(empty.preview.finality.worstProof, 'none');
  assert.ok(empty.preview.cannotSubmitReasons.some((x) => x.includes('REAL 库为空')));
});

test('05 锁定 note 不参与选币（spendable=false 跳过）', () => {
  const r = buildWithdrawPreview({
    ...BASE,
    realNotes: [{ ...note(5000, 'finalized', 1), spendable: false }, note(2000, 'finalized', 2)],
  });
  assert.equal(r.preview.inputs.length, 1);
  assert.equal(r.preview.inputs[0].amount, '2000');
});

test('06 十进制字符串金额边界（u64 级不丢精度）', () => {
  const r = buildWithdrawPreview({
    ...BASE,
    amount: '18446744073709551615',
    realNotes: [note('18446744073709551615', 'finalized')],
  });
  assert.equal(r.ok, true);
  assert.equal(r.preview.amount, '18446744073709551615');
  assert.equal(r.preview.inputs[0].amount, '18446744073709551615');
});
