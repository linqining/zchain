// =============================================================================
// extension/common/withdraw_preview.js — REAL 提现预览（Extension 0.3，展示态）
//
// plan §6.12.4 Extension 0.3"提现预览"：REAL 提现请求的**逐字段预览**（金额/
// 收款 owner/finality 状态/托管风险），finality 未达 proven+finalized 时提交
// 按钮禁用并显示原因。
//
// 红线（与 0.2 的 REAL 展示边界一致，绝不越过）：本模块**不开放真实提现
// 提交**——canSubmit 恒为 false，且是 wallet-core display.rs 展示门（
// readiness=vault_offline）与 finality 判定的**合取**：任何一层不满足都不
// 可能出现可提交态。UI 只消费本模块输出，不得自行决定。
//
// 纯函数、零依赖、无 IO、零密码学。
// =============================================================================

import { validateHex } from './validation.js';

/** proof 层级高度（finality 聚合用；与 note_store ProofState 对应）。 */
const PROOF_RANK = { pending: 0, soft: 1, proven: 2, finalized: 3 };

/** 提现准入的最低层级（plan：finality 未达 proven+finalized 时禁用——
 *  此处取 finalized 为最低要求，从严）。 */
export const WITHDRAW_MIN_PROOF = 'finalized';

/**
 * 构造 REAL 提现预览（展示态）。
 *
 * @param {object} input
 *   {amount: 十进制字符串, owner: hex33, realNotes: [{amount, proof, spendable,
 *   commitment}...], displayViews: {real: {show_claim, claim_disabled_reason,
 *   custody_risk_notice}}, chainId, nowSec}
 * @returns {{ok:true, preview}} | {{ok:false, code, reason}}
 */
export function buildWithdrawPreview(input) {
  if (!input || typeof input !== 'object') {
    return { ok: false, code: 'InvalidArgument', reason: 'input required' };
  }
  const amount = typeof input.amount === 'string' ? input.amount.trim() : String(input.amount ?? '');
  if (!/^[0-9]+$/.test(amount) || amount === '0') {
    return { ok: false, code: 'AmountInvalid', reason: '金额必须是正十进制整数' };
  }
  if (amount.length > 20) {
    return { ok: false, code: 'AmountOverflow', reason: '金额超出 u64 范围' };
  }
  const owner = validateHex(input.owner, 33);
  if (!owner.ok) {
    return { ok: false, code: 'OwnerInvalid', reason: '收款 owner 必须是 66 位 hex（33B 压缩公钥）' };
  }

  const notes = Array.isArray(input.realNotes) ? input.realNotes : [];
  const spendable = notes.filter((n) => n && n.spendable !== false);
  // 贪心选币（金额降序；展示面，不承担密码学/账本职责——真实选币随提现
  // 路径开放时由 wallet-core 承担）。
  const sorted = [...spendable].sort((a, b) => BigInt(b.amount ?? '0') > BigInt(a.amount ?? '0') ? 1 : -1);
  let remaining = BigInt(amount);
  const selected = [];
  for (const n of sorted) {
    if (remaining <= 0n) break;
    selected.push(n);
    remaining -= BigInt(n.amount ?? '0');
  }
  const covered = remaining <= 0n;

  // finality 聚合：所选 note 的最低层级（短板决定整体 finality）；库空或
  // 余额不足时如实标注。
  const worst = selected.reduce(
    (acc, n) => (PROOF_RANK[n.proof] ?? 0) < (PROOF_RANK[acc] ?? 0) ? (n.proof ?? 'pending') : acc,
    selected.length > 0 ? 'finalized' : 'none',
  );
  const finalityReached = selected.length > 0 && covered && (PROOF_RANK[worst] ?? 0) >= PROOF_RANK[WITHDRAW_MIN_PROOF];

  const real = input.displayViews?.real ?? {};
  const reasons = [];
  if (real.show_claim === false) {
    reasons.push(`vault_offline: ${real.claim_disabled_reason ?? 'wallet-core 展示门未就绪'}`);
  }
  if (notes.length === 0) {
    reasons.push('REAL 库为空（当前版本不开放 REAL 入金/铸造）');
  } else if (!covered) {
    reasons.push(`可花费 REAL 余额不足以覆盖请求金额 ${amount}`);
  } else if (!finalityReached) {
    reasons.push(`finality 未达标：所选 note 最低层级为 ${worst}，提现要求 ${WITHDRAW_MIN_PROOF}`);
  }

  return {
    ok: true,
    preview: {
      kind: 'withdraw',
      assetClass: 'REAL',
      chainId: typeof input.chainId === 'string' ? input.chainId : null,
      amount,
      owner: String(input.owner).toLowerCase(),
      inputs: selected.map((n) => ({
        commitment: n.commitment ?? null,
        amount: String(n.amount ?? '0'),
        proof: n.proof ?? 'pending',
      })),
      finality: {
        worstProof: worst,
        requiredProof: WITHDRAW_MIN_PROOF,
        reached: finalityReached,
      },
      custodyRisk: real.custody_risk_notice ?? 'real_is_custodial',
      // 展示态红线：canSubmit 恒 false；reasons 逐条解释（UI 禁用按钮并展示）。
      canSubmit: false,
      cannotSubmitReasons: reasons,
      displayOnly: true,
      generatedAtSec: Number.isSafeInteger(input.nowSec) ? input.nowSec : Math.floor(Date.now() / 1000),
    },
  };
}
