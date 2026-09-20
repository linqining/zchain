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
  /**
   * 逐条原因 + **性质标注**（R-07 / AC-08）。
   *
   * `policy` = 策略/依赖型：本版本不会自行开放（提现通道未开放、托管方签名
   * 服务待接入、REAL 入金未开放）；
   * `data` = 数据型：会随网关水位 / finality 推进自行满足。
   *
   * 为什么必须分开：三类原因同视觉权重时，用户会把"finality 未达标"这种
   * 等待型原因读成"等一会儿就能提"，而实际上策略型那两条本版本永远不会满足。
   * 这是资产误解，不是文案偏好——所以标注由数据产出，不由界面猜。
   */
  const reasonDetails = [];
  const push = (text, kind) => {
    reasons.push(text);
    reasonDetails.push({
      text,
      kind,
      qualifier: kind === 'policy' ? '本版本不会开放' : '随凭证推进可能满足',
    });
  };
  if (real.show_claim === false) {
    push(`vault_offline: ${real.claim_disabled_reason ?? 'wallet-core 展示门未就绪'}`, 'policy');
  }
  if (notes.length === 0) {
    push('REAL 库为空（当前版本不开放 REAL 入金/铸造）', 'policy');
  } else if (!covered) {
    push(`可花费 REAL 余额不足以覆盖请求金额 ${amount}`, 'data');
  } else if (!finalityReached) {
    push(`finality 未达标：所选 note 最低层级为 ${worst}，提现要求 ${WITHDRAW_MIN_PROOF}`, 'data');
  }
  if (real.custody_risk_notice === 'real_is_custodial_v1_offline') {
    push('托管方签名服务待接入（REAL 为托管映射，非链上可自由动用）', 'policy');
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
      // 与 `cannotSubmitReasons` 同序、逐条对应的性质标注（R-07 / AC-08）：
      // 策略型必须带"本版本不会开放"限定语，数据型才可说"随凭证推进可能满足"。
      cannotSubmitReasonDetails: reasonDetails,
      displayOnly: true,
      generatedAtSec: Number.isSafeInteger(input.nowSec) ? input.nowSec : Math.floor(Date.now() / 1000),
    },
  };
}
