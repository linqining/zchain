// =============================================================================
// extension/tests/e2e/stark_portal_harness_page.js — run_04 的 http 同源 harness 页
//
// 与 portal_harness_page.js（run_02，wallet-core 结算复验管线）同模式：Chrome 138+
// 对 chrome-extension 页访问 127.0.0.1 施加 LNA 限制，跨源 fetch 网关改在
// http://127.0.0.1 同源 harness 页执行**与 portal/portal.js 完全相同**的逻辑模块
// （common/portal.js 的 verifyStarkProof + common/stwo_verify.js 的真 wasm 门面），
// 对 fixture 网关执行 STARK 验证管线：
//   fetchSettlement → fetchProof(payload_b64) → verifyStarkProof(stwo wasm 完整验证)
//   →（可选）wallet-core 结算关系复验 → fail-closed 结论汇总。
//
// 诚实边界：本页不做任何验证语义；STARK 验证全部在 vendor/stwo-verify 的 wasm 内；
// settlement 复验全部在 vendor/wallet-core 的 wasm 内。结论 fail-closed：
// STARK 跳过/拒绝 ≠ verified。
// =============================================================================

import { callCore } from '../../common/wallet_core.js';
import { verifyCanonicalArchive } from '../../common/stwo_verify.js';
import {
  parseBinding, fetchSettlement, fetchProof, verifyStarkProof, verifyLocally,
} from '../../common/portal.js';

window.__STARK_PORTAL_RESULT = null;

/**
 * STARK portal 管线（与 portal/portal.js 的 verify 处理器同序）。
 * @param {string} gatewayUrl 网关 base
 * @param {string} bindingInput hand binding（64 hex）
 * @param {object} opts { fetchTimeoutMs?: number }
 */
window.runStarkPortalCheck = async (gatewayUrl, bindingInput, opts = {}) => {
  const out = { steps: {} };
  const b = parseBinding(bindingInput);
  if (!b.ok) return { ok: false, step: 'parseBinding', ...b };
  out.steps.binding = 'ok';

  const s = await fetchSettlement(gatewayUrl, b.binding, fetch, opts.fetchTimeoutMs);
  if (!s.ok) return { ok: false, step: 'fetchSettlement', ...s };
  out.steps.settlement = {
    hand_binding: s.detail.hand_binding,
    pot: s.detail.pot,
    level: s.detail.level,
  };

  const p = await fetchProof(gatewayUrl, b.binding, fetch, opts.fetchTimeoutMs);
  if (!p.ok) return { ok: false, step: 'fetchProof', ...p };
  out.steps.proof = {
    engine: p.proof.engine,
    engineSource: p.proof.engineSource,
    payloadLen: p.proof.payloadLen,
    payloadB64Present: typeof p.proof.payloadB64 === 'string' && p.proof.payloadB64.length > 0,
  };

  // STARK 完整验证（真 wasm：vendor/stwo-verify）
  const stark = await verifyStarkProof(p.proof.payloadB64, verifyCanonicalArchive);
  out.steps.stark = stark;

  // wallet-core 结算关系复验（保留步骤；fixture 明细可能复验不过——如实记录，
  // run_04 断言对象是 STARK 阶段与 fail-closed 结论规则）
  let settle = null;
  try {
    const v = await verifyLocally(s.detail, async (json) => {
      const res = await callCore('wallet_verify_settlement_detail', json);
      if (res?.error) {
        const e = new Error(res.error);
        e.code = res.error;
        throw e;
      }
      return res;
    });
    settle = v.ok ? { verdict: v.verdict.verdict, elapsedMs: v.elapsedMs } : { verdict: 'error', code: v.code };
  } catch (e) {
    settle = { verdict: 'error', code: String(e?.code ?? e?.message ?? e).slice(0, 60) };
  }
  out.steps.settlementReverify = settle;

  // fail-closed 结论（与 portal/portal.js renderConclusion 同规则）
  out.ok = stark?.ok === true;
  out.conclusion = {
    starkPass: stark?.ok === true,
    starkState: stark?.ok ? 'verified' : (stark?.code ?? 'unknown'),
    settlePass: settle?.verdict === 'verified',
    overall: stark?.ok === true && settle?.verdict === 'verified' ? 'fully verified' : 'not verified',
  };
  return out;
};
