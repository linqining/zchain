// =============================================================================
// extension/tests/e2e/portal_harness_page.js — portal E2E 的 http 同源 harness 页
//
// 用途：Chrome 138+ 对 chrome-extension 页面访问 127.0.0.1 施加 Local Network
// Access 限制（无主机权限 → fetch 直接失败；headless 无法点击浏览器权限弹窗），
// E2E 无法在扩展页内完成"跨源 fetch 真实网关"这一步。本 harness 页从
// http://127.0.0.1（static server 根 = extension/）加载**与 portal/portal.js
// 完全相同**的逻辑模块（common/portal.js + common/wallet_core.js），对真实
// explorer gateway 执行同一管线：
//   fetchSettlement → fetchProof → verifyLocally(wallet_verify_settlement_detail)
// 覆盖：URL 组装/错误分类（GatewayUnreachable/NotFound）、网关 --public CORS
// 路径、wasm 结算关系复验。扩展 portal 页自身的 UI 接线由扩展页加载烟测覆盖
// （见 run_02.mjs D 节说明与 ACCEPTANCE.md 边界记录）。
// =============================================================================

import { callCore } from '../../common/wallet_core.js';
import { parseBinding, fetchSettlement, fetchProof, verifyLocally, verdictRows } from '../../common/portal.js';

// 结果挂到 window 供 CDP runner 取用。
window.__PORTAL_RESULT = null;

window.runPortalCheck = async (gatewayUrl, bindingInput) => {
  const out = { steps: {} };
  const b = parseBinding(bindingInput);
  if (!b.ok) return { ok: false, step: 'parseBinding', ...b };
  out.steps.binding = 'ok';

  const s = await fetchSettlement(gatewayUrl, b.binding);
  if (!s.ok) return { ok: false, step: 'fetchSettlement', ...s };
  out.steps.settlement = {
    hand_binding: s.detail.hand_binding,
    pot: s.detail.pot,
    payout_root: s.detail.payout_root,
    level: s.detail.level,
    rake_total: s.detail.rake?.total,
    payouts: (s.detail.payouts ?? []).length,
  };

  const p = await fetchProof(gatewayUrl, b.binding);
  out.steps.proof = p.ok
    ? { engine: p.proof.engine, engineSource: p.proof.engineSource, payloadLen: p.proof.payloadLen }
    : { notFound: p.code === 'ProofNotFound', code: p.code };

  const v = await verifyLocally(s.detail, async (json) => {
    const res = await callCore('wallet_verify_settlement_detail', json);
    if (res?.error) {
      const e = new Error(res.error);
      e.code = res.error;
      e.detail = res.detail;
      throw e;
    }
    return res;
  });
  if (!v.ok) return { ok: false, step: 'verifyLocally', ...v };
  out.steps.verdict = {
    verdict: v.verdict.verdict,
    elapsedMs: v.elapsedMs,
    verifier: v.verdict.verifier,
    rows: verdictRows(v.verdict).map((r) => ({ label: r.label, ok: r.ok })),
  };
  out.ok = v.verdict.verdict === 'verified';
  return out;
};
