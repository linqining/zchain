// =============================================================================
// extension/portal/portal.js — Proof Portal 页面（Extension 0.2，扩展页）
//
// 流程：hand binding → 网关 settlement 明细（payout_root/rake/层级）→
// proof 归档（engine/payload 长度）→ wallet-core wasm
// `wallet_verify_settlement_detail` 本地复验 → 展示 verifier 版本/耗时/结论。
//
// 纪律：
// - 全部验证逻辑在 wallet-core wasm（本文件零密码学、零结算语义重实现）；
// - 网关 URL 按当前网络解析（popup 设置的 per-network 覆盖优先）；未配置
//   如实报 GatewayNotConfigured；网络层失败如实报 GatewayUnreachable；
// - 层级（proven/soft_accepted）是网关水位声明，原样展示、不推进；
// - 主机权限：可选权限（optional_host_permissions），仅在用户点击"授予"时
//   请求该网关 origin；未授予且网关未开 --public CORS 时，fetch 会失败并
//   如实报网关不可达。
// =============================================================================

import { callCore } from '../common/wallet_core.js';
import { verifyCanonicalArchive } from '../common/stwo_verify.js';
import { parseBinding, fetchSettlement, fetchProof, verifyStarkProof, verifyLocally, verdictRows } from '../common/portal.js';
import { assetBadge } from '../common/assets.js';

const $ = (id) => document.getElementById(id);
const send = (m) => chrome.runtime.sendMessage(m);

function row(k, v, mono = false) {
  const r = document.createElement('div');
  r.className = 'row';
  const kk = document.createElement('span');
  kk.className = 'k';
  kk.textContent = k;
  const vv = document.createElement('span');
  vv.className = mono ? 'v mono' : 'v';
  vv.textContent = String(v ?? '');
  r.append(kk, vv);
  return r;
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text) n.textContent = text;
  return n;
}

async function refreshHeader() {
  const state = await send({ type: 'popup:getState' });
  const $net = $('net-badge');
  $net.textContent = `${state.networkKind} · ${state.chainId}`;
  $net.className = `badge badge-${state.networkKind}`;
  $('gateway-line').textContent = `网关：${state.gatewayUrl ?? '未配置（testnet 必须显式设置）'}`;
  $('gateway-input').value = state.gatewayUrl ?? '';
  $('gateway-input').placeholder = state.networkKind === 'devnet' ? 'http://127.0.0.1:18900' : 'https://<testnet-gateway>';
  return state;
}

$('save-gateway').addEventListener('click', async () => {
  const state = await refreshHeader();
  const res = await send({ type: 'popup:setGateway', chainId: state.chainId, gatewayUrl: $('gateway-input').value.trim() });
  if (res?.error) {
    $('err').textContent = `${res.error.code}: ${res.error.reason}`;
    return;
  }
  $('err').textContent = '';
  await refreshHeader();
});

$('grant-permission').addEventListener('click', async () => {
  const state = await refreshHeader();
  if (!state.gatewayUrl) {
    $('err').textContent = '未配置网关 URL，无法请求主机权限';
    return;
  }
  const origin = new URL(state.gatewayUrl).origin;
  try {
    const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
    $('err').textContent = granted ? `已授予 ${origin} 主机权限` : '未授予（网关需以 --public 启动才能跨源访问）';
  } catch (e) {
    $('err').textContent = `权限请求失败：${String(e?.message ?? e)}`;
  }
});

$('verify').addEventListener('click', async () => {
  $('err').textContent = '';
  for (const id of ['settlement-card', 'proof-card', 'stark-card', 'verdict-card', 'conclusion-card']) {
    $(id).style.display = 'none';
  }
  const state = await refreshHeader();
  const gateway = state.gatewayUrl;

  // (0) binding 形状校验（fail-closed）
  const b = parseBinding($('binding').value);
  if (!b.ok) {
    $('err').textContent = `${b.code}: ${b.reason}`;
    return;
  }

  // (1) 网关 settlement 明细
  const s = await fetchSettlement(gateway, b.binding);
  if (!s.ok) {
    $('err').textContent = `${s.code}: ${s.reason}`;
    return;
  }
  renderSettlement(s.detail);
  $('settlement-card').style.display = '';

  // (2) proof 归档（缺失时如实展示"无已归档证明产物"，跳过 STARK 阶段）
  const p = await fetchProof(gateway, b.binding);
  if (p.ok) {
    renderProof(p.proof);
  } else if (p.code === 'ProofNotFound') {
    renderProof(null);
    $('err').textContent = '';
  } else {
    // 网关不可达 / 超时 / 其他 HTTP 错误：如实报错并终止。
    $('err').textContent = `${p.code}: ${p.reason}`;
    return;
  }
  $('proof-card').style.display = '';

  // (3) STARK wasm 完整验证（0.4：归档字节本地全量验证 FRI+Merkle+约束+scope 重建）
  let stark = null; // { ok, stark?, code?, reason?, stats?, elapsedMs? }
  if (p.ok && p.proof.payloadB64) {
    stark = await verifyStarkProof(p.proof.payloadB64, verifyCanonicalArchive);
  } else {
    stark = { ok: false, skipped: true, code: 'ProofNotFound', reason: '该结算无已归档证明产物，STARK 阶段跳过（如实展示）' };
  }
  renderStark(stark);
  $('stark-card').style.display = '';

  // (4) wallet-core wasm 本地复验（结算关系；独立于 STARK 阶段照常执行）
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
  if (!v.ok) {
    $('err').textContent = `${v.code}: ${v.reason}`;
    renderConclusion(stark, null);
    $('conclusion-card').style.display = '';
    return;
  }
  renderVerdict(v.verdict, v.elapsedMs);
  $('verdict-card').style.display = '';

  // (5) 结论页：两项独立验证汇总（fail-closed——STARK 跳过/拒绝 ≠ verified）
  renderConclusion(stark, v.verdict);
  $('conclusion-card').style.display = '';
});

function renderSettlement(d) {
  const body = $('settlement-body');
  body.replaceChildren();
  body.appendChild(row('hand_binding', d.hand_binding ?? '', true));
  body.appendChild(row('table_id', d.table_id ?? ''));
  body.appendChild(row('pot', d.pot != null ? String(d.pot) : ''));
  body.appendChild(row('payout_root', d.payout_root ?? '', true));
  const levelBadge = el('span', `badge ${d.level === 'proven' ? 'badge-play' : 'badge-devnet'}`, d.level ?? 'unknown');
  const levelRow = el('div', 'row');
  const k = el('span', 'k', '层级（网关水位声明）');
  levelRow.append(k, levelBadge);
  body.appendChild(levelRow);
  const rake = d.rake ?? {};
  body.appendChild(row('rake.total', rake.total != null ? String(rake.total) : ''));
  if (rake.treasury_out) body.appendChild(row('rake → treasury', `${rake.treasury_out.amount}（${rake.treasury_out.asset_class}）`));
  if (rake.operator_out) body.appendChild(row('rake → operator', `${rake.operator_out.amount}（${rake.operator_out.asset_class}）`));
  body.appendChild(row('inputs / payouts', `${(d.inputs ?? []).length} / ${(d.payouts ?? []).length}`));
  // TE-M5：payout 逐条带资产徽章——网关 `asset_id` 字段（domain/token 名称
  // 解析）优先，旧网关载荷回落 v1 asset_class 冻结映射；解析失败如实给
  // 原始值（不造名）。
  for (const [i, p] of (d.payouts ?? []).entries()) {
    const b = assetBadge(p.asset_id ?? p.asset_class);
    const label = b.ok ? `${b.domainName}/${b.tokenLabel}` : String(p.asset_class ?? '?');
    body.appendChild(row(`payout#${i}`, `${p.amount} → ${(p.owner ?? '').slice(0, 12)}…（pot ${p.pot_index}/run ${p.runout_index}）`, true));
    const badgeRow = el('div', 'row');
    badgeRow.append(el('span', 'k', `payout#${i} 资产`), el('span', `badge ${b.ok ? b.badgeClass : 'badge-real'}`, `${label} · ${b.ok ? b.asset : 'asset_id 解析失败'}`));
    body.appendChild(badgeRow);
  }
}

function renderProof(proof) {
  const body = $('proof-body');
  body.replaceChildren();
  if (!proof) {
    body.appendChild(el('div', 'dim', '该结算暂无已归档证明产物（网关 404）——如实展示，不影响结算关系复验。'));
    return;
  }
  body.appendChild(row('binding', proof.bindingHex, true));
  body.appendChild(row('engine', proof.engine ?? '未知（未授予主机权限且响应体无 engine）'));
  body.appendChild(row('engine 来源', proof.engineSource));
  body.appendChild(row('payload 字节数', proof.payloadLen != null ? String(proof.payloadLen) : ''));
  body.appendChild(el('div', 'hint', '0.4 起 STARK 证明本体会交给下方 stwo wasm 验证器在本地完整验证（见 STARK 卡片）。'));
}

/** STARK 阶段三态渲染：verified / 拒绝（含跳过） / 验证器错误——如实展示。 */
function renderStark(stark) {
  const body = $('stark-body');
  body.replaceChildren();
  if (stark.skipped) {
    body.appendChild(el('div', 'dim', `STARK 阶段未执行：${stark.reason ?? '无归档'}`));
    return;
  }
  if (stark.ok) {
    const s = stark.stark ?? {};
    const stats = s.stats ?? {};
    const badge = el('span', 'badge badge-play', 'verified（完整 STARK 验证通过）');
    const vRow = el('div', 'row');
    vRow.append(el('span', 'k', '结论'), badge);
    body.appendChild(vRow);
    body.appendChild(row('verifier', stats.verifier ?? 'stwo-wasm-verify', true));
    if (stats.table_id != null) body.appendChild(row('table_id', String(stats.table_id)));
    if (stats.log_size != null) body.appendChild(row('log_size / 列数', `${stats.log_size} / ${stats.num_columns ?? '?'}`));
    if (stats.transition_count != null) body.appendChild(row('transition_count', String(stats.transition_count)));
    if (stats.batch_digest) body.appendChild(row('batch_digest', String(stats.batch_digest).slice(0, 32) + '…', true));
    body.appendChild(row('耗时（wasm 调用，宿主墙钟）', `${s.elapsedMs ?? stark.elapsedMs} ms`));
    if (typeof s.elapsedMs === 'number' && s.elapsedMs > 500) {
      body.appendChild(el('div', 'hint', '注意：本次 STARK 验证超过 500ms 预算门槛（如实标注：低频验证场景可接受，性能优化留后续）。'));
    }
    return;
  }
  // 拒绝 / 归档非法 / 验证器错误三态（不伪造 verified）
  const badgeMap = {
    StarkVerifyRejected: ['badge-real', 'REJECTED（STARK 验证拒绝）'],
    StarkArchiveInvalid: ['badge-real', 'INVALID（归档无法解码）'],
    StarkVerifierError: ['badge-real', 'ERROR（验证器不可用/内部错误）'],
  };
  const [cls, text] = badgeMap[stark.code] ?? ['badge-real', `FAILED（${stark.code ?? '未知错误'}）`];
  const vRow = el('div', 'row');
  vRow.append(el('span', 'k', '结论'), el('span', `badge ${cls}`, text));
  body.appendChild(vRow);
  if (stark.reason) body.appendChild(el('div', 'dim', stark.reason));
  if (stark.elapsedMs != null) body.appendChild(row('耗时', `${stark.elapsedMs} ms`));
}

/** 结论页：STARK 与结算关系两项独立验证汇总（fail-closed）。 */
function renderConclusion(stark, verdict) {
  const body = $('conclusion-body');
  body.replaceChildren();
  const starkPass = stark?.ok === true;
  const settlePass = verdict?.verdict === 'verified';
  const starkText = stark?.skipped ? '未执行（无归档，如实跳过）' : starkPass ? 'verified（STARK 完整验证通过）' : `未通过（${stark?.code ?? '?'})`;
  const rows = [
    ['STARK 完整验证（stwo wasm）', starkText, starkPass],
    ['结算关系复验（wallet-core wasm）',
      verdict ? (settlePass ? 'verified（payout_root 复算一致）' : 'rejected（复验不一致）') : '未执行（复验失败）',
      settlePass],
  ];
  for (const [k, text, ok] of rows) {
    const r = el('div', 'row');
    r.append(el('span', 'k', k), el('span', ok ? 'v' : 'v', text));
    r.style.color = ok ? 'var(--ok)' : 'var(--bad)';
    body.appendChild(r);
  }
  const overall = starkPass && settlePass;
  const line = el('div', 'row');
  line.append(
    el('span', 'k', '总体结论'),
    el('span', `badge ${overall ? 'badge-play' : 'badge-real'}`,
      overall ? 'fully verified（STARK + 结算关系均一致）' : 'not verified（任一环节未通过即不算 verified）'),
  );
  body.appendChild(line);
}

function renderVerdict(verdict, elapsedMs) {
  const body = $('verdict-body');
  body.replaceChildren();
  const verdictBadge = el('span', `badge ${verdict.verdict === 'verified' ? 'badge-play' : 'badge-real'}`,
    verdict.verdict === 'verified' ? 'verified（结算关系复验一致）' : 'rejected（复验不一致）');
  const vRow = el('div', 'row');
  vRow.append(el('span', 'k', '结论'), verdictBadge);
  body.appendChild(vRow);
  const verifier = verdict.verifier ?? {};
  body.appendChild(row('verifier', `${verifier.name ?? '?'} v${verifier.version ?? '?'}`));
  body.appendChild(row('ABI', `v${verifier.abi_version ?? '?'}`));
  body.appendChild(row('耗时', `${elapsedMs} ms（含 wasm 调用）`));
  const ul = el('ul', 'checks');
  for (const r of verdictRows(verdict)) {
    ul.appendChild(el('li', r.ok ? 'ok' : 'no', `${r.ok ? '✓' : '✗'} ${r.label} — ${r.detail}`));
  }
  body.appendChild(ul);
}

refreshHeader();
